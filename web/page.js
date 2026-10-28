// Draws the result envelope on the report page. The rules live in check.js.

import { LEVEL_WORDS, MAX_LOOKUPS, checkDomain, createDohResolver, normalizeDomain } from "./check.js";

const SEVERITY_ORDER = ["high", "medium", "low", "info", "good"];
const POLICY_MEANING = {
  none: "Mail that fails the check is delivered as normal.",
  quarantine: "Mail that fails the check goes to spam.",
  reject: "Mail that fails the check is refused.",
};
const ALIGNMENT_MEANING = {
  r: "relaxed: a subdomain of the From address counts as a match.",
  s: "strict: only the exact From domain counts.",
};
const ALL_MEANING = {
  "-": "Servers not listed are failed.",
  "~": "Servers not listed are marked suspicious, not failed.",
  "?": "Makes no claim about servers not listed.",
  "+": "Every server on the internet is allowed to send.",
};
const NO_ALL_MEANING = "No all at the end, so servers not listed are neither passed nor failed.";

const form = document.getElementById("check-form");
const input = document.getElementById("domain");
const output = document.getElementById("result");
const reference = Promise.all([loadJson("/assets/findings.json"), loadJson("/assets/orgs.json")]);

form.addEventListener("submit", (event) => {
  event.preventDefault();
  runCheck(input.value);
});

const fromUrl = new URLSearchParams(location.search).get("domain");
if (fromUrl) {
  input.value = fromUrl;
  runCheck(fromUrl);
}

async function loadJson(url) {
  const response = await fetch(url);
  return response.ok ? response.json() : {};
}

async function runCheck(typed) {
  const domain = normalizeDomain(typed);
  if (!domain) {
    showStatus("That doesn't look like a domain. Type the part after the @, like example.ca.", true);
    input.focus();
    return;
  }
  history.replaceState(null, "", `?domain=${encodeURIComponent(domain)}`);
  showStatus(`Asking DNS about ${domain}…`);

  let result;
  try {
    result = await checkDomain(domain, createDohResolver());
  } catch {
    showStatus("Couldn't reach dns.google. Check your connection, or try again in a minute.", true);
    return;
  }
  if (result.error === "nxdomain") {
    showStatus(`DNS says ${domain} doesn't exist. Check the spelling, or try the part after the @ in a staff email address.`, true);
    return;
  }
  const [catalogue, orgs] = await reference;
  const byCode = Object.fromEntries((catalogue.findings ?? []).map((f) => [f.code, f]));
  output.innerHTML = envelopeHtml(result, byCode, orgs[domain], new Date());
  output.hidden = false;
}

function showStatus(message, isError = false) {
  output.innerHTML = `<div class="wrap"><p class="result-status${isError ? " is-error" : ""}">${escapeHtml(message)}</p></div>`;
  output.hidden = false;
}

function envelopeHtml(result, byCode, org, checkedAt) {
  const { domain, level } = result;
  const timeoutNote = result.error === "timeout"
    ? `<p class="result-status is-error">Some lookups for ${escapeHtml(domain)} got no answer, so this result is incomplete. Try again in a minute.</p>`
    : "";
  return `<div class="wrap">
    <article class="envelope result-env">
      <h2 id="result-title" class="visually-hidden">Result for ${escapeHtml(domain)}</h2>
      <div class="result-top">
        <div class="result-info">
          <p class="checked-at">Checked ${escapeHtml(formatCheckedAt(checkedAt))}</p>
          <div class="address">
            <p class="domain">${escapeHtml(domain)}</p>
            ${org ? `<p class="org">${escapeHtml(org)}</p>` : ""}
          </div>
          <p class="verdict">${escapeHtml(verdictSentence(result.dmarc))}</p>
          ${timeoutNote}
        </div>
        ${postmarkSvg(level, checkedAt)}
      </div>
      <div class="enclosures">
        ${dmarcEnclosure(domain, result.dmarc)}
        ${spfEnclosure(domain, result.spf)}
      </div>
      ${fixListHtml(result.findings, byCode, domain)}
      ${alsoCheckedHtml(result)}
    </article>
  </div>`;
}

function verdictSentence(dmarc) {
  if (!dmarc || dmarc.level === 0) {
    return "Receivers get no instruction about forged mail from this domain, so most deliver it.";
  }
  if (dmarc.level === 3) return "Receivers are told to refuse forged mail from this domain.";
  if (dmarc.policy === "reject") {
    return `Only ${dmarc.record.pct}% of forged mail from this domain is refused. The rest is filed as spam.`;
  }
  if (dmarc.level === 2) {
    return "Forged mail from this domain is filed as spam, not refused. People can still find it and open it.";
  }
  return "Receivers are asked to deliver forged mail as normal and only send reports.";
}

function readDmarcTags(dmarc) {
  const { record, policy } = dmarc;
  if (!record) return [];
  const { tags } = record;
  const lines = [];
  if (policy) lines.push([`p=${tags.p ?? policy}`, POLICY_MEANING[policy]]);
  if ("sp" in tags && record.subdomainPolicy) {
    const sp = record.subdomainPolicy;
    lines.push([
      `sp=${tags.sp}`,
      sp === policy ? "Same rule for made-up subdomains." : `Subdomains: ${POLICY_MEANING[sp].toLowerCase()}`,
    ]);
  }
  if ("pct" in tags) lines.push([`pct=${tags.pct}`, `The policy applies to ${record.pct}% of failing mail.`]);
  if (record.reportAddresses.length) {
    lines.push(["rua", `Daily reports go to ${record.reportAddresses.join(", ")}.`]);
  }
  for (const [tag, label] of [["adkim", "DKIM"], ["aspf", "SPF"]]) {
    const value = (tags[tag] ?? "").toLowerCase();
    if (value in ALIGNMENT_MEANING) lines.push([`${tag}=${value}`, `${label} alignment is ${ALIGNMENT_MEANING[value]}`]);
  }
  return lines;
}

function readingHtml(lines) {
  if (!lines.length) return "";
  const rows = lines.map(([tag, meaning]) => `<dt>${escapeHtml(tag)}</dt><dd>${escapeHtml(meaning)}</dd>`);
  return `<dl class="reading">${rows.join("")}</dl>`;
}

function dmarcEnclosure(domain, dmarc) {
  const body = dmarc.seen.length
    ? `<pre class="record">${dmarc.seen.map(escapeHtml).join("\n")}</pre>${readingHtml(readDmarcTags(dmarc))}`
    : `<p class="empty">Nothing published.</p>`;
  return `<section class="enclosure" aria-labelledby="dmarc-h">
    <h3 id="dmarc-h">DMARC <small>at _dmarc.${escapeHtml(domain)}</small></h3>
    ${body}
  </section>`;
}

function spfEnclosure(domain, spf) {
  let body;
  if (spf.record === null) {
    const multiple = spf.findings.some((f) => f.code === "SPF_MULTIPLE");
    const seen = spf.seen.filter((s) => /^v=spf1/i.test(s.trim()));
    body = multiple
      ? `<pre class="record">${seen.map(escapeHtml).join("\n")}</pre><p class="empty">Two SPF records, so receivers ignore both.</p>`
      : `<p class="empty">No SPF record.</p>`;
  } else {
    const all = spf.allQualifier;
    const tag = all ? `${all}all` : "no all";
    body = `<pre class="record">${escapeHtml(spf.record)}</pre>
      <div>
        ${lookupMeter(spf.lookups)}
        <dl class="reading" style="margin-top:12px"><dt>${escapeHtml(tag)}</dt><dd>${escapeHtml(all ? ALL_MEANING[all] : NO_ALL_MEANING)}</dd></dl>
      </div>`;
  }
  return `<section class="enclosure" aria-labelledby="spf-h">
    <h3 id="spf-h">SPF <small>at ${escapeHtml(domain)}</small></h3>
    ${body}
  </section>`;
}

function lookupMeter(used) {
  const ticks = Array.from({ length: MAX_LOOKUPS }, (_, i) => `<span class="tick${i < used ? " used" : ""}"></span>`);
  return `<div class="lookups${used > MAX_LOOKUPS ? " over" : ""}">
    <span class="ticks" aria-hidden="true">${ticks.join("")}</span>
    <span>${used} of ${MAX_LOOKUPS} DNS lookups used</span>
  </div>`;
}

function fixListHtml(findings, byCode, domain) {
  const todo = findings
    .filter((f) => byCode[f.code] && byCode[f.code].severity !== "good")
    .sort((a, b) => SEVERITY_ORDER.indexOf(byCode[a.code].severity) - SEVERITY_ORDER.indexOf(byCode[b.code].severity));
  if (!todo.length) {
    return `<section class="fix-first" aria-labelledby="fix-h"><h3 id="fix-h">What to fix, in order</h3><p>Nothing. These records are set up the way the standards recommend.</p></section>`;
  }
  const forDomain = (text) => text.replaceAll("<domain>", domain).replaceAll("example.ca", domain);
  const items = todo.map((f) => {
    const entry = byCode[f.code];
    const detail = f.detail ? ` (${f.detail})` : "";
    return `<li><div class="f-body">
      <h4>${escapeHtml(entry.title)} ${severityMark(entry.severity)}</h4>
      <p>${escapeHtml(entry.explain + detail)}</p>
      ${entry.fix ? `<p>${escapeHtml(forDomain(entry.fix))}</p>` : ""}
      ${entry.example ? `<pre class="record">${escapeHtml(forDomain(entry.example))}</pre>` : ""}
      <p class="f-more"><a href="/fix/#${entry.code}">More in the fix guide</a></p>
    </div></li>`;
  });
  return `<section class="fix-first" aria-labelledby="fix-h"><h3 id="fix-h">What to fix, in order</h3><ol>${items.join("")}</ol></section>`;
}

function severityMark(severity) {
  return `<span class="sev sev-${severity}">${severity[0].toUpperCase()}${severity.slice(1)}</span>`;
}

function alsoCheckedHtml({ mx, dkim, mtaSts, tlsRpt }) {
  let servers = "None listed";
  if (mx.nullMx) servers = "None. The domain says it takes no mail.";
  else if (mx.hosts.length) {
    const n = mx.hosts.length;
    servers = `${n} server${n > 1 ? "s" : ""}: ${mx.hosts.map((h) => h.host).join(", ")}`;
  }
  const dkimText = dkim.selectors.length
    ? `<span class="sev sev-good">Found</span> at ${escapeHtml(dkim.selectors.join(", "))}`
    : "Not found at common selectors, which doesn't mean it's missing";
  const stsText = mtaSts.record ? "TXT record only; the policy file can't be checked from a browser" : "Not published";
  return `<section class="also" aria-labelledby="also-h">
    <h3 id="also-h">Also checked</h3>
    <dl>
      <dt>Mail servers</dt><dd>${escapeHtml(servers)}</dd>
      <dt>DKIM</dt><dd>${dkimText}</dd>
      <dt>MTA-STS</dt><dd>${escapeHtml(stsText)}</dd>
      <dt>TLS reports</dt><dd>${tlsRpt.record ? "Published" : "Not published"}</dd>
    </dl>
  </section>`;
}

const STAMP_CLASS = { 3: "enforced", 2: "partial", 1: "monitoring", 0: "unprotected" };

function postmarkSvg(level, when) {
  const word = LEVEL_WORDS[level];
  const id = STAMP_CLASS[level];
  const date = when.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" }).toUpperCase();
  // Long verdict words don't fit the band at full size (docs/DESIGN.md).
  const wordSize = word.length > 9 ? ' style="font-size:14.5px"' : "";
  const wave = "q 6.5 -5 13 0 q 6.5 5 13 0 ".repeat(3) + "q 6.5 -5 13 0";
  const waves = [34, 45, 56, 67, 78].map((y) => `<path d="M118 ${y} ${wave}"/>`).join("");
  return `<svg class="postmark postmark-${id}" viewBox="0 0 214 112" role="img" aria-label="Verdict: ${word}">
  <defs>
    <filter id="ink-${id}" x="-5%" y="-5%" width="110%" height="110%">
      <feTurbulence type="fractalNoise" baseFrequency="0.9" numOctaves="2" seed="7" result="noise"/>
      <feDisplacementMap in="SourceGraphic" in2="noise" scale="1.6"/>
    </filter>
    <path id="arc-top-${id}" d="M 14 56 A 42 42 0 0 1 98 56"/>
    <path id="arc-bottom-${id}" d="M 10 56 A 46 46 0 0 0 102 56"/>
  </defs>
  <g filter="url(#ink-${id})">
    <circle cx="56" cy="56" r="52" class="pm-ring"/>
    <line x1="6.5" y1="44" x2="105.5" y2="44" class="pm-ring pm-ring-thin"/>
    <line x1="6.5" y1="68" x2="105.5" y2="68" class="pm-ring pm-ring-thin"/>
    <text class="pm-arc"><textPath href="#arc-top-${id}" startOffset="50%" text-anchor="middle">SPOOFCHECK BC</textPath></text>
    <text class="pm-arc"><textPath href="#arc-bottom-${id}" startOffset="50%" text-anchor="middle">${escapeHtml(date)}</textPath></text>
    <text class="pm-word" x="56" y="56.5" text-anchor="middle" dominant-baseline="central"${wordSize}>${word}</text>
    <g class="pm-waves">${waves}</g>
  </g>
</svg>`;
}

function formatCheckedAt(date) {
  const day = date.toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" });
  const time = date.toLocaleTimeString("en-CA", { hour: "numeric", minute: "2-digit" });
  return `${day} at ${time}`;
}

function escapeHtml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}
