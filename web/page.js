// Draws the result envelope on the report page. The rules live in check.js.

import { LEVEL_WORDS, MAX_LOOKUPS, checkDomain, createDohResolver, normalizeDomain } from "./check.js";

const SEVERITY_ORDER = ["high", "medium", "low", "info", "good"];
const STAMP_CLASS = { 3: "enforced", 2: "partial", 1: "monitoring", 0: "unprotected" };

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
  null: "No all at the end, so servers not listed are neither passed nor failed.",
};

const form = document.getElementById("check-form");
const input = document.getElementById("domain");
const output = document.getElementById("result");
const stampTemplate = document.getElementById("postmark");
const catalogue = loadJson("/assets/findings.json");
const orgNames = loadJson("/assets/orgs.json");

form.addEventListener("submit", (event) => {
  event.preventDefault();
  runCheck(input.value);
});

// A link like /?domain=example.ca runs the check straight away.
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

  const findingsByCode = {};
  for (const entry of (await catalogue).findings ?? []) findingsByCode[entry.code] = entry;
  const org = (await orgNames)[domain];
  const checkedAt = new Date();

  output.innerHTML = envelopeHtml(result, findingsByCode, org, checkedAt);
  output.querySelector(".result-top").append(postmark(result.level, checkedAt));
  output.hidden = false;
}

function showStatus(message, isError = false) {
  const css = isError ? "result-status is-error" : "result-status";
  output.innerHTML = `<div class="wrap"><p class="${css}">${escapeHtml(message)}</p></div>`;
  output.hidden = false;
}

function envelopeHtml(result, findingsByCode, org, checkedAt) {
  const domain = escapeHtml(result.domain);
  let timeoutNote = "";
  if (result.error === "timeout") {
    timeoutNote = `<p class="result-status is-error">Some lookups for ${domain} got no answer,
      so this result is incomplete. Try again in a minute.</p>`;
  }
  return `<div class="wrap">
    <article class="envelope result-env">
      <h2 id="result-title" class="visually-hidden">Result for ${domain}</h2>
      <div class="result-top">
        <div class="result-info">
          <p class="checked-at">Checked ${formatCheckedAt(checkedAt)}</p>
          <div class="address">
            <p class="domain">${domain}</p>
            ${org ? `<p class="org">${escapeHtml(org)}</p>` : ""}
          </div>
          <p class="verdict">${verdictSentence(result.dmarc)}</p>
          ${timeoutNote}
        </div>
      </div>
      <div class="enclosures">
        ${dmarcSection(result.domain, result.dmarc)}
        ${spfSection(result.domain, result.spf)}
      </div>
      ${fixListSection(result.findings, findingsByCode, result.domain)}
      ${alsoCheckedSection(result)}
    </article>
  </div>`;
}

function verdictSentence(dmarc) {
  if (dmarc.level === 3) return "Receivers are told to refuse forged mail from this domain.";
  if (dmarc.level === 2 && dmarc.policy === "reject") {
    return `Only ${dmarc.record.pct}% of forged mail from this domain is refused. The rest is filed as spam.`;
  }
  if (dmarc.level === 2) {
    return "Forged mail from this domain is filed as spam, not refused. People can still find it and open it.";
  }
  if (dmarc.level === 1) return "Receivers are asked to deliver forged mail as normal and only send reports.";
  return "Receivers get no instruction about forged mail from this domain, so most deliver it.";
}

// Each DMARC tag next to a sentence a resident could follow.
function readDmarcTags({ record, policy }) {
  if (!record) return [];
  const { tags } = record;
  const lines = [];
  if (policy) {
    lines.push([`p=${tags.p ?? policy}`, POLICY_MEANING[policy]]);
  }
  const sp = record.subdomainPolicy;
  if (sp && sp === policy) {
    lines.push([`sp=${tags.sp}`, "Same rule for made-up subdomains."]);
  } else if (sp) {
    lines.push([`sp=${tags.sp}`, `Subdomains: ${POLICY_MEANING[sp].toLowerCase()}`]);
  }
  if ("pct" in tags) {
    lines.push([`pct=${tags.pct}`, `The policy applies to ${record.pct}% of failing mail.`]);
  }
  if (record.reportAddresses.length) {
    lines.push(["rua", `Daily reports go to ${record.reportAddresses.join(", ")}.`]);
  }
  for (const [tag, label] of [["adkim", "DKIM"], ["aspf", "SPF"]]) {
    const value = (tags[tag] ?? "").toLowerCase();
    if (value in ALIGNMENT_MEANING) {
      lines.push([`${tag}=${value}`, `${label} alignment is ${ALIGNMENT_MEANING[value]}`]);
    }
  }
  return lines;
}

function readingList(lines) {
  if (!lines.length) return "";
  const rows = lines.map(([tag, meaning]) => `<dt>${escapeHtml(tag)}</dt><dd>${escapeHtml(meaning)}</dd>`);
  return `<dl class="reading">${rows.join("")}</dl>`;
}

function recordBlock(lines) {
  return `<pre class="record">${lines.map(escapeHtml).join("\n")}</pre>`;
}

function dmarcSection(domain, dmarc) {
  let body = `<p class="empty">Nothing published.</p>`;
  if (dmarc.seen.length) {
    body = recordBlock(dmarc.seen) + readingList(readDmarcTags(dmarc));
  }
  return `<section class="enclosure" aria-labelledby="dmarc-h">
    <h3 id="dmarc-h">DMARC <small>at _dmarc.${escapeHtml(domain)}</small></h3>
    ${body}
  </section>`;
}

function spfSection(domain, spf) {
  let body;
  if (spf.findings.some((f) => f.code === "SPF_MULTIPLE")) {
    const records = spf.seen.filter((s) => /^v=spf1/i.test(s.trim()));
    body = recordBlock(records) + `<p class="empty">Two SPF records, so receivers ignore both.</p>`;
  } else if (spf.record === null) {
    body = `<p class="empty">No SPF record.</p>`;
  } else {
    const all = spf.allQualifier;
    const reading = readingList([[all ? `${all}all` : "no all", ALL_MEANING[all]]]);
    body = `${recordBlock([spf.record])}
      <div>${lookupMeter(spf.lookups)}<div style="margin-top:12px">${reading}</div></div>`;
  }
  return `<section class="enclosure" aria-labelledby="spf-h">
    <h3 id="spf-h">SPF <small>at ${escapeHtml(domain)}</small></h3>
    ${body}
  </section>`;
}

function lookupMeter(used) {
  let ticks = "";
  for (let i = 0; i < MAX_LOOKUPS; i++) {
    ticks += i < used ? `<span class="tick used"></span>` : `<span class="tick"></span>`;
  }
  return `<div class="lookups${used > MAX_LOOKUPS ? " over" : ""}">
    <span class="ticks" aria-hidden="true">${ticks}</span>
    <span>${used} of ${MAX_LOOKUPS} DNS lookups used</span>
  </div>`;
}

function fixListSection(findings, findingsByCode, domain) {
  const severity = (f) => SEVERITY_ORDER.indexOf(findingsByCode[f.code].severity);
  const toFix = findings
    .filter((f) => findingsByCode[f.code] && findingsByCode[f.code].severity !== "good")
    .sort((a, b) => severity(a) - severity(b));

  let body = "<p>Nothing. These records are set up the way the standards recommend.</p>";
  if (toFix.length) {
    body = `<ol>${toFix.map((f) => fixItem(f, findingsByCode[f.code], domain)).join("")}</ol>`;
  }
  return `<section class="fix-first" aria-labelledby="fix-h">
    <h3 id="fix-h">What to fix, in order</h3>
    ${body}
  </section>`;
}

function fixItem(finding, entry, domain) {
  // Catalogue examples use example.ca; show them with the domain that was checked.
  const forDomain = (text) => text.replaceAll("<domain>", domain).replaceAll("example.ca", domain);
  const detail = finding.detail ? ` (${finding.detail})` : "";
  const fix = entry.fix ? `<p>${escapeHtml(forDomain(entry.fix))}</p>` : "";
  const example = entry.example ? recordBlock([forDomain(entry.example)]) : "";
  return `<li><div class="f-body">
    <h4>${escapeHtml(entry.title)} ${severityMark(entry.severity)}</h4>
    <p>${escapeHtml(entry.explain + detail)}</p>
    ${fix}
    ${example}
    <p class="f-more"><a href="/fix/#${entry.code}">More in the fix guide</a></p>
  </div></li>`;
}

function severityMark(severity, word) {
  const label = word ?? severity[0].toUpperCase() + severity.slice(1);
  return `<span class="sev sev-${severity}">${label}</span>`;
}

function alsoCheckedSection({ mx, dkim, mtaSts, tlsRpt }) {
  let servers = "None listed";
  if (mx.nullMx) {
    servers = "None. The domain says it takes no mail.";
  } else if (mx.hosts.length === 1) {
    servers = `1 server: ${mx.hosts[0].host}`;
  } else if (mx.hosts.length > 1) {
    servers = `${mx.hosts.length} servers: ${mx.hosts.map((h) => h.host).join(", ")}`;
  }

  let dkimText = "Not found at common selectors, which doesn't mean it's missing";
  if (dkim.selectors.length) {
    dkimText = `${severityMark("good", "Found")} at ${escapeHtml(dkim.selectors.join(", "))}`;
  }

  // Browsers can't fetch the MTA-STS policy file: those servers send no CORS headers.
  let mtaStsText = "Not published";
  if (mtaSts.record) mtaStsText = "TXT record only; the policy file can't be checked from a browser";

  return `<section class="also" aria-labelledby="also-h">
    <h3 id="also-h">Also checked</h3>
    <dl>
      <dt>Mail servers</dt><dd>${escapeHtml(servers)}</dd>
      <dt>DKIM</dt><dd>${dkimText}</dd>
      <dt>MTA-STS</dt><dd>${mtaStsText}</dd>
      <dt>TLS reports</dt><dd>${tlsRpt.record ? "Published" : "Not published"}</dd>
    </dl>
  </section>`;
}

function postmark(level, date) {
  const word = LEVEL_WORDS[level];
  const svg = stampTemplate.content.firstElementChild.cloneNode(true);
  svg.classList.add(`postmark-${STAMP_CLASS[level]}`);
  svg.setAttribute("aria-label", `Verdict: ${word}`);
  svg.querySelector(".pm-word").textContent = word;
  svg.querySelector(".pm-date").textContent = date
    .toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" })
    .toUpperCase();
  // Long verdict words don't fit the band at full size (docs/DESIGN.md).
  if (word.length > 9) svg.querySelector(".pm-word").style.fontSize = "14.5px";
  return svg;
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
