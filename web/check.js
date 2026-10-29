// The same rules as the Python package, for the checker on the report page.
// Function names follow the Python ones so the two can be read side by side;
// tests/vectors/*.json keeps them in agreement.

export const DOH_URL = "https://dns.google/resolve";
export const MAX_IN_FLIGHT = 4;
export const TIMEOUT_MS = 5000;

export const MAX_LOOKUPS = 10;
export const MAX_VOID_LOOKUPS = 2;
const MAX_DEPTH = 10;

export const LEVEL_WORDS = { 3: "ENFORCED", 2: "PARTIAL", 1: "MONITORING", 0: "UNPROTECTED" };
const POLICY_STRENGTH = { none: 0, quarantine: 1, reject: 2 };
const DMARC_VERSION = /^\s*v\s*=\s*DMARC1\s*(;|$)/i;
const SPF_VERSION = /^v=spf1(\s|$)/i;
const LOOKUP_MECHANISMS = ["include", "a", "mx", "ptr", "exists"];
const HOSTNAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const RR_TYPES = { TXT: 16, MX: 15, A: 1, AAAA: 28 };

export const COMMON_SELECTORS = [
  "selector1", "selector2", "google", "k1", "s1", "s2", "default", "dkim", "mail",
];

const finding = (code, detail = null) => ({ code, detail });
const isVoid = (answer) => answer.outcome === "nxdomain" || answer.outcome === "empty";

export function normalizeDomain(text) {
  let domain = text.trim().toLowerCase().replace(/\.$/, "");
  if (domain.includes("@")) domain = domain.slice(domain.lastIndexOf("@") + 1);
  if (!HOSTNAME.test(domain)) return null;
  return domain;
}

// DMARC (RFC 7489)

export function parseDmarcTags(raw) {
  const tags = {};
  for (const part of raw.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const name = part.slice(0, eq).trim().toLowerCase();
    // RFC 7489 §6.4: empty tags from a trailing ";" are allowed and ignored
    if (name && !(name in tags)) tags[name] = part.slice(eq + 1).trim();
  }
  return tags;
}

export function parseReportAddresses(value) {
  const addresses = [];
  for (let uri of value.split(",")) {
    uri = uri.trim();
    if (!uri.toLowerCase().startsWith("mailto:")) continue;
    // RFC 7489 §6.2: a "!size" suffix isn't part of the address
    const address = uri.slice("mailto:".length).split("!")[0];
    const at = address.indexOf("@");
    if (at > 0 && address.slice(at + 1).includes(".")) addresses.push(address);
  }
  return addresses;
}

export function parseDmarcRecord(raw) {
  const tags = parseDmarcTags(raw);
  return {
    raw,
    tags,
    policy: policyValue(tags.p),
    subdomainPolicy: policyValue(tags.sp),
    pct: pctValue(tags.pct),
    reportAddresses: parseReportAddresses(tags.rua ?? ""),
  };
}

export function protectionLevel(policy, pct) {
  if (policy === "reject") return pct === 100 ? 3 : 2;
  if (policy === "quarantine") return 2;
  if (policy === "none") return 1;
  return 0;
}

export function evaluateDmarc(seen) {
  const candidates = seen.filter((s) => DMARC_VERSION.test(s));
  if (candidates.length > 1) {
    // RFC 7489 §6.6.3: more than one record means none of them apply
    return { seen, record: null, policy: null, level: 0, findings: [finding("DMARC_MULTIPLE")] };
  }
  if (candidates.length === 0) {
    const misplaced = seen.some((s) => s.toLowerCase().replaceAll(" ", "").includes("v=dmarc1"));
    const code = misplaced ? "DMARC_SYNTAX" : "DMARC_MISSING";
    return { seen, record: null, policy: null, level: 0, findings: [finding(code)] };
  }

  const record = parseDmarcRecord(candidates[0]);
  const findings = [];
  let policy = record.policy;
  if (policy === null) {
    findings.push(finding("DMARC_SYNTAX", "p tag missing or not none, quarantine or reject"));
    // RFC 7489 §6.6.3: a bad p with a usable rua is treated as p=none
    if (record.reportAddresses.length) policy = "none";
  }
  const level = protectionLevel(policy, record.pct);
  findings.push(...policyFindings(policy, record));
  if (!record.reportAddresses.length) findings.push(finding("DMARC_NO_REPORTS"));
  return { seen, record, policy, level, findings };
}

function policyFindings(policy, record) {
  const findings = [];
  if (policy === "reject" && record.pct === 100) findings.push(finding("DMARC_ENFORCED"));
  else if (policy === "quarantine") findings.push(finding("DMARC_POLICY_QUARANTINE"));
  else if (policy === "none") findings.push(finding("DMARC_POLICY_NONE"));

  if ((policy === "reject" || policy === "quarantine") && record.pct < 100) {
    findings.push(finding("DMARC_PCT_PARTIAL", `pct=${record.pct}`));
  }
  const sp = record.subdomainPolicy;
  if (policy && sp && POLICY_STRENGTH[sp] < POLICY_STRENGTH[policy]) {
    findings.push(finding("DMARC_SUBDOMAIN_WEAKER", `p=${policy}, sp=${sp}`));
  }
  return findings;
}

function policyValue(value) {
  if (value === undefined) return null;
  const lower = value.toLowerCase();
  return lower in POLICY_STRENGTH ? lower : null;
}

function pctValue(value) {
  // RFC 7489 §6.3: pct defaults to 100; a value we can't read is treated the same
  if (value === undefined || !/^\d+$/.test(value)) return 100;
  return Math.min(Number(value), 100);
}

export async function checkDmarc(domain, resolver) {
  const answer = await resolver.txt(`_dmarc.${domain}`);
  if (answer.outcome === "timeout") {
    return { seen: [], record: null, policy: null, level: 0, findings: [finding("DNS_TIMEOUT")] };
  }
  const result = evaluateDmarc(answer.records);
  if (result.record === null) return result;
  const unauthorized = await unauthorizedReportDomains(domain, result.record, resolver);
  for (const dest of unauthorized) {
    result.findings.push(finding("DMARC_REPORT_DEST_UNAUTHORIZED", dest));
  }
  return result;
}

export async function unauthorizedReportDomains(domain, record, resolver) {
  const external = [
    ...new Set(
      record.reportAddresses
        .map((a) => a.slice(a.lastIndexOf("@") + 1).toLowerCase().replace(/\.$/, ""))
        .filter((dest) => !sameOrganization(domain, dest)),
    ),
  ].sort();
  // RFC 7489 §7.1: <our domain>._report._dmarc.<their domain> TXT "v=DMARC1"
  const answers = await Promise.all(
    external.map((dest) => resolver.txt(`${domain}._report._dmarc.${dest}`)),
  );
  return external.filter(
    (_, i) =>
      answers[i].outcome !== "timeout" && !answers[i].records.some((r) => DMARC_VERSION.test(r)),
  );
}

function sameOrganization(a, b) {
  return a === b || a.endsWith(`.${b}`) || b.endsWith(`.${a}`);
}

// SPF (RFC 7208)

export function selectSpfRecords(txt) {
  return txt.filter((s) => SPF_VERSION.test(s.trim()));
}

export function parseSpfRecord(raw) {
  const mechanisms = [];
  let redirect = null;
  for (const token of raw.trim().split(/\s+/).slice(1)) {
    const eq = token.indexOf("=");
    if (eq !== -1 && !token.slice(0, eq).includes(":")) {
      if (token.slice(0, eq).toLowerCase() === "redirect") redirect = token.slice(eq + 1);
      continue;
    }
    mechanisms.push(parseMechanism(token));
  }
  const all = mechanisms.find((m) => m.name === "all");
  return { raw, mechanisms, redirect, allQualifier: all ? all.qualifier : null };
}

function parseMechanism(token) {
  let qualifier = "+";
  if ("+-~?".includes(token[0])) {
    qualifier = token[0];
    token = token.slice(1);
  }
  const colon = token.indexOf(":");
  const name = (colon === -1 ? token : token.slice(0, colon)).split("/")[0].toLowerCase();
  const value = colon === -1 ? null : token.slice(colon + 1) || null;
  return { qualifier, name, value };
}

export async function checkSpf(domain, resolver) {
  const answer = await resolver.txt(domain);
  const empty = {
    seen: answer.records,
    record: null,
    allQualifier: null,
    lookups: 0,
    voidLookups: 0,
  };
  if (answer.outcome === "timeout") return { ...empty, findings: [finding("DNS_TIMEOUT")] };
  const found = selectSpfRecords(answer.records);
  if (found.length === 0) return { ...empty, findings: [finding("SPF_MISSING")] };
  // RFC 7208 §4.5: two records is a permerror, so nothing else matters
  if (found.length > 1) return { ...empty, findings: [finding("SPF_MULTIPLE")] };

  const record = parseSpfRecord(found[0]);
  const tally = {
    lookups: 0,
    voidLookups: 0,
    loop: false,
    broken: [],
    usesPtr: false,
    timedOut: false,
  };
  const allQualifier = await countSpfLookups(record, domain, resolver, tally, [domain]);
  return {
    seen: answer.records,
    record: record.raw,
    allQualifier,
    lookups: tally.lookups,
    voidLookups: tally.voidLookups,
    findings: spfFindings(allQualifier, tally),
  };
}

// Counting is static, the way checkers do it: every include and redirect is
// followed, not only the path one message would take.
export async function countSpfLookups(record, domain, resolver, tally, path) {
  for (const term of record.mechanisms) {
    if (!LOOKUP_MECHANISMS.includes(term.name)) continue;
    tally.lookups += 1;
    if (term.name === "ptr") tally.usesPtr = true;
    else if (term.name === "include" && term.value) await follow(term.value, resolver, tally, path);
    else if (term.name !== "include") await checkTarget(term, domain, resolver, tally);
  }
  // RFC 7208 §6.1: redirect is ignored when the record has an all mechanism
  if (record.redirect === null || record.allQualifier !== null) return record.allQualifier;
  tally.lookups += 1;
  return follow(record.redirect, resolver, tally, path);
}

async function follow(target, resolver, tally, path) {
  // Macros expand per message, so the target can't be known ahead of time.
  if (target.includes("%")) return null;
  target = target.toLowerCase().replace(/\.$/, "");
  if (path.includes(target) || path.length > MAX_DEPTH) {
    tally.loop = true;
    return null;
  }
  const answer = await resolver.txt(target);
  if (answer.outcome === "timeout") {
    tally.timedOut = true;
    return null;
  }
  if (isVoid(answer)) tally.voidLookups += 1;
  const found = selectSpfRecords(answer.records);
  if (found.length !== 1) {
    // RFC 7208 §5.2: an include target with no (or two) SPF records is a permerror
    tally.broken.push(target);
    return null;
  }
  return countSpfLookups(parseSpfRecord(found[0]), target, resolver, tally, [...path, target]);
}

async function checkTarget(term, domain, resolver, tally) {
  const target = (term.value ?? domain).split("/")[0];
  if (target.includes("%")) return;
  const answer = term.name === "mx" ? await resolver.mx(target) : await resolver.address(target);
  if (answer.outcome === "timeout") tally.timedOut = true;
  else if (isVoid(answer)) tally.voidLookups += 1;
}

export function spfFindings(allQualifier, tally) {
  const findings = [];
  // RFC 7208 §4.6.4: more than 10 lookups is a permerror. A loop would hit the
  // same limit during real evaluation, so it's reported the same way.
  if (tally.lookups > MAX_LOOKUPS || tally.loop) {
    const detail = tally.loop ? "include loop" : `${tally.lookups} lookups`;
    findings.push(finding("SPF_TOO_MANY_LOOKUPS", detail));
  }
  if (tally.voidLookups > MAX_VOID_LOOKUPS) {
    findings.push(finding("SPF_VOID_LOOKUPS", `${tally.voidLookups} void lookups`));
  }
  for (const target of tally.broken) findings.push(finding("SPF_INCLUDE_BROKEN", target));
  if (tally.usesPtr) findings.push(finding("SPF_PTR"));
  if (tally.timedOut) findings.push(finding("DNS_TIMEOUT", "SPF include"));

  if (allQualifier === "+") findings.push(finding("SPF_PASS_ALL"));
  else if ((allQualifier === "?" || allQualifier === null) && !tally.broken.length) {
    findings.push(finding("SPF_NEUTRAL_ALL"));
  } else if (allQualifier === "~") findings.push(finding("SPF_SOFTFAIL_ALL"));
  return findings;
}

// MX (RFC 5321, RFC 7505)

export function parseMxRecords(records) {
  return records
    .map((record) => {
      const [preference, host = ""] = record.trim().split(/\s+/);
      const lower = host.toLowerCase();
      // Keep the lone "." of a null MX; strip the trailing dot from real hosts
      const name = lower === "." ? "." : lower.replace(/\.$/, "");
      return { preference: Number(preference), host: name };
    })
    .sort((a, b) => a.preference - b.preference || a.host.localeCompare(b.host));
}

// RFC 7505 §3: exactly one MX, preference 0, host "."
export function isNullMx(hosts) {
  return hosts.length === 1 && hosts[0].preference === 0 && hosts[0].host === ".";
}

export async function checkMx(domain, resolver) {
  const answer = await resolver.mx(domain);
  if (answer.outcome === "timeout") {
    return { hosts: [], nullMx: false, receivesMail: false, findings: [finding("DNS_TIMEOUT")] };
  }
  const hosts = parseMxRecords(answer.records);
  if (!hosts.length) {
    return { hosts, nullMx: false, receivesMail: false, findings: [finding("MX_NONE")] };
  }
  if (isNullMx(hosts)) {
    return { hosts, nullMx: true, receivesMail: false, findings: [finding("MX_NULL")] };
  }
  return { hosts, nullMx: false, receivesMail: true, findings: [] };
}

// Transport and DKIM. A browser can't fetch MTA-STS policy files (no CORS
// headers on those servers), so only the TXT records are read here.

export async function checkMtaStsRecord(domain, resolver) {
  const answer = await resolver.txt(`_mta-sts.${domain}`);
  const record = answer.records.find((r) => r.replaceAll(" ", "").startsWith("v=STSv1")) ?? null;
  return { record, findings: record ? [] : [finding("MTASTS_MISSING")] };
}

export async function checkTlsRpt(domain, resolver) {
  const answer = await resolver.txt(`_smtp._tls.${domain}`);
  const record = answer.records.find((r) => r.replaceAll(" ", "").startsWith("v=TLSRPTv1")) ?? null;
  return { record, findings: record ? [] : [finding("TLSRPT_MISSING")] };
}

export function looksLikeDkimKey(record) {
  return record.split(";").some((part) => {
    const eq = part.indexOf("=");
    return eq !== -1 && part.slice(0, eq).trim().toLowerCase() === "p";
  });
}

export async function checkDkim(domain, resolver) {
  const answers = await Promise.all(
    COMMON_SELECTORS.map((s) => resolver.txt(`${s}._domainkey.${domain}`)),
  );
  const selectors = COMMON_SELECTORS.filter((_, i) => answers[i].records.some(looksLikeDkimKey));
  const findings = selectors.length
    ? [finding("DKIM_FOUND", selectors.join(", "))]
    : [finding("DKIM_UNKNOWN")];
  return { selectors, findings };
}

// Whole domain

export function nonMailFindings(mx, spf, level) {
  // A domain that takes no mail should say it sends none either (CCCS ITSP.40.065).
  if (mx.receivesMail || mx.findings.some((f) => f.code === "DNS_TIMEOUT")) return [];
  const spfText = (spf.record ?? "").toLowerCase().split(/\s+/).join(" ");
  const locked = spfText === "v=spf1 -all";
  return locked && level === 3 ? [] : [finding("NON_MAIL_DOMAIN_OPEN")];
}

export async function checkDomain(domain, resolver) {
  const apex = await resolver.txt(domain);
  if (apex.outcome === "nxdomain") {
    return { domain, level: 0, error: "nxdomain", findings: [finding("DNS_NXDOMAIN")] };
  }
  const [dmarc, spf, mx, mtaSts, tlsRpt, dkim] = await Promise.all([
    checkDmarc(domain, resolver),
    checkSpf(domain, resolver),
    checkMx(domain, resolver),
    checkMtaStsRecord(domain, resolver),
    checkTlsRpt(domain, resolver),
    checkDkim(domain, resolver),
  ]);
  const findings = [
    ...mx.findings,
    ...nonMailFindings(mx, spf, dmarc.level),
    ...dmarc.findings,
    ...spf.findings,
    ...mtaSts.findings,
    ...tlsRpt.findings,
    ...dkim.findings,
  ];
  const error = findings.some((f) => f.code === "DNS_TIMEOUT") ? "timeout" : null;
  return { domain, level: dmarc.level, error, findings, dmarc, spf, mx, mtaSts, tlsRpt, dkim };
}

// DNS-over-HTTPS

export function normalizeTxtData(data) {
  // dns.google returns TXT data either bare or as quoted strings, and a long
  // record split into several strings means one value (RFC 7208 §3.3).
  const trimmed = data.trim();
  if (!trimmed.startsWith('"')) return trimmed;
  // Each match is one quoted string; \" inside it is an escaped quote.
  const quoted = [...trimmed.matchAll(/"((?:[^"\\]|\\.)*)"/g)];
  const parts = quoted.map((match) => match[1].replace(/\\(.)/g, "$1"));
  return parts.join("");
}

export function answerFromDoh(json, type) {
  if (json.Status === 3) return { outcome: "nxdomain", records: [] };
  if (json.Status !== 0) return { outcome: "timeout", records: [] };
  const rows = (json.Answer ?? []).filter((row) => row.type === RR_TYPES[type]);
  if (!rows.length) return { outcome: "empty", records: [] };
  const records = rows.map((row) => (type === "TXT" ? normalizeTxtData(row.data) : row.data));
  return { outcome: "ok", records };
}

export function createLimiter(limit) {
  let active = 0;
  const waiting = [];
  const release = () => {
    active -= 1;
    if (waiting.length) waiting.shift()();
  };
  return async function run(task) {
    if (active >= limit) await new Promise((resolve) => waiting.push(resolve));
    active += 1;
    try {
      return await task();
    } finally {
      release();
    }
  };
}

export function createDohResolver(fetchImpl = fetch) {
  const run = createLimiter(MAX_IN_FLIGHT);
  const query = (name, type) =>
    run(async () => {
      const url = `${DOH_URL}?name=${encodeURIComponent(name)}&type=${type}`;
      let response;
      try {
        response = await fetchImpl(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
      } catch (err) {
        if (err.name === "TimeoutError") return { outcome: "timeout", records: [] };
        throw err;
      }
      if (!response.ok) return { outcome: "timeout", records: [] };
      return answerFromDoh(await response.json(), type);
    });
  return {
    txt: (name) => query(name, "TXT"),
    mx: (name) => query(name, "MX"),
    async address(name) {
      const answer = await query(name, "A");
      return answer.outcome === "empty" ? query(name, "AAAA") : answer;
    },
  };
}
