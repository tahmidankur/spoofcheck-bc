import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  answerFromDoh,
  checkDomain,
  checkSpf,
  createDohResolver,
  createLimiter,
  evaluateDmarc,
  normalizeDomain,
  normalizeTxtData,
} from "./check.js";

const vectors = (name) =>
  JSON.parse(readFileSync(new URL(`../tests/vectors/${name}`, import.meta.url))).cases;

const VECTOR_CHECKS = new Set(["DMARC", "SPF", "MX", "NON", "DNS"]);
const codes = (findings) => new Set(findings.map((f) => f.code));
const vectorCodes = (findings) =>
  new Set(findings.map((f) => f.code).filter((c) => VECTOR_CHECKS.has(c.split("_")[0])));

// Same idea as tests/fakes.py: a missing name is NXDOMAIN, a missing type is empty.
function fakeResolver(zone) {
  const normal = (name) => name.toLowerCase().replace(/\.$/, "");
  const records = Object.fromEntries(Object.entries(zone).map(([k, v]) => [normal(k), v]));
  const lookup = async (name, type) => {
    const entry = records[normal(name)];
    if (!entry) return { outcome: "nxdomain", records: [] };
    if (!entry[type]?.length) return { outcome: "empty", records: [] };
    return { outcome: "ok", records: entry[type] };
  };
  return {
    txt: (name) => lookup(name, "TXT"),
    mx: (name) => lookup(name, "MX"),
    async address(name) {
      const answer = await lookup(name, "A");
      return answer.outcome === "empty" ? lookup(name, "AAAA") : answer;
    },
  };
}

for (const vector of vectors("dmarc.json")) {
  test(`dmarc: ${vector.name}`, () => {
    const result = evaluateDmarc(vector.txt);
    const { expect } = vector;
    assert.equal(result.level, expect.level);
    if ("policy" in expect) assert.equal(result.policy, expect.policy);
    if ("pct" in expect) assert.equal(result.record?.pct, expect.pct);
    if ("subdomain_policy" in expect) assert.equal(result.record?.subdomainPolicy, expect.subdomain_policy);
    assert.deepEqual(codes(result.findings), new Set(expect.findings));
  });
}

for (const vector of vectors("spf.json")) {
  test(`spf: ${vector.name}`, async () => {
    const result = await checkSpf(vector.domain, fakeResolver(vector.zone));
    const { expect } = vector;
    if ("all" in expect) assert.equal(result.allQualifier, expect.all);
    if ("lookups" in expect) assert.equal(result.lookups, expect.lookups);
    if ("void_lookups" in expect) assert.equal(result.voidLookups, expect.void_lookups);
    assert.deepEqual(codes(result.findings), new Set(expect.findings));
  });
}

for (const vector of vectors("domain.json")) {
  test(`domain: ${vector.name}`, async () => {
    const result = await checkDomain(vector.domain, fakeResolver(vector.zone));
    assert.equal(result.level, vector.expect.level);
    assert.deepEqual(vectorCodes(result.findings), new Set(vector.expect.findings));
  });
}

test("quoted and split TXT strings are joined", () => {
  assert.equal(normalizeTxtData('"v=spf1 include:a.example " "-all"'), "v=spf1 include:a.example -all");
  assert.equal(normalizeTxtData('"v=DMARC1; p=reject"'), "v=DMARC1; p=reject");
});

test("bare TXT data is kept as it is", () => {
  assert.equal(normalizeTxtData("v=spf1 -all"), "v=spf1 -all");
});

test("DoH status 3 is NXDOMAIN and a CNAME-only answer is empty", () => {
  assert.equal(answerFromDoh({ Status: 3 }, "TXT").outcome, "nxdomain");
  const cnameOnly = { Status: 0, Answer: [{ type: 5, data: "elsewhere.example." }] };
  assert.equal(answerFromDoh(cnameOnly, "TXT").outcome, "empty");
});

test("DoH answers keep only rows of the asked type", () => {
  const json = {
    Status: 0,
    Answer: [
      { type: 5, data: "selector1-example-ca._domainkey.mailhost.example." },
      { type: 16, data: '"v=DKIM1; p=MIIB"' },
    ],
  };
  assert.deepEqual(answerFromDoh(json, "TXT"), { outcome: "ok", records: ["v=DKIM1; p=MIIB"] });
});

test("resolver never has more than four requests in flight", async () => {
  let active = 0;
  let peak = 0;
  const slowFetch = async () => {
    active += 1;
    peak = Math.max(peak, active);
    await new Promise((resolve) => setTimeout(resolve, 5));
    active -= 1;
    return { ok: true, json: async () => ({ Status: 0, Answer: [] }) };
  };
  const resolver = createDohResolver(slowFetch);
  await Promise.all(Array.from({ length: 12 }, (_, i) => resolver.txt(`n${i}.example.ca`)));
  assert.equal(peak, 4);
});

test("limiter runs every task even when they queue", async () => {
  const run = createLimiter(1);
  const results = await Promise.all([1, 2, 3].map((n) => run(async () => n * 2)));
  assert.deepEqual(results, [2, 4, 6]);
});

test("typed input becomes a bare domain or null", () => {
  assert.equal(normalizeDomain(" Staff@Riverbend.Example. "), "riverbend.example");
  assert.equal(normalizeDomain("https://example.ca/"), null);
});
