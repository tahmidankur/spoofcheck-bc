# SpoofCheck BC: product spec

Owner: Tahmid Hossain Ankur
Status: v1 live, scanning weekly
Last edited: 2026-10-28

## 1. The problem

Anyone can send an email that claims to come from `@yourcity.ca`. Receiving mail servers only know to throw that forged mail away if the real domain publishes the right DNS records: SPF (which servers may send for the domain), DKIM (a signature key), and DMARC (what receivers should do when a message fails both, plus where to send reports).

Federal domains are required to publish all three and to send DMARC reports to the Canadian Centre for Cyber Security (Treasury Board email configuration requirements, CCCS guidance ITSP.40.065). The federal government's own Tracker already grades federal domains.

Nobody tracks the same thing for B.C.'s provincial and local public bodies: municipalities, regional districts, school districts and health authorities. These are the senders whose names show up in property tax, school and health scams.

SpoofCheck BC reads their public DNS records every week, works out how well each domain is protected against spoofing, and publishes the overall picture plus a plain-language guide to fixing it.

## 2. Who uses it

| Person | What they want |
|---|---|
| A resident or journalist | "Is the overall picture getting better?" and "Can I check one domain myself?" |
| IT staff at a public body | "What exactly is wrong with our records and what do I change?" |

## 3. Scope

### In scope (v1)
- Inventory of B.C. public bodies and their primary email domain, each row with a source URL and a "verified by a human" flag.
- Passive checks of public DNS: DMARC, SPF (including counting DNS lookups across includes), MX, MTA-STS, TLS-RPT, and a probe of common DKIM selectors.
- One protection level per domain (section 5) plus a list of findings.
- A command-line tool for checking one domain or scanning the whole inventory.
- SQLite history so week-over-week changes can be reported.
- A static website: this week's summary, sector breakdown, trend, an in-browser checker, methodology, and a fix guide.
- A weekly GitHub Actions run that scans and commits a new snapshot; Vercel rebuilds the site on each push.
- A `disclose` command that writes a polite, private note for one organization explaining its findings.

### Out of scope (v1)
- Sending any email, or connecting to anyone's mail server.
- Port scanning, vulnerability scanning, login pages, anything beyond public DNS and the public MTA-STS policy file.
- First Nations governments and private companies.
- Universities and colleges (possible phase 2).
- A public ranked or named list of organizations (section 8).

## 4. Checks

All lookups go to a normal recursive resolver. Every check records the raw records it saw, so results can be audited later.

### 4.1 DMARC (RFC 7489)
- Query `TXT _dmarc.<domain>`. Keep only strings starting with `v=DMARC1`.
- Zero records: no policy. More than one: receivers must ignore all of them (RFC 7489 §6.6.3), so treat as no valid policy.
- Parse tags: `p`, `sp`, `pct`, `rua`, `ruf`, `adkim`, `aspf`, `fo`. Tag names and values are case-insensitive; ignore empty tags from trailing semicolons.
- A TXT string that contains `v=DMARC1` but doesn't start with it is not a DMARC record. Report it as `DMARC_SYNTAX` so the owner learns why, and treat the domain as having no record.
- If `p` is missing or invalid: when there is at least one valid `rua` URI, treat the record as `p=none` (RFC 7489 §6.6.3) and add `DMARC_SYNTAX`; otherwise there is no usable policy.
- `DMARC_NO_REPORTS` applies to any record that starts with `v=DMARC1` and has no valid `rua`.
- For each `rua` destination on a different domain, check the external authorization record `<domain>._report._dmarc.<destination-domain>` (RFC 7489 §7.1). Report-only finding.

### 4.2 SPF (RFC 7208)
- Query `TXT <domain>`. Keep strings starting with `v=spf1` (case-insensitive).
- More than one SPF record is a permanent error (§4.5).
- Parse mechanisms and modifiers. Note the `all` qualifier (`-`, `~`, `?`, `+`) and `redirect=`.
- Count DNS-querying terms recursively through `include` and `redirect`: `include`, `a`, `mx`, `ptr`, `exists`, `redirect`. More than 10 is a permanent error (§4.6.4).
- Count void lookups (NXDOMAIN or no answer). More than 2 is a permanent error (§4.6.4).
- Flag `ptr` (§5.5 says it SHOULD NOT be used).
- Stop recursion at depth 10 and on loops.

### 4.3 MX (RFC 5321, RFC 7505)
- Query `MX <domain>`. Record hosts and preferences.
- A single MX with preference 0 and host `.` is a null MX: the domain says it never receives mail.
- A domain with no MX or a null MX should usually publish `v=spf1 -all` and `p=reject`, since it should never send mail either. Rule for `NON_MAIL_DOMAIN_OPEN`: no MX or null MX, and either the SPF record is not exactly `v=spf1 -all` or the level is below 3.
- If the domain itself returns NXDOMAIN, report only `DNS_NXDOMAIN` and skip every other check.

### 4.4 Transport security
- MTA-STS (RFC 8461): `TXT _mta-sts.<domain>` with `v=STSv1`; if present, fetch `https://mta-sts.<domain>/.well-known/mta-sts.txt` once, with a 5 second timeout and our own User-Agent, and read `mode`.
- TLS-RPT (RFC 8460): `TXT _smtp._tls.<domain>` with `v=TLSRPTv1`.
- Both are informational. They protect mail in transit, not against spoofing.
- The in-browser checker reads only the two TXT records. It can't fetch the policy file, because those servers don't send CORS headers, and the result says so.

### 4.5 DKIM probe (RFC 6376)
- DKIM keys live at `<selector>._domainkey.<domain>`, and selectors cannot be listed. We only try a short list of common ones: `selector1`, `selector2` (Microsoft 365), `google`, `k1`, `s1`, `s2`, `default`, `dkim`, `mail`.
- Finding a key is reported as good. Not finding one is reported as "unknown", never as a failure.

## 5. Protection level

One level per domain, taken from DMARC alone, because DMARC is the record that tells receivers what to do with forged mail. SPF and DKIM problems show up as findings.

| Level | Stamp word | Rule | Plain meaning |
|---|---|---|---|
| 3 | ENFORCED | `p=reject`, and `pct` absent or 100 | Receivers are told to refuse forged mail. |
| 2 | PARTIAL | `p=quarantine`, or `p=reject` with `pct` below 100 | Forged mail is sent to spam, or only some of it is refused. |
| 1 | MONITORING | `p=none` | The domain collects reports but asks receivers to do nothing. |
| 0 | UNPROTECTED | No DMARC record, more than one, or invalid | Receivers get no instruction at all. |

The level never goes up because of anything else. Findings can still be serious at level 3 (for example an SPF record with too many lookups breaks SPF entirely).

## 6. Findings

Every finding has a stable code, a severity (`good`, `info`, `low`, `medium`, `high`), a one-line title, a plain explanation, a fix, and a reference. The catalogue lives in `data/findings.json` and is the single source for the CLI, the site and the in-browser checker. The full list with wording is in `docs/FINDINGS.md`.

## 7. Data

### 7.1 Inventory (`data/inventory.csv`)

```
org_name,sector,region,domain,source_url,verified,notes
```

- `sector`: `municipality`, `regional_district`, `school_district`, `health_authority`, `provincial`.
- `region`: one of the regional district names, free text for v1.
- `verified`: `yes` only after a person has opened `source_url` (the organization's official site) and confirmed the domain used in its staff email addresses.
- The seed file has about 20 well-known bodies marked `no`. Build the full list from the Accessible British Columbia Regulation list of prescribed public sector organizations (gov.bc.ca) and CivicInfo BC's local government directory.

### 7.2 SQLite (`spoofcheck.db`, never committed)

```sql
CREATE TABLE organization (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  sector TEXT NOT NULL,
  region TEXT,
  source_url TEXT,
  UNIQUE (name)
);

CREATE TABLE domain (
  id INTEGER PRIMARY KEY,
  organization_id INTEGER NOT NULL REFERENCES organization(id),
  name TEXT NOT NULL UNIQUE,
  verified INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE scan (
  id INTEGER PRIMARY KEY,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  tool_version TEXT NOT NULL,
  resolver TEXT NOT NULL,
  iso_week TEXT NOT NULL            -- e.g. 2026-W44
);

CREATE TABLE result (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scan(id),
  domain_id INTEGER NOT NULL REFERENCES domain(id),
  level INTEGER NOT NULL,           -- 0..3
  dmarc_raw TEXT,                   -- JSON list of strings seen
  dmarc_policy TEXT,
  dmarc_subdomain_policy TEXT,
  dmarc_pct INTEGER,
  spf_raw TEXT,
  spf_all TEXT,                     -- '-', '~', '?', '+', or NULL
  spf_lookups INTEGER,
  mx_hosts TEXT,                    -- JSON
  mta_sts_mode TEXT,
  tls_rpt INTEGER,
  dkim_selectors TEXT,              -- JSON list found
  error TEXT,                       -- e.g. 'timeout', 'nxdomain'
  UNIQUE (scan_id, domain_id)
);

CREATE TABLE finding (
  id INTEGER PRIMARY KEY,
  result_id INTEGER NOT NULL REFERENCES result(id),
  code TEXT NOT NULL,
  detail TEXT
);
```

Migrations: plain numbered `.sql` files in `src/spoofcheck/migrations/`, applied in order, tracked with `PRAGMA user_version`. No ORM.

### 7.3 Published snapshots (`data/snapshots/2026-W44.json`, committed)

- Aggregates: totals per level, per sector per level, count of domains that moved up or down since the previous snapshot, tool version, scan date.
- `levels_by_key`: each domain's level keyed by `HMAC-SHA256(SNAPSHOT_KEY, domain)` in hex. This lets next week's run work out who moved without the file naming anyone. A plain hash would not be enough, because the domain list is public and short enough to guess.
- `SNAPSHOT_KEY` comes from the environment: a GitHub Actions secret in CI and a git-ignored `.env` locally. Never committed, never logged.
- No domain or organization names anywhere in the file.

## 8. Publishing and ethics

- Only public DNS records and the public MTA-STS policy file are read. Nothing touches a mail server, and nothing is sent.
- Scans run at most once a week, with at most 4 lookups in flight and a 5 second timeout.
- The public site shows aggregates by sector. It does not publish a ranked or named list. Full per-domain history lives only in my local SQLite file; CI needs only the keyed levels in the last snapshot.
- `PUBLISH_NAMED` stays `false`. If that ever changes, it happens only after every organization in the list has been sent its disclosure note and given 60 days.
- The in-browser checker lets anyone check any one domain, the same way public lookup tools do. Queries go from the visitor's browser to a public DNS-over-HTTPS resolver, and the site says so.
- Every page carries: "Independent student project. Not affiliated with the Government of British Columbia or any organization listed." The site must not use B.C. government logos, the BC Sans typeface, or colours that imitate gov.bc.ca.

## 9. Command line

```
spoofcheck check kamloops.ca              # one domain, readable report in the terminal
spoofcheck check kamloops.ca --json       # same, as JSON
spoofcheck scan                           # whole inventory into SQLite
spoofcheck scan --only-sector school_district
spoofcheck diff                           # what changed since the previous scan
spoofcheck snapshot                       # write data/snapshots/<week>.json
spoofcheck build-site --out site/         # static site from snapshots + findings catalogue
spoofcheck disclose "City of Kamloops"    # private markdown note to the org, printed to stdout
spoofcheck inventory check                # validate inventory.csv, list unverified rows
```

Exit codes: `0` ok, `1` the checked domain has a `high` finding (useful in CI for anyone who reuses the tool), `2` usage or input error, `3` DNS failure.

## 10. Architecture

```
            data/inventory.csv
                    │
                    ▼
 ┌────────────── spoofcheck (Python 3.12) ─────────────────┐
 │ cli.py ─► scanner.py ─► resolver.py (dnspython, async)  │
 │                │                                         │
 │                ├─ dmarc.py   parse + level               │
 │                ├─ spf.py     parse + lookup counting     │
 │                ├─ mx.py                                  │
 │                ├─ transport.py  MTA-STS, TLS-RPT         │
 │                └─ dkim.py    common selector probe       │
 │                                                          │
 │ store.py (sqlite3) ◄── results          findings.py ◄── data/findings.json
 │ snapshot.py ─► data/snapshots/*.json                     │
 │ site/build.py (Jinja2) ─► site/  ─► Vercel               │
 └──────────────────────────────────────────────────────────┘

 web/check.js (copied to site/assets/ on build)  ─► DNS-over-HTTPS JSON API
         └── same rules, tested with node --test against tests/vectors/*.json
```

The exact expected behaviour for tricky cases is pinned down in `tests/vectors/` (DMARC, SPF and whole-domain cases with fake DNS zones). When this spec and a vector disagree, stop and ask; don't guess.

Two implementations of the parsing rules exist on purpose: Python for scans, JavaScript for the in-browser checker. Both must pass the same test vectors in `tests/vectors/`. That shared suite is how they are kept honest.

### Libraries
- Python: `dnspython`, `typer`, `jinja2`, `httpx` (MTA-STS fetch only). Dev: `pytest`, `ruff`, `mypy`.
- JavaScript: none. Plain ES modules, `fetch`, `node --test` for the vector tests.
- No CSS framework, no chart library, no icon library.

## 11. Website pages

| Page | Contents |
|---|---|
| `/` | Checker at the top. Then this week's sentence, sector chart, 12-week trend, what changed. |
| `/method/` | What is checked, how levels work, rate limits, what this cannot tell you. |
| `/fix/` | One section per finding code: what it means, what to change, example record. |
| `/about/` | Who made it and why, the disclaimer, contact, source code link. |

The look is defined in `docs/DESIGN.md` and drawn in `docs/design-reference/index.html`.

## 12. Build order

The order I built it in. Each step ended with the tests passing.

| # | Milestone | Done when | Rough time |
|---|---|---|---|
| M0 | Project setup | `uv run pytest` passes on an empty test; ruff and mypy run in CI | 1 hour |
| M1 | DMARC | `spoofcheck check <domain>` prints the DMARC record, parsed tags and level; vector tests pass | 1 evening |
| M2 | SPF and MX | Lookup counting works through nested includes; null MX handled; findings come from the catalogue | 1–2 evenings |
| M3 | Transport and DKIM | MTA-STS, TLS-RPT and DKIM probe in the report; network calls faked in tests | 1 evening |
| M4 | Inventory, scan, history | `scan`, `diff`, `snapshot`, `inventory check` work on the seed list | 1 evening |
| M5 | Static site | `build-site` output matches the design reference at 390 px and 1280 px | 1 weekend |
| M6 | Browser checker | `check.js` passes every vector with `node --test`; live check works on the built site | 1 weekend |
| M7 | Automation and disclosure | Weekly workflow scans, commits a snapshot, Vercel redeploys; `disclose` writes a note | 1 evening |
| M8 | Finish | README, screenshots, short demo recording | 1 evening |

M0 to M4 give a working command-line tool with history. M5 to M8 add the website, the browser checker and the weekly run.
