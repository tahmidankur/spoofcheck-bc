# Building SpoofCheck BC with Claude Code

Paste these prompts one at a time. Each one is a milestone from `docs/SPEC.md` §12. Don't paste the next until you've reviewed the last one and can answer its "Explain it back" questions without looking.

## Before you start (Mac)

```bash
brew install uv node git          # skip any you already have
mkdir -p ~/code && cd ~/code
unzip ~/Downloads/spoofcheck-bc-kit.zip -d spoofcheck-bc
cd spoofcheck-bc
git init && git add . && git commit -m "Add project spec, design reference and test vectors"
claude                            # start Claude Code in this folder
```

Claude Code reads `CLAUDE.md` on its own. Don't run `/init`; the file is already written and `/init` would rewrite it.

Open `docs/design-reference/index.html` in your browser once so you know what you're aiming for.

---

## Kickoff

```
Read CLAUDE.md, docs/SPEC.md, docs/DESIGN.md, docs/FINDINGS.md and tests/vectors/README.md, then skim the three vector files.

Don't write any code yet. In 10 lines or fewer, tell me what you understood the project to be. Then list anything in the spec or vectors that is ambiguous, contradicts an RFC, or that you'd push back on.
```

Answer its questions yourself. Decisions you make here are things you can talk about in interviews.

## M0: Project setup

```
Start milestone M0 from docs/SPEC.md. Plan first and wait for my OK.

Scope:
- pyproject.toml for a uv-managed package `spoofcheck` with a src/ layout, Python 3.12, console script `spoofcheck`, the runtime and dev dependencies listed in CLAUDE.md, and ruff + mypy (strict on src/) + pytest config in the same file.
- .gitignore covering .venv, __pycache__, *.db, .env, site/, test screenshots.
- src/spoofcheck/__init__.py with __version__ = "0.1.0".
- A Typer app in cli.py with a `version` command only.
- tests/test_vectors_load.py that loads each vector file and checks every case has a name and an expect block.
- .github/workflows/ci.yml that runs ruff check, ruff format --check, mypy and pytest on push and pull request. Leave a commented-out step for `node --test web/`; we add it in M6.

Done when `uv run pytest`, `uv run ruff check .` and `uv run mypy src` all pass. Commit in two or three small commits.
```

**Explain it back:** What does the `src/` layout protect you from? Why is mypy strict only on `src/`? What would CI catch that your laptop wouldn't?

## M1: DMARC

```
Start M1: DMARC. Plan first and wait for my OK.

Build:
- resolver.py: a thin async wrapper around dns.asyncresolver with a 5 second lifetime. One function per record type we need (txt, mx). TXT records made of several strings must be joined before returning. Map NXDOMAIN, NoAnswer and timeouts to a small set of outcomes the checks can turn into findings. Include a FakeResolver for tests that's built from a vector "zone" dict, in tests/fakes.py, not in src/.
- findings.py: load data/findings.json once, expose a frozen Finding dataclass and a lookup by code. Unknown codes raise.
- dmarc.py: parse a record into tags, select records per RFC 7489 §6.6.3, apply the p-missing-with-rua rule, compute the level from docs/SPEC.md §5, and return a DmarcResult plus findings. DMARC_REPORT_DEST_UNAUTHORIZED is part of this milestone; it needs the resolver.
- cli.py: `spoofcheck check <domain>` prints the raw record, the parsed tags in plain English, the level and the findings. Add --json.

Tests: one parametrised test over tests/vectors/dmarc.json, plus focused tests for the external report destination check using FakeResolver. Every DMARC vector must pass.
```

**Explain it back:** Why are two DMARC records treated as none? Why does a missing `p` with a valid `rua` count as `p=none`? What does `pct=50` do to a reject policy?

## M2: SPF and MX

```
Start M2: SPF and MX. Plan first and wait for my OK.

Build:
- spf.py: parse mechanisms and modifiers, find the effective `all` (including through redirect=), count DNS-querying terms recursively through include and redirect, count void lookups, detect loops, and stop at depth 10. Follow the counting rules written in tests/vectors/spf.json's description exactly, including how macros are handled.
- mx.py: MX hosts, null MX detection (RFC 7505), no-MX.
- scanner.py: check_domain(domain, resolver) runs DMARC, SPF and MX together and applies the whole-domain rules: NON_MAIL_DOMAIN_OPEN and "NXDOMAIN reports only DNS_NXDOMAIN". Lookups run concurrently, at most 4 at a time.
- Extend `spoofcheck check` output with an SPF section (record, all qualifier in plain English, a "7 of 10 lookups used" line) and an MX line.

Tests: parametrised over spf.json and domain.json. All must pass.
```

**Explain it back:** Walk through how your code counts lookups for the "nested includes over the limit" vector. What is a void lookup and why do receivers care? Why do parked domains need `v=spf1 -all`?

## M3: Transport security and DKIM

```
Start M3. Plan first and wait for my OK.

Build:
- transport.py: MTA-STS TXT check, then one HTTPS fetch of https://mta-sts.<domain>/.well-known/mta-sts.txt with httpx, a 5 second timeout and the User-Agent from CLAUDE.md; read the mode. TLS-RPT TXT check.
- dkim.py: try the selector list from docs/SPEC.md §4.5 in parallel (still within the global limit of 4 in flight). A TXT record containing p= counts as a key. Report DKIM_FOUND with the selectors, or DKIM_UNKNOWN.
- Add both to check_domain and the CLI output.

Tests: fake the HTTPS fetch with httpx.MockTransport and DNS with FakeResolver. Cover: policy in enforce mode, testing mode, TXT present but fetch fails, nothing published, DKIM found at selector1, DKIM not found.
```

**Explain it back:** Why can't you list a domain's DKIM selectors? What does MTA-STS protect against that DMARC doesn't?

## M4: Inventory, scan and history

```
Start M4. Plan first and wait for my OK.

Build:
- inventory.py: load and validate data/inventory.csv (allowed sectors, valid hostnames, no duplicate domains). `spoofcheck inventory check` prints problems and lists rows with verified=no.
- store.py: sqlite3 with numbered migration files in src/spoofcheck/migrations/ tracked by PRAGMA user_version, using the schema in docs/SPEC.md §7.2. No ORM.
- `spoofcheck scan` (with --only-sector): scan every inventory domain, save one scan row and one result row per domain with its findings, print a short summary.
- `spoofcheck diff`: what changed between the last two scans, by domain, locally only.
- snapshot.py and `spoofcheck snapshot`: write data/snapshots/<iso-week>.json with the aggregates and HMAC-keyed levels from docs/SPEC.md §7.3. Read SNAPSHOT_KEY from the environment and fail with a clear message if it's missing. Compare with the previous snapshot to fill in moved-up and moved-down counts.

Tests: inventory validation, migrations on a fresh in-memory DB, a scan over a 3-domain fake zone, snapshot contents (assert no domain string appears anywhere in the JSON), and diff.
```

Then run it for real: `uv run spoofcheck inventory check`, open each seed organization's official website, fix any wrong domains, set `verified` to `yes`, and run `uv run spoofcheck scan`.

**Explain it back:** Why HMAC and not SHA-256 on its own? What happens on the first week, when there's no previous snapshot?

## M5: Static site

```
Start M5: the static site. Plan first and wait for my OK.

Match docs/design-reference/index.html. Copy its CSS custom properties, type settings, postmark SVG, security tint and component styles into site/assets/site.css and Jinja2 templates under src/spoofcheck/site/templates/. Don't redesign anything.

Pages: / (checker placeholder form, this week's sentence, sector bars, legend, table in <details>, 12-week trend, moved count), /method/, /fix/ (one section per finding code from data/findings.json, with example records), /about/ (leave the "why I built this" paragraph as a clearly marked gap for me to write).

Data comes only from data/snapshots/*.json and data/findings.json. The trend SVG is generated in Python like the reference does. The checker form is static in this milestone.

`spoofcheck build-site --out site/` produces plain HTML/CSS with no JavaScript yet.

Finish with the full self-check in CLAUDE.md and show me the screenshots next to the reference.
```

**Explain it back:** Why is the sector chart HTML and not SVG? Where does every number on the home page come from?

## M6: In-browser checker

```
Start M6: the in-browser checker. Plan first and wait for my OK.

Build web/check.js as a plain ES module, plus web/check.test.js for node --test:
- Port the DMARC, SPF and MX rules from the Python package. Keep function names parallel to the Python ones so the two are easy to compare.
- Load tests/vectors/*.json in the Node tests and make every case pass. Use the same fake-zone idea as the Python tests.
- DNS goes through the DNS-over-HTTPS JSON API at https://dns.google/resolve. Normalise TXT answers: strip surrounding quotes and join split strings, with tests for both shapes. Treat Status 3 as NXDOMAIN.
- Keep the 10-lookup and loop limits in the browser too, and never fire more than 4 requests at once.
- Render the result envelope exactly like the reference: postmark (with the stamp animation, off under reduced motion), records with plain-English readings, lookup meter, "What to fix, in order", "Also checked". MTA-STS shows "TXT record only; the policy file can't be checked from a browser".
- If the domain is in the inventory, show the organization name. Build-site writes that map as site/assets/orgs.json.
- Errors in the interface's voice: what went wrong and what to do next.
- Enable the node step in ci.yml.

Then build the site, check a few domains for real in a browser, confirm the requests aren't blocked by CORS, and run the self-check.
```

**Explain it back:** How do you know the JavaScript and Python give the same answers? What does the visitor's browser send to Google?

## M7: Weekly automation and disclosure

```
Start M7. Plan first and wait for my OK. Don't push anything; I'll do it.

Build:
- .github/workflows/weekly.yml: runs on a weekly cron (Mondays, a minute that isn't :00) and on workflow_dispatch. Steps: install with uv, `spoofcheck scan`, `spoofcheck snapshot` using the SNAPSHOT_KEY secret, commit only the new file in data/snapshots/ with a plain message, `spoofcheck build-site`, deploy site/ to GitHub Pages with the official Pages actions. Minimal permissions per job.
- disclose.py and `spoofcheck disclose "<org name>"`: print a short, polite markdown note to that organization's IT team, listing their findings with the fix text from the catalogue and a link to the fix guide. It never writes to disk and never sends anything.

Tell me exactly which repository settings and secrets I need to set, step by step.
```

## M8: Finish

Do this one yourself, with Claude Code as a reviewer:

1. Write `README.md` from `docs/README_OUTLINE.md` in your own words.
2. Take screenshots of the live site on your phone and laptop.
3. Record a 30–45 second screen capture of checking a domain.
4. Run the review prompt below and fix what it finds.

```
Review the whole repository against CLAUDE.md ("Code style", "Ethics and safety", "Writing") and docs/DESIGN.md ("What makes it look generated"). List every violation as file:line with one sentence each. Don't fix anything yet.
```

---

## If Claude Code drifts

```
Stop. Re-read the "Code style" section of CLAUDE.md. List which rules your last change breaks, then fix only those.
```

```
That's more than I asked for. Revert everything except <the part you want>, and tell me what you removed.
```

```
Before changing anything, explain in 5 lines why the current code fails this case, and which RFC section says what should happen.
```
