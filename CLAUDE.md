# CLAUDE.md

SpoofCheck BC reads public DNS records of B.C. public bodies and reports how well each domain is protected against email spoofing. Owner: Ankur (TRU Computing Science). This is a portfolio project, so the code must be something he can explain line by line in an interview.

Read before doing anything:
- `docs/SPEC.md`: what to build, the rules, milestones.
- `docs/DESIGN.md` and `docs/design-reference/index.html`: how the site looks.
- `docs/FINDINGS.md` / `data/findings.json`: every finding code and its wording.
- `tests/vectors/`: expected behaviour for tricky cases. These are the contract.

## How we work

- One milestone at a time, in the order in `docs/SPEC.md` §12. Don't start the next one until Ankur says so.
- Start every milestone by writing a short plan: files you'll create or change, functions with their signatures, tests you'll add, anything you're unsure about. Wait for Ankur's OK before writing code.
- Commit in small steps that each leave the tests passing. A good size is one function plus its tests. Never commit a whole milestone in one go.
- Never push, create a remote, publish, or run anything on a schedule unless Ankur asks in that message.
- End each milestone with: what you built, what you'd question in review, and three things Ankur should be able to explain about it. Keep that under 15 lines.
- If the spec, a test vector and the RFC disagree, stop and ask. Don't pick one quietly.

## Stack and commands

- Python 3.12, managed with `uv`. `src/` layout, package name `spoofcheck`, console script `spoofcheck`.
- Runtime deps: `dnspython`, `typer`, `jinja2`, `httpx`. Dev deps: `pytest`, `pytest-asyncio`, `ruff`, `mypy`, `playwright`, `axe-playwright-python`.
- No other dependencies without asking first. No ORM, no web framework, no CSS framework, no chart or icon library, no JS build step.

```
uv sync                         # install
uv run pytest                   # Python tests, including vectors
node --test web/*.test.js       # browser checker tests against the same vectors
uv run ruff check . && uv run ruff format --check .
uv run mypy src
uv run spoofcheck check example.ca
uv run spoofcheck build-site --out site/ && python -m http.server -d site 8000
```

## Code style

The code should read like it was written by one careful engineer who knows DNS, not generated in bulk.

- Name things after the domain: `parse_dmarc_record`, `count_spf_lookups`, `NullMx`. Never `utils.py`, `helpers.py`, `common.py`, `manager`, `handler`, `processor`, `data`, `info`, `result2`.
- Small modules with one job each, matching the layout in `docs/SPEC.md` §10. Functions short enough to read without scrolling.
- Plain functions and frozen dataclasses. No class with a single method, no abstract base class with a single implementation, no factories, no dependency-injection containers.
- Type hints everywhere; `mypy` must pass with `strict = true` on `src/`.
- Comments explain *why*, never *what*. Cite the RFC section where a rule comes from: `# RFC 7208 §4.6.4: more than 10 lookups is a permerror`. No banner comments, no comment above every line, no "This function does X" docstrings on obvious functions. Docstrings only on public functions whose behaviour isn't obvious from the name and types.
- Catch specific exceptions (`dns.resolver.NXDOMAIN`, `NoAnswer`, `LifetimeTimeout`) where they can actually happen and turn them into findings. No bare `except`, no `except Exception: pass`, no wrapping every call in try/except "to be safe".
- No dead code, no commented-out code, no `TODO` left behind at the end of a milestone, no placeholder functions that return fake data.
- No print statements for debugging. User-facing output goes through the CLI layer only. Log messages are short and lowercase: `scan finished: 20 domains, 2 timeouts`.
- No emoji in code, comments, logs, CLI output, commit messages or docs.
- Config is a few constants at the top of the module that uses them. No YAML config system.
- JavaScript in `web/check.js`: plain ES modules, `const`/`let`, small named functions, no classes unless there's state, no frameworks, no bundler.

## Tests

- Every parser and rule gets tests from `tests/vectors/*.json`, loaded by one parametrised test per file, with the vector's `name` as the test id.
- DNS is faked with a small `FakeResolver` built from a vector's `zone`. Unit tests never touch the network.
- A separate `tests/live/` folder may hit real DNS for two or three domains; mark it `@pytest.mark.live` and skip it by default.
- Test names describe behaviour: `test_pct_below_100_lowers_reject_to_partial`, not `test_dmarc_1`.
- When you fix a bug, add a vector or test that fails first.

## Ethics and safety (hard rules)

- Read only public DNS and the public MTA-STS policy file. Never connect to a mail server, never send email, never scan ports, never request any other URL on a scanned domain.
- At most 4 lookups in flight, 5 second timeout, one scan per week. Identify HTTP requests with `User-Agent: SpoofCheckBC/<version> (+<repo url>)`.
- `PUBLISH_NAMED` stays `False`. The public site and committed files contain aggregates only. The SQLite file is in `.gitignore` and never committed.
- Every page footer carries: "Independent student project. Not affiliated with the Government of British Columbia or any organization listed."
- Don't use B.C. government logos, crests, the BC Sans font, or anything that makes the site look official.
- Never put real organizations in made-up examples. Use `example.ca`, `riverbend.example` and the fictional Village of Riverbend.

## Design rules (summary; full version in docs/DESIGN.md)

- Copy the CSS custom properties from `docs/design-reference/index.html` exactly. One stylesheet, `site/assets/site.css`, hand-written.
- No purple, violet or indigo. No decorative gradients, glass effects or blurred blobs.
- Archivo for all text, using its width axis for headings; Martian Mono only for DNS records and domain names.
- The postmark stamp and the security tint pattern are the only decorative elements. Don't add others.
- No icon libraries and no emoji. Severity marks are the CSS shapes in the reference.
- No all-caps labels above headings, no middle-dot meta strings, no arrows appended to links, no scroll-triggered animations. The only animation is the stamp landing once, and it's off under `prefers-reduced-motion`.
- Mobile-first. Must work at 360 px wide with no horizontal page scroll.

### Self-check after any change to the site

Do this before saying a site task is done:

1. `uv run spoofcheck build-site --out site/` and serve it.
2. Take full-page Playwright screenshots at 390 × 844 and 1280 × 900, in light and dark colour schemes, with reduced motion on.
3. Open the reference page at the same sizes and compare. List every visible difference and fix the ones that aren't intentional.
4. Check `document.documentElement.scrollWidth` equals the viewport width at 360 and 390 px.
5. Run axe on every page with `axe-playwright-python` and fix any violation of impact `serious` or `critical`.
6. Tab through the checker form and confirm the focus ring is visible on every control.

Report what you checked and anything you couldn't fix.

## Writing

- Site copy follows the "Words" section of `docs/DESIGN.md`. Plain verbs, sentence case, no marketing language.
- Banned words in code, docs, UI and commits: seamless, robust, comprehensive, powerful, leverage, empower, unlock, elevate, delve, effortless, cutting-edge, game-changer, streamline, harness.
- Don't write `README.md`. Ankur writes it from `docs/README_OUTLINE.md`. You may suggest edits when asked.
- Commit messages: imperative, specific, under 72 characters for the subject, body only when the why isn't obvious. Good: `Count void lookups across nested SPF includes`. Bad: `feat: implement comprehensive SPF analysis module`.
