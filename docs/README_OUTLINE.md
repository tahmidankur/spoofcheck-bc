# README outline

Write the README yourself, in first person, using these headings. Answer each question in a few plain sentences. A recruiter should be able to read the top half in under a minute.

Keep it short. No badges wall, no emoji, no "Features" list of twelve bullets.

## SpoofCheck BC

One sentence: what it does. One sentence: who it's for.

A screenshot of a result envelope (light mode) and the live site link.

## Why I built this

- What made you think about email spoofing? (A scam email you or someone you know received? Something from your Network Security course?)
- Why B.C. public bodies specifically, and not federal domains? (The federal government already tracks its own.)
- What surprised you once you ran the first real scan?

## What it checks

Three or four sentences, not a table. DMARC sets the level; SPF, MX, MTA-STS, TLS-RPT and DKIM add findings. Link to `docs/FINDINGS.md`.

## How it works

- The diagram from `docs/SPEC.md` §10, or a simpler one you draw.
- One paragraph on the hardest part. (Probably SPF lookup counting through nested includes, or keeping the Python and JavaScript versions in agreement.)
- One paragraph on testing: shared vectors, fake DNS zones, CI.

## Ethics and limits

- What it reads, and what it never does.
- Why the public site shows only totals, and how you tell organizations about their own results.
- Why snapshots use HMAC keys instead of domain names.
- What it can't tell you.

## Run it yourself

```bash
uv sync
uv run spoofcheck check example.ca
```

## What I'd do next

Two or three honest items. Examples: universities and colleges, DMARC aggregate report parsing for organizations that opt in, a per-organization page after the disclosure period.

## Built with

Python, dnspython, Typer, Jinja2, plain JavaScript and CSS. Say plainly how you used Claude Code (for example: "I wrote the spec and test vectors, made the design decisions, and used Claude Code to implement milestones, which I reviewed and revised").
