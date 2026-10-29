# SpoofCheck BC: design

The visual reference is `docs/design-reference/index.html`. Open it in a browser. When this file and the reference disagree, the reference wins. Copy its CSS tokens exactly; don't re-derive them.

## Idea

The site is about forged mail, so it borrows from the physical world of mail. Two details only:

1. **The postmark.** Every verdict is stamped onto the result like a cancellation mark: a ring with SPOOFCHECK BC on the top arc, the date on the bottom arc, the verdict word in a band across the middle, wavy cancellation lines to the right, rotated −7°, with a slight ink roughness. It's the one bold thing on the page.
2. **The security tint.** The inside of a privacy envelope is printed with a dense pattern so nobody can read the letter through the paper. A faint version of that pattern sits behind the checker, and only there.

Everything else stays quiet: left-aligned text, generous space, thin rules, no decoration that doesn't carry information.

## Colour

Light theme is the default. Dark theme switches on `prefers-color-scheme: dark` and on `data-theme="dark"`. Every pair below passes WCAG AA for body text.

| Token | Light | Dark | Use |
|---|---|---|---|
| `--page` | `#EEF1F0` | `#101B25` | Page background, a cool sorting-room grey |
| `--envelope` | `#FCFCFA` | `#16232F` | Envelope panels |
| `--window` | `#F4F7F8` | `#1B2A37` | Input "window" and record blocks |
| `--ink` | `#14212E` | `#E6EBEE` | Text, primary button |
| `--ink-soft` | `#4A5866` | `#A3B0BB` | Secondary text |
| `--rule` | `#C7D0D6` | `#2E3E4C` | Borders and dividers |
| `--tint` | `#3D5A80` | `#7E9CC2` | Security pattern, record left border |
| `--link` | `#1F4E8C` | `#8DB8EE` | Links, focus ring |
| `--lvl-3` | `#1C6B57` | `#5FC0A3` | ENFORCED |
| `--lvl-2` | `#8A5A00` | `#E0AE45` | PARTIAL |
| `--lvl-1` | `#56636F` | `#9AA8B4` | MONITORING |
| `--lvl-0` | `#B3261E` | `#F07A6E` | UNPROTECTED |

Rules:
- No purple, violet or indigo anywhere, including hover states, charts and focus rings.
- No gradients used as decoration. The only gradient in the CSS draws the half-filled "medium" severity mark.
- Level colours are only for level meaning. Never use green for a button or red for a heading.
- No pure black or pure white text on the page background; use `--ink` and `--envelope`.

## Type

| Role | Face | Settings |
|---|---|---|
| Everything readable | Archivo (variable, width axis 62–125) | Body at width 100, 400. Headings at width 106–125, 700–850. |
| Verdict words in the stamp and legend | Archivo | Width 62–70, 800–850, caps, letter-spacing 0.04em |
| DNS records and domain names only | Martian Mono (variable) | Width 88–100, 400–500 |

Load both from Google Fonts with the exact URL in the reference. One family carries the whole voice; its width axis does the work other sites use a second display font for.

Scale (fluid, from the reference): h1 `clamp(2rem, 1.2rem + 3.6vw, 3.6rem)`, h2 `clamp(1.45rem, 1.1rem + 1.4vw, 2rem)`, h3 `1.12rem`, body `1.0625rem` with line-height 1.55, small text `0.9rem`. Keep body lines under about 66 characters.

Rules:
- Monospace is for actual DNS data: records, domains, tag names. Never for labels, dates, buttons or decoration.
- Caps only inside the stamp and the legend's verdict words. No all-caps eyebrow labels above headings.
- Sentence case for every heading and button.
- Tabular figures (`"tnum"`) wherever numbers line up: chart totals, tables.

## Layout

- Content column max 1080 px, 16 px side gutters on phones, 32 px from 760 px up.
- Left-aligned throughout. Nothing is centred except text inside the stamp.
- Breakpoints: 520 px (stack definition lists, move the stamp above the address) and 760 px (two-column enclosures, chart beside trend).
- No page-level horizontal scroll at 360 px. Long records wrap; the data table scrolls inside its own box.

```
┌ SpoofCheck BC ─────────────────────── Report  Method  Fix guide  About ┐
│ Can someone forge email from a B.C. public body?                       │
│ One-line explanation                                                   │
│░░░░░░░░░░░░░░░░░░░░ security tint ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░│
│░  ┌ envelope ───────────────────────────────┐                         ░│
│░  │ Domain  [ window input          ][Check]│                         ░│
│░  └─────────────────────────────────────────┘                         ░│
│ ┌ result envelope ─────────────────────────────────────── (postmark) ┐ │
│ │ Checked at …                                                       │ │
│ │ riverbend.example            (mono, large)                         │ │
│ │ Plain sentence: what happens to forged mail                        │ │
│ │ ─ DMARC  [record]           tag → meaning                          │ │
│ │ ─ SPF    [record]           ▮▮▮▮▮▮▮▯▯▯ 7 of 10 lookups             │ │
│ │ What to fix, in order  1 2 3                                        │ │
│ │ Also checked  (definition list)                                     │ │
│ └────────────────────────────────────────────────────────────────────┘ │
│ Week 44, 2026                                                          │
│ 32 of 118 B.C. public bodies tell other mail servers to refuse…        │
│ By sector (stacked bars + legend + table)   │  12-week trend line      │
│ How the check works  │  What it can't tell you                         │
└ footer: independent project, not affiliated …                         ┘
```

## Components

**Envelope.** `--envelope` fill, 1 px `--rule` border, 3 px radius, and a two-step 1 px "paper edge" shadow below. This is the only shadow on the site.

**Window input.** Mono text in a `--window` box with a 10 px radius, the only rounded corner larger than 3 px, because envelope windows are rounded. The button next to it is square-cornered (2 px) and solid `--ink`.

**Postmark.** Inline SVG, `currentColor`, coloured by level class. Rings 2.6 px, centre band lines 1.3 px, five wavy lines. Ink texture is an `feTurbulence` + `feDisplacementMap` filter at scale 1.6, no more. Words longer than 9 letters drop to 14.5 px. Width `clamp(180px, 22vw, 268px)`, 176 px on phones. It animates once ("stamped down") when a result appears, and not at all under `prefers-reduced-motion`.

**Record block.** Mono, `--window` background, 3 px `--tint` left border, wraps anywhere. Next to it a two-column definition list reads each tag in plain English.

**Lookup meter.** Ten 12 × 18 px boxes, filled for used lookups, outlined for the rest, with the count written next to it. It goes red only when the limit is exceeded.

**Severity marks.** Small CSS shapes, never icons or emoji: high is a filled square in `--lvl-0`, medium a half-filled square in `--lvl-2`, low an empty square, info an empty circle, good a filled circle in `--lvl-3`. Always followed by the word.

**Fix list.** Numbered because it is a real order of work. Number set in Archivo width 125, in `--ink-soft`.

**Sector chart.** HTML flex bars, not SVG and not a chart library, so text stays real size on phones. 28 px tall, 2 px gaps between segments, count inside a segment only if the segment is at least 7 % wide. The total sits on the label line. A `<details>` underneath shows the same numbers as a table.

**Trend chart.** Small inline SVG generated in Python: three gridlines (20, 25, 30 %), first and last week labels, the line in `--lvl-3`, end dot and end value label. No tooltips.

## Words

- Write for a resident first and an IT person second. "Forged mail is filed as spam, not refused" before "p=quarantine".
- Say what happens, not how good or bad it is. No "Great news!", no "Uh oh", no scores out of 100.
- Errors say what went wrong and what to do: "No DNS answer for riverbend.example. Check the spelling, or try again in a minute."
- Never write: seamless, robust, comprehensive, powerful, leverage, empower, unlock, elevate, delve, effortless, cutting-edge, game-changer, "in today's digital landscape".
- No emoji anywhere on the site.
- Each page footer carries the independence disclaimer. The site must not look like gov.bc.ca: no B.C. government logo, crest or BC Sans font.

## Things to avoid

- Purple or blue-to-purple gradients, glassmorphism, blurred colour blobs.
- A grid of identical rounded cards with the same soft shadow.
- A hero made of one huge number, three stat tiles and a gradient.
- Icon libraries (Lucide, Heroicons, Font Awesome) or emoji as icons.
- An all-caps tracked label above every heading.
- Fade-and-slide-up on every section as it scrolls in.
- Meta strings joined with middle dots, arrows appended to every link.
- Tailwind or shadcn defaults left as they come.
