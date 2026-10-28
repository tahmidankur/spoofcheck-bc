import json
import math
import shutil
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from spoofcheck import REPO_URL, __version__
from spoofcheck.findings import CATALOGUE_PATH, load_catalogue
from spoofcheck.inventory import read_inventory
from spoofcheck.snapshot import load_snapshots

ROOT = Path(__file__).resolve().parents[3]
ASSETS = Path(__file__).parent / "assets"
WEB = ROOT / "web"
TREND_WEEKS = 12
MIN_LABEL_SHARE = 7.0

# The public site shows totals only. Naming bodies waits until every one has had
# its disclosure note and 60 days to respond (docs/SPEC.md §8).
PUBLISH_NAMED = False

SECTOR_LABELS = {
    "municipality": "Municipalities",
    "regional_district": "Regional districts",
    "school_district": "School districts",
    "health_authority": "Health authorities",
    "provincial": "Provincial bodies",
}
LEVELS = [
    ("3", "enforced", "ENFORCED", "Forged mail refused"),
    ("2", "partial", "PARTIAL", "Filed as spam, or only some refused"),
    ("1", "monitoring", "MONITORING", "Reports only, no action"),
    ("0", "unprotected", "UNPROTECTED", "No usable instruction"),
]
CHECK_HEADINGS = {
    "dmarc": "DMARC",
    "spf": "SPF",
    "mx": "Mail servers",
    "transport": "Transport security",
    "dkim": "DKIM",
    "dns": "DNS errors",
}


@dataclass(frozen=True)
class Segment:
    css: str
    word: str
    count: int
    share: float

    @property
    def labelled(self) -> bool:
        return self.share >= MIN_LABEL_SHARE


@dataclass(frozen=True)
class SectorBar:
    label: str
    total: int
    counts: dict[str, int]
    segments: list[Segment]


def build_site(out: Path) -> list[Path]:
    if PUBLISH_NAMED:
        raise RuntimeError("named results wait for the disclosure period; see docs/SPEC.md §8")
    snapshots = load_snapshots()
    env = Environment(
        loader=PackageLoader("spoofcheck.site"),
        autoescape=select_autoescape(),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    common = {"repo_url": REPO_URL, "version": __version__, "levels": LEVELS}
    pages = {
        "index.html": ("index.html", {"page": "report", **week_context(snapshots)}),
        "method/index.html": ("method.html", {"page": "method"}),
        "fix/index.html": ("fix.html", {"page": "fix", "groups": fix_groups()}),
        "about/index.html": ("about.html", {"page": "about"}),
        "404.html": ("404.html", {"page": None}),
    }
    if out.exists():
        shutil.rmtree(out)
    written = []
    for target, (template, context) in pages.items():
        path = out / target
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(env.get_template(template).render(**common, **context), encoding="utf-8")
        written.append(path)
    written += copy_assets(out / "assets")
    return written


def copy_assets(folder: Path) -> list[Path]:
    folder.mkdir(parents=True, exist_ok=True)
    copied = [Path(shutil.copy(ASSETS / "site.css", folder))]
    copied += [
        Path(shutil.copy(js, folder)) for js in sorted(WEB.glob("*.js")) if ".test." not in js.name
    ]
    copied.append(Path(shutil.copy(CATALOGUE_PATH, folder / "findings.json")))
    orgs = folder / "orgs.json"
    orgs.write_text(json.dumps(org_names(), indent=1, sort_keys=True), encoding="utf-8")
    copied.append(orgs)
    return copied


def org_names() -> dict[str, str]:
    """Domain to organization name, so the checker can say whose domain was typed in."""
    bodies, _ = read_inventory()
    return {b.domain: f"{b.name}, {b.region}" if b.region else b.name for b in bodies}


def week_context(snapshots: list[dict[str, Any]]) -> dict[str, Any]:
    if not snapshots:
        return {"latest": None}
    latest = snapshots[-1]
    year, week = latest["week"].split("-W")
    return {
        "latest": latest,
        "week_label": f"Week {int(week)}, {year}",
        "scanned_on": date.fromisoformat(latest["scanned_on"]),
        "bars": sector_bars(latest),
        "trend_svg": trend_svg(snapshots[-TREND_WEEKS:]),
        "trend_title": trend_title(snapshots[-TREND_WEEKS:]),
    }


def sector_bars(snapshot: dict[str, Any]) -> list[SectorBar]:
    bars = []
    for sector, counts in snapshot["sectors"].items():
        total = sum(counts.values())
        if not total:
            continue
        segments = [
            Segment(css, word, counts[level], 100 * counts[level] / total)
            for level, css, word, _ in LEVELS
            if counts[level]
        ]
        bars.append(SectorBar(SECTOR_LABELS[sector], total, counts, segments))
    return bars


def enforced_share(snapshot: dict[str, Any]) -> float:
    total = snapshot["total"]
    return 100 * snapshot["levels"]["3"] / total if total else 0.0


def trend_title(snapshots: list[dict[str, Any]]) -> str:
    first, last = snapshots[0], snapshots[-1]
    a, b = round(enforced_share(first)), round(enforced_share(last))
    if len(snapshots) < 2:
        return f"{b}% of bodies were at ENFORCED in week {_week_number(last)}."
    verb = "rose" if b > a else "fell" if b < a else "stayed"
    if verb == "stayed":
        weeks = f"week {_week_number(first)} to {_week_number(last)}"
        return f"Share of bodies at ENFORCED stayed at {b}% from {weeks}."
    return (
        f"Share of bodies at ENFORCED {verb} from {a}% in week {_week_number(first)} "
        f"to {b}% in week {_week_number(last)}."
    )


def trend_svg(snapshots: list[dict[str, Any]]) -> str | None:
    """The ENFORCED share as a small line chart, drawn the way the design reference does it."""
    if len(snapshots) < 2:
        return None
    shares = [enforced_share(s) for s in snapshots]
    low = 5 * math.floor(min(shares) / 5)
    high = max(5 * math.ceil(max(shares) / 5), low + 10)
    left, right, top, bottom = 34.0, 280.0, 10.0, 98.0

    def y(share: float) -> float:
        return bottom - (share - low) / (high - low) * (bottom - top)

    step = (right - left) / (len(shares) - 1)
    points = [(left + i * step, y(s)) for i, s in enumerate(shares)]
    end_x, end_y = points[-1]
    parts = []
    for share in (low, (low + high) / 2, high):
        gy = y(share)
        parts.append(
            f'<line class="t-grid" x1="{left:g}" x2="{right:g}" y1="{gy:.1f}" y2="{gy:.1f}"/>'
        )
        parts.append(
            f'<text class="t-axis" x="28" y="{gy:.1f}" text-anchor="end" '
            f'dominant-baseline="central">{share:g}%</text>'
        )
    parts.append(
        '<polyline class="t-line" points="'
        + " ".join(f"{x:.1f},{py:.1f}" for x, py in points)
        + '"/>'
    )
    parts.append(f'<circle class="t-end" cx="{end_x:.1f}" cy="{end_y:.1f}" r="3.5"/>')
    parts.append(
        f'<text class="t-endlabel" x="{end_x + 8:.1f}" y="{end_y:.1f}" '
        f'dominant-baseline="central">{round(shares[-1])}%</text>'
    )
    parts.append(
        f'<text class="t-axis" x="{left:g}" y="116" text-anchor="start">'
        f"W{_week_number(snapshots[0])}</text>"
    )
    parts.append(
        f'<text class="t-axis" x="{end_x:.1f}" y="116" text-anchor="end">'
        f"W{_week_number(snapshots[-1])}</text>"
    )
    return "".join(parts)


def fix_groups() -> list[tuple[str, list[Any]]]:
    groups: dict[str, list[Any]] = {}
    for entry in load_catalogue().values():
        groups.setdefault(entry.check, []).append(entry)
    return [(CHECK_HEADINGS[check], entries) for check, entries in groups.items()]


def _week_number(snapshot: dict[str, Any]) -> int:
    return int(snapshot["week"].split("-W")[1])
