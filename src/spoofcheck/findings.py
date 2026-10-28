import json
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Literal

# data/ sits at the repository root so the site build and the browser checker
# read the same file the CLI does.
CATALOGUE_PATH = Path(__file__).resolve().parents[2] / "data" / "findings.json"

Severity = Literal["good", "info", "low", "medium", "high"]
SEVERITY_ORDER: tuple[Severity, ...] = ("high", "medium", "low", "info", "good")


@dataclass(frozen=True)
class CatalogueEntry:
    code: str
    check: str
    severity: Severity
    title: str
    explain: str
    fix: str | None
    example: str | None
    reference: str | None


@dataclass(frozen=True)
class Finding:
    code: str
    detail: str | None = None

    def __post_init__(self) -> None:
        if self.code not in load_catalogue():
            raise KeyError(f"unknown finding code: {self.code}")

    @property
    def entry(self) -> CatalogueEntry:
        return load_catalogue()[self.code]

    @property
    def severity(self) -> Severity:
        return self.entry.severity


@cache
def load_catalogue(path: Path = CATALOGUE_PATH) -> dict[str, CatalogueEntry]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {item["code"]: CatalogueEntry(**item) for item in raw["findings"]}


def by_severity(findings: tuple[Finding, ...]) -> list[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.severity))
