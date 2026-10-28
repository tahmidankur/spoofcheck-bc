import csv
from dataclasses import dataclass
from pathlib import Path

from spoofcheck.scanner import HOSTNAME

INVENTORY_PATH = Path(__file__).resolve().parents[2] / "data" / "inventory.csv"
SECTORS = ("municipality", "regional_district", "school_district", "health_authority", "provincial")
COLUMNS = ["org_name", "sector", "region", "domain", "source_url", "verified", "notes"]


@dataclass(frozen=True)
class Body:
    name: str
    sector: str
    region: str
    domain: str
    source_url: str
    verified: bool


def read_inventory(path: Path = INVENTORY_PATH) -> tuple[list[Body], list[str]]:
    """Every row that passes validation, plus one message per problem found."""
    bodies: list[Body] = []
    problems: list[str] = []
    seen: dict[str, int] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != COLUMNS:
            return [], [f"header should be {','.join(COLUMNS)}"]
        for line, row in enumerate(reader, start=2):
            row_problems = _row_problems(row, seen.get(row["domain"].strip().lower()))
            problems += [f"line {line}: {p}" for p in row_problems]
            if not row_problems:
                seen[row["domain"].strip().lower()] = line
                bodies.append(_body(row))
    return bodies, problems


def _row_problems(row: dict[str, str], duplicate_of: int | None) -> list[str]:
    problems = []
    domain = row["domain"].strip().lower()
    if not row["org_name"].strip():
        problems.append("org_name is empty")
    if row["sector"] not in SECTORS:
        problems.append(f"sector {row['sector']!r} is not one of {', '.join(SECTORS)}")
    if not HOSTNAME.match(domain):
        problems.append(f"{domain!r} is not a valid hostname")
    if duplicate_of is not None:
        problems.append(f"{domain} already listed on line {duplicate_of}")
    if row["verified"] not in ("yes", "no"):
        problems.append("verified must be yes or no")
    elif row["verified"] == "yes" and not row["source_url"].startswith("https://"):
        problems.append("verified rows need an https source_url")
    return problems


def _body(row: dict[str, str]) -> Body:
    return Body(
        name=row["org_name"].strip(),
        sector=row["sector"],
        region=row["region"].strip(),
        domain=row["domain"].strip().lower(),
        source_url=row["source_url"].strip(),
        verified=row["verified"] == "yes",
    )
