import hashlib
import hmac
import json
import os
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any

from spoofcheck.inventory import SECTORS
from spoofcheck.store import StoredLevel

SNAPSHOT_DIR = Path(__file__).resolve().parents[2] / "data" / "snapshots"
ENV_FILE = Path(".env")
LEVELS = ("3", "2", "1", "0")


class MissingKeyError(RuntimeError):
    pass


def snapshot_key(env_file: Path = ENV_FILE) -> bytes:
    """SNAPSHOT_KEY from the environment, falling back to a local .env file."""
    key = os.environ.get("SNAPSHOT_KEY")
    if not key and env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            name, _, value = line.partition("=")
            if name.strip() == "SNAPSHOT_KEY":
                key = value.strip().strip('"')
    if not key:
        raise MissingKeyError(
            "SNAPSHOT_KEY is not set. Put SNAPSHOT_KEY=<long random string> in .env "
            "or the environment; the same key has to be used every week."
        )
    return key.encode()


def domain_key(key: bytes, domain: str) -> str:
    # A plain hash wouldn't hide anything: the domain list is public and short,
    # so anyone could hash every entry and match them up. A keyed hash can't be
    # reversed that way without the key.
    return hmac.new(key, domain.encode(), hashlib.sha256).hexdigest()


def build_snapshot(
    levels: dict[str, StoredLevel],
    key: bytes,
    week: str,
    scanned_on: date,
    version: str,
    previous: dict[str, Any] | None,
) -> dict[str, Any]:
    by_key = {domain_key(key, d): s.level for d, s in sorted(levels.items())}
    sectors = {
        sector: _level_counts(s.level for s in levels.values() if s.sector == sector)
        for sector in SECTORS
        if any(s.sector == sector for s in levels.values())
    }
    moved_up = moved_down = 0
    if previous:
        for k, level in by_key.items():
            before = previous["levels_by_key"].get(k)
            if before is not None:
                moved_up += level > before
                moved_down += level < before
    return {
        "week": week,
        "scanned_on": scanned_on.isoformat(),
        "tool_version": version,
        "total": len(levels),
        "levels": _level_counts(s.level for s in levels.values()),
        "sectors": sectors,
        "compared_with": previous["week"] if previous else None,
        "moved_up": moved_up,
        "moved_down": moved_down,
        "levels_by_key": dict(sorted(by_key.items())),
    }


def load_snapshots(folder: Path = SNAPSHOT_DIR) -> list[dict[str, Any]]:
    paths = sorted(folder.glob("*-W*.json"))
    return [json.loads(p.read_text(encoding="utf-8")) for p in paths]


def previous_snapshot(week: str, folder: Path = SNAPSHOT_DIR) -> dict[str, Any] | None:
    earlier = [s for s in load_snapshots(folder) if s["week"] < week]
    return earlier[-1] if earlier else None


def write_snapshot(snapshot: dict[str, Any], folder: Path = SNAPSHOT_DIR) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{snapshot['week']}.json"
    path.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    return path


def _level_counts(levels: Any) -> dict[str, int]:
    counts = Counter(str(level) for level in levels)
    return {level: counts.get(level, 0) for level in LEVELS}
