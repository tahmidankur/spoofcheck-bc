import json
from datetime import date
from pathlib import Path

import pytest

from spoofcheck.snapshot import (
    MissingKeyError,
    build_snapshot,
    domain_key,
    previous_snapshot,
    snapshot_key,
    write_snapshot,
)
from spoofcheck.store import StoredLevel

KEY = b"test-key-not-secret"


def levels(**by_domain: int) -> dict[str, StoredLevel]:
    sectors = {"riverbend.example": "municipality"}
    return {
        d: StoredLevel(d, f"Org {d}", sectors.get(d, "school_district"), lvl, frozenset())
        for d, lvl in by_domain.items()
    }


def test_snapshot_never_contains_a_domain_or_organization_name() -> None:
    current = levels(**{"riverbend.example": 3, "sd.example": 1})
    text = json.dumps(build_snapshot(current, KEY, "2026-W44", date(2026, 10, 28), "0.1.0", None))
    for stored in current.values():
        assert stored.domain not in text
        assert stored.organization not in text
        assert "riverbend" not in text


def test_totals_and_sector_counts() -> None:
    current = levels(**{"riverbend.example": 3, "sd.example": 1, "sd2.example": 1})
    snap = build_snapshot(current, KEY, "2026-W44", date(2026, 10, 28), "0.1.0", None)
    assert snap["total"] == 3
    assert snap["levels"] == {"3": 1, "2": 0, "1": 2, "0": 0}
    assert snap["sectors"]["school_district"]["1"] == 2
    assert snap["compared_with"] is None


def test_moves_are_counted_against_the_previous_week() -> None:
    before = build_snapshot(
        levels(**{"riverbend.example": 1, "sd.example": 2}),
        KEY,
        "2026-W43",
        date(2026, 10, 21),
        "0.1.0",
        None,
    )
    after = build_snapshot(
        levels(**{"riverbend.example": 3, "sd.example": 0}),
        KEY,
        "2026-W44",
        date(2026, 10, 28),
        "0.1.0",
        before,
    )
    assert (after["moved_up"], after["moved_down"]) == (1, 1)
    assert after["compared_with"] == "2026-W43"


def test_keyed_hash_differs_from_a_plain_hash_and_between_keys() -> None:
    assert domain_key(KEY, "riverbend.example") != domain_key(b"other", "riverbend.example")


def test_previous_snapshot_is_the_latest_earlier_week(tmp_path: Path) -> None:
    for week in ("2026-W42", "2026-W43", "2026-W44"):
        write_snapshot({"week": week, "levels_by_key": {}}, tmp_path)
    found = previous_snapshot("2026-W44", tmp_path)
    assert found is not None and found["week"] == "2026-W43"
    assert previous_snapshot("2026-W42", tmp_path) is None


def test_missing_key_fails_with_a_clear_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SNAPSHOT_KEY", raising=False)
    with pytest.raises(MissingKeyError, match="SNAPSHOT_KEY"):
        snapshot_key(tmp_path / ".env")


def test_key_is_read_from_env_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SNAPSHOT_KEY", raising=False)
    env = tmp_path / ".env"
    env.write_text('SNAPSHOT_KEY="abc123"\n')
    assert snapshot_key(env) == b"abc123"
