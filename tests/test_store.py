import sqlite3
from datetime import UTC, datetime

import httpx

from spoofcheck.inventory import Body
from spoofcheck.scanner import check_domains
from spoofcheck.store import (
    finish_scan,
    finished_scans,
    levels_for_scan,
    migrate,
    save_result,
    start_scan,
)
from tests.fakes import FakeResolver

BODIES = [
    Body("Village of Riverbend", "municipality", "Thompson-Nicola", "riverbend.example", "", False),
    Body(
        "Riverbend School District", "school_district", "Thompson-Nicola", "sd.example", "", False
    ),
    Body("Riverbend Health", "health_authority", "Interior", "health.example", "", False),
]
ZONE = {
    "riverbend.example": {"TXT": ["v=spf1 -all"], "MX": ["10 mail.riverbend.example."]},
    "_dmarc.riverbend.example": {"TXT": ["v=DMARC1; p=reject; rua=mailto:d@riverbend.example"]},
    "sd.example": {"TXT": ["v=spf1 ~all"], "MX": ["10 mail.sd.example."]},
    "_dmarc.sd.example": {"TXT": ["v=DMARC1; p=none; rua=mailto:d@sd.example"]},
}


def offline_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404)))


def test_migrations_set_user_version_and_run_once() -> None:
    conn = sqlite3.connect(":memory:")
    migrate(conn)
    migrate(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 1
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert tables == {"organization", "domain", "scan", "result", "finding"}


async def test_scan_of_three_fake_domains_is_stored_with_findings() -> None:
    conn = sqlite3.connect(":memory:")
    migrate(conn)
    started = datetime(2026, 10, 28, tzinfo=UTC)
    scan_id = start_scan(conn, started, "0.1.0", "fake")
    async with offline_client() as client:
        reports = await check_domains([b.domain for b in BODIES], FakeResolver(ZONE), client)
    for body, report in zip(BODIES, reports, strict=True):
        save_result(conn, scan_id, body, report)
    finish_scan(conn, scan_id, started)

    (latest,) = finished_scans(conn)
    assert (latest.id, latest.week, latest.started_on.isoformat()) == (
        scan_id,
        "2026-W44",
        "2026-10-28",
    )
    levels = levels_for_scan(conn, scan_id)
    assert {d: s.level for d, s in levels.items()} == {
        "riverbend.example": 3,
        "sd.example": 1,
        "health.example": 0,
    }
    assert levels["health.example"].codes == {"DNS_NXDOMAIN"}
    assert "DMARC_POLICY_NONE" in levels["sd.example"].codes
