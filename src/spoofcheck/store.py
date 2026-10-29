import json
import sqlite3
from dataclasses import dataclass
from datetime import date, datetime
from importlib import resources
from pathlib import Path

from spoofcheck.inventory import Body
from spoofcheck.scanner import DomainReport

DB_PATH = Path("spoofcheck.db")


@dataclass(frozen=True)
class StoredLevel:
    domain: str
    organization: str
    sector: str
    level: int
    codes: frozenset[str]


@dataclass(frozen=True)
class ScanInfo:
    id: int
    week: str
    started_on: date


def connect(path: Path | str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    migrate(conn)
    return conn


def migrate(conn: sqlite3.Connection) -> None:
    """Apply numbered .sql files above the version stored in PRAGMA user_version."""
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    folder = resources.files("spoofcheck") / "migrations"
    scripts = sorted((f for f in folder.iterdir() if f.name.endswith(".sql")), key=lambda f: f.name)
    for script in scripts:
        number = int(script.name.split("_", 1)[0])
        if number <= current:
            continue
        with conn:
            conn.executescript(script.read_text(encoding="utf-8"))
            # PRAGMA can't take a bound parameter; number comes from our own filenames.
            conn.execute(f"PRAGMA user_version = {number}")


def start_scan(conn: sqlite3.Connection, started_at: datetime, version: str, resolver: str) -> int:
    year, week, _ = started_at.isocalendar()
    with conn:
        cursor = conn.execute(
            "INSERT INTO scan (started_at, tool_version, resolver, iso_week) VALUES (?, ?, ?, ?)",
            (started_at.isoformat(timespec="seconds"), version, resolver, f"{year}-W{week:02d}"),
        )
    assert cursor.lastrowid is not None
    return cursor.lastrowid


def finish_scan(conn: sqlite3.Connection, scan_id: int, finished_at: datetime) -> None:
    with conn:
        conn.execute(
            "UPDATE scan SET finished_at = ? WHERE id = ?",
            (finished_at.isoformat(timespec="seconds"), scan_id),
        )


def save_result(conn: sqlite3.Connection, scan_id: int, body: Body, report: DomainReport) -> None:
    dmarc, spf, mx = report.dmarc, report.spf, report.mx
    with conn:
        domain_id = _upsert_body(conn, body)
        cursor = conn.execute(
            """INSERT INTO result (scan_id, domain_id, level, dmarc_raw, dmarc_policy,
                 dmarc_subdomain_policy, dmarc_pct, spf_raw, spf_all, spf_lookups, mx_hosts,
                 mta_sts_mode, tls_rpt, dkim_selectors, error)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                domain_id,
                report.level,
                json.dumps(list(dmarc.seen)) if dmarc else None,
                dmarc.policy if dmarc else None,
                dmarc.subdomain_policy if dmarc else None,
                dmarc.pct if dmarc else None,
                spf.record if spf else None,
                spf.all_qualifier if spf else None,
                spf.lookups if spf else None,
                json.dumps([[h.preference, h.host] for h in mx.hosts]) if mx else None,
                report.mta_sts.mode if report.mta_sts else None,
                int(report.tls_rpt.record is not None) if report.tls_rpt else None,
                json.dumps(list(report.dkim.selectors)) if report.dkim else None,
                report.error,
            ),
        )
        conn.executemany(
            "INSERT INTO finding (result_id, code, detail) VALUES (?, ?, ?)",
            [(cursor.lastrowid, f.code, f.detail) for f in report.findings],
        )


def _upsert_body(conn: sqlite3.Connection, body: Body) -> int:
    conn.execute(
        """INSERT INTO organization (name, sector, region, source_url) VALUES (?, ?, ?, ?)
           ON CONFLICT (name) DO UPDATE SET sector = excluded.sector,
             region = excluded.region, source_url = excluded.source_url""",
        (body.name, body.sector, body.region, body.source_url),
    )
    org_id = conn.execute("SELECT id FROM organization WHERE name = ?", (body.name,)).fetchone()[0]
    conn.execute(
        """INSERT INTO domain (organization_id, name, verified) VALUES (?, ?, ?)
           ON CONFLICT (name) DO UPDATE SET organization_id = excluded.organization_id,
             verified = excluded.verified""",
        (org_id, body.domain, int(body.verified)),
    )
    row = conn.execute("SELECT id FROM domain WHERE name = ?", (body.domain,)).fetchone()
    return int(row[0])


def finished_scans(conn: sqlite3.Connection) -> list[ScanInfo]:
    """Every completed scan, newest first."""
    rows = conn.execute(
        "SELECT id, iso_week, started_at FROM scan WHERE finished_at IS NOT NULL ORDER BY id DESC"
    ).fetchall()
    return [
        ScanInfo(scan_id, week, datetime.fromisoformat(started).date())
        for scan_id, week, started in rows
    ]


def levels_for_scan(conn: sqlite3.Connection, scan_id: int) -> dict[str, StoredLevel]:
    rows = conn.execute(
        """SELECT d.name, o.name, o.sector, r.level, group_concat(f.code)
           FROM result r
           JOIN domain d ON d.id = r.domain_id
           JOIN organization o ON o.id = d.organization_id
           LEFT JOIN finding f ON f.result_id = r.id
           WHERE r.scan_id = ?
           GROUP BY r.id""",
        (scan_id,),
    ).fetchall()
    return {
        domain: StoredLevel(domain, org, sector, level, frozenset((codes or "").split(",")) - {""})
        for domain, org, sector, level, codes in rows
    }
