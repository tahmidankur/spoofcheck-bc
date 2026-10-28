import asyncio
import json
import logging
from datetime import UTC, datetime

import typer

from spoofcheck import __version__, store
from spoofcheck import snapshot as snapshots
from spoofcheck.diff import describe_changes
from spoofcheck.inventory import SECTORS, read_inventory
from spoofcheck.report import (
    ALL_MEANING,
    LEVEL_WORDS,
    also_checked,
    fix_list,
    read_dmarc_tags,
    report_to_dict,
    verdict_sentence,
)
from spoofcheck.resolver import DnsResolver
from spoofcheck.scanner import DomainReport, check_domain, check_domains, normalize_domain
from spoofcheck.spf import MAX_LOOKUPS
from spoofcheck.transport import policy_client

app = typer.Typer(no_args_is_help=True, add_completion=False, help="Email spoofing checks.")

inventory_app = typer.Typer(no_args_is_help=True, help="Work with data/inventory.csv.")
app.add_typer(inventory_app, name="inventory")

log = logging.getLogger("spoofcheck")

EXIT_HIGH_FINDING = 1
EXIT_USAGE = 2
EXIT_DNS_FAILURE = 3


@app.callback()
def main(verbose: bool = typer.Option(False, "--verbose", "-v")) -> None:
    logging.basicConfig(level=logging.INFO if verbose else logging.WARNING, format="%(message)s")


@app.command()
def version() -> None:
    """Print the tool version."""
    typer.echo(__version__)


@app.command()
def check(
    domain: str,
    as_json: bool = typer.Option(False, "--json", help="Print the result as JSON."),
) -> None:
    """Check one domain and print what its DNS records tell receivers to do."""
    try:
        domain = normalize_domain(domain)
    except ValueError as err:
        typer.echo(f"{err}. Try something like example.ca.", err=True)
        raise typer.Exit(EXIT_USAGE) from None

    report = asyncio.run(_check_one(domain))
    checked_at = datetime.now().astimezone()
    if as_json:
        typer.echo(json.dumps(report_to_dict(report, checked_at), indent=2))
    else:
        typer.echo(render_report(report, checked_at))

    if report.error == "timeout":
        raise typer.Exit(EXIT_DNS_FAILURE)
    if report.worst_severity == "high":
        raise typer.Exit(EXIT_HIGH_FINDING)


@inventory_app.command("check")
def inventory_check() -> None:
    """Validate the inventory and list rows nobody has verified yet."""
    bodies, problems = read_inventory()
    for problem in problems:
        typer.echo(problem)
    unverified = [b for b in bodies if not b.verified]
    typer.echo(f"{len(bodies)} rows ok, {len(problems)} problems, {len(unverified)} not verified")
    for body in unverified:
        typer.echo(f"  {body.domain:<24} {body.name}")
    if problems:
        raise typer.Exit(EXIT_USAGE)


@app.command()
def scan(
    only_sector: str | None = typer.Option(None, help=f"One of: {', '.join(SECTORS)}."),
) -> None:
    """Scan every domain in the inventory and save the results to spoofcheck.db."""
    if only_sector is not None and only_sector not in SECTORS:
        typer.echo(f"Unknown sector {only_sector!r}. Use one of: {', '.join(SECTORS)}.", err=True)
        raise typer.Exit(EXIT_USAGE)
    bodies, problems = read_inventory()
    if problems:
        typer.echo("Fix data/inventory.csv first: spoofcheck inventory check", err=True)
        raise typer.Exit(EXIT_USAGE)
    bodies = [b for b in bodies if only_sector in (None, b.sector)]

    resolver = DnsResolver()
    conn = store.connect()
    scan_id = store.start_scan(conn, datetime.now(UTC), __version__, resolver.description)
    reports = asyncio.run(_check_many([b.domain for b in bodies], resolver))
    for body, report in zip(bodies, reports, strict=True):
        store.save_result(conn, scan_id, body, report)
    store.finish_scan(conn, scan_id, datetime.now(UTC))

    timeouts = sum(r.error == "timeout" for r in reports)
    log.info("scan finished: %d domains, %d timeouts", len(reports), timeouts)
    for level in (3, 2, 1, 0):
        count = sum(r.level == level for r in reports)
        typer.echo(f"{LEVEL_WORDS[level]:<12} {count}")
    typer.echo(f"{len(reports)} domains scanned, {timeouts} timed out")


@app.command()
def diff() -> None:
    """Show what changed between the last two scans. Stays on this machine."""
    conn = store.connect()
    scans = store.finished_scans(conn)
    if len(scans) < 2:
        typer.echo("Need at least two finished scans to compare.")
        return
    (new_id, new_week), (old_id, old_week) = scans[0], scans[1]
    changes = describe_changes(
        store.levels_for_scan(conn, old_id), store.levels_for_scan(conn, new_id)
    )
    typer.echo(f"Scan {old_id} ({old_week}) to scan {new_id} ({new_week})")
    typer.echo("\n".join(changes) if changes else "No changes.")


@app.command()
def snapshot() -> None:
    """Write data/snapshots/<week>.json with totals and keyed levels only."""
    try:
        key = snapshots.snapshot_key()
    except snapshots.MissingKeyError as err:
        typer.echo(str(err), err=True)
        raise typer.Exit(EXIT_USAGE) from None
    conn = store.connect()
    scans = store.finished_scans(conn)
    if not scans:
        typer.echo("No finished scan yet. Run spoofcheck scan first.", err=True)
        raise typer.Exit(EXIT_USAGE)
    scan_id, week = scans[0]
    started = conn.execute("SELECT started_at FROM scan WHERE id = ?", (scan_id,)).fetchone()[0]
    data = snapshots.build_snapshot(
        store.levels_for_scan(conn, scan_id),
        key,
        week,
        datetime.fromisoformat(started).date(),
        __version__,
        snapshots.previous_snapshot(week),
    )
    path = snapshots.write_snapshot(data)
    typer.echo(f"Wrote {path.relative_to(path.parents[2])}")


async def _check_many(domains: list[str], resolver: DnsResolver) -> list[DomainReport]:
    async with policy_client() as client:
        return await check_domains(domains, resolver, client)


async def _check_one(domain: str) -> DomainReport:
    async with policy_client() as client:
        return await check_domain(domain, DnsResolver(), client)


def render_report(report: DomainReport, checked_at: datetime) -> str:
    lines = [
        report.domain,
        f"Checked {checked_at:%-d %B %Y at %H:%M}",
        "",
        f"{LEVEL_WORDS[report.level]}  {verdict_sentence(report.dmarc)}",
    ]
    if report.error == "nxdomain":
        lines += ["", "DNS says this domain doesn't exist. Check the spelling."]
        return "\n".join(lines)

    lines += _dmarc_section(report) + _spf_section(report) + _also_checked(report)
    fixes = fix_list(report)
    if fixes:
        lines += ["", "What to fix, in order"]
        for number, finding in enumerate(fixes, 1):
            entry = finding.entry
            detail = f" ({finding.detail})" if finding.detail else ""
            lines.append(f"  {number}. [{entry.severity}] {entry.title}{detail}")
            if entry.fix:
                lines.append(f"     {entry.fix}")
    return "\n".join(lines)


def _dmarc_section(report: DomainReport) -> list[str]:
    dmarc = report.dmarc
    lines = ["", f"DMARC at _dmarc.{report.domain}"]
    if dmarc is None or not dmarc.seen:
        return [*lines, "  nothing published"]
    lines += [f"  {raw}" for raw in dmarc.seen]
    width = max((len(tag) for tag, _ in read_dmarc_tags(dmarc)), default=0)
    lines += [f"  {tag.ljust(width)}  {meaning}" for tag, meaning in read_dmarc_tags(dmarc)]
    return lines


def _spf_section(report: DomainReport) -> list[str]:
    spf = report.spf
    lines = ["", f"SPF at {report.domain}"]
    if spf is None or spf.record is None:
        return [*lines, "  no single SPF record"]
    qualifier = spf.all_qualifier
    return [
        *lines,
        f"  {spf.record}",
        f"  {spf.lookups} of {MAX_LOOKUPS} DNS lookups used",
        f"  {(qualifier or '') + 'all' if qualifier else 'no all'}: {ALL_MEANING[qualifier]}",
    ]


def _also_checked(report: DomainReport) -> list[str]:
    rows = also_checked(report)
    return ["", "Also checked", *(f"  {label.ljust(12)}  {text}" for label, text in rows)]
