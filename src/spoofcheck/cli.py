import asyncio
import json
from datetime import datetime

import typer

from spoofcheck import __version__
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
from spoofcheck.scanner import DomainReport, check_domain, normalize_domain
from spoofcheck.spf import MAX_LOOKUPS
from spoofcheck.transport import policy_client

app = typer.Typer(no_args_is_help=True, add_completion=False, help="Email spoofing checks.")

EXIT_HIGH_FINDING = 1
EXIT_USAGE = 2
EXIT_DNS_FAILURE = 3


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
