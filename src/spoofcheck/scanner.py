import asyncio
import re
from dataclasses import dataclass

import httpx

from spoofcheck.dkim import DkimResult, check_dkim
from spoofcheck.dmarc import DmarcResult, check_dmarc
from spoofcheck.findings import Finding, by_severity
from spoofcheck.mx import MxResult, check_mx
from spoofcheck.resolver import Outcome, Resolver
from spoofcheck.spf import SpfResult, check_spf
from spoofcheck.transport import MtaStsResult, TlsRptResult, check_mta_sts, check_tls_rpt

HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


@dataclass(frozen=True)
class DomainReport:
    domain: str
    level: int
    findings: tuple[Finding, ...]
    dmarc: DmarcResult | None = None
    spf: SpfResult | None = None
    mx: MxResult | None = None
    mta_sts: MtaStsResult | None = None
    tls_rpt: TlsRptResult | None = None
    dkim: DkimResult | None = None
    error: str | None = None

    @property
    def worst_severity(self) -> str | None:
        ordered = by_severity(self.findings)
        return ordered[0].severity if ordered else None


def normalize_domain(text: str) -> str:
    domain = text.strip().lower().rstrip(".")
    if "@" in domain:
        domain = domain.rsplit("@", 1)[1]
    domain = domain.encode("idna").decode("ascii") if not domain.isascii() else domain
    if not HOSTNAME.match(domain):
        raise ValueError(f"{text!r} is not a domain name")
    return domain


async def check_domain(domain: str, resolver: Resolver, client: httpx.AsyncClient) -> DomainReport:
    apex = await resolver.txt(domain)
    if apex.outcome is Outcome.NXDOMAIN:
        return DomainReport(domain, 0, (Finding("DNS_NXDOMAIN"),), error="nxdomain")

    dmarc, spf, mx, mta_sts, tls_rpt, dkim = await asyncio.gather(
        check_dmarc(domain, resolver),
        check_spf(domain, resolver),
        check_mx(domain, resolver),
        check_mta_sts(domain, resolver, client),
        check_tls_rpt(domain, resolver),
        check_dkim(domain, resolver),
    )
    findings = (
        *mx.findings,
        *non_mail_findings(mx, spf, dmarc.level),
        *dmarc.findings,
        *spf.findings,
        *mta_sts.findings,
        *tls_rpt.findings,
        *dkim.findings,
    )
    timed_out = any(f.code == "DNS_TIMEOUT" for f in findings)
    return DomainReport(
        domain,
        dmarc.level,
        tuple(findings),
        dmarc,
        spf,
        mx,
        mta_sts,
        tls_rpt,
        dkim,
        error="timeout" if timed_out else None,
    )


def non_mail_findings(mx: MxResult, spf: SpfResult, level: int) -> tuple[Finding, ...]:
    # A domain that takes no mail should say it sends none either: v=spf1 -all
    # and p=reject (CCCS ITSP.40.065). Otherwise it's an easy name to forge.
    if mx.receives_mail or any(f.code == "DNS_TIMEOUT" for f in mx.findings):
        return ()
    locked = spf.record is not None and " ".join(spf.record.lower().split()) == "v=spf1 -all"
    if locked and level == 3:
        return ()
    return (Finding("NON_MAIL_DOMAIN_OPEN"),)
