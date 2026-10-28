from dataclasses import dataclass

import httpx

from spoofcheck import USER_AGENT
from spoofcheck.findings import Finding
from spoofcheck.resolver import Outcome, Resolver

FETCH_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True)
class MtaStsResult:
    record: str | None
    mode: str | None
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class TlsRptResult:
    record: str | None
    findings: tuple[Finding, ...]


def policy_client() -> httpx.AsyncClient:
    # RFC 8461 §3.3: the policy fetch must not follow redirects
    return httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        timeout=FETCH_TIMEOUT_SECONDS,
        follow_redirects=False,
    )


def parse_policy_mode(policy: str) -> str | None:
    for line in policy.splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() == "mode":
            return value.strip().lower()
    return None


async def check_mta_sts(domain: str, resolver: Resolver, client: httpx.AsyncClient) -> MtaStsResult:
    answer = await resolver.txt(f"_mta-sts.{domain}")
    if answer.outcome is Outcome.TIMEOUT:
        return MtaStsResult(None, None, (Finding("DNS_TIMEOUT", f"_mta-sts.{domain}"),))
    record = _first_with_prefix(answer.records, "v=STSv1")
    if record is None:
        return MtaStsResult(None, None, (Finding("MTASTS_MISSING"),))

    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        response = await client.get(url)
    except httpx.HTTPError as err:
        return MtaStsResult(
            record, None, (Finding("MTASTS_POLICY_UNREACHABLE", type(err).__name__),)
        )
    if response.status_code != 200:
        detail = f"HTTP {response.status_code}"
        return MtaStsResult(record, None, (Finding("MTASTS_POLICY_UNREACHABLE", detail),))

    mode = parse_policy_mode(response.text)
    if mode == "testing":
        return MtaStsResult(record, mode, (Finding("MTASTS_TESTING"),))
    # RFC 8461 §5: mode "none" withdraws the policy, which leaves senders where
    # they'd be with nothing published.
    if mode != "enforce":
        return MtaStsResult(record, mode, (Finding("MTASTS_MISSING", f"mode {mode}"),))
    return MtaStsResult(record, mode, ())


async def check_tls_rpt(domain: str, resolver: Resolver) -> TlsRptResult:
    answer = await resolver.txt(f"_smtp._tls.{domain}")
    if answer.outcome is Outcome.TIMEOUT:
        return TlsRptResult(None, (Finding("DNS_TIMEOUT", f"_smtp._tls.{domain}"),))
    record = _first_with_prefix(answer.records, "v=TLSRPTv1")
    if record is None:
        return TlsRptResult(None, (Finding("TLSRPT_MISSING"),))
    return TlsRptResult(record, ())


def _first_with_prefix(records: tuple[str, ...], prefix: str) -> str | None:
    return next((r for r in records if r.replace(" ", "").startswith(prefix)), None)
