from dataclasses import dataclass

from spoofcheck.findings import Finding
from spoofcheck.resolver import Outcome, Resolver


@dataclass(frozen=True)
class MxHost:
    preference: int
    host: str


@dataclass(frozen=True)
class MxResult:
    hosts: tuple[MxHost, ...]
    null_mx: bool
    findings: tuple[Finding, ...]

    @property
    def receives_mail(self) -> bool:
        return bool(self.hosts) and not self.null_mx


def parse_mx_records(records: tuple[str, ...]) -> tuple[MxHost, ...]:
    hosts = []
    for record in records:
        preference, _, host = record.strip().partition(" ")
        host = host.strip().lower()
        hosts.append(MxHost(int(preference), host if host == "." else host.rstrip(".")))
    return tuple(sorted(hosts, key=lambda h: (h.preference, h.host)))


def is_null_mx(hosts: tuple[MxHost, ...]) -> bool:
    # RFC 7505 §3: exactly one MX, preference 0, host "."
    return len(hosts) == 1 and hosts[0].preference == 0 and hosts[0].host == "."


async def check_mx(domain: str, resolver: Resolver) -> MxResult:
    answer = await resolver.mx(domain)
    if answer.outcome is Outcome.TIMEOUT:
        return MxResult((), False, (Finding("DNS_TIMEOUT", f"MX {domain}"),))
    hosts = parse_mx_records(answer.records)
    if not hosts:
        return MxResult((), False, (Finding("MX_NONE"),))
    if is_null_mx(hosts):
        return MxResult(hosts, True, (Finding("MX_NULL"),))
    return MxResult(hosts, False, ())
