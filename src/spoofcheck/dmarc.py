import asyncio
import re
from dataclasses import dataclass, field, replace

from spoofcheck.findings import Finding
from spoofcheck.resolver import Outcome, Resolver

POLICY_STRENGTH = {"none": 0, "quarantine": 1, "reject": 2}
DMARC_VERSION = re.compile(r"^\s*v\s*=\s*DMARC1\s*(;|$)", re.IGNORECASE)


@dataclass(frozen=True)
class DmarcRecord:
    raw: str
    tags: dict[str, str]
    policy: str | None
    subdomain_policy: str | None
    pct: int
    report_addresses: tuple[str, ...]


@dataclass(frozen=True)
class DmarcResult:
    seen: tuple[str, ...]
    record: DmarcRecord | None
    policy: str | None
    level: int
    findings: tuple[Finding, ...] = field(default=())

    @property
    def subdomain_policy(self) -> str | None:
        return self.record.subdomain_policy if self.record else None

    @property
    def pct(self) -> int | None:
        return self.record.pct if self.record else None


def parse_dmarc_tags(raw: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in raw.split(";"):
        name, sep, value = part.partition("=")
        # RFC 7489 §6.4: empty tags from a trailing ";" are allowed and ignored
        if not sep or not name.strip():
            continue
        tags.setdefault(name.strip().lower(), value.strip())
    return tags


def parse_report_addresses(value: str) -> tuple[str, ...]:
    """Mailbox addresses from a rua/ruf list, dropping anything that isn't mailto:."""
    addresses = []
    for uri in value.split(","):
        uri = uri.strip()
        if not uri.lower().startswith("mailto:"):
            continue
        # RFC 7489 §6.2: a "!size" suffix limits report size and isn't part of the address
        address = uri[len("mailto:") :].split("!", 1)[0]
        local, at, domain = address.partition("@")
        if local and at and "." in domain:
            addresses.append(address)
    return tuple(addresses)


def parse_dmarc_record(raw: str) -> DmarcRecord:
    tags = parse_dmarc_tags(raw)
    policy = _policy_value(tags.get("p"))
    subdomain_policy = _policy_value(tags.get("sp"))
    return DmarcRecord(
        raw=raw,
        tags=tags,
        policy=policy,
        subdomain_policy=subdomain_policy,
        pct=_pct_value(tags.get("pct")),
        report_addresses=parse_report_addresses(tags.get("rua", "")),
    )


def protection_level(policy: str | None, pct: int) -> int:
    if policy == "reject":
        return 3 if pct == 100 else 2
    if policy == "quarantine":
        return 2
    if policy == "none":
        return 1
    return 0


def evaluate_dmarc(seen: list[str] | tuple[str, ...]) -> DmarcResult:
    """Pick the DMARC record out of the TXT strings at _dmarc.<domain> and grade it."""
    seen = tuple(seen)
    candidates = [s for s in seen if DMARC_VERSION.match(s)]
    if len(candidates) > 1:
        # RFC 7489 §6.6.3: more than one record means none of them apply
        return DmarcResult(seen, None, None, 0, (Finding("DMARC_MULTIPLE"),))
    if not candidates:
        misplaced = any("v=dmarc1" in s.lower().replace(" ", "") for s in seen)
        code = "DMARC_SYNTAX" if misplaced else "DMARC_MISSING"
        return DmarcResult(seen, None, None, 0, (Finding(code),))

    record = parse_dmarc_record(candidates[0])
    findings: list[Finding] = []
    policy = record.policy
    if policy is None:
        findings.append(Finding("DMARC_SYNTAX", "p tag missing or not none, quarantine or reject"))
        # RFC 7489 §6.6.3: a record with a bad p but a usable rua is treated as p=none
        if record.report_addresses:
            policy = "none"

    level = protection_level(policy, record.pct)
    findings.extend(_policy_findings(policy, record))
    if not record.report_addresses:
        findings.append(Finding("DMARC_NO_REPORTS"))
    return DmarcResult(seen, record, policy, level, tuple(findings))


async def check_dmarc(domain: str, resolver: Resolver) -> DmarcResult:
    answer = await resolver.txt(f"_dmarc.{domain}")
    if answer.outcome is Outcome.TIMEOUT:
        return DmarcResult((), None, None, 0, (Finding("DNS_TIMEOUT", f"_dmarc.{domain}"),))
    result = evaluate_dmarc(answer.records)
    if result.record is None:
        return result
    unauthorized = await unauthorized_report_domains(domain, result.record, resolver)
    extra = tuple(Finding("DMARC_REPORT_DEST_UNAUTHORIZED", d) for d in unauthorized)
    return replace(result, findings=result.findings + extra)


async def unauthorized_report_domains(
    domain: str, record: DmarcRecord, resolver: Resolver
) -> list[str]:
    """Report domains outside this one that haven't said they accept its reports."""
    external = sorted(
        {
            address.rsplit("@", 1)[1].lower().rstrip(".")
            for address in record.report_addresses
            if not _same_organization(domain, address.rsplit("@", 1)[1])
        }
    )
    # RFC 7489 §7.1: the destination authorizes us with a v=DMARC1 TXT record
    # at <our domain>._report._dmarc.<their domain>
    answers = await asyncio.gather(
        *(resolver.txt(f"{domain}._report._dmarc.{dest}") for dest in external)
    )
    return [
        dest
        for dest, answer in zip(external, answers, strict=True)
        if answer.outcome is not Outcome.TIMEOUT
        and not any(DMARC_VERSION.match(r) for r in answer.records)
    ]


def _policy_findings(policy: str | None, record: DmarcRecord) -> list[Finding]:
    findings = []
    if policy == "reject" and record.pct == 100:
        findings.append(Finding("DMARC_ENFORCED"))
    elif policy == "quarantine":
        findings.append(Finding("DMARC_POLICY_QUARANTINE"))
    elif policy == "none":
        findings.append(Finding("DMARC_POLICY_NONE"))

    if policy in ("reject", "quarantine") and record.pct < 100:
        findings.append(Finding("DMARC_PCT_PARTIAL", f"pct={record.pct}"))

    sp = record.subdomain_policy
    if policy and sp and POLICY_STRENGTH[sp] < POLICY_STRENGTH[policy]:
        findings.append(Finding("DMARC_SUBDOMAIN_WEAKER", f"p={policy}, sp={sp}"))
    return findings


def _policy_value(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.lower()
    return value if value in POLICY_STRENGTH else None


def _pct_value(value: str | None) -> int:
    # RFC 7489 §6.3: pct defaults to 100; a value we can't read is treated the same
    if value is None or not value.isdigit():
        return 100
    return min(int(value), 100)


def _same_organization(domain: str, other: str) -> bool:
    # Without the public suffix list, a parent/child match is the honest
    # approximation of "same organizational domain".
    a, b = domain.lower().rstrip("."), other.lower().rstrip(".")
    return a == b or a.endswith("." + b) or b.endswith("." + a)
