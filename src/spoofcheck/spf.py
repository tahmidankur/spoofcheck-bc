import re
from dataclasses import dataclass, field

from spoofcheck.findings import Finding
from spoofcheck.resolver import Answer, Outcome, Resolver

# RFC 7208 §4.6.4
MAX_LOOKUPS = 10
MAX_VOID_LOOKUPS = 2
MAX_DEPTH = 10

LOOKUP_MECHANISMS = ("include", "a", "mx", "ptr", "exists")
SPF_VERSION = re.compile(r"^v=spf1(\s|$)", re.IGNORECASE)
QUALIFIERS = "+-~?"


@dataclass(frozen=True)
class SpfTerm:
    qualifier: str
    name: str
    value: str | None


@dataclass(frozen=True)
class SpfRecord:
    raw: str
    mechanisms: tuple[SpfTerm, ...]
    redirect: str | None

    @property
    def all_qualifier(self) -> str | None:
        return next((t.qualifier for t in self.mechanisms if t.name == "all"), None)


@dataclass
class LookupTally:
    lookups: int = 0
    void_lookups: int = 0
    loop: bool = False
    broken: list[str] = field(default_factory=list)
    uses_ptr: bool = False
    timed_out: bool = False


@dataclass(frozen=True)
class SpfResult:
    seen: tuple[str, ...]
    record: str | None
    all_qualifier: str | None
    lookups: int
    void_lookups: int
    findings: tuple[Finding, ...]


def select_spf_records(txt: tuple[str, ...]) -> list[str]:
    return [s for s in txt if SPF_VERSION.match(s.strip())]


def parse_spf_record(raw: str) -> SpfRecord:
    mechanisms = []
    redirect = None
    for token in raw.split()[1:]:
        name, sep, value = token.partition("=")
        if sep and ":" not in name:
            if name.lower() == "redirect":
                redirect = value
            continue
        mechanisms.append(_parse_mechanism(token))
    return SpfRecord(raw=raw, mechanisms=tuple(mechanisms), redirect=redirect)


def _parse_mechanism(token: str) -> SpfTerm:
    qualifier = "+"
    if token[0] in QUALIFIERS:
        qualifier, token = token[0], token[1:]
    name, _, value = token.partition(":")
    # a/24 and mx/24 carry a CIDR length but no domain
    name = name.split("/", 1)[0].lower()
    return SpfTerm(qualifier, name, value or None)


async def check_spf(domain: str, resolver: Resolver) -> SpfResult:
    answer = await resolver.txt(domain)
    if answer.outcome is Outcome.TIMEOUT:
        return SpfResult((), None, None, 0, 0, (Finding("DNS_TIMEOUT", domain),))
    found = select_spf_records(answer.records)
    if not found:
        return SpfResult(answer.records, None, None, 0, 0, (Finding("SPF_MISSING"),))
    if len(found) > 1:
        # RFC 7208 §4.5: two records is a permerror, so nothing else matters
        return SpfResult(answer.records, None, None, 0, 0, (Finding("SPF_MULTIPLE"),))

    record = parse_spf_record(found[0])
    tally = LookupTally()
    all_qualifier = await count_spf_lookups(record, domain, resolver, tally, (domain.lower(),))
    findings = spf_findings(all_qualifier, tally)
    return SpfResult(
        answer.records, record.raw, all_qualifier, tally.lookups, tally.void_lookups, findings
    )


async def count_spf_lookups(
    record: SpfRecord,
    domain: str,
    resolver: Resolver,
    tally: LookupTally,
    path: tuple[str, ...],
) -> str | None:
    """Walk every include and redirect, adding to tally; return the effective all qualifier.

    Counting is static, the way checkers do it: every branch is followed, not only
    the path a given message would take.
    """
    for term in record.mechanisms:
        if term.name not in LOOKUP_MECHANISMS:
            continue
        tally.lookups += 1
        if term.name == "ptr":
            tally.uses_ptr = True
        elif term.name == "include" and term.value:
            await _follow(term.value, resolver, tally, path)
        elif term.name in ("a", "mx", "exists"):
            await _check_target(term, domain, resolver, tally)

    # RFC 7208 §6.1: redirect is ignored when the record has an all mechanism
    if record.redirect is None or record.all_qualifier is not None:
        return record.all_qualifier
    tally.lookups += 1
    return await _follow(record.redirect, resolver, tally, path)


async def _follow(
    target: str, resolver: Resolver, tally: LookupTally, path: tuple[str, ...]
) -> str | None:
    if "%" in target:
        # Macros expand per message, so the target can't be known ahead of time.
        return None
    target = target.lower().rstrip(".")
    if target in path or len(path) > MAX_DEPTH:
        tally.loop = True
        return None

    answer = await resolver.txt(target)
    if answer.outcome is Outcome.TIMEOUT:
        tally.timed_out = True
        return None
    if answer.is_void:
        tally.void_lookups += 1
    found = select_spf_records(answer.records)
    if len(found) != 1:
        # RFC 7208 §5.2: an include target with no (or two) SPF records is a permerror
        tally.broken.append(target)
        return None
    return await count_spf_lookups(
        parse_spf_record(found[0]), target, resolver, tally, (*path, target)
    )


async def _check_target(term: SpfTerm, domain: str, resolver: Resolver, tally: LookupTally) -> None:
    target = (term.value or domain).split("/", 1)[0]
    if "%" in target:
        return
    answer: Answer
    if term.name == "mx":
        answer = await resolver.mx(target)
    else:
        answer = await resolver.address(target)
    if answer.outcome is Outcome.TIMEOUT:
        tally.timed_out = True
    elif answer.is_void:
        tally.void_lookups += 1


def spf_findings(all_qualifier: str | None, tally: LookupTally) -> tuple[Finding, ...]:
    findings = []
    # RFC 7208 §4.6.4: more than 10 lookups is a permerror. A loop would hit the
    # same limit during real evaluation, so it's reported the same way.
    if tally.lookups > MAX_LOOKUPS or tally.loop:
        detail = "include loop" if tally.loop else f"{tally.lookups} lookups"
        findings.append(Finding("SPF_TOO_MANY_LOOKUPS", detail))
    if tally.void_lookups > MAX_VOID_LOOKUPS:
        findings.append(Finding("SPF_VOID_LOOKUPS", f"{tally.void_lookups} void lookups"))
    for target in tally.broken:
        findings.append(Finding("SPF_INCLUDE_BROKEN", target))
    if tally.uses_ptr:
        findings.append(Finding("SPF_PTR"))
    if tally.timed_out:
        findings.append(Finding("DNS_TIMEOUT", "SPF include"))

    if all_qualifier == "+":
        findings.append(Finding("SPF_PASS_ALL"))
    elif all_qualifier in ("?", None) and not tally.broken:
        findings.append(Finding("SPF_NEUTRAL_ALL"))
    elif all_qualifier == "~":
        findings.append(Finding("SPF_SOFTFAIL_ALL"))
    return tuple(findings)
