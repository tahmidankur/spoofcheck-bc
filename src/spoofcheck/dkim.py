import asyncio
from dataclasses import dataclass

from spoofcheck.findings import Finding
from spoofcheck.resolver import Resolver

# Selectors can't be listed (RFC 6376 §3.1), so we try the names big providers use.
COMMON_SELECTORS = ("selector1", "selector2", "google", "k1", "s1", "s2", "default", "dkim", "mail")


@dataclass(frozen=True)
class DkimResult:
    selectors: tuple[str, ...]
    findings: tuple[Finding, ...]


def looks_like_dkim_key(record: str) -> bool:
    tags = (part.strip().partition("=") for part in record.split(";"))
    return any(name.strip().lower() == "p" and sep for name, sep, _ in tags)


async def check_dkim(domain: str, resolver: Resolver) -> DkimResult:
    answers = await asyncio.gather(
        *(resolver.txt(f"{selector}._domainkey.{domain}") for selector in COMMON_SELECTORS)
    )
    found = tuple(
        selector
        for selector, answer in zip(COMMON_SELECTORS, answers, strict=True)
        if any(looks_like_dkim_key(r) for r in answer.records)
    )
    if found:
        return DkimResult(found, (Finding("DKIM_FOUND", ", ".join(found)),))
    return DkimResult((), (Finding("DKIM_UNKNOWN"),))
