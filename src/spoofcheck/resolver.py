import asyncio
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver

LIFETIME_SECONDS = 5.0
MAX_IN_FLIGHT = 4


class Outcome(StrEnum):
    OK = "ok"
    NXDOMAIN = "nxdomain"
    EMPTY = "empty"
    TIMEOUT = "timeout"


@dataclass(frozen=True)
class Answer:
    outcome: Outcome
    records: tuple[str, ...] = ()

    @property
    def is_void(self) -> bool:
        # RFC 7208 §4.6.4: a void lookup is NXDOMAIN or an answer with no records
        return self.outcome in (Outcome.NXDOMAIN, Outcome.EMPTY)


class Resolver(Protocol):
    async def txt(self, name: str) -> Answer: ...
    async def mx(self, name: str) -> Answer: ...
    async def address(self, name: str) -> Answer: ...


class DnsResolver:
    """Real DNS through dnspython, never more than MAX_IN_FLIGHT queries at once."""

    def __init__(self, nameservers: list[str] | None = None) -> None:
        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.lifetime = LIFETIME_SECONDS
        if nameservers:
            self._resolver.nameservers = nameservers
        self._slots = asyncio.Semaphore(MAX_IN_FLIGHT)

    @property
    def description(self) -> str:
        return ",".join(str(ns) for ns in self._resolver.nameservers)

    async def txt(self, name: str) -> Answer:
        return await self._query(name, dns.rdatatype.TXT)

    async def mx(self, name: str) -> Answer:
        return await self._query(name, dns.rdatatype.MX)

    async def address(self, name: str) -> Answer:
        answer = await self._query(name, dns.rdatatype.A)
        if answer.outcome is Outcome.EMPTY:
            return await self._query(name, dns.rdatatype.AAAA)
        return answer

    async def _query(self, name: str, rdtype: dns.rdatatype.RdataType) -> Answer:
        async with self._slots:
            try:
                response = await self._resolver.resolve(name, rdtype)
            except dns.resolver.NXDOMAIN:
                return Answer(Outcome.NXDOMAIN)
            except dns.resolver.NoAnswer:
                return Answer(Outcome.EMPTY)
            # Every nameserver failing (usually SERVFAIL) leaves the result as
            # incomplete as a timeout does, so both become "try next week".
            except (dns.exception.Timeout, dns.resolver.NoNameservers):
                return Answer(Outcome.TIMEOUT)
        return Answer(Outcome.OK, tuple(_rdata_text(r) for r in response))


def _rdata_text(rdata: object) -> str:
    strings = getattr(rdata, "strings", None)
    if strings is not None:
        # A TXT record longer than 255 bytes arrives as several strings that
        # mean one value (RFC 7208 §3.3), so join them without spaces.
        return b"".join(strings).decode("utf-8", errors="replace")
    return str(rdata)
