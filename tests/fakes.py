from spoofcheck.resolver import Answer, Outcome

Zone = dict[str, dict[str, list[str]]]


class FakeResolver:
    """DNS answered from a vector's zone: a missing name is NXDOMAIN, a missing type is empty."""

    def __init__(self, zone: Zone) -> None:
        self.zone = {_normal(name): records for name, records in zone.items()}
        self.queries: list[tuple[str, str]] = []

    async def txt(self, name: str) -> Answer:
        return self._lookup(name, "TXT")

    async def mx(self, name: str) -> Answer:
        return self._lookup(name, "MX")

    async def address(self, name: str) -> Answer:
        answer = self._lookup(name, "A")
        if answer.outcome is Outcome.EMPTY:
            return self._lookup(name, "AAAA")
        return answer

    def _lookup(self, name: str, rdtype: str) -> Answer:
        self.queries.append((_normal(name), rdtype))
        records = self.zone.get(_normal(name))
        if records is None:
            return Answer(Outcome.NXDOMAIN)
        if not records.get(rdtype):
            return Answer(Outcome.EMPTY)
        return Answer(Outcome.OK, tuple(records[rdtype]))


def _normal(name: str) -> str:
    return name.lower().rstrip(".")
