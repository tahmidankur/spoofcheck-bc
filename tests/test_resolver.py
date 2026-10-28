from spoofcheck.resolver import Outcome
from tests.fakes import FakeResolver


async def test_fake_zone_missing_name_is_nxdomain_and_missing_type_is_empty() -> None:
    resolver = FakeResolver({"example.ca": {"TXT": ["v=spf1 -all"]}})
    assert (await resolver.txt("nope.example.ca")).outcome is Outcome.NXDOMAIN
    assert (await resolver.mx("example.ca")).outcome is Outcome.EMPTY
    assert (await resolver.txt("EXAMPLE.ca.")).records == ("v=spf1 -all",)
