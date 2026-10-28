from spoofcheck.dkim import check_dkim, looks_like_dkim_key
from tests.fakes import FakeResolver


async def test_key_at_selector1_is_found() -> None:
    zone = {"selector1._domainkey.example.ca": {"TXT": ["v=DKIM1; k=rsa; p=MIIBIjANBg"]}}
    result = await check_dkim("example.ca", FakeResolver(zone))
    assert result.selectors == ("selector1",)
    assert [f.code for f in result.findings] == ["DKIM_FOUND"]


async def test_no_common_selector_is_unknown_not_missing() -> None:
    result = await check_dkim("example.ca", FakeResolver({}))
    assert [f.code for f in result.findings] == ["DKIM_UNKNOWN"]


def test_only_a_p_tag_counts_as_a_key() -> None:
    assert looks_like_dkim_key("v=DKIM1; p=")
    assert not looks_like_dkim_key("v=spf1 -all")
