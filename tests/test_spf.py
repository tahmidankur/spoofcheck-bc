from typing import Any

import pytest

from spoofcheck.spf import check_spf, parse_spf_record
from tests.fakes import FakeResolver
from tests.vectors import vector_cases


@pytest.mark.parametrize("case", vector_cases("spf.json"))
async def test_spf_vector(case: dict[str, Any]) -> None:
    result = await check_spf(case["domain"], FakeResolver(case["zone"]))
    expect = case["expect"]
    if "all" in expect:
        assert result.all_qualifier == expect["all"]
    if "lookups" in expect:
        assert result.lookups == expect["lookups"]
    if "void_lookups" in expect:
        assert result.void_lookups == expect["void_lookups"]
    assert {f.code for f in result.findings} == set(expect["findings"])


def test_modifiers_are_kept_apart_from_mechanisms() -> None:
    record = parse_spf_record(
        "v=spf1 a/24 -ip4:192.0.2.0/24 redirect=_spf.example.ca exp=x.example"
    )
    assert [(t.qualifier, t.name) for t in record.mechanisms] == [("+", "a"), ("-", "ip4")]
    assert record.redirect == "_spf.example.ca"


async def test_redirect_is_ignored_when_the_record_has_its_own_all() -> None:
    zone = {"example.ca": {"TXT": ["v=spf1 ~all redirect=_spf.example.ca"]}}
    result = await check_spf("example.ca", FakeResolver(zone))
    assert result.lookups == 0
    assert result.all_qualifier == "~"


async def test_a_mechanism_with_cidr_resolves_the_bare_host() -> None:
    zone = {
        "example.ca": {"TXT": ["v=spf1 a:mail.example.ca/28 -all"]},
        "mail.example.ca": {"A": ["192.0.2.10"]},
    }
    result = await check_spf("example.ca", FakeResolver(zone))
    assert result.void_lookups == 0
