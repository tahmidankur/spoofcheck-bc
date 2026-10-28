from typing import Any

import pytest

from spoofcheck.dmarc import (
    check_dmarc,
    evaluate_dmarc,
    parse_dmarc_tags,
    parse_report_addresses,
)
from tests.fakes import FakeResolver
from tests.vectors import vector_cases


@pytest.mark.parametrize("case", vector_cases("dmarc.json"))
def test_dmarc_vector(case: dict[str, Any]) -> None:
    result = evaluate_dmarc(case["txt"])
    expect = case["expect"]
    assert result.level == expect["level"]
    if "policy" in expect:
        assert result.policy == expect["policy"]
    if "pct" in expect:
        assert result.pct == expect["pct"]
    if "subdomain_policy" in expect:
        assert result.subdomain_policy == expect["subdomain_policy"]
    assert {f.code for f in result.findings} == set(expect["findings"])


def test_tag_names_are_case_insensitive_and_first_value_wins() -> None:
    assert parse_dmarc_tags("V=DMARC1; P=reject; p=none") == {"v": "DMARC1", "p": "reject"}


def test_report_size_suffix_is_dropped_and_http_uris_ignored() -> None:
    value = "mailto:a@example.ca!10m, https://example.ca/r, mailto:broken"
    assert parse_report_addresses(value) == ("a@example.ca",)


async def test_external_report_domain_without_authorization_is_reported() -> None:
    resolver = FakeResolver(
        {"_dmarc.example.ca": {"TXT": ["v=DMARC1; p=reject; rua=mailto:r@reports.example"]}}
    )
    result = await check_dmarc("example.ca", resolver)
    unauthorized = [f for f in result.findings if f.code == "DMARC_REPORT_DEST_UNAUTHORIZED"]
    assert [f.detail for f in unauthorized] == ["reports.example"]


async def test_external_report_domain_that_publishes_authorization_is_accepted() -> None:
    resolver = FakeResolver(
        {
            "_dmarc.example.ca": {"TXT": ["v=DMARC1; p=reject; rua=mailto:r@reports.example"]},
            "example.ca._report._dmarc.reports.example": {"TXT": ["v=DMARC1"]},
        }
    )
    result = await check_dmarc("example.ca", resolver)
    assert {f.code for f in result.findings} == {"DMARC_ENFORCED"}


async def test_report_address_on_a_subdomain_needs_no_authorization() -> None:
    resolver = FakeResolver(
        {"_dmarc.example.ca": {"TXT": ["v=DMARC1; p=reject; rua=mailto:r@dmarc.example.ca"]}}
    )
    result = await check_dmarc("example.ca", resolver)
    assert ("example.ca._report._dmarc.dmarc.example.ca", "TXT") not in resolver.queries
    assert {f.code for f in result.findings} == {"DMARC_ENFORCED"}
