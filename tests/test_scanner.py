from typing import Any

import httpx
import pytest

from spoofcheck.scanner import check_domain, normalize_domain
from tests.fakes import FakeResolver
from tests.vectors import vector_cases

VECTOR_CHECKS = {"dmarc", "spf", "mx", "dns"}


def offline_client() -> httpx.AsyncClient:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected fetch of {request.url}")

    return httpx.AsyncClient(transport=httpx.MockTransport(refuse))


@pytest.mark.parametrize("case", vector_cases("domain.json"))
async def test_domain_vector(case: dict[str, Any]) -> None:
    report = await check_domain(case["domain"], FakeResolver(case["zone"]), offline_client())
    codes = {f.code for f in report.findings if f.entry.check in VECTOR_CHECKS}
    assert report.level == case["expect"]["level"]
    assert codes == set(case["expect"]["findings"])


async def test_nxdomain_skips_every_other_lookup() -> None:
    resolver = FakeResolver({})
    await check_domain("example.ca", resolver, offline_client())
    assert resolver.queries == [("example.ca", "TXT")]


@pytest.mark.parametrize(
    ("typed", "domain"),
    [("Example.CA.", "example.ca"), ("  staff@riverbend.example ", "riverbend.example")],
)
def test_domain_input_is_cleaned_up(typed: str, domain: str) -> None:
    assert normalize_domain(typed) == domain


@pytest.mark.parametrize("typed", ["", "localhost", "exa mple.ca", "https://example.ca/"])
def test_things_that_are_not_domains_are_refused(typed: str) -> None:
    with pytest.raises(ValueError):
        normalize_domain(typed)
