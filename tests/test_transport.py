import httpx

from spoofcheck.transport import check_mta_sts, check_tls_rpt
from tests.fakes import FakeResolver

STS_ZONE = {"_mta-sts.example.ca": {"TXT": ["v=STSv1; id=20261028"]}}
POLICY_URL = "https://mta-sts.example.ca/.well-known/mta-sts.txt"


def client_serving(status: int, body: str = "") -> httpx.AsyncClient:
    def serve(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == POLICY_URL
        return httpx.Response(status, text=body)

    return httpx.AsyncClient(transport=httpx.MockTransport(serve))


def client_that_fails() -> httpx.AsyncClient:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    return httpx.AsyncClient(transport=httpx.MockTransport(refuse))


async def test_enforce_policy_has_no_findings() -> None:
    body = "version: STSv1\nmode: enforce\nmx: mail.example.ca\nmax_age: 86400\n"
    result = await check_mta_sts("example.ca", FakeResolver(STS_ZONE), client_serving(200, body))
    assert result.mode == "enforce"
    assert result.findings == ()


async def test_testing_mode_is_reported() -> None:
    body = "version: STSv1\nmode: testing\n"
    result = await check_mta_sts("example.ca", FakeResolver(STS_ZONE), client_serving(200, body))
    assert [f.code for f in result.findings] == ["MTASTS_TESTING"]


async def test_txt_present_but_policy_fetch_fails_is_unreachable() -> None:
    result = await check_mta_sts("example.ca", FakeResolver(STS_ZONE), client_that_fails())
    assert [f.code for f in result.findings] == ["MTASTS_POLICY_UNREACHABLE"]


async def test_policy_returning_404_is_unreachable() -> None:
    result = await check_mta_sts("example.ca", FakeResolver(STS_ZONE), client_serving(404))
    assert [f.code for f in result.findings] == ["MTASTS_POLICY_UNREACHABLE"]


async def test_nothing_published_skips_the_fetch() -> None:
    result = await check_mta_sts("example.ca", FakeResolver({}), client_that_fails())
    assert [f.code for f in result.findings] == ["MTASTS_MISSING"]


async def test_tls_rpt_record_is_found() -> None:
    zone = {"_smtp._tls.example.ca": {"TXT": ["v=TLSRPTv1; rua=mailto:tls@example.ca"]}}
    assert (await check_tls_rpt("example.ca", FakeResolver(zone))).findings == ()
    missing = await check_tls_rpt("example.ca", FakeResolver({}))
    assert [f.code for f in missing.findings] == ["TLSRPT_MISSING"]
