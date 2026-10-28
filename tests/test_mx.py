from spoofcheck.mx import check_mx, is_null_mx, parse_mx_records
from tests.fakes import FakeResolver


def test_null_mx_is_one_record_with_preference_zero_and_a_dot() -> None:
    assert is_null_mx(parse_mx_records(("0 .",)))
    assert not is_null_mx(parse_mx_records(("10 .",)))
    assert not is_null_mx(parse_mx_records(("0 .", "10 mail.example.ca.")))


def test_hosts_sort_by_preference_without_trailing_dot() -> None:
    hosts = parse_mx_records(("20 b.example.ca.", "10 A.example.ca."))
    assert [h.host for h in hosts] == ["a.example.ca", "b.example.ca"]


async def test_domain_without_mx_reports_mx_none() -> None:
    result = await check_mx("example.ca", FakeResolver({"example.ca": {}}))
    assert [f.code for f in result.findings] == ["MX_NONE"]
    assert not result.receives_mail
