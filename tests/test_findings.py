import pytest

from spoofcheck.findings import Finding, by_severity, load_catalogue


def test_every_catalogue_entry_has_a_known_severity() -> None:
    for entry in load_catalogue().values():
        assert entry.severity in ("good", "info", "low", "medium", "high")


def test_unknown_code_raises() -> None:
    with pytest.raises(KeyError):
        Finding("DMARC_TYPO")


def test_findings_sort_worst_first() -> None:
    ordered = by_severity((Finding("DKIM_FOUND"), Finding("DMARC_MISSING")))
    assert [f.code for f in ordered] == ["DMARC_MISSING", "DKIM_FOUND"]
