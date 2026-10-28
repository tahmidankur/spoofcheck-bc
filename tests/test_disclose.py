from datetime import date

from spoofcheck.disclose import disclosure_note
from spoofcheck.store import StoredLevel


def test_note_lists_findings_worst_first_with_fix_links() -> None:
    stored = StoredLevel(
        "riverbend.example",
        "Village of Riverbend",
        "municipality",
        1,
        frozenset({"DMARC_POLICY_NONE", "SPF_TOO_MANY_LOOKUPS", "DKIM_FOUND"}),
    )
    note = disclosure_note("Village of Riverbend", stored, date(2026, 10, 28))
    assert note.index("SPF needs more than 10") < note.index("DMARC is in monitoring mode")
    assert "/fix/#SPF_TOO_MANY_LOOKUPS" in note
    assert "DKIM key found" not in note
    assert "MONITORING" in note
