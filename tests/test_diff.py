from spoofcheck.diff import describe_changes
from spoofcheck.store import StoredLevel


def stored(level: int, *codes: str) -> StoredLevel:
    return StoredLevel(
        "riverbend.example", "Village of Riverbend", "municipality", level, frozenset(codes)
    )


def test_level_change_and_fixed_finding_are_listed() -> None:
    before = {"riverbend.example": stored(1, "DMARC_POLICY_NONE", "SPF_PTR")}
    after = {"riverbend.example": stored(3, "DMARC_ENFORCED", "SPF_PTR")}
    assert describe_changes(before, after) == [
        "riverbend.example: was MONITORING, now ENFORCED",
        "riverbend.example: new finding DMARC_ENFORCED",
        "riverbend.example: fixed DMARC_POLICY_NONE",
    ]


def test_nothing_changed_gives_no_lines() -> None:
    same = {"riverbend.example": stored(2, "DMARC_POLICY_QUARANTINE")}
    assert describe_changes(same, same) == []
