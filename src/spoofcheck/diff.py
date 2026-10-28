from spoofcheck.report import LEVEL_WORDS
from spoofcheck.store import StoredLevel


def describe_changes(before: dict[str, StoredLevel], after: dict[str, StoredLevel]) -> list[str]:
    lines = []
    for domain in sorted(before.keys() | after.keys()):
        old, new = before.get(domain), after.get(domain)
        if old is None and new is not None:
            lines.append(f"{domain}: first scan, {LEVEL_WORDS[new.level]}")
            continue
        if old is None or new is None:
            lines.append(f"{domain}: no longer scanned")
            continue
        if old.level != new.level:
            lines.append(f"{domain}: was {LEVEL_WORDS[old.level]}, now {LEVEL_WORDS[new.level]}")
        for code in sorted(new.codes - old.codes):
            lines.append(f"{domain}: new finding {code}")
        for code in sorted(old.codes - new.codes):
            lines.append(f"{domain}: fixed {code}")
    return lines
