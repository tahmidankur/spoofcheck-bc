from datetime import date

from spoofcheck import REPO_URL, SITE_URL
from spoofcheck.findings import Finding, by_severity
from spoofcheck.report import LEVEL_WORDS
from spoofcheck.store import StoredLevel

LEVEL_MEANING = {
    3: "receivers are told to refuse forged mail that uses your domain",
    2: "forged mail using your domain is filed as spam, or only some of it is refused",
    1: "receivers are asked to deliver forged mail as normal and only send you reports",
    0: "receivers get no instruction about forged mail using your domain, so most deliver it",
}


def disclosure_note(organization: str, stored: StoredLevel, scanned_on: date) -> str:
    """A private markdown note for one organization's IT team. Never written to disk or sent."""
    findings = [
        f for f in by_severity(tuple(Finding(c) for c in stored.codes)) if f.severity != "good"
    ]
    lines = [
        f"Subject: Email spoofing records for {stored.domain}",
        "",
        f"Hello {organization} IT team,",
        "",
        "I'm a Computing Science student at Thompson Rivers University. As part of an "
        "independent project, I read the public DNS records that tell other mail servers how "
        f"to treat forged email from B.C. public bodies. On {scanned_on:%-d %B %Y} the records "
        f"for `{stored.domain}` were at the level {LEVEL_WORDS[stored.level]}: "
        f"{LEVEL_MEANING[stored.level]}.",
        "",
        "Only public DNS was read. Nothing was sent to your mail servers, and your results are "
        "not published by name; the public site shows totals by sector only.",
        "",
    ]
    if findings:
        lines += ["What I found, most important first:", ""]
        for number, finding in enumerate(findings, 1):
            entry = finding.entry
            lines.append(f"{number}. **{entry.title}** ({entry.severity}). {entry.explain}")
            if entry.fix:
                lines.append(f"   What to change: {entry.fix.replace('<domain>', stored.domain)}")
            lines.append(f"   More detail: {SITE_URL}/fix/#{entry.code}")
        lines.append("")
    else:
        lines += ["I didn't find anything that needs changing. Thank you for keeping these up.", ""]
    lines += [
        "You know your mail setup far better than a DNS lookup can, so please treat this as a "
        "second pair of eyes rather than an audit. If anything here is wrong, I'd like to hear "
        f"about it. The method and source code are at {REPO_URL}.",
        "",
        "Thank you,",
        "Tahmid Hossain Ankur",
    ]
    return "\n".join(lines)
