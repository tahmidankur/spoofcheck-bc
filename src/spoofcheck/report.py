from datetime import datetime
from typing import Any

from spoofcheck.dmarc import DmarcResult
from spoofcheck.findings import Finding, by_severity
from spoofcheck.scanner import DomainReport

LEVEL_WORDS = {3: "ENFORCED", 2: "PARTIAL", 1: "MONITORING", 0: "UNPROTECTED"}

POLICY_MEANING = {
    "none": "Mail that fails the check is delivered as normal.",
    "quarantine": "Mail that fails the check goes to spam.",
    "reject": "Mail that fails the check is refused.",
}
ALIGNMENT_MEANING = {
    "r": "relaxed: a subdomain of the From address counts as a match.",
    "s": "strict: only the exact From domain counts.",
}
ALL_MEANING = {
    "-": "Servers not listed are failed.",
    "~": "Servers not listed are marked suspicious, not failed.",
    "?": "Makes no claim about servers not listed.",
    "+": "Every server on the internet is allowed to send.",
    None: "No all at the end, so servers not listed are neither passed nor failed.",
}


def verdict_sentence(dmarc: DmarcResult | None) -> str:
    if dmarc is None or dmarc.level == 0:
        return (
            "Receivers get no instruction about forged mail from this domain, so most deliver it."
        )
    if dmarc.level == 3:
        return "Receivers are told to refuse forged mail from this domain."
    if dmarc.policy == "reject":
        return (
            f"Only {dmarc.pct}% of forged mail from this domain is refused. "
            "The rest is filed as spam."
        )
    if dmarc.level == 2:
        return (
            "Forged mail from this domain is filed as spam, not refused. "
            "People can still find it and open it."
        )
    return "Receivers are asked to deliver forged mail as normal and only send reports."


def read_dmarc_tags(dmarc: DmarcResult) -> list[tuple[str, str]]:
    """Each DMARC tag next to a sentence a resident could follow."""
    if dmarc.record is None:
        return []
    tags = dmarc.record.tags
    lines = []
    if dmarc.policy:
        lines.append((f"p={tags.get('p', dmarc.policy)}", POLICY_MEANING[dmarc.policy]))
    if "sp" in tags:
        sp = dmarc.record.subdomain_policy
        if sp == dmarc.policy:
            lines.append((f"sp={tags['sp']}", "Same rule for made-up subdomains."))
        elif sp:
            lines.append((f"sp={tags['sp']}", "Subdomains: " + POLICY_MEANING[sp].lower()))
    if "pct" in tags:
        lines.append((f"pct={tags['pct']}", f"The policy applies to {dmarc.pct}% of failing mail."))
    if dmarc.record.report_addresses:
        lines.append(("rua", f"Daily reports go to {', '.join(dmarc.record.report_addresses)}."))
    for tag, label in (("adkim", "DKIM"), ("aspf", "SPF")):
        value = tags.get(tag, "").lower()
        if value in ALIGNMENT_MEANING:
            lines.append((f"{tag}={value}", f"{label} alignment is {ALIGNMENT_MEANING[value]}"))
    return lines


def also_checked(report: DomainReport) -> list[tuple[str, str]]:
    mx, dkim, sts, tls = report.mx, report.dkim, report.mta_sts, report.tls_rpt
    if mx is None or dkim is None or sts is None or tls is None:
        return []
    if mx.null_mx:
        servers = "None. The domain says it takes no mail."
    elif mx.hosts:
        count = len(mx.hosts)
        servers = f"{count} server{'s' if count > 1 else ''}: {', '.join(h.host for h in mx.hosts)}"
    else:
        servers = "None listed"
    if dkim.selectors:
        dkim_text = f"Found at {', '.join(dkim.selectors)}"
    else:
        dkim_text = "Not found at common selectors, which doesn't mean it's missing"
    if sts.mode:
        sts_text = f"Published, mode {sts.mode}"
    else:
        sts_text = "Published, but the policy file didn't load" if sts.record else "Not published"
    return [
        ("Mail servers", servers),
        ("DKIM", dkim_text),
        ("MTA-STS", sts_text),
        ("TLS reports", "Published" if tls.record else "Not published"),
    ]


def fix_list(report: DomainReport) -> list[Finding]:
    return [f for f in by_severity(report.findings) if f.severity != "good"]


def report_to_dict(report: DomainReport, checked_at: datetime) -> dict[str, Any]:
    dmarc, spf, mx = report.dmarc, report.spf, report.mx
    return {
        "domain": report.domain,
        "checked_at": checked_at.isoformat(timespec="seconds"),
        "level": report.level,
        "level_word": LEVEL_WORDS[report.level],
        "error": report.error,
        "dmarc": dmarc
        and {
            "seen": list(dmarc.seen),
            "record": dmarc.record.raw if dmarc.record else None,
            "policy": dmarc.policy,
            "subdomain_policy": dmarc.subdomain_policy,
            "pct": dmarc.pct,
        },
        "spf": spf
        and {
            "record": spf.record,
            "all": spf.all_qualifier,
            "lookups": spf.lookups,
            "void_lookups": spf.void_lookups,
        },
        "mx": mx and {"hosts": [[h.preference, h.host] for h in mx.hosts], "null_mx": mx.null_mx},
        "mta_sts": report.mta_sts
        and {"record": report.mta_sts.record, "mode": report.mta_sts.mode},
        "tls_rpt": report.tls_rpt and {"record": report.tls_rpt.record},
        "dkim": report.dkim and {"selectors": list(report.dkim.selectors)},
        "findings": [
            {"code": f.code, "severity": f.severity, "title": f.entry.title, "detail": f.detail}
            for f in by_severity(report.findings)
        ],
    }
