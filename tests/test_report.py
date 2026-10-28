from spoofcheck.dmarc import evaluate_dmarc
from spoofcheck.report import read_dmarc_tags, verdict_sentence


def test_reject_on_part_of_the_mail_says_how_much_is_refused() -> None:
    sentence = verdict_sentence(
        evaluate_dmarc(["v=DMARC1; p=reject; pct=25; rua=mailto:d@example.ca"])
    )
    assert sentence.startswith("Only 25% of forged mail")


def test_matching_subdomain_policy_reads_as_same_rule() -> None:
    dmarc = evaluate_dmarc(["v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:d@example.ca"])
    assert ("sp=quarantine", "Same rule for made-up subdomains.") in read_dmarc_tags(dmarc)
