# Findings catalogue

Generated from `data/findings.json`, which is the source of truth for the CLI, the website and the in-browser checker. Edit the JSON, not this file.

Severity: `high` breaks protection outright, `medium` weakens it, `low` is worth fixing, `info` is context, `good` is something done right.

## DMARC

| Code | Severity | Title |
|---|---|---|
| `DMARC_MISSING` | high | No DMARC record |
| `DMARC_MULTIPLE` | high | More than one DMARC record |
| `DMARC_SYNTAX` | high | DMARC record can't be read |
| `DMARC_POLICY_NONE` | medium | DMARC is in monitoring mode |
| `DMARC_POLICY_QUARANTINE` | low | Forged mail goes to spam, not refused |
| `DMARC_PCT_PARTIAL` | medium | Policy applies to only part of the mail |
| `DMARC_SUBDOMAIN_WEAKER` | medium | Subdomains are less protected than the main domain |
| `DMARC_NO_REPORTS` | low | No address for DMARC reports |
| `DMARC_REPORT_DEST_UNAUTHORIZED` | info | Report address on another domain is not authorized |
| `DMARC_ENFORCED` | good | Forged mail is refused |

### `DMARC_MISSING`: No DMARC record

Receiving mail servers get no instruction about forged mail that claims to come from this domain, so most will deliver it.

**Fix:** Publish a TXT record at _dmarc.<domain>. Start with p=none and a rua address to collect reports, then move to quarantine and reject once every legitimate sender passes.

```
_dmarc.example.ca  TXT  "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.ca"
```

Reference: RFC 7489 §6.1; CCCS ITSP.40.065

### `DMARC_MULTIPLE`: More than one DMARC record

When a domain publishes two DMARC records, receivers are required to ignore both. The domain is effectively unprotected.

**Fix:** Merge them into one TXT record at _dmarc.<domain> and delete the other.

Reference: RFC 7489 §6.6.3

### `DMARC_SYNTAX`: DMARC record can't be read

The record exists but receivers can't use it, usually because v=DMARC1 is not the first tag or the p tag is missing or misspelled.

**Fix:** Rewrite the record so it starts with v=DMARC1 followed by p=none, p=quarantine or p=reject.

```
_dmarc.example.ca  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.ca"
```

Reference: RFC 7489 §6.3, §6.4

### `DMARC_POLICY_NONE`: DMARC is in monitoring mode

p=none asks receivers to deliver forged mail as normal and only send reports. It is the right first step, not a place to stay.

**Fix:** Read the aggregate reports, make sure every service that sends as this domain passes SPF or DKIM, then change p=none to p=quarantine.

Reference: RFC 7489 §6.3; CCCS ITSP.40.065 Annex A

### `DMARC_POLICY_QUARANTINE`: Forged mail goes to spam, not refused

p=quarantine tells receivers to treat failing mail as suspicious, usually by filing it as spam. Recipients can still find and open it.

**Fix:** Once reports show no legitimate mail failing, change p=quarantine to p=reject.

Reference: RFC 7489 §6.3

### `DMARC_PCT_PARTIAL`: Policy applies to only part of the mail

A pct value below 100 means the policy is applied to only that percentage of failing messages. The rest are treated as if the policy were one step weaker.

**Fix:** Raise pct to 100, or remove the tag, since 100 is the default.

Reference: RFC 7489 §6.3

### `DMARC_SUBDOMAIN_WEAKER`: Subdomains are less protected than the main domain

The sp tag sets a weaker policy for subdomains, so forged mail from made-up subdomains such as billing.example.ca is treated more leniently.

**Fix:** Set sp to the same value as p, or remove sp so subdomains inherit p.

Reference: RFC 7489 §6.3

### `DMARC_NO_REPORTS`: No address for DMARC reports

Without a rua address the domain owner never sees who is sending mail in its name, which makes it hard to tighten the policy safely.

**Fix:** Add rua=mailto: with a mailbox or a reporting service you control.

Reference: RFC 7489 §7.2

### `DMARC_REPORT_DEST_UNAUTHORIZED`: Report address on another domain is not authorized

Reports are addressed to a different domain, and that domain has not published the record saying it accepts them. Many receivers will skip sending reports there.

**Fix:** Ask the owner of the report domain to publish <your-domain>._report._dmarc.<their-domain> TXT "v=DMARC1".

Reference: RFC 7489 §7.1

### `DMARC_ENFORCED`: Forged mail is refused

p=reject applies to all failing mail. Receivers that honour DMARC will refuse messages that forge this domain.

Reference: RFC 7489 §6.3

## SPF

| Code | Severity | Title |
|---|---|---|
| `SPF_MISSING` | medium | No SPF record |
| `SPF_MULTIPLE` | high | More than one SPF record |
| `SPF_TOO_MANY_LOOKUPS` | high | SPF needs more than 10 DNS lookups |
| `SPF_VOID_LOOKUPS` | medium | SPF points at names that don't exist |
| `SPF_INCLUDE_BROKEN` | high | SPF includes a record that isn't there |
| `SPF_PASS_ALL` | high | SPF allows every server on the internet |
| `SPF_NEUTRAL_ALL` | medium | SPF makes no claim about other servers |
| `SPF_SOFTFAIL_ALL` | info | SPF uses softfail |
| `SPF_PTR` | low | SPF uses the ptr mechanism |

### `SPF_MISSING`: No SPF record

The domain doesn't list which servers are allowed to send its mail, so SPF can never pass. DMARC then depends entirely on DKIM.

**Fix:** Publish one TXT record at the domain listing your mail providers, ending in -all or ~all.

```
example.ca  TXT  "v=spf1 include:spf.protection.outlook.com -all"
```

Reference: RFC 7208 §3

### `SPF_MULTIPLE`: More than one SPF record

Two records starting with v=spf1 cause a permanent error, so SPF fails for every message.

**Fix:** Combine the mechanisms into a single record and delete the other.

Reference: RFC 7208 §4.5

### `SPF_TOO_MANY_LOOKUPS`: SPF needs more than 10 DNS lookups

Counting every include, a, mx, ptr, exists and redirect, including those inside included records, the total is over 10. Receivers return a permanent error and SPF fails.

**Fix:** Remove services you no longer use, replace a and mx with ip4 and ip6 ranges where they are stable, or move some senders to a subdomain.

Reference: RFC 7208 §4.6.4

### `SPF_VOID_LOOKUPS`: SPF points at names that don't exist

More than two lookups in the record return no answer. Receivers may treat this as a permanent error.

**Fix:** Remove includes and hostnames that no longer resolve.

Reference: RFC 7208 §4.6.4

### `SPF_INCLUDE_BROKEN`: SPF includes a record that isn't there

An include points to a domain that has no SPF record. That is a permanent error, so SPF fails for every message.

**Fix:** Fix the hostname in the include or remove it.

Reference: RFC 7208 §5.2

### `SPF_PASS_ALL`: SPF allows every server on the internet

+all tells receivers that any server may send for this domain, which defeats the purpose of SPF.

**Fix:** Change +all to -all or ~all.

Reference: RFC 7208 §5.1

### `SPF_NEUTRAL_ALL`: SPF makes no claim about other servers

?all, or a record with no all at all, says nothing about servers not listed. Mail from them is neither passed nor failed.

**Fix:** End the record with -all or ~all.

Reference: RFC 7208 §4.7, §5.1

### `SPF_SOFTFAIL_ALL`: SPF uses softfail

~all marks unlisted servers as suspicious rather than failing them. With DMARC at quarantine or reject this is common and acceptable. -all is the stricter choice.

**Fix:** Optional: change ~all to -all once you are sure every sender is listed.

Reference: RFC 7208 §8.5

### `SPF_PTR`: SPF uses the ptr mechanism

ptr is slow, unreliable and discouraged by the SPF standard. Some receivers ignore it.

**Fix:** Replace ptr with ip4, ip6 or include entries.

Reference: RFC 7208 §5.5

## MX

| Code | Severity | Title |
|---|---|---|
| `MX_NONE` | info | No mail servers listed |
| `MX_NULL` | good | Domain declares it takes no mail |
| `NON_MAIL_DOMAIN_OPEN` | medium | Domain doesn't use email but can still be forged |

### `MX_NONE`: No mail servers listed

The domain has no MX records, so it probably doesn't receive mail. It can still be forged as a sender.

**Fix:** If the domain never sends mail, see NON_MAIL_DOMAIN_OPEN.

Reference: RFC 5321 §5.1

### `MX_NULL`: Domain declares it takes no mail

A null MX record tells senders this domain never accepts mail. It's the correct setup for a domain used only for a website.

```
example.ca  MX  0 .
```

Reference: RFC 7505

### `NON_MAIL_DOMAIN_OPEN`: Domain doesn't use email but can still be forged

The domain has no mail servers or a null MX, but hasn't published v=spf1 -all and p=reject. Attackers favour domains like this because nobody watches them.

**Fix:** Publish v=spf1 -all at the domain and v=DMARC1; p=reject at _dmarc.

```
example.ca  TXT  "v=spf1 -all"
_dmarc.example.ca  TXT  "v=DMARC1; p=reject;"
```

Reference: CCCS ITSP.40.065; RFC 7505

## Transport security (MTA-STS, TLS-RPT)

| Code | Severity | Title |
|---|---|---|
| `MTASTS_MISSING` | info | No MTA-STS policy |
| `MTASTS_TESTING` | info | MTA-STS is in testing mode |
| `MTASTS_POLICY_UNREACHABLE` | low | MTA-STS policy file can't be fetched |
| `TLSRPT_MISSING` | info | No TLS reporting address |

### `MTASTS_MISSING`: No MTA-STS policy

Other mail servers aren't told to require an encrypted connection when delivering to this domain. This is about privacy in transit, not spoofing.

**Fix:** Publish _mta-sts.<domain> TXT and a policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt, starting in testing mode.

Reference: RFC 8461

### `MTASTS_TESTING`: MTA-STS is in testing mode

The policy is published but senders only report problems instead of refusing unencrypted delivery.

**Fix:** Change mode: testing to mode: enforce once TLS reports are clean.

Reference: RFC 8461 §5

### `MTASTS_POLICY_UNREACHABLE`: MTA-STS policy file can't be fetched

The TXT record says a policy exists, but the policy file did not load over HTTPS. Senders will ignore MTA-STS.

**Fix:** Check that https://mta-sts.<domain>/.well-known/mta-sts.txt loads with a valid certificate.

Reference: RFC 8461 §3.3

### `TLSRPT_MISSING`: No TLS reporting address

The domain won't hear about failed encrypted deliveries.

**Fix:** Publish _smtp._tls.<domain> TXT "v=TLSRPTv1; rua=mailto:tls-reports@<domain>".

Reference: RFC 8460

## DKIM

| Code | Severity | Title |
|---|---|---|
| `DKIM_FOUND` | good | DKIM key found |
| `DKIM_UNKNOWN` | info | DKIM not found at common selectors |

### `DKIM_FOUND`: DKIM key found

A DKIM public key was found at one of the common selectors, so at least one sender signs mail for this domain.

Reference: RFC 6376 §3.6

### `DKIM_UNKNOWN`: DKIM not found at common selectors

DKIM keys can only be found if you know the selector name, and none of the common ones answered. This does not mean DKIM is missing.

Reference: RFC 6376 §3.1

## DNS errors

| Code | Severity | Title |
|---|---|---|
| `DNS_NXDOMAIN` | high | Domain doesn't exist |
| `DNS_TIMEOUT` | info | DNS didn't answer in time |

### `DNS_NXDOMAIN`: Domain doesn't exist

DNS says this domain doesn't exist. The inventory entry is probably wrong.

**Fix:** Check the domain against the organization's official website and correct data/inventory.csv.

### `DNS_TIMEOUT`: DNS didn't answer in time

The lookup timed out, so this result is incomplete. The next scan will try again.
