# Test vectors

Shared by the Python package and `check.js`. Both test suites load these files and must pass every case.

- `dmarc.json`: TXT records found at `_dmarc.<domain>` and the expected level, tags and findings.
- `spf.json`: a fake DNS zone and the expected `all` qualifier, lookup count, void lookup count and findings.
- `domain.json`: whole-domain cases across DMARC, SPF and MX.

Zone format: `{"name": {"TXT": [...], "MX": ["10 mail.example.ca."], "A": ["192.0.2.1"]}}`. A name missing from the zone is NXDOMAIN. A record type missing under a name that exists is an empty answer.

Findings are compared as sets. A key left out of `expect` is not checked.

Add a vector before fixing any parsing bug, so the bug can't come back in either implementation.
