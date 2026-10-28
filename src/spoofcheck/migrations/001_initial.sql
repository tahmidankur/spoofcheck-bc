CREATE TABLE organization (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  sector TEXT NOT NULL,
  region TEXT,
  source_url TEXT,
  UNIQUE (name)
);

CREATE TABLE domain (
  id INTEGER PRIMARY KEY,
  organization_id INTEGER NOT NULL REFERENCES organization(id),
  name TEXT NOT NULL UNIQUE,
  verified INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE scan (
  id INTEGER PRIMARY KEY,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  tool_version TEXT NOT NULL,
  resolver TEXT NOT NULL,
  iso_week TEXT NOT NULL
);

CREATE TABLE result (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scan(id),
  domain_id INTEGER NOT NULL REFERENCES domain(id),
  level INTEGER NOT NULL,
  dmarc_raw TEXT,
  dmarc_policy TEXT,
  dmarc_subdomain_policy TEXT,
  dmarc_pct INTEGER,
  spf_raw TEXT,
  spf_all TEXT,
  spf_lookups INTEGER,
  mx_hosts TEXT,
  mta_sts_mode TEXT,
  tls_rpt INTEGER,
  dkim_selectors TEXT,
  error TEXT,
  UNIQUE (scan_id, domain_id)
);

CREATE TABLE finding (
  id INTEGER PRIMARY KEY,
  result_id INTEGER NOT NULL REFERENCES result(id),
  code TEXT NOT NULL,
  detail TEXT
);
