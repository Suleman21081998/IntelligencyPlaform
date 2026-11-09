"""Firmographics feed: validate a real vendor file, or generate a mock one.

The scan dump has no headcount, hiring or funding data. Those signals come
from a firmographics file (Apollo / ZoomInfo / Crunchbase export, etc.)
keyed by registered domain. Until one is supplied, ``--mock`` writes a
deterministic SYNTHETIC file for every prospect domain in the scan so the
full pipeline and dashboard can be exercised end to end.

Expected schema (JSON or Parquet; missing columns are defaulted in ingest.py):
    company_id (registered domain), name, industry, employee_count,
    tech_stack (list), hiring_signals (list of open job titles),
    is_regulated (bool), days_since_funding (int)

Usage:
    python firmographics.py --mock      # synthetic, derived from scan domains
    python firmographics.py --check     # report match rate of the current feed
"""

from __future__ import annotations

import argparse
import sys

import config
from ingest import register_views
from signals import _industry_from_domain_sql, _lookup_tables, _q, candidate_exposures_sql

MOCK_PATH = config.DATA_DIR / "firmographics_mock.parquet"

INDUSTRIES = ["SaaS", "Fintech", "Healthtech", "Legal", "E-commerce", "Manufacturing",
              "Media", "Logistics", "Education", "Insurance", "Retail", "Real Estate"]
SEC_TOOLS = ["CrowdStrike", "SentinelOne", "Okta", "Azure AD", "Splunk", "Datadog",
             "Palo Alto Networks", "Zscaler"]
GENERIC_TOOLS = ["AWS", "GCP", "GitHub", "Jira", "Slack", "Salesforce", "HubSpot",
                 "Kubernetes", "PostgreSQL", "Snowflake", "Google Workspace", "Microsoft 365"]
DEV_TITLES = ["Senior Software Engineer", "Backend Developer", "DevOps Engineer",
              "Frontend Developer", "Data Engineer", "IT Administrator", "SRE"]
SEC_TITLES = ["Security Engineer", "CISO", "SOC Analyst", "AppSec Engineer"]


def _arr(xs: list[str]) -> str:
    return "[" + ", ".join(_q(x) for x in xs) + "]"


def generate_mock() -> int:
    con = config.connect()
    register_views(con)
    _lookup_tables(con)
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    pick = lambda arr, salt, p: (  # noqa: E731 - include each item with prob p%
        f"list_filter({_arr(arr)}, x -> hash(domain || {_q(salt)} || x) % 100 < {p})")
    sql = f"""
    COPY (
      WITH d AS (SELECT DISTINCT domain FROM ({candidate_exposures_sql()})),
      h AS (SELECT domain, hash(domain) AS h FROM d)
      SELECT
        domain                                                    AS company_id,
        upper(left(split_part(domain, '.', 1), 1)) || substr(split_part(domain, '.', 1), 2)                       AS name,
        -- keep obvious domain evidence (.gov, .edu, 'bank'...) consistent
        COALESCE({_industry_from_domain_sql('domain')},
                 {_arr(INDUSTRIES)}[1 + (h % {len(INDUSTRIES)})::INT]) AS industry,
        -- log-uniform headcount 5 .. 20,000
        CAST(5 * exp(((h >> 8) % 1000) / 1000.0 * ln(4000)) AS INTEGER) AS employee_count,
        list_concat({pick(SEC_TOOLS, 'sec', 30)}, {pick(GENERIC_TOOLS, 'gen', 45)}) AS tech_stack,
        list_concat({pick(DEV_TITLES, 'dev', 25)},
                    CASE WHEN (h >> 16) % 100 < 20 THEN {pick(SEC_TITLES, 'sec_t', 50)}
                         ELSE []::VARCHAR[] END)                  AS hiring_signals,
        (h >> 24) % 10 = 0                                        AS is_regulated,
        CASE WHEN (h >> 32) % 100 < 45 THEN NULL
             ELSE CAST((h >> 40) % 720 AS INTEGER) END            AS days_since_funding,
        true                                                      AS is_synthetic
      FROM h
    ) TO {_q(MOCK_PATH.as_posix())} (FORMAT parquet, COMPRESSION zstd)
    """
    n = con.execute(sql).fetchone()[0]
    con.close()
    print(f"[firmographics] wrote {n:,} SYNTHETIC company profiles -> {MOCK_PATH}")
    return n


def check() -> None:
    con = config.connect()
    register_views(con)
    _lookup_tables(con)
    n_c = con.execute("SELECT count(*) FROM companies").fetchone()[0]
    n_m = con.execute(f"""SELECT count(DISTINCT c.company_id) FROM companies c
                          JOIN ({candidate_exposures_sql()}) e ON e.domain = c.company_id""").fetchone()[0]
    print(f"[firmographics] {n_c:,} companies in feed; {n_m:,} matched to scan footprint "
          f"({(n_m / n_c * 100) if n_c else 0:.1f}%)")
    con.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mock", action="store_true")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    if not (a.mock or a.check):
        ap.print_help()
        sys.exit(1)
    if a.mock:
        generate_mock()
    if a.check:
        check()
