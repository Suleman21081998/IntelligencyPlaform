"""Feature extraction: exposures + firmographics -> one signal row per company.

All logic is set-based DuckDB SQL (no Python row loops), so it scales to
millions of companies and spills to disk under the configured memory limit.

Tables produced
---------------
attack_surface   per registered domain: IPs, services, CVEs, risky ports, TLS hygiene, edge tech
company_signals  attack_surface FULL OUTER JOIN companies + derived boolean signals

Run:  python signals.py
"""

from __future__ import annotations

import sys
import time

import duckdb

import config
from ingest import register_views


def _q(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _regex(words: list[str]) -> str:
    """Case-insensitive alternation for regexp_matches on lower()'d text."""
    return _q("|".join(w.lower().replace(".", r"\.") for w in words))


def _varchar_list(items: list[str]) -> str:
    return "[" + ", ".join(_q(i) for i in items) + "]::VARCHAR[]"


def _lookup_tables(con: duckdb.DuckDBPyConnection) -> None:
    """Small dimension tables materialised from config dictionaries."""
    con.execute("CREATE OR REPLACE TEMP TABLE infra_domains(domain VARCHAR)")
    con.executemany("INSERT INTO infra_domains VALUES (?)", [[d] for d in config.INFRA_DOMAINS])
    con.execute("CREATE OR REPLACE TEMP TABLE risky_ports(port INTEGER, service VARCHAR)")
    con.executemany("INSERT INTO risky_ports VALUES (?, ?)", [[p, s] for p, s in config.RISKY_PORTS.items()])


def candidate_exposures_sql() -> str:
    """Exposures attributable to a prospect (not cloud/CDN/ISP reverse DNS)."""
    return """
        SELECT e.* FROM exposures e
        WHERE NOT e.is_ptr_only
          AND e.domain NOT IN (SELECT domain FROM infra_domains)
          -- registered domains that are themselves reverse-DNS artefacts
          AND NOT regexp_matches(e.domain, '^(ip|host|static|dyn)[-.]|\\d{1,3}-\\d{1,3}-\\d{1,3}')
    """


def _industry_from_domain_sql(col: str) -> str:
    whens = " ".join(
        f"WHEN regexp_matches({col}, {_q(k)}) THEN {_q(v)}" for k, v in config.DOMAIN_INDUSTRY_HINTS.items()
    )
    return (f"CASE WHEN regexp_matches({col}, '\\.gov(\\.[a-z]{{2}})?$|\\.mil$') THEN 'Government' "
            f"WHEN regexp_matches({col}, '\\.edu(\\.[a-z]{{2}})?$|\\.ac\\.[a-z]{{2}}$|\\.k12\\.') THEN 'Education' "
            f"{whens} ELSE NULL END")


def build_attack_surface(con: duckdb.DuckDBPyConnection) -> int:
    con.execute(f"""
    CREATE OR REPLACE TABLE attack_surface AS
    WITH ce AS ({candidate_exposures_sql()}),
    rows AS (
        SELECT ce.*,
               COALESCE(rp.service,
                   CASE ce.module WHEN 'rdp' THEN 'RDP' WHEN 'telnet' THEN 'Telnet' WHEN 'vnc' THEN 'VNC'
                                  WHEN 'mongodb' THEN 'MongoDB' WHEN 'redis' THEN 'Redis'
                                  WHEN 'elastic' THEN 'Elasticsearch' WHEN 'smb' THEN 'SMB' END) AS risky_service
        FROM ce LEFT JOIN risky_ports rp USING (port)
    ),
    agg AS (
        SELECT
            domain,
            count(DISTINCT ip)                                            AS n_ips,
            count(*)                                                      AS n_services,
            arg_max(org, seen_at)                                         AS org,      -- mode() is ~1GB heavier
            arg_max(country, seen_at)                                     AS country,
            list(DISTINCT risky_service) FILTER (risky_service IS NOT NULL) AS risky_services,
            max(max_cvss)                                                 AS max_cvss,
            count(*) FILTER (max_cvss >= {config.CRITICAL_CVSS})          AS n_critical_services,
            count(*) FILTER (max_cvss >= {config.HIGH_CVSS})              AS n_high_services,
            arg_max(cves, max_cvss)[1:5]                                  AS top_cves,
            count(*) FILTER (list_contains(tags, 'eol-product'))          AS n_eol,
            count(*) FILTER (weak_tls)                                    AS n_weak_tls,
            count(*) FILTER (cert_expired)                                AS n_expired_cert,
            count(*) FILTER (list_contains(tags, 'self-signed'))          AS n_self_signed,
            max(seen_at)                                                  AS last_seen
        FROM rows
        GROUP BY domain
        HAVING count(DISTINCT ip) <= {config.MAX_IPS_PER_COMPANY}
           AND NOT (count(DISTINCT ip) >= {config.INFRA_REGEX_MIN_IPS}
                    AND regexp_matches(domain, {_q(config.INFRA_DOMAIN_REGEX)}))
    ),
    tech AS (
        SELECT domain, list(DISTINCT t ORDER BY t)[1:60] AS scan_tech
        FROM (SELECT domain, unnest(tech) AS t FROM ce)
        GROUP BY domain
    )
    SELECT agg.*, COALESCE(tech.scan_tech, []::VARCHAR[]) AS scan_tech
    FROM agg LEFT JOIN tech USING (domain)
    """)
    return con.execute("SELECT count(*) FROM attack_surface").fetchone()[0]


def build_company_signals(con: duckdb.DuckDBPyConnection) -> int:
    cat_cols = []
    for cat, words in config.SECURITY_TOOL_CATEGORIES.items():
        cat_cols.append(f"CASE WHEN NOT regexp_matches(stack_lc, {_regex(words)}) THEN {_q(cat)} END")
    missing_expr = f"list_filter([{', '.join(cat_cols)}], x -> x IS NOT NULL)"

    comp_whens = " ".join(f"WHEN {_q(k)} THEN {_q(v)}" for k, v in config.COMPLIANCE_BY_INDUSTRY.items())
    high_risk = _varchar_list(config.HIGH_RISK_INDUSTRIES)
    dev_re, sec_re = _regex(config.DEV_ROLE_KEYWORDS), _regex(config.SEC_ROLE_KEYWORDS)

    con.execute(f"""
    CREATE OR REPLACE TABLE company_signals AS
    WITH j AS (
        SELECT
            COALESCE(c.company_id, a.domain)                               AS company_id,
            COALESCE(c.name, upper(left(split_part(COALESCE(c.company_id, a.domain), '.', 1), 1)) || substr(split_part(COALESCE(c.company_id, a.domain), '.', 1), 2)) AS name,
            c.company_id IS NOT NULL                                       AS has_firmographics,
            a.domain IS NOT NULL                                           AS has_scan_footprint,
            NULLIF(c.industry, 'Unknown')                                  AS vendor_industry,
            {_industry_from_domain_sql("COALESCE(c.company_id, a.domain)")} AS inferred_industry,
            c.employee_count,
            COALESCE(c.hiring_signals, []::VARCHAR[])                      AS hiring_signals,
            COALESCE(c.is_regulated, false)                                AS vendor_regulated,
            c.days_since_funding,
            list_distinct(list_concat(COALESCE(c.tech_stack, []::VARCHAR[]),
                                      COALESCE(a.scan_tech, []::VARCHAR[]))) AS tech_stack,
            a.* EXCLUDE (domain, scan_tech)
        FROM attack_surface a
        FULL OUTER JOIN companies c ON c.company_id = a.domain
    ),
    d AS (
        SELECT *,
            COALESCE(vendor_industry, inferred_industry, 'Unknown')        AS industry,
            CASE WHEN vendor_industry IS NOT NULL THEN 'firmographics'
                 WHEN inferred_industry IS NOT NULL THEN 'domain-inferred'
                 ELSE 'unknown' END                                        AS industry_source,
            lower(array_to_string(tech_stack, ' | '))                      AS stack_lc,
            list_filter(hiring_signals, h -> regexp_matches(lower(h), {dev_re})) AS dev_roles,
            list_filter(hiring_signals, h -> regexp_matches(lower(h), {sec_re})) AS sec_roles
        FROM j
    )
    SELECT
        * EXCLUDE (stack_lc, vendor_regulated, vendor_industry, inferred_industry),
        {missing_expr}                                                     AS missing_security_categories,
        (vendor_regulated OR industry IN ('Banking','Fintech','Payments','Insurance',
                                          'Healthcare','Healthtech','Government')) AS is_regulated,
        CASE industry {comp_whens} ELSE NULL END                           AS compliance_frameworks,

        -- ---- boolean signals (drive filters + scoring) ----
        COALESCE(max_cvss >= {config.CRITICAL_CVSS}, false)                AS sig_critical_cve,
        COALESCE(max_cvss >= {config.HIGH_CVSS} AND max_cvss < {config.CRITICAL_CVSS}, false) AS sig_high_cve,
        COALESCE(len(risky_services) > 0, false)                           AS sig_risky_service,
        COALESCE(n_eol > 0, false)                                         AS sig_eol_software,
        COALESCE(n_weak_tls + n_expired_cert + n_self_signed > 0, false)   AS sig_weak_tls,
        (COALESCE(employee_count, 0) > {config.MIN_EMPLOYEES_FOR_GAP}
            OR len(dev_roles) >= 3)
          AND len({missing_expr}) > 0                                      AS sig_tooling_gap,
        list_contains({high_risk}, industry)                               AS sig_high_risk_industry,
        len(dev_roles) >= {config.MIN_DEV_ROLES_FOR_MISMATCH} AND len(sec_roles) = 0 AS sig_hiring_mismatch,
        COALESCE(days_since_funding <= {config.FUNDING_WINDOW_DAYS}, false) AS sig_recent_funding
    FROM d
    """)
    return con.execute("SELECT count(*) FROM company_signals").fetchone()[0]


def run(con: duckdb.DuckDBPyConnection | None = None) -> int:
    own = con is None
    con = con or config.connect()
    if not config.EXPOSURES_PARQUET.exists():
        raise FileNotFoundError("exposures.parquet missing - run `python ingest.py` first")
    register_views(con)
    _lookup_tables(con)
    t0 = time.time()
    n_as = build_attack_surface(con)
    print(f"[signals] attack_surface: {n_as:,} companies ({time.time()-t0:.1f}s)")
    t1 = time.time()
    n = build_company_signals(con)
    print(f"[signals] company_signals: {n:,} rows ({time.time()-t1:.1f}s)")
    if own:
        con.close()
    return n


if __name__ == "__main__":
    try:
        run()
    except (FileNotFoundError, duckdb.Error) as e:
        print(f"[signals] ERROR: {e}", file=sys.stderr)
        raise SystemExit(1)
