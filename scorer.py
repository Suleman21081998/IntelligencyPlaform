"""Scoring engine: company_signals -> 0-100 Cybersecurity Readiness Score.

The score is deterministic and fully explainable. Each component's points
are computed in SQL from the boolean signals and raw evidence, and a
``buying_reasons`` array spells out exactly why every point was awarded.

Components (weights in config.WEIGHTS, sum = 100)
-------------------------------------------------
attack_surface  critical/high CVEs, risky exposed services, EOL software, weak TLS (capped)
tooling_gap     >50 staff (or 3+ eng openings) missing EDR / IAM / SIEM / edge categories,
                pro-rated by number of missing categories
compliance      high-risk industry (full) or other regulated entity (60%)
hiring          eng/IT openings with no CISO / security openings
funding         funding event within FUNDING_WINDOW_DAYS

Run:  python scorer.py [--rebuild-signals] [--top 25]
"""

from __future__ import annotations

import argparse
import sys
import time

import duckdb

import config
import signals

W = config.WEIGHTS
S = config.ATTACK_SUBPOINTS
N_CATS = len(config.SECURITY_TOOL_CATEGORIES)


SCORE_SQL = f"""
CREATE OR REPLACE TABLE company_scores AS
WITH p AS (
    SELECT *,
        -- ---------------- component points ----------------
        LEAST({W['attack_surface']},
              CASE WHEN sig_critical_cve THEN {S['critical_cve']}
                   WHEN sig_high_cve     THEN {S['high_cve']} ELSE 0 END
            + CASE WHEN sig_risky_service THEN {S['risky_service']} ELSE 0 END
            + CASE WHEN sig_eol_software  THEN {S['eol_software']} ELSE 0 END
            + CASE WHEN sig_weak_tls      THEN {S['weak_tls']} ELSE 0 END)      AS pts_attack_surface,
        CASE WHEN sig_tooling_gap
             THEN round({W['tooling_gap']} * len(missing_security_categories) / {N_CATS})::INT
             ELSE 0 END                                                        AS pts_tooling_gap,
        CASE WHEN sig_high_risk_industry THEN {W['compliance']}
             WHEN is_regulated THEN round({W['compliance']} * 0.6)::INT
             ELSE 0 END                                                        AS pts_compliance,
        CASE WHEN sig_hiring_mismatch THEN {W['hiring']} ELSE 0 END            AS pts_hiring,
        CASE WHEN sig_recent_funding  THEN {W['funding']} ELSE 0 END           AS pts_funding
    FROM company_signals
),
s AS (
    SELECT *,
        pts_attack_surface + pts_tooling_gap + pts_compliance + pts_hiring + pts_funding AS score
    FROM p
)
SELECT
    company_id, name, industry, industry_source, employee_count, score,
    CASE WHEN score > {config.HIGH_PRIORITY_SCORE} THEN 'P1'
         WHEN score >= 50 THEN 'P2'
         WHEN score >= 25 THEN 'P3' ELSE 'P4' END                              AS priority,

    -- ---------------- human-readable evidence ----------------
    list_filter([
        CASE WHEN sig_critical_cve THEN
            printf('Critical vulnerability exposure: %s (max CVSS %.1f) on %d internet-facing service(s)',
                   array_to_string(top_cves[1:3], ', '), max_cvss, n_critical_services) END,
        CASE WHEN sig_high_cve THEN
            printf('High-severity CVEs (max CVSS %.1f) on %d service(s): %s',
                   max_cvss, n_high_services, array_to_string(top_cves[1:3], ', ')) END,
        CASE WHEN sig_risky_service THEN
            'Admin/data services exposed to the internet: ' || array_to_string(risky_services, ', ') END,
        CASE WHEN sig_eol_software THEN
            printf('End-of-life software running on %d service(s)', n_eol) END,
        CASE WHEN sig_weak_tls THEN
            printf('TLS hygiene issues: %d legacy-protocol, %d expired-cert, %d self-signed endpoint(s)',
                   n_weak_tls, n_expired_cert, n_self_signed) END,
        CASE WHEN sig_tooling_gap THEN
            printf('Missing key %s tools with %s employees',
                   array_to_string(missing_security_categories, '/'),
                   COALESCE(employee_count::VARCHAR, 'unknown')) END,
        CASE WHEN sig_high_risk_industry THEN
            'High-risk industry: ' || industry ||
            COALESCE(' (' || compliance_frameworks || ')', '') END,
        CASE WHEN NOT sig_high_risk_industry AND is_regulated THEN
            'Regulated entity with formal compliance obligations' END,
        CASE WHEN sig_hiring_mismatch THEN
            printf('High dev hiring without CISO: %d eng/IT opening(s), 0 security openings',
                   len(dev_roles)) END,
        CASE WHEN sig_recent_funding THEN
            printf('Recent funding event %d days ago - new budget, investor security diligence',
                   days_since_funding) END
    ], x -> x IS NOT NULL)                                                     AS buying_reasons,

    -- short labels for table badges / filters
    list_filter([
        CASE WHEN sig_critical_cve THEN 'Critical CVE' END,
        CASE WHEN sig_high_cve THEN 'High CVE' END,
        CASE WHEN sig_risky_service THEN 'Exposed ' || risky_services[1] END,
        CASE WHEN sig_eol_software THEN 'EOL software' END,
        CASE WHEN sig_weak_tls THEN 'Weak TLS' END,
        CASE WHEN sig_tooling_gap THEN array_to_string(missing_security_categories, '/') || ' gap' END,
        CASE WHEN sig_high_risk_industry THEN 'Regulated: ' || industry
             WHEN is_regulated THEN 'Regulated' END,
        CASE WHEN sig_hiring_mismatch THEN 'Dev hiring, no security' END,
        CASE WHEN sig_recent_funding THEN 'Funded ' || days_since_funding || 'd ago' END
    ], x -> x IS NOT NULL)                                                     AS evidence_badges,

    pts_attack_surface, pts_tooling_gap, pts_compliance, pts_hiring, pts_funding,
    * EXCLUDE (company_id, name, industry, industry_source, employee_count, score,
               pts_attack_surface, pts_tooling_gap, pts_compliance, pts_hiring, pts_funding)
FROM s
"""


def run(rebuild_signals: bool = False, top: int = 20) -> None:
    con = config.connect()
    try:
        has_signals = con.execute(
            "SELECT count(*) FROM duckdb_tables() WHERE table_name = 'company_signals'").fetchone()[0]
        if rebuild_signals or not has_signals:
            signals.run(con)
        t0 = time.time()
        con.execute(SCORE_SQL)
        bad = con.execute("SELECT count(*) FROM company_scores WHERE score NOT BETWEEN 0 AND 100").fetchone()[0]
        if bad:
            raise AssertionError(f"{bad} scores outside 0-100 - check WEIGHTS/ATTACK_SUBPOINTS")
        # Sorted export -> the dashboard's top-N reads touch only the first row groups.
        con.execute(f"COPY (SELECT * FROM company_scores ORDER BY score DESC, n_services DESC NULLS LAST) "
                    f"TO '{config.SCORES_PARQUET.as_posix()}' (FORMAT parquet, COMPRESSION zstd)")
        n, p1, avg = con.execute(f"""SELECT count(*), count(*) FILTER (score > {config.HIGH_PRIORITY_SCORE}),
                                     round(avg(score), 1) FROM company_scores""").fetchone()
        print(f"[scorer] scored {n:,} accounts in {time.time()-t0:.1f}s | "
              f"P1 (>{config.HIGH_PRIORITY_SCORE}): {p1:,} | avg score {avg}")
        print(con.execute(f"""SELECT company_id, industry, employee_count AS emp, score,
                                     pts_attack_surface AS att, pts_tooling_gap AS gap, pts_compliance AS comp,
                                     pts_hiring AS hire, pts_funding AS fund
                              FROM company_scores ORDER BY score DESC, n_services DESC NULLS LAST
                              LIMIT {top}""").fetchdf().to_string(index=False)
              if top else "")
    finally:
        con.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rebuild-signals", action="store_true", help="recompute company_signals first")
    ap.add_argument("--top", type=int, default=20, help="print the top N accounts (0 = none)")
    a = ap.parse_args()
    try:
        run(a.rebuild_signals, a.top)
    except (FileNotFoundError, duckdb.Error, AssertionError) as e:
        print(f"[scorer] ERROR: {e}", file=sys.stderr)
        raise SystemExit(1)
