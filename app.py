"""Streamlit dashboard for the Cybersecurity Sales Intelligence platform.

    streamlit run app.py

Reads the scored Parquet produced by ``scorer.py`` through an in-memory
DuckDB connection (no lock on the warehouse DB, so the pipeline can rebuild
while the app is open). Every filter is pushed down to DuckDB; only the
visible page of rows ever reaches pandas.
"""

from __future__ import annotations

import glob
from typing import Any

import duckdb
import pandas as pd
import streamlit as st

import config

st.set_page_config(page_title="Cyber Readiness Prospecting", layout="wide")

SIGNALS: dict[str, str] = {
    "Critical CVE (CVSS ≥ 9)": "sig_critical_cve",
    "High CVE (CVSS 7–9)": "sig_high_cve",
    "Exposed admin/data service": "sig_risky_service",
    "End-of-life software": "sig_eol_software",
    "Weak TLS / bad certs": "sig_weak_tls",
    "Security tooling gap": "sig_tooling_gap",
    "High-risk industry": "sig_high_risk_industry",
    "Dev hiring without security": "sig_hiring_mismatch",
    "Recent funding (≤180d)": "sig_recent_funding",
}
EMP_BANDS: list[int] = [0, 10, 50, 200, 1000, 5000, 1_000_000]
EMP_LABELS: list[str] = ["0", "10", "50", "200", "1k", "5k", "max"]
COMPONENTS: list[tuple[str, str]] = [
    ("Attack surface", "pts_attack_surface"), ("Tooling gap", "pts_tooling_gap"),
    ("Compliance", "pts_compliance"), ("Hiring", "pts_hiring"), ("Funding", "pts_funding"),
]
COMPONENT_MAX = {
    "pts_attack_surface": config.WEIGHTS["attack_surface"], "pts_tooling_gap": config.WEIGHTS["tooling_gap"],
    "pts_compliance": config.WEIGHTS["compliance"], "pts_hiring": config.WEIGHTS["hiring"],
    "pts_funding": config.WEIGHTS["funding"],
}


# ---------------------------------------------------------------------------
# data access
# ---------------------------------------------------------------------------
@st.cache_resource
def get_con() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect()
    con.execute(f"PRAGMA memory_limit='{config.MEMORY_LIMIT}'")
    con.execute(f"CREATE VIEW scores AS SELECT * FROM read_parquet('{config.SCORES_PARQUET.as_posix()}')")
    if config.EXPOSURES_PARQUET.exists():
        con.execute(f"CREATE VIEW exposures AS SELECT * FROM "
                    f"read_parquet('{config.EXPOSURES_PARQUET.as_posix()}')")
    return con


@st.cache_data(ttl=600, show_spinner=False)
def q(sql: str, params: tuple[Any, ...] = ()) -> pd.DataFrame:
    return get_con().cursor().execute(sql, list(params)).fetchdf()


def firmographics_are_synthetic() -> bool:
    files = glob.glob(config.FIRMO_GLOB)
    return bool(files) and all("mock" in f for f in files)


# ---------------------------------------------------------------------------
# cold email
# ---------------------------------------------------------------------------
PROMPT_TEMPLATE = """You are a senior security account executive. Write a short, respectful cold email
(<=120 words) to the security/IT leader at {name} ({domain}), a {industry} company with
about {employees} employees. Ground it ONLY in these observed signals:
{reasons}
Do not list IP addresses or CVE IDs; describe risk categories. Offer a free 20-minute
external attack-surface review. Close with a soft call to action."""


def draft_email(r: pd.Series) -> tuple[str, str]:
    hooks: list[str] = []
    if r.sig_critical_cve or r.sig_high_cve:
        hooks.append(f"public-facing services running software with known "
                     f"{'critical' if r.sig_critical_cve else 'high-severity'} vulnerabilities")
    if r.sig_risky_service and len(r.risky_services):
        hooks.append(f"{', '.join(list(r.risky_services)[:3])} reachable from the open internet")
    if r.sig_eol_software:
        hooks.append("end-of-life server software that no longer receives patches")
    if r.sig_weak_tls:
        hooks.append("TLS configuration gaps (legacy protocols or certificate issues)")
    gap = ", ".join(r.missing_security_categories) if r.sig_tooling_gap else ""
    why_now = []
    if r.sig_recent_funding:
        why_now.append(f"your funding round {int(r.days_since_funding)} days ago usually brings investor security diligence")
    if r.sig_hiring_mismatch:
        why_now.append(f"you're hiring {len(r.dev_roles)} engineering/IT roles but no security roles")
    if r.compliance_frameworks:
        why_now.append(f"{r.industry} teams are typically held to {r.compliance_frameworks}")

    lines = [f"Subject: {r['name']} — a quick external security observation", "",
             "Hi there,", ""]
    if hooks:
        lines.append(f"While reviewing public internet-scan data we noticed {r['name']} has "
                     + "; ".join(hooks) + ".")
    if why_now:
        lines.append("It caught our attention because " + ", and ".join(why_now) + ".")
    if gap:
        lines.append(f"Teams in a similar position often close the {gap} gap first — it's where we help most.")
    lines += ["",
              "Happy to walk your team through what we saw in a free 20-minute external "
              "attack-surface review — no slides, just findings and fixes.",
              "", "Would next Tuesday or Wednesday work?", "", "Best,", "<your name>"]
    prompt = PROMPT_TEMPLATE.format(
        name=r["name"], domain=r.company_id, industry=r.industry,
        employees=r.employee_count if pd.notna(r.employee_count) else "an unknown number of",
        reasons="\n".join(f"- {x}" for x in r.buying_reasons))
    return "\n".join(lines), prompt


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------
def main() -> None:
    st.title("Cybersecurity Readiness — Prospect Queue")
    if not config.SCORES_PARQUET.exists():
        st.error("No scores yet. Run the pipeline first:")
        st.code("python ingest.py\npython firmographics.py --mock   # or drop a real feed in data/\n"
                "python scorer.py --rebuild-signals", language="bash")
        st.stop()
    if firmographics_are_synthetic():
        st.warning("Firmographic signals (industry, headcount, hiring, funding, vendor tech stack) are "
                   "SYNTHETIC placeholders. Attack-surface signals come from the real scan data. "
                   "Drop a vendor feed matching `data/firmographics*.parquet` and re-run the scorer.",
                   icon="⚠️")

    # ---------------- sidebar filters ----------------
    sb = st.sidebar
    sb.header("Filters")
    industries = q("SELECT industry, count(*) n FROM scores GROUP BY 1 ORDER BY n DESC")["industry"].tolist()
    sel_ind = sb.multiselect("Industry", industries)
    min_score = sb.slider("Minimum score", 0, 100, 50, step=5)
    emp_lo, emp_hi = sb.select_slider("Employee range", options=EMP_LABELS, value=("0", "max"))
    include_unknown_emp = sb.checkbox("Include unknown headcount", value=True)
    sel_sig = sb.multiselect("Must have signals", list(SIGNALS))
    sel_prio = sb.multiselect("Priority", ["P1", "P2", "P3", "P4"])
    search = sb.text_input("Search domain / name")
    page_size = sb.select_slider("Rows shown", options=[50, 100, 250, 500, 1000], value=250)

    where, params = ["score >= ?"], [min_score]
    if sel_ind:
        where.append(f"industry IN ({', '.join('?' * len(sel_ind))})")
        params += sel_ind
    lo, hi = EMP_BANDS[EMP_LABELS.index(emp_lo)], EMP_BANDS[EMP_LABELS.index(emp_hi)]
    emp_clause = "(employee_count BETWEEN ? AND ?)"
    where.append(f"({emp_clause} OR employee_count IS NULL)" if include_unknown_emp else emp_clause)
    params += [lo, hi]
    where += [SIGNALS[s] for s in sel_sig]
    if sel_prio:
        where.append(f"priority IN ({', '.join('?' * len(sel_prio))})")
        params += sel_prio
    if search:
        where.append("(company_id ILIKE ? OR name ILIKE ?)")
        params += [f"%{search}%"] * 2
    wsql = " AND ".join(where)

    # ---------------- metrics ----------------
    total, hp_all, avg_all = q(f"""SELECT count(*), count(*) FILTER (score > {config.HIGH_PRIORITY_SCORE}),
                                   avg(score) FROM scores""").iloc[0]
    f_n, f_hp, f_avg = q(f"""SELECT count(*), count(*) FILTER (score > {config.HIGH_PRIORITY_SCORE}),
                            avg(score) FROM scores WHERE {wsql}""", tuple(params)).iloc[0]
    m = st.columns(4)
    m[0].metric("Total accounts processed", f"{int(total):,}")
    m[1].metric(f"High-priority leads (>{config.HIGH_PRIORITY_SCORE})", f"{int(hp_all):,}",
                f"{int(f_hp):,} in current filter", delta_color="off")
    m[2].metric("Average security score", f"{avg_all:.1f}",
                f"{(f_avg or 0):.1f} in filter", delta_color="off")
    m[3].metric("Matching current filters", f"{int(f_n):,}")

    # ---------------- table + drawer ----------------
    left, right = st.columns([3, 2], gap="large")
    df = q(f"""SELECT company_id, name, industry, employee_count, score, priority, evidence_badges
               FROM scores WHERE {wsql}
               ORDER BY score DESC, n_services DESC NULLS LAST LIMIT {int(page_size)}""", tuple(params))
    with left:
        st.subheader(f"Prospects ({len(df):,} of {int(f_n):,})")
        event = st.dataframe(
            df, hide_index=True, width="stretch", height=620,
            on_select="rerun", selection_mode="single-row",
            column_config={
                "company_id": st.column_config.TextColumn("Domain"),
                "name": st.column_config.TextColumn("Company"),
                "industry": "Industry",
                "employee_count": st.column_config.NumberColumn("Employees", format="%d"),
                "score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100, format="%d"),
                "priority": "Tier",
                "evidence_badges": st.column_config.ListColumn("Evidence", width="large"),
            },
        )
        st.download_button("Export filtered list (CSV)", df.to_csv(index=False).encode(),
                           "prospects.csv", "text/csv")

    with right:
        rows = event.selection.rows if event and event.selection else []
        if not rows:
            st.info("Select a row to open the account deep-dive.")
            return
        render_drawer(df.iloc[rows[0]]["company_id"])


def render_drawer(company_id: str) -> None:
    r = q("SELECT * FROM scores WHERE company_id = ?", (company_id,)).iloc[0]
    st.subheader(f"{r['name']}")
    st.caption(f"{r.company_id} · {r.industry} ({r.industry_source}) · "
               f"{'%d employees' % r.employee_count if pd.notna(r.employee_count) else 'headcount unknown'}"
               f" · {r.country or '—'}")
    c1, c2, c3 = st.columns(3)
    c1.metric("Readiness score", int(r.score))
    c2.metric("Tier", r.priority)
    c3.metric("Exposed services", int(r.n_services) if pd.notna(r.n_services) else 0)

    breakdown = pd.DataFrame({"component": [c for c, _ in COMPONENTS],
                              "points": [int(r[col]) for _, col in COMPONENTS],
                              "max": [COMPONENT_MAX[col] for _, col in COMPONENTS]}).set_index("component")
    st.bar_chart(breakdown, horizontal=True, stack=False, height=200)

    st.markdown("**Why this account, why now**")
    for reason in r.buying_reasons:
        st.markdown(f"- {reason}")

    st.markdown("**Detected tech stack**")
    stack = list(r.tech_stack)[:40]
    st.markdown(" ".join(f":blue-badge[{t}]" for t in stack) if stack else "_none detected_")
    if len(r.missing_security_categories):
        st.markdown("**Missing security categories** " +
                    " ".join(f":red-badge[{m}]" for m in r.missing_security_categories))

    st.markdown("**Hiring signals**")
    if len(r.hiring_signals):
        st.markdown(" ".join(
            f":orange-badge[{h}]" if h in list(r.sec_roles) else f":gray-badge[{h}]"
            for h in r.hiring_signals))
    else:
        st.caption("No open roles in feed.")

    with st.expander("Observed exposures (scan data)"):
        if config.EXPOSURES_PARQUET.exists():
            ex = q("""SELECT ip, port, module, product, version, max_cvss, cves[1:3] AS cves, tags,
                             weak_tls, cert_expired, seen_at
                      FROM exposures WHERE domain = ? AND NOT is_ptr_only
                      ORDER BY max_cvss DESC NULLS LAST LIMIT 100""", (company_id,))
            st.dataframe(ex, hide_index=True, width="stretch")
        else:
            st.caption("exposures.parquet not found.")

    if st.button("Draft cold email", type="primary", width="stretch"):
        st.session_state["draft_for"] = company_id
    if st.session_state.get("draft_for") == company_id:
        email, prompt = draft_email(r)
        st.text_area("Email draft", email, height=300)
        st.download_button("Download .txt", email.encode(), f"{company_id}_email.txt")
        with st.expander("LLM prompt (paste into Claude for a polished version)"):
            st.code(prompt, language="markdown")


if __name__ == "__main__":
    main()
