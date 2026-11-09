"""Streamlit dashboard for the Cybersecurity Sales Intelligence platform.

    streamlit run app.py

Three data sources, picked in the sidebar:

* Full dataset   - warehouse/ produced by ingest.py + scorer.py on this machine
* Demo snapshot  - demo_data/ (built by make_demo.py, committed to git; used when hosted)
* Upload a file  - visitor uploads a scan file (+ optional firmographics); pipeline.py
                   runs the whole ingest -> signals -> score flow in a private work dir

Every source ends as two Parquet files (scores + exposures) read through an
in-memory DuckDB connection; filters are pushed down to DuckDB and only the
visible page of rows reaches pandas.
"""

from __future__ import annotations

import glob
import json
import shutil
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
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
UPLOAD_TTL_HOURS = 24


@dataclass(frozen=True)
class Source:
    label: str
    scores: Path
    exposures: Path | None
    synthetic: bool
    note: str = ""


# ---------------------------------------------------------------------------
# data sources
# ---------------------------------------------------------------------------
def _firmo_is_mock() -> bool:
    files = glob.glob(config.FIRMO_GLOB)
    return bool(files) and all("mock" in Path(f).name for f in files)


def available_sources() -> dict[str, Source]:
    out: dict[str, Source] = {}
    if config.SCORES_PARQUET.exists():
        out["Full dataset"] = Source("Full dataset", config.SCORES_PARQUET,
                                     config.EXPOSURES_PARQUET if config.EXPOSURES_PARQUET.exists() else None,
                                     _firmo_is_mock())
    if config.DEMO_SCORES.exists():
        try:
            meta = json.loads((config.DEMO_DIR / "meta.json").read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            meta = {}
        out["Demo snapshot"] = Source(
            "Demo snapshot", config.DEMO_SCORES,
            config.DEMO_EXPOSURES if config.DEMO_EXPOSURES.exists() else None,
            meta.get("synthetic_firmographics", True),
            f"Snapshot of a full 20 GB run. Raw exposure rows are included for accounts scoring "
            f"≥ {meta.get('exposures_min_score', 50)}.")
    return out


def _cleanup_old_uploads() -> None:
    """Best-effort removal of upload work dirs older than UPLOAD_TTL_HOURS."""
    if not config.UPLOAD_ROOT.exists():
        return
    cutoff = time.time() - UPLOAD_TTL_HOURS * 3600
    for d in config.UPLOAD_ROOT.iterdir():
        try:
            if d.is_dir() and d.stat().st_mtime < cutoff:
                shutil.rmtree(d, ignore_errors=True)
        except OSError:
            pass


def _save_upload(uploaded: Any, dest: Path) -> Path:
    path = dest / Path(uploaded.name).name
    with path.open("wb") as fh:
        shutil.copyfileobj(uploaded, fh, length=16 * 1024 * 1024)
    return path


def upload_panel() -> Source | None:
    """Upload UI. Returns a Source once an upload has been analysed this session."""
    st.subheader("Analyse your own scan file")
    st.markdown(
        "Upload **newline-delimited JSON** in the internet-scan banner format "
        "(one object per line with `ip_str`, `port`, `domains`, `vulns`, `http`, `ssl`, …). "
        "Plain, `.gz` or `.zst` files are accepted. "
        f"Max upload: **{st.get_option('server.maxUploadSize')} MB**. For multi-GB dumps, run the "
        "CLI pipeline instead (`python ingest.py`).")
    sample = config.DEMO_DIR / "sample_scan_5k.json.zst"
    if sample.exists():
        st.download_button("Download a 5k-line sample to try", sample.read_bytes(),
                           sample.name, "application/zstd")
    c1, c2 = st.columns(2)
    scan = c1.file_uploader("Scan file (required)", type=None, key="scan_up")
    firmo = c2.file_uploader("Company profiles (optional: CSV / JSON / Parquet, keyed by domain)",
                             type=["csv", "json", "jsonl", "parquet"], key="firmo_up")
    c2.caption("Columns: company_id (domain), name, industry, employee_count, tech_stack, "
               "hiring_signals, is_regulated, days_since_funding. In CSV, separate list items with ';'. "
               "Without a file, synthetic profiles are generated.")

    if st.button("Run analysis", type="primary", disabled=scan is None):
        _cleanup_old_uploads()
        workdir = config.UPLOAD_ROOT / uuid.uuid4().hex[:12]
        workdir.mkdir(parents=True, exist_ok=True)
        from pipeline import run_pipeline  # local import keeps the dashboard light

        with st.status("Running pipeline…", expanded=True) as status:
            bar = st.progress(0.0)
            try:
                scan_path = _save_upload(scan, workdir)
                firmo_path = _save_upload(firmo, workdir) if firmo else None
                res = run_pipeline(scan_path, workdir, firmo_path,
                                   progress=lambda msg, pct: (bar.progress(pct, text=msg)))
                scan_path.unlink(missing_ok=True)  # raw upload no longer needed
            except (ValueError, duckdb.Error, OSError) as e:
                status.update(label="Pipeline failed", state="error", expanded=True)
                st.error(str(e))
                return None
            status.update(label=f"Scored {res.companies:,} accounts from {res.exposure_rows:,} exposures "
                                f"in {sum(res.timings.values()):.1f}s", state="complete", expanded=False)
        st.session_state["upload_source"] = Source(
            f"Upload: {scan.name}", res.scores, res.exposures, res.synthetic_firmographics,
            "Analysis of your uploaded file.")
    return st.session_state.get("upload_source")


# ---------------------------------------------------------------------------
# query layer
# ---------------------------------------------------------------------------
@st.cache_resource(max_entries=8)
def get_con(scores: str, exposures: str | None) -> duckdb.DuckDBPyConnection:
    con = duckdb.connect()
    con.execute(f"PRAGMA memory_limit='{config.MEMORY_LIMIT}'")
    con.execute(f"CREATE VIEW scores AS SELECT * FROM read_parquet('{scores}')")
    if exposures:
        con.execute(f"CREATE VIEW exposures AS SELECT * FROM read_parquet('{exposures}')")
    return con


@st.cache_data(ttl=600, show_spinner=False, max_entries=500)
def _q(scores: str, exposures: str | None, sql: str, params: tuple[Any, ...]) -> pd.DataFrame:
    return get_con(scores, exposures).cursor().execute(sql, list(params)).fetchdf()


class Q:
    """Query helper bound to one data source (paths are part of the cache key)."""

    def __init__(self, src: Source) -> None:
        self.scores = src.scores.as_posix()
        self.exposures = src.exposures.as_posix() if src.exposures and src.exposures.exists() else None

    def __call__(self, sql: str, params: tuple[Any, ...] = ()) -> pd.DataFrame:
        return _q(self.scores, self.exposures, sql, params)


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
    if r.sig_risky_service and r.risky_services is not None and len(r.risky_services):
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

    lines = [f"Subject: {r['name']} — a quick external security observation", "", "Hi there,", ""]
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
# dashboard
# ---------------------------------------------------------------------------
def render_dashboard(src: Source) -> None:
    q = Q(src)
    if src.synthetic:
        st.warning("Firmographic signals (industry, headcount, hiring, funding, vendor tech stack) are "
                   "SYNTHETIC placeholders. Attack-surface signals come from the real scan data.", icon="⚠️")
    if src.note:
        st.caption(src.note)

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

    total, hp_all, avg_all = q(f"""SELECT count(*), count(*) FILTER (score > {config.HIGH_PRIORITY_SCORE}),
                                   avg(score) FROM scores""").iloc[0]
    f_n, f_hp, f_avg = q(f"""SELECT count(*), count(*) FILTER (score > {config.HIGH_PRIORITY_SCORE}),
                            avg(score) FROM scores WHERE {wsql}""", tuple(params)).iloc[0]
    m = st.columns(4)
    m[0].metric("Total accounts processed", f"{int(total):,}")
    m[1].metric(f"High-priority leads (>{config.HIGH_PRIORITY_SCORE})", f"{int(hp_all):,}",
                f"{int(f_hp):,} in current filter", delta_color="off")
    m[2].metric("Average security score", f"{(avg_all or 0):.1f}",
                f"{(f_avg or 0):.1f} in filter", delta_color="off")
    m[3].metric("Matching current filters", f"{int(f_n):,}")

    left, right = st.columns([3, 2], gap="large")
    df = q(f"""SELECT company_id, name, industry, employee_count, score, priority, evidence_badges
               FROM scores WHERE {wsql}
               ORDER BY score DESC, n_services DESC NULLS LAST LIMIT {int(page_size)}""", tuple(params))
    with left:
        st.subheader(f"Prospects ({len(df):,} of {int(f_n):,})")
        event = st.dataframe(
            df, hide_index=True, width="stretch", height=620,
            on_select="rerun", selection_mode="single-row", key=f"tbl_{src.label}",
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
        render_drawer(q, df.iloc[rows[0]]["company_id"])


def render_drawer(q: Q, company_id: str) -> None:
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
    stack = list(r.tech_stack)[:40] if r.tech_stack is not None else []
    st.markdown(" ".join(f":blue-badge[{t}]" for t in stack) if stack else "_none detected_")
    if r.missing_security_categories is not None and len(r.missing_security_categories):
        st.markdown("**Missing security categories** " +
                    " ".join(f":red-badge[{m}]" for m in r.missing_security_categories))

    st.markdown("**Hiring signals**")
    if r.hiring_signals is not None and len(r.hiring_signals):
        sec = set(r.sec_roles) if r.sec_roles is not None else set()
        st.markdown(" ".join(f":orange-badge[{h}]" if h in sec else f":gray-badge[{h}]"
                             for h in r.hiring_signals))
    else:
        st.caption("No open roles in feed.")

    with st.expander("Observed exposures (scan data)"):
        if q.exposures:
            ex = q("""SELECT ip, port, module, product, version, max_cvss, cves[1:3] AS cves, tags,
                             weak_tls, cert_expired, seen_at
                      FROM exposures WHERE domain = ? AND NOT is_ptr_only
                      ORDER BY max_cvss DESC NULLS LAST LIMIT 100""", (company_id,))
            if ex.empty:
                st.caption("Raw exposure rows are not included for this account in this data source.")
            else:
                st.dataframe(ex, hide_index=True, width="stretch")
        else:
            st.caption("Exposure detail not available for this data source.")

    if st.button("Draft cold email", type="primary", width="stretch"):
        st.session_state["draft_for"] = company_id
    if st.session_state.get("draft_for") == company_id:
        email, prompt = draft_email(r)
        st.text_area("Email draft", email, height=300)
        st.download_button("Download .txt", email.encode(), f"{company_id}_email.txt")
        with st.expander("LLM prompt (paste into Claude for a polished version)"):
            st.code(prompt, language="markdown")


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------
UPLOAD = "Upload a scan file"


def main() -> None:
    st.title("Cybersecurity Readiness — Prospect Queue")
    sources = available_sources()
    choice = st.sidebar.radio("Data source", [*sources, UPLOAD], key="data_source")
    st.sidebar.divider()

    if choice == UPLOAD:
        src = upload_panel()
        if src is None:
            st.stop()
        cols = st.columns([4, 1])
        cols[0].success(f"Showing results for **{src.label.removeprefix('Upload: ')}**")
        if cols[1].button("Clear upload"):
            st.session_state.pop("upload_source", None)
            st.rerun()
        st.divider()
    else:
        src = sources[choice]
    render_dashboard(src)


if __name__ == "__main__":
    main()
