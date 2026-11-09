"""Global configuration for the Cybersecurity Sales Intelligence platform.

Everything tunable lives here: file paths, DuckDB resource limits, the
scoring weights, and the keyword/port dictionaries the signal layer uses.
Most values can be overridden with environment variables so the same code
runs on a 3 GB laptop VM and a 64 GB server without edits.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

import duckdb

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT: Final[Path] = Path(__file__).resolve().parent
DATA_DIR: Final[Path] = Path(os.getenv("CI_DATA_DIR", ROOT / "data"))
WAREHOUSE_DIR: Final[Path] = Path(os.getenv("CI_WAREHOUSE_DIR", ROOT / "warehouse"))
TEMP_DIR: Final[Path] = Path(os.getenv("CI_TEMP_DIR", WAREHOUSE_DIR / "spill"))

# Raw internet-scan dump (Shodan-style NDJSON, one banner per IP:port).
# Accepts a glob. Default points at the file sitting next to this repo.
SCAN_GLOB: Final[str] = os.getenv("CI_SCAN_GLOB", str(ROOT.parent / "b2_download_file_by_id"))
# 'auto' lets DuckDB sniff by extension; files without an extension need it set.
SCAN_COMPRESSION: Final[str] = os.getenv("CI_SCAN_COMPRESSION", "zstd")

# Firmographics (company profiles: industry, headcount, tech stack, hiring,
# funding). JSON or Parquet; glob allowed. firmographics.py --mock writes a
# synthetic one here until a real vendor file is dropped in.
FIRMO_GLOB: Final[str] = os.getenv("CI_FIRMO_GLOB", str(DATA_DIR / "firmographics*.parquet"))

DB_PATH: Final[Path] = WAREHOUSE_DIR / "intel.duckdb"
EXPOSURES_PARQUET: Final[Path] = WAREHOUSE_DIR / "exposures.parquet"
SCORES_PARQUET: Final[Path] = WAREHOUSE_DIR / "company_scores.parquet"
MANIFEST_PATH: Final[Path] = WAREHOUSE_DIR / "ingest_manifest.json"

# Small, git-friendly snapshot of a full run (built by make_demo.py). The
# hosted app falls back to it when warehouse/ is absent.
DEMO_DIR: Final[Path] = ROOT / "demo_data"
DEMO_SCORES: Final[Path] = DEMO_DIR / "company_scores.parquet"
DEMO_EXPOSURES: Final[Path] = DEMO_DIR / "exposures_top.parquet"
# Upload limits for the "Upload a scan file" mode of the dashboard.
UPLOAD_ROOT: Final[Path] = Path(os.getenv("CI_UPLOAD_ROOT", WAREHOUSE_DIR / "uploads"))

# ---------------------------------------------------------------------------
# DuckDB resources
# ---------------------------------------------------------------------------
def _default_memory_limit() -> str:
    """8GB, or 60% of physical RAM on smaller hosts (e.g. ~1 GB cloud containers)."""
    try:
        total_gb = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 1024**3
    except (ValueError, OSError, AttributeError):
        return "8GB"
    return f"{max(0.25, min(8.0, round(total_gb * 0.6, 2)))}GB"


MEMORY_LIMIT: Final[str] = os.getenv("CI_MEMORY_LIMIT", _default_memory_limit())
THREADS: Final[int] = int(os.getenv("CI_THREADS", str(os.cpu_count() or 4)))
# Largest single JSON line we accept (banners with big favicons/HTML).
MAX_OBJECT_BYTES: Final[int] = int(os.getenv("CI_MAX_OBJECT_BYTES", str(64 * 1024 * 1024)))
PARQUET_ROW_GROUP: Final[int] = 250_000


def connect(read_only: bool = False, db_path: Path | str | None = None,
            temp_dir: Path | None = None) -> duckdb.DuckDBPyConnection:
    """Open a DuckDB database with the memory/spill settings applied.

    ``db_path=':memory:'`` gives a throwaway in-memory database (used by the
    upload pipeline); ``temp_dir`` overrides where large operators spill.
    """
    spill = temp_dir or TEMP_DIR
    spill.mkdir(parents=True, exist_ok=True)
    if db_path is None:
        WAREHOUSE_DIR.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(db_path or DB_PATH), read_only=read_only)
    con.execute(f"PRAGMA memory_limit='{MEMORY_LIMIT}'")
    con.execute(f"PRAGMA threads={THREADS}")
    con.execute(f"PRAGMA temp_directory='{spill.as_posix()}'")
    # Streaming COPY does not need input order -> lets DuckDB flush early.
    con.execute("SET preserve_insertion_order=false")
    return con


# ---------------------------------------------------------------------------
# Scoring weights (must sum to 100)
# ---------------------------------------------------------------------------
# Hybrid model: the brief's four firmographic signals re-weighted to 70,
# plus 30 points of observed external attack surface from the scan data.
WEIGHTS: Final[dict[str, int]] = {
    "attack_surface": 30,  # exposed risky services, CVEs, EOL software, weak TLS
    "tooling_gap": 20,     # >50 staff but missing security tool categories
    "compliance": 20,      # high-risk / regulated industry
    "hiring": 15,          # eng/IT hiring without security hiring
    "funding": 15,         # funding event in the last FUNDING_WINDOW_DAYS
}
assert sum(WEIGHTS.values()) == 100, "WEIGHTS must sum to 100"

# Attack-surface sub-points; capped at WEIGHTS['attack_surface'].
ATTACK_SUBPOINTS: Final[dict[str, int]] = {
    "critical_cve": 12,      # any CVE with CVSS >= CRITICAL_CVSS
    "high_cve": 6,           # CVSS >= 7 (only if no critical)
    "risky_service": 10,     # admin/data service open to the internet
    "eol_software": 4,
    "weak_tls": 4,           # TLS1.0/1.1/SSLv3 accepted, expired or self-signed cert
}
CRITICAL_CVSS: Final[float] = 9.0
HIGH_CVSS: Final[float] = 7.0

MIN_EMPLOYEES_FOR_GAP: Final[int] = 50
FUNDING_WINDOW_DAYS: Final[int] = 180
MIN_DEV_ROLES_FOR_MISMATCH: Final[int] = 1
HIGH_PRIORITY_SCORE: Final[int] = 75

# ---------------------------------------------------------------------------
# Dictionaries used by signals.py
# ---------------------------------------------------------------------------
# Security tool categories. A company "has" a category when any keyword
# appears (case-insensitive) in its combined tech stack (vendor list + what
# the scan saw at the edge).
SECURITY_TOOL_CATEGORIES: Final[dict[str, list[str]]] = {
    "EDR": ["crowdstrike", "sentinelone", "defender for endpoint", "carbon black", "sophos", "cortex xdr"],
    "IAM": ["okta", "azure ad", "entra", "auth0", "ping identity", "onelogin", "duo"],
    "SIEM/Observability": ["splunk", "datadog", "sumo logic", "elastic security", "qradar", "sentinel"],
    "Network/Edge": ["palo alto", "fortinet", "fortigate", "zscaler", "imperva", "cloudflare",
                     "akamai", "f5 bigip", "check point", "sonicwall", "netskope"],
}

# Internet-exposed services that should almost never be public.
RISKY_PORTS: Final[dict[int, str]] = {
    21: "FTP", 23: "Telnet", 445: "SMB", 135: "MS-RPC", 139: "NetBIOS", 161: "SNMP",
    1433: "MSSQL", 1521: "Oracle DB", 2375: "Docker API", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 6379: "Redis", 6443: "Kubernetes API",
    9200: "Elasticsearch", 10250: "Kubelet", 11211: "Memcached", 27017: "MongoDB",
}

HIGH_RISK_INDUSTRIES: Final[list[str]] = [
    "Fintech", "Banking", "Insurance", "Healthtech", "Healthcare", "Legal", "SaaS",
    "Government", "Payments",
]
COMPLIANCE_BY_INDUSTRY: Final[dict[str, str]] = {
    "Fintech": "PCI-DSS / SOC 2", "Banking": "PCI-DSS / GLBA", "Payments": "PCI-DSS",
    "Insurance": "SOC 2 / NAIC", "Healthtech": "HIPAA", "Healthcare": "HIPAA",
    "Legal": "ISO 27001 / client confidentiality", "SaaS": "SOC 2 / ISO 27001",
    "Government": "FedRAMP / NIST 800-53",
}
# Domain keyword -> inferred industry (used when no firmographic match).
DOMAIN_INDUSTRY_HINTS: Final[dict[str, str]] = {
    "bank": "Banking", "finance": "Fintech", "capital": "Fintech", "pay": "Payments",
    "insur": "Insurance", "health": "Healthcare", "clinic": "Healthcare", "hospital": "Healthcare",
    "medic": "Healthcare", "pharma": "Healthcare", "law": "Legal", "legal": "Legal",
    "gov": "Government",
}

DEV_ROLE_KEYWORDS: Final[list[str]] = ["software engineer", "developer", "devops", "sre",
                                       "it admin", "systems engineer", "data engineer", "backend", "frontend"]
SEC_ROLE_KEYWORDS: Final[list[str]] = ["ciso", "security engineer", "security analyst",
                                       "appsec", "soc analyst", "head of security", "grc"]

# Registered domains that belong to clouds, CDNs and ISPs rather than to a
# prospect. Exposures under these are ignored for company scoring.
INFRA_DOMAINS: Final[list[str]] = [
    "amazonaws.com", "cloudfront.net", "awsglobalaccelerator.com", "googleusercontent.com",
    "1e100.net", "google.com", "incapdns.net", "akamaitechnologies.com", "akamaiedge.net",
    "cloudflare.com", "azure.com", "cloudapp.net", "windows.net", "linode.com",
    "vultrusercontent.com", "digitaloceanspaces.com", "scw.cloud", "your-server.de",
    "hetzner.com", "ovh.net", "flyio.net", "fastly.net", "edgecastcdn.net", "sendgrid.net",
    "hinet.net", "ocn.ne.jp", "spectrum.com", "comcast.net", "verizon.net", "bbtec.net",
    "nuro.jp", "rr.com", "charter.com", "telus.net", "vodafone.com", "chinanet.cn",
    "dynamic-ip.com", "ui-r.com", "duckdns.org", "dynu.com", "no-ip.com", "ddns.net",
    "hostgator.com", "websitewelcome.com", "aliyuncs.com", "shawcable.net", "telefonica.net", "018.net.il", "contaboserver.net", "herokuapp.com",
]
# Any domain seen on more than this many distinct IPs is treated as infra
# (median prospect has 1 IP, p99.9 ~130 in the reference dump).
MAX_IPS_PER_COMPANY: Final[int] = int(os.getenv("CI_MAX_IPS_PER_COMPANY", "300"))
# Hosting / ISP / dynamic-DNS naming; applied only to domains with at least
# INFRA_REGEX_MIN_IPS IPs so small companies named e.g. "cloudsec" survive.
INFRA_DOMAIN_REGEX: Final[str] = (r"host|vps|server|dedicated|datacenter|colo|cable|broadband|"
                                  r"telecom|ddns|dyndns|duckdns|no-ip|isp\.|\.net\.[a-z]{2}$")
INFRA_REGEX_MIN_IPS: Final[int] = 25
