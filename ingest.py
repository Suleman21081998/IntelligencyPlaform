"""Streaming ingestion: raw scan dump + firmographics -> DuckDB views/Parquet.

Design
------
* The scan dump is one huge zstd-compressed NDJSON file (~20 GB compressed,
  roughly 150-200 GB of JSON). DuckDB reads it as a stream with an explicit
  column projection, so the multi-KB banner/HTML/favicon payloads are never
  materialised and RAM stays under ``PRAGMA memory_limit``.
* One pass writes a slim, columnar ``exposures.parquet`` (one row per
  company-domain x IP x port). Every later stage queries that file, which is
  ~100x smaller than the raw JSON and supports projection pushdown.
* Idempotent: a manifest records the source files' size/mtime and the schema
  version. Re-running is a no-op unless the source changed or --force is set.
  Output is written to a temp file and atomically renamed, so an interrupted
  run never leaves a half-written Parquet behind.

Usage
-----
    python ingest.py                      # ingest default SCAN_GLOB
    python ingest.py --source 'data/*.zst' --force
    CI_MEMORY_LIMIT=2GB python ingest.py  # low-RAM run
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

import duckdb

import config

SCHEMA_VERSION = 3

# Explicit projection of the scan JSON. Keys not listed are skipped by the
# parser, which is what keeps memory flat on 10 KB+ banners.
SCAN_COLUMNS: dict[str, str] = {
    "ip_str": "VARCHAR",
    "port": "INTEGER",
    "transport": "VARCHAR",
    "timestamp": "VARCHAR",
    "org": "VARCHAR",
    "isp": "VARCHAR",
    "asn": "VARCHAR",
    "hostnames": "VARCHAR[]",
    "domains": "VARCHAR[]",
    "location": "STRUCT(country_code VARCHAR, city VARCHAR)",
    "product": "VARCHAR",
    "version": "VARCHAR",
    "tags": "VARCHAR[]",
    "cpe23": "VARCHAR[]",
    "vulns": "JSON",
    "http": "STRUCT(title VARCHAR, server VARCHAR, components JSON)",
    "ssl": "STRUCT(cert STRUCT(expired BOOLEAN), versions VARCHAR[])",
    "_shodan": "STRUCT(module VARCHAR)",
    "cloud": "STRUCT(provider VARCHAR)",
}

# Normalised firmographic schema required by the scorer, with safe defaults.
FIRMO_SCHEMA: dict[str, tuple[str, str]] = {
    "company_id": ("VARCHAR", "NULL"),
    "name": ("VARCHAR", "NULL"),
    "industry": ("VARCHAR", "'Unknown'"),
    "employee_count": ("INTEGER", "NULL"),
    "tech_stack": ("VARCHAR[]", "[]::VARCHAR[]"),
    "hiring_signals": ("VARCHAR[]", "[]::VARCHAR[]"),
    "is_regulated": ("BOOLEAN", "false"),
    "days_since_funding": ("INTEGER", "NULL"),
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _sql_str(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _source_files(pattern: str) -> list[Path]:
    return sorted(Path(p) for p in glob.glob(pattern) if Path(p).is_file())


def _fingerprint(files: list[Path]) -> list[dict[str, Any]]:
    return [{"path": str(f), "bytes": f.stat().st_size, "mtime": int(f.stat().st_mtime)} for f in files]


def _load_manifest() -> dict[str, Any]:
    try:
        return json.loads(config.MANIFEST_PATH.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _read_json_expr(pattern: str, compression: str) -> str:
    cols = "{" + ", ".join(f"{_sql_str(k)}: {_sql_str(v)}" for k, v in SCAN_COLUMNS.items()) + "}"
    return (
        f"read_json({_sql_str(pattern)}, format='newline_delimited', "
        f"compression={_sql_str(compression)}, columns={cols}, "
        f"ignore_errors=true, maximum_object_size={config.MAX_OBJECT_BYTES})"
    )


class ProgressReporter:
    """Polls ``con.query_progress()`` from a side thread and draws a bar."""

    def __init__(self, con: duckdb.DuckDBPyConnection, label: str, interval: float = 5.0) -> None:
        self.con, self.label, self.interval = con, label, interval
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)
        self.start_ts = time.time()

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                pct = float(self.con.query_progress())
            except Exception:  # noqa: BLE001 - progress is best effort
                pct = -1.0
            elapsed = time.time() - self.start_ts
            if pct >= 0:
                filled = int(pct / 100 * 30)
                eta = elapsed / pct * (100 - pct) if pct > 0 else float("nan")
                bar = "#" * filled + "-" * (30 - filled)
                msg = f"\r[{self.label}] [{bar}] {pct:5.1f}%  elapsed {elapsed/60:5.1f}m  eta {eta/60:5.1f}m"
            else:
                msg = f"\r[{self.label}] running... elapsed {elapsed/60:5.1f}m"
            sys.stderr.write(msg)
            sys.stderr.flush()

    def __enter__(self) -> "ProgressReporter":
        self._t.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._t.join(timeout=1)
        sys.stderr.write("\n")


# ---------------------------------------------------------------------------
# SQL
# ---------------------------------------------------------------------------
def exposures_select(pattern: str, compression: str) -> str:
    """Flatten each banner to one row per (registered domain, ip, port)."""
    ip_like = r"\d{1,3}[-.]\d{1,3}[-.]\d{1,3}[-.]\d{1,3}"
    ptr_prefix = r"^(ec2|ip|static|dynamic|host|customer|pool|dsl|cpe|client|dhcp)[-.0-9]"
    return f"""
    WITH b AS (
        SELECT
            ip_str                                   AS ip,
            port,
            transport,
            _shodan.module                           AS module,
            TRY_CAST("timestamp" AS TIMESTAMP)       AS seen_at,
            org, isp, asn,
            location.country_code                    AS country,
            location.city                            AS city,
            cloud.provider                           AS cloud_provider,
            product, version,
            COALESCE(tags, [])                       AS tags,
            COALESCE(cpe23, [])                      AS cpe,
            http.title                               AS http_title,
            -- tech fingerprint = HTTP components + banner product
            list_distinct(list_filter(
                list_concat(COALESCE(json_keys(http.components), []), [product]),
                lambda x: x IS NOT NULL))                 AS tech,
            COALESCE(json_keys(vulns), [])           AS cves,
            list_max(list_transform(
                map_values(TRY_CAST(vulns AS MAP(VARCHAR, STRUCT(cvss DOUBLE)))),
                lambda v: v.cvss))                        AS max_cvss,
            list_has_any(COALESCE(ssl.versions, []), ['SSLv2','SSLv3','TLSv1','TLSv1.1'])
                                                     AS weak_tls,
            COALESCE(ssl.cert.expired, false)        AS cert_expired,
            COALESCE(hostnames, [])                  AS hostnames,
            domains
        FROM {_read_json_expr(pattern, compression)}
        WHERE len(domains) > 0
    )
    SELECT
        lower(d)                                     AS domain,
        * EXCLUDE (domains, hostnames),
        -- true when every hostname under this domain is reverse-DNS noise
        -- (ISP/hosting PTR records), i.e. the domain is not the IP's owner
        COALESCE(list_aggregate(
            list_transform(
                list_filter(hostnames, lambda h: h = d OR ends_with(h, '.' || d)),
                lambda h: regexp_matches(h, '{ip_like}') OR regexp_matches(h, '{ptr_prefix}')),
            'bool_and'), false)                      AS is_ptr_only
    FROM b, UNNEST(domains) AS t(d)
    """


def register_views(con: duckdb.DuckDBPyConnection, scan_glob: str | None = None) -> None:
    """(Re)create the logical views every downstream module relies on."""
    scan_glob = scan_glob or config.SCAN_GLOB
    if _source_files(scan_glob):
        con.execute(f"CREATE OR REPLACE VIEW raw_scan AS SELECT * FROM "
                    f"{_read_json_expr(scan_glob, config.SCAN_COMPRESSION)}")
    if config.EXPOSURES_PARQUET.exists():
        con.execute(f"CREATE OR REPLACE VIEW exposures AS SELECT * FROM "
                    f"read_parquet({_sql_str(config.EXPOSURES_PARQUET.as_posix())})")
    register_firmographics(con)


def register_firmographics(con: duckdb.DuckDBPyConnection, firmo_glob: str | None = None) -> bool:
    """Create raw_companies (as-is) and companies (normalised) views.

    Missing columns are filled with typed defaults so a partial vendor feed
    still produces a valid ``companies`` view.
    """
    firmo_glob = firmo_glob or config.FIRMO_GLOB
    files = _source_files(firmo_glob)
    if not files:
        # Empty typed view keeps downstream SQL valid with zero firmographics.
        cols = ", ".join(f"CAST(NULL AS {t}) AS {c}" for c, (t, _) in FIRMO_SCHEMA.items())
        con.execute(f"CREATE OR REPLACE VIEW companies AS SELECT {cols} WHERE false")
        return False
    suffix = files[0].suffix.lower()
    if suffix == ".parquet":
        reader = f"read_parquet({_sql_str(firmo_glob)}, union_by_name=true)"
    elif suffix == ".csv":
        # list columns in CSV are expected as ';'-separated strings
        reader = f"read_csv_auto({_sql_str(firmo_glob)}, union_by_name=true, ignore_errors=true)"
    else:
        reader = f"read_json_auto({_sql_str(firmo_glob)}, ignore_errors=true, union_by_name=true)"
    con.execute(f"CREATE OR REPLACE VIEW raw_companies AS SELECT * FROM {reader}")
    present = {r[0] for r in con.execute("DESCRIBE raw_companies").fetchall()}
    exprs = []
    col_types = {r[0]: r[1] for r in con.execute("DESCRIBE raw_companies").fetchall()}
    for col, (typ, default) in FIRMO_SCHEMA.items():
        if col in present and typ == "VARCHAR[]" and col_types[col] == "VARCHAR":
            # CSV-style "Okta;Splunk" -> ['Okta', 'Splunk']
            exprs.append(f"COALESCE(list_transform(string_split({col}, ';'), lambda x: trim(x)), {default}) AS {col}")
        elif col in present:
            exprs.append(f"COALESCE(TRY_CAST({col} AS {typ}), {default}) AS {col}")
        else:
            exprs.append(f"CAST({default} AS {typ}) AS {col}")
    con.execute(f"""
        CREATE OR REPLACE VIEW companies AS
        SELECT * REPLACE (lower(trim(company_id)) AS company_id)
        FROM (SELECT {', '.join(exprs)} FROM raw_companies)
        WHERE company_id IS NOT NULL
    """)
    return True


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def ingest_scan(source: str, force: bool = False) -> dict[str, Any]:
    files = _source_files(source)
    if not files:
        raise FileNotFoundError(f"No scan files match {source!r}")
    fp = _fingerprint(files)
    manifest = _load_manifest()
    if (not force and config.EXPOSURES_PARQUET.exists()
            and manifest.get("sources") == fp and manifest.get("schema_version") == SCHEMA_VERSION):
        print(f"[ingest] up to date ({manifest.get('rows'):,} exposure rows) - use --force to rebuild")
        return manifest

    total_gb = sum(f["bytes"] for f in fp) / 1e9
    print(f"[ingest] {len(files)} file(s), {total_gb:.2f} GB on disk | memory_limit={config.MEMORY_LIMIT} "
          f"threads={config.THREADS}")
    con = config.connect()
    con.execute("SET enable_progress_bar=false")  # we draw our own
    tmp = config.EXPOSURES_PARQUET.with_suffix(".parquet.tmp")
    tmp.unlink(missing_ok=True)

    t0 = time.time()
    with ProgressReporter(con, "scan->parquet"):
        rows = con.execute(f"""
            COPY ({exposures_select(source, config.SCAN_COMPRESSION)})
            TO {_sql_str(tmp.as_posix())}
            (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE {config.PARQUET_ROW_GROUP})
        """).fetchone()[0]
    elapsed = time.time() - t0
    os.replace(tmp, config.EXPOSURES_PARQUET)

    out_mb = config.EXPOSURES_PARQUET.stat().st_size / 1e6
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "sources": fp,
        "rows": int(rows),
        "seconds": round(elapsed, 1),
        "source_gb": round(total_gb, 3),
        "throughput_mb_s_compressed": round(total_gb * 1000 / max(elapsed, 1e-6), 1),
        "parquet_mb": round(out_mb, 1),
        "memory_limit": config.MEMORY_LIMIT,
        "threads": config.THREADS,
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    config.MANIFEST_PATH.write_text(json.dumps(manifest, indent=2))
    print(f"[ingest] wrote {rows:,} exposure rows -> {config.EXPOSURES_PARQUET.name} "
          f"({out_mb:,.1f} MB) in {elapsed/60:.1f} min "
          f"[{manifest['throughput_mb_s_compressed']} MB/s compressed input]")
    register_views(con, source)
    con.close()
    return manifest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", default=config.SCAN_GLOB, help="glob of scan NDJSON files")
    ap.add_argument("--force", action="store_true", help="rebuild even if the manifest matches")
    ap.add_argument("--views-only", action="store_true", help="only (re)register views")
    args = ap.parse_args(argv)
    try:
        if args.views_only:
            con = config.connect()
            register_views(con, args.source)
            print("[ingest] views registered:",
                  [r[0] for r in con.execute("SELECT view_name FROM duckdb_views() WHERE NOT internal").fetchall()])
            return 0
        ingest_scan(args.source, args.force)
        return 0
    except FileNotFoundError as e:
        print(f"[ingest] ERROR: {e}", file=sys.stderr)
        return 2
    except duckdb.Error as e:
        print(f"[ingest] DuckDB error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
