"""End-to-end pipeline on an arbitrary file, in an isolated work directory.

Used by the dashboard's "Upload a scan file" mode (and handy for tests):
the same SQL as ingest.py -> signals.py -> scorer.py, but every artefact is
written to ``workdir`` instead of the shared warehouse, so concurrent users
and the bundled dataset never interfere with each other.

    from pipeline import run_pipeline
    result = run_pipeline("upload/scan.json.gz", "/tmp/run1")

CLI:
    python pipeline.py data/sample/scan_5k.json.zst /tmp/run1 [--firmo companies.csv]
"""

from __future__ import annotations

import argparse
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import duckdb

import config
import signals
from firmographics import mock_select_sql
from ingest import _sql_str, exposures_select, register_firmographics
from scorer import SCORE_SQL

ProgressFn = Callable[[str, float], None]


@dataclass
class PipelineResult:
    workdir: Path
    scores: Path
    exposures: Path
    exposure_rows: int = 0
    companies: int = 0
    high_priority: int = 0
    synthetic_firmographics: bool = True
    timings: dict[str, float] = field(default_factory=dict)


def detect_compression(path: Path) -> str:
    """Pick the DuckDB compression for a file, sniffing magic bytes if needed."""
    suffix = path.suffix.lower()
    if suffix in {".zst", ".zstd"}:
        return "zstd"
    if suffix == ".gz":
        return "gzip"
    with path.open("rb") as fh:
        magic = fh.read(4)
    if magic == b"\x28\xb5\x2f\xfd":
        return "zstd"
    if magic[:2] == b"\x1f\x8b":
        return "gzip"
    return "uncompressed"


def run_pipeline(scan_path: str | Path, workdir: str | Path, firmo_path: str | Path | None = None,
                 progress: ProgressFn | None = None) -> PipelineResult:
    """ingest -> (mock) firmographics -> signals -> score, all inside ``workdir``."""
    scan_path, workdir = Path(scan_path), Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    say: ProgressFn = progress or (lambda msg, pct: print(f"[pipeline] {pct:3.0%} {msg}"))
    res = PipelineResult(workdir=workdir, scores=workdir / "company_scores.parquet",
                         exposures=workdir / "exposures.parquet")
    con = config.connect(db_path=":memory:", temp_dir=workdir / "spill")
    try:
        # 1. scan -> exposures.parquet (same projection/flattening as ingest.py)
        t = time.time()
        say("Parsing scan file", 0.05)
        comp = detect_compression(scan_path)
        res.exposure_rows = con.execute(
            f"COPY ({exposures_select(str(scan_path), comp)}) TO {_sql_str(res.exposures.as_posix())} "
            "(FORMAT parquet, COMPRESSION zstd)").fetchone()[0]
        res.timings["ingest"] = time.time() - t
        if res.exposure_rows == 0:
            raise ValueError("No rows with a 'domains' field were found. The file must be newline-delimited "
                             "JSON in the Shodan banner format (ip_str, port, domains, vulns, ...).")
        con.execute(f"CREATE VIEW exposures AS SELECT * FROM read_parquet({_sql_str(res.exposures.as_posix())})")
        signals._lookup_tables(con)

        # 2. firmographics: uploaded feed, or deterministic synthetic profiles
        t = time.time()
        say("Loading company profiles", 0.45)
        if firmo_path:
            res.synthetic_firmographics = False
            register_firmographics(con, str(firmo_path))
        else:
            mock = workdir / "firmographics_mock.parquet"
            con.execute(f"COPY ({mock_select_sql()}) TO {_sql_str(mock.as_posix())} (FORMAT parquet)")
            register_firmographics(con, str(mock))
        res.timings["firmographics"] = time.time() - t

        # 3. signals
        t = time.time()
        say("Extracting signals", 0.6)
        signals.build_attack_surface(con)
        signals.build_company_signals(con)
        res.timings["signals"] = time.time() - t

        # 4. score + sorted export
        t = time.time()
        say("Scoring accounts", 0.85)
        con.execute(SCORE_SQL)
        con.execute(f"COPY (SELECT * FROM company_scores ORDER BY score DESC, n_services DESC NULLS LAST) "
                    f"TO {_sql_str(res.scores.as_posix())} (FORMAT parquet, COMPRESSION zstd)")
        res.companies, res.high_priority = con.execute(
            f"SELECT count(*), count(*) FILTER (score > {config.HIGH_PRIORITY_SCORE}) FROM company_scores"
        ).fetchone()
        res.timings["score"] = time.time() - t
        say("Done", 1.0)
        return res
    finally:
        con.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scan")
    ap.add_argument("workdir")
    ap.add_argument("--firmo", default=None, help="optional firmographics CSV/JSON/Parquet")
    a = ap.parse_args()
    try:
        r = run_pipeline(a.scan, a.workdir, a.firmo)
    except (ValueError, duckdb.Error) as e:
        raise SystemExit(f"[pipeline] ERROR: {e}")
    print(f"[pipeline] {r.exposure_rows:,} exposures -> {r.companies:,} accounts, {r.high_priority:,} P1 | "
          + ", ".join(f"{k} {v:.1f}s" for k, v in r.timings.items()))
