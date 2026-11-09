"""Build the git-friendly demo snapshot used by the hosted dashboard.

warehouse/ (~600 MB) is too big for GitHub and for free hosting tiers, so
this writes a trimmed copy to demo_data/:

* company_scores.parquet  - every scored account (~32 MB)
* exposures_top.parquet   - raw exposure rows only for accounts scoring >= MIN_SCORE (~12 MB)
* sample_scan_5k.json.zst - small scan slice visitors can try in "Upload" mode

Run after scorer.py:  python make_demo.py [--min-score 50]
"""

from __future__ import annotations

import argparse
import glob
import json
import shutil
import time
from pathlib import Path

import duckdb

import config


def main(min_score: int) -> None:
    if not config.SCORES_PARQUET.exists() or not config.EXPOSURES_PARQUET.exists():
        raise SystemExit("Run ingest.py and scorer.py first - warehouse/ is incomplete.")
    config.DEMO_DIR.mkdir(exist_ok=True)
    con = duckdb.connect()
    con.execute(f"""COPY (SELECT * FROM read_parquet('{config.SCORES_PARQUET.as_posix()}')
                          ORDER BY score DESC, n_services DESC NULLS LAST)
                    TO '{config.DEMO_SCORES.as_posix()}' (FORMAT parquet, COMPRESSION zstd)""")
    con.execute(f"""COPY (
                      SELECT e.* FROM read_parquet('{config.EXPOSURES_PARQUET.as_posix()}') e
                      SEMI JOIN (SELECT company_id FROM read_parquet('{config.SCORES_PARQUET.as_posix()}')
                                 WHERE score >= {min_score}) s ON e.domain = s.company_id
                      WHERE NOT e.is_ptr_only
                      ORDER BY e.domain)           -- sorted -> row-group pruning on domain lookups
                    TO '{config.DEMO_EXPOSURES.as_posix()}' (FORMAT parquet, COMPRESSION zstd)""")
    firmo = [Path(p) for p in glob.glob(config.FIRMO_GLOB)]
    (config.DEMO_DIR / "meta.json").write_text(json.dumps({
        "synthetic_firmographics": bool(firmo) and all("mock" in p.name for p in firmo),
        "exposures_min_score": min_score,
        "built_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }, indent=2))
    sample = config.DATA_DIR / "sample" / "scan_5k.json.zst"
    if sample.exists():
        shutil.copyfile(sample, config.DEMO_DIR / "sample_scan_5k.json.zst")
    for f in sorted(config.DEMO_DIR.iterdir()):
        print(f"[demo] {f.name:28s} {f.stat().st_size / 1e6:6.1f} MB")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--min-score", type=int, default=50)
    main(ap.parse_args().min_score)
