#!/usr/bin/env python3
"""Import the offline staging package as model DRAFTS (nothing is approved or published).

  .venv\\Scripts\\python.exe scripts\\import_staging.py --actor operator [--dir data/regintel/staging/eu-starter]

Only staged documents that are byte-identical to a global catalog version are
imported; every candidate is re-grounded against the catalog's section text.
Stop the catalog-admin process (or make sure no job is running) first.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from regintel.db import CatalogDb  # noqa: E402
from regintel.preload import import_staging  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--actor", required=True)
    p.add_argument("--dir", default=str(ROOT / "data" / "regintel" / "staging" / "eu-starter"))
    p.add_argument("--db", default=str(ROOT / "data" / "regintel" / "catalog.db"))
    args = p.parse_args()
    db = CatalogDb(Path(args.db))
    try:
        report = import_staging(db, Path(args.dir), actor=args.actor)
    finally:
        db.close()
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
