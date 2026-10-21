"""Summarize one evidence bundle offline without modifying it (Issue #293).

Usage: python scripts/summarize_competition_coverage.py --bundle DIR --format json
       python scripts/summarize_competition_coverage.py --bundle DIR --format markdown

Only summary.json and optional {vulnerable,fixed}/platform.json are read.
Exit 0 means parsing succeeded, even when validation_status is failed.
Exit 2 means invalid arguments, damaged input, or conflicting duplicated fields.
See docs/competition/tools/coverage.md for the schema and synthetic examples.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lima.competition_coverage import main  # noqa: E402


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    raise SystemExit(main())
