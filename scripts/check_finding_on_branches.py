#!/usr/bin/env python3
"""Check whether a finding made on one branch still exists on others.

A detection battle scans ``master`` HEAD, but a submission (e.g. the
OpenHarmony security reward program) only counts defects reachable on
supported Release/LTS versions.  This is the fixed alignment step of the
battle workflow: for every named ref it classifies the audited file as

  PRESENT-UNCHANGED  the file blob is identical, so the code-level
                     finding carries over as-is;
  CHANGED            the ref diverged; the unified diff is printed for
                     a human to decide whether the defect survived;
  ABSENT             the file does not exist on that ref (not affected);
  ERROR              ref does not resolve in this clone.

Read-only by construction (rev-parse / cat-file / diff only).  Blobless
clones fetch blobs lazily, so run a fetch first when diffs report
missing objects.

Exit code: 0 when every ref is PRESENT-UNCHANGED, 1 when any ref needs
human review (CHANGED/ABSENT/ERROR), 2 on usage errors.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

_MAX_DIFF_LINES = 200


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def classify(repo: Path, file: str, ref: str, base: str) -> tuple[str, str]:
    """Classify ``file`` on ``ref`` relative to ``base``."""

    if _git(repo, "rev-parse", "--verify", "--quiet", ref).returncode != 0:
        return "ERROR", f"ref {ref!r} does not resolve in this clone"
    cat = _git(repo, "cat-file", "-e", f"{ref}:{file}")
    if cat.returncode != 0:
        return "ABSENT", f"{ref}:{file} does not exist"
    diff = _git(repo, "diff", f"{base}..{ref}", "--", file)
    if diff.returncode != 0:
        detail = (diff.stderr or "diff failed").strip()
        return "ERROR", f"{detail} (fetch blobs first on blobless clones?)"
    if not diff.stdout.strip():
        return "PRESENT-UNCHANGED", ""
    lines = diff.stdout.splitlines()
    shown = "\n".join(lines[:_MAX_DIFF_LINES])
    if len(lines) > _MAX_DIFF_LINES:
        shown += f"\n... ({len(lines) - _MAX_DIFF_LINES} more lines)"
    return "CHANGED", shown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
    )
    parser.add_argument("--repo", required=True, help="repository checkout")
    parser.add_argument(
        "--file", required=True, help="audited file path relative to repo root"
    )
    parser.add_argument(
        "--ref",
        action="append",
        required=True,
        dest="refs",
        help="branch/tag to check (repeatable)",
    )
    parser.add_argument(
        "--base", default="HEAD", help="ref the finding was made on"
    )
    args = parser.parse_args(argv)

    repo = Path(args.repo)
    if not repo.is_dir():
        print(f"repository not found: {repo}", file=sys.stderr)
        return 2

    needs_review = False
    for ref in args.refs:
        status, detail = classify(repo, args.file, ref, args.base)
        print(f"[{status}] {ref}")
        if detail:
            print(detail)
        if status != "PRESENT-UNCHANGED":
            needs_review = True
    return 1 if needs_review else 0


if __name__ == "__main__":
    raise SystemExit(main())
