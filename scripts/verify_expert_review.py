"""Read-only verification command for expert-review evidence pairs.

One command, two modes:

- Default (verification): independently verify every evidence pair in a
  sessions directory -- each verdict receipt against its content-addressed
  timing sidecar, replaying the frozen event state machine, recomputing
  active time and every digest from the persisted bytes, and (with
  ``--review-set``) cross-checking the full source binding.  Any single
  mismatch fails closed; the printed summary counts verified human
  sessions separately from verified synthetic sessions and reports
  incomplete residue honestly (a sidecar without its receipt is an
  unfinished session, never a human minute).
- ``--derive-report`` (explicit derivation): additionally rebuild the
  sealed LF baseline inputs read-only (run files -> frozen summary face;
  sealed tarball -> rematerialize + rescan through the frozen production
  helpers, with the rebuilt scanner digest required to equal the sealed
  binding), verify the pairs, exclude synthetic sessions, and write a
  derived report with only verified human minutes into a brand-new
  out-of-repo directory.  The sealed report is hashed before and after;
  it is never modified.  A derivation record documents every digest.

Everything here is offline and read-only with respect to sealed inputs.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.v4.baseline.expert_review_pair import (  # noqa: E402
    ExpertReviewPairError,
    derive_expert_review_report,
    verify_session_directory,
)


def build_parser() -> argparse.ArgumentParser:
    """The frozen flag surface of the verification CLI."""
    parser = argparse.ArgumentParser(
        prog="verify_expert_review.py",
        description=(
            "Read-only verification of expert-review evidence pairs, plus "
            "an explicit derived-report flow that excludes synthetic pairs."
        ),
    )
    parser.add_argument(
        "--sessions-dir",
        required=True,
        help="directory holding the evidence pairs to verify",
    )
    parser.add_argument(
        "--review-set",
        default=None,
        help="optional review-set document; enables full source-binding checks",
    )
    parser.add_argument(
        "--derive-report",
        action="store_true",
        help=(
            "additionally derive a report with verified human minutes into "
            "--output-dir (requires --source-dir, --archive and --review-set)"
        ),
    )
    parser.add_argument(
        "--source-dir",
        default=None,
        help="sealed baseline output directory (read-only; LF R2 layout)",
    )
    parser.add_argument(
        "--archive",
        default=None,
        help="path to the sealed repository tarball (read-only)",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="brand-new directory for the derived report and derivation record",
    )
    parser.add_argument(
        "--json", action="store_true", help="print the JSON record verbatim"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Verify evidence pairs (and optionally derive a report), read-only."""
    args = build_parser().parse_args(argv)
    if args.derive_report:
        missing = [
            name
            for name in ("review_set", "source_dir", "archive", "output_dir")
            if getattr(args, name) is None
        ]
        if missing:
            print(
                f"--derive-report requires: {', '.join(missing)}", file=sys.stderr
            )
            return 2
        record = derive_expert_review_report(
            source_dir=args.source_dir,
            sessions_dir=args.sessions_dir,
            review_set_path=args.review_set,
            archive_path=args.archive,
            output_dir=args.output_dir,
        )
        if args.json:
            print(json.dumps(record, ensure_ascii=False, indent=2))
        else:
            sessions = record["sessions"]
            print(f"derived report: {record['derived_report_path']}")
            print(f"derived report sha256: {record['derived_report_sha256']}")
            print(f"rebuilt scanner digest: {record['rebuilt_scanner_payload_sha256']}")
            print(f"sealed scanner digest: {record['sealed_scanner_payload_sha256']}")
            print(f"human sessions: {sessions['human_sessions']}")
            print(f"synthetic sessions: {sessions['synthetic_sessions']}")
            print(
                "human active_time_ms_total: "
                f"{sessions['human_active_time_ms_total']}"
            )
            print(f"human sidecars entering the report: {record['human_sidecar_count']}")
            print(
                "sealed report sha256 before/after: "
                f"{record['sealed_report_sha256_before']} / "
                f"{record['sealed_report_sha256_after']}"
            )
        return 0
    record = verify_session_directory(
        args.sessions_dir,
        review_set_path=args.review_set,
    )
    if args.json:
        print(json.dumps(record, ensure_ascii=False, indent=2))
        return 0
    for pair in record["pairs"]:
        kind = "synthetic" if pair["synthetic"] else "human"
        print(
            f"verified pair ({kind}): {pair['receipt']} + {pair['sidecar']} "
            f"active_time_ms={pair['active_time_ms']}"
        )
    for name in record["incomplete_sidecars"]:
        print(f"incomplete residue (no receipt): {name}")
    print(f"human_sessions: {record['human_sessions']}")
    print(f"synthetic_sessions: {record['synthetic_sessions']}")
    print(f"human_active_time_ms_total: {record['human_active_time_ms_total']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ExpertReviewPairError as error:
        print(f"evidence pair verification rejected: {error}", file=sys.stderr)
        raise SystemExit(1) from error
