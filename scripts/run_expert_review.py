"""Thin interactive CLI for the human expert review entry (IP-0043).

This is the one runnable command of the LIMA human-review entry: it loads
a review-set document, drives one frozen ``ExpertTimingSession`` from real
human key presses (start/pause/resume/finish with live
``time.perf_counter_ns()`` reads -- nothing is pre-filled and no agent
ever records an event on behalf of a human), builds the independently
versioned verdict receipt through the frozen module, writes it into the
output directory and prints the honest session summary.  Reviewer
identity is persisted only as its SHA-256 digest.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.v4.baseline.expert_review import (  # noqa: E402
    EXPERT_REVIEW_VERDICTS,
    ExpertReviewError,
    build_review_receipt,
    load_review_set,
    summarize_review_receipts,
    write_review_receipt,
)
from benchmarks.v4.baseline.expert_timing import ExpertTimingSession  # noqa: E402

_COMMANDS = ("start", "pause", "resume", "finish")


def build_parser() -> argparse.ArgumentParser:
    """The frozen flag surface of the expert review CLI."""
    parser = argparse.ArgumentParser(
        prog="run_expert_review.py",
        description=(
            "Human expert review entry: one timing session driven by real "
            "key presses plus a frozen-vocabulary verdict receipt."
        ),
    )
    parser.add_argument(
        "--review-set", required=True, help="path to the review-set JSON document"
    )
    parser.add_argument(
        "--reviewer-id",
        required=True,
        help="human reviewer id (persisted only as its SHA-256 digest)",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="directory that receives the versioned receipt document",
    )
    parser.add_argument(
        "--verdict",
        required=True,
        choices=sorted(EXPERT_REVIEW_VERDICTS),
        help="frozen verdict vocabulary value",
    )
    parser.add_argument(
        "--notes", default="", help="free-text verdict notes (default empty)"
    )
    parser.add_argument(
        "--synthetic",
        action="store_true",
        help="mark this session as synthetic (isolated test events only)",
    )
    return parser


def _run_timing_session(session: ExpertTimingSession) -> None:
    """Drive the frozen session from real human key presses."""
    print("Review timing session: type start / pause / resume / finish.")
    print("The clock is the live monotonic nanosecond clock; nothing is pre-filled.")
    while True:
        try:
            command = input("review> ").strip().lower()
        except EOFError:
            raise SystemExit("review interrupted; no receipt was written") from None
        if command not in _COMMANDS:
            if command in ("quit", "abort"):
                raise SystemExit("review aborted; no receipt was written")
            print("unknown command; expected start / pause / resume / finish")
            continue
        getattr(session, command)(time.perf_counter_ns())
        print(f"{command} recorded")
        if command == "finish":
            return


def main(argv: list[str] | None = None) -> int:
    """Load the review set, run one human timing session, write the receipt."""
    args = build_parser().parse_args(argv)
    review_set = load_review_set(args.review_set)
    print(f"review set loaded: {review_set['review_set_id']}")
    print(f"binding: run_spec_digest={review_set['run_spec_digest']}")
    session = ExpertTimingSession(args.reviewer_id)
    _run_timing_session(session)
    sidecar_bytes = session.sidecar_bytes(review_set["run_spec_digest"])
    receipt = build_review_receipt(
        review_set=review_set,
        reviewer_id=args.reviewer_id,
        sidecar_bytes=sidecar_bytes,
        verdict=args.verdict,
        notes=args.notes,
        synthetic=args.synthetic,
    )
    path = write_review_receipt(receipt, args.output_dir)
    print(f"receipt written: {path}")
    print(f"reviewer_digest: {receipt['reviewer_digest']}")
    print(f"active_time_ms: {receipt['active_time_ms']}")
    summary = summarize_review_receipts(args.output_dir)
    print(f"sessions: {summary['sessions']}")
    print(f"synthetic_sessions: {summary['synthetic_sessions']}")
    print(f"active_time_ms_total: {summary['active_time_ms_total']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ExpertReviewError as error:
        print(f"expert review rejected: {error}", file=sys.stderr)
        raise SystemExit(1) from error
