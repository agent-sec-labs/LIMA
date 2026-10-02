"""Interactive CLI for the human expert review entry (IP-0043 + the
2026-10-02 evidence-pair follow-up).

This is the one runnable command of the LIMA human-review entry.  It gates
every deterministic failure **before** the first key press (the frozen
review-set loader, the optional pinned review-set file digest, the
canonical dry run of the review-set and its findings, and the output
target with its explicit create-as-new-leaf rule plus a real write probe),
then drives one frozen ``ExpertTimingSession`` from real human key presses
(start/pause/resume/finish with live ``time.perf_counter_ns()`` reads --
nothing is pre-filled and no agent ever records an event on behalf of a
human).  After ``finish`` the raw canonical five-key sidecar is persisted
first (events survive everything else), and only then is the verdict
confirmed: a verdict typed at start-up through ``--verdict`` is a
suggestion only and is never accepted as the post-review confirmation --
the human must type the verdict again once the review is actually over.
The independently versioned verdict receipt completes the evidence pair,
both files are read back immediately, and the honest session summary is
printed.  Reviewer identity is persisted only as its SHA-256 digest.
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
)
from benchmarks.v4.baseline.expert_review_pair import (  # noqa: E402
    ExpertReviewPairError,
    attach_verdict_receipt,
    persist_timing_sidecar,
    prepare_session,
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
        help="directory that receives the evidence pair (sidecar + receipt)",
    )
    parser.add_argument(
        "--verdict",
        choices=sorted(EXPERT_REVIEW_VERDICTS),
        help=(
            "compatibility pre-fill only: it is shown as a suggestion and "
            "is never accepted as the post-review verdict confirmation"
        ),
    )
    parser.add_argument(
        "--notes", default="", help="free-text verdict notes (default empty)"
    )
    parser.add_argument(
        "--synthetic",
        action="store_true",
        help="mark this session as synthetic (isolated test events only)",
    )
    parser.add_argument(
        "--review-set-sha256",
        default=None,
        help=(
            "optional pinned SHA-256 of the review-set file; a mismatch "
            "is rejected before any human timing starts"
        ),
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
            raise SystemExit(
                "review interrupted; no evidence pair was completed"
            ) from None
        if command not in _COMMANDS:
            if command in ("quit", "abort"):
                raise SystemExit("review aborted; no evidence pair was completed")
            print("unknown command; expected start / pause / resume / finish")
            continue
        getattr(session, command)(time.perf_counter_ns())
        print(f"{command} recorded")
        if command == "finish":
            return


def _confirm_verdict(prefill: str | None) -> str | None:
    """Collect the authoritative post-review verdict from the human.

    The pre-start ``--verdict`` value is only echoed as a suggestion; the
    confirmation must be typed after the review has finished.  ``None``
    means the verdict was not confirmed and the session stays incomplete.
    """
    suggestion = (
        f" (suggestion from --verdict: {prefill}; typing it again confirms it)"
        if prefill
        else ""
    )
    print(
        "Confirm the verdict for THIS completed review"
        f"{suggestion}. Choices: {', '.join(sorted(EXPERT_REVIEW_VERDICTS))}."
    )
    while True:
        try:
            answer = input("verdict> ").strip()
        except EOFError:
            return None
        if answer in ("quit", "abort"):
            return None
        if answer in EXPERT_REVIEW_VERDICTS:
            return answer
        print(
            "unknown verdict; expected one of: "
            f"{', '.join(sorted(EXPERT_REVIEW_VERDICTS))}"
        )


def _confirm_notes(prefill: str) -> str:
    """Collect free-text notes; an empty line keeps the --notes value."""
    print(f"notes for the receipt (empty line keeps --notes: {prefill!r}):")
    try:
        answer = input("notes> ")
    except EOFError:
        return prefill
    return answer if answer.strip() else prefill


def main(argv: list[str] | None = None) -> int:
    """Gate, run one human timing session, persist the evidence pair."""
    args = build_parser().parse_args(argv)
    prepared = prepare_session(
        args.review_set,
        args.output_dir,
        review_set_sha256=args.review_set_sha256,
    )
    review_set = prepared.review_set
    print(f"review set loaded: {review_set['review_set_id']}")
    print(f"binding: run_spec_digest={review_set['run_spec_digest']}")
    print(f"output directory ready: {prepared.output_dir}")
    session = ExpertTimingSession(args.reviewer_id)
    _run_timing_session(session)
    sidecar_bytes = session.sidecar_bytes(review_set["run_spec_digest"])
    sidecar_path = persist_timing_sidecar(sidecar_bytes, args.output_dir)
    print(f"timing sidecar saved: {sidecar_path}")
    print(
        "the pair is INCOMPLETE until the verdict receipt lands; "
        "an unconfirmed verdict keeps this sidecar as unfinished residue"
    )
    verdict = _confirm_verdict(args.verdict)
    if verdict is None:
        raise SystemExit(
            "verdict not confirmed; the sidecar stays as incomplete "
            "residue and no successful session is recorded"
        )
    notes = _confirm_notes(args.notes)
    receipt = build_review_receipt(
        review_set=review_set,
        reviewer_id=args.reviewer_id,
        sidecar_bytes=sidecar_bytes,
        verdict=verdict,
        notes=notes,
        synthetic=args.synthetic,
    )
    pair = attach_verdict_receipt(receipt, args.output_dir)
    print(f"verdict receipt written: {pair.receipt_path}")
    print(f"evidence pair complete: {pair.sidecar_path.name} + {pair.receipt_path.name}")
    print(f"reviewer_digest: {receipt['reviewer_digest']}")
    print(f"active_time_ms: {receipt['active_time_ms']}")
    summary = summarize_review_receipts(args.output_dir)
    print(f"sessions: {summary['sessions']}")
    print(f"synthetic_sessions: {summary['synthetic_sessions']}")
    print(f"active_time_ms_total: {summary['active_time_ms_total']}")
    if args.synthetic:
        print(
            "synthetic sessions never count as human sessions in any "
            "formal summary or report input"
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ExpertReviewError as error:
        print(f"expert review rejected: {error}", file=sys.stderr)
        raise SystemExit(1) from error
    except ExpertReviewPairError as error:
        print(f"expert review evidence pair rejected: {error}", file=sys.stderr)
        raise SystemExit(1) from error
