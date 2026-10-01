"""Human expert review entry for LIMA v4 (IP-0043, Issue #257).

This module reuses the frozen :class:`ExpertTimingSession` unchanged: the
five-key sidecar protocol (``schema_version``/``run_spec_digest``/
``reviewer_digest``/``active_time_ms``/``events``), the digest-only
reviewer identity, the event state machine and the monotonic clock guard
are all frozen faces, and real humans drive start/pause/resume/finish with
live ``time.perf_counter_ns()`` reads (the thin CLI
``scripts/run_expert_review.py`` is that one runnable command).  Agents
never start or finish a session, never fill a verdict and never record an
event on behalf of a human.

The verdict vocabulary is a frozen closed set (``agree``/``disagree``/
``partially-agree``/``needs-more-evidence``) with free-text notes.  The
verdict goes into an independently versioned receipt (schema v1, separate
from the sidecar): the verdict itself, the review-set digest, the source
binding triple (run spec digest, aggregate digest, findings digest), the
coverage and unreviewed declarations, the reviewer digest, the active-time
back reference, the event digest and the sidecar digest.

Typed fail-closed validation (own independent error family, the
``B1SourceError`` precedent): an invalid review-set document, an illegal /
non-monotonic / repeated / unterminated event sequence, an off-vocabulary
verdict, a sidecar bound to a different review set (cross-review-set
rejection), a reviewer id that disagrees with the sidecar's reviewer
digest, a malformed receipt, and a duplicated event set or sidecar being
bound to a second result (one event set can never be copied onto many
results to multiply the recorded time) each terminate with their own code.

The raw reviewer identity never persists: only its SHA-256 digest appears
in any produced byte.  Synthetic (test) events are explicitly marked and
isolated to temp directories; without human return
:func:`summarize_review_receipts` reports ``sessions=0`` and unavailable
active time honestly.  The module is a pure offline stdlib-only library:
deterministic, secretless, no network, no ambient reads.
"""

import enum
import hashlib
import json
import pathlib
import typing

from benchmarks.v4.baseline.collect import BaselineCollectionError
from benchmarks.v4.baseline.expert_timing import ExpertTimingSession
from benchmarks.v4.baseline.run import write_exclusive
from lima.contracts.codec import canonical_encode, compute_content_digest

__all__ = [
    "EXPERT_REVIEW_VERDICTS",
    "ExpertReviewError",
    "ExpertReviewErrorCode",
    "build_review_receipt",
    "load_review_set",
    "summarize_review_receipts",
    "validate_timing_events",
    "write_review_receipt",
]

#: The frozen verdict vocabulary (Packet R4: four values, closed).
EXPERT_REVIEW_VERDICTS: typing.Final[frozenset[str]] = frozenset(
    {"agree", "disagree", "partially-agree", "needs-more-evidence"}
)

#: The frozen timing event names (the frozen session state machine).
_TIMING_EVENT_NAMES: typing.Final[frozenset[str]] = frozenset(
    {"start", "pause", "resume", "finish"}
)
_TIMING_EVENT_KEYS: typing.Final[frozenset[str]] = frozenset({"event", "time_ns"})

#: The frozen five-key sidecar protocol (expert_timing.py L129-142; guard).
_SIDECAR_KEYS: typing.Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "run_spec_digest",
        "reviewer_digest",
        "active_time_ms",
        "events",
    }
)

#: The frozen review-set document key set (closed, schema v1).
_REVIEW_SET_KEYS: typing.Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "review_set_id",
        "run_spec_digest",
        "aggregate_sha256",
        "findings_digest",
        "findings",
        "coverage",
        "unreviewed",
        "representative_result_sha256",
    }
)
_REVIEW_SET_DIGEST_FIELDS: typing.Final[tuple[str, ...]] = (
    "run_spec_digest",
    "aggregate_sha256",
    "findings_digest",
    "representative_result_sha256",
)

#: The frozen receipt key set (closed, schema v1; separate from sidecar).
_RECEIPT_KEYS: typing.Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "synthetic",
        "verdict",
        "notes",
        "review_set_digest",
        "run_spec_digest",
        "aggregate_sha256",
        "findings_digest",
        "coverage",
        "unreviewed",
        "reviewer_digest",
        "active_time_ms",
        "events_digest",
        "sidecar_sha256",
    }
)
_RECEIPT_DIGEST_FIELDS: typing.Final[tuple[str, ...]] = (
    "review_set_digest",
    "run_spec_digest",
    "aggregate_sha256",
    "findings_digest",
    "reviewer_digest",
    "events_digest",
    "sidecar_sha256",
)

#: The frozen receipt file-name family (independently versioned).
_RECEIPT_NAME_PREFIX: typing.Final[str] = "expert-review-receipt-v1-"

_HEX64_ALPHABET: typing.Final[frozenset[str]] = frozenset("0123456789abcdef")


class ExpertReviewErrorCode(str, enum.Enum):  # noqa: UP042 -- frozen by IP-0043 Packet
    """Frozen wire values for every deterministic expert-review failure."""

    REVIEW_SET_INVALID = "REVIEW_SET_INVALID"
    TIMING_SEQUENCE_INVALID = "TIMING_SEQUENCE_INVALID"
    VERDICT_VOCABULARY_INVALID = "VERDICT_VOCABULARY_INVALID"
    VERDICT_REVIEW_SET_MISMATCH = "VERDICT_REVIEW_SET_MISMATCH"
    EVENT_DUPLICATE = "EVENT_DUPLICATE"
    RECEIPT_INVALID = "RECEIPT_INVALID"

    def __str__(self) -> str:
        """Render the bare frozen wire value (the str-mixin face)."""
        return self.value


_STABLE_MESSAGES: dict[ExpertReviewErrorCode, str] = {
    ExpertReviewErrorCode.REVIEW_SET_INVALID: (
        "The expert review set document is invalid."
    ),
    ExpertReviewErrorCode.TIMING_SEQUENCE_INVALID: (
        "The expert timing event sequence is invalid."
    ),
    ExpertReviewErrorCode.VERDICT_VOCABULARY_INVALID: (
        "The expert review verdict is outside the frozen vocabulary."
    ),
    ExpertReviewErrorCode.VERDICT_REVIEW_SET_MISMATCH: (
        "The verdict sidecar is bound to a different review set."
    ),
    ExpertReviewErrorCode.EVENT_DUPLICATE: (
        "The timing event set is already bound to a receipt."
    ),
    ExpertReviewErrorCode.RECEIPT_INVALID: (
        "The expert review receipt is invalid."
    ),
}


class ExpertReviewError(ValueError):
    """Deterministic expert-review violation with a stable code and message.

    The shape aligns with the frozen ``B1SourceError`` precedent while
    remaining an independent class.  The rendered message is exactly the
    catalog entry above; raw payloads, secrets, reviewer identities, digest
    values and host paths are never embedded.
    """

    code: ExpertReviewErrorCode
    field_path: str

    def __init__(self, code: ExpertReviewErrorCode, field_path: str = "") -> None:
        if not isinstance(code, ExpertReviewErrorCode):
            raise TypeError("code must be a ExpertReviewErrorCode member")
        if not isinstance(field_path, str):
            raise TypeError("field_path must be a str")
        self.code = code
        self.field_path = field_path
        super().__init__(_STABLE_MESSAGES[code])


def _is_hex64(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX64_ALPHABET for character in value)
    )


def _validate_review_set(document: object) -> dict[str, object]:
    """Validate one schema-v1 review-set document, fail-closed."""
    if not isinstance(document, dict) or set(document) != _REVIEW_SET_KEYS:
        raise ExpertReviewError(ExpertReviewErrorCode.REVIEW_SET_INVALID, "$")
    if document["schema_version"] != 1:
        raise ExpertReviewError(
            ExpertReviewErrorCode.REVIEW_SET_INVALID, "$.schema_version"
        )
    if not isinstance(document["review_set_id"], str) or not document["review_set_id"]:
        raise ExpertReviewError(
            ExpertReviewErrorCode.REVIEW_SET_INVALID, "$.review_set_id"
        )
    for field in _REVIEW_SET_DIGEST_FIELDS:
        if not _is_hex64(document[field]):
            raise ExpertReviewError(
                ExpertReviewErrorCode.REVIEW_SET_INVALID, f"$.{field}"
            )
    findings = document["findings"]
    if not isinstance(findings, list) or any(
        not isinstance(finding, dict) for finding in findings
    ):
        raise ExpertReviewError(ExpertReviewErrorCode.REVIEW_SET_INVALID, "$.findings")
    for field in ("coverage", "unreviewed"):
        if not isinstance(document[field], str) or not document[field]:
            raise ExpertReviewError(
                ExpertReviewErrorCode.REVIEW_SET_INVALID, f"$.{field}"
            )
    return document


def load_review_set(path: str | pathlib.Path) -> dict[str, object]:
    """Load and validate one review-set document from a UTF-8 JSON file.

    An unreadable file, a non-UTF-8 byte stream, invalid JSON or any
    schema-v1 contract violation fails closed with ``REVIEW_SET_INVALID``.
    """
    try:
        payload = pathlib.Path(path).read_bytes()
        document = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ExpertReviewError(
            ExpertReviewErrorCode.REVIEW_SET_INVALID, "$.review_set"
        ) from exc
    return _validate_review_set(document)


def validate_timing_events(events: object) -> int:
    """Validate one timing event sequence and recompute its active time.

    The frozen :class:`ExpertTimingSession` engine is replayed verbatim
    (never loosened): shape faces, the state machine, the exact-int clock
    reads and the monotonic guard all keep their frozen rejection behavior,
    mapped onto ``TIMING_SEQUENCE_INVALID``.  A legal sequence must be
    non-empty and terminate with ``finish``; the return value is the total
    closed active time in whole milliseconds, independently recomputed by
    the frozen engine.
    """
    if not isinstance(events, list) or not events:
        raise ExpertReviewError(ExpertReviewErrorCode.TIMING_SEQUENCE_INVALID, "$.events")
    session = ExpertTimingSession("expert-review-timing-validator")
    for index, event in enumerate(events):
        prefix = f"$.events[{index}]"
        if not isinstance(event, dict) or set(event) != _TIMING_EVENT_KEYS:
            raise ExpertReviewError(ExpertReviewErrorCode.TIMING_SEQUENCE_INVALID, prefix)
        name = event["event"]
        if name not in _TIMING_EVENT_NAMES:
            raise ExpertReviewError(ExpertReviewErrorCode.TIMING_SEQUENCE_INVALID, prefix)
        try:
            getattr(session, typing.cast(str, name))(event["time_ns"])
        except BaselineCollectionError as exc:
            raise ExpertReviewError(
                ExpertReviewErrorCode.TIMING_SEQUENCE_INVALID, prefix
            ) from exc
    if events[-1]["event"] != "finish":
        raise ExpertReviewError(ExpertReviewErrorCode.TIMING_SEQUENCE_INVALID, "$.events")
    return session.active_time_ms()


def build_review_receipt(
    *,
    review_set: object,
    reviewer_id: str,
    sidecar_bytes: bytes,
    verdict: str,
    notes: str = "",
    synthetic: bool = False,
) -> dict[str, object]:
    """Validate every input face and assemble one schema-v1 receipt.

    Gate order: the review-set document; the verdict vocabulary; the
    reviewer id, notes and synthetic flag shapes; the sidecar bytes parse
    and carry the frozen five-key protocol; the sidecar's run identity
    matches this review set (cross-review-set rejection); the sidecar's
    event sequence validates and its declared active time equals the
    independent recomputation; and the reviewer id digest equals the
    sidecar's reviewer digest (identity consistency).  The returned
    receipt is a fresh plain mapping; the raw reviewer id never appears.
    """
    document = _validate_review_set(review_set)
    if not isinstance(verdict, str) or verdict not in EXPERT_REVIEW_VERDICTS:
        raise ExpertReviewError(
            ExpertReviewErrorCode.VERDICT_VOCABULARY_INVALID, "$.verdict"
        )
    if not isinstance(reviewer_id, str) or not reviewer_id:
        raise ExpertReviewError(ExpertReviewErrorCode.RECEIPT_INVALID, "$.reviewer_id")
    if not isinstance(notes, str):
        raise ExpertReviewError(ExpertReviewErrorCode.RECEIPT_INVALID, "$.notes")
    if type(synthetic) is not bool:
        raise ExpertReviewError(ExpertReviewErrorCode.RECEIPT_INVALID, "$.synthetic")
    if not isinstance(sidecar_bytes, (bytes, bytearray)):
        raise ExpertReviewError(ExpertReviewErrorCode.RECEIPT_INVALID, "$.sidecar_bytes")
    try:
        sidecar = json.loads(bytes(sidecar_bytes).decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ExpertReviewError(
            ExpertReviewErrorCode.RECEIPT_INVALID, "$.sidecar_bytes"
        ) from exc
    if (
        not isinstance(sidecar, dict)
        or set(sidecar) != _SIDECAR_KEYS
        or sidecar["schema_version"] != 1
    ):
        raise ExpertReviewError(ExpertReviewErrorCode.RECEIPT_INVALID, "$.sidecar")
    if sidecar["run_spec_digest"] != document["run_spec_digest"]:
        raise ExpertReviewError(
            ExpertReviewErrorCode.VERDICT_REVIEW_SET_MISMATCH,
            "$.sidecar.run_spec_digest",
        )
    active_time_ms = validate_timing_events(sidecar["events"])
    if sidecar["active_time_ms"] != active_time_ms or type(
        sidecar["active_time_ms"]
    ) is not int:
        raise ExpertReviewError(
            ExpertReviewErrorCode.RECEIPT_INVALID, "$.sidecar.active_time_ms"
        )
    reviewer_digest = hashlib.sha256(reviewer_id.encode("utf-8")).hexdigest()
    if sidecar["reviewer_digest"] != reviewer_digest:
        raise ExpertReviewError(ExpertReviewErrorCode.RECEIPT_INVALID, "$.reviewer_digest")
    return {
        "schema_version": 1,
        "synthetic": synthetic,
        "verdict": verdict,
        "notes": notes,
        "review_set_digest": compute_content_digest(document),
        "run_spec_digest": document["run_spec_digest"],
        "aggregate_sha256": document["aggregate_sha256"],
        "findings_digest": document["findings_digest"],
        "coverage": document["coverage"],
        "unreviewed": document["unreviewed"],
        "reviewer_digest": reviewer_digest,
        "active_time_ms": active_time_ms,
        "events_digest": compute_content_digest(sidecar["events"]),
        "sidecar_sha256": compute_content_digest(bytes(sidecar_bytes)),
    }


def _validate_receipt(receipt: object) -> dict[str, object]:
    """Validate one receipt mapping, fail-closed with ``RECEIPT_INVALID``."""
    if not isinstance(receipt, dict) or set(receipt) != _RECEIPT_KEYS:
        raise ExpertReviewError(ExpertReviewErrorCode.RECEIPT_INVALID, "$")
    if receipt["schema_version"] != 1 or type(receipt["synthetic"]) is not bool:
        raise ExpertReviewError(ExpertReviewErrorCode.RECEIPT_INVALID, "$.schema_version")
    if receipt["verdict"] not in EXPERT_REVIEW_VERDICTS:
        raise ExpertReviewError(
            ExpertReviewErrorCode.VERDICT_VOCABULARY_INVALID, "$.verdict"
        )
    if not isinstance(receipt["notes"], str):
        raise ExpertReviewError(ExpertReviewErrorCode.RECEIPT_INVALID, "$.notes")
    for field in _RECEIPT_DIGEST_FIELDS:
        if not _is_hex64(receipt[field]):
            raise ExpertReviewError(
                ExpertReviewErrorCode.RECEIPT_INVALID, f"$.{field}"
            )
    if type(receipt["active_time_ms"]) is not int or receipt["active_time_ms"] < 0:
        raise ExpertReviewError(
            ExpertReviewErrorCode.RECEIPT_INVALID, "$.active_time_ms"
        )
    for field in ("coverage", "unreviewed"):
        if not isinstance(receipt[field], str) or not receipt[field]:
            raise ExpertReviewError(
                ExpertReviewErrorCode.RECEIPT_INVALID, f"$.{field}"
            )
    return receipt


def _load_receipt_documents(
    directory: pathlib.Path,
) -> list[tuple[pathlib.Path, dict[str, object]]]:
    """Load and validate every receipt document already in the directory."""
    try:
        paths = sorted(directory.glob(f"{_RECEIPT_NAME_PREFIX}*.json"))
    except OSError as exc:
        raise ExpertReviewError(
            ExpertReviewErrorCode.RECEIPT_INVALID, "$.output_dir"
        ) from exc
    loaded: list[tuple[pathlib.Path, dict[str, object]]] = []
    for index, path in enumerate(paths):
        try:
            document = json.loads(path.read_bytes().decode("utf-8"))
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            raise ExpertReviewError(
                ExpertReviewErrorCode.RECEIPT_INVALID, f"$.receipts[{index}]"
            ) from exc
        loaded.append((path, _validate_receipt(document)))
    return loaded


def write_review_receipt(
    receipt: object, output_dir: str | pathlib.Path
) -> pathlib.Path:
    """Validate and persist one receipt exclusively, with event dedup.

    The receipt mapping must carry the frozen closed key set.  The event
    set is the uniqueness object: a receipt whose ``events_digest`` is
    already bound inside this output directory is rejected with
    ``EVENT_DUPLICATE`` -- re-submitting the same event set for the same
    review set, binding the same events under a second review set, or
    copying one sidecar onto many results can never multiply the recorded
    time.  Writing a receipt never writes a sidecar file; the five-key
    sidecar protocol stays with the frozen timing session.
    """
    validated = _validate_receipt(receipt)
    directory = pathlib.Path(output_dir)
    if not directory.is_dir():
        raise ExpertReviewError(ExpertReviewErrorCode.RECEIPT_INVALID, "$.output_dir")
    existing = _load_receipt_documents(directory)
    seen = {document["events_digest"] for _, document in existing}
    if validated["events_digest"] in seen:
        raise ExpertReviewError(ExpertReviewErrorCode.EVENT_DUPLICATE, "$.events_digest")
    sequence = len(existing) + 1
    path = directory / f"{_RECEIPT_NAME_PREFIX}{sequence:02d}.json"
    write_exclusive(path, canonical_encode(validated))
    return path


def summarize_review_receipts(output_dir: str | pathlib.Path) -> dict[str, object]:
    """Summarize one receipt directory honestly.

    Only non-synthetic receipts count as human sessions; synthetic
    receipts count separately and never contribute active time, reviewer
    digests or verdict counts.  With no human return the summary reports
    ``sessions=0`` and unavailable total active time (``None``), never a
    fabricated zero.  Malformed receipt files fail closed with
    ``RECEIPT_INVALID``.
    """
    directory = pathlib.Path(output_dir)
    existing = _load_receipt_documents(directory) if directory.is_dir() else []
    sessions = 0
    synthetic_sessions = 0
    active_total = 0
    reviewer_digests: set[str] = set()
    verdict_counts: dict[str, int] = {}
    for _, document in existing:
        if document["synthetic"]:
            synthetic_sessions += 1
            continue
        sessions += 1
        active_total += typing.cast(int, document["active_time_ms"])
        reviewer_digests.add(typing.cast(str, document["reviewer_digest"]))
        verdict = typing.cast(str, document["verdict"])
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
    return {
        "schema_version": 1,
        "sessions": sessions,
        "synthetic_sessions": synthetic_sessions,
        "active_time_ms_total": active_total if sessions else None,
        "reviewer_digests": sorted(reviewer_digests),
        "verdict_counts": dict(sorted(verdict_counts.items())),
    }
