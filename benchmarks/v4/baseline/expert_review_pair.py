"""Evidence-pair persistence and independent verification for the human
expert review entry (the 2026-10-02 Maintainer-authorized follow-up to
IP-0043).

The IP-0043 delivery persisted only the verdict receipt: the canonical
timing sidecar was assembled in memory and dropped, so one finished human
session left a single JSON file and the promised "sidecar + receipt" return
pair could not actually be produced.  This module fixes exactly that gap
without touching any frozen face:

- The frozen five-key sidecar protocol, the frozen receipt schema, the
  frozen event state machine and the frozen ``write_review_receipt``
  receipt-only persistence are reused unchanged (``expert_timing`` /
  ``expert_review``).  Nothing here re-implements or loosens them.
- One completed session persists an **evidence pair**: the raw canonical
  timing sidecar file plus the independently versioned verdict receipt,
  bound by content digests, never by directory position or file order.
  The sidecar file name is content-addressed
  (``expert-timing-sidecar-v1-{sidecar_sha256[:16]}.json``) and the
  verification requires the name prefix, the file bytes and the receipt's
  ``sidecar_sha256`` to agree simultaneously -- a pair is never established
  by guessing a directory or picking the first JSON file.
- Write order is raw-events-first: the sidecar lands before the receipt,
  and the receipt is the completion voucher of the pair.  A sidecar without
  its receipt (or a receipt without its sidecar) is explicitly **incomplete
  residue** -- never a successful human session, never synthesized into
  one, never counted.  All writes are exclusive and never overwrite; an
  identical pre-existing sidecar (same content-addressed name, same bytes)
  is the only reuse allowed.
- Everything that can fail without human time fails **before the first key
  press**: the review-set document (frozen loader), the optional pinned
  review-set file digest (tamper rejection), the canonical dry run of the
  review-set and its findings (the DR-IP-0043-CFINAL-FLOAT fail-early
  precheck -- a float-bearing or otherwise non-canonical review-set is
  rejected at start, not after the human has finished), the internal
  findings-digest consistency, and the output target (one explicit
  directory-creation rule plus a real write probe).  Existing legal
  directories stay reusable; existing sessions are never silently
  overwritten.
- Verification is read-only and fail-closed.  One pair check replays the
  events through the frozen engine, recomputes active time and every
  digest from the persisted bytes, and cross-checks the reviewer digest,
  the sidecar/receipt binding and (when a review set is supplied) the
  full source binding triple, coverage, unreviewed and review-set digest.
  Any single mismatch rejects the pair -- the verifier never prints or
  returns "human minutes valid" on partial evidence.
- Synthetic isolation: the frozen five-key sidecar carries no marker, so
  every human aggregate here filters by the **paired receipt's**
  ``synthetic`` flag first.  A bare sidecar file can therefore never enter
  a human report face through this module; :func:`summarize_review_receipts`
  keeps its frozen semantics unchanged.

The module is pure offline stdlib-only code: deterministic, secretless, no
network, no ambient reads.  The raw reviewer identity never persists --
only its SHA-256 digest is ever written, and reviewer ids never enter
errors, events, file names or logs.
"""

import dataclasses
import enum
import hashlib
import json
import pathlib
import re
import tempfile
import typing

from benchmarks.v4.baseline import lf_baseline
from benchmarks.v4.baseline.collect import BaselineCollectionError
from benchmarks.v4.baseline.expert_review import (
    ExpertReviewError,
    load_review_receipts,
    load_review_set,
    validate_review_receipt,
    validate_timing_events,
    write_review_receipt,
)
from benchmarks.v4.baseline.orchestrate import BaselineRunSummary
from benchmarks.v4.baseline.report import (
    build_baseline_report,
    find_run_artifacts,
    write_report_file,
)
from benchmarks.v4.baseline.run import write_exclusive
from lima.baseline_run_result import from_mapping as result_from_mapping
from lima.contracts.codec import canonical_encode, compute_content_digest

__all__ = [
    "ExpertReviewPairError",
    "ExpertReviewPairErrorCode",
    "EvidencePairArtifacts",
    "PreparedReviewSession",
    "SIDECAR_NAME_PREFIX",
    "derive_expert_review_report",
    "persist_timing_sidecar",
    "attach_verdict_receipt",
    "prepare_session",
    "sidecar_file_name",
    "verified_human_sidecar_documents",
    "verify_pair",
    "verify_session_directory",
]

#: The frozen sidecar file-name family (content-addressed, v1).
SIDECAR_NAME_PREFIX: typing.Final[str] = "expert-timing-sidecar-v1-"

_SIDECAR_NAME_PATTERN: typing.Final[re.Pattern[str]] = re.compile(
    r"^expert-timing-sidecar-v1-([0-9a-f]{16})\.json$"
)

#: The frozen derivation-record document version.
_DERIVATION_DOCUMENT_VERSION: typing.Final[int] = 1

#: The deterministic write-probe name (created then removed, never a session
#: artifact; a leftover probe only blocks a concurrent prepare, honestly).
_WRITE_PROBE_NAME: typing.Final[str] = ".expert-review-write-probe"

#: The frozen review-set source-binding fields cross-checked on verification.
_REVIEW_SET_BINDING_FIELDS: typing.Final[tuple[str, ...]] = (
    "run_spec_digest",
    "aggregate_sha256",
    "findings_digest",
)


class ExpertReviewPairErrorCode(str, enum.Enum):
    """Frozen wire values for every deterministic evidence-pair failure."""

    REVIEW_SET_PIN_MISMATCH = "REVIEW_SET_PIN_MISMATCH"
    REVIEW_SET_ENCODING_INVALID = "REVIEW_SET_ENCODING_INVALID"
    REVIEW_SET_FINDINGS_MISMATCH = "REVIEW_SET_FINDINGS_MISMATCH"
    OUTPUT_TARGET_INVALID = "OUTPUT_TARGET_INVALID"
    PAIR_INCOMPLETE = "PAIR_INCOMPLETE"
    PAIR_INVALID = "PAIR_INVALID"

    def __str__(self) -> str:
        """Render the bare frozen wire value (the str-mixin face)."""
        return self.value


_STABLE_MESSAGES: dict[ExpertReviewPairErrorCode, str] = {
    ExpertReviewPairErrorCode.REVIEW_SET_PIN_MISMATCH: (
        "The review-set file does not match its pinned SHA-256 digest."
    ),
    ExpertReviewPairErrorCode.REVIEW_SET_ENCODING_INVALID: (
        "The review-set document cannot enter the canonical codec."
    ),
    ExpertReviewPairErrorCode.REVIEW_SET_FINDINGS_MISMATCH: (
        "The review-set findings disagree with the findings digest."
    ),
    ExpertReviewPairErrorCode.OUTPUT_TARGET_INVALID: (
        "The evidence-pair output target is unavailable or not writable."
    ),
    ExpertReviewPairErrorCode.PAIR_INCOMPLETE: (
        "The evidence pair is incomplete; no successful session is recorded."
    ),
    ExpertReviewPairErrorCode.PAIR_INVALID: (
        "The evidence pair fails independent verification."
    ),
}


class ExpertReviewPairError(ValueError):
    """Deterministic evidence-pair violation with a stable code and message.

    The shape follows the frozen ``ExpertReviewError`` precedent while
    staying an independent class.  The rendered message is exactly the
    catalog entry above; raw payloads, reviewer identities, digest values
    and host paths are never embedded -- ``field_path`` is structure-only.
    """

    code: ExpertReviewPairErrorCode
    field_path: str

    def __init__(self, code: ExpertReviewPairErrorCode, field_path: str = "") -> None:
        if not isinstance(code, ExpertReviewPairErrorCode):
            raise TypeError("code must be an ExpertReviewPairErrorCode member")
        if not isinstance(field_path, str):
            raise TypeError("field_path must be a str")
        self.code = code
        self.field_path = field_path
        super().__init__(_STABLE_MESSAGES[code])


def _is_hex64(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


@dataclasses.dataclass(frozen=True)
class PreparedReviewSession:
    """Everything the timing loop needs, gated before the first key press."""

    review_set: dict[str, object]
    review_set_path: pathlib.Path
    output_dir: pathlib.Path
    review_set_digest: str


@dataclasses.dataclass(frozen=True)
class EvidencePairArtifacts:
    """The persisted evidence pair of one completed session."""

    sidecar_path: pathlib.Path
    receipt_path: pathlib.Path
    sidecar_sha256: str
    active_time_ms: int


def sidecar_file_name(sidecar_sha256: str) -> str:
    """The content-addressed sidecar file name for one sidecar digest."""
    if not _is_hex64(sidecar_sha256):
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.PAIR_INVALID, "$.sidecar_sha256"
        )
    return f"{SIDECAR_NAME_PREFIX}{sidecar_sha256[:16]}.json"


def _sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _probe_writable(directory: pathlib.Path) -> None:
    """Fail closed unless a real exclusive write into the directory works."""
    probe = directory / _WRITE_PROBE_NAME
    try:
        write_exclusive(probe, b"write-probe")
        probe.unlink()
    except (BaselineCollectionError, OSError) as exc:
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.OUTPUT_TARGET_INVALID, "$.output_dir"
        ) from exc


def prepare_session(
    review_set_path: str | pathlib.Path,
    output_dir: str | pathlib.Path,
    *,
    review_set_sha256: str | None = None,
) -> PreparedReviewSession:
    """Gate every deterministic failure before the human timing starts.

    Gate order: the frozen review-set loader; the optional pinned file
    digest (byte-level tamper rejection); the canonical dry run of the
    whole review-set document and of its findings list (the float
    fail-early precheck -- a document that could never produce a receipt
    must never consume human time); the internal findings-digest
    consistency; then the output target.  The target directory rule is
    explicit: a missing directory is created as a single new leaf under an
    existing parent (no recursive creation), an existing directory stays
    reusable as-is (the frozen receipt writer deduplicates and never
    overwrites), and a real write probe must succeed before timing may
    start.  A file, a missing parent, or an unwritable target is rejected
    here -- never after the session.
    """
    path = pathlib.Path(review_set_path)
    if review_set_sha256 is not None:
        if not _is_hex64(review_set_sha256):
            raise ExpertReviewPairError(
                ExpertReviewPairErrorCode.REVIEW_SET_PIN_MISMATCH,
                "$.review_set_sha256",
            )
        try:
            actual = _sha256_file(path)
        except OSError as exc:
            raise ExpertReviewPairError(
                ExpertReviewPairErrorCode.REVIEW_SET_PIN_MISMATCH,
                "$.review_set_sha256",
            ) from exc
        if actual != review_set_sha256:
            raise ExpertReviewPairError(
                ExpertReviewPairErrorCode.REVIEW_SET_PIN_MISMATCH,
                "$.review_set_sha256",
            )
    review_set = load_review_set(path)
    try:
        review_set_digest = compute_content_digest(review_set)
        findings_digest = compute_content_digest(review_set["findings"])
    except (ValueError, TypeError) as exc:
        # The DR-IP-0043-CFINAL-FLOAT failure face, moved in front of the
        # human clock: a review-set that cannot be canonicalized can never
        # produce a receipt, so it is refused before timing starts.
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.REVIEW_SET_ENCODING_INVALID, "$.review_set"
        ) from exc
    if findings_digest != review_set["findings_digest"]:
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.REVIEW_SET_FINDINGS_MISMATCH,
            "$.review_set.findings_digest",
        )
    directory = pathlib.Path(output_dir)
    try:
        if directory.exists() and not directory.is_dir():
            raise NotADirectoryError(directory)
        if not directory.exists():
            directory.mkdir(parents=False)
    except (OSError, ValueError) as exc:
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.OUTPUT_TARGET_INVALID, "$.output_dir"
        ) from exc
    _probe_writable(directory)
    return PreparedReviewSession(
        review_set=review_set,
        review_set_path=path,
        output_dir=directory,
        review_set_digest=review_set_digest,
    )


def persist_timing_sidecar(
    sidecar_bytes: bytes, output_dir: str | pathlib.Path
) -> pathlib.Path:
    """Persist the raw canonical sidecar exclusively, events-first.

    The file name is derived from the sidecar's own SHA-256, so an
    interrupted retry of the same session addresses the same path: an
    existing byte-identical sidecar is reused (nothing overwritten), any
    other occupant fails closed.  The persisted bytes are read back and
    compared before the path is returned; a sidecar written here is still
    incomplete residue until its receipt lands.
    """
    if not isinstance(sidecar_bytes, (bytes, bytearray)):
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.PAIR_INVALID, "$.sidecar_bytes"
        )
    payload = bytes(sidecar_bytes)
    digest = compute_content_digest(payload)
    path = pathlib.Path(output_dir) / sidecar_file_name(digest)
    try:
        if path.exists():
            if path.read_bytes() != payload:
                raise ExpertReviewPairError(
                    ExpertReviewPairErrorCode.PAIR_INVALID, "$.sidecar_path"
                )
        else:
            write_exclusive(path, payload)
    except BaselineCollectionError as exc:
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.PAIR_INVALID, "$.sidecar_path"
        ) from exc
    if path.read_bytes() != payload:
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.PAIR_INVALID, "$.sidecar_path"
        )
    return path


def attach_verdict_receipt(
    receipt: object, output_dir: str | pathlib.Path
) -> EvidencePairArtifacts:
    """Complete the evidence pair: frozen receipt write plus pair read-back.

    The receipt keeps its frozen writer (closed key set, event-set dedup,
    versioned naming, exclusive write).  After it lands, both pair members
    are read back from disk immediately; the pair digest is recomputed
    from the persisted sidecar bytes and cross-checked against the
    receipt.  Only a fully persisted, read-back-verified pair returns.
    """
    validated = validate_review_receipt(receipt)
    directory = pathlib.Path(output_dir)
    sidecar_path = directory / sidecar_file_name(
        typing.cast(str, validated["sidecar_sha256"])
    )
    if not sidecar_path.is_file():
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.PAIR_INCOMPLETE, "$.sidecar_path"
        )
    receipt_path = write_review_receipt(validated, directory)
    persisted = _sha256_file(sidecar_path)
    if persisted != validated["sidecar_sha256"]:
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.PAIR_INVALID, "$.sidecar_sha256"
        )
    loaded = json.loads(sidecar_path.read_bytes().decode("utf-8"))
    if not isinstance(loaded, dict) or loaded["active_time_ms"] != validated[
        "active_time_ms"
    ]:
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.PAIR_INVALID, "$.sidecar.active_time_ms"
        )
    return EvidencePairArtifacts(
        sidecar_path=sidecar_path,
        receipt_path=receipt_path,
        sidecar_sha256=persisted,
        active_time_ms=typing.cast(int, validated["active_time_ms"]),
    )


def _pair_record(
    receipt_path: pathlib.Path,
    receipt: dict[str, object],
    sidecar_document: dict[str, object],
    active_time_ms: int,
) -> dict[str, object]:
    return {
        "receipt": receipt_path.name,
        "sidecar": sidecar_file_name(typing.cast(str, receipt["sidecar_sha256"])),
        "synthetic": receipt["synthetic"],
        "verdict": receipt["verdict"],
        "reviewer_digest": receipt["reviewer_digest"],
        "active_time_ms": active_time_ms,
        "sidecar_sha256": receipt["sidecar_sha256"],
        "events_digest": receipt["events_digest"],
    }


def verify_pair(
    receipt_path: str | pathlib.Path,
    receipt: object,
    *,
    review_set: dict[str, object] | None = None,
) -> dict[str, object]:
    """Independently verify one evidence pair from the persisted bytes.

    Check order (fail-closed, one mismatch rejects): the frozen receipt
    validation; the content-addressed sidecar name rule; the sidecar bytes
    re-hash to the receipt's ``sidecar_sha256``; the sidecar parses with
    the frozen five-key protocol and schema v1; the sidecar's run identity
    equals the receipt's; the events replay through the frozen engine
    (state machine, monotonic clock, ``finish`` termination) and the
    independently recomputed active time equals both the sidecar's and the
    receipt's declared value; the events digest recomputed from the
    persisted events equals the receipt's; the reviewer digest agrees
    between sidecar and receipt; and, with a review set supplied, the
    receipt's review-set digest, source-binding triple, coverage and
    unreviewed faces all re-derive from that review set.  The returned
    record is descriptive only; it is never a "human minutes valid" claim.
    """
    path = pathlib.Path(receipt_path)
    validated = validate_review_receipt(receipt)
    digest = typing.cast(str, validated["sidecar_sha256"])
    expected_name = sidecar_file_name(digest)
    sidecar_path = path.with_name(expected_name)
    if not sidecar_path.is_file():
        # No sidecar at the receipt's content-addressed name: with no
        # sidecar-family file at all this is incomplete residue; with
        # other sidecars present the pairing itself is broken.
        family = [
            item
            for item in sidecar_path.parent.iterdir()
            if _SIDECAR_NAME_PATTERN.fullmatch(item.name)
        ] if sidecar_path.parent.is_dir() else []
        if family:
            raise ExpertReviewPairError(
                ExpertReviewPairErrorCode.PAIR_INVALID, "$.sidecar_sha256"
            )
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.PAIR_INCOMPLETE, "$.sidecar_path"
        )
    raw = sidecar_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.PAIR_INVALID, "$.sidecar_sha256"
        )
    try:
        sidecar = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.PAIR_INVALID, "$.sidecar"
        ) from exc
    if (
        not isinstance(sidecar, dict)
        or set(sidecar)
        != {
            "schema_version",
            "run_spec_digest",
            "reviewer_digest",
            "active_time_ms",
            "events",
        }
        or sidecar["schema_version"] != 1
    ):
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.PAIR_INVALID, "$.sidecar"
        )
    if sidecar["run_spec_digest"] != validated["run_spec_digest"]:
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.PAIR_INVALID, "$.sidecar.run_spec_digest"
        )
    replayed_ms = validate_timing_events(sidecar["events"])
    if replayed_ms != sidecar["active_time_ms"] or replayed_ms != validated[
        "active_time_ms"
    ]:
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.PAIR_INVALID, "$.sidecar.active_time_ms"
        )
    if compute_content_digest(sidecar["events"]) != validated["events_digest"]:
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.PAIR_INVALID, "$.events_digest"
        )
    if sidecar["reviewer_digest"] != validated["reviewer_digest"]:
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.PAIR_INVALID, "$.reviewer_digest"
        )
    if review_set is not None:
        if compute_content_digest(review_set) != validated["review_set_digest"]:
            raise ExpertReviewPairError(
                ExpertReviewPairErrorCode.PAIR_INVALID, "$.review_set_digest"
            )
        for field in _REVIEW_SET_BINDING_FIELDS:
            if validated[field] != review_set[field]:
                raise ExpertReviewPairError(
                    ExpertReviewPairErrorCode.PAIR_INVALID, f"$.{field}"
                )
        if validated["coverage"] != review_set["coverage"] or validated[
            "unreviewed"
        ] != review_set["unreviewed"]:
            raise ExpertReviewPairError(
                ExpertReviewPairErrorCode.PAIR_INVALID, "$.coverage"
            )
        if sidecar["run_spec_digest"] != review_set["run_spec_digest"]:
            raise ExpertReviewPairError(
                ExpertReviewPairErrorCode.PAIR_INVALID, "$.sidecar.run_spec_digest"
            )
    return _pair_record(path, validated, sidecar, replayed_ms)


def verify_session_directory(
    output_dir: str | pathlib.Path,
    *,
    review_set: dict[str, object] | None = None,
    review_set_path: str | pathlib.Path | None = None,
) -> dict[str, object]:
    """Verify every evidence pair in one directory, honestly and read-only.

    Every receipt in the frozen receipt family must verify against its own
    content-addressed sidecar (a receipt without its sidecar is a broken
    pair and fails closed).  Sidecar files no receipt claims are reported
    as ``incomplete_sidecars`` -- unfinished sessions that never count.
    The summary distinguishes verified human sessions from verified
    synthetic sessions (the paired receipt's flag is the only marker),
    totals human active time only over verified non-synthetic pairs, and
    reports ``None`` when no human session exists.  Nothing is written.
    """
    if review_set is None and review_set_path is not None:
        review_set = load_review_set(review_set_path)
    directory = pathlib.Path(output_dir)
    loaded = load_review_receipts(directory) if directory.is_dir() else []
    pairs = [
        verify_pair(receipt_path, receipt, review_set=review_set)
        for receipt_path, receipt in loaded
    ]
    claimed = {record["sidecar"] for record in pairs}
    incomplete_sidecars: list[str] = []
    if directory.is_dir():
        for entry in sorted(directory.iterdir(), key=lambda item: item.name):
            if _SIDECAR_NAME_PATTERN.fullmatch(entry.name) and (
                entry.name not in claimed
            ):
                incomplete_sidecars.append(entry.name)
    human_pairs = [record for record in pairs if record["synthetic"] is False]
    return {
        "schema_version": _DERIVATION_DOCUMENT_VERSION,
        "pairs": pairs,
        "human_sessions": len(human_pairs),
        "synthetic_sessions": len(pairs) - len(human_pairs),
        "human_active_time_ms_total": (
            sum(record["active_time_ms"] for record in human_pairs)
            if human_pairs
            else None
        ),
        "incomplete_sidecars": incomplete_sidecars,
    }


def verified_human_sidecar_documents(
    output_dir: str | pathlib.Path,
    *,
    review_set: dict[str, object] | None = None,
    review_set_path: str | pathlib.Path | None = None,
) -> list[dict[str, object]]:
    """The report-input gate for human minutes: verified pairs only.

    The whole directory is verified first (fail-closed); then only the
    sidecar documents of verified **non-synthetic** pairs are returned, in
    receipt-discovery order.  Synthetic pairs are excluded by their paired
    receipt flag; bare sidecar files never appear here at all.  The result
    is the exact ``expert_sidecars`` input for the frozen report builder.
    """
    directory = pathlib.Path(output_dir)
    if review_set is None and review_set_path is not None:
        review_set = load_review_set(review_set_path)
    loaded = (
        load_review_receipts(directory) if directory.is_dir() else []
    )
    documents: list[dict[str, object]] = []
    for receipt_path, receipt in loaded:
        record = verify_pair(receipt_path, receipt, review_set=review_set)
        if record["synthetic"] is False:
            sidecar_path = receipt_path.with_name(
                typing.cast(str, record["sidecar"])
            )
            document = json.loads(sidecar_path.read_bytes().decode("utf-8"))
            documents.append(typing.cast(dict[str, object], document))
    return documents


def _reconstruct_summary(
    source_dir: pathlib.Path, run_spec_digest: str
) -> BaselineRunSummary:
    """Rebuild the frozen summary face from persisted run files, read-only."""
    entries = find_run_artifacts(source_dir)
    prefix = run_spec_digest[:16]
    matching = [entry for entry in entries if entry.digest16 == prefix]
    aggregate_entries = [
        entry for entry in matching if entry.is_aggregate
    ]
    attempt_entries = [entry for entry in matching if not entry.is_aggregate]
    if not aggregate_entries or not attempt_entries:
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.PAIR_INVALID, "$.source_dir"
        )
    aggregate_entry = max(aggregate_entries, key=lambda entry: entry.sequence)
    attempt_entries = sorted(attempt_entries, key=lambda entry: entry.sequence)

    def _load(entry) -> object:
        # A persisted artifact carries the canonical output face (status and
        # percentile fields included); the frozen input contract owns the
        # strictly smaller input face and recomputes the rest.  Project
        # before parsing, exactly like the frozen artifact reader.
        mapping = json.loads(entry.result_path.read_bytes().decode("utf-8"))
        try:
            projected = {
                field: mapping[field]
                for field in ("schema_version", "run_spec_digest", "samples")
            }
        except KeyError as exc:
            raise ExpertReviewPairError(
                ExpertReviewPairErrorCode.PAIR_INVALID, "$.source_dir.results"
            ) from exc
        return result_from_mapping(projected)

    attempts = tuple(_load(entry) for entry in attempt_entries)
    aggregate = _load(aggregate_entry)
    summary = BaselineRunSummary(
        attempts=attempts,
        result_paths=tuple(entry.result_path for entry in attempt_entries),
        aggregate=aggregate,
        aggregate_path=aggregate_entry.result_path,
        aggregate_sha256=aggregate.content_digest(),
        status=aggregate.status,
    )
    return summary


def derive_expert_review_report(
    *,
    source_dir: str | pathlib.Path,
    sessions_dir: str | pathlib.Path,
    review_set_path: str | pathlib.Path,
    archive_path: str | pathlib.Path,
    output_dir: str | pathlib.Path,
) -> dict[str, object]:
    """Derive one report with verified human minutes, sealed sources intact.

    The explicit derivation chain (read-only on every sealed input): the
    frozen review-set loader binds the run identity; the persisted run
    files rebuild the frozen summary face; the sealed tarball is
    rematerialized and rescanned **through the frozen LF production
    helpers** and the rebuilt scanner wire digest must equal the sealed
    binding's ``scanner_payload_sha256`` (a rebuild that does not
    reproduce the sealed binding fails closed); the sessions directory is
    pair-verified and only verified non-synthetic sidecars enter the
    report; the derived report lands in a brand-new out-of-repo directory
    through the frozen report writer.  The sealed report file is hashed
    before and after the whole derivation and both hashes must be equal.
    The derivation record documents every input digest, the verified pair
    summary, the synthetic exclusion and both report digests.
    """
    source = pathlib.Path(source_dir)
    review_set = load_review_set(review_set_path)
    run_spec_digest = typing.cast(str, review_set["run_spec_digest"])
    summary = _reconstruct_summary(source, run_spec_digest)
    if summary.aggregate_sha256 != review_set["aggregate_sha256"]:
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.PAIR_INVALID, "$.review_set.aggregate_sha256"
        )
    try:
        binding_document = json.loads(
            (source / "lf-binding.json").read_bytes().decode("utf-8")
        )
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.PAIR_INVALID, "$.source_dir.lf-binding"
        ) from exc
    sealed_scanner_digest = binding_document.get("scanner_payload_sha256")
    if not _is_hex64(sealed_scanner_digest):
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.PAIR_INVALID, "$.scanner_payload_sha256"
        )
    report_prefix = run_spec_digest[:16]
    sealed_report_path = source / f"{report_prefix}-report-1.json"
    if not sealed_report_path.is_file():
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.PAIR_INVALID, "$.source_dir.report"
        )
    sealed_before = _sha256_file(sealed_report_path)
    archive = pathlib.Path(archive_path)
    try:
        archive_digest = _sha256_file(archive)
    except OSError as exc:
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.PAIR_INVALID, "$.archive_path"
        ) from exc
    with tempfile.TemporaryDirectory(prefix="lf-derive-") as temporary:
        snapshot = lf_baseline._materialize_snapshot(
            archive, pathlib.Path(temporary) / "snapshot"
        )
        scan = lf_baseline._scan_snapshot(snapshot)
        payload = lf_baseline._canonical_payload(
            scan, lf_baseline.LF_CANONICAL_LABEL
        )
        rebuilt_scanner_digest = lf_baseline._wire_fingerprint(payload)
    if rebuilt_scanner_digest != sealed_scanner_digest:
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.PAIR_INVALID, "$.scanner_payload_sha256"
        )
    sessions = pathlib.Path(sessions_dir)
    session_record = verify_session_directory(sessions, review_set=review_set)
    human_sidecars = verified_human_sidecar_documents(sessions, review_set=review_set)
    derived = pathlib.Path(output_dir)
    if derived.exists():
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.OUTPUT_TARGET_INVALID, "$.derived_output_dir"
        )
    try:
        derived.mkdir(parents=False)
    except OSError as exc:
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.OUTPUT_TARGET_INVALID, "$.derived_output_dir"
        ) from exc
    report = build_baseline_report(
        summary, payload, expert_sidecars=human_sidecars
    )
    artifacts = write_report_file(report, derived)
    sealed_after = _sha256_file(sealed_report_path)
    if sealed_after != sealed_before:
        raise ExpertReviewPairError(
            ExpertReviewPairErrorCode.PAIR_INVALID, "$.sealed_report_sha256"
        )
    record = {
        "schema_version": _DERIVATION_DOCUMENT_VERSION,
        "flow": "verify-pairs-exclude-synthetic-derive-report",
        "run_spec_digest": run_spec_digest,
        "sealed_aggregate_sha256": summary.aggregate_sha256,
        "review_set_digest": compute_content_digest(review_set),
        "archive_sha256": archive_digest,
        "rebuilt_scanner_payload_sha256": rebuilt_scanner_digest,
        "sealed_scanner_payload_sha256": sealed_scanner_digest,
        "sessions": {
            key: session_record[key]
            for key in (
                "human_sessions",
                "synthetic_sessions",
                "human_active_time_ms_total",
                "incomplete_sidecars",
            )
        },
        "human_sidecar_count": len(human_sidecars),
        "derived_report_path": artifacts.report_path.name,
        "derived_report_sha256": artifacts.report_sha256,
        "sealed_report_sha256_before": sealed_before,
        "sealed_report_sha256_after": sealed_after,
    }
    record_path = derived / "expert-review-derivation-v1.json"
    write_exclusive(record_path, canonical_encode(record))
    return record
