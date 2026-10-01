"""LF resource observation companion for LIMA v4 (IP-0043, Issue #257).

This module implements the companion scheme (Packet R3): the frozen
``report.py`` keeps its v2 default (the three-key null resources face for
scanner payloads stays byte-identical, zero hunks), and the per-attempt
resource evidence of the LF local baseline is reported by an independent,
versioned document -- ``lf-local-observation-v1.json`` -- written into the
same directory as the run artifacts under its own name family.

The document carries the five mandatory back references (``run_spec_digest``,
``aggregate_sha256``, the scanner wire digest, ``snapshot_tree_sha256`` and
``archive_sha256``), one per-attempt entry per result file pointing back to
that file's original bytes (SHA-256 of the raw file), the mandatory
measurement-semantics notes, and the scoped zero-call model-usage face.

Measurement semantics are honest by construction (the tenth-round ruling:
no fake values, no guesses, no zero substitutes):

- ``memory_rss_peak_bytes`` is the process-lifetime cumulative peak
  (``ru_maxrss`` scope), not a per-attempt delta;
- ``io_read_bytes``/``io_write_bytes`` are process-lifetime cumulative
  counters at read time, not per-attempt deltas;
- ``wall_time_ms``/``cpu_time_ms`` are per-attempt deltas between two
  monotonic reads;
- platforms without the sources (Windows: no ``resource`` module and no
  ``/proc/self/io``) report ``null`` with the platform reason -- never a
  fabricated value.

The model-usage face is scoped zero-call by construction: there is no wire
client and no request path anywhere in the LF workload, so
prompt/completion/cost are integer zero under the frozen source string
pinned below, and the note records that local compute and human time are
not therefore free.

:func:`build_lf_observation` re-reads one LF run directory and derives every
value from the artifacts on disk (never from in-memory state); :func:
`verify_lf_observation` re-derives everything again and fails closed with
the typed four-code family on a missing version/profile, artifacts from
another run (source mismatch), any back-reference digest mismatch
(tampering) or missing/invalid run artifacts.  There is no fallback guess
algorithm.  The module is a pure offline stdlib-only reader/writer:
deterministic, secretless, no network, no ambient reads.
"""

import dataclasses
import enum
import json
import pathlib
import typing

from benchmarks.v4.baseline.run import write_exclusive
from lima.contracts.codec import canonical_encode, compute_content_digest

__all__ = [
    "LFObservationError",
    "LFObservationErrorCode",
    "LFObservationProfile",
    "build_lf_observation",
    "verify_lf_observation",
]

#: The companion document name and profile (independently versioned family).
LFObservationProfile: typing.Final[str] = "lf-local-observation-v1"
OBSERVATION_DOCUMENT_NAME: typing.Final[str] = "lf-local-observation-v1.json"

#: The frozen companion top-level key set (closed, ten keys).
_OBSERVATION_KEYS: typing.Final[tuple[str, ...]] = (
    "schema_version",
    "profile",
    "run_spec_digest",
    "aggregate_sha256",
    "scanner_payload_sha256",
    "snapshot_tree_sha256",
    "archive_sha256",
    "attempts",
    "measurement_semantics",
    "model_usage",
)
_OBSERVATION_KEY_SET: typing.Final[frozenset[str]] = frozenset(_OBSERVATION_KEYS)

#: The frozen per-attempt observation key set (closed, eight keys).
_ATTEMPT_KEYS: typing.Final[tuple[str, ...]] = (
    "attempt_index",
    "mode",
    "result_sha256",
    "wall_time_ms",
    "cpu_time_ms",
    "memory_rss_peak_bytes",
    "io_read_bytes",
    "io_write_bytes",
)
_ATTEMPT_KEY_SET: typing.Final[frozenset[str]] = frozenset(_ATTEMPT_KEYS)

#: The mandatory measurement-semantics notes (exact frozen strings).
MEASUREMENT_SEMANTICS: typing.Final[dict[str, str]] = {
    "memory_rss_peak_bytes": (
        "process-lifetime cumulative peak (ru_maxrss scope); "
        "not a per-attempt delta"
    ),
    "io_read_bytes": (
        "process-lifetime cumulative counter at read time; "
        "not a per-attempt delta"
    ),
    "io_write_bytes": (
        "process-lifetime cumulative counter at read time; "
        "not a per-attempt delta"
    ),
    "wall_time_ms": "per-attempt delta between two monotonic reads",
    "cpu_time_ms": "per-attempt delta between two monotonic reads",
    "platform": (
        "windows: no resource module and no /proc/self/io; unavailable "
        "platform metrics are null, never zero-filled or guessed"
    ),
}

#: The scoped zero-call model face (exact frozen strings and zeros).
MODEL_USAGE: typing.Final[dict[str, object]] = {
    "prompt_tokens": 0,
    "completion_tokens": 0,
    "cost_micro_usd": 0,
    "source": "zero-model-calls-by-construction",
    "cost_note": (
        "zero model usage does not make local compute or human time free"
    ),
}

#: The frozen lf-binding manifest faces this companion consumes (subset).
_BINDING_REQUIRED_KEYS: typing.Final[tuple[str, ...]] = (
    "schema_version",
    "run_spec_digest",
    "attempt_count",
    "scanner_payload_sha256",
    "snapshot_tree_sha256",
    "archive_sha256",
)

_SAMPLE_FACES: typing.Final[tuple[str, ...]] = (
    "attempt_index",
    "mode",
    "wall_time_ms",
    "cpu_time_ms",
    "memory_rss_peak_bytes",
    "io_read_bytes",
    "io_write_bytes",
)

_HEX64_ALPHABET: typing.Final[frozenset[str]] = frozenset("0123456789abcdef")


class LFObservationErrorCode(str, enum.Enum):  # noqa: UP042 -- frozen by IP-0043 Packet
    """Frozen wire values for every deterministic observation failure."""

    OBSERVATION_VERSION_MISSING = "OBSERVATION_VERSION_MISSING"
    OBSERVATION_SOURCE_MISMATCH = "OBSERVATION_SOURCE_MISMATCH"
    OBSERVATION_DIGEST_MISMATCH = "OBSERVATION_DIGEST_MISMATCH"
    OBSERVATION_ARTIFACT_INVALID = "OBSERVATION_ARTIFACT_INVALID"

    def __str__(self) -> str:
        """Render the bare frozen wire value (the str-mixin face)."""
        return self.value


_STABLE_MESSAGES: dict[LFObservationErrorCode, str] = {
    LFObservationErrorCode.OBSERVATION_VERSION_MISSING: (
        "The observation document version or profile is missing or invalid."
    ),
    LFObservationErrorCode.OBSERVATION_SOURCE_MISMATCH: (
        "The observation artifacts belong to a different run."
    ),
    LFObservationErrorCode.OBSERVATION_DIGEST_MISMATCH: (
        "An observation back reference does not match its artifact."
    ),
    LFObservationErrorCode.OBSERVATION_ARTIFACT_INVALID: (
        "A run artifact required by the observation companion is invalid."
    ),
}


class LFObservationError(ValueError):
    """Deterministic observation violation with a stable code and message.

    The shape aligns with the frozen ``B1SourceError`` precedent while
    remaining an independent class.  The rendered message is exactly the
    catalog entry above; raw payloads, secrets, digest values and host
    paths are never embedded.
    """

    code: LFObservationErrorCode
    field_path: str

    def __init__(self, code: LFObservationErrorCode, field_path: str = "") -> None:
        if not isinstance(code, LFObservationErrorCode):
            raise TypeError("code must be a LFObservationErrorCode member")
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


@dataclasses.dataclass(frozen=True, slots=True)
class _RunArtifacts:
    """Every artifact face the companion derives its values from."""

    binding: dict[str, object]
    run_spec_digest: str
    scanner_payload_sha256: str | None
    snapshot_tree_sha256: str
    archive_sha256: str
    attempt_paths: tuple[pathlib.Path, ...]
    aggregate_path: pathlib.Path


def _read_json(path: pathlib.Path, field_path: str) -> object:
    try:
        return json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_ARTIFACT_INVALID, field_path
        ) from exc


def _load_binding(directory: pathlib.Path) -> dict[str, object]:
    binding = _read_json(directory / "lf-binding.json", "$.lf_binding")
    if not isinstance(binding, dict):
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_ARTIFACT_INVALID, "$.lf_binding"
        )
    for key in _BINDING_REQUIRED_KEYS:
        if key not in binding:
            raise LFObservationError(
                LFObservationErrorCode.OBSERVATION_ARTIFACT_INVALID,
                f"$.lf_binding.{key}",
            )
    if binding["schema_version"] != 1 or not _is_hex64(binding["run_spec_digest"]):
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_ARTIFACT_INVALID, "$.lf_binding"
        )
    for key in ("snapshot_tree_sha256", "archive_sha256"):
        if not _is_hex64(binding[key]):
            raise LFObservationError(
                LFObservationErrorCode.OBSERVATION_ARTIFACT_INVALID,
                f"$.lf_binding.{key}",
            )
    if binding["scanner_payload_sha256"] is not None and not _is_hex64(
        binding["scanner_payload_sha256"]
    ):
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_ARTIFACT_INVALID,
            "$.lf_binding.scanner_payload_sha256",
        )
    return binding


def _load_result_documents(
    directory: pathlib.Path, binding: dict[str, object]
) -> tuple[tuple[pathlib.Path, ...], pathlib.Path]:
    """Locate the attempt/aggregate result files, verifying run identity."""
    prefix = typing.cast(str, binding["run_spec_digest"])[:16]
    try:
        paths = sorted(
            directory.glob(f"{prefix}-run-*.json"),
            key=lambda path: int(path.stem.rsplit("-", 1)[1]),
        )
    except (OSError, ValueError) as exc:
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_ARTIFACT_INVALID, "$.results"
        ) from exc
    if len(paths) < 2:
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_ARTIFACT_INVALID, "$.results"
        )
    attempt_paths = tuple(paths[:-1])
    aggregate_path = paths[-1]
    run_spec_digest = binding["run_spec_digest"]
    for index, path in enumerate(paths):
        document = _read_json(path, f"$.results[{index}]")
        if not isinstance(document, dict):
            raise LFObservationError(
                LFObservationErrorCode.OBSERVATION_ARTIFACT_INVALID,
                f"$.results[{index}]",
            )
        if document.get("run_spec_digest") != run_spec_digest:
            raise LFObservationError(
                LFObservationErrorCode.OBSERVATION_SOURCE_MISMATCH,
                f"$.results[{index}].run_spec_digest",
            )
    return attempt_paths, aggregate_path


def _load_report_scanner_digest(
    directory: pathlib.Path, binding: dict[str, object]
) -> str:
    """The report's scanner source digest, cross-checked against the binding."""
    prefix = typing.cast(str, binding["run_spec_digest"])[:16]
    try:
        report_paths = sorted(directory.glob(f"{prefix}-report-*.json"))
    except OSError as exc:
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_ARTIFACT_INVALID, "$.report"
        ) from exc
    if not report_paths:
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_ARTIFACT_INVALID, "$.report"
        )
    report = _read_json(report_paths[-1], "$.report")
    if not isinstance(report, dict):
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_ARTIFACT_INVALID, "$.report"
        )
    scanner_digest: object = None
    sources = report.get("sources")
    if isinstance(sources, list):
        for source in sources:
            if isinstance(source, dict) and source.get("kind") == "scanner":
                scanner_digest = source.get("payload_sha256")
    if not _is_hex64(scanner_digest):
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_ARTIFACT_INVALID, "$.report.sources"
        )
    if binding["scanner_payload_sha256"] != scanner_digest:
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_SOURCE_MISMATCH,
            "$.report.sources.scanner",
        )
    return typing.cast(str, scanner_digest)


def _load_run_artifacts(directory: pathlib.Path) -> _RunArtifacts:
    """Load and cross-check every artifact face the companion needs."""
    binding = _load_binding(directory)
    attempt_paths, aggregate_path = _load_result_documents(directory, binding)
    if binding["attempt_count"] != len(attempt_paths):
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_SOURCE_MISMATCH,
            "$.lf_binding.attempt_count",
        )
    scanner_digest: str | None = None
    if binding["scanner_payload_sha256"] is not None:
        scanner_digest = _load_report_scanner_digest(directory, binding)
    return _RunArtifacts(
        binding=binding,
        run_spec_digest=typing.cast(str, binding["run_spec_digest"]),
        scanner_payload_sha256=scanner_digest,
        snapshot_tree_sha256=typing.cast(str, binding["snapshot_tree_sha256"]),
        archive_sha256=typing.cast(str, binding["archive_sha256"]),
        attempt_paths=attempt_paths,
        aggregate_path=aggregate_path,
    )


def _attempt_entry(path: pathlib.Path, index: int) -> dict[str, object]:
    document = _read_json(path, f"$.attempts[{index}]")
    if not isinstance(document, dict):
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_ARTIFACT_INVALID,
            f"$.attempts[{index}]",
        )
    samples = document.get("samples")
    if not isinstance(samples, list) or len(samples) != 1 or not isinstance(
        samples[0], dict
    ):
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_ARTIFACT_INVALID,
            f"$.attempts[{index}].samples",
        )
    sample = samples[0]
    entry: dict[str, object] = {"result_sha256": compute_content_digest(path.read_bytes())}
    for face in _SAMPLE_FACES:
        if face not in sample:
            raise LFObservationError(
                LFObservationErrorCode.OBSERVATION_ARTIFACT_INVALID,
                f"$.attempts[{index}].samples[0].{face}",
            )
        entry[face] = sample[face]
    return entry


def build_lf_observation(*, output_dir: str | pathlib.Path) -> pathlib.Path:
    """Derive and write the versioned observation companion for one LF run.

    Every value is recomputed from the run directory on disk: the five back
    references from the closed-key ``lf-binding.json`` manifest, the raw
    report scanner wire digest cross-check, and one per-attempt entry per
    attempt result file (each pointing back to that file's original bytes).
    The document is written canonically and exclusively under its frozen
    name in the same directory; nothing is ever overwritten.
    """
    directory = pathlib.Path(output_dir)
    if not directory.is_dir():
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_ARTIFACT_INVALID, "$.output_dir"
        )
    artifacts = _load_run_artifacts(directory)
    aggregate_sha256 = compute_content_digest(artifacts.aggregate_path.read_bytes())
    attempts = [
        _attempt_entry(path, index)
        for index, path in enumerate(artifacts.attempt_paths)
    ]
    document = {
        "schema_version": 1,
        "profile": LFObservationProfile,
        "run_spec_digest": artifacts.run_spec_digest,
        "aggregate_sha256": aggregate_sha256,
        "scanner_payload_sha256": artifacts.scanner_payload_sha256,
        "snapshot_tree_sha256": artifacts.snapshot_tree_sha256,
        "archive_sha256": artifacts.archive_sha256,
        "attempts": attempts,
        "measurement_semantics": dict(MEASUREMENT_SEMANTICS),
        "model_usage": dict(MODEL_USAGE),
    }
    if set(document) != _OBSERVATION_KEY_SET:  # pragma: no cover - closed by design
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_ARTIFACT_INVALID, "$.observation"
        )
    path = directory / OBSERVATION_DOCUMENT_NAME
    write_exclusive(path, canonical_encode(document))
    return path


def _validate_document_shape(document: object) -> dict[str, object]:
    if not isinstance(document, dict):
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_ARTIFACT_INVALID, "$.observation"
        )
    if (
        document.get("schema_version") != 1
        or document.get("profile") != LFObservationProfile
    ):
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_VERSION_MISSING, "$.schema_version"
        )
    if set(document) != _OBSERVATION_KEY_SET:
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_ARTIFACT_INVALID, "$.observation"
        )
    return document


def verify_lf_observation(path: str | pathlib.Path) -> dict[str, object]:
    """Re-derive every companion value and fail closed on any disagreement.

    Gate order: the document parses and carries the frozen version/profile
    (``OBSERVATION_VERSION_MISSING``); the run artifacts load and agree with
    each other on the run identity (``OBSERVATION_SOURCE_MISMATCH`` for
    artifacts swapped from another run); every document back reference
    equals its freshly recomputed value and every per-attempt entry equals
    its result file's sample faces and raw-byte digest
    (``OBSERVATION_DIGEST_MISMATCH`` for any tampered face); malformed or
    missing artifacts fail with ``OBSERVATION_ARTIFACT_INVALID``.  On
    success a summary mapping with the verified identity faces is
    returned.
    """
    document = _validate_document_shape(
        _read_json(pathlib.Path(path), "$.observation")
    )
    artifacts = _load_run_artifacts(pathlib.Path(path).parent)
    if document["run_spec_digest"] != artifacts.run_spec_digest:
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_SOURCE_MISMATCH, "$.run_spec_digest"
        )
    if document["aggregate_sha256"] != compute_content_digest(
        artifacts.aggregate_path.read_bytes()
    ):
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_DIGEST_MISMATCH, "$.aggregate_sha256"
        )
    if document["scanner_payload_sha256"] != artifacts.scanner_payload_sha256:
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_DIGEST_MISMATCH,
            "$.scanner_payload_sha256",
        )
    if document["snapshot_tree_sha256"] != artifacts.snapshot_tree_sha256:
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_DIGEST_MISMATCH,
            "$.snapshot_tree_sha256",
        )
    if document["archive_sha256"] != artifacts.archive_sha256:
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_DIGEST_MISMATCH, "$.archive_sha256"
        )
    if document["measurement_semantics"] != MEASUREMENT_SEMANTICS or (
        document["model_usage"] != MODEL_USAGE
    ):
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_DIGEST_MISMATCH,
            "$.measurement_semantics",
        )
    entries = document["attempts"]
    if not isinstance(entries, list) or len(entries) != len(artifacts.attempt_paths):
        raise LFObservationError(
            LFObservationErrorCode.OBSERVATION_ARTIFACT_INVALID, "$.attempts"
        )
    for index, (entry, result_path) in enumerate(
        zip(entries, artifacts.attempt_paths, strict=True)
    ):
        prefix = f"$.attempts[{index}]"
        if not isinstance(entry, dict) or set(entry) != _ATTEMPT_KEY_SET:
            raise LFObservationError(
                LFObservationErrorCode.OBSERVATION_ARTIFACT_INVALID, prefix
            )
        if entry["result_sha256"] != compute_content_digest(result_path.read_bytes()):
            raise LFObservationError(
                LFObservationErrorCode.OBSERVATION_DIGEST_MISMATCH,
                f"{prefix}.result_sha256",
            )
        expected = _attempt_entry(result_path, index)
        for face in _SAMPLE_FACES:
            if entry[face] != expected[face]:
                raise LFObservationError(
                    LFObservationErrorCode.OBSERVATION_DIGEST_MISMATCH,
                    f"{prefix}.{face}",
                )
    return {
        "schema_version": 1,
        "profile": LFObservationProfile,
        "run_spec_digest": artifacts.run_spec_digest,
        "aggregate_sha256": document["aggregate_sha256"],
        "scanner_payload_sha256": artifacts.scanner_payload_sha256,
        "snapshot_tree_sha256": artifacts.snapshot_tree_sha256,
        "archive_sha256": artifacts.archive_sha256,
        "attempt_count": len(artifacts.attempt_paths),
    }
