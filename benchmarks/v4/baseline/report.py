"""Frozen report projection for LIMA v4 baseline runs (IP-0029).

This module owns the independent ``lima.baseline-report`` v1 document: an
offline, canonical, sealable aggregate report that projects the FR-04
counting face (signals, security issues, hypotheses, confirmed and
inconclusive counts, scanned files, coverage gap) and the compression
chain (raw candidates -> deterministic alerts -> confirmed) from exactly
one injected evaluator payload -- a repository scan result, an e2e harness
output, or a real-world evaluation output -- plus the expert active-time
face consumed from expert-timing sidecar documents and the automation
percentile face passed through from the frozen run aggregate.

Honest-absence discipline is structural: every position without a faithful
derivation is ``null`` under an explicit ``unavailable`` or
``legacy_projection`` marker, never a fabricated zero.  The two-layer
legacy projection marks the report as a whole (the ``legacy_projection``
bool derived from the structural presence of an injected
``EvidenceDomainBundle``) and every count individually (``measured`` /
``legacy_projection`` / ``unavailable``).  A real-world payload's own
``schema_version == 2`` is that output schema's version and is never
evidence of a v2 evidence domain; a statically supported hypothesis is
never promoted into the runtime verification ladder.

The document is digest-and-hash only: evaluator payloads enter as SHA-256
input fingerprints, the run is referenced by its aggregate digest, and no
host path, source fragment, log line, credential, or raw reviewer id ever
enters the canonical bytes.  Canonical encoding and digests go exclusively
through ``lima.contracts.codec``; report artifacts are created exclusively
through the frozen ``write_exclusive`` primitive and never overwrite
history.  The module is a pure offline stdlib-only library: deterministic,
secretless, no network, no platform probing, and no dataset-registry
consumption (the v1 report surface consumes only already-gated upstream
inputs).
"""

import dataclasses
import enum
import hashlib
import json
import pathlib
import re

from benchmarks.v4.baseline.collect import (
    BaselineCollectionError,
    BaselineCollectionErrorCode,
)
from benchmarks.v4.baseline.orchestrate import BaselineRunSummary
from benchmarks.v4.baseline.run import write_exclusive
from lima.baseline_run_result import BaselineRunResult, BaselineRunResultError
from lima.baseline_run_result import from_mapping as result_from_mapping
from lima.contracts.codec import canonical_encode, compute_content_digest
from lima.contracts.compat import Finding, finding_to_domain_bundle
from lima.contracts.evidence import EvidenceDomainBundle

__all__ = [
    "BASELINE_REPORT_SCHEMA_NAME",
    "BASELINE_REPORT_SCHEMA_VERSION",
    "BASELINE_REPORT_DECLARATIONS",
    "BaselineReport",
    "BaselineReportError",
    "BaselineReportErrorCode",
    "ReportFileArtifacts",
    "RunArtifactEntry",
    "build_baseline_report",
    "find_run_artifacts",
    "from_mapping",
    "write_report_file",
]

BASELINE_REPORT_SCHEMA_NAME = "lima.baseline-report"
BASELINE_REPORT_SCHEMA_VERSION = 1
BASELINE_REPORT_DECLARATIONS = ("baseline_mode_legacy_report_parameters_inert",)

_REPORT_FIELDS = (
    "schema_name",
    "schema_version",
    "run_spec_digest",
    "aggregate_sha256",
    "aggregate_status",
    "attempt_count",
    "evidence_domain",
    "legacy_projection",
    "declarations",
    "sources",
    "counts",
    "coverage_gap_reasons",
    "compression_chain",
    "expert",
    "automation",
    "resources",
)
_REPORT_FIELD_SET = frozenset(_REPORT_FIELDS)

_COUNT_KEYS = (
    "signals",
    "security_issues",
    "hypotheses",
    "confirmed",
    "inconclusive",
    "scanned_files",
    "coverage_gap",
)
_COUNT_KEY_SET = frozenset(_COUNT_KEYS)

_PROJECTIONS = frozenset({"measured", "legacy_projection", "unavailable"})
_SOURCE_KINDS = frozenset({"e2e", "real-world", "scanner", "evidence-domain"})
_EVIDENCE_DOMAINS = frozenset({"v2", "legacy"})
_AGGREGATE_STATUSES = frozenset({"sufficient_sample", "insufficient_sample"})

_CHAIN_FIELDS = (
    "raw_candidates",
    "deterministic_alerts",
    "confirmed",
    "inconclusive",
    "candidates_to_deterministic",
    "deterministic_to_confirmed",
)
_CHAIN_FIELD_SET = frozenset(_CHAIN_FIELDS)
_RATIO_LINK_FIELDS = ("numerator", "denominator", "ratio_basis_points")

_EXPERT_FIELDS = ("active_time_ms_total", "sessions", "reviewer_digests")
_AUTOMATION_FIELDS = (
    "cold_p50_wall_time_ms",
    "cold_p95_wall_time_ms",
    "warm_p50_wall_time_ms",
    "warm_p95_wall_time_ms",
)
_RESOURCE_FIELDS = ("prompt_tokens", "completion_tokens", "cost_micro_usd")

_SIDECAR_FIELDS = (
    "schema_version",
    "run_spec_digest",
    "reviewer_digest",
    "active_time_ms",
    "events",
)
_SIDECAR_FIELD_SET = frozenset(_SIDECAR_FIELDS)

# Transcribed verbatim from lima.repository_scanner.COVERAGE_AFFECTING_SKIPS
# (frozen at the IP-0029 baseline 8e61ddd, blob 97b80b0c, lines 43-51) and
# consumed read-only: the Packet 7.0 import whitelist pins this module's
# import surface and does not admit the scanner module itself.
_COVERAGE_AFFECTING_SKIPS = frozenset(
    {
        "symlink",
        "unreadable",
        "file-size-limit",
        "file-limit",
        "total-size-limit",
        "binary",
        "non-utf8",
    }
)

# The scanner verification ladder (repository_scanner.VERIFICATION_RANK,
# frozen at the same baseline): candidate -> syntax-verified -> corroborated
# -> dataflow-verified -> confirmed.  The report contract freezes the
# partition: confirmed == the "confirmed" rung; inconclusive == the
# candidate and syntax-verified rungs (proposed but never corroborated);
# deterministic_alerts == the corroborated, dataflow-verified and confirmed
# rungs, so raw_candidates == deterministic_alerts + inconclusive always.
_VERIFICATION_STATES = frozenset(
    {"candidate", "syntax-verified", "corroborated", "dataflow-verified", "confirmed"}
)
_INCONCLUSIVE_STATES = frozenset({"candidate", "syntax-verified"})
_CONFIRMED_STATE = "confirmed"
_DETERMINISTIC_STATES = frozenset({"corroborated", "dataflow-verified", "confirmed"})

_DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}")
_RESULT_NAME_PATTERN = re.compile(r"([0-9a-f]{16})-run-([1-9][0-9]*)\.json")
_SIDECAR_SUFFIX = ".expert-timing.json"


class BaselineReportErrorCode(str, enum.Enum):  # noqa: UP042 -- frozen by IP-0029 7.1
    """Frozen wire values for every deterministic baseline-report failure."""

    SCHEMA_NAME_INVALID = "SCHEMA_NAME_INVALID"
    SCHEMA_VERSION_INVALID = "SCHEMA_VERSION_INVALID"
    REQUIRED_FIELD_MISSING = "REQUIRED_FIELD_MISSING"
    UNKNOWN_FIELD = "UNKNOWN_FIELD"
    INVALID_FIELD_TYPE = "INVALID_FIELD_TYPE"
    INVALID_FIELD_VALUE = "INVALID_FIELD_VALUE"
    INVALID_DIGEST = "INVALID_DIGEST"
    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    EVALUATOR_PAYLOAD_UNRECOGNIZED = "EVALUATOR_PAYLOAD_UNRECOGNIZED"
    EVALUATOR_PAYLOAD_INVALID = "EVALUATOR_PAYLOAD_INVALID"
    SIDECAR_INVALID = "SIDECAR_INVALID"
    ARTIFACT_UNREADABLE = "ARTIFACT_UNREADABLE"


_STABLE_MESSAGES: dict[BaselineReportErrorCode, str] = {
    BaselineReportErrorCode.SCHEMA_NAME_INVALID: (
        "Baseline report schema name is invalid."
    ),
    BaselineReportErrorCode.SCHEMA_VERSION_INVALID: (
        "Baseline report schema version is invalid."
    ),
    BaselineReportErrorCode.REQUIRED_FIELD_MISSING: (
        "A required baseline report field is missing."
    ),
    BaselineReportErrorCode.UNKNOWN_FIELD: (
        "Baseline report contains an unknown field for this schema version."
    ),
    BaselineReportErrorCode.INVALID_FIELD_TYPE: (
        "Baseline report field has an invalid type."
    ),
    BaselineReportErrorCode.INVALID_FIELD_VALUE: (
        "Baseline report field has an invalid value."
    ),
    BaselineReportErrorCode.INVALID_DIGEST: (
        "A digest is not a lowercase 64-character hex digest."
    ),
    BaselineReportErrorCode.DIGEST_MISMATCH: (
        "A digest does not match the content it summarizes."
    ),
    BaselineReportErrorCode.EVALUATOR_PAYLOAD_UNRECOGNIZED: (
        "The evaluator payload matches no frozen evaluator output shape."
    ),
    BaselineReportErrorCode.EVALUATOR_PAYLOAD_INVALID: (
        "The evaluator payload violates its frozen output shape."
    ),
    BaselineReportErrorCode.SIDECAR_INVALID: (
        "An expert-timing sidecar document is invalid."
    ),
    BaselineReportErrorCode.ARTIFACT_UNREADABLE: (
        "A baseline run artifact file could not be parsed."
    ),
}


class BaselineReportError(ValueError):
    """Deterministic baseline-report violation with a stable code and message.

    The shape aligns with the frozen collection/spec/result/orchestration
    error precedents while remaining an independent class.  The rendered
    message is exactly the catalog entry above; raw payloads, secrets, and
    field values are never embedded.  Use ``field_path`` for structure-only
    position reporting such as ``$.counts.signals.value``.
    """

    code: BaselineReportErrorCode
    field_path: str

    def __init__(self, code: BaselineReportErrorCode, field_path: str = "") -> None:
        if not isinstance(code, BaselineReportErrorCode):
            raise TypeError("code must be a BaselineReportErrorCode member")
        if not isinstance(field_path, str):
            raise TypeError("field_path must be a str")
        self.code = code
        self.field_path = field_path
        super().__init__(_STABLE_MESSAGES[code])


def _fail(code: BaselineReportErrorCode, field_path: str) -> None:
    raise BaselineReportError(code, field_path)


def _is_hex64(value: object) -> bool:
    return isinstance(value, str) and _DIGEST_PATTERN.fullmatch(value) is not None


def _validated_non_negative(value: object, field_path: str) -> int | None:
    """Pass ``None`` through, or require an exact non-negative ``int``."""

    if value is None:
        return None
    if type(value) is not int:
        _fail(BaselineReportErrorCode.INVALID_FIELD_TYPE, field_path)
    if value < 0:
        _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, field_path)
    return value


class _ReadOnlyMapping:
    """A deeply immutable read-only view over one validated report mapping.

    Content is stored as an immutable tuple of key-value pairs, so no mutable
    builtin container is reachable through the view.  Reads (subscript,
    ``len``, iteration, membership, ``get``/``keys``/``values``/``items``)
    behave like a plain ``dict`` over the already-validated frozen items;
    every mutating operation and every attribute assignment fails closed
    with ``TypeError`` (the IP-0025 frozen-mapping precedent).
    """

    __slots__ = ("_items",)

    def __init__(self, items: dict[str, object]) -> None:
        object.__setattr__(self, "_items", tuple(items.items()))

    def _as_dict(self) -> dict[str, object]:
        return dict(self._items)

    def __setattr__(self, name: str, value: object) -> None:
        raise TypeError("baseline report mappings are deeply immutable")

    def __delattr__(self, name: str) -> None:
        raise TypeError("baseline report mappings are deeply immutable")

    def __getitem__(self, key: str) -> object:
        for item_key, item_value in self._items:
            if item_key == key:
                return item_value
        raise KeyError(key)

    def __iter__(self):
        return iter(self._as_dict())

    def __len__(self) -> int:
        return len(self._items)

    def __contains__(self, key: object) -> bool:
        return any(item_key == key for item_key, _ in self._items)

    def keys(self) -> tuple[str, ...]:
        return tuple(item_key for item_key, _ in self._items)

    def values(self) -> tuple[object, ...]:
        return tuple(item_value for _, item_value in self._items)

    def items(self) -> tuple[tuple[str, object], ...]:
        return self._items

    def get(self, key: str, default: object = None) -> object:
        for item_key, item_value in self._items:
            if item_key == key:
                return item_value
        return default

    def __setitem__(self, key: str, value: object) -> None:
        raise TypeError("baseline report mappings are deeply immutable")

    def __delitem__(self, key: str) -> None:
        raise TypeError("baseline report mappings are deeply immutable")

    def update(self, *args: object, **kwargs: object) -> None:
        raise TypeError("baseline report mappings are deeply immutable")

    def pop(self, *args: object, **kwargs: object) -> object:
        raise TypeError("baseline report mappings are deeply immutable")

    def popitem(self) -> tuple[str, object]:
        raise TypeError("baseline report mappings are deeply immutable")

    def setdefault(self, *args: object, **kwargs: object) -> object:
        raise TypeError("baseline report mappings are deeply immutable")

    def clear(self) -> None:
        raise TypeError("baseline report mappings are deeply immutable")

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _ReadOnlyMapping):
            return self._as_dict() == other._as_dict()
        if isinstance(other, dict):
            return self._as_dict() == other
        return NotImplemented

    def __repr__(self) -> str:
        return repr(self._as_dict())


@dataclasses.dataclass(frozen=True, slots=True)
class SourceEntry:
    """One injected source fingerprint: a kind plus its payload digest."""

    kind: str
    payload_sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class CountEntry:
    """One counting position: a value plus its three-valued projection mark."""

    value: int | None
    projection: str


@dataclasses.dataclass(frozen=True, slots=True)
class RatioLink:
    """One compression link with integer basis points (floor semantics)."""

    numerator: int | None
    denominator: int | None
    ratio_basis_points: int | None


@dataclasses.dataclass(frozen=True, slots=True)
class CompressionChain:
    """The raw -> deterministic -> confirmed compression chain."""

    raw_candidates: int | None
    deterministic_alerts: int | None
    confirmed: int | None
    inconclusive: int | None
    candidates_to_deterministic: RatioLink
    deterministic_to_confirmed: RatioLink


@dataclasses.dataclass(frozen=True, slots=True)
class ExpertFace:
    """The expert active-time face aggregated from sidecar documents."""

    active_time_ms_total: int | None
    sessions: int
    reviewer_digests: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class AutomationFace:
    """The automation timing face passed through from the run aggregate."""

    cold_p50_wall_time_ms: int | None
    cold_p95_wall_time_ms: int | None
    warm_p50_wall_time_ms: int | None
    warm_p95_wall_time_ms: int | None


@dataclasses.dataclass(frozen=True, slots=True)
class ResourcesFace:
    """The resource face, honestly absent in the offline slice (all null)."""

    prompt_tokens: int | None
    completion_tokens: int | None
    cost_micro_usd: int | None


@dataclasses.dataclass(frozen=True, slots=True)
class BaselineReport:
    """The frozen, canonical, sealable aggregate report of one baseline run.

    Instances are constructed through :func:`build_baseline_report` or
    :func:`from_mapping` so that every field carries the validated
    schema-v1 shape; the full strict validation runs on both paths.  The
    nested ``counts`` and ``coverage_gap_reasons`` containers are deeply
    immutable read-only mapping views and the list-like fields are tuples.
    Canonical bytes and the SHA-256 digest are always recomputed from the
    frozen content exclusively through ``lima.contracts.codec``.
    """

    schema_name: str
    schema_version: int
    run_spec_digest: str
    aggregate_sha256: str
    aggregate_status: str
    attempt_count: int
    evidence_domain: str
    legacy_projection: bool
    declarations: tuple[str, ...]
    sources: tuple[SourceEntry, ...]
    counts: _ReadOnlyMapping
    coverage_gap_reasons: _ReadOnlyMapping
    compression_chain: CompressionChain
    expert: ExpertFace
    automation: AutomationFace
    resources: ResourcesFace

    def to_canonical_value(self) -> dict[str, object]:
        """Return a fresh, plain JSON-subset tree sharing no mutable state."""

        counts: dict[str, object] = {}
        for key in _COUNT_KEYS:
            entry: CountEntry = self.counts[key]  # type: ignore[assignment]
            counts[key] = {"value": entry.value, "projection": entry.projection}
        chain = self.compression_chain
        return {
            "schema_name": self.schema_name,
            "schema_version": self.schema_version,
            "run_spec_digest": self.run_spec_digest,
            "aggregate_sha256": self.aggregate_sha256,
            "aggregate_status": self.aggregate_status,
            "attempt_count": self.attempt_count,
            "evidence_domain": self.evidence_domain,
            "legacy_projection": self.legacy_projection,
            "declarations": list(self.declarations),
            "sources": [
                {"kind": entry.kind, "payload_sha256": entry.payload_sha256}
                for entry in self.sources
            ],
            "counts": counts,
            "coverage_gap_reasons": dict(sorted(self.coverage_gap_reasons.items())),
            "compression_chain": {
                "raw_candidates": chain.raw_candidates,
                "deterministic_alerts": chain.deterministic_alerts,
                "confirmed": chain.confirmed,
                "inconclusive": chain.inconclusive,
                "candidates_to_deterministic": {
                    "numerator": chain.candidates_to_deterministic.numerator,
                    "denominator": chain.candidates_to_deterministic.denominator,
                    "ratio_basis_points": (
                        chain.candidates_to_deterministic.ratio_basis_points
                    ),
                },
                "deterministic_to_confirmed": {
                    "numerator": chain.deterministic_to_confirmed.numerator,
                    "denominator": chain.deterministic_to_confirmed.denominator,
                    "ratio_basis_points": (
                        chain.deterministic_to_confirmed.ratio_basis_points
                    ),
                },
            },
            "expert": {
                "active_time_ms_total": self.expert.active_time_ms_total,
                "sessions": self.expert.sessions,
                "reviewer_digests": list(self.expert.reviewer_digests),
            },
            "automation": {
                "cold_p50_wall_time_ms": self.automation.cold_p50_wall_time_ms,
                "cold_p95_wall_time_ms": self.automation.cold_p95_wall_time_ms,
                "warm_p50_wall_time_ms": self.automation.warm_p50_wall_time_ms,
                "warm_p95_wall_time_ms": self.automation.warm_p95_wall_time_ms,
            },
            "resources": {
                "prompt_tokens": self.resources.prompt_tokens,
                "completion_tokens": self.resources.completion_tokens,
                "cost_micro_usd": self.resources.cost_micro_usd,
            },
        }

    def canonical_bytes(self) -> bytes:
        """Return the canonical UTF-8 JSON bytes via ``lima.contracts.codec``."""

        return canonical_encode(self.to_canonical_value())

    def content_digest(self) -> str:
        """Return the lowercase hex SHA-256 of :meth:`canonical_bytes`."""

        return compute_content_digest(self.canonical_bytes())


@dataclasses.dataclass(frozen=True, slots=True)
class ReportFileArtifacts:
    """Path and SHA-256 digest of one persisted report artifact file."""

    report_path: pathlib.Path
    report_sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class RunArtifactEntry:
    """One discovered baseline run result file and its paired sidecar."""

    digest16: str
    sequence: int
    result_path: pathlib.Path
    sidecar_path: pathlib.Path | None
    sample_count: int
    is_aggregate: bool


def _check_exact_fields(
    container: dict[object, object], fields: tuple[str, ...], prefix: str
) -> None:
    """Reject unknown keys, then require every frozen key, in frozen order."""

    allowed = frozenset(fields)
    for key in container:
        if key not in allowed:
            _fail(BaselineReportErrorCode.UNKNOWN_FIELD, f"{prefix}.{key}")
    for field in fields:
        if field not in container:
            _fail(BaselineReportErrorCode.REQUIRED_FIELD_MISSING, f"{prefix}.{field}")


def _validated_count_entry(value: object, key: str) -> CountEntry:
    prefix = f"$.counts.{key}"
    if not isinstance(value, dict):
        _fail(BaselineReportErrorCode.INVALID_FIELD_TYPE, prefix)
    _check_exact_fields(value, ("value", "projection"), prefix)
    count_value = _validated_non_negative(value["value"], f"{prefix}.value")
    projection = value["projection"]
    if not isinstance(projection, str) or projection not in _PROJECTIONS:
        _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, f"{prefix}.projection")
    if (projection == "unavailable") != (count_value is None):
        _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, f"{prefix}.value")
    return CountEntry(value=count_value, projection=projection)


def _validated_ratio_link(value: object, prefix: str) -> RatioLink:
    if not isinstance(value, dict):
        _fail(BaselineReportErrorCode.INVALID_FIELD_TYPE, prefix)
    _check_exact_fields(value, _RATIO_LINK_FIELDS, prefix)
    numerator = _validated_non_negative(value["numerator"], f"{prefix}.numerator")
    denominator = _validated_non_negative(value["denominator"], f"{prefix}.denominator")
    basis = value["ratio_basis_points"]
    if (numerator is None) != (denominator is None):
        _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, prefix)
    if numerator is None or denominator is None:
        if basis is not None:
            _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, f"{prefix}.ratio_basis_points")
        return RatioLink(numerator=None, denominator=None, ratio_basis_points=None)
    if denominator == 0:
        if basis is not None:
            _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, f"{prefix}.ratio_basis_points")
        return RatioLink(numerator=numerator, denominator=0, ratio_basis_points=None)
    if type(basis) is not int:
        _fail(BaselineReportErrorCode.INVALID_FIELD_TYPE, f"{prefix}.ratio_basis_points")
    if basis != numerator * 10000 // denominator:
        _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, f"{prefix}.ratio_basis_points")
    return RatioLink(numerator=numerator, denominator=denominator, ratio_basis_points=basis)


def _freeze_document(mapping: object) -> BaselineReport:
    """Run the full strict schema-v1 validation and freeze one report.

    This is the single validation and construction core shared by
    :func:`from_mapping` (external documents) and
    :func:`build_baseline_report` (internal projection output), so a built
    report always round-trips losslessly through ``from_mapping``.
    """

    if not isinstance(mapping, dict):
        _fail(BaselineReportErrorCode.INVALID_FIELD_TYPE, "$")
    _check_exact_fields(mapping, _REPORT_FIELDS, "$")

    schema_name = mapping["schema_name"]
    if (
        not isinstance(schema_name, str)
        or schema_name != BASELINE_REPORT_SCHEMA_NAME
    ):
        _fail(BaselineReportErrorCode.SCHEMA_NAME_INVALID, "$.schema_name")
    schema_version = mapping["schema_version"]
    if type(schema_version) is not int or schema_version != BASELINE_REPORT_SCHEMA_VERSION:
        _fail(BaselineReportErrorCode.SCHEMA_VERSION_INVALID, "$.schema_version")
    if not _is_hex64(mapping["run_spec_digest"]):
        _fail(BaselineReportErrorCode.INVALID_DIGEST, "$.run_spec_digest")
    if not _is_hex64(mapping["aggregate_sha256"]):
        _fail(BaselineReportErrorCode.INVALID_DIGEST, "$.aggregate_sha256")

    aggregate_status = mapping["aggregate_status"]
    if not isinstance(aggregate_status, str) or aggregate_status not in _AGGREGATE_STATUSES:
        _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, "$.aggregate_status")
    attempt_count = mapping["attempt_count"]
    if type(attempt_count) is not int:
        _fail(BaselineReportErrorCode.INVALID_FIELD_TYPE, "$.attempt_count")
    if attempt_count < 1:
        _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, "$.attempt_count")

    evidence_domain = mapping["evidence_domain"]
    if not isinstance(evidence_domain, str) or evidence_domain not in _EVIDENCE_DOMAINS:
        _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, "$.evidence_domain")
    legacy_projection = mapping["legacy_projection"]
    if type(legacy_projection) is not bool:
        _fail(BaselineReportErrorCode.INVALID_FIELD_TYPE, "$.legacy_projection")
    if legacy_projection != (evidence_domain == "legacy"):
        _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, "$.legacy_projection")

    declarations = mapping["declarations"]
    if not isinstance(declarations, list):
        _fail(BaselineReportErrorCode.INVALID_FIELD_TYPE, "$.declarations")
    if declarations != list(BASELINE_REPORT_DECLARATIONS):
        _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, "$.declarations")

    sources_value = mapping["sources"]
    if not isinstance(sources_value, list):
        _fail(BaselineReportErrorCode.INVALID_FIELD_TYPE, "$.sources")
    sources: list[SourceEntry] = []
    seen_kinds: set[str] = set()
    for index, entry in enumerate(sources_value):
        prefix = f"$.sources[{index}]"
        if not isinstance(entry, dict):
            _fail(BaselineReportErrorCode.INVALID_FIELD_TYPE, prefix)
        _check_exact_fields(entry, ("kind", "payload_sha256"), prefix)
        kind = entry["kind"]
        if not isinstance(kind, str) or kind not in _SOURCE_KINDS:
            _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, f"{prefix}.kind")
        if not _is_hex64(entry["payload_sha256"]):
            _fail(BaselineReportErrorCode.INVALID_DIGEST, f"{prefix}.payload_sha256")
        if kind in seen_kinds:
            _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, "$.sources")
        seen_kinds.add(kind)
        sources.append(SourceEntry(kind=kind, payload_sha256=entry["payload_sha256"]))
    if seen_kinds and [entry.kind for entry in sources] != sorted(seen_kinds):
        _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, "$.sources")

    counts_value = mapping["counts"]
    if not isinstance(counts_value, dict):
        _fail(BaselineReportErrorCode.INVALID_FIELD_TYPE, "$.counts")
    _check_exact_fields(counts_value, _COUNT_KEYS, "$.counts")
    counts = {
        key: _validated_count_entry(counts_value[key], key) for key in _COUNT_KEYS
    }

    reasons_value = mapping["coverage_gap_reasons"]
    if not isinstance(reasons_value, dict):
        _fail(BaselineReportErrorCode.INVALID_FIELD_TYPE, "$.coverage_gap_reasons")
    reasons: dict[str, int] = {}
    for key, value in reasons_value.items():
        if not isinstance(key, str) or key not in _COVERAGE_AFFECTING_SKIPS:
            _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, f"$.coverage_gap_reasons.{key}")
        count_value = _validated_non_negative(value, f"$.coverage_gap_reasons.{key}")
        reasons[key] = count_value if count_value is not None else 0
    if list(reasons) != sorted(reasons):
        _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, "$.coverage_gap_reasons")
    gap_value = counts["coverage_gap"].value
    if not reasons:
        if gap_value not in (None, 0):
            _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, "$.coverage_gap_reasons")
    elif gap_value is None or sum(reasons.values()) != gap_value:
        _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, "$.coverage_gap_reasons")

    chain_value = mapping["compression_chain"]
    if not isinstance(chain_value, dict):
        _fail(BaselineReportErrorCode.INVALID_FIELD_TYPE, "$.compression_chain")
    _check_exact_fields(chain_value, _CHAIN_FIELDS, "$.compression_chain")
    chain = CompressionChain(
        raw_candidates=_validated_non_negative(
            chain_value["raw_candidates"], "$.compression_chain.raw_candidates"
        ),
        deterministic_alerts=_validated_non_negative(
            chain_value["deterministic_alerts"], "$.compression_chain.deterministic_alerts"
        ),
        confirmed=_validated_non_negative(
            chain_value["confirmed"], "$.compression_chain.confirmed"
        ),
        inconclusive=_validated_non_negative(
            chain_value["inconclusive"], "$.compression_chain.inconclusive"
        ),
        candidates_to_deterministic=_validated_ratio_link(
            chain_value["candidates_to_deterministic"],
            "$.compression_chain.candidates_to_deterministic",
        ),
        deterministic_to_confirmed=_validated_ratio_link(
            chain_value["deterministic_to_confirmed"],
            "$.compression_chain.deterministic_to_confirmed",
        ),
    )

    expert_value = mapping["expert"]
    if not isinstance(expert_value, dict):
        _fail(BaselineReportErrorCode.INVALID_FIELD_TYPE, "$.expert")
    _check_exact_fields(expert_value, _EXPERT_FIELDS, "$.expert")
    active_time_ms_total = _validated_non_negative(
        expert_value["active_time_ms_total"], "$.expert.active_time_ms_total"
    )
    sessions = expert_value["sessions"]
    if type(sessions) is not int:
        _fail(BaselineReportErrorCode.INVALID_FIELD_TYPE, "$.expert.sessions")
    if sessions < 0:
        _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, "$.expert.sessions")
    digests_value = expert_value["reviewer_digests"]
    if not isinstance(digests_value, list):
        _fail(BaselineReportErrorCode.INVALID_FIELD_TYPE, "$.expert.reviewer_digests")
    digests: list[str] = []
    for index, digest in enumerate(digests_value):
        if not _is_hex64(digest):
            _fail(
                BaselineReportErrorCode.INVALID_DIGEST,
                f"$.expert.reviewer_digests[{index}]",
            )
        digests.append(digest)
    if digests != sorted(digests) or len(set(digests)) != len(digests):
        _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, "$.expert.reviewer_digests")
    if (sessions == 0) != (active_time_ms_total is None and not digests):
        _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, "$.expert.sessions")

    automation_value = mapping["automation"]
    if not isinstance(automation_value, dict):
        _fail(BaselineReportErrorCode.INVALID_FIELD_TYPE, "$.automation")
    _check_exact_fields(automation_value, _AUTOMATION_FIELDS, "$.automation")
    automation = AutomationFace(
        cold_p50_wall_time_ms=_validated_non_negative(
            automation_value["cold_p50_wall_time_ms"],
            "$.automation.cold_p50_wall_time_ms",
        ),
        cold_p95_wall_time_ms=_validated_non_negative(
            automation_value["cold_p95_wall_time_ms"],
            "$.automation.cold_p95_wall_time_ms",
        ),
        warm_p50_wall_time_ms=_validated_non_negative(
            automation_value["warm_p50_wall_time_ms"],
            "$.automation.warm_p50_wall_time_ms",
        ),
        warm_p95_wall_time_ms=_validated_non_negative(
            automation_value["warm_p95_wall_time_ms"],
            "$.automation.warm_p95_wall_time_ms",
        ),
    )
    percentile_values = (
        automation.cold_p50_wall_time_ms,
        automation.cold_p95_wall_time_ms,
        automation.warm_p50_wall_time_ms,
        automation.warm_p95_wall_time_ms,
    )
    if aggregate_status == "sufficient_sample":
        if any(value is None for value in percentile_values):
            _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, "$.automation")
    elif any(value is not None for value in percentile_values):
        _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, "$.automation")

    resources_value = mapping["resources"]
    if not isinstance(resources_value, dict):
        _fail(BaselineReportErrorCode.INVALID_FIELD_TYPE, "$.resources")
    _check_exact_fields(resources_value, _RESOURCE_FIELDS, "$.resources")
    for field in _RESOURCE_FIELDS:
        if resources_value[field] is not None:
            _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, f"$.resources.{field}")

    return BaselineReport(
        schema_name=schema_name,
        schema_version=schema_version,
        run_spec_digest=mapping["run_spec_digest"],
        aggregate_sha256=mapping["aggregate_sha256"],
        aggregate_status=aggregate_status,
        attempt_count=attempt_count,
        evidence_domain=evidence_domain,
        legacy_projection=legacy_projection,
        declarations=tuple(declarations),
        sources=tuple(sources),
        counts=_ReadOnlyMapping({key: counts[key] for key in _COUNT_KEYS}),
        coverage_gap_reasons=_ReadOnlyMapping(reasons),
        compression_chain=chain,
        expert=ExpertFace(
            active_time_ms_total=active_time_ms_total,
            sessions=sessions,
            reviewer_digests=tuple(digests),
        ),
        automation=automation,
        resources=ResourcesFace(
            prompt_tokens=None, completion_tokens=None, cost_micro_usd=None
        ),
    )


def from_mapping(mapping: object) -> BaselineReport:
    """Strictly validate and freeze one baseline report mapping (schema v1).

    Required-field presence, unknown-key rejection at every nesting level,
    exact types, value domains, digest shapes, enum domains, and every
    frozen cross-field rule (legacy-projection pairing, unavailable-null
    pairing, coverage-reason sums, all-or-nothing automation percentiles,
    ratio floor arithmetic, null-only resources) are enforced; any
    violation raises :class:`BaselineReportError`.
    """

    return _freeze_document(mapping)


def _gate_summary(summary: object) -> BaselineRunResult:
    """Validate the frozen summary shape and cross-check its aggregate digest."""

    if not isinstance(summary, BaselineRunSummary):
        _fail(BaselineReportErrorCode.INVALID_FIELD_TYPE, "$.summary")
    attempts = summary.attempts
    if not isinstance(attempts, tuple) or not attempts:
        _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, "$.summary.attempts")
    aggregate = summary.aggregate
    if not isinstance(aggregate, BaselineRunResult):
        _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, "$.summary.aggregate")
    if not _is_hex64(aggregate.run_spec_digest):
        _fail(
            BaselineReportErrorCode.INVALID_FIELD_VALUE,
            "$.summary.aggregate.run_spec_digest",
        )
    if not isinstance(aggregate.status, str) or (
        aggregate.status not in _AGGREGATE_STATUSES
    ):
        _fail(BaselineReportErrorCode.INVALID_FIELD_VALUE, "$.summary.aggregate.status")
    if not _is_hex64(summary.aggregate_sha256):
        _fail(
            BaselineReportErrorCode.INVALID_FIELD_VALUE, "$.summary.aggregate_sha256"
        )
    if summary.aggregate_sha256 != aggregate.content_digest():
        _fail(BaselineReportErrorCode.DIGEST_MISMATCH, "$.aggregate_sha256")
    return aggregate


def _gate_sidecar(sidecar: object, index: int, run_spec_digest: str) -> None:
    """Validate one expert-timing sidecar document against the frozen shape."""

    prefix = f"$.expert_sidecars[{index}]"
    if not isinstance(sidecar, dict):
        _fail(BaselineReportErrorCode.SIDECAR_INVALID, prefix)
    for key in sidecar:
        if key not in _SIDECAR_FIELD_SET:
            _fail(BaselineReportErrorCode.SIDECAR_INVALID, f"{prefix}.{key}")
    for field in _SIDECAR_FIELDS:
        if field not in sidecar:
            _fail(BaselineReportErrorCode.SIDECAR_INVALID, f"{prefix}.{field}")
    if type(sidecar["schema_version"]) is not int or sidecar["schema_version"] != 1:
        _fail(BaselineReportErrorCode.SIDECAR_INVALID, f"{prefix}.schema_version")
    sidecar_digest = sidecar["run_spec_digest"]
    if not _is_hex64(sidecar_digest) or sidecar_digest != run_spec_digest:
        _fail(BaselineReportErrorCode.SIDECAR_INVALID, f"{prefix}.run_spec_digest")
    if not _is_hex64(sidecar["reviewer_digest"]):
        _fail(BaselineReportErrorCode.SIDECAR_INVALID, f"{prefix}.reviewer_digest")
    if (
        type(sidecar["active_time_ms"]) is not int
        or sidecar["active_time_ms"] < 0
    ):
        _fail(BaselineReportErrorCode.SIDECAR_INVALID, f"{prefix}.active_time_ms")
    if not isinstance(sidecar["events"], list):
        _fail(BaselineReportErrorCode.SIDECAR_INVALID, f"{prefix}.events")


def _is_e2e_shape(payload: dict[object, object]) -> bool:
    for key in ("name", "metrics", "by_split", "case_results", "dataset"):
        if key not in payload:
            return False
    metrics = payload["metrics"]
    if not isinstance(metrics, dict):
        return False
    for key in ("tp", "fp", "fn"):
        value = metrics.get(key)
        if type(value) is not int or value < 0:
            return False
    return True


def _is_real_world_shape(payload: dict[object, object]) -> bool:
    for key in ("mode", "scanner_profile", "metrics"):
        if key not in payload:
            return False
    results = payload.get("results")
    if not isinstance(results, list):
        return False
    for case in results:
        if not isinstance(case, dict):
            return False
        deterministic = case.get("deterministic")
        if not isinstance(deterministic, dict):
            return False
        total_findings = deterministic.get("total_findings")
        if not isinstance(total_findings, dict):
            return False
        for value in total_findings.values():
            if type(value) is not int or value < 0:
                return False
        workspace = deterministic.get("workspace")
        if not isinstance(workspace, dict):
            return False
        for revision_face in workspace.values():
            if not isinstance(revision_face, dict):
                return False
            if type(revision_face.get("files")) is not int or revision_face["files"] < 0:
                return False
            skipped = revision_face.get("skipped")
            if not isinstance(skipped, dict):
                return False
            for count in skipped.values():
                if type(count) is not int or count < 0:
                    return False
    return True


def _recognize_evaluator_payload(evaluator_payload: object) -> str:
    """Identify the one injected evaluator payload by its frozen shape.

    Returns ``"scanner"``, ``"e2e"`` or ``"real-world"``; everything else
    (including ``None``, repair-evaluator shapes, unknown schema versions,
    and key-incomplete or type-violating dictionaries) fails closed with
    ``EVALUATOR_PAYLOAD_UNRECOGNIZED``.
    """

    if not isinstance(evaluator_payload, dict):
        if hasattr(evaluator_payload, "report") and hasattr(
            evaluator_payload, "inventory"
        ):
            return "scanner"
        _fail(
            BaselineReportErrorCode.EVALUATOR_PAYLOAD_UNRECOGNIZED,
            "$.evaluator_payload",
        )
    version = evaluator_payload.get("schema_version")
    if type(version) is int and version == 1 and _is_e2e_shape(evaluator_payload):
        return "e2e"
    if type(version) is int and version == 2 and _is_real_world_shape(evaluator_payload):
        return "real-world"
    _fail(
        BaselineReportErrorCode.EVALUATOR_PAYLOAD_UNRECOGNIZED,
        "$.evaluator_payload",
    )


def _validate_scanner_payload(evaluator_payload: object) -> None:
    """Deep-validate a recognized scanner payload (frozen output shape)."""

    report = evaluator_payload.report
    inventory = evaluator_payload.inventory
    findings = getattr(report, "findings", None)
    if not isinstance(findings, list):
        _fail(BaselineReportErrorCode.EVALUATOR_PAYLOAD_INVALID, "$.evaluator_payload")
    for finding in findings:
        if not isinstance(finding, Finding):
            _fail(
                BaselineReportErrorCode.EVALUATOR_PAYLOAD_INVALID,
                "$.evaluator_payload",
            )
        state = getattr(finding, "verification_state", None)
        if not isinstance(state, str) or state not in _VERIFICATION_STATES:
            _fail(
                BaselineReportErrorCode.EVALUATOR_PAYLOAD_INVALID,
                "$.evaluator_payload",
            )
    collaboration = getattr(report, "collaboration", None)
    if not isinstance(collaboration, dict):
        _fail(
            BaselineReportErrorCode.EVALUATOR_PAYLOAD_INVALID, "$.evaluator_payload"
        )
    if "scanned_files" not in collaboration or type(
        collaboration["scanned_files"]
    ) is not int or collaboration["scanned_files"] < 0:
        _fail(
            BaselineReportErrorCode.EVALUATOR_PAYLOAD_INVALID, "$.evaluator_payload"
        )
    if "skipped" not in collaboration or not isinstance(
        collaboration["skipped"], dict
    ):
        _fail(
            BaselineReportErrorCode.EVALUATOR_PAYLOAD_INVALID, "$.evaluator_payload"
        )
    for count in collaboration["skipped"].values():
        if type(count) is not int or count < 0:
            _fail(
                BaselineReportErrorCode.EVALUATOR_PAYLOAD_INVALID,
                "$.evaluator_payload",
            )
    if not callable(getattr(inventory, "to_dict", None)):
        _fail(
            BaselineReportErrorCode.EVALUATOR_PAYLOAD_INVALID, "$.evaluator_payload"
        )


def _fingerprint(wire_value: object) -> str:
    """The frozen input-fingerprint rule for wire-value payloads.

    This is the input fingerprint of an injected evaluator or bundle
    payload (which may itself contain floats), distinct from the canonical
    artifact encoding: sorted-key compact UTF-8 JSON via the stdlib, then
    SHA-256.  The same payload always yields the same fingerprint.
    """

    encoded = json.dumps(
        wire_value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _skip_face(skipped: dict[object, int]) -> tuple[int, dict[str, int]]:
    """Sum coverage-affecting skip counts and collect per-reason tallies."""

    reasons: dict[str, int] = {}
    total = 0
    for reason, count in skipped.items():
        if isinstance(reason, str) and reason in _COVERAGE_AFFECTING_SKIPS and count > 0:
            reasons[reason] = count
            total += count
    return total, dict(sorted(reasons.items()))


def _ratio_link(
    numerator: int | None, denominator: int | None
) -> dict[str, int | None]:
    """One compression link: integer basis points with floor semantics.

    The link is fully null when either position is absent; a zero
    denominator keeps both counts but yields a null ratio (never zero).
    """

    if numerator is None or denominator is None:
        return {
            "numerator": None,
            "denominator": None,
            "ratio_basis_points": None,
        }
    basis = numerator * 10000 // denominator if denominator > 0 else None
    return {
        "numerator": numerator,
        "denominator": denominator,
        "ratio_basis_points": basis,
    }


def build_baseline_report(
    summary: object,
    evaluator_payload: object,
    *,
    expert_sidecars: object = (),
    bundle: object = None,
) -> BaselineReport:
    """Project one canonical baseline report from the frozen upstream faces.

    Consumes exactly one orchestrated summary (isinstance-gated against
    ``BaselineRunSummary`` with its aggregate digest cross-checked), one
    injected evaluator payload (recognized structurally as a scanner scan
    result, an e2e harness output, or a real-world evaluation output; the
    scanner shape is then deep-validated), an optional sequence of
    expert-timing sidecar documents, and an optional ``EvidenceDomainBundle``
    whose structural presence alone marks the v2 evidence domain.  The gate
    order is frozen: summary shape, aggregate digest cross-check, sidecar
    documents, bundle, payload recognition, payload deep validation,
    projection, strict freeze.  Every position without a faithful
    derivation stays null and explicitly marked; nothing is fabricated.
    """

    aggregate = _gate_summary(summary)
    run_spec_digest = aggregate.run_spec_digest
    sidecars = tuple(expert_sidecars)
    for index, sidecar in enumerate(sidecars):
        _gate_sidecar(sidecar, index, run_spec_digest)
    if bundle is not None and not isinstance(bundle, EvidenceDomainBundle):
        _fail(BaselineReportErrorCode.INVALID_FIELD_TYPE, "$.bundle")
    kind = _recognize_evaluator_payload(evaluator_payload)

    counts_doc: dict[str, tuple[int | None, str]] = {}
    source_pairs: list[tuple[str, str]] = []
    raw_candidates: int | None = None
    deterministic_alerts: int | None = None
    chain_confirmed: int | None = None
    chain_inconclusive: int | None = None
    scanned_files: int | None = None
    coverage_gap: int | None = None
    coverage_reasons: dict[str, int] = {}

    if kind == "scanner":
        _validate_scanner_payload(evaluator_payload)
        report = evaluator_payload.report
        findings = report.findings
        signals = 0
        security_issues = 0
        for finding in findings:
            converted = finding_to_domain_bundle(finding)
            signals += len(converted.signals)
            security_issues += len(converted.security_issues)
        states = [finding.verification_state for finding in findings]
        raw_candidates = len(findings)
        deterministic_alerts = sum(
            1 for state in states if state in _DETERMINISTIC_STATES
        )
        chain_confirmed = sum(1 for state in states if state == _CONFIRMED_STATE)
        chain_inconclusive = sum(
            1 for state in states if state in _INCONCLUSIVE_STATES
        )
        scanned_files = report.collaboration["scanned_files"]
        coverage_gap, coverage_reasons = _skip_face(report.collaboration["skipped"])
        if bundle is not None:
            counts_doc["signals"] = (len(bundle.signals), "measured")
            counts_doc["security_issues"] = (
                len(bundle.security_issues),
                "measured",
            )
            counts_doc["hypotheses"] = (
                len(bundle.vulnerability_hypotheses),
                "measured",
            )
        else:
            counts_doc["signals"] = (signals, "legacy_projection")
            counts_doc["security_issues"] = (
                security_issues,
                "legacy_projection",
            )
            counts_doc["hypotheses"] = (None, "unavailable")
        counts_doc["confirmed"] = (chain_confirmed, "legacy_projection")
        counts_doc["inconclusive"] = (chain_inconclusive, "legacy_projection")
        counts_doc["scanned_files"] = (scanned_files, "measured")
        counts_doc["coverage_gap"] = (coverage_gap, "measured")
        wire = {
            **report.to_dict(),
            "workspace": evaluator_payload.inventory.to_dict(),
        }
        source_pairs.append(("scanner", _fingerprint(wire)))
    else:
        if bundle is not None:
            counts_doc["signals"] = (len(bundle.signals), "measured")
            counts_doc["security_issues"] = (
                len(bundle.security_issues),
                "measured",
            )
            counts_doc["hypotheses"] = (
                len(bundle.vulnerability_hypotheses),
                "measured",
            )
        else:
            counts_doc["signals"] = (None, "unavailable")
            counts_doc["security_issues"] = (None, "unavailable")
            counts_doc["hypotheses"] = (None, "unavailable")
        counts_doc["confirmed"] = (None, "unavailable")
        counts_doc["inconclusive"] = (None, "unavailable")
        if kind == "e2e":
            raw_candidates = (
                evaluator_payload["metrics"]["tp"] + evaluator_payload["metrics"]["fp"]
            )
            counts_doc["scanned_files"] = (None, "unavailable")
            counts_doc["coverage_gap"] = (None, "unavailable")
        else:
            scanned_files = 0
            coverage_gap = 0
            raw_candidates = 0
            for case in evaluator_payload["results"]:
                deterministic = case["deterministic"]
                raw_candidates += sum(deterministic["total_findings"].values())
                for revision_face in deterministic["workspace"].values():
                    scanned_files += revision_face["files"]
                    case_gap, case_reasons = _skip_face(revision_face["skipped"])
                    coverage_gap += case_gap
                    for reason, count in case_reasons.items():
                        coverage_reasons[reason] = (
                            coverage_reasons.get(reason, 0) + count
                        )
            coverage_reasons = dict(sorted(coverage_reasons.items()))
            counts_doc["scanned_files"] = (scanned_files, "measured")
            counts_doc["coverage_gap"] = (coverage_gap, "measured")
        source_pairs.append((kind, _fingerprint(evaluator_payload)))

    evidence_domain = "v2" if bundle is not None else "legacy"
    if bundle is not None:
        source_pairs.append(("evidence-domain", _fingerprint(bundle.to_dict())))

    if sidecars:
        active_time_ms_total: int | None = sum(
            sidecar["active_time_ms"] for sidecar in sidecars
        )
    else:
        active_time_ms_total = None
    reviewer_digests = sorted({sidecar["reviewer_digest"] for sidecar in sidecars})

    document = {
        "schema_name": BASELINE_REPORT_SCHEMA_NAME,
        "schema_version": BASELINE_REPORT_SCHEMA_VERSION,
        "run_spec_digest": run_spec_digest,
        "aggregate_sha256": summary.aggregate_sha256,
        "aggregate_status": aggregate.status,
        "attempt_count": len(summary.attempts),
        "evidence_domain": evidence_domain,
        "legacy_projection": evidence_domain == "legacy",
        "declarations": list(BASELINE_REPORT_DECLARATIONS),
        "sources": [
            {"kind": source_kind, "payload_sha256": source_digest}
            for source_kind, source_digest in sorted(source_pairs)
        ],
        "counts": {
            key: {"value": value, "projection": projection}
            for key, (value, projection) in (
                (key, counts_doc[key]) for key in _COUNT_KEYS
            )
        },
        "coverage_gap_reasons": coverage_reasons,
        "compression_chain": {
            "raw_candidates": raw_candidates,
            "deterministic_alerts": deterministic_alerts,
            "confirmed": chain_confirmed,
            "inconclusive": chain_inconclusive,
            "candidates_to_deterministic": _ratio_link(
                deterministic_alerts, raw_candidates
            ),
            "deterministic_to_confirmed": _ratio_link(
                chain_confirmed, deterministic_alerts
            ),
        },
        "expert": {
            "active_time_ms_total": active_time_ms_total,
            "sessions": len(sidecars),
            "reviewer_digests": reviewer_digests,
        },
        "automation": {
            "cold_p50_wall_time_ms": aggregate.cold_p50_wall_time_ms,
            "cold_p95_wall_time_ms": aggregate.cold_p95_wall_time_ms,
            "warm_p50_wall_time_ms": aggregate.warm_p50_wall_time_ms,
            "warm_p95_wall_time_ms": aggregate.warm_p95_wall_time_ms,
        },
        "resources": {
            "prompt_tokens": None,
            "completion_tokens": None,
            "cost_micro_usd": None,
        },
    }
    return _freeze_document(document)


def write_report_file(
    report: BaselineReport, output_dir: str | pathlib.Path
) -> ReportFileArtifacts:
    """Persist one report artifact exclusively under its digest prefix.

    The output directory must already exist (otherwise the frozen
    ``OUTPUT_DIRECTORY_UNAVAILABLE`` collection error is re-raised).  The
    file name is ``{run_spec_digest[:16]}-report-{n}.json`` with ``n`` the
    smallest positive integer whose report name is either free or already
    holds a byte-identical prior copy of this very report (rewriting the
    same report appends a new sequence instead of overwriting history;
    the ``-run-`` family never collides with the report family).  Any
    other occupant of the next report slot is surfaced through the frozen
    ``write_exclusive`` primitive as ``OUTPUT_PATH_ALREADY_EXISTS`` and is
    never overwritten or silently resequenced around.  The payload is
    exactly ``report.canonical_bytes()``, and the returned digest is
    recomputed from those bytes alone.  The path never enters the report
    document.
    """

    directory = pathlib.Path(output_dir)
    if not directory.is_dir():
        raise BaselineCollectionError(
            BaselineCollectionErrorCode.OUTPUT_DIRECTORY_UNAVAILABLE, "$.output_dir"
        )
    prefix = report.run_spec_digest[:16]
    payload = report.canonical_bytes()
    sequence = 1
    report_path = directory / f"{prefix}-report-{sequence}.json"
    while report_path.exists():
        if report_path.read_bytes() != payload:
            break
        sequence += 1
        report_path = directory / f"{prefix}-report-{sequence}.json"
    write_exclusive(report_path, payload)
    return ReportFileArtifacts(
        report_path=report_path, report_sha256=compute_content_digest(payload)
    )


def _read_json_document(path: pathlib.Path) -> object:
    try:
        data = path.read_bytes()
        return json.loads(data.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise BaselineReportError(
            BaselineReportErrorCode.ARTIFACT_UNREADABLE, "$.artifact"
        ) from exc


def _read_result_artifact(path: pathlib.Path) -> BaselineRunResult:
    """Parse one result file through the frozen result contract.

    A persisted artifact carries the canonical output face of
    ``BaselineRunResult`` (schema version, run spec digest, samples, plus
    the computed status and percentile fields), while ``from_mapping``
    owns the strictly smaller input face (schema version, run spec
    digest, samples) and recomputes everything else.  The document is
    therefore projected onto the input face before the frozen parse; a
    document missing any input field, or failing the frozen validation,
    is unreadable and fails closed.
    """

    mapping = _read_json_document(path)
    if not isinstance(mapping, dict):
        raise BaselineReportError(
            BaselineReportErrorCode.ARTIFACT_UNREADABLE, "$.artifact"
        )
    projected: dict[str, object] = {}
    for field in ("schema_version", "run_spec_digest", "samples"):
        if field not in mapping:
            raise BaselineReportError(
                BaselineReportErrorCode.ARTIFACT_UNREADABLE, "$.artifact"
            )
        projected[field] = mapping[field]
    try:
        return result_from_mapping(projected)
    except BaselineRunResultError as exc:
        raise BaselineReportError(
            BaselineReportErrorCode.ARTIFACT_UNREADABLE, "$.artifact"
        ) from exc


def _validate_sidecar_artifact(document: object) -> None:
    if not isinstance(document, dict):
        _fail(BaselineReportErrorCode.ARTIFACT_UNREADABLE, "$.artifact")
    if set(document) != _SIDECAR_FIELD_SET:
        _fail(BaselineReportErrorCode.ARTIFACT_UNREADABLE, "$.artifact")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        _fail(BaselineReportErrorCode.ARTIFACT_UNREADABLE, "$.artifact")
    if not _is_hex64(document["run_spec_digest"]):
        _fail(BaselineReportErrorCode.ARTIFACT_UNREADABLE, "$.artifact")
    if not _is_hex64(document["reviewer_digest"]):
        _fail(BaselineReportErrorCode.ARTIFACT_UNREADABLE, "$.artifact")
    if (
        type(document["active_time_ms"]) is not int
        or document["active_time_ms"] < 0
    ):
        _fail(BaselineReportErrorCode.ARTIFACT_UNREADABLE, "$.artifact")
    if not isinstance(document["events"], list):
        _fail(BaselineReportErrorCode.ARTIFACT_UNREADABLE, "$.artifact")


def find_run_artifacts(
    directory: str | pathlib.Path, *, prefix: str | None = None
) -> tuple[RunArtifactEntry, ...]:
    """Discover persisted baseline run artifacts in one output directory.

    Frozen discovery contract: only files whose whole name matches
    ``{digest16}-run-{n}.json`` (digest16 lowercase hex, n a positive
    integer) are considered; every other file in the user-owned directory
    is ignored, not an error.  Each matching result file is parsed through
    the frozen ``lima.baseline_run_result.from_mapping`` to yield
    ``sample_count`` and ``is_aggregate`` (a multi-sample file, samples >
    1, is the aggregate).  Sidecars pair by stem (``{stem}.expert-timing.
    json``): present and structurally valid yields ``sidecar_path``,
    otherwise ``None``.  A result file or sidecar that cannot be parsed
    fails closed with ``ARTIFACT_UNREADABLE``; an orphan sidecar without a
    result file produces no entry and no error (the known residual state
    is reported as absence).  Entries are returned sorted by
    ``(digest16, sequence)``.  The frozen aggregate convention: under one
    digest16 prefix, the highest-sequence multi-sample result file is the
    most recent orchestrated run's aggregate, whose samples are exactly
    that run's attempt results sorted by attempt index; single-sample
    files are per-attempt results.  ``prefix`` optionally filters to one
    digest16.
    """

    directory_path = pathlib.Path(directory)
    entries: list[RunArtifactEntry] = []
    for path in sorted(directory_path.iterdir(), key=lambda item: item.name):
        match = _RESULT_NAME_PATTERN.fullmatch(path.name)
        if match is None:
            continue
        digest16 = match.group(1)
        if prefix is not None and digest16 != prefix:
            continue
        parsed = _read_result_artifact(path)
        sidecar_path = path.with_name(path.stem + _SIDECAR_SUFFIX)
        if sidecar_path.exists():
            _validate_sidecar_artifact(_read_json_document(sidecar_path))
        else:
            sidecar_path = None
        sample_count = len(parsed.samples)
        entries.append(
            RunArtifactEntry(
                digest16=digest16,
                sequence=int(match.group(2)),
                result_path=path,
                sidecar_path=sidecar_path,
                sample_count=sample_count,
                is_aggregate=sample_count > 1,
            )
        )
    return tuple(sorted(entries, key=lambda entry: (entry.digest16, entry.sequence)))
