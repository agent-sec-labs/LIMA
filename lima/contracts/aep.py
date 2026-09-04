"""Deterministic Audit Evidence Package (AEP) contracts for LIMA (IP-0004).

Module-only leaf contracts on top of the IP-0001 artifact foundation and
the IP-0002 evidence domain: package status/depth/outcome enums with a
vocabulary that structurally cannot express a safety verdict, coverage and
budget meters as exact non-negative ints, typed coverage gaps, and the
``AuditEvidencePackage`` that embeds a full ``EvidenceDomainBundle`` and
enforces the mining-eligibility exact-set and audit-outcome mapping
invariants. Pure in-memory, stdlib-only, fail-closed. Dependency direction
is fixed: this module may import ``evidence``/``codec``/``common``/
``errors`` and must never import ``lima.contracts.profile``; repository
profiles are referenced only through typed envelope lineage entries.
"""

import copy
import hmac
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Final

from lima.contracts.codec import (
    DEFAULT_LIMITS,
    ContractLimits,
    JSONValue,
    compute_content_digest,
)
from lima.contracts.common import (
    ArtifactClassification,
    ArtifactEnvelope,
    RetentionClass,
    SchemaVersion,
    decode_envelope,
    encode_envelope,
)
from lima.contracts.errors import ContractError, ContractErrorCode
from lima.contracts.evidence import EvidenceDomainBundle, HypothesisStatus

__all__ = [
    "AUDIT_EVIDENCE_PACKAGE_SCHEMA_NAME",
    "AuditPackageStatus",
    "AuditDepth",
    "AuditOutcome",
    "AuditCoverage",
    "AuditBudget",
    "AuditCoverageGap",
    "AuditEvidencePackage",
    "decode_aep_payload",
    "encode_aep_payload",
    "decode_aep_envelope",
    "encode_aep_envelope",
]

AUDIT_EVIDENCE_PACKAGE_SCHEMA_NAME = "lima.audit-evidence-package"

_PROFILE_LINEAGE_SCHEMA_NAME = "lima.repository-profile"
_INT64_MAX: Final[int] = (1 << 63) - 1
_MAX_DETAIL_BYTES: Final[int] = 4096

_IDENTIFIER_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_GAP_CODE_PATTERN: Final = re.compile(r"[A-Z][A-Z0-9_]{0,63}")


def _is_current_minor(version: SchemaVersion) -> bool:
    return version == SchemaVersion(4, 0)


def _as_mapping(value: object) -> Mapping[str, JSONValue]:
    if not isinstance(value, Mapping):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$")
    return value


def _repath(error: ContractError, prefix: str) -> ContractError:
    field_path = error.field_path
    if field_path.startswith("$."):
        return ContractError(error.code, prefix + field_path[1:])
    if field_path:
        return ContractError(error.code, prefix + "." + field_path)
    return ContractError(error.code, prefix)


def _utf8_bytes(value: str, path: str) -> bytes:
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ContractError(ContractErrorCode.INVALID_UTF8, path) from exc


def _validated_identifier(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    normalized = unicodedata.normalize("NFC", value)
    if _IDENTIFIER_PATTERN.fullmatch(normalized) is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return normalized


def _validated_gap_code(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    normalized = unicodedata.normalize("NFC", value)
    if _GAP_CODE_PATTERN.fullmatch(normalized) is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return normalized


def _validated_bounded_text(value: object, path: str, *, max_bytes: int) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    normalized = unicodedata.normalize("NFC", value)
    encoded = _utf8_bytes(normalized, path)
    if not normalized:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    if any(unicodedata.category(char) == "Cc" for char in normalized):
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    if normalized != normalized.strip():
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    if len(encoded) > max_bytes:
        raise ContractError(ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED, path)
    return normalized


def _validated_int(
    value: object,
    path: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int:
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if not minimum <= value <= maximum:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return value


def _validated_extensions(
    extensions: object,
    *,
    known_fields: tuple[str, ...],
    version: "SchemaVersion | None",
    path: str,
) -> dict[str, JSONValue]:
    if not isinstance(extensions, dict):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if version is not None and _is_current_minor(version) and extensions:
        raise ContractError(ContractErrorCode.UNKNOWN_FIELD, path)
    normalized: dict[str, JSONValue] = {}
    for key, value in extensions.items():
        if not isinstance(key, str):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
        normalized_key = unicodedata.normalize("NFC", key)
        _utf8_bytes(normalized_key, path)
        if normalized_key in normalized or normalized_key in known_fields:
            raise ContractError(ContractErrorCode.DUPLICATE_SEMANTIC_FIELD, path)
        normalized[normalized_key] = copy.deepcopy(value)
    return normalized


def _split_extensions(
    data: Mapping[str, JSONValue],
    *,
    known_fields: tuple[str, ...],
    schema_version: SchemaVersion,
) -> dict[str, JSONValue]:
    extensions: dict[str, JSONValue] = {}
    for key, value in data.items():
        if key in known_fields:
            continue
        normalized_key = unicodedata.normalize("NFC", key)
        _utf8_bytes(normalized_key, "$")
        if normalized_key in known_fields or normalized_key in extensions:
            raise ContractError(ContractErrorCode.DUPLICATE_SEMANTIC_FIELD, "$")
        extensions[normalized_key] = value
    if _is_current_minor(schema_version) and extensions:
        raise ContractError(ContractErrorCode.UNKNOWN_FIELD, f"$.{sorted(extensions)[0]}")
    return extensions


def _wire_enum(value: object, enum_type: type, path: str):
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ContractError(ContractErrorCode.UNKNOWN_ENUM_VALUE, path) from exc


def _validated_sorted_str_array(
    items: object,
    path: str,
    *,
    cap: int,
    allow_empty: bool,
    item_validator,
) -> tuple[str, ...]:
    if not isinstance(items, (list, tuple)):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if len(items) > cap:
        raise ContractError(ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, path)
    if not items and not allow_empty:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    normalized = [
        item_validator(item, f"{path}[{index}]") for index, item in enumerate(items)
    ]
    for index in range(1, len(normalized)):
        if normalized[index] <= normalized[index - 1]:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, f"{path}[{index}]")
    return tuple(normalized)


class AuditPackageStatus(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0004 §10
    """Draft is a legal intermediate state; sealed closes one revision."""

    DRAFT = "draft"
    SEALED = "sealed"


class AuditDepth(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0004 §10
    """Which audit pass produced this package."""

    INITIAL = "initial"
    DEEP = "deep"


class AuditOutcome(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0004 §10
    """Audit conclusions; the vocabulary structurally cannot express safety."""

    COMPLETED = "completed"
    INCOMPLETE = "incomplete"
    NO_ACTIONABLE_HYPOTHESIS = "no_actionable_hypothesis"
    NO_SUPPORTED_ATTACK_SURFACE = "no_supported_attack_surface"


_AUDIT_COVERAGE_WIRE_FIELDS: Final = ("in_scope_file_count", "analyzed_file_count")


@dataclass(frozen=True, slots=True)
class AuditCoverage:
    """File-scope coverage facts for one audit run."""

    in_scope_file_count: int
    analyzed_file_count: int
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        in_scope = _validated_int(
            self.in_scope_file_count,
            "$.in_scope_file_count",
            minimum=0,
            maximum=_INT64_MAX,
        )
        analyzed = _validated_int(
            self.analyzed_file_count,
            "$.analyzed_file_count",
            minimum=0,
            maximum=_INT64_MAX,
        )
        if analyzed > in_scope:
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE, "$.analyzed_file_count"
            )
        object.__setattr__(self, "in_scope_file_count", in_scope)
        object.__setattr__(self, "analyzed_file_count", analyzed)
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_AUDIT_COVERAGE_WIRE_FIELDS,
                version=None,
                path="$",
            ),
        )

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "AuditCoverage":
        data = _as_mapping(value)
        missing = [name for name in _AUDIT_COVERAGE_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data,
            known_fields=_AUDIT_COVERAGE_WIRE_FIELDS,
            schema_version=schema_version,
        )
        return cls(
            in_scope_file_count=data["in_scope_file_count"],
            analyzed_file_count=data["analyzed_file_count"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "in_scope_file_count": self.in_scope_file_count,
            "analyzed_file_count": self.analyzed_file_count,
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_AUDIT_BUDGET_WIRE_FIELDS: Final = (
    "tool_runs",
    "model_calls",
    "model_tokens",
    "wall_clock_ms",
)


@dataclass(frozen=True, slots=True)
class AuditBudget:
    """Consumption meters for one audit run; facts, not quota decisions."""

    tool_runs: int
    model_calls: int
    model_tokens: int
    wall_clock_ms: int
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in _AUDIT_BUDGET_WIRE_FIELDS:
            object.__setattr__(
                self,
                name,
                _validated_int(
                    getattr(self, name), f"$.{name}", minimum=0, maximum=_INT64_MAX
                ),
            )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_AUDIT_BUDGET_WIRE_FIELDS,
                version=None,
                path="$",
            ),
        )

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "AuditBudget":
        data = _as_mapping(value)
        missing = [name for name in _AUDIT_BUDGET_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data,
            known_fields=_AUDIT_BUDGET_WIRE_FIELDS,
            schema_version=schema_version,
        )
        return cls(
            tool_runs=data["tool_runs"],
            model_calls=data["model_calls"],
            model_tokens=data["model_tokens"],
            wall_clock_ms=data["wall_clock_ms"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "tool_runs": self.tool_runs,
            "model_calls": self.model_calls,
            "model_tokens": self.model_tokens,
            "wall_clock_ms": self.wall_clock_ms,
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_AUDIT_COVERAGE_GAP_WIRE_FIELDS: Final = ("gap_code", "detail")


@dataclass(frozen=True, slots=True)
class AuditCoverageGap:
    """Machine-readable coverage limitation of one audit run."""

    gap_code: str
    detail: str
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "gap_code", _validated_gap_code(self.gap_code, "$.gap_code")
        )
        object.__setattr__(
            self,
            "detail",
            _validated_bounded_text(
                self.detail, "$.detail", max_bytes=_MAX_DETAIL_BYTES
            ),
        )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_AUDIT_COVERAGE_GAP_WIRE_FIELDS,
                version=None,
                path="$",
            ),
        )

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "AuditCoverageGap":
        data = _as_mapping(value)
        missing = [name for name in _AUDIT_COVERAGE_GAP_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data,
            known_fields=_AUDIT_COVERAGE_GAP_WIRE_FIELDS,
            schema_version=schema_version,
        )
        return cls(
            gap_code=data["gap_code"],
            detail=data["detail"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "gap_code": self.gap_code,
            "detail": self.detail,
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_AEP_WIRE_FIELDS: Final = (
    "package_status",
    "revision",
    "audit_depth",
    "audit_outcome",
    "evidence_domain",
    "repository_profile_artifact_ids",
    "mining_eligible_hypothesis_ids",
    "coverage",
    "coverage_gaps",
    "budget",
)
_EMPTY_ELIGIBILITY_OUTCOMES: Final = (
    AuditOutcome.NO_ACTIONABLE_HYPOTHESIS,
    AuditOutcome.NO_SUPPORTED_ATTACK_SURFACE,
    AuditOutcome.INCOMPLETE,
)


def _require_sorted_by_key(items, key_function, path):
    for index in range(1, len(items)):
        if key_function(items[index]) <= key_function(items[index - 1]):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE, f"{path}[{index}]"
            )


def _reject_current_minor_nested_extensions(
    *,
    coverage,
    budget,
    coverage_gaps,
    version,
):
    if not _is_current_minor(version):
        return

    def check(container, path):
        if container:
            raise ContractError(ContractErrorCode.UNKNOWN_FIELD, path)

    check(coverage.extensions, "$.coverage")
    check(budget.extensions, "$.budget")
    for index, gap in enumerate(coverage_gaps):
        check(gap.extensions, f"$.coverage_gaps[{index}]")


@dataclass(frozen=True, slots=True)
class AuditEvidencePackage:
    """Self-contained, fail-closed output of one audit stage revision."""

    schema_version: SchemaVersion
    package_status: AuditPackageStatus
    revision: int
    audit_depth: AuditDepth
    audit_outcome: AuditOutcome
    evidence: EvidenceDomainBundle
    coverage: AuditCoverage
    budget: AuditBudget
    repository_profile_artifact_ids: tuple[str, ...]
    mining_eligible_hypothesis_ids: tuple[str, ...] = ()
    coverage_gaps: tuple[AuditCoverageGap, ...] = ()
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, SchemaVersion):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.schema_version")
        if not isinstance(self.package_status, AuditPackageStatus):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.package_status")
        revision = _validated_int(
            self.revision, "$.revision", minimum=1, maximum=_INT64_MAX
        )
        if not isinstance(self.audit_depth, AuditDepth):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.audit_depth")
        if not isinstance(self.audit_outcome, AuditOutcome):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.audit_outcome")
        if not isinstance(self.evidence, EvidenceDomainBundle):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.evidence_domain")
        evidence = copy.deepcopy(self.evidence)
        if not isinstance(self.coverage, AuditCoverage):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.coverage")
        coverage = copy.deepcopy(self.coverage)
        if not isinstance(self.budget, AuditBudget):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.budget")
        budget = copy.deepcopy(self.budget)
        repository_profile_artifact_ids = _validated_sorted_str_array(
            self.repository_profile_artifact_ids,
            "$.repository_profile_artifact_ids",
            cap=16,
            allow_empty=False,
            item_validator=_validated_identifier,
        )
        mining_eligible_hypothesis_ids = _validated_sorted_str_array(
            self.mining_eligible_hypothesis_ids,
            "$.mining_eligible_hypothesis_ids",
            cap=2048,
            allow_empty=True,
            item_validator=_validated_identifier,
        )
        if not isinstance(self.coverage_gaps, (list, tuple)):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.coverage_gaps")
        if len(self.coverage_gaps) > 256:
            raise ContractError(
                ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, "$.coverage_gaps"
            )
        coverage_gaps = []
        for index, gap in enumerate(self.coverage_gaps):
            if not isinstance(gap, AuditCoverageGap):
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_TYPE, f"$.coverage_gaps[{index}]"
                )
            coverage_gaps.append(copy.deepcopy(gap))
        coverage_gaps = tuple(coverage_gaps)
        _require_sorted_by_key(
            coverage_gaps,
            lambda item: (item.gap_code, item.detail.encode("utf-8")),
            "$.coverage_gaps",
        )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_AEP_WIRE_FIELDS,
                version=self.schema_version,
                path="$",
            ),
        )
        _reject_current_minor_nested_extensions(
            coverage=coverage,
            budget=budget,
            coverage_gaps=coverage_gaps,
            version=self.schema_version,
        )

        supported_ids = {
            hypothesis.hypothesis_id
            for hypothesis in evidence.vulnerability_hypotheses
            if hypothesis.status is HypothesisStatus.STATICALLY_SUPPORTED
        }
        declared_ids = list(mining_eligible_hypothesis_ids)
        for index, identifier in enumerate(declared_ids):
            if identifier not in supported_ids:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    f"$.mining_eligible_hypothesis_ids[{index}]",
                )
        if set(declared_ids) != supported_ids:
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE,
                "$.mining_eligible_hypothesis_ids",
            )

        if declared_ids:
            if self.audit_outcome is not AuditOutcome.COMPLETED:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE, "$.audit_outcome"
                )
        elif self.audit_outcome not in _EMPTY_ELIGIBILITY_OUTCOMES:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.audit_outcome")
        if self.audit_outcome is AuditOutcome.INCOMPLETE and not coverage_gaps:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.coverage_gaps")

        object.__setattr__(self, "revision", revision)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "coverage", coverage)
        object.__setattr__(self, "budget", budget)
        object.__setattr__(
            self, "repository_profile_artifact_ids", repository_profile_artifact_ids
        )
        object.__setattr__(
            self, "mining_eligible_hypothesis_ids", mining_eligible_hypothesis_ids
        )
        object.__setattr__(self, "coverage_gaps", coverage_gaps)

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "AuditEvidencePackage":
        data = _as_mapping(value)
        missing = [name for name in _AEP_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data, known_fields=_AEP_WIRE_FIELDS, schema_version=schema_version
        )
        package_status = _wire_enum(
            data["package_status"], AuditPackageStatus, "$.package_status"
        )
        _validated_int(data["revision"], "$.revision", minimum=1, maximum=_INT64_MAX)
        audit_depth = _wire_enum(data["audit_depth"], AuditDepth, "$.audit_depth")
        audit_outcome = _wire_enum(data["audit_outcome"], AuditOutcome, "$.audit_outcome")
        if not isinstance(data["coverage"], Mapping):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.coverage")
        try:
            coverage = AuditCoverage.from_dict(
                data["coverage"], schema_version=schema_version
            )
        except ContractError as error:
            raise _repath(error, "$.coverage") from error
        if not isinstance(data["budget"], Mapping):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.budget")
        try:
            budget = AuditBudget.from_dict(
                data["budget"], schema_version=schema_version
            )
        except ContractError as error:
            raise _repath(error, "$.budget") from error
        repository_profile_artifact_ids = _validated_sorted_str_array(
            data["repository_profile_artifact_ids"],
            "$.repository_profile_artifact_ids",
            cap=16,
            allow_empty=False,
            item_validator=_validated_identifier,
        )
        mining_eligible_hypothesis_ids = _validated_sorted_str_array(
            data["mining_eligible_hypothesis_ids"],
            "$.mining_eligible_hypothesis_ids",
            cap=2048,
            allow_empty=True,
            item_validator=_validated_identifier,
        )
        if not isinstance(data["coverage_gaps"], list):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.coverage_gaps")
        if len(data["coverage_gaps"]) > 256:
            raise ContractError(
                ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, "$.coverage_gaps"
            )
        coverage_gaps = []
        for index, gap in enumerate(data["coverage_gaps"]):
            try:
                coverage_gaps.append(
                    AuditCoverageGap.from_dict(gap, schema_version=schema_version)
                )
            except ContractError as error:
                raise _repath(error, f"$.coverage_gaps[{index}]") from error
        if not isinstance(data["evidence_domain"], Mapping):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.evidence_domain")
        try:
            evidence = EvidenceDomainBundle.from_dict(
                data["evidence_domain"], schema_version=schema_version
            )
        except ContractError as error:
            raise _repath(error, "$.evidence_domain") from error
        return cls(
            schema_version=schema_version,
            package_status=package_status,
            revision=data["revision"],
            audit_depth=audit_depth,
            audit_outcome=audit_outcome,
            evidence=evidence,
            coverage=coverage,
            budget=budget,
            repository_profile_artifact_ids=repository_profile_artifact_ids,
            mining_eligible_hypothesis_ids=mining_eligible_hypothesis_ids,
            coverage_gaps=coverage_gaps,
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "package_status": self.package_status.value,
            "revision": self.revision,
            "audit_depth": self.audit_depth.value,
            "audit_outcome": self.audit_outcome.value,
            "evidence_domain": self.evidence.to_dict(),
            "repository_profile_artifact_ids": list(self.repository_profile_artifact_ids),
            "mining_eligible_hypothesis_ids": list(self.mining_eligible_hypothesis_ids),
            "coverage": self.coverage.to_dict(),
            "coverage_gaps": [gap.to_dict() for gap in self.coverage_gaps],
            "budget": self.budget.to_dict(),
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


def _require_aep_schema_name(envelope: ArtifactEnvelope) -> None:
    if envelope.schema_name != AUDIT_EVIDENCE_PACKAGE_SCHEMA_NAME:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.schema_name")


def _require_inline_payload(envelope: ArtifactEnvelope) -> None:
    if envelope.payload is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.payload")


def _require_protected_envelope(envelope: ArtifactEnvelope) -> None:
    if envelope.classification is ArtifactClassification.PUBLIC:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.classification")
    if envelope.retention_class is RetentionClass.EPHEMERAL:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.retention_class")


def _require_lineage_provenance(
    envelope: ArtifactEnvelope, package: AuditEvidencePackage
) -> None:
    lineage_by_id = {
        reference.artifact_id: reference for reference in envelope.lineage
    }
    for position, artifact_id in enumerate(package.repository_profile_artifact_ids):
        reference = lineage_by_id.get(artifact_id)
        if reference is None or reference.schema_name != _PROFILE_LINEAGE_SCHEMA_NAME:
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE,
                f"$.payload.repository_profile_artifact_ids[{position}]",
            )
    for index, record in enumerate(package.evidence.evidence):
        for position, artifact_id in enumerate(record.source_artifact_ids):
            if artifact_id not in lineage_by_id:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    "$.payload.evidence_domain.evidence"
                    f"[{index}].source_artifact_ids[{position}]",
                )


def decode_aep_payload(
    value: Mapping[str, JSONValue],
    *,
    schema_version: SchemaVersion,
) -> AuditEvidencePackage:
    """Decode a validated payload mapping into an AuditEvidencePackage."""
    return AuditEvidencePackage.from_dict(value, schema_version=schema_version)


def encode_aep_payload(package: AuditEvidencePackage) -> dict[str, JSONValue]:
    """Return the canonical wire payload of a validated package."""
    if not isinstance(package, AuditEvidencePackage):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    return package.to_dict()


def decode_aep_envelope(
    data: bytes,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> "tuple[ArtifactEnvelope, AuditEvidencePackage]":
    """Decode envelope bytes and return the envelope with its audit package."""
    envelope = decode_envelope(data, limits=limits)
    _require_aep_schema_name(envelope)
    _require_inline_payload(envelope)
    package = AuditEvidencePackage.from_dict(
        envelope.payload, schema_version=envelope.schema_version
    )
    _require_lineage_provenance(envelope, package)
    _require_protected_envelope(envelope)
    return envelope, package


def encode_aep_envelope(
    envelope: ArtifactEnvelope,
    package: AuditEvidencePackage,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> bytes:
    """Verify the full AEP binding and encode the envelope canonically."""
    if not isinstance(envelope, ArtifactEnvelope):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if not isinstance(package, AuditEvidencePackage):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    _require_aep_schema_name(envelope)
    _require_inline_payload(envelope)
    if envelope.schema_version != package.schema_version:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.schema_version")
    payload = encode_aep_payload(package)
    if envelope.payload != payload:
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.payload")
    if not hmac.compare_digest(
        compute_content_digest(payload, limits=limits), envelope.content_digest
    ):
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.content_digest")
    _require_protected_envelope(envelope)
    _require_lineage_provenance(envelope, package)
    return encode_envelope(envelope, limits=limits)
