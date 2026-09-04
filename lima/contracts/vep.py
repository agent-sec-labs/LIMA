"""Deterministic Vulnerability Evidence Package (VEP) contracts for LIMA (IP-0005).

Module-only leaf contracts on top of the IP-0001 artifact foundation and
the IP-0002 evidence domain: verdict/claim/reproduction enums whose
vocabularies structurally separate six-state execution facts from
adjudication (no safe/clear/not_vulnerable anywhere), typed AEP and
Oracle references pinned by digest, embedded D3/D4 ``EvidenceRecord``
graphs bound to one hypothesis, and the frozen verdict-by-evidence-level
matrix that makes "no D4 verified", "conflict folded into a verdict", and
"missing oracle" impossible to express. Pure in-memory, stdlib-only,
fail-closed. Dependency direction is fixed: this module may import
``evidence``/``codec``/``common``/``errors`` and must never import
``lima.contracts.aep`` or ``lima.contracts.profile``; upstream artifacts
travel only through typed envelope lineage entries.
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
from lima.contracts.evidence import (
    EvidenceLevel,
    EvidencePolarity,
    EvidenceRecord,
    EvidenceSubjectKind,
    SourceLocation,
)

__all__ = [
    "VULNERABILITY_EVIDENCE_PACKAGE_SCHEMA_NAME",
    "ClaimKind",
    "VerificationVerdict",
    "ReproductionOutcome",
    "AepReference",
    "OracleReference",
    "ReproductionRun",
    "VulnerabilityEvidencePackage",
    "decode_vep_payload",
    "encode_vep_payload",
    "decode_vep_envelope",
    "encode_vep_envelope",
]

VULNERABILITY_EVIDENCE_PACKAGE_SCHEMA_NAME = "lima.vulnerability-evidence-package"

_AEP_LINEAGE_SCHEMA_NAME = "lima.audit-evidence-package"
_INT64_MAX: Final[int] = (1 << 63) - 1
_MAX_TEXT_BYTES: Final[int] = 4096

_IDENTIFIER_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_DIGEST_PATTERN: Final = re.compile(r"[0-9a-f]{64}")
_CWE_PATTERN: Final = re.compile(r"CWE-[1-9][0-9]{0,5}")


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


def _validated_digest(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if _DIGEST_PATTERN.fullmatch(value) is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return value


def _validated_cwe(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    normalized = unicodedata.normalize("NFC", value)
    if _CWE_PATTERN.fullmatch(normalized) is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return normalized


def _validated_bounded_text(value: object, path: str) -> str:
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
    if len(encoded) > _MAX_TEXT_BYTES:
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


def _validated_sorted_text_array(
    items: object,
    path: str,
    *,
    cap: int,
) -> tuple[str, ...]:
    if not isinstance(items, (list, tuple)):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if len(items) > cap:
        raise ContractError(ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, path)
    normalized = [
        _validated_bounded_text(item, f"{path}[{index}]")
        for index, item in enumerate(items)
    ]
    encoded = [item.encode("utf-8") for item in normalized]
    for index in range(1, len(normalized)):
        if encoded[index] <= encoded[index - 1]:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, f"{path}[{index}]")
    return tuple(normalized)


class ClaimKind(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0005 §10
    """What this package claims; static_property must never imply runtime exploitability."""

    RUNTIME_EXPLOITABILITY = "runtime_exploitability"
    STATIC_PROPERTY = "static_property"


class VerificationVerdict(str, Enum):  # noqa: UP042 -- frozen by IP-0005 §10
    """FR-03 verdicts; admissibility is machine-checked by the level matrix."""

    CANDIDATE = "candidate"
    INCONCLUSIVE = "inconclusive"
    REFUTED_SCOPE = "refuted_scope"
    VERIFIED = "verified"


class ReproductionOutcome(str, Enum):  # noqa: UP042 -- frozen by IP-0005 §10
    """Six-state execution facts; never an adjudication and never a safety claim."""

    REPRODUCED = "reproduced"
    NOT_REPRODUCED = "not_reproduced"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"
    TOOL_ERROR = "tool_error"
    POLICY_DENIED = "policy_denied"


_AEP_REFERENCE_WIRE_FIELDS: Final = (
    "artifact_id",
    "content_digest",
    "schema_version",
)


@dataclass(frozen=True, slots=True)
class AepReference:
    """FR-02 identity triple pinning the source audit evidence package."""

    artifact_id: str
    content_digest: str
    schema_version: SchemaVersion
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "artifact_id", _validated_identifier(self.artifact_id, "$.artifact_id")
        )
        object.__setattr__(
            self,
            "content_digest",
            _validated_digest(self.content_digest, "$.content_digest"),
        )
        if not isinstance(self.schema_version, SchemaVersion):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.schema_version")
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_AEP_REFERENCE_WIRE_FIELDS,
                version=None,
                path="$",
            ),
        )

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "AepReference":
        data = _as_mapping(value)
        missing = [name for name in _AEP_REFERENCE_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data,
            known_fields=_AEP_REFERENCE_WIRE_FIELDS,
            schema_version=schema_version,
        )
        version = SchemaVersion.parse(data["schema_version"])
        return cls(
            artifact_id=data["artifact_id"],
            content_digest=data["content_digest"],
            schema_version=version,
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "artifact_id": self.artifact_id,
            "content_digest": self.content_digest,
            "schema_version": str(self.schema_version),
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_ORACLE_REFERENCE_WIRE_FIELDS: Final = ("oracle_artifact_id", "content_digest")


@dataclass(frozen=True, slots=True)
class OracleReference:
    """Minimal descriptor of the machine-executable oracle artifact."""

    oracle_artifact_id: str
    content_digest: str
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "oracle_artifact_id",
            _validated_identifier(self.oracle_artifact_id, "$.oracle_artifact_id"),
        )
        object.__setattr__(
            self,
            "content_digest",
            _validated_digest(self.content_digest, "$.content_digest"),
        )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_ORACLE_REFERENCE_WIRE_FIELDS,
                version=None,
                path="$",
            ),
        )

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "OracleReference":
        data = _as_mapping(value)
        missing = [name for name in _ORACLE_REFERENCE_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data,
            known_fields=_ORACLE_REFERENCE_WIRE_FIELDS,
            schema_version=schema_version,
        )
        return cls(
            oracle_artifact_id=data["oracle_artifact_id"],
            content_digest=data["content_digest"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "oracle_artifact_id": self.oracle_artifact_id,
            "content_digest": self.content_digest,
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_REPRODUCTION_RUN_WIRE_FIELDS: Final = (
    "run_artifact_id",
    "outcome",
    "detail",
)


@dataclass(frozen=True, slots=True)
class ReproductionRun:
    """One sandbox run's six-state outcome; execution facts, never a verdict."""

    run_artifact_id: str
    outcome: ReproductionOutcome
    detail: str
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "run_artifact_id",
            _validated_identifier(self.run_artifact_id, "$.run_artifact_id"),
        )
        if not isinstance(self.outcome, ReproductionOutcome):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.outcome")
        object.__setattr__(
            self,
            "detail",
            _validated_bounded_text(self.detail, "$.detail"),
        )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_REPRODUCTION_RUN_WIRE_FIELDS,
                version=None,
                path="$",
            ),
        )

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "ReproductionRun":
        data = _as_mapping(value)
        missing = [name for name in _REPRODUCTION_RUN_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data,
            known_fields=_REPRODUCTION_RUN_WIRE_FIELDS,
            schema_version=schema_version,
        )
        outcome = _wire_enum(data["outcome"], ReproductionOutcome, "$.outcome")
        return cls(
            run_artifact_id=data["run_artifact_id"],
            outcome=outcome,
            detail=data["detail"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "run_artifact_id": self.run_artifact_id,
            "outcome": self.outcome.value,
            "detail": self.detail,
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_VEP_WIRE_FIELDS: Final = (
    "verification_verdict",
    "claim_kind",
    "hypothesis_id",
    "source_aep",
    "source_aep_revision",
    "oracle",
    "evidence",
    "reproduction_runs",
    "target_location",
    "path_locations",
    "trigger_conditions",
    "cwe_ids",
    "impact",
    "refutation_scope",
)
_MINING_LEVELS: Final = (EvidenceLevel.D3, EvidenceLevel.D4)


def _level_number(level: EvidenceLevel) -> int:
    return int(level.value[1:])


def _reject_current_minor_nested_extensions(
    *,
    source_aep,
    oracle,
    reproduction_runs,
    version,
):
    if not _is_current_minor(version):
        return

    def check(container, path):
        if container:
            raise ContractError(ContractErrorCode.UNKNOWN_FIELD, path)

    check(source_aep.extensions, "$.source_aep")
    check(oracle.extensions, "$.oracle")
    for index, run in enumerate(reproduction_runs):
        check(run.extensions, f"$.reproduction_runs[{index}]")


def _allowed_verdicts(claim_kind, has_d4_supports, has_d3_supports, has_refutes):
    """Return the frozen set of admissible verdicts for the evidence profile."""
    if claim_kind is ClaimKind.STATIC_PROPERTY:
        if has_d4_supports and has_refutes:
            return frozenset({VerificationVerdict.INCONCLUSIVE})
        if has_d4_supports:
            return frozenset({VerificationVerdict.VERIFIED})
        if has_refutes:
            return frozenset(
                {VerificationVerdict.REFUTED_SCOPE, VerificationVerdict.INCONCLUSIVE}
            )
        return frozenset({VerificationVerdict.INCONCLUSIVE})
    if has_d4_supports and has_refutes:
        return frozenset({VerificationVerdict.INCONCLUSIVE})
    if has_d4_supports:
        if has_d3_supports:
            return frozenset({VerificationVerdict.VERIFIED, VerificationVerdict.CANDIDATE})
        return frozenset({VerificationVerdict.INCONCLUSIVE})
    if has_refutes:
        return frozenset(
            {VerificationVerdict.REFUTED_SCOPE, VerificationVerdict.INCONCLUSIVE}
        )
    if has_d3_supports:
        return frozenset({VerificationVerdict.CANDIDATE, VerificationVerdict.INCONCLUSIVE})
    return frozenset({VerificationVerdict.INCONCLUSIVE})


@dataclass(frozen=True, slots=True)
class VulnerabilityEvidencePackage:
    """Self-contained, fail-closed output of one mining verification pass."""

    schema_version: SchemaVersion
    verification_verdict: VerificationVerdict
    claim_kind: ClaimKind
    hypothesis_id: str
    source_aep: AepReference
    source_aep_revision: int
    oracle: OracleReference
    evidence: tuple[EvidenceRecord, ...]
    target_location: SourceLocation
    impact: str | None
    refutation_scope: str | None
    path_locations: tuple[SourceLocation, ...] = ()
    reproduction_runs: tuple[ReproductionRun, ...] = ()
    trigger_conditions: tuple[str, ...] = ()
    cwe_ids: tuple[str, ...] = ()
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, SchemaVersion):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.schema_version")
        if not isinstance(self.verification_verdict, VerificationVerdict):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_TYPE, "$.verification_verdict"
            )
        if not isinstance(self.claim_kind, ClaimKind):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.claim_kind")
        hypothesis_id = _validated_identifier(self.hypothesis_id, "$.hypothesis_id")
        if not isinstance(self.source_aep, AepReference):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.source_aep")
        source_aep = copy.deepcopy(self.source_aep)
        revision = _validated_int(
            self.source_aep_revision,
            "$.source_aep_revision",
            minimum=1,
            maximum=_INT64_MAX,
        )
        if not isinstance(self.oracle, OracleReference):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.oracle")
        oracle = copy.deepcopy(self.oracle)
        if not isinstance(self.evidence, (list, tuple)):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.evidence")
        if len(self.evidence) > 256:
            raise ContractError(
                ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, "$.evidence"
            )
        evidence = []
        for index, record in enumerate(self.evidence):
            if not isinstance(record, EvidenceRecord):
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_TYPE, f"$.evidence[{index}]"
                )
            evidence.append(copy.deepcopy(record))
        evidence = tuple(evidence)
        for index in range(1, len(evidence)):
            if evidence[index].evidence_id <= evidence[index - 1].evidence_id:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    f"$.evidence[{index}].evidence_id",
                )
        if not isinstance(self.target_location, SourceLocation):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_TYPE, "$.target_location"
            )
        target_location = copy.deepcopy(self.target_location)
        if not isinstance(self.path_locations, (list, tuple)):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.path_locations")
        if len(self.path_locations) > 256:
            raise ContractError(
                ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, "$.path_locations"
            )
        path_locations = []
        for index, location in enumerate(self.path_locations):
            if not isinstance(location, SourceLocation):
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_TYPE, f"$.path_locations[{index}]"
                )
            path_locations.append(copy.deepcopy(location))
        path_locations = tuple(path_locations)
        if not isinstance(self.reproduction_runs, (list, tuple)):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_TYPE, "$.reproduction_runs"
            )
        if len(self.reproduction_runs) > 64:
            raise ContractError(
                ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, "$.reproduction_runs"
            )
        reproduction_runs = []
        for index, run in enumerate(self.reproduction_runs):
            if not isinstance(run, ReproductionRun):
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_TYPE, f"$.reproduction_runs[{index}]"
                )
            reproduction_runs.append(copy.deepcopy(run))
        reproduction_runs = tuple(reproduction_runs)
        for index in range(1, len(reproduction_runs)):
            if (
                reproduction_runs[index].run_artifact_id
                <= reproduction_runs[index - 1].run_artifact_id
            ):
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    f"$.reproduction_runs[{index}].run_artifact_id",
                )
        trigger_conditions = _validated_sorted_text_array(
            self.trigger_conditions, "$.trigger_conditions", cap=64
        )
        cwe_ids = _validated_sorted_str_array(
            self.cwe_ids,
            "$.cwe_ids",
            cap=32,
            allow_empty=True,
            item_validator=_validated_cwe,
        )
        impact = (
            None
            if self.impact is None
            else _validated_bounded_text(self.impact, "$.impact")
        )
        refutation_scope = (
            None
            if self.refutation_scope is None
            else _validated_bounded_text(self.refutation_scope, "$.refutation_scope")
        )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_VEP_WIRE_FIELDS,
                version=self.schema_version,
                path="$",
            ),
        )
        _reject_current_minor_nested_extensions(
            source_aep=source_aep,
            oracle=oracle,
            reproduction_runs=reproduction_runs,
            version=self.schema_version,
        )

        for index, record in enumerate(evidence):
            if record.level not in _MINING_LEVELS:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE, f"$.evidence[{index}].level"
                )
            if record.subject_kind is not EvidenceSubjectKind.VULNERABILITY_HYPOTHESIS:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    f"$.evidence[{index}].subject_kind",
                )
            if record.subject_id != hypothesis_id:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    f"$.evidence[{index}].subject_id",
                )

        has_d4_supports = any(
            record.level is EvidenceLevel.D4
            and record.polarity is EvidencePolarity.SUPPORTS
            for record in evidence
        )
        has_d3_supports = any(
            record.level is EvidenceLevel.D3
            and record.polarity is EvidencePolarity.SUPPORTS
            for record in evidence
        )
        has_refutes = any(
            record.level in _MINING_LEVELS
            and record.polarity is EvidencePolarity.REFUTES
            for record in evidence
        )
        allowed = _allowed_verdicts(
            self.claim_kind, has_d4_supports, has_d3_supports, has_refutes
        )
        if self.verification_verdict not in allowed:
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE, "$.verification_verdict"
            )
        if self.verification_verdict is VerificationVerdict.VERIFIED:
            if impact is None:
                raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.impact")
            if self.claim_kind is ClaimKind.RUNTIME_EXPLOITABILITY and not any(
                run.outcome is ReproductionOutcome.REPRODUCED
                for run in reproduction_runs
            ):
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE, "$.reproduction_runs"
                )
        if (
            self.verification_verdict is VerificationVerdict.REFUTED_SCOPE
            and refutation_scope is None
        ):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE, "$.refutation_scope"
            )

        dependencies: dict[str, tuple[str, ...]] = {
            record.evidence_id: record.depends_on_evidence_ids for record in evidence
        }
        evidence_by_id = {record.evidence_id: record for record in evidence}
        index_of = {
            record.evidence_id: position for position, record in enumerate(evidence)
        }
        for index, record in enumerate(evidence):
            for position, dependency in enumerate(record.depends_on_evidence_ids):
                path = f"$.evidence[{index}].depends_on_evidence_ids[{position}]"
                if dependency == record.evidence_id:
                    raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
                target = evidence_by_id.get(dependency)
                if target is None:
                    raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
                if _level_number(target.level) > _level_number(record.level):
                    raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
        state: dict[str, int] = {}
        for record in evidence:
            if state.get(record.evidence_id, 0):
                continue
            stack = [(record.evidence_id, iter(dependencies[record.evidence_id]))]
            state[record.evidence_id] = 1
            while stack:
                node, iterator = stack[-1]
                successor = next(iterator, None)
                if successor is None:
                    state[node] = 2
                    stack.pop()
                    continue
                if state.get(successor, 0) == 1:
                    position = dependencies[node].index(successor)
                    raise ContractError(
                        ContractErrorCode.INVALID_FIELD_VALUE,
                        f"$.evidence[{index_of[node]}]"
                        f".depends_on_evidence_ids[{position}]",
                    )
                if state.get(successor, 0) == 0:
                    state[successor] = 1
                    stack.append((successor, iter(dependencies[successor])))

        object.__setattr__(self, "hypothesis_id", hypothesis_id)
        object.__setattr__(self, "source_aep", source_aep)
        object.__setattr__(self, "source_aep_revision", revision)
        object.__setattr__(self, "oracle", oracle)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "target_location", target_location)
        object.__setattr__(self, "impact", impact)
        object.__setattr__(self, "refutation_scope", refutation_scope)
        object.__setattr__(self, "path_locations", path_locations)
        object.__setattr__(self, "reproduction_runs", reproduction_runs)
        object.__setattr__(self, "trigger_conditions", trigger_conditions)
        object.__setattr__(self, "cwe_ids", cwe_ids)

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "VulnerabilityEvidencePackage":
        data = _as_mapping(value)
        missing = [name for name in _VEP_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data, known_fields=_VEP_WIRE_FIELDS, schema_version=schema_version
        )
        verification_verdict = _wire_enum(
            data["verification_verdict"], VerificationVerdict, "$.verification_verdict"
        )
        claim_kind = _wire_enum(data["claim_kind"], ClaimKind, "$.claim_kind")
        _validated_identifier(data["hypothesis_id"], "$.hypothesis_id")
        _validated_int(
            data["source_aep_revision"],
            "$.source_aep_revision",
            minimum=1,
            maximum=_INT64_MAX,
        )
        if not isinstance(data["source_aep"], Mapping):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.source_aep")
        try:
            source_aep = AepReference.from_dict(
                data["source_aep"], schema_version=schema_version
            )
        except ContractError as error:
            raise _repath(error, "$.source_aep") from error
        if not isinstance(data["oracle"], Mapping):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.oracle")
        try:
            oracle = OracleReference.from_dict(
                data["oracle"], schema_version=schema_version
            )
        except ContractError as error:
            raise _repath(error, "$.oracle") from error
        if not isinstance(data["target_location"], Mapping):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_TYPE, "$.target_location"
            )
        try:
            target_location = SourceLocation.from_dict(
                data["target_location"], schema_version=schema_version
            )
        except ContractError as error:
            raise _repath(error, "$.target_location") from error
        if not isinstance(data["path_locations"], list):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.path_locations")
        if len(data["path_locations"]) > 256:
            raise ContractError(
                ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, "$.path_locations"
            )
        path_locations = []
        for index, location in enumerate(data["path_locations"]):
            try:
                path_locations.append(
                    SourceLocation.from_dict(location, schema_version=schema_version)
                )
            except ContractError as error:
                raise _repath(error, f"$.path_locations[{index}]") from error
        if not isinstance(data["evidence"], list):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.evidence")
        if len(data["evidence"]) > 256:
            raise ContractError(
                ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, "$.evidence"
            )
        evidence = []
        for index, record in enumerate(data["evidence"]):
            try:
                evidence.append(
                    EvidenceRecord.from_dict(record, schema_version=schema_version)
                )
            except ContractError as error:
                raise _repath(error, f"$.evidence[{index}]") from error
        if not isinstance(data["reproduction_runs"], list):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_TYPE, "$.reproduction_runs"
            )
        if len(data["reproduction_runs"]) > 64:
            raise ContractError(
                ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, "$.reproduction_runs"
            )
        reproduction_runs = []
        for index, run in enumerate(data["reproduction_runs"]):
            try:
                reproduction_runs.append(
                    ReproductionRun.from_dict(run, schema_version=schema_version)
                )
            except ContractError as error:
                raise _repath(error, f"$.reproduction_runs[{index}]") from error
        return cls(
            schema_version=schema_version,
            verification_verdict=verification_verdict,
            claim_kind=claim_kind,
            hypothesis_id=data["hypothesis_id"],
            source_aep=source_aep,
            source_aep_revision=data["source_aep_revision"],
            oracle=oracle,
            evidence=evidence,
            target_location=target_location,
            impact=data["impact"],
            refutation_scope=data["refutation_scope"],
            path_locations=path_locations,
            reproduction_runs=reproduction_runs,
            trigger_conditions=data["trigger_conditions"],
            cwe_ids=data["cwe_ids"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "verification_verdict": self.verification_verdict.value,
            "claim_kind": self.claim_kind.value,
            "hypothesis_id": self.hypothesis_id,
            "source_aep": self.source_aep.to_dict(),
            "source_aep_revision": self.source_aep_revision,
            "oracle": self.oracle.to_dict(),
            "evidence": [record.to_dict() for record in self.evidence],
            "reproduction_runs": [run.to_dict() for run in self.reproduction_runs],
            "target_location": self.target_location.to_dict(),
            "path_locations": [
                location.to_dict() for location in self.path_locations
            ],
            "trigger_conditions": list(self.trigger_conditions),
            "cwe_ids": list(self.cwe_ids),
            "impact": self.impact,
            "refutation_scope": self.refutation_scope,
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


def _require_vep_schema_name(envelope: ArtifactEnvelope) -> None:
    if envelope.schema_name != VULNERABILITY_EVIDENCE_PACKAGE_SCHEMA_NAME:
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
    envelope: ArtifactEnvelope, package: VulnerabilityEvidencePackage
) -> None:
    lineage_by_id = {
        reference.artifact_id: reference for reference in envelope.lineage
    }
    aep_entry = lineage_by_id.get(package.source_aep.artifact_id)
    if (
        aep_entry is None
        or aep_entry.schema_name != _AEP_LINEAGE_SCHEMA_NAME
        or aep_entry.schema_version != package.source_aep.schema_version
    ):
        raise ContractError(
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.payload.source_aep.artifact_id",
        )
    if aep_entry.content_digest != package.source_aep.content_digest:
        raise ContractError(
            ContractErrorCode.DIGEST_MISMATCH,
            "$.payload.source_aep.content_digest",
        )
    oracle_entry = lineage_by_id.get(package.oracle.oracle_artifact_id)
    if oracle_entry is None:
        raise ContractError(
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.payload.oracle.oracle_artifact_id",
        )
    if oracle_entry.content_digest != package.oracle.content_digest:
        raise ContractError(
            ContractErrorCode.DIGEST_MISMATCH,
            "$.payload.oracle.content_digest",
        )
    for index, run in enumerate(package.reproduction_runs):
        if run.run_artifact_id not in lineage_by_id:
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE,
                f"$.payload.reproduction_runs[{index}].run_artifact_id",
            )
    for index, record in enumerate(package.evidence):
        for position, artifact_id in enumerate(record.source_artifact_ids):
            if artifact_id not in lineage_by_id:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    f"$.payload.evidence[{index}].source_artifact_ids[{position}]",
                )


def decode_vep_payload(
    value: Mapping[str, JSONValue],
    *,
    schema_version: SchemaVersion,
) -> VulnerabilityEvidencePackage:
    """Decode a validated payload mapping into a VulnerabilityEvidencePackage."""
    return VulnerabilityEvidencePackage.from_dict(value, schema_version=schema_version)


def encode_vep_payload(package: VulnerabilityEvidencePackage) -> dict[str, JSONValue]:
    """Return the canonical wire payload of a validated package."""
    if not isinstance(package, VulnerabilityEvidencePackage):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    return package.to_dict()


def decode_vep_envelope(
    data: bytes,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> "tuple[ArtifactEnvelope, VulnerabilityEvidencePackage]":
    """Decode envelope bytes and return the envelope with its VEP."""
    envelope = decode_envelope(data, limits=limits)
    _require_vep_schema_name(envelope)
    _require_inline_payload(envelope)
    package = VulnerabilityEvidencePackage.from_dict(
        envelope.payload, schema_version=envelope.schema_version
    )
    _require_lineage_provenance(envelope, package)
    _require_protected_envelope(envelope)
    return envelope, package


def encode_vep_envelope(
    envelope: ArtifactEnvelope,
    package: VulnerabilityEvidencePackage,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> bytes:
    """Verify the full VEP binding and encode the envelope canonically."""
    if not isinstance(envelope, ArtifactEnvelope):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if not isinstance(package, VulnerabilityEvidencePackage):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    _require_vep_schema_name(envelope)
    _require_inline_payload(envelope)
    if envelope.schema_version != package.schema_version:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.schema_version")
    payload = encode_vep_payload(package)
    if envelope.payload != payload:
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.payload")
    if not hmac.compare_digest(
        compute_content_digest(payload, limits=limits), envelope.content_digest
    ):
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.content_digest")
    _require_protected_envelope(envelope)
    _require_lineage_provenance(envelope, package)
    return encode_envelope(envelope, limits=limits)
