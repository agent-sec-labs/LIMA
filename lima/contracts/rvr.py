"""Deterministic Repair Verification Report (RVR) contracts for LIMA (IP-0006).

Module-only leaf contracts on top of the IP-0001 artifact foundation:
per-candidate x per-gate verification with the frozen mandatory gate pair
(functional_preservation + security_preservation, each exactly once), the
three-way candidate verdict mapping (verified_patch only when every
mandatory gate passes; any failed gate means rejected; anything else is
inconclusive), the generator-may-not-verify-own-candidate ban, cross-
candidate patch-digest uniqueness, and typed VEP lineage provenance.
The payload structurally cannot express a vulnerability status: there is
no overall report verdict and no confidence/severity/is_fixed vocabulary,
so empty or fully-rejected reports never imply the vulnerability is gone.
Pure in-memory, stdlib-only, fail-closed. Dependency direction is fixed:
this module may import only ``codec``/``common``/``errors`` — never
``evidence``/``aep``/``vep``/``profile``; upstream artifacts travel only
through the local :class:`VepReference` triple and typed lineage entries.
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

__all__ = [
    "REPAIR_VERIFICATION_REPORT_SCHEMA_NAME",
    "GateKind",
    "GateOutcome",
    "CandidateVerdict",
    "VepReference",
    "GateResult",
    "CandidateVerification",
    "RepairVerificationReport",
    "decode_rvr_payload",
    "encode_rvr_payload",
    "decode_rvr_envelope",
    "encode_rvr_envelope",
]

REPAIR_VERIFICATION_REPORT_SCHEMA_NAME = "lima.repair-verification-report"

_VEP_LINEAGE_SCHEMA_NAME = "lima.vulnerability-evidence-package"
_MAX_PATH_BYTES: Final[int] = 1024
_MAX_STRATEGY_BYTES: Final[int] = 512
_MAX_DETAIL_BYTES: Final[int] = 4096

_IDENTIFIER_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_DIGEST_PATTERN: Final = re.compile(r"[0-9a-f]{64}")
_DRIVE_PREFIX_PATTERN: Final = re.compile(r"[A-Za-z]:")


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


def _validated_path(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    normalized = unicodedata.normalize("NFC", value)
    encoded = _utf8_bytes(normalized, path)
    if not normalized:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    if len(encoded) > _MAX_PATH_BYTES:
        raise ContractError(ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED, path)
    if any(unicodedata.category(char) == "Cc" for char in normalized):
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    if normalized.startswith("/") or "\\" in normalized:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    if _DRIVE_PREFIX_PATTERN.match(normalized) is not None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    for segment in normalized.split("/"):
        if segment in ("", ".", ".."):
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return normalized


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


class GateKind(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0006 §10
    """The mandatory preservation gate pair every candidate must carry."""

    FUNCTIONAL_PRESERVATION = "functional_preservation"
    SECURITY_PRESERVATION = "security_preservation"


class GateOutcome(str, Enum):  # noqa: UP042 -- frozen by IP-0006 §10
    """Six-state gate execution facts; never folded into a safety conclusion."""

    # "pass" is the frozen IP-0006 §10 wire value, not a credential.
    PASS = "pass"  # noqa: S105 -- frozen wire value  # nosec B105
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"
    TOOL_ERROR = "tool_error"
    POLICY_DENIED = "policy_denied"


class CandidateVerdict(str, Enum):  # noqa: UP042 -- frozen by IP-0006 §10
    """Per-candidate adjudication; the vocabulary has no vulnerability status."""

    VERIFIED_PATCH = "verified_patch"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


_VEP_REFERENCE_WIRE_FIELDS: Final = (
    "artifact_id",
    "content_digest",
    "schema_version",
)


@dataclass(frozen=True, slots=True)
class VepReference:
    """FR-02 identity triple pinning the source vulnerability evidence package."""

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
                known_fields=_VEP_REFERENCE_WIRE_FIELDS,
                version=None,
                path="$",
            ),
        )

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "VepReference":
        data = _as_mapping(value)
        missing = [name for name in _VEP_REFERENCE_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data,
            known_fields=_VEP_REFERENCE_WIRE_FIELDS,
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


_PATCH_REFERENCE_WIRE_FIELDS: Final = ("patch_artifact_id", "content_digest")


@dataclass(frozen=True, slots=True)
class PatchReference:
    """Module-internal logical reference to one candidate patch artifact."""

    patch_artifact_id: str
    content_digest: str
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "patch_artifact_id",
            _validated_identifier(self.patch_artifact_id, "$.patch_artifact_id"),
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
                known_fields=_PATCH_REFERENCE_WIRE_FIELDS,
                version=None,
                path="$",
            ),
        )

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "PatchReference":
        data = _as_mapping(value)
        missing = [name for name in _PATCH_REFERENCE_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data,
            known_fields=_PATCH_REFERENCE_WIRE_FIELDS,
            schema_version=schema_version,
        )
        return cls(
            patch_artifact_id=data["patch_artifact_id"],
            content_digest=data["content_digest"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "patch_artifact_id": self.patch_artifact_id,
            "content_digest": self.content_digest,
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_GATE_RESULT_WIRE_FIELDS: Final = (
    "gate",
    "outcome",
    "producer",
    "evidence_artifact_ids",
    "detail",
)


@dataclass(frozen=True, slots=True)
class GateResult:
    """One mandatory gate's outcome with its independent producer and evidence."""

    gate: GateKind
    outcome: GateOutcome
    producer: str
    evidence_artifact_ids: tuple[str, ...]
    detail: str
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.gate, GateKind):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.gate")
        if not isinstance(self.outcome, GateOutcome):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.outcome")
        object.__setattr__(
            self, "producer", _validated_identifier(self.producer, "$.producer")
        )
        object.__setattr__(
            self,
            "evidence_artifact_ids",
            _validated_sorted_str_array(
                self.evidence_artifact_ids,
                "$.evidence_artifact_ids",
                cap=32,
                allow_empty=False,
                item_validator=_validated_identifier,
            ),
        )
        object.__setattr__(
            self,
            "detail",
            _validated_bounded_text(self.detail, "$.detail", max_bytes=_MAX_DETAIL_BYTES),
        )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_GATE_RESULT_WIRE_FIELDS,
                version=None,
                path="$",
            ),
        )

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "GateResult":
        data = _as_mapping(value)
        missing = [name for name in _GATE_RESULT_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data,
            known_fields=_GATE_RESULT_WIRE_FIELDS,
            schema_version=schema_version,
        )
        gate = _wire_enum(data["gate"], GateKind, "$.gate")
        outcome = _wire_enum(data["outcome"], GateOutcome, "$.outcome")
        return cls(
            gate=gate,
            outcome=outcome,
            producer=data["producer"],
            evidence_artifact_ids=data["evidence_artifact_ids"],
            detail=data["detail"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "gate": self.gate.value,
            "outcome": self.outcome.value,
            "producer": self.producer,
            "evidence_artifact_ids": list(self.evidence_artifact_ids),
            "detail": self.detail,
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_MANDATORY_GATE_ORDER: Final = (
    GateKind.FUNCTIONAL_PRESERVATION,
    GateKind.SECURITY_PRESERVATION,
)
_CANDIDATE_WIRE_FIELDS: Final = (
    "candidate_id",
    "patch",
    "strategy",
    "changed_files",
    "generator",
    "gates",
    "verdict",
)


@dataclass(frozen=True, slots=True)
class CandidateVerification:
    """Per-candidate verification: patch identity, surface, and both gate results."""

    candidate_id: str
    patch: PatchReference
    strategy: str
    changed_files: tuple[str, ...]
    generator: str
    gates: tuple[GateResult, ...]
    verdict: CandidateVerdict
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        candidate_id = _validated_identifier(self.candidate_id, "$.candidate_id")
        if not isinstance(self.patch, PatchReference):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.patch")
        patch = copy.deepcopy(self.patch)
        strategy = _validated_bounded_text(
            self.strategy, "$.strategy", max_bytes=_MAX_STRATEGY_BYTES
        )
        changed_files = _validated_sorted_str_array(
            self.changed_files,
            "$.changed_files",
            cap=1024,
            allow_empty=True,
            item_validator=_validated_path,
        )
        generator = _validated_identifier(self.generator, "$.generator")
        if not isinstance(self.gates, (list, tuple)):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.gates")
        if len(self.gates) != 2:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.gates")
        gates = []
        for index, gate_result in enumerate(self.gates):
            if not isinstance(gate_result, GateResult):
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_TYPE, f"$.gates[{index}]"
                )
            gates.append(copy.deepcopy(gate_result))
        gates = tuple(gates)
        if tuple(gate_result.gate for gate_result in gates) != _MANDATORY_GATE_ORDER:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.gates")
        if not isinstance(self.verdict, CandidateVerdict):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.verdict")
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_CANDIDATE_WIRE_FIELDS,
                version=None,
                path="$",
            ),
        )

        outcomes = [gate_result.outcome for gate_result in gates]
        any_failed = any(outcome is GateOutcome.FAILED for outcome in outcomes)
        all_pass = all(outcome is GateOutcome.PASS for outcome in outcomes)
        if all_pass and not any_failed:
            expected = CandidateVerdict.VERIFIED_PATCH
        elif any_failed:
            expected = CandidateVerdict.REJECTED
        else:
            expected = CandidateVerdict.INCONCLUSIVE
        if self.verdict is not expected:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.verdict")
        for index, gate_result in enumerate(gates):
            if gate_result.producer == generator:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    f"$.gates[{index}].producer",
                )

        object.__setattr__(self, "candidate_id", candidate_id)
        object.__setattr__(self, "patch", patch)
        object.__setattr__(self, "strategy", strategy)
        object.__setattr__(self, "changed_files", changed_files)
        object.__setattr__(self, "generator", generator)
        object.__setattr__(self, "gates", gates)

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "CandidateVerification":
        data = _as_mapping(value)
        missing = [name for name in _CANDIDATE_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data,
            known_fields=_CANDIDATE_WIRE_FIELDS,
            schema_version=schema_version,
        )
        if not isinstance(data["patch"], Mapping):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.patch")
        try:
            patch = PatchReference.from_dict(
                data["patch"], schema_version=schema_version
            )
        except ContractError as error:
            raise _repath(error, "$.patch") from error
        if not isinstance(data["gates"], list):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.gates")
        gates = []
        for index, gate_result in enumerate(data["gates"]):
            try:
                gates.append(
                    GateResult.from_dict(gate_result, schema_version=schema_version)
                )
            except ContractError as error:
                raise _repath(error, f"$.gates[{index}]") from error
        verdict = _wire_enum(data["verdict"], CandidateVerdict, "$.verdict")
        return cls(
            candidate_id=data["candidate_id"],
            patch=patch,
            strategy=data["strategy"],
            changed_files=data["changed_files"],
            generator=data["generator"],
            gates=gates,
            verdict=verdict,
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "candidate_id": self.candidate_id,
            "patch": self.patch.to_dict(),
            "strategy": self.strategy,
            "changed_files": list(self.changed_files),
            "generator": self.generator,
            "gates": [gate_result.to_dict() for gate_result in self.gates],
            "verdict": self.verdict.value,
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_REPORT_WIRE_FIELDS: Final = ("source_vep", "candidates")


def _reject_current_minor_nested_extensions(
    *,
    source_vep,
    candidates,
    version,
):
    if not _is_current_minor(version):
        return

    def check(container, path):
        if container:
            raise ContractError(ContractErrorCode.UNKNOWN_FIELD, path)

    check(source_vep.extensions, "$.source_vep")
    for index, candidate in enumerate(candidates):
        check(candidate.extensions, f"$.candidates[{index}]")
        check(candidate.patch.extensions, f"$.candidates[{index}].patch")
        for position, gate_result in enumerate(candidate.gates):
            check(
                gate_result.extensions,
                f"$.candidates[{index}].gates[{position}]",
            )


@dataclass(frozen=True, slots=True)
class RepairVerificationReport:
    """Per-candidate x per-gate verification output for one source VEP."""

    schema_version: SchemaVersion
    source_vep: VepReference
    candidates: tuple[CandidateVerification, ...] = ()
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, SchemaVersion):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.schema_version")
        if not isinstance(self.source_vep, VepReference):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.source_vep")
        source_vep = copy.deepcopy(self.source_vep)
        if not isinstance(self.candidates, (list, tuple)):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.candidates")
        if len(self.candidates) > 64:
            raise ContractError(
                ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, "$.candidates"
            )
        candidates = []
        for index, candidate in enumerate(self.candidates):
            if not isinstance(candidate, CandidateVerification):
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_TYPE, f"$.candidates[{index}]"
                )
            candidates.append(copy.deepcopy(candidate))
        candidates = tuple(candidates)
        for index in range(1, len(candidates)):
            if candidates[index].candidate_id <= candidates[index - 1].candidate_id:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    f"$.candidates[{index}].candidate_id",
                )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_REPORT_WIRE_FIELDS,
                version=self.schema_version,
                path="$",
            ),
        )
        _reject_current_minor_nested_extensions(
            source_vep=source_vep,
            candidates=candidates,
            version=self.schema_version,
        )
        seen_patch_digests: set[str] = set()
        for index, candidate in enumerate(candidates):
            digest = candidate.patch.content_digest
            if digest in seen_patch_digests:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    f"$.candidates[{index}].patch.content_digest",
                )
            seen_patch_digests.add(digest)
        object.__setattr__(self, "source_vep", source_vep)
        object.__setattr__(self, "candidates", candidates)

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "RepairVerificationReport":
        data = _as_mapping(value)
        missing = [name for name in _REPORT_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data, known_fields=_REPORT_WIRE_FIELDS, schema_version=schema_version
        )
        if not isinstance(data["source_vep"], Mapping):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.source_vep")
        try:
            source_vep = VepReference.from_dict(
                data["source_vep"], schema_version=schema_version
            )
        except ContractError as error:
            raise _repath(error, "$.source_vep") from error
        if not isinstance(data["candidates"], list):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.candidates")
        if len(data["candidates"]) > 64:
            raise ContractError(
                ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, "$.candidates"
            )
        candidates = []
        for index, candidate in enumerate(data["candidates"]):
            try:
                candidates.append(
                    CandidateVerification.from_dict(
                        candidate, schema_version=schema_version
                    )
                )
            except ContractError as error:
                raise _repath(error, f"$.candidates[{index}]") from error
        return cls(
            schema_version=schema_version,
            source_vep=source_vep,
            candidates=candidates,
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "source_vep": self.source_vep.to_dict(),
            "candidates": [candidate.to_dict() for candidate in self.candidates],
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


def _require_rvr_schema_name(envelope: ArtifactEnvelope) -> None:
    if envelope.schema_name != REPAIR_VERIFICATION_REPORT_SCHEMA_NAME:
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
    envelope: ArtifactEnvelope, report: RepairVerificationReport
) -> None:
    lineage_by_id = {
        reference.artifact_id: reference for reference in envelope.lineage
    }
    vep_entry = lineage_by_id.get(report.source_vep.artifact_id)
    if (
        vep_entry is None
        or vep_entry.schema_name != _VEP_LINEAGE_SCHEMA_NAME
        or vep_entry.schema_version != report.source_vep.schema_version
    ):
        raise ContractError(
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.payload.source_vep.artifact_id",
        )
    if vep_entry.content_digest != report.source_vep.content_digest:
        raise ContractError(
            ContractErrorCode.DIGEST_MISMATCH,
            "$.payload.source_vep.content_digest",
        )
    for index, candidate in enumerate(report.candidates):
        patch_entry = lineage_by_id.get(candidate.patch.patch_artifact_id)
        if patch_entry is None:
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE,
                f"$.payload.candidates[{index}].patch.patch_artifact_id",
            )
        if patch_entry.content_digest != candidate.patch.content_digest:
            raise ContractError(
                ContractErrorCode.DIGEST_MISMATCH,
                f"$.payload.candidates[{index}].patch.content_digest",
            )
        for position, gate_result in enumerate(candidate.gates):
            for slot, artifact_id in enumerate(gate_result.evidence_artifact_ids):
                if artifact_id not in lineage_by_id:
                    raise ContractError(
                        ContractErrorCode.INVALID_FIELD_VALUE,
                        f"$.payload.candidates[{index}].gates[{position}]"
                        f".evidence_artifact_ids[{slot}]",
                    )


def decode_rvr_payload(
    value: Mapping[str, JSONValue],
    *,
    schema_version: SchemaVersion,
) -> RepairVerificationReport:
    """Decode a validated payload mapping into a RepairVerificationReport."""
    return RepairVerificationReport.from_dict(value, schema_version=schema_version)


def encode_rvr_payload(report: RepairVerificationReport) -> dict[str, JSONValue]:
    """Return the canonical wire payload of a validated report."""
    if not isinstance(report, RepairVerificationReport):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    return report.to_dict()


def decode_rvr_envelope(
    data: bytes,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> "tuple[ArtifactEnvelope, RepairVerificationReport]":
    """Decode envelope bytes and return the envelope with its RVR."""
    envelope = decode_envelope(data, limits=limits)
    _require_rvr_schema_name(envelope)
    _require_inline_payload(envelope)
    report = RepairVerificationReport.from_dict(
        envelope.payload, schema_version=envelope.schema_version
    )
    _require_lineage_provenance(envelope, report)
    _require_protected_envelope(envelope)
    return envelope, report


def encode_rvr_envelope(
    envelope: ArtifactEnvelope,
    report: RepairVerificationReport,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> bytes:
    """Verify the full RVR binding and encode the envelope canonically."""
    if not isinstance(envelope, ArtifactEnvelope):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if not isinstance(report, RepairVerificationReport):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    _require_rvr_schema_name(envelope)
    _require_inline_payload(envelope)
    if envelope.schema_version != report.schema_version:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.schema_version")
    payload = encode_rvr_payload(report)
    if envelope.payload != payload:
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.payload")
    if not hmac.compare_digest(
        compute_content_digest(payload, limits=limits), envelope.content_digest
    ):
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.content_digest")
    _require_protected_envelope(envelope)
    _require_lineage_provenance(envelope, report)
    return encode_envelope(envelope, limits=limits)
