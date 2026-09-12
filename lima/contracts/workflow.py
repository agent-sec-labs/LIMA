"""Deterministic workflow spine contracts for LIMA (IP-0007).

Module-only leaf contracts on top of the IP-0001 artifact foundation for
the three cross-stage orchestration schemas: ``Workflow`` (identity,
mode, status, and references to already-emitted stage attempts),
``StageAttempt`` (stage type, attempt identity, typed input/output
artifact links, and the terminal execution fact), and
``SecurityOutcome`` (a partitioned kind vocabulary plus mandatory
evidence links). The execution-fact vocabularies (:class:`AttemptStatus`
/:class:`FailureKind`) and the security-conclusion vocabulary
(:class:`SecurityOutcomeKind`) are structurally disjoint: blocked,
skipped, failed, timeout, out-of-memory, and tool-error can never be
expressed as a safety conclusion, and vulnerability_verified /
verified_patch are illegal without the matching artifact evidence. All
cross-artifact references travel through the local :class:`ArtifactLink`
value type (kind literal + artifact_id + content_digest +
schema_version) and are double-checked against typed envelope lineage.
Payloads carry no free-text, float, confidence, severity, timestamp,
lease, or resource-accounting fields. Pure in-memory, stdlib-only,
fail-closed. Dependency direction is fixed: this module may import only
``codec``/``common``/``errors`` — never ``evidence``/``aep``/``vep``/
``profile``/``rvr``; upstream artifacts are referenced, never mirrored.
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
    "WORKFLOW_SCHEMA_NAME",
    "STAGE_ATTEMPT_SCHEMA_NAME",
    "SECURITY_OUTCOME_SCHEMA_NAME",
    "WorkflowMode",
    "WorkflowStatus",
    "StageType",
    "ArtifactKind",
    "AttemptStatus",
    "SkipReason",
    "FailureKind",
    "SecurityOutcomeKind",
    "ArtifactLink",
    "Workflow",
    "StageAttempt",
    "SecurityOutcome",
    "decode_workflow_payload",
    "encode_workflow_payload",
    "decode_workflow_envelope",
    "encode_workflow_envelope",
    "decode_stage_attempt_payload",
    "encode_stage_attempt_payload",
    "decode_stage_attempt_envelope",
    "encode_stage_attempt_envelope",
    "decode_security_outcome_payload",
    "encode_security_outcome_payload",
    "decode_security_outcome_envelope",
    "encode_security_outcome_envelope",
]

WORKFLOW_SCHEMA_NAME = "lima.workflow"
STAGE_ATTEMPT_SCHEMA_NAME = "lima.stage-attempt"
SECURITY_OUTCOME_SCHEMA_NAME = "lima.security-outcome"

_INT64_MAX: Final[int] = (1 << 63) - 1
_MAX_STAGE_ATTEMPTS: Final[int] = 256
_MAX_STAGE_REFERENCES: Final[int] = 64

_IDENTIFIER_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_DIGEST_PATTERN: Final = re.compile(r"[0-9a-f]{64}")


class WorkflowMode(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0007 §10
    """Four execution scopes; AUDIT_ONLY_LEGACY is a legacy API mapping, not a value."""

    FULL_CHAIN = "full_chain"
    AUDIT_ONLY = "audit_only"
    VERIFY_VEP = "verify_vep"
    REPAIR_FROM_VEP = "repair_from_vep"


class WorkflowStatus(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0007 §10
    """Sixteen workflow states; ``terminal`` is the only terminal state."""

    ACCEPTED = "accepted"
    CLASSIFYING = "classifying"
    MATERIALIZING = "materializing"
    AUDITING = "auditing"
    AUDIT_ADJUDICATING = "audit_adjudicating"
    AUDIT_GATE = "audit_gate"
    MINING_PLANNING = "mining_planning"
    MINING_ENV_PREPARING = "mining_env_preparing"
    MINING_RUNNING = "mining_running"
    MINING_ADJUDICATING = "mining_adjudicating"
    REPAIR_GATE = "repair_gate"
    REPAIR_PLANNING = "repair_planning"
    REPAIR_CANDIDATE_GENERATION = "repair_candidate_generation"
    REPAIR_VERIFYING = "repair_verifying"
    SUMMARIZING = "summarizing"
    TERMINAL = "terminal"


class StageType(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0007 §10
    """Five stages, one per frozen evidence artifact plus summarize."""

    PROFILE = "profile"
    AUDIT = "audit"
    MINE = "mine"
    REPAIR = "repair"
    SUMMARIZE = "summarize"


class ArtifactKind(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0007 §10
    """Referable artifact kinds; each wire value is the schema_name literal."""

    REPOSITORY_PROFILE = "lima.repository-profile"
    AUDIT_EVIDENCE_PACKAGE = "lima.audit-evidence-package"
    VULNERABILITY_EVIDENCE_PACKAGE = "lima.vulnerability-evidence-package"
    REPAIR_VERIFICATION_REPORT = "lima.repair-verification-report"
    WORKFLOW = "lima.workflow"
    STAGE_ATTEMPT = "lima.stage-attempt"


class AttemptStatus(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0007 §10
    """Seven terminal execution facts; never folded into a safety conclusion."""

    NOT_STARTED = "not_started"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    SKIPPED = "skipped"
    BLOCKED = "blocked"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SkipReason(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0007 §10
    """The two causes that make a skipped attempt legal."""

    BY_REQUEST = "by_request"
    BY_POLICY = "by_policy"


class FailureKind(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0007 §10
    """Minimal failure-category vocabulary; a FailureReport is IP-0008 scope."""

    ENVIRONMENT = "environment"
    TOOL_ERROR = "tool_error"
    TIMEOUT = "timeout"
    OUT_OF_MEMORY = "out_of_memory"
    POLICY_DENIED = "policy_denied"
    INTERNAL = "internal"


class SecurityOutcomeKind(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0007 §10
    """Twelve first security outcomes; no safe/clear/not_vulnerable exists."""

    NO_SUPPORTED_ATTACK_SURFACE = "no_supported_attack_surface"
    NO_ACTIONABLE_HYPOTHESIS = "no_actionable_hypothesis"
    MINING_SKIPPED_BY_REQUEST = "mining_skipped_by_request"
    MINING_SKIPPED_BY_POLICY = "mining_skipped_by_policy"
    MINING_BLOCKED_ENVIRONMENT = "mining_blocked_environment"
    HYPOTHESIS_NOT_REPRODUCED = "hypothesis_not_reproduced"
    VULNERABILITY_VERIFIED = "vulnerability_verified"
    REPAIR_UNSUPPORTED = "repair_unsupported"
    REPAIR_BLOCKED_ENVIRONMENT = "repair_blocked_environment"
    NO_CANDIDATE_PASSED = "no_candidate_passed"
    VERIFIED_PATCH = "verified_patch"
    FULL_CHAIN_INCOMPLETE = "full_chain_incomplete"


_AUDIT_ONLY_FORBIDDEN_STATUSES: Final[frozenset[WorkflowStatus]] = frozenset(
    {
        WorkflowStatus.MINING_PLANNING,
        WorkflowStatus.MINING_ENV_PREPARING,
        WorkflowStatus.MINING_RUNNING,
        WorkflowStatus.MINING_ADJUDICATING,
        WorkflowStatus.REPAIR_GATE,
        WorkflowStatus.REPAIR_PLANNING,
        WorkflowStatus.REPAIR_CANDIDATE_GENERATION,
        WorkflowStatus.REPAIR_VERIFYING,
    }
)

_STAGE_INPUT_KINDS: Final[dict[StageType, frozenset[ArtifactKind]]] = {
    StageType.PROFILE: frozenset(),
    StageType.AUDIT: frozenset({ArtifactKind.REPOSITORY_PROFILE}),
    StageType.MINE: frozenset({ArtifactKind.AUDIT_EVIDENCE_PACKAGE}),
    StageType.REPAIR: frozenset({ArtifactKind.VULNERABILITY_EVIDENCE_PACKAGE}),
    StageType.SUMMARIZE: frozenset(
        {
            ArtifactKind.REPOSITORY_PROFILE,
            ArtifactKind.AUDIT_EVIDENCE_PACKAGE,
            ArtifactKind.VULNERABILITY_EVIDENCE_PACKAGE,
            ArtifactKind.REPAIR_VERIFICATION_REPORT,
        }
    ),
}

_STAGE_OUTPUT_KINDS: Final[dict[StageType, frozenset[ArtifactKind]]] = {
    StageType.PROFILE: frozenset({ArtifactKind.REPOSITORY_PROFILE}),
    StageType.AUDIT: frozenset({ArtifactKind.AUDIT_EVIDENCE_PACKAGE}),
    StageType.MINE: frozenset({ArtifactKind.VULNERABILITY_EVIDENCE_PACKAGE}),
    StageType.REPAIR: frozenset({ArtifactKind.REPAIR_VERIFICATION_REPORT}),
    StageType.SUMMARIZE: frozenset(),
}

_SUCCEEDED_INPUT_KINDS: Final[dict[StageType, ArtifactKind]] = {
    StageType.AUDIT: ArtifactKind.REPOSITORY_PROFILE,
    StageType.MINE: ArtifactKind.AUDIT_EVIDENCE_PACKAGE,
    StageType.REPAIR: ArtifactKind.VULNERABILITY_EVIDENCE_PACKAGE,
}

_SUCCEEDED_OUTPUT_KINDS: Final[dict[StageType, ArtifactKind]] = {
    StageType.PROFILE: ArtifactKind.REPOSITORY_PROFILE,
    StageType.AUDIT: ArtifactKind.AUDIT_EVIDENCE_PACKAGE,
    StageType.MINE: ArtifactKind.VULNERABILITY_EVIDENCE_PACKAGE,
    StageType.REPAIR: ArtifactKind.REPAIR_VERIFICATION_REPORT,
}

_OUTCOME_EVIDENCE_KINDS: Final[frozenset[ArtifactKind]] = frozenset(
    {
        ArtifactKind.REPOSITORY_PROFILE,
        ArtifactKind.AUDIT_EVIDENCE_PACKAGE,
        ArtifactKind.VULNERABILITY_EVIDENCE_PACKAGE,
        ArtifactKind.REPAIR_VERIFICATION_REPORT,
    }
)

# Packet §14.2-O4 partition: these five kinds never carry conclusion
# semantics, so their required-evidence sets exclude conclusion-level
# artifacts (rvr is forbidden outright for all of them).
_NON_CONCLUSION_KINDS: Final[frozenset[SecurityOutcomeKind]] = frozenset(
    {
        SecurityOutcomeKind.MINING_SKIPPED_BY_REQUEST,
        SecurityOutcomeKind.MINING_SKIPPED_BY_POLICY,
        SecurityOutcomeKind.MINING_BLOCKED_ENVIRONMENT,
        SecurityOutcomeKind.REPAIR_BLOCKED_ENVIRONMENT,
        SecurityOutcomeKind.FULL_CHAIN_INCOMPLETE,
    }
)

_NO_CONCLUSION_REQUIRED: Final[frozenset[ArtifactKind]] = frozenset(
    {ArtifactKind.AUDIT_EVIDENCE_PACKAGE}
)
_NO_CONCLUSION_FORBIDDEN: Final[frozenset[ArtifactKind]] = frozenset(
    {
        ArtifactKind.VULNERABILITY_EVIDENCE_PACKAGE,
        ArtifactKind.REPAIR_VERIFICATION_REPORT,
    }
)
_MINE_REQUIRED: Final[frozenset[ArtifactKind]] = frozenset(
    {ArtifactKind.VULNERABILITY_EVIDENCE_PACKAGE}
)
_REPAIR_FORBIDDEN: Final[frozenset[ArtifactKind]] = frozenset(
    {ArtifactKind.REPAIR_VERIFICATION_REPORT}
)
_RVR_REQUIRED: Final[frozenset[ArtifactKind]] = frozenset(
    {ArtifactKind.REPAIR_VERIFICATION_REPORT}
)

_KIND_EVIDENCE_MATRIX: Final[
    dict[SecurityOutcomeKind, tuple[frozenset[ArtifactKind], frozenset[ArtifactKind]]]
] = {
    SecurityOutcomeKind.NO_SUPPORTED_ATTACK_SURFACE: (
        _NO_CONCLUSION_REQUIRED,
        _NO_CONCLUSION_FORBIDDEN,
    ),
    SecurityOutcomeKind.NO_ACTIONABLE_HYPOTHESIS: (
        _NO_CONCLUSION_REQUIRED,
        _NO_CONCLUSION_FORBIDDEN,
    ),
    SecurityOutcomeKind.MINING_SKIPPED_BY_REQUEST: (
        _NO_CONCLUSION_REQUIRED,
        _NO_CONCLUSION_FORBIDDEN,
    ),
    SecurityOutcomeKind.MINING_SKIPPED_BY_POLICY: (
        _NO_CONCLUSION_REQUIRED,
        _NO_CONCLUSION_FORBIDDEN,
    ),
    SecurityOutcomeKind.MINING_BLOCKED_ENVIRONMENT: (
        _NO_CONCLUSION_REQUIRED,
        _NO_CONCLUSION_FORBIDDEN,
    ),
    SecurityOutcomeKind.HYPOTHESIS_NOT_REPRODUCED: (_MINE_REQUIRED, _REPAIR_FORBIDDEN),
    SecurityOutcomeKind.VULNERABILITY_VERIFIED: (_MINE_REQUIRED, _REPAIR_FORBIDDEN),
    SecurityOutcomeKind.REPAIR_UNSUPPORTED: (_MINE_REQUIRED, _REPAIR_FORBIDDEN),
    SecurityOutcomeKind.REPAIR_BLOCKED_ENVIRONMENT: (
        _MINE_REQUIRED,
        _REPAIR_FORBIDDEN,
    ),
    SecurityOutcomeKind.NO_CANDIDATE_PASSED: (_RVR_REQUIRED, frozenset()),
    SecurityOutcomeKind.VERIFIED_PATCH: (_RVR_REQUIRED, frozenset()),
    SecurityOutcomeKind.FULL_CHAIN_INCOMPLETE: (frozenset(), frozenset()),
}


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


def _validated_int(value: object, path: str) -> int:
    # Exact type check: bool is an int subclass and must still be rejected.
    if type(value) is not int:
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if not 1 <= value <= _INT64_MAX:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return value


def _validated_extensions(
    extensions: object,
    *,
    known_fields: tuple[str, ...],
    path: str,
) -> dict[str, JSONValue]:
    if not isinstance(extensions, dict):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
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


_ARTIFACT_LINK_WIRE_FIELDS: Final = (
    "kind",
    "artifact_id",
    "content_digest",
    "schema_version",
)


def _parse_link_array(
    items: object,
    path: str,
    *,
    schema_version: SchemaVersion,
) -> "list[ArtifactLink]":
    if not isinstance(items, list):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    links: list[ArtifactLink] = []
    for index, item in enumerate(items):
        if not isinstance(item, Mapping):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, f"{path}[{index}]")
        try:
            links.append(ArtifactLink.from_dict(item, schema_version=schema_version))
        except ContractError as error:
            raise _repath(error, f"{path}[{index}]") from error
    return links


def _validated_link_tuple(
    items: object,
    path: str,
    *,
    cap: int,
) -> tuple["ArtifactLink", ...]:
    if not isinstance(items, (list, tuple)):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if len(items) > cap:
        raise ContractError(ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, path)
    links = []
    for index, item in enumerate(items):
        if not isinstance(item, ArtifactLink):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, f"{path}[{index}]")
        links.append(copy.deepcopy(item))
    result = tuple(links)
    for index in range(1, len(result)):
        if result[index].artifact_id <= result[index - 1].artifact_id:
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE, f"{path}[{index}].artifact_id"
            )
    return result


@dataclass(frozen=True, slots=True)
class ArtifactLink:
    """Typed local reference to another artifact: kind literal + identity triple."""

    kind: ArtifactKind
    artifact_id: str
    content_digest: str
    schema_version: SchemaVersion
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ArtifactKind):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.kind")
        artifact_id = _validated_identifier(self.artifact_id, "$.artifact_id")
        content_digest = _validated_digest(self.content_digest, "$.content_digest")
        if not isinstance(self.schema_version, SchemaVersion):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.schema_version")
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_ARTIFACT_LINK_WIRE_FIELDS,
                path="$",
            ),
        )
        object.__setattr__(self, "artifact_id", artifact_id)
        object.__setattr__(self, "content_digest", content_digest)

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "ArtifactLink":
        data = _as_mapping(value)
        missing = [name for name in _ARTIFACT_LINK_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}")
        extensions = _split_extensions(
            data,
            known_fields=_ARTIFACT_LINK_WIRE_FIELDS,
            schema_version=schema_version,
        )
        kind = _wire_enum(data["kind"], ArtifactKind, "$.kind")
        return cls(
            kind=kind,
            artifact_id=data["artifact_id"],
            content_digest=data["content_digest"],
            schema_version=SchemaVersion.parse(data["schema_version"]),
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "kind": self.kind.value,
            "artifact_id": self.artifact_id,
            "content_digest": self.content_digest,
            "schema_version": str(self.schema_version),
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_WORKFLOW_WIRE_FIELDS: Final = (
    "workflow_id",
    "workflow_mode",
    "status",
    "revision",
    "stage_attempts",
)


@dataclass(frozen=True, slots=True)
class Workflow:
    """Workflow spine artifact: identity, mode, status, and attempt references."""

    schema_version: SchemaVersion
    workflow_id: str
    workflow_mode: WorkflowMode
    status: WorkflowStatus
    revision: int
    stage_attempts: tuple[ArtifactLink, ...] = ()
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, SchemaVersion):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.schema_version")
        if not isinstance(self.workflow_mode, WorkflowMode):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.workflow_mode")
        if not isinstance(self.status, WorkflowStatus):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.status")
        workflow_id = _validated_identifier(self.workflow_id, "$.workflow_id")
        revision = _validated_int(self.revision, "$.revision")
        stage_attempts = _validated_link_tuple(
            self.stage_attempts, "$.stage_attempts", cap=_MAX_STAGE_ATTEMPTS
        )
        for index, link in enumerate(stage_attempts):
            if link.kind is not ArtifactKind.STAGE_ATTEMPT:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    f"$.stage_attempts[{index}].kind",
                )
        if (
            self.workflow_mode is WorkflowMode.AUDIT_ONLY
            and self.status in _AUDIT_ONLY_FORBIDDEN_STATUSES
        ):
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.status")
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_WORKFLOW_WIRE_FIELDS,
                path="$",
            ),
        )
        object.__setattr__(self, "workflow_id", workflow_id)
        object.__setattr__(self, "revision", revision)
        object.__setattr__(self, "stage_attempts", stage_attempts)

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "Workflow":
        data = _as_mapping(value)
        missing = [name for name in _WORKFLOW_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}")
        extensions = _split_extensions(
            data, known_fields=_WORKFLOW_WIRE_FIELDS, schema_version=schema_version
        )
        workflow_mode = _wire_enum(data["workflow_mode"], WorkflowMode, "$.workflow_mode")
        status = _wire_enum(data["status"], WorkflowStatus, "$.status")
        stage_attempts = _parse_link_array(
            data["stage_attempts"], "$.stage_attempts", schema_version=schema_version
        )
        return cls(
            schema_version=schema_version,
            workflow_id=data["workflow_id"],
            workflow_mode=workflow_mode,
            status=status,
            revision=data["revision"],
            stage_attempts=stage_attempts,
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "workflow_id": self.workflow_id,
            "workflow_mode": self.workflow_mode.value,
            "status": self.status.value,
            "revision": self.revision,
            "stage_attempts": [link.to_dict() for link in self.stage_attempts],
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_STAGE_ATTEMPT_WIRE_FIELDS: Final = (
    "workflow_id",
    "stage_attempt_id",
    "stage_type",
    "attempt_number",
    "status",
    "inputs",
    "outputs",
    "skip_reason",
    "failure_kind",
)


@dataclass(frozen=True, slots=True)
class StageAttempt:
    """One immutable attempt of one stage: execution facts, never a verdict."""

    schema_version: SchemaVersion
    workflow_id: str
    stage_attempt_id: str
    stage_type: StageType
    attempt_number: int
    status: AttemptStatus
    inputs: tuple[ArtifactLink, ...] = ()
    outputs: tuple[ArtifactLink, ...] = ()
    skip_reason: SkipReason | None = None
    failure_kind: FailureKind | None = None
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, SchemaVersion):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.schema_version")
        if not isinstance(self.stage_type, StageType):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.stage_type")
        if not isinstance(self.status, AttemptStatus):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.status")
        if self.skip_reason is not None and not isinstance(self.skip_reason, SkipReason):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.skip_reason")
        if self.failure_kind is not None and not isinstance(self.failure_kind, FailureKind):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.failure_kind")
        workflow_id = _validated_identifier(self.workflow_id, "$.workflow_id")
        stage_attempt_id = _validated_identifier(
            self.stage_attempt_id, "$.stage_attempt_id"
        )
        attempt_number = _validated_int(self.attempt_number, "$.attempt_number")
        inputs = _validated_link_tuple(self.inputs, "$.inputs", cap=_MAX_STAGE_REFERENCES)
        outputs = _validated_link_tuple(
            self.outputs, "$.outputs", cap=_MAX_STAGE_REFERENCES
        )
        allowed_inputs = _STAGE_INPUT_KINDS[self.stage_type]
        for index, link in enumerate(inputs):
            if link.kind not in allowed_inputs:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE, f"$.inputs[{index}].kind"
                )
        allowed_outputs = _STAGE_OUTPUT_KINDS[self.stage_type]
        for index, link in enumerate(outputs):
            if link.kind not in allowed_outputs:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE, f"$.outputs[{index}].kind"
                )
        if self.status is AttemptStatus.SKIPPED and self.skip_reason is None:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.skip_reason")
        if self.status is not AttemptStatus.SKIPPED and self.skip_reason is not None:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.skip_reason")
        failure_required = self.status in (AttemptStatus.BLOCKED, AttemptStatus.FAILED)
        if failure_required and self.failure_kind is None:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.failure_kind")
        if not failure_required and self.failure_kind is not None:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.failure_kind")
        if self.status is not AttemptStatus.SUCCEEDED and outputs:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.outputs")
        if self.status is AttemptStatus.SUCCEEDED:
            required_input = _SUCCEEDED_INPUT_KINDS.get(self.stage_type)
            if required_input is not None and not any(
                link.kind is required_input for link in inputs
            ):
                raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.inputs")
            required_output = _SUCCEEDED_OUTPUT_KINDS.get(self.stage_type)
            if required_output is not None and not any(
                link.kind is required_output for link in outputs
            ):
                raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.outputs")
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_STAGE_ATTEMPT_WIRE_FIELDS,
                path="$",
            ),
        )
        object.__setattr__(self, "workflow_id", workflow_id)
        object.__setattr__(self, "stage_attempt_id", stage_attempt_id)
        object.__setattr__(self, "attempt_number", attempt_number)
        object.__setattr__(self, "inputs", inputs)
        object.__setattr__(self, "outputs", outputs)

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "StageAttempt":
        data = _as_mapping(value)
        missing = [name for name in _STAGE_ATTEMPT_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}")
        extensions = _split_extensions(
            data, known_fields=_STAGE_ATTEMPT_WIRE_FIELDS, schema_version=schema_version
        )
        stage_type = _wire_enum(data["stage_type"], StageType, "$.stage_type")
        status = _wire_enum(data["status"], AttemptStatus, "$.status")
        skip_reason = (
            None
            if data["skip_reason"] is None
            else _wire_enum(data["skip_reason"], SkipReason, "$.skip_reason")
        )
        failure_kind = (
            None
            if data["failure_kind"] is None
            else _wire_enum(data["failure_kind"], FailureKind, "$.failure_kind")
        )
        inputs = _parse_link_array(data["inputs"], "$.inputs", schema_version=schema_version)
        outputs = _parse_link_array(
            data["outputs"], "$.outputs", schema_version=schema_version
        )
        return cls(
            schema_version=schema_version,
            workflow_id=data["workflow_id"],
            stage_attempt_id=data["stage_attempt_id"],
            stage_type=stage_type,
            attempt_number=data["attempt_number"],
            status=status,
            inputs=inputs,
            outputs=outputs,
            skip_reason=skip_reason,
            failure_kind=failure_kind,
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "workflow_id": self.workflow_id,
            "stage_attempt_id": self.stage_attempt_id,
            "stage_type": self.stage_type.value,
            "attempt_number": self.attempt_number,
            "status": self.status.value,
            "inputs": [link.to_dict() for link in self.inputs],
            "outputs": [link.to_dict() for link in self.outputs],
            "skip_reason": None if self.skip_reason is None else self.skip_reason.value,
            "failure_kind": (
                None if self.failure_kind is None else self.failure_kind.value
            ),
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_SECURITY_OUTCOME_WIRE_FIELDS: Final = (
    "workflow_id",
    "kind",
    "workflow",
    "evidence",
)


@dataclass(frozen=True, slots=True)
class SecurityOutcome:
    """Terminal security conclusion for one workflow: partitioned kind + evidence."""

    schema_version: SchemaVersion
    workflow_id: str
    kind: SecurityOutcomeKind
    workflow: ArtifactLink
    evidence: tuple[ArtifactLink, ...] = ()
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, SchemaVersion):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.schema_version")
        if not isinstance(self.kind, SecurityOutcomeKind):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.kind")
        if not isinstance(self.workflow, ArtifactLink):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.workflow")
        if self.workflow.kind is not ArtifactKind.WORKFLOW:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.workflow.kind")
        workflow = copy.deepcopy(self.workflow)
        workflow_id = _validated_identifier(self.workflow_id, "$.workflow_id")
        evidence = _validated_link_tuple(
            self.evidence, "$.evidence", cap=_MAX_STAGE_REFERENCES
        )
        for index, link in enumerate(evidence):
            if link.kind not in _OUTCOME_EVIDENCE_KINDS:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE, f"$.evidence[{index}].kind"
                )
        required_kinds, forbidden_kinds = _KIND_EVIDENCE_MATRIX[self.kind]
        if required_kinds and not any(link.kind in required_kinds for link in evidence):
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.kind")
        for index, link in enumerate(evidence):
            if link.kind in forbidden_kinds:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE, f"$.evidence[{index}].kind"
                )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_SECURITY_OUTCOME_WIRE_FIELDS,
                path="$",
            ),
        )
        object.__setattr__(self, "workflow_id", workflow_id)
        object.__setattr__(self, "workflow", workflow)
        object.__setattr__(self, "evidence", evidence)

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "SecurityOutcome":
        data = _as_mapping(value)
        missing = [name for name in _SECURITY_OUTCOME_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}")
        extensions = _split_extensions(
            data, known_fields=_SECURITY_OUTCOME_WIRE_FIELDS, schema_version=schema_version
        )
        kind = _wire_enum(data["kind"], SecurityOutcomeKind, "$.kind")
        if not isinstance(data["workflow"], Mapping):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.workflow")
        try:
            workflow = ArtifactLink.from_dict(
                data["workflow"], schema_version=schema_version
            )
        except ContractError as error:
            raise _repath(error, "$.workflow") from error
        evidence = _parse_link_array(
            data["evidence"], "$.evidence", schema_version=schema_version
        )
        return cls(
            schema_version=schema_version,
            workflow_id=data["workflow_id"],
            kind=kind,
            workflow=workflow,
            evidence=evidence,
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "workflow_id": self.workflow_id,
            "kind": self.kind.value,
            "workflow": self.workflow.to_dict(),
            "evidence": [link.to_dict() for link in self.evidence],
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


def _require_schema_name(envelope: ArtifactEnvelope, schema_name: str) -> None:
    if envelope.schema_name != schema_name:
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
    envelope: ArtifactEnvelope,
    links_with_paths: tuple[tuple[ArtifactLink, str], ...],
) -> None:
    lineage_by_id = {
        reference.artifact_id: reference for reference in envelope.lineage
    }
    for link, path in links_with_paths:
        entry = lineage_by_id.get(link.artifact_id)
        if (
            entry is None
            or entry.schema_name != link.kind.value
            or entry.schema_version != link.schema_version
        ):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE, f"{path}.artifact_id"
            )
        if not hmac.compare_digest(entry.content_digest, link.content_digest):
            raise ContractError(ContractErrorCode.DIGEST_MISMATCH, f"{path}.content_digest")


def _workflow_lineage_pairs(
    workflow: Workflow,
) -> tuple[tuple[ArtifactLink, str], ...]:
    return tuple(
        (link, f"$.payload.stage_attempts[{index}]")
        for index, link in enumerate(workflow.stage_attempts)
    )


def _stage_attempt_lineage_pairs(
    attempt: StageAttempt,
) -> tuple[tuple[ArtifactLink, str], ...]:
    return (
        *((link, f"$.payload.inputs[{index}]") for index, link in enumerate(attempt.inputs)),
        *((link, f"$.payload.outputs[{index}]") for index, link in enumerate(attempt.outputs)),
    )


def _security_outcome_lineage_pairs(
    outcome: SecurityOutcome,
) -> tuple[tuple[ArtifactLink, str], ...]:
    return (
        (outcome.workflow, "$.payload.workflow"),
        *(
            (link, f"$.payload.evidence[{index}]")
            for index, link in enumerate(outcome.evidence)
        ),
    )


def _require_workflow_binding(
    envelope: ArtifactEnvelope, workflow: Workflow
) -> None:
    if workflow.workflow_id != envelope.workflow_id:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.workflow_id")
    if workflow.revision > 1 and envelope.supersedes is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.supersedes")
    if workflow.revision == 1 and envelope.supersedes is not None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.supersedes")
    if (
        envelope.supersedes is not None
        and envelope.supersedes.schema_name != WORKFLOW_SCHEMA_NAME
    ):
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.supersedes")
    _require_lineage_provenance(envelope, _workflow_lineage_pairs(workflow))


def _require_stage_attempt_binding(
    envelope: ArtifactEnvelope, attempt: StageAttempt
) -> None:
    if attempt.workflow_id != envelope.workflow_id:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.workflow_id")
    if attempt.stage_attempt_id != envelope.stage_attempt_id:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.stage_attempt_id")
    _require_lineage_provenance(envelope, _stage_attempt_lineage_pairs(attempt))


def _require_security_outcome_binding(
    envelope: ArtifactEnvelope, outcome: SecurityOutcome
) -> None:
    if outcome.workflow_id != envelope.workflow_id:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.workflow_id")
    _require_lineage_provenance(envelope, _security_outcome_lineage_pairs(outcome))


def decode_workflow_payload(
    value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
) -> Workflow:
    """Decode a validated payload mapping into a Workflow."""
    return Workflow.from_dict(value, schema_version=schema_version)


def encode_workflow_payload(workflow: Workflow) -> dict[str, JSONValue]:
    """Return the canonical wire payload of a validated workflow."""
    if not isinstance(workflow, Workflow):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    return workflow.to_dict()


def decode_workflow_envelope(
    data: bytes, *, limits: ContractLimits = DEFAULT_LIMITS
) -> tuple[ArtifactEnvelope, Workflow]:
    """Decode envelope bytes and return the envelope with its workflow."""
    envelope = decode_envelope(data, limits=limits)
    _require_schema_name(envelope, WORKFLOW_SCHEMA_NAME)
    _require_inline_payload(envelope)
    workflow = Workflow.from_dict(
        envelope.payload, schema_version=envelope.schema_version
    )
    _require_workflow_binding(envelope, workflow)
    _require_protected_envelope(envelope)
    return envelope, workflow


def encode_workflow_envelope(
    envelope: ArtifactEnvelope,
    workflow: Workflow,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> bytes:
    """Verify the full workflow binding and encode the envelope canonically."""
    if not isinstance(envelope, ArtifactEnvelope):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if not isinstance(workflow, Workflow):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    _require_schema_name(envelope, WORKFLOW_SCHEMA_NAME)
    _require_inline_payload(envelope)
    if envelope.schema_version != workflow.schema_version:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.schema_version")
    payload = encode_workflow_payload(workflow)
    if envelope.payload != payload:
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.payload")
    if not hmac.compare_digest(
        compute_content_digest(payload, limits=limits), envelope.content_digest
    ):
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.content_digest")
    _require_workflow_binding(envelope, workflow)
    _require_protected_envelope(envelope)
    return encode_envelope(envelope, limits=limits)


def decode_stage_attempt_payload(
    value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
) -> StageAttempt:
    """Decode a validated payload mapping into a StageAttempt."""
    return StageAttempt.from_dict(value, schema_version=schema_version)


def encode_stage_attempt_payload(attempt: StageAttempt) -> dict[str, JSONValue]:
    """Return the canonical wire payload of a validated stage attempt."""
    if not isinstance(attempt, StageAttempt):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    return attempt.to_dict()


def decode_stage_attempt_envelope(
    data: bytes, *, limits: ContractLimits = DEFAULT_LIMITS
) -> tuple[ArtifactEnvelope, StageAttempt]:
    """Decode envelope bytes and return the envelope with its stage attempt."""
    envelope = decode_envelope(data, limits=limits)
    _require_schema_name(envelope, STAGE_ATTEMPT_SCHEMA_NAME)
    _require_inline_payload(envelope)
    attempt = StageAttempt.from_dict(
        envelope.payload, schema_version=envelope.schema_version
    )
    _require_stage_attempt_binding(envelope, attempt)
    _require_protected_envelope(envelope)
    return envelope, attempt


def encode_stage_attempt_envelope(
    envelope: ArtifactEnvelope,
    attempt: StageAttempt,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> bytes:
    """Verify the full stage-attempt binding and encode the envelope canonically."""
    if not isinstance(envelope, ArtifactEnvelope):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if not isinstance(attempt, StageAttempt):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    _require_schema_name(envelope, STAGE_ATTEMPT_SCHEMA_NAME)
    _require_inline_payload(envelope)
    if envelope.schema_version != attempt.schema_version:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.schema_version")
    payload = encode_stage_attempt_payload(attempt)
    if envelope.payload != payload:
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.payload")
    if not hmac.compare_digest(
        compute_content_digest(payload, limits=limits), envelope.content_digest
    ):
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.content_digest")
    _require_stage_attempt_binding(envelope, attempt)
    _require_protected_envelope(envelope)
    return encode_envelope(envelope, limits=limits)


def decode_security_outcome_payload(
    value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
) -> SecurityOutcome:
    """Decode a validated payload mapping into a SecurityOutcome."""
    return SecurityOutcome.from_dict(value, schema_version=schema_version)


def encode_security_outcome_payload(outcome: SecurityOutcome) -> dict[str, JSONValue]:
    """Return the canonical wire payload of a validated security outcome."""
    if not isinstance(outcome, SecurityOutcome):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    return outcome.to_dict()


def decode_security_outcome_envelope(
    data: bytes, *, limits: ContractLimits = DEFAULT_LIMITS
) -> tuple[ArtifactEnvelope, SecurityOutcome]:
    """Decode envelope bytes and return the envelope with its security outcome."""
    envelope = decode_envelope(data, limits=limits)
    _require_schema_name(envelope, SECURITY_OUTCOME_SCHEMA_NAME)
    _require_inline_payload(envelope)
    outcome = SecurityOutcome.from_dict(
        envelope.payload, schema_version=envelope.schema_version
    )
    _require_security_outcome_binding(envelope, outcome)
    _require_protected_envelope(envelope)
    return envelope, outcome


def encode_security_outcome_envelope(
    envelope: ArtifactEnvelope,
    outcome: SecurityOutcome,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> bytes:
    """Verify the full security-outcome binding and encode the envelope canonically."""
    if not isinstance(envelope, ArtifactEnvelope):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if not isinstance(outcome, SecurityOutcome):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    _require_schema_name(envelope, SECURITY_OUTCOME_SCHEMA_NAME)
    _require_inline_payload(envelope)
    if envelope.schema_version != outcome.schema_version:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.schema_version")
    payload = encode_security_outcome_payload(outcome)
    if envelope.payload != payload:
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.payload")
    if not hmac.compare_digest(
        compute_content_digest(payload, limits=limits), envelope.content_digest
    ):
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.content_digest")
    _require_security_outcome_binding(envelope, outcome)
    _require_protected_envelope(envelope)
    return encode_envelope(envelope, limits=limits)
