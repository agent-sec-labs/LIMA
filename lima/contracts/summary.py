"""Deterministic summary + failure report contracts for LIMA (IP-0009).

Module-only leaf contracts on top of the IP-0001 artifact foundation for
the two terminal-conclusion schemas: ``WorkflowSummary`` (reference
aggregation with mutually exclusive source vocabularies — a chain summary
must carry a typed security-outcome reference and may never carry legacy
ids, a legacy-audit summary may carry no typed link at all and must carry
at least one untyped legacy id, so a legacy success can never be
expressed as a full-chain success) and ``FailureReport`` (the six-value
failure vocabulary x scope x disposition plus untyped evidence ids — the
structured carrier for timeout / out-of-memory / tool-error facts that
never encodes a security conclusion). Both payloads carry zero
conclusion mirroring, zero free text, zero timestamps, zero metering,
and zero floats. All typed cross-artifact references travel through the
local :class:`ArtifactLink` value type (SummaryReferenceKind literal +
artifact_id + content_digest + schema_version) and are double-checked
against typed envelope lineage; untyped ids (legacy / evidence) are
lineage-existence-checked only, because their schemas are not frozen.
Pure in-memory, stdlib-only, fail-closed. Dependency direction is
fixed: this module may import only ``codec``/``common``/``errors`` —
never ``evidence``/``profile``/``aep``/``vep``/``rvr``/``workflow``/
``execution``. The wire-value equality with workflow's FailureKind is a
string-level interface: the enum is defined locally and never imported.
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
    "WORKFLOW_SUMMARY_SCHEMA_NAME",
    "FAILURE_REPORT_SCHEMA_NAME",
    "SummarySourceKind",
    "ExecutionStatus",
    "FailureKind",
    "FailureScope",
    "FailureDisposition",
    "SummaryReferenceKind",
    "ArtifactLink",
    "WorkflowSummary",
    "FailureReport",
    "decode_workflow_summary_payload",
    "encode_workflow_summary_payload",
    "decode_workflow_summary_envelope",
    "encode_workflow_summary_envelope",
    "decode_failure_report_payload",
    "encode_failure_report_payload",
    "decode_failure_report_envelope",
    "encode_failure_report_envelope",
]

WORKFLOW_SUMMARY_SCHEMA_NAME = "lima.workflow-summary"
FAILURE_REPORT_SCHEMA_NAME = "lima.failure-report"

_MAX_SUMMARY_ATTEMPTS: Final[int] = 256
_MAX_SUMMARY_EVIDENCE: Final[int] = 64
_MAX_UNTYPED_IDS: Final[int] = 256

_IDENTIFIER_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_DIGEST_PATTERN: Final = re.compile(r"[0-9a-f]{64}")


class SummarySourceKind(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0009 §10
    """Two summary origins with disjoint reference vocabularies (V5-FR-05)."""

    CHAIN = "chain"
    LEGACY_AUDIT = "legacy_audit"


class ExecutionStatus(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0009 §10
    """Terminal technical execution dimension; queued/running are runtime states."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FailureKind(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0009 §10
    """Six NFR-01 failure categories; value-equal to workflow.FailureKind."""

    ENVIRONMENT = "environment"
    TOOL_ERROR = "tool_error"
    TIMEOUT = "timeout"
    OUT_OF_MEMORY = "out_of_memory"
    POLICY_DENIED = "policy_denied"
    INTERNAL = "internal"


class FailureScope(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0009 §10
    """The orchestration object a failure is attached to."""

    WORKFLOW = "workflow"
    STAGE_ATTEMPT = "stage_attempt"


class FailureDisposition(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0009 §10
    """Permanent vs transient; retry execution itself belongs to #90 policy."""

    PERMANENT = "permanent"
    TRANSIENT = "transient"


class SummaryReferenceKind(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0009 §10
    """Referable artifact kinds; each wire value is the schema_name literal."""

    REPOSITORY_PROFILE = "lima.repository-profile"
    AUDIT_EVIDENCE_PACKAGE = "lima.audit-evidence-package"
    VULNERABILITY_EVIDENCE_PACKAGE = "lima.vulnerability-evidence-package"
    REPAIR_VERIFICATION_REPORT = "lima.repair-verification-report"
    WORKFLOW = "lima.workflow"
    STAGE_ATTEMPT = "lima.stage-attempt"
    SECURITY_OUTCOME = "lima.security-outcome"
    RUN_MANIFEST = "lima.run-manifest"


_SUMMARY_EVIDENCE_KINDS: Final[frozenset[SummaryReferenceKind]] = frozenset(
    {
        SummaryReferenceKind.REPOSITORY_PROFILE,
        SummaryReferenceKind.AUDIT_EVIDENCE_PACKAGE,
        SummaryReferenceKind.VULNERABILITY_EVIDENCE_PACKAGE,
        SummaryReferenceKind.REPAIR_VERIFICATION_REPORT,
    }
)


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


def _parse_optional_link(
    value: object,
    path: str,
    *,
    schema_version: SchemaVersion,
) -> "ArtifactLink | None":
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    try:
        return ArtifactLink.from_dict(value, schema_version=schema_version)
    except ContractError as error:
        raise _repath(error, path) from error


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
) -> "tuple[ArtifactLink, ...]":
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


def _validated_untyped_ids(
    items: object,
    path: str,
    *,
    cap: int,
) -> tuple[str, ...]:
    if not isinstance(items, (list, tuple)):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if len(items) > cap:
        raise ContractError(ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, path)
    validated = [
        _validated_identifier(item, f"{path}[{index}]")
        for index, item in enumerate(items)
    ]
    for index in range(1, len(validated)):
        if validated[index] <= validated[index - 1]:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, f"{path}[{index}]")
    return tuple(validated)


@dataclass(frozen=True, slots=True)
class ArtifactLink:
    """Typed local reference to another artifact: kind literal + identity triple."""

    kind: SummaryReferenceKind
    artifact_id: str
    content_digest: str
    schema_version: SchemaVersion
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.kind, SummaryReferenceKind):
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
        kind = _wire_enum(data["kind"], SummaryReferenceKind, "$.kind")
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


_WORKFLOW_SUMMARY_WIRE_FIELDS: Final = (
    "source",
    "execution_status",
    "workflow",
    "security_outcome",
    "run_manifest",
    "stage_attempts",
    "evidence",
    "legacy_artifact_ids",
)


@dataclass(frozen=True, slots=True)
class WorkflowSummary:
    """Terminal workflow summary: source-exclusive reference aggregation."""

    schema_version: SchemaVersion
    source: SummarySourceKind
    execution_status: ExecutionStatus
    workflow: ArtifactLink | None = None
    security_outcome: ArtifactLink | None = None
    run_manifest: ArtifactLink | None = None
    stage_attempts: tuple[ArtifactLink, ...] = ()
    evidence: tuple[ArtifactLink, ...] = ()
    legacy_artifact_ids: tuple[str, ...] = ()
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, SchemaVersion):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.schema_version")
        if not isinstance(self.source, SummarySourceKind):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.source")
        if not isinstance(self.execution_status, ExecutionStatus):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.execution_status")
        workflow = self._validated_field_link("workflow", SummaryReferenceKind.WORKFLOW)
        security_outcome = self._validated_field_link(
            "security_outcome", SummaryReferenceKind.SECURITY_OUTCOME
        )
        run_manifest = self._validated_field_link(
            "run_manifest", SummaryReferenceKind.RUN_MANIFEST
        )
        stage_attempts = _validated_link_tuple(
            self.stage_attempts, "$.stage_attempts", cap=_MAX_SUMMARY_ATTEMPTS
        )
        for index, link in enumerate(stage_attempts):
            if link.kind is not SummaryReferenceKind.STAGE_ATTEMPT:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    f"$.stage_attempts[{index}].kind",
                )
        evidence = _validated_link_tuple(
            self.evidence, "$.evidence", cap=_MAX_SUMMARY_EVIDENCE
        )
        for index, link in enumerate(evidence):
            if link.kind not in _SUMMARY_EVIDENCE_KINDS:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE, f"$.evidence[{index}].kind"
                )
        legacy_artifact_ids = _validated_untyped_ids(
            self.legacy_artifact_ids,
            "$.legacy_artifact_ids",
            cap=_MAX_UNTYPED_IDS,
        )
        if self.source is SummarySourceKind.CHAIN:
            if workflow is None:
                raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.workflow")
            if security_outcome is None:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE, "$.security_outcome"
                )
            if legacy_artifact_ids:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE, "$.legacy_artifact_ids"
                )
        else:
            if workflow is not None:
                raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.workflow")
            if security_outcome is not None:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE, "$.security_outcome"
                )
            if run_manifest is not None:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE, "$.run_manifest"
                )
            if stage_attempts:
                raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.stage_attempts")
            if evidence:
                raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.evidence")
            if not legacy_artifact_ids:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE, "$.legacy_artifact_ids"
                )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_WORKFLOW_SUMMARY_WIRE_FIELDS,
                path="$",
            ),
        )
        object.__setattr__(self, "workflow", workflow)
        object.__setattr__(self, "security_outcome", security_outcome)
        object.__setattr__(self, "run_manifest", run_manifest)
        object.__setattr__(self, "stage_attempts", stage_attempts)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "legacy_artifact_ids", legacy_artifact_ids)

    def _validated_field_link(
        self, name: str, expected_kind: SummaryReferenceKind
    ) -> "ArtifactLink | None":
        value = getattr(self, name)
        if value is None:
            return None
        if not isinstance(value, ArtifactLink):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, f"$.{name}")
        if value.kind is not expected_kind:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, f"$.{name}.kind")
        return copy.deepcopy(value)

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "WorkflowSummary":
        data = _as_mapping(value)
        missing = [
            name for name in _WORKFLOW_SUMMARY_WIRE_FIELDS if name not in data
        ]
        if missing:
            raise ContractError(ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}")
        extensions = _split_extensions(
            data,
            known_fields=_WORKFLOW_SUMMARY_WIRE_FIELDS,
            schema_version=schema_version,
        )
        source = _wire_enum(data["source"], SummarySourceKind, "$.source")
        execution_status = _wire_enum(
            data["execution_status"], ExecutionStatus, "$.execution_status"
        )
        workflow = _parse_optional_link(
            data["workflow"], "$.workflow", schema_version=schema_version
        )
        security_outcome = _parse_optional_link(
            data["security_outcome"], "$.security_outcome", schema_version=schema_version
        )
        run_manifest = _parse_optional_link(
            data["run_manifest"], "$.run_manifest", schema_version=schema_version
        )
        stage_attempts = _parse_link_array(
            data["stage_attempts"], "$.stage_attempts", schema_version=schema_version
        )
        evidence = _parse_link_array(
            data["evidence"], "$.evidence", schema_version=schema_version
        )
        if not isinstance(data["legacy_artifact_ids"], list):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_TYPE, "$.legacy_artifact_ids"
            )
        return cls(
            schema_version=schema_version,
            source=source,
            execution_status=execution_status,
            workflow=workflow,
            security_outcome=security_outcome,
            run_manifest=run_manifest,
            stage_attempts=stage_attempts,
            evidence=evidence,
            legacy_artifact_ids=data["legacy_artifact_ids"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "source": self.source.value,
            "execution_status": self.execution_status.value,
            "workflow": None if self.workflow is None else self.workflow.to_dict(),
            "security_outcome": (
                None if self.security_outcome is None else self.security_outcome.to_dict()
            ),
            "run_manifest": (
                None if self.run_manifest is None else self.run_manifest.to_dict()
            ),
            "stage_attempts": [link.to_dict() for link in self.stage_attempts],
            "evidence": [link.to_dict() for link in self.evidence],
            "legacy_artifact_ids": list(self.legacy_artifact_ids),
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_FAILURE_REPORT_WIRE_FIELDS: Final = (
    "failure_kind",
    "scope",
    "disposition",
    "owner",
    "workflow",
    "stage_attempt",
    "evidence_artifact_ids",
)


@dataclass(frozen=True, slots=True)
class FailureReport:
    """Structured failure fact: six-value kind x scope x disposition + evidence ids."""

    schema_version: SchemaVersion
    failure_kind: FailureKind
    scope: FailureScope
    disposition: FailureDisposition
    owner: str
    workflow: ArtifactLink | None = None
    stage_attempt: ArtifactLink | None = None
    evidence_artifact_ids: tuple[str, ...] = ()
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, SchemaVersion):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.schema_version")
        if not isinstance(self.failure_kind, FailureKind):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.failure_kind")
        if not isinstance(self.scope, FailureScope):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.scope")
        if not isinstance(self.disposition, FailureDisposition):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.disposition")
        owner = _validated_identifier(self.owner, "$.owner")
        workflow = None
        if self.workflow is not None:
            if not isinstance(self.workflow, ArtifactLink):
                raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.workflow")
            if self.workflow.kind is not SummaryReferenceKind.WORKFLOW:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE, "$.workflow.kind"
                )
            workflow = copy.deepcopy(self.workflow)
        stage_attempt = None
        if self.stage_attempt is not None:
            if not isinstance(self.stage_attempt, ArtifactLink):
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_TYPE, "$.stage_attempt"
                )
            if self.stage_attempt.kind is not SummaryReferenceKind.STAGE_ATTEMPT:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE, "$.stage_attempt.kind"
                )
            stage_attempt = copy.deepcopy(self.stage_attempt)
        evidence_artifact_ids = _validated_untyped_ids(
            self.evidence_artifact_ids,
            "$.evidence_artifact_ids",
            cap=_MAX_UNTYPED_IDS,
        )
        if self.scope is FailureScope.WORKFLOW:
            if workflow is None:
                raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.workflow")
            if stage_attempt is not None:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE, "$.stage_attempt"
                )
        else:
            if stage_attempt is None:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE, "$.stage_attempt"
                )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_FAILURE_REPORT_WIRE_FIELDS,
                path="$",
            ),
        )
        object.__setattr__(self, "owner", owner)
        object.__setattr__(self, "workflow", workflow)
        object.__setattr__(self, "stage_attempt", stage_attempt)
        object.__setattr__(self, "evidence_artifact_ids", evidence_artifact_ids)

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "FailureReport":
        data = _as_mapping(value)
        missing = [
            name for name in _FAILURE_REPORT_WIRE_FIELDS if name not in data
        ]
        if missing:
            raise ContractError(ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}")
        extensions = _split_extensions(
            data,
            known_fields=_FAILURE_REPORT_WIRE_FIELDS,
            schema_version=schema_version,
        )
        failure_kind = _wire_enum(data["failure_kind"], FailureKind, "$.failure_kind")
        scope = _wire_enum(data["scope"], FailureScope, "$.scope")
        disposition = _wire_enum(data["disposition"], FailureDisposition, "$.disposition")
        workflow = _parse_optional_link(
            data["workflow"], "$.workflow", schema_version=schema_version
        )
        stage_attempt = _parse_optional_link(
            data["stage_attempt"], "$.stage_attempt", schema_version=schema_version
        )
        if not isinstance(data["evidence_artifact_ids"], list):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_TYPE, "$.evidence_artifact_ids"
            )
        return cls(
            schema_version=schema_version,
            failure_kind=failure_kind,
            scope=scope,
            disposition=disposition,
            owner=data["owner"],
            workflow=workflow,
            stage_attempt=stage_attempt,
            evidence_artifact_ids=data["evidence_artifact_ids"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "failure_kind": self.failure_kind.value,
            "scope": self.scope.value,
            "disposition": self.disposition.value,
            "owner": self.owner,
            "workflow": None if self.workflow is None else self.workflow.to_dict(),
            "stage_attempt": (
                None if self.stage_attempt is None else self.stage_attempt.to_dict()
            ),
            "evidence_artifact_ids": list(self.evidence_artifact_ids),
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


def _lineage_index(envelope: ArtifactEnvelope) -> dict[str, object]:
    return {reference.artifact_id: reference for reference in envelope.lineage}


def _require_link_lineage(
    lineage_by_id: Mapping[str, object], link: ArtifactLink, path: str
) -> None:
    entry = lineage_by_id.get(link.artifact_id)
    if (
        entry is None
        or entry.schema_name != link.kind.value
        or entry.schema_version != link.schema_version
    ):
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, f"{path}.artifact_id")
    if not hmac.compare_digest(entry.content_digest, link.content_digest):
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, f"{path}.content_digest")


def _require_workflow_summary_binding(
    envelope: ArtifactEnvelope, summary: WorkflowSummary
) -> None:
    lineage_by_id = _lineage_index(envelope)
    if summary.workflow is not None:
        _require_link_lineage(lineage_by_id, summary.workflow, "$.payload.workflow")
    if summary.security_outcome is not None:
        _require_link_lineage(
            lineage_by_id, summary.security_outcome, "$.payload.security_outcome"
        )
    if summary.run_manifest is not None:
        _require_link_lineage(
            lineage_by_id, summary.run_manifest, "$.payload.run_manifest"
        )
    for index, link in enumerate(summary.stage_attempts):
        _require_link_lineage(
            lineage_by_id, link, f"$.payload.stage_attempts[{index}]"
        )
    for index, link in enumerate(summary.evidence):
        _require_link_lineage(lineage_by_id, link, f"$.payload.evidence[{index}]")
    for index, artifact_id in enumerate(summary.legacy_artifact_ids):
        if artifact_id not in lineage_by_id:
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE,
                f"$.payload.legacy_artifact_ids[{index}]",
            )


def _require_failure_report_binding(
    envelope: ArtifactEnvelope, report: FailureReport
) -> None:
    lineage_by_id = _lineage_index(envelope)
    if report.workflow is not None:
        _require_link_lineage(lineage_by_id, report.workflow, "$.payload.workflow")
    if report.stage_attempt is not None:
        _require_link_lineage(
            lineage_by_id, report.stage_attempt, "$.payload.stage_attempt"
        )
    for index, artifact_id in enumerate(report.evidence_artifact_ids):
        if artifact_id not in lineage_by_id:
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE,
                f"$.payload.evidence_artifact_ids[{index}]",
            )


def decode_workflow_summary_payload(
    value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
) -> WorkflowSummary:
    """Decode a validated payload mapping into a WorkflowSummary."""
    return WorkflowSummary.from_dict(value, schema_version=schema_version)


def encode_workflow_summary_payload(
    summary: WorkflowSummary,
) -> dict[str, JSONValue]:
    """Return the canonical wire payload of a validated workflow summary."""
    if not isinstance(summary, WorkflowSummary):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    return summary.to_dict()


def decode_workflow_summary_envelope(
    data: bytes, *, limits: ContractLimits = DEFAULT_LIMITS
) -> tuple[ArtifactEnvelope, WorkflowSummary]:
    """Decode envelope bytes and return the envelope with its workflow summary."""
    envelope = decode_envelope(data, limits=limits)
    _require_schema_name(envelope, WORKFLOW_SUMMARY_SCHEMA_NAME)
    _require_inline_payload(envelope)
    summary = WorkflowSummary.from_dict(
        envelope.payload, schema_version=envelope.schema_version
    )
    _require_workflow_summary_binding(envelope, summary)
    _require_protected_envelope(envelope)
    return envelope, summary


def encode_workflow_summary_envelope(
    envelope: ArtifactEnvelope,
    summary: WorkflowSummary,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> bytes:
    """Verify the full summary binding and encode the envelope canonically."""
    if not isinstance(envelope, ArtifactEnvelope):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if not isinstance(summary, WorkflowSummary):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    _require_schema_name(envelope, WORKFLOW_SUMMARY_SCHEMA_NAME)
    _require_inline_payload(envelope)
    if envelope.schema_version != summary.schema_version:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.schema_version")
    payload = encode_workflow_summary_payload(summary)
    if envelope.payload != payload:
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.payload")
    if not hmac.compare_digest(
        compute_content_digest(payload, limits=limits), envelope.content_digest
    ):
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.content_digest")
    _require_workflow_summary_binding(envelope, summary)
    _require_protected_envelope(envelope)
    return encode_envelope(envelope, limits=limits)


def decode_failure_report_payload(
    value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
) -> FailureReport:
    """Decode a validated payload mapping into a FailureReport."""
    return FailureReport.from_dict(value, schema_version=schema_version)


def encode_failure_report_payload(report: FailureReport) -> dict[str, JSONValue]:
    """Return the canonical wire payload of a validated failure report."""
    if not isinstance(report, FailureReport):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    return report.to_dict()


def decode_failure_report_envelope(
    data: bytes, *, limits: ContractLimits = DEFAULT_LIMITS
) -> tuple[ArtifactEnvelope, FailureReport]:
    """Decode envelope bytes and return the envelope with its failure report."""
    envelope = decode_envelope(data, limits=limits)
    _require_schema_name(envelope, FAILURE_REPORT_SCHEMA_NAME)
    _require_inline_payload(envelope)
    report = FailureReport.from_dict(
        envelope.payload, schema_version=envelope.schema_version
    )
    _require_failure_report_binding(envelope, report)
    _require_protected_envelope(envelope)
    return envelope, report


def encode_failure_report_envelope(
    envelope: ArtifactEnvelope,
    report: FailureReport,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> bytes:
    """Verify the full failure-report binding and encode the envelope canonically."""
    if not isinstance(envelope, ArtifactEnvelope):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if not isinstance(report, FailureReport):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    _require_schema_name(envelope, FAILURE_REPORT_SCHEMA_NAME)
    _require_inline_payload(envelope)
    if envelope.schema_version != report.schema_version:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.schema_version")
    payload = encode_failure_report_payload(report)
    if envelope.payload != payload:
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.payload")
    if not hmac.compare_digest(
        compute_content_digest(payload, limits=limits), envelope.content_digest
    ):
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.content_digest")
    _require_failure_report_binding(envelope, report)
    _require_protected_envelope(envelope)
    return encode_envelope(envelope, limits=limits)
