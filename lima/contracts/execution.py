"""Deterministic execution-intent pair contracts for LIMA (IP-0008).

Module-only leaf contracts on top of the IP-0001 artifact foundation for
the two pre/post-run orchestration schemas: ``Plan`` (mode, versioned
ordered stage sequence, and the mode-governed VEP prerequisite links)
and ``RunManifest`` (the executed plan version pinned by digest and
revision, the owning workflow, recorded stage attempts, and an untyped
resource-artifact id inventory). Both payloads carry zero conclusion
semantics, zero free text, zero timestamps, zero metering, and zero
floats. All cross-artifact references travel through the local
:class:`ArtifactLink` value type (ReferenceKind literal + artifact_id +
content_digest + schema_version) and are double-checked against typed
envelope lineage; resource ids are lineage-existence-checked only,
because their schemas are not frozen yet. Pure in-memory, stdlib-only,
fail-closed. Dependency direction is fixed: this module may import only
``codec``/``common``/``errors`` — never ``evidence``/``profile``/
``aep``/``vep``/``rvr``/``workflow``. The wire-value equality with
``workflow``'s mode/stage vocabularies is a string-level interface: the
enums are defined locally and that module is never imported.
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
    "PLAN_SCHEMA_NAME",
    "RUN_MANIFEST_SCHEMA_NAME",
    "PlanMode",
    "PlanStageType",
    "ReferenceKind",
    "ArtifactLink",
    "Plan",
    "RunManifest",
    "decode_plan_payload",
    "encode_plan_payload",
    "decode_plan_envelope",
    "encode_plan_envelope",
    "decode_run_manifest_payload",
    "encode_run_manifest_payload",
    "decode_run_manifest_envelope",
    "encode_run_manifest_envelope",
]

PLAN_SCHEMA_NAME = "lima.plan"
RUN_MANIFEST_SCHEMA_NAME = "lima.run-manifest"

_INT64_MAX: Final[int] = (1 << 63) - 1
_MAX_PLANNED_STAGES: Final[int] = 16
_MAX_PLAN_INPUTS: Final[int] = 16
_MAX_MANIFEST_REFERENCES: Final[int] = 256

_IDENTIFIER_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_DIGEST_PATTERN: Final = re.compile(r"[0-9a-f]{64}")


class PlanMode(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0008 §10
    """Four execution scopes; value-equal to workflow.WorkflowMode by design."""

    FULL_CHAIN = "full_chain"
    AUDIT_ONLY = "audit_only"
    VERIFY_VEP = "verify_vep"
    REPAIR_FROM_VEP = "repair_from_vep"


class PlanStageType(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0008 §10
    """Five planned stages; value-equal to workflow.StageType by design."""

    PROFILE = "profile"
    AUDIT = "audit"
    MINE = "mine"
    REPAIR = "repair"
    SUMMARIZE = "summarize"


class ReferenceKind(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0008 §10
    """Referable artifact kinds; each wire value is the schema_name literal."""

    VULNERABILITY_EVIDENCE_PACKAGE = "lima.vulnerability-evidence-package"
    WORKFLOW = "lima.workflow"
    STAGE_ATTEMPT = "lima.stage-attempt"
    PLAN = "lima.plan"


_VEP_PREREQUISITE_MODES: Final[frozenset[PlanMode]] = frozenset(
    {PlanMode.VERIFY_VEP, PlanMode.REPAIR_FROM_VEP}
)
_AUDIT_ONLY_FORBIDDEN_STAGES: Final[frozenset[PlanStageType]] = frozenset(
    {PlanStageType.MINE, PlanStageType.REPAIR}
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


def _validated_resource_ids(
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
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE, f"{path}[{index}]"
            )
    return tuple(validated)


@dataclass(frozen=True, slots=True)
class ArtifactLink:
    """Typed local reference to another artifact: kind literal + identity triple."""

    kind: ReferenceKind
    artifact_id: str
    content_digest: str
    schema_version: SchemaVersion
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ReferenceKind):
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
        kind = _wire_enum(data["kind"], ReferenceKind, "$.kind")
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


_PLAN_WIRE_FIELDS: Final = (
    "workflow_mode",
    "revision",
    "planned_stages",
    "inputs",
)


@dataclass(frozen=True, slots=True)
class Plan:
    """Pre-run execution intent: mode, ordered stages, VEP prerequisites."""

    schema_version: SchemaVersion
    workflow_mode: PlanMode
    revision: int
    planned_stages: tuple[PlanStageType, ...]
    inputs: tuple[ArtifactLink, ...] = ()
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, SchemaVersion):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.schema_version")
        if not isinstance(self.workflow_mode, PlanMode):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.workflow_mode")
        revision = _validated_int(self.revision, "$.revision")
        planned_stages = self._validated_planned_stages()
        inputs = _validated_link_tuple(
            self.inputs, "$.inputs", cap=_MAX_PLAN_INPUTS
        )
        if self.workflow_mode is PlanMode.AUDIT_ONLY:
            for index, stage in enumerate(planned_stages):
                if stage in _AUDIT_ONLY_FORBIDDEN_STAGES:
                    raise ContractError(
                        ContractErrorCode.INVALID_FIELD_VALUE,
                        f"$.planned_stages[{index}]",
                    )
        if self.workflow_mode in _VEP_PREREQUISITE_MODES:
            if not inputs:
                raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.inputs")
            for index, link in enumerate(inputs):
                if link.kind is not ReferenceKind.VULNERABILITY_EVIDENCE_PACKAGE:
                    raise ContractError(
                        ContractErrorCode.INVALID_FIELD_VALUE, f"$.inputs[{index}].kind"
                    )
        elif inputs:
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE, "$.inputs[0].kind"
            )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_PLAN_WIRE_FIELDS,
                path="$",
            ),
        )
        object.__setattr__(self, "revision", revision)
        object.__setattr__(self, "planned_stages", planned_stages)
        object.__setattr__(self, "inputs", inputs)

    def _validated_planned_stages(self) -> tuple[PlanStageType, ...]:
        items = self.planned_stages
        if not isinstance(items, (list, tuple)):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.planned_stages")
        if len(items) > _MAX_PLANNED_STAGES:
            raise ContractError(
                ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, "$.planned_stages"
            )
        if not items:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.planned_stages")
        stages = []
        for index, item in enumerate(items):
            if not isinstance(item, PlanStageType):
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_TYPE, f"$.planned_stages[{index}]"
                )
            stages.append(item)
        result = tuple(stages)
        seen: set[PlanStageType] = set()
        for index, stage in enumerate(result):
            if stage in seen:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE, f"$.planned_stages[{index}]"
                )
            seen.add(stage)
        return result

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "Plan":
        data = _as_mapping(value)
        missing = [name for name in _PLAN_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}")
        extensions = _split_extensions(
            data, known_fields=_PLAN_WIRE_FIELDS, schema_version=schema_version
        )
        workflow_mode = _wire_enum(data["workflow_mode"], PlanMode, "$.workflow_mode")
        planned_stages = data["planned_stages"]
        if not isinstance(planned_stages, list):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.planned_stages")
        if not planned_stages:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.planned_stages")
        stages = [
            _wire_enum(item, PlanStageType, f"$.planned_stages[{index}]")
            for index, item in enumerate(planned_stages)
        ]
        inputs = _parse_link_array(
            data["inputs"], "$.inputs", schema_version=schema_version
        )
        return cls(
            schema_version=schema_version,
            workflow_mode=workflow_mode,
            revision=data["revision"],
            planned_stages=stages,
            inputs=inputs,
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "workflow_mode": self.workflow_mode.value,
            "revision": self.revision,
            "planned_stages": [stage.value for stage in self.planned_stages],
            "inputs": [link.to_dict() for link in self.inputs],
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_RUN_MANIFEST_WIRE_FIELDS: Final = (
    "plan",
    "plan_revision",
    "workflow",
    "stage_attempts",
    "resource_artifact_ids",
)


@dataclass(frozen=True, slots=True)
class RunManifest:
    """Post-run record: executed plan version, workflow, attempts, resources."""

    schema_version: SchemaVersion
    plan: ArtifactLink
    plan_revision: int
    workflow: ArtifactLink
    stage_attempts: tuple[ArtifactLink, ...] = ()
    resource_artifact_ids: tuple[str, ...] = ()
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, SchemaVersion):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.schema_version")
        if not isinstance(self.plan, ArtifactLink):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.plan")
        if not isinstance(self.workflow, ArtifactLink):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.workflow")
        if self.plan.kind is not ReferenceKind.PLAN:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.plan.kind")
        if self.workflow.kind is not ReferenceKind.WORKFLOW:
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE, "$.workflow.kind"
            )
        plan = copy.deepcopy(self.plan)
        workflow = copy.deepcopy(self.workflow)
        plan_revision = _validated_int(self.plan_revision, "$.plan_revision")
        stage_attempts = _validated_link_tuple(
            self.stage_attempts, "$.stage_attempts", cap=_MAX_MANIFEST_REFERENCES
        )
        for index, link in enumerate(stage_attempts):
            if link.kind is not ReferenceKind.STAGE_ATTEMPT:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    f"$.stage_attempts[{index}].kind",
                )
        resource_artifact_ids = _validated_resource_ids(
            self.resource_artifact_ids,
            "$.resource_artifact_ids",
            cap=_MAX_MANIFEST_REFERENCES,
        )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_RUN_MANIFEST_WIRE_FIELDS,
                path="$",
            ),
        )
        object.__setattr__(self, "plan", plan)
        object.__setattr__(self, "workflow", workflow)
        object.__setattr__(self, "plan_revision", plan_revision)
        object.__setattr__(self, "stage_attempts", stage_attempts)
        object.__setattr__(self, "resource_artifact_ids", resource_artifact_ids)

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "RunManifest":
        data = _as_mapping(value)
        missing = [name for name in _RUN_MANIFEST_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}")
        extensions = _split_extensions(
            data, known_fields=_RUN_MANIFEST_WIRE_FIELDS, schema_version=schema_version
        )
        if not isinstance(data["plan"], Mapping):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.plan")
        try:
            plan = ArtifactLink.from_dict(data["plan"], schema_version=schema_version)
        except ContractError as error:
            raise _repath(error, "$.plan") from error
        if not isinstance(data["workflow"], Mapping):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.workflow")
        try:
            workflow = ArtifactLink.from_dict(
                data["workflow"], schema_version=schema_version
            )
        except ContractError as error:
            raise _repath(error, "$.workflow") from error
        stage_attempts = _parse_link_array(
            data["stage_attempts"], "$.stage_attempts", schema_version=schema_version
        )
        if not isinstance(data["resource_artifact_ids"], list):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_TYPE, "$.resource_artifact_ids"
            )
        return cls(
            schema_version=schema_version,
            plan=plan,
            plan_revision=data["plan_revision"],
            workflow=workflow,
            stage_attempts=stage_attempts,
            resource_artifact_ids=data["resource_artifact_ids"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "plan": self.plan.to_dict(),
            "plan_revision": self.plan_revision,
            "workflow": self.workflow.to_dict(),
            "stage_attempts": [link.to_dict() for link in self.stage_attempts],
            "resource_artifact_ids": list(self.resource_artifact_ids),
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
        raise ContractError(
            ContractErrorCode.INVALID_FIELD_VALUE, f"{path}.artifact_id"
        )
    if not hmac.compare_digest(entry.content_digest, link.content_digest):
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, f"{path}.content_digest")


def _require_plan_binding(envelope: ArtifactEnvelope, plan: Plan) -> None:
    if plan.revision > 1 and envelope.supersedes is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.supersedes")
    if plan.revision == 1 and envelope.supersedes is not None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.supersedes")
    if (
        envelope.supersedes is not None
        and envelope.supersedes.schema_name != PLAN_SCHEMA_NAME
    ):
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.supersedes")
    lineage_by_id = _lineage_index(envelope)
    for index, link in enumerate(plan.inputs):
        _require_link_lineage(lineage_by_id, link, f"$.payload.inputs[{index}]")


def _require_run_manifest_binding(
    envelope: ArtifactEnvelope, manifest: RunManifest
) -> None:
    lineage_by_id = _lineage_index(envelope)
    _require_link_lineage(lineage_by_id, manifest.plan, "$.payload.plan")
    _require_link_lineage(lineage_by_id, manifest.workflow, "$.payload.workflow")
    for index, link in enumerate(manifest.stage_attempts):
        _require_link_lineage(
            lineage_by_id, link, f"$.payload.stage_attempts[{index}]"
        )
    for index, artifact_id in enumerate(manifest.resource_artifact_ids):
        if artifact_id not in lineage_by_id:
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE,
                f"$.payload.resource_artifact_ids[{index}]",
            )


def decode_plan_payload(
    value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
) -> Plan:
    """Decode a validated payload mapping into a Plan."""
    return Plan.from_dict(value, schema_version=schema_version)


def encode_plan_payload(plan: Plan) -> dict[str, JSONValue]:
    """Return the canonical wire payload of a validated plan."""
    if not isinstance(plan, Plan):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    return plan.to_dict()


def decode_plan_envelope(
    data: bytes, *, limits: ContractLimits = DEFAULT_LIMITS
) -> tuple[ArtifactEnvelope, Plan]:
    """Decode envelope bytes and return the envelope with its plan."""
    envelope = decode_envelope(data, limits=limits)
    _require_schema_name(envelope, PLAN_SCHEMA_NAME)
    _require_inline_payload(envelope)
    plan = Plan.from_dict(envelope.payload, schema_version=envelope.schema_version)
    _require_plan_binding(envelope, plan)
    _require_protected_envelope(envelope)
    return envelope, plan


def encode_plan_envelope(
    envelope: ArtifactEnvelope,
    plan: Plan,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> bytes:
    """Verify the full plan binding and encode the envelope canonically."""
    if not isinstance(envelope, ArtifactEnvelope):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if not isinstance(plan, Plan):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    _require_schema_name(envelope, PLAN_SCHEMA_NAME)
    _require_inline_payload(envelope)
    if envelope.schema_version != plan.schema_version:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.schema_version")
    payload = encode_plan_payload(plan)
    if envelope.payload != payload:
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.payload")
    if not hmac.compare_digest(
        compute_content_digest(payload, limits=limits), envelope.content_digest
    ):
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.content_digest")
    _require_plan_binding(envelope, plan)
    _require_protected_envelope(envelope)
    return encode_envelope(envelope, limits=limits)


def decode_run_manifest_payload(
    value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
) -> RunManifest:
    """Decode a validated payload mapping into a RunManifest."""
    return RunManifest.from_dict(value, schema_version=schema_version)


def encode_run_manifest_payload(manifest: RunManifest) -> dict[str, JSONValue]:
    """Return the canonical wire payload of a validated run manifest."""
    if not isinstance(manifest, RunManifest):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    return manifest.to_dict()


def decode_run_manifest_envelope(
    data: bytes, *, limits: ContractLimits = DEFAULT_LIMITS
) -> tuple[ArtifactEnvelope, RunManifest]:
    """Decode envelope bytes and return the envelope with its run manifest."""
    envelope = decode_envelope(data, limits=limits)
    _require_schema_name(envelope, RUN_MANIFEST_SCHEMA_NAME)
    _require_inline_payload(envelope)
    manifest = RunManifest.from_dict(
        envelope.payload, schema_version=envelope.schema_version
    )
    _require_run_manifest_binding(envelope, manifest)
    _require_protected_envelope(envelope)
    return envelope, manifest


def encode_run_manifest_envelope(
    envelope: ArtifactEnvelope,
    manifest: RunManifest,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> bytes:
    """Verify the full run-manifest binding and encode the envelope canonically."""
    if not isinstance(envelope, ArtifactEnvelope):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if not isinstance(manifest, RunManifest):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    _require_schema_name(envelope, RUN_MANIFEST_SCHEMA_NAME)
    _require_inline_payload(envelope)
    if envelope.schema_version != manifest.schema_version:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.schema_version")
    payload = encode_run_manifest_payload(manifest)
    if envelope.payload != payload:
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.payload")
    if not hmac.compare_digest(
        compute_content_digest(payload, limits=limits), envelope.content_digest
    ):
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.content_digest")
    _require_run_manifest_binding(envelope, manifest)
    _require_protected_envelope(envelope)
    return encode_envelope(envelope, limits=limits)
