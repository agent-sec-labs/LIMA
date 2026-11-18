"""Version-1 contracts for persistent C/C++ investigations.

The investigation loop keeps its runtime trace in memory; these
dataclasses are the durable, versioned projection of that trace.  They
are deliberately stricter than the runtime shapes: every field set is
closed, every vocabulary is an enum, and parsing rejects unknown or
duplicated fields instead of guessing forward.  ``InvestigationIdentity``
is created only by trusted code; model replies reference task-local IDs
(evidence and hypothesis numbers) and can never introduce a foreign
tenant, task or snapshot.
"""

from __future__ import annotations

import dataclasses
import json
import re
from dataclasses import dataclass, field
from typing import Any

from .cxx_agent_models import parse_untrusted_json

SCHEMA_VERSION = 1

INVESTIGATION_STATUSES = (
    "queued",
    "running",
    "waiting_children",
    "completed",
    "inconclusive",
    "needs_attention",
    "cancelled",
    "failed",
)
HYPOTHESIS_STATUSES = ("active", "supported", "refuted", "unresolved")

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _bounded_text(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{label} must be non-empty text of at most {maximum} chars")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase sha-256 digest")
    return value


def _string_list(value: Any, label: str, maximum: int) -> list[str]:
    if type(value) is not list or len(value) > maximum:
        raise ValueError(f"{label} must be a bounded array")
    for item in value:
        if not isinstance(item, str) or not item or len(item) > 200:
            raise ValueError(f"{label} entries must be bounded text")
    return list(value)


def _enum(value: Any, vocabulary: tuple[str, ...], label: str) -> str:
    if value not in vocabulary:
        raise ValueError(f"{label} is outside the closed vocabulary")
    return value


def _exact_fields(
    payload: Any, expected: frozenset[str], label: str
) -> dict[str, Any]:
    if type(payload) is not dict or set(payload) != set(expected):
        raise ValueError(f"{label} fields do not match the schema")
    return payload


@dataclass(frozen=True)
class InvestigationIdentity:
    """Trusted binding of one investigation to tenant, task and snapshot."""

    tenant_id: str
    task_id: str
    investigation_id: str
    snapshot_hash: str
    context_digest: str
    config_digest: str

    def __post_init__(self) -> None:
        _bounded_text(self.tenant_id, "identity tenant_id", 128)
        _bounded_text(self.task_id, "identity task_id", 128)
        _bounded_text(self.investigation_id, "identity investigation_id", 128)
        _digest(self.snapshot_hash, "identity snapshot_hash")
        _digest(self.context_digest, "identity context_digest")
        _digest(self.config_digest, "identity config_digest")

    def to_json(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_json(cls, payload: Any) -> "InvestigationIdentity":
        fields = _exact_fields(
            payload,
            frozenset(
                {
                    "tenant_id", "task_id", "investigation_id",
                    "snapshot_hash", "context_digest", "config_digest",
                }
            ),
            "investigation identity",
        )
        return cls(**fields)


@dataclass
class HypothesisRecord:
    hypothesis_id: str
    revision: int
    statement: str
    cwe: str
    trigger_path: list[str]
    assumptions: list[str]
    status: str
    evidence_ids: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        _bounded_text(self.hypothesis_id, "hypothesis_id", 64)
        if type(self.revision) is not int or isinstance(self.revision, bool) or self.revision < 1:
            raise ValueError("hypothesis revision must be a positive integer")
        _bounded_text(self.statement, "hypothesis statement", 4_000)
        _bounded_text(self.cwe, "hypothesis cwe", 32)
        self.trigger_path = _string_list(self.trigger_path, "hypothesis trigger_path", 64)
        self.assumptions = _string_list(self.assumptions, "hypothesis assumptions", 64)
        _enum(self.status, HYPOTHESIS_STATUSES, "hypothesis status")
        self.evidence_ids = _string_list(self.evidence_ids, "hypothesis evidence_ids", 512)

    def to_json(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_json(cls, payload: Any) -> "HypothesisRecord":
        fields = _exact_fields(
            payload,
            frozenset(
                {
                    "hypothesis_id", "revision", "statement", "cwe",
                    "trigger_path", "assumptions", "status", "evidence_ids",
                }
            ),
            "hypothesis record",
        )
        return cls(**fields)


@dataclass
class InvestigationEvidence:
    """One observed tool result bound to the investigation identity."""

    evidence_id: str
    identity: InvestigationIdentity
    action_id: str
    tool_name: str
    path: str
    start_line: int
    end_line: int
    artifact_ref: str
    payload_digest: str
    scope: str
    truncated: bool

    def __post_init__(self) -> None:
        _bounded_text(self.evidence_id, "evidence_id", 64)
        if not isinstance(self.identity, InvestigationIdentity):
            raise ValueError("evidence identity must be an InvestigationIdentity")
        _bounded_text(self.action_id, "evidence action_id", 64)
        _bounded_text(self.tool_name, "evidence tool_name", 64)
        _bounded_text(self.path, "evidence path", 4_096)
        for name in ("start_line", "end_line"):
            value = getattr(self, name)
            if type(value) is not int or isinstance(value, bool) or value < 0:
                raise ValueError(f"evidence {name} must be a non-negative integer")
        if self.end_line and self.start_line and self.end_line < self.start_line:
            raise ValueError("evidence end_line precedes start_line")
        if not isinstance(self.artifact_ref, str) or len(self.artifact_ref) > 4_096:
            raise ValueError("evidence artifact_ref must be bounded text")
        _digest(self.payload_digest, "evidence payload_digest")
        _bounded_text(self.scope, "evidence scope", 200)
        if type(self.truncated) is not bool:
            raise ValueError("evidence truncated must be a boolean")

    def to_json(self) -> dict[str, Any]:
        return {
            **dataclasses.asdict(self),
            "identity": self.identity.to_json(),
        }

    @classmethod
    def from_json(cls, payload: Any) -> "InvestigationEvidence":
        fields = _exact_fields(
            payload,
            frozenset(
                {
                    "evidence_id", "identity", "action_id", "tool_name",
                    "path", "start_line", "end_line", "artifact_ref",
                    "payload_digest", "scope", "truncated",
                }
            ),
            "investigation evidence",
        )
        return cls(
            identity=InvestigationIdentity.from_json(fields["identity"]),
            **{key: value for key, value in fields.items() if key != "identity"},
        )


@dataclass
class InvestigationState:
    """The durable head of one investigation with its history."""

    schema_version: int
    identity: InvestigationIdentity
    version: int
    lead: str
    hypotheses: list[HypothesisRecord]
    evidence: dict[str, InvestigationEvidence]
    open_questions: list[str]
    action_ids: list[str]
    child_ids: list[str]
    status: str
    stop_reason: str | None

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported investigation schema version")
        if not isinstance(self.identity, InvestigationIdentity):
            raise ValueError("state identity must be an InvestigationIdentity")
        if type(self.version) is not int or isinstance(self.version, bool) or self.version < 1:
            raise ValueError("state version must be a positive integer")
        _bounded_text(self.lead, "state lead", 4_096)
        if type(self.hypotheses) is not list or len(self.hypotheses) > 10_000:
            raise ValueError("state hypotheses must be a bounded array")
        if type(self.evidence) is not dict or len(self.evidence) > 100_000:
            raise ValueError("state evidence must be a bounded object")
        for key, item in self.evidence.items():
            _bounded_text(key, "evidence key", 64)
            if not isinstance(item, InvestigationEvidence):
                raise ValueError("state evidence entries must be InvestigationEvidence")
        self.open_questions = _string_list(self.open_questions, "state open_questions", 512)
        self.action_ids = _string_list(self.action_ids, "state action_ids", 10_000)
        self.child_ids = _string_list(self.child_ids, "state child_ids", 64)
        _enum(self.status, INVESTIGATION_STATUSES, "state status")
        if self.stop_reason is not None and (
            not isinstance(self.stop_reason, str) or not self.stop_reason
        ):
            raise ValueError("state stop_reason must be non-empty text or null")

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "identity": self.identity.to_json(),
            "version": self.version,
            "lead": self.lead,
            "hypotheses": [item.to_json() for item in self.hypotheses],
            "evidence": {key: item.to_json() for key, item in self.evidence.items()},
            "open_questions": list(self.open_questions),
            "action_ids": list(self.action_ids),
            "child_ids": list(self.child_ids),
            "status": self.status,
            "stop_reason": self.stop_reason,
        }

    @classmethod
    def from_json(cls, payload: Any) -> "InvestigationState":
        fields = _exact_fields(
            payload,
            frozenset(
                {
                    "schema_version", "identity", "version", "lead",
                    "hypotheses", "evidence", "open_questions", "action_ids",
                    "child_ids", "status", "stop_reason",
                }
            ),
            "investigation state",
        )
        return cls(
            schema_version=fields["schema_version"],
            identity=InvestigationIdentity.from_json(fields["identity"]),
            version=fields["version"],
            lead=fields["lead"],
            hypotheses=[
                HypothesisRecord.from_json(item) for item in fields["hypotheses"]
            ],
            evidence={
                key: InvestigationEvidence.from_json(item)
                for key, item in fields["evidence"].items()
            },
            open_questions=fields["open_questions"],
            action_ids=fields["action_ids"],
            child_ids=fields["child_ids"],
            status=fields["status"],
            stop_reason=fields["stop_reason"],
        )


@dataclass(frozen=True)
class InvestigationAction:
    """The closed model-action union: one tool call or one final request."""

    action: str
    tool: str | None = None
    arguments: dict[str, Any] | None = None
    purpose: str | None = None
    hypothesis_id: str | None = None
    evidence_ids: tuple[str, ...] = ()
    unresolved_questions: tuple[str, ...] = ()


_TOOL_KEYS = frozenset({"action", "tool", "arguments", "purpose"})
_FINAL_KEYS = frozenset(
    {"action", "hypothesis_id", "evidence_ids", "unresolved_questions"}
)


def parse_investigation_action(raw: str) -> InvestigationAction:
    """Parse one model reply into the closed action union."""

    payload = parse_untrusted_json(raw)
    if not isinstance(payload, dict):
        raise ValueError("action must be a JSON object")
    kind = payload.get("action")
    if kind == "tool":
        fields = _exact_fields(payload, _TOOL_KEYS, "tool action")
        tool = _bounded_text(fields["tool"], "action tool", 64)
        if type(fields["arguments"]) is not dict:
            raise ValueError("action arguments must be an object")
        purpose = _bounded_text(fields["purpose"], "action purpose", 2_000)
        return InvestigationAction(
            action="tool", tool=tool,
            arguments=dict(fields["arguments"]), purpose=purpose,
        )
    if kind == "final":
        fields = _exact_fields(payload, _FINAL_KEYS, "final action")
        hypothesis_id = fields["hypothesis_id"]
        if not isinstance(hypothesis_id, str) or len(hypothesis_id) > 64:
            raise ValueError("final hypothesis_id must be bounded text")
        evidence_ids = _string_list(fields["evidence_ids"], "final evidence_ids", 512)
        unresolved = _string_list(
            fields["unresolved_questions"], "final unresolved_questions", 512
        )
        return InvestigationAction(
            action="final", hypothesis_id=hypothesis_id,
            evidence_ids=tuple(evidence_ids),
            unresolved_questions=tuple(unresolved),
        )
    raise ValueError("action must be either tool or final")


def validate_evidence_reference(
    state: InvestigationState, evidence_id: str
) -> InvestigationEvidence:
    """Return the referenced evidence or explain why it is not citable."""

    evidence = state.evidence.get(evidence_id)
    if evidence is None:
        raise ValueError(f"unknown evidence reference: {evidence_id}")
    if evidence.identity != state.identity:
        raise ValueError(
            f"foreign investigation identity on evidence: {evidence_id}"
        )
    return evidence


def validate_final_action(
    state: InvestigationState, action: InvestigationAction
) -> None:
    """A final must cite observed evidence and a recorded hypothesis."""

    if action.action != "final":
        raise ValueError("validate_final_action expects a final action")
    for evidence_id in action.evidence_ids:
        evidence = state.evidence.get(evidence_id)
        if evidence is None:
            raise ValueError(f"final cites unobserved evidence: {evidence_id}")
        if evidence.identity != state.identity:
            raise ValueError(
                f"final cites foreign investigation identity: {evidence_id}"
            )
    if action.hypothesis_id:
        known = {
            hypothesis.hypothesis_id for hypothesis in state.hypotheses
        }
        if action.hypothesis_id not in known:
            raise ValueError(f"unknown hypothesis reference: {action.hypothesis_id}")


def state_to_json(state: InvestigationState) -> str:
    """Canonical JSON for persistence; round-trips through from_json."""

    return json.dumps(state.to_json(), ensure_ascii=True, sort_keys=True)


def state_from_json(raw: str) -> InvestigationState:
    return InvestigationState.from_json(parse_untrusted_json(raw))
