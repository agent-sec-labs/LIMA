"""Durable task execution progress, separate from the coarse TaskState lifecycle.

TaskState answers "is the task pending / running / done"; TaskProgress answers
"which execution stage is running right now, with what counters and attempt".
The two models are intentionally orthogonal (#T1):

- progress lives in its own persistence column — never inside ``input_json``,
  which represents immutable user-submitted task input;
- stage names are fixed constants, not scattered magic strings;
- every persisted payload passes a defensive sanitizer so credentials can
  never leak into progress metadata even if a caller misbehaves.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

QUEUED = "QUEUED"
RESOLVING_REVISION = "RESOLVING_REVISION"
CHECKING_CACHE = "CHECKING_CACHE"
DOWNLOADING_ARCHIVE = "DOWNLOADING_ARCHIVE"
VALIDATING_ARCHIVE = "VALIDATING_ARCHIVE"
PREPARING_WORKSPACE = "PREPARING_WORKSPACE"
INVENTORY = "INVENTORY"
DATAFLOW_ANALYSIS = "DATAFLOW_ANALYSIS"
AST_ANALYSIS = "AST_ANALYSIS"
SAST_ANALYSIS = "SAST_ANALYSIS"
SEMANTIC_TRIAGE = "SEMANTIC_TRIAGE"
FINALIZING = "FINALIZING"
COMPLETED = "COMPLETED"

STAGE_ORDER: tuple[str, ...] = (
    QUEUED,
    RESOLVING_REVISION,
    CHECKING_CACHE,
    DOWNLOADING_ARCHIVE,
    VALIDATING_ARCHIVE,
    PREPARING_WORKSPACE,
    INVENTORY,
    DATAFLOW_ANALYSIS,
    AST_ANALYSIS,
    SAST_ANALYSIS,
    SEMANTIC_TRIAGE,
    FINALIZING,
    COMPLETED,
)
STAGE_INDEX: dict[str, int] = {
    stage: index for index, stage in enumerate(STAGE_ORDER, start=1)
}

# 终态阶段：到达后 polling 应停止，progress 必须持久化保留。
TERMINAL_STAGES = frozenset({COMPLETED})

_SENSITIVE_KEY_PATTERN = re.compile(
    r"(?:token|secret|password|passwd|authorization|api[_-]?key|bearer)",
    re.IGNORECASE,
)
# 只匹配显式凭据形态（"Bearer xxx"、"token=xxx"），普通文案不受影响。
_CREDENTIAL_VALUE_PATTERN = re.compile(
    r"(?:Bearer\s+\S+|(?:token|secret|password|api[_-]?key)\s*[=:]\s*\S+)",
    re.IGNORECASE,
)
_REDACTED = "[redacted]"
_SUMMARY_FIELDS = (
    "stage",
    "stage_index",
    "stage_total",
    "message",
    "attempt",
    "max_attempts",
    "current",
    "total",
    "unit",
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def sanitize(value: Any) -> Any:
    """Recursively redact credential-shaped keys and values from progress."""

    if isinstance(value, dict):
        return {
            key: (
                _REDACTED
                if _SENSITIVE_KEY_PATTERN.search(str(key))
                else sanitize(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        return _CREDENTIAL_VALUE_PATTERN.sub(_REDACTED, value)
    return value


@dataclass
class TaskProgress:
    """A single durable snapshot of task execution progress."""

    stage: str
    message: str
    stage_index: int = 1
    stage_total: int = len(STAGE_ORDER)
    started_at: str = field(default_factory=_utc_now)
    stage_started_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)
    attempt: int = 1
    max_attempts: int = 1
    current: int | None = None
    total: int | None = None
    unit: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.stage not in STAGE_INDEX:
            raise ValueError(f"unknown task progress stage: {self.stage!r}")
        self.stage_index = STAGE_INDEX[self.stage]

    # ------------------------------------------------------------------
    # Construction / mutation
    # ------------------------------------------------------------------

    @classmethod
    def begin(
        cls, stage: str = QUEUED, message: str = "任务已进入队列", **overrides: Any
    ) -> TaskProgress:
        now = _utc_now()
        progress = cls(stage=stage, message=message)
        progress.started_at = now
        progress.stage_started_at = now
        progress.updated_at = now
        for key, value in overrides.items():
            if not hasattr(progress, key):
                raise TypeError(f"unknown TaskProgress field: {key!r}")
            setattr(progress, key, value)
        return progress

    def advance(self, stage: str, message: str = "") -> TaskProgress:
        """Move to another stage, refreshing stage timestamps."""

        if stage not in STAGE_INDEX:
            raise ValueError(f"unknown task progress stage: {stage!r}")
        self.stage = stage
        self.stage_index = STAGE_INDEX[stage]
        self.message = message or self.message
        self.stage_started_at = _utc_now()
        self.updated_at = self.stage_started_at
        self.current = None
        self.total = None
        self.unit = ""
        return self

    def update(
        self,
        message: str = "",
        *,
        current: int | None = None,
        total: int | None = None,
        unit: str = "",
        detail: dict[str, Any] | None = None,
    ) -> TaskProgress:
        """Refresh counters/message within the current stage."""

        if message:
            self.message = message
        self.current = current
        self.total = total
        self.unit = unit
        if detail is not None:
            self.detail.update(detail)
        self.updated_at = _utc_now()
        return self

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "stage_index": self.stage_index,
            "stage_total": self.stage_total,
            "message": self.message,
            "started_at": self.started_at,
            "stage_started_at": self.stage_started_at,
            "updated_at": self.updated_at,
            "attempt": self.attempt,
            "max_attempts": self.max_attempts,
            "current": self.current,
            "total": self.total,
            "unit": self.unit,
            "detail": sanitize(self.detail),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> TaskProgress:
        known = {field_name for field_name in cls.__dataclass_fields__}
        payload = {key: item for key, item in value.items() if key in known}
        payload["stage"] = str(payload.get("stage", QUEUED))
        return cls(**payload)

    def summary(self) -> dict[str, Any]:
        """Lightweight projection for task lists (no timestamps, no detail)."""

        payload = self.to_dict()
        return {key: payload[key] for key in _SUMMARY_FIELDS}


def progress_summary(value: dict[str, Any] | None) -> dict[str, Any] | None:
    """Build a list-safe summary from a persisted progress payload."""

    if not value:
        return None
    return {key: value.get(key) for key in _SUMMARY_FIELDS}


__all__ = [
    "COMPLETED",
    "STAGE_INDEX",
    "STAGE_ORDER",
    "TERMINAL_STAGES",
    "TaskProgress",
    "progress_summary",
    "sanitize",
]
