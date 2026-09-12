"""Typed fail-closed errors for the evidence privacy core (Packet IP-0015 §8.6).

Mirrors the ``lima.contracts.errors`` design principle: every failure carries a
frozen ``PrivacyErrorCode`` and a stable, value-free message. ``field_path``
carries structural position only; ``context`` may carry non-value metadata
(type names, lengths, enum names, limits) and never raw evidence values.
"""

from __future__ import annotations

import enum
from collections.abc import Mapping

from lima.contracts.codec import JSONValue

__all__ = ["PrivacyError", "PrivacyErrorCode"]


class PrivacyErrorCode(str, enum.Enum):  # noqa: UP042 -- wire values frozen by IP-0015 §8.6
    """Frozen wire values for every deterministic privacy failure."""

    INVALID_FIELD_TYPE = "INVALID_FIELD_TYPE"
    INVALID_FIELD_VALUE = "INVALID_FIELD_VALUE"
    UNKNOWN_SINK = "UNKNOWN_SINK"
    MISSING_TENANT_KEY = "MISSING_TENANT_KEY"
    POLICY_ERROR = "POLICY_ERROR"
    RESOURCE_LIMIT_EXCEEDED = "RESOURCE_LIMIT_EXCEEDED"
    MAX_DEPTH_EXCEEDED = "MAX_DEPTH_EXCEEDED"
    MAX_ITEMS_EXCEEDED = "MAX_ITEMS_EXCEEDED"
    MAX_STRING_LENGTH_EXCEEDED = "MAX_STRING_LENGTH_EXCEEDED"
    TIME_BUDGET_EXCEEDED = "TIME_BUDGET_EXCEEDED"
    UNSUPPORTED_PAYLOAD_KIND = "UNSUPPORTED_PAYLOAD_KIND"
    INTERNAL_REDACTION_FAILURE = "INTERNAL_REDACTION_FAILURE"


_STABLE_MESSAGE_PREFIX = "evidence privacy failure"


class PrivacyError(Exception):
    """Fail-closed privacy error; ``str``/``repr`` never embed raw evidence values."""

    def __init__(
        self,
        code: PrivacyErrorCode,
        field_path: str = "",
        context: Mapping[str, JSONValue] | None = None,
    ) -> None:
        self.code = code
        self.field_path = field_path
        self.context: Mapping[str, JSONValue] = dict(context) if context else {}
        super().__init__(self._format())

    def _format(self) -> str:
        parts = [_STABLE_MESSAGE_PREFIX, self.code.value]
        if self.field_path:
            parts.append(f"field_path={self.field_path}")
        for key in sorted(self.context):
            parts.append(f"{key}={self.context[key]}")
        return " ".join(parts)

    def __str__(self) -> str:
        return self._format()
