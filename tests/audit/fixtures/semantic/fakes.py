"""Deterministic fakes for the frozen ``SemanticModelClient`` protocol.

Packet IP-0019-PACKET/v1 §5.4.2 freezes the port protocol
``complete(prompt, *, timeout_seconds) -> str``. These fakes are fully
scripted: each call consumes exactly one queued response (a ``str`` payload
or an exception instance to raise); an unexpected call fails the test loudly.
No network facility is used anywhere in this module.
"""

from __future__ import annotations

import json
import time
from typing import Any


class ScriptedModelClient:
    """Scripted deterministic stand-in for ``SemanticModelClient``."""

    def __init__(
        self, responses: list[str | Exception] | None = None, *, sleep_seconds: float = 0.0
    ) -> None:
        self._responses = list(responses or [])
        self._sleep_seconds = sleep_seconds
        self.calls: list[str] = []
        self.timeout_seconds_seen: list[int] = []

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def complete(self, prompt: str, *, timeout_seconds: int) -> str:
        self.calls.append(prompt)
        self.timeout_seconds_seen.append(timeout_seconds)
        if self._sleep_seconds:
            time.sleep(self._sleep_seconds)
        if not self._responses:
            raise AssertionError("unexpected model call: no scripted response left")
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def valid_batch_response(entries: list[tuple[str, str, str]]) -> str:
    """Serialize one conforming model batch output for the given entries.

    ``entries`` are ``(candidate_id, category, rationale)`` triples; the
    result is the exact JSON the prioritizer is frozen to accept (§5.4.3).
    """

    payload: list[dict[str, Any]] = [
        {
            "candidate_id": candidate_id,
            "category": category,
            "rationale": rationale,
        }
        for candidate_id, category, rationale in entries
    ]
    return json.dumps(payload)
