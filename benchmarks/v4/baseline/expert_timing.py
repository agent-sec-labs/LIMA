"""Expert timing protocol for LIMA v4 baseline runs (IP-0027).

A :class:`ExpertTimingSession` records the human review timeline of one
baseline attempt as a start/pause/resume/finish event sequence with explicit
nanosecond timestamps.  The reviewer identity is stored only as its SHA-256
digest: the raw reviewer id never survives on any attribute, event, or
sidecar byte.  Active time counts only closed active intervals (paused
intervals are excluded), and automation time is deliberately not part of it
-- the frozen result contract expresses automation through ``wall_time_ms``
and ``cpu_time_ms``.

The sidecar serialization is delegated entirely to
``lima.contracts.codec``: sorted-key compact UTF-8 canonical JSON without
BOM or trailing newline, with a SHA-256 digest recomputable from the bytes
alone.  No counting-class metric ever enters the sidecar document.
"""

import hashlib

from benchmarks.v4.baseline.collect import (
    BaselineCollectionError,
    BaselineCollectionErrorCode,
)
from lima.contracts.codec import canonical_encode, compute_content_digest

__all__ = ["ExpertTimingSession"]

_NS_PER_MS = 1_000_000
_STATE_IDLE = "idle"
_STATE_ACTIVE = "active"
_STATE_PAUSED = "paused"
_STATE_FINISHED = "finished"


class ExpertTimingSession:
    """One expert review timeline with digest-only reviewer identity.

    The event state machine is: idle --start--> active --pause--> paused
    --resume--> active, with ``finish`` legal from both active and paused.
    Any other transition, any event after ``finish``, any non-int timestamp,
    or any timestamp that moves backwards fails closed with a typed error and
    leaves the session unchanged.
    """

    def __init__(self, reviewer_id: str) -> None:
        if not isinstance(reviewer_id, str) or not reviewer_id:
            raise BaselineCollectionError(
                BaselineCollectionErrorCode.INVALID_REVIEWER_ID, "$.reviewer_id"
            )
        self._reviewer_digest = hashlib.sha256(
            reviewer_id.encode("utf-8")
        ).hexdigest()
        self._events: list[dict[str, int | str]] = []
        self._state = _STATE_IDLE

    @property
    def reviewer_digest(self) -> str:
        """The SHA-256 hex digest of the raw reviewer id (never the id itself)."""
        return self._reviewer_digest

    def _reject_sequence(self) -> None:
        raise BaselineCollectionError(
            BaselineCollectionErrorCode.EVENT_SEQUENCE_INVALID,
            f"$.events[{len(self._events)}]",
        )

    def _append_event(self, kind: str, time_ns: int) -> None:
        if type(time_ns) is not int:
            raise BaselineCollectionError(
                BaselineCollectionErrorCode.INVALID_METRIC_TYPE,
                f"$.events[{len(self._events)}].time_ns",
            )
        if self._events and time_ns < self._events[-1]["time_ns"]:
            raise BaselineCollectionError(
                BaselineCollectionErrorCode.CLOCK_NOT_MONOTONIC,
                f"$.events[{len(self._events)}].time_ns",
            )
        self._events.append({"event": kind, "time_ns": time_ns})

    def start(self, time_ns: int) -> None:
        """Begin the review timeline; legal only from the initial state."""
        if self._state != _STATE_IDLE:
            self._reject_sequence()
        self._append_event("start", time_ns)
        self._state = _STATE_ACTIVE

    def pause(self, time_ns: int) -> None:
        """Pause an active review interval."""
        if self._state != _STATE_ACTIVE:
            self._reject_sequence()
        self._append_event("pause", time_ns)
        self._state = _STATE_PAUSED

    def resume(self, time_ns: int) -> None:
        """Resume a paused review interval."""
        if self._state != _STATE_PAUSED:
            self._reject_sequence()
        self._append_event("resume", time_ns)
        self._state = _STATE_ACTIVE

    def finish(self, time_ns: int) -> None:
        """Close the review; legal while active or paused."""
        if self._state not in (_STATE_ACTIVE, _STATE_PAUSED):
            self._reject_sequence()
        self._append_event("finish", time_ns)
        self._state = _STATE_FINISHED

    def active_time_ms(self) -> int:
        """Total closed active intervals in whole milliseconds.

        Only intervals closed by a pause or finish event count; an interval
        still open at query time is excluded rather than estimated, and
        paused time never accrues.
        """
        total_ns = 0
        active_since: int | None = None
        for event in self._events:
            if event["event"] in ("start", "resume"):
                active_since = event["time_ns"]
            elif active_since is not None:
                total_ns += event["time_ns"] - active_since
                active_since = None
        return total_ns // _NS_PER_MS

    def events(self) -> tuple[dict[str, int | str], ...]:
        """A fresh copy of the recorded event sequence, in occurrence order."""
        return tuple(dict(event) for event in self._events)

    def to_sidecar_document(self, run_spec_digest: str) -> dict[str, object]:
        """The canonical sidecar document for this session.

        The schema is exactly ``schema_version``, ``run_spec_digest``,
        ``reviewer_digest``, ``active_time_ms`` and the ``events`` list; the
        raw reviewer id is never part of it.
        """
        return {
            "schema_version": 1,
            "run_spec_digest": run_spec_digest,
            "reviewer_digest": self._reviewer_digest,
            "active_time_ms": self.active_time_ms(),
            "events": [dict(event) for event in self._events],
        }

    def sidecar_bytes(self, run_spec_digest: str) -> bytes:
        """Canonical UTF-8 bytes of :meth:`to_sidecar_document` via the codec."""
        return canonical_encode(self.to_sidecar_document(run_spec_digest))

    def sidecar_digest(self, run_spec_digest: str) -> str:
        """The lowercase hex SHA-256 of :meth:`sidecar_bytes`."""
        return compute_content_digest(self.sidecar_bytes(run_spec_digest))
