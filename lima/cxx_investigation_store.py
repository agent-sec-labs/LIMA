"""Durable investigation journal over both task stores.

The journal keeps three facts in one database per investigation: the
versioned state head (compare-and-swap via ``expected_version``), the
action ledger (``prepared/dispatched/completed/ambiguous`` with payload
digests so retries are idempotent) and the budget reservation aggregates.
State updates and budget reservations commit in the same transaction;
nothing is durable half-way.  ``fencing_token`` and ``child_ids`` columns
exist for the T9 delegation work and are unused here.

The mixin mirrors :class:`lima.webhook_outbox.WebhookOutboxStore`: the
host class provides ``_connect()`` (and ``_lock`` on SQLite hosts) and
sets ``_investigation_postgres = True`` on PostgreSQL hosts.
"""

from __future__ import annotations

import json
import re
from contextlib import contextmanager, nullcontext
from typing import Any, Iterator, Protocol

from .cxx_investigation_models import (
    InvestigationIdentity,
    InvestigationState,
    state_from_json,
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

_ACTION_STATUSES = ("prepared", "dispatched", "completed", "ambiguous", "failed")

INVESTIGATION_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS cxx_investigations (
        tenant_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        investigation_id TEXT NOT NULL,
        snapshot_hash TEXT NOT NULL,
        context_digest TEXT NOT NULL,
        config_digest TEXT NOT NULL,
        version INTEGER NOT NULL,
        status TEXT NOT NULL,
        state_json TEXT NOT NULL,
        reserved_calls INTEGER NOT NULL DEFAULT 0,
        settled_calls INTEGER NOT NULL DEFAULT 0,
        reserved_bytes INTEGER NOT NULL DEFAULT 0,
        settled_bytes INTEGER NOT NULL DEFAULT 0,
        child_ids_json TEXT NOT NULL DEFAULT '[]',
        fencing_token INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (tenant_id, task_id, investigation_id)
    )""",
    """CREATE TABLE IF NOT EXISTS cxx_investigation_actions (
        tenant_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        investigation_id TEXT NOT NULL,
        action_id TEXT NOT NULL,
        payload_digest TEXT NOT NULL,
        status TEXT NOT NULL,
        reservation_json TEXT NOT NULL,
        receipt_json TEXT,
        fencing_token INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (tenant_id, task_id, investigation_id, action_id)
    )""",
)


class InvestigationJournal(Protocol):
    """The store contract the investigator and its recovery path rely on."""

    def load_investigation(
        self, identity: InvestigationIdentity
    ) -> InvestigationState | None: ...

    def save_investigation(
        self, state: InvestigationState, *, expected_version: int
    ) -> None: ...

    def prepare_action(
        self,
        identity: InvestigationIdentity,
        action_id: str,
        payload_digest: str,
        reservation: dict[str, int],
    ) -> None: ...

    def mark_dispatched(
        self, identity: InvestigationIdentity, action_id: str
    ) -> None: ...

    def complete_action(
        self,
        identity: InvestigationIdentity,
        action_id: str,
        receipt: dict[str, int],
    ) -> None: ...

    def restore_investigation(
        self, identity: InvestigationIdentity
    ) -> InvestigationState | None: ...


def _identity_values(identity: InvestigationIdentity) -> tuple[str, str, str]:
    return identity.tenant_id, identity.task_id, identity.investigation_id


def _usage(value: Any, label: str) -> int:
    if type(value) is not int or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _validate_reservation(reservation: dict[str, int]) -> tuple[int, int]:
    if not isinstance(reservation, dict):
        raise ValueError("reservation must be an object")
    return (
        _usage(reservation.get("calls"), "reservation calls"),
        _usage(reservation.get("bytes"), "reservation bytes"),
    )


class CxxInvestigationStore:
    _investigation_postgres = False

    @contextmanager
    def _investigation_connection(self):
        with nullcontext() if self._investigation_postgres else self._lock:
            with self._connect() as conn:
                yield conn

    def _investigation_sql(self, query: str) -> str:
        query = query.replace("{lock}", " FOR UPDATE" if self._investigation_postgres else "")
        return query.replace("?", "%s") if self._investigation_postgres else query

    def save_investigation(
        self, state: InvestigationState, *, expected_version: int
    ) -> None:
        """Create or advance the state head with compare-and-swap."""

        if type(expected_version) is not int or expected_version < 0:
            raise ValueError("expected_version must be a non-negative integer")
        if state.version != expected_version + 1:
            raise ValueError("state version must advance expected_version by one")
        tenant, task, investigation = _identity_values(state.identity)
        with self._investigation_connection() as conn:
            cur = conn.cursor()
            if expected_version == 0:
                try:
                    cur.execute(
                        self._investigation_sql(
                            "INSERT INTO cxx_investigations ("
                            "tenant_id, task_id, investigation_id, snapshot_hash,"
                            " context_digest, config_digest, version, status,"
                            " state_json) VALUES (?,?,?,?,?,?,?,?,?)"
                        ),
                        (
                            tenant, task, investigation,
                            state.identity.snapshot_hash,
                            state.identity.context_digest,
                            state.identity.config_digest,
                            state.version, state.status,
                            json.dumps(state.to_json(), ensure_ascii=True, sort_keys=True),
                        ),
                    )
                except Exception as exc:
                    if "UNIQUE" in str(exc) or "duplicate key" in str(exc):
                        raise ValueError(
                            "investigation already exists"
                        ) from exc
                    raise
            else:
                cur.execute(
                    self._investigation_sql(
                        "UPDATE cxx_investigations SET version = ?, status = ?,"
                        " state_json = ? WHERE tenant_id = ? AND task_id = ?"
                        " AND investigation_id = ? AND version = ?"
                        " AND snapshot_hash = ? AND context_digest = ?"
                        " AND config_digest = ?"
                    ),
                    (
                        state.version, state.status,
                        json.dumps(state.to_json(), ensure_ascii=True, sort_keys=True),
                        tenant, task, investigation, expected_version,
                        state.identity.snapshot_hash,
                        state.identity.context_digest,
                        state.identity.config_digest,
                    ),
                )
                if cur.rowcount == 0:
                    raise ValueError(
                        "investigation version conflict, identity mismatch"
                        " or unknown investigation"
                    )
            conn.commit()

    def load_investigation(
        self, identity: InvestigationIdentity
    ) -> InvestigationState | None:
        tenant, task, investigation = _identity_values(identity)
        with self._investigation_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                self._investigation_sql(
                    "SELECT state_json FROM cxx_investigations"
                    " WHERE tenant_id = ? AND task_id = ? AND investigation_id = ?"
                    " AND snapshot_hash = ? AND context_digest = ?"
                    " AND config_digest = ?"
                ),
                (
                    tenant, task, investigation,
                    identity.snapshot_hash, identity.context_digest,
                    identity.config_digest,
                ),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return state_from_json(row["state_json"])

    def _require_investigation(self, cur, identity: InvestigationIdentity) -> None:
        tenant, task, investigation = _identity_values(identity)
        cur.execute(
            self._investigation_sql(
                "SELECT 1 FROM cxx_investigations"
                " WHERE tenant_id = ? AND task_id = ? AND investigation_id = ?"
                " AND snapshot_hash = ? AND context_digest = ?"
                " AND config_digest = ?{lock}"
            ),
            (
                tenant, task, investigation,
                identity.snapshot_hash, identity.context_digest,
                identity.config_digest,
            ),
        )
        if cur.fetchone() is None:
            raise ValueError("unknown investigation")

    def prepare_action(
        self,
        identity: InvestigationIdentity,
        action_id: str,
        payload_digest: str,
        reservation: dict[str, int],
    ) -> None:
        calls, byte_count = _validate_reservation(reservation)
        if not isinstance(action_id, str) or not action_id or len(action_id) > 64:
            raise ValueError("action_id must be bounded text")
        if not isinstance(payload_digest, str) or not _HEX64.fullmatch(payload_digest):
            raise ValueError("payload_digest must be a lowercase sha-256 digest")
        tenant, task, investigation = _identity_values(identity)
        with self._investigation_connection() as conn:
            cur = conn.cursor()
            self._require_investigation(cur, identity)
            cur.execute(
                self._investigation_sql(
                    "SELECT payload_digest FROM cxx_investigation_actions"
                    " WHERE tenant_id = ? AND task_id = ? AND investigation_id = ?"
                    " AND action_id = ?{lock}"
                ),
                (tenant, task, investigation, action_id),
            )
            row = cur.fetchone()
            if row is not None:
                if row["payload_digest"] != payload_digest:
                    raise ValueError("payload digest conflict for action")
                # Same idempotent retry: the reservation is already held.
                conn.rollback()
                return
            cur.execute(
                self._investigation_sql(
                    "INSERT INTO cxx_investigation_actions ("
                    "tenant_id, task_id, investigation_id, action_id,"
                    " payload_digest, status, reservation_json)"
                    " VALUES (?,?,?,?,?,'prepared',?)"
                ),
                (
                    tenant, task, investigation, action_id, payload_digest,
                    json.dumps({"calls": calls, "bytes": byte_count}),
                ),
            )
            cur.execute(
                self._investigation_sql(
                    "UPDATE cxx_investigations SET reserved_calls = reserved_calls + ?,"
                    " reserved_bytes = reserved_bytes + ?"
                    " WHERE tenant_id = ? AND task_id = ? AND investigation_id = ?"
                ),
                (calls, byte_count, tenant, task, investigation),
            )
            conn.commit()

    def _require_action(
        self, cur, identity: InvestigationIdentity, action_id: str
    ):
        tenant, task, investigation = _identity_values(identity)
        cur.execute(
            self._investigation_sql(
                "SELECT status FROM cxx_investigation_actions"
                " WHERE tenant_id = ? AND task_id = ? AND investigation_id = ?"
                " AND action_id = ?{lock}"
            ),
            (tenant, task, investigation, action_id),
        )
        row = cur.fetchone()
        if row is None:
            raise ValueError("unknown investigation action")
        return row["status"]

    def mark_dispatched(
        self, identity: InvestigationIdentity, action_id: str
    ) -> None:
        tenant, task, investigation = _identity_values(identity)
        with self._investigation_connection() as conn:
            cur = conn.cursor()
            status = self._require_action(cur, identity, action_id)
            if status == "prepared":
                cur.execute(
                    self._investigation_sql(
                        "UPDATE cxx_investigation_actions SET status = 'dispatched'"
                        " WHERE tenant_id = ? AND task_id = ? AND investigation_id = ?"
                        " AND action_id = ? AND status = 'prepared'"
                    ),
                    (tenant, task, investigation, action_id),
                )
            elif status != "dispatched":
                raise ValueError(f"action is not dispatchable: {status}")
            conn.commit()

    def complete_action(
        self,
        identity: InvestigationIdentity,
        action_id: str,
        receipt: dict[str, int],
    ) -> None:
        calls = _usage(receipt.get("calls") if isinstance(receipt, dict) else None,
                       "receipt calls")
        byte_count = _usage(
            receipt.get("bytes") if isinstance(receipt, dict) else None,
            "receipt bytes",
        )
        tenant, task, investigation = _identity_values(identity)
        receipt_json = json.dumps({"calls": calls, "bytes": byte_count})
        with self._investigation_connection() as conn:
            cur = conn.cursor()
            status = self._require_action(cur, identity, action_id)
            if status == "completed":
                cur.execute(
                    self._investigation_sql(
                        "SELECT receipt_json FROM cxx_investigation_actions"
                        " WHERE tenant_id = ? AND task_id = ? AND investigation_id = ?"
                        " AND action_id = ?{lock}"
                    ),
                    (tenant, task, investigation, action_id),
                )
                if cur.fetchone()["receipt_json"] != receipt_json:
                    raise ValueError("receipt conflict for completed action")
                conn.rollback()
                return
            if status not in ("prepared", "dispatched"):
                raise ValueError(f"action cannot complete from {status}")
            cur.execute(
                self._investigation_sql(
                    "UPDATE cxx_investigation_actions SET status = 'completed',"
                    " receipt_json = ? WHERE tenant_id = ? AND task_id = ?"
                    " AND investigation_id = ? AND action_id = ?"
                ),
                (receipt_json, tenant, task, investigation, action_id),
            )
            cur.execute(
                self._investigation_sql(
                    "UPDATE cxx_investigations SET settled_calls = settled_calls + ?,"
                    " settled_bytes = settled_bytes + ?"
                    " WHERE tenant_id = ? AND task_id = ? AND investigation_id = ?"
                ),
                (calls, byte_count, tenant, task, investigation),
            )
            conn.commit()

    def restore_investigation(
        self, identity: InvestigationIdentity
    ) -> InvestigationState | None:
        """Load the head, marking dispatched actions without a receipt.

        Any action left in ``dispatched`` is honestly ambiguous — the call
        may have happened — so the investigation head moves to
        ``needs_attention`` (a versioned write) and the action ledger
        keeps the ``ambiguous`` status for the operator resume choice.
        """

        tenant, task, investigation = _identity_values(identity)
        state = self.load_investigation(identity)
        if state is None:
            return None
        with self._investigation_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                self._investigation_sql(
                    "UPDATE cxx_investigation_actions SET status = 'ambiguous'"
                    " WHERE tenant_id = ? AND task_id = ? AND investigation_id = ?"
                    " AND status = 'dispatched'"
                ),
                (tenant, task, investigation),
            )
            ambiguous = cur.rowcount
            if not ambiguous:
                conn.rollback()
                return state
            # Inline compare-and-swap head update: calling save_investigation
            # here would re-enter the host lock and deadlock on SQLite.
            state.status = "needs_attention"
            state.version = state.version + 1
            cur.execute(
                self._investigation_sql(
                    "UPDATE cxx_investigations SET version = ?, status = ?,"
                    " state_json = ? WHERE tenant_id = ? AND task_id = ?"
                    " AND investigation_id = ? AND version = ?"
                ),
                (
                    state.version, state.status,
                    json.dumps(state.to_json(), ensure_ascii=True, sort_keys=True),
                    tenant, task, investigation, state.version - 1,
                ),
            )
            if cur.rowcount != 1:
                raise ValueError(
                    "investigation version conflict during restore"
                )
            conn.commit()
        return state

    def investigation_actions(
        self, identity: InvestigationIdentity
    ) -> list[dict[str, Any]]:
        tenant, task, investigation = _identity_values(identity)
        with self._investigation_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                self._investigation_sql(
                    "SELECT a.action_id, a.payload_digest, a.status,"
                    " a.reservation_json, a.receipt_json, a.fencing_token"
                    " FROM cxx_investigation_actions a JOIN cxx_investigations i"
                    " ON a.tenant_id = i.tenant_id AND a.task_id = i.task_id"
                    " AND a.investigation_id = i.investigation_id"
                    " WHERE a.tenant_id = ? AND a.task_id = ?"
                    " AND a.investigation_id = ? AND i.snapshot_hash = ?"
                    " AND i.context_digest = ? AND i.config_digest = ?"
                    " ORDER BY a.action_id"
                ),
                (
                    tenant, task, investigation,
                    identity.snapshot_hash, identity.context_digest,
                    identity.config_digest,
                ),
            )
            rows = cur.fetchall()
        return [
            {
                "action_id": row["action_id"],
                "payload_digest": row["payload_digest"],
                "status": row["status"],
                "reservation": json.loads(row["reservation_json"]),
                "receipt": (
                    json.loads(row["receipt_json"]) if row["receipt_json"] else None
                ),
                "fencing_token": row["fencing_token"],
            }
            for row in rows
        ]

    def investigation_budget(
        self, identity: InvestigationIdentity
    ) -> dict[str, int]:
        tenant, task, investigation = _identity_values(identity)
        with self._investigation_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                self._investigation_sql(
                    "SELECT reserved_calls, settled_calls, reserved_bytes,"
                    " settled_bytes FROM cxx_investigations"
                    " WHERE tenant_id = ? AND task_id = ? AND investigation_id = ?"
                    " AND snapshot_hash = ? AND context_digest = ?"
                    " AND config_digest = ?"
                ),
                (
                    tenant, task, investigation,
                    identity.snapshot_hash, identity.context_digest,
                    identity.config_digest,
                ),
            )
            row = cur.fetchone()
        if row is None:
            raise ValueError("unknown investigation")
        return {
            "reserved_calls": row["reserved_calls"],
            "settled_calls": row["settled_calls"],
            "reserved_bytes": row["reserved_bytes"],
            "settled_bytes": row["settled_bytes"],
        }
