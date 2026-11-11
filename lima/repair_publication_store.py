"""Durable, idempotent persistence for repair publication operations."""

import json
import re
from datetime import UTC, datetime
from typing import Any

from .webhook_outbox import WebhookOutboxStore

REPAIR_PUBLICATION_SCHEMA = """CREATE TABLE IF NOT EXISTS repair_publications (
    operation_id TEXT PRIMARY KEY,
    intent_json TEXT NOT NULL,
    stages_json TEXT NOT NULL DEFAULT '{}',
    result_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
)"""

_OPERATION_ID = re.compile(r"[0-9a-f]{64}")
_STAGES = {"commit", "draft"}
_MAX_JSON_BYTES = 32 * 1024 * 1024


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _canonical_json(value: dict[str, Any], name: str) -> str:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a dict")
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be JSON-serializable") from exc
    if len(encoded.encode("utf-8")) > _MAX_JSON_BYTES:
        raise ValueError(f"{name} is too large")
    return encoded


class RepairPublicationStore(WebhookOutboxStore):
    """Mixin storing one immutable intent and one idempotent result per operation."""

    def _validate_operation_id(self, operation_id: str) -> None:
        if not isinstance(operation_id, str) or not _OPERATION_ID.fullmatch(operation_id):
            raise ValueError("operation_id must be a 64-character lowercase hexadecimal digest")

    @staticmethod
    def _record(row) -> dict[str, Any]:
        return {
            "operation_id": row["operation_id"],
            "intent": json.loads(row["intent_json"]),
            "stages": json.loads(row["stages_json"]),
            "result": json.loads(row["result_json"]) if row["result_json"] is not None else None,
        }

    def prepare_repair_publication(
        self, operation_id: str, intent: dict[str, Any]
    ) -> dict[str, Any]:
        self._validate_operation_id(operation_id)
        encoded_intent = _canonical_json(intent, "intent")
        now = _utc_now()
        with self._outbox_connection() as conn:
            conn.execute(
                self._outbox_sql(
                    "INSERT INTO repair_publications "
                    "(operation_id,intent_json,stages_json,created_at,updated_at) "
                    "VALUES (?,?,?, ?,?) ON CONFLICT(operation_id) DO NOTHING"
                ),
                (operation_id, encoded_intent, "{}", now, now),
            )
            row = conn.execute(
                self._outbox_sql(
                    "SELECT operation_id,intent_json,stages_json,result_json "
                    "FROM repair_publications "
                    "WHERE operation_id=?{lock}"
                ),
                (operation_id,),
            ).fetchone()
            if row is None:  # Defensive: an adapter must honor the transaction contract.
                raise RuntimeError("repair publication was not persisted")
            if row["intent_json"] != encoded_intent:
                raise ValueError("operation_id was already used with a different intent")
            return self._record(row)

    def get_repair_publication(self, operation_id: str) -> dict[str, Any] | None:
        self._validate_operation_id(operation_id)
        with self._connect() as conn:
            row = conn.execute(
                self._outbox_sql(
                    "SELECT operation_id,intent_json,stages_json,result_json "
                    "FROM repair_publications "
                    "WHERE operation_id=?"
                ),
                (operation_id,),
            ).fetchone()
        return self._record(row) if row else None

    def record_repair_publication_stage(
        self,
        operation_id: str,
        stage: str,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        self._validate_operation_id(operation_id)
        if stage not in _STAGES:
            raise ValueError("stage must be commit or draft")
        encoded_value = _canonical_json(value, "stage value")
        with self._outbox_connection() as conn:
            row = conn.execute(
                self._outbox_sql(
                    "SELECT operation_id,intent_json,stages_json,result_json "
                    "FROM repair_publications "
                    "WHERE operation_id=?{lock}"
                ),
                (operation_id,),
            ).fetchone()
            if row is None:
                raise ValueError("repair publication operation not found")
            stages = json.loads(row["stages_json"])
            existing = stages.get(stage)
            if existing is not None:
                if _canonical_json(existing, "stored stage value") != encoded_value:
                    raise ValueError(
                        f"repair publication stage {stage} is already recorded differently"
                    )
                return self._record(row)
            stages[stage] = json.loads(encoded_value)
            conn.execute(
                self._outbox_sql(
                    "UPDATE repair_publications SET stages_json=?,updated_at=? WHERE operation_id=?"
                ),
                (_canonical_json(stages, "stages"), _utc_now(), operation_id),
            )
            row = conn.execute(
                self._outbox_sql(
                    "SELECT operation_id,intent_json,stages_json,result_json "
                    "FROM repair_publications "
                    "WHERE operation_id=?"
                ),
                (operation_id,),
            ).fetchone()
            return self._record(row)

    def complete_repair_publication(
        self,
        operation_id: str,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        self._validate_operation_id(operation_id)
        encoded_result = _canonical_json(result, "result")
        with self._outbox_connection() as conn:
            row = conn.execute(
                self._outbox_sql(
                    "SELECT operation_id,intent_json,stages_json,result_json "
                    "FROM repair_publications "
                    "WHERE operation_id=?{lock}"
                ),
                (operation_id,),
            ).fetchone()
            if row is None:
                raise ValueError("repair publication operation not found")
            if row["result_json"] is None:
                conn.execute(
                    self._outbox_sql(
                        "UPDATE repair_publications SET result_json=?,updated_at=? "
                        "WHERE operation_id=?"
                    ),
                    (encoded_result, _utc_now(), operation_id),
                )
                row = conn.execute(
                    self._outbox_sql(
                        "SELECT operation_id,intent_json,stages_json,result_json "
                        "FROM repair_publications "
                        "WHERE operation_id=?"
                    ),
                    (operation_id,),
                ).fetchone()
            return self._record(row)
