"""Atomic webhook admission; publication is at least once for one logical task."""

import hashlib
import json
from contextlib import contextmanager, nullcontext
from datetime import UTC, datetime

OUTBOX_SCHEMA = """CREATE TABLE IF NOT EXISTS webhook_outbox (
    delivery_id TEXT PRIMARY KEY, task_id TEXT NOT NULL,
    payload_json TEXT NOT NULL, dispatched INTEGER NOT NULL DEFAULT 0
)"""


class WebhookOutboxStore:
    _outbox_postgres = False

    @contextmanager
    def _outbox_connection(self):
        with nullcontext() if self._outbox_postgres else self._lock:
            with self._connect() as conn:
                yield conn

    def _outbox_sql(self, query):
        query = query.replace("{lock}", " FOR UPDATE" if self._outbox_postgres else "")
        query = query.replace("{json}", "?::jsonb" if self._outbox_postgres else "?")
        return query.replace("?", "%s") if self._outbox_postgres else query

    def prepare_webhook_review(
        self,
        delivery_id,
        tenant_id,
        payload_sha256,
        task_id,
        repository,
        pull_request,
        task_input,
        queue_payload,
    ):
        if not delivery_id:
            raise ValueError("X-GitHub-Delivery is required")
        now = datetime.now(UTC).isoformat()
        with self._outbox_connection() as conn:
            inserted = (
                conn.execute(
                    self._outbox_sql(
                        "INSERT INTO webhook_deliveries "
                        "(delivery_id,tenant_id,event_type,payload_sha256,received_at) "
                        "VALUES (?,?,'pull_request',?,?) ON CONFLICT(delivery_id) DO NOTHING"
                    ),
                    (delivery_id, tenant_id, payload_sha256, now),
                ).rowcount
                == 1
            )
            row = conn.execute(
                self._outbox_sql("SELECT * FROM webhook_deliveries WHERE delivery_id=?{lock}"),
                (delivery_id,),
            ).fetchone()
            if row["payload_sha256"] != payload_sha256 or row["tenant_id"] != tenant_id:
                raise ValueError("delivery id was already used with a different payload or tenant")
            if row["task_id"]:
                return row["task_id"], False
            # Recover incomplete legacy claims as well as admitting new events.
            conn.execute(
                self._outbox_sql(
                    "INSERT INTO tasks (id,state,repository,pull_request,input_json,"
                    "created_at,updated_at,tenant_id) VALUES (?,'PENDING',?,?,{json},?,?,?)"
                ),
                (
                    task_id,
                    repository,
                    pull_request,
                    json.dumps(task_input, ensure_ascii=False),
                    now,
                    now,
                    tenant_id,
                ),
            )
            conn.execute(
                self._outbox_sql(
                    "INSERT INTO webhook_outbox (delivery_id,task_id,payload_json) VALUES (?,?,?)"
                ),
                (delivery_id, task_id, json.dumps(queue_payload, ensure_ascii=False)),
            )
            conn.execute(
                self._outbox_sql("UPDATE webhook_deliveries SET task_id=? WHERE delivery_id=?"),
                (task_id, delivery_id),
            )
            return task_id, inserted

    def pending_webhook_outbox(self, delivery_id=None, limit=100):
        with self._connect() as conn:
            rows = conn.execute(
                self._outbox_sql(
                    "SELECT delivery_id,task_id,payload_json FROM webhook_outbox WHERE dispatched=0"
                    " AND (CAST(? AS TEXT) IS NULL OR delivery_id=?) ORDER BY delivery_id LIMIT ?"
                ),
                (delivery_id, delivery_id, limit),
            ).fetchall()
        return [
            {
                "delivery_id": row["delivery_id"],
                "task_id": row["task_id"],
                "payload": json.loads(row["payload_json"]),
            }
            for row in rows
        ]

    def mark_webhook_dispatched(self, delivery_id):
        with self._outbox_connection() as conn:
            conn.execute(
                self._outbox_sql("UPDATE webhook_outbox SET dispatched=1 WHERE delivery_id=?"),
                (delivery_id,),
            )

    def save_pinned_webhook_diff(self, task_id, diff, base_sha, head_sha):
        """Persist bytes and their immutable origin in one transaction."""
        now = datetime.now(UTC).isoformat()
        encoded = diff.encode("utf-8")
        with self._outbox_connection() as conn:
            row = conn.execute(
                self._outbox_sql("SELECT input_json FROM tasks WHERE id=?{lock}"), (task_id,)
            ).fetchone()
            if not row:
                raise ValueError("task not found")
            value = row["input_json"] if self._outbox_postgres else json.loads(row["input_json"])
            if value.get("head_sha") != head_sha or value.get("base_sha") != base_sha:
                raise ValueError("webhook source identity changed")
            value.update(
                {
                    "diff_pending": False,
                    "diff_source": "pinned-compare-v1",
                    "diff_bytes": len(encoded),
                    "diff_sha256": hashlib.sha256(encoded).hexdigest(),
                }
            )
            conn.execute(
                self._outbox_sql(
                    "INSERT INTO task_payloads (task_id,diff,created_at) VALUES (?,?,?) "
                    "ON CONFLICT(task_id) DO UPDATE SET "
                    "diff=excluded.diff,created_at=excluded.created_at"
                ),
                (task_id, diff, now),
            )
            conn.execute(
                self._outbox_sql("UPDATE tasks SET input_json={json},updated_at=? WHERE id=?"),
                (json.dumps(value, ensure_ascii=False), now, task_id),
            )
