"""Durable investigation journal: versions, atomic ledger, recovery marks."""

import tempfile
import unittest
from pathlib import Path

from lima.cxx_investigation_models import (
    InvestigationEvidence,
    InvestigationIdentity,
    InvestigationState,
    HypothesisRecord,
)
from lima.postgres_store import PostgresTaskStore
from lima.store import TaskStore

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


def identity(tenant: str = "tenant-a", investigation_id: str = "inv-1") -> InvestigationIdentity:
    return InvestigationIdentity(
        tenant_id=tenant,
        task_id="task-1",
        investigation_id=investigation_id,
        snapshot_hash=DIGEST_A,
        context_digest=DIGEST_B,
        config_digest=DIGEST_C,
    )


def state(version: int = 1, status: str = "running", ident: InvestigationIdentity | None = None) -> InvestigationState:
    ident = ident or identity()
    return InvestigationState(
        schema_version=1,
        identity=ident,
        version=version,
        lead="lead-001",
        hypotheses=[
            HypothesisRecord(
                hypothesis_id="h1", revision=1, statement="s",
                cwe="CWE-416", trigger_path=["src/a.cpp"], assumptions=[],
                status="active", evidence_ids=[],
            )
        ],
        evidence={
            "e1": InvestigationEvidence(
                evidence_id="e1", identity=ident, action_id="a1",
                tool_name="read_source", path="src/a.cpp", start_line=1,
                end_line=2, artifact_ref="", payload_digest=DIGEST_B,
                scope="snapshot", truncated=False,
            )
        },
        open_questions=[],
        action_ids=["a1"],
        child_ids=[],
        status=status,
        stop_reason=None,
    )


class InvestigationJournalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = TaskStore(str(Path(self.temporary.name) / "journal.db"))

    def _save_initial(self) -> None:
        self.store.save_investigation(state(version=1), expected_version=0)

    def test_expected_version_rejects_lost_update(self):
        self._save_initial()
        concurrent = state(version=2, status="waiting_children")
        self.store.save_investigation(concurrent, expected_version=1)
        # A second writer still claiming version 1 has lost the race.
        stale = state(version=2, status="completed")
        with self.assertRaisesRegex(ValueError, "version conflict"):
            self.store.save_investigation(stale, expected_version=1)
        restored = self.store.load_investigation(identity())
        self.assertEqual(2, restored.version)
        self.assertEqual("waiting_children", restored.status)
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.store.save_investigation(state(version=1), expected_version=0)

    def test_action_and_budget_reservation_are_atomic(self):
        self._save_initial()
        reservation = {"calls": 1, "bytes": 512}
        self.store.prepare_action(
            identity(), "a1", DIGEST_B, reservation
        )
        # A conflicting prepare fails at insert time and must not move the
        # budget reservation either.
        with self.assertRaisesRegex(ValueError, "payload digest conflict"):
            self.store.prepare_action(identity(), "a1", DIGEST_C, reservation)
        budget = self.store.investigation_budget(identity())
        self.assertEqual({"reserved_calls": 1, "settled_calls": 0,
                          "reserved_bytes": 512, "settled_bytes": 0}, budget)

    def test_same_action_is_not_double_charged(self):
        self._save_initial()
        for _ in range(2):
            self.store.prepare_action(
                identity(), "a1", DIGEST_B, {"calls": 1, "bytes": 100}
            )
        self.store.mark_dispatched(identity(), "a1")
        self.store.mark_dispatched(identity(), "a1")
        budget = self.store.investigation_budget(identity())
        self.assertEqual(1, budget["reserved_calls"])
        self.assertEqual(100, budget["reserved_bytes"])
        self.store.complete_action(
            identity(), "a1", {"calls": 1, "bytes": 90}
        )
        self.store.complete_action(
            identity(), "a1", {"calls": 1, "bytes": 90}
        )
        budget = self.store.investigation_budget(identity())
        self.assertEqual(1, budget["settled_calls"])
        self.assertEqual(90, budget["settled_bytes"])

    def test_dispatched_without_receipt_restores_as_ambiguous(self):
        self._save_initial()
        self.store.prepare_action(identity(), "a1", DIGEST_B, {"calls": 1, "bytes": 10})
        self.store.mark_dispatched(identity(), "a1")
        self.store.prepare_action(identity(), "a2", DIGEST_C, {"calls": 1, "bytes": 10})
        restored = self.store.restore_investigation(identity())
        self.assertEqual("needs_attention", restored.status)
        actions = {
            item["action_id"]: item["status"]
            for item in self.store.investigation_actions(identity())
        }
        self.assertEqual("ambiguous", actions["a1"])
        self.assertEqual("prepared", actions["a2"])
        # The recovery mark itself is versioned and persisted.
        self.assertEqual("needs_attention", self.store.load_investigation(identity()).status)

    def test_foreign_tenant_cannot_load_state(self):
        self._save_initial()
        self.assertIsNone(self.store.load_investigation(identity(tenant="tenant-b")))
        self.assertIsNone(
            self.store.restore_investigation(identity(tenant="tenant-b"))
        )
        with self.assertRaisesRegex(ValueError, "unknown investigation"):
            self.store.prepare_action(
                identity(tenant="tenant-b"), "a1", DIGEST_B, {"calls": 1, "bytes": 1}
            )

    def test_actions_reference_their_investigation_and_unknown_ids_rejected(self):
        self._save_initial()
        self.store.prepare_action(identity(), "a1", DIGEST_B, {"calls": 0, "bytes": 0})
        rows = self.store.investigation_actions(identity())
        self.assertEqual(1, len(rows))
        self.assertEqual("a1", rows[0]["action_id"])
        self.assertEqual("prepared", rows[0]["status"])
        with self.assertRaisesRegex(ValueError, "unknown investigation action"):
            self.store.mark_dispatched(identity(), "a99")


class JournalContractTests(unittest.TestCase):
    def test_postgres_store_exposes_the_same_journal(self):
        for name in (
            "save_investigation", "load_investigation", "prepare_action",
            "mark_dispatched", "complete_action", "restore_investigation",
            "investigation_actions", "investigation_budget",
        ):
            self.assertTrue(
                hasattr(PostgresTaskStore, name),
                f"PostgresTaskStore is missing {name}",
            )
            self.assertTrue(hasattr(TaskStore, name))


if __name__ == "__main__":
    unittest.main()
