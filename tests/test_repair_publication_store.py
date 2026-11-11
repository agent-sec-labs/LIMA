"""SQLite durability and idempotency coverage for repair publication storage."""

from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from lima.store import TaskStore

OPERATION_ID = "a" * 64


class RepairPublicationStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tempdir.name) / "lima.sqlite")
        self.store = TaskStore(self.path)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_survives_restart_and_preserves_first_result(self):
        initial = self.store.prepare_repair_publication(OPERATION_ID, {"repo": "org/repo"})
        self.assertEqual(initial["stages"], {})
        self.store.record_repair_publication_stage(OPERATION_ID, "commit", {"sha": "c" * 40})
        self.store.complete_repair_publication(OPERATION_ID, {"status": "published"})

        restarted = TaskStore(self.path)
        record = restarted.get_repair_publication(OPERATION_ID)
        self.assertEqual(record["intent"], {"repo": "org/repo"})
        self.assertEqual(record["stages"], {"commit": {"sha": "c" * 40}})
        self.assertEqual(record["result"], {"status": "published"})
        self.assertEqual(
            restarted.complete_repair_publication(OPERATION_ID, {"status": "different"})["result"],
            {"status": "published"},
        )

    def test_concurrent_stages_merge_without_overwrite(self):
        self.store.prepare_repair_publication(OPERATION_ID, {"repository": "org/repo"})
        barrier = threading.Barrier(3)
        failures = []

        def record(stage, value):
            try:
                barrier.wait()
                self.store.record_repair_publication_stage(OPERATION_ID, stage, value)
            except BaseException as exc:  # pragma: no cover - assertion below reports it
                failures.append(exc)

        commit = threading.Thread(target=record, args=("commit", {"sha": "c" * 40}))
        draft = threading.Thread(target=record, args=("draft", {"number": 7}))
        commit.start()
        draft.start()
        barrier.wait()
        commit.join()
        draft.join()
        self.assertEqual(failures, [])
        self.assertEqual(
            self.store.get_repair_publication(OPERATION_ID)["stages"],
            {"commit": {"sha": "c" * 40}, "draft": {"number": 7}},
        )

    def test_intent_and_stage_are_immutable_and_conflict_rolls_back(self):
        self.store.prepare_repair_publication(OPERATION_ID, {"a": 1, "b": [2]})
        self.assertEqual(
            self.store.prepare_repair_publication(OPERATION_ID, {"b": [2], "a": 1})["intent"],
            {"a": 1, "b": [2]},
        )
        with self.assertRaisesRegex(ValueError, "different intent"):
            self.store.prepare_repair_publication(OPERATION_ID, {"a": 2})

        self.store.record_repair_publication_stage(OPERATION_ID, "draft", {"number": 1})
        with self.assertRaisesRegex(ValueError, "already recorded differently"):
            self.store.record_repair_publication_stage(OPERATION_ID, "draft", {"number": 2})
        self.assertEqual(
            self.store.get_repair_publication(OPERATION_ID)["stages"],
            {"draft": {"number": 1}},
        )

    def test_invalid_write_rolls_back_without_creating_operation(self):
        with self.assertRaisesRegex(ValueError, "must be a dict"):
            self.store.prepare_repair_publication("b" * 64, [])
        self.assertIsNone(self.store.get_repair_publication("b" * 64))


if __name__ == "__main__":
    unittest.main()
