"""Offline retention checks for Build Agent task artifacts."""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

from lima.build_artifact_cleanup import (
    ArtifactCleanupError,
    apply_cleanup,
    main,
    plan_cleanup,
)


class FakeStore:
    def __init__(self, tasks: dict[str, dict | None]) -> None:
        self.tasks = tasks

    def get(self, task_id: str):
        return self.tasks.get(task_id)


def _task(state: str, at: datetime) -> dict[str, str]:
    return {"state": state, "updated_at": at.isoformat()}


class BuildArtifactCleanupTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "artifacts"
        self.root.mkdir()
        self.now = datetime(2026, 11, 6, tzinfo=UTC)
        self.old = self.now - timedelta(days=31)

    def _directory(self, task_id: str, *, newest: datetime | None = None) -> Path:
        target = self.root / task_id
        nested = target / "run-1" / "attempt-1"
        nested.mkdir(parents=True)
        payload = nested / "record.json"
        payload.write_text("{}", encoding="utf-8")
        instant = (newest or self.old).timestamp()
        os.utime(payload, (instant, instant))
        os.utime(nested, (instant, instant))
        os.utime(target / "run-1", (instant, instant))
        os.utime(target, (instant, instant))
        return target

    def test_dry_run_selects_only_old_terminal_task_directories(self) -> None:
        stale = self._directory("stale")
        self._directory("active")
        self._directory("unknown")
        plan = plan_cleanup(
            self.root,
            FakeStore(
                {
                    "stale": _task("SUCCESS", self.old),
                    "active": _task("EXECUTING", self.old),
                    "unknown": None,
                }
            ),
            retention_days=30,
            now=self.now,
        )
        self.assertEqual([item.task_id for item in plan.candidates], ["stale"])
        self.assertTrue(stale.is_dir())
        self.assertEqual(
            {item.reason for item in plan.skipped},
            {"task-not-terminal", "task-not-found"},
        )

    def test_new_nested_write_prevents_deletion_even_when_task_is_old(self) -> None:
        target = self._directory("recent-write", newest=self.now - timedelta(days=1))
        plan = plan_cleanup(
            self.root,
            FakeStore({"recent-write": _task("FAILED", self.old)}),
            retention_days=30,
            now=self.now,
        )
        self.assertFalse(plan.candidates)
        self.assertEqual(plan.skipped[0].reason, "artifact-not-expired")
        self.assertTrue(target.is_dir())

    def test_apply_deletes_only_prevalidated_candidate(self) -> None:
        target = self._directory("cancelled")
        plan = plan_cleanup(
            self.root,
            FakeStore({"cancelled": _task("CANCELLED", self.old)}),
            retention_days=30,
            now=self.now,
        )
        self.assertEqual(apply_cleanup(plan), ("cancelled",))
        self.assertFalse(target.exists())

    def test_cli_refuses_apply_without_worker_stop_acknowledgement(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            main(["--apply"])
        self.assertEqual(raised.exception.code, 2)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_symlinked_task_directory_is_never_a_candidate(self) -> None:
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        (outside / "keep.txt").write_text("keep", encoding="utf-8")
        link = self.root / "linked"
        try:
            os.symlink(outside, link, target_is_directory=True)
        except OSError as exc:
            self.skipTest(str(exc))
        plan = plan_cleanup(
            self.root,
            FakeStore({"linked": _task("SUCCESS", self.old)}),
            retention_days=30,
            now=self.now,
        )
        self.assertFalse(plan.candidates)
        self.assertEqual(plan.skipped[0].reason, "artifact-link")
        self.assertTrue((outside / "keep.txt").exists())

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_link_inside_task_tree_is_never_a_candidate(self) -> None:
        target = self._directory("nested-link")
        outside = Path(self.temporary.name) / "outside-file"
        outside.write_text("keep", encoding="utf-8")
        try:
            os.symlink(outside, target / "run-1" / "attempt-1" / "linked-file")
        except OSError as exc:
            self.skipTest(str(exc))
        plan = plan_cleanup(
            self.root,
            FakeStore({"nested-link": _task("SUCCESS", self.old)}),
            retention_days=30,
            now=self.now,
        )
        self.assertFalse(plan.candidates)
        self.assertEqual(plan.skipped[0].reason, "artifact-tree-link")
        self.assertTrue(outside.exists())

    def test_root_link_is_rejected_before_path_resolution(self) -> None:
        logical_root = Path("logical-artifacts-root")
        resolved_root = self.root
        with mock.patch(
            "lima.build_artifact_cleanup._is_link_or_junction",
            side_effect=lambda value: Path(value) == logical_root,
        ), mock.patch.object(Path, "resolve", return_value=resolved_root):
            with self.assertRaisesRegex(ArtifactCleanupError, "artifacts-root-link"):
                plan_cleanup(logical_root, FakeStore({}), retention_days=30, now=self.now)

    def test_unreadable_tree_is_skipped_fail_closed(self) -> None:
        self._directory("unreadable")

        def denied_walk(_root, *, onerror, **_kwargs):
            onerror(PermissionError("denied"))
            return []

        with mock.patch("lima.build_artifact_cleanup.os.walk", side_effect=denied_walk):
            plan = plan_cleanup(
                self.root,
                FakeStore({"unreadable": _task("SUCCESS", self.old)}),
                retention_days=30,
                now=self.now,
            )
        self.assertFalse(plan.candidates)
        self.assertEqual(plan.skipped[0].reason, "artifact-unreadable")

