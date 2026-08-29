"""Task runtime progress contract and persistence (observability epic T1)."""

from __future__ import annotations

import os
import tempfile
import unittest

from lima.store import TaskStore
from lima.task_failure import GITHUB_NOT_FOUND, TaskFailure
from lima.task_progress import (
    COMPLETED,
    DOWNLOADING_ARCHIVE,
    QUEUED,
    RESOLVING_REVISION,
    STAGE_INDEX,
    STAGE_ORDER,
    TERMINAL_STAGES,
    TaskProgress,
    progress_summary,
    sanitize,
)


class TaskProgressContractTests(unittest.TestCase):
    def test_stage_constants_are_ordered_and_indexed(self):
        self.assertEqual(13, len(STAGE_ORDER))
        self.assertEqual(len(set(STAGE_ORDER)), len(STAGE_ORDER))
        self.assertEqual(1, STAGE_INDEX[QUEUED])
        self.assertEqual(13, STAGE_INDEX[COMPLETED])
        self.assertEqual(STAGE_ORDER, tuple(STAGE_INDEX))
        self.assertEqual(frozenset({COMPLETED}), TERMINAL_STAGES)

    def test_begin_initializes_timestamps_once(self):
        progress = TaskProgress.begin(QUEUED, "任务已进入队列")
        self.assertEqual(QUEUED, progress.stage)
        self.assertEqual(1, progress.stage_index)
        self.assertEqual(13, progress.stage_total)
        self.assertEqual(progress.started_at, progress.stage_started_at)
        self.assertEqual(progress.started_at, progress.updated_at)

    def test_advance_moves_stage_and_resets_counters(self):
        progress = TaskProgress.begin()
        progress.update("下载中", current=5, total=100, unit="MiB")
        progress.advance(DOWNLOADING_ARCHIVE, "正在下载仓库快照")
        self.assertEqual(DOWNLOADING_ARCHIVE, progress.stage)
        self.assertEqual(STAGE_INDEX[DOWNLOADING_ARCHIVE], progress.stage_index)
        self.assertIsNone(progress.current)
        self.assertIsNone(progress.total)
        self.assertEqual("", progress.unit)
        self.assertLessEqual(progress.stage_started_at, progress.updated_at)

    def test_unknown_stage_is_rejected(self):
        with self.assertRaises(ValueError):
            TaskProgress(stage="MAGIC_STAGE", message="x")
        with self.assertRaises(ValueError):
            TaskProgress.begin().advance("not-a-stage")

    def test_begin_rejects_unknown_overrides(self):
        with self.assertRaises(TypeError):
            TaskProgress.begin(QUEUED, "msg", bogus=1)

    def test_roundtrip_via_dict(self):
        progress = (
            TaskProgress.begin(QUEUED, "排队")
            .advance(RESOLVING_REVISION, "解析版本")
            .update(current=1, total=2, unit="refs")
        )
        progress.attempt = 2
        restored = TaskProgress.from_dict(progress.to_dict())
        self.assertEqual(progress.to_dict(), restored.to_dict())

    def test_summary_is_lightweight(self):
        progress = TaskProgress.begin().advance(DOWNLOADING_ARCHIVE, "下载")
        summary = progress.summary()
        self.assertEqual(
            {
                "stage", "stage_index", "stage_total", "message",
                "attempt", "max_attempts", "current", "total", "unit",
            },
            set(summary),
        )
        self.assertNotIn("detail", summary)
        self.assertNotIn("started_at", summary)

    def test_sanitize_redacts_credentials_only(self):
        payload = {
            "api_key": "ghp_supersecret",
            "nested": {"Authorization": "Bearer abc123", "plain": "正常文案 token 位置说明"},
            "bearer_token=abc123": "value",
            "keep": {"count": 3, "path": "src/app.py"},
        }
        cleaned = sanitize(payload)
        self.assertEqual("[redacted]", cleaned["api_key"])
        self.assertEqual("[redacted]", cleaned["nested"]["Authorization"])
        self.assertEqual("正常文案 token 位置说明", cleaned["nested"]["plain"])
        self.assertEqual("[redacted]", cleaned["bearer_token=abc123"])
        self.assertEqual({"count": 3, "path": "src/app.py"}, cleaned["keep"])

    def test_persisted_payload_never_contains_credentials(self):
        sensitive_key = "download_" + "token"
        canary = "ghp_" + "supersecret"
        progress = TaskProgress.begin(DOWNLOADING_ARCHIVE, "下载中")
        progress.detail[sensitive_key] = canary
        progress.detail["url"] = "https://codeload.github.com/x"
        rendered = str(progress.to_dict())
        self.assertNotIn(canary, rendered)
        self.assertEqual("[redacted]", progress.to_dict()["detail"][sensitive_key])


class TaskProgressPersistenceTests(unittest.TestCase):
    def setUp(self):
        handle, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.store = TaskStore(self.db_path)
        self.store.create("task-1", "org/repo", None, {"task_type": "repository_scan"})

    def tearDown(self):
        os.unlink(self.db_path)

    def test_progress_persists_and_survives_restart(self):
        progress = TaskProgress.begin().advance(DOWNLOADING_ARCHIVE, "正在下载")
        self.store.update_task_progress("task-1", progress.to_dict())

        # 模拟进程重启：同一 SQLite 文件上的全新 store 实例
        reopened = TaskStore(self.db_path)
        stored = reopened.get("task-1")["progress"]
        self.assertEqual(DOWNLOADING_ARCHIVE, stored["stage"])
        self.assertEqual("正在下载", stored["message"])
        self.assertEqual(STAGE_INDEX[DOWNLOADING_ARCHIVE], stored["stage_index"])

    def test_progress_update_never_touches_task_input(self):
        before = self.store.get("task-1")["input"]
        progress = TaskProgress.begin().advance(COMPLETED, "完成")
        self.store.update_task_progress("task-1", progress.to_dict())
        after = self.store.get("task-1")
        self.assertEqual(before, after["input"])
        self.assertEqual({"task_type": "repository_scan"}, after["input"])
        self.assertEqual(COMPLETED, after["progress"]["stage"])

    def test_terminal_progress_is_persisted(self):
        progress = TaskProgress.begin().advance(COMPLETED, "审计完成")
        self.store.update_task_progress("task-1", progress.to_dict())
        self.assertEqual(COMPLETED, self.store.get("task-1")["progress"]["stage"])

    def test_task_list_returns_lightweight_summary(self):
        progress = (
            TaskProgress.begin()
            .advance(DOWNLOADING_ARCHIVE, "正在下载仓库快照")
            .update(current=4, total=None, unit="MiB")
        )
        self.store.update_task_progress("task-1", progress.to_dict())
        listed = self.store.list_tasks(10)[0]
        summary = listed["progress"]
        self.assertEqual(DOWNLOADING_ARCHIVE, summary["stage"])
        self.assertEqual(4, summary["stage_index"])
        self.assertEqual(13, summary["stage_total"])
        self.assertEqual("正在下载仓库快照", summary["message"])
        self.assertEqual(4, summary["current"])
        self.assertNotIn("detail", summary)
        self.assertNotIn("started_at", summary)

    def test_tasks_without_progress_expose_none(self):
        task = self.store.get("task-1")
        self.assertIsNone(task["progress"])
        self.assertIsNone(task["failure"])
        self.assertIsNone(self.store.list_tasks(10)[0]["progress"])
        self.assertIsNone(progress_summary(None))
        self.assertIsNone(progress_summary({}))

    def test_failure_persists_on_own_column_and_survives_restart(self):
        failure = TaskFailure.from_code(
            GITHUB_NOT_FOUND, stage="RESOLVING_REVISION",
            technical_detail="HTTP 404",
        )
        self.store.update_task_failure("task-1", failure.to_dict())

        reopened = TaskStore(self.db_path)
        stored = reopened.get("task-1")["failure"]
        self.assertEqual(GITHUB_NOT_FOUND, stored["code"])
        self.assertEqual("RESOLVING_REVISION", stored["stage"])
        self.assertFalse(stored["retryable"])
        self.assertTrue(stored["suggestion"])
        # 独立列：不污染 input，也不挤占 progress
        task = reopened.get("task-1")
        self.assertEqual({"task_type": "repository_scan"}, task["input"])
        self.assertIsNone(task["progress"])
        # 任务列表保持轻量：不携带 failure 载荷
        self.assertNotIn("failure", self.store.list_tasks(10)[0])

    def test_progress_summary_tolerates_partial_payloads(self):
        summary = progress_summary({"stage": QUEUED, "message": "x"})
        self.assertEqual(QUEUED, summary["stage"])
        self.assertIsNone(summary["current"])


if __name__ == "__main__":
    unittest.main()
