"""Cancellation and resume behavior for repository scan tasks."""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from lima.config import Settings
from lima.models import ReviewReport, TaskState, TraceEvent
from lima.postgres_store import PostgresTaskStore
from lima.repository_scanner import RepositoryScanner, RepositoryScanResult
from lima.service import ReviewService
from lima.store import TaskStore
from lima.workspace import RepositoryWorkspace, WorkspaceInventory


def _settings(root: Path) -> Settings:
    return Settings(
        host="127.0.0.1",
        port=0,
        db_path=str(root / "state.db"),
        max_diff_bytes=10_000,
        max_steps=8,
        timeout_seconds=30,
        llm_base_url="",
        llm_api_key="",
        llm_model="",
        github_token="",
        github_webhook_secret="",
        auto_post_review=False,
        repository_import_root=str(root / "imports"),
        repository_scan_sources="local-import",
        repository_scan_sast_mode="off",
    )


class _CapturingQueue:
    def __init__(self) -> None:
        self.submissions: list[tuple[dict, str]] = []

    def submit(self, payload: dict, message_id: str = "") -> str:
        self.submissions.append((payload, message_id))
        return message_id


class _StaticScanner:
    def __init__(self, cxx_status: str) -> None:
        self.cxx_status = cxx_status

    def scan(self, workspace, **_kwargs) -> RepositoryScanResult:
        inventory = WorkspaceInventory(root=str(workspace.root))
        return RepositoryScanResult(
            report=ReviewReport(
                repository=str(workspace.root),
                pull_request=None,
                summary="scan",
                risk="low",
                collaboration={"cxx_memory": {"status": self.cxx_status}},
            ),
            inventory=inventory,
        )


class _PostgresConnection:
    def __init__(self, rowcount: int = 1) -> None:
        self.calls: list[tuple[str, object]] = []
        self.rowcount = rowcount

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql: str, params):
        self.calls.append((sql, params))
        return type("Result", (), {"rowcount": self.rowcount})()


class RepositoryScanCancellationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.imports = self.root / "imports"
        self.repo = self.imports / "demo"
        self.repo.mkdir(parents=True)
        (self.repo / "app.py").write_text("value = 1\n", encoding="utf-8")
        self.service = ReviewService(_settings(self.root))
        self.addCleanup(self.service.queue.close)
        self.addCleanup(self.temp.cleanup)

    def _create_scan(self, task_id: str, state: TaskState = TaskState.PENDING) -> None:
        self.service.store.create(
            task_id,
            "demo",
            None,
            {
                "task_type": "repository_scan",
                "repository_key": "demo",
                "scan_source": {
                    "type": "local-import",
                    "repository_key": "demo",
                },
                "effective_cxx_agent_mode": "off",
                "investigate_paths": [],
            },
            "tenant-a",
        )
        if state is not TaskState.PENDING:
            self.service.store.transition(
                task_id,
                __import__("lima.models", fromlist=["TraceEvent"]).TraceEvent(
                    1,
                    state,
                    "test",
                    "2026-01-01T00:00:00+00:00",
                ),
            )

    def test_scanner_stops_before_work_when_cancelled(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "repository scan cancelled"):
            RepositoryScanner(sast_mode="off").scan(
                RepositoryWorkspace(self.repo),
                should_cancel=lambda: True,
            )

    def test_queued_cancelled_scan_becomes_cancelled_without_running(self) -> None:
        self._create_scan("queued-cancel")
        self.assertTrue(self.service.cancel_task("queued-cancel", "tenant-a"))

        self.service._process_queued(
            {
                "task_id": "queued-cancel",
                "task_type": "repository_scan",
                "repository_key": "demo",
                "tenant_id": "tenant-a",
            }
        )

        task = self.service.store.get("queued-cancel", "tenant-a")
        self.assertEqual(TaskState.CANCELLED.value, task["state"])
        self.assertIsNone(task["report"])

    def test_inflight_cancel_after_scanner_returns_never_persists_success(self) -> None:
        self._create_scan("inflight-cancel")
        service = self.service

        class CancellingScanner(_StaticScanner):
            def scan(self, workspace, **kwargs) -> RepositoryScanResult:
                service.store.request_cancel("inflight-cancel", "tenant-a")
                return super().scan(workspace, **kwargs)

        self.service.repository_scanner = CancellingScanner("disabled")
        self.service._process_queued(
            {
                "task_id": "inflight-cancel",
                "task_type": "repository_scan",
                "repository_key": "demo",
                "tenant_id": "tenant-a",
            }
        )

        task = self.service.store.get("inflight-cancel", "tenant-a")
        self.assertEqual(TaskState.CANCELLED.value, task["state"])
        self.assertIsNone(task["report"])

    def test_resume_cancelled_scan_clears_cancel_and_requeues_snapshot(self) -> None:
        self._create_scan("resume-scan", TaskState.CANCELLED)
        self.assertTrue(self.service.cancel_task("resume-scan", "tenant-a"))
        queue = _CapturingQueue()
        self.service.queue = queue

        resumed = self.service.resume_task("resume-scan", "tenant-a")

        self.assertEqual({"task_id": "resume-scan", "state": "PENDING", "resumed": True}, resumed)
        self.assertFalse(self.service.store.is_cancelled("resume-scan"))
        self.assertEqual(
            TaskState.PENDING.value, self.service.store.get("resume-scan", "tenant-a")["state"]
        )
        self.assertEqual(1, len(queue.submissions))
        payload, message_id = queue.submissions[0]
        self.assertEqual("resume-scan", message_id)
        self.assertEqual("repository_scan", payload["task_type"])
        self.assertEqual("demo", payload["repository_key"])

    def test_resume_success_keeps_existing_report_contract(self) -> None:
        self._create_scan("completed", TaskState.SUCCESS)
        self.service.store.request_cancel("completed", "tenant-a")

        resumed = self.service.resume_task("completed", "tenant-a")

        self.assertEqual("SUCCESS", resumed["state"])
        self.assertTrue(self.service.store.is_cancelled("completed"))

    def test_resume_rejects_nonterminal_task(self) -> None:
        self._create_scan("still-running", TaskState.EXECUTING)

        with self.assertRaisesRegex(ValueError, "FAILED or CANCELLED"):
            self.service.resume_task("still-running", "tenant-a")

        self.assertEqual(
            TaskState.EXECUTING.value,
            self.service.store.get("still-running", "tenant-a")["state"],
        )

    def test_resume_cancelled_diff_still_uses_saved_payload(self) -> None:
        self.service.store.create(
            "resume-diff",
            "org/repo",
            7,
            {"task_type": "review"},
            "tenant-a",
        )
        self.service.store.save_task_payload("resume-diff", "diff --git a/a.py b/a.py")
        self.service.store.transition(
            "resume-diff",
            __import__("lima.models", fromlist=["TraceEvent"]).TraceEvent(
                1,
                TaskState.CANCELLED,
                "test",
                "2026-01-01T00:00:00+00:00",
            ),
        )
        self.assertTrue(self.service.cancel_task("resume-diff", "tenant-a"))
        queue = _CapturingQueue()
        self.service.queue = queue

        resumed = self.service.resume_task("resume-diff", "tenant-a")

        self.assertEqual("PENDING", resumed["state"])
        self.assertFalse(self.service.store.is_cancelled("resume-diff"))
        self.assertEqual("org/repo", queue.submissions[0][0]["repository"])

    def test_resume_diff_without_payload_does_not_clear_cancel_state(self) -> None:
        self.service.store.create(
            "missing-diff",
            "org/repo",
            7,
            {"task_type": "review"},
            "tenant-a",
        )
        self.service.store.transition(
            "missing-diff",
            __import__("lima.models", fromlist=["TraceEvent"]).TraceEvent(
                1,
                TaskState.CANCELLED,
                "test",
                "2026-01-01T00:00:00+00:00",
            ),
        )
        self.assertTrue(self.service.cancel_task("missing-diff", "tenant-a"))

        with self.assertRaisesRegex(ValueError, "payload"):
            self.service.resume_task("missing-diff", "tenant-a")

        task = self.service.store.get("missing-diff", "tenant-a")
        self.assertEqual(TaskState.CANCELLED.value, task["state"])
        self.assertTrue(task["cancel_requested"])

    def test_failed_cxx_summary_marks_completion_with_coverage_warning(self) -> None:
        self._create_scan("cxx-failed")
        self.service.repository_scanner = _StaticScanner("failed")

        self.service._execute_repository_scan(
            "cxx-failed",
            self.repo,
            "tenant-a",
            "demo",
            {"repository_key": "demo"},
            self.service._scan_progress_tracker("cxx-failed"),
        )

        completion = self.service.store.get("cxx-failed", "tenant-a")["progress"]["detail"][
            "completion"
        ]
        self.assertEqual("completed_with_warnings", completion["status"])
        self.assertEqual({"cxx-analysis-failed": 1}, completion["warnings"])

    def test_resume_clears_old_terminal_result_fields_but_keeps_snapshot(self) -> None:
        self._create_scan("failed-scan", TaskState.FAILED)
        self.service.store.succeed(
            "failed-scan",
            ReviewReport("demo", None, "old", "low"),
            TraceEvent(2, TaskState.SUCCESS, "old", "2026-01-01T00:00:00+00:00"),
        )
        self.service.store.fail(
            "failed-scan",
            "old failure",
            TraceEvent(3, TaskState.FAILED, "old", "2026-01-01T00:00:01+00:00"),
        )
        queue = _CapturingQueue()
        self.service.queue = queue

        self.service.resume_task("failed-scan", "tenant-a")

        task = self.service.store.get("failed-scan", "tenant-a")
        self.assertEqual(TaskState.PENDING.value, task["state"])
        self.assertIsNone(task["report"])
        self.assertIsNone(task["error"])
        self.assertIsNone(task["failure"])
        self.assertIsNone(task["progress"])
        self.assertEqual("demo", task["input"]["repository_key"])

    def test_stores_expose_atomic_completion_and_postgres_resume_contract(self) -> None:
        self.assertTrue(hasattr(TaskStore, "succeed_unless_cancelled"))
        self.assertTrue(hasattr(PostgresTaskStore, "succeed_unless_cancelled"))
        self.assertTrue(hasattr(PostgresTaskStore, "reset_task_for_resume"))

    def test_cancel_at_final_commit_boundary_never_publishes_success(self) -> None:
        self._create_scan("commit-race")
        self.service.repository_scanner = _StaticScanner("disabled")
        original = self.service.store.succeed_unless_cancelled

        def cancel_then_commit(task_id, report, event):
            self.service.store.request_cancel(task_id, "tenant-a")
            return original(task_id, report, event)

        self.service.store.succeed_unless_cancelled = cancel_then_commit
        self.service._process_queued(
            {
                "task_id": "commit-race",
                "task_type": "repository_scan",
                "repository_key": "demo",
                "tenant_id": "tenant-a",
            }
        )
        task = self.service.store.get("commit-race", "tenant-a")
        self.assertEqual("CANCELLED", task["state"])
        self.assertIsNone(task["report"])

    def test_postgres_atomic_commit_and_resume_sql(self) -> None:
        store = PostgresTaskStore.__new__(PostgresTaskStore)
        connection = _PostgresConnection(rowcount=0)
        store._connect = lambda: connection
        event = TraceEvent(1, TaskState.SUCCESS, "done", "2026-01-01T00:00:00+00:00")
        self.assertFalse(
            store.succeed_unless_cancelled(
                "task", ReviewReport("demo", None, "report", "low"), event
            )
        )
        self.assertEqual(1, len(connection.calls))
        self.assertIn("cancel_requested=FALSE", connection.calls[0][0])
        connection.rowcount = 1
        connection.calls.clear()
        store.reset_task_for_resume(
            "task", TraceEvent(2, TaskState.PENDING, "resume", event.created_at)
        )
        self.assertIn("failure_json=NULL", connection.calls[0][0])
        self.assertIn("state IN", connection.calls[0][0])

    def test_github_resume_preserves_investigation_paths_to_worker(self) -> None:
        self._create_scan("github-resume", TaskState.CANCELLED)
        self.service.store.update_task_input("github-resume", {
            "scan_source": {"type": "github", "url": "https://github.com/OPM/ResInsight"},
            "investigate_paths": ["ApplicationExeCode/RiaMain.cpp"],
        })
        queue = _CapturingQueue()
        self.service.queue = queue
        captured = {}

        def capture(*_args, **kwargs):
            captured.update(kwargs)

        self.service._process_github_repository_scan = capture
        self.service.resume_task("github-resume", "tenant-a")
        self.service._process_queued(queue.submissions[0][0])
        self.assertEqual(["ApplicationExeCode/RiaMain.cpp"], captured.get("investigate_paths"))

    def test_source_enqueue_preserves_investigation_paths_for_both_sources(self) -> None:
        self.service.settings = replace(self.service.settings, repository_scan_sources="both")
        paths = ["ApplicationExeCode/RiaMain.cpp"]
        for source in [
            {"type": "github", "url": "https://github.com/OPM/ResInsight"},
            {"type": "local-import", "repository_key": "demo"},
        ]:
            with self.subTest(source=source), patch.object(
                self.service, "_enqueue_scan_task", return_value={"task_id": "captured"}
            ) as enqueue:
                self.service.enqueue_repository_scan_source(
                    source, "tenant-a", False, investigate_paths=paths
                )
                self.assertEqual(paths, enqueue.call_args.kwargs["investigate_paths"])


if __name__ == "__main__":
    unittest.main()
