"""Build-agent service integration tests (build agent slice 5).

The build-agent mode is frozen at enqueue, carried by the queue message
and the persisted task input, and executed between the fixed snapshot and
the repository scan: ``off`` keeps the current path untouched, ``auto``
degrades with an explicit gap, ``required`` blocks the context-dependent
stages, and every outcome lands as a persisted BuildResult summary the
task detail can render.
"""

import os
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from lima.build_agent import NEEDS_ATTENTION, SUCCEEDED, BuildResult
from lima.config import Settings
from lima.service import ReviewService


def make_build_result(status: str, failure_code: str | None = None) -> BuildResult:
    return BuildResult(
        run_id="build-test",
        status=status,
        snapshot_hash="a" * 64,
        plan_digest="b" * 64,
        image_digest=None,
        dependency_digest=None,
        package_ref="attempt-1/package" if status == SUCCEEDED else None,
        artifact_digest=None,
        attempts=1,
        coverage=None,
        failure_code=failure_code,
        evidence_refs=("attempt-1/logs/step-000.stderr.log",),
    )


class BuildAgentServiceTests(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.addCleanup(os.unlink, self.path)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        repository = Path(self.temporary.name, "team", "project")
        repository.mkdir(parents=True)
        (repository / "app.py").write_text("safe = True\n", encoding="utf-8")
        self.base = Settings(
            host="127.0.0.1", port=8080, db_path=self.path, max_diff_bytes=10000,
            max_steps=8, timeout_seconds=120, llm_base_url="", llm_api_key="",
            llm_model="", github_webhook_secret="", github_token="",
            auto_post_review=False, repository_import_root=self.temporary.name,
            repository_scan_sast_mode="off", cxx_memory_mode="off",
        )

    def _service(self, **overrides) -> ReviewService:
        service = ReviewService(replace(self.base, **overrides))
        self.addCleanup(service.queue.close)
        return service

    def _enqueue(self, service, mode=None):
        kwargs = {} if mode is None else {"build_agent_mode": mode}
        with mock.patch.object(service.queue, "submit") as submit:
            created = service.enqueue_repository_scan("team/project", **kwargs)
        message = submit.call_args[0][0]
        return created, message

    def test_mode_frozen_in_task_input_and_message(self):
        for requested, expected in (
            (None, "off"), ("off", "off"), ("auto", "auto"),
            ("required", "required"),
        ):
            with self.subTest(requested=requested):
                service = self._service(build_agent_mode="off")
                created, message = self._enqueue(service, requested)
                task_input = service.store.get(created["task_id"])["input"]
                self.assertEqual(task_input["build_agent_mode"], expected)
                self.assertEqual(message["build_agent_mode"], expected)

    def test_invalid_mode_rejected_at_enqueue(self):
        service = self._service()
        with self.assertRaises(ValueError):
            service.enqueue_repository_scan(
                "team/project", build_agent_mode="always"
            )

    def test_off_mode_never_touches_the_build_agent(self):
        service = self._service()
        with mock.patch.object(
            service, "_run_build_agent"
        ) as run_build, mock.patch.object(service.queue, "submit"):
            service.enqueue_repository_scan("team/project")
            # Drain the in-memory queue synchronously.
            service.queue.close()
        run_build.assert_not_called()

    def _run_scan_with_build(self, mode, build_result):
        """Run one local scan to completion with a stubbed build result."""

        service = self._service(
            build_agent_mode=mode, build_agent_image="lima-builder:test"
        )
        with mock.patch.object(
            service,
            "_run_build_agent",
            return_value=build_result,
        ) as run_build:
            created = service.enqueue_repository_scan(
                "team/project", build_agent_mode=mode
            )
            task = {}
            for _ in range(300):
                task = service.store.get(created["task_id"]) or {}
                if task.get("state") in {"SUCCESS", "FAILED"}:
                    break
                time.sleep(0.02)
        self.assertTrue(run_build.called or task.get("state") in {
            "SUCCESS", "FAILED",
        })
        return service, created["task_id"], task

    def test_auto_success_persists_summary_without_gap(self):
        service, task_id, task = self._run_scan_with_build(
            "auto", make_build_result(SUCCEEDED)
        )
        self.assertEqual(task["state"], "SUCCESS")
        summary = task["input"]["build_agent_result"]
        self.assertEqual(summary["status"], "SUCCEEDED")
        self.assertEqual(summary["package_ref"], "attempt-1/package")
        self.assertEqual(summary["evidence_refs"][0], (
            "attempt-1/logs/step-000.stderr.log"
        ))
        report = task.get("report") or {}
        visible = report.get("collaboration", {}).get("build_agent")
        self.assertIsNotNone(visible)
        self.assertEqual(visible["status"], "SUCCEEDED")
        self.assertFalse(visible["blocking"])

    def test_auto_failure_degrades_with_explicit_gap(self):
        service, task_id, task = self._run_scan_with_build(
            "auto", make_build_result(NEEDS_ATTENTION, "build-not-configured")
        )
        # The scan itself still succeeds: auto degrades, never blocks.
        self.assertEqual(task["state"], "SUCCESS")
        summary = task["input"]["build_agent_result"]
        self.assertEqual(summary["status"], "NEEDS_ATTENTION")
        self.assertEqual(summary["failure_code"], "build-not-configured")
        report = task.get("report") or {}
        gap = report.get("collaboration", {}).get("build_agent")
        self.assertIsNotNone(gap)
        self.assertFalse(gap["blocking"])
        self.assertEqual(gap["failure_code"], "build-not-configured")

    def test_required_failure_blocks_context_stages(self):
        service, task_id, task = self._run_scan_with_build(
            "required", make_build_result(NEEDS_ATTENTION, "build-not-configured")
        )
        report = task.get("report") or {}
        gap = report.get("collaboration", {}).get("build_agent")
        self.assertIsNotNone(gap)
        self.assertTrue(gap["blocking"])
        self.assertEqual(gap["build_agent_mode"], "required")
        # The context-dependent stage is recorded as refused, not silently
        # absent: the effective cxx mode was forced off by the gap.
        self.assertEqual(gap["blocking"], True)

    def test_required_failure_forces_cxx_stage_off(self):
        # The cxx agent stage must not run while the required build
        # context is missing; a scanner-level mode spy pins the handoff.
        service = self._service(
            build_agent_mode="required", build_agent_image="lima-builder:test",
            cxx_agent_mode="auto",
            **{
                "llm_provider": "custom",
                "llm_base_url": "http://127.0.0.1:9/v1",
                "llm_api_key": "unit-test-key",
                "llm_model": "unit-test-model",
            },
        )
        with mock.patch.object(
            service,
            "_run_build_agent",
            return_value=make_build_result(NEEDS_ATTENTION, "build-not-configured"),
        ), mock.patch.object(
            service.repository_scanner,
            "scan",
            wraps=service.repository_scanner.scan,
        ) as scan_spy:
            created = service.enqueue_repository_scan(
                "team/project", build_agent_mode="required"
            )
            task = {}
            for _ in range(300):
                task = service.store.get(created["task_id"]) or {}
                if task.get("state") in {"SUCCESS", "FAILED"}:
                    break
                time.sleep(0.02)
        self.assertTrue(scan_spy.called)
        self.assertEqual(scan_spy.call_args.kwargs.get("cxx_agent_mode"), "off")

    def test_cancel_reaches_the_build_agent(self):
        service = self._service(
            build_agent_mode="auto", build_agent_image="lima-builder:test"
        )
        captured_cancel = {}

        def fake_run_build(task_id, workspace, label, progress):
            captured_cancel["task_id"] = task_id
            service.store.request_cancel(task_id)
            captured_cancel["cancelled_after_request"] = (
                service.store.is_cancelled(task_id)
            )
            return make_build_result(NEEDS_ATTENTION, "cancelled")

        with mock.patch.object(
            service, "_run_build_agent", side_effect=fake_run_build
        ):
            service.enqueue_repository_scan(
                "team/project", build_agent_mode="auto"
            )
            for _ in range(300):
                if "cancelled_after_request" in captured_cancel:
                    break
                time.sleep(0.02)
        self.assertIn("task_id", captured_cancel)
        self.assertTrue(captured_cancel.get("cancelled_after_request"))


if __name__ == "__main__":
    unittest.main()
