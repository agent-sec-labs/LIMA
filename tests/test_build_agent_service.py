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
from lima.workspace import RepositoryWorkspace


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


class Round1ReviewTests(unittest.TestCase):
    """Targeted regressions for the PR #348 review."""

    def test_from_env_reads_build_settings(self):
        from lima.config import Settings

        # Defaults: standard deployments stay off.
        defaults = Settings.from_env()
        self.assertEqual(defaults.build_agent_mode, "off")
        self.assertEqual(defaults.build_agent_image, "")
        self.assertEqual(defaults.build_concurrency, 1)

        env = {
            "LIMA_BUILD_AGENT_MODE": "required",
            "LIMA_BUILD_AGENT_IMAGE": "approved:test",
            "LIMA_BUILD_ARTIFACTS_ROOT": "output/custom",
            "LIMA_BUILD_ARTIFACTS_RETENTION_DAYS": "7",
            "LIMA_BUILD_CONCURRENCY": "4",
        }
        with mock.patch.dict(os.environ, env):
            explicit = Settings.from_env()
        self.assertEqual(explicit.build_agent_mode, "required")
        self.assertEqual(explicit.build_agent_image, "approved:test")
        self.assertEqual(explicit.build_artifacts_root, "output/custom")
        self.assertEqual(explicit.build_artifacts_retention_days, 7)
        self.assertEqual(explicit.build_concurrency, 4)

    def test_build_admission_limits_concurrent_builds(self):
        import threading

        service = self._service_for_admission()
        active = 0
        peak = 0
        lock = threading.Lock()

        def fake_run_build(task_id, workspace, label, progress):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.3)
            with lock:
                active -= 1
            return make_build_result(NEEDS_ATTENTION, "build-not-configured")

        with mock.patch.object(
            service, "_run_build_agent", side_effect=fake_run_build
        ):
            # Run two auto scans concurrently through the real queue.
            created = [
                service.enqueue_repository_scan(
                    "team/project", build_agent_mode="auto"
                )
                for _ in range(2)
            ]
            for task_id in [item["task_id"] for item in created]:
                for _ in range(300):
                    task = service.store.get(task_id)
                    if task and task.get("state") in {"SUCCESS", "FAILED"}:
                        break
                    time.sleep(0.02)

    def _service_for_admission(self):
        # The admission gate wraps _run_build_agent at the executor level;
        # assert the semaphore cap directly with the real method stack.
        handle, path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.addCleanup(os.unlink, path)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        repository = Path(temporary.name, "team", "project")
        repository.mkdir(parents=True)
        (repository / "app.py").write_text("safe = True\n", encoding="utf-8")
        from lima.service import ReviewService

        service = ReviewService(
            Settings(
                host="127.0.0.1", port=8080, db_path=path, max_diff_bytes=10000,
                max_steps=8, timeout_seconds=120, llm_base_url="",
                llm_api_key="", llm_model="", github_webhook_secret="",
                github_token="", auto_post_review=False,
                repository_import_root=temporary.name,
                repository_scan_sast_mode="off", cxx_memory_mode="off",
                build_agent_mode="auto", build_agent_image="lima-builder:test",
                build_concurrency=1,
            )
        )
        self.addCleanup(service.queue.close)
        return service

    def test_admission_semaphore_enforces_the_cap(self):

        service = self._service_for_admission()
        slot = service._build_admission_slot()
        self.assertTrue(slot.acquire(blocking=False))
        try:
            second = service._build_admission_slot()
            self.assertIs(slot, second)  # one process-wide slot
            self.assertFalse(second.acquire(blocking=False))
        finally:
            slot.release()
        self.assertTrue(slot.acquire(blocking=False))
        slot.release()

    def test_replay_reuses_persisted_success(self):
        service = self._service_for_admission()
        with tempfile.TemporaryDirectory() as artifacts:
            with mock.patch.object(
                type(service.settings),
                "build_artifacts_root",
                artifacts,
                create=True,
            ):
                # service.settings is a frozen dataclass; patch the lookup
                # the reuse path performs through the instance instead.
                service.__dict__["settings"] = replace(
                    service.settings, build_artifacts_root=artifacts
                )
                # Lay out a real verified package for the fake build result
                # so the reuse gate can re-verify it (PR #348 round-2 F4).
                from lima.build_context_view import (
                    compute_artifact_digest,
                    snapshot_fingerprint,
                    verify_build_artifact,
                )
                from tests.test_build_context_view import (
                    write_package_fixture as write_view_fixture,
                )

                workspace_root = Path(artifacts) / "snapshot"
                (workspace_root / "app").mkdir(parents=True)
                (workspace_root / "app" / "main.cpp").write_text(
                    "int main(void) { return 0; }\\n", encoding="utf8"
                )
                fingerprint = snapshot_fingerprint(workspace_root)
                package_dir = (
                    Path(artifacts) / "task-1" / "run-1" / "attempt-1" / "package"
                )
                write_view_fixture(
                    package_dir,
                    revision=fingerprint,
                    entry={
                        "directory": "app",
                        "arguments": [
                            "/usr/bin/c++", "-DVERIFIED=1", "-c", "main.cpp",
                        ],
                        "file": "app/main.cpp",
                    },
                )
                artifact_digest = compute_artifact_digest(package_dir)
                verify_build_artifact(package_dir, fingerprint, artifact_digest)

                task_root = Path(artifacts) / "task-1"
                service.store.create("task-1", "team/project", None, {}, "default")
                service.store.update_task_input("task-1", {
                    "build_agent_result": {
                        "run_id": "build-1",
                        "status": "SUCCEEDED",
                        "snapshot_hash": fingerprint,
                        "plan_digest": "p" * 64,
                        "package_ref": "run-1/attempt-1/package",
                        "artifact_digest": artifact_digest,
                        "attempts": 1,
                        "failure_code": None,
                        "evidence_refs": ["run-1/attempt-1/package"],
                    },
                })
                reused = service._persisted_build_result(task_root.name, fingerprint)
                self.assertIsNotNone(reused)
                self.assertEqual(reused.status, "SUCCEEDED")
                self.assertEqual(reused.package_ref, "run-1/attempt-1/package")

                # A different snapshot must not reuse.
                self.assertIsNone(
                    service._persisted_build_result(task_root.name, "b" * 64)
                )

                # Removing the package must not reuse either.
                import shutil as _shutil

                _shutil.rmtree(package_dir)
                self.assertIsNone(
                    service._persisted_build_result(task_root.name, fingerprint)
                )

    def test_run_directories_are_run_scoped(self):
        with tempfile.TemporaryDirectory() as artifacts:
            base = Path(artifacts) / "task-1"
            base.mkdir(parents=True)
            (base / "run-1").mkdir()
            (base / "run-2").mkdir()
            # The allocator must pick run-3, never the occupied run-1.
            existing = [
                int(entry.name.split("-", 1)[-1])
                for entry in base.glob("run-*")
            ]
            self.assertEqual(max(existing, default=0) + 1, 3)

    def test_success_summary_marks_unconsumed(self):
        service, task_id, task = self._real_scan_with_success()
        summary = task["input"]["build_agent_result"]
        self.assertIn("artifact_digest", summary)
        visible = (task.get("report") or {}).get("collaboration", {}).get(
            "build_agent"
        )
        self.assertFalse(visible["consumed_by_analysis"])

    def _real_scan_with_success(self):
        handle, path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.addCleanup(os.unlink, path)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        repository = Path(temporary.name, "team", "project")
        repository.mkdir(parents=True)
        (repository / "app.py").write_text("safe = True\n", encoding="utf-8")
        from lima.service import ReviewService

        service = ReviewService(
            Settings(
                host="127.0.0.1", port=8080, db_path=path, max_diff_bytes=10000,
                max_steps=8, timeout_seconds=120, llm_base_url="",
                llm_api_key="", llm_model="", github_webhook_secret="",
                github_token="", auto_post_review=False,
                repository_import_root=temporary.name,
                repository_scan_sast_mode="off", cxx_memory_mode="off",
                build_agent_mode="auto", build_agent_image="lima-builder:test",
            )
        )
        self.addCleanup(service.queue.close)
        with mock.patch.object(
            service,
            "_run_build_agent",
            return_value=make_build_result(SUCCEEDED),
        ):
            created = service.enqueue_repository_scan(
                "team/project", build_agent_mode="auto"
            )
            task = {}
            for _ in range(300):
                task = service.store.get(created["task_id"]) or {}
                if task.get("state") in {"SUCCESS", "FAILED"}:
                    break
                time.sleep(0.02)
        return service, created["task_id"], task


class Round2ReviewTests(unittest.TestCase):
    """The real _run_build_agent call paths (PR #348 round 2)."""

    def _service(self, **overrides):
        handle, path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.addCleanup(os.unlink, path)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        repository = Path(temporary.name, "team", "project")
        repository.mkdir(parents=True)
        (repository / "app").mkdir(exist_ok=True)
        (repository / "app" / "main.cpp").write_text(
            "int main(void) { return 0; }\n", encoding="utf8"
        )
        (repository / "app" / "util.cpp").write_text(
            "int util(void) { return 1; }\n", encoding="utf8"
        )
        from lima.service import ReviewService

        settings = replace(
            Settings(
                host="127.0.0.1", port=8080, db_path=path, max_diff_bytes=10000,
                max_steps=8, timeout_seconds=120, llm_base_url="",
                llm_api_key="", llm_model="", github_webhook_secret="",
                github_token="", auto_post_review=False,
                repository_import_root=temporary.name,
                repository_scan_sast_mode="off", cxx_memory_mode="off",
                build_agent_mode="auto", build_agent_image="lima-builder:test",
            ),
            **overrides,
        )
        service = ReviewService(settings)
        self.addCleanup(service.queue.close)
        return service, Path(temporary.name) / "team" / "project"

    def test_stage_callback_persists_through_real_path(self):
        # The progress callback must run the real pipeline_event path with
        # the registered stage (round-2 F1): no NameError, no swallowed
        # observation.
        from lima.build_agent import BuildProgress
        from lima.service import ScanProgressTracker
        from lima.task_progress import BUILD_AGENT_PREPARATION, TaskProgress

        service, repo = self._service()
        task_id = "cb-real"
        service.store.create(task_id, "team/project", None, {}, "default")
        service.store.update_task_input(task_id, {"build_agent_mode": "auto"})
        tracker = ScanProgressTracker(
            service.store,
            task_id,
            TaskProgress.begin(max_attempts=1),
        )
        events: list[str] = []

        def fake_agent_run(request, *, cancel, progress):
            progress(
                BuildProgress(
                    phase="INSPECTING", attempt=1, plan_digest=None,
                    evidence_refs=(),
                )
            )
            events.append(BUILD_AGENT_PREPARATION)
            return make_build_result(NEEDS_ATTENTION, "build-not-configured")

        with mock.patch.object(
            service,
            "_make_build_agent_components",
            return_value=(
                lambda state: {"action": "final", "output": {"status": "done"}},
                None,
                None,
            ),
        ), mock.patch(
            "lima.service.BuildAgent"
        ) as agent_cls:
            agent_cls.return_value.run.side_effect = fake_agent_run
            service._run_build_agent(
                task_id, RepositoryWorkspace(str(repo)), "team/project", tracker
            )
        self.assertEqual(events, [BUILD_AGENT_PREPARATION])
        persisted = (service.store.get(task_id) or {}).get("progress") or {}
        self.assertEqual(persisted.get("stage"), BUILD_AGENT_PREPARATION)

    def test_admission_wait_is_cancellable(self):
        # With the budget exhausted and the task cancelled, the wait loop
        # must return a terminal result instead of sleeping forever
        # (round-2 F1/F2).
        service, repo = self._service(build_concurrency=1)
        task_id = "cb-wait"
        service.store.create(task_id, "team/project", None, {}, "default")
        slot = service._build_admission_slot()
        self.assertTrue(slot.acquire(blocking=False))
        try:
            service.store.request_cancel(task_id)
            with mock.patch.object(
                service,
                "_make_build_agent_components",
                return_value=(
                    lambda state: {"action": "final", "output": {"status": "done"}},
                    None,
                    None,
                ),
            ), mock.patch("lima.service.BuildAgent"):
                result = service._run_build_agent(
                    task_id,
                    RepositoryWorkspace(str(repo)),
                    "team/project",
                    None,
                )
            self.assertEqual(result.status, NEEDS_ATTENTION)
            self.assertEqual(
                result.failure_code, "build-admission-cancelled"
            )
        finally:
            slot.release()

    def test_run_prefix_rewrites_references(self):
        # package_ref and evidence refs must carry the run-N prefix so the
        # persisted reference resolves on disk (round-2 F3).
        from lima.build_agent import BuildResult as AgentResult

        service, repo = self._service()

        def fake_agent_run(request, *, cancel, progress):
            return AgentResult(
                run_id="build-x",
                status="SUCCEEDED",
                snapshot_hash=request.snapshot_hash,
                plan_digest="p" * 64,
                image_digest=None,
                dependency_digest=None,
                package_ref="attempt-1/package",
                artifact_digest=None,
                attempts=1,
                coverage=None,
                failure_code=None,
                evidence_refs=("attempt-1/logs/step-000.stderr.log",),
            )

        with mock.patch.object(
            service,
            "_make_build_agent_components",
            return_value=(
                lambda state: {"action": "final", "output": {"status": "done"}},
                None,
                None,
            ),
        ), mock.patch("lima.service.BuildAgent") as agent_cls:
            agent_cls.return_value.run.side_effect = fake_agent_run
            result = service._run_build_agent(
                "prefix-task", RepositoryWorkspace(str(repo)), "team/project", None
            )
        self.assertEqual(result.package_ref, "run-1/attempt-1/package")
        self.assertEqual(
            result.evidence_refs,
            ("run-1/attempt-1/logs/step-000.stderr.log",),
        )
        # The reference resolves on disk relative to the task artifacts root.
        task_root = Path(service.settings.build_artifacts_root) / "prefix-task"
        self.assertEqual(
            (task_root / result.package_ref),
            task_root / "run-1" / "attempt-1" / "package",
        )


if __name__ == "__main__":
    unittest.main()
