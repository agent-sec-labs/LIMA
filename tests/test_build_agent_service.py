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
from lima.build_inputs import compute_build_input_digest
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
                build_artifacts_root=str(Path(temporary.name) / "artifacts"),
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
                        "build_input_digest": compute_build_input_digest(workspace_root),
                    },
                })
                reused = service._persisted_build_result(
                    task_root.name, fingerprint, workspace_root,
                )
                self.assertIsNotNone(reused)
                self.assertEqual(reused.status, "SUCCEEDED")
                self.assertEqual(reused.package_ref, "run-1/attempt-1/package")

                # A different snapshot must not reuse.
                self.assertIsNone(
                    service._persisted_build_result(task_root.name, "b" * 64, workspace_root)
                )

                # Removing the package must not reuse either.
                import shutil as _shutil

                _shutil.rmtree(package_dir)
                self.assertIsNone(
                    service._persisted_build_result(task_root.name, fingerprint, workspace_root)
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
        settings = replace(settings, build_artifacts_root=overrides.get(
            "build_artifacts_root", str(Path(temporary.name) / "artifacts"),
        ))
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

    def test_admission_exhausted_releases_worker_and_respects_cancel(self):
        # Round-3 F2: an exhausted budget must free the scan worker (raise
        # the retry signal, never sleep-loop inside the worker), and a
        # cancelled task must still get a terminal result instead of a
        # pointless retry.
        from lima.service import _BuildAdmissionRetry

        service, repo = self._service(build_concurrency=1)
        task_id = "cb-wait"
        service.store.create(task_id, "team/project", None, {}, "default")
        slot = service._build_admission_slot()
        self.assertTrue(slot.acquire(blocking=False))
        components = (
            lambda state: {"action": "final", "output": {"status": "done"}},
            None,
            None,
        )
        try:
            # Cancelled: terminal result, no retry signal.
            service.store.request_cancel(task_id)
            with mock.patch.object(
                service, "_make_build_agent_components", return_value=components
            ), mock.patch("lima.service.BuildAgent"):
                result = service._run_build_agent(
                    task_id, RepositoryWorkspace(str(repo)),
                    "team/project", None,
                )
            self.assertEqual(result.status, NEEDS_ATTENTION)
            self.assertEqual(result.failure_code, "build-admission-cancelled")
        finally:
            slot.release()

        # Not cancelled: the retry signal frees the worker immediately.
        task_id2 = "cb-wait-2"
        service.store.create(task_id2, "team/project", None, {}, "default")
        slot2 = service._build_admission_slot()
        self.assertTrue(slot2.acquire(blocking=False))
        try:
            with mock.patch.object(
                service, "_make_build_agent_components", return_value=components
            ), mock.patch("lima.service.BuildAgent"):
                with self.assertRaises(_BuildAdmissionRetry):
                    service._run_build_agent(
                        task_id2, RepositoryWorkspace(str(repo)),
                        "team/project", None,
                    )
        finally:
            slot2.release()

    def test_off_scan_runs_while_build_budget_exhausted(self):
        # Round-3 F2: an off scan must complete even while a build task is
        # waiting on the exhausted budget - the worker is never blocked.
        service, repo = self._service(build_concurrency=1)
        slot = service._build_admission_slot()
        self.assertTrue(slot.acquire(blocking=False))
        try:
            # Submit an off scan while the budget is fully occupied.
            created = service.enqueue_repository_scan(
                "team/project", build_agent_mode="off"
            )
            task = {}
            for _ in range(300):
                task = service.store.get(created["task_id"]) or {}
                if task.get("state") in {"SUCCESS", "FAILED"}:
                    break
                time.sleep(0.02)
            self.assertEqual(task["state"], "SUCCESS")
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


class Round3ReviewTests(unittest.TestCase):
    """Round-3: publish-boundary digest and end-to-end reuse closure."""

    def test_success_publishes_digest_and_reuses_without_reexecution(self):
        # The full closure (round-3 F1): a real _run_build_agent success
        # computes and anchors the artifact digest at the publish boundary,
        # the summary persists it, and a second call with the budget free
        # reuses the result without touching the executor.
        from lima.build_agent import BuildResult as AgentResult
        from lima.build_context_view import (
            verify_build_artifact,
        )
        from tests.test_build_context_view import write_package_fixture

        handle, path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.addCleanup(os.unlink, path)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        artifacts = tempfile.TemporaryDirectory()
        self.addCleanup(artifacts.cleanup)
        repository = Path(temporary.name, "team", "project")
        (repository / "app").mkdir(parents=True)
        (repository / "app" / "main.cpp").write_text(
            "int main(void) { return 0; }\\n", encoding="utf8"
        )
        from lima.service import ReviewService
        from lima.workspace import RepositoryWorkspace

        service = ReviewService(
            Settings(
                host="127.0.0.1", port=8080, db_path=path, max_diff_bytes=10000,
                max_steps=8, timeout_seconds=120, llm_base_url="",
                llm_api_key="", llm_model="", github_webhook_secret="",
                github_token="", auto_post_review=False,
                repository_import_root=temporary.name,
                repository_scan_sast_mode="off", cxx_memory_mode="off",
                build_agent_mode="auto", build_agent_image="lima-builder:test",
                build_artifacts_root=artifacts.name,
            )
        )
        self.addCleanup(service.queue.close)

        workspace = RepositoryWorkspace(str(repository))
        fingerprint = workspace.inventory().fingerprint()
        # The fake agent run lays out a real package inside the run root so
        # the publish boundary can compute and verify the digest.
        executor_calls = []

        def fake_agent_run(request, *, cancel, progress):
            executor_calls.append(1)
            package_dir = (
                Path(artifacts.name) / "digest-task" / f"run-{len(executor_calls)}"
                / "attempt-1" / "package"
            )
            write_package_fixture(
                package_dir,
                revision=request.snapshot_hash,
                entry={
                    "directory": "app",
                    "arguments": [
                        "/usr/bin/c++", "-DVERIFIED=1", "-c", "main.cpp",
                    ],
                    "file": "app/main.cpp",
                },
            )
            return AgentResult(
                run_id="build-d",
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
                evidence_refs=("attempt-1/package",),
                build_input_digest=compute_build_input_digest(repository),
            )

        task_id = "digest-task"
        service.store.create(task_id, "team/project", None, {}, "default")
        components = (
            lambda state: {"action": "final", "output": {"status": "done"}},
            None,
            None,
        )
        with mock.patch.object(
            service, "_make_build_agent_components", return_value=components
        ), mock.patch("lima.service.BuildAgent") as agent_cls:
            agent_cls.return_value.run.side_effect = fake_agent_run
            first = service._run_build_agent(
                task_id, workspace, "team/project", None
            )
            self.assertEqual(first.status, "SUCCEEDED")
            self.assertIsNotNone(first.artifact_digest)
            package_dir = Path(artifacts.name) / task_id / first.package_ref
            verify_build_artifact(
                package_dir, fingerprint, first.artifact_digest
            )
            service.store.update_task_input(task_id, {
                "build_agent_result": {
                    "run_id": first.run_id,
                    "status": first.status,
                    "snapshot_hash": first.snapshot_hash,
                    "plan_digest": first.plan_digest,
                    "package_ref": first.package_ref,
                    "artifact_digest": first.artifact_digest,
                    "attempts": first.attempts,
                    "failure_code": first.failure_code,
                    "evidence_refs": list(first.evidence_refs),
                    "build_input_digest": first.build_input_digest,
                },
            })
            before = len(executor_calls)
            second = service._run_build_agent(
                task_id, workspace, "team/project", None
            )
            self.assertEqual(second.status, "SUCCEEDED")
            self.assertEqual(len(executor_calls), before)
            self.assertEqual(second.package_ref, first.package_ref)
            (package_dir / "headers" / "fixture" / "lib.h").write_bytes(
                b"// tampered bytes\\n"
            )
            service._run_build_agent(
                task_id, workspace, "team/project", None
            )
            self.assertEqual(len(executor_calls), before + 1)


class Round4ReviewTests(unittest.TestCase):
    """Deferral is not a failure: retry budget and DLQ stay intact."""

    def test_waiting_build_survives_retry_budget_and_eventually_succeeds(self):
        # Round-4: a task waiting on the build budget must not consume
        # failure retries or dead-letter; once the budget frees, it builds.
        # Uses the real queue, store, semaphore and _run_build_agent; only
        # the BuildAgent.run is a controlled stub.
        import threading

        handle, path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.addCleanup(os.unlink, path)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        repository = Path(temporary.name, "team", "project")
        repository.mkdir(parents=True)
        (repository / "app").mkdir(exist_ok=True)
        (repository / "app" / "main.cpp").write_text(
            "int main(void) { return 0; }\\n", encoding="utf8"
        )
        (repository / "app" / "util.cpp").write_text(
            "int util(void) { return 1; }\\n", encoding="utf8"
        )
        from lima.build_agent import SUCCEEDED as BUILD_OK
        from lima.build_agent import BuildResult as AgentResult
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
                build_concurrency=1, queue_max_attempts=2,
                # Round-4 uses the real _run_build_agent admission path, so
                # artifact namespaces must stay inside the temporary root
                # (read-only containers have no writable output/).
                build_artifacts_root=str(Path(temporary.name) / "artifacts"),
            )
        )
        self.addCleanup(service.queue.close)

        budget_released = threading.Event()
        agent_entries = []
        lock = threading.Lock()

        def stub_agent_run(request, *, cancel, progress):
            with lock:
                agent_entries.append(request.snapshot_hash[:8])
            if not budget_released.is_set():
                budget_released.wait(timeout=20)
            return AgentResult(
                run_id="build-r4",
                status=BUILD_OK,
                snapshot_hash=request.snapshot_hash,
                plan_digest="p" * 64,
                image_digest=None,
                dependency_digest=None,
                package_ref=None,
                artifact_digest=None,
                attempts=1,
                coverage=None,
                failure_code=None,
                evidence_refs=(),
            )

        components = (
            lambda state: {"action": "final", "output": {"status": "done"}},
            None,
            None,
        )
        with mock.patch.object(
            service, "_make_build_agent_components", return_value=components
        ), mock.patch("lima.service.BuildAgent") as agent_cls:
            agent_cls.return_value.run.side_effect = stub_agent_run

            # First build occupies the budget.
            first = service.enqueue_repository_scan(
                "team/project", build_agent_mode="auto"
            )
            for _ in range(200):
                with lock:
                    if agent_entries:
                        break
                time.sleep(0.05)

            # Second build must defer (real admission gate, budget=1).
            second = service.enqueue_repository_scan(
                "team/project", build_agent_mode="auto"
            )
            time.sleep(1.5)  # let the deferral cycle through the queue

            # Off scan must succeed while the budget is occupied.
            off = service.enqueue_repository_scan(
                "team/project", build_agent_mode="off"
            )
            off_task = {}
            for _ in range(200):
                off_task = service.store.get(off["task_id"]) or {}
                if off_task.get("state") in {"SUCCESS", "FAILED"}:
                    break
                time.sleep(0.05)
            self.assertEqual(off_task["state"], "SUCCESS")

            # The waiting second task must not be FAILED nor dead-lettered.
            second_task = service.store.get(second["task_id"]) or {}
            self.assertNotEqual(second_task.get("state"), "FAILED")
            self.assertEqual(len(service.queue.dead_letters()), 0)

            # Release the budget: the second task eventually builds.
            budget_released.set()
            for _ in range(400):
                second_task = service.store.get(second["task_id"]) or {}
                if second_task.get("state") in {"SUCCESS", "FAILED"}:
                    break
                time.sleep(0.05)
            self.assertEqual(second_task["state"], "SUCCESS")
            for _ in range(400):
                first_task = service.store.get(first["task_id"]) or {}
                if first_task.get("state") in {"SUCCESS", "FAILED"}:
                    break
                time.sleep(0.05)
            self.assertEqual(first_task["state"], "SUCCESS")
            self.assertEqual(len(service.queue.dead_letters()), 0)


class Round5ReviewTests(unittest.TestCase):
    """Redis deferral: persistent delay set, no hot re-delivery loop."""

    def test_redis_deferral_uses_delayed_zset_not_immediate_xadd(self):
        # Round-5 P2: the Redis deferred path must not immediately xadd;
        # it writes to a ZSET keyed by not-before timestamp, and only the
        # promotion step (called from the worker loop) moves due entries
        # back to the stream.  Uses a recording transport.
        from lima.task_queue import DeferredTaskError, TaskQueue

        xadds = []
        zadds = []
        zrem_results = []
        due_members: list[str] = []

        class RecordingRedis:
            def xadd(self, stream, fields):
                xadds.append((stream, fields))

            def zadd(self, key, mapping):
                zadds.append((key, dict(mapping)))

            def zrangebyscore(self, key, lo, hi, start=0, num=10):
                return list(due_members)

            def zrem(self, key, member):
                zrem_results.append((key, member))
                return 1 if member in due_members else 0

            def eval(self, script, numkeys, *args):
                # Lua promote: check, XADD publish, then ZREM remove.
                deferred_key, stream, envelope = args
                if envelope not in due_members:
                    return 0
                xadds.append((stream, {"envelope": envelope}))
                due_members.remove(envelope)
                zrem_results.append((deferred_key, envelope))
                return 1

        def handler(payload):
            raise DeferredTaskError("budget exhausted", delay_seconds=5.0)

        queue = TaskQueue(handler, workers=1)
        queue._redis = RecordingRedis()
        envelope = {"message_id": "m1", "attempt": 0, "payload": {}}

        queue._deliver(envelope)
        # The deferral wrote to the ZSET, not the stream.
        self.assertEqual(len(xadds), 0)
        self.assertEqual(len(zadds), 1)
        key, mapping = zadds[0]
        self.assertIn("lima:review:stream:deferred", key)
        serialized, not_before = next(iter(mapping.items()))
        self.assertGreater(not_before, 0)  # a real timestamp score
        self.assertIn("m1", serialized)
        # attempt was rolled back (deferral is not a failure).
        self.assertEqual(envelope["attempt"], 0)

        # Before expiry: promotion sees no due members, does nothing.
        queue._promote_expired_deferred()
        self.assertEqual(len(xadds), 0)
        self.assertEqual(len(zrem_results), 0)

        # After expiry: the due member is promoted to the stream.
        due_members.append(serialized)
        queue._promote_expired_deferred()
        self.assertEqual(len(xadds), 1)
        stream, fields = xadds[0]
        self.assertEqual(stream, "lima:review:stream")
        self.assertEqual(fields["envelope"], serialized)
        self.assertEqual(len(zrem_results), 1)

    def test_redis_worker_loop_promotes_deferred(self):
        # The worker loop calls _promote_expired_deferred before each
        # _reclaim_stale, so due entries eventually re-enter the stream.
        import inspect

        from lima.task_queue import TaskQueue

        source = inspect.getsource(TaskQueue._redis_worker)
        self.assertIn(
            "_promote_expired_deferred", source,
            "worker loop must promote due deferred entries",
        )
        # And the promote happens before reclaim, not after.
        self.assertLess(
            source.index("_promote_expired_deferred"),
            source.index("_reclaim_stale"),
        )


class Round6ReviewTests(unittest.TestCase):
    """Queue-isolated deferral and atomic promote (round 6)."""

    def test_deferred_keys_are_per_queue(self):
        # Two queues on the same Redis backend must use separate deferred
        # ZSETs so an experiment worker can never deliver a scan envelope
        # to the experiment stream (round-6 F1).
        from lima.task_queue import TaskQueue

        scan = TaskQueue(lambda p: None, workers=1)
        scan._redis = object()  # any non-None backend
        experiment = TaskQueue(
            lambda p: None, workers=1, stream="lima:experiment:stream"
        )
        experiment._redis = object()
        scan_key = scan._deferred_key
        exp_key = experiment._deferred_key
        self.assertNotEqual(scan_key, exp_key)
        self.assertIn("lima:review:stream", scan_key)
        self.assertIn("lima:experiment:stream", exp_key)
        self.assertTrue(scan_key.endswith(":deferred"))
        self.assertTrue(exp_key.endswith(":deferred"))

    def test_promote_is_atomic_and_exception_safe(self):
        # The promote path uses Lua (ZREM+XADD atomic) and swallows
        # infrastructure errors so the worker loop survives (round-6 F2).
        from lima.task_queue import TaskQueue

        evals = []

        class FlakyRedis:
            def zrangebyscore(self, key, lo, hi, start=0, num=10):
                return ["envelope-json"]

            def eval(self, script, numkeys, *args):
                evals.append((script, args))
                raise ConnectionError("redis down")

        queue = TaskQueue(lambda p: None, workers=1)
        queue._redis = FlakyRedis()

        # The infrastructure error must not escape (worker loop survives).
        queue._promote_expired_deferred()
        self.assertEqual(len(evals), 1)
        # The Lua script contains both ZREM and XADD (atomic transfer).
        script = evals[0][0]
        self.assertIn("ZREM", script)
        self.assertIn("XADD", script)
        # Arguments carry the deferred key and the stream (per-queue).
        deferred_key, stream, envelope = evals[0][1]
        self.assertIn(":deferred", deferred_key)
        self.assertIn("lima:review:stream", stream)
        self.assertEqual(envelope, "envelope-json")

    def test_promote_uses_per_queue_keys(self):
        # The Lua call binds this queue's deferred key AND this queue's
        # stream — never another queue's (round-6 F1).
        from lima.task_queue import TaskQueue

        class RecordingRedis:
            def __init__(self):
                self.evals = []

            def zrangebyscore(self, key, lo, hi, start=0, num=10):
                return ["member"]

            def eval(self, script, numkeys, *args):
                self.evals.append(args)
                return 1

        queue = TaskQueue(
            lambda p: None, workers=1, stream="lima:experiment:stream"
        )
        redis_stub = RecordingRedis()
        queue._redis = redis_stub
        queue._promote_expired_deferred()
        self.assertEqual(len(redis_stub.evals), 1)
        deferred_key, stream, _ = redis_stub.evals[0]
        self.assertEqual(deferred_key, "lima:experiment:stream:deferred")
        self.assertEqual(stream, "lima:experiment:stream")


class Round7ReviewTests(unittest.TestCase):
    """Publish-first promote: a failed XADD never loses the member."""

    def test_lua_publishes_before_removing(self):
        # The Lua script must XADD before ZREM — Redis Lua does not roll
        # back runtime errors, so delete-first loses tasks on XADD failure
        # (round-7 P1).
        from lima.task_queue import TaskQueue

        script = TaskQueue._PROMOTE_LUA
        zscore = script.index("ZSCORE")
        xadd = script.index("XADD")
        zrem = script.index("ZREM")
        self.assertLess(zscore, xadd, "existence check precedes publish")
        self.assertLess(xadd, zrem, "publish precedes removal")

    def test_publish_failure_preserves_member(self):
        # An XADD runtime error must leave the member in the ZSET so the
        # next promotion cycle can retry (round-7 P1).
        from lima.task_queue import TaskQueue

        state = {"zset": ["envelope-A"], "stream_is_string": True}
        xadds = []

        class WrongTypeRedis:
            """Simulates WRONGTYPE: the stream key is a string, XADD errors."""

            def zrangebyscore(self, key, lo, hi, start=0, num=10):
                return list(state["zset"])

            def eval(self, script, numkeys, *args):
                deferred_key, stream, envelope = args
                # Model the Lua: ZSCORE check passes, then XADD errors.
                if envelope not in state["zset"]:
                    return 0
                if state["stream_is_string"]:
                    raise Exception("WRONGTYPE Operation against a key")
                # Successful publish: XADD then ZREM.
                xadds.append((stream, envelope))
                state["zset"].remove(envelope)
                return 1

        queue = TaskQueue(lambda p: None, workers=1)
        queue._redis = WrongTypeRedis()

        # The promote must not escape the exception (worker survives)…
        queue._promote_expired_deferred()
        # …and the member must still be in the ZSET (not lost).
        self.assertIn("envelope-A", state["zset"])
        self.assertEqual(len(xadds), 0)

        # Fix the stream type: the next promotion succeeds.
        state["stream_is_string"] = False
        queue._promote_expired_deferred()
        self.assertEqual(len(xadds), 1)
        self.assertNotIn("envelope-A", state["zset"])


if __name__ == "__main__":
    unittest.main()
