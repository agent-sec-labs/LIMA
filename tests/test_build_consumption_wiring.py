"""Consumption chain wiring tests.

After a successful build, the service must construct the verified
AnalysisContextView from the produced package, hand it to the repository
scanner, which passes it to run_platform_review so facts, repro and the
Specialist actually consume the verified-package projection instead of the
legacy paths — and the report must honestly mark consumed_by_analysis.
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


def make_build_result(status: str, package_ref: str | None = None) -> BuildResult:
    return BuildResult(
        run_id="build-wire",
        status=status,
        snapshot_hash="a" * 64,
        plan_digest="b" * 64,
        image_digest=None,
        dependency_digest=None,
        package_ref=package_ref,
        artifact_digest="c" * 64,
        attempts=1,
        coverage=None,
        failure_code=None if status == SUCCEEDED else "build-not-configured",
        evidence_refs=(),
    )


class ConsumptionWiringTests(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.addCleanup(os.unlink, self.path)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        repository = Path(self.temporary.name, "team", "project")
        repository.mkdir(parents=True)
        (repository / "app.py").write_text("safe = True\n", encoding="utf8")
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

    def _run_scan(self, service, build_result, *, mode="auto"):
        """Run one scan with a stubbed build result; return the task."""
        with mock.patch.object(
            service, "_run_build_agent", return_value=build_result
        ), mock.patch.object(
            service.repository_scanner, "scan",
            wraps=service.repository_scanner.scan,
        ) as scan_spy, mock.patch.object(
            service, "_consume_build_context",
            wraps=service._consume_build_context,
        ) as consume_spy:
            created = service.enqueue_repository_scan(
                "team/project", build_agent_mode=mode
            )
            task = {}
            for _ in range(300):
                task = service.store.get(created["task_id"]) or {}
                if task.get("state") in {"SUCCESS", "FAILED"}:
                    break
                time.sleep(0.02)
        return task, scan_spy, consume_spy

    def test_success_constructs_view_and_passes_to_scanner(self):
        """A successful build must produce a view consumed by the scanner."""
        service = self._service(
            build_agent_mode="auto", build_agent_image="lima-builder:test"
        )
        build_result = make_build_result(SUCCEEDED, "run-1/attempt-1/package")
        sentinel_view = object()  # stands in for the AnalysisContextView

        with mock.patch.object(
            service, "_run_build_agent", return_value=build_result
        ), mock.patch.object(
            service, "_consume_build_context", return_value=sentinel_view
        ) as consume_mock, mock.patch.object(
            service.repository_scanner, "scan",
            wraps=service.repository_scanner.scan,
        ) as scan_spy:
            created = service.enqueue_repository_scan(
                "team/project", build_agent_mode="auto"
            )
            task = {}
            for _ in range(300):
                task = service.store.get(created["task_id"]) or {}
                if task.get("state") in {"SUCCESS", "FAILED"}:
                    break
                time.sleep(0.02)

        self.assertEqual(task["state"], "SUCCESS")
        # The consumption wiring was invoked.
        consume_mock.assert_called_once()
        # The scanner received the verified_view.
        kwargs = scan_spy.call_args.kwargs
        self.assertIs(kwargs.get("verified_view"), sentinel_view)
        # The report honestly says the context was consumed.
        report = task.get("report") or {}
        visible = report.get("collaboration", {}).get("build_agent")
        self.assertIsNotNone(visible)
        self.assertTrue(visible["consumed_by_analysis"])

    def test_failure_does_not_construct_view(self):
        """A failed build must not produce a view for the scanner."""
        service = self._service(
            build_agent_mode="auto", build_agent_image="lima-builder:test"
        )
        build_result = make_build_result(NEEDS_ATTENTION)
        task, scan_spy, consume_spy = self._run_scan(service, build_result)

        self.assertEqual(task["state"], "SUCCESS")  # auto degrades
        consume_spy.assert_not_called()
        kwargs = scan_spy.call_args.kwargs
        self.assertIsNone(kwargs.get("verified_view"))
        report = task.get("report") or {}
        visible = report.get("collaboration", {}).get("build_agent")
        self.assertFalse(visible["consumed_by_analysis"])

    def test_off_mode_never_consumes(self):
        """off mode keeps the current path with no consumption wiring."""
        service = self._service()
        task, scan_spy, consume_spy = self._run_scan(
            service, make_build_result(SUCCEEDED), mode="off"
        )
        consume_spy.assert_not_called()
        report = task.get("report") or {}
        self.assertNotIn("build_agent", report.get("collaboration", {}))

    def test_invalid_package_does_not_crash_scan(self):
        """A missing/corrupt package degrades to gap, not a scan failure."""
        service = self._service(
            build_agent_mode="auto", build_agent_image="lima-builder:test"
        )
        # The build "succeeded" but the package doesn't exist on disk.
        build_result = make_build_result(SUCCEEDED, "run-1/nonexistent/package")
        task, scan_spy, consume_spy = self._run_scan(service, build_result)

        # The scan still completes (the consumption attempt failed silently
        # — the context isn't consumed, but the detection isn't blocked).
        self.assertEqual(task["state"], "SUCCESS")
        report = task.get("report") or {}
        visible = report.get("collaboration", {}).get("build_agent")
        # The consumption failed, so it's not marked as consumed.
        self.assertFalse(visible["consumed_by_analysis"])


class ConsumptionRealPathTests(unittest.TestCase):
    """The real _consume_build_context path: package → view → scanner kwarg."""

    def test_consume_build_context_returns_real_view(self):
        """A real package on disk produces a real AnalysisContextView."""
        import json as _json

        from lima.build_context_view import (
            AnalysisContextView,
            compute_artifact_digest,
        )
        from lima.context_package import build_manifest, write_package

        handle, path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.addCleanup(os.unlink, path)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        artifacts = tempfile.TemporaryDirectory()
        self.addCleanup(artifacts.cleanup)
        repository = Path(temporary.name, "team", "project")
        repository.mkdir(parents=True)
        (repository / "app").mkdir()
        (repository / "app" / "main.cpp").write_text(
            "int main(void) { return 0; }\\n", encoding="utf8"
        )
        from lima.service import ReviewService
        from lima.workspace import RepositoryWorkspace

        service = ReviewService(
            Settings(
                host="127.0.0.1", port=8080, db_path=path,
                max_diff_bytes=10000, max_steps=8, timeout_seconds=120,
                llm_base_url="", llm_api_key="", llm_model="",
                github_webhook_secret="", github_token="",
                auto_post_review=False,
                repository_import_root=temporary.name,
                repository_scan_sast_mode="off", cxx_memory_mode="off",
                build_artifacts_root=artifacts.name,
            )
        )
        self.addCleanup(service.queue.close)

        workspace = RepositoryWorkspace(str(repository))
        fingerprint = workspace.inventory().fingerprint()
        # Lay out a real verified package.
        compdb = [
            {
                "directory": "app",
                "arguments": [
                    "/usr/bin/c++", "-DREAL=1", "-c", "main.cpp",
                ],
                "file": "app/main.cpp",
            }
        ]
        manifest = build_manifest(
            repository="team/project", revision=fingerprint,
            compdb=compdb, generated=[], header_roots=[], rewrites={},
            created_by="consumption-test",
        )
        package_dir = Path(artifacts.name) / "task-x" / "run-1" / "package"
        write_package(
            package_dir, manifest,
            _json.dumps(compdb).encode("utf8"), {}, {},
        )
        digest = compute_artifact_digest(package_dir)
        from lima.build_agent import SUCCEEDED as OK
        from lima.build_agent import BuildResult

        build_result = BuildResult(
            run_id="build-real", status=OK, snapshot_hash=fingerprint,
            plan_digest="p" * 64, image_digest=None, dependency_digest=None,
            package_ref="run-1/package", artifact_digest=digest,
            attempts=1, coverage=None, failure_code=None, evidence_refs=(),
        )
        view = service._consume_build_context("task-x", workspace, build_result)
        # The view is a real AnalysisContextView with the compdb's TU list.
        self.assertIsInstance(view, AnalysisContextView)
        self.assertEqual(view.target_units, ("app/main.cpp",))
        self.assertIn("-DREAL=1", view.flags_for_tu("app/main.cpp"))


if __name__ == "__main__":
    unittest.main()
