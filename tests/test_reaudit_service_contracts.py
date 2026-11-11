"""Task completion and build artifacts respect execution boundaries."""

import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from lima.build_agent import NEEDS_ATTENTION
from lima.cxx_memory import CxxAnalysisResult
from lima.workspace import RepositoryWorkspace
from tests import test_build_agent_service as fixtures


class ReauditServiceTests(unittest.TestCase):
    def test_execution_receipt_updates_import_policy_even_when_build_failed(self):
        service, _ = fixtures.Round2ReviewTests._service(self)
        build = replace(
            fixtures.make_build_result(NEEDS_ATTENTION, "configure-step-failed"),
            repository_code_executed=True,
        )
        with mock.patch.object(service, "_run_build_agent", return_value=build):
            task = service.enqueue_repository_scan("team/project", build_agent_mode="auto")
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                observed = service.store.get(task["task_id"])
                if observed["state"] in {"SUCCESS", "FAILED"}:
                    break
                threading.Event().wait(0.02)
        self.assertEqual(observed["state"], "SUCCESS")
        policy = observed["report"]["collaboration"]["import_policy"]
        self.assertTrue(policy["repository_code_executed"])
        self.assertFalse(policy["host_repository_code_executed"])
        self.assertEqual(policy["repository_code_execution_environment"], "build-sandbox")

    def test_build_only_input_change_invalidates_restore_even_if_audit_hash_matches(self):
        from lima.build_context_view import compute_artifact_digest
        from lima.build_inputs import compute_build_input_digest
        from tests.test_build_context_view import write_package_fixture

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        service, repository = fixtures.Round2ReviewTests._service(
            self, build_artifacts_root=temporary.name,
        )
        resource = repository / "config.dat"
        resource.write_text("first", encoding="utf8")
        fingerprint = RepositoryWorkspace(repository).inventory().fingerprint()
        package = Path(temporary.name) / "restored" / "run-1" / "package"
        write_package_fixture(package, revision=fingerprint)
        service.store.create("restored", "team/project", None, {
            "investigate_paths": ["app/main.cpp"],
            "build_agent_result": {
                "status": "SUCCEEDED", "snapshot_hash": fingerprint,
                "package_ref": "run-1/package",
                "artifact_digest": compute_artifact_digest(package),
                "build_input_digest": compute_build_input_digest(repository),
            },
        }, "default")
        restored = service._persisted_build_result("restored", fingerprint, repository)
        self.assertIsNotNone(restored)
        self.assertIsNotNone(service._consume_build_context(
            "restored", RepositoryWorkspace(repository), restored,
        ))
        resource.write_text("changed", encoding="utf8")
        self.assertEqual(RepositoryWorkspace(repository).inventory().fingerprint(), fingerprint)
        self.assertIsNone(service._persisted_build_result("restored", fingerprint, repository))
        self.assertIsNone(service._consume_build_context(
            "restored", RepositoryWorkspace(repository), restored,
        ))

    def test_required_build_gap_is_visible_in_total_completion(self):
        service, _ = fixtures.Round2ReviewTests._service(self)
        layer_requests = []

        class SourceAdapter:
            def analyze(self, repository, fingerprint, layers, **kwargs):
                layer_requests.append(layers)
                return CxxAnalysisResult("completed", [], [], {}, [])

        service.repository_scanner.cxx_memory_mode = "auto"
        service.repository_scanner.cxx_memory_adapter = SourceAdapter()
        with mock.patch.object(service, "_run_build_agent", return_value=fixtures.make_build_result(
            NEEDS_ATTENTION, "build-not-configured",
        )):
            task = service.enqueue_repository_scan("team/project", build_agent_mode="required")
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                observed = service.store.get(task["task_id"])
                if observed["state"] in {"SUCCESS", "FAILED"}:
                    break
                threading.Event().wait(0.02)
        self.assertEqual(observed["state"], "SUCCESS")
        self.assertEqual(layer_requests, [("source-only",)])
        self.assertTrue(observed["report"]["collaboration"]["build_agent"]["blocking"])
        completion = observed["progress"]["detail"]["completion"]
        self.assertEqual(completion["status"], "completed_with_warnings")
        self.assertIn("build-context-blocked", completion["warnings"])

    def test_same_task_concurrent_builds_reserve_distinct_directories(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        service, repository = fixtures.Round2ReviewTests._service(
            self, build_concurrency=2, build_artifacts_root=temporary.name,
        )
        service.store.create("same-task", "team/project", None, {}, "default")
        barrier = threading.Barrier(2)
        roots = []
        errors = []

        def make_agent(**kwargs):
            roots.append(Path(kwargs["artifacts_root"]))
            barrier.wait(5)

            class Agent:
                def run(self, request, **kwargs):
                    return fixtures.make_build_result(NEEDS_ATTENTION, "test-stop")
            return Agent()

        def execute():
            try:
                service._run_build_agent(
                    "same-task", RepositoryWorkspace(repository), "team/project", None,
                )
            except Exception as error:
                errors.append(error)

        with mock.patch.object(service, "_make_build_agent_components",
                               return_value=(None, None, None)), \
                mock.patch("lima.service.BuildAgent", side_effect=make_agent):
            threads = [threading.Thread(target=execute) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(10)
        self.assertFalse(errors, errors)
        self.assertEqual(len(roots), 2)
        self.assertEqual(len(set(roots)), 2)
        self.assertTrue(all(path.is_dir() for path in roots))
