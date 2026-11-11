"""Build requests and restored packages obey the task's selected scan scope."""

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from tests import test_build_agent_service as service_tests


class BuildScanScopeTests(unittest.TestCase):
    def test_restored_success_missing_current_target_is_not_reused(self):
        from lima.build_context_view import compute_artifact_digest
        from lima.context_package import read_package
        from tests.test_build_context_view import write_package_fixture

        service, _ = service_tests.Round2ReviewTests._service(self)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        service.settings = replace(service.settings, build_artifacts_root=temporary.name)
        package = Path(temporary.name) / "restored" / "run-1" / "package"
        write_package_fixture(package, revision="a" * 64)
        manifest = read_package(package).manifest
        service.store.create("restored", "team/project", None, {
            "build_target_units": ["app/util.cpp"],
            "build_agent_result": {
                "status": "SUCCEEDED", "snapshot_hash": manifest.revision,
                "package_ref": "run-1/package",
                "artifact_digest": compute_artifact_digest(package),
            },
        }, "default")
        self.assertIsNone(service._persisted_build_result("restored", manifest.revision))

    def test_explicit_scope_is_persisted_and_used_by_build_request(self):
        service, repository = service_tests.Round2ReviewTests._service(self)
        from lima.build_agent import NEEDS_ATTENTION
        from lima.workspace import RepositoryWorkspace

        task_id = "scope-task"
        service.store.create(task_id, "team/project", None, {
            "investigate_paths": ["app/util.cpp"],
        }, "default")
        requests = []

        def run(request, **kwargs):
            requests.append(request)
            return service_tests.make_build_result(NEEDS_ATTENTION, "test-stop")

        with mock.patch.object(service, "_make_build_agent_components",
                               return_value=(None, None, None)), \
                mock.patch("lima.service.BuildAgent") as agent:
            agent.return_value.run.side_effect = run
            service._run_build_agent(task_id, RepositoryWorkspace(repository), "team/project", None)
        self.assertEqual(requests[0].target_units, ("app/util.cpp",))
        task_input = service.store.get(task_id)["input"]
        self.assertEqual(task_input["build_target_units"], ["app/util.cpp"])
