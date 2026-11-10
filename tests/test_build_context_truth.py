"""Actual facts availability, rather than selected mode, controls consumption."""

import json
import unittest
from dataclasses import replace
from unittest import mock

from lima.build_agent import SUCCEEDED
from tests import test_verified_view_execution_holders as holders
from tests.test_agent_orchestrator import RESOLVED_LLM
from tests.test_build_consumption_wiring import make_build_result


class BuildContextTruthTests(unittest.TestCase):
    def test_lost_registration_is_incomplete_and_never_claimed_consumed(self):
        service, sidecar = holders.ExecutionHolderTests._service_with_sidecar(self)

        class LosingAdapter:
            holder = None

            def register_verified_view(self, snapshot, view, *, holder=None):
                self.holder = holder
                return sidecar.client.register_verified_view(snapshot, view, holder=holder)

            def analyze_uaf_facts(self, repository, snapshot, units, mode, **kwargs):
                sidecar.client.unregister_verified_view(
                    snapshot, kwargs["artifact_digest"], holder=self.holder,
                )
                return sidecar.client.analyze_uaf_facts(
                    repository, snapshot, units, mode, **kwargs,
                )

            def unregister_verified_view(self, snapshot, digest, *, holder=None):
                return sidecar.client.unregister_verified_view(snapshot, digest, holder=holder)

        service.repository_scanner.cxx_memory_adapter = LosingAdapter()
        service.repository_scanner.cxx_uaf_llm_factory = lambda: dict(RESOLVED_LLM)
        build = replace(
            make_build_result(SUCCEEDED, "run-1/pkg"),
            snapshot_hash=sidecar.snapshot_hash, artifact_digest=sidecar.digest,
        )
        for mode in ("auto", "required"):
            with self.subTest(mode=mode), mock.patch.object(service.queue, "submit"):
                task = service.enqueue_repository_scan("team/project", build_agent_mode=mode)
                with (
                    mock.patch.object(service, "_run_build_agent", return_value=build),
                    mock.patch.object(service, "_consume_build_context", return_value=sidecar.view),
                    mock.patch("lima.agent_orchestrator.send_semantic_request",
                               return_value=json.dumps({"leads": []})) as llm,
                ):
                    service._execute_repository_scan(
                        task["task_id"], sidecar.repository, "default", "team/project", {},
                        cxx_agent_mode="auto", build_agent_mode=mode,
                    )
                    if mode == "required":
                        self.assertEqual(llm.call_count, 0)
                report = service.store.get(task["task_id"])["report"]
                build_summary = report["collaboration"]["build_agent"]
                platform = report["collaboration"]["platform"]
                self.assertFalse(build_summary["consumed_by_analysis"])
                self.assertEqual(build_summary["blocking"], mode == "required")
                self.assertEqual(build_summary["failure_code"], "verified-context-unavailable")
                self.assertEqual(platform["status"], "review-incomplete")
                self.assertEqual(platform["verified_context_units"], [])
                self.assertIn("src/a.cpp", platform["unreviewed_units"])
                self.assertIn("verified-view-not-registered", " ".join(platform["diagnostics"]))
                self.assertEqual(platform["v4"]["aep"]["audit_outcome"], "incomplete")
