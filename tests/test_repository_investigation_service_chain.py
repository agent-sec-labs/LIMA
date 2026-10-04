"""Service-chain acceptance tests for the report-consistency packet.

Matrix row 14 / AC-14: the REAL ``ReviewService`` -> queue worker ->
``FindingInvestigator`` -> ``merge_investigation_into_report`` -> store ->
persisted JSON chain, with a transport-level fake only.  The fake replaces
``lima.reviewer.post_chat_completion_full`` BEFORE the service (and thus
``InvestigationLLMClient``) is constructed, so the production client binds
the fake as its transport and the whole chain above it is real code.  The
merge function itself is never monkeypatched and no unit report is passed
off as a service result.

Independent sample (``fleet/*``): different packages, symbols and source
shapes from the frozen unit sample, the frozen ``svc/*`` sample and the
B-1 probes.
"""

import json
import os
import pathlib
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from lima.models import ReviewReport
from lima.repository_investigation import (
    FindingInvestigator,
    InvestigationBudget,
    InvestigationLLMClient,
    InvestigationSnapshot,
    build_module_targets,
    merge_investigation_into_report,
)

SERVICE_SAMPLE = {
    "fleet/__init__.py": "",
    "fleet/telemetry.py": (
        "from telemetry_bus import publish\n"
        "\n"
        "\n"
        "def emit(signal):\n"
        "    return publish(signal)\n"
    ),
}

MODULE_PATH = "fleet/telemetry.py"
MODULE_FP = "module-scope:" + MODULE_PATH
DISCOVERY_WHY = (
    "publish is imported from an unresolved bus module and invoked on "
    "caller-controlled signals"
)

ENV_KEYS = (
    "LIMA_DB_PATH",
    "LIMA_REPOSITORY_CACHE_ROOT",
    "LIMA_REPOSITORY_INVESTIGATION_MODE",
    "LIMA_LLM_PROVIDER",
    "LIMA_DEEPSEEK_API_KEY",
    "LIMA_REPOSITORY_SCAN_SAST_MODE",
    "LIMA_REPOSITORY_SCAN_LLM_MODE",
    "LIMA_REPOSITORY_SCAN_SOURCES",
    "LIMA_REPOSITORY_IMPORT_ROOT",
)

ENV_VALUES = {
    "LIMA_REPOSITORY_INVESTIGATION_MODE": "auto",
    "LIMA_LLM_PROVIDER": "deepseek",
    "LIMA_DEEPSEEK_API_KEY": "test-key",
    "LIMA_REPOSITORY_SCAN_SAST_MODE": "off",
    "LIMA_REPOSITORY_SCAN_LLM_MODE": "off",
    "LIMA_REPOSITORY_SCAN_SOURCES": "local-import",
}


def tool_action(tool, **arguments):
    return {"action": "tool", "tool": tool, "arguments": arguments,
            "reason": "missing evidence"}


def final(results, new_targets=None):
    return {
        "action": "final", "results": results,
        "new_targets": new_targets or [],
    }


def result(fp, path, line, verdict, refs=None, reasoning="model reasoning"):
    return {
        "fingerprint": fp, "path": path, "line": line, "verdict": verdict,
        "reasoning": reasoning, "evidence_refs": refs or [],
        "evidence_basis": {
            "syntax_hit": True, "model_reasoning": True,
            "dynamic_observation": False,
        },
        "confidence": 0.9,
    }


def candidate_script():
    """Module review that reads real source then reports a legal target."""
    return [
        tool_action("read_source", path=MODULE_PATH,
                    start_line=1, end_line=6),
        final(
            [result(MODULE_FP, MODULE_PATH, 0, "insufficient",
                    reasoning="telemetry bus binding unresolved in snapshot")],
            new_targets=[{
                "path": MODULE_PATH, "line": 5, "symbol": "emit",
                "why": DISCOVERY_WHY,
                "evidence_refs": [f"read_source:{MODULE_PATH}:1-6"],
            }],
        ),
    ]


def module_failure_script():
    return [TimeoutError("model timeout")]


class ScriptedTransport:
    """Offline stand-in for the shared chat-completions transport.

    No network I/O ever happens: real external model calls are zero by
    construction while the production client/loop/tools keep running.
    """

    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def __call__(self, provider, base_url, api_key, payload, timeout,
                 extra_headers=None, max_bytes=None):
        self.calls.append({
            "provider": provider, "model": payload.get("model"),
            "messages": len(payload.get("messages") or []),
        })
        if not self.script:
            raise RuntimeError("script exhausted (offline transport)")
        action = self.script.pop(0)
        if isinstance(action, Exception):
            raise action
        return {
            "content": json.dumps(action),
            "usage": {"prompt_tokens": 10, "completion_tokens": 10,
                      "total_tokens": 20},
            "finish_reason": "stop",
        }


class ScriptedClient(InvestigationLLMClient):
    """Offline client for the unit-side comparison merge."""

    def __init__(self, script):
        super().__init__(
            base_url="http://offline", api_key="offline-key",
            model="offline-model", provider="scripted-offline",
            budget=InvestigationBudget(max_requests=100),
        )
        self.script = list(script)

    def complete_json(self, *, system: str, user: str):
        self.budget = self.budget.reserve()
        if not self.script:
            raise RuntimeError("script exhausted (offline client)")
        action = self.script.pop(0)
        if isinstance(action, Exception):
            raise action
        return action


def canonical_faces(report_document):
    """The comparison subset shared by unit merge and persisted JSON.

    Usage (latency/token/provider detail) differs by construction between
    the offline unit client and the service-configured provider, so it is
    deliberately excluded; every adjudication/risk/summary/detail face the
    Packet freezes is included.
    """
    adjudication = report_document["adjudication"]
    block = report_document["collaboration"]["investigation"]
    faces = adjudication["investigation_summary"]
    return {
        "overall_disposition": adjudication["overall_disposition"],
        "counts": adjudication["counts"],
        "decisions": sorted(
            (d["fingerprint"], d["disposition"]) for d in adjudication["decisions"]
        ),
        "supported": faces["supported"],
        "refuted": faces["refuted"],
        "insufficient": faces["insufficient"],
        "active_alerts": faces["active_alerts"],
        "new_targets": faces["new_targets"],
        "risk": report_document["risk"],
        "summary": report_document["summary"],
        "verdict_counts": block["verdict_counts"],
        "block_new_targets": block["new_targets"],
        "block_statuses": block["statuses"],
    }


class TestServiceChain(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(suffix="-pr265b2-svc")
        self.outer_root = pathlib.Path(tmp)
        self.repo_root = self.outer_root / "repo"
        for rel, text in SERVICE_SAMPLE.items():
            path = self.repo_root / pathlib.PurePosixPath(rel)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        self._saved_env = {key: os.environ.get(key) for key in ENV_KEYS}
        values = dict(ENV_VALUES)
        values["LIMA_DB_PATH"] = str(self.outer_root / "state.db")
        values["LIMA_REPOSITORY_CACHE_ROOT"] = str(self.outer_root / "cache")
        values["LIMA_REPOSITORY_IMPORT_ROOT"] = str(self.outer_root)
        for key, value in values.items():
            os.environ[key] = value
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def run_service_scan(self, script):
        """Full chain: real service + worker + investigator, fake transport."""
        from lima.config import Settings
        from lima.service import ReviewService

        transport = ScriptedTransport(script)
        with mock.patch(
            "lima.reviewer.post_chat_completion_full", new=transport,
        ):
            settings = Settings.from_env()
            service = ReviewService(settings)
            try:
                self.assertIsInstance(
                    service.repository_investigation, FindingInvestigator
                )
                import lima.repository_import as import_mod

                original_resolve = import_mod.RepositoryImportPolicy.resolve
                import_mod.RepositoryImportPolicy.resolve = (
                    lambda policy, key: self.repo_root
                )
                try:
                    created = service.enqueue_repository_scan(
                        "repo", "default", investigate_paths=[MODULE_PATH],
                    )
                    deadline = time.time() + 60
                    task = {}
                    while time.time() < deadline:
                        task = service.store.get(
                            created["task_id"], "default"
                        ) or {}
                        if task.get("state") in {"SUCCESS", "FAILED"}:
                            break
                        time.sleep(0.05)
                finally:
                    import_mod.RepositoryImportPolicy.resolve = original_resolve
            finally:
                service.queue.close()
        self.assertEqual(task.get("state"), "SUCCESS", task.get("error"))
        return task, transport, service

    def unit_merge_document(self):
        """Same candidate scenario through the real unit merge chain.

        The static-findings argument mirrors the production call form
        (``result.report.findings`` -- the report's own list), so the unit
        face and the service face exercise the identical merge inputs.
        """
        snapshot = InvestigationSnapshot(self.repo_root)
        targets = build_module_targets(snapshot, [MODULE_PATH])
        investigator = FindingInvestigator(
            ScriptedClient(candidate_script()),
            batch_size=6, max_steps=5, timeout_seconds=30,
        )
        outcome = investigator.investigate(targets, snapshot)
        report = ReviewReport(
            repository="consistency", pull_request=None, summary="old",
            risk="low",
        )
        merge_investigation_into_report(report, outcome, report.findings)
        return report.to_dict()

    def test_service_persists_candidate_discovery_faces(self):
        task, _, _ = self.run_service_scan(candidate_script())
        report = task["report"]
        adjudication = report["adjudication"]
        discovered = [
            f for f in report["findings"] if f["rule_id"] == "AGENT-DISCOVERY"
        ]
        self.assertEqual(len(discovered), 1)
        self.assertEqual(discovered[0]["verification_state"], "candidate")
        self.assertEqual(discovered[0]["path"], MODULE_PATH)
        self.assertEqual(discovered[0]["line"], 5)
        decisions = {
            d["fingerprint"]: d for d in adjudication["decisions"]
        }
        self.assertEqual(len(decisions), 2)
        candidate = decisions[discovered[0]["fingerprint"]]
        self.assertEqual(candidate["disposition"], "needs_review")
        self.assertEqual(
            candidate["reason"], "unverified-finding-requires-human-review"
        )
        self.assertEqual(
            candidate["investigation_evidence_refs"],
            [f"read_source:{MODULE_PATH}:1-6"],
        )
        self.assertNotIn("investigation_verdict", candidate)
        self.assertEqual(report["risk"], "high")
        self.assertEqual(adjudication["overall_disposition"], "needs_review")
        self.assertEqual(adjudication["counts"]["needs_review"], 2)

    def test_service_persists_module_failure_faces(self):
        task, _, _ = self.run_service_scan(module_failure_script())
        report = task["report"]
        adjudication = report["adjudication"]
        self.assertEqual(report["findings"], [])
        decisions = {
            d["fingerprint"]: d for d in adjudication["decisions"]
        }
        self.assertEqual(set(decisions), {MODULE_FP})
        decision = decisions[MODULE_FP]
        self.assertEqual(decision["disposition"], "needs_review")
        self.assertEqual(decision["investigation_status"], "failed")
        self.assertEqual(
            decision.get("investigation_failure_reason"),
            "batch-error:TimeoutError",
        )
        self.assertEqual(adjudication["overall_disposition"], "needs_review")
        self.assertNotEqual(adjudication["overall_disposition"], "clear")
        block = report["collaboration"]["investigation"]
        self.assertEqual(
            block["statuses"][MODULE_FP],
            {"status": "failed", "reason": "batch-error:TimeoutError"},
        )
        self.assertEqual(report["risk"], "low")

    def test_service_json_matches_unit_merge_faces(self):
        task, _, _ = self.run_service_scan(candidate_script())
        service_faces = canonical_faces(task["report"])
        unit_faces = canonical_faces(self.unit_merge_document())
        # Same derivation source: the persisted JSON equals the unit merge.
        self.assertEqual(service_faces, unit_faces)
        # And the shared face is the acceptance face, not clear/low.
        self.assertEqual(unit_faces["overall_disposition"], "needs_review")
        self.assertEqual(unit_faces["risk"], "high")
        self.assertEqual(len(unit_faces["decisions"]), 2)

    def test_real_investigator_used_with_fake_transport(self):
        task, transport, service = self.run_service_scan(candidate_script())
        investigator = service.repository_investigation
        self.assertIsInstance(investigator, FindingInvestigator)
        self.assertIsInstance(investigator.client, InvestigationLLMClient)
        # The production client really sent its requests through the fake
        # (candidate path: tool call + final, all round-trips accounted).
        self.assertGreaterEqual(len(transport.calls), 2)
        self.assertEqual(transport.calls[0]["provider"], "deepseek")
        block = task["report"]["collaboration"]["investigation"]
        self.assertEqual(block["usage"]["provider"], "deepseek")
        self.assertEqual(block["usage"]["requests"], len(transport.calls))
        self.assertFalse(block["secret_persisted"])
        # The real chain's persisted face carries the unknown, not a clear.
        self.assertEqual(
            task["report"]["adjudication"]["overall_disposition"],
            "needs_review",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
