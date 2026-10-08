"""Joint coexistence acceptance tests for the agent-modes integration packet.

PACKET-265D-AGENT-MODES-INTEGRATION v0.1 (APPROVED-EFFECTIVE per
COORD-RULING-C2-PACKET_v1) §9: the C-Final Python investigation chain
(``investigate_paths`` normalization/persistence/recovery) and the
main-side C++ agent chain (``agent_detection`` three-state -> enqueue
snapshot -> queue message/store persistence -> worker dual recovery ->
per-task scanner mode) must coexist on one ``ReviewService`` after the
integration merge, each side behaving as it did before the merge.

14 methods / 4 classes: 13 expected RED at the C-Final baseline
(``e8c5366``) because the joint/agent capability is absent there -- the
failures are TypeError/KeyError raised at real product call points
(``enqueue_repository_scan(...)``, task-input key access, recorded scan
kwargs), never import/fixture/arrange errors.  T3 is the single GREEN
baseline row (investigation-side compatibility preservation).

Offline policy and proof scope (packet §9 declaration): the local tests
prove enqueue/snapshot/persistence/recovery/wiring composition plus
agent-off worker execution; agent-on real analysis, the real sidecar
protocol and the container faces are CI jobs and remain UNVERIFIED on
this machine.  Real external model calls are zero by construction:

- investigation chain: a transport-level fake replaces
  ``lima.reviewer.post_chat_completion_full`` BEFORE the service (and
  thus ``InvestigationLLMClient``, which binds the transport at
  construction) is built -- every layer above the transport is real
  production code, and the merge itself is never stubbed;
- agent chain: ``_llm_overrides()`` resolves llm_config through a
  custom provider pinned at http://127.0.0.1:9/v1 (construction-time
  resolution only, no request is ever sent) and ``cxx_memory_mode``
  makes the analyzer "configured" state without any sidecar call;
- worker real execution covers the agent-off state only (main
  ``test_worker_uses_snapshot_mode_not_shared_scanner_state``
  precedent); ``queue.submit`` is intercepted only for pure-enqueue
  assertions and ``repository_scanner.scan`` only as a wraps-spy (the
  execution still runs the real scanner).  merge/enqueue/worker/store
  and the core dispatch are never replaced with fixed success stubs and
  no scripted investigator is passed off as a service-chain one.

Sample independence (ruling condition C-3, option 2 -- brand-new package
names): ``smelter/`` (``pour_schedule.py``: unresolved-import call shape
for the Python investigation chain) and ``crucible/``
(``heat_treatment.cpp``/``heat_treatment.h``: C++-chain processable
files that enter the workspace scan boundary).  Both names are new --
distinct from every earlier round's samples (svc, payroll, ingest,
orchard, tannery, depot, greenhouse, harbor, observatory, kiln, foundry,
press, lumber, sawmill, aqueduct, parchment, windlass, ledger, vault,
fleet) at file, symbol and source-shape level.
"""

import inspect
import json
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lima.config import Settings
from lima.repository_investigation import FindingInvestigator
from lima.service import ReviewService

REPOSITORY_KEY = "team/project"
MODULE_PATH = "smelter/pour_schedule.py"
MODULE_FP = "module-scope:" + MODULE_PATH
DISCOVERY_WHY = (
    "book_heat is imported from an unresolved registry module and "
    "invoked on caller-controlled orders"
)

# Normalization fixture: strip whitespace, strip leading/trailing path
# separators, drop empty entries (the C-Final rule, kept verbatim).
RAW_PATHS = [" /smelter/pour_schedule.py/ ", "", "   "]
NORMALIZED_PATHS = ["smelter/pour_schedule.py"]

# Construction-time-only LLM resolution (main AgentDetectionEnqueueTests
# precedent): a complete custom-provider triple resolves llm_config
# without any network request (the host is never contacted).
LLM_OVERRIDES = {
    "llm_provider": "custom",
    "llm_base_url": "http://127.0.0.1:9/v1",
    "llm_api_key": "unit-test-key",
    "llm_model": "unit-test-model",
}

GITHUB_SOURCE = {"type": "github", "url": "https://github.com/team/project"}

# Dual-scope sample (packet §9 matrix row S): one repository containing
# a Python package the investigation chain can process and C++ files the
# agent chain could process -- not just signature-tolerating containers.
WORKSPACE_SAMPLE = {
    "smelter/__init__.py": "",
    "smelter/pour_schedule.py": (
        "from pour_registry import book_heat\n"
        "\n"
        "\n"
        "def schedule_heat(order):\n"
        "    return book_heat(order)\n"
    ),
    "crucible/heat_treatment.h": (
        "#pragma once\n"
        "\n"
        "namespace heat_treatment {\n"
        "\n"
        "struct HeatPlan {\n"
        "    int stage;\n"
        "    int target_celsius;\n"
        "};\n"
        "\n"
        "HeatPlan anneal(HeatPlan plan);\n"
        "\n"
        "}  // namespace heat_treatment\n"
    ),
    "crucible/heat_treatment.cpp": (
        '#include "heat_treatment.h"\n'
        "\n"
        "namespace heat_treatment {\n"
        "\n"
        "HeatPlan anneal(HeatPlan plan) {\n"
        "    plan.stage = 2;\n"
        "    plan.target_celsius = 720;\n"
        "    return plan;\n"
        "}\n"
        "\n"
        "}  // namespace heat_treatment\n"
    ),
}


def tool_action(tool, **arguments):
    return {"action": "tool", "tool": tool, "arguments": arguments,
            "reason": "missing evidence"}


def final(results, new_targets=None):
    return {"action": "final", "results": results,
            "new_targets": new_targets or []}


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
                    reasoning="pour registry binding unresolved in snapshot")],
            new_targets=[{
                "path": MODULE_PATH, "line": 5, "symbol": "schedule_heat",
                "why": DISCOVERY_WHY,
                "evidence_refs": [f"read_source:{MODULE_PATH}:1-6"],
            }],
        ),
    ]


class ScriptedInvestigationTransport:
    """Transport-level offline fake for the shared completions transport.

    No network I/O ever happens: real external model calls are zero by
    construction while the production client, the bounded tool loop and
    the merge layer keep running (cycle-I offline policy).
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


class _AgentModesTestCase(unittest.TestCase):
    """Shared fixture: dual-scope sample repo, base settings, helpers."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(suffix="-pr265d-int")
        self.addCleanup(self.temporary.cleanup)
        repository = Path(self.temporary.name, "team", "project")
        for rel, text in WORKSPACE_SAMPLE.items():
            path = repository / Path(rel)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        self.base = Settings(
            host="127.0.0.1", port=8080,
            db_path=str(Path(self.temporary.name) / "state.db"),
            max_diff_bytes=10000, max_steps=8, timeout_seconds=120,
            llm_base_url="", llm_api_key="", llm_model="",
            github_webhook_secret="", github_token="",
            auto_post_review=False,
            repository_import_root=self.temporary.name,
            repository_scan_sast_mode="off",
        )

    def _service(self, **overrides) -> ReviewService:
        service = ReviewService(replace(self.base, **overrides))
        self.addCleanup(service.queue.close)
        return service

    def _task_input(self, service: ReviewService, created: dict) -> dict:
        return service.store.get(created["task_id"])["input"]

    def _wait_terminal(self, service: ReviewService, task_id: str) -> dict:
        task = {}
        deadline = time.time() + 60
        while time.time() < deadline:
            task = service.store.get(task_id) or {}
            if task.get("state") in {"SUCCESS", "FAILED"}:
                break
            time.sleep(0.05)
        return task

    def _discovered(self, report_document):
        return [
            f for f in report_document["findings"]
            if f["rule_id"] == "AGENT-DISCOVERY"
        ]


class JointEnqueueSnapshotTests(_AgentModesTestCase):
    """T1-T4: joint enqueue persistence and unchanged agent rejections."""

    def test_three_state_by_paths_task_input_union(self):
        # Matrix M1-M6: one enqueue persists BOTH parameter groups in the
        # task input -- agent_detection + effective_cxx_agent_mode AND
        # investigation_mode + normalized investigate_paths.
        cells = [
            ("m1_none_empty", {"cxx_agent_mode": "auto",
                               "repository_investigation_mode": "auto"},
             None, [], "auto", []),
            ("m2_none_paths", {"cxx_agent_mode": "auto",
                               "repository_investigation_mode": "auto"},
             None, RAW_PATHS, "auto", NORMALIZED_PATHS),
            ("m3_true_empty", {"cxx_memory_mode": "auto", **LLM_OVERRIDES},
             True, [], "auto", []),
            ("m4_true_paths", {"cxx_memory_mode": "auto", **LLM_OVERRIDES},
             True, RAW_PATHS, "auto", NORMALIZED_PATHS),
            ("m5_false_empty", {"cxx_agent_mode": "auto"}, False, [],
             "off", []),
            ("m6_false_paths", {"cxx_agent_mode": "auto"}, False, RAW_PATHS,
             "off", NORMALIZED_PATHS),
        ]
        for name, overrides, agent, raw, mode, paths in cells:
            with self.subTest(cell=name):
                service = self._service(**overrides)
                with mock.patch.object(service.queue, "submit"):
                    created = service.enqueue_repository_scan(
                        REPOSITORY_KEY,
                        agent_detection=agent, investigate_paths=raw,
                    )
                task_input = self._task_input(service, created)
                self.assertEqual(agent, task_input["agent_detection"])
                self.assertEqual(mode, task_input["effective_cxx_agent_mode"])
                self.assertEqual(paths, task_input["investigate_paths"])
                self.assertEqual(
                    overrides.get("repository_investigation_mode", "off"),
                    task_input["investigation_mode"],
                )
                # A per-task switch never rewrites the shared scanner.
                self.assertEqual(
                    overrides.get("cxx_agent_mode", "off"),
                    service.repository_scanner.cxx_agent_mode,
                )

    def test_queue_message_carries_both_groups(self):
        # M4/T2: the queue message carries the resolved agent snapshot and
        # the normalized investigation paths at the same time (retry reuse).
        service = self._service(cxx_memory_mode="auto", **LLM_OVERRIDES)
        for agent, expected_mode in ((True, "auto"), (False, "off")):
            with self.subTest(agent_detection=agent):
                with mock.patch.object(service.queue, "submit") as submit:
                    created = service.enqueue_repository_scan(
                        REPOSITORY_KEY,
                        agent_detection=agent,
                        investigate_paths=[MODULE_PATH],
                    )
                message = submit.call_args.args[0]
                self.assertEqual(created["task_id"], message["task_id"])
                self.assertEqual(
                    expected_mode, message["effective_cxx_agent_mode"]
                )
                self.assertEqual(
                    [MODULE_PATH], message["investigate_paths"]
                )

    def test_investigate_paths_normalization_without_agent_param(self):
        # T3 -- the ONLY baseline GREEN row: the investigation-side
        # normalization/persistence faces keep their exact C-Final
        # behavior when no agent parameter is passed, so the integration
        # cannot silently change the delivered investigation chain.
        service = self._service(repository_investigation_mode="auto")
        with mock.patch.object(service.queue, "submit") as submit:
            created = service.enqueue_repository_scan(
                REPOSITORY_KEY, investigate_paths=RAW_PATHS,
            )
        self.assertEqual("PENDING", created["state"])
        task_input = self._task_input(service, created)
        self.assertEqual("auto", task_input["investigation_mode"])
        self.assertEqual(NORMALIZED_PATHS, task_input["investigate_paths"])
        message = submit.call_args.args[0]
        self.assertEqual(NORMALIZED_PATHS, message["investigate_paths"])

    def test_agent_rejections_unchanged_with_paths_present(self):
        # IC-2: the three named rejection codes plus the non-bool
        # ValueError keep their main semantics verbatim; investigation
        # paths being present never changes an agent-side rejection.
        paths = [MODULE_PATH]
        typed = self._service()
        with self.assertRaises(ValueError) as ctx:
            typed.enqueue_repository_scan(
                REPOSITORY_KEY, agent_detection=1, investigate_paths=paths,
            )
        self.assertIn("agent_detection must be a boolean", str(ctx.exception))

        from lima.service import AgentDetectionRequestError  # main contract

        unconfigured = self._service(cxx_memory_mode="auto")
        with self.assertRaises(AgentDetectionRequestError) as ctx:
            unconfigured.enqueue_repository_scan(
                REPOSITORY_KEY, agent_detection=True, investigate_paths=paths,
            )
        self.assertEqual("agent-detection-unavailable", ctx.exception.code)

        without_analyzer = self._service(cxx_memory_mode="off", **LLM_OVERRIDES)
        with self.assertRaises(AgentDetectionRequestError) as ctx:
            without_analyzer.enqueue_repository_scan(
                REPOSITORY_KEY, agent_detection=True, investigate_paths=paths,
            )
        self.assertEqual(
            "agent-detection-analyzer-unavailable", ctx.exception.code
        )

        required = self._service(
            cxx_agent_mode="required",
            cxx_agent_model="unit-test-model",
            cxx_memory_mode="auto",
        )
        with self.assertRaises(AgentDetectionRequestError) as ctx:
            required.enqueue_repository_scan(
                REPOSITORY_KEY, agent_detection=False, investigate_paths=paths,
            )
        self.assertEqual("agent-detection-required", ctx.exception.code)


class IndependentToggleTests(_AgentModesTestCase):
    """T5-T7: each side switches without consuming the other side."""

    def test_agent_off_keeps_investigation_params(self):
        # IC-6/M6: agent_detection=False disables only this task's agent
        # mode; the investigation parameters persist untouched and the
        # investigation wiring stays assembled.
        service = self._service(
            cxx_agent_mode="auto",
            repository_investigation_mode="auto",
            **LLM_OVERRIDES,
        )
        with mock.patch.object(service.queue, "submit"):
            created = service.enqueue_repository_scan(
                REPOSITORY_KEY,
                agent_detection=False, investigate_paths=RAW_PATHS,
            )
        task_input = self._task_input(service, created)
        self.assertFalse(task_input["agent_detection"])
        self.assertEqual("off", task_input["effective_cxx_agent_mode"])
        self.assertEqual("auto", task_input["investigation_mode"])
        self.assertEqual(NORMALIZED_PATHS, task_input["investigate_paths"])
        self.assertIsInstance(
            service.repository_investigation, FindingInvestigator
        )
        self.assertEqual("auto", service.repository_scanner.cxx_agent_mode)

    def test_investigation_off_leaves_agent_chain_untouched(self):
        # IC-6: repository_investigation_mode=off skips the investigation
        # block entirely while the agent chain still snapshots its own
        # group from the server default.
        service = self._service(
            cxx_agent_mode="auto",
            repository_investigation_mode="off",
            **LLM_OVERRIDES,
        )
        with mock.patch.object(service.queue, "submit"):
            created = service.enqueue_repository_scan(
                REPOSITORY_KEY,
                agent_detection=None, investigate_paths=[MODULE_PATH],
            )
        task_input = self._task_input(service, created)
        self.assertIsNone(task_input["agent_detection"])
        self.assertEqual("auto", task_input["effective_cxx_agent_mode"])
        self.assertEqual("off", task_input["investigation_mode"])
        self.assertEqual([MODULE_PATH], task_input["investigate_paths"])
        self.assertIsNone(service.repository_investigation)
        self.assertEqual("auto", service.repository_scanner.cxx_agent_mode)

    def test_agent_snapshot_immune_to_post_enqueue_config_drift(self):
        # IC-3/IC-7: the effective mode is resolved once at enqueue; after
        # the global setting drifts to "required", the worker still runs
        # the snapshotted "off" mode and the investigation block still
        # consumes its paths.
        transport = ScriptedInvestigationTransport(candidate_script())
        with mock.patch(
            "lima.reviewer.post_chat_completion_full", new=transport,
        ):
            service = self._service(
                cxx_agent_mode="auto",
                repository_investigation_mode="auto",
                **LLM_OVERRIDES,
            )
            with mock.patch.object(
                service.repository_scanner, "scan",
                wraps=service.repository_scanner.scan,
            ) as scan:
                with mock.patch.object(service.queue, "submit") as submit:
                    created = service.enqueue_repository_scan(
                        REPOSITORY_KEY,
                        agent_detection=False,
                        investigate_paths=[MODULE_PATH],
                    )
                message = submit.call_args.args[0]
                self.assertEqual(
                    "off", message["effective_cxx_agent_mode"]
                )
                service.settings = replace(
                    service.settings,
                    cxx_agent_mode="required",
                    cxx_agent_model="unit-test-model",
                    cxx_memory_mode="auto",
                )
                service._process_queued(message)
                task = service.store.get(created["task_id"]) or {}
        self.assertEqual("SUCCESS", task.get("state"), task.get("error"))
        self.assertEqual("off", scan.call_args.kwargs["cxx_agent_mode"])
        self.assertEqual("auto", service.repository_scanner.cxx_agent_mode)
        discovered = self._discovered(task["report"])
        self.assertEqual(1, len(discovered))
        self.assertEqual(MODULE_PATH, discovered[0]["path"])
        self.assertEqual(5, discovered[0]["line"])


class JointWorkerExecutionTests(_AgentModesTestCase):
    """T8-T11: real worker execution composes both chains (agent-off)."""

    def _run_worker_scan(self, overrides, script, **enqueue_kwargs):
        """Real service + queue worker + investigator; fake transport."""
        transport = ScriptedInvestigationTransport(script)
        with mock.patch(
            "lima.reviewer.post_chat_completion_full", new=transport,
        ):
            service = self._service(**overrides)
            with mock.patch.object(
                service.repository_scanner, "scan",
                wraps=service.repository_scanner.scan,
            ) as scan:
                created = service.enqueue_repository_scan(
                    REPOSITORY_KEY, **enqueue_kwargs
                )
                task = self._wait_terminal(service, created["task_id"])
        self.assertEqual("SUCCESS", task.get("state"), task.get("error"))
        return task, scan, transport, service

    def test_joint_task_worker_composes_both_chains(self):
        # IC-7/S: one joint task on the dual-scope sample -- the scanner
        # receives the snapshotted "off" mode while the investigation
        # block consumes the paths and materializes the module candidate
        # with the cycle-I merge semantics.
        task, scan, transport, service = self._run_worker_scan(
            {"cxx_agent_mode": "auto",
             "repository_investigation_mode": "auto", **LLM_OVERRIDES},
            candidate_script(),
            agent_detection=False, investigate_paths=RAW_PATHS,
        )
        self.assertEqual("off", scan.call_args.kwargs["cxx_agent_mode"])
        self.assertEqual("auto", service.repository_scanner.cxx_agent_mode)
        report = task["report"]
        discovered = self._discovered(report)
        self.assertEqual(1, len(discovered))
        self.assertEqual("candidate", discovered[0]["verification_state"])
        self.assertEqual(MODULE_PATH, discovered[0]["path"])
        self.assertEqual(5, discovered[0]["line"])
        decisions = {
            d["fingerprint"]: d for d in report["adjudication"]["decisions"]
        }
        self.assertEqual(
            "unverified-finding-requires-human-review",
            decisions[discovered[0]["fingerprint"]]["reason"],
        )
        self.assertEqual("needs_review", report["adjudication"]["overall_disposition"])
        self.assertEqual(2, report["adjudication"]["counts"]["needs_review"])
        self.assertEqual("high", report["risk"])
        block = report["collaboration"]["investigation"]
        self.assertGreaterEqual(len(transport.calls), 2)
        self.assertEqual(len(transport.calls), block["usage"]["requests"])
        self.assertFalse(block["secret_persisted"])

    def test_recovery_from_persisted_task_input(self):
        # IC-5/R1: a queue payload carrying only task_id/task_type/
        # tenant_id recovers BOTH parameter groups from the persisted
        # task input (message-first -> input fallback for each group).
        transport = ScriptedInvestigationTransport(candidate_script())
        with mock.patch(
            "lima.reviewer.post_chat_completion_full", new=transport,
        ):
            service = self._service(
                cxx_agent_mode="auto",
                repository_investigation_mode="auto",
                **LLM_OVERRIDES,
            )
            with mock.patch.object(
                service.repository_scanner, "scan",
                wraps=service.repository_scanner.scan,
            ) as scan:
                with mock.patch.object(service.queue, "submit"):
                    created = service.enqueue_repository_scan(
                        REPOSITORY_KEY,
                        agent_detection=False,
                        investigate_paths=[MODULE_PATH],
                    )
                persisted = self._task_input(service, created)
                self.assertEqual(
                    "off", persisted["effective_cxx_agent_mode"]
                )
                self.assertEqual(
                    [MODULE_PATH], persisted["investigate_paths"]
                )
                service._process_queued({
                    "task_id": created["task_id"],
                    "task_type": "repository_scan",
                    "tenant_id": "default",
                })
                task = service.store.get(created["task_id"]) or {}
        self.assertEqual("SUCCESS", task.get("state"), task.get("error"))
        self.assertEqual("off", scan.call_args.kwargs["cxx_agent_mode"])
        self.assertEqual(1, len(self._discovered(task["report"])))

    def test_python_zero_static_module_only_discovery(self):
        # R2: a module with zero static findings, requested module-only,
        # still goes through build_module_targets into the investigation
        # and materializes its AGENT-DISCOVERY candidate (cycle-I CA-4
        # semantics): static total stays zero.
        task, _, _, _ = self._run_worker_scan(
            {"repository_investigation_mode": "auto", **LLM_OVERRIDES},
            candidate_script(),
            agent_detection=None, investigate_paths=RAW_PATHS,
        )
        report = task["report"]
        rule_ids = {f["rule_id"] for f in report["findings"]}
        self.assertEqual({"AGENT-DISCOVERY"}, rule_ids)
        discovered = self._discovered(report)
        self.assertEqual(1, len(discovered))
        self.assertEqual("candidate", discovered[0]["verification_state"])
        self.assertEqual(MODULE_PATH, discovered[0]["path"])
        self.assertEqual(5, discovered[0]["line"])
        self.assertEqual("needs_review", report["adjudication"]["overall_disposition"])

    def test_cxx_agent_off_execution_path(self):
        # R3 (main-equivalent, agent-off real execution): the task
        # succeeds, the scanner receives the snapshotted mode through the
        # per-task cxx_agent_mode argument and the shared scanner state
        # is untouched; with investigation off the whole task needs no
        # LLM at all (independence in the other direction).
        service = self._service(repository_investigation_mode="off")
        with mock.patch.object(
            service.repository_scanner, "scan",
            wraps=service.repository_scanner.scan,
        ) as scan:
            created = service.enqueue_repository_scan(
                REPOSITORY_KEY, investigate_paths=[MODULE_PATH],
            )
            task = self._wait_terminal(service, created["task_id"])
        self.assertEqual("SUCCESS", task.get("state"), task.get("error"))
        self.assertEqual("off", scan.call_args.kwargs["cxx_agent_mode"])
        self.assertEqual("off", service.repository_scanner.cxx_agent_mode)
        report = task["report"]
        self.assertEqual([], report["findings"])
        self.assertNotIn("investigation", report["collaboration"])
        task_input = self._task_input(service, created)
        self.assertEqual("off", task_input["investigation_mode"])
        self.assertEqual([MODULE_PATH], task_input["investigate_paths"])


class UpstreamCompatSurfaceTests(_AgentModesTestCase):
    """T12-T14: main-side API/capability surfaces survive the merge."""

    def test_github_source_agent_snapshot_no_investigation_surface(self):
        # IC-9: the source path snapshots the same agent switch and
        # message, while the source surface never exposes
        # investigate_paths (the exact union of both delivered states).
        service = self._service(
            repository_scan_sources="both",
            cxx_memory_mode="auto",
            **LLM_OVERRIDES,
        )
        with mock.patch.object(service.queue, "submit") as submit:
            created = service.enqueue_repository_scan_source(
                GITHUB_SOURCE, agent_detection=True,
            )
        task_input = self._task_input(service, created)
        self.assertTrue(task_input["agent_detection"])
        self.assertEqual("auto", task_input["effective_cxx_agent_mode"])
        message = submit.call_args.args[0]
        self.assertEqual("auto", message["effective_cxx_agent_mode"])
        params = inspect.signature(
            ReviewService.enqueue_repository_scan_source
        ).parameters
        self.assertNotIn("investigate_paths", params)
        with self.assertRaises(TypeError):
            service.enqueue_repository_scan_source(
                GITHUB_SOURCE, investigate_paths=[MODULE_PATH],
            )

    def test_api_positional_third_arg_contract(self):
        # IC-8/IC-1: main api.py passes agent_detection as the THIRD
        # positional argument; the merged signature must keep binding it
        # there, with investigate_paths in the fourth slot.
        service = self._service(
            cxx_memory_mode="auto",
            repository_investigation_mode="auto",
            **LLM_OVERRIDES,
        )
        with mock.patch.object(service.queue, "submit"):
            created = service.enqueue_repository_scan(
                REPOSITORY_KEY, "default", True,
                ["/smelter/pour_schedule.py/"],
            )
        task_input = self._task_input(service, created)
        self.assertTrue(task_input["agent_detection"])
        # server default off upgraded to auto for this task only
        self.assertEqual("auto", task_input["effective_cxx_agent_mode"])
        self.assertEqual("auto", task_input["investigation_mode"])
        self.assertEqual(NORMALIZED_PATHS, task_input["investigate_paths"])

    def test_capabilities_shape_unchanged(self):
        # IC-8: the cxx_agent capabilities object keeps the main
        # per-request contract fields the frontend consumes.
        service = self._service(
            cxx_agent_mode="auto", cxx_memory_mode="auto", **LLM_OVERRIDES,
        )
        cxx = service.repository_scan_capabilities()["cxx_agent"]
        self.assertTrue(cxx["per_request_switch"])
        self.assertTrue(cxx["llm_configured"])
        self.assertTrue(cxx["analyzer_configured"])
        self.assertEqual(
            service.settings.cxx_agent_max_calls, cxx["max_agent_calls"]
        )

        required = self._service(
            cxx_agent_mode="required",
            cxx_agent_model="unit-test-model",
            cxx_memory_mode="auto",
        )
        self.assertFalse(
            required.repository_scan_capabilities()["cxx_agent"][
                "per_request_switch"
            ]
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
