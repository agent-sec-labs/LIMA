"""Production adapters for the model-selected C/C++ investigation loop."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


from lima.agent_orchestrator import run_platform_review
from lima.agent_repro_tools import ExperimentObservation
from lima.agent_scout import ScoutLead, ScoutReport, ScoutTarget
from lima.config import Settings
from lima.cxx_agent_tools import AgentBudgetExceeded, CxxAgentBudget
from lima.runtime import AgentLoopProtocolError
from lima.repository_scanner import RepositoryScanner
from lima.workspace import RepositoryWorkspace


LEAD = ScoutLead("lead-a", "src/a.cpp", 2, "lifetime issue", "test")
TARGET = ScoutTarget("lead-a", "src/a.cpp", 2, "inspect lifetime", "high")
HYPOTHESIS = {
    "target_id": "lead-a", "hypothesis": "released object is reused",
    "trigger_path": ["src/a.cpp:2"], "cwe": "CWE-416",
    "driver_code": "int main() { return 0; }",
    "experiment_design": "exercise public entry", "unresolved_assumptions": [],
}


def review(workspace, **kwargs):
    report = ScoutReport((TARGET,), (), (), 0, lead_ids=frozenset({"lead-a"}))
    with patch("lima.agent_orchestrator.review_leads", return_value=report):
        return run_platform_review(
            None, workspace, repository_key="team/repo", snapshot_hash="a" * 64,
            translation_units=("src/a.cpp",), leads=(LEAD,),
            llm_config={"provider": "local"}, **kwargs,
        )


def completed_engine(result):
    def run(**kwargs):
        if result.critic is not None:
            kwargs["send"]("critic", "observed evidence", "critic")
        return result
    return run


class InvestigationIntegrationTests(unittest.TestCase):
    def test_auto_partial_investigation_requires_review_for_each_failure_status(self):
        observation = ExperimentObservation(
            False, "run", 1, "heap-use-after-free", 2, 1, 1, (), "ASan hit",
            faulting_file="src/a.cpp",
        )
        for stop in ("protocol-error", "error", "budget-exhausted", "incomplete"):
            with self.subTest(stop=stop):
                result = SimpleNamespace(
                    hypothesis=HYPOTHESIS,
                    experiments=[{
                        "driver_code": HYPOTHESIS["driver_code"],
                        "source_files": ("src/a.cpp",), "observation": observation,
                        "hypothesis": HYPOTHESIS,
                    }],
                    critic=None,
                    trace={"stop_reason": stop},
                )
                with patch("lima.cxx_scout_exploration.explore_leads", return_value=(
                    (), {"stop_reason": "final", "actions": []},
                )), patch("lima.cxx_investigator.run_investigation", return_value=result):
                    outcome = review(
                        self.workspace, mode="auto", investigation_strategy="investigator",
                    )
                finding = outcome.targets[0]
                self.assertEqual("needs-human-review", finding.state)
                self.assertEqual(stop, finding.investigation["stop_reason"])
                self.assertEqual(1, len(finding.experiment_log))
                self.assertTrue(finding.evidence_records)

    def test_forged_specialist_final_after_runtime_hit_respects_agent_mode(self):
        class Workbench:
            def run_experiment(self, *args, **kwargs):
                return ExperimentObservation(
                    False, "run", 1, "heap-use-after-free", 2, 1, 1, (), "ASan hit",
                    faulting_file="src/a.cpp",
                )

        for mode in ("auto", "required"):
            with self.subTest(mode=mode):
                actions = iter([
                    {"action": "tool", "tool": "record_hypothesis", "purpose": "propose",
                     "arguments": {"hypothesis": HYPOTHESIS, "trigger_path": "src/a.cpp",
                                   "cwe": "CWE-416", "driver_code": HYPOTHESIS["driver_code"],
                                   "experiment_design": "call", "unresolved_assumptions": []}},
                    {"action": "tool", "tool": "run_reproduction", "purpose": "test",
                     "arguments": {"source_files": ["src/a.cpp"],
                                   "driver_code": HYPOTHESIS["driver_code"]}},
                    {"action": "final", "hypothesis_id": "h1", "evidence_ids": ["forged"],
                     "unresolved_questions": []},
                ])
                with patch("lima.cxx_scout_exploration.explore_leads", return_value=(
                    (), {"stop_reason": "final", "actions": []},
                )), patch("lima.agent_orchestrator.send_semantic_request",
                          side_effect=lambda *args: json.dumps(next(actions))):
                    if mode == "required":
                        with self.assertRaisesRegex(RuntimeError, "protocol-error"):
                            review(self.workspace, mode=mode, investigation_strategy="investigator",
                                   repro_workbench=Workbench())
                    else:
                        outcome = review(
                            self.workspace, mode=mode, investigation_strategy="investigator",
                            repro_workbench=Workbench(),
                        )
                        finding = outcome.targets[0]
                        self.assertEqual("needs-human-review", finding.state)
                        self.assertEqual("protocol-error", finding.investigation["stop_reason"])
                        self.assertIsNone(finding.investigation["critic"])
                        self.assertEqual(1, len(finding.experiment_log))
                        self.assertTrue(finding.evidence_records)

    def test_required_mode_rejects_failed_critic_after_runtime_hit(self):
        class Workbench:
            def run_experiment(self, *args, **kwargs):
                return ExperimentObservation(
                    False, "run", 1, "heap-use-after-free", 2, 1, 1, (), "ASan hit",
                    faulting_file="src/a.cpp",
                )

        for error in (AgentBudgetExceeded("critic exhausted"),
                      AgentLoopProtocolError("invalid critic"),
                      ValueError("provider unavailable")):
            with self.subTest(error=type(error).__name__):
                actions = iter([
                    {"action": "tool", "tool": "record_hypothesis", "purpose": "propose",
                     "arguments": {"hypothesis": HYPOTHESIS, "trigger_path": "src/a.cpp",
                                   "cwe": "CWE-416", "driver_code": HYPOTHESIS["driver_code"],
                                   "experiment_design": "call", "unresolved_assumptions": []}},
                    {"action": "tool", "tool": "run_reproduction", "purpose": "test",
                     "arguments": {"source_files": ["src/a.cpp"],
                                   "driver_code": HYPOTHESIS["driver_code"]}},
                    {"action": "final", "hypothesis_id": "h1", "evidence_ids": ["e2"],
                     "unresolved_questions": []},
                ])

                def send(config, system, user, timeout, budget):
                    if "You are the critic." in system:
                        raise error
                    context = json.loads(user)["target"]
                    self.assertEqual(TARGET.path, context["path"])
                    self.assertEqual(TARGET.line, context["line"])
                    self.assertEqual(TARGET.reason, context["reason"])
                    return json.dumps(next(actions))

                with patch("lima.cxx_scout_exploration.explore_leads", return_value=(
                    (), {"stop_reason": "final", "actions": []},
                )), patch("lima.agent_orchestrator.send_semantic_request", side_effect=send):
                    with self.assertRaisesRegex(RuntimeError, "required investigation failed"):
                        review(self.workspace, mode="required", investigation_strategy="investigator",
                               repro_workbench=Workbench())

    def test_cancelled_critic_preserves_trace_and_abstains(self):
        result = SimpleNamespace(
            hypothesis=HYPOTHESIS, experiments=[], critic=None,
            trace={"stop_reason": "cancelled", "critic_error": "critic cancelled"},
        )
        with patch("lima.cxx_scout_exploration.explore_leads", return_value=(
            (), {"stop_reason": "final", "actions": []},
        )), patch("lima.cxx_investigator.run_investigation", return_value=result), patch(
            "lima.agent_orchestrator._adjudicate_target",
            side_effect=AssertionError("cancelled investigation reached adjudication"),
        ):
            outcome = review(self.workspace, mode="required", investigation_strategy="investigator")
        self.assertEqual("abstain", outcome.targets[0].state)
        self.assertEqual("cancelled", outcome.targets[0].rejected_reason)
        self.assertEqual("critic cancelled", outcome.targets[0].investigation["critic_error"])

    def test_auto_critic_failure_keeps_runtime_evidence_for_review(self):
        observation = ExperimentObservation(
            False, "run", 1, "heap-use-after-free", 2, 1, 1, (), "ASan hit",
            faulting_file="src/a.cpp",
        )
        result = SimpleNamespace(
            hypothesis=HYPOTHESIS,
            experiments=[{
                "driver_code": HYPOTHESIS["driver_code"], "source_files": ("src/a.cpp",),
                "observation": observation, "hypothesis": HYPOTHESIS,
            }],
            critic=None,
            trace={"stop_reason": "error", "critic_error": "provider unavailable"},
        )
        with patch("lima.cxx_scout_exploration.explore_leads", return_value=(
            (), {"stop_reason": "final", "actions": []},
        )), patch("lima.cxx_investigator.run_investigation", return_value=result):
            outcome = review(self.workspace, mode="auto", investigation_strategy="investigator")
        finding = outcome.targets[0]
        self.assertEqual("needs-human-review", finding.state)
        self.assertEqual(1, len(finding.experiment_log))
        self.assertTrue(finding.evidence_records)
        self.assertEqual("provider unavailable", finding.investigation["critic_error"])

    def test_cancelled_exploration_does_not_start_fallback_discovery(self):
        checks = iter((False, True))
        with patch("lima.agent_orchestrator.send_semantic_request") as send:
            outcome = run_platform_review(
                None, self.workspace, repository_key="team/repo", snapshot_hash="a" * 64,
                translation_units=("src/a.cpp",), llm_config={"provider": "local"},
                investigation_strategy="investigator", should_cancel=lambda: next(checks, True),
            )
        self.assertEqual("cancelled", outcome.scout_exploration["stop_reason"])
        self.assertEqual(("src/a.cpp",), outcome.unreviewed_units)
        self.assertEqual((), outcome.targets)
        send.assert_not_called()

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "src").mkdir()
        (root / "src/a.cpp").write_text("void f() {\n int x = 1;\n}\n")
        self.workspace = RepositoryWorkspace(root)

    def test_strategy_off_makes_no_calls(self):
        budget = CxxAgentBudget()
        result = review(self.workspace, mode="off", investigation_strategy="team", budget=budget)
        assert result.targets == ()
        assert budget.remaining().calls == 40


    def test_unknown_strategy_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "strategy"):
            review(self.workspace, investigation_strategy="unknown")


    def test_settings_load_strategy_and_controls(self):
        with patch.dict(os.environ, {
            "LIMA_CXX_INVESTIGATION_STRATEGY": "team",
            "LIMA_CXX_INVESTIGATION_MAX_STEPS": "18",
            "LIMA_CXX_INVESTIGATION_MAX_CHILDREN": "2",
        }), patch("lima.config.load_dotenv"):
            settings = Settings.from_env()
        assert settings.cxx_investigation_strategy == "team"
        assert settings.cxx_investigation_max_steps == 18
        assert settings.cxx_investigation_max_children == 2


    def test_scanner_passes_strategy_controls(self):
        scanner = RepositoryScanner(
            cxx_investigation_strategy="team", cxx_investigation_max_steps=17,
            cxx_investigation_max_children=1,
        )
        assert scanner.cxx_investigation_strategy == "team"
        assert scanner.cxx_investigation_max_steps == 17


    def test_new_strategy_keeps_executed_runtime_evidence(self):
        observation = ExperimentObservation(
            False, "run", 1, "heap-use-after-free", 2, 1, 1, (), "ASan hit",
            faulting_file="src/a.cpp",
        )
        result = SimpleNamespace(
            hypothesis=HYPOTHESIS,
            experiments=[{"driver_code": HYPOTHESIS["driver_code"],
                          "source_files": ("src/a.cpp",), "observation": observation,
                          "hypothesis": HYPOTHESIS}],
            critic={"assessment": "supports", "rationale": "observed", "evidence_ids": ["e1"]},
            trace={"strategy": "investigator", "stop_reason": "final", "actions": []},
        )
        with patch("lima.agent_orchestrator.send_semantic_request", return_value="{}"), patch(
            "lima.cxx_investigator.run_investigation", side_effect=completed_engine(result),
        ):
            outcome = review(self.workspace, investigation_strategy="investigator")
        assert outcome.targets[0].state == "runtime-confirmed"
        assert outcome.targets[0].investigation["stop_reason"] == "final"
        assert outcome.stats.experiment_count == 1


    def test_runtime_hit_with_critic_refutation_requires_review(self):
        observation = ExperimentObservation(
            False, "run", 1, "heap-use-after-free", 2, 1, 1, (), "ASan hit",
            faulting_file="src/a.cpp",
        )
        result = SimpleNamespace(
            hypothesis=HYPOTHESIS,
            experiments=[{"driver_code": HYPOTHESIS["driver_code"],
                          "source_files": ("src/a.cpp",), "observation": observation,
                          "hypothesis": HYPOTHESIS}],
            critic={"assessment": "refutes", "rationale": "API precondition violated"},
            trace={"strategy": "team", "stop_reason": "final", "actions": []},
        )
        with patch("lima.agent_orchestrator.send_semantic_request", return_value="{}"), patch(
            "lima.cxx_investigator.run_investigation", side_effect=completed_engine(result),
        ):
            outcome = review(self.workspace, investigation_strategy="team")
        assert outcome.targets[0].state == "needs-human-review"


    def test_trace_survives_no_hypothesis(self):
        result = SimpleNamespace(
            hypothesis=None, experiments=[], critic=None,
            trace={"stop_reason": "steps-exhausted", "actions": [{"tool": "read_source"}]},
        )
        with patch("lima.cxx_investigator.run_investigation", return_value=result):
            outcome = review(self.workspace, investigation_strategy="investigator")
        assert outcome.targets[0].state == "abstain"
        assert outcome.targets[0].investigation["actions"]
        json.dumps(RepositoryScanner()._platform_collaboration("auto", "completed", outcome))
