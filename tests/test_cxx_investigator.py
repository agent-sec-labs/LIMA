"""Focused contract tests for the bounded C++ investigation engine."""

from __future__ import annotations

import hashlib
import json
import unittest
import tempfile
from pathlib import Path


from lima.agent_repro_tools import ExperimentObservation
from lima.cxx_agent_tools import AgentBudgetExceeded, CxxAgentBudget
from lima.cxx_investigator import run_investigation
from lima.runtime import AgentLoopProtocolError, RuntimeBudgetExceeded, RuntimeCancelled
from lima.workspace import RepositoryWorkspace


def _hypothesis(driver: str = "int main() { return 0; }") -> dict:
    return {
        "target_id": "target-1",
        "hypothesis": "a controlled use is unsafe",
        "trigger_path": ["src/a.cpp"],
        "cwe": "CWE-476",
        "driver_code": driver,
        "experiment_design": "call the target",
        "unresolved_assumptions": [],
    }


class _Workbench:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def run_experiment(self, repository_key, snapshot_hash, source_files, driver_code, **kwargs):
        self.calls.append((repository_key, snapshot_hash, source_files, driver_code, kwargs))
        return ExperimentObservation(False, "run", 1, "SEGV", 4, None, None, (), "")


def _run(workspace, replies, **kwargs):
    iterator = iter(replies)
    return run_investigation(
        target={"target_id": "target-1", "path": "src/a.cpp"},
        workspace=workspace,
        repository_key="org/repo",
        snapshot_hash="a" * 64,
        budget=CxxAgentBudget(
            max_calls=20, max_context_files=10, max_context_lines=500, max_output_bytes=100_000
        ),
        send=lambda system, user, role: next(iterator),
        **kwargs,
    )


class CxxInvestigatorTests(unittest.TestCase):
    def test_critic_receives_actual_reproduction_driver_sources_and_hypothesis(self):
        (self.workspace.root / "src/helper.cpp").write_text(
            "int helper() { return 1; }\n", encoding="utf-8",
        )
        declared_driver = "int main() { return 0; }"
        executed_driver = "int main() { /* revised API sequence */ return 1; }"
        sources = ["src/a.cpp", "src/helper.cpp"]
        replies = iter([
            {"action": "tool", "tool": "record_hypothesis", "purpose": "propose",
             "arguments": {"hypothesis": _hypothesis(declared_driver),
                           "trigger_path": "src/a.cpp", "cwe": "CWE-476",
                           "driver_code": declared_driver, "experiment_design": "call",
                           "unresolved_assumptions": []}},
            {"action": "tool", "tool": "run_reproduction", "purpose": "test revised driver",
             "arguments": {"source_files": sources, "driver_code": executed_driver}},
            {"action": "final", "hypothesis_id": "h1", "evidence_ids": ["e2"],
             "unresolved_questions": []},
        ])
        critic_prompts = []

        def send(system, user, role):
            if role == "critic":
                critic_prompts.append(json.loads(user))
                return json.dumps({
                    "action": "final", "assessment": "insufficient",
                    "rationale": "inspect actual API sequence", "evidence_ids": ["e2"],
                    "unresolved_questions": [],
                })
            return json.dumps(next(replies))

        workbench = _Workbench()
        result = run_investigation(
            target={"target_id": "target-1", "path": "src/a.cpp"},
            workspace=self.workspace, repository_key="org/repo", snapshot_hash="a" * 64,
            budget=CxxAgentBudget(), send=send, workbench=workbench,
        )
        self.assertEqual(tuple(sources), workbench.calls[0][2])
        self.assertEqual(executed_driver, workbench.calls[0][3])
        evidence = critic_prompts[0]["evidence"]["e2"]["value"]
        self.assertEqual(executed_driver, evidence.get("driver_code"))
        self.assertEqual(sources, evidence["source_files"])
        self.assertEqual("h1", evidence["hypothesis_id"])
        self.assertEqual(declared_driver, evidence["hypothesis"]["driver_code"])
        self.assertEqual("target-1", evidence["hypothesis"]["target_id"])
        self.assertEqual(hashlib.sha256(executed_driver.encode()).hexdigest(),
                         evidence["driver_sha256"])
        self.assertEqual("run", evidence["stage"])
        self.assertEqual(evidence, result.trace["evidence"]["e2"]["value"])

    def test_child_search_charges_each_exposed_file_at_result_limit(self):
        (self.workspace.root / "src/b.cpp").write_text("int beta = 2;\n", encoding="utf-8")
        for file_cap in (1, 2):
            with self.subTest(file_cap=file_cap):
                budget = CxxAgentBudget(max_context_files=file_cap)
                parent_actions = iter([
                    {"action": "tool", "tool": "delegate_subtask", "purpose": "inspect",
                     "arguments": {"role": "ownership", "question": "inspect two files",
                                   "paths": ["src/a.cpp", "src/b.cpp"], "evidence_ids": []}},
                    {"action": "final", "hypothesis_id": "", "evidence_ids": [],
                     "unresolved_questions": []},
                ])
                child_actions = iter([
                    {"action": "tool", "tool": "search_code", "purpose": "inspect target",
                     "arguments": {"query": "target", "limit": 1}},
                    {"action": "tool", "tool": "search_code", "purpose": "inspect beta",
                     "arguments": {"query": "beta", "limit": 1}},
                    {"action": "final", "summary": "inspected two files",
                     "evidence_ids": ["e1", "e2"], "unresolved_questions": []},
                ])

                def send(system, user, role):
                    if role == "ownership":
                        return json.dumps(next(child_actions))
                    if role == "critic":
                        return json.dumps({
                            "action": "final", "assessment": "insufficient", "rationale": "none",
                            "evidence_ids": [], "unresolved_questions": [],
                        })
                    return json.dumps(next(parent_actions))

                result = run_investigation(
                    target={"target_id": "target-1", "path": "src/a.cpp"},
                    workspace=self.workspace, repository_key="org/repo", snapshot_hash="a" * 64,
                    budget=budget, send=send, strategy="team",
                )
                searches = [record for record in result.trace["evidence"].values()
                            if record["kind"] == "child_search_code"]
                self.assertEqual(file_cap, budget.usage_snapshot()["used_files"])
                self.assertEqual(file_cap, len(searches))
                if file_cap == 1:
                    self.assertEqual("budget-exhausted", result.trace["stop_reason"])
                    self.assertEqual("src/a.cpp", searches[0]["value"]["hits"][0]["path"])
                else:
                    self.assertEqual("final", result.trace["stop_reason"])

    def test_scout_target_context_reaches_model(self):
        prompts = []

        def send(system, user, role):
            prompts.append(json.loads(user))
            return json.dumps({
                "action": "final", "hypothesis_id": "", "evidence_ids": [],
                "unresolved_questions": [],
            })

        run_investigation(
            target={"target_id": "target-1", "path": "src/a.cpp", "line": 1,
                    "reason": "inspect target ownership", "confidence": "high"},
            workspace=self.workspace, repository_key="org/repo", snapshot_hash="a" * 64,
            budget=CxxAgentBudget(), send=send,
        )
        self.assertEqual({
            "target_id": "target-1", "path": "src/a.cpp", "line": 1,
            "reason": "inspect target ownership", "confidence": "high",
        }, prompts[0].get("target"))

    def test_critic_failure_sets_investigation_stop_reason(self):
        cases = (
            (AgentBudgetExceeded("exhausted"), "budget-exhausted"),
            (RuntimeBudgetExceeded("deadline"), "budget-exhausted"),
            (RuntimeCancelled("cancelled"), "cancelled"),
            (AgentLoopProtocolError("invalid reply"), "protocol-error"),
            (ValueError("provider unavailable"), "error"),
        )
        for error, expected in cases:
            with self.subTest(error=type(error).__name__):
                def send(system, user, role):
                    if role == "critic":
                        raise error
                    return json.dumps({
                        "action": "final", "hypothesis_id": "", "evidence_ids": [],
                        "unresolved_questions": [],
                    })

                result = run_investigation(
                    target={"target_id": "target-1", "path": "src/a.cpp"},
                    workspace=self.workspace, repository_key="org/repo", snapshot_hash="a" * 64,
                    budget=CxxAgentBudget(), send=send,
                )
                self.assertEqual(expected, result.trace["stop_reason"])
                self.assertIn(str(error), result.trace["critic_error"])

    def test_failed_child_consumes_delegation_slot_and_retains_actions(self):
        child_calls = []
        parent_prompts = []

        def send(system, user, role):
            if role == "ownership":
                child_calls.append(user)
                return json.dumps({
                    "action": "tool", "tool": "query_facts", "arguments": {},
                    "purpose": "inspect ownership facts",
                })
            parent_prompts.append(json.loads(user))
            return json.dumps({
                "action": "tool", "tool": "delegate_subtask", "purpose": "delegate",
                "arguments": {"role": "ownership", "question": "check ownership",
                              "paths": ["src/a.cpp"], "evidence_ids": []},
            })

        result = run_investigation(
            target={"target_id": "target-1", "path": "src/a.cpp"},
            workspace=self.workspace, repository_key="org/repo", snapshot_hash="a" * 64,
            budget=CxxAgentBudget(), send=send, strategy="team", max_children=1, max_steps=6,
        )
        self.assertEqual(4, len(child_calls))
        self.assertEqual(1, len(result.trace["children"]))
        child = result.trace["children"][0]
        self.assertEqual("budget-exhausted", child["stop_reason"])
        self.assertEqual(4, len(child["actions"]))
        self.assertIn("child steps exhausted", child["error_kind"])
        self.assertTrue(any(
            "child delegation limit" in observation.get("error", "")
            for prompt in parent_prompts
            for observation in prompt.get("observations", [])
        ))

    def test_child_transport_failure_is_retained(self):
        def send(system, user, role):
            if role == "ownership":
                raise ValueError("child provider unavailable")
            return json.dumps({
                "action": "tool", "tool": "delegate_subtask", "purpose": "delegate",
                "arguments": {"role": "ownership", "question": "check ownership",
                              "paths": ["src/a.cpp"], "evidence_ids": []},
            })

        result = run_investigation(
            target={"target_id": "target-1", "path": "src/a.cpp"},
            workspace=self.workspace, repository_key="org/repo", snapshot_hash="a" * 64,
            budget=CxxAgentBudget(), send=send, strategy="team", max_children=1, max_steps=5,
        )
        self.assertEqual(1, len(result.trace["children"]))
        child = result.trace["children"][0]
        self.assertEqual("error", child["stop_reason"])
        self.assertIn("child provider unavailable", child["error_kind"])
        self.assertEqual([], child["actions"])

    def test_critic_step_exhaustion_is_not_reported_as_final(self):
        def send(system, user, role):
            if role == "critic":
                return json.dumps({
                    "action": "tool", "tool": "query_facts", "arguments": {},
                    "purpose": "inspect facts",
                })
            return json.dumps({
                "action": "final", "hypothesis_id": "", "evidence_ids": [],
                "unresolved_questions": [],
            })

        result = run_investigation(
            target={"target_id": "target-1", "path": "src/a.cpp"},
            workspace=self.workspace, repository_key="org/repo", snapshot_hash="a" * 64,
            budget=CxxAgentBudget(), send=send, max_steps=2,
        )
        self.assertEqual("budget-exhausted", result.trace["stop_reason"])
        self.assertEqual(2, len(result.trace["critic_actions"]))
        self.assertIn("critic-steps-exhausted", result.trace["critic_error"])

    def test_final_selects_requested_hypothesis_or_abstains(self):
        for selected in ("h1", ""):
            with self.subTest(selected=selected):
                replies = []
                for claim in ("first claim", "second claim"):
                    hypothesis = {**_hypothesis(), "hypothesis": claim}
                    replies.append(json.dumps({
                        "action": "tool", "tool": "record_hypothesis", "purpose": "propose",
                        "arguments": {
                            "hypothesis": hypothesis, "trigger_path": "src/a.cpp",
                            "cwe": "CWE-476", "driver_code": hypothesis["driver_code"],
                            "experiment_design": "call", "unresolved_assumptions": [],
                        },
                    }))
                replies.extend([
                    json.dumps({"action": "final", "hypothesis_id": selected,
                                "evidence_ids": [], "unresolved_questions": []}),
                    json.dumps({"action": "final", "assessment": "insufficient",
                                "rationale": "no proof", "evidence_ids": [],
                                "unresolved_questions": []}),
                ])
                prompts = []
                iterator = iter(replies)

                def send(system, user, role):
                    prompts.append((role, json.loads(user)))
                    return next(iterator)

                result = run_investigation(
                    target={"target_id": "target-1", "path": "src/a.cpp"},
                    workspace=self.workspace, repository_key="org/repo", snapshot_hash="a" * 64,
                    budget=CxxAgentBudget(), send=send,
                )
                expected = "first claim" if selected else None
                actual = result.hypothesis["hypothesis"] if result.hypothesis else None
                self.assertEqual(expected, actual)
                critic_hypothesis = prompts[-1][1]["hypothesis"]
                self.assertEqual(json.loads(json.dumps(result.hypothesis)), critic_hypothesis)

    def test_tool_failure_is_visible_to_next_model_step(self):
        prompts = []
        replies = iter([
            json.dumps({"action": "tool", "tool": "read_source", "purpose": "inspect",
                        "arguments": {"path": "src/a.cpp", "start_line": 1, "end_line": 999}}),
            json.dumps({"action": "final", "hypothesis_id": "", "evidence_ids": [],
                        "unresolved_questions": []}),
            json.dumps({"action": "final", "assessment": "insufficient", "rationale": "none",
                        "evidence_ids": [], "unresolved_questions": []}),
        ])

        def send(system, user, role):
            prompts.append(json.loads(user))
            return next(replies)

        run_investigation(
            target={"target_id": "target-1", "path": "src/a.cpp"},
            workspace=self.workspace, repository_key="org/repo", snapshot_hash="a" * 64,
            budget=CxxAgentBudget(), send=send,
        )
        observations = prompts[1].get("observations", [])
        self.assertTrue(observations)
        self.assertFalse(observations[-1]["ok"])
        self.assertIn("invalid source line range", observations[-1]["error"])

    def test_repeated_successful_read_stops_before_step_budget(self):
        action = json.dumps({
            "action": "tool", "tool": "read_source", "purpose": "inspect",
            "arguments": {"path": "src/a.cpp", "start_line": 1, "end_line": 1},
        })
        result = run_investigation(
            target={"target_id": "target-1", "path": "src/a.cpp"},
            workspace=self.workspace, repository_key="org/repo", snapshot_hash="a" * 64,
            budget=CxxAgentBudget(), send=lambda *args: action, max_steps=8,
        )
        self.assertEqual("repeated identical action", result.trace["error_kind"])
        self.assertLess(len(result.trace["actions"]), 8)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "src").mkdir()
        (root / "src" / "a.cpp").write_text("int target() { return 0; }\n", encoding="utf-8")
        self.workspace = RepositoryWorkspace(root)

    def test_reproduction_binds_observation_to_recorded_hypothesis(self):
        wb = _Workbench()
        result = _run(
            self.workspace,
            [
                json.dumps(
                    {
                        "action": "tool",
                        "tool": "record_hypothesis",
                        "purpose": "propose",
                        "arguments": {
                            "hypothesis": _hypothesis(),
                            "trigger_path": "src/a.cpp",
                            "cwe": "CWE-476",
                            "driver_code": "int main() { return 0; }",
                            "experiment_design": "call",
                            "unresolved_assumptions": [],
                        },
                    }
                ),
                json.dumps(
                    {
                        "action": "tool",
                        "tool": "run_reproduction",
                        "purpose": "test",
                        "arguments": {
                            "source_files": ["src/a.cpp"],
                            "driver_code": "int main() { return 0; }",
                        },
                    }
                ),
                json.dumps(
                    {
                        "action": "final",
                        "hypothesis_id": "h1",
                        "evidence_ids": ["e2"],
                        "unresolved_questions": [],
                    }
                ),
                json.dumps(
                    {
                        "action": "final",
                        "assessment": "supports",
                        "rationale": "observed crash",
                        "evidence_ids": ["e2"],
                        "unresolved_questions": [],
                    }
                ),
            ],
            workbench=wb,
        )
        assert result.experiments[0]["hypothesis"]["target_id"] == "target-1"
        assert set(result.hypothesis) == {
            "target_id",
            "hypothesis",
            "trigger_path",
            "cwe",
            "driver_code",
            "experiment_design",
            "unresolved_assumptions",
        }
        assert "hypothesis_id" not in result.hypothesis
        assert wb.calls[0][0:2] == ("org/repo", "a" * 64)
        assert result.critic["assessment"] == "supports"


    def test_foreign_source_and_forged_final_evidence_fail_safe(self):
        result = _run(
            self.workspace,
            [
                json.dumps(
                    {
                        "action": "tool",
                        "tool": "run_reproduction",
                        "purpose": "bad",
                        "arguments": {"source_files": ["outside.cpp"], "driver_code": "int main(){}"},
                    }
                ),
                json.dumps(
                    {
                        "action": "final",
                        "hypothesis_id": "h9",
                        "evidence_ids": ["forged"],
                        "unresolved_questions": [],
                    }
                ),
            ],
        )
        assert result.hypothesis is None
        assert result.trace["stop_reason"] == "protocol-error"
        assert result.trace["error_kind"] == "invalid-evidence-reference"


    def test_cancel_and_diff_only_preserve_trace_without_execution(self):
        result = _run(self.workspace, [], should_cancel=lambda: True)
        assert result.trace["stop_reason"] == "cancelled"
        wb = _Workbench()
        result = _run(
            self.workspace,
            [
                json.dumps(
                    {
                        "action": "tool",
                        "tool": "record_hypothesis",
                        "purpose": "propose",
                        "arguments": {
                            "hypothesis": _hypothesis(),
                            "trigger_path": "src/a.cpp",
                            "cwe": "CWE-476",
                            "driver_code": "int main(){}",
                            "experiment_design": "call",
                            "unresolved_assumptions": [],
                        },
                    }
                ),
                json.dumps(
                    {
                        "action": "tool",
                        "tool": "run_reproduction",
                        "purpose": "test",
                        "arguments": {"source_files": ["src/a.cpp"], "driver_code": "int main(){}"},
                    }
                ),
                json.dumps(
                    {
                        "action": "final",
                        "hypothesis_id": "h1",
                        "evidence_ids": [],
                        "unresolved_questions": [],
                    }
                ),
            ],
            source_mode="diff-only",
            workbench=wb,
        )
        assert wb.calls == []
        assert result.trace["actions"][-1]["tool"] == "run_reproduction"


    def test_team_child_is_bounded_and_critic_uses_observed_evidence(self):
        replies = iter(
            [
                json.dumps(
                    {
                        "action": "tool",
                        "tool": "record_hypothesis",
                        "purpose": "propose",
                        "arguments": {
                            "hypothesis": _hypothesis(),
                            "trigger_path": "src/a.cpp",
                            "cwe": "CWE-476",
                            "driver_code": "int main(){}",
                            "experiment_design": "call",
                            "unresolved_assumptions": [],
                        },
                    }
                ),
                json.dumps(
                    {
                        "action": "tool",
                        "tool": "delegate_subtask",
                        "purpose": "check caller",
                        "arguments": {
                            "role": "scout",
                            "question": "find callers",
                            "paths": ["src/a.cpp"],
                            "evidence_ids": ["e1"],
                        },
                    }
                ),
                json.dumps(
                    {
                        "action": "final",
                        "summary": "no additional observed evidence",
                        "evidence_ids": ["e1"],
                        "unresolved_questions": [],
                    }
                ),
                json.dumps(
                    {
                        "action": "final",
                        "hypothesis_id": "h1",
                        "evidence_ids": ["e2"],
                        "unresolved_questions": [],
                    }
                ),
                json.dumps(
                    {
                        "action": "final",
                        "assessment": "insufficient",
                        "rationale": "no runtime run",
                        "evidence_ids": ["e2"],
                        "unresolved_questions": ["exercise API"],
                    }
                ),
            ]
        )
        roles = []
        result = run_investigation(
            target={"target_id": "target-1", "path": "src/a.cpp"},
            workspace=self.workspace,
            repository_key="org/repo",
            snapshot_hash="a" * 64,
            budget=CxxAgentBudget(max_calls=20),
            send=lambda system, user, role: (roles.append(role), next(replies))[1],
            strategy="team",
        )
        assert len(result.trace["children"]) == 1
        assert roles[-2:] == ["specialist", "critic"]
        assert "scout" in roles
        assert result.critic["evidence_ids"] == ["e2"]


    def test_model_receives_closed_action_and_tool_catalog(self):
        prompts = []
        reply = json.dumps(
            {
                "action": "final",
                "hypothesis_id": "",
                "evidence_ids": [],
                "unresolved_questions": [],
            }
        )
        result = run_investigation(
            target={"target_id": "target-1", "path": "src/a.cpp"},
            workspace=self.workspace,
            repository_key="org/repo",
            snapshot_hash="a" * 64,
            budget=CxxAgentBudget(max_calls=20),
            send=lambda system, user, role: (prompts.append((system, user, role)), reply)[1],
        )
        assert result.hypothesis is None
        assert prompts[0][2] == "specialist"
        assert "record_hypothesis" in prompts[0][0]
        assert '"action":"tool"' in prompts[0][0]
        assert '"hypothesis_id"' in prompts[0][0]
