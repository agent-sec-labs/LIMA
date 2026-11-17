"""Focused contract tests for the bounded C++ investigation engine."""

from __future__ import annotations

import json
import unittest
import tempfile
from pathlib import Path


from lima.agent_repro_tools import ExperimentObservation
from lima.cxx_agent_tools import CxxAgentBudget
from lima.cxx_investigator import run_investigation
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
