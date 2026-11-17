"""Production adapters for the model-selected C/C++ investigation loop."""

import json
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from lima.agent_orchestrator import run_platform_review
from lima.agent_repro_tools import ExperimentObservation
from lima.agent_scout import ScoutLead, ScoutReport, ScoutTarget
from lima.config import Settings
from lima.cxx_agent_tools import CxxAgentBudget
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


@pytest.fixture
def workspace():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "src").mkdir()
        (root / "src/a.cpp").write_text("void f() {\n int x = 1;\n}\n")
        yield RepositoryWorkspace(root)


def test_strategy_off_makes_no_calls(workspace):
    budget = CxxAgentBudget()
    result = review(workspace, mode="off", investigation_strategy="team", budget=budget)
    assert result.targets == ()
    assert budget.remaining().calls == 40


def test_unknown_strategy_is_rejected(workspace):
    with pytest.raises(ValueError, match="strategy"):
        review(workspace, investigation_strategy="unknown")


def test_settings_load_strategy_and_controls():
    with patch.dict(os.environ, {
        "LIMA_CXX_INVESTIGATION_STRATEGY": "team",
        "LIMA_CXX_INVESTIGATION_MAX_STEPS": "18",
        "LIMA_CXX_INVESTIGATION_MAX_CHILDREN": "2",
    }), patch("lima.config.load_dotenv"):
        settings = Settings.from_env()
    assert settings.cxx_investigation_strategy == "team"
    assert settings.cxx_investigation_max_steps == 18
    assert settings.cxx_investigation_max_children == 2


def test_scanner_passes_strategy_controls():
    scanner = RepositoryScanner(
        cxx_investigation_strategy="team", cxx_investigation_max_steps=17,
        cxx_investigation_max_children=1,
    )
    assert scanner.cxx_investigation_strategy == "team"
    assert scanner.cxx_investigation_max_steps == 17


def test_new_strategy_keeps_executed_runtime_evidence(workspace):
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
        outcome = review(workspace, investigation_strategy="investigator")
    assert outcome.targets[0].state == "runtime-confirmed"
    assert outcome.targets[0].investigation["stop_reason"] == "final"
    assert outcome.stats.experiment_count == 1


def test_runtime_hit_with_critic_refutation_requires_review(workspace):
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
        outcome = review(workspace, investigation_strategy="team")
    assert outcome.targets[0].state == "needs-human-review"


def test_trace_survives_no_hypothesis(workspace):
    result = SimpleNamespace(
        hypothesis=None, experiments=[], critic=None,
        trace={"stop_reason": "steps-exhausted", "actions": [{"tool": "read_source"}]},
    )
    with patch("lima.cxx_investigator.run_investigation", return_value=result):
        outcome = review(workspace, investigation_strategy="investigator")
    assert outcome.targets[0].state == "abstain"
    assert outcome.targets[0].investigation["actions"]
    json.dumps(RepositoryScanner()._platform_collaboration("auto", "completed", outcome))
