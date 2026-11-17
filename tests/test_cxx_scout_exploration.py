import json
import tempfile
from pathlib import Path

from lima.cxx_agent_tools import CxxAgentBudget
from lima.workspace import RepositoryWorkspace


def test_scout_can_add_only_observed_in_scope_location():
    from lima.cxx_scout_exploration import explore_leads
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "a.cpp").write_text("void release() {}\nvoid use() {}\n")
        replies = iter([
            {"action": "tool", "tool": "read_source", "arguments": {
                "path": "a.cpp", "start_line": 1, "end_line": 2}},
            {"action": "tool", "tool": "add_lead", "arguments": {
                "path": "a.cpp", "line": 2, "summary": "inspect use after release"}},
            {"action": "final"},
        ])
        leads, trace = explore_leads(
            workspace=RepositoryWorkspace(root), units=("a.cpp",), initial_leads=(),
            budget=CxxAgentBudget(), send=lambda *_: json.dumps(next(replies)),
        )
    assert len(leads) == 1
    assert leads[0].path == "a.cpp" and leads[0].line == 2
    assert trace["stop_reason"] == "final"


def test_scout_cannot_invent_location_without_reading():
    from lima.cxx_scout_exploration import explore_leads
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "a.cpp").write_text("void f() {}\n")
        replies = iter([
            {"action": "tool", "tool": "add_lead", "arguments": {
                "path": "a.cpp", "line": 1, "summary": "guessed"}},
            {"action": "final"},
        ])
        leads, trace = explore_leads(
            workspace=RepositoryWorkspace(root), units=("a.cpp",), initial_leads=(),
            budget=CxxAgentBudget(), send=lambda *_: json.dumps(next(replies)),
        )
    assert not leads
    assert trace["actions"][0]["ok"] is False
