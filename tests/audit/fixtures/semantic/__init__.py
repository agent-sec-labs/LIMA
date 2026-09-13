"""Deterministic semantic-prioritizer fixtures (IP-0019, Packet IP-0019-PACKET/v1).

Repo shapes are plain ``dict[str, str]`` materialized through
``tests.audit.fixtures.repo_shapes.workspace_with`` (which pins
``newline="\\n"`` per PI-DR1/PI-DR6). The fake model clients in
:mod:`tests.audit.fixtures.semantic.fakes` implement the frozen
``SemanticModelClient`` protocol deterministically; they never touch the
network. Nothing in this package imports ``lima.audit`` so the module-absence
RED anchor (PI-DR4) stays observable per test case.
"""

from tests.audit.fixtures.semantic.fakes import ScriptedModelClient
from tests.audit.fixtures.semantic.shapes import (
    MANY_SINK_REPO,
    MIXED_REPO,
    SINK_TAINTED_REPO,
)

__all__ = [
    "MANY_SINK_REPO",
    "MIXED_REPO",
    "SINK_TAINTED_REPO",
    "ScriptedModelClient",
]
