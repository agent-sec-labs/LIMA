"""IP-0021 acceptance tests: five-shape golden matrix (Packet §5.5/§6).

Every shape runs the full profile -> RAM -> Top-N chain (model-off path,
default options) twice independently. The golden JSON files under
``fixtures/golden_matrix/golden/`` are Implementation-produced data
artifacts checked against the frozen wire contract. The module under test
is imported lazily per test (PI-DR4 module-absence anchor).
"""

from __future__ import annotations

import importlib
import json
import unittest
from pathlib import Path
from typing import Any

from lima.audit import build_python_ram_facts, build_repository_profile, build_semantic_top_n
from tests.audit.fixtures.golden_matrix import shapes
from tests.audit.fixtures.repo_shapes import profile_kwargs, workspace_with

GOLDEN_DIR = Path(__file__).resolve().parent / "fixtures" / "golden_matrix" / "golden"


def rs_module() -> Any:
    return importlib.import_module("lima.audit.ram_schema")


def build_full_chain(repo: dict[str, str]) -> tuple[Any, Any, Any]:
    with workspace_with(repo) as workspace:
        profile_result = build_repository_profile(workspace, **profile_kwargs())
        ram_result = build_python_ram_facts(workspace)
    semantic_result = build_semantic_top_n(ram_result.facts)
    return profile_result, ram_result, semantic_result


class GoldenChainTests(unittest.TestCase):
    """Five shapes x (full-chain golden equality + provenance chain)."""

    def _run_golden(self, name: str) -> None:
        rs = rs_module()
        profile_result, ram_result, semantic_result = build_full_chain(
            shapes.SHAPES[name]
        )
        self.assertEqual(profile_result.provenance_anchor_ids, ("inventory",))
        self.assertEqual(ram_result.provenance_anchor_ids, ("ram-facts",))
        self.assertEqual(
            semantic_result.provenance_anchor_ids, ("semantic-prioritizer",)
        )
        payload = rs.ram_wire_payload(ram_result, semantic_result)
        self.assertIsNone(rs.validate_ram_wire_payload(payload))
        golden = json.loads((GOLDEN_DIR / f"{name}.json").read_text(encoding="utf-8"))
        self.assertEqual(payload, golden)

    def test_golden_application(self) -> None:
        self._run_golden("application")

    def test_golden_library(self) -> None:
        self._run_golden("library")

    def test_golden_cli(self) -> None:
        self._run_golden("cli")

    def test_golden_docs(self) -> None:
        self._run_golden("docs")

    def test_golden_test_heavy(self) -> None:
        self._run_golden("test-heavy")


class ReplayDeterminismTests(unittest.TestCase):
    """Five shapes x replayable identity (three digests + candidate order)."""

    def _run_replay(self, name: str) -> None:
        rs = rs_module()
        _p1, r1, s1 = build_full_chain(shapes.SHAPES[name])
        _p2, r2, s2 = build_full_chain(shapes.SHAPES[name])
        self.assertEqual(r1.facts, r2.facts)
        self.assertEqual(s1.result_digest, s2.result_digest)
        self.assertEqual(s1.config_digest, s2.config_digest)
        self.assertEqual(
            [item.candidate_id for item in s1.ranked],
            [item.candidate_id for item in s2.ranked],
        )
        first = rs.ram_wire_payload(r1, s1)
        second = rs.ram_wire_payload(r2, s2)
        self.assertEqual(
            first["identity"]["ram_facts_digest"],
            second["identity"]["ram_facts_digest"],
        )
        self.assertEqual(
            first["identity"]["semantic_config_digest"],
            second["identity"]["semantic_config_digest"],
        )
        self.assertEqual(
            first["identity"]["semantic_result_digest"],
            second["identity"]["semantic_result_digest"],
        )
        self.assertEqual(first["identity"]["wire_digest"], second["identity"]["wire_digest"])
        self.assertEqual(
            [item["candidate_id"] for item in first["semantic"]["ranked"]],
            [item["candidate_id"] for item in second["semantic"]["ranked"]],
        )

    def test_replay_application(self) -> None:
        self._run_replay("application")

    def test_replay_library(self) -> None:
        self._run_replay("library")

    def test_replay_cli(self) -> None:
        self._run_replay("cli")

    def test_replay_docs(self) -> None:
        self._run_replay("docs")

    def test_replay_test_heavy(self) -> None:
        self._run_replay("test-heavy")


class WireIdentityCrossCheckTests(unittest.TestCase):
    """Wire identity digests equal the frozen layer digests (three shapes)."""

    def _run_cross(self, name: str) -> None:
        rs = rs_module()
        import lima.audit.ram as ram
        import lima.audit.semantic_prioritizer as sp

        _profile, ram_result, semantic_result = build_full_chain(shapes.SHAPES[name])
        facts_digest = ram.ram_facts_digest(ram_result.facts)
        payload = rs.ram_wire_payload(ram_result, semantic_result)
        self.assertEqual(payload["identity"]["ram_facts_digest"], facts_digest)
        self.assertEqual(
            payload["identity"]["semantic_config_digest"],
            sp.semantic_config_digest(sp.SemanticOptions()),
        )
        self.assertEqual(
            payload["identity"]["semantic_result_digest"],
            sp.semantic_result_digest(
                semantic_result, input_facts_digest=facts_digest
            ),
        )
        self.assertEqual(
            payload["identity"]["prompt_digest"], semantic_result.prompt_digest
        )
        self.assertEqual(
            payload["identity"]["model_digest"], semantic_result.model_digest
        )
        self.assertEqual(
            payload["identity"]["wire_digest"], rs.ram_wire_digest(payload)
        )

    def test_wire_identity_application(self) -> None:
        self._run_cross("application")

    def test_wire_identity_library(self) -> None:
        self._run_cross("library")

    def test_wire_identity_cli(self) -> None:
        self._run_cross("cli")


class WireConventionTests(unittest.TestCase):
    """LF wire convention and zero-execution/zero-network guarantees."""

    def test_shape_and_golden_files_are_lf_only(self) -> None:
        shapes.assert_lf_only()
        rs = rs_module()
        for name in shapes.SHAPE_NAMES:
            raw = (GOLDEN_DIR / f"{name}.json").read_bytes()
            self.assertNotIn(b"\r", raw, name)
        self.assertEqual(rs.PROVENANCE_ANCHOR_CHAIN[-1], "semantic-prioritizer")

    def test_wire_module_uses_no_network_facility(self) -> None:
        import inspect

        source = inspect.getsource(rs_module())
        for forbidden in ("socket", "urllib", "httpx", "requests", "subprocess"):
            self.assertNotIn(forbidden, source, forbidden)
        self.assertEqual(shapes.SHAPE_NAMES, tuple(shapes.SHAPES))


if __name__ == "__main__":
    unittest.main()
