"""IP-0021 acceptance tests: three-layer budget end-to-end (Packet §5.6/§6).

Every case injects explicit frozen budgets (no defaults relied upon) and
asserts the typed ``BUDGET_EXHAUSTED`` gap plus non-blocking behaviour
across layers. L3 model paths use scripted fake clients only: zero
network, zero paid calls. Module under test imported lazily (PI-DR4).
"""

from __future__ import annotations

import importlib
import unittest
from typing import Any

import lima.audit.semantic_prioritizer as sp
from lima.audit import build_python_ram_facts, build_repository_profile
from lima.audit.inventory import ProfileBudgets, ProfileInventoryOptions
from lima.audit.ram import RamBudgets
from tests.audit.fixtures.ram.shapes import (
    TWO_FLOW_REPO,
    UNRESOLVED_BUDGET_REPO,
)
from tests.audit.fixtures.repo_shapes import profile_kwargs, workspace_with
from tests.audit.fixtures.semantic.fakes import ScriptedModelClient


def rs_module() -> Any:
    return importlib.import_module("lima.audit.ram_schema")


def profile_gap_pairs(files: dict[str, str], budgets: ProfileBudgets) -> list[tuple[str, str]]:
    with workspace_with(files) as workspace:
        result = build_repository_profile(
            workspace,
            options=ProfileInventoryOptions(budgets=budgets),
            **profile_kwargs(),
        )
    return [(gap.gap_code, gap.detail) for gap in result.profile.coverage_gaps]


def ram_gap_pairs(
    files: dict[str, str], budgets: RamBudgets
) -> tuple[list[tuple[str, str]], Any]:
    with workspace_with(files) as workspace:
        ram_result = build_python_ram_facts(workspace, budgets=budgets)
    pairs = [(gap.gap_code, gap.detail) for gap in ram_result.facts.coverage_gaps]
    return pairs, ram_result


def semantic_gap_pairs(
    files: dict[str, str], options: sp.SemanticOptions, client: Any = None
) -> list[tuple[str, str]]:
    with workspace_with(files) as workspace:
        ram_result = build_python_ram_facts(workspace)
    kwargs: dict[str, Any] = {"options": options}
    if client is not None:
        kwargs["model_client"] = client
    result = sp.build_semantic_top_n(ram_result.facts, **kwargs)
    return [(gap.gap_code, gap.detail) for gap in result.coverage_gaps]


class Layer1ProfileBudgetTests(unittest.TestCase):
    """L1 ProfileBudgets: manifest-file-limit and manifest bytes cap."""

    def setUp(self) -> None:
        rs_module()  # module-absence RED anchor (PI-DR4)

    def test_manifest_file_count_over_budget(self) -> None:
        files = {
            "requirements.txt": "fastapi==0.110.0\n",
            "requirements-dev.txt": "ruff==0.4.0\n",
            "pyproject.toml": "[project]\nname = 'x'\n",
            "app.py": "import os\n",
        }
        pairs = profile_gap_pairs(files, ProfileBudgets(max_manifest_files=1))
        self.assertIn(
            ("BUDGET_EXHAUSTED", "reason=manifest-file-limit; count=2"), pairs
        )

    def test_manifest_bytes_over_budget(self) -> None:
        content = "# padding line\n" * 40
        files = {"pyproject.toml": content, "app.py": "import os\n"}
        budgets = ProfileBudgets(manifest_max_bytes=16)
        pairs = profile_gap_pairs(files, budgets)
        expected = (
            "BUDGET_EXHAUSTED",
            f"manifest-index=0; bytes={len(content.encode('utf-8'))}; limit=16",
        )
        self.assertIn(expected, pairs)


class Layer2RamBudgetTests(unittest.TestCase):
    """L2 RamBudgets: python-file / key-flow / unresolved-edge limits."""

    def setUp(self) -> None:
        rs_module()  # module-absence RED anchor (PI-DR4)

    def test_python_file_count_over_budget(self) -> None:
        files = {"a_first.py": "A = 1\n", "b_second.py": "B = 2\n"}
        pairs, ram_result = ram_gap_pairs(files, RamBudgets(max_python_files=1))
        self.assertIn(
            ("BUDGET_EXHAUSTED", "reason=python-file-limit; count=1"), pairs
        )
        self.assertEqual(
            sorted(ram_result.facts.counters),
            sorted(
                [
                    "ambiguous_modules",
                    "cross_file_edges",
                    "dynamic_import_sites",
                    "functions_indexed",
                    "interprocedural_edges",
                    "modules_indexed",
                    "parse_error_files",
                    "unresolved_calls",
                ]
            ),
        )

    def test_key_flow_count_over_budget(self) -> None:
        pairs, ram_result = ram_gap_pairs(TWO_FLOW_REPO, RamBudgets(max_key_flows=1))
        self.assertIn(("BUDGET_EXHAUSTED", "reason=key-flow-limit; count=1"), pairs)
        self.assertEqual(len(ram_result.facts.key_flows), 1)
        self.assertEqual(len(ram_result.facts.sensitive_sinks), 2)

    def test_unresolved_edge_count_over_budget(self) -> None:
        pairs, ram_result = ram_gap_pairs(
            UNRESOLVED_BUDGET_REPO, RamBudgets(max_unresolved_edges=1)
        )
        self.assertIn(
            ("BUDGET_EXHAUSTED", "reason=unresolved-edge-limit; count=2"), pairs
        )
        self.assertEqual(len(ram_result.facts.unresolved_edges), 1)


class Layer3SemanticBudgetTests(unittest.TestCase):
    """L3 SemanticBudgets: pre-call checkpoints with scripted clients only."""

    def setUp(self) -> None:
        rs_module()  # module-absence RED anchor (PI-DR4)

    def _many_sink_repo(self) -> dict[str, str]:
        from tests.audit.fixtures.semantic.shapes import MANY_SINK_REPO

        return MANY_SINK_REPO

    def test_llm_call_budget_stops_with_notable_note(self) -> None:
        options = sp.SemanticOptions(
            model_id="fake-model",
            budgets=sp.SemanticBudgets(max_llm_calls=1),
        )
        client = ScriptedModelClient(["not json"])
        pairs = semantic_gap_pairs(self._many_sink_repo(), options, client=client)
        budget_details = [detail for code, detail in pairs if code == "BUDGET_EXHAUSTED"]
        self.assertEqual(len(budget_details), 1)
        self.assertIn("stage=llm-calls", budget_details[0])
        self.assertIn("not-an-absence-of-risk", budget_details[0])
        self.assertIn(
            ("SEMANTIC_MALFORMED_OUTPUT", "batch=0; offending=json"), pairs
        )

    def test_prompt_token_budget_stops_before_any_call(self) -> None:
        options = sp.SemanticOptions(
            model_id="fake-model",
            budgets=sp.SemanticBudgets(max_prompt_tokens_estimate=10),
        )
        client = ScriptedModelClient()
        pairs = semantic_gap_pairs(self._many_sink_repo(), options, client=client)
        self.assertEqual(client.call_count, 0)
        self.assertIn("stage=prompt-tokens", dict(pairs)["BUDGET_EXHAUSTED"])

    def test_output_token_budget_stops_before_any_call(self) -> None:
        options = sp.SemanticOptions(
            model_id="fake-model",
            budgets=sp.SemanticBudgets(max_output_tokens_estimate=1),
        )
        client = ScriptedModelClient()
        pairs = semantic_gap_pairs(self._many_sink_repo(), options, client=client)
        self.assertEqual(client.call_count, 0)
        self.assertIn("stage=output-tokens", dict(pairs)["BUDGET_EXHAUSTED"])

    def test_total_token_budget_is_fail_closed_at_construction(self) -> None:
        with self.assertRaises(ValueError):
            sp.SemanticBudgets(
                max_prompt_tokens_estimate=24_000,
                max_output_tokens_estimate=4_096,
                max_total_tokens_estimate=28_095,
            )


class CombinedThreeLayerTests(unittest.TestCase):
    """L1+L2+L3 simultaneously: gaps coexist, sorted, digests replayable."""

    def test_combined_budget_fixture_gaps_coexist_and_replay(self) -> None:
        rs = rs_module()
        files = {
            "requirements.txt": "fastapi==0.110.0\n",
            "requirements-dev.txt": "ruff==0.4.0\n",
            "pyproject.toml": "[project]\nname = 'x'\n",
            "a_first.py": (
                "import os\n"
                "from framework import request\n"
                "\n"
                "\n"
                "def run(request):\n"
                "    os.system(request.args.get('cmd'))\n"
            ),
            "b_second.py": "import os\n",
        }
        profile_budgets = ProfileBudgets(max_manifest_files=1)
        ram_budgets = RamBudgets(max_python_files=1)
        semantic_options = sp.SemanticOptions(
            model_id="fake-model",
            budgets=sp.SemanticBudgets(max_prompt_tokens_estimate=10),
        )

        def build() -> tuple[Any, Any, Any, Any]:
            with workspace_with(files) as workspace:
                profile_result = build_repository_profile(
                    workspace,
                    options=ProfileInventoryOptions(budgets=profile_budgets),
                    **profile_kwargs(),
                )
                ram_result = build_python_ram_facts(workspace, budgets=ram_budgets)
            client = ScriptedModelClient()
            semantic_result = sp.build_semantic_top_n(
                ram_result.facts, options=semantic_options, model_client=client
            )
            payload = rs.ram_wire_payload(
                ram_result,
                semantic_result,
                profile_budgets=profile_budgets,
                ram_budgets=ram_budgets,
                semantic_options=semantic_options,
            )
            return profile_result, ram_result, semantic_result, payload

        p1, r1, s1, wire1 = build()
        p2, r2, s2, wire2 = build()

        l1_codes = [gap.gap_code for gap in p1.profile.coverage_gaps]
        self.assertIn("BUDGET_EXHAUSTED", l1_codes)
        l2_pairs = [(gap.gap_code, gap.detail) for gap in r1.facts.coverage_gaps]
        self.assertIn(
            ("BUDGET_EXHAUSTED", "reason=python-file-limit; count=1"), l2_pairs
        )
        l3_pairs = [(gap.gap_code, gap.detail) for gap in s1.coverage_gaps]
        self.assertIn("BUDGET_EXHAUSTED", dict(l3_pairs))
        self.assertIn("stage=prompt-tokens", dict(l3_pairs)["BUDGET_EXHAUSTED"])

        semantic_codes = [code for code, _ in l3_pairs]
        self.assertEqual(semantic_codes, sorted(semantic_codes))
        ram_codes = [code for code, _ in l2_pairs]
        self.assertEqual(ram_codes, sorted(ram_codes))

        self.assertTrue(wire1["execution_required"]["required"])
        self.assertEqual(
            wire1["execution_required"]["trigger_gap_codes"],
            ["BUDGET_EXHAUSTED"],
        )
        self.assertEqual(wire1, wire2)
        self.assertEqual(
            wire1["identity"]["wire_digest"], wire2["identity"]["wire_digest"]
        )
        self.assertIsNone(rs.validate_ram_wire_payload(wire1))


class DigestInvariantTests(unittest.TestCase):
    """Budget configuration values enter identity; wall time never does."""

    def test_budget_value_change_changes_config_and_wire_digest(self) -> None:
        rs = rs_module()
        from tests.audit.fixtures.ram.shapes import SINK_TAINTED_REPO

        with workspace_with(SINK_TAINTED_REPO) as workspace:
            ram_result = build_python_ram_facts(workspace)
        first_options = sp.SemanticOptions()
        second_options = sp.SemanticOptions(
            budgets=sp.SemanticBudgets(max_llm_calls=7)
        )
        first = rs.ram_wire_payload(
            ram_result,
            sp.build_semantic_top_n(ram_result.facts, options=first_options),
            semantic_options=first_options,
        )
        second = rs.ram_wire_payload(
            ram_result,
            sp.build_semantic_top_n(ram_result.facts, options=second_options),
            semantic_options=second_options,
        )
        self.assertNotEqual(
            first["identity"]["semantic_config_digest"],
            second["identity"]["semantic_config_digest"],
        )
        self.assertNotEqual(
            first["identity"]["wire_digest"], second["identity"]["wire_digest"]
        )

    def test_same_config_rebuild_keeps_all_identity_digests(self) -> None:
        rs = rs_module()
        from tests.audit.fixtures.ram.shapes import SINK_TAINTED_REPO

        def build() -> dict[str, Any]:
            with workspace_with(SINK_TAINTED_REPO) as workspace:
                ram_result = build_python_ram_facts(
                    workspace, budgets=RamBudgets(max_python_files=9)
                )
            semantic_result = sp.build_semantic_top_n(ram_result.facts)
            return rs.ram_wire_payload(
                ram_result,
                semantic_result,
                ram_budgets=RamBudgets(max_python_files=9),
            )

        first, second = build(), build()
        self.assertEqual(first["identity"], second["identity"])
        self.assertEqual(first["ram"]["coverage_gaps"], second["ram"]["coverage_gaps"])


if __name__ == "__main__":
    unittest.main()
