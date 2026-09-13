"""IP-0021 acceptance tests: RAM wire schema module (Packet §6, test_ram_schema).

The module under test (``lima.audit.ram_schema``) is imported lazily inside
each test so the module-absence RED anchor (PI-DR4) stays observable per
test case. Chain inputs are built through the frozen three-layer surfaces
(read-only consumption; Packet §1 Non-goals).
"""

from __future__ import annotations

import copy
import importlib
import re
import unittest
from typing import Any

from lima.audit import build_python_ram_facts, build_semantic_top_n
from lima.contracts.errors import ContractError
from tests.audit.fixtures.ram.shapes import SINK_TAINTED_REPO
from tests.audit.fixtures.repo_shapes import workspace_with

#: Packet §5.3: K = 10 new re-exported symbols appended to ``lima.audit``.
IP0021_K: int = 10
IP0021_NEW_SYMBOLS: list[str] = sorted(
    [
        "GAP_CODES_ALL",
        "GAP_EXECUTION_REQUIRED_TRIGGERS",
        "PROVENANCE_ANCHOR_CHAIN",
        "RAM_WIRE_SCHEMA_FILE",
        "RAM_WIRE_SCHEMA_NAME",
        "execution_required_from_gaps",
        "load_ram_wire_schema",
        "ram_wire_digest",
        "ram_wire_payload",
        "validate_ram_wire_payload",
    ]
)

HEX64 = "0" * 64
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

_WEIGHTS = {
    "sink_flow_command": 80,
    "sink_flow_sql": 80,
    "sink_flow_eval": 90,
    "sink_flow_path": 70,
    "sink_flow_deserialization": 70,
    "entrypoint": 60,
    "external_source": 50,
    "trust_boundary": 40,
    "unresolved_edge": 30,
}
_SEMANTIC_BUDGETS = {
    "max_llm_calls": 8,
    "max_prompt_tokens_estimate": 24000,
    "max_output_tokens_estimate": 4096,
    "max_total_tokens_estimate": 28096,
    "max_wall_time_seconds": 120,
}
_COUNTERS = {
    "ambiguous_modules": 0,
    "cross_file_edges": 0,
    "dynamic_import_sites": 0,
    "functions_indexed": 1,
    "interprocedural_edges": 0,
    "modules_indexed": 1,
    "parse_error_files": 0,
    "unresolved_calls": 0,
}
_ENTRY = {
    "path": "danger.py",
    "reason_codes": ["sensitive-sink"],
    "source_artifact_ids": [],
    "symbol": None,
}

#: One minimal, fully valid wire payload: the frozen wire-format contract
#: (Packet §5.1 field table) expressed as data.
MINIMAL_PAYLOAD: dict[str, Any] = {
    "schema_version": "4.0",
    "model_kind": "lima.repository-architecture-model",
    "build": {
        "profile_budgets": {"manifest_max_bytes": 262144, "max_manifest_files": 64},
        "ram_budgets": {
            "max_python_files": 512,
            "max_key_flows": 256,
            "max_unresolved_edges": 1024,
        },
        "semantic": {
            "top_n": 20,
            "seed": 0,
            "tie_break": "kind-path-symbol-ordinal",
            "model_id": "unset",
            "weights": dict(_WEIGHTS),
            "budgets": dict(_SEMANTIC_BUDGETS),
        },
    },
    "ram": {
        "entrypoints": [],
        "external_sources": [],
        "source_labels": [],
        "sensitive_sinks": [dict(_ENTRY)],
        "sink_rule_ids": ["rule-x"],
        "sink_cwes": ["CWE-78"],
        "trust_boundaries": [],
        "key_flows": [{"sink_rule_id": "rule-x", "steps": ["danger.py:3"]}],
        "unresolved_edges": [],
        "coverage_gaps": [{"gap_code": "DYNAMIC_IMPORT", "detail": "reason=probe"}],
        "counters": dict(_COUNTERS),
    },
    "semantic": {
        "ranked": [
            {
                "candidate_id": "sensitive-sink:danger.py:-#1",
                "kind": "sensitive-sink",
                "path": "danger.py",
                "symbol": None,
                "score": 80,
                "rank": 1,
                "category": "command-execution",
                "rationale": "fallback",
                "key_flow_steps": ["danger.py:3"],
            }
        ],
        "total_candidates": 1,
        "coverage_gaps": [],
    },
    "identity": {
        "ram_facts_digest": HEX64,
        "semantic_config_digest": HEX64,
        "semantic_result_digest": HEX64,
        "prompt_digest": HEX64,
        "model_digest": HEX64,
        "wire_digest": HEX64,
    },
    "provenance": {
        "provenance_anchor_ids": ["inventory", "ram-facts", "semantic-prioritizer"]
    },
    "execution_required": {"required": True, "trigger_gap_codes": ["DYNAMIC_IMPORT"]},
}


def rs_module() -> Any:
    """Import the module under test lazily (PI-DR4 module-absence anchor)."""
    return importlib.import_module("lima.audit.ram_schema")


def build_chain(repo: dict[str, str]) -> tuple[Any, Any]:
    """Build one RAM -> semantic chain over a temporary workspace."""
    with workspace_with(repo) as workspace:
        ram_result = build_python_ram_facts(workspace)
    semantic_result = build_semantic_top_n(ram_result.facts)
    return ram_result, semantic_result


class SchemaFileTests(unittest.TestCase):
    """Packet §5.1: schema file self-consistency via ``load_ram_wire_schema``."""

    def test_schema_file_loads_as_draft_2020_12_object(self) -> None:
        schema = rs_module().load_ram_wire_schema()
        self.assertIsInstance(schema, dict)
        self.assertEqual(
            schema["$schema"], "https://json-schema.org/draft/2020-12/schema"
        )

    def test_schema_top_level_is_closed_with_const_identity(self) -> None:
        schema = rs_module().load_ram_wire_schema()
        properties = schema["properties"]
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(properties["schema_version"]["const"], "4.0")
        self.assertEqual(
            properties["model_kind"]["const"],
            "lima.repository-architecture-model",
        )

    def test_schema_required_lists_every_top_level_property(self) -> None:
        schema = rs_module().load_ram_wire_schema()
        self.assertEqual(sorted(schema["required"]), sorted(schema["properties"]))
        self.assertEqual(
            sorted(schema["properties"]),
            sorted(
                [
                    "schema_version",
                    "model_kind",
                    "build",
                    "ram",
                    "semantic",
                    "identity",
                    "provenance",
                    "execution_required",
                ]
            ),
        )

    def test_schema_collection_fields_carry_maxitems_cap(self) -> None:
        schema = rs_module().load_ram_wire_schema()
        capped: list[str] = []

        def _walk(node: Any) -> None:
            if isinstance(node, dict):
                if node.get("maxItems") == 4096:
                    capped.append("found")
                for value in node.values():
                    _walk(value)
            elif isinstance(node, list):
                for value in node:
                    _walk(value)

        _walk(schema)
        self.assertGreaterEqual(len(capped), 4, "expected >=4 maxItems:4096 caps")

    def test_schema_file_path_constant_matches_disk_layout(self) -> None:
        rs = rs_module()
        self.assertEqual(
            tuple(rs.RAM_WIRE_SCHEMA_FILE.parts),
            ("schemas", "v4", "lima.repository-architecture-model.json"),
        )


class WireFormatPositiveTests(unittest.TestCase):
    """Positive validation on the minimal payload and one real chain wire."""

    def test_minimal_payload_validates(self) -> None:
        self.assertIsNone(rs_module().validate_ram_wire_payload(MINIMAL_PAYLOAD))

    def test_real_chain_payload_validates_with_frozen_top_sections(self) -> None:
        rs = rs_module()
        payload = rs.ram_wire_payload(*build_chain(SINK_TAINTED_REPO))
        self.assertIsNone(rs.validate_ram_wire_payload(payload))
        self.assertEqual(
            sorted(payload),
            sorted(
                [
                    "schema_version",
                    "model_kind",
                    "build",
                    "ram",
                    "semantic",
                    "identity",
                    "provenance",
                    "execution_required",
                ]
            ),
        )


class ValidationNegativeTests(unittest.TestCase):
    """Fail-closed negative validation (Packet §5.2): every case ContractError."""

    def assert_rejected(self, payload: dict[str, Any]) -> None:
        with self.assertRaises(ContractError):
            rs_module().validate_ram_wire_payload(payload)

    def test_unknown_top_level_field_rejected(self) -> None:
        payload = copy.deepcopy(MINIMAL_PAYLOAD)
        payload["extra_top"] = "x"
        self.assert_rejected(payload)

    def test_unknown_nested_field_in_ram_entry_rejected(self) -> None:
        payload = copy.deepcopy(MINIMAL_PAYLOAD)
        payload["ram"]["sensitive_sinks"][0]["unexpected"] = 1
        self.assert_rejected(payload)

    def test_wrong_scalar_type_rejected(self) -> None:
        payload = copy.deepcopy(MINIMAL_PAYLOAD)
        payload["schema_version"] = 4
        self.assert_rejected(payload)

    def test_category_outside_vocabulary_rejected(self) -> None:
        payload = copy.deepcopy(MINIMAL_PAYLOAD)
        payload["semantic"]["ranked"][0]["category"] = "not-a-category"
        self.assert_rejected(payload)

    def test_rank_not_consecutive_from_one_rejected(self) -> None:
        payload = copy.deepcopy(MINIMAL_PAYLOAD)
        payload["semantic"]["ranked"].append(
            {**payload["semantic"]["ranked"][0], "rank": 3}
        )
        self.assert_rejected(payload)

    def test_identity_digest_not_hex64_rejected(self) -> None:
        for key, value in (
            ("ram_facts_digest", "z" * 64),
            ("wire_digest", "abc"),
            ("semantic_result_digest", "A" * 64),
        ):
            payload = copy.deepcopy(MINIMAL_PAYLOAD)
            payload["identity"][key] = value
            self.assert_rejected(payload)

    def test_sink_rule_ids_length_mismatch_rejected(self) -> None:
        payload = copy.deepcopy(MINIMAL_PAYLOAD)
        payload["ram"]["sink_rule_ids"] = ["a", "b"]
        self.assert_rejected(payload)

    def test_sink_cwes_length_mismatch_rejected(self) -> None:
        payload = copy.deepcopy(MINIMAL_PAYLOAD)
        payload["ram"]["sink_cwes"] = []
        self.assert_rejected(payload)

    def test_trigger_gap_code_outside_frozen_set_rejected(self) -> None:
        payload = copy.deepcopy(MINIMAL_PAYLOAD)
        payload["execution_required"]["trigger_gap_codes"] = ["NOT_A_GAP_CODE"]
        self.assert_rejected(payload)

    def test_trigger_gap_codes_unsorted_or_duplicated_rejected(self) -> None:
        payload = copy.deepcopy(MINIMAL_PAYLOAD)
        payload["execution_required"]["trigger_gap_codes"] = [
            "DYNAMIC_IMPORT",
            "BUDGET_EXHAUSTED",
        ]
        self.assert_rejected(payload)
        payload = copy.deepcopy(MINIMAL_PAYLOAD)
        payload["execution_required"]["trigger_gap_codes"] = [
            "DYNAMIC_IMPORT",
            "DYNAMIC_IMPORT",
        ]
        self.assert_rejected(payload)

    def test_provenance_chain_wrong_order_rejected(self) -> None:
        payload = copy.deepcopy(MINIMAL_PAYLOAD)
        payload["provenance"]["provenance_anchor_ids"] = [
            "ram-facts",
            "inventory",
            "semantic-prioritizer",
        ]
        self.assert_rejected(payload)

    def test_key_flow_steps_over_cap_rejected(self) -> None:
        payload = copy.deepcopy(MINIMAL_PAYLOAD)
        payload["ram"]["key_flows"][0]["steps"] = [f"s.py:{i}" for i in range(13)]
        self.assert_rejected(payload)

    def test_gap_code_pattern_violation_rejected(self) -> None:
        payload = copy.deepcopy(MINIMAL_PAYLOAD)
        payload["ram"]["coverage_gaps"][0]["gap_code"] = "dynamic-import"
        self.assert_rejected(payload)

    def test_top_n_out_of_range_rejected(self) -> None:
        for bad in (0, 101):
            payload = copy.deepcopy(MINIMAL_PAYLOAD)
            payload["build"]["semantic"]["top_n"] = bad
            self.assert_rejected(payload)

    def test_missing_required_section_rejected(self) -> None:
        payload = copy.deepcopy(MINIMAL_PAYLOAD)
        del payload["identity"]
        self.assert_rejected(payload)

    def test_candidate_id_pattern_violation_rejected(self) -> None:
        payload = copy.deepcopy(MINIMAL_PAYLOAD)
        payload["semantic"]["ranked"][0]["candidate_id"] = "no-ordinal-here"
        self.assert_rejected(payload)

    def test_execution_required_inconsistent_with_gaps_rejected(self) -> None:
        payload = copy.deepcopy(MINIMAL_PAYLOAD)
        payload["ram"]["coverage_gaps"] = []
        payload["execution_required"] = {
            "required": True,
            "trigger_gap_codes": ["DYNAMIC_IMPORT"],
        }
        self.assert_rejected(payload)


class PayloadDeterminismTests(unittest.TestCase):
    """Packet §5.2: pure-function determinism (no clock/random/env/net)."""

    def test_two_independent_builds_yield_equal_payloads(self) -> None:
        rs = rs_module()
        first = rs.ram_wire_payload(*build_chain(SINK_TAINTED_REPO))
        second = rs.ram_wire_payload(*build_chain(SINK_TAINTED_REPO))
        self.assertEqual(first, second)

    def test_two_independent_builds_yield_equal_wire_digests(self) -> None:
        rs = rs_module()
        first = rs.ram_wire_payload(*build_chain(SINK_TAINTED_REPO))
        second = rs.ram_wire_payload(*build_chain(SINK_TAINTED_REPO))
        self.assertEqual(rs.ram_wire_digest(first), rs.ram_wire_digest(second))


class WireDigestTests(unittest.TestCase):
    """Packet §5.1/§5.2: wire digest shape and config sensitivity."""

    def test_wire_digest_is_lowercase_hex64(self) -> None:
        self.assertRegex(rs_module().ram_wire_digest(MINIMAL_PAYLOAD), _HEX64_RE)

    def test_wire_digest_changes_with_build_config(self) -> None:
        rs = rs_module()
        import lima.audit.semantic_prioritizer as sp

        ram_result, semantic_result = build_chain(SINK_TAINTED_REPO)
        base = rs.ram_wire_payload(ram_result, semantic_result)
        reseeded = rs.ram_wire_payload(
            ram_result,
            semantic_result,
            semantic_options=sp.SemanticOptions(seed=1),
        )
        self.assertNotEqual(rs.ram_wire_digest(base), rs.ram_wire_digest(reseeded))


class InitAppendSegmentTests(unittest.TestCase):
    """Packet §5.3: pure-append re-export with bounded segment assertions.

    After the DR-2 authorized relaxation in ``test_semantic_prioritizer.py``
    (``>= 44``), this file carries the repository's only exact cap
    assertion: ``len(__all__) == 44 + K`` (DR-IP-0021-0102 DR-2 落位注记).
    """

    def test_all_prefix_unchanged_and_exact_cap_44_plus_k(self) -> None:
        import lima.audit as audit
        from tests.audit.test_semantic_prioritizer import (
            IP0016_IP0018_ALL_PREFIX,
            IP0019_NEW_SYMBOLS,
        )

        self.assertEqual(len(IP0021_NEW_SYMBOLS), IP0021_K)
        self.assertEqual(
            list(audit.__all__[:44]),
            list(IP0016_IP0018_ALL_PREFIX) + list(IP0019_NEW_SYMBOLS),
        )
        self.assertEqual(len(audit.__all__), 44 + IP0021_K)
        for name in IP0021_NEW_SYMBOLS:
            self.assertTrue(hasattr(audit, name), name)

    def test_all_bounded_tail_is_exactly_the_new_symbol_set(self) -> None:
        import lima.audit as audit

        self.assertEqual(list(audit.__all__[44 : 44 + IP0021_K]), IP0021_NEW_SYMBOLS)
        self.assertEqual(len(audit.__all__[44:]), IP0021_K)


class EntryContractTests(unittest.TestCase):
    """Packet §5.2 entry contracts: fail-closed inputs and decoupling."""

    def test_payload_builder_rejects_non_result_inputs(self) -> None:
        rs = rs_module()
        _ram_result, semantic_result = build_chain(SINK_TAINTED_REPO)
        with self.assertRaises(ContractError):
            rs.ram_wire_payload("not-a-ram-result", semantic_result)
        ram_result, _semantic_result = build_chain(SINK_TAINTED_REPO)
        with self.assertRaises(ContractError):
            rs.ram_wire_payload(ram_result, "not-a-semantic-result")

    def test_execution_required_from_gaps_rejects_unknown_code(self) -> None:
        with self.assertRaises(ValueError):
            rs_module().execution_required_from_gaps(["NOT_A_GAP_CODE"])

    def test_validation_module_does_not_reference_layer_build_functions(self) -> None:
        import inspect

        source = inspect.getsource(rs_module())
        for forbidden in (
            "build_repository_profile",
            "build_python_ram_facts",
            "build_semantic_top_n",
        ):
            self.assertNotIn(forbidden, source, forbidden)

    def test_frozen_constants_match_packet_values(self) -> None:
        rs = rs_module()
        self.assertEqual(
            rs.RAM_WIRE_SCHEMA_NAME, "lima.repository-architecture-model"
        )
        self.assertEqual(
            rs.PROVENANCE_ANCHOR_CHAIN,
            ("inventory", "ram-facts", "semantic-prioritizer"),
        )
        self.assertEqual(
            rs.GAP_CODES_ALL,
            frozenset(
                {
                    "BUDGET_EXHAUSTED",
                    "INVENTORY_SKIPPED",
                    "MANIFEST_PARSE_ERROR",
                    "NO_LANGUAGES_DETECTED",
                    "UNSUPPORTED_LANGUAGE",
                    "DYNAMIC_IMPORT",
                    "AMBIGUOUS_DISPATCH",
                    "SEMANTIC_MODEL_OFF",
                    "SEMANTIC_MODEL_TIMEOUT",
                    "SEMANTIC_MALFORMED_OUTPUT",
                }
            ),
        )
        self.assertEqual(
            rs.GAP_EXECUTION_REQUIRED_TRIGGERS,
            frozenset(rs.GAP_CODES_ALL - {"SEMANTIC_MODEL_OFF"}),
        )


class ImportSideEffectTests(unittest.TestCase):
    """Packet §8 compatibility: importing the module has zero side effects."""

    def test_double_import_returns_same_module_and_raises_nothing(self) -> None:
        first = importlib.import_module("lima.audit.ram_schema")
        second = importlib.import_module("lima.audit.ram_schema")
        self.assertIs(first, second)
        self.assertTrue(callable(first.ram_wire_payload))


if __name__ == "__main__":
    unittest.main()
