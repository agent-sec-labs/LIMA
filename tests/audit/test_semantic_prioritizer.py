"""IP-0019 acceptance tests: semantic prioritizer / Top-N (Packet v1 §6/§7).

Matrix traceability (Packet IP-0019-PACKET/v1 §6): every test below maps to
exactly one matrix row -- degradation D1..D8 (10), candidate-ID collision
(B-7, 4), determinism/identity (FR-04, 5), scoring/Top-N (A-1/B-6, 4),
budget interception (A-2, 5), zero-paid-call/zero-network (A-2, 3), FR-03
invariants (4), malformed subdivision (3), regression/boundary (4), B-10
independent carrier (1), NFR-01 semantic re-check (1) -- 44 cases total.

PI-DR1: fixtures are materialized via ``workspace_with`` which pins
``newline="\\n"``; path assertions use POSIX literals only. The module under
test is imported in ``setUp`` so the module-absence RED anchor (PI-DR4) fails
each case individually instead of hiding behind a module-level import error.
"""

from __future__ import annotations

import ast
import json
import re
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from lima.audit.ram import build_python_ram_facts, ram_facts_digest
from tests.audit.fixtures.repo_shapes import workspace_with
from tests.audit.fixtures.semantic.fakes import (
    ScriptedModelClient,
    valid_batch_response,
)
from tests.audit.fixtures.semantic.shapes import MANY_SINK_REPO, MIXED_REPO

IP0016_IP0018_ALL_PREFIX = [
    "GAP_BUDGET_EXHAUSTED",
    "GAP_INVENTORY_SKIPPED",
    "GAP_MANIFEST_PARSE_ERROR",
    "GAP_NO_LANGUAGES_DETECTED",
    "GAP_UNSUPPORTED_LANGUAGE",
    "PROFILE_PROVENANCE_ANCHOR",
    "SKIP_REASON_TO_GAP_DETAIL",
    "ProfileBudgets",
    "ProfileBuildResult",
    "ProfileInventoryOptions",
    "build_repository_profile",
    "GAP_AMBIGUOUS_DISPATCH",
    "GAP_DYNAMIC_IMPORT",
    "PythonRamFacts",
    "RAM_PROVENANCE_ANCHOR",
    "RamBudgets",
    "RamFactsBuildResult",
    "RamKeyFlow",
    "build_python_ram_facts",
    "ram_facts_digest",
]

IP0019_NEW_SYMBOLS = sorted(
    [
        "GAP_SEMANTIC_MALFORMED_OUTPUT",
        "GAP_SEMANTIC_MODEL_OFF",
        "GAP_SEMANTIC_MODEL_TIMEOUT",
        "SEMANTIC_CATEGORY_CODE_EXECUTION",
        "SEMANTIC_CATEGORY_COMMAND_EXECUTION",
        "SEMANTIC_CATEGORY_DESERIALIZATION",
        "SEMANTIC_CATEGORY_ENTRYPOINT",
        "SEMANTIC_CATEGORY_EXTERNAL_INPUT",
        "SEMANTIC_CATEGORY_PATH_TRAVERSAL",
        "SEMANTIC_CATEGORY_SQL_INJECTION",
        "SEMANTIC_CATEGORY_TRUST_BOUNDARY",
        "SEMANTIC_CATEGORY_UNRESOLVED_EDGE",
        "SEMANTIC_MAX_TOP_N",
        "SEMANTIC_PROVENANCE_ANCHOR",
        "SemanticBudgets",
        "SemanticCandidate",
        "SemanticModelClient",
        "SemanticOptions",
        "SemanticTopNResult",
        "SemanticWeights",
        "build_semantic_top_n",
        "candidate_id",
        "semantic_config_digest",
        "semantic_result_digest",
    ]
)

ENRICHED_CATEGORY = "path-traversal"
ENRICHED_RATIONALE = "model-enriched"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class SemanticTestBase(unittest.TestCase):
    sp: Any

    def setUp(self) -> None:
        import lima.audit.semantic_prioritizer as semantic_prioritizer

        self.sp = semantic_prioritizer

    def facts_of(self, repo: dict[str, str]) -> Any:
        with workspace_with(repo) as workspace:
            return build_python_ram_facts(workspace).facts

    def options(self, **overrides: Any) -> Any:
        return self.sp.SemanticOptions(**overrides)

    def build(self, facts: Any, *, options: Any = None, client: Any = None) -> Any:
        kwargs: dict[str, Any] = {}
        if options is not None:
            kwargs["options"] = options
        if client is not None:
            kwargs["model_client"] = client
        return self.sp.build_semantic_top_n(facts, **kwargs)

    def model_options(self, **overrides: Any) -> Any:
        values: dict[str, Any] = {"model_id": "fake-model"}
        values.update(overrides)
        return self.sp.SemanticOptions(**values)

    def processing_ids(self, facts: Any, **overrides: Any) -> list[str]:
        """Return candidate IDs in frozen processing order (full set)."""

        result = self.build(
            facts, options=self.options(top_n=100, **overrides)
        )
        return [item.candidate_id for item in result.ranked]

    def responses_for_batches(
        self, ids: list[str], *, batch_cap: int, corrupt_batches: set[int]
    ) -> list[str]:
        responses: list[str] = []
        index = 0
        batch_index = 0
        while index < len(ids):
            batch = ids[index : index + batch_cap]
            if batch_index in corrupt_batches:
                responses.append("{not json")
            else:
                responses.append(
                    valid_batch_response(
                        [
                            (cid, ENRICHED_CATEGORY, ENRICHED_RATIONALE)
                            for cid in batch
                        ]
                    )
                )
            index += len(batch)
            batch_index += 1
        return responses

    def batch_count(self, ids: list[str], batch_cap: int) -> int:
        return (len(ids) + batch_cap - 1) // batch_cap

    def padded(
        self, responses: list[str | Exception], ids: list[str], batch_cap: int
    ) -> list[str | Exception]:
        """Pad scripted responses with empty valid batches (model returns [])."""

        needed = self.batch_count(ids, batch_cap) - len(responses)
        return list(responses) + ["[]"] * max(0, needed)

    def gap_codes(self, result: Any) -> list[str]:
        return [gap.gap_code for gap in result.coverage_gaps]

    def gap_detail(self, result: Any, gap_code: str) -> str:
        matches = [
            gap.detail for gap in result.coverage_gaps if gap.gap_code == gap_code
        ]
        self.assertEqual(len(matches), 1, matches)
        return matches[0]


class DegradationMatrixTests(SemanticTestBase):
    """Packet §5.6.5 -- D1..D8, gap accumulation and the A-4 note wording."""

    def test_degradation_d1_off_candidates_below_n(self) -> None:
        facts = self.facts_of(MIXED_REPO)
        result = self.build(facts)
        self.assertEqual(len(result.ranked), result.total_candidates)
        self.assertEqual(len(result.ranked), 18)
        self.assertEqual(
            [item.rank for item in result.ranked], list(range(1, 19))
        )
        self.assertEqual(self.gap_codes(result), ["SEMANTIC_MODEL_OFF"])
        self.assertEqual(
            self.gap_detail(result, "SEMANTIC_MODEL_OFF"),
            "reason=model-disabled; candidates=18",
        )
        for item in result.ranked:
            self.assertTrue(item.rationale)

    def test_degradation_d2_off_truncated_to_n(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        result = self.build(facts, options=self.options(top_n=5))
        self.assertEqual(len(result.ranked), 5)
        self.assertEqual(result.total_candidates, 25)
        self.assertEqual(self.gap_codes(result), ["SEMANTIC_MODEL_OFF"])

    def test_degradation_d3_timeout_stops_all_calls(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        client = ScriptedModelClient([TimeoutError("boom")])
        result = self.build(
            facts, options=self.model_options(), client=client
        )
        self.assertEqual(client.call_count, 1)
        self.assertTrue(
            all(1 <= value <= 120 for value in client.timeout_seconds_seen)
        )
        self.assertEqual(self.gap_codes(result), ["SEMANTIC_MODEL_TIMEOUT"])
        self.assertEqual(
            self.gap_detail(result, "SEMANTIC_MODEL_TIMEOUT"),
            "reason=model-timeout; batch=0",
        )
        off = self.build(facts, options=self.model_options())
        self.assertEqual(result.ranked, off.ranked)

    def test_degradation_d4_malformed_batch_continues(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        ids = self.processing_ids(facts, model_id="fake-model")
        client = ScriptedModelClient(
            self.responses_for_batches(ids, batch_cap=8, corrupt_batches={0})
        )
        result = self.build(
            facts, options=self.model_options(), client=client
        )
        self.assertEqual(client.call_count, 4)
        self.assertEqual(self.gap_codes(result), ["SEMANTIC_MALFORMED_OUTPUT"])
        self.assertTrue(
            self.gap_detail(result, "SEMANTIC_MALFORMED_OUTPUT").startswith(
                "batch=0; offending="
            )
        )
        first_batch = {item.candidate_id for item in result.ranked[:8]}
        for item in result.ranked:
            if item.candidate_id in first_batch:
                self.assertNotEqual(item.rationale, ENRICHED_RATIONALE)
            else:
                self.assertEqual(item.rationale, ENRICHED_RATIONALE)

    def test_degradation_d5_board_full_no_new_budget_gap(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        ids = self.processing_ids(facts, model_id="fake-model")
        client = ScriptedModelClient(
            self.responses_for_batches(ids[:8], batch_cap=8, corrupt_batches=set())
        )
        with mock.patch.object(
            self.sp.time, "monotonic", side_effect=[100.0, 100.0, 300.0]
        ):
            result = self.build(
                facts, options=self.model_options(top_n=5), client=client
            )
        self.assertEqual(client.call_count, 1)
        self.assertEqual(result.coverage_gaps, ())
        for item in result.ranked:
            self.assertEqual(item.rationale, ENRICHED_RATIONALE)

    def test_degradation_d6_budget_stop_pending_gap(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        budgets = self.sp.SemanticBudgets(max_llm_calls=1)
        first_id = self.processing_ids(facts)[0]
        client = ScriptedModelClient(
            [valid_batch_response([(first_id, ENRICHED_CATEGORY, ENRICHED_RATIONALE)])]
        )
        result = self.build(
            facts, options=self.model_options(budgets=budgets), client=client
        )
        self.assertEqual(client.call_count, 1)
        self.assertEqual(self.gap_codes(result), ["BUDGET_EXHAUSTED"])
        self.assertEqual(
            self.gap_detail(result, "BUDGET_EXHAUSTED"),
            "reason=semantic-budget; stage=llm-calls; pending=24;"
            " note=semantic-coverage-incomplete; not-an-absence-of-risk",
        )
        self.assertEqual(result.ranked[0].rationale, ENRICHED_RATIONALE)
        self.assertNotEqual(result.ranked[1].rationale, ENRICHED_RATIONALE)

    def test_degradation_d7_malformed_then_budget_stop(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        ids = self.processing_ids(facts, model_id="fake-model")
        budgets = self.sp.SemanticBudgets(max_llm_calls=2)
        client = ScriptedModelClient(
            [
                "{not json",
                valid_batch_response(
                    [
                        (cid, ENRICHED_CATEGORY, ENRICHED_RATIONALE)
                        for cid in ids[2:4]
                    ]
                ),
            ]
        )
        result = self.build(
            facts, options=self.model_options(budgets=budgets), client=client
        )
        self.assertEqual(client.call_count, 2)
        self.assertEqual(
            self.gap_codes(result), ["BUDGET_EXHAUSTED", "SEMANTIC_MALFORMED_OUTPUT"]
        )

    def test_degradation_d8_normal_completion_below_n(self) -> None:
        facts = self.facts_of(MIXED_REPO)
        ids = self.processing_ids(facts, model_id="fake-model")
        client = ScriptedModelClient(
            self.responses_for_batches(ids, batch_cap=8, corrupt_batches=set())
        )
        result = self.build(
            facts, options=self.model_options(), client=client
        )
        self.assertEqual(len(result.ranked), result.total_candidates)
        self.assertEqual(result.coverage_gaps, ())
        for item in result.ranked:
            self.assertEqual(item.rationale, ENRICHED_RATIONALE)

    def test_gap_accumulation_preserves_earlier_gaps(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        ids = self.processing_ids(facts, model_id="fake-model")
        budgets = self.sp.SemanticBudgets(max_llm_calls=2)
        client = ScriptedModelClient(
            [
                "{not json",
                valid_batch_response(
                    [
                        (cid, ENRICHED_CATEGORY, ENRICHED_RATIONALE)
                        for cid in ids[2:4]
                    ]
                ),
            ]
        )
        result = self.build(
            facts, options=self.model_options(budgets=budgets), client=client
        )
        pairs = [(gap.gap_code, gap.detail) for gap in result.coverage_gaps]
        self.assertEqual(pairs, sorted(pairs))
        self.assertIn("SEMANTIC_MALFORMED_OUTPUT", self.gap_codes(result))
        self.assertIn("BUDGET_EXHAUSTED", self.gap_codes(result))

    def test_budget_gap_not_absence_of_risk(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        budgets = self.sp.SemanticBudgets(max_llm_calls=1)
        first_id = self.processing_ids(facts)[0]
        client = ScriptedModelClient(
            [valid_batch_response([(first_id, ENRICHED_CATEGORY, ENRICHED_RATIONALE)])]
        )
        result = self.build(
            facts, options=self.model_options(budgets=budgets), client=client
        )
        detail = self.gap_detail(result, "BUDGET_EXHAUSTED")
        self.assertIn("note=semantic-coverage-incomplete; not-an-absence-of-risk", detail)
        self.assertIn("stage=llm-calls", detail)
        self.assertRegex(detail, r"pending=\d+")


class CandidateIdCollisionTests(SemanticTestBase):
    """Packet §5.2.1 -- B-7 frozen candidate ID rules."""

    def test_candidate_id_format_and_same_path_sinks_distinct(self) -> None:
        self.assertEqual(
            self.sp.candidate_id("sensitive-sink", "a.py", None, 3),
            "sensitive-sink:a.py:-#3",
        )
        self.assertEqual(
            self.sp.candidate_id("entrypoint", "a.py", "main", 0),
            "entrypoint:a.py:main#0",
        )
        facts = self.facts_of(MANY_SINK_REPO)
        result = self.build(facts, options=self.options(top_n=100))
        sink_ids = [
            item.candidate_id
            for item in result.ranked
            if item.kind == "sensitive-sink"
        ]
        self.assertEqual(len(sink_ids), 12)
        self.assertEqual(len(set(sink_ids)), 12)
        self.assertEqual(
            sink_ids,
            [f"sensitive-sink:danger.py:-#{index}" for index in range(12)],
        )

    def test_candidate_id_cross_kind_no_collision(self) -> None:
        facts = self.facts_of(MIXED_REPO)
        result = self.build(facts, options=self.options(top_n=100))
        ids = [item.candidate_id for item in result.ranked]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("sensitive-sink:sinks.py:-#0", ids)
        self.assertIn("trust-boundary:sinks.py:-#2", ids)

    def test_candidate_id_replay_same_set(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        first = self.processing_ids(facts)
        second = self.processing_ids(facts)
        self.assertEqual(first, second)

    def test_candidate_id_order_stability_under_full_ties(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        result = self.build(facts, options=self.options(top_n=20))
        sink_ids = [
            item.candidate_id
            for item in result.ranked
            if item.kind == "sensitive-sink"
        ]
        self.assertEqual(
            sink_ids, sorted(sink_ids, key=lambda value: int(value.rsplit("#", 1)[1]))
        )


class DeterminismIdentityTests(SemanticTestBase):
    """Packet §5.1/§5.7 -- FR-04 identity, seed, digest composition."""

    def test_identity_stable_same_inputs(self) -> None:
        facts = self.facts_of(MIXED_REPO)
        options = self.model_options()
        first = self.build(facts, options=options)
        second = self.build(facts, options=options)
        self.assertEqual(first.ranked, second.ranked)
        self.assertEqual(first.config_digest, second.config_digest)
        self.assertEqual(first.result_digest, second.result_digest)
        self.assertEqual(first.coverage_gaps, second.coverage_gaps)

    def test_seed_changes_digest_only(self) -> None:
        facts = self.facts_of(MIXED_REPO)
        zero = self.build(facts, options=self.options(seed=0))
        seven = self.build(facts, options=self.options(seed=7))
        self.assertEqual(zero.ranked, seven.ranked)
        self.assertNotEqual(zero.config_digest, seven.config_digest)
        self.assertNotEqual(zero.result_digest, seven.result_digest)

    def test_config_digest_sensitivity(self) -> None:
        base = self.options()
        variants = [
            self.options(top_n=19),
            self.options(weights=self.sp.SemanticWeights(entrypoint=61)),
            self.options(budgets=self.sp.SemanticBudgets(max_llm_calls=7)),
            self.options(model_id="other-model"),
            self.options(prompt_template="other template"),
        ]
        base_digest = self.sp.semantic_config_digest(base)
        for variant in variants:
            self.assertNotEqual(
                self.sp.semantic_config_digest(variant), base_digest
            )

    def test_digest_excludes_elapsed_time(self) -> None:
        facts = self.facts_of(MIXED_REPO)
        ids = self.processing_ids(facts, model_id="fake-model")
        responses = self.responses_for_batches(
            ids, batch_cap=8, corrupt_batches=set()
        )
        fast = ScriptedModelClient(list(responses))
        slow = ScriptedModelClient(list(responses), sleep_seconds=0.02)
        fast_result = self.build(
            facts, options=self.model_options(), client=fast
        )
        slow_result = self.build(
            facts, options=self.model_options(), client=slow
        )
        self.assertEqual(fast_result.ranked, slow_result.ranked)
        self.assertEqual(fast_result.result_digest, slow_result.result_digest)

    def test_digest_hex64_and_recompute(self) -> None:
        facts = self.facts_of(MIXED_REPO)
        options = self.model_options()
        result = self.build(facts, options=options)
        for digest in (
            result.prompt_digest,
            result.model_digest,
            result.config_digest,
            result.result_digest,
        ):
            self.assertRegex(digest, _HEX64)
        self.assertEqual(
            self.sp.semantic_config_digest(options), result.config_digest
        )
        self.assertEqual(
            self.sp.semantic_result_digest(
                result, input_facts_digest=ram_facts_digest(facts)
            ),
            result.result_digest,
        )


class ScoringTopNTests(SemanticTestBase):
    """Packet §5.2.3/§5.1 -- B-6 frozen scoring and A-1 bounds."""

    def test_default_weight_order_and_categories(self) -> None:
        facts = self.facts_of(MIXED_REPO)
        result = self.build(facts)
        scores = [item.score for item in result.ranked]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(result.ranked[0].score, 90)
        self.assertEqual(result.ranked[0].category, "code-execution")
        sink_categories = {
            item.category
            for item in result.ranked
            if item.kind == "sensitive-sink"
        }
        self.assertIn("sql-injection", sink_categories)
        self.assertIn("command-execution", sink_categories)
        self.assertIn("path-traversal", sink_categories)
        self.assertIn("deserialization", sink_categories)
        first_rank: dict[str, int] = {}
        for item in result.ranked:
            first_rank.setdefault(item.kind, item.rank)
        self.assertLess(
            first_rank["entrypoint"],
            min(first_rank["external-source"], first_rank["trust-boundary"]),
        )
        self.assertLess(first_rank["trust-boundary"], first_rank["unresolved-edge"])

    def test_custom_weights_change_order(self) -> None:
        facts = self.facts_of(MIXED_REPO)
        weights = self.sp.SemanticWeights(entrypoint=200)
        result = self.build(facts, options=self.options(weights=weights))
        self.assertEqual(result.ranked[0].kind, "entrypoint")
        self.assertEqual(result.ranked[0].score, 200)

    def test_tie_break_full_order_no_equal_ids(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        result = self.build(facts, options=self.options(top_n=20))
        ids = [item.candidate_id for item in result.ranked]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(
            [item.rank for item in result.ranked], list(range(1, 21))
        )

    def test_top_n_truncation_and_bounds(self) -> None:
        facts = self.facts_of(MIXED_REPO)
        result = self.build(facts, options=self.options(top_n=3))
        self.assertEqual([item.rank for item in result.ranked], [1, 2, 3])
        self.assertEqual(result.total_candidates, 18)
        self.options(top_n=100)
        for bad in (101, 0, -5):
            with self.assertRaises(ValueError):
                self.options(top_n=bad)


class BudgetInterceptionTests(SemanticTestBase):
    """Packet §5.3/§5.5 -- A-2 pre-call checkpoints, fail-closed degrade."""

    def test_budget_llm_calls_intercept_before_second_call(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        ids = self.processing_ids(facts, model_id="fake-model")
        budgets = self.sp.SemanticBudgets(max_llm_calls=1)
        client = ScriptedModelClient(
            [valid_batch_response([(ids[0], ENRICHED_CATEGORY, ENRICHED_RATIONALE)])]
        )
        result = self.build(
            facts, options=self.model_options(budgets=budgets), client=client
        )
        self.assertEqual(client.call_count, 1)
        self.assertIn("stage=llm-calls", self.gap_detail(result, "BUDGET_EXHAUSTED"))

    def test_budget_prompt_tokens_intercept_before_first_call(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        budgets = self.sp.SemanticBudgets(
            max_llm_calls=8,
            max_prompt_tokens_estimate=1,
            max_output_tokens_estimate=1,
            max_total_tokens_estimate=100_000,
        )
        client = ScriptedModelClient(["[]"])
        result = self.build(
            facts, options=self.model_options(budgets=budgets), client=client
        )
        self.assertEqual(client.call_count, 0)
        self.assertIn(
            "stage=prompt-tokens", self.gap_detail(result, "BUDGET_EXHAUSTED")
        )

    def test_budget_output_tokens_intercept_before_first_call(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        budgets = self.sp.SemanticBudgets(
            max_llm_calls=8,
            max_prompt_tokens_estimate=100_000,
            max_output_tokens_estimate=1,
            max_total_tokens_estimate=200_000,
        )
        client = ScriptedModelClient(["[]"])
        result = self.build(
            facts, options=self.model_options(budgets=budgets), client=client
        )
        self.assertEqual(client.call_count, 0)
        self.assertIn(
            "stage=output-tokens", self.gap_detail(result, "BUDGET_EXHAUSTED")
        )

    def test_budget_wall_time_intercept(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        client = ScriptedModelClient(["[]"])
        with mock.patch.object(
            self.sp.time, "monotonic", side_effect=[100.0, 100.0, 300.0]
        ):
            result = self.build(
                facts, options=self.model_options(), client=client
            )
        self.assertEqual(client.call_count, 1)
        self.assertIn("stage=wall-time", self.gap_detail(result, "BUDGET_EXHAUSTED"))

    def test_budget_invariant_value_error(self) -> None:
        with self.assertRaises(ValueError):
            self.sp.SemanticBudgets(
                max_llm_calls=8,
                max_prompt_tokens_estimate=100,
                max_output_tokens_estimate=100,
                max_total_tokens_estimate=150,
            )


class ZeroPaidCallTests(SemanticTestBase):
    """Packet §5.4.1/§5.8 -- A-2 explicit opt-in, zero paid calls/network."""

    def test_model_id_unset_with_client_is_off(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        client = ScriptedModelClient(["[]"])
        result = self.build(facts, client=client)
        self.assertEqual(client.call_count, 0)
        self.assertEqual(self.gap_codes(result), ["SEMANTIC_MODEL_OFF"])
        off = self.build(facts)
        self.assertEqual(result.ranked, off.ranked)

    def test_model_id_set_without_client_is_off(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        result = self.build(facts, options=self.model_options())
        self.assertEqual(self.gap_codes(result), ["SEMANTIC_MODEL_OFF"])
        off = self.build(facts)
        self.assertEqual(result.ranked, off.ranked)

    def test_static_no_network_subprocess_environ_or_writes(self) -> None:
        source = Path(self.sp.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        forbidden_modules = {
            "socket", "ssl", "http", "urllib", "requests", "subprocess",
            "ftplib", "telnetlib", "os", "sys", "pathlib", "shutil",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                names = {node.module.split(".")[0]} if node.module else set()
            else:
                names = set()
            self.assertEqual(names & forbidden_modules, set(), names)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                self.assertNotIn(
                    node.attr, {"environ", "getenv", "urlopen", "socket", "write"}
                )
            if isinstance(node, ast.Name):
                self.assertNotIn(node.id, {"open", "system", "popen", "Popen"})


class Fr03InvariantTests(SemanticTestBase):
    """Packet §5.2 -- FR-03: Tier 0 immutable, no invented candidates."""

    def test_facts_digest_unchanged_by_semantic_layer(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        before = ram_facts_digest(facts)
        ids = self.processing_ids(facts, model_id="fake-model")
        client = ScriptedModelClient(
            self.responses_for_batches(ids, batch_cap=8, corrupt_batches={1})
        )
        self.build(facts, options=self.model_options(), client=client)
        self.assertEqual(ram_facts_digest(facts), before)
        self.assertEqual(facts.sensitive_sinks, self.facts_of(MANY_SINK_REPO).sensitive_sinks)

    def test_unauthorized_candidate_id_is_malformed(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        ids = self.processing_ids(facts, model_id="fake-model")
        payload = json.dumps(
            [
                {
                    "candidate_id": ids[0],
                    "category": ENRICHED_CATEGORY,
                    "rationale": ENRICHED_RATIONALE,
                },
                {
                    "candidate_id": "sensitive-sink:ghost.py:-#99",
                    "category": ENRICHED_CATEGORY,
                    "rationale": ENRICHED_RATIONALE,
                },
            ]
        )
        client = ScriptedModelClient(self.padded([payload], ids, 8))
        result = self.build(
            facts, options=self.model_options(), client=client
        )
        self.assertEqual(self.gap_codes(result), ["SEMANTIC_MALFORMED_OUTPUT"])
        off = self.build(facts, options=self.model_options())
        self.assertEqual(
            [item.candidate_id for item in result.ranked],
            [item.candidate_id for item in off.ranked],
        )

    def test_model_cannot_change_score_or_rank(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        ids = self.processing_ids(facts, model_id="fake-model")
        entries = [
            {
                "candidate_id": cid,
                "category": ENRICHED_CATEGORY,
                "rationale": ENRICHED_RATIONALE,
                "score": 9999,
                "rank": 1,
            }
            for cid in reversed(ids[:8])
        ]
        client = ScriptedModelClient(self.padded([json.dumps(entries)], ids, 8))
        result = self.build(
            facts, options=self.model_options(), client=client
        )
        off = self.build(facts, options=self.model_options())
        self.assertEqual(
            [(item.score, item.rank, item.candidate_id) for item in result.ranked],
            [(item.score, item.rank, item.candidate_id) for item in off.ranked],
        )
        self.assertEqual(result.ranked[0].rationale, ENRICHED_RATIONALE)

    def test_rationale_leak_falls_back(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        ids = self.processing_ids(facts, model_id="fake-model")
        for leak in (
            "calls os.system(request.args.get('cmd')) directly",
            "token AKIAIOSFODNN7EXAMPLE was seen",
        ):
            client = ScriptedModelClient(
                self.padded(
                    [valid_batch_response([(ids[0], ENRICHED_CATEGORY, leak)])],
                    ids,
                    8,
                )
            )
            result = self.build(
                facts, options=self.model_options(), client=client
            )
            self.assertEqual(
                self.gap_codes(result), ["SEMANTIC_MALFORMED_OUTPUT"], leak
            )
            self.assertNotEqual(result.ranked[0].rationale, leak)


class MalformedSubdivisionTests(SemanticTestBase):
    """Packet §5.4.3 -- malformed output classification."""

    def test_malformed_non_json(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        ids = self.processing_ids(facts, model_id="fake-model")
        client = ScriptedModelClient(self.padded(["not json {"], ids, 8))
        result = self.build(
            facts, options=self.model_options(), client=client
        )
        self.assertEqual(self.gap_codes(result), ["SEMANTIC_MALFORMED_OUTPUT"])
        self.assertTrue(
            self.gap_detail(result, "SEMANTIC_MALFORMED_OUTPUT").startswith(
                "batch=0; offending=json"
            )
        )

    def test_malformed_category_out_of_vocabulary(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        ids = self.processing_ids(facts, model_id="fake-model")
        client = ScriptedModelClient(
            self.padded(
                [valid_batch_response([(ids[0], "buffer-overflow", "why not")])],
                ids,
                8,
            )
        )
        result = self.build(
            facts, options=self.model_options(), client=client
        )
        self.assertEqual(self.gap_codes(result), ["SEMANTIC_MALFORMED_OUTPUT"])
        self.assertTrue(
            self.gap_detail(result, "SEMANTIC_MALFORMED_OUTPUT").startswith(
                "batch=0; offending=category"
            )
        )

    def test_rationale_empty_rejected_and_oversize_truncated(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        ids = self.processing_ids(facts, model_id="fake-model")
        empty_client = ScriptedModelClient(
            self.padded(
                [valid_batch_response([(ids[0], ENRICHED_CATEGORY, "   ")])],
                ids,
                8,
            )
        )
        empty_result = self.build(
            facts, options=self.model_options(), client=empty_client
        )
        self.assertEqual(
            self.gap_codes(empty_result), ["SEMANTIC_MALFORMED_OUTPUT"]
        )
        oversize = "long rationale " * 100
        oversize_client = ScriptedModelClient(
            self.padded(
                [valid_batch_response([(ids[0], ENRICHED_CATEGORY, oversize)])],
                ids,
                8,
            )
        )
        oversize_result = self.build(
            facts, options=self.model_options(), client=oversize_client
        )
        self.assertEqual(oversize_result.coverage_gaps, ())
        self.assertLessEqual(
            len(oversize_result.ranked[0].rationale.encode("utf-8")), 512
        )


class RegressionBoundaryTests(SemanticTestBase):
    """Packet §6 regression row -- IP-0016/0018 surface and fail-closed."""

    def test_audit_all_prefix_unchanged_and_new_symbols_appended(self) -> None:
        import lima.audit as audit

        self.assertEqual(list(audit.__all__[:20]), IP0016_IP0018_ALL_PREFIX)
        self.assertEqual(audit.__all__[20:44], IP0019_NEW_SYMBOLS)
        self.assertGreaterEqual(len(audit.__all__), 44)
        for name in IP0019_NEW_SYMBOLS:
            self.assertTrue(hasattr(audit, name), name)

    def test_invalid_inputs_fail_closed(self) -> None:
        from lima.contracts.errors import ContractError

        facts = self.facts_of(MIXED_REPO)
        with self.assertRaises(ContractError):
            self.sp.build_semantic_top_n("not-facts")
        with self.assertRaises(ContractError):
            self.sp.build_semantic_top_n(facts, options="not-options")
        with self.assertRaises(ContractError):
            self.sp.build_semantic_top_n(facts, model_client=object())

    def test_options_validation_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            self.options(seed=-1)
        with self.assertRaises(ValueError):
            self.options(tie_break="free-text")
        with self.assertRaises(ValueError):
            self.sp.SemanticWeights(entrypoint=-1)
        with self.assertRaises(ValueError):
            self.sp.SemanticBudgets(max_llm_calls=0)

    def test_independent_carrier_no_profile_extensions(self) -> None:
        source = Path(self.sp.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "SemanticTopNResult":
                fields = {
                    statement.target.id
                    for statement in node.body
                    if isinstance(statement, ast.AnnAssign)
                    and isinstance(statement.target, ast.Name)
                }
                self.assertIn("config_digest", fields)
                self.assertIn("result_digest", fields)
                self.assertNotIn("extensions", fields)
            if isinstance(node, ast.Attribute):
                self.assertNotEqual(node.attr, "RepositoryProfile")
            if isinstance(node, ast.Name):
                self.assertNotEqual(node.id, "RepositoryProfile")
        facts = self.facts_of(MIXED_REPO)
        result = self.build(facts)
        self.assertEqual(result.provenance_anchor_ids, ("semantic-prioritizer",))


class Nfr01SemanticLayerTests(SemanticTestBase):
    """Packet §5.8 -- NFR-01 semantic-layer re-check."""

    def test_paths_repo_relative_and_no_source_text(self) -> None:
        facts = self.facts_of(MANY_SINK_REPO)
        facts_paths = {
            entry.path
            for group in (
                facts.entrypoints,
                facts.external_sources,
                facts.sensitive_sinks,
                facts.trust_boundaries,
                facts.unresolved_edges,
            )
            for entry in group
        }
        ids = self.processing_ids(facts, model_id="fake-model")
        client = ScriptedModelClient(
            self.responses_for_batches(ids, batch_cap=8, corrupt_batches=set())
        )
        result = self.build(
            facts, options=self.model_options(), client=client
        )
        for item in result.ranked:
            self.assertFalse(item.path.startswith(("/", "\\")))
            self.assertNotIn("\\", item.path)
            self.assertIn(item.path, facts_paths)
            for step in item.key_flow_steps:
                self.assertRegex(step, r"[^:]+:\d+")
        for prompt in client.calls:
            self.assertNotIn("os.system", prompt)
            self.assertNotIn("request.args.get", prompt)
        board_text = "\n".join(
            [item.rationale for item in result.ranked]
            + [item.path for item in result.ranked]
        )
        self.assertNotIn("os.system", board_text)
        self.assertNotIn("AKIA", board_text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
