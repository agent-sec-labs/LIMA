"""IP-0021 acceptance tests: FR-05 residual gap encoding (Packet §5.4/§6).

Covers: ``GAP_MANIFEST_PARSE_ERROR`` encoding, unsupported-subset typed gap
encoding via the frozen skip-reason mapping, the DR-IP-0021-0102 DR-1
(amendment C) nine-code ``execution_required`` rule table, and the IP-0019
gap-① generic-exception regression. The module under test is imported
lazily per test (PI-DR4 module-absence anchor).
"""

from __future__ import annotations

import importlib
import unittest
from typing import Any

from lima.audit import build_python_ram_facts, build_semantic_top_n
from lima.audit.inventory import (
    GAP_BUDGET_EXHAUSTED,
    GAP_MANIFEST_PARSE_ERROR,
    GAP_UNSUPPORTED_LANGUAGE,
    SKIP_REASON_TO_GAP_DETAIL,
    build_repository_profile,
)
from lima.contracts.errors import ContractError
from tests.audit.fixtures.ram.shapes import DYNAMIC_IMPORT_REPO
from tests.audit.fixtures.repo_shapes import profile_kwargs, workspace_with
from tests.audit.fixtures.semantic.fakes import ScriptedModelClient

TRIGGER_CODES: tuple[str, ...] = (
    "BUDGET_EXHAUSTED",
    "INVENTORY_SKIPPED",
    "MANIFEST_PARSE_ERROR",
    "NO_LANGUAGES_DETECTED",
    "UNSUPPORTED_LANGUAGE",
    "DYNAMIC_IMPORT",
    "AMBIGUOUS_DISPATCH",
    "SEMANTIC_MODEL_TIMEOUT",
    "SEMANTIC_MALFORMED_OUTPUT",
)
NON_TRIGGER_CODES: tuple[str, ...] = ("SEMANTIC_MODEL_OFF",)
ALL_CODES: frozenset[str] = frozenset(TRIGGER_CODES + NON_TRIGGER_CODES)

FROZEN_SKIP_REASONS: frozenset[str] = frozenset(
    {
        "binary",
        "file-limit",
        "file-size-limit",
        "ignored-directory",
        "non-utf8",
        "sensitive-config",
        "symlink",
        "total-size-limit",
        "unreadable",
        "unsupported-extension",
    }
)

GENERIC_EXCEPT_REPO: dict[str, str] = {
    "wide.py": (
        "from framework import request\n"
        "\n"
        "\n"
        "def risky(request):\n"
        "    try:\n"
        "        return request.args.get('q')\n"
        "    except:\n"
        "        return None\n"
    ),
    "broad.py": (
        "import os\n"
        "from framework import request\n"
        "\n"
        "\n"
        "def run(request):\n"
        "    try:\n"
        "        os.system(request.args.get('cmd'))\n"
        "    except Exception:\n"
        "        pass\n"
    ),
    "plain.py": "def helper(value):\n    return value + 1\n",
}


def rs_module() -> Any:
    return importlib.import_module("lima.audit.ram_schema")


def profile_gaps(files: dict[str, str]) -> list[tuple[str, str]]:
    with workspace_with(files) as workspace:
        result = build_repository_profile(workspace, **profile_kwargs())
    return [(gap.gap_code, gap.detail) for gap in result.profile.coverage_gaps]


class ManifestParseErrorTests(unittest.TestCase):
    """GAP_MANIFEST_PARSE_ERROR encoding: frozen code + frozen detail."""

    def setUp(self) -> None:
        rs_module()  # module-absence RED anchor (PI-DR4)

    def test_broken_pyproject_toml_yields_frozen_code_and_detail(self) -> None:
        gaps = profile_gaps({"pyproject.toml": "[[[not toml\n", "a.py": "X = 1\n"})
        self.assertIn(
            ("MANIFEST_PARSE_ERROR", "manifest=pyproject.toml; error=TOMLDecodeError"),
            gaps,
        )

    def test_broken_package_json_yields_frozen_code_and_detail(self) -> None:
        gaps = profile_gaps({"package.json": "{not json", "a.py": "X = 1\n"})
        self.assertIn(
            ("MANIFEST_PARSE_ERROR", "manifest=package.json; error=JSONDecodeError"),
            gaps,
        )

    def test_broken_manifest_in_level_one_directory_is_typed_not_fatal(self) -> None:
        gaps = profile_gaps(
            {"pkg/pyproject.toml": "]]]bad\n", "pkg/__init__.py": "", "b.py": "Y = 2\n"}
        )
        self.assertIn(
            (
                "MANIFEST_PARSE_ERROR",
                "manifest=pkg/pyproject.toml; error=TOMLDecodeError",
            ),
            gaps,
        )
        self.assertTrue(all(code == GAP_MANIFEST_PARSE_ERROR for code, _ in gaps))


class SkipReasonMappingTests(unittest.TestCase):
    """Unsupported-subset typed gap encoding via the frozen skip mapping."""

    def setUp(self) -> None:
        rs_module()  # module-absence RED anchor (PI-DR4)

    def test_skip_reason_table_covers_frozen_reason_set(self) -> None:
        self.assertEqual(frozenset(SKIP_REASON_TO_GAP_DETAIL), FROZEN_SKIP_REASONS)
        for reason in SKIP_REASON_TO_GAP_DETAIL:
            self.assertEqual(
                SKIP_REASON_TO_GAP_DETAIL[reason].format(reason=reason, count=2),
                f"reason={reason}; count=2",
            )

    def test_unsupported_extension_end_to_end_yields_unsupported_language(self) -> None:
        with workspace_with(
            {"main.go": "package main\n", "util.go": "package main\n"},
            extensions=(".py",),
        ) as workspace:
            result = build_repository_profile(workspace, **profile_kwargs())
        codes = [gap.gap_code for gap in result.profile.coverage_gaps]
        details = [gap.detail for gap in result.profile.coverage_gaps]
        self.assertIn(GAP_UNSUPPORTED_LANGUAGE, codes)
        self.assertTrue(
            any(
                detail.startswith("reason=unsupported-extension; count=")
                for detail in details
            ),
            details,
        )

    def test_file_limit_end_to_end_yields_budget_exhausted(self) -> None:
        files = {f"m{i}.py": f"V{i} = {i}\n" for i in range(4)}
        with workspace_with(files, max_files=2) as workspace:
            result = build_repository_profile(workspace, **profile_kwargs())
        codes = [gap.gap_code for gap in result.profile.coverage_gaps]
        details = [gap.detail for gap in result.profile.coverage_gaps]
        self.assertIn(GAP_BUDGET_EXHAUSTED, codes)
        self.assertTrue(
            any(detail.startswith("reason=file-limit; count=") for detail in details),
            details,
        )


class ExecutionRequiredRuleTableTests(unittest.TestCase):
    """DR-IP-0021-0102 DR-1 (amendment C): nine trigger codes, OFF is not."""

    def test_each_trigger_code_alone_sets_required(self) -> None:
        rs = rs_module()
        for code in TRIGGER_CODES:
            with self.subTest(code=code):
                self.assertEqual(
                    rs.execution_required_from_gaps([code]), (True, (code,))
                )

    def test_empty_and_off_only_do_not_set_required(self) -> None:
        rs = rs_module()
        self.assertEqual(rs.execution_required_from_gaps([]), (False, ()))
        self.assertEqual(
            rs.execution_required_from_gaps(["SEMANTIC_MODEL_OFF"]),
            (False, ()),
        )

    def test_mixed_input_is_deduplicated_sorted_and_off_excluded(self) -> None:
        rs = rs_module()
        result = rs.execution_required_from_gaps(
            ["SEMANTIC_MODEL_OFF", "DYNAMIC_IMPORT", "BUDGET_EXHAUSTED", "DYNAMIC_IMPORT"]
        )
        self.assertEqual(result, (True, ("BUDGET_EXHAUSTED", "DYNAMIC_IMPORT")))

    def test_unknown_code_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            rs_module().execution_required_from_gaps(["NOT_A_GAP_CODE"])

    def test_model_off_wire_keeps_gap_but_required_false(self) -> None:
        rs = rs_module()
        import lima.audit.ram as ram
        import lima.audit.semantic_prioritizer as sp
        from tests.audit.fixtures.ram.shapes import SINK_TAINTED_REPO

        with workspace_with(SINK_TAINTED_REPO) as workspace:
            ram_result = build_python_ram_facts(workspace)
        self.assertEqual(ram_result.facts.coverage_gaps, ())
        semantic_result = sp.build_semantic_top_n(ram_result.facts)
        self.assertIn(
            "SEMANTIC_MODEL_OFF",
            [gap.gap_code for gap in semantic_result.coverage_gaps],
        )
        payload = rs.ram_wire_payload(ram_result, semantic_result)
        self.assertFalse(payload["execution_required"]["required"])
        self.assertEqual(payload["execution_required"]["trigger_gap_codes"], [])
        self.assertIn(
            "SEMANTIC_MODEL_OFF",
            [gap["gap_code"] for gap in payload["semantic"]["coverage_gaps"]],
        )
        self.assertEqual(
            payload["identity"]["ram_facts_digest"],
            ram.ram_facts_digest(ram_result.facts),
        )

    def test_gap_triggering_shape_sets_required_with_typed_triggers(self) -> None:
        rs = rs_module()
        with workspace_with(DYNAMIC_IMPORT_REPO) as workspace:
            ram_result = build_python_ram_facts(workspace)
        semantic_result = build_semantic_top_n(ram_result.facts)
        ram_gap_codes = [gap.gap_code for gap in ram_result.facts.coverage_gaps]
        self.assertIn("DYNAMIC_IMPORT", ram_gap_codes)
        payload = rs.ram_wire_payload(ram_result, semantic_result)
        self.assertTrue(payload["execution_required"]["required"])
        self.assertIn(
            "DYNAMIC_IMPORT", payload["execution_required"]["trigger_gap_codes"]
        )
        self.assertEqual(
            [gap["gap_code"] for gap in payload["ram"]["coverage_gaps"]],
            sorted(ram_gap_codes),
        )


class GenericExceptionRegressionTests(unittest.TestCase):
    """IP-0019 gap-①: bare/wide ``except`` shapes stay stable, codes frozen."""

    def setUp(self) -> None:
        rs_module()  # module-absence RED anchor (PI-DR4)

    def test_generic_except_shape_builds_stable_facts(self) -> None:
        def build() -> tuple[str, list[str]]:
            with workspace_with(GENERIC_EXCEPT_REPO) as workspace:
                ram_result = build_python_ram_facts(workspace)
            semantic_result = build_semantic_top_n(ram_result.facts)
            from lima.audit.ram import ram_facts_digest

            codes = [gap.gap_code for gap in ram_result.facts.coverage_gaps]
            codes += [gap.gap_code for gap in semantic_result.coverage_gaps]
            return ram_facts_digest(ram_result.facts), codes

        first_digest, first_codes = build()
        second_digest, second_codes = build()
        self.assertEqual(first_digest, second_digest)
        self.assertEqual(first_codes, second_codes)
        self.assertLessEqual(set(first_codes), ALL_CODES)

    def test_client_generic_exception_degrades_to_malformed_output(self) -> None:
        rs = rs_module()
        import lima.audit.semantic_prioritizer as sp

        with workspace_with(GENERIC_EXCEPT_REPO) as workspace:
            ram_result = build_python_ram_facts(workspace)
        client = ScriptedModelClient([RuntimeError("boom")])
        semantic_result = sp.build_semantic_top_n(
            ram_result.facts,
            options=sp.SemanticOptions(model_id="fake-model"),
            model_client=client,
        )
        self.assertEqual(
            [gap.gap_code for gap in semantic_result.coverage_gaps],
            ["SEMANTIC_MALFORMED_OUTPUT"],
        )
        payload = rs.ram_wire_payload(ram_result, semantic_result)
        self.assertTrue(payload["execution_required"]["required"])
        self.assertEqual(
            payload["execution_required"]["trigger_gap_codes"],
            ["SEMANTIC_MALFORMED_OUTPUT"],
        )

    def test_invalid_chain_inputs_still_fail_closed(self) -> None:
        with self.assertRaises(ContractError):
            build_semantic_top_n("not-facts")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
