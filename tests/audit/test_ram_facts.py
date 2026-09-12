"""IP-0018 acceptance tests: Python RAM facts six elements + typed gaps.

Matrix traceability (Packet IP-0018-PACKET/v1 §6/§7): every test below maps
to exactly one matrix row -- call-graph derivation (>=12), gap categories
(>=5), determinism (>=3), IP-0016 integration regression (>=2), and security
negatives for NFR-01 (>=4). ``lima.audit`` is imported in ``setUp`` so the
absence of the new RAM layer (PI-DR4) fails each case individually instead
of hiding behind a module-level import error.

PI-DR1: fixtures are materialized via ``workspace_with`` which pins
``newline="\\n"``; no platform permission or case-sensitivity semantics are
relied upon anywhere in this module.
"""

from __future__ import annotations

import os
import re
import unittest
from typing import Any

from tests.audit.fixtures.ram import shapes
from tests.audit.fixtures.repo_shapes import workspace_with

IP0016_ALL_PREFIX = [
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
]

IP0018_NEW_SYMBOLS = [
    "GAP_AMBIGUOUS_DISPATCH",
    "GAP_DYNAMIC_IMPORT",
    "RAM_PROVENANCE_ANCHOR",
    "PythonRamFacts",
    "RamBudgets",
    "RamFactsBuildResult",
    "RamKeyFlow",
    "build_python_ram_facts",
    "ram_facts_digest",
]

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class RamFactsTestBase(unittest.TestCase):
    audit: Any

    def setUp(self) -> None:
        import lima.audit as audit

        self.audit = audit

    def build(self, files: dict[str, str], **budgets: Any) -> Any:
        with workspace_with(files) as workspace:
            kwargs: dict[str, Any] = {}
            if budgets:
                kwargs["budgets"] = self.audit.RamBudgets(**budgets)
            return self.audit.build_python_ram_facts(workspace, **kwargs)

    def flat_facts_text(self, facts: Any) -> str:
        """Serialize every public text field of the facts payload (no code text)."""
        parts: list[str] = []
        for group in (
            facts.entrypoints,
            facts.external_sources,
            facts.sensitive_sinks,
            facts.trust_boundaries,
            facts.unresolved_edges,
        ):
            for entry in group:
                parts.extend([entry.path, entry.symbol or ""])
        parts.extend(facts.source_labels)
        parts.extend(facts.sink_rule_ids)
        parts.extend(facts.sink_cwes)
        for flow in facts.key_flows:
            parts.append(flow.sink_rule_id)
            parts.extend(flow.steps)
        for gap in facts.coverage_gaps:
            parts.extend([gap.gap_code, gap.detail])
        parts.extend(str(value) for value in facts.counters.values())
        return "\n".join(parts)

    def gap_details(self, result: Any, gap_code: str) -> list[str]:
        return [
            gap.detail
            for gap in result.facts.coverage_gaps
            if gap.gap_code == gap_code
        ]


class EntrypointTests(RamFactsTestBase):
    """Packet §5.1.1 -- FR-02 entrypoint."""

    def test_entrypoint_decorated(self) -> None:
        result = self.build(shapes.ENDPOINT_REPO)
        entries = result.facts.entrypoints
        self.assertEqual(
            [(entry.path, entry.symbol) for entry in entries],
            [("api.py", "list_items"), ("app.py", "submit")],
        )
        for entry in entries:
            self.assertEqual(entry.reason_codes, ("RAM_ENDPOINT_DECORATED",))
            self.assertEqual(entry.source_artifact_ids, ("ram-facts",))

    def test_entrypoint_class_method(self) -> None:
        result = self.build(shapes.ENDPOINT_REPO)
        symbols = {entry.symbol for entry in result.facts.entrypoints}
        self.assertIn("submit", symbols)

    def test_entrypoint_empty(self) -> None:
        result = self.build(shapes.ENDPOINT_EMPTY_REPO)
        self.assertEqual(result.facts.entrypoints, ())


class ExternalSourceTests(RamFactsTestBase):
    """Packet §5.1.2 -- FR-02 external source."""

    def test_external_source_env(self) -> None:
        result = self.build(shapes.SOURCE_REPO)
        sources = [
            (entry.path, entry.reason_codes)
            for entry in result.facts.external_sources
            if entry.path == "envs.py"
        ]
        self.assertEqual(sources, [("envs.py", ("RAM_EXTERNAL_SOURCE",))])
        self.assertIn("environment variable", result.facts.source_labels)

    def test_external_source_request(self) -> None:
        result = self.build(shapes.SOURCE_REPO)
        self.assertIn("web.py", {e.path for e in result.facts.external_sources})
        self.assertIn("request query parameter", result.facts.source_labels)

    def test_external_source_attribute(self) -> None:
        result = self.build(shapes.SOURCE_REPO)
        self.assertIn("bodies.py", {e.path for e in result.facts.external_sources})
        self.assertIn("request JSON body", result.facts.source_labels)

    def test_external_source_negative(self) -> None:
        result = self.build(shapes.SOURCE_NEGATIVE_REPO)
        self.assertEqual(result.facts.external_sources, ())
        self.assertEqual(result.facts.source_labels, ())


class SensitiveSinkTests(RamFactsTestBase):
    """Packet §5.1.3 -- FR-02 sensitive sink (taint-proven only)."""

    def test_sensitive_sink_tainted(self) -> None:
        result = self.build(shapes.SINK_TAINTED_REPO)
        sinks = result.facts.sensitive_sinks
        self.assertEqual(len(sinks), 1)
        self.assertEqual(sinks[0].path, "danger.py")
        self.assertEqual(sinks[0].reason_codes, ("RAM_SENSITIVE_SINK",))
        self.assertEqual(result.facts.sink_rule_ids, ("FLOW-COMMAND",))
        self.assertEqual(result.facts.sink_cwes, ("CWE-78",))

    def test_sensitive_sink_constant_negative(self) -> None:
        result = self.build(shapes.SINK_CONSTANT_REPO)
        self.assertEqual(result.facts.sensitive_sinks, ())
        self.assertEqual(result.facts.sink_rule_ids, ())
        self.assertEqual(result.facts.sink_cwes, ())


class TrustBoundaryTests(RamFactsTestBase):
    """Packet §5.1.4 -- FR-02 trust boundary (path-level dedup union)."""

    def test_trust_boundary_union_dedup(self) -> None:
        result = self.build(shapes.BOUNDARY_SAME_FILE_REPO)
        self.assertEqual(
            [(entry.path, entry.symbol) for entry in result.facts.trust_boundaries],
            [("other.py", None), ("service.py", None)],
        )
        for entry in result.facts.trust_boundaries:
            self.assertEqual(entry.reason_codes, ("RAM_TRUST_BOUNDARY",))

    def test_trust_boundary_from_source_only(self) -> None:
        result = self.build({"only.py": shapes.BOUNDARY_SAME_FILE_REPO["other.py"]})
        self.assertEqual(
            [entry.path for entry in result.facts.trust_boundaries], ["only.py"]
        )


class KeyFlowTests(RamFactsTestBase):
    """Packet §5.1.5 -- FR-02 key flow (path:line anchors only)."""

    def test_key_flow_steps(self) -> None:
        result = self.build(shapes.SINK_TAINTED_REPO)
        flows = result.facts.key_flows
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].sink_rule_id, "FLOW-COMMAND")
        steps = flows[0].steps
        self.assertGreaterEqual(len(steps), 2)
        self.assertTrue(all(re.fullmatch(r"[^:]+:\d+", step) for step in steps))
        self.assertEqual(steps[0], "danger.py:6")
        self.assertEqual(steps[-1], "danger.py:7")

    def test_key_flow_no_source_text(self) -> None:
        result = self.build(shapes.SINK_TAINTED_REPO)
        text = self.flat_facts_text(result.facts)
        self.assertNotIn("os.system", text)
        self.assertNotIn("request.args.get", text)

    def test_key_flow_budget(self) -> None:
        result = self.build(shapes.TWO_FLOW_REPO, max_key_flows=1)
        self.assertEqual(len(result.facts.key_flows), 1)
        self.assertEqual(
            self.gap_details(result, "BUDGET_EXHAUSTED"),
            ["reason=key-flow-limit; count=1"],
        )


class UnresolvedEdgeTests(RamFactsTestBase):
    """Packet §5.1.6 -- FR-02 unresolved edge."""

    def test_unresolved_edge_symbol(self) -> None:
        result = self.build(shapes.UNRESOLVED_REPO)
        edges = result.facts.unresolved_edges
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0].path, "edges.py")
        self.assertEqual(edges[0].symbol, "missing_target")
        self.assertEqual(edges[0].reason_codes, ("RAM_UNRESOLVED_CALL",))

    def test_unresolved_edge_empty(self) -> None:
        result = self.build(shapes.UNRESOLVED_EMPTY_REPO)
        self.assertEqual(result.facts.unresolved_edges, ())

    def test_unresolved_edge_plain_call_negative(self) -> None:
        # analyzer semantics (Packet §3.1 transcription clarification):
        # unresolved_call_sites records only taint-carrying unresolved calls,
        # so a plain call of an undefined name yields no edge fact.
        result = self.build(shapes.UNRESOLVED_PLAIN_REPO)
        self.assertEqual(result.facts.unresolved_edges, ())
        self.assertEqual(result.facts.counters["unresolved_calls"], 0)

    def test_unresolved_edge_budget(self) -> None:
        result = self.build(shapes.UNRESOLVED_BUDGET_REPO, max_unresolved_edges=1)
        self.assertEqual(len(result.facts.unresolved_edges), 1)
        self.assertEqual(
            self.gap_details(result, "BUDGET_EXHAUSTED"),
            ["reason=unresolved-edge-limit; count=2"],
        )


class GapCategoryTests(RamFactsTestBase):
    """Packet §5.2 -- FR-05 subset: two new typed gap categories + budgets."""

    def test_gap_dynamic_import(self) -> None:
        result = self.build(shapes.DYNAMIC_IMPORT_REPO)
        self.assertEqual(
            self.gap_details(result, "DYNAMIC_IMPORT"),
            ["reason=dynamic-import; count=1"],
        )
        self.assertEqual(result.facts.counters["dynamic_import_sites"], 1)

    def test_gap_ambiguous_dispatch(self) -> None:
        result = self.build(shapes.AMBIGUOUS_REPO)
        self.assertEqual(
            self.gap_details(result, "AMBIGUOUS_DISPATCH"),
            ["reason=ambiguous-module; count=1"],
        )
        self.assertEqual(result.facts.counters["ambiguous_modules"], 1)

    def test_gap_budget_python_files(self) -> None:
        result = self.build(shapes.PYTHON_FILE_BUDGET_REPO, max_python_files=1)
        self.assertEqual(
            self.gap_details(result, "BUDGET_EXHAUSTED"),
            ["reason=python-file-limit; count=1"],
        )
        self.assertEqual(result.facts.counters["modules_indexed"], 1)

    def test_gap_absent_when_clean(self) -> None:
        result = self.build(shapes.UNRESOLVED_EMPTY_REPO)
        self.assertEqual(result.facts.coverage_gaps, ())

    def test_gap_codes_are_frozen_constants(self) -> None:
        self.assertEqual(self.audit.GAP_DYNAMIC_IMPORT, "DYNAMIC_IMPORT")
        self.assertEqual(self.audit.GAP_AMBIGUOUS_DISPATCH, "AMBIGUOUS_DISPATCH")
        self.assertEqual(self.audit.RAM_PROVENANCE_ANCHOR, "ram-facts")


class DeterminismTests(RamFactsTestBase):
    """Packet §5.1.7 -- determinism, digest, contract validation negatives."""

    def test_determinism_same_workspace_equal(self) -> None:
        with workspace_with(shapes.SINK_TAINTED_REPO) as workspace:
            first = self.audit.build_python_ram_facts(workspace)
            second = self.audit.build_python_ram_facts(workspace)
        self.assertEqual(first.facts, second.facts)
        self.assertEqual(
            self.audit.ram_facts_digest(first.facts),
            self.audit.ram_facts_digest(second.facts),
        )

    def test_digest_is_64_lowercase_hex(self) -> None:
        result = self.build(shapes.SINK_TAINTED_REPO)
        digest = self.audit.ram_facts_digest(result.facts)
        self.assertRegex(digest, _HEX64)

    def test_contract_validation_negative(self) -> None:
        from lima.contracts.errors import ContractError

        with self.assertRaises(ContractError):
            self.audit.build_python_ram_facts("not-a-workspace")
        with self.assertRaises(ValueError):
            self.audit.RamBudgets(max_python_files=0)
        with self.assertRaises(ValueError):
            self.audit.RamBudgets(max_key_flows=-1)


class Ip0016IntegrationTests(RamFactsTestBase):
    """Packet §5.3 -- pure-append re-export boundary against IP-0016."""

    def test_ip0016_public_api_prefix_unchanged(self) -> None:
        self.assertEqual(list(self.audit.__all__[:11]), IP0016_ALL_PREFIX)
        self.assertEqual(
            self.audit.__all__[11:], sorted(IP0018_NEW_SYMBOLS)
        )
        for name in IP0018_NEW_SYMBOLS:
            self.assertTrue(hasattr(self.audit, name), name)

    def test_ip0016_profile_build_coexists(self) -> None:
        from tests.audit.fixtures.repo_shapes import profile_kwargs

        files = {
            "pyproject.toml": (
                "[project]\nname = \"demo-app\"\nrequires-python = \">=3.11\"\n"
            ),
            "main.py": "from app import views\n\n\ndef main() -> None:\n    views.run()\n",
            "app/__init__.py": "",
            "app/views.py": "def run() -> None:\n    return None\n",
        }
        with workspace_with(files) as workspace:
            profile = self.audit.build_repository_profile(
                workspace, **profile_kwargs()
            )
            facts = self.audit.build_python_ram_facts(workspace)
        self.assertTrue(profile.profile.entrypoints)
        self.assertEqual(facts.facts.unresolved_edges, ())


class SecurityNegativeTests(RamFactsTestBase):
    """Packet §5.6 -- NFR-01: repo-relative, no source text, no secrets, fail-closed."""

    def test_no_execution_malicious_setup(self) -> None:
        os.environ.pop("LIMA_IP0018_PWNED", None)
        result = self.build(shapes.MALICIOUS_SETUP_REPO)
        self.assertEqual(result.facts.unresolved_edges, ())
        self.assertNotIn("LIMA_IP0018_PWNED", os.environ)

    def test_no_secret_in_facts(self) -> None:
        result = self.build(shapes.SECRET_REPO)
        text = self.flat_facts_text(result.facts)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", text)
        self.assertNotIn("TOKEN_VALUE", text)

    def test_no_host_path_leak(self) -> None:
        with workspace_with(shapes.SINK_TAINTED_REPO) as workspace:
            result = self.audit.build_python_ram_facts(workspace)
            host_root = str(workspace.root)
        groups = (
            result.facts.entrypoints,
            result.facts.external_sources,
            result.facts.sensitive_sinks,
            result.facts.trust_boundaries,
            result.facts.unresolved_edges,
        )
        for group in groups:
            for entry in group:
                self.assertFalse(entry.path.startswith(("/", "\\")))
                self.assertNotIn("\\", entry.path)
                self.assertNotIn(host_root, entry.path)
        for flow in result.facts.key_flows:
            for step in flow.steps:
                path = step.rsplit(":", 1)[0]
                self.assertNotIn(host_root, path)

    def test_fail_closed_inputs(self) -> None:
        from lima.contracts.errors import ContractError

        with self.assertRaises(ContractError):
            self.audit.build_python_ram_facts(None)
        with self.assertRaises(ValueError):
            self.audit.RamBudgets(max_unresolved_edges=0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
