"""IP-0023 component-graph acceptance tests (Packet v5.1 section 6, #1-#37
and #42-#79).

Assertions are derived from the frozen requirements (Packet v5.1 sections
5.1-5.9, the CL-01..05 cross-layer rulings and the R1/R2/R3 targeted rework),
never from an algorithm implementation. The golden expectation carrier lives
in ``tests/audit/fixtures/monorepo/golden/monorepo.json`` and is checked by
``tests/audit/test_monorepo_golden.py`` (#38-#41).

The module under test (``lima.audit.component_graph``) is imported lazily per
test so the module-absence RED anchor (PI-DR4) stays observable: at the frozen
baseline the module does not exist and every test below fails on that import,
while the assertion structure carries the semantic coverage.

D2 execution-precision anchors (Assignment D2-01..04):
- D2-01 four-way bound-digest equality + unbound negative control:
  ``test_consumer_obtains_all_facts_from_public_artifacts`` (#42).
- D2-02 three-leg digest discriminability and content-change transfer:
  ``test_identical_content_components_equal_digest_allowed`` (#35),
  ``test_component_identity_keyed_association`` (#36),
  ``test_content_change_digest_changes`` (#37),
  ``test_graph_digest_binds_artifact_references`` (#78).
- D2-03 metadata-policy-key forgery capability boundary:
  ``test_t6_t8_gap_domain_marker_and_dual_counts`` (#77) plus positive
  builder proof in #61/#73/#39.
- D2-04 canonical/wire name mapping (digests -> artifact_digests):
  ``test_component_identity_keyed_association`` (#36),
  ``test_validator_graph_digest_recompute`` (#47), and the golden oracle in
  ``tests/audit/test_monorepo_golden.py`` (#38).
"""

from __future__ import annotations

import ast
import importlib
import json
import re
import shutil
import tempfile
import unittest
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from typing import Any

from lima.audit.inventory import is_secret_shaped_path
from lima.audit.ram import RamBudgets, build_python_ram_facts, ram_facts_digest
from lima.audit.ram_schema import (
    execution_required_from_gaps,
    ram_facts_digest_from_wire,
    ram_wire_digest,
    semantic_config_digest_from_wire,
    semantic_result_digest_from_wire,
    validate_ram_wire_payload,
)
from lima.audit.semantic_prioritizer import (
    SemanticBudgets,
    SemanticOptions,
    build_semantic_top_n,
    semantic_config_digest,
    semantic_result_digest,
)
from lima.contracts.codec import compute_content_digest
from lima.contracts.errors import ContractError
from lima.contracts.profile import (
    decode_profile_envelope,
    encode_profile_envelope,
)
from lima.workspace import RepositoryWorkspace
from tests.audit.fixtures.monorepo import shapes
from tests.audit.test_monorepo_golden import (
    canonical_dict_from_payload,
    monorepo_build_kwargs,
)

MODULE_PATH = (
    Path(__file__).resolve().parents[2] / "lima" / "audit" / "component_graph.py"
)

SENTINEL = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
HEX_A = "1" * 64
HEX_B = "2" * 64
HEX_C = "3" * 64

EFFECTIVE_DEFAULT_BUDGETS: dict[str, int] = {
    "max_components": 16,
    "max_edges": 4_096,
    "max_edge_evidence": 64,
    "max_unassigned_files": 256,
    "max_total_model_calls": 8,
    "aggregate_max_prompt_tokens": 24_000,
    "aggregate_max_output_tokens": 4_096,
    "aggregate_max_total_tokens": 28_096,
    "max_metadata_manifests": 64,
    "max_metadata_total_bytes": 1_048_576,
}

CHANNEL_GAP_DETAIL = re.compile(
    r"^channel=(?P<channel>source-inventory|metadata-channel); "
    r"reason=(?P<reason>[a-z0-9\-]+); count=(?P<count>[1-9][0-9]*)$"
)
BUDGET_GAP_DETAIL = re.compile(
    r"^reason=(?P<reason>[a-z0-9\-]+); count=(?P<count>[1-9][0-9]*)$"
)


def load_cg() -> Any:
    """Lazily import the module under test (PI-DR4 module-absence anchor)."""

    return importlib.import_module("lima.audit.component_graph")


@contextmanager
def detect_on(
    files: Mapping[str, str | bytes],
    *,
    budgets: Any = None,
    manifest_policy: str | None = None,
    **workspace_limits: object,
) -> Iterator[tuple[Any, Any, Any]]:
    """Yield ``(cg, discovery, repo_root)`` for ``detect_components``."""

    cg = load_cg()
    with shapes.monorepo_workspace(files, **workspace_limits) as (root, ws):
        kwargs: dict[str, Any] = {}
        if budgets is not None:
            kwargs["budgets"] = budgets
        if manifest_policy is not None:
            kwargs["manifest_policy"] = manifest_policy
        yield cg, cg.detect_components(ws, **kwargs), root


@contextmanager
def build_on(
    files: Mapping[str, str | bytes],
    *,
    monorepo_budgets: Any = None,
    ram_budgets: Any = None,
    semantic_options: Any = None,
    model_client: Any = None,
    manifest_policy: str | None = None,
    **workspace_limits: object,
) -> Iterator[tuple[Any, Any, dict[str, Any]]]:
    """Yield ``(cg, result, payload)`` for a full ``build_monorepo_profile``."""

    cg = load_cg()
    with shapes.monorepo_workspace(files, **workspace_limits) as (root, ws):
        kwargs: dict[str, Any] = dict(monorepo_build_kwargs())
        if monorepo_budgets is not None:
            kwargs["monorepo_budgets"] = monorepo_budgets
        if ram_budgets is not None:
            kwargs["ram_budgets"] = ram_budgets
        if semantic_options is not None:
            kwargs["semantic_options"] = semantic_options
        if model_client is not None:
            kwargs["model_client"] = model_client
        if manifest_policy is not None:
            kwargs["manifest_policy"] = manifest_policy
        result = cg.build_monorepo_profile(ws, **kwargs)
        yield cg, result, cg.component_graph_payload(result)


class FakeModelClient:
    """Offline deterministic model double (no network, fails on demand)."""

    def __init__(self, *, fail: bool = False) -> None:
        self.calls = 0
        self.fail = fail

    def complete(self, prompt: str, *, timeout_seconds: int) -> str:
        self.calls += 1
        if self.fail:
            raise TimeoutError("fake offline timeout")
        return "not-a-json-model-reply"


def classify_three_state(entry: Mapping[str, Any], payload: Mapping[str, Any]) -> str:
    """Frozen section 5.2.4 decision table (P1 > P2 > P3, unique value).

    Objects without a resolved out-edge are classified; a component holding a
    resolved out-edge has dependencies and is not a three-state object
    (returned as ``"has-dependencies"``).
    """

    cid = entry["component_id"]
    if any(
        edge["source_component_id"] == cid and edge["status"] == "resolved"
        for edge in payload["edges"]
    ):
        return "has-dependencies"
    if any(
        edge["source_component_id"] == cid
        and edge["status"] in ("ambiguous", "unresolved")
        for edge in payload["edges"]
    ):
        return "parse-failed"
    scan = entry["scan_summary"]
    real_no_deps = (
        payload["dependencies_complete"] is True
        and payload["unassigned_file_count"] == 0
        and scan["parse_error_file_count"] == 0
        and scan["read_failure_file_count"] == 0
        and not any(
            item["source_component_id"] == cid
            for item in payload["unknown_imports"]
        )
        and scan["unknown_truncated_count"] == 0
        and scan["dynamic_import_site_count"] == 0
        and scan["manifest_parse_failure_count"] == 0
        and not any(
            edge["source_component_id"] == cid
            or edge["target_component_id"] == cid
            for edge in payload["edges"]
        )
    )
    return "real-no-dependencies" if real_no_deps else "insufficient-evidence"


def payload_entry(payload: Mapping[str, Any], component_id: str) -> dict[str, Any]:
    for entry in payload["components"]:
        if entry["component_id"] == component_id:
            return entry
    raise AssertionError(f"component {component_id} missing from payload")


def gap_details(payload: Mapping[str, Any], code: str) -> list[str]:
    return [
        gap["detail"]
        for gap in payload["coverage_gaps"]
        if gap["gap_code"] == code
    ]


def find_gap(payload: Mapping[str, Any], code: str, reason: str) -> str | None:
    for detail in gap_details(payload, code):
        if f"reason={reason};" in detail:
            return detail
    return None


def path_fields(payload: Mapping[str, Any]) -> list[str]:
    """Collect every path-bearing public surface (section 5.8 admission table)."""

    values: list[str] = []
    for entry in payload["components"]:
        values.append(entry["component_id"])
        values.append(entry["root_dir"])
        values.extend(ref["path"] for ref in entry["manifests"])
    values.extend(payload["unassigned_files"])
    for edge in payload["edges"]:
        values.extend(item["path"] for item in edge["evidence"])
    return values


def _scan_zero(component_id: str) -> dict[str, Any]:
    return {
        "component_id": component_id,
        "parse_error_file_count": 0,
        "read_failure_file_count": 0,
        "dynamic_import_site_count": 0,
        "unknown_truncated_count": 0,
        "manifest_parse_failure_count": 0,
    }


def _entry_zero(component_id: str, root_dir: str, digests: Any) -> dict[str, Any]:
    summary = _scan_zero(component_id)
    summary.pop("component_id")
    return {
        "component_id": component_id,
        "root_dir": root_dir,
        "manifests": [
            {
                "path": f"{root_dir}/pyproject.toml" if root_dir else "pyproject.toml",
                "manifest_kind": "pyproject",
                "source": "source-inventory",
            }
        ],
        "python_file_count": 1,
        "is_empty": False,
        "built": True,
        "digests": digests,
        "scan_summary": summary,
        "semantic_topn": {
            "model_id": "unset",
            "top_n": 20,
            "ranked_candidate_ids": ["sensitive-sink:x.py:-#0"],
        },
    }


def _finalize(payload: dict[str, Any]) -> dict[str, Any]:
    payload["identity"]["component_graph_digest"] = compute_content_digest(
        canonical_dict_from_payload(payload)
    )
    return payload


def minimal_valid_payload() -> dict[str, Any]:
    """Hand-built single-component payload that a correct validator accepts.

    Also serves as the PI-DR2 compliance witness: the frozen contract admits
    at least this output shape.
    """

    return _finalize(
        {
            "schema_version": "2.0",
            "model_kind": "lima.component-graph",
            "components": [
                _entry_zero(
                    "component:x",
                    "x",
                    {
                        "profile_content_digest": HEX_A,
                        "ram_facts_digest": HEX_B,
                        "semantic_result_digest": HEX_C,
                    },
                )
            ],
            "edges": [],
            "unknown_imports": [],
            "unassigned_files": [],
            "unassigned_file_count": 0,
            "scan_summaries": [_scan_zero("component:x")],
            "unbuilt_components": [],
            "dependencies_complete": True,
            "coverage_gaps": [],
            "metadata_manifest_count": 0,
            "metadata_channel_skipped": {},
            "manifests_discovered_count": 1,
            "collaboration_manifest_count": 0,
            "overflow_manifest_count": 0,
            "build": {"monorepo_budgets": dict(EFFECTIVE_DEFAULT_BUDGETS)},
            "identity": {"component_graph_digest": ""},
            "provenance": {"provenance_anchor_ids": ["component-graph"]},
        }
    )


def two_component_payload(
    *, max_edges: int = 4_096, max_edge_evidence: int = 64
) -> dict[str, Any]:
    """Hand-built two-component payload (one resolved edge + one unknown)."""

    budgets = dict(EFFECTIVE_DEFAULT_BUDGETS)
    budgets["max_edges"] = max_edges
    budgets["max_edge_evidence"] = max_edge_evidence
    second = _entry_zero("component:y", "y", None)
    second["manifests"] = []
    second["built"] = True
    second["digests"] = {
        "profile_content_digest": HEX_C,
        "ram_facts_digest": HEX_B,
        "semantic_result_digest": HEX_A,
    }
    return _finalize(
        {
            "schema_version": "2.0",
            "model_kind": "lima.component-graph",
            "components": [
                _entry_zero(
                    "component:x",
                    "x",
                    {
                        "profile_content_digest": HEX_A,
                        "ram_facts_digest": HEX_B,
                        "semantic_result_digest": HEX_C,
                    },
                ),
                second,
            ],
            "edges": [
                {
                    "source_component_id": "component:x",
                    "target_component_id": "component:y",
                    "status": "resolved",
                    "imported_name": "ylib",
                    "evidence": [
                        {"path": "x/main.py", "line": 1, "imported_name": "ylib"}
                    ],
                }
            ],
            "unknown_imports": [
                {
                    "source_component_id": "component:x",
                    "imported_name": "missing_thing",
                    "count": 1,
                }
            ],
            "unassigned_files": [],
            "unassigned_file_count": 0,
            "scan_summaries": [_scan_zero("component:x"), _scan_zero("component:y")],
            "unbuilt_components": [],
            "dependencies_complete": True,
            "coverage_gaps": [],
            "metadata_manifest_count": 0,
            "metadata_channel_skipped": {},
            "manifests_discovered_count": 1,
            "collaboration_manifest_count": 0,
            "overflow_manifest_count": 0,
            "build": {"monorepo_budgets": budgets},
            "identity": {"component_graph_digest": ""},
            "provenance": {"provenance_anchor_ids": ["component-graph"]},
        }
    )


class ComponentDiscoveryTests(unittest.TestCase):
    """C1: nested discovery, anchors, IDs, truncation (Packet #1-#8)."""

    def test_detect_components_nested_services_packages(self) -> None:
        with detect_on(shapes.NESTED_ROOT_SERVICES_PACKAGES) as (cg, discovery, _r):
            ids = [component.component_id for component in discovery.components]
            self.assertEqual(
                ids,
                ["component:.", "component:packages/core", "component:services/api"],
            )
            by_id = {c.component_id: c for c in discovery.components}
            self.assertEqual(by_id["component:."].root_dir, "")
            self.assertEqual(
                [m.path for m in by_id["component:."].manifests],
                ["pyproject.toml"],
            )
            core = by_id["component:packages/core"]
            self.assertEqual(core.root_dir, "packages/core")
            self.assertEqual(
                [(m.path, m.manifest_kind) for m in core.manifests],
                [("packages/core/pyproject.toml", cg.COMPONENT_MANIFEST_KIND_PYPROJECT)],
            )
            self.assertEqual(core.python_file_count, 2)
            self.assertFalse(core.is_empty)
            api = by_id["component:services/api"]
            self.assertEqual(api.python_file_count, 1)
            self.assertFalse(discovery.truncated)

    def test_detect_components_multiple_manifests_same_dir(self) -> None:
        with detect_on(shapes.PARENT_CHILD_MANIFESTS) as (_cg, discovery, _r):
            by_id = {c.component_id: c for c in discovery.components}
            self.assertEqual(
                [m.path for m in by_id["component:."].manifests],
                ["pyproject.toml", "requirements.txt"],
            )
            self.assertEqual(
                [m.path for m in by_id["component:services"].manifests],
                ["services/pyproject.toml", "services/requirements.txt"],
            )

    def test_detect_components_root_only_and_zero_component(self) -> None:
        with detect_on(shapes.ROOT_ONLY) as (_cg, discovery, _r):
            self.assertEqual(
                [c.component_id for c in discovery.components], ["component:."]
            )
        with detect_on(shapes.ZERO_COMPONENT) as (_cg, discovery, _r):
            self.assertEqual(discovery.components, ())
            self.assertEqual(discovery.unassigned_files, ("loose/a.py", "loose/b.py"))
            self.assertEqual(discovery.unassigned_file_count, 2)

    def test_detect_components_workspace_manifest_not_component(self) -> None:
        with detect_on(shapes.WORKSPACE_MANIFEST_MEMBERS) as (_cg, discovery, _r):
            ids = [c.component_id for c in discovery.components]
            self.assertEqual(ids, ["component:libraries/utils"])
            self.assertNotIn("component:.", ids)
            self.assertEqual(discovery.collaboration_manifest_count, 1)

    def test_detect_components_unassigned_files(self) -> None:
        with detect_on(shapes.UNASSIGNED_SCATTER) as (_cg, discovery, _r):
            self.assertEqual(
                [c.component_id for c in discovery.components], ["component:tools"]
            )
            self.assertEqual(discovery.unassigned_files, ("alpha.py", "beta/beta.py"))
            self.assertEqual(discovery.unassigned_file_count, 2)

    def test_detect_components_empty_component(self) -> None:
        with detect_on(shapes.EMPTY_COMPONENT_DIR) as (_cg, discovery, _r):
            by_id = {c.component_id: c for c in discovery.components}
            docs = by_id["component:docs_only"]
            self.assertTrue(docs.is_empty)
            self.assertEqual(docs.python_file_count, 0)
            self.assertEqual(len(docs.manifests), 1)

    def test_detect_components_max_components_truncation(self) -> None:
        repo = shapes.many_component_repo(17)
        with detect_on(repo) as (cg, discovery, _r):
            self.assertEqual(len(discovery.components), 16)
            self.assertTrue(discovery.truncated)
            details = [
                gap.detail
                for gap in discovery.coverage_gaps
                if gap.gap_code == "BUDGET_EXHAUSTED"
            ]
            self.assertEqual(details, ["reason=component-limit; count=1"])
        with build_on(repo) as (_cg2, result, payload):
            self.assertFalse(payload["dependencies_complete"])
            self.assertEqual(
                find_gap(payload, "BUDGET_EXHAUSTED", "component-limit"),
                "reason=component-limit; count=1",
            )
            self.assertEqual(
                payload["overflow_manifest_count"], 1,
            )
        with detect_on(repo, budgets=load_cg().MonorepoBudgets(max_components=17)) as (
            _cg3,
            discovery17,
            _r2,
        ):
            self.assertEqual(len(discovery17.components), 17)
            self.assertFalse(discovery17.truncated)

    def test_detect_components_secret_shaped_anchor_suppressed(self) -> None:
        with detect_on(shapes.SECRET_ANCHOR_REPO) as (_cg, discovery, _r):
            ids = [c.component_id for c in discovery.components]
            self.assertEqual(ids, ["component:."])
            details = [
                gap.detail
                for gap in discovery.coverage_gaps
                if gap.gap_code == "INVENTORY_SKIPPED"
            ]
            self.assertEqual(
                details,
                ["channel=source-inventory; reason=sensitive-filename; count=1"],
            )
            for detail in details:
                self.assertNotIn("secrets", detail)


class OwnershipInvariantTests(unittest.TestCase):
    """C1: INV-OWN-1/2/3 ownership invariants (Packet #9-#10)."""

    def test_component_counts_match_build_inputs(self) -> None:
        with build_on(shapes.NESTED_ROOT_SERVICES_PACKAGES) as (cg, result, payload):
            with shapes.monorepo_workspace(shapes.NESTED_ROOT_SERVICES_PACKAGES) as (
                root,
                ws,
            ):
                admitted_py = sorted(
                    f.path
                    for f in ws.inventory().files
                    if f.path.endswith(".py")
                )
            # INV-OWN-2: built + unbuilt + unassigned == admitted .py total.
            built_sum = sum(e["python_file_count"] for e in payload["components"])
            unbuilt_ids = {r["component_id"] for r in payload["unbuilt_components"]}
            unbuilt_sum = sum(
                e["python_file_count"]
                for e in payload["components"]
                if e["component_id"] in unbuilt_ids
            )
            self.assertEqual(
                built_sum + unbuilt_sum + payload["unassigned_file_count"],
                len(admitted_py),
            )
            self.assertEqual(built_sum, 4)
            # INV-OWN-3(a): file-level conservation.
            published = sum(len(e["manifests"]) for e in payload["components"])
            self.assertEqual(
                payload["manifests_discovered_count"],
                published
                + payload["collaboration_manifest_count"]
                + payload["overflow_manifest_count"],
            )
            # INV-OWN-3(b): parent/child manifest isolation, key-level compare.
            root_manifests = {
                m.path for m in result.graph.components[0].manifests
            } if result.graph.components[0].component_id == "component:." else set()
            self.assertNotIn("services/api/pyproject.toml", root_manifests)
            self.assertNotIn("packages/core/pyproject.toml", root_manifests)
            # INV-OWN-3(d): every published manifest source is in the enum.
            for entry in payload["components"]:
                for ref in entry["manifests"]:
                    self.assertIn(ref["source"], cg.COMPONENT_MANIFEST_SOURCES)
            # Five-input consistency: per-component counts match slices and
            # the per-component RAM universe never leaves the slice.
            expected_counts = {
                "component:.": 1,
                "component:packages/core": 2,
                "component:services/api": 1,
            }
            for entry in payload["components"]:
                self.assertEqual(
                    entry["python_file_count"],
                    expected_counts[entry["component_id"]],
                )
            for built in result.per_component:
                prefix = built.component.root_dir
                for section in (
                    built.ram_result.facts.entrypoints,
                    built.ram_result.facts.external_sources,
                    built.ram_result.facts.sensitive_sinks,
                    built.ram_result.facts.trust_boundaries,
                    built.ram_result.facts.unresolved_edges,
                ):
                    for item in section:
                        repo_path = (
                            f"{prefix}/{item.path}" if prefix else item.path
                        )
                        self.assertIn(repo_path, admitted_py)
            # semantic Top-N candidate paths stay inside the slice too.
            for built in result.per_component:
                prefix = built.component.root_dir
                for candidate in built.semantic_result.ranked:
                    internal = candidate.path
                    repo_path = f"{prefix}/{internal}" if prefix else internal
                    self.assertIn(repo_path, admitted_py)

    def test_root_component_excludes_child_files(self) -> None:
        with build_on(shapes.NESTED_ROOT_SERVICES_PACKAGES) as (_cg, result, payload):
            root_entry = payload_entry(payload, "component:.")
            self.assertEqual(root_entry["python_file_count"], 1)
            built_by_id = {b.component.component_id: b for b in result.per_component}
            root_built = built_by_id["component:."]
            observed = {
                item.path
                for section in (
                    root_built.ram_result.facts.entrypoints,
                    root_built.ram_result.facts.external_sources,
                    root_built.ram_result.facts.sensitive_sinks,
                    root_built.ram_result.facts.trust_boundaries,
                    root_built.ram_result.facts.unresolved_edges,
                )
                for item in section
            } | set(root_built.ram_result.facts.source_labels)
            self.assertTrue(observed <= {"main.py"})
            # Child module counts are not double-counted in the root RAM view.
            self.assertEqual(
                root_built.ram_result.facts.counters.get("modules_indexed"), 1
            )
            self.assertEqual(
                built_by_id["component:packages/core"]
                .ram_result.facts.counters.get("modules_indexed"),
                2,
            )


class ModuleResolutionTests(unittest.TestCase):
    """C2: module roots, three-state edges, unknown imports (Packet #11-#18)."""

    def test_module_resolution_src_layout_cross_component(self) -> None:
        with build_on(shapes.SRC_LAYOUT_CROSS) as (_cg, _result, payload):
            self.assertEqual(len(payload["edges"]), 1)
            edge = payload["edges"][0]
            self.assertEqual(edge["source_component_id"], "component:a")
            self.assertEqual(edge["target_component_id"], "component:b")
            self.assertEqual(edge["status"], "resolved")
            self.assertEqual(edge["imported_name"], "beta")
            self.assertEqual(
                edge["evidence"],
                [
                    {
                        "path": "a/a_main.py",
                        "line": 1,
                        "imported_name": "beta",
                    }
                ],
            )

    def test_module_resolution_build_config_declared_root(self) -> None:
        with build_on(shapes.BUILD_CONFIG_SRC_ROOT) as (_cg, _result, payload):
            self.assertEqual(len(payload["edges"]), 1)
            edge = payload["edges"][0]
            self.assertEqual(edge["status"], "resolved")
            self.assertEqual(
                edge["source_component_id"],
                "component:appc",
            )
            self.assertEqual(edge["target_component_id"], "component:cfgcom")
            self.assertEqual(edge["imported_name"], "cfglib")

    def test_module_resolution_namespace_package(self) -> None:
        with build_on(shapes.NAMESPACE_PACKAGES) as (_cg, _result, payload):
            edges = {
                (
                    edge["source_component_id"],
                    edge["status"],
                    edge["imported_name"],
                )
                for edge in payload["edges"]
            }
            self.assertIn(
                ("component:second", "resolved", "solo_ns"), edges
            )
            self.assertIn(("component:host", "ambiguous", "nsp"), edges)
            ambiguous = [
                edge
                for edge in payload["edges"]
                if edge["status"] == "ambiguous"
            ]
            self.assertEqual(len(ambiguous), 1)
            self.assertIsNone(ambiguous[0]["target_component_id"])

    def test_relative_import_package_context(self) -> None:
        with build_on(shapes.RELATIVE_PACKAGE_IMPORTS) as (_cg, _result, payload):
            edges = {
                (edge["status"], edge["target_component_id"]): edge
                for edge in payload["edges"]
            }
            self.assertIn(("resolved", "component:shared"), edges)
            resolved = edges[("resolved", "component:shared")]
            self.assertEqual(resolved["evidence"][0]["path"], "app/mod.py")
            self.assertEqual(resolved["evidence"][0]["line"], 1)
            self.assertIn(("unresolved", None), edges)
            unresolved = edges[("unresolved", None)]
            self.assertEqual(unresolved["source_component_id"], "component:app")
            self.assertEqual(unresolved["evidence"][0]["line"], 2)
            # Intra-package level-1 import produces no edge at all.
            self.assertEqual(len(payload["edges"]), 2)

    def test_duplicate_module_name_self_first_and_ambiguous(self) -> None:
        with build_on(shapes.DUPLICATE_MODULE_NAMES) as (_cg, _result, payload):
            self.assertEqual(len(payload["edges"]), 1)
            edge = payload["edges"][0]
            self.assertEqual(edge["status"], "ambiguous")
            self.assertEqual(edge["source_component_id"], "component:host")
            self.assertIsNone(edge["target_component_id"])
            self.assertEqual(edge["imported_name"], "shared")
            self.assertEqual(edge["evidence"][0]["path"], "host/host_user.py")
            # Self-first: component:one importing its own "shared" adds no edge.

    def test_unknown_import_carried_not_external(self) -> None:
        with build_on(shapes.UNKNOWN_IMPORT_REPO) as (_cg, _result, payload):
            self.assertEqual(
                payload["unknown_imports"],
                [
                    {
                        "source_component_id": "component:.",
                        "imported_name": "missing_alpha",
                        "count": 2,
                    },
                    {
                        "source_component_id": "component:.",
                        "imported_name": "missing_beta",
                        "count": 1,
                    },
                ],
            )
            # Unknown imports are carried, never faked as external edges.
            self.assertEqual(payload["edges"], [])
            entry = payload_entry(payload, "component:.")
            self.assertEqual(
                classify_three_state(entry, payload),
                "insufficient-evidence",
            )

    def test_known_external_stdlib_and_declared_deps(self) -> None:
        with build_on(shapes.KNOWN_EXTERNAL_REPO) as (_cg, _result, payload):
            self.assertEqual(payload["edges"], [])
            self.assertEqual(payload["unknown_imports"], [])
            for entry in payload["components"]:
                scan = entry["scan_summary"]
                self.assertEqual(scan["parse_error_file_count"], 0)

    def test_dynamic_import_sites_carried(self) -> None:
        with build_on(shapes.DYNAMIC_IMPORT_REPO) as (_cg, result, payload):
            entry = payload_entry(payload, "component:.")
            self.assertEqual(entry["scan_summary"]["dynamic_import_site_count"], 1)
            self.assertEqual(payload["edges"], [])
            self.assertEqual(payload["unknown_imports"], [])
            # Dynamic sites are a resolution limit, not a collection failure:
            # completeness is untouched and the classification excludes P3.
            self.assertTrue(payload["dependencies_complete"])
            self.assertEqual(
                classify_three_state(entry, payload), "insufficient-evidence"
            )
            # RAM-layer DYNAMIC_IMPORT gap and the graph counter are two
            # observable carriers of the same uncertainty (frozen layers).
            root_built = result.per_component[0]
            ram_gaps = [
                gap.gap_code
                for gap in root_built.ram_result.facts.coverage_gaps
            ]
            self.assertIn("DYNAMIC_IMPORT", ram_gaps)


class PolicyBudgetTests(unittest.TestCase):
    """C3: policy inheritance, aggregate envelope, caps (Packet #19-#25)."""

    def test_policy_inheritance_all_five_params(self) -> None:
        limits = {"extensions": (".py",), "ignored_directories": ("legacy",)}
        with build_on(shapes.POLICY_INHERITANCE_REPO, **limits) as (
            cg,
            _result,
            payload,
        ):
            ids = [e["component_id"] for e in payload["components"]]
            self.assertEqual(ids, ["component:.", "component:child"])
            self.assertNotIn("component:legacy/dead", ids)
            # The .json payload file is never re-admitted through slicing.
            for value in path_fields(payload):
                self.assertFalse(value.endswith(".json"))
            # Extensions={".py"}: manifests are S2-only, so both published
            # manifest refs come from the metadata channel.
            for entry in payload["components"]:
                for ref in entry["manifests"]:
                    self.assertEqual(
                        ref["source"],
                        cg.COMPONENT_MANIFEST_SOURCE_METADATA_CHANNEL,
                    )
            child = payload_entry(payload, "component:child")
            self.assertEqual(child["python_file_count"], 1)
            # Policy-key skips never break completeness (explicit choice).
            self.assertTrue(payload["dependencies_complete"])
            self.assertIn(
                "ignored-directory",
                payload["metadata_channel_skipped"],
            )

    def test_no_readmission_under_caller_caps(self) -> None:
        with shapes.monorepo_workspace(shapes.CALLER_CAP_REPO, max_files=3) as (
            _root,
            ws,
        ):
            admitted = {f.path for f in ws.inventory().files}
            # Frozen priority order at the root: five/four/one.py sort first.
            self.assertEqual(admitted, {"five.py", "four.py", "one.py"})
        with build_on(shapes.CALLER_CAP_REPO, max_files=3) as (_cg, _r, payload):
            # No re-admission: every inventory-derived public surface
            # (unassigned, evidence, owned .py counts) stays inside the main
            # admitted set; manifest references are channel-discovered
            # facts, covered by the bounded S2 discovery permission.
            for edge in payload["edges"]:
                for item in edge["evidence"]:
                    self.assertIn(item["path"], admitted)
            for value in payload["unassigned_files"]:
                self.assertIn(value, admitted)
            self.assertFalse(payload["dependencies_complete"])
            self.assertEqual(
                find_gap(payload, "INVENTORY_SKIPPED", "file-limit"),
                "channel=source-inventory; reason=file-limit; count=3",
            )
            for record in payload["unbuilt_components"]:
                self.assertIn(record["reason"], load_cg().UNBUILT_REASONS)
            root = payload_entry(payload, "component:.")
            self.assertEqual(root["python_file_count"], 3)

    def test_aggregate_model_call_envelope(self) -> None:
        client = FakeModelClient()
        options = SemanticOptions(model_id="fake-offline-model")
        budgets = load_cg().MonorepoBudgets(max_total_model_calls=1)
        with build_on(
            shapes.MODEL_CALL_REPO,
            monorepo_budgets=budgets,
            semantic_options=options,
            model_client=client,
        ) as (_cg, _result, payload):
            # Whole-repo envelope of one attempt: exactly one client call.
            self.assertEqual(client.calls, 1)
            detail = find_gap(
                payload, "BUDGET_EXHAUSTED", "aggregate-model-call-limit"
            )
            self.assertIsNotNone(detail)
            self.assertTrue(detail is not None and "count=1" in detail)
            # Non-dependency-evidence state: completeness is untouched.
            self.assertTrue(payload["dependencies_complete"])
            for entry in payload["components"]:
                self.assertIsNotNone(entry["digests"])
                self.assertLessEqual(
                    len(entry["semantic_topn"]["ranked_candidate_ids"]),
                    entry["semantic_topn"]["top_n"],
                )
        failing = FakeModelClient(fail=True)
        with build_on(
            shapes.MODEL_CALL_REPO,
            monorepo_budgets=budgets,
            semantic_options=options,
            model_client=failing,
        ) as (_cg2, _result2, payload2):
            # Failed attempts count towards the envelope and are not refunded.
            self.assertEqual(failing.calls, 1)
            self.assertIsNotNone(
                find_gap(payload2, "BUDGET_EXHAUSTED", "aggregate-model-call-limit")
            )
        with build_on(shapes.MODEL_CALL_REPO) as (_cg3, _result3, payload3):
            self.assertIsNone(
                find_gap(payload3, "BUDGET_EXHAUSTED", "aggregate-model-call-limit")
            )

    def test_budget_caps_edge_evidence_unassigned_unknown(self) -> None:
        cg = load_cg()
        budgets = cg.MonorepoBudgets(max_edges=1)
        with build_on(shapes.EDGE_CAP_REPO, monorepo_budgets=budgets) as (
            _cg,
            _result,
            payload,
        ):
            # Edge-priority single truncation of the mixed flow: the edge
            # survives, both unknown records are dropped and counted.
            self.assertEqual(len(payload["edges"]), 1)
            self.assertEqual(payload["unknown_imports"], [])
            self.assertEqual(
                find_gap(payload, "BUDGET_EXHAUSTED", "unknown-import-limit"),
                "reason=unknown-import-limit; count=2",
            )
            self.assertIsNone(
                find_gap(payload, "BUDGET_EXHAUSTED", "edge-limit")
            )
            self.assertFalse(payload["dependencies_complete"])
            truncated_total = sum(
                summary["unknown_truncated_count"]
                for summary in payload["scan_summaries"]
            )
            self.assertEqual(truncated_total, 2)
            # V8 same-semantic bound: len(edges) + len(unknown) <= cap.
            self.assertLessEqual(
                len(payload["edges"]) + len(payload["unknown_imports"]), 1
            )
        evidence_budgets = cg.MonorepoBudgets(max_edge_evidence=1)
        with build_on(
            shapes.EVIDENCE_CAP_REPO, monorepo_budgets=evidence_budgets
        ) as (_cg2, _result2, payload2):
            self.assertEqual(len(payload2["edges"]), 1)
            self.assertEqual(len(payload2["edges"][0]["evidence"]), 1)
            self.assertEqual(
                find_gap(payload2, "BUDGET_EXHAUSTED", "edge-evidence-limit"),
                "reason=edge-evidence-limit; count=7",
            )
            self.assertTrue(payload2["dependencies_complete"])
        unassigned_budgets = cg.MonorepoBudgets(max_unassigned_files=1)
        with build_on(
            shapes.UNASSIGNED_CAP_REPO, monorepo_budgets=unassigned_budgets
        ) as (_cg3, _result3, payload3):
            self.assertEqual(payload3["unassigned_files"], ["u1.py"])
            self.assertEqual(payload3["unassigned_file_count"], 2)
            self.assertEqual(
                find_gap(payload3, "BUDGET_EXHAUSTED", "unassigned-file-limit"),
                "reason=unassigned-file-limit; count=1",
            )
            # List truncation alone never breaks completeness.
            self.assertTrue(payload3["dependencies_complete"])

    def test_invalid_inputs_fail_closed(self) -> None:
        cg = load_cg()
        with shapes.monorepo_workspace(shapes.ROOT_ONLY) as (_root, ws):
            with self.assertRaises(ContractError):
                cg.detect_components("not-a-workspace")  # type: ignore[arg-type]
            with self.assertRaises(ContractError):
                cg.detect_components(None)  # type: ignore[arg-type]
            bad_ids = dict(monorepo_build_kwargs())
            bad_ids["tenant_id"] = 42  # type: ignore[assignment]
            with self.assertRaises(ContractError):
                cg.build_monorepo_profile(ws, **bad_ids)
            empty_digest = dict(monorepo_build_kwargs())
            empty_digest["repository_snapshot_digest"] = ""
            with self.assertRaises(ContractError):
                cg.build_monorepo_profile(ws, **empty_digest)
            with self.assertRaises(ValueError):
                cg.detect_components(ws, manifest_policy="bogus")
            with self.assertRaises(ValueError):
                cg.build_monorepo_profile(
                    ws, **monorepo_build_kwargs(), manifest_policy="bogus"
                )
            with self.assertRaises(ContractError):
                cg.detect_components(ws, budgets=12345)  # type: ignore[arg-type]

    def test_monorepo_budgets_invariants(self) -> None:
        cg = load_cg()
        defaults = cg.MonorepoBudgets()
        self.assertEqual(
            (
                defaults.max_components,
                defaults.max_edges,
                defaults.max_edge_evidence,
                defaults.max_unassigned_files,
                defaults.max_total_model_calls,
                defaults.aggregate_max_prompt_tokens,
                defaults.aggregate_max_output_tokens,
                defaults.aggregate_max_total_tokens,
                defaults.max_metadata_manifests,
                defaults.max_metadata_total_bytes,
            ),
            (16, 4_096, 64, 256, 8, 24_000, 4_096, 28_096, 64, 1_048_576),
        )
        # Legal-domain boundaries are accepted (three-way separation: the
        # schema hard caps equal the domain upper bounds; the total bound
        # 1,000,000 must still dominate prompt + output).
        cg.MonorepoBudgets(
            max_components=64,
            max_edges=16_384,
            max_edge_evidence=1_024,
            max_unassigned_files=4_096,
            max_total_model_calls=512,
            aggregate_max_prompt_tokens=999_999,
            aggregate_max_output_tokens=1,
            aggregate_max_total_tokens=1_000_000,
            max_metadata_manifests=1_024,
            max_metadata_total_bytes=1,
        )
        bad_values = (
            {"max_components": 0},
            {"max_components": 65},
            {"max_components": True},
            {"max_components": "16"},
            {"max_edges": -1},
            {"max_edges": 16_385},
            {"max_edge_evidence": 0},
            {"max_edge_evidence": 1_025},
            {"max_unassigned_files": 4_097},
            {"max_total_model_calls": 0},
            {"max_total_model_calls": 513},
            {"aggregate_max_prompt_tokens": 0},
            {"aggregate_max_output_tokens": 1_000_001},
            {"aggregate_max_total_tokens": 0},
            {"max_metadata_manifests": 0},
            {"max_metadata_manifests": 1_025},
            {"max_metadata_total_bytes": 0},
        )
        for overrides in bad_values:
            with self.subTest(overrides=overrides):
                with self.assertRaises(ValueError):
                    cg.MonorepoBudgets(**overrides)
        with self.assertRaises(ValueError):
            cg.MonorepoBudgets(
                aggregate_max_prompt_tokens=2_000,
                aggregate_max_output_tokens=4_096,
                aggregate_max_total_tokens=4_096,
            )

    def test_budget_exhaustion_partial_facts(self) -> None:
        cg = load_cg()
        # T1: component-count truncation keeps partial facts (16 built).
        with build_on(shapes.many_component_repo(17)) as (_cg, result, payload):
            self.assertFalse(payload["dependencies_complete"])
            self.assertEqual(len(result.per_component), 16)
            for entry in payload["components"]:
                self.assertTrue(entry["built"])
                self.assertIsNotNone(entry["digests"])
        # T3: mixed-cap truncation with a partially published flow (cap 2
        # keeps the edge plus one unknown record, drops the other).
        budgets = cg.MonorepoBudgets(max_edges=2)
        with build_on(shapes.EDGE_CAP_REPO, monorepo_budgets=budgets) as (
            _cg2,
            _result2,
            payload2,
        ):
            self.assertEqual(len(payload2["edges"]), 1)
            self.assertEqual(len(payload2["unknown_imports"]), 1)
            self.assertEqual(
                find_gap(payload2, "BUDGET_EXHAUSTED", "unknown-import-limit"),
                "reason=unknown-import-limit; count=1",
            )
            self.assertFalse(payload2["dependencies_complete"])
        # T7: unbuilt components force dependencies_complete=False (V7).
        synthetic = minimal_valid_payload()
        synthetic["components"][0]["built"] = False
        synthetic["components"][0]["digests"] = None
        synthetic["unbuilt_components"] = [
            {"component_id": "component:x", "reason": "cap-divergence"}
        ]
        synthetic["dependencies_complete"] = False
        _finalize(synthetic)
        self.assertIsNone(cg.validate_component_graph_payload(synthetic))
        lying = deepcopy(synthetic)
        lying["dependencies_complete"] = True
        _finalize(lying)
        with self.assertRaises(ContractError):
            cg.validate_component_graph_payload(lying)

    def test_read_failure_carrier_default_and_trigger(self) -> None:
        # Default carrier is zero (frozen field; read failures cannot be
        # constructed deterministically under a static snapshot -- declared,
        # not faked green). The T5 trigger stays in the closed set via the
        # synthetic decision-table path below.
        with build_on(shapes.ROOT_ONLY) as (_cg, _result, payload):
            for summary in payload["scan_summaries"]:
                self.assertEqual(summary["read_failure_file_count"], 0)
        synthetic = minimal_valid_payload()
        entry = synthetic["components"][0]
        entry["scan_summary"]["read_failure_file_count"] = 1
        for summary in synthetic["scan_summaries"]:
            if summary["component_id"] == entry["component_id"]:
                summary["read_failure_file_count"] = 1
        _finalize(synthetic)
        # Frozen decision table: read failures exclude "real-no-dependencies".
        self.assertEqual(
            classify_three_state(synthetic["components"][0], synthetic),
            "insufficient-evidence",
        )


class AdmissionPrivacyTests(unittest.TestCase):
    """C4: repo-level admission before component views (Packet #26-#29)."""

    def test_repo_level_admission_before_component_views(self) -> None:
        with build_on(shapes.SECRET_ANCHOR_REPO) as (_cg, result, payload):
            ids = [e["component_id"] for e in payload["components"]]
            self.assertEqual(ids, ["component:."])
            root = payload_entry(payload, "component:.")
            # INV-OWN-2: the admitted secret-shaped .py still counts towards
            # the owning component, but never appears on any public surface.
            self.assertEqual(root["python_file_count"], 2)
            for value in path_fields(payload):
                self.assertNotIn("secrets", value)
            built = result.per_component[0]
            observed = {
                item.path
                for section in (
                    built.ram_result.facts.entrypoints,
                    built.ram_result.facts.external_sources,
                    built.ram_result.facts.sensitive_sinks,
                    built.ram_result.facts.trust_boundaries,
                    built.ram_result.facts.unresolved_edges,
                )
                for item in section
            } | set(built.ram_result.facts.source_labels)
            # Two calibres, pinned apart: ownership counts the admitted
            # secret-shaped .py (python_file_count == 2), while the public
            # RAM universe is admission-filtered (good.py carries no
            # RAM-relevant facts here, so no path is published at all).
            self.assertEqual(observed, set())
            self.assertEqual(
                built.ram_result.facts.counters.get("modules_indexed"), 1
            )
            # Frozen RAM admission keeps its own carrier for the same file.
            ram_gaps = [
                (gap.gap_code, gap.detail)
                for gap in built.ram_result.facts.coverage_gaps
            ]
            self.assertIn(
                ("INVENTORY_SKIPPED", "reason=sensitive-filename; count=1"),
                ram_gaps,
            )

    def test_all_public_surfaces_admission_rules(self) -> None:
        with build_on(shapes.SECRET_ANCHOR_REPO) as (_cg, _result, payload):
            # Section 5.8 admission table, applied mechanically to every
            # path-bearing public surface (path fields only; digest values
            # are not paths -- the frozen V5 checks path fields likewise).
            for value in path_fields(payload):
                self.assertFalse(is_secret_shaped_path(value))

    def test_secret_gap_reason_count_no_filename(self) -> None:
        with build_on(shapes.SECRET_ANCHOR_REPO) as (_cg, _result, payload):
            details = gap_details(payload, "INVENTORY_SKIPPED")
            self.assertEqual(
                details,
                ["channel=source-inventory; reason=sensitive-filename; count=1"],
            )
            for detail in details:
                self.assertNotIn("secrets", detail)
                self.assertNotIn("hidden", detail)
                match = CHANNEL_GAP_DETAIL.match(detail)
                self.assertIsNotNone(match)

    def test_no_masked_paths_no_old_digest_changes(self) -> None:
        with build_on(shapes.GOLDEN_MONOREPO) as (_cg, _result, payload):
            serialized = json.dumps(payload)
            self.assertNotIn("redact:", serialized)
            self.assertNotIn("\\", serialized)
            # Graph identity carries exactly the new independent member.
            self.assertEqual(
                set(payload["identity"]), {"component_graph_digest"}
            )
            for entry in payload["components"]:
                self.assertEqual(
                    set(entry["digests"]),
                    {
                        "profile_content_digest",
                        "ram_facts_digest",
                        "semantic_result_digest",
                    },
                )
            # Old digest-family members never appear as graph-level fields.
            for legacy in (
                "wire_digest",
                "prompt_digest",
                "model_digest",
                "semantic_config_digest",
            ):
                self.assertNotIn(legacy, payload)


class CompletenessTests(unittest.TestCase):
    """C5: unified T1-T8 trigger set and three-state table (Packet #30-#34)."""

    def test_dependencies_complete_unified_triggers(self) -> None:
        cg = load_cg()
        cases: list[tuple[str, Any, dict[str, Any], bool]] = []

        cases.append(("T1", shapes.many_component_repo(17), {}, False))
        cases.append(
            (
                "T2",
                shapes.NESTED_ROOT_SERVICES_PACKAGES,
                {"ram_budgets": RamBudgets(max_python_files=1)},
                False,
            )
        )
        cases.append(
            (
                "T3",
                shapes.EDGE_CAP_REPO,
                {"monorepo_budgets": cg.MonorepoBudgets(max_edges=1)},
                False,
            )
        )
        cases.append(("T4", shapes.PARSE_ERROR_REPO, {}, False))
        cases.append(
            (
                "T6",
                shapes.T6_ADMISSION_SKIPPED_REPO,
                {"max_file_bytes": 128},
                False,
            )
        )
        cases.append(
            (
                "T8-count",
                shapes.METADATA_ONLY_ANCHORS,
                {"monorepo_budgets": cg.MonorepoBudgets(max_metadata_manifests=2)},
                False,
            )
        )
        cases.append(("no-trigger-golden", shapes.GOLDEN_MONOREPO, {}, True))
        cases.append(
            ("no-trigger-dynamic", shapes.DYNAMIC_IMPORT_REPO, {}, True)
        )
        cases.append(
            ("no-trigger-unknown", shapes.UNKNOWN_IMPORT_REPO, {}, True)
        )
        cases.append(
            (
                "no-trigger-evidence-cap",
                shapes.EVIDENCE_CAP_REPO,
                {"monorepo_budgets": cg.MonorepoBudgets(max_edge_evidence=1)},
                True,
            )
        )
        for name, repo, params, expected in cases:
            with self.subTest(case=name):
                with build_on(repo, **params) as (_cg2, _result, payload):
                    self.assertIs(payload["dependencies_complete"], expected)
        # Aggregate model/token state and SEMANTIC_MODEL_OFF never flip it.
        client = FakeModelClient()
        with build_on(
            shapes.MODEL_CALL_REPO,
            monorepo_budgets=cg.MonorepoBudgets(max_total_model_calls=1),
            semantic_options=SemanticOptions(model_id="fake-offline-model"),
            model_client=client,
        ) as (_cg3, _result3, payload3):
            self.assertTrue(payload3["dependencies_complete"])
        # T5/T7 belong to the closed set even though T5 cannot be built
        # deterministically under a static snapshot (declared, not faked).
        synthetic = minimal_valid_payload()
        synthetic["scan_summaries"][0]["read_failure_file_count"] = 1
        synthetic["components"][0]["scan_summary"]["read_failure_file_count"] = 1
        _finalize(synthetic)
        self.assertIs(
            classify_three_state(synthetic["components"][0], synthetic),
            "insufficient-evidence",
        )
        # Priority spot check: in-edge-only components fall to P2 (section
        # 5.2.4 participating-edge = incoming union outgoing).
        with build_on(shapes.SRC_LAYOUT_CROSS) as (_cg4, _result4, payload4):
            target = payload_entry(payload4, "component:b")
            self.assertEqual(
                classify_three_state(target, payload4), "insufficient-evidence"
            )
            source = payload_entry(payload4, "component:a")
            self.assertEqual(
                classify_three_state(source, payload4), "has-dependencies"
            )

    def test_parse_error_carried_in_graph(self) -> None:
        with build_on(shapes.PARSE_ERROR_REPO) as (_cg, _result, payload):
            entry = payload_entry(payload, "component:.")
            self.assertEqual(entry["scan_summary"]["parse_error_file_count"], 1)
            self.assertFalse(payload["dependencies_complete"])
            self.assertEqual(
                classify_three_state(entry, payload), "insufficient-evidence"
            )
            for value in path_fields(payload):
                self.assertIn(value, {"component:.", "", "pyproject.toml", "good.py"})

    def test_empty_edge_set_with_gap_not_no_dep(self) -> None:
        load_cg()  # PI-DR4 anchor: the frozen carrier must exist.
        # Real builds: an empty edge set with any gap never classifies as
        # "real no dependencies"; the all-hold positive does.
        with build_on(shapes.UNKNOWN_IMPORT_REPO) as (_cg, _r, payload):
            self.assertEqual(payload["edges"], [])
            entry = payload_entry(payload, "component:.")
            self.assertEqual(
                classify_three_state(entry, payload), "insufficient-evidence"
            )
        with build_on(shapes.UNASSIGNED_SCATTER) as (_cg2, _r2, payload2):
            self.assertEqual(payload2["edges"], [])
            tools = payload_entry(payload2, "component:tools")
            self.assertEqual(
                classify_three_state(tools, payload2), "insufficient-evidence"
            )
        with build_on(shapes.ROOT_ONLY) as (_cg3, _r3, payload3):
            solo = payload_entry(payload3, "component:.")
            self.assertEqual(
                classify_three_state(solo, payload3), "real-no-dependencies"
            )
        # Nine-conjunct table drive: breaking each P3 conjunct on a synthetic
        # payload yields the unique classification "insufficient-evidence".
        def mutate_case(mutate: Any) -> dict[str, Any]:
            payload = minimal_valid_payload()
            mutate(payload)
            return payload

        def break_complete(p: dict[str, Any]) -> None:
            p["dependencies_complete"] = False

        def break_unassigned(p: dict[str, Any]) -> None:
            p["unassigned_files"] = ["loose.py"]
            p["unassigned_file_count"] = 1

        def break_parse_error(p: dict[str, Any]) -> None:
            p["components"][0]["scan_summary"]["parse_error_file_count"] = 1
            p["scan_summaries"][0]["parse_error_file_count"] = 1

        def break_read_failure(p: dict[str, Any]) -> None:
            p["components"][0]["scan_summary"]["read_failure_file_count"] = 1
            p["scan_summaries"][0]["read_failure_file_count"] = 1

        def break_unknown_record(p: dict[str, Any]) -> None:
            p["unknown_imports"] = [
                {
                    "source_component_id": "component:x",
                    "imported_name": "missing",
                    "count": 1,
                }
            ]

        def break_unknown_truncated(p: dict[str, Any]) -> None:
            p["components"][0]["scan_summary"]["unknown_truncated_count"] = 1
            p["scan_summaries"][0]["unknown_truncated_count"] = 1

        def break_dynamic(p: dict[str, Any]) -> None:
            p["components"][0]["scan_summary"]["dynamic_import_site_count"] = 1
            p["scan_summaries"][0]["dynamic_import_site_count"] = 1

        def break_manifest_parse(p: dict[str, Any]) -> None:
            p["components"][0]["scan_summary"]["manifest_parse_failure_count"] = 1
            p["scan_summaries"][0]["manifest_parse_failure_count"] = 1

        def break_participating_edge(p: dict[str, Any]) -> None:
            second = two_component_payload()
            p["edges"] = deepcopy(second["edges"])
            p["edges"][0]["source_component_id"] = "component:y"
            p["edges"][0]["target_component_id"] = "component:x"

        breakers = (
            break_complete,
            break_unassigned,
            break_parse_error,
            break_read_failure,
            break_unknown_record,
            break_unknown_truncated,
            break_dynamic,
            break_manifest_parse,
            break_participating_edge,
        )
        for breaker in breakers:
            with self.subTest(breaker=breaker.__name__):
                payload = mutate_case(breaker)
                self.assertEqual(
                    classify_three_state(payload["components"][0], payload),
                    "insufficient-evidence",
                )
        baseline = mutate_case(lambda _p: None)
        self.assertEqual(
            classify_three_state(baseline["components"][0], baseline),
            "real-no-dependencies",
        )

    def test_failure_family_observability(self) -> None:
        cg = load_cg()
        families: list[tuple[str, Any, dict[str, Any], str]] = [
            (
                "parse-error",
                shapes.PARSE_ERROR_REPO,
                {},
                "parse_error_file_count",
            ),
            (
                "dynamic-import",
                shapes.DYNAMIC_IMPORT_REPO,
                {},
                "dynamic_import_site_count",
            ),
            (
                "unknown-truncated",
                shapes.EDGE_CAP_REPO,
                {"monorepo_budgets": cg.MonorepoBudgets(max_edges=1)},
                "unknown_truncated_count",
            ),
        ]
        for name, repo, params, field in families:
            with self.subTest(family=name):
                with build_on(repo, **params) as (_cg, _result, payload):
                    self.assertTrue(
                        any(
                            summary[field] > 0
                            for summary in payload["scan_summaries"]
                        ),
                        f"no carrier for failure family {name}",
                    )
        with build_on(shapes.UNKNOWN_IMPORT_REPO) as (_cg2, _r2, payload2):
            self.assertTrue(payload2["unknown_imports"])
        with build_on(shapes.NAMESPACE_PACKAGES) as (_cg3, _r3, payload3):
            statuses = {edge["status"] for edge in payload3["edges"]}
            self.assertIn("ambiguous", statuses)
        with build_on(shapes.RELATIVE_PACKAGE_IMPORTS) as (_cg4, _r4, payload4):
            statuses = {edge["status"] for edge in payload4["edges"]}
            self.assertIn("unresolved", statuses)
        with build_on(shapes.SECRET_ANCHOR_REPO) as (_cg5, _r5, payload5):
            self.assertIsNotNone(
                find_gap(payload5, "INVENTORY_SKIPPED", "sensitive-filename")
            )


class DigestIdentityTests(unittest.TestCase):
    """C6: digest/identity separation and binding (Packet #35-#37)."""

    def test_identical_content_components_equal_digest_allowed(self) -> None:
        with build_on(shapes.IDENTICAL_CONTENT_PAIR) as (_cg, _result, payload):
            by_id = {
                entry["component_id"]: entry for entry in payload["components"]
            }
            twin_a = by_id["component:twin_a"]
            twin_b = by_id["component:twin_b"]
            # API-05: identical local content under two anchors yields equal
            # digests; identity is carried by component_id, not by uniqueness.
            self.assertEqual(
                twin_a["digests"]["profile_content_digest"],
                twin_b["digests"]["profile_content_digest"],
            )
            self.assertEqual(
                twin_a["digests"]["ram_facts_digest"],
                twin_b["digests"]["ram_facts_digest"],
            )
            self.assertEqual(
                twin_a["digests"]["semantic_result_digest"],
                twin_b["digests"]["semantic_result_digest"],
            )
            self.assertNotEqual(
                twin_a["component_id"], twin_b["component_id"]
            )

    def test_component_identity_keyed_association(self) -> None:
        cg = load_cg()
        with build_on(shapes.GOLDEN_MONOREPO) as (_cg, result, payload):
            graph_by_id = {
                info.component_id: info for info in result.graph.components
            }
            canonical = canonical_dict_from_payload(payload)
            canonical_by_id = {
                item["component_id"]: item for item in canonical["components"]
            }
            # D2-04: payload digests == graph artifact_digests == canonical
            # projection, per field, for every built component.
            for entry in payload["components"]:
                artifact = graph_by_id[entry["component_id"]].artifact_digests
                projected = canonical_by_id[entry["component_id"]][
                    "artifact_digests"
                ]
                self.assertEqual(
                    entry["digests"]["profile_content_digest"],
                    artifact.profile_content_digest,
                )
                self.assertEqual(
                    entry["digests"]["ram_facts_digest"],
                    artifact.ram_facts_digest,
                )
                self.assertEqual(
                    entry["digests"]["semantic_result_digest"],
                    artifact.semantic_result_digest,
                )
                self.assertEqual(
                    entry["digests"]["profile_content_digest"],
                    projected["profile_content_digest"],
                )
                self.assertEqual(
                    entry["digests"]["ram_facts_digest"],
                    projected["ram_facts_digest"],
                )
                self.assertEqual(
                    entry["digests"]["semantic_result_digest"],
                    projected["semantic_result_digest"],
                )
            # Swap two components' references without updating the identity
            # digest: V9 (canonical key set includes artifact_digests) must
            # reject the stale swap (R3 path 1).
            swapped = deepcopy(payload)
            first, second = swapped["components"][0], swapped["components"][1]
            first["digests"], second["digests"] = second["digests"], first["digests"]
            with self.assertRaises(ContractError):
                cg.validate_component_graph_payload(swapped)
        # built/null boundary on a synthetic payload (V7 cross-check).
        synthetic = minimal_valid_payload()
        synthetic["components"][0]["built"] = False
        synthetic["components"][0]["digests"] = None
        synthetic["unbuilt_components"] = [
            {
                "component_id": "component:x",
                "reason": cg.UNBUILT_REASON_VIEW_UNFORMABLE,
            }
        ]
        synthetic["dependencies_complete"] = False
        _finalize(synthetic)
        self.assertIsNone(cg.validate_component_graph_payload(synthetic))
        forged = deepcopy(synthetic)
        forged["components"][0]["digests"] = {
            "profile_content_digest": HEX_A,
            "ram_facts_digest": HEX_B,
            "semantic_result_digest": HEX_C,
        }
        _finalize(forged)
        with self.assertRaises(ContractError):
            cg.validate_component_graph_payload(forged)
        bad_hex = deepcopy(synthetic)
        bad_hex["components"][0]["digests"] = {
            "profile_content_digest": "nothex",
            "ram_facts_digest": HEX_B,
            "semantic_result_digest": HEX_C,
        }
        _finalize(bad_hex)
        with self.assertRaises(ContractError):
            cg.validate_component_graph_payload(bad_hex)

    def test_content_change_digest_changes(self) -> None:
        load_cg()  # PI-DR4 anchor.
        with shapes.monorepo_tree(shapes.CONTENT_CHANGE_REPO) as root:
            sub_v1 = RepositoryWorkspace(root / "single")
            profile_v1 = build_repository_profile_for_oracle(sub_v1)
            ram_v1 = build_python_ram_facts(sub_v1)
            ram_digest_v1 = ram_facts_digest(ram_v1.facts)
            semantic_v1 = semantic_result_digest(
                build_semantic_top_n(ram_v1.facts),
                input_facts_digest=ram_digest_v1,
            )
        edited = dict(shapes.CONTENT_CHANGE_REPO)
        edited.update(shapes.CONTENT_CHANGE_EDIT)
        with shapes.monorepo_tree(edited) as root2:
            sub_v2 = RepositoryWorkspace(root2 / "single")
            profile_v2 = build_repository_profile_for_oracle(sub_v2)
            ram_v2 = build_python_ram_facts(sub_v2)
            ram_digest_v2 = ram_facts_digest(ram_v2.facts)
            semantic_v2 = semantic_result_digest(
                build_semantic_top_n(ram_v2.facts),
                input_facts_digest=ram_digest_v2,
            )
        # D2-02: prove each leg's discriminability through the frozen public
        # API before asserting graph-level transfer. The tainted-flow edit
        # changes all three legs (a sensitive-sink finding appears, ranked
        # candidates appear, source keywords change).
        legs_changed = {
            "profile": profile_v1 != profile_v2,
            "ram": ram_digest_v1 != ram_digest_v2,
            "semantic": semantic_v1 != semantic_v2,
        }
        self.assertTrue(legs_changed["ram"], "RAM leg must be discriminative")
        self.assertTrue(legs_changed["profile"], "profile leg must change")
        self.assertTrue(all(legs_changed.values()), legs_changed)

        with build_on(shapes.CONTENT_CHANGE_REPO) as (_cg, _result, payload_v1):
            pass
        with build_on(edited) as (_cg2, _result2, payload_v2):
            pass
        self.assertNotEqual(
            payload_v1["identity"]["component_graph_digest"],
            payload_v2["identity"]["component_graph_digest"],
        )
        entry_v1 = payload_entry(payload_v1, "component:single")
        entry_v2 = payload_entry(payload_v2, "component:single")
        for leg, key in (
            ("profile", "profile_content_digest"),
            ("ram", "ram_facts_digest"),
            ("semantic", "semantic_result_digest"),
        ):
            self.assertNotEqual(
                entry_v1["digests"][key],
                entry_v2["digests"][key],
                f"{leg} leg must transfer to the graph payload",
            )
        # The bystander component's references stay untouched.
        by_v1 = payload_entry(payload_v1, "component:bystander")
        by_v2 = payload_entry(payload_v2, "component:bystander")
        self.assertEqual(by_v1["digests"], by_v2["digests"])


def build_repository_profile_for_oracle(workspace: RepositoryWorkspace) -> str:
    """Oracle helper: per-component profile content digest via frozen API."""

    from lima.audit.inventory import build_repository_profile

    return build_repository_profile(
        workspace,
        **shapes.MONOREPO_PROFILE_KWARGS,
        producer=shapes.COMPONENT_GRAPH_PRODUCER,
    ).envelope.content_digest


class ConsumerClosureTests(unittest.TestCase):
    """C7: public-artifact consumption and validator dimensions (#42-#49)."""

    def test_consumer_obtains_all_facts_from_public_artifacts(self) -> None:
        with shapes.monorepo_workspace(shapes.MODEL_CALL_REPO) as (_root, ws):
            admitted_repo_files = {f.path for f in ws.inventory().files}
        with build_on(shapes.MODEL_CALL_REPO) as (cg, result, payload):
            entries = {
                entry["component_id"]: entry for entry in payload["components"]
            }
            built_by_id = {
                b.component.component_id: b for b in result.per_component
            }
            for component_id, built in built_by_id.items():
                entry = entries[component_id]
                self.assertTrue(entry["built"])
                profile_bytes = encode_profile_envelope(
                    built.profile_result.envelope, built.profile_result.profile
                )
                ram_wire = dict(built.ram_wire)
                # Section 5.4.7 consumer baseline (verbatim semantics), with
                # only public artifacts: no workspace, no rebuild, no
                # builder-private memory objects.
                envelope, _profile = decode_profile_envelope(profile_bytes)
                self.assertIsNone(validate_ram_wire_payload(ram_wire))
                self.assertEqual(
                    envelope.content_digest,
                    entry["digests"]["profile_content_digest"],
                )
                self.assertEqual(
                    ram_facts_digest_from_wire(ram_wire),
                    entry["digests"]["ram_facts_digest"],
                )
                self.assertEqual(
                    semantic_result_digest_from_wire(ram_wire),
                    entry["digests"]["semantic_result_digest"],
                )
                self.assertEqual(
                    ram_wire_digest(ram_wire),
                    ram_wire["identity"]["wire_digest"],
                )
                self.assertNotEqual(
                    ram_wire_digest(ram_wire),
                    ram_facts_digest_from_wire(ram_wire),
                )
                gap_codes = [
                    gap["gap_code"]
                    for section in ("ram", "semantic")
                    for gap in ram_wire[section]["coverage_gaps"]
                ]
                required, triggers = execution_required_from_gaps(gap_codes)
                self.assertEqual(
                    ram_wire["execution_required"],
                    {"required": required, "trigger_gap_codes": list(triggers)},
                )
                # D2-01 four-way bound-digest equality (Assignment section D):
                # recomputed binding == stored result digest == wire
                # recomputation == graph payload entry slot.
                facts_digest = ram_facts_digest(built.ram_result.facts)
                bound_digest = semantic_result_digest(
                    built.semantic_result, input_facts_digest=facts_digest
                )
                self.assertEqual(
                    bound_digest, built.semantic_result.result_digest
                )
                self.assertEqual(
                    bound_digest, semantic_result_digest_from_wire(ram_wire)
                )
                self.assertEqual(
                    bound_digest, entry["digests"]["semantic_result_digest"]
                )
                # D2-01 negative control: the unbound recomputation differs.
                unbound = semantic_result_digest(built.semantic_result)
                self.assertNotEqual(unbound, bound_digest)
                # Coordinate mapping: repo path == root_dir + "/" + the
                # component-internal path of every published fact.
                prefix = built.component.root_dir
                for section in (
                    built.ram_result.facts.entrypoints,
                    built.ram_result.facts.external_sources,
                    built.ram_result.facts.sensitive_sinks,
                    built.ram_result.facts.trust_boundaries,
                    built.ram_result.facts.unresolved_edges,
                ):
                    for item in section:
                        repo_path = (
                            f"{prefix}/{item.path}" if prefix else item.path
                        )
                        self.assertIn(repo_path, admitted_repo_files)
                # Tamper rejection: ranked score changes break the wire digest.
                if ram_wire["semantic"]["ranked"]:
                    tampered = deepcopy(ram_wire)
                    tampered["semantic"]["ranked"][0]["score"] = (
                        int(tampered["semantic"]["ranked"][0]["score"]) + 1
                    )
                    with self.assertRaises(ContractError):
                        validate_ram_wire_payload(tampered)
            # Graph-level digest recomputation from the payload alone.
            self.assertEqual(
                compute_content_digest(canonical_dict_from_payload(payload)),
                payload["identity"]["component_graph_digest"],
            )
            _ = cg

    def test_validator_unknown_fields(self) -> None:
        cg = load_cg()
        base = minimal_valid_payload()
        self.assertIsNone(cg.validate_component_graph_payload(deepcopy(base)))
        top = deepcopy(base)
        top["unexpected"] = 1
        with self.assertRaises(ContractError):
            cg.validate_component_graph_payload(top)
        nested = deepcopy(base)
        nested["components"][0]["unexpected"] = 1
        with self.assertRaises(ContractError):
            cg.validate_component_graph_payload(nested)
        edge_level = two_component_payload()
        edge_level["edges"][0]["unexpected"] = 1
        _finalize(edge_level)
        with self.assertRaises(ContractError):
            cg.validate_component_graph_payload(edge_level)

    def test_validator_enums_and_digest_format(self) -> None:
        cg = load_cg()
        base = minimal_valid_payload()

        def prepared(mutate: Any) -> dict[str, Any]:
            payload = deepcopy(base)
            mutate(payload)
            return payload

        def bad_status(p: dict[str, Any]) -> None:
            payload = two_component_payload()
            payload["edges"][0]["status"] = "bogus"
            del p["edges"]
            p["edges"] = payload["edges"]
            p["components"].append(deepcopy(payload["components"][1]))
            p["scan_summaries"].append(_scan_zero("component:y"))

        def bad_kind(p: dict[str, Any]) -> None:
            p["components"][0]["manifests"][0]["manifest_kind"] = "gemfile"

        def bad_source(p: dict[str, Any]) -> None:
            p["components"][0]["manifests"][0]["source"] = "ftp"

        def bad_digest(p: dict[str, Any]) -> None:
            p["components"][0]["digests"]["ram_facts_digest"] = "XYZ"

        def bad_identity(p: dict[str, Any]) -> None:
            p["identity"]["component_graph_digest"] = "short"

        def bad_line(p: dict[str, Any]) -> None:
            payload = two_component_payload()
            payload["edges"][0]["evidence"][0]["line"] = 0
            p["edges"] = payload["edges"]
            p["components"].append(deepcopy(payload["components"][1]))
            p["scan_summaries"].append(_scan_zero("component:y"))

        def bad_schema_version(p: dict[str, Any]) -> None:
            p["schema_version"] = "3.0"

        def bad_model_kind(p: dict[str, Any]) -> None:
            p["model_kind"] = "lima.other-model"

        for mutate in (
            bad_status,
            bad_kind,
            bad_source,
            bad_digest,
            bad_identity,
            bad_line,
            bad_schema_version,
            bad_model_kind,
        ):
            with self.subTest(mutate=mutate.__name__):
                with self.assertRaises(ContractError):
                    cg.validate_component_graph_payload(prepared(mutate))

    def test_validator_uniqueness_target_existence_ordering(self) -> None:
        cg = load_cg()
        base = two_component_payload()
        self.assertIsNone(cg.validate_component_graph_payload(deepcopy(base)))

        def prepared(mutate: Any) -> dict[str, Any]:
            payload = deepcopy(base)
            mutate(payload)
            return payload

        def duplicate_id(p: dict[str, Any]) -> None:
            p["components"].append(deepcopy(p["components"][0]))

        def ghost_target(p: dict[str, Any]) -> None:
            p["edges"][0]["target_component_id"] = "component:ghost"

        def ghost_unknown_source(p: dict[str, Any]) -> None:
            p["unknown_imports"][0]["source_component_id"] = "component:ghost"

        def ghost_scan_summary(p: dict[str, Any]) -> None:
            p["scan_summaries"][0]["component_id"] = "component:ghost"

        def ghost_unbuilt(p: dict[str, Any]) -> None:
            p["unbuilt_components"] = [
                {"component_id": "component:ghost", "reason": "cap-divergence"}
            ]

        def unsorted_components(p: dict[str, Any]) -> None:
            p["components"].reverse()

        def unsorted_evidence(p: dict[str, Any]) -> None:
            edge = two_component_payload(max_edge_evidence=64)["edges"][0]
            edge["evidence"].append(
                {"path": "x/a.py", "line": 1, "imported_name": "ylib"}
            )
            # Sorted order would be [x/a.py, x/main.py]; the appended order
            # keeps the higher path first, which V6 must reject.
            p["edges"][0]["evidence"] = edge["evidence"]

        def duplicate_edge(p: dict[str, Any]) -> None:
            p["edges"].append(deepcopy(p["edges"][0]))

        def duplicate_manifest(p: dict[str, Any]) -> None:
            p["components"][0]["manifests"].append(
                deepcopy(p["components"][0]["manifests"][0])
            )

        for mutate in (
            duplicate_id,
            ghost_target,
            ghost_unknown_source,
            ghost_scan_summary,
            ghost_unbuilt,
            unsorted_components,
            unsorted_evidence,
            duplicate_edge,
            duplicate_manifest,
        ):
            with self.subTest(mutate=mutate.__name__):
                candidate = prepared(mutate)
                _finalize(candidate)
                with self.assertRaises(ContractError):
                    cg.validate_component_graph_payload(candidate)

    def test_validator_cross_field_and_caps(self) -> None:
        cg = load_cg()
        base = two_component_payload()
        self.assertIsNone(cg.validate_component_graph_payload(deepcopy(base)))

        def prepared(mutate: Any) -> dict[str, Any]:
            payload = deepcopy(base)
            mutate(payload)
            return payload

        def empty_mismatch(p: dict[str, Any]) -> None:
            p["components"][0]["is_empty"] = True

        def null_digests_built(p: dict[str, Any]) -> None:
            p["components"][0]["digests"] = None

        def unbuilt_without_record(p: dict[str, Any]) -> None:
            p["components"][0]["built"] = False
            p["components"][0]["digests"] = None
            p["dependencies_complete"] = False

        def unbuilt_but_complete(p: dict[str, Any]) -> None:
            p["components"][0]["built"] = False
            p["components"][0]["digests"] = None
            p["unbuilt_components"] = [
                {"component_id": "component:x", "reason": "cap-divergence"}
            ]

        def count_below_list(p: dict[str, Any]) -> None:
            p["unassigned_files"] = ["loose.py"]
            p["unassigned_file_count"] = 0

        def top_n_zero(p: dict[str, Any]) -> None:
            for entry in p["components"]:
                entry["semantic_topn"]["top_n"] = 0

        def top_n_over_100(p: dict[str, Any]) -> None:
            for entry in p["components"]:
                entry["semantic_topn"]["top_n"] = 101

        def ranked_over_top_n(p: dict[str, Any]) -> None:
            entry = p["components"][0]
            entry["semantic_topn"]["ranked_candidate_ids"] = [
                f"sensitive-sink:x{i}.py:-#0" for i in range(21)
            ]

        def conservation_broken(p: dict[str, Any]) -> None:
            p["manifests_discovered_count"] = 2

        def metadata_over_discovered(p: dict[str, Any]) -> None:
            p["metadata_manifest_count"] = 2

        def published_over_metadata(p: dict[str, Any]) -> None:
            ref = p["components"][0]["manifests"][0]
            ref["source"] = "metadata-channel"
            p["metadata_manifest_count"] = 0

        def mixed_over_cap(p: dict[str, Any]) -> None:
            p["build"]["monorepo_budgets"]["max_edges"] = 1

        def evidence_over_cap(p: dict[str, Any]) -> None:
            p["build"]["monorepo_budgets"]["max_edge_evidence"] = 0

        def unassigned_over_cap(p: dict[str, Any]) -> None:
            p["build"]["monorepo_budgets"]["max_unassigned_files"] = 0
            p["unassigned_files"] = ["loose.py"]
            p["unassigned_file_count"] = 1

        def metadata_over_budget(p: dict[str, Any]) -> None:
            p["metadata_manifest_count"] = 65
            p["manifests_discovered_count"] = 65

        def skipped_key_off_vocabulary(p: dict[str, Any]) -> None:
            p["metadata_channel_skipped"] = {"made-up-key": 1}

        for mutate in (
            empty_mismatch,
            null_digests_built,
            unbuilt_without_record,
            unbuilt_but_complete,
            count_below_list,
            top_n_zero,
            top_n_over_100,
            ranked_over_top_n,
            conservation_broken,
            metadata_over_discovered,
            published_over_metadata,
            mixed_over_cap,
            evidence_over_cap,
            unassigned_over_cap,
            metadata_over_budget,
            skipped_key_off_vocabulary,
        ):
            with self.subTest(mutate=mutate.__name__):
                candidate = prepared(mutate)
                _finalize(candidate)
                with self.assertRaises(ContractError):
                    cg.validate_component_graph_payload(candidate)

    def test_validator_graph_digest_recompute(self) -> None:
        cg = load_cg()
        base = two_component_payload()
        original = base["identity"]["component_graph_digest"]

        def prepared(mutate: Any) -> dict[str, Any]:
            payload = deepcopy(base)
            mutate(payload)
            return payload

        def tamper_component(p: dict[str, Any]) -> None:
            p["components"][0]["python_file_count"] = 5

        def tamper_root_dir(p: dict[str, Any]) -> None:
            p["components"][0]["root_dir"] = "z"

        def tamper_manifest_source(p: dict[str, Any]) -> None:
            p["components"][0]["manifests"][0]["source"] = "metadata-channel"

        def tamper_edge_evidence(p: dict[str, Any]) -> None:
            p["edges"][0]["evidence"][0]["line"] = 9

        def tamper_unknown_count(p: dict[str, Any]) -> None:
            p["unknown_imports"][0]["count"] = 7

        def tamper_scan_summary(p: dict[str, Any]) -> None:
            p["scan_summaries"][0]["manifest_parse_failure_count"] = 2
            p["components"][0]["scan_summary"]["manifest_parse_failure_count"] = 2

        def tamper_complete(p: dict[str, Any]) -> None:
            p["dependencies_complete"] = False

        def tamper_counts(p: dict[str, Any]) -> None:
            p["collaboration_manifest_count"] = 1

        def swap_artifact_refs(p: dict[str, Any]) -> None:
            first, second = p["components"][0], p["components"][1]
            first["digests"], second["digests"] = second["digests"], first["digests"]

        for mutate in (
            tamper_component,
            tamper_root_dir,
            tamper_manifest_source,
            tamper_edge_evidence,
            tamper_unknown_count,
            tamper_scan_summary,
            tamper_complete,
            tamper_counts,
            swap_artifact_refs,
        ):
            with self.subTest(mutate=mutate.__name__):
                candidate = prepared(mutate)
                self.assertNotEqual(
                    compute_content_digest(canonical_dict_from_payload(candidate)),
                    original,
                )
                with self.assertRaises(ContractError):
                    cg.validate_component_graph_payload(candidate)
        # Honest capability boundary (section 5.4.6/V9): a content digest is
        # a self-consistency check, not a signature -- an attacker who also
        # recomputes the identity digest passes this path.
        recomputed = prepared(tamper_component)
        _finalize(recomputed)
        self.assertIsNone(cg.validate_component_graph_payload(recomputed))

    def test_validator_secret_shaped_path_rejected(self) -> None:
        cg = load_cg()
        base = two_component_payload()

        def prepared(mutate: Any) -> dict[str, Any]:
            payload = deepcopy(base)
            mutate(payload)
            _finalize(payload)
            return payload

        def secret_manifest(p: dict[str, Any]) -> None:
            p["components"][0]["manifests"][0]["path"] = "x/secrets/pyproject.toml"

        def secret_evidence(p: dict[str, Any]) -> None:
            p["edges"][0]["evidence"][0]["path"] = "secrets/leaked.py"

        def secret_unassigned(p: dict[str, Any]) -> None:
            p["unassigned_files"] = ["secrets/stray.py"]
            p["unassigned_file_count"] = 1

        def secret_root_dir(p: dict[str, Any]) -> None:
            p["components"][0]["root_dir"] = "secrets"
            p["components"][0]["component_id"] = "component:secrets"
            p["scan_summaries"][0]["component_id"] = "component:secrets"

        for mutate in (
            secret_manifest,
            secret_evidence,
            secret_unassigned,
            secret_root_dir,
        ):
            with self.subTest(mutate=mutate.__name__):
                with self.assertRaises(ContractError):
                    cg.validate_component_graph_payload(prepared(mutate))

    def test_validator_unicode_and_charset_range(self) -> None:
        cg = load_cg()
        base = two_component_payload()
        unicode_ok = deepcopy(base)
        unicode_ok["components"][0]["manifests"][0]["path"] = "x/café/mod.py"
        unicode_ok["components"][0]["manifests"][0]["source"] = "metadata-channel"
        unicode_ok["metadata_manifest_count"] = 1
        _finalize(unicode_ok)
        self.assertIsNone(cg.validate_component_graph_payload(unicode_ok))

        def prepared(mutate: Any) -> dict[str, Any]:
            payload = deepcopy(base)
            mutate(payload)
            _finalize(payload)
            return payload

        def nul_path(p: dict[str, Any]) -> None:
            p["components"][0]["manifests"][0]["path"] = "x/ba\x00d.py"

        def absolute_path(p: dict[str, Any]) -> None:
            p["components"][0]["manifests"][0]["path"] = "/abs/mod.py"

        def dotdot_path(p: dict[str, Any]) -> None:
            p["components"][0]["manifests"][0]["path"] = "../escape.py"

        def trailing_slash(p: dict[str, Any]) -> None:
            p["components"][0]["root_dir"] = "x/"
            p["unassigned_files"] = ["x/"]

        def charset_component_id(p: dict[str, Any]) -> None:
            p["components"][0]["component_id"] = "component:café"
            p["components"][0]["root_dir"] = "café"
            p["scan_summaries"][0]["component_id"] = "component:café"

        for mutate in (
            nul_path,
            absolute_path,
            dotdot_path,
            trailing_slash,
            charset_component_id,
        ):
            with self.subTest(mutate=mutate.__name__):
                with self.assertRaises(ContractError):
                    cg.validate_component_graph_payload(prepared(mutate))

    def test_no_execution_marker_absent(self) -> None:
        marker = Path(tempfile.gettempdir()) / "lima_ip0023_exec_marker_dir"
        evil = {
            "pyproject.toml": "[project]\nname = \"evilhost\"\nversion = \"1.0\"\n",
            "evil/setup.py": (
                "import os\n"
                "import pyproj_fake_missing\n"  # never executed; parse only
                "\n"
                "\n"
                "def setup():\n"
                "    os.makedirs(r'"
                + str(marker).replace("\\", "\\\\")
                + "', exist_ok=True)\n"
            ),
            "main.py": "def main():\n    return 31\n",
        }
        if marker.exists():
            shutil.rmtree(marker, ignore_errors=True)
        with build_on(evil) as (_cg, _result, payload):
            self.assertFalse(marker.exists())
        self.assertFalse(marker.exists())
        # setup.py anchors its own component; the marker-writing file is
        # parsed, never executed, and lands in the evil component's slice.
        root = payload_entry(payload, "component:.")
        self.assertEqual(root["python_file_count"], 1)
        evil_entry = payload_entry(payload, "component:evil")
        self.assertEqual(evil_entry["python_file_count"], 1)

    def test_static_no_network_no_env_no_syspath(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
        banned_imports = {
            "socket",
            "urllib",
            "urllib.request",
            "urllib.error",
            "http",
            "http.client",
            "requests",
            "httpx",
            "ftplib",
            "telnetlib",
            "smtplib",
            "subprocess",
            "spacy",
        }
        banned_attr_chains = ("os.environ", "sys.path")
        write_calls = {
            "open",
            "write_text",
            "write_bytes",
            "mkdir",
            "remove",
            "unlink",
            "rmtree",
            "makedirs",
            "rename",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotIn(alias.name, banned_imports)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                self.assertNotIn(module, banned_imports)
                self.assertFalse(module.startswith("urllib"))
                self.assertFalse(module.startswith("http"))
            elif isinstance(node, ast.Attribute):
                chain = _attribute_chain(node)
                for banned in banned_attr_chains:
                    self.assertNotEqual(chain, banned)
                if isinstance(node.ctx, ast.Load):
                    self.assertNotIn(node.attr, write_calls)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                self.assertNotIn(node.id, write_calls)


def _attribute_chain(node: ast.AST) -> str:
    parts: list[str] = []
    current: ast.AST = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


class DeterminismTests(unittest.TestCase):
    """#52: determinism and input-order invariance."""

    def test_determinism_and_input_order_invariance(self) -> None:
        cg = load_cg()
        with shapes.monorepo_workspace(shapes.GOLDEN_MONOREPO) as (_root, ws):
            first = cg.build_monorepo_profile(ws, **monorepo_build_kwargs())
        with shapes.monorepo_workspace(shapes.GOLDEN_MONOREPO) as (_root2, ws2):
            second = cg.build_monorepo_profile(ws2, **monorepo_build_kwargs())
        self.assertEqual(
            cg.component_graph_digest(first.graph),
            cg.component_graph_digest(second.graph),
        )
        self.assertEqual(first.graph, second.graph)
        self.assertEqual(first.metering, second.metering)
        self.assertEqual(first.discovery, second.discovery)
        for left, right in zip(first.per_component, second.per_component, strict=True):
            self.assertEqual(left.component, right.component)
            self.assertEqual(
                left.profile_result.envelope.content_digest,
                right.profile_result.envelope.content_digest,
            )
            self.assertEqual(
                ram_facts_digest(left.ram_result.facts),
                ram_facts_digest(right.ram_result.facts),
            )
            self.assertEqual(
                left.semantic_result.result_digest,
                right.semantic_result.result_digest,
            )
        # Input-order invariance: same content, reversed materialization.
        reversed_root = Path(tempfile.mkdtemp(prefix="lima-ip0023-rev-"))
        try:
            for rel in sorted(shapes.GOLDEN_MONOREPO, reverse=True):
                target = reversed_root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(
                    shapes.GOLDEN_MONOREPO[rel],
                    encoding="utf-8",
                    newline="\n",
                )
            ws3 = RepositoryWorkspace(reversed_root)
            third = cg.build_monorepo_profile(ws3, **monorepo_build_kwargs())
        finally:
            shutil.rmtree(reversed_root, ignore_errors=True)
        self.assertEqual(
            cg.component_graph_digest(first.graph),
            cg.component_graph_digest(third.graph),
        )
        self.assertEqual(first.graph.components, third.graph.components)
        self.assertEqual(first.graph.edges, third.graph.edges)


class AdmissionSkipT6Tests(unittest.TestCase):
    """#53: main-inventory skipped .py files break completeness (ER SF-1)."""

    def test_admission_skipped_py_t6_incomplete_and_carried(self) -> None:
        with build_on(shapes.T6_ADMISSION_SKIPPED_REPO, max_file_bytes=128) as (
            _cg,
            _result,
            payload,
        ):
            self.assertFalse(payload["dependencies_complete"])
            details = sorted(gap_details(payload, "INVENTORY_SKIPPED"))
            self.assertEqual(
                details,
                [
                    "channel=source-inventory; reason=binary; count=1",
                    "channel=source-inventory; reason=file-size-limit; count=1",
                    "channel=source-inventory; reason=non-utf8; count=1",
                ],
            )
            # INV-OWN-2: only good.py is admitted; the three skipped files
            # appear on no public surface.
            root = payload_entry(payload, "component:.")
            self.assertEqual(root["python_file_count"], 1)
            for value in path_fields(payload):
                self.assertNotIn("oversize", value)
                self.assertNotIn("binary", value)
                self.assertNotIn("nonutf8", value)
                self.assertNotIn("guide", value)
            # Exempt keys (unsupported-extension / ignored-directory) never
            # enter the T6 key set: only the three loss keys above appear.
            for detail in details:
                self.assertNotIn("unsupported-extension", detail)
                self.assertNotIn("ignored-directory", detail)
        with shapes.monorepo_workspace(
            shapes.T6_ADMISSION_SKIPPED_REPO, max_file_bytes=128
        ) as (_root, ws):
            skipped = dict(ws.inventory().skipped)
        self.assertEqual(
            skipped,
            {
                "file-size-limit": 1,
                "binary": 1,
                "non-utf8": 1,
                "unsupported-extension": 1,
                "ignored-directory": 1,
            },
        )


class ManifestPolicyTests(unittest.TestCase):
    """#54/#60/#71: metadata channel default positive / strict negative."""

    def test_manifest_metadata_default_positive_and_strict_negative(self) -> None:
        with build_on(shapes.METADATA_ONLY_ANCHORS) as (cg, _result, payload):
            self.assertEqual(
                [e["component_id"] for e in payload["components"]], ["component:."]
            )
            root = payload["components"][0]
            self.assertEqual(
                [ref["path"] for ref in root["manifests"]],
                ["go.mod", "pom.xml", "requirements.txt", "setup.cfg"],
            )
            for ref in root["manifests"]:
                self.assertEqual(
                    ref["source"],
                    cg.COMPONENT_MANIFEST_SOURCE_METADATA_CHANNEL,
                )
            self.assertEqual(root["python_file_count"], 2)
            self.assertEqual(payload["manifests_discovered_count"], 4)
            self.assertEqual(payload["metadata_manifest_count"], 4)
            self.assertEqual(
                payload["collaboration_manifest_count"] + payload["overflow_manifest_count"],
                0,
            )
            self.assertTrue(payload["dependencies_complete"])
        with build_on(
            shapes.METADATA_ONLY_ANCHORS, manifest_policy="admitted-only"
        ) as (_cg2, _result2, payload2):
            self.assertEqual(payload2["components"], [])
            self.assertEqual(
                payload2["unassigned_files"], ["nested/note.py", "script.py"]
            )
            self.assertEqual(payload2["unassigned_file_count"], 2)
            self.assertEqual(payload2["manifests_discovered_count"], 0)
            self.assertEqual(payload2["metadata_manifest_count"], 0)
            self.assertEqual(payload2["metadata_channel_skipped"], {})
            # Strict closure is an explicit choice: no T8, completeness kept.
            self.assertTrue(payload2["dependencies_complete"])
        with shapes.monorepo_workspace(shapes.METADATA_ONLY_ANCHORS) as (_root, ws):
            skipped = dict(ws.inventory().skipped)
        self.assertEqual(skipped.get("unsupported-extension"), 4)


class PreciseViewTests(unittest.TestCase):
    """#55/#56: file-list view positives (P60-V3-01/CL-02)."""

    def test_detect_components_same_name_dir_not_nested_anchor_builds(self) -> None:
        with build_on(shapes.SAME_NAME_DIR_REPO) as (_cg, _result, payload):
            by_id = {e["component_id"]: e for e in payload["components"]}
            self.assertEqual(
                sorted(by_id), ["component:a", "component:a/b"]
            )
            self.assertEqual(by_id["component:a"]["python_file_count"], 2)
            self.assertEqual(by_id["component:a/b"]["python_file_count"], 1)
            # Same-name directory is a positive case: nothing is unbuilt.
            self.assertEqual(payload["unbuilt_components"], [])
            self.assertTrue(all(e["built"] for e in payload["components"]))
            self.assertTrue(
                all(e["digests"] is not None for e in payload["components"])
            )

    def test_parent_component_profile_manifest_excludes_child(self) -> None:
        with build_on(shapes.PARENT_CHILD_MANIFESTS) as (_cg, result, payload):
            by_id = {e["component_id"]: e for e in payload["components"]}
            self.assertEqual(
                [ref["path"] for ref in by_id["component:."]["manifests"]],
                ["pyproject.toml", "requirements.txt"],
            )
            self.assertEqual(
                [ref["path"] for ref in by_id["component:services"]["manifests"]],
                ["services/pyproject.toml", "services/requirements.txt"],
            )
            built_by_id = {b.component.component_id: b for b in result.per_component}
            parent = built_by_id["component:."]
            child = built_by_id["component:services"]
            parent_frameworks = {t.name for t in parent.profile_result.profile.frameworks}
            child_frameworks = {t.name for t in child.profile_result.profile.frameworks}
            # INV-OWN-3(b)/(c): the parent Profile never consumes the child
            # manifest (its own metadata view only), and vice versa.
            self.assertNotIn("django", parent_frameworks)
            self.assertIn("flask", parent_frameworks)
            self.assertNotIn("flask", child_frameworks)
            self.assertIn("django", child_frameworks)
            # INV-OWN-3(d): sources reflect the actual input sets -- the
            # admitted .toml manifests publish the S1 view, the S2-only
            # requirements files publish the channel view.
            for entry in payload["components"]:
                for ref in entry["manifests"]:
                    expected = (
                        "source-inventory"
                        if ref["path"].endswith(".toml")
                        else "metadata-channel"
                    )
                    self.assertEqual(ref["source"], expected)


class EffectiveConfigTests(unittest.TestCase):
    """#57/#58/#59: effective configuration carriers and boundaries."""

    def test_component_ram_wire_effective_config_no_default_backfill(self) -> None:
        with build_on(shapes.MODEL_CALL_REPO) as (_cg, result, payload):
            self.assertEqual(
                payload["build"]["monorepo_budgets"], EFFECTIVE_DEFAULT_BUDGETS
            )
            for built in result.per_component:
                wire = built.ram_wire
                self.assertEqual(
                    wire["build"]["profile_budgets"],
                    {
                        "manifest_max_bytes": (
                            built.effective_profile_budgets.manifest_max_bytes
                        ),
                        "max_manifest_files": (
                            built.effective_profile_budgets.max_manifest_files
                        ),
                    },
                )
                self.assertEqual(
                    wire["build"]["ram_budgets"],
                    {
                        "max_python_files": (
                            built.effective_ram_budgets.max_python_files
                        ),
                        "max_key_flows": built.effective_ram_budgets.max_key_flows,
                        "max_unresolved_edges": (
                            built.effective_ram_budgets.max_unresolved_edges
                        ),
                    },
                )
                self.assertEqual(
                    semantic_config_digest(built.effective_semantic_options),
                    semantic_config_digest_from_wire(wire),
                )
                self.assertIsNone(validate_ram_wire_payload(wire))
        # After an aggregation change the build section still mirrors the
        # effective configuration (no layer-default backfill).
        client = FakeModelClient()
        with build_on(
            shapes.MODEL_CALL_REPO,
            monorepo_budgets=load_cg().MonorepoBudgets(max_total_model_calls=1),
            semantic_options=SemanticOptions(model_id="fake-offline-model"),
            model_client=client,
        ) as (_cg2, result2, _payload2):
            for built in result2.per_component:
                self.assertIsNone(validate_ram_wire_payload(built.ram_wire))
                self.assertEqual(
                    semantic_config_digest(built.effective_semantic_options),
                    semantic_config_digest_from_wire(built.ram_wire),
                )

    def test_parameter_boundary_unique_behavior(self) -> None:
        cg = load_cg()
        repo17 = shapes.many_component_repo(17)
        with build_on(
            repo17, monorepo_budgets=cg.MonorepoBudgets(max_components=17)
        ) as (_cg, _result, payload):
            self.assertEqual(len(payload["components"]), 17)
            self.assertTrue(payload["dependencies_complete"])
        repo18 = shapes.many_component_repo(18)
        with build_on(
            repo18, monorepo_budgets=cg.MonorepoBudgets(max_components=17)
        ) as (_cg2, _result2, payload2):
            self.assertEqual(len(payload2["components"]), 17)
            self.assertFalse(payload2["dependencies_complete"])
            self.assertEqual(
                find_gap(payload2, "BUDGET_EXHAUSTED", "component-limit"),
                "reason=component-limit; count=1",
            )
        with build_on(
            shapes.MODEL_CALL_REPO,
            semantic_options=SemanticOptions(top_n=21),
        ) as (_cg3, _result3, payload3):
            for entry in payload3["components"]:
                self.assertEqual(entry["semantic_topn"]["top_n"], 21)
                self.assertLessEqual(
                    len(entry["semantic_topn"]["ranked_candidate_ids"]), 21
                )
        for bad_top_n in (0, 101):
            with self.subTest(top_n=bad_top_n):
                with self.assertRaises(ValueError):
                    SemanticOptions(top_n=bad_top_n)
        # Tight caller cap: single honest home for divergence events.
        with build_on(shapes.CALLER_CAP_REPO, max_files=1) as (_cg4, _r4, payload4):
            for record in payload4["unbuilt_components"]:
                self.assertEqual(
                    record["reason"], cg.UNBUILT_REASON_CAP_DIVERGENCE
                )
        for bad in (0, -1, 65, 16_385):
            with self.subTest(value=bad):
                with self.assertRaises(ValueError):
                    cg.MonorepoBudgets(max_components=bad)

    def test_partial_products_pass_own_validators(self) -> None:
        cg = load_cg()
        with self.assertRaises(ValueError):
            SemanticBudgets(max_llm_calls=0)
        cases: list[tuple[str, Any, dict[str, Any]]] = [
            ("t1", shapes.many_component_repo(17), {}),
            (
                "t3",
                shapes.EDGE_CAP_REPO,
                {"monorepo_budgets": cg.MonorepoBudgets(max_edges=1)},
            ),
            (
                "t8",
                shapes.METADATA_ONLY_ANCHORS,
                {"monorepo_budgets": cg.MonorepoBudgets(max_metadata_manifests=2)},
            ),
        ]
        for name, repo, params in cases:
            with self.subTest(case=name):
                with build_on(repo, **params) as (_cg, result, payload):
                    self.assertIsNone(
                        cg.validate_component_graph_payload(payload)
                    )
                    for built in result.per_component:
                        self.assertIsNone(
                            validate_ram_wire_payload(built.ram_wire)
                        )
                        self.assertIsNotNone(built.component.artifact_digests)
        client = FakeModelClient()
        with build_on(
            shapes.MODEL_CALL_REPO,
            monorepo_budgets=cg.MonorepoBudgets(max_total_model_calls=1),
            semantic_options=SemanticOptions(model_id="fake-offline-model"),
            model_client=client,
        ) as (_cg2, result2, payload2):
            self.assertIsNone(cg.validate_component_graph_payload(payload2))
            for built in result2.per_component:
                self.assertIsNone(validate_ram_wire_payload(built.ram_wire))
                self.assertIsNotNone(built.component.artifact_digests)
                self.assertGreaterEqual(
                    len(built.semantic_result.ranked), 0
                )


class ChannelIsolationTests(unittest.TestCase):
    """#60/#61/#71: channel isolation, two input sets, no re-admission."""

    def test_manifest_channel_no_source_readmission(self) -> None:
        with build_on(shapes.S2ONLY_MANIFEST_REPO) as (cg, result, payload):
            root = payload["components"][0]
            self.assertEqual(root["python_file_count"], 1)
            self.assertEqual(
                [ref["path"] for ref in root["manifests"]],
                ["requirements.txt"],
            )
            self.assertEqual(
                root["manifests"][0]["source"],
                cg.COMPONENT_MANIFEST_SOURCE_METADATA_CHANNEL,
            )
            built = result.per_component[0]
            self.assertEqual(
                built.ram_result.facts.counters.get("modules_indexed"), 1
            )
            # CL-04 double metering: the same manifest is read by the channel
            # (S8) and by the Profile candidate walk (S3).
            self.assertGreaterEqual(result.metering.metadata_channel_read_attempts, 1)
            self.assertGreaterEqual(result.metering.profile_manifest_read_attempts, 1)
            for value in path_fields(payload):
                self.assertNotIn(".txt", value.replace("requirements.txt", ""))
        # Channel pruning negatives: secret / ignored / out-of-name-set.
        with build_on(shapes.SECRET_ANCHOR_REPO) as (_cg2, _r2, payload2):
            self.assertIn(
                "sensitive-filename", payload2["metadata_channel_skipped"]
            )
            self.assertNotIn(
                "secrets/pyproject.toml",
                [
                    ref["path"]
                    for entry in payload2["components"]
                    for ref in entry["manifests"]
                ],
            )
        with build_on(
            shapes.POLICY_INHERITANCE_REPO,
            ignored_directories=("legacy",),
        ) as (_cg3, _r3, payload3):
            self.assertIn(
                "ignored-directory", payload3["metadata_channel_skipped"]
            )
        gemfile_repo = {
            "pyproject.toml": "[project]\nname = \"gemhost\"\nversion = \"1.0\"\n",
            "main.py": "def main():\n    return 32\n",
            "Gemfile": "source 'https://rubygems.org'\n",
        }
        with build_on(gemfile_repo) as (_cg4, _r4, payload4):
            self.assertEqual(payload4["manifests_discovered_count"], 1)
            for value in path_fields(payload4):
                self.assertNotIn("Gemfile", value)
        # Symlink pruning: channel must not follow symlinked directories
        # (platform-denied symlink creation is recorded honestly).
        root = shapes.monorepo_tree(shapes.ROOT_ONLY)
        outside = root.parent / "lima-ip0023-outside"
        try:
            outside.mkdir(exist_ok=True)
            (outside / "requirements.txt").write_text(
                "flask==3.0.0\n", encoding="utf-8", newline="\n"
            )
            link = root / "linked"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"platform denied symlink creation: {exc}")
            cg5 = load_cg()
            discovery = cg5.detect_components(RepositoryWorkspace(root))
            for component in discovery.components:
                for ref in component.manifests:
                    self.assertNotIn("linked", ref.path)
            # The channel discovers the repo's own pyproject.toml (count 1)
            # and never follows the symlinked directory: the outside
            # requirements.txt stays out of the metadata manifest count.
            self.assertEqual(discovery.metadata_manifest_count, 1)
        finally:
            shutil.rmtree(root, ignore_errors=True)
            shutil.rmtree(outside, ignore_errors=True)

    def test_two_input_sets_counts_and_provenance_separated(self) -> None:
        with build_on(shapes.PARENT_CHILD_MANIFESTS) as (cg, _result, payload):
            published_meta = sum(
                1
                for entry in payload["components"]
                for ref in entry["manifests"]
                if ref["source"] == cg.COMPONENT_MANIFEST_SOURCE_METADATA_CHANNEL
            )
            self.assertEqual(payload["manifests_discovered_count"], 4)
            self.assertEqual(payload["metadata_manifest_count"], 4)
            self.assertLessEqual(published_meta, payload["metadata_manifest_count"])
            # Overlap member publishes the single S1 source view.
            root_refs = [
                ref
                for ref in payload["components"][0]["manifests"]
                if ref["path"] == "pyproject.toml"
            ]
            self.assertEqual(root_refs[0]["source"], "source-inventory")
        with build_on(shapes.MIXED_DOMAIN_LOSS_REPO) as (_cg2, _r2, payload2):
            vocabulary = {
                "ignored-directory",
                "sensitive-filename",
                "symlink",
                "unreadable",
                "non-utf8",
                "metadata-manifest-limit",
                "metadata-byte-limit",
            }
            self.assertTrue(
                set(payload2["metadata_channel_skipped"]) <= vocabulary
            )
            # The main workspace skipped facts stay separate from the channel
            # dictionary (never rewritten or merged).
            with shapes.monorepo_workspace(shapes.MIXED_DOMAIN_LOSS_REPO) as (
                _root,
                ws,
            ):
                main_skipped = dict(ws.inventory().skipped)
            self.assertEqual(main_skipped.get("non-utf8"), 1)
            self.assertEqual(main_skipped.get("unsupported-extension"), 2)
            self.assertEqual(payload2["metadata_channel_skipped"].get("non-utf8"), 2)
            # Per-domain accounting: every metadata-domain gap record count
            # equals the channel dictionary count (V7 forward direction).
            for gap in payload2["coverage_gaps"]:
                if gap["gap_code"] != "INVENTORY_SKIPPED":
                    continue
                match = CHANNEL_GAP_DETAIL.match(gap["detail"])
                self.assertIsNotNone(match)
                if match and match.group("channel") == "metadata-channel":
                    self.assertEqual(
                        payload2["metadata_channel_skipped"].get(
                            match.group("reason")
                        ),
                        int(match.group("count")),
                    )

    def test_s2only_not_source_readmitted(self) -> None:
        with build_on(shapes.S2ONLY_MANIFEST_REPO) as (_cg, result, payload):
            root = payload["components"][0]
            self.assertEqual(root["python_file_count"], 1)
            built = result.per_component[0]
            observed = {
                item.path
                for section in (
                    built.ram_result.facts.entrypoints,
                    built.ram_result.facts.external_sources,
                    built.ram_result.facts.sensitive_sinks,
                    built.ram_result.facts.trust_boundaries,
                    built.ram_result.facts.unresolved_edges,
                )
                for item in section
            } | set(built.ram_result.facts.source_labels)
            self.assertNotIn("requirements.txt", observed)
            self.assertEqual(
                built.ram_result.facts.counters.get("modules_indexed"), 1
            )
            for candidate in built.semantic_result.ranked:
                self.assertNotEqual(candidate.path, "requirements.txt")


class AggregatePoolTests(unittest.TestCase):
    """#62/#63/#72: aggregate pools, IO metering, four-class scheduling."""

    def test_aggregate_token_pool_exhaustion_typed_degradation(self) -> None:
        cg = load_cg()
        client = FakeModelClient()
        options = SemanticOptions(
            model_id="fake-offline-model",
            budgets=SemanticBudgets(
                max_llm_calls=2,
                max_prompt_tokens_estimate=1_000,
                max_output_tokens_estimate=500,
                max_total_tokens_estimate=1_500,
            ),
        )
        with build_on(
            shapes.MODEL_CALL_REPO,
            semantic_options=options,
            model_client=client,
        ) as (_cg, result, payload):
            # CL-03: effective pools == min(requested defaults, caller) == the
            # small caller values (the API-POOL 1684/2048/3732 schedule would
            # need pools above these and is unreachable).
            budgets = payload["build"]["monorepo_budgets"]
            self.assertEqual(
                (
                    budgets["aggregate_max_prompt_tokens"],
                    budgets["aggregate_max_output_tokens"],
                    budgets["aggregate_max_total_tokens"],
                ),
                (1_000, 500, 1_500),
            )
            for built in result.per_component:
                self.assertIsNone(validate_ram_wire_payload(built.ram_wire))
                self.assertIsNotNone(built.component.artifact_digests)
                self.assertGreaterEqual(len(built.semantic_result.ranked), 0)
            detail = find_gap(
                payload, "BUDGET_EXHAUSTED", "aggregate-token-pool-limit"
            )
            if detail is not None:
                match = BUDGET_GAP_DETAIL.match(detail)
                self.assertIsNotNone(match)
                self.assertGreaterEqual(
                    int(match.group("count")) if match else 0, 1
                )
            # Non-dependency-evidence state: completeness is untouched.
            self.assertTrue(payload["dependencies_complete"])
            _ = cg

    def test_read_amplification_metered_and_bounded(self) -> None:
        # Premise (SF-3): the staged IO bounds hold under the W-1 restricted
        # double view, where component slices are exact file lists. This test
        # is the third layer (real new-chain verification).
        with build_on(shapes.GOLDEN_MONOREPO) as (cg, result, payload):
            with shapes.monorepo_workspace(shapes.GOLDEN_MONOREPO) as (_root, ws):
                inventory = ws.inventory()
            metering = result.metering
            slice_total = sum(e["python_file_count"] for e in payload["components"])
            slice_total += sum(
                len(entry["manifests"]) for entry in payload["components"]
            )
            owned_py = sum(e["python_file_count"] for e in payload["components"])
            self.assertLessEqual(
                metering.main_inventory_read_attempts, inventory.discovered_files
            )
            self.assertLessEqual(
                metering.component_rescan_read_attempts, 5 * slice_total
            )
            self.assertLessEqual(
                metering.profile_manifest_read_attempts,
                payload["manifests_discovered_count"]
                + payload["collaboration_manifest_count"],
            )
            self.assertLessEqual(metering.ast_read_attempts, owned_py)
            self.assertLessEqual(
                metering.metadata_channel_read_attempts,
                EFFECTIVE_DEFAULT_BUDGETS["max_metadata_manifests"],
            )
            attempts = (
                metering.main_inventory_read_attempts
                + metering.component_rescan_read_attempts
                + metering.profile_manifest_read_attempts
                + metering.ast_read_attempts
                + metering.metadata_channel_read_attempts
            )
            self.assertLessEqual(
                attempts,
                7 * inventory.discovered_files
                + 2 * payload["manifests_discovered_count"]
                + EFFECTIVE_DEFAULT_BUDGETS["max_metadata_manifests"],
            )
            self.assertLessEqual(
                metering.read_success_bytes,
                attempts * (512 * 1024),
            )
            # API-IO anti-undercount: each owned .py is read at least five
            # times across the chain (pre-check, Profile inventory, RAM
            # inventory, RAM source, graph AST).
            self.assertGreaterEqual(attempts, 5 * owned_py)
            _ = cg

    def test_effective_pools_min_caller_graph_scheduling(self) -> None:
        cg = load_cg()
        small = SemanticBudgets(
            max_llm_calls=2,
            max_prompt_tokens_estimate=1_000,
            max_output_tokens_estimate=500,
            max_total_tokens_estimate=1_500,
        )
        large = SemanticBudgets(
            max_llm_calls=8,
            max_prompt_tokens_estimate=50_000,
            max_output_tokens_estimate=8_192,
            max_total_tokens_estimate=58_192,
        )
        # Default caller: effective pools equal the conservative defaults.
        with build_on(shapes.MODEL_CALL_REPO) as (_cg, _r, payload):
            self.assertEqual(
                payload["build"]["monorepo_budgets"]["aggregate_max_prompt_tokens"],
                24_000,
            )
        # Small caller: pools clamp to the caller values.
        with build_on(
            shapes.MODEL_CALL_REPO,
            semantic_options=SemanticOptions(
                model_id="fake-offline-model", budgets=small
            ),
            model_client=FakeModelClient(),
        ) as (_cg2, _r2, payload2):
            self.assertEqual(
                payload2["build"]["monorepo_budgets"]["aggregate_max_prompt_tokens"],
                1_000,
            )
            self.assertEqual(
                payload2["build"]["monorepo_budgets"]["aggregate_max_total_tokens"],
                1_500,
            )
        # Large caller: pools never expand past the requested defaults.
        with build_on(
            shapes.MODEL_CALL_REPO,
            semantic_options=SemanticOptions(
                model_id="fake-offline-model", budgets=large
            ),
            model_client=FakeModelClient(),
        ) as (_cg3, _r3, payload3):
            self.assertEqual(
                payload3["build"]["monorepo_budgets"]["aggregate_max_prompt_tokens"],
                24_000,
            )
            self.assertEqual(
                payload3["build"]["monorepo_budgets"]["aggregate_max_total_tokens"],
                28_096,
            )
        # Explicitly higher requested pools: effective == min(requested,
        # caller) -- a policy authorization point carried as data, with the
        # wire build section mirroring the effective values.
        with build_on(
            shapes.MODEL_CALL_REPO,
            monorepo_budgets=cg.MonorepoBudgets(
                aggregate_max_prompt_tokens=50_000,
                aggregate_max_output_tokens=8_192,
                aggregate_max_total_tokens=58_192,
            ),
            semantic_options=SemanticOptions(
                model_id="fake-offline-model", budgets=large
            ),
            model_client=FakeModelClient(),
        ) as (_cg4, result4, payload4):
            budgets = payload4["build"]["monorepo_budgets"]
            self.assertEqual(
                (
                    budgets["aggregate_max_prompt_tokens"],
                    budgets["aggregate_max_output_tokens"],
                    budgets["aggregate_max_total_tokens"],
                ),
                (50_000, 8_192, 58_192),
            )
            for built in result4.per_component:
                self.assertIsNone(validate_ram_wire_payload(built.ram_wire))


class MetadataLossTests(unittest.TestCase):
    """#64-#68: S2 metadata evidence loss (CL-01) and partial consumption."""

    def test_metadata_loss_count_cap_incomplete_not_real_no_deps(self) -> None:
        cg = load_cg()
        budgets = cg.MonorepoBudgets(max_metadata_manifests=2)
        with build_on(
            shapes.METADATA_ONLY_ANCHORS, monorepo_budgets=budgets
        ) as (_cg, _result, payload):
            self.assertEqual(payload["manifests_discovered_count"], 2)
            root = payload["components"][0]
            self.assertEqual(
                [ref["path"] for ref in root["manifests"]],
                ["go.mod", "pom.xml"],
            )
            self.assertFalse(payload["dependencies_complete"])
            self.assertIsNotNone(
                find_gap(payload, "BUDGET_EXHAUSTED", "metadata-manifest-limit")
            )
            self.assertEqual(
                payload["metadata_channel_skipped"].get("metadata-manifest-limit"),
                2,
            )
            self.assertEqual(
                classify_three_state(root, payload), "insufficient-evidence"
            )
            # Conservation holds at the actually-discovered value.
            published = sum(len(e["manifests"]) for e in payload["components"])
            self.assertEqual(
                payload["manifests_discovered_count"],
                published
                + payload["collaboration_manifest_count"]
                + payload["overflow_manifest_count"],
            )

    def test_metadata_loss_byte_cap_incomplete(self) -> None:
        cg = load_cg()
        go_mod_bytes = len(shapes.METADATA_ONLY_ANCHORS["go.mod"].encode("utf-8"))
        budgets = cg.MonorepoBudgets(max_metadata_total_bytes=go_mod_bytes)
        with build_on(
            shapes.METADATA_ONLY_ANCHORS, monorepo_budgets=budgets
        ) as (_cg, _result, payload):
            self.assertFalse(payload["dependencies_complete"])
            detail = find_gap(payload, "BUDGET_EXHAUSTED", "metadata-byte-limit")
            self.assertIsNotNone(detail)
            self.assertEqual(
                payload["metadata_channel_skipped"].get("metadata-byte-limit"),
                int(
                    CHANNEL_OR_BUDGET_COUNT(detail or "")
                ),
            )
            root = payload["components"][0]
            self.assertEqual(
                classify_three_state(root, payload), "insufficient-evidence"
            )

    def test_metadata_loss_read_failure_t8(self) -> None:
        with build_on(shapes.CHANNEL_UNREADABLE_REPO) as (_cg, _result, payload):
            self.assertFalse(payload["dependencies_complete"])
            self.assertEqual(
                find_gap(payload, "INVENTORY_SKIPPED", "unreadable"),
                "channel=metadata-channel; reason=unreadable; count=1",
            )
            self.assertEqual(
                payload["metadata_channel_skipped"].get("unreadable"), 1
            )
            # Enumerated-but-unreadable still counts as discovered and the
            # anchor still publishes the manifest reference (partial facts).
            self.assertEqual(payload["manifests_discovered_count"], 1)
            huge = payload_entry(payload, "component:huge")
            self.assertEqual(
                [ref["path"] for ref in huge["manifests"]],
                ["huge/requirements.txt"],
            )
            self.assertEqual(
                classify_three_state(huge, payload), "insufficient-evidence"
            )

    def test_metadata_loss_decode_failure_t8(self) -> None:
        with build_on(shapes.MIXED_DOMAIN_LOSS_REPO) as (_cg, _result, payload):
            self.assertFalse(payload["dependencies_complete"])
            self.assertEqual(
                find_gap(payload, "INVENTORY_SKIPPED", "non-utf8"),
                "channel=metadata-channel; reason=non-utf8; count=2",
            )
            self.assertEqual(
                payload["metadata_channel_skipped"].get("non-utf8"), 2
            )
            # Same reason name on both domains: two records, both preserved,
            # independent counts (1 in source-inventory, 2 in the channel).
            non_utf8_details = sorted(
                detail
                for detail in gap_details(payload, "INVENTORY_SKIPPED")
                if "reason=non-utf8" in detail
            )
            self.assertEqual(len(non_utf8_details), 2)
            self.assertIn(
                "channel=source-inventory; reason=non-utf8; count=1",
                non_utf8_details,
            )

    def test_metadata_loss_partial_payload_public_consumption(self) -> None:
        cg = load_cg()
        cases: list[tuple[str, Any, dict[str, Any]]] = [
            (
                "count-cap",
                shapes.METADATA_ONLY_ANCHORS,
                {"monorepo_budgets": cg.MonorepoBudgets(max_metadata_manifests=2)},
            ),
            (
                "read-failure",
                shapes.CHANNEL_UNREADABLE_REPO,
                {},
            ),
            ("decode-failure", shapes.MIXED_DOMAIN_LOSS_REPO, {}),
            (
                "unknown-truncation",
                shapes.EDGE_CAP_REPO,
                {"monorepo_budgets": cg.MonorepoBudgets(max_edges=1)},
            ),
        ]
        for name, repo, params in cases:
            with self.subTest(case=name):
                with build_on(repo, **params) as (_cg, result, payload):
                    self.assertIsNone(
                        cg.validate_component_graph_payload(payload)
                    )
                    for built in result.per_component:
                        self.assertIsNone(
                            validate_ram_wire_payload(built.ram_wire)
                        )
                    for entry in payload["components"]:
                        if not entry["built"]:
                            continue
                        built = next(
                            b
                            for b in result.per_component
                            if b.component.component_id == entry["component_id"]
                        )
                        wire = built.ram_wire
                        self.assertEqual(
                            ram_facts_digest_from_wire(wire),
                            entry["digests"]["ram_facts_digest"],
                        )
                        self.assertEqual(
                            semantic_result_digest_from_wire(wire),
                            entry["digests"]["semantic_result_digest"],
                        )


class S1ViewTests(unittest.TestCase):
    """#69/#70: own-manifest facts under the S1 view (CL-02)."""

    def test_profile_own_manifest_facts_preserved_under_s1_view(self) -> None:
        with build_on(shapes.S2ONLY_MANIFEST_REPO) as (_cg, result, payload):
            built = result.per_component[0]
            frameworks = {t.name for t in built.profile_result.profile.frameworks}
            managers = {
                t.name for t in built.profile_result.profile.package_managers
            }
            # API-META repair: the S2-only manifest still feeds the Profile
            # static facts through the own-metadata view.
            self.assertIn("flask", frameworks)
            self.assertIn("pip", managers)
            root = payload["components"][0]
            self.assertEqual(root["python_file_count"], 1)
            self.assertEqual(
                payload["manifests_discovered_count"], 1
            )

    def test_parent_child_distinct_requirements_isolated(self) -> None:
        with build_on(shapes.PARENT_CHILD_MANIFESTS) as (_cg, result, payload):
            built_by_id = {b.component.component_id: b for b in result.per_component}
            parent = built_by_id["component:."]
            child = built_by_id["component:services"]
            parent_frameworks = {t.name for t in parent.profile_result.profile.frameworks}
            child_frameworks = {t.name for t in child.profile_result.profile.frameworks}
            self.assertNotIn("django", parent_frameworks)
            self.assertNotIn("flask", child_frameworks)
            # Conservation: 4 discovered == 2 + 2 published + 0 + 0.
            published = sum(len(e["manifests"]) for e in payload["components"])
            self.assertEqual(
                payload["manifests_discovered_count"],
                published
                + payload["collaboration_manifest_count"]
                + payload["overflow_manifest_count"],
            )


class MeteringDomainTests(unittest.TestCase):
    """#73: V7/V8 overlap and collaboration metering domains (CL-05)."""

    def test_v7_v8_overlap_and_collab_manifest_metering_domains(self) -> None:
        cg = load_cg()
        for name, repo, _child_id in (
            ("uv", shapes.WORKSPACE_MANIFEST_MEMBERS, "component:libraries/utils"),
            ("package-json", shapes.COLLAB_PACKAGE_JSON_REPO, "component:pkgs/one"),
            ("cargo", shapes.COLLAB_CARGO_REPO, "component:crates/tiny"),
        ):
            with self.subTest(collab=name):
                with build_on(repo) as (_cg, _result, payload):
                    self.assertNotIn(
                        "component:.",
                        [e["component_id"] for e in payload["components"]],
                    )
                    self.assertEqual(
                        payload["collaboration_manifest_count"], 1
                    )
                    published = sum(
                        len(e["manifests"]) for e in payload["components"]
                    )
                    self.assertEqual(
                        payload["manifests_discovered_count"],
                        published + 1 + payload["overflow_manifest_count"],
                    )
                    self.assertIsNone(
                        cg.validate_component_graph_payload(payload)
                    )
        with build_on(shapes.PARENT_CHILD_MANIFESTS) as (_cg2, _r2, payload2):
            tampered = deepcopy(payload2)
            tampered["manifests_discovered_count"] += 1
            with self.assertRaises(ContractError):
                cg.validate_component_graph_payload(tampered)
            tampered2 = deepcopy(payload2)
            tampered2["metadata_manifest_count"] += 1
            with self.assertRaises(ContractError):
                cg.validate_component_graph_payload(tampered2)


class R1EvidenceLossTests(unittest.TestCase):
    """#74/#75/#76: R1 classification and dependency-evidence controls."""

    def test_unknown_truncation_evidence_loss_not_real_no_deps(self) -> None:
        cg = load_cg()
        with build_on(
            shapes.EDGE_CAP_REPO,
            monorepo_budgets=cg.MonorepoBudgets(max_edges=1),
        ) as (_cg, _result, payload):
            self.assertFalse(payload["dependencies_complete"])
            self.assertEqual(
                find_gap(payload, "BUDGET_EXHAUSTED", "unknown-import-limit"),
                "reason=unknown-import-limit; count=2",
            )
            self.assertEqual(payload["unknown_imports"], [])
            by_id = {s["component_id"]: s for s in payload["scan_summaries"]}
            self.assertEqual(
                by_id["component:a"]["unknown_truncated_count"], 1
            )
            self.assertEqual(
                by_id["component:b"]["unknown_truncated_count"], 1
            )
            # Neither component ever reaches P3: a (no out-edge) falls to
            # "insufficient-evidence"; b keeps its edge-priority resolved
            # out-edge, so it is not a three-state object at all -- under
            # both readings the truncated evidence prevents P3.
            entry_a = payload_entry(payload, "component:a")
            entry_b = payload_entry(payload, "component:b")
            self.assertEqual(
                classify_three_state(entry_a, payload), "insufficient-evidence"
            )
            self.assertEqual(
                classify_three_state(entry_b, payload), "has-dependencies"
            )
            # Partial payload stays publicly consumable.
            self.assertIsNone(cg.validate_component_graph_payload(payload))
        with build_on(
            shapes.EDGE_CAP_REPO,
            monorepo_budgets=cg.MonorepoBudgets(max_edges=4_096),
        ) as (_cg2, _result2, payload2):
            self.assertTrue(payload2["dependencies_complete"])
            self.assertEqual(len(payload2["unknown_imports"]), 2)
            # Untruncated contrast: publishing both unknown records still
            # keeps every component out of P3 (a via the published unknown
            # record, b via its resolved out-edge) -- no under-reporting.
            entry_a = payload_entry(payload2, "component:a")
            entry_b = payload_entry(payload2, "component:b")
            self.assertEqual(
                classify_three_state(entry_a, payload2), "insufficient-evidence"
            )
            self.assertEqual(
                classify_three_state(entry_b, payload2), "has-dependencies"
            )

    def test_dynamic_import_excludes_real_no_deps(self) -> None:
        with build_on(shapes.DYNAMIC_IMPORT_REPO) as (_cg, _result, payload):
            entry = payload_entry(payload, "component:.")
            self.assertEqual(entry["scan_summary"]["dynamic_import_site_count"], 1)
            self.assertTrue(payload["dependencies_complete"])
            self.assertEqual(
                classify_three_state(entry, payload), "insufficient-evidence"
            )

    def test_dependency_evidence_controls_model_off_and_pool(self) -> None:
        cg = load_cg()
        # Control 1: model off never demotes static no-dependency evidence.
        with build_on(shapes.ROOT_ONLY) as (_cg, result, payload):
            entry = payload["components"][0]
            self.assertTrue(payload["dependencies_complete"])
            self.assertEqual(
                classify_three_state(entry, payload), "real-no-dependencies"
            )
            built = result.per_component[0]
            semantic_gaps = [
                gap.gap_code for gap in built.semantic_result.coverage_gaps
            ]
            self.assertIn("SEMANTIC_MODEL_OFF", semantic_gaps)
        # Control 2: aggregate pool exhaustion keeps static facts and the
        # no-dependency classification for components without dependencies.
        client = FakeModelClient()
        with build_on(
            shapes.MODEL_CALL_REPO,
            monorepo_budgets=cg.MonorepoBudgets(max_total_model_calls=1),
            semantic_options=SemanticOptions(model_id="fake-offline-model"),
            model_client=client,
        ) as (_cg2, result2, payload2):
            self.assertTrue(payload2["dependencies_complete"])
            for built in result2.per_component:
                self.assertIsNotNone(built.component.artifact_digests)
                self.assertGreaterEqual(len(built.semantic_result.ranked), 0)
            for entry in payload2["components"]:
                self.assertIn(
                    classify_three_state(entry, payload2),
                    ("real-no-dependencies", "insufficient-evidence"),
                )
        # Control 3: the normal no-dependency positive, empty and non-empty.
        with build_on(shapes.EMPTY_COMPONENT_DIR) as (_cg3, _r3, payload3):
            docs = payload_entry(payload3, "component:docs_only")
            self.assertTrue(docs["is_empty"])
            self.assertEqual(
                classify_three_state(docs, payload3), "real-no-dependencies"
            )
            host = payload_entry(payload3, "component:.")
            self.assertEqual(
                classify_three_state(host, payload3), "real-no-dependencies"
            )


class R2DomainMarkerTests(unittest.TestCase):
    """#77: dual-domain counts, independent tamper rejection (R2/D2-03)."""

    def test_t6_t8_gap_domain_marker_and_dual_counts(self) -> None:
        cg = load_cg()
        with build_on(shapes.MIXED_DOMAIN_LOSS_REPO) as (_cg, _result, payload):
            details = sorted(gap_details(payload, "INVENTORY_SKIPPED"))
            self.assertEqual(
                details,
                [
                    "channel=metadata-channel; reason=non-utf8; count=2",
                    "channel=source-inventory; reason=non-utf8; count=1",
                ],
            )
            self.assertIsNone(cg.validate_component_graph_payload(payload))

            def tampered(mutate: Any) -> dict[str, Any]:
                candidate = deepcopy(payload)
                mutate(candidate)
                return candidate

            def bump_source_count(p: dict[str, Any]) -> None:
                for gap in p["coverage_gaps"]:
                    if "channel=source-inventory; reason=non-utf8" in gap["detail"]:
                        gap["detail"] = (
                            "channel=source-inventory; reason=non-utf8; count=2"
                        )

            def bump_metadata_count(p: dict[str, Any]) -> None:
                for gap in p["coverage_gaps"]:
                    if (
                        "channel=metadata-channel; reason=non-utf8"
                        in gap["detail"]
                    ):
                        gap["detail"] = (
                            "channel=metadata-channel; reason=non-utf8; count=1"
                        )
                p["metadata_channel_skipped"]["non-utf8"] = 1

            def net_out_source(p: dict[str, Any]) -> None:
                p["coverage_gaps"] = [
                    gap
                    for gap in p["coverage_gaps"]
                    if "channel=source-inventory" not in gap["detail"]
                ]
                for gap in p["coverage_gaps"]:
                    if (
                        "channel=metadata-channel; reason=non-utf8"
                        in gap["detail"]
                    ):
                        gap["detail"] = (
                            "channel=metadata-channel; reason=non-utf8; count=3"
                        )
                p["metadata_channel_skipped"]["non-utf8"] = 3

            def duplicate_triple(p: dict[str, Any]) -> None:
                p["coverage_gaps"].append(deepcopy(p["coverage_gaps"][0]))

            for mutate in (
                bump_source_count,
                bump_metadata_count,
                net_out_source,
                duplicate_triple,
            ):
                with self.subTest(mutate=mutate.__name__):
                    candidate = tampered(mutate)
                    with self.assertRaises(ContractError):
                        cg.validate_component_graph_payload(candidate)
        # Zero-count keys publish no records (legal path).
        with build_on(shapes.ROOT_ONLY) as (_cg2, _r2, payload2):
            self.assertEqual(payload2["coverage_gaps"], [])
            self.assertIsNone(cg.validate_component_graph_payload(payload2))
        # Detail-format negatives on a synthetic carrier.
        synthetic = minimal_valid_payload()
        synthetic["metadata_channel_skipped"] = {"non-utf8": 1}

        def with_gap(detail: str) -> dict[str, Any]:
            candidate = deepcopy(synthetic)
            candidate["coverage_gaps"] = [
                {"gap_code": "INVENTORY_SKIPPED", "detail": detail}
            ]
            _finalize(candidate)
            return candidate

        for detail in (
            "reason=non-utf8; count=1; channel=metadata-channel",
            "channel=ftp; reason=non-utf8; count=1",
            "channel=metadata-channel; reason=non-utf8; count=0",
            "channel=metadata-channel; reason=non-utf8; count=1",
            "channel=metadata-channel; reason=component-limit; count=1",
        ):
            with self.subTest(detail=detail):
                candidate = with_gap(detail)
                expectation = detail == (
                    "channel=metadata-channel; reason=non-utf8; count=1"
                )
                try:
                    cg.validate_component_graph_payload(candidate)
                    accepted = True
                except ContractError:
                    accepted = False
                self.assertIs(accepted, expectation)
        # Budget-family graph gaps carry no channel segment (and leave no
        # dangling channel accounting behind).
        budget_gap = deepcopy(synthetic)
        budget_gap["metadata_channel_skipped"] = {}
        budget_gap["coverage_gaps"] = [
            {"gap_code": "BUDGET_EXHAUSTED", "detail": "reason=edge-limit; count=1"}
        ]
        _finalize(budget_gap)
        self.assertIsNone(cg.validate_component_graph_payload(budget_gap))
        bad_budget_gap = deepcopy(synthetic)
        bad_budget_gap["metadata_channel_skipped"] = {}
        bad_budget_gap["coverage_gaps"] = [
            {
                "gap_code": "BUDGET_EXHAUSTED",
                "detail": "channel=source-inventory; reason=edge-limit; count=1",
            }
        ]
        _finalize(bad_budget_gap)
        with self.assertRaises(ContractError):
            cg.validate_component_graph_payload(bad_budget_gap)


class R3BindingTests(unittest.TestCase):
    """#78: two independent verification paths for artifact references."""

    def test_graph_digest_binds_artifact_references(self) -> None:
        cg = load_cg()
        with build_on(shapes.MODEL_CALL_REPO) as (_cg, result, payload):
            self.assertIsNone(cg.validate_component_graph_payload(payload))
            first, second = payload["components"][0], payload["components"][1]
            self.assertNotEqual(
                first["digests"]["ram_facts_digest"],
                second["digests"]["ram_facts_digest"],
            )
            # Path 1: swap references without recomputing the graph digest.
            swapped = deepcopy(payload)
            head, tail = swapped["components"][0], swapped["components"][1]
            head["digests"], tail["digests"] = tail["digests"], head["digests"]
            with self.assertRaises(ContractError):
                cg.validate_component_graph_payload(swapped)
            # Path 2: pair each entry with the OTHER component's real public
            # artifacts -- the section 5.4.7 baseline rejects the mismatch
            # even when the graph digest would be recomputed consistently.
            built_by_id = {b.component.component_id: b for b in result.per_component}
            head_id = head["component_id"]
            other_id = tail["component_id"]
            wrong = built_by_id[other_id]
            wrong_profile_bytes = encode_profile_envelope(
                wrong.profile_result.envelope, wrong.profile_result.profile
            )
            envelope, _profile = decode_profile_envelope(wrong_profile_bytes)
            self.assertNotEqual(
                envelope.content_digest,
                payload_entry(payload, head_id)["digests"][
                    "profile_content_digest"
                ],
            )
            self.assertNotEqual(
                ram_facts_digest_from_wire(dict(wrong.ram_wire)),
                payload_entry(payload, head_id)["digests"]["ram_facts_digest"],
            )
            # A wire whose identity slots were swapped fails its validator.
            mixed_wire = deepcopy(dict(built_by_id[head_id].ram_wire))
            mixed_wire["identity"]["ram_facts_digest"] = ram_facts_digest_from_wire(
                dict(wrong.ram_wire)
            )
            with self.assertRaises(ContractError):
                validate_ram_wire_payload(mixed_wire)
        # built/null boundary and hex-domain negatives are covered by #36;
        # the honest non-capability note: content digest is self-consistency
        # only, which #47 pins by accepting a consistently recomputed tamper.


class MixedCapTests(unittest.TestCase):
    """#79: shared edge/unknown cap semantics (section 5.3.4)."""

    def test_mixed_edge_unknown_shared_cap_semantics(self) -> None:
        cg = load_cg()
        # Tight cap 2: 1 edge + 2 unknowns -> keep 1 edge + 1 unknown.
        with build_on(
            shapes.EDGE_CAP_REPO,
            monorepo_budgets=cg.MonorepoBudgets(max_edges=2),
        ) as (_cg, _result, payload):
            self.assertEqual(len(payload["edges"]), 1)
            self.assertEqual(len(payload["unknown_imports"]), 1)
            self.assertEqual(
                payload["unknown_imports"][0]["imported_name"], "missing_alpha"
            )
            self.assertIsNone(
                find_gap(payload, "BUDGET_EXHAUSTED", "edge-limit")
            )
            self.assertEqual(
                find_gap(payload, "BUDGET_EXHAUSTED", "unknown-import-limit"),
                "reason=unknown-import-limit; count=1",
            )
            self.assertFalse(payload["dependencies_complete"])
            self.assertEqual(
                len(payload["edges"]) + len(payload["unknown_imports"]), 2
            )
            self.assertIsNone(cg.validate_component_graph_payload(payload))
        # Tight cap 1: only the edge survives; both unknowns truncate.
        with build_on(
            shapes.EDGE_CAP_REPO,
            monorepo_budgets=cg.MonorepoBudgets(max_edges=1),
        ) as (_cg2, _r2, payload2):
            self.assertEqual(len(payload2["edges"]), 1)
            self.assertEqual(payload2["unknown_imports"], [])
            self.assertEqual(
                find_gap(payload2, "BUDGET_EXHAUSTED", "unknown-import-limit"),
                "reason=unknown-import-limit; count=2",
            )
        # Constructive unreachability of "each side truncated to cap and the
        # sum exceeding cap": the validator rejects such a payload outright.
        synthetic = two_component_payload(max_edges=2)
        second_edge = {
            "source_component_id": "component:y",
            "target_component_id": "component:x",
            "status": "resolved",
            "imported_name": "xlib",
            "evidence": [
                {"path": "y/main.py", "line": 1, "imported_name": "xlib"}
            ],
        }
        synthetic["edges"].append(second_edge)
        _finalize(synthetic)
        # Each side alone stays within cap (2 edges <= 2, 1 unknown <= 2)
        # while the mixed sum 3 > 2: only the V8 aggregate check rejects it.
        with self.assertRaises(ContractError):
            cg.validate_component_graph_payload(synthetic)


def CHANNEL_OR_BUDGET_COUNT(detail: str) -> str:
    """Return the trailing count digits of a channel/budget gap detail."""

    match = CHANNEL_GAP_DETAIL.match(detail) or BUDGET_GAP_DETAIL.match(detail)
    if match is None:
        raise AssertionError(f"unparseable gap detail: {detail!r}")
    return match.group("count")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
