"""IP-0023 monorepo golden acceptance tests (Packet v5.1 section 6, #38-#41).

The golden JSON under ``fixtures/monorepo/golden/monorepo.json`` is the
expectation carrier independently produced by the packet-and-verification
role *before* any implementation exists (R60-07): the components, anchors,
edges, unknown imports, counters, three-state inputs and manifest metering
domains are hand-derived from the frozen rules, and the three per-component
digest references plus the graph digest are recomputed through the frozen
public APIs (``build_repository_profile`` / ``build_python_ram_facts`` /
``build_semantic_top_n`` / ``ram_facts_digest`` / ``semantic_result_digest`` /
``compute_content_digest``) on plain component sub-workspaces. It is never
back-filled from builder output.

The module under test (``lima.audit.component_graph``) is imported lazily per
test so the module-absence RED anchor (PI-DR4) stays observable.
"""

from __future__ import annotations

import importlib
import json
import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any

from lima.audit.inventory import build_repository_profile
from lima.audit.ram import build_python_ram_facts, ram_facts_digest
from lima.audit.semantic_prioritizer import (
    build_semantic_top_n,
    semantic_result_digest,
)
from lima.contracts.codec import compute_content_digest
from lima.contracts.errors import ContractError
from lima.workspace import RepositoryWorkspace
from tests.audit.fixtures.monorepo import shapes

GOLDEN_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "monorepo" / "golden" / "monorepo.json"
)

SENTINEL = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

#: Effective default MonorepoBudgets carried in the payload build section
#: (Packet v5.1 section 5.4.3; model-off build -> requested == defaults and
#: effective token pools == min(defaults, caller SemanticBudgets defaults)).
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


def load_cg() -> Any:
    """Lazily import the module under test (PI-DR4 module-absence anchor)."""

    return importlib.import_module("lima.audit.component_graph")


def monorepo_build_kwargs() -> dict[str, str]:
    """Return the fixed six-ID kwargs for ``build_monorepo_profile``."""

    return dict(shapes.MONOREPO_PROFILE_KWARGS)


# ---------------------------------------------------------------------------
# Independent oracle (Packet v5.1 sections 5.1-5.4; zero component_graph use)
# ---------------------------------------------------------------------------


def _three_digests_for_component(root: Path, rel: str) -> dict[str, str]:
    """Recompute the three public digest references for one plain child view.

    Both golden components have no nested anchors, so their precise file-list
    views equal the plain sub-workspace under the anchor (Packet v5.1
    section 5.2.1): a caller-inheriting ``RepositoryWorkspace`` rooted at the
    anchor discovers exactly the component slice.
    """

    sub = RepositoryWorkspace(root / rel)
    profile = build_repository_profile(
        sub,
        **shapes.MONOREPO_PROFILE_KWARGS,
        producer=shapes.COMPONENT_GRAPH_PRODUCER,
    )
    ram = build_python_ram_facts(sub)
    semantic = build_semantic_top_n(ram.facts)
    facts_digest = ram_facts_digest(ram.facts)
    bound = semantic_result_digest(semantic, input_facts_digest=facts_digest)
    # D2-01 negative control lives in the callers; here we pin the bound form
    # (the frozen builder stores the bound digest; the frozen public layer
    # already binds it internally, so both forms must agree for this build).
    assert bound == semantic.result_digest
    return {
        "profile_content_digest": profile.envelope.content_digest,
        "ram_facts_digest": facts_digest,
        "semantic_result_digest": bound,
    }


def _semantic_topn_for_component(root: Path, rel: str) -> dict[str, Any]:
    """Recompute the per-component semantic Top-N digest carrier."""

    sub = RepositoryWorkspace(root / rel)
    ram = build_python_ram_facts(sub)
    semantic = build_semantic_top_n(ram.facts)
    return {
        "model_id": "unset",
        "top_n": 20,
        "ranked_candidate_ids": [item.candidate_id for item in semantic.ranked],
    }


def independent_golden_payload(root: Path) -> dict[str, Any]:
    """Hand-derived expectation for ``shapes.GOLDEN_MONOREPO`` (R60-07).

    Static table (components/anchors/edges/counts/three-state inputs) is
    derived from the frozen rules; digest slots come from the frozen public
    APIs via :func:`_three_digests_for_component`.
    """

    core_digests = _three_digests_for_component(root, "packages/core")
    api_digests = _three_digests_for_component(root, "services/api")
    zero_scan = {
        "parse_error_file_count": 0,
        "read_failure_file_count": 0,
        "dynamic_import_site_count": 0,
        "unknown_truncated_count": 0,
        "manifest_parse_failure_count": 0,
    }
    components = [
        {
            "component_id": "component:packages/core",
            "root_dir": "packages/core",
            "manifests": [
                {
                    "path": "packages/core/pyproject.toml",
                    "manifest_kind": "pyproject",
                    "source": "source-inventory",
                }
            ],
            "python_file_count": 2,
            "is_empty": False,
            "built": True,
            "digests": core_digests,
            "scan_summary": dict(zero_scan),
            "semantic_topn": _semantic_topn_for_component(root, "packages/core"),
        },
        {
            "component_id": "component:services/api",
            "root_dir": "services/api",
            "manifests": [
                {
                    "path": "services/api/pyproject.toml",
                    "manifest_kind": "pyproject",
                    "source": "source-inventory",
                },
                {
                    "path": "services/api/requirements.txt",
                    "manifest_kind": "requirements",
                    "source": "metadata-channel",
                },
            ],
            "python_file_count": 1,
            "is_empty": False,
            "built": True,
            "digests": api_digests,
            "scan_summary": dict(zero_scan),
            "semantic_topn": _semantic_topn_for_component(root, "services/api"),
        },
    ]
    edges = [
        {
            "source_component_id": "component:services/api",
            "target_component_id": "component:packages/core",
            "status": "resolved",
            "imported_name": "core",
            "evidence": [
                {
                    "path": "services/api/api.py",
                    "line": 2,
                    "imported_name": "core",
                }
            ],
        }
    ]
    unknown_imports = [
        {
            "source_component_id": "component:services/api",
            "imported_name": "missing_zeta",
            "count": 1,
        }
    ]
    scan_summaries = [
        {"component_id": "component:packages/core", **zero_scan},
        {"component_id": "component:services/api", **zero_scan},
    ]
    payload: dict[str, Any] = {
        "schema_version": "2.0",
        "model_kind": "lima.component-graph",
        "components": components,
        "edges": edges,
        "unknown_imports": unknown_imports,
        "unassigned_files": ["main.py"],
        "unassigned_file_count": 1,
        "scan_summaries": scan_summaries,
        "unbuilt_components": [],
        "dependencies_complete": True,
        "coverage_gaps": [],
        "metadata_manifest_count": 4,
        "metadata_channel_skipped": {},
        "manifests_discovered_count": 4,
        "collaboration_manifest_count": 1,
        "overflow_manifest_count": 0,
        "build": {"monorepo_budgets": dict(EFFECTIVE_DEFAULT_BUDGETS)},
        "identity": {"component_graph_digest": ""},
        "provenance": {"provenance_anchor_ids": ["component-graph"]},
    }
    payload["identity"]["component_graph_digest"] = compute_content_digest(
        canonical_dict_from_payload(payload)
    )
    return payload


def canonical_dict_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Project a graph payload onto the frozen canonical dict (section 5.4.5).

    D2-04 explicit projection: the wire field ``components[].digests`` maps
    to the canonical key ``artifact_digests`` (three per-field values equal,
    names differ); wire ``manifest_kind`` maps to canonical ``kind``. The
    projection never reads a payload ``artifact_digests`` key and never adds
    fields outside the frozen key set.
    """

    components = []
    for entry in payload["components"]:
        digests = entry["digests"]
        components.append(
            {
                "component_id": entry["component_id"],
                "root_dir": entry["root_dir"],
                "manifests": [
                    {
                        "path": ref["path"],
                        "kind": ref["manifest_kind"],
                        "source": ref["source"],
                    }
                    for ref in entry["manifests"]
                ],
                "python_file_count": entry["python_file_count"],
                "is_empty": entry["is_empty"],
                "artifact_digests": (
                    None
                    if digests is None
                    else {
                        "profile_content_digest": digests["profile_content_digest"],
                        "ram_facts_digest": digests["ram_facts_digest"],
                        "semantic_result_digest": digests["semantic_result_digest"],
                    }
                ),
            }
        )
    return {
        "components": components,
        "edges": [
            {
                "source_component_id": edge["source_component_id"],
                "target_component_id": edge["target_component_id"],
                "status": edge["status"],
                "imported_name": edge["imported_name"],
                "evidence": [
                    {
                        "path": item["path"],
                        "line": item["line"],
                        "imported_name": item["imported_name"],
                    }
                    for item in edge["evidence"]
                ],
            }
            for edge in payload["edges"]
        ],
        "unknown_imports": [
            {
                "source_component_id": item["source_component_id"],
                "imported_name": item["imported_name"],
                "count": item["count"],
            }
            for item in payload["unknown_imports"]
        ],
        "scan_summaries": [
            {
                "component_id": item["component_id"],
                "parse_error_file_count": item["parse_error_file_count"],
                "read_failure_file_count": item["read_failure_file_count"],
                "dynamic_import_site_count": item["dynamic_import_site_count"],
                "unknown_truncated_count": item["unknown_truncated_count"],
                "manifest_parse_failure_count": item["manifest_parse_failure_count"],
            }
            for item in payload["scan_summaries"]
        ],
        "unbuilt_components": [
            {"component_id": item["component_id"], "reason": item["reason"]}
            for item in payload["unbuilt_components"]
        ],
        "unassigned_files": list(payload["unassigned_files"]),
        "unassigned_file_count": payload["unassigned_file_count"],
        "dependencies_complete": payload["dependencies_complete"],
        "coverage_gaps": [
            {"gap_code": gap["gap_code"], "detail": gap["detail"]}
            for gap in payload["coverage_gaps"]
        ],
        "manifests_discovered_count": payload["manifests_discovered_count"],
        "metadata_manifest_count": payload["metadata_manifest_count"],
        "collaboration_manifest_count": payload["collaboration_manifest_count"],
        "overflow_manifest_count": payload["overflow_manifest_count"],
    }


class GoldenOracleTests(unittest.TestCase):
    """#38: golden JSON == P&V independent expectation (never builder output)."""

    def test_golden_expected_from_independent_oracle(self) -> None:
        cg = load_cg()
        golden = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
        with shapes.monorepo_workspace(shapes.GOLDEN_MONOREPO) as (root, _ws):
            expected = independent_golden_payload(root)
        self.assertEqual(golden, expected)

        # Frozen-contract cross-checks against the module constants (V2
        # const domain): the golden must carry the frozen schema identity,
        # provenance anchor and manifest enum values, not free text.
        self.assertEqual(golden["schema_version"], cg.COMPONENT_GRAPH_SCHEMA_VERSION)
        self.assertEqual(golden["model_kind"], cg.COMPONENT_GRAPH_SCHEMA_NAME)
        self.assertEqual(
            golden["provenance"]["provenance_anchor_ids"],
            [cg.COMPONENT_GRAPH_PROVENANCE_ANCHOR],
        )
        kind_by_value = {
            "pyproject": cg.COMPONENT_MANIFEST_KIND_PYPROJECT,
            "requirements": cg.COMPONENT_MANIFEST_KIND_REQUIREMENTS,
        }
        for entry in golden["components"]:
            for ref in entry["manifests"]:
                self.assertEqual(
                    ref["manifest_kind"], kind_by_value[ref["manifest_kind"]]
                )
                self.assertIn(ref["source"], cg.COMPONENT_MANIFEST_SOURCES)
            self.assertIn(entry["semantic_topn"]["top_n"], range(1, 101))

        # D2-01 negative control on the golden itself: the stored semantic
        # slot is the facts-bound form; the unbound recomputation must differ.
        with shapes.monorepo_workspace(shapes.GOLDEN_MONOREPO) as (root, _ws2):
            api = RepositoryWorkspace(root / "services/api")
            ram = build_python_ram_facts(api)
            semantic = build_semantic_top_n(ram.facts)
        unbound = semantic_result_digest(semantic)
        api_entry = next(
            entry
            for entry in golden["components"]
            if entry["component_id"] == "component:services/api"
        )
        bound_slot = api_entry["digests"]["semantic_result_digest"]
        self.assertNotEqual(unbound, bound_slot)
        self.assertEqual(
            semantic_result_digest(
                semantic, input_facts_digest=ram_facts_digest(ram.facts)
            ),
            bound_slot,
        )


class GoldenReplayTests(unittest.TestCase):
    """#39: two independent builds replay the golden payload and Top-N order."""

    def test_golden_monorepo_replay_and_topn(self) -> None:
        cg = load_cg()
        golden = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
        payloads = []
        for _round in range(2):
            with shapes.monorepo_workspace(shapes.GOLDEN_MONOREPO) as (_root, ws):
                result = cg.build_monorepo_profile(
                    ws, **monorepo_build_kwargs()
                )
                payloads.append(cg.component_graph_payload(result))
        first, second = payloads
        self.assertEqual(first, second)
        self.assertEqual(first, golden)
        self.assertEqual(
            first["identity"]["component_graph_digest"],
            second["identity"]["component_graph_digest"],
        )
        for entry in first["components"]:
            self.assertLessEqual(
                len(entry["semantic_topn"]["ranked_candidate_ids"]),
                entry["semantic_topn"]["top_n"],
            )


class GoldenProvenanceTests(unittest.TestCase):
    """#40: graph anchor, per-component three-stage anchor chain, manifests."""

    def test_golden_monorepo_provenance_chain(self) -> None:
        cg = load_cg()
        with shapes.monorepo_workspace(shapes.GOLDEN_MONOREPO) as (_root, ws):
            result = cg.build_monorepo_profile(ws, **monorepo_build_kwargs())
        self.assertEqual(
            result.provenance_anchor_ids, (cg.COMPONENT_GRAPH_PROVENANCE_ANCHOR,)
        )
        self.assertEqual(
            result.discovery.provenance_anchor_ids,
            (cg.COMPONENT_GRAPH_PROVENANCE_ANCHOR,),
        )
        self.assertEqual(
            result.graph.provenance_anchor_ids,
            (cg.COMPONENT_GRAPH_PROVENANCE_ANCHOR,),
        )
        for built in result.per_component:
            self.assertEqual(built.profile_result.provenance_anchor_ids, ("inventory",))
            self.assertEqual(built.ram_result.provenance_anchor_ids, ("ram-facts",))
            self.assertEqual(
                built.semantic_result.provenance_anchor_ids,
                ("semantic-prioritizer",),
            )
            for ref in built.component.manifests:
                self.assertIn(ref.source, cg.COMPONENT_MANIFEST_SOURCES)
        payload = cg.component_graph_payload(result)
        self.assertEqual(
            payload["provenance"]["provenance_anchor_ids"],
            ["component-graph"],
        )


class GoldenTamperTests(unittest.TestCase):
    """#41: tampering any participating golden field breaks the graph digest."""

    def test_golden_tamper_detected(self) -> None:
        cg = load_cg()
        golden = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
        original_digest = golden["identity"]["component_graph_digest"]
        cg.validate_component_graph_payload(deepcopy(golden))

        def tampered(mutate: Any) -> dict[str, Any]:
            candidate = deepcopy(golden)
            mutate(candidate)
            return candidate

        def bump_component_count(payload: dict[str, Any]) -> None:
            payload["components"][0]["python_file_count"] += 1

        def rename_component(payload: dict[str, Any]) -> None:
            payload["components"][0]["component_id"] = "component:evil"

        def retarget_edge(payload: dict[str, Any]) -> None:
            payload["edges"][0]["target_component_id"] = "component:services/api"

        def bump_unknown_count(payload: dict[str, Any]) -> None:
            payload["unknown_imports"][0]["count"] += 1

        def bump_scan_count(payload: dict[str, Any]) -> None:
            payload["scan_summaries"][0]["dynamic_import_site_count"] += 1

        def flip_complete(payload: dict[str, Any]) -> None:
            payload["dependencies_complete"] = False

        def bump_discovered(payload: dict[str, Any]) -> None:
            payload["manifests_discovered_count"] += 1

        def swap_artifact_refs(payload: dict[str, Any]) -> None:
            first, second = payload["components"][0], payload["components"][1]
            first["digests"], second["digests"] = second["digests"], first["digests"]

        def null_out_digests(payload: dict[str, Any]) -> None:
            payload["components"][0]["digests"] = None

        def add_gap(payload: dict[str, Any]) -> None:
            payload["coverage_gaps"].append(
                {"gap_code": "INVENTORY_SKIPPED", "detail": "reason=binary; count=1"}
            )

        mutations = (
            bump_component_count,
            rename_component,
            retarget_edge,
            bump_unknown_count,
            bump_scan_count,
            flip_complete,
            bump_discovered,
            swap_artifact_refs,
            null_out_digests,
            add_gap,
        )
        for mutate in mutations:
            candidate = tampered(mutate)
            with self.subTest(mutate=mutate.__name__):
                self.assertNotEqual(
                    compute_content_digest(canonical_dict_from_payload(candidate)),
                    original_digest,
                )
                with self.assertRaises(ContractError):
                    cg.validate_component_graph_payload(candidate)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
