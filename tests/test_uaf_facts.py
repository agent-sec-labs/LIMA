"""Fact Adapter tests: main-process UAF fact bundle validation (plan Task 5).

The wire fixtures mirror the Task 4 Sidecar shape exactly
(``cxx_analyzer/uaf_scan.py`` ``_UnitSink.add_fact`` plus the
``wire_fact`` helper of ``tests/test_uaf_protocol.py``): seven common
fact fields plus the per-kind additional fields, hash provenance at
bundle level only.  ``load_fact_bundle`` is the primary entry point
under test; ``adapt_uaf_response`` is exercised on the client-object
path and must produce the identical bundle.
"""

import unittest

from lima.cxx_memory import UafFactsResponse, uaf_facts_bundle_sha256
from lima.uaf_facts import (
    FACT_FIELD_SETS,
    FactBundleError,
    UafFactBundle,
    UnitFacts,
    adapt_uaf_response,
    load_fact_bundle,
)
from lima.uaf_models import FactBundleExpectation, UafFactKind

SNAPSHOT = "a" * 64
OTHER_SNAPSHOT = "b" * 64
CONTEXT = "c" * 64
OTHER_CONTEXT = "d" * 64
ROOT = "src"
UNIT_A = "src/a.cpp"
UNIT_B = "src/b.cpp"
RUN_ID = "run-uaf-1"
POINTER = "p"


def _fid(number: int) -> str:
    """One distinct lowercase-hex fact id."""
    return format(number, "064x")


ALLOC_ID = _fid(1)
RELEASE_ID = _fid(2)
DEREF_ID = _fid(3)


_KIND_EXTRA_FIELDS = {
    "allocation": {"allocation_api": "new", "pointer_id": POINTER},
    "release": {"release_api": "delete", "pointer_id": POINTER, "related_fact_ids": []},
    "dereference": {"pointer_id": POINTER},
    "member-access": {"pointer_id": POINTER},
    "alias-copy": {"pointer_id": "q", "source_pointer_id": POINTER},
    "points-to": {"pointer_id": POINTER, "source_pointer_id": "", "related_fact_ids": []},
    "rebind": {"pointer_id": POINTER, "source_pointer_id": "", "related_fact_ids": []},
}
_COMMON_FIELDS = {
    "fact_id": "",
    "kind": "",
    "translation_unit": UNIT_A,
    "canonical_path": UNIT_A,
    "function_usr": "c:@F@use#",
    "source_range": [2, 2],
    "cfg_block": 0,
}


def _wire_fact(kind: str, fact_id: str, **changes):
    kind = changes.pop("kind", kind)
    fact = dict(_COMMON_FIELDS)
    fact["fact_id"] = fact_id
    fact["kind"] = kind
    fact.update(_KIND_EXTRA_FIELDS.get(kind, {}))
    fact.update(changes)
    return fact


def _unit_a_facts() -> list[dict]:
    """All seven Task 4 emitted kinds over one object, with a related chain."""
    return [
        _wire_fact("allocation", ALLOC_ID),
        _wire_fact("points-to", _fid(11), related_fact_ids=[ALLOC_ID]),
        _wire_fact("release", RELEASE_ID, related_fact_ids=[ALLOC_ID]),
        _wire_fact("dereference", DEREF_ID),
        _wire_fact("rebind", _fid(12), related_fact_ids=[ALLOC_ID]),
        _wire_fact("alias-copy", _fid(13)),
        _wire_fact("member-access", _fid(14)),
    ]


def _unit_entry(
    unit: str = UNIT_A,
    extraction: str = "completed",
    facts: list[dict] | None = None,
    context_hash: str = CONTEXT,
    gaps: list[str] | None = None,
) -> dict:
    completed = extraction == "completed"
    return {
        "translation_unit": unit,
        "extraction": extraction,
        "build_context": {
            "status": "resolved" if completed else "unavailable",
            "source_kind": "repository-compdb" if completed else "",
            "context_hash": context_hash if completed else "",
            "diagnostics": [],
        },
        "coverage": {
            "ast_complete": completed,
            "cfg_complete": completed,
            "semantic_gaps": list(gaps or ()),
        },
        "facts": list(facts or ()),
    }


def _tool_run(**changes) -> dict:
    run = {"run_id": RUN_ID, "tool": "uaf-facts", "status": "completed"}
    run.update(changes)
    return run


def _raw_bundle(units=None, *, snapshot: str = SNAPSHOT, tool_runs=None, **changes) -> dict:
    if units is None:
        units = [_unit_entry(facts=_unit_a_facts())]
    if tool_runs is None:
        tool_runs = [_tool_run()]
    payload = {
        "schema_version": 1,
        "request_id": "req-1",
        "repository_key": "team/project",
        "snapshot_sha256": snapshot,
        "tool_runs": tool_runs,
        "translation_units": units,
        "bundle_sha256": uaf_facts_bundle_sha256(units),
        "diagnostics": [],
    }
    payload.update(changes)
    return payload


def _expectation(**overrides) -> FactBundleExpectation:
    fields = {
        "snapshot_hash": SNAPSHOT,
        "build_context_hash": CONTEXT,
        "repository_root": ROOT,
        "allowed_tool_runs": frozenset({RUN_ID}),
    }
    fields.update(overrides)
    return FactBundleExpectation(**fields)


class ValidBundleTests(unittest.TestCase):
    def test_fact_field_sets_align_with_task4_wire(self):
        common = frozenset(
            {
                "fact_id",
                "kind",
                "translation_unit",
                "canonical_path",
                "function_usr",
                "source_range",
                "cfg_block",
            }
        )
        expected = {
            "allocation": common | {"allocation_api", "pointer_id"},
            "release": common | {"release_api", "pointer_id", "related_fact_ids"},
            "dereference": common | {"pointer_id"},
            "member-access": common | {"pointer_id"},
            "alias-copy": common | {"pointer_id", "source_pointer_id"},
            "points-to": common | {"pointer_id", "source_pointer_id", "related_fact_ids"},
            "rebind": common | {"pointer_id", "source_pointer_id", "related_fact_ids"},
            # Kinds the Task 4 extractor does not emit yet accept the common
            # fields only; any extra field stays an unknown field.
            "lifetime-restart": common,
            "cfg-node": common,
            "cfg-edge": common,
            "coverage-gap": common,
        }
        self.assertEqual(expected, FACT_FIELD_SETS)

    def test_valid_bundle_round_trips_all_fields(self):
        payload = _raw_bundle()
        bundle = load_fact_bundle(payload, _expectation())

        self.assertIsInstance(bundle, UafFactBundle)
        self.assertEqual(SNAPSHOT, bundle.meta.snapshot_hash)
        self.assertEqual(CONTEXT, bundle.meta.build_context_hash)
        self.assertEqual("uaf-facts", bundle.meta.producer_name)
        self.assertEqual(RUN_ID, bundle.meta.tool_run_id)
        self.assertEqual(payload["bundle_sha256"], bundle.meta.bundle_sha256)
        self.assertEqual(7, len(bundle.facts))

        by_id = {fact.fact_id: fact for fact in bundle.facts}
        allocation = by_id[ALLOC_ID]
        self.assertEqual(UafFactKind.ALLOCATION, allocation.kind)
        self.assertEqual(POINTER, allocation.pointer_id)
        self.assertEqual((2, 2), allocation.source_range)
        self.assertEqual(UNIT_A, allocation.translation_unit)
        self.assertEqual(UNIT_A, allocation.canonical_path)
        self.assertEqual(0, allocation.cfg_block)
        release = by_id[RELEASE_ID]
        self.assertEqual(UafFactKind.RELEASE, release.kind)
        # The related chain resolves inside the bundle.
        self.assertEqual((ALLOC_ID,), release.related_fact_ids)
        deref = by_id[DEREF_ID]
        self.assertEqual(UafFactKind.DEREFERENCE, deref.kind)
        self.assertEqual(POINTER, deref.pointer_id)

        # Three-way hash identity: every stamped fact == meta == expectation.
        for fact in bundle.facts:
            self.assertEqual(SNAPSHOT, fact.snapshot_hash)
            self.assertEqual(CONTEXT, fact.build_context_hash)

        unit = bundle.per_unit[0]
        self.assertIsInstance(unit, UnitFacts)
        self.assertEqual(UNIT_A, unit.translation_unit)
        self.assertEqual("resolved", unit.build_context.status)
        self.assertTrue(unit.coverage.ast_complete)
        self.assertTrue(unit.coverage.cfg_complete)
        self.assertEqual(tuple(bundle.facts), unit.facts)
        self.assertEqual((), bundle.coverage_gaps)

    def test_wire_api_and_source_pointer_fill_fact_fields(self):
        # Task 6 contract-gap closure: the adapter must keep the Task 4 wire
        # fields it previously dropped -- allocation/release api and the
        # alias source pointer -- instead of discarding them at the boundary.
        payload = _raw_bundle()
        bundle = load_fact_bundle(payload, _expectation())
        by_id = {fact.fact_id: fact for fact in bundle.facts}
        allocation = by_id[ALLOC_ID]
        self.assertEqual("new", allocation.api)
        self.assertEqual("", allocation.source_pointer_id)
        release = by_id[RELEASE_ID]
        self.assertEqual("delete", release.api)
        self.assertEqual("", release.source_pointer_id)
        alias = by_id[_fid(13)]
        self.assertEqual(POINTER, alias.source_pointer_id)
        self.assertEqual("", alias.api)
        deref = by_id[DEREF_ID]
        self.assertEqual("", deref.api)
        self.assertEqual("", deref.source_pointer_id)

    def test_coverage_gaps_aggregate_across_units(self):
        units = [
            _unit_entry(UNIT_A, facts=_unit_a_facts(), gaps=["macro-expansion"]),
            _unit_entry(UNIT_B, facts=[], gaps=["cfg-loop", "macro-expansion"]),
        ]
        bundle = load_fact_bundle(_raw_bundle(units=units), _expectation())
        self.assertEqual(("macro-expansion", "cfg-loop"), bundle.coverage_gaps)

    def test_adapt_from_client_response_round_trips(self):
        payload = _raw_bundle()
        response = UafFactsResponse(
            request_id=payload["request_id"],
            repository_key=payload["repository_key"],
            snapshot_sha256=payload["snapshot_sha256"],
            tool_runs=tuple(payload["tool_runs"]),
            translation_units=tuple(payload["translation_units"]),
            bundle_sha256=payload["bundle_sha256"],
            diagnostics=(),
        )
        from_adapt = adapt_uaf_response(response, _expectation())
        from_load = load_fact_bundle(payload, _expectation())
        self.assertEqual(7, len(from_adapt.facts))
        self.assertEqual(from_load, from_adapt)

    def test_rootless_expectation_skips_root_check_but_keeps_paths_safe(self):
        expectation = _expectation(repository_root="")
        relocated = [
            dict(fact, translation_unit="include/b.cpp", canonical_path="include/b.cpp")
            for fact in _unit_a_facts()
        ]
        bundle = load_fact_bundle(
            _raw_bundle(units=[_unit_entry(unit="include/b.cpp", facts=relocated)]),
            expectation,
        )
        self.assertEqual("include/b.cpp", bundle.per_unit[0].translation_unit)
        with self.assertRaises(FactBundleError):
            load_fact_bundle(_raw_bundle(units=[_unit_entry(unit="../b.cpp")]), expectation)


class BundleRejectionTests(unittest.TestCase):
    def _assert_rejected(self, expectation=None, keyword: str = "", **payload_kwargs) -> str:
        payload = _raw_bundle(**payload_kwargs)
        with self.assertRaises(FactBundleError) as caught:
            load_fact_bundle(
                payload, _expectation() if expectation is None else expectation
            )
        message = str(caught.exception)
        if keyword:
            self.assertIn(keyword, message)
        return message

    def test_fact_bundle_error_is_value_error(self):
        self.assertTrue(issubclass(FactBundleError, ValueError))

    def test_unknown_fact_field_rejected(self):
        fact = _wire_fact("allocation", ALLOC_ID, notes="extra")
        self._assert_rejected(units=[_unit_entry(facts=[fact])], keyword="unknown fact field")

    def test_non_string_wire_api_rejected(self):
        # The api and alias-source wire fields are kept now, so their value
        # domain is enforced through UafFact construction instead of dropped.
        fact = _wire_fact("allocation", ALLOC_ID, allocation_api=7)
        self._assert_rejected(units=[_unit_entry(facts=[fact])], keyword="fact 0")
        misphrased = _wire_fact("release", RELEASE_ID, release_api=True)
        self._assert_rejected(units=[_unit_entry(facts=[misphrased])], keyword="fact 0")

    def test_non_string_wire_source_pointer_rejected(self):
        fact = _wire_fact("alias-copy", _fid(13), source_pointer_id=None)
        self._assert_rejected(units=[_unit_entry(facts=[fact])], keyword="fact 0")

    def test_missing_fact_field_rejected(self):
        fact = _wire_fact("allocation", ALLOC_ID)
        del fact["pointer_id"]
        self._assert_rejected(units=[_unit_entry(facts=[fact])], keyword="missing fact field")

    def test_duplicate_fact_id_rejected(self):
        facts = [
            _wire_fact("allocation", ALLOC_ID),
            _wire_fact("dereference", ALLOC_ID),
        ]
        self._assert_rejected(units=[_unit_entry(facts=facts)], keyword="duplicate fact_id")

    def test_dangling_related_fact_id_rejected(self):
        fact = _wire_fact("release", RELEASE_ID, related_fact_ids=[_fid(999)])
        self._assert_rejected(units=[_unit_entry(facts=[fact])], keyword="dangling")

    def test_out_of_range_source_range_rejected(self):
        cases = (
            ("end before start", [5, 2]),
            ("zero start line", [0, 3]),
            ("negative start line", [-1, 3]),
        )
        for name, source_range in cases:
            with self.subTest(name=name):
                fact = _wire_fact("dereference", DEREF_ID, source_range=source_range)
                self._assert_rejected(
                    units=[_unit_entry(facts=[fact])], keyword="source_range"
                )

    def test_snapshot_hash_mismatch_rejected(self):
        # Task 4 wire facts carry snapshot identity at bundle level only;
        # the meta and fact layers are stamped from the verified echo (the
        # round-trip test asserts the three-way equality), so the response
        # echo is the wire leg that can fail.
        self._assert_rejected(snapshot=OTHER_SNAPSHOT, keyword="snapshot_sha256")
        self._assert_rejected(snapshot="z" * 64, keyword="snapshot_sha256")

    def test_build_context_hash_mismatch_rejected(self):
        units = [_unit_entry(facts=_unit_a_facts(), context_hash=OTHER_CONTEXT)]
        self._assert_rejected(units=units, keyword="build context hash")

    def test_tool_run_not_allowed_rejected(self):
        self._assert_rejected(
            tool_runs=[_tool_run(run_id="run-other")], keyword="allowed tool runs"
        )
        self._assert_rejected(tool_runs=[_tool_run(tool="clang")], keyword="tool")

    def test_multiple_tool_runs_rejected(self):
        self._assert_rejected(
            tool_runs=[_tool_run(run_id="run-1"), _tool_run(run_id="run-2")],
            keyword="exactly one",
        )

    def test_bundle_hash_mismatch_rejected(self):
        self._assert_rejected(bundle_sha256=OTHER_SNAPSHOT, keyword="bundle_sha256")

    def test_path_escape_rejected(self):
        fact = _wire_fact("dereference", DEREF_ID, canonical_path="../escape.cpp")
        self._assert_rejected(units=[_unit_entry(facts=[fact])], keyword="canonical_path")
        self._assert_rejected(
            units=[_unit_entry(unit="include/b.cpp", facts=_unit_a_facts())],
            keyword="repository root",
        )
        self._assert_rejected(
            units=[_unit_entry(unit="/etc/evil.cpp")], keyword="safe relative"
        )

    def test_fact_from_foreign_unit_rejected(self):
        fact = _wire_fact("dereference", DEREF_ID, translation_unit="src/other.cpp")
        self._assert_rejected(
            units=[_unit_entry(facts=[fact])], keyword="translation_unit"
        )

    def test_oversized_bundle_rejected(self):
        facts = [_wire_fact("dereference", _fid(number)) for number in range(1025)]
        self._assert_rejected(units=[_unit_entry(facts=facts)], keyword="1024")

    def test_oversized_bundle_bytes_rejected(self):
        fat_pointer = "x" * 2048
        facts = [
            _wire_fact("dereference", _fid(number), pointer_id=fat_pointer)
            for number in range(1024)
        ]
        self._assert_rejected(units=[_unit_entry(facts=facts)], keyword="byte")

    def test_unavailable_unit_with_facts_rejected(self):
        units = [
            _unit_entry(extraction="unavailable", facts=[_wire_fact("allocation", ALLOC_ID)])
        ]
        self._assert_rejected(units=units, keyword="unavailable")

    def test_unavailable_unit_cannot_claim_completeness(self):
        entry = _unit_entry(extraction="unavailable")
        entry["coverage"]["ast_complete"] = True
        self._assert_rejected(units=[entry], keyword="completeness")

    def test_unknown_kind_rejected(self):
        fact = _wire_fact("double-free-record", ALLOC_ID)
        self._assert_rejected(units=[_unit_entry(facts=[fact])], keyword="unknown fact kind")

    def test_load_rejects_wrong_schema_version(self):
        self._assert_rejected(schema_version=2, keyword="schema")

    def test_load_rejects_unknown_response_field(self):
        self._assert_rejected(extra="field", keyword="response field")

    def test_adapt_rejects_bundle_hash_mismatch(self):
        payload = _raw_bundle()
        response = UafFactsResponse(
            request_id=payload["request_id"],
            repository_key=payload["repository_key"],
            snapshot_sha256=payload["snapshot_sha256"],
            tool_runs=tuple(payload["tool_runs"]),
            translation_units=tuple(payload["translation_units"]),
            bundle_sha256=OTHER_SNAPSHOT,
            diagnostics=(),
        )
        with self.assertRaises(FactBundleError) as caught:
            adapt_uaf_response(response, _expectation())
        self.assertIn("bundle_sha256", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
