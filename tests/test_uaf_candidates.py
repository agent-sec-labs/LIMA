"""Deterministic Candidate Generator tests (plan Task 6).

The generator is a pure function over a certified
:class:`~lima.uaf_facts.UafFactBundle`: zero LLM, zero labels, zero I/O.
Fixtures below construct :class:`~lima.uaf_models.UafFact` records
directly (they satisfy the same per-field validators the Task 5 adapter
applies) and freeze them into bundles through :class:`~lima.uaf_facts.UnitFacts`.
"""

import unittest

from lima.uaf_candidates import (
    CandidateGenerationStats,
    generate_candidates,
    generation_stats,
)
from lima.uaf_facts import UafFactBundle, UnitFacts
from lima.uaf_models import (
    UAF_SCHEMA_VERSION,
    BuildContextResolution,
    ExtractionCoverage,
    FactBundleMeta,
    UafCandidate,
    UafFact,
    UafFactKind,
    derive_candidate_id,
    derive_object_id,
)

SNAPSHOT = "a" * 64
CONTEXT = "c" * 64
RUN_ID = "run-uaf-1"
UNIT_A = "src/a.cpp"
UNIT_B = "src/b.cpp"
USR_MAIN = "c:@F@main#"
USR_OTHER = "c:@F@other#"


def _fid(number: int) -> str:
    """One distinct lowercase-hex fact id."""
    return format(number, "064x")


ALLOC = _fid(1)
RELEASE = _fid(2)
DEREF = _fid(3)
MEMBER = _fid(4)


def _fact(
    kind: UafFactKind,
    number: int,
    *,
    line: int = 1,
    end: int | None = None,
    usr: str = USR_MAIN,
    pointer: str = "",
    api: str = "",
    source: str = "",
    related: tuple[str, ...] = (),
    unit: str = UNIT_A,
) -> UafFact:
    return UafFact(
        fact_id=_fid(number),
        kind=kind,
        snapshot_hash=SNAPSHOT,
        build_context_hash=CONTEXT,
        translation_unit=unit,
        canonical_path=unit,
        function_usr=usr,
        source_range=(line, line if end is None else end),
        cfg_block=0,
        pointer_id=pointer,
        api=api,
        source_pointer_id=source,
        related_fact_ids=tuple(related),
    )


def _unit(facts, *, unit: str = UNIT_A, cfg_complete: bool = True, gaps: tuple = ()) -> UnitFacts:
    return UnitFacts(
        translation_unit=unit,
        build_context=BuildContextResolution(
            status="resolved",
            source_kind="repository-compdb",
            context_hash=CONTEXT,
        ),
        coverage=ExtractionCoverage(
            ast_complete=True,
            cfg_complete=cfg_complete,
            semantic_gaps=tuple(gaps),
        ),
        facts=tuple(facts),
    )


def _bundle(*units: UnitFacts) -> UafFactBundle:
    return UafFactBundle(
        meta=FactBundleMeta(
            snapshot_hash=SNAPSHOT,
            build_context_hash=CONTEXT,
            producer_name="uaf-facts",
            producer_version="1",
            tool_run_id=RUN_ID,
        ),
        facts=tuple(fact for unit in units for fact in unit.facts),
        per_unit=tuple(units),
        coverage_gaps=(),
    )


def _straight_line_bundle() -> UafFactBundle:
    """alloc p (10) -> release p (20) -> *p (30): the canonical one-candidate shape."""
    return _bundle(
        _unit(
            [
                _fact(UafFactKind.ALLOCATION, 1, line=10, pointer="p", api="new"),
                _fact(UafFactKind.RELEASE, 2, line=20, pointer="p", api="delete", related=(ALLOC,)),
                _fact(UafFactKind.DEREFERENCE, 3, line=30, pointer="p"),
            ]
        )
    )


class StraightLineGenerationTests(unittest.TestCase):
    def test_candidate_id_matches_manual_derivation(self):
        candidates = generate_candidates(_straight_line_bundle())
        self.assertEqual(1, len(candidates))
        candidate = candidates[0]
        object_id = derive_object_id(
            UAF_SCHEMA_VERSION, UNIT_A, USR_MAIN, 10, 10, "new"
        )
        self.assertEqual(object_id, candidate.object_id)
        self.assertEqual(
            derive_candidate_id(UAF_SCHEMA_VERSION, object_id, RELEASE, DEREF),
            candidate.candidate_id,
        )
        self.assertEqual(ALLOC, candidate.allocation_fact_id)
        self.assertEqual(RELEASE, candidate.release_fact_id)
        self.assertEqual(DEREF, candidate.use_fact_id)
        self.assertEqual(UNIT_A, candidate.canonical_path)
        self.assertEqual(USR_MAIN, candidate.function_usr)
        self.assertEqual((20, 20), candidate.release_range)
        self.assertEqual((30, 30), candidate.use_range)
        self.assertIsInstance(candidate, UafCandidate)

    def test_same_object_multiple_release_use_pairs_yield_distinct_candidates(self):
        # One release, two uses: each pair becomes its own candidate id.
        bundle = _bundle(
            _unit(
                [
                    _fact(UafFactKind.ALLOCATION, 1, line=10, pointer="p", api="new"),
                    _fact(
                        UafFactKind.RELEASE, 2, line=20, pointer="p", api="delete", related=(ALLOC,)
                    ),
                    _fact(UafFactKind.DEREFERENCE, 3, line=30, pointer="p"),
                    _fact(UafFactKind.MEMBER_ACCESS, 4, line=40, pointer="p"),
                ]
            )
        )
        candidates = generate_candidates(bundle)
        self.assertEqual(2, len(candidates))
        self.assertEqual(2, len({candidate.candidate_id for candidate in candidates}))
        self.assertEqual({DEREF, MEMBER}, {candidate.use_fact_id for candidate in candidates})

        # Two releases, one use: the release leg also multiplies candidates.
        bundle = _bundle(
            _unit(
                [
                    _fact(UafFactKind.ALLOCATION, 1, line=10, pointer="p", api="new"),
                    _fact(
                        UafFactKind.RELEASE, 2, line=20, pointer="p", api="delete", related=(ALLOC,)
                    ),
                    _fact(
                        UafFactKind.RELEASE,
                        5,
                        line=25,
                        pointer="p",
                        api="free",
                        related=(ALLOC,),
                    ),
                    _fact(UafFactKind.DEREFERENCE, 3, line=30, pointer="p"),
                ]
            )
        )
        candidates = generate_candidates(bundle)
        self.assertEqual(2, len(candidates))
        self.assertEqual(2, len({candidate.candidate_id for candidate in candidates}))
        self.assertEqual(
            {RELEASE, _fid(5)}, {candidate.release_fact_id for candidate in candidates}
        )

    def test_no_release_or_no_use_yields_no_candidate(self):
        alloc = _fact(UafFactKind.ALLOCATION, 1, line=10, pointer="p", api="new")
        release = _fact(
            UafFactKind.RELEASE, 2, line=20, pointer="p", api="delete", related=(ALLOC,)
        )
        use = _fact(UafFactKind.DEREFERENCE, 3, line=30, pointer="p")
        self.assertEqual((), generate_candidates(_bundle(_unit([alloc, use]))))
        self.assertEqual((), generate_candidates(_bundle(_unit([alloc, release]))))
        self.assertEqual((), generate_candidates(_bundle(_unit([alloc]))))

    def test_release_without_related_allocation_is_skipped_not_guessed(self):
        # A release with an empty related list is never attached by pointer
        # name or position, and a release whose related ids only reference a
        # non-allocation fact is equally unattached: no candidate, no guess.
        bundle = _bundle(
            _unit(
                [
                    _fact(UafFactKind.ALLOCATION, 1, line=10, pointer="p", api="new"),
                    _fact(UafFactKind.RELEASE, 2, line=20, pointer="p", api="delete"),
                    _fact(UafFactKind.DEREFERENCE, 3, line=30, pointer="p"),
                ]
            )
        )
        candidates = generate_candidates(bundle)
        self.assertEqual((), candidates)
        stats = generation_stats(candidates, bundle)
        self.assertEqual(1, stats.unattached_release_count)

        misrelated = _bundle(
            _unit(
                [
                    _fact(UafFactKind.ALLOCATION, 1, line=10, pointer="p", api="new"),
                    _fact(
                        UafFactKind.RELEASE,
                        2,
                        line=20,
                        pointer="p",
                        api="delete",
                        related=(DEREF,),
                    ),
                    _fact(UafFactKind.DEREFERENCE, 3, line=30, pointer="p"),
                ]
            )
        )
        self.assertEqual((), generate_candidates(misrelated))

    def test_cross_function_uses_not_paired(self):
        bundle = _bundle(
            _unit(
                [
                    _fact(UafFactKind.ALLOCATION, 1, line=10, pointer="p", api="new"),
                    _fact(
                        UafFactKind.RELEASE,
                        2,
                        line=20,
                        pointer="p",
                        api="delete",
                        related=(ALLOC,),
                    ),
                    _fact(UafFactKind.DEREFERENCE, 3, line=30, pointer="p", usr=USR_OTHER),
                    # A same-function alias edge cannot smuggle the foreign
                    # use in either: q in the other function stays unattached.
                    _fact(
                        UafFactKind.ALIAS_COPY, 6, line=15, pointer="q", source="p", usr=USR_OTHER
                    ),
                ]
            )
        )
        self.assertEqual((), generate_candidates(bundle))

    def test_coverage_gap_does_not_block_candidate_generation(self):
        # A coverage gap narrows provability (Task 7), never recall here.
        bundle = _bundle(
            _unit(
                [
                    _fact(UafFactKind.ALLOCATION, 1, line=10, pointer="p", api="new"),
                    _fact(
                        UafFactKind.RELEASE,
                        2,
                        line=20,
                        pointer="p",
                        api="delete",
                        related=(ALLOC,),
                    ),
                    _fact(UafFactKind.DEREFERENCE, 3, line=30, pointer="p"),
                ],
                cfg_complete=False,
                gaps=("cfg-loop",),
            )
        )
        candidates = generate_candidates(bundle)
        self.assertEqual(1, len(candidates))
        self.assertEqual(("cfg-loop",), bundle.per_unit[0].coverage.semantic_gaps)


class AliasReachabilityTests(unittest.TestCase):
    def test_alias_chain_use_pairs_with_allocation(self):
        # q = p; r = q; *r after release -> reachable through the chain.
        bundle = _bundle(
            _unit(
                [
                    _fact(UafFactKind.ALLOCATION, 1, line=10, pointer="p", api="new"),
                    _fact(UafFactKind.ALIAS_COPY, 5, line=12, pointer="q", source="p"),
                    _fact(UafFactKind.ALIAS_COPY, 6, line=14, pointer="r", source="q"),
                    _fact(
                        UafFactKind.RELEASE,
                        2,
                        line=20,
                        pointer="p",
                        api="delete",
                        related=(ALLOC,),
                    ),
                    _fact(UafFactKind.DEREFERENCE, 3, line=30, pointer="r"),
                ]
            )
        )
        candidates = generate_candidates(bundle)
        self.assertEqual(1, len(candidates))
        self.assertEqual(DEREF, candidates[0].use_fact_id)

    def test_alias_edge_respected_line_order(self):
        # *q at line 12 precedes the q = p assignment at line 15: that edge
        # cannot carry the use onto the object; only the later use pairs.
        bundle = _bundle(
            _unit(
                [
                    _fact(UafFactKind.ALLOCATION, 1, line=10, pointer="p", api="new"),
                    _fact(UafFactKind.DEREFERENCE, 3, line=12, pointer="q"),
                    _fact(UafFactKind.ALIAS_COPY, 5, line=15, pointer="q", source="p"),
                    _fact(
                        UafFactKind.RELEASE,
                        2,
                        line=20,
                        pointer="p",
                        api="delete",
                        related=(ALLOC,),
                    ),
                    _fact(UafFactKind.DEREFERENCE, 4, line=30, pointer="q"),
                ]
            )
        )
        candidates = generate_candidates(bundle)
        self.assertEqual(1, len(candidates))
        self.assertEqual(_fid(4), candidates[0].use_fact_id)

    def test_backward_alias_edge_chain_still_reaches(self):
        # Edges are usable in any traversal direction as long as each edge's
        # assignment line precedes the use: r = q (14) then q = p (16) still
        # connects *r at 30 to p's object.
        bundle = _bundle(
            _unit(
                [
                    _fact(UafFactKind.ALLOCATION, 1, line=10, pointer="p", api="new"),
                    _fact(UafFactKind.ALIAS_COPY, 5, line=14, pointer="r", source="q"),
                    _fact(UafFactKind.ALIAS_COPY, 6, line=16, pointer="q", source="p"),
                    _fact(
                        UafFactKind.RELEASE,
                        2,
                        line=20,
                        pointer="p",
                        api="delete",
                        related=(ALLOC,),
                    ),
                    _fact(UafFactKind.DEREFERENCE, 3, line=30, pointer="r"),
                ]
            )
        )
        candidates = generate_candidates(bundle)
        self.assertEqual(1, len(candidates))

    def test_cross_unit_alias_edges_are_not_built(self):
        # Alias graphs are per (TU, function): an edge in another TU never
        # attaches this TU's use to this TU's object.
        bundle = _bundle(
            _unit(
                [
                    _fact(UafFactKind.ALLOCATION, 1, line=10, pointer="p", api="new"),
                    _fact(
                        UafFactKind.RELEASE,
                        2,
                        line=20,
                        pointer="p",
                        api="delete",
                        related=(ALLOC,),
                    ),
                    _fact(UafFactKind.DEREFERENCE, 3, line=30, pointer="q"),
                ]
            ),
            _unit(
                [_fact(UafFactKind.ALIAS_COPY, 5, line=15, pointer="q", source="p", unit=UNIT_B)],
                unit=UNIT_B,
            ),
        )
        self.assertEqual((), generate_candidates(bundle))


class OrderingAndDeterminismTests(unittest.TestCase):
    def test_syntactically_later_only(self):
        alloc = _fact(UafFactKind.ALLOCATION, 1, line=10, pointer="p", api="new")
        release = _fact(
            UafFactKind.RELEASE, 2, line=20, pointer="p", api="delete", related=(ALLOC,)
        )
        before = _fact(UafFactKind.DEREFERENCE, 3, line=15, pointer="p")
        same_spot = _fact(UafFactKind.DEREFERENCE, 4, line=20, pointer="p")
        same_line_later_column = _fact(UafFactKind.DEREFERENCE, 5, line=20, end=25, pointer="p")
        after = _fact(UafFactKind.DEREFERENCE, 6, line=21, pointer="p")

        # Use before release and use at the release position never pair; a
        # use later on the same line and any later line do.
        candidates = generate_candidates(
            _bundle(_unit([alloc, release, before, same_spot, same_line_later_column, after]))
        )
        self.assertEqual(
            {_fid(5), _fid(6)}, {candidate.use_fact_id for candidate in candidates}
        )

        # Same-line later-column pairing carries the release range (20, 20).
        by_use = {candidate.use_fact_id: candidate for candidate in candidates}
        self.assertEqual((20, 20), by_use[_fid(5)].release_range)
        self.assertEqual((20, 25), by_use[_fid(5)].use_range)

    def test_deterministic_ordering(self):
        facts = [
            _fact(UafFactKind.ALLOCATION, 1, line=10, pointer="p", api="new"),
            _fact(UafFactKind.ALIAS_COPY, 7, line=12, pointer="q", source="p"),
            _fact(UafFactKind.RELEASE, 2, line=20, pointer="p", api="delete", related=(ALLOC,)),
            _fact(UafFactKind.DEREFERENCE, 3, line=30, pointer="p"),
            _fact(UafFactKind.MEMBER_ACCESS, 4, line=40, pointer="q"),
            _fact(UafFactKind.ALLOCATION, 8, line=50, pointer="s", api="malloc"),
            _fact(UafFactKind.RELEASE, 9, line=60, pointer="s", api="free", related=(_fid(8),)),
            _fact(UafFactKind.DEREFERENCE, 10, line=70, pointer="s"),
        ]
        first = generate_candidates(_bundle(_unit(facts)))
        second = generate_candidates(_bundle(_unit(facts)))
        self.assertEqual(first, second)
        self.assertEqual(3, len(first))
        keys = [
            (c.canonical_path, c.object_id, c.release_fact_id, c.use_fact_id) for c in first
        ]
        self.assertEqual(sorted(keys), keys)

        # Shuffled input facts produce the identical ordered tuple.
        shuffled = _bundle(_unit([facts[index] for index in (3, 0, 6, 2, 7, 1, 5, 4)]))
        self.assertEqual(first, generate_candidates(shuffled))

    def test_generation_stats_counts_units_allocations_and_unattached_releases(self):
        bundle = _bundle(
            _unit(
                [
                    _fact(UafFactKind.ALLOCATION, 1, line=10, pointer="p", api="new"),
                    _fact(
                        UafFactKind.RELEASE,
                        2,
                        line=20,
                        pointer="p",
                        api="delete",
                        related=(ALLOC,),
                    ),
                    _fact(UafFactKind.DEREFERENCE, 3, line=30, pointer="p"),
                    _fact(UafFactKind.RELEASE, 11, line=25, pointer="z", api="free"),
                ]
            ),
            _unit(
                [_fact(UafFactKind.ALLOCATION, 8, line=5, pointer="s", api="malloc", unit=UNIT_B)],
                unit=UNIT_B,
            ),
        )
        candidates = generate_candidates(bundle)
        stats = generation_stats(candidates, bundle)
        self.assertIsInstance(stats, CandidateGenerationStats)
        self.assertEqual(2, stats.tu_count)
        self.assertEqual(2, stats.allocation_count)
        self.assertEqual(1, stats.pair_count)
        self.assertEqual(1, stats.unattached_release_count)

    def test_cross_unit_related_release_counts_unattached(self):
        # The Task 5 validator accepts related ids bundle-wide, but pairing
        # is per TU: a release attached only to a foreign-TU allocation is
        # unattached, not guessed across units.
        bundle = _bundle(
            _unit([_fact(UafFactKind.ALLOCATION, 1, line=10, pointer="p", api="new")]),
            _unit(
                [
                    _fact(
                        UafFactKind.RELEASE,
                        2,
                        line=20,
                        pointer="p",
                        api="delete",
                        related=(ALLOC,),
                        unit=UNIT_B,
                    ),
                    _fact(UafFactKind.DEREFERENCE, 3, line=30, pointer="p", unit=UNIT_B),
                ],
                unit=UNIT_B,
            ),
        )
        candidates = generate_candidates(bundle)
        self.assertEqual((), candidates)
        self.assertEqual(1, generation_stats(candidates, bundle).unattached_release_count)

    def test_generator_rejects_non_bundle_input(self):
        with self.assertRaises(ValueError):
            generate_candidates(("not", "a", "bundle"))
        with self.assertRaises(ValueError):
            generation_stats((), "not a bundle")


if __name__ == "__main__":
    unittest.main()
