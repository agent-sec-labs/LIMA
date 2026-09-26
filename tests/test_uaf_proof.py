"""P1-P7 Proof Engine tests (plan Task 7, design sections 9.1/9.2 and 15.3).

Fixtures construct :class:`~lima.uaf_models.UafFact` records directly (the
same per-field validators the Task 5 adapter applies) and freeze them into
bundles through :class:`~lima.uaf_facts.UnitFacts`, mirroring the Task 6
test style.  Every obligation's reachable verdict states are pinned:

- P1 satisfied / unknown (custom allocator, missing USR) / refuted (id
  corruption);
- P2 satisfied (direct and alias chain) / refuted (complete graph,
  unreachable) / unknown (incomplete graph);
- P3/P4 satisfied / refuted (defensive: the generator never emits such
  candidates, corruption only);
- P5 satisfied (straight line, single guard region) / refuted (block-order
  unreachability, clang constant-unreachable) / unknown (cfg gaps,
  x>10 / x<=10 predicate pairs);
- P6 satisfied / refuted / unknown; P7 satisfied / refuted / unknown.

Red lines pinned here: complex predicates are always unknown; unknown
paths are never selectively ignored; incomplete coverage and missing USR
forbid PASS even when every visible obligation looks satisfied.
"""

import unittest
from dataclasses import asdict

from lima.contracts.evidence import EvidenceLevel, EvidencePolarity
from lima.uaf_candidates import generate_candidates
from lima.uaf_facts import UafFactBundle, UnitFacts
from lima.uaf_models import (
    OBLIGATION_VERDICTS,
    BuildContextResolution,
    ExtractionCoverage,
    FactBundleMeta,
    P5Detail,
    ProofObligation,
    ProofResult,
    UafCandidate,
    UafFact,
    UafFactKind,
)
from lima.uaf_proof import prove_candidate

SNAPSHOT = "a" * 64
CONTEXT = "c" * 64
RUN_ID = "run-uaf-1"
UNIT_A = "src/a.cpp"
USR_MAIN = "c:@F@main#"


def _fid(number: int) -> str:
    """One distinct lowercase-hex fact id."""
    return format(number, "064x")


ALLOC = _fid(1)
RELEASE = _fid(2)
USE = _fid(3)
REBIND = _fid(4)
RESTART = _fid(5)
ALIAS_Q = _fid(6)
ALIAS_R = _fid(7)
ALIAS_BROKEN = _fid(8)


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
    block: int = 0,
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
        cfg_block=block,
        pointer_id=pointer,
        api=api,
        source_pointer_id=source,
        related_fact_ids=tuple(related),
    )


def _unit(
    facts,
    *,
    unit: str = UNIT_A,
    status: str = "resolved",
    source_kind: str = "repository-compdb",
    ast_complete: bool = True,
    cfg_complete: bool = True,
    gaps: tuple = (),
) -> UnitFacts:
    return UnitFacts(
        translation_unit=unit,
        build_context=BuildContextResolution(
            status=status,
            source_kind=source_kind,
            context_hash=CONTEXT if status == "resolved" else "",
        ),
        coverage=ExtractionCoverage(
            ast_complete=ast_complete,
            cfg_complete=cfg_complete,
            semantic_gaps=tuple(gaps),
        ),
        facts=tuple(facts),
    )


def _bundle(*units: UnitFacts) -> UafFactBundle:
    """Freeze units into a bundle, aggregating coverage gaps like the adapter."""
    coverage_gaps: list[str] = []
    seen: set[str] = set()
    for unit in units:
        for gap in unit.coverage.semantic_gaps:
            if gap not in seen:
                seen.add(gap)
                coverage_gaps.append(gap)
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
        coverage_gaps=tuple(coverage_gaps),
    )


def _candidate(
    *,
    alloc_id: str = ALLOC,
    release_id: str = RELEASE,
    use_id: str = USE,
    usr: str = USR_MAIN,
    release_range: tuple[int, int] = (20, 20),
    use_range: tuple[int, int] = (30, 30),
) -> UafCandidate:
    return UafCandidate(
        candidate_id=_fid(900),
        object_id=_fid(901),
        allocation_fact_id=alloc_id,
        release_fact_id=release_id,
        use_fact_id=use_id,
        canonical_path=UNIT_A,
        function_usr=usr,
        release_range=release_range,
        use_range=use_range,
    )


def _resolution(
    *, status: str = "resolved", source_kind: str = "repository-compdb"
) -> BuildContextResolution:
    return BuildContextResolution(
        status=status,
        source_kind=source_kind,
        context_hash=CONTEXT if status == "resolved" else "",
    )


def _coverage(
    *,
    ast_complete: bool = True,
    cfg_complete: bool = True,
    gaps: tuple = (),
) -> ExtractionCoverage:
    return ExtractionCoverage(
        ast_complete=ast_complete,
        cfg_complete=cfg_complete,
        semantic_gaps=tuple(gaps),
    )


def _straight_facts(
    *,
    use_pointer: str = "p",
    alloc_block: int = 0,
    release_block: int = 0,
    use_block: int = 0,
    usr: str = USR_MAIN,
    extra: tuple[UafFact, ...] = (),
) -> list[UafFact]:
    """alloc p (10) -> delete p (20) -> use (30): the canonical witness shape."""
    return [
        _fact(
            UafFactKind.ALLOCATION, 1, line=10, pointer="p", api="new",
            usr=usr, block=alloc_block,
        ),
        _fact(
            UafFactKind.RELEASE, 2, line=20, pointer="p", api="delete",
            related=(ALLOC,), usr=usr, block=release_block,
        ),
        _fact(
            UafFactKind.DEREFERENCE, 3, line=30, pointer=use_pointer,
            usr=usr, block=use_block,
        ),
        *extra,
    ]


def _prove(
    facts,
    candidate: UafCandidate | None = None,
    *,
    resolution: BuildContextResolution | None = None,
    coverage: ExtractionCoverage | None = None,
    bundle: UafFactBundle | None = None,
) -> ProofResult:
    unit = _unit(facts)
    if bundle is None:
        bundle = _bundle(unit)
    return prove_candidate(
        candidate or _candidate(),
        bundle,
        resolution or _resolution(),
        coverage or _coverage(),
    )


def _verdict(result: ProofResult, obligation: ProofObligation):
    return next(
        item for item in result.obligations if item.obligation is obligation
    )


class StraightLineProofTests(unittest.TestCase):
    def test_straight_line_uaf_all_satisfied(self):
        # Same cfg block everywhere: P1-P7 all satisfied under a complete,
        # resolved readiness -> PASS with (D2, SUPPORTS) evidence.
        bundle = _bundle(_unit(_straight_facts()))
        candidates = generate_candidates(bundle)
        self.assertEqual(1, len(candidates))
        result = prove_candidate(
            candidates[0], bundle, _resolution(), _coverage()
        )
        self.assertIsInstance(result, ProofResult)
        self.assertEqual("PASS", result.verdict)
        self.assertEqual(
            (EvidenceLevel.D2, EvidencePolarity.SUPPORTS), result.evidence_hint()
        )
        self.assertEqual(
            list(ProofObligation), [item.obligation for item in result.obligations]
        )
        self.assertTrue(
            all(item.verdict == "satisfied" for item in result.obligations)
        )
        self.assertIsNotNone(result.p5_detail)
        self.assertEqual((0, 0), result.p5_detail.witness_cfg_blocks)
        self.assertEqual(
            ("satisfied", "satisfied"),
            (result.p5_detail.structural_reachability, result.p5_detail.path_feasibility),
        )


class RefutationTests(unittest.TestCase):
    def test_rebind_after_release_refutes_p6(self):
        # p = n; between delete p (20) and *p (30): the use pointer was
        # rebound away from the released object -> P6 refuted -> REFUTED.
        extra = (
            _fact(
                UafFactKind.REBIND, 4, line=25, pointer="p", source="n",
                related=(ALLOC,),
            ),
        )
        result = _prove(_straight_facts(extra=extra))
        self.assertEqual("REFUTED", result.verdict)
        self.assertEqual(
            (EvidenceLevel.D2, EvidencePolarity.REFUTES), result.evidence_hint()
        )
        p6 = _verdict(result, ProofObligation.P6)
        self.assertEqual("refuted", p6.verdict)
        self.assertIn(REBIND, p6.fact_ids)
        self.assertIn(USE, p6.fact_ids)

    def test_lifetime_restart_refutes_p7(self):
        extra = (_fact(UafFactKind.LIFETIME_RESTART, 5, line=25),)
        result = _prove(_straight_facts(extra=extra))
        self.assertEqual("REFUTED", result.verdict)
        p7 = _verdict(result, ProofObligation.P7)
        self.assertEqual("refuted", p7.verdict)
        self.assertIn(RESTART, p7.fact_ids)


class ReachabilityFeasibilityTests(unittest.TestCase):
    def test_unreachable_use_refutes_p5_structural(self):
        # (a) The use cfg block precedes the release cfg block on a complete
        # restricted cfg: no non-decreasing block-order path exists.
        facts = _straight_facts(release_block=3, use_block=1)
        result = _prove(facts)
        self.assertEqual("REFUTED", result.verdict)
        p5 = _verdict(result, ProofObligation.P5)
        self.assertEqual("refuted", p5.verdict)
        self.assertEqual("refuted", result.p5_detail.structural_reachability)

        # (b) cfg extraction incomplete with a cfg-goto gap in between:
        # structural reachability is unknown, so P5 and the proof are
        # UNKNOWN -- unknown paths are never selectively ignored.
        result = _prove(
            _straight_facts(release_block=0, use_block=1),
            coverage=_coverage(cfg_complete=False, gaps=("cfg-goto",)),
        )
        self.assertEqual("UNKNOWN", result.verdict)
        p5 = _verdict(result, ProofObligation.P5)
        self.assertEqual("unknown", p5.verdict)
        self.assertEqual("unknown", result.p5_detail.structural_reachability)
        self.assertEqual("unknown", result.p5_detail.path_feasibility)

    def test_clang_constant_unreachable_refutes_feasibility(self):
        # Clang constant evaluation marks the witness edge infeasible: the
        # feasibility sub-result alone refutes P5 (structural stays satisfied).
        result = _prove(
            _straight_facts(release_block=1, use_block=2),
            coverage=_coverage(gaps=("clang-constant-unreachable",)),
        )
        self.assertEqual("REFUTED", result.verdict)
        p5 = _verdict(result, ProofObligation.P5)
        self.assertEqual("refuted", p5.verdict)
        self.assertEqual("satisfied", result.p5_detail.structural_reachability)
        self.assertEqual("refuted", result.p5_detail.path_feasibility)

    def test_single_guard_region_satisfied_when_guard_polarity_shared(self):
        # delete p and *p inside one if body share one cfg block: whitelist
        # (a) straight-line semantics apply, no guard facts needed.
        result = _prove(_straight_facts(alloc_block=0, release_block=2, use_block=2))
        self.assertEqual("PASS", result.verdict)
        p5 = _verdict(result, ProofObligation.P5)
        self.assertEqual("satisfied", p5.verdict)
        self.assertEqual("satisfied", result.p5_detail.structural_reachability)
        self.assertEqual("satisfied", result.p5_detail.path_feasibility)

    def test_predicated_pair_x_gt_10_and_x_le_10_is_unknown(self):
        # if (x > 10) delete p; if (x <= 10) *p;  -- different cfg blocks,
        # no guard facts: structural satisfied, feasibility unknown (the
        # predicate relation must not be heuristically solved), P5 unknown.
        result = _prove(_straight_facts(release_block=1, use_block=2))
        self.assertEqual("UNKNOWN", result.verdict)
        p5 = _verdict(result, ProofObligation.P5)
        self.assertEqual("unknown", p5.verdict)
        self.assertEqual("satisfied", result.p5_detail.structural_reachability)
        self.assertEqual("unknown", result.p5_detail.path_feasibility)
        self.assertTrue(result.p5_detail.unresolved_constraints)

    def test_two_branch_predicates_joint_satisfaction_unknown(self):
        # Two independent branch predicates spanning separate blocks: joint
        # satisfaction would need a solver the first phase forbids.
        result = _prove(_straight_facts(release_block=1, use_block=4))
        self.assertEqual("UNKNOWN", result.verdict)
        p5 = _verdict(result, ProofObligation.P5)
        self.assertEqual("unknown", p5.verdict)
        self.assertEqual("satisfied", result.p5_detail.structural_reachability)
        self.assertEqual("unknown", result.p5_detail.path_feasibility)


class AliasAndReadinessTests(unittest.TestCase):
    def test_alias_unbindable_p2_unknown(self):
        # (a) The use pointer cannot be bound, but the alias graph is
        # incomplete (an alias fact without its source anchor): P2 must be
        # unknown, never refuted on possibly-missing evidence.
        extra = (_fact(UafFactKind.ALIAS_COPY, 8, line=15, pointer="q", source=""),)
        result = _prove(_straight_facts(use_pointer="z", extra=extra))
        self.assertEqual("UNKNOWN", result.verdict)
        p2 = _verdict(result, ProofObligation.P2)
        self.assertEqual("unknown", p2.verdict)
        p6 = _verdict(result, ProofObligation.P6)
        self.assertEqual("unknown", p6.verdict)

        # (b) Same unbindable pointer over a complete graph: P2 refutes.
        result = _prove(_straight_facts(use_pointer="z"))
        self.assertEqual("REFUTED", result.verdict)
        self.assertEqual("refuted", _verdict(result, ProofObligation.P2).verdict)

    def test_macro_template_cross_function_unknown(self):
        # Macro/template gaps are critical coverage gaps: the obligations may
        # look satisfiable, but PASS is forbidden -> UNKNOWN.
        result = _prove(
            _straight_facts(),
            coverage=_coverage(gaps=("macro-expansion", "template-instantiation")),
        )
        self.assertEqual("UNKNOWN", result.verdict)

    def test_coverage_incomplete_forbids_pass_even_when_facts_look_satisfied(self):
        # AST completeness fails while every visible fact satisfies P1-P7:
        # the adjudication still forces UNKNOWN.
        result = _prove(
            _straight_facts(), coverage=_coverage(ast_complete=False)
        )
        self.assertTrue(
            all(item.verdict == "satisfied" for item in result.obligations)
        )
        self.assertEqual("UNKNOWN", result.verdict)

    def test_heuristic_context_forbids_pass(self):
        result = _prove(
            _straight_facts(),
            resolution=_resolution(status="incomplete", source_kind="heuristic"),
        )
        self.assertTrue(
            all(item.verdict == "satisfied" for item in result.obligations)
        )
        self.assertEqual("UNKNOWN", result.verdict)


class ContractTests(unittest.TestCase):
    def test_p5detail_serialized_with_both_subresults(self):
        result = _prove(_straight_facts(release_block=1, use_block=2))
        detail = result.p5_detail
        self.assertIsInstance(detail, P5Detail)
        encoded = asdict(detail)
        self.assertEqual(
            {
                "structural_reachability",
                "path_feasibility",
                "witness_cfg_blocks",
                "guard_facts",
                "unresolved_constraints",
            },
            set(encoded),
        )
        self.assertEqual((1, 2), encoded["witness_cfg_blocks"])
        self.assertEqual("satisfied", encoded["structural_reachability"])
        self.assertEqual("unknown", encoded["path_feasibility"])
        self.assertEqual((), encoded["guard_facts"])
        for value in (encoded["structural_reachability"], encoded["path_feasibility"]):
            self.assertIn(value, OBLIGATION_VERDICTS)

    def test_usr_synthesized_p1_unknown(self):
        facts = _straight_facts(usr="")
        result = _prove(facts, _candidate(usr=""))
        p1 = _verdict(result, ProofObligation.P1)
        self.assertEqual("unknown", p1.verdict)
        self.assertIn(ALLOC, p1.fact_ids)
        self.assertIn("USR", p1.reason)
        self.assertEqual("UNKNOWN", result.verdict)

    def test_refuted_wins_over_incomplete_readiness(self):
        # Design 9.2: any refuted obligation forces REFUTED regardless of
        # readiness, deterministic rejection needs no complete context.
        extra = (
            _fact(UafFactKind.REBIND, 4, line=25, pointer="p", source="n"),
        )
        result = _prove(
            _straight_facts(extra=extra),
            resolution=_resolution(status="incomplete", source_kind="heuristic"),
        )
        self.assertEqual("REFUTED", result.verdict)

    def test_prove_rejects_candidate_with_unknown_fact_ids(self):
        bundle = _bundle(_unit(_straight_facts()))
        with self.assertRaises(ValueError):
            prove_candidate(
                _candidate(release_id=_fid(999)), bundle, _resolution(), _coverage()
            )


class ObligationUnitTests(unittest.TestCase):
    def test_p1_states(self):
        # satisfied: eligible allocation with full identity.
        result = _prove(_straight_facts())
        self.assertEqual("satisfied", _verdict(result, ProofObligation.P1).verdict)
        self.assertEqual((ALLOC,), _verdict(result, ProofObligation.P1).fact_ids)

        # unknown: custom allocator outside the modeled api whitelist.
        custom = [
            _fact(UafFactKind.ALLOCATION, 1, line=10, pointer="p", api="pool_alloc"),
            _fact(
                UafFactKind.RELEASE, 2, line=20, pointer="p", api="pool_free",
                related=(ALLOC,),
            ),
            _fact(UafFactKind.DEREFERENCE, 3, line=30, pointer="p"),
        ]
        result = _prove(custom)
        self.assertEqual("unknown", _verdict(result, ProofObligation.P1).verdict)
        self.assertEqual("UNKNOWN", result.verdict)

        # refuted (defensive corruption): the allocation id resolves to a
        # non-allocation fact, so the concrete object claim is false.
        corrupt = _candidate(alloc_id=RELEASE, release_id=ALLOC)
        result = _prove(
            _straight_facts(), corrupt,
        )
        self.assertEqual("refuted", _verdict(result, ProofObligation.P1).verdict)
        self.assertEqual("REFUTED", result.verdict)

    def test_p2_states(self):
        # satisfied, direct pointer equality.
        result = _prove(_straight_facts())
        self.assertEqual("satisfied", _verdict(result, ProofObligation.P2).verdict)

        # satisfied through a supported alias chain, carrying the edge facts.
        facts = [
            _fact(UafFactKind.ALLOCATION, 1, line=10, pointer="p", api="new"),
            _fact(UafFactKind.ALIAS_COPY, 6, line=12, pointer="q", source="p"),
            _fact(UafFactKind.ALIAS_COPY, 7, line=14, pointer="r", source="q"),
            _fact(
                UafFactKind.RELEASE, 2, line=20, pointer="p", api="delete",
                related=(ALLOC,),
            ),
            _fact(UafFactKind.DEREFERENCE, 3, line=30, pointer="r"),
        ]
        result = _prove(facts)
        p2 = _verdict(result, ProofObligation.P2)
        self.assertEqual("satisfied", p2.verdict)
        self.assertIn(ALIAS_Q, p2.fact_ids)
        self.assertIn(ALIAS_R, p2.fact_ids)

        # refuted: complete graph, use pointer unreachable (covered in
        # test_alias_unbindable_p2_unknown case b), here the unknown branch
        # of a partially broken graph is re-pinned for P2 alone.
        extra = (_fact(UafFactKind.ALIAS_COPY, 8, line=15, pointer="q", source=""),)
        result = _prove(_straight_facts(use_pointer="z", extra=extra))
        self.assertEqual("unknown", _verdict(result, ProofObligation.P2).verdict)

    def test_p3_states(self):
        result = _prove(_straight_facts())
        self.assertEqual("satisfied", _verdict(result, ProofObligation.P3).verdict)
        self.assertEqual((RELEASE,), _verdict(result, ProofObligation.P3).fact_ids)

        # Defensive: a release not related to this allocation never satisfies
        # P3 (the generator cannot emit this; corruption only).
        unattached = [
            _fact(UafFactKind.ALLOCATION, 1, line=10, pointer="p", api="new"),
            _fact(UafFactKind.RELEASE, 2, line=20, pointer="p", api="delete"),
            _fact(UafFactKind.DEREFERENCE, 3, line=30, pointer="p"),
        ]
        result = _prove(unattached)
        self.assertEqual("refuted", _verdict(result, ProofObligation.P3).verdict)
        self.assertEqual("REFUTED", result.verdict)

    def test_p4_states(self):
        result = _prove(_straight_facts())
        self.assertEqual("satisfied", _verdict(result, ProofObligation.P4).verdict)
        self.assertEqual((USE,), _verdict(result, ProofObligation.P4).fact_ids)

        # Defensive: a use not syntactically after the release refutes P4.
        early = [
            _fact(UafFactKind.ALLOCATION, 1, line=10, pointer="p", api="new"),
            _fact(
                UafFactKind.RELEASE, 2, line=20, pointer="p", api="delete",
                related=(ALLOC,),
            ),
            _fact(UafFactKind.DEREFERENCE, 3, line=15, pointer="p"),
        ]
        result = _prove(early, _candidate(use_range=(15, 15)))
        self.assertEqual("refuted", _verdict(result, ProofObligation.P4).verdict)
        self.assertEqual("REFUTED", result.verdict)

    def test_p6_states(self):
        # satisfied: no rebind of the use pointer inside (release, use].
        result = _prove(_straight_facts())
        self.assertEqual("satisfied", _verdict(result, ProofObligation.P6).verdict)

        # satisfied: a rebind back onto the object's binding keeps the UAF.
        keep = (
            _fact(UafFactKind.ALIAS_COPY, 6, line=12, pointer="q", source="p"),
            _fact(UafFactKind.REBIND, 4, line=25, pointer="p", source="q"),
        )
        result = _prove(_straight_facts(extra=keep))
        self.assertEqual("satisfied", _verdict(result, ProofObligation.P6).verdict)

        # satisfied: rebind after the use is off the witness window.
        late = (_fact(UafFactKind.REBIND, 4, line=35, pointer="p", source="n"),)
        result = _prove(_straight_facts(extra=late))
        self.assertEqual("satisfied", _verdict(result, ProofObligation.P6).verdict)

        # refuted: rebind to a fresh source cuts the binding (pinned in
        # test_rebind_after_release_refutes_p6) ...
        cut = (_fact(UafFactKind.REBIND, 4, line=25, pointer="p", source="n"),)
        result = _prove(_straight_facts(extra=cut))
        self.assertEqual("refuted", _verdict(result, ProofObligation.P6).verdict)

        # ... unknown: alias state incomplete, the rebind's cut cannot be
        # certified either way.
        broken = (
            _fact(UafFactKind.ALIAS_COPY, 8, line=12, pointer="q", source=""),
            _fact(UafFactKind.REBIND, 4, line=25, pointer="p", source="n"),
        )
        result = _prove(_straight_facts(extra=broken))
        self.assertEqual("unknown", _verdict(result, ProofObligation.P6).verdict)
        self.assertEqual("UNKNOWN", result.verdict)

    def test_p7_states(self):
        result = _prove(_straight_facts())
        self.assertEqual("satisfied", _verdict(result, ProofObligation.P7).verdict)

        # refuted: a supported lifetime restart inside the witness window.
        result = _prove(
            _straight_facts(extra=(_fact(UafFactKind.LIFETIME_RESTART, 5, line=25),))
        )
        self.assertEqual("refuted", _verdict(result, ProofObligation.P7).verdict)

        # satisfied: restart after the use is off the witness window.
        result = _prove(
            _straight_facts(extra=(_fact(UafFactKind.LIFETIME_RESTART, 5, line=35),))
        )
        self.assertEqual("satisfied", _verdict(result, ProofObligation.P7).verdict)

        # unknown: the lifetime-restart placement gap makes every window
        # uncertain -- unknown paths are never ignored.
        result = _prove(
            _straight_facts(), coverage=_coverage(gaps=("lifetime-restart",))
        )
        self.assertEqual("unknown", _verdict(result, ProofObligation.P7).verdict)
        self.assertEqual("UNKNOWN", result.verdict)


if __name__ == "__main__":
    unittest.main()
