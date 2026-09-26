"""Deterministic P1-P7 Proof Engine for UAF v2 candidates (plan Task 7).

Design sections 9.1/9.2 (``docs/superpowers/specs/2026-09-10-cxx-uaf-v2-design.md``).
:func:`prove_candidate` is a pure function over a certified
:class:`~lima.uaf_facts.UafFactBundle`, the candidate's
:class:`~lima.uaf_models.BuildContextResolution` and
:class:`~lima.uaf_models.ExtractionCoverage`: no LLM, no labels, no I/O.
Each obligation P1-P7 yields ``satisfied | refuted | unknown`` with the
supporting/refuting ``fact_ids``, a structured reason and (for P5) the
witness CFG blocks; the adjudication is the frozen design 9.2 rule:

    any obligation refuted                        -> REFUTED
    all satisfied and ProofReadiness.complete     -> PASS
    otherwise                                     -> UNKNOWN

Red lines implemented here (fail closed):

- Complex branch predicates are never solved: two independent predicates,
  ``x > 10`` / ``x <= 10`` pairs, written/aliased guards and incomplete
  guard provenance are ``unknown`` (design 9.1).  SAT/SMT, symbolic state
  and heuristic condition solving are out of scope for phase 1.
- P6/P7 are decided on the selected witness path only -- the window
  ``(release_line, use_line]`` on the line axis and the
  release-to-use block range on the CFG axis.  One reachable path without
  rebind/restart supports the UAF; safer sibling paths never refute it.
- Coverage that is not complete forbids PASS at the adjudication layer,
  regardless of how satisfied the visible obligations look.  Readiness is
  computed here with ``critical = bool(coverage.semantic_gaps or
  bundle.coverage_gaps)``; every obligation is still evaluated so the LLM
  branch and the audit trail keep maximal information.
- A missing function USR (usr-synthesized extraction) surfaces as P1
  ``unknown``, so it can never reach PASS.

Phase-1 capability boundary (honest downgrades, not omissions):

1. Task 4 emits no ``cfg-node``/``cfg-edge`` facts, so structural
   reachability is a conservative restricted-CFG test over the linearized
   fact blocks -- satisfied only when ``cfg_complete`` holds, no cfg-class
   gap was recorded, and the use block does not precede the release block
   (the supported syntax whitelist makes block order a sound path order);
   ``refuted`` only for the strictly-preceding use block; everything else
   is ``unknown``.  ``witness_cfg_blocks`` carries the release and use
   blocks; real CFG walking is left to a later extractor version.
2. Task 4 emits no guard facts, so of the three ``path_feasibility =
   satisfied`` whitelists only (a) the unconditional same-block
   straight-line path is derivable.  Whitelist (b) (one shared guard
   region, one polarity, no guard redefinition) and (c) (Clang constant
   evaluation proving the edge executable) have no supporting facts and
   therefore stay ``unknown`` -- by design they must, not by omission.
3. ``clang-constant-unreachable`` is not produced by Task 4 yet; the
   ``path_feasibility = refuted`` branch is defensive and exercised via
   injected coverage gaps until the extractor grows the evidence.
4. ``lifetime-restart`` facts are accepted but the extractor currently
   records the ``lifetime-restart`` gap instead; the gap forces P7
   ``unknown`` because restart placement cannot be certified.
"""

from __future__ import annotations

from typing import Final

from .uaf_candidates import AliasGraph, alias_binding_facts, build_alias_graph
from .uaf_facts import UafFactBundle, UnitFacts
from .uaf_models import (
    BuildContextResolution,
    ExtractionCoverage,
    ObligationVerdict,
    P5Detail,
    ProofObligation,
    ProofReadiness,
    ProofResult,
    UafCandidate,
    UafFact,
    UafFactKind,
    proof_readiness,
)

__all__ = ["prove_candidate"]

_SATISFIED: Final = "satisfied"
_REFUTED: Final = "refuted"
_UNKNOWN: Final = "unknown"

# Allocation kinds with modeled create semantics (Task 4 whitelist plus new).
_ALLOCATION_APIS: Final = frozenset({"new", "malloc", "calloc", "realloc"})
_USE_KINDS: Final = frozenset({UafFactKind.DEREFERENCE, UafFactKind.MEMBER_ACCESS})
# Mirror of the frozen Task 4 cfg gap vocabulary (cxx_analyzer.uaf_scan
# CFG_GAP_NAMES).  Kept local on purpose: the main process never imports
# the sidecar analyzer package, and the vocabulary is frozen by design.
_CFG_GAPS: Final = frozenset(
    {
        "cfg-loop",
        "cfg-switch",
        "cfg-goto",
        "cfg-exception",
        "short-circuit-side-effect",
        "destructor-control-flow",
        "lambda-body",
        "coroutine",
        "indirect-call",
        "template-instantiation",
        "macro-expansion",
        "cfg-unsupported",
    }
)
_GAP_CONSTANT_UNREACHABLE: Final = "clang-constant-unreachable"
_GAP_LIFETIME_RESTART: Final = "lifetime-restart"


def _verdict(
    obligation: ProofObligation,
    state: str,
    fact_ids: tuple[str, ...],
    reason: str,
    witness_cfg_blocks: tuple[int, ...] = (),
) -> ObligationVerdict:
    return ObligationVerdict(
        obligation=obligation,
        verdict=state,
        fact_ids=fact_ids,
        reason=reason,
        witness_cfg_blocks=witness_cfg_blocks,
    )


def _dedup(fact_ids: tuple[str, ...]) -> tuple[str, ...]:
    ordered: list[str] = []
    seen: set[str] = set()
    for fact_id in fact_ids:
        if fact_id not in seen:
            seen.add(fact_id)
            ordered.append(fact_id)
    return tuple(ordered)


def _cfg_gap_covered(coverage: ExtractionCoverage) -> bool:
    """Whether any recorded gap breaks the restricted-CFG whitelist."""

    return any(gap in _CFG_GAPS for gap in coverage.semantic_gaps)


def _p1_concrete_object(allocation: UafFact) -> ObligationVerdict:
    """P1: a supported allocation with complete identity exists."""

    if allocation.kind is not UafFactKind.ALLOCATION:
        return _verdict(
            ProofObligation.P1,
            _REFUTED,
            (),
            "the referenced allocation fact id does not resolve to an allocation fact",
        )
    if not allocation.api:
        return _verdict(
            ProofObligation.P1,
            _UNKNOWN,
            (allocation.fact_id,),
            "allocation fact records no allocation kind: object creation is unsupported",
        )
    if allocation.api not in _ALLOCATION_APIS:
        return _verdict(
            ProofObligation.P1,
            _UNKNOWN,
            (allocation.fact_id,),
            f"custom allocator {allocation.api!r} is outside the modeled allocation apis",
        )
    if not allocation.pointer_id:
        return _verdict(
            ProofObligation.P1,
            _UNKNOWN,
            (allocation.fact_id,),
            "allocation fact lacks its pointer anchor: the object identity is incomplete",
        )
    if not allocation.function_usr:
        return _verdict(
            ProofObligation.P1,
            _UNKNOWN,
            (allocation.fact_id,),
            "function USR is missing (usr-synthesized): object identity cannot be "
            "certified and PASS is forbidden",
        )
    return _verdict(
        ProofObligation.P1,
        _SATISFIED,
        (allocation.fact_id,),
        f"supported {allocation.api} allocation with complete identity",
    )


def _alias_binding(
    allocation: UafFact,
    graph: AliasGraph,
    pointer_id: str,
    line: int,
) -> tuple[str, ...] | None:
    """Alias-edge fact ids binding ``pointer_id`` to the object, else states.

    ``()`` for direct equality, a fact-id tuple for a supported chain and
    ``None`` when the graph does not bind the pointer.
    """

    return alias_binding_facts(allocation.pointer_id, pointer_id, graph, line)


def _p2_pointer_binds_object(
    allocation: UafFact,
    release: UafFact,
    use: UafFact,
    graph: AliasGraph,
) -> ObligationVerdict:
    """P2: the release and use pointers bind the object over supported alias."""

    release_binding = _alias_binding(
        allocation, graph, release.pointer_id, release.source_range[0]
    )
    use_binding = _alias_binding(
        allocation, graph, use.pointer_id, use.source_range[0]
    )
    if release_binding is not None and use_binding is not None:
        return _verdict(
            ProofObligation.P2,
            _SATISFIED,
            _dedup((release.fact_id, use.fact_id, *release_binding, *use_binding)),
            "release and use pointers equal or alias-reach the allocation pointer",
        )
    if graph.complete:
        return _verdict(
            ProofObligation.P2,
            _REFUTED,
            (),
            "a release/use pointer neither equals nor alias-reaches the allocation "
            "pointer over the complete alias graph",
        )
    return _verdict(
        ProofObligation.P2,
        _UNKNOWN,
        (),
        "alias state is incomplete (alias facts without source/target anchors): "
        "unreachability cannot be proven",
    )


def _p3_object_released(
    allocation: UafFact, release: UafFact
) -> ObligationVerdict:
    """P3: a release matching this object exists on the witness path."""

    if release.kind is not UafFactKind.RELEASE:
        return _verdict(
            ProofObligation.P3,
            _REFUTED,
            (),
            "the referenced release fact id does not resolve to a release fact",
        )
    if allocation.fact_id not in release.related_fact_ids:
        return _verdict(
            ProofObligation.P3,
            _REFUTED,
            (),
            "the release fact does not reference this allocation: the object is "
            "not released by it",
        )
    return _verdict(
        ProofObligation.P3,
        _SATISFIED,
        (release.fact_id,),
        f"release via {release.api or 'recognized release'} references the allocation",
    )


def _p4_post_release_use(
    release: UafFact, use: UafFact
) -> ObligationVerdict:
    """P4: a supported use of the object exists after the release."""

    if use.kind not in _USE_KINDS:
        return _verdict(
            ProofObligation.P4,
            _REFUTED,
            (),
            "the referenced use fact id does not resolve to a dereference or "
            "member-access fact",
        )
    if not use.source_range > release.source_range:
        return _verdict(
            ProofObligation.P4,
            _REFUTED,
            (),
            "the use is not syntactically after the release",
        )
    return _verdict(
        ProofObligation.P4,
        _SATISFIED,
        (use.fact_id,),
        "supported dereference/member access syntactically after the release",
    )


def _structural_reachability(
    coverage: ExtractionCoverage, release_block: int, use_block: int
) -> tuple[str, str]:
    """Phase-1 structural reachability over the linearized fact blocks."""

    if not coverage.cfg_complete:
        return (
            _UNKNOWN,
            "cfg extraction incomplete: structural reachability is uncertifiable",
        )
    if _cfg_gap_covered(coverage):
        return (
            _UNKNOWN,
            "restricted cfg violated by recorded cfg gap(s): block order does not "
            "certify a release-to-use path",
        )
    if use_block < release_block:
        return (
            _REFUTED,
            "use cfg block precedes release cfg block: the restricted cfg admits "
            "no non-decreasing block-order path from the release",
        )
    return (
        _SATISFIED,
        "restricted cfg: the use follows the release in non-decreasing block order",
    )


def _path_feasibility(
    coverage: ExtractionCoverage, release_block: int, use_block: int
) -> tuple[str, str]:
    """Phase-1 feasibility whitelists; every non-whitelisted shape is unknown."""

    if _GAP_CONSTANT_UNREACHABLE in coverage.semantic_gaps:
        return (
            _REFUTED,
            "clang constant evaluation marks the witness edge constant-unreachable",
        )
    if coverage.cfg_complete and not _cfg_gap_covered(coverage):
        if release_block == use_block:
            return (
                _SATISFIED,
                "straight-line witness: release and use share one cfg block with no "
                "conditional edge between them",
            )
        return (
            _UNKNOWN,
            "release and use sit in different cfg blocks and no guard facts exist: "
            "shared guard polarity, guard redefinition freedom and joint "
            "branch-predicate satisfiability cannot be proven",
        )
    return (
        _UNKNOWN,
        "restricted cfg coverage is incomplete over the witness region: path "
        "feasibility is uncertifiable",
    )


def _p5_path(
    coverage: ExtractionCoverage, release: UafFact, use: UafFact
) -> tuple[ObligationVerdict, P5Detail]:
    """P5 with the two explicit sub-results (design 9.1 mapping)."""

    release_block = release.cfg_block
    use_block = use.cfg_block
    structural_state, structural_reason = _structural_reachability(
        coverage, release_block, use_block
    )
    feasibility_state, feasibility_reason = _path_feasibility(
        coverage, release_block, use_block
    )
    if structural_state == _REFUTED or feasibility_state == _REFUTED:
        p5_state = _REFUTED
    elif structural_state == _SATISFIED and feasibility_state == _SATISFIED:
        p5_state = _SATISFIED
    else:
        p5_state = _UNKNOWN
    unresolved: list[str] = []
    if structural_state != _SATISFIED:
        unresolved.append(structural_reason)
    if feasibility_state != _SATISFIED:
        unresolved.append(feasibility_reason)
    witness = (release_block, use_block)
    detail = P5Detail(
        structural_reachability=structural_state,
        path_feasibility=feasibility_state,
        witness_cfg_blocks=witness,
        # Task 4 emits no guard facts yet; the slot is kept for the
        # extractor's future guard evidence instead of dropping the field.
        guard_facts=(),
        unresolved_constraints=tuple(unresolved),
    )
    return (
        _verdict(
            ProofObligation.P5,
            p5_state,
            (),
            f"structural reachability {structural_state}; path feasibility "
            f"{feasibility_state}",
            witness_cfg_blocks=witness,
        ),
        detail,
    )


def _p6_no_rebind(
    candidate: UafCandidate,
    unit: UnitFacts,
    allocation: UafFact,
    graph: AliasGraph,
    use: UafFact,
    release_line: int,
    use_line: int,
) -> ObligationVerdict:
    """P6: the use pointer is not rebound away on the witness path."""

    if not graph.complete:
        return _verdict(
            ProofObligation.P6,
            _UNKNOWN,
            (),
            "alias state is incomplete: the witness binding cannot be certified "
            "rebind-free",
        )
    for fact in unit.facts:
        if (
            fact.kind is not UafFactKind.REBIND
            or fact.function_usr != candidate.function_usr
            or fact.pointer_id != use.pointer_id
            or not release_line < fact.source_range[0] <= use_line
        ):
            continue
        # Value semantics: only a rebind whose new source no longer binds
        # the released object cuts the witness binding.  Rebinding the use
        # pointer back onto the object's alias set keeps the UAF alive.
        if (
            _alias_binding(allocation, graph, fact.source_pointer_id, fact.source_range[0])
            is None
        ):
            return _verdict(
                ProofObligation.P6,
                _REFUTED,
                (fact.fact_id, use.fact_id),
                "the use pointer is rebound on the witness path to a source that "
                "does not bind the released object",
            )
    return _verdict(
        ProofObligation.P6,
        _SATISFIED,
        (use.fact_id,),
        "no rebind of the use pointer away from the object inside the witness window",
    )


def _p7_no_lifetime_restart(
    candidate: UafCandidate,
    unit: UnitFacts,
    coverage: ExtractionCoverage,
    use: UafFact,
    release_line: int,
    use_line: int,
) -> ObligationVerdict:
    """P7: no supported lifetime restart on the witness path before the use."""

    if _GAP_LIFETIME_RESTART in coverage.semantic_gaps:
        return _verdict(
            ProofObligation.P7,
            _UNKNOWN,
            (),
            "lifetime-restart placement detection is uncertain (coverage gap): "
            "restart freedom on the witness path cannot be certified",
        )
    restarts = tuple(
        fact.fact_id
        for fact in unit.facts
        if fact.kind is UafFactKind.LIFETIME_RESTART
        and fact.function_usr == candidate.function_usr
        and release_line < fact.source_range[0] <= use_line
    )
    if restarts:
        return _verdict(
            ProofObligation.P7,
            _REFUTED,
            (*restarts, use.fact_id),
            "a supported lifetime restart of the storage occurs between the "
            "release and the use",
        )
    return _verdict(
        ProofObligation.P7,
        _SATISFIED,
        (use.fact_id,),
        "no lifetime restart inside the witness window",
    )


def prove_candidate(
    candidate: UafCandidate,
    bundle: UafFactBundle,
    resolution: BuildContextResolution,
    coverage: ExtractionCoverage,
) -> ProofResult:
    """Prove one UAF candidate against P1-P7 over the certified facts.

    Pure and deterministic.  Every obligation is evaluated even when the
    completeness trio forbids ``fact-verified`` -- unknown readiness only
    removes PASS from the adjudication, never the per-obligation audit
    record the LLM branch and reports consume.
    """

    if not isinstance(candidate, UafCandidate):
        raise ValueError("candidate must be a UafCandidate")
    if not isinstance(bundle, UafFactBundle):
        raise ValueError("bundle must be a UafFactBundle")
    if not isinstance(resolution, BuildContextResolution):
        raise ValueError("resolution must be a BuildContextResolution")
    if not isinstance(coverage, ExtractionCoverage):
        raise ValueError("coverage must be an ExtractionCoverage")

    index = {fact.fact_id: fact for fact in bundle.facts}
    try:
        allocation = index[candidate.allocation_fact_id]
        release = index[candidate.release_fact_id]
        use = index[candidate.use_fact_id]
    except KeyError as exc:
        raise ValueError(
            f"candidate references a fact id absent from the bundle: {exc}"
        ) from exc
    unit = next(
        (
            entry
            for entry in bundle.per_unit
            if entry.translation_unit == allocation.translation_unit
        ),
        None,
    )
    if unit is None:
        raise ValueError(
            f"no bundle unit carries the candidate translation unit "
            f"{allocation.translation_unit!r}"
        )

    graph = build_alias_graph(unit.facts, candidate.function_usr)
    release_line = candidate.release_range[0]
    use_line = candidate.use_range[0]

    p5, p5_detail = _p5_path(coverage, release, use)
    obligations = (
        _p1_concrete_object(allocation),
        _p2_pointer_binds_object(allocation, release, use, graph),
        _p3_object_released(allocation, release),
        _p4_post_release_use(release, use),
        p5,
        _p6_no_rebind(
            candidate, unit, allocation, graph, use, release_line, use_line
        ),
        _p7_no_lifetime_restart(
            candidate, unit, coverage, use, release_line, use_line
        ),
    )

    # Any TU-level coverage gap is critical: a partial extraction must never
    # reach fact-verified, whatever the visible facts look like.
    readiness: ProofReadiness = proof_readiness(
        resolution,
        coverage,
        critical=bool(coverage.semantic_gaps or bundle.coverage_gaps),
    )
    if any(item.verdict == _REFUTED for item in obligations):
        verdict = "REFUTED"
    elif all(item.verdict == _SATISFIED for item in obligations) and readiness.complete:
        verdict = "PASS"
    else:
        verdict = "UNKNOWN"
    return ProofResult(verdict=verdict, obligations=obligations, p5_detail=p5_detail)
