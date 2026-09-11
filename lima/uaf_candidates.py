"""Deterministic Candidate Generator for the UAF v2 review pipeline.

Plan Task 6 (design section 8).  This module is a pure function layer over
a certified :class:`~lima.uaf_facts.UafFactBundle`: no LLM call, no
evaluation labels, no CVE descriptions, no fix diffs, no tool findings,
no I/O.  It only combines supported facts about the same object into the
release/use pairs awaiting proof:

    allocation/object + reachable release + syntactically later use
    -> UafCandidate

Frozen phase-1 semantics:

- Grouping is per translation unit.  A release is attributed to an
  allocation exclusively through its ``related_fact_ids`` resolving to an
  eligible allocation of the same unit.  A release without such a
  reference is reported as unattached by :func:`generation_stats` and is
  never guessed onto an object by pointer name, position or path.
- Eligible allocations carry a non-empty api (allocation kind), function
  USR and pointer anchor: all three feed the section 7.1 identity tuple or
  the use-attribution walk, and a missing one must surface as the
  extractor's coverage gap instead of a fabricated candidate.
- Alias reachability is built per (translation unit, function USR) from
  ``alias-copy``/``points-to``/``rebind`` facts (edge
  ``source_pointer_id -> pointer_id``, edge line = fact range start).  A
  use reaches an object when its pointer equals the allocation's pointer
  or connects to it over edges whose assignment line does not follow the
  use line (an assignment after the use cannot have aliased yet).  The
  graph construction is public (:func:`build_alias_graph`,
  :func:`alias_reaches`, :func:`alias_binding_facts`) so the Proof Engine
  consumes the identical edges instead of rebuilding its own.  The
  generator applies no rebind filtering: chain cutting is Proof
  obligation P6's decision, this stage only widens recall.
- "Syntactically later" is the lexicographic source-range comparison
  ``use_range > release_range``; an equal position never pairs.  This
  ordering only widens candidate recall -- path reachability, rebind,
  lifetime restart and alias validity are Proof Engine decisions.
- The returned tuple is ordered by the deterministic key
  ``(canonical_path, object_id, release_fact_id, use_fact_id)`` with
  ``allocation_fact_id`` as the final tiebreaker, so the output is
  independent of the bundle's fact input order.

Models and external tools may only reference the ``candidate_id`` values
generated here; anything else is rejected downstream (design section 8).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .uaf_facts import UafFactBundle
from .uaf_models import (
    UAF_SCHEMA_VERSION,
    UafCandidate,
    UafFact,
    UafFactKind,
    derive_candidate_id,
    derive_object_id,
)

__all__ = [
    "AliasGraph",
    "CandidateGenerationStats",
    "alias_binding_facts",
    "alias_reaches",
    "build_alias_graph",
    "generate_candidates",
    "generation_stats",
]

_USE_KINDS: Final = frozenset({UafFactKind.DEREFERENCE, UafFactKind.MEMBER_ACCESS})
_ALIAS_KINDS: Final = frozenset(
    {UafFactKind.ALIAS_COPY, UafFactKind.POINTS_TO, UafFactKind.REBIND}
)


@dataclass(frozen=True)
class CandidateGenerationStats:
    """Diagnostic counts of one candidate generation pass.

    ``unattached_release_count`` is the exact "better none than guessed"
    diagnostic: every release fact that no eligible same-TU allocation
    claims via ``related_fact_ids``.  These releases produce no candidate;
    the missing attribution must surface as an upstream coverage gap.
    """

    tu_count: int
    allocation_count: int
    pair_count: int
    unattached_release_count: int


def _eligible_allocations(facts: tuple[UafFact, ...]) -> tuple[UafFact, ...]:
    """Allocations that can anchor an object identity and its uses."""

    return tuple(
        fact
        for fact in facts
        if fact.kind is UafFactKind.ALLOCATION
        and bool(fact.api)
        and bool(fact.function_usr)
        and bool(fact.pointer_id)
    )


@dataclass(frozen=True)
class AliasGraph:
    """The alias graph of one (translation unit, function USR) scope.

    ``edges`` are ``(source_pointer_id, pointer_id, line, fact_id)``
    quads -- one per ``alias-copy``/``points-to``/``rebind`` fact with both
    pointer anchors, edge line = fact range start.  ``rebind`` facts build
    edges like any other alias assignment here: recall widening leaves
    rebind refutation to Proof obligation P6.

    ``complete`` is false when any alias-kind fact in the scope cannot
    yield an edge (missing ``source_pointer_id`` or ``pointer_id``):
    reachability may then silently miss a binding, so a *refuted*
    conclusion may only be drawn on a complete graph.  Consumers that only
    widen recall (the generator) ignore the flag.
    """

    function_usr: str
    edges: tuple[tuple[str, str, int, str], ...]
    complete: bool


def build_alias_graph(facts: tuple[UafFact, ...], function_usr: str) -> AliasGraph:
    """Build the public alias graph for one (TU, function) scope.

    Pure and deterministic; edges are emitted in input fact order.  This is
    the single graph definition shared by the Candidate Generator (recall)
    and the Proof Engine (P2/P6), so both never drift apart.
    """

    edges: list[tuple[str, str, int, str]] = []
    complete = True
    for fact in facts:
        if fact.kind not in _ALIAS_KINDS:
            continue
        if not fact.source_pointer_id or not fact.pointer_id:
            complete = False
            continue
        if fact.function_usr != function_usr:
            continue
        edges.append(
            (fact.source_pointer_id, fact.pointer_id, fact.source_range[0], fact.fact_id)
        )
    return AliasGraph(function_usr=function_usr, edges=tuple(edges), complete=complete)


def alias_binding_facts(
    root: str, target: str, graph: AliasGraph, use_line: int
) -> tuple[str, ...] | None:
    """Fact ids of one alias path binding ``target`` to ``root``.

    Returns ``()`` when ``target`` is ``root`` itself, the ``fact_id`` tuple
    of one connecting path when reachable over edges whose assignment line
    does not follow ``use_line`` (an assignment after the use cannot have
    aliased yet), and ``None`` when unreachable over this graph.  The graph
    is consumed in either traversal direction: only the per-edge line
    budget carries the flow-ordering semantics.
    """

    if root == target:
        return ()
    parents: dict[str, tuple[str, str] | None] = {root: None}
    frontier = [root]
    while frontier:
        current = frontier.pop()
        for source, destination, line, fact_id in graph.edges:
            if source != current or line > use_line or destination in parents:
                continue
            parents[destination] = (current, fact_id)
            if destination == target:
                path: list[str] = []
                cursor = destination
                while parents[cursor] is not None:
                    previous, edge_fact_id = parents[cursor]
                    path.append(edge_fact_id)
                    cursor = previous
                return tuple(reversed(path))
            frontier.append(destination)
    return None


def alias_reaches(root: str, target: str, graph: AliasGraph, use_line: int) -> bool:
    """Whether ``target`` connects to ``root`` over edges not after ``use_line``."""

    return alias_binding_facts(root, target, graph, use_line) is not None


def generate_candidates(bundle: UafFactBundle) -> tuple[UafCandidate, ...]:
    """Pair same-object reachable releases with syntactically later uses.

    Pure and deterministic: same bundle in, identical ordered candidate
    tuple out.  Units with no eligible allocation, releases without a
    related same-TU allocation and uses that neither equal nor alias-reach
    the allocation pointer simply yield nothing -- they never guess.
    """

    if not isinstance(bundle, UafFactBundle):
        raise ValueError("bundle must be a UafFactBundle")
    candidates: list[UafCandidate] = []
    for unit in bundle.per_unit:
        allocations = _eligible_allocations(unit.facts)
        if not allocations:
            continue
        uses = tuple(fact for fact in unit.facts if fact.kind in _USE_KINDS)
        for allocation in allocations:
            graph = build_alias_graph(unit.facts, allocation.function_usr)
            object_id = derive_object_id(
                UAF_SCHEMA_VERSION,
                allocation.canonical_path,
                allocation.function_usr,
                allocation.source_range[0],
                allocation.source_range[1],
                allocation.api,
            )
            for release in unit.facts:
                if release.kind is not UafFactKind.RELEASE:
                    continue
                if allocation.fact_id not in release.related_fact_ids:
                    continue
                for use in uses:
                    if use.function_usr != allocation.function_usr:
                        continue
                    if use.source_range <= release.source_range:
                        continue
                    if use.pointer_id != allocation.pointer_id and not alias_reaches(
                        allocation.pointer_id, use.pointer_id, graph, use.source_range[0]
                    ):
                        continue
                    candidates.append(
                        UafCandidate(
                            candidate_id=derive_candidate_id(
                                UAF_SCHEMA_VERSION, object_id, release.fact_id, use.fact_id
                            ),
                            object_id=object_id,
                            allocation_fact_id=allocation.fact_id,
                            release_fact_id=release.fact_id,
                            use_fact_id=use.fact_id,
                            canonical_path=allocation.canonical_path,
                            function_usr=allocation.function_usr,
                            release_range=release.source_range,
                            use_range=use.source_range,
                        )
                    )
    candidates.sort(
        key=lambda candidate: (
            candidate.canonical_path,
            candidate.object_id,
            candidate.release_fact_id,
            candidate.use_fact_id,
            candidate.allocation_fact_id,
        )
    )
    return tuple(candidates)


def generation_stats(
    candidates: tuple[UafCandidate, ...], bundle: UafFactBundle
) -> CandidateGenerationStats:
    """Recompute the deterministic diagnostic counters of a generation pass.

    ``pair_count`` is the length of the caller's candidate tuple; the other
    counters are recomputed from the bundle with the same eligibility and
    per-unit attribution rules :func:`generate_candidates` applies.
    """

    if not isinstance(bundle, UafFactBundle):
        raise ValueError("bundle must be a UafFactBundle")
    if not isinstance(candidates, tuple) or any(
        not isinstance(candidate, UafCandidate) for candidate in candidates
    ):
        raise ValueError("candidates must be a tuple of UafCandidate records")
    unattached = 0
    for unit in bundle.per_unit:
        attached = {fact.fact_id for fact in _eligible_allocations(unit.facts)}
        for fact in unit.facts:
            if fact.kind is UafFactKind.RELEASE and not attached.intersection(
                fact.related_fact_ids
            ):
                unattached += 1
    return CandidateGenerationStats(
        tu_count=len(bundle.per_unit),
        allocation_count=sum(1 for fact in bundle.facts if fact.kind is UafFactKind.ALLOCATION),
        pair_count=len(candidates),
        unattached_release_count=unattached,
    )
