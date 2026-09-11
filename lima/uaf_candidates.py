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
    "CandidateGenerationStats",
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


def _alias_edges(
    facts: tuple[UafFact, ...], function_usr: str
) -> tuple[tuple[str, str, int], ...]:
    """Alias edges ``(source, target, line)`` inside one (TU, function) scope.

    ``rebind`` facts build edges like any other alias assignment here: the
    generator widens recall and leaves rebind refutation to P6.
    """

    return tuple(
        (fact.source_pointer_id, fact.pointer_id, fact.source_range[0])
        for fact in facts
        if fact.kind in _ALIAS_KINDS
        and fact.function_usr == function_usr
        and bool(fact.source_pointer_id)
        and bool(fact.pointer_id)
    )


def _reaches(
    root: str, target: str, edges: tuple[tuple[str, str, int], ...], use_line: int
) -> bool:
    """Whether ``target`` connects to ``root`` over edges not after ``use_line``.

    An alias assignment at a line after the use cannot have taken effect
    yet, so only edges with ``line <= use_line`` participate.
    """

    seen = {root}
    frontier = [root]
    while frontier:
        current = frontier.pop()
        for source, destination, line in edges:
            if source == current and line <= use_line and destination not in seen:
                seen.add(destination)
                frontier.append(destination)
    return target in seen


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
            edges = _alias_edges(unit.facts, allocation.function_usr)
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
                    if use.pointer_id != allocation.pointer_id and not _reaches(
                        allocation.pointer_id, use.pointer_id, edges, use.source_range[0]
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
