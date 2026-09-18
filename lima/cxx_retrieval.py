"""Label-free candidate retrieval over the bounded C/C++ context index.

This module ranks bounded review candidates for the C/C++ memory-safety
agent pipeline from a :class:`~lima.cxx_context.CxxContextIndex`.

Label red line: candidates come only from source structure and generic
risk invariants -- allocation/release events (including ``new``/``delete``
recorded by the index), buffer/length API usage, call adjacency, and in
pull-request mode containment of changed lines plus adjacency to the
symbols that contain them. The index carries no
case IDs, CVE descriptions, vulnerable/fixed labels, or ground-truth
paths, and this module never accepts or derives any. Symbol and file
names never contribute to scores; they are used only to resolve call
edges and as a plain lexicographic tie-break.

Determinism: scores are fixed integer sums of the module-level constants
below, and the ranking key ``(-score, path, line, symbol, seed_reason)``
is a total order over candidates, so no dict or set iteration order can
influence the output. Calling a retrieval function twice with equal
inputs returns fully equal runs.

Budget semantics: every retrieval is a single selection pass. The ranked
candidate list is truncated to ``max_candidates`` and the overflow is
reported as ``uncovered_candidates``. Context files are then allocated in
candidate rank order: a file's allocated lines are its merged candidate
symbol spans capped by the remaining ``max_context_lines`` and at most
``max_context_files`` files receive a slot. Files holding selected
candidates that receive no slot are reported as ``uncovered_files``.
No mutable state is shared between calls.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath

from .cxx_context import CxxContextIndex, SymbolRecord

SEED_PR_CHANGED = "pr-changed-symbol"
SEED_ALLOCATION = "allocation-event"
SEED_RELEASE = "release-event"
SEED_LENGTH_API = "length-api"
SEED_CALL_NEIGHBORHOOD = "call-neighborhood"

SEED_REASONS = frozenset(
    {
        SEED_PR_CHANGED,
        SEED_ALLOCATION,
        SEED_RELEASE,
        SEED_LENGTH_API,
        SEED_CALL_NEIGHBORHOOD,
    }
)

# The seed reported for a candidate is its most specific contributing
# seed, ordered from pull-request distance over lifecycle events down to
# plain call adjacency.
_SEED_PRIORITY = (
    SEED_PR_CHANGED,
    SEED_ALLOCATION,
    SEED_RELEASE,
    SEED_LENGTH_API,
    SEED_CALL_NEIGHBORHOOD,
)

# Fixed additive scores. Only structural evidence earns points; identifier
# names, file names, comments, and any label-like metadata never do.
SCORE_LENGTH_API = 2
SCORE_ALLOCATION = 3
SCORE_RELEASE = 3
SCORE_CALL_NEIGHBORHOOD = 1
SCORE_PR_CHANGED = 5
SCORE_PR_NEIGHBOR = 2

# A candidate location: (path, symbol start line, qualified symbol name).
_Location = tuple[str, int, str]

_EVENT_SEEDS = {
    "allocate": (SEED_ALLOCATION, SCORE_ALLOCATION),
    "release": (SEED_RELEASE, SCORE_RELEASE),
}


@dataclass(frozen=True)
class RetrievalBudget:
    """Task-level retrieval limits shared by both retrieval modes."""

    max_candidates: int = 100
    max_context_files: int = 12
    max_context_lines: int = 1200

    def __post_init__(self) -> None:
        for name in ("max_candidates", "max_context_files", "max_context_lines"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer, got {value!r}")


@dataclass(frozen=True)
class RetrievalCandidate:
    """One ranked review anchor. Never carries CVE, label, or truth data."""

    path: str
    line: int
    symbol: str
    seed_reason: str
    score: int


@dataclass(frozen=True)
class RetrievalContextFile:
    """A file granted reading budget and the line count allocated to it."""

    path: str
    allocated_lines: int


@dataclass(frozen=True)
class RetrievalRun:
    """Deterministic retrieval outcome plus budget accounting."""

    candidates: tuple[RetrievalCandidate, ...]
    context_files: tuple[RetrievalContextFile, ...]
    context_lines: int
    uncovered_candidates: int
    uncovered_files: int
    snapshot_sha256: str
    unassigned_changed_lines: int = 0


def retrieve_repository(
    index: CxxContextIndex, budget: RetrievalBudget
) -> RetrievalRun:
    """Rank label-free whole-repository candidates under the budget."""
    accumulator, spans = _collect_repository_entries(index)
    return _build_run(index, accumulator, spans, budget)


def retrieve_pull_request(
    index: CxxContextIndex,
    changed_lines: Mapping[str, Sequence[int]],
    budget: RetrievalBudget,
) -> RetrievalRun:
    """Rank pull-request candidates under the budget.

    The repository-wide generic risk pass always runs; pull-request
    containment and adjacency only add score. Changed lines that fall
    inside no indexed symbol are counted in ``unassigned_changed_lines``
    instead of being guessed into a symbol. An empty effective change set
    -- an empty mapping, or every path mapping to an empty line list --
    yields an empty run, including the generic risk pass.
    """
    validated = _validate_changed_lines(changed_lines)
    if not validated:
        return _empty_run(index)
    accumulator, spans = _collect_repository_entries(index)
    unassigned = _add_pull_request_entries(index, validated, accumulator, spans)
    return _build_run(index, accumulator, spans, budget, unassigned)


class _CandidateAccumulator:
    """Aggregates additive seed scores per candidate location."""

    def __init__(self) -> None:
        self._seeds: dict[_Location, dict[str, int]] = {}

    def add(self, path: str, line: int, symbol: str, seed: str, score: int) -> None:
        seeds = self._seeds.setdefault((path, line, symbol), {})
        seeds[seed] = seeds.get(seed, 0) + score

    def ranked(self) -> list[RetrievalCandidate]:
        candidates = [
            RetrievalCandidate(
                path=path,
                line=line,
                symbol=symbol,
                seed_reason=next(
                    seed for seed in _SEED_PRIORITY if seed in contributions
                ),
                score=sum(contributions.values()),
            )
            for (path, line, symbol), contributions in self._seeds.items()
        ]
        candidates.sort(
            key=lambda item: (
                -item.score,
                item.path,
                item.line,
                item.symbol,
                item.seed_reason,
            )
        )
        return candidates


def _symbol_lookups(
    index: CxxContextIndex,
) -> tuple[dict[tuple[str, str], SymbolRecord], dict[str, list[SymbolRecord]]]:
    by_location: dict[tuple[str, str], SymbolRecord] = {}
    by_name: dict[str, list[SymbolRecord]] = {}
    for record in index.symbols:
        by_location[(record.file, record.qualified_name)] = record
        by_name.setdefault(record.qualified_name, []).append(record)
    return by_location, by_name


def _matching_callee_symbols(
    by_name: dict[str, list[SymbolRecord]], written: str
) -> list[SymbolRecord]:
    """Resolve a callee written as-is, keeping the index's conservative loss.

    Call edges record the callee exactly as written and the index layer
    never invents points-to facts, so this resolver over-approximates: an
    unqualified callee matches every symbol with that exact qualified name
    or that ``::`` suffix (``read`` also matches ``Session::read``). Every
    match receives the same adjacency score, so ambiguity only contributes
    bounded +/-1 or +/-2 noise to candidates; it never drops, reweights,
    or reorders candidates by name beyond the documented tie-break.
    """
    matched = list(by_name.get(written, ()))
    suffix = "::" + written
    for name, records in by_name.items():
        if name != written and name.endswith(suffix):
            matched.extend(records)
    return matched


def _name_matches(qualified_name: str, written: str) -> bool:
    return qualified_name == written or qualified_name.endswith("::" + written)


def _add_symbol_candidate(
    accumulator: _CandidateAccumulator,
    spans: dict[_Location, int],
    record: SymbolRecord,
    seed: str,
    score: int,
) -> None:
    location = (record.file, record.start_line, record.qualified_name)
    accumulator.add(record.file, record.start_line, record.qualified_name, seed, score)
    spans[location] = record.end_line


def _collect_repository_entries(
    index: CxxContextIndex,
) -> tuple[_CandidateAccumulator, dict[_Location, int]]:
    accumulator = _CandidateAccumulator()
    spans: dict[_Location, int] = {}
    by_location, by_name = _symbol_lookups(index)
    event_functions = {event.function for event in index.resource_events}

    for event in index.resource_events:
        seed_score = _EVENT_SEEDS.get(event.event)
        record = by_location.get((event.file, event.function))
        if seed_score is None or record is None:
            continue
        seed, score = seed_score
        _add_symbol_candidate(accumulator, spans, record, seed, score)

    for reference in index.references:
        record = by_location.get((reference.file, reference.function))
        if record is not None:
            _add_symbol_candidate(
                accumulator, spans, record, SEED_LENGTH_API, SCORE_LENGTH_API
            )

    for edge in index.calls:
        if edge.callee in event_functions:
            caller = by_location.get((edge.file, edge.caller))
            if caller is not None:
                _add_symbol_candidate(
                    accumulator,
                    spans,
                    caller,
                    SEED_CALL_NEIGHBORHOOD,
                    SCORE_CALL_NEIGHBORHOOD,
                )
        if edge.caller in event_functions:
            for record in _matching_callee_symbols(by_name, edge.callee):
                _add_symbol_candidate(
                    accumulator,
                    spans,
                    record,
                    SEED_CALL_NEIGHBORHOOD,
                    SCORE_CALL_NEIGHBORHOOD,
                )
    return accumulator, spans


def _validate_changed_path(path: str) -> None:
    if not isinstance(path, str) or not path:
        raise ValueError("changed file paths must be non-empty strings")
    if "\\" in path:
        raise ValueError(f"changed file path must be POSIX-relative, got {path!r}")
    if len(path) >= 2 and path[1] == ":":
        raise ValueError(f"changed file path must be relative, got {path!r}")
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError(
            f"changed file path must not escape the snapshot, got {path!r}"
        )


def _validate_changed_lines(
    changed_lines: Mapping[str, Sequence[int]],
) -> dict[str, tuple[int, ...]]:
    if not isinstance(changed_lines, Mapping):
        raise ValueError("changed_lines must map relative paths to line numbers")
    validated: dict[str, tuple[int, ...]] = {}
    for path, lines in changed_lines.items():
        _validate_changed_path(path)
        numbers: list[int] = []
        for line in lines:
            if isinstance(line, bool) or not isinstance(line, int) or line < 1:
                raise ValueError(
                    f"changed lines must be positive integers, got {line!r} in {path!r}"
                )
            numbers.append(line)
        if numbers:
            validated[path] = tuple(sorted(set(numbers)))
    return validated


def _containing_symbol(
    index: CxxContextIndex, path: str, line: int
) -> SymbolRecord | None:
    containing = [
        record
        for record in index.symbols
        if record.file == path and record.start_line <= line <= record.end_line
    ]
    if not containing:
        return None
    return min(
        containing, key=lambda record: (record.end_line - record.start_line,
                                        record.qualified_name)
    )


def _add_pull_request_entries(
    index: CxxContextIndex,
    changed_lines: dict[str, tuple[int, ...]],
    accumulator: _CandidateAccumulator,
    spans: dict[_Location, int],
) -> int:
    by_location, by_name = _symbol_lookups(index)
    changed_symbols: list[SymbolRecord] = []
    seen: set[_Location] = set()
    unassigned = 0
    for path in sorted(changed_lines):
        for line in changed_lines[path]:
            record = _containing_symbol(index, path, line)
            if record is None:
                unassigned += 1
                continue
            location = (record.file, record.start_line, record.qualified_name)
            if location not in seen:
                seen.add(location)
                changed_symbols.append(record)

    for record in changed_symbols:
        _add_symbol_candidate(
            accumulator, spans, record, SEED_PR_CHANGED, SCORE_PR_CHANGED
        )
    for record in changed_symbols:
        for edge in index.calls:
            if edge.caller == record.qualified_name:
                for target in _matching_callee_symbols(by_name, edge.callee):
                    _add_symbol_candidate(
                        accumulator,
                        spans,
                        target,
                        SEED_CALL_NEIGHBORHOOD,
                        SCORE_PR_NEIGHBOR,
                    )
            if _name_matches(record.qualified_name, edge.callee):
                caller = by_location.get((edge.file, edge.caller))
                if caller is not None:
                    _add_symbol_candidate(
                        accumulator,
                        spans,
                        caller,
                        SEED_CALL_NEIGHBORHOOD,
                        SCORE_PR_NEIGHBOR,
                    )
    return unassigned


def _merged_line_count(spans: list[tuple[int, int]]) -> int:
    total = 0
    current: tuple[int, int] | None = None
    for start, end in sorted(spans):
        if current is None or start > current[1] + 1:
            if current is not None:
                total += current[1] - current[0] + 1
            current = (start, end)
        elif end > current[1]:
            current = (current[0], end)
    if current is not None:
        total += current[1] - current[0] + 1
    return total


def _allocate_context(
    selected: list[RetrievalCandidate],
    spans: dict[_Location, int],
    budget: RetrievalBudget,
) -> tuple[list[RetrievalContextFile], int]:
    file_order: list[str] = []
    spans_by_file: dict[str, list[tuple[int, int]]] = {}
    for candidate in selected:
        if candidate.path not in spans_by_file:
            spans_by_file[candidate.path] = []
            file_order.append(candidate.path)
        end = spans.get(
            (candidate.path, candidate.line, candidate.symbol), candidate.line
        )
        spans_by_file[candidate.path].append(
            (candidate.line, max(end, candidate.line))
        )

    context_files: list[RetrievalContextFile] = []
    uncovered_files = 0
    remaining = budget.max_context_lines
    for position, path in enumerate(file_order):
        if position >= budget.max_context_files or remaining <= 0:
            uncovered_files += 1
            continue
        allocated = min(_merged_line_count(spans_by_file[path]), remaining)
        remaining -= allocated
        context_files.append(
            RetrievalContextFile(path=path, allocated_lines=allocated)
        )
    return context_files, uncovered_files


def _build_run(
    index: CxxContextIndex,
    accumulator: _CandidateAccumulator,
    spans: dict[_Location, int],
    budget: RetrievalBudget,
    unassigned_changed_lines: int = 0,
) -> RetrievalRun:
    ranked = accumulator.ranked()
    selected = ranked[: budget.max_candidates]
    context_files, uncovered_files = _allocate_context(selected, spans, budget)
    return RetrievalRun(
        candidates=tuple(selected),
        context_files=tuple(context_files),
        context_lines=sum(item.allocated_lines for item in context_files),
        uncovered_candidates=len(ranked) - len(selected),
        uncovered_files=uncovered_files,
        snapshot_sha256=index.snapshot_sha256,
        unassigned_changed_lines=unassigned_changed_lines,
    )


def _empty_run(index: CxxContextIndex) -> RetrievalRun:
    return RetrievalRun(
        candidates=(),
        context_files=(),
        context_lines=0,
        uncovered_candidates=0,
        uncovered_files=0,
        snapshot_sha256=index.snapshot_sha256,
        unassigned_changed_lines=0,
    )


__all__ = [
    "SCORE_ALLOCATION",
    "SCORE_CALL_NEIGHBORHOOD",
    "SCORE_LENGTH_API",
    "SCORE_PR_CHANGED",
    "SCORE_PR_NEIGHBOR",
    "SCORE_RELEASE",
    "SEED_ALLOCATION",
    "SEED_CALL_NEIGHBORHOOD",
    "SEED_LENGTH_API",
    "SEED_PR_CHANGED",
    "SEED_RELEASE",
    "SEED_REASONS",
    "RetrievalBudget",
    "RetrievalCandidate",
    "RetrievalContextFile",
    "RetrievalRun",
    "retrieve_pull_request",
    "retrieve_repository",
]
