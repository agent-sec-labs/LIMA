"""Deterministic tool-finding to UafCandidate binder (UAF v2 plan Task 9).

Freezes the plan's binder rules for exact candidate identity binding, which
are deliberately stricter than the legacy function-level matching in
:func:`lima.cxx_memory.bind_tool_evidence` (CWE/path/symbol with a bounded
line-distance fallback and a bare ``candidate_id`` key):

- Semgrep/Clang findings bind only when ``finding.path`` equals the
  candidate's ``canonical_path`` exactly (no normalization, no prefix or
  suffix guessing), the finding line falls inside the candidate's
  ``release_range`` or ``use_range`` as a closed interval (no +/-N
  tolerance), and the finding symbol is empty (line-only pass-through) or
  equals the last ``::``-segment of ``function_usr``.  Every other outcome
  is a named ``binding_gap``: ``path-mismatch``, ``line-outside-ranges`` or
  ``symbol-mismatch``.
- ASan findings bind only when the faulting ``finding.line`` hits
  ``use_range`` and at least one evidence-record snippet carries both
  "freed by" and "allocated by" stack segments.  **Honest phase-1
  downgrade**: the frozen plan rule ("freed by" stack-top frame hits
  ``release_range``, "allocated by" stack-top frame hits the allocation
  range) needs per-frame line structures that ``Finding.evidence_records``
  do not carry yet, so frame lines are checked by existence only and
  row-level frame matching is deferred to an evidence-structure upgrade.
  Gaps: ``asan-witness-miss`` (faulting line outside ``use_range``) and
  ``asan-stack-missing`` (either stack segment absent).
- Any other producer is ``unsupported-producer`` and never binds.

:func:`collect_bound_evidence` keeps only evidence records whose
``tool_run_id`` resolves to an existing, tool-matching, ``completed`` run
in ``tool_runs`` (same run identity standard as
:func:`lima.cxx_memory.bind_tool_evidence`: Semgrep/Clang findings cite
runs named after the tool, ASan findings cite ``asan-test`` runs).
Unresolvable records are skipped and reported as
``provenance-incomplete`` gaps.  An empty or unbindable tool result is
never safety: gaps surface, no verdict is implied.

Pure and deterministic: zero LLM, zero I/O, no path normalization and no
line tolerance anywhere.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .models import EvidenceRecord, Finding
from .uaf_models import UafCandidate

__all__ = [
    "ToolFindingBinding",
    "bind_finding_to_candidate",
    "collect_bound_evidence",
]

_STATIC_PRODUCERS = frozenset({"semgrep", "clang"})
_ASAN_SOURCE = "asan"
# Finding source -> tool-run ``tool`` name (frozen by the strict client in
# lima.cxx_memory; repeated locally so the binder stays decoupled from the
# legacy client's private constants).
_RUN_TOOL_BY_SOURCE = {
    "semgrep": "semgrep",
    "clang": "clang",
    "asan": "asan-test",
}
_ASAN_FREED_MARKER = "freed by"
_ASAN_ALLOCATED_MARKER = "allocated by"

_GAP_PATH_MISMATCH = "path-mismatch"
_GAP_LINE_OUTSIDE = "line-outside-ranges"
_GAP_SYMBOL_MISMATCH = "symbol-mismatch"
_GAP_ASAN_WITNESS_MISS = "asan-witness-miss"
_GAP_ASAN_STACK_MISSING = "asan-stack-missing"
_GAP_UNSUPPORTED_PRODUCER = "unsupported-producer"
_GAP_PROVENANCE_INCOMPLETE = "provenance-incomplete"


@dataclass(frozen=True)
class ToolFindingBinding:
    """Binary binding outcome plus the reason a finding did not bind.

    ``bound`` is True only for an exact identity hit; ``binding_gap`` is
    then empty.  An unbound result always names exactly one gap (checked,
    never coerced).
    """

    bound: bool
    binding_gap: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.bound, bool):
            raise ValueError("bound must be a boolean")
        if not isinstance(self.binding_gap, str):
            raise ValueError("binding_gap must be a string")
        if self.bound and self.binding_gap:
            raise ValueError("a bound finding must not carry a binding gap")
        if not self.bound and not self.binding_gap:
            raise ValueError("an unbound finding must name its binding gap")


def _line_in_closed_range(line: int, span: tuple[int, int]) -> bool:
    return span[0] <= line <= span[1]


def bind_finding_to_candidate(
    finding: Finding, candidate: UafCandidate
) -> ToolFindingBinding:
    """Decide whether one tool finding is exact evidence for one candidate.

    Pure function over the frozen Task 9 rules; see the module docstring
    for the rule text and the ASan phase-1 downgrade declaration.
    """

    if not isinstance(finding, Finding):
        raise ValueError("finding must be a lima.models.Finding")
    if not isinstance(candidate, UafCandidate):
        raise ValueError("candidate must be a lima.uaf_models.UafCandidate")

    source = finding.source
    if source in _STATIC_PRODUCERS:
        if finding.path != candidate.canonical_path:
            return ToolFindingBinding(False, _GAP_PATH_MISMATCH)
        if not (
            _line_in_closed_range(finding.line, candidate.release_range)
            or _line_in_closed_range(finding.line, candidate.use_range)
        ):
            return ToolFindingBinding(False, _GAP_LINE_OUTSIDE)
        symbol = (finding.symbol or "").strip()
        if symbol:
            # The frozen symbol standard: the finding symbol must equal the
            # last ``::``-segment of the function USR.  An empty USR has an
            # empty last segment, so no non-empty finding symbol matches it.
            if symbol != candidate.function_usr.rsplit("::", 1)[-1]:
                return ToolFindingBinding(False, _GAP_SYMBOL_MISMATCH)
        return ToolFindingBinding(True)

    if source == _ASAN_SOURCE:
        # Phase-1 downgrade: witness position by faulting line, stack
        # segments by existence only (module docstring declares the gap).
        if not _line_in_closed_range(finding.line, candidate.use_range):
            return ToolFindingBinding(False, _GAP_ASAN_WITNESS_MISS)
        for record in finding.evidence_records or ():
            snippet = (getattr(record, "snippet", "") or "").lower()
            if _ASAN_FREED_MARKER in snippet and _ASAN_ALLOCATED_MARKER in snippet:
                return ToolFindingBinding(True)
        return ToolFindingBinding(False, _GAP_ASAN_STACK_MISSING)

    return ToolFindingBinding(False, _GAP_UNSUPPORTED_PRODUCER)


def _run_index(tool_runs: Iterable[dict]) -> dict[str, dict]:
    runs: dict[str, dict] = {}
    for run in tool_runs or ():
        if isinstance(run, dict) and isinstance(run.get("run_id"), str):
            runs[run["run_id"]] = run
    return runs


def _record_resolves(
    record: EvidenceRecord, run: dict | None, expected_tool: str
) -> bool:
    return (
        run is not None
        and run.get("status") == "completed"
        and run.get("tool") == expected_tool
    )


def collect_bound_evidence(
    findings: Iterable[Finding],
    candidate: UafCandidate,
    tool_runs: Iterable[dict],
) -> tuple[tuple[EvidenceRecord, ...], tuple[str, ...]]:
    """Collect evidence records of bound findings with resolvable runs.

    Returns ``(records, binding_gaps)``.  Records follow the findings order
    and keep only records whose ``tool_run_id`` names an existing,
    tool-matching, ``completed`` run in ``tool_runs``; skipped records turn
    into one ``provenance-incomplete`` gap per affected finding.  Unbound
    findings contribute their ``binding_gap`` and none of their records.
    """

    if not isinstance(candidate, UafCandidate):
        raise ValueError("candidate must be a lima.uaf_models.UafCandidate")
    runs = _run_index(tool_runs)
    records: list[EvidenceRecord] = []
    gaps: list[str] = []
    for finding in findings or ():
        if not isinstance(finding, Finding):
            raise ValueError("findings must be lima.models.Finding instances")
        binding = bind_finding_to_candidate(finding, candidate)
        if not binding.bound:
            gaps.append(binding.binding_gap)
            continue
        expected_tool = _RUN_TOOL_BY_SOURCE[finding.source]
        skipped = False
        for record in finding.evidence_records or ():
            if not isinstance(record, EvidenceRecord):
                skipped = True
                continue
            run = runs.get(record.tool_run_id or "")
            if _record_resolves(record, run, expected_tool):
                records.append(record)
            else:
                skipped = True
        if skipped:
            gaps.append(_GAP_PROVENANCE_INCOMPLETE)
    return tuple(records), tuple(gaps)
