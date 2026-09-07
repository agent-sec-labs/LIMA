"""C/C++ multi-agent orchestration reusing the LIMA collaboration protocol.

This module wires the C/C++ memory-safety pipeline onto the existing LIMA
agent infrastructure (:class:`~lima.agents.CollaborationBus`,
:class:`~lima.runtime.AgentLoop`, :class:`~lima.runtime.ToolRegistry`) without
touching the Diff-only ``MultiAgentCoordinator`` behaviour.  The C++
coordinator is snapshot-bound: every stage's input and output is a validated
set of :class:`~lima.cxx_agent_models.CxxAgentCandidate` objects anchored on
the indexed snapshot.

Role order is fixed: planner -> memory-lifetime / bounds / interprocedural
specialists (independent, parallel) -> critic -> evidence -> verifier ->
arbiter.  The arbiter is deterministic and issues no LLM calls.

Isolation red lines (design spec 8.1-8.5):

* The planner sees only retrieval anchors; it runs against an empty tool
  registry, so it can never read a tool result, and its reply may only
  trim or reorder the anchors: after the ``(path, line, symbol)`` key
  containment check the coordinator rebuilds every accepted candidate from
  its anchor (deterministic seed shell), so the model chooses and orders a
  subset but contributes no claim text of its own.
* Each specialist sees only its own seed-routed assignment plus its own tool
  observations; peer candidates and evidence records never enter a
  specialist context.
* The critic sees the specialist candidate union (with source-role labels)
  but neither peer observations nor raw peer output.
* Only the evidence role receives ``get_tool_evidence`` (the evidence
  registry); every other role's review registry rejects it as an unknown
  tool.

Untrusted-output red line: every stage's final candidate set is validated
against its input set by location key.  A violating set triggers exactly one
format-repair request; a second violation degrades the role to
``failed-replaced`` and the pipeline passes the previous stage's survivors
through unchanged (or, for the planner, deterministic shells built from the
retrieval seeds).  Degradation never invents locations, CWEs or mechanisms:
seed shells carry the non-CWE marker ``unreviewed``, confidence ``0.0`` and
verification state ``needs-human-review`` so they can neither masquerade as
an LLM claim nor merge into CWE-based consensus downstream.

Budget honesty: all roles share one :class:`~lima.cxx_agent_tools.CxxAgentBudget`.
Once ``AgentBudgetExceeded`` surfaces in any stage, the failing role is
marked ``failed-replaced`` immediately (a retry would fail identically) and
every later LLM role is skipped without a client call, passing its incoming
survivors straight through; the arbiter still closes the pipeline and the
coverage records ``candidates_budget_exhausted``.

``read_paths`` decision: the ``read_paths`` handed to the client starts from
the paths already present in the role's input (assignment candidates for
specialists, incoming survivors for critic/evidence/verifier -- all of them
were read earlier in the same task) and grows with every path whose content
a tool actually returned (tracked at the reader boundary).  The planner
passes ``read_paths=None`` because it never reads code.

Message kinds reuse the existing ``lima.agents`` vocabulary: ``assignment``
(planner -> specialist), ``specialist_evidence`` (specialist -> critic),
``peer_challenge`` (critic -> evidence), ``evidence_report`` (evidence ->
verifier), ``verification_decision`` (verifier -> arbiter),
``arbitration_decision`` (arbiter -> review-report), plus ``agent_failure``
and ``retry_request`` around specialist retries.

Coverage mapping: ``CxxAgentCoverage`` has no role-count fields, so
``candidates_generated`` carries the number of pipeline-reviewed input
candidates, ``candidates_budget_exhausted`` the budget degradation flag and
``context_files_used`` the distinct files of the accepted candidates; the
executed/failed role counts are derivable from ``role_outcomes``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, is_dataclass
from typing import Any

from .agents import CollaborationBus
from .cxx_agent_models import CxxAgentCandidate, CxxAgentCoverage
from .cxx_agent_tools import (
    AgentBudgetExceeded,
    CxxAgentBudget,
    SnapshotReader,
    build_evidence_registry,
    build_review_registry,
)
from .cxx_retrieval import (
    SEED_ALLOCATION,
    SEED_CALL_NEIGHBORHOOD,
    SEED_LENGTH_API,
    SEED_PR_CHANGED,
    SEED_RELEASE,
    RetrievalCandidate,
    RetrievalRun,
    _validate_changed_lines,
)
from .runtime import AgentLoop, AgentTool, ToolRegistry

ROLE_PLANNER = "planner"
ROLE_MEMORY_LIFETIME = "memory-lifetime"
ROLE_BOUNDS = "bounds"
ROLE_INTERPROCEDURAL = "interprocedural"
ROLE_CRITIC = "critic"
ROLE_EVIDENCE = "evidence"
ROLE_VERIFIER = "verifier"
ROLE_ARBITER = "arbiter"

SPECIALIST_ROLES = (ROLE_MEMORY_LIFETIME, ROLE_BOUNDS, ROLE_INTERPROCEDURAL)
ROLE_ORDER = (
    ROLE_PLANNER,
    ROLE_MEMORY_LIFETIME,
    ROLE_BOUNDS,
    ROLE_INTERPROCEDURAL,
    ROLE_CRITIC,
    ROLE_EVIDENCE,
    ROLE_VERIFIER,
    ROLE_ARBITER,
)
LLM_ROLES = ROLE_ORDER[:-1]

SEED_DOMAINS = {
    ROLE_MEMORY_LIFETIME: frozenset({SEED_ALLOCATION, SEED_RELEASE}),
    ROLE_BOUNDS: frozenset({SEED_LENGTH_API}),
    ROLE_INTERPROCEDURAL: frozenset({SEED_CALL_NEIGHBORHOOD, SEED_PR_CHANGED}),
}

ROLE_OUTCOME_STATUSES = frozenset({"ok", "failed-retried", "failed-replaced"})
_DEGRADED_CWE_MARKER = "unreviewed"
_DEGRADED_VERIFICATION_STATE = "needs-human-review"
_REVIEW_REPORT = "review-report"
_BUDGET_ERROR_MARKER = "agent tool budget exhausted"
_CandidateKey = tuple[str, int, str]

__all__ = [
    "CxxAgentCoordinator",
    "CxxAgentReviewResult",
    "CxxRoleOutcome",
    "LLM_ROLES",
    "ROLE_ARBITER",
    "ROLE_BOUNDS",
    "ROLE_CRITIC",
    "ROLE_EVIDENCE",
    "ROLE_INTERPROCEDURAL",
    "ROLE_MEMORY_LIFETIME",
    "ROLE_ORDER",
    "ROLE_PLANNER",
    "ROLE_VERIFIER",
    "SEED_DOMAINS",
    "SPECIALIST_ROLES",
]


class _CandidateSetError(RuntimeError):
    """A role's final candidate set violated its input-set containment."""


@dataclass(frozen=True)
class CxxRoleOutcome:
    """Deterministic per-role outcome record for one pipeline run.

    ``status`` is ``ok`` (first attempt succeeded), ``failed-retried`` (the
    first attempt failed and the single retry succeeded) or
    ``failed-replaced`` (the role failed for good; ``candidates`` then carries
    the deterministic passthrough of its input and ``error`` the reason).
    """

    role: str
    status: str
    candidates: tuple[CxxAgentCandidate, ...] = ()
    error: str = ""

    def __post_init__(self) -> None:
        if self.role not in ROLE_ORDER:
            raise ValueError(f"unknown coordinator role: {self.role!r}")
        if self.status not in ROLE_OUTCOME_STATUSES:
            raise ValueError(
                f"role outcome status must be one of {sorted(ROLE_OUTCOME_STATUSES)}, "
                f"got {self.status!r}"
            )


@dataclass(frozen=True)
class CxxAgentReviewResult:
    """Deterministic outcome of one coordinator run over a fixed snapshot."""

    candidates: tuple[CxxAgentCandidate, ...]
    role_outcomes: tuple[CxxRoleOutcome, ...]
    coverage: CxxAgentCoverage
    snapshot_sha256: str
    message_count: int
    arbiter_rejections: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        seen: list[str] = []
        for outcome in self.role_outcomes:
            if outcome.role not in seen:
                seen.append(outcome.role)
        if tuple(seen) != ROLE_ORDER:
            raise ValueError(
                "role outcomes must cover the coordinator role order exactly, "
                f"got {tuple(seen)!r}"
            )


def _candidate_key(candidate: CxxAgentCandidate) -> _CandidateKey:
    return (candidate.path, candidate.line, candidate.symbol)


def _validated_subset(
    candidates: tuple[CxxAgentCandidate, ...],
    allowed_keys: frozenset[_CandidateKey],
    indexed_paths: frozenset[str] | None = None,
) -> tuple[CxxAgentCandidate, ...]:
    """Reject the whole set unless every candidate stays inside its input set."""
    for candidate in candidates:
        key = _candidate_key(candidate)
        if key not in allowed_keys:
            raise _CandidateSetError(
                f"candidate location is outside the role's input set: "
                f"{candidate.path}:{candidate.line}:{candidate.symbol}"
            )
        if indexed_paths is not None and candidate.path not in indexed_paths:
            raise _CandidateSetError(
                f"candidate path is not part of the indexed snapshot: "
                f"{candidate.path!r}"
            )
    return tuple(candidates)


def _seed_shell(anchor: RetrievalCandidate) -> CxxAgentCandidate:
    """Project one retrieval anchor into a non-claim candidate shell.

    Degraded planner output only ever passes through existing retrieval
    seeds: the shell preserves the anchor's location and names the seed in
    its title, while the non-CWE marker and zero confidence keep it from
    being mistaken for an LLM finding or forming CWE-based consensus.
    ``verification_state`` is deliberately ``needs-human-review`` (inside the
    closed state domain): the shell never went through any LLM analysis, so
    the default ``llm-candidate`` would misrepresent its origin.
    """
    material = (
        f"retrieval:{anchor.path}:{anchor.line}:{anchor.symbol}:{anchor.seed_reason}"
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return CxxAgentCandidate(
        candidate_id="retrieval-" + digest[:32],
        cwe=_DEGRADED_CWE_MARKER,
        path=anchor.path,
        line=anchor.line,
        symbol=anchor.symbol,
        title=f"retrieval seed passthrough ({anchor.seed_reason})",
        mechanism=(
            "degraded role output: unreviewed retrieval seed passed through with "
            f"score {anchor.score}; no LLM analysis was performed"
        ),
        trigger_path=(anchor.symbol,),
        confidence=0.0,
        verification_state=_DEGRADED_VERIFICATION_STATE,
    )


class _ReadTrackingReader:
    """Delegating reader that records every path whose content was returned.

    Tracking at the reader boundary captures exactly the snapshot paths the
    tools actually delivered to the model (``read_code_snippet`` and
    ``get_type_definition`` both read through it) without instrumenting the
    registries themselves.
    """

    def __init__(self, reader: SnapshotReader) -> None:
        self._reader = reader
        self.read_paths: set[str] = set()

    def read_text(self, path: str) -> str:
        text = self._reader.read_text(path)
        self.read_paths.add(path)
        return text


def _to_json_safe(value: Any) -> Any:
    """Project dataclasses to plain containers for ``AgentLoop`` rendering."""
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    if isinstance(value, list):
        return [_to_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_to_json_safe(item) for item in value)
    return value


class _JsonSafeRegistry(ToolRegistry):
    """Tool registry whose tool results are plain JSON-safe containers.

    ``AgentLoop`` renders dict/list/tuple tool results with ``json.dumps``,
    which cannot serialise dataclass items (``CodeSnippet``,
    ``list[SymbolRef]``, ``list[EvidenceRecord]``).  The wrapper keeps the
    wrapped registry's schema validation and budget charging untouched and
    only projects the returned value to plain containers afterwards.
    """

    @classmethod
    def wrapping(cls, registry: ToolRegistry) -> _JsonSafeRegistry:
        wrapper = cls()
        for entry in registry.catalog():
            name = str(entry["name"])
            parameters = dict(entry.get("parameters") or {})

            def handler(name: str = name, **kwargs: Any) -> Any:
                return _to_json_safe(registry.invoke(name, kwargs))

            wrapper.register(AgentTool(
                name, str(entry.get("description") or ""), parameters, handler,
            ))
        return wrapper


def _ensure_budget_usable(
    budget: CxxAgentBudget, observations: list[dict[str, Any]]
) -> None:
    """Fail fast, from the stepper, when the shared tool pool is dead.

    ``AgentLoop`` wraps tool-invocation exceptions into error observations,
    so an ``AgentBudgetExceeded`` raised inside a tool handler cannot stop
    the loop on its own: without this check a specialist would keep burning
    LLM calls on failing reads and might end on a misleading step/time
    budget error.  Called before every model turn:

    * any empty remaining dimension raises.  ``calls`` and ``bytes`` are the
      hard cases; ``files``/``lines`` exhaustion is treated as exhausted too
      because the code-reading tools can no longer serve a single range, so
      continuing the loop is pointless -- conservative but honest;
    * a prior observation whose error is this module's budget-exhaustion
      failure means the pool was already too small for a requested read
      (the failed deduction charged nothing, so the remaining amounts alone
      cannot reveal it) and the loop must not request another model turn.

    The exception is raised from the stepper, which ``AgentLoop`` does not
    catch, so it propagates into the role's failed-replaced handling and
    sets the global budget-degradation flag.
    """
    remaining = budget.remaining()
    if min(
        remaining.calls,
        remaining.files,
        remaining.lines,
        remaining.bytes_remaining,
    ) <= 0:
        raise AgentBudgetExceeded(
            f"{_BUDGET_ERROR_MARKER} before a model turn "
            f"(calls={remaining.calls}, files={remaining.files}, "
            f"lines={remaining.lines}, bytes={remaining.bytes_remaining})"
        )
    for observation in observations:
        if not observation.get("ok") and _BUDGET_ERROR_MARKER in str(
            observation.get("error") or ""
        ):
            raise AgentBudgetExceeded(
                f"{_BUDGET_ERROR_MARKER} by a previous tool call in this loop"
            )


def _loop_action(step: Any) -> dict[str, Any]:
    """Translate an ``AgentStep`` into an ``AgentLoop`` action dict."""
    if step.action == "tool":
        return {"action": "tool", "tool": step.tool, "arguments": step.arguments_dict}
    return {"action": "final", "findings": tuple(step.candidates)}


def _render_observations(
    observations: list[dict[str, Any]], max_items: int = 8, max_chars: int = 600
) -> str:
    if not observations:
        return ""
    lines = ["Observations from this role's own tool calls so far:"]
    for observation in observations[-max_items:]:
        body = str(
            observation.get("result")
            if observation.get("ok")
            else observation.get("error") or ""
        )[:max_chars]
        lines.append(
            f"- step={observation.get('step')} tool={observation.get('tool')} "
            f"ok={bool(observation.get('ok'))}: {body}"
        )
    return "\n".join(lines)


def _repair_note(error: str) -> str:
    return (
        f"FORMAT REPAIR: the previous reply was rejected ({error}). Return a "
        "final step whose candidates reuse the exact path, line and symbol of "
        "entries from the provided candidate list; never invent locations."
    )


def _anchor_block(anchors: tuple[RetrievalCandidate, ...]) -> str:
    lines = [
        "Assignment anchors (ranked retrieval candidates). Reply with a final "
        "step that selects and orders a subset of exactly these anchors:"
    ]
    for position, anchor in enumerate(anchors, 1):
        lines.append(
            f"{position}. path={anchor.path} line={anchor.line} "
            f"symbol={anchor.symbol} seed={anchor.seed_reason} score={anchor.score}"
        )
    return "\n".join(lines)


def _assignment_block(
    role: str,
    candidates: tuple[CxxAgentCandidate, ...],
    anchor_by_key: Mapping[_CandidateKey, RetrievalCandidate],
) -> str:
    lines = [
        f"Assignment for the {role} specialist: review only these anchors. You "
        "see only your own assignment and your own tool observations."
    ]
    for position, item in enumerate(candidates, 1):
        anchor = anchor_by_key.get(_candidate_key(item))
        seed = anchor.seed_reason if anchor is not None else "unknown"
        lines.append(
            f"{position}. path={item.path} line={item.line} symbol={item.symbol} "
            f"seed={seed} cwe={item.cwe} id={item.candidate_id} title={item.title}"
        )
    return "\n".join(lines)


def _candidate_block(
    title: str,
    candidates: tuple[CxxAgentCandidate, ...],
    sources: Sequence[str] | None = None,
) -> str:
    lines = [title]
    for position, item in enumerate(candidates, 1):
        label = f"[{sources[position - 1]}] " if sources is not None else ""
        lines.append(
            f"{position}. {label}path={item.path} line={item.line} "
            f"symbol={item.symbol} cwe={item.cwe} id={item.candidate_id} "
            f"confidence={item.confidence:.2f} title={item.title}"
        )
    return "\n".join(lines)


def _rebuild_planner_assignment(
    candidates: tuple[CxxAgentCandidate, ...],
    anchor_by_key: Mapping[_CandidateKey, RetrievalCandidate],
) -> tuple[CxxAgentCandidate, ...]:
    """Rebuild the planner's reply from anchor data, keeping subset and order.

    The key containment check alone would still let the model rewrite
    ``cwe``/``title``/``mechanism`` under an accepted location.  The planner
    is a selection stage, not an analysis stage: its output is therefore the
    model-chosen, model-ordered subset of deterministic seed shells, so no
    model-authored claim text can enter the pipeline through it.
    """
    rebuilt: list[CxxAgentCandidate] = []
    seen: set[_CandidateKey] = set()
    for candidate in candidates:
        key = _candidate_key(candidate)
        if key in seen:
            continue
        seen.add(key)
        rebuilt.append(_seed_shell(anchor_by_key[key]))
    return tuple(rebuilt)


def _route_assignment(
    assignment: tuple[CxxAgentCandidate, ...],
    anchor_by_key: Mapping[_CandidateKey, RetrievalCandidate],
) -> tuple[dict[str, tuple[CxxAgentCandidate, ...]], dict[_CandidateKey, str], dict[str, str]]:
    """Split planner candidates into per-specialist assignments by seed domain.

    The split is deterministic: planner output order is preserved inside each
    specialist assignment, and every routed candidate's seed comes from its
    input anchor, never from model text.  Candidates whose anchor seed falls
    into no specialist domain stay unrouted.
    """
    routed: dict[str, list[CxxAgentCandidate]] = {role: [] for role in SPECIALIST_ROLES}
    assignee: dict[_CandidateKey, str] = {}
    for candidate in assignment:
        anchor = anchor_by_key.get(_candidate_key(candidate))
        seed = anchor.seed_reason if anchor is not None else ""
        for role in SPECIALIST_ROLES:
            if seed in SEED_DOMAINS[role]:
                routed[role].append(candidate)
                assignee[_candidate_key(candidate)] = role
                break
    blocks = {
        role: _assignment_block(role, tuple(items), anchor_by_key)
        for role, items in routed.items()
    }
    return (
        {role: tuple(items) for role, items in routed.items()},
        assignee,
        blocks,
    )


class CxxAgentCoordinator:
    """Deterministic planner -> specialists -> critic -> evidence -> verifier
    -> arbiter orchestration for the C/C++ memory-safety pipeline.

    The client is a :class:`~lima.cxx_llm.CxxLLMClient` or any duck-typed
    replacement exposing ``step(role, managed_context, tools, budget,
    read_paths=None) -> AgentStep``.  All roles share one
    :class:`CxxAgentBudget`; the per-run ``budget`` argument of the review
    methods overrides the constructor budget for that single run.
    """

    def __init__(
        self,
        client: Any,
        index: Any,
        reader: SnapshotReader,
        store: Any = None,
        task_id: str = "",
        evidence_lookup: Callable[[str], list] | None = None,
        loop_max_steps: int = 4,
        loop_timeout_seconds: int = 45,
        max_assignment_candidates: int = 8,
        budget: CxxAgentBudget | None = None,
    ) -> None:
        if (
            isinstance(max_assignment_candidates, bool)
            or not isinstance(max_assignment_candidates, int)
            or max_assignment_candidates < 1
        ):
            raise ValueError("max_assignment_candidates must be a positive integer")
        self._client = client
        self._index = index
        self._reader = reader
        self._store = store
        self._task_id = task_id
        self._evidence_lookup: Callable[[str], list] = (
            evidence_lookup if evidence_lookup is not None else lambda _candidate_id: []
        )
        self._loop = AgentLoop(loop_max_steps, loop_timeout_seconds)
        self._max_assignment_candidates = max_assignment_candidates
        self._budget = budget if budget is not None else CxxAgentBudget()
        self._indexed_paths = frozenset(index.coverage.indexed)

    def review_repository(
        self, retrieval_run: RetrievalRun, budget: CxxAgentBudget | None = None
    ) -> CxxAgentReviewResult:
        """Run the C/C++ agent pipeline over one whole-repository retrieval."""
        return self._review(retrieval_run, (), self._effective_budget(budget))

    def review_pull_request(
        self,
        retrieval_run: RetrievalRun,
        changed_lines: Mapping[str, Sequence[int]],
        budget: CxxAgentBudget | None = None,
    ) -> CxxAgentReviewResult:
        """Run the pipeline with a per-file changed-lines header in every context."""
        validated = _validate_changed_lines(changed_lines)
        counts = tuple(
            (path, len(lines)) for path, lines in sorted(validated.items())
        )
        return self._review(retrieval_run, counts, self._effective_budget(budget))

    def _effective_budget(self, budget: CxxAgentBudget | None) -> CxxAgentBudget:
        return budget if budget is not None else self._budget

    # ------------------------------------------------------------------ stages

    def _base_header(
        self, retrieval_run: RetrievalRun, changed_line_counts: tuple[tuple[str, int], ...]
    ) -> str:
        lines = [
            "Task: LIMA C/C++ memory-safety review on a fixed repository snapshot.",
            f"Snapshot: {retrieval_run.snapshot_sha256}",
            (
                f"Index coverage: {len(self._indexed_paths)} indexed files, "
                f"{len(self._index.symbols)} indexed symbols."
            ),
            (
                f"Retrieval: {len(retrieval_run.candidates)} candidates, "
                f"{retrieval_run.uncovered_candidates} uncovered, "
                f"{len(retrieval_run.context_files)} context files, "
                f"{retrieval_run.context_lines} context lines."
            ),
        ]
        if changed_line_counts:
            lines.append(
                "Pull request changed lines (per-file counts; contents are not included):"
            )
            lines.extend(
                f"- {path}: {count} changed line(s)"
                for path, count in changed_line_counts
            )
        return "\n".join(lines)

    def _plan_stage(
        self,
        anchors: tuple[RetrievalCandidate, ...],
        anchor_by_key: Mapping[_CandidateKey, RetrievalCandidate],
        header: str,
        run_budget: CxxAgentBudget,
        exhausted: list[bool],
    ) -> tuple[CxxRoleOutcome, tuple[CxxAgentCandidate, ...]]:
        if not anchors:
            return CxxRoleOutcome(ROLE_PLANNER, "ok", ()), ()
        context = "\n\n".join([header, _anchor_block(anchors)])
        allowed = frozenset(anchor_by_key)
        last_error = ""
        for attempt in (1, 2):
            if exhausted[0]:
                break
            attempt_context = (
                context if attempt == 1 else "\n\n".join([context, _repair_note(last_error)])
            )
            try:
                step = self._client.step(
                    ROLE_PLANNER, attempt_context, ToolRegistry(), run_budget,
                    read_paths=None,
                )
                if step.action != "final":
                    raise _CandidateSetError("planner must return a final step")
                candidates = _rebuild_planner_assignment(
                    _validated_subset(tuple(step.candidates), allowed),
                    anchor_by_key,
                )
                status = "ok" if attempt == 1 else "failed-retried"
                return CxxRoleOutcome(ROLE_PLANNER, status, candidates), candidates
            except AgentBudgetExceeded as exc:
                exhausted[0] = True
                last_error = str(exc)
                break
            except _CandidateSetError as exc:
                last_error = str(exc)
            except RuntimeError as exc:
                # Provider/transport failures are hard failures, not format
                # errors: they are never repaired.
                last_error = str(exc)
                break
        shells = tuple(_seed_shell(anchor) for anchor in anchors)
        return (
            CxxRoleOutcome(ROLE_PLANNER, "failed-replaced", shells, last_error),
            shells,
        )

    def _specialist_stage(
        self,
        bus: CollaborationBus,
        routed: Mapping[str, tuple[CxxAgentCandidate, ...]],
        blocks: Mapping[str, str],
        run_budget: CxxAgentBudget,
        exhausted: list[bool],
    ) -> dict[str, CxxRoleOutcome]:
        outcomes: dict[str, CxxRoleOutcome] = {}
        failure_events: dict[str, list[tuple[str, str, str, dict[str, Any]]]] = {
            role: [] for role in SPECIALIST_ROLES
        }
        with ThreadPoolExecutor(max_workers=len(SPECIALIST_ROLES)) as pool:
            futures = {
                role: pool.submit(
                    self._run_specialist,
                    role, routed[role], blocks[role], run_budget, exhausted,
                    failure_events[role],
                )
                for role in SPECIALIST_ROLES
            }
            for role, future in futures.items():
                outcomes[role] = future.result()
        # Failure and retry messages are emitted after the pool join, grouped
        # by role in SPECIALIST_ROLES order, so the TaskStore transcript order
        # is reproducible regardless of thread scheduling.
        for role in SPECIALIST_ROLES:
            for sender, recipient, kind, content in failure_events[role]:
                bus.send(sender, recipient, kind, content)
            outcome = outcomes[role]
            bus.send(role, ROLE_CRITIC, "specialist_evidence", {
                "role": role,
                "status": outcome.status,
                "error": outcome.error,
                "candidates": [asdict(item) for item in outcome.candidates],
            })
        return outcomes

    def _run_specialist(
        self,
        role: str,
        assignment: tuple[CxxAgentCandidate, ...],
        assignment_block: str,
        run_budget: CxxAgentBudget,
        exhausted: list[bool],
        failure_events: list[tuple[str, str, str, dict[str, Any]]],
    ) -> CxxRoleOutcome:
        if exhausted[0]:
            return CxxRoleOutcome(
                role, "failed-replaced", tuple(assignment),
                "skipped: the agent tool budget was exhausted earlier in the pipeline",
            )
        if not assignment:
            return CxxRoleOutcome(role, "ok", ())
        last_error = ""
        for attempt in (1, 2):
            try:
                candidates = self._run_specialist_loop(
                    role, assignment, assignment_block, run_budget
                )
                status = "ok" if attempt == 1 else "failed-retried"
                return CxxRoleOutcome(role, status, candidates)
            except AgentBudgetExceeded as exc:
                # The pool is empty: a retry would fail identically, so the
                # role degrades at once and later LLM roles are skipped.
                exhausted[0] = True
                failure_events.append((
                    role, ROLE_PLANNER, "agent_failure",
                    {"role": role, "attempt": attempt, "error": str(exc)[:1000]},
                ))
                return CxxRoleOutcome(role, "failed-replaced", tuple(assignment), str(exc))
            except RuntimeError as exc:
                # AgentLoopProtocolError and RuntimeBudgetExceeded are
                # RuntimeError subclasses: retry exactly once, then replace.
                last_error = str(exc)
                failure_events.append((
                    role, ROLE_PLANNER, "agent_failure",
                    {"role": role, "attempt": attempt, "error": last_error[:1000]},
                ))
                if attempt == 1:
                    failure_events.append((
                        ROLE_PLANNER, role, "retry_request",
                        {"role": role, "next_attempt": 2, "reason": last_error[:500]},
                    ))
        return CxxRoleOutcome(role, "failed-replaced", tuple(assignment), last_error)

    def _run_specialist_loop(
        self,
        role: str,
        assignment: tuple[CxxAgentCandidate, ...],
        assignment_block: str,
        run_budget: CxxAgentBudget,
    ) -> tuple[CxxAgentCandidate, ...]:
        reader = _ReadTrackingReader(self._reader)
        registry = _JsonSafeRegistry.wrapping(
            build_review_registry(self._index, reader, run_budget)
        )
        initial_paths = frozenset(item.path for item in assignment)

        def stepper(loop_state: dict[str, Any]) -> dict[str, Any]:
            observations = list(loop_state.get("observations") or [])
            _ensure_budget_usable(run_budget, observations)
            parts = [assignment_block]
            rendered = _render_observations(observations)
            if rendered:
                parts.append(rendered)
            step = self._client.step(
                role, "\n\n".join(parts), registry, run_budget,
                read_paths=frozenset(initial_paths | reader.read_paths),
            )
            return _loop_action(step)

        result = self._loop.run(stepper, registry, {"observations": []})
        return tuple(result.output or ())

    def _filter_stage(
        self,
        bus: CollaborationBus,
        role: str,
        incoming: tuple[CxxAgentCandidate, ...],
        base_context: str,
        registry_builder: Callable[[SnapshotReader], ToolRegistry],
        run_budget: CxxAgentBudget,
        exhausted: list[bool],
        require_indexed: bool = False,
    ) -> tuple[CxxRoleOutcome, tuple[CxxAgentCandidate, ...], list[dict[str, Any]]]:
        if exhausted[0]:
            outcome = CxxRoleOutcome(
                role, "failed-replaced", tuple(incoming),
                "skipped: the agent tool budget was exhausted earlier in the pipeline",
            )
            return outcome, tuple(incoming), ()
        if not incoming:
            return CxxRoleOutcome(role, "ok", ()), (), ()
        reader = _ReadTrackingReader(self._reader)
        registry = _JsonSafeRegistry.wrapping(registry_builder(reader))
        initial_paths = frozenset(item.path for item in incoming)
        allowed = frozenset(_candidate_key(item) for item in incoming)
        indexed = self._indexed_paths if require_indexed else None

        def build_context(observations: list[dict[str, Any]], repair: str = "") -> str:
            parts = [base_context]
            rendered = _render_observations(observations)
            if rendered:
                parts.append(rendered)
            if repair:
                parts.append(repair)
            return "\n\n".join(parts)

        def read_paths_now() -> frozenset[str]:
            return frozenset(initial_paths | reader.read_paths)

        def stepper(loop_state: dict[str, Any]) -> dict[str, Any]:
            observations = list(loop_state.get("observations") or [])
            _ensure_budget_usable(run_budget, observations)
            step = self._client.step(
                role, build_context(observations), registry, run_budget,
                read_paths=read_paths_now(),
            )
            return _loop_action(step)

        try:
            result = self._loop.run(stepper, registry, {"observations": []})
            observations = list(result.observations)
            try:
                survivors = _validated_subset(
                    tuple(result.output or ()), allowed, indexed
                )
            except _CandidateSetError as exc:
                step = self._client.step(
                    role, build_context(observations, _repair_note(str(exc))),
                    registry, run_budget, read_paths=read_paths_now(),
                )
                if step.action != "final":
                    raise _CandidateSetError("repair must return a final step") from None
                survivors = _validated_subset(tuple(step.candidates), allowed, indexed)
            return CxxRoleOutcome(role, "ok", survivors), survivors, observations
        except AgentBudgetExceeded as exc:
            exhausted[0] = True
            self._emit_agent_failure(bus, role, 1, exc)
            outcome = CxxRoleOutcome(role, "failed-replaced", tuple(incoming), str(exc))
            return outcome, tuple(incoming), ()
        except RuntimeError as exc:
            self._emit_agent_failure(bus, role, 1, exc)
            outcome = CxxRoleOutcome(role, "failed-replaced", tuple(incoming), str(exc))
            return outcome, tuple(incoming), ()

    def _arbitrate(
        self,
        anchors: tuple[RetrievalCandidate, ...],
        assignee_by_key: Mapping[_CandidateKey, str],
        stage_keys: tuple[
            frozenset[_CandidateKey], frozenset[_CandidateKey],
            frozenset[_CandidateKey], frozenset[_CandidateKey],
            frozenset[_CandidateKey],
        ],
        verifier_survivors: tuple[CxxAgentCandidate, ...],
    ) -> tuple[tuple[CxxAgentCandidate, ...], tuple[str, ...]]:
        planner_keys, union_keys, critic_keys, evidence_keys, verifier_keys = stage_keys
        merged: dict[_CandidateKey, CxxAgentCandidate] = {}
        for candidate in verifier_survivors:
            key = _candidate_key(candidate)
            current = merged.get(key)
            if (
                current is None
                or candidate.confidence > current.confidence
                or (
                    candidate.confidence == current.confidence
                    and candidate.candidate_id < current.candidate_id
                )
            ):
                merged[key] = candidate
        final = tuple(sorted(
            merged.values(),
            key=lambda item: (item.path, item.line, item.symbol, item.candidate_id),
        ))
        rejections: list[str] = []
        for anchor in anchors:
            key = (anchor.path, anchor.line, anchor.symbol)
            if key not in planner_keys:
                dropper = ROLE_PLANNER
            elif key not in union_keys:
                dropper = assignee_by_key.get(key, "specialists")
            elif key not in critic_keys:
                dropper = ROLE_CRITIC
            elif key not in evidence_keys:
                dropper = ROLE_EVIDENCE
            elif key not in verifier_keys:
                dropper = ROLE_VERIFIER
            else:
                continue
            rejections.append(
                f"{anchor.path}:{anchor.line}:{anchor.symbol}: dropped-by-{dropper}"
            )
        rejections.sort()
        return final, tuple(rejections)

    def _emit_agent_failure(
        self, bus: CollaborationBus, role: str, attempt: int, exc: Exception
    ) -> None:
        bus.send(role, ROLE_PLANNER, "agent_failure", {
            "role": role, "attempt": attempt, "error": str(exc)[:1000],
        })

    # ------------------------------------------------------------------ driver

    def _review(
        self,
        retrieval_run: RetrievalRun,
        changed_line_counts: tuple[tuple[str, int], ...],
        run_budget: CxxAgentBudget,
    ) -> CxxAgentReviewResult:
        bus = CollaborationBus(self._task_id, self._store)
        exhausted = [False]
        header = self._base_header(retrieval_run, changed_line_counts)
        anchors = tuple(retrieval_run.candidates[: self._max_assignment_candidates])
        anchor_by_key = {
            (item.path, item.line, item.symbol): item for item in anchors
        }

        planner_outcome, assignment = self._plan_stage(
            anchors, anchor_by_key, header, run_budget, exhausted
        )
        if planner_outcome.status == "failed-replaced":
            bus.send(ROLE_PLANNER, _REVIEW_REPORT, "agent_failure", {
                "role": ROLE_PLANNER, "attempt": 1,
                "error": planner_outcome.error[:1000],
            })
        routed, assignee_by_key, blocks = _route_assignment(assignment, anchor_by_key)
        for role in SPECIALIST_ROLES:
            bus.send(ROLE_PLANNER, role, "assignment", {
                "candidates": [asdict(item) for item in routed[role]],
            })
        specialist_outcomes = self._specialist_stage(
            bus, routed, blocks, run_budget, exhausted
        )

        union = tuple(
            (role, item)
            for role in SPECIALIST_ROLES
            for item in specialist_outcomes[role].candidates
        )
        union_keys = frozenset(_candidate_key(item) for _, item in union)

        def review_registry(reader: SnapshotReader) -> ToolRegistry:
            return build_review_registry(self._index, reader, run_budget)

        def evidence_registry(reader: SnapshotReader) -> ToolRegistry:
            return build_evidence_registry(
                self._index, reader, run_budget, self._evidence_lookup
            )

        critic_context = "\n\n".join([
            header,
            _candidate_block(
                "Candidate union proposed by the specialists "
                "(return only candidates from this list):",
                tuple(item for _, item in union),
                tuple(role for role, _ in union),
            ),
        ])
        critic_outcome, critic_survivors, _critic_observations = self._filter_stage(
            bus, ROLE_CRITIC, tuple(item for _, item in union), critic_context,
            review_registry, run_budget, exhausted,
        )
        bus.send(ROLE_CRITIC, ROLE_EVIDENCE, "peer_challenge", {
            "status": critic_outcome.status,
            "candidates": [asdict(item) for item in critic_survivors],
        })

        evidence_context = "\n\n".join([
            header,
            _candidate_block(
                "Candidates under evidence review (call get_tool_evidence with "
                "each candidate id; conflicts and empty results stay as they are):",
                critic_survivors,
            ),
        ])
        evidence_outcome, evidence_survivors, evidence_observations = self._filter_stage(
            bus, ROLE_EVIDENCE, critic_survivors, evidence_context,
            evidence_registry, run_budget, exhausted,
        )
        bus.send(ROLE_EVIDENCE, ROLE_VERIFIER, "evidence_report", {
            "status": evidence_outcome.status,
            "tool_observations": len(evidence_observations),
            "candidates": [asdict(item) for item in evidence_survivors],
        })

        verifier_context = "\n\n".join([
            header,
            _candidate_block(
                "Candidates for final verification (return only candidates from "
                "this list, bound to the indexed snapshot):",
                evidence_survivors,
            ),
            (
                f"Coverage: {len(self._indexed_paths)} indexed files, "
                f"{len(self._index.symbols)} indexed symbols, "
                f"{len(anchors)} candidates reviewed."
            ),
            _render_observations(evidence_observations)
            or "No tool evidence observations were recorded.",
        ])
        verifier_outcome, verifier_survivors, _verifier_observations = self._filter_stage(
            bus, ROLE_VERIFIER, evidence_survivors, verifier_context,
            review_registry, run_budget, exhausted, require_indexed=True,
        )
        bus.send(ROLE_VERIFIER, ROLE_ARBITER, "verification_decision", {
            "status": verifier_outcome.status,
            "candidates": [asdict(item) for item in verifier_survivors],
        })

        final_candidates, rejections = self._arbitrate(
            anchors,
            assignee_by_key,
            (
                frozenset(_candidate_key(item) for item in planner_outcome.candidates),
                union_keys,
                frozenset(_candidate_key(item) for item in critic_survivors),
                frozenset(_candidate_key(item) for item in evidence_survivors),
                frozenset(_candidate_key(item) for item in verifier_survivors),
            ),
            verifier_survivors,
        )
        coverage = CxxAgentCoverage(
            indexed_files=len(self._indexed_paths),
            indexed_symbols=len(self._index.symbols),
            candidates_generated=len(anchors),
            candidates_budget_exhausted=exhausted[0],
            context_files_used=len({item.path for item in final_candidates}),
            context_lines_sent=retrieval_run.context_lines,
            unparsed_regions=tuple(sorted({
                gap.file for gap in self._index.coverage.parse_gaps
            })),
            llm_unavailable=False,
        )
        arbiter_outcome = CxxRoleOutcome(ROLE_ARBITER, "ok", final_candidates)
        outcomes_by_role = {
            ROLE_PLANNER: planner_outcome,
            ROLE_MEMORY_LIFETIME: specialist_outcomes[ROLE_MEMORY_LIFETIME],
            ROLE_BOUNDS: specialist_outcomes[ROLE_BOUNDS],
            ROLE_INTERPROCEDURAL: specialist_outcomes[ROLE_INTERPROCEDURAL],
            ROLE_CRITIC: critic_outcome,
            ROLE_EVIDENCE: evidence_outcome,
            ROLE_VERIFIER: verifier_outcome,
            ROLE_ARBITER: arbiter_outcome,
        }
        # Key names match the existing ``lima.harness`` summary consumer, which
        # reads the lengths of ``approved_findings``/``rejected_findings`` from
        # the last arbitration message; the C++ payload keeps its candidate ids
        # and deterministic rejection strings inside those keys.
        bus.send(ROLE_ARBITER, _REVIEW_REPORT, "arbitration_decision", {
            "approved_findings": [item.candidate_id for item in final_candidates],
            "rejected_findings": list(rejections),
            "coverage": asdict(coverage),
            "roles": {role: outcome.status for role, outcome in outcomes_by_role.items()},
        })
        return CxxAgentReviewResult(
            candidates=final_candidates,
            role_outcomes=tuple(outcomes_by_role[role] for role in ROLE_ORDER),
            coverage=coverage,
            snapshot_sha256=retrieval_run.snapshot_sha256,
            message_count=bus.count(),
            arbiter_rejections=rejections,
        )
