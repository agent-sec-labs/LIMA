"""UAF v2 instruments and the frozen evaluation chain.

Production routing (agent-vuln-platform design section 10): the v2
proof-first orchestration is **retired from the production path** -- the
scanner runs the single agent chain in :mod:`lima.agent_orchestrator`.  This
module now hosts two things:

1. **Instruments** retained for agent consultation (design section 10
   "保留为仪器"): :func:`instrument_facts` (strict ``/v1/uaf-facts`` client
   call plus expectation pinning and adapter certification),
   :func:`instrument_proof` (P1-P7 :func:`lima.uaf_proof.prove_candidate`
   consult), :func:`instrument_broker` (tool-evidence binding plus
   three-state broker per producer) and :func:`contract_evidence_record`
   (models record -> contract evidence lift).  The pure
   :func:`arbiter_state` state machine is unchanged.
2. **The frozen v2 evaluation chain** :func:`review_uaf` -- kept verbatim in
   behavior only because the pinned UAF v2 evaluation harness
   (``scripts/run_uaf_v2_evaluation.py`` + ``tests/test_uaf_v2_evaluation.py``)
   drives it; it is no longer imported by any production module and its
   proof-before-LLM routing is scheduled for migration with the harness
   (platform plan Task 10).  New code must not call it.

Frozen arbiter semantics (design 12.3), reused by both consumers:

    1. REFUTED proof + valid D2+ SUPPORTS, or PASS proof + valid D2+
       REFUTES evidence  -> ``needs-human-review``;
    2. valid D3 SUPPORTS runtime evidence -> ``runtime-confirmed``;
    3. proof PASS -> ``fact-verified``;
    4. equivalent D2+ SUPPORTS tool evidence -> ``tool-corroborated``;
    5. proof REFUTED -> ``rejected`` (audit record, never a finding);
    6. UNKNOWN + (D1, SUPPORTS) consensus -> ``semantic-supported``;
    7. everything else -> ``abstain``.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Final

from .contracts.errors import ContractError
from .contracts.evidence import EvidenceLevel, EvidencePolarity
from .cxx_agent_tools import CxxAgentBudget
from .cxx_memory import (
    MAX_UAF_TRANSLATION_UNITS,
    UAF_FACTS_BUILD_CONTEXT_MODES,
    UafFactsResponse,
)
from .uaf_broker import broker_verdict
from .uaf_candidates import generate_candidates
from .uaf_evidence_binder import collect_bound_evidence
from .uaf_facts import UafFactBundle, UnitFacts, adapt_uaf_response
from .uaf_llm_branch import (
    MODE_REQUIRED,
    SPECIALIST_ROLE,
    SemanticBranchOutcome,
    run_semantic_branch,
)
from .uaf_models import (
    CandidateIdentity,
    FactBundleExpectation,
    ProofResult,
    UafCandidate,
)
from .uaf_proof import prove_candidate
from .workspace import RepositoryWorkspace

__all__ = [
    "UAF_FINDING_STATES",
    "UAF_POSITIVE_STATES",
    "UafOutcomeCandidate",
    "UafReviewOutcome",
    "UafReviewStats",
    "arbiter_state",
    "contract_evidence_record",
    "instrument_broker",
    "instrument_facts",
    "instrument_proof",
    "review_uaf",
]

AGENT_MODES: Final = frozenset({"off", "auto", "required"})
SOURCE_MODES: Final = frozenset({"repository", "diff-only"})

# Final states that a scanner may project into a vulnerability Finding.
# ``rejected`` (audit-only) and ``abstain`` (no claim) are never members.
UAF_FINDING_STATES: Final = frozenset(
    {
        "semantic-supported",
        "fact-verified",
        "tool-corroborated",
        "runtime-confirmed",
        "needs-human-review",
    }
)
# Positive evidence claims; capped at ``needs-human-review`` in Diff-only
# source mode.
UAF_POSITIVE_STATES: Final = frozenset(
    {
        "semantic-supported",
        "fact-verified",
        "tool-corroborated",
        "runtime-confirmed",
    }
)

UAF_REVIEW_CWE: Final = "CWE-416"
UAF_SOURCE_NAME: Final = "cxx-uaf-v2"
UAF_RULE_ID: Final = "cxx.uaf-v2.cwe-416"

_LEVEL_RANK: Final = {
    EvidenceLevel.D0: 0,
    EvidenceLevel.D1: 1,
    EvidenceLevel.D2: 2,
    EvidenceLevel.D3: 3,
    EvidenceLevel.D4: 4,
}

# Honest, state-gated confidence: the score never crosses the Arbiter's
# discrete gates (design 12.3) -- it only orders findings inside a state.
UAF_STATE_CONFIDENCE: Final = {
    "runtime-confirmed": 0.99,
    "fact-verified": 0.97,
    "tool-corroborated": 0.95,
    "semantic-supported": 0.6,
    "needs-human-review": 0.5,
    "abstain": 0.3,
    "rejected": 0.0,
}
_STATE_CONFIDENCE = UAF_STATE_CONFIDENCE

_MAX_SNIPPET_LINES: Final = 200
_MAX_AUDIT_CANDIDATES: Final = 32


# ----------------------------------------------------------------- outcome


@dataclass(frozen=True)
class UafOutcomeCandidate:
    """One candidate's audited journey through the review pipeline.

    ``state`` is the Arbiter's final state; ``rejected_reason`` carries the
    audit reason for non-claims (the refuted obligation for ``rejected``,
    the degradation/deadline/cancel cause for ``abstain``) and stays empty
    for positive states.  Rejected candidates are kept here -- and only
    here -- so the audit trail survives without becoming a Finding.
    """

    identity: CandidateIdentity
    candidate: UafCandidate
    state: str
    broker_verdicts: tuple[Any, ...] = ()
    proof: ProofResult | None = None
    llm: SemanticBranchOutcome | None = None
    rejected_reason: str = ""
    # Bound tool evidence records (wire models records) behind the broker
    # verdicts -- audit payload for the finding projection.
    evidence: tuple[Any, ...] = ()


@dataclass(frozen=True)
class UafReviewStats:
    """Deterministic counters of one review run."""

    tu_count: int
    candidate_count: int
    pass_count: int
    refuted_count: int
    unknown_count: int
    llm_invoked_count: int
    llm_calls: int


@dataclass(frozen=True)
class UafReviewOutcome:
    """Full audit-facing result of one UAF v2 review."""

    candidates: tuple[UafOutcomeCandidate, ...]
    stats: UafReviewStats
    diagnostics: tuple[str, ...] = ()
    translation_units: tuple[str, ...] = ()


# ------------------------------------------------------------------ arbiter


def _valid_support(verdict: Any) -> bool:
    return (
        verdict.verdict == "support"
        and verdict.evidence_polarity is EvidencePolarity.SUPPORTS
        and verdict.evidence_level is not None
        and _LEVEL_RANK[verdict.evidence_level] >= _LEVEL_RANK[EvidenceLevel.D2]
    )


def _valid_contradiction(verdict: Any) -> bool:
    return (
        verdict.verdict == "contradict"
        and verdict.evidence_polarity is EvidencePolarity.REFUTES
        and verdict.evidence_level is not None
        and _LEVEL_RANK[verdict.evidence_level] >= _LEVEL_RANK[EvidenceLevel.D2]
    )


def arbiter_state(
    proof: ProofResult,
    broker_verdicts: Iterable[Any] = (),
    llm_outcome: SemanticBranchOutcome | None = None,
) -> str:
    """Adjudicate one candidate (design 12.3, priority order, deterministic).

    Reads only the proof verdict, contract-validated broker verdicts and
    the semantic outcome -- never free text.  The Diff-only cap is not an
    Arbiter rule: :func:`review_uaf` applies it to the Arbiter's output so
    the pure function stays free of source-mode policy.
    """

    if not isinstance(proof, ProofResult):
        raise ValueError("proof must be a ProofResult")
    brokers = tuple(broker_verdicts or ())
    support = next((item for item in brokers if _valid_support(item)), None)
    contradiction = next(
        (item for item in brokers if _valid_contradiction(item)), None
    )

    if proof.verdict == "REFUTED" and support is not None:
        return "needs-human-review"
    if proof.verdict == "PASS" and contradiction is not None:
        return "needs-human-review"
    if support is not None and support.evidence_level is EvidenceLevel.D3:
        return "runtime-confirmed"
    if proof.verdict == "PASS":
        return "fact-verified"
    if support is not None:
        return "tool-corroborated"
    if proof.verdict == "REFUTED":
        return "rejected"
    if (
        llm_outcome is not None
        and llm_outcome.verdict == "supports-uaf"
        and llm_outcome.level_polarity
        == (EvidenceLevel.D1, EvidencePolarity.SUPPORTS)
    ):
        return "semantic-supported"
    return "abstain"


def _capped(state: str, source_mode: str) -> str:
    """Diff-only cap: positive claims never leave needs-human-review."""

    if source_mode == "diff-only" and state in UAF_POSITIVE_STATES:
        return "needs-human-review"
    return state


# -------------------------------------------------------------- helpers


def _bounded_snippet(workspace: RepositoryWorkspace, candidate: UafCandidate) -> str:
    """A bounded snapshot window around the witness; never empty."""

    fallback = (
        f"source snippet unavailable for {candidate.canonical_path}; "
        f"release range [{candidate.release_range[0]}, "
        f"{candidate.release_range[1]}], use range "
        f"[{candidate.use_range[0]}, {candidate.use_range[1]}]"
    )
    reader = getattr(workspace, "read_text", None)
    if reader is None:
        return fallback
    try:
        text = reader(candidate.canonical_path)
    except (OSError, ValueError, KeyError):
        return fallback
    lines = text.splitlines()
    start = max(1, candidate.release_range[0] - 2)
    end = min(len(lines), candidate.use_range[1] + 2)
    if start > end:
        return fallback
    snippet = "\n".join(lines[start - 1:end][:_MAX_SNIPPET_LINES])
    return snippet if snippet.strip() else fallback


def _completed_run_ids(tool_analysis: Any) -> frozenset[str]:
    if tool_analysis is None:
        return frozenset()
    return frozenset(
        run["run_id"]
        for run in tool_analysis.tool_runs or ()
        if isinstance(run, dict)
        and isinstance(run.get("run_id"), str)
        and run.get("status") == "completed"
    )


def contract_evidence_record(record: Any, candidate_id: str) -> Any:
    """Lift one bound models record into the contract evidence domain.

    The level is the producer-documented assignment (design 5): a bound
    ASan runtime record is D3, static tool records are D2; bound tool
    findings always support the candidate.  Conversion failures fail
    closed (the record is skipped by the caller).
    """

    from .contracts.evidence import EvidenceRecord as ContractRecord
    from .contracts.evidence import EvidenceSubjectKind

    material = json.dumps(
        {
            "source": record.source,
            "path": record.path,
            "line": record.line,
            "snippet": record.snippet,
            "tool_run_id": record.tool_run_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    evidence_id = "ev" + hashlib.sha256(material).hexdigest()[:32]
    runtime = record.source == "asan"
    return ContractRecord(
        evidence_id=evidence_id,
        subject_kind=EvidenceSubjectKind.VULNERABILITY_HYPOTHESIS,
        subject_id=candidate_id,
        level=EvidenceLevel.D3 if runtime else EvidenceLevel.D2,
        polarity=EvidencePolarity.SUPPORTS,
        analysis_family="runtime-sanitizer" if runtime else "static-analysis",
        producer=record.source,
        independence_key=f"{record.source}:{record.path}:{record.line}"[:512],
        summary=(record.snippet or record.path)[:4096] or record.path,
        source_artifact_ids=(record.tool_run_id,) if record.tool_run_id else (),
        reason_codes=("TOOL_EVIDENCE_SUPPORTS",),
        extensions=(
            {"tool_run_id": record.tool_run_id} if record.tool_run_id else {}
        ),
    )


def instrument_broker(
    identity: CandidateIdentity,
    candidate: UafCandidate,
    tool_analysis: Any,
    proof: ProofResult,
    diagnostics: list[str],
) -> tuple[tuple[Any, ...], tuple[Any, ...]]:
    """Bind the tool findings for one candidate and broker per producer."""

    if tool_analysis is None:
        return (), ()
    findings = tuple(tool_analysis.findings or ())
    if not findings:
        return (), ()
    runs = tuple(tool_analysis.tool_runs or ())
    records, gaps = collect_bound_evidence(findings, candidate, runs)
    for gap in gaps:
        diagnostics.append(f"binding gap {gap} for {candidate.candidate_id}")
    verdicts: list[Any] = []
    evidence_records: list[Any] = []
    completed = _completed_run_ids(tool_analysis)
    for producer in sorted({record.source for record in records}):
        producer_records = [
            item for item in records if item.source == producer
        ]
        contract_records = []
        for record in producer_records:
            try:
                contract_records.append(
                    contract_evidence_record(record, candidate.candidate_id)
                )
            except (ContractError, ValueError) as exc:
                diagnostics.append(
                    f"provenance-incomplete record skipped for "
                    f"{candidate.candidate_id}: {exc}"
                )
        if not contract_records:
            continue
        evidence_records.extend(producer_records)
        verdicts.append(
            broker_verdict(
                identity, producer, contract_records, completed, proof
            )
        )
    return tuple(verdicts), tuple(evidence_records)


def instrument_facts(
    analyzer_client: Any,
    *,
    repository_key: str,
    snapshot_hash: str,
    translation_units: tuple[str, ...],
    build_context_mode: str = "snapshot-compdb",
) -> UafFactBundle:
    """Consult the facts instrument: analyzer call -> certified bundle.

    One strict ``/v1/uaf-facts`` request whose response is pinned to the
    review identity by :func:`_expectation_for` and certified by
    :func:`adapt_uaf_response` (fail-closed).  Purely a tool for the
    platform agents; it never produces a conclusion by itself.
    """

    if not callable(getattr(analyzer_client, "analyze_uaf_facts", None)):
        raise ValueError(
            "analyzer_client must expose analyze_uaf_facts "
            "(CxxMemoryAnalyzerClient or a test double)"
        )
    if (
        type(translation_units) is not tuple
        or not translation_units
        or len(translation_units) > MAX_UAF_TRANSLATION_UNITS
        or any(not isinstance(unit, str) or not unit for unit in translation_units)
    ):
        raise ValueError(
            f"translation_units must be a non-empty tuple of at most "
            f"{MAX_UAF_TRANSLATION_UNITS} paths"
        )
    response = analyzer_client.analyze_uaf_facts(
        repository_key,
        snapshot_hash,
        translation_units,
        build_context_mode,
    )
    expectation = _expectation_for(
        response, snapshot_hash, build_context_mode, translation_units
    )
    return adapt_uaf_response(response, expectation)


def instrument_proof(
    candidate: UafCandidate, bundle: UafFactBundle,
) -> ProofResult:
    """Consult the P1-P7 proof instrument for one candidate.

    Pure and deterministic (:func:`lima_uaf_proof.prove_candidate`); the
    candidate's allocation fact selects its unit inside the certified
    bundle.  The verdict is evidence for the arbiter, never a gate.
    """

    if not isinstance(candidate, UafCandidate):
        raise ValueError("candidate must be a UafCandidate")
    if not isinstance(bundle, UafFactBundle):
        raise ValueError("bundle must be a UafFactBundle")
    unit = next(
        (
            unit
            for unit in bundle.per_unit
            for fact in unit.facts
            if fact.fact_id == candidate.allocation_fact_id
        ),
        None,
    )
    if unit is None:
        raise ValueError(
            f"candidate {candidate.candidate_id} allocation fact is not in "
            "the certified bundle"
        )
    return prove_candidate(candidate, bundle, unit.build_context, unit.coverage)


def _expectation_for(
    response: UafFactsResponse,
    snapshot_hash: str,
    build_context_mode: str,
    translation_units: tuple[str, ...],
) -> FactBundleExpectation:
    """Build the bundle expectation for one strictly validated response.

    The frozen Sidecar protocol has no out-of-band channel for the
    per-unit build-context hash or the server-side tool-run id, so the
    expectation pins them from the response the strict client just
    certified (echo identity, closed schema, re-derived bundle digest):

    - one distinct hash over the completed units is the single anchor;
    - distinct compdb entries give completed units legitimately distinct
      context hashes, so the expectation carries the closed allowlist of
      every observed hash with an empty anchor instead of failing the
      identity chain -- each completed unit is still re-checked against
      that allowlist by :func:`adapt_uaf_response` (invariant 8 is
      membership, not uniformity);
    - units with no completed extraction pin a review-identity digest
      instead -- they carry no facts, so nothing can pass the
      completeness gate.
    """

    completed: set[str] = set()
    for unit in response.translation_units:
        if (
            isinstance(unit, dict)
            and unit.get("extraction") == "completed"
            and isinstance(unit.get("build_context"), dict)
        ):
            completed.add(str(unit["build_context"].get("context_hash") or ""))
    allowed_hashes: frozenset[str] = frozenset()
    if len(completed) == 1:
        context_hash = next(iter(completed))
        allowed_hashes = frozenset(completed)
    elif completed:
        # Completed units legitimately disagree on their build context:
        # allowlist every observed hash so the identity chain stays closed
        # as a membership check, never a mixed or fuzzy context.
        context_hash = ""
        allowed_hashes = frozenset(completed)
    else:
        material = json.dumps(
            {
                "snapshot": snapshot_hash,
                "mode": build_context_mode,
                "units": list(translation_units),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        context_hash = hashlib.sha256(material).hexdigest()
    run_ids = frozenset(
        run["run_id"]
        for run in response.tool_runs
        if isinstance(run, dict) and isinstance(run.get("run_id"), str)
    )
    return FactBundleExpectation(
        snapshot_hash=snapshot_hash,
        build_context_hash=context_hash,
        repository_root="",
        allowed_tool_runs=run_ids,
        allowed_context_hashes=allowed_hashes,
    )


def _semantic_outcome(
    candidate: UafCandidate,
    unit: UnitFacts,
    proof: ProofResult,
    snippet: str,
    llm_config: Mapping[str, object],
    budget: CxxAgentBudget,
    mode: str,
    dialogue_rounds: int,
    timeout: int,
) -> SemanticBranchOutcome:
    """Run the UNKNOWN-only branch with mode-faithful failure semantics."""

    try:
        return run_semantic_branch(
            SPECIALIST_ROLE,
            dict(llm_config),
            candidate,
            unit.facts,
            proof,
            unit.coverage,
            snippet,
            budget,
            mode,
            dialogue_rounds=dialogue_rounds,
            timeout=timeout,
        )
    except ValueError as exc:
        # Provider not configured / invalid resolution: under ``required``
        # the fallback must not be silently missing, so the task fails
        # before any wire call; ``auto`` records the degradation.
        if mode == MODE_REQUIRED:
            raise RuntimeError(
                "UAF review required the semantic fallback but no usable "
                f"LLM provider is configured: {exc}"
            ) from exc
        return SemanticBranchOutcome(
            invoked=False, calls=0, verdict="abstain", level_polarity=None,
            specialist_reply=None, critic_reply=None,
            degradation="llm-unavailable",
        )


def _abstain_outcome(reason: str) -> SemanticBranchOutcome:
    return SemanticBranchOutcome(
        invoked=False, calls=0, verdict="abstain", level_polarity=None,
        specialist_reply=None, critic_reply=None, degradation=reason,
    )


# --------------------------------------------------------------- entry point


def review_uaf(
    analyzer_client: Any,
    workspace: RepositoryWorkspace,
    *,
    repository_key: str,
    snapshot_hash: str,
    translation_units: tuple[str, ...],
    build_context_mode: str = "snapshot-compdb",
    mode: str = "auto",
    budget: CxxAgentBudget | None = None,
    tool_analysis: Any = None,
    llm_config: Mapping[str, object] | None = None,
    deadline: float | None = None,
    parallelism: int = 1,
    dialogue_rounds: int = 1,
    timeout: int = 60,
    source_mode: str = "repository",
    should_cancel: Any = None,
) -> UafReviewOutcome:
    """Run the frozen v2 evaluation chain over the requested TUs.

    **Retired from the production path**: no production module imports this
    any more -- the scanner runs the single agent chain
    (:func:`lima.agent_orchestrator.run_platform_review`).  This entry keeps
    its exact historical behavior only because the pinned UAF v2 evaluation
    harness (``scripts/run_uaf_v2_evaluation.py`` and
    ``tests/test_uaf_v2_evaluation.py``) drives it; the harness migrates to
    the platform chain with platform plan Task 10.  New code must consult
    the instruments (:func:`instrument_facts`, :func:`instrument_proof`,
    :func:`instrument_broker`) through the platform orchestrator instead.

    ``translation_units`` is the caller's TU selection (the scanner passes
    the snapshot's C/C++ sources); the request and the review stay bounded
    by ``MAX_UAF_TRANSLATION_UNITS``.  All failure semantics are
    mode-faithful per design 12.2; transport and protocol errors of the
    strict client propagate to the caller.
    """

    if not callable(getattr(analyzer_client, "analyze_uaf_facts", None)):
        raise ValueError(
            "analyzer_client must expose analyze_uaf_facts "
            "(CxxMemoryAnalyzerClient or a test double)"
        )
    if not isinstance(workspace, RepositoryWorkspace):
        raise ValueError("workspace must be a RepositoryWorkspace")
    if mode not in AGENT_MODES:
        raise ValueError("mode must be off, auto or required")
    if build_context_mode not in UAF_FACTS_BUILD_CONTEXT_MODES:
        raise ValueError("build_context_mode is outside the closed domain")
    if source_mode not in SOURCE_MODES:
        raise ValueError("source_mode must be repository or diff-only")
    if (
        type(translation_units) is not tuple
        or not translation_units
        or len(translation_units) > MAX_UAF_TRANSLATION_UNITS
        or any(not isinstance(unit, str) or not unit for unit in translation_units)
    ):
        raise ValueError(
            f"translation_units must be a non-empty tuple of at most "
            f"{MAX_UAF_TRANSLATION_UNITS} paths"
        )
    if isinstance(parallelism, bool) or not isinstance(parallelism, int) \
            or parallelism < 1:
        raise ValueError("parallelism must be a positive integer")
    if isinstance(dialogue_rounds, bool) or not isinstance(dialogue_rounds, int) \
            or dialogue_rounds < 0:
        raise ValueError("dialogue_rounds must be a non-negative integer")
    if deadline is not None and (
        isinstance(deadline, bool) or not isinstance(deadline, int | float)
    ):
        raise ValueError("deadline must be a monotonic timestamp or None")

    diagnostics: list[str] = []
    resolved_llm = dict(llm_config) if llm_config else {}
    rounds = max(1, dialogue_rounds)
    run_budget = budget if budget is not None else CxxAgentBudget()

    def _expired() -> bool:
        return deadline is not None and time.monotonic() >= deadline

    def _cancelled() -> bool:
        return bool(should_cancel is not None and should_cancel())

    def _branch_timeout() -> int | None:
        """The semantic-branch timeout capped by the remaining deadline.

        ``None`` means the deadline already passed; a fractional remainder
        floors onto the one-second wire minimum so the timeout contract
        stays a positive integer.
        """

        if deadline is None:
            return timeout
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        return max(1, min(timeout, int(remaining)))

    if _expired():
        return UafReviewOutcome(
            candidates=(),
            stats=UafReviewStats(0, 0, 0, 0, 0, 0, 0),
            diagnostics=("deadline-exceeded before the UAF review started",),
            translation_units=translation_units,
        )
    if _cancelled():
        return UafReviewOutcome(
            candidates=(),
            stats=UafReviewStats(0, 0, 0, 0, 0, 0, 0),
            diagnostics=("cancelled before the UAF review started",),
            translation_units=translation_units,
        )

    response = analyzer_client.analyze_uaf_facts(
        repository_key,
        snapshot_hash,
        translation_units,
        build_context_mode,
    )
    expectation = _expectation_for(
        response, snapshot_hash, build_context_mode, translation_units
    )
    bundle = adapt_uaf_response(response, expectation)
    candidates = generate_candidates(bundle)
    unit_by_fact = {
        fact.fact_id: unit
        for unit in bundle.per_unit
        for fact in unit.facts
    }

    # Phase 1: deterministic proof + tool evidence, in candidate order.
    prepared: list[dict[str, Any]] = []
    for candidate in candidates:
        identity = CandidateIdentity(snapshot_hash, candidate.candidate_id)
        if _expired():
            prepared.append({
                "identity": identity, "candidate": candidate,
                "skip": "deadline-exceeded",
            })
            diagnostics.append(
                f"deadline-exceeded before candidate {candidate.candidate_id}"
            )
            continue
        if _cancelled():
            prepared.append({
                "identity": identity, "candidate": candidate,
                "skip": "cancelled",
            })
            diagnostics.append(
                f"cancelled before candidate {candidate.candidate_id}"
            )
            continue
        unit = unit_by_fact[candidate.allocation_fact_id]
        proof = prove_candidate(
            candidate, bundle, unit.build_context, unit.coverage
        )
        verdicts, evidence = instrument_broker(
            identity, candidate, tool_analysis, proof, diagnostics
        )
        prepared.append({
            "identity": identity,
            "candidate": candidate,
            "unit": unit,
            "proof": proof,
            "verdicts": verdicts,
            "evidence": evidence,
        })

    # Phase 2: the UNKNOWN-only LLM branches, optionally concurrent; the
    # result order stays the deterministic candidate order.
    pending = [item for item in prepared if "skip" not in item
               and item["proof"].verdict == "UNKNOWN"]
    if pending and mode != "off":
        workers = min(parallelism, len(pending))

        def _branch(item: dict[str, Any]) -> SemanticBranchOutcome:
            if _expired():
                return _abstain_outcome("deadline-exceeded")
            if _cancelled():
                return _abstain_outcome("cancelled")
            branch_timeout = _branch_timeout()
            if branch_timeout is None:
                return _abstain_outcome("deadline-exceeded")
            return _semantic_outcome(
                item["candidate"], item["unit"], item["proof"],
                _bounded_snippet(workspace, item["candidate"]), resolved_llm,
                run_budget, mode, rounds, branch_timeout,
            )

        if workers > 1:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                outcomes = list(pool.map(_branch, pending))
        else:
            outcomes = [_branch(item) for item in pending]
        by_candidate = {
            item["candidate"].candidate_id: outcome
            for item, outcome in zip(pending, outcomes, strict=True)
        }
    else:
        by_candidate = {}

    # Phase 3: deterministic adjudication in candidate order.
    outcome_candidates: list[UafOutcomeCandidate] = []
    pass_count = refuted_count = unknown_count = 0
    llm_invoked = llm_calls = 0
    for item in prepared:
        candidate = item["candidate"]
        if "skip" in item:
            outcome_candidates.append(UafOutcomeCandidate(
                identity=item["identity"], candidate=candidate,
                state="abstain", rejected_reason=item["skip"],
            ))
            unknown_count += 1
            continue
        proof: ProofResult = item["proof"]
        llm = by_candidate.get(candidate.candidate_id)
        state = _capped(
            arbiter_state(proof, item["verdicts"], llm), source_mode
        )
        reason = ""
        if state == "rejected":
            refuted = next(
                (
                    entry
                    for entry in proof.obligations
                    if entry.verdict == "refuted"
                ),
                None,
            )
            reason = (
                f"{refuted.obligation.value}: {refuted.reason}"
                if refuted is not None
                else "proof refuted"
            )
        elif state == "abstain":
            reason = (
                llm.degradation
                if llm is not None and llm.degradation
                else "unknown proof without a usable semantic opinion"
            )
        outcome_candidates.append(UafOutcomeCandidate(
            identity=item["identity"], candidate=candidate, state=state,
            broker_verdicts=item["verdicts"], proof=proof, llm=llm,
            rejected_reason=reason, evidence=item["evidence"],
        ))
        if proof.verdict == "PASS":
            pass_count += 1
        elif proof.verdict == "REFUTED":
            refuted_count += 1
        else:
            unknown_count += 1
        if llm is not None:
            llm_invoked += 1 if llm.invoked else 0
            llm_calls += llm.calls

    stats = UafReviewStats(
        tu_count=len(bundle.per_unit),
        candidate_count=len(candidates),
        pass_count=pass_count,
        refuted_count=refuted_count,
        unknown_count=unknown_count,
        llm_invoked_count=llm_invoked,
        llm_calls=llm_calls,
    )
    for gap in bundle.coverage_gaps:
        diagnostics.append(f"coverage gap: {gap}")
    return UafReviewOutcome(
        candidates=tuple(outcome_candidates),
        stats=stats,
        diagnostics=tuple(diagnostics),
        translation_units=translation_units,
    )
