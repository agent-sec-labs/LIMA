"""Deterministic semantic prioritizer / Top-N layer for repository RAM facts (IP-0019).

Layer 3 of the repository profile stack: consume the frozen
:class:`lima.audit.ram.PythonRamFacts` (IP-0018) as the only source of truth
and produce an independent carrier ``SemanticTopNResult`` holding a ranked
Top-N board (at most ``top_n`` candidates) with model-supplemented
category/rationale plus typed semantic coverage gaps.

Frozen behaviour (Packet ``IP-0019-PACKET/v1.1``):

- two-layer structure: the Tier 0 facts are consumed read-only and never
  rewritten, filtered, or reordered; the ranked board is a supplementary view
  and never replaces the base layer;
- candidate IDs are collision-free and replayable:
  ``{kind}:{path}:{symbol|-}#{ordinal}`` with the 0-based index inside the
  source tuple;
- scoring is fully deterministic from static facts and configured weights;
  the model can never influence score, rank, or board membership, and an
  out-of-set candidate ID, out-of-vocabulary category, or leaking rationale
  makes the whole batch fall back (candidates are never deleted);
- model calls happen only when a protocol client is injected AND
  ``options.model_id != "unset"``; there is no implicit enablement channel,
  no network facility, no subprocess, no environment read and no file write,
  so tests and CI default to zero paid calls;
- every model call passes five pre-call budget checkpoints (fail-closed);
  off/timeout/malformed/budget-exhaustion degrade to deterministic fallbacks
  plus typed gaps, and ``BUDGET_EXHAUSTED`` carries the mandatory
  ``not-an-absence-of-risk`` note;
- all digests are ``compute_content_digest`` products (64-hex), include every
  budget configuration value and exclude elapsed time; ``seed`` participates
  in identity only (zero randomness in the current frozen ranking);
- failures are fail-closed: invalid arguments raise
  :class:`lima.contracts.errors.ContractError` or ``ValueError`` and model
  path failures never propagate to the caller.
"""

from __future__ import annotations

import json
import re
import time
import unicodedata
from dataclasses import dataclass, field
from typing import Final, Protocol

from lima.audit.ram import PythonRamFacts, ram_facts_digest
from lima.contracts.codec import compute_content_digest
from lima.contracts.errors import ContractError, ContractErrorCode
from lima.contracts.profile import ProfileCoverageGap

__all__ = [
    "GAP_SEMANTIC_MALFORMED_OUTPUT",
    "GAP_SEMANTIC_MODEL_OFF",
    "GAP_SEMANTIC_MODEL_TIMEOUT",
    "SEMANTIC_CATEGORY_CODE_EXECUTION",
    "SEMANTIC_CATEGORY_COMMAND_EXECUTION",
    "SEMANTIC_CATEGORY_DESERIALIZATION",
    "SEMANTIC_CATEGORY_ENTRYPOINT",
    "SEMANTIC_CATEGORY_EXTERNAL_INPUT",
    "SEMANTIC_CATEGORY_PATH_TRAVERSAL",
    "SEMANTIC_CATEGORY_SQL_INJECTION",
    "SEMANTIC_CATEGORY_TRUST_BOUNDARY",
    "SEMANTIC_CATEGORY_UNRESOLVED_EDGE",
    "SEMANTIC_MAX_TOP_N",
    "SEMANTIC_PROVENANCE_ANCHOR",
    "SemanticBudgets",
    "SemanticCandidate",
    "SemanticModelClient",
    "SemanticOptions",
    "SemanticTopNResult",
    "SemanticWeights",
    "build_semantic_top_n",
    "candidate_id",
    "semantic_config_digest",
    "semantic_result_digest",
]

SEMANTIC_PROVENANCE_ANCHOR: Final[str] = "semantic-prioritizer"

SEMANTIC_MAX_TOP_N: Final[int] = 100

GAP_SEMANTIC_MODEL_OFF: Final[str] = "SEMANTIC_MODEL_OFF"
GAP_SEMANTIC_MODEL_TIMEOUT: Final[str] = "SEMANTIC_MODEL_TIMEOUT"
GAP_SEMANTIC_MALFORMED_OUTPUT: Final[str] = "SEMANTIC_MALFORMED_OUTPUT"

#: Frozen IP-0016 gap semantics reused by value (Packet §4/§5.6.4): the
#: semantic layer must not import :mod:`lima.audit.inventory` (dependency
#: direction), so the identical frozen gap-code string is restated here.
_GAP_BUDGET_EXHAUSTED: Final[str] = "BUDGET_EXHAUSTED"

SEMANTIC_CATEGORY_COMMAND_EXECUTION: Final[str] = "command-execution"
SEMANTIC_CATEGORY_SQL_INJECTION: Final[str] = "sql-injection"
SEMANTIC_CATEGORY_CODE_EXECUTION: Final[str] = "code-execution"
SEMANTIC_CATEGORY_PATH_TRAVERSAL: Final[str] = "path-traversal"
SEMANTIC_CATEGORY_DESERIALIZATION: Final[str] = "deserialization"
SEMANTIC_CATEGORY_EXTERNAL_INPUT: Final[str] = "external-input"
SEMANTIC_CATEGORY_ENTRYPOINT: Final[str] = "entrypoint"
SEMANTIC_CATEGORY_TRUST_BOUNDARY: Final[str] = "trust-boundary"
SEMANTIC_CATEGORY_UNRESOLVED_EDGE: Final[str] = "unresolved-edge"

_CATEGORY_VOCABULARY: Final[frozenset[str]] = frozenset(
    {
        SEMANTIC_CATEGORY_COMMAND_EXECUTION,
        SEMANTIC_CATEGORY_SQL_INJECTION,
        SEMANTIC_CATEGORY_CODE_EXECUTION,
        SEMANTIC_CATEGORY_PATH_TRAVERSAL,
        SEMANTIC_CATEGORY_DESERIALIZATION,
        SEMANTIC_CATEGORY_EXTERNAL_INPUT,
        SEMANTIC_CATEGORY_ENTRYPOINT,
        SEMANTIC_CATEGORY_TRUST_BOUNDARY,
        SEMANTIC_CATEGORY_UNRESOLVED_EDGE,
    }
)

_KIND_SENSITIVE_SINK: Final[str] = "sensitive-sink"
_KIND_ENTRYPOINT: Final[str] = "entrypoint"
_KIND_EXTERNAL_SOURCE: Final[str] = "external-source"
_KIND_TRUST_BOUNDARY: Final[str] = "trust-boundary"
_KIND_UNRESOLVED_EDGE: Final[str] = "unresolved-edge"

_KIND_ORDER: Final[dict[str, int]] = {
    _KIND_SENSITIVE_SINK: 0,
    _KIND_ENTRYPOINT: 1,
    _KIND_EXTERNAL_SOURCE: 2,
    _KIND_TRUST_BOUNDARY: 3,
    _KIND_UNRESOLVED_EDGE: 4,
}

_SINK_RULE_WEIGHT_FIELD: Final[dict[str, str]] = {
    "FLOW-EVAL": "sink_flow_eval",
    "FLOW-COMMAND": "sink_flow_command",
    "FLOW-SQL": "sink_flow_sql",
    "FLOW-PATH": "sink_flow_path",
    "FLOW-DESERIALIZATION": "sink_flow_deserialization",
}

_SINK_RULE_CATEGORY: Final[dict[str, str]] = {
    "FLOW-EVAL": SEMANTIC_CATEGORY_CODE_EXECUTION,
    "FLOW-COMMAND": SEMANTIC_CATEGORY_COMMAND_EXECUTION,
    "FLOW-SQL": SEMANTIC_CATEGORY_SQL_INJECTION,
    "FLOW-PATH": SEMANTIC_CATEGORY_PATH_TRAVERSAL,
    "FLOW-DESERIALIZATION": SEMANTIC_CATEGORY_DESERIALIZATION,
}

_TIE_BREAK_FROZEN: Final[str] = "kind-path-symbol-ordinal"

_RATIONALE_MAX_BYTES: Final[int] = 512

#: Frozen per-candidate output size estimate used by the pre-call output/total
#: token checkpoints (Packet §5.5 clarification of the frozen test contract).
_PER_CANDIDATE_OUTPUT_TOKENS: Final[int] = 128

_DEFAULT_PROMPT_TEMPLATE: Final[str] = (
    "You assist a static repository security audit. Below is a JSON array of "
    "candidates; each descriptor carries candidate_id, kind, path, symbol, "
    "category (the deterministic fallback category) and rule_id. Reply with a "
    "JSON array where every item has exactly the keys candidate_id, category "
    "and rationale. Use only the provided candidate_id values, pick category "
    "only from the provided category vocabulary, and write for every rationale "
    "a short non-empty plain-text sentence without source code, credentials or "
    "new candidates. Candidates: {descriptors}"
)

_WEIGHT_FIELD_NAMES: Final[tuple[str, ...]] = (
    "sink_flow_command",
    "sink_flow_sql",
    "sink_flow_eval",
    "sink_flow_path",
    "sink_flow_deserialization",
    "entrypoint",
    "external_source",
    "trust_boundary",
    "unresolved_edge",
)

_BUDGET_FIELD_NAMES: Final[tuple[str, ...]] = (
    "max_llm_calls",
    "max_prompt_tokens_estimate",
    "max_output_tokens_estimate",
    "max_total_tokens_estimate",
    "max_wall_time_seconds",
)

_SECRET_TOKEN_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"AKIA[0-9A-Z]{16}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|ghp_[0-9A-Za-z]{36}"
    r"|xox[baprs]-[0-9A-Za-z-]{10,}"
    r"|eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}"
)

#: Dotted-attribute call syntax such as ``os.system(`` or
#: ``request.args.get(`` marks leaked source-level detail (Packet §5.8).
_CODE_FRAGMENT_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*\s*\("
)


@dataclass(frozen=True)
class SemanticWeights:
    """Frozen non-negative scoring weights; the only score inputs (B-6)."""

    sink_flow_command: int = 80
    sink_flow_sql: int = 80
    sink_flow_eval: int = 90
    sink_flow_path: int = 70
    sink_flow_deserialization: int = 70
    entrypoint: int = 60
    external_source: int = 50
    trust_boundary: int = 40
    unresolved_edge: int = 30

    def __post_init__(self) -> None:
        for name in _WEIGHT_FIELD_NAMES:
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")


@dataclass(frozen=True)
class SemanticBudgets:
    """Frozen pre-call budgets for the semantic model pass (A-2, B-9).

    Named independently of ``ProfileBudgets``/``RamBudgets``; every value is a
    positive integer and the total upper bound must satisfy
    ``max_total_tokens_estimate >= max_prompt_tokens_estimate
    + max_output_tokens_estimate``. All six configuration values enter the
    config digest; actual elapsed time and actual token consumption never do.
    """

    max_llm_calls: int = 8
    max_prompt_tokens_estimate: int = 24_000
    max_output_tokens_estimate: int = 4_096
    max_total_tokens_estimate: int = 28_096
    max_wall_time_seconds: int = 120

    def __post_init__(self) -> None:
        for name in _BUDGET_FIELD_NAMES:
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        minimum_total = self.max_prompt_tokens_estimate + self.max_output_tokens_estimate
        if self.max_total_tokens_estimate < minimum_total:
            raise ValueError(
                "max_total_tokens_estimate must be >= max_prompt_tokens_estimate"
                " + max_output_tokens_estimate"
            )


@dataclass(frozen=True)
class SemanticOptions:
    """Frozen FR-04 parameter carrier for one semantic prioritization (A-1).

    ``seed`` participates in identity only: the frozen ranking is purely
    deterministic, so changing the seed changes digests but never the board.
    """

    top_n: int = 20
    weights: SemanticWeights = field(default_factory=SemanticWeights)
    seed: int = 0
    budgets: SemanticBudgets = field(default_factory=SemanticBudgets)
    model_id: str = "unset"
    prompt_template: str = _DEFAULT_PROMPT_TEMPLATE
    tie_break: str = _TIE_BREAK_FROZEN

    def __post_init__(self) -> None:
        if type(self.top_n) is not int or not 1 <= self.top_n <= SEMANTIC_MAX_TOP_N:
            raise ValueError("top_n must be an integer in [1, 100]")
        if not isinstance(self.weights, SemanticWeights):
            raise ValueError("weights must be a SemanticWeights instance")
        if type(self.seed) is not int or self.seed < 0:
            raise ValueError("seed must be a non-negative integer")
        if not isinstance(self.budgets, SemanticBudgets):
            raise ValueError("budgets must be a SemanticBudgets instance")
        if not isinstance(self.model_id, str):
            raise ValueError("model_id must be a string")
        if not isinstance(self.prompt_template, str):
            raise ValueError("prompt_template must be a string")
        if self.tie_break != _TIE_BREAK_FROZEN:
            raise ValueError(f"tie_break must be {_TIE_BREAK_FROZEN!r}")


class SemanticModelClient(Protocol):
    """Read-only port for one model completion (B-8); no built-in network."""

    def complete(self, prompt: str, *, timeout_seconds: int) -> str: ...


@dataclass(frozen=True)
class SemanticCandidate:
    """One ranked board entry; semantic fields live only here (B-10)."""

    candidate_id: str
    kind: str
    path: str
    symbol: str | None
    score: int
    rank: int
    category: str
    rationale: str
    key_flow_steps: tuple[str, ...]


@dataclass(frozen=True)
class SemanticTopNResult:
    """Independent semantic carrier; never touches profile extensions (B-10)."""

    ranked: tuple[SemanticCandidate, ...]
    total_candidates: int
    coverage_gaps: tuple[ProfileCoverageGap, ...]
    prompt_digest: str
    model_digest: str
    config_digest: str
    result_digest: str
    provenance_anchor_ids: tuple[str, ...] = (SEMANTIC_PROVENANCE_ANCHOR,)


@dataclass(frozen=True)
class _Candidate:
    """Internal pre-ranking record with deterministic fallback semantics."""

    candidate_id: str
    kind: str
    path: str
    symbol: str | None
    score: int
    ordinal: int
    category: str
    rule_id: str
    key_flow_steps: tuple[str, ...]


def candidate_id(kind: str, path: str, symbol: str | None, ordinal: int) -> str:
    """Return the frozen collision-free candidate ID (B-7)."""

    suffix = symbol if symbol is not None else "-"
    return f"{kind}:{path}:{suffix}#{ordinal}"


def _fallback_rationale(kind: str) -> str:
    return f"deterministic fallback; kind={kind}"


def _estimate_tokens(text: str) -> int:
    """Return the frozen uppercase-bound token estimate ``ceil(chars / 4)``."""

    return max(1, (len(text) + 3) // 4)


def _bounded_rationale(text: str) -> str | None:
    """Bound and screen one model rationale; ``None`` means malformed (§5.4.3).

    NFC-normalize, drop control characters, strip, reject secret-shaped or
    source-code-shaped content, then truncate to 512 UTF-8 bytes on a whole
    character boundary. An empty residue is malformed as well.
    """

    normalized = unicodedata.normalize("NFC", text)
    normalized = "".join(
        char for char in normalized if unicodedata.category(char) != "Cc"
    )
    normalized = normalized.strip()
    if not normalized:
        return None
    if _SECRET_TOKEN_PATTERN.search(normalized) is not None:
        return None
    if _CODE_FRAGMENT_PATTERN.search(normalized) is not None:
        return None
    encoded = normalized.encode("utf-8")
    if len(encoded) > _RATIONALE_MAX_BYTES:
        normalized = encoded[:_RATIONALE_MAX_BYTES].decode("utf-8", errors="ignore")
    return normalized


def _render_prompt(batch: list[_Candidate]) -> str:
    """Render one batch prompt from descriptors only (no source text, §5.4.2)."""

    descriptors = [
        {
            "candidate_id": item.candidate_id,
            "kind": item.kind,
            "path": item.path,
            "symbol": item.symbol if item.symbol is not None else "",
            "category": item.category,
            "rule_id": item.rule_id,
        }
        for item in batch
    ]
    payload = json.dumps(
        descriptors, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )
    return _DEFAULT_PROMPT_TEMPLATE.replace("{descriptors}", payload)


def _validated_entries(
    response: str, batch: list[_Candidate]
) -> tuple[list[tuple[str, str, str]] | None, str]:
    """Validate one model batch response; return entries or (None, offending)."""

    try:
        parsed = json.loads(response)
    except ValueError:
        return None, "json"
    if not isinstance(parsed, list):
        return None, "json"
    batch_ids = {item.candidate_id for item in batch}
    entries: list[tuple[str, str, str]] = []
    for item in parsed:
        if not isinstance(item, dict):
            return None, "json"
        candidate = item.get("candidate_id")
        if not isinstance(candidate, str) or candidate not in batch_ids:
            return None, "candidate_id"
        category = item.get("category")
        if not isinstance(category, str) or category not in _CATEGORY_VOCABULARY:
            return None, "category"
        raw_rationale = item.get("rationale")
        if not isinstance(raw_rationale, str):
            return None, "rationale"
        rationale = _bounded_rationale(raw_rationale)
        if rationale is None:
            return None, "rationale"
        entries.append((candidate, category, rationale))
    return entries, ""


def _run_model_pass(
    ordered: list[_Candidate],
    options: SemanticOptions,
    model_client: SemanticModelClient,
) -> tuple[dict[str, tuple[str, str]], list[tuple[str, str]]]:
    """Run the batched model pass under the frozen pre-call checkpoints (§5.5).

    Returns the enrichment map and any semantic gap pairs produced by
    timeout, budget exhaustion, or malformed batches. Never raises for model
    path failures; only entry-contract violations reach the caller.
    """

    budgets = options.budgets
    batch_size = max(1, budgets.max_llm_calls)
    enrichment: dict[str, tuple[str, str]] = {}
    gap_pairs: list[tuple[str, str]] = []
    calls_made = 0
    processed = 0
    stop_stage: str | None = None
    timeout_batch: int | None = None
    malformed: tuple[int, str] | None = None
    start = time.monotonic()
    for batch_index in range(0, len(ordered), batch_size):
        batch = ordered[batch_index : batch_index + batch_size]
        if calls_made >= budgets.max_llm_calls:
            stop_stage = "llm-calls"
            break
        prompt = _render_prompt(batch)
        prompt_estimate = _estimate_tokens(prompt)
        if prompt_estimate > budgets.max_prompt_tokens_estimate:
            stop_stage = "prompt-tokens"
            break
        output_estimate = _PER_CANDIDATE_OUTPUT_TOKENS * len(batch)
        if output_estimate > budgets.max_output_tokens_estimate:
            stop_stage = "output-tokens"
            break
        if (
            prompt_estimate + budgets.max_output_tokens_estimate
            > budgets.max_total_tokens_estimate
        ):
            stop_stage = "total-tokens"
            break
        elapsed = time.monotonic() - start
        if elapsed >= budgets.max_wall_time_seconds:
            stop_stage = "wall-time"
            break
        timeout_seconds = max(1, int(budgets.max_wall_time_seconds - elapsed))
        calls_made += 1
        entries: list[tuple[str, str, str]] | None
        offending: str
        try:
            response = model_client.complete(prompt, timeout_seconds=timeout_seconds)
        except TimeoutError:
            timeout_batch = batch_index
            break
        except Exception:
            # Any other protocol failure must not propagate (Packet §5.0);
            # the batch falls back and is recorded as a malformed batch.
            entries = None
            offending = "exception"
        else:
            entries, offending = _validated_entries(response, batch)
        if entries is None:
            if malformed is None:
                malformed = (batch_index, offending)
        else:
            for cid, category, rationale in entries:
                enrichment[cid] = (category, rationale)
        processed += len(batch)
    if timeout_batch is not None:
        gap_pairs.append(
            (
                GAP_SEMANTIC_MODEL_TIMEOUT,
                f"reason=model-timeout; batch={timeout_batch}",
            )
        )
    if stop_stage is not None and processed < options.top_n:
        pending = len(ordered) - processed
        gap_pairs.append(
            (
                _GAP_BUDGET_EXHAUSTED,
                f"reason=semantic-budget; stage={stop_stage}; pending={pending}; "
                "note=semantic-coverage-incomplete; not-an-absence-of-risk",
            )
        )
    if malformed is not None:
        gap_pairs.append(
            (
                GAP_SEMANTIC_MALFORMED_OUTPUT,
                f"batch={malformed[0]}; offending={malformed[1]}",
            )
        )
    return enrichment, gap_pairs


_FROZEN_INVENTORIES: tuple[str, ...] = (
    "entrypoints",
    "external_sources",
    "sensitive_sinks",
    "trust_boundaries",
    "unresolved_edges",
)


def _reject_dash_symbols(facts: PythonRamFacts) -> None:
    from lima.contracts.errors import ContractError, ContractErrorCode

    for section in _FROZEN_INVENTORIES:
        for index, entry in enumerate(getattr(facts, section)):
            if entry.symbol == "-":
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    f"$.facts.{section}[{index}].symbol",
                )


def _collect_candidates(
    facts: PythonRamFacts, weights: SemanticWeights
) -> list[_Candidate]:
    """Map the five frozen RAM inventories into scored candidates (§5.2.1)."""

    candidates: list[_Candidate] = []
    for ordinal, entry in enumerate(facts.sensitive_sinks):
        if ordinal >= len(facts.sink_rule_ids):
            raise ValueError("sensitive_sinks must be parallel to sink_rule_ids")
        rule_id = facts.sink_rule_ids[ordinal]
        weight_field = _SINK_RULE_WEIGHT_FIELD.get(rule_id)
        category = _SINK_RULE_CATEGORY.get(rule_id)
        if weight_field is None or category is None:
            raise ValueError(f"unknown sensitive sink rule id: {rule_id}")
        key_flow_steps: tuple[str, ...] = ()
        if ordinal < len(facts.key_flows):
            key_flow_steps = facts.key_flows[ordinal].steps
        candidates.append(
            _Candidate(
                candidate_id=candidate_id(
                    _KIND_SENSITIVE_SINK, entry.path, entry.symbol, ordinal
                ),
                kind=_KIND_SENSITIVE_SINK,
                path=entry.path,
                symbol=entry.symbol,
                score=getattr(weights, weight_field),
                ordinal=ordinal,
                category=category,
                rule_id=rule_id,
                key_flow_steps=key_flow_steps,
            )
        )
    simple_kinds: tuple[tuple[str, str, int], ...] = (
        (_KIND_ENTRYPOINT, SEMANTIC_CATEGORY_ENTRYPOINT, weights.entrypoint),
        (_KIND_EXTERNAL_SOURCE, SEMANTIC_CATEGORY_EXTERNAL_INPUT, weights.external_source),
        (_KIND_TRUST_BOUNDARY, SEMANTIC_CATEGORY_TRUST_BOUNDARY, weights.trust_boundary),
        (_KIND_UNRESOLVED_EDGE, SEMANTIC_CATEGORY_UNRESOLVED_EDGE, weights.unresolved_edge),
    )
    inventories: dict[str, tuple[object, ...]] = {
        _KIND_ENTRYPOINT: facts.entrypoints,
        _KIND_EXTERNAL_SOURCE: facts.external_sources,
        _KIND_TRUST_BOUNDARY: facts.trust_boundaries,
        _KIND_UNRESOLVED_EDGE: facts.unresolved_edges,
    }
    for kind, category, score in simple_kinds:
        for ordinal, entry in enumerate(inventories[kind]):
            candidates.append(
                _Candidate(
                    candidate_id=candidate_id(kind, entry.path, entry.symbol, ordinal),
                    kind=kind,
                    path=entry.path,
                    symbol=entry.symbol,
                    score=score,
                    ordinal=ordinal,
                    category=category,
                    rule_id="",
                    key_flow_steps=(),
                )
            )
    return candidates


def _sort_key(candidate: _Candidate) -> tuple[int, int, str, str, int]:
    """Return the frozen total order key (B-6); never yields ties on IDs."""

    return (
        -candidate.score,
        _KIND_ORDER[candidate.kind],
        candidate.path,
        candidate.symbol if candidate.symbol is not None else "",
        candidate.ordinal,
    )


def _assemble_ranked(
    ordered: list[_Candidate],
    top_n: int,
    enrichment: dict[str, tuple[str, str]],
) -> tuple[SemanticCandidate, ...]:
    """Truncate to ``top_n`` and finalize rank/category/rationale per entry."""

    ranked: list[SemanticCandidate] = []
    for rank, item in enumerate(ordered[:top_n], start=1):
        category, rationale = enrichment.get(
            item.candidate_id, (item.category, _fallback_rationale(item.kind))
        )
        ranked.append(
            SemanticCandidate(
                candidate_id=item.candidate_id,
                kind=item.kind,
                path=item.path,
                symbol=item.symbol,
                score=item.score,
                rank=rank,
                category=category,
                rationale=rationale,
                key_flow_steps=item.key_flow_steps,
            )
        )
    return tuple(ranked)


def _config_digest_payload(options: SemanticOptions) -> dict[str, object]:
    """Compose the frozen config digest payload (§5.7); no elapsed time."""

    weights = {name: getattr(options.weights, name) for name in sorted(_WEIGHT_FIELD_NAMES)}
    budgets = {name: getattr(options.budgets, name) for name in sorted(_BUDGET_FIELD_NAMES)}
    return {
        "top_n": options.top_n,
        "weights": weights,
        "tie_break": options.tie_break,
        "seed": options.seed,
        "budgets": budgets,
        "prompt_digest": compute_content_digest(options.prompt_template),
        "model_digest": compute_content_digest(options.model_id),
    }


def _result_digest(
    *,
    config_digest: str,
    input_facts_digest: str | None,
    ranked: tuple[SemanticCandidate, ...],
    total_candidates: int,
    coverage_gaps: tuple[ProfileCoverageGap, ...],
) -> str:
    """Compose the frozen result digest payload (§5.7); no elapsed time."""

    return compute_content_digest(
        {
            "config_digest": config_digest,
            "input_facts_digest": input_facts_digest,
            "ranked": [
                {
                    "rank": item.rank,
                    "candidate_id": item.candidate_id,
                    "score": item.score,
                    "category": item.category,
                    "rationale": item.rationale,
                    "key_flow_steps": list(item.key_flow_steps),
                }
                for item in ranked
            ],
            "total_candidates": total_candidates,
            "coverage_gaps": [gap.to_dict() for gap in coverage_gaps],
        }
    )


def semantic_config_digest(options: SemanticOptions) -> str:
    """Return the 64-hex identity digest of one frozen option set."""

    if not isinstance(options, SemanticOptions):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    return compute_content_digest(_config_digest_payload(options))


def semantic_result_digest(
    result: SemanticTopNResult, *, input_facts_digest: str | None = None
) -> str:
    """Recompute the 64-hex result digest of one built semantic result.

    The result carrier does not store the input facts digest, so callers pass
    ``ram_facts_digest(facts)`` to recompute the identity binding; the payload
    slot itself is always present (``None`` when unbound).
    """

    if not isinstance(result, SemanticTopNResult):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    return _result_digest(
        config_digest=result.config_digest,
        input_facts_digest=input_facts_digest,
        ranked=result.ranked,
        total_candidates=result.total_candidates,
        coverage_gaps=result.coverage_gaps,
    )


def build_semantic_top_n(
    facts: PythonRamFacts,
    *,
    options: SemanticOptions | None = None,
    model_client: SemanticModelClient | None = None,
) -> SemanticTopNResult:
    """Build the two-layer semantic Top-N view of one frozen fact set (§5.0).

    The base ``PythonRamFacts`` are consumed read-only; the returned carrier
    holds the ranked board, semantic gaps, and the four identity digests.
    Entry-contract violations raise ``ContractError``; every model path
    failure degrades to deterministic fallbacks plus typed gaps.
    """

    if not isinstance(facts, PythonRamFacts):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    _reject_dash_symbols(facts)
    resolved = options if options is not None else SemanticOptions()
    if not isinstance(resolved, SemanticOptions):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if model_client is not None and not callable(getattr(model_client, "complete", None)):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)

    candidates = _collect_candidates(facts, resolved.weights)
    ordered = sorted(candidates, key=_sort_key)
    total_candidates = len(ordered)
    gap_pairs: list[tuple[str, str]] = []
    enrichment: dict[str, tuple[str, str]] = {}
    if model_client is None or resolved.model_id == "unset":
        gap_pairs.append(
            (
                GAP_SEMANTIC_MODEL_OFF,
                f"reason=model-disabled; candidates={total_candidates}",
            )
        )
    else:
        enrichment, model_gap_pairs = _run_model_pass(ordered, resolved, model_client)
        gap_pairs.extend(model_gap_pairs)

    ranked = _assemble_ranked(ordered, resolved.top_n, enrichment)
    gap_pairs.sort(key=lambda pair: (pair[0], pair[1]))
    coverage_gaps = tuple(
        ProfileCoverageGap(gap_code=code, detail=detail) for code, detail in gap_pairs
    )
    config_payload = _config_digest_payload(resolved)
    prompt_digest = str(config_payload["prompt_digest"])
    model_digest = str(config_payload["model_digest"])
    config_digest = compute_content_digest(config_payload)
    result_digest = _result_digest(
        config_digest=config_digest,
        input_facts_digest=ram_facts_digest(facts),
        ranked=ranked,
        total_candidates=total_candidates,
        coverage_gaps=coverage_gaps,
    )
    return SemanticTopNResult(
        ranked=ranked,
        total_candidates=total_candidates,
        coverage_gaps=coverage_gaps,
        prompt_digest=prompt_digest,
        model_digest=model_digest,
        config_digest=config_digest,
        result_digest=result_digest,
    )
