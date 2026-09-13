"""Deterministic semantic prioritizer / Top-N layer for repository audits (IP-0019).

Layer 3 of the repository profile stack (Packet ``IP-0019-PACKET/v1``):
consume the frozen :class:`lima.audit.ram.PythonRamFacts` fact set as the
single source of truth, score every candidate deterministically from static
facts and configured weights, and build an independent Top-N board
(:class:`SemanticTopNResult`) that never mutates the Tier 0 base layer and
never attaches semantic fields to ``RepositoryProfile`` /
``AttackSurfaceEntry`` (DR-TOPN-01 B-10: the v4 wire contract rejects
non-empty ``extensions``).

Frozen behaviour:

- the model path is enabled only when the caller both injects a client
  implementing :class:`SemanticModelClient` **and** sets
  ``options.model_id != "unset"``; the default path performs zero model
  calls, zero network attempts and reads no environment variable;
- every model-path failure degrades (A-3/A-4): model off, timeout, malformed
  output and budget exhaustion become typed coverage gaps plus deterministic
  fallbacks instead of exceptions; only argument contract violations raise
  ``ContractError``/``ValueError`` (fail-closed);
- model output may only enrich ``category``/``rationale`` of candidates that
  exist in the fact set; scores and ranks are fully determined by static
  facts plus configuration and can never be influenced by the model (FR-03);
- all digests are ``lima.contracts.codec.compute_content_digest`` products;
  elapsed wall time and actual token consumption never enter any digest or
  output field (A-2), while all six budget configuration values do.
"""

from __future__ import annotations

import json
import math
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

#: Frozen IP-0016 gap semantics reused by value (Packet §4.1): this module
#: must not import ``lima.audit.inventory``, so the identical frozen gap-code
#: string is restated here.
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

SEMANTIC_CATEGORIES: Final[frozenset[str]] = frozenset(
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

_DEFAULT_PROMPT_TEMPLATE: Final[str] = (
    "You are a repository security semantic prioritizer. For each candidate "
    "return one JSON object with the keys candidate_id, category (from the "
    "allowed vocabulary below) and a short rationale. Allowed category "
    "vocabulary: command-execution, sql-injection, code-execution, "
    "path-traversal, deserialization, external-input, entrypoint, "
    "trust-boundary, unresolved-edge. Never include source code in the "
    "rationale. Candidates: {candidates}"
)

_TIE_BREAK: Final[str] = "kind-path-symbol-ordinal"

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

_KIND_WEIGHT_FIELD: Final[dict[str, str]] = {
    _KIND_ENTRYPOINT: "entrypoint",
    _KIND_EXTERNAL_SOURCE: "external_source",
    _KIND_TRUST_BOUNDARY: "trust_boundary",
    _KIND_UNRESOLVED_EDGE: "unresolved_edge",
}

_KIND_CATEGORY: Final[dict[str, str]] = {
    _KIND_EXTERNAL_SOURCE: SEMANTIC_CATEGORY_EXTERNAL_INPUT,
    _KIND_ENTRYPOINT: SEMANTIC_CATEGORY_ENTRYPOINT,
    _KIND_TRUST_BOUNDARY: SEMANTIC_CATEGORY_TRUST_BOUNDARY,
    _KIND_UNRESOLVED_EDGE: SEMANTIC_CATEGORY_UNRESOLVED_EDGE,
}

_MAX_RATIONALE_BYTES: Final[int] = 512
_OUTPUT_TOKENS_PER_CANDIDATE: Final[int] = 128

_SECRET_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{16,}|[A-Fa-f0-9]{32}|Bearer\s+[A-Za-z0-9._-]{16,}"
)
_SOURCE_TEXT_MARKERS: Final[tuple[str, ...]] = (
    "os.system",
    "os.popen",
    "subprocess",
    "shell=True",
    "eval(",
    "exec(",
    "pickle.loads",
    "request.args.get",
    "getenv(",
    "environ[",
)


class SemanticModelClient(Protocol):
    """Frozen port protocol of the model backend (no implementation here)."""

    def complete(self, prompt: str, *, timeout_seconds: int) -> str: ...  # pragma: no cover


@dataclass(frozen=True)
class SemanticWeights:
    """Deterministic scoring weights; every value must be a non-negative int."""

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
        for name in (
            "sink_flow_command",
            "sink_flow_sql",
            "sink_flow_eval",
            "sink_flow_path",
            "sink_flow_deserialization",
            "entrypoint",
            "external_source",
            "trust_boundary",
            "unresolved_edge",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")


@dataclass(frozen=True)
class SemanticBudgets:
    """Model-call resource ceilings; every value must be a positive int."""

    max_llm_calls: int = 8
    max_prompt_tokens_estimate: int = 24_000
    max_output_tokens_estimate: int = 4_096
    max_total_tokens_estimate: int = 28_096  # DR-TOPN-01 A-2 invariant fix (see DR record)
    max_wall_time_seconds: int = 120

    def __post_init__(self) -> None:
        for name in (
            "max_llm_calls",
            "max_prompt_tokens_estimate",
            "max_output_tokens_estimate",
            "max_total_tokens_estimate",
            "max_wall_time_seconds",
        ):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if (
            self.max_total_tokens_estimate
            < self.max_prompt_tokens_estimate + self.max_output_tokens_estimate
        ):
            raise ValueError(
                "max_total_tokens_estimate must be >= max_prompt_tokens_estimate"
                " + max_output_tokens_estimate"
            )


@dataclass(frozen=True)
class SemanticOptions:
    """Frozen configuration carrier of the semantic layer (FR-04 subset)."""

    top_n: int = 20
    weights: SemanticWeights = field(default_factory=SemanticWeights)
    seed: int = 0
    budgets: SemanticBudgets = field(default_factory=SemanticBudgets)
    model_id: str = "unset"
    prompt_template: str = _DEFAULT_PROMPT_TEMPLATE
    tie_break: str = _TIE_BREAK

    def __post_init__(self) -> None:
        if type(self.top_n) is not int or not 1 <= self.top_n <= SEMANTIC_MAX_TOP_N:
            raise ValueError(f"top_n must be an integer in 1..{SEMANTIC_MAX_TOP_N}")
        if type(self.seed) is not int or self.seed < 0:
            raise ValueError("seed must be a non-negative integer")
        if self.tie_break != _TIE_BREAK:
            raise ValueError(f"tie_break must be {_TIE_BREAK!r}")
        if not isinstance(self.weights, SemanticWeights):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
        if not isinstance(self.budgets, SemanticBudgets):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
        if not isinstance(self.model_id, str) or not self.model_id:
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
        if not isinstance(self.prompt_template, str):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)


@dataclass(frozen=True)
class SemanticCandidate:
    """One enriched row of the Top-N board (independent carrier, B-10)."""

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
    """Independent semantic result carrier with its own digest chain (B-8)."""

    ranked: tuple[SemanticCandidate, ...]
    total_candidates: int
    coverage_gaps: tuple[ProfileCoverageGap, ...]
    prompt_digest: str
    model_digest: str
    config_digest: str
    result_digest: str
    provenance_anchor_ids: tuple[str, ...] = (SEMANTIC_PROVENANCE_ANCHOR,)


def candidate_id(kind: str, path: str, symbol: str | None, ordinal: int) -> str:
    """Return the frozen collision-free candidate ID of one fact entry."""

    return f"{kind}:{path}:{symbol if symbol is not None else '-'}#{ordinal}"


def semantic_config_digest(options: SemanticOptions) -> str:
    """Return the frozen configuration digest of one options instance."""

    if not isinstance(options, SemanticOptions):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    prompt_digest = compute_content_digest(options.prompt_template)
    model_digest = compute_content_digest(options.model_id)
    return compute_content_digest(
        {
            "top_n": options.top_n,
            "weights": {
                name: getattr(options.weights, name)
                for name in sorted(options.weights.__dataclass_fields__)
            },
            "tie_break": options.tie_break,
            "seed": options.seed,
            "budgets": {
                "max_llm_calls": options.budgets.max_llm_calls,
                "max_prompt_tokens_estimate": options.budgets.max_prompt_tokens_estimate,
                "max_output_tokens_estimate": options.budgets.max_output_tokens_estimate,
                "max_total_tokens_estimate": options.budgets.max_total_tokens_estimate,
                "max_wall_time_seconds": options.budgets.max_wall_time_seconds,
            },
            "prompt_digest": prompt_digest,
            "model_digest": model_digest,
        }
    )


def semantic_result_digest(
    result: SemanticTopNResult, *, input_facts_digest: str | None = None
) -> str:
    """Recompute the frozen result digest of one semantic result.

    Packet §5.7 binds the result digest to the input RAM fact set; pass
    ``input_facts_digest=ram_facts_digest(facts)`` to reproduce the digest a
    build produced. Without it the digest covers the result carrier alone.
    """

    if not isinstance(result, SemanticTopNResult):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    return compute_content_digest(
        {
            "config_digest": result.config_digest,
            "input_facts_digest": input_facts_digest,
            "ranked": [_candidate_digest_payload(item) for item in result.ranked],
            "total_candidates": result.total_candidates,
            "coverage_gaps": [gap.to_dict() for gap in result.coverage_gaps],
        }
    )


def _candidate_digest_payload(item: SemanticCandidate) -> dict[str, object]:
    return {
        "rank": item.rank,
        "candidate_id": item.candidate_id,
        "score": item.score,
        "category": item.category,
        "rationale": item.rationale,
        "key_flow_steps": list(item.key_flow_steps),
    }


def _estimate_tokens(text: str) -> int:
    """Frozen estimation: one token per four UTF-8 characters, minimum one."""

    return max(1, math.ceil(len(text) / 4))


def _normalize_rationale(text: str) -> str:
    """NFC-normalize, strip control characters and bound to 512 UTF-8 bytes."""

    normalized = unicodedata.normalize("NFC", text).strip()
    normalized = "".join(
        ch
        for ch in normalized
        if unicodedata.category(ch) not in {"Cc", "Cf"}
    )
    encoded = normalized.encode("utf-8")
    if len(encoded) > _MAX_RATIONALE_BYTES:
        truncated = encoded[:_MAX_RATIONALE_BYTES]
        while truncated:
            try:
                normalized = truncated.decode("utf-8")
                break
            except UnicodeDecodeError:
                truncated = truncated[:-1]
        else:  # pragma: no cover - defensive
            normalized = ""
    return normalized


def _rationale_is_safe(text: str) -> bool:
    if _SECRET_PATTERN.search(text):
        return False
    lowered = text.lower()
    return not any(marker in lowered for marker in _SOURCE_TEXT_MARKERS)


@dataclass(frozen=True)
class _RawCandidate:
    cid: str
    kind: str
    path: str
    symbol: str | None
    ordinal: int
    score: int
    category: str
    rationale: str
    key_flow_steps: tuple[str, ...]


def _fallback_rationale(kind: str) -> str:
    return f"deterministic fallback; kind={kind}"


def _score(kind: str, rule_id: str | None, weights: SemanticWeights) -> int:
    if kind == _KIND_SENSITIVE_SINK and rule_id is not None:
        field_name = _SINK_RULE_WEIGHT_FIELD.get(rule_id)
        if field_name is not None:
            return getattr(weights, field_name)
        return 0
    return getattr(weights, _KIND_WEIGHT_FIELD[kind])


def _build_candidates(facts: PythonRamFacts, options: SemanticOptions) -> list[_RawCandidate]:
    weights = options.weights
    candidates: list[_RawCandidate] = []
    for index, entry in enumerate(facts.sensitive_sinks):
        rule_id = facts.sink_rule_ids[index] if index < len(facts.sink_rule_ids) else None
        steps: tuple[str, ...] = ()
        if index < len(facts.key_flows):
            steps = tuple(facts.key_flows[index].steps)
        candidates.append(
            _RawCandidate(
                cid=candidate_id(_KIND_SENSITIVE_SINK, entry.path, entry.symbol, index),
                kind=_KIND_SENSITIVE_SINK,
                path=entry.path,
                symbol=entry.symbol,
                ordinal=index,
                score=_score(_KIND_SENSITIVE_SINK, rule_id, weights),
                category=_SINK_RULE_CATEGORY.get(
                    rule_id or "", SEMANTIC_CATEGORY_COMMAND_EXECUTION
                ),
                rationale=_fallback_rationale(_KIND_SENSITIVE_SINK),
                key_flow_steps=steps,
            )
        )
    for index, entry in enumerate(facts.entrypoints):
        candidates.append(
            _RawCandidate(
                cid=candidate_id(_KIND_ENTRYPOINT, entry.path, entry.symbol, index),
                kind=_KIND_ENTRYPOINT,
                path=entry.path,
                symbol=entry.symbol,
                ordinal=index,
                score=_score(_KIND_ENTRYPOINT, None, weights),
                category=_KIND_CATEGORY[_KIND_ENTRYPOINT],
                rationale=_fallback_rationale(_KIND_ENTRYPOINT),
                key_flow_steps=(),
            )
        )
    for index, entry in enumerate(facts.external_sources):
        candidates.append(
            _RawCandidate(
                cid=candidate_id(_KIND_EXTERNAL_SOURCE, entry.path, entry.symbol, index),
                kind=_KIND_EXTERNAL_SOURCE,
                path=entry.path,
                symbol=entry.symbol,
                ordinal=index,
                score=_score(_KIND_EXTERNAL_SOURCE, None, weights),
                category=_KIND_CATEGORY[_KIND_EXTERNAL_SOURCE],
                rationale=_fallback_rationale(_KIND_EXTERNAL_SOURCE),
                key_flow_steps=(),
            )
        )
    for index, entry in enumerate(facts.trust_boundaries):
        candidates.append(
            _RawCandidate(
                cid=candidate_id(_KIND_TRUST_BOUNDARY, entry.path, entry.symbol, index),
                kind=_KIND_TRUST_BOUNDARY,
                path=entry.path,
                symbol=entry.symbol,
                ordinal=index,
                score=_score(_KIND_TRUST_BOUNDARY, None, weights),
                category=_KIND_CATEGORY[_KIND_TRUST_BOUNDARY],
                rationale=_fallback_rationale(_KIND_TRUST_BOUNDARY),
                key_flow_steps=(),
            )
        )
    for index, entry in enumerate(facts.unresolved_edges):
        candidates.append(
            _RawCandidate(
                cid=candidate_id(_KIND_UNRESOLVED_EDGE, entry.path, entry.symbol, index),
                kind=_KIND_UNRESOLVED_EDGE,
                path=entry.path,
                symbol=entry.symbol,
                ordinal=index,
                score=_score(_KIND_UNRESOLVED_EDGE, None, weights),
                category=_KIND_CATEGORY[_KIND_UNRESOLVED_EDGE],
                rationale=_fallback_rationale(_KIND_UNRESOLVED_EDGE),
                key_flow_steps=(),
            )
        )
    candidates.sort(
        key=lambda item: (
            -item.score,
            _KIND_ORDER[item.kind],
            item.path,
            item.symbol or "",
            item.ordinal,
        )
    )
    return candidates


def _render_prompt(batch: list[_RawCandidate], template: str) -> str:
    descriptors = [
        {
            "candidate_id": item.cid,
            "kind": item.kind,
            "path": item.path,
            "symbol": item.symbol,
            "category": item.category,
            "rule_id": None,
        }
        for item in batch
    ]
    return template.replace("{candidates}", json.dumps(descriptors, ensure_ascii=False))


def _parse_batch_output(
    payload: str, allowed_ids: frozenset[str]
) -> tuple[dict[str, tuple[str, str]], str | None]:
    """Validate one model batch; return enrichments and first offending key."""

    try:
        data = json.loads(payload)
    except (TypeError, ValueError):
        return {}, "json"
    if not isinstance(data, list):
        return {}, "json"
    enrichments: dict[str, tuple[str, str]] = {}
    for item in data:
        if not isinstance(item, dict):
            return {}, "candidate_id"
        cid = item.get("candidate_id")
        if not isinstance(cid, str) or cid not in allowed_ids:
            return {}, "candidate_id"
        category = item.get("category")
        if not isinstance(category, str) or category not in SEMANTIC_CATEGORIES:
            return {}, "category"
        raw_rationale = item.get("rationale")
        if not isinstance(raw_rationale, str):
            return {}, "rationale"
        rationale = _normalize_rationale(raw_rationale)
        if not rationale or not _rationale_is_safe(rationale):
            return {}, "rationale"
        enrichments[cid] = (category, rationale)
    return enrichments, None


def build_semantic_top_n(
    facts: PythonRamFacts,
    *,
    options: SemanticOptions | None = None,
    model_client: SemanticModelClient | None = None,
) -> SemanticTopNResult:
    """Build the deterministic Top-N semantic board over one RAM fact set."""

    if not isinstance(facts, PythonRamFacts):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if options is not None and not isinstance(options, SemanticOptions):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    resolved = options if options is not None else SemanticOptions()
    if model_client is not None and not callable(getattr(model_client, "complete", None)):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)

    prompt_digest = compute_content_digest(resolved.prompt_template)
    model_digest = compute_content_digest(resolved.model_id)
    config_digest = semantic_config_digest(resolved)

    ordered = _build_candidates(facts, resolved)
    total_candidates = len(ordered)

    gaps: list[tuple[str, str]] = []
    enriched: dict[str, tuple[str, str]] = {}
    model_enabled = model_client is not None and resolved.model_id != "unset"

    if not model_enabled:
        gaps.append(
            (
                GAP_SEMANTIC_MODEL_OFF,
                f"reason=model-disabled; candidates={total_candidates}",
            )
        )
    else:
        budgets = resolved.budgets
        batch_cap = max(1, budgets.max_llm_calls)
        start = time.monotonic()
        index = 0
        calls_made = 0
        while index < len(ordered):
            batch = ordered[index : index + batch_cap]
            allowed = frozenset(item.cid for item in batch)
            prompt = _render_prompt(batch, resolved.prompt_template)
            prompt_estimate = _estimate_tokens(prompt)
            batch_output_estimate = _OUTPUT_TOKENS_PER_CANDIDATE * len(batch)
            now = time.monotonic()
            stage: str | None = None
            if calls_made >= budgets.max_llm_calls:
                stage = "llm-calls"
            elif prompt_estimate > budgets.max_prompt_tokens_estimate:
                stage = "prompt-tokens"
            elif batch_output_estimate > budgets.max_output_tokens_estimate:
                stage = "output-tokens"
            elif (
                prompt_estimate + batch_output_estimate
                > budgets.max_total_tokens_estimate
            ):
                stage = "total-tokens"
            elif now - start >= budgets.max_wall_time_seconds:
                stage = "wall-time"
            if stage is not None:
                pending = len(ordered) - index
                board_ids = {item.cid for item in ordered[: resolved.top_n]}
                if not board_ids.issubset(enriched):
                    gaps.append(
                        (
                            _GAP_BUDGET_EXHAUSTED,
                            (
                                f"reason=semantic-budget; stage={stage};"
                                f" pending={pending};"
                                " note=semantic-coverage-incomplete;"
                                " not-an-absence-of-risk"
                            ),
                        )
                    )
                break
            remaining = max(1.0, budgets.max_wall_time_seconds - (now - start))
            timeout_seconds = int(max(1, min(budgets.max_wall_time_seconds, remaining)))
            try:
                payload = model_client.complete(
                    prompt, timeout_seconds=timeout_seconds
                )
            except TimeoutError:
                gaps.append(
                    (
                        GAP_SEMANTIC_MODEL_TIMEOUT,
                        f"reason=model-timeout; batch={index // batch_cap}",
                    )
                )
                break
            batch_enrichments, offending = _parse_batch_output(payload, allowed)
            if offending is not None:
                gaps.append(
                    (
                        GAP_SEMANTIC_MALFORMED_OUTPUT,
                        f"batch={index // batch_cap}; offending={offending}",
                    )
                )
            else:
                enriched.update(batch_enrichments)
            calls_made += 1
            index += len(batch)

    ranked: list[SemanticCandidate] = []
    board = ordered[: resolved.top_n]
    for position, item in enumerate(board):
        category = item.category
        rationale = item.rationale
        if item.cid in enriched:
            category, rationale = enriched[item.cid]
        ranked.append(
            SemanticCandidate(
                candidate_id=item.cid,
                kind=item.kind,
                path=item.path,
                symbol=item.symbol,
                score=item.score,
                rank=position + 1,
                category=category,
                rationale=rationale,
                key_flow_steps=item.key_flow_steps,
            )
        )

    ordered_gaps = tuple(
        ProfileCoverageGap(gap_code=code, detail=detail)
        for code, detail in sorted(gaps, key=lambda pair: (pair[0], pair[1]))
    )
    result = SemanticTopNResult(
        ranked=tuple(ranked),
        total_candidates=total_candidates,
        coverage_gaps=ordered_gaps,
        prompt_digest=prompt_digest,
        model_digest=model_digest,
        config_digest=config_digest,
        result_digest="0" * 64,
    )
    object.__setattr__(
        result,
        "result_digest",
        semantic_result_digest(
            result, input_facts_digest=ram_facts_digest(facts)
        ),
    )
    return result
