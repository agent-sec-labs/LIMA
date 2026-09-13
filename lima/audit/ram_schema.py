"""RAM wire schema validation and composition module (IP-0021, Packet v1.1 §5.2).

Stdlib-only, deterministic, fail-closed. This module never builds profiles,
RAM facts, or Top-N boards: it composes already-built frozen results into
the wire payload, validates the wire contract, and derives the
``execution_required`` typed carrier (DR-IP-0021-0102 DR-1 amendment C).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, Final

from lima.audit.inventory import ProfileBudgets
from lima.audit.ram import (
    RamBudgets,
    RamFactsBuildResult,
    ram_facts_digest,
)
from lima.audit.semantic_prioritizer import (
    SEMANTIC_CATEGORY_CODE_EXECUTION,
    SEMANTIC_CATEGORY_COMMAND_EXECUTION,
    SEMANTIC_CATEGORY_DESERIALIZATION,
    SEMANTIC_CATEGORY_ENTRYPOINT,
    SEMANTIC_CATEGORY_EXTERNAL_INPUT,
    SEMANTIC_CATEGORY_PATH_TRAVERSAL,
    SEMANTIC_CATEGORY_SQL_INJECTION,
    SEMANTIC_CATEGORY_TRUST_BOUNDARY,
    SEMANTIC_CATEGORY_UNRESOLVED_EDGE,
    SemanticOptions,
    SemanticTopNResult,
    semantic_config_digest,
    semantic_result_digest,
)
from lima.contracts.codec import compute_content_digest
from lima.contracts.errors import ContractError, ContractErrorCode

RAM_WIRE_SCHEMA_NAME: Final[str] = "lima.repository-architecture-model"
RAM_WIRE_SCHEMA_FILE: Final[Path] = (
    Path("schemas") / "v4" / "lima.repository-architecture-model.json"
)

#: Frozen ten-code gap vocabulary (value restatement; Packet §3.1).
GAP_CODES_ALL: Final[frozenset[str]] = frozenset(
    {
        "BUDGET_EXHAUSTED",
        "INVENTORY_SKIPPED",
        "MANIFEST_PARSE_ERROR",
        "NO_LANGUAGES_DETECTED",
        "UNSUPPORTED_LANGUAGE",
        "DYNAMIC_IMPORT",
        "AMBIGUOUS_DISPATCH",
        "SEMANTIC_MODEL_OFF",
        "SEMANTIC_MODEL_TIMEOUT",
        "SEMANTIC_MALFORMED_OUTPUT",
    }
)

#: DR-IP-0021-0102 DR-1 (amendment C): nine trigger codes; MODEL_OFF excluded.
GAP_EXECUTION_REQUIRED_TRIGGERS: Final[frozenset[str]] = GAP_CODES_ALL - {
    "SEMANTIC_MODEL_OFF"
}

PROVENANCE_ANCHOR_CHAIN: Final[tuple[str, str, str]] = (
    "inventory",
    "ram-facts",
    "semantic-prioritizer",
)

_CATEGORIES: Final[frozenset[str]] = frozenset(
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
_COUNTER_KEYS: Final[frozenset[str]] = frozenset(
    {
        "ambiguous_modules",
        "cross_file_edges",
        "dynamic_import_sites",
        "functions_indexed",
        "interprocedural_edges",
        "modules_indexed",
        "parse_error_files",
        "unresolved_calls",
    }
)
_WEIGHT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "sink_flow_command",
        "sink_flow_sql",
        "sink_flow_eval",
        "sink_flow_path",
        "sink_flow_deserialization",
        "entrypoint",
        "external_source",
        "trust_boundary",
        "unresolved_edge",
    }
)
_SEMANTIC_BUDGET_KEYS: Final[frozenset[str]] = frozenset(
    {
        "max_llm_calls",
        "max_prompt_tokens_estimate",
        "max_output_tokens_estimate",
        "max_total_tokens_estimate",
        "max_wall_time_seconds",
    }
)

_TOP_KEYS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "model_kind",
        "build",
        "ram",
        "semantic",
        "identity",
        "provenance",
        "execution_required",
    }
)
_ENTRY_KEYS: Final[frozenset[str]] = frozenset(
    {"path", "reason_codes", "source_artifact_ids", "symbol"}
)
_GAP_KEYS: Final[frozenset[str]] = frozenset({"gap_code", "detail"})
_FLOW_KEYS: Final[frozenset[str]] = frozenset({"sink_rule_id", "steps"})
_RANKED_KEYS: Final[frozenset[str]] = frozenset(
    {
        "candidate_id",
        "kind",
        "path",
        "symbol",
        "score",
        "rank",
        "category",
        "rationale",
        "key_flow_steps",
    }
)
_IDENTITY_KEYS: Final[frozenset[str]] = frozenset(
    {
        "ram_facts_digest",
        "semantic_config_digest",
        "semantic_result_digest",
        "prompt_digest",
        "model_digest",
        "wire_digest",
    }
)

_RE_HEX64: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_RE_GAP_CODE: Final[re.Pattern[str]] = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_RE_CANDIDATE_ID: Final[re.Pattern[str]] = re.compile(r"^[^:#]+:[^:#]+:[^:#]*#\d+$")
_TIE_BREAK: Final[str] = "kind-path-symbol-ordinal"
_MAX_TRACE_STEPS: Final[int] = 12


def _fail(detail: str) -> None:
    raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, detail)


def _check_keys(value: Mapping[str, Any], expected: frozenset[str], where: str) -> None:
    if not isinstance(value, Mapping):
        _fail(f"{where}: expected object")
    present = set(value)
    if present != set(expected):
        unknown = sorted(present - set(expected))
        missing = sorted(set(expected) - present)
        _fail(f"{where}: unknown={unknown} missing={missing}")


def _check_str(value: Any, where: str) -> str:
    if not isinstance(value, str):
        _fail(f"{where}: expected string")
    return value


def _check_int(value: Any, where: str, *, minimum: int) -> int:
    if type(value) is not int or value < minimum:  # noqa: PLR2004
        _fail(f"{where}: expected int >= {minimum}")
    return value


def _check_str_list(value: Any, where: str) -> list[str]:
    if not isinstance(value, list):
        _fail(f"{where}: expected array")
    for item in value:
        if not isinstance(item, str):
            _fail(f"{where}: expected string item")
    return value


def _check_entry(value: Any, where: str) -> dict[str, Any]:
    _check_keys(value, _ENTRY_KEYS, where)
    path = _check_str(value["path"], f"{where}.path")
    if "\\" in path:
        _fail(f"{where}.path: expected POSIX relative path")
    _check_str_list(value["reason_codes"], f"{where}.reason_codes")
    _check_str_list(value["source_artifact_ids"], f"{where}.source_artifact_ids")
    if value["symbol"] is not None and not isinstance(value["symbol"], str):
        _fail(f"{where}.symbol: expected string or null")
    return dict(value)


def _check_gap(value: Any, where: str) -> dict[str, Any]:
    _check_keys(value, _GAP_KEYS, where)
    code = _check_str(value["gap_code"], f"{where}.gap_code")
    if not _RE_GAP_CODE.match(code):
        _fail(f"{where}.gap_code: pattern violation")
    _check_str(value["detail"], f"{where}.detail")
    return dict(value)


def execution_required_from_gaps(
    gap_codes: Iterable[str],
) -> tuple[bool, tuple[str, ...]]:
    """Derive the typed execution-required carrier from observed gap codes."""
    triggers: set[str] = set()
    for code in gap_codes:
        if code not in GAP_CODES_ALL:
            raise ValueError(f"unknown gap code: {code}")
        if code in GAP_EXECUTION_REQUIRED_TRIGGERS:
            triggers.add(code)
    ordered = tuple(sorted(triggers))
    return (bool(ordered), ordered)


def _wire_digest_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    identity = dict(payload["identity"])
    identity.pop("wire_digest", None)
    normalized = dict(payload)
    normalized["identity"] = identity
    return normalized


def ram_wire_digest(payload: Mapping[str, Any]) -> str:
    """Return the 64-hex wire digest of one payload (no clock/env/net)."""
    return compute_content_digest(_wire_digest_payload(payload))


def ram_wire_payload(
    ram_result: RamFactsBuildResult,
    semantic_result: SemanticTopNResult,
    *,
    profile_budgets: ProfileBudgets | None = None,
    ram_budgets: RamBudgets | None = None,
    semantic_options: SemanticOptions | None = None,
) -> dict[str, Any]:
    """Compose the deterministic RAM wire payload from frozen results."""
    if not isinstance(ram_result, RamFactsBuildResult):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if not isinstance(semantic_result, SemanticTopNResult):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    p_budgets = profile_budgets if profile_budgets is not None else ProfileBudgets()
    if not isinstance(p_budgets, ProfileBudgets):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    r_budgets = ram_budgets if ram_budgets is not None else RamBudgets()
    if not isinstance(r_budgets, RamBudgets):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    options = semantic_options if semantic_options is not None else SemanticOptions()
    if not isinstance(options, SemanticOptions):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)

    facts = ram_result.facts
    ram_section: dict[str, Any] = {
        "entrypoints": [e.to_dict() for e in facts.entrypoints],
        "external_sources": [e.to_dict() for e in facts.external_sources],
        "source_labels": list(facts.source_labels),
        "sensitive_sinks": [e.to_dict() for e in facts.sensitive_sinks],
        "sink_rule_ids": list(facts.sink_rule_ids),
        "sink_cwes": list(facts.sink_cwes),
        "trust_boundaries": [e.to_dict() for e in facts.trust_boundaries],
        "key_flows": [
            {"sink_rule_id": flow.sink_rule_id, "steps": list(flow.steps)}
            for flow in facts.key_flows
        ],
        "unresolved_edges": [e.to_dict() for e in facts.unresolved_edges],
        "coverage_gaps": [gap.to_dict() for gap in facts.coverage_gaps],
        "counters": {name: facts.counters[name] for name in sorted(facts.counters)},
    }
    semantic_section: dict[str, Any] = {
        "ranked": [
            {
                "candidate_id": item.candidate_id,
                "kind": item.kind,
                "path": item.path,
                "symbol": item.symbol,
                "score": item.score,
                "rank": item.rank,
                "category": item.category,
                "rationale": item.rationale,
                "key_flow_steps": list(item.key_flow_steps),
            }
            for item in semantic_result.ranked
        ],
        "total_candidates": semantic_result.total_candidates,
        "coverage_gaps": [gap.to_dict() for gap in semantic_result.coverage_gaps],
    }
    facts_digest = ram_facts_digest(facts)
    payload: dict[str, Any] = {
        "schema_version": "4.0",
        "model_kind": RAM_WIRE_SCHEMA_NAME,
        "build": {
            "profile_budgets": {
                "manifest_max_bytes": p_budgets.manifest_max_bytes,
                "max_manifest_files": p_budgets.max_manifest_files,
            },
            "ram_budgets": {
                "max_python_files": r_budgets.max_python_files,
                "max_key_flows": r_budgets.max_key_flows,
                "max_unresolved_edges": r_budgets.max_unresolved_edges,
            },
            "semantic": {
                "top_n": options.top_n,
                "seed": options.seed,
                "tie_break": options.tie_break,
                "model_id": options.model_id,
                "weights": {name: getattr(options.weights, name) for name in sorted(_WEIGHT_KEYS)},
                "budgets": {
                    name: getattr(options.budgets, name)
                    for name in sorted(_SEMANTIC_BUDGET_KEYS)
                },
            },
        },
        "ram": ram_section,
        "semantic": semantic_section,
        "identity": {
            "ram_facts_digest": facts_digest,
            "semantic_config_digest": semantic_config_digest(options),
            "semantic_result_digest": semantic_result_digest(
                semantic_result, input_facts_digest=facts_digest
            ),
            "prompt_digest": semantic_result.prompt_digest,
            "model_digest": semantic_result.model_digest,
            "wire_digest": "",
        },
        "provenance": {"provenance_anchor_ids": list(PROVENANCE_ANCHOR_CHAIN)},
    }
    observed = [g["gap_code"] for g in ram_section["coverage_gaps"]]
    observed += [g["gap_code"] for g in semantic_section["coverage_gaps"]]
    required, trigger_codes = execution_required_from_gaps(observed)
    payload["execution_required"] = {
        "required": required,
        "trigger_gap_codes": list(trigger_codes),
    }
    payload["identity"]["wire_digest"] = ram_wire_digest(payload)
    return payload


def validate_ram_wire_payload(payload: Mapping[str, Any]) -> None:
    """Validate one wire payload against the frozen contract; fail-closed."""
    if not isinstance(payload, Mapping):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    _check_keys(payload, _TOP_KEYS, "$")
    if payload["schema_version"] != "4.0":
        _fail("$.schema_version: const '4.0'")
    if payload["model_kind"] != RAM_WIRE_SCHEMA_NAME:
        _fail("$.model_kind: const mismatch")

    build = payload["build"]
    _check_keys(build, frozenset({"profile_budgets", "ram_budgets", "semantic"}), "$.build")
    pb = build["profile_budgets"]
    _check_keys(
        pb,
        frozenset({"manifest_max_bytes", "max_manifest_files"}),
        "$.build.profile_budgets",
    )
    for key in ("manifest_max_bytes", "max_manifest_files"):
        _check_int(pb[key], f"$.build.profile_budgets.{key}", minimum=1)
    rb = build["ram_budgets"]
    _check_keys(
        rb,
        frozenset({"max_python_files", "max_key_flows", "max_unresolved_edges"}),
        "$.build.ram_budgets",
    )
    for key in ("max_python_files", "max_key_flows", "max_unresolved_edges"):
        _check_int(rb[key], f"$.build.ram_budgets.{key}", minimum=1)
    sem = build["semantic"]
    _check_keys(
        sem,
        frozenset({"top_n", "seed", "tie_break", "model_id", "weights", "budgets"}),
        "$.build.semantic",
    )
    _check_int(sem["top_n"], "$.build.semantic.top_n", minimum=1)
    if sem["top_n"] > 100:  # noqa: PLR2004
        _fail("$.build.semantic.top_n: max 100")
    _check_int(sem["seed"], "$.build.semantic.seed", minimum=0)
    if sem["tie_break"] != _TIE_BREAK:
        _fail("$.build.semantic.tie_break: const mismatch")
    _check_str(sem["model_id"], "$.build.semantic.model_id")
    weights = sem["weights"]
    _check_keys(weights, _WEIGHT_KEYS, "$.build.semantic.weights")
    for key in sorted(_WEIGHT_KEYS):
        _check_int(weights[key], f"$.build.semantic.weights.{key}", minimum=0)
    budgets = sem["budgets"]
    _check_keys(budgets, _SEMANTIC_BUDGET_KEYS, "$.build.semantic.budgets")
    for key in sorted(_SEMANTIC_BUDGET_KEYS):
        _check_int(budgets[key], f"$.build.semantic.budgets.{key}", minimum=1)

    ram = payload["ram"]
    _check_keys(
        ram,
        frozenset(
            {
                "entrypoints",
                "external_sources",
                "source_labels",
                "sensitive_sinks",
                "sink_rule_ids",
                "sink_cwes",
                "trust_boundaries",
                "key_flows",
                "unresolved_edges",
                "coverage_gaps",
                "counters",
            }
        ),
        "$.ram",
    )
    for section in (
        "entrypoints",
        "external_sources",
        "sensitive_sinks",
        "trust_boundaries",
        "unresolved_edges",
    ):
        value = ram[section]
        if not isinstance(value, list):
            _fail(f"$.ram.{section}: expected array")
        for index, item in enumerate(value):
            _check_entry(item, f"$.ram.{section}[{index}]")
    _check_str_list(ram["source_labels"], "$.ram.source_labels")
    rule_ids = _check_str_list(ram["sink_rule_ids"], "$.ram.sink_rule_ids")
    cwes = _check_str_list(ram["sink_cwes"], "$.ram.sink_cwes")
    sinks = ram["sensitive_sinks"]
    if len(rule_ids) != len(sinks) or len(cwes) != len(sinks):
        _fail("$.ram.sink_rule_ids/sink_cwes: parallel length mismatch")
    flows = ram["key_flows"]
    if not isinstance(flows, list):
        _fail("$.ram.key_flows: expected array")
    for index, flow in enumerate(flows):
        _check_keys(flow, _FLOW_KEYS, f"$.ram.key_flows[{index}]")
        _check_str(flow["sink_rule_id"], f"$.ram.key_flows[{index}].sink_rule_id")
        steps = _check_str_list(flow["steps"], f"$.ram.key_flows[{index}].steps")
        if len(steps) > _MAX_TRACE_STEPS:
            _fail(f"$.ram.key_flows[{index}].steps: max {_MAX_TRACE_STEPS}")
    gaps = ram["coverage_gaps"]
    if not isinstance(gaps, list):
        _fail("$.ram.coverage_gaps: expected array")
    for index, gap in enumerate(gaps):
        _check_gap(gap, f"$.ram.coverage_gaps[{index}]")
    counters = ram["counters"]
    _check_keys(counters, _COUNTER_KEYS, "$.ram.counters")
    for key in sorted(_COUNTER_KEYS):
        _check_int(counters[key], f"$.ram.counters.{key}", minimum=0)

    semantic = payload["semantic"]
    _check_keys(semantic, frozenset({"ranked", "total_candidates", "coverage_gaps"}), "$.semantic")
    _check_int(semantic["total_candidates"], "$.semantic.total_candidates", minimum=0)
    sgaps = semantic["coverage_gaps"]
    if not isinstance(sgaps, list):
        _fail("$.semantic.coverage_gaps: expected array")
    for index, gap in enumerate(sgaps):
        _check_gap(gap, f"$.semantic.coverage_gaps[{index}]")
    ranked = semantic["ranked"]
    if not isinstance(ranked, list):
        _fail("$.semantic.ranked: expected array")
    for index, item in enumerate(ranked):
        _check_keys(item, _RANKED_KEYS, f"$.semantic.ranked[{index}]")
        cid = _check_str(item["candidate_id"], f"$.semantic.ranked[{index}].candidate_id")
        if not _RE_CANDIDATE_ID.match(cid):
            _fail(f"$.semantic.ranked[{index}].candidate_id: pattern violation")
        _check_str(item["kind"], f"$.semantic.ranked[{index}].kind")
        _check_str(item["path"], f"$.semantic.ranked[{index}].path")
        if item["symbol"] is not None and not isinstance(item["symbol"], str):
            _fail(f"$.semantic.ranked[{index}].symbol")
        _check_int(item["score"], f"$.semantic.ranked[{index}].score", minimum=0)
        _check_int(item["rank"], f"$.semantic.ranked[{index}].rank", minimum=1)
        if item["rank"] != index + 1:
            _fail(f"$.semantic.ranked[{index}].rank: not consecutive from 1")
        if item["category"] not in _CATEGORIES:
            _fail(f"$.semantic.ranked[{index}].category: outside vocabulary")
        _check_str(item["rationale"], f"$.semantic.ranked[{index}].rationale")
        _check_str_list(item["key_flow_steps"], f"$.semantic.ranked[{index}].key_flow_steps")

    identity = payload["identity"]
    _check_keys(identity, _IDENTITY_KEYS, "$.identity")
    for key in sorted(_IDENTITY_KEYS):
        if not _RE_HEX64.match(_check_str(identity[key], f"$.identity.{key}")):
            _fail(f"$.identity.{key}: expected lowercase 64-hex")

    provenance = payload["provenance"]
    _check_keys(provenance, frozenset({"provenance_anchor_ids"}), "$.provenance")
    if list(provenance["provenance_anchor_ids"]) != list(PROVENANCE_ANCHOR_CHAIN):
        _fail("$.provenance.provenance_anchor_ids: frozen chain mismatch")

    execution = payload["execution_required"]
    _check_keys(execution, frozenset({"required", "trigger_gap_codes"}), "$.execution_required")
    if not isinstance(execution["required"], bool):
        _fail("$.execution_required.required: expected bool")
    triggers = execution["trigger_gap_codes"]
    _check_str_list(triggers, "$.execution_required.trigger_gap_codes")
    for code in triggers:
        if code not in GAP_EXECUTION_REQUIRED_TRIGGERS:
            _fail(f"$.execution_required.trigger_gap_codes: {code} not a trigger code")
    if list(triggers) != sorted(set(triggers)):
        _fail("$.execution_required.trigger_gap_codes: expected sorted unique")

    observed = [g["gap_code"] for g in ram["coverage_gaps"]]
    observed += [g["gap_code"] for g in semantic["coverage_gaps"]]
    expected = execution_required_from_gaps(observed)
    if execution["required"] != expected[0] or tuple(triggers) != expected[1]:
        _fail("$.execution_required: inconsistent with payload gaps")


def load_ram_wire_schema() -> dict[str, Any]:
    """Load the RAM wire schema file read-only (repo-root relative, no net)."""
    schema_path = Path(__file__).resolve().parents[2] / RAM_WIRE_SCHEMA_FILE
    with schema_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)
