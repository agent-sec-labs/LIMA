"""RAM wire envelope: schema load, payload build, validation, digest (IP-0021).

Wire-side companion of the frozen three-layer repository profile stack:
compose the ``lima.repository-architecture-model`` payload from one built RAM
facts result plus one built semantic Top-N result, validate any such payload
fail-closed against the frozen wire format, derive its identity digest, and
derive the typed ``execution_required`` carrier from coverage-gap codes
(Packet ``IP-0021-PACKET/v1.1`` §5.1/§5.2, DR-IP-0021-0102 DR-1 amendment C).

Frozen behaviour:

- stdlib-only; the only dependency surface is ``lima.contracts`` plus
  ``isinstance`` type checks against the frozen three-layer data classes; the
  layer constructors are never imported, so validation and construction stay
  decoupled, and the gap-code universe is restated by value (the established
  frozen layer-by-value precedent);
- pure functions: no clock, no randomness, no environment read, no network
  facility, no file write; the only disk access is the read-only schema load
  located relative to the repository root;
- ``validate_ram_wire_payload`` never corrects anything: unknown fields, wrong
  types, out-of-vocabulary categories, non-consecutive ranks, non-parallel
  parallel arrays, non-hex digests, wrong provenance order and inconsistent
  ``execution_required`` carriers all raise
  :class:`lima.contracts.errors.ContractError`;
- ``execution_required_from_gaps`` follows the frozen nine-code trigger table:
  every coverage-gap code except ``SEMANTIC_MODEL_OFF`` sets ``required``;
  ``SEMANTIC_MODEL_OFF`` alone keeps ``required=False`` while the typed gap
  stays visible in the coverage-gap lists; unknown codes raise ``ValueError``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Final

from lima.audit.inventory import ProfileBudgets
from lima.audit.ram import (
    PythonRamFacts,
    RamBudgets,
    RamFactsBuildResult,
    ram_facts_digest,
)
from lima.audit.semantic_prioritizer import SemanticOptions, SemanticTopNResult
from lima.contracts.codec import compute_content_digest
from lima.contracts.errors import ContractError, ContractErrorCode
from lima.contracts.profile import AttackSurfaceEntry, ProfileCoverageGap

__all__ = [
    "GAP_CODES_ALL",
    "GAP_EXECUTION_REQUIRED_TRIGGERS",
    "PROVENANCE_ANCHOR_CHAIN",
    "RAM_WIRE_SCHEMA_FILE",
    "RAM_WIRE_SCHEMA_NAME",
    "execution_required_from_gaps",
    "load_ram_wire_schema",
    "ram_wire_digest",
    "ram_wire_payload",
    "validate_ram_wire_payload",
]

RAM_WIRE_SCHEMA_NAME: Final[str] = "lima.repository-architecture-model"
RAM_WIRE_SCHEMA_FILE: Final[Path] = (
    Path("schemas") / "v4" / "lima.repository-architecture-model.json"
)

#: Frozen ten-code coverage-gap universe (Packet §3.1), restated by value.
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

#: DR-IP-0021-0102 DR-1 (amendment C): nine trigger codes; the disabled-model
#: default state never sets ``execution_required``.
GAP_EXECUTION_REQUIRED_TRIGGERS: Final[frozenset[str]] = frozenset(
    GAP_CODES_ALL - {"SEMANTIC_MODEL_OFF"}
)

PROVENANCE_ANCHOR_CHAIN: Final[tuple[str, str, str]] = (
    "inventory",
    "ram-facts",
    "semantic-prioritizer",
)

_SCHEMA_VERSION: Final[str] = "4.0"
_TIE_BREAK_FROZEN: Final[str] = "kind-path-symbol-ordinal"
_MAX_TOP_N: Final[int] = 100
_MAX_ITEMS: Final[int] = 4096
_MAX_TRACE_STEPS: Final[int] = 12

_GAP_CODE_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_HEX64_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_CANDIDATE_ID_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[^:#\s]+:[^:#\s]+:(?:[^:#\s]+|-)#[0-9]+$"
)

_CATEGORY_VOCABULARY: Final[frozenset[str]] = frozenset(
    {
        "code-execution",
        "command-execution",
        "deserialization",
        "entrypoint",
        "external-input",
        "path-traversal",
        "sql-injection",
        "trust-boundary",
        "unresolved-edge",
    }
)

_WEIGHT_FIELDS: Final[tuple[str, ...]] = (
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
_SEMANTIC_BUDGET_FIELDS: Final[tuple[str, ...]] = (
    "max_llm_calls",
    "max_prompt_tokens_estimate",
    "max_output_tokens_estimate",
    "max_total_tokens_estimate",
    "max_wall_time_seconds",
)
_COUNTER_FIELDS: Final[tuple[str, ...]] = (
    "ambiguous_modules",
    "cross_file_edges",
    "dynamic_import_sites",
    "functions_indexed",
    "interprocedural_edges",
    "modules_indexed",
    "parse_error_files",
    "unresolved_calls",
)

_TOP_LEVEL_KEYS: Final[frozenset[str]] = frozenset(
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
_BUILD_KEYS: Final[frozenset[str]] = frozenset(
    {"profile_budgets", "ram_budgets", "semantic"}
)
_PROFILE_BUDGET_KEYS: Final[frozenset[str]] = frozenset(
    {"manifest_max_bytes", "max_manifest_files"}
)
_RAM_BUDGET_KEYS: Final[frozenset[str]] = frozenset(
    {"max_python_files", "max_key_flows", "max_unresolved_edges"}
)
_SEMANTIC_BUILD_KEYS: Final[frozenset[str]] = frozenset(
    {"top_n", "seed", "tie_break", "model_id", "weights", "budgets"}
)
_RAM_KEYS: Final[frozenset[str]] = frozenset(
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
)
_ENTRY_KEYS: Final[frozenset[str]] = frozenset(
    {"path", "symbol", "reason_codes", "source_artifact_ids"}
)
_FLOW_KEYS: Final[frozenset[str]] = frozenset({"sink_rule_id", "steps"})
_GAP_KEYS: Final[frozenset[str]] = frozenset({"gap_code", "detail"})
_SEMANTIC_KEYS: Final[frozenset[str]] = frozenset(
    {"ranked", "total_candidates", "coverage_gaps"}
)
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
_PROVENANCE_KEYS: Final[frozenset[str]] = frozenset({"provenance_anchor_ids"})
_EXECUTION_KEYS: Final[frozenset[str]] = frozenset({"required", "trigger_gap_codes"})


def execution_required_from_gaps(
    gap_codes: Iterable[str],
) -> tuple[bool, tuple[str, ...]]:
    """Return the frozen ``execution_required`` carrier for one gap-code set.

    ``required`` is true exactly when at least one code of the frozen
    nine-code trigger set occurs; ``trigger_gap_codes`` is the deduplicated
    ascending trigger intersection. Codes outside the ten-code universe raise
    ``ValueError``; ``SEMANTIC_MODEL_OFF`` is accepted but never triggers.
    """

    triggers: set[str] = set()
    for code in gap_codes:
        if not isinstance(code, str) or code not in GAP_CODES_ALL:
            raise ValueError(f"gap code outside the frozen universe: {code!r}")
        if code in GAP_EXECUTION_REQUIRED_TRIGGERS:
            triggers.add(code)
    ordered = tuple(sorted(triggers))
    return (bool(ordered), ordered)


def load_ram_wire_schema() -> dict[str, object]:
    """Load the frozen ``lima.repository-architecture-model`` schema file.

    The file is located relative to the repository root and read only; no
    network facility is used and nothing is written.
    """

    schema_path = Path(__file__).resolve().parents[2] / RAM_WIRE_SCHEMA_FILE
    return json.loads(schema_path.read_text(encoding="utf-8"))


def ram_wire_payload(
    ram_result: RamFactsBuildResult,
    semantic_result: SemanticTopNResult,
    *,
    profile_budgets: ProfileBudgets | None = None,
    ram_budgets: RamBudgets | None = None,
    semantic_options: SemanticOptions | None = None,
) -> dict[str, object]:
    """Compose one deterministic RAM wire payload from two built layer results.

    Pure function over the frozen layer carriers: no clock, no randomness, no
    environment read, no network facility, no file write. Budget and option
    arguments default to the frozen layer defaults and enter the ``build``
    section (and therefore the wire digest); actual elapsed time never does.
    Invalid argument types raise ``ContractError`` (fail-closed).
    """

    if not isinstance(ram_result, RamFactsBuildResult):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.ram_result")
    if not isinstance(semantic_result, SemanticTopNResult):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.semantic_result")
    if profile_budgets is not None and not isinstance(profile_budgets, ProfileBudgets):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.profile_budgets")
    if ram_budgets is not None and not isinstance(ram_budgets, RamBudgets):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.ram_budgets")
    if semantic_options is not None and not isinstance(
        semantic_options, SemanticOptions
    ):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.semantic_options")

    profile_limits = profile_budgets if profile_budgets is not None else ProfileBudgets()
    ram_limits = ram_budgets if ram_budgets is not None else RamBudgets()
    options = semantic_options if semantic_options is not None else SemanticOptions()
    facts = ram_result.facts

    identity: dict[str, object] = {
        "ram_facts_digest": ram_facts_digest(facts),
        "semantic_config_digest": semantic_result.config_digest,
        "semantic_result_digest": semantic_result.result_digest,
        "prompt_digest": semantic_result.prompt_digest,
        "model_digest": semantic_result.model_digest,
        "wire_digest": "",
    }
    payload: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "model_kind": RAM_WIRE_SCHEMA_NAME,
        "build": {
            "profile_budgets": {
                "manifest_max_bytes": profile_limits.manifest_max_bytes,
                "max_manifest_files": profile_limits.max_manifest_files,
            },
            "ram_budgets": {
                "max_python_files": ram_limits.max_python_files,
                "max_key_flows": ram_limits.max_key_flows,
                "max_unresolved_edges": ram_limits.max_unresolved_edges,
            },
            "semantic": {
                "top_n": options.top_n,
                "seed": options.seed,
                "tie_break": options.tie_break,
                "model_id": options.model_id,
                "weights": {
                    name: getattr(options.weights, name) for name in _WEIGHT_FIELDS
                },
                "budgets": {
                    name: getattr(options.budgets, name)
                    for name in _SEMANTIC_BUDGET_FIELDS
                },
            },
        },
        "ram": _ram_section(facts),
        "semantic": {
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
            "coverage_gaps": _gap_dicts(semantic_result.coverage_gaps),
        },
        "identity": identity,
        "provenance": {"provenance_anchor_ids": list(PROVENANCE_ANCHOR_CHAIN)},
        "execution_required": _execution_required(
            facts.coverage_gaps, semantic_result.coverage_gaps
        ),
    }
    identity["wire_digest"] = ram_wire_digest(payload)
    return payload


def validate_ram_wire_payload(payload: Mapping[str, object]) -> None:
    """Validate one RAM wire payload fail-closed against the frozen format.

    Any unknown field, wrong type, out-of-vocabulary category, non-consecutive
    rank, non-parallel parallel array, non-hex digest, wrong provenance order,
    or ``execution_required`` carrier inconsistent with the payload's typed
    coverage gaps raises :class:`lima.contracts.errors.ContractError`; nothing
    is ever silently corrected. Returns ``None`` on success.
    """

    if not isinstance(payload, Mapping):
        raise ContractError(ContractErrorCode.TOP_LEVEL_NOT_OBJECT, "$")
    _check_keys(payload, _TOP_LEVEL_KEYS, "$")
    if payload["schema_version"] != _SCHEMA_VERSION:
        raise ContractError(
            ContractErrorCode.INVALID_FIELD_VALUE, "$.schema_version"
        )
    if payload["model_kind"] != RAM_WIRE_SCHEMA_NAME:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.model_kind")

    ram_gaps = _validate_build(_object_field(payload, "build", "$"))
    semantic_gaps = _validate_ram(_object_field(payload, "ram", "$"))
    semantic_gaps += _validate_semantic(_object_field(payload, "semantic", "$"))
    _validate_identity(_object_field(payload, "identity", "$"))
    _validate_provenance(_object_field(payload, "provenance", "$"))
    _validate_execution(
        _object_field(payload, "execution_required", "$"), ram_gaps + semantic_gaps
    )


def ram_wire_digest(payload: Mapping[str, object]) -> str:
    """Return the 64-hex wire digest: three identity digests plus build config.

    The digest is the ``compute_content_digest`` re-wrap of the payload's
    ``build`` section and the three identity digests
    (``ram_facts_digest``, ``semantic_config_digest``, ``semantic_result_digest``);
    the embedded ``wire_digest`` slot itself never participates, so the
    function is total over finished payloads and equals the embedded value.
    """

    if not isinstance(payload, Mapping):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$")
    identity = payload.get("identity")
    build = payload.get("build")
    if not isinstance(identity, Mapping) or not isinstance(build, Mapping):
        raise ContractError(ContractErrorCode.REQUIRED_FIELD_MISSING, "$")
    return compute_content_digest(
        {
            "build": build,
            "identity": {
                "ram_facts_digest": _digest_slot(identity, "ram_facts_digest"),
                "semantic_config_digest": _digest_slot(
                    identity, "semantic_config_digest"
                ),
                "semantic_result_digest": _digest_slot(
                    identity, "semantic_result_digest"
                ),
            },
        }
    )


def _digest_slot(identity: Mapping[str, object], key: str) -> str:
    value = identity.get(key)
    if not isinstance(value, str):
        raise ContractError(
            ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.identity.{key}"
        )
    return value


def _execution_required(
    *gap_groups: tuple[ProfileCoverageGap, ...],
) -> dict[str, object]:
    codes: list[str] = []
    for group in gap_groups:
        codes.extend(gap.gap_code for gap in group)
    required, triggers = execution_required_from_gaps(codes)
    return {"required": required, "trigger_gap_codes": list(triggers)}


def _entry_dicts(entries: tuple[AttackSurfaceEntry, ...]) -> list[dict[str, object]]:
    return [entry.to_dict() for entry in entries]


def _gap_dicts(gaps: tuple[ProfileCoverageGap, ...]) -> list[dict[str, object]]:
    return [gap.to_dict() for gap in gaps]


def _ram_section(facts: PythonRamFacts) -> dict[str, object]:
    return {
        "entrypoints": _entry_dicts(facts.entrypoints),
        "external_sources": _entry_dicts(facts.external_sources),
        "source_labels": list(facts.source_labels),
        "sensitive_sinks": _entry_dicts(facts.sensitive_sinks),
        "sink_rule_ids": list(facts.sink_rule_ids),
        "sink_cwes": list(facts.sink_cwes),
        "trust_boundaries": _entry_dicts(facts.trust_boundaries),
        "key_flows": [
            {"sink_rule_id": flow.sink_rule_id, "steps": list(flow.steps)}
            for flow in facts.key_flows
        ],
        "unresolved_edges": _entry_dicts(facts.unresolved_edges),
        "coverage_gaps": _gap_dicts(facts.coverage_gaps),
        "counters": dict(facts.counters),
    }


def _check_keys(
    section: Mapping[str, object], allowed: frozenset[str], path: str
) -> None:
    for key in section:
        if not isinstance(key, str) or key not in allowed:
            raise ContractError(ContractErrorCode.UNKNOWN_FIELD, f"{path}.{key}")
    for key in sorted(allowed):
        if key not in section:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"{path}.{key}"
            )


def _object_field(
    section: Mapping[str, object], key: str, path: str
) -> Mapping[str, object]:
    value = section[key]
    if not isinstance(value, Mapping):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, f"{path}.{key}")
    return value


def _capped_list(value: object, path: str) -> list[object]:
    if not isinstance(value, list):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if len(value) > _MAX_ITEMS:
        raise ContractError(ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, path)
    return value


def _str_items(value: object, path: str) -> None:
    if not isinstance(value, list):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    for item in value:
        if not isinstance(item, str):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)


def _positive_int(value: object, path: str) -> None:
    if type(value) is not int or value < 1:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)


def _non_negative_int(value: object, path: str) -> None:
    if type(value) is not int or value < 0:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)


def _hex64(value: object, path: str) -> None:
    if not isinstance(value, str) or _HEX64_PATTERN.fullmatch(value) is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)


def _validate_entries(value: object, path: str) -> None:
    for index, entry in enumerate(_capped_list(value, path)):
        entry_path = f"{path}[{index}]"
        if not isinstance(entry, Mapping):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, entry_path)
        _check_keys(entry, _ENTRY_KEYS, entry_path)
        if not isinstance(entry["path"], str):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_TYPE, f"{entry_path}.path"
            )
        symbol = entry["symbol"]
        if symbol is not None and not isinstance(symbol, str):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_TYPE, f"{entry_path}.symbol"
            )
        _str_items(
            _capped_list(entry["reason_codes"], f"{entry_path}.reason_codes"),
            f"{entry_path}.reason_codes",
        )
        _str_items(
            _capped_list(
                entry["source_artifact_ids"], f"{entry_path}.source_artifact_ids"
            ),
            f"{entry_path}.source_artifact_ids",
        )


def _validate_gaps(value: object, path: str) -> list[str]:
    codes: list[str] = []
    for index, gap in enumerate(_capped_list(value, path)):
        gap_path = f"{path}[{index}]"
        if not isinstance(gap, Mapping):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, gap_path)
        _check_keys(gap, _GAP_KEYS, gap_path)
        code = gap["gap_code"]
        if not isinstance(code, str) or _GAP_CODE_PATTERN.fullmatch(code) is None:
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE, f"{gap_path}.gap_code"
            )
        if not isinstance(gap["detail"], str):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_TYPE, f"{gap_path}.detail"
            )
        codes.append(code)
    return codes


def _validate_build(section: Mapping[str, object]) -> list[str]:
    _check_keys(section, _BUILD_KEYS, "$.build")
    profile_budgets = _object_field(section, "profile_budgets", "$.build")
    _check_keys(profile_budgets, _PROFILE_BUDGET_KEYS, "$.build.profile_budgets")
    _positive_int(
        profile_budgets["manifest_max_bytes"],
        "$.build.profile_budgets.manifest_max_bytes",
    )
    _positive_int(
        profile_budgets["max_manifest_files"],
        "$.build.profile_budgets.max_manifest_files",
    )
    ram_budgets = _object_field(section, "ram_budgets", "$.build")
    _check_keys(ram_budgets, _RAM_BUDGET_KEYS, "$.build.ram_budgets")
    for name in sorted(_RAM_BUDGET_KEYS):
        _positive_int(ram_budgets[name], f"$.build.ram_budgets.{name}")
    semantic = _object_field(section, "semantic", "$.build")
    _check_keys(semantic, _SEMANTIC_BUILD_KEYS, "$.build.semantic")
    top_n = semantic["top_n"]
    if type(top_n) is not int or not 1 <= top_n <= _MAX_TOP_N:
        raise ContractError(
            ContractErrorCode.INVALID_FIELD_VALUE, "$.build.semantic.top_n"
        )
    seed = semantic["seed"]
    if type(seed) is not int or seed < 0:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.build.semantic.seed")
    if semantic["tie_break"] != _TIE_BREAK_FROZEN:
        raise ContractError(
            ContractErrorCode.INVALID_FIELD_VALUE, "$.build.semantic.tie_break"
        )
    if not isinstance(semantic["model_id"], str):
        raise ContractError(
            ContractErrorCode.INVALID_FIELD_TYPE, "$.build.semantic.model_id"
        )
    weights = _object_field(semantic, "weights", "$.build.semantic")
    _check_keys(weights, frozenset(_WEIGHT_FIELDS), "$.build.semantic.weights")
    for name in _WEIGHT_FIELDS:
        _non_negative_int(weights[name], f"$.build.semantic.weights.{name}")
    budgets = _object_field(semantic, "budgets", "$.build.semantic")
    _check_keys(
        budgets, frozenset(_SEMANTIC_BUDGET_FIELDS), "$.build.semantic.budgets"
    )
    for name in _SEMANTIC_BUDGET_FIELDS:
        _positive_int(budgets[name], f"$.build.semantic.budgets.{name}")
    return []


def _validate_ram(section: Mapping[str, object]) -> list[str]:
    _check_keys(section, _RAM_KEYS, "$.ram")
    for name in (
        "entrypoints",
        "external_sources",
        "sensitive_sinks",
        "trust_boundaries",
        "unresolved_edges",
    ):
        _validate_entries(section[name], f"$.ram.{name}")
    for name in ("source_labels", "sink_rule_ids", "sink_cwes"):
        _str_items(_capped_list(section[name], f"$.ram.{name}"), f"$.ram.{name}")
    sink_count = len(_capped_list(section["sensitive_sinks"], "$.ram.sensitive_sinks"))
    if len(_capped_list(section["sink_rule_ids"], "$.ram.sink_rule_ids")) != sink_count:
        raise ContractError(
            ContractErrorCode.INVALID_FIELD_VALUE, "$.ram.sink_rule_ids"
        )
    if len(_capped_list(section["sink_cwes"], "$.ram.sink_cwes")) != sink_count:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.ram.sink_cwes")
    for index, flow in enumerate(_capped_list(section["key_flows"], "$.ram.key_flows")):
        flow_path = f"$.ram.key_flows[{index}]"
        if not isinstance(flow, Mapping):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, flow_path)
        _check_keys(flow, _FLOW_KEYS, flow_path)
        if not isinstance(flow["sink_rule_id"], str):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_TYPE, f"{flow_path}.sink_rule_id"
            )
        steps = _capped_list(flow["steps"], f"{flow_path}.steps")
        _str_items(steps, f"{flow_path}.steps")
        if len(steps) > _MAX_TRACE_STEPS:
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE, f"{flow_path}.steps"
            )
    counters = _object_field(section, "counters", "$.ram")
    _check_keys(counters, frozenset(_COUNTER_FIELDS), "$.ram.counters")
    for name in _COUNTER_FIELDS:
        _non_negative_int(counters[name], f"$.ram.counters.{name}")
    return _validate_gaps(section["coverage_gaps"], "$.ram.coverage_gaps")


def _validate_semantic(section: Mapping[str, object]) -> list[str]:
    _check_keys(section, _SEMANTIC_KEYS, "$.semantic")
    ranked = _capped_list(section["ranked"], "$.semantic.ranked")
    for index, item in enumerate(ranked):
        item_path = f"$.semantic.ranked[{index}]"
        if not isinstance(item, Mapping):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, item_path)
        _check_keys(item, _RANKED_KEYS, item_path)
        candidate = item["candidate_id"]
        if (
            not isinstance(candidate, str)
            or _CANDIDATE_ID_PATTERN.fullmatch(candidate) is None
        ):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE, f"{item_path}.candidate_id"
            )
        for name in ("kind", "path", "rationale"):
            if not isinstance(item[name], str):
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_TYPE, f"{item_path}.{name}"
                )
        symbol = item["symbol"]
        if symbol is not None and not isinstance(symbol, str):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_TYPE, f"{item_path}.symbol"
            )
        _non_negative_int(item["score"], f"{item_path}.score")
        if type(item["rank"]) is not int:
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_TYPE, f"{item_path}.rank"
            )
        category = item["category"]
        if not isinstance(category, str) or category not in _CATEGORY_VOCABULARY:
            raise ContractError(
                ContractErrorCode.UNKNOWN_ENUM_VALUE, f"{item_path}.category"
            )
        _str_items(
            _capped_list(item["key_flow_steps"], f"{item_path}.key_flow_steps"),
            f"{item_path}.key_flow_steps",
        )
    ranks = [item["rank"] for item in ranked]
    if ranks != list(range(1, len(ranked) + 1)):
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.semantic.ranked")
    total = section["total_candidates"]
    if type(total) is not int or total < 0 or total < len(ranked):
        raise ContractError(
            ContractErrorCode.INVALID_FIELD_VALUE, "$.semantic.total_candidates"
        )
    return _validate_gaps(section["coverage_gaps"], "$.semantic.coverage_gaps")


def _validate_identity(section: Mapping[str, object]) -> None:
    _check_keys(section, _IDENTITY_KEYS, "$.identity")
    for name in sorted(_IDENTITY_KEYS):
        _hex64(section[name], f"$.identity.{name}")


def _validate_provenance(section: Mapping[str, object]) -> None:
    _check_keys(section, _PROVENANCE_KEYS, "$.provenance")
    if section["provenance_anchor_ids"] != list(PROVENANCE_ANCHOR_CHAIN):
        raise ContractError(
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.provenance.provenance_anchor_ids",
        )


def _validate_execution(
    section: Mapping[str, object], gap_codes: list[str]
) -> None:
    _check_keys(section, _EXECUTION_KEYS, "$.execution_required")
    required = section["required"]
    if type(required) is not bool:
        raise ContractError(
            ContractErrorCode.INVALID_FIELD_TYPE, "$.execution_required.required"
        )
    triggers = _capped_list(
        section["trigger_gap_codes"], "$.execution_required.trigger_gap_codes"
    )
    _str_items(triggers, "$.execution_required.trigger_gap_codes")
    for code in triggers:
        if code not in GAP_CODES_ALL:
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE,
                "$.execution_required.trigger_gap_codes",
            )
    expected_required, expected_triggers = execution_required_from_gaps(gap_codes)
    if required != expected_required or triggers != list(expected_triggers):
        raise ContractError(
            ContractErrorCode.INVALID_FIELD_VALUE, "$.execution_required"
        )
