"""Main-process Fact Adapter: validate and freeze Sidecar UAF fact bundles.

Plan Task 5 (UAF v2, design section 7.2).  This module is the only place
where validated wire facts from a ``/v1/uaf-facts`` response become
:class:`~lima.uaf_models.UafFact` records.  It is fail-closed and
non-guessing: every wire field must be present, no field may be extra,
and nothing is inferred, defaulted or repaired -- a bundle that does not
match the caller's :class:`~lima.uaf_models.FactBundleExpectation` is
rejected with :class:`FactBundleError` (a ``ValueError`` subclass).

Validation chain (the order below is also the error-report order):

1. Bundle level: the response ``snapshot_sha256`` echo must equal
   ``expectation.snapshot_hash``; the single ``uaf-facts`` tool run must
   be well-formed and its ``run_id`` must sit inside
   ``expectation.allowed_tool_runs``; ``bundle_sha256`` must match a
   local re-derivation via ``uaf_facts_bundle_sha256``.
2. Per translation unit: closed unit / build-context / coverage field
   sets, safe relative paths contained under
   ``expectation.repository_root`` (the root check is skipped when the
   root is the empty string), a completed extraction must pin the
   expected build context hash, and an ``unavailable`` extraction can
   carry neither facts nor AST/CFG completeness claims.
3. Fact level: the per-kind closed field set (``FACT_FIELD_SETS``), then
   :class:`~lima.uaf_models.UafFact` construction; duplicate fact ids
   are rejected, and ``related_fact_ids`` must resolve inside the bundle
   (checked in a second pass after all ids have been collected).
4. Size limits: at most 1024 facts and at most 2 MiB serialized, the
   Sidecar response budget.

Layering note: Task 4 wire facts carry hash provenance at bundle level
(the response snapshot echo and each unit's ``build_context.context_hash``),
not per fact.  The adapter certifies the three-way identity
wire == meta == expectation from those wire legs, and every constructed
fact is stamped with the verified bundle-level values.

``repository_key`` is intentionally not checked: the frozen
:class:`~lima.uaf_models.FactBundleExpectation` carries no repository
identity, and the strict client already echoes it before the adapter
runs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Final

from .cxx_memory import (
    MAX_DIAGNOSTIC_BYTES,
    MAX_DIAGNOSTICS,
    MAX_RUN_ID_BYTES,
    MAX_UAF_TRANSLATION_UNITS,
    UAF_FACTS_EXTRACTIONS,
    UAF_FACTS_SCHEMA_VERSION,
    UAF_FACTS_TOOL,
    UAF_FACTS_TOOL_RUN_STATUSES,
    UafFactsResponse,
    uaf_facts_bundle_sha256,
)
from .uaf_models import (
    RESOLUTION_SOURCE_KINDS,
    RESOLUTION_STATUSES,
    BuildContextResolution,
    ExtractionCoverage,
    FactBundleExpectation,
    FactBundleMeta,
    UafFact,
    UafFactKind,
)

__all__ = [
    "FACT_FIELD_SETS",
    "MAX_BUNDLE_BYTES",
    "MAX_BUNDLE_FACTS",
    "FactBundleError",
    "UafFactBundle",
    "UnitFacts",
    "adapt_uaf_response",
    "load_fact_bundle",
]

MAX_BUNDLE_FACTS: Final = 1024
MAX_BUNDLE_BYTES: Final = 2 * 1024 * 1024
# Mirrors the frozen client path byte budget (MAX_PATH_BYTES in
# lima.cxx_agent_models); kept local to avoid a private cross-import.
_MAX_PATH_BYTES: Final = 4_096
_HEX64: Final = frozenset("0123456789abcdef")

_RESPONSE_KEYS: Final = frozenset(
    {
        "schema_version",
        "request_id",
        "repository_key",
        "snapshot_sha256",
        "tool_runs",
        "translation_units",
        "bundle_sha256",
        "diagnostics",
    }
)
_TOOL_RUN_KEYS: Final = frozenset({"run_id", "tool", "status"})
_UNIT_KEYS: Final = frozenset(
    {"translation_unit", "extraction", "build_context", "coverage", "facts"}
)
_BUILD_CONTEXT_KEYS: Final = frozenset({"status", "source_kind", "context_hash", "diagnostics"})
_COVERAGE_KEYS: Final = frozenset({"ast_complete", "cfg_complete", "semantic_gaps"})

# The seven common wire fields of every Task 4 fact
# (cxx_analyzer/uaf_scan.py, ``_UnitSink.add_fact``): hash provenance
# lives at bundle level, producer/tool-run identity in the bundle header.
_COMMON_FACT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "fact_id",
        "kind",
        "translation_unit",
        "canonical_path",
        "function_usr",
        "source_range",
        "cfg_block",
    }
)
# Per-kind additional fields exactly as the Task 4 extractor emits them.
_TASK4_KIND_EXTRA_FIELDS: Final[dict[str, frozenset[str]]] = {
    "allocation": frozenset({"allocation_api", "pointer_id"}),
    "release": frozenset({"release_api", "pointer_id", "related_fact_ids"}),
    "dereference": frozenset({"pointer_id"}),
    "member-access": frozenset({"pointer_id"}),
    "alias-copy": frozenset({"pointer_id", "source_pointer_id"}),
    "points-to": frozenset({"pointer_id", "source_pointer_id", "related_fact_ids"}),
    "rebind": frozenset({"pointer_id", "source_pointer_id", "related_fact_ids"}),
}
# Closed field set per fact kind.  Kinds the Task 4 extractor does not
# emit yet (lifetime-restart, cfg-node, cfg-edge, coverage-gap) accept the
# common fields only; an extra field is still an unknown field.
FACT_FIELD_SETS: Final[dict[str, frozenset[str]]] = {
    kind.value: _COMMON_FACT_FIELDS | _TASK4_KIND_EXTRA_FIELDS.get(kind.value, frozenset())
    for kind in UafFactKind
}


class FactBundleError(ValueError):
    """A fact bundle failed expectation-driven validation (fail-closed)."""


@dataclass(frozen=True)
class UnitFacts:
    """One translation unit's certified resolution, coverage and facts."""

    translation_unit: str
    build_context: BuildContextResolution
    coverage: ExtractionCoverage
    facts: tuple[UafFact, ...]


@dataclass(frozen=True)
class UafFactBundle:
    """The adapter's certified fact bundle.

    ``facts`` flattens ``per_unit`` in unit order; ``coverage_gaps``
    aggregates every unit's semantic gaps, deduplicated in first-seen
    order.
    """

    meta: FactBundleMeta
    facts: tuple[UafFact, ...]
    per_unit: tuple[UnitFacts, ...]
    coverage_gaps: tuple[str, ...]


# ------------------------------------------------------------------ helpers


def _bounded_strings(value: object, field: str) -> None:
    if type(value) not in (list, tuple) or len(value) > MAX_DIAGNOSTICS:
        raise FactBundleError(f"{field} must be a bounded string list")
    for item in value:
        if not isinstance(item, str) or not item:
            raise FactBundleError(f"{field} entries must be non-empty strings")
        if len(item.encode("utf-8")) > MAX_DIAGNOSTIC_BYTES:
            raise FactBundleError(f"{field} entry exceeds the byte limit")


def _optional_hex64(value: object, field: str) -> None:
    if value == "":
        return
    if not isinstance(value, str) or len(value) != 64 or any(c not in _HEX64 for c in value):
        raise FactBundleError(f"{field} must be a lowercase SHA-256 digest")


def _require_contained_path(value: object, root: str, field: str) -> str:
    """Require a safe relative path and, when rooted, containment under root."""

    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > _MAX_PATH_BYTES
    ):
        raise FactBundleError(f"{field} must be a bounded relative path string")
    if (
        PurePosixPath(value).is_absolute()
        or "\\" in value
        or "\0" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise FactBundleError(f"{field} must be a safe relative POSIX path")
    if root and not value.startswith(root + "/"):
        raise FactBundleError(f"{field} escapes the expected repository root {root!r}")
    return value


def _serialized_bytes(units: object) -> int:
    encoded = json.dumps(
        {"translation_units": units},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return len(encoded.encode("utf-8"))


def _build_fact(
    raw_fact: dict[str, Any],
    index: int,
    unit: str,
    root: str,
    snapshot_hash: str,
    build_context_hash: str,
) -> UafFact:
    """Validate one wire fact against its kind's closed field set and build it."""

    where = f"fact {index} in {unit!r}"
    kind_value = raw_fact.get("kind")
    expected = FACT_FIELD_SETS.get(kind_value) if isinstance(kind_value, str) else None
    if expected is None:
        raise FactBundleError(f"{where}: unknown fact kind {kind_value!r}")
    actual = frozenset(raw_fact)
    unknown = sorted(actual - expected)
    if unknown:
        raise FactBundleError(f"{where}: unknown fact field(s) {', '.join(unknown)}")
    missing = sorted(expected - actual)
    if missing:
        raise FactBundleError(f"{where}: missing fact field(s) {', '.join(missing)}")

    fact_id = raw_fact["fact_id"]
    if not isinstance(fact_id, str):
        raise FactBundleError(f"{where}: fact_id must be a string")
    wire_unit = raw_fact["translation_unit"]
    if wire_unit != unit:
        raise FactBundleError(
            f"{where}: fact translation_unit does not match the containing translation unit"
        )
    canonical_path = _require_contained_path(raw_fact["canonical_path"], root, "canonical_path")
    source_range = raw_fact["source_range"]
    if type(source_range) is not list or len(source_range) != 2:
        raise FactBundleError(f"{where}: source_range must be a [start, end] pair")
    # The closure check above guarantees the key is present exactly when
    # the kind's field set carries it.
    related: tuple[str, ...] = ()
    if "related_fact_ids" in raw_fact:
        related_raw = raw_fact["related_fact_ids"]
        if type(related_raw) is not list:
            raise FactBundleError(f"{where}: related_fact_ids must be a list")
        related = tuple(related_raw)

    try:
        return UafFact(
            fact_id=fact_id,
            kind=UafFactKind(kind_value),
            snapshot_hash=snapshot_hash,
            build_context_hash=build_context_hash,
            translation_unit=wire_unit,
            canonical_path=canonical_path,
            function_usr=raw_fact["function_usr"],
            source_range=(source_range[0], source_range[1]),
            cfg_block=raw_fact["cfg_block"],
            pointer_id=raw_fact.get("pointer_id", ""),
            related_fact_ids=related,
        )
    except ValueError as exc:
        raise FactBundleError(f"{where}: {exc}") from exc


def _validate_tool_run(run: object, expectation: FactBundleExpectation) -> str:
    if type(run) is not dict or frozenset(run) != _TOOL_RUN_KEYS:
        raise FactBundleError("invalid tool run fields")
    run_id = run["run_id"]
    if (
        not isinstance(run_id, str)
        or not run_id
        or len(run_id.encode("utf-8")) > MAX_RUN_ID_BYTES
    ):
        raise FactBundleError("invalid tool run id")
    tool = run["tool"]
    if tool != UAF_FACTS_TOOL:
        raise FactBundleError(f"tool run tool must be {UAF_FACTS_TOOL!r}")
    status = run["status"]
    if not isinstance(status, str) or status not in UAF_FACTS_TOOL_RUN_STATUSES:
        raise FactBundleError("invalid tool run status")
    if run_id not in expectation.allowed_tool_runs:
        raise FactBundleError(f"tool run {run_id!r} is not in the allowed tool runs")
    return run_id


# -------------------------------------------------------------- entry points


def adapt_uaf_response(
    response: UafFactsResponse, expectation: FactBundleExpectation
) -> UafFactBundle:
    """Validate one strict-client response against the expectation and freeze it.

    Raises :class:`FactBundleError` on the first failed check of the
    documented validation chain; a returned bundle is fully certified.
    """

    if not isinstance(response, UafFactsResponse):
        raise FactBundleError("fact bundle response must be a UafFactsResponse")
    if not isinstance(expectation, FactBundleExpectation):
        raise FactBundleError("expectation must be a FactBundleExpectation")
    if len(response.translation_units) > MAX_UAF_TRANSLATION_UNITS:
        raise FactBundleError("fact bundle exceeds the translation unit budget")

    # 1. bundle level
    if response.snapshot_sha256 != expectation.snapshot_hash:
        raise FactBundleError(
            "response snapshot_sha256 does not match the expected snapshot hash"
        )
    if len(response.tool_runs) != 1:
        raise FactBundleError("fact bundle must carry exactly one uaf-facts tool run")
    run_id = _validate_tool_run(response.tool_runs[0], expectation)
    if response.bundle_sha256 != uaf_facts_bundle_sha256(response.translation_units):
        raise FactBundleError("bundle_sha256 does not match the recomputed bundle digest")
    _bounded_strings(response.diagnostics, "response diagnostics")

    try:
        meta = FactBundleMeta(
            snapshot_hash=response.snapshot_sha256,
            build_context_hash=expectation.build_context_hash,
            producer_name=UAF_FACTS_TOOL,
            producer_version=str(UAF_FACTS_SCHEMA_VERSION),
            tool_run_id=run_id,
            bundle_sha256=response.bundle_sha256,
        )
    except ValueError as exc:
        raise FactBundleError(f"invalid bundle header: {exc}") from exc

    # 2. + 3. per translation unit and per fact
    per_unit: list[UnitFacts] = []
    all_facts: list[UafFact] = []
    fact_ids: set[str] = set()
    for entry in response.translation_units:
        if type(entry) is not dict or frozenset(entry) != _UNIT_KEYS:
            raise FactBundleError("invalid translation unit fields")
        unit = _require_contained_path(
            entry["translation_unit"], expectation.repository_root, "translation_unit"
        )
        extraction = entry["extraction"]
        if not isinstance(extraction, str) or extraction not in UAF_FACTS_EXTRACTIONS:
            raise FactBundleError(f"translation unit {unit!r}: invalid extraction")

        context = entry["build_context"]
        if type(context) is not dict or frozenset(context) != _BUILD_CONTEXT_KEYS:
            raise FactBundleError(f"translation unit {unit!r}: invalid build_context fields")
        status = context["status"]
        if not isinstance(status, str) or status not in RESOLUTION_STATUSES:
            raise FactBundleError(f"translation unit {unit!r}: invalid build context status")
        source_kind = context["source_kind"]
        if source_kind != "" and (
            not isinstance(source_kind, str) or source_kind not in RESOLUTION_SOURCE_KINDS
        ):
            raise FactBundleError(f"translation unit {unit!r}: invalid build context source kind")
        context_hash = context["context_hash"]
        _optional_hex64(context_hash, f"translation unit {unit!r}: build_context.context_hash")
        _bounded_strings(context["diagnostics"], "build_context diagnostics")

        coverage = entry["coverage"]
        if type(coverage) is not dict or frozenset(coverage) != _COVERAGE_KEYS:
            raise FactBundleError(f"translation unit {unit!r}: invalid coverage fields")
        ast_complete = coverage["ast_complete"]
        cfg_complete = coverage["cfg_complete"]
        if type(ast_complete) is not bool or type(cfg_complete) is not bool:
            raise FactBundleError(f"translation unit {unit!r}: invalid coverage flags")
        _bounded_strings(coverage["semantic_gaps"], "coverage semantic_gaps")

        facts = entry["facts"]
        if type(facts) is not list:
            raise FactBundleError(f"translation unit {unit!r}: facts must be a list")
        if facts and extraction != "completed":
            raise FactBundleError(
                f"translation unit {unit!r}: unavailable extraction cannot carry facts"
            )
        if extraction == "unavailable" and (ast_complete or cfg_complete):
            raise FactBundleError(
                f"translation unit {unit!r}: unavailable extraction cannot claim AST or "
                "CFG completeness"
            )
        if extraction == "completed" and context_hash != expectation.build_context_hash:
            raise FactBundleError(
                f"translation unit {unit!r}: build_context.context_hash does not match "
                "the expected build context hash"
            )

        try:
            resolution = BuildContextResolution(
                status=status,
                source_kind=source_kind,
                context_hash=context_hash,
                diagnostics=tuple(context["diagnostics"]),
            )
            unit_coverage = ExtractionCoverage(
                ast_complete=ast_complete,
                cfg_complete=cfg_complete,
                semantic_gaps=tuple(coverage["semantic_gaps"]),
            )
        except ValueError as exc:
            raise FactBundleError(f"translation unit {unit!r}: {exc}") from exc

        unit_facts: list[UafFact] = []
        for index, raw_fact in enumerate(facts):
            if type(raw_fact) is not dict:
                raise FactBundleError(f"fact {index} in {unit!r} must be a JSON object")
            fact = _build_fact(
                raw_fact,
                index,
                unit,
                expectation.repository_root,
                snapshot_hash=meta.snapshot_hash,
                build_context_hash=context_hash,
            )
            if fact.fact_id in fact_ids:
                raise FactBundleError(f"duplicate fact_id {fact.fact_id!r} in the bundle")
            fact_ids.add(fact.fact_id)
            unit_facts.append(fact)
        per_unit.append(
            UnitFacts(
                translation_unit=unit,
                build_context=resolution,
                coverage=unit_coverage,
                facts=tuple(unit_facts),
            )
        )
        all_facts.extend(unit_facts)

    # 3. second pass: every related reference must resolve inside the bundle.
    for fact in all_facts:
        for related_id in fact.related_fact_ids:
            if related_id not in fact_ids:
                raise FactBundleError(
                    f"dangling related_fact_ids reference {related_id!r} in fact "
                    f"{fact.fact_id!r}"
                )

    # 4. size limits (Sidecar response budget)
    if len(all_facts) > MAX_BUNDLE_FACTS:
        raise FactBundleError(f"fact bundle exceeds the fact budget of {MAX_BUNDLE_FACTS}")
    if _serialized_bytes(response.translation_units) > MAX_BUNDLE_BYTES:
        raise FactBundleError(
            f"serialized fact bundle exceeds the {MAX_BUNDLE_BYTES}-byte budget"
        )

    coverage_gaps: list[str] = []
    seen_gaps: set[str] = set()
    for unit_facts in per_unit:
        for gap in unit_facts.coverage.semantic_gaps:
            if gap not in seen_gaps:
                seen_gaps.add(gap)
                coverage_gaps.append(gap)

    return UafFactBundle(
        meta=meta,
        facts=tuple(all_facts),
        per_unit=tuple(per_unit),
        coverage_gaps=tuple(coverage_gaps),
    )


def load_fact_bundle(raw: dict, expectation: FactBundleExpectation) -> UafFactBundle:
    """Adapt a bare ``/v1/uaf-facts`` wire dict (client bypass, tests).

    Performs the minimal closed-form checks the strict client would
    apply at the JSON boundary (exact response field set, schema
    version, field types) and then delegates the full expectation-driven
    chain to :func:`adapt_uaf_response`.  Duplicate JSON keys must
    already have been rejected at the JSON layer.
    """

    if not isinstance(raw, dict):
        raise FactBundleError("fact bundle response must be a JSON object")
    if frozenset(raw) != _RESPONSE_KEYS:
        raise FactBundleError("unexpected /v1/uaf-facts response field set")
    version = raw["schema_version"]
    if type(version) is not int or version != UAF_FACTS_SCHEMA_VERSION:
        raise FactBundleError("unsupported fact bundle schema version")
    for field in ("request_id", "repository_key", "snapshot_sha256", "bundle_sha256"):
        value = raw[field]
        if not isinstance(value, str) or (field in ("request_id", "repository_key") and not value):
            raise FactBundleError(f"response field {field} must be a non-empty string")
    for field in ("tool_runs", "translation_units", "diagnostics"):
        if type(raw[field]) is not list:
            raise FactBundleError(f"response field {field} must be a list")
    response = UafFactsResponse(
        request_id=raw["request_id"],
        repository_key=raw["repository_key"],
        snapshot_sha256=raw["snapshot_sha256"],
        tool_runs=tuple(raw["tool_runs"]),
        translation_units=tuple(raw["translation_units"]),
        bundle_sha256=raw["bundle_sha256"],
        diagnostics=tuple(raw["diagnostics"]),
    )
    return adapt_uaf_response(response, expectation)
