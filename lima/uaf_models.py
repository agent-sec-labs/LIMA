"""Strict, immutable contracts for the C/C++ UAF v2 review pipeline.

This module freezes the identity, fact, proof and completeness contracts of
the UAF v2 design (``docs/superpowers/specs/2026-09-10-cxx-uaf-v2-design.md``
sections 4/5/7).  Everything here is deterministic and fail-closed:

- ``CandidateIdentity`` is the only legal composite run identity.  The
  ``candidate_id`` alone is reproducible across snapshots and is never a
  global run identity; every map/set/cache key must go through
  :meth:`CandidateIdentity.as_key` -- a full ``(snapshot_hash, candidate_id)``
  pair.
- ``derive_object_id`` / ``derive_candidate_id`` hash a canonical material
  tuple (JSON, ``sort_keys`` + compact separators) so inserting an unrelated
  allocation never drifts existing object identities.
- Evidence levels are never redefined here: PASS/REFUTED proof results hint
  at the frozen ``EvidenceLevel``/``EvidencePolarity`` pair from
  :mod:`lima.contracts.evidence`.  No mixed level+polarity enums exist.
- ``ProofReadiness`` defines the necessary condition for ``fact-verified``:
  a ``resolved`` build context, complete AST and CFG extraction, and no
  critical coverage gap.  Heuristic, ``incomplete`` or ``unavailable``
  build contexts are never complete, and unknown proof results are never
  evidence.

Producer/tool-run metadata lives on the bundle header
(:class:`FactBundleMeta`), not on individual facts; cross-fact integrity
(unknown fields, duplicate ids, dangling references) is the bundle
validator's job (``load_fact_bundle``, plan Task 5), driven by
:class:`FactBundleExpectation`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Final

from .contracts.evidence import EvidenceLevel, EvidencePolarity
from .cxx_agent_models import _bounded_text, _hex_digest, _safe_relative_path

__all__ = [
    "BuildContextResolution",
    "CandidateIdentity",
    "ExtractionCoverage",
    "FactBundleExpectation",
    "FactBundleMeta",
    "OBLIGATION_VERDICTS",
    "PROOF_OBLIGATIONS",
    "PROOF_VERDICTS",
    "P5Detail",
    "ProofObligation",
    "ProofReadiness",
    "ProofResult",
    "RESOLUTION_SOURCE_KINDS",
    "RESOLUTION_STATUSES",
    "UAF_SCHEMA_VERSION",
    "UafCandidate",
    "UafFact",
    "UafFactKind",
    "derive_candidate_id",
    "derive_object_id",
    "proof_readiness",
]

UAF_SCHEMA_VERSION: Final = 1
MAX_LINE_VALUE: Final = 10_000_000
MAX_CFG_BLOCK_VALUE: Final = 10_000_000
MAX_WITNESS_BLOCKS: Final = 1_024
MAX_GUARD_FACTS: Final = 256

_CANDIDATE_CWE: Final = "CWE-416"


class UafFactKind(str, Enum):  # noqa: UP042 -- fact kinds are frozen wire values
    """The eleven first-phase fact kinds (design section 7.2)."""

    ALLOCATION = "allocation"
    POINTS_TO = "points-to"
    ALIAS_COPY = "alias-copy"
    RELEASE = "release"
    DEREFERENCE = "dereference"
    MEMBER_ACCESS = "member-access"
    REBIND = "rebind"
    LIFETIME_RESTART = "lifetime-restart"
    CFG_NODE = "cfg-node"
    CFG_EDGE = "cfg-edge"
    COVERAGE_GAP = "coverage-gap"


class ProofObligation(str, Enum):  # noqa: UP042 -- obligation codes are frozen
    """The seven first-phase proof obligations P1-P7 (design section 9.1)."""

    P1 = "P1"  # concrete object exists
    P2 = "P2"  # pointer/alias refers to the object
    P3 = "P3"  # object is released
    P4 = "P4"  # post-release use exists
    P5 = "P5"  # release-to-use path is reachable and feasible
    P6 = "P6"  # no pointer rebind on the witness path
    P7 = "P7"  # no lifetime restart on the witness path


PROOF_OBLIGATIONS: Final = (
    ProofObligation.P1,
    ProofObligation.P2,
    ProofObligation.P3,
    ProofObligation.P4,
    ProofObligation.P5,
    ProofObligation.P6,
    ProofObligation.P7,
)
OBLIGATION_VERDICTS: Final = frozenset({"satisfied", "refuted", "unknown"})
PROOF_VERDICTS: Final = frozenset({"PASS", "REFUTED", "UNKNOWN"})
RESOLUTION_STATUSES: Final = frozenset({"resolved", "incomplete", "unavailable"})
RESOLUTION_SOURCE_KINDS: Final = frozenset(
    {"repository-compdb", "cmake-export", "build-adapter", "heuristic"}
)


# ------------------------------------------------------------------ helpers


def _sha256_of_material(material: dict) -> str:
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _positive_version(value: object, field_name: str) -> int:
    if isinstance(value, bool) or type(value) is not int or value < 1:
        raise ValueError(f"{field_name} must be a positive schema version")
    return value


def _line_value(value: object, field_name: str) -> int:
    if isinstance(value, bool) or type(value) is not int:
        raise ValueError(f"{field_name} must be an integer")
    if not 1 <= value <= MAX_LINE_VALUE:
        raise ValueError(f"{field_name} is outside the allowed line range")
    return value


def _cfg_block(value: object, field_name: str) -> int:
    if isinstance(value, bool) or type(value) is not int:
        raise ValueError(f"{field_name} must be an integer")
    if not 0 <= value <= MAX_CFG_BLOCK_VALUE:
        raise ValueError(f"{field_name} is outside the allowed block range")
    return value


def _closed_range(value: object, field_name: str) -> tuple[int, int]:
    if type(value) is not tuple or len(value) != 2:
        raise ValueError(f"{field_name} must be a (start, end) tuple")
    start = _line_value(value[0], f"{field_name}[0]")
    end = _line_value(value[1], f"{field_name}[1]")
    if end < start:
        raise ValueError(f"{field_name} end precedes start")
    return (start, end)


def _cfg_block_tuple(value: object, field_name: str) -> tuple[int, ...]:
    if type(value) is not tuple:
        raise ValueError(f"{field_name} must be a tuple")
    if len(value) > MAX_WITNESS_BLOCKS:
        raise ValueError(f"{field_name} exceeds the block budget")
    return tuple(_cfg_block(item, f"{field_name}[{index}]") for index, item in enumerate(value))


def _hex_tuple(value: object, field_name: str, *, cap: int = MAX_GUARD_FACTS) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise ValueError(f"{field_name} must be a tuple")
    if len(value) > cap:
        raise ValueError(f"{field_name} exceeds the entry budget")
    return tuple(_hex_digest(item, f"{field_name}[{index}]") for index, item in enumerate(value))


def _text_tuple(value: object, field_name: str, *, cap: int = MAX_GUARD_FACTS) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise ValueError(f"{field_name} must be a tuple")
    if len(value) > cap:
        raise ValueError(f"{field_name} exceeds the entry budget")
    return tuple(
        _bounded_text(item, f"{field_name}[{index}]") for index, item in enumerate(value)
    )


def _optional_hex(value: object, field_name: str) -> str:
    if value == "":
        return ""
    return _hex_digest(value, field_name)


def _optional_text(value: object, field_name: str) -> str:
    if value == "":
        return ""
    return _bounded_text(value, field_name)


def _strict_bool(value: object, field_name: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{field_name} must be a boolean")
    return value


def _domain_member(value: object, domain: frozenset, field_name: str) -> str:
    if not isinstance(value, str) or value not in domain:
        raise ValueError(f"{field_name} is outside the closed domain")
    return value


# ------------------------------------------------------------------ identity


def derive_object_id(
    schema_version: int,
    canonical_path: str,
    function_usr: str,
    alloc_begin_line: int,
    alloc_end_line: int,
    alloc_kind: str,
) -> str:
    """Hash the canonical allocation tuple into a stable object id.

    The material is the design section 7.1 tuple: schema version, canonical
    repository-relative path, function USR, allocation AST begin/end line and
    the allocation kind.  No ordinal participates, so inserting an unrelated
    allocation before the object never changes this id.  A missing function
    USR is refused here: callers must record a coverage gap instead of
    fabricating a substitute string identity.
    """

    begin = _line_value(alloc_begin_line, "alloc_begin_line")
    end = _line_value(alloc_end_line, "alloc_end_line")
    if end < begin:
        raise ValueError("allocation range end precedes start")
    material = {
        "schema_version": _positive_version(schema_version, "schema_version"),
        "canonical_path": _safe_relative_path(canonical_path, "canonical_path"),
        "function_usr": _bounded_text(function_usr, "function_usr"),
        "alloc_begin_line": begin,
        "alloc_end_line": end,
        "alloc_kind": _bounded_text(alloc_kind, "alloc_kind"),
    }
    return _sha256_of_material(material)


def derive_candidate_id(
    schema_version: int,
    object_id: str,
    release_fact_id: str,
    use_fact_id: str,
) -> str:
    """Hash the canonical candidate tuple (CWE-416 mixed into the material).

    Distinct release/use pairs on the same object never collapse into one
    candidate, and the id is reproducible across snapshots.
    """

    material = {
        "schema_version": _positive_version(schema_version, "schema_version"),
        "cwe": _CANDIDATE_CWE,
        "object_id": _hex_digest(object_id, "object_id"),
        "release_fact_id": _hex_digest(release_fact_id, "release_fact_id"),
        "use_fact_id": _hex_digest(use_fact_id, "use_fact_id"),
    }
    return _sha256_of_material(material)


@dataclass(frozen=True)
class CandidateIdentity:
    """The composite UAF candidate identity.

    ``candidate_id`` is stable across snapshots (derived from snapshot-independent
    material); it is a reproducible local id, never a global run identity.
    Every in-memory map/set, cache, message, persisted record and database key
    must use the full pair via :meth:`as_key` -- a bare ``candidate_id`` lookup
    across snapshots is forbidden by design section 7.1.
    """

    snapshot_hash: str
    candidate_id: str

    def __post_init__(self) -> None:
        _hex_digest(self.snapshot_hash, "snapshot_hash")
        _hex_digest(self.candidate_id, "candidate_id")

    def as_key(self) -> tuple[str, str]:
        """Return the only legal composite key form for this identity."""

        return (self.snapshot_hash, self.candidate_id)


# ------------------------------------------------------------------ candidate


@dataclass(frozen=True)
class UafCandidate:
    """One release/use pair frozen for review (plan Task 6/7/8/9 share it).

    ``function_usr`` may be empty: a candidate whose function USR is missing
    still carries its identity, but the missing USR must be recorded as a
    coverage gap and forbids any PASS direction downstream.
    """

    candidate_id: str
    object_id: str
    allocation_fact_id: str
    release_fact_id: str
    use_fact_id: str
    canonical_path: str
    function_usr: str
    release_range: tuple[int, int]
    use_range: tuple[int, int]

    def __post_init__(self) -> None:
        _hex_digest(self.candidate_id, "candidate_id")
        _hex_digest(self.object_id, "object_id")
        _hex_digest(self.allocation_fact_id, "allocation_fact_id")
        _hex_digest(self.release_fact_id, "release_fact_id")
        _hex_digest(self.use_fact_id, "use_fact_id")
        if len({self.allocation_fact_id, self.release_fact_id, self.use_fact_id}) != 3:
            raise ValueError("allocation, release and use fact ids must be distinct")
        _safe_relative_path(self.canonical_path, "canonical_path")
        _optional_text(self.function_usr, "function_usr")
        object.__setattr__(
            self, "release_range", _closed_range(self.release_range, "release_range")
        )
        object.__setattr__(self, "use_range", _closed_range(self.use_range, "use_range"))


# ------------------------------------------------------------------ bundles


@dataclass(frozen=True)
class FactBundleExpectation:
    """What a fact bundle must match before any fact is accepted.

    ``repository_root`` is the non-drifty snapshot-relative root the bundle's
    paths are validated against (empty string means the snapshot root itself);
    ``allowed_tool_runs`` is the closed allowlist of acceptable
    ``tool_run_id`` values.  This is the Task 1 / fact-phase contract; the
    candidate-scoped check happens after candidate generation.

    Multi-TU responses: each completed translation unit may pin a distinct
    ``build_context.context_hash`` (distinct compdb entries mean distinct
    compile arguments and therefore distinct, individually correct hashes).
    The expectation then carries the closed allowlist of those hashes in
    ``allowed_context_hashes`` with an empty ``build_context_hash`` anchor,
    and a completed unit is accepted only when its hash is the anchor or a
    member of that allowlist.  ``build_context_hash`` keeps its single-hash
    anchor semantics and may be empty if and only if ``allowed_context_hashes``
    is non-empty -- at least one hash source must pin the bundle; both being
    empty is refused.
    """

    snapshot_hash: str
    build_context_hash: str
    repository_root: str
    allowed_tool_runs: frozenset[str]
    allowed_context_hashes: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        _hex_digest(self.snapshot_hash, "snapshot_hash")
        if self.build_context_hash != "":
            _hex_digest(self.build_context_hash, "build_context_hash")
        if self.repository_root != "":
            _safe_relative_path(self.repository_root, "repository_root")
        if not isinstance(self.allowed_tool_runs, (frozenset, set)):
            raise ValueError("allowed_tool_runs must be a frozenset of run names")
        normalized = frozenset(
            _bounded_text(run, f"allowed_tool_runs[{index}]")
            for index, run in enumerate(sorted(self.allowed_tool_runs))
        )
        object.__setattr__(self, "allowed_tool_runs", normalized)
        if not isinstance(self.allowed_context_hashes, frozenset | set):
            raise ValueError(
                "allowed_context_hashes must be a frozenset of SHA-256 digests"
            )
        normalized_hashes = frozenset(
            _hex_digest(item, f"allowed_context_hashes[{index}]")
            for index, item in enumerate(sorted(self.allowed_context_hashes))
        )
        object.__setattr__(self, "allowed_context_hashes", normalized_hashes)
        if self.build_context_hash == "" and not normalized_hashes:
            raise ValueError(
                "build_context_hash may be empty only when allowed_context_hashes "
                "carries at least one hash"
            )


@dataclass(frozen=True)
class FactBundleMeta:
    """Bundle header: provenance metadata shared by every fact inside.

    Producer and tool-run identity live here, once per bundle, never
    duplicated onto individual :class:`UafFact` records.
    """

    snapshot_hash: str
    build_context_hash: str
    producer_name: str
    producer_version: str
    tool_run_id: str
    bundle_sha256: str = ""

    def __post_init__(self) -> None:
        _hex_digest(self.snapshot_hash, "snapshot_hash")
        _hex_digest(self.build_context_hash, "build_context_hash")
        _bounded_text(self.producer_name, "producer_name")
        _bounded_text(self.producer_version, "producer_version")
        _bounded_text(self.tool_run_id, "tool_run_id")
        _optional_hex(self.bundle_sha256, "bundle_sha256")


@dataclass(frozen=True)
class UafFact:
    """One Clang-derived UAF fact (design section 7.2).

    Cross-fact integrity -- unknown fields, duplicate fact ids and dangling
    ``related_fact_ids`` references -- is enforced by the bundle validator
    against a :class:`FactBundleExpectation`; the constructor validates each
    field's own value domain only.
    """

    fact_id: str
    kind: UafFactKind
    snapshot_hash: str
    build_context_hash: str
    translation_unit: str
    canonical_path: str
    function_usr: str
    source_range: tuple[int, int]
    cfg_block: int
    object_id: str = ""
    pointer_id: str = ""
    related_fact_ids: tuple[str, ...] = ()
    # Task 6 contract-gap closure: the wire api (allocation/release) and the
    # alias source pointer are validated and kept, never dropped.
    api: str = ""
    source_pointer_id: str = ""

    def __post_init__(self) -> None:
        _hex_digest(self.fact_id, "fact_id")
        if not isinstance(self.kind, UafFactKind):
            raise ValueError("kind must be a UafFactKind")
        _hex_digest(self.snapshot_hash, "snapshot_hash")
        _hex_digest(self.build_context_hash, "build_context_hash")
        _safe_relative_path(self.translation_unit, "translation_unit")
        _safe_relative_path(self.canonical_path, "canonical_path")
        _optional_text(self.function_usr, "function_usr")
        object.__setattr__(self, "source_range", _closed_range(self.source_range, "source_range"))
        _cfg_block(self.cfg_block, "cfg_block")
        _optional_hex(self.object_id, "object_id")
        _optional_text(self.pointer_id, "pointer_id")
        object.__setattr__(
            self, "related_fact_ids", _hex_tuple(self.related_fact_ids, "related_fact_ids")
        )
        _optional_text(self.api, "api")
        _optional_text(self.source_pointer_id, "source_pointer_id")


# ------------------------------------------------------------------ proof


@dataclass(frozen=True)
class ObligationVerdict:
    """The outcome of one proof obligation over concrete facts."""

    obligation: ProofObligation
    verdict: str
    fact_ids: tuple[str, ...]
    reason: str
    witness_cfg_blocks: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.obligation, ProofObligation):
            raise ValueError("obligation must be a ProofObligation")
        _domain_member(self.verdict, OBLIGATION_VERDICTS, "verdict")
        object.__setattr__(self, "fact_ids", _hex_tuple(self.fact_ids, "fact_ids"))
        _bounded_text(self.reason, "reason")
        object.__setattr__(
            self,
            "witness_cfg_blocks",
            _cfg_block_tuple(self.witness_cfg_blocks, "witness_cfg_blocks"),
        )


@dataclass(frozen=True)
class P5Detail:
    """P5's two explicit sub-results (design section 9.1).

    CFG reachability is never silently treated as path feasibility: both
    sub-verdicts share the three-state obligation vocabulary and the P5
    mapping (any ``refuted`` -> refuted, both ``satisfied`` -> satisfied,
    otherwise ``unknown``) is the proof engine's decision, not this type's.
    """

    structural_reachability: str
    path_feasibility: str
    witness_cfg_blocks: tuple[int, ...]
    guard_facts: tuple[str, ...]
    unresolved_constraints: tuple[str, ...]

    def __post_init__(self) -> None:
        _domain_member(
            self.structural_reachability, OBLIGATION_VERDICTS, "structural_reachability"
        )
        _domain_member(self.path_feasibility, OBLIGATION_VERDICTS, "path_feasibility")
        object.__setattr__(
            self,
            "witness_cfg_blocks",
            _cfg_block_tuple(self.witness_cfg_blocks, "witness_cfg_blocks"),
        )
        object.__setattr__(self, "guard_facts", _hex_tuple(self.guard_facts, "guard_facts"))
        object.__setattr__(
            self,
            "unresolved_constraints",
            _text_tuple(self.unresolved_constraints, "unresolved_constraints"),
        )


@dataclass(frozen=True)
class ProofResult:
    """The deterministic proof verdict over one candidate.

    ``obligations`` must carry exactly one verdict per P1-P7.  ``UNKNOWN``
    results are not evidence: :meth:`evidence_hint` refuses them, so an
    unknown can never be dressed up as a level/polarity pair.
    """

    verdict: str
    obligations: tuple[ObligationVerdict, ...]
    p5_detail: P5Detail | None = None

    def __post_init__(self) -> None:
        _domain_member(self.verdict, PROOF_VERDICTS, "verdict")
        if type(self.obligations) is not tuple or not self.obligations:
            raise ValueError("obligations must be a non-empty tuple")
        seen = []
        for index, item in enumerate(self.obligations):
            if not isinstance(item, ObligationVerdict):
                raise ValueError(f"obligations[{index}] must be an ObligationVerdict")
            seen.append(item.obligation)
        if len(seen) != len(PROOF_OBLIGATIONS) or set(seen) != set(PROOF_OBLIGATIONS):
            raise ValueError("obligations must cover P1-P7 exactly once each")
        if self.p5_detail is not None and not isinstance(self.p5_detail, P5Detail):
            raise ValueError("p5_detail must be a P5Detail")

    def evidence_hint(self) -> tuple[EvidenceLevel, EvidencePolarity]:
        """Map the verdict onto the frozen evidence level/polarity pair.

        PASS and REFUTED are deterministic static outcomes and both carry
        D2 with their polarity; UNKNOWN is not evidence at all and raises
        instead of inventing a level.
        """

        if self.verdict == "PASS":
            return (EvidenceLevel.D2, EvidencePolarity.SUPPORTS)
        if self.verdict == "REFUTED":
            return (EvidenceLevel.D2, EvidencePolarity.REFUTES)
        raise ValueError("UNKNOWN proof results carry no evidence level or polarity")


# ------------------------------------------------------- completeness trio


@dataclass(frozen=True)
class BuildContextResolution:
    """Whether compile semantics are pinned for one translation unit.

    This type only answers the build-context question.  It never claims
    Clang parse success or AST/CFG generation: that is
    :class:`ExtractionCoverage`'s answer.  A ``heuristic`` source kind is
    always paired with ``incomplete`` by the resolver.
    """

    status: str
    source_kind: str = ""
    context_hash: str = ""
    diagnostics: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _domain_member(self.status, RESOLUTION_STATUSES, "status")
        if self.source_kind != "":
            _domain_member(self.source_kind, RESOLUTION_SOURCE_KINDS, "source_kind")
        _optional_hex(self.context_hash, "context_hash")
        object.__setattr__(
            self, "diagnostics", _text_tuple(self.diagnostics, "diagnostics")
        )


@dataclass(frozen=True)
class ExtractionCoverage:
    """Whether AST and CFG extraction fully supported the target function."""

    ast_complete: bool
    cfg_complete: bool
    semantic_gaps: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _strict_bool(self.ast_complete, "ast_complete")
        _strict_bool(self.cfg_complete, "cfg_complete")
        object.__setattr__(
            self, "semantic_gaps", _text_tuple(self.semantic_gaps, "semantic_gaps")
        )


@dataclass(frozen=True)
class ProofReadiness:
    """The necessary condition for ``fact-verified`` (design section 6.3).

    ``complete`` is ``resolved`` AND AST-complete AND CFG-complete AND no
    critical gap.  ``heuristic``, ``incomplete`` and ``unavailable``
    resolution statuses are never complete, so a heuristic build context can
    never reach ``fact-verified`` regardless of how the facts look.
    """

    resolution_status: str
    ast_complete: bool
    cfg_complete: bool
    critical_gaps: bool

    def __post_init__(self) -> None:
        _domain_member(self.resolution_status, RESOLUTION_STATUSES, "resolution_status")
        _strict_bool(self.ast_complete, "ast_complete")
        _strict_bool(self.cfg_complete, "cfg_complete")
        _strict_bool(self.critical_gaps, "critical_gaps")

    @property
    def complete(self) -> bool:
        return (
            self.resolution_status == "resolved"
            and self.ast_complete
            and self.cfg_complete
            and not self.critical_gaps
        )


def proof_readiness(
    resolution: BuildContextResolution,
    coverage: ExtractionCoverage,
    critical: bool,
) -> ProofReadiness:
    """Combine the completeness trio into one readiness verdict.

    Pure and deterministic; ``critical`` is the caller's judgement that at
    least one coverage gap blocks a verified outcome (design section 4,
    invariant 7: any critical coverage gap prevents ``fact-verified``).
    """

    if not isinstance(resolution, BuildContextResolution):
        raise ValueError("resolution must be a BuildContextResolution")
    if not isinstance(coverage, ExtractionCoverage):
        raise ValueError("coverage must be an ExtractionCoverage")
    return ProofReadiness(
        resolution_status=resolution.status,
        ast_complete=coverage.ast_complete,
        cfg_complete=coverage.cfg_complete,
        critical_gaps=_strict_bool(critical, "critical"),
    )
