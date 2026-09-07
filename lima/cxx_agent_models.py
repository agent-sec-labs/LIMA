"""Strict, immutable data contracts for the C/C++ LLM agent layer.

Every model output crosses a `from_untrusted_json` constructor that
validates field sets, types, bounds and value domains before any value
reaches the collaboration pipeline. Unknown fields, duplicate keys,
out-of-range numbers, unsafe paths and foreign verification states are
rejected outright; nothing is accepted partially.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Final

from .models import Severity

CXX_AGENT_VERIFICATION_STATES: Final = frozenset(
    {
        "llm-candidate",
        "agent-corroborated",
        "tool-corroborated",
        "runtime-confirmed",
        "human-confirmed",
        "needs-human-review",
    }
)
VERIFIED_STATES: Final = frozenset(
    {
        "agent-corroborated",
        "tool-corroborated",
        "runtime-confirmed",
        "human-confirmed",
    }
)
AGENT_CONSENSUS_KEYS: Final = (
    "cwe",
    "path",
    "symbol",
    "resource",
    "mechanism",
    "trigger-overlap",
)
SUPPORTED_CWES: Final = frozenset({"CWE-787", "CWE-125", "CWE-416", "CWE-415"})
AGENT_ROLES: Final = frozenset(
    {
        "planner",
        "memory-lifetime",
        "bounds",
        "interprocedural",
        "critic",
        "evidence",
        "verifier",
        "arbiter",
    }
)
MAX_TEXT_BYTES: Final = 2_048
MAX_PATH_BYTES: Final = 4_096
MAX_TRIGGER_STEPS: Final = 32
MAX_TRIGGER_STEP_BYTES: Final = 256
MAX_CONTEXT_LINES: Final = 4_096
MAX_REGIONS: Final = 64
MAX_REGION_BYTES: Final = 4_096
_HEX64 = frozenset("0123456789abcdef")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def parse_untrusted_json(raw: str | bytes) -> Any:
    """Parse one JSON document rejecting duplicate keys and odd numbers."""

    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("payload is not UTF-8") from exc
    if not isinstance(raw, str):
        raise ValueError("payload must be text")
    try:
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("payload is not valid JSON") from exc


def _exact_fields(payload: Any, expected: frozenset[str]) -> dict[str, Any]:
    if type(payload) is not dict or set(payload) != expected:
        raise ValueError("payload fields do not match the contract")
    return payload


def _bounded_text(value: Any, field_name: str, maximum: int = MAX_TEXT_BYTES) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be non-empty text")
    if len(value.encode("utf-8")) > maximum:
        raise ValueError(f"{field_name} exceeds the byte limit")
    return value


def _safe_relative_path(value: Any, field_name: str) -> str:
    text = _bounded_text(value, field_name, MAX_PATH_BYTES)
    parsed = PurePosixPath(text)
    if (
        parsed.is_absolute()
        or "\\" in text
        or "\0" in text
        or any(part in {"", ".", ".."} for part in text.split("/"))
        or text.startswith("/")
    ):
        raise ValueError(f"{field_name} must be a safe relative POSIX path")
    return text


def _hex_digest(value: Any, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HEX64 for character in value)
    ):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _confidence(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("confidence must be a number")
    try:
        number = float(value)
    except (OverflowError, ValueError) as exc:
        raise ValueError("confidence must be a finite number") from exc
    if not 0.0 <= number <= 1.0:
        raise ValueError("confidence must be between zero and one")
    return number


def _bounded_int(value: Any, field_name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or type(value) is not int:
        raise ValueError(f"{field_name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{field_name} is outside the allowed range")
    return value


def _bounded_flag(value: Any, field_name: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{field_name} must be a boolean")
    return value


@dataclass(frozen=True)
class ContextReference:
    """A snapshot-verified code range an agent actually read."""

    path: str
    start_line: int
    end_line: int
    content_sha256: str

    @classmethod
    def from_untrusted_json(cls, payload: Any) -> ContextReference:
        fields = _exact_fields(
            payload,
            frozenset(
                {"path", "start_line", "end_line", "content_sha256"}
            ),
        )
        start = _bounded_int(fields["start_line"], "start_line", 1, 10_000_000)
        end = _bounded_int(fields["end_line"], "end_line", 1, 10_000_000)
        if end < start:
            raise ValueError("context range end precedes start")
        if end - start + 1 > MAX_CONTEXT_LINES:
            raise ValueError("context range exceeds the line budget")
        return cls(
            path=_safe_relative_path(fields["path"], "path"),
            start_line=start,
            end_line=end,
            content_sha256=_hex_digest(fields["content_sha256"], "content_sha256"),
        )


@dataclass(frozen=True)
class CxxAgentCandidate:
    """One LLM-proposed memory-safety candidate, bound to its exact wording."""

    candidate_id: str
    cwe: str
    path: str
    line: int
    symbol: str
    title: str
    mechanism: str
    trigger_path: tuple[str, ...]
    confidence: float
    verification_state: str = "llm-candidate"
    context: tuple[ContextReference, ...] = field(default=())

    @classmethod
    def from_untrusted_json(cls, payload: Any) -> CxxAgentCandidate:
        fields = _exact_fields(
            payload,
            frozenset(
                {
                    "cwe",
                    "path",
                    "line",
                    "symbol",
                    "title",
                    "mechanism",
                    "trigger_path",
                    "confidence",
                }
            ),
        )
        cwe = fields["cwe"]
        if cwe not in SUPPORTED_CWES:
            raise ValueError("candidate CWE is unsupported")
        raw_steps = fields["trigger_path"]
        if (
            type(raw_steps) is not list
            or not raw_steps
            or len(raw_steps) > MAX_TRIGGER_STEPS
        ):
            raise ValueError("trigger_path must be a bounded non-empty list")
        steps: list[str] = []
        for step in raw_steps:
            if not isinstance(step, str) or not step:
                raise ValueError("trigger_path steps must be non-empty text")
            if len(step.encode("utf-8")) > MAX_TRIGGER_STEP_BYTES:
                raise ValueError("trigger_path step exceeds the byte limit")
            banned = {"/", chr(92), chr(0), chr(13), chr(10)}
            if any(ch in step for ch in banned) or ".." in step:
                raise ValueError("trigger_path steps must not contain path syntax")
            # Task 15 fix: the validated step must actually be collected.
            # Since f2d52b9 the loop validated each step but never appended
            # it, so every candidate silently carried an empty trigger_path
            # and trigger-overlap consensus could never fire.
            steps.append(step)
        line = _bounded_int(fields["line"], "line", 1, 10_000_000)
        material = json.dumps(
            {
                "cwe": cwe,
                "path": fields["path"],
                "line": line,
                "symbol": fields["symbol"],
                "mechanism": fields["mechanism"],
                "trigger_path": steps,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return cls(
            candidate_id="sha256-" + hashlib.sha256(material).hexdigest(),
            cwe=cwe,
            path=_safe_relative_path(fields["path"], "path"),
            line=line,
            symbol=_bounded_text(fields["symbol"], "symbol"),
            title=_bounded_text(fields["title"], "title"),
            mechanism=_bounded_text(fields["mechanism"], "mechanism"),
            trigger_path=tuple(steps),
            confidence=_confidence(fields["confidence"]),
        )


@dataclass(frozen=True)
class CxxAgentDecision:
    """One verifier or arbiter verdict over already-validated candidates."""

    decision: str
    verification_state: str
    rationale: str
    corroborating_agent_roles: tuple[str, ...]

    @classmethod
    def from_untrusted_json(cls, payload: Any) -> CxxAgentDecision:
        fields = _exact_fields(
            payload,
            frozenset(
                {
                    "decision",
                    "verification_state",
                    "rationale",
                    "corroborating_agent_roles",
                }
            ),
        )
        if fields["decision"] not in {"accept", "reject"}:
            raise ValueError("decision must be accept or reject")
        if fields["verification_state"] not in CXX_AGENT_VERIFICATION_STATES:
            raise ValueError("verification state is outside the closed domain")
        raw_roles = fields["corroborating_agent_roles"]
        if type(raw_roles) is not list or len(raw_roles) > len(AGENT_ROLES):
            raise ValueError("corroborating roles must be a bounded list")
        roles: list[str] = []
        for role in raw_roles:
            if role not in AGENT_ROLES:
                raise ValueError("corroborating role is unknown")
            roles.append(role)
        return cls(
            decision=fields["decision"],
            verification_state=fields["verification_state"],
            rationale=_bounded_text(fields["rationale"], "rationale"),
            corroborating_agent_roles=tuple(sorted(set(roles))),
        )


@dataclass(frozen=True)
class CxxAgentCoverage:
    """Honest coverage and degradation markers for one agent run."""

    indexed_files: int
    indexed_symbols: int
    candidates_generated: int
    candidates_budget_exhausted: bool
    context_files_used: int
    context_lines_sent: int
    unparsed_regions: tuple[str, ...]
    llm_unavailable: bool

    @classmethod
    def from_untrusted_json(cls, payload: Any) -> CxxAgentCoverage:
        fields = _exact_fields(
            payload,
            frozenset(
                {
                    "indexed_files",
                    "indexed_symbols",
                    "candidates_generated",
                    "candidates_budget_exhausted",
                    "context_files_used",
                    "context_lines_sent",
                    "unparsed_regions",
                    "llm_unavailable",
                }
            ),
        )
        raw_regions = fields["unparsed_regions"]
        if type(raw_regions) is not list or len(raw_regions) > MAX_REGIONS:
            raise ValueError("unparsed regions must be a bounded list")
        regions: list[str] = []
        for region in raw_regions:
            if not isinstance(region, str) or not region:
                raise ValueError("unparsed regions must be non-empty paths")
            regions.append(_safe_relative_path(region, "unparsed region"))
            if len(region.encode("utf-8")) > MAX_REGION_BYTES:
                raise ValueError("unparsed region exceeds the byte limit")
        return cls(
            indexed_files=_bounded_int(
                fields["indexed_files"], "indexed_files", 0, 1_000_000
            ),
            indexed_symbols=_bounded_int(
                fields["indexed_symbols"], "indexed_symbols", 0, 10_000_000
            ),
            candidates_generated=_bounded_int(
                fields["candidates_generated"], "candidates_generated", 0, 100_000
            ),
            candidates_budget_exhausted=_bounded_flag(
                fields["candidates_budget_exhausted"], "candidates_budget_exhausted"
            ),
            context_files_used=_bounded_int(
                fields["context_files_used"], "context_files_used", 0, 1_000_000
            ),
            context_lines_sent=_bounded_int(
                fields["context_lines_sent"], "context_lines_sent", 0, 100_000_000
            ),
            unparsed_regions=tuple(regions),
            llm_unavailable=_bounded_flag(
                fields["llm_unavailable"], "llm_unavailable"
            ),
        )


@dataclass(frozen=True)
class ConsensusVerdict:
    """Deterministic consensus outcome for one specialist candidate.

    ``state`` is ``agent-corroborated`` (at least two independent specialist
    roles proposed fully agreeing claims), ``llm-candidate`` (a single role),
    or ``needs-human-review`` (degraded non-CWE shells never take part in and
    never receive consensus).  ``agreement_keys`` names the consensus keys the
    agreeing peers matched; it is the full key set when corroborated and empty
    otherwise.
    """

    state: str
    supporting_roles: tuple[str, ...] = ()
    agreement_keys: tuple[str, ...] = ()


def _normalized_mechanism(text: str) -> str:
    return " ".join(text.split())


def _agreement_key_hits(
    candidate: CxxAgentCandidate, peer: CxxAgentCandidate
) -> tuple[str, ...]:
    hits: list[str] = []
    if candidate.cwe == peer.cwe:
        hits.append("cwe")
    if candidate.path == peer.path:
        hits.append("path")
    if candidate.symbol == peer.symbol:
        hits.append("symbol")
    if (candidate.path, candidate.line, candidate.symbol) == (
        peer.path,
        peer.line,
        peer.symbol,
    ):
        # The resource/buffer identity is the exact snapshot position.
        hits.append("resource")
    if _normalized_mechanism(candidate.mechanism) == _normalized_mechanism(
        peer.mechanism
    ):
        hits.append("mechanism")
    if not set(candidate.trigger_path).isdisjoint(peer.trigger_path):
        hits.append("trigger-overlap")
    return tuple(hits)


def candidate_agreement(
    candidate: CxxAgentCandidate, peer: CxxAgentCandidate
) -> bool:
    """True only when every consensus key agrees.

    Consistency is never title- or CWE-only: agreement requires the exact
    snapshot position (path, line, symbol -- the resource identity), the same
    CWE, a whitespace-insensitive mechanism match and a non-empty
    ``trigger_path`` intersection (design spec section 9).
    """

    return len(_agreement_key_hits(candidate, peer)) == len(AGENT_CONSENSUS_KEYS)


def agent_consensus_state(
    role_reports: Mapping[str, Sequence[CxxAgentCandidate]],
) -> dict[str, ConsensusVerdict]:
    """Score every specialist candidate against the other roles' candidates.

    Pure and deterministic (zero LLM): a candidate is ``agent-corroborated``
    only when candidates from at least two distinct roles agree with it under
    :func:`candidate_agreement`; duplicates inside one role never count as
    independent support.  Candidates carrying the degraded non-CWE marker
    (``cwe`` outside :data:`SUPPORTED_CWES`) are excluded from consensus on
    both sides and always receive ``needs-human-review``.
    """

    instances: list[tuple[str, CxxAgentCandidate]] = []
    for role in sorted(role_reports):
        for candidate in role_reports[role]:
            instances.append((role, candidate))
    ordered_ids: list[str] = []
    by_id: dict[str, CxxAgentCandidate] = {}
    for _role, candidate in instances:
        if candidate.candidate_id not in by_id:
            by_id[candidate.candidate_id] = candidate
            ordered_ids.append(candidate.candidate_id)

    verdicts: dict[str, ConsensusVerdict] = {}
    for candidate_id in ordered_ids:
        candidate = by_id[candidate_id]
        if candidate.cwe not in SUPPORTED_CWES:
            verdicts[candidate_id] = ConsensusVerdict(
                "needs-human-review", (), ()
            )
            continue
        supporting: set[str] = set()
        key_hits: set[str] = set()
        for role, peer in instances:
            if peer.cwe not in SUPPORTED_CWES:
                continue
            hits = _agreement_key_hits(candidate, peer)
            if len(hits) == len(AGENT_CONSENSUS_KEYS):
                supporting.add(role)
                key_hits.update(hits)
        if len(supporting) >= 2:
            verdicts[candidate_id] = ConsensusVerdict(
                "agent-corroborated",
                tuple(sorted(supporting)),
                tuple(sorted(key_hits)),
            )
        else:
            verdicts[candidate_id] = ConsensusVerdict(
                "llm-candidate", tuple(sorted(supporting)), ()
            )
    return verdicts


def verified_only_gate(
    candidates: Sequence[CxxAgentCandidate],
) -> tuple[tuple[CxxAgentCandidate, ...], tuple[CxxAgentCandidate, ...]]:
    """Split candidates into (accepted, rejected) for the verified-only gate.

    Exactly the four states in :data:`VERIFIED_STATES` pass; ``llm-candidate``
    and ``needs-human-review`` never do.  Both halves are sorted by
    ``(path, line, symbol, candidate_id)`` so the gate output is deterministic.
    """

    def sort_key(item: CxxAgentCandidate) -> tuple[str, int, str, str]:
        return (item.path, item.line, item.symbol, item.candidate_id)

    accepted = tuple(sorted(
        (item for item in candidates if item.verification_state in VERIFIED_STATES),
        key=sort_key,
    ))
    rejected = tuple(sorted(
        (item for item in candidates if item.verification_state not in VERIFIED_STATES),
        key=sort_key,
    ))
    return accepted, rejected


def to_agent_finding_payload(candidate: CxxAgentCandidate) -> dict[str, Any]:
    """Project one candidate onto the Finding JSON shape the report expects."""

    return {
        "rule_id": f"cxx.llm.{candidate.cwe.lower()}",
        "severity": Severity.HIGH,
        "title": candidate.title,
        "explanation": candidate.mechanism,
        "path": candidate.path,
        "line": candidate.line,
        "evidence": " → ".join(candidate.trigger_path),
        "fix": "",
        "test": "Exercise the trigger path under AddressSanitizer.",
        "confidence": candidate.confidence,
        "cwe": candidate.cwe,
        "source": "llm-agent",
        "evidence_kind": "line",
        "verification_state": candidate.verification_state,
        "language": "c++",
        "symbol": candidate.symbol,
        "analysis_mode": "llm-agent",
        "automatic_repair": False,
    }


__all__: list[str] = [
    "AGENT_CONSENSUS_KEYS",
    "AGENT_ROLES",
    "CXX_AGENT_VERIFICATION_STATES",
    "ConsensusVerdict",
    "ContextReference",
    "CxxAgentCandidate",
    "CxxAgentCoverage",
    "CxxAgentDecision",
    "SUPPORTED_CWES",
    "VERIFIED_STATES",
    "agent_consensus_state",
    "candidate_agreement",
    "parse_untrusted_json",
    "to_agent_finding_payload",
    "verified_only_gate",
]
