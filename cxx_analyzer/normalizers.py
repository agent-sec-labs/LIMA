"""Strict, bounded finding schema shared by isolated C/C++ analyzer layers."""

from __future__ import annotations

from collections.abc import MutableSequence
from dataclasses import dataclass, replace
from pathlib import PurePosixPath
from typing import Final

from .protocol import MAX_RUN_ID_BYTES

SUPPORTED_CWES: Final = frozenset({"CWE-787", "CWE-125", "CWE-416", "CWE-415"})
SUPPORTED_SEVERITIES: Final = frozenset({"low", "medium", "high", "critical"})
MAX_FIELD_BYTES: Final = 2_048
MAX_EVIDENCE_BYTES: Final = 4_096
MAX_TRACE_BYTES: Final = 4_096
_IDENTITY_FIELDS: Final = frozenset({"rule_id", "cwe", "path", "symbol"})

_OUTPUT_FIELDS: Final = (
    "rule_id", "severity", "title", "explanation", "path", "line", "evidence",
    "fix", "test", "confidence", "cwe", "tool", "evidence_kind",
    "verification_state", "language", "symbol", "analysis_mode",
)


def _safe_path(path: str) -> bool:
    parsed = PurePosixPath(path)
    return bool(path) and not (
        parsed.is_absolute()
        or "\\" in path
        or "\0" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
    )


def _truncate(value: str, maximum: int, field: str, diagnostics: MutableSequence[str]) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= maximum:
        return value
    clipped = encoded[:maximum].decode("utf-8", errors="ignore")
    diagnostics.append(f"truncated {field}")
    return clipped


@dataclass(frozen=True)
class NormalizedFinding:
    """An immutable client-compatible finding with non-response trace context."""

    rule_id: str
    severity: str
    title: str
    explanation: str
    path: str
    line: int
    evidence: str
    fix: str
    test: str
    confidence: float
    cwe: str
    tool: str
    evidence_kind: str
    verification_state: str
    language: str
    symbol: str
    analysis_mode: str
    trace: str = ""
    producer_run_ids: tuple[str, ...] = ()

    @classmethod
    def create(
        cls,
        *,
        diagnostics: MutableSequence[str],
        trace: str = "",
        producer_run_ids: object = (),
        **values: object,
    ) -> NormalizedFinding:
        expected = set(_OUTPUT_FIELDS)
        if set(values) != expected:
            raise ValueError("finding fields do not match the response schema")
        if isinstance(producer_run_ids, str) or not isinstance(
            producer_run_ids, (list, tuple)
        ):
            raise ValueError("producer run ids must be a sequence")
        producers = tuple(producer_run_ids)
        if any(
            not isinstance(item, str)
            or not item
            or len(item.encode("utf-8")) > MAX_RUN_ID_BYTES
            for item in producers
        ) or len(set(producers)) != len(producers):
            raise ValueError("producer run ids must be bounded, unique text")
        strings = set(_OUTPUT_FIELDS) - {"line", "confidence"}
        for field in strings:
            if not isinstance(values[field], str):
                raise ValueError(f"finding {field} must be text")
            if (
                field in _IDENTITY_FIELDS
                and len(values[field].encode("utf-8")) > MAX_FIELD_BYTES
            ):
                raise ValueError(f"finding {field} exceeds the identity limit")
        if not isinstance(trace, str):
            raise ValueError("finding trace must be text")
        if type(values["line"]) is not int or values["line"] < 1:
            raise ValueError("finding line must be positive")
        confidence = values["confidence"]
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, int | float)
            or not 0.0 <= confidence <= 1.0
        ):
            raise ValueError("finding confidence must be between zero and one")
        if values["cwe"] not in SUPPORTED_CWES:
            raise ValueError("finding CWE is unsupported")
        if values["severity"] not in SUPPORTED_SEVERITIES:
            raise ValueError("finding severity is unsupported")
        if not _safe_path(values["path"]):
            raise ValueError("finding path must be a safe POSIX relative path")
        mode_contract = {
            "source-only": ("candidate", "semgrep"),
            "build-backed": ("build-verified", "clang"),
            "sanitizer-confirmed": ("confirmed", "asan"),
        }
        contract = mode_contract.get(values["analysis_mode"])
        if contract is None or (values["verification_state"], values["tool"]) != contract:
            raise ValueError("finding analysis mode does not match its fixed evidence tier")
        if values["fix"]:
            raise ValueError("C/C++ findings must not contain automatic fixes")
        if values["language"] not in {"c", "c++"}:
            raise ValueError("finding language is unsupported")
        for field in strings - {"fix", "path"}:
            if not values[field]:
                raise ValueError(f"finding {field} must not be empty")

        bounded = {
            field: _truncate(
                values[field],
                MAX_EVIDENCE_BYTES if field == "evidence" else MAX_FIELD_BYTES,
                field,
                diagnostics,
            )
            if field in strings else values[field]
            for field in _OUTPUT_FIELDS
        }
        return cls(
            **bounded,  # type: ignore[arg-type]
            trace=_truncate(trace, MAX_TRACE_BYTES, "trace", diagnostics),
            producer_run_ids=producers,
        )

    def bind_producer(self, run_id: str) -> NormalizedFinding:
        """Return a copy bound to the exact tool run that produced it."""

        if (
            not isinstance(run_id, str)
            or not run_id
            or len(run_id.encode("utf-8")) > MAX_RUN_ID_BYTES
            or run_id in self.producer_run_ids
        ):
            raise ValueError("producer run id must be bounded and unique")
        return replace(self, producer_run_ids=(*self.producer_run_ids, run_id))

    def to_dict(self) -> dict[str, object]:
        """Return only the exact client-contract fields in a stable order."""

        payload = {field: getattr(self, field) for field in _OUTPUT_FIELDS}
        payload["producer_run_ids"] = list(self.producer_run_ids)
        return payload


def conservative_identity(finding: NormalizedFinding) -> tuple[str, str, str, int]:
    return finding.cwe, finding.path, finding.symbol, finding.line


def fuse_findings(
    source_findings: tuple[NormalizedFinding, ...],
    build_findings: tuple[NormalizedFinding, ...],
    sanitizer_findings: tuple[NormalizedFinding, ...] = (),
) -> tuple[NormalizedFinding, ...]:
    """Preserve every evidence layer; main-boundary fusion owns presentation merge."""

    fused: list[NormalizedFinding] = []
    seen: set[tuple[str, str, str, int, str, str]] = set()
    for layer in (source_findings, build_findings, sanitizer_findings):
        for item in layer:
            identity = (
                *conservative_identity(item),
                item.tool,
                item.rule_id,
            )
            if identity not in seen:
                seen.add(identity)
                fused.append(item)
    return tuple(fused)
