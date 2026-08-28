"""Strict, bounded finding schema shared by isolated C/C++ analyzer layers."""

from __future__ import annotations

from collections.abc import MutableSequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final

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

    @classmethod
    def create(
        cls,
        *,
        diagnostics: MutableSequence[str],
        trace: str = "",
        **values: object,
    ) -> NormalizedFinding:
        expected = set(_OUTPUT_FIELDS)
        if set(values) != expected:
            raise ValueError("finding fields do not match the response schema")
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
        if values["analysis_mode"] != "source-only" or values["verification_state"] != "candidate":
            raise ValueError("source-only findings must remain candidates")
        if values["tool"] != "semgrep":
            raise ValueError("source-only findings must be attributed to semgrep")
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
        )

    def to_dict(self) -> dict[str, object]:
        """Return only the exact client-contract fields in a stable order."""

        return {field: getattr(self, field) for field in _OUTPUT_FIELDS}


def conservative_identity(finding: NormalizedFinding) -> tuple[str, str, str, int]:
    return finding.cwe, finding.path, finding.symbol, finding.line
