"""Strict client boundary for the isolated C/C++ memory analyzer."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Protocol

from .models import Finding, Severity

SUPPORTED_CWES = frozenset({"CWE-787", "CWE-125", "CWE-416", "CWE-415"})
REQUESTED_LAYERS = ("source-only", "build-backed", "sanitizer-confirmed")
ANALYSIS_STATES = {
    "source-only": "candidate",
    "build-backed": "build-verified",
    "sanitizer-confirmed": "confirmed",
}
_TOP_LEVEL_KEYS = {
    "schema_version", "request_id", "status", "snapshot_sha256",
    "tool_runs", "findings", "coverage", "diagnostics",
}
_FINDING_KEYS = {
    "rule_id", "severity", "title", "explanation", "path", "line",
    "evidence", "fix", "test", "confidence", "cwe", "tool",
    "evidence_kind", "verification_state", "language", "symbol",
    "analysis_mode",
}
_FINDING_STRING_KEYS = {
    "rule_id", "severity", "title", "explanation", "path", "evidence",
    "fix", "test", "cwe", "tool", "evidence_kind", "verification_state",
    "language", "symbol", "analysis_mode",
}


class CxxAnalyzerUnavailable(RuntimeError):
    """The configured analyzer could not be reached or read."""


class CxxAnalyzerProtocolError(RuntimeError):
    """The analyzer returned an invalid or untrusted response."""


@dataclass(frozen=True)
class CxxAnalysisResult:
    status: str
    tool_runs: list[dict[str, Any]]
    findings: list[Finding]
    coverage: dict[str, Any]
    diagnostics: list[Any]


class CxxMemoryAdapter(Protocol):
    def analyze(
        self,
        repository_key: str,
        snapshot_sha256: str,
        requested_layers: tuple[str, ...],
    ) -> CxxAnalysisResult: ...


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _reject_non_json_number(value: str) -> None:
    raise ValueError(f"invalid JSON number: {value}")


def map_asan_error(error_type: str, access: str) -> str | None:
    overflow_types = {
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "global-buffer-overflow",
    }
    if error_type in overflow_types:
        return {"WRITE": "CWE-787", "READ": "CWE-125"}.get(access)
    if error_type == "heap-use-after-free":
        return "CWE-416"
    if error_type == "attempting double-free" and access == "FREE":
        return "CWE-415"
    return None


class CxxMemoryAnalyzerClient:
    def __init__(
        self,
        base_url: str,
        timeout_seconds: int,
        max_response_bytes: int,
        opener=urllib.request.urlopen,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.opener = opener

    def analyze(
        self,
        repository_key: str,
        snapshot_sha256: str,
        requested_layers: tuple[str, ...],
    ) -> CxxAnalysisResult:
        request_id = str(uuid.uuid4())
        body = json.dumps({
            "request_id": request_id,
            "repository_key": repository_key,
            "snapshot_sha256": snapshot_sha256,
            "requested_layers": list(requested_layers),
        }).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 - Settings permits only HTTP(S).
            self.base_url + "/v1/analyze",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with self.opener(request, timeout=self.timeout_seconds) as response:
                raw_response = response.read(self.max_response_bytes + 1)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise CxxAnalyzerUnavailable("C/C++ analyzer is unavailable") from exc

        if len(raw_response) > self.max_response_bytes:
            raise CxxAnalyzerProtocolError("C/C++ analyzer response exceeds size limit")
        try:
            payload = json.loads(
                raw_response.decode("utf-8"),
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=_reject_non_json_number,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
            raise CxxAnalyzerProtocolError("C/C++ analyzer returned invalid JSON") from exc

        self._validate_payload(payload, request_id, snapshot_sha256)
        findings = [self._convert_finding(item) for item in payload["findings"]]
        return CxxAnalysisResult(
            status=payload["status"],
            tool_runs=payload["tool_runs"],
            findings=findings,
            coverage=payload["coverage"],
            diagnostics=payload["diagnostics"],
        )

    @classmethod
    def _validate_payload(
        cls,
        payload: Any,
        request_id: str,
        snapshot_sha256: str,
    ) -> None:
        if not isinstance(payload, dict) or set(payload) != _TOP_LEVEL_KEYS:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer response fields")
        if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
            raise CxxAnalyzerProtocolError("unsupported C/C++ analyzer schema")
        if payload["request_id"] != request_id:
            raise CxxAnalyzerProtocolError("C/C++ analyzer request identity mismatch")
        if payload["snapshot_sha256"] != snapshot_sha256:
            raise CxxAnalyzerProtocolError("C/C++ analyzer snapshot identity mismatch")
        if payload["status"] != "completed":
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer status")
        if (
            not isinstance(payload["tool_runs"], list)
            or not all(isinstance(item, dict) for item in payload["tool_runs"])
            or not isinstance(payload["findings"], list)
            or not isinstance(payload["coverage"], dict)
            or not isinstance(payload["diagnostics"], list)
        ):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer response structure")
        for item in payload["findings"]:
            cls._validate_finding(item)

    @staticmethod
    def _validate_finding(item: Any) -> None:
        if not isinstance(item, dict) or set(item) != _FINDING_KEYS:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer finding fields")
        if any(not isinstance(item[key], str) for key in _FINDING_STRING_KEYS):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer finding text")
        if any(
            not item[key]
            for key in _FINDING_STRING_KEYS - {"fix"}
        ):
            raise CxxAnalyzerProtocolError("empty C/C++ analyzer finding field")
        if item["cwe"] not in SUPPORTED_CWES:
            raise CxxAnalyzerProtocolError("unsupported C/C++ analyzer CWE")
        if item["severity"] not in {severity.value for severity in Severity}:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer severity")
        if item["language"] not in {"c", "c++"}:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer language")
        analysis_mode = item["analysis_mode"]
        if analysis_mode not in ANALYSIS_STATES:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer analysis mode")
        if item["verification_state"] != ANALYSIS_STATES[analysis_mode]:
            raise CxxAnalyzerProtocolError("C/C++ analyzer mode and state mismatch")
        if type(item["line"]) is not int or item["line"] < 1:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer line")
        confidence = item["confidence"]
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, int | float)
            or not 0.0 <= confidence <= 1.0
        ):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer confidence")
        CxxMemoryAnalyzerClient._validate_path(item["path"])

    @staticmethod
    def _validate_path(path: str) -> None:
        segments = path.split("/")
        parsed = PurePosixPath(path)
        if (
            parsed.is_absolute()
            or "\\" in path
            or "\x00" in path
            or any(segment in {"", ".", ".."} for segment in segments)
        ):
            raise CxxAnalyzerProtocolError("unsafe C/C++ analyzer finding path")

    @staticmethod
    def _convert_finding(item: dict[str, Any]) -> Finding:
        return Finding(
            rule_id=item["rule_id"],
            severity=Severity(item["severity"]),
            title=item["title"],
            explanation=item["explanation"],
            path=item["path"],
            line=item["line"],
            evidence=item["evidence"],
            fix=item["fix"],
            test=item["test"],
            confidence=item["confidence"],
            cwe=item["cwe"],
            source=item["tool"],
            evidence_kind=item["evidence_kind"],
            verification_state=item["verification_state"],
            language=item["language"],
            symbol=item["symbol"],
            analysis_mode=item["analysis_mode"],
            automatic_repair=False,
        )
