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
from .workspace import WorkspaceInventory

SUPPORTED_CWES = frozenset({"CWE-787", "CWE-125", "CWE-416", "CWE-415"})
REQUESTED_LAYERS = ("source-only", "build-backed", "sanitizer-confirmed")
ANALYSIS_STATES = {
    "source-only": "candidate",
    "build-backed": "build-verified",
    "sanitizer-confirmed": "confirmed",
}
_TOOL_ANALYSIS_BINDINGS = frozenset(
    {
        ("semgrep", "source-only", "candidate"),
        ("clang", "build-backed", "build-verified"),
        ("asan", "sanitizer-confirmed", "confirmed"),
    }
)
_TOP_LEVEL_KEYS = {
    "schema_version",
    "request_id",
    "status",
    "snapshot_sha256",
    "tool_runs",
    "findings",
    "coverage",
    "diagnostics",
}
_FINDING_KEYS = {
    "rule_id",
    "severity",
    "title",
    "explanation",
    "path",
    "line",
    "evidence",
    "fix",
    "test",
    "confidence",
    "cwe",
    "tool",
    "evidence_kind",
    "verification_state",
    "language",
    "symbol",
    "analysis_mode",
}
_FINDING_STRING_KEYS = {
    "rule_id",
    "severity",
    "title",
    "explanation",
    "path",
    "evidence",
    "fix",
    "test",
    "cwe",
    "tool",
    "evidence_kind",
    "verification_state",
    "language",
    "symbol",
    "analysis_mode",
}
_TOOL_RUN_KEYS = {
    "tool",
    "status",
    "returncode",
    "output_sha256",
    "output_truncated",
    "digests_complete",
}
_TOOL_RUN_STATUSES = {
    "semgrep": frozenset({"completed", "failed", "timed-out"}),
    "build-step": frozenset({"completed", "build_failed", "timed-out"}),
    "clang": frozenset({"completed", "failed", "timed-out"}),
    "asan-test": frozenset({"completed", "failed", "timed-out"}),
}
_COVERAGE_KEYS = {"source_files", "snapshot_files"}
_HEALTH_KEYS = {"schema_version", "tools", "configuration"}
_HEALTH_TOOL_KEYS = {"semgrep", "cmake", "clang"}
_HEALTH_CONFIGURATION_KEYS = {"source", "build", "test"}
_HEX64 = frozenset("0123456789abcdef")
_CXX_LANGUAGE_BY_SUFFIX = {
    ".c": "c",
    ".h": "c",
    ".cc": "c++",
    ".cpp": "c++",
    ".cxx": "c++",
    ".hh": "c++",
    ".hpp": "c++",
    ".hxx": "c++",
}
MAX_TOOL_RUNS = 320
MAX_DIAGNOSTICS = 256
MAX_DIAGNOSTIC_BYTES = 2_048
MAX_COVERAGE_FILES = 1_000_000
MAX_HEALTH_RESPONSE_BYTES = 64 * 1024
HEALTH_TIMEOUT_SECONDS = 2.0


class CxxAnalyzerUnavailable(RuntimeError):
    """The configured analyzer could not be reached or read."""


class CxxAnalyzerProtocolError(RuntimeError):
    """The analyzer returned an invalid or untrusted response."""


@dataclass(frozen=True)
class CxxAnalysisResult:
    status: str
    tool_runs: list[dict[str, Any]]
    findings: list[Finding]
    coverage: dict[str, int]
    diagnostics: list[str]


@dataclass(frozen=True)
class CxxAnalyzerHealth:
    schema_version: int
    tools: dict[str, bool]
    configuration: dict[str, bool]


class CxxMemoryAdapter(Protocol):
    def analyze(
        self,
        repository_key: str,
        snapshot_sha256: str,
        requested_layers: tuple[str, ...],
        *,
        inventory: WorkspaceInventory,
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


def validate_response_metadata(
    tool_runs: object,
    coverage: object,
    diagnostics: object,
) -> None:
    """Reject any non-Finding v1 response field outside the bounded contract."""

    if type(tool_runs) is not list or len(tool_runs) > MAX_TOOL_RUNS:
        raise CxxAnalyzerProtocolError("invalid C/C++ analyzer tool runs")
    for run in tool_runs:
        if type(run) is not dict or set(run) != _TOOL_RUN_KEYS:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer tool run fields")
        tool = run["tool"]
        status = run["status"]
        if type(tool) is not str or tool not in _TOOL_RUN_STATUSES:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer tool")
        if type(status) is not str or status not in _TOOL_RUN_STATUSES[tool]:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer tool status")
        returncode = run["returncode"]
        if returncode is not None and (
            type(returncode) is not int or not -(2**31) <= returncode < 2**31
        ):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer return code")
        if type(run["output_truncated"]) is not bool or type(run["digests_complete"]) is not bool:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer tool flags")
        output_sha256 = run["output_sha256"]
        expected_digest_length = 64 if run["digests_complete"] else 0
        if (
            type(output_sha256) is not str
            or len(output_sha256) != expected_digest_length
            or any(character not in _HEX64 for character in output_sha256)
        ):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer output digest")
        if status == "completed" and (
            returncode != 0 or not run["digests_complete"]
        ):
            raise CxxAnalyzerProtocolError("inconsistent completed C/C++ tool run")
        if status in {"failed", "build_failed"} and returncode == 0:
            raise CxxAnalyzerProtocolError("inconsistent failed C/C++ tool run")
        if status == "timed-out" and returncode is not None:
            raise CxxAnalyzerProtocolError("inconsistent timed-out C/C++ tool run")
        if not run["digests_complete"] and not run["output_truncated"]:
            raise CxxAnalyzerProtocolError("incomplete C/C++ tool output is not truncated")

    if type(coverage) is not dict or set(coverage) != _COVERAGE_KEYS:
        raise CxxAnalyzerProtocolError("invalid C/C++ analyzer coverage fields")
    for value in coverage.values():
        if type(value) is not int or not 0 <= value <= MAX_COVERAGE_FILES:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer coverage value")
    if coverage["source_files"] > coverage["snapshot_files"]:
        raise CxxAnalyzerProtocolError("inconsistent C/C++ analyzer coverage")

    if type(diagnostics) is not list or len(diagnostics) > MAX_DIAGNOSTICS:
        raise CxxAnalyzerProtocolError("invalid C/C++ analyzer diagnostics")
    if any(
        type(item) is not str or not item or len(item.encode("utf-8")) > MAX_DIAGNOSTIC_BYTES
        for item in diagnostics
    ):
        raise CxxAnalyzerProtocolError("invalid C/C++ analyzer diagnostic")


def map_asan_error(error_type: str, access: str) -> str | None:
    overflow_types = {
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "global-buffer-overflow",
    }
    if error_type in overflow_types:
        return {"WRITE": "CWE-787", "READ": "CWE-125"}.get(access)
    if error_type == "heap-use-after-free" and access in {"READ", "WRITE"}:
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
        self._health_cache: CxxAnalyzerHealth | None = None

    def health(self) -> CxxAnalyzerHealth:
        """Return one strictly validated, cached Sidecar v1 capability snapshot."""

        if self._health_cache is not None:
            return self._health_cache
        request = urllib.request.Request(  # noqa: S310 - Settings permits only HTTP(S).
            self.base_url + "/health",
            method="GET",
        )
        try:
            with self.opener(
                request,
                timeout=min(float(self.timeout_seconds), HEALTH_TIMEOUT_SECONDS),
            ) as response:
                if getattr(response, "status", 200) != 200:
                    raise CxxAnalyzerUnavailable("C/C++ analyzer health probe failed")
                raw_response = response.read(MAX_HEALTH_RESPONSE_BYTES + 1)
        except CxxAnalyzerUnavailable:
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise CxxAnalyzerUnavailable("C/C++ analyzer is unavailable") from exc
        if len(raw_response) > MAX_HEALTH_RESPONSE_BYTES:
            raise CxxAnalyzerProtocolError("C/C++ analyzer health response exceeds size limit")
        try:
            payload = json.loads(
                raw_response.decode("utf-8"),
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=_reject_non_json_number,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
            raise CxxAnalyzerProtocolError("C/C++ analyzer returned invalid health JSON") from exc
        if type(payload) is not dict or set(payload) != _HEALTH_KEYS:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer health fields")
        if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
            raise CxxAnalyzerProtocolError("unsupported C/C++ analyzer health schema")
        tools = payload["tools"]
        configuration = payload["configuration"]
        if (
            type(tools) is not dict
            or set(tools) != _HEALTH_TOOL_KEYS
            or any(type(value) is not bool for value in tools.values())
        ):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer health tools")
        if (
            type(configuration) is not dict
            or set(configuration) != _HEALTH_CONFIGURATION_KEYS
            or any(type(value) is not bool for value in configuration.values())
        ):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer health configuration")
        health = CxxAnalyzerHealth(
            schema_version=1,
            tools=dict(tools),
            configuration=dict(configuration),
        )
        self._health_cache = health
        return health

    def analyze(
        self,
        repository_key: str,
        snapshot_sha256: str,
        requested_layers: tuple[str, ...],
        *,
        inventory: WorkspaceInventory,
    ) -> CxxAnalysisResult:
        if (
            type(requested_layers) is not tuple
            or not requested_layers
            or any(type(layer) is not str for layer in requested_layers)
            or len(set(requested_layers)) != len(requested_layers)
            or any(layer not in REQUESTED_LAYERS for layer in requested_layers)
        ):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer requested layers")
        if not isinstance(inventory, WorkspaceInventory):
            raise CxxAnalyzerProtocolError("invalid local C/C++ analyzer inventory")
        if snapshot_sha256 != inventory.fingerprint():
            raise CxxAnalyzerProtocolError("local C/C++ analyzer snapshot identity mismatch")
        request_id = str(uuid.uuid4())
        body = json.dumps(
            {
                "request_id": request_id,
                "repository_key": repository_key,
                "snapshot_sha256": snapshot_sha256,
                "requested_layers": list(requested_layers),
            }
        ).encode("utf-8")
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

        self._validate_payload(payload, request_id, snapshot_sha256, inventory)
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
        inventory: WorkspaceInventory,
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
        if not isinstance(payload["findings"], list):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer response structure")
        validate_response_metadata(
            payload["tool_runs"], payload["coverage"], payload["diagnostics"]
        )
        for item in payload["findings"]:
            cls._validate_finding(item)
        cls._validate_inventory_binding(payload, inventory)

    @classmethod
    def _validate_inventory_binding(
        cls,
        payload: dict[str, Any],
        inventory: WorkspaceInventory,
    ) -> None:
        inventory_by_path = {item.path: item for item in inventory.files}
        if len(inventory_by_path) != len(inventory.files) or any(
            type(item.line_count) is not int or item.line_count < 0
            for item in inventory.files
        ):
            raise CxxAnalyzerProtocolError("invalid local C/C++ analyzer inventory")
        expected_coverage = {
            "source_files": sum(
                PurePosixPath(item.path).suffix.lower() in _CXX_LANGUAGE_BY_SUFFIX
                for item in inventory.files
            ),
            "snapshot_files": len(inventory.files),
        }
        if payload["coverage"] != expected_coverage:
            raise CxxAnalyzerProtocolError("C/C++ analyzer coverage mismatch")
        for finding in payload["findings"]:
            local_file = inventory_by_path.get(finding["path"])
            if local_file is None:
                raise CxxAnalyzerProtocolError(
                    "C/C++ analyzer finding is outside the local inventory"
                )
            expected_language = _CXX_LANGUAGE_BY_SUFFIX.get(
                PurePosixPath(finding["path"]).suffix.lower()
            )
            if expected_language is None or finding["language"] != expected_language:
                raise CxxAnalyzerProtocolError(
                    "C/C++ analyzer finding language does not match its path"
                )
            if not 1 <= finding["line"] <= local_file.line_count:
                raise CxxAnalyzerProtocolError(
                    "C/C++ analyzer finding line is outside the local file"
                )

    @staticmethod
    def _validate_finding(item: Any) -> None:
        if not isinstance(item, dict) or set(item) != _FINDING_KEYS:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer finding fields")
        if any(not isinstance(item[key], str) for key in _FINDING_STRING_KEYS):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer finding text")
        if any(not item[key] for key in _FINDING_STRING_KEYS - {"fix"}):
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
        if (
            item["tool"],
            analysis_mode,
            item["verification_state"],
        ) not in _TOOL_ANALYSIS_BINDINGS:
            raise CxxAnalyzerProtocolError("C/C++ analyzer tool evidence mismatch")
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
