"""Strict client boundary for the isolated C/C++ memory analyzer.

Tool-evidence binding (:func:`bind_tool_evidence`) matches Sidecar findings
to agent candidates by a function-level identity: path + CWE + symbol, with
a bounded line-distance fallback only when both symbols are empty.  This is
deliberately wider than the agent-consensus position key (exact
``path, line, symbol`` in :mod:`lima.cxx_agent_models`): Sidecar tools
report symbol-level matches and their line numbers drift between tool
versions, while consensus claims anchor on exact snapshot positions.
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Protocol

from .models import EvidenceRecord, Finding, Severity
from .uaf_models import RESOLUTION_SOURCE_KINDS, RESOLUTION_STATUSES, UafFactKind
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
    "producer_run_ids",
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
    "run_id",
    "tool",
    "status",
    "returncode",
    "output_sha256",
    "output_truncated",
    "digests_complete",
}
MAX_RUN_ID_BYTES = 64
MAX_PRODUCER_RUNS = 16
_FINDING_TOOL_TO_RUN_TOOL = {
    "semgrep": "semgrep",
    "clang": "clang",
    "asan": "asan-test",
}
_FINDING_TOOL_TO_RUN_STATUS = {
    "semgrep": frozenset({"completed"}),
    "clang": frozenset({"completed"}),
    "asan": frozenset({"completed", "failed"}),
}
_TOOL_RUN_STATUSES = {
    "semgrep": frozenset({"completed", "failed", "timed-out"}),
    "build-step": frozenset({"completed", "build_failed", "timed-out"}),
    "clang": frozenset({"completed", "failed", "timed-out"}),
    "asan-test": frozenset({"completed", "failed", "timed-out"}),
}
_COVERAGE_KEYS = {"source_files", "snapshot_files"}
_HEALTH_KEYS = {
    "schema_version",
    "source_available",
    "build_available",
    "test_configured",
    "clang_c_available",
    "clang_cxx_available",
    "cmake_available",
    "landlock_available",
    "process_isolation_available",
    "trusted_build_context_generation_available",
}
_HEALTH_CAPABILITY_KEYS = frozenset(_HEALTH_KEYS - {"schema_version"})
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

# --- /v1/uaf-facts protocol (UAF v2 plan Task 2; extraction from Task 4) ---
UAF_FACTS_SCHEMA_VERSION = 1
UAF_FACTS_PATH = "/v1/uaf-facts"
UAF_FACTS_TOOL = "uaf-facts"
UAF_FACTS_BUILD_CONTEXT_MODES = frozenset({"snapshot-compdb", "heuristic"})
UAF_FACTS_TOOL_RUN_STATUSES = frozenset({"completed", "unavailable"})
UAF_FACTS_EXTRACTIONS = frozenset({"completed", "unavailable"})
# The eleven frozen first-phase fact kinds (design section 7.2); the client
# certifies only the kind vocabulary here -- full wire-fact field and
# identity validation is the Fact Adapter's job (plan Task 5).
UAF_FACT_KINDS = frozenset(kind.value for kind in UafFactKind)
MAX_UAF_TRANSLATION_UNITS = 16
MAX_UAF_TOOL_RUNS = 16
_UAF_RESPONSE_KEYS = {
    "schema_version",
    "request_id",
    "repository_key",
    "snapshot_sha256",
    "tool_runs",
    "translation_units",
    "bundle_sha256",
    "diagnostics",
}
_UAF_TOOL_RUN_KEYS = {"run_id", "tool", "status"}
_UAF_UNIT_KEYS = {"translation_unit", "extraction", "build_context", "coverage", "facts"}
_UAF_BUILD_CONTEXT_KEYS = {"status", "source_kind", "context_hash", "diagnostics"}
_UAF_COVERAGE_KEYS = {"ast_complete", "cfg_complete", "semantic_gaps"}

# --- /v1/repro protocol (agent vuln platform plan Task 1: repro workbench) ---
REPRO_SCHEMA_VERSION = 1
REPRO_PATH = "/v1/repro"
REPRO_STAGES = frozenset({"compile", "run"})
REPRO_ACCESS_KINDS = frozenset({"READ", "WRITE"})
REPRO_FRAME_KEYS = frozenset({"function", "file", "line", "column"})
MAX_REPRO_SOURCES = 16
MAX_REPRO_DRIVER_BYTES = 256 * 1024
_REPRO_RESPONSE_KEYS = {
    "schema_version",
    "request_id",
    "snapshot_sha256",
    "stage",
    "ok",
    "exit_code",
    "asan_report",
    "diagnostics",
    "experiment",
}
_REPRO_ASAN_REPORT_KEYS = {
    "error_type",
    "access",
    "access_size",
    "faulting_frame",
    "freed_by_frame",
    "allocated_by_frame",
    "raw_report_sha256",
}
_REPRO_EXPERIMENT_KEYS = {"driver_sha256", "binary_sha256", "elapsed_seconds"}


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
class UafFactsResponse:
    """Strictly validated ``/v1/uaf-facts`` response.

    This boundary certifies protocol integrity only: closed response fields,
    schema version, echo identity, the ``uaf-facts`` tool run, and the bundle
    digest re-derived over the received wire list.  Facts stay validated wire
    dicts -- turning them into :class:`~lima.uaf_models.UafFact` records is
    the Fact Adapter's job (plan Task 5), so no fact objects are built here.
    """

    request_id: str
    repository_key: str
    snapshot_sha256: str
    tool_runs: tuple[dict[str, Any], ...]
    translation_units: tuple[dict[str, Any], ...]
    bundle_sha256: str
    diagnostics: tuple[str, ...]


@dataclass(frozen=True)
class ReproResponse:
    """Strictly validated ``/v1/repro`` execution record.

    ``asan_report`` stays a validated wire dict: the structured ASan
    answer (error type, access, frames, raw-report digest) is consumed by
    the agent loop as evidence, so this boundary certifies protocol
    integrity (closed fields, echo identity, outcome consistency, audit
    hashes) without reinterpreting the report.
    """

    request_id: str
    snapshot_sha256: str
    stage: str
    ok: bool
    exit_code: int | None
    asan_report: dict[str, Any] | None
    diagnostics: tuple[str, ...]
    driver_sha256: str
    binary_sha256: str
    elapsed_seconds: float


@dataclass(frozen=True)
class CxxAnalyzerHealth:
    """Probed executability of every analyzer layer and prerequisite."""

    schema_version: int
    source_available: bool
    build_available: bool
    test_configured: bool
    clang_c_available: bool
    clang_cxx_available: bool
    cmake_available: bool
    landlock_available: bool
    process_isolation_available: bool
    # Health-time lower bound of the untrusted build generation gate: the
    # admin switch plus the two sandbox probes; execution-time probes
    # (uid, network, mount) still run inside the Sidecar before any build.
    trusted_build_context_generation_available: bool = False

    def capabilities(self) -> dict[str, bool]:
        return {
            "source_available": self.source_available,
            "build_available": self.build_available,
            "test_configured": self.test_configured,
            "clang_c_available": self.clang_c_available,
            "clang_cxx_available": self.clang_cxx_available,
            "cmake_available": self.cmake_available,
            "landlock_available": self.landlock_available,
            "process_isolation_available": self.process_isolation_available,
            "trusted_build_context_generation_available": (
                self.trusted_build_context_generation_available
            ),
        }


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


def uaf_facts_bundle_sha256(translation_units: object) -> str:
    """Re-derive the frozen Sidecar bundle digest over the received units.

    Same algorithm as the server's ``uaf_facts_bundle_sha256``:
    ``sha256(json.dumps({"translation_units": ...}, sort_keys=True,
    separators=(",", ":"), ensure_ascii=False).encode("utf-8"))``.  A
    mismatch proves the bundle was tampered with in transit.
    """

    material = json.dumps(
        {"translation_units": translation_units},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _require_safe_relative_unit(value: object) -> str:
    if (
        not isinstance(value, str)
        or PurePosixPath(value).is_absolute()
        or "\\" in value
        or "\x00" in value
        or any(segment in {"", ".", ".."} for segment in value.split("/"))
    ):
        raise CxxAnalyzerProtocolError("unsafe C/C++ analyzer translation unit")
    return value


def _validate_uaf_requested_units(units: object) -> tuple[str, ...]:
    if (
        type(units) is not tuple
        or not units
        or len(units) > MAX_UAF_TRANSLATION_UNITS
        or any(type(unit) is not str for unit in units)
        or len(set(units)) != len(units)
    ):
        raise CxxAnalyzerProtocolError("invalid C/C++ analyzer translation units")
    return tuple(_require_safe_relative_unit(unit) for unit in units)


def _validate_repro_requested_sources(sources: object) -> tuple[str, ...]:
    if (
        type(sources) is not tuple
        or not sources
        or len(sources) > MAX_REPRO_SOURCES
        or any(type(source) is not str for source in sources)
        or len(set(sources)) != len(sources)
    ):
        raise CxxAnalyzerProtocolError("invalid C/C++ analyzer repro sources")
    return tuple(_require_safe_relative_unit(source) for source in sources)


def _validate_repro_driver_code(driver_code: object) -> str:
    if (
        not isinstance(driver_code, str)
        or not driver_code
        or "\x00" in driver_code
        or len(driver_code.encode("utf-8")) > MAX_REPRO_DRIVER_BYTES
    ):
        raise CxxAnalyzerProtocolError("invalid C/C++ analyzer repro driver code")
    return driver_code


def _validate_bounded_strings(value: object, limit: int) -> None:
    if (
        type(value) is not list
        or len(value) > limit
        or any(
            type(item) is not str
            or not item
            or len(item.encode("utf-8")) > MAX_DIAGNOSTIC_BYTES
            for item in value
        )
    ):
        raise CxxAnalyzerProtocolError("invalid C/C++ analyzer bounded text list")


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
    seen_run_ids: set[str] = set()
    for run in tool_runs:
        if type(run) is not dict or set(run) != _TOOL_RUN_KEYS:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer tool run fields")
        run_id = run["run_id"]
        if (
            type(run_id) is not str
            or not run_id
            or len(run_id.encode("utf-8")) > MAX_RUN_ID_BYTES
            or run_id in seen_run_ids
        ):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer run identity")
        seen_run_ids.add(run_id)
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


_RUNTIME_CONFIRMATION_SOURCE = "asan"


@dataclass(frozen=True)
class ToolCorroboration:
    """Deterministic tool-evidence binding for one agent candidate.

    ``state`` is ``runtime-confirmed`` (an ASan finding at the same identity
    bound to a completed tool run), ``tool-corroborated`` (a Semgrep or Clang
    finding at the same identity), or empty (no usable tool evidence; an empty
    tool result is never treated as safety).  ``conflict`` marks conflicting
    evidence (same identity, different CWE) or an unbindable ASan hit; the
    arbiter maps it to ``needs-human-review``.
    """

    state: str
    matched: tuple[EvidenceRecord, ...] = ()
    tool_run_ids: tuple[str, ...] = ()
    conflict: bool = False


def _finding_matches_identity(finding: Finding, candidate: Any) -> bool:
    """Same-location identity between a tool finding and an agent candidate.

    The path must be equal.  Symbols match when they are equal or one is a
    ``::``-qualified suffix of the other; when both are empty the line
    distance must stay within three lines.  Mixed empty/non-empty symbols
    never match.
    """

    if finding.path != candidate.path:
        return False
    finding_symbol = (finding.symbol or "").strip()
    candidate_symbol = (candidate.symbol or "").strip()
    if finding_symbol and candidate_symbol:
        return (
            finding_symbol == candidate_symbol
            or candidate_symbol.endswith("::" + finding_symbol)
            or finding_symbol.endswith("::" + candidate_symbol)
        )
    if not finding_symbol and not candidate_symbol:
        return abs(finding.line - candidate.line) <= 3
    return False


def _run_is_usable(run: Any, tool: str) -> bool:
    return (
        isinstance(run, dict)
        and run.get("tool") == tool
        and run.get("status") == "completed"
    )


def bind_tool_evidence(
    candidates: Any,
    analysis: CxxAnalysisResult,
) -> dict[str, ToolCorroboration]:
    """Bind Sidecar tool findings to agent candidates by shared identity.

    Identity standard (deliberately function-level, wider than the consensus
    side): the path and CWE must be equal and the symbols must match exactly
    or by ``::``-qualified suffix; only when both symbols are empty does the
    line distance (<= 3 lines) decide, and mixed empty/non-empty symbols
    never match.  Unlike the agent-consensus position key (exact
    ``path, line, symbol``), the line is not compared when a symbol is
    present: Sidecar tools report symbol-level matches and their line
    numbers drift between tool versions, so demanding line equality would
    silently drop true hits.

    Pure and deterministic (zero LLM).  Beyond the identity hit, every
    matched finding must also bind to an exact, completed tool run: its
    evidence records must carry a ``tool_run_id`` that names a run present in
    ``analysis.tool_runs`` whose tool matches the finding source
    (``semgrep``/``clang`` runs share the finding tool name verbatim; ASan
    findings cite runs named ``asan-test``) and whose status is
    ``completed``.  Resolvable records are returned in ``matched`` --
    Semgrep/Clang hits yield ``tool-corroborated``, ASan hits
    ``runtime-confirmed`` -- while a hit whose run identity is missing,
    unknown, tool-mismatched or incomplete is unsafely bound evidence and
    sets ``conflict`` (the upstream arbiter falls back to
    ``needs-human-review``).  Same-identity findings with a different CWE are
    conflicts too.  Empty or missing tool findings leave the candidate
    untouched -- an empty tool result is never safety.
    """

    runs_by_id: dict[str, Any] = {}
    for run in getattr(analysis, "tool_runs", None) or ():
        if isinstance(run, dict) and isinstance(run.get("run_id"), str):
            runs_by_id[run["run_id"]] = run
    findings = [
        finding
        for finding in getattr(analysis, "findings", None) or ()
        if isinstance(finding, Finding)
    ]
    bindings: dict[str, ToolCorroboration] = {}
    for candidate in candidates:
        matched: list[EvidenceRecord] = []
        run_ids: list[str] = []
        runtime_ready = False
        tool_ready = False
        conflict = False
        for finding in findings:
            if not _finding_matches_identity(finding, candidate):
                continue
            if finding.cwe != candidate.cwe:
                # Same identity, different CWE: conflicting evidence.
                conflict = True
                continue
            expected_tool = _FINDING_TOOL_TO_RUN_TOOL.get(finding.source)
            if expected_tool is None:
                # Not one of the three Sidecar tools (the strict client never
                # emits one): it can neither corroborate nor conflict.
                continue
            records = [
                record
                for record in (finding.evidence_records or ())
                if isinstance(record, EvidenceRecord)
            ]
            resolvable: list[EvidenceRecord] = []
            for record in records:
                run_id = record.tool_run_id
                if run_id and _run_is_usable(runs_by_id.get(run_id), expected_tool):
                    resolvable.append(record)
                    if run_id not in run_ids:
                        run_ids.append(run_id)
                else:
                    # A hit whose run identity is missing, unknown,
                    # tool-mismatched or incomplete is unsafely bound
                    # evidence, never corroboration.
                    conflict = True
            if resolvable:
                matched.extend(resolvable)
                if finding.source == _RUNTIME_CONFIRMATION_SOURCE:
                    runtime_ready = True
                else:
                    tool_ready = True
        if runtime_ready:
            state = "runtime-confirmed"
        elif tool_ready:
            state = "tool-corroborated"
        else:
            state = ""
        bindings[candidate.candidate_id] = ToolCorroboration(
            state=state,
            matched=tuple(matched),
            tool_run_ids=tuple(run_ids),
            conflict=conflict,
        )
    return bindings


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
        if any(
            type(payload[field]) is not bool for field in _HEALTH_CAPABILITY_KEYS
        ):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer health capabilities")
        health = CxxAnalyzerHealth(
            schema_version=1,
            source_available=payload["source_available"],
            build_available=payload["build_available"],
            test_configured=payload["test_configured"],
            clang_c_available=payload["clang_c_available"],
            clang_cxx_available=payload["clang_cxx_available"],
            cmake_available=payload["cmake_available"],
            landlock_available=payload["landlock_available"],
            process_isolation_available=payload["process_isolation_available"],
            trusted_build_context_generation_available=(
                payload["trusted_build_context_generation_available"]
            ),
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
        payload = self._post_json("/v1/analyze", body)

        self._validate_payload(payload, request_id, snapshot_sha256, inventory)
        findings = [self._convert_finding(item) for item in payload["findings"]]
        return CxxAnalysisResult(
            status=payload["status"],
            tool_runs=payload["tool_runs"],
            findings=findings,
            coverage=payload["coverage"],
            diagnostics=payload["diagnostics"],
        )

    def analyze_uaf_facts(
        self,
        repository_key: str,
        snapshot_sha256: str,
        translation_units: tuple[str, ...],
        build_context_mode: str,
    ) -> UafFactsResponse:
        """Request one versioned UAF fact bundle under a strict contract.

        Shares the ``analyze`` transport (timeouts, response cap, duplicate
        JSON keys, error mapping) and then validates the response against the
        closed ``/v1/uaf-facts`` schema: unknown fields, a wrong schema
        version, an echo mismatch, an out-of-vocabulary extraction, or a
        bundle digest that fails local re-derivation all raise
        :class:`CxxAnalyzerProtocolError`.
        """

        if not isinstance(repository_key, str) or not repository_key:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer repository key")
        if (
            not isinstance(snapshot_sha256, str)
            or len(snapshot_sha256) != 64
            or any(character not in _HEX64 for character in snapshot_sha256)
        ):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer snapshot digest")
        if build_context_mode not in UAF_FACTS_BUILD_CONTEXT_MODES:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer build context mode")
        requested_units = _validate_uaf_requested_units(translation_units)
        request_id = str(uuid.uuid4())
        body = json.dumps(
            {
                "schema_version": UAF_FACTS_SCHEMA_VERSION,
                "request_id": request_id,
                "repository_key": repository_key,
                "snapshot_sha256": snapshot_sha256,
                "translation_units": list(requested_units),
                "build_context": {"mode": build_context_mode},
            }
        ).encode("utf-8")
        payload = self._post_json(UAF_FACTS_PATH, body)
        self._validate_uaf_payload(
            payload, request_id, repository_key, snapshot_sha256, requested_units
        )
        return UafFactsResponse(
            request_id=payload["request_id"],
            repository_key=payload["repository_key"],
            snapshot_sha256=payload["snapshot_sha256"],
            tool_runs=tuple(payload["tool_runs"]),
            translation_units=tuple(payload["translation_units"]),
            bundle_sha256=payload["bundle_sha256"],
            diagnostics=tuple(payload["diagnostics"]),
        )

    def repro_compile_run(
        self,
        repository_key: str,
        snapshot_sha256: str,
        source_files: tuple[str, ...],
        driver_code: str,
        *,
        timeout: int | None = None,
    ) -> ReproResponse:
        """Request one sandboxed ASan compile-and-run under a strict contract.

        Shares the ``analyze`` transport (timeouts, response cap, duplicate
        JSON keys, error mapping) and then validates the response against
        the closed ``/v1/repro`` schema: unknown fields, a wrong schema
        version, an echo mismatch, an out-of-vocabulary stage, an outcome
        that contradicts its own exit code or ASan report, or an audit
        experiment block with malformed hashes all raise
        :class:`CxxAnalyzerProtocolError`.
        """

        if not isinstance(repository_key, str) or not repository_key:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer repository key")
        if (
            not isinstance(snapshot_sha256, str)
            or len(snapshot_sha256) != 64
            or any(character not in _HEX64 for character in snapshot_sha256)
        ):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer snapshot digest")
        requested_sources = _validate_repro_requested_sources(source_files)
        validated_driver = _validate_repro_driver_code(driver_code)
        request_id = str(uuid.uuid4())
        body = json.dumps(
            {
                "schema_version": REPRO_SCHEMA_VERSION,
                "request_id": request_id,
                "repository_key": repository_key,
                "snapshot_sha256": snapshot_sha256,
                "source_files": list(requested_sources),
                "driver_code": validated_driver,
            }
        ).encode("utf-8")
        payload = self._post_json(REPRO_PATH, body, timeout=timeout)
        self._validate_repro_payload(payload, request_id, snapshot_sha256)
        return ReproResponse(
            request_id=payload["request_id"],
            snapshot_sha256=payload["snapshot_sha256"],
            stage=payload["stage"],
            ok=payload["ok"],
            exit_code=payload["exit_code"],
            asan_report=payload["asan_report"],
            diagnostics=tuple(payload["diagnostics"]),
            driver_sha256=payload["experiment"]["driver_sha256"],
            binary_sha256=payload["experiment"]["binary_sha256"],
            elapsed_seconds=payload["experiment"]["elapsed_seconds"],
        )

    def _post_json(self, path: str, body: bytes, *, timeout: int | None = None) -> Any:
        """POST one JSON request and return the parsed, size-capped response.

        ``timeout`` overrides the client-level default for this single call
        (the deadline-bounded step timeout); ``None`` keeps
        :attr:`timeout_seconds`.
        """
        if (
            timeout is not None
            and (isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0)
        ):
            raise CxxAnalyzerProtocolError("per-call timeout must be a positive integer")
        wire_timeout = timeout if timeout is not None else self.timeout_seconds

        request = urllib.request.Request(  # noqa: S310 - Settings permits only HTTP(S).
            self.base_url + path,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with self.opener(request, timeout=wire_timeout) as response:
                raw_response = response.read(self.max_response_bytes + 1)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise CxxAnalyzerUnavailable("C/C++ analyzer is unavailable") from exc

        if len(raw_response) > self.max_response_bytes:
            raise CxxAnalyzerProtocolError("C/C++ analyzer response exceeds size limit")
        try:
            return json.loads(
                raw_response.decode("utf-8"),
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=_reject_non_json_number,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
            raise CxxAnalyzerProtocolError("C/C++ analyzer returned invalid JSON") from exc

    @classmethod
    def _validate_repro_payload(
        cls,
        payload: Any,
        request_id: str,
        snapshot_sha256: str,
    ) -> None:
        if not isinstance(payload, dict) or set(payload) != _REPRO_RESPONSE_KEYS:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer response fields")
        if (
            type(payload["schema_version"]) is not int
            or payload["schema_version"] != REPRO_SCHEMA_VERSION
        ):
            raise CxxAnalyzerProtocolError("unsupported C/C++ analyzer schema")
        if payload["request_id"] != request_id:
            raise CxxAnalyzerProtocolError("C/C++ analyzer request identity mismatch")
        if payload["snapshot_sha256"] != snapshot_sha256:
            raise CxxAnalyzerProtocolError("C/C++ analyzer snapshot identity mismatch")
        stage = payload["stage"]
        if not isinstance(stage, str) or stage not in REPRO_STAGES:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer repro stage")
        if type(payload["ok"]) is not bool:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer repro flag")
        exit_code = payload["exit_code"]
        if exit_code is not None and (
            type(exit_code) is not int or not -(2**31) <= exit_code < 2**31
        ):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer repro exit code")
        asan_report = payload["asan_report"]
        if stage == "compile" and (payload["ok"] or asan_report is not None):
            raise CxxAnalyzerProtocolError(
                "inconsistent compile C/C++ analyzer repro stage"
            )
        if stage == "run" and payload["ok"] is not (
            asan_report is None and exit_code == 0
        ):
            raise CxxAnalyzerProtocolError(
                "inconsistent run C/C++ analyzer repro outcome"
            )
        if asan_report is not None:
            cls._validate_repro_asan_report(asan_report)
        _validate_bounded_strings(payload["diagnostics"], MAX_DIAGNOSTICS)
        cls._validate_repro_experiment(payload["experiment"])

    @classmethod
    def _validate_repro_asan_report(cls, report: object) -> None:
        if type(report) is not dict or set(report) != _REPRO_ASAN_REPORT_KEYS:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer ASan report fields")
        error_type = report["error_type"]
        if not isinstance(error_type, str) or not error_type:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer ASan error type")
        access = report["access"]
        if access is not None and (
            not isinstance(access, str) or access not in REPRO_ACCESS_KINDS
        ):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer ASan access")
        access_size = report["access_size"]
        if access_size is not None and (
            type(access_size) is not int or access_size < 1
        ):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer ASan access size")
        if (access is None) != (access_size is None):
            raise CxxAnalyzerProtocolError(
                "inconsistent C/C++ analyzer ASan access pair"
            )
        for frame_key in ("faulting_frame", "freed_by_frame", "allocated_by_frame"):
            frame = report[frame_key]
            if frame is not None:
                cls._validate_repro_frame(frame)
        digest = report["raw_report_sha256"]
        if (
            type(digest) is not str
            or len(digest) != 64
            or any(character not in _HEX64 for character in digest)
        ):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer ASan report digest")

    @staticmethod
    def _validate_repro_frame(frame: object) -> None:
        if type(frame) is not dict or set(frame) != REPRO_FRAME_KEYS:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer ASan frame fields")
        for key in ("function", "file"):
            value = frame[key]
            if (
                not isinstance(value, str)
                or not value
                or "\\" in value
                or "\x00" in value
            ):
                raise CxxAnalyzerProtocolError("invalid C/C++ analyzer ASan frame text")
        if type(frame["line"]) is not int or frame["line"] < 1:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer ASan frame line")
        column = frame["column"]
        if column is not None and (type(column) is not int or column < 1):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer ASan frame column")

    @staticmethod
    def _validate_repro_experiment(experiment: object) -> None:
        if type(experiment) is not dict or set(experiment) != _REPRO_EXPERIMENT_KEYS:
            raise CxxAnalyzerProtocolError(
                "invalid C/C++ analyzer repro experiment fields"
            )
        for key in ("driver_sha256", "binary_sha256"):
            digest = experiment[key]
            if digest == "" and key != "driver_sha256":
                continue
            if (
                type(digest) is not str
                or len(digest) != 64
                or any(character not in _HEX64 for character in digest)
            ):
                raise CxxAnalyzerProtocolError(
                    "invalid C/C++ analyzer repro experiment digest"
                )
        elapsed = experiment["elapsed_seconds"]
        if (
            isinstance(elapsed, bool)
            or not isinstance(elapsed, int | float)
            or elapsed < 0
        ):
            raise CxxAnalyzerProtocolError(
                "invalid C/C++ analyzer repro experiment elapsed seconds"
            )

    @classmethod
    def _validate_uaf_payload(
        cls,
        payload: Any,
        request_id: str,
        repository_key: str,
        snapshot_sha256: str,
        requested_units: tuple[str, ...],
    ) -> None:
        if not isinstance(payload, dict) or set(payload) != _UAF_RESPONSE_KEYS:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer response fields")
        if (
            type(payload["schema_version"]) is not int
            or payload["schema_version"] != UAF_FACTS_SCHEMA_VERSION
        ):
            raise CxxAnalyzerProtocolError("unsupported C/C++ analyzer schema")
        if payload["request_id"] != request_id:
            raise CxxAnalyzerProtocolError("C/C++ analyzer request identity mismatch")
        if payload["repository_key"] != repository_key:
            raise CxxAnalyzerProtocolError("C/C++ analyzer repository identity mismatch")
        if payload["snapshot_sha256"] != snapshot_sha256:
            raise CxxAnalyzerProtocolError("C/C++ analyzer snapshot identity mismatch")
        cls._validate_uaf_tool_runs(payload["tool_runs"])
        cls._validate_uaf_units_payload(payload["translation_units"], requested_units)
        bundle_sha256 = payload["bundle_sha256"]
        if (
            type(bundle_sha256) is not str
            or len(bundle_sha256) != 64
            or any(character not in _HEX64 for character in bundle_sha256)
        ):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer bundle digest")
        if bundle_sha256 != uaf_facts_bundle_sha256(payload["translation_units"]):
            raise CxxAnalyzerProtocolError("C/C++ analyzer bundle digest mismatch")
        _validate_bounded_strings(payload["diagnostics"], MAX_DIAGNOSTICS)

    @staticmethod
    def _validate_uaf_tool_runs(tool_runs: object) -> None:
        if (
            type(tool_runs) is not list
            or not tool_runs
            or len(tool_runs) > MAX_UAF_TOOL_RUNS
        ):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer tool runs")
        seen_run_ids: set[str] = set()
        for run in tool_runs:
            if type(run) is not dict or set(run) != _UAF_TOOL_RUN_KEYS:
                raise CxxAnalyzerProtocolError("invalid C/C++ analyzer tool run fields")
            run_id = run["run_id"]
            if (
                type(run_id) is not str
                or not run_id
                or len(run_id.encode("utf-8")) > MAX_RUN_ID_BYTES
                or run_id in seen_run_ids
            ):
                raise CxxAnalyzerProtocolError("invalid C/C++ analyzer run identity")
            seen_run_ids.add(run_id)
            if run["tool"] != UAF_FACTS_TOOL:
                raise CxxAnalyzerProtocolError("invalid C/C++ analyzer facts tool")
            if (
                type(run["status"]) is not str
                or run["status"] not in UAF_FACTS_TOOL_RUN_STATUSES
            ):
                raise CxxAnalyzerProtocolError("invalid C/C++ analyzer tool status")

    @classmethod
    def _validate_uaf_units_payload(
        cls,
        translation_units: object,
        requested_units: tuple[str, ...],
    ) -> None:
        if (
            type(translation_units) is not list
            or len(translation_units) != len(requested_units)
        ):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer translation units")
        served_units: list[str] = []
        for entry in translation_units:
            if type(entry) is not dict or set(entry) != _UAF_UNIT_KEYS:
                raise CxxAnalyzerProtocolError(
                    "invalid C/C++ analyzer translation unit fields"
                )
            served_units.append(_require_safe_relative_unit(entry["translation_unit"]))
            extraction = entry["extraction"]
            if not isinstance(extraction, str) or extraction not in UAF_FACTS_EXTRACTIONS:
                raise CxxAnalyzerProtocolError("invalid C/C++ analyzer extraction")
            cls._validate_uaf_build_context(entry["build_context"])
            cls._validate_uaf_coverage(entry["coverage"], extraction)
            if type(entry["facts"]) is not list:
                raise CxxAnalyzerProtocolError("invalid C/C++ analyzer facts")
            # A not-extracted unit can never carry facts or claim extraction
            # completeness; facts require a completed extraction and each
            # fact kind must sit inside the frozen eleven-kind vocabulary.
            if entry["facts"] and extraction != "completed":
                raise CxxAnalyzerProtocolError(
                    "inconsistent unavailable C/C++ analyzer extraction"
                )
            for fact in entry["facts"]:
                if type(fact) is not dict or fact.get("kind") not in UAF_FACT_KINDS:
                    raise CxxAnalyzerProtocolError("invalid C/C++ analyzer fact kind")
        if tuple(served_units) != requested_units:
            raise CxxAnalyzerProtocolError("C/C++ analyzer translation unit echo mismatch")

    @staticmethod
    def _validate_uaf_build_context(build_context: object) -> None:
        if type(build_context) is not dict or set(build_context) != _UAF_BUILD_CONTEXT_KEYS:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer build context fields")
        status = build_context["status"]
        if not isinstance(status, str) or status not in RESOLUTION_STATUSES:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer build context status")
        source_kind = build_context["source_kind"]
        if source_kind != "" and (
            not isinstance(source_kind, str) or source_kind not in RESOLUTION_SOURCE_KINDS
        ):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer build context source kind")
        context_hash = build_context["context_hash"]
        if context_hash != "" and (
            type(context_hash) is not str
            or len(context_hash) != 64
            or any(character not in _HEX64 for character in context_hash)
        ):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer build context hash")
        _validate_bounded_strings(build_context["diagnostics"], MAX_DIAGNOSTICS)

    @staticmethod
    def _validate_uaf_coverage(coverage: object, extraction: str) -> None:
        if type(coverage) is not dict or set(coverage) != _UAF_COVERAGE_KEYS:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer coverage fields")
        ast_complete = coverage["ast_complete"]
        cfg_complete = coverage["cfg_complete"]
        if type(ast_complete) is not bool or type(cfg_complete) is not bool:
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer coverage flags")
        if extraction == "unavailable" and (ast_complete or cfg_complete):
            raise CxxAnalyzerProtocolError(
                "incomplete extraction cannot claim AST or CFG completeness"
            )
        _validate_bounded_strings(coverage["semantic_gaps"], MAX_DIAGNOSTICS)

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
        cls._validate_producer_binding(payload)
        cls._validate_inventory_binding(payload, inventory)

    @staticmethod
    def _validate_producer_binding(payload: dict[str, Any]) -> None:
        """Every producer reference must name an exact, layer-matched run."""

        run_by_id = {run["run_id"]: run for run in payload["tool_runs"]}
        for finding in payload["findings"]:
            # _validate_finding has already constrained the finding tool.
            expected_tool = _FINDING_TOOL_TO_RUN_TOOL.get(finding["tool"])
            allowed_statuses = _FINDING_TOOL_TO_RUN_STATUS.get(finding["tool"])
            if expected_tool is None or allowed_statuses is None:
                raise CxxAnalyzerProtocolError(
                    "invalid C/C++ analyzer finding tool binding"
                )
            for identifier in finding["producer_run_ids"]:
                run = run_by_id.get(identifier)
                if run is None:
                    raise CxxAnalyzerProtocolError(
                        "C/C++ analyzer finding cites an unknown tool run"
                    )
                if run["tool"] != expected_tool:
                    raise CxxAnalyzerProtocolError(
                        "C/C++ analyzer finding cites a mismatched tool run"
                    )
                if run["status"] not in allowed_statuses:
                    raise CxxAnalyzerProtocolError(
                        "C/C++ analyzer finding cites an unusable tool run"
                    )

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
        producers = item["producer_run_ids"]
        if (
            type(producers) is not list
            or not producers
            or len(producers) > MAX_PRODUCER_RUNS
            or any(
                type(identifier) is not str
                or not identifier
                or len(identifier.encode("utf-8")) > MAX_RUN_ID_BYTES
                for identifier in producers
            )
            or len(set(producers)) != len(producers)
        ):
            raise CxxAnalyzerProtocolError("invalid C/C++ analyzer producer runs")
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
        # The producer run identity is carried on the primary evidence record
        # (validated by _validate_producer_binding) so downstream consumers can
        # bind a finding to the exact tool run that produced it.  The record
        # mirrors Finding's implicit fallback record plus that identity.
        # Review round 6: sidecar free text is masked BEFORE the Finding is
        # constructed -- Finding.fingerprint digests the evidence field, so
        # building from raw text would leak it through the id.
        from .platform_contracts import privacy_text  # lazy: import cycle

        title = privacy_text(item["title"])
        explanation = privacy_text(item["explanation"])
        evidence = privacy_text(item["evidence"])
        return Finding(
            rule_id=item["rule_id"],
            severity=Severity(item["severity"]),
            title=title,
            explanation=explanation,
            path=item["path"],
            line=item["line"],
            evidence=evidence,
            fix=privacy_text(item["fix"]),
            test=privacy_text(item["test"]),
            confidence=item["confidence"],
            cwe=item["cwe"],
            source=item["tool"],
            evidence_kind=item["evidence_kind"],
            verification_state=item["verification_state"],
            language=item["language"],
            symbol=item["symbol"],
            analysis_mode=item["analysis_mode"],
            automatic_repair=False,
            evidence_records=[EvidenceRecord(
                source=item["tool"],
                kind=item["evidence_kind"],
                path=item["path"],
                line=item["line"],
                snippet=evidence,
                rule_id=item["rule_id"],
                cwe=item["cwe"],
                confidence=item["confidence"],
                language=item["language"],
                symbol=item["symbol"],
                analysis_mode=item["analysis_mode"],
                tool_run_id=item["producer_run_ids"][0],
            )],
        )
