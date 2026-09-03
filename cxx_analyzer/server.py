"""Bounded internal HTTP service for the isolated C/C++ analyzer."""

from __future__ import annotations

import json
import shutil
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any, Final

from .build_scan import run_build_scan
from .config import AnalyzerSettings
from .deadline import AnalysisDeadline, AnalysisDeadlineExceeded
from .languages import CXX_SOURCE_SUFFIXES
from .normalizers import NormalizedFinding, fuse_findings
from .sanitizer_scan import run_sanitizer_scan
from .snapshot import _normalize_repository_key, prepare_snapshot
from .source_scan import run_source_scan

SCHEMA_VERSION: Final = 1
HOST: Final = "0.0.0.0"  # noqa: S104 - Reachable only on the internal Compose network.
PORT: Final = 8090
MAX_REQUEST_BYTES: Final = 64 * 1024
MAX_RESPONSE_BYTES: Final = 2 * 1024 * 1024
MAX_FINDINGS: Final = 256
MAX_DIAGNOSTICS: Final = 256
MAX_TOOL_RUNS: Final = 320
IMPORT_ROOT: Final = Path("/repositories")
WORK_ROOT: Final = Path("/work/snapshots")

_ANALYZE_PATH: Final = "/v1/analyze"
_HEALTH_PATH: Final = "/health"
_REQUEST_FIELDS: Final = frozenset(
    {"request_id", "repository_key", "snapshot_sha256", "requested_layers"}
)
_SUPPORTED_LAYERS: Final = frozenset(
    {"source-only", "build-backed", "sanitizer-confirmed"}
)

def _bound_response_lists(
    findings: tuple[NormalizedFinding, ...], diagnostics: list[object],
    tool_runs: list[dict[str, object]],
) -> tuple[tuple[NormalizedFinding, ...], tuple[object, ...], tuple[dict[str, object], ...]]:
    """Apply one evidence-aware response budget, preferring stronger proof.

    A finding and every run it names as its producer form one inseparable
    unit: runs are selected by exact producer reference, never by guessing
    from tool and status alone.
    """

    ranked = sorted(
        enumerate(findings),
        key=lambda item: (
            {"source-only": 0, "build-backed": 1, "sanitizer-confirmed": 2}[
                item[1].analysis_mode
            ],
            -item[0],
        ),
        reverse=True,
    )
    run_by_id: dict[object, int] = {}
    for index, run in enumerate(tool_runs):
        identifier = run.get("run_id")
        if isinstance(identifier, str) and identifier:
            run_by_id.setdefault(identifier, index)
    kept_indexes: set[int] = set()
    producer_indexes: set[int] = set()
    missing_evidence = False
    budget_blocked = False
    for finding_index, finding in ranked:
        if len(kept_indexes) >= MAX_FINDINGS:
            break
        producers: set[int] = set()
        for identifier in finding.producer_run_ids:
            producer_index = run_by_id.get(identifier)
            if producer_index is None:
                producers = set()
                break
            producers.add(producer_index)
        if not producers:
            missing_evidence = True
            continue
        if len(producer_indexes | producers) > MAX_TOOL_RUNS:
            budget_blocked = True
            continue
        kept_indexes.add(finding_index)
        producer_indexes |= producers
    selected_run_indexes = set(producer_indexes)
    for index in range(len(tool_runs)):
        if len(selected_run_indexes) >= MAX_TOOL_RUNS:
            break
        selected_run_indexes.add(index)
    bounded_findings = tuple(
        item for index, item in enumerate(findings) if index in kept_indexes
    )
    bounded_tool_runs = tuple(
        run for index, run in enumerate(tool_runs) if index in selected_run_indexes
    )
    exhausted = (
        len(findings) > MAX_FINDINGS
        or len(diagnostics) > MAX_DIAGNOSTICS
        or len(tool_runs) > MAX_TOOL_RUNS
        or budget_blocked
    )
    diagnostic_values = list(diagnostics)
    if (missing_evidence or budget_blocked) and (
        "finding-without-tool-evidence" not in diagnostic_values
    ):
        diagnostic_values.append("finding-without-tool-evidence")
    bounded_diagnostics = tuple(diagnostic_values[:MAX_DIAGNOSTICS])
    if exhausted or len(diagnostic_values) > MAX_DIAGNOSTICS:
        if MAX_DIAGNOSTICS < 1:
            bounded_diagnostics = ()
        elif len(bounded_diagnostics) >= MAX_DIAGNOSTICS:
            bounded_diagnostics = (*bounded_diagnostics[:-1], "analysis-budget-exhausted")
        elif "analysis-budget-exhausted" not in bounded_diagnostics:
            bounded_diagnostics = (*bounded_diagnostics, "analysis-budget-exhausted")
    return bounded_findings, bounded_diagnostics, bounded_tool_runs


class RequestError(ValueError):
    """Stable request failure safe to expose across the internal boundary."""

    def __init__(
        self,
        code: str,
        *,
        status: int = 400,
        request_id: str | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.status = status
        self.request_id = request_id


def _canonical_request_id(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError):
        return None
    return value if str(parsed) == value else None


def _validate_payload(payload: object) -> dict[str, object]:
    request_id = (
        _canonical_request_id(payload.get("request_id"))
        if isinstance(payload, dict)
        else None
    )
    if type(payload) is not dict or set(payload) != _REQUEST_FIELDS:
        raise RequestError("invalid_request", request_id=request_id)

    if request_id is None:
        raise RequestError("invalid_request")

    repository_key = payload["repository_key"]
    try:
        normalized_key = _normalize_repository_key(repository_key)  # type: ignore[arg-type]
    except ValueError as exc:
        raise RequestError("invalid_request", request_id=request_id) from exc
    if normalized_key != repository_key:
        raise RequestError("invalid_request", request_id=request_id)

    snapshot_sha256 = payload["snapshot_sha256"]
    if (
        not isinstance(snapshot_sha256, str)
        or len(snapshot_sha256) != 64
        or any(character not in "0123456789abcdef" for character in snapshot_sha256)
    ):
        raise RequestError("invalid_request", request_id=request_id)

    requested_layers = payload["requested_layers"]
    if (
        type(requested_layers) is not list
        or not requested_layers
        or any(type(layer) is not str for layer in requested_layers)
        or len(set(requested_layers)) != len(requested_layers)
        or any(layer not in _SUPPORTED_LAYERS for layer in requested_layers)
    ):
        raise RequestError("invalid_request", request_id=request_id)

    return {
        "request_id": request_id,
        "repository_key": normalized_key,
        "snapshot_sha256": snapshot_sha256,
        "requested_layers": tuple(requested_layers),
    }


def analyze_request(payload: object, settings: AnalyzerSettings) -> dict[str, object]:
    """Validate a complete request before preparing and analyzing its snapshot."""

    deadline = AnalysisDeadline.start(settings.total_timeout_seconds)
    request = _validate_payload(payload)
    request_id = request["request_id"]
    try:
        prepared = prepare_snapshot(
            IMPORT_ROOT,
            request["repository_key"],  # type: ignore[arg-type]
            request["snapshot_sha256"],  # type: ignore[arg-type]
            WORK_ROOT,
            deadline=deadline,
        )
    except AnalysisDeadlineExceeded as exc:
        raise RequestError(
            "analysis_timed_out", status=504, request_id=request_id  # type: ignore[arg-type]
        ) from exc
    except (OSError, ValueError) as exc:
        raise RequestError(
            "snapshot_rejected", request_id=request_id  # type: ignore[arg-type]
        ) from exc

    source_findings: tuple[NormalizedFinding, ...] = ()
    build_findings: tuple[NormalizedFinding, ...] = ()
    sanitizer_findings: tuple[NormalizedFinding, ...] = ()
    tool_runs: list[dict[str, object]] = []
    diagnostics: list[object] = []
    build_context: object | None = None
    snapshot = prepared.__enter__()
    try:
        snapshot.verify_inventory(deadline)
        requested_layers = request["requested_layers"]
        if "source-only" in requested_layers:
            result = run_source_scan(snapshot, settings, deadline=deadline)
            source_findings = result.findings
            tool_runs.extend(result.tool_runs)
            diagnostics.extend(result.diagnostics)
            snapshot.verify_inventory(deadline)
        if "build-backed" in requested_layers:
            if "sanitizer-confirmed" in requested_layers:
                result = run_build_scan(
                    snapshot,
                    settings,
                    sanitizer_enabled=True,
                    deadline=deadline,
                )
            else:
                result = run_build_scan(snapshot, settings, deadline=deadline)
            build_findings = result.findings
            build_context = result.build_context
            tool_runs.extend(result.tool_runs)
            diagnostics.extend(result.diagnostics)
            snapshot.verify_inventory(deadline)
        if "sanitizer-confirmed" in requested_layers:
            result = run_sanitizer_scan(
                snapshot,
                settings,
                build_context,
                deadline=deadline,
            )
            sanitizer_findings = result.findings
            tool_runs.extend(result.tool_runs)
            diagnostics.extend(result.diagnostics)
            snapshot.verify_inventory(deadline)
        source_files = sum(
            PurePosixPath(path).suffix.lower() in CXX_SOURCE_SUFFIXES
            for path in snapshot.files
        )
        snapshot_files = len(snapshot.files)
    except AnalysisDeadlineExceeded as exc:
        raise RequestError(
            "analysis_timed_out", status=504, request_id=request_id  # type: ignore[arg-type]
        ) from exc
    except ValueError as exc:
        raise RequestError(
            "snapshot_rejected", request_id=request_id  # type: ignore[arg-type]
        ) from exc
    finally:
        try:
            prepared.cleanup(deadline=deadline)
        except AnalysisDeadlineExceeded as exc:
            raise RequestError(
                "analysis_timed_out", status=504, request_id=request_id  # type: ignore[arg-type]
            ) from exc

    findings, diagnostics, tool_runs = _bound_response_lists(
        fuse_findings(source_findings, build_findings, sanitizer_findings),
        diagnostics, tool_runs,
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "request_id": request_id,
        "status": "completed",
        "snapshot_sha256": request["snapshot_sha256"],
        "tool_runs": list(tool_runs),
        "findings": [finding.to_dict() for finding in findings],
        "coverage": {
            "source_files": source_files,
            "snapshot_files": snapshot_files,
        },
        "diagnostics": list(diagnostics),
    }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _reject_non_json_number(value: str) -> None:
    raise ValueError(f"invalid JSON number: {value}")


def _error_payload(code: str, request_id: str | None = None) -> dict[str, object]:
    return {"error": code, "request_id": request_id}


def _json_encoder() -> json.JSONEncoder:
    return json.JSONEncoder(
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _response_fits(payload: dict[str, object]) -> bool:
    total = 0
    for chunk in _json_encoder().iterencode(payload):
        total += len(chunk.encode("utf-8"))
        if total > MAX_RESPONSE_BYTES:
            return False
    return True


def _encode_payload(payload: dict[str, object]) -> bytes:
    return _json_encoder().encode(payload).encode("utf-8")


def health_payload(settings: AnalyzerSettings) -> dict[str, object]:
    """Return no process detail beyond versioned tool availability booleans."""

    clang_pair = (
        shutil.which("clang-14") is not None
        and shutil.which("clang++-14") is not None
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "tools": {
            "semgrep": shutil.which("semgrep") is not None,
            "cmake": shutil.which("cmake") is not None,
            "clang": clang_pair,
        },
        "configuration": {
            "source": True,
            "build": bool(settings.auto_cmake or settings.build_steps),
            "test": bool(settings.test_steps),
        },
    }


def dispatch_request(
    method: str,
    path: str,
    content_type: str,
    body: bytes,
    settings: AnalyzerSettings,
) -> tuple[int, dict[str, object]]:
    """Handle an HTTP-shaped request without exposing server implementation details."""

    if path not in {_ANALYZE_PATH, _HEALTH_PATH}:
        return 404, _error_payload("not_found")
    if path == _HEALTH_PATH:
        if method != "GET":
            return 405, _error_payload("method_not_allowed")
        return 200, health_payload(settings)
    if method != "POST":
        return 405, _error_payload("method_not_allowed")
    if content_type.split(";", 1)[0].strip().lower() != "application/json":
        return 415, _error_payload("unsupported_media_type")
    if not isinstance(body, bytes) or len(body) > MAX_REQUEST_BYTES:
        return 413, _error_payload("request_too_large")

    try:
        payload = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_json_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        return 400, _error_payload("invalid_json")

    try:
        result = analyze_request(payload, settings)
        if not _response_fits(result):
            response_request_id = (
                _canonical_request_id(payload.get("request_id"))
                if isinstance(payload, dict)
                else None
            )
            return 500, _error_payload("response_too_large", response_request_id)
        return 200, result
    except RequestError as exc:
        return exc.status, _error_payload(exc.code, exc.request_id)
    except Exception:
        request_id = (
            _canonical_request_id(payload.get("request_id"))
            if isinstance(payload, dict)
            else None
        )
        return 500, _error_payload("internal_error", request_id)


class AnalyzerRequestHandler(BaseHTTPRequestHandler):
    """Small stdlib HTTP adapter around the testable dispatch boundary."""

    analyzer_settings: AnalyzerSettings
    server_version = "LimaCxxAnalyzer/1"
    sys_version = ""

    def __getattr__(self, name: str) -> Any:
        if name.startswith("do_"):
            return self._handle
        raise AttributeError(name)

    def _send(self, status: int, payload: dict[str, object]) -> None:
        body = _encode_payload(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _handle(self, body: bytes = b"") -> None:
        status, payload = dispatch_request(
            self.command,
            self.path,
            self.headers.get("Content-Type", ""),
            body,
            self.analyzer_settings,
        )
        self._send(status, payload)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        self._handle()

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        raw_length = self.headers.get("Content-Length")
        try:
            content_length = int(raw_length) if raw_length is not None else -1
        except ValueError:
            content_length = -1
        if content_length < 0:
            self._send(400, _error_payload("invalid_request"))
            return
        if content_length > MAX_REQUEST_BYTES:
            self._send(413, _error_payload("request_too_large"))
            return
        body = self.rfile.read(content_length)
        self._handle(body)

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        self._handle()

    def do_PUT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        self._handle()

    def do_PATCH(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        self._handle()

    def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        self._handle()

    def log_message(self, format: str, *args: object) -> None:
        return


def serve() -> None:
    """Bind the analyzer only on its Compose-internal port."""

    settings = AnalyzerSettings.from_env()
    WORK_ROOT.mkdir(parents=True, exist_ok=True)

    class ConfiguredHandler(AnalyzerRequestHandler):
        analyzer_settings = settings

    server = ThreadingHTTPServer((HOST, PORT), ConfiguredHandler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    serve()
