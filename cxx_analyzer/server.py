"""Bounded internal HTTP service for the isolated C/C++ analyzer."""

from __future__ import annotations

import json
import shutil
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any, Final

from .config import AnalyzerSettings
from .snapshot import _normalize_repository_key, prepare_snapshot
from .source_scan import run_source_scan

SCHEMA_VERSION: Final = 1
HOST: Final = "0.0.0.0"  # noqa: S104 - Reachable only on the internal Compose network.
PORT: Final = 8090
MAX_REQUEST_BYTES: Final = 64 * 1024
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
_SOURCE_SUFFIXES: Final = frozenset({".c", ".cc", ".cpp", ".cxx"})


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

    request = _validate_payload(payload)
    request_id = request["request_id"]
    try:
        prepared = prepare_snapshot(
            IMPORT_ROOT,
            request["repository_key"],  # type: ignore[arg-type]
            request["snapshot_sha256"],  # type: ignore[arg-type]
            WORK_ROOT,
        )
    except (OSError, ValueError) as exc:
        raise RequestError(
            "snapshot_rejected", request_id=request_id  # type: ignore[arg-type]
        ) from exc

    findings: list[dict[str, object]] = []
    tool_runs: list[dict[str, object]] = []
    diagnostics: list[object] = []
    with prepared as snapshot:
        requested_layers = request["requested_layers"]
        if "source-only" in requested_layers:
            result = run_source_scan(snapshot, settings)
            findings.extend(finding.to_dict() for finding in result.findings)
            tool_runs.extend(result.tool_runs)
            diagnostics.extend(result.diagnostics)
        if "build-backed" in requested_layers:
            diagnostics.append("build-backed-not-available")
        if "sanitizer-confirmed" in requested_layers:
            diagnostics.append("sanitizer-confirmed-not-available")
        source_files = sum(
            PurePosixPath(path).suffix.lower() in _SOURCE_SUFFIXES
            for path in snapshot.files
        )
        snapshot_files = len(snapshot.files)

    return {
        "schema_version": SCHEMA_VERSION,
        "request_id": request_id,
        "status": "completed",
        "snapshot_sha256": request["snapshot_sha256"],
        "tool_runs": tool_runs,
        "findings": findings,
        "coverage": {
            "source_files": source_files,
            "snapshot_files": snapshot_files,
        },
        "diagnostics": diagnostics,
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


def health_payload() -> dict[str, object]:
    """Return no process detail beyond versioned tool availability booleans."""

    return {
        "schema_version": SCHEMA_VERSION,
        "tools": {
            "semgrep": shutil.which("semgrep") is not None,
            "cmake": shutil.which("cmake") is not None,
            "clang": shutil.which("clang") is not None,
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
        return 200, health_payload()
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
        return 200, analyze_request(payload, settings)
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
        body = json.dumps(
            payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
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
    Path("/work/tmp").mkdir(parents=True, exist_ok=True)

    class ConfiguredHandler(AnalyzerRequestHandler):
        analyzer_settings = settings

    server = ThreadingHTTPServer((HOST, PORT), ConfiguredHandler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    serve()
