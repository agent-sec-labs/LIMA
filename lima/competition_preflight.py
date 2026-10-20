"""Read-only competition run preflight (#311).

Lets an operator confirm the prerequisites of one competition
validation run -- manifest, import root, pinned checkouts, model
config presence and (opt-in) Sidecar health -- before any expensive
validation starts.  Every decision is delegated to the frozen
validators in :mod:`lima.openharmony_validation`; this module only
orchestrates them and projects their results onto a stable JSON v1
report.  Nothing here fetches, checks out, builds or executes target
code, and no model or auth request is ever sent.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from . import openharmony_validation
from .cxx_memory import CxxAnalyzerProtocolError, CxxAnalyzerUnavailable
from .openharmony_validation import CheckoutPreflightError, WorkspaceLimits
from .repository_import import RepositoryImportPolicy

PREFLIGHT_SCHEMA_VERSION: Final = "competition-preflight-v1"
DISCLAIMER_TEXT: Final = "前提通过不代表漏洞成立，也不代表模型已认证"

EXIT_PASSED: Final = 0
EXIT_PREREQUISITES_FAILED: Final = 2
EXIT_USAGE_ERROR: Final = 3

STATUS_PASS: Final = "pass"  # noqa: S105 -- frozen wire value
STATUS_FAIL: Final = "fail"
STATUS_NOT_REQUESTED: Final = "not-requested"

CHECK_CASE_MANIFEST: Final = "case-manifest"
CHECK_REPOSITORY_IMPORT_ROOT: Final = "repository-import-root"
CHECK_CHECKOUTS: Final = "checkouts"
CHECK_MODEL_CONFIG: Final = "model-config"
CHECK_SIDECAR_HEALTH: Final = "sidecar-health"

SIDECAR_TIMEOUT_SECONDS: Final = 5
SIDECAR_MAX_RESPONSE_BYTES: Final = 64 * 1024
DEFAULT_ANALYZER_URL: Final = "http://127.0.0.1:8090"

READ_ONLY_NOTE: Final = (
    "read-only preflight: git identify/diff queries only; no fetch, "
    "checkout, build, target execution or model call"
)

_SECRET_RE: Final = re.compile(r"sk-[A-Za-z0-9_-]{8,}")
_MAX_DETAIL_CHARS: Final = 200


@dataclass(frozen=True)
class PreflightRequest:
    """One preflight invocation against a single case."""

    case_path: str
    repository_import_root: str
    check_sidecar: bool = False
    analyzer_url: str = ""


def _safe_detail(text: object, limit: int = _MAX_DETAIL_CHARS) -> str:
    scrubbed = _SECRET_RE.sub("sk-***", str(text))
    return " ".join(scrubbed.split())[:limit]


def _record(
    name: str,
    status: str,
    reason_code: str = "",
    detail: str = "",
) -> dict:
    return {
        "name": name,
        "status": status,
        "reason_code": reason_code,
        "detail": _safe_detail(detail),
    }


def validate_analyzer_url(url: str) -> str:
    """Accept one plain http(s) origin; refuse everything else.

    Credentials, query strings and fragments are rejected without the
    URL ever being echoed back, so a mistyped secret cannot leak into
    diagnostics or reports.
    """

    text = str(url or "").strip().rstrip("/")
    if not text:
        raise ValueError("analyzer URL is required")
    try:
        split = urllib.parse.urlsplit(text)
        _ = split.port  # forces port syntax validation
    except ValueError as exc:
        raise ValueError("analyzer URL is malformed") from exc
    if split.scheme not in ("http", "https"):
        raise ValueError("analyzer URL must use http or https")
    if split.username is not None or split.password is not None:
        raise ValueError(
            "analyzer URL must not embed user or password credentials"
        )
    if split.query or split.fragment:
        raise ValueError("analyzer URL must not include a query or fragment")
    if not split.hostname:
        raise ValueError("analyzer URL must include a host")
    return text


def _effective_analyzer_url(url: str, environ: Mapping[str, str]) -> str:
    candidate = (
        str(url or "").strip()
        or str(environ.get("LIMA_CXX_ANALYZER_URL", "")).strip()
        or DEFAULT_ANALYZER_URL
    )
    return validate_analyzer_url(candidate)


def _positive_env_int(
    environ: Mapping[str, str], name: str, default: int,
) -> int:
    raw = str(environ.get(name, "")).strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < 1:
        raise ValueError(f"{name} must be positive")
    return value


def _resolve_workspace_limits(environ: Mapping[str, str]) -> WorkspaceLimits:
    """The synchronized scan budgets, mirroring the validation CLI."""

    return WorkspaceLimits(
        max_files=_positive_env_int(
            environ, "LIMA_REPOSITORY_SCAN_MAX_FILES", 5000,
        ),
        max_file_bytes=_positive_env_int(
            environ, "LIMA_REPOSITORY_SCAN_MAX_FILE_BYTES", 512 * 1024,
        ),
        max_total_bytes=_positive_env_int(
            environ, "LIMA_REPOSITORY_SCAN_MAX_TOTAL_BYTES", 20 * 1024 * 1024,
        ),
    )


def _model_config_presence(environ: Mapping[str, str]) -> dict[str, bool]:
    """Presence only: values are never read, echoed or validated."""

    provider = str(environ.get("LIMA_LLM_BASE_URL", "")).strip()
    model = str(
        environ.get("LIMA_CXX_AGENT_MODEL", "")
        or environ.get("LIMA_LLM_MODEL", "")
    ).strip()
    api_key = str(environ.get("LIMA_LLM_API_KEY", "")).strip()
    return {
        "provider_url": bool(provider),
        "model": bool(model),
        "api_key": bool(api_key),
    }


def _default_analyzer_client_factory(
    base_url: str, timeout_seconds: int, max_response_bytes: int,
):
    from .cxx_memory import CxxMemoryAnalyzerClient

    return CxxMemoryAnalyzerClient(
        base_url, timeout_seconds, max_response_bytes,
    )


def _probe_sidecar(base_url: str, client_factory: Callable):
    """One health call, bounded timeout, no retries."""

    client = client_factory(
        base_url, SIDECAR_TIMEOUT_SECONDS, SIDECAR_MAX_RESPONSE_BYTES,
    )
    try:
        return client.health()
    except (TimeoutError, OSError) as exc:
        raise CxxAnalyzerUnavailable(
            "C/C++ analyzer is unavailable",
        ) from exc


def _health_summary(health) -> str:
    def wire(value: object) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value)

    fields = dataclasses.asdict(health)
    return " ".join(f"{name}={wire(value)}" for name, value in fields.items())


def run_competition_preflight(
    request: PreflightRequest,
    *,
    environ: Mapping[str, str] | None = None,
    analyzer_client_factory: Callable | None = None,
) -> dict:
    """Run every applicable check and return the JSON v1 payload.

    Raises :class:`ValueError` for operator-input problems (malformed
    analyzer URL, unusable budget environment) so callers can map them
    to the usage-error exit code before any report is written.
    """

    environment = os.environ if environ is None else environ
    client_factory = (
        analyzer_client_factory or _default_analyzer_client_factory
    )

    sidecar_url = (
        _effective_analyzer_url(request.analyzer_url, environment)
        if request.check_sidecar
        else ""
    )
    limits = _resolve_workspace_limits(environment)

    checks: list[dict] = []
    diagnostics: list[str] = [READ_ONLY_NOTE]

    case = None
    try:
        case = openharmony_validation.load_openharmony_case(
            request.case_path,
        )
        checks.append(_record(CHECK_CASE_MANIFEST, STATUS_PASS))
    except (OSError, ValueError) as exc:
        checks.append(_record(
            CHECK_CASE_MANIFEST, STATUS_FAIL, "manifest-invalid",
            str(exc),
        ))
    except Exception as exc:  # contained: scrubbed and bounded below
        checks.append(_record(
            CHECK_CASE_MANIFEST, STATUS_FAIL, "check-error", str(exc),
        ))

    policy = RepositoryImportPolicy(str(request.repository_import_root))
    root_available = bool(policy.capabilities()["enabled"])
    checks.append(_record(
        CHECK_REPOSITORY_IMPORT_ROOT,
        STATUS_PASS if root_available else STATUS_FAIL,
        "" if root_available else "import-root-unavailable",
    ))

    if case is None or not root_available:
        # A dependent check is never faked as passed or failed: it did
        # not run because an upstream prerequisite already failed.
        checks.append(_record(
            CHECK_CHECKOUTS, STATUS_NOT_REQUESTED, "skipped-upstream-failed",
        ))
    else:
        try:
            openharmony_validation.validate_case_checkouts(
                case, policy, limits,
            )
            checks.append(_record(CHECK_CHECKOUTS, STATUS_PASS))
        except CheckoutPreflightError as exc:
            checks.append(_record(
                CHECK_CHECKOUTS, STATUS_FAIL, exc.reason,
                exc.detail or str(exc),
            ))
        except Exception as exc:  # contained: scrubbed and bounded below
            checks.append(_record(
                CHECK_CHECKOUTS, STATUS_FAIL, "check-error", str(exc),
            ))

    presence = _model_config_presence(environment)
    missing = sorted(
        name for name, provided in presence.items() if not provided
    )
    if missing:
        checks.append(_record(
            CHECK_MODEL_CONFIG, STATUS_FAIL, "model-config-missing",
            "missing: " + ", ".join(missing),
        ))
    else:
        checks.append(_record(
            CHECK_MODEL_CONFIG, STATUS_PASS, "",
            "provider_url=present model=present api_key=present;"
            " authentication not verified",
        ))
    diagnostics.append(
        "model-config: "
        + " ".join(
            f"{name}={'present' if provided else 'absent'}"
            for name, provided in presence.items()
        )
    )

    if not request.check_sidecar:
        checks.append(_record(
            CHECK_SIDECAR_HEALTH, STATUS_NOT_REQUESTED, "not-selected",
        ))
    else:
        try:
            health = _probe_sidecar(sidecar_url, client_factory)
        except CxxAnalyzerUnavailable:
            checks.append(_record(
                CHECK_SIDECAR_HEALTH, STATUS_FAIL, "sidecar-unavailable",
            ))
        except CxxAnalyzerProtocolError:
            checks.append(_record(
                CHECK_SIDECAR_HEALTH, STATUS_FAIL, "sidecar-protocol-error",
            ))
        except Exception as exc:  # contained: scrubbed and bounded below
            checks.append(_record(
                CHECK_SIDECAR_HEALTH, STATUS_FAIL, "check-error", str(exc),
            ))
        else:
            checks.append(_record(
                CHECK_SIDECAR_HEALTH, STATUS_PASS, "",
                "sidecar reachable; capabilities recorded in diagnostics",
            ))
            diagnostics.append(f"sidecar: {_health_summary(health)}")

    prerequisites_passed = all(
        record["status"] == STATUS_PASS
        for record in checks
        if record["name"] != CHECK_SIDECAR_HEALTH
    )
    return {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "case_id": case.case_id if case is not None else "",
        "checks": checks,
        "prerequisites_passed": prerequisites_passed,
        "sidecar_requested": bool(request.check_sidecar),
        "diagnostics": diagnostics,
        "disclaimer": DISCLAIMER_TEXT,
    }


def preflight_exit_code(payload: dict) -> int:
    """0 only when every requested check passed; 2 otherwise."""

    sidecar = next(
        record for record in payload["checks"]
        if record["name"] == CHECK_SIDECAR_HEALTH
    )
    if payload["prerequisites_passed"] and (
        not payload["sidecar_requested"] or sidecar["status"] == STATUS_PASS
    ):
        return EXIT_PASSED
    return EXIT_PREREQUISITES_FAILED


def write_preflight_report(payload: dict, output_path: str | Path) -> Path:
    """Write the report once; an existing target is never overwritten."""

    path = Path(output_path)
    if path.exists():
        raise ValueError(
            f"output path already exists, refusing to overwrite: {path}"
        )
    with open(path, "x", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    return path


def format_summary(payload: dict, report_path: object) -> str:
    """The short stdout summary, derived from the report payload."""

    def wire(value: object) -> str:
        return "true" if value else "false"

    lines = [f"schema_version: {payload['schema_version']}"]
    if payload.get("case_id"):
        lines.append(f"case_id: {payload['case_id']}")
    for record in payload["checks"]:
        line = f"check {record['name']}: {record['status']}"
        if record["reason_code"]:
            line += f" ({record['reason_code']})"
        lines.append(line)
    lines.append(
        f"prerequisites_passed: {wire(payload['prerequisites_passed'])}"
    )
    lines.append(
        f"sidecar_requested: {wire(payload['sidecar_requested'])}"
    )
    lines.append(f"report: {report_path}")
    lines.append(f"说明：{DISCLAIMER_TEXT}")
    return "\n".join(lines)
