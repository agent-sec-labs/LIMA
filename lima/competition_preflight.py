"""Read-only competition run preflight (#311).

Lets an operator confirm the prerequisites of one competition
validation run -- manifest, import root, pinned checkouts, model
config presence and (opt-in) Sidecar health -- before any expensive
validation starts.  Every decision is delegated to the frozen
validators in :mod:`lima.openharmony_validation`; this module only
orchestrates them and projects their results onto a stable JSON v1
report.  Nothing here fetches, checks out, builds or executes target
code, and no model or auth request is ever sent.

Diagnostic policy (review #328): reports and stdout carry fixed
reason codes and fixed detail strings only.  Loader and validator
exception text is never echoed, because manifest content and other
operator input can carry secret sentinels; the manifest failure
location is narrowed with a controlled, non-echoing triage instead.
"""

from __future__ import annotations

import dataclasses
import json
import ntpath
import os
import re
import unicodedata
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
UNEXPECTED_FAILURE_DETAIL: Final = (
    "unexpected failure; raw diagnostics are never echoed"
)

# The run entry (scripts/run_openharmony_validation.py) requires the
# provider URL and model, but accepts an empty API key for local
# endpoints; the preflight records the key's presence without gating
# on it (review #328, P2-3).
MODEL_CONFIG_REQUIRED: Final = ("provider_url", "model")

_MAX_MANIFEST_TRIAGE_BYTES: Final = 256 * 1024  # the loader's cap

_WINDOWS_DEVICE_RE: Final = re.compile(
    r"(?:CON|PRN|AUX|NUL|COM[0-9¹²³]|LPT[0-9¹²³])(?:\..*)?\Z",
    re.IGNORECASE,
)
_WINDOWS_FORBIDDEN_CHARS: Final = ':<>"|?*'
_WINDOWS_RESERVED_STREAMS: Final = frozenset({"CONIN$", "CONOUT$"})


@dataclass(frozen=True)
class PreflightRequest:
    """One preflight invocation against a single case."""

    case_path: str
    repository_import_root: str
    check_sidecar: bool = False
    analyzer_url: str = ""
    output_path: str = ""


def _record(
    name: str,
    status: str,
    reason_code: str = "",
    detail: str = "",
) -> dict:
    # ``detail`` must always be a fixed, non-input string; callers
    # never pass exception or manifest text here.
    return {
        "name": name,
        "status": status,
        "reason_code": reason_code,
        "detail": detail,
    }


# ---------------------------------------------------------- output guard

def _validate_windows_output_components(raw: str) -> None:
    """Reject device/stream aliases before Win32 normalization hides them.

    Component rules mirror ``lima.competition_report_materials``: a
    colon beyond the drive letter is an NTFS alternate data stream, and
    DOS device names (with extensions and case variants), CONIN$/CONOUT$,
    trailing dots/spaces and control characters are all refused.
    """

    drive, tail = ntpath.splitdrive(raw)
    if drive and re.fullmatch(r"[A-Za-z]:", drive) is None:
        raise ValueError("invalid_output_path")
    for component in re.split(r"[\\/]", tail):
        if component in ("", ".", ".."):
            continue
        stem = component.split(".", 1)[0].strip(" ")
        if (
            component.startswith(" ")
            or component.endswith((" ", "."))
            or any(
                character in _WINDOWS_FORBIDDEN_CHARS
                or unicodedata.category(character) in ("Cc", "Cf", "Cs")
                for character in component
            )
            or _WINDOWS_DEVICE_RE.fullmatch(stem) is not None
            or stem.upper() in _WINDOWS_RESERVED_STREAMS
        ):
            raise ValueError("invalid_output_path")


def _is_within(candidate: Path, root: Path) -> bool:
    child = os.path.normcase(str(candidate))
    parent = os.path.normcase(str(root))
    return child == parent or child.startswith(parent + os.sep)


def validate_output_placement(
    output_path: str | Path,
    *,
    repository_import_root: str,
    case_path: str,
) -> None:
    """Refuse outputs that would land inside the tested inputs (#328 P2-1).

    A report written below the import root would become an untracked
    file and fail the next preflight of the same checkout; on Windows,
    an ADS-style path could attach a stream to the case manifest.  The
    guard fires before any check runs, so no report is ever written.
    """

    raw = os.fspath(output_path)
    if os.name == "nt":
        _validate_windows_output_components(raw)
    try:
        output = Path(raw).expanduser().resolve()
        import_root = (
            Path(repository_import_root).expanduser().resolve()
        )
        case = Path(case_path).expanduser().resolve()
    except (OSError, RuntimeError) as exc:
        raise ValueError("invalid_output_path") from exc
    if output == case:
        raise ValueError("output_is_input")
    if _is_within(output, import_root):
        raise ValueError("output_inside_repository_import_root")


# ------------------------------------------------------------ input checks

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


def _presence_items(presence: Mapping[str, bool]) -> str:
    return " ".join(
        f"{name}={'present' if provided else 'absent'}"
        for name, provided in presence.items()
    )


def _manifest_failure_bucket(path: str) -> str:
    """Narrow a manifest failure with controlled, non-echoing triage.

    The loader's exception text can embed raw manifest values, so the
    failure location is re-derived here from exception kinds alone and
    reported as one of four fixed strings.
    """

    try:
        with open(path, "rb") as handle:
            raw = handle.read(_MAX_MANIFEST_TRIAGE_BYTES + 1)
    except OSError:
        return "case manifest unreadable"
    if not raw:
        return "case manifest unreadable"
    if len(raw) > _MAX_MANIFEST_TRIAGE_BYTES:
        return "case manifest exceeds the size limit"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return "case manifest is not UTF-8"
    try:
        json.loads(text)
    except ValueError:
        return "case manifest is not valid JSON"
    return "case manifest violates the frozen schema"


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

    Raises :class:`ValueError` with a fixed reason code for
    operator-input problems (unsafe output placement, malformed
    analyzer URL, unusable budget environment) so callers can map them
    to the usage-error exit code before any report is written.
    """

    environment = os.environ if environ is None else environ
    client_factory = (
        analyzer_client_factory or _default_analyzer_client_factory
    )

    if request.output_path:
        validate_output_placement(
            request.output_path,
            repository_import_root=request.repository_import_root,
            case_path=request.case_path,
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
    except (OSError, ValueError):
        checks.append(_record(
            CHECK_CASE_MANIFEST, STATUS_FAIL, "manifest-invalid",
            _manifest_failure_bucket(request.case_path),
        ))
    except Exception:  # contained: fixed detail, nothing echoed
        checks.append(_record(
            CHECK_CASE_MANIFEST, STATUS_FAIL, "check-error",
            UNEXPECTED_FAILURE_DETAIL,
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
            # The stable reason category is the contract; the error's
            # detail text can embed input values and is not echoed.
            checks.append(_record(
                CHECK_CHECKOUTS, STATUS_FAIL, exc.reason,
            ))
        except Exception:  # contained: fixed detail, nothing echoed
            checks.append(_record(
                CHECK_CHECKOUTS, STATUS_FAIL, "check-error",
                UNEXPECTED_FAILURE_DETAIL,
            ))

    presence = _model_config_presence(environment)
    missing = sorted(
        name for name in MODEL_CONFIG_REQUIRED if not presence[name]
    )
    if missing:
        checks.append(_record(
            CHECK_MODEL_CONFIG, STATUS_FAIL, "model-config-missing",
            "missing required items: " + ", ".join(missing),
        ))
    else:
        checks.append(_record(
            CHECK_MODEL_CONFIG, STATUS_PASS, "",
            f"{_presence_items(presence)}; authentication not verified",
        ))
    diagnostics.append(f"model-config: {_presence_items(presence)}")

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
        except Exception:  # contained: fixed detail, nothing echoed
            checks.append(_record(
                CHECK_SIDECAR_HEALTH, STATUS_FAIL, "check-error",
                UNEXPECTED_FAILURE_DETAIL,
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
        raise ValueError("output_already_exists")
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
