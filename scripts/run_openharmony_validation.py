"""OpenHarmony pilot validation command (plan Task 6).

A thin CLI: it parses and validates arguments, assembles the import
policy, analyzer client, workspace limits, budgets and the LLM config,
then delegates every actual decision to ``lima.openharmony_validation``.
Exit codes: 0 = passed, 2 = failed, 3 = inconclusive or configuration
error.  The provider API key is read only from the environment; it never
appears in arguments, output or error text.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lima.openharmony_validation import (  # noqa: E402 - after sys.path setup
    ValidationStatus,
    WorkspaceLimits,
    load_openharmony_case,
    run_openharmony_case,
    write_validation_bundle,
)
from lima.repository_import import RepositoryImportPolicy  # noqa: E402

EXIT_PASSED = 0
EXIT_FAILED = 2
EXIT_INCONCLUSIVE = 3

_SECRET_RE = re.compile(r"sk-[A-Za-z0-9_-]{8,}")
_MAX_DIAGNOSTIC_CHARS = 200


class _ConfigError(Exception):
    """One bounded configuration failure; the message is already safe."""


def _scrub(text: str) -> str:
    return _SECRET_RE.sub("sk-***", text)


def _positive_int(value: str, name: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise _ConfigError(f"{name} must be an integer") from exc
    if parsed < 1:
        raise _ConfigError(f"{name} must be positive")
    return parsed


def _positive_float(value: str, name: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise _ConfigError(f"{name} must be a number") from exc
    if parsed <= 0:
        raise _ConfigError(f"{name} must be positive")
    return parsed


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run_openharmony_validation.py",
        description="Run the frozen OpenHarmony dual-revision pilot case.",
    )
    parser.add_argument("--case", required=True)
    parser.add_argument("--repository-import-root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--cxx-analyzer-url")
    parser.add_argument("--timeout")
    parser.add_argument("--deadline-seconds")
    parser.add_argument("--parallelism")
    parser.add_argument("--dialogue-rounds")
    parser.add_argument("--provider-url")
    parser.add_argument("--model")
    parser.add_argument("--max-files", dest="max_files", default=None)
    parser.add_argument(
        "--max-file-bytes", dest="max_file_bytes", default=None,
    )
    parser.add_argument(
        "--max-total-bytes", dest="max_total_bytes", default=None,
    )
    return parser


def _resolve_limit(arguments, flag: str, env_name: str, default: int) -> int:
    raw = getattr(arguments, flag, None)
    if raw is not None:
        return _positive_int(raw, f"--{flag.replace('_', '-')}")
    env = os.environ.get(env_name, "").strip()
    if env:
        return _positive_int(env, env_name)
    return default


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _build_parser().parse_args(argv)
    except SystemExit as exc:
        # Missing or malformed arguments are configuration errors here:
        # argparse exits 2 (which this CLI reserves for `failed`), so the
        # message is re-printed and mapped to the inconclusive code.
        if exc.code == 0:
            raise
        print("configuration error: arguments incomplete or invalid")
        return EXIT_INCONCLUSIVE

    from lima.cxx_agent_tools import CxxAgentBudget
    from lima.cxx_memory import CxxMemoryAnalyzerClient

    try:
        limits = WorkspaceLimits(
            max_files=_resolve_limit(
                arguments, "max_files",
                "LIMA_REPOSITORY_SCAN_MAX_FILES", 5000,
            ),
            max_file_bytes=_resolve_limit(
                arguments, "max_file_bytes",
                "LIMA_REPOSITORY_SCAN_MAX_FILE_BYTES", 512 * 1024,
            ),
            max_total_bytes=_resolve_limit(
                arguments, "max_total_bytes",
                "LIMA_REPOSITORY_SCAN_MAX_TOTAL_BYTES", 20 * 1024 * 1024,
            ),
        )
        timeout = (
            _positive_int(arguments.timeout, "--timeout")
            if arguments.timeout is not None else 60
        )
        deadline_seconds = (
            _positive_float(arguments.deadline_seconds, "--deadline-seconds")
            if arguments.deadline_seconds is not None else 1800.0
        )
        parallelism = (
            _positive_int(arguments.parallelism, "--parallelism")
            if arguments.parallelism is not None else 1
        )
        dialogue_rounds = (
            _positive_int(arguments.dialogue_rounds, "--dialogue-rounds")
            if arguments.dialogue_rounds is not None else 1
        )
    except _ConfigError as exc:
        print(f"configuration error: {exc}")
        return EXIT_INCONCLUSIVE

    base_url = (
        arguments.provider_url
        or os.environ.get("LIMA_LLM_BASE_URL", "")
    ).rstrip("/")
    model = (
        arguments.model
        or os.environ.get("LIMA_CXX_AGENT_MODEL", "")
        or os.environ.get("LIMA_LLM_MODEL", "")
    ).strip()
    if not base_url or not model:
        print(
            "configuration error: provider not configured: pass "
            "--provider-url and --model, or set LIMA_LLM_BASE_URL and "
            "LIMA_CXX_AGENT_MODEL (or LIMA_LLM_MODEL); the API key comes "
            "from LIMA_LLM_API_KEY"
        )
        return EXIT_INCONCLUSIVE
    llm_config = {
        "provider": os.environ.get("LIMA_LLM_PROVIDER", "custom").strip()
        or "custom",
        "base_url": base_url,
        "api_key": os.environ.get("LIMA_LLM_API_KEY", ""),
        "model": model,
        "headers": {},
    }
    if os.environ.get("LIMA_CXX_AGENT_REQUEST_PARAMS_JSON"):
        import json

        try:
            llm_config["request_params"] = json.loads(
                os.environ["LIMA_CXX_AGENT_REQUEST_PARAMS_JSON"]
            )
        except ValueError:
            print(
                "configuration error: "
                "LIMA_CXX_AGENT_REQUEST_PARAMS_JSON is not valid JSON"
            )
            return EXIT_INCONCLUSIVE

    output = pathlib.Path(arguments.output)
    if output.exists():
        print(
            f"configuration error: output path already exists, refusing to "
            f"overwrite: {output}"
        )
        return EXIT_INCONCLUSIVE

    try:
        case = load_openharmony_case(arguments.case)
    except (OSError, ValueError) as exc:
        print(f"configuration error: cannot load case: {_scrub(str(exc))}")
        return EXIT_INCONCLUSIVE

    analyzer_url = (
        arguments.cxx_analyzer_url
        or os.environ.get("LIMA_CXX_ANALYZER_URL", "http://127.0.0.1:8090")
    )
    analyzer_client = CxxMemoryAnalyzerClient(
        analyzer_url, timeout, 8 * 1024 * 1024,
    )

    def budget_factory():
        return CxxAgentBudget(
            max_calls=160, max_output_bytes=16 * 1024 * 1024,
        )

    try:
        result = run_openharmony_case(
            case,
            import_policy=RepositoryImportPolicy(
                arguments.repository_import_root
            ),
            workspace_limits=limits,
            analyzer_client=analyzer_client,
            llm_config=llm_config,
            budget_factory=budget_factory,
            timeout=timeout,
            deadline_seconds=deadline_seconds,
            parallelism=parallelism,
            dialogue_rounds=dialogue_rounds,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"inconclusive: {_scrub(str(exc))[:400]}")
        return EXIT_INCONCLUSIVE

    try:
        bundle = write_validation_bundle(
            result, output,
            git_root=_resolve_git_root(arguments.repository_import_root, case),
        )
    except (OSError, ValueError) as exc:
        print(f"bundle write failed: {_scrub(str(exc))[:400]}")
        return EXIT_INCONCLUSIVE

    print(f"status: {result.status.value}")
    print(f"bundle: {bundle}")
    for note in result.reason_codes[:8]:
        print(f"  diagnostic: {_scrub(note)[:_MAX_DIAGNOSTIC_CHARS]}")
    if result.status == ValidationStatus.PASSED:
        return EXIT_PASSED
    if result.status == ValidationStatus.FAILED:
        return EXIT_FAILED
    return EXIT_INCONCLUSIVE


def _resolve_git_root(import_root: str, case) -> pathlib.Path | None:
    """The vulnerable checkout directory below the import root."""

    policy = RepositoryImportPolicy(import_root)
    try:
        return policy.resolve(case.vulnerable.repository_key)
    except ValueError:
        return None


if __name__ == "__main__":
    raise SystemExit(main())
