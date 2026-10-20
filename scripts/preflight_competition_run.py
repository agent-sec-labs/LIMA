"""Competition run preflight command (#311).

A thin read-only CLI: it parses arguments, refuses unsafe or existing
output paths, then delegates every check to
``lima.competition_preflight`` and prints the summary derived from the
same JSON payload it writes.  Exit codes: 0 = every requested
prerequisite check passed, 2 = prerequisites not met, 3 = usage or
output error.  No model, auth or Sidecar request is made unless
``--check-sidecar`` is passed, and no target code ever runs.

Error text policy (review #328): usage and output failures print fixed
reason codes only -- never raw arguments, paths or exception text --
and argparse's own echo (which would repeat a mistyped secret) is
suppressed before it reaches stderr.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lima.competition_preflight import (  # noqa: E402 - after sys.path setup
    EXIT_USAGE_ERROR,
    PreflightRequest,
    format_summary,
    preflight_exit_code,
    run_competition_preflight,
    validate_output_placement,
    write_preflight_report,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="preflight_competition_run.py",
        description=(
            "Read-only preflight for one competition validation run; "
            "confirms case, checkout, compdb, model-config and (opt-in) "
            "Sidecar prerequisites without starting a model or target code."
        ),
    )
    parser.add_argument("--case", required=True)
    parser.add_argument("--repository-import-root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--check-sidecar", action="store_true",
        help="probe the C/C++ analyzer Sidecar /health endpoint once",
    )
    parser.add_argument(
        "--analyzer-url",
        help="Sidecar base URL; defaults to LIMA_CXX_ANALYZER_URL "
        "or http://127.0.0.1:8090",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            arguments = _build_parser().parse_args(argv)
    except SystemExit as exc:
        # argparse exits 2 (reserved here for `failed`) and echoes the
        # raw argument text to stderr -- a mistyped `--api-key=...`
        # would leak its value -- so the echo is suppressed and a
        # fixed message printed instead.
        if exc.code == 0:
            raise
        print("configuration error: arguments incomplete or invalid")
        return EXIT_USAGE_ERROR

    try:
        output = validate_output_placement(
            arguments.output,
            repository_import_root=arguments.repository_import_root,
            case_path=arguments.case,
        )
    except ValueError as exc:
        print(f"configuration error: {exc}")
        return EXIT_USAGE_ERROR

    if output.exists():
        print("configuration error: output_already_exists")
        return EXIT_USAGE_ERROR

    request = PreflightRequest(
        case_path=arguments.case,
        repository_import_root=arguments.repository_import_root,
        check_sidecar=arguments.check_sidecar,
        analyzer_url=arguments.analyzer_url or "",
        output_path=str(output),
    )
    try:
        payload = run_competition_preflight(request)
    except ValueError as exc:
        print(f"configuration error: {exc}")
        return EXIT_USAGE_ERROR
    except OSError:
        print("configuration error: io_error")
        return EXIT_USAGE_ERROR

    try:
        report = write_preflight_report(payload, output)
    except ValueError:
        print("output error: output_already_exists")
        return EXIT_USAGE_ERROR
    except OSError:
        print("output error: report_not_written")
        return EXIT_USAGE_ERROR

    print(format_summary(payload, report))
    return preflight_exit_code(payload)


if __name__ == "__main__":
    raise SystemExit(main())
