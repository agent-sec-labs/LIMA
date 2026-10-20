"""Competition run preflight command (#311).

A thin read-only CLI: it parses arguments, refuses to overwrite the
output path, then delegates every check to
``lima.competition_preflight`` and prints the summary derived from the
same JSON payload it writes.  Exit codes: 0 = every requested
prerequisite check passed, 2 = prerequisites not met, 3 = usage or
output error.  No model, auth or Sidecar request is made unless
``--check-sidecar`` is passed, and no target code ever runs.
"""

from __future__ import annotations

import argparse
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
        arguments = _build_parser().parse_args(argv)
    except SystemExit as exc:
        # argparse exits 2 (reserved here for `failed`), so a missing or
        # malformed argument is re-mapped to the usage-error code.
        if exc.code == 0:
            raise
        print("configuration error: arguments incomplete or invalid")
        return EXIT_USAGE_ERROR

    output = pathlib.Path(arguments.output)
    if output.exists():
        print(
            f"configuration error: output path already exists, refusing "
            f"to overwrite: {output}"
        )
        return EXIT_USAGE_ERROR

    request = PreflightRequest(
        case_path=arguments.case,
        repository_import_root=arguments.repository_import_root,
        check_sidecar=arguments.check_sidecar,
        analyzer_url=arguments.analyzer_url or "",
    )
    try:
        payload = run_competition_preflight(request)
    except ValueError as exc:
        print(f"configuration error: {str(exc)[:200]}")
        return EXIT_USAGE_ERROR

    try:
        report = write_preflight_report(payload, output)
    except (OSError, ValueError) as exc:
        print(f"output error: {str(exc)[:200]}")
        return EXIT_USAGE_ERROR

    print(format_summary(payload, report))
    return preflight_exit_code(payload)


if __name__ == "__main__":
    raise SystemExit(main())
