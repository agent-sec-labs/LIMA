"""Scan a local repository with the deterministic LIMA baseline."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from lima.console import configure_utf8_stdio
from lima.cxx_memory import CxxMemoryAnalyzerClient
from lima.report import to_markdown
from lima.repository_import import RepositoryImportPolicy
from lima.repository_scanner import RepositoryScanner
from lima.workspace import RepositoryWorkspace

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
VERIFIED_STATES = {
    "syntax-verified", "corroborated", "dataflow-verified", "confirmed"
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bounded, read-only repository security scan (no remote API required)."
    )
    parser.add_argument("repository", help="Local repository directory to scan")
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    parser.add_argument(
        "--sast", choices=("auto", "off", "required"), default="auto",
        help="Use installed SAST engines, disable them, or fail when unavailable",
    )
    parser.add_argument(
        "--dataflow", choices=("on", "off"), default="on",
        help="Enable or disable local source-to-sink verification for ablation baselines",
    )
    parser.add_argument(
        "--cxx-memory", choices=("auto", "off", "required"), default="off",
        help="Opt in to the configured C/C++ memory analysis Sidecar",
    )
    parser.add_argument(
        "--repository-key",
        help="Bounded import-policy repository key required for C/C++ Sidecar analysis",
    )
    parser.add_argument(
        "--cxx-analyzer-url",
        default=os.getenv("LIMA_CXX_ANALYZER_URL", "http://cxx-analyzer:8090"),
        help="Internal C/C++ analyzer URL",
    )
    parser.add_argument(
        "--cxx-analysis-timeout-seconds",
        type=int,
        default=int(os.getenv("LIMA_CXX_ANALYSIS_TIMEOUT_SECONDS", "300")),
    )
    parser.add_argument(
        "--cxx-max-response-bytes",
        type=int,
        default=int(os.getenv("LIMA_CXX_MAX_RESPONSE_BYTES", str(2 * 1024 * 1024))),
    )
    parser.add_argument("--output", help="Write the report to this path instead of stdout")
    parser.add_argument("--max-files", type=int, default=5_000)
    parser.add_argument("--max-file-bytes", type=int, default=512 * 1024)
    parser.add_argument("--max-total-bytes", type=int, default=20 * 1024 * 1024)
    parser.add_argument(
        "--exclude-dir", action="append", default=[], metavar="NAME",
        help="Directory name to exclude; may be supplied more than once",
    )
    parser.add_argument(
        "--fail-on", choices=("never", "low", "medium", "high", "critical"),
        default="never", help="Return exit code 2 when this severity or higher is found",
    )
    parser.add_argument(
        "--verified-only", action="store_true",
        help="Apply --fail-on only to findings with deterministic verification evidence",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    configure_utf8_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    repository_key = ""
    cxx_memory_adapter = None
    if args.cxx_memory != "off":
        if not args.repository_key:
            parser.error("--repository-key is required when --cxx-memory is auto or required")
        try:
            repository_key = RepositoryImportPolicy().normalize_key(args.repository_key)
        except ValueError as exc:
            parser.error("invalid --repository-key: %s" % exc)
        cxx_memory_adapter = CxxMemoryAnalyzerClient(
            args.cxx_analyzer_url,
            timeout_seconds=args.cxx_analysis_timeout_seconds,
            max_response_bytes=args.cxx_max_response_bytes,
        )
    workspace = RepositoryWorkspace(
        args.repository,
        max_files=args.max_files,
        max_file_bytes=args.max_file_bytes,
        max_total_bytes=args.max_total_bytes,
        ignored_directories=args.exclude_dir,
    )
    try:
        result = RepositoryScanner(
            sast_mode=args.sast,
            dataflow_enabled=args.dataflow == "on",
            cxx_memory_mode=args.cxx_memory,
            cxx_memory_adapter=cxx_memory_adapter,
        ).scan(workspace, repository_key=repository_key)
    except RuntimeError as exc:
        print("scan failed: %s" % exc, file=sys.stderr)
        return 3
    payload = result.to_dict()
    rendered = (
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        if args.format == "json"
        else to_markdown(payload)
    )

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        print("Report written to %s" % output_path)
    else:
        sys.stdout.write(rendered)

    if args.fail_on != "never":
        threshold = SEVERITY_RANK[args.fail_on]
        if any(
            SEVERITY_RANK[item.severity.value] >= threshold
            and (
                not args.verified_only
                or item.verification_state in VERIFIED_STATES
            )
            for item in result.report.findings
        ):
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
