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
from lima.report import to_markdown
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
    args = build_parser().parse_args(argv)
    workspace = RepositoryWorkspace(
        args.repository,
        max_files=args.max_files,
        max_file_bytes=args.max_file_bytes,
        max_total_bytes=args.max_total_bytes,
        ignored_directories=args.exclude_dir,
    )
    try:
        result = RepositoryScanner(
            sast_mode=args.sast, dataflow_enabled=args.dataflow == "on"
        ).scan(workspace)
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
