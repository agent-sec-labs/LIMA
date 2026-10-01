"""Thin CLI entry for the fixed-SHA LlamaFactory local baseline (IP-0043).

One command runs the fully offline 3 cold + 5 warm local scanner suite over
the sealed LlamaFactory snapshot pinned at commit
``7fcf5b3b130e5713b52415bb7404c476fada9c8c`` (zero model calls, zero
network, zero credentials).  The source binding is a schema-v1 JSON
document declared by the operator; the machine profile is declared
explicitly (never probed) through ``--machine-profile``; the suite itself
is implemented by ``benchmarks.v4.baseline.lf_baseline``.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.v4.baseline.lf_baseline import (  # noqa: E402
    LF_WORKLOAD,
    run_lf_local_baseline_suite,
)


def build_parser() -> argparse.ArgumentParser:
    """The frozen flag surface of the LF local baseline CLI."""
    parser = argparse.ArgumentParser(
        prog="run_lf_baseline.py",
        description=(
            "Run the offline fixed-SHA LlamaFactory local baseline suite "
            f"({LF_WORKLOAD}); zero model calls, zero network, zero credentials."
        ),
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="empty directory that receives the run artifact family",
    )
    parser.add_argument(
        "--source-root",
        required=True,
        help="path to the sealed LlamaFactory source tarball (read-only reuse)",
    )
    parser.add_argument(
        "--binding",
        required=True,
        help="path to the run-specific schema-v1 source-binding JSON document",
    )
    parser.add_argument(
        "--machine-profile",
        default=None,
        help="path to the declared eight-field machine-profile JSON document",
    )
    parser.add_argument(
        "--cold-count", type=int, default=3, help="cold attempt count (default 3)"
    )
    parser.add_argument(
        "--warm-count", type=int, default=5, help="warm attempt count (default 5)"
    )
    parser.add_argument("--seed", type=int, default=0, help="run seed (default 0)")
    return parser


def _load_json(path: str) -> object:
    return json.loads(pathlib.Path(path).read_bytes().decode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    """Parse the frozen flag surface, run the suite, print the result faces."""
    args = build_parser().parse_args(argv)
    if args.machine_profile is None:
        print(
            "--machine-profile is required: the declared eight-field machine "
            "profile is never probed from the host",
            file=sys.stderr,
        )
        return 2
    binding = _load_json(args.binding)
    machine_profile = _load_json(args.machine_profile)
    result = run_lf_local_baseline_suite(
        output_dir=args.output_dir,
        machine_profile=machine_profile,
        source_root=args.source_root,
        binding=binding,
        cold_count=args.cold_count,
        warm_count=args.warm_count,
        seed=args.seed,
    )
    print(f"workload: {result.workload}")
    print(f"run_spec_digest: {result.run_spec_digest}")
    print(f"attempt_count: {result.attempt_count}")
    print(f"status: {result.status}")
    print(f"scanner_executions: {result.scanner_executions}")
    print(f"materializations: {result.materializations}")
    print(f"model_calls: {result.model_calls}")
    print(f"aggregate_path: {result.aggregate_path}")
    print(f"aggregate_sha256: {result.aggregate_sha256}")
    print(f"report_path: {result.report_path}")
    print(f"binding_path: {result.binding_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
