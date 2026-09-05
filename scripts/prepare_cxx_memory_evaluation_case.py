#!/usr/bin/env python3
"""Emit one validated public C/C++ case's trusted Sidecar argv as CI outputs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from run_cxx_memory_evaluation import (
    _reject_duplicate_keys,
    select_evaluation_cases,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    document = json.loads(
        args.cases.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
    )
    case = select_evaluation_cases(document, args.case_id)[0]
    values = {
        "case_id": case["id"],
        "build_steps_json": json.dumps(case["build_steps"], separators=(",", ":")),
        "test_steps_json": json.dumps(case["test_steps"], separators=(",", ":")),
    }
    with args.github_output.open("a", encoding="utf-8", newline="\n") as output:
        for name, value in values.items():
            output.write(f"{name}={value}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
