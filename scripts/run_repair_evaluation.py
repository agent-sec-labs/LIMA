"""Run the deterministic CWE repair constraint benchmark."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from lima.repair_evaluation import RepairConstraintEvaluator, load_repair_dataset


def markdown(result: dict) -> str:
    metrics = result["metrics"]
    lines = [
        "# LIMA 修复约束评测",
        "",
        "- 数据集：`%s`" % result["dataset"],
        "- SHA-256：`%s`" % result["dataset_sha256"],
        "- 范围：`%s`" % result["scope"],
        "- 用例：%d（应修 %d / 应拒 %d）" % (
            metrics["cases"], metrics["repair_cases"], metrics["abstain_cases"],
        ),
        "",
        "| 指标 | 结果 |",
        "|---|---:|",
        "| 验证修复率 | %.2f%% |" % (metrics["verified_repair_rate"] * 100),
        "| 正确拒修率 | %.2f%% |" % (metrics["correct_abstention_rate"] * 100),
        "| 约束准确率 | %.2f%% |" % (metrics["constraint_accuracy"] * 100),
        "| Oracle 通过率 | %.2f%% |" % (metrics["oracle_pass_rate"] * 100),
        "| 不安全补丁逃逸率 | %.2f%% |" % (metrics["unsafe_patch_escape_rate"] * 100),
        "| 平均耗时 | %.3f ms |" % metrics["latency_ms_mean"],
        "| P95 耗时 | %.3f ms |" % metrics["latency_ms_p95"],
        "",
        "## CWE 分组",
        "",
        "| CWE | 用例 | 通过 | 约束准确率 |",
        "|---|---:|---:|---:|",
    ]
    for cwe, values in result["by_cwe"].items():
        lines.append("| %s | %d | %d | %.2f%% |" % (
            cwe, values["cases"], values["passed"],
            values["constraint_accuracy"] * 100,
        ))
    lines.extend(["", "## 失败分类", ""])
    lines.append(
        json.dumps(result["failure_categories"], ensure_ascii=False, sort_keys=True)
    )
    lines.extend(["", "## 有效性边界", ""])
    lines.extend("- " + item for item in result["limitations"])
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate constrained security repairs.")
    parser.add_argument(
        "--dataset", default=os.path.join(ROOT, "evaluation_data", "security_repair_cases.json")
    )
    parser.add_argument("--output", default="")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--min-constraint-accuracy", type=float, default=1.0)
    args = parser.parse_args(argv)
    result = RepairConstraintEvaluator().run(load_repair_dataset(args.dataset))
    rendered = (
        json.dumps(result, ensure_ascii=False, indent=2) + "\n"
        if args.format == "json" else markdown(result)
    )
    if args.output:
        target = Path(args.output).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")
        print("Repair evaluation written to %s" % target)
    else:
        sys.stdout.write(rendered)
    return int(result["metrics"]["constraint_accuracy"] < args.min_constraint_accuracy)


if __name__ == "__main__":
    raise SystemExit(main())
