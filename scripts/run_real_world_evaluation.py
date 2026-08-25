"""Fetch or evaluate fixed-SHA real-world security cases."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lima.config import Settings
from lima.real_world_evaluation import (
    LLMSecurityTriageClient,
    RealProjectOracleRunner,
    RealWorldSecurityEvaluator,
    SnapshotStore,
    load_real_world_dataset,
)
from lima.repository_scanner import RepositoryScanner


def markdown(result: dict) -> str:
    metrics = result.get("metrics", {})
    lines = [
        "# LIMA 真实项目成对评测",
        "",
        "- 数据集：`%s`" % result["dataset"],
        "- 数据集 SHA-256：`%s`" % result["dataset_sha256"],
        "- 清单 SHA-256：`%s`" % result.get("manifest_sha256", "not-recorded"),
        "- 评测角色：`%s`" % result.get("evaluation_role", "development"),
        "- 分析器 SHA-256：`%s`" % (result.get("analyzer") or {}).get(
            "sha256", "not-recorded"
        ),
        "- 分析器冻结匹配：`%s`" % (result.get("analyzer") or {}).get(
            "frozen_match", "not-applicable"
        ),
        "- 模式：`%s`" % result.get("mode", "fetch"),
        "- 扫描档位：`%s`" % result.get("scanner_profile", "not-applicable"),
        "- 范围：`%s`" % result.get("scope", "pinned snapshot acquisition"),
        "",
    ]
    if "snapshots" in result:
        lines.extend(["| 快照 | SHA-256 | 缓存命中 |", "|---|---|---:|"])
        for item in result["snapshots"]:
            lines.append("| %s/%s | `%s` | %s |" % (
                item["case_id"], item["revision"], item["archive_sha256"], item["cache_hit"],
            ))
        return "\n".join(lines) + "\n"
    if result.get("mode") == "oracle":
        oracle_metrics = result["metrics"]
        lines.extend([
            "| 指标 | 结果 |", "|---|---:|",
            "| 用例数 | %d |" % oracle_metrics["cases"],
            "| 已配置 Oracle 覆盖 | %.2f%% |" % (
                oracle_metrics["configured_oracle_coverage"] * 100
            ),
            "| 已执行 Oracle 覆盖 | %.2f%% |" % (
                oracle_metrics["executed_oracle_coverage"] * 100
            ),
            "| 成对 Oracle 通过率 | %.2f%% |" % (
                oracle_metrics["paired_oracle_pass_rate"] * 100
            ),
            "| 耗时 | %.3f s |" % oracle_metrics["duration_seconds"],
        ])
        return "\n".join(lines) + "\n"
    lines.extend([
        "| 指标 | 结果 |",
        "|---|---:|",
        "| 用例数 | %d |" % metrics["cases"],
        "| 漏洞版本已知文件召回率 | %.2f%% |" % (metrics["vulnerable_detection_recall_at_known_file"] * 100),
        "| 修复版本已知文件特异度 | %.2f%% |" % (metrics["fixed_pair_specificity_at_known_file"] * 100),
        "| 确定性成对区分率 | %.2f%% |" % (metrics["paired_discrimination_rate"] * 100),
        "| 验证证据率 | %.2f%% |" % (metrics["verified_evidence_rate"] * 100),
        "| 验证补丁率 | %.2f%% |" % (metrics["verified_patch_rate"] * 100),
        "| 上游语义 Oracle 执行覆盖 | %.2f%% |" % (metrics["executed_project_oracle_coverage"] * 100),
        "| 上游语义 Oracle 成对通过率 | %.2f%% |" % (metrics["paired_project_oracle_pass_rate"] * 100),
        "| LLM API 成功率 | %.2f%% |" % (metrics["llm_api_success_rate"] * 100),
        "| LLM 输出契约有效率 | %.2f%% |" % (metrics["llm_contract_valid_rate"] * 100),
        "| 候选符号 Recall@K | %.2f%% |" % (metrics["retrieval_vulnerable_symbol_recall_at_k"] * 100),
        "| 漏洞版风险不变量召回率 | %.2f%% |" % (metrics["invariant_vulnerable_risk_recall"] * 100),
        "| 修复版缓解不变量命中率 | %.2f%% |" % (metrics["invariant_fixed_mitigation_rate"] * 100),
        "| LLM 当前评测范围成对区分率 | %.2f%% |" % (metrics["llm_paired_discrimination_at_evaluation_scope"] * 100),
        "| 扫描平均耗时 | %.3f ms |" % metrics["scan_latency_ms_mean"],
        "| LLM 平均耗时 | %.3f ms |" % metrics["llm_latency_ms_mean"],
        "",
        "## 逐例结果",
        "",
        "| 用例 | CWE | 确定性漏洞命中 | 修复版干净 | Oracle | LLM 成对正确 |",
        "|---|---|---:|---:|---:|---:|",
    ])
    for case in result["cases"]:
        lines.append("| %s | %s | %s | %s | %s | %s |" % (
            case["id"], case["cwe"], case["deterministic"]["vulnerable_hit"],
            case["deterministic"]["fixed_clean"], case["oracle"]["paired_pass"],
            None if case["llm"] is None else case["llm"]["paired_correct"],
        ))
    lines.extend(["", "## 失败分类", "", "```json", json.dumps(
        result["failure_categories"], ensure_ascii=False, indent=2
    ), "```", "", "## 有效性边界", ""])
    lines.extend("- " + item for item in result["limitations"])
    return "\n".join(lines) + "\n"


def _llm_client() -> LLMSecurityTriageClient:
    settings = Settings.from_env()
    resolved = settings.resolved_llm()
    if not resolved:
        raise ValueError(
            "LLM mode is not configured; set LIMA_LLM_PROVIDER and its API key"
        )
    return LLMSecurityTriageClient(
        base_url=str(resolved["base_url"]), api_key=str(resolved["api_key"]),
        model=str(resolved["model"]), provider=str(resolved["provider"]),
        extra_headers=dict(resolved.get("headers") or {}),
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run pinned real-world security evaluation.")
    parser.add_argument(
        "--dataset", default=str(ROOT / "evaluation_data" / "real_world_security_cases.json")
    )
    parser.add_argument("--cache", default=str(ROOT / "output" / "real-world-cache"))
    parser.add_argument("--output", default="")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument(
        "--mode", choices=(
            "fetch", "deterministic", "retrieval", "llm", "llm-retrieval", "oracle"
        ),
        default="deterministic",
    )
    parser.add_argument("--dataflow", choices=("on", "off"), default="on")
    parser.add_argument("--run-oracles", action="store_true")
    args = parser.parse_args(argv)

    dataset = load_real_world_dataset(
        args.dataset, allow_unpinned_archives=args.mode == "fetch"
    )
    evaluator = RealWorldSecurityEvaluator(
        SnapshotStore(args.cache),
        scanner=RepositoryScanner(sast_mode="off", dataflow_enabled=args.dataflow == "on"),
        oracle_runner=RealProjectOracleRunner(ROOT / "scripts" / "run_real_project_oracle.py"),
        llm_client=_llm_client() if args.mode in {"llm", "llm-retrieval"} else None,
    )
    if args.mode == "fetch":
        result = evaluator.fetch(dataset)
    elif args.mode == "oracle":
        result = evaluator.run_oracle_matrix(dataset)
    else:
        result = evaluator.run(dataset, mode=args.mode, run_oracles=args.run_oracles)
    rendered = (
        json.dumps(result, ensure_ascii=False, indent=2) + "\n"
        if args.format == "json" else markdown(result)
    )
    if args.output:
        target = Path(args.output).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")
        print("Real-world evaluation written to %s" % target)
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
