# CI 证据采集与离线校验

用途：PR 交付或合并后复核时，保存指定 GitHub Actions attempt 的原始记录，自动核对运行身份、完整分页和任务结果，避免漏计或混用证据。来源是 [PR #265](https://github.com/agent-sec-labs/LIMA/pull/265) 的 CI 记录错误；这是开发辅助工具，不是 #264 的真实模型验收或漏洞分析能力。

Python 3.11+，仅标准库，无需 GitHub CLI。从仓库根目录执行。

## 一条命令采集

先从交付提交和 GitHub Actions 页面独立确认 run id、attempt、完整 head SHA 和 event。父目录须已存在，证据目录须为新目录。下面是 PR265 的历史成功记录，可直接执行：

```powershell
python scripts/collect_ci_evidence.py --run-id 37721994494 --attempt 2 --head-sha a1666f06282ed15847518c2653ddd6fac26dbcb3 --event pull_request --evidence-dir output/ci-pr265-attempt2
```

新任务替换身份和目录；main 合并后的运行通常使用 `--event push` 和实际 merge SHA，不能沿用 PR head。`--repository` 默认为 `agent-sec-labs/LIMA`，可指定公开 fork。

采集器只向 api.github.com 发出匿名 HTTPS GET，使用指定 attempt 的 run/jobs 端点，自动获取全部页，并核对 `.github/workflows/ci.yml` 路径。它不读取凭据、跟随重定向、重跑 CI 或修改 GitHub。每请求超时最多 15 秒，整体采集期限 120 秒；超时/网络失败返回 invalid，不自动重试。仅支持公开资源，受匿名 API 限流影响。403/404 等返回固定 HTTP 错误码；可稍后换新目录重试，或自行导出后离线检查。

目录包含 `run.json`、`jobs-1.json`（多页为 jobs-2.json 等）和 `report.json`。响应按原始字节保存。已存在目录拒绝执行；中途失败可能留下部分原始文件，但不会生成成功报告，保留它们排查并改用新目录。

## 离线复算

采集后可断网执行同一身份校验：

```powershell
python scripts/verify_ci_evidence.py --run output/ci-pr265-attempt2/run.json --jobs output/ci-pr265-attempt2/jobs-1.json --repository agent-sec-labs/LIMA --run-id 37721994494 --attempt 2 --head-sha a1666f06282ed15847518c2653ddd6fac26dbcb3 --event pull_request
```

多页时重复 `--jobs`，必须传齐。可加 `--output output/ci-replay.json`；仅创建新文件，拒绝覆盖输入或旧输出。`source_sha256` 可复算原始输入字节。

也可自行导出 UTF-8 JSON：

```text
GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}
GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/jobs?per_page=100&page=1
```

继续导出后续页；不要以默认 latest jobs 或 CLI 简化字段替代原始 attempt 对象。采集期间变化造成页间总数冲突时重新采集。官方 API：[run attempt](https://docs.github.com/en/rest/actions/workflow-runs#get-a-workflow-run-attempt)、[attempt jobs](https://docs.github.com/en/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run-attempt)。

## 结果与边界

| decision / exit | 含义 |
|---|---|
| pass / 0 | 完整快照中，必需任务齐全，所有观察任务及 run 均成功 |
| fail / 1 | 快照完整且已结束，run 或至少一个任务非 success |
| invalid / 2 | 身份、格式、状态、唯一性、预算、参数、网络或 IO 校验失败 |
| incomplete / 3 | 缺页、缺必需任务或 run/job 未结束；可同时含已知失败 |

默认必需名称是现有 `merge-gate` 聚合任务，沿用它对底层工程任务的要求，不另建门禁。所有返回任务均须成功，额外任务失败也不能忽略。需要逐名约束时，两种 CLI 均支持重复 `--required-job`，提供**完整名单并包含 merge-gate**；名单来自待验工作流，不从观察到的成功任务反推。

校验 repository/run id/head SHA/event/attempt；每个 job 的 run_id/run_attempt/head_sha/run_url 必须匹配；每页 total_count 一致、ID/名称不重复、合并条数等于总数。`success + failed + pending == total`；skipped、neutral、cancelled、timed_out 等完成但非 success 的结果均计入 failed。JSON 重复键、NaN/Infinity、非法 UTF-8、缺失身份均拒绝。每输入文件最多 8 MiB，共 32 MiB，最多 100 页/10000 任务。

失败任务重跑可能返回此前成功任务的继承记录。若由**同一指定 attempt 端点**返回，且身份明确绑定本 attempt，可正常纳入快照；这不代表所有任务都重新执行。工具不计算实际重跑数量，也不根据 head SHA 推断 checkout 的 synthetic merge SHA。手工拼入其他 attempt 的记录会被拒绝。

PR265 真实回放：attempt1 → fail，12=10 success+2 failed（frontend-tests/merge-gate）；attempt2 → pass，12 success。这是历史 run 的两个快照，不能据此宣称新分支的 CI 已通过。

pass 仅为 CI 快照结论，不认证手工输入来源，不判断远端 head 新鲜度、branch rules、review、合并资格、checkout/base 拓扑、真实模型能力或产品 Issue 完成度。诊断不转抄原始值、路径或异常文本；摘要不包含 steps/日志。完整原始 JSON 留作本地复算，无须提交到 PR。

## 修改后的验证

```powershell
python -B -m unittest -v tests.test_ci_evidence tests.test_ci_evidence_collection tests.test_ci_contract
python -m ruff check scripts/verify_ci_evidence.py scripts/collect_ci_evidence.py tests/test_ci_evidence.py tests/test_ci_evidence_collection.py
python -m bandit -q scripts/verify_ci_evidence.py scripts/collect_ci_evidence.py
git diff --check
```

普通测试 mock 网络，不需要 GitHub/模型凭据；现有完整 unittest CI 自动发现这些测试。设计及验收映射见 [实现记录](implementation/AUX_CI_EVIDENCE_2026-10-08.md)。
