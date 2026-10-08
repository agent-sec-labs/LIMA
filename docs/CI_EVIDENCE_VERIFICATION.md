# 离线 CI 证据校验

`scripts/verify_ci_evidence.py` 将 GitHub Actions 的同一 run/attempt 原始 JSON 转为可复核摘要。它核对 repository、run id、head SHA、event、attempt，检查分页与必需任务，再计算成功、失败、未完成数量。工具只读本地输入，使用 Python 3.11+ 标准库，不调用 GitHub、模型或项目服务，也不修改工作流。

设计及验收映射见 [AUX-CI-EVIDENCE](implementation/AUX_CI_EVIDENCE_2026-10-08.md)。

## 准备证据

使用 GitHub REST 的指定 attempt 端点保存响应为 UTF-8 JSON：

```text
GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}
GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/jobs?per_page=100&page=1
```

任务超过一页时继续获取同一 attempt 的后续页面，并通过多个 `--jobs` 参数传入。工具要求各页 `total_count` 一致、任务 ID 和名称唯一、合并条数等于总数。不要用默认 latest jobs 端点混合不同 attempt，也不要把 GitHub CLI 的简化 view 字段替代 REST 对象。采集期间状态变化导致总数冲突时，重新采集一个一致快照。

官方说明：[workflow run attempt](https://docs.github.com/en/rest/actions/workflow-runs#get-a-workflow-run-attempt)、[attempt jobs 与分页](https://docs.github.com/en/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run-attempt)。

Expected head SHA、event、run id、attempt 应由当前交付对象和运行身份独立确定。必需 job 名称应从当前提交的工作流展开矩阵确定，不从待检查的 jobs 列表反向生成，也不能只列出其中已成功的任务。

## 使用

从仓库根目录执行。下面名称对应 main@caed1b6 的 12 项工程任务；将占位符替换为本次明确的运行身份。后续工作流发生变化时要调整必需名称，工具不硬编码这个列表。

```powershell
python scripts/verify_ci_evidence.py `
  --run output/ci-run-attempt.json `
  --jobs output/ci-jobs-page-1.json `
  --repository agent-sec-labs/LIMA `
  --run-id <run-id> --head-sha <40位小写SHA> `
  --event pull_request --attempt <attempt> `
  --required-job quality-contracts `
  --required-job unit-ubuntu-latest-py3.11 `
  --required-job unit-ubuntu-latest-py3.12 `
  --required-job unit-windows-latest-py3.11 `
  --required-job unit-windows-latest-py3.12 `
  --required-job repair-constraints `
  --required-job container-read-only `
  --required-job security-baseline `
  --required-job frontend-tests `
  --required-job frontend-e2e `
  --required-job cxx-sidecar-integration `
  --required-job merge-gate `
  --output output/ci-snapshot-report.json
```

标准输出为 JSON；`--output` 可选，仅创建新文件，父目录须已存在。输出与任一输入解析到同一路径、输出已存在（含符号链接）或写入失败时退出 2，保留已有证据。无效输入只在标准输出给出固定类别和结构位置，不把原始值、异常文本、路径或未知字段转抄到诊断。报告中仅展示经过校验的运行/任务元数据；不载入或输出任务日志、steps、凭据或源码。

每文件最大 8 MiB、全部输入共 32 MiB、最多 100 页/10000 任务。JSON 重复键、NaN/Infinity、非法 UTF-8、过深 JSON 和类型错误均拒绝，不用默认值修补缺失身份。

## 解释结果

| decision / exit | 含义 |
|---|---|
| pass / 0 | 当前提供的完整快照中，必需任务齐全，所有观测任务及 run 均成功 |
| fail / 1 | 快照完整且已结束，但 run 或至少一个任务非 success |
| invalid / 2 | 绑定、格式、状态、唯一性、预算、参数或 IO 校验失败 |
| incomplete / 3 | 缺页、缺必需任务或 run/job 未结束；可同时含已知失败 |

`success + failed + pending == total`。skipped、neutral、cancelled、timed_out 等非 success 的完成结果全部计入 failed。额外观测到的任务也必须成功，不能因未列入 required jobs 而隐藏其失败。任何 job 不能省略 `run_attempt` 或借用 run 字段补值。重复任务名称拒绝，避免将同名不同任务当作满足一个必需 gate。

只重跑失败任务的 attempt 可能不包含之前成功的必需任务；工具会如实返回 incomplete，不跨 attempt 拼接“全绿”。若需要采纳旧成功证据，必须另有审查过的复用规则；本版本没有这种规则。

`source_sha256` 记录本次本地输入文件的原始字节摘要和长度，用于复算；它不认证文件来自 GitHub。摘要记录的是保存后的文件字节，JSON 重排或空白变化会改变摘要。

pass 只表达离线 CI 快照完整成功，不授予合并许可。它不验证当前远端 head、新鲜度、branch rules、review、对话解决、实际 checkout 的合成 merge SHA/base 组合、post-merge 或真实模型能力。run 的 head SHA 保留为 API 身份，不能当作实际测试 checkout SHA；checkout lineage 需要另读日志并单独审查。

## 验证开发修改

```powershell
python -B -m unittest -v tests.test_ci_evidence tests.test_ci_contract
python -m ruff check scripts/verify_ci_evidence.py tests/test_ci_evidence.py
python -m bandit -q scripts/verify_ci_evidence.py
git diff --check
```

沙箱若限制系统临时目录写入，可在测试进程内把 `tempfile.tempdir` 指向本任务可写临时目录；不修改产品或测试断言。
