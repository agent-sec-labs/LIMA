# CI 交付证据工具：设计与验收

## 来源与价值

Source Finding 是 [PR #265](https://github.com/agent-sec-labs/LIMA/pull/265) 交付中的人工记录错误：run37721994494/attempt1 应为 pull_request、12 项（10 成功+2 失败），且须区分 attempt2 的继承成功与实际重跑。没有对应的产品 Source Issue；本切片减少维护者重复核对 API 的工作，不认领 #264 的能力验收，不改变 Audit → Mining → Verified Repair 目标。

2026-10-08 用户先授权隔离辅助开发，随后要求补齐实际入口并提交独立 PR。独立 codex/aux-ci-evidence-2026-10-08 分支从 caed1b6 开始，交付前整合 PR265 已合并的 main@7956e360。既有 lima/、frontend/、.github/、依赖和冻结测试只读；只新增两脚本、两测试、两说明，在 CONTRIBUTING 链接入口。

## 最小设计

- `ExpectedRun` 由交付对象独立给出 repo/run/head/event/attempt/required names；`verify_snapshot` 是无副作用纯函数。离线 CLI 采用有界严格 JSON 读取及独占输出创建。
- 公开采集 CLI 保存 run 和全部 attempt-jobs 页原始字节，再复用同一校验逻辑。固定 api.github.com HTTPS GET，默认 TLS 证书校验，无凭据/重定向/远端写；请求、采集期限和输入大小有界。中途失败保留部分证据，不制造成功报告。
- 默认沿用现有 merge-gate，不复制矩阵或新增政策。显式名单必须含 merge-gate；所有观察任务仍须成功。
- 拒绝错身份、页间冲突、重复任务、缺失标识及非法状态/类型/JSON；缺页/任务/未结束为 incomplete，非 success 为 fail，完整全成功为 pass。退出码依次为 2/3/1/0。
- 输入 SHA256 用于复算。继承成功按指定 attempt 的明确身份接纳，不宣称全量重新执行。不转抄 steps/未知字段，不推断 checkout 拓扑或 merge readiness。

## 验收映射

| 行为 | 测试或实际验证 |
|---|---|
| 成败统计与额外失败/skipped/neutral | test_exact_counts_and_failed_jobs、test_non_success_conclusions_fail_closed、test_run_failure_and_extra_failed_job_prevent_pass |
| 运行/任务身份严格绑定 | test_binding_mismatches_rejected、test_mixed_job_identity_rejected |
| 缺页、重复任务、缺 gate 不产生 pass | test_missing_page_incomplete、test_duplicate_jobs_rejected、test_default_aggregate_gate_is_required_even_without_name_arguments |
| 一条命令保存可离线复算的原始字节 | test_one_command_saves_replayable_raw_responses_and_report |
| 完整分页与错误工作流拒绝 | test_all_pages_are_collected_from_the_same_attempt、test_wrong_workflow_or_identity_stops_before_jobs |
| 正确接纳重跑继承证据 | test_inherited_success_is_valid_but_never_claimed_as_rerun |
| HTTP/预算/超时/覆盖边界 | DownloadTests、test_existing_evidence_is_preserved_without_requests、CliTests |
| 真实历史失败/成功一致 | PR265 run37721994494 attempt1→12/10/2/fail，attempt2→12/12/0/pass |

## 留痕与验证口径

本机计划、原始响应、命令、日志和自查保留于 output/aux-ci-evidence-2026-10-08/；过程产物不进入 PR。最初离线提交 22fcf7c 的 31 项验证保留为历史；补充实际入口后重新验证。

普通测试不联网，现有 unittest CI 自动发现新测试。作者自查不冒充独立第三方审核，最终 CI 必须绑定本 PR 实际 head。工具不替代模型验收、产品安全裁决、合并授权或 Issue 闭环。
