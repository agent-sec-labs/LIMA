# AUX-CI-EVIDENCE：离线 GitHub Actions 证据校验切片

授权：2026-10-08 用户要求开展与 ZCode 无冲突的辅助开发并完成自查。此开发工具补充交付证据，产品 NOW 仍为 PR #265，不激活新的产品 Issue。

## 问题与设计

人工记录可能漏计失败任务、误写事件类型，或把不同 SHA/attempt 的成功检查拼接。工具接受显式预期身份和 GitHub REST run/attempt-jobs 原始 JSON，校验身份及页面完整性，计算同一 attempt 的准确统计。

输入合同：ExpectedRun(repository, run_id, head_sha, event, attempt, required_jobs)，required_jobs 为当前工作流展开后的必需名称，必须显式提供且含 merge-gate。verify_snapshot(run, job_pages, expected) 为无副作用纯函数。重复 ID、重复名称、错 repository/run/SHA/event/attempt、矛盾状态、非法类型或未知 conclusion 产生 EvidenceError；缺页、缺任务、运行中返回 incomplete；完整已完成但任一非 success 返回 fail；完整且所有任务和 run 为 success 返回 pass。

CLI 只读取调用者指定文件（每个文件最多 8 MiB、最多 100 页、最多 10000 jobs）。拒绝重复 JSON 键、NaN/Infinity、非 UTF-8、深层解析失败。标准输出为 JSON；可选 --output 仅创建新文件，不覆盖旧证据，不允许与输入同路径；异常诊断只打印固定类别/位置，不转抄错误值。

Exit 0=pass、1=fail、2=invalid/usage/IO、3=incomplete。所有结论限于离线快照，不能替代远端状态、merge policy/reviews 或真实模型证据。run.head_sha 不等于 checkout 合成 merge SHA，工具不推断 actual checkout。摘要 SHA256 绑定输入字节，用于复现，不证明文件真实性或远端新鲜度。

## 文件与角色边界

只新增 scripts/verify_ci_evidence.py、tests/test_ci_evidence.py、本文件及 docs/CI_EVIDENCE_VERIFICATION.md。现有 frontend/、.github/、lima/ 和测试只读。独立分支 codex/aux-ci-evidence-2026-10-08，base caed1b6702f1de05f366e089c39118220f363c9a，worktree 位于 output/aux-ci-evidence-2026-10-08/worktree。

本轮为同一会话测试与自查，没有独立第三方审核，不声称满足 P&V 的独立验证或 READY-FOR-MERGE。

## 验收

| AC | 行为 | 测试/证据 |
|---|---|---|
| A1 | 统计自洽，不把 failure/skipped/neutral 当 success | test_exact_counts_and_failed_jobs、test_non_success_conclusions_fail_closed |
| A2 | 严格绑定 repo/run/SHA/event/attempt | test_binding_mismatches_rejected、test_mixed_job_identity_rejected |
| A3 | 分页完整、去混合、重复/漏页拒绝 | test_multi_page_success、test_missing_page_incomplete、test_duplicate_jobs_rejected |
| A4 | pending/缺任务不产生全绿 | test_pending_and_missing_required_incomplete |
| A5 | 类型、JSON、读取预算、输出安全 | CLI integration tests，含 duplicate keys、NaN、覆盖拒绝、超限读取 |
| A6 | 实际 PR265 失败证据准确复算 | 本机 run37721994494 attempt1 → 12 total / 10 success / 2 failed |
| A7 | 不冲突、无权限/依赖/费用扩张 | allowlist 差分、ZCode branch 只读快照、Ruff/Bandit/现有 CI 合同回归 |

原始证据、完整命令和日志保留于 output/aux-ci-evidence-2026-10-08/。最终验证与限制写在本文件末尾。

## 实现与最终验证

新增公共入口：ExpectedRun、EvidenceError、verify_snapshot、main；内部包含严格对象/类型/绑定/状态检查、有界 JSON 读取、重复键拒绝、来源字节摘要、独占输出创建。未新增依赖、网络或模型调用，没有既有产品行为变更。

2026-10-08 Windows / Python 3.12.4：25 项新增测试 + 6 项既有 CI 合同回归共 31/31 通过（0 failed、0 skipped）；Ruff 0.16.5 和 Bandit 1.9.4 通过；两文件编译及 Python 3.11 语法解析通过；cached git diff --check 通过。

真实离线回放：run37721994494 / attempt1 / pull_request / head a1666f06282ed15847518c2653ddd6fac26dbcb3 → fail，退出 1（预期），12 total = 10 success + 2 failed + 0 pending，失败 frontend-tests/merge-gate。该回放检查历史快照，不能声称当前 PR CI 仍失败。

文件边界验证：只新增本切片的四文件，与 caed1b6→a1666f06 的 PR265 文件集交集为零；主工作区 tracked 文件未改变，ZCode 的现有 worktree/分支未操作。

自查收口了缺失 conclusion 误归 pending、Path.resolve 的 RuntimeError 分类，并用拒绝路径回归锁定。独立 P&V、Linux/容器、完整产品回归及远端 CI 尚未执行；作者自查不能替代后续全面审核。后续由维护者审查本地独立提交，决定单独工具 PR 或在主线稳定后集成；不修改 PR265 或关闭 Issue。
