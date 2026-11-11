# LIMA 全局复审修复记录（2026-11-09）

对应 `LIMA_GLOBAL_AUDIT_2026-11-09.md` 的 F1/F2/F3。本次修改在本地工作区，尚未提交或推送。保留此前修复及用户已有改动。

## 改动

### F1：审计 diff 绑定不可变来源

- GitHub 客户端新增 `fetch_diff_at_commits`，严格校验仓库标识和完整小写 40 位 base/head SHA，使用固定提交的 compare API 并限制读取字节数。无法获取时不回退到 PR diff URL。
- worker 使用任务保存的提交对；diff 内容、摘要、字节数及 `pinned-compare-v1` 来源标记在一个数据库事务内保存。SQLite 与 PostgreSQL 共用逻辑，后者使用 JSONB 参数和行锁。
- 已缓存旧可变 diff 或旧 checkpoint 的任务不能通过恢复流程补出可信来源，必须创建新审计。修复发布也拒绝没有来源标记的旧报告，错误为 `repair-source-unverified`。

### F2：Webhook 持久投递恢复

- 新增 `webhook_outbox` 表。delivery claim、task、队列 payload 和 delivery→task 关联一起提交；任一步失败则整笔回滚。
- 入队成功才标记 dispatched。入队失败、应答丢失或 dispatched 写入失败时保留待投递记录；重投沿用同一 task_id，不创建新逻辑任务。
- 服务启动及运行期间每两秒尝试恢复待投递记录。维护线程随队列关闭而停止，并在关闭执行器前等待维护线程退出。
- 并发请求在数据库中绑定同一个任务；同进程 dispatcher 串行工作。多个服务实例或应答丢失仍可能重复投递同一 task，沿用队列的至少一次语义。本次没有实现整个任务系统的执行权 fencing，不能宣称所有副作用恰好执行一次。
- 无效 SHA、缺少授权等请求在持久 admission 前拒绝，避免先占用 delivery。旧版未完成且 task_id 为空的 claim 可由合法重投恢复；以前失去关联的孤立任务不会被自动删除。

数据库初始化自动新增 outbox 表，无需手工改库。Redis 持久队列适用于生产投递恢复；内存队列在确认接收后仍不是跨进程持久队列，outbox 不改变这个边界。

### F3：PR 最后阶段的取消门禁

`ReviewHarness` 改用已有的 `succeed_unless_cancelled`，原子决定是否保存成功报告。取消获胜时抛出 `RuntimeCancelled`，进入现有取消终态处理，不返回报告供后续评论发布使用。SQLite 和 PostgreSQL 均已有对应原子提交实现。

## 验证

新增回归先在修复前暴露缺陷，再验证修复结果。覆盖固定提交取 diff、非法 ref/仓库标识、原始复现、并发重投、队列应答丢失、数据库确认失败、事务回滚、持久记录重开、服务启动自动恢复、维护线程失败重试及关闭、旧报告/旧 checkpoint 拒绝，以及最终节点与原子写入前取消。

最新聚焦验证：91 项通过，25.092 秒，无失败。日志：`output/lima-global-fixes-2026-11-09/focused.log`。命令：

```powershell
python -m unittest tests.test_webhook_delivery_recovery tests.test_repair_publication_service tests.test_pinned_diff tests.test_pr_final_cancellation tests.test_service tests.test_production_features tests.test_task_failure tests.test_repository_scan_cancellation -q
```

全量验证：3,764 项，42 跳过、1 项 error，440.085 秒。日志：`output/lima-global-fixes-2026-11-09/full-suite.log`。唯一错误：

```text
test_cxx_analyzer.SourceScanContainerTests.test_fixture_manifest_is_complete_and_semgrep_marks_only_candidates
subprocess.TimeoutExpired: semgrep scan ... timed out after 30 seconds
```

该项单独复跑仍在 30 秒超时。对应测试和 `cxx_analyzer/rules/cxx-memory.yml` 无本地修改，没有为通过测试增加超时或跳过规则。不能将本轮称为全量全绿。全量运行之后新增的启动恢复、数据库确认失败和旧 checkpoint 回归已包含在上面的最新 91 项聚焦运行中。

新模块及新增测试的 Ruff 检查通过，修改的 Python 文件编译检查通过，`git diff --check` 无空白错误（有此前 verifier 的换行提示）。既有大文件有原有 lint 问题，未进行无关格式化。

## 验收范围

本地验证使用真实 SQLite、真实 Harness/Runtime，以及用于模拟外部网络失败的队列/GitHub 替身；启动恢复测试运行真实 ReviewService 和内存队列。未连接真实 PostgreSQL/Redis/GitHub 做故障切换或 fork compare 验收，没有远程写入。PostgreSQL 共用实现已检查，但不将它等同于实机数据库验收。

此前 Docker 成功路径验收缺口仍保留，本次未重启 Docker、改部署权限或调用真实模型。11-09 原始探针文件保留为历史复现，不作为修复后预期；修复后的行为以测试及本记录为准。
