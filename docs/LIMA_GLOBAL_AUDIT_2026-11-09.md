# LIMA 全局复审：输入身份、任务投递与取消一致性

日期：2026-11-09。基线 HEAD：`fcd098562001d1d610134c86e3a92e15cde1ea72`，另包含当前工作区尚未提交的前几轮修复。本报告针对本地工作区，不能直接代表远程 main 或某个 PR 的状态。

本轮未修改生产代码，没有提交、推送或 GitHub 写入。新增内容仅为本报告和离线复现脚本。结合 README、前几轮修复记录，重点检查审计输入身份、Webhook 到 worker 的交接、修复发布所依赖的来源以及任务终态。没有把文档已声明尚未实现的完整三阶段平台当作当前缺陷。

## 结论

仍有两项 P1 和一项 P2 需要修复。前几轮对构建输入、verified context 和修复 sandbox 的加固不能消除本轮发现的上游输入和任务状态问题。下面三项均已通过本地探针复现；未调用真实 GitHub、Redis 或模型。

## F1 / P1：Webhook 固定了 SHA，实际审阅的 diff 仍会随 PR 更新

位置：`lima/service.py:2424` 保存 head/base SHA；`lima/service.py:2336` 直接调用 `fetch_diff(payload["diff_url"])`；`lima/github.py:69` 的 `fetch_diff` 仅请求传入 URL。

触发过程：Webhook 对应 head A，任务排队期间 PR 更新为 B，worker 随后访问 `/pull/7.diff`。该地址返回当前 PR 内容，并没有绑定保存的 base/head 提交对。worker 保存取得的 diff 与摘要，却保留任务输入中的 A。

离线探针通过真实 `_process_queued` 和 SQLite TaskStore 模拟 URL 返回 B 的 diff：审阅入口接收到 B，保存的 head 仍为 A，也没有检查当前 head。审阅器本身使用捕获输入的替身，本探针证明输入路由错配，不宣称执行了真实模型或发布了错误补丁。

影响：报告与任务保存的提交身份不一致；排队和重新投递时可出现漏报或不属于该提交的发现。新修复发布门禁依赖保存的 head SHA，因此还需要先保证这份报告确实来自该 SHA；不能仅依赖发布时检查当前 head 来补足审计来源证明。

建议：使用保存的 base/head 不可变提交生成 diff，验证并保存其来源身份；fork 场景也必须使用明确的源仓和不可变提交。可变 PR URL 不能作为可发布审计结果的唯一输入依据。测试应覆盖排队期间 head/base 变化及重试恢复。

## F2 / P1：Webhook 入队失败后，同一 delivery 重投不会恢复任务

位置：`lima/service.py:2403` 先 claim delivery，`lima/service.py:2430` 才入队，`lima/service.py:2438` 最后关联 task；`lima/store.py:1204` 持久保存 claim，重复 claim 返回 false。

触发过程：首次 delivery 已写入 claim 和 PENDING 任务，但 Redis XADD 失败。处理抛错后，delivery 仍占用且 task_id 为空。随后 GitHub 对同一 delivery 重投，服务立即返回 `duplicate=true, task_id=null, state=ACCEPTED`，没有再次入队。

探针在真实 `handle_github_pull_request` / SQLite 路径注入一次 `queue.submit` 连接异常，再恢复队列并重投。两次请求合计只调用一次 submit，delivery 记录一直没有 task_id。没有执行真实 Redis 故障切换。

影响：一次短暂队列故障可使该事件对应的审阅一直不执行，重投却返回已接受。delivery 去重阻断了恢复路径。

建议：引入与任务创建共同提交的持久 outbox，或具有可恢复状态、执行权与 task_id 绑定的投递协议。不能仅删除 claim 后盲目重建：还须处理 XADD 已成功但应答丢失、进程崩溃、并发重投和重复投递。验收应同时证明可恢复与不会丢任务。

## F3 / P2：PR 审阅最后一步收到取消，仍可保存 SUCCESS 报告

位置：`lima/harness.py:77` 执行 runtime 后，`lima/harness.py:90` 调用无条件 `store.succeed`；`lima/store.py:392` 的成功写入不检查取消标志。

runtime 只在节点开始前检查取消。若取消发生在最后的 reviewing 节点内，节点返回后不会再经过取消检查，Harness 直接提交成功。与 repository scan 已使用 `succeed_unless_cancelled` 的行为不一致。

探针运行真实 ReviewHarness / LocalRuleReviewer / SQLite，在 reviewing 生成报告后、节点返回前注入取消请求。最终结果：`cancel_requested=true`，状态 `SUCCESS`，报告已保存。这不是在成功之后才发出的取消请求。

影响：用户在任务仍运行时发出的取消请求不能阻止最终报告发布；异步后续流程还可能继续消费该结果。

建议：PR 审阅也采用原子取消条件下的终态提交，并在取消获胜时进入取消路径、阻止后续发布。单纯在 succeed 前加一次独立查询仍留有检查与写入间的竞态。

## 验证记录与范围

复现文件：`output/lima-global-audit-2026-11-09/probes.py`；结果：同目录 `results.json`。复现命令：

```powershell
$env:PYTHONUTF8='1'
python output/lima-global-audit-2026-11-09/probes.py
```

针对现有功能运行：

```powershell
python -m unittest tests.test_github tests.test_service tests.test_production_features tests.test_repair_publication_service tests.test_repair_publication_gates -q
```

结果：53 项通过，16.433 秒，无失败。运行时有现有 TracerProvider 重复初始化提示。现有测试通过不能否定以上新探针。本轮未重跑全量测试；此前全量结果见 2026-11-06 修复报告。

独立只读队列检查还识别了待专项验证的旧执行权问题：Redis 租约失效后旧 handler 没有结果 fencing，过期消息解析异常也未按新消息路径进入 DLQ。本轮未做真实 Redis 重领复现，不把这些静态线索计入上述三项已复现结论。此前报告已明确未完成整个队列 fencing 协议。

Docker 实机成功路径仍是此前留下的验收缺口。本轮没有重启 Docker 或重复运行失败环境探测，也没有将 mock sandbox 测试当作容器验收。修复这三项后，仍需在可用执行节点完成真实构建与修复测试隔离、超时停止及清理的验收。
