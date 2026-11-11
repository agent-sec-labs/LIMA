# 修复下载预算与发布恢复（2026-11-09）

对应 `LIMA_GLOBAL_PUBLICATION_RECOVERY_AUDIT_2026-11-09.md` 的 F1/P1 和 F2/P2。本次在当前工作区修改，保留已有改动，尚未提交或推送，没有真实 GitHub 写入。

## 下载与规划前预算

- 新增 `GitHubClient.download_archive_file` 上下文接口，默认最多 64 MiB，每次最多读 64 KiB，并在余量处最多多读一个探测字节。实际读取量为准，Content-Length 缺失或虚报也不能绕过上限。
- 归档流式写入服务控制的临时文件；发布验证直接读取该 Path，不先构造完整归档 bytes。正常结束、读取/写入错误、响应关闭失败或验证异常均清理文件。旧 bytes 接口也有默认 64 MiB 上限。
- Contents JSON 上限为 1,000,000 字节，解码后源码上限 512 KiB。消费方在规划前再次检查，累计源码上限 20 MiB；AST 验证也在 parse/compile 前检查。超预算不能进入后续测试或发布。
- 单次最多 299 个修改文件；持久意图和结果 JSON 各最多 32 MiB。发布前预检记录大小并为远端标识预留空间。超预算使用 `repair-input-too-large`。

这些是明确的默认单次预算，不是全服务并发配额，也不是新的下载总耗时硬保证。已有 socket timeout 和只对读取进行的重试继续适用。

## 持久发布操作

SQLite 和 PostgreSQL 初始化新增 `repair_publications` 表。实现保存在 `repair_publication_store.py`：不可变意图、已确认 commit/PR 阶段及首次完成结果分别持久化；事务中处理并发及冲突，不覆盖不同的已记录阶段。PostgreSQL 共用逻辑，使用行锁；本地测试使用真实 SQLite。

操作 ID 绑定租户/任务、仓库/PR、固定 SHA、补丁、repair manifest、验证命令、实际镜像 ID 和验证检查项。分支名由该 ID 决定，取消按当前时间另建分支的行为。首次远端写入前必须成功持久化意图；缺少存储或 scope 的直接发布调用会被阻断。

每次重试仍先通过当前授权、来源和验证门禁。恢复阶段查询稳定 ref，校验父提交和包含操作标记的 message；再以有界的非递归 tree 读取核对完整变化：目标 blob 内容及模式必须符合补丁，其他路径/子树必须保持原 SHA，不能偷偷附加其他改动。该证明不依赖可能很大的 compare 文本 diff。

Draft PR 按稳定 head 查询所有状态并核对仓库、head SHA、base、操作标记和 PR 身份。已确认成果缺失、被改写或产生歧义时返回冲突，不自动重建或覆盖。确认后的同一操作重试不再 POST，返回最初保存的成果。

HTTP 客户端不再对写操作的未知结果盲目重发。发生网络异常或服务端错误后，发布恢复先读取远端状态；未知状态返回 `repair-publication-pending`，冲突返回 `repair-publication-conflict`，两者不会用成功 branch 字段误导管理台。API 审计会关联操作 ID 和结果码。

管理台对待确认情况提示“可能已产生远端改动，请重试同一任务核对”，成功或恢复成功提示“修复发布已确认”。不再把未知结果一律显示为“未创建分支”。

## 恢复边界

稳定分支、持久记录及 GitHub ref/PR 状态用于恢复可见成果；本次不承诺每个 Git 对象恰好创建一次。tree/commit 应答丢失且尚无 ref 时，可能重建不可达对象。已发布分支和 Draft PR 的离线故障夹具收敛为一套成果，不能等同于真实 GitHub 的所有一致性或故障行为已经验收。

权限撤销、来源变化或验证失败仍会阻断，不能通过恢复跳过门禁；持续未知状态或人工修改需核对已保存操作。升级前的时间戳分支没有新操作身份，不会被猜测性认领或自动删除。没有新增后台自动发布任务，待确认操作通过重试同一任务继续核对。

## 验证

先补失败回归，再实施。新增测试涵盖：未知/虚假 Content-Length、读取超预算、解码源码超限、AST/规划前阻断、临时文件异常清理；SQLite 重开与并发合并；tree/commit/ref/PR 各阶段应答丢失；完成结果保存失败；并发重试；远端内容被改写或删除；写请求禁止盲重发；完整树中的非计划改动拒绝；大文本 diff 不影响树核对。

最新聚焦：143 项通过，6.196 秒。日志：`output/lima-publication-recovery-fixes-2026-11-09/focused-final.log`。其中 HTTP 安全负例会有预期的服务端异常日志；测试总结果为 OK。

最终后端全量：3,807 项，42 跳过、无失败或错误，352.945 秒。日志：同目录 `full-suite-final.log`。这是完整树核对及最终代码完成后的验证；较早的 3,802 项运行保留在 `full-suite.log`，不作为最终版本计数。

前端完整验证：11 个文件、88 项通过，51.92 秒。类型检查通过。日志分别为同目录 `frontend-full.log`、`frontend-typecheck.log`。既有 antd/jsdom 样式测量提示不影响通过结果。

离线恢复证据：同目录 `regression_probe.py` / `regression-results.json`。真实 SQLite、真实发布客户端恢复逻辑，HTTP 状态为内存替身，plan/verifier 是专门准备的测试夹具，没有执行真实 Docker：

- 虚报长度的响应按实际字节预算拒绝；
- tree/commit 丢失应答后，重开存储并重试成功；ref/PR 丢失应答可直接查询确认；
- 每个夹具最终只有一个分支和一个 PR；完成后的再次请求 POST 数量不增加。

新模块及新增测试 Ruff 检查通过，Python 编译与 `git diff --check` 通过。原有大文件未做无关整体格式化。真实 GitHub 发布故障、Docker 成功路径和 PostgreSQL/Redis 故障切换仍未实机验收。
