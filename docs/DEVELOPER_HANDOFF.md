# LIMA 开发者交接入口

> 本路径保留为兼容入口。原文中的历史 Epic/Issue 状态、Issue-first 开工流程和旧代码基线已于 2026-09-01 废止，禁止继续作为开发依据。

Coding Agent 必须按顺序完整阅读：

1. [LIMA 项目定位与 Coding Agent 开发交接标准](LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md)
2. 仓库根目录的 `PROGRESS.md`
3. `PROGRESS.md` 指定的唯一活动 Implementation Packet
4. `CONTRIBUTING.md` 以及 Packet 明确引用的代码与测试

关键规则：

- GitHub Issue 及 `status:ready` 标签不等于 Ready-for-Code。
- 只有完整并被激活的 Implementation Packet 可以直接指导编码。
- 全项目同时最多允许 1 个 NOW、2 个 NEXT。
- 一个 Coding Agent 只消费一个 Packet，并只产出一个独立 PR。
- Coding Agent 不修改 GitHub Issue，也不得关闭仅完成了一个实现切片的 Source Issue。
- 工作树状态、执行队列、当前基线与下一步以本机 `PROGRESS.md` 的当前快照为准。

已完成 Packet：

- [IP-0001：Contract Foundation](LIMA_Implementation_Packet_IP-0001_Contract_Foundation.md)

当前活动 Packet：

- [IP-0002：Evidence Domain](LIMA_Implementation_Packet_IP-0002_Evidence_Domain.md)
- [IP-0002：Coding Agent 正式开发任务交接](LIMA_Coding_Agent_IP-0002_正式开发任务交接.md)

IP-0002 两份文档合并到 `main` 前状态为 `DESIGN-FROZEN / PENDING-DOC-MERGE`，只允许 Review；合并后才满足 Coding Agent 开工的文档可见性 Gate。具体状态仍以本机 `PROGRESS.md` 为准。

若长期标准、`PROGRESS.md`、Packet、代码事实或 Issue 之间发生冲突，必须按长期标准中的真值优先级和 Decision Request 规则暂停并报告，不得自行猜测。
