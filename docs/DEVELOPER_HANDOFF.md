# LIMA 多 Agent 开发交接入口

> 本文件是角色路由入口，不记录临时 NOW/NEXT。跨 Agent 状态以 Source Issue Delivery Ledger、Coordinator Assignment 和可验证的 Git/GitHub 状态为准；本机 `PROGRESS.md` 只是可选缓存。

## 1. 所有 Agent 共同必读

1. [LIMA 项目定位与开发交接标准](LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md)
2. [Issue → IP → PR → Issue Closure 完整生命周期](LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md)
3. 与自己身份对应的角色责任书
4. `CONTRIBUTING.md`
5. Coordinator Assignment 与 Source Issue Delivery Ledger

若本机存在 `PROGRESS.md`，Agent 可以把它作为恢复线索，但必须对照远端事实核验；新 clone 不要求存在该文件。Coordinator 可从根目录 `PROGRESS.example.md` 创建本机副本。

## 2. 按角色读取

### Coordinator Agent

必读：

- [Coordinator Agent 责任书](LIMA_COORDINATOR_AGENT_RESPONSIBILITY_CHARTER.md)
- 当前 Source Issue、Delivery Ledger、依赖 Issue 和所有上游 PR/evidence
- 当前活动/候选 Packet，只用于分配和状态控制
- 可选的本机 `PROGRESS.md`；缺失时从 Delivery Ledger 和 Git/GitHub 重建

Coordinator 不编写产品代码或冻结测试。它负责 Issue 分解、队列、Owner、合并决策、post-merge 调度和最终 Issue Closure Audit。

### Packet & Verification Agent

必读：

- [Packet & Verification Agent 责任书](LIMA_PACKET_AND_VERIFICATION_AGENT_RESPONSIBILITY_CHARTER.md)
- Coordinator Assignment 指定的 Issue requirement、架构/Decision、上游 IP 和真实 main 代码/测试
- 当前 IP 的 Packet 和正式交接书（制作阶段为自己维护的草案；合并后以 main 版本为准）

P&V Agent 制作 Packet、冻结测试、证明 RED、独立验证 Implementation commit，并形成/推送 PR。它不写产品代码、不合并 PR、不关闭 Issue。

### Implementation Agent

必读：

- [Implementation Agent 责任书](LIMA_IMPLEMENTATION_AGENT_RESPONSIBILITY_CHARTER.md)
- Coordinator Assignment 指定的唯一活动 Packet 与 Frozen Test Commit
- 当前 IP 正式交接书
- Frozen tests/fixture、RED Evidence Record 和 Packet 引用的代码/测试

Implementation Agent 只修改 product-code allowlist，交付 final commit 和 Completion Summary 给 P&V Agent。它不修改 Packet、测试、Issue、PR 或 `PROGRESS.md`。

## 3. 已完成的基础 Packet

- [IP-0001：Contract Foundation](LIMA_Implementation_Packet_IP-0001_Contract_Foundation.md) — PR #98 已合并；恢复切片 IP-0001-R1 经 PR #102 合并
- [IP-0002：Evidence Domain](LIMA_Implementation_Packet_IP-0002_Evidence_Domain.md) — Packet PR #99、Implementation PR #100 已合并
- [IP-0002：正式开发任务交接](LIMA_Coding_Agent_IP-0002_正式开发任务交接.md) — 历史执行输入，只读保留
- [IP-0003：Repository Profile / RAM Foundation](LIMA_Implementation_Packet_IP-0003_Repository_Profile.md) — Packet PR #103、Implementation PR #104 已合并（IP-DONE）
- [IP-0004：Audit Evidence Package(AEP) Foundation](LIMA_Implementation_Packet_IP-0004_AEP_Foundation.md) — Packet PR #105、Implementation PR #107 已合并（IP-DONE）
- [IP-0005：Vulnerability Evidence Package(VEP) Foundation](LIMA_Implementation_Packet_IP-0005_VEP_Foundation.md) — Packet PR #108、Implementation PR #110 已合并（IP-DONE）
- [IP-0006：Repair Verification Report(RVR) Foundation](LIMA_Implementation_Packet_IP-0006_RVR_Foundation.md) — Packet 与 [正式开发任务交接](LIMA_Coding_Agent_IP-0006_正式开发任务交接.md) 冻结中；实现未开始

IP-0001 至 IP-0005 完成以及 IP-0006 的 Packet 合并都不等于 Source Issue #58 完成。#58 只有在 Delivery Ledger 的全部 mandatory requirements、集成/真实运行和 Issue Closure Audit 均通过后才可手工关闭。

## 4. 不可混淆的四个 Gate

- `Packet merged`：规范可被实现 Agent 消费；
- `merge-gate passed`：一个 PR 可以进入 `main`；
- `post-merge verification passed`：一个 IP 可以标记 Done；
- `Issue Closure Audit passed`：整个 Source Issue 才可形成 Closure Record 并手工关闭。

所有 IP PR 一律只关联 Source Issue，不自动关闭。若长期标准、角色责任书、Coordinator Assignment、Delivery Ledger、Packet、代码事实或 Issue 发生冲突，按稳定标准和生命周期的真值优先级停止并提交 Decision Request，不得自行猜测。本机 `PROGRESS.md` 与远端事实冲突时必须重建，不能覆盖远端真值。
