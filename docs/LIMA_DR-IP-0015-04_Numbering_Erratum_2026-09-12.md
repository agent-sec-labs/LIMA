# DR-IP-0015-04 · 记录性编号勘误（2026-09-12）

> 文档类型：Decision Record / Erratum（记录性，不改变任何契约）
>
> 签发：Maintainer 编号裁定（2026-09-12），Coordinator 落盘，主会话执行
>
> 适用：Issue #94 工作轨道全部历史与在途文档

## 1. 裁定正本（Maintainer 2026-09-12）

1. 全局编号正式固定：**IP-0015 = Issue #94**（Evidence Privacy S1-Core）；**IP-0016 = Issue #60**（Repository Profile Layer 1）。
2. 两个当前 IP 继续并行，不暂停、不回滚、不重新冻结现有测试。
3. #94 文档中把未来内容适配写为 "IP-0016"、把 vault/审计写为 "IP-0017"，属提前占号造成的规划性编号错误，统一解释为：
   - 原 "IP-0016" → **#94-S2（Content Conformance，全局编号待分配）**
   - 原 "IP-0017" → **#94-S3（Vault/Audit，全局编号待分配）**
4. 未来 IP 不得在路线图阶段预占具体全局编号；Issue 正文与 Packet 只能使用本地阶段名（如 #94-S2 Content Conformance、#94-S3 Vault/Audit、#60-S2 RAM Facts）。
5. 只有某个新 Packet 正式启动时，Coordinator 才检查 #60/#94 双边 Registry 与远端分支，**原子分配下一个空闲全局编号**。
6. 本勘误为记录性，不改变 IP-0015 当前范围、接口、断言或文件边界，**不触发重新冻结**。
7. 本勘误完成前禁止创建新的 IP-0017 分支、worktree、Assignment 或 PR；当前 IP-0015 与 IP-0016 可继续执行。

## 2. 解释映射表（覆盖 #94 轨道全部历史文档）

| 出现位置（历史原样保留） | 原文写法 | 统一解释 |
|---|---|---|
| IP-0015 Packet §5 Not-covered / 附录 A/B 归属标注 / §10 后续序列 | IP-0016 | #94-S2（编号待分配） |
| IP-0015 Packet §5 / 附录 B / §10 后续序列 | IP-0017 | #94-S3（编号待分配） |
| DR-IP-0015-02 裁定文本（COORD-IP0015-TESTS_FROZEN_REVIEW / Ledger 已同步修订） | 细化归属 IP-0016 | 细化归属 #94-S2（编号待分配） |
| DR-IP-0015-03 勘误文档 | 涉及后续 IP 的表述 | 按 #94-S2 / #94-S3 解释 |
| COORD-IP94-R1 裁定 §C.5 后续序列（.pv_tmp 本地证据） | IP-0016/IP-0017 方向 | #94-S2 / #94-S3 方向 |

历史文档原文不作追溯改写（证据不可变）；上述位置的自即日起新增文本一律使用本地阶段名。

## 3. 编号分配协议（自此生效）

- 路线图/Issue/Packet 阶段：仅本地阶段名；
- 新 Packet 正式启动时：Coordinator 核对 #94 Ledger IP registry、#60 对应 registry、远端分支命名与开放 PR 中的 IP 编号占用，原子分配 `IP-00XX` 下一个空闲号并登记后才能派发；
- 主会话派发记录同步登记占用（延续 F2 处置惯例）。

## 4. 影响声明

- IP-0015 已于 PR #155 合并（merge commit `e895079a1b43980bc35532bfd46c5cdbd8d3cae2`），其范围、接口、断言、文件边界均不受本勘误影响；
- 本勘误经 docs PR 入库（本 PR）；#94 Delivery Ledger 已由主会话按同一裁定同步修订（Planned IP 列与 closure gates 列改用 #94-S2/#94-S3）；
- 禁令（裁定第 7 条）自本 PR 合并起解除；解除前任何新 IP 分支/worktree/Assignment/PR 不得创建。
