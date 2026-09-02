# LIMA Issue → IP → PR → Issue Closure 完整生命周期规范

> 文档类型：稳定交付流程（Stable Delivery Policy）
>
> 版本：`1.0`
>
> 生效条件：本文合并到 `main`
>
> 适用范围：所有由 Coordinator、Packet & Verification、Implementation 三类 Agent 交付的 LIMA 需求
>
> 核心原则：`Issue is a requirement container; IP is an executable slice; PR is a change vehicle; only aggregate evidence can close an Issue.`

## 1. 要解决的流程缺口

LIMA 已经能够制作细粒度 Implementation Packet，但如果缺少 Issue 级聚合约束，会出现四种错误：

1. 一个 IP 完成后被误认为整个 Issue 完成；
2. 多个 IP 分别测试通过，但组合后没有端到端能力；
3. Issue 的部分 FR/AC/NFR 没有被任何 IP 覆盖；
4. PR 使用自动关闭关键字，在 post-merge 和真实运行验证前提前关闭 Issue。

本文将四个对象明确分层：

| 对象 | 回答的问题 | 完成含义 |
|---|---|---|
| GitHub Issue | 最终为什么做、必须交付什么 | 全部 mandatory requirements 在 `main` 上有聚合证据 |
| Implementation Packet（IP） | 本次最小切片精确怎样实现和验证 | 一个冻结切片通过 post-merge verification |
| Pull Request | 哪些提交要进入 `main` | 此变更可安全合并，不代表 Source Issue 完成 |
| Issue Closure Record | 为什么现在可以关闭 | 对整个 Issue 的最终、可审计证据汇总 |

因此：

```text
IP-DONE ≠ Feature fully integrated ≠ Issue-DONE
PR-MERGED ≠ IP-DONE
All planned IPs merged ≠ Issue-DONE
```

## 2. 规范性角色

### Coordinator Agent

- 维护队列、Issue Delivery Ledger、Owner 和状态；
- 决定 Issue 如何分解、何时激活 IP；
- 接收 P&V Verdict，决定 PR 是否可合并；
- 安排 post-merge verification；
- 执行 Issue Closure Audit，并在授权后手工关闭 Issue。

### Packet & Verification Agent

- 制作 Packet、交接书、冻结测试和 RED 证据；
- 对 Implementation Agent 的交付进行独立验证；
- 形成和推送 Implementation PR；
- 合并后在 `main` 上复验；
- 不写产品实现、不合并 PR、不关闭 Issue。

### Implementation Agent

- 从 Frozen Test Commit 派生；
- 只修改 product-code allowlist；
- 交付产品代码 commit 和 Completion Summary；
- 不改测试/Packet、不管理 PR/Issue、不宣告完成。

详细边界以三份角色责任书为准。

### 2.1 端到端 RACI

`R` = 实际执行，`A` = 对状态转换负责，`C` = 提供输入/接受咨询，`—` = 禁止执行。

| 活动 | Coordinator | P&V | Implementation |
|---|---:|---:|---:|
| 冻结 Issue 需求与 Delivery Ledger | A/R | C | — |
| 选择/编号/排序 IP | A/R | C | — |
| 制作 Packet 与正式交接书 | C | A/R | — |
| 创建/更新 Packet docs PR | C | A/R | — |
| 合并 Packet docs PR | A/R | — | — |
| 编写 acceptance tests/fixture/oracle | — | A/R | — |
| 证明 RED、创建 Frozen Test Commit | C | A/R | — |
| 分配 implementation branch/worktree | A/R | C | C |
| 编写产品代码 | — | — | A/R |
| 修改冻结测试/Packet | — | 仅重新冻结流程 | — |
| 产出 Implementation Completion Summary | C | C | A/R |
| 独立验证实现 | C | A/R | C/修复 |
| 创建/更新 Implementation PR | C | A/R | — |
| Required Check / `merge-gate` | A/检查 | R/响应 | C/修复 |
| 合并 Implementation PR | A/R | — | — |
| 在 `main` 上 post-merge verification | A/调度 | R | C |
| 更新 IP/Requirement 交付状态 | A/R | C/证据 | — |
| Issue Closure Audit / Record | A/R | C | — |
| 手工关闭/重新打开 Issue | A/R（需远端授权） | — | — |

任何 Agent 缺少远端权限时只能停在相应 `READY-FOR-*` 状态并交接，不能用别的身份绕过。

## 3. 事实源与优先级

| 问题 | 第一事实源 |
|---|---|
| 长期项目定位、安全不变量 | 稳定开发标准 + 已批准 Decision |
| Issue 最终需求 | Source Issue 的冻结规格版本 |
| Issue 交付覆盖和剩余缺口 | Source Issue 的 Delivery Ledger |
| 跨 Agent 执行状态、Owner、分支 | Issue Delivery Ledger + Coordinator Assignment + 可验证 Git/GitHub 状态 |
| 本机 worktree/dirty files/临时验证 | 当前 Git 状态 + 可选 `PROGRESS.md` |
| 当前 IP 目标行为 | 已合并的活动 Packet + Decision Record |
| 当前产品行为 | 最新 `origin/main` 代码和可重复测试 |
| 实现是否满足 IP | P&V Verification Report + Required Checks |
| IP 是否完成 | `main` 上 post-merge evidence |
| Issue 是否完成 | Issue Closure Record |

Issue、Packet 和代码的语义不同，不能用其中一个代替另一个。

## 4. 标识与可追踪性

### 4.1 Issue Requirement ID

每个可交付需求必须有稳定 ID：

- 功能需求：`FR-01`、`FR-02`；
- 验收条件：`AC-01`、`AC-02`；
- 非功能要求：`NFR-01`、`NFR-02`；
- 安全不变量：`SEC-01`；
- 迁移/运维要求：`OPS-01`、`MIG-01`。

ID 在 Issue 生命周期内不可被复用。需求被替换时保留旧 ID 并标记 `SUPERSEDED-BY`。

### 4.2 IP ID

IP 使用仓库全局递增编号 `IP-XXXX`。一个 IP：

- 只有一个 Source Issue；
- 可以贡献多个 requirement；
- 可以依赖多个上游 IP；
- 只有一个 Implementation PR；
- 可以有独立的 Packet docs PR；
- 只有 post-merge PASS 后才为 Done。

跨 Issue 共用底座时，选择一个 Primary Source Issue，其他 Issue 的 Delivery Ledger 以 `CONSUMES IP-XXXX` 引用，不复制或伪造 IP。

### 4.3 PR ID

每个 IP 通常有两个 PR：

1. `Packet PR`：Packet、交接书和必要导航；
2. `Implementation PR`：frozen tests/fixture + product implementation。

紧急恢复可有 Recovery PR，但必须由独立 Recovery IP 管理，不得把多个未冻结修复堆入原 PR。

## 5. Issue Specification Gate

Issue 进入 `READY-FOR-DECOMPOSITION` 前必须具备：

- Problem / Value；
- Scope / Non-goals；
- `FR-*`、`AC-*`、`NFR-*`；
- Security / Privacy / Tenant / Permission boundaries；
- Compatibility / Migration / Rollback；
- Integration / Real-run expectations；
- Dependency / Conflict map；
- Issue-level Definition of Done；
- 初始 `Delivery Ledger`。

如果需求只能表达成“优化一下”“支持更多”“结果更准”，必须先定义量化或可观察标准，不能直接产生 IP。

## 6. Issue Delivery Ledger

### 6.1 位置和所有权

每个进入实现的 Source Issue 必须在正文中包含唯一 `Delivery Ledger` 区段，由 Coordinator Agent 独占维护。推荐使用以下边界标记：

```markdown
<!-- LIMA:DELIVERY-LEDGER:START -->
...
<!-- LIMA:DELIVERY-LEDGER:END -->
```

Issue 规格区和 Ledger 区分开：规格改变需要 Decision/需求审查；Ledger 只记录如何交付和当前证据。

### 6.2 Ledger 必填模板

```markdown
## Delivery Ledger

- Specification revision: <timestamp / issue edit / linked commit>
- Coordinator: <agent identity>
- Delivery status: DESIGN | IN-PROGRESS | CLOSURE-REVIEW | DONE | BLOCKED
- Closure policy: MANUAL-AFTER-POST-MERGE-AUDIT
- Last verified main: <sha>
- Last updated: <ISO-8601>

### Requirement coverage
| Requirement | Short meaning | Mandatory | Planned IP(s) | Evidence level required | Status | PR / merge | Post-merge evidence | Gap/decision |
|---|---|---:|---|---|---|---|---|---|
| FR-01 | ... | yes | IP-0001 | contract | SATISFIED | #98 / sha | report | — |
| AC-03 | ... | yes | IP-0003, IP-0005 | integration | PARTIAL | ... | pending | ... |

### IP registry
| IP | Delivery role | Depends on | Packet PR | Frozen tests | Implementation PR | Merge commit | Post-merge | Status |
|---|---|---|---|---|---|---|---|---|

### Integration / closure gates
| Gate | Required evidence | Owning IP | Status | Artifact |
|---|---|---|---|---|

### Open decisions and blockers
- none | <Decision / owner / next action>

### Deferred / superseded requirements
- none | <requirement → approval → replacement Issue>
```

### 6.3 Requirement 状态

- `UNMAPPED`：尚无 IP；
- `PLANNED`：已映射但 Packet 未合并；
- `IN-DELIVERY`：至少一个 IP 正在执行；
- `PARTIAL`：部分 IP 有证据，但聚合标准未满足；
- `SATISFIED-BY-EVIDENCE`：所需 IP 均 post-merge PASS，且证据层级满足；
- `BLOCKED`：外部条件或 Decision 未解决；
- `DEFERRED-APPROVED`：经批准移到明确的新 Issue；
- `SUPERSEDED`：由新 requirement/Issue 替代并有链接。

只有 `SATISFIED-BY-EVIDENCE` 可以计入 Closure PASS。`DEFERRED-APPROVED` 是否允许关闭必须由原 Issue 规格和批准决定；不得把 mandatory scope 静默改成 deferred。

## 7. Issue → IP 分解 Gate

Coordinator 与 P&V Agent 在不同职责下完成分解：Coordinator 决定目标和需求映射，P&V Agent证明一个切片能被冻结和测试。

### 7.1 合格 IP 边界

一个 IP 应同时满足：

- 单一核心不确定性或单一纵向行为；
- 一名实现 Agent 0.5～3 天可完成；
- 文件边界可独占；
- 上游/下游契约可精确陈述；
- 可独立产生 RED → GREEN；
- 能在 `main` 上独立复验；
- 失败不会迫使 Agent 重设整个架构；
- Non-goals 足够明确，避免吸入相邻需求。

### 7.2 必须拆开的情况

- Contract/schema 与业务接线；
- 纯领域模型与外部 Adapter；
- 数据迁移与新行为；
- 高风险权限/网络/Sandbox 与普通逻辑；
- 后端 API 与大规模前端迁移；
- 单元能力与真实 Golden Path 集成；
- 产品实现与性能/HA 扩展；
- 一个 PR 会占用多个并行高冲突区域。

### 7.3 不应过度拆开的情况

- 测试无法在没有另一个 IP 时观察任何有意义行为；
- 两个 IP 必须同时修改同一 exact symbols 才能工作；
- 切分只产生空接口、占位函数或永久 mock；
- 每个 IP 都无法独立回滚或复验；
- 分解成本明显大于实现且不降低风险/冲突。

### 7.4 Closure IP

大型 Issue 必须预留一个 integration/closure IP，负责证明多个切片组合满足 Issue-level AC。Closure IP 不应重复实现功能，主要交付：

- 跨模块接线；
- migration/compatibility；
- 真实 Golden Path 或端到端测试；
- 性能、压力、恢复或运维 Gate；
- 用户可见行为验证；
- Issue Closure Audit 所需的聚合 evidence。

并非所有小 Issue 都需独立 Closure IP，但都必须执行 Closure Audit。

## 8. IP Packet Gate

P&V Agent 制作的 Packet 必须包含：

- Header：Source Issue、spec revision、covered/not-covered requirements、role、closure impact；
- Design Input Manifest 与 Explicitly Rejected Inputs；
- iteration hypothesis / measurement；
- goal / non-goals；
- exact base/upstream contracts；
- Files Add/Modify/Tests/Read-only/Forbidden；
- Symbol-to-File Map；
- exact behavior、state、error、schema、resource 和 permission contracts；
- test matrix、minimum counts、golden/oracle；
- AC traceability；
- baseline/slice/compatibility/integration/boundary/post-merge commands；
- Stop Conditions / Decision Request；
- Completion Summary / PR contract；
- Packet completion definition。

Packet docs PR 合并前状态最多为 `DESIGN-FROZEN / PENDING-MERGE`。只有其 exact version 已在 `main`，Coordinator 才可标记 `PACKET-MERGED`。

## 9. Tests-Frozen Gate

P&V Agent 必须在 Packet merge commit 之后：

1. 写 Packet 指定测试和 fixture；
2. 验证测试自身质量；
3. 在产品实现前证明预期 RED；
4. 记录非预期 baseline/环境问题；
5. 创建 Frozen Test Commit；
6. 记录测试文件 digest 和 required test count；
7. 交 Coordinator 激活 Implementation Agent。

Tests-Frozen Gate 的必要条件：

- RED 原因是缺失目标行为；
- 测试不是依赖/导入/环境损坏；
- 测试覆盖 success、failure、安全和边界；
- 不依赖不稳定外网、付费模型或未冻结数据；
- 真实运行测试如需专用环境，已有明确可重放配置。

### 9.1 标准分支交接拓扑

标准拓扑固定为：

```text
origin/main + Packet docs merge
        |
        +-- codex/ip-xxxx-integration      (P&V owner)
               |
               +-- Frozen Test Commit      (valid RED)
                       |
                       +-- codex/ip-xxxx-implementation  (Implementation owner)
                               |
                               +-- Product Implementation Commit(s)
                                       |
                                       +-- Final Implementation Commit
```

Implementation Agent 交付后：

1. P&V Agent 在独立 worktree 验证 final commit；
2. 验证 PASS 后，将 integration branch **fast-forward** 到 final commit；
3. 不以 cherry-pick/rebase 改写 Frozen Test Commit 或实现证据链；
4. P&V Agent 从 integration branch 推送 Implementation PR；
5. 若不能 fast-forward、commit ancestry 不一致或分支含额外提交，状态进入 `BLOCKED-BY-HANDOFF`，由 Coordinator 处理；
6. 两个 Agent 不在同一 worktree 或同一时刻写同一 branch。

Frozen Test Commit 必须能被 Implementation Agent 按 SHA 获取：共享同一 Git object store 时可直接创建 worktree/branch；跨主机时，P&V Agent 在已获授权的 integration branch 上先推送该 commit 作为传输点，但此时不得创建可合并的 Implementation PR。Coordinator Assignment 必须记录获取方式和精确 SHA。

如果仓库策略要求不同分支名，Coordinator 可以在 Assignment 中替换名称，但不得改变所有权和 ancestry 规则。

## 10. Implementation Gate

Implementation Agent：

- 从 Frozen Test Commit 创建 implementation branch；
- 只改 product allowlist；
- 不改 tests/fixture/oracle/Packet；
- 运行全部 mandatory commands；
- 交付 final commit 和 Completion Summary；
- 不创建/合并 PR，不改 Issue。

实现完成只进入 `VERIFICATION`，不得直接进入 `IP-DONE`。

## 11. Independent Verification Gate

P&V Agent 在干净环境核对：

- commit ancestry；
- tests frozen and unchanged；
- file/symbol/dependency/permission boundaries；
- AC tests and negative paths；
- regression/integration/security/compatibility；
- skip/warning/flaky/coverage；
- generality / anti-overfitting；
- Completion Summary reproducibility。

结果仅有：

- `READY-FOR-PR`；
- `NEEDS-REWORK`；
- `BLOCKED-BY-CONTRACT`；
- `BLOCKED-BY-ENVIRONMENT`；
- `SECURITY-REJECTED`。

## 12. PR Contract

### 12.1 Packet PR

```text
Title: docs: freeze IP-XXXX <name> handoff
Body first relation: Related to #<source-issue>
Auto-close: forbidden
Content: docs/coordination only
Merge meaning: Packet version becomes consumable; no product behavior delivered
```

### 12.2 Implementation PR

```text
Title: <type>: <implemented behavior>
Body: Implements IP-XXXX; Related to #<source-issue>
Auto-close: forbidden for every IP, including closure candidate
Content: frozen tests/fixtures + product allowlist only
Merge meaning: reviewed change is in main; IP still awaits post-merge verification
```

Implementation PR 正文至少包含：

- Packet link/merge commit；
- Source Issue and requirement IDs；
- Frozen Test Commit / implementation commit；
- changed files / API / dependency / permission；
- AC matrix；
- commands and actual results；
- P&V Verdict；
- known limitations/decisions；
- post-merge plan；
- `This PR does not auto-close the Source Issue.`

### 12.3 禁止自动关闭

所有 IP PR、docs PR 和 recovery PR 都不得把 `close/fix/resolve` 类自动关闭关键字与 Source Issue 编号组合。原因是 GitHub 会在合并时关闭 Issue，而 LIMA 的 Issue 关闭必须晚于 post-merge 聚合审计。

只有 Coordinator Agent 可以在 Closure Record 完成后执行独立的手工关闭动作。

## 13. Merge Gate

Coordinator Agent 只在以下全部成立时批准 Implementation PR 合并：

- P&V Verdict = `READY-FOR-PR/READY-FOR-MERGE`；
- Review conversations 全部解决；
- Required Checks 包括 `merge-gate` 全绿；
- PR diff 与 Packet allowlist 一致；
- no unapproved dependency/API/permission expansion；
- no unresolved Decision Request；
- no mandatory skip or unexplained failure；
- PR 不会自动关闭 Source Issue；
- post-merge verifier、命令和环境已明确。

`merge-gate` 是 GitHub 分支保护中的 Required Check 名称；它是合并门禁之一，不是一个 Agent，也不等于 Issue Closure Gate。

## 14. Post-merge Gate

合并后 P&V Agent 必须在最新 `origin/main` 复验。最低证据：

```text
PR / merge commit：
Verified main commit：
Environment/tool versions：
Packet mandatory commands：
Pass/fail/skip/exit：
Integration/real-run artifacts：
Regression/security results：
Verdict：POST-MERGE PASS | POST-MERGE FAIL
```

`POST-MERGE FAIL` 时：

- IP 不得标记 Done；
- Ledger requirement 不得标记 satisfied；
- Coordinator 创建最小 Recovery IP 或回滚路径；
- 原失败证据不得删除或被后续绿测覆盖。

## 15. IP Done Gate

一个 IP 只有同时满足以下条件才是 `IP-DONE`：

- Packet docs 已在 `main`；
- Frozen Test Commit 可追溯；
- Implementation PR 已合并；
- P&V Verification Report PASS；
- Required Checks PASS；
- post-merge verification PASS；
- Completion Summary 完整；
- Decision Requests 已解决；
- Ledger 已记录 merge/evidence；
- 下一消费者已完成必要 consumer review，或明确记录该 review 属下一 IP 的入口 Gate。

IP-DONE 只允许更新其明确映射 requirement 的证据状态。

## 16. Issue Closure Gate

### 16.1 Closure 候选条件

当 Ledger 中所有 mandatory requirements 均显示可能满足时，Coordinator 把 Issue 置为 `CLOSURE-REVIEW`，不立即关闭。

### 16.2 聚合审计清单

必须逐项检查：

- [ ] Issue specification revision 唯一且无未合并语义变更；
- [ ] 每个 mandatory FR/AC/NFR/SEC/OPS/MIG 有 evidence；
- [ ] Requirement → IP → PR → merge → post-merge 正向追踪完整；
- [ ] 每个 IP/PR → requirement 反向追踪完整；
- [ ] 所有必需 IP 为 `IP-DONE`；
- [ ] 组合后的实际系统行为通过 integration/Golden Path；
- [ ] 与真实需求匹配的证据层级已达到，未用低层测试代替高层验收；
- [ ] 安全、兼容、migration、rollback、performance/pressure/HA 要求按 Issue 范围完成；
- [ ] 生产/沙箱/网络/依赖等环境差异已覆盖或明确不适用；
- [ ] 用户可见文档、API、UI 或运维说明已同步；
- [ ] 没有 unresolved blocker/Decision/security regression；
- [ ] mandatory tests 无 skip，其他 skip 有批准原因；
- [ ] deferred/superseded scope 有批准和新 Issue 链接；
- [ ] Issue Closure Record 已生成并可复现。

### 16.3 关闭动作

1. 记录 final `main` commit 和全部证据，将 Delivery Ledger 置为 `READY-FOR-CLOSURE`；
2. Coordinator 在 Source Issue 发布 Closure Record；
3. 在仓库授权存在时手工关闭 Issue；
4. 关闭成功后将 Delivery Ledger 置为 `DONE`；
5. 如使用本机 `PROGRESS.md`，同步其缓存；
6. 不删除 Packet、PR、失败记录、Decision 或分支证据链；
7. 无授权或关闭失败时保持 `READY-FOR-CLOSURE`，交 Maintainer 执行，不得提前写 `DONE`。

### 16.4 绝对禁止的关闭依据

不得仅因为以下任一情况关闭 Issue：

- 最后一个“计划中的”IP 已合并；
- 单元测试或 CI 全绿；
- PR 描述称功能完成；
- LLM/Agent 给出高置信结论；
- 代码已存在但没有接线或真实运行；
- Issue 开放时间过长；
- 剩余需求很难、工期长或暂时没有 Owner；
- 未发现新问题；
- 用户手动验证过一次但无法复现。

## 17. Reopen Gate

已关闭 Issue 在以下情况必须重新打开：

- 原 mandatory requirement 实际未满足；
- Closure Record 使用的证据不可重放或与 main 不一致；
- regression 直接破坏原 Issue 的验收；
- 自动关闭发生在 Closure Audit 前；
- deferred/superseded 记录无有效批准或替代 Issue；
- security invariant 被证明错误或不完整。

重新打开时保留原 Closure Record并新增：发现时间、复现、影响 requirement、责任 IP/PR、Recovery 计划。不得改写历史使其看似从未关闭。

## 18. 状态机

### 18.1 Issue 状态

```text
DISCOVERY
  → DESIGN
  → READY-FOR-DECOMPOSITION
  → IN-PROGRESS
  → CLOSURE-REVIEW
  → READY-FOR-CLOSURE
  → DONE
```

旁路状态：`BLOCKED`、`DEFERRED`、`REOPENED`、`SUPERSEDED`。

### 18.2 IP 状态

```text
PROPOSED
  → DESIGN
  → PACKET-REVIEW
  → PACKET-MERGED
  → TESTS-FROZEN
  → IMPLEMENTING
  → VERIFICATION
  → PR-REVIEW
  → MERGED
  → POST-MERGE-VERIFIED
  → IP-DONE
```

旁路状态：`NEEDS-REWORK`、`BLOCKED`、`ABORTED`、`SUPERSEDED`、`POST-MERGE-FAILED`。

### 18.3 状态转换证据

| 转换 | 最低证据 | 执行者 |
|---|---|---|
| Issue → READY-FOR-DECOMPOSITION | 冻结 requirement + Ledger | Coordinator |
| IP → PACKET-MERGED | Packet docs merge commit | Coordinator |
| IP → TESTS-FROZEN | Frozen commit + valid RED | Coordinator based on P&V evidence |
| IP → VERIFICATION | Implementation commit + Summary | Coordinator/P&V reception |
| IP → PR-REVIEW | P&V PASS + PR | Coordinator |
| IP → MERGED | merge commit + Required Checks | Coordinator |
| IP → IP-DONE | post-merge PASS + Ledger update | Coordinator |
| Issue → READY-FOR-CLOSURE | aggregate Closure Audit PASS | Coordinator |
| Issue → DONE | Closure Record + authorized manual close | Coordinator/Maintainer |

## 19. PR/Issue 文案约束

### 19.1 普通 IP PR

```markdown
Implements IP-XXXX.

Related to #NN.

This PR contributes to FR-01 and AC-02. It does not cover AC-05 or the
Issue-level integration gate. This PR does not auto-close the Source Issue.
```

### 19.2 Issue 进度更新

Coordinator 更新 Ledger，不用“完成 XX%”替代证据。进度应表达为：

```text
Requirements satisfied by evidence: 4/9
Requirements partial: 2/9
Requirements unmapped/blocked: 3/9
IPs post-merge verified: 3/6
Closure gates passed: 1/4
```

### 19.3 Closure Record

使用 Coordinator 责任书模板；必须包含 final main commit、requirement matrix、integration/operational evidence、deferred scope、open risks 和结论。

## 20. 典型示例：#58、IP-0001、IP-0002

截至 PR #100 合并：

- IP-0001 / PR #98 提供 deterministic Artifact Contract Foundation；
- IP-0002 / PR #100 提供 deterministic Evidence Domain；
- 两个 IP 均只能满足 #58 中各自映射的部分 contract/domain requirement；
- RAM/profile、AEP/VEP/RVR、workflow/stage/outcome、legacy adapter、跨 Artifact 集成和真实 Golden Path 等若仍属于 #58 的 mandatory requirements，就必须继续保留在 Ledger；
- 即使 IP-0001、IP-0002 都为 `IP-DONE`，#58 仍应保持打开，直到全部需求和 closure gates 有 post-merge evidence。

这就是“IP 完成”与“Issue 完成”的边界。

## 21. 规模化生产 IP 的质量控制

IP 数量增长后必须持续检查：

- 每个 IP 是否仍在 0.5～3 天边界；
- 是否出现多个 IP 重复覆盖同一需求却无人负责集成；
- 是否出现 requirement 永久 `UNMAPPED`；
- 是否出现 Packet 比代码更难维护的过度切分；
- 是否出现共享文件 Owner 冲突；
- 是否形成长期未 post-merge 的已合并 PR；
- 是否只生产底层 Contract 而没有 vertical slice/closure IP；
- 是否把规划完成率当产品可用性；
- 是否积累不可检索的日志而没有 digest、artifact index 和 retention；
- 是否有 Agent 在用过期 Packet 或聊天记忆。

Coordinator 每完成 3～5 个 IP 或一个 vertical slice，应做一次 Delivery Ledger Review，重新检查剩余关键路径，而不是机械执行最初列表。

## 22. 异常处理

| 异常 | 处置 |
|---|---|
| Issue 需求变化 | 冻结活动 IP；修订 spec/Ledger；评估新 Packet 版本 |
| Packet 多解 | 退回 DESIGN，提交 Decision Request |
| Frozen test 错误 | 撤销冻结，修订 Packet/test，重新 RED |
| Implementation 越界 | 拒收 commit，回退 product allowlist |
| PR checks flaky | 分类并修基础设施；不以重跑偶然绿替代根因 |
| 合并后失败 | POST-MERGE-FAILED，Recovery IP/回滚 |
| 远端无权限 | 停在 READY-FOR-*，输出可手工执行材料 |
| Issue 被误关闭 | 立即 reopen，记录自动关闭来源，完成 Closure Audit |
| 新发现属于原验收 | Ledger 新增 gap，Issue 保持打开 |
| 新发现独立于原验收 | 新 Issue，建立 depends/related 链接 |
| 环境/网络/依赖不可用 | 保留 primary failure，按环境问题处理，不改产品语义 |

## 23. 最小自动化建议

后续可逐步自动化，但自动化不能改变责任边界：

- 检查 Packet header 是否有 Source Issue、requirements、closure impact；
- 检查 Implementation PR 是否使用自动关闭关键字；
- 校验 changed files 与 Packet allowlist；
- 校验 tests/fixture 在 implementation commit 中未变化；
- 从 PR 提取 AC matrix 和 test statistics；
- 检查 Ledger 是否存在 `UNMAPPED` mandatory requirement；
- 在 PR merge 后自动创建 post-merge verification task；
- 在 Issue close 事件上验证 Closure Record 是否存在，否则自动 reopen/告警。

自动化只执行 Gate；不能由统计值自动批准 Contract 例外或安全降级。

## 24. 最终纪律

```text
Issue 定义完整结果。
Delivery Ledger 保证没有需求失踪。
IP 冻结一个最小可执行切片。
Frozen tests 定义可观察验收。
Implementation Agent 只写产品代码。
P&V Agent 独立验证并形成 PR。
merge-gate 只决定能否合并。
post-merge evidence 决定 IP 是否完成。
Issue Closure Audit 决定整个需求是否完成。
Coordinator 只在最终审计后手工关闭 Issue。
```
