# LIMA V4 多人协作需求拆分与 GitHub Issue Backlog

> 规划基线：`main@bf7d79d`（2026-08-31）
> 上游规划：`LIMA_三沙箱通信与依赖网络治理_迭代规划_v3.md`、`LIMA_可用性性能与安全知识库_迭代规划_v4.md`
> 目标：把 V4 从路线图拆成可认领、可并行、可测试、可关闭的 GitHub Issues
> 约束：一个 Issue 一个主要责任域、一个逻辑 PR；高冲突文件只有 Integration Issue 可以修改

## 1. 拆分结论

V4 不应被拆成“按技术名词分工”的横向大项目，例如一个人做数据库、一个人做 Agent、一个人做 Sandbox，然后在最后集中集成。这样的拆法会让所有人同时修改 `service.py`、`store.py`、`task_queue.py` 和 API，产生高冲突和长期不可运行分支。

本 Backlog 采用三层拆分：

```text
Contract Issues
  先冻结跨模块输入、输出、证据等级和失败语义
       ↓
Leaf Capability Issues
  各自在新模块/独立目录实现，可使用 fixture 并行开发
       ↓
Integration Issues
  由单一负责人接入 service/API/store/frontend，并执行端到端 Gate
```

最终拆为：

- 1 个 Tracking Epic；
- 22 个 14–16 周 MVP Issues；
- 5 个必须经过 Go/No-Go 才能启动的 Post-MVP Issues；
- 共 28 个 GitHub Issue 单元（1 Epic + 27 Tasks）。

V3 继续作为信任边界和长期目标架构，V4 Issues 只实现能够证明价值的最小纵向切片。

## 2. 与已有 Issues 的去重

创建 V4 Issues 前已核对仓库现有工作。以下能力直接复用，不重复立项：

| 已有 Issue | 已有能力 | V4 处理方式 |
|---|---|---|
| #10–#13 | RepositorySource、Materializer、Snapshot Cache、异步扫描接线 | 作为 RAM、缓存和 Sandbox 输入基础 |
| #14 | repository cache / repair workspace 部署卷 | 复用存储信任域，不重新设计卷 |
| #15 | GitHub repository source UI | 不重复创建来源选择 UI |
| #16 | disposable RepairWorkspace | Repair 候选隔离在其上扩展 |
| #34 | TaskProgress 持久化 | V4 只增加阶段/Artifact 语义，不另建进度模型 |
| #35 | typed failure 与 retry | V4 扩展 Sandbox/Artifact/Dependency failure code |
| #36–#37 | 物化和扫描真实进度 | Fast Audit Integration 在此基础上接入 |
| #38–#43 | React 基座、任务中心、测试与旧前端移除 | V4 只新增 Issue-centric Audit/Mining/Repair 体验 |

如果旧 Issue 的代码已合并但 Issue 状态未同步，应先关闭旧 Issue；不能用 V4 新 Issue 代替历史收尾。

## 3. 优先级、状态与规模定义

### 3.1 优先级

| 标记 | 含义 |
|---|---|
| P0 | 契约或决策门；不完成会导致多人返工或无法判断价值 |
| P1 | MVP 主路径；直接贡献 Fast Audit、VEP 或 Verified Patch |
| P2 | MVP 可靠性、运维与试点门禁 |
| P3 | 达标后投资；当前不能认领实现，只允许研究/测量 |

### 3.2 Issue 状态

| 状态 | 可否编码 | 说明 |
|---|---:|---|
| `status:ready` | 是 | 依赖已满足且改动域无人占用 |
| `status:ready-against-contract` | 是 | 可基于已冻结 schema/fixture 开发，暂不接主链路 |
| `status:blocked` | 否 | 前置 Issue 未合并 |
| `status:gated` | 否 | 需要阶段 Go/No-Go 或容量数据触发 |
| `status:in-progress` | 仅认领者 | 必须在 Issue 留言、分配负责人后进入 |

### 3.3 规模

| 规模 | 建议工作量 | 规则 |
|---|---:|---|
| S | 1–3 人日 | 单模块、接口已冻结 |
| M | 3–6 人日 | 一个能力与完整测试 |
| L | 6–10 人日 | 一个纵向能力或有限集成；超过 10 人日必须再拆 |

规模是排期参考，不是承诺。任何 Issue 如果需要同时修改两个高冲突域，应拆分或转为显式 Integration Issue。

## 4. 总体依赖图

```text
I01 Baseline ───────┬──────────────► I03 Telemetry
                    ├──────────────► I06 CWE-798 Evaluation
                    └──────────────► I22 Pilot / Go-No-Go

I02 Contracts ──────┬──► I04 RAM ──────────┐
                    ├──► I05 Fusion ──► I06 ├──► I07 Tier Planner
                    ├──► I08 Audit Cache ───┤         │
                    ├──► I11 Case v0        └─────────┼──► I09 Fast Audit Integration
                    └──► I12 Artifact Store ──────────┘                │
                                                                      └──► I10 Frontend

I12 Artifact Store ─► I13 Lease/Recovery ─► I14 Sandbox Supervisor
                               │                      ├──► I15 Tool Registry v0
                               │                      └──► I16 Dependency Snapshot
                               │                                  │
I04 + I05 + I12 + I14 + I16 ───────────────────────────────► I17 CWE-22 Mining
                                                                    │
                                                                    ▼
                                                           I18 Repair Candidates
                                                                    │
                                                                    ▼
                                                           I19 Repair Gates/RVR

I12 + I13 ─► I20 Backup/Restore
I03 + I09 + I13 + I14 + I19 ─► I21 Load/Soak/Fault
I01 + I06 + I09 + I10 + I17 + I19 + I20 + I21 ─► I22 Pilot/Go-No-Go

I22 Go ─► I23 Case Library ─► I24 Python CWE Expansion
       ├► I25 Beta HA（需容量触发）
       ├► I26 pgvector/RAG（需检索收益触发）
       └► I27 Language/Isolation/Tool Evolution（需单独选型）
```

## 5. 并行批次

| 批次 | 可并行 Issue | 合并条件 |
|---|---|---|
| A：第 1–2 周 | I01、I02 | I02 必须先于所有 schema 消费者合并 |
| B：第 2–4 周 | I03、I04、I05、I08、I11、I12 | 只能使用各自目录；不得提前接 `service.py`/store |
| C：第 4–5 周 | I06、I07、I13、I15 | I05/I12 合并；以 frozen fixture 开发 |
| D：第 5–8 周 | I09、I10、I14、I16、I20 | I09 是唯一 Fast Audit 后端接线者；I14 是唯一 root Docker policy 接线者 |
| E：第 9–11 周 | I17；I21 可先搭负载框架 | Mining 单纵向切片，不扩 CWE |
| F：第 12–14 周 | I18 后接 I19 | 候选生成与裁决不能由同一组件自证 |
| G：第 15–16 周 | I20、I21 收尾，I22 | 只有量化报告可做 Go/No-Go |
| Post-MVP | I23–I27 | 全部 `status:gated`，不能提前混入 MVP PR |

## 6. 文件所有权与冲突控制

### 6.1 高冲突文件

| 文件/目录 | 唯一主 Issue | 其他 Issue 的规则 |
|---|---|---|
| `lima/service.py`、`lima/api.py`、`lima/repository_scanner.py` | I09 | Leaf Issues 只提供接口和 fixture，不直接接主链路 |
| `frontend/src/shared/api/` 与 V4 路由接线 | I10 | 其他后端 Issue 不改前端 |
| `lima/store.py`、`lima/postgres_store.py`、数据库 migration | I12；I11/I23 预约顺序 migration | 同一时间只能有一个 migration owner |
| `lima/task_queue.py` | I13 | I14/I17/I19 只调用 lease/attempt 接口 |
| root `Dockerfile`、`docker-compose.yml` | I14 | I16 只维护 dependency 镜像/fixture，root 接线交给 I14 |
| `lima/metrics.py`、`lima/observability.py` | I03 | 其他 Issue 仅通过公共 recorder 接口埋点 |
| `lima/repair_workspace.py`、`lima/security_repair.py` | I18 | I19 新建 verifier/gate 模块，必要兼容修改需在 I18 合并后进行 |

### 6.2 新目录所有权

```text
lima/contracts/        I02
lima/audit/inventory*  I04
lima/audit/fusion*     I05
lima/audit/rules/      I06
lima/audit/planner*    I07
lima/audit/cache*      I08
lima/knowledge/        I11（v0）→ I23（v1）
lima/artifacts/        I12
lima/worker_runtime/   I13
lima/sandbox/          I14
lima/tool_registry/    I15
lima/dependencies/     I16
lima/mining/           I17
lima/repair/candidate* I18
lima/repair/gates*     I19
benchmarks/v4/         I01/I21（不同子目录）
```

### 6.3 合并纪律

- 每个 PR 必须 `Closes #<issue>`，不能一个 PR 同时关闭多个 V4 Tasks；
- 依赖未合并时允许基于 schema fixture 开发，但 PR 标记 draft；
- 不允许两个活跃 PR 同时添加数据库 migration；
- 不允许 Leaf Issue 为“方便联调”顺手修改 `service.py` 或 `api.py`；
- 公共接口变更先回到 I02/ADR 讨论，不在下游 PR 私自漂移；
- Integration Issue 不重写 Leaf 能力，只做组合、状态推进、API 和端到端测试；
- 合并顺序按依赖图，不以“谁先写完”替代拓扑顺序。

## 7. MVP GitHub Issues

以下内容可直接作为 GitHub Issue 正文。GitHub 正式编号创建后，应将 `V4-Ixx` 保留在标题中，并在本文件增加链接。

### V4-I01 `[P0][Phase 0] 冻结 MVP 支持矩阵并建立可用性、成本与精度基线`

- 状态/规模：`status:ready` / M。
- Primary ownership：`benchmarks/v4/baseline/`、`evaluation_data/v4/`、基准脚本与报告。
- 不修改：扫描、队列、Sandbox、store、前端业务实现。
- 交付：固定 LlamaFactory commit 和 S/M Python 样本；cold/warm p50/p95；CPU/RSS/IO/Token；Signal/Issue；专家分钟数；支持矩阵和不做清单。
- 验收：同 commit/config/seed 可复现；CI 只跑 smoke；完整评测显式触发；无私有源码、Secret 或付费评测进入普通 CI。
- 依赖：无。
- Blocks：I03、I06、I22。

### V4-I02 `[P0][Phase 0] 冻结 Signal→Issue→Hypothesis 与跨阶段 Artifact 版本契约`

- 状态/规模：`status:ready` / L；merge-first。
- Primary ownership：`lima/contracts/`、`schemas/v4/`、`tests/contracts/`、ADR-027–040。
- 不修改：`models.py`、store、queue、业务流水线。
- 交付：Signal、SecurityIssue、Hypothesis、Evidence Level、Common Envelope、RAM/AEP/VEP/RVR、Task Manifest、Dependency Snapshot、Sandbox Run Manifest 的最小 versioned schema。
- 验收：合法/非法 fixture；round-trip；major version fail closed；digest/lineage 规则；environment failure 不得等价 safe/refuted；schema 包不依赖 DB/Docker/LLM。
- 依赖：无。
- Blocks：除 I01 外的所有核心能力。

### V4-I03 `[P0][Phase 0] 建立任务级 SLO、资源预算与端到端成本遥测`

- 状态/规模：`status:blocked` / M。
- Primary ownership：`metrics.py`、`observability.py`、SLO 文档。
- 不修改：service、scanner、queue 控制流。
- 交付：task/run/stage/tool/model/artifact 关联；queue wait、CPU、RSS、IO、Token、cache/dependency/artifact 指标；budget stop reason；单任务成本账单。
- 验收：可区分 retry/cache/cancel/timeout；Prometheus label 低基数；日志脱敏；遥测关闭不改变结论。
- 依赖：I01、I02。
- Can parallel：I04、I05、I08、I11、I12。

### V4-I04 `[P0][Phase 1] 建立 Repository Architecture Model 与安全语义清单`

- 状态/规模：`status:blocked` / L。
- Primary ownership：`lima/audit/inventory.py`、`ram.py`、`semantic_prioritizer.py`。
- 不修改：scanner、service、store、Sandbox、前端。
- 交付：语言/框架/入口/Source/Sink/信任边界/关键流程/调用关系；Top-N 高价值路径；未分析与 execution-required gap；模型与 prompt provenance。
- 验收：不 import/执行仓库代码、不装依赖；同 snapshot 可重复；剪枝只影响 Deep Path 排序，不删除 Tier 0；覆盖空仓库、monorepo 和预算超限。
- 依赖：I02；复用 #10–#13。
- Can parallel：I05、I08、I11、I12。

### V4-I05 `[P0][Phase 1] 实现 Signal→SecurityIssue 聚类、Evidence Fusion 与 Hypothesis 生成`

- 状态/规模：`status:blocked` / L。
- Primary ownership：`lima/audit/fusion.py`、`issue_cluster.py`、`hypothesis.py`、tool result adapters。
- 不修改：scanner/service/API/store/frontend。
- 交付：统一 Signal adapter；稳定 Issue identity；同根因去重；Source→Sink/控制流/语义证据合并；支持/反驳/缺口；Hypothesis 和 adjudication reason。
- 验收：896 类原始 Signal 可聚为可解释 Issue；不会因多个工具重复命中提高虚假置信度；自动关闭必须引用确定性反证；顺序变化不改变 identity。
- 依赖：I02。
- Blocks：I06、I07、I09、I17。

### V4-I06 `[P1][Phase 1] 建立 CWE-798 协议 Token、Fixture 与 Placeholder 降噪专项`

- 状态/规模：`status:blocked` / M。
- Primary ownership：`lima/audit/rules/hardcoded_secret.py`、CWE-798 golden dataset/tests。
- 不修改：通用 fusion、service、API、前端。
- 交付：credential/token 分类；协议常量、模型名、fixture、placeholder、canary 与真实凭据形态区分；正例/安全近邻/不确定样本。
- 验收：LlamaFactory CWE-798 人工队列显著下降；已知真实 Secret 召回不低于 I01；不确定项不自动判安全；所有结论附确定性或语义依据。
- 依赖：I01、I02、I05。
- 决策门：未改善 Issue-level precision 时，停止扩大 Audit 工具数量。

### V4-I07 `[P1][Phase 1] 实现 Fast/Deep Path、Tier 0/1/2 预算与停止策略`

- 状态/规模：`status:blocked` / M。
- Primary ownership：`lima/audit/planner.py`、`budget.py`、`scheduler_policy.py`。
- 不修改：queue backend、service/API、Sandbox runtime。
- 交付：Tier 0 全仓；Tier 1 Top 10–20 Issue；Tier 2 Top 3–5 Hypothesis；工具/LLM/时间/输出预算；证据充分与无收益停止条件；资源池声明。
- 验收：预算耗尽产生结构化 gap 而非安全结论；Fast Path 不等待 Mining/Repair；LLM 429 只降级语义路径；优先级策略有确定性测试。
- 依赖：I03、I04、I05。
- Blocks：I09。

### V4-I08 `[P1][Phase 1] 实现确定性 Audit Cache、失效与增量分析契约`

- 状态/规模：`status:blocked` / L。
- Primary ownership：`lima/audit/cache.py`、`analysis_cache.py`、缓存测试。
- 不修改：`repository_cache.py` 内部、不接 service/API。
- 交付：file parse、tool result、RAM、evidence cluster、LLM result 缓存；digest/version/policy/tenant key；增量失效图；single-flight。
- 验收：任何输入/工具/规则/schema/policy 变化正确失效；跨租户不可命中；只复用不可变结果，不复用 Mining/Repair 可变状态；冷/热性能差异可测。
- 依赖：I02、I04、I05；复用 #12 snapshot cache。
- Blocks：I09、I21。

### V4-I09 `[P1][Phase 1] 将 RAM、Fusion、Tier Planner 与 Cache 接入 Fast Audit/AEP 后端`

- 状态/规模：`status:blocked` / L；唯一 Audit backend Integration Issue。
- Primary ownership：`service.py`、`api.py`、`repository_scanner.py`、repository scan integration tests。
- 不修改：Leaf 模块算法、store schema、前端。
- 交付：Snapshot→Inventory→Tier0→Issue Cluster→initial AEP；Deep Path revision；真实阶段进度；预算/降级/取消；Issue-centric API；AEP Artifact 指针。
- 验收：30–60 秒可见 RAM/进度；M 仓库 Fast Audit p95 ≤ 5 分钟（参考机）；重复 snapshot 能命中缓存；initial/deep AEP 版本与 lineage 正确；失败不覆盖已封存 revision。
- 依赖：I03–I08、I12，以及已有 #34–#37。
- Blocks：I10、I21、I22。

### V4-I10 `[P1][Phase 1] 新增 Issue-centric Audit、Mining 与 Repair 渐进式前端`

- 状态/规模：`status:blocked` / L；唯一 V4 frontend Integration Issue。
- Primary ownership：`frontend/src/features/security-analysis/`、V4 API types、Vitest/Playwright 场景。
- 不修改：后端算法、store、Sandbox、旧前端（已由 #43 处理）。
- 交付：RAM/覆盖缺口；Issue 而非原始 Signal 队列；AEP revision；Mining 证据/Gate；Repair candidate matrix；typed failure 与可重试动作。
- 验收：Fast Path 结果可逐步出现；不把 inconclusive 显示为 safe；不把 candidate 显示为 verified；刷新/路由恢复；终态停止轮询；无浏览器端 Secret/源码泄漏。
- 依赖：I09，以及 #38–#42。
- Can start：基于 I02/I09 mock API 提前开发。

### V4-I11 `[P1][Phase 1] 建立 Security Case Candidate v0 与专家正负反馈入口`

- 状态/规模：`status:blocked` / M。
- Primary ownership：`lima/knowledge/candidates.py`、candidate repository interface、反馈 API 契约。
- 不修改：通用 store migration、向量、RAG、全量检索。
- 交付：正例、负例、工具失败/inconclusive candidate；provenance、scope、quality、fingerprint；promote/reject/revoke 状态机草案。
- 验收：原始 Signal 和单一 Agent 总结不能直接 promoted；专家反馈可追溯；跨租户默认不可见；候选只辅助评测，不提升当前证据等级。
- 依赖：I02、I05；持久化 adapter 在 I12 合并后接入。
- Blocks：I23。

### V4-I12 `[P0][Phase 2] 实现不可变 Artifact Registry、内容寻址存储与 Lineage`

- 状态/规模：`status:blocked` / L；唯一 MVP store/migration owner。
- Primary ownership：`lima/artifacts/`、local durable artifact store、SQLite/PostgreSQL metadata migration。
- 不修改：queue、Sandbox runner、Audit/Mining/Repair 业务。
- 交付：put/get/seal/reference；digest/schema/producer/tenant/retention/lineage；P0/P1/P2 TTL；原子封存；orphan/partial cleanup；本地与 S3-compatible port。
- 验收：Artifact 不可原地覆盖；metadata commit 与 blob 封存有恢复协议；digest/type/schema/size 校验；ACL/tenant isolation；Redis 不成为权威存储。
- 依赖：I02。
- Blocks：I13–I20、I23。

### V4-I13 `[P0][Phase 2] 扩展 durable lease、attempt、幂等提交与断点恢复`

- 状态/规模：`status:blocked` / L；唯一 V4 queue owner。
- Primary ownership：`task_queue.py`、`lima/worker_runtime/lease.py`、recovery tests。
- 不修改：Sandbox implementation、业务 stage、前端。
- 交付：至少一次投递；lease/heartbeat/reclaim；attempt-scoped output；idempotency key；Artifact seal 后的权威提交；取消与费用去重；typed retry。
- 验收：Worker 在上传前/后被 kill 均可恢复；重复消息不产生两个权威 Artifact/费用；API/Scheduler 重启不丢任务；基础设施失败与安全 verdict 分离。
- 依赖：I12，复用 #34/#35。
- Blocks：I14、I20、I21。

### V4-I14 `[P0][Phase 2] 实现单机 Worker Supervisor 与 R--/RX-/RWX 三种 Sandbox Profile`

- 状态/规模：`status:blocked` / L；唯一 root Docker policy owner。
- Primary ownership：`lima/sandbox/`、Supervisor、Sandbox Docker profiles、root compose 接线。
- 不修改：具体 Audit/Mining/Repair 算法、dependency resolver。
- 交付：Task Manifest 验证；只读 inbox/有界 outbox；R--/RX-/RWX mount/capability/network/resource policy；非 root、read-only rootfs、PID/CPU/RSS/disk/time/output 限制；销毁与节点隔离。
- 验收：Sandbox 无 Control Plane/DB/Object Store 长期凭据；三 Sandbox 不直连、不共享可写卷；Audit 不能执行项目；cleanup 失败隔离节点；越权 Manifest fail closed。
- 依赖：I12、I13。
- Blocks：I15–I19、I21。

### V4-I15 `[P1][Phase 2] 建立 Tool Registry v0、固定 Tool Bundle 与按需检索`

- 状态/规模：`status:blocked` / M。
- Primary ownership：`lima/tool_registry/`、tool manifests、adapter contracts、批准清单。
- 不修改：Skill evolution、自动下载、Sandbox policy、业务 planner。
- 交付：name/version/digest/source/language/CWE/capability/risk/input-output contract；approved/revoked；Tool Bundle Manifest；按语言/攻击面/假设的 Top-K retrieval；Semgrep/Bandit/测试/Harness 基础条目。
- 验收：工具镜像/规则包只按 digest；被撤销工具不能进入新任务；不会把全部 Registry 装入每个 Sandbox；历史成功率不等于当前证据。
- 依赖：I02、I14 contract。
- Out of scope：全自动 Tool Evolution、任意公网下载、新工具自动批准。

### V4-I16 `[P1][Phase 2] 实现 Python Dependency Snapshot、离线 Wheelhouse 与 N0/N1 网络兜底`

- 状态/规模：`status:blocked` / L。
- Primary ownership：`lima/dependencies/`、wheelhouse builder、dependency fixtures/images。
- 不修改：root compose（由 I14 接线）、Mining/Repair 业务。
- 交付：lock/manifest→Resolution Plan→digest-pinned Snapshot；纯 wheel 优先；N0 无网安装；N1 内部测试网络；缓存 miss、私有依赖、sdist/build backend、摘要不匹配的 typed failure；before/after 同 Snapshot。
- 验收：Mining/Repair 在断网下重建同环境；Sandbox 本身不访问公网；失败不自动降级开放互联网；凭据不进入 Snapshot/log；缓存按 tenant/policy/digest 隔离。
- 依赖：I02、I14、I15。
- Blocks：I17、I19。

### V4-I17 `[P1][Phase 3] 完成 CWE-22 Hypothesis→Harness→Oracle→VEP 动态挖掘闭环`

- 状态/规模：`status:blocked` / L；唯一 MVP Mining 纵向切片。
- Primary ownership：`lima/mining/`、CWE-22 fixtures、Harness/Oracle、VEP replay tests。
- 不修改：Repair、其他 CWE、Sandbox/Dependency 实现。
- 交付：reachability probe；canary filesystem；正向/negative control；coverage；重复与最小化；安全不变量；D0–D4；VEP；clean-room replay；environment failure/refuted 分离。
- 验收：支持样本 VEP replay ≥ 90%；D3/D4 无已知 false confirmation；默认预算完成率 ≥ 80%；路径逃逸的实际影响可观测；超时/缺依赖不能确认漏洞。
- 依赖：I04、I05、I12、I14–I16。
- 决策门：未达标不启动 Repair 或新增 CWE。

### V4-I18 `[P1][Phase 4] 实现 2–3 个隔离 Repair Candidate 与最小可解释 Patch`

- 状态/规模：`status:blocked` / L；Repair generation owner。
- Primary ownership：`lima/repair/candidates.py`、`repair_workspace.py`/`security_repair.py` 的兼容扩展。
- 不修改：最终 verifier/gate 裁决、GitHub 发布、原始 snapshot。
- 交付：VEP-only 输入；fresh disposable copy；默认 2、最大 3 候选；候选互相隔离；最小 diff/scope；deterministic template + LLM 多样性；candidate manifest。
- 验收：Mining 可变状态不被复制；候选不能改依赖/关闭功能来绕过；原仓库、cache、GitHub 不被修改；每个候选有独立 patch digest 和解释。
- 依赖：I17，复用 #16。
- Blocks：I19。

### V4-I19 `[P1][Phase 4] 实现独立 Repair Gate、RVR 与 Verified Patch 裁决`

- 状态/规模：`status:blocked` / L；Repair verification owner。
- Primary ownership：`lima/repair/gates.py`、`verification.py`、RVR/clean-room tests。
- 不修改：候选生成策略、GitHub 自动写入。
- 交付：scope→parse/build→原测试→关键回归→PoC/Oracle→独立扫描→行为差分→必要 re-fuzz；same Dependency Snapshot；失败矩阵；RVR/Verified Patch。
- 验收：Security Preservation 与 Functional Preservation 同时通过；任一强制 Gate 失败即淘汰；Verified Patch Yield 基准 ≥ 50%；已知合法回归逃逸为 0；关键 Gate replay ≥ 90%。
- 依赖：I12、I16、I18。
- 决策门：未通过候选永不显示为“已修复”。

### V4-I20 `[P2][Phase 2/5] 建立 H1 PostgreSQL/Artifact 备份、恢复与一致性演练`

- 状态/规模：`status:blocked` / M。
- Primary ownership：`docs/operations/backup-restore.md`、deployment backup scripts/config、recovery test fixtures。
- 不修改：自研数据库复制、业务 schema、队列算法。
- 交付：PostgreSQL base backup + WAL/PITR 或托管等效方案；Artifact versioning/backup；配置/schema/tool manifest/key 备份；引用一致性校验；季度演练 runbook。
- 验收：实测 H1 RPO ≤ 5 min、RTO ≤ 30 min 或记录真实差距；恢复后任务与 Artifact 指针一致；SQLite 明确仅开发使用。
- 依赖：I12、I13。
- Can parallel：I14、I16。

### V4-I21 `[P2][Phase 5] 建立 API/Queue/Worker/Artifact/DB 联合压力、Soak 与故障注入门禁`

- 状态/规模：`status:blocked` / L。
- Primary ownership：`benchmarks/v4/load/`、k6、Worker load generator、chaos fixtures、报告。
- 不修改：核心业务算法；发现瓶颈后另开修复 Issue。
- 交付：micro/smoke/baseline/stress/spike/8–24h soak/fault/adversarial resource；60/25/10/5 工作负载；冷/热 cache；LLM/Dependency 正常、限流、断开。
- 验收：1× 峰值错误率 <1%；5× burst 背压而非崩溃；Control Plane 保持可响应；无持续资源泄漏/残留 Sandbox；重复投递无重复权威结果；容量拐点可复现。
- 依赖：I03、I09、I13、I14、I19。
- Blocks：I22、I25。

### V4-I22 `[P0][Phase 5] 执行 5–10 个真实 Python 仓库试点并作 MVP Go/No-Go`

- 状态/规模：`status:blocked` / L；MVP release gate。
- Primary ownership：试点协议、脱敏结果、人工时间研究、Go/No-Go 报告。
- 不修改：为通过门槛临时改 analyzer、数据标签或 holdout fingerprint。
- 交付：5–10 个 repository-disjoint 仓库；人工 Review Reduction；高风险召回；VEP replay；Verified Patch Yield；总时延/成本；用户反馈；失败原因分类。
- 验收：至少 3 个仓库实际减少专家时间；Review Queue 下降 ≥ 60%；高风险召回不低于 I01；性能/恢复/证据门同时通过；无逐条人工筛告警才能完成闭环。
- 依赖：I01、I06、I09、I10、I17、I19–I21。
- 输出：`GO`、`CONDITIONAL GO` 或 `NO-GO`，并明确停止/继续投资项。

## 8. Post-MVP Gated Issues

这些 Issue 必须创建以保留需求，但标签应为 `status:gated`。没有 I22 的 Go 结论和各自触发指标，不得进入 `status:ready`。

### V4-I23 `[P3][Release 1] Security Case Library v1 与结构化/全文检索`

- 启动条件：I22 Go；已有足够高质量正例、负例与失败 Case。
- Primary ownership：`lima/knowledge/`、Case migration/search indexes/retrieval benchmark。
- 交付：promotion/version/scope/revoke；PostgreSQL exact/JSONB/full-text；Audit/Mining/Repair retrieval；repository-disjoint benchmark；10 万 synthetic Case 查询评测。
- 验收：带 tenant/language/CWE filter 的 p95 ≤ 150 ms；历史 Case 仅影响计划；provenance/质量/撤销可追溯；负例进入排序与评测。
- 依赖：I11、I12、I22。

### V4-I24 `[P3][Release 2] 扩展 CWE-78、CWE-89 与授权绕过的 Python 闭环`

- 启动条件：I17/I19 达标，且 I22 Go。
- Primary ownership：按 CWE 建独立子 Issue；本 Issue 仅作为 Release Epic。
- 交付：每个 CWE 独立 Hypothesis schema、Harness、Oracle、VEP、Repair Gate 和正负基准。
- 验收：任何新 CWE 不得复用不适用 Oracle；每个 CWE 单独达到 replay/false-confirmation/yield 门槛。
- 依赖：I17、I19、I22、I23。
- 拆分要求：实施时至少再拆为 CWE-78、CWE-89、AuthZ 三个不共享主文件的 Task。

### V4-I25 `[P3][Release 3] Beta HA、分布式 Worker 与可选 Redis Streams 扩展`

- 启动条件：I21 证明单机容量成为瓶颈；存在明确用户/SLO；团队具备运维责任。
- Primary ownership：deployment/HA、scheduler distribution、admission control；不修改分析结论。
- 交付：2+ stateless API、托管/主备 PostgreSQL、持久对象存储、冗余 queue、多 Worker、tenant fairness、RPO/RTO 演练。
- 验收：API 99.9% 目标和 RPO/RTO 由演练证明；Redis 不是唯一真相源；网络分区与重复消息保持幂等。
- 依赖：I20–I22。
- Stop：若瓶颈仍是误报、模型或人工流程，不启动。

### V4-I26 `[P3][Release 4] 运行 pgvector/Hybrid RAG 增益与泄漏实验`

- 启动条件：I23 上线；promoted Case 数量达到预注册阈值；结构化+全文 baseline 稳定。
- Primary ownership：retrieval experiment、pgvector migration（实验环境）、ablation report。
- 交付：Top-K recall/MRR、Tool Plan 成功率、Harness 首次成功率、D3 时间、成本、false transfer、tenant leakage；结构化/全文/vector/hybrid 对照。
- 验收：Top-K 至少提升 10% 或调查时间下降 15%，且 false transfer/泄漏不增加；否则关闭实验，不进入生产关键路径。
- 依赖：I23。
- Out of scope：独立向量数据库、全仓源码默认 embedding。

### V4-I27 `[P3][Release 5] 选择性扩展语言、强隔离、Tool Evolution 与 N3 网络`

- 启动条件：I22 Go；由真实需求选择一个方向，不允许四项同时启动。
- Primary ownership：先做决策/威胁模型 Epic，再按 JavaScript/Java/Go、gVisor/VM、Tool Evolution、N3 分别拆 Task。
- 交付：语言/隔离/网络能力与当前 Case/Oracle/Tool Registry 的差距评估；供应链、权限、容量和退出方案。
- 验收：不能降低 V3 三阶段边界；新工具先 quarantine/benchmark/approve；N3 使用短时限域 grant；新语言必须有独立 benchmark 与 Oracle。
- 依赖：I15、I22；具体方向有额外前置。

## 9. Tracking Epic 模板

建议标题：

```text
[Epic][V4] Evidence-driven Python MVP: Fast Audit → CWE-22 Mining → Verified Repair
```

建议正文的任务清单：

```markdown
## Phase 0 — Baseline and contracts
- [ ] V4-I01 Baseline
- [ ] V4-I02 Contracts
- [ ] V4-I03 Telemetry

## Phase 1 — Fast Audit
- [ ] V4-I04 RAM
- [ ] V4-I05 Fusion/Hypothesis
- [ ] V4-I06 CWE-798 noise reduction
- [ ] V4-I07 Tier planner/budgets
- [ ] V4-I08 Audit cache
- [ ] V4-I09 Backend integration/AEP
- [ ] V4-I10 Progressive frontend
- [ ] V4-I11 Case Candidate v0

## Phase 2 — Durable three-sandbox runtime
- [ ] V4-I12 Artifact Registry
- [ ] V4-I13 Lease/idempotency/recovery
- [ ] V4-I14 Sandbox Supervisor
- [ ] V4-I15 Tool Registry v0
- [ ] V4-I16 Dependency Snapshot/N0/N1
- [ ] V4-I20 Backup/restore

## Phase 3/4 — Vertical security loop
- [ ] V4-I17 CWE-22 Mining/VEP
- [ ] V4-I18 Repair candidates
- [ ] V4-I19 Repair gates/RVR

## Phase 5 — Release evidence
- [ ] V4-I21 Load/soak/fault
- [ ] V4-I22 Pilot and Go/No-Go

## Gated post-MVP
- [ ] V4-I23 Security Case Library v1
- [ ] V4-I24 Python CWE expansion
- [ ] V4-I25 Beta HA/distributed workers
- [ ] V4-I26 pgvector/RAG experiment
- [ ] V4-I27 language/isolation/tool evolution/N3
```

Epic 必须记录以下全局决策：

- MVP 只支持 Python、S/M 仓库、单机 Docker、CWE-22 动态闭环；
- CWE-798 只作为 Audit 降噪专项；
- PostgreSQL/SQLite + Artifact Store 是权威源，Redis 可选；
- 历史 Case 不提升当前 Evidence Level；
- 任何 Post-MVP 工作都由 I22 或专项数据门触发；
- 自动提交/合并用户仓库修复不在本 Epic 范围。

## 10. 每个 GitHub Issue 的必填正文

所有正式 Issue 均应包含：

```markdown
## Status / Size
## Problem to solve
## Primary ownership
## Avoid modifying / Out of scope
## Contract inputs and outputs
## Security invariants
## Acceptance criteria
## Required tests and evidence
## Dependencies / Blocks / Can run in parallel
## Rollback or migration notes
```

认领人必须把验收条件映射为测试，不得把“实现完成”作为唯一验收证据。

## 11. 建议 GitHub 标签

如果仓库暂无这些标签，管理员可按需建立；标签不应成为创建 Issue 的阻塞条件。

| 类别 | 标签 |
|---|---|
| 状态 | `status:ready`、`status:blocked`、`status:gated`、`status:in-progress` |
| 优先级 | `priority:p0`、`priority:p1`、`priority:p2`、`priority:p3` |
| 阶段 | `area:audit`、`area:mining`、`area:repair`、`area:runtime`、`area:knowledge`、`area:frontend`、`area:evaluation` |
| 风险 | `security-boundary`、`schema-migration`、`cost-bearing` |
| 规模 | `size:s`、`size:m`、`size:l` |

MVP 的 `status:gated` Issue 不应被分配给开发者，也不应放入当前 Sprint。

## 12. PR 与验收规则

每个 V4 PR 除项目通用门禁外，至少满足：

1. `Closes #<issue>`，标题保留 `V4-Ixx`；
2. 只修改 Issue Ownership 内文件；例外必须在 Epic 留言协调；
3. 危险样本、安全近邻、不确定形态和基础设施失败均有测试；
4. 不执行不可信仓库代码的 Issue 必须有“未发生执行/联网”的负面断言；
5. Sandbox/Dependency/Repair 变更必须声明权限、网络、凭据和文件系统差异；
6. Analyzer/Case/Retrieval 变更必须声明 dataset fingerprint 和 repository-disjoint 影响；
7. 性能结论必须绑定硬件、冷/热缓存、版本和样本等级；
8. 所有 generated evidence 均脱敏，私有源码、真实 Secret、Token 和生产日志不得提交；
9. Integration PR 必须在 Leaf PR 合并后 rebase，并跑端到端 Gate；
10. `merge-gate`、Code Owner review 和会话解决后才可合并。

## 13. 阶段 Definition of Done

### Phase 0

- I01 基线可重复；
- I02 schema 有 golden fixtures；
- I03 能解释每任务成本与预算停止；
- 未达到基线稳定性时不扩大架构。

### Phase 1

- LlamaFactory 人工队列下降至少 60%；
- 高风险召回不低于基线；
- M 仓库 Fast Audit p95 ≤ 5 分钟；
- 用户看到 Issue/Hypothesis 和证据缺口，而不是 896 个重复 Signal。

### Phase 2

- 三 Sandbox 不直连、不共享可写状态；
- 无已接受任务/已封存 Artifact 丢失；
- 重复投递不产生重复权威结果；
- Mining/Repair 可在断网下用同一 Dependency Snapshot 重建；
- cleanup 失败会隔离而不是静默复用节点。

### Phase 3/4

- CWE-22 VEP clean-room replay ≥ 90%；
- D3/D4 无已知 false confirmation；
- Repair 同时通过 Security 与 Functional Gate；
- Verified Patch Yield ≥ 50%，已知合法回归逃逸为 0。

### Phase 5

- 1× 峰值可持续，5× burst 可背压；
- 8–24 小时 soak 无持续泄漏；
- 备份恢复实测 RPO/RTO；
- 至少 3 个真实仓库减少专家时间；
- I22 形成可审计 Go/No-Go，而不是主观“感觉可用”。

## 14. Issue 发布与维护流程

1. 先创建 I01、I02 和 Tracking Epic；
2. 按依赖拓扑创建其余 Tasks，正文使用真实 `#number` 回链；
3. Epic 用 checklist 关联全部 Issue；
4. 为 I01/I02 标记 ready，其余按依赖标记 blocked/gated；
5. 每次 Leaf 合并后，由维护者更新下游状态，不提前认领 blocked Issue；
6. 每个阶段决策门结束后，更新 Epic 的指标、结论和下一批 ready 列表；
7. Scope 变化必须同时更新 V4 规划、本 Backlog 和相关 Issue，不能只在聊天中改变；
8. Issue 关闭时记录 PR、验证结果、Artifact/benchmark 链接和遗留项；
9. 若验收失败，Issue 保持 open 或拆 follow-up，不以“代码已写”关闭；
10. I22 No-Go 时冻结 I23–I27，并把资源投入到未达标主路径。

## 15. 最终取舍

本拆分刻意把“架构必要性”和“立即开发”分开：

```text
现在必须落实：
  可测基线 → Fast Audit → 可恢复三 Sandbox
  → CWE-22 VEP → Verified Repair → 压测与真实试点

现在必须建 Issue、但不能开工：
  完整 Case Library、更多 CWE、HA、向量/RAG、多语言与强隔离
```

这能保证后续需求不会丢失，同时避免所有“未来可能必要”的能力同时进入当前工期。对多人项目而言，最重要的不是 Issue 数量少，而是每个 Issue 都能独立认领、独立验证、清楚知道不能修改什么，并且只有极少数 Integration Issue 触碰高冲突主链路。
