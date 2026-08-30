# LIMA 可用性、性能与安全知识库迭代规划（V4）

> 分析基线：`main` / `bf7d79d`（2026-08-31）
> 继承文档：V2 证据驱动三阶段平台、V3 三沙箱通信与依赖网络治理
> 本版主题：工程取舍、运行速度、容量、高可用、压测、持久化、检索与跨仓库安全知识复用
> 文档性质：产品与工程实施规划，不包含业务代码修改
> 核心结论：**保留 V3 作为目标架构，但不按 V3 的全量清单同步开工；以 14–16 周的单语言纵向 MVP 先证明可用性和价值。**

## 1. 决策摘要

面对 V3 的工程量，正确选择不是“全部做完再使用”，也不是“因为太大而退回简单扫描器”，而是将规划拆成两个层次：

```text
V3 = North-star Architecture
     规定不能破坏的安全边界和长期方向

V4 = Execution Plan
     规定当前必须交付、可以延后和需要数据证明的内容
```

建议做明确取舍：

1. **一期只支持 Python、中小型仓库和单机 Docker Worker。**
2. **一期只做一个完整动态闭环：路径穿越 CWE-22。** 同时保留 CWE-798 作为 Audit 降噪专项，用来证明“减少人工队列”。
3. **一期不做 Kubernetes、gVisor、多语言、跨区域 HA、全自动 Tool Evolution、独立向量数据库、图数据库和 Kafka。**
4. **一期优先实现可恢复，而不是完整高可用。** 长任务可 checkpoint、Worker 可重试、Artifact 不丢，比一开始追求多活更重要。
5. **信息需要持久化，但不是所有信息都永久保存。** 安全证据、任务状态和晋升后的知识 Case 必须持久化；Sandbox scratch、可重建 AST 和大部分原始日志按 TTL 清理。
6. **安全知识库值得做，但第一版不是“把所有源码向量化”。** 应先建立结构化 Security Case Library，使用 PostgreSQL 关系字段、JSONB、边表与全文检索；向量检索只有在离线评测证明增益后才启用。
7. **RAG 是知识消费方式，不是数据库替代品。** 检索到的历史案例只能帮助产生 Hypothesis、Tool Plan、Oracle 和 Repair Pattern，不能直接证明当前仓库存在漏洞。
8. **速度通过分层预算、异步执行、增量缓存和主动停止获得，而不是通过降低证据门槛获得。**
9. **每个阶段都有继续投资门槛。** 如果 Audit 不能显著压缩人工队列，就不应急着扩大 Mining；如果 VEP 无法稳定重放，就不应自动修复；如果向量检索没有明显增益，就不引入。

推荐的产品体验是：

```text
任务提交 < 1 秒
  ↓
30–60 秒内看到仓库画像和扫描进度
  ↓
数分钟内得到可处置 Audit 结果
  ↓
Mining / Repair 异步运行、持续展示证据和 Gate
  ↓
只有高价值问题消耗昂贵算力
```

LIMA 不需要把所有高级基础设施一次建齐。它首先需要证明三件事：

- 比原始扫描器显著减少专家工作量；
- 对支持的漏洞类型能够稳定复现并形成 VEP；
- 修复候选能在可接受时间与成本内通过安全/功能双 Gate。

只有这三件事成立，知识库、HA、多语言和分布式调度才有扩大投资的意义。

---

## 2. 当前工程基础与真实起点

当前 `main` 并非原型空壳。按本次基线统计：

| 项 | 当前规模/能力 |
|---|---:|
| Python 业务源码 | 52 个文件，约 21,467 行 |
| 测试代码 | 37 个文件，约 8,191 行 |
| 数据存储 | SQLite 开发模式、PostgreSQL 生产适配 |
| 队列 | Redis Streams 或本地 ACK 队列 |
| 长任务 | checkpoint、resume、预算和 ambiguous retry |
| 仓库缓存 | 有界、内容寻址、固定 revision、pin/release |
| 实验 | run、dataset hash、Artifact checksum、恢复与取消 |
| 可观测性 | Prometheus metrics、可选 OpenTelemetry tracing、持久化告警 |
| Repair | 固定 snapshot 的一次性 workspace 基础 |

LlamaFactory 截图显示，当前对 444 个 UTF-8 文件、约 2.68 MB 源码的基础扫描耗时约 24 秒。这个数字只代表当前静态扫描快路径，不代表未来包含语义画像、深度分析、Mining 和 Repair 的总时延，但它是重要性能基线：

> 新架构不应让所有仓库无差别进入昂贵流程，也不能把一个几十秒的基础扫描变成用户必须同步等待数十分钟的黑盒。

因此 V4 的工作不是重新搭一套通用分布式平台，而是优先复用现有模块：

- `repository_cache.py` 和 materializer 作为增量与内容寻址基础；
- `task_queue.py`、checkpoint 和 experiments 作为可恢复任务基础；
- PostgreSQL/SQLite store 作为结构化事实存储；
- Redis Streams 继续作为可选队列，而不是新增必选组件；
- Prometheus/OpenTelemetry 作为性能和可靠性评估基础；
- `repair_workspace.py` 作为候选一次性副本基础；
- V2/V3 的 Artifact 和 Sandbox 边界作为不能绕过的架构约束。

---

## 3. “可用”的定义

LIMA 的可用性不能只看“功能能运行”，应同时满足六个维度。

### 3.1 结果可用

- 原始 Signal 被压缩为少量 Issue/Hypothesis；
- 高风险结论有可复现证据；
- 用户能理解升级、关闭和未决的原因；
- 修复结果不是建议，而是明确 Gate Matrix。

### 3.2 时间可用

- 用户在一分钟内获得可见进度和初步画像；
- Audit 的主要结果在数分钟级，而不是小时级；
- Mining/Repair 异步运行，有预算、停止条件和 ETA；
- 相同 snapshot 的重复分析能够显著复用缓存。

### 3.3 系统可恢复

- API 重启不丢已提交任务；
- Worker 崩溃可从 Artifact/checkpoint 重试；
- 重复投递不产生两个权威结论；
- 长任务中断后无需从仓库导入重新开始；
- 已封存 VEP/RVR 不依赖临时容器继续存在。

### 3.4 容量可控

- 自动测试、Fuzz 和多候选 Repair 不会挤死 Control Plane；
- 队列具备背压、公平性和每租户/每仓库预算；
- CPU、内存、磁盘、PID、LLM Token、外部 API rate limit 均被调度；
- 超载时延迟低优先任务，而不是牺牲证据完整性。

### 3.5 成本可解释

- 每个 Issue、VEP 和 Verified Patch 有工具时间、CPU-hour、Token 和存储成本；
- 能说明缓存、检索和历史 Case 节省了多少时间；
- 无收益的深度分析和候选能被主动停止。

### 3.6 运维可用

- 能区分系统故障、环境故障、工具故障和安全结论；
- 有队列、Worker、数据库、Artifact、依赖缓存和模型调用指标；
- 有备份恢复演练，而不只是在配置中声明“支持 HA”；
- 压测结果可重复，并作为发布门禁。

---

## 4. 必须做、延后做与暂不做

### 4.1 MVP 必须做

| 能力 | MVP 范围 |
|---|---|
| 语言 | Python |
| 仓库 | GitHub/现有导入能力，中小型仓库 |
| Audit | 全仓 Tier 0 + 高价值 Tier 1；Issue 聚类、CWE-798 降噪 |
| Sandbox | 单机 Docker，Audit/Mining/Repair 三种 policy profile |
| Artifact | 本地内容寻址文件存储 + PostgreSQL/SQLite 元数据 |
| 通信 | 现有队列扩展 lease/attempt；inbox/outbox |
| 网络 | N0 无网、N1 内部测试网络；N3 暂不开放 |
| 依赖 | Python wheelhouse/Dependency Snapshot 最小实现 |
| Mining | CWE-22 单一纵向场景，Harness + Oracle + VEP |
| Repair | 最多 3 个候选，核心 Gate，Verified Patch/RVR |
| 可恢复 | checkpoint、Artifact 幂等、Worker 重试 |
| 性能 | 分层预算、缓存、压测和 soak test |
| 知识库 | 结构化 Security Case v1 + 精确/全文检索 |

### 4.2 验证价值后再做

| 能力 | 启动条件 |
|---|---|
| pgvector/向量检索 | 已有足够高质量 Case，离线评测证明结构化+全文之外有增益 |
| Redis 作为必选队列/缓存 | PostgreSQL/本地队列在目标并发下成为可测瓶颈 |
| Kubernetes Worker | 单机 Worker 资源、调度或隔离成为瓶颈，且有实际并发需求 |
| gVisor/VM | 高风险原生工作负载或隔离评审要求 |
| CodeQL/Pysa/Joern 深度组合 | Issue 模型稳定，新工具不会直接扩大用户告警 |
| Java/JavaScript/Go | Python 纵向闭环达到发布 Gate |
| 自动 Tool Evolution | Tool Registry、评测、撤销和供应链治理成熟 |
| 高可用 Control Plane | Beta 用户和任务量需要明确 SLO |
| N3 受限外联 | 本地 stub/Dependency Gateway 无法覆盖的真实用例存在 |

### 4.3 当前明确不做

- 自研通用静态分析器、Fuzzer、容器运行时或向量数据库；
- 微服务化拆分所有逻辑模块；
- Kafka/Pulsar 等独立流平台；
- 独立图数据库；
- 跨区域多活；
- 自动访问任意公网安装工具；
- 全仓源码默认向量化；
- 历史 Case 直接自动确认新漏洞；
- 同时支持十余种 CWE 的动态验证；
- 自动提交或合并修复到用户主分支。

---

## 5. 运行速度与用户时延预算

### 5.1 先定义仓库工作负载等级

所有性能数字必须绑定固定硬件、工具版本、冷/热缓存和仓库等级。

| 等级 | 建议定义 | 默认产品策略 |
|---|---|---|
| S | ≤ 20k LOC、≤ 500 文件 | 全功能 MVP |
| M | 20k–200k LOC、≤ 5k 文件 | 全功能，深度预算受限 |
| L | 200k–1M LOC、≤ 20k 文件 | 分区 Audit，Top Hypothesis Mining |
| XL | > 1M LOC 或 monorepo | 必须选择子项目/自定义预算，MVP 不承诺 |

LOC 不是唯一变量，还应记录语言数、依赖数、生成代码、调用图规模、测试数量、构建时长和工具内存峰值。

### 5.2 用户感知 SLO（初始建议）

以下目标需在固定参考机上校准，不应作为脱离硬件的营销承诺：

| 用户动作 | Beta 目标 |
|---|---:|
| 创建任务 API p95 | < 500 ms |
| 查询列表/详情 API p95 | < 300 ms |
| 状态事件可见延迟 p95 | < 2 s |
| S/M 仓库 inventory 首次结果 | 30–60 s |
| M 仓库 Fast Audit p50 | ≤ 2 min |
| M 仓库 Fast Audit p95 | ≤ 5 min |
| M 仓库完整 Audit p95 | ≤ 15 min |
| 单 Hypothesis Mining 默认预算 | 10 min |
| 单 Hypothesis Mining 硬上限 | 30 min，需策略覆盖 |
| 单 Repair Candidate 默认预算 | 10 min |
| 单 Repair Candidate 硬上限 | 20 min |
| 每漏洞候选数 | 默认 2，最大 3 |

更稳妥的相对门槛：同一参考仓库的 Tier 0 Audit p95 不应超过当前确定性基础扫描的 3 倍；超出部分必须能解释为新增工具、冷启动或外部模型等待。

Mining 和 Repair 不应进入同步 HTTP 请求。用户看到的是可取消、可恢复、分阶段出结果的后台任务。

### 5.3 Fast Path 与 Deep Path

```text
Fast Path
  Snapshot/Cache Check
  → Inventory
  → Tier 0 Scan
  → Issue Cluster
  → Initial AEP/UI

Deep Path（异步）
  Architecture Reasoning
  → Tier 1/2 Tool Planning
  → Evidence Fusion
  → Top Hypotheses
  → Mining / Repair
```

Fast Path 的输出可以继续被 Deep Path 修订，但每次修订是新的 Artifact revision。用户无需等待全部工具完成才看到仓库风险概览。

### 5.4 强制预算与停止条件

#### Audit

- Tier 0 全仓执行；
- Tier 1 默认只分析最高价值的 10–20 个 Issue Cluster；
- Tier 2 默认只为 3–5 个 Hypothesis 准备 Mining；
- 单工具超时、内存和输出有硬上限；
- 同一证据 Claim 已充分支持/反驳后停止继续堆工具；
- LLM 只处理 Issue/Evidence Slice，不逐文件通读。

#### Mining

- 每仓库默认最多同时挖掘 3 个 Hypothesis；
- 先运行最便宜的 reachability probe，再构建完整环境；
- 路径不可达且静态反证充分时停止；
- coverage 长时间不增长、Fuzz 无新路径或预算耗尽时停止；
- 达到稳定 D3/D4 后进入最小化，而不是继续无限 fuzz；
- environment failure 不消耗漏洞重试预算。

#### Repair

- 默认生成 2 个候选，只有多样性不足时增加到 3；
- 先运行 parse/build/scope 等廉价 Gate；
- 任一强制 Gate 失败立即淘汰；
- 只有剩余候选运行完整测试和 re-fuzz；
- 已有确定性修复模板时，不强制调用多个 LLM；
- 全部候选失败则停止并返回失败矩阵。

### 5.5 并发与背压

将工作分为独立资源池：

```text
audit-light
analysis-heavy
mining-exec
repair-test
llm-requests
artifact-io
dependency-fetch
```

调度器根据 CPU、内存、磁盘、PID、GPU（如有）、Token、外部 rate limit 和 tenant quota 计算可用 slot：

```text
available_slots = min(
  cpu_available / task_cpu,
  memory_available / task_memory,
  disk_available / task_disk,
  policy_concurrency_limit
)
```

策略：

- API/Control Plane 与重型 Worker 资源隔离；
- 同一仓库避免重复运行相同 tool/snapshot/config；
- Repair candidate 并发受内存和测试环境限制；
- Weighted Fair Queue 防止一个大仓库占满系统；
- 队列超过阈值时停止接受低优先级 Deep Path，而 Fast Audit 仍可服务；
- LLM 429/配额不足时暂停语义任务，不阻塞已完成静态结果；
- Dependency cache stampede 通过单飞锁和内容寻址去重。

### 5.6 缓存与增量策略

优先实现以下高收益缓存：

| 缓存 | Key | 失效条件 |
|---|---|---|
| Repository Snapshot | provider + repo + commit digest | commit 变化 |
| File Parse | file hash + parser version + config | 文件/解析器变化 |
| Tool Result | snapshot/scope hash + tool/rules/config digest | 任一输入变化 |
| Repository Model | snapshot + extractor/schema version | 源码/提取器变化 |
| Evidence Cluster | normalized signal digests + clustering version | 信号/算法变化 |
| Dependency Snapshot | lock + platform + resolver/policy digest | 依赖/平台/策略变化 |
| LLM Result | evidence slice + prompt/model/policy version | 任一输入变化 |
| Repair Gate | base snapshot + patch digest + gate/env version | Patch/Gate/环境变化 |

缓存命中必须校验 digest 和租户边界。缓存只复用分析结果，不复用 Mining/Repair 的可变运行状态。

增量分析优先于更大机器：

- 变更文件重新解析；
- 受影响调用图子图失效；
- 规则/工具未变化时复用其他结果；
- Issue identity 保持稳定；
- 新 commit 只重跑受影响 Hypothesis 和 Gate；
- 定期全量运行校验增量没有产生盲区。

---

## 6. 高可用：先可恢复，再多副本

### 6.1 为什么一期不应先做完整 HA

LIMA 的主工作负载是分钟到小时级后台任务。最常见损失不是 API 短暂停机，而是：

- 长任务因 Worker 崩溃从头运行；
- Artifact 已生成但状态未提交；
- 重试产生重复模型费用或重复权威结论；
- Repair workspace 丢失却被错误标记成功；
- 队列消息丢失；
- 数据库恢复后无法关联 Artifact。

因此一期优先级应为：

```text
Durability
→ Idempotency
→ Resume/Retry
→ Backup/Restore
→ Stateless API Replicas
→ Database/Queue HA
```

### 6.2 可用性等级

| 等级 | 适用 | 架构 | 目标 |
|---|---|---|---|
| H0 开发 | 单人、本地 | SQLite + 本地 Artifact + 本地 ACK | 数据可导出，允许手工恢复 |
| H1 MVP/Beta | 小团队试用 | 单 Control Plane + PostgreSQL + 持久 Artifact + 可重启 Worker | 无已提交任务/Artifact 丢失；RPO ≤ 5 min，RTO ≤ 30 min（演练后确认） |
| H2 生产 | 有明确用户/SLO | 2+ 无状态 API、托管/主备 PostgreSQL、持久对象存储、冗余队列、多个 Worker | API 99.9%；RPO ≤ 1 min，RTO ≤ 10 min（按部署能力校准） |
| H3 大规模 | 多租户/跨区 | 分区调度、跨 AZ、灾备集群 | 只有业务量证明后设计 |

数字必须通过故障演练验证，不能只写进配置或 SLA。

### 6.3 MVP 持久化拓扑

```text
Stateless-ish API / Scheduler
            │
        PostgreSQL
   task / state / metadata
            │
Content-addressed Artifact Store
   local durable volume or S3-compatible
            │
Ephemeral Workers
 checkpoint / inbox / outbox
```

Redis 在 MVP 中是可选加速/队列，不是权威事实存储。Redis Streams 可以提供 consumer group、ACK 和 pending reclaim，但其持久性取决于 AOF/RDB、复制和部署策略；因此最终任务状态和 Artifact 指针仍应落 PostgreSQL。

### 6.4 必须实现的恢复场景

- API 进程重启；
- Scheduler 重启；
- Worker 在 Tool 执行中被杀；
- Worker 在 Artifact 上传前/后崩溃；
- Redis 重启或消息重复；
- PostgreSQL 短暂断连；
- Artifact Store 暂时不可用；
- LLM 请求已计费但结果未落盘；
- Dependency Gateway 不可用；
- Sandbox cleanup 失败；
- 整机重启。

每种场景都应定义：权威状态、可重试点、是否产生新 attempt、费用处理、partial Artifact 和人工介入条件。

### 6.5 备份与恢复

Beta 至少需要：

- PostgreSQL 定期 base backup + WAL/PITR 或托管等效能力；
- Artifact Store 版本化/不可变策略和异地备份；
- 配置、Schema、Tool manifest、规则包和签名密钥备份；
- 每季度恢复演练，验证数据库与 Artifact 引用一致；
- RPO/RTO 从实际演练获得；
- SQLite 仅用于开发，不承担团队生产 HA。

PostgreSQL 的主备和 WAL/PITR 是成熟能力，应使用托管服务或标准方案，不在 LIMA 内自研复制协议。

---

## 7. 自动测试压力与容量验证

### 7.1 两类压力必须分开

#### 平台请求压力

- 用户提交/查询任务；
- UI 轮询或事件流；
- Artifact 元数据查询；
- 多仓库并发；
- 队列与数据库热点。

#### 安全执行压力

- 多 Tool Worker 冷启动；
- 多个 Fuzzer 长时间占 CPU；
- Repair 候选并行跑测试；
- 大量 stdout/coverage/trace 写入；
- 依赖并发下载和 cache stampede；
- 恶意仓库触发 fork bomb、内存或磁盘压力。

只压 API 无法证明系统能承受自动测试；只跑几个端到端任务也无法发现控制面瓶颈。

### 7.2 压测层级

| 测试 | 频率 | 内容 |
|---|---|---|
| Microbenchmark | 每次相关 PR | parser、cluster、search、Artifact hash、DB query |
| Smoke load | 每次主分支构建 | 少量并发提交/查询/取消 |
| Baseline load | 每日/每周 | 目标峰值并发和固定仓库集 |
| Stress | 发布前 | 逐步升压到背压触发，寻找容量拐点 |
| Spike | 发布前 | 短时 5× 任务提交，验证 admission control |
| Soak | 每周/大版本 | 8–24 小时，检查泄漏、队列、缓存和清理 |
| Chaos/Fault | 每个里程碑 | kill Worker、断 DB/Store/Proxy、重复消息 |
| Adversarial resource | 安全版本 | fork、OOM、输出洪泛、压缩炸弹、慢请求 |

可使用 k6 对 API/事件流建立可重复负载和 threshold；重型 Worker 压测需要专用任务生成器，不能只靠 HTTP 虚拟用户。

### 7.3 工作负载模型

在真实流量出现前，建议构造固定组合：

```text
60% S 仓库 Fast Audit
25% M 仓库完整 Audit
10% Mining
5% Repair
```

分别运行：

- 1× 预期峰值 8 小时；
- 2× 预期峰值 30–60 分钟；
- 5× 提交 burst，验证排队而非崩溃；
- 冷缓存和热缓存两套；
- LLM/Dependency Gateway 正常、限流、断开三种模式。

预期峰值应来自试点用户，不应凭空假设。Beta 初期可先以 10 个并发仓库、8–16 个 Worker slot 为参考实验规模，再根据硬件与任务混合校准。

### 7.4 初始发布门槛

- 不丢已接受任务；
- 不产生重复权威 AEP/VEP/RVR；
- API p95 达到第 5.2 节目标；
- 预期峰值下队列可稳定，2× 压力后能在合理时间排空；
- Control Plane CPU/内存不会被 Worker 饥饿；
- intentional overload 触发 429/排队/降级，而不是 5xx 风暴；
- Worker cleanup 成功率 100%，失败节点立即隔离；
- Artifact digest/Schema 错误率为 0；
- 8 小时 soak 后无持续内存、文件描述符、volume 和 queue pending 增长；
- 缓存击穿不会导致公网请求或重复大规模下载；
- 任务取消后资源在 SLO 内释放；
- 故障注入后任务状态与 Artifact 一致。

性能门禁初期以 warning 为主；在基准稳定后才转成阻断发布，避免错误阈值造成虚假安全感。

---

## 8. 信息是否需要持久化：分层答案

结论是：**必须持久化权威事实，但不应把所有中间数据永久保存。**

### 8.1 P0：必须持久化

| 数据 | 原因 |
|---|---|
| Repository identity、commit、snapshot digest | 复现与防止版本错配 |
| Task/attempt/lease/checkpoint | 恢复、幂等和费用控制 |
| Artifact Envelope 与 lineage | 跨阶段事实链 |
| RAM/AEP/VEP/RVR | 系统核心交付物 |
| Tool/Rule/DB/Dependency/Network manifest | 环境与供应链复现 |
| Gate Result 与 Verified Patch digest | 修复可信性 |
| Expert decision/label/appeal | 评测和知识晋升 |
| Policy/Schema/model/prompt/tool version | 解释历史结果 |
| Audit/security events | 责任与异常调查 |

### 8.2 P1：按 TTL 或价值持久化

| 数据 | 建议 |
|---|---|
| 原始工具输出 | 30–90 天，VEP/RVR 引用则延长 |
| stdout/stderr | 脱敏摘要长期；原始日志短 TTL |
| coverage/trace | 已确认漏洞和修复保留；普通运行 TTL |
| AST/CFG/CPG | 可重建缓存，按 snapshot/tool digest TTL |
| LLM 输入/输出 | 保存结构化输出与引用；完整上下文按隐私策略短期 |
| Fuzz corpus | 产生新 coverage/crash 的保留，其余压缩/淘汰 |
| Dependency/Tool cache | 引用计数 + TTL + quota |
| Failed workspace | 默认删除；需要取证时隔离短期保留 |

### 8.3 P2：任务结束即删除

- Sandbox writable layer；
- 进程、socket、内部测试网络；
- 临时凭据和 canary token；
- 未被引用的中间编译产物；
- LLM 临时 scratch/reasoning；
- 未通过安全校验的任意可执行临时文件，除非进入隔离取证区。

### 8.4 推荐存储分工

```text
PostgreSQL
  权威元数据、状态、关系、检索字段、标签、统计

Content-addressed Object/File Store
  源码快照、工具输出、图、日志、PoC、Patch、大型 Artifact

Redis（可选）
  队列、短期 cache、rate limit、lease acceleration
  不作为唯一权威事实

Vector Index（可选、后置）
  已晋升 Security Case 的 embedding
  不保存唯一正文和证据
```

---

## 9. 是否需要漏洞“数据库”：需要，但要存正确的东西

### 9.1 漏洞确实有共性，但结论不能直接迁移

可复用的共性包括：

- Source/Sink 与危险 API 组合；
- 缺失或错误的 sanitizer/validator；
- 信任边界与攻击者能力；
- 典型调用/控制流形态；
- 安全不变量；
- Harness/Oracle 模板；
- 负对照和常见误报；
- 有效工具与规则组合；
- 修复模式与回归风险；
- 框架、版本和部署前提。

不能直接迁移的是：

- “另一个仓库确认过，所以当前也是漏洞”；
- 未经校准的 severity/confidence；
- 私有仓库代码片段；
- 环境特有权限、配置和业务语义；
- 没有 provenance 的 Agent memory；
- 原始扫描器告警堆积。

因此应建设的是 **Security Case Library**，而不是 Finding Warehouse。

### 9.2 Security Case 数据模型

每个 Case 来源于已评审 AEP、VEP、RVR 或明确误报，建议包含：

| 分类 | 字段 |
|---|---|
| Identity | case_id、version、status、scope、tenant、provenance |
| Taxonomy | CWE、CAPEC/攻击技术、风险类别 |
| Context | language、framework、version range、repo/component type |
| Architecture | entry point、asset、trust boundary、identity/role |
| Pattern | source、transform、sink、call/control/dataflow fingerprint |
| Preconditions | config、permission、platform、dependency、attacker capability |
| Security Invariant | 被保护属性及可观察破坏 |
| Positive Evidence | 静态链路、动态复现、impact、coverage |
| Negative Evidence | sanitizer、不可达、协议 token、测试 fixture、环境限制 |
| Validation | Harness/Oracle template、fixture、observer、stability rule |
| Repair | fix pattern、API replacement、patch shape、regression risks |
| Tooling | 有效/无效工具、配置、耗时、成本、失败原因 |
| Quality | evidence level、replay rate、expert review、known limitations |
| Privacy | public/tenant/project scope、redaction、license、retention |
| Lifecycle | candidate、evaluated、promoted、deprecated、revoked |

正例和负例必须同等重要。只有正例的知识库会强化误报；LlamaFactory 中协议 token 被误认作硬编码凭据，就是需要沉淀为 Negative Case 的典型模式。

### 9.3 知识产生流程

```text
AEP/VEP/RVR/Expert Decision
        ↓
Case Candidate Extraction
        ↓
Root-cause Normalize + Deduplicate
        ↓
Remove raw/private identifiers
        ↓
Privacy / License / Provenance Check
        ↓
Replay and Holdout Evaluation
        ↓
Human/Policy Promotion
        ↓
Versioned Security Case
        ↓
Usage Metrics / Deprecation / Revocation
```

不能把每次 Agent 生成的总结直接在线写入全局知识库。初期采用离线晋升，避免错误和恶意仓库污染后续任务。

### 9.4 知识作用位置

| 阶段 | 可帮助的决策 | 不可替代的证据 |
|---|---|---|
| Audit | 架构模式、危险路径、误报反证、工具选择 | 当前源码与静态路径 |
| Mining | Harness/Oracle 模板、环境准备、工具组合 | 当前 Sandbox 运行证据 |
| Repair | 修复模式、回归风险、候选多样性 | 当前 Patch 的 Gate 结果 |
| Evaluation | 构造 benchmark、holdout 和 regression | 当前版本实际评测 |

历史知识提供 prior 和 plan，不提供 verdict。

---

## 10. 检索路线：关系/全文优先，向量与 RAG 后置

### 10.1 第一阶段：结构化过滤

多数安全查询具有强结构条件：

```text
language = python
framework = fastapi
CWE = 22
source = HTTP path parameter
sink = pathlib/open
attacker_auth = anonymous
evidence_level >= E4
```

这些应首先由 PostgreSQL B-tree/GIN/JSONB/边表完成，具有可解释、可过滤、可授权和易评测的优势。

建议表：

```text
security_cases
case_patterns
case_preconditions
case_evidence_refs
case_oracle_templates
case_repair_patterns
case_tool_metrics
case_negative_patterns
case_edges
case_embeddings（后置）
```

### 10.2 第二阶段：全文检索

对摘要、框架习惯、错误信息、业务语义和修复说明使用 PostgreSQL Full Text Search。GIN 是 PostgreSQL 推荐的全文索引类型，足以支撑 MVP 级 Case 规模。

检索顺序：

```text
权限/租户过滤
→ language/framework/CWE/source/sink 精确过滤
→ 结构指纹与标签匹配
→ 全文召回
→ Evidence Quality/Context Fit 重排
```

### 10.3 第三阶段：pgvector 实验

只有满足以下条件才引入向量列：

1. 至少积累数百个经过晋升、去重和脱敏的高质量 Case；
2. 建立 repository-disjoint 检索 benchmark；
3. 结构化+全文的 Top-K 召回存在明确缺口；
4. 选定 embedding 模型、版本、维度、数据外发和重建策略；
5. 能测量 false transfer、tenant filter 和查询成本。

优先使用 PostgreSQL + pgvector，而不是立即部署独立向量数据库，因为：

- 现有系统已支持 PostgreSQL；
- Case 正文、权限、质量和向量可以事务关联；
- 支持 exact/approximate nearest-neighbor 与 HNSW/IVFFlat；
- 可以与结构化过滤和全文组合；
- 运维面更小。

只有达到百万级 embedding、复杂多模态索引或 PostgreSQL 明确成为瓶颈时，再评估独立向量服务。

### 10.4 RAG 的正确位置

```text
Current Issue/Hypothesis
        ↓
Structured + Full-text + Optional Vector Retrieval
        ↓
Top Cases with provenance and quality
        ↓
LLM generates Tool/Validation/Repair Plan
        ↓
Current Repository Evidence Collection
        ↓
Normal Evidence Gate
```

RAG 输出必须引用 case_id/version，并明确哪些内容来自历史、哪些来自当前仓库。历史 Case 不能提高当前 Evidence Level，除非当前工具或运行结果重新证明相同 Claim。

### 10.5 向量/RAG 投资门槛

与结构化+全文 baseline 比较：

- Top-5/Top-10 relevant case recall；
- Mean Reciprocal Rank；
- 工具选择成功率；
- Harness 首次运行成功率；
- 达到 D3 的平均时间；
- Token/CPU/人工时间；
- false transfer 和误导率；
- private/tenant leakage 测试。

建议门槛：向量混合检索至少带来 10% 的 Top-K 召回提升，或让调查时间下降 15%，且不显著增加 false transfer；否则保留结构化+全文方案。阈值可根据首轮数据校准。

检索性能也应进入压测：在 10 万条 promoted Case 的参考数据集上，带租户与语言/CWE 过滤的结构化+全文查询 p95 目标为 150 ms；可选混合向量查询 p95 目标为 300 ms。实际规模不足 10 万时仍使用合成扩容数据验证索引与权限过滤，避免等知识库增长后才发现查询模型不可扩展。

### 10.6 Redis 的定位

Redis 适合：

- Streams/consumer groups；
- 短期查询/模型结果缓存；
- rate limit、debounce、single-flight；
- 实时进度和临时 lease acceleration。

Redis 不适合承担：

- 唯一 AEP/VEP/RVR；
- 唯一 Case 正文；
- 唯一任务完成状态；
- 依赖和 Patch 的唯一 provenance。

如果 PostgreSQL 队列与应用内 cache 已满足 Beta 负载，就暂不把 Redis 设为部署硬依赖。

---

## 11. 知识库的安全、隐私与抗污染

### 11.1 知识作用域

| 级别 | 内容 | 可见性 |
|---|---|---|
| Public Pattern | 通用 CWE、公开漏洞、脱敏模板 | 所有租户 |
| Organization Case | 组织批准的内部模式 | 同组织 |
| Project Case | 包含项目语义或私有接口 | 仅项目 |
| Raw Evidence | 源码、PoC、日志、secret/canary | 严格 Artifact ACL |

跨租户复用只使用公共或经过彻底脱敏和授权晋升的 Pattern。embedding 同样可能泄露语义，不能绕过作用域控制。

### 11.2 防知识投毒

- 只有 E4/E5 VEP、通过 Gate 的 RVR 或专家确认负例可自动成为高优先 Case Candidate；
- 单一 Agent 总结不能直接 promoted；
- 来源仓库、工具、模型、时间和证据等级可追溯；
- repository-disjoint holdout 防止记忆同一仓库；
- Case 有有效期、适用版本和撤销机制；
- 工具/规则被撤销时找到依赖 Case 重评；
- 检索结果按质量和新鲜度重排；
- 历史成功率同时记录失败和 inconclusive；
- 恶意仓库文本不得成为全局 instruction。

### 11.3 去重与抽象层级

避免把相同漏洞在不同文件中的实例堆成海量 Case：

```text
Instance Evidence
  当前仓库具体路径与 PoC

Repository Case
  同一根因的多处实例

Reusable Pattern
  跨仓库的 Source/Sink/Invariant/Oracle/Fix 模式
```

知识库默认检索 Reusable Pattern 和高质量 Repository Case；具体 Instance 只在权限允许和上下文高度相关时使用。

---

## 12. 简化后的 MVP 架构

```text
┌──────────────────── Modular Monolith ────────────────────┐
│ API / UI / Workflow / Policy / Agent Planner             │
│ Evidence Fusion / Case Retrieval / Scheduler             │
└───────────────┬───────────────────────┬───────────────────┘
                │                       │
         PostgreSQL/SQLite      Local/S3-compatible
         state + metadata       content-addressed artifacts
                │                       │
                └──────── Task Queue ───┘
                            │
                    Worker Supervisor
            ┌───────────────┼───────────────┐
            ▼               ▼               ▼
        Audit R--       Mining RX-      Repair RWX
        Docker          Docker/N1       Docker/N1
```

MVP 不拆分独立 Artifact、Dependency、Knowledge 微服务。它们先作为清晰模块运行在 modular monolith/Worker Supervisor 中；接口、Schema 和信任边界保持 V3 设计，以便后续按容量拆分。

### 12.1 MVP 数据选择

- 开发：SQLite + 本地 Artifact Store；
- 团队/Beta：PostgreSQL + 持久文件卷或 S3-compatible store；
- Queue：优先复用现有实现，Redis 可选；
- Search：PostgreSQL exact/JSONB/full-text；
- Vector：Schema 预留，不启用；
- Metrics：现有 Prometheus；
- Trace：关键路径启用 OpenTelemetry，不强制全量采样。

### 12.2 Worker 数量

一期可以只有一个 Supervisor 和有限 Worker slot，但逻辑池隔离：

- 2–4 个 audit-light slot；
- 1 个 analysis-heavy slot；
- 1–2 个 mining/repair slot；
- LLM 请求单独限流。

具体数量由参考硬件压测决定。优先保证 Control Plane 始终有资源，而不是把 CPU 全部用于 Fuzz。

---

## 13. 修订后的 14–16 周交付路线

### Phase 0：可用性基线与删减冻结（第 1–2 周）

交付：

- 固定 LlamaFactory 和小/中型 Python benchmark；
- 记录现有扫描 p50/p95、CPU、内存、Finding/Issue/人工时间；
- 固定 MVP 支持矩阵和不做清单；
- 定义任务/Artifact/Case/性能指标；
- 建立端到端成本账单；
- 建立 k6 API smoke 和 Worker 基础负载脚本设计。

决策门：如果无法稳定复现实有 896/902 和耗时数据，不进入架构扩展。

### Phase 1：可用的 Fast Audit（第 3–5 周）

交付：

- Signal→Issue→Hypothesis 统一对象；
- CWE-798 协议 token/fixture/placeholder 降噪；
- Repository Inventory/RAM 最小版；
- Tier 0 全仓 + Tier 1 Top Issue；
- 异步进度和初始 AEP；
- snapshot/file/tool result 缓存；
- Case Candidate 数据模型和专家标签入口。

决策门：

- LlamaFactory 人工队列相比原始 Signal 至少减少 60%；
- 高风险已知样本召回不低于基线；
- M 仓库 Fast Audit p95 ≤ 5 分钟；
- 自动关闭没有未经支持的 claim。

未达标时继续优化 Audit，不扩大 Mining 范围。

### Phase 2：最小三 Sandbox 与 Artifact 恢复（第 6–8 周）

交付：

- 单机 Docker Audit/Mining/Repair policy；
- inbox/outbox、Task Manifest、Artifact digest；
- Worker lease/attempt/retry/cancel；
- Python Dependency Snapshot/wheelhouse；
- N0/N1 网络；
- Worker crash、API restart、Store outage 恢复测试；
- PostgreSQL Beta 拓扑与备份恢复演练。

决策门：

- 无丢失已接受任务/已封存 Artifact；
- 重复投递不产生重复权威结果；
- Sandbox cleanup 100%；
- Mining/Repair 可在断网下复建同一 Python 环境。

### Phase 3：CWE-22 Mining 闭环（第 9–11 周）

交付：

- Hypothesis→Harness→canary filesystem→Oracle；
- reachability、negative control、coverage、重复与最小化；
- VEP 与 clean-room replay；
- environment failure 和 refuted 分离；
- 首批正/负 Security Case 晋升流程。

决策门：

- 支持样本 VEP replay ≥ 90%；
- D3/D4 结论无已知 false confirmation；
- 单 Hypothesis 默认预算内完成率达到 80%；
- 历史 Case 能减少 Harness/Tool 规划时间，但不参与直接裁决。

### Phase 4：最小 Verified Repair（第 12–14 周）

交付：

- 2–3 候选；
- scope、parse/build、原测试、PoC/Oracle、行为差分、独立扫描；
- same Dependency Snapshot；
- candidate isolation；
- RVR/Verified Patch；
- 修复模式与回归负例 Case。

决策门：

- benchmark Verified Patch Yield ≥ 50%；
- 已知合法功能回归逃逸为 0；
- clean-room 关键 Gate replay ≥ 90%；
- 未通过候选不会出现在“已修复”状态。

### Phase 5：性能、压力与试点（第 15–16 周）

交付：

- API/Queue/Worker/Artifact/DB 联合压测；
- 8–24 小时 soak；
- kill Worker/DB/Store/LLM/Dependency 故障注入；
- 缓存收益和冷/热性能对比；
- 5–10 个真实 Python 仓库试点；
- Expert Review Reduction、成本和总时长报告；
- Go/No-Go 评审。

MVP Go 条件：

- 至少 3 个试点仓库实际减少专家时间；
- 性能、恢复和证据门槛同时达标；
- 单仓库成本在用户可接受范围；
- 没有依靠人工逐条扫描告警才能完成闭环。

---

## 14. MVP 后投资顺序

### Release 1：Security Case Library v1（约 3–4 周）

- Case promotion、version、scope、revoke；
- exact/JSONB/full-text 检索；
- Audit/Mining/Repair 三处 retrieval；
- repository-disjoint benchmark；
- 负例和工具失败经验；
- 使用收益指标。

### Release 2：Python 漏洞类型扩展（约 4–6 周）

- CWE-78、CWE-89、授权绕过；
- Oracle 库与环境 fixture；
- Tool/Case Retrieval 精化；
- 更完整 Repair Gate。

### Release 3：Beta HA 与分布式 Worker（按需求，约 3–5 周）

- 无状态 API 多副本；
- 托管/主备 PostgreSQL；
- 持久对象存储；
- Redis Streams 或等效冗余队列；
- 多 Worker 节点和 admission control；
- RPO/RTO 演练。

### Release 4：向量/RAG 实验（约 2–3 周，不保证上线）

- pgvector；
- hybrid retrieval；
- benchmark 与 ablation；
- false transfer/tenant leakage；
- 达不到增益门槛则关闭。

### Release 5：语言与隔离扩展

只有前述阶段证明产品价值后，再选择 JavaScript/Java/Go、Kubernetes、gVisor、Tool Evolution 和 N3 网络。

---

## 15. 阶段决策门与停止投资条件

### 15.1 Audit

继续条件：

- Issue 级 precision、召回和人工时间改善；
- Fast Audit 达到时延预算；
- 用户认为解释和排序可用。

停止扩展条件：

- 接入新工具只增加 Signal，不改善 Issue 质量；
- LLM 成本上升但人工队列不下降；
- 高风险召回因剪枝下降；
- 大部分时间消耗在不可解释的全仓模型调用。

### 15.2 Mining

继续条件：

- supported CWE 的 VEP 可重放；
- Oracle 的 false confirmation 接近 0；
- 环境建立成功率和平均时长持续改善。

停止扩大 CWE 条件：

- 现有 CWE 仍大量依赖人工改 Harness；
- 动态验证不能区分环境失败和漏洞反证；
- 每个仓库成本远高于人工验证且无复用收益。

### 15.3 Repair

继续条件：

- Verified Patch Yield 与功能保持达到门槛；
- 候选淘汰自动化确实减少专家 diff 数量。

停止自动化升级条件：

- 主要成功来自禁用功能；
- 回归测试覆盖不足；
- Repair 经常修改依赖或大范围重构；
- clean-room replay 不稳定。

### 15.4 知识库/向量检索

继续条件：

- Case 检索减少规划/验证时间；
- repository-disjoint 数据上保持增益；
- 负例降低误报；
- 隐私和作用域可证明。

停止向量投资条件：

- 与结构化+全文相比增益不足；
- false transfer 增加；
- embedding 成本、模型迁移和索引运维高于节省；
- 缺少足够 promoted Case，向量只是在搜索噪声。

### 15.5 HA/分布式

继续条件：

- 单机 Worker 已持续达到资源上限；
- 有付费/内部生产用户要求 SLO；
- 故障成本高于 HA 运维成本。

停止提前建设条件：

- 试点任务量很低；
- 系统瓶颈仍是模型、工具准确性或人工流程；
- 团队没有 24×7 运维能力。

---

## 16. 成本模型

每个任务记录：

```text
repository size/class
cache hit ratio
tool CPU-seconds / peak memory / disk IO
sandbox startup and idle time
LLM input/output tokens and requests
dependency bytes / cache misses
artifact bytes and retention
expert review minutes
verified outcomes
```

核心成本指标：

| 指标 | 意义 |
|---|---|
| Cost per Audited Repository | 基础使用成本 |
| Cost per Actionable Issue | 降噪后的有效产出成本 |
| Cost per D3/D4 Vulnerability | 动态验证效率 |
| Cost per Verified Patch | 完整闭环效率 |
| Expert Minutes Saved | 最核心业务价值 |
| Cache Savings | 增量和重复仓库收益 |
| Retrieval Savings | 历史 Case 是否有价值 |

工具更多、Token 更多、Fuzz 更久都不是进步，只有 verified outcome 或专家时间改善才是进步。

---

## 17. 风险与控制

| 风险 | 控制 |
|---|---|
| 规划再次膨胀 | MVP 支持矩阵与“不做清单”冻结；新增项必须替换而非叠加 |
| 为性能降低证据门槛 | 只降低 scope/并发/候选数，不降低 Gate |
| 过早 HA | 先恢复演练和单机容量数据 |
| 数据存太多 | 分 P0/P1/P2、TTL、引用计数和 quota |
| 知识库变成告警垃圾场 | 只存 promoted Case，正负例并重 |
| RAG 产生错误迁移 | 历史 Case 不提升当前 Evidence Level |
| 向量库运维膨胀 | PostgreSQL/全文 baseline，pgvector 仅实验 |
| Redis 成为隐式真相源 | PostgreSQL/Artifact 保持权威 |
| 缓存污染 | digest、tenant scope、只读、promotion/revocation |
| 压测只测 API | 增加 Worker、Fuzz、Repair、Artifact、Dependency 压力 |
| 大仓库拖垮系统 | 仓库分级、budget、admission control、子项目模式 |
| LLM 限流导致全链阻塞 | 静态 Fast Path 独立，语义任务可暂停恢复 |
| 试点数据不代表泛化 | repository-disjoint benchmark 与真实多仓库试点 |

---

## 18. 建议立即启动的三个 Sprint

### Sprint A：把“可用性”变成数字

- 固定参考硬件和 S/M benchmark；
- 测量当前 LlamaFactory cold/warm scan、CPU、内存、IO；
- 记录专家处理 896 Signal 的真实时间；
- 打通 task/tool/model/artifact 成本指标；
- 建立 API smoke、Worker concurrency 和 crash recovery 测试；
- 冻结 14–16 周 MVP 范围。

### Sprint B：Fast Audit + Case v0

- 统一 Issue/Hypothesis；
- 先解决 CWE-798 协议 token 误报；
- 30–60 秒内展示 RAM/进度；
- 5 分钟内输出 M 仓库 Fast Audit；
- 将专家确认的正例/负例写入结构化 Case Candidate；
- 用 PostgreSQL exact/JSONB/full-text 原型检索，不做 embedding。

### Sprint C：单节点恢复与 CWE-22 纵向切片

- 三 policy profile、inbox/outbox、Artifact digest；
- Worker kill/retry、API restart、重复消息；
- Python wheelhouse/Dependency Snapshot；
- CWE-22 Harness/Oracle/VEP；
- 2 个修复候选和核心 Gate；
- 记录总耗时、成本和人工介入点。

---

## 19. V4 Definition of Done

### 产品价值

- 真实仓库的人工 Review Queue 至少下降 60%；
- 高风险召回不低于当前基线；
- 至少一个 CWE 从 Audit 到 Verified Patch 无需人工逐条处理 Signal；
- 试点专家确认系统节省时间，而不只是换成阅读模型输出。

### 性能

- Fast Audit 达到参考硬件上的时延预算；
- Mining/Repair 全部异步、可取消、可恢复；
- 缓存命中对重复分析有可测加速；
- 自动测试峰值下 Control Plane 可响应，队列能够背压和排空；
- soak test 无持续泄漏和残留 Sandbox。

### 可恢复性

- API、Scheduler、Worker 和依赖服务故障不会丢已提交 Artifact；
- 重试不会产生重复权威结论或重复自动费用；
- PostgreSQL/Artifact 备份可以实际恢复；
- Sandbox cleanup 失败会隔离节点；
- H1 的 RPO/RTO 经过演练。

### 持久化与检索

- P0/P1/P2 数据分类和 TTL 生效；
- PostgreSQL 是状态和 Case 元数据真相源；
- Artifact Store 是大型证据真相源；
- Redis 仅是可选队列/缓存；
- Security Case 有 provenance、正负例、作用域、版本和晋升流程；
- 结构化+全文检索先通过 benchmark；
- 向量/RAG 未通过增益门槛前不进入生产关键路径。

### 安全闭环

- 历史知识只帮助规划，不替代当前证据；
- VEP 能 clean-room replay；
- 修复前后同环境、候选相互隔离；
- Security/Functional Gate 同时通过才标记 Verified；
- 无法证明时安全 abstain。

---

## 20. 架构决策记录（ADR）补充

建议新增：

1. **ADR-027：V3 是目标架构，V4 MVP 采用纵向切片交付。**
2. **ADR-028：一期只支持 Python、中小仓库和 CWE-22 动态闭环。**
3. **ADR-029：先可恢复，再建设多副本 HA。**
4. **ADR-030：PostgreSQL 是权威状态/知识元数据源，Artifact Store 保存大型不可变证据。**
5. **ADR-031：Redis 是可选队列/缓存，不是唯一真相源。**
6. **ADR-032：持久化分为 P0/P1/P2，不永久保存所有中间数据。**
7. **ADR-033：安全知识存储单位是 promoted Security Case，不是原始 Finding。**
8. **ADR-034：正例和负例同等进入知识评测。**
9. **ADR-035：检索顺序为结构化→全文→可选向量。**
10. **ADR-036：优先 pgvector 实验，不直接引入独立向量数据库。**
11. **ADR-037：RAG 只影响计划，不提升当前证据等级。**
12. **ADR-038：性能优化通过预算、缓存、增量和背压，不降低安全 Gate。**
13. **ADR-039：所有新增基础设施必须由容量/质量指标触发。**
14. **ADR-040：每阶段设置 Go/No-Go，未达标不扩大下游范围。**

---

## 21. 最终建议

应该做取舍，而且应当现在就做。建议把 V3 保留为长期架构规范，用它防止未来在权限、通信、依赖和证据方面走错；但执行上采用 V4 的短路线：

```text
先证明 Audit 能减少工作量
→ 再证明一个漏洞类型能稳定 Mining
→ 再证明 Repair 能保持功能
→ 再做压力、恢复和真实试点
→ 再建设知识库检索
→ 最后由数据决定向量、HA、K8s 和多语言
```

安全知识库有必要。随着仓库数量增长，Source/Sink、边界、误报、Oracle、工具效果和修复模式一定会产生复用价值。但第一版真正需要的不是“向量数据库”这个技术名词，而是高质量、可追溯、可脱敏、可淘汰的 Case。没有 Case 质量和评测，RAG 只会更快地复用错误；有了结构化 Case，即使没有 embedding，也已经能显著改善 Tool Planning 和误报处理。

高可用也有必要，但一期更需要“任务不丢、证据不丢、能恢复”。一个 99.99% 在线却经常重跑昂贵任务或产生重复结论的系统，并不比可短暂停机但能正确恢复的系统更可用。

最终的投资原则应是：

> **架构边界一次想清楚，功能能力逐项证明；先交付可用的窄闭环，再扩大成平台。**

---

## 22. 参考资料

### 项目内材料

- `docs/LIMA_证据驱动三阶段安全平台_迭代规划_v2.md`；
- `docs/LIMA_三沙箱通信与依赖网络治理_迭代规划_v3.md`；
- `docs/LIMA_可信审计挖掘修复闭环_迭代规划.md`；
- 当前 `main` / `bf7d79d` 的 queue、store、experiments、repository cache、metrics、observability 和 repair workspace 实现。

### 外部一手资料

- [PostgreSQL Full Text Search Indexes](https://www.postgresql.org/docs/17/textsearch-indexes.html)：GIN/GiST 全文检索索引；
- [PostgreSQL JSONB Indexing](https://www.postgresql.org/docs/17/datatype-json.html)：结构化 Case JSONB 查询与 GIN 索引；
- [PostgreSQL Streaming Replication](https://www.postgresql.org/docs/current/warm-standby.html)：主备、异步/同步复制的可用性与时延权衡；
- [PostgreSQL PITR](https://www.postgresql.org/docs/17/continuous-archiving.html)：WAL 归档与时间点恢复；
- [pgvector](https://github.com/pgvector/pgvector)：PostgreSQL 中的 exact/approximate nearest-neighbor、HNSW/IVFFlat 和混合检索；
- [Redis Streams](https://redis.io/docs/latest/develop/data-types/streams/)：consumer groups、ACK、pending 与持久化边界；
- [Redis Persistence](https://redis.io/docs/latest/operate/oss_and_stack/management/persistence/)：RDB、AOF 和无持久化模式；
- [Grafana k6 Automated Performance Testing](https://grafana.com/docs/k6/latest/testing-guides/automated-performance-testing/)：可重复性能基线、负载模型、threshold 与自动化策略；
- [OpenTelemetry Signals](https://opentelemetry.io/docs/concepts/signals/)：trace、metric 等可观测信号；
- [Docker none network driver](https://docs.docker.com/engine/network/drivers/none/) 与 [internal networks](https://docs.docker.com/reference/compose-file/networks/)：MVP Sandbox 网络隔离；
- [SLSA Provenance](https://slsa.dev/spec/v1.2/provenance)：Artifact 输入和生产过程来源记录。
