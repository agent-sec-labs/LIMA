# LIMA 三沙箱通信、Artifact 交换与依赖网络治理迭代规划（V3）

> 分析基线：`main` / `bf7d79d`（2026-08-31）
> 继承文档：`docs/LIMA_证据驱动三阶段安全平台_迭代规划_v2.md`
> 新增输入：`D:/DownloadPackage/LIMA_Audit_Mining_Repair_Sandbox_Architecture.md`
> 文档性质：架构分析与开发规划，不包含业务代码修改
> 目标定位：**Policy-Governed, Artifact-Driven and Reproducible Security Agent Platform**

## 1. 执行摘要

V2 已经确定 Audit、Vulnerability Mining、Verified Repair 三阶段信任边界。本版进一步收敛两个此前仍不够明确的问题：

1. **Audit 自身也必须运行在隔离环境中。** 仓库、归档、Manifest、Parser 输入和静态分析器都可能是攻击面；“不执行目标程序”不代表可以在 LIMA 主服务内安全解析不可信仓库。
2. **三个 Sandbox 不能靠共享目录、直连 API 或隐式 Agent 记忆交换信息。** 它们必须通过 Control Plane 管理的、不可变且可校验的 Artifact 交换；依赖下载也必须与目标代码执行隔离，通过受控 Dependency Gateway、内容寻址缓存和显式网络授权完成。

正式环境名称统一为：

```text
Audit Analysis Sandbox          = R--
Vulnerability Mining Sandbox   = RX-
Repair Verification Sandbox    = RWX
```

其中：

- `R`：读取固定仓库快照；
- `W`：修改一次性工作副本；
- `X`：受控执行目标代码或仓库控制的构建/安装逻辑；
- Audit 只能运行受信分析工具，不能执行仓库代码、仓库脚本、依赖安装脚本或项目构建生命周期；
- Mining 可以在严格隔离中执行目标、Harness、Fuzz Driver、构建和动态观测，但不能修改原仓库；
- Repair 可以修改一次性副本并执行验证，但不能复用 Mining 的可变状态或直接写回用户仓库。

本版的核心架构为：

```text
                         LIMA Control Plane
       ┌──────────────────────┼──────────────────────┐
       │                      │                      │
  Policy / Planner       Artifact Registry    Dependency Gateway
  Task / Lease           Schema / Lineage     Mirror / Quarantine
  Tool Registry          Digest / Signature   Cache / Credential
       │                      │                      │
       └────────────── Worker Supervisor ───────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│ Audit Analysis   │ │ Vulnerability    │ │ Repair           │
│ Tool Workers     │ │ Mining Sandbox   │ │ Verification     │
│ R-- / no target X│ │ RX- / controlled │ │ RWX / disposable │
└────────┬─────────┘ └────────┬─────────┘ └────────┬─────────┘
         │ AEP                │ VEP                │ RVR + Patch
         └────────────────────┴────────────────────┘
                  No direct sandbox-to-sandbox network
```

三个 Sandbox 的通信原则是：

> **控制消息走 Control Plane，事实数据走 Artifact Registry，依赖走 Dependency Gateway，Sandbox 之间永不直连。**

本地 Docker MVP 中，推荐优先使用预挂载的只读 `inbox` 和可写 `outbox`，避免为 Artifact 交换给 Sandbox 开网络。分布式环境中，由受信 Worker Supervisor 与 Artifact Gateway 通信，工作负载容器本身仍不持有 LIMA API、数据库、对象存储或队列凭据。

依赖与网络采用三层模式：

1. **Hermetic Offline**：默认模式，使用已批准、按 digest 固定的工具镜像、Dependency Snapshot、漏洞数据库和只读缓存；
2. **Brokered Fetch**：缓存缺失时，由 Sandbox 外的 Dependency Gateway 经 allowlist 代理下载、校验和隔离，Sandbox 本身仍不上网；
3. **Explicit Network Grant**：只有验证真实网络协议或私有服务不可替代时，才向特定 Mining/Repair 任务签发短时、限域、限流、全审计的 Network Access Grant。

任何失败都不能自动回退到开放互联网。DNS 故障、镜像缺失、私有依赖凭据不足、包摘要不匹配、代理不可用或漏洞数据库过期，都必须返回结构化失败或证据缺口。

与 V2 一致，最终目标仍然是：

```text
Signal → Issue → Hypothesis → Static Evidence
       → Runtime Evidence → Verified Vulnerability
       → Candidate Repairs → Independent Gates → Verified Patch
```

V3 并不改变证据驱动方向，而是补齐让它能够安全落地的执行、通信与供应链基础设施。

---

## 2. V3 相对 V2 的架构修正

### 2.1 Audit 从主进程能力改为独立只读分析域

V2 将 Audit 视为只读阶段，但没有充分强调其执行位置。本版明确：

- Repository Materializer 在受信域拉取并封存源码；
- Audit Analysis Sandbox 只接收固定 snapshot；
- AST、CFG、CPG、静态数据流、SAST、SCA、Secret 和 IaC 分析均在独立 Tool Worker 中运行；
- Tool Worker 不访问 LIMA API、PostgreSQL、Redis、Git Token、LLM Key 或宿主其他目录；
- LLM Architecture Reasoner 运行在 Control Plane，通过结构化 Repository Model 与 Evidence Slice 工作，不获得 Sandbox shell。

Audit Sandbox 是**逻辑安全域**，底层不是一个巨型镜像，而是多个按需启动、版本固定、最小权限的 Tool Worker Sandbox。

### 2.2 “目标执行”边界包括构建与依赖生命周期

以下行为都可能执行仓库或第三方代码，因此不属于 `R--` Audit：

- `pip install -r requirements.txt`，尤其是 sdist/build backend；
- `npm install` / `npm ci` 的 lifecycle scripts；
- Maven/Gradle plugin、build script、annotation processor；
- `setup.py`、Git hook、pre-commit hook；
- `make`、项目 build 脚本、代码生成器；
- `pytest`、单元测试、示例程序；
- 执行仓库 binary、import 时会运行顶层代码的探测方式；
- CodeQL `autobuild` 或 `manual build` 等会触发项目构建的模式。

Audit 中应优先使用纯源码/`build-mode:none`/无生命周期 hook 的分析方式。若工具必须构建才能提供更高精度，Audit 记录 `execution-required evidence gap`，由 Mining 阶段在 RX 权限下补全。不能为了“静态分析完整”悄悄提升 Audit 权限。

### 2.3 三阶段之间禁止直连

禁止：

- Audit 容器调用 Mining 容器 API；
- Mining 将工作目录直接挂给 Repair；
- 共享可写 volume 作为跨阶段状态；
- 用 Redis/数据库账号直接写主服务状态；
- 用 Agent 对话或 memory 传递漏洞事实；
- Repair 发现问题后直接回连 Mining 修改证据；
- Sandbox 使用对象存储长期密钥上传结果。

允许：

- Control Plane 下发带输入 Artifact 引用的 Task Manifest；
- Worker Supervisor 在启动前准备只读 inbox；
- Sandbox 将输出写入限额 outbox；
- 可信 Collector 在任务结束后校验、哈希、签名并注册 Artifact；
- 下游通过新的 Task Manifest 引用上游不可变 Artifact；
- 下游对证据有异议时提交 Evidence Dispute Artifact，由 Control Plane 决定是否创建新阶段任务。

### 2.4 网络从 Sandbox 属性升级为独立治理域

V2 只有“默认无网络和必要时 allowlist”。V3 新增：

- Network Policy Compiler；
- Egress Proxy / DNS Policy；
- Dependency Gateway；
- Package/OCI/Advisory Mirrors；
- Credential Broker；
- Network Access Grant；
- 连接、域名、字节、时间和响应摘要审计；
- offline/fetch/grant 三种明确模式；
- 断网与上游异常的 typed fallback。

### 2.5 Artifact 增加执行环境与争议契约

除 AEP、VEP、RVR 外，新增：

- Repository Architecture Model；
- Task Manifest；
- Tool Bundle Manifest；
- Dependency Resolution Plan；
- Dependency Snapshot；
- Network Access Grant；
- Sandbox Run Manifest；
- Evidence Dispute / Enrichment Request；
- Failure Report。

这些是支撑三沙箱协作的控制和环境 Artifact，不替代三份核心业务证据包。

---

## 3. 威胁模型与不可妥协原则

### 3.1 主要威胁

| 威胁 | 入口 | 可能后果 |
|---|---|---|
| 恶意仓库/归档 | 源码、压缩包、symlink、Git 对象 | 路径逃逸、解析器漏洞、资源耗尽 |
| Parser/Analyzer 漏洞 | AST/CPG/SAST 工具处理恶意输入 | Worker compromise、横向移动 |
| Prompt Injection | 注释、README、测试字符串、工具输出 | LLM 请求越权工具或泄露数据 |
| 恶意依赖 | 包、构建后端、安装脚本、插件 | 任意代码执行、凭据窃取 |
| Dependency Confusion | 公私包同名、未固定版本、错误源顺序 | 安装攻击者包 |
| Poisoned Cache | 跨任务/租户共享的可写缓存 | 结果污染、代码执行、证据伪造 |
| 恶意工具镜像 | 被篡改工具、可变 tag、供应链攻击 | 全面绕过 Sandbox 约束 |
| Sandbox Egress | DNS/HTTP/自定义协议 | 源码、凭据、PoC 数据外泄 |
| Artifact Tampering | 跨阶段修改或重放旧 Artifact | 错误裁决、错误修复 |
| Shared State Contamination | Mining 与 Repair 共用目录/缓存 | PoC 副作用影响修复验证 |
| Log/Output Abuse | 超大日志、控制字符、伪造 JSON | DoS、界面欺骗、Parser 攻击 |
| Credential Leakage | Git、包源、LLM、对象存储 token | 外部系统失陷 |
| Cross-tenant Leakage | 缓存、对象存储 key、Worker 复用 | 私有代码与依赖泄露 |

### 3.2 核心原则

1. **Repository Is Hostile Input**：固定 commit 只保证版本，不保证内容可信。
2. **Control Plane Never Executes Repository Code**：主服务只管理计划、策略、状态和 Artifact。
3. **LLM Is Planner, Not Shell**：模型只能提出结构化 Tool Request。
4. **Audit Is Static-only, Not Unsandboxed**：Audit 隔离但不执行目标控制逻辑。
5. **No Direct Cross-stage Communication**：三阶段只通过 Control Plane 和 Artifact 交接。
6. **Network Deny by Default**：缺依赖不是开放网络的理由。
7. **Dependencies Are Artifacts**：依赖必须被解析、固定、校验、封存和引用。
8. **Tools Are Supply-chain Subjects**：工具、Adapter、规则包、数据库均有 digest、来源和生命周期。
9. **Evidence Is Immutable and Versioned**：修正结论创建新版本，不能原地覆写。
10. **Execution Failure Is Not Security Evidence**：断网、超时、依赖缺失不能证明漏洞或安全。
11. **Same Environment for Before/After**：修复前后必须使用同一 Dependency Snapshot 和策略。
12. **Safe Abstention**：基础设施或证据不完整时降级为未决，不降低 Gate。

---

## 4. 总体组件架构

### 4.1 Control Plane

LIMA 主服务逐步收敛为：

```text
Repository Snapshot Management
Workflow / State Machine
Agent Planning
Policy Enforcement
Tool Registry / Retrieval
Sandbox Scheduling
Task Lease / Retry / Cancel
Artifact Registry / Lineage
Dependency Resolution Coordination
Evidence Fusion / Adjudication
Budget / Observability / Approval
```

主服务不得直接运行静态分析器、包管理器、目标代码、测试或补丁生成脚本。

### 4.2 可信基础服务

| 服务 | 职责 | 是否接触不可信执行 |
|---|---|---:|
| Source Materializer | 拉取仓库、拒绝危险归档、生成 snapshot | 只处理数据，不执行仓库 |
| Artifact Gateway | Artifact 上传/下载、Schema、digest、签名和 ACL | 不执行 Artifact |
| Worker Supervisor | 领取任务、准备 mount、启动/销毁 Sandbox、采集 outbox | 启动隔离工作负载 |
| Dependency Resolver | 解析 lock/manifest，形成固定依赖计划 | 不运行项目安装脚本 |
| Dependency Fetcher | 从批准上游下载包/镜像/数据库 | 不运行下载内容 |
| Quarantine Scanner | 摘要、签名、SBOM、许可、恶意内容和策略检查 | 在专用隔离域解析包 |
| Credential Broker | 签发短期、限域、用途绑定凭据 | 不把上游凭据交给目标容器 |
| Egress Proxy | 执行域名、方法、流量、时间和 TLS 策略 | 记录所有特许外联 |
| Advisory Sync | 同步 OSV/Trivy/规则包等数据库快照 | 定时受信任务 |

可信服务也需要最小权限和自身隔离；“可信”表示属于平台控制面，不表示其输入安全。

### 4.3 执行平面

```text
Audit Analysis Domain
  ├─ Inventory Worker
  ├─ Semgrep Worker
  ├─ Bandit Worker
  ├─ Pysa Worker
  ├─ CodeQL No-build Worker
  ├─ Joern Worker
  └─ Trivy/OSV Worker

Mining Execution Domain
  ├─ Environment Builder
  ├─ Target/Harness Runner
  ├─ Fuzzer/Property Runner
  ├─ Internal Test Services
  └─ Trusted Observer/Collector

Repair Verification Domain
  ├─ Candidate Generator Worker
  ├─ Candidate-specific Writable Workspace
  ├─ Build/Test Worker
  ├─ PoC/Oracle Worker
  ├─ Differential Analyzer
  └─ Independent Verification Worker
```

每个 Tool Worker 都应是单任务或严格清理后的短生命周期实例。优先使用“一个工具一个 Worker 镜像”，避免所有编译器、运行时和分析器进入同一巨型容器。

---

## 5. 三类 Sandbox 的正式契约

### 5.1 Audit Analysis Sandbox（R--）

目标：回答“仓库是什么、攻击面在哪里、哪些安全假设值得进入动态验证”。

允许：

- 只读遍历固定 snapshot；
- 安全解析源码、Manifest、配置和 IaC；
- AST/CFG/CPG/调用图/纯静态数据流；
- Semgrep、Bandit、Pysa、Trivy/OSV metadata 等静态分析；
- 不需要项目构建的 CodeQL 模式；
- 将结果写入任务级 outbox；
- 读取由平台挂载的规则包、类型 stub、漏洞数据库和工具数据。

禁止：

- 执行目标程序或仓库 binary；
- import 探测导致模块顶层代码执行；
- 运行测试、示例、CLI、服务和 hooks；
- 安装仓库依赖或运行 package lifecycle；
- 运行仓库 build script、CodeQL autobuild/manual build；
- 修改 snapshot；
- 访问公网或 Control Plane API；
- 持有 Git、LLM、数据库、对象存储和包源凭据。

默认资源：只读 rootfs、非 root、drop all capabilities、`no-new-privileges`、只读 snapshot、任务级 `/tmp` 与 `/outbox`、CPU/memory/PID/disk/time/output 限制、network none。

### 5.2 Vulnerability Mining Sandbox（RX-）

目标：回答“假设是否能被真实执行稳定证明”。

允许：

- 读取固定 snapshot；
- 从只读 Dependency Snapshot 构建任务环境；
- 写 Harness、fixture、coverage 和临时运行状态；
- 运行局部函数、服务、测试、Fuzzer、PoC 和动态插桩；
- 在内部隔离网络运行目标、数据库、HTTP stub、DNS stub 等测试服务；
- 使用 canary 凭据和 canary 数据；
- 将可复现运行证据写入 outbox。

禁止：

- 修改原始 snapshot；
- 把 Harness 变化当成项目修复；
- 默认访问公网；
- 使用真实生产凭据、生产数据库或真实攻击目标；
- 直接联系 Repair Sandbox；
- 把可写 dependency/cache 传给其他任务；
- 发布 Patch。

### 5.3 Repair Verification Sandbox（RWX）

目标：回答“补丁是否消除已验证漏洞并保持原有功能”。

允许：

- 从固定 snapshot 创建全新一次性 writable copy；
- 生成多个候选 Patch；
- 使用与基线一致的 Dependency Snapshot；
- 编译、测试、PoC replay、Oracle、差分扫描、行为差分和 re-fuzz；
- 为每个候选创建相互隔离的工作区或 Sandbox；
- 产出 Verified Patch 与 RVR。

禁止：

- 复制 Mining 工作目录、进程、容器、数据库卷或可写缓存；
- 读取 Mining Agent memory/聊天记录；
- 直接修改原始 Git 仓库或推送远端；
- 为使测试通过而静默改变依赖版本；
- 自动增加网络权限；
- 跳过失败 Gate 或让候选生成器裁决自己。

### 5.4 权限矩阵

| 能力 | Audit | Mining | Repair |
|---|---:|---:|---:|
| 读取固定 snapshot | 是，RO | 是，RO | 是，RO；另建 RW copy |
| 运行受信静态工具 | 是 | 是 | 是 |
| 执行目标/仓库脚本 | 否 | 受控允许 | 仅验证用途 |
| 安装项目依赖 | 否 | 仅从 Dependency Snapshot | 仅从同一 Snapshot |
| 写 Harness | 否 | 任务 scratch | 只重放/经审查扩展 |
| 修改项目代码 | 否 | 否 | 仅 disposable copy |
| Sandbox 外网 | 否 | 默认否，Grant 后有限 | 默认否，Grant 后有限 |
| 内部测试网络 | 不需要 | 按计划创建 | 按 Gate 创建 |
| LLM API | 仅 Control Plane 调用 | 仅 Control Plane 调用 | 仅 Control Plane 调用 |
| 跨阶段共享 volume | 否 | 否 | 否 |

---

## 6. 三沙箱通信架构

### 6.1 三条独立通道

#### Control Channel

传输：任务创建、租约、心跳、取消、资源状态和完成通知。

只允许 Control Plane 与 Worker Supervisor 通信。Sandbox 内的目标进程不直接接触任务队列或主 API。

#### Artifact Data Channel

传输：snapshot、Tool Bundle、Dependency Snapshot、AEP、VEP、RVR、日志、coverage、trace 和 Patch。

优先通过文件型 `inbox/outbox` 交接；分布式部署中由 Supervisor 使用短期 capability token 与 Artifact Gateway 通信。

#### Observability Channel

传输：限流的 stdout/stderr、结构化事件、资源指标、网络审计和 Sandbox 状态。

原始日志是非权威、不可信数据；安全结论必须引用封存后的 Artifact。

### 6.2 Inbox / Outbox 模式

```text
Control Plane creates Task Manifest
          ↓
Supervisor validates task and lease
          ↓
Supervisor downloads/verifies input blobs
          ↓
Read-only /inbox + empty bounded /outbox
          ↓
Sandbox executes without Artifact network access
          ↓
Sandbox writes declared outputs
          ↓
Supervisor stops workload and freezes outbox
          ↓
Path/size/type/schema/malware/digest validation
          ↓
Artifact Gateway stores immutable blobs
          ↓
Control Plane commits state transition
```

这样可把 Artifact Store 凭据、LIMA API token 和对象存储网络从不可信工作负载中移除。

### 6.3 Task Manifest

每次任务必须包含：

| 分类 | 字段 |
|---|---|
| Identity | task_id、run_id、stage、attempt、lease_id |
| Subject | repository、commit、snapshot digest、tenant/project |
| Inputs | Artifact ID、digest、mount path、read-only 标记 |
| Tools | Tool Bundle ID/digest、允许 invocation |
| Dependencies | Dependency Snapshot ID/digest |
| Policy | Sandbox class、network mode、filesystem、identity、capability |
| Resources | CPU、memory、PIDs、disk、time、output、concurrency |
| Expected Outputs | Artifact type、Schema version、size/count limits |
| Secrets | 默认空；仅引用用途绑定的短期 grant，不保存值 |
| Reproducibility | seed、clock、locale、timezone、environment whitelist |
| Signature | Control Plane 签名、过期时间、防重放 nonce |

Supervisor 必须在启动前校验 Manifest；Sandbox 只能看到执行所需的最小投影视图。

### 6.4 消息与状态语义

建议采用“至少一次投递 + 幂等处理”，不追求难以证明的端到端 exactly-once：

- `task_id + attempt + manifest_digest` 作为幂等键；
- 同一 lease 同时只能有一个 active worker；
- heartbeat 由 Supervisor 发出，不信任目标进程自报；
- 只有 Artifact 完成封存后才 ack task completion；
- Worker 崩溃可重放同一输入，生成新 attempt 和 Run Manifest；
- 重复完成事件按 artifact digest 去重；
- 状态迁移和 Artifact 注册使用事务/outbox 保证不出现“任务完成但证据丢失”；
- cancel 先阻止新 invocation，再终止 Sandbox，最后封存 partial evidence。

标准消息：

```text
TaskReady
LeaseGranted
SandboxStarted
InvocationStarted / Finished
ArtifactCandidateReady
Heartbeat
PolicyViolation
FailureReported
CancellationRequested
SandboxDestroyed
TaskCommitted
```

### 6.5 跨阶段反馈不是反向直连

正常数据流保持单向：

```text
RAM/AEP → VEP → RVR/Verified Patch
```

但工程上必须允许下游质疑上游：

- Mining 发现架构信息缺失 → `Audit Enrichment Request`；
- Mining 发现静态假设不成立 → `Hypothesis Refutation`；
- Repair 无法重放 VEP → `VEP Reproduction Dispute`；
- Repair 发现 Oracle 过拟合 → `Oracle Dispute`；
- Tool 被撤销 → `Evidence Re-evaluation Request`。

这些都提交给 Control Plane。Control Plane 创建新的 Audit/Mining task 和新 Artifact 版本；旧 Artifact 保持不可变。禁止 Repair 直接修改 VEP 或回连原 Mining 容器。

### 6.6 本地与分布式实现

| 场景 | 通信方式 | Sandbox 凭据 |
|---|---|---|
| 本地 Docker MVP | 本地任务 DB/队列 + Supervisor + bind-mounted inbox/outbox | 无 |
| 单机多 Worker | 本地 Artifact Store + per-task namespace | 无 |
| Kubernetes | Control Plane→Supervisor/Job；Artifact Gateway 由 init/collector 或节点代理访问 | 工作负载默认不挂 ServiceAccount token |
| 跨集群 | mTLS Worker Gateway + 内容寻址 Artifact Store | Supervisor 持短期 audience-bound token |

Kubernetes 部署时应显式关闭不必要的 ServiceAccount token 自动挂载；若 Supervisor 确需访问平台 API，使用短期、受众绑定的 token，不能把它共享给目标容器。

---

## 7. Artifact 交换与数据契约

### 7.1 Common Envelope

沿用 V2，并补充通信字段：

```text
schema_version
artifact_type / artifact_id / revision
subject.repository / commit / snapshot_digest
producer.stage / worker / tool / model / version
inputs[].artifact_id / digest / relation
task_id / run_id / attempt / sandbox_id
policy_version / grant_ids
classification / tenant / retention / redaction
completeness / coverage / limitations / warnings
created_at / expires_at
content_digest / signature / provenance
supersedes / disputes / revoked_by
```

### 7.2 Repository Architecture Model（RAM）

Audit 的第一份固定 Artifact：

- languages、frameworks、components；
- manifests、build/test entry metadata；
- routes、CLI、workers、plugins、external interfaces；
- assets、trust boundaries、identities、roles；
- sensitive sinks、security controls、critical paths；
- import/call/config/dependency graph references；
- business workflows；
- extraction coverage 和 parser failures；
- 所有语义推断的源码引用与 confidence/evidence gap。

RAM 先由 Audit Worker 结构化提取，再由 Control Plane 上的 LLM Reasoner 补充语义，最终再次经过 Schema 与引用校验。

### 7.3 Audit Evidence Package（AEP）

沿用 V2 的 Profile、Signals、Issues、Hypotheses、Evidence 和 Functional Contract Seeds，并增加：

- RAM ID/digest；
- Tier 0/1/2 分析覆盖；
- 每个 Tool Worker 的 Run Manifest；
- 禁止执行导致的 analysis gap；
- 需要依赖/构建才能补全的 hypothesis；
- 推荐 Mining capability、environment requirements 和内部服务拓扑；
- 静态工具数据库/规则包 snapshot；
- Artifact sensitivity 与最小下游 disclosure。

AEP 只能表达“值得动态验证的假设”和静态处置结论，不能标记 runtime-confirmed。

### 7.4 Dependency Resolution Plan（DRP）

由 Resolver 根据 Manifest/lockfile 生成：

- ecosystem、platform、runtime/toolchain；
- direct/transitive dependency identity、version、source；
- lock/hash 完整度；
- private/public source 分类；
- package lifecycle/build script presence；
- required native/system libraries；
- candidate artifact digest；
- unresolved/dynamic/VCS/path dependency；
- network/credential requirements；
- planned verification、quarantine 和 cache policy；
- reproducibility risk。

DRP 不是“已安全依赖”，只是下载与环境构建计划。

### 7.5 Dependency Snapshot（DS）

通过 Fetch/Quarantine/Verification 后生成：

- DRP digest；
- 所有包、wheel、crate、module、jar、image layer 和系统层 digest；
- lockfile 与解析结果；
- 来源、签名、SBOM、许可和安全扫描结果；
- 是否包含 install/build scripts；
- 允许的安装模式和脚本 allowlist；
- 支持的 OS/arch/runtime；
- read-only mount/layout；
- cache namespace、tenant 和有效期；
- 未解决项与环境真实性评分。

Mining 和 Repair 的基线/补丁验证必须引用同一个 DS digest。若 Repair 的候选修改依赖，则创建新的候选 DS，并把依赖变化作为补丁的一部分进入全部 Gate。

### 7.6 Tool Bundle Manifest（TBM）

包含工具、Adapter、规则包、数据库、镜像 digest、权限、资源、输入输出契约和选择理由。Audit/Mining/Repair 必须使用阶段适配的不同 Bundle；同名工具在不同阶段也可有不同 invocation policy。

### 7.7 Network Access Grant（NAG）

仅在 offline 和 brokered fetch 都无法满足时签发：

| 字段 | 要求 |
|---|---|
| subject | task/run/sandbox，不能跨任务复用 |
| purpose | 明确说明为何 mock/cache 不足 |
| destinations | 域名、端口、协议、路径/方法，默认不接受任意 IP |
| DNS policy | 允许解析器、重解析与 DNS rebinding 防护 |
| traffic | request/response byte limits、连接数、速率 |
| time | not_before、expires_at、最大持续时间 |
| identity | 需要时的短期 client identity，不暴露上游长期 secret |
| data | 允许发送的数据分类和脱敏要求 |
| capture | 请求元数据、TLS identity、响应摘要和失败记录 |
| approval | 策略/人工审批与原因 |

### 7.8 Sandbox Run Manifest（SRM）

记录 Task Manifest、Tool/Dependency/Network digest、镜像、平台、argv、环境白名单、资源限制、每次 invocation、exit/OOM/timeout、coverage、trace、outbox Artifact 和 cleanup proof。

### 7.9 VEP 与 RVR

VEP 继续作为 Repair 认定漏洞事实的唯一权威输入，增加：

- Mining DS、TBM、NAG 和 SRM 引用；
- 内部测试网络拓扑；
- dependency/environment fidelity；
- 外部服务 mock 与真实协议差异；
- clean-room reproduction 所需的 Artifact 清单。

RVR 增加：

- 修复前后 DS 一致性；
- 所有候选的网络策略一致性；
- 基线与补丁运行环境差分；
- 依赖变更 Gate；
- Repair SRM 与 Sandbox cleanup proof；
- 对 VEP 的任何争议和处理结果。

---

## 8. 网络治理与拓扑

### 8.1 默认通信矩阵

| 来源 | 目标 | 默认 | 说明 |
|---|---|---:|---|
| Audit Worker | 公网/内网 | 拒绝 | 工具、规则、DB 均预置/挂载 |
| Audit Worker | Control Plane/DB/Queue | 拒绝 | 通过 Supervisor inbox/outbox |
| Mining target/harness | 公网 | 拒绝 | 只有 NAG + egress proxy 可例外 |
| Mining containers | 同任务内部服务 | 按 Validation Plan 允许 | internal-only test network |
| Repair candidate | 公网 | 拒绝 | 依赖来自同一 DS |
| Repair containers | 同候选测试服务 | 按 Gate 允许 | 不与其他候选共享状态 |
| Supervisor | Control Plane/Queue | mTLS 允许 | 任务租约与状态 |
| Supervisor | Artifact Gateway | 短期 token 允许 | 仅指定 Artifact |
| Dependency Fetcher | 批准上游 | allowlist 允许 | 与 Sandbox 分离 |
| Advisory Sync | 批准数据源 | 定时 allowlist | 生成版本化 DB snapshot |
| LLM Gateway | 模型供应商 | 项目策略允许 | Sandbox 不持有 LLM Key |

### 8.2 网络模式

#### N0 — None

只有 loopback。适用于 Audit、单进程 Harness、大多数 Repair Gate。

#### N1 — Internal Test Network

允许同一任务中的 target、database、stub、observer 互相通信，但无外部默认路由。适用于 HTTP、SQL、队列、鉴权和微服务验证。

#### N2 — Brokered Dependency Fetch

Sandbox 仍无网；Dependency Gateway 根据 DRP 获取缺失 Artifact。它不是 Sandbox 的网络模式，而是外部准备步骤。

#### N3 — Restricted Egress

Sandbox 只能经透明/显式 egress proxy 访问 NAG 列出的目的地。必须限时、限量、记录，任务结束立即撤销。

#### N4 — Prohibited

任意公网、宿主网络、云元数据、Docker socket、Kubernetes API、企业内网扫描、直接 VCS/包源 fallback 一律禁止。

### 8.3 DNS 与域名策略

- N0 不提供外部 DNS；
- N1 只提供任务内部 service discovery；
- N3 的 DNS 请求经策略解析器；
- 域名 allowlist 在解析后仍校验 IP 范围，阻止解析到 loopback、link-local、RFC1918、metadata 和管理网；
- 连接建立时重新校验，防止 DNS rebinding；
- 禁止直接访问未授权 IP 和自定义 DNS server；
- DNS 日志也是 Run Manifest 的引用证据；
- Kubernetes default-deny egress 会同时阻断 DNS，只有 N1/N3 策略显式开放所需解析器。

### 8.4 本地 Docker 与 Kubernetes

本地 MVP：

- N0 使用 `--network none`；
- N1 使用每任务唯一的 `internal` network；
- 不使用 `host` network；
- 不向目标容器挂 Docker socket；
- Supervisor 与 Sandbox 不加入同一个可外联 network。

Kubernetes：

- namespace/pod 默认 deny ingress/egress；
- 使用支持 NetworkPolicy 的 CNI；
- 工作负载禁用默认 ServiceAccount token；
- Artifact 拉取/收集由 init/sidecar 或节点 Supervisor 完成，但凭据不挂给目标容器；
- N1 只允许同 task/sandbox label 的端点；
- N3 仅允许到 egress proxy，不能直接 allowlist 大段公网 CIDR；
- 高风险任务可调度到 gVisor/VM 隔离节点。

NetworkPolicy 是防御层，不足以单独实现域名、HTTP method、响应大小和审计；这些由 Egress Proxy 与 NAG 补充。

### 8.5 LLM 通信

- 模型调用只由 Control Plane 的 LLM Gateway 发起；
- Sandbox 输出先解析、限量、脱敏和标记为不可信，再进入模型上下文；
- 私有仓库必须遵循项目的数据外发策略；
- 发送源码片段时携带 Artifact 引用，模型返回的判断不成为 Artifact 事实，必须由证据验证；
- 模型不能请求任意 URL，也不能把仓库内容编码进 Tool Request；
- Provider failure 只影响语义规划，不触发 Sandbox 开网兜底。

---

## 9. 依赖下载、缓存与供应链兜底

### 9.1 核心架构

```text
Manifest / Lockfile
        ↓
Dependency Resolver（无目标代码执行）
        ↓
Dependency Resolution Plan
        ↓
Policy / Source / License Check
        ↓
Dependency Fetcher（批准上游 allowlist）
        ↓
Quarantine Store
        ↓
Hash / Signature / SBOM / Malware / Archive Safety
        ↓
Content-addressed Approved Cache
        ↓
Dependency Snapshot
        ↓
Read-only mount into Mining / Repair
```

绝不采用：

```text
Sandbox 发现缺包
  → 临时启用公网
  → package manager 自由解析 latest
  → 执行 install script
```

### 9.2 Audit 的依赖策略

- 静态工具运行时和 Python/Java/Node tool dependencies 烘焙在工具镜像中；
- Tool 镜像用 digest 固定，tag 仅作可读别名；
- Pysa stub、CodeQL query pack、Semgrep rules、Trivy DB、OSV data 作为版本化只读 Artifact；
- Audit 不运行项目依赖安装；
- 只解析 lockfile/manifest 产生 dependency metadata；
- 缺失类型信息降低 dataflow completeness，记录 gap；
- CodeQL no-build 若仍需 restore dependency，应由 Dependency Gateway 预取并只读挂载；不得让 Audit Worker 自行联网；
- 若工具必须运行 build/autobuild 才能工作，移交 Mining，而不是提升 Audit 为 RX。

### 9.3 Mining 的依赖策略

- 先执行基于 lockfile 的 DRP；
- 从 DS 离线安装，默认禁用 install scripts/hooks；
- 某些 native extension/build backend 必须运行时，在 Mining Sandbox 内作为显式 invocation，记录源码、工具链、权限和输出；
- 构建结果是任务级 Environment Artifact，不晋升为全局缓存，除非通过单独 promotion；
- 环境准备失败与漏洞验证失败分开；
- 使用 mock/stub 替代真实云服务、支付、邮件、对象存储和消息服务；
- 只有协议真实性无法由本地服务替代时申请 NAG。

### 9.4 Repair 的依赖策略

- 默认复用漏洞基线的 DS digest；
- 每个 Patch 候选从同一只读依赖快照开始；
- 候选不得通过刷新依赖“顺便修复”原漏洞，除非 VEP 指明依赖升级就是修复策略；
- 若候选修改 lockfile/依赖版本，必须创建 Candidate Dependency Snapshot；
- 依赖差分进入 SCA、许可、SBOM、行为回归和供应链 Gate；
- 修复前后环境存在不可解释 drift 时不得标记 Verified；
- Repair 不能使用上一次 Mining 的 virtualenv、node_modules、Maven local repo 可写副本或构建目录。

### 9.5 语言生态策略矩阵

| 生态 | 预取/固定方式 | Sandbox 离线方式 | 关键风险与控制 |
|---|---|---|---|
| Python/pip | lock + pinned version + hashes；优先 wheelhouse | `--no-index --find-links`，要求 hash；默认 wheel-only | sdist/build backend 可执行代码，进入 Mining 显式构建 |
| Node/npm | `package-lock.json` + approved registry mirror | `npm ci` 语义，默认禁 lifecycle scripts；缓存只读 | pre/install/post/prepare scripts；Git/path dependency |
| Java/Maven | lock/解析清单 + 隔离 local repository | offline repo；固定 plugin/dependency | Maven plugin/build extension 会执行代码 |
| Java/Gradle | dependency cache snapshot + verification metadata | `--offline`；每任务 writable overlay | init/build scripts、plugin、dynamic/changing version |
| Go | `go.mod`/`go.sum` + internal GOPROXY/cache | `GOPROXY=off` 或只读 file/internal proxy；`go mod verify` | `direct` fallback、private module 泄露、关闭 sumdb |
| Rust/Cargo | `Cargo.lock` + `cargo vendor`/local registry | `--locked --offline` 或 `--frozen` | build.rs/proc macro 在构建时执行；vendor 校验边界 |
| OS packages | 预构建基础镜像层 + package manifest | 运行时不执行 apt/yum/apk | mutable repository、post-install script、root 权限 |
| Container images | OCI registry mirror + digest + signature/SBOM | 节点/Supervisor 预拉，Sandbox 不拉取 | mutable tag、跨 registry redirect、恶意 layer |

命令参数只是 Adapter 的实现建议，权威要求应写入 Tool/Dependency Contract，避免 Agent 自由拼接 shell。

### 9.6 Lockfile 缺失或不完整

分级处理：

| 情况 | 处置 |
|---|---|
| 完整 lock + hash | 可创建高复现 DS |
| lock 存在但缺 hash | Resolver 固定 Artifact digest，标记来源验证弱 |
| 只有宽松版本范围 | 在受信 Resolver 中解析一次并封存 resolved lock Artifact，不修改原仓库 |
| `latest`/SNAPSHOT/dynamic version | 默认拒绝或冻结当前解析结果并标记高风险 |
| VCS dependency | 固定 commit digest，禁止 branch-only |
| local/path dependency | 必须位于 snapshot 内，路径逃逸拒绝 |
| 私有依赖不可访问 | `dependency_unavailable`，等待授权或使用批准 fixture |
| 只有 sdist/源码构建 | Quarantine 后在 Mining/Repair 显式构建，不进入 Audit |

解析得到的临时 lock 只能用于该任务的可复现环境，不代表建议写回项目。

### 9.7 私有依赖与凭据

- 项目配置声明私有源范围；
- Credential Broker 按 repository/package scope、只读权限和短 TTL 获取凭据；
- 凭据只给 Dependency Fetcher，不给目标 Sandbox；
- Fetcher 日志进行 URL/userinfo/header 脱敏；
- private cache 按 tenant/project 隔离，禁止公共复用；
- 包内容可去重，但授权元数据和可见性仍隔离；
- 凭据过期只重试 fetch，不重放整个漏洞任务；
- 无授权时返回明确 dependency gap，不尝试公共同名包。

### 9.8 缓存安全

缓存键至少包含：

```text
ecosystem + package identity + version/commit
+ artifact digest + platform/arch/runtime ABI
+ source registry identity + policy version
```

控制：

- content-addressed、只读挂载；
- quarantine 与 approved namespace 分离；
- 公有与私有、不同租户、不同信任级别分区；
- cache promotion 需要校验结果，不能因“下载成功”自动晋升；
- 任务只能写 local overlay，不能写 approved cache；
- 命中缓存仍校验 digest 和策略有效期；
- 工具/包撤销后阻止新任务并标记依赖 Run 需要重评；
- 防 zip bomb、路径穿越、symlink、特殊设备、超大文件数和嵌套归档；
- GC 依据引用计数、保留策略和 legal hold，不删除仍被 VEP/RVR 引用的内容。

### 9.9 漏洞数据库与规则更新

Trivy DB、OSV 数据、Semgrep rules、CodeQL packs 等由独立 Sync Job：

1. 按固定 allowlist 下载；
2. 校验来源、digest/签名和版本；
3. 生成 Advisory/Rule Snapshot；
4. 记录生成时间、上游时间、TTL 和 coverage；
5. 推广到 approved store；
6. Sandbox 以只读 Artifact 使用并禁止自更新。

数据库过期时：

- 仍可按策略运行，但结果明确标记 `stale_database`；
- 超过 hard TTL 的安全发布 Gate 应暂停；
- 不允许 Trivy/OSV Worker自行访问公网更新；
- 同一对比/修复验证必须固定同一数据库 snapshot，另行运行“最新数据库补充扫描”。

---

## 10. 收敛后的 Audit Pipeline

### 10.1 总流程

```text
Trusted Source Materializer
        ↓
Pinned Read-only Repository Snapshot
        ↓
Audit Inventory Worker
        ↓
Repository Architecture Model
        ↓
Control Plane LLM Architecture Reasoning
        ↓
Attack Surface + Security Hypotheses
        ↓
Semantic Prioritization / Tool Planning
        ↓
┌──────── Tier 0 全仓低成本覆盖 ────────┐
│ AST/Bandit/Semgrep/Secret/SCA/IaC     │
└────────────────┬───────────────────────┘
                 +
┌──────── Tier 1 高风险语义分析 ────────┐
│ Call/Dataflow/Pysa/CodeQL no-build    │
└────────────────┬───────────────────────┘
                 +
┌──────── Tier 2 候选深度静态分析 ──────┐
│ Joern/Targeted Query/Evidence Slice   │
└────────────────┬───────────────────────┘
                 ↓
Evidence Normalization → Fusion → Adjudication
                 ↓
Audit Evidence Package
```

### 10.2 Semantic Prioritization，不是删除式剪枝

- Tier 0 不受 LLM 剪枝，保证全仓基础覆盖；
- Tier 1/2 由 RAM、攻击面、业务资产和 Hypothesis 决定预算；
- 未进入深度分析的范围保留 inventory 与 Tier 0 状态；
- Parser failure、oversize、symlink、unsupported language 都是 AEP coverage gap；
- LLM 每个架构/风险主张必须引用 RAM/源码位置；
- 原始 Signal 围绕 Issue/Hypothesis 融合，不与语义候选并列相加。

### 10.3 Audit Tool Worker

每个 Worker 获得：

- 同一 snapshot 的只读 scope；
- 单一或小型兼容 Tool Bundle；
- 只读规则/数据库；
- 明确 output schema；
- 独立 `/tmp` 和 outbox；
- network none；
- 无项目依赖安装能力。

Worker 之间不共享可写缓存。可复用分析缓存必须由平台以工具版本、规则、snapshot 和配置生成内容寻址 Artifact，再以只读形式挂载。

### 10.4 LLM 架构理解

LLM 不遍历磁盘、不调用 shell，只消费：

- Repository Tree/Map；
- Function/Class/Route/Config Index；
- 调用、数据流和依赖图摘要；
- Tool Evidence Slice；
- 受预算限制的源码片段；
- 明确标记的不可信 README/comment 内容。

LLM 输出 Structured Tool Request，经 Policy Engine 检查 stage、scope、tool、resource、network 和 output contract 后，才能生成新 Worker task。

### 10.5 Audit 与需要构建的分析器

工具标签必须声明：

```text
static_source_only
dependency_restore_without_hooks
repository_build_required
target_execution_required
```

只有前两类且满足 Audit Policy 才可进入 Audit。以 CodeQL 为例，可使用支持的 no-build 模式；若 autobuild/manual build 会执行 `make`、Gradle、Maven 或仓库脚本，则转为 Mining 深度验证任务。准确性损失进入 AEP，不通过扩大权限隐藏。

---

## 11. Mining 与 Repair 的通信/环境闭环

### 11.1 Mining 输入

```text
AEP + RAM refs
Pinned Snapshot
Selected Hypothesis
Tool Bundle Manifest
Dependency Snapshot
Validation Plan
Sandbox/Network Policy
```

Mining 首先验证所有 digest 和 environment requirements，再构造内部实验拓扑。环境不完整时先返回 `environment_blocked`，不得把 Harness 启动失败裁决为 refuted。

### 11.2 Mining 内部多容器拓扑

对于 HTTP/SQL/Queue 等场景：

```text
           internal-only network
┌────────┐     ┌────────┐     ┌──────────┐
│Harness │ ──▶ │ Target │ ──▶ │ Test DB  │
└────────┘     └────────┘     └──────────┘
      │              │
      └──────▶ Trusted Observer
```

- 所有容器只属于同一 sandbox_id；
- 无默认外部路由；
- Test DB/Service 使用合成数据和 canary；
- Observer 尽可能独立于目标进程；
- 任务结束封存状态差分后销毁网络和 volumes；
- 运行拓扑进入 SRM/VEP。

### 11.3 Repair 候选隔离

每个候选必须至少拥有独立 writable overlay、服务状态和运行记录。高风险或有状态验证建议 candidate-per-sandbox：

```text
Pinned Snapshot + same DS
   ├─ Candidate A Sandbox → Gate Matrix A
   ├─ Candidate B Sandbox → Gate Matrix B
   └─ Candidate C Sandbox → Gate Matrix C
```

不能让候选 A 的数据库迁移、缓存、生成文件或端口服务影响候选 B。

### 11.4 修复验证 Gate 补充

V2 的 G0–G12 保留，新增环境与网络检查：

| Gate | 新增要求 |
|---|---|
| G0 Input Integrity | AEP/VEP/RAM/TBM/DS/SRM digest 全部一致 |
| G1 Scope | 禁止未声明依赖、网络和 CI 配置变化 |
| G2 Build | 使用同一离线 DS；记录 build scripts |
| G3/G4 Tests | 基线与候选使用同一内部服务拓扑和 seed |
| G5/G6 PoC/Oracle | 重放 VEP 环境；网络 grant 不得扩大 |
| G7/G8 Static/Diff | 固定规则/DB snapshot，另做 latest supplemental run |
| G9 Behavior Diff | 区分代码变化与环境/依赖 drift |
| G10 Re-fuzz | 独立 scratch 与 corpus 输出 |
| G11 Reproducibility | 新 Worker、新 Sandbox、重新挂载同一 DS |
| G12 Provenance | 所有 NAG、SRM、依赖和 cleanup proof 完整 |

---

## 12. Tool Registry 与网络/执行策略扩展

在 V2 Tool Descriptor 上新增：

| 字段组 | 字段 |
|---|---|
| Stage | allowed_stages、execution_class、target_execution_possible |
| Build | requires_project_build、may_run_hooks、supports_no_build |
| Network | default_mode、required_hosts、telemetry/update endpoints、offline flags |
| Dependencies | baked_in、external DB/rules、runtime package needs、cache layout |
| Image | registry、digest、signature、SBOM、base image、OS/arch |
| Filesystem | snapshot access、tmp/output、cache read/write、special mounts |
| Secrets | secret types、required audience、redaction |
| Output | schema、max files/bytes、archive behavior、parser risk |
| Isolation | minimum backend、seccomp/AppArmor、gVisor/VM requirement |

Tool Planner 必须区分：

- 工具本身需要联网更新；
- 工具分析目标时需要联网；
- 工具需要项目依赖；
- 工具会隐式触发构建/脚本；
- 工具只需要平台预同步的数据。

生产策略应把前四类默认转化为预取 Artifact 或更高阶段任务，而不是给 Tool Worker 开通通用 egress。

---

## 13. LIMA 模块复用、重构与新增

### 13.1 复用

| 当前模块 | 复用方向 |
|---|---|
| repository source/materializer/cache/workspace | Source Materializer、pinned snapshot 和缓存基础 |
| `task_queue.py` | Control Channel 的初始任务队列；增加 lease/attempt/idempotency |
| `task_progress.py` / `task_failure.py` | typed stage/run/failure 状态 |
| `experiments.py` | Run、budget、event、artifact checksum、resume/cancel |
| SQLite/Postgres store | Task/Artifact/Tool/Sandbox/Dependency/Grant 索引 |
| `runtime.AgentLoop` | Planner 循环和结构化参数校验；移除直接自由工具调用 |
| `repair_workspace.py` | Repair 一次性 workspace 与路径安全基础 |
| observability/audit log | task/run/sandbox/tool/network/artifact 全链追踪 |

### 13.2 重构

| 模块 | 重构 |
|---|---|
| repository import/materializer | 拉取与解析分离；归档安全、snapshot manifest、只读交付 |
| `runtime.ToolRegistry` | Catalog/Retriever/Planner/Bundle/Gateway，增加 stage/network/build policy |
| `agents.py` | Agent 只产生 Structured Request；事实只引用 Artifact |
| scanner/semantic triage | 迁移到 Audit Orchestrator 和 Tool Worker |
| context manager | 只读取 RAM/Evidence Slice，不允许 shell/全目录漫游 |
| repair verifier | 使用候选独立 Sandbox、DS 一致性与完整 SRM |
| stores | Artifact immutable revision、task lease、outbox、grant、cache lineage |

### 13.3 新增逻辑模块

```text
lima/control/
  workflow_engine
  policy_engine
  task_manifest
  lease_manager
  state_outbox

lima/communication/
  worker_protocol
  artifact_refs
  event_schema
  idempotency
  dispute_protocol

lima/sandbox/
  manager
  worker_supervisor
  policy_compiler
  docker_backend
  kubernetes_backend
  hardened_backend
  inbox_outbox
  cleanup_verifier

lima/network/
  policy
  access_grant
  egress_proxy_adapter
  dns_guard
  audit

lima/dependencies/
  manifest_parser
  resolver
  fetcher
  quarantine
  snapshot
  cache
  credential_broker
  ecosystem_adapters

lima/artifacts/
  registry
  gateway
  schema
  validator
  content_store
  provenance
  signer

lima/audit/
  inventory_worker
  architecture_model
  semantic_prioritization
  tool_worker_orchestrator
```

这些是逻辑边界，可先在现有包内实现接口，再按依赖成熟度拆分服务，避免一开始微服务化过度。

---

## 14. 异常处理与兜底矩阵

### 14.1 通信与 Artifact

| 失败 | 处置 | 禁止兜底 |
|---|---|---|
| Task 重复投递 | 以幂等键返回已有结果或新 attempt | 重复修改同一 workspace |
| Lease 过期 | 停止/隔离旧 Worker，重新调度 | 两个 Worker 同时提交权威结果 |
| Control Plane 暂时不可用 | Supervisor 有界完成当前 invocation，封存本地 outbox，等待重连 | Sandbox 直接写 DB |
| Artifact 下载中断 | digest-aware resume；失败则不启动 Sandbox | 使用不完整输入 |
| Artifact digest 不符 | quarantine、告警、拒绝任务 | 忽略校验 |
| Outbox 上传失败 | 本地加密 spool + 有界重试；保持任务未提交 | 标记完成后丢证据 |
| Output 超限 | 终止/截断并记录 coverage degradation，原始片段封存 | 静默截断后声称完整 |
| Schema 不兼容 | 使用受信迁移器或拒绝 | 让 LLM 猜字段 |
| Evidence Dispute | 新建上游重评任务和 Artifact revision | 原地修改 VEP/AEP |

### 14.2 网络

| 失败 | 处置 | 禁止兜底 |
|---|---|---|
| DNS 不可用 | N0/N1 使用本地映射；N3 重试策略解析器 | 改用任意公共 DNS |
| Egress Proxy 不可用 | 有界重试/改期；使用已批准缓存 | 直连公网 |
| 域名解析到私网/metadata | 阻断并记 policy violation | 跟随重定向 |
| 上游重定向到未授权域 | 拒绝或重新审批 | 自动携带 Authorization |
| TLS/签名错误 | quarantine 并告警 | 关闭校验 |
| NAG 过期 | 终止新连接，保存 partial evidence | 自动续期 |
| 外部服务 rate limit | backoff、缓存、延迟任务 | 扩大并发绕过 |
| 网络验证不可替代但审批拒绝 | runtime-gap / environment-blocked | 使用真实生产目标 |

### 14.3 依赖

| 失败 | 处置 | 结论语义 |
|---|---|---|
| 缓存未命中 | Brokered Fetch；无法获取则 dependency_unavailable | 不得判定漏洞不存在 |
| lock 与 manifest 不一致 | Resolver 拒绝或生成明确 drift 计划 | 环境不可复现 |
| checksum mismatch | quarantine、撤销缓存、供应链告警 | 不安装 |
| 私有凭据缺失/过期 | Credential Broker 重取；无授权则暂停 | 不回退公共同名包 |
| install script 被禁止 | 报告 exact package/script；审批后只在 Mining/Repair 运行 | Audit 仍禁止 |
| 只有 sdist | 专用 build Sandbox/Mining invocation；产出 task-local wheel | 不在 Audit 构建 |
| native library 缺失 | 选择批准基础镜像或标记 platform gap | 不执行 apt/yum 公网安装 |
| 动态版本/SNAPSHOT | 冻结 resolved digest + 高风险标记或拒绝 | 不随时间漂移 |
| DB/rules 过期 | 标记 stale；hard TTL 后阻塞发布 Gate | Worker 自更新 |
| Cache 被撤销 | 阻止新用并找到依赖 Run 重评 | 继续信任旧结果 |

### 14.4 Sandbox

| 失败 | 处置 |
|---|---|
| Provision 失败 | 基础设施有界重试，attempt+1 |
| OOM/PID/Disk/Timeout | partial SRM；缩小 scope 或申请新预算，不产生安全结论 |
| Cleanup 验证失败 | 隔离 Worker node，停止复用，安全告警 |
| Observer 失败 | 结果降级为 inconclusive，不能仅信任 target logs |
| Internal service 未就绪 | 环境失败，与 PoC 失败分离 |
| Candidate cross-contamination | 全部受影响候选结果作废并重新运行 |
| Policy violation | 立即终止、封存证据、撤销 grants、审计 |

---

## 15. 可观测性、审计与成本

### 15.1 关联 ID

所有日志和指标携带：

```text
tenant_id / project_id
repository_id / snapshot_digest
workflow_id / task_id / attempt / lease_id
stage / sandbox_id / worker_id
tool_id / invocation_id
artifact_id / dependency_snapshot_id
network_grant_id / candidate_id / gate_id
```

### 15.2 必报指标

#### 通信

- queue delay、lease expiry、duplicate delivery；
- artifact upload/download latency、resume、digest failure；
- outbox spool size、schema rejection；
- dispute/re-evaluation 数量和闭环时间。

#### Sandbox

- provision/start/cleanup latency；
- CPU/memory/PID/disk/time utilization；
- policy violation、unexpected network attempt；
- per-stage success/infra-failure/inconclusive。

#### 依赖与网络

- cache hit/miss、approved/quarantine/rejected；
- dependency resolution completeness；
- unpinned/dynamic/private/VCS dependency；
- brokered fetch success、bytes、domains、latency；
- NAG issue/deny/expire；
- advisory DB age、hard TTL breach；
- environment fidelity 和 pre/post drift。

#### 安全成果

沿用 V2：Issue compression、Expert Review Reduction、D3/D4 reproduction、VEP replay、Verified Patch Yield、Functional Regression Escape。

### 15.3 数据最小化

- 默认不把完整源码、依赖私有 URL 和原始 secret 放入日志；
- Artifact 按 tenant/project ACL；
- VEP PoC 可能具有攻击性，单独 sensitivity 和下载审批；
- stdout/stderr 脱敏版本供 UI，原始版本受限封存；
- 网络抓包仅在策略要求时保存，避免无差别捕获敏感数据；
- TTL/保留由 Artifact 类型和项目政策决定。

---

## 16. 前端与运维体验

### 16.1 三阶段视图

每个 Issue 显示：

- Audit Analysis Sandbox：RAM、Tier 覆盖、Tool Worker、静态 gap；
- Mining Sandbox：DS、内部拓扑、Harness、Oracle、网络模式、复现次数；
- Repair Sandbox：候选、环境一致性、G0–G12、行为差分和最终 Patch。

### 16.2 环境与网络解释

用户应看到：

- 为什么需要某个依赖或网络访问；
- 是否命中批准缓存；
- 使用的依赖、规则、数据库和镜像 digest；
- 网络访问的域、时间、数据量和审批；
- 哪些生命周期脚本被阻止或执行；
- 环境与真实部署的差异；
- 失败是“漏洞被反驳”还是“环境无法建立”。

### 16.3 人工审批对象

- NAG 与高风险网络例外；
- 私有依赖授权；
- install/build script allowlist；
- 新 Tool/镜像/数据库 Promotion；
- 高风险 Sandbox backend；
- Evidence Dispute；
- 依赖升级型 Patch；
- Verified Patch 合并/发布。

审批请求必须具体到 task、purpose、scope、TTL、预期输出和失败行为，不能是“是否允许联网”这种泛化问题。

---

## 17. 分阶段实施路线（约 26–30 周）

### Phase 0：契约与威胁模型（第 1–3 周）

交付：

- 固化 R--/RX-/RWX 与禁止行为；
- Common Envelope、RAM/AEP/VEP/RVR、Task Manifest、TBM、DRP/DS、SRM、NAG Schema；
- typed failure、state transition、dispute protocol；
- LlamaFactory 固定 snapshot 与现有 896/902 基线；
- ADR 和威胁模型评审。

退出门槛：任意跨阶段事实都有 Artifact 类型；缺失或错误 digest 能阻止下游。

### Phase 1：Audit Analysis Sandbox MVP（第 4–7 周）

交付：

- Source Materializer 与只读 snapshot manifest；
- Docker Sandbox Manager/Worker Supervisor；
- network none、非 root、只读 rootfs、资源限制；
- Inventory、现有 AST/Bandit、Semgrep、Trivy 独立 Tool Worker；
- Tool Worker inbox/outbox；
- Repository Architecture Model；
- LLM Structured Tool Request + Policy Engine；
- Audit 禁止目标执行的自动策略测试。

退出门槛：恶意仓库解析不触及主进程；Worker 无 LIMA/DB/Git/LLM 凭据；Audit 无法运行测试、build 或安装项目依赖。

### Phase 2：Artifact/Communication Plane（第 8–11 周）

交付：

- Artifact Gateway、内容寻址 store、Schema/digest/signature；
- Task lease、attempt、heartbeat、cancel、幂等；
- Supervisor 本地 spool 与断线恢复；
- Artifact lineage 和事务 outbox；
- AEP→Mining、VEP→Repair 交接；
- Evidence Dispute/Enrichment Request；
- clean-room replay 基础。

退出门槛：三个 Sandbox 不直连、不共享可写 volume；任务重复/Worker 崩溃不产生双重权威结果；任务完成前 Artifact 已封存。

### Phase 3：Dependency Gateway 与网络治理（第 12–16 周）

交付：

- DRP/DS、Resolver、Fetcher、Quarantine、approved cache；
- Python/pip 与 Node/npm 首批生态 Adapter；
- 私有依赖 Credential Broker；
- Tool/OCI/Trivy DB/OSV/rule snapshot 同步；
- N0/N1/N2/N3 policy compiler；
- internal test network；
- egress proxy、DNS guard、NAG 和审计；
- checksum mismatch、cache poisoning、upstream outage 演练。

退出门槛：Mining/Repair 可在断网条件从同一 DS 重建环境；缓存缺失不会使 Sandbox 开公网；私有凭据不进入目标容器。

### Phase 4：Mining 纵向闭环（第 17–20 周）

交付：

- Hypothesis→Validation Plan→Harness→Oracle；
- CWE-22、CWE-78、CWE-89；
- 多容器内部实验拓扑；
- Observer、coverage、稳定复现、最小化；
- VEP + DS/TBM/SRM/NAG lineage；
- environment-blocked 与 runtime-refuted 分离。

退出门槛：VEP 在全新 Worker 中用同一 DS 重放；无网络/依赖/Observer 失败不会升级或清除漏洞。

### Phase 5：Repair Verification 闭环（第 21–24 周）

交付：

- candidate-per-workspace/sandbox；
- 同 DS 的 baseline/candidate 对比；
- V2 G0–G12 + dependency/network consistency；
- Functional/Security Preservation；
- 依赖变更型候选 Gate；
- RVR、Verified Patch、Evidence Dispute；
- 人工发布审批。

退出门槛：Repair 不可见 Mining 状态；候选间无污染；改变依赖或网络才通过的候选不能伪装成代码修复。

### Phase 6：语言扩展与生产治理（第 25–30 周）

交付：

- Maven/Gradle、Go、Cargo Dependency Adapter；
- CodeQL/Pysa/Joern 分阶段执行策略；
- Kubernetes backend、default-deny NetworkPolicy；
- gVisor/VM hardened tier；
- Tool/Dependency revocation 与 selective re-evaluation；
- 多租户缓存隔离、SLO、容量、成本和灾备；
- shadow→assist→verified 发布梯度。

---

## 18. 建议立即启动的四个 Sprint

### Sprint 1：让 Audit 真正离开主进程

- 定义 Audit Tool Worker Contract；
- snapshot RO mount、network none、无凭据；
- 将 Inventory 与一个现有静态分析器放入独立 Worker；
- 通过 inbox/outbox 返回原始结果；
- 对恶意 symlink、archive bomb、超大输出和 parser crash 做故障注入。

完成标志：Audit Worker 被攻陷也拿不到主服务、数据库、Git/LLM token 或其他仓库。

### Sprint 2：打通 Artifact-only AEP→Mining

- RAM/AEP/Task/SRM Schema；
- Artifact digest/lineage/store；
- task lease 与 attempt；
- 由 Supervisor 准备 inbox、收集 outbox；
- 禁止 Sandbox-to-Sandbox、共享 RW volume 和直接 DB 写入。

完成标志：关闭网络后仍能完成 Audit 并将 AEP 可靠交给新建 Mining Sandbox。

### Sprint 3：Python 离线依赖纵向切片

- 解析 requirements/lock；
- Gateway 预下载固定 wheel、hash/SBOM/许可/安全检查；
- 生成 DS 并只读挂载；
- Mining 离线建环境；
- sdist/build backend 明确转入 RX invocation；
- 代理故障、hash mismatch、私有包无授权等失败演练。

完成标志：Sandbox 不接公网也能重建已批准 Python 环境；失败原因不被误判为漏洞结论。

### Sprint 4：CWE-22 三沙箱闭环

- Audit 产生路径穿越 Hypothesis；
- Mining 通过 canary 文件树、内部 Harness 和路径 Oracle 生成 VEP；
- Repair 用同一 DS 生成多个候选并运行 Gate；
- 全程记录 RAM/AEP/DRP/DS/TBM/SRM/VEP/RVR；
- 在全新 Worker clean-room replay。

完成标志：没有 Agent memory、共享 workspace 或临时开网也能得到 Verified Patch。

---

## 19. 验收测试清单

### 19.1 Audit 隔离

- 仓库中的 `setup.py`、hooks、测试和 binary 均无法在 Audit 被执行；
- Analyzer crash 不影响 Control Plane；
- Audit Worker 无公网、LIMA API、DB、Redis、Git、LLM 和对象存储凭据；
- Tool Worker 只能读取声明 scope；
- 超出 outbox 限额的输出被终止并记录；
- CodeQL/build-required 分析被正确标记为 execution-required gap。

### 19.2 通信与 Artifact

- Sandbox 间不存在可达网络；
- AEP/VEP/RVR digest 被修改后下游拒绝；
- 重复 Task 不产生重复权威 Artifact；
- Worker 在上传中崩溃可 resume，任务不提前完成；
- Control Plane 暂时断开时不丢 outbox；
- Evidence Dispute 生成新任务而不修改原 Artifact；
- 清理失败会隔离 Worker node。

### 19.3 网络

- N0 只有 loopback；
- N1 服务互通但无法出网；
- DNS rebinding、redirect、IP literal、metadata 和私网目标被阻断；
- NAG 到期后新连接失败；
- 审批域以外的请求被记录并终止；
- Sandbox 无法绕过 proxy 直连；
- LLM Provider、包源和 Artifact Store 凭据不进入目标容器。

### 19.4 依赖

- hash mismatch 包无法晋升；
- cache miss 不触发 Sandbox 公网；
- 公私同名包不会 fallback；
- install script 默认不执行；
- 同一 DS 在 Mining 和 Repair 解析结果一致；
- Repair 候选不能静默刷新依赖；
- cache 跨租户不可读；
- 撤销包/工具能定位依赖 VEP/RVR；
- stale advisory DB 会影响发布 Gate 而不是静默使用。

### 19.5 安全闭环

- 环境失败、Harness 失败、路径未覆盖与 runtime-refuted 区分；
- VEP 在干净 Sandbox 重放；
- Repair candidate 间状态隔离；
- 原 PoC 失败但合法功能也失败的候选被淘汰；
- 只有安全与功能双保持、环境一致、Artifact 完整的候选可标记 Verified。

---

## 20. 架构决策记录（ADR）

建议在 V2 ADR 基础上新增：

1. **ADR-013：Audit 必须运行在 R-- 隔离域。**
2. **ADR-014：Audit Sandbox 是按需 Tool Worker 集合，不是巨型工具容器。**
3. **ADR-015：项目构建、依赖 lifecycle 和 import side effect 均属于目标执行。**
4. **ADR-016：Sandbox 之间无直连网络和共享可写状态。**
5. **ADR-017：Control 消息、Artifact 数据、Observability 三通道分离。**
6. **ADR-018：Worker Supervisor 而非目标容器持有平台通信凭据。**
7. **ADR-019：任务至少一次投递，以 digest/attempt 幂等，不追求隐式 exactly-once。**
8. **ADR-020：依赖通过 DRP→Quarantine→DS 进入 Sandbox。**
9. **ADR-021：Cache miss 不允许自动回退公网。**
10. **ADR-022：Sandbox 网络采用 N0/N1/N2/N3 分级和 NAG。**
11. **ADR-023：模型 API 只由 Control Plane 调用。**
12. **ADR-024：Mining 与 Repair 基线使用同一 Dependency Snapshot。**
13. **ADR-025：下游质疑通过 Evidence Dispute 触发新任务，不修改上游 Artifact。**
14. **ADR-026：漏洞/规则数据库由平台同步为固定快照，Worker 禁止自更新。**

---

## 21. V3 Definition of Done

### Audit

- 所有仓库解析与静态分析离开 Control Plane；
- Audit 只读、无目标执行、无项目依赖安装、默认无网；
- LLM 只消费 RAM/Evidence Slice，只生成结构化请求；
- 全仓 Tier 0 + 高价值 Tier 1/2 并存；
- build-required 分析不会偷渡执行权限；
- AEP 包含 Worker、工具、规则/DB、coverage 和执行缺口 lineage。

### Communication

- 三 Sandbox 无直连、无共享 RW volume、无直接 DB/Artifact Store 写权限；
- Task Manifest、lease、attempt、inbox/outbox、SRM 完整；
- Artifact 在状态提交前完成 Schema/digest/provenance 校验；
- 重试、重复、断线、取消和争议不会破坏不可变历史；
- 任何结论都可追到固定输入和干净重放步骤。

### Network and Dependencies

- 默认 Hermetic Offline；
- 缺依赖通过 Gateway，不通过给 Sandbox 开网；
- 包、镜像、规则、DB 按 digest 固定并有来源；
- private credential 只存在于 Broker/Fetcher；
- N1 内部网络无外部路由，N3 有短时 Grant 和全审计；
- 修复前后使用同一 DS，环境 drift 可检测；
- 上游、缓存、凭据和数据库失败有明确安全降级。

### Mining and Repair

- Mining 只有在可重复破坏安全不变量后确认漏洞；
- 环境/网络失败不被当作漏洞反证；
- VEP 带完整 DS/TBM/NAG/SRM 并能 clean-room replay；
- Repair 从全新 snapshot 和同一 DS 启动；
- 候选相互隔离，安全与功能 Gate 独立；
- 只有通过全部 Gate 的 Patch 才标记 Verified；
- 发布仍需项目策略或人工批准。

---

## 22. 最终建议

V3 的实施优先级应从“先做三个功能型 Agent”调整为“先建立三个安全执行域及其交换协议”：

1. 先把 Audit 静态工具移出主进程，证明 `R--` 边界；
2. 再完成 Task Manifest、Supervisor、inbox/outbox 和 Artifact Registry；
3. 再做 Dependency Gateway、离线 Dependency Snapshot 和网络分级；
4. 然后用一个 CWE 打通 Audit→Mining→Repair；
5. 最后扩展更多工具、语言、网络场景和自主 Tool Evolution。

如果通信和依赖治理没有先完成，三个 Sandbox 只会成为三个名字不同但通过共享 volume、开放网络和临时脚本耦合的容器，无法提供可信隔离与可复现性。正确的平台应让 Sandbox 即使完全不知道其他阶段的地址、凭据和运行状态，仍能仅凭固定输入 Artifact 完成本阶段任务，并产出可被下游独立验证的新 Artifact。

LIMA 的护城河不是“容器化运行了几个安全工具”，而是：

```text
可证明的权限边界
+ 可复现的环境快照
+ 不可变的证据交换
+ 受控的依赖和网络供应链
+ 真实执行的漏洞 Oracle
+ 独立验证的修复 Gate
```

这六项共同成立，三阶段 Agent 才是可信平台，而不是三个共享上下文的自动化脚本。

---

## 23. 参考资料

### 项目内材料

- `docs/LIMA_证据驱动三阶段安全平台_迭代规划_v2.md`：证据模型、Tool Registry、Mining 与 Verified Repair 基线；
- `D:/DownloadPackage/LIMA_Audit_Mining_Repair_Sandbox_Architecture.md`：Audit R-- 收敛、三阶段权限与 Tool Worker 设计；
- `docs/LIMA_可信审计挖掘修复闭环_迭代规划.md`：Finding 降噪、Issue/Evidence/Decision 初始规划；
- 当前 `main`：`bf7d79d`。

### 外部一手资料

- [Docker none network driver](https://docs.docker.com/engine/network/drivers/none/)：完全隔离容器网络，仅保留 loopback；
- [Docker Compose internal networks](https://docs.docker.com/reference/compose-file/networks/)：创建无外部连接的容器内部网络；
- [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)：default-deny ingress/egress 及 DNS 注意事项；
- [Kubernetes Service Accounts](https://kubernetes.io/docs/concepts/security/service-accounts/)：短期、受众绑定 token 与关闭自动挂载；
- [Kubernetes Init Containers](https://kubernetes.io/docs/concepts/workloads/pods/init-containers/)：通过共享 volume 在主工作负载启动前准备数据；
- [pip Secure Installs](https://pip.pypa.io/en/stable/topics/secure-installs/) 与 [pip download](https://pip.pypa.io/en/stable/cli/pip_download/)：固定版本、hash 校验、预下载和离线安装；
- [npm ci](https://docs.npmjs.com/cli/commands/npm-ci/) 与 [npm lifecycle scripts](https://docs.npmjs.com/cli/using-npm/scripts/)：lockfile 冻结安装和 install script 风险；
- [Go Modules Reference](https://go.dev/ref/mod)：GOPROXY、GOSUMDB、module cache 和 hash 验证；
- [Cargo vendor](https://doc.rust-lang.org/cargo/commands/cargo-vendor.html) 与 [Cargo source replacement](https://doc.rust-lang.org/cargo/reference/source-replacement.html)：vendoring、offline/locked 与镜像；
- [Maven dependency:go-offline](https://maven.apache.org/components/plugins/maven-dependency-plugin/go-offline-mojo.html)：预解析依赖和插件；
- [Gradle Dependency Caching](https://docs.gradle.org/current/userguide/dependency_caching.html)：只使用缓存的 offline 模式；
- [CodeQL for compiled languages](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-for-compiled-languages) 与 [CodeQL build options](https://docs.github.com/en/code-security/reference/code-scanning/codeql/build-options-for-compiled-languages)：no-build、autobuild/manual build 与依赖恢复差异；
- [Trivy air-gapped environments](https://trivy.dev/docs/latest/guide/advanced/air-gap/) 与 [Trivy Databases](https://trivy.dev/docs/dev/configuration/db/)：离线扫描、自托管和预下载数据库；
- [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec)：按 digest 分发容器和通用 Artifact；
- [SLSA Provenance v1.2](https://slsa.dev/spec/v1.2/provenance)：Artifact 生产过程与输入来源；
- [Sigstore Cosign verification](https://docs.sigstore.dev/cosign/verifying/verify/)：镜像与 Artifact 签名验证；
- [gVisor documentation](https://gvisor.dev/docs/)：高风险工作负载的强化 OCI 隔离选项。
