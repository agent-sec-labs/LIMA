# LIMA：仓库级代码审计、漏洞挖掘与可验证自动修复 Agent 计划书

版本：v1.8  
日期：2026-08-24  
目标：把当前 PR Diff 审查原型升级为一个可复现、可评测、适合秋招展示，并具备继续开展“大模型自动化漏洞检测”研究能力的仓库级安全 Agent。

实施状态（2026-08-24）：

- [x] 项目安全迁移到 `D:\BaseAIProject\LIMA`，并完成逐文件 SHA-256 校验。
- [x] 修复 SQLite 事务连接未关闭导致的 Windows 文件句柄泄漏。
- [x] 将自动修复测试从引号文本匹配改为 AST 语义验证。
- [x] 当前完整测试由 13 passed / 39 errors / 1 failure 恢复并扩展为 117 项；Windows 116 passed / 1 symlink permission skipped，Linux 容器 117/117 passed。
- [x] Compose 移除默认共享认证密钥和管理员密码，并默认仅绑定本机端口。
- [x] 建立非 root、只读根文件系统的容器运行时与本地随机凭据引导脚本。
- [x] 容器测试 117/117 通过，PostgreSQL、Redis、Web 服务全栈健康；官方基础镜像经 AWS Public ECR 拉取并锁定 digest。
- [x] 建立 Windows/Linux CI 和项目元数据。
- [x] 实现只读、有资源边界的 `RepositoryWorkspace` 和无需 API 的本地仓库扫描 CLI。
- [x] Python 仓库默认使用 AST 安全分析，文本规则退为非 Python 兜底；项目自扫描噪声由 107 条降至 2 条可复核候选。
- [x] 队列关闭改为等待在途任务完成，消除 Windows 异步测试的数据库句柄竞态。
- [x] 接入 Bandit 并统一 CWE、来源、证据类型、指纹和验证状态；支持多源证据融合。
- [x] 增加无网络、只读挂载的 Docker 仓库扫描命令，并将 required SAST 基线接入 CI。
- [x] 服务端只接受白名单导入根目录下的仓库键；仓库扫描已接入 RBAC、异步队列、PostgreSQL、审计日志和管理台。
- [x] 真实 API 冒烟测试完成 AST + Bandit 的 CWE-95 证据融合，并拒绝目录穿越输入。
- [x] 实现 Python 单函数 def-use/source-to-sink 证据路径，覆盖 CWE-95/78/89/502/22，并验证类型转换、参数化 SQL 和安全重赋值不会被错误提升。
- [x] 增加 verified-only CI 门禁与自动修复资格门禁；未验证候选不得触发补丁生成或仓库文件读取。
- [x] 增加 `--dataflow on/off` 消融开关，可直接复现 AST-only、AST+Bandit、AST+Dataflow、Hybrid+Verifier 四组基线。
- [x] 实现同文件顶层函数索引、实参与形参绑定、返回值摘要和最长 4 层调用传播；递归、超预算和未解析调用显式计数并降级。
- [x] v0.8 真实 API 冒烟测试完成两条调用边与一次返回传播的 CWE-95 证据链；AST、Bandit、数据流三源融合，且持久化任务不暴露宿主绝对路径。
- [x] v0.9 建立仓库级 Python 模块/静态 import 索引，支持模块别名、函数别名和相对导入；证据步骤保留各自文件路径。
- [x] 循环调用、深度超限、动态导入、重复模块和名称遮蔽均显式计数或保守降级；单个语法错误不阻断其他模块。
- [x] v0.9 真实 API 冒烟测试完成 `app.py → normalizer.py → executor.py` 跨文件 CWE-95 路径，2 条跨文件调用边、0 截断、0 未解析。
- [ ] 锁定并自动更新第三方依赖。
- [x] v1.0 为 CWE-78/CWE-89/CWE-22 建立根因约束与 fail-closed 最小补丁模板：固定 argv/禁用 shell、DB-API 值参数化、规范化路径根目录包含校验。
- [x] v1.0 建立独立 AST 安全 Oracle、完整仓库前后差分复扫、强制原生回归测试、不可变 SHA 取件、原子提交和 Draft PR 人工审批闭环。
- [x] 对动态可执行文件、Shell 语法、动态 SQL 结构、未知 paramstyle、未证明可信根目录与辅助符号冲突明确 abstain；CWE-22 TOCTOU 残余风险进入 manifest 和文档。
- [x] v1.0 Windows 全量回归、Linux 只读容器回归、自扫描 verified-only 高危门禁与运行服务 API 冒烟全部通过；服务版本升级至 1.0.0。
- [x] v1.1 增加仓库内容指纹与只读修复预览；扫描后仓库变化会 fail closed，预览不会修改导入仓库或冒充已通过原生测试。
- [x] v1.1 建立 18 个 CWE-22/78/89 修复约束用例和跨 Windows/Docker 可复现报告，统计验证修复、正确 abstention、Oracle 与不安全补丁逃逸指标。

## 0. 当前流程复盘与两周执行计划

当前系统有两条可运行入口：PR Diff 通过服务端多 Agent 流程审查；完整本地仓库通过只读 `RepositoryWorkspace` 执行 AST + 仓库级有界数据流 + Bandit 混合扫描。两者输出同一个 `Finding` 结构；完整仓库扫描已接入 Web 任务中心，能解析受支持的静态 import 并输出跨文件 source-to-sink 路径、真实文件定位和调用预算指标。下一缺口是面向首批 CWE 的可验证最小安全修复。

下一阶段按工程收益排序：

1. **P0 检测闭环（已完成）**：完成 SAST 适配、结构化证据、多源融合、失败降级、CI 门禁和隔离扫描命令；`--sast required` 已在无网络只读容器中稳定产出报告。
2. **P0 服务接入（已完成）**：只接受白名单根目录内的相对仓库键，不开放任意服务端路径读取；扫描任务、证据和报告已持久化并展示在管理台。
3. **P1 同文件证据验证（已完成）**：Python def-use/source-to-sink 已覆盖五类汇点、同文件直接调用、实参/形参和返回值传播，并输出逐行证据；递归和未解析调用安全降级。
4. **P1 跨文件证据图（已完成首版）**：解析模块/函数别名和相对 import，跨文件复用调用预算并保留逐文件证据；动态导入、类方法和反射派发继续 abstain。
5. **P1 修复闭环（已完成首版）**：CWE-22/78/89 已具备根因约束、最小补丁、AST Oracle、差分复扫、原生测试、Draft PR 与快照固定的只读预览。
6. **P2 实验与秋招包装（进行中）**：已建立 synthetic-controlled 修复约束集；下一步引入授权真实漏洞/修复对，只保留 AST-only、Bandit-only、Hybrid、Hybrid+Verifier 四组强基线。

## 1. 执行摘要

项目可以升级，但不能简单地继续增加 Agent 数量或提示词长度。近年的实证研究反复表明：

1. 仅基于函数或 Diff 的漏洞分类指标容易被数据重复、标签噪声和训练泄漏显著高估。
2. LLM 单独处理全仓库时容易丢失上下文、幻觉数据流，并产生大量误报。
3. 当前更可靠的路线是神经符号结合：程序分析缩小搜索空间，LLM 负责安全语义、规划与解释，确定性工具负责验证。
4. 自动修复必须包含故障定位、候选生成、编译/测试/安全 Oracle 验证，不能以“生成了类似人工补丁的文本”作为成功。
5. 复杂多 Agent 并不天然优于简单流水线；需要通过消融实验证明每个角色的必要性。

因此，LIMA 的目标形态确定为：

> 一个以程序分析为事实底座、以 LLM Agent 为推理与调度层、以静态分析/测试/动态验证为安全门禁的仓库级代码审计、漏洞挖掘与自动修复系统。

秋招版本优先交付一个“窄而可信”的闭环：仓库获取与索引 → 漏洞候选生成 → 跨文件证据追踪 → 误报验证 → 补丁生成 → 隔离验证 → 可复现实验报告。不会在第一版承诺支持所有语言、所有 CWE 或完全自主的零日利用。

### 1.1 工程 70% / 科研 30% 的取舍

- **工程 70%**：一键部署、仓库接入、任务可恢复、SAST/测试工具集成、证据可追溯、补丁可验证、GitHub 工作流和可观测性。
- **科研 30%**：只保留能回答工程决策的强基线与关键消融，例如“静态切片是否降低误报”“外部验证是否提高补丁通过率”。
- 不把解决前沿开放难题作为秋招版本门槛，包括全仓库未知漏洞召回率、统一跨语言 F1、零日发现率和纯 LLM Judge 的补丁正确率。
- 优先报告可复现、可操作的指标：任务完成率、有效 Finding 精确率、证据覆盖率、验证通过的补丁率、误修复拦截率、耗时和成本。
- 任何研究模块必须能以开关关闭，并有确定性工程基线；若未带来稳定收益，则不进入默认生产链路。

## 2. 当前项目基线

### 2.1 已有资产

- PR unified diff 解析和新增行定位。
- Security、Reliability、本地规则、LLM 和动态 Skill 协作。
- Planner、Critic、Evidence、Verifier、Arbiter 协作协议。
- Agent Loop、Tool Registry、预算、Checkpoint、取消和续跑。
- SQLite/PostgreSQL、内存队列/Redis、Webhook、RBAC、审计和管理台。
- Prompt/Skill 反馈演进、Validation/Holdout 门禁、灰度和回滚。
- 少量确定性安全修复和 GitHub 修复 PR。

### 2.2 关键缺口

- 输入主要是 Diff 新增行，没有完整仓库、调用图、控制流和数据流事实。
- 内置规则数量少，漏洞类型覆盖有限。
- Planner 把全部文件交给所有 Specialist，并未真正进行语义路由。
- Critic/Verifier 多数依赖字符串启发式，不能验证跨过程安全结论。
- “进化”只改变 Prompt 或字面规则，尚未形成漏洞知识/安全规范库。
- 修复主要处理三个简单规则，缺少漏洞语义、故障定位和安全 Oracle。
- 现有 100 条评测数据是 synthetic-controlled，不能支撑真实效果声明。
- SQLite 连接释放、Compose 默认凭据、Skill 隔离和 GitHub App 流程存在工程问题。

## 3. 实证论文证据与设计决策

以下优先采用正式会议论文或作者原始论文页面。不同论文的任务输入、数据集和成功定义不同，数字不可直接横向排名。

| 工作 | 核心实证结果 | 对 LIMA 的直接启示 |
|---|---|---|
| [PrimeVul / Vulnerability Detection with Code Language Models: How Far Are We? (2024)](https://arxiv.org/abs/2403.18624) | 7B 模型在 BigVul 上 F1 68.26%，在严格去重和时间切分的 PrimeVul 上只有 3.09%；大型闭源模型在严格设置下也接近随机 | 必须做项目级去重、时间切分、脆弱/修复成对评测；不能只报告随机函数级 F1 |
| [Uncovering the Limits of ML for Automatic Vulnerability Detection, USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/risse) | 高分模型常不能区分漏洞版本和已修复版本，存在非因果特征过拟合和 OOD 泛化问题 | 增加 patched-pair accuracy、语义保持扰动和跨项目泛化实验 |
| [LLM4Vuln (2024)](https://arxiv.org/abs/2401.16185) | 在 294 个三语言样本、3,528 个场景中解耦知识、上下文和 Prompt；还在试点中发现并获得奖励的真实漏洞 | 将漏洞知识、代码上下文和推理策略做成可插拔模块，分别消融，而不是混成一个 Prompt |
| [Large Language Models for Code Analysis, USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/fang) | 系统评估显示 LLM 可辅助代码分析，但在混淆、低可读性和复杂程序语义上存在限制 | 不依赖 LLM 自己重建 AST/CFG；优先把确定性结构事实交给模型 |
| [IRIS, ICLR 2025](https://arxiv.org/abs/2405.17238) | 在真实 Java 项目上，LLM 推断 taint source/sink，CodeQL 执行全仓分析；GPT-4 版本检测 55 个漏洞，CodeQL 为 27 个，并发现此前未知漏洞 | 采用“LLM 生成/补全安全规范 + CodeQL/分析器执行”的神经符号路线 |
| [LLMxCPG, USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/lekssays) | CPG 切片减少 67.84%–90.93% 输入规模，并带来 15%–40% F1 提升 | 建立 AST/CFG/DFG/CPG 切片层，只给 LLM 最相关的语义子图和源码 |
| [RepoAudit, ICML 2025](https://arxiv.org/abs/2501.18160) | 在 15 个真实系统发现 38 个真 Bug；移除 abstraction 后 TP 降 47.5%、FP 增 181.82%，移除 validator 后 FP 增 245.45%，移除缓存成本增 3–4 倍 | 程序抽象、事实验证器和结构化缓存都是核心模块，不是可选装饰 |
| [JitVul (2025)](https://arxiv.org/abs/2503.03586) | 879 个 CVE 的仓库级 JIT 基准中，带跨过程上下文的 ReAct Agent 优于直接 LLM，但两者仍会混淆安全检查和漏洞 | Agent 工具探索有价值，但必须加入终止策略、证据约束和成对判断 |
| [SWE-bench, ICLR 2024](https://openreview.net/forum?id=VTF8yNQM66) | 2,294 个真实 GitHub 问题需要跨函数/跨文件修改；早期最佳模型只解决 1.96% | 仓库级任务必须提供真实工作区、搜索、编辑和测试环境 |
| [SWE-agent, NeurIPS 2024](https://openreview.net/forum?id=7b9425730150fb166d4e6c77995f67ea38638fca) | 面向 Agent 设计的仓库导航、编辑与反馈接口显著提升修复效果 | Tool/Observation 的接口质量需要独立设计和评测 |
| [Agentless (2024)](https://arxiv.org/abs/2407.01489) | 简单的定位→修复→验证流水线在 SWE-bench Lite 达到 32%，平均约 0.70 美元，优于当时多种复杂 Agent | 必须把简单确定性流水线作为强基线；仅在不确定步骤使用 Agent |
| [VRpilot, AIware 2024](https://arxiv.org/abs/2405.15690) | 推理加编译器、测试、Sanitizer 等外部验证反馈，比基线多生成约 14% 的 C 正确补丁和 7.6% 的 Java 正确补丁 | 修复循环必须由外部验证反馈驱动，不能让模型无依据自我反思 |
| [APPATCH, USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/nong) | 在 97 个零日样本和 20 个已有漏洞上，漏洞语义推理与自适应 Prompt 优于多种基线 | 修复前先生成结构化 root cause、触发条件、安全不变量和修复策略 |
| [PatchAgent, USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/yu-zheng) | 结合 LSP、故障定位和补丁验证，在给定触发输入的 178 个真实漏洞上修复超过 90% | 引入 LSP/符号导航；明确“给定触发证据”和“未知漏洞”是不同任务设置 |
| [VulnLLMEval (2024)](https://arxiv.org/abs/2409.10756) | 对 307 个 Linux 内核真实漏洞的检测与修复评测显示，LLM 难以区分脆弱/修复代码，补丁常过度简化 | 修复评测不能只用文本相似度；要运行安全 Oracle 和回归测试 |
| [CI-Repair-Bench (2026)](https://arxiv.org/abs/2604.27148) | 567 个真实 CI 失败中，最佳 LLM 修复成功率为 18.9%，环境和依赖问题尤其困难 | 最终门禁应尽量重放原 CI，而不是只运行一个单元测试命令 |
| [PentestGPT, USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/deng) | 模块化上下文管理使任务完成率相对 GPT-3.5 基线提高 228.6%，但长程上下文仍是主要困难 | 漏洞验证采用阶段化状态和结构化事实摘要，不保存无限增长的聊天历史 |

### 3.1 归纳出的设计原则

1. **Program analysis first**：程序结构和数据流由解析器、LSP、CodeQL/Joern/Semgrep 等工具提供。
2. **LLM on uncertainty**：LLM 用于生成安全规范、选择分析目标、解释跨文件语义和提出补丁策略。
3. **Evidence before finding**：没有可复查 source→propagation→sink/path/trigger 证据，就不发布高置信 Finding。
4. **External feedback over self-reflection**：编译器、测试、SAST、Sanitizer、PoC 和差分行为是修复反馈源。
5. **Adaptive pipeline over agent theater**：能用确定性阶段解决的，不强行增加 Agent；每个 Agent 必须通过消融证明价值。
6. **Pairs and chronology**：脆弱/修复成对、跨项目、时间切分、去重是最低评测要求。
7. **Abstention is a feature**：证据不足时输出 `needs-human-review`，而不是强制猜测。

## 4. 项目目标与边界

### 4.1 秋招 MVP 目标

构建一个能在授权仓库中完成以下闭环的系统：

1. 拉取指定 commit/PR 的完整只读工作区。
2. 建立文件、符号、调用关系和静态分析结果索引。
3. 使用规则/SAST 生成候选，使用 LLM 进行证据导向的跨文件审计。
4. 输出结构化漏洞路径、CWE、置信度、证据和可复现验证步骤。
5. 生成多个最小补丁候选。
6. 在无网络、资源受限的临时容器中执行编译、测试和安全 Oracle。
7. 只把通过门禁的补丁提交为 Draft PR；其余输出人工复核建议。
8. 在公开、去重、时间切分的数据集上运行基线和消融实验。

### 4.2 首版明确不做

- 不在未授权目标上执行攻击或扫描。
- 不默认生成可直接武器化的利用代码。
- 不声称支持所有语言、所有 CWE 或发现通用零日漏洞。
- 不把 LLM 判断或 LLM-as-a-judge 单独作为漏洞/补丁正确性真值。
- 不把“编译通过”或“与人工补丁相似”视作安全修复成功。

### 4.3 语言与漏洞范围

为了在秋招周期内形成可信成果，采用两层范围：

- **工程 MVP：Python**。复用现有代码基础，接入 AST、LSP、Bandit/Semgrep、pytest，重点支持命令注入、路径遍历、SQL 注入、危险反序列化、认证/授权误用和敏感信息泄漏。
- **研究复现实验：Java**。使用 CodeQL 与 CWE-Bench-Java 复现神经符号检测路线，重点支持 CWE-22、CWE-78、CWE-79、CWE-94。

C/C++ 内存安全和 Fuzzing 放入长期路线，避免第一阶段同时处理编译环境、指针分析和 Sanitizer 基准带来的范围失控。

## 5. 研究问题

### RQ1：程序分析引导的上下文是否优于 Diff-only 和 Full-context LLM？

- 对照：当前 LIMA Diff-only、直接截断全仓库、语义检索、静态切片/CPG 切片。
- 指标：Precision、Recall、F1、patched-pair accuracy、false alerts/KLoC、token、延迟。
- 假设：静态切片在保持或提高高危召回率的同时，降低误报和 Token 成本。

### RQ2：证据验证器能否显著降低 LLM 审计误报？

- 对照：无验证、LLM 自我反思、独立 LLM Critic、确定性数据流/路径/新增行验证器。
- 指标：Precision、evidence validity、误报类型、人工复核时间。
- 假设：确定性验证优于纯自我反思；验证器对高危 Finding 的收益最大。

### RQ3：安全规范检索能否提升罕见 CWE 和跨项目泛化？

- 对照：无知识、原始 CVE 报告 RAG、结构化 security specification RAG。
- 切分：按项目和时间严格隔离。
- 指标：Unseen-project F1、Rare-CWE recall、错误根因分类。

### RQ4：外部验证反馈能否提高安全补丁正确率？

- 对照：One-shot、reasoning-only、compile/test feedback、完整 security-oracle feedback。
- 指标：生成率、编译率、测试通过率、漏洞消除率、回归率、正确补丁率、最小修改度。

### RQ5：复杂多 Agent 是否值得其成本？

- 对照：确定性三阶段流水线、单 ReAct Agent、当前多 Agent、按风险自适应 Agent。
- 指标：端到端成功率、Token、美元成本、延迟、重试、故障恢复率。
- 目标：证明“何时需要 Agent”，而不是预设多 Agent 一定更优。

## 6. 目标架构

```text
Authorized GitHub Repo / PR / Commit
                 │
                 ▼
       Scope & Policy Controller
     授权、预算、语言、CWE、网络策略
                 │
                 ▼
       Isolated Repository Workspace
       只读基线 + 可丢弃补丁工作树
                 │
        ┌────────┴────────┐
        ▼                 ▼
 Repository Indexer   Baseline Runner
 AST/LSP/符号/调用图    构建/测试/SAST/覆盖率
        │                 │
        └────────┬────────┘
                 ▼
       Candidate Generation Layer
  规则 + Semgrep/Bandit/CodeQL + PR 风险变化
                 │
                 ▼
      Analysis Router / Audit Planner
   按 CWE、source/sink、调用边和风险选择任务
                 │
        ┌────────┼─────────┐
        ▼        ▼         ▼
 Taint Hunter  AuthZ Hunter  Logic/Config Hunter
        └────────┬─────────┘
                 ▼
          Evidence Graph Builder
 source → propagation → guard → sink → trigger
                 │
                 ▼
      Deterministic Evidence Validator
 位置/符号/路径/可达性/静态告警/动态证据
                 │
        ┌────────┴────────┐
        ▼                 ▼
  Verified Finding   Needs Human Review
        │
        ▼
      Repair Strategy & Candidate Generator
        │
        ▼
       Patch Validation Tournament
 compile → tests → SAST → security test/PoC
 → differential behavior → patch minimality
        │
        ▼
  Draft PR + Audit Report + Reproducible Trace
```

### 6.1 核心数据结构

新增 `SecurityFinding`：

- `finding_id`、`cwe_id`、`rule_id`、`severity`、`confidence`。
- `repository`、`commit_sha`、`path`、`start_line`、`end_line`。
- `source`、`sink`、`propagation_steps`、`guards`、`call_chain`。
- `preconditions`、`attack_surface`、`security_property`、`impact`。
- `evidence_ids`、`validator_results`、`abstention_reason`。
- `repair_strategy`、`candidate_patch_ids`、`verification_status`。

新增 `Evidence`：

- 来源工具、事实类型、稳定定位、原始 Observation 哈希。
- 是否由确定性工具确认、是否由第二来源交叉确认。
- 对应 commit 和分析器版本，保证可复现。

新增 `PatchCandidate`：

- 完整 unified diff、父 commit、修改文件、修复策略。
- 编译/测试/SAST/动态验证结果。
- 漏洞是否消除、是否引入新告警、差分行为和最小性评分。

### 6.2 工具层

首版工具接口：

- `repo.list_files`、`repo.read_range`、`repo.search_text`。
- `symbol.definition`、`symbol.references`、`symbol.callers`、`symbol.callees`。
- `analysis.ast`、`analysis.cfg_slice`、`analysis.taint_paths`。
- `scanner.semgrep`、`scanner.bandit`、`scanner.codeql`。
- `build.run`、`test.run_targeted`、`test.run_full`。
- `patch.apply`、`patch.diff`、`patch.revert`。
- `security.run_oracle`，仅允许注册的安全测试模板。
- `knowledge.retrieve_specification`。

所有工具使用结构化 Schema，Observation 包含退出码、超时、截断信息、版本和内容哈希。LLM 不直接获得任意 Shell。

### 6.3 Agent 策略

- Orchestrator 仍是确定性状态机。
- Specialist 不是固定全量并行，而是由风险路由器按需要启动。
- 同一 Finding 的生成者不能成为唯一验证者。
- Critic 只能提出缺失证据，不能凭语言风格否决确定性事实。
- Repair Agent 每轮只能提交一个最小补丁，并由外部工具决定是否继续。
- 达到预算、证据不足或验证冲突时必须 abstain。

## 7. 评测设计

### 7.1 数据集

第一阶段：

- 项目现有 synthetic-controlled 100 条，只用于回归，不用于对外效果声明。
- PrimeVul 子集：函数级、去重、时间切分、脆弱/修复成对。
- CWE-Bench-Java 子集：仓库级真实 CVE、可构建项目和 CodeQL 基线。
- VulnLLMEval 子集：Linux 内核脆弱/修复代码对，验证模型是否过度简化修复。
- Vul4J 或同类可执行 Java 漏洞修复集：用于补丁安全正确性。

第二阶段：

- 从公开 CVE 修复 commit 构造 `EvoVulBench`。
- 保留 vulnerable commit、fixed commit、CWE、修复文件、可执行测试/PoC、构建容器。
- 按仓库和时间切分；同一漏洞家族不得跨 split。
- 自动去重后，对 Holdout 进行人工双人复核并记录分歧。

### 7.2 检测指标

- Finding-level Precision、Recall、F1。
- High/Critical Recall。
- False Alerts per KLoC 和每仓库误报数。
- Vulnerable/Patched Pair Accuracy。
- Localization Top-1/Top-5、行范围 IoU。
- CWE 分类准确率。
- Evidence Validity Rate。
- Abstention coverage、selective risk、Brier/ECE 校准。
- Token、模型调用次数、延迟和单仓库成本。

### 7.3 修复指标

- Patch generation rate。
- Apply/compile rate。
- Existing tests pass rate。
- Security oracle pass rate：原漏洞测试失败转为通过。
- Regression-free rate。
- Correct patch rate：安全属性恢复且无功能回归。
- End-to-end secure repair rate：检测正确 × 定位正确 × 修复正确。
- Patch minimality：修改文件/行数、无关修改比例。
- 新增 SAST 告警数量。

CodeBLEU、ROUGE 或与人工补丁的文本相似度只能作为辅助指标，不能作为安全正确性的主指标。

### 7.4 基线与消融

必须包含：

1. 当前 LIMA 规则审查。
2. SAST-only。
3. Diff-only zero-shot LLM。
4. Full-context/truncated LLM。
5. Retrieval-only LLM。
6. Static-slice + LLM。
7. 简单定位→分析→验证流水线。
8. 完整自适应 Agent。

消融项：

- 去掉程序切片。
- 去掉证据验证器。
- 去掉安全规范检索。
- 去掉跨文件工具。
- 去掉缓存/记忆。
- 独立 Specialist 改为单 Agent。
- 外部补丁反馈改为纯自我反思。

实验至少固定模型版本、Prompt 版本、分析器版本和数据指纹。对非确定模型执行多次重复，报告均值、置信区间和失败率；成对检测可采用 McNemar 检验，连续指标采用 Bootstrap 置信区间。

## 8. 分阶段实施计划

当前日期已进入秋招周期，因此并行维护“六周秋招主线”和“长期研究线”。

### Phase 0：可信工程基线（第 1 周）

任务：

- 修复 SQLite 连接关闭和 Windows 测试失败。
- 修复自动修复的脆弱字符串断言。
- 增加 Python 3.11/3.12、Windows/Linux CI。
- 增加 `pyproject.toml`、格式化、静态检查、类型检查和依赖锁定。
- 移除 Compose 默认认证密钥/密码，缺少生产密钥时拒绝启动。
- 明确 Skill 本地进程不是强沙箱；生产模式强制容器。
- 修复 GitHub App callback 的 state、租户和认证流程。

验收：

- 现有 53 个测试在 Windows/Linux 全部通过。
- CI 可复现本地测试。
- 默认生产配置不存在已知共享凭据。
- 形成 `baseline-v1` 测试和性能报告。

### Phase 1：仓库工作区与证据模型（第 2 周）

任务：

- 新增 `RepositoryWorkspace`：commit 固定、只读基线、临时补丁工作树。
- 新增仓库文件读取、搜索、符号导航、定向测试工具。
- 引入 Tree-sitter/标准 AST 和可选 LSP。
- 将现有 Finding 升级为 SecurityFinding/Evidence，同时保持 API 兼容。
- 让 Planner 根据语言、路径、静态告警和 source/sink 进行真实任务路由。

验收：

- Agent 可从一个 PR 行追踪到至少一个未修改的调用者/被调用者。
- 每个高危 Finding 至少关联一个稳定代码位置和一个工具 Observation。
- 工具均有超时、资源预算、Schema 和审计记录。

### Phase 2：混合漏洞检测（第 3–4 周）

任务：

- Python 接入 Bandit/Semgrep；Java 接入 CodeQL。
- 将 SAST 告警转为候选，不直接等同最终漏洞。
- 实现 source/sink/propagation/guard 证据图。
- 实现安全规范知识库：CWE 描述、已确认 CVE root cause、项目级规则。
- 使用静态切片或 CPG/CodeQL path 缩小 LLM 上下文。
- 实现确定性 Evidence Validator 和 abstention。

验收：

- 在选定公开数据子集上跑通 SAST-only、Diff-LLM、Slice-LLM 和完整系统。
- 输出 Detection Evaluation Report，包含 patched-pair 和跨项目结果。
- 相比 Diff-only 基线，目标是 F1 提升至少 10 个百分点，或在高危召回不退化时误报下降至少 30%；这是研究目标，不预先当作已达成事实。

### Phase 3：可验证自动安全修复（第 5 周）

任务：

- 把修复拆成 root-cause → invariant → strategy → candidate patch。
- 每个 Finding 生成 1–3 个最小候选，禁止无界重写。
- 在隔离容器中执行 apply、compile、targeted tests、full tests、SAST diff。
- 为首批 CWE 建立安全 Oracle 模板。
- 通过所有门禁后才允许创建 Draft PR。

验收：

- 所有发布补丁都有完整验证矩阵。
- 原漏洞告警/测试消失，原有测试保持通过，不新增同级或更高 SAST 告警。
- 对无法验证的补丁明确标注 `unverified`，永不自动发布。

### Phase 4：实验、消融与秋招包装（第 6 周）

任务：

- 运行 RQ1–RQ5 中时间允许的核心实验。
- 固化 Docker 环境、数据 manifest、模型/Prompt/工具版本。
- 输出 JSON、CSV 和 Markdown 报告以及错误案例分类。
- 制作 3–5 分钟演示：真实仓库审计 → 跨文件证据 → 自动补丁 → 门禁失败/成功对比。
- 重写 README：问题、方法、实证结果、威胁有效性、复现命令。
- 准备项目介绍、架构图、简历 bullet 和面试问答。

验收：

- 一条命令复现实验子集。
- README 中所有数字都能追溯到报告和数据指纹。
- 至少展示一个成功案例和一个系统正确 abstain/阻止错误补丁的失败案例。

### 长期研究线

- C/C++：Joern/LLVM/CodeQL、ASan/UBSan、覆盖率引导 Fuzzing。
- 自动生成安全测试和最小化触发输入。
- 基于历史补丁提取可执行 security specifications。
- 主动学习：人工复核最有信息量且低置信的样本。
- 小模型用于路由/分类，强模型只处理复杂路径，研究成本—效果前沿。
- 多语言统一 Evidence Graph。
- 负责任地向开源项目提交确认漏洞，遵循披露流程。

## 9. 第一批工程 Backlog

按执行顺序：

### P0-1 SQLite 生命周期

- 用真正关闭连接的 context manager 统一 SQLite 访问。
- 启用 `PRAGMA foreign_keys=ON`、合理 busy timeout。
- 添加连接泄漏和 Windows 文件删除回归测试。

### P0-2 测试与 CI

- 修复 AST 自动修复断言，按 AST/语义比较而不是引号格式。
- 增加 GitHub Actions Windows + Ubuntu matrix。
- 给测试结果增加 JUnit/coverage 输出。

### P0-3 安全默认值

- Compose 的 secret/password 改为 required variable。
- 生产启动时检查认证、公开监听、Skill 容器和 Webhook secret。
- 增加安全配置测试。

### P1-1 RepositoryWorkspace

- 定义 workspace 生命周期、commit pinning、只读基线和临时工作树。
- 加入允许仓库、最大仓库大小、文件数量和语言策略。

### P1-2 Tool Registry v2

- 为 repo、symbol、scanner、build、test、patch 定义结构化工具。
- 所有 Observation 记录版本、耗时、退出码和哈希。

### P1-3 Evidence Graph

- 实现稳定符号 ID 和 source/sink/path 数据结构。
- 兼容现有 Finding API 和 Markdown 报告。

### P2-1 Python Hybrid Detector

- 集成 AST + Bandit/Semgrep。
- 首批 6 个 CWE 的候选归一化和验证器。
- 建立 Python 演示仓库与安全测试。

### P2-2 Java Research Track

- 接入 CodeQL SARIF/path 输出。
- 导入可运行的 CWE-Bench-Java 小规模 manifest。
- 完成 CodeQL-only 与 CodeQL+LLM 基线。

## 10. 安全、伦理与负责任披露

- 系统只允许用户明确授权的仓库和隔离测试环境。
- 动态验证默认无外网、非特权、只读根文件系统、限制 CPU/内存/PID/时间。
- 禁止使用宿主凭据；测试密钥使用一次性伪值。
- 高风险命令、公开漏洞披露和外部 PR 必须人工批准。
- 原始漏洞 PoC、敏感路径和未披露漏洞默认不进入公开日志或 LLM Provider。
- 对外报告区分 `suspected`、`statically-confirmed`、`dynamically-confirmed`、`patched-and-verified`。
- 如果发现真实未知漏洞，先保存最小证据，停止自动公开，通过项目安全策略或 CERT/平台流程披露。

## 11. 秋招交付物

1. 可运行项目：本地模式和 Docker 模式。
2. 公开演示：选择有授权的测试仓库，不展示未披露漏洞。
3. 可复现实验：数据 manifest、固定版本和一键运行脚本。
4. Paper-style 技术报告：Abstract、RQ、Method、Experiment、Ablation、Threats to Validity。
5. Benchmark 报告：检测、修复、成本和错误分类。
6. 架构图和 3–5 分钟演示视频。
7. 简历素材，不提前填写未经实验验证的数字。

建议简历描述模板：

> 设计并实现仓库级神经符号安全审计 Agent，将 SAST/调用与数据流分析、LLM 证据推理和隔离补丁验证整合为可追踪流水线；在去重、时间切分的真实 CVE 基准上对比 Diff-only、SAST-only 与 Agent 基线，并通过消融实验量化程序切片、证据验证和外部修复反馈的贡献。

实验完成后再把实际 F1、误报下降、正确补丁率、成本和延迟填入简历。

## 12. 成功标准

秋招版本成功不是“功能最多”，而是同时满足：

- **有明确研究问题**：程序分析、LLM 和验证分别解决什么问题。
- **有可信证据**：真实 CVE、成对样本、跨项目/时间切分、可执行 Oracle。
- **有工程闭环**：仓库→检测→证据→修复→验证→Draft PR。
- **有诚实边界**：能解释误报、漏报、abstention 和威胁有效性。
- **有可复现结果**：任何简历数字都能从固定脚本重新生成。
- **有个人贡献辨识度**：不是简单调用模型 API，而是 Evidence Graph、神经符号检测、验证门禁和严谨实验体系。

当前已完成 Phase 0、仓库工作区、混合扫描、静态 import 跨文件 Evidence Graph 首版、CWE-78/CWE-89/CWE-22 可验证修复闭环、快照固定预览和首个修复约束评测集。下一主线是引入授权真实漏洞/修复对，补齐真实项目测试重放和秋招演示链路；synthetic-controlled 的 100% 约束指标不得替代真实项目效果。
