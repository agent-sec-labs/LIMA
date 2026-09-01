# LIMA 项目定位与 Coding Agent 开发交接标准

> 文档类型：稳定工程规范（Stable Policy）
>
> 本文回答“LIMA 是什么、如何把工作变成 Coding Agent 可执行任务、如何开发、验证和交接”。当前分支、NOW/NEXT、未提交文件和最近测试结果不写在本文，统一记录在本机 `PROGRESS.md`。具体实现细节只写在活动 Implementation Packet。

## 1. 项目定位

LIMA 的目标不是成为“会阅读代码并给修改建议的 LLM Agent”，也不是把多个静态扫描器的告警直接汇总给人工。

LIMA 的长期定位是：

> **以可复现证据驱动的 Repository Security Analysis、Vulnerability Mining 与 Verified Repair Agent Platform。**

平台由三条职责不同、信任边界独立的链路组成：

```text
Audit
发现值得调查的位置，形成安全语义、证据和可验证假设
        ↓ Audit Evidence Package
Mining
在隔离环境中通过真实执行证明漏洞是否存在、如何触发
        ↓ Vulnerability Evidence Package
Repair
在全新隔离环境中生成多个候选，并证明安全恢复与功能保持
        ↓ Repair Verification Report / Verified Patch
```

三个阶段只通过版本化 Artifact 交换事实，不依赖隐式 Agent memory。LLM 可以参与语义剪枝、证据解释、规划、Harness/PoC 设计和候选修复，但不能单独决定漏洞成立、安全放行或补丁验证通过。

LIMA 自己重点实现：

- Repository 语义剪枝和高价值目标选择；
- 工具检索、规划、调度和运行编排；
- Evidence 归一化、Fusion 和 Adjudication；
- Audit/Mining/Repair 三阶段 Artifact 契约；
- Sandbox、依赖、资源、网络和失败治理；
- 动态验证、Oracle 和 Verified Repair Gate；
- 可重放、可观测、可恢复的 Workflow。

LIMA 不重复实现 Semgrep、CodeQL、Pysa、Joern、Bandit、Trivy、Atheris、LibCST 等成熟能力；这些能力通过 Adapter/Plugin/Port 被编排和取证。

## 2. 当前能力与目标能力必须分开陈述

### 2.1 当前代码基线

当前发布版本为 `lima.__version__ == "1.6.0"`，主要具备：

- Python 仓库有界读取、AST、跨文件数据流、Bandit 和本地规则扫描；
- GitHub/local-import RepositorySource、不可变快照物化与缓存；
- 证据融合、可选 LLM 语义复核和 legacy 审计报告；
- 只读 Repair Preview 与受限 CWE-22/78/89 修复验证能力；
- SQLite/PostgreSQL、内存队列/Redis Streams、React 管理台和 CI 门禁。

当前“发起仓库审计”主要完成 legacy Audit/Report 流程。它还不是目标态的通用 Audit → Mining → Verified Repair 全链路。不得把规划中的 Workflow、三 Sandbox、AEP/VEP/RVR、Tool Registry 或通用 Mining Core 描述成已经存在的生产能力。

### 2.2 目标 Golden Path

当前只围绕一条 Python Golden Path 演进：

```text
用户提交 Python Repository
        ↓
不可变 Repository Snapshot
        ↓
Repository Profile / RAM
        ↓
Evidence-backed Audit Hypothesis
        ↓
Mining Sandbox 动态验证
        ↓
Vulnerability Evidence Package
        ↓
独立 Repair Sandbox 多候选修复
        ↓
Security + Functional Verification Gates
        ↓
Verified Patch
        ↓
前端展示 Timeline、Artifact、结论和缺口
```

Golden Path 稳定前，Java、多语言全面覆盖、更多 CWE、RAG、Tool Evolution、复杂 HA 和高级 UI 均属于 LATER，不能挤占当前关键路径。

## 3. 核心开发原则

所有维护者和 Coding Agent 必须遵守：

> **Plan broadly, freeze narrowly, implement vertically, test continuously, promote only evidence-backed problems.**

具体含义：

1. 规划可以宽，但一次只冻结一个小切片；
2. Issue 表达需求，不自动等于可开发任务；
3. Coding Agent 只消费 Implementation Packet；
4. 一个切片解决一个核心不确定性，预计 0.5～3 天；
5. 优先交付薄而真实的 Vertical Slice，不长期堆积横向半成品；
6. 测试先形成 Finding，再分类和 Triage，不能直接膨胀成大量 Issue；
7. 结论、修复和“已完成”都必须有可复核 Evidence；
8. 安全失败默认 fail closed，不把 blocked/inconclusive/failed 伪装成 safe；
9. 保留现有可用功能，通过兼容 Adapter 渐进迁移，不进行大爆炸重写。

## 4. 三种文档的职责边界

| Artifact | 回答的问题 | 是否可直接指导编码 | 更新者 |
|---|---|---:|---|
| GitHub Epic/Issue/Roadmap | 为什么做、最终范围、依赖和需求库存是什么 | 否 | Maintainer |
| 本文 | 项目定位、稳定流程、安全边界和交接标准是什么 | 否 | Maintainer |
| `PROGRESS.md` | 当前代码/工作树/队列/验证的真实状态是什么 | 否 | Session Coordinator |
| Implementation Packet | 这一个切片改哪些文件、Symbols、Contract、Tests、Commands | 是 | Maintainer/Designer |
| Completion Summary | Agent 实际做了什么、验证了什么、还缺什么 | 作为复核证据 | Coding Agent |

禁止把 `PROGRESS.md` 写成长期 Roadmap，也禁止把长期架构讨论塞进 Implementation Packet。

## 5. 真值与冲突处理

不同问题使用不同事实源：

| 问题 | 第一事实源 | 次级参考 |
|---|---|---|
| 当前代码真实行为 | 最新 `main` 的代码和可重复测试 | README/历史文档 |
| 当前工作树、Owner、NOW/NEXT、最近测试 | `PROGRESS.md` | GitHub 状态 |
| 活动切片的目标行为 | 活动 Implementation Packet + 已批准 Decision Record | Source Issue |
| 长期平台方向 | 本文“项目定位” + 最新批准的架构规划 | Epic/研究材料 |
| 安全与权限边界 | 当前代码安全测试 + 本文冻结不变量 + Packet | 普通需求描述 |

冲突规则：

- 代码与文档冲突时，代码说明“当前是什么”，但不能自动推翻 Packet 的“本次要变成什么”；
- Packet 与 Source Issue 冲突时，本切片以 Packet 为准，并把冲突报告给 Maintainer；Coding Agent 不改 Issue；
- Packet 要求削弱本文安全不变量时必须停止，不能执行；
- `PROGRESS.md` 只记录事实，不能创造架构规则；
- 任何关键冲突都通过 Decision Request 处理，不由 Agent 猜测。

## 6. Backlog 与执行状态

工作统一分为：

- `Discovery`：有观察、想法或风险，尚未决定是否做；
- `Design`：问题成立，但 Contract/状态机/安全边界尚未冻结；
- `Design Frozen`：目标规则已确定，但还没有代码级 Packet；
- `Ready-for-Code`：存在完整且通过审查的 Implementation Packet；
- `Blocked/Later/Gated`：最终可能重要，但当前不可执行；
- `In Progress/Review/Verification/Done`：仅用于已经进入实现的 Packet。

GitHub `status:ready` 只代表 Issue 层依赖或 Refinement 状态，不再作为 Coding Agent 开工凭据。一个任务只有同时满足以下条件才是 `Ready-for-Code`：

- 当前 Golden Path 确实被该问题阻塞；
- Goal/Non-goal 无歧义；
- Contract、状态和错误语义冻结；
- Files to Add/Modify/Forbidden 明确；
- Public Symbols 和依赖方向明确；
- Required Tests 精确到文件和 Symbol；
- Done Commands 可执行；
- 上游 fixture 可消费；
- 无关键 TBD；
- 有唯一活动 Implementation Packet。

## 7. Findings → Implementation Packet 生命周期

真实运行后的标准闭环：

```text
Build → Run → Observe → Findings Ledger → Classify → Triage
      → Select One Blocker → Design → Implementation Slice
      → Implementation Packet → Coding Agent → Verify
      → Integration/Real Run → Evidence → Triage
```

Finding 必须先分类：

| 分类 | 处理 |
|---|---|
| Implementation Bug | 在冻结 Contract 下形成最小 Bugfix Packet |
| Contract Gap | 先修订 Contract，再制作 Packet |
| Architecture Gap | RFC/Design，不直接编码 |
| Missing Capability | Backlog，只有阻塞 Golden Path 才提升 |
| Quality Gap | 定义 Benchmark 和量化目标后再提升 |
| Test/Environment Problem | 修测试或环境，不修改产品语义掩盖问题 |

30 个 Observation 不等于 30 个开发任务。NOW 只选择当前阻塞 Golden Path 的一个问题。

## 8. WIP、Owner 与并行边界

全局队列固定为：

```text
NOW  ≤ 1
NEXT ≤ 2
LATER = 其余
```

多人协作规则：

- 一个 Coding Agent = 一个 Implementation Packet = 一个逻辑 PR；
- 一个高冲突文件区域同一时间只有一个 Owner；
- 未列入 Packet allowlist 的文件全部只读；
- Review Agent 与 Implementation Agent 角色分离；Reviewer 提意见，不在同一轮越权改实现；
- 并行仅允许在文件集合不相交且公共 Contract 已冻结时发生；
- Agent 不认领完整 Epic，也不同时处理 NOW 和 NEXT。

## 9. Coding Agent 启动协议

Coding Agent 开始编码前必须执行以下步骤。

### 9.1 读取顺序

1. 完整阅读本文；
2. 完整阅读本机 `PROGRESS.md`；
3. 完整阅读唯一活动 Implementation Packet；
4. 阅读 `CONTRIBUTING.md` 和 Packet 引用的代码/测试；
5. Source Issue 只用于背景，不从中扩展 Packet 范围。

### 9.2 工作树审计

先运行：

```powershell
git status --short --branch
git rev-parse HEAD
git log -1 --format="%H%n%ad%n%s" --date=iso-strict
```

若工作树不干净：

- 不删除、不覆盖、不 `git reset --hard`；
- 不擅自 stash 用户文件；
- 记录所有 tracked/untracked 文件并请求 Coordinator 提供干净分支或 worktree；
- Packet 中明确允许的既有改动除外，但必须证明所有权。

干净后再执行：

```powershell
git fetch origin
git switch main
git pull --ff-only origin main
git switch -c <packet-recommended-branch>
```

### 9.3 开工 Gate

必须确认：

- Packet 状态为 `READY-FOR-CODE`；
- Packet 的 base commit 已包含在当前分支；
- NOW 只有此 Packet；
- 文件 allowlist 未被其他 Agent 占用；
- baseline commands 真实通过或既有失败已记录；
- 没有未解决 Stop Condition。

任何一项不满足，状态为 BLOCKED，不开始编码。

## 10. Coding Agent 实施规则

Agent 负责实现，不负责重新定义需求：

1. 只修改 Packet allowlist；
2. 不重命名或扩大 public API；
3. 不新增未批准依赖、网络、文件系统、数据库、容器或凭据权限；
4. 先写 Packet 指定的危险输入、失败和边界测试，再实现成功路径；
5. 一个行为必须映射到一个 AC 和测试证据；
6. 不通过删除测试、放宽断言、吞异常、填默认值或修改 fixture 掩盖失败；
7. 不顺手格式化、重构或清理范围外技术债；
8. 不把 LLM 输出、置信度或“未发现”当成安全证明；
9. 不在实现 PR 中修改 GitHub Issue 规格；
10. Contract 不足时立即停止并提交 Decision Request。

## 11. Decision Request 与停止条件

以下情况必须停止：

- 最新 main 已存在冲突实现或活跃 Owner；
- 需要修改 forbidden 文件；
- 需要新增依赖或扩大权限；
- Contract 字段、状态、错误、兼容或安全规则存在多个合理答案；
- baseline 或回归失败无法归因；
- 只能削弱安全门禁才能继续；
- Packet 的测试不能验证其 AC；
- 发现当前问题其实属于 Architecture/Contract Gap。

Decision Request 必须包含：

```text
Packet/规则位置：
实际代码证据：
最小复现命令：
阻塞原因：
可选方案：
各方案的兼容、安全、工期影响：
建议：
```

维护者决策应追加到 Packet 的 Decision Record 或新版本 Packet；不要让结论只存在于聊天记录。

## 12. 验证与证据标准

每个 Packet 至少定义：

- Unit Tests；
- Contract Tests；
- 相关 Regression Tests；
- Integration Tests（适用时）；
- File Boundary Gate；
- Ruff/Bandit 或对应语言质量门禁；
- 完成命令和预期结果。

Python 代码 PR 的通用底线：

```powershell
python -m compileall -q lima scripts tests
python -m unittest discover -s tests -v
python -m ruff check <changed-python-files> <changed-test-files>
python -m bandit -q <changed-python-files>
git diff --check
git diff --name-only --diff-filter=ACMRTUXB
```

具体命令以活动 Packet 为准。涉及前端、Docker、数据库、Sandbox、依赖下载、真实仓库或评测时，Packet 必须增加相应 Gate。普通 CI 不得联网、注入模型 Key 或产生付费调用。

“测试通过”必须记录：

- 完整命令；
- 运行环境和版本；
- passed/failed/skipped 数量；
- 退出码；
- artifact/log 路径；
- skip 和告警的原因。

Bug 没有 Regression Test 不能 Done。

## 13. Completion、Review 与 Merge

Coding Agent 完成实现后必须输出 Packet 定义的 Completion Summary，至少包含：

- Base/final commit；
- 修改文件和 public symbols；
- AC → Test → Result 证据；
- 实际命令与统计；
- 文件边界检查；
- 安全/权限/依赖变化；
- 已知限制和未完成项；
- 是否满足 Stop Condition；
- 建议的下一步，但不得自行激活 NEXT。

Reviewer 依次检查：

1. 是否严格实现 Packet，而非实现其个人理解；
2. 是否越过 allowlist 或 Owner；
3. 是否出现隐式 API、依赖或权限扩张；
4. 测试是否真的覆盖拒绝路径和边界；
5. 是否过拟合单个测试仓库或 PoC；
6. Completion Summary 是否可复现；
7. `merge-gate` 是否通过。

一个 Packet 只是 Source Issue 的切片时，PR 不得 `Closes #<source-issue>`。只有 Issue 的全部 Packet、集成和 Completion Summary 完成后才允许关闭 Issue。

## 14. 无缝交接协议

### 14.1 Coding Agent 离场输出

无论 DONE、BLOCKED 还是中断，都必须提供：

```text
Packet ID / 状态：
当前分支 / HEAD：
Base commit：
Dirty tracked files：
Untracked files：
已完成行为：
未完成行为：
实际测试命令与结果：
失败/skip/告警：
生成的 artifact/log：
已批准 Decision：
未决 Decision Request：
安全、兼容、迁移、费用影响：
下一位 Agent 可以立即执行的一个最小步骤：
禁止下一位 Agent 做的事：
```

### 14.2 Session Coordinator 更新 `PROGRESS.md`

Coordinator 根据可验证结果更新：

- snapshot 时间和最新 main；
- NOW/NEXT/LATER；
- active owner、branch、HEAD；
- dirty/untracked 文件；
- baseline/最新验证；
- Decision 和 blocker；
- 最小下一步。

Coding Agent 默认不修改 `PROGRESS.md`，因为它是本机忽略的运行台账，不应混入实现 PR。

### 14.3 下一位 Agent 恢复

下一位 Agent 不能只相信文字总结。必须：

1. 核对分支、HEAD 和文件状态；
2. 查看实际 diff；
3. 复跑最近失败或最小定向测试；
4. 对照 Packet 勾选已完成 AC；
5. 从交接中“一个最小步骤”继续；
6. 若证据不一致，将状态退回 NEEDS-REWORK/BLOCKED。

## 15. 中断、冲突与恢复

- Agent 中断时保留工作树，不执行破坏性清理；
- 不用 `git checkout --`、`git reset --hard` 覆盖未知改动；
- merge/rebase 冲突必须先确认每个文件 Owner；
- Packet 公共 Contract 冲突时停止，不由后合并者临时改字段；
- 测试环境失败先分类为 Test/Environment Problem，不修改产品语义求绿；
- 外部依赖、网络或模型失败必须保留根因，不能被次生 timeout 覆盖；
- 任何产生费用、远端写操作、Issue/PR 变更或权限扩张都需要明确授权。

## 16. 项目代码地图

| 领域 | 主要入口 | 当前职责 |
|---|---|---|
| API/Service | `lima/api.py`, `lima/service.py` | HTTP、认证、任务创建、业务编排 |
| Legacy domain | `lima/models.py` | Finding、EvidenceRecord、ReviewReport；新平台 Contract 不继续堆入此文件 |
| Store/Queue | `lima/store.py`, `lima/postgres_store.py`, `lima/task_queue.py` | SQLite/PostgreSQL、内存/Redis 任务与恢复 |
| Repository intake | `lima/repository_source.py`, `repository_materializer.py`, `repository_cache.py` | 来源规范化、不可变物化、缓存 |
| Workspace/Scan | `lima/workspace.py`, `repository_scanner.py`, `python_analyzer.py`, `python_dataflow.py`, `sast.py` | 有界读取、AST/数据流/SAST |
| Semantic/Adjudication | `semantic_retrieval.py`, `repository_triage.py`, `adjudication.py` | 候选选择、可选 LLM、证据裁决 |
| Repair baseline | `security_repair.py`, `repair_workspace.py`, `repair_preview.py`, `verifier.py` | 现有约束型修复和只读预览基线 |
| Runtime/Agent | `runtime.py`, `agents.py`, `harness.py`, `task_progress.py`, `task_failure.py` | Agent loop、checkpoint、进度与失败 |
| Frontend | `frontend/src/` | React 管理台和 legacy API projection |
| Evaluation | `evaluation_data/`, `real_world_evaluation.py`, `experiments.py` | 冻结数据集、实验和回归证据 |
| New platform contracts | `lima/contracts/` | 由活动 Packet 渐进创建；当前开始前可能不存在 |

先读对应 tests，再读实现。不要因规划文档出现了目标模块名就假设代码已经存在。

## 17. 不可削弱的安全不变量

### Repository 与 Snapshot

- 目标仓库始终视为不可信输入；
- Audit 阶段不得执行目标代码、setup hook、Git hook 或安装脚本；
- 拒绝绝对路径、`..`、隐藏逃逸、symlink/junction 逃逸；
- 移动 ref 必须钉死到不可变 commit；Snapshot sealed 后不可原地修改；
- 文件数、单文件、总字节、日志和执行时间必须有界。

### Tenant、凭据与 Artifact

- 任务、Artifact、缓存、工具、日志、反馈和记忆按 tenant 隔离；
- Token、API Key、认证头、`.env` 和 raw secret 不进入普通日志/数据库/Prompt/fixture；
- Artifact digest、schema、tenant、snapshot 或 lineage 不匹配时 fail closed；
- 大 payload 使用受控 blob reference，不以内联巨型 JSON 静默降级；
- blocked/timeout/OOM/tool_error 不是安全结论。

### Mining 与 Repair

- Mining 与 Repair 使用不同的一次性 Sandbox，不复用可变状态；
- Sandbox 默认无网络、无宿主 Docker socket、无用户凭据、无主仓写权限；
- 依赖下载只通过受控 Gateway/Snapshot，包含来源、hash、预算和失败证据；
- 没有机器可执行 Oracle 的运行时漏洞不得升级为 verified；
- Repair 必须验证 Security Preservation 和 Functional Preservation；
- 候选不能修改测试、PoC、Oracle、依赖锁、安全配置或范围外文件来伪造通过；
- 任一 mandatory Gate skipped/failed 都不能产生 Verified Patch；
- GitHub 分支、commit、Draft PR 属于独立显式写权限，不能隐藏在扫描/预览中。

### Evaluation

- 不为通过测试修改冻结 holdout 的标签、顺序、commit、archive digest 或 analyzer fingerprint；
- 真实模型实验显式 opt-in、固定预算和模型身份；
- 普通 PR/CI 不进行付费调用；
- 仓库专用 allowlist 不能冒充通用能力。

## 18. 环境与协作约束

- Python 支持 3.11/3.12；前端使用 React/TypeScript/Vite；
- Docker Compose 默认服务地址 `127.0.0.1:18080`，本地主机默认 `127.0.0.1:8080`；
- `.env`、`repositories/`、`output/` 和 `PROGRESS.md` 不提交；
- `security-agent_postgres_data` / `security-agent_redis_data` 是兼容卷名，不因旧品牌删除；
- `merge-gate` 是稳定 Required Check；
- Ruff/Bandit 只对本次改动负责，业务 PR 不批量清理历史债务；
- 用户未明确授权时，不创建/关闭/修改 GitHub Issue、PR、Label 或远端分支。

## 19. 标准 Coding Agent 任务前缀

维护者交付 Packet 时使用：

```text
你正在实现一个已经冻结的 LIMA Implementation Packet。

必须：
1. 完整阅读 LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD、PROGRESS 和活动 Packet。
2. 只修改 Packet allowlist。
3. 不重新设计 public contract，不添加未批准依赖或权限。
4. 先运行 baseline，再按指定测试顺序实现。
5. Contract 不足或需要越界时立即停止并提交 Decision Request。
6. 不修改 GitHub Issues，不关闭 Source Issue。
7. 完成后输出 Packet 要求的 Completion Summary 和真实测试证据。
```

## 20. 本文维护规则

本文只在以下情况更新：

- 项目定位或 Golden Path 发生批准后的变化；
- 开发/交接状态机发生变化；
- 稳定安全不变量或通用验证规则发生变化；
- 代码目录职责发生长期变化。

不要在本文记录：当前 Agent、临时分支、单次测试结果、某个 Issue 的实时状态、历史排障流水或短期 TODO；这些内容属于 `PROGRESS.md`、Implementation Packet、Completion Summary 或 Findings Ledger。

最终纪律：

> **Planning is not Coding. Issue is not Implementation-Ready. Coding Agents receive Implementation Packets, not architecture ambiguity. Evidence decides what is complete.**
