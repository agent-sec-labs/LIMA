# C/C++ 大模型多 Agent 内存漏洞检测设计

日期：2026-09-02
状态：已确认，等待实施
目标分支：`codex/cxx-llm-agent-detection`
依赖分支：`codex/cxx-memory-detection-impl`，当前已推送提交 `2e69f3c`

## 1. 目标

在 LIMA 中增加真正由大模型阅读 C/C++ 代码并提出内存漏洞的检测链路，同时支持：

1. 管理员导入仓库的整仓扫描；
2. GitHub Pull Request 修改及相关仓库上下文扫描；
3. `required` 与 `auto` 两种大模型运行模式，并保留 `off`；
4. 与 LIMA 现有 `plan → specialist → challenge → evidence → verify → arbitrate`
   多 Agent 协议一致的执行、消息持久化、重试和审计方式；
5. 将 Semgrep、Clang Static Analyzer、AddressSanitizer 作为独立证据层，而不是冒充
   大模型检测；
6. C/C++ 结果只检测、不自动修复。

第一版只覆盖：

- CWE-787：越界写；
- CWE-125：越界读；
- CWE-416：释放后使用；
- CWE-415：重复释放。

第一版不承诺全语言、全 CWE、零误报、零日发现或自动修复。

## 2. 当前项目状态与前置条件

现有 C/C++ Sidecar 已实现 Semgrep、Clang 和 ASan 三层检测，远程分支
`codex/cxx-memory-detection-impl` 当前为 `2e69f3c`。完整宿主测试曾通过，但最终 scoped
复审仍有七项未关闭：

1. 同 UID 进程控制与 PID 1 孤儿/僵尸后代回收不完整；
2. 进程终止、输出 drain 和递归清理可能越过请求总 deadline；
3. Finding 未绑定实际产生它的具体 tool-run；
4. health/capabilities 未完整反映 CMake、Landlock 和进程隔离可用性；
5. Markdown 普通文本仍可能注入分隔线或链接，路径还可能被双重转义；
6. HTTP 慢速持续读取仍可能越过绝对下载 deadline；
7. 镜像记录了 image ID，但 apt/pip 传递依赖与包清单归档仍不足以支撑可审计工具链。

这些是大模型 Evidence Agent 将依赖的信任边界。必须先修复并独立复审通过，再开始新增
LLM Agent 功能。不得以“LLM 只做候选”为理由绕过该前置条件。

工作树当前还存在两个用户的未提交修改：根 `Dockerfile` 和 `tests/test_service.py`。后续模型
不得暂存、覆盖、删除或混入任何提交。

## 3. 核心原则

### 3.1 大模型是真实检测者

Specialist Agent 必须实际收到源码片段、调用关系和类型定义，并独立提出漏洞机制。不能把
Semgrep/Clang/ASan Finding 改写后伪装成 Agent 发现。

### 3.2 工具是证据，不是提示答案

初始 Specialist 不得看到其他 Specialist 的结论，也不得看到传统工具 Finding。Critic 阶段
才能看到候选；Evidence 阶段才关联 Semgrep、Clang、ASan。这保证 `agent-corroborated` 的
独立性，也避免工具标签诱导模型。

### 3.3 所有模型输出均不可信

模型输出必须经过严格、封闭、有限大小的 JSON Schema 校验。文件、行号、符号、代码引用、
调用路径和读取范围都必须重新绑定本地快照。未知字段、重复 JSON key、非法类型、超限数组、
越界行号、未读取文件引用或路径逃逸使该轮输出失败，不能部分接受。

### 3.4 源码也是不可信输入

源码、注释、字符串、README、构建输出、历史 Agent 消息和工具输出都只能作为数据，不能改变
系统提示词、工具权限、预算或响应 Schema。Agent 工具只读，不能执行任意命令、访问任意路径、
联网或读取密钥。

### 3.5 不保存隐藏思维链

跟随 LIMA 现有持久化策略保存 Agent 分配、结构化结论、Critic 质疑、Evidence 结果、Verifier
决策、Arbiter 结果和其中携带的代码证据。不新增独立的源码过期或脱敏策略，也不要求保存模型
隐藏思维链。模型必须输出简洁、可审计的 `mechanism`、`trigger_path` 和证据引用。

### 3.6 C/C++ 永不自动修复

`automatic_repair` 必须恒为 `false`。SafeFixer、修复预览、Web 修复按钮和 GitHub 自动修复流程
必须继续拒绝所有 C/C++ Finding，包括 `runtime-confirmed` 和 `human-confirmed`。

## 4. 总体架构

```text
整仓任务 / PR 任务
        ↓
CxxContextIndex（可信快照上的符号、类型、调用和资源操作索引）
        ↓
CxxCandidateRetriever（无标签、有界候选检索）
        ↓
CxxPlannerAgent
        ↓
独立 Specialist
├─ MemoryLifetimeAgent
├─ BoundsAgent
└─ InterproceduralAgent
        ↓
CxxCriticAgent
        ↓
CxxEvidenceAgent ← Semgrep / Clang / ASan
        ↓
CxxVerifierAgent
        ↓
CxxArbiterAgent
        ↓
ReviewReport / Agent messages / metrics
```

新增模块：

| 文件 | 单一职责 |
|---|---|
| `lima/cxx_agent_models.py` | 上下文包、候选、Agent 结论、验证决定和 coverage 类型 |
| `lima/cxx_context.py` | 对有界快照建立函数、类型、调用、引用、分配/释放与长度操作索引 |
| `lima/cxx_retrieval.py` | 为整仓和 PR 生成无标签候选并选取上下文 |
| `lima/cxx_agent_tools.py` | 向 Agent 暴露只读、有界、可审计的代码查询工具 |
| `lima/cxx_llm.py` | C/C++ 提示词、严格 JSON、Provider 调用和结果解析 |
| `lima/cxx_agents.py` | C/C++ Planner、Specialist、Critic、Evidence、Verifier、Arbiter 协议 |
| `lima/github_source.py` | 按 GitHub 固定 commit SHA 获取有界 PR 仓库上下文 |

修改入口：

- `lima/repository_scanner.py`：整仓 C/C++ Agent 扫描；
- `lima/service.py`：PR Agent 扫描、依赖装配和 capabilities；
- `lima/agents.py`：复用 CollaborationBus、重试、消息和 Runtime，不破坏现有 Python PR 流程；
- `lima/cxx_memory.py`：向 Evidence Agent 提供严格工具证据；
- `lima/models.py`：扩展 Finding 与 EvidenceRecord 的 Agent 字段；
- `lima/report.py`、`web/app.js`：展示 Agent 来源、上下文、验证等级和降级；
- `lima/config.py`、`.env.example`、`docker-compose.yml`：模式和任务总预算；
- GitHub client/webhook 模块：读取固定 PR head SHA，而不是浮动分支。

## 5. 上下文索引与检索

### 5.1 索引范围

索引只读取当前 `RepositoryWorkspace` 已接受的 C/C++ 文本文件：

- `.c`、`.cc`、`.cpp`、`.cxx`；
- `.h`、`.hh`、`.hpp`、`.hxx`。

索引记录：

- 函数/方法名称、限定名、文件、起止行；
- 类型、结构体、类及其定义位置；
- 函数调用和有限的 caller/callee 关系；
- `malloc/calloc/realloc/new` 等分配；
- `free/delete/delete[]` 等释放；
- 缓冲区、数组、指针运算、长度计算和拷贝 API；
- 返回值、参数和成员字段上的资源/长度传递线索。

第一版不要求完整 C++ AST 或精确 points-to analysis。无法稳定解析的语法必须记录 coverage
缺口，不能猜测调用边。

### 5.2 整仓候选

整仓检索从资源生命周期、边界操作和调用邻域生成候选。候选只能使用源码结构和通用风险不变量，
不得读取评测 case ID、CVE 描述、脆弱/修复标签或 ground-truth path。

### 5.3 PR 候选

PR 从新增/修改的 C/C++ 行定位所在符号，再扩展：

- 直接 caller/callee；
- 同一资源的创建、释放和使用位置；
- 相关类型定义与成员；
- 长度来源、转换和最终内存访问。

Finding 优先绑定修改行。如果根因位于未修改代码，必须同时保存 `trigger_path` 与根因位置；
Diff-only 模式不能把未读取的旧代码当成证据。

## 6. PR 源码来源

优先级：

1. 使用管理员导入的本地仓库，且其 commit 必须等于 PR `head SHA`；
2. 本地仓库不可用时，使用现有 GitHub 凭据读取固定 `head SHA`；
3. GitHub 上下文不可用时降级为 Diff-only。

GitHub 获取规则：

- 所有 URL/API 参数绑定完整 40 位 commit SHA；
- 禁止以 branch、短 SHA 或 PR 可变 ref 作为最终证据；
- 只接纳预算内的 C/C++ 文件和必要构建元数据；
- 不跟随路径逃逸、子模块、符号链接或特殊文件；
- 记录 repository、commit、文件、行范围和内容 SHA-256；
- `diff-only` 最高只能产生 `llm-candidate`。

## 7. Agent 工具

允许工具及返回值：

```python
search_symbols(query: str, limit: int = 20) -> list[SymbolHit]
read_code_snippet(path: str, start_line: int, end_line: int) -> CodeSnippet
find_callers(symbol_id: str, limit: int = 20) -> list[SymbolRef]
find_callees(symbol_id: str, limit: int = 20) -> list[SymbolRef]
find_references(symbol_id: str, limit: int = 40) -> list[SymbolRef]
get_type_definition(type_name: str) -> CodeSnippet | None
get_tool_evidence(candidate_id: str) -> list[EvidenceRecord]
```

前六个工具可供 Planner/Specialist/Critic 使用；`get_tool_evidence` 只能在 Evidence 阶段注册。
每次调用必须扣减同一任务总预算并记录到 Agent 消息。路径必须存在于固定快照，行范围必须有效，
单次和累计输出均有上限。

## 8. 多 Agent 协作协议

### 8.1 Planner

Planner 根据候选、语言、改动文件和风险域生成有界 assignment。它不产出 Finding，不读取工具
漏洞结果。

### 8.2 Specialist

- `MemoryLifetimeAgent`：所有权、别名、分配、释放、重复释放、释放后访问；
- `BoundsAgent`：数组大小、指针偏移、长度单位/符号/截断、越界读写；
- `InterproceduralAgent`：跨函数/跨文件的资源与长度传播。

三个 Specialist 独立运行，不能看彼此输出。每个结果必须引用已读取代码并返回严格 Schema。

### 8.3 Critic

Critic 检查释放后的别名是否仍可达、边界是否已验证、错误路径是否可执行、生命周期是否由 RAII
保护、宏/模板/条件编译是否造成不确定性，并输出接受、反对、问题和置信度调整。

### 8.4 Evidence

Evidence 将候选与 Semgrep、Clang、ASan 的 path、symbol、CWE、访问类型和具体 tool-run identity
绑定。冲突和工具未运行必须原样保留，不能把空结果表述为安全。

### 8.5 Verifier 与 Arbiter

Verifier 校验上下文绑定、独立共识和工具证据，决定状态；Arbiter 仅合并已经通过结构与证据校验
的结果，并保存被拒绝原因和 coverage。

## 9. Finding Schema 与验证等级

Agent 原始候选至少包含：

```json
{
  "candidate_id": "sha256-derived-id",
  "cwe": "CWE-416",
  "path": "src/session.cpp",
  "line": 128,
  "symbol": "Session::close",
  "title": "对象释放后仍可能被回调访问",
  "mechanism": "callback retains an alias after owner deletion",
  "trigger_path": ["register_callback", "Session::close", "on_event"],
  "evidence": [],
  "confidence": 0.78,
  "verification_state": "llm-candidate"
}
```

验证等级：

| 状态 | 条件 | 默认进入 `verified-only` 门禁 |
|---|---|---|
| `llm-candidate` | 单个 Agent 候选或 Diff-only | 否 |
| `agent-corroborated` | 至少两个独立 Agent 对 CWE、位置、资源、机制和触发路径一致 | 是 |
| `tool-corroborated` | Agent 候选获得 Semgrep 或 Clang 的同身份证据 | 是 |
| `runtime-confirmed` | 完整 ASan 报告绑定同一身份和运行记录 | 是 |
| `human-confirmed` | 授权人工确认 | 是 |
| `needs-human-review` | 证据冲突、不完整或无法安全绑定 | 否 |

一致性不能只比较标题或 CWE。至少比较 CWE、path、symbol、资源/缓冲区身份、错误机制和
`trigger_path` 的可验证交集。

## 10. 模式与配置

新增配置：

```dotenv
LIMA_CXX_AGENT_MODE=required
LIMA_CXX_AGENT_MODEL=
LIMA_CXX_AGENT_MAX_CANDIDATES=100
LIMA_CXX_AGENT_MAX_CALLS=40
LIMA_CXX_AGENT_MAX_CONTEXT_FILES=12
LIMA_CXX_AGENT_MAX_CONTEXT_LINES=1200
LIMA_CXX_AGENT_MAX_OUTPUT_BYTES=1048576
LIMA_CXX_AGENT_TIMEOUT_SECONDS=600
LIMA_CXX_AGENT_PARALLELISM=3
LIMA_CXX_AGENT_DIALOGUE_ROUNDS=2
```

`LIMA_CXX_AGENT_MODEL` 为空时复用 `LIMA_LLM_MODEL`。Provider、base URL、API key 和额外 header
完全复用现有 `Settings.resolved_llm()`；不得建立第二套密钥持久化。

模式语义：

- `off`：不调用大模型，只运行已有工具链；
- `auto`：尝试大模型；不可用时保留工具结果并记录 `llm-unavailable`；
- `required`：未配置模型、全部 Specialist 失败、关键协议失败或总预算/超时导致无法完成验证时，
  任务失败；已有部分候选可留在审计消息中，但不能将任务标为成功。

LLM 与工具模式是两个独立轴。推荐：

```dotenv
LIMA_CXX_AGENT_MODE=required
LIMA_CXX_MEMORY_MODE=auto
```

所有限制均是任务总预算，不得按 Agent 各自重置。单 Specialist 允许一次重试；输出格式错误允许
一次格式修复请求；Critic/Verifier/Arbiter 失败时不得升级候选。

## 11. 接口与任务行为

整仓继续使用 `POST /v1/repository-scans`。PR 继续由现有 GitHub Webhook 创建任务，不新增绕过
认证或租户边界的入口。单次调用方不能覆盖模型、提示词、命令或预算。

`GET /api/repository-scans/capabilities` 增加：

```json
{
  "cxx_agent": {
    "mode": "required",
    "provider": "deepseek",
    "model": "model-name",
    "repository_scan": true,
    "pull_request_scan": true,
    "external_source_context": true,
    "automatic_repair": false
  }
}
```

capabilities 必须来自实际 Provider 配置和健康结果，不能仅凭 URL/API key 非空宣称可用。

## 12. 持久化、报告与可观测性

跟随原有 LIMA 策略，通过 `CollaborationBus` 和 `TaskStore` 保存：

- Planner assignment；
- Specialist 结构化结论；
- Critic 质疑与 revision；
- Evidence 关联；
- Verifier 决策；
- Arbiter 接受/拒绝；
- Agent 工具调用、错误、重试和预算消耗。

报告必须显示：

- 是否真正调用 LLM；
- Provider、模型、提示词版本；
- `repository`、`pr-context` 或 `diff-only`；
- 固定 snapshot/head SHA；
- 发送的文件/行范围与上下文 hash；
- 调用次数、Token、延迟、重试；
- 检索候选、文件、函数和 coverage；
- 截断、未解析和未覆盖范围；
- 每个 Finding 的 Agent 来源、Critic、工具证据、验证状态和门禁资格；
- `automatic_repair=false`。

不得将 LLM/工具未覆盖区域或空 Finding 写成“仓库安全”。

## 13. 安全与隐私边界

用户允许外部模型读取检索出的源码片段。发送范围必须受配置预算限制，模型请求不得包含环境变量、
密钥、`.env`、Git credential、数据库内容或仓库范围外文件。现有 `RepositoryWorkspace` 忽略和
文件预算继续生效。

外部 Provider 返回内容不得成为命令、路径、URL 或工具参数的未经验证输入。Agent 只能调用注册
的只读工具；不能调用构建命令。构建/测试仍只来自 Sidecar 管理员 argv 配置。

## 14. 测试与评测规范

### 14.1 单元与合同测试

- 索引：C/C++ 文件、函数边界、类型、调用、资源和长度操作；
- 检索：整仓、PR、预算、公平性和确定性；
- 工具：路径、行号、输出上限、总预算、未读取证据；
- LLM：严格 JSON、重复 key、未知字段、类型、大小、超时和格式修复；
- 协作：独立 Specialist、Critic、Evidence、Verifier、Arbiter、重试；
- 状态：六种验证状态与 `verified-only` 门禁；
- 模式：`off/auto/required`；
- 安全：提示词注入、路径逃逸、伪造符号/行号、跨租户、密钥泄漏；
- 报告/Web：来源、coverage、降级、Token 和禁止修复。

### 14.2 集成测试

- 整仓 Fake LLM 端到端；
- PR Diff + 本地匹配 head SHA；
- PR GitHub 固定 SHA 获取；
- GitHub 不可用时 Diff-only 降级；
- Sidecar 工具证据与 Agent 结果融合；
- Provider 部分失败和任务总 deadline。

### 14.3 真实模型评测

真实模型只在手动/定时任务运行，不在普通 PR 单测消耗 Token。使用固定 vulnerable/fixed 版本对，
评测检索和模型输入不得读取标签、CVE 描述、fix diff 或 ground truth。记录：

- TP/FP/FN/TN、precision、recall、F1；
- vulnerable/fixed 成对准确率；
- 各验证等级数量；
- repository/PR/diff-only coverage；
- 调用成功率、Token、费用、延迟和截断率；
- Provider、模型、提示词、数据、上下文和镜像身份 hash。

未经真实外部样本验证，不得在 README 中宣称生产召回率或零日能力。

## 15. 验收标准

1. `required` 模式发生真实模型调用，否则任务失败；
2. `auto` 模式降级时明确记录 `llm-unavailable`；
3. 整仓和 PR 共用同一协作协议与 Finding Schema；
4. PR 上下文绑定完整 head SHA；
5. Specialist 独立，初始阶段不可见其他 Agent 或工具结果；
6. 单 Agent 或 Diff-only 最高为 `llm-candidate`；
7. 两 Agent 共识必须校验 CWE、位置、资源、机制和路径；
8. 路径、行号、符号、引用和已读取范围全部绑定可信快照；
9. 总调用、Token、文件、行数、输出和时间预算不可绕过；
10. C/C++ 所有 Finding 均不可自动修复；
11. Agent 消息按 LIMA 原策略持久化且租户隔离；
12. 固定版本对评测无标签泄漏并可重算；
13. 七项 Sidecar 前置问题独立复审通过；
14. Windows 宿主单测、Linux/Docker 安全合同、真实 Sidecar 和真实模型评测分别记录证据；
15. 环境未提供 Docker 或模型时必须写“未验证”，不得推断通过。

## 16. 项目开发规范

- 从新的隔离 worktree 和 `codex/cxx-llm-agent-detection` 分支开发；
- 使用 TDD：每个行为先记录 RED，再写最小实现并记录 GREEN；
- 每个任务使用独立 Signed-off-by 提交，提交格式使用 Conventional Commits；
- 每个任务由独立 reviewer 同时审查规范符合性和代码质量；
- Critical/Important 未关闭不得进入下一依赖任务；
- 禁止 amend/rebase 已推送的 `codex/cxx-memory-detection-impl` 历史；
- 禁止混入根 `Dockerfile` 和 `tests/test_service.py` 的用户修改；
- 不因测试通过而声称 Docker、Linux、真实模型或公开评测已通过；
- 不修改 main，不自动合并，不自动创建正式 PR；
- 设计变化必须先更新本文档并由用户确认。

## 17. 后续模型开发与当前模型验收的分工

由于后续代码将由其他模型实施，本文档与配套实施计划是唯一经用户确认的需求基线。开发模型负责
逐项实现、测试、提交和记录证据；当前验收模型负责按设计和计划复核代码，不以开发模型的完成声明
替代独立验证。

### 17.1 开发模型必须完成的事项

1. 从 `2e69f3ce56f80b91e4b180ab0556100d3e173e4f` 创建新的隔离 worktree 和
   `codex/cxx-llm-agent-detection` 分支，不在 main 或现有已推送分支上改写历史；
2. 按实施计划 Task 1–21 顺序工作，先关闭 Sidecar 七项问题，再开发 LLM Agent；
3. 每个 Task 保存 RED/GREEN 命令、测试计数、提交 SHA 和复审结论；
4. 遇到规范冲突、接口必须变更、Critical/Important 复审问题或外部环境缺失时暂停并记录，不得
   静默降低要求；
5. 只提交该 Task 的文件，禁止使用 `git add .`，并在提交前检查 `git diff --cached --name-only`；
6. 暂停或交接时更新实施计划进度台账并提供可复现的下一条命令。

### 17.2 验收模型必须独立检查的事项

1. 核对实际 diff 与设计条款、任务文件范围和接口合同，不只阅读总结；
2. 重新运行适合当前环境的单元测试、回归测试、静态检查和 `git diff --check`；
3. 检查 Specialist 独立性、源码/模型输出不可信边界、任务级总预算、固定 SHA、租户隔离和
   `automatic_repair=false`；
4. 将 Fake LLM、真实模型、Docker/Linux、真实 Clang/ASan 和联网评测证据分开验收；
5. 对无法在当前环境复现的结果标记“未验证”，不能仅根据日志截图认定通过；
6. 有未解决 Critical/Important 时不得给出 merge-ready 结论，不得合并 main。

### 17.3 每次交接的最小证据

交接必须包含：worktree 绝对路径、branch、base/head SHA、commit list、`git status --short`、修改
文件清单、RED/GREEN 与完整回归命令及结果、Docker/真实模型证据、未解决问题、进度台账路径、
GitHub 分支和 Actions URL。任何缺项都由验收模型标记为待补证据，而不是自行推测。
