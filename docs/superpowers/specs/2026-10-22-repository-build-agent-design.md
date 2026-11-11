# LIMA 待审计仓库智能体构建方案（设计草案）

日期：2026-10-22。核查位置：`D:\Projects\LIMA`；HEAD：`4c3adfa`，包含核查时已有的本地修改。

本文是供评审的方案，不是已批准的 Implementation Packet，不启动产品代码开发、真实构建、模型调用或依赖下载。

## 1. 目标和范围

将待审计仓库的构建准备，从人工或交互式 Codex 阅读说明、安装依赖、编写配方、运行命令和排错，改为 LIMA 自身可调度、可记录、可停止的 Build Agent 任务。用户提供仓库快照、目标范围和预算，系统自动识别环境、生成配方、执行构建准备、诊断失败，并向检测链交付经校验的结果。

这里暂将“构建仓库”理解为**准备被 LIMA 检测的目标仓库**，优先覆盖现有 C/C++ 链路。若实际目标是构建 LIMA 自身的 Python/前端/Docker 发布产物，应另行调整输入、工具和验收对象。

区分两个目标，避免结果名称混用：

| 目标 | 应产出什么 | 本方案位置 |
| --- | --- | --- |
| `analysis-context` | 可被下游使用的 compdb、生成头文件、第三方头文件及来源证据 | 首期默认目标 |
| `compile-target` | 指定 target 的实际编译/链接产物和验证报告 | 后续独立扩展 |

首期不要求大型仓库整仓编译成功，不让 Agent 修改业务源码来绕过错误，不把构建成功当作漏洞证实。生成代码仅允许由已授权构建步骤在临时工作副本产生。平台升级后，日常任务不依赖用户在聊天中逐条运行命令；人工只处理策略外的依赖、资源、凭据或不支持的构建系统。

## 2. 当前基础和实际缺口

以下以当前代码为准，历史规划只作背景。

| 现有位置 | 已有能力 | 本次需要补齐 |
| --- | --- | --- |
| `deploy/build-recipes/README.md`、`resinsight/` | 人工维护 Dockerfile 和严格 schema v1 配方；以 configure 导出分析上下文 | 自动识别、生成候选配方、诊断和修订 |
| `lima/build_recipe.py` | `BuildRecipe.from_yaml()`、`ContainerRunner`、`run_recipe_in_container()`；失败中止，统一写包 | 自动任务使用的执行策略、完整诊断、状态保持、取消和资源上限 |
| `lima/context_package.py` | schema v1、路径重写、包读写与结构校验 | 下游接入和按文件内容计算的完整性证据 |
| `lima/runtime.py` | `AgentRuntime`、`AgentLoop`、`ToolRegistry`、预算和 checkpoint 接口 | 构建专用状态、工具与持久化映射 |
| `cxx_analyzer/build_context.py` | 读取快照中现有 compdb，过滤危险参数，按 TU 解析上下文 | 独立上下文包的消费适配；生成层目前仍会返回未实现诊断 |
| `lima/agent_orchestrator.py` | `_semantic_flags_from_compdb()` 从快照 compdb 提取 Specialist 的参数提示 | 与 facts/repro 使用同一份已验证上下文 |

必须先解决的工程问题：

1. `DockerContainerRunner` 每次交互都会新建 `docker run --rm`。挂载目录内文件会保留，容器可写层内安装的依赖和 `/tmp` 文件不会跨调用保留。Agent 不能假定前一步安装自动作用于下一步。
2. `_run()` 捕获 stdout/stderr，但 `run()` 只返回退出码和 stdout；配方失败只抛简短原因。需要保留有界 stderr 和步骤信息，模型才有事实可用于排错。
3. 当前默认 Runner 挂载传入源码目录可写，未设置自动任务所需的网络、CPU、内存、PID 等限制。不能直接对用户导入目录启动自主重试。
4. 配方严格解析验证的是格式和路径，不代表命令已经获得执行授权；当前 schema 本身不禁止所有危险命令。需要单独的执行策略。
5. 当前包格式上限为 compdb 4 MiB、2048 条目、单文件 2 MiB、总载荷 256 MiB。大型仓库首期按声明的组件范围处理；超过上限明确失败，不静默截断。扩大范围需要独立契约变更。
6. 包级 `context_hash` 主要基于 compdb 和路径结构等材料，不能替代全部头文件字节的摘要；也不能与下游按 TU 计算的同名 `context_hash` 混为一谈。

当前服务入口是 `lima/service.py::_execute_repository_scan()` → `RepositoryWorkspace` → `lima/repository_scanner.py` → `run_platform_review()`，未调用包读取器。不能把“包模块存在”描述成“服务端已支持构建包”。此外 Specialist 的参数提示目前独立解析 compdb，其中 `command.split()` 与 Sidecar 的严格解析并不等价；接入时应收敛到同一份校验后参数。

## 3. 可选路线

| 路线 | 优点 | 代价和限制 |
| --- | --- | --- |
| A：在服务端封装外部 Coding CLI | 可快速试验既有 Coding Agent 能力 | 引入 CLI 会话、工具权限、授权和费用管理；产物与既有 LIMA 契约还需适配 |
| B：LIMA 原生 Build Agent + 结构化工具 | 可复用现有 runtime、配方和证据结构；权限和验收由程序控制 | 需要实现构建工具与调度接入 |
| C：识别、依赖、构建、审查多智能体 | 可针对复杂仓库分工 | 初期交接、上下文、预算和失败归因更复杂 |

**推荐 B。** 第一版一个负责规划和排错的 Agent，加独立确定性校验器；依赖解析和执行由工具完成。保留模型供应商适配能力，后续有真实失败数据再决定是否拆分多个 Agent。

## 4. 处理流程

```text
固定仓库快照 + 明确目标范围 + 部署策略 + 预算
  → 读取构建描述和 CI 线索
  → 复用已验证配方，或生成候选 BuildPlan
  → 策略校验和依赖准备
  → 一次性构建会话内执行 configure
  → 有界日志 → 分类诊断 → 修订计划 → 再校验、再尝试
  → 导出上下文包 → 校验来源与内容 → 下游 TU 解析检查
  → SUCCEEDED / PARTIAL / FAILED / NEEDS_ATTENTION
```

先复用确定性成果，再调用模型。完全匹配的可信缓存可直接复用；相似仓库的配方只作候选，必须重新执行验证。README、CI 文件和日志均为不可信任务数据，不获得改变权限或工具策略的能力。

### 4.1 仓库识别

有界读取 `README`、`CMakeLists.txt`、`CMakePresets.json`、工具链文件、依赖锁文件、子模块清单和相关 CI 配置。输出构建系统、语言、目标架构、拟支持组件、所需依赖及证据位置。

首期仅执行 Linux 容器内的 CMake 配置，优先验证 C/C++ 项目。Make/Autotools、Meson、Bazel、OpenHarmony GN 等先识别并报告 `unsupported-build-system`，后续逐一增加 adapter。大型 monorepo 必须明确组件和目标 TU 清单，不能由 Agent 随意缩小任务后宣称整仓成功。

### 4.2 计划和配方

Agent 输出结构化 BuildPlan，至少包括快照引用、目标、组件范围、工具链引用、依赖要求、候选 configure argv、预计 compdb 路径、生成头文件模式、include roots 和预算引用。计划中每项非显然决定附来源或失败日志引用。

执行器把批准的计划转换为现有 `BuildRecipe`。首期沿用 schema v1；计划、预算、日志和来源信息保存在包外的任务记录，不往冻结 YAML 中添加未知键。

不开放“模型生成任意 Dockerfile 并直接执行”的工具。依赖由受信模板/工具根据结构化要求准备；首期从部署者已批准的工具链镜像和依赖集选择。选不到的依赖进入 `NEEDS_ATTENTION`，不猜测替代包、不转向任意下载脚本。

### 4.3 执行会话

固定快照保持只读。受信 Worker 创建一次性工作副本，容器仅挂载该副本及限定输出目录。configure 可写工作副本内构建目录；结束时校验业务源码是否被改变，发生非允许变更则结果不发布。

每次尝试使用一个持续会话，在同一环境完成 configure、读取 compdb 和导出头文件；也可用“固定依赖镜像 + 持久化临时构建卷”实现等价语义。会话由 Worker 管理，模型只获得 session id，不获得 Docker socket 或宿主路径。

构建脚本属于目标代码执行：放在独立的构建执行域，作为受控执行阶段管理，不在静态 Audit 主进程或分析沙箱里执行。Windows/PowerShell 用于提交和查看任务，首期实际执行要求 Docker Desktop Linux 容器或 Linux Worker。

### 4.4 排错和有界重试

工具返回 `step_id`、argv、退出码、stdout/stderr 引用、有界脱敏摘要、耗时、超时/取消状态和文件变化摘要。常见分类及动作如下：

| 分类 | 允许的自动动作 | 停止条件 |
| --- | --- | --- |
| 缺少批准列表内的依赖 | 选择对应依赖集，重建干净环境 | 不在列表、版本冲突或缺少凭据 |
| CMake 选项或工具链不匹配 | 按源码/官方配置证据修订选项 | 需要修改业务源码或换成不支持的平台 |
| 缺少生成头文件 | 修正允许的 configure 参数、导出规则 | 需要额外执行尚未支持的生成流程 |
| 路径映射、include roots 缺失 | 修订配方并重新导出 | 路径越界、缺失文件或无法验证来源 |
| 网络、资源、工具基础设施故障 | 仅对明确可重试故障执行有界重试 | 超预算、策略禁止或重复同一失败 |

建议试点默认：最多 3 次构建尝试、8 次模型调用、每步 300 秒、总任务 1800 秒、每轮模型日志摘要 32 KiB。这些是待试点校准的配置建议，不是当前已实现参数或性能承诺。CPU/内存/PID/磁盘/输出字节额度由部署策略冻结，模型不能上调。

只有配置、依赖或路径等条件发生有效变化时，才发起下一次尝试。记录规范化失败指纹；同一失败且无新修订直接停止。每次工具调用执行前计算剩余总时限，并把剩余时间传给执行器；不能仅依赖 AgentLoop 轮间检查来中断长构建。

## 5. 权限和依赖准备

Agent 只可调用受控工具：`inspect_build_files`、`propose_build_plan`、`prepare_dependencies`、`execute_configure`、`inspect_build_failure`、`export_context_package`、`validate_context`。工具参数使用快照、计划和会话引用，不接受任意宿主路径或自由 shell。

具体约束：

- 执行工具校验 adapter、可执行文件、argv 选项、输出目录、镜像来源和目标架构；argv 数组仅解决 shell 插值问题，不能代替策略校验。
- 配置构建容器无外网、非 root、capabilities drop、只读基础文件系统和明确可写临时目录，设置 CPU/内存/PID/磁盘/输出/时间限制。取消与超时必须由 Worker 清理容器和子进程。
- 容器不持有模型、Git、数据库或包源凭据，不挂载宿主 Docker socket。私有依赖凭据由受信下载组件使用，不进入 Agent 上下文和日志。
- 首期使用批准并固定标识的工具镜像及离线依赖。后续联网依赖由容器外的下载组件按白名单、摘要和额度获取并封存；任务失败不能自动放宽网络。
- 镜像内部依赖安装如需 root，仅在受信依赖准备阶段完成。仓库控制的 configure 在后续非 root 会话运行。
- 不修改源仓库、不伪造头文件、不删除待分析目标、不通过关闭目标功能掩盖失败。功能开关变更必须属于预先声明的扫描配置，并在结果中显示。

这比旧配方手工工作流的默认 Docker 执行约束更严格，因此需先补齐执行器，之后才能启用自主重试。

## 6. 任务契约和状态

以下字段为拟新增契约，须在开发前冻结。

**BuildRequest：** `repository_ref`、`revision`（适用时）、`snapshot_hash`、`goal`、`component_scope`、`target_units`、`toolchain_profile`、`policy_ref`、`budget`。快照和目标必须由受信控制面绑定，不能相信 Agent 自报的 hash。

**BuildResult：** `run_id`、`status`、`snapshot_hash`、`plan_digest`、实际镜像标识、依赖集摘要、`package_ref`、`package_context_hash`、`artifact_digest`、`attempts`、`coverage`、`failure_code` 和日志引用。

`artifact_digest` 根据所有包成员的规范路径、字节长度和逐文件 SHA-256 生成，覆盖头文件内容；保留既有包格式和原有 `context_hash` 语义。TU resolver 的 hash 单独记录为 `tu_context_hash`，建立包→TU 的来源映射，禁止要求两种 hash 数值相等。

```text
QUEUED → INSPECTING → PLANNING → PREPARING → EXECUTING → VALIDATING
                                 ↑              │          │
                                 └── REPLANNING ←┘          ├→ SUCCEEDED
                                             （可重试失败） ├→ PARTIAL
                                                           └→ FAILED
任意运行态 → NEEDS_ATTENTION / CANCELLED / TIMED_OUT
```

校验失败也可进入有界重规划。预算耗尽返回 `FAILED/budget-exhausted`；需要新依赖或策略外权限返回 `NEEDS_ATTENTION`。`PARTIAL` 仅用于事先允许部分范围的请求，并逐项报告缺失 TU；不能进入要求完整上下文的下游门禁。

所有终态记录实际费用/调用数、耗时、尝试次数和已使用预算。checkpoint 记录计划、观察、尝试和会话状态；Worker 中断后先检查已有副作用和产物。不能把“checkpoint 存在”直接理解为可以重放上一次模型请求或构建步骤。

## 7. 下游接入和成功判定

这是首期必须完成的工作，不能在“配方已生成”处结束。

1. 控制面接收包，调用 `read_package()` 校验格式，再验证完整内容摘要、快照绑定、实际工具链和声明的组件范围。
2. 为下游建立只读分析视图：固定源码 + 包内生成文件和依赖头文件；通过受信适配器映射 compdb 路径。拒绝文件覆盖冲突、路径逃逸和对构建会话绝对路径的依赖。
3. 明确接入 facts、repro 和 Specialist 参数上下文。三者必须读取同一份经批准的 TU 参数投影，继续拒绝响应文件、插件载入和危险编译选项。
4. 逐个检查声明目标 TU 的 resolver 状态；首期小范围试点对全部目标 TU 运行真实 Clang 解析检查，记录缺头文件、宏和语言标准等失败。不能只采样一个文件后声称全部可用。
5. 仅当全部必需 TU 上下文可解析且检查通过，才返回 `SUCCEEDED`。包有效但下游不支持，不算端到端完成。

缓存键至少包含租户/授权范围、快照内容 hash、组件和 TU 范围、goal、构建选项、平台/架构、镜像内容标识、依赖摘要、配方与策略版本、消费者版本。命中后重验内容摘要和当前策略，不复用可写构建目录。

## 8. 开发拆分建议

以下是建议切片和文件职责，不是可直接开工的 Packet；各切片需按项目交接标准明确 Public Symbols、冻结测试和允许修改范围。

| 切片 | 建议位置 | 交付与验收 |
| --- | --- | --- |
| 1：执行器基础 | 修改 `lima/build_recipe.py`；新增 `lima/build_executor.py`、`tests/test_build_executor.py` | 有界 stdout/stderr、隔离会话、资源限制、取消和临时副本；证明跨步骤文件可用且原仓库不变 |
| 2：任务契约和工具 | 新增 `lima/build_contracts.py`、`lima/build_tools.py` 及对应测试 | 请求/结果、策略校验、快照绑定；覆盖危险 argv、未批准依赖、路径越界和预算拒绝 |
| 3：原生 Build Agent | 新增 `lima/build_agent.py`、`tests/test_build_agent.py`；复用 `lima/runtime.py` | 候选配方→执行→诊断→修订；用 fake model/runner 验证无效重试、预算和中断恢复 |
| 4：包消费接入 | 新增受信包视图适配器；修改实际调用点及 `cxx_analyzer/build_context.py` 等消费者 | facts/repro/Specialist 参数一致，真实目标 TU 可解析；损坏包、错快照和危险参数均拒绝 |
| 5：服务调度和可见性 | 扩展 `lima/service.py`、配置/持久化/Worker 实际接入点，随后增加前端任务页 | 后台运行、进度、日志、取消、恢复；浏览器关闭后继续执行 |

首期配置建议采用 `LIMA_BUILD_AGENT_MODE=off/auto/required`：`off` 保持现有手动路径；`auto` 在已授权范围内尝试，失败可继续静态扫描但必须显示构建证据缺口；`required` 缺少合格结果时阻断依赖构建上下文的阶段。它们是拟新增语义，不是当前有效环境变量。

默认 `off`。启用模型构建要有单独预算和代码外发范围；不能因通用模型已经配置就自动运行构建 Agent。Build Worker 是独立职责，优先复用实际任务基础设施；现有不同任务队列是否适合承载长构建，需在第 5 切片的 Packet 中核查后确定。

## 9. 验证安排

先固定测试对象和成功标准，再开发。普通 CI 使用 fake model 和 fake runner，不需要模型 Key；真实 Docker/模型试点单独运行并记录环境。

| 测试组 | 必须证明的行为 |
| --- | --- |
| 最小 CMake 夹具 | 自动识别、configure、导出、包读取和目标 TU 解析全链完成 |
| 缺依赖夹具 | 从真实 stderr 诊断；批准范围内修订一次后成功；未批准依赖停止 |
| 会话夹具 | 步骤间能读取生成文件；重试使用干净环境；不依赖已删除容器的可写层 |
| 安全负例 | 恶意 README/日志、危险 argv、符号链接逃逸、越权挂载、联网请求、原源码改写均不能获得额外权限 |
| 完整性与来源 | 头文件同长度篡改也会被摘要校验拒绝；错快照、包视图覆盖冲突和跨租户缓存不可接受 |
| 预算与恢复 | 长步骤会被剩余时限打断；超输出限额可停止；取消后无残留容器；不重复发布包或盲目重放调用 |
| 消费一致性 | facts、repro、Specialist 使用同一 TU 参数；包 hash 与 TU hash 分别验证；不把 heuristic 标为 resolved |
| 范围和降级 | 超过包上限、缺失 TU、unsupported 系统都有明确结果；`auto` 降级不冒充成功 |

真实试点从一个小型 CMake 仓库开始，再验证已提供人工配方的 ResInsight 指定组件；具体 commit、组件与 TU 范围在运行前冻结。OpenHarmony 仅在有对应 adapter 和依赖集后进入执行试点。

比较三条路径：人工配方、确定性模板、模板 + Build Agent。使用相同快照、目标范围、依赖权限、资源预算和消费者版本，分别记录冷缓存和热缓存结果。统计端到端成功率、TU 上下文可解析率、Clang 检查通过率、人工介入次数、模型调用/费用、墙钟时间和失败分类。预先排除的目标也保留在范围记录中，不把主动缩小范围当作成功率提升。

首期通过标准是：受支持夹具和安全负例通过；至少一项冻结真实目标在无人逐条操作的情况下完成构建准备并由下游消费；失败任务能给出可复核原因；原仓库未被修改。真实仓库总体成功率和节省时间由试点测得，本文不预设提升数字。

## 10. 交付和后续扩展

首期交付 Build Agent、受控执行器、任务记录、可复用配方、完整内容摘要和下游可用性报告。用户操作收敛为：选择固定仓库和范围 → 选择构建配置与预算 → 提交 → 查看结果或处理明确阻塞。

后续按失败分布增加依赖下载组件、其他构建 adapter 和 `compile-target`。需要编译/链接才能产生的头文件或源码，作为显式扩展处理；不能偷偷在现有 configure-only 配方中加入完整构建。实际测试运行继续属于独立验证目标。

Fork 开发时采用一切片一 PR，并先核对原仓库贡献规范和维护者接受范围。向上游提交时附真实执行证据、兼容行为和安全负例；不把个人本地环境、私有依赖或模型 Key 写入仓库。

## 11. 核查依据

- `README.md`：项目定位、仓库导入、C/C++ 智能体检测入口和部署说明。
- `CONTRIBUTING.md`、`docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md`：贡献流程和 Ready-for-Code 要求。
- `deploy/build-recipes/README.md`、`deploy/build-recipes/resinsight/recipe.yaml`、`Dockerfile`：现有手工配方流程和 configure-only 约定。
- `lima/build_recipe.py`：`BuildRecipe`、`ContainerRunner`、`DockerContainerRunner`、`run_recipe_in_container()`。
- `lima/context_package.py`：schema、限额、摘要材料、`read_package()` 和 `write_package()`。
- `lima/runtime.py`：`AgentRuntime`、`AgentLoop`、`ToolRegistry`。
- `cxx_analyzer/build_context.py`：`_resolve()`、`resolve_build_context_execution()` 和生成层未实现诊断。
- `lima/agent_orchestrator.py`：`_semantic_flags_from_compdb()`、`_driver_contract()`。
- `lima/service.py`、`lima/repository_scanner.py`：当前扫描入口及 snapshot-compdb 路径。
- `deploy/competition/README.md`、`docs/LIMA_三沙箱通信与依赖网络治理_迭代规划_v3.md`：执行边界和离线依赖方向；规划内容不作为已实现能力。
- `tests/test_build_recipe.py`、`tests/test_context_package.py`：既有配方和上下文包测试。
