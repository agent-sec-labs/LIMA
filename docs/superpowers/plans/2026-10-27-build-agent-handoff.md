# LIMA Build Agent and Analysis Context Handoff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 用户提交固定仓库快照和 C/C++ 目标范围后，LIMA 自动准备 Linux/CMake 构建上下文，并将经校验的编译参数交给 facts、repro 和 Specialist，最后在隔离容器运行 PoC，完整呈现结果和覆盖缺口。

**Architecture:** 一个原生 Build Agent 负责提出与修订结构化计划；受信策略层决定允许的镜像、依赖和命令，独立 Worker 在临时副本中执行。产出的上下文包通过完整性与快照校验后，形成只读分析视图；下游消费者共享同一 TU 参数投影。任务状态和证据由服务端持久化，前端只展示与控制已授权任务。

**Tech Stack:** Python、pytest、Docker Desktop Linux 容器或 Linux Worker、CMake/Clang、现有 LIMA context package、React/TypeScript。

**Spec:** [待审计仓库智能体构建方案](../specs/2026-10-22-repository-build-agent-design.md)。该文件是设计草案；执行前以本计划的首期范围和本地当前代码为准。

## Global Constraints

- 首期目标为 `analysis-context`，仅执行指定组件的 Linux/CMake C/C++ configure 与必要的目标 TU 检查；不宣称整仓构建成功。OpenHarmony GN、其他构建系统和 `compile-target` 单独立项。
- 固定仓库快照只读；构建脚本只能操作一次性工作副本。仓库专用配方、私有依赖及本机路径留在本地配置，不提交 GitHub。
- 模型输出是候选 BuildPlan，绝不直接执行任意 Dockerfile、shell、网络下载或业务源码修改。README、CI 和日志均作为不可信数据。
- 策略默认关闭自动构建；拟新增模式 `off/auto/required`：`auto` 失败可继续静态扫描但显式记录缺口，`required` 阻断依赖构建上下文的阶段。
- 构建 Worker 限制网络、权限、CPU、内存、PID、磁盘、输出和时间；不挂载 Docker socket，不向容器传模型、Git 或数据库凭据。取消和超时清理所有子进程及容器。
- 试点预算建议为最多 3 次构建尝试、8 次模型调用、单步 300 秒、任务总计 1800 秒、每轮日志摘要 32 KiB；执行前作为部署策略冻结并按试点数据调整。
- 包内所有成员按规范路径、长度、SHA-256 计算 `artifact_digest`；既有包 `context_hash` 与下游 `tu_context_hash` 分别保留，不要求数值相等。
- `SUCCEEDED` 要求声明的全部目标 TU 可解析且真实 Clang 检查通过。`PARTIAL` 只能用于请求事先允许的部分范围，并逐项列出缺失 TU。
- 与现有 Python Golden Path 隔离；不改变现有审计默认路径。每个任务实施前检查 `AGENTS.md`、工作区状态和当前接口，避免覆盖已有本地修改。

## Review Focus

以下输入容易造成“看似成功”，每项在对应任务的测试中固定预期：

1. 构建步骤生成的文件仅在容器可写层：Task 1 测试跨步骤可见及重试清洁性。
2. README 或失败日志诱导扩大权限：Task 2 测试工具拒绝策略外 argv、网络和依赖。
3. 头文件被同长度替换或包与快照不匹配：Task 4A 测试内容摘要及快照绑定拒绝。
4. facts、repro 和 Specialist 读取不同编译参数：Task 4B 测试同一 TU 参数投影和危险 flag 拒绝。
5. 浏览器断开或构建超时后任务状态错误：Task 5 测试后台持续、取消清理、恢复不盲目重放。

---

## 交付边界与依赖顺序

顺序为 Task 1 → 2 → 3 → 4A → 4B → 5 → 6。每项完成后可独立审查，下一项只消费已冻结接口。首期只以一个小型 CMake 夹具和一个冻结的真实仓库组件验收；ResInsight 可作真实试点，OpenHarmony 不在首期自动执行范围。不要把现有 `python -m lima.container_build` 的人工完整构建命令等同于审计任务已自动消费构建结果。

当前工作区的 `lima/agent_orchestrator.py` 及其测试已有与本计划无关的未提交修改。Task 4B 开工前须由该修改的负责人单独提交、移到独立工作树，或明确保留后只暂存 Task 4B 的补丁；不得把 Discovery 窗口调整卷入 Build Agent 提交。

### Task 1: 隔离、可诊断的构建执行器

**Files:**
- Create: `lima/build_executor.py`
- Create: `lima/container_execution.py`，仅放通用容器启动限制、取消确认与 worker 证据发布原语
- Modify: `lima/container_build.py`，把可复用原语下沉到共享模块，保持人工完整构建 CLI 的外部行为
- Modify: `lima/build_recipe.py`，仅在需要时补充配方到受控执行器的适配；`DockerContainerRunner` 保留为人工路径
- Test: `tests/test_build_executor.py`、`tests/test_container_build.py`、`tests/test_build_recipe.py`

**Interfaces:**
- Consumes: `BuildRecipe` 的解析/包导出契约、`lima/container_build.py` 的隔离 worker 与结果发布规则；现有 `run_recipe_in_container()` 继续服务人工路径，不作为 Agent 的执行入口。
- Produces: `BuildStepResult(step_id: str, argv: tuple[str, ...], exit_code: int | None, stdout_ref: str, stderr_ref: str, elapsed_seconds: float, timed_out: bool, cancelled: bool)`；`BuildExecutor.execute(recipe: BuildRecipe, snapshot_dir: Path, output_dir: Path, limits: BuildLimits, cancel: Callable[[], bool]) -> BuildExecutionResult`。`BuildExecutionResult` 包含步骤证据、实际镜像摘要和暂存包路径，成功标记不代表下游可用。`container_execution.py` 提供 `run_isolated_worker(spec: ContainerRunSpec, cancel: Callable[[], bool]) -> ContainerRunResult` 与 `publish_verified_worker_record(attempt_dir: Path) -> dict[str, Any]`，供人工 CLI 和 Agent 执行器共用；`build_executor.py` 不再自行拼接另一套 `docker run` 命令。
- Evidence storage: 每次尝试写入配置的本地任务产物根目录下 `task_id/attempt-N/`，保存有界且脱敏的 stdout/stderr、步骤 JSON 和原子发布的尝试结果。`stdout_ref/stderr_ref` 仅是该任务目录内的相对引用，服务端按 tenant/task 授权解析，绝不把宿主绝对路径写进任务或模型上下文。首期每流最多保留 1 MiB，给模型的单轮摘要最多 32 KiB；超过上限显式标记截断。默认终态后保留 30 天，由部署配置缩短或延长；清理必须跳过活动任务。

- [ ] **Step 0: 记录执行栈裁定。** 对照 `container_build.py` 的 `container_command()`、worker 挂载、`publish_worker_record()`、取消结果校验及 `build_recipe.py` 的 `DockerContainerRunner`；把哪些原语复用、哪些人工 CLI 语义保留写入本任务提交说明。裁定为共享底层隔离与证据发布，Agent 不调用人工完整构建 CLI，也不新增独立 Docker 命令拼接栈。
- [ ] **Step 1: 写失败测试。** `test_generated_file_survives_configure_and_export` 断言同一次尝试的后续步骤看得到生成头文件；`test_retry_starts_clean_and_snapshot_unchanged` 断言重试没有旧产物且原仓库字节未改变；`test_timeout_cancel_and_stderr_are_recorded` 断言中断清理、stderr 相对引用、有界脱敏和截断标记；`test_worker_result_not_published_after_cancel` 固定人工 CLI 与 Agent 共同规则。
- [ ] **Step 2: 运行测试并确认失败。** `python -m pytest tests/test_build_executor.py tests/test_container_build.py -q`，预期新增执行器和共享原语测试失败。
- [ ] **Step 3: 实现执行器。** 从现有 CLI 提取通用容器限制和证据发布原语；使用固定镜像和一次性副本/持久化临时构建卷保持单次尝试的步骤状态；每次重试重建干净环境；每步取剩余总时限，按 Evidence storage 契约写日志，结束后删除资源。
- [ ] **Step 4: 运行回归。** `python -m pytest tests/test_build_executor.py tests/test_container_build.py tests/test_build_recipe.py -q`，预期人工 CLI 和 Agent 路径均通过。
- [ ] **Step 5: 单独提交。** 只暂存上述文件，提交信息建议 `feat: share bounded container execution primitives`。

### Task 2: 构建请求、策略与受控工具

**Files:**
- Create: `lima/build_contracts.py`、`lima/build_tools.py`
- Test: `tests/test_build_contracts.py`、`tests/test_build_tools.py`

**Interfaces:**
- Consumes: Task 1 的 `BuildExecutor.execute(...)`。
- Produces: `BuildRequest(repository_ref, snapshot_hash, goal, component_scope, target_units, toolchain_profile, policy_ref, budget)`；`BuildPlan(snapshot_hash, adapter, component_scope, configure_argv, expected_compdb, generated_headers, include_roots, dependency_set_ref)`；`BuildResult(run_id, status, snapshot_hash, plan_digest, image_digest, dependency_digest, package_ref, artifact_digest, attempts, coverage, failure_code, evidence_refs)`。实现 `validate_build_plan(request: BuildRequest, plan: BuildPlan, policy: BuildPolicy) -> ValidatedBuildPlan` 和 `register_build_tools(registry: ToolRegistry, executor: BuildExecutor, policy: BuildPolicy) -> None`。

- [ ] **Step 1: 写失败测试。** `test_plan_rejects_snapshot_scope_mismatch`、`test_plan_rejects_shell_or_host_path`、`test_tool_rejects_unapproved_dependency_and_network`、`test_budget_cannot_be_raised_by_model`；各自断言明确失败码且未调用执行器。
- [ ] **Step 2: 运行测试并确认失败。** `python -m pytest tests/test_build_contracts.py tests/test_build_tools.py -q`。
- [ ] **Step 3: 实现契约与工具。** 首期仅 `cmake-linux` adapter；工具只接受结构化引用和 argv 数组，校验可执行文件、参数、路径、镜像、依赖集和预算。提供 `inspect_build_files`、`propose_build_plan`、`prepare_dependencies`、`execute_configure`、`inspect_build_failure`、`export_context_package`、`validate_context`，不向模型暴露 Docker socket 或宿主绝对路径。
- [ ] **Step 4: 运行测试。** `python -m pytest tests/test_build_contracts.py tests/test_build_tools.py -q`，预期通过。
- [ ] **Step 5: 单独提交。** 只暂存本任务文件，提交信息建议 `feat: define policy checked build tools`。

### Task 3: 原生 Build Agent 的规划与有界修订

**Files:**
- Create: `lima/build_agent.py`
- Test: `tests/test_build_agent.py`

**Interfaces:**
- Consumes: Task 2 的 `BuildRequest`、`BuildPlan`、`BuildResult`、`validate_build_plan(...)` 和受控工具；复用 `lima/runtime.py` 中的 `AgentRuntime`、`AgentLoop`、`ToolRegistry`。
- Produces: `BuildAgent.run(request: BuildRequest, *, cancel: Callable[[], bool], progress: Callable[[BuildProgress], None]) -> BuildResult`；`BuildProgress` 记录状态、尝试序号、计划摘要和证据引用。终态为 `SUCCEEDED/PARTIAL/FAILED/NEEDS_ATTENTION/CANCELLED/TIMED_OUT`。

- [ ] **Step 1: 写失败测试。** fake model 与 fake executor 覆盖“识别 CMake→生成计划→configure→校验”、“批准依赖缺失后修订一次成功”、“同一失败指纹且无有效变更立即停止”、“超预算、策略外依赖、取消分别返回正确终态”；断言每轮保留计划和日志证据。
- [ ] **Step 2: 运行测试并确认失败。** `python -m pytest tests/test_build_agent.py -q`。
- [ ] **Step 3: 实现状态机。** 固定 `INSPECTING/PLANNING/PREPARING/EXECUTING/VALIDATING/REPLANNING`；优先复用完全匹配且重验的成果，模型仅在需要规划/排错时调用。每次尝试须改变有效配置/依赖/路径；超时和预算由代码检查，不由模型自报。checkpoint 恢复先核实副作用，不盲目重放上一次构建或模型调用。
- [ ] **Step 4: 运行测试。** `python -m pytest tests/test_build_agent.py -q`，预期通过。
- [ ] **Step 5: 单独提交。** 只暂存本任务文件，提交信息建议 `feat: add bounded repository build agent`。

### Task 4A: 独立包校验与只读分析视图

**Files:**
- Create: `lima/build_context_view.py`、`tests/test_build_context_view.py`
- Test: `tests/test_context_package.py`（仅运行回归，不在本任务修改）

**Interfaces:**
- Consumes: `BuildResult.package_ref`、`read_package(pkg_dir: Path)`、固定仓库快照、声明的目标 TU。
- Produces: `verify_build_artifact(package_dir: Path, expected_snapshot_hash: str, expected_artifact_digest: str) -> VerifiedBuildArtifact`；`create_analysis_view(snapshot_dir: Path, artifact: VerifiedBuildArtifact, target_units: tuple[str, ...]) -> AnalysisContextView`；`AnalysisContextView.flags_for_tu(tu: str) -> tuple[str, ...]`。视图为只读，暴露目标 TU、规范化路径、过滤后的参数与包来源；保留包 `context_hash`、`artifact_digest`，TU hash 由下游解析后独立记录。本任务不改现有消费者，也不宣称下游已接入。

- [ ] **Step 1: 写失败测试。** `test_same_length_header_tamper_rejected`、`test_wrong_snapshot_and_path_escape_rejected`、`test_view_rejects_file_overlay_conflict`、`test_view_rejects_unlisted_target_tu`；断言完整性与来源失败时绝不创建视图。
- [ ] **Step 2: 运行测试并确认失败。** `python -m pytest tests/test_build_context_view.py tests/test_context_package.py -q`。
- [ ] **Step 3: 实现受信视图。** 调用既有 `read_package()` 后再按规范路径、长度和文件字节 SHA-256 验证完整包；检查快照与范围绑定、文件覆盖冲突和路径逃逸。只为已声明 TU 建立只读映射，不写入原仓库。
- [ ] **Step 4: 运行回归。** `python -m pytest tests/test_build_context_view.py tests/test_context_package.py -q`，预期通过。
- [ ] **Step 5: 单独提交。** 只暂存新建视图及其测试，提交信息建议 `feat: verify repository build artifacts`。

### Task 4B: facts、repro 与 Specialist 共同消费 TU 上下文

**Files:**
- Modify: `lima/cxx_memory.py`、`cxx_analyzer/build_context.py`、`cxx_analyzer/server.py`、`lima/agent_orchestrator.py`
- Test: `tests/test_cxx_memory.py`、`tests/test_agent_orchestrator.py`，以及 `cxx_analyzer` 现有 build-context/server 对应测试

**Interfaces:**
- Consumes: Task 4A 的 `VerifiedBuildArtifact`、`AnalysisContextView.flags_for_tu(tu: str) -> tuple[str, ...]`。
- Produces: Sidecar 明确的 `verified-package` 构建上下文模式和包视图引用；facts、repro、Specialist 从同一视图读取 TU 参数，逐个目标 TU 记录 Clang 解析检查及 `tu_context_hash`。既有 `snapshot-compdb`/`heuristic` 语义保持不变。

- [ ] **Step 0: 保护已有改动。** 核查 `lima/agent_orchestrator.py` 和 `tests/test_agent_orchestrator.py` 的未提交 Discovery 窗口调整，采用单独提交或独立工作树；若仍共享工作区，逐块暂存并审核提交 diff，避免混入本任务。
- [ ] **Step 1: 写失败测试。** `test_all_target_tus_checked`、`test_facts_repro_specialist_share_sanitized_flags`、`test_response_file_and_plugin_flag_rejected`、`test_heuristic_never_reports_resolved`；对每个目标 TU 断言消费者参数一致、危险 flag 被拒绝且 `tu_context_hash` 单独记录。
- [ ] **Step 2: 运行目标测试并确认失败。** `python -m pytest tests/test_cxx_memory.py tests/test_agent_orchestrator.py -q`，加跑 `cxx_analyzer` 现有 build-context/server 对应测试。
- [ ] **Step 3: 接入消费者。** 为 Sidecar 增加经校验包视图输入；让 facts、repro、Specialist 使用同一 TU 参数投影，逐个目标 TU 做真实 Clang 检查。不把包 hash 与 TU hash 混同；不把现有 `heuristic` 重命名成 resolved。
- [ ] **Step 4: 运行回归与 Clang 小夹具。** `python -m pytest tests/test_build_context_view.py tests/test_cxx_memory.py tests/test_agent_orchestrator.py -q`，以及 `cxx_analyzer` 现有测试；预期全部目标 TU 检查通过，危险输入明确失败。
- [ ] **Step 5: 单独提交。** 仅提交本任务消费者及测试改动，提交信息建议 `feat: share verified tu flags across cxx stages`。

### Task 5: 服务端调度、任务配置与前端可见性

**Files:**
- Modify: `lima/service.py`、`lima/repository_scanner.py`、`lima/config.py`、`lima/task_progress.py`、`lima/store.py`、`lima/postgres_store.py`、`lima/task_queue.py`、`lima/api.py`、`frontend/src/features/audit-create/AuditCreatePage.tsx`、`frontend/src/features/tasks/TaskDetailPage.tsx`
- Test: `tests/test_service.py`、`tests/test_repository_scan_integration.py`、`tests/test_repository_scan_cancellation.py`、`tests/test_task_progress.py`、`frontend/src/features/audit-create/AuditCreatePage.test.tsx`、`frontend/src/features/tasks/TaskDetail.report.test.tsx`

**Interfaces:**
- Consumes: `BuildAgent.run(...)`、`BuildResult`、`AnalysisContextView`。
- Produces: 创建任务时在 `task_input` 和队列消息中冻结 `build_agent_mode: Literal['off','auto','required']`、组件/TU 范围及预算引用；SQLite `TaskStore` 与 Postgres `PostgresTaskStore` 持久化 BuildResult 摘要和进度，日志只存 Task 1 的产物根目录相对引用。`Settings` 提供受控产物根目录、保留天数和 build 并发额度。任务详情提供构建状态、尝试、产物摘要、覆盖缺口、失败码和授权证据链接；现有取消位经 service 传给 Worker。

- [ ] **Step 0: 冻结队列裁定。** 只读核对 `TaskQueue` 的 Redis lease heartbeat/reclaim 和内存执行器、`_enqueue_scan_task` 的任务快照、`_scan_progress_tracker`、两个 Store 的进度/取消写入；在本任务提交说明写清长构建的 worker 隔离与重启语义。首期沿用现有任务队列与租约心跳，同时为 build 阶段设置独立执行容量与非阻塞准入，防止等待 build 名额的任务占满扫描 worker。Redis 模式在重新领取消息后先核对 checkpoint 和副作用才恢复；内存模式仅保证浏览器断开后同一服务进程内继续，不能承诺服务进程重启恢复。
- [ ] **Step 1: 写失败测试。** `off` 保持当前路径；`auto` 构建失败仍可静态扫描但展示缺口；`required` 拒绝进入依赖上下文的阶段；浏览器断开任务继续；取消后资源清理；Redis 重领任务不重复发布包或重放不可确认步骤；SQLite/Postgres 的任务快照与构建状态一致。前端测试断言创建字段与进度/失败详情可见。
- [ ] **Step 2: 运行目标测试并确认失败。** `python -m pytest tests/test_service.py tests/test_repository_scan_integration.py tests/test_repository_scan_cancellation.py tests/test_task_progress.py -q`；前端按 `frontend/package.json` 的测试脚本运行两个组件测试，记录精确命令。
- [ ] **Step 3: 接入服务。** 在 `_execute_repository_scan` 固定快照建立后触发 Build Agent；沿用 `TaskQueue` 投递、`TaskProgress` 阶段更新和两个 Store 的任务快照/结果，增加 build 并发额度与受控产物根目录。扫描器从受信视图消费包上下文；API 只返回授权租户可读取的相对证据引用。前端配置模式、范围与预算并显示状态，不由浏览器维持执行。
- [ ] **Step 4: 运行服务和前端回归。** 定向测试通过后执行仓库规定的后端测试与前端 typecheck/build；确认旧任务与默认 `off` 行为兼容，并分别记录 Redis/内存模式的重启验收结论。
- [ ] **Step 5: 单独提交。** 只暂存本任务涉及文件，提交信息建议 `feat: expose build agent in repository scans`。

### Task 6: 端到端真实试点与使用说明

**Files:**
- Create: `docs/BUILD_AGENT_USER_FLOW.md`、`tests/fixtures/build_agent_cmake/`（最小 CMake 仓库）
- Modify: `docs/CONTAINER_BUILD_GUIDE.md`、`README.md` 中涉及自动构建的实际入口说明
- Test: `tests/test_build_agent_e2e.py`

**Interfaces:**
- Consumes: Task 1–5 的任务 API、`BuildResult`、只读分析视图与 PoC repro 容器接口。
- Produces: 可复现的夹具验收记录，以及冻结真实试点的快照、目标 TU、镜像/依赖摘要、日志、覆盖率和结论。文档说明用户何时提交仓库、何时产生构建配方、容器是否复用、PoC 如何在新的隔离容器执行。真实试点前置条件是 Docker Desktop/Linux Worker 可用，且 `docker info` 报告 Linux 容器；fake runner 测试不依赖 Docker daemon。

- [ ] **Step 1: 写端到端失败测试。** 小型 CMake 夹具从提交任务到包消费、facts/repro/Specialist、PoC 隔离执行与报告可见全链通过；缺依赖、恶意 README、缺目标 TU 和 `unsupported-build-system` 得到明确失败/缺口，不冒充成功。
- [ ] **Step 2: 运行夹具测试并确认失败。** `python -m pytest tests/test_build_agent_e2e.py -q`。
- [ ] **Step 3: 补齐端到端适配与文档。** 固定真实试点的仓库 commit、组件、TU、预算、依赖与镜像摘要；PoC 使用新容器和同一受信 TU 上下文，不复用构建容器的可写层。配方可由 Agent 生成候选并被策略校验，不要求普通用户预先编写。
- [ ] **Step 4: 验收并留证。** 先运行 `docker info` 并记录 daemon、Linux 容器模式、镜像和资源限制；若 daemon 未启动，先启动 Docker Desktop/Linux Worker，再运行真实试点。夹具与安全负例通过；真实 Docker 试点至少一项冻结目标在无人逐条输入命令的情况下完成上下文构建并被下游消费。记录 `compile_commands.json` 条目数、目标 TU 可解析率、Clang 检查结果、人工介入、时间和费用。若使用已知漏洞对照，脆弱版同一 PoC 3/3 触发、修复版 0/3，且正常功能回归；没有发现不得写成安全证明。
- [ ] **Step 5: 单独提交。** 仅提交通用夹具与文档；真实仓库专用配方、路径、日志中的私有信息和依赖缓存留在本地，提交信息建议 `test: verify build agent handoff end to end`。

## 完成定义

用户只需选择仓库快照、组件/TU 范围与构建模式后提交任务。对支持范围内的目标，LIMA 自动规划、受控执行、校验并交接上下文，随后完成检测和独立容器 PoC 验证；每一步都有可查状态和证据。失败时说明停止原因、已覆盖范围及人工需要处理的具体阻塞。首期验收不以生成 Dockerfile 或 `compile_commands.json` 本身为终点，而以目标 TU 被下游真实消费为终点。
