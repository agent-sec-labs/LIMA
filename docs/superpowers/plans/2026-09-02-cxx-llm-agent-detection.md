# C/C++ 大模型多 Agent 内存漏洞检测实施计划

> **给后续开发模型：** 必须逐任务执行本计划并维护复选框和进度台账。若运行环境提供
> `superpowers:subagent-driven-development`，优先使用它；否则使用
> `superpowers:executing-plans`；两者均不可用时，也必须遵守本文的逐任务 TDD、独立复审、门禁和交接要求。

**目标：** 先关闭现有 C/C++ Sidecar 的七项安全审查问题，再为整仓和 GitHub PR 增加真正由外部大模型阅读代码、由多 Agent 协作检测 CWE-125/415/416/787 的流程。

**架构：** 在可信仓库快照上建立有界 C/C++ 上下文索引和无标签候选检索，复用 LIMA 的 CollaborationBus、AgentRuntime、重试和消息持久化，依次执行 Planner、独立 Specialist、Critic、Evidence、Verifier 和 Arbiter。Semgrep、Clang 和 ASan 仅在 Evidence 阶段出现；所有模型输出重新绑定快照并按严格 Schema 校验。

**技术栈：** Python 3.11、`unittest`、OpenAI Chat Completions 兼容 API、现有 LIMA AgentRuntime/TaskStore、Docker Compose、Semgrep、Clang Static Analyzer、ASan、GitHub REST API。

**设计依据：** `docs/superpowers/specs/2026-09-02-cxx-llm-agent-detection-design.md`

## 执行前必读

1. 先完整阅读设计文档，再阅读本计划的全局约束、文件地图和当前进度，不得只读取当前任务。
2. 一次只实施一个 Task。每个 Task 必须经历 RED、最小实现、GREEN、相关回归、独立复审、提交和台账更新。
3. 后续模型不得自行改变已确认的模式语义、验证等级、Agent 顺序、外部源码读取范围或“不自动修复”策略；需要变更时先暂停并请求用户确认。
4. 本计划中的函数签名是跨任务合同。若仓库真实接口要求调整，必须在同一个提交中同步更新设计、计划、测试和调用方，并在台账记录原因。
5. 测试通过只证明测试覆盖的边界。没有实际执行 Docker/Linux、真实 Clang/ASan 或真实外部模型时，交接报告必须明确写“未验证”。

## 全局约束

- 起点必须是已推送的 `codex/cxx-memory-detection-impl` 提交 `2e69f3ce56f80b91e4b180ab0556100d3e173e4f`；创建隔离 worktree 和新分支 `codex/cxx-llm-agent-detection`。
- 根 `Dockerfile` 与 `tests/test_service.py` 是用户的未提交修改；任何任务不得暂存、覆盖或提交它们。
- 第一阶段必须关闭现有七项 residual 并通过独立复审；未通过不得开始 Task 8。
- C/C++ Agent 第一版只覆盖 CWE-125、CWE-415、CWE-416、CWE-787。
- C/C++ `automatic_repair` 恒为 `false`；SafeFixer、预览、Web 和 GitHub 修复均不得放行。
- Agent 模式严格为 `off | auto | required`；工具模式继续由 `LIMA_CXX_MEMORY_MODE` 独立控制。
- Specialist 初始阶段不得看到其他 Agent 输出或 Semgrep/Clang/ASan Finding。
- `diff-only` 和单 Agent 结果最高只能是 `llm-candidate`。
- 外部模型可读取预算内源码片段；不得发送 `.env`、凭据、环境变量、数据库内容或仓库外文件。
- 模型输出、源码、工具输出和 Agent 消息均视为不可信数据；不能成为未经校验的命令、路径或 URL。
- 所有预算是任务总预算，不能为每个 Agent 重置。
- Agent 消息按现有 CollaborationBus/TaskStore 策略持久化，不新增独立过期或脱敏机制，不保存隐藏思维链。
- 所有新增行为必须有先失败的 RED 测试；每个任务提交前运行该任务覆盖测试。
- 每个任务创建独立、Signed-off-by、Conventional Commit；禁止 amend/rebase 已推送历史。
- 禁止使用 `git add .`、`git add -A` 或目录级暂存可能包含用户修改的路径；必须显式暂存文件并用 `git diff --cached --name-only` 复核。
- Docker、Linux、真实模型或联网评测未实际运行时必须写“未验证”。

## 文件地图

### 新文件

- `lima/cxx_agent_models.py`：C/C++ Agent 数据合同。
- `lima/cxx_context.py`：可信快照上的符号/调用/资源索引。
- `lima/cxx_retrieval.py`：整仓和 PR 候选检索。
- `lima/cxx_agent_tools.py`：有界只读 Agent 工具。
- `lima/cxx_llm.py`：严格 C/C++ LLM 请求/响应。
- `lima/cxx_agents.py`：多 Agent 编排和验证状态机。
- `lima/github_source.py`：固定 GitHub commit 源码获取。
- `tests/test_cxx_agent_models.py`
- `tests/test_cxx_context.py`
- `tests/test_cxx_retrieval.py`
- `tests/test_cxx_agent_tools.py`
- `tests/test_cxx_llm.py`
- `tests/test_cxx_agents.py`
- `tests/test_cxx_agent_integration.py`
- `evaluation_data/cxx_llm_agent_cases.json`
- `scripts/run_cxx_llm_agent_evaluation.py`
- `docs/CXX_LLM_AGENT_ANALYSIS.md`

### 修改文件

- `cxx_analyzer/*`、`lima/cxx_memory.py`：先关闭七项工具证据 residual。
- `lima/config.py`、`.env.example`、`docker-compose.yml`：Agent 模式和总预算。
- `lima/models.py`：Agent Finding/Evidence 元数据。
- `lima/agents.py`、`lima/runtime.py`：复用但不破坏现有 Diff reviewer。
- `lima/repository_scanner.py`：整仓 Agent 入口。
- `lima/service.py`：依赖装配、PR 入口、capabilities。
- GitHub client/webhook 模块：固定 head SHA 上下文。
- `lima/report.py`、`web/app.js`：报告展示与禁止修复。
- `.github/workflows/ci.yml`、`README.md`：验证、部署和真实模型评测说明。

---

## 当前进度台账

更新时间：2026-09-02。

| 项目 | 当前状态 | 证据或下一步 |
|---|---|---|
| 既有 C/C++ Sidecar 实现 | 已完成并推送，但复审未通过 | `codex/cxx-memory-detection-impl`，`2e69f3ce56f80b91e4b180ab0556100d3e173e4f` |
| 本设计文档 | 已提交 | 提交 `08c9a2a docs: specify C++ LLM agent detection`（位于 `codex/cxx-memory-detection-impl` 本地，未推送） |
| 本实施计划 | 已提交 | 同上；分支 `codex/cxx-llm-agent-detection` 自 `08c9a2a` 创建（即 `2e69f3c` + 文档提交，偏差已在此记录） |
| 阶段 A：Sidecar 七项复审问题 | 未开始（Task 0 基线修复已完成） | 从 Task 1 开始；Task 1–7 全部复审通过后才能进入阶段 B |
| 阶段 B：大模型多 Agent 检测 | 未开始 | Task 8–21；依赖阶段 A 门禁 |
| Docker/Linux 安全验证 | 未验证 | Docker Desktop Linux daemon 可用后执行 Task 21 |
| 真实 Clang/ASan 验证 | 未验证 | 依赖 Sidecar 容器环境 |
| 真实外部模型验收 | 未验证 | 依赖用户提供/允许使用的现有 LIMA Provider 配置 |

### 基线调查记录（2026-09-02，Task 0 之前）

基线全量宿主测试（`python -m unittest discover -s tests`）在 `08c9a2a` 上失败 1 项：
`test_cxx_analyzer.SourceScanContainerTests.test_fixture_manifest_is_complete_and_semgrep_marks_only_candidates`。
根因调查结论（两项 semgrep 行为，均有实测证据）：

1. **生产级缺陷（Task 0 修复）**：`run_source_scan` 把规则文件暂存在快照 scratch（绝对路径、不在
   cwd 下），semgrep（含 Docker 固定的 1.130.0）默认给 `check_id` 加 config 路径前缀（如
   `work.snapshots...cxx.source.oob-write.constant-index`），`parse_semgrep_json._rule_cwe` 只接受
   裸 `cxx.source.*` → 必然拒绝 → **source-only 层在 semgrep 1.130 下永远产不出 Finding**。此前未暴露
   的原因：Docker/Linux 端到端从未实际运行（台账本就记为“未验证”）。
   修复：semgrep 调用加 `--no-rewrite-rule-ids`；同步更新宿主回归测试调用、argv 合同测试与索引。
2. **宿主环境问题**：semgrep 在仓库无 `.semgrepignore` 时套用内置默认忽略表（含 `tests/` 等模式），
   静默排除 `tests/fixtures/cxx_memory` 全部文件。修复：提交根 `.semgrepignore`（内容仅
   `.git/ node_modules/ vendor/ .venv/ __pycache__/`）。该文件不在快照清单扩展名集合内，不会进入
   sidecar 快照，对生产行为无影响（reviewer 已验证）。
3. **观察项（未修复，留给阶段 A 复审裁决）**：生产快照内没有 `.semgrepignore`，semgrep 默认忽略表
   会在真实扫描中静默跳过名为 `tests/`、`test/`、`doc/` 等目录的 C/C++ 文件，而 coverage 仍按清单
   计数——覆盖声称与实际扫描存在偏差的可能。是否在 Task 7 工具链审计中处理待复审裁决。

宿主环境备注：测试 venv 需 `semgrep==1.130.0` + `setuptools<81`（Python 3.13 无 pkg_resources）；
semgrep 对 git linked worktree 的目录枚举有缺陷（扫描目标为目录时恒 0 文件），因此宿主全量测试在
`D:\Projects\LIMA-test-mirror`（同分支独立 clone）中执行，开发提交仍在
`D:\Projects\LIMA\.worktrees\cxx-llm-agent-detection`。

```text
Task 0 | 复审通过 | commits 08c9a2a..（见 git log） | RED: 基线 test_fixture_manifest... 失败（rule id outside narrow set / 路径反斜杠拒绝） | GREEN: 镜像中 python -m unittest discover -s tests → Ran 328 tests, OK (skipped=11) | reviewer: 通过（修复一处 Important 陈旧索引 [4]→[5] 后；.semgrepignore 需随提交）
```

```text
Task 1 | 复审通过 | commits b54c051..(见 git log) | RED: 容器 python -m unittest tests.test_cxx_final_fixes.ProcessIsolationTests -v → 3 failures（不可信工具经 prlimit64 成功修改父进程 RLIMIT_NOFILE；并发现基线 Linux 既有失败 test_stream_timeout_kills_group_after_leader_exits_and_hashes_to_eof：leader 提前退出时立即杀组会截断后代输出，属 Docker/Linux 从未运行过的既有缺陷，一并修复） | GREEN: 容器 tests.test_cxx_final_fixes+test_cxx_analyzer 91 OK (3 skip)；容器全量 329 OK (3 skip)；宿主全量 329 OK (12 skip)；ruff 通过 | reviewer: 修复后通过（C1 aarch64 clone3 436→435 修正为 asm-generic 编号；I1 clone3 返回 ENOSYS 供 glibc≥2.34 回退 clone；I2 增加 self-prlimit64 放行与 clone3=ENOSYS 正向断言；M1 组 SIGKILL 提前到收割 leader 之前消除 PID 复用窗口；M4 删除死代码 _linux_group_exists；M5 guarded None 检查）
```

Task 1 补充记录：`cxx_analyzer/Dockerfile` 未改动——Compose 已配置 `init: true`（tini 作为 PID 1），且本修复在分析器进程内安装 `PR_SET_CHILD_SUBREAPER` 并由 `terminate_execution_boundary` 用 `waitpid(-pgid)` 精确回收，镜像层无需变更。leader 提前退出但后代仍持有管道的工具现在会等待管道 EOF 至 step deadline 并如实报告 `timed-out`（旧行为为 `completed`），该语义变化已由基线既有测试固化并由 reviewer 确认为良性。

```text
Task 2 | 复审通过 | commits a980a71..(见 git log) | RED: python -m unittest tests.test_cxx_final_fixes.RequestDeadlineTests → TypeError: run_step() got an unexpected keyword argument 'deadline'（接口缺失；初版真实进程测试另证 step_timeout int() 截断后 SIGKILL 可即时回收、真实时钟无法构造越界场景，改按计划本意用 FakeClock+挂起进程替身确定性复现） | GREEN: 宿主全量 330 OK (12 skip)；Linux 容器全量 330 OK (3 skip)；容器 final_fixes+analyzer 三连跑均 OK；ruff 全过 | reviewer: 修复后通过（I1 cleanup 预算放弃路径 detach TemporaryDirectory finalizer 防 GC 无界 rmtree、成功路径显式 cleanup 卸载；I2 条目/时间预算移入文件内层循环防单目录海量生成文件绕过；M1 check 复用 remaining_seconds；M3 报错文案；M5 run_step→_stream_process 的 expires_at 传递断言）
```

Task 2 补充记录：`cxx_analyzer/server.py` 未改动——deadline 已在 analyze_request 入口创建并贯穿 prepare/三层/verify/cleanup，既有测试固化；文件清单中的 server.py 属保守列举。source_scan/build_scan/sanitizer_scan 的 4 个 run_step 调用点按计划规则 4 作为接口同步在同一提交传入 `deadline=active_deadline`。"request-deadline-exceeded" 诊断标识当前仅在 ToolExecution.diagnostic 可见（v1 tool-run schema 有意不透传），外部超时一致性由 504 analysis_timed_out 兜底；prepare 失败路径的清理不受 deadline 约束但受 inventory 上限间接约束（≤5000 文件/20MB），均已在代码注释/台账注明。实现过程中自纠两个缺陷：teardown 预算曾误在 stream 开始时预计算（被 step 消耗）改为使用点计算；孤儿重挂靠竞态致 timeout 模式残留僵尸，ECHILD 增加 3×10ms 有界重试。

任务状态只能填写 `未开始`、`进行中`、`受阻`、`已完成待复审` 或 `复审通过`。后续模型每完成一个
任务，必须在本节追加一行，格式如下；不得用“基本完成”“应该通过”等模糊状态：

```text
Task N | 复审通过 | commits <base>..<head> | RED: <命令与失败摘要> | GREEN: <命令与通过计数> | reviewer: <结论>
```

## 开发启动检查

以下命令从 `D:\Projects\LIMA` 执行。若目标 branch 或 worktree 已存在，不得重复创建或强制删除；
先用 `git worktree list`、`git branch --list codex/cxx-llm-agent-detection` 和 `git status --short`
确认其状态，再从台账记录的 HEAD 继续。

```powershell
git fetch origin
git worktree add D:\Projects\LIMA\.worktrees\cxx-llm-agent-detection -b codex/cxx-llm-agent-detection 2e69f3ce56f80b91e4b180ab0556100d3e173e4f
Set-Location D:\Projects\LIMA\.worktrees\cxx-llm-agent-detection
git status --short --branch
python -m unittest discover -s tests -v
git diff --check
```

预期：新 worktree 初始状态干净，HEAD 精确等于上述基线，宿主测试全部通过。任一条件不满足时，
在进度台账记录实际输出并停止 Task 1；不得通过删除文件、重置用户修改或降低测试范围绕过基线失败。

## 阶段 A — 关闭现有 Sidecar 审查问题

### Task 1: 完整回收不可信工具后代并隔离请求进程

**Files:**
- Modify: `cxx_analyzer/sandbox.py`
- Modify: `cxx_analyzer/execution.py`
- Modify: `cxx_analyzer/Dockerfile`
- Test: `tests/test_cxx_final_fixes.py`

**Interfaces:**
- Consumes: `run_step(...)`、Landlock/seccomp launcher、Compose `init: true`。
- Produces: `terminate_execution_boundary(process, *, deadline) -> CleanupResult`；成功、失败、超时都保证边界内无存活后代，并处理 PID 1 收养的孤儿。

- [x] **Step 1: 写 RED 测试**

新增 Linux 子进程用例：leader 依次尝试 `setsid`、`prlimit64` 操作父进程并派生会退出的孙进程；分别覆盖 leader 返回 0、返回 1、超时。断言父服务限制未改变、所有后代消失且无 zombie。

```python
def test_success_failure_timeout_cannot_escape_or_leave_zombies():
    for mode in ("success", "failure", "timeout"):
        result = run_untrusted_process_tree(mode)
        assert result.parent_limits_unchanged
        assert result.live_descendants == []
        assert result.zombie_descendants == []
```

- [x] **Step 2: 运行 RED**

Run: `python -m unittest tests.test_cxx_final_fixes.ProcessIsolationTests -v`
Expected: FAIL，至少证明 `prlimit64` 或 orphan/zombie 场景未被当前实现阻止。

- [x] **Step 3: 实现可证明的执行边界**

使用容器内可用的 PID namespace/init 监督方式或严格 cgroup/supervisor；若运行环境缺少所需内核能力则 fail closed。seccomp 同时拒绝逃逸进程组和同 UID 进程控制系统调用。所有 leader 退出路径进入同一清理函数，不能只等待 leader PID。

- [x] **Step 4: 运行 GREEN 与回归**

Run: `python -m unittest tests.test_cxx_final_fixes.ProcessIsolationTests tests.test_cxx_analyzer -v`
Expected: PASS；Windows 上 Linux-only 用例只允许以明确平台原因 skip。

- [x] **Step 5: 提交**

```powershell
git add cxx_analyzer/sandbox.py cxx_analyzer/execution.py cxx_analyzer/Dockerfile tests/test_cxx_final_fixes.py
git commit -s -m "fix: contain C++ analyzer process trees"
```

### Task 2: 统一严格请求 deadline，包括终止、drain 和清理

**Files:**
- Modify: `cxx_analyzer/deadline.py`
- Modify: `cxx_analyzer/execution.py`
- Modify: `cxx_analyzer/snapshot.py`
- Modify: `cxx_analyzer/server.py`
- Test: `tests/test_cxx_final_fixes.py`

**Interfaces:**
- Consumes: `RequestDeadline`。
- Produces: `remaining_seconds(stage: str) -> float` 和 deadline-aware、受条目/字节/时间限制的清理；超过预算后以隔离边界销毁请求资源，不进行无限递归遍历。

- [x] **Step 1: 写 RED 测试**

```python
def test_request_deadline_includes_termination_drain_and_cleanup():
    clock = FakeClock()
    result = analyze_with_slow_process_and_cleanup(clock, total=5.0)
    assert result.elapsed <= 5.0 + TEST_SCHEDULER_TOLERANCE
    assert result.diagnostic == "request-deadline-exceeded"
```

- [x] **Step 2: 运行 RED**

Run: `python -m unittest tests.test_cxx_final_fixes.RequestDeadlineTests -v`
Expected: FAIL，当前 grace/drain/cleanup 越过 deadline。

- [x] **Step 3: 贯通单一 deadline**

从 HTTP handler 接收请求时创建唯一绝对 deadline，snapshot/source/build/ASan/termination/drain/cleanup 只消费该对象。不得创建新的完整总预算。清理采用请求私有根和有界删除；无法在 deadline 内完成时由已验证的隔离容器边界回收。

- [x] **Step 4: 运行 GREEN**

Run: `python -m unittest tests.test_cxx_final_fixes.RequestDeadlineTests tests.test_cxx_analyzer -v`
Expected: PASS。

- [x] **Step 5: 提交**

```powershell
git add cxx_analyzer/deadline.py cxx_analyzer/execution.py cxx_analyzer/snapshot.py cxx_analyzer/server.py tests/test_cxx_final_fixes.py
git commit -s -m "fix: enforce one C++ request deadline"
```

### Task 3: 将 Finding 绑定到具体 tool-run 并统一预算

**Files:**
- Modify: `cxx_analyzer/protocol.py`
- Modify: `cxx_analyzer/normalizers.py`
- Modify: `cxx_analyzer/source_scan.py`
- Modify: `cxx_analyzer/build_scan.py`
- Modify: `cxx_analyzer/sanitizer_scan.py`
- Modify: `cxx_analyzer/server.py`
- Modify: `lima/cxx_memory.py`
- Test: `tests/test_cxx_final_fixes.py`
- Test: `tests/test_cxx_memory.py`

**Interfaces:**
- Produces: 每个 tool-run 有不可重复 `run_id`；每个 Finding 有非空 `producer_run_ids: list[str]`；客户端验证引用存在、tool/layer 匹配且被保留。

- [ ] **Step 1: 写 RED 测试**

构造两个 `clang` 和两个 `asan-test` run，只有第二个产生 Finding，随后触发响应预算截断。断言不得保留错误 run，也不得留下无 producer 的 Finding。

```python
def test_budget_preserves_exact_producer_runs():
    response = budget_response(two_clang_runs=True, two_asan_runs=True)
    for finding in response["findings"]:
        assert set(finding["producer_run_ids"]) <= {
            run["run_id"] for run in response["tool_runs"]
        }
```

- [ ] **Step 2: 运行 RED**

Run: `python -m unittest tests.test_cxx_final_fixes.ToolRunBindingTests tests.test_cxx_memory -v`
Expected: FAIL，当前按 tool/status 猜测 producing run。

- [ ] **Step 3: 实现 ID 和共同预算**

run ID 由 analyzer 生成并在单请求内唯一，不接受仓库输入。normalizer 保留各层 finding 和精确 producer。预算算法以 Finding 及其所有 producer 为不可拆分单元；无法一起保留时删除或降级 Finding。

- [ ] **Step 4: 运行 GREEN 并检查 Schema**

Run: `python -m unittest tests.test_cxx_final_fixes.ToolRunBindingTests tests.test_cxx_memory tests.test_cxx_analyzer -v`
Expected: PASS。

- [ ] **Step 5: 提交**

```powershell
git add cxx_analyzer lima/cxx_memory.py tests/test_cxx_final_fixes.py tests/test_cxx_memory.py
git commit -s -m "fix: bind C++ findings to exact tool runs"
```

### Task 4: 让 health 与 capabilities 反映真实可执行能力

**Files:**
- Modify: `cxx_analyzer/server.py`
- Modify: `lima/cxx_memory.py`
- Modify: `lima/service.py`
- Create: `tests/test_cxx_capabilities.py`
- Test: `tests/test_cxx_analyzer.py`
- Test: `tests/test_cxx_memory.py`
- Do not modify: `tests/test_service.py`，该文件存在用户未提交修改；相关回归只运行、不编辑。

**Interfaces:**
- Produces: versioned health object with `source_available`、`build_available`、`test_configured`、`clang_c_available`、`clang_cxx_available`、`cmake_available`、`landlock_available`、`process_isolation_available`。

- [ ] **Step 1: 写 RED 合同测试**

```python
def test_auto_cmake_requires_cmake_and_both_clang_drivers():
    health = health_with(tools={"clang-14": True, "clang++-14": True, "cmake": False})
    assert health["build_available"] is False
```

同时覆盖 Landlock/进程隔离不可用时 build/test 不得显示 available。

- [ ] **Step 2: 运行 RED**

Run: `python -m unittest tests.test_cxx_analyzer tests.test_cxx_memory tests.test_cxx_capabilities -v`
Expected: FAIL。

- [ ] **Step 3: 实现精确探测和安全缓存**

Sidecar health 使用执行时相同的 binary 和 kernel probe；主服务只展示已成功解析且未过期的版本化 health。连接失败时状态为 unavailable，不以 URL 非空代替健康。

- [ ] **Step 4: GREEN 与提交**

Run: `python -m unittest tests.test_cxx_analyzer tests.test_cxx_memory tests.test_cxx_capabilities -v`

```powershell
git add cxx_analyzer/server.py lima/cxx_memory.py lima/service.py tests/test_cxx_analyzer.py tests/test_cxx_memory.py tests/test_cxx_capabilities.py
git commit -s -m "fix: report executable C++ analyzer capabilities"
```

### Task 5: 完成 C/C++ Markdown 上下文编码

**Files:**
- Modify: `lima/report.py`
- Test: `tests/test_cxx_memory.py`

**Interfaces:**
- Produces: 分离的 heading/prose/inline-code/fenced-evidence 编码函数；输入只编码一次。

- [ ] **Step 1: 写 RED 测试**

覆盖 `---`、`***`、`[label](target)`、`<script>`、反引号、`&` 路径和多行 fence，解析结果不得产生额外 heading/link/HTML，显示路径仍为原字符。

```python
def test_cxx_markdown_cannot_inject_structure_or_double_escape_paths():
    rendered = render_hostile_cxx_finding(path="src/a&b.cpp", explanation="---\n[label](x)")
    assert "a&amp;amp;b.cpp" not in rendered
    assert "[label](x)" not in rendered
```

- [ ] **Step 2: RED**

Run: `python -m unittest tests.test_cxx_memory.CxxMarkdownSafetyTests -v`
Expected: FAIL。

- [ ] **Step 3: 实现按上下文编码**

prose 转义 Markdown 标记和 HTML；inline-code 自适应 delimiter 且不重复 HTML encode；evidence 使用自适应 fence 或缩进块。调用者保存原始 path，只有最终输出点编码。

- [ ] **Step 4: GREEN 与提交**

Run: `python -m unittest tests.test_cxx_memory -v`

```powershell
git add lima/report.py tests/test_cxx_memory.py
git commit -s -m "fix: encode C++ report markdown contexts"
```

### Task 6: 对公开归档下载实施硬 deadline

**Files:**
- Modify: `scripts/run_cxx_memory_evaluation.py`
- Test: `tests/test_cxx_memory_evaluation.py`

**Interfaces:**
- Produces: 小块/非阻塞或 `read1` 循环，每次底层 read 前按绝对剩余预算设置 socket timeout；slow trickle 不能延长总 deadline。

- [ ] **Step 1: RED slow-trickle 测试**

```python
def test_slow_trickle_cannot_extend_absolute_download_deadline():
    with self.assertRaises(TimeoutError):
        download_with_fake_clock(bytes_per_tick=1, tick_seconds=1, deadline_seconds=3)
```

- [ ] **Step 2: RED**

Run: `python -m unittest tests.test_cxx_memory_evaluation.ArchiveSafetyTests -v`
Expected: FAIL 或观察一次 read 越过绝对 deadline。

- [ ] **Step 3: 实现可抢占读取**

将单次 read 控制到有界小块，底层 socket 每轮设置 `min(per_operation_timeout, remaining)`；零剩余立即失败并删除 partial。保持逐跳 HTTPS、hash、大小和 archive 安全边界。

- [ ] **Step 4: GREEN 与提交**

Run: `python -m unittest tests.test_cxx_memory_evaluation -v`

```powershell
git add scripts/run_cxx_memory_evaluation.py tests/test_cxx_memory_evaluation.py
git commit -s -m "fix: bound C++ evaluation downloads by deadline"
```

### Task 7: 固定并归档可审计 Sidecar 工具链身份

**Files:**
- Modify: `cxx_analyzer/Dockerfile`
- Modify: `.github/workflows/ci.yml`
- Modify: `scripts/run_cxx_memory_evaluation.py`
- Modify: `docs/CXX_MEMORY_ANALYSIS.md`
- Test: `tests/test_cxx_memory_evaluation.py`
- Test: `tests/test_cxx_analyzer.py`

**Interfaces:**
- Produces: 实际 image ID、base image digest、精确直接/传递 Debian 与 Python package manifest；CI 将 package manifests 与 JSON report 一起上传。

- [ ] **Step 1: RED 合同测试**

```python
def test_public_evaluation_artifact_retains_toolchain_manifests():
    workflow = load_ci_yaml()
    assert artifact_uploads(workflow) >= {
        "evaluation-report", "debian-packages", "python-packages", "image-inspect"
    }
```

- [ ] **Step 2: RED**

Run: `python -m unittest tests.test_cxx_memory_evaluation tests.test_cxx_analyzer -v`
Expected: FAIL。

- [ ] **Step 3: 实现身份闭环**

Dockerfile 使用 digest-pinned base；能够可靠固定的直接依赖使用精确版本，全部解析后的包版本在镜像内生成 manifest。CI 从宿主 `docker image inspect` 获取 ID并导出镜像/包清单，作为同一 artifact 上传。若 apt repository 不能 snapshot-pin，文档必须明确仅“可审计”而非“逐字节可复现”。

- [ ] **Step 4: 验证 Phase A**

Run:

```powershell
python -m unittest discover -s tests -v
python -m ruff check cxx_analyzer scripts/run_cxx_memory_evaluation.py
docker compose config --quiet
git diff --check 2e69f3c..HEAD
```

在 Docker Linux daemon 可用时还必须运行 Sidecar build、真实 Semgrep/Clang/ASan、集成和四 case matrix。不可用则停止在“Phase A 未获 Linux/Docker 完整证据”，不得声称前置完成。

- [ ] **Step 5: 提交并执行独立全 Phase A 审查**

```powershell
git add cxx_analyzer/Dockerfile .github/workflows/ci.yml scripts/run_cxx_memory_evaluation.py docs/CXX_MEMORY_ANALYSIS.md tests/test_cxx_memory_evaluation.py tests/test_cxx_analyzer.py
git commit -s -m "build: preserve C++ analyzer toolchain identity"
```

审查 `2e69f3c..HEAD`，逐项裁决七个 residual。任何 Critical/Important 未关闭时不得执行 Task 8。

---

## 阶段 B — C/C++ 大模型多 Agent 检测

### Task 8: 增加 Agent 配置与严格数据合同

**Files:**
- Create: `lima/cxx_agent_models.py`
- Create: `tests/test_cxx_agent_models.py`
- Modify: `lima/config.py`
- Modify: `.env.example`
- Modify: `docker-compose.yml`
- Modify: `lima/models.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Produces: `CxxAgentSettings`、`ContextReference`、`CxxAgentCandidate`、`CxxAgentDecision`、`CxxAgentCoverage`；`Settings.cxx_agent_mode` 及设计文档中的九个配置值。

- [ ] **Step 1: 写 RED Schema/配置测试**

```python
def test_cxx_agent_mode_and_total_budgets_are_strict():
    settings = Settings.from_env()
    assert settings.cxx_agent_mode in {"off", "auto", "required"}
    assert settings.cxx_agent_max_calls == 40
    assert settings.cxx_agent_max_context_lines == 1200
```

候选构造测试拒绝未知 CWE、绝对路径、零行号、未知字段和超限 `trigger_path`。

- [ ] **Step 2: RED**

Run: `python -m unittest tests.test_cxx_agent_models tests.test_config -v`
Expected: import/config failure。

- [ ] **Step 3: 实现不可变合同**

使用 frozen dataclass 或等价不可变值；提供 `from_untrusted_json` 严格构造器。扩展 Finding 时保持旧 JSON 向后兼容，新增字段默认空值，`automatic_repair=False`。

- [ ] **Step 4: GREEN 与提交**

Run: `python -m unittest tests.test_cxx_agent_models tests.test_config -v`

```powershell
git add lima/cxx_agent_models.py lima/config.py lima/models.py .env.example docker-compose.yml tests/test_cxx_agent_models.py tests/test_config.py
git commit -s -m "feat: define C++ agent contracts and budgets"
```

### Task 9: 建立有界 C/C++ 上下文索引

**Files:**
- Create: `lima/cxx_context.py`
- Create: `tests/test_cxx_context.py`
- Test fixtures: `tests/fixtures/cxx_agent_context/`

**Interfaces:**
- Produces: `CxxContextIndex.build(workspace, inventory) -> CxxContextIndex`；`symbols`、`types`、`calls`、`references`、`resource_events`、`coverage`；所有记录绑定 snapshot hash。

- [ ] **Step 1: 创建最小 C/C++ fixture 与 RED**

fixture 包含 `.c/.cpp/.hpp`、重载、成员函数、malloc/free/new/delete、数组长度和无法解析宏。测试断言限定名、行范围、caller/callee、资源事件及 parse gap。

- [ ] **Step 2: RED**

Run: `python -m unittest tests.test_cxx_context -v`
Expected: module missing。

- [ ] **Step 3: 实现确定性索引**

优先复用现有 inventory 和语言扩展映射。第一版允许保守轻量解析，但输出排序必须确定，解析失败进入 coverage，不得生成虚构调用边。

- [ ] **Step 4: GREEN 与提交**

Run: `python -m unittest tests.test_cxx_context tests.test_workspace -v`

```powershell
git add lima/cxx_context.py tests/test_cxx_context.py tests/fixtures/cxx_agent_context
git commit -s -m "feat: index bounded C++ review context"
```

### Task 10: 实现无标签整仓与 PR 候选检索

**Files:**
- Create: `lima/cxx_retrieval.py`
- Create: `tests/test_cxx_retrieval.py`

**Interfaces:**
- Produces: `retrieve_repository(index, budget) -> RetrievalRun`；`retrieve_pull_request(index, changed_lines, budget) -> RetrievalRun`；候选包含 seed reason，不包含 CVE/ground truth。

- [ ] **Step 1: RED**

测试分配/释放、边界操作、PR changed symbol 扩展、稳定排序、100 candidate/12 file/1200 line 限制，以及输入中出现 `vulnerable/fixed/CVE` 元数据不会改变排序。

- [ ] **Step 2: 运行 RED**

Run: `python -m unittest tests.test_cxx_retrieval -v`

- [ ] **Step 3: 实现检索**

候选分数只来自通用 API/语法风险、调用邻域和 PR 距离。预算在选择过程中一次性扣减；返回未覆盖候选/文件计数。

- [ ] **Step 4: GREEN 与提交**

Run: `python -m unittest tests.test_cxx_retrieval tests.test_cxx_context -v`

```powershell
git add lima/cxx_retrieval.py tests/test_cxx_retrieval.py
git commit -s -m "feat: retrieve C++ memory review candidates"
```

### Task 11: 获取绑定固定 SHA 的 GitHub PR 上下文

**Files:**
- Create: `lima/github_source.py`
- Create: `tests/test_github_source.py`
- Modify: `lima/github.py`，这是当前 `lima/service.py` 使用的 GitHub webhook/client 模块。

**Interfaces:**
- Produces: `GitHubSourceProvider.fetch(repository, commit_sha, paths, budget) -> GitHubSnapshot`；只接受 40 位 SHA，返回每文件 SHA-256。

- [ ] **Step 1: RED**

覆盖 branch/短 SHA 拒绝、路径逃逸、404/rate limit、内容超限、本地 head 匹配优先、GitHub 固定 SHA 获取及 Diff-only 降级。

- [ ] **Step 2: RED**

Run: `python -m unittest tests.test_github_source -v`

- [ ] **Step 3: 实现固定内容提供者**

使用现有 GitHub 认证/重试约束；不得记录 Authorization；响应先按预算读取再解码；只将验证后的文件交给 `RepositoryWorkspace` 等价清单逻辑。

- [ ] **Step 4: GREEN 与提交**

Run: `python -m unittest tests.test_github_source tests.test_github -v`

```powershell
git add lima/github_source.py lima/github.py tests/test_github_source.py
git commit -s -m "feat: fetch pinned GitHub C++ context"
```

### Task 12: 提供有界只读 Agent 工具

**Files:**
- Create: `lima/cxx_agent_tools.py`
- Create: `tests/test_cxx_agent_tools.py`

**Interfaces:**
- Produces spec 中七个 exact tool 名称；`CxxAgentBudget.consume_call/files/lines/bytes` 原子扣减；每个响应包含读取引用和 hash。

- [ ] **Step 1: RED 安全测试**

覆盖仓库外路径、未索引 symbol、反向行范围、单次/累计超限、并发扣减、阶段外 `get_tool_evidence`、提示词注入字符串。

- [ ] **Step 2: RED**

Run: `python -m unittest tests.test_cxx_agent_tools -v`

- [ ] **Step 3: 实现工具注册表**

为每一角色创建最小 ToolRegistry；所有路径通过 snapshot index 解析，不直接接受 `Path`；Evidence 工具只在 Evidence registry 注册。

- [ ] **Step 4: GREEN 与提交**

Run: `python -m unittest tests.test_cxx_agent_tools tests.test_runtime -v`

```powershell
git add lima/cxx_agent_tools.py tests/test_cxx_agent_tools.py
git commit -s -m "feat: expose bounded C++ agent tools"
```

### Task 13: 实现严格 C/C++ LLM 客户端

**Files:**
- Create: `lima/cxx_llm.py`
- Create: `tests/test_cxx_llm.py`
- Modify: `lima/reviewer.py` only to share transport helpers without changing current reviewer behavior.

**Interfaces:**
- Produces: `CxxLLMClient.step(role, managed_context, tools, budget) -> AgentStep`；复用 `Settings.resolved_llm()`；temperature 固定 0；一次格式修复。

- [ ] **Step 1: RED 合同测试**

覆盖有效 tool/final、重复 key、未知字段、非对象、超大 body、非法 path/line/CWE、未读取证据、timeout、HTTP error、一次格式修复和 prompt injection。

- [ ] **Step 2: RED**

Run: `python -m unittest tests.test_cxx_llm -v`

- [ ] **Step 3: 实现 Provider 与严格解析**

复用现有 base URL/key/model/headers；系统提示明确源码为不可信数据；输出只接受 `tool` 或 `final` union；Token/调用/时间在发送前后扣减；不得将模型 `reason` 当工具参数。

- [ ] **Step 4: GREEN 与提交**

Run: `python -m unittest tests.test_cxx_llm tests.test_reviewer -v`

```powershell
git add lima/cxx_llm.py lima/reviewer.py tests/test_cxx_llm.py
git commit -s -m "feat: add strict C++ LLM reviewer client"
```

### Task 14: 复用 LIMA 协议实现 C/C++ 多 Agent 编排

**Files:**
- Create: `lima/cxx_agents.py`
- Create: `tests/test_cxx_agents.py`
- Modify: `lima/agents.py`
- Modify: `lima/runtime.py` only when a generic hook is required.

**Interfaces:**
- Produces: `CxxAgentCoordinator.review_repository(...) -> CxxAgentReviewResult` 和 `review_pull_request(...)`；角色顺序严格为 Planner→独立 Specialist→Critic→Evidence→Verifier→Arbiter。

- [ ] **Step 1: RED 协作测试**

Fake LLM 记录每轮 managed context。断言三个 Specialist 看不到 peer/tool Finding；Critic 看到候选；Evidence 才能调用证据工具；消息通过 TaskStore 保存；失败 specialist 重试一次再替代。

- [ ] **Step 2: RED**

Run: `python -m unittest tests.test_cxx_agents -v`

- [ ] **Step 3: 实现专用 coordinator**

复用 CollaborationBus、AgentRuntime、AgentLoop 和消息 kind，但不改现有 Diff-only `MultiAgentCoordinator` 的 added-line verifier。C++ coordinator 使用 snapshot-bound verifier。

- [ ] **Step 4: GREEN 与提交**

Run: `python -m unittest tests.test_cxx_agents tests.test_advanced -v`

```powershell
git add lima/cxx_agents.py lima/agents.py lima/runtime.py tests/test_cxx_agents.py
git commit -s -m "feat: orchestrate C++ memory review agents"
```

### Task 15: 实现独立共识、工具印证与最终验证等级

**Files:**
- Modify: `lima/cxx_agents.py`
- Modify: `lima/cxx_agent_models.py`
- Modify: `lima/cxx_memory.py`
- Modify: `lima/models.py`
- Test: `tests/test_cxx_agents.py`
- Test: `tests/test_cxx_memory.py`

**Interfaces:**
- Produces exact states: `llm-candidate`、`agent-corroborated`、`tool-corroborated`、`runtime-confirmed`、`human-confirmed`、`needs-human-review`。

- [ ] **Step 1: RED 状态矩阵**

覆盖单 Agent、两个 Agent 仅 CWE 相同但 mechanism 不同、完整独立一致、Semgrep/Clang 同身份、ASan exact run、证据冲突、Diff-only 和人工确认。

- [ ] **Step 2: RED**

Run: `python -m unittest tests.test_cxx_agents.VerificationStateTests tests.test_cxx_memory -v`

- [ ] **Step 3: 实现一致性与 gate**

共识键至少包括 CWE/path/symbol/resource/mechanism/trigger overlap。`verified-only` 只接受设计规定的四个已验证状态；`needs-human-review` 和 `llm-candidate` 不进入 gate。所有 C/C++ 自动修复仍 false。

- [ ] **Step 4: GREEN 与提交**

Run: `python -m unittest tests.test_cxx_agents tests.test_cxx_memory tests.test_workspace -v`

```powershell
git add lima/cxx_agents.py lima/cxx_agent_models.py lima/cxx_memory.py lima/models.py tests/test_cxx_agents.py tests/test_cxx_memory.py
git commit -s -m "feat: verify C++ agent memory findings"
```

### Task 16: 接入整仓扫描

**Files:**
- Modify: `lima/repository_scanner.py`
- Modify: `lima/service.py`
- Create: `tests/test_cxx_agent_integration.py`
- Modify: `tests/test_workspace.py`

**Interfaces:**
- Consumes: workspace inventory、CxxContextIndex、retriever、coordinator、Sidecar evidence。
- Produces: 一个融合 ReviewReport；`collaboration.cxx_agent` 保存模式、模型、上下文、预算、coverage 和 Agent 统计。

- [ ] **Step 1: RED Fake-LLM 端到端**

构造整仓 UAF 与安全版本；断言真实代码片段进入模型、工具证据只在 Evidence 阶段、Finding 绑定快照、报告持久化且安全版本不被强行判漏洞。

- [ ] **Step 2: RED**

Run: `python -m unittest tests.test_cxx_agent_integration.RepositoryAgentTests -v`

- [ ] **Step 3: 接入扫描器**

索引只构建一次；传统扫描与 LLM 分支共享同一 inventory；`off/auto/required` 按规范决定任务状态；取消任务时停止后续模型调用。

- [ ] **Step 4: GREEN 与提交**

Run: `python -m unittest tests.test_cxx_agent_integration.RepositoryAgentTests tests.test_workspace tests.test_service -v`

```powershell
git add lima/repository_scanner.py lima/service.py tests/test_cxx_agent_integration.py tests/test_workspace.py
git commit -s -m "feat: run C++ agents on imported repositories"
```

### Task 17: 接入 GitHub PR 与固定 head SHA 上下文

**Files:**
- Modify: `lima/service.py`
- Modify: `lima/github.py`
- Modify: `lima/cxx_agents.py`
- Modify: `tests/test_cxx_agent_integration.py`
- Modify: `tests/test_github.py`

**Interfaces:**
- Produces: context scope `repository | pr-context | diff-only`；任务输入保存 base/head SHA 和 source manifest hash。

- [ ] **Step 1: RED PR 端到端**

覆盖本地 repo head 匹配、head 不匹配后 GitHub pinned fetch、GitHub 失败后的 Diff-only、非 C/C++ PR 不调用 C++ Agent、Diff-only 不得升级。

- [ ] **Step 2: RED**

Run: `python -m unittest tests.test_cxx_agent_integration.PullRequestAgentTests tests.test_github -v`

- [ ] **Step 3: 接入现有 PR task**

从 webhook 已验证 payload 取得完整 head SHA；代码上下文和 diff 都绑定任务。不得用 PR ref 或默认分支替代 head SHA。C++ Agent Finding 可绑定触发行和根因行，但 gate 规则保持不变。

- [ ] **Step 4: GREEN 与提交**

Run: `python -m unittest tests.test_cxx_agent_integration tests.test_github tests.test_service -v`

```powershell
git add lima/service.py lima/github.py lima/cxx_agents.py tests/test_cxx_agent_integration.py tests/test_github.py
git commit -s -m "feat: review C++ pull requests with agents"
```

### Task 18: 持久化、报告、Web 与 capabilities

**Files:**
- Modify: `lima/agents.py`
- Modify: `lima/store.py`
- Modify: `lima/report.py`
- Modify: `lima/service.py`
- Modify: `web/app.js`
- Modify: `tests/test_frontend_ui.py`
- Modify: `tests/test_cxx_agent_integration.py`

**Interfaces:**
- Produces: spec 第 12 节全部字段；沿用 Agent message storage；capabilities 返回 `cxx_agent` 对象。

- [ ] **Step 1: RED 报告/持久化测试**

断言 Planner/Specialist/Critic/Evidence/Verifier/Arbiter 消息可查询；报告包含 provider/model/prompt/context/hash/token/coverage/degradation；Web 禁止 C/C++ 修复按钮。

- [ ] **Step 2: RED**

Run: `python -m unittest tests.test_cxx_agent_integration.ReportTests tests.test_frontend_ui -v`

- [ ] **Step 3: 实现显示和 capabilities**

复用现有 TaskStore，不建平行消息库。Markdown/Web 对不可信字段使用正确上下文编码。capabilities 的 configured/healthy 分开，Provider 未探测时不宣称 healthy。

- [ ] **Step 4: GREEN 与提交**

Run: `python -m unittest tests.test_cxx_agent_integration tests.test_frontend_ui tests.test_service -v`

```powershell
git add lima/agents.py lima/store.py lima/report.py lima/service.py web/app.js tests/test_frontend_ui.py tests/test_cxx_agent_integration.py
git commit -s -m "feat: report C++ agent collaboration evidence"
```

### Task 19: 锁定模式、预算、错误和攻击面

**Files:**
- Modify: `lima/cxx_agent_tools.py`
- Modify: `lima/cxx_llm.py`
- Modify: `lima/cxx_agents.py`
- Modify: `lima/service.py`
- Modify: `tests/test_cxx_agent_tools.py`
- Modify: `tests/test_cxx_llm.py`
- Modify: `tests/test_cxx_agent_integration.py`

**Interfaces:**
- Produces: 全任务共享 budget ledger；mode outcome；`llm-unavailable`、`budget-exhausted`、`context-truncated` 等有界诊断。

- [ ] **Step 1: RED 攻击/故障矩阵**

覆盖源码注释提示词注入、模型请求任意工具、跨仓库 path、工具参数超限、并发预算竞争、Provider 超时/429/5xx、全部 specialist 失败、Critic/Verifier/Arbiter 失败、取消任务。

- [ ] **Step 2: RED**

Run: `python -m unittest tests.test_cxx_agent_tools tests.test_cxx_llm tests.test_cxx_agent_integration.FailureModeTests -v`

- [ ] **Step 3: 实现 fail-closed 结果**

`required` 关键阶段失败使任务 FAILED；`auto` 仅在允许点降级并写 diagnostic；格式修复最多一次；达到任一总预算立即停止新调用。任何失败不得提升验证状态。

- [ ] **Step 4: GREEN 与提交**

Run: `python -m unittest tests.test_cxx_agent_tools tests.test_cxx_llm tests.test_cxx_agents tests.test_cxx_agent_integration -v`

```powershell
git add lima/cxx_agent_tools.py lima/cxx_llm.py lima/cxx_agents.py lima/service.py tests/test_cxx_agent_tools.py tests/test_cxx_llm.py tests/test_cxx_agent_integration.py
git commit -s -m "fix: enforce C++ agent trust and budget boundaries"
```

### Task 20: 建立无标签评测、CI 和使用文档

**Files:**
- Create: `evaluation_data/cxx_llm_agent_cases.json`
- Create: `scripts/run_cxx_llm_agent_evaluation.py`
- Create: `docs/CXX_LLM_AGENT_ANALYSIS.md`
- Create: `tests/test_cxx_llm_agent_evaluation.py`
- Modify: `.github/workflows/ci.yml`
- Modify: `README.md`
- Modify: `THIRD_PARTY_NOTICES.md` when new external metadata requires attribution.

**Interfaces:**
- Produces: 固定 vulnerable/fixed 对、可重算 metrics、手动/定时真实模型 job；普通 PR 只跑 Fake-LLM 合同测试。

- [ ] **Step 1: RED Schema/公平性/指标测试**

断言 exact commits/archive hashes/licenses、无标签 retrieval input、零分母 null+diagnostic、TP/FP/FN/TN/F1/pairwise/token/cost/latency/coverage 可由 revision records 重算。

- [ ] **Step 2: RED**

Run: `python -m unittest tests.test_cxx_llm_agent_evaluation -v`

- [ ] **Step 3: 实现评测与文档**

真实模型 job 从 secret 读取现有 Provider key，固定模型和 prompt hash，上传原始结构化结果及身份清单。文档说明外部模型会读取代码、两种入口、模式、费用、隐私、状态、门禁、禁止修复和局限。

- [ ] **Step 4: GREEN 与提交**

Run:

```powershell
python -m unittest tests.test_cxx_llm_agent_evaluation tests.test_cxx_agent_integration -v
python -c "import json; json.load(open('evaluation_data/cxx_llm_agent_cases.json', encoding='utf-8'))"
docker compose config --quiet
```

```powershell
git add evaluation_data/cxx_llm_agent_cases.json scripts/run_cxx_llm_agent_evaluation.py docs/CXX_LLM_AGENT_ANALYSIS.md tests/test_cxx_llm_agent_evaluation.py .github/workflows/ci.yml README.md THIRD_PARTY_NOTICES.md
git commit -s -m "test: evaluate C++ LLM agent detection"
```

### Task 21: 最终验证、审查与交接

**Files:**
- Modify only defects found by final review; no opportunistic refactor.
- Create: `.superpowers/sdd/2026-09-02-cxx-llm-agent-detection/final-report.md` as ignored execution evidence.

**Interfaces:**
- Produces: 可供验收的 commit range、测试证据、真实/未验证边界和 GitHub 分支。

- [ ] **Step 1: 干净 HEAD 验证**

在临时 detached worktree 上运行：

```powershell
python -m unittest discover -s tests -v
python -m ruff check lima/cxx_agent_models.py lima/cxx_context.py lima/cxx_retrieval.py lima/cxx_agent_tools.py lima/cxx_llm.py lima/cxx_agents.py lima/github_source.py scripts/run_cxx_llm_agent_evaluation.py
node --check web/app.js
docker compose config --quiet
git diff --check 2e69f3c..HEAD
```

- [ ] **Step 2: Linux/Docker 验证**

构建 Sidecar/LIMA，运行 Landlock/process/deadline、真实 Semgrep/Clang/ASan、整仓 Fake LLM、PR Fake LLM 和公开版本对。如果 Docker 不可用，最终状态不得写 complete/merge-ready。

- [ ] **Step 3: 真实模型最小验收**

在用户授权的 Provider 上至少运行一个 vulnerable/fixed pair 和一个 PR case，证明 `required` 发生真实调用、`auto` 降级、消息/Token/上下文持久化以及单 Agent 不进门禁。不得以 Fake LLM 代替。

- [ ] **Step 4: 全分支独立审查**

review range 为 `2e69f3c..HEAD`。reviewer 必须读取 spec、plan、每任务报告和完整 diff，逐项检查 Global Constraints、七项前置 residual、整仓/PR、Agent 独立性、严格 Schema、预算、状态、禁止修复、公平评测和部署文档。

- [ ] **Step 5: 交给当前验收模型**

交接内容必须包含：分支、base/head、commit list、dirty files、测试命令与完整计数、Docker/真实模型证据、未解决 Critical/Important、报告路径和 GitHub Actions URL。未经用户明确授权不合并 main。

## 进度安排与阶段门禁

按依赖和审查门禁安排，不以日历时间替代完成条件：

| 阶段 | 任务 | 可开始条件 | 完成条件 |
|---|---|---|---|
| A1 隔离与 deadline | 1–2 | 新 worktree 基线通过 | Linux 合同通过且任务复审无 Critical/Important |
| A2 协议与能力 | 3–4 | A1 复审通过 | tool-run/health 跨边界复审通过 |
| A3 输出与供应链 | 5–7 | A2 复审通过 | 七项遗留问题全量复审通过 |
| B1 基础数据面 | 8–10 | 阶段 A 复审通过 | 配置、索引和检索具有确定性且测试通过 |
| B2 上下文与模型 | 11–13 | B1 复审通过 | 固定 SHA、工具权限和严格 LLM 合同通过 |
| B3 Agent 协作 | 14–15 | B2 复审通过 | 独立性、状态机和门禁复审通过 |
| B4 产品接入 | 16–19 | B3 复审通过 | 整仓、PR、报告、模式和安全回归通过 |
| B5 评测与验收 | 20–21 | B4 复审通过 | Docker、真实模型和最终复审证据齐全 |

每个任务结束即更新该计划专属 ledger：

```text
Task N: complete (commits <base>..<head>, review clean)
```

若 review 有 Critical/Important，按最多五轮 task fix loop 处理；不得开始依赖任务。暂停时记录当前
worktree、branch、HEAD、完成任务、未提交文件、运行中代理、下一条精确命令和不得混入的用户修改。

## 暂停与验收交接模板

后续开发模型暂停、额度耗尽或请求当前模型验收时，必须把下面模板填写到
`.superpowers/sdd/2026-09-02-cxx-llm-agent-detection/handoff.md`，并同步更新上面的进度台账：

```markdown
# C/C++ LLM Agent 开发交接

- Worktree：<绝对路径>
- Branch：<branch>
- Base：2e69f3ce56f80b91e4b180ab0556100d3e173e4f
- HEAD：<完整 SHA>
- 当前 Task 与状态：<Task N / 允许状态>
- 已完成并复审通过：<Task 列表>
- 提交：<git log --oneline --reverse 2e69f3c..HEAD>
- 工作树：<git status --short>
- RED 证据：<命令、预期失败原因、实际失败摘要>
- GREEN 证据：<命令、通过/失败/跳过计数>
- Docker/Linux：<已验证证据或未验证原因>
- 真实模型：<Provider/模型/运行 ID/脱敏统计，或未验证原因>
- 未解决 Critical/Important：<无或逐项列出>
- 未提交文件及归属：<逐项列出；用户文件必须标明禁止提交>
- 下一条精确命令：<PowerShell 命令>
- GitHub：<远程分支和 Actions URL，未推送则明确写未推送>
```

当前验收模型收到交接后，将以 `2e69f3c..HEAD` 为边界独立读取 diff、复跑可执行测试并逐条核对
设计验收标准。缺少真实环境的项目保持“未验证”；存在 Critical/Important 时退回对应 Task，
不得用后续 Task 的功能或更多测试掩盖前置问题。
