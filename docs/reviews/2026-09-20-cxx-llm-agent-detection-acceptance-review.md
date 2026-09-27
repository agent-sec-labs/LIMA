# `codex/cxx-llm-agent-detection` 分支代码验收报告

日期：2026-09-20  
审阅范围：`D:/Projects/LIMA/.worktrees/cxx-llm-agent-detection`  
审阅方式：只读代码审查、主机测试、前端门禁、静态质量检查与合同级最小复现  
初审 HEAD：`bbacf16b926636b78f2ba92772f96a269423be72`  
二次验收 HEAD：`8574be4aebbb0aba633e5acc445035e11336e1a8`  
三次验收 HEAD：`61c744fb8e8955d3eb7651cad935e859f4ed52c3`  
对比基线：本地 `main@dfa0f85a92b14bbbc46ea9f465c381d953f2a797`  

## 三次验收更新（2026-09-20）

### 结论

**结论：仍为条件不通过。逐次 wire timeout 已接通，但总 deadline 仍不是硬边界。**

本次提交 `61c744f` 正确完成了 `CxxMemoryAnalyzerClient.repro_compile_run -> _post_json -> opener` 的逐次 timeout 传递。合同级探针确认 `_post_json(timeout=7)` 最终向 opener 传入 `timeout=7`，因此二次验收中“实验 timeout 完全没有进入生产传输层”的问题已经关闭。

但是，当前实现仍会在 deadline 已过时用 `or 1` 重新放行调用；Scout 内部的多轮请求和格式修复也只复用进入 Scout 前计算的一次 timeout，未共享绝对 deadline。另外，Workbench 用捕获任意 `TypeError` 的方式探测旧客户端签名，会重复执行新版客户端调用并掩盖其内部错误。上述问题使本次修改仍不能满足“整个评审流程受同一硬 deadline 约束”的验收条件。

本节覆盖下面的二次验收结论；初审与二次验收章节继续作为历史证据保留。

### 已关闭部分

| 调用层 | 状态 | 三次验收证据 |
| --- | --- | --- |
| `_post_json` | **通过** | 接受 keyword-only `timeout`；未提供时保留 `self.timeout_seconds`；提供正整数时向 opener 使用逐次覆盖值。探针结果：`wire_timeout=7`。 |
| `repro_compile_run` | **通过** | 新增 keyword-only `timeout=None` 并传入 `_post_json`；原有四位置参数调用保持兼容。 |
| `ReproWorkbench` 到生产客户端的 timeout 传递 | **主体通过** | `effective_timeout` 已传给支持新签名的生产客户端。旧客户端兼容探测方式仍有阻断问题，见下节。 |

### 仍阻断问题

#### 1. deadline 已过仍会执行格式修复和 Scout

`lima/agent_orchestrator.py:888` 与 `lima/agent_orchestrator.py:1368` 使用：

```python
_bounded_step_timeout(timeout, deadline) or 1
```

但 `_bounded_step_timeout` 的合同明确规定：返回 `None` 表示 deadline 已过，调用者必须 abstain、不得发送。`or 1` 将这个“禁止发送”状态改写为一次新的 1 秒调用。

合同级探针把 deadline 固定为已过期状态，结果为：

```text
repair_calls=2 repair_timeout=1 result=ok
```

即第一次回复格式错误后，即使 deadline 已经过期，仍发送了第二次格式修复请求。这直接违反硬 deadline 语义。Scout 入口也存在相同的 `None -> 1` 问题。

修复要求：显式保存返回值并判断 `is None`；过期时返回 abstain/降级结果，不能使用 `or 1`。

#### 2. Scout 只在入口计算一次 timeout，内部多轮仍可越过总 deadline

`run_platform_review` 在进入 `review_leads` 前只计算一次剩余 timeout。随后 `lima/agent_scout.py:510-542` 的正常请求和格式修复、`lima/agent_scout.py:616-627` 的最多三轮 batch 都复用同一个 timeout；Scout API 没有接收绝对 deadline，也不会在每次发送前重新计算剩余量。

因此，一个 5 秒剩余预算可以被多次最长 5 秒的 Scout 请求顺序消费，整体仍可明显超过总 deadline。当前改动只修复了“Scout 不再拿原始 60/600 秒 timeout”，没有完成 aggregate deadline 贯穿。

修复要求：向 Scout 传递绝对 deadline（或 remaining-budget callback），并在每个普通请求、每次格式修复和每个 batch 前重新计算；返回 `None` 时停止发送并将未处理 lead 标记为 unresolved/deadline-exceeded。

#### 3. `except TypeError` 会重复实验并掩盖新版客户端错误

`lima/agent_repro_tools.py:313-321` 通过捕获整个新版调用抛出的任意 `TypeError` 来判断客户端是否是旧四参数签名。这个异常也可能来自新版客户端方法内部，而不是参数绑定。

合同级探针使用一个接受 `timeout`、但内部抛出 `TypeError` 的客户端，结果为：

```text
typeerror_calls=2 masked_as=run
```

Workbench 将真实内部错误误判为旧签名，随后无 timeout 重复执行一次实验并返回成功。这样会造成重复 Sidecar 工作、调用预算与真实执行次数不一致，并掩盖程序错误。

修复要求：不要用宽泛运行时 `TypeError` 探测签名。优先统一协议并更新所有 fake/adapter；若必须兼容旧客户端，应在调用前用显式 capability/adapter 或安全的签名绑定判断，不能捕获客户端方法体内的 `TypeError` 后重试。

### 测试覆盖缺口

`61c744f` 只修改三个生产文件，没有新增或修改测试。现有 deadline 测试仍只断言 mock 收到的 timeout 位于允许范围，未覆盖：

- deadline 在第一次请求后过期时，不得发送格式修复；
- Scout 多 batch、多轮和格式修复共享同一个绝对 deadline；
- per-call timeout 最终到达 `CxxMemoryAnalyzerClient` opener；
- 新签名客户端内部 `TypeError` 不得触发 legacy 重试；
- legacy 客户端兼容路径最多执行一次。

### 三次验收验证结果

重新执行：

```powershell
python -m unittest tests.test_agent_repro_tools tests.test_repro_protocol tests.test_agent_orchestrator -v
python -m unittest discover -s tests
python -m ruff check -- lima/agent_orchestrator.py lima/agent_repro_tools.py lima/cxx_memory.py
python -m compileall -q lima scripts tests cxx_analyzer
git diff --check main...HEAD
```

结果：

- 相关测试：`55` 项，全部通过。
- 完整主机测试：运行 `2453` 项，跳过 `24` 项，`0` 失败，用时约 `88.8s`。
- Ruff：`All checks passed!`。
- `compileall`：退出码 0。
- `git diff --check`：退出码 0。
- 逐次 wire timeout 探针：通过，`wire_timeout=7`。
- 过期格式修复探针：失败，deadline 已过仍发生第二次请求。
- TypeError 兼容探针：失败，新客户端内部错误导致两次调用并被掩盖。

测试全绿说明本次提交没有触发现有回归，但由于关键负例未进入测试集，不能据此判定 deadline 合同通过。

### 下一次验收的最小条件

1. 删除两个 deadline 调用点的 `or 1`；对 `None` 显式 abstain/停止发送。
2. 将绝对 deadline 贯穿 Scout 内部每次发送和格式修复，而不是只在入口计算一次 timeout。
3. 移除 `except TypeError` 的运行时签名探测，确保任何客户端调用最多执行一次。
4. 将上述三个合同级负例固化为自动化测试，再重跑完整主机门禁。

## 二次验收更新（2026-09-20）

### 结论

**结论：条件不通过，暂不做最终验收。**

初审的两项 P1 核心正确性问题已经按目标场景关闭，Ruff、空白和新增 `.superpowers/` 忽略规则也已通过复核；但是 P2 总 deadline 仍未真正贯穿到正在执行的传输/实验边界。当前实现会计算并向若干调用点传递“剩余超时”，但 `ReproWorkbench` 不使用该值约束客户端调用，Scout 仍接收原始 `timeout`，同一轮格式修复也复用预先计算的超时。因此，这个分支仍不能保证 `deadline_seconds` 是整个评审流程的硬截止时间。

本节结论覆盖下方保留的初审结论；下方第 1～8 节作为初审历史和问题来源保留。

### 修复项复核

| 验收项 | 二次验收状态 | 复核结论 |
| --- | --- | --- |
| P1-3.1 ASan 命中不可达 | **关闭** | `lima/agent_orchestrator.py:753-789` 已删除 `ok=True` 前提，改为 run-stage、完整 ASan 错误类型、CWE marker 和目标文件绑定。测试使用真实 `ReproResponse -> ExperimentObservation` 转换；真实形状 UAF 命中，安全运行和编译失败不命中。 |
| P1-3.2 驱动误归因 | **关闭（有非阻断加固项）** | `ExperimentObservation` 已保留 faulting/freed/allocated 文件与函数；驱动文件、未知文件和无符号帧均拒绝，负例不得升级为 `runtime-confirmed`。当前命中门槛使用 faulting file 与 Scout target 绑定，尚未使用 freed/allocated frame 绑定到候选的具体 allocation/release/use 身份；这不再复现初审的“驱动自身崩溃被确认”问题，但若未来一个 target 文件内同时存在多个候选，建议继续收紧到候选级 witness。 |
| P2-3.3 deadline 贯穿 | **未关闭，阻断** | 调用点虽然使用 `_remaining_budget` / `_bounded_step_timeout`，但真实实验传输未被该值约束，且 Scout、格式修复和退役 UAF 分支仍存在聚合 deadline 缺口。详见下一节。 |
| 4.1 Ruff `UP038` | **关闭** | 对初审列出的新增 Python 文件重跑 Ruff，结果 `All checks passed!`。 |
| 4.2 空白问题 | **关闭** | `git diff --check main...HEAD` 退出码为 0。 |
| 4.3 `.superpowers` | **部分关闭，非本轮核心阻断** | `.gitignore` 已阻止后续本地产物进入状态列表；但两个历史文件仍被 Git 跟踪，ignore 规则不会自动移除它们：`.superpowers/sdd/2026-08-26-cxx-memory-detection/final-fix-report.md`、`.superpowers/sdd/2026-08-26-cxx-memory-detection/task-5-report.md`。是否从分支删除仍需维护者决定。 |

### 仍阻断：deadline 只传值，未形成硬边界

1. `lima/agent_repro_tools.py:269-314` 接收并验证 `timeout`，但调用仍是：

   ```python
   response = self._client.repro_compile_run(repo, snapshot, sources, driver)
   ```

   `timeout` 没有传入客户端，也没有由 Workbench 自身实施 wall-clock 取消。

2. `lima/cxx_memory.py:804-868` 的 `CxxMemoryAnalyzerClient.repro_compile_run` 没有单次 timeout 参数；`_post_json` 固定使用客户端级 `self.timeout_seconds`。因此，即使上层计算出更小的剩余预算，真实 HTTP 调用也不会采用它。

3. 合同级阻塞客户端复现：向 `run_experiment` 传 `timeout=1`，客户端阻塞 1.25 秒，实测输出为：

   ```text
   elapsed=1.250s for timeout=1s
   ```

   该结果直接证明当前 timeout 未执行，而不仅是测试覆盖不足。

4. `lima/agent_orchestrator.py:1356-1364` 的 Scout 仍接收原始 `timeout`，没有使用剩余 deadline。

5. `lima/agent_orchestrator.py:863-895` 的 `_platform_round` 在格式修复调用前不重新计算剩余时间，而是复用同一个 timeout。

6. `lima/uaf_orchestrator.py:669-682` 只在进入语义分支前计算一次 branch timeout；`lima/uaf_llm_branch.py:486-607` 的 Specialist、Critic 和格式修复可能连续复用该值，因此也不是多调用共享的硬聚合 deadline。

现有 deadline 单测只断言 fake transport/workbench 收到的数值位于 `[1, remaining]`，没有使用阻塞 transport/client 验证 wall-clock 上界，所以无法发现上述缺口。

### 二次验收验证结果

在 `8574be4` 上重新执行：

```powershell
python -m unittest discover -s tests
python -m compileall -q lima scripts tests cxx_analyzer
git diff --check main...HEAD
python -m ruff check -- <初审列出的新增 Python 文件>
```

结果：

- Python 完整主机测试：`2453` 项，`24` 项跳过，`0` 失败，用时约 `93.1s`。
- `compileall`：退出码 0。
- `git diff --check`：退出码 0。
- Ruff：`All checks passed!`。
- deadline 阻塞复现：`timeout=1s` 时仍耗时 `1.250s`，复现成功，说明 P2 未关闭。

Docker daemon 仍未运行，因此 Linux Sidecar、真实 clang/ASan 容器执行和容器隔离门禁本轮仍未验证；主机测试通过不能替代这些证据。

### 工作区真实性说明

二次验收时 `git status --short` 仍显示：

```text
 M deploy/build-recipes/resinsight/Dockerfile
 M deploy/build-recipes/resinsight/recipe.yaml
?? docs/reviews/
```

前两项是用户已有的 ResInsight 修改；第三项是本验收报告。它们均未被本轮代码审阅改写。因此“`.superpowers/` 不再出现在状态列表”成立，但“整个 worktree 已干净”并不成立。

### 最终签字前的最小剩余条件

1. 为 `repro_compile_run` / `_post_json` 增加单次调用 timeout，或在 Workbench 层实施可证明的 wall-clock 取消，并让真实传输采用剩余 deadline。
2. Scout、Specialist、Critic、每次格式修复和每次实验都在调用前重新计算同一个绝对 deadline 的剩余量。
3. 增加阻塞 transport/client 的聚合 wall-clock 测试，覆盖普通回复、格式修复、多轮 Critic 和实验调用；不能只检查 mock 收到的 timeout 数值。
4. 在 Docker 可用环境补跑 Linux Sidecar 与真实 Clang/ASan 全链门禁。

## 1. 验收结论

**结论：暂不验收，不建议将当前分支合并到 `main`。**

主机 Python 测试、前端类型检查、前端测试和生产构建均已通过，说明大部分已有功能和合同具备较好的回归保护。但是，智能体漏洞平台的核心目标“真实 ASan 实验命中后升级为 `runtime-confirmed`”目前在生产合同下不可达；即使修复该问题，当前运行时证据仍缺少对目标代码身份的严格绑定，可能把 PoC 驱动自身触发的同类漏洞错误归因给被审计目标。这两项均属于阻断验收的核心正确性问题。

此外，总 deadline 未贯穿正在执行的 LLM/实验步骤，新增代码未通过项目 Ruff 规则，diff 存在空白字符问题，并有文件违反计划中“`.superpowers/` 不入库”的硬约束。Linux Sidecar 和真实 Clang/ASan 容器门禁因本机 Docker daemon 未运行，本轮未能复验。

## 2. 分支与工作区状态

- 分支相对本地 `main`：ahead 105 commits。
- 分支相对当前本地 `origin/main`：ahead 105、behind 1。
- 落后的 `origin/main` 提交为 `b4c4c06`，仅修改 IP-0020 文档，但合并前仍应同步并重新执行必要门禁。
- 对比 `main...HEAD` 的规模约为 274 个文件、76,253 行新增、86 行删除。
- 分支范围已经从 C/C++ UAF v2 扩展到 Agent 平台、PoC 复现、补丁验证、Context Package、Build Recipe 和 CWE 扩展规划。

审阅期间工作区原有以下未提交内容，均未被修改或清理：

- `deploy/build-recipes/resinsight/Dockerfile`
- `deploy/build-recipes/resinsight/recipe.yaml`
- `.superpowers/sdd/2026-09-02-cxx-llm-agent-detection/`
- `.superpowers/tmp/`

前两项 ResInsight 修改不被当前单元测试直接读取，因此主机测试结果主要反映提交代码；但当前工作区不是可直接复现的干净 HEAD，正式验收仍应在干净 checkout 或隔离 worktree 中再执行一次。

## 3. 阻断问题

### 3.1 P1：真实 ASan 命中无法进入 `runtime-confirmed`

涉及位置：

- `cxx_analyzer/repro.py:461-464`
- `lima/cxx_memory.py:917-921`
- `lima/agent_repro_tools.py:121-139`
- `lima/agent_orchestrator.py:750-762`
- `tests/test_agent_orchestrator.py:363-367`

Sidecar 将 `ok` 定义为“运行成功退出、没有 ASan 报告且输出未截断”。因此一旦解析出 ASan 报告，`ok` 必然为 `false`：

```python
clean_exit = (
    run_execution.status == "completed" and run_execution.returncode == 0
)
ok = report is None and clean_exit and not run_execution.output_truncated
```

严格客户端进一步固化了同一合同：运行阶段只有在 `asan_report is None and exit_code == 0` 时才允许 `ok=true`。

但是平台命中判定同时要求：

```python
observation.ok is True
observation.stage == "run"
observation.error_type 非空且匹配目标 CWE
```

这三个条件在真实协议响应中不能同时成立。现有平台单测之所以通过，是因为测试直接构造了协议不可能返回的对象：

```python
ExperimentObservation(
    ok=True,
    stage="run",
    exit_code=-9,
    error_type="heap-use-after-free",
    ...
)
```

合同级最小复现使用真实响应形状构造 `heap-use-after-free` 报告，得到：

```text
ExperimentObservation(ok=False, stage='run', ..., error_type='heap-use-after-free', ...)
hit=False
```

影响：

- 真实 ASan 崩溃不能生成 D3 SUPPORTS 证据。
- 生产路径不能达到 `runtime-confirmed`。
- 平台计划 Task 4 的核心验收目标与当前实现不一致。
- Fake 测试给出了错误的通过信号。

建议修复：

1. 明确区分“实验成功执行”和“被测程序安全退出”。不要复用当前 `ok` 同时表达这两个语义。
2. `_experiment_hit` 应依据已执行的 run-stage、完整且合同验证通过的 ASan report 判断命中，而不是要求 clean-run `ok=true`。
3. 删除测试中的不可能状态，改用经过 `ReproResponse -> ExperimentObservation` 真实转换链生成的 fixture。
4. 新增 Sidecar 响应、严格客户端、Workbench 和 Orchestrator 的跨模块合同测试。

### 3.2 P1：PoC 驱动自身触发同类漏洞可被误归因为目标漏洞

涉及位置：

- `lima/agent_orchestrator.py:750-762`
- `lima/agent_orchestrator.py:960-995`
- `lima/agent_repro_tools.py:121-139`

当前 `_experiment_hit` 只检查实验阶段、`ok` 和 ASan 错误类型是否与 CWE marker 匹配。它没有验证：

- faulting frame 是否位于目标文件和目标函数；
- UAF 的 freed-by、allocated-by 和 faulting frame 是否分别命中候选的 release/allocation/use 范围；
- 崩溃是否发生在模型生成的 PoC driver，而不是被测仓库代码；
- 无确定性 candidate 时，运行时报告是否确实绑定到了 Scout target。

命中后，代码直接创建 D3 SUPPORTS EvidenceRecord 并交给 Broker，没有复用现有的 ASan witness binder。因此，一个模型生成的 driver 可以在 `main()` 内自行制造 UAF 或越界写；只要错误类型匹配假设 CWE，目标即可被升级为 `runtime-confirmed`，即使被审计代码本身是安全的。

影响：

- 形成高置信度误报，违反“实证必须命中同一身份”的系统不变量。
- 竞赛场景中可能把 PoC 缺陷当作目标项目漏洞，直接影响准确率和报告可信度。
- 当前 ExperimentObservation 丢弃了 ASan frame 的文件名和函数名，后续层甚至没有足够信息完成严格绑定。

建议修复：

1. 在 Workbench 观察合同中保留 faulting/freed/allocated frame 的规范路径、函数和行号。
2. 对有 CandidateIdentity 的目标，复用或扩展 `uaf_evidence_binder`，要求 ASan 三段 witness 精确绑定。
3. 对无 candidate 的目标，至少要求 faulting frame 落在目标 snapshot 文件和目标函数/行域，并显式排除 driver 文件。
4. run identity 应覆盖 snapshot、source file set、driver digest、binary digest 和真实执行记录，不能只依赖 snapshot 与 driver 文本。
5. 增加“driver 自身 UAF、目标代码安全”的负例测试，断言不得达到 `runtime-confirmed`。

### 3.3 P2：`deadline_seconds` 不是正在执行流程的总 deadline

涉及位置：

- `lima/agent_orchestrator.py:1146-1153`
- `lima/agent_orchestrator.py:1280-1292`
- `lima/agent_orchestrator.py:1305-1324`

`run_platform_review` 计算了绝对截止时间，但只在平台启动前和每个 target 启动前检查。剩余时间没有传递给：

- Scout 调用；
- Specialist 调用及格式修复调用；
- Critic 多轮调用；
- Repro Workbench 实验；
- 并行任务的取消机制。

因此，只要 target 在截止时间前开始，它仍可能执行多轮固定 `timeout=60` 的 LLM 请求和实验，显著越过 `deadline_seconds`。并行模式会提前启动多个 target，截止时间到达后已启动任务仍继续运行。

影响：

- API/任务总时限不能得到保证。
- 高并发或外部服务变慢时，线程和 Sidecar 资源可能被长时间占用。
- 与设计文档中“多轮受总 deadline 约束”的冻结语义不一致。

建议修复：

1. 使用一个贯穿整次平台审查的绝对 deadline 对象。
2. 每次 LLM 和实验调用前计算剩余时间，并将 `min(step_timeout, remaining)` 传入下层。
3. 格式修复和 Critic 重试同样消费同一个剩余预算。
4. 并行模式增加协作取消；截止后不再领取新任务，已运行任务应由下层 deadline 有界终止。
5. 新增 FakeClock + 阻塞 transport/workbench 测试，断言总耗时不会被多轮步骤放大。

## 4. 合并质量与流程问题

### 4.1 新增 Python 文件未通过项目 Ruff 规则

项目 `pyproject.toml` 启用了 `E/F/I/B/UP/S` 规则。对本分支新增 Python 文件执行 Ruff 得到 13 个 `UP038` 错误，涉及：

- `cxx_analyzer/normalizers.py`
- `cxx_analyzer/repro.py`
- `lima/agent_orchestrator.py`
- `lima/agent_repro_tools.py`
- `lima/cxx_agent_models.py`
- `lima/cxx_memory.py`
- `lima/impact_mining.py`
- `lima/uaf_models.py`
- `lima/uaf_orchestrator.py`
- `tests/test_cxx_capabilities.py`

这些问题主要是 `isinstance(value, (X, Y))` 未按项目 Python 3.11 规则改用 `X | Y`。它们通常不影响运行时正确性，但说明分支尚未通过已配置的静态质量门禁。

### 4.2 `git diff --check` 失败

```text
.github/workflows/ci.yml:560: new blank line at EOF
cxx_analyzer/trust.py:11: trailing whitespace
```

合并前应清理这两处空白问题，并将 `git diff --check` 纳入验收门禁。

### 4.3 `.superpowers/` 文件违反实施计划硬边界

`docs/superpowers/plans/2026-09-11-cxx-uaf-v2.md` 第 11 行明确规定：

> `.superpowers/` 不入库；提交一律精确文件清单。

但 HEAD 已提交：

- `.superpowers/sdd/2026-08-26-cxx-memory-detection/final-fix-report.md`
- `.superpowers/sdd/2026-08-26-cxx-memory-detection/task-5-report.md`

应确认这些文件是否确实属于产品文档。如果只是本地执行产物，应从 Git 历史/当前分支删除，并补充 ignore 规则或提交清单检查。

### 4.4 Build Recipe Docker 输出缺少显式字节上限

涉及位置：`lima/build_recipe.py:465-488`。

Docker configure 命令最长可运行一小时，使用 `subprocess.run(..., capture_output=True)` 将 stdout/stderr 全部保存在内存中，没有流式截断或输出字节预算。被分析仓库的构建脚本可以持续输出并造成主进程内存耗尽。

此问题没有前述 P1 问题紧急，但在 Build Recipe 投入真实大型仓库前应增加流式读取、硬字节上限和超限诊断。

## 5. 已完成验证

### 5.1 Python 主机测试

命令：

```powershell
python -m unittest discover -s tests -v
```

结果：

- 2442 passed
- 24 skipped
- 0 failed
- 用时约 83.7 秒

跳过项主要为 Linux、容器或编译器依赖测试。

### 5.2 Python 编译检查

```powershell
python -m compileall -q lima scripts tests cxx_analyzer
```

结果：通过。

### 5.3 前端门禁

执行并通过：

```powershell
npm run typecheck
npm test
npm run test:coverage
npm run build
```

测试结果：7 个测试文件、40 项测试全部通过。

非阻断观察：

- Ant Design `destroyOnClose` 和 Table rowKey index 弃用警告；
- jsdom `window.getComputedStyle(..., pseudoElt)` 未实现噪声；
- 生产 bundle `dist/assets/index-*.js` 约 1,418.87 kB，Vite 报告 chunk 大于 500 kB。

### 5.4 Compose 静态配置

使用 CI 占位环境变量执行：

```powershell
$env:LIMA_POSTGRES_PASSWORD='ci-only-database-password'
$env:LIMA_AUTH_SECRET='ci-only-auth-secret-with-at-least-32-bytes'
$env:LIMA_BOOTSTRAP_ADMIN_PASSWORD='ci-only-admin-password'
docker compose config --quiet
```

结果：通过。Docker 用户配置文件存在访问警告，但不影响 Compose 配置解析。

### 5.5 静态质量检查

```powershell
git diff --check main...HEAD
```

结果：失败，2 个空白问题。

```powershell
$files = @(git diff --diff-filter=A --name-only main...HEAD -- '*.py' |
  Where-Object { $_ -notlike '.superpowers/*' })
python -m ruff check -- $files
```

结果：失败，13 个 `UP038`。

说明：仓库级 `ruff check .` 会遍历未跟踪的 `.superpowers/tmp/ResInsight` 和大量既存文件，产生数千项与本分支无关的结果，因此未将其作为分支质量证据。

## 6. 未完成验证与证据边界

以下内容本轮未验证，因此不能据此声明通过：

- Linux Python 3.11/3.12 CI 矩阵；
- Sidecar 容器只读/隔离合同；
- 真实 clang-14 UAF facts 提取；
- 真实 ASan reproduction 和 `runtime-confirmed` 全链；
- Linux Playwright；
- ResInsight Build Recipe 镜像构建和真实上下文包导出；
- 真实模型平台端到端检测；
- GitHub Actions 远端状态。

原因：本机 Docker daemon 未运行，且环境中没有 `gh` CLI。Compose 静态解析可用，但不能替代容器执行验证。

## 7. 重新验收条件

重新提交验收前，至少应满足：

1. 修正 ASan `ok`/hit 合同错位，并用真实响应转换链覆盖。
2. 对运行时证据实施目标身份绑定，增加“driver 自身崩溃不得确认目标”的负例。
3. 将总 deadline 贯穿 Scout、Specialist、Critic、格式修复和 Repro Workbench。
4. 新增跨模块测试：Sidecar `ReproExecution` → wire response → `ReproResponse` → `ExperimentObservation` → Orchestrator → Arbiter。
5. 新增真实容器测试，证明一个脆弱样例可达到 `runtime-confirmed`，对应修复样例不得达到该状态。
6. 清零新增文件 Ruff 错误，确保 `git diff --check` 通过。
7. 处理误提交的 `.superpowers/` 文件。
8. 同步 `origin/main`，在干净 worktree 重跑主机和前端门禁。
9. 运行 Linux Sidecar、真实 Clang/ASan、容器隔离和相关 CI 门禁。
10. 保留真实测试日志、镜像/工具链身份和执行哈希，作为最终验收附件。

## 8. 建议验收顺序

```text
修复 ASan 合同
  → 修复运行时身份绑定
  → 补总 deadline
  → 跨模块合同测试
  → Ruff / diff / 仓库卫生
  → 干净 worktree 主机回归
  → Linux Sidecar + 真实 ASan 容器回归
  → 远端 CI 全绿
  → 重新验收
```

在上述条件完成前，可以将当前分支视为“功能量较大、主机回归良好，但核心运行时确认链尚未满足生产合同”的候选实现，不能视为 merge-ready。
