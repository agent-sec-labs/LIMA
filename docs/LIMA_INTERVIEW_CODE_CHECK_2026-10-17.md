# LIMA 口述稿代码校对记录

日期：2026-10-17。基线：`main`，`f5668ff`。目标文件：`docs/LIMA_INTERVIEW_ORAL_GUIDE.md`。

本次检查用于核对面试稿描述是否对应当前实现，不实施业务代码修复，不重新验证外部漏洞数量，也不声称已对任意仓库完成真实模型与 Sanitizer 验收。

## 检查范围

重新检查了 README、打包依赖、进程和 HTTP 入口、服务装配、仓库来源与物化缓存、完整仓库扫描、通用 PR Agent、Python 调查链、C/C++ 工具和 Agent 链、证据仲裁、复现工作台、隔离执行、修复边界、前端路由与依赖、部署及 CI。口述稿仍以用户负责的 C/C++ 模块为重点，平台其他部分只保留背景说明。

代码可以证明模块能力，不能单独证明个人贡献。稿中的个人职责沿用用户提供的分工；面试时需要结合自己的提交说明具体实现。

## 逐项结论

| 需要核对的说法 | 当前实现与改稿处理 | 代码依据 |
|---|---|---|
| “整个项目就是纯 Agent” | 不准确。完整仓库扫描保留基础工具链，其结果独立进入报告，再和 Agent 结果合并 | `lima/repository_scanner.py:920` 至该文件扫描主流程 |
| “Agent 必须等 Semgrep 告警才开始” | 不准确。优先使用外部 leads，否则尝试从 UAF 事实生成候选；无候选再 Discovery 读源码 | `lima/agent_orchestrator.py:2007`，尤其 leads 生成部分 |
| “Agent 已能直接读源码发现” | 内核支持。无 facts 也可以通过 Discovery 生成线索，但服务入口仍要求 analyzer 已配置；事实客户端错误可能向外传播 | `lima/agent_orchestrator.py:1246`、`:2165`；`lima/repository_scanner.py:661`；`lima/service.py:1036` |
| “静态工具只是辅助，所以不会独立出报告” | 不准确。基础链 Finding 独立合并，Agent 内部的证据工具又有不同职责 | `lima/repository_scanner.py:937` 及后续 Finding 合并 |
| “所有分析都由我手工完成” | 不符合模块调用链。模型筛选、假设、驱动和有界实验由编排程序执行；人工工作主要是独立复现和实际应用核查 | `lima/agent_orchestrator.py:1778` |
| “只由人工生成和运行 PoC” | 不准确。Specialist 输出 driver，工作台自动编译和运行；依赖模型、Sidecar、环境和预算，不保证每个目标均能成功 | `lima/agent_orchestrator.py:1845`；`cxx_analyzer/repro.py:643` |
| “每项发现都经 Critic 交叉验证” | 不准确。实验首次命中后直接退出实验循环进入仲裁；未命中且有轮数才调用 Critic，无法实验时另有语义分支 | `lima/agent_orchestrator.py:1833` 后的循环 |
| “C/C++ Agent 可以任意搜索全仓、查定义引用” | 当前链主要是固定编排和程序提供的源码窗口、事实、假设、实验上下文，不应借用通用 PR 或 Python Investigation 的工具能力来描述 | `lima/agent_orchestrator.py:625`、`:749`、`:779`；`lima/agent_scout.py` 的批次上下文 |
| “仓库级意味着全仓全部文件都已被模型分析” | 不成立。服务端最多选 16 个翻译单元，Discovery 还有字节与窗口上限；覆盖缺口必须保留 | `lima/repository_scanner.py:698`；`lima/cxx_memory.py:158`；`lima/agent_orchestrator.py:1246` |
| “Clang Static Analyzer 告警就是 Clang 程序事实” | 需要区分。前者归基础构建分析，后者是 UAF AST/CFG 事实提取，为候选、证明等仪器提供输入 | `cxx_analyzer/build_scan.py`、`cxx_analyzer/uaf_scan.py`；`lima/uaf_facts.py` |
| “三层工具状态就是 Agent 的全部状态” | 不准确。基础链为 candidate/build-verified/confirmed；Agent 另有 semantic-supported、tool-corroborated、fact-verified、runtime-confirmed 等 | `lima/cxx_memory.py` 顶部常量；`lima/uaf_orchestrator.py:210` |
| “ASan 一命中就证明是可利用的真实应用漏洞” | 不成立。命中检查运行阶段、类型、故障文件并排除 driver 文件；不自动证明完整根因、真实入口可达性或利用价值；证据冲突还可能需要人工复核 | `lima/agent_orchestrator.py:1471`；`lima/uaf_orchestrator.py:210` |
| “服务配置中的并行、轮数和总时限都已生效” | 需要修正。内核接收 parallelism/dialogue_rounds/deadline_seconds，但扫描器当前调用没有传入这些字段，沿用内核默认；配置项存在不能当作已经接线 | `lima/repository_scanner.py:730`；`lima/agent_orchestrator.py:2007`；`lima/config.py` |
| “所有上下文都按文件数和行数精确扣预算” | 不准确。预算类有这些字段，但当前主要调用点扣 calls/bytes；另有窗口和文件读取限制。Scout、Specialist/Critic、工作台的字节记账范围也不同 | `lima/cxx_agent_tools.py:49`；`lima/agent_scout.py:512`；`lima/uaf_llm_branch.py:433`；`lima/agent_repro_tools.py` |
| “Agent 已接到 C/C++ PR 扫描” | 当前服务明确 `pull_request_scan=false`。内核的 diff-only 支持不等于端到端 PR 接入 | `lima/service.py:917` |
| “无需配置模型也能运行 C/C++ LLM Agent” | 不成立。可不用模型运行基础工具，不等于 Agent 链运行；Agent 默认关闭并检查 Provider/Sidecar | `lima/config.py`；`lima/service.py:1036`；`lima/repository_scanner.py:661` |
| “Docker 加只读挂载就够了” | 不完整。还有非 root、capabilities、Landlock/seccomp、请求时限、进程与输出约束。构建生成门禁默认关闭，并要求执行时探测能力 | `docker-compose.yml`；`cxx_analyzer/execution.py:458`、`trust.py:130`、`build_scan.py:99` |
| “平台评测通过就是用了真实 Clang/ASan” | 不成立。fixture runner 即使接真实 LLM，仍用 FakePlatformSidecar 和 FakePlatformWorkbench；真实工具验证另做 | `scripts/run_platform_evaluation.py:1051` |
| “C/C++ 已自动修复并发布补丁” | 不成立。Finding 固定禁用自动修复；复现工作台的临时源码覆盖用于回归，不代表服务已自动修复发布 | `lima/repository_scanner.py:275`；`lima/agent_repro_tools.py`；`cxx_analyzer/repro.py:643` |

## 测试验证

本次在本地 Python 环境执行两组检查，均退出码 0：

```powershell
python -m unittest tests.test_agent_orchestrator tests.test_agent_scout tests.test_agent_repro_tools tests.test_cxx_memory tests.test_cxx_capabilities tests.test_repository_agent_modes_integration tests.test_platform_evaluation -q
# Ran 231 tests in 9.323s / OK

python -m unittest tests.test_config tests.test_service tests.test_reviewer tests.test_harness tests.test_multi_agent_collaboration tests.test_task_progress tests.test_task_failure tests.test_ci_contract -q
# Ran 83 tests in 17.908s / OK
```

共 314 项通过，输出未报告 skip。期间出现重复初始化 OpenTelemetry TracerProvider 的警告，不影响两组测试通过。上述测试包含模拟传输、假 Sidecar、假实验台和代码契约检查，不等于本轮执行了真实模型调用、Linux 隔离探针或真实 Sanitizer 容器测试，也不等于全仓测试全部通过。

## 对口述稿的处理

开场和 30 秒版本突出 C/C++ 模块开发与后续人工复现。展开流程按当前 Agent 调用顺序重写；修正 Semgrep 线索、Critic 执行条件、上下文自主性、预算和入口能力的混写。保留 28 个面试追问，新增当前实现边界。Python、前端、存储和修复仍只作平台背景，不作为用户个人开发贡献。
