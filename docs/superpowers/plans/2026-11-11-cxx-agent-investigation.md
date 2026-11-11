# LIMA C/C++ 自主调查与多智能体协作开发计划

> 执行人员按任务使用 `superpowers:executing-plans`，采用子任务委派时使用 `superpowers:subagent-driven-development`。步骤以复选框跟踪，每个任务完成后核对接口与验收证据。

**目标**

将 C/C++ 检测发展为可主动取证、修订假设、调整实验、按需委派并恢复进度的调查流程，最终通过现有仓库扫描入口交付可复核的漏洞证据。

**架构**

工具能力、单线索持续调查、多智能体协作共同组成目标架构。Scout 负责仓库探索和线索排序，每条线索有一个持续负责的 Investigator，按需委派专业子任务，Critic 独立检查反证，现有确定性裁决与 VEP 转换消费验证后的证据。

**技术栈**

Python 3.11+、现有 AgentLoop / ToolRegistry、RepositoryWorkspace、CxxAgentBudget、SQLite / PostgreSQL、C/C++ Sidecar / clang / ASan、React / TypeScript、pytest / Vitest。

**设计依据**

本次讨论确认三层能力组合建设并分步交付。本文第 2～5 节给出供实施使用的设计约定，历史上下文见 `docs/AGENT_VULN_PLATFORM.md`、`docs/superpowers/specs/2026-09-12-agent-vuln-platform-design.md`，工程交接见 `docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md`。本文属于可供拆分 Implementation Packet 的开发计划。

## 1. 阅读基线与现有资产

计划日期为 2026-11-11。阅读时 HEAD 为 `3f58d11cffa642dad7ef48fbf6a3da177b8a34c6`，工作区含多项未提交改动，包含 Build Agent、快照、服务、存储和前端接口。实施时先记录实际 commit、相关文件差异和目标回归结果，再冻结每个 Packet 的接口基线。

以下结论来自源码阅读，性能收益与真实模型行为待实验验证。

| 资产 | 当前用途 | 本次使用方式 |
| --- | --- | --- |
| `lima/repository_scanner.py` | 调用 `run_platform_review`，传递模式、预算、上下文和取消回调 | 保持正常服务入口贯通 |
| `lima/agent_orchestrator.py` | Scout、单次 Specialist 假设、ASan、Critic 驱动修订、证据裁决 | 逐步接入自主调查，复用命中检查和结果契约 |
| `lima/agent_scout.py` | 基于给定片段返回升级或排除判断 | 增加主动取证与新增线索 |
| `lima/runtime.py` | `AgentLoop`、`ToolRegistry`、节点 checkpoint | 复用工具循环，补齐 C/C++ 所需控制语义 |
| `lima/repository_investigation.py` | Python 调查的搜索、读码、证据引用及结果合并 | 复用经过核对的模式，C/C++ 符号与动态执行走专用适配 |
| `lima/cxx_agent_tools.py` | 线程内原子扣减 calls / files / lines / bytes | 扩展持久化计费与并行共享预算 |
| `lima/agent_repro_tools.py` | `ReproWorkbench` 与 `as_agent_tool` | 将结构化观察与受校验源文件集合接入调查 |
| `cxx_analyzer/repro.py` | 沙箱编译运行，最多 16 个源文件，默认 clang++-14 / ASan | 先复用当前多源文件能力，验证真实语言与依赖限制 |
| `lima/build_context_view.py` | 已验证构建包的只读视图 | 查询目标 TU 的编译环境，绑定 artifact digest |
| `lima/store.py`、`lima/postgres_store.py` | 任务、事件与节点 checkpoint | 增加调查级版本状态与动作台账 |
| `lima/agent_scale.py` | 完成结果缓存与并行目标处理 | 区分结果复用与调查恢复，扩充缓存身份 |
| `lima/platform_contracts.py` | PlatformFinding 到 VEP 的转换 | 消费经裁决的调查结果 |
| `scripts/run_platform_evaluation.py` | 现有 vulnerable/fixed 配对评测 | 扩展公平比较与行动轨迹指标 |

现有 C++ 调查中的主要限制包括固定片段上下文、driver-only 修订、编排层固定源文件集合，以及完成结果缓存之外缺少中途调查恢复。通用 runtime 已有工具调用能力，Python 调查链已实际使用它。

## 2. 总体设计与交付边界

```text
仓库扫描请求 → 固定快照与已验证构建上下文
                     ↓
              Scout 探索与线索队列
                     ↓
          每条线索一个 Investigator
                     │
          读取状态 → 识别证据缺口 → 选择动作
                     │
       ┌─────────────┼────────────────┐
       ↓             ↓                ↓
   搜索/读码/事实   复现工作台       委派专业子任务
       └─────────────┼────────────────┘
                     ↓
             更新证据、假设与未决问题
                     ↓
            Critic 独立检查 → 必要时继续调查
                     ↓
           确定性裁决 → PlatformFinding / VEP
                     ↓
               持久报告与调查时间线
```

### 2.1 三种方案的组合

| 能力 | 选择理由 | 实施代价与控制方式 |
| --- | --- | --- |
| 各角色可调用工具 | 为自主取证提供执行入口 | 限定工具权限、路径、预算和输出大小 |
| 单线索持续调查 | 保持假设、证据和实验上下文连贯 | 显式记录状态，限制重复动作，支持检查点 |
| 共享任务板与多智能体委派 | 处理跨模块取证、实验与反证子任务 | 单一负责人整合结果，限制深度、并行和预算 |

推荐顺序为工具与单线索调查 → 持续反证与主动 Scout → 多智能体委派 → 完整服务和评测验收。三种能力均在本计划范围内。

### 2.2 首期能力范围

- 覆盖现有内存漏洞类型包支持的 C/C++ 检测类别。
- 先提供快照搜索、范围读码、符号定位、事实查询、构建上下文查询和现有 ASan 实验。
- 实验允许选择当前协议支持且经过范围校验的源文件集合，并明确记录构建能力缺口。
- 仓库 Scout 可从已选 TU 和快照索引探索新线索，记录未覆盖范围。
- 子任务初期角色为 `ownership`、`reachability`、`reproduction`、`critic`，父调查负责整合。
- 调查证据通过版本化制品传递，持久状态绑定 tenant、task、snapshot、context 和配置身份。
- 完整 CMake 目标重建、额外 sanitizer、coverage-guided fuzzing、调试器和更深委派列入后续扩展项，各自需要能力适配和验收。

## 3. 全局约束

- 快照、租户、任务范围由服务端绑定。模型工具参数使用任务内相对路径和已登记制品引用。
- `LIMA_CXX_AGENT_MODE=off/auto/required` 沿用现有调用与失败语义，`off` 的模型和实验调用计数均为 0。
- 默认沿用现有预算上限和配置值。新增上限是本文提出的实现建议，执行时写入配置与实验身份。
- 现有调用预算默认 40，文件 12，行数 1200，字节 1 MiB。模型、实验和子任务共享任务总池，分别记录消费类别。
- 总时间沿用现有 `cxx_agent_timeout_seconds`，并行上限沿用 `cxx_agent_parallelism`。单次调用取剩余 deadline 与工具上限的较小值。
- 新增建议缺省值为每条调查最多 24 个动作、最多 2 个在途子任务、最多一层委派、相同状态下相同动作最多执行 1 次。工具失败后的有效参数变化可以产生新动作。
- 子任务额度预留在总池内部，剩余额度随租约完成或释放归还。恢复与并行执行使用持久台账结算，已经发生的调用保留费用。
- runtime-confirmed 必须经过真实实验、错误类别、故障位置和快照绑定检查。CWE 或置信度文本本身只参与假设记录。
- ASan 命中附带实验输入与输出摘要。驱动 API 合法性和触发路径交由独立复核，分歧按照现有证据裁决规则处理。
- diff-only 路径沿用现有证据等级上限。工具结果带能力范围与截断标记。
- 新旧任务和报告采用可选新增字段兼容读取，旧缓存与新配置身份隔离。
- 涉及工具输出、日志、模型输入和持久制品时使用现有 evidence-privacy 入口，并检验实际租户绑定。
- 复现调用继续走现有沙箱执行器，构建包继续携带 `verified_artifact_digest`。C/C++ 检测结果继续使用现有自动修复资格边界。
- 任务实现先写针对具体行为的失败测试，再完成实现和回归。每次提交仅暂存对应任务文件。

## 4. 调查状态、动作和证据约定

### 4.1 基础数据结构

在 `lima/cxx_investigation_models.py` 定义版本 1 契约，提供严格解析和 JSON 往返。

- `InvestigationIdentity` 包含 `tenant_id, task_id, investigation_id, snapshot_hash, context_digest, config_digest`。
- `HypothesisRecord` 包含 `hypothesis_id, revision, statement, cwe, trigger_path, assumptions, status, evidence_ids`，status 为 `active/supported/refuted/unresolved`。
- `InvestigationEvidence` 包含 `evidence_id, identity, action_id, tool_name, path, start_line, end_line, artifact_ref, payload_digest, scope, truncated`。文本行号与路径按工具实际结果校验。
- `InvestigationState` 包含 `schema_version, identity, version, lead, hypotheses, evidence, open_questions, action_ids, child_ids, status, stop_reason`。
- `InvestigationAction` 为封闭联合，使用 `action=tool/final`。tool 包含 `tool, arguments, purpose`，final 包含 `hypothesis_id, evidence_ids, unresolved_questions`。模型提交结束请求后由代码生成实际终态。
- `InvestigationResult` 包含 `state, finding, stats`，其中 finding 为现有 `PlatformFinding | None`，stats 为结构化计数。
- `InvestigationPolicy` 包含动作数、委派数、深度、并行、超时及工具权限，来源为服务端冻结配置。
- `InvestigationRuntimeContext` 包含只读 workspace / verified_view、共享 budget、workbench、model_step、journal、cancel、progress。引用具体已有对象或 Protocol，避免将凭据序列化入 state。

调查执行状态为 `queued/running/waiting_children/completed/inconclusive/needs_attention/cancelled/failed`。验证等级沿用 PlatformFinding 状态词表。两者分别序列化。

### 4.2 证据与推理记录

模型只需记录行动目的、假设变更原因和证据引用。每条证据必须来自本次任务实际获取的观察或通过身份校验的既有制品。子任务结果带子任务身份，父调查显式引用后归并。未解析调用、部分 AST、文本符号命中和截断各自保留范围说明。

### 4.3 持久化和恢复

动作台账状态为 `prepared/dispatched/completed/ambiguous/failed`，记录稳定 operation ID、输入摘要、预算预留、执行回执和结果制品。状态保存使用 expected_version，子任务领取使用租约和 fencing token。

恢复时校验快照、上下文、配置、schema 和预算累计值。已完成动作读取持久结果。已经 dispatched 且缺少回执的模型或实验动作进入 ambiguous，任务进入 needs_attention，并通过任务现有恢复流程提交明确重试选择。operation ID 的本地去重与外部执行回执分别验证。

## 5. 文件职责

| 文件 | 职责 |
| --- | --- |
| 新增 `lima/cxx_investigation_models.py` | 调查、假设、证据、动作与子任务契约 |
| 新增 `lima/cxx_investigation_tools.py` | 快照与事实工具、权限和预算适配 |
| 新增 `lima/cxx_investigation_store.py` | 两类数据库的调查状态、动作和任务板存取 |
| 新增 `lima/cxx_investigator.py` | 持续调查、模型动作解析、状态更新和结果组装 |
| 新增 `lima/cxx_investigation_critic.py` | 独立反证调查及证据审查结果 |
| 新增 `lima/cxx_investigation_coordinator.py` | 子任务调度、租约、预算分配与归并 |
| 新增 `lima/cxx_investigation_reporting.py` | 持久调查状态到报告/API摘要的脱敏投影 |
| 修改现有 runtime、budget、repro、Scout、orchestrator | 各自增量接入已有入口和边界 |
| 修改 store、service、scanner、config、API | 持久恢复、配置和生产路径接线 |
| 修改现有任务详情并新增调查视图组件 | 展示动作、证据、假设版本和未决问题 |

新增模块以职责划分。实现中可合并规模很小的内部实现，但对外契约和测试归属按本文保持一致。

## 6. 审查重点

1. 老任务缺少调查字段或引用旧缓存时，仍可读取报告，执行选择保持可解释。由 T10、T11 验证。
2. Windows 目录联接、路径逃逸、跨租户或跨快照引用在工具执行前拒绝。由 T1、T3、T4 验证。
3. 两个 worker 争抢同一任务、预算临界并发和执行后失联时，结果与费用保持一致。由 T4、T6、T9 验证。
4. 编译失败、运行正常、driver 自身崩溃、错误类别不符和不完整 ASan 输出分别进入可解释状态。由 T5～T7 验证。
5. 大工具结果、协议错误、取消、deadline 和子任务失败能够终止并保留已获取证据。由 T2、T5、T9、T10 验证。

## 7. 实施任务

### T1 调查契约与证据身份

**文件**

- 新增 `lima/cxx_investigation_models.py`、`tests/test_cxx_investigation_models.py`。
- 回归 `tests/test_cxx_agent_models.py`、`tests/test_platform_contracts.py`。

**接口**

实现第 4 节数据结构，以及 `parse_investigation_action(raw: str) -> InvestigationAction`、`validate_evidence_reference(state: InvestigationState, evidence_id: str) -> InvestigationEvidence`。identity 一经创建由受信代码持有，模型回包只引用任务内 ID。

- [ ] 写失败测试 `test_action_rejects_unknown_fields`、`test_evidence_rejects_foreign_snapshot`、`test_final_rejects_unobserved_evidence`、`test_state_json_roundtrip_preserves_versions`，断言拒绝伪造引用，且 JSON 往返完整。
- [ ] 运行 `python -m pytest tests/test_cxx_investigation_models.py -q`，确认相关断言失败。
- [ ] 实现契约、字段范围、枚举、版本解析和证据引用校验。复用现有 untrusted JSON 解析。
- [ ] 运行新增测试及上述两组回归，预期通过。
- [ ] 精确暂存本任务文件并提交 `feat: define cxx investigation contracts`。

### T2 工具循环的取消、控制错误和结构化观察

**文件**

- 修改 `lima/runtime.py`、`lima/cxx_agent_tools.py`。
- 修改 `tests/test_runtime_memory_context.py`，新增 `tests/test_cxx_investigation_runtime.py`。

**接口**

对 `AgentLoop.run` 增加可选 keyword-only `cancel_check` 与 `fatal_exceptions`，旧调用使用缺省行为。对工具 registry 增加可选 result projector，使模型接收有界摘要，受信调用方保留完整结构化结果。CxxAgentBudget 增加版本化 `usage_snapshot() -> dict` 与 `from_usage(caps: dict, usage: dict) -> CxxAgentBudget`，恢复时校验累计值与上限。

- [ ] 写失败测试 `test_cancel_stops_before_next_tool`、`test_fatal_budget_error_escapes_loop`、`test_large_observation_retains_evidence_reference`、`test_budget_restore_cannot_reset_spend`。通用调用默认行为加入回归断言。
- [ ] 运行 `python -m pytest tests/test_cxx_investigation_runtime.py tests/test_runtime_memory_context.py -q`，确认新增行为失败。
- [ ] 实现可选扩展。C/C++ 调用明确配置预算、取消和 deadline 异常穿透。数据类结果先受信投影，再产生模型摘要和截断标记。
- [ ] 运行上述测试及 `tests/test_cxx_agent_tools.py`，预期通过。
- [ ] 提交 `feat: support controlled cxx investigation loops`。

### T3 快照读码、搜索、事实与上下文工具

**文件**

- 新增 `lima/cxx_investigation_tools.py`、`tests/test_cxx_investigation_tools.py`。
- 回归 `tests/test_workspace_reparse_boundary.py`、`tests/test_cxx_agent_tools.py`。

**接口**

`register_investigation_tools(registry: ToolRegistry, state: InvestigationState, context: InvestigationRuntimeContext) -> None` 注册 `read_source(path, start_line, end_line)`、`search_code(query, limit)`、`find_symbol(symbol, limit)`、`query_facts(path, symbol)`、`inspect_build_context(path)`。所有返回值含 evidence_id、scope、truncated 和结构化 payload。工具参数完整校验由专用解析负责，通用 registry 负责外层参数检查。

- [ ] 写失败测试 `test_search_then_read_records_real_lines`、`test_read_rejects_junction_escape`、`test_context_query_binds_artifact_digest`、`test_symbol_text_match_is_not_certified_call_edge`、`test_tool_output_privacy_scrub`，验证身份、范围和实际脱敏。
- [ ] 运行 `python -m pytest tests/test_cxx_investigation_tools.py -q`，确认失败。
- [ ] 实现基于固定 inventory 的有界搜索与读码。优先消费已有事实 bundle，缺少 AST/调用信息时返回明确能力缺口。Python 调查的可复用逻辑经适配后调用。
- [ ] 运行新增测试及两组回归，预期通过。
- [ ] 提交 `feat: expose evidence tools to cxx investigators`。

### T4 调查状态、动作台账与预算恢复

**文件**

- 新增 `lima/cxx_investigation_store.py`、`tests/test_cxx_investigation_store.py`。
- 修改 `lima/store.py`、`lima/postgres_store.py`，在两种 store 接入同一存取契约。

**接口**

定义 `InvestigationJournal` Protocol，提供 `load(identity)`、`save(state, expected_version)`、`prepare_action(identity, action_id, payload_digest, reservation)`、`mark_dispatched(identity, action_id)`、`complete_action(identity, action_id, receipt)`。实现 `CxxInvestigationStore`，数据库分别采用现有连接与事务方式，新增带 schema version 的调查、动作和预算表。

唯一身份包含 tenant/task/investigation，action_id 在调查内唯一。状态更新和预算预留同事务提交，预留、实际结算及余额有各自字段。为 T9 预留 children 与 fencing token 字段。

- [ ] 写失败测试 `test_expected_version_rejects_lost_update`、`test_action_and_budget_reservation_are_atomic`、`test_same_action_is_not_double_charged`、`test_dispatched_without_receipt_restores_as_ambiguous`、`test_foreign_tenant_cannot_load_state`。
- [ ] 运行 `python -m pytest tests/test_cxx_investigation_store.py -q`，确认失败。
- [ ] 实现 SQLite / PostgreSQL 等价事务、增量建表、错误回滚与恢复校验。模型调用记录真实 usage，可用时保存 provider usage，缺失时保留 bytes/calls 代理及缺失标记。
- [ ] 两类数据库运行同一行为测试。PostgreSQL 测试使用项目既有测试部署方式，环境缺失单独记录 pending。
- [ ] 提交 `feat: persist cxx investigations and action accounting`。

### T5 单线索 Investigator 持续调查

**文件**

- 新增 `lima/cxx_investigator.py`、`tests/test_cxx_investigator.py`。
- 修改 `lima/agent_orchestrator.py`，抽取或复用现有裁决适配所需最小入口。

**接口**

`run_investigation(state: InvestigationState, context: InvestigationRuntimeContext, policy: InvestigationPolicy) -> InvestigationResult`。model_step 消费当前状态摘要、可用工具及已观察证据，返回第 4 节动作。将 `record_hypothesis`、`revise_hypothesis`、`record_question` 注册为受校验状态工具。

- [ ] 写失败测试 `test_missing_ownership_evidence_triggers_read`、`test_failed_experiment_can_return_to_code_search`、`test_hypothesis_revision_preserves_prior_version`、`test_duplicate_action_without_new_state_stops`、`test_empty_final_remains_inconclusive`。
- [ ] 用脚本模型运行 `python -m pytest tests/test_cxx_investigator.py -q`，确认失败。
- [ ] 接入 T2～T4，每个动作保存目的、输入摘要、观察和假设变化。动作指纹由工具名、规范化参数、证据版本和假设版本构成。重复无进展动作达到上限时返回 inconclusive。
- [ ] 通过新增测试和 `tests/test_agent_orchestrator.py`。验证预算耗尽、取消和格式失败能保留既有证据。
- [ ] 提交 `feat: add persistent cxx investigator loop`。

### T6 可调整源文件集合的复现实验

**文件**

- 修改 `lima/agent_repro_tools.py`、`lima/cxx_investigation_tools.py`。
- 按实际协议需要修改 `cxx_analyzer/repro.py`、`lima/cxx_memory.py` 和 `cxx_analyzer/server.py`。
- 新增 `tests/test_cxx_investigation_reproduction.py`、`tests/fixtures/cxx_investigation/`。
- 回归 `tests/test_agent_repro_tools.py`、`tests/test_repro_protocol.py`、`tests/test_verified_view_registration_wiring.py`。

**接口**

注册 `run_reproduction(source_files, driver_code, hypothesis_id)`，身份、上下文 digest、deadline 与预算从 runtime context 注入。继续调用 `ReproWorkbench.run_experiment(..., verified_artifact_digest=...)`。复用当前协议最多 16 个源文件的能力，并明确单次编译命令对语言、flags 和链接依赖的限制。

- [ ] 写失败测试 `test_link_failure_can_add_real_dependency_source`、`test_source_set_rejects_out_of_scope_file`、`test_verified_digest_is_forwarded`、`test_driver_crash_does_not_confirm_target`、`test_ambiguous_dispatch_requires_explicit_resume`。
- [ ] 宿主 fake client 测试确认失败，真实容器夹具建立多源文件漏洞与对应修复版本。
- [ ] 实现实验结果到编译失败、环境失败、正常退出、其他故障、目标命中的结构化分类。完整日志保存为制品，模型读取有界诊断。动作台账保存实验回执，按当前协议能力处理不确定执行。
- [ ] 运行新增与回归测试，再在已有 CXX Docker profile 内运行真实 clang/ASan 夹具。分别记录 vulnerable 命中、fixed 正常与 driver-only 崩溃三个结果。
- [ ] 提交 `feat: let cxx investigators revise reproducible experiments`。

### T7 独立 Critic 的反证调查

**文件**

- 新增 `lima/cxx_investigation_critic.py`、`tests/test_cxx_investigation_critic.py`。
- 修改 `lima/cxx_investigator.py`，复用 `lima/uaf_orchestrator.py` 的裁决接口。

**接口**

`review_investigation(state, context, policy) -> CriticReview`，`CriticReview` 在 T1 模型模块中定义，包含 `assessment, evidence_ids, unresolved_questions, driver_contract_review`。assessment 为 `supports/refutes/insufficient`。Critic 从已绑定证据和原始工具结果独立核查，可继续搜索读码。

- [ ] 写失败测试 `test_critic_reads_caller_to_refute_ownership_claim`、`test_refutation_requires_observed_evidence`、`test_invalid_api_sequence_is_flagged`、`test_runtime_and_refutation_conflict_reaches_existing_arbiter`。
- [ ] 运行 `python -m pytest tests/test_cxx_investigation_critic.py -q`，确认失败。
- [ ] 在首次拟提交有效假设和 runtime 命中后执行独立复核，重复复核按证据/假设版本去重。支持已有证据冲突状态，并保留未决问题。
- [ ] 运行新增测试及 `tests/test_agent_orchestrator.py`、`tests/test_platform_contracts.py`，预期通过。
- [ ] 提交 `feat: add evidence seeking cxx critic`。

### T8 主动 Scout 与仓库线索调度

**文件**

- 修改 `lima/agent_scout.py`、`lima/agent_orchestrator.py`。
- 新增 `tests/test_cxx_scout_exploration.py`，回归 `tests/test_agent_scout.py`、`tests/test_platform_scope_budget.py`。

**接口**

增加 `explore_leads(workspace, initial_leads, context, policy) -> ScoutReport`，复用已有目标/排除/未解决输出。新增线索带来源 evidence_id，并在服务端重绑已审核 inventory 中的文件和真实行号。维护队列的优先级理由、已调查身份和未覆盖 TU。

- [ ] 写失败测试 `test_scout_search_finds_new_in_scope_lead`、`test_new_lead_requires_observed_location`、`test_duplicate_leads_merge_provenance`、`test_budget_exhaustion_preserves_unreviewed_units`、`test_no_seed_still_allows_bounded_exploration`。
- [ ] 运行新增测试并确认失败。
- [ ] 以固定快照索引和工具目录启动 Scout，允许搜索后追加线索和调整优先级。初始线索来源、LLM fallback 与探索消耗分别统计，避免重复扫描与重复调用。
- [ ] 运行新增测试及上述回归，预期通过。
- [ ] 提交 `feat: enable evidence driven cxx scout exploration`。

### T9 共享任务板与按需多智能体委派

**文件**

- 新增 `lima/cxx_investigation_coordinator.py`、`tests/test_cxx_investigation_coordinator.py`。
- 修改 `lima/cxx_investigation_models.py`、`lima/cxx_investigation_store.py`、`lima/cxx_investigation_tools.py`。
- 回归 `tests/test_multi_agent_collaboration.py`、`tests/test_agent_scale.py`。

**接口**

定义 `ChildTask`，包含 parent identity、child ID、role、question、scope、input evidence IDs、budget reservation、status、lease owner/expiry、fencing token、result evidence IDs。`InvestigationCoordinator.submit(parent, role, question, scope, evidence_ids) -> ChildTask`，`claim(child_id, worker_id) -> ChildTask`，`complete(child_id, result, fencing_token) -> None`，`collect(parent_id) -> tuple[ChildTask, ...]`。

向父调查注册 `delegate_subtask(role, question, paths, evidence_ids)` 与 `collect_subtasks()`。子任务拥有工具权限子集，使用共享总预算和继承 deadline。父调查线程持续拥有状态写入权，子任务写自身结果，再由父调查归并。

- [ ] 写失败测试 `test_two_independent_children_merge_evidence`、`test_child_cannot_delegate_at_depth_one`、`test_two_workers_cannot_complete_same_lease`、`test_parallel_reservations_never_exceed_parent_budget`、`test_cancel_propagates_and_preserves_completed_child`、`test_disagreement_returns_open_question`。
- [ ] 运行 `python -m pytest tests/test_cxx_investigation_coordinator.py -q`，确认失败。
- [ ] 实现单一负责人、最多 2 个在途子任务与一层委派。子任务能力由角色映射到工具白名单。失效租约的迟到结果通过 fencing token 拒绝，完成后的证据可重复读取。
- [ ] SQLite / PostgreSQL 运行同一租约和预算竞争测试，执行两组回归。
- [ ] 提交 `feat: coordinate bounded cxx investigation teams`。

### T10 正常服务入口、配置、恢复和结果兼容

**文件**

- 修改 `lima/config.py`、`lima/service.py`、`lima/repository_scanner.py`、`lima/agent_orchestrator.py`、`lima/agent_scale.py`。
- 按报告映射需要修改 `lima/platform_contracts.py`。
- 新增 `tests/test_cxx_investigation_service.py`，扩展 `tests/test_repository_agent_modes_integration.py`。
- 修改 `.env.example` 和 `docs/AGENT_VULN_PLATFORM.md` 的对应配置说明。

**接口与配置**

增加 `LIMA_CXX_INVESTIGATION_STRATEGY=pipeline/investigator/team`，初始缺省为 pipeline，分别用于冻结旧基线、单调查及完整协作。它与 agent mode 正交。新增 action steps、max children、delegation depth 三项配置对应第 3 节缺省值，pipeline 接受旧配置。

服务显式传入 task/tenant identity、journal 和 cancel/progress。现有 resume 请求增加可选 `allow_ambiguous_retry`，服务端 RBAC 校验后才重新调度不确定动作。新策略输出继续投影 PlatformReviewOutcome / PlatformFinding，缓存身份增加 strategy、schema、policy、context、tool catalog 和 prompt digest。

- [ ] 写失败测试 `test_off_has_zero_calls_in_all_strategies`、`test_real_service_scanner_store_chain_records_actions`、`test_old_payload_uses_pipeline_default`、`test_auto_and_required_keep_failure_semantics`、`test_ambiguous_resume_needs_authorized_explicit_choice`、`test_cache_isolated_by_strategy_and_context`。
- [ ] 运行新增集成测试确认失败，fake 仅替换模型 transport 与沙箱边界。
- [ ] 贯通入队、worker、scanner、调查、持久状态、结果保存与恢复。对取消和 required 失败保留调查制品，旧报告读取缺省为空。
- [ ] 运行新增测试及 agent modes、build consumption、verified delivery、scan cancellation 相关既有测试，核对选中策略的实际调用轨迹。
- [ ] 提交 `feat: wire cxx investigations through repository scans`。

### T11 调查报告、API 与前端时间线

**文件**

- 新增 `lima/cxx_investigation_reporting.py`、`tests/test_cxx_investigation_reporting.py`。
- 修改 `lima/api.py`、`lima/agent_report.py`、`frontend/src/shared/api/types.ts`、`frontend/src/features/tasks/TaskDetailPage.tsx`。
- 新增 `frontend/src/features/tasks/CxxInvestigationTimeline.tsx` 及同目录测试，扩展 `TaskDetail.report.test.tsx`。

**接口**

`build_investigation_summary(state, actions, children) -> dict`，通过现有 task/report 结构新增可选 `collaboration.platform.investigations` 摘要。动作/证据详情使用新增分页 `GET /v1/tasks/{task_id}/investigations/{investigation_id}`，query 为 cursor/limit，响应含 items/next_cursor。每次查询使用现有任务访问控制和制品读取校验。

- [ ] 写失败测试 `test_old_report_renders_without_investigations`、`test_timeline_distinguishes_compile_failure_and_clean_run`、`test_foreign_task_detail_is_forbidden`、`test_pagination_retains_order_and_redaction`、`test_ambiguous_action_displays_needs_attention`。
- [ ] 运行新增后端测试和前端目标测试确认失败。
- [ ] 展示当前问题、假设版本、工具动作、简短行动理由、支持/反驳证据、子任务、预算和停止原因。详细日志按需分页加载，证据引用关联实际制品。
- [ ] 运行后端目标测试，在 frontend 目录运行 `npm run typecheck`、`npm test -- src/features/tasks/CxxInvestigationTimeline.test.tsx src/features/tasks/TaskDetail.report.test.tsx`、`npm run build`，预期通过。
- [ ] 提交 `feat: show cxx investigation evidence and progress`。

### T12 配对评测、真实执行与发布验收

**文件**

- 修改 `scripts/run_platform_evaluation.py`、`tests/test_platform_evaluation.py`。
- 新增 `evaluation_data/cxx_investigation_cases/cases.json`、`tests/test_cxx_investigation_evaluation.py`，扩充 T6 夹具。
- 新增 `docs/CXX_AGENT_INVESTIGATION_VALIDATION.md`，记录命令、版本、环境和实际结果。

**接口与样本**

为现有 evaluator 增加 `--strategy pipeline/investigator/team` 和 `--compare-strategies`，使用同一评测实现聚合逐例记录。配对运行冻结 model/provider、snapshot、context、总预算、工具能力、timeout 和重复次数，记录 prompt/tool digest 与不同策略的固有差异。按预注册顺序交错执行策略，记录失败与预算耗尽样本。

在已有配对基准之外加入至少 8 组专项场景，包括跨文件所有权、链接依赖补齐、错误分支触发、调用方反证、driver 误用、正常运行但路径未达、模糊执行恢复、独立子任务证据冲突。行为场景可使用协议夹具，漏洞确认场景使用真实源码 vulnerable/fixed 对。标签仅在评测端读取。

- [ ] 写失败测试 `test_three_strategies_use_same_case_identity`、`test_labels_never_enter_model_context`、`test_budget_and_incomplete_cases_remain_in_denominator`、`test_trace_metrics_derive_from_records`、`test_scripted_results_carry_fake_marker`。
- [ ] 运行 `python -m pytest tests/test_cxx_investigation_evaluation.py tests/test_platform_evaluation.py -q`，确认新增断言失败。
- [ ] 扩展逐例记录和聚合，输出检测率、误报率、runtime-confirmed 数、复现稳定性、有效取证动作、重复无进展动作、跨文件取证、恢复成功、委派完成、calls/bytes/tokens/耗时和可得实际费用。零分母沿用 null 与 diagnostic。
- [ ] 完成脚本模型行为验收，再完成真实模型加真实 Sidecar 运行。费用、模型与执行授权沿用执行会话明确范围，待取得的运行条件在报告中逐项列出。
- [ ] 执行 `python -m pytest tests -q`，记录通过、失败、skip 和环境依赖。执行前端 T11 命令，核对服务入口产生的持久结果。
- [ ] 提交 `test: validate cxx investigation strategies`，附逐例 records、实验配置和结果制品引用。

## 8. 依赖、里程碑与工作量

采用两次交付。第 7 节的 T1～T12 描述最终范围，每个任务的完整完成条件在第二次交付时统一核对。首次交付优先接通已有 runtime、工具和工作台。

```text
首次交付
T1/T2 最小契约与循环 → T3/T5/T6 调查与实验
    → T7/T8 反证与探索 → T9 有界委派
    → T10 正常入口 + T12 小样本配对验收

第二次交付
T4 持久台账 + T9 跨 worker 租约与恢复
    → T10 恢复接口 + T11 完整前端
    → T12 双数据库与完整配对验收
```

### 8.1 首次交付，三层能力可运行

| 切片 | 对应任务 | 交付与检查 | 规划估算 |
| --- | --- | --- | --- |
| 单线索自主调查 | T1/T2/T3/T5/T6 | 复用工具循环、主动读码、假设修订、多源文件 ASan 实验 | 1～2 工作日 |
| 探索与反证 | T7/T8 | Scout 补充线索，Critic 调用工具核对反证 | 0.5～1 工作日 |
| 多智能体协作 | T9 的单 worker 调度 | 父调查按需启动最多两个专业子任务，共享预算并归并证据 | 0.5～1 工作日 |
| 服务入口与小样本验收 | T10/T12 的首批集成 | 从现有扫描入口执行，保存动作和证据摘要，比较三种策略 | 1 工作日 |

首次交付约 3～5 工作日。先用运行内 journal 实现统一接口，完成报告沿用现有存储。父调查和子任务由同一 worker 持有，进程中断后显式标记调查未完成。对外部执行结果不确定的动作保留 ambiguity，恢复策略在第二次交付验收。

首次验收选择跨文件取证、实验依赖调整、调用方反证和专业子任务归并四类场景，其中漏洞确认场景运行真实 Sidecar。动作计费、路径范围、证据引用、取消和验证等级边界纳入首次回归。前端先使用现有任务详情中的报告与轨迹展示。

### 8.2 第二次交付，完成生产化验收

补齐 T4、T9 的跨 worker 租约和持久预算、T10 的恢复链、T11 的分页调查视图，以及 T12 的完整场景和两类数据库测试。暂估追加 3～5 工作日，累计约 6～10 工作日。

上述数字是基于复用现有代码的排期假设，待首个切片实际完成后按改动量、测试结果和构建环境校准。模型服务、Sidecar 和数据库可用，且当前未提交接口变更已明确归属，是该估算的前提。此前 21～33 人日按完整范围逐项独立建设累计，未充分计入现有工具与调查逻辑的复用，本次用分次交付估算替代。

T1 稳定后可并行准备独立夹具和报告投影，共享文件由一个执行者负责。每个 Implementation Packet 冻结当前切片的接口、验证命令和证据要求。

## 9. 最终验收清单

- [ ] 工具能力、单线索调查和多智能体协作均从正常仓库扫描入口可达。
- [ ] 同一条调查在实验反馈后能够主动回到读码或事实查询，假设版本与证据引用可核对。
- [ ] 主动 Scout 能定位已审核范围内的新线索，并记录覆盖缺口。
- [ ] 父调查能够委派 ownership/reachability/reproduction/critic 专业任务，子任务结果有独立证据和预算记录。
- [ ] 真实多源文件实验通过受信构建上下文运行，runtime 命中满足现有裁决检查。
- [ ] 中断、并发领取、取消、预算耗尽与 ambiguous 执行均通过恢复测试。
- [ ] SQLite 与 PostgreSQL 通过一致性验收，旧任务、报告、调用模式和缓存兼容行为有回归证据。
- [ ] 前端展示真实状态、行动理由、假设变化、证据与子任务，详细日志分页且经过访问控制与脱敏。
- [ ] 三种策略使用一致实验条件产生可重算 records，脚本模型与真实模型运行分别标记。
- [ ] 调用次数或检出效果的变化由结果报告给出，发布结论引用实际实验记录。

## 10. 本计划采用的工程建议

以下为本次编制时提出、供执行前核对的选择。

- 新增 pipeline/investigator/team 三策略作为渐进接入和评测方式，初始缺省采用 pipeline，验证后再决定生产缺省值。
- 首期使用现有 ASan 和最多 16 源文件的复现协议，完整构建目标支持后续独立扩展。
- 每调查 24 个动作、最多 2 个在途子任务、一层委派为建议值。首次交付约 3～5 工作日，完整验收累计约 6～10 工作日，待首个切片完成后校准。
- 调查状态采用独立版本化存储，复用现有任务访问控制、恢复入口和通用 runtime。
- 当前交付物为开发计划，验收清单待实施与运行证据逐项填写。
