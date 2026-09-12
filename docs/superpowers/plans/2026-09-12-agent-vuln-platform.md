# 通用智能体漏洞挖掘平台实施计划

依据设计：`docs/superpowers/specs/2026-09-12-agent-vuln-platform-design.md`
基线：HEAD 待定（以动工时为准；当前 `756c985`，宿主全量 1425 OK skipped 16）
工作流沿用：每任务 TDD（RED→GREEN）→ 复审 → 目标回归 → 单任务精确清单提交；
里程碑任务（T1/T4/T8/T11）跑双平台全量（宿主 mirror + 容器，pathspec 同步法）。

硬边界：受保护文件（根 `Dockerfile`、`tests/test_service.py`）只运行不编辑；
`.superpowers/` 不入库；改 `ANALYZER_COMPONENTS` 文件的任务最后一步刷新校准指纹；
沙箱五层锁不放宽。

通用命令：`PY=./.venv/Scripts/python`（worktree 根目录执行）。

---

## Task 0: 设计入库与资产盘点

**Files:**
- Add: 本计划文档 + `docs/superpowers/specs/2026-09-12-agent-vuln-platform-design.md`
- Create: `docs/AGENT_VULN_PLATFORM.md`（面向评委的架构总览，技术说明书骨架）

**Steps:**
- [ ] 0.1 设计/计划文档用户确认后入库
- [ ] 0.2 `AGENT_VULN_PLATFORM.md` 写五层漏斗图、资产复用映射表（阶段 A 沙箱/
  阶段 B 管线/UAF v2 资产 → 新角色）、赛题评分项映射表
- [ ] 0.3 提交：`docs: specify agent vulnerability platform`

---

## Task 1: 复现工作台——Sidecar 编译运行层（里程碑）

设计依据：§5。在 Sidecar 新增版本化 `/v1/repro` 端点：请求（快照、源文件集、
PoC 驱动代码、入口、预算）→ 沙箱内 clang++ -fsanitize=address 编译并运行 →
结构化返回（编译诊断/退出码/ASan 解析：错误类型、faulting frame 行号列、
freed-by/allocated-by 栈、截断标记）。实验台账记录输入哈希/产物哈希/耗时/结论。

**Files:**
- Create: `cxx_analyzer/repro.py`（编译运行 + ASan 报告结构化解析）
- Create: `tests/fixtures/repro/`（正例：UAF/越界/干净三驱动；负例：编译失败、
  超时、输出爆炸、驱动读写快照外路径）
- Modify: `cxx_analyzer/server.py`（`/v1/repro` 端点，独立版本化，不动旧端点）
- Modify: `lima/cxx_memory.py`（`repro_compile_run` 客户端 + 严格校验）
- Create: `tests/test_repro_protocol.py`

**Steps:**
- [x] 1.1 RED：`$PY -m unittest tests.test_repro_protocol -v`
  - `ServerContractTests.test_unknown_request_field_rejected` /
    `test_driver_code_size_capped` / `test_response_carries_run_identity_and_hashes`
  - `ClientContractTests.test_malformed_asan_report_rejected` /
    `test_transport_error_maps_to_unavailable`
- [x] 1.2 RED（提取器）：`tests/test_cxx_analyzer.ReproTests`
  - `test_uaf_driver_produces_structured_asan_report`（faulting frame 行号命中）
  - `test_clean_driver_returns_zero_exit_without_report`
  - `test_compile_failure_returns_diagnostics_not_crash`
  - `test_driver_path_escape_rejected` / `test_timeout_kills_process_tree` /
    `test_oversized_output_truncated_flagged`
- [x] 1.3 GREEN（宿主协议 fake）
- [x] 1.4 容器实证：真实 clang-14 + ASan 三驱动正例 + 超时/输出爆炸负例
- [x] 1.5 里程碑全量（宿主 + 容器）
- [x] 1.6 提交：`feat: add reproducible ASan workbench endpoint`

---

## Task 2: 复现工具封装与 PoC 驱动模板

设计依据：§5.1。把 `/v1/repro` 包装为智能体工具 `compile_and_run_asan`；
按漏洞类型包提供驱动骨架模板（内存包：堆 UAF/越界/双释放/空指针）。

**Files:**
- Create: `lima/agent_repro_tools.py`（工具封装：入参校验、结果→智能体观察格式、
  预算扣减、实验台账装配）
- Create: `lima/repro_templates.py`（驱动模板：每 CWE 一个最小骨架 + 占位符约定）
- Create: `tests/test_agent_repro_tools.py`

**Steps:**
- [x] 2.1 RED：工具合同（schema 校验/预算/台账/结果转观察文本转义）
- [x] 2.2 RED：模板合同（每模板可编译占位展开、类型正确、无网络/文件副作用声明）
- [x] 2.3 GREEN → 目标回归 → 提交：`feat: expose ASan workbench to agents`

---

## Task 3: Scout 智能体（侦察筛选循环）

设计依据：§6。线索清单→自主排查→目标清单；目标选取不再固定前 16。

**Files:**
- Create: `lima/agent_scout.py`（侦察循环：线索批处理、读码排查、可疑度升级/
  排除理由、产出 `ScoutReport{targets, reasons, discarded}`；受预算/轮数约束）
- Create: `tests/test_agent_scout.py`

**Steps:**
- [x] 3.1 RED（Fake LLM）：循环推进/排除理由留痕/预算耗尽诚实降级/
  线索零命中安静返回/伪造路径拒收
- [x] 3.2 GREEN → 回归 → 提交：`feat: add autonomous scout agent`

---

## Task 4: 假设-实验-修正闭环编排 + v2 编排退役（里程碑）

设计依据：§6、§10。Specialist 假设 → 复现实验 → 不命中修正重来（多轮）；确定性
事实/证明作为可咨询仪器（PASS/REFUTED 为证据来源而非关卡）；终态裁决沿用状态机
（runtime-confirmed 仅实证可达）。**本任务同时退役 v2 编排**（proof-before-LLM
路由、UNKNOWN-only 门控、scanner uaf_v2 双链接线），同一提交内删除与切换。

**Files:**
- Create: `lima/agent_orchestrator.py`（漏斗第 1–4 层编排）
- Create: `tests/test_agent_orchestrator.py`
- Modify: `lima/repository_scanner.py`（**指纹组件——校准刷新**：uaf_v2 分支替换为
  平台分支）
- Modify: `lima/uaf_llm_branch.py`（UNKNOWN-only 门控移除，Specialist/Critic 直接
  可用；合同与传输保留）
- Delete/重构: `lima/uaf_orchestrator.py` 的 proof-first 编排路由（事实/证明调用
  逻辑抽为仪器接口保留）；对应编排测试改写
- Modify: `tests/test_uaf_orchestrator.py` → `tests/test_uaf_instruments.py`
  （仪器层用例保留，编排路由用例改写进平台测试）

**Steps:**
- [x] 4.1 RED（Fake LLM + Fake repro）：
  - `test_hypothesis_experiment_revision_loop_converges`（首轮 PoC 不命中→修正→命中
    → runtime-confirmed，实验台账两次留痕）
  - `test_runtime_confirmed_requires_executed_asan_evidence`
  - `test_specialists_run_without_proof_gate`（v2 退役证据： Specialist 不等
    证明放行；proof 仪器仅在智能体咨询时调用）
  - `test_proof_engine_consultable_as_instrument`（咨询 → PASS/REFUTED 作为 D2
    证据进裁决）
  - `test_revision_rounds_bounded_by_dialogue_rounds_and_budget`
  - `test_fp_discipline_low_confidence_states_without_evidence`
  - `test_scanner_runs_single_agent_chain`（双链分支不复存在的源码级断言）
- [x] 4.2 GREEN（含 v2 退役与测试迁移）
- [x] 4.3 里程碑全量（宿主 + 容器）
- [x] 4.4 校准指纹最后刷新（repository_scanner 变更）
- [x] 4.5 提交：`feat: replace deterministic-first orchestration with agent loop`

---

## Task 5: 内存漏洞包补全（论文核心）

空指针解引用 + 整数溢出致内存破坏两个新 Specialist 角色 + 分诊种子（空指针：
解引用模式；整数溢出：长度算术前置溢出）+ PoC 驱动模板 + 配对基准；包插件接口
固化（`VulnPack{specialist_prompts, seeds, templates, asan_rules, cwe_map}`）。

**Files:**
- Create: `lima/vuln_packs/__init__.py`（插件接口）、`lima/vuln_packs/memory.py`
- Create: `tests/fixtures/vuln_packs/memory/`（新类型配对样例）
- Create: `tests/test_vuln_packs.py`
- Modify: 分诊检索接入包种子（`lima/cxx_retrieval.py` 仅扩展不破坏）

**Steps:**
- [x] 5.1 RED：包接口合同 + 新类型端到端（分诊→假设→实验命中）
- [x] 5.2 GREEN → 回归（旧四类行为不变）→ 提交：`feat: complete memory vulnerability pack`

---

## Task 6: 报告智能体与 CVE 离线匹配

eRST 式档案生成（基本信息/概览/技术分析/复现指南/影响/披露）；CVE 本地库匹配
（无库时跳过并标注，不臆测）。

**Files:**
- Create: `lima/agent_report.py`、`evaluation_data/cve_index/`（离线索引 + 装载脚本）
- Create: `tests/test_agent_report.py`

**Steps:**
- [x] 6.1 RED：报告字段齐全/复现命令真实可粘贴/无实证不写"已确认"/CVE 匹配
  正反例（时间窗/组件/位置三键匹配；无匹配标注待评审）
- [x] 6.2 GREEN → 提交：`feat: generate dossier reports with CVE matching`

---

## Task 7: git 影响范围挖掘

引入提交定位 → 分支传播 → 版本范围。

**Files:**
- Create: `lima/impact_mining.py`（blame/log/branch-contains 的有界封装，
  只读、无网络、行号漂移容忍规则显式化）
- Create: `tests/test_impact_mining.py`（本地 fixture 仓库构造多分支历史）

**Steps:**
- [x] 7.1 RED：引入提交/分支包含/版本范围三判定 + 行漂移边界
- [x] 7.2 GREEN → 提交：`feat: mine vulnerable version impact from git history`

---

## Task 8: 补丁建议与 PoC 回归验证（里程碑）

智能体出补丁 → 应用补丁重跑 PoC → 不再触发才标"验证通过的修复建议"。

**Files:**
- Create: `lima/agent_patch.py`（补丁生成合同 + 应用 + 回归验证循环）
- Create: `tests/test_agent_patch.py`

**Steps:**
- [ ] 8.1 RED（Fake）：补丁应用失败诚实报告/PoC 仍触发则不标通过/
  补丁验证预算受控/回归通过才入报告
- [ ] 8.2 GREEN → 里程碑全量 → 提交：`feat: verify agent patches by PoC regression`

---

## Task 9: 规模化与参赛部署 profile

并行（独立沙箱实例并行实验）、缓存（snapshot+输入哈希键）、增量；参赛部署
profile：快照限额放开参数组、tmpfs/内存加大、受信构建门禁开启指引、离线依赖
预处理流程文档。

**Files:**
- Modify: `lima/agent_orchestrator.py`（并行/缓存/增量）
- Create: `deploy/competition/README.md` + `.env.competition.example`
- Create: `tests/test_agent_scale.py`

**Steps:**
- [x] 9.1 RED：缓存键/失效/并行确定性（结果按目标序聚合）/增量变更检测
- [x] 9.2 GREEN → 提交：`feat: scale agent scans with caching and parallelism`

---

## Task 10: 评测扩展与双仓库验证

配对基准按包扩展（含"需修正假设才命中"样例）；比赛指标映射采集（PoC 重复
运行稳定性 N 次统计）；油气仓库（ResInsight/OPM 子集）论文侧运行记录。

**Files:**
- Modify: `scripts/run_uaf_v2_evaluation.py` 或新增 `scripts/run_platform_evaluation.py`
- Create: `evaluation_data/platform_cases/`
- Create: `tests/test_platform_evaluation.py`

**Steps:**
- [ ] 10.1 RED → GREEN → 提交：`test: benchmark the agent vulnerability platform`

---

## Task 11: 交付件（里程碑）

技术说明书（设计文档扩写）、使用说明书 + DEMO 视频脚本、性能数据采集报告。

**Files:**
- Create: `docs/competition/技术说明书.md`、`docs/competition/使用说明书.md`、
  `docs/competition/DEMO脚本.md`、`docs/competition/性能数据.md`
- Steps: 全量双平台收官 → 提交：`docs: prepare competition deliverables`

---

## 依赖与里程碑

0 独立；1→2→(3,4)；5 依赖 4（闭环需要）；6 依赖 4；7/8 依赖 6；9 依赖 4；
10 依赖 5/6/8；11 收官。里程碑全量回归：T1/T4/T8/T11。Task 4 含 v2 编排退役
（单一智能体链，仪器保留——设计 §10）。

## 论文复用映射

内存包（Task 5）+ 复现工作台（Task 1/2）+ eRST 报告（Task 6）+ 油气仓库验证
（Task 10）= 论文实验章节主体；OpenHarmony 仅为仓库接入差异。

---

## 实施记录

- **Task 1（提交见 git log）**：除计划内容外，容器实证发现 ASan 运行时在受限容器（drop ALL caps + 非 root + 只读根）下有 ~30% 概率渲染自身段错误（exit -11 无任何报告输出，clang-14 已知类问题）。产品修复：run_repro 运行阶段对 `SIGSEGV+无报告` 自动重试（最多 3 次尝试，共享 deadline），耗尽后 ok=False + `asan-runtime-segv-retried` 诊断。容器 3 连跑全 OK。全量 1462 OK (skipped 20) 双平台。

---

## 实施记录

- **Task 4（里程碑）**：v2 编排退役落地——proof-before-LLM 路由/UNKNOWN 门控/scanner 双链删除；仪器接口保留（instrument_facts/proof/broker、arbiter_state）；review_uaf 暂保留为冻结 v2 评测链（评测脚本耦合，Task 10 迁移）。平台编排单链：Scout→Specialist假设→实验→Critic修正→仪器咨询（非门禁）→Arbiter。校准指纹第 6 次刷新（c910ffa1…）。全量 1512 双平台 OK。镜像同步注意：删除的测试文件需在 mirror 手动 rm（tar 增量不删文件）。
