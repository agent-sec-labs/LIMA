# LIMA Implementation Packet — IP-0027 Baseline Collection Foundation（采集原语 + SF-01 role 门 + RunResult 独立落盘）

> Packet ID：IP-0027
> Packet 版本：1.0（2026-09-25，阶段 P / C1 单次提交，不回填）
> 状态：**PHASE-P-IN-PROGRESS**（阶段 P 进行中；C2 Frozen Test Commit 落盘后 READY-FOR-CODE 由 commit SHA 链
> 与 #212 Delivery Ledger 反映——SHADOW 模式单 PR 拓扑，影子证据锚点 = C1/C2 commit SHA）
> Packet 作者：lima-packet-verification（P&V）
> Coordinator Assignment：CA-IP-0027-v1.0（2026-09-25；本 Packet 的约束权威，R1-R10 全文照录登记于 §11）
> 精确基线：`2f4b8bb4c06475ed6a45b541f89ba0ce6e6856d7`（完整 40 位 = PR #211 合并点 = origin/main，亲验）
> 工作分支：`codex/ip-0027-baseline-collection`（worktree `D:\BaseAIProject\LIMA-ip-0027-wt`）
> Source Issue：#212（叶子，open）；Parent #57 仅背景，保持打开
> Frozen Test Commit：C2（本 Packet 提交后由 P&V 产生；精确 SHA、RED 证据与验收面摘要登记于 C2 commit
> message 与 P&V 阶段 P 交付记录，本文件按"单次提交"纪律不回填）

---

## 0. 交付物角色声明（强制，先于一切）

本切片的"实现产物"是 `benchmarks/v4/baseline/` 独立包下的 **6 个 Python 文件**（3 个包标记 + 3 个含逻辑
模块），加上 2 个 P&V 阶段产物（本 Packet + 冻结测试文件），恰为 Assignment §R1 的 8 个 Add 路径。
**`benchmarks/v4/baseline/` 下的 6 个文件是 Implementation（阶段 C3+）的实现交付物，不是 P&V fixture。**
P&V 的交付物只有本 Packet（C1）与 `tests/test_v4_baseline_collection.py`（C2 Frozen Test Commit）。

本轮**零 `lima/` 产品代码、零 `scripts/` 修改、零 `evaluation_data/` 修改、Modify 文件数 = 0**（R1/R6）。
若实施中发现"必须改冻结契约/脚本/数据才能满足验收"：停止，提交 Decision Request，不得静默新增。

## 1. 需求映射（Packet 头）

```text
Source Issue：#212（父 #57）
Issue specification revision：2026-09-25 创建版正文（Coordinator GitHub API 亲验：Scope 1-8、Non-goals、Coverage gaps、AC-1..AC-4、Packet 段）
Covered requirements：FR-01…FR-08、AC-1…AC-4（本切片范围；FR-06 为受限部分，见下）
Not covered requirements：见 §4 Non-goals（= Assignment Not-covered 12 条全文照录）
Delivery role：vertical-slice（#57 PR2 执行与采集基础）
Issue closure impact：PARTIAL（#212 按 Ledger 走 MANUAL-AFTER-POST-MERGE-AUDIT；本 IP 不宣告任何 Issue 完成）
Upstream IP/merge commits：IP-0024（lima/baseline_run_spec.py）、IP-0025（lima/baseline_run_result.py）、
  IP-0026（evaluation_data/v4/baseline_manifest.json + 支持矩阵，merge 2f4b8bb）——均在基线内冻结，本轮只读消费
```

FR-01..FR-08 为 Coordinator 对 #212 "Scope (this slice)" 1-8 的规范化编号（语义不变，CA-IP-0027-v1.0）；
AC-1..AC-4 沿用 Issue 原文编号（登记于 #212 Delivery Ledger 初始版）。

| ID | 内容（#212 Scope 1-8） | 本 Packet 贡献方式 |
|---|---|---|
| FR-01 | 采集原语：wall/queue wait/CPU 计时（时钟非单调守卫）、peak RSS、IO bytes、token 计数与 estimated cost 字段、专家计时协议适配（#57 FR-05 部分） | `benchmarks/v4/baseline/collect.py`（§7.1）+ `expert_timing.py`（§7.2）；stdlib-only、源可注入（R5） |
| FR-02 | RunResult 稳定落盘：独立 result 文件不覆盖历史、canonical JSON（UTF-8、稳定 key 顺序、SHA-256 封存）、失败 run 写 bounded taxonomy 并保留 | `benchmarks/v4/baseline/run.py` writer（§7.3，R3 命名/目录裁定）；复用 IP-0025 `from_mapping/canonical_bytes`，不另造编码器 |
| FR-03 | 冻结契约只读消费：`BaselineRunSpec`（IP-0024）与 `BaselineRunResult`（IP-0025） | 只 import（§5 消费清单）；冻结面 diff 必空（AC-4） |
| FR-04 | SF-IP-0026-20260925-01 硬入口条件：manifest 消费端在消费 manifest 或开始扫描前显式校验 dataset→role 绑定；不得仅依赖 `validate_baseline_manifest`；必须覆盖自洽角色对调 fail-closed 负例 | `validate_role_bindings` 三层校验 + 冻结角色注册表（§7.3.1，R2）；负例 1-5（§8） |
| FR-05 | 身份与指纹消费侧：不可变 commit、指纹变化改变 run identity、moving ref/缩写 SHA fail closed | 委托冻结 `from_mapping`/`validate_baseline_manifest` 语义透传，runner 路径负例证明（§8 负例 6） |
| FR-06 | CLI 入口与离线验证（**受限部分**） | 离线验证全部执行；**零 `scripts/run_*.py` 修改**（R6）——#57 FR-02 CLI 部分本切片不标 satisfied，留 PR3 接线 |
| FR-07 | 验证全部离线：断网、无 Secret、无付费模型、默认 CI smoke 不联网（#57 NFR-02 适配） | stdlib-only + 离线卫生源扫描测试（§8 负例 13）+ import 白名单测试 |
| FR-08 | 正例 + fail-closed 负例（含 SF-01 角色对调负例） | C2 测试矩阵（§8）：26 方法，13 类负例面全覆盖 |

| ID | 内容（#212 验收） | 验证方式 |
|---|---|---|
| AC-1 | 采集与落盘 canonical 稳定、SHA-256 封存、独立文件不覆盖 | TestRunRecording + TestWriter + TestClockGuardAndSources（§8） |
| AC-2 | role 门 + 全负例面 typed error fail closed（含自洽对调、moving ref、缩写 SHA、指纹漂移） | TestRoleBindingGate + TestRunnerIdentityGates（§8 负例 1-7） |
| AC-3 | 全离线 + 冻结测试先行有效 RED | C2 RED 证据（模块缺席态）+ TestPublicSurfaceAndHygiene |
| AC-4 | IP-0024/0025/0026 冻结面与生产扫描语义零改动 | File Boundary Gate（§9 命令 5/6/7；Modify = 0） |

## 2. Design Input Manifest

| Input ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001 | Standard | `docs/LIMA_PACKET_AND_VERIFICATION_AGENT_RESPONSIBILITY_CHARTER.md` | 基线 2f4b8bb 内版本 | P&V 角色边界、Pre-Freeze Harness Gate、RED/冻结纪律 | normative | 无冲突 |
| DI-002 | Issue | Source Issue #212 正文（Scope 1-8、Non-goals、Coverage gaps、AC-1..4、Packet 段） | 2026-09-25 创建版（Coordinator API 亲验转述于 Assignment） | FR-01..08、AC-1..4 | normative | 无冲突 |
| DI-003 | Issue | Parent #57（File ownership、输出契约、PR plan、Required tests） | 基线 2f4b8bb（Assignment 亲验） | Add 边界 `benchmarks/v4/baseline/`、FR-05 适配、NFR-01/02、PR3 切分 | 边界 normative / 其余 background | #57 Modify 权限（scripts）本切片不使用（R6） |
| DI-004 | Decision | CA-IP-0027-v1.0 全文（R1-R10、Allowed Files 8 路径、§8 验收命令、Stop Conditions、ALLOWED_ONCE） | 2026-09-25 | 本切片全部边界与裁定 | normative（本切片最高活动权威） | 与历史文档冲突时以 Assignment 为准 |
| DI-005 | Intent | `.pv_tmp/INTENT_RECORD_IP-0027_2026-09-25.md`（INTENT-IP-0027-20260925-01，M1-M9/P1-P2/I1-I8/A1-A4/B1-B6） | 2026-09-25 | 需求语义、授权原文、SF-01 盲区取证（I3）、承载边界（I4） | normative（经 Assignment 消费） | 无冲突 |
| DI-006 | Code | `lima/baseline_run_spec.py`（752 行全文亲读 @ 2f4b8bb；role 枚举 L73、SHA 分级 L384-395、fingerprint L368-373、`BaselineRunSpecError` L143-163、`from_mapping` L629、`validate_baseline_manifest` L672-752、**role 盲区 L729-739 亲证**） | 2f4b8bb | FR-03/FR-04/FR-05 消费对象；三层门第 1/2 层 | normative（冻结契约，只读） | 无冲突 |
| DI-007 | Code | `lima/baseline_run_result.py`（555 行全文亲读 @ 2f4b8bb；`_METRIC_FIELDS` L48-61 恰 10 字段、`_SAMPLE_FIELDS` L61、failure_code 模式 L65、cross-field L392-403、`_validate_metric` L372-379、聚合 L532-545、UNKNOWN_FIELD L78/L320-329、canonical L506-514） | 2f4b8bb | FR-02 样本组装与承载边界（R4） | normative（冻结契约，只读） | 无冲突 |
| DI-008 | Code | `lima/contracts/codec.py`（`canonical_encode` L170-184、`compute_content_digest` L187-196、float 拒绝 L113/L140-141、int64 界 L88-89） | 2f4b8bb | sidecar 封存、int-only 度量前提（R5） | normative（冻结契约，只读） | 无冲突 |
| DI-009 | Data | `evaluation_data/v4/baseline_manifest.json`（3 datasets / 13 entries，全文亲读 @ 2f4b8bb = e7c97cf 落盘） | 2f4b8bb | R2 冻结角色注册表真值（name/role/fingerprint 三元组逐字来源）；测试正例共享工件 | normative（冻结数据，只读） | 无冲突 |
| DI-010 | Test | 三个冻结测试文件：`tests/test_v4_baseline.py`（70 方法）、`tests/test_v4_baseline_manifest.py`（28）、`tests/test_v4_baseline_result.py`（33）——测试风格先例（负例断言、离线源扫描、import 白名单、深不可变探针） | 2f4b8bb | §8 测试组织与负例语义参照 | normative（冻结测试，只读，零改动含零追加） | 无冲突 |
| DI-011 | Decision | IP-0026 Packet `docs/LIMA_Implementation_Packet_IP-0026_Baseline_Static_Foundation.md`（结构先例：FR 规范化编号、≤35 方法上限、Done Commands 模式、ALLOWED_ONCE、单次提交纪律） | 2f4b8bb | 本 Packet 结构与流程先例 | normative（流程先例） | 无冲突 |
| DI-012 | Finding | 本轮 P&V 亲验（worktree @ 2f4b8bb，2026-09-25）：冻结回归 131 方法 `OK`（exit 0）；`benchmarks/` 目录不存在；`pyproject.toml` 无 `[project] dependencies`、ruff py311/100/E,F,I,B,UP,S（ignore S101）；CI runner `scripts/run_ci_tests.py` = `unittest discover -s tests -v`（cwd=repo root）自动纳入新测试文件；`tests/` 无 `__init__.py`/conftest.py（repo-root cwd + `python -m unittest` 机制与 IP-0026 先例一致）；Python 3.12.4 / ruff 0.16.5 / bandit 1.9.4 | 2026-09-25 | 冻结前基线绿、导入机制、质量门禁环境 | evidence | 无冲突 |
| DI-013 | Standard | `docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md`、`docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md` | 基线 2f4b8bb | 交付流程、Completion Summary、PR 文案约束（Assignment 以单 PR 拓扑覆盖 §9.1 标准拓扑） | normative（流程） | 无冲突 |

## 3. Explicitly Rejected Inputs

1. **任何 `lima/` 产品代码新增或修改**（含在冻结契约上加 role 比对）——R1：Add 边界只有
   `benchmarks/v4/baseline/`；SF-01 盲区的修复职责在**新消费端**，不在冻结函数（R2 源码亲证）。
2. **任何 `scripts/run_*.py` 修改**（`--run-spec`/`--output`/`--repeat` 接线）——R6：CLI 部分留 PR3；
   #57 File ownership 的 Modify 权限本切片不使用。
3. **Signal/SecurityIssue/Hypothesis 计数、压缩率、precision/recall proxy 写入 RunResult 本体或 sidecar**——
   R4/Not-covered 第 4 条：无真实扫描执行，任何计数字段都是虚构证据（M8/I4）。
4. **LlamaFactory `7fcf5b3b130e5713b52415bb7404c476fada9c8c` 相关的任何执行/物化/数据条目**——PR3；
   物化失败走 #57 FR-06 needs-decision，绝不换 latest main。
5. **psutil 或任何新依赖**（R5：环境内 psutil 5.9.0 为未声明偶然安装，消费即隐式依赖扩张）；**float 度量值**
   （codec 拒绝一切 float，canonical 稳定性前提）。
6. **Windows 平台 peak RSS/IO bytes 实测支持**——R5：None 是诚实表示；登记已知限制，不编造数值。
7. **默认输出目录约定与任何 run 产物提交**（results/*.json、RunSpec JSON 工件、machine profile 工件）——
   R3：writer 必填显式输出目录；测试一律 tempfile；不落盘从未运行的 spec。
8. **对三个冻结测试文件的任何修改（含追加测试）**——冻结 digest 与 RED 证据链不可破坏；所有新测试进新文件。
9. **新数据集/fixture 创作或负例专用 fixture 数据文件**——反过拟合纪律（R7）：负例基于冻结 manifest 与
   spec arrange 的深拷贝变异；正例与真实冻结 manifest 共享同一工件。
10. **新 py 文件超出 R1 上限 7 个（3 逻辑模块 + 3 包标记 + 1 测试）**——需要第 9 个及以后 Allowed File 即
    Stop Condition。

## 4. Goal / Non-goals

**Iteration hypothesis**：#57 PR2 的"执行与采集基础"可以完全由"`benchmarks/v4/baseline/` 独立包（6 文件，
stdlib-only）+ 1 个冻结测试文件"离线交付：SF-01 role 门以冻结注册表为第三方真值三层校验，runner 在三门
全过前零执行，采集原语可注入可离线验证，RunResult 经冻结契约 canonical 封存独立落盘（单调序号、不覆盖
历史、失败 run 保留），expert 计时以 active-minutes 聚合入冻结 `expert_time_ms` 字段 + 事件流 sidecar。
**measurement** = C2 冻结时有效 RED（`benchmarks.v4.baseline` 包缺席，collection 发现文件但模块 import 以
ModuleNotFoundError 失败，exit 1）→ 阶段 C3+ 实现后定向 26 方法全绿 + 冻结回归 131 全绿 + `git diff` 相对
基线恰为 8 个 Allowed Files。

**Goal**：(a) 采集原语（wall/queue/CPU/RSS/IO/token/cost，时钟非单调守卫，指标源可注入，int-or-None）；
(b) 专家计时协议（事件序列、reviewer ID 只存 SHA-256 摘要、active minutes 与自动化耗时分列、sidecar
canonical 序列化）；(c) SF-01 dataset→role 显式校验门（三层，注册表第三方真值，任一失败零执行）；
(d) RunResult 稳定独立落盘（确定性命名、单调序号、独占创建、失败 run 保留）；(e) 全离线、无 Secret、
无付费、无新依赖的验证方式。

**Non-goals**（= Assignment Not-covered 12 条全文照录；全团队不得扩张）：

1. LlamaFactory 固定 SHA `7fcf5b3b130e5713b52415bb7404c476fada9c8c` 真实重放与物化（PR3；若物化失败按
   #57 FR-06 转 needs-decision，绝不换 latest main——预授权升级路径 P2，占 ≤1 决策预算）。
2. cold/warm ×3/×5 聚合对照的**执行**与 nearest-rank p50/p95 报告产出（PR3；冻结聚合语义已在 IP-0025，
   本切片至多出现单 attempt 的 `insufficient_sample`，如实保留，I5）。
3. 完整报告模板与 secretless smoke 的 LlamaFactory 侧集成（PR3）。
4. Signal/SecurityIssue/Hypothesis 计数、confirmed/inconclusive、压缩率、precision/recall proxy（#57 FR-04
   主体，T-03/PR3）——**既不写入 RunResult 本体，也不做 sidecar 承载**（R4：本切片无真实扫描执行，制造
   计数字段即虚构证据，M8/I4）。
5. 真实 LLM token/费用实测（PR3 手动 run；本切片只交付字段与采集通道的离线可测语义）。
6. `scripts/run_*.py` 的 `--run-spec`/`--output`/`--repeat` 接线与默认输出目录约定（R6，PR3；#57 File
   ownership 的 Modify 权限本切片不使用）。
7. 新数据集/fixture 创作、frozen holdout 修改或角色重分类、空仓/最小 Python 仓支持声明（如实 coverage
   gap，维持 IP-0026 矩阵 unsupported 登记，I7/M8）。
8. 扫描器、Prompt、标签、数据 split、默认 analyzer 及生产 Audit/Queue/Sandbox/Repair/Frontend 的任何修改
   （硬禁区，M5）。
9. 任何 `lima/` 产品代码新增或修改；`evaluation_data/` 任何文件修改；support matrix/manifest 内容变更。
10. 提交运行产物（results/*.json、RunSpec JSON 工件、machine profile 工件）进版本库（IP-0026 R6 同款
    纪律：不落盘从未运行的 spec；本切片不提交任何 run 产物，测试写 tempfile）。
11. psutil 或任何新依赖引入（R5）；Windows 平台 peak RSS/IO bytes 实测支持（登记 None 语义，R5）。
12. #57 Parent 关闭与 Completion Summary 填写（Parent 保持 open）；#212 关闭判断。

## 5. 冻结接口消费清单（本轮只消费，零改动；行号 = 2f4b8bb 亲读）

| 接口 | 消费方 | 消费方式 |
|---|---|---|
| `lima.baseline_run_spec.from_mapping`（L629-651） | run.py runner 门 1 | spec 构造 + frozen 身份错误透传（缩写 SHA/moving ref/fingerprint 形态） |
| `lima.baseline_run_spec.validate_baseline_manifest`（L672-752） | run.py runner 门 2 | 冻结交叉（fingerprint/身份/内部 role 交叉/重复仓库）透传 |
| `lima.baseline_run_spec.BaselineRunSpecError`/`ErrorCode`（L86-163） | run.py | 门 1/2 失败以冻结码原样上抛；**不得捕获后改码** |
| `lima.baseline_run_spec.BaselineRunSpec`（L576-626） | run.py | `spec.datasets`（name/fingerprint/role）读取 + `spec.content_digest()` → `run_spec_digest` |
| role 枚举 `(external-holdout, calibration, development)`（L73） | run.py 注册表 | 注册表 role 值域与冻结枚举一致 |
| `lima.baseline_run_result.from_mapping`（L517-555） | run.py 组装 | 样本组装入口：success 必 wall、非 success 必 failure_code、10 字段 int-or-None、UNKNOWN_FIELD fail closed、聚合 all-or-nothing（单 attempt → `insufficient_sample` 属预期，I5） |
| `lima.baseline_run_result.BaselineRunResult`（L464-514） | run.py writer | `result.canonical_bytes()` 直接落盘；`result.run_spec_digest` 驱动文件名与 sidecar |
| `lima.contracts.codec.canonical_encode`（L170-184） | expert_timing.py | sidecar canonical 序列化（排序键、紧凑、UTF-8、无 BOM/尾换行、**拒绝 float** L113/L140-141） |
| `lima.contracts.codec.compute_content_digest`（L187-196） | expert_timing.py | sidecar digest（SHA-256 小写 hex；bytes 输入直接哈希） |
| `evaluation_data/v4/baseline_manifest.json`（@ e7c97cf = 2f4b8bb） | run.py 注册表真值 + 测试正例 | R2 三条 name→(role, fingerprint) 双钉绑定逐字来源；测试与冻结数据共享工件 |

**SF-01 盲区亲证（R2，作为本 Packet 新增消费端职责的依据）**：`validate_baseline_manifest` L729-739 对
spec.datasets 与 manifest 仅按 name 比对 fingerprint；L737-739 只检测 manifest **内部**同身份跨
holdout∩calibration 的角色交叉；**从不比对 `spec.datasets[i].role` 与 manifest 同名 dataset 的 `role`**——
自洽角色对调（spec+manifest 同时换 role）可通过冻结层。故 role 绑定门是 PR2 新增消费端职责，不构成对
冻结函数的修改（与 #210 关闭时登记的 SF-01 约束闭环一致）。

## 6. 文件边界（= Assignment §R1 Allowed Files，恰 8 路径；Modify = 0）

**Add — P&V 阶段产物（C1/C2）：**

1. `docs/LIMA_Implementation_Packet_IP-0027_Baseline_Collection_Foundation.md` — 本文件（C1）。
2. `tests/test_v4_baseline_collection.py` — 本轮唯一新测试文件（C2 冻结，26 方法 ≤ 35 上限，§8）。

**Add — Implementation 阶段产物（C3+）：**

3. `benchmarks/__init__.py` — 包标记，仅 docstring（授权树的机械必需父级）。
4. `benchmarks/v4/__init__.py` — 同上。
5. `benchmarks/v4/baseline/__init__.py` — 包标记 + 可选 re-export（不强制；测试直接 import 子模块）。
6. `benchmarks/v4/baseline/collect.py` — 采集原语 + 包级 typed error 族（§7.1）。
7. `benchmarks/v4/baseline/expert_timing.py` — 专家计时协议 + sidecar 序列化（§7.2）。
8. `benchmarks/v4/baseline/run.py` — SF-01 role 门 + 采集 runner + 落盘 writer（§7.3）。

**Modify：无（零个）。**

**Read-only**：`lima/**`（全部生产模块）、`evaluation_data/**`（全部 10 文件）、三个冻结测试文件、
`scripts/run_ci_tests.py`（unittest discover 自动纳入新测试文件，无需改动）。

**Do Not Touch（diff 必空，§9 命令 6 全列）**：`lima/**`、`scripts/**`、`evaluation_data/**`、
`tests/test_v4_baseline.py`、`tests/test_v4_baseline_manifest.py`、`tests/test_v4_baseline_result.py`、
`pyproject.toml`、`requirements.txt`、`.gitignore`、`.gitattributes`、其余一切 tracked 文件；不提交 run
产物与 RunSpec/machine-profile 工件（§9 命令 7）；GitHub Issue/PR/Ledger 远端状态。

**Symbol-to-File Map（公共符号面冻结——Implementation 不得重设计、不得改名、不得扩公共面）：**

| 文件 | 公共符号（`__all__` 恰为此集） |
|---|---|
| `benchmarks/v4/baseline/collect.py` | `BaselineCollectionError`、`BaselineCollectionErrorCode`、`FAILURE_TAXONOMY_CODES`、`classify_failure`、`elapsed_ms`、`require_metric`、`read_peak_rss_bytes`、`read_io_bytes`、`default_io_read_bytes`、`default_io_write_bytes`、`PlatformSources` |
| `benchmarks/v4/baseline/expert_timing.py` | `ExpertTimingSession` |
| `benchmarks/v4/baseline/run.py` | `FROZEN_DATASET_BINDINGS`、`ResultFileArtifacts`、`validate_role_bindings`、`write_exclusive`、`write_result_file`、`run_baseline_attempt` |
| `benchmarks/__init__.py` / `benchmarks/v4/__init__.py` | 无公共符号（仅 docstring） |
| `benchmarks/v4/baseline/__init__.py` | 无新增公共符号（可选 re-export 上述符号，不引入新名） |

**导入方向冻结**（无环）：`run.py` → `collect.py`（error 族/原语）与 `lima.baseline_run_spec`、
`lima.baseline_run_result`；`expert_timing.py` → `collect.py`（error 族）与 `lima.contracts.codec`；
`collect.py` → 仅 stdlib。`BaselineCollectionError` 族**只定义于 `collect.py`**（包级唯一 error 族），
`run.py`/`expert_timing.py` import 复用，禁止在各模块重复定义或子类化冻结 error 类。

**冲突分析**：`benchmarks/` 为全新路径（基线实测不存在，无占用冲突）；三个含逻辑模块文件集合两两不重叠；
无其他活动 IP 占用上述路径（Assignment 亲验占用检查）。暂存纪律：只逐路径 `git add <精确路径>`；禁止
`git add .` / `-A` / `-u`。

**stdlib-only 白名单（产品模块 import 面，测试冻结）**：stdlib 根集合
`{dataclasses, enum, hashlib, json, pathlib, re, time, types, typing, resource}`（`resource` 仅限
try/except ImportError 守卫下的 POSIX 分支，Windows 缺席必须优雅降级 None）+ lima 只读三方
`{lima.contracts.codec, lima.baseline_run_spec, lima.baseline_run_result}`。出现任何其他 import 即越界
（psutil/网络/环境读取均不可）。

## 7. 交付物规范（Implementation 必须满足的行为契约）

### 7.0 包级 typed error 族（定义于 `collect.py`，包内唯一）

- `BaselineCollectionErrorCode(str, enum.Enum)`：**恰 10 成员，value == name**（闭合集，测试冻结）：

  | 成员 | 触发语义 |
  |---|---|
  | `INVALID_FIELD_TYPE` | `validate_role_bindings` 收到非 `BaselineRunSpec` spec / 非 dict manifest / datasets 非 list / dataset 元素非 dict 或缺 name/fingerprint/role |
  | `UNKNOWN_FROZEN_DATASET` | dataset name 不在冻结角色注册表内（spec 侧或 manifest 侧） |
  | `ROLE_BINDING_MISMATCH` | dataset role 与注册表不一致（spec 侧或 manifest 侧，含自洽对调） |
  | `FROZEN_FINGERPRINT_MISMATCH` | dataset fingerprint 与注册表双钉不一致（含 spec+manifest 同步重算指纹的自洽篡改） |
  | `CLOCK_NOT_MONOTONIC` | 任何后读 < 前读（计时区间、事件序列时间戳） |
  | `INVALID_METRIC_TYPE` | 度量值/度量源返回值非 `int` 非 `None`（bool/float/str 一律拒绝） |
  | `INVALID_REVIEWER_ID` | reviewer ID 非 str 或空串 |
  | `EVENT_SEQUENCE_INVALID` | 专家计时事件序列非法（见 §7.2） |
  | `OUTPUT_DIRECTORY_UNAVAILABLE` | 输出目录参数缺失/不存在/不是目录 |
  | `OUTPUT_PATH_ALREADY_EXISTS` | 独占创建撞上已存在路径（拒绝覆盖） |

- `BaselineCollectionError(ValueError)`：属性 `code: BaselineCollectionErrorCode`、`field_path: str`（结构
  化定位如 `$.datasets[0].role`）；同一 code 渲染同一稳定消息（模块内 catalog；不内嵌原始 payload/secret/
  字段值）；构造器签名 `__init__(code, field_path="")`。**不得继承或复用** `BaselineRunSpecError`/
  `BaselineRunResultError`/`ContractError`（独立类，风格对齐冻结先例）。

### 7.1 `benchmarks/v4/baseline/collect.py` — 采集原语

1. **失败 taxonomy（闭合稳定大写码集，符合冻结 failure_code 模式 `[A-Z][A-Z0-9_]{0,63}`）**：
   `FAILURE_TAXONOMY_CODES = frozenset({"EXECUTION_ERROR", "EXECUTION_TIMEOUT", "EXECUTION_CANCELLED"})`；
   `classify_failure(exception: BaseException) -> str`：`TimeoutError`（含子类）→ `EXECUTION_TIMEOUT`；
   `KeyboardInterrupt` / `CancelledError` → `EXECUTION_CANCELLED`；其余 → `EXECUTION_ERROR`。
   outcome 映射（runner 使用）：`EXECUTION_ERROR→"failure"`、`EXECUTION_TIMEOUT→"timeout"`、
   `EXECUTION_CANCELLED→"cancelled"`（全部满足冻结 outcome 模式 `[a-z][a-z0-9_]{0,63}`）。
2. **单调时钟守卫**：`elapsed_ms(start_ns: int, end_ns: int) -> int`——`end_ns < start_ns` →
   `BaselineCollectionError(CLOCK_NOT_MONOTONIC)`；返回 `(end_ns - start_ns) // 1_000_000`（毫秒 int）。
   入参非 int（bool/float 拒绝）→ `INVALID_METRIC_TYPE`。基于 `time.perf_counter_ns` 读数的差值；
   等值读数合法（差 0）。
3. **度量值类型门**：`require_metric(value, field_path) -> int | None`——`None` 透传；`type(value) is not
   int`（含 bool/float）→ `INVALID_METRIC_TYPE`；负数不在本层拒绝（由冻结 `from_mapping` 域校验兜底，
   语义透传）。**禁止 float（R5）**。
4. **平台源（真路径只断言 类型-or-None）**：
   - `read_peak_rss_bytes() -> int | None`：POSIX 下 `resource.getrusage(RUSAGE_SELF).ru_maxrss` 按平台
     惯例换算字节（Linux KB×1024；macOS 已是字节）；`resource` 不可得（Windows/ImportError）→ `None`。
   - `read_io_bytes() -> tuple[int | None, int | None]`：Linux 读 `/proc/self/io` 的
     `read_bytes`/`write_bytes`；不可读/不存在 → `(None, None)`；其余平台 `(None, None)`。
   - `default_io_read_bytes()`/`default_io_write_bytes()`：`read_io_bytes()` 的分量包装。
5. **可注入源集合**：`PlatformSources`（`@dataclasses.dataclass(frozen=True, slots=True)`），5 个可调用
   字段：`wall_ns`（默认 `time.perf_counter_ns`）、`cpu_ns`（默认 `time.process_time_ns`）、
   `peak_rss_bytes`（默认 `read_peak_rss_bytes`）、`io_read_bytes`（默认 `default_io_read_bytes`）、
   `io_write_bytes`（默认 `default_io_write_bytes`）。测试注入 fake source；源返回值经 `require_metric`
   类型门（fake 返回 float 同样拒绝）。
6. queue wait 语义：无 enqueue 标记 → `None`（不虚构 0）；有标记 → enqueue→start 差值毫秒 int（在
   runner 内用 `elapsed_ms` 实现，无独立公共函数）。

### 7.2 `benchmarks/v4/baseline/expert_timing.py` — 专家计时协议（#57 FR-05 适配）

1. **会话**：`ExpertTimingSession(reviewer_id: str)`——reviewer_id 非 str 或空串 →
   `INVALID_REVIEWER_ID`；**只保存** `reviewer_digest = hashlib.sha256(reviewer_id.encode("utf-8"))
   .hexdigest()`（属性名冻结为 `reviewer_digest`），原始 reviewer ID 不得留存于任何属性、事件、文档或
   sidecar 字节。
2. **事件协议**（方法名冻结）：`start(time_ns)`、`pause(time_ns)`、`resume(time_ns)`、`finish(time_ns)`。
   状态机：初始 —start→ 活跃 —pause→ 暂停 —resume→ 活跃；`finish` 仅在 活跃|暂停 态合法；任何
   start 之前的事件、活跃态重复 start、非活跃态 pause、非暂停态 resume、未 start 即 finish、finish 后
   任何事件 → `EVENT_SEQUENCE_INVALID`（`field_path` 形如 `$.events[i]`）。
   **单调守卫**：每个事件 `time_ns` 必须 ≥ 前一事件 `time_ns`，否则 `CLOCK_NOT_MONOTONIC`。
3. **active minutes 累计**：`active_time_ms() -> int` = 已闭合活跃区间（start→pause、resume→pause、
   start→finish、resume→finish）ns 总和 `// 1_000_000`；未闭合区间不计；自动化耗时**不在本字段**（由
   `wall_time_ms`/`cpu_time_ms` 表达，R4）。
4. **事件只读视图**：`events() -> tuple[dict, ...]`，每项 `{"event": "start"|"pause"|"resume"|"finish",
   "time_ns": int}`，按发生顺序。
5. **sidecar 序列化**：`to_sidecar_document(run_spec_digest: str) -> dict` →
   `{"schema_version": 1, "run_spec_digest": <str>, "reviewer_digest": <str>, "active_time_ms": <int>,
   "events": [<事件 dict>...]}`（canonical JSON 子集）；
   `sidecar_bytes(run_spec_digest) -> bytes` = `canonical_encode(document)`（UTF-8、排序键、紧凑、无 BOM/
   尾换行、拒绝 float）；`sidecar_digest(run_spec_digest) -> str` = `compute_content_digest(sidecar_bytes)`
   （SHA-256 小写 hex，可由文件内容独立重算）。
6. **承载边界（R4）**：聚合 active 值只进冻结 `BaselineRunResult.expert_time_ms`（10 字段之一，合法承载）；
   事件流只进 sidecar；**均不写入任何计数类指标**（Explicitly Rejected Inputs 第 3 条）。

### 7.3 `benchmarks/v4/baseline/run.py` — SF-01 role 门 + runner + writer

#### 7.3.1 冻结角色注册表（第三方真值，逐字取自 `evaluation_data/v4/baseline_manifest.json`）

`FROZEN_DATASET_BINDINGS`：不可变映射（`types.MappingProxyType`），name → `(role, fingerprint)`，恰 3 条：

| dataset name | role | fingerprint |
|---|---|---|
| `lima-popular-python-calibration-v1` | `calibration` | `049d69b25731e51f75a800c5c406ab2d8faef1257d7dacfb275f9734b407b986` |
| `lima-popular-python-external-holdout-v2` | `external-holdout` | `23d4ef1da097e6af3d1099546d3cb6167b8964ecdc23f546ad5a835f342b284a` |
| `lima-real-world-pilot-v1` | `development` | `7d88728caca8bc3387802b7bdaa09b59e5ffe1ede21a71c3d314bd63eb0c106` |

#### 7.3.2 `validate_role_bindings(spec: BaselineRunSpec, manifest: object) -> None`

- 形态门：spec 非 `BaselineRunSpec` 实例 / manifest 非 dict / `manifest["datasets"]` 非 list / 元素非 dict
  或缺 `name`/`fingerprint`/`role` → `INVALID_FIELD_TYPE`。
- **spec 侧先查**（R2 层 2）：`spec.datasets` 每项——name 不在注册表 → `UNKNOWN_FROZEN_DATASET`
  （`$.datasets[i].name`）；role ≠ 注册表 → `ROLE_BINDING_MISMATCH`（`$.datasets[i].role`）；
  fingerprint ≠ 注册表 → `FROZEN_FINGERPRINT_MISMATCH`（`$.datasets[i].fingerprint`）。
- **manifest 侧后查**（R2 层 3）：manifest 每个 dataset 同样三项对照注册表（捕获 manifest-only 与
  spec+manifest 自洽角色对调——SF-01 负例核心）。fingerprint 双钉捕获"spec+manifest 同时重算指纹"的
  全自洽篡改（防御纵深，#57 NFR-01 消费侧）。
- 全部通过 → 返回 `None`。本函数**不调用**任何执行体、不做任何 I/O。

#### 7.3.3 独立落盘 writer（R3）

- `write_exclusive(path: pathlib.Path, payload: bytes) -> None`：以独占创建（`"xb"`）写 payload；已存在
  路径 → `OUTPUT_PATH_ALREADY_EXISTS`（不覆盖、不改写既有字节）。
- `write_result_file(result: BaselineRunResult, output_dir, *, expert_session=None) -> ResultFileArtifacts`：
  - 输出目录必须已存在且为目录，否则 `OUTPUT_DIRECTORY_UNAVAILABLE`（本切片不定默认目录，R3）。
  - 文件名确定性、无墙钟时间戳：`f"{result.run_spec_digest[:16]}-run-{n}.json"`，n = 该前缀下目录内最小
    未占用正整数（`path.exists()` 判占用）；sidecar 同 stem：`{stem}.expert-timing.json`（仅当
    `expert_session` 提供）。
  - 字节：result 文件 = `result.canonical_bytes()` **逐字节**（冻结契约产物，不自造编码器）；sidecar =
    `expert_session.sidecar_bytes(result.run_spec_digest)`。两者 SHA-256 可由文件内容独立重算。
  - `ResultFileArtifacts`（`@dataclasses.dataclass(frozen=True, slots=True)`）：`result_path:
    pathlib.Path`、`sidecar_path: pathlib.Path | None`、`result_sha256: str`、`sidecar_sha256: str | None`。

#### 7.3.4 采集 runner：`run_baseline_attempt(spec_mapping, manifest, execute, output_dir, *, attempt_index=0, mode="cold", enqueued_ns=None, sources=None, prompt_tokens=None, completion_tokens=None, cost_micro_usd=None, expert_session=None) -> BaselineRunResult`

**门序（冻结，任一失败 = 零执行体调用 + 零文件写出）**：

1. 参数类型门：`prompt_tokens`/`completion_tokens`/`cost_micro_usd` 经 `require_metric`（float/bool →
   `INVALID_METRIC_TYPE`）。
2. 输出目录门：`output_dir` 存在且为目录，否则 `OUTPUT_DIRECTORY_UNAVAILABLE`。
3. **门 1（spec 层）**：`baseline_run_spec.from_mapping(spec_mapping)`——moving ref/缩写 SHA/fingerprint
   形态等以冻结 `BaselineRunSpecError` 原样透传。
4. **门 2（冻结交叉）**：`validate_baseline_manifest(manifest, spec)`——冻结码原样透传。
5. **门 3（role 绑定门）**：`validate_role_bindings(spec, manifest)`——新 typed error。
6. 三门全过后才调用 `execute()`（**校验门全通过前绝不调用执行体 callable**，R2 组合顺序）。

**采集与组装**：wall start/end 与 cpu start/end 取自 `sources`（默认 `PlatformSources()`）；
`wall_time_ms = elapsed_ms(wall_start, wall_end)`、`cpu_time_ms = elapsed_ms(cpu_start, cpu_end)`；
`queue_time_ms = elapsed_ms(enqueued_ns, wall_start)` 当 `enqueued_ns` 非 None 否则 None；
`memory_rss_peak_bytes`/`io_read_bytes`/`io_write_bytes` 取自源并经 `require_metric`；
`expert_time_ms = expert_session.active_time_ms()` 当提供会话否则 None。样本 14 键闭合（attempt_index、
mode、outcome + 10 metric + failure_code）→ `BaselineRunResult.from_mapping({"schema_version": 1,
"run_spec_digest": spec.content_digest(), "samples": [sample]})`（委托冻结 cross-field：success 必
wall_time、非 success 必 failure_code）。

**失败 run（R1/FR-02）**：`execute` 抛 `Exception` → `outcome` 按 §7.1 taxonomy 映射、`failure_code` =
taxonomy 码，**result 文件照常写出并保留**（不因数据"不好看"排除），返回 result；`execute` 抛
`BaseException`（`CancelledError`/`KeyboardInterrupt`/`SystemExit`）→ 先按同规则分类写出失败样本，**然后
原样重抛**（控制流异常不吞）。`elapsed_ms` 抛 `CLOCK_NOT_MONOTONIC` → 直接上抛、**不写出任何文件**
（不可信时钟下不产出可伪造结果）。单 attempt 语义下 `status == "insufficient_sample"` 属预期（I5）。

**返回**：`BaselineRunResult` 实例（调用方另可经 writer 返回值拿路径；本函数内已落盘）。

## 8. 测试矩阵（`tests/test_v4_baseline_collection.py`，C2 冻结）

组织（R7）：unittest 风格、单文件；模块级 import = stdlib + 冻结 `lima.baseline_run_spec`/
`lima.baseline_run_result` + `from benchmarks.v4.baseline import collect, expert_timing, run`（产品 import
模块级放置 → RED 形态，见下）；正例 fixture = 真实冻结 `evaluation_data/v4/baseline_manifest.json` + 名义
spec arrange（值同 IP-0026 先例：`analyzer_fingerprint="a"*64`、`config_digest="b"*64`、`seed=20260925`、
声明式 machine profile）；负例全部深拷贝变异，**不新建 fixture 数据文件**；测试临时输出一律 tempfile。
CI 经 `scripts/run_ci_tests.py`（unittest discover -s tests，cwd=repo root）自动纳入。**测试方法总数 26
（≤ 35 上限）**。

**RED 形态（R7 + 责任书 §7.2）**：C2 冻结时 `benchmarks/` 整树缺席，测试文件被 runner 正常发现，但模块
import 在 `from benchmarks.v4.baseline import ...` 语句处以 `ModuleNotFoundError` 失败（Python 语义下报文
指向首个缺席祖先 `benchmarks`），`python -m unittest tests.test_v4_baseline_collection` → `Ran 1 test /
FAILED (errors=1)`、exit 1——镜像 IP-0024/0025 冻结头先例；不得是测试语法/其他依赖损坏（缺席态
`python -m py_compile` 通过 + 存在态（桩沙箱）模块 import 与 26 方法全绿共同证明缺席是唯一失败源）。

负例面 13 类覆盖对照（Assignment R7 清单 → 测试锚点）：

| # | 负例面 | 测试锚点 |
|---|---|---|
| 1 | SF-01 自洽角色对调（spec+manifest 同步 swap）→ 新门 typed error（先证冻结层确不放行，盲区属实） | TestRoleBindingGate.test_self_consistent_role_swap_rejected_despite_frozen_contract_pass |
| 2 | spec-only role 对调 → 拒绝 | TestRoleBindingGate.test_spec_only_role_swap_rejected |
| 3 | manifest-only role 对调 → 拒绝 | TestRoleBindingGate.test_manifest_only_role_swap_rejected |
| 4 | 注册表外 dataset name（spec 侧 / manifest 侧）→ 拒绝 | TestRoleBindingGate.test_unknown_dataset_name_rejected_on_spec_and_manifest_sides |
| 5 | spec+manifest 同步重算指纹的自洽篡改 → 注册表 fingerprint 双钉拒绝 | TestRoleBindingGate.test_self_consistent_fingerprint_recomputation_rejected |
| 6 | moving ref / 缩写 SHA / fingerprint 漂移经 runner 路径 → 冻结 typed error 透传（每错误码 ≥1 断言）+ 零调用 + 零文件 | TestRunnerIdentityGates.test_identity_gate_failures_pass_through_with_zero_execution_and_no_files |
| 7 | role 门失败时执行体零调用（守卫断言） | 同上（自洽对调案例）+ test_runner_rejects_invalid_metric_params_before_execution |
| 8 | writer：已存在路径拒绝覆盖；同 spec 二次执行新文件不覆盖历史；文件名含 digest 前 16 位无墙钟时间戳 | TestWriter.test_write_exclusive_refuses_existing_path；test_result_filenames_are_digest_prefixed_monotonic_without_timestamps；TestRunRecording.test_second_execution_writes_new_file_preserving_history |
| 9 | 失败 run：执行体抛异常 → 非 success outcome + 有界 failure code，文件保留 | TestRunRecording.test_failed_runs_recorded_with_taxonomy_and_retained |
| 10 | success 必带 wall_time（经冻结 from_mapping 传导）；指标缺失平台路径 → None（不虚构） | TestClockGuardAndSources.test_null_semantics_keep_missing_metrics_none；TestRunRecording.test_success_run_records_canonical_result_with_metrics |
| 11 | 时钟非单调注入 → typed error fail closed | TestClockGuardAndSources.test_elapsed_ms_rejects_non_monotonic_reads / test_runner_rejects_non_monotonic_injected_wall_clock；TestExpertTimingProtocol.test_invalid_event_sequences_and_non_monotonic_events_rejected |
| 12 | expert timing：active 与自动化分离、暂停剔除、reviewer 只存摘要、canonical 字节稳定 + digest 可重算 | TestExpertTimingProtocol 全部 + TestSidecarIntegration.test_runner_writes_sidecar_alongside_result |
| 13 | 离线卫生：新测试与产品源码自扫描无网络/Secret 依赖 | TestPublicSurfaceAndHygiene.test_offline_hygiene_source_scan + test_product_modules_import_whitelist |

| Test class | 方法数 | 覆盖点 |
|---|---:|---|
| TestPublicSurfaceAndHygiene | 5 | error 族形态与闭合 10 码集（同 code 同消息、独立于冻结 error 类）；taxonomy 码集 + `classify_failure` 四分支（含冻结 failure_code 模式断言）；注册表与落盘 manifest 逐字一致；产品模块 import 白名单（ast）；离线卫生源扫描（自扫 + 三产品模块扫） |
| TestRoleBindingGate | 6 | 正例对照（原样 manifest+spec 通过返回 None）；负例 1-5（§8 表）；每负例断言 code（+field_path 片段） |
| TestRunnerIdentityGates | 2 | runner 门序负例 6/7（MOVING_REF/缩写/DATASET_FINGERPRINT_MISMATCH/自洽对调，逐码断言 + execute 零调用 + 输出目录空）；参数类型门（float cost/bool tokens → INVALID_METRIC_TYPE，零调用） |
| TestClockGuardAndSources | 3 | `elapsed_ms` 非单调拒绝与等值/正值合法；注入非单调 wall 源 → runner 拒绝且零文件；真平台 RSS/IO 仅断言 类型-or-None + 注入 None 源时字段保持 None（不虚构） |
| TestRunRecording | 3 | success run：canonical 字节落盘、SHA-256 独立重算、queue wait/tokens/cost/expert 字段记录、status=insufficient_sample；失败 run taxonomy 三分支（ValueError/TimeoutError/CancelledError 重抛）文件保留；二次执行新文件且历史字节不变 |
| TestWriter | 2 | `write_exclusive` 拒绝覆盖（哨兵字节不变）；命名模式 `^[0-9a-f]{16}-run-\d+\.json$`、同 digest 双写单调 1→2、目录不可得拒绝 |
| TestExpertTimingProtocol | 4 | reviewer 只存 SHA-256 摘要（原文不入属性/文档/字节/digest）；active 剔除暂停区间且与自动化分离；非法事件序列 + 非单调事件时间戳拒绝；sidecar canonical 字节稳定 + digest 可重算 + 无 BOM/尾换行 |
| TestSidecarIntegration | 1 | runner 提供会话 → sidecar 同 stem 落盘、字节 = 会话 sidecar_bytes、SHA-256 重算一致；无会话 → 无 sidecar |
| **合计** | **26** | ≤ 35 上限 |

反过拟合：负例基于冻结 manifest/spec arrange 的深拷贝变异；正例与真实冻结 manifest 文件共享同一工件；
采集源全部注入 fake（真平台路径仅 类型-or-None）；不锁定内部容器类型与实现细节（行为断言为主）。

## 9. Done Commands（= Assignment §8 验收命令全文，在 worktree 根执行，Windows 设 PYTHONUTF8=1）

```bash
# 1. 定向新测试（C2 冻结时须全 RED 且归因 benchmarks.v4.baseline 模块缺席；C-final 后须全绿）
python -m unittest -v tests.test_v4_baseline_collection
# 2. 冻结测试回归（必须保持 70+28+33=131 方法全绿；C2 之前先跑一次作为冻结前基线绿）
python -m unittest -v tests.test_v4_baseline tests.test_v4_baseline_manifest tests.test_v4_baseline_result
# 3. 编译
python -m compileall -q lima benchmarks tests scripts
# 4. 质量门禁（仅对本次新增 py 文件）
python -m ruff check --no-cache benchmarks/__init__.py benchmarks/v4/__init__.py \
  benchmarks/v4/baseline/__init__.py benchmarks/v4/baseline/collect.py \
  benchmarks/v4/baseline/expert_timing.py benchmarks/v4/baseline/run.py \
  tests/test_v4_baseline_collection.py
python -m bandit -q benchmarks/v4/baseline/collect.py benchmarks/v4/baseline/expert_timing.py benchmarks/v4/baseline/run.py
# 5. 文件边界：恰等于 Allowed Files 8 路径，无其他
git diff --name-only 2f4b8bb4c06475ed6a45b541f89ba0ce6e6856d7..HEAD
# 6. 冻结面/生产面守护：预期输出为空
git diff 2f4b8bb4c06475ed6a45b541f89ba0ce6e6856d7..HEAD -- lima scripts evaluation_data \
  tests/test_v4_baseline.py tests/test_v4_baseline_manifest.py tests/test_v4_baseline_result.py \
  pyproject.toml requirements.txt .gitignore .gitattributes
# 7. 产物守护：预期输出为空（不提交任何 run 产物/RunSpec 工件）
git diff --name-only --diff-filter=A 2f4b8bb4c06475ed6a45b541f89ba0ce6e6856d7..HEAD -- 'benchmarks/v4/baseline/results*' '*.json' ':!docs' ':!tests'
#    （若第 5 步已恰为 8 Allowed Files，第 6/7 步为其子集断言）
# 8. ancestry 守护（P&V 终验；<Frozen-Test-Commit-SHA> 由 C2 登记）
git merge-base --is-ancestor <Frozen-Test-Commit-SHA> HEAD && echo ANCESTRY-OK
```

成功判据（全部满足才算本切片 GREEN）：AC-1 采集原语与落盘 canonical 稳定、SHA-256 封存、独立文件不覆盖；
AC-2 role 门 + 全负例面 fail closed（typed error，含 SF-01 自洽对调）；AC-3 全离线 + C2 有效 RED 先于 C3；
AC-4 冻结面与生产扫描语义零改动。

失败判据（任一命中即未达标）：任一负例未按稳定错误码拒绝；role 门失败后执行体被调用；任一冻结面字节变化；
任何 `lima/`/`scripts/`/`evaluation_data/` 路径出现于 diff；测试方法数 >35；出现网络/Secret/付费/新依赖；
RED 不可归因于模块缺席；计数类字段出现在 RunResult 本体或 sidecar；提交了 run 产物。

## 10. Stop Conditions（停止并提交 Decision Request 给 Coordinator；= Assignment §R9）

1. 需要修改任何 Forbidden/Do Not Touch 路径，或需要第 9 个及以后 Allowed File（含更多 py 模块）。
2. 需要把计数类指标（Signal/Issue/Hypothesis/压缩率/precision-recall proxy）写入 RunResult 本体或
   sidecar，或需要改动 IP-0024/IP-0025 冻结语义（R4 升级触发器 → Maintainer）。
3. SF-01 role 门无法在不改冻结契约的情况下实现（含注册表与 manifest 演进的冲突）。
4. 需要网络、Secret、付费模型、psutil 或任何新依赖。
5. 测试方法数无法压进 35 且无法合并断言（冻结前）。
6. 冻结测试自身语义错误（解冻-修订-重新 RED 流程，或 ALLOWED_ONCE 范围内处理）。
7. 发现 base SHA 之后 main 出现冲突性实现或 IP-0027 占用冲突。
8. LlamaFactory 物化需求或任何 #57 FR-06 触发情形出现（预授权路径：转 needs-decision，绝不换 latest
   main）。
9. 需求冲突无法唯一解决；验收面覆盖不了真实需求；实现与冻结基线不一致且原因不明。

**Mechanical Test Correction Allowance：ALLOWED_ONCE**（Assignment 一次性授出，不得出错后补写）。P&V 可
在不新增 Coordinator 调用的情况下自行纠正一次纯测试机械缺陷并重新冻结，五项条件全满足：①不改产品语义、
公共接口、稳定错误码或文件范围；②仅限 fixture/arrange/import/lint/测试基础设施缺陷（含 §R7 导入机制类
缺陷）；③旧 Frozen Commit 保留；④修正前缺陷证据、修正后有效 RED、新 Frozen Commit 完整记录；
⑤Implementation 未参与测试修改。产品行为、验收语义或文件范围问题仍走 Decision Request。

## 11. Decision Record（Coordinator 裁定登记，依据 CA-IP-0027-v1.0）

| 裁定 | 内容（摘要） | 依据 | 落点 |
|---|---|---|---|
| R1 | 全部新代码落 `benchmarks/v4/baseline/` 独立包；Allowed Files 恰 8（2 P&V + 6 Implementation）；Modify = 0；新 py 上限 7 | #57 Add 清单唯一预留目录；`benchmarks/` 实测不存在；挂 lima/ 即越界 | §0、§6 |
| R2 | SF-01 role 门三层校验：冻结注册表（3 条 name→role+fingerprint 双钉，逐字取自 manifest）+ spec 侧 + manifest 侧；独立 typed error `BaselineCollectionError`；组合顺序 load spec → 冻结交叉 → role 门 → 才允许执行体；任一失败零扫描启动 | `validate_baseline_manifest` L729-739 无 role 比对（亲证）；SF-IP-0026-20260925-01；M6 | §7.0、§7.3.1、§7.3.2、§7.3.4 |
| R3 | writer：显式输出目录必填（缺失/不可写 fail closed）；文件名 `{run_spec_digest[:16]}-run-{n}.json`（n = 最小未占用正整数，无墙钟时间戳）；独占创建拒绝覆盖（OUTPUT_PATH_ALREADY_EXISTS）；sidecar 同 stem `.expert-timing.json`；字节 = `canonical_bytes()`/`canonical_encode` 产物；SHA-256 可独立重算；本切片不提交任何 run 产物 | A2 采纳 + 一次性给全；PR3 CLI 再定默认目录 | §7.3.3 |
| R4 | expert active 聚合值 → 冻结 `expert_time_ms`（10 字段之一，合法承载）；事件流 → sidecar（PR2 落地）；计数类指标整体留 PR3，不做任何承载；升级触发器：写入冻结 schema 本体或改冻结语义 → 升级 Maintainer | 冻结 `_METRIC_FIELDS` 恰 10、UNKNOWN_FIELD fail closed（I4）；#212 Scope 1 | §7.2、§3 |
| R5 | stdlib-only（time/resource/pathlib/json/dataclasses/enum/hashlib/re/types/typing）+ 只读 import lima 三方；Windows/不可得平台 RSS/IO = None（诚实表示）；一切度量 int-or-None 禁 float | pyproject 无 dependencies；psutil 未声明（消费即隐式扩张）；codec 拒绝 float | §6、§7.1 |
| R6 | 本切片零 `scripts/run_*.py` 修改、不新增脚本；#57 FR-02 CLI 部分不标 satisfied；FR-06 = PARTIAL（离线验证本切片交付） | CLI 完整语义依赖 PR3；3 处生产 diff 面与最小充分集合/预算冲突（I6）；#212 委托授权 | §1、§3、§4 |
| R7 | 单一新冻结文件 ≤35 方法；模块级产品 import（RED = ModuleNotFoundError，镜像 IP-0024/25）；负例面 13 类全覆盖；深拷贝变异反过拟合；CI discover 自动纳入 | IP-0026 M17 同款上限；B6 | §8 |
| R8 | Done Commands = §9 全文（定向 + 131 回归 + compileall + ruff/bandit + 边界/冻结面 diff 空 + 产物守护 + ancestry）；worktree 根执行；PYTHONUTF8=1 | 验收面一次性给全 | §9 |
| R9 | Not-covered 12 条 + Stop Conditions 9 条 + 已知缺口如实登记（空仓/最小仓 unsupported；token/cost 实测 PR3；Windows RSS/IO None；FR-02 CLI PR3；单 attempt insufficient_sample 预期） | M8/I5/I7 | §4、§10、§12 |
| R10 | #212 Ledger 初始版（§11 草案）；#57 satisfied 只标实际证明项（可主张 FR-02 落盘部分/FR-05 协议原语/NFR-01 消费侧/NFR-02；不可主张 FR-02 CLI/FR-03 执行侧/FR-04 主体/FR-06 覆盖）；PR2 完成 ≠ #57 完成 | M3/B4 | §12、§13 |

## 12. 已知缺口与诚实声明（Ledger gap 行来源）

空仓/最小 Python 仓维持 IP-0026 矩阵 unsupported；真实 token/费用仅字段与采集通道语义，实测留 PR3；
Windows peak RSS/IO bytes = None 语义（已知限制，PR3 可扩展）；FR-02 CLI 入口留 PR3（R6）；FR-06 数据集
覆盖依赖 PR3 物化；单 attempt 结果 `insufficient_sample` 属预期（I5）；本切片不产生任何真实扫描执行证据。

## 13. Completion Summary 模板（Implementation 交付时）与 PR 纪律

```text
IP / 状态：IP-0027 / VERIFICATION
Base / Frozen Test Commit / final commit：<SHA 列表>
修改文件：恰为 6 个 Implementation Add 路径（benchmarks 包 6 文件）
AC → Test → Result：逐 AC 附命令与输出摘要（§9 全量，命令 1 全绿 26 方法、命令 2 全绿 131、命令 3-8 通过/为空）
实际命令与统计：§9 命令 1-7 输出摘要 + ruff/bandit 零告警
安全/权限/依赖变化：无（stdlib-only；零网络；零 Secret；零新依赖）
已知限制与未完成项：§12 清单
是否满足 Stop Condition：否
下一步建议：P&V 独立验证（不自行激活）
```

PR 纪律：单一 Implementation PR（Draft→Ready→merge，不 amend/force/squash）；正文含 `Implements
IP-0027`、`Related to #212`、Packet/Frozen Test/final commit SHA、AC→Test→Result 表、"This PR does not
auto-close the Source Issue."；**严禁 close/fix/resolve 关键字与 #212/#57 组合**；不修改 Issue/Ledger/
PROGRESS；交付后不建 PR（P&V 验证 PASS 后由 P&V 形成）。

## 14. Packet completion definition

- 本 Packet 关键字段无 TBD；§7 行为契约（10 稳定码、注册表 3 条值、门序、文件名/序号/独占创建语义、
  sidecar 文档 schema、taxonomy 码集与 outcome 映射、int-or-None 纪律、BaseException 重抛规则）已完整
  冻结，Implementation 无需再做语义决策，只做命名面与行为的忠实实现。
- 状态 `READY-FOR-CODE` 的激活条件：C2 Frozen Test Commit 落盘（精确 SHA、测试文件 digest、required
  test count = 26、有效 RED 证据交回 Coordinator）+ 主会话登记后派发阶段 C3+。
- 本 Packet 为 vertical-slice 贡献（#57 PR2）；#212/#57 保持打开；本 IP 不宣告任何 Issue 完成。
- 本文件按"单次提交"纪律于 C1 落盘，后续不回填 C2 SHA（冻结证据以 C2 commit message 与 #212 Delivery
  Ledger 为准）。
