# Implementation Packet IP-0023 — Monorepo Component Graph & Per-Component Profile/RAM（#60-CLOSURE-A 首片）

> 文档类型：Implementation Packet（P&V 制作；本版为 **D1 修订（D1R）** 产物——只修订 Packet 文档，未写测试/产品/schema、未冻结）
>
> Packet 版本：`IP-0023-PACKET/v2`；**v2 supersedes v1**（v1 = 同文件 @`41c899ef10be682e52d61ab0f92e4bef11aed27c`，SHA-256 `e9702fe2bbf403f58a60afa07400cb0ef7fe4aca1cd1d20f736195048d1f7f9f`，原样保留在提交历史，不重写、不删除）。v1→v2 修订依据：Maintainer 指令 `MR-60-PR282-GOAL-CORRECTION-20261009/v1`（§五 R60-01..08、§六 测试计划、§七 custody、§八 呈审）+ Coordinator Assignment `ASSIGN-60-CLOSURE-A-PKT-D1R_v1`（SHA-256 `30a0e9198bd3914e3c2ea511f8d5ad523addabd1496dc654ce755d03d61c040a`）+ `MDR-60-PR282-GOAL-CORRECTION-20261009-v1`。逐项处置见 §0.1（R60-01..08）。
>
> 状态：`D1R-REVISION / PENDING-REVIEW`（**未冻结的修订待审态**：本版尚待 Coordinator readiness、独立 ER 语义反证与 Maintainer 对修订后具体 PR 的合并批准；获批合并进 main 并由 Coordinator 标 `PACKET-MERGED` 前，本状态行不得改标为任何"可进入实现"表述——判据见 §13）
>
> Exact base：修订基线 = 分支 `codex/ip-0023-monorepo-packet` @`41c899ef10be682e52d61ab0f92e4bef11aed27c`（Packet v1 提交）；产品/冻结面基线 = `fbbbd619fb0b96efbbb903916ab46dc0daed2214`（origin/main；D1R 开工时 `git fetch origin` 亲验未前移，2026-10-09）
>
> 制作人：lima-packet-verification（v1：Assignment `ASSIGN-60-CLOSURE-A-PKT-D1_v1`，任务 `PKT-IP-0023-D1`；v2：Assignment `ASSIGN-60-CLOSURE-A-PKT-D1R_v1`，任务 `PKT-IP-0023-D1R`，2026-10-09）
>
> 编号依据：`ALLOC-IP-0023-60-CLOSURE-A/v1`（Coordinator，2026-10-09，基线 fbbbd619；2026-10-09 编号四查通过；IP-0023 = #60-CLOSURE-A 首片编号，**不是整个 Issue 的 closure 编号**）
>
> 上游决策：Maintainer 批复 `MR-60-RESUME-APPROVAL-20261009/v1` §五/§六（批复正文 SHA-256 `e4bcc9c3772fecddd7a3dc67e232aa56bd1d46aede643f2dcdbe5eda5cabbbbc`）+ 修订指令 `MR-60-PR282-GOAL-CORRECTION-20261009/v1`（正文 SHA-256 `4f7134551994f521f94f722eb9ef5a41b2f8da85246aca2b6edbdd1f220edd89`）；恢复审计 `RESUME-AUDIT-60-2026-10-09_v1` + addendum-1/2；PI-DR1..PI-DR6 全部生效
>
> 阶段边界：本版仍只交付设计（D1 修订）。验收测试文件、有效 RED、Frozen Test Commit 属 D2，另行 Assignment 派发；本阶段无 Frozen Test Commit，Mechanical Test Correction Allowance = NOT_ALLOWED（D1R 明示）。

---

## 0. Header（生命周期 §8）

```text
Source Issue：#60（[V4-I04][P0] Repository Profile、RAM 与安全语义清单，V5 覆盖层版）
Issue specification revision：2026-10-09 live 正文（v1 制作时 GitHub API 亲取；body SHA-256
  477ad50cd383d22dbbbefce3a71e1a2250abd89d01218c6e1d94e6c1fd9f8180；含 V5 覆盖层、
  7/6/4 勘误后 Delivery Ledger、ENTRY60-RESUME-1/v1、ALLOC-IP-0023-60-CLOSURE-A/v1）
Covered requirements（本 IP 只声明自身贡献，且仅此贡献；D1R 未缩减目标）：
  V5-FR-03 前半句（monorepo 输出 component graph——嵌套组件识别、每组件 Profile/RAM、
    组件间依赖/歧义/未解析/未知导入关系 + provenance、重复模块名与相对导入处理、monorepo golden）
  AC-01/T-01 的 monorepo 维度（monorepo/重复模块/相对导入 fixture 下已解析与未解析调用
    均有 provenance、Top-N 顺序可重放——经每组件全链 + 图承载实现）
  V5-AC-01/V5-T-01 的 monorepo 维度（monorepo 形态输出 RepositoryProfile/code roles/
    support level/execution capability/coverage gap——每组件维度）
  V5-AC-02/V5-T-02 的后半句（monorepo 按 component 生成 profile/RAM）
  FR-02/FR-03/FR-04/NFR-01 的组件维度复验（复用三层冻结公共接口，每组件重放；
    不改三层语义，仅声明组件维度复验贡献）
Not covered requirements（相邻但明确不在本 IP；A 自身的新正确性/隐私/预算回归必须在 A 解决，
  不得转移到 B/C/D——R60-04 尤其如此）：
  V5-FR-03 后半句（docs/content 与 unsupported 安全停止端到端——机器可读 gap/停止结果）→ #60-CLOSURE-B
  V5-AC-02/V5-T-02 前半句（docs/unsupported 安全停止、不能输出"未发现漏洞"）→ #60-CLOSURE-B
  T-03/AC-03/NFR-02/V5-FR-04/V5-AC-03 端到端安全负例与 F3（_safe_path TOCTOU）/F4
    （回包/时间上限的强制约束与聚合墙钟证明）→ #60-CLOSURE-C（F3/F4 路线归切片 C，
    本片零 workspace 改动；本片不宣称任何已证明的聚合墙钟上界）
  FR-01 全跳过原因内部逐项留痕（公开面维持 reason→count）→ #60-CLOSURE-D
  DR-LINT-0022-A 六处 lint 正式处理 → #60-CLOSURE-D
  #64/#68 公共 Contract 消费验证与下游接线（含 full semantic payload 的下游消费）→
    #60-CLOSURE-D / 下游 Issue（本片只闭合"仅凭公开 Artifact 可取得并核对五类事实"）
  #58 字段/schema 任何改动（本 IP 零修改 lima/contracts/**）
  version_compatibility_matrix 注册（BG-60-01 维持默认不注册；本 IP 新 schema 同样不注册）
  整个 Issue Closure（IP-0023 DONE 不能据此关闭 #60）
Delivery role：closure-first-slice（monorepo 组件层：嵌套识别 + 单一归属 + 每组件全链 +
  独立版本化图承载 + 公开 Artifact 消费闭合）
Issue closure impact：PARTIAL
Upstream IP/PR/merge commits：IP-0016（#167 @fd219724）、IP-0018（#170 @cc17662）、
  IP-0019（#174 @e000e6f）、IP-0021（#179 @30bdfaa）、IP-0022（#180 @dfa0f85）；
  全部冻结消费面经恢复审计 §6 consumer review 43/43 PASS + 本 Packet §3 亲验复核
Upstream ruling：ALLOC-IP-0023-60-CLOSURE-A/v1；MR-60-RESUME-APPROVAL-20261009/v1 §五/§六；
  MR-60-PR282-GOAL-CORRECTION-20261009/v1 §四/§五/§六
```

本 Packet 只声明 IP-0023 自身贡献。它不宣称 #60 任何端到端 AC 整体满足、不宣称 B/C/D 切片完成、不以 Packet 文档完成声称产品已交付。

---

## 0.1 D1R 变更记录（R60-01..08 逐项处置；行号均指 v1 @41c899ef）

每项格式：原规则（v1 行号）→ 反例（review_probe_results.json，SHA-256 `90f3d975…acb8a4`）→ 修订规则（v2 节）→ 对应验收（测试符号/命令）→ 剩余限制（如实）。

| # | 原规则（v1） | 反例 | 修订规则（v2） | 对应验收 | 剩余限制 |
|---|---|---|---|---|---|
| R60-01 | 候选范围="根+一级子目录"（§5.1.1 L192），示例却用 `component:services/api`（§5.1.2 L203）；测试 #1–#6 全平铺形态（L574-579） | RULE-01：`services/api/pyproject.toml`、`packages/core/pyproject.toml` 按字面规则均不在候选集 | 锚点=主 workspace 已准入 inventory 中 manifest 类文件（封闭名集）的 POSIX 父目录，**任意深度**；组件边界证据=manifest+静态 workspace/build 配置+源码/导入证据组合（§5.1.1/§5.1.2/§5.1.5） | C1 类 `test_detect_components_nested_services_packages` 等（§6 表 1-10）；D1R 探针 D1-RULE01（设计推导+实跑 inventory） | 调用方 ignore 集/扩展策略裁剪掉的 manifest 不可发现（策略继承语义，如实声明）；不支持形态以 typed gap 承载（§5.1.5） |
| R60-02 | "锚定目录互不嵌套⇒至多一归属"（§5.1.1 L194、§5.1.3 L210-213），但根组件用普通 `RepositoryWorkspace(仓库根)`（§5.2.1 L235），递归吸入子组件文件 | API-01：根 workspace 看到 `a/main.py`（root_modules=2），子组件再计 1——计数/所有权与构建输入不一致 | 最深锚点前缀精确归属（仓库级坐标，in-module 单解）+ 组件 workspace 构造（锚点根 + 继承五参数 + 嵌套锚点名 ignore）+ **所有权不变量**：构建后逐文件比对组件扫描集与精确切片，分歧→`unbuilt_components` typed 承载，不出错误数据（§5.1.3/§5.2.1） | C1 类 `test_component_counts_match_build_inputs`、`test_root_component_excludes_child_files`（§6 #9/#10）；D1R 探针 D2-API01/D7-COLLISION | 祖先组件的 Profile 层 manifest 候选仍含其一级子目录内嵌套组件 manifest（确定性、有界，已知限度）；名字碰撞目录触发不变量分歧→typed 承载——彻底消除需共享层支持（DR-IP-0023-02 草案随交接报告，不进 v2 正文为既成事实） |
| R60-03 | 从路径重建默认 workspace（§5.2.1 L235）；每组件默认预算 5000/512KiB/20MiB + 每组件独立 SemanticBudgets（§5.4.4 L431-434）＝变相扩预算；§5.7 L550 称"公共入口合法使用" | API-02：父 workspace 1/30/30 且忽略 a；子 workspace 5000/524288/20971520 且忽略规则丢失 | 组件 workspace **继承调用方全部五个策略参数**（max_files/max_file_bytes/max_total_bytes/extensions/ignored_directories）；主仓未准入输入不得因组件切分重新准入（隔离不变量强制）；聚合模型调用包络 `max_total_model_calls`（默认 128=16×8）作为**显式新预算设计**呈审 + fail-closed typed 截断；资源计量口径显式（§5.4.4）；墙钟降级为"F4 未闭合、不宣称聚合上界"（§5.4.4 末） | C3 类 `test_policy_inheritance_all_five_params`、`test_no_readmission_under_caller_caps`、`test_aggregate_model_call_envelope` 等（§6 #19-#25）；D1R 探针 D3-API02 | 调用方 cap 收紧导致组件扫描集与精确切片分歧时，该组件 typed 不构建（不扩权优先于多产出）；F4/聚合墙钟未闭合（归 C） |
| R60-04 | 坐标分离（§5.2.1 L248）+ 准入仅覆盖 unassigned/evidence 路径（§5.8 L562-564，测试 #26 L599） | API-03：整仓 `secrets/main.py` 被拒（0 模块+gap）；根重设为 secrets 后局部坐标 `main.py` 被采纳（1 模块）——坐标变换绕过准入 | **仓库级坐标先准入、后建组件视图**：主仓 inventory（工作区级准入）→ 锚点准入（is_secret_shaped_path@仓库级）→ 归属划分 → 组件视图；锚点级准入使组件坐标下 Profile 准入与仓库级**等价**（§5.2.1 时序 + §5.8 公开面准入规则表：component_id/root_dir/manifests/unassigned/evidence/scan_summary/unknown_imports/digests/candidate_ids 逐项） | C4 类 `test_repo_level_admission_before_component_views`、`test_all_public_surfaces_admission_rules`、`test_secret_gap_reason_count_no_filename`（§6 #26-#29）；D1R 探针 D4-API03 | 启发式非穷尽声明保留（不改成"零泄漏"）；reason→count/内部无原文件名口径保留；内部 family 级全 vocabulary 留痕归 D |
| R60-05 | anchors=剥离前缀后第一级目录名（§5.3.2 L283-284，src/alpha 与 src/beta 同得 `src`）；`T ∉ anchors` 一律归外部无边无 gap（§5.3.3 L292-303，测试 #10-#14 L583-587） | RULE-02：A `import beta` → 无边、无 gap（被伪装成外部/未知） | **模块根解析**替代目录首段臆断：模块根=组件根 ∪ 构建配置声明目录（封闭键集）∪ 含包/模块内容的直接子目录 `src`；顶层名表（含 namespace）；解析优先级 自身→唯一他组件→歧义；**已知外部（stdlib 冻结集 ∪ manifest 静态声明依赖名）与未知导入区分**，未知入 `unknown_imports` typed 承载；相对导入按包上下文解析；动态 import 位点自计 `dynamic_import_site_count`（§5.3.1-§5.3.3）；与 `lima/python_dataflow.py` 只读语义对照（§5.3.5） | C2 类 `test_module_resolution_src_layout_cross_component` 等（§6 #11-#18）；D1R 探针 D6-RULE02 | 构建配置识别键集封闭（未识别配置→回退根+src 约定+未知承载）；stdlib 集为冻结快照（跨解释器版本稳定优先于穷尽）；不执行/install/sys.path 探测 |
| R60-06 | complete=False 封闭两触发（§5.2.4 L265-269）与 edge-limit 置 False（§5.3.4 L310-311）矛盾；"真实无依赖"不要求 gaps 空（L265-267）；解析失败靠"组件 RAM 继承"（§5.3.1 L276） | API-04：`parse_error_files=1` 而 RAM `coverage_gaps=[]`——"底层继承"不成立 | **单一封闭触发集 T1-T7**（组件数/python-file-limit/edge-limit/图自计 parse_error/图自计 read_failure/主仓 cap 截断/unbuilt 非空），全文唯一定义（§5.2.4）；三态判据表修订：空边集+缺口 ≠ 真实无依赖（机械可查）；解析/读失败由图层级 `ComponentScanSummary` 自计承载（不依赖"底层继承"四字）（§5.2.4/§5.3.1） | C5 类 `test_dependencies_complete_unified_triggers`、`test_parse_error_carried_in_graph`、`test_empty_edge_set_with_gap_not_no_dep` 等（§6 #30-#34）；D1R 探针 D5-API04 | read_failure 在静态快照下难以确定性构造（TOCTOU 类，归 F3/C）——承载字段保留、触发入封闭集、测试以默认零值+相邻触发覆盖并如实声明 |
| R60-07 | fixtures/golden "P&V 独占"却"Implementation 有效 RED 后产出、提交前经 P&V 核对 digest 链"（§4.2 L154-162）＝实现定义自身预期；测试 #7 断言"各 envelope content_digest 互异"（L580；§5.2.1 L245、§5.6.4 L537 同口径；§8 L645/§13 L698 依赖之） | API-05：不同组件根、相同局部内容 → content_digest 完全相等（`e11772ff…` 两例同值）——互异不是合法普遍不变量 | **Oracle 独立**：全部 expected/golden 由 P&V 在实现前独立产出并冻结（最小独立重算例：人工推导组件集/边/计数/三态 + 既有公共 `compute_content_digest` 对手写 canonical dict 独立重算 digest）；Implementation 只产产品代码与 schema，不生成/改期望；**删除"互异"断言**，替换为：相同内容两组件摘要**允许相等**且 component_id 可区分、内容变化→摘要变化、关联篡改被识别；D2 计划写入有效 RED + scratch/reference 非自相矛盾验证（PI-DR2 流程）；方法数=规划参考（§4.2/§6 注记/§13） | C6 类 `test_identical_content_components_equal_digest_allowed`、`test_component_identity_keyed_association`、`test_content_change_digest_changes`、`test_golden_expected_from_independent_oracle`（§6 #35-#41） | golden 全量 digest 值依赖既有公共 digest 函数的独立重算（该函数属既有冻结面，非新实现）；scratch/reference 细化在 D2 执行 |
| R60-08 | payload 只携带每组件三 digest，消费者"重放三段构建复算"（§5.4.6 L456；§5.5 L504-510、§5.6.3 L531、§5.6.4 L537 未闭合只凭公开 Artifact 的消费） | （设计缺口——违背"阶段间经版本化 Artifact 交换事实"；非探针反例） | **公开 Artifact 消费闭合**：图 payload 自身携带 scan_summary/semantic_topn/built/键控 digest 引用；每组件完整 Profile=既有 #58 envelope、完整 RAM=既有 IP-0021 RAM wire payload（阶段 Artifact 并行交换），图以 component_id 键控关联三 digest；消费例全程不重跑构建、不依赖构建者内存（§5.4.6/§5.4.8）；validator 单解清单十维（§5.4.8）；Unicode/字符集口径与输入范围声明一致 | C7 类 `test_consumer_obtains_all_facts_from_public_artifacts` + validator 检查测试（§6 #42-#49，覆盖 §5.4.8 V1-V10 十维）；§8 验收命令 | full semantic payload 的下游消费归 D/#64/#68（本片承载 ranked_candidate_ids+digest）；#58/54 帽/旧 digest/matrix 零扩展（若 ER 认定承载不足 → 具体 DR，不留不可消费摘要列表） |

R60-09（记录补齐）不属本 Assignment：归主会话/Coordinator 一次性最小处理（指令 §七）；P&V 未为此修改任何索引/登记文件。

---

## 1. Goal / Non-goals

### Goal

1. 新增 `lima/audit/component_graph.py`：确定性、只读、stdlib-only 的 monorepo 组件层——**嵌套**组件识别（manifest 锚定 + 静态 workspace/build 配置 + 包结构/导入证据组合，仓库级坐标、有界、确定顺序）、**单一真实归属**（最深锚点前缀精确划分 + 机器可校验所有权不变量）、每组件 Profile/RAM/semantic 全链（**复用三层冻结公共接口** `build_repository_profile` / `build_python_ram_facts` / `build_semantic_top_n`，组件 workspace 继承调用方策略）、组件间依赖分析（resolved / ambiguous / unresolved 边 + **未知导入 typed 承载**，AST import 证据 + provenance）、**仓库级秘密形态准入先于坐标变换**、**统一完整性触发集**、**聚合预算新设计（fail-closed）**；
2. 新增 `schemas/v4/lima.component-graph.json`：独立版本化 component graph wire schema（**不注册 version_compatibility_matrix**，BG-60-01 口径），携带仅凭公开 Artifact 即可消费/核对全部五类事实的承载；
3. 图与每组件产物经独立 digest 关联（`component_graph_digest` 64-hex + 每组件三 digest 键控关联；相同内容不同组件允许摘要相等——身份用 component ID/坐标/版本表达），**沿用 IP-0019 B-10 独立承载先例**（DI-007：v4 RepositoryProfile 非空 extensions 即拒）；
4. monorepo golden fixture（可重放、排序稳定、输入顺序无关；**expected 由 P&V 独立产出并在实现前冻结**，不由实现输出定义）。

### Non-goals

- 不修改 `lima/audit/__init__.py`（`__all__` 54 帽零触碰，见 §5.6.1）；
- 不修改三层冻结面 `lima/audit/{inventory,ram,semantic_prioritizer}.py`、`lima/audit/ram_schema.py`、既有 tests/audit 全部测试与 fixtures、既有 schemas/v4 15 文件、`lima/contracts/**`、`lima/workspace.py`（确需共享层配合的精确隔离增强 → DR-IP-0023-02 草案随交接报告呈审，获批前不实现，见 §13）；
- 不把图挂入 `RepositoryProfile` / `AttackSurfaceEntry.extensions` / RAM wire payload / 任何 #58 envelope（B-10 + Assignment 冻结约束）；
- 不扩展 digest 家族既有成员语义（ram_facts/semantic_config/semantic_result/prompt/model/wire 六 digest 原样；新增的 `component_graph_digest` 是独立新成员，不改不动旧成员）；
- 不执行、不 import、不安装目标项目；不通过目标脚本补证据；不引入网络/付费模型调用（semantic 默认 off；有界离线 fake client 仅限设计反证与测试，不调真实模型——指令 §五 R60-03）；
- 不处理 F3/F4 强制约束与聚合墙钟证明、安全停止端到端、FR-01 全 vocabulary 内部留痕、#64/#68 消费接线（见 §0 Not covered）。

---

## 2. Design Input Manifest

| Input ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001 | Standard | `docs/LIMA_PACKET_AND_VERIFICATION_AGENT_RESPONSIBILITY_CHARTER.md` | main @fbbbd619 | Packet 结构、Manifest/Rejected 要件、RED/冻结/验证边界 | normative | 最高优先级之一，冲突时停止 |
| DI-002 | Standard | `docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md` | main @fbbbd619 | 不执行/路径有界/fail-closed 不变量、验证命令底线 | normative | 同上 |
| DI-003 | Standard | `docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md` §8/§9 | main @fbbbd619 | Packet Gate 全清单、分支拓扑、禁自动关闭关键字 | normative | 同上 |
| DI-004 | Decision | Coordinator Assignment `ASSIGN-60-CLOSURE-A-PKT-D1_v1`（SHA-256 `5a118ea9603c67663a63c17da7db203a705edecddd60ed0f06c77b5f2d573b82`）+ **`ASSIGN-60-CLOSURE-A-PKT-D1R_v1`（SHA-256 `30a0e9198bd3914e3c2ea511f8d5ad523addabd1496dc654ce755d03d61c040a`，D1R 唯一任务合同，读取前重算一致）**；D1R 明示：D1_v1 的 Goal/Frozen Interfaces/安全基线/停止条件继续有效，除本文明确修订或收紧处 | 2026-10-09 | v2 范围（R60-01..08 逐项修订要求、T 节七类测试计划、Acceptance 1-7、停点） | normative（唯一任务合同） | 与其他输入冲突时以 Assignment 为准并提交 Decision Request |
| DI-005 | Decision | `ALLOC-IP-0023-60-CLOSURE-A/v1`（#60 Ledger 恢复记录条目内，live 亲取） | 2026-10-09 | IP-0023 编号有效性、首片范围、禁令与失效条款 | normative | 编号失效（对端先占用）→ 停止上报 |
| DI-006 | Issue | Source Issue #60 live 正文 + Delivery Ledger | 2026-10-09 API 亲取（v1 制作时；body SHA-256 `477ad50c…f8180`） | L28 AC-01、L65 边界矩阵、L77 V5-FR-03、L82-83 V5-AC-01/02、Ledger 7/6/4 覆盖矩阵与切片归属 | normative（需求范围） | V5 覆盖层优先于 V4 正文 |
| DI-007 | Decision | 恢复审计链：`RESUME-AUDIT-60-2026-10-09_v1`（SHA-256 `74ad8c13…9b71`）+ addendum-1（`852e2d05…7e7ef`）+ addendum-2（`e9dbbb58…1bd31`） | 2026-10-09，SHA 全部重算一致 | workspace 漂移定性、五 IP 消费面结论（43/43）、切片归属表、停点条款修订版、开放 PR #266/#281 零交集 | normative | — |
| DI-008 | Decision | Maintainer 批复 `MR-60-RESUME-APPROVAL-20261009/v1`（正文 SHA-256 `e4bcc9c3…cabb`） | 2026-10-09 | §五（D1 边界）、§六（七条产品目标与设计边界、已否决路线、安全基线） | normative | 已否决路线不得重试 |
| DI-009 | Upstream IP | IP-0016 Packet v1.2（`docs/LIMA_Implementation_Packet_IP-0016_Repository_Profile_Layer1.md`，@fbbbd619 亲读） | main @fbbbd619 | manifest 候选口径（D4）、`build_repository_profile` 签名与 sentinel digest、LF 口径（DR-IP-0016-02/PI-DR6） | normative（先例+接口） | 只读消费 |
| DI-010 | Upstream IP | IP-0018 Packet v1.1 + IP-0019 Packet v1.2（含 B-10/DI-007 独立承载先例、candidate_id 冻结编码、SemanticBudgets 勘误值 28,096） | main @fbbbd619 亲读 | 每组件 RAM/semantic 复用路径、B-10 承载先例、降级语义 | normative（先例+接口） | 只读消费 |
| DI-011 | Upstream IP | IP-0021 Packet v1.1（wire schema 先例、GAP_CODES_ALL 10 码、execution_required 9 码定案、golden matrix 模式、matrix 不注册先例）+ IP-0022 Packet v6（`is_secret_shaped_path` 准入口径、R1 终案 reason→count、manifest-index 稳定标识先例、AdmissionSkipRecord） | main @fbbbd619 亲读 | wire schema 风格、gap 复用口径、隐私准入、NFR-01 五面口径 | normative（先例+接口） | 只读消费 |
| DI-012 | Code | 三层冻结面 + ram_schema + `__init__.py`：`lima/audit/{inventory,ram,semantic_prioritizer,ram_schema,__init__}.py`（@fbbbd619，§3.1 逐符号 import 亲验；`__all__` 恰 54 项 + 冻结断言；**两层入口 `isinstance(workspace, RepositoryWorkspace)` 硬校验 + 自行调用 `workspace.inventory()`——R60-02/03 设计的可行性边界**） | @fbbbd619 | 全部公共签名/常量/预算默认值/错误语义的精确消费面 | normative（接口冻结） | 漂移 → DR 停点 |
| DI-013 | Code | `lima/workspace.py`（@fbbbd619 亲验：构造器五策略参数 max_files/max_file_bytes/max_total_bytes/extensions/ignored_directories；`ignored_directories` 按**目录名**剪枝、无路径级排除；`inventory()` 递归扫描 root 并返回 `files` + `skipped: dict[reason→count]` 公开计数字段；`read_text` 有界 UTF-8 无换行归一；`_safe_path` 边界）+ `lima/contracts/profile.py`（`encode/decode_profile_envelope`、`_validated_path`、`_validated_extensions` v4 非空 extensions 拒绝、`RepositoryKind.MONOREPO="monorepo"`）+ `lima/contracts/codec.py::compute_content_digest` + `lima/contracts/errors.py::ContractError`（UNKNOWN_FIELD/INVALID_FIELD_TYPE/INVALID_FIELD_VALUE） | @fbbbd619 | 输入域口径、策略继承可行性、#58 契约消费、错误码复用、独立 digest 重算 | normative（契约冻结）+ current-behavior（workspace） | workspace 行为以当前 main 为准，不当作隐式新能力 |
| DI-014 | Test | tests/audit 既有 10 测试文件（235 用例基线锚，含 IP-0022 51 例回归锚）+ 五形态 golden + `fixtures/repo_shapes.py` helper 先例 | @fbbbd619 亲验文件清单 | 回归零破坏边界、fixture 构造模式 | normative（回归锚） | 计数变化需解释（addendum-2 §3 修订版），不删测试追平 |
| DI-015 | Decision | PI-DR1..PI-DR6 | Ledger 2026-09-12/13 | arrange 平台中立（LF 钉死）、冻结前非 Windows 完整跑一次、PR 禁 close 关键字、PI-DR2 scratch/reference 非自相矛盾流程（R60-07 D2 计划引用） | normative | — |
| DI-016 | Decision | DR 链：DR-IP-0016-01/02、DR-TOPN-01、DR-IP-0021-0102（DR-1/DR-2）、DR-IP-0022-01/02/03/04、DR-C1、IP-0024 Packet §0.1/DI-013 | Ledger + docs @fbbbd619 | digest sentinel、LF 重冻结先例、B 组批准值、9 码触发、准入/R1 终案、编号预留依据 | normative | — |
| DI-017 | Decision | **Maintainer 修订指令 `MR-60-PR282-GOAL-CORRECTION-20261009/v1`**（机械抽取正文 `.pv_tmp/issue60-resume-2026-10-09/authorization/v3/PR282_CORRECTION_BODY.md`，SHA-256 `4f7134551994f521f94f722eb9ef5a41b2f8da85246aca2b6edbdd1f220edd89`，读取前重算一致） | 2026-10-09 | §五 R60-01..08 修订方向、§六 七类测试计划与 ER 承重主张、§二 本轮允许/不允许、§八 呈审终点 | normative（最高需求权威） | 与 v1 设计冲突处以指令为准 |
| DI-018 | Review | **回顾文档 `docs/LIMA_Issue60_Goal_Process_and_PR282_Retrospective_2026-10-09.md`**（SHA-256 `00483bd67ada7352c6f077c6d26dafcc465f6285faee2b106b0c936e87c6658b`，main 工作区） | 2026-10-09 | §5 R60-01..08 行号锚点（本 Packet §0.1 引用）、§8 长程约束、需求映射表 | normative（背景裁定建议） | — |
| DI-019 | Evidence | **反例证据**：`output/issue60-pr282-retrospective-2026-10-09/review_probe_results.json`（SHA-256 `90f3d975f18ea2e479dd6631c40508a17883afb58eaac073a1471ac3eeacb8a4`）+ `github_snapshot.json`（`9b24579a12f44902a306a10450524a7209a6990d157ad734a5d1ad5abc44d81d`）+ `review_probe.py`（5 API case 用 fbbbd619 真实公共 API、2 RULE case 只执行 Packet 字面规则；**不得替代产品验收**——指令 §三） | 2026-10-09，SHA 重算一致 | R60-01..08 反例定义、D1R 设计探针输入集（§附） | normative（反例基准） | — |
| DI-020 | Decision | **MDR 登记 `published/MDR-60-PR282-GOAL-CORRECTION-20261009-v1.md`**（SHA-256 `759a9225f58af509cf32e38417c9e3bd54d7f2a22df4773c9d1b8260db953403`，重算一致） | 2026-10-09 | R60-01..09 语义登记（§三） | normative | — |
| DI-021 | Code | `lima/python_dataflow.py`（@fbbbd619 只读亲验：`PythonDataflowAnalyzer.analyze_project(files: dict[path→text])` 纯静态、`_module_name` 由全路径派生点分模块名、结果含 `parse_errors/dynamic_import_sites/ambiguous_modules` 计数）——**只读语义参照**（R60-05：比较模块解析语义一致性；不作为代码依赖，见 §5.3.5） | @fbbbd619 | 模块解析语义对照声明 | current-behavior（参照） | 不引入新依赖方向 |

### Explicitly Rejected Inputs

- 任何需要修改 `lima/workspace.py` 或共享输入/安全层才能表达的方案**作为 v2 默认设计**（F3 路线归 #60-CLOSURE-C；确需共享层配合的精确隔离增强以 DR-IP-0023-02 草案呈审，获批前不实现——Assignment R60-02 交付形态）；
- 任何扩展 `lima/audit/__init__.py.__all__` 54 帽、私加 #58 Profile 字段、借 `AttackSurfaceEntry.extensions` / RAM wire payload / 任何未知 extensions 携带图的方案（B-10 + `_validated_extensions` 冻结语义冲突）；
- 已否决路线（累计，不得重试）：D1_v1 原清单（prompt/wire 层掩码 path；full-payload digest 扩展；公开 redact:sha8/家族计数；摘要检查前置于结构检查；IP-0022 单 PR 流程例外；借 extensions 携带图）+ **本轮反例否决**（指令 §二/D1R Known Gaps）：从路径重建默认 workspace 覆盖调用方策略（API-02）；以目录首段推导 import 锚点（RULE-02）；坐标变换后再准入/仅覆盖部分公开面（API-03）；"底层继承"当作解析失败 gap 的证明（API-04）；组件 content_digest 互异断言（API-05）；实现后产 golden 自证（R60-07）；消费者重跑构建获取事实（R60-08）；
- `lima/python_dataflow.py`、`lima/semantic_retrieval.py` 的**代码依赖**（v2 仅将前者作只读语义参照文档化，§5.3.5；semantic 链复用指 `lima.audit.semantic_prioritizer` 公共入口；组件层 import 扫描自带最小 AST 解析，不引入对共享模块的新依赖方向）；
- 修改 `repository_kinds` monorepo 判定语义（inventory 冻结行为；本片组件图与 kinds 分类各自表述，见 §5.1.6）；
- #266（OpenHarmony pilot）与 #281（offline preflight）的任何文件/语义面（恢复审计 addendum-2 §5 四查③亲验与 #60 预期路径零交集；#281 的 profile_consumer 仅为只读参考，不作为本片验收依据）；
- #94 轨道全部路径、IP-0020 vault、IP-0024..IP-0043 baseline 轨道、BG-IP-0016-01/BG-60-01 处置（OPEN 项归置权在 Coordinator，本片不清偿不扩大）；
- 任何聊天记录、调研文档推断、快照外时点数据（以 §2 Manifest 所列 live/锚定输入为准）。

---

## 3. Current code baseline（P&V 亲验誊录，@fbbbd619）

本阶段（D1R）按 D1R Assignment §Acceptance 第 6 条执行：不重跑全量产品测试（引用恢复审计 §5 真实数字为基线锚），对 Packet 引用的冻结符号/常量做只读核对（import 亲验或源码誊录，禁止执行目标项目样本）。

### 3.1 三层冻结面 + ram_schema 消费面（DI-012，import 亲验）

- **Layer 1（inventory）**：`build_repository_profile(workspace, *, tenant_id, task_id, workflow_id, stage_attempt_id, artifact_id, repository_snapshot_digest, producer="lima.audit.inventory", policy_digest=<sentinel e3b0c442…b855>, toolchain_digest=<sentinel>, options: ProfileInventoryOptions|None)` → `ProfileBuildResult{profile, envelope, provenance_anchor_ids, admission_skips}`；`ProfileInventoryOptions{budgets=ProfileBudgets(), schema_version=SchemaVersion(4,0)}`；`ProfileBudgets{manifest_max_bytes=262_144, max_manifest_files=64}`；`is_secret_shaped_path`（段级检测，`tests/secrets/x.py`→True / `tests/tokenizer/x.py`→False 亲验；`secrets/pyproject.toml`/`secrets/main.py`→True、`main.py`→False 亲验）；`AdmissionSkipRecord{index, reason, family}`（内部留痕，无文件名）。**入口行为（R60-02/03/04 承重）**：`isinstance(workspace, RepositoryWorkspace)` 硬校验（鸭子类型视图不可注入）；内部自行 `workspace.inventory()` 与 `_manifest_candidates(workspace)`（`os.listdir` root+一级子目录，**不读 ignored_directories**）。
- **Layer 2（ram）**：`build_python_ram_facts(workspace, *, budgets=None)` → `RamFactsBuildResult{facts, provenance_anchor_ids, admission_skips}`；`RamBudgets{max_python_files=512, max_key_flows=256, max_unresolved_edges=1024}`；`PythonRamFacts` 11 字段（含 `counters: Mapping[str,int]`——`parse_error_files`、`modules_indexed` 等在此）；`ram_facts_digest(facts)`（64-hex）。**入口行为同上**：isinstance 硬校验 + 自行 `workspace.inventory()`；py 候选排序后先过 `_secret_shape_family` 准入（路径=该 workspace 相对坐标），拒绝计数入 `INVENTORY_SKIPPED`（detail `reason=sensitive-filename; count=N`）；`>max_python_files` 截断入 `BUDGET_EXHAUSTED`（detail `reason=python-file-limit; count=…`）。
- **Layer 3（semantic）**：`build_semantic_top_n(facts, *, options=None, model_client=None)`；`SemanticOptions{top_n=20, weights, seed=0, budgets, model_id="unset", prompt_template, tie_break="kind-path-symbol-ordinal"}`；`SemanticBudgets{max_llm_calls=8, max_prompt_tokens_estimate=24_000, max_output_tokens_estimate=4_096, max_total_tokens_estimate=28_096, max_wall_time_seconds=120}`；`candidate_id("sensitive-sink","a/b.py",None,0) == "sensitive-sink:a/b.py:-#0"`（冻结编码亲验）；`semantic_result_digest(result, *, input_facts_digest=None)`；模型默认 off（`model_id="unset"` 或无 client → 零调用零网络）。
- **Schema 层（ram_schema）**：`GAP_CODES_ALL` 恰 10 码（AMBIGUOUS_DISPATCH / BUDGET_EXHAUSTED / DYNAMIC_IMPORT / INVENTORY_SKIPPED / MANIFEST_PARSE_ERROR / NO_LANGUAGES_DETECTED / SEMANTIC_MALFORMED_OUTPUT / SEMANTIC_MODEL_OFF / SEMANTIC_MODEL_TIMEOUT / UNSUPPORTED_LANGUAGE）；`GAP_EXECUTION_REQUIRED_TRIGGERS = GAP_CODES_ALL - {"SEMANTIC_MODEL_OFF"}` 恰 9 码；`PROVENANCE_ANCHOR_CHAIN=("inventory","ram-facts","semantic-prioritizer")`；`ram_wire_payload` / `validate_ram_wire_payload` / `ram_wire_digest` / `execution_required_from_gaps` / `load_ram_wire_schema`。
- **manifest 候选机制（inventory 私有，值重述不 import）**：`_MANIFEST_EXACT_NAMES` = {Cargo.toml, environment.yml, go.mod, package.json, pom.xml, pyproject.toml, setup.cfg, setup.py} + `requirements*.txt` 模式；候选 = 根目录 + 一级子目录（os.listdir 后 sorted；**这是 inventory 冻结旧行为，不授权本片组件层沿用浅层限制**——R60-01）；`_record_manifest_error` 用 `manifest-index=<排序下标>` 稳定标识（DR-IP-0022-04 A 定稿版，不泄漏敏感文件名）。
- **monorepo kind 判定（inventory 冻结行为，亲验 `_repository_kinds`）**：`has_languages and len(manifest_subdirs) >= 2` → `RepositoryKind.MONOREPO`（wire 值 `"monorepo"`，#58 IP-0003 §10 冻结）。

### 3.2 `lima/audit/__init__.py` 现状（DI-012）

134 行；`__all__` 恰 54 项 = IP-0016 段 `[0:11]` + IP-0018 段 `[11:20]` + IP-0019 段 `[20:44]` + IP-0021 段 `[44:54]`（字母序段追加先例）；docstring 内冻结断言说明 ``len(__all__) == 54``。本 Packet 对该文件**零修改**（§5.6.1）。

### 3.3 workspace 口径（DI-013；恢复审计 §4② 定性移交，全部 @fbbbd619 亲验）

- 构造器 `RepositoryWorkspace(root, *, max_files=5_000, max_file_bytes=512KiB, max_total_bytes=20MiB, extensions=None→DEFAULT_EXTENSIONS, ignored_directories=None→∅∪DEFAULT_IGNORED_DIRECTORIES)`——**五策略参数即策略继承的公共载体（R60-03）**；
- `inventory()`：os.walk topdown、`followlinks=False`；目录按**名字** ∈ ignored_directories 剪枝（无路径级排除——R60-02 设计边界）；文件级跳过原因 closed 词表（ignored-directory/symlink/sensitive-config/unsupported-extension/unreadable/file-size-limit/file-limit/total-size-limit/binary/non-utf8）；候选按 `_candidate_priority`（low-priority/source-root/其余 + 相对路径）排序后过 cap；返回 `WorkspaceInventory{files: list[WorkspaceFile], skipped: dict[reason→count]（**公开**）, total_bytes, discovered_files/bytes, truncated}`——**主仓准入与截断状态对组件层可观察（R60-03/04/06 依据）**；
- `read_text` = 有界（≤max_file_bytes）`read_bytes().decode("utf-8")`，无 universal-newline 归一（保留 CRLF）；`absolute_file`=`_safe_path`（相对、不越界、常规文件）；`DEFAULT_EXTENSIONS` 37 项（含 C++/构建类）、`DEFAULT_FILENAMES` 6 项、`WorkspaceFile` 第 4 字段 `line_count`、`fingerprint()`=逐文件 path/size/sha256——**输入域扩容为既有事实，本片不依赖新扩展进入 inventory**；
- F3（_safe_path TOCTOU）未闭合，归 #60-CLOSURE-C。

### 3.4 基线数字（恢复审计 §5 Coordinator 实跑 @fbbbd619，锚定引用非本轮重跑）

contracts `617 OK` / audit `235 OK 0 skip`（含 IP-0022 51 例回归锚）/ evidence_privacy `244 OK 3 skip` / workspace+dataflow `44 OK` / `ruff check --no-cache lima/audit` 净 / `ruff check --no-cache lima/audit tests/audit` 恰 DR-LINT-0022-A 六处（B009×1 + B017×5，全在 tests/audit/test_ip_0022_fix.py）零漂移 / CI 完整入口 `3006 OK 24 skip`（全环境类）。数字为基线锚，按 addendum-2 §3 修订版停点条款执行：计数变化需解释，不单独构成停点；不得删测试/改 Oracle 追平。

### 3.5 反例索引（DI-019；七例 SHA 锚定于 `90f3d975…acb8a4`）

API-01（根 workspace 吸入子组件文件：root_modules=2 / child=1）、API-02（子 workspace 重置策略：1/30/30+ignore a → 5000/524288/20971520+丢失）、API-03（坐标重设绕过准入：整仓 0 模块+gap → rebased 1 模块）、API-04（`parse_error_files=1` 而 facts `coverage_gaps=[]`）、API-05（不同组件根同内容 → content_digest 相等）、RULE-01（`services/api`、`packages/core` 不在"根+一级"候选集）、RULE-02（src 布局 anchors 同为 `src`，`import beta` 无边无 gap）。处置映射见 §0.1；D1R 设计探针复跑结果见附录 B。

---

## 4. Files boundary（冻结单解；D2 冻结与 Implementation 将据此执行）

### 4.1 Files to Add（产品与数据产物，Implementation Agent 拥有）

| # | 文件 | 说明 |
|---|---|---|
| 1 | `lima/audit/component_graph.py` | 唯一产品代码文件（§5 全部实现） |
| 2 | `schemas/v4/lima.component-graph.json` | component graph wire schema（独立版本 2.0——v2 设计的承载字段集；**不注册 matrix**） |

### 4.2 Test/Fixture Files（P&V 独占，D2 创建，Implementation 禁改）

| # | 文件 | 说明 |
|---|---|---|
| 3 | `tests/audit/test_component_graph.py` | 组件识别/单一归属/策略继承/模块解析/完整性/隐私/消费闭合/wire 负例（§6 C1-C7） |
| 4 | `tests/audit/test_monorepo_golden.py` | monorepo golden 可重放 + 独立 Oracle 摘要核对（§6 C6） |
| 5 | `tests/audit/fixtures/monorepo/__init__.py` | fixture 包 |
| 6 | `tests/audit/fixtures/monorepo/shapes.py` | monorepo repo 形态构造（LF 钉死；沿用 `repo_shapes.workspace_with` 模式；含嵌套/src 布局/同内容双组件/秘密形态负例专用形态） |
| 7 | `tests/audit/fixtures/monorepo/golden/monorepo.json` | monorepo golden（**P&V 在实现前独立产出并冻结的预期载体——R60-07：内容=独立推导预期（人工推导的组件/边/计数/三态 + 既有公共 `compute_content_digest` 对手写 canonical dict 的独立重算），不是实现输出的回填**；D2 Frozen Test Commit 内提交） |

### 4.3 Product Files Allowed to Modify

**无**。`lima/audit/__init__.py` 本 IP 零修改（与 IP-0019/0021/0022 的"纯追加 re-export"边界不同：本 IP 新公共符号不经 `lima.audit` 命名空间 re-export，见 §5.6.1 单解）。

### 4.4 Read-only Reference

三层冻结面 `lima/audit/{inventory,ram,semantic_prioritizer,ram_schema}.py`、`lima/audit/__init__.py`、`lima/workspace.py`、`lima/contracts/**`、`schemas/v4/**` 既有 15 文件、`scripts/run_ci_tests.py`、tests/audit 既有 10 测试文件与全部既有 fixtures（`fixtures/{repo_shapes.py, library_profile_golden.json, ram/, semantic/, golden_matrix/}`）、五 IP Packet 与 DR 链文档、本 Packet（v2 与 v1 历史）。**只读语义参照**：`lima/python_dataflow.py`（§5.3.5 对照声明，不 import）。

### 4.5 Files Forbidden

除 §4.1/§4.2 外的一切路径；特别冻结：`lima/audit/__init__.py`（54 帽）、三层+ram_schema 模块、既有 tests/audit 测试与 fixtures（含 `test_ip_0022_fix.py` 六处 DR-LINT-0022-A 登记处）、`schemas/v4/version_compatibility_matrix.json` 与既有 14 schema 文件、`lima/contracts/**`、`lima/workspace.py`、`lima/python_dataflow.py`、`lima/semantic_retrieval.py`、scanner/service/api/store/sandbox/frontend、`.zcode/**`、`.github/**`、#94/#266/#281/baseline 轨道路径、`docs/**`（本 Packet 阶段 D1R 定稿后）、根检出与全部历史 worktree、`main` 分支。

### 4.6 Symbol-to-File Map（全部新增公共符号均在 `lima/audit/component_graph.py`）

见 §5.4.7 模块级 `__all__` 导出清单（恰 34 项：23 个类型/函数/图常量 + 9 个 manifest kind 常量 + 2 个 v2 新增类型）。

### 4.7 冲突分析

与 #266（30 文件）与 #281（6 新增文件）文件级零交集（恢复审计 addendum-2 §5 亲验；本 Packet 预期路径 `lima/audit/component_graph.py`、`schemas/v4/lima.component-graph.json`、`tests/audit/{test_component_graph,test_monorepo_golden}.py`、`tests/audit/fixtures/monorepo/**` 均不在两 PR diff 内）。与 B/C/D 切片边界按 §0 Not-covered 划分，无重叠 Owner。

---

## 5. 冻结设计（D1R Assignment §R 逐项落位 + D1_v1 §六 1-7 继承）

### 5.1 组件识别（R60-01；嵌套发现，仓库级坐标，只读有界确定）

#### 5.1.1 发现范围与锚点集合（冻结单解；替代 v1 "根+一级子目录"）

- **证据来源（组合，不单凭目录名）**：锚点 = 主 workspace **已准入 inventory** 中 manifest 类文件（封闭名集，值重述 inventory 冻结口径：`_MANIFEST_EXACT_NAMES` 8 类 + `requirements*.txt` 模式）的 POSIX 父目录，**任意深度**（`services/api`、`packages/core` 均落入——RULE-01 消除）。组件层**不另起 os.walk**：发现范围 = 调用方主 workspace 的已准入集合（有界 = 调用方 cap；确定顺序 = inventory 路径 sorted）。
- **静态 workspace/build 配置证据（封闭规则集，只读静态解析）**：仓库根（`""` 锚点）的 manifest 若声明 workspace 协作语义——pyproject.toml 含非空 `tool.uv.workspace.members` 或 `tool.pdm.workspace`；package.json 含非空 `workspaces` 数组；Cargo.toml 含 `[workspace]` 表且**无** `[package]` 表——则该 manifest 为 **workspace 协作 manifest**，**不产生根组件**（其成员经自身 manifest 锚定）。除此之外的 manifest 一律为组件 manifest（含根级 pyproject 含 `[project]` 者——根组件，见 5.1.3 嵌套归属）。解析失败/未识别形态 → 按组件 manifest 保守处理（确定性默认）。
- **同目录多 manifest 归并**：同锚点目录多个 manifest 归并为同一组件，`manifests` 列表按 path 排序全记。
- **锚点准入（R60-04 前置）**：锚点目录的仓库级路径（`锚点/` + 任一子段探测）先过 `is_secret_shaped_path`——命中者**不准入为锚点**（不产组件、不进任何公开面），`INVENTORY_SKIPPED` gap（detail `reason=sensitive-filename; count=N`，N=被拒锚点数；不泄漏目录名）。
- **发现预算与截断**：发现候选数以主仓 inventory 为上界（调用方 cap 有界）；组件数 > `MonorepoBudgets.max_components`（默认 16）→ 按 component_id 序取前 16 + `BUDGET_EXHAUSTED`（detail `reason=component-limit; count=<溢出>`）+ `truncated=True` + `dependencies_complete=False`（触发集 T1，§5.2.4）。
- **不支持/受削形态（typed 承载，不静默排除）**：调用方 ignored_directories 剪枝掉的子树内 manifest（策略继承语义，随 `skipped` 计数可见）；调用方扩展策略排除的 manifest 类型（如 extensions={".py"} 时 .toml 不可见→无锚点，全仓 unassigned 如实呈现）；主仓 cap 截断（`truncated=True` 或 `skipped` 含 file-limit/total-size-limit>0）→ 发现不完整，触发 T6；秘密形态锚点 → 上述 gap。**以上均为范围声明而非需求缩减：无任何 Maintainer 批准的"仅一级目录"豁免，17 项原始/V5 mandatory 不删不降。**

#### 5.1.2 稳定 component ID（冻结单解）

```text
component_id = "component:" + <已准入锚点目录的 repo-relative POSIX 路径>
根目录组件   = "component:."
嵌套组件     = "component:services/api" / "component:packages/core"（POSIX 正斜杠多段，
               无尾斜杠、无 "." / ".." 段，段字符集 [A-Za-z0-9._\-]）
```

无碰撞可重放：锚点集合由已准入 manifest 文件的父目录唯一确定（sorted 枚举）；同目录归并单组件；ID 由目录路径一一映射。`components` 按 `component_id` 字符串升序排序（`"component:."` 因 `.`(0x2E) 排序在最前，稳定）。

#### 5.1.3 文件归属（单一真实归属，精确单解；R60-02）

- **归属规则（仓库级坐标，in-module 精确计算）**：已准入文件 f 的归属 = 路径前缀包含 f 的**最深**已准入锚点（锚点 a 拥有 f ⟺ f 以 `a+"/"` 开点或 f 位于 a 目录内；取路径深度最大者；根锚点 `""` 的前缀即一切路径，故天然涵盖所有未被更深锚点包含的文件——根组件存在时不存在"无前缀"文件）。无任何锚点包含 f（即不存在根锚点 `""` 且无其他锚点前缀命中）→ **unassigned**。
- **归属唯一性**：最深前缀规则在任意嵌套锚点树上单解、可机械复算（D1R 探针 D1/D2/D7 复算验证）；目录名仅为路径计算输入，**不产生任何依赖边**（边唯一来源 = AST import 证据，§5.3）。
- `python_file_count` = 该组件归属的已准入 `.py` 文件数；`is_empty = (python_file_count == 0)`（空组件如实保留、`is_empty=True`，不编造边、不剔除）。非 `.py` 已准入文件同样按归属规则划入组件构建输入（Profile inventory 维度），但不计入 `python_file_count`、不产 Python import 边。
- **unassigned 文件**：`unassigned_files` 列表（repo-relative POSIX 排序，仅 `.py`，cap = `max_unassigned_files`，超限截断 + `BUDGET_EXHAUSTED` gap）+ `unassigned_file_count` 完整计数（不受 cap 影响）。列表准入：路径先过 `is_secret_shaped_path`（命中者不入列表仅计数，§5.8）。零组件仓库 = 全部已准入 `.py` 落 unassigned，`components=()`、`edges=()`——不因零组件报错。
- **共同文件两义分别落位**：(a) "被多组件引用" = 跨组件 import 边的多条 evidence（文件归属仍唯一）；(b) "无法唯一归属" = unassigned 集。最深前缀规则下不存在第三种归属歧义（名字碰撞导致的**构建**隔离分歧不改变归属规则本身，由 unbuilt 承载，见 §5.2.1 不变量）。
- **守恒不变量（INV-OWN-2，测试锚）**：Σ(已构建组件 python_file_count) + Σ(unbuilt 组件 python_file_count) + unassigned_file_count + 秘密形态拒绝 `.py` 计数 = 主仓已准入 `.py` 总数（逐文件可复算）。

#### 5.1.4 解析依据不足与不执行

- 归属证据不足（无已准入锚点前缀）→ unassigned 如实记录，不按目录名猜测组件；
- 依赖解析依据不足 → 边三态 + 未知导入承载（5.3），不编造依赖；
- **不执行目标项目补证据**：零 importlib 目标代码、零 subprocess、零网络、零 sys.path 探测（模块静态断言，§6 C7）；manifest 与 `.py` 只经 `workspace.read_text()` 有界读取后静态解析（`tomllib`/`ast.parse`，IP-0016 setup.py 先例）。

#### 5.1.5 适用输入范围与不支持形态声明（冻结）

任意 `RepositoryWorkspace` 快照（含非 monorepo）：零组件/单组件（仅根 manifest，图 = 单组件零边，合法输出）/多组件/嵌套组件/根 workspace 协作 manifest。图分析面向已准入 `.py`（Python 平台，Golden Path 口径与三层一致）；其他语言文件进入组件 Profile 的 inventory 维度（既有行为），不产组件间 Python import 边。**不支持/受削形态一律 typed 承载（§5.1.1 末）+ 范围声明，不静默排除**；确需削减 mandatory 支持 → 具体需求 DR + Maintainer 明确批准（默认继续完成目标）。

#### 5.1.6 与 `repository_kinds` 的关系（不重算、不修改）

monorepo kind 判定是 inventory 冻结行为（作用于全仓单仓构建）。本片每组件构建使用组件 workspace（其内部一般无嵌套 manifest 子目录，组件 profile 通常不判 monorepo——如实呈现，不修正）；全仓维度 kind 分类由既有 `build_repository_profile(全仓 workspace)` 独立承载（现状行为，零改动）。组件图与 kinds 各自表述，互不覆写。

### 5.2 每组件 Profile/RAM/semantic 全链（R60-02/R60-03/R60-04；复用公共接口 + 策略继承 + 隔离不变量）

#### 5.2.0 构建时序（冻结；R60-04 准入时序单解）

```text
(1) 仓库级准入（唯一入口，调用方策略）：main_inventory = workspace.inventory()
    —— 工作区级准入（ignored/symlink/sensitive-config/extension/size/binary/non-utf8）
      在仓库级坐标完成；skipped 计数与 truncated 状态公开可读（T6 触发源）。
(2) 锚点发现与锚点准入（§5.1.1，仓库级坐标：is_secret_shaped_path）。
(3) 归属划分（§5.1.3，精确最深前缀，仓库级坐标）。
(4) 组件视图构造（§5.2.1，继承策略）+ 隔离不变量校验（逐文件，仓库级映射比对）。
(5) 图级 import 扫描（§5.3.1，经主 workspace.read_text，仓库级坐标）。
(6) 每组件三段链（Profile/RAM/semantic，经组件 workspace，组件内坐标——
      准入等价性见 §5.2.1 证明）。
任何组件级/图级公开输出所含路径，或为仓库级坐标且已过 (1)(2) 准入，
或为组件内坐标且其仓库级原像已过 (1)(2) 准入——无第三种来源。
```

#### 5.2.1 组件视图构造与所有权不变量（冻结单解；替代 v1 L235 默认重建）

```python
# 每组件（component_id 序遍历，未超 max_components 截断的全部处理）：
component_ws = RepositoryWorkspace(
    workspace.root if root_dir == "" else workspace.root / root_dir,
    max_files=workspace.max_files,               # 五参数全部继承（R60-03；API-02 消除）
    max_file_bytes=workspace.max_file_bytes,
    max_total_bytes=workspace.max_total_bytes,
    extensions=workspace.extensions,
    ignored_directories=workspace.ignored_directories
                      | {严格嵌套于本锚点内的子锚点目录 basename})
if {map_to_repo(f) for f in component_ws.inventory().files} != ownership_slice(root_dir):
    # 隔离不变量（INV-OWN-1）分歧：名字碰撞目录被同名剪枝 / 调用方 cap 导致扫描集
    # 与精确切片不一致 —— 该组件三段链不构建，typed 承载，不出错误数据：
    unbuilt_components += [component_id]        # 触发 T7（§5.2.4）
    continue
profile_result   = build_repository_profile(component_ws, **六 ID 参数原样透传,
                        producer="lima.audit.component_graph",
                        policy_digest=..., toolchain_digest=...,
                        options=profile_options)            # 复用 IP-0016 入口
ram_result       = build_python_ram_facts(component_ws, budgets=ram_budgets)
semantic_result  = build_semantic_top_n(ram_result.facts, options=effective_semantic_options,
                       model_client=model_client)           # 复用 IP-0019 入口（聚合包络 §5.4.4）
```

- **策略继承（R60-03 冻结）**：不从路径重建默认 workspace；五参数逐一取自调用方 workspace 的公开属性（extensions/ignored_directories 为其**有效值** frozenset——构造器内部与 DEFAULT 的并集幂等）。主仓未准入输入不因组件切分重新准入：组件视图文件集 ⊆ 主仓已准入集，由 INV-OWN-1 强制（分歧即不构建）；D1R 探针 D3-API02 实证继承构造可行、D7-COLLISION 实证分歧可机械检出。
- **INV-OWN-1（机器可校验，测试锚 #9）**：`map_to_repo(component_ws.inventory().files) == 精确归属切片`（逐文件集合相等；`map_to_repo(p) = root_dir + "/" + p`，根组件恒等映射）。成立 ⇒ ComponentInfo 计数、Profile、RAM、Top-N、图 evidence **五处输入集合一致**（Profile/RAM/Top-N 的输入即该组件 workspace 的 inventory；图 evidence 的输入即精确切片的 `.py` 子集；两者经 INV-OWN-1 相等）。
- **准入等价性（R60-04 证明，实现于锚点准入之上）**：对已准入锚点 a，其组件 workspace 相对坐标下任一文件路径的**目录段与文件名段** = 仓库级坐标对应段（仅丢失 a 之上的段，而已准入锚点无秘密形态段——§5.1.1 锚点准入）；`is_secret_shaped_path`/`_secret_shape_family` 按段判定 ⇒ 组件内 Profile/RAM 准入与仓库级准入对同一文件**判定一致**（API-03 的 rebased 重新采纳在 v2 下不可达：秘密形态锚点在 (2) 已被拒，根本不构造其组件视图——D1R 探针 D4-API03）。
- **六 ID 参数**对每组件原样透传同一组值；`policy_digest`/`toolchain_digest` 默认 sentinel（DR-IP-0016-01 口径）；`producer` 固定 `"lima.audit.component_graph"`（调用方不可覆盖）。
- **坐标分离（保留 v1 冻结声明，时序修正）**：每组件三段产物内路径 = 组件内相对坐标（与单仓行为一致）；图与边证据、unassigned、锚点、manifest refs 一律仓库级 repo-relative POSIX；映射 `仓库路径 = root_dir + "/" + 组件内路径` 确定可复算（payload 消费核对用，§5.4.6）。
- **已知限度（如实声明，不掩饰）**：(i) 祖先组件（锚点内严格嵌套其他锚点者，含根组件）的 Profile 层 manifest 候选机制（`_manifest_candidates` 的 root+一级 os.listdir）可能把其一级子目录内嵌套子组件的 manifest 纳入该组件 Profile 的 manifest 证据（确定性、有界，文件 inventory 不受影响——INV-OWN-1 仍成立）；(ii) 名字碰撞目录（祖先子树内与嵌套锚点 basename 同名者）触发 INV-OWN-1 分歧 → typed 不构建。二者的**彻底**消除需 workspace 路径级排除/文件清单视图等共享层能力 → **DR-IP-0023-02 草案**（选项：构造器 additive `exclude_directory_paths` 参数 / 显式文件清单视图 / manifest 候选范围参数；推荐第一项；附调用链与兼容影响）随交接报告呈 Coordinator，获批前不写入实现（本节为 v2 默认单解，不依赖该 DR）。

#### 5.2.2 provenance（冻结单解）

- 每组件三段 `provenance_anchor_ids` 原样保留（`("inventory",)` / `("ram-facts",)` / `("semantic-prioritizer",)`）——逐层断言（与 golden_matrix 先例同）；
- 组件身份 provenance = `ComponentInfo.manifests`（manifest 路径 + kind 枚举，仓库级坐标）；
- 边 provenance = evidence 位点列表（`EdgeEvidence{path, line, imported_name}`，排序去重 cap）；
- 图级 `provenance_anchor_ids = ("component-graph",)`（新 anchor，独立承载；**不修改** `ram_schema.PROVENANCE_ANCHOR_CHAIN` 冻结三元组）。

#### 5.2.3 断开的组件（disconnected）

无任何入边/出边的非空组件 = 图中孤立节点，**如实呈现**（`components` 含该节点，`edges` 无引用）；空组件同。不编造连接、不删除节点、不加"孤立"特殊标记（孤立性由 edges 可推导）。

#### 5.2.4 三态区分与统一完整性（R60-06；单规件，全文唯一）

**`dependencies_complete = False` 的封闭触发集（全文唯一定义，v1 L265-269 与 L310-311 矛盾消除）：**

| 触发 | 判据（机械可查） |
|---|---|
| T1 组件数截断 | `discovery.truncated == True`（组件数 > max_components） |
| T2 组件内 .py 截断 | 任一已构建组件 `ram_result.facts.coverage_gaps` 含 `BUDGET_EXHAUSTED` 且 detail 以 `reason=python-file-limit` 开头 |
| T3 边数截断 | 边数超 `max_edges` 被截断（§5.3.4） |
| T4 解析失败 | 图层级 `parse_error_file_count` 总计 > 0（§5.3.1 自计，不依赖底层继承——API-04） |
| T5 读取失败 | 图层级 `read_failure_file_count` 总计 > 0（同上；静态快照下难构造，保留触发并如实声明） |
| T6 主仓 cap 截断 | 主仓 `inventory.truncated == True` 或 `skipped["file-limit"]>0` 或 `skipped["total-size-limit"]>0`（发现与证据输入不完整） |
| T7 隔离分歧 | `unbuilt_components` 非空（INV-OWN-1 分歧组件） |

除 T1-T7 外无任何置 False 的来源；evidence/unassigned 列表截断不置 False（gap 承载，与 v1 §5.3.4 口径统一）；symlink 跳过的 `.py` 经主仓 `skipped["symlink"]` 计数可见（T6 不含——与单仓 RAM 行为口径一致，避免双标准）。

**三态判据表（承载中可观察，机械可查）：**

| 状态 | 判据 |
|---|---|
| 真实无依赖 | 组件无参与边 **且** `dependencies_complete == True` **且** `unassigned_file_count == 0` **且** 该组件 `scan_summary.parse_error_file_count == 0` **且** `read_failure_file_count == 0` **且** 该组件无 `unknown_imports` 记录 **且** 无 ambiguous/unresolved 出边（`SEMANTIC_MODEL_OFF` 不计入依赖证据——模型状态非依赖证据） |
| 解析失败 | 存在 `status ∈ {"ambiguous","unresolved"}` 的出边 |
| 证据不足 | 其余全部：unassigned>0 / 未知导入 / parse 或 read 失败 / T1-T7 任一 / 图 coverage_gaps 非空（除仅 `SEMANTIC_MODEL_OFF`）——**不得**解释为"没有依赖" |

**空边集伴随缺口 ≠ 真实无依赖**（判据表第一行的合取使二者互斥，机械可查；测试锚 #32）。

**解析/读失败 typed 承载（R60-06 交付；替代 v1"底层继承"表述）**：图层级 AST 扫描（§5.3.1）自计每组件 `ComponentScanSummary{component_id, parse_error_file_count, read_failure_file_count, dynamic_import_site_count}`（计数 only，无路径无源码正文；API-04 关系：RAM `counters.parse_error_files` 存在而 facts gaps 可空——v2 不依赖 RAM gap 继承，图自计并触发 T4）。若 D2 冻结期发现需新 GAP 码 → 具体 DR（不私改 `GAP_CODES_ALL`/9 码触发）。

### 5.3 模块解析（R60-05；模块根解析替代目录首段臆断，未知导入有承载）

#### 5.3.1 证据采集（图层级，主 workspace，仓库级坐标）

- 扫描对象 = 全部**归属** `.py` 文件（按仓库级路径 sorted）；unassigned `.py` 不产边（`unassigned_file_count>0` 显式声明证据缺口）；
- 解析方式 = `ast.parse(workspace.read_text(path))`（主 workspace 有界读取）；**parse 失败自计** `parse_error_file_count`（触发 T4），**读失败自计** `read_failure_file_count`（触发 T5），**动态 import 位点自计** `dynamic_import_site_count`（封闭检测集：`ast.Call` 且函数名为 `importlib.import_module` / `importlib.util` 动态装载形态 / `__import__`；不产边）；收集 `ast.Import`（各 alias 顶级名）与 `ast.ImportFrom`（module 名 + level）；
- 证据位点 = `EdgeEvidence{path: 仓库级 repo-relative, line: 1 基行号, imported_name: import 的名字}`（imported_name 是标识符/点号串，非源码正文——NFR-01 相容）；
- 与 `python_dataflow.py` 的关系：**只读语义参照**（§5.3.5），本层不 import 该模块（依赖方向不变）。

#### 5.3.2 模块根解析（module roots；冻结单解）

组件 C（锚点 `root_dir`，组件内坐标）的**模块根集合** R(C)（确定序：组件根在前，其余按路径升序）：

- (a) **组件根本身**（flat 布局：包/模块直接位于组件根）；
- (b) **构建配置声明的目录**（封闭键集，静态解析组件自身 manifest）：pyproject.toml `[tool.setuptools.packages.find] where`（值或值列表）、`[tool.setuptools.package-dir]` 值中的目录部分、`[tool.hatch.build.targets.wheel] packages` 路径的公共父目录——解析失败/键缺失 → 不贡献（保守回退 (a)/(c)，未知导入承载兜底）；
- (c) **内容证据支持的 `src` 直接子目录**：组件根的直接子目录 `src`，当且仅当其直接内容含 ≥1 包（含 `__init__.py` 的子目录）或 ≥1 `.py` 模块（src 布局约定 + 内容证据，非目录名臆断——RULE-02 消除：`A/src/alpha`、`B/src/beta` 下顶层名 `alpha`/`beta` 分别归属 A/B，D1R 探针 D6-RULE02）。

**顶层名表（name table）**：对每组件 C，`names(C)` = {各模块根直接子项的导入名}——含 `__init__.py` 的子目录（regular package，名=目录名）、模块根直接子 `.py`（名=去扩展名）、模块根直接子**无** `__init__.py` 目录（**namespace package 候选**，名=目录名，证据较弱但仍可解析；同多名跨组件 → ambiguous）。构建仓库级名→组件集映射表（确定序，sorted）。

#### 5.3.3 边推导规则（封闭枚举；优先级显式）

对归属文件中的每条绝对 import（顶级名 T，非 "." 开头）：

| 情形（按序判定，优先级冻结） | 判定 | 承载 |
|---|---|---|
| P1 `T ∈ names(C源)`（**先命中自身**） | 组件内依赖 | 无边（属该组件 RAM 范围；自身定义的名字优先于跨组件同名——静态单解声明） |
| P2 `T ∈ names(C')` 唯一 `C'≠C源` | 跨组件 resolved | 边 (C→C', status="resolved", imported_name=T) |
| P3 `T ∈ names(≥2 组件)` | 重复模块名歧义 | 边 (C→target=None, status="ambiguous")；候选集不入边；歧义范围由名表可复算 |
| P4a `T ∈ stdlib 冻结集` | **已知外部（stdlib）** | 无边、无承载（确定外部；集为模块内冻结字面量快照，值锚定来源注释，跨解释器版本稳定优先） |
| P4b `T ∈ 该组件 manifest 静态声明依赖名`（封闭解析：pyproject `[project].dependencies` 依赖名 + `requirements*.txt` 行首名，regex `^[A-Za-z0-9_.\-]+`；解析失败不贡献） | **已知外部（三方，有证据）** | 无边、无 unknown 承载 |
| P5 其余 | **未知导入**（无法区分未声明三方/仓库内无法定位/拼写错误） | `unknown_imports` 记录 {source_component_id, imported_name, count}（排序去重 cap `max_edges` 同预算；**不产边、不伪称外部**） |

对相对 import（`level ≥ 1`，**包上下文优先**）：

- 包上下文 = 导入文件经其 `__init__.py` 链与所属模块根推导的包序列（文件在包内：level=1 → 当前包，level=2 → 父包，依此类推）；文件不在任何包内（模块根直接子 `.py`）→ 物理路径上下文（当前目录基准）；目标 = 上下文向上 `level-1` 层 + module 路径，仓库坐标；
- 目标落回本组件子树（`.py` 存在或包 `__init__.py` 存在）→ 无边；落另一已准入锚点子树且存在 → 边 resolved；不存在（含越出仓库根）→ 边 (C→None, status="unresolved")；落秘密形态路径 → 不入 evidence（§5.8 准入）。

#### 5.3.4 去重、排序与 cap（冻结单解）

- resolved 边键 = `(source, target)`；ambiguous/unresolved 边键 = `(source, status, imported_name)`；同键多证据聚合进 `evidence`；
- `evidence` 按 `(path, line, imported_name)` 排序去重，每边 cap = `max_edge_evidence`，超限截断 + `BUDGET_EXHAUSTED`（detail `reason=edge-evidence-limit; count=<溢出>`）；
- `edges` 按 `(source_component_id, status, target_component_id or "", imported_name)` 升序；总数 cap = `max_edges`，超限截断 + gap（detail `reason=edge-limit; count=<溢出>`）+ **T3 置 `dependencies_complete=False`（引用 §5.2.4 触发集，不另立口径）**；
- `unknown_imports` 按 `(source_component_id, imported_name)` 排序去重，cap = `max_edges`（共享），超限截断 + gap（detail `reason=unknown-import-limit; count=<溢出>`）。

#### 5.3.5 与既有 `python_dataflow` 解析语义的对照（只读声明，R60-05 交付）

`PythonDataflowAnalyzer._module_name` 以**全路径**派生点分模块名（单一名空间、每文件必归属、`__init__.py` 判包）；本组件层为**多根名空间**（每组件独立模块根集合，顶层名对组件解析）。语义差异如实声明：dataflow 回答"该文件叫什么名"，组件层回答"该顶层名由哪个组件定义"；两者均纯静态、零执行、零 sys.path 探测。不引入对 `python_dataflow` 的 import 依赖（值/语义对照，非代码复用）。

### 5.4 独立版本化 component graph 承载（Assignment §六.3 / R60-08；B-10 先例）

#### 5.4.1 数据结构（frozen dataclass，全部在 `lima/audit/component_graph.py`）

```python
@dataclass(frozen=True)
class ComponentManifestRef:
    path: str            # 仓库级 repo-relative manifest 路径（已准入）
    manifest_kind: str   # COMPONENT_MANIFEST_KIND_* 枚举值（5.4.2）

@dataclass(frozen=True)
class EdgeEvidence:
    path: str            # 仓库级 repo-relative POSIX（.py 文件，已准入）
    line: int            # 1 基
    imported_name: str   # import 顶级名或相对导入点号串

@dataclass(frozen=True)
class ComponentInfo:
    component_id: str    # "component:." / "component:<锚点相对路径（可多段）>"
    root_dir: str        # ""（根）或锚点 repo-relative 路径（可多段）
    manifests: tuple[ComponentManifestRef, ...]   # 按 path 排序
    python_file_count: int
    is_empty: bool

@dataclass(frozen=True)
class ComponentScanSummary:          # v2 新增（R60-06：图层级自计承载）
    component_id: str
    parse_error_file_count: int      # T4 触发源（计数 only，无路径）
    read_failure_file_count: int     # T5（同上；静态快照下通常 0，字段保留）
    dynamic_import_site_count: int   # 动态 import 位点计数（不产边）

@dataclass(frozen=True)
class UnknownImportRecord:           # v2 新增（R60-05：未知导入 typed 承载）
    source_component_id: str
    imported_name: str
    count: int                       # 该名字的 import 位点数（evidence 同构口径）

@dataclass(frozen=True)
class ComponentEdge:
    source_component_id: str
    target_component_id: str | None    # resolved 非 None；ambiguous/unresolved 为 None
    status: str                        # COMPONENT_EDGE_STATUS_*（5.4.2）
    imported_name: str
    evidence: tuple[EdgeEvidence, ...] # 排序去重 cap（5.3.4）

@dataclass(frozen=True)
class ComponentGraph:
    components: tuple[ComponentInfo, ...]              # 按 component_id 升序
    edges: tuple[ComponentEdge, ...]                   # 按 5.3.4 排序
    unassigned_files: tuple[str, ...]                  # 排序，cap，已过准入
    unassigned_file_count: int
    unknown_imports: tuple[UnknownImportRecord, ...]   # 排序去重 cap（5.3.4）
    scan_summaries: tuple[ComponentScanSummary, ...]   # 按 component_id 升序
    unbuilt_components: tuple[str, ...]                # INV-OWN-1 分歧组件（T7）
    dependencies_complete: bool                        # 触发集 T1-T7（§5.2.4）
    coverage_gaps: tuple[ProfileCoverageGap, ...]      # gap_code 复用 10 码全集值重述（5.6.3）
    provenance_anchor_ids: tuple[str, ...] = (COMPONENT_GRAPH_PROVENANCE_ANCHOR,)
```

#### 5.4.2 枚举（Final 常量，冻结单解）

```python
COMPONENT_GRAPH_SCHEMA_VERSION: Final[str] = "2.0"    # v2 承载字段集（v1 未实现未发布，无迁移）
COMPONENT_GRAPH_SCHEMA_NAME: Final[str] = "lima.component-graph"
COMPONENT_GRAPH_SCHEMA_FILE: Final[Path] = Path("schemas") / "v4" / "lima.component-graph.json"
COMPONENT_GRAPH_PROVENANCE_ANCHOR: Final[str] = "component-graph"
COMPONENT_EDGE_STATUS_RESOLVED: Final[str] = "resolved"
COMPONENT_EDGE_STATUS_AMBIGUOUS: Final[str] = "ambiguous"
COMPONENT_EDGE_STATUS_UNRESOLVED: Final[str] = "unresolved"
COMPONENT_EDGE_STATUSES: Final[frozenset[str]] = frozenset({"resolved","ambiguous","unresolved"})
COMPONENT_MANIFEST_KIND_*: Final[str]  # 九值："pyproject" / "setup_py" / "setup_cfg" /
                                       # "requirements" / "environment_yml" / "package_json" /
                                       # "go_mod" / "cargo_toml" / "pom_xml"（对齐 manifest 候选口径）
# 模块私有（不入 __all__）：_STDLIB_TOP_LEVEL_NAMES（冻结字面量快照，§5.3.3 P4a）
```

#### 5.4.3 公共函数签名（冻结单解）

```python
@dataclass(frozen=True)
class MonorepoBudgets:          # 全 int，__post_init__ 逐字段 type is int 且 ≥1 校验，否则 ValueError
    max_components: int = 16
    max_edges: int = 4_096
    max_edge_evidence: int = 64
    max_unassigned_files: int = 256
    max_total_model_calls: int = 128    # v2 新增：聚合模型调用包络（显式新预算设计，§5.4.4）

@dataclass(frozen=True)
class ComponentDiscoveryResult:
    components: tuple[ComponentInfo, ...]
    unassigned_files: tuple[str, ...]
    unassigned_file_count: int
    coverage_gaps: tuple[ProfileCoverageGap, ...]
    truncated: bool                      # 组件数超 max_components
    provenance_anchor_ids: tuple[str, ...] = (COMPONENT_GRAPH_PROVENANCE_ANCHOR,)

@dataclass(frozen=True)
class ComponentBuildResult:
    component: ComponentInfo
    profile_result: ProfileBuildResult
    ram_result: RamFactsBuildResult
    semantic_result: SemanticTopNResult

@dataclass(frozen=True)
class MonorepoProfileBuildResult:
    discovery: ComponentDiscoveryResult
    per_component: tuple[ComponentBuildResult, ...]   # 按 component_id 升序（实际构建的组件）
    graph: ComponentGraph
    provenance_anchor_ids: tuple[str, ...] = (COMPONENT_GRAPH_PROVENANCE_ANCHOR,)

def detect_components(workspace: RepositoryWorkspace,
                      *, budgets: MonorepoBudgets | None = None) -> ComponentDiscoveryResult

def build_monorepo_profile(workspace: RepositoryWorkspace, *,
                           tenant_id: str, task_id: str, workflow_id: str,
                           stage_attempt_id: str, artifact_id: str,
                           repository_snapshot_digest: str,
                           policy_digest: str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                           toolchain_digest: str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                           profile_options: ProfileInventoryOptions | None = None,
                           ram_budgets: RamBudgets | None = None,
                           semantic_options: SemanticOptions | None = None,
                           monorepo_budgets: MonorepoBudgets | None = None,
                           model_client: SemanticModelClient | None = None,
                           ) -> MonorepoProfileBuildResult

def component_graph_digest(graph: ComponentGraph) -> str        # 64-hex（5.4.5）
def component_graph_payload(result: MonorepoProfileBuildResult) -> dict   # wire payload（5.4.6）
def validate_component_graph_payload(payload: Mapping[str, object]) -> None  # fail-closed ContractError（5.4.8）
def load_component_graph_schema() -> dict                       # 只读加载 schema 文件（零网络）
```

**行为约束（冻结）**：stdlib-only + 既有 audit/contracts/workspace 模块；依赖方向 `lima.audit.component_graph → {lima.audit.inventory, lima.audit.ram, lima.audit.semantic_prioritizer, lima.contracts.*, lima.workspace}`（复用公共构建接口与 `is_secret_shaped_path`；**不 import** `lima.audit.ram_schema`——gap 码全集值重述，构建/验证解耦）；`detect_components`/`build_monorepo_profile` 入参非 `RepositoryWorkspace` → `ContractError(INVALID_FIELD_TYPE)`；非 str 六 ID / 非 64-hex digest 按 IP-0016 同口径 fail-closed（异常由底层传播，本层不吞不改）；模型路径失败不抛出到调用方（IP-0019 §5.0 部分结果语义）；纯函数确定性——无时钟/随机/env/网络/写盘。

#### 5.4.4 预算语义单解（R60-03 重写；fail-closed）

- **策略继承（第一原则）**：组件视图五参数继承调用方（§5.2.1）；主仓未准入输入不重新准入（INV-OWN-1 强制，分歧→typed 不构建）；调用方 cap 收紧时"不扩权优先于多产出"。
- **资源计量口径（显式声明）**：(i) 主仓 inventory 全仓一次（图层级发现/归属/AST 读取基准）；(ii) 每组件 workspace 各自重扫其锚点子树（重读字节计入该组件构建，受继承 cap 约束；重复读取不改变任何输出值——确定性优先）；(iii) 图层级 AST 读取经主仓 `read_text`（有界，每归属 `.py` 一次）；(iv) 每组件三层 Budgets（`RamBudgets` 512/256/1024、`SemanticBudgets` 8/24_000/4_096/28_096/120、`ProfileBudgets` 262_144/64）逐组件适用，不共享池；(v) 发现/图边/evidence/unassigned/未知导入预算 = `MonorepoBudgets` 各 cap（§5.3.4）。
- **聚合模型调用包络（显式新预算设计，呈审对象）**：`max_total_model_calls`（默认 128 = 16 组件 × 每组件 8）——**这是本 Packet 的新预算提案，不是"旧每仓 8 次预算的自动延伸"**（指令 §五 R60-03：不得把每仓 8 次变成 16 份预算并声称无需新预算设计）。执行：`model_client is None`（默认）→ 零调用零网络；注入时按 component_id 序构建，每组件生效语义预算 = `min(每组件 SemanticBudgets.max_llm_calls, 剩余聚合额度)`（`dataclasses.replace` 公共构造），剩余归零后的组件 semantic 阶段跳过 + `BUDGET_EXHAUSTED`（detail `reason=aggregate-model-call-limit; count=<溢出组件数>`）+ 该组件 partial facts——机器可读截断，无静默。
- **fail-closed（不静默截断）**：组件数/边/evidence/unassigned/未知导入五类 cap 全部 typed gap（§5.1.1/§5.3.4）；预算耗尽一律返回部分事实 + typed gap + 对应 complete 触发（T1/T3/T7），不报错、不吞。
- **墙钟（降级表述）**：F4 未闭合——**本 Packet 不宣称任何已证明的聚合墙钟上界**；每组件 `max_wall_time_seconds` 语义照旧由 IP-0019 承载，聚合墙钟治理归 F4/#60-CLOSURE-C（无全局时钟入 digest，确定性优先）。
- **与 `max_manifest_files`（BG-IP-0016-01）的关系**：组件层锚点发现不读 manifest 内容预算（仅封闭键集静态解析 §5.1.1/§5.3.2(b)，读取经 `read_text` 有界通道）；每组件 Profile 构建内部仍受其自身 ProfileBudgets 约束（既有行为）。BG-IP-0016-01 保持 OPEN，本片不清偿不扩大。

#### 5.4.5 canonical bytes 与 graph digest（冻结单解）

```text
component_graph_digest = compute_content_digest(canonical_dict)
canonical_dict = {
  "components": [每组件规范 dict（component_id/root_dir/manifests[{path,kind}]/
                  python_file_count/is_empty）——按序],
  "edges": [每边规范 dict（source_component_id/target_component_id|null/status/
             imported_name/evidence[{path,line,imported_name}]）——按序],
  "unknown_imports": [{source_component_id, imported_name, count}]，      # v2
  "scan_summaries": [{component_id, parse_error_file_count,
                      read_failure_file_count, dynamic_import_site_count}]，# v2
  "unbuilt_components": [...],                                            # v2
  "unassigned_files": [...], "unassigned_file_count": N,
  "dependencies_complete": bool,
  "coverage_gaps": [{"gap_code","detail"}...]   # 排序 (gap_code, detail)
}
```

- canonical JSON = `lima.contracts.codec.compute_content_digest` 口径（IP-0018/0019 digest 先例），恒 64-hex；**不含** digest 自身、时钟、耗时、环境；
- 与 digest 家族的关系（冻结声明）：`component_graph_digest` 是**独立新成员**；既有六 digest 语义与算法零改动、零交叉（图 digest 不进任何 envelope、不进 RAM wire payload、不参与 wire_digest 计算）；
- **独立重算（R60-07）**：消费者可对手写/独立构造的 canonical dict（不经产品代码）调用同一既有公共 `compute_content_digest` 复算核对——Oracle 独立于 `component_graph` 实现。

#### 5.4.6 与组件 Profile/RAM 的关联及公开 Artifact 消费闭合（R60-08 重写）

- **键控关联（替代 v1"消费者重放三段构建"表述）**：`component_graph_payload(result)` 的 `components[]` 以 `component_id` 为键携带 `{built, digests{profile_content_digest, ram_facts_digest, semantic_result_digest}|null, scan_summary, semantic_topn}`；三 digest 全部可由**公开 Artifact** 复算核对（见下），不要求重跑目标构建、不依赖构建者内存对象。
- **每组件完整事实的公开承载（不扩 #58/54 帽/旧 digest/matrix）**：
  - 完整 Profile = 既有 #58 公共契约产物：`profile_result.envelope` 经既有 `encode_profile_envelope` 序列化的版本化 envelope（既有 schema `lima.repository-profile.json` / `lima.artifact-envelope.json` 校验）；
  - 完整 RAM = 既有 IP-0021 公共产物：`ram_wire_payload` / `validate_ram_wire_payload` / `ram_wire_digest`（既有 schema 校验；`execution_required` 由既有公共 `execution_required_from_gaps` 对其 gaps 复算——不复制不重定义）；
  - semantic 摘要消费 = 图 payload 自身承载 `semantic_topn{model_id, ranked_candidate_ids[]}`（cap=每组件 top_n≤20；`candidate_id` 冻结编码）；**full semantic payload 的下游消费归 #60-CLOSURE-D/#64/#68 真实 fixture（Not-covered 声明）**；
  - 路径坐标映射：`仓库路径 = root_dir + "/" + 组件内路径`（root_dir="" 恒等）——payload 消费侧可核对组件产物坐标与图证据坐标的对应；
  - 阶段 Artifact 交换形态：monorepo 阶段的公开 Artifact 集 = 1 个 graph payload + N 组每组件公开产物（profile envelope + RAM wire payload），全部经既有公共 schema/函数校验，阶段间交换不依赖内存对象（系统约束落位）。
- **消费例（可重放，仅公开 Artifact；§5.4.7 代码块）**：decode 两族组件产物（既有公共 decoder）→ 三 digest 与 payload `digests` 逐组件比对 → `execution_required_from_gaps` 复算 → canonical 重算图 digest 比对 `identity.component_graph_digest` → 校验 scan_summary 与组件产物计数自洽。

#### 5.4.7 公共消费路径（`__all__` 导出与消费示例）

模块级 `__all__`（**恰 34 项**，字母序，封闭清单——实现不得增删公开名，D2 冻结测试逐一锁定）：

```text
COMPONENT_EDGE_STATUSES, COMPONENT_EDGE_STATUS_AMBIGUOUS, COMPONENT_EDGE_STATUS_RESOLVED,
COMPONENT_EDGE_STATUS_UNRESOLVED, COMPONENT_GRAPH_PROVENANCE_ANCHOR, COMPONENT_GRAPH_SCHEMA_FILE,
COMPONENT_GRAPH_SCHEMA_NAME, COMPONENT_GRAPH_SCHEMA_VERSION,
COMPONENT_MANIFEST_KIND_CARGO_TOML, COMPONENT_MANIFEST_KIND_ENVIRONMENT_YML,
COMPONENT_MANIFEST_KIND_GO_MOD, COMPONENT_MANIFEST_KIND_PACKAGE_JSON,
COMPONENT_MANIFEST_KIND_POM_XML, COMPONENT_MANIFEST_KIND_PYPROJECT,
COMPONENT_MANIFEST_KIND_REQUIREMENTS, COMPONENT_MANIFEST_KIND_SETUP_CFG,
COMPONENT_MANIFEST_KIND_SETUP_PY,
ComponentBuildResult, ComponentDiscoveryResult, ComponentEdge, ComponentGraph,
ComponentInfo, ComponentManifestRef, ComponentScanSummary, EdgeEvidence,
MonorepoBudgets, MonorepoProfileBuildResult, UnknownImportRecord,
build_monorepo_profile, component_graph_digest, component_graph_payload,
detect_components, load_component_graph_schema, validate_component_graph_payload
```

构建与消费示例（公共接口，非内部窥探；**消费段不持有 workspace、不重跑构建**）：

```python
# 构建侧（一次性）
from lima.workspace import RepositoryWorkspace
from lima.audit.component_graph import (build_monorepo_profile,
    component_graph_payload, validate_component_graph_payload)

ws = RepositoryWorkspace(snapshot_root)               # 调用方策略在此生效并被全程继承
result = build_monorepo_profile(ws, tenant_id=..., task_id=...,
    workflow_id=..., stage_attempt_id=..., artifact_id=...,
    repository_snapshot_digest=...)                   # semantic 默认 off（零模型调用）
payload = component_graph_payload(result)             # 组件清单+边+未知导入+scan 摘要+
                                                      # 键控三 digest+semantic_topn+图 digest
validate_component_graph_payload(payload)             # fail-closed 契约校验（5.4.8 十维）

# 消费侧（只拿公开 Artifact：graph payload + 每组件 profile envelope + RAM wire payload，
# 均为已落盘的版本化产物；不重跑目标构建、不依赖构建者内存）
from lima.contracts.profile import decode_profile_envelope
from lima.contracts.codec import compute_content_digest
from lima.audit.ram_schema import (validate_ram_wire_payload, ram_wire_digest,
                                   execution_required_from_gaps)

for entry in payload["components"]:
    if not entry["built"]:
        continue                                       # typed 未构建组件（unbuilt 承载）
    profile, _ = decode_profile_envelope(json.loads(read_artifact(f"{entry['component_id']}.profile.json")))
    ram_wire = json.loads(read_artifact(f"{entry['component_id']}.ram.json"))
    validate_ram_wire_payload(ram_wire)
    assert profile_envelope_content_digest(profile) == entry["digests"]["profile_content_digest"]
    assert ram_wire_digest(ram_wire) == entry["digests"]["ram_facts_digest"]
    execution_required = execution_required_from_gaps(ram_wire["coverage_gaps"])
    # semantic_topn：payload["components"][i]["semantic_topn"]["ranked_candidate_ids"]（cap≤20）
recomputed = compute_content_digest(canonical_dict_from(payload))     # 独立重算（R60-07）
assert recomputed == payload["identity"]["component_graph_digest"]
```

（示例中 `read_artifact`/`canonical_dict_from`/`profile_envelope_content_digest` 为消费侧占位叙述：前两者是消费方自己的 Artifact 读取与 canonical 投影，后者为 envelope 上的公开 digest 字段访问——产品冻结面仅 §5.4.3 签名。）

#### 5.4.8 validator 单解（`validate_component_graph_payload` 行为清单，fail-closed）

| # | 检查维度 | 行为（违规 → `ContractError`） |
|---|---|---|
| V1 | 未知字段 | 任意层级未知字段 → `UNKNOWN_FIELD`（schema `additionalProperties:false` 全层级 + 运行时同口径） |
| V2 | 枚举/const | `schema_version`/`model_kind` const；`status` ∈ 三值；`manifest_kind` ∈ 九值；`provenance` const 单元序列 |
| V3 | ID 唯一性 | `components[].component_id` 全局唯一；边键/`unknown_imports` 键唯一 |
| V4 | 目标存在 | 边 `target_component_id`（非 null）∈ components；`unknown_imports.source_component_id`、`scan_summaries.component_id`、`unbuilt_components[]` ∈ components |
| V5 | 路径合法与秘密形态 | 全部路径字段满足 repo-relative POSIX 模式（无 NUL/绝对/`..`/首尾斜杠，UTF-8）；任一路径字段命中 `is_secret_shaped_path` → 拒绝（公开面零秘密形态路径） |
| V6 | 排序去重 | components / edges / evidence / unassigned / unknown_imports / unbuilt / manifests / scan_summaries 各自按 §5.3.4/§5.1 规定序排列且去重 |
| V7 | 数量与跨字段 | `unassigned_file_count ≥ len(unassigned_files)`；`is_empty ⇔ python_file_count==0`；`digests` 非 null ⇔ `built==true`；`built==false` ⇔ 该 id ∈ `unbuilt_components`；`unbuilt_components` 非空 ⇒ `dependencies_complete==false`；`semantic_topn.ranked_candidate_ids` 长度 ≤ 20 |
| V8 | cap（maxItems） | components ≤16 / edges ≤4096 / 每边 evidence ≤64 / unassigned ≤256 / unknown_imports ≤4096（与 MonorepoBudgets 默认一致，schema maxItems） |
| V9 | 图 digest 自洽重算 | 由 payload 字段投影 canonical dict（§5.4.5 键集）经既有公共 `compute_content_digest` 重算 == `identity.component_graph_digest`；任一参与字段被篡改 → 失配拒绝 |
| V10 | digest 形态 | 全部 digest 字段 64-hex 小写；`line ≥ 1`；`count ≥ 1`（unknown_imports）/ ≥0（scan 计数） |

**Unicode/字符集口径（与输入支持范围一致）**：输入侧支持范围 = 主仓 inventory 可准入的 UTF-8 可解码路径（non-utf8 上游已跳过——workspace 冻结行为）；payload 路径原样保留（无归一化），段字符集除 component_id 的 `[A-Za-z0-9._\-]` 限制外允许合法 Unicode 字母/数字（V5 模式校验）；**不宣称"任意 workspace"都能正常输出**——声明范围之外的形态由上游跳过计数与 typed gap 承载。

### 5.5 wire schema（`schemas/v4/lima.component-graph.json`）

结构风格沿 `lima.repository-architecture-model.json` 先例（draft 2020-12、顶层 `additionalProperties:false`、required 全列、集合字段 `maxItems` 上界）。字段映射（每字段 ← 冻结产物，无凭空字段）：

| schema 路径 | 来源 | 约束 |
|---|---|---|
| `schema_version` | `COMPONENT_GRAPH_SCHEMA_VERSION` | const `"2.0"` |
| `model_kind` | `COMPONENT_GRAPH_SCHEMA_NAME` | const `"lima.component-graph"` |
| `components[].component_id / root_dir / python_file_count / is_empty` | `ComponentInfo` | component_id = `"component:"` + 锚点 repo-relative 路径（根为 `"."`；段字符集 `[A-Za-z0-9._\-]`、多段嵌套、无 `..` 段——regex 按此单解书写于 schema）；root_dir 同段字符集或 `""`；is_empty 恒 `python_file_count==0`（V7） |
| `components[].manifests[].{path, manifest_kind}` | `ComponentManifestRef` | kind ∈ 九值 const 枚举；按 path 升序；path 过 V5 模式+秘密形态拒绝 |
| `components[].built` | INV-OWN-1 结果 | bool；与 digests/unbuilt 交叉校验（V7） |
| `components[].digests.{profile_content_digest, ram_facts_digest, semantic_result_digest}` | 5.4.6 键控关联 | 64-hex；`built=false` 时为 null（V7） |
| `components[].scan_summary.{parse_error_file_count, read_failure_file_count, dynamic_import_site_count}` | `ComponentScanSummary` | int ≥0；与图级 `scan_summaries` 同项相等（V7） |
| `components[].semantic_topn.{model_id, ranked_candidate_ids[]}` | 每组件 semantic 摘要 | maxItems 20；candidate_id 冻结编码形态；`built=false` 时 null |
| `edges[].{source_component_id, target_component_id, status, imported_name, evidence[]}` | `ComponentEdge` | target 可 null（resolved 时必非 null 且 ≠ source；ambiguous/unresolved 时必 null——V7）；status ∈ 三值；evidence[].{path,line,imported_name}，line ≥ 1，path 过 V5 |
| `unknown_imports[].{source_component_id, imported_name, count}` | `UnknownImportRecord` | count ≥ 1；排序去重；maxItems 4096 |
| `unassigned_files[] / unassigned_file_count` | `ComponentGraph` | 排序字符串（过准入）；count ≥ len(list)；maxItems 256 |
| `scan_summaries[]` | `ComponentScanSummary` | 按 component_id 升序；与 components 逐项对应 |
| `unbuilt_components[]` | INV-OWN-1 分歧 | ⊆ components ids；`built=false` 恰对应 |
| `dependencies_complete` | `ComponentGraph` | bool；触发集 T1-T7 唯一（§5.2.4） |
| `coverage_gaps[].{gap_code, detail}` | `ProfileCoverageGap.to_dict()` | gap_code pattern `[A-Z][A-Z0-9_]{0,63}` 且 ∈ 10 码全集（值重述，不 import ram_schema） |
| `identity.component_graph_digest` | `component_graph_digest(graph)` | 64-hex；V9 自洽重算 |
| `provenance.provenance_anchor_ids[]` | `("component-graph",)` | const 单元序列 |

版本语义：`"2.0"` 是 component graph 承载自身第 2 版（**v1.0 从未实现/发布/合并，无迁移兼容负担**——版本号跟随 Packet v2 字段集）；文件置于 `schemas/v4/` 沿用工程布局，但**不注册** `version_compatibility_matrix.json`（BG-60-01 口径维持；`tests/contracts/test_compatibility_matrix.py` 只以 matrix 文件行为枚举源，IP-0021 §3.4 先例，新增未注册 schema 不触及 contracts 617）。

### 5.6 兼容约束（Assignment §六.4；逐项冻结声明）

#### 5.6.1 `lima/audit/__init__.py.__all__` 54 帽——零触碰单解

- **处置**：本 IP **不修改** `lima/audit/__init__.py`。新公共符号仅经 `lima.audit.component_graph` 模块级 `__all__` 导出（§5.4.7）；
- **与 54 帽的关系**：帽（含冻结断言 `len(__all__) == 54`）原样成立；`import lima.audit` 零新副作用；
- **不扩帽的理由与备选**：扩帽=触及冻结面（需 DR 获批前不实现）。默认方案自足；"追加 re-export" 列为 **DR-IP-0023-01 备选草案**（随交接报告，不进实现范围）。

#### 5.6.2 candidate_id 与 digest 家族

- `candidate_id` 冻结编码零改动；component_id 是**新命名空间**（`"component:"` 前缀，槽位结构不同，无碰撞）；
- 既有六 digest 算法与取值零改动；新增 `component_graph_digest` 独立成员（5.4.5）；**不扩展全 payload digest、不改 wire_digest 输入**（已否决路线不重试）；
- **相同内容不同组件允许摘要相等**（API-05 事实；v1 §5.2.1/§5.6.4"互异"表述废除）：身份与关联一律经 component_id/root_dir/键控 digest 引用表达，不以摘要互异为不变量（§5.4.6/§6 C6）。

#### 5.6.3 GAP 码全集与 execution_required 语义

- `GAP_CODES_ALL` 10 码**不新增、不改名**：图 coverage_gaps 复用既有码值（**值重述** frozenset 字面量，注释锚定来源；不 import ram_schema）；使用码：`BUDGET_EXHAUSTED`（六类 cap：component/edge/edge-evidence/unassigned/unknown-import/aggregate-model-call）、`INVENTORY_SKIPPED`（秘密形态拒绝：锚点与文件名准入，detail `reason=sensitive-filename; count=N`，R1 终案 reason→count）；
- **v2 新承载（ComponentScanSummary/UnknownImportRecord/unbuilt_components）是独立新字段，非新 GAP 码**——不触 `GAP_CODES_ALL` 冻结面与 9 码触发集推导；若 D2 发现确需新码 → 具体 DR；
- `execution_required` 9 码触发语义零改动：图 payload **不承载**该字段（每组件值由既有 `execution_required_from_gaps` 对该组件 RAM wire gaps 复算——消费例 §5.4.7）。

#### 5.6.4 #58 Contract 与 v4 schema/旧 golden

- `encode/decode_profile_envelope`、`encode_envelope`、`ArtifactReference`/`ArtifactEnvelope`、`AttackSurfaceEntry`/`ProfileCoverageGap`、`_validated_path`、v4 非空 extensions 拒绝语义：**全部只读消费**（ProfileCoverageGap 作为图 gap 公共类型构造；组件 Profile envelope 经既有 encode 产出，语义 = 同一 artifact 下的组件子剖面）；
- **不私加 #58 Profile 字段、不借 extensions 携带图**（B-10）；图不进任何 envelope；
- 六 ID 每组件透传兼容论证（修订）：#58 envelope 校验按单 envelope 独立（artifact_id 无跨 envelope 全局唯一性断言）；相同局部内容的组件 envelope content_digest **可以相等**（API-05），下游以 component_id 关联区分——不影响旧消费者（只消费全仓单 envelope / RAM wire）；
- schemas/v4 既有 15 文件与 matrix 零改动；**旧 golden（五形态 + library_profile_golden）期望值零改动**。

#### 5.6.5 TaskManifest 消费面衔接

RAM wire 以 TaskManifest 消费面衔接的既有口径不变；`build_monorepo_profile.repository_snapshot_digest` 与全仓单仓构建取同值（组件层不重定义快照语义）。

### 5.7 输入与确定性（恢复审计 §4② 移交口径落位 + D1R 修订）

- **workspace 输入域扩容**：组件识别与每组件构建均在**当前 main workspace 口径**下工作；本片不把扩容当隐式新能力——不依赖任何新扩展进入 inventory；新 fixture 扩展名集合显式（5.7.1）；
- **CRLF**：`read_text` 保留 CRLF（当前行为）；AST 行号按保留 CRLF 原文计算；本片 fixture 全 LF（5.7.1）；`line_count` 字段存在但本片不消费其值；
- `fingerprint()`/skip 词表/`_safe_path` 边界语义未变（F3 归 CLOSURE-C）；
- **确定性判据（冻结）**：同一 workspace 快照 + 同一 budgets/options 两次独立构建 ⇒ `component_graph_digest` 相等、`components`/`edges`/`unassigned`/`unknown_imports`/`scan_summaries`/`unbuilt_components` 逐字段相等、每组件三 digest 相等；**输入顺序变化**（目录枚举顺序/文件写入顺序不同、内容相同的两个快照目录）⇒ 结果不变——全部枚举入口（manifest 候选/锚点/组件/文件/边/evidence/未知导入）一律 sorted，禁 mtime/权限/随机/env/时钟；
- **跨 workspace/共享安全层改动**：本片默认设计**零需求**（组件视图 = 继承策略的 `RepositoryWorkspace` 公共构造 + INV-OWN-1 校验；D1R 探针 D2/D3/D7 实证可构造可校验）；祖先组件精确隔离的共享层增强以 **DR-IP-0023-02** 呈审（§5.2.1 已知限度）；若 D2/实现期发现必须改 `lima/workspace.py` 才能表达的语义 → 停止并单列 DR（附调用链与理由）。

#### 5.7.1 fixture 口径约束（冻结）

- 新 fixture（`tests/audit/fixtures/monorepo/shapes.py`）文本写入一律 `newline="\n"` 钉死 LF（PI-DR1）；路径断言用 POSIX 字面量；
- **扩展名集合显式声明**：monorepo fixture 仅含 `.py` 文件 + manifest 文件名（经已准入 inventory 通道）；不含 C++/构建类扩展文件、不含 CRLF 文件；**秘密形态文件名仅存在于专用隐私负例形态**（C4 类），其断言只验证"不入公开面 + gap 计数"，不在任何期望列表中断言其路径；
- fixture 构造沿用 `repo_shapes.workspace_with` 模式（临时目录 + `RepositoryWorkspace`，零网络零执行）；嵌套/src 布局/同内容双组件/祖先-嵌套/名字碰撞形态均在 shapes.py 显式构造（§6 各类引用）。

### 5.8 安全基线（Assignment §六 末段 + R60-04；全程）

- **准入时序（冻结单解）**：仓库级坐标先准入、后建组件视图（§5.2.0 六步时序；任何组件级/图级公开输出所含路径均在仓库级坐标过 `is_secret_shaped_path` 或其组件内坐标的仓库级原像已过准入）；
- **公开面准入规则表（R60-04 交付；逐项）**：

| 公开面 | 准入规则 |
|---|---|
| `component_id` / `root_dir` | 源自已准入锚点（锚点路径已过 `is_secret_shaped_path`，§5.1.1）；字符集 pattern（V5） |
| `manifests[].path` | 已准入 inventory 内 manifest（工作区级准入 + 秘密形态双过） |
| `unassigned_files[]` | 仓库级路径过 `is_secret_shaped_path`；命中者不入列表、仅计数，`INVENTORY_SKIPPED` gap reason→count |
| `edges[].evidence[].path` | 同上（归属 `.py` 已准入 + 秘密形态过滤） |
| `unknown_imports[].imported_name` | 标识符/点号串（非源码正文、非路径） |
| `scan_summaries` / `unbuilt_components` | 纯计数与 component_id（无路径无源码） |
| `semantic_topn.ranked_candidate_ids` | candidate_id 冻结编码（含组件内路径坐标——该文件已过仓库级准入，准入等价 §5.2.1） |
| `digests` / `identity` / `provenance` | 无路径承载 |

- **R1 口径保留**：公开 reason→count；内部 `AdmissionSkipRecord`（family 级、无原文件名）不入任何公开面；**启发式非穷尽声明保留**（`is_secret_shaped_path` 为启发式，不宣称零泄漏——残余治理归 C）；
- 不执行/不 import/不安装目标项目（AST 断言 + 行为负例：恶意 setup.py marker 文件不存在）；模块静态断言：零网络 import（socket/urllib/requests/http）、零 subprocess、零 os.environ、零文件写、零 sys.path 变更；
- fail-closed 与有界读取：全部入参类型/值校验抛 `ContractError`/`ValueError`；读取一律经 workspace 有界通道；**无掩码 path 方案、不改旧 digest 家族**（已否决路线不重试）。

---

## 6. 测试矩阵（D2 冻结计划：FR→AC→T→预定测试符号；本阶段不写测试文件）

**方法预算注记（R60-07 口径）**：v1 的 33/≤35 仅为规划参考；v2 按指令 §六七类"不配合算法"样例重排后计划 **52** 个方法——超出 35 的逐类覆盖收益见各类括注（反例暴露的承重行为必须有自己的语义覆盖，不以方法数帽换安全）。回归锚（contracts 617 / audit 235 / 五形态 golden 零改动 / DR-LINT-0022-A 六处恰存）经命令覆盖（§8），不计入新增方法数。断言一律**从需求推导**（V5-FR-03/AC-01/NFR-01/R1 终案等），不从算法实现推导。

| # | 类别（方法数） | 预定测试符号（`test_file::test_symbol`） | 断言要点（需求来源） | 追踪 |
|---|---|---|---|---|
| 1 | C1 组件发现与计数一致（10；收益：RULE-01/API-01 两反例的语义覆盖，嵌套/归属/守恒不再依赖平铺巧合） | `test_component_graph.py::test_detect_components_nested_services_packages` | `services/api`、`packages/core` 落入组件集；component_id/root_dir/manifests/排序 | V5-FR-03、R60-01 |
| 2 | | `…::test_detect_components_multiple_manifests_same_dir` | 同目录多 manifest 归并单组件 | V5-FR-03 |
| 3 | | `…::test_detect_components_root_only_and_zero_component` | 仅根 manifest→单组件零边；零 manifest→components=()+unassigned | V5-FR-03、边界 |
| 4 | | `…::test_detect_components_workspace_manifest_not_component` | 根 workspace 协作 manifest（uv/pdm/workspace 键）不产根组件；成员组件仍识别 | V5-FR-03 |
| 5 | | `…::test_detect_components_unassigned_files` | 根无锚点时散 `.py` 落 unassigned（列表排序+count）；不编造组件 | AC-01、三态 |
| 6 | | `…::test_detect_components_empty_component` | 有 manifest 零 `.py`→is_empty=True 保留 | V5-FR-03 |
| 7 | | `…::test_detect_components_max_components_truncation` | 17 组件→前 16+BUDGET_EXHAUSTED(reason=component-limit)+truncated+complete=False(T1) | 预算 fail-closed |
| 8 | | `…::test_detect_components_secret_shaped_anchor_suppressed` | `secrets/` 锚点不准入；INVENTORY_SKIPPED reason=sensitive-filename; count=N；无目录名泄漏 | NFR-01、R60-04 |
| 9 | | `…::test_component_counts_match_build_inputs` | INV-OWN-1：每组件计数/Profile 输入/RAM 输入/Top-N 输入/图 evidence 五处输入集合逐文件一致；INV-OWN-2 守恒 | R60-02、AC-01 |
| 10 | | `…::test_root_component_excludes_child_files` | API-01 输入集：根组件 RAM 不计子组件文件；跨组件模块计数不重复 | R60-02、FR-02 复验 |
| 11 | C2 模块解析与未知区分（8；收益：RULE-02 反例 + 未知导入三态可观察） | `…::test_module_resolution_src_layout_cross_component` | RULE-02 输入集：A `import beta`→resolved 边 A→B（src 布局模块根解析） | R60-05、AC-01 |
| 12 | | `…::test_module_resolution_build_config_declared_root` | pyproject setuptools `where`/`package-dir` 声明目录成为模块根 | R60-05 |
| 13 | | `…::test_module_resolution_namespace_package` | 无 `__init__.py` 目录作 namespace 名解析；跨组件可产边；多名跨组件→ambiguous | R60-05 |
| 14 | | `…::test_relative_import_package_context` | 包上下文（`__init__` 链）相对导入解析；跨组件 resolved；越出仓库→unresolved | AC-01（相对导入） |
| 15 | | `…::test_duplicate_module_name_self_first_and_ambiguous` | P1 自身优先无边；P3 多组件命中→ambiguous（target=None，不向候选画边） | AC-01（重复模块名） |
| 16 | | `…::test_unknown_import_carried_not_external` | P5：非 stdlib/未声明/未定位导入入 `unknown_imports`；无边且**不伪称外部** | R60-05、三态 |
| 17 | | `…::test_known_external_stdlib_and_declared_deps` | P4a/P4b：stdlib 与 manifest 声明依赖名→无边无承载 | R60-05 |
| 18 | | `…::test_dynamic_import_sites_carried` | 封闭检测集位点→dynamic_import_site_count；不产边 | FR-05、三态 |
| 19 | C3 策略与预算不扩权（7；收益：API-02 反例 + 聚合包络新设计的机器可读验证） | `…::test_policy_inheritance_all_five_params` | API-02 输入集：组件视图五策略参数逐一==调用方有效值；ignore 集不丢失 | R60-03、NFR-01 |
| 20 | | `…::test_no_readmission_under_caller_caps` | 调用方 max_files=1：全输出不得含未准入文件；分歧组件 typed 不构建（不扩权优先） | R60-03 |
| 21 | | `…::test_aggregate_model_call_envelope` | 注入有界离线 fake client：聚合 cap 触发→BUDGET_EXHAUSTED(reason=aggregate-model-call-limit)+partial facts；component_id 序确定；默认 off 零调用 | R60-03、AC-02 |
| 22 | | `…::test_budget_caps_edge_evidence_unassigned_unknown` | 四类列表 cap 截断+typed gap（detail reason/count）不静默 | 预算 fail-closed |
| 23 | | `…::test_invalid_inputs_fail_closed` | 非 workspace/坏 budgets（0/负/非 int）/非 str 六 ID/空 digest→ContractError/ValueError | fail-closed |
| 24 | | `…::test_monorepo_budgets_invariants` | MonorepoBudgets 默认（16/4096/64/256/128）+构造期正值校验 | 预算单解 |
| 25 | | `…::test_budget_exhaustion_partial_facts` | 各截断形态返回部分事实+对应 gap+complete 触发（T1/T3/T7 对号） | fail-closed、R60-03 |
| 26 | C4 秘密形态与坐标变换（4；收益：API-03 反例的全公开面机械扫描） | `…::test_repo_level_admission_before_component_views` | API-03 输入集：`secrets/` 不产组件、`secrets/main.py` 不入任何组件 RAM/Profile/图面；整仓输出 0 模块语义保持+gap | R60-04、NFR-01 |
| 27 | | `…::test_all_public_surfaces_admission_rules` | 对序列化 payload 全文机械执行 §5.8 准入表（逐公开面字段过 `is_secret_shaped_path`）→零命中 | R60-04、NFR-01 |
| 28 | | `…::test_secret_gap_reason_count_no_filename` | gap detail 形态 `reason=sensitive-filename; count=N`；公开面无原文件名/目录名 | NFR-01（R1 终案） |
| 29 | | `…::test_no_masked_paths_no_old_digest_changes` | payload 路径为真实 repo-relative POSIX（无 redact: 前缀/掩码）；旧 digest 家族成员不出现于图承载 | 边界（已否决路线） |
| 30 | C5 完整性与缺口（5；收益：API-04 反例 + v1 矛盾触发的唯一化） | `…::test_dependencies_complete_unified_triggers` | T1-T7 表驱动逐触发置 False；T 集外（evidence/unassigned 列表截断等）不置 False | R60-06、FR-05 |
| 31 | | `…::test_parse_error_carried_in_graph` | API-04 输入集：图层级 parse_error_file_count=1+T4；三态=证据不足非无依赖 | R60-06 |
| 32 | | `…::test_empty_edge_set_with_gap_not_no_dep` | 空边集+缺口（unassigned/unknown/parse）→判据表输出"证据不足"；真实无依赖仅在全合取下成立 | R60-06 |
| 33 | | `…::test_read_failure_carrier_default_and_trigger` | read_failure_file_count 默认 0、入 T5 封集；静态快照不可确定性构造的负例如实声明（不造假绿） | R60-06、诚实声明 |
| 34 | | `…::test_failure_family_observability` | 扫描/解析/动态/歧义/预算/敏感准入各失败族在图输出有可观察 typed 承载（表驱动） | FR-05 |
| 35 | C6 摘要与身份分离（7；收益：API-05 反例 + Oracle 独立性） | `…::test_identical_content_components_equal_digest_allowed` | API-05 输入集：同内容两组件三摘要**相等**且 component_id 不同可区分 | R60-07、FR-04 |
| 36 | | `…::test_component_identity_keyed_association` | payload 以 component_id 键控关联三 digest；交换两组件 digest（篡改关联）→validator 拒绝 | R60-07、R60-08 |
| 37 | | `…::test_content_change_digest_changes` | 单组件内容变化→其 digest 变+图 digest 变；他组件 digest 不变 | FR-04 复验 |
| 38 | | `test_monorepo_golden.py::test_golden_expected_from_independent_oracle` | golden JSON == P&V 独立预期（人工推导组件/边/计数/三态 + 既有公共 `compute_content_digest` 对手写 canonical dict 独立重算），**非实现输出回填** | R60-07、AC-01 |
| 39 | | `…::test_golden_monorepo_replay_and_topn` | 两次独立构建 digest 相等+每组件 ranked candidate_id 序列逐位相等 | AC-01（可重放） |
| 40 | | `…::test_golden_monorepo_provenance_chain` | 图 anchor=("component-graph",)+每组件三段 anchor 链+manifests provenance | AC-01（provenance） |
| 41 | | `…::test_golden_tamper_detected` | 篡改 golden 任一参与字段→digest 失配被识别 | R60-07 |
| 42 | C7 公开 Artifact 消费自洽（11；收益：R60-08 消费闭合与 validator 十维） | `test_component_graph.py::test_consumer_obtains_all_facts_from_public_artifacts` | 仅凭 payload+每组件 envelope/RAM wire（无 workspace/不重跑构建/无内存对象）：取得并核对五类事实（Profile/RAM/semantic 摘要/坐标映射/gap+execution_required 复算/图关联） | R60-08、系统约束 |
| 43 | | `…::test_validator_unknown_fields` | 未知顶层/嵌套字段→ContractError(UNKNOWN_FIELD)（V1） | fail-closed |
| 44 | | `…::test_validator_enums_and_digest_format` | 枚举外 status/kind、非 64-hex、line<1→ContractError(INVALID_FIELD_VALUE)（V2/V10） | fail-closed |
| 45 | | `…::test_validator_uniqueness_target_existence_ordering` | ID 唯一/目标存在/各集合排序去重违规→拒绝（V3/V4/V6） | fail-closed |
| 46 | | `…::test_validator_cross_field_and_caps` | is_empty⇔count、digests⇔built、unbuilt⇒complete=False、count≥len、maxItems cap（V7/V8） | fail-closed |
| 47 | | `…::test_validator_graph_digest_recompute` | 任一参与字段篡改→canonical 重算失配→拒绝（V9） | R60-07/08 |
| 48 | | `…::test_validator_secret_shaped_path_rejected` | payload 注入秘密形态路径（任一公开面）→拒绝（V5） | R60-04 |
| 49 | | `…::test_validator_unicode_and_charset_range` | 合法 Unicode 路径按声明范围通过；NUL/绝对路径/`..`/越界 charset 拒绝；不宣称任意 workspace（V5/V10） | R60-08 |
| 50 | | `…::test_no_execution_marker_absent` | 恶意 setup.py/import 副作用 fixture：构建前后 marker 不存在 | NFR-02 清单层复验、V5-FR-04 |
| 51 | | `…::test_static_no_network_no_env_no_syspath` | AST 断言零网络/subprocess/os.environ/文件写/sys.path 变更 import | V5-FR-04 |
| 52 | | `…::test_determinism_and_input_order_invariance` | 同快照两次构建全字段相等；同内容不同写入顺序两快照→digest 相等（含嵌套/unknown/unbuilt 字段） | AC-01、FR-04 |

PI-DR 落实：PI-DR1（LF 钉死/POSIX 断言/零平台权限依赖）；PI-DR4 模块缺席 RED 锚（新测试 import `lima.audit.component_graph` 失败为 RED 锚**之一**——不代替语义覆盖）；**PI-DR2 scratch/reference 流程（R60-07 D2 计划）**：D2 冻结前须以 scratch 参考实现或等价独立参考验证验收测试非自相矛盾、能接纳合规结果（存在满足全部断言的合法输出），并记录于 Frozen Test Commit；PI-DR6 冻结前非 Windows 平台完整跑一次并记录 run SHA；PI-DR5 PR 禁自动关闭关键字。

## 7. AC traceability（正向+反向 100%）

| Requirement | 本 IP 贡献声明 | Test（§6 #） |
|---|---|---|
| V5-FR-03（前半句：monorepo 输出 component graph） | 嵌套组件识别 + 边三态 + 未知导入承载 + 独立承载 + 每组件三段 | #1-#18、#42-#49 |
| AC-01/T-01（monorepo/重复模块/相对导入维度：provenance + Top-N 可重放） | golden（独立 Oracle）+ 边三态 + 确定性 | #11-#15、#38-#41、#52 |
| V5-AC-01/V5-T-01（monorepo 维度：Profile/roles/support/execution capability/gap） | 每组件 Profile 全字段（复用 IP-0016 规则） | #3、#9-#10、#38-#40 |
| V5-AC-02/V5-T-02（后半句：monorepo 按 component 生成 profile/RAM） | `build_monorepo_profile` 每组件全链（单一归属） | #9-#10、#21 |
| FR-02/03/04/NFR-01（组件维度复验） | 复用三层公共接口逐组件重放（策略继承+隔离不变量） | #9-#10、#19-#21、#26-#29、#35-#37、#52 |
| FR-05（typed gaps / 三态可观察） | 统一完整性触发集 + scan/unknown/unbuilt 承载 | #16、#18、#30-#34 |
| 预算/安全基线 | 聚合包络 fail-closed + 隐私/no-execution/静态断言 | #7、#19-#25、#50-#51 |

反向：§6 每个测试符号唯一指向上表行（D2 冻结时以 `test_file::test_symbol` 表落档）。本 IP 不宣称：AC-01 整体满足、V5-FR-03 后半句（安全停止）、T-03 端到端、F3/F4、#64/#68 消费。

## 8. 验收命令（Done Commands；D2/Implementation/验证共用，全部在交付 worktree 根执行）

```text
# slice（新增用例全绿，0 skip；v2 计划 52 方法——§6 注记）
python -B -m unittest tests.audit.test_component_graph tests.audit.test_monorepo_golden -v
# tests/audit 全量回归（基线锚 235 @fbbbd619；含 IP-0022 51 例回归锚；计数变化需解释、不得删测试追平）
python -B -m unittest discover -s tests/audit -q
# contracts 回归（基线锚 617 @fbbbd619）
python -B -m unittest discover -s tests/contracts -q
# lint（lima/audit 净；audit+tests/audit 恰 DR-LINT-0022-A 六处=B009×1+B017×5 全在 test_ip_0022_fix.py，零新增）
python -B -m ruff check --no-cache lima/audit
python -B -m ruff check --no-cache lima/audit tests/audit
python -B -m bandit -q lima/audit/component_graph.py        # 零 finding
python -B -m compileall -q lima tests                       # exit 0
# CI 完整入口（ci.yml 同款；基线锚 3006 OK 24 skip @fbbbd619，全环境类 skip，#60 验收面零 skip）
python -B scripts/run_ci_tests.py
# 边界
git diff --check                                           # 干净
git diff --name-only --diff-filter=ACMRTUXB                # 恰为 §4 Add 7 文件（__init__.py 必不在列）
# 契约单点
python -B -c "import lima.audit as a; assert len(a.__all__) == 54"   # 54 帽零触碰锚
python -B -c "import lima.audit"                                      # 零副作用
sha256sum schemas/v4/lima.component-graph.json tests/audit/fixtures/monorepo/golden/monorepo.json  # 与冻结记录一致
```

**平台实跑计划**：Windows 本机（RED/GREEN + 上述全组）；**PI-DR6**——D2 冻结前在非 Windows 平台（GitHub Actions Linux runner，临时验证分支 workflow_dispatch，先例 `pv/ip-0022-freeze-pidr6` run 34826215469）完整跑一次新增测试集，记录 run SHA 与结论入 Frozen Test Commit 记录；安全关键用例不得用 skip 充当 PASS（#33 的不可构造负例以显式声明处理，不造绿）。

**Post-merge**（Coordinator 指令后）：上述 mandatory 全组在最新 origin/main 复跑，输出 `POST-MERGE PASS/FAIL`。

## 9. Stop Conditions / Decision Request

1. 组件识别需跨 manifest/路径组合证据而现有公共承载（workspace 只读 inventory + read_text）无法表达 → Contract Gap 停点，提 DR（选项+推荐+兼容影响+草案），不发明扩展字段；
2. 任何需要修改 `lima/workspace.py`、`lima/contracts/**`、三层+ram_schema 冻结面、既有 tests/audit 文件、schemas/v4 既有 15 文件才能满足本 Packet 的情形 → 停点（共享层改动单列 DR 附调用链与理由；**DR-IP-0023-02（祖先组件精确隔离共享层增强）已按此预呈**；F3 路线归 #60-CLOSURE-C）；
3. 触及冻结约束的新设计（54 帽扩帽、digest 家族语义、GAP 码新增、execution_required 语义、#58 字段、v4 schema/旧 golden 期望值）→ 具体 DR 获批前不实现、不留 TBD 空位；
4. 与 #266/#281 出现文件或语义冲突迹象（含远端分支前移触及 #60 敏感路径）→ 停止上报 Coordinator；
5. 基线前移：开工时已核验 fbbbd619 未前移；后续阶段（D2/Implementation）开工时重新 `git fetch origin`，前移涉冻结产品面/共享输入层/Contract·fixtures → 按批复 §四分类补核验，涉 #60 敏感路径上报复核后开工；
6. 回归计数与基线锚（617/235/3006+24skip）不符 → 按实际覆盖变化与失败内容判断（addendum-2 §3 修订版）：计数变化须可追溯，不单独构成停点；真实失败按停点纪律上报；**不得删测试/改 Oracle/改期望值追平数字**；
7. 实现期发现需改冻结测试 → 先 Decision Request（缺陷证据+影响面+建议方案），获授权后走 Packet 修订 → 撤销旧冻结 → 重新 RED → 新 Frozen Test Commit；禁止同提交悄悄修测试；
8. IP-0023 编号被对端轨道登记占用（ALLOC 失效条款）→ 停止上报；
9. **（D1R 新增）R60-01..08 修订方案在 D2/实现期确需触及 54 帽、digest 家族、#58、v4 schema/旧 golden、GAP 码全集、execution_required 语义、`lima/workspace.py`/共享接口任一项 → 停在具体 DR**（选项+推荐+兼容影响+调用链），获批前不写入实现为既成事实。

## 10. 回滚与兼容影响

- **纯新增交付**：产品面恰 2 新文件，测试面 5 新文件；零修改既有任何文件（含 `__init__.py`）⇒ 回滚 = revert 单个实现 PR，无迁移、无数据兼容问题；
- **旧消费者零影响论证**：54 帽原样、六 digest 原样、GAP 10 码与 9 码触发原样、#58 契约零改动、v4 schema 既有 15 文件与 matrix 零改动、五形态旧 golden 期望值零改动、错误目录既有码值零改动——既有消费路径行为逐字节不变（tests/audit 235 + tests/contracts 617 + golden 全绿为证）；
- **schema 版本共存**：`lima.component-graph.json` 独立版本 `"2.0"`（v1.0 未实现未发布，无迁移）、不注册 matrix——旧消费者不可见该文件；未来注册属 BG-60-01 口径（Maintainer 另决 + DR）；
- **回滚不降低门禁**：不涉及 Evidence Level/Gate/raw-secret/FULL_CHAIN 任何维度。

## 11. 危险与失败矩阵（危险输入 × 失败模式处置表）

| 危险输入 | 失败模式 | 处置（承载/行为） | Test |
|---|---|---|---|
| 嵌套组件（services/api、packages/core） | 浅层规则漏识别 | 任意深度锚点（已准入 manifest 父目录）；识别不了→unassigned/gap 如实 | #1 |
| 根组件与子组件并存 | 根构建吸入子组件文件（API-01） | 继承策略组件视图+嵌套锚点名 ignore+INV-OWN-1 逐文件校验 | #9、#10 |
| 名字碰撞目录（祖先子树内与嵌套锚点同名） | 同名剪枝过度排除 | INV-OWN-1 分歧→`unbuilt_components` typed 承载（T7），不出错误数据 | #9、#20 |
| 空仓库 / 零 manifest | 无组件边界证据 | components=()、edges=()、unassigned 计数如实；不报错 | #3 |
| 根 workspace 协作 manifest | 误产根组件/双计 | workspace 键集识别→不产根组件 | #4 |
| 调用方 cap 收紧（max_files=1 等） | 组件切分重新准入（API-02 反向） | 五参数继承+INV-OWN-1；分歧组件 typed 不构建 | #19、#20 |
| ≥17 组件 | 聚合放大 | 前 16+BUDGET_EXHAUSTED+complete=False（T1） | #7 |
| src 布局（src/alpha vs src/beta） | 锚点同名 `src`、跨组件导入丢失（RULE-02） | 模块根解析（构建配置+src 内容证据）；顶层名表跨组件 resolved | #11、#12 |
| 两组件同名顶层包 | import 目标不唯一 | P1 自身优先；P3 ambiguous（target=None） | #15 |
| namespace 包（无 `__init__.py`） | 漏解析或误歧义 | namespace 名候选可解析；多名跨组件→ambiguous | #13 |
| 未知导入（非 stdlib/未声明/未定位） | 伪装成外部无边无 gap（RULE-02 隐患） | P5 `unknown_imports` typed 承载；三态可观察 | #16、#32 |
| 相对导入越界/目标缺失 | 解析失败 | 包上下文解析；unresolved 边（target=None） | #14 |
| 语法错误文件 | RAM counter 有值而 gap 空（API-04） | 图层级自计 parse_error_file_count（T4）+scan_summary 承载 | #31 |
| 读取失败（保留触发） | 静默丢证据 | read_failure_file_count（T5）；静态快照不可构造性如实声明 | #33 |
| 组件内动态 import | 静态不可解 | dynamic_import_site_count 自计；不产边 | #18 |
| 恶意 setup.py / import 副作用 | 执行风险 | 零执行（tomllib/ast.parse/存在性检查）；marker 负例 | #50、#51 |
| 秘密形态目录/文件名（secrets/ 等） | 坐标变换绕过准入（API-03） | 仓库级先准入：锚点拒绝+公开面准入表+validator V5；reason→count | #8、#26-#28、#48 |
| CRLF 文件 | 行号口径漂移 | 行号按保留 CRLF 原文计算；fixture 全 LF | （并入 #52） |
| symlink .py / 二进制 / 超大文件 | workspace 跳过 | 主仓 `skipped` 计数可见；T6 判据 | #30 |
| manifest 静态解析失败 | 模块根/依赖证据缺失 | 保守回退（根+src 约定+unknown 承载）；Profile 层既有 MANIFEST_PARSE_ERROR 不受影响 | #12、#16 |
| 非 workspace 入参 / 非法预算值 / 空 digest | 类型违约 | ContractError/ValueError fail-closed | #23、#24 |
| 边/evidence/unassigned/未知导入超量 | 无界放大 | cap+typed gap（count 如实），无静默截断 | #22 |
| payload 篡改（未知字段/枚举外/坏 digest/乱序/换 digest/注入秘密路径） | 契约违约 | validator V1-V10 一律 ContractError；digest 自洽重算 | #43-#49 |
| 相同内容不同组件 | digest"互异"假断言（API-05） | 允许相等；component_id 键控关联；篡改关联被拒 | #35、#36 |
| 目录枚举顺序不定 | 结果漂移 | 全枚举入口 sorted；输入顺序不变性断言 | #52 |

## 12. Completion Summary / PR contract

- Completion Summary 必含：base/final commit、修改文件与公共符号清单（§5.4.7 的 `__all__` 逐项）、AC→Test→Result 表（§7 + §6 符号）、§8 全部命令实际输出与统计（含计数与退出码）、schema 与 golden 文件 SHA-256、文件边界自查（`__init__.py` 未改动证明）、**R60-01..08 逐项实现对照**（实现行为 → §0.1 修订规则 → 对应测试符号）、已知限制（monorepo golden 单形态、Python-only 组件边、祖先组件 manifest 证据范围限度、名字碰撞 typed 不构建、安全停止/T-03/F3/F4 归 B/C、FR-01 全 vocabulary 留痕归 D、full semantic 下游消费归 D）；
- Implementation PR：`Implements IP-0023` + `Related to #60`；正文含 Packet merge commit、Frozen Test Commit、covered/not-covered（§0）、AC 矩阵、命令实测、Verdict、`This PR does not auto-close the Source Issue.`；**禁止** close/fix/resolve 与 #60 组合（PI-DR5）；
- Packet docs PR（主会话在 Coordinator readiness 复核通过后执行）：docs-only，恰含本 Packet 修改（同文件 v2 commit），`Related to #60`，禁自动关闭关键字；合并批准逐项请求 Maintainer；PR 正文重写围绕最终问题与行为，说明实际验证/未验证（含 D1R 探针为设计证据而非产品验收）。

## 13. Packet 完成定义与 Open Decisions

- 本 Packet 关键 TBD 数 = 0；状态 `D1R-REVISION / PENDING-REVIEW`——**不标 READY-FOR-CODE**；`READY-FOR-CODE` 当且仅当：本文档（v2 或后续修订版）合并进 main（Coordinator 标 `PACKET-MERGED`）且 D2 按 §6 计划完成有效 RED（含 PI-DR2 scratch/reference 非自相矛盾验证）与 PI-DR6 双平台记录；
- **Open Decisions（呈审项，非实现阻塞、非 TBD 空位）**：
  1. DR-IP-0023-01（备选）：`lima.audit` 命名空间追加 re-export（=扩 54 帽）——默认不扩帽，草案随交接报告；
  2. DR-IP-0023-02：祖先组件精确隔离的共享层增强（workspace 路径级排除参数 / 显式文件清单视图 / manifest 候选范围参数；推荐 additive `exclude_directory_paths`；附调用链与兼容影响）——v2 默认设计不依赖它（INV-OWN-1 分歧→typed 不构建 + 限度声明），获批后可消除 §5.2.1 已知限度 (i)(ii)；
  3. 聚合模型调用包络 `max_total_model_calls=128` 为本 Packet **显式新预算设计**（§5.4.4），随修订版 PR 一并呈审（非"旧预算已批准"的引申）；
  4. BG-IP-0016-01 / BG-60-01 / DR-LINT-0022-A 维持 OPEN（归置权在 Coordinator）；F4 聚合墙钟未闭合（归 #60-CLOSURE-C）。
- 后续阶段（D2 冻结测试、Implementation、独立验证、ER、合并、post-merge、IP-DONE）均未授权，另行 Assignment。

---

## 附 A. 本 Packet 制作证据摘要（D1R，全部本轮亲验）

- 基线：`git fetch origin` 后 `origin/main = fbbbd619fb0b96efbbb903916ab46dc0daed2214`（未前移）；修订基线 worktree `D:/BaseAIProject/LIMA-60-closure-a-pv-wt`（分支 `codex/ip-0023-monorepo-packet`，开工 HEAD=`41c899ef10be682e52d61ab0f92e4bef11aed27c`，`git status --porcelain` 为空）；Packet v1 SHA-256 重算一致（`e9702fe2…f7f9f`）；
- 输入 SHA-256 重算一致（全部亲验）：D1R Assignment `30a0e919…c040a`、指令正文 `4f713455…edd89`、回顾 `00483bd6…658b`、probe results `90f3d975…acb8a4`、github snapshot `9b24579a…4d81d`、MDR `759a9225…3403`、D1_v1 Assignment `5a118ea9…73b82`；
- 冻结面只读核对（@fbbbd619，import/源码亲验，零目标项目执行）：§3.1 全部签名/常量/默认值（含 **两层入口 isinstance 硬校验 + 自行 inventory()**——R60-02/03 可行性边界）；workspace 构造器五策略参数/`inventory()` 公开 skipped 计数/按名剪枝无路径级排除（§3.3）；`is_secret_shaped_path` 对 `secrets/pyproject.toml`、`secrets/main.py`、`main.py` 的取值亲验；`PythonDataflowAnalyzer.analyze_project`/`_module_name` 只读参照（§5.3.5）；schemas/v4 15 文件清单；
- 本阶段未执行：产品代码/测试/schema 修改、全量产品测试重跑（基线数字引用恢复审计 §5）、远端写、冻结（D2 另行）、推送（本轮派发要求不 push；Assignment 允许推送以 Coordinator 后续指令为准）。

## 附 B. D1R 设计探针（设计证据，非产品验收）

- 探针：系统临时目录 `design_probe_v2_d1r.py`（本轮自写，只读仓库、fixture 全在系统临时目录、零网络零目标执行；运行时 = 归档基线 `output/issue60-pr282-retrospective-2026-10-09/baseline-runtime`，`_review_base_sha.txt` 校验 fbbbd619）；结果 JSON：`%TEMP%/design_probe_v2_d1r_results.json`，断言 7/7 全过；
- 输出明确区分：**设计推导**（D1-RULE01 段落规则于真实 inventory 之上复算、D6-RULE02 模块根规则字面推导）与**已有公共 API 实跑**（D2/D3/D4/D5/D7 使用 fbbbd619 真实 `RepositoryWorkspace`/`build_python_ram_facts`/`is_secret_shaped_path` + v2 构造规则）；
- 结论（方向性，产品验证归 D2）：D1 `services/api`、`packages/core` 均可识别（RULE-01 消除）；D2 根组件构建输入=精确切片、v2 根 RAM 计 1 模块（v1 构造计 2——API-01 消除）；D3 组件视图五策略参数==调用方（API-02 消除）；D4 秘密形态锚点被拒、rebased 视图不可达（API-03 消除）；D5 图层级 parse 计数可自计（API-04 承载补齐）；D6 `import beta` → resolved 边 A→B（RULE-02 消除）；D7 名字碰撞分歧机械可检（unbuilt 承载可行）。
