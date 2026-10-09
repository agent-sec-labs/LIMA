# Implementation Packet IP-0023 — Monorepo Component Graph & Per-Component Profile/RAM（#60-CLOSURE-A 首片）

> 文档类型：Implementation Packet（P&V 制作，阶段 D1 / Packet 文档）
>
> Packet 版本：`IP-0023-PACKET/v1`
>
> 状态：`READY-FOR-CODE`（TBD = 0；生效以本 Packet docs PR 合并进 `main`、Coordinator 标记 `PACKET-MERGED` 为前提；D2 测试冻结另行 Assignment）
>
> Exact base：`fbbbd619fb0b96efbbb903916ab46dc0daed2214`（origin/main；P&V 开工时 `git fetch origin` 复核 `rev-list fbbbd619..origin/main = 0`，未前移，2026-10-09）
>
> 制作人：lima-packet-verification（Assignment `ASSIGN-60-CLOSURE-A-PKT-D1_v1`，任务标识 `PKT-IP-0023-D1`，2026-10-09）
>
> 编号依据：`ALLOC-IP-0023-60-CLOSURE-A/v1`（Coordinator，2026-10-09，基线 fbbbd619；2026-10-09 编号四查通过；IP-0023 = #60-CLOSURE-A 首片编号，**不是整个 Issue 的 closure 编号**）
>
> 上游决策：Maintainer 批复 `MR-60-RESUME-APPROVAL-20261009/v1` §五/§六（批复正文 SHA-256 `e4bcc9c3772fecddd7a3dc67e232aa56bd1d46aede643f2dcdbe5eda5cabbbbc`）；恢复审计 `RESUME-AUDIT-60-2026-10-09_v1` + addendum-1/2；PI-DR1..PI-DR6 全部生效
>
> 阶段边界：本 Packet 只交付设计（D1）。验收测试文件、有效 RED、Frozen Test Commit 属 D2，另行 Assignment 派发；本阶段无 Frozen Test Commit，Mechanical Test Correction Allowance = NOT_ALLOWED。

---

## 0. Header（生命周期 §8）

```text
Source Issue：#60（[V4-I04][P0] Repository Profile、RAM 与安全语义清单，V5 覆盖层版）
Issue specification revision：2026-10-09 live 正文（P&V 开工时 GitHub API 亲取；body SHA-256
  477ad50cd383d22dbbbefce3a71e1a2250abd89d01218c6e1d94e6c1fd9f8180；含 V5 覆盖层、
  7/6/4 勘误后 Delivery Ledger、ENTRY60-RESUME-1/v1、ALLOC-IP-0023-60-CLOSURE-A/v1）
Covered requirements（本 IP 只声明自身贡献，且仅此贡献）：
  V5-FR-03 前半句（monorepo 输出 component graph——组件识别、每组件 Profile/RAM、
    组件间依赖/歧义/未解析关系 + provenance、重复模块名与相对导入处理、monorepo golden）
  AC-01/T-01 的 monorepo 维度（monorepo/重复模块/相对导入 fixture 下已解析与未解析调用
    均有 provenance、Top-N 顺序可重放——经每组件全链 + 图承载实现）
  V5-AC-01/V5-T-01 的 monorepo 维度（monorepo 形态输出 RepositoryProfile/code roles/
    support level/execution capability/coverage gap——每组件维度）
  V5-AC-02/V5-T-02 的后半句（monorepo 按 component 生成 profile/RAM）
  FR-02/FR-03/FR-04/NFR-01 的组件维度复验（复用三层冻结公共接口，每组件重放；
    不改三层语义，仅声明组件维度复验贡献）
Not covered requirements（相邻但明确不在本 IP）：
  V5-FR-03 后半句（docs/content 与 unsupported 安全停止端到端——机器可读 gap/停止结果）→ #60-CLOSURE-B
  V5-AC-02/V5-T-02 前半句（docs/unsupported 安全停止、不能输出"未发现漏洞"）→ #60-CLOSURE-B
  T-03/AC-03/NFR-02/V5-FR-04/V5-AC-03 端到端安全负例与 F3（_safe_path TOCTOU）/F4
    （回包/时间上限）→ #60-CLOSURE-C（F3 路线归切片 C，本片零 workspace 改动）
  FR-01 全跳过原因内部逐项留痕（公开面维持 reason→count）→ #60-CLOSURE-D
  DR-LINT-0022-A 六处 lint 正式处理 → #60-CLOSURE-D
  #64/#68 公共 Contract 消费验证与下游接线 → #60-CLOSURE-D / 下游 Issue
  #58 字段/schema 任何改动（本 IP 零修改 lima/contracts/**）
  version_compatibility_matrix 注册（BG-60-01 维持默认不注册；本 IP 新 schema 同样不注册）
  整个 Issue Closure（IP-0023 DONE 不能据此关闭 #60）
Delivery role：closure-first-slice（monorepo 组件层：识别 + 每组件全链 + 独立版本化图承载）
Issue closure impact：PARTIAL
Upstream IP/PR/merge commits：IP-0016（#167 @fd219724）、IP-0018（#170 @cc17662）、
  IP-0019（#174 @e000e6f）、IP-0021（#179 @30bdfaa）、IP-0022（#180 @dfa0f85）；
  全部冻结消费面经恢复审计 §6 consumer review 43/43 PASS + 本 Packet §3 亲验复核
Upstream ruling：ALLOC-IP-0023-60-CLOSURE-A/v1；MR-60-RESUME-APPROVAL-20261009/v1 §五/§六
```

本 Packet 只声明 IP-0023 自身贡献。它不宣称 #60 任何端到端 AC 整体满足、不宣称 B/C/D 切片完成、不以 Packet 文档完成声称产品已交付。

---

## 1. Goal / Non-goals

### Goal

1. 新增 `lima/audit/component_graph.py`：确定性、只读、stdlib-only 的 monorepo 组件层——组件识别（manifest 锚定 + 目录归属证据）、每组件 Profile/RAM/semantic 全链（**复用三层冻结公共接口** `build_repository_profile` / `build_python_ram_facts` / `build_semantic_top_n`）、组件间依赖边三态分析（resolved / ambiguous / unresolved，AST import 证据 + provenance）、聚合上界预算（fail-closed）；
2. 新增 `schemas/v4/lima.component-graph.json`：独立版本化 component graph wire schema（**不注册 version_compatibility_matrix**，BG-60-01 口径）；
3. 图与每组件产物经独立 digest 关联（`component_graph_digest` 64-hex + 每组件三 digest 复算关联），**沿用 IP-0019 B-10 独立承载先例**（独立结果承载 + 自身 digest；DI-007：v4 RepositoryProfile 非空 extensions 即拒）；
4. monorepo golden fixture（可重放、排序稳定、输入顺序无关）。

### Non-goals

- 不修改 `lima/audit/__init__.py`（`__all__` 54 帽零触碰，见 §5.6.1）；
- 不修改三层冻结面 `lima/audit/{inventory,ram,semantic_prioritizer}.py`、`lima/audit/ram_schema.py`、既有 tests/audit 全部测试与 fixtures、既有 schemas/v4 15 文件、`lima/contracts/**`、`lima/workspace.py`；
- 不把图挂入 `RepositoryProfile` / `AttackSurfaceEntry.extensions` / RAM wire payload / 任何 #58 envelope（B-10 + Assignment 冻结约束）；
- 不扩展 digest 家族既有成员语义（ram_facts/semantic_config/semantic_result/prompt/model/wire 六 digest 原样；新增的 `component_graph_digest` 是独立新成员，不改不动旧成员）；
- 不执行、不 import、不安装目标项目；不通过目标脚本补证据；不引入网络/付费模型调用（semantic 默认 off，与 IP-0019 §5.4.1 相同）；
- 不处理 F3/F4、安全停止端到端、FR-01 全 vocabulary 内部留痕、#64/#68 消费接线（见 §0 Not covered）。

---

## 2. Design Input Manifest

| Input ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001 | Standard | `docs/LIMA_PACKET_AND_VERIFICATION_AGENT_RESPONSIBILITY_CHARTER.md` | main @fbbbd619 | Packet 结构、Manifest/Rejected 要件、RED/冻结/验证边界 | normative | 最高优先级之一，冲突时停止 |
| DI-002 | Standard | `docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md` | main @fbbbd619 | 不执行/路径有界/fail-closed 不变量、验证命令底线 | normative | 同上 |
| DI-003 | Standard | `docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md` §8/§9 | main @fbbbd619 | Packet Gate 全清单、分支拓扑、禁自动关闭关键字 | normative | 同上 |
| DI-004 | Decision | Coordinator Assignment `ASSIGN-60-CLOSURE-A-PKT-D1_v1`（SHA-256 `5a118ea9603c67663a63c17da7db203a705edecddd60ed0f06c77b5f2d573b82`，读取前重算一致） | 2026-10-09 | 范围、文件边界（Allowed Files 恰一个本文档）、冻结接口清单、验收判据 1-6、停止条件 | normative（唯一任务合同） | 与其他输入冲突时以 Assignment 为准并提交 Decision Request |
| DI-005 | Decision | `ALLOC-IP-0023-60-CLOSURE-A/v1`（#60 Ledger 恢复记录条目内，live 亲取） | 2026-10-09 | IP-0023 编号有效性、首片范围、禁令与失效条款 | normative | 编号失效（对端先占用）→ 停止上报 |
| DI-006 | Issue | Source Issue #60 live 正文 + Delivery Ledger | 2026-10-09 API 亲取（body SHA-256 `477ad50c…f8180`，state=open，updated_at=2026-10-09T06:37:15Z，comments=10，labels 含 status:in-progress） | L28 AC-01、L65 边界矩阵、L77 V5-FR-03、L82-83 V5-AC-01/02、Ledger 7/6/4 覆盖矩阵与切片归属 | normative（需求范围） | V5 覆盖层优先于 V4 正文 |
| DI-007 | Decision | 恢复审计链：`RESUME-AUDIT-60-2026-10-09_v1`（SHA-256 `74ad8c13…9b71`）+ addendum-1（`852e2d05…7e7ef`）+ addendum-2（`e9dbbb58…1bd31`） | 2026-10-09，SHA 全部重算一致 | workspace 漂移定性（§4②移交口径）、五 IP 消费面结论（43/43）、切片归属表、停点条款修订版（计数变化需解释、不删测试追平）、开放 PR #266/#281 零交集 | normative | — |
| DI-008 | Decision | Maintainer 批复 `MR-60-RESUME-APPROVAL-20261009/v1`（正文 SHA-256 `e4bcc9c3…cabb`，指针 `authorization/v2/PHASE_B_APPROVAL_BODY.md`，重算一致） | 2026-10-09 | §五（D1 边界、分支/文件名建议、allowance NOT_ALLOWED）、§六（七条产品目标与设计边界、已否决路线、安全基线） | normative | 已否决路线不得重试 |
| DI-009 | Upstream IP | IP-0016 Packet v1.2（`docs/LIMA_Implementation_Packet_IP-0016_Repository_Profile_Layer1.md`，@fbbbd619 亲读） | main @fbbbd619 | manifest 候选口径（D4）、`build_repository_profile` 签名与 sentinel digest、LF 口径（DR-IP-0016-02/PI-DR6） | normative（先例+接口） | 只读消费 |
| DI-010 | Upstream IP | IP-0018 Packet v1.1（`…_IP-0018_RAM_Facts.md`）+ IP-0019 Packet v1.2（`…_IP-0019_Semantic_TopN.md`，含 B-10/DI-007 独立承载先例、candidate_id 冻结编码、SemanticBudgets 勘误值 28,096） | main @fbbbd619 亲读 | 每组件 RAM/semantic 复用路径、B-10 承载先例、降级语义 | normative（先例+接口） | 只读消费 |
| DI-011 | Upstream IP | IP-0021 Packet v1.1（`…_IP-0021_RAM_Schema_Golden.md`：wire schema 先例、GAP_CODES_ALL 10 码、execution_required 9 码定案 DR-IP-0021-0102 DR-1、golden matrix 模式、matrix 不注册先例）+ IP-0022 Packet v6（`…_IP-0022_Fix.md`：`is_secret_shaped_path` 准入口径、R1 终案 reason→count、manifest-index 稳定标识先例、AdmissionSkipRecord） | main @fbbbd619 亲读 | wire schema 风格、gap 复用口径、隐私准入、NFR-01 五面口径 | normative（先例+接口） | 只读消费 |
| DI-012 | Code | 三层冻结面 + ram_schema + `__init__.py`：`lima/audit/{inventory,ram,semantic_prioritizer,ram_schema,__init__}.py`（@fbbbd619，§3.1 逐符号 import 亲验；`__all__` 恰 54 项 + 冻结断言 `len(__all__) == 54`） | @fbbbd619 | 全部公共签名/常量/预算默认值/错误语义的精确消费面 | normative（接口冻结） | 漂移 → DR 停点 |
| DI-013 | Code | `lima/workspace.py`（@fbbbd619 亲验：DEFAULT_EXTENSIONS 37 项含 C++ 扩容、DEFAULT_FILENAMES 6 项、`WorkspaceFile` 第 4 字段 `line_count`、`read_text`=`read_bytes().decode("utf-8")` 保留 CRLF、`fingerprint()`=path/size/sha256、skip reason 词表与 `_safe_path` 边界语义未变）+ `lima/contracts/profile.py`（`encode/decode_profile_envelope`、`_validated_path`、`_validated_extensions` v4 非空 extensions 拒绝、`RepositoryKind.MONOREPO="monorepo"`）+ `lima/contracts/codec.py::compute_content_digest` + `lima/contracts/errors.py::ContractError`（UNKNOWN_FIELD/INVALID_FIELD_TYPE/INVALID_FIELD_VALUE） | @fbbbd619 | 输入域口径、#58 契约消费、错误码复用 | normative（契约冻结）+ current-behavior（workspace） | workspace 行为以当前 main 为准，不当作隐式新能力 |
| DI-014 | Test | tests/audit 既有 10 测试文件（235 用例基线锚，含 IP-0022 51 例回归锚）+ 五形态 golden（`fixtures/golden_matrix/golden/{application,cli,docs,library,test-heavy}.json`）+ `fixtures/repo_shapes.py` helper 先例（`workspace_with`/`profile_kwargs`） | @fbbbd619 亲验文件清单 | 回归零破坏边界、fixture 构造模式 | normative（回归锚） | 计数变化需解释（addendum-2 §3 修订版），不删测试追平 |
| DI-015 | Decision | PI-DR1..PI-DR6（生效于五 IP Packet 与 DR 链内；IP-0016 §13/§14、IP-0018 L339-340 定义） | Ledger 2026-09-12/13 | arrange 平台中立（LF 钉死）、冻结前非 Windows 完整跑一次、PR 禁 close 关键字 | normative | — |
| DI-016 | Decision | DR 链：DR-IP-0016-01/02、DR-TOPN-01、DR-IP-0021-0102（DR-1/DR-2）、DR-IP-0022-01/02/03/04、DR-C1（ERRATUM 2026-09-13）、IP-0024 Packet §0.1/DI-013（IP-0023 预留行政勘正） | Ledger + docs @fbbbd619（IP-0024 §0.1 亲读） | digest sentinel、LF 重冻结先例、B 组批准值、9 码触发、准入/R1 终案、编号预留依据 | normative | — |

### Explicitly Rejected Inputs

- 任何需要修改 `lima/workspace.py` 或共享输入/安全层才能表达的方案（F3 路线归 #60-CLOSURE-C；本片组件识别在现有 workspace 行为内表达）；
- 任何扩展 `lima/audit/__init__.py.__all__` 54 帽、私加 #58 Profile 字段、借 `AttackSurfaceEntry.extensions` / RAM wire payload / 任何未知 extensions 携带图的方案（B-10 + `_validated_extensions` 冻结语义冲突）；
- 已否决路线（Assignment/MR §六，不重试）：prompt/wire 层掩码 path；full-payload digest 扩展；公开 redact:sha8/家族计数；摘要检查前置于结构检查；IP-0022 单 PR 流程例外（不推广）；
- `lima/python_dataflow.py`、`lima/semantic_retrieval.py` 的消费（Issue §Current code baseline 列为只读背景；semantic 链复用指 `lima.audit.semantic_prioritizer` 公共入口，非 `semantic_retrieval.py`；组件层 import 扫描自带最小 AST 解析，不引入对共享模块的新依赖方向）；
- 修改 `repository_kinds` monorepo 判定语义（inventory 冻结行为；本片组件图与 kinds 分类各自表述，见 §5.1.6）；
- #266（OpenHarmony pilot）与 #281（offline preflight）的任何文件/语义面（恢复审计 addendum-2 §5 四查③亲验与 #60 预期路径零交集；#281 的 profile_consumer 仅为只读参考，不作为本片验收依据）；
- #94 轨道全部路径、IP-0020 vault、IP-0024..IP-0043 baseline 轨道、BG-IP-0016-01/ BG-60-01 处置（OPEN 项归置权在 Coordinator，本片不清偿不扩大）；
- 任何聊天记录、调研文档推断、快照外时点数据（以 §2 Manifest 所列 live/锚定输入为准）。

---

## 3. Current code baseline（P&V 亲验誊录，@fbbbd619）

本阶段（D1）按 Assignment §Acceptance 第 6 条执行：不重跑全量产品测试（引用恢复审计 §5 真实数字为基线锚），对 Packet 引用的冻结符号/常量做只读核对（import 亲验或源码誊录，禁止执行目标项目样本）。

### 3.1 三层冻结面 + ram_schema 消费面（DI-012，import 亲验）

- **Layer 1（inventory）**：`build_repository_profile(workspace, *, tenant_id, task_id, workflow_id, stage_attempt_id, artifact_id, repository_snapshot_digest, producer="lima.audit.inventory", policy_digest=<sentinel e3b0c442…b855>, toolchain_digest=<sentinel>, options: ProfileInventoryOptions|None)` → `ProfileBuildResult{profile, envelope, provenance_anchor_ids, admission_skips}`；`ProfileBudgets{manifest_max_bytes=262_144, max_manifest_files=64}`；`is_secret_shaped_path`（段级检测，`tests/secrets/x.py`→True / `tests/tokenizer/x.py`→False 亲验）；`AdmissionSkipRecord{index, reason, family}`（内部留痕，无文件名）。
- **Layer 2（ram）**：`build_python_ram_facts(workspace, *, budgets=None)` → `RamFactsBuildResult{facts, provenance_anchor_ids, admission_skips}`；`RamBudgets{max_python_files=512, max_key_flows=256, max_unresolved_edges=1024}`；`PythonRamFacts` 11 字段；`ram_facts_digest(facts)`（64-hex）。
- **Layer 3（semantic）**：`build_semantic_top_n(facts, *, options=None, model_client=None)`；`SemanticOptions{top_n=20, weights, seed=0, budgets, model_id="unset", prompt_template, tie_break="kind-path-symbol-ordinal"}`；`SemanticBudgets{max_llm_calls=8, max_prompt_tokens_estimate=24_000, max_output_tokens_estimate=4_096, max_total_tokens_estimate=28_096, max_wall_time_seconds=120}`；`candidate_id("sensitive-sink","a/b.py",None,0) == "sensitive-sink:a/b.py:-#0"`（冻结编码亲验）；`semantic_result_digest(result, *, input_facts_digest=None)`；模型默认 off（`model_id="unset"` 或无 client → 零调用零网络）。
- **Schema 层（ram_schema）**：`GAP_CODES_ALL` 恰 10 码（AMBIGUOUS_DISPATCH / BUDGET_EXHAUSTED / DYNAMIC_IMPORT / INVENTORY_SKIPPED / MANIFEST_PARSE_ERROR / NO_LANGUAGES_DETECTED / SEMANTIC_MALFORMED_OUTPUT / SEMANTIC_MODEL_OFF / SEMANTIC_MODEL_TIMEOUT / UNSUPPORTED_LANGUAGE）；`GAP_EXECUTION_REQUIRED_TRIGGERS = GAP_CODES_ALL - {"SEMANTIC_MODEL_OFF"}` 恰 9 码；`PROVENANCE_ANCHOR_CHAIN=("inventory","ram-facts","semantic-prioritizer")`；`ram_wire_payload` / `validate_ram_wire_payload` / `ram_wire_digest` / `execution_required_from_gaps` / `load_ram_wire_schema`。
- **manifest 候选机制（inventory 私有，值重述不 import）**：`_MANIFEST_EXACT_NAMES` = {Cargo.toml, environment.yml, go.mod, package.json, pom.xml, pyproject.toml, setup.cfg, setup.py} + `requirements*.txt` 模式；候选 = 根目录 + 一级子目录（os.listdir 后 sorted）；`_record_manifest_error` 用 `manifest-index=<排序下标>` 稳定标识（DR-IP-0022-04 A 定稿版，不泄漏敏感文件名）。
- **monorepo kind 判定（inventory 冻结行为，亲验 `_repository_kinds`）**：`has_languages and len(manifest_subdirs) >= 2` → `RepositoryKind.MONOREPO`（wire 值 `"monorepo"`，#58 IP-0003 §10 冻结）。

### 3.2 `lima/audit/__init__.py` 现状（DI-012）

134 行；`__all__` 恰 54 项 = IP-0016 段 `[0:11]` + IP-0018 段 `[11:20]` + IP-0019 段 `[20:44]` + IP-0021 段 `[44:54]`（字母序段追加先例）；docstring 内冻结断言说明 ``len(__all__) == 54``。本 Packet 对该文件**零修改**（§5.6.1）。

### 3.3 workspace 口径（DI-013；恢复审计 §4② 定性移交，全部 @fbbbd619 亲验）

- `DEFAULT_EXTENSIONS` 已扩容至 37 项（新增 .ac/.am/.cmake/.conf/.css/.cxx/.hh/.html/.hxx/.in/.inl/.ipp/.tpp/.list/.m4/.po/.pot 等 C/C++/构建类）+ `DEFAULT_FILENAMES` 6 项（CMakeLists.txt/Makefile 等）——**输入域变化**：此前按 unsupported-extension 跳过的文件现进入 inventoried 集合；既有五形态 golden 不受影响（fixtures 不含新扩展文件，tests/audit 235 全绿，恢复审计实证）；
- `read_text` = `path.read_bytes().decode("utf-8")`——**保留 CRLF，无 universal-newline 归一**；
- `WorkspaceFile` 第 4 字段 `line_count`（`to_dict()` 同步）；`fingerprint()` 仍 = path/size/sha256（逐项 update，亲验实现）；skip reason 词表（ignored-directory/symlink/sensitive-config/unsupported-extension/unreadable/file-size-limit/file-limit/total-size-limit/binary/non-utf8 + IP-0022 新增 sensitive-filename）与 `_safe_path`/`absolute_file` 边界语义未变；
- F3（_safe_path TOCTOU）未因漂移闭合，归 #60-CLOSURE-C。

### 3.4 基线数字（恢复审计 §5 Coordinator 实跑 @fbbbd619，锚定引用非本轮重跑）

contracts `617 OK` / audit `235 OK 0 skip`（含 IP-0022 51 例回归锚）/ evidence_privacy `244 OK 3 skip` / workspace+dataflow `44 OK` / `ruff check --no-cache lima/audit` 净 / `ruff check --no-cache lima/audit tests/audit` 恰 DR-LINT-0022-A 六处（B009×1 + B017×5，全在 tests/audit/test_ip_0022_fix.py）零漂移 / CI 完整入口 `3006 OK 24 skip`（全环境类：15 requires-Linux + 2 POSIX-only + 6 WinError 1314 + 1 Semgrep）。数字为基线锚，按 addendum-2 §3 修订版停点条款执行：计数变化需解释，不单独构成停点；不得删测试/改 Oracle 追平。

---

## 4. Files boundary（冻结单解；D2 冻结与 Implementation 将据此执行）

### 4.1 Files to Add（产品与数据产物，Implementation Agent 拥有）

| # | 文件 | 说明 |
|---|---|---|
| 1 | `lima/audit/component_graph.py` | 唯一产品代码文件（§5 全部实现） |
| 2 | `schemas/v4/lima.component-graph.json` | component graph wire schema（独立版本 1.0；**不注册 matrix**） |

### 4.2 Test/Fixture Files（P&V 独占，D2 创建，Implementation 禁改）

| # | 文件 | 说明 |
|---|---|---|
| 3 | `tests/audit/test_component_graph.py` | 组件识别/边三态/确定性/预算/隐私/wire 负例（§6） |
| 4 | `tests/audit/test_monorepo_golden.py` | monorepo golden 可重放（§6） |
| 5 | `tests/audit/fixtures/monorepo/__init__.py` | fixture 包 |
| 6 | `tests/audit/fixtures/monorepo/shapes.py` | monorepo repo 形态构造（LF 钉死；沿用 `repo_shapes.workspace_with` 模式） |
| 7 | `tests/audit/fixtures/monorepo/golden/monorepo.json` | monorepo golden（Implementation 有效 RED 后产出的合法数据产物，提交前经 P&V 核对 digest 链） |

### 4.3 Product Files Allowed to Modify

**无**。`lima/audit/__init__.py` 本 IP 零修改（与 IP-0019/0021/0022 的"纯追加 re-export"边界不同：本 IP 新公共符号不经 `lima.audit` 命名空间 re-export，见 §5.6.1 单解）。

### 4.4 Read-only Reference

三层冻结面 `lima/audit/{inventory,ram,semantic_prioritizer,ram_schema}.py`、`lima/audit/__init__.py`、`lima/workspace.py`、`lima/contracts/**`、`schemas/v4/**` 既有 15 文件、`scripts/run_ci_tests.py`、tests/audit 既有 10 测试文件与全部既有 fixtures（`fixtures/{repo_shapes.py, library_profile_golden.json, ram/, semantic/, golden_matrix/}`）、五 IP Packet 与 DR 链文档、本 Packet。

### 4.5 Files Forbidden

除 §4.1/§4.2 外的一切路径；特别冻结：`lima/audit/__init__.py`（54 帽）、三层+ram_schema 模块、既有 tests/audit 测试与 fixtures（含 `test_ip_0022_fix.py` 六处 DR-LINT-0022-A 登记处）、`schemas/v4/version_compatibility_matrix.json` 与既有 14 schema 文件、`lima/contracts/**`、`lima/workspace.py`、`lima/python_dataflow.py`、`lima/semantic_retrieval.py`、scanner/service/api/store/sandbox/frontend、`.zcode/**`、`.github/**`、#94/#266/#281/baseline 轨道路径、`docs/**`（本 Packet 阶段 D1 已定稿）、根检出与全部历史 worktree、`main` 分支。

### 4.6 Symbol-to-File Map（全部新增公共符号均在 `lima/audit/component_graph.py`）

见 §5.4.7 模块级 `__all__` 导出清单（恰 32 项：23 个类型/函数/图常量 + 9 个 manifest kind 常量）。

### 4.7 冲突分析

与 #266（30 文件：Dockerfile/cxx_analyzer/deploy/docs/competition/evaluation_data/lima/agent_*/openharmony_validation/uaf_llm_branch/scripts/tests 对应面）与 #281（6 新增文件：benchmarks/v4/preflight/* + tests/test_investigation_preflight.py + tests/test_profile_consumer_preflight.py）文件级零交集（恢复审计 addendum-2 §5 亲验，本轮 Assignment 引用；本 Packet 预期路径 `lima/audit/component_graph.py`、`schemas/v4/lima.component-graph.json`、`tests/audit/{test_component_graph,test_monorepo_golden}.py`、`tests/audit/fixtures/monorepo/**` 均不在两 PR diff 内）。与 B/C/D 切片边界按 §0 Not-covered 划分，无重叠 Owner。

---

## 5. 冻结设计（Assignment §六 1-7 逐条落位）

### 5.1 组件识别（Assignment §六.1 / §六.2 部分）

#### 5.1.1 组件边界与锚定（冻结单解）

- **锚点集合**（值重述 inventory 冻结口径，不 import 私有符号）：manifest 文件 = `_MANIFEST_EXACT_NAMES` 8 类 + `requirements*.txt` 模式；**候选范围 = 仓库根目录 + 一级子目录**（与 inventory manifest 候选口径一致；经 `workspace.absolute_file()` 边界校验存在性，不 os.walk 全仓）。
- **组件** = 恰有一个锚定目录（manifest 所在目录）的文件集合主张：锚定目录 ∈ {"根目录", "一级子目录"}；同目录多个 manifest（如 pyproject.toml + setup.cfg）**归并为同一组件**，`manifests` 列表记录全部（按 path 排序）。
- **锚定目录互不嵌套**（根与一级子目录平级），因此每个文件至多归属一个组件——唯一归属可构造（见 5.1.3）。
- 组件识别**只做存在性+文件名模式匹配，不解析 manifest 内容**（parse 属 Profile 层既有行为；组件层无新增 MANIFEST_PARSE_ERROR 来源，manifest 解析失败经该组件 Profile 构建继承既有 gap）。
- **归属依据 = manifest 锚定（主证据）+ 目录结构（辅助证据）**；路径目录名只用于文件归属的目录锚点计算，**不产生任何依赖边**（依赖边唯一来源 = AST import 语句证据，见 5.3）。

#### 5.1.2 稳定 component ID（冻结单解）

```text
component_id = "component:" + <锚定目录的 repo-relative POSIX 路径>
根目录组件   = "component:."
一级子目录   = "component:services/api"（目录名原样，POSIX 正斜杠，无尾斜杠、无 "."/ ".." 段）
```

无碰撞可重放：锚定目录集合由 manifest 候选确定（sorted 枚举）；同目录归并单组件；ID 由目录路径一一映射。`components` 按 `component_id` 字符串升序排序（`"component:."` 因 `.`(0x2E) 排序在最前，稳定）。

#### 5.1.3 文件归属（inventoried .py 文件，冻结单解）

- 归属规则：文件的锚点 = 自文件路径向上（`path.split("/")` 前缀）最近的**一级子目录组件**；若所在一级子目录无 manifest → 落到根组件（根有 manifest 时）；根无 manifest → **unassigned**。根目录散文件 → 根组件（根有 manifest 时）否则 unassigned。
- `python_file_count` = 该组件归属的 inventoried `.py` 文件数；`is_empty = (python_file_count == 0)`（**空组件策略**：有 manifest 但零归属 .py 文件的组件如实保留在 `components` 中、`is_empty=True`，不编造边、不剔除）。
- **unassigned 文件**（归属证据不足，三态之"证据不足"的具体承载之一）：`unassigned_files` 列表（repo-relative POSIX 排序，cap = `MonorepoBudgets.max_unassigned_files`，超限截断 + BUDGET_EXHAUSTED gap）+ `unassigned_file_count` 完整计数（不受 cap 影响）。零组件仓库 = 全部 inventoried .py 落 unassigned（cap 后列表 + 完整计数），`components=()`、`edges=()`——不因零组件报错。
- **共同文件两义分别落位**（Assignment §六.2）：(a) "被多组件引用的文件" = 跨组件 import 边的多条 evidence（文件归属仍唯一）；(b) "无法唯一归属的文件" = unassigned 集。因锚定目录互不嵌套，本设计不存在第三种归属歧义。

#### 5.1.4 解析依据不足与不执行

- 组件识别证据不足（文件无 manifest 锚点）→ unassigned 如实记录，**不**按目录名猜测组件；
- 依赖解析依据不足 → 边三态（5.3），不编造依赖；
- **不执行目标项目补证据**：零 importlib 目标代码、零 subprocess、零网络（模块静态断言，§6 类别 7）；manifest 只读存在性检查，.py 只经 `workspace.read_text()` 有界读取后 `ast.parse`（IP-0016 setup.py 先例）。

#### 5.1.5 适用输入范围

任意 `RepositoryWorkspace` 快照（含非 monorepo）：零组件/单组件（仅根 manifest，图 = 单组件零边，合法输出）/多组件。图分析面向 inventoried `.py`（Python 平台，当前 Golden Path 口径与其余三层一致）；其他语言文件进入组件 Profile 的 inventory 维度（既有行为），不产组件间 Python import 边。

#### 5.1.6 与 `repository_kinds` 的关系（不重算、不修改）

monorepo kind 判定是 inventory 冻结行为（`has_languages and len(manifest_subdirs)>=2`，作用于全仓单仓构建）。本片每组件构建使用组件子 workspace（其内部一般无嵌套 manifest 子目录，组件 profile 通常不判 monorepo——如实呈现，不修正）；全仓维度 kind 分类由既有 `build_repository_profile(全仓 workspace)` 独立承载（现状行为，零改动）。组件图与 kinds 各自表述，互不覆写。

### 5.2 每组件 Profile/RAM/semantic 全链（Assignment §六.2；复用公共接口）

#### 5.2.1 构建路径（冻结单解）

```python
# 每组件（component_id 按序遍历，未超 max_components 截断的全部构建）：
component_ws = RepositoryWorkspace(<仓库根 / component.root_dir 或 仓库根本身>)
profile_result = build_repository_profile(component_ws, **六 ID 参数原样透传,
                                          producer="lima.audit.component_graph",
                                          policy_digest=..., toolchain_digest=...,
                                          options=profile_options)            # 复用 IP-0016 入口
ram_result     = build_python_ram_facts(component_ws, budgets=ram_budgets)   # 复用 IP-0018 入口
semantic_result = build_semantic_top_n(ram_result.facts, options=semantic_options,
                                       model_client=model_client)            # 复用 IP-0019 入口
```

- **六 ID 参数**（tenant_id/task_id/workflow_id/stage_attempt_id/artifact_id/repository_snapshot_digest）对每组件**原样透传同一组值**（#58 envelope 无全局唯一性约束，每组件 envelope `content_digest` 各自不同；语义 = 同一 artifact 下的组件子剖面——单解，见 §5.6.4 兼容论证）；
- `policy_digest`/`toolchain_digest` 默认 sentinel `e3b0c442…b855`（DR-IP-0016-01 口径，空串非法语义由 IP-0016 入口承担）；`producer` 固定 `"lima.audit.component_graph"`（调用方不可覆盖该值——与 `build_repository_profile` 的 producer 可选参数区分：本层是有明确来源的聚合层）；
- `model_client` 默认 None → 每组件 semantic off（`SEMANTIC_MODEL_OFF` gap 在各 `semantic_result.coverage_gaps` 内，继承不复制）；调用方注入时**每组件独立预算包络**（SemanticBudgets 按组件计，聚合上界见 5.4.4）；
- **坐标分离**（冻结声明）：每组件三段产物内的路径 = 组件内相对坐标（与单仓行为一致）；**图与边证据的路径一律仓库级 repo-relative POSIX**（实现层维护 `仓库路径 = component.root_dir + "/" + 组件内路径` 的确定映射；边证据扫描基于**主 workspace**（全仓根）读取归属文件，路径天然仓库级）。

#### 5.2.2 provenance（冻结单解）

- 每组件三段 `provenance_anchor_ids` 原样保留（`("inventory",)` / `("ram-facts",)` / `("semantic-prioritizer",)`）——逐层断言（与 golden_matrix 先例同）；
- 组件身份 provenance = `ComponentInfo.manifests`（manifest 路径 + kind 枚举）；
- 边 provenance = evidence 位点列表（`EdgeEvidence{path, line, imported_name}`，排序去重 cap）；
- 图级 `provenance_anchor_ids = (COMPONENT_GRAPH_PROVENANCE_ANCHOR,) = ("component-graph",)`（新 anchor，独立承载；**不修改** `ram_schema.PROVENANCE_ANCHOR_CHAIN` 冻结三元组）。

#### 5.2.3 断开的组件（disconnected）

无任何入边/出边的非空组件 = 图中孤立节点，**如实呈现**（`components` 含该节点，`edges` 无引用）；空组件同。不编造连接、不删除节点、不加"孤立"特殊标记（孤立性由 edges 可推导，不冗余字段）。

#### 5.2.4 三态区分（Assignment §六.2；承载必须可区分，冻结单解）

| 状态 | 判据（承载中可观察） | 语义 |
|---|---|---|
| 真实无依赖 | `edges` 中无该组件参与的边 **且** `dependencies_complete == True` **且** `unassigned_file_count == 0` | 组件集完整、文件全归属、import 证据全量检查后确无组件间依赖 |
| 解析失败 | 存在 `status in {"ambiguous","unresolved"}` 的边（组件内动态 import 经该组件 RAM `DYNAMIC_IMPORT` gap 继承） | 存在 import 意图但静态无法唯一解析（歧义/目标不存在） |
| 证据不足 | `dependencies_complete == False`（预算截断：组件数超限或任一组件 python-file-limit 截断）**或** `unassigned_file_count > 0`（归属证据不足）**或**图 coverage_gaps 非空 | 分析覆盖不完整；**不得**解释为"没有依赖" |

`dependencies_complete` 置 False 的精确触发（枚举封闭）：(a) 组件数超过 `max_components` 被截断；(b) 任一组件 `ram_result.facts.coverage_gaps` 含 `BUDGET_EXHAUSTED` 且 detail 以 `reason=python-file-limit` 开头（组件内 .py 截断 → import 证据不全）。symlink 跳过的 .py 经组件 RAM 继承 `INVENTORY_SKIPPED` gap 可见（不单独置 False——与单仓 RAM 行为口径一致，避免双标准）。

### 5.3 重复模块名与相对导入（Assignment §六.2；边三态分析，冻结单解）

#### 5.3.1 证据采集

- 扫描对象 = 全部**归属**文件（各组件 inventoried .py，按仓库级路径 sorted）；unassigned 文件不产边（其归属未定，import 证据不入组件图——由 `unassigned_file_count>0` 显式声明该证据缺口）；
- 解析方式 = `ast.parse(workspace.read_text(path))`（主 workspace 有界读取；parse error 文件跳过并继承组件 RAM `MANIFEST_PARSE_ERROR`/facts 层既有 gap 通道——组件图不新增 parse-error gap 来源）；收集 `ast.Import`（各 alias 顶级名）与 `ast.ImportFrom`（module 名 + level）；
- 证据位点 = `EdgeEvidence{path: 仓库级 repo-relative, line: 1 基行号, imported_name: import 的名字}`（imported_name 是标识符/点号串，非源码正文——AttackSurfaceEntry.symbol 同类口径，NFR-01 相容）。

#### 5.3.2 组件 import 锚点名集合（anchors）

对组件 C（root_dir=d；d="" 为根）：

- (a) 组件归属 .py 文件仓库路径剥离前缀 `d + "/"` 后的**第一级目录名**（若剩余路径含 "/"）去重排序——组件内子包名；
- (b) 若组件根直接含 `__init__.py`（组件根本身是包）且 d ≠ ""：加入 d 的最后一段目录名（repo-relative 坐标内的确定性目录名）。**根组件不做 (b)**：根作为包的 import 名 = checkout 目录名，随宿主环境变化，非确定——如实不锚定（证据不足不编造）。

#### 5.3.3 边推导规则（封闭枚举）

对归属文件中的每条绝对 import（顶级名 T，`T` 非 "." 开头）：

| 情形 | 判定 | 边 |
|---|---|---|
| T ∈ anchors(C)（自组件） | 组件内依赖 | 无边（属该组件 RAM 范围） |
| T ∈ anchors(C') 唯一 C'≠C | 跨组件 resolved | 边 (C→C', status="resolved", imported_name=T) |
| T ∈ anchors(≥2 组件) | **重复模块名歧义** | 边 (C→target=None, status="ambiguous", imported_name=T)，evidence 聚合该名字全部位点。**候选组件集不入边**（防歧义被读成对每个候选的依赖断言）；歧义范围由 anchors 规则（5.3.2）确定且消费者可复算，边只声明"该名字无法唯一解析"（target=None + status） |
| T ∉ 任何 anchors | 外部依赖（stdlib/三方/未知） | 无边（组件级外部依赖线索属组件 Profile 既有维度；"未看见"不产边不产 gap） |

对相对 import（`ast.ImportFrom.level >= 1`，基准 = 当前文件目录，目标 = 基准向上 `level-1` 层 + module 路径，仓库坐标）：

| 情形 | 判定 | 边 |
|---|---|---|
| 目标落回本组件子树（目标 .py 存在或其包 `__init__.py` 存在） | 组件内相对导入 | 无边 |
| 目标落另一组件 root_dir 子树且存在（.py 或 `__init__.py`） | **跨组件相对导入 resolved** | 边 (C→C', status="resolved", imported_name=点号串如 "..mod"） |
| 目标路径不存在（文件与包均无；含越出仓库根的层级） | 解析失败 | 边 (C→None, status="unresolved", imported_name=点号串) |

动态 import（`importlib` 等）：不产组件边（目标运行时才知，静态无证据）；该位点经组件 RAM 的 `DYNAMIC_IMPORT` gap 继承（三层链既有承载，图不复制不重定义）。

#### 5.3.4 去重、排序与 cap（冻结单解）

- resolved 边键 = `(source, target)`；ambiguous/unresolved 边键 = `(source, status, imported_name)`（target 恒 None）；同键多证据聚合进 `evidence`；
- `evidence` 按 `(path, line, imported_name)` 排序去重，每边 cap = `MonorepoBudgets.max_edge_evidence`，超限截断 + BUDGET_EXHAUSTED gap（detail `reason=edge-evidence-limit; count=<溢出>`）；
- `edges` 按 `(source_component_id, status, target_component_id or "", imported_name)` 字符串元组升序排序；总数 cap = `MonorepoBudgets.max_edges`，超限截断 + gap（detail `reason=edge-limit; count=<溢出>`）+ `dependencies_complete=False`。

### 5.4 独立版本化 component graph 承载（Assignment §六.3；B-10 先例）

#### 5.4.1 数据结构（frozen dataclass，全部在 `lima/audit/component_graph.py`）

```python
@dataclass(frozen=True)
class ComponentManifestRef:
    path: str            # 仓库级 repo-relative manifest 路径
    manifest_kind: str   # COMPONENT_MANIFEST_KIND_* 枚举值（5.4.2）

@dataclass(frozen=True)
class EdgeEvidence:
    path: str            # 仓库级 repo-relative POSIX（.py 文件）
    line: int            # 1 基
    imported_name: str   # import 顶级名或相对导入点号串

@dataclass(frozen=True)
class ComponentInfo:
    component_id: str    # "component:." / "component:<一级子目录>"
    root_dir: str        # ""（根）或一级子目录名
    manifests: tuple[ComponentManifestRef, ...]   # 按 path 排序
    python_file_count: int
    is_empty: bool

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
    unassigned_files: tuple[str, ...]                  # 排序，cap
    unassigned_file_count: int
    dependencies_complete: bool
    coverage_gaps: tuple[ProfileCoverageGap, ...]      # gap_code 复用 10 码全集值重述（5.6.3）
    provenance_anchor_ids: tuple[str, ...] = (COMPONENT_GRAPH_PROVENANCE_ANCHOR,)
```

#### 5.4.2 枚举（Final 常量，冻结单解）

```python
COMPONENT_GRAPH_SCHEMA_VERSION: Final[str] = "1.0"
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
```

#### 5.4.3 公共函数签名（冻结单解）

```python
@dataclass(frozen=True)
class MonorepoBudgets:          # 全 int，__post_init__ 逐字段 type is int 且 ≥1 校验，否则 ValueError
    max_components: int = 16
    max_edges: int = 4_096
    max_edge_evidence: int = 64
    max_unassigned_files: int = 256

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
    per_component: tuple[ComponentBuildResult, ...]   # 按 component_id 升序（截断后实际构建的组件）
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
def validate_component_graph_payload(payload: Mapping[str, object]) -> None  # fail-closed ContractError
def load_component_graph_schema() -> dict                       # 只读加载 schema 文件（零网络）
```

**行为约束（冻结）**：stdlib-only + 既有 audit/contracts/workspace 模块；依赖方向 `lima.audit.component_graph → {lima.audit.inventory, lima.audit.ram, lima.audit.semantic_prioritizer, lima.contracts.*, lima.workspace}`（复用公共构建接口与 `is_secret_shaped_path`；**不 import** `lima.audit.ram_schema`——gap 码全集值重述，保持构建/验证解耦，与 IP-0021 先例方向一致）；`detect_components` 入参非 `RepositoryWorkspace` → `ContractError(INVALID_FIELD_TYPE)`；`build_monorepo_profile` 对非 str 的六 ID / 非 64-hex 的 digest 入参按 IP-0016 同口径 fail-closed（异常由底层入口传播，本层不吞不改）；任何模型路径失败不抛出到调用方（IP-0019 §5.0 部分结果语义，由 `build_semantic_top_n` 承担）；纯函数确定性——无时钟/随机/env/网络/写盘。

#### 5.4.4 预算语义单解（Assignment §六.5；fail-closed）

- **每组件预算包络**：每组件独立 `RepositoryWorkspace(component_root)`（默认 max_files=5_000 / max_file_bytes=512KiB / max_total_bytes=20MiB，与单仓一致）+ 每组件三层 Budgets 各自默认（`RamBudgets` 512/256/1024、`SemanticBudgets` 8/24_000/4_096/28_096/120、`ProfileBudgets` 262_144/64）——逐组件适用，不共享池；
- **聚合上界（有界放大证明）**：组件数 ≤ `max_components`（默认 16）⇒ 总 Python 文件分析 ≤ 16×512 = 8_192；总边 ≤ `max_edges`（4_096）；每边 evidence ≤ 64 ⇒ 总 evidence ≤ 262_144；unassigned 列表 ≤ 256（计数不受限）；semantic 默认 off 零调用，启用时总调用 ≤ 16×8 = 128（每组件独立包络，墙钟上限亦按组件计——聚合墙钟上界 = Σ 每组件 max_wall_time_seconds，由调用方以组件数自行约束，Packet 不引入跨组件墙钟共享状态（无全局时钟入 digest，确定性优先））；
- **fail-closed（不静默截断）**：组件数超限 → 按 component_id 序取前 16 + BUDGET_EXHAUSTED gap（detail `reason=component-limit; count=<溢出数>`）+ `truncated=True` + `dependencies_complete=False`；边/evidence/unassigned 三处 cap 同口径（5.3.4/5.1.3）；全部走 typed gap，无静默丢弃；
- **与 `max_manifest_files`（BG-IP-0016-01）的关系**：组件识别的 manifest 候选数 ≤ (根 + 一级子目录数) × 9 类模式，**不受** `ProfileBudgets.max_manifest_files=64`（Profile 层 manifest 读取预算）约束；每组件 Profile 构建内部仍受其自身 ProfileBudgets 约束（既有行为）。BG-IP-0016-01 保持 OPEN（>64 manifests 计数上限路径用例归置权在 Coordinator），本片不清偿不扩大。

#### 5.4.5 canonical bytes 与 graph digest（冻结单解）

```text
component_graph_digest = compute_content_digest(canonical_dict)
canonical_dict = {
  "components": [每组件规范 dict（component_id/root_dir/manifests[{path,kind}]/
                  python_file_count/is_empty）——按序],
  "edges": [每边规范 dict（source_component_id/target_component_id|null/status/
             imported_name/evidence[{path,line,imported_name}]）——按序],
  "unassigned_files": [...], "unassigned_file_count": N,
  "dependencies_complete": bool,
  "coverage_gaps": [{"gap_code","detail"}...]   # 排序 (gap_code, detail)
}
```

- canonical JSON = `lima.contracts.codec.compute_content_digest` 口径（IP-0018/0019 digest 先例），恒 64-hex；**不含** digest 自身、时钟、耗时、环境；
- 与 digest 家族的关系（冻结声明）：`component_graph_digest` 是**独立新成员**；既有六 digest（ram_facts/semantic_config/semantic_result/prompt/model/wire）语义与算法零改动、零交叉（图 digest 不进任何 envelope、不进 RAM wire payload、不参与 wire_digest 计算）。

#### 5.4.6 与组件 Profile/RAM 的关联（冻结单解）

- 关联发生在 **wire payload 层**（非图结构内）：`component_graph_payload(result)` 的 `components[].digests = {profile_content_digest: result.per_component[i].profile_result.envelope.content_digest, ram_facts_digest: ram_facts_digest(该组件 facts), semantic_result_digest: 该组件 result_digest}`——三个 64-hex 全部**复算可核对**（消费者重放三段构建即可复算）；
- 图 digest（拓扑+归属+证据）与每组件三 digest 并列进入 payload `identity` 段（§5.5 schema 表）；图 digest 输入不含组件三 digest（识别层可在三段构建前独立计算与消费——`detect_components` 单独公开的依据）。

#### 5.4.7 公共消费路径（`__all__` 导出与消费示例）

模块级 `__all__`（**恰 32 项**，字母序，封闭清单——实现不得增删公开名，D2 冻结测试逐一锁定）：

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
ComponentInfo, ComponentManifestRef, EdgeEvidence,
MonorepoBudgets, MonorepoProfileBuildResult,
build_monorepo_profile, component_graph_digest, component_graph_payload,
detect_components, load_component_graph_schema, validate_component_graph_payload
```

消费示例（公共接口，非内部窥探）：

```python
from lima.workspace import RepositoryWorkspace
from lima.audit.component_graph import (build_monorepo_profile,
    component_graph_payload, validate_component_graph_payload)

ws = RepositoryWorkspace(snapshot_root)
result = build_monorepo_profile(ws, tenant_id=..., task_id=...,
    workflow_id=..., stage_attempt_id=..., artifact_id=...,
    repository_snapshot_digest=...)          # semantic 默认 off
payload = component_graph_payload(result)    # 组件清单 + 边三态 + 每组件三 digest + 图 digest
validate_component_graph_payload(payload)    # fail-closed 契约校验
```

### 5.5 wire schema（`schemas/v4/lima.component-graph.json`）

结构风格沿 `lima.repository-architecture-model.json` 先例（draft 2020-12、顶层 `additionalProperties:false`、required 全列、集合字段 `maxItems` 上界）。字段映射（每字段 ← 冻结产物，无凭空字段）：

| schema 路径 | 来源 | 约束 |
|---|---|---|
| `schema_version` | `COMPONENT_GRAPH_SCHEMA_VERSION` | const `"1.0"` |
| `model_kind` | `COMPONENT_GRAPH_SCHEMA_NAME` | const `"lima.component-graph"` |
| `components[].component_id / root_dir / python_file_count / is_empty` | `ComponentInfo` | component_id pattern `^component:(\.|[A-Za-z0-9._\-]+(/[A-Za-z0-9._\-]+)*)$`（一级子目录名限定字符集，无 `..` 段）；is_empty 恒 `python_file_count==0`（模块校验） |
| `components[].manifests[].{path, manifest_kind}` | `ComponentManifestRef` | kind ∈ 九值 const 枚举；按 path 升序 |
| `components[].digests.{profile_content_digest, ram_facts_digest, semantic_result_digest}` | 5.4.6 复算关联 | 64-hex |
| `edges[].{source_component_id, target_component_id, status, imported_name, evidence[]}` | `ComponentEdge` | target 可 null（status=resolved 时必非 null 且 ≠ source；ambiguous/unresolved 时必 null——模块校验）；status ∈ 三值 const 枚举；evidence[].{path,line,imported_name}，line ≥ 1 |
| `unassigned_files[] / unassigned_file_count` | `ComponentGraph` | 排序字符串；count ≥ len(list) |
| `dependencies_complete` | `ComponentGraph` | bool |
| `coverage_gaps[].{gap_code, detail}` | `ProfileCoverageGap.to_dict()` | gap_code pattern `[A-Z][A-Z0-9_]{0,63}` 且 ∈ 10 码全集（模块校验） |
| `identity.component_graph_digest` | `component_graph_digest(graph)` | 64-hex |
| `provenance.provenance_anchor_ids[]` | `("component-graph",)` | const 单元序列 |

版本语义：`"1.0"` 是 component graph 承载自身第 1 版（独立小版本域）；文件置于 `schemas/v4/` 目录沿用工程布局，但**不注册** `version_compatibility_matrix.json`（BG-60-01 口径维持默认不注册；`tests/contracts/test_compatibility_matrix.py` 只以 matrix 文件行为枚举源，IP-0021 §3.4 先例亲验，新增未注册 schema 文件不触及 contracts 617）。

### 5.6 兼容约束（Assignment §六.4；逐项冻结声明）

#### 5.6.1 `lima/audit/__init__.py.__all__` 54 帽——零触碰单解

- **处置**：本 IP **不修改** `lima/audit/__init__.py`（不在 Modify 边界内，§4.3）。新公共符号仅经 `lima.audit.component_graph` 模块级 `__all__` 导出（§5.4.7），消费路径 `from lima.audit.component_graph import ...`；
- **与 54 帽的关系**：帽（含冻结断言 `len(__all__) == 54`）原样成立；`import lima.audit` 零新副作用（`__init__` 不 import component_graph）；既有分段断言（`[0:11]`/`[11:20]`/`[20:44]`/`[44:54]`）零影响；
- **不扩帽的理由与备选**：扩帽=触及冻结面（需 DR 获批前不实现）。本 Packet 默认方案完全自足（独立模块消费与 IP-0019 B-10 独立承载方向一致）；"追加 re-export 进 `lima.audit`" 列为**备选 DR 草案**（见本 Packet 交接报告附件，不进实现范围）——若 Coordinator/Maintainer 未来批准扩帽，走 Packet 修订 + DR 流程，与本片验收面解耦。

#### 5.6.2 candidate_id 与 digest 家族

- `candidate_id` 冻结编码（`"sensitive-sink:a/b.py:-#0"` 形态）零改动——每组件 semantic 链原样产出；component_id 是**新命名空间**（`"component:"` 前缀），与 candidate_id 的 `kind:path:symbol#ordinal` 形态无碰撞（前缀与槽位结构不同）；
- 既有六 digest（ram_facts/semantic_config/semantic_result/prompt/model/wire）算法与取值零改动；新增 `component_graph_digest` 独立成员（5.4.5）；**不扩展全 payload digest、不改 wire_digest 输入**（已否决路线不重试）。

#### 5.6.3 GAP 码全集与 execution_required 语义

- `GAP_CODES_ALL` 10 码**不新增、不改名**：component graph 的 coverage_gaps 复用既有码值（**值重述** `frozenset` 字面量于 component_graph.py，注释锚定来源；不 import ram_schema，构建/验证解耦）；使用的码：`BUDGET_EXHAUSTED`（四类 cap 截断）、`INVENTORY_SKIPPED`（敏感形态文件名准入拒绝，detail `reason=sensitive-filename; count=N`，R1 终案 reason→count 口径）；
- **不新增 GAP 码**的理由：新码会破坏 `GAP_CODES_ALL` 冻结面与 9 码触发集推导；本片全部缺口语义在既有码内单解表达；
- `execution_required` 9 码触发语义（DR-IP-0021-0102 DR-1）零改动：component graph payload **不承载** execution_required 字段（它属于 RAM wire envelope 的 typed 字段；每组件的 execution_required 由既有 `execution_required_from_gaps` 对该组件 facts/semantic gaps 派生，消费者可自行经公共函数计算——本片不复制不重定义）。

#### 5.6.4 #58 Contract 与 v4 schema/旧 golden

- `encode/decode_profile_envelope`、`encode_envelope`、`ArtifactReference`/`ArtifactEnvelope`、`AttackSurfaceEntry`/`ProfileCoverageGap`、`_validated_path`、v4 非空 extensions 拒绝语义：**全部只读消费**（ProfileCoverageGap 作为图 gap 的公共类型构造——gap_code pattern 校验天然复用；`_validated_path` 语义经 entries 继承，本层不自造路径校验）；
- **不私加 #58 Profile 字段、不借 extensions 携带图**（B-10）；图不进任何 envelope；
- 六 ID 每组件透传的兼容论证：#58 envelope 校验按单 envelope 独立（artifact_id 无跨 envelope 全局唯一性断言；IP-0016 golden 即以固定六 ID 单 envelope 构造）；每组件 envelope content_digest 因内容不同而互异，语义 = 同一 artifact 的组件子剖面；旧消费者（只消费全仓单 envelope / RAM wire）不受影响；
- schemas/v4 既有 15 文件与 matrix 零改动；**旧 golden（五形态 + library_profile_golden）期望值零改动**（本片不触三层行为，回归锚见 §8）。

#### 5.6.5 TaskManifest 消费面衔接

RAM wire 以 TaskManifest 消费面衔接（repository snapshot digest 入参）的既有口径不变；`build_monorepo_profile.repository_snapshot_digest` 与全仓单仓构建取同值（同一快照 digest 传入，组件层不重定义快照语义）。

### 5.7 输入与确定性（Assignment §六.5；恢复审计 §4② 移交口径落位）

- **workspace 输入域扩容**：组件识别与每组件构建均在**当前 main workspace 口径**下工作（DEFAULT_EXTENSIONS 37 项/DEFAULT_FILENAMES 6 项）；本片**不把扩容当作隐式新能力**——不依赖任何新扩展（.in/.cmake 等）进入 inventory 的行为；新 fixture 扩展名集合显式声明（5.7.1）；
- **CRLF 保留**：`read_text` 保留 CRLF（当前行为）；若被分析文件含 CRLF，AST 行号按保留 CRLF 的原文计算（口径 = 当前 workspace 行为，不引入归一化）；本片 fixture 全 LF（5.7.1），无 CRLF 敏感断言；`line_count` 字段存在但本片不消费其值（仅知悉）；
- `fingerprint()`/skip 词表/`_safe_path` 边界语义未变（恢复审计定性移交如实引用，F3 归 CLOSURE-C）；
- **确定性判据（冻结）**：同一 workspace 快照 + 同一 budgets/options 两次独立构建 ⇒ `component_graph_digest` 相等、`components`/`edges`/`unassigned` 逐字段相等、每组件三 digest 相等；**输入顺序变化**（目录枚举顺序/文件写入顺序不同、内容相同的两个快照目录）⇒ 结果不变——全部枚举入口（manifest 候选/组件/文件/边/evidence）一律 sorted，禁 mtime/权限/随机/env/时钟；
- **跨 workspace/共享安全层改动**：本片**零需求**（组件子 workspace 构造 = 现有 `RepositoryWorkspace(root)` 公共入口的合法使用）；若 D2/实现期发现必须改 `lima/workspace.py` 才能表达的语义 → 停止并单列 DR（附调用链与理由），F3 路线归 #60-CLOSURE-C。

#### 5.7.1 fixture 口径约束（冻结）

- 新 fixture（`tests/audit/fixtures/monorepo/shapes.py`）文本写入一律 `newline="\n"` 钉死 LF（PI-DR1）；路径断言用 POSIX 字面量；
- **扩展名集合显式声明**：monorepo fixture 仅含 `.py` 文件 + manifest 文件名（pyproject.toml / setup.py / requirements*.txt 等，经 manifest 候选读取通道，不依赖 inventory 扩展集）；不含 C++/构建类扩展文件、不含 CRLF 文件、不含秘密形态文件名（隐私负例在专用用例内构造，marker 型副作用文件仅存在于测试临时目录）；
- fixture 构造沿用 `repo_shapes.workspace_with` 模式（临时目录 + `RepositoryWorkspace`，零网络零执行）。

### 5.8 安全基线（Assignment §六 末段；全程）

- 不执行/不 import/不安装目标项目（AST 断言 + 行为负例：恶意 setup.py marker 文件不存在）；`ast.parse` 先例（IP-0016）；
- 模块静态断言：零网络 import（socket/urllib/requests/http）、零 subprocess、零 os.environ、零文件写；
- 路径 100% repo-relative POSIX（仓库级或组件内相对坐标，均无 host path/盘符/绝对路径形态）；evidence/imported_name/manifest path 无源码正文、无 secret 值；
- **秘密形态文件名准入**（NFR-01 五面口径延续）：进入 `unassigned_files` 与 `EdgeEvidence.path` 的路径先过 `is_secret_shaped_path`（公共导入自 inventory）——命中者不入列表（计数保留），图 coverage_gaps 加 `INVENTORY_SKIPPED`（detail `reason=sensitive-filename; count=N`，R1 终案公开面 reason→count）；内部 family 级逐项留痕属 CLOSURE-D FR-01 全 vocabulary 范围，本片不扩；
- fail-closed 与有界读取：全部入参类型/值校验抛 `ContractError`/`ValueError`，绝不静默纠正；读取一律经 workspace 有界通道。

---

## 6. 测试矩阵（D2 冻结计划：FR→AC→T→预定测试符号；本阶段不写测试文件）

新增测试方法预算 **33**（≤35 规划起点，无需超额解释）。回归锚（contracts 617 / audit 235 / 五形态 golden 零改动 / DR-LINT-0022-A 六处恰存）经命令覆盖（§8），不计入新增方法数。

| # | 类别（方法数） | 预定测试符号（`test_file::test_symbol`） | 断言要点 | 追踪 |
|---|---|---|---|---|
| 1 | 组件识别（6） | `test_component_graph.py::test_detect_components_manifest_anchor` | 多组件 fixture：components/component_id/root_dir/manifests（kind 枚举）/排序 | V5-FR-03、AC-01 |
| 2 | | `…::test_detect_components_same_dir_multiple_manifests` | 同目录 pyproject+setup.cfg 归并单组件，manifests 两条 | V5-FR-03 |
| 3 | | `…::test_detect_components_root_only_and_zero_component` | 仅根 manifest → 单组件零边；零 manifest → components=() + unassigned 计数 | V5-FR-03、边界 |
| 4 | | `…::test_detect_components_unassigned_files` | 根无 manifest 时散 .py 落 unassigned（列表排序 + count）；归属证据不足不编造组件 | AC-01、三态 |
| 5 | | `…::test_detect_components_empty_component` | 有 manifest 零 .py → is_empty=True 如实保留 | V5-FR-03 |
| 6 | | `…::test_detect_components_max_components_truncation` | 17 组件 fixture（显式 budgets=16）：前 16 构建 + BUDGET_EXHAUSTED gap（reason=component-limit; count=1）+ truncated/dependencies_complete=False | 预算 fail-closed |
| 7 | 每组件三段复用（3） | `…::test_monorepo_profile_per_component_chain` | 每组件 profile/ram/semantic 产物存在、三段 provenance_anchor_ids 逐层正确、六 ID 透传后各 envelope content_digest 互异 | V5-AC-02 后半句、AC-01 |
| 8 | | `…::test_monorepo_profile_component_path_coordinates` | 组件产物路径=组件内坐标；图 evidence/unassigned 路径=仓库级坐标（前缀 root_dir 复算） | NFR-01、AC-01 |
| 9 | | `…::test_monorepo_profile_semantic_off_default` | 默认零模型调用：每组件 SEMANTIC_MODEL_OFF gap（继承）；graph digest 与 semantic off 状态无交叉污染 | AC-02 复验、FR-03 |
| 10 | 边三态（6） | `…::test_edge_resolved_absolute_import` | 组件 A `from b_pkg import x` → resolved 边 (A→B)，evidence{path,line,imported_name} | V5-FR-03、AC-01 |
| 11 | | `…::test_edge_resolved_relative_import_cross_component` | 组件 A 内 `from ..b_pkg.y import z` 解析落 B 子树 → resolved | AC-01（相对导入） |
| 12 | | `…::test_edge_ambiguous_duplicate_module_names` | 两组件均有顶级目录 `utils`，第三方组件 `import utils` → target=None + status=ambiguous；不向候选逐个画边 | AC-01（重复模块名） |
| 13 | | `…::test_edge_unresolved_relative_import_missing_target` | 相对导入目标 .py/`__init__.py` 均不存在 → unresolved | AC-01（未解析） |
| 14 | | `…::test_edge_external_and_internal_imports_no_edge` | `import os`/`import fastapi`（外部）与组件内自环 → 无边；不产 gap（"未看见"不产边） | V5-FR-03 |
| 15 | | `…::test_disconnected_and_empty_components_present` | 无边组件=孤立节点如实存在；edges 无引用；不编造 | V5-FR-03（断开组件） |
| 16 | 确定性与排序（4） | `…::test_determinism_two_builds_equal` | 同快照两次构建：graph digest 相等 + 全字段相等 + 每组件三 digest 相等 | AC-01（可重放）、FR-04 复验 |
| 17 | | `…::test_input_order_invariance` | 同内容不同写入顺序的两个快照目录 → digest 相等（目录枚举顺序无关） | AC-01（确定性） |
| 18 | | `…::test_canonical_ordering_components_edges_evidence` | components 按 component_id、edges 按 (source, status, target-or-empty, imported_name)、evidence 按 (path, line, imported_name) 排序断言 | AC-01 |
| 19 | | `…::test_graph_digest_hex64_and_scope` | digest 64-hex；canonical dict 不含 digest 自身/时钟；改变任一组件归属或边 → digest 变化 | FR-04 复验 |
| 20 | monorepo golden（3） | `test_monorepo_golden.py::test_golden_monorepo_payload` | monorepo fixture 全链 payload == golden JSON（组件+边+digests+identity）逐字段 | AC-01 monorepo 维度、V5-AC-01 |
| 21 | | `…::test_golden_monorepo_topn_replayable` | 两次独立构建：component_graph_digest 相等 + 每组件 semantic ranked candidate_id 序列逐位相等（Top-N 可重放） | AC-01（Top-N 可重放） |
| 22 | | `…::test_golden_monorepo_provenance_chain` | 图 anchor=("component-graph",) + 每组件三段 anchor 链 + manifests provenance | AC-01（provenance） |
| 23 | 预算与 fail-closed（3） | `test_component_graph.py::test_budget_caps_edge_and_evidence_and_unassigned` | max_edges/max_edge_evidence/max_unassigned_files 超限 → 截断 + 三类 BUDGET_EXHAUSTED gap（detail reason/count）不静默 | 预算 fail-closed |
| 24 | | `…::test_invalid_inputs_fail_closed` | 非 RepositoryWorkspace / 坏 budgets 值（0/负/非 int）/ 非 str 六 ID / 空 digest → ContractError/ValueError | fail-closed |
| 25 | | `…::test_monorepo_budgets_invariants` | MonorepoBudgets 默认值（16/4096/64/256）+ 构造期正值校验 | 预算单解 |
| 26 | 隐私与 no-execution（4） | `…::test_secret_shaped_filenames_excluded` | `secrets/x.py` 形态文件名不入 unassigned/evidence；INVENTORY_SKIPPED gap reason→count | NFR-01（R1 终案） |
| 27 | | `…::test_no_host_path_or_source_text` | payload 全文搜索 host root/盘符/源码行非平凡子串 → 零命中 | NFR-01 |
| 28 | | `…::test_no_execution_marker_absent` | 恶意 setup.py/import side effect fixture：构建前后 marker 文件不存在 | NFR-02 清单层复验、V5-FR-04 |
| 29 | | `…::test_static_no_network_no_env` | AST 断言模块零网络/subprocess/os.environ/文件写 import | V5-FR-04 |
| 30 | wire 契约（4） | `…::test_validate_payload_positive` | 五形态无关的正例（monorepo payload）validate 通过 + schema 文件加载 const/required 自洽 | FR-04 复验 |
| 31 | | `…::test_validate_payload_negative_unknown_field` | 未知顶层/嵌套字段 → ContractError(UNKNOWN_FIELD) | fail-closed |
| 32 | | `…::test_validate_payload_negative_enums_and_digests` | 枚举外 status/manifest_kind、非 64-hex digest、target 与 status 组合违规（resolved+null / ambiguous+非 null）→ ContractError(INVALID_FIELD_VALUE) | fail-closed |
| 33 | | `…::test_validate_payload_negative_ordering` | components/edges/evidence 排序违规、is_empty 与 count 矛盾、unassigned count < len(list) → ContractError | fail-closed |

PI-DR 落实：PI-DR1（LF 钉死/POSIX 断言/零平台权限依赖）；PI-DR4 模块缺席 RED 锚（新测试 import `lima.audit.component_graph` 失败即天然 RED）；PI-DR6 冻结前非 Windows 平台完整跑一次并记录 run SHA 与结论；PI-DR5 PR 禁自动关闭关键字。

## 7. AC traceability（正向+反向 100%）

| Requirement | 本 IP 贡献声明 | Test（§6 #） |
|---|---|---|
| V5-FR-03（前半句：monorepo 输出 component graph） | 组件识别 + 边三态 + 独立承载 + 每组件三段 | #1-#15、#30-#33 |
| AC-01/T-01（monorepo/重复模块/相对导入维度：provenance + Top-N 可重放） | golden + 边三态 + 确定性 | #10-#22 |
| V5-AC-01/V5-T-01（monorepo 维度：Profile/roles/support/execution capability/gap） | 每组件 Profile 全字段（复用 IP-0016 规则） | #7-#9、#20-#22 |
| V5-AC-02/V5-T-02（后半句：monorepo 按 component 生成 profile/RAM） | `build_monorepo_profile` 每组件全链 | #7-#9 |
| FR-02/03/04/NFR-01（组件维度复验） | 复用三层公共接口逐组件重放 | #7-#9、#16-#19、#26-#29 |
| 预算/安全基线 | 聚合上界 fail-closed + 隐私/no-execution | #6、#23-#29 |

反向：§6 每个测试符号唯一指向上表行（D2 冻结时以 `test_file::test_symbol` 表落档）。本 IP 不宣称：AC-01 整体满足（非 monorepo 五形态外的全部维度）、V5-FR-03 后半句（安全停止）、T-03 端到端、#64/#68 消费。

## 8. 验收命令（Done Commands；D2/Implementation/验证共用，全部在交付 worktree 根执行）

```text
# slice（新增用例全绿，0 skip）
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

**平台实跑计划**：Windows 本机（RED/GREEN + 上述全组）；**PI-DR6**——D2 冻结前在非 Windows 平台（GitHub Actions Linux runner，临时验证分支 workflow_dispatch，先例 `pv/ip-0022-freeze-pidr6` run 34826215469）完整跑一次新增测试集，记录 run SHA 与结论入 Frozen Test Commit 记录；安全关键用例不得用 skip 充当 PASS。

**Post-merge**（Coordinator 指令后）：上述 mandatory 全组在最新 origin/main 复跑，输出 `POST-MERGE PASS/FAIL`。

## 9. Stop Conditions / Decision Request

1. 组件识别需跨 manifest/路径组合证据而现有公共承载（workspace 只读 inventory + read_text）无法表达 → Contract Gap 停点，提 DR（选项+推荐+兼容影响+草案），不发明扩展字段；
2. 任何需要修改 `lima/workspace.py`、`lima/contracts/**`、三层+ram_schema 冻结面、既有 tests/audit 文件、schemas/v4 既有 15 文件才能满足本 Packet 的情形 → 停点（共享层改动单列 DR 附调用链与理由；F3 路线归 #60-CLOSURE-C）；
3. 触及冻结约束的新设计（54 帽扩帽、digest 家族语义、GAP 码新增、execution_required 语义、#58 字段、v4 schema/旧 golden 期望值）→ 具体 DR 获批前不实现、不留 TBD 空位；
4. 与 #266/#281 出现文件或语义冲突迹象（含远端分支前移触及 #60 敏感路径）→ 停止上报 Coordinator；
5. 基线前移：开工时已核验 fbbbd619 未前移；后续阶段（D2/Implementation）开工时重新 `git fetch origin`，前移涉冻结产品面/共享输入层/Contract·fixtures → 按批复 §四分类补核验，涉 #60 敏感路径上报复核后开工；
6. 回归计数与基线锚（617/235/3006+24skip）不符 → 按实际覆盖变化与失败内容判断（addendum-2 §3 修订版）：新增/消失用例须可追溯到对应轨道提交与理由，计数变化不单独构成停点；真实失败（RED 非预期、冻结面用例失败、语义回归）按停点纪律上报；**不得删测试/改 Oracle/改期望值追平数字**；
7. 实现期发现需改冻结测试 → 先 Decision Request（缺陷证据+影响面+建议方案），获授权后走 Packet 修订 → 撤销旧冻结 → 重新 RED → 新 Frozen Test Commit；禁止同提交悄悄修测试；
8. IP-0023 编号被对端轨道登记占用（ALLOC 失效条款）→ 停止上报（顺延 IP-0044 需 Coordinator 重四查 + Maintainer 报备）。

## 10. 回滚与兼容影响

- **纯新增交付**：产品面恰 2 新文件（component_graph.py + lima.component-graph.json），测试面 5 新文件；零修改既有任何文件（含 `__init__.py`）⇒ 回滚 = revert 单个实现 PR，无迁移、无数据兼容问题；
- **旧消费者零影响论证**：54 帽原样、六 digest 原样、GAP 10 码与 9 码触发原样、#58 契约零改动、v4 schema 既有 15 文件与 matrix 零改动、五形态旧 golden 期望值零改动、错误目录既有码值零改动——既有消费路径（单仓 Profile/RAM/semantic/RAM wire）行为逐字节不变（tests/audit 235 + tests/contracts 617 + golden 全绿为证）；
- **schema 版本共存**：`lima.component-graph.json` 独立版本 `"1.0"`、不注册 matrix——旧消费者（matrix 驱动的兼容矩阵消费方）不可见该文件，无版本协商负担；未来注册属 BG-60-01 口径（Maintainer 另决 + DR）；
- **回滚不降低门禁**：不涉及 Evidence Level/Gate/raw-secret/FULL_CHAIN 任何维度（本片纯新增，无既有行为迁移）。

## 11. 危险与失败矩阵（危险输入 × 失败模式处置表）

| 危险输入 | 失败模式 | 处置（承载/行为） | Test |
|---|---|---|---|
| 空仓库 / 零 manifest | 无组件边界证据 | components=()、edges=()、unassigned 计数如实；不报错、不编造"无依赖"结论 | #3 |
| 无 Python 文件的 manifest 子目录（空组件） | 组件存在但零内容 | is_empty=True 保留节点 | #5 |
| ≥17 组件（超 max_components） | 聚合放大风险 | 前 16 构建（component_id 序）+ BUDGET_EXHAUSTED gap + dependencies_complete=False | #6 |
| 两个组件同名顶级包（重复模块名） | import 目标不唯一 | ambiguous 边（target=None），不向候选逐个画边 | #12 |
| 相对导入越界/目标缺失 | 解析失败 | unresolved 边（target=None） | #13 |
| 组件内动态 import | 静态不可解 | 不产边；组件 RAM DYNAMIC_IMPORT gap 继承（三层承载，图不复制） | #9（语义复验） |
| 恶意 setup.py / import 副作用 | 执行风险 | 零执行（ast.parse / 存在性检查）；marker 负例 | #28、#29 |
| 秘密形态文件名（secrets/x.py 等） | NFR-01 泄漏 | is_secret_shaped_path 准入：不入 unassigned/evidence 列表；INVENTORY_SKIPPED gap reason→count | #26 |
| CRLF 文件 | 行号口径漂移 | 行号按保留 CRLF 原文计算（当前 workspace 口径）；fixture 全 LF | （口径断言并入 #16/#17） |
| symlink .py / 二进制 / 超大文件 | workspace 跳过 | 继承组件 RAM INVENTORY_SKIPPED/BUDGET_EXHAUSTED gap（既有通道） | （回归锚） |
| manifest 解析失败（TOML 语法错） | 组件元数据未知 | 组件 Profile 构建继承 MANIFEST_PARSE_ERROR（manifest-index 稳定标识）；组件层不新增来源 | （回归锚 + #7 链路） |
| 非 workspace 入参 / 非法预算值 / 空 digest | 类型违约 | ContractError/ValueError fail-closed，绝不静默纠正 | #24、#25 |
| 边/evidence/unassigned 超量 | 无界放大 | 三类 cap + typed gap（count 如实），无静默截断 | #23 |
| payload 篡改（未知字段/枚举外/坏 digest/乱序） | 契约违约 | validate_component_graph_payload 一律 ContractError | #30-#33 |
| 目录枚举顺序不定 | 结果漂移 | 全枚举入口 sorted；输入顺序不变性断言 | #17 |

## 12. Completion Summary / PR contract

- Completion Summary 必含：base/final commit、修改文件与公共符号清单（§5.4.7 的 `__all__` 逐项）、AC→Test→Result 表（§7 + §6 符号）、§8 全部命令实际输出与统计（含计数与退出码）、schema 与 golden 文件 SHA-256、文件边界自查（`__init__.py` 未改动证明）、已知限制（monorepo golden 单形态、Python-only 组件边、安全停止/T-03 归 B/C、FR-01 全 vocabulary 留痕归 D）；
- Implementation PR：`Implements IP-0023` + `Related to #60`；正文含 Packet merge commit、Frozen Test Commit、covered/not-covered（§0）、AC 矩阵、命令实测、Verdict、`This PR does not auto-close the Source Issue.`；**禁止** close/fix/resolve 与 #60 组合（PI-DR5）；
- Packet docs PR（主会话在 Coordinator readiness 复核通过后执行）：docs-only，恰含本 Packet 一个新文件，`Related to #60`，禁自动关闭关键字；合并批准逐项请求 Maintainer。

## 13. Packet 完成定义与 Open Decisions

- 本 Packet 关键 TBD 数 = 0；`READY-FOR-CODE` 当且仅当：本文档合并进 main（Coordinator 标 `PACKET-MERGED`）且 D2 按 §6 计划完成有效 RED 与 PI-DR6 双平台记录；
- **Open Decisions：无**。需要产品/冻结面决定的唯一候选项（"`lima.audit` 命名空间追加 re-export 即扩 54 帽"）已按"默认不扩帽 + 备选 DR 草案随交接报告呈 Coordinator、不进实现范围"处置，不构成本 Packet 的 TBD；BG-IP-0016-01 / BG-60-01 / DR-LINT-0022-A 维持 OPEN 状态归置权在 Coordinator（分别在 §5.4.4/§5.5/§8 引用，本片不清偿不扩大）；
- 后续阶段（D2 冻结测试、Implementation、独立验证、ER、合并、post-merge、IP-DONE）均未授权，另行 Assignment。

---

## 附：本 Packet 制作证据摘要（D1，全部本轮亲验）

- 基线：`git fetch origin` 后 `origin/main = fbbbd619fb0b96efbbb903916ab46dc0daed2214`（`rev-list fbbbd619..origin/main` = 0，未前移）；worktree `D:/BaseAIProject/LIMA-60-closure-a-pv-wt`（分支 `codex/ip-0023-monorepo-packet`，HEAD=基线，`git status --porcelain` 为空）；
- Assignment SHA-256 重算一致（`5a118ea9…73b82`）；恢复审计 v1/addendum-1/addendum-2 与批复正文 SHA-256 全部重算一致（§2 DI-007/DI-008）；
- Issue #60 live 亲取：state=open、updated_at=2026-10-09T06:37:15Z、comments=10、labels 含 status:in-progress、body SHA-256 `477ad50c…f8180`（与 PUBLISHED-INDEX 远端发布登记逐字节一致）；
- 冻结面只读核对（import 亲验，零目标项目执行）：§3.1 全部签名/常量/默认值（`__all__` 54 项、GAP 10 码/9 触发、三层 build_* 签名、RamBudgets/SemanticBudgets 默认、candidate_id 冻结编码、AdmissionSkipRecord、is_secret_shaped_path 段级行为）；workspace.py（DEFAULT_EXTENSIONS/FILENAMES/read_text CRLF/fingerprint/line_count）；#58（encode/decode_profile_envelope、_validated_extensions、RepositoryKind.MONOREPO、ArtifactEnvelope.content_digest、ContractError 三码）；schemas/v4 15 文件清单；五形态 golden + repo_shapes helper 清单；test_ip_0022_fix.py 51 例；`scripts/run_ci_tests.py` 存在；IP-0024 Packet §0.1（IP-0023 预留勘正）亲读；
- 本阶段未执行：产品代码/测试/schema 修改、全量产品测试重跑（按 Assignment §Acceptance 6，文档阶段基线数字引用恢复审计 §5 真实输出）、远端写、冻结（D2 另行）。
