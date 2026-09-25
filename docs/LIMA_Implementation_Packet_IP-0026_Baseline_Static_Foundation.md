# LIMA Implementation Packet — IP-0026 Baseline Static Foundation（冻结支持矩阵 + manifest v1 落盘）

> Packet ID：IP-0026
> Packet 版本：1.0（2026-09-25，阶段 P / C1 单次提交，不回填）
> 状态：**PHASE-P-IN-PROGRESS**（阶段 P 进行中；C2 冻结测试完成后，READY-FOR-CODE 由 Draft PR 正文与
> #210 Delivery Ledger 反映——SHADOW 模式无真实合并，影子证据锚点 = commit SHA 链）
> Packet 作者：lima-packet-verification（P&V）
> Coordinator Assignment：CA-IP-0026-v1.0（2026-09-25；本 Packet 的约束权威，R1-R8 全文照录登记于 §11）
> 精确基线：`89cbfc49cde7da448682e82d132fd0afbb7c827c`（完整 40 位 = origin/main，亲验）
> 工作分支：`codex/ip-0026-baseline-matrix`（worktree `D:\BaseAIProject\LIMA-ip0026-wt`）
> Source Issue：#210（叶子，开放）；Parent #57 仅背景，保持打开
> Frozen Test Commit：C2（本 Packet 提交后由 P&V 产生；精确 SHA、RED 证据与验收面摘要登记于 C2 commit
> message 与 P&V 阶段 P 交付记录，本文件按"单次提交"纪律不回填）

---

## 0. 交付物角色声明（强制，先于一切）

本切片的"实现产物"是**两个 JSON 数据文件**，不是 Python 产品代码：

- `evaluation_data/v4/baseline_manifest.json`
- `evaluation_data/v4/python_mvp_support_matrix.json`

**二者是 Implementation（阶段 I / IP-0026-IMPL）的实现交付物，不是 P&V fixture。**
P&V 的交付物只有本 Packet（C1）与 `tests/test_v4_baseline_manifest.py`（C2 Frozen Test Commit）。
"冻结验收面不可改"不得被扩写为"这两个 JSON 不可写"——它们是本轮被验收的产品本体。
（依据：Assignment R1"数据产物是合法实现交付"；责任书 §2"区分两类产物"。）

本轮**零 `lima/` 产品代码**（R1）：无 manifest 加载封装、无矩阵常量模块、无 CLI。若实施中发现"必须加
`lima/` 代码才能满足验收"：停止，提交 Decision Request，不得静默新增。

## 1. 需求映射（Packet 头）

```text
Source Issue：#210（父 #57）
Issue specification revision：2026-09-25 创建版正文（GitHub API 亲验，含 Scope 1-9、Non-goals、AC-1..AC-4、Packet 段）
Covered requirements：FR-01…FR-09、AC-1…AC-4（本切片全范围）
Not covered requirements：见 §4 Non-goals（= Assignment Not-covered 全文照录）
Delivery role：foundation（#57 PR1 静态基础收敛）
Issue closure impact：PARTIAL（#210 按 Ledger 走 MANUAL-AFTER-POST-MERGE-AUDIT；本 IP 不宣告任何 Issue 完成）
Upstream IP/merge commits：IP-0024（lima/baseline_run_spec.py，PR #205 链）、IP-0025
  （lima/baseline_run_result.py，PR #207 链）——均在基线 89cbfc4 内冻结，本轮只消费
```

FR-01..FR-09 为 Coordinator 对 #210 "Scope (this slice)" 1-9 的规范化编号（语义不变）；
AC-1..AC-4 沿用 Issue 原文编号（登记于 #210 Delivery Ledger 草案）。

| ID | 内容（#210 Scope 1-9） | 本 Packet 贡献方式 |
|---|---|---|
| FR-01 | 冻结 Python MVP 支持矩阵（三级分级） | 矩阵 JSON 产物（§7.2 schema）+ 结构测试 |
| FR-02 | 每项理由/边界/证据指针 | capability 条目必填 `reason`/`boundary`/`evidence`（§7.2.2） |
| FR-03 | manifest v1 落盘并消费 BaselineRunSpec/validate_baseline_manifest | manifest JSON 产物（§7.1）+ 正例经冻结契约校验（R6：spec 于测试 arrange 内构造，不落盘） |
| FR-04 | 完整不可变 commit SHA，branch/tag/缩写 fail closed | 产物级 40 位小写 hex 不变量 + spec 层负例（复用 #204 冻结语义） |
| FR-05 | 来源/许可/角色/fingerprint/固定身份 | dataset 级 `source`/`license`/`pinned_file` + name + fingerprint（§7.1.4） |
| FR-06 | 正例 + fail-closed 负例 | C2 测试矩阵（§8）：正例 1 组 + 逐错误码负例面 |
| FR-07 | 只复用仓库内已冻结数据 | R3 登记集合强约束（§7.1.1）；排除文件 registration note；LlamaFactory 不入 manifest（R4） |
| FR-08 | 证据不足 archetype 登记 coverage gap | coverage_gaps 数组 + 三项必需 gap key（§7.2.3） |
| FR-09 | calibration 不重宣称为 external holdout | R3 角色绑定 + M12 一致性测试（v1 holdout 五身份仅以 calibration 面目出现） |

| ID | 内容（#210 验收） | 验证方式 |
|---|---|---|
| AC-1 | 矩阵存在且逐项含级别/理由/边界/证据；LlamaFactory、空仓、最小 Python 仓及 4 个排除文件诚实登记 | `tests/test_v4_baseline_manifest.py` TestSupportMatrixArtifact |
| AC-2 | manifest 正例通过 + 冻结负例面 fail closed 且错误码一致 | TestBaselineManifestArtifact + TestSpecLayerFailClosed + TestManifestValidationFailClosed |
| AC-3 | 全部验证离线（无网络/无 Secret/无付费） | 测试源离线自扫描（镜像 #204 冻结先例）+ stdlib-only 模块级 import |
| AC-4 | IP-0024/IP-0025 冻结面与 frozen holdout 零字节变化 | File Boundary Gate（§9 命令 5；本轮对任何已跟踪文件修改量为 0） |

## 2. Design Input Manifest

| Input ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001 | Standard | `docs/LIMA_PACKET_AND_VERIFICATION_AGENT_RESPONSIBILITY_CHARTER.md` | 基线 89cbfc4 内版本 | P&V 角色边界、Packet/冻结/RED/Pre-Freeze Harness Gate 规则 | normative | 无冲突 |
| DI-002 | Issue | Source Issue #210 正文（2026-09-25 创建版：Scope 1-9、Non-goals、AC-1..AC-4、Packet 段） | Coordinator GitHub API 亲验转述于 Assignment | FR-01..FR-09、AC-1..AC-4 | normative | 无冲突 |
| DI-003 | Issue | Parent #57（PR1/PR2/PR3 切分、FR-06 LlamaFactory `7fcf5b3b130e5713b52415bb7404c476fada9c8c` needs-decision 防线） | 基线 89cbfc4（Assignment 亲验） | R4 处置依据、Not-covered 边界 | background / 边界 normative | #57 FR-06 要求执行期物化；本切片静态登记身份（R4），不执行 |
| DI-004 | Decision | CA-IP-0026-v1.0 全文（R1-R8、Allowed Files、验收命令、Stop Conditions、ALLOWED_ONCE） | 2026-09-25 | 本切片全部边界 | normative（本切片最高活动权威） | 与历史文档冲突时以 Assignment 为准 |
| DI-005 | Intent | `.pv_tmp/INTENT_RECORD_IP-0026_2026-09-25.md`（M1-M17、I1-I7、S1-S5，READY-FOR-COORDINATOR） | 2026-09-25 | 需求语义、技术偏好、离线/诚实性不变量 | normative（经 Assignment 消费） | 无冲突 |
| DI-006 | Code | `lima/baseline_run_spec.py`（BaselineRunSpec L576、from_mapping L629、load_baseline_run_spec L654、validate_baseline_manifest L672-752、角色枚举 L73、SHA 分级拒绝 L384-395、错误码 L86-101、manifest 交叉校验 L729-752） | 基线 89cbfc4（本轮亲读全文） | FR-03/FR-04/FR-06 消费对象 | normative（冻结契约，只读） | 无冲突 |
| DI-007 | Code | `tests/test_v4_baseline.py`（70 方法；负例语义先例 L505-600、L635-723、L879-895；离线源扫描先例 L239-249；fixture license/source 额外字段先例 L97-155） | 基线 89cbfc4（本轮亲读全文） | 负例面语义复用、测试风格对齐、额外字段先例 | normative（冻结测试，只读，禁止任何修改含追加，R5） | 无冲突 |
| DI-008 | Data | `evaluation_data/` 8 个冻结文件（README.md + 7 数据文件） | 基线 89cbfc4（本轮亲读 3 个入册文件全文 + 4 个排除文件头部与程序化事实核验） | R3 登记集合、fingerprint 重算、条目逐字转录、registration note 事实 | normative（冻结数据，只读） | 无冲突 |
| DI-009 | Decision | IP-0024 Packet（`docs/LIMA_Implementation_Packet_IP-0024_BaselineRunSpec.md` L37-41："生产 manifest 落盘与真实样本清单（D-4 选 A，#57 PR1）"显式推迟到本切片） | 基线 89cbfc4 | 授权链连续性证明（无契约真空） | normative（历史决策） | 无冲突 |
| DI-010 | Finding | 本轮 P&V 亲验（worktree @ 89cbfc4）：三入册文件 SHA-256（§7.1.3）；三数据集 13 身份两两不相交；security_repair_cases.json 18 案例 0 个含 repository 字段；pr_diff_100.jsonl 100 记录 0 条含 40 位 pinned SHA；冻结回归 `python -m unittest tests.test_v4_baseline` → Ran 70 / OK（exit 0）；`.gitattributes` = `* text=auto eol=lf` | 2026-09-25 | 指纹登记值、registration note 理由事实、RED 前基线绿、跨平台指纹稳定性 | evidence | 无冲突 |
| DI-011 | Standard | `docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md`、`docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md` | 基线 89cbfc4 | 交付流程、Completion Summary、PR 文案约束 | normative（流程） | 无冲突 |

## 3. Explicitly Rejected Inputs

1. **任何 `lima/` 产品代码**（manifest 加载封装、矩阵常量模块、CLI 接线）——R1 裁定零产品代码；
   出现该需求即触发 Stop Condition。
2. **LlamaFactory `7fcf5b3b130e5713b52415bb7404c476fada9c8c` 进入 manifest v1**——R4：仓库内无该冻结数据
   来源（evaluation_data/ 与 tracked 文档均无命中），为其发明 dataset 条目即虚构数据源；其身份只在矩阵
   coverage gap 条目静态登记。
3. **popular_external_holdout.json（v1）或 popular_external_calibration_v2.json 入 manifest**——R3：家族
   身份已分别以 calibration / external-holdout 角色登记，双登记触发冻结 `DATASET_ROLE_CONFLICT` 且违背
   "holdout 已消费"重分类事实。
4. **security_repair_cases.json / pr_diff_100.jsonl 入 manifest**——R3：纯合成约束集无 repository 字段 /
   synthetic-controlled 无 pinned SHA（亲验 DI-010），无法满足 M6 完整不可变 SHA。
5. **持久化 BaselineRunSpec JSON 或 machine profile 工件**——R6：本切片排除任何执行，落盘从未运行的
   spec 制造运行身份过度声明；spec 只在测试 arrange 内构造。
6. **新增数据/数据集/fixture 创作**（空仓、最小 Python 仓样本等）——M10/M13 只允许复用既有冻结数据，
   无冻结数据的 archetype 登记 coverage gap，不现场造样本。
7. **对 `tests/test_v4_baseline.py` 的任何形式修改（含追加测试）**——R5：IP-0024/IP-0025 冻结面，AC-4
   要求字节不变；追加会破坏冻结 digest 与 RED 证据链。所有新测试进新文件。
8. **`evaluation_data/README.md` 或任何既有 evaluation_data/ 文件的修改**——产物文档说明写入本 Packet
   与产物自身字段。
9. **fixed_commit 数据同表登记**——R3 条目转录规则：commit_sha 统一取 vulnerable_commit（分析基线
   语义）；fixed_commit 仍在冻结文件中，受同身份不重复规则约束无法同表登记（本 Packet 记载该边界）。

## 4. Goal / Non-goals

**Iteration hypothesis**：#57 PR1 的静态基础可以完全由"两个 JSON 数据产物 + 一个冻结测试文件"交付：
manifest v1 作为冻结契约 `validate_baseline_manifest` 的第一个生产级输入通过正例；支持矩阵以机器可校验
JSON 落盘并对无证据 archetype 诚实登记 coverage gap；全部验证离线可复现。
**measurement** = C2 冻结时有效 RED（产物缺席 fail closed，28 方法全失败且逐条归因产物缺失）→
阶段 I 落盘产物后定向全绿 + 冻结回归 70 全绿 + `git diff` 相对基线恰为 4 个 Allowed Files。

**Goal**：(a) 冻结 Python MVP 支持矩阵（三级分级、逐项理由/边界/证据指针、coverage gap 诚实登记）；
(b) 落盘 baseline manifest v1（完整不可变 40 位小写 SHA、来源/许可/角色/fingerprint/固定身份齐全），
经冻结契约正例通过 + fail-closed 负例；(c) 离线、无 Secret、无付费模型的验证方式。

**Non-goals**（照录 Assignment Not-covered）：baseline 执行 CLI；真实仓库扫描；cold/warm 执行编排；
指标采集；CPU/RSS/IO/Token/费用/人工时间遥测；LlamaFactory 真实 replay；报告生成系统；Prompt、分析器、
标签、评分或 split 修改；frozen holdout 修改或角色重分类；网络下载；产品扫描路径接线；#57 其余
PR2/PR3 内容；新增数据/数据集/fixture 的创作；任何 `lima/` 产品代码；持久化 BaselineRunSpec /
machine profile 工件；修改 `evaluation_data/README.md` 或任何既有 `evaluation_data/` 文件。

## 5. 冻结接口消费清单（本轮只消费，零改动）

来源 `lima/baseline_run_spec.py` @ 89cbfc4（行号为该 SHA 亲读）：

| 接口 | 消费方式 |
|---|---|
| `from_mapping(mapping)`（L629） | 测试 arrange 内由落盘 manifest 值 + 名义 machine_profile 构造 spec（R6）；spec 层负例的构造入口 |
| `validate_baseline_manifest(manifest, spec)`（L672-752） | manifest 正例 + 深拷贝变异负例（逐错误码断言） |
| `BaselineRunSpecError` / `BaselineRunSpecErrorCode`（L86-143） | 全部负例断言 `caught.exception.code` 与冻结码逐一相等 |
| 角色枚举 `_DATASET_ROLES = ("external-holdout", "calibration", "development")`（L73） | manifest dataset role 必须取自该枚举 |
| commit SHA 分级拒绝（L384-395） | spec 层负例：7-39 位 hex → `ABBREVIATED_COMMIT_SHA_REJECTED`；branch/tag/40 位大写 → `MOVING_REF_REJECTED`；40 位非 hex → `INVALID_COMMIT_SHA` |
| fingerprint 形态 `[0-9a-f]{64}`（L75、L368-373） | `INVALID_FINGERPRINT` 负例 + 产物级 fingerprint 重算断言 |
| manifest 必填 `name/fingerprint/role/entries` + entry 必填 `repository/commit_sha`（L55-56、L702、L716） | `REQUIRED_FIELD_MISSING` 负例 + 产物结构断言 |
| 额外字段容忍（L678-679；先例 tests/test_v4_baseline.py L133-155、L716-721） | dataset 级 `source`/`license`/`pinned_file` 与 entry 级附加字段的合法性 |
| manifest 交叉校验（L729-752）：同名同 fingerprint、holdout×calibration 交叉、同身份跨条目重复、spec 仓库 SHA 一致 | `DATASET_FINGERPRINT_MISMATCH` / `DATASET_ROLE_CONFLICT` / `DUPLICATE_REPOSITORY` / `MANIFEST_IDENTITY_CONFLICT` 负例 |

## 6. 文件边界（= Assignment Allowed Files，逐字对齐）

**新增 — 阶段 I（Implementation 交付物，数据产物即本切片的合法"产品"）：**

1. `evaluation_data/v4/baseline_manifest.json` — baseline manifest v1 生产工件（实现产物）。
2. `evaluation_data/v4/python_mvp_support_matrix.json` — 冻结支持矩阵 + coverage gap + 登记备注（实现产物）。

**新增 — 阶段 P（P&V 冻结物）：**

3. `tests/test_v4_baseline_manifest.py` — 本轮唯一新测试文件（manifest + matrix + 一致性 + 离线卫生，单文件）。
4. `docs/LIMA_Implementation_Packet_IP-0026_Baseline_Static_Foundation.md` — 本文件。

**修改：无。** 本轮对任何已跟踪文件的修改量必须为 0（AC-4 与 R1 的直接推论）。

**Read-only**：`lima/baseline_run_spec.py`、`lima/baseline_run_result.py`、`tests/test_v4_baseline.py`、
`evaluation_data/` 全部既有 8 文件（含 README.md）、`scripts/run_ci_tests.py`（unittest discover 自动纳
入新测试文件，无需改动）。

**Do Not Touch（Forbidden）**：`lima/` 全目录；`scripts/`、`frontend/`、`.github/`、`pyproject.toml`、
`requirements.txt`、`.gitattributes`；冻结面三文件；`evaluation_data/` 既有文件；GitHub Issue/PR/LABEL
远端状态（既授权 Draft PR 与 #210 Ledger 写入除外）；`PROGRESS.md`；他人 Issue；#57/#60。

**Symbol-to-File Map**：无产品符号（零产品代码）。manifest schema → `evaluation_data/v4/baseline_manifest.json`；
矩阵 schema → `evaluation_data/v4/python_mvp_support_matrix.json`（schema 冻结于本 Packet §7 与 C2 测试）；
冻结验收测试 → `tests/test_v4_baseline_manifest.py`；Packet → 本文件。

**冲突分析**：无其他活动 IP 占用上述文件（Assignment 亲验占用检查）。#57 PR1 静态部分由本 IP 收敛，
PR2/PR3 不动。暂存纪律：只逐路径 `git add <精确路径>`；禁止 `git add .` / `-A` / `-u`。

## 7. 交付物规范（Implementation 必须满足的数据规格）

### 7.1 `evaluation_data/v4/baseline_manifest.json`

#### 7.1.1 数据集登记集合（R3 强约束表，逐条转录）

| 冻结文件 | 是否入 manifest v1 | 角色 | 理由（须照此登记） |
| --- | --- | --- | --- |
| `popular_calibration_v1.json` | **是** | `calibration` | 5 案例（pip、yt-dlp、rembg、calibre-web、praisonai）现行有效角色为 calibration（文件内 `evaluation_role` 与 README 重分类记录一致，M12） |
| `popular_external_holdout_v2.json` | **是** | `external-holdout` | 活跃 repository-disjoint 冻结 holdout；两次预注册运行已完成，作为历史外部基线保留（README） |
| `real_world_security_cases.json` | **是** | `development` | 3 个 pinned 公共修复仓（aiohttp、django、GitPython），无 holdout 声明；身份与上两者不相交（亲验） |
| `popular_external_holdout.json`（v1） | **否** | —（matrix note） | 其 5 身份已以 calibration 角色登记；同表再登记为 external-holdout 触发冻结角色交叉拒绝，且违背"holdout 状态已被消费"的重分类事实 |
| `popular_external_calibration_v2.json` | **否** | —（matrix note） | v2 holdout 身份已登记为 external-holdout；该文件是事后工程 calibration 副本（README："never a new external claim"），不双登记 |
| `security_repair_cases.json` | **否** | —（matrix note） | 纯合成约束集，无仓库、无可 pinned 的不可变 revision（亲验：case 无 repository 字段） |
| `pr_diff_100.jsonl` | **否** | —（matrix note） | synthetic-controlled 记录（source.kind=synthetic-controlled），100 条记录中 0 条含 40 位 pinned SHA（亲验），无法满足 M6 |

#### 7.1.2 dataset 结构（契约必填 + R3/M7 附加字段）

- 顶层：`schema_version: 1`；`datasets: [dataset, ...]`（恰 3 个，名字为冻结文件内部 `name` 原文）。
- 每个 dataset 必含（契约 L55、L702）：`name`、`fingerprint`、`role`、`entries`。
- 每个 dataset 附加必含（M7，契约 L678-679 容忍；测试冻结为必填）：
  - `source`：冻结文件仓库相对路径（如 `evaluation_data/popular_calibration_v1.json`）；
  - `license`：按 README 口径（上游材料保留原许可；LIMA 标注/选择逻辑 Apache-2.0）；
  - `pinned_file`：同源冻结文件路径（固定身份 = `name` + `fingerprint` + `pinned_file`）。
  - `source` 与 `pinned_file` 必须解析到同一既有冻结文件，且与 dataset `name` 按 7.1.1 一一对应。
- 每个 entry 必含（契约 L56、L716）：`repository`、`commit_sha`；**逐字取自冻结文件的 pinned 字段**：
  `repository` = case 的 `repository` 原文；`commit_sha` 统一取 `vulnerable_commit`（分析基线语义：对
  漏洞在位状态做基线）。禁止 branch/tag/缩写/大写；禁止任何发明值。entry 可带附加字段（契约容忍）。

#### 7.1.3 fingerprint 定义（绑定）

`fingerprint = SHA-256(冻结文件原始字节)`，小写 64-hex；测试以 `rb` 二进制读冻结文件离线重算并断言
与 manifest 值一致。仓库 `.gitattributes` 为 `* text=auto eol=lf`（亲验），各平台 checkout 字节一致，
无需换行归一化。P&V 重算登记值（DI-010，2026-09-25 @ 89cbfc4）：

| 冻结文件 | SHA-256（登记参考值；绑定定义 = 离线重算一致） |
| --- | --- |
| `evaluation_data/popular_calibration_v1.json` | `049d69b25731e51f75a800c5c406ab2d8faef1257d7dacfb275f9734b407b986` |
| `evaluation_data/popular_external_holdout_v2.json` | `23d4ef1da097e6af3d1099546d3cb6167b8964ecdc23f546ad5a835f342b284a` |
| `evaluation_data/real_world_security_cases.json` | `7d88728caca8bc3387802b7bdaa09b59e5ffe1fede21a71c3d314bd63eb0c106` |

#### 7.1.4 正例 arrange 的名义 spec 值（R6：不落盘，仅测试内构造）

测试以落盘 manifest 值构造 spec：`repositories` = manifest 全部 entries 扁平化（identity=`repository`，
commit_sha）；`datasets` = manifest 三数据集（name/fingerprint/role）；名义声明值（digest-only，不构成
任何执行声明）：`analyzer_fingerprint = "a"*64`、`config_digest = "b"*64`、`seed = 20260925`、
`machine_profile` 参照冻结 fixture L97-107 形态（`profile_id: "lima-baseline-profile-001"`、
`cpu_arch: "x86_64"`、`cpu_model: "declared-baseline-cpu"`、`cores: 8`、`ram_gb: 32`、
`os_family: "linux"`、`python_version: "3.12.4"`、`gpu_summary: "none"`）。

### 7.2 `evaluation_data/v4/python_mvp_support_matrix.json`（schema 冻结）

#### 7.2.1 顶层

| 键 | 类型 | 约束 |
| --- | --- | --- |
| `schema_version` | int | == 1 |
| `matrix_id` | str | 非空（稳定矩阵标识，建议 `lima-python-mvp-support-matrix`） |
| `matrix_version` | str | 非空（矩阵版本） |
| `capabilities` | list[dict] | 非空；元素结构见 7.2.2 |
| `coverage_gaps` | list[dict] | 元素结构见 7.2.3 |
| `registration_notes` | list[dict] | 元素结构见 7.2.4 |

#### 7.2.2 capability 条目

必填键：`capability_key`（非空 str，全文件唯一、稳定，跨版本不复用）；`level` ∈
`{"supported", "conditionally-supported", "unsupported"}`；`reason`（非空 str）；`boundary`（非空 str）；
`evidence`（非空 list[非空 str]；指针 = 仓库内路径或 Issue/PR/commit 引用）。

诚实性硬规则（R2，机器可校验部分由测试冻结）：`level == "supported"` 的条目必须至少有一个 evidence
指针是**可解析的仓库内路径**（相对仓库根存在该文件）；无证据的 archetype 只能进 `coverage_gaps` 或以
`unsupported`/`conditionally-supported` + 缺证据说明登记；任何条目不得声称"已验证"除非证据指针可解析
到冻结测试/数据。

#### 7.2.3 coverage_gaps 条目

必填键：`capability_key`（非空 str，必须引用 `capabilities` 中存在的条目——引用完整性）；`reason`
（非空 str）。**必需登记的 gap**（capability_key 绑定值，#57 FR-06 点名但无冻结数据）：

- `archetype/empty-repository`（空仓）
- `archetype/minimal-python-repository`（最小 Python 仓）
- `archetype/llamafactory-replay`（LlamaFactory，见 7.3）

#### 7.2.4 registration_notes 条目

必填键：`file`（非空 str，仓库相对路径）；`reason`（非空 str）。**必需恰好覆盖** 7.1.1 表中 4 个
"否"文件的路径集合：

```
evaluation_data/popular_external_holdout.json
evaluation_data/popular_external_calibration_v2.json
evaluation_data/security_repair_cases.json
evaluation_data/pr_diff_100.jsonl
```

#### 7.2.5 覆盖要求（R2 (a)-(d)）

矩阵必须至少覆盖：(a) manifest v1 已登记的每个数据集对应的 archetype/能力条目（测试冻结锚：三个入册
冻结文件路径各自出现在至少一个 capability 条目的 `evidence` 中）；(b) 每个被排除登记的冻结文件各一条
registration note（7.2.4）；(c) 7.2.3 三项必需 coverage gap；(d) P&V 判定需补充的其他 Python MVP
能力条目（受诚实性硬规则约束，Implementation 依证据自行补充）。

### 7.3 LlamaFactory `7fcf5b3b130e5713b52415bb7404c476fada9c8c` 处置（R4 裁定）

- **不纳入 manifest v1**；在支持矩阵中静态登记为 coverage gap（矩阵侧保留完整 SHA 作为固定身份记录）。
- 矩阵条目要求（测试冻结）：`capability_key = "archetype/llamafactory-replay"`；`level =
  "unsupported"`（无任何仓库内证据，不得用 conditionally-supported 暗示部分证据）；条目内出现完整
  40 位 SHA 原文；`reason` 说明"仓库内无冻结数据集与执行证据"；`boundary` 说明"真实 replay 属 PR3
  （本轮排除）；该 SHA 无法物化时按 #57 FR-06 转 needs-decision，禁止换最新 main"；`evidence` 指向
  Issue #57 FR-06 与 "evaluation_data/ 无该仓库（可由 manifest 枚举复验）"。
- 一致性（测试冻结）：manifest v1 中不出现该身份（任何拼写形态——测试以 repository 不含 "llama"
  （大小写不敏感）且无任何 commit_sha 等于该 SHA 断言）；矩阵中该条目存在且带完整 40 位 SHA。

### 7.4 人类可读支持矩阵渲染表（唯一渲染处；真值在 JSON）

下表是本 Packet 对矩阵结构的**预期渲染**（先行列出；各级别真值以阶段 I 落盘的 JSON 为唯一权威，
本表不预先宣称任何级别，除 R4 已裁定的 LlamaFactory = unsupported）：

| capability_key（预期） | 级别（阶段 I 依证据定级） | 理由/边界要点 | 证据指针形态 |
| --- | --- | --- | --- |
| `archetype/popular-python-calibration`（对应 popular_calibration_v1.json） | 待定 | 现行 calibration 角色；不得重宣称为 external holdout | evaluation_data/popular_calibration_v1.json |
| `archetype/popular-python-external-holdout`（对应 popular_external_holdout_v2.json） | 待定 | 两次预注册运行已完成，历史外部基线 | evaluation_data/popular_external_holdout_v2.json |
| `archetype/real-world-pinned-pairs`（对应 real_world_security_cases.json） | 待定 | development 角色；pinned 修复对 | evaluation_data/real_world_security_cases.json |
| `archetype/empty-repository` | 无证据 → coverage gap | 无冻结数据（M10），不造样本 | — |
| `archetype/minimal-python-repository` | 无证据 → coverage gap | 无冻结数据（M10），不造样本 | — |
| `archetype/llamafactory-replay` | **unsupported**（R4 裁定） | 无冻结数据与执行证据；PR3 范围；SHA 无法物化转 needs-decision（#57 FR-06） | Issue #57 FR-06；manifest 枚举复验 |
| （Implementation 依证据补充的其他 Python MVP 能力条目） | 三级之一 | 受 7.2.2 诚实性硬规则 | 仓库内路径 / Issue 引用 |

注：capability_key 命名除 7.2.3 三项必需 gap key 与测试引用的键外，前缀/命名风格为 Implementation
实现选择（M16 不升级）；上表第一列除绑定键外为建议值。

## 8. 测试矩阵（`tests/test_v4_baseline_manifest.py`，C2 冻结）

组织（R5）：unittest 风格、单文件、模块级只 import stdlib + 冻结 `lima.baseline_run_spec`；产物加载
全部置于测试方法内（产物缺席 → fail closed，collection 必须成功）；CI 经 `scripts/run_ci_tests.py`
（unittest discover -s tests）自动纳入，无需改 runner。测试方法总数 **28（≤ 35 上限，M17）**。

负例面覆盖对照（错误码 → 测试锚点）：

| 冻结错误码 | 触发层 | 测试方法 |
| --- | --- | --- |
| `ABBREVIATED_COMMIT_SHA_REJECTED` | spec/from_mapping | TestSpecLayerFailClosed.test_abbreviated_commit_sha_rejected |
| `MOVING_REF_REJECTED`（branch/tag/大写 40 位） | spec/from_mapping | TestSpecLayerFailClosed.test_moving_and_nonhex_refs_rejected |
| `INVALID_COMMIT_SHA`（40 位非 hex） | spec/from_mapping | TestSpecLayerFailClosed.test_moving_and_nonhex_refs_rejected |
| `DUPLICATE_REPOSITORY`（case-fold/git-suffix/URL；manifest 内/跨条目） | spec + manifest | TestSpecLayerFailClosed.test_duplicate_identity_variants_rejected；TestManifestValidationFailClosed.test_duplicate_repository_rejected |
| `INVALID_FINGERPRINT` | spec/from_mapping | TestSpecLayerFailClosed.test_invalid_fingerprints_rejected |
| `SCHEMA_VERSION_INVALID` | manifest | TestManifestValidationFailClosed.test_schema_version_and_datasets_container_rules |
| `INVALID_FIELD_VALUE`（datasets 空）/`INVALID_FIELD_TYPE`（datasets 错型） | manifest | TestManifestValidationFailClosed.test_schema_version_and_datasets_container_rules |
| `REQUIRED_FIELD_MISSING`（dataset/entry 缺必填） | manifest | TestManifestValidationFailClosed.test_missing_required_fields_rejected |
| `DATASET_FINGERPRINT_MISMATCH`（spec 不符 + 冻结文件篡改副本重算） | manifest | TestManifestValidationFailClosed.test_dataset_fingerprint_mismatch_rejected |
| `DATASET_ROLE_CONFLICT`（holdout×calibration 交叉） | manifest | TestManifestValidationFailClosed.test_role_crossing_rejected_as_role_conflict |
| `MANIFEST_IDENTITY_CONFLICT`（SHA 不符 / spec 仓库缺席） | manifest | TestManifestValidationFailClosed.test_identity_conflicts_rejected |

| Test class | 方法数 | 覆盖点 |
| --- | ---: | --- |
| TestBaselineManifestArtifact | 7 | 产物存在与 schema v1；恰三数据集与 R3 角色；source/license/pinned_file 固定身份与 name↔file 对应；fingerprint 离线重算一致；entries 逐字转录（repository + vulnerable_commit）；全 entry 40 位小写 hex；正例经冻结契约通过（含额外字段容忍） |
| TestSpecLayerFailClosed | 4 | 缩写 SHA；moving ref/非 hex；重复身份三变体；非法 fingerprint |
| TestManifestValidationFailClosed | 6 | schema_version/容器规则；缺必填；指纹不符（含篡改副本漂移）；角色交叉；重复仓库；身份冲突 |
| TestSupportMatrixArtifact | 7 | 顶层结构；capability 结构与级别枚举与键唯一；supported 可解析证据；三项必需 gap + 引用完整性；LlamaFactory 条目形态（unsupported + 完整 SHA + #57 指针）；registration notes 恰覆 4 排除文件；三入册路径被矩阵 evidence 覆盖 |
| TestCrossArtifactConsistencyAndHygiene | 4 | M12：v1 holdout 五身份仅以 calibration 出现 + 冻结 evaluation_role 与 manifest 角色一致；13 身份两两不相交（数量由三冻结文件 cases 数推导）；LlamaFactory 身份 absent-in-manifest/present-in-matrix；离线卫生源扫描（镜像 #204 先例 L239-249） |

RED 形态（R5）：C2 冻结时两个产物文件不存在，全部 28 方法以"产物缺席 → fail closed"失败（加载助手
`self.fail("required deliverable artifact is missing: …")`），逐条可归因于目标产物缺失；不得是
import/环境损坏（collection 成功即证）。

反过拟合：负例全部基于落盘产物深拷贝变异（而非专用 fixture），正例与产物共享同一工件（S5），防止
"只测 fixture 不测落盘物"。

## 9. Done Commands（= Assignment 验收命令，在 worktree 根执行，Windows 设 PYTHONUTF8=1）

```bash
# 1. 定向新测试（阶段 I 完成后须全绿；C2 冻结时须全 RED 且归因产物缺失）
python -m unittest -v tests.test_v4_baseline_manifest
# 2. 冻结测试回归（必须保持 70 方法全绿）
python -m unittest -v tests.test_v4_baseline
# 3. 编译
python -m compileall -q lima tests
# 4. 质量门禁（仅对本次新增 py 文件）
python -m ruff check --no-cache tests/test_v4_baseline_manifest.py
python -m bandit -q tests/test_v4_baseline_manifest.py
# 5. 文件边界 / AC-4 守护
git diff --name-only 89cbfc49cde7da448682e82d132fd0afbb7c827c..HEAD
#    预期恰好等于 4 个 Allowed Files，无其他
git diff 89cbfc49cde7da448682e82d132fd0afbb7c827c..HEAD -- \
  lima/baseline_run_spec.py lima/baseline_run_result.py tests/test_v4_baseline.py \
  evaluation_data/README.md evaluation_data/popular_external_holdout.json \
  evaluation_data/popular_calibration_v1.json evaluation_data/popular_external_holdout_v2.json \
  evaluation_data/popular_external_calibration_v2.json evaluation_data/security_repair_cases.json \
  evaluation_data/real_world_security_cases.json evaluation_data/pr_diff_100.jsonl
#    预期输出为空
# 6. ancestry 守护（P&V 终验）
git merge-base --is-ancestor <Frozen-Test-Commit-SHA> HEAD && echo ANCESTRY-OK
```

成功判据（全部满足才算本切片 GREEN）：AC-1 矩阵诚实登记（R2/R3/R4）；AC-2 manifest 正例 + 全负例
面 fail closed 且错误码与冻结语义一致；AC-3 全部验证离线；AC-4 冻结面与 frozen data 零字节变化。

失败判据（任一命中即未达标）：任一负例未按冻结错误码拒绝；任一冻结面字节变化；测试方法数 > 35；
出现网络/Secret 依赖；出现 allowlist 之外路径；RED 不可归因于产物缺失。

## 10. Stop Conditions（停止并提交 Decision Request 给 Coordinator）

1. 需要修改任何 Forbidden 文件或新增 `lima/` 产品代码（R1）。
2. 需要把 LlamaFactory 或任何无冻结数据来源的身份写入 manifest（R4）。
3. 需要给任何数据集改派与其冻结语义不符的角色（含把 calibration 登记为 external-holdout 或反向）
   （R3/M12）。
4. 测试方法数无法压进 35 且无法合并断言（冻结前）。
5. 需要网络、Secret、付费模型或新依赖。
6. 冻结测试自身被发现语义错误（走解冻-修订-重新 RED 流程，或在 ALLOWED_ONCE 范围内处理，见 §12）。
7. 发现 base SHA 之后 main 出现冲突性实现或 IP-0026 占用冲突。
8. 需求冲突无法唯一解决；验收面覆盖不了真实需求；实现交付与冻结基线不一致且原因不明。

Mechanical Test Correction Allowance：**ALLOWED_ONCE**（Assignment 一次性授出）。P&V 可不新增
Coordinator 调用自行纠正一次纯测试机械缺陷并重新冻结，五项条件：①不改产品语义/公共接口/错误码语义/
文件范围；②仅限 fixture/arrange/import/lint/测试基础设施缺陷；③旧 Frozen Commit 保留；④修正前缺陷
证据、修正后有效 RED、新 Frozen Commit 完整记录；⑤Implementation 未参与测试修改。产物语义、验收语义
或文件范围问题仍走 Decision Request。

## 11. Decision Record（Coordinator 裁定登记，依据 CA-IP-0026-v1.0）

| 裁定 | 内容 | 依据（摘要） | 落点 |
| --- | --- | --- | --- |
| R1 | 零 `lima/` 产品代码；最小充分集合 = 2 JSON 产物 + 1 冻结测试 + 1 Packet | 校验语义已由冻结契约提供；加载封装属 PR2/PR3 投机范围；零产品代码使 AC-4 由纯 git 证据闭合 | §0、§6 |
| R2 | 矩阵为机器可校验 JSON（`evaluation_data/v4/python_mvp_support_matrix.json`）；gap 与登记备注同文件；人类可读渲染唯一落位于本 Packet | Intent S1/S2（防两处漂移）；JSON 唯一真值 | §7.2、§7.4 |
| R3 | manifest 登记集合强约束表（3 入册 / 4 排除；角色绑定；逐字转录；fingerprint=SHA-256(文件字节)；vulnerable_commit 取值；fixed_commit 不变量边界） | v1/cal_v2 家族共享身份触发冻结 DATASET_ROLE_CONFLICT（契约设计行为）；M6/M10/M12/M7 | §7.1 |
| R4 | LlamaFactory SHA 不入 manifest；矩阵静态登记 coverage gap（level=unsupported，完整 SHA 身份记录） | SHA 不存在于任何冻结文件（发明即虚构数据源）；塞入既有 dataset 伪造成员关系；#57 FR-06 needs-decision 防线针对执行期 | §7.3、§3 |
| R5 | 禁止修改 tests/test_v4_baseline.py（含追加）；新测试进 `tests/test_v4_baseline_manifest.py`；≤35 方法；负例面与 RED 形态要求 | 冻结面 digest 与 RED 证据链不可破坏；CI discover 自动纳入 | §8 |
| R6 | 不持久化 BaselineRunSpec JSON / machine profile 工件；spec 于测试 arrange 内构造（名义声明值） | 本切片排除任何执行；落盘从未运行的 spec 制造运行身份过度声明（Intent I3） | §7.1.4 |
| R7 | 单分支按序 commit（C1 Packet → C2 Frozen Test → C3..Cn 实现 → P&V 终验 → 单个 Draft PR） | 授权限定单 PR 且禁合并；IP-0024/IP-0025 已验证路径 | §9、§13 |
| R8 | Packet 路径绑定 `docs/LIMA_Implementation_Packet_IP-0026_Baseline_Static_Foundation.md`；内容含需求映射/文件边界/测试矩阵/Done Commands/Stop Conditions/Decision Record | docs 惯例 + 责任书 §6.8 + 生命周期 §8 | 本文件 |

## 12. Completion Summary 模板（Implementation 交付时）

```text
IP / 状态：IP-0026 / VERIFICATION
Base / Frozen Test Commit / final commit：<SHA 列表>
修改文件：恰为 evaluation_data/v4/baseline_manifest.json 与 evaluation_data/v4/python_mvp_support_matrix.json
AC → Test → Result：逐 AC 附命令与输出摘要（§9 全量）
实际命令与统计：定向 28 方法全绿 + 冻结回归 70 全绿 + ruff/bandit/compileall + git diff 边界检查
安全/权限/依赖变化：无（声明性；零产品代码、零新依赖、零网络）
已知限制与未完成项：coverage gap 清单（空仓/最小仓/LlamaFactory/pr_diff pinned 化/家族并存登记机制）
是否满足 Stop Condition：否
下一步建议：P&V 独立验证（不自行激活）
```

## 13. Packet completion definition

- 本 Packet 关键字段无 TBD；§7 数据规格（schema、键名、必需 gap key、registration note 集合、指纹
  定义与登记参考值、名义 arrange 值）已完整冻结，Implementation 无需再做语义决策。
- 状态 `READY-FOR-CODE` 的激活条件（Assignment Handoff）：C2 Frozen Test Commit 落盘（精确 SHA 登记
  于 C2 commit message 与 P&V 交付记录）+ 有效 RED + 主会话登记后派发阶段 I。
- 本 Packet 为 foundation 贡献；#210/#57 保持打开；本 IP 不宣告任何 Issue 完成；Draft PR 正文含
  "This PR does not auto-close the Source Issue."，严禁 close/fix/resolve 关键字与 #57/#210 组合，
  PR 关联语用 `Related to #210`（父 #57 仅背景引用）。
- 本文件按"单次提交"纪律于 C1 落盘，后续不回填 C2 SHA（避免追加修改已提交 Packet；冻结证据以 C2
  commit 与 Delivery Ledger 为准）。
