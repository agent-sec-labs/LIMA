# LIMA Implementation Packet — IP-0023 BaselineRunSpec（冻结基线输入身份）

> Packet ID：IP-0023（SHADOW-PILOT V4-I01a）
> Packet 版本：1.0（2026-09-24）
> 状态：`READY-FOR-CODE`（受 SHADOW-PILOT Maintainer 检查点约束，见 §0/§11）
> Packet 作者：lima-packet-verification（P&V）
> Coordinator Assignment：v1.0（2026-09-24 lima-coordinator 签发；主会话核对授权后按原内容派发）
> 精确基线：`87f867096ec604e269142380ac1c4a3dcc57d25a`（完整 40 位）
> 工作分支：`codex/ip-0023-v4-baseline-run-spec`（worktree `D:\BaseAIProject\LIMA-ip-0023-pv-wt`）
> Source Issue：#204（父任务 #57，保持打开）

## 0. 假设标注（强制声明）

D-1/D-2/D-3/D-4 为冻结时采用的 Coordinator 推荐假设，Maintainer 检查点可推翻；D-0/DR-SHADOW-01 为既有授权落地确认。

- **D-0（既有授权确认）**：DR-SHADOW-01 单分支单 PR 拓扑。本 Packet 文档与 Frozen Test Commit 在同一分支提交；push 与 Draft PR 由主会话执行。这是对标准流程"Packet 先入 main 再冻结测试"（P&V 责任书 §6.8）的 Coordinator 授权偏离，记录于此。
- **D-1（假设）**：machine_profile 为声明式抽象档案（§5.2.6 字段清单），全 str/int、禁 float、禁自动探测；被 `TestAssumptionD1*` 分区测试锚定。
- **D-2（假设）**：冻结三角色 `{external-holdout, calibration, development}`；角色冲突谓词按 repository normalized identity 在 manifest 全量条目上判交；被 `TestAssumptionD2*` 分区测试锚定。
- **D-3（假设，选 A）**：不接线生产 CLI；`lima/baseline_run_spec.py` 为纯库模块。
- **D-4（假设，选 A）**：不落盘生产 `evaluation_data/v4/baseline_manifest.json`（留 #57 PR1）；manifest 校验消费的 fixture 由测试内联提供。

推翻通道：检查点结论（经主会话转达）→ DR 授权 → 更新 Packet → 撤销旧冻结状态 → 重新 RED → 新 Frozen Test Commit；旧证据保留。

## 1. 需求映射（Packet 头）

```text
Source Issue：#204（父 #57）
Issue specification revision：2026-09-24 创建版正文
Covered requirements：FR-01…FR-08、NFR-01（范围 9 条全部）；AC-1…AC-5（单测可证）
Not covered requirements：#57 的 PR2（计时/资源/Token 采集与 BaselineRunResult）、PR3（LlamaFactory
  基线/cold-warm/报告模板）、cold/warm 与 p50/p95 指标、扫描器/Prompt/标签/评分/split 改动、
  frozen holdout 改动、生产 CLI 接线（D-3 选 A）、生产 manifest 落盘与真实样本清单（D-4 选 A，#57 PR1）
Delivery role：foundation（评测基线契约层）
Issue closure impact：PARTIAL
Upstream IP/PR/merge commits：IP-0001 Contract Foundation（lima/contracts/{codec,errors}.py，
  基线内既存）；无其他活动上游
```

Requirement ID 说明：Issue #204 远端原文在本 Packet 制作会话中不可达（见 DI-002 缺口声明），
FR/AC/NFR 编号由本 Packet 依 Coordinator Assignment v1.0 对 Issue 正文的逐条转述赋号，
在 Maintainer 检查点时与 Issue 原文核对；若编号或语义与原文冲突，按 §9 停止条件处理。

| ID | 内容（转述自 Assignment 的 Issue 范围 9 条） |
|---|---|
| FR-01 | 版本化 BaselineRunSpec |
| FR-02 | 严格读取字段校验与 canonical JSON encode |
| FR-03 | repository revision 必须是完整不可变 commit SHA |
| FR-04 | branch、tag、缩写 SHA 和 moving ref 必须 typed error 拒绝 |
| FR-05 | 记录并校验 repository identity、commit SHA、dataset fingerprint、analyzer fingerprint、config digest、seed、machine profile、数据角色 |
| FR-06 | 相同输入 → 逐字节一致 canonical JSON 与 SHA-256 |
| FR-07 | 任一身份字段变化必须改变 digest |
| FR-08 | 数据集漂移、重复 repository、holdout-calibration 交叉必须拒绝 |
| NFR-01 | 默认测试离线、无 Secret、无付费模型 |

| ID | 内容（转述自 Assignment 的 Issue 验收 8 条） | 本 Packet 验证方式 |
|---|---|---|
| AC-1 | 两次编码字节与 digest 一致 | 冻结测试 TestCanonicalEncodingDeterminism 等 |
| AC-2 | 身份字段变化变 digest | 冻结测试 TestIdentityFieldSensitivity + TestAssumptionD1 分区 |
| AC-3 | branch/tag/缩写 SHA 被 typed error 拒绝 | 冻结测试 TestRevisionTriage |
| AC-4 | 漂移/重复仓库/角色交叉被拒 | 冻结测试 TestDuplicateRepositoryDetection、TestValidateBaselineManifest、TestAssumptionD2 分区 |
| AC-5 | 无网络、无 Secret、无付费 LLM 依赖 | 冻结测试 TestPublicContractSurface 静态断言（import 白名单 + 网络与环境 token 扫描 + 测试自扫描） |
| AC-6 | 生产扫描逻辑和既有 evaluator 语义零变化 | File Boundary Gate（§8 命令；diff 仅 Allowed Files） |
| AC-7 | 一个 PR | 流程约束（D-0 单分支单 PR，主会话执行） |
| AC-8 | CI 全绿 | merge-gate（.github/workflows/ci.yml `merge-gate` job）；新测试文件由 `scripts/run_ci_tests.py`（unittest discover）自动纳入，无需改 runner |

## 2. Design Input Manifest

| Input ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001 | Standard | `docs/LIMA_PACKET_AND_VERIFICATION_AGENT_RESPONSIBILITY_CHARTER.md` | 基线 87f8670 内版本 1.0 | P&V 角色边界、Packet/冻结/RED 规则 | normative | 无冲突 |
| DI-002 | Issue | Source Issue #204 正文（2026-09-24 创建版） | 经 Assignment v1.0 逐条转述（范围 9 条 + 验收 8 条） | FR-01…FR-08、NFR-01、AC-1…AC-8 | normative | 本会话网络不可达（curl exit 35、WebFetch 两次超时），未能亲取远端原文；以 Assignment 转述为唯一可用版本，缺口在 §9 与检查点核对 |
| DI-003 | Issue | 父任务 #57 冻结正文（本地落地：`docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md` 内 `<!-- ISSUE_BODY:57 START/END -->` 区段） | 基线 87f8670 | 文件所有权（benchmarks/v4/baseline/、evaluation_data/v4/baseline_manifest.json、tests/test_v4_baseline.py 均为 #57 声明 Add）、PR1/PR2/PR3 边界、cold/warm 归属 | background / 上下游边界 normative | #57 正文 BaselineRunSpec 输入含 cold/warm 与 BaselineRunResult 指标，#204 子任务只冻结输入身份 → 按 Assignment（优先级更高）裁剪，cold/warm 列入 Not covered 与 Explicitly Rejected Inputs |
| DI-004 | Decision | Coordinator Assignment v1.0 全文（含派发记录与主会话补充说明） | 2026-09-24 | 本切片全部边界：范围、Allowed/Forbidden 文件、冻结接口 v1.0、D-0…D-4、验收命令、测试结构门禁 | normative（本切片最高活动权威） | 与历史文档冲突时以 Assignment 为准 |
| DI-005 | Code | `lima/contracts/codec.py`（canonical_decode/canonical_encode/compute_content_digest/ContractLimits） | 基线 87f8670（亲读） | FR-02/FR-06：canonical encode 直接复用，禁止新写编码器 | normative（复用对象，只读） | 无冲突 |
| DI-006 | Code | `lima/contracts/errors.py`（ContractError/ContractErrorCode 形态） | 基线 87f8670（亲读） | BaselineRunSpecError 形态对齐（code + field_path，独立类） | normative（对齐对象，只读复用） | 无冲突 |
| DI-007 | Code | `lima/evaluation_harness.py::dataset_fingerprint`（L54-L60） | 基线 87f8670（亲读） | dataset fingerprint 的 64-hex 语义锚点 | current-behavior | 无冲突 |
| DI-008 | Code | `lima/real_world_evaluation.py::analyzer_fingerprint`（L111-L125） | 基线 87f8670（亲读） | analyzer fingerprint 的 64-hex 语义锚点 | current-behavior | 无冲突 |
| DI-009 | Code | `lima/repository_source.py::normalize_github_repository`（L109-L141）、`normalize_local_repository_key`（L144-L149）、`_normalize_requested_ref`（L61-L82，仅形状参考）；`lima/repository_import.py::RepositoryImportPolicy.normalize_key`（L33-L51） | 基线 87f8670（亲读） | identity 规范化语义（github-first 次序见 §5.3） | current-behavior | 无冲突 |
| DI-010 | Code/CI | `.github/workflows/ci.yml`（quality-contracts L40 `python -m unittest -v tests.test_ci_contract`；unit-tests L64 `python scripts/run_ci_tests.py`；merge-gate job ~L222）+ `scripts/run_ci_tests.py`（unittest discover -s tests -v） | 基线 87f8670（亲读） | AC-8：新测试文件自动纳入 CI，无需改 runner/tests/test_ci_contract.py | evidence | 无冲突 |
| DI-011 | Standard | `docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md`、`docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md` | 基线 87f8670 | 交付流程、验证证据标准、PR 文案约束 | normative（流程） | D-0 对"Packet 先入 main"的偏离已获 Assignment 授权 |
| DI-012 | Finding | 冻结前基线绿证明（本次亲验，worktree D:\BaseAIProject\LIMA-ip-0023-pv-wt @ 87f8670）：`python -m compileall -q lima scripts tests` exit 0；`python -m unittest discover -s tests` → `Ran 1441 tests … OK (skipped=4)` exit 0 | 2026-09-24 | 冻结前提；零新增 skip 基线 = 4 | evidence | 无冲突 |

## 3. Explicitly Rejected Inputs

1. `docs/LIMA_DR-C1_ENTRY60-CLOSURE-1_Erratum_2026-09-13.md` 中历史占位的"IP-0023（closure IP）"编号语义：属另一任务线（ENTRY60-CLOSURE-1）的历史文档；本 Packet 按 Assignment v1.0 采用 IP-0023 编号。已提请主会话/Coordinator 留意编号复用事实（见交付返回消息），不构成停止条件。
2. `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md` 中 #57 的 BaselineRunResult（wall time p50/p95、queue wait、CPU/RSS/IO、token/费用、expert minutes、precision/recall proxy、failure taxonomy）：属 #57 PR2/PR3，本轮不冻结、不实现。
3. #57 正文 BaselineRunSpec 输入中的 cold/warm 运行模式字段：#204 范围 9 条不含，Assignment 字段清单亦无 → 拒绝进入本轮 schema（防止 schema 后续破坏性变更，届时按 minor/major 版本演进处理）。
4. 生产 `evaluation_data/v4/baseline_manifest.json` 落盘、真实公开样本清单填充、`benchmarks/v4/baseline/` 目录创建（D-4 选 A）：留 #57 PR1。
5. 修改 `scripts/run_*` 评测脚本做参数适配：Assignment 未授权（#57 允许"仅在必要时"，本切片不必要）。

## 4. Goal / Non-goals

**Iteration hypothesis**：基线扫描的输入身份可以在零触碰既有 evaluator/扫描器语义的前提下，以"纯新增单模块 + 冻结测试"交付为可验证、可重放契约；**measurement** = 预期 RED（模块缺失）→ 实现后定向 GREEN + 全量回归零变化 + §7 AC 映射测试全绿 + diff 仅 Allowed Files。

**Goal**：任何基线扫描前，一次 baseline 的输入身份被冻结为可验证、可重放的 `BaselineRunSpec`；相同输入 → 逐字节一致 canonical JSON 与 SHA-256；漂移/移动引用/数据角色冲突在扫描前 fail closed（typed error）。

**Non-goals**：见 §1 Not covered requirements 全清单；另显式排除：不改任何 Do-Not-Touch 文件（§6）、不新增依赖、不联网、不读取 Secret、不产生付费调用、不在本轮创建 benchmarks/ 或 evaluation_data/v4/ 任何文件。

## 5. 冻结接口契约（Frozen Interfaces v1.0）

### 5.1 模块与公共符号（全部位于 `lima/baseline_run_spec.py`，Implementation 轮交付）

| 符号 | 契约 |
|---|---|
| `BaselineRunSpecErrorCode` | `str`-Enum（同时为 `enum.Enum` 与 `str` 子类）；成员 value == 成员名（13 个，见 §5.5） |
| `BaselineRunSpecError(Exception)` | 属性 `code: BaselineRunSpecErrorCode` 与 `field_path: str`；形态对齐 `ContractError` 但**独立类**（不得是 `ContractError` 子类）；消息不内嵌原始输入值 |
| `BaselineRunSpec` | frozen dataclass（属性赋值必须抛 `dataclasses.FrozenInstanceError`） |
| `from_mapping(mapping)` | 严格读取：必填缺失/未知字段/类型/值逐一校验（§5.2）；失败抛 `BaselineRunSpecError` |
| `to_canonical_value()` | **BaselineRunSpec 公共方法**：返回 codec JSONValue 子集（plain `dict/list/str/int`，无 enum/float/tuple），覆盖全部字段含 schema_version |
| `canonical_bytes()` | **BaselineRunSpec 公共方法**：直接复用 `lima.contracts.codec.canonical_encode(to_canonical_value())`；禁止新写编码器 |
| `content_digest()` | **BaselineRunSpec 公共方法**：直接复用 `lima.contracts.codec.compute_content_digest`；等于 `sha256(canonical_bytes())` 的小写 hex |
| `load_baseline_run_spec(path)` | 从文件读取 UTF-8 JSON（格式无关：缩进/键序/ASCII 转义不影响语义）→ 严格校验 → 返回 spec；坏 JSON 必须以 `BaselineRunSpecError` fail closed |
| `validate_baseline_manifest(manifest, spec)` | §5.7 四类一致性 + 结构规则；成功不抛异常；失败抛对应 typed error |

### 5.2 字段清单（全部必填、无默认值、未知字段拒绝；类型受 codec 子集约束）

顶层键集合（封闭，to_canonical_value 顶层键恰为此 7 项，无任何自动时间戳/主机名/环境取值字段）：

1. `schema_version: int`，字面量 1（值非 1 → `SCHEMA_VERSION_INVALID`；非 int 含 bool/float/str → `INVALID_FIELD_TYPE`）。
2. `repositories: list[≥1]`；元素为封闭键集 `{identity, commit_sha}` 的 dict：
   - `identity: str`：按 §5.3 规范化后比较与匹配；
   - `commit_sha: str`：按 §5.4 三分矩阵校验；
   - 空列表 / 非 list / 元素非 dict → `INVALID_FIELD_VALUE` / `INVALID_FIELD_TYPE`。
3. `datasets: list[≥1]`；元素为封闭键集 `{name, fingerprint, role}` 的 dict：
   - `name: str`；`fingerprint: str` 匹配 `^[0-9a-f]{64}$`（否则 `INVALID_FINGERPRINT`）；`role` ∈ 三角色（否则 `INVALID_FIELD_VALUE`）。
4. `analyzer_fingerprint: str(64-hex)`；`config_digest: str(64-hex)`（否则 `INVALID_FINGERPRINT`）。
5. `seed: int`（int64 含边界；超界 → `INVALID_FIELD_VALUE`；非 int 含 bool/float/str → `INVALID_FIELD_TYPE`）。
6. `machine_profile: object`（D-1）：声明式抽象档案，封闭键集
   `{profile_id, cpu_arch, cpu_model, cores, ram_gb, os_family, python_version, gpu_summary}`；
   `cpu_arch ∈ {x86_64, aarch64}`、`os_family ∈ {linux, windows, darwin}`、`cores/ram_gb: int`（bool 拒绝）、其余 str；全 str/int、禁 float、禁自动探测、禁未知键。
7. 缺任一必填键（含嵌套元素与 machine_profile 内）→ `REQUIRED_FIELD_MISSING`，`field_path` 含字段名；未知键（顶层/元素/machine_profile）→ `UNKNOWN_FIELD`。

### 5.3 identity 规范化次序（矩阵定稿）

github-first：identity 形如 github `owner/repository`（含 https://github.com/… URL 与 `.git` 后缀变体）时按 `normalize_github_repository` 语义规范化（小写折叠、去 `.git`）；否则按 `normalize_local_repository_key` 语义规范化（保留大小写的有界相对键）；两者皆拒 → `INVALID_FIELD_VALUE`。定稿依据：Assignment 列举次序（github 在前）+ fail-closed（github 折叠更保守，重复检出更强）。可观察后果：`Owner/Repo` 与 `owner/repo`、`owner/repo.git`、`https://github.com/owner/repo` 判等。

### 5.4 revision 三分矩阵（`commit_sha`，按序判定）

| 次序 | 形状（fullmatch） | 结果 |
|---|---|---|
| 1 | `^[0-9a-f]{40}$` | 合法 |
| 2 | `^[0-9a-f]{7,39}$` | `ABBREVIATED_COMMIT_SHA_REJECTED` |
| 3 | 长度 40 且 `^[0-9a-fA-F]{40}$`（含大写） | `MOVING_REF_REJECTED` |
| 4 | 长度 40 且含非 hex 字符 | `INVALID_COMMIT_SHA` |
| 5 | 其余全部形状（branch/tag/ref 路径、`main`、`v1.2.3`、`refs/heads/main`、<7 位 hex 等） | `MOVING_REF_REJECTED` |

非 str 类型 → `INVALID_FIELD_TYPE`（先于三分）。此表为 Assignment v1.0 字面冻结：40 位含大写归 `MOVING_REF_REJECTED`、40 位非 hex 归 `INVALID_COMMIT_SHA`。

### 5.5 typed error 矩阵定稿（13 码）

| Code | 触发条件 | 优先级备注 |
|---|---|---|
| `SCHEMA_VERSION_INVALID` | spec 或 manifest 的 `schema_version` 值非 int 1 | 类型错走 `INVALID_FIELD_TYPE` |
| `REQUIRED_FIELD_MISSING` | 顶层/元素/machine_profile/manifest dataset/manifest entry 缺必填键 | `field_path` 含字段名 |
| `UNKNOWN_FIELD` | spec 侧（顶层、repositories/datasets 元素、machine_profile）出现未冻结键 | manifest 侧宽容（§5.7） |
| `INVALID_FIELD_TYPE` | 类型不符（bool 冒充 int、float、容器错型、非 str 等） | |
| `INVALID_FIELD_VALUE` | 值域不符（schema_version 值、seed 超 int64、role 非三角色、cpu_arch/os_family 非白名单、identity 双规范化均拒、空列表） | |
| `ABBREVIATED_COMMIT_SHA_REJECTED` | §5.4 次序 2 | |
| `MOVING_REF_REJECTED` | §5.4 次序 3、5 | |
| `INVALID_COMMIT_SHA` | §5.4 次序 4 | |
| `DUPLICATE_REPOSITORY` | spec 内 normalized identity 相等；manifest 同 dataset 内重复；manifest 跨 dataset 重复且**不**构成 holdout-calibration 交叉 | 特异性低于 `DATASET_ROLE_CONFLICT`（矩阵定稿：交叉场景报更特定的安全码） |
| `DATASET_FINGERPRINT_MISMATCH` | spec.dataset.fingerprint ≠ manifest 同名 dataset.fingerprint | |
| `DATASET_ROLE_CONFLICT` | manifest 全量条目中同一 normalized identity 同时挂 `external-holdout` 与 `calibration` | 特异性优先于 `DUPLICATE_REPOSITORY` |
| `INVALID_FINGERPRINT` | `analyzer_fingerprint`/`config_digest`/dataset `fingerprint` 非 `^[0-9a-f]{64}$` | |
| `MANIFEST_IDENTITY_CONFLICT` | spec.repository 的 (normalized identity, commit_sha) 与 manifest 条目不一致或缺失 | identity 按 §5.3 匹配 |

### 5.6 canonical encode 与 digest

- 直接复用 `lima.contracts.codec.canonical_encode` / `compute_content_digest`（NFC、sorted keys、compact separators、全禁 float、int64 界、UTF-8、SHA-256 小写 hex），禁止新写编码器。
- digest 覆盖全部字段含 `schema_version`（由 to_canonical_value 顶层键封闭性保证）。
- 相同语义输入（键插入序、文件格式、ASCII 转义差异）→ 相同 canonical bytes 与 digest。

### 5.7 manifest schema v1 与 fail-closed 校验（D-4）

manifest 形状：`{schema_version: 1, datasets: [{name, fingerprint, role, license, source, entries: [{repository, commit_sha, …}]}]}`。

`validate_baseline_manifest(manifest, spec)` 校验（全部 fail closed）：

1. 结构：manifest 为 dict；`schema_version == 1`（否则 `SCHEMA_VERSION_INVALID`）；`datasets` 为非空 list（错型 `INVALID_FIELD_TYPE`/空 `INVALID_FIELD_VALUE`）；每个 dataset 含 `name/fingerprint/role/entries`（缺失 → `REQUIRED_FIELD_MISSING`）；每个 entry 含 `repository/commit_sha` 为 str（缺失 → `REQUIRED_FIELD_MISSING`；错型 → `INVALID_FIELD_TYPE`）；dataset `role` ∈ 三角色（否则 `INVALID_FIELD_VALUE`）。
2. dataset 指纹一致：spec 每个 dataset 在 manifest 同名 dataset 上 fingerprint 必须相等（否则 `DATASET_FINGERPRINT_MISMATCH`）。
3. 跨 dataset / 同 dataset 重复仓库：normalized identity 重复 → `DUPLICATE_REPOSITORY`（与角色交叉并存时按 §5.5 优先级）。
4. 角色交叉：任一 normalized identity 同时挂 `external-holdout` 与 `calibration` → `DATASET_ROLE_CONFLICT`。
5. spec↔manifest 身份一致：spec 每个 repository 的 (normalized identity, commit_sha) 必须能在 manifest 条目中找到一致项（否则 `MANIFEST_IDENTITY_CONFLICT`；identity 匹配大小写不敏感、容忍 URL/`.git` 变体）。
6. 宽容面（D-4 前向兼容）：manifest dataset 的 `license/source` 与 entry 的 `…` 附加字段**不拒**（生产 manifest 是 #57 PR1 的产物）；spec 侧保持严格。

### 5.8 未冻结角落（显式列出；实现可自选，测试不 pin，但安全不变量仍适用）

1. 列表（repositories/datasets/manifest entries）顺序的 digest 显著性：按字面输入顺序进入 canonical，未冻结排序归一规则。
2. spec 引用的 dataset name 在 manifest 完全缺失：必须 fail closed 抛 `BaselineRunSpecError`，具体 code 未冻结（`DATASET_FINGERPRINT_MISMATCH` 与 `MANIFEST_IDENTITY_CONFLICT` 均合理）。
3. manifest 含 spec 未引用的额外 dataset：容忍与否未冻结（测试用例均构造 spec.datasets ⊆ manifest.datasets，回避该分歧）。
4. manifest dataset 的 `license/source` 必填性未冻结（happy-path fixture 含二者；不 pin 缺失行为）。
5. `load_baseline_run_spec` 对不存在路径的异常类型未冻结（OSError 直抛可接受）。
6. manifest entry 的 `commit_sha` 是否走 §5.4 三分：未冻结（仅要求为 str；身份不一致由 `MANIFEST_IDENTITY_CONFLICT` 兜底）。
7. spec.datasets 内同名 dataset 的处理未冻结。

## 6. 文件边界

**Files to Add（本 Frozen Test Commit，P&V 交付）**

- `tests/test_v4_baseline.py`（P&V 独占，含内联 fixture，不建独立 fixture 目录）
- `docs/LIMA_Implementation_Packet_IP-0023_BaselineRunSpec.md`（本文件）

**Files to Add（Implementation 轮，预声明）**

- `lima/baseline_run_spec.py`（Implementation 独占；仅可 import：stdlib `dataclasses/enum/hashlib/json/re/typing` + `lima.contracts.codec` + `lima.contracts.errors`（只读复用）；源内不得出现 `os.environ`/`getenv`/`socket`/`urllib`/`requests` token）

**Product Files Allowed to Modify**：无（零既有文件修改）。

**Test/Fixture Files Owned by P&V**：`tests/test_v4_baseline.py`（冻结后只读；变更须走解冻-重 RED 流程）。

**Read-only Reference Files**：`lima/contracts/codec.py`、`lima/contracts/errors.py`、`lima/evaluation_harness.py`、`lima/real_world_evaluation.py`、`lima/repository_source.py`、`lima/repository_import.py`、`.github/workflows/ci.yml`、`scripts/run_ci_tests.py`。

**Files Forbidden（Do Not Touch）**：`lima/contracts/manifests.py`；`lima/contracts/codec.py`、`lima/contracts/errors.py`；`lima/evaluation_harness.py`、`lima/real_world_evaluation.py`、`lima/repository_source.py` 及 `lima/` 其余全部既有文件；`scripts/`；`tests/` 既有全部文件；`evaluation_data/` 既有文件（含 frozen holdout）；`.github/`；`frontend/`；PR #183/C/C++ 平台文件面；`docs/` 治理文档与六 Agent 定义；`PROGRESS.md`。不新增 `evaluation_data/v4/baseline_manifest.json`（D-4 选 A）、不新增 `benchmarks/`。

**Symbol-to-File Map**：§5.1 全部公共符号 → `lima/baseline_run_spec.py` 单文件；冻结测试 → `tests/test_v4_baseline.py`；Packet → 本文件。

**冲突分析**：无其他活动 IP 占用上述文件；`lima/contracts/**` 全只读；#57 PR1（未来）是 `validate_baseline_manifest` 的生产 manifest 消费者，接口以本 Packet §5.7 为准。IP 编号 "IP-0023" 与 `docs/LIMA_DR-C1_ENTRY60-CLOSURE-1_Erratum_2026-09-13.md` 的历史占位撞号，已按 Assignment 采用并记录（§3.1）。

## 7. 测试矩阵（tests/test_v4_baseline.py，冻结）

结构门禁（Assignment 变更 3）：`TestAssumptionD1*`（machine profile 字段语义）与 `TestAssumptionD2*`（角色冲突谓词）独立成 class、fixture 全部 class 内定义；其余决策无关测试不依赖两分区任何常量/fixture（以 class 作用域隔离达成，并有元测试断言分区恰为两类）。

| Test class（决策无关核心） | 映射 | 覆盖点 |
|---|---|---|
| TestPublicContractSurface | AC-5、FR-01 | 9 公共符号存在性；str-Enum 与 13 码 value==name；Error 独立类（非 ContractError 子类）+code/field_path；frozen dataclass；模块 import 白名单（ast）；模块源无网络/环境 token；测试自扫描离线无 Secret；分区结构元测试 |
| TestCanonicalEncodingDeterminism | AC-1、FR-02/FR-06 | 同输入两次 → 字节与 digest 一等；digest==sha256(canonical_bytes) 小写 hex；bytes 为 sorted/compact/UTF-8 canonical JSON 且与 to_canonical_value round-trip；键插入序无关；NFC 归一 |
| TestIdentityFieldSensitivity | AC-2、FR-05/FR-07 | 8 类身份字段逐一变化 → digest 变化；to_canonical_value 顶层恰 7 键且含 schema_version=1 |
| TestStrictFieldValidation | FR-01/FR-02/FR-05 | 非 dict 输入；7 必填缺失；未知键（顶层/元素/machine_profile 外部由 D-1 覆盖）；schema_version 值/型；容器规则；seed 型与 int64 边界；64-hex 指纹；identity 非法形状 |
| TestRevisionTriage | AC-3、FR-03/FR-04 | §5.4 五分支全覆盖（7/39 位缩写、branch/tag/ref、6 位 hex、40 位大写、40 位非 hex、非 str 型） |
| TestDuplicateRepositoryDetection | AC-4、FR-08 | 大小写折叠、`.git` 后缀、URL 变体判等 → DUPLICATE_REPOSITORY；不同 identity 正常通过（正控制） |
| TestLoadBaselineRunSpec | AC-1、FR-02 | canonical 文件 round-trip 相等；格式无关（缩进/键序/转义）同 digest；坏 JSON fail closed；文件内契约违规报 typed error |
| TestValidateBaselineManifest | AC-4、FR-08 | 合法通过；指纹漂移；commit 冲突；spec 仓库缺失；大小写不敏感匹配（正控制）；同 dataset 重复；结构规则（schema_version/datasets 型与空/dataset/entry 必填）；entry 附加字段宽容；spec dataset 缺失 fail closed（code 不 pin） |
| TestAssumptionD1MachineProfileFields（D-1 分区） | AC-2、FR-05 | canonical 值恰 8 键；cpu_arch/os_family 白名单与拒大写；float/bool 拒；str 字段型；缺字段；未知键（hostname 类）；machine_profile 变化 → digest 变化 |
| TestAssumptionD2DatasetRoleConflict（D-2 分区） | AC-4、FR-08 | spec 三角色合法+未知拒；manifest 未知 role 拒；holdout×calibration 交叉 → DATASET_ROLE_CONFLICT（特异性优先级）；dev×dev 跨 dataset → DUPLICATE_REPOSITORY（非角色冲突） |

Required test count（冻结时方法数，逐方法清单见测试文件）：61。
反过拟合：全部 fixture 为合成内联数据（github 形 + local-key 形两类 identity、多 dataset/多 repo 组合），无真实仓库/网络/环境依赖；静态测试机器可查（AC-5）。

## 8. 命令（在 worktree 根 `D:\BaseAIProject\LIMA-ip-0023-pv-wt` 执行）

**Baseline（冻结前，已亲验）**

```bash
python -m compileall -q lima scripts tests        # exit 0
python -m unittest discover -s tests              # Ran 1441 tests, OK (skipped=4), exit 0
```

**RED（实现前定向，预期）**

```bash
python -m unittest -v tests.test_v4_baseline      # ModuleNotFoundError: No module named 'lima.baseline_run_spec'
```

**Slice 质量门禁（冻结时与实现时均须通过）**

```bash
python -m ruff check tests/test_v4_baseline.py
python -m compileall -q lima scripts tests
python -m unittest discover -s tests              # 冻结时：既有 1441 全过 + 仅新增模块加载错误（RED 归因）；实现后：全绿、skip 仍为 4（零新增 skip）
python -m ruff check lima/baseline_run_spec.py    # 实现时追加
python -m bandit -q lima/baseline_run_spec.py     # 实现时追加
```

**File Boundary Gate**

```bash
git diff --check
git diff --name-only --diff-filter=ACMRTUXB 87f867096ec604e269142380ac1c4a3dcc57d25a..HEAD
# Frozen Test Commit 时 ⊆ {docs/LIMA_Implementation_Packet_IP-0023_BaselineRunSpec.md, tests/test_v4_baseline.py}
# Implementation final 时 ⊆ 上述两项 + lima/baseline_run_spec.py（AC-6：生产扫描逻辑与既有 evaluator 语义零变化）
```

**Post-merge（merge-gate 全绿后，在最新 origin/main）**：复跑 Slice 质量门禁全量命令 + 定向 `-v tests.test_v4_baseline` + `tests.test_evaluation_harness tests.test_real_world_evaluation`（相邻回归面）。

## 9. Stop Conditions / Decision Request

停止并提交 Decision Request 的情形：

1. D-1/D-2/D-3/D-4 任一被 Maintainer 检查点推翻（唯一推翻通道；P&V 不得自行改选）。
2. Issue #204 远端原文与 Assignment 转述出现语义冲突（检查点核对时）。
3. 需要修改 §6 Forbidden 文件、新增依赖、网络、权限或付费调用。
4. typed-error 语义出现第二个合理解，且不在 §5.8 未冻结角落清单内。
5. RED 不可归因（失败非由缺失目标行为触发）。
6. 文件面被其他 Agent 占用或基线不再是 87f8670 且原因不明。
7. 冻结测试自身存在缺陷（走解冻-重 RED 流程：DR 授权 → 更新 Packet → 撤销旧冻结 → 新 RED → 新 Frozen Test Commit；旧证据保留）。

## 10. Completion Summary 模板（Implementation 交付时）

```text
IP / 状态：IP-0023 / VERIFICATION
Base / Frozen Test Commit / final commit：<SHA 列表>
修改文件与公共符号：lima/baseline_run_spec.py（§5.1 九符号）
AC → Test → Result：逐 AC 附命令与输出摘要
实际命令与统计：§8 Slice 质量门禁全量（passed/failed/skipped/exit code）
文件边界检查：git diff --name-only 结果
安全/权限/依赖变化：无（声明性）
已知限制与未完成项：Not covered 清单确认
是否满足 Stop Condition：否
下一步建议：P&V 独立验证（不自行激活）
```

## 11. Packet completion definition

- 本 Packet 关键字段无 TBD；冻结测试已按 §7 交付并形成 Frozen Test Commit（SHA、测试文件 SHA-256、required test count=61、假设标注句记录于 commit message 与交付返回）。
- 状态 `READY-FOR-CODE` 的激活条件（Assignment Handoff）：检查点结论落定 + Coordinator 签发 Implementation Assignment（product allowlist = `lima/baseline_run_spec.py` 单文件）+ Frozen Test Commit 可按 SHA 获取 + RED 有效。
- 本 Packet 对 #204 为 foundation 贡献；#57 保持打开；本 IP 不宣告任何 Issue 完成，PR 不使用自动关闭关键字。
