# LIMA Implementation Packet — IP-0025 BaselineRunResult（冻结基线结果样本合同与 cold/warm 百分位聚合）

> Packet ID：IP-0025（SHADOW-PILOT V4-I01b）
> Packet 版本：1.0（2026-09-25）
> 状态：`READY-FOR-CODE`（Assignment v1.0 单 PR 一次成形，无实现前检查点）
> Packet 作者：lima-packet-verification（P&V）
> Coordinator Assignment：v1.0（2026-09-25 agent_b36bcbaf 签发；主会话核对授权后按原文派发）
> 精确基线：`a3b2d12e785f359db37a804e2d11bd61c567bb15`（完整 40 位）
> 工作分支：`codex/ip-0025-baseline-run-result`（worktree `D:\BaseAIProject\LIMA-ip-0025-pv-wt`，P&V 独占；Implementation 从 Frozen Test Commit 派生）
> Source Issue：#206（父任务 #57，保持打开）

## 0. 语义总清单（16 条 = Issue #206 预裁定 14 条 + Maintainer 补充裁定 A/B；C-1..C-8 为 Assignment 完形，均冻结）

| ID | 冻结语义 | 来源 |
|---|---|---|
| S1 | `schema_version` 字面量 1；非 int（含 bool/float/str）→ `INVALID_FIELD_TYPE`，int 但值非 1 → `SCHEMA_VERSION_INVALID` | Issue #206 裁定 1 + C-5 |
| S2 | `run_spec_digest` 必须匹配 `^[0-9a-f]{64}$`（小写）；大写/混合大小写/错长/非 hex → `INVALID_DIGEST`；非 str → `INVALID_FIELD_TYPE` | Issue #206 裁定 2 + C-5 |
| S3 | `attempt_index` 唯一（跨样本，重复 → `DUPLICATE_ATTEMPT_INDEX`）、非负 int（`type() is int` 拒 bool；0..2^63-1，越界 → `INVALID_FIELD_VALUE`）；canonical 输出按 `attempt_index` 升序；输入顺序不同但内容相同 → 逐字节一致 canonical bytes 与相同 digest | Issue #206 裁定 3 + C-5/C-8 |
| S4 | `mode ∈ {cold, warm}`（其他 → `INVALID_FIELD_VALUE`；非 str → `INVALID_FIELD_TYPE`） | Issue #206 裁定 4 |
| S5 | `outcome` 匹配 `^[a-z][a-z0-9_]{0,63}$`；六已知值 `success/failure/cancelled/timeout/oom/rate_limited` 必须支持，且为**开放域**（形状合法的未知值如 `agent_aborted` 接受）；形状不合法 → `INVALID_FIELD_VALUE`；非 str → `INVALID_FIELD_TYPE` | Issue #206 裁定 5 + C-5 |
| S6 | 十个可空度量字段统一 `int\|None`：`wall_time_ms/queue_time_ms/cpu_time_ms/expert_time_ms`（整数毫秒）、`memory_rss_peak_bytes/io_read_bytes/io_write_bytes`（整数 byte）、`prompt_tokens/completion_tokens/cost_micro_usd`（非负整数）；全部拒 bool/float/str/list（→ `INVALID_FIELD_TYPE`）与负值、>2^63-1（→ `INVALID_FIELD_VALUE`）；0 与 2^63-1 为合法观测值 | Issue #206 裁定 6 + C-5 |
| S7 | 未取得的指标必须显式 `null`，不得默认为 0；null 与 0 是不同输入、不同 digest | Issue #206 裁定 7 |
| S8 | `failure_code`：`^[A-Z][A-Z0-9_]{0,63}$` 或 `null`；形状外的任何值（小写、空格、路径、异常原文、Secret 形 token、SQL、超长）→ `INVALID_FIELD_VALUE`（有界稳定码字符集即"禁存原文/路径/Secret/Prompt/源码"的机制化执行）；非 str 非 null → `INVALID_FIELD_TYPE` | Issue #206 裁定 8 + C-5 |
| S9 | 原始 sample 全部保留（含失败样本），canonical 输出逐键保真，不删失败样本 | Issue #206 裁定 9 + C-8 |
| S10 | p50/p95 仅对**各 mode 的 `outcome=="success"` 样本**的 `wall_time_ms` 计算（失败样本的 wall 即使存在也排除；两 mode 独立不串扰）；nearest-rank：整数算术 `rank_r = ceil(r·n/100)`（等价 `(r·n + 99)//100`），1-based 升序取 `v[rank]`，`r ∈ {50, 95}`，禁 float 中间值 | Issue #206 裁定 10 + C-7 |
| S11 | `cold_n < 3 或 warm_n < 5`（`<mode>_n` = 该 mode 成功样本数）→ `status="insufficient_sample"` 且四个百分位**全部 null** | Issue #206 裁定 11 + 补充 A |
| S12 | 结果对象深层不可变：对 result / `result.samples` / 任一 sample 条目的修改尝试要么抛异常要么无可观察变化，失败后 `canonical_bytes()`/`content_digest()` 逐字节不变；标准属性（非 dunder）闭包无可变内建容器（dict/list/set/bytearray）；输入隔离；`to_canonical_value()` 副本隔离；不要求抵抗 `object.__setattr__`/ctypes/解释器级篡改 | Issue #206 裁定 12 + C-8（MF-IP-0024-01/02 教训前置） |
| S13 | canonical JSON 与 SHA-256 digest 确定：`canonical_bytes()` 每次 `= codec.canonical_encode(to_canonical_value())` 现算、`content_digest()` 每次 `= codec.compute_content_digest(canonical_bytes())` 现算；复用 `lima.contracts.codec`，禁新写编码器；不得用 digest/canonical 缓存掩盖可变状态 | Issue #206 裁定 13 + C-8 |
| S14 | 本轮只实现合同、校验与聚合；不实现实际指标采集与生产接线（不接 CLI、不跑真实仓库、不创建生产 artifact） | Issue #206 裁定 14 |
| SA | 阈值判定与全有全无策略：`cold_n ≥ 3 且 warm_n ≥ 5` → `status="sufficient_sample"` 且四个百分位**全部为非 null int**（真 int，非 bool）；否则 `insufficient_sample` 且四个百分位**全部 null**（不发布局部百分位）；`status` 与百分位由模块计算，输入不得携带（顶层封闭三键） | Maintainer 补充裁定 A |
| SB | 样本内跨字段判定次序：① 结构/类型/值域校验先行（14 键必在场、逐字段合法，缺失 → `REQUIRED_FIELD_MISSING`）；② `success` 且 `wall_time_ms` 为 null → `SUCCESS_WALL_TIME_REQUIRED`（先判，即使 failure_code 同时违规也报此码）；③ 随后 `success` 配非 null `failure_code` 或非 success 配 null → `FAILURE_CODE_CONFLICT`；非 success 样本的 `wall_time_ms` 允许 null（不触发②） | Maintainer 补充裁定 B |

**C-1..C-8 完形（Assignment v1.0 字面冻结）**

- **C-1 公共符号恰四**：`lima/baseline_run_result.py` 必须定义 `__all__` 且恰为 `{BaselineRunResult, BaselineRunResultError, BaselineRunResultErrorCode, from_mapping}`；`to_canonical_value/canonical_bytes/content_digest` 是 `BaselineRunResult` 的公共方法而非模块级符号。
- **C-2 错误码枚举**：`BaselineRunResultErrorCode` 为 str-Enum（同时为 `enum.Enum` 与 `str` 子类），成员 value == 成员名，**恰 9 码**（§5.3）。
- **C-3 错误类形态**：`BaselineRunResultError(ValueError)`（独立类，非 `ContractError` 子类）；属性 `code: BaselineRunResultErrorCode` + `field_path: str`；消息为稳定目录句，不内嵌任何原始输入值。
- **C-4 结果 dataclass**：`BaselineRunResult` frozen dataclass（属性赋值抛 `dataclasses.FrozenInstanceError`），字段**恰八**：`schema_version:int`、`run_spec_digest:str`、`samples:冻结序列`、`status:str`、`cold_p50_wall_time_ms/cold_p95_wall_time_ms/warm_p50_wall_time_ms/warm_p95_wall_time_ms:int|None`；**无 digest/canonical 缓存字段**。
- **C-5 输入 schema**：顶层恰三键 `schema_version(=1)` / `run_spec_digest` / `samples(list，可空)`；样本恰 14 键封闭 = `{attempt_index, mode, outcome} ∪ 十度量 ∪ {failure_code}`（见 S3–S8）。
- **C-6 跨字段次序**：见 SB。
- **C-7 聚合算法**：见 S10/SA；rank 计算不得引入 float 中间值。
- **C-8 canonical 输出与不可变**：`to_canonical_value()` 顶层恰八键（与 C-4 字段一一对应）、`samples` 为 plain list、按 `attempt_index` 升序、全样本逐键保真；置换不变；深层不可变与隔离见 S12/S13。

## 1. 需求映射（Packet 头）

```text
Source Issue：#206（父 #57）
Issue specification revision：2026-09-25 远端正文（updated_at 2026-09-25T07:58:36Z，P&V 亲取核对，与 Assignment 转述一致）
Covered requirements：预裁定语义 S1…S14（全部）+ 补充裁定 A/B + AC-1…AC-6（单测可证面）
Not covered requirements：#57 PR2 剩余（真实计时/资源/Token 采集接线）、PR3（LlamaFactory 基线执行、cold-warm 运行编排、报告模板）、
  生产 CLI 接线、生产 manifest/样本清单落盘、扫描器/Prompt/标签/评分/split 改动、frozen holdout 改动、Issue 级端到端集成
Delivery role：foundation（评测基线契约层第二切片）
Issue closure impact：PARTIAL
Upstream IP/PR/merge commits：IP-0001 Contract Foundation（lima/contracts/{codec,errors}.py，基线内既存）；
  IP-0024 BaselineRunSpec（PR #205，merge a3b2d12e785f359db37a804e2d11bd61c567bb15 = 本 Packet 精确基线）
```

| AC（Issue #206 验收 6 条） | 本 Packet 验证方式 |
|---|---|
| AC-1 | 14 条语义各有测试覆盖且方法总数 ≤35 → §7 覆盖矩阵 + 冻结计数 32 |
| AC-2 | `TestCanonicalDeterminism.test_samples_sorted_by_attempt_index_and_permutation_invariant`（逐字节 bytes + digest 相等） |
| AC-3 | `TestDeepImmutability` 全类（标准属性闭包 + 现算 bytes/digest + 副本隔离 + 每次调用重建） |
| AC-4 | `TestPublicContractSurface.test_module_source_has_no_network_or_environment_access` + `test_suite_source_is_offline_and_secretless`（静态断言，机器可查） |
| AC-5 | 全量 discover（1510 既有含 IP-0024 的 69 项）零回归；文件边界零触碰既有文件 |
| AC-6 | 单分支单 PR（Assignment 授权拓扑，push/PR 归主会话）；CI：新测试文件由 `scripts/run_ci_tests.py`（unittest discover）自动纳入，`merge-gate` Required Check 照常生效 |

## 2. Design Input Manifest

| Input ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001 | Standard | `docs/LIMA_PACKET_AND_VERIFICATION_AGENT_RESPONSIBILITY_CHARTER.md` | 基线 a3b2d12 内版本 1.0 | P&V 角色边界、Packet/RED/冻结规则 | normative | 无冲突 |
| DI-002 | Issue | Source Issue #206 远端正文（`api.github.com/repos/agent-sec-labs/LIMA/issues/206`，只读 curl） | updated_at 2026-09-25T07:58:36Z（本会话亲取全文） | S1…S14、AC-1…AC-6、Allowed Files 三文件清单、SHADOW 边界 | normative | 亲取正文与 Assignment v1.0 转述逐条一致（14 裁定 + 验收 + 非目标），无冲突；补充 A/B 为 Assignment 增量、与正文不冲突（正文的裁定 11 只说 p50/p95=null，补充 A 细化 insufficient 全 null / sufficient 全非 null 的全有全无策略） |
| DI-003 | Decision | Coordinator Assignment v1.0 全文（agent_b36bcbaf，2026-09-25） | 2026-09-25 | 16 语义 + C-1..C-8、冻结接口 v1.0、方法预算 ≤35、验收命令、单 PR 拓扑 | normative（本切片最高活动权威） | 与历史文档冲突时以 Assignment 为准 |
| DI-004 | Code | `lima/contracts/codec.py`（canonical_encode/compute_content_digest/JSONValue/ContractLimits） | 基线 a3b2d12（亲读） | S13：canonical encode 与 digest 直接复用，禁新写编码器 | normative（复用对象，只读） | 无冲突 |
| DI-005 | Code | `lima/baseline_run_spec.py` + `docs/LIMA_Implementation_Packet_IP-0024_BaselineRunSpec.md` | 基线 a3b2d12（亲读） | 镜像形态（frozen dataclass、str-Enum 错误码、`_FrozenSequence/_FrozenMapping` 只读视图先例、`to_canonical_value/canonical_bytes/content_digest` 方法签名）；§12/§13 两条 CORRECTIVE 的深层不可变教训 | normative（对齐对象，只读；本轮**禁 import** 该模块） | 无冲突 |
| DI-006 | Test | `tests/test_v4_baseline.py`（IP-0024 冻结测试，69 方法） | 基线 a3b2d12 blob（亲读） | 测试形态基准：`assert_from_mapping_rejected` 助手、ast import 白名单扫描、`_mutate_builtin_container` 闭包探针、`--no-cache` ruff 纪律 | evidence（形态参照） | 无冲突；本 Packet 测试为独立新文件，不改不依赖其运行 |
| DI-007 | Code/CI | `.github/workflows/ci.yml` + `scripts/run_ci_tests.py`（unittest discover -s tests） | 基线 a3b2d12 | AC-6：新测试文件自动纳入 CI，无需改 runner | evidence | 无冲突 |
| DI-008 | Finding | 冻结前基线绿证明（本次亲验，worktree D:\BaseAIProject\LIMA-ip-0025-pv-wt @ a3b2d12）：`python -m unittest discover -s tests` → `Ran 1510 tests … OK (skipped=4)`，exit 0；Python 3.12.4、ruff 0.16.5 | 2026-09-25 | 冻结前提；零新增 skip 基线 = 4 | evidence | 无冲突 |
| DI-009 | Standard | `docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md`、`docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md` | 基线 a3b2d12 | 交付流程、验证证据标准、PR 文案约束、PR 不自动关闭 | normative（流程） | 单 PR 拓扑为 Assignment 授权（同 IP-0024 D-0 先例） |

## 3. Explicitly Rejected Inputs

1. `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md` 中 #57 的 BaselineRunResult 采集侧与报告侧条目（计时/资源/Token 采集、expert minutes、precision/recall proxy、报告模板、生产接线）：属 #57 PR2 剩余/PR3，本轮只做合同与聚合（S14）。
2. `lima.baseline_run_spec` 的任何 import（含公共 API）：Assignment import 白名单明确排除；本模块自包含，`run_spec_digest` 只做形状校验不做交叉验证。
3. digest/canonical 构造期缓存字段、`@property` 惰性缓存：S13/C-4/C-8 禁止（MF-IP-0024-01 教训）。
4. float 百分位中间值、插值百分位（linear interpolation）：S10/C-7 指定整数 nearest-rank。
5. insufficient_sample 下发布任一非 null 百分位（局部百分位）：SA 禁止。
6. 缺失指标默认 0 或默认 -1：S7 禁止（必须显式 null）。
7. 错误码 `INVALID_FINGERPRINT`（IP-0024 名称）：本轮 run_spec_digest 违规统一 `INVALID_DIGEST`（C-2 恰 9 码封闭）。
8. 修改 `lima/baseline_run_spec.py`、`tests/test_v4_baseline.py`、IP-0024 Packet 或任何既有文件的"顺手改进"：Issue #206 非目标 + §6 Forbidden。

## 4. Goal / Non-goals

**Iteration hypothesis**：基线运行的**结果侧**可以在零触碰既有 evaluator/扫描器/采集路径的前提下，以"纯新增单模块 + 冻结测试"交付为可验证、可重放、深层不可变的样本合同与聚合契约；**measurement** = 预期 RED（`lima.baseline_run_result` 模块缺失）→ 实现后定向 32/32 GREEN + 全量 1542 零回归（skip 仍 4）+ diff 恰三文件（本 Commit 两文件 + 产品单文件）。

**Goal**：一次基线运行的样本集合被冻结为可校验、可重放的 `BaselineRunResult`：严格 14 键样本合同（typed error 全拒绝路径）、success-wall/failure-code 配对校验、每 mode nearest-rank p50/p95 聚合、全有全无 status 策略、canonical JSON + SHA-256 digest（顺序置换不变）、深层不可变。

**Non-goals**：见 §1 Not covered requirements 全清单；另显式排除：不改任何 Do-Not-Touch 文件（§6）、不新增依赖、不联网、不读 Secret、不产生付费调用、不采集真实指标、不创建 `benchmarks/` 或 `evaluation_data/v4/` 任何文件。

## 5. 冻结接口契约（Frozen Interfaces v1.0）

### 5.1 模块与公共符号（全部位于 `lima/baseline_run_result.py`，Implementation 轮交付；C-1）

| 符号 | 契约 |
|---|---|
| `BaselineRunResultErrorCode` | str-Enum；成员 value == 名；恰 9 码（§5.3） |
| `BaselineRunResultError(ValueError)` | 属性 `code` + `field_path`；独立类（非 `ContractError` 子类）；稳定消息不内嵌原始值 |
| `BaselineRunResult` | frozen dataclass；字段恰八（C-4）；`samples` 为冻结只读序列视图（JSON 兼容读：下标/len/迭代/成员；一切变异操作 fail closed） |
| `from_mapping(mapping)` | 严格读取（§5.2）；任何违规抛 `BaselineRunResultError` |
| `BaselineRunResult.to_canonical_value()` | 返回**全新可变** plain dict/list JSON 子集副本；顶层恰八键；samples 升序、逐键保真；每次调用重建（无共享/缓存） |
| `BaselineRunResult.canonical_bytes()` | `= codec.canonical_encode(self.to_canonical_value())`，每次现算 |
| `BaselineRunResult.content_digest()` | `= codec.compute_content_digest(self.canonical_bytes())`（小写 64-hex SHA-256），每次现算 |
| `__all__` | 恰四符号（C-1） |

### 5.2 输入 schema（C-5；全部必填在场、未知字段拒绝）

顶层恰三键：

1. `schema_version: int`（=1，S1 规则）。
2. `run_spec_digest: str`（`^[0-9a-f]{64}$`，S2 规则）。
3. `samples: list`（可空；非 list 含 tuple/dict → `INVALID_FIELD_TYPE`；元素非 dict → `INVALID_FIELD_TYPE`）。

样本恰 14 键封闭（缺任一键 → `REQUIRED_FIELD_MISSING`；未知键 → `UNKNOWN_FIELD`；两者 `field_path` 含字段名）：

| 字段 | 规则 |
|---|---|
| `attempt_index` | `type() is int`（拒 bool）→ 否则 `INVALID_FIELD_TYPE`；0 ≤ v ≤ 2^63-1 → 否则 `INVALID_FIELD_VALUE`；跨样本唯一 → 否则 `DUPLICATE_ATTEMPT_INDEX`（field_path 含 `attempt_index`） |
| `mode` | str 且 ∈ {cold, warm}；非 str → `INVALID_FIELD_TYPE`，域外 → `INVALID_FIELD_VALUE`（field_path 含 `mode`） |
| `outcome` | str 且 `^[a-z][a-z0-9_]{0,63}$`；开放域；非 str → `INVALID_FIELD_TYPE`，形状违规 → `INVALID_FIELD_VALUE`（field_path 含 `outcome`） |
| 十度量字段（S6 清单） | `int \| None`；拒 bool/float/str/list → `INVALID_FIELD_TYPE`；<0 或 >2^63-1 → `INVALID_FIELD_VALUE` |
| `failure_code` | `None` 或 str 匹配 `^[A-Z][A-Z0-9_]{0,63}$`；非 str 非 null → `INVALID_FIELD_TYPE`；形状违规 → `INVALID_FIELD_VALUE`（field_path 含 `failure_code`） |

### 5.3 typed error 矩阵（恰 9 码，C-2/C-3）

| Code | 触发条件 |
|---|---|
| `SCHEMA_VERSION_INVALID` | `schema_version` 为 int 但 ≠ 1 |
| `REQUIRED_FIELD_MISSING` | 顶层三键或样本 14 键任一缺失 |
| `UNKNOWN_FIELD` | 顶层或样本出现未冻结键（含输入携带 `status`/百分位） |
| `INVALID_FIELD_TYPE` | 任何类型不符（非 dict 输入、samples 非 list、元素非 dict、bool 冒充 int、float、str 错位等） |
| `INVALID_FIELD_VALUE` | 值域不符（schema_version 值、attempt_index/度量越界、mode 域外、outcome/failure_code 形状） |
| `INVALID_DIGEST` | `run_spec_digest` 非 `^[0-9a-f]{64}$`（含大写/混合） |
| `DUPLICATE_ATTEMPT_INDEX` | 跨样本 attempt_index 重复 |
| `SUCCESS_WALL_TIME_REQUIRED` | SB ②：success 且 `wall_time_ms` null（先于 ③） |
| `FAILURE_CODE_CONFLICT` | SB ③：success 配非 null `failure_code`，或非 success 配 null |

`field_path` 约定（对齐 IP-0024 形态）：JSONPath 风格结构定位（如 `$.samples[0].mode`）；字段级失败的 `field_path` 必须含字段名，样本级结构失败含 `samples`。测试仅锚定字段名 fragment（§5.4 例外不锚定）。

### 5.4 校验次序（冻结与未冻结边界）

**冻结**：① 结构/类型/值域先于跨字段（SB ①→②→③）；② SUCCESS_WALL_TIME_REQUIRED 先于 FAILURE_CODE_CONFLICT（SB ②→③）。

**未冻结角落（实现自选，测试不 pin）**：互相独立的字段违规之间的先后（如同一样本两个坏字段报其一即可）；顶层字段间与样本间的遍历次序；DUPLICATE_ATTEMPT_INDEX 与后继样本其他违规的先后；`field_path` 的下标编号细节（只锚字段名 fragment）；`result.samples` 视图自身的迭代顺序（canonical 顺序已冻结，字段顺序未冻结）；dataclass `__eq__`/`__repr__` 语义；`from_mapping` 对 `dict` 子类的接受性（按 `isinstance(…, dict)`，同 IP-0024）。

### 5.5 聚合与 status（S10/S11/SA/C-7）

1. 每 mode 独立：`n = |{s : s.mode == <mode> ∧ s.outcome == "success"}|`。
2. 候选值 = 该 mode 成功样本的 `wall_time_ms` 升序序列 `v`（1-based）。
3. `percentile(r) = v[ceil(r·n/100)]`，整数算术（如 `(r·n + 99)//100` 或 `math.ceil` 于整商），`r ∈ {50, 95}`，禁 float 中间值。
4. `cold_n ≥ 3 且 warm_n ≥ 5` → `status="sufficient_sample"`、四百分位全为非 null int；否则 `status="insufficient_sample"`、四百分位全 null（不发布局部）。
5. `status` 与四百分位由模块计算；输入携带（顶层第四键）→ `UNKNOWN_FIELD`。

### 5.6 canonical 输出与确定性（S3/S9/S13/C-8）

- 顶层恰八键 = C-4 字段一一对应；samples 为 plain list、按 `attempt_index` 升序、全样本（含失败样本）14 键逐键保真。
- 编码/摘要完全委托 `lima.contracts.codec`（NFC、sorted keys、compact、全禁 float、int64 界、UTF-8、SHA-256 小写 hex）。
- 相同语义输入（样本顺序置换、键插入序差异）→ 逐字节一致 bytes 与相同 digest；每次调用现算。

### 5.7 深层不可变（S12/C-8；MF-IP-0024-01/02 教训前置，不等实现后补）

1. 对 result（含 dataclass 属性赋值 → `FrozenInstanceError`）、`result.samples`（集合级 append/insert/extend/pop/clear/del/setitem）、任一条目（setitem/delitem/update/pop/setattr）的修改尝试要么抛异常要么无可观察变化；所有失败尝试后 bytes/digest 逐字节不变。
2. 标准属性（非 dunder）闭包无可变内建容器：对闭包内每个 dict/list/set/bytearray 的代表性变异后 bytes/digest 不变；`__dict__` 等 dunder 与 `object.__setattr__`/ctypes 不在范围。
3. 输入隔离：构造后修改传入 mapping（含嵌套样本）不影响 result。
4. 副本隔离：`to_canonical_value()` 返回可变纯 JSON 副本，修改副本不影响 result；两次调用返回互不共享的新对象。

### 5.8 import 白名单与离线约束（S14/AC-4；测试 ast 静态锚定）

- 产品模块 import ⊆ stdlib `{dataclasses, enum, math, re, typing}` ∪ `lima.contracts.codec`；禁相对 import；**禁 import `lima.baseline_run_spec`**（任何成员）。
- 源内不得出现 `os.environ`/`getenv`/`socket`/`urllib`/`requests` token；测试文件自扫描同规则。

## 6. 文件边界

**Files to Add（本 Frozen Test Commit，P&V 交付）**

- `tests/test_v4_baseline_result.py`（P&V 独占，内联合成 fixture，无独立 fixture 目录）
- `docs/LIMA_Implementation_Packet_IP-0025_BaselineRunResult.md`（本文件）

**Files to Add（Implementation 轮，预声明）**

- `lima/baseline_run_result.py`（Implementation 独占；import 白名单见 §5.8）

**Product Files Allowed to Modify**：无（零既有文件修改）。

**Test/Fixture Files Owned by P&V**：`tests/test_v4_baseline_result.py`（冻结后只读；变更须走解冻-重 RED 流程）。

**Read-only Reference Files**：`lima/contracts/codec.py`、`lima/contracts/errors.py`、`lima/baseline_run_spec.py`、`tests/test_v4_baseline.py`、`.github/workflows/ci.yml`、`scripts/run_ci_tests.py`、`pyproject.toml`。

**Files Forbidden（Do Not Touch）**：`lima/` 其余全部既有文件（含 `contracts/**`、`baseline_run_spec.py`）；`scripts/`；`tests/` 既有全部文件（含 `test_v4_baseline.py`）；`evaluation_data/`（含 frozen holdout）；`benchmarks/`；`.github/`；`frontend/`；`docs/` 治理文档与六 Agent 定义；`pyproject.toml`；`PROGRESS.md`；不新增 `evaluation_data/v4/` 或 `benchmarks/` 任何文件。

**Symbol-to-File Map**：§5.1 全部公共符号 → `lima/baseline_run_result.py` 单文件；冻结测试 → `tests/test_v4_baseline_result.py`；Packet → 本文件。

**冲突分析**：无其他活动 IP 占用上述文件；测试文件名与 `tests/test_v4_baseline.py`（IP-0024 冻结面）不重叠；`lima/contracts/**` 全只读。未来 #57 PR2 的采集接线是 `BaselineRunResult` 的生产消费者，接口以本 Packet §5 为准。

## 7. 测试矩阵（tests/test_v4_baseline_result.py，冻结；方法数 32 ≤ 35）

| Test class | 映射 | 覆盖点（方法级） |
|---|---|---|
| TestPublicContractSurface（7 方法） | AC-4、S14、C-1..C-4 | 9 码 str-Enum value==name；Error=独立 ValueError、code/field_path、稳定消息不内嵌原始值；frozen dataclass 恰八字段；`__all__` 恰四符号；ast import 白名单；产品源禁网络/环境 token；测试自扫描离线无 Secret |
| TestCanonicalDeterminism（6 方法） | S3/S9/S13、AC-2 | 同输入两次 bytes/digest 一等；digest==sha256(bytes)==codec.compute_content_digest(bytes)；sorted/compact/UTF-8 round-trip；顶层恰八键；升序+置换（样本逆序、键序打乱）逐字节同 bytes 同 digest；全样本（含 2 个失败样本）逐键保真（list==dict 相等强断言） |
| TestStrictFieldValidation（3 方法） | S1/S2/S6、C-5 | 非 dict/缺三键/未知键（含 status/百分位携带）/schema_version 型与值/samples 型（tuple/dict/str/int 拒、空 list 合法）；run_spec_digest 型与 `^[0-9a-f]{64}$`（大写/混合/错长拒，0/9/a/f/16hex*4 收）；样本非 dict/14 键逐一缺失/未知键 |
| TestSampleContract（4 方法） | S3/S4/S5/S8 | attempt_index 型（bool/float/str/None）、界（-1、2^63 拒；0、2^63-1 收）、跨样本重复 → DUPLICATE_ATTEMPT_INDEX；mode 域（cold/warm 收；hot/COLD/空格/空拒；型拒）；outcome 开放域（六已知+agent_aborted+z 收；大写/数字开头/标点/65 长/空拒）；failure_code 形状（A/A_1/A*64 收；小写/数字开头/空格/连字符/65 长拒）+ S8 禁存内容（异常原文/绝对路径/Secret 形 token/SQL 全拒）+ 型拒 |
| TestNullMetricSemantics（4 方法） | S6/S7+补充 B | 十度量逐一型/界（bool/float/str/list、-1、2^63 拒；0、2^63-1 收）；null 保持为 null 非 0 且与显式 0 digest 不同；success 缺 wall → SUCCESS_WALL_TIME_REQUIRED（wall+code 双违规时仍先报此码）；conflict 矩阵（success+code / 非 success+null code（wall 亦 null）/非 success+wall+null code → FAILURE_CODE_CONFLICT） |
| TestPercentileAggregation（3 方法） | S10/S11+补充 A、C-7 | nearest-rank 精确值（n=3/5/20/40 手算 oracle：200/300、30/50；10/19、15/25；200/300、20/38；重复值 7/7）；阈值矩阵（(3,5) sufficient 全真 int；(2,5)、(3,4)、空、仅 cold、cold 含失败样本 → insufficient 全 null）+ status 字符串恰两值；仅成功样本（失败样本 wall=999999 排除）+ 两 mode 不串扰 |
| TestDeepImmutability（5 方法） | S12、AC-3 | samples 集合与条目 14 路变异弹幕；标量赋值 FrozenInstanceError + 组合弹幕后 bytes/digest 稳定；标准属性闭包探针（dict/list/set/bytearray）；输入隔离；副本隔离 + 每次现建（S13 无缓存） |

Required test count（冻结时方法数）：**32**。反过拟合：全部 fixture 为合成内联数据（合成 wall 阶梯、重复值、混合 outcome/mode、int64 边界），无真实运行/网络/环境依赖；离线性由静态断言机器可查（AC-4）。

## 8. 命令（在 worktree 根 `D:\BaseAIProject\LIMA-ip-0025-pv-wt` 执行）

**Baseline（冻结前，已亲验 @ a3b2d12）**

```bash
python -m compileall -q lima scripts tests        # exit 0
python -m unittest discover -s tests              # Ran 1510 tests, OK (skipped=4), exit 0
```

**RED（实现前定向，已亲验；工具：Python 3.12.4、ruff 0.16.5）**

```bash
python -m unittest -v tests.test_v4_baseline_result
# → ModuleNotFoundError: No module named 'lima.baseline_run_result'；FAILED (errors=1)；exit 1
# 归因证明：python -c "import lima.contracts.codec" OK；python -c "import lima.baseline_run_spec" OK；
#          python -c "import lima.baseline_run_result" → ModuleNotFoundError（唯一缺失 = 目标产品模块）
```

**Slice 质量门禁（冻结时与实现时均须通过；ruff 一律 `--no-cache`，IP-0024 §12.1 教训）**

```bash
python -m ruff check --no-cache tests/test_v4_baseline_result.py   # All checks passed（已亲验）
python -m compileall -q lima scripts tests
python -m unittest discover -s tests   # 冻结时：1510 既有全过 + 仅新增模块加载错误（RED 归因）；
                                       # 实现后：Ran 1542, OK (skipped=4)，零新增 skip
python -m ruff check --no-cache lima/baseline_run_result.py        # 实现时追加
python -m bandit -q lima/baseline_run_result.py                    # 实现时追加
```

**File Boundary Gate**

```bash
git diff --check
git diff --name-only --diff-filter=ACMRTUXB a3b2d12e785f359db37a804e2d11bd61c567bb15..HEAD
# Frozen Test Commit 时 ⊆ {docs/LIMA_Implementation_Packet_IP-0025_BaselineRunResult.md, tests/test_v4_baseline_result.py}
# Implementation final 时 ⊆ 上述两项 + lima/baseline_run_result.py（AC-5：既有生产逻辑零变化）
```

**Post-merge（merge-gate 全绿后，在最新 origin/main）**：复跑 Slice 质量门禁全量命令 + 定向 `-v tests.test_v4_baseline_result` + `tests.test_v4_baseline`（IP-0024 相邻回归面）。

## 9. Stop Conditions / Decision Request

停止并提交 Decision Request 的情形：

1. Issue #206 远端正文与 Assignment v1.0 转述出现语义冲突（本轮冻结前已亲取核对一致；后续若 Issue 编辑则重核）。
2. 需要第三文件（Packet 与冻结测试之外）、修改 §6 Forbidden 文件、新增依赖、网络、权限或付费调用。
3. typed-error 语义或聚合语义出现第二个合理解，且不在 §5.4 未冻结角落清单内。
4. RED 不可归因（失败非由缺失目标行为触发）。
5. 35 方法预算不足覆盖 §7 矩阵（不得砍覆盖或超限）。
6. 文件面被其他 Agent 占用或基线不再是 a3b2d12 且原因不明。
7. 冻结测试自身存在缺陷（走解冻-重 RED 流程：DR 授权 → 更新 Packet → 撤销旧冻结 → 新 RED → 新 Frozen Test Commit；旧证据保留）。

## 10. Completion Summary 模板（Implementation 交付时）

```text
IP / 状态：IP-0025 / VERIFICATION
Base / Frozen Test Commit / final commit：<SHA 列表>
修改文件与公共符号：lima/baseline_run_result.py（§5.1 四符号 + 三方法）
AC → Test → Result：逐 AC 附命令与输出摘要（定向 32/32 + 全量 1542）
实际命令与统计：§8 Slice 质量门禁全量（passed/failed/skipped/exit code）
文件边界检查：git diff --name-only 结果
安全/权限/依赖变化：无（声明性；import ⊆ §5.8 白名单）
已知限制与未完成项：Not covered 清单确认（S14：无采集/接线）
是否满足 Stop Condition：否
下一步建议：P&V 独立验证（不自行激活）
```

## 11. Packet completion definition

- 本 Packet 关键字段无 TBD；16 条语义 + C-1..C-8 全部冻结于 §0/§5；冻结测试已按 §7 交付并形成 Frozen Test Commit（SHA、测试文件 SHA-256、required test count=32、RED 证据记录于 commit message 与 P&V 交付返回）。
- 状态 `READY-FOR-CODE` 的激活条件：Coordinator 签发 Implementation Assignment（product allowlist = `lima/baseline_run_result.py` 单文件）+ Frozen Test Commit 可按 SHA 获取 + RED 有效。
- 本 Packet 对 #206 为 foundation 贡献；#57/#206 保持打开；本 IP 不宣告任何 Issue 完成，PR 不使用自动关闭关键字。

## 12. CORRECTIVE（DR-IP-0025-FTD-01）：冻结测试两缺陷、合法解冻与新冻结 F2（2026-09-25 追加；仅追加，§1-§11 历史内容不删改）

### 12.1 缺陷记录与根因（两缺陷均属冻结测试自身，非产品行为）

- **缺陷一（fixture 调用元数错误，被 import 期 RED 掩蔽）**：F1（c73977838b553e48593aae499c5b89e9ac49b4d4）的 `TestPercentileAggregation.test_status_thresholds_and_null_policy` 内保留两参调用 `warm5 = _warm_samples(5, (10, 20, 30, 40, 50))`（约行 719）——冻结前将助手签名 `_warm_samples(count, walls)` 收敛为 `_warm_samples(walls)` 时遗漏该调用点，运行期抛 `TypeError: _warm_samples() takes 1 positional argument but 2 were given`。F1 的 RED 是模块缺失导致的**收集期** import 失败（整文件未进入运行期），掩盖该 arrange 缺陷；ruff（不做实参元数检查）与 compileall（仅语法）均不可见。模块存在态复现（交付 worktree，产品文件在场）：定向 `Ran 32 tests … FAILED (errors=1)`，唯一错误即上述 TypeError（亲验）。
- **缺陷二（isort 分区分类依赖模块存在性——第二类 I001 掩蔽）**：ruff 0.16.5 isort 依 import 目标可解析性分区：`lima/baseline_run_result.py` 缺位时 `from lima.baseline_run_result import …` 判入 third-party 段、`lima.contracts.*` 判入 first-party 段，两段间要求空行（F1 冻结时 ruff --fix 依此插入空行并判"通过"）；模块存在时两块同判 first-party、要求紧连，F1 的空行反而触发 I001（模块存在态复现，亲验）。同一字节序列无法同时满足两态。
- **前提关系登记（DR-IP-0025-FTD-01）**：此后 `tests/test_v4_baseline_result.py` 的一切 ruff 证据一律为**模块存在态**；模块缺位态对 F2 报 I001（可修复项）属已登记前提工件，不构成门禁失败。

### 12.2 解冻理由与授权链（合法解冻，按 P&V 责任书 §3 / 生命周期 §22 "Frozen test 错误"路径）

授权链：Coordinator 裁决 **DR-IP-0025-FTD-01**（2026-09-25，agent_b36bcbaf）→ 主会话转达本 P&V 执行纠正性阶段（解冻修正 → 新 RED → 新 Frozen Test Commit F2）。c739778 上对 `tests/test_v4_baseline_result.py` 的冻结状态撤销；按裁决边界做恰两处字节修正（§12.3），重新产生 RED 并登记 F2（本 commit）；本 Packet §1-§11 历史内容不删改，仅本节追加与 §12.6 所列勘正。

### 12.3 修正边界与 B 证明（裁决 A/B 义务，全部亲验）

- 授权修正恰两处：① `test_status_thresholds_and_null_policy` 内 `_warm_samples(5, (10, 20, 30, 40, 50))` → `_warm_samples((10, 20, 30, 40, 50))`；② 删除两个 `lima.*` from-import 块之间的那一个空行。不新增/删除/重排任何 import；测试其他字节、产品文件、语义/覆盖、方法数、门禁零变化（裁决 D）。
- **两 hunk 证明**：`git diff c739778..F2 -- tests/test_v4_baseline_result.py` 恰两个 hunk（hunk1=import 块删空行；hunk2=行 719 调用点）。
- **AST 逐方法证明**：67 个比较单元（模块级助手/语句 + 各类方法）中，唯一不等单元为 `TestPercentileAggregation.test_status_thresholds_and_null_policy`；该方法内 dump 序列差异恰为被编辑 Call 的祖先链（FunctionDef 根 / 所在 Assign / 该 Call 本身——`ast.dump` 递归嵌入编辑子树所致）+ 被删除的唯一节点 `Constant(value=5)`；其余全部节点 dump 逐字节相同且次序相同；该 Call 位置实参 2→1、新实参恰为原第二实参、被调名 `_warm_samples`。**方法数 F1=F2=32**。
- **指纹登记**：F1 测试文件 SHA-256 `1e6d2e3cad84fe46ceb9b8af1bc158221ef2a1431bd90cf74b993c4e63bbe578` → F2（本 commit）`8994c380ddd0dd86b9596e51443ebdf5d542ab51f44eb1dd9f177da6d7c0c969`。
- **产品文件零触碰**：`lima/baseline_run_result.py`（未跟踪，在场）修正前后 SHA-256 均为 `38fbd94285d58b2871f2a975aac7654e5c1a72a5825eefe30c16a225bbf6166f`。

### 12.4 双态证据（新 RED 判据=裁决 3；工具 Python 3.12.4 / ruff 0.16.5）

- **F2 冻结态（F2 干净检出一次性 worktree 复放，判据）**：`python -m unittest -v tests.test_v4_baseline_result` → `ModuleNotFoundError: No module named 'lima.baseline_run_result'`、`FAILED (errors=1)`、exit 1；归因注记：`lima.contracts.codec` 与 `lima.baseline_run_spec` import OK、唯一缺失=目标产品模块。全量 `python -m unittest discover -s tests` → `Ran 1511 … FAILED (errors=1, skipped=4)`（唯一 error=新模块载入失败，既有 1510 全过，skip=4 零新增）。该态 ruff 对 F2 报 I001=已登记前提工件（§12.1）。实测复放结果登记于 F2 commit 后的 P&V 交付返回。
- **模块存在态（交付 worktree，产品文件在场，实测）**：定向 `python -m unittest -q tests.test_v4_baseline_result` → `Ran 32 tests … OK`，exit 0；`python -m ruff check --no-cache tests/test_v4_baseline_result.py` → All checks passed，exit 0；全量 `python -m unittest discover -s tests` → `Ran 1542 tests … OK (skipped=4)`，exit 0。
- **全量口径（勘正后终值）**：F2 冻结态 `Ran 1511 FAILED (errors=1 载入) skipped=4`；实现后 `Ran 1542 OK skipped=4`。

### 12.5 调用预算偏差登记

SHADOW 试点目标 Agent 调用 ≤6（Issue #206 SHADOW 说明）；本 IP 实际 **6→9**（含本纠正阶段），由 DR-IP-0025-FTD-01 授权链追认并在此登记。

### 12.6 勘正登记

- **1541→1542（3 处）**：§4 measurement、§8 注释、§10 模板中"实现后全量 Ran 1541"为算术笔误（1510 既有 + 32 冻结 = 1542），已就地勘正（行 94/242/276）。
- **41 字符 SHA 笔误**：载体核验=Packet 正文、`tests/test_v4_baseline_result.py`、c739778 提交消息三处精确 41-hex 扫描（前后非 hex 边界）均**零命中**（Coordinator 扫描同判）；笔误载体为 F1 阶段 P&V 交付返回文本（非仓库文件），不落仓库字节。真值登记：F1 Frozen Test Commit = `c73977838b553e48593aae499c5b89e9ac49b4d4`（40 位）。

## 13. CORRECTIVE（MF-DICT-01 / MF-IP-0025-01 + MF-IP-0024-02）：实例级可写 `__dict__` 缺陷、双文件合法解冻与新冻结（2026-09-25 追加；仅追加，§1-§12 历史内容不删改）

### 13.1 缺陷记录（Maintainer 增量自审裁定 2026-09-25；主会话已复现；P&V 本轮亲验）

- **MF-IP-0025-01**：`lima/baseline_run_result.py`（`@dataclasses.dataclass(frozen=True)`，实现 commit 3d2a407 L464 附近）未用 slots，实例暴露可写 `__dict__`——`result.__dict__["status"] = "tampered"` 无异常静默改写冻结状态，`canonical_bytes()`/`content_digest()` 随之漂移。P&V 亲验（worktree @ 3d2a407）：bytes 变化 = True、digest 变化 = True，canonical 输出 `"status":"sufficient_sample"` → `"status":"tampered"`。
- **MF-IP-0024-02（跨 IP，随 PR #207 一并交付）**：已合并的 `lima/baseline_run_spec.py`（frozen dataclass，276cadf 后 L576 附近）同样问题——`spec.__dict__["seed"] = 0` 静默改变 canonical/digest。P&V 亲验：`"seed":20260924` → `"seed":0`。Source Issue #204 已重开并留言记录（远端操作归主会话）。
- **根因（两缺陷同因）**：frozen dataclass 的赋值护栏（`FrozenInstanceError`）只拦截 `setattr` 协议，不拦截 `__dict__` 直写；既有 ER 闭包扫描（两文件 `test_standard_attribute_paths_expose_no_mutable_builtin_containers`，源自 IP-0024 §13.2 契约）只枚举非 dunder 属性（`dir(target)` 跳过 `__` 前缀），`__dict__` 属 dunder 天然漏扫。
- **SF-PROCESS-03 登记（流程教训，本轮起生效）**：不可变性闭包扫描以后必须显式检查 `__dict__`、`vars()`、slots 和嵌套 backing storage；不能只枚举非 dunder 属性。

### 13.2 解冻理由与授权链（合法解冻，按 P&V 责任书 §3 / 生命周期 "Frozen test 错误"路径）

- 授权链：Maintainer 增量自审裁定（2026-09-25，精简修复路径：只 P&V → Implementation → 定向 ER）→ 主会话按裁定派发本 P&V 执行【解冻 + 双回归测试 + 双 RED + 新冻结 + 双 Packet 追加】。
- **旧冻结撤销声明**：`c739778`（F1）→ `c12dffd`（F2）→ `3d2a407` 链上对 `tests/test_v4_baseline_result.py` 的冻结状态、`e59a585` → `d9e914f` → `ff76102` → `3d2a407` 链上对 `tests/test_v4_baseline.py` 的冻结状态，一并撤销（仅扩充"新增面"；既有 69+32 项断言/语义零删改，AST 逐单元等价证明见 §13.4）。撤销后按授权各扩充恰一个回归方法、重新产生 RED 并登记新 Frozen Test Commit（本节所在 commit）。
- **授权文件临时扩展（六项；本轮 P&V 只动四项）**：`tests/test_v4_baseline.py`（+1 方法）、`tests/test_v4_baseline_result.py`（+1 方法）、本 Packet（本节追加）、IP-0024 Packet（§14 追加）归 P&V；产品两文件 `lima/baseline_run_result.py`、`lima/baseline_run_spec.py` 归 Implementation 轮（跨 IP 修复随 PR #207 交付）。
- 远端写（push/PR #207/Issue 留言）归主会话。

### 13.3 新增冻结面：实例级 `__dict__` 不可达契约（行为契约，不钉实现手段）

实现可自选手段（如 `slots=True`），但 `BaselineRunResult` 与 `BaselineRunSpec` 的实例必须满足：

1. `hasattr(instance, "__dict__")` 为 `False`（无可写属性字典，`__dict__` 写入路径天然不可达）；
2. `vars(instance)` 抛 `TypeError`；
3. `instance.__dict__` 属性访问抛 `AttributeError`；
4. 尝试经 `__dict__` 写冻结字段（捕获异常）后 `canonical_bytes()` 与 `content_digest()` 与基线逐字节一致；
5. 不要求抵抗 `object.__setattr__`/ctypes/pickle/解释器级篡改（维持 §5.7 范围声明）。

新增测试（恰 1 方法/文件，均在 `TestDeepImmutability` 内）：

| 文件 | 新方法 | 探针字段 | 映射 |
|---|---|---|---|
| `tests/test_v4_baseline_result.py` | `test_instance_has_no_writable_attribute_dict` | `status` | MF-IP-0025-01 / S12 / AC-3 |
| `tests/test_v4_baseline.py` | `test_instance_has_no_writable_attribute_dict` | `seed` | MF-IP-0024-02 / IP-0024 §14 |

### 13.4 双 RED 证据与既有面不变证明（2026-09-25，worktree @ `3d2a407db446d2dda6530e92a979030c112caea2`；Python 3.12.4、ruff 0.16.5 一律 `--no-cache`）

- **双 RED（定向新方法 `python -m unittest -v`，两方法合计 8 条 subTest 失败）**，失败全部由 `__dict__` 存在/可写触发：
  - `probe='instance_has_no_attribute_dict'`：`AssertionError: True is not false`（`hasattr(instance,"__dict__")` 为 True）；
  - `probe='vars_rejects_instance'`：`AssertionError: TypeError not raised`（`vars()` 返回 dict）；
  - `probe='attribute_dict_access_unreachable'`：`AssertionError: AttributeError not raised`（`instance.__dict__` 可达）；
  - `probe='digest_stable_after_dict_write_attempt'`：canonical bytes 断言不等——spec 侧 `"seed":20260924` ≠ `"seed":0`、result 侧 `"status":"sufficient_sample"` ≠ `"status":"tampered"`（`__dict__` 写入静默生效后的漂移本身）。
  - 归因证明：失败模式即缺陷复现路径（与 §13.1 亲验一致），非 arrange/导入/环境错误——两产品模块 import 正常、既有 69+32 项全过可证。
- **定向全文件**：`python -m unittest -q tests.test_v4_baseline` → `Ran 70 tests, FAILED (failures=4, exit 1)`（既有 69 全过，唯一失败方法 = 新方法）；`tests.test_v4_baseline_result` → `Ran 33 tests, FAILED (failures=4, exit 1)`（既有 32 全过）。
- **全量**：`python -m unittest discover -s tests` → `Ran 1544 tests, FAILED (failures=8, skipped=4)`（1542 既有全过 + 恰 2 新方法各 4 条 subTest；skip 基线 4 零新增）。此为本阶段预期状态（登记口径：实现后定向 70/70 与 33/33、全量 1544 OK skipped=4）；实现修复归 Implementation 轮（PR #207），不得为全量变绿做任何产品修改。
- **既有面不变（AST 逐单元证明）**：勘改前后逐单元 `ast.dump` 比较——`test_v4_baseline.py` 111 个既有单元（69 test 方法 + 助手 + class 级语句）与 `test_v4_baseline_result.py` 64 个既有单元全部逐字节等价、变更 0、删除 0；模块级 `if __name__ == "__main__"` 语句 AST 等价（仅行号位移，stash 往返亲证）；新增恰 1 单元/文件（同名 `TestDeepImmutability.test_instance_has_no_writable_attribute_dict`）。方法数 69→70、32→33。
- **质量门禁**：`python -m ruff check --no-cache tests/test_v4_baseline.py tests/test_v4_baseline_result.py` → All checks passed（exit 0；每文件恰 1 个带理由 noqa B018——探针表达式 `instance.__dict__` 裸表达式即断言本体，与既有 S112 noqa 探针先例同风格）；`--select I --no-cache` 复核通过；`python -m compileall -q` 两文件通过；`git diff --check` 干净。

### 13.5 新 Frozen Test Commit 登记

- 本 CORRECTIVE commit（追加于 `3d2a407db446d2dda6530e92a979030c112caea2` 之后，不 amend、不 force）为新 Frozen Test Commit 登记点；完整 40 位 SHA 与提交链见 P&V 交付记录。
- 冻结面：`tests/test_v4_baseline.py` 70 方法（69 + 1）、`tests/test_v4_baseline_result.py` 33 方法（32 + 1）。
- Digest 登记（SHA-256）：`tests/test_v4_baseline.py` `4eeb86036c981615a96b7be70df29a7eedaf7aaa488d7d2676d0ed24f83fa4ed`（ff76102 起）→ `75a74b2b259f39150e761a00cae82e97758950d1fa55a80131f705ae7309b8ba`（本 commit）；`tests/test_v4_baseline_result.py` `8994c380ddd0dd86b9596e51443ebdf5d542ab51f44eb1dd9f177da6d7c0c969`（c12dffd 起）→ `7c750c42c993f0b45401c5eaa507a07a66b39446b2956d80846ca293f8c51f76`（本 commit）。
- 本轮文件边界：恰四文件（两测试文件各 +1 方法 + 本 Packet §13 + IP-0024 Packet §14）；产品文件零改动。
- 交付后两测试文件恢复只读；Implementation 轮按 §13.3 契约修改两产品文件（`lima/baseline_run_result.py`、`lima/baseline_run_spec.py`，PR #207 载体），完成后定向 ER 复验。
- 预期实现后口径：定向 70/70（`tests.test_v4_baseline`）与 33/33（`tests.test_v4_baseline_result`）、全量 `Ran 1544 OK (skipped=4)`。
