# LIMA Implementation Packet — IP-0029 Baseline Report Projection（基线报告/投影层 + IP-0028 两遗留收口）

- Packet ID：IP-0029（Source Issue #217；Parent #57 PR3-b）
- 依据：Coordinator Assignment CA-IP-0029-v1.0（2026-09-26，一轮 Assignment 全裁定）；Intent Record INTENT-RECORD-IP-0029-2026-09-26（READY-FOR-COORDINATOR）
- 精确基线（Exact Baseline）：`8e61ddd0f0efa4624cca138d99e4b263594327fd`（= origin/main = PR #216 合并点 = IP-0028 post-merge PASS）
- 工作分支 / worktree：`codex/ip-0029-baseline-report` @ `D:\BaseAIProject\LIMA-ip0029-wt`
- 授权：Maintainer 长程授权（2026-09-26；Operating Mode SHADOW，ACTIVE: DISABLED；Execution Authorization: MAINTAINER_AUTHORIZED）
- 本 Packet 由 P&V 制作；公共符号面、错误码逐字消息、识别谓词、测试矩阵方法切分为 P&V 在 CA R1-R11 边界内的冻结细化（见 §7 与 §10；偏离本 Packet 冻结面 = Stop Condition 7）

## 0. 交付物角色声明（强制，先于一切）

本 Packet 是 IP-0029 的唯一实现依据。实现交付物恰为一个新模块 `benchmarks/v4/baseline/report.py`（Add，不修改任何既有 tracked 文件）。冻结验收测试为 `tests/test_v4_baseline_report.py`（C2 Frozen Test Commit，≤35 方法）。本切片零 Modify：diff 恰 3 个 Add 路径。任何超出 = Stop Condition。实现者不得修改本 Packet 与冻结测试；测试缺陷走 Decision Request（或一次性 ALLOWED_ONCE，见 §12）。

## 1. 需求映射（Packet 头）

#217 "Scope (this slice)" 1-8 规范化为 FR-01..FR-08（语义不变，CA-IP-0029-v1.0）；AC 沿用 #217 原文 AC-1..AC-4。本 Packet 只声明本切片的贡献。

| ID | #217 出处 | 本轮交付 | 验收承载 |
| --- | --- | --- | --- |
| FR-01 | Scope 1 | 报告/投影层模块：消费 BaselineRunSummary（IP-0028）+ expert sidecar（IP-0027）+ 注入的 evaluator 输出结构，产出 FR-04 计数字段与压缩率链（独立报告 schema，不扩任何既有对象） | TestProjectionScanner / TestProjectionE2E / TestProjectionRealWorld |
| FR-02 | Scope 2 | legacy projection 显式标记（报告级 + 字段级双层）；缺席即 null + 标记，永不用 0 冒充未知；不虚构字段或计数 | TestLegacyProjectionMarking / TestCompressionRatios |
| FR-03 | Scope 3 | 专家 active minutes 与自动化耗时进同一报告、分开统计（FR-05 收口） | TestExpertAndAutomationFace |
| FR-04 | Scope 4 | 报告 canonical JSON（UTF-8/稳定 key/SHA-256 封存）；公开报告只存摘要与哈希（无源码/日志/凭据/本机路径） | TestReportSchemaAndCanonical / TestContentBoundary / TestReportWriter |
| FR-05 | Scope 5 | 聚合件离线发现约定固化为纯函数契约 + 测试（IP-0028 known gap 收口） | TestFindRunArtifacts |
| FR-06 | Scope 6 | SF-IP-0028-20260926-2 收口：基线模式惰性声明的用户可见面（等效面 = 报告 declarations 枚举 + PR 正文冻结句，CA R5） | TestHygieneAndSurface（declarations 封闭枚举）+ PR 纪律（§14） |
| FR-07 | Scope 7 | SF-01 纪律：v1 报告层零 manifest 消费（可测的空缺证明） | TestHygieneAndSurface（零 manifest 源扫描） |
| FR-08 | Scope 8 | 全离线验证（无网络/Secret/付费）；正例 + fail-closed 负例 | TestFailClosedNegatives / TestHygieneAndSurface |

AC 映射：AC-1（计数与压缩率链确定性投影、legacy 显式、不虚构）→ TestProjection* + TestLegacyProjectionMarking + TestCompressionRatios + TestFailClosedNegatives；AC-2（canonical 稳定、SHA-256 封存、内容边界）→ TestReportSchemaAndCanonical + TestContentBoundary；AC-3（专家分钟与自动化耗时分列同报告、发现约定可测）→ TestExpertAndAutomationFace + TestFindRunArtifacts；AC-4（五冻结面 184 方法零改动全绿、全离线、diff 恰 3 Add）→ Done Commands 2/5/6/7 + TestHygieneAndSurface。

**Not-covered（全团队不得扩张；= CA §Not-covered 1-10）**：PR3-c fixture 创作；PR3-d（真实重放/cold-warm 对照/真实 token-cost/evaluator 输出真实落盘与 CLI 接线/--report 开关）；PR3-e V5 扩展；修改 `scripts/run_e2e_evaluation.py`、`run_real_world_evaluation.py`、`run_repair_evaluation.py`、`benchmarks/v4/baseline/orchestrate.py` 的任何内容（含 help 字符串）；修改扫描器/Prompt/标签/split/默认 analyzer/生产逻辑；`lima/**`、`evaluation_data/**` 任何改动；v2 evidence domain 生产端；五冻结测试文件零改动零追加；不提交任何 run 产物（测试一律 tempfile）；IP-0028 ruff legacy 债；psutil 或任何新依赖、网络、Secret、付费 LLM；#217/#57 关闭判断与 #57 PR3 行勾选。

## 2. Design Input Manifest

| 输入 | 版本 / SHA | 消费方式 |
| --- | --- | --- |
| CA-IP-0029-v1.0 | `.pv_tmp/COORDINATOR_ASSIGNMENT_IP-0029_2026-09-26.md`（2026-09-26） | 范围权威；R1-R11 全文照录进 §13 |
| Intent Record INTENT-RECORD-IP-0029-2026-09-26 | `.pv_tmp/INTENT_RECORD_IP-0029_2026-09-26.md` | 需求语义 R1-R11/I1-I6/A1-A6/Q1-Q7 |
| Source Issue #217 | GitHub issue 217（open，status:in-progress，评论 0；2026-09-26 匿名 API 亲验，CA §证据清单 2） | Scope 1-8 / Non-goals / AC-1..4 / Packet 占用 |
| Parent #57 | GitHub issue 57（open） | FR-04/05、Contract invariants、File ownership、PR3 拆解 |
| `benchmarks/v4/baseline/orchestrate.py` @8e61ddd | blob `8655067e180ffafc2ee2e8b0ca93c5531201e344` | BaselineRunSummary 六字段、run_repeats 写盘行为（R4 契约锚点；测试经它产盘） |
| `benchmarks/v4/baseline/run.py` @8e61ddd | blob `d29928e5ea6a4a737d937e649a0f24a850dea7d3` | write_exclusive 复用、OUTPUT_PATH_ALREADY_EXISTS / OUTPUT_DIRECTORY_UNAVAILABLE 呈现、run_baseline_attempt（sidecar 配对正例产盘） |
| `benchmarks/v4/baseline/expert_timing.py` @8e61ddd | blob `dd7aa3654df58382425af9dfb02cbefb7ebf0b9b` | sidecar 五字段文档 schema、active_time_ms 语义、reviewer digest-only |
| `benchmarks/v4/baseline/collect.py` @8e61ddd | blob `063ecb41e4f472e9fa7f575f7ccc358809c0f6db` | BaselineCollectionError 族（writer 错误复用呈现，零改动） |
| `benchmarks/v4/baseline/__init__.py` @8e61ddd | blob `1c478346d7543f6c7f64d5d71081c612ca50fb55` | 零改动 marker（R1） |
| `lima/baseline_run_result.py` @8e61ddd | blob `aafd02b653e0bd8e5eaada00703a0d98968ece6a` | from_mapping 解析（R4）、四百分位字段名（L486-489）、UNKNOWN_FIELD fail-closed |
| `lima/contracts/codec.py` @8e61ddd | blob `a442076db6f193a3b362cc6caf6d53d4f76570b8` | canonical_encode / compute_content_digest（唯一 canonical 编码器；无 float） |
| `lima/contracts/evidence.py` @8e61ddd | blob `924692f6b9336657f7a475737244fdb3e2969d25` | EvidenceDomainBundle（v2 在场判据唯一入口）、HypothesisStatus（反虚构映射禁令） |
| `lima/contracts/compat.py` @8e61ddd | blob `a58707379d199c3317363c00bef11df38163c7f1` | finding_to_domain_bundle（signals/issues legacy 投影唯一路径；1 Finding→1 Signal+1 Issue+0 Hypothesis，L170-262 亲验） |
| `lima/evaluation_harness.py` @8e61ddd | blob `5f4f91026fbf942531ba5d83fc6ac96e61b9fd1d` | e2e 输出 dict 形状（schema v1；run() L265-300 亲读） |
| `lima/real_world_evaluation.py` @8e61ddd | blob `e9ae9e3f4574a79365c485a62ed1f16788f6f435` | real-world 输出 dict 形状（schema v2；results[].deterministic.total_findings+workspace L1448-1477 亲读） |
| `lima/repository_scanner.py` @8e61ddd | blob `97b80b0c0a803c7d1e1ff67021cf34fb45d53c4f` | VERIFICATION_RANK（L32-38）、COVERAGE_AFFECTING_SKIPS（L43-51，冻结集只读 import）、collaboration 字段（L313-337）、RepositoryScanResult |
| `lima/workspace.py` @8e61ddd | blob `647567179070c16067689224ab5fba43cd60cd88` | WorkspaceInventory.skipped taxonomy |
| `lima/models.py` @8e61ddd | tracked（Finding/ReviewReport/Severity dataclass 面） | Finding.verification_state、ReviewReport.to_dict |
| 五冻结测试文件 @8e61ddd | blobs：test_v4_baseline `4cde7bdf0a76f56a2e1504483470dda4fbc3fef7`（70）/ test_v4_baseline_result `0a44cf7d41bee4756de966e77e88e5439ed386a5`（33）/ test_v4_baseline_manifest `8e8ab0dcb9fdea5a8b0a216610c5bd5dae2c92b9`（28）/ test_v4_baseline_collection `35e6ec6a497719be5495048600ea1db6802d9fc4`（26）/ test_v4_baseline_cli `edb2391bfcf3592739a3ac48e1fa5e9ddd752c60`（27）＝184 | AC-4 回归基线；测试风格镜像（`_forbidden_source_tokens` 拼接、RED 锚点先例） |
| IP-0028 收口输入 | `.pv_tmp/EVIDENCE_REVIEW_RECORD_IP-0028_2026-09-26.md`（SF-2 条目 L90-99）、`.pv_tmp/VERIFICATION_REPORT_IP-0028_2026-09-26.md` §8 | §8 收口登记依据 |
| 先例 | CA-IP-0028-v1.0、IP-0026/0027/0028 Packet、IP-0024/0025 错误族风格 | 模板与纪律 |

哈希真值来源：`git ls-tree -r 8e61ddd0f0efa4624cca138d99e4b263594327fd -- <paths>`（P&V 2026-09-26 程序化复制，未手抄）；冻结前基线 184 方法回归已由 P&V 在 C2 之前亲跑全绿（命令 0，Ran 184 tests OK，exit 0）。

## 3. Explicitly Rejected Inputs

1. "报告计数并入 BaselineRunResult 本体或 expert sidecar"——被拒：`_reject_unknown_fields` 对未知字段 fail-closed、`test_baseline_run_summary_surface` 精确断言 `_SUMMARY_FIELDS`/`orchestrate.__all__`、sidecar 契约原文 "No counting-class metric ever enters the sidecar document"（Intent I2；CA R2）。
2. "把 real-world 输出 `schema_version == 2` 当作 v2 evidence domain 在场证据"——被拒（Intent I3 反混淆；CA R2/R3）：该 2 是 real-world 输出 schema 自身版本号，与 evidence v2 domain 无关。同理 e2e 的 v1 与任何 dict 形状探嗅均不构成在场证据。
3. "把 HypothesisStatus.statically_supported 映射为 confirmed"——被拒（反虚构条款；CA R3）：v2 静态证据状态枚举明文 "none of these values means runtime verification"。
4. "改 `orchestrate.add_baseline_arguments` help 或三脚本 help/epilog 落地 SF-2"——被拒（CA R5 否决 (a)/(b)；#57 Modify 白名单与 Add 边界空档，无授权）。
5. "本切片新增 `--report` CLI 开关或基线 run 自动产报告"——被拒（CA R6）：破三冻结 wiring stdout 整 buffer 断言；接线与空 stash 行为整体后移 PR3-d。
6. "无 evaluator 载荷时产出全 null 报告"——被拒（CA R6 预置裁定）：`build_baseline_report` 的 evaluator_payload 为必填；缺载荷 → typed error。
7. "unavailable 位以 0 填充 / 资源位以 0 或估计值填充 / ratio 分母缺席时以 0 填充"——被拒（CA R2/R3 永不 0 冒充条款）。
8. "report.py 自造 canonical 编码器 / 自造聚合或 manifest 校验 / float 度量"——被拒（CA R2/R9/R11）。
9. "修改 IP-0028 Packet 文档登记 SF 收口"——被拒（C8 冻结纪律；只能在本文档 §8 新增登记）。
10. "find_run_artifacts 对不匹配模式的外来文件报错、或静默跳过损坏工件"——被拒（CA R4 fail-closed 面：外来忽略、损坏 typed error）。

## 4. Goal / Non-goals

**Goal**：为基线 run 交付独立结构、canonical、可封存的公开报告层：同一报告结构内分列呈现 FR-04 计数面（Signal、SecurityIssue、Hypothesis、confirmed/inconclusive、扫描文件、coverage gap）、原始候选→确定性告警→confirmed/inconclusive 的压缩率链、专家 active minutes 与自动化耗时（FR-05 收口）、资源与费用（离线诚实缺席）；v2 evidence domain 缺席时以显式 legacy projection 标记呈现、绝不虚构；同时收口 IP-0028 两个遗留（聚合件离线发现约定固化为契约；SF-IP-0028-20260926-2 用户可见面）。

**Non-goals**：见 §1 Not-covered（= CA §Not-covered 全文）。

## 5. 冻结接口消费清单（本轮只消费，零改动）

1. `benchmarks.v4.baseline.orchestrate.BaselineRunSummary`（attempts/result_paths/aggregate/aggregate_path/aggregate_sha256/status 六字段）与 `run_repeats`（测试经真实调用产盘）。
2. `lima.baseline_run_result.from_mapping` 与 `BaselineRunResult` 字段（status/cold_p50/cold_p95/warm_p50/warm_p95_wall_time_ms，L486-489）。
3. `benchmarks.v4.baseline.run.write_exclusive`、`BaselineCollectionError`（OUTPUT_PATH_ALREADY_EXISTS / OUTPUT_DIRECTORY_UNAVAILABLE 呈现）、`run_baseline_attempt`（expert_session 形态产盘）。
4. `benchmarks.v4.baseline.expert_timing`：sidecar 文档 schema 恰 `{schema_version, run_spec_digest, reviewer_digest, active_time_ms, events}`；reviewer 只以 digest 存在。
5. `lima.contracts.codec.canonical_encode / compute_content_digest`（唯一 canonical 编码器；JSONValue 无 float）。
6. `lima.contracts.evidence.EvidenceDomainBundle`（v2 在场判据唯一入口）与 `HypothesisStatus`。
7. `lima.contracts.compat.finding_to_domain_bundle`（signals/issues legacy 投影唯一路径）。
8. `lima.repository_scanner.VERIFICATION_RANK / COVERAGE_AFFECTING_SKIPS / RepositoryScanResult`（冻结集只读 import）。
9. `lima.evaluation_harness` / `lima.real_world_evaluation` 输出 dict 形状（识别谓词与投影矩阵依据）。
10. 五冻结测试文件 184 方法：零改动零追加；所有新测试进新文件。

## 6. 文件边界（= Assignment §Workspace Allowed Files，恰 3 路径，全部 Add）

**Add — P&V（C1/C2，本阶段交付）**：
1. `docs/LIMA_Implementation_Packet_IP-0029_Baseline_Report_Projection.md`（本文档）。
2. `tests/test_v4_baseline_report.py`（C2 冻结测试，unittest 风格，方法数 ≤35）。

**Add — Implementation（C3+）**：
3. `benchmarks/v4/baseline/report.py`——§7 公共面；禁止改任何既有文件、网络/环境读取、自造编码器/聚合实现、manifest 消费、float。

**Do Not Touch（diff 必空）**：`lima/**`、`evaluation_data/**`、`benchmarks/v4/baseline/__init__.py`、`collect.py`、`expert_timing.py`、`orchestrate.py`、`run.py`、`benchmarks/__init__.py`、`benchmarks/v4/__init__.py`、`scripts/**`、五冻结测试文件、`pyproject.toml`/`requirements.txt`/`.gitignore`/`.gitattributes`/`Dockerfile`、其余一切 tracked 文件；不提交 run 产物。

## 7. 交付物规范（Implementation 必须满足的行为契约；公共符号面在此冻结）

### 7.0 模块落位与导入面（R1/R7/R11 冻结）

新文件 `benchmarks.v4.baseline.report.py`，本切片唯一产品文件。包 `__init__.py` 零改动；消费面一律 `from benchmarks.v4.baseline import report` / `import benchmarks.v4.baseline.report` 直接导入子模块。

**report.py 导入白名单（冻结；测试 AST 断言）**：
- stdlib 根：`dataclasses`、`enum`、`hashlib`、`json`、`pathlib`、`re`、`typing`。
- 产品：`lima.contracts.codec`、`lima.contracts.evidence`、`lima.contracts.compat`、`lima.baseline_run_result`、`benchmarks.v4.baseline.collect`、`benchmarks.v4.baseline.run`、`benchmarks.v4.baseline.orchestrate`（末者仅用于 BaselineRunSummary 的 isinstance 门与类型注解，CA R7 已授权冻结）。
- 相对导入禁止（level==0）。

### 7.1 错误族（R8 + P&V 冻结最终集与逐字消息）

`BaselineReportError(ValueError)`：属性 `code: BaselineReportErrorCode`、`field_path: str`（structure-only，如 `$.counts.signals.value`）；消息恰为目录条目，不嵌载荷、秘密、字段值、本机路径。`BaselineReportErrorCode(str, enum.Enum)` 成员名与 wire 值一致。封闭码目录（12 码，逐字消息冻结）：

| code | message（逐字） |
| --- | --- |
| SCHEMA_NAME_INVALID | Baseline report schema name is invalid. |
| SCHEMA_VERSION_INVALID | Baseline report schema version is invalid. |
| REQUIRED_FIELD_MISSING | A required baseline report field is missing. |
| UNKNOWN_FIELD | Baseline report contains an unknown field for this schema version. |
| INVALID_FIELD_TYPE | Baseline report field has an invalid type. |
| INVALID_FIELD_VALUE | Baseline report field has an invalid value. |
| INVALID_DIGEST | A digest is not a lowercase 64-character hex digest. |
| DIGEST_MISMATCH | A digest does not match the content it summarizes. |
| EVALUATOR_PAYLOAD_UNRECOGNIZED | The evaluator payload matches no frozen evaluator output shape. |
| EVALUATOR_PAYLOAD_INVALID | The evaluator payload violates its frozen output shape. |
| SIDECAR_INVALID | An expert-timing sidecar document is invalid. |
| ARTIFACT_UNREADABLE | A baseline run artifact file could not be parsed. |

工件写出的目录缺失/路径已占用错误经复用呈现为冻结 `BaselineCollectionError(OUTPUT_DIRECTORY_UNAVAILABLE / OUTPUT_PATH_ALREADY_EXISTS)`（collect.py 封闭 10 码零改动，不另造码；见 §7.8）。

### 7.2 公共符号面（冻结；测试精确断言）

```python
__all__ = [
    "BASELINE_REPORT_SCHEMA_NAME",
    "BASELINE_REPORT_SCHEMA_VERSION",
    "BASELINE_REPORT_DECLARATIONS",
    "BaselineReport",
    "BaselineReportError",
    "BaselineReportErrorCode",
    "ReportFileArtifacts",
    "RunArtifactEntry",
    "build_baseline_report",
    "find_run_artifacts",
    "from_mapping",
    "write_report_file",
]
```

常量（冻结字面）：`BASELINE_REPORT_SCHEMA_NAME = "lima.baseline-report"`（独立命名空间，先例 `lima.evidence-domain`）；`BASELINE_REPORT_SCHEMA_VERSION = 1`（不复用 BaselineRunResult 的 v1 或 real-world 输出自身的 `schema_version: 2`）；`BASELINE_REPORT_DECLARATIONS = ("baseline_mode_legacy_report_parameters_inert",)`（封闭枚举 v1 恰此一值，SF-2 收口，见 §7.9/§8）。

函数签名（冻结）：

```python
def build_baseline_report(
    summary,                # orchestrate.BaselineRunSummary（isinstance 门）
    evaluator_payload,      # object，必填（R6 预置裁定：缺载荷不允许构建报告）
    *,
    expert_sidecars=(),     # typing.Iterable[dict]；每个为 sidecar 文档
    bundle=None,            # lima.contracts.evidence.EvidenceDomainBundle | None
) -> BaselineReport: ...

def from_mapping(mapping) -> BaselineReport: ...          # 严格校验 + 冻结（§7.4）
def write_report_file(report, output_dir) -> ReportFileArtifacts: ...
def find_run_artifacts(directory, *, prefix=None) -> tuple[RunArtifactEntry, ...]: ...
```

数据类（frozen dataclass + slots）：
- `BaselineReport`：恰 16 字段，名与序冻结——`schema_name, schema_version, run_spec_digest, aggregate_sha256, aggregate_status, attempt_count, evidence_domain, legacy_projection, declarations, sources, counts, coverage_gap_reasons, compression_chain, expert, automation, resources`。方法面：`to_canonical_value()`（全新建普通 dict/list 树，与内部状态零共享）、`canonical_bytes()`（= `canonical_encode(self.to_canonical_value())`，只经 codec）、`content_digest()`（= `compute_content_digest(self.canonical_bytes())`）。嵌套面为模块内 frozen slots dataclass，字段名与 JSON 键一致（不进 `__all__`）：`SourceEntry(kind, payload_sha256)`、`CountEntry(value, projection)`、`RatioLink(numerator, denominator, ratio_basis_points)`、`CompressionChain(raw_candidates, deterministic_alerts, confirmed, inconclusive, candidates_to_deterministic, deterministic_to_confirmed)`、`ExpertFace(active_time_ms_total, sessions, reviewer_digests)`、`AutomationFace(cold_p50_wall_time_ms, cold_p95_wall_time_ms, warm_p50_wall_time_ms, warm_p95_wall_time_ms)`、`ResourcesFace(prompt_tokens, completion_tokens, cost_micro_usd)`。`counts`（7 键 → CountEntry）与 `coverage_gap_reasons`（str → int）为深不可变只读映射视图：下标/len/迭代/成员读取行为等同普通 dict，一切变更尝试 fail-closed（IP-0025 `_FrozenMapping` 先例）；`declarations`/`sources`/`reviewer_digests` 为 tuple。
- `ReportFileArtifacts(report_path: pathlib.Path, report_sha256: str)`。
- `RunArtifactEntry(digest16: str, sequence: int, result_path: pathlib.Path, sidecar_path: pathlib.Path | None, sample_count: int, is_aggregate: bool)`。

构造纪律：BaselineReport 仅经 `build_baseline_report` / `from_mapping` 构造（完整校验在这两条路径执行；直接 dataclass 构造不属于公共契约）。

### 7.3 报告文档 schema（R2 逐字冻结；实现偏差 = Stop Condition 7）

```
BaselineReport（frozen dataclass，slots，仅经 build/validate 构造）
{
  "schema_name": "lima.baseline-report",          # 冻结字面
  "schema_version": 1,
  "run_spec_digest": <64hex>,                     # 来自 summary.aggregate.run_spec_digest
  "aggregate_sha256": <64hex>,                    # 来自 summary.aggregate_sha256（与 aggregate.content_digest() 交叉校验，不一致→DIGEST_MISMATCH fail closed）
  "aggregate_status": "sufficient_sample"|"insufficient_sample",
  "attempt_count": int >= 1,                      # len(summary.attempts)
  "evidence_domain": "v2"|"legacy",               # 判据见 §7.6
  "legacy_projection": bool,                      # = (evidence_domain == "legacy")，报告级标志（双层之上层）
  "declarations": ["baseline_mode_legacy_report_parameters_inert"],  # 封闭枚举，v1 恰此一值（SF-2 收口）
  "sources": [ {"kind": "e2e"|"real-world"|"scanner"|"evidence-domain",
                "payload_sha256": <64hex>} ],      # 注入面指纹（摘要+哈希原则：载荷以摘要进场，内容不进场）
  "counts": {                                      # 计数面（R1/FR-04）；每个位置 = {"value": int|null, "projection": "measured"|"legacy_projection"|"unavailable"}
    "signals", "security_issues", "hypotheses",
    "confirmed", "inconclusive",
    "scanned_files", "coverage_gap"
  },
  "coverage_gap_reasons": { "<reason>": int, ... }, # 键 ∈ COVERAGE_AFFECTING_SKIPS（冻结集，只读 import），按 key 排序；仅 coverage_gap>0 的原因出现
  "compression_chain": {                            # R3 冻结定义
    "raw_candidates": int|null, "deterministic_alerts": int|null,
    "confirmed": int|null, "inconclusive": int|null,
    "candidates_to_deterministic": {"numerator": int|null, "denominator": int|null, "ratio_basis_points": int|null},
    "deterministic_to_confirmed":  {同上}
  },
  "expert": { "active_time_ms_total": int|null,     # 各 sidecar active_time_ms 之和；零 sidecar→null（不是 0）
              "sessions": int,                      # 消费的 sidecar 数（可为 0）
              "reviewer_digests": [<64hex>] },      # 排序去重；只有摘要，绝无 reviewer 原文 id
  "automation": { "cold_p50_wall_time_ms": int|null, "cold_p95_wall_time_ms": int|null,
                  "warm_p50_wall_time_ms": int|null, "warm_p95_wall_time_ms": int|null },  # 逐字段透传 summary.aggregate 四百分位（insufficient→null）
  "resources": { "prompt_tokens": null, "completion_tokens": null, "cost_micro_usd": null }  # 离线诚实缺席；真实实测=PR3-d
}
```

补充冻结（值域与顺序）：
- `sources` 条目按 `kind` 升序排列（每 kind 至多一条：evaluator 载荷一条 + bundle 在场时 `evidence-domain` 一条）；无重复。
- `coverage_gap_reasons` 键升序；仅收录计数 > 0 的 coverage-affecting skip 原因；`coverage_gap` 为 null 或 0 时该映射为空；非 null 时 Σ值 == `counts.coverage_gap.value`。
- `reviewer_digests` 升序去重。
- **无自由文本保证（AC-2 结构层）**：文档内不存在任何自由文本字符串——每个字符串要么是 64-hex 摘要、要么是固定枚举字面（`lima.baseline-report`/状态/domain/projection/kind/declaration）、要么是 skip 原因键（`^[a-z][a-z0-9-]{0,63}$` 且 ∈ COVERAGE_AFFECTING_SKIPS）。由构造保证：无源码片段、无日志、无凭据、无本机路径能进入报告字节（负例测试仍做字节级断言）。
- **资源与费用 None 语义**：三位置恒为 null；不得以 0 或估计值填充。
- **摘要+哈希粒度**：仅聚合级单文档。无 case 级内容、无 per-sample 转储、无 findings 列表、无事件序列——底层样本细节以 `aggregate_sha256` 回指；evaluator 载荷以 `payload_sha256` 指纹进场。
- **无 float**：报告全文 int/str/bool/null/容器；压缩率以整数基点表达（§7.5）。

### 7.4 `from_mapping` 严格校验（冻结）

- 输入非 dict → `INVALID_FIELD_TYPE "$"`；缺字段 → `REQUIRED_FIELD_MISSING`；多余字段 → `UNKNOWN_FIELD`（嵌套每层同样执行）。
- `schema_name` 非 str 或 != `"lima.baseline-report"` → `SCHEMA_NAME_INVALID "$.schema_name"`；`schema_version` 非 int（bool 排除）或 != 1 → `SCHEMA_VERSION_INVALID "$.schema_version"`。
- 摘要字段非 64-hex 小写 → `INVALID_DIGEST`（`$.run_spec_digest`、`$.aggregate_sha256`、`sources[i].payload_sha256`、`expert.reviewer_digests[i]`）。
- 枚举域：`aggregate_status` ∈ {sufficient_sample, insufficient_sample}；`evidence_domain` ∈ {v2, legacy}；`counts.*.projection` ∈ {measured, legacy_projection, unavailable}；`sources[i].kind` ∈ {e2e, real-world, scanner, evidence-domain}；违者 `INVALID_FIELD_VALUE`。
- 交叉校验（违者 `INVALID_FIELD_VALUE`）：`legacy_projection == (evidence_domain == "legacy")`；`declarations == BASELINE_REPORT_DECLARATIONS`（恰一值封闭）；`counts.*.projection == "unavailable"` ⇔ `value is null`（非 unavailable ⇒ 非 null）；`coverage_gap_reasons` 空 ⇔ `counts.coverage_gap.value ∈ {null, 0}` 且非空时 Σ值 == value；`expert.sessions == 0` ⇔ `active_time_ms_total is null` 且 `reviewer_digests` 空；`aggregate_status == "sufficient_sample"` ⇔ automation 四字段全 int（insufficient ⇔ 全 null，all-or-nothing）；`resources` 三字段必须全 null（v1）。
- `compression_chain`：链位 int≥0 或 null；每链接三字段全 null，或 numerator/denominator 为 int≥0 且 `ratio_basis_points` 满足 §7.5 语义（`ratio_basis_points` 为 null 当且仅当 numerator/denominator 任一为 null 或 denominator == 0；非 null 时 == numerator*10000//denominator）。
- `counts` 恰 7 键；`sources` 无重复 kind 且按 kind 升序；`coverage_gap_reasons`/`reviewer_digests` 升序；键 ∈ COVERAGE_AFFECTING_SKIPS。

### 7.5 投影语义：识别谓词、投影矩阵、inconclusive 定义、压缩率（R3 逐字冻结 + P&V 冻结谓词）

**统一规则**：`build_baseline_report` 每份报告消费恰好一个 evaluator 载荷（+ 可选 bundle + sidecar 序列）；多载荷/混合 → typed error。载荷种类经结构化严格识别（错认/歧义 → fail closed）。

**识别谓词（冻结；三种形状两两不可混同——scanner 非 dict、e2e 与 real-world 的 schema_version 互斥）**：

- `scanner`：`evaluator_payload` 为非 dict 对象且具有 `report` 与 `inventory` 属性 → 识别为 scanner 载荷；深层校验（违者 `EVALUATOR_PAYLOAD_INVALID`）：`report` 具 `findings`（list，元素为 `lima.models.Finding` 实例）与 `collaboration`（dict，含 `scanned_files` int≥0 与 `skipped` dict[str,int≥0]）；`inventory` 具 `to_dict`。
- `e2e`：dict 且 `schema_version == 1` 且含 `name/metrics/by_split/case_results/dataset` 全部五键，且 `metrics` 为 dict 且 `tp/fp/fn` 为 int（bool 排除）且 ≥ 0 → 识别为 e2e 载荷。
- `real-world`：dict 且 `schema_version == 2` 且含 `mode/scanner_profile/metrics` 全部三键，且 `results` 为 list 且每一项为 dict，其 `deterministic.total_findings` 为 dict（每值 int≥0）、`deterministic.workspace` 为 dict 且每个 revision 值为含 `files`（int≥0）与 `skipped`（dict[str,int≥0]）的 dict → 识别为 real-world 载荷。
- 其余一切（含 `None`、修复 evaluator 输出、schema_version 3、缺键 dict、双形状均不满足的 dict）→ `EVALUATOR_PAYLOAD_UNRECOGNIZED "$.evaluator_payload"`。

**"inconclusive" 定义（报告契约自定义，上游无明文——在此冻结）**：以 scanner 验证阶梯（`VERIFICATION_RANK`：candidate→syntax-verified→corroborated→dataflow-verified→confirmed，冻结于 repository_scanner.py L32-38）为准：
- `confirmed` = `verification_state == "confirmed"`；
- `inconclusive` = `verification_state ∈ {"candidate", "syntax-verified"}`（已提出但未达任何确定性佐证态）；
- `deterministic_alerts` = `verification_state ∈ {"corroborated", "dataflow-verified", "confirmed"}`。
**阶梯完备分割不变量**：`raw_candidates == deterministic_alerts + inconclusive`（五态互斥完备）。此定义是报告契约对 FR-04 语义的显式投影约定（不回写任何上游文档）。

**压缩率链**：链位 `raw_candidates / deterministic_alerts / confirmed / inconclusive` + 两个比率链接 `candidates_to_deterministic = deterministic_alerts / raw_candidates`、`deterministic_to_confirmed = confirmed / deterministic_alerts`。每链接 = `{numerator, denominator, ratio_basis_points}`；`ratio_basis_points = numerator * 10000 // denominator`（整数 floor，确定性，无 float；分母为 0 或分子分母任一为 null → null，绝不为 0）。

**逐源投影矩阵（逐字冻结；"—"=null+"unavailable"）**：

| 报告位 | scanner 注入 | e2e dict 注入 | real-world dict 注入 |
| --- | --- | --- | --- |
| signals | `len(findings)`，经冻结 compat 面 `finding_to_domain_bundle` 逐 Finding 转换后计数（1 Finding→1 Signal），标记 `legacy_projection` | —（无 Finding 对象，compat 面不可用） | —（matching findings 是 dict，无 Finding 对象） |
| security_issues | 同上（1 Finding→1 SecurityIssue），`legacy_projection` | — | — |
| hypotheses | —（compat 面不产出 VulnerabilityHypothesis——每 bundle 恰 1 Signal+1 Issue+0 Hypothesis） | — | — |
| confirmed | 阶梯计数，`legacy_projection` | —（e2e 输出无阶梯） | —（阶梯仅匹配子集可见，混入将错报总体） |
| inconclusive | 阶梯计数，`legacy_projection` | — | — |
| scanned_files | `collaboration["scanned_files"]`，`measured` | —（无工作区面） | Σ over cases×revisions `deterministic.workspace[rev]["files"]`，`measured` |
| coverage_gap（及 reasons） | Σ `collaboration["skipped"][r]`，r ∈ COVERAGE_AFFECTING_SKIPS（冻结集只读 import），`measured` | — | Σ over cases×revisions 同式于 `workspace[rev]["skipped"]`，`measured` |
| chain: raw_candidates | `len(findings)` | `metrics["tp"] + metrics["fp"]`（reviewer 全量告警面） | Σ over cases×revisions `deterministic.total_findings[rev]` |
| chain: deterministic_alerts / confirmed / inconclusive | 阶梯计数（见上） | — | — |

**domain 在场时（合成 bundle 注入）**：`signals/security_issues/hypotheses = len(bundle.signals/security_issues/vulnerability_hypotheses)`，标记 `measured`；`evidence_domain="v2"`、`legacy_projection=false`；confirmed/inconclusive 与链仍按上表（v2 静态证据状态枚举 HypothesisStatus 明文 "none of these values means runtime verification"，禁止把 statically_supported 映射为 confirmed——反虚构条款）。

**payload_sha256 指纹规则（区别于 canonical 工件编码）**：evaluator dict 载荷（e2e/real-world）以 stdlib `json.dumps(payload, sort_keys=True, separators=(",",":"), ensure_ascii=False, allow_nan=False).encode("utf-8")` → `hashlib.sha256` 小写 hex（载荷含 float，codec 不可用于输入指纹；此为输入指纹规则，非第二 canonical 编码器——报告工件本身仍只经 codec）。scanner 对象载荷：经冻结 to_dict 面取得 wire 值——`{**payload.report.to_dict(), "workspace": payload.inventory.to_dict()}`（即 `RepositoryScanResult.to_dict()` 语义；等价 stub 提供同名 to_dict 面即可）——后同规则指纹。evidence-domain 载荷：`bundle.to_dict()` 后同规则指纹。同载荷 → 同指纹，可从载荷独立复算。

**build 校验序（冻结）**：summary 形状门（isinstance `orchestrate.BaselineRunSummary`，非者 `INVALID_FIELD_TYPE "$.summary"`；attempts 非空且 digest/status 形状合法，违者 `INVALID_FIELD_VALUE`）→ 聚合交叉校验（`summary.aggregate_sha256 != summary.aggregate.content_digest()` → `DIGEST_MISMATCH "$.aggregate_sha256"`）→ sidecar 序列门（§7.7）→ bundle 门（非 None 且非 EvidenceDomainBundle 实例 → `INVALID_FIELD_TYPE "$.bundle"`）→ 载荷识别（UNRECOGNIZED）→ 载荷深层校验（INVALID）→ 投影 → 构造。构造结果必须通过 §7.4 全部校验（等价于 from_mapping 可无损往返）。

### 7.6 legacy projection 双层 + v2 缺席判据（R2 逐字冻结）

**v2 domain 缺席判据（显式、结构化，不做探嗅）**：`evidence_domain = "v2"` 当且仅当调用方注入了一个通过 `lima.contracts.evidence` 自身冻结校验的 `EvidenceDomainBundle` 实例（isinstance 判定；bundle 的合法性由其构造器保证，报告层不重造校验）；否则 `"legacy"`。禁止把 real-world 输出的 `schema_version == 2`、e2e 的 v1、或任何 dict 形状探嗅当作 v2 domain 在场证据（I3 反混淆）。今日无任何 producer，注入测试用合成 bundle 覆盖在场分支。

**legacy_projection 双层形态**：报告级 `legacy_projection` bool + 字段级 `projection` 三值标记（`measured` = 从注入原生表面按其自身语义直接计数；`legacy_projection` = v2 domain 语义目标经冻结映射从 legacy 表面投影；`unavailable` = 无忠实推导 → value 必须 null）。永不用 0 冒充未知：unavailable ⇒ null；0 只能出现在真实计得为 0 的 measured/legacy_projection 位置。字段归属：`signals/security_issues/hypotheses/confirmed/inconclusive` 属 v2 语义目标（domain 缺席时带 legacy_projection 或 unavailable 标记）；`scanned_files/coverage_gap` 是工作区事实（无论 domain 在场与否均为 `measured`——把它们标成 legacy_projection 反而语义失真；全局缺席状态由报告级 bool 承载）。

### 7.7 expert face（sidecar 消费面，冻结）

`build_baseline_report(..., expert_sidecars=<iterable of sidecar 文档>)`：
- 每个 sidecar 必须是恰含五字段 `{schema_version, run_spec_digest, reviewer_digest, active_time_ms, events}` 的 dict，`schema_version == 1`，`run_spec_digest` 为 64-hex 且 == summary 的 run_spec_digest（不匹配 → `SIDECAR_INVALID`），`reviewer_digest` 64-hex，`active_time_ms` int≥0，`events` list；多层未知字段 fail-closed；违者 `SIDECAR_INVALID`（field_path `$.expert_sidecars[i]...` structure-only）。
- `active_time_ms_total` = 各 sidecar `active_time_ms` 之和（零 sidecar → null，不是 0）；`sessions` = sidecar 数（可为 0）；`reviewer_digests` = 排序去重摘要列表，绝无 reviewer 原文 id。

### 7.8 报告工件落盘 `write_report_file`（R10 冻结）

`write_report_file(report, output_dir) -> ReportFileArtifacts(report_path, report_sha256)`：
- 文件名 `{run_spec_digest[:16]}-report-{n}.json`，n = 该前缀下 `-report-` 族最小未占正整数（仅探测 report 名；与 `-run-` 族名字不重叠、无碰撞）。
- payload 恰 `report.canonical_bytes()`；独占创建经复用 `benchmarks.v4.baseline.run.write_exclusive`（绝不覆盖；占用 → 冻结 `BaselineCollectionError(OUTPUT_PATH_ALREADY_EXISTS)`）。
- 摘要 = `compute_content_digest(payload_bytes)`。
- 目录必须已存在（缺失 → 冻结 `BaselineCollectionError(OUTPUT_DIRECTORY_UNAVAILABLE, "$.output_dir")`，复用不另造）。
- 路径绝不进入报告文档（AC-2）。
- `find_run_artifacts` v1 只发现 `-run-` 族（§7.9）；report 族发现留待需要时扩展（登记，不做）。

### 7.9 聚合件离线发现 `find_run_artifacts`（R4 冻结 + P&V 细化）

`find_run_artifacts(directory, *, prefix=None) -> tuple[RunArtifactEntry, ...]`——把 IP-0028 运行时约定固化为可测纯函数契约，零修改 orchestrate.py：
- **命名模式（冻结）**：result 文件 `^([0-9a-f]{16})-run-([1-9][0-9]*)\.json$`；sidecar 同 stem + `.expert-timing.json`。
- **发现语义（冻结）**：仅收录名字完整匹配 result 模式的文件；经冻结 `lima.baseline_run_result.from_mapping` 解析取 `sample_count = len(samples)`、`is_aggregate = sample_count > 1`；sidecar 按 stem 配对（在场且合法 → `sidecar_path`，否则 None）；返回条目按 `(digest16, sequence)` 升序。
- **fail-closed 面**：不匹配模式的文件忽略（目录归用户所有，外来文件非错误）；匹配 result 模式但内容不可经 `from_mapping` 解析 → `ARTIFACT_UNREADABLE`（field_path `$.artifact`，structure-only，不嵌路径；`BaselineRunResultError` 被转译为该 typed error，不得静默跳过损坏的基线工件）；sidecar 存在但非合法 sidecar 文档（JSON 不可解码，或非恰五字段/schema_version!=1/digest 非 64-hex/active_time_ms 非 int≥0/events 非 list）→ 同族 `ARTIFACT_UNREADABLE`。
- **孤儿 sidecar 语义（P&V 在 R4 冻结返回形状内的澄清，登记）**：无对应 result 的 sidecar 不产生条目、不报错（IP-0028 已知残留态如实呈现为"缺席"而非错误；返回形状已冻结为 result 键控条目，孤儿无 result 不可成条）。
- **prefix 参数**：可选 digest16 过滤（供 PR3-d 消费）；默认全量。
- **契约文本（冻结进 Packet）**："同一 digest16 前缀下序号最大的多样本（samples>1）result 文件即该前缀最近一次编排 run 的聚合件，其 samples 恰为该 run 全部 attempt 结果按 attempt_index 排序；单样本文件为逐 attempt 结果"。
- **测试锚定**：正例必须经真实 `orchestrate.run_repeats`（stub execute+sources）产盘后用 `find_run_artifacts` 找回并正确识别聚合件（不用手写文件冒充——契约锚定真实写盘行为）；sidecar 配对正例经真实 `run_baseline_attempt`（expert_session 形参）产盘。

### 7.10 declarations 封闭枚举与 SF-2 收口（R5 冻结）

1. **报告面（工件级）**：`declarations` 字段封闭枚举 v1 恰一值 `baseline_mode_legacy_report_parameters_inert`——每份报告工件字节内可读到惰性声明（机器可读、无自由文本、canonical 稳定）。
2. **PR 正文（流程级）**：Implementation PR 正文必须含以下冻结句（一字不差，中英各一）：
   - EN: "In baseline mode (--run-spec), the legacy report parameters (--output / --output-dir) are inert; --baseline-output is the only output channel."
   - CN: "基线模式（--run-spec）下，legacy 报告参数（--output / --output-dir）为惰性；--baseline-output 是唯一输出通道。"
   并在 PR 正文登记 SF-IP-0028-20260926-2 收口引用（本 Packet §8 + CA R5）。

### 7.11 零 manifest 消费（R9 冻结）

v1 报告层不消费 manifest（构建面只需 summary/sidecar/evaluator 载荷/bundle——均已在上游门后），故 dataset→role 门在本切片无新入口；SF-01 纪律以可测的空缺证明落地：源扫描断言 report.py 不含 `baseline_manifest` / `validate_baseline_manifest` / `evaluation_data` token。**对 PR3-d 的约束性登记：任何后续为报告层引入 manifest 消费的入口必须复用冻结 `validate_role_bindings` 门。**

### 7.12 离线与依赖纪律（R11 冻结）

全离线：无网络、无 Secret、无付费、无环境读取；stdlib-only（允许集 = §7.0 导入白名单）；report.py + 测试文件纳入 offline hygiene 源扫描（token 拼接避免自匹配）；无新依赖、无新配置文件、无 Dockerfile 改动；测试一律 tempfile，不提交 run 产物。

## 8. IP-0028 SF-2 与 known gap 收口登记节（不修改 IP-0028 Packet——C8 冻结纪律，先例 fd37d4e）

| 项 | 登记内容 | 落点 |
| --- | --- | --- |
| SF-IP-0028-20260926-2（基线模式惰性声明用户可见面） | CA R5 裁定选 (c) 等效面：(1) 报告工件 `declarations` 封闭枚举恰一值 `baseline_mode_legacy_report_parameters_inert`（§7.10）；(2) Implementation PR 正文含 R5 冻结句（EN+CN 一字不差）并引用本节。否决 (a)（改 `orchestrate.add_baseline_arguments` help）与 (b)（三脚本级 help/epilog）理由：#57 File ownership 的 Modify 白名单字面不含 help 编辑、`benchmarks/v4/baseline/` 对 #57 是 Add 边界（orchestrate.py 已存在，修改落入 Add/Modify 空档无授权）；I6 证实 --help 非字节冻结面（风险纯在授权面）；(c) 零源码触碰且满足 Evidence Review 最小回应与 #217 "--help 或等效" 显式授权。若后续 Maintainer 指名要求 help 文本落点，另走 DR（占 ≤1 决策预算）。 | report.py declarations + PR 正文（本 Packet §7.10） |
| IP-0028 known gap：聚合件离线发现约定 | CA R4 裁定：report.py 内纯函数 `find_run_artifacts`（§7.9），把 run_repeats 的"目录前后差集"运行时约定固化为可测契约，零修改 orchestrate.py；正例锚定真实 run_repeats 产盘。 | report.py find_run_artifacts + TestFindRunArtifacts |

## 9. Done Commands（= Assignment §验收命令全文；worktree 根执行，Windows 设 `PYTHONUTF8=1`）

```bash
# 0. 冻结前基线绿（C2 之前先跑一次并登记）
python -m unittest -v tests.test_v4_baseline tests.test_v4_baseline_result tests.test_v4_baseline_manifest tests.test_v4_baseline_collection tests.test_v4_baseline_cli
# 1. 定向新测试（C2 冻结时全 RED 且归因 benchmarks.v4.baseline.report 缺席；C-final 后全绿）
python -m unittest -v tests.test_v4_baseline_report
# 2. 五冻结文件回归（70+33+28+26+27=184 必须全绿）
python -m unittest -v tests.test_v4_baseline tests.test_v4_baseline_result tests.test_v4_baseline_manifest tests.test_v4_baseline_collection tests.test_v4_baseline_cli
# 3. 编译
python -m compileall -q lima benchmarks tests scripts
# 4. 质量门禁（新增 py 文件）
python -m ruff check --no-cache benchmarks/v4/baseline/report.py tests/test_v4_baseline_report.py
python -m bandit -q benchmarks/v4/baseline/report.py
# 5. 文件边界：恰等于 Allowed Files 3 路径
git diff --name-only 8e61ddd0f0efa4624cca138d99e4b263594327fd..HEAD
# 6. 冻结面/生产面守护（预期空）：除 report.py 外的一切
git diff 8e61ddd0f0efa4624cca138d99e4b263594327fd..HEAD -- lima evaluation_data scripts \
  benchmarks/__init__.py benchmarks/v4/__init__.py benchmarks/v4/baseline/__init__.py \
  benchmarks/v4/baseline/collect.py benchmarks/v4/baseline/expert_timing.py \
  benchmarks/v4/baseline/orchestrate.py benchmarks/v4/baseline/run.py \
  tests/test_v4_baseline.py tests/test_v4_baseline_result.py tests/test_v4_baseline_manifest.py \
  tests/test_v4_baseline_collection.py tests/test_v4_baseline_cli.py \
  pyproject.toml requirements.txt .gitignore .gitattributes Dockerfile
# 7. 产物守护（预期空；测试一律 tempfile）
git diff --name-only --diff-filter=A 8e61ddd0f0efa4624cca138d99e4b263594327fd..HEAD -- '*.json' ':!docs' ':!tests'
# 8. ancestry（P&V 终验；<Frozen-Test-Commit-SHA> 由 C2 登记）
git merge-base --is-ancestor <Frozen-Test-Commit-SHA> HEAD && echo ANCESTRY-OK
```

成功判据（全部满足才算本切片 GREEN）：AC-1 计数字段与压缩率链由注入 evaluator 载荷确定性投影（三源矩阵全覆盖；scanner 源链值 + 分割不变量）；legacy projection 双层显式标记；hypotheses 及一切无忠实推导位 = null + unavailable，绝无 0 冒充、绝无虚构。AC-2 报告 canonical 字节稳定（同输入两次逐字节一致）且 SHA-256 可从字节独立复算；字节级断言不含本机路径/源码片段/凭据/reviewer 原文。AC-3 专家 active minutes 与自动化耗时分列同一报告；聚合件发现约定经真实 run_repeats 产盘后可测地找回（含聚合件识别与负例）。AC-4 五冻结文件 184 方法零改动全绿；本切片 diff 恰 3 个 Add 路径；全离线。

失败判据（任一命中即未达标）：任一 fail-closed 负例未以预期稳定码拒绝；任一 unavailable 位出现非 null 值或 measured 位出现虚构值；ratio 在分母缺席时为 0 而非 null；报告字节含路径分隔符/盘符/注入片段子串；canonical 字节不稳定或摘要不可复算；发现约定在真实产盘上识别错误或对外来文件报错/对损坏工件静默；冻结面 diff 非空；diff 超 3 路径或含 Modify；测试方法数 >35；出现网络/Secret/付费/新依赖/float 度量/manifest 消费；提交 run 产物。

## 10. 测试矩阵（`tests/test_v4_baseline_report.py`，C2 冻结，28 方法 ≤ 35 上限）

RED 锚点：模块级 `import benchmarks.v4.baseline.report as report` → `ModuleNotFoundError: No module named 'benchmarks.v4.baseline.report'`（包存在、子模块缺席；镜像 IP-0027/0028 冻结头先例）；不得是语法/环境/依赖损坏。

| 测试类 | 映射 | 方法（28） |
| --- | --- | --- |
| TestReportSchemaAndCanonical | AC-2/FR-04 | test_canonical_bytes_stable_and_digest_recomputable；test_roundtrip_from_mapping_and_unknown_field_rejected；test_schema_name_and_version_invalid_rejected；test_document_value_types_no_floats_no_free_text；test_report_surface_frozen |
| TestProjectionScanner | AC-1/FR-01 | test_scanner_counts_and_partition_invariant；test_scanner_coverage_face_and_reasons；test_scanner_projection_marks_and_hypotheses_unavailable |
| TestProjectionE2E | AC-1/FR-01 | test_e2e_projection_raw_only_and_fingerprint_recomputable |
| TestProjectionRealWorld | AC-1/FR-01 | test_realworld_projection_and_v2_anticonfusion |
| TestLegacyProjectionMarking | AC-1/FR-02 | test_legacy_absent_marks_and_null_not_zero；test_synthetic_bundle_measured_and_no_static_promotion |
| TestCompressionRatios | AC-1/FR-01 | test_ratio_basis_points_floor_arithmetic；test_ratio_null_not_zero_and_subset_invariants |
| TestExpertAndAutomationFace | AC-3/FR-03 | test_expert_face_sum_sessions_digests；test_zero_sidecar_active_time_null；test_automation_passthrough_and_resources_null |
| TestContentBoundary | AC-2/FR-04 | test_report_bytes_exclude_paths_fragments_credentials |
| TestReportWriter | FR-04 | test_writer_naming_payload_and_resequence；test_writer_directory_and_collision_errors |
| TestFindRunArtifacts | AC-3/FR-05 | test_discovery_after_real_run_repeats；test_sidecar_pairing_via_real_attempt；test_foreign_ignored_prefix_filter_and_orphan；test_corrupted_result_and_sidecar_fail_closed |
| TestFailClosedNegatives | AC-1/AC-4 | test_payload_none_and_unrecognized_shapes；test_malformed_payload_matrix；test_sidecar_and_summary_digest_negatives |
| TestHygieneAndSurface | AC-4/FR-07/FR-08 | test_import_whitelist_and_offline_tokens；test_zero_manifest_consumption_and_declarations_closed |

负例矩阵最低集对照（CA §新测试文件矩阵，缺一即 C2 不完整）：缺 v2 domain 标记 → TestLegacyProjectionMarking.test_legacy_absent_marks_and_null_not_zero；real-world v2 反混淆 → TestProjectionRealWorld.test_realworld_projection_and_v2_anticonfusion；畸形注入 fail-closed（e2e/real-world/scanner/双形状歧义/None 载荷）→ TestFailClosedNegatives 前两法；sidecar 摘要不匹配 → test_sidecar_and_summary_digest_negatives；泄露拒绝（路径/片段/凭据/reviewer 原文）→ TestContentBoundary + test_expert_face_sum_sessions_digests；canonical 稳定 → test_canonical_bytes_stable_and_digest_recomputable；发现约定负例（外来忽略/损坏 fail-closed/孤儿 sidecar）→ TestFindRunArtifacts 后两法；ratio null-not-zero → test_ratio_null_not_zero_and_subset_invariants；declarations 封闭 → test_zero_manifest_consumption_and_declarations_closed + test_report_surface_frozen；零 manifest 消费源扫描 → test_zero_manifest_consumption_and_declarations_closed。

## 11. Stop Conditions（停止并提交 Decision Request 给 Coordinator；= Assignment §Known Gaps and Stop Conditions）

1. 需要触碰任何 Do Not Touch 路径，或第 4 个及以后 Allowed File（含"只改一行 help"——R5 已裁定 (c)，改 help 走 DR）。
2. 投影矩阵某位无法在不虚构的前提下确定（如发现某表面计数语义歧义）——不得以猜测定值。
3. canonical 编码无法仅经 lima.contracts.codec 完成（如某必需值形状超出 JSONValue）。
4. 发现约定与 run_repeats 真实写盘行为存在不可调和差异（契约必须描述现行为，不得要求改 orchestrate）。
5. 需要 manifest 消费、网络、Secret、付费模型、psutil 或任何新依赖、float 度量。
6. 测试方法数无法压进 35 且无法合并断言（冻结前）；或 184 冻结回归出现非预期失败。
7. schema 字段/错误码与 §7.1-§7.4 冻结清单冲突且无法照录（Packet 冻结面即本 Assignment 清单 + P&V 冻结细化，偏离=回到 Coordinator）。
8. base SHA 之后 main 出现冲突性实现或 IP-0029 占用冲突。
9. 需要消耗 Maintainer 决策的任何事项（预算 ≤1，预期 0）。

已知缺口（如实登记 Ledger gap 行）：零真实 run（投影证明面为注入测试）；evaluator 输出真实捕获/落盘/CLI 接线（--report 或等效）留 PR3-d（R6；空 stash 行为=预置裁定"无载荷不构建报告"）；真实 token/cost=None（PR3-d）；v2 domain 生产端不存在（消费面以合成 bundle 注入测试）；hypotheses 计数在 domain 缺席时恒 null+unavailable（compat 面不产出——结构性事实，非缺陷）；real-world/e2e 源的链中段缺席（表面无阶梯，诚实 null）；修复 evaluator（run_repair_evaluation）不进识别面（其计数语义属修复维度，V5/后续再议）。

## 12. Mechanical Test Correction Allowance（ALLOWED_ONCE）

**ALLOWED_ONCE**（随 CA-IP-0029-v1.0 一次性授出，不得出错后补写）。P&V 可在不新增 Coordinator 调用的情况下自行纠正一次纯测试机械缺陷并重新冻结，条件五项全满足：①不改产品语义、公共接口、稳定错误码或文件范围；②仅限 fixture/arrange/import/lint/测试基础设施缺陷；③旧 Frozen Commit 保留；④修正前缺陷证据、修正后有效 RED、新 Frozen Commit 完整记录；⑤Implementation 未参与测试修改。涉及产品行为、验收语义或文件范围 → Decision Request，不得以本授权消化。

## 13. Decision Record（Coordinator 裁定登记，R1-R11 全文照录，依据 CA-IP-0029-v1.0）

### R1（Q1）报告模块落位与包导出策略

新文件 `benchmarks/v4/baseline/report.py`，本切片唯一产品文件。包导出策略沿用既有先例：`benchmarks/v4/baseline/__init__.py` 是"加零公共符号"的 marker（IP-0027 立例），不修改它；消费面一律 `from benchmarks.v4.baseline import report` / `from benchmarks.v4.baseline.report import ...` 直接导入子模块（与 collect/expert_timing/run/orchestrate 完全一致）。理由：① #57 File ownership 的 Add 面明确含 `benchmarks/v4/baseline/`；② 同包已有四个分模块先例，命名一致性最大化；③ 改 `__init__.py` 无收益且引入一个额外 diff 路径（它在 IP-0028 Do-Not-Touch 清单内，保持零触碰更稳）。

### R2（Q2）报告 schema 冻结

裁定总则：报告是独立结构（C2：计数类字段不得进 BaselineRunResult 本体——其 `_reject_unknown_fields` 对未知字段 fail-closed，且 `test_baseline_run_summary_surface` 精确断言 `_SUMMARY_FIELDS` 元组与 `orchestrate.__all__` 集合；也不进 expert sidecar——契约原文 "No counting-class metric ever enters the sidecar document"）。报告文档使用独立 schema 命名空间：`schema_name = "lima.baseline-report"`（字符串字面冻结，先例 `lima.evidence-domain`）+ `schema_version = 1`；不复用 BaselineRunResult 的 v1 或 real-world 输出自身的 `schema_version: 2`（后者是其输出 schema 版本，与 evidence v2 domain 无关——Intent I3 反混淆条款）。编解码与 SHA-256 只经 `lima.contracts.codec`（canonical_encode/compute_content_digest），不实现自有编码器（codec 无 float——报告全文 int/str/bool/null/容器，压缩率以整数基点表达）。字段集冻结清单、字段值域与无自由文本保证、v2 domain 缺席判据、legacy_projection 双层形态、资源与费用 None 语义、摘要+哈希粒度——全文照录于 §7.3/§7.6（Assignment R2 原文逐字保留，P&V 未改动任何语义）。

### R3（Q3）投影源映射表、"inconclusive" 定义与压缩率分子分母

统一规则（每份报告恰一个 evaluator 载荷；结构化严格识别三形状）与逐字段裁定全文照录于 §7.5（识别谓词为 P&V 按 R3 "C1 Packet 冻结精确识别谓词与畸形拒绝码" 授权细化；投影矩阵、inconclusive/confirmed/deterministic_alerts 阶梯定义、完备分割不变量、ratio_basis_points 整数 floor 语义、domain 在场分支、反虚构禁令、payload_sha256 指纹规则均为 R3 原文照录或授权细化）。

### R4（Q5 前置·IP-0028 遗留）聚合件离线发现约定

`benchmarks/v4/baseline/report.py` 新增纯函数 `find_run_artifacts(directory, *, prefix=None)`，把 IP-0028 运行时约定固化为可测契约，零修改 orchestrate.py（其 `run_repeats` 的"目录前后差集"实现保持原样——描述现行为契约，不引入新 API 到冻结模块）。命名模式、发现语义、契约文本、fail-closed 面、测试要求、prefix 参数全文照录于 §7.9（孤儿 sidecar 语义为 P&V 在冻结返回形状内的澄清登记）。

### R5（Q5）SF-2 收口：选 (c) 等效用户可见面

两处精确落点（均为新增文本，符合 Evidence Review "PR 正文或 PR3-b 报告面补一句用户可见声明；不可改 Packet（冻结）" 的最小回应，且 #217 Scope 6 "--help 或等效" 明文授权等效路径）：(1) 报告面（工件级）：R2 schema 的 `declarations` 字段，封闭枚举 v1 恰一值 `baseline_mode_legacy_report_parameters_inert`；(2) PR 正文（流程级）：EN/CN 冻结句（§7.10 逐字）并登记 SF-IP-0028-20260926-2 收口引用。否决 (a)/(b) 的理由：① #57 File ownership 的 Modify 白名单字面仅容纳三脚本"新增 --run-spec/--output/--repeat 参数"，help 字符串编辑不在其中；`benchmarks/v4/baseline/` 对 #57 是 Add 边界——orchestrate.py 已存在，修改它落入 Add/Modify 两清单的空档，无授权；② I6 已证 --help 非字节冻结面——(a)/(b) 技术上不破 184 测试，风险纯在授权面；③ (c) 零源码触碰且完全满足 Evidence Review 最小回应与 #217 "或等效" 授权。本裁定行使 Intent P1 已授权裁定，不消耗 Maintainer 决策。若后续 Maintainer 指名要求 help 文本落点，另行走 DR。C1 Packet 专设 §8 收口登记节——不修改 IP-0028 Packet 文档本身。

### R6（Q6）CLI 集成深度：本切片最小化

不动三脚本、不动 orchestrate、不加 --report；报告函数独立 + 注入测试；接线归 PR3-d。本切片交付库函数面：`build_baseline_report(...)`（纯投影）+ 报告工件写出 + `find_run_artifacts`。兼容性论证（本轮源码亲验）：三个 TestScriptWiring 测试 assertEqual 整个 stdout buffer 为单行且 `entry.assert_called_once()`——任何自动报告打印都会破断言；wiring 测试的 `_fake_summary()` 桩形态若被自动报告消费将立即崩溃。空 evaluator stash 行为（预置裁定，供 PR3-d 直接消费）：无 evaluator 载荷时不允许构建报告（evaluator_payload 为必填；缺载荷 → typed error，不得产出全 null 报告冒充）。

### R7（Q7）测试组织：单新文件，≤35 方法

`tests/test_v4_baseline_report.py`（unittest 风格，镜像五冻结文件先例；五冻结文件零追加）。类划分见 §10（方法切分由 P&V 定：28 方法）。RED 锚点与 Pre-Freeze Harness Gate 沿用先例。

### R8 错误族

report.py 自建独立错误族（ValueError 子类 + `field_path` structure-only + 稳定消息目录），不扩 `collect.py` 的封闭 10 码（整文件零改动），不复用 BaselineRunResultError。12 码封闭集与逐字消息由 P&V 冻结于 §7.1。消息不嵌载荷、秘密、字段值、本机路径。工件写出的碰撞错误经复用 `write_exclusive` 呈现为冻结 `BaselineCollectionError(OUTPUT_PATH_ALREADY_EXISTS)`（文档化，不另造码）。

### R9（FR-07/SF-01）零 manifest 消费的空缺证明

v1 报告层不消费 manifest，SF-01 纪律以可测的空缺证明落地（§7.11）。对 PR3-d 的约束性登记照录。

### R10 报告工件落盘：独立命名族 + 复用独占写纪律

`write_report_file(report, output_dir) -> ReportFileArtifacts(report_path, report_sha256)`：命名/独占/摘要/目录门/探测范围全文照录于 §7.8。`find_run_artifacts` v1 只发现 `-run-` 族。

### R11（FR-08/M 约束）离线与依赖纪律

全离线：无网络、无 Secret、无付费、无环境读取；stdlib-only（允许集见 §7.0）；report.py+测试文件纳入 offline hygiene 源扫描（token 拼接避免自匹配）；无新依赖、无新配置文件、无 Dockerfile 改动。测试一律 tempfile，不提交 run 产物。

## 14. Completion Summary 模板（Implementation 交付时）与 PR 纪律

Completion Summary 必含：final SHA；变更文件（对照 3 Allowed Files）；AC→Test→Result 逐项映射；实际执行命令与输出统计（passed/failed/skipped/exit code）；边界检查（命令 5/6/7 输出）；已知限制（§11 缺口清单）；Stop Condition 状态（应全部未触发）。

PR 纪律：单一 Implementation PR（Draft→Ready→merge commit；不 amend/force/squash；逐路径 git add）。**PR 正文必须含 §7.10 两条冻结句（EN+CN 一字不差）与 SF-IP-0028-20260926-2 收口引用（§8）**。commit/PR/merge title 不得含自动关闭关键词与 #217/#57 编号组合（否定句同样禁止；"Related to" only）。Implementation 交付后不建 PR、不改 Issue/Ledger（P&V 验证 PASS 后按授权形成）。

## 15. Packet completion definition

本 Packet 就绪条件：CA Q1-Q7 全部裁定并照录（无 TBD）；公共符号面/错误码目录与逐字消息/识别谓词/schema 字段表/投影矩阵/发现契约/工件命名全部冻结（§7）；测试矩阵冻结（§10，28 方法）；Done Commands 全文（§9）；Stop Conditions 与 ALLOWED_ONCE（§11/§12）；IP-0028 收口登记（§8）。**状态：READY-FOR-CODE（待 C2 冻结测试完成后由主会话派发 Implementation）。**
