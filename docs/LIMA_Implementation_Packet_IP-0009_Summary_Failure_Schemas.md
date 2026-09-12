# LIMA Implementation Packet IP-0009:Summary + Failure Schemas(结论对)

> Packet ID:`IP-0009`
>
> 状态:`DESIGN-FROZEN / READY-FOR-CODE WHEN THIS PACKET IS MERGED TO MAIN`
>
> Source Issue:[#58](https://github.com/agent-sec-labs/LIMA/issues/58) 的第九个独立实现切片(第八个 domain 切片,V5-FR-01 收官结论对:工作流终局摘要 + 失败事实报告)
>
> 最低代码基线:Assignment 基线 `be1b890bed87a0610d20cc2dbe3d8eee36e7620e`(IP-0008 实现 PR #129 squash merge);实现基线必须是包含本 Packet 与正式交接书的最新 `origin/main`
>
> 推荐分支:`codex/ip-0009-summary-failure-schemas`(依 lifecycle §9.1 从 Frozen Test Commit 派生)
>
> Owner:唯一 Implementation Agent;不得与任何活动 IP 并行修改 `lima/contracts/` 或 `tests/contracts/`

## 需求映射(Header)

```text
Source Issue:#58
Issue specification revision:正文修订 2026-09-01T14:36:22Z(V4 基线 + V5 覆盖层,冲突以 V5 节为准);
  Delivery Ledger v32 @ 2026-09-06T09:09:22Z(定序终审:IP-0009 = Summary + Failure,V5-FR-01 尾款)
Covered requirements:V5-FR-01 的 Summary、Failure 两 schema 子集(完成后 V5-FR-01 全部 schema 就绪,
  仅余聚合证据);**NFR-01 后半句的完整契约证明**(timeout/OOM/tool_error 的最终结构化载体 = Failure,
  永不编码安全结论);**V5-AC-02 机器断言面**(blocked/failed ≠ safe/refuted/verified:失败/结论词表
  分离 + 引用互斥);**V5-FR-05 契约层禁止面**(legacy success 不得自动映射为 full-chain success:
  SummarySourceKind 双值 + 引用词表按来源互斥——DR-IP0009-DESIGN-03);支撑性覆盖 FR-05(两 schema
  fixtures)、FR-06(current/future-minor)、NFR-02、AC-04
Not covered requirements:V5-FR-04 场景 fixtures(聚合阶段);PR4 legacy adapter 实现与接线(本 IP 只交付
  "不自动迁移"的契约禁止面);PR3 类(JSON Schema 文件/兼容矩阵/ADR);FR-02 manifests 子集;
  #90(V5-N01)runtime 全部实现职责;#68 生产层改造;closure IP;consumer review ×4 调度;
  修改任何既有十模块(含 workflow 的 FailureKind 六值占位)
Delivery role:domain
Issue closure impact:PARTIAL(合并后不触发 #58 closure;#58 保持 open)
Upstream IP/PR/merge commits:
  IP-0001..0006 见 Ledger(#97..#113 链)
  IP-0007 #126 `a647251` / 冻结 v3 `52eec1e` / #127 `f3acc72`(IP-DONE)
  IP-0008 #128 `b1e07a1` / 冻结 v2 `8e6a9b6` / #129 `be1b890`(IP-DONE,post-merge PASS @ `be1b890`)
Activation gate:lifecycle 入口 consumer review(见 §1,已完成,无 Contract Gap)
```

---

## 0. 执行决策

当前执行队列(Ledger v32,2026-09-06):

```text
DONE
IP-0001(+R1)、IP-0002..0008(全部 IP-DONE,9/9)

NOW(只允许 1 个)
IP-0009 Summary + Failure Schemas(Design Frozen;文档合并后进入阶段二测试冻结)

NEXT(不得实现)
V5-FR-01 聚合证据补全 / Ledger Review 重排(manifests、场景 fixtures、PR3/PR4、closure IP 候选)

LATER
manifests 子集、V5-FR-04 场景 fixtures、PR3(矩阵/ADR)、PR4(legacy adapter)、closure IP、
consumer review 调度(#60/#61/#66/#70)
```

本 Packet 只建立可被 #90/#68(WorkflowSummary/FailureReport 的运行时生产者与消费者)与 PR4(legacy 投影)消费的确定性 Summary/Failure 两份 Artifact 契约。它不实现投影、迁移接线、调度或任何生产逻辑。

---

## 1. IP-0008 消费者评审结论(lifecycle 入口 Gate,只读)

### 1.1 已验证事实(@ main `be1b890`,P&V 实证,2026-09-06)

- **基线复现**:contracts **369/369**、全量 **714 / 0 failed / 1 既有 skip**(post-merge 同 commit 亲跑);`ruff check --no-cache` exit 0;冻结面 18/16/15/12/12/12/27/**16**/29;十三 golden 字节核验;
- **execution consumer review(Assignment §7-1,焦点;P&V 于 IP-0008 验证期通读全部 782 行,本期复核关键面)**:`ArtifactLink`(ReferenceKind 字面量 + 三元组)+ `_require_link_lineage` 类型化双向核对是可复制模式;**`plan_revision` 镜像先例**(int ≥1 与 digest 钉死共同表达版本)确立"引用 + 标量镜像"的复合表达范式;**资源 id 未类型化存在性核对**(`$.payload.resource_artifact_ids[i]`)确立"schema 未冻结引用的存在性"范式——本 IP 的 legacy ids 与 evidence ids 直接沿用;
- **八模块适用面核对(Assignment §7-2)**:common/codec/errors 复用;evidence/profile/aep/vep/rvr 经 Summary.evidence 以类型化链接引用(四领域 kind);workflow 经 workflow/stage-attempt/security-outcome 三字面量引用;**FailureKind 衔接面预研**:workflow.FailureKind 六值(environment/tool_error/timeout/out_of_memory/policy_denied/internal)已冻结(DR-IP0007-DESIGN-02),衔接 = 本地枚举 wire 值逐值相等(PlanMode≡WorkflowMode 先例,IP-0008 已实战)——**零 workflow.py 修改**;
- **确认:summary 模块无需 import 任何领域模块。**

**结论:不存在阻塞 IP-0009 的 Contract Gap。** IP-0008 满足其 IP-DONE 的消费者评审入口条件;十模块在 IP-0009 消费视角下均无需修改。

### 1.2 本 Packet 的兼容决策(冻结)

延续 IP-0002..0008 既定模式(适用部分),并针对结论对扩展:

1. 只新增 `lima/contracts/summary.py`,不修改任何既有模块与 `lima/contracts/__init__.py`;
2. **依赖方向冻结:`summary.py → {codec, common, errors}`,不 import 任何领域模块**;领域引用一律经本地 `ArtifactLink`(自有 `SummaryReferenceKind` 八值字面量枚举)+ Envelope lineage 双重表达;未类型化 id(legacy/evidence)走存在性核对(execution 资源 id 先例);
3. 复用 **29** 个 `ContractErrorCode`;复用 Envelope/inline-only;schema 版本 4.0 全规则;classification 禁 public、retention 禁 ephemeral;
4. 两 schema 独立成 Envelope artifact:`lima.workflow-summary`、`lima.failure-report`;
5. **零自由文本、零时间、零计量、零 float、零结论镜像**(Summary 不镜像 SecurityOutcome 的 kind——经类型化链接 digest 钉死引用,DR-IP0007-DESIGN-08 纪律);
6. **FailureKind 衔接 = 本地枚举 wire 值与 workflow.FailureKind 逐值相等**(不 import;六值即 NFR-01 点名类别,不再细分——DR-IP0009-DESIGN-02);
7. **V5-FR-05 禁止面 = SummarySourceKind 双值 + 引用词表按来源互斥**(chain ⇒ 类型化引用且 security_outcome 必填;legacy_audit ⇒ 全部类型化链接禁用、仅未类型化 legacy ids ≥1)——legacy success 在结构上不可表达为 full-chain success(DR-IP0009-DESIGN-03);
8. **Disposition 单枚举**:`permanent`(不重试)/`transient`(外层 lease 策略可重试)——V5-N01 与 V5 §13.3(FR-N03-04"标明 permanent/retryable")的 permanent/retryable 二分先例;不设双字段避免伪两可(DR-IP0009-DESIGN-04);
9. ExecutionStatus 三值(succeeded/failed/cancelled):V5 §4.3 五值中 queued/running 属在途任务、非终局摘要;blocked 属 stage 级(DR-IP0009-DESIGN-08)。

---

## 2. Design Input Manifest

| Input ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001..003 | Standard/Charter | 稳定标准 / lifecycle / P&V 责任书 | main `be1b890` | 分工、拓扑、冻结纪律 | normative | — |
| DI-004 | Issue(Assignment) | PKT-IP-0009 Coordinator Assignment | Ledger v32 @ 2026-09-06 | 覆盖/不覆盖、§5 设计义务、§10 十二问、九项 Checklist | normative | — |
| DI-005 | Issue | #58 正文 | 修订 `2026-09-01T14:36:22Z` | V5-FR-01 尾款、V5-FR-05、V5-AC-01/02、NFR-01 后半句 | normative | V5 节优先 |
| DI-006 | Issue(Ledger) | #58 Delivery Ledger v32 | `2026-09-06T09:09:22Z` | 定序终审、基线数字、九项 Checklist 登记 | normative(current) | — |
| DI-007 | Decision | DR 正本(#58 评论:5505168221…5557510175 全链) | 2026-09-02..06 | 重冻结先例、八/九项 Checklist 渊源、DESIGN-DR 链 | normative | — |
| DI-008 | Upstream IP | IP-0001..0008 Packets + 各 merge | #97..#129 | 三元组/类型化 lineage/未类型化 id 三范式;wire 等值枚举先例(PlanMode);版本语义二分(编排族 supersedes 耦合 vs 域 artifact 无 revision);NON_CONCLUSION 分区 | normative | — |
| DI-009 | Architecture | V5 规划文档(#58 指定 Source of truth) | 本地工作树副本 | §4.3(三维终态)、§5.2(WorkflowSummary/FailureReport 最低内容)、§4.1/行 794(legacy 投影不回填)、行 819/826(permanent/retryable 二分与 FailureReport 标明面)、§13.1(N01 重试纪律) | normative(经 #58 V5 覆盖层转正) | 与 #58 正文冲突以 #58 为准 |
| DI-010 | Code | `lima/contracts/` 十模块 | main `be1b890` | §1 consumer review;validator 风格 | current-behavior | 代码事实让位于 Packet 目标行为 |
| DI-011 | Test | `tests/contracts/` 全部 | main `be1b890` | 测试风格、369 基线 | current-behavior | — |
| DI-012 | Evidence | IP-0008 POST-MERGE + 本期基线复现 + golden 预计算 | 2026-09-06 | 369/714/冻结面/十三 golden;四新 golden | evidence | — |
| DI-013 | Issue | #90 正文(V5-N01) | `.pv_tmp/` 镜像 | runtime 消费面与豁免边界(background) | background-only | — |

### Explicitly Rejected Inputs

| 材料 | 拒绝原因 |
|---|---|
| V5 §5.2 WorkflowSummary 的 cost/gaps 字段 | 计量属 aep.budget 唯一先例(DR-IP0008-DESIGN-08);gaps 已有 Envelope `coverage_gaps`(IP-0001)表达面 |
| FailureReport 的 root cause/policy 自由文本字段 | 零自由文本纪律(DR-IP0007-DESIGN-06);根因/策略由 owner + evidence ids 承载 |
| Failure 自有更细失败词表(超出六值)+ 映射表 | 六值即 NFR-01 点名类别(DR-IP0007-DESIGN-02 占位的完整语义);更细词表 = 无冻结需求的新真值源;映射表制造两可 |
| Summary 镜像 security outcome kind / vep verdict 的字段 | DR-IP0007-DESIGN-08 纪律(引用不可解析;镜像制造虚假保证) |
| Summary 携带 queued/running 状态或 Blocked 值 | 终局摘要语义;在途状态属 #90 runtime;blocked 属 stage 级 AttemptStatus |
| legacy_audit 携带任何类型化链接 | V5-FR-05 互斥面的结构性要求(legacy 流从未产生新平台 artifact);放宽即破坏禁止面 |
| permanence + retryability 双字段 | 二者双射(V5-N01/FR-N03-04 二分),双字段制造伪两可;单枚举 Disposition |
| 未冻结 schema(legacy report/sandbox log/queue DL)进入类型化词表 | 存在性核对范式(execution 资源 id 先例);类型化由 PR4/manifests IP 收紧 |
| float/confidence/severity/时间戳/计量 | 无 float 契约;全平台唯一时间 = Envelope created_at |
| V4 backlog、未引用本地文档、"28/13"笔误口径 | 历次 Packet 已登记拒绝 |

---

## 3. Iteration Hypothesis 与 Measurement

### 3.1 Hypothesis

如果终局结论被冻结为一对确定性 schema——Summary 只做引用聚合(按来源互斥的词表:chain 必携 security_outcome 类型化引用,legacy_audit 仅未类型化 ids)与三值执行状态声明,Failure 只以六值失败类别 × 作用域 × 二分处置 + 未类型化证据 ids 表达失败事实——那么"legacy success 被读成 full-chain success""失败被读成安全结论""摘要重复裁决 artifact 终态"这类结论阶段真值事故在契约层就没有合法表达。

### 3.2 Measurement

- 四个固定 golden(1333/218/535/681 bytes)固定 canonical bytes 与 SHA-256;引用链全部由 IP-0001 codec 对上游 golden 实算;
- 来源互斥、scope 耦合、词表成员、排序/唯一/上限的非法组合全部 fail closed;
- Failure 词表与 SecurityOutcomeKind 词表不相交且无 safe/clear/not_vulnerable 子串(机器断言);
- 新模块导入不加载 DB/网络/Docker/LLM/legacy models 与十领域模块中任何一个;既有 714 测试无新增失败。

---

## 4. Goal

实现 `lima.contracts.summary` 叶子模块:2 常量、6 枚举(SummarySourceKind 2 / ExecutionStatus 3 / FailureKind 6 / FailureScope 2 / FailureDisposition 2 / SummaryReferenceKind 8)、`ArtifactLink`/`WorkflowSummary`/`FailureReport` 三 dataclass、8 个 decode/encode 函数、四个 golden fixture、负向边界测试、import isolation 与 legacy regression。

---

## 5. Non-goals

#90 runtime、PR4 legacy adapter 实现与接线、V5-FR-04 场景 fixtures、manifests、PR3、closure、生产接线、LLM/网络/IO、自由文本/时间/计量/float、修改十模块或既有测试、下一 IP 定序。

---

## 6. 工作树与分支前置条件

Coding Agent 必须:完整阅读稳定标准、lifecycle、Implementation Agent 责任书、本 Packet、`LIMA_Coding_Agent_IP-0009_正式开发任务交接.md`、`CONTRIBUTING.md`;确认两份 IP-0009 文档均已合并到 `origin/main`;依 lifecycle §9.1 从 Frozen Test Commit 派生 `codex/ip-0009-summary-failure-schemas` 独立干净 worktree;确认 `lima/contracts/summary.py`、3 个测试文件、4 个 fixture 尚不存在;输出 Scope Confirmation 后再运行 baseline;不一致时停止提交 Decision Request。根工作树未跟踪文件属用户资产。

---

## 7. 文件边界

### 7.1 Files to Add(恰好 8 个)

```text
lima/contracts/summary.py
tests/contracts/test_summary.py
tests/contracts/test_summary_envelope.py
tests/contracts/test_summary_import_isolation.py
tests/contracts/fixtures/workflow_summary_v4_golden.json
tests/contracts/fixtures/workflow_summary_legacy_v4_golden.json
tests/contracts/fixtures/failure_report_v4_golden.json
tests/contracts/fixtures/failure_report_alternates_v4_golden.json
```

### 7.2 Files Allowed to Modify

```text
none
```

### 7.3 Files Forbidden

除上述 8 个新增文件外全部禁止,特别包括:`lima/contracts/{__init__,errors,codec,common,evidence,profile,aep,vep,rvr,workflow,execution}.py`;IP-0001..0008 的任何测试或 fixture;legacy/生产层;frontend/、requirements*.txt、pyproject.toml、.github/、PROGRESS.md;任意范围外文档。

### 7.4 Ownership 与冲突边界

`summary.py` 唯一 Owner;`__all__` 恰 19 symbols 冻结;依赖方向 `summary.py → {codec,common,errors}`;其余 lima 模块不得 import summary(直至消费 IP 冻结其入口)。

---

## 8. Allowed / Forbidden Dependencies

`summary.py` 只允许导入:

```text
collections.abc.Mapping
copy
dataclasses
enum
hmac
re
typing
unicodedata

lima.contracts.codec
lima.contracts.common
lima.contracts.errors
```

测试只允许额外使用 stdlib:`hashlib`、`json`、`pathlib`、`subprocess`、`sys`、`unittest`。Forbidden:任何第三方包;`lima.contracts.{evidence,profile,aep,vep,rvr,workflow,execution}` 与 `lima.models` 及生产层;HTTP/socket/DB/Docker/subprocess(产品)/文件系统(产品);UUID/时间/随机/环境变量;绝对路径。

---

## 9. 冻结的公共 Symbols

`lima/contracts/summary.py` 的 `__all__` 必须严格等于以下集合,不多不少(**19** 项;已逐项点数——强制 Checklist 第 3 条):

```python
__all__ = [
    "WORKFLOW_SUMMARY_SCHEMA_NAME",
    "FAILURE_REPORT_SCHEMA_NAME",
    "SummarySourceKind",
    "ExecutionStatus",
    "FailureKind",
    "FailureScope",
    "FailureDisposition",
    "SummaryReferenceKind",
    "ArtifactLink",
    "WorkflowSummary",
    "FailureReport",
    "decode_workflow_summary_payload",
    "encode_workflow_summary_payload",
    "decode_workflow_summary_envelope",
    "encode_workflow_summary_envelope",
    "decode_failure_report_payload",
    "encode_failure_report_payload",
    "decode_failure_report_envelope",
    "encode_failure_report_envelope",
]
```

计数:2 常量 + 6 枚举 + 3 dataclass + 8 函数 = **19**。

模块常量:

```python
WORKFLOW_SUMMARY_SCHEMA_NAME = "lima.workflow-summary"
FAILURE_REPORT_SCHEMA_NAME = "lima.failure-report"
```

---

## 10. 冻结枚举

```python
class SummarySourceKind(str, Enum):
    CHAIN = "chain"
    LEGACY_AUDIT = "legacy_audit"

class ExecutionStatus(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"

class FailureKind(str, Enum):
    ENVIRONMENT = "environment"
    TOOL_ERROR = "tool_error"
    TIMEOUT = "timeout"
    OUT_OF_MEMORY = "out_of_memory"
    POLICY_DENIED = "policy_denied"
    INTERNAL = "internal"

class FailureScope(str, Enum):
    WORKFLOW = "workflow"
    STAGE_ATTEMPT = "stage_attempt"

class FailureDisposition(str, Enum):
    PERMANENT = "permanent"
    TRANSIENT = "transient"

class SummaryReferenceKind(str, Enum):
    REPOSITORY_PROFILE = "lima.repository-profile"
    AUDIT_EVIDENCE_PACKAGE = "lima.audit-evidence-package"
    VULNERABILITY_EVIDENCE_PACKAGE = "lima.vulnerability-evidence-package"
    REPAIR_VERIFICATION_REPORT = "lima.repair-verification-report"
    WORKFLOW = "lima.workflow"
    STAGE_ATTEMPT = "lima.stage-attempt"
    SECURITY_OUTCOME = "lima.security-outcome"
    RUN_MANIFEST = "lima.run-manifest"
```

语义冻结:

- `SummarySourceKind`:chain = 新平台工作流产物;legacy_audit = legacy 审计流投影(PR4 适配期生产);互斥引用词表见 §14.2-S2/S3(V5-FR-05 禁止面);
- `ExecutionStatus`:V5 §4.3 技术执行维度的终局三值;
- `FailureKind`:**wire 值与 workflow.FailureKind 逐值相等**(本地定义、不 import;衔接面 = 字符串相等,PlanMode 先例;DR-IP0009-DESIGN-02);
- `FailureScope`:失败作用的编排对象;`FailureDisposition`:permanent = 永久失败不重试,transient = 外层 lease 策略可重试(V5-N01/FR-N03-04 二分;DR-IP0009-DESIGN-04);
- `SummaryReferenceKind`:八字面量 = 本对 schema 的全部类型化引用目标;plan 不入(Summary 经 run_manifest 间接钉定计划版本);legacy report/sandbox log/queue DL 等未冻结 schema 不入(走未类型化 id)。

---

## 11. Exact Constructors and Defaults

全部 `@dataclass(frozen=True, slots=True)`,defensive-copy:

```python
ArtifactLink(kind: SummaryReferenceKind, artifact_id: str, content_digest: str,
             schema_version: SchemaVersion, extensions: dict[str, JSONValue] = field(default_factory=dict))

WorkflowSummary(schema_version: SchemaVersion, source: SummarySourceKind,
               execution_status: ExecutionStatus,
               workflow: ArtifactLink | None = None,
               security_outcome: ArtifactLink | None = None,
               run_manifest: ArtifactLink | None = None,
               stage_attempts: tuple[ArtifactLink, ...] = (),
               evidence: tuple[ArtifactLink, ...] = (),
               legacy_artifact_ids: tuple[str, ...] = (),
               extensions: dict[str, JSONValue] = field(default_factory=dict))

FailureReport(schema_version: SchemaVersion, failure_kind: FailureKind,
             scope: FailureScope, disposition: FailureDisposition, owner: str,
             workflow: ArtifactLink | None = None,
             stage_attempt: ArtifactLink | None = None,
             evidence_artifact_ids: tuple[str, ...] = (),
             extensions: dict[str, JSONValue] = field(default_factory=dict))
```

三 dataclass 均提供 `from_dict(value, *, schema_version) -> Self` 与 `to_dict()`(执行 §14 全部校验)。

---

## 12. Exact Wire Shapes

### 12.1 WorkflowSummary payload(required 恰 **8**;nullable 字段必填出现为 `null`)

```json
{"source": "chain", "execution_status": "succeeded",
 "workflow": {"kind": "lima.workflow", "artifact_id": "wf-0001", "content_digest": "<64hex>", "schema_version": "4.0"},
 "security_outcome": {"kind": "lima.security-outcome", "artifact_id": "sec-0001", "content_digest": "<64hex>", "schema_version": "4.0"},
 "run_manifest": null, "stage_attempts": [], "evidence": [], "legacy_artifact_ids": []}
```

### 12.2 FailureReport payload(required 恰 **7**)

```json
{"failure_kind": "environment", "scope": "stage_attempt", "disposition": "transient",
 "owner": "lima-sandbox-supervisor",
 "workflow": null,
 "stage_attempt": {"kind": "lima.stage-attempt", "artifact_id": "attempt-0001", "content_digest": "<64hex>", "schema_version": "4.0"},
 "evidence_artifact_ids": ["sandbox-run-0001"]}
```

### 12.3 `ArtifactLink`

```json
{"kind": "lima.security-outcome", "artifact_id": "sec-0001", "content_digest": "<64hex>", "schema_version": "4.0"}
```

### 12.4 Extensions

4.0 任何层级 unknown field 以 `UNKNOWN_FIELD` 拒绝;未来 4.x 经 `extensions` 无损 round-trip;required 缺失与 unknown enum 即使未来 minor 也拒绝。

---

## 13. Scalar Validation

- `artifact_id`/`owner`/`legacy_artifact_ids[]`/`evidence_artifact_ids[]`:identifier 规则 `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`(NFC);
- `content_digest`:`[0-9a-f]{64}`;link 内 `schema_version`:IP-0001 parse 规则;
- enum 字段:非 str `INVALID_FIELD_TYPE`,未知值 `UNKNOWN_ENUM_VALUE`;无 bounded-text;无 float;error message 不回显原值。

---

## 14. Array Limits,Canonical Ordering 与 Cross-field Invariants

### 14.1 数组上限与排序

| Array | 上限 | 允许空 | 排序规则 |
|---|---:|---:|---|
| Summary `stage_attempts` | 256 | 是 | `artifact_id` ASCII 升序、唯一 |
| Summary `evidence` | 64 | 是 | 同上 |
| Summary `legacy_artifact_ids` | 256 | 视来源(S3) | ASCII 升序、唯一 |
| Failure `evidence_artifact_ids` | 256 | 是 | ASCII 升序、唯一 |

### 14.2 WorkflowSummary 不变量

- S1 `source ∈ SummarySourceKind`;`execution_status ∈ ExecutionStatus`;链接 kind 与字段精确绑定(workflow 字段 ⇔ WORKFLOW、security_outcome 字段 ⇔ SECURITY_OUTCOME、run_manifest 字段 ⇔ RUN_MANIFEST),违反 → `INVALID_FIELD_VALUE $.<field>.kind`;
- S2 **chain**:workflow 链接必填(`$.workflow`),security_outcome 链接必填(`$.security_outcome`),run_manifest 可空;stage_attempts 每 link kind == STAGE_ATTEMPT;evidence 每 link kind ∈ 四领域 kind;`legacy_artifact_ids` 必须为空(非空 → `INVALID_FIELD_VALUE $.legacy_artifact_ids`);
- S3 **legacy_audit**:workflow/security_outcome/run_manifest 必须 null(非 null → 对应 `INVALID_FIELD_VALUE $.<field>`),stage_attempts 与 evidence 必须为空,`legacy_artifact_ids` ≥1(空 → `INVALID_FIELD_VALUE $.legacy_artifact_ids`);
- S4 **V5-FR-05 禁止面(机器断言)**:S2 ∪ S3 使两类来源的引用词表不相交——legacy 摘要结构上不可能携带 security_outcome/vep/rvr 引用,chain 摘要结构上不可能不携带 security_outcome;"legacy success 自动映射为 full-chain success"无合法表达;
- S5 无 revision 字段(终局摘要;修正走 Envelope supersedes 通用机制)。

### 14.3 FailureReport 不变量

- F1 `failure_kind`/`scope`/`disposition` 枚举成员;`owner` identifier;
- F2 **scope 耦合**:`scope == workflow` ⇒ workflow 链接必填、stage_attempt 必须 null;`scope == stage_attempt` ⇒ stage_attempt 链接必填(kind STAGE_ATTEMPT),workflow 可空;违反 → `INVALID_FIELD_VALUE $.workflow` / `$.stage_attempt`;
- F3 链接 kind 与字段精确绑定(workflow 字段 ⇔ WORKFLOW;stage_attempt 字段 ⇔ STAGE_ATTEMPT);
- F4 `evidence_artifact_ids` 仅存在性核对(未类型化;失败证据 = 日志/运行,schema 未冻结);
- F5 **NFR-01 最终载体(机器断言)**:FailureKind 词表与 SecurityOutcomeKind 词表不相交且无 safe/clear/not_vulnerable 子串;Failure payload 无任何结论字段——timeout/OOM/tool_error 在此结构化表达且永不编码为安全结论。

### 14.4 Provenance(Envelope binding 阶段)

- Summary:全部非空类型化链接(workflow/security_outcome/run_manifest/stage_attempts/evidence)存在 lineage 条目并双向核对(schema_name == kind 字面量、schema_version 相等、digest 恒 `hmac.compare_digest`);`legacy_artifact_ids[i]` 存在性核对(缺失 → `INVALID_FIELD_VALUE $.payload.legacy_artifact_ids[i]`);
- Failure:非空 workflow/stage_attempt 链接类型化核对;`evidence_artifact_ids[i]` 存在性核对;
- lineage 允许额外条目;tenant/snapshot/self/duplicate/conflict 由 IP-0001 拒绝。

### 14.5 明确豁免清单(Registry/PR4/#90;单解)

1. Summary 所引 SecurityOutcome 的 kind 与 Summary.execution_status 的一致性——引用不可解析,Registry/消费侧(DR-IP0007-DESIGN-08 纪律);
2. legacy ids 对应 artifact 的 schema 合法性与真实 legacy 语义——PR4 适配期类型化收紧;
3. failure 重试的实际执行与 lease 策略——#90/外层策略(disposition 只是事实声明);
4. evidence/legacy id 的 schema 类型化——未来 manifest/PR4 IP;
5. Summary 的产生时机与完备性(是否穷尽全部 attempts)——#90 runtime。

---

## 15. Envelope Binding Contract

```python
def decode_workflow_summary_payload(value, *, schema_version) -> WorkflowSummary: ...
def encode_workflow_summary_payload(summary) -> dict[str, JSONValue]: ...
def decode_workflow_summary_envelope(data: bytes, *, limits=DEFAULT_LIMITS) -> tuple[ArtifactEnvelope, WorkflowSummary]: ...
def encode_workflow_summary_envelope(envelope, summary, *, limits=DEFAULT_LIMITS) -> bytes: ...
# failure_report 四函数同构
```

Binding rules 同十模块先例:schema_name 精确、inline only、以 envelope 版本 decode、§14 全部校验、§14.4 provenance、classification != public、retention != ephemeral;encode 侧另加版本/payload/digest 三重核对;不自动创建/修补 Envelope。

---

## 16. Stable Error Mapping and Precedence

复用 **29** codes;八级优先级同 §16 先例(container → required/unknown → enum/scalar type → scalar value/range/array → 内嵌对象 → 跨字段(S2/S3 → F2/F3)→ lineage provenance → envelope binding)。

`field_path` 示例:

```text
$.security_outcome
$.legacy_artifact_ids[0]
$.stage_attempts[1].kind
$.failure_kind
$.payload.security_outcome.content_digest
$.payload.evidence_artifact_ids[0]
```

---

## 17. Golden Fixture

四个文件(逐字节复制;禁止更改):

```text
tests/contracts/fixtures/workflow_summary_v4_golden.json          1333 bytes
tests/contracts/fixtures/workflow_summary_legacy_v4_golden.json   218 bytes
tests/contracts/fixtures/failure_report_v4_golden.json             535 bytes
tests/contracts/fixtures/failure_report_alternates_v4_golden.json 681 bytes
```

已由 IP-0001 codec 在 main `be1b890` 预计算;引用链使用上游 golden 真实 digest(workflow `3be59c6c…`、security_outcome `bfa0b2dc…`、run_manifest `213fbebd…`、stage_attempt `34746de4…`、alternates[0] `418c461a…`、vep `cd76622b…`、rvr `a9a35d35…`)。

### 17.1 `workflow_summary_v4_golden.json`(1333 bytes)

SHA-256:`5df80cd44cf3af456d153f967508e46b8d2a0f0595b3bb306a8fe41638cd0e34`

chain/succeeded 全引用聚合面(workflow + security_outcome + run_manifest + 两 attempts + rvr/vep evidence,真实 digest):

```json
{"evidence":[{"artifact_id":"rvr-0001","content_digest":"a9a35d358308a2957b9182d2ca5e503903d8c7282c6c43bb09d1680313cb2cac","kind":"lima.repair-verification-report","schema_version":"4.0"},{"artifact_id":"vep-0001","content_digest":"cd76622b48d11c0300e63d7489701479c75dc2f4b06cc6c4e88af1f453061d01","kind":"lima.vulnerability-evidence-package","schema_version":"4.0"}],"execution_status":"succeeded","legacy_artifact_ids":[],"run_manifest":{"artifact_id":"run-0001","content_digest":"213fbebd48a966ee9071b5a19f385731e833b17f4d8c7c653c55b2c19eaf9cd7","kind":"lima.run-manifest","schema_version":"4.0"},"security_outcome":{"artifact_id":"sec-0001","content_digest":"bfa0b2dc55940bcdadf88f8e4991adb4d762f7a8b17ded3fa8817936504ba831","kind":"lima.security-outcome","schema_version":"4.0"},"source":"chain","stage_attempts":[{"artifact_id":"attempt-audit-0001","content_digest":"418c461a1d82fcc9cbf6b60d1caad21e76491abe2d4f4a0a3a1a178cb15e8fb4","kind":"lima.stage-attempt","schema_version":"4.0"},{"artifact_id":"attempt-profile-0001","content_digest":"34746de4860ae5ce9ec69c43ad8c8ad596d4e79172a284bf3defc1a866edb259","kind":"lima.stage-attempt","schema_version":"4.0"}],"workflow":{"artifact_id":"wf-0001","content_digest":"3be59c6c7f1736954fbce5f1e74b4c7789ab8a1e956f4229904ea30bbe756146","kind":"lima.workflow","schema_version":"4.0"}}
```

### 17.2 `workflow_summary_legacy_v4_golden.json`(218 bytes)

SHA-256:`18c1faa3e058b4d5b293fd4148fa3ad5834a804c84928f868c5cc9a8b6a097d4`

**V5-FR-05 禁止面的 golden 形态**:legacy_audit/succeeded(legacy success)——全部类型化引用为 null/空、仅未类型化 legacy ids:

```json
{"evidence":[],"execution_status":"succeeded","legacy_artifact_ids":["legacy-report-0001","legacy-scan-log-0001"],"run_manifest":null,"security_outcome":null,"source":"legacy_audit","stage_attempts":[],"workflow":null}
```

### 17.3 `failure_report_v4_golden.json`(535 bytes)

SHA-256:`05a2005fd4856ff2e8e098ed6989a29aa24146b0672af086a9c3b62c07935539`

environment/transient/stage_attempt 作用域(blocked 类失败,可重试;attempt + workflow 链接真实 digest;evidence ids 存在性):

```json
{"disposition":"transient","evidence_artifact_ids":["sandbox-log-0001","sandbox-run-0001"],"failure_kind":"environment","owner":"lima-sandbox-supervisor","scope":"stage_attempt","stage_attempt":{"artifact_id":"attempt-profile-0001","content_digest":"34746de4860ae5ce9ec69c43ad8c8ad596d4e79172a284bf3defc1a866edb259","kind":"lima.stage-attempt","schema_version":"4.0"},"workflow":{"artifact_id":"wf-0001","content_digest":"3be59c6c7f1736954fbce5f1e74b4c7789ab8a1e956f4229904ea30bbe756146","kind":"lima.workflow","schema_version":"4.0"}}
```

### 17.4 `failure_report_alternates_v4_golden.json`(681 bytes)

SHA-256:`3a016bfa5b338894e989707f516b2d3535a421be90652f75318ce0ab98e20c95`

双元素数组:timeout/permanent/workflow 作用域 + tool_error/transient/stage_attempt 作用域(混合失败形态;第二元素 workflow 为 null——F2 可空面):

```json
[{"disposition":"permanent","evidence_artifact_ids":["queue-dead-letter-0001"],"failure_kind":"timeout","owner":"lima-orchestrator","scope":"workflow","stage_attempt":null,"workflow":{"artifact_id":"wf-0001","content_digest":"3be59c6c7f1736954fbce5f1e74b4c7789ab8a1e956f4229904ea30bbe756146","kind":"lima.workflow","schema_version":"4.0"}},{"disposition":"transient","evidence_artifact_ids":[],"failure_kind":"tool_error","owner":"lima-mining-harness","scope":"stage_attempt","stage_attempt":{"artifact_id":"attempt-audit-0001","content_digest":"418c461a1d82fcc9cbf6b60d1caad21e76491abe2d4f4a0a3a1a178cb15e8fb4","kind":"lima.stage-attempt","schema_version":"4.0"},"workflow":null}]
```

### 17.5 Frozen envelope vectors

```text
[summary §17.1] schema_name = lima.workflow-summary / artifact_id = summary-0001
  tenant-1 / task-1 / workflow_id = workflow-0001 / stage_attempt_id = summarize-emit-1
  snapshot "3"*64 / producer lima-orchestrator / created_at 2026-09-06T00:00:00Z
  policy "5"*64 / toolchain "6"*64 / classification internal / retention audit
  content_digest = 5df80cd4…d0e34
  lineage = [wf-0001/lima.workflow/3be59c6c…, sec-0001/lima.security-outcome/bfa0b2dc…,
             run-0001/lima.run-manifest/213fbebd…, attempt-audit-0001/lima.stage-attempt/418c461a…,
             attempt-profile-0001/lima.stage-attempt/34746de4…, vep-0001/lima.vulnerability-evidence-package/cd76622b…,
             rvr-0001/lima.repair-verification-report/a9a35d35…] / supersedes = null

[summary §17.2] schema_name = lima.workflow-summary / artifact_id = summary-legacy-0001
  其余同上 / classification internal / retention standard
  content_digest = 18c1faa3…097d4
  lineage = [legacy-report-0001/lima.legacy-report/"7"*64(未冻结 schema,存在性段),
             legacy-scan-log-0001/lima.legacy-scan-log/"8"*64(同上)] / supersedes = null

[failure §17.3] schema_name = lima.failure-report / artifact_id = failure-0001
  workflow_id = workflow-0001 / stage_attempt_id = attempt-profile-0001(失败对象)
  classification sensitive / retention audit / content_digest = 05a2005f…35539
  lineage = [wf-0001/lima.workflow/3be59c6c…, attempt-profile-0001/lima.stage-attempt/34746de4…,
             sandbox-log-0001/lima.sandbox-log/"7"*64, sandbox-run-0001/lima.sandbox-run/"9"*64] / supersedes = null
```

---

## 18. Required Tests

方法名冻结;可增不可减/改名。

### 18.1 `tests/contracts/test_summary.py`(33)

```text
SummaryEnumTests
  test_wire_values_are_exact

ArtifactLinkTests
  test_round_trip_has_exact_wire_shape
  test_rejects_missing_invalid_and_mismatched_fields

WorkflowSummaryTests
  test_minimal_chain_summary_round_trip_is_valid
  test_golden_chain_summary_round_trip_and_digest
  test_golden_legacy_summary_round_trip_and_digest
  test_rejects_wrong_container_and_missing_required_fields
  test_rejects_unknown_enum_and_wrong_field_type
  test_chain_requires_workflow_and_security_outcome_links
  test_legacy_forbids_every_typed_link
  test_legacy_requires_at_least_one_legacy_id
  test_chain_forbids_legacy_ids
  test_rejects_links_outside_field_vocabulary
  test_rejects_unsorted_duplicate_and_oversize_arrays
  test_future_minor_round_trips_unknown_fields_at_every_level
  test_current_minor_rejects_unknown_fields_at_every_level
  test_defensive_copy_prevents_post_construction_mutation
  test_payload_has_no_confidence_severity_or_verdict_bypass_fields

FailureReportTests
  test_minimal_workflow_scope_failure_round_trip_is_valid
  test_golden_failure_report_round_trip_and_digest
  test_alternates_golden_round_trip_and_digest
  test_rejects_wrong_container_and_missing_required_fields
  test_rejects_unknown_enum_and_wrong_field_type
  test_workflow_scope_requires_workflow_link_and_forbids_attempt_link
  test_attempt_scope_requires_attempt_link
  test_rejects_wrong_link_kinds
  test_owner_follows_identifier_rules
  test_rejects_unsorted_duplicate_and_oversize_evidence_ids
  test_failure_vocabulary_never_encodes_safety
  test_future_minor_round_trips_unknown_fields_at_every_level
  test_current_minor_rejects_unknown_fields_at_every_level
  test_defensive_copy_prevents_post_construction_mutation
  test_payload_has_no_confidence_severity_or_verdict_bypass_fields
```

`test_wire_values_are_exact` 须断言 FailureKind wire 值与 workflow.FailureKind **逐值相等**(硬编码清单,不 import workflow);`test_failure_vocabulary_never_encodes_safety` 须断言 FailureKind 与 SecurityOutcomeKind 十二值词表不相交、无 safe/clear/not_vulnerable 子串、blocked/failed/cancelled 仅属执行/状态词表;`test_payload_has_no…`(两处)递归禁键 `confidence/severity/risk_score/is_safe/vulnerability_resolved/safe/clear`。

### 18.2 `tests/contracts/test_summary_envelope.py`(13)

```text
WorkflowSummaryEnvelopeTests
  test_frozen_envelope_encode_decode_is_byte_stable
  test_rejects_wrong_schema_name_and_version_mismatch
  test_rejects_blob_backed_summary
  test_rejects_missing_or_mistyped_typed_lineage
  test_rejects_missing_legacy_id_lineage
  test_rejects_public_classification_and_ephemeral_retention

FailureReportEnvelopeTests
  test_frozen_envelope_encode_decode_is_byte_stable
  test_rejects_wrong_schema_name_and_version_mismatch
  test_rejects_blob_backed_failure_report
  test_rejects_missing_or_mistyped_scope_links_lineage
  test_rejects_missing_evidence_id_lineage
  test_rejects_public_classification_and_ephemeral_retention
  test_tampered_payload_fails_before_domain_promotion
```

### 18.3 `tests/contracts/test_summary_import_isolation.py`(4)

```text
SummaryImportIsolationTests
  test_module_public_api_matches_frozen_symbol_set
  test_clean_process_import_has_no_db_network_docker_llm_service_or_legacy_models
  test_module_only_uses_allowed_imports
  test_import_does_not_change_lima_contracts_top_level_public_api
```

干净子进程须断言 evidence/profile/aep/vep/rvr/**workflow/execution** 均不在 `sys.modules`。

### 18.4 Minimum count

至少 **50** 个 test methods(33+13+4)。

---

## 19. Acceptance Criteria and Traceability

| AC | Required behavior | Evidence | Requirement |
|---|---|---|---|
| SF-AC-01 | 19 symbols、6 枚举(2/3/6/2/2/8)、FailureKind≡workflow.FailureKind wire 等值 | enum/isolation tests | V5-FR-01、FR-02 |
| SF-AC-02 | identifier/digest/上限/排序 fail closed | negative tests | NFR-02 |
| SF-AC-03 | 四 golden(1333/218/535/681 B)固定 digest;真实链 | golden tests | FR-05、AC-01 |
| SF-AC-04 | 来源互斥(chain⇒SO 必填/legacy⇒全禁 + ids ≥1) | S2/S3 tests | **V5-FR-05、V5-AC-02** |
| SF-AC-05 | scope 耦合(F2)与链接 kind 精确绑定 | F-tests | FR-02 |
| SF-AC-06 | 类型化 lineage + 未类型化 id 存在性 | envelope tests | FR-02、NFR-01 |
| SF-AC-07 | Failure 词表永不编码安全(NFR-01 后半句机器面) | vocabulary test | **NFR-01、V5-AC-02** |
| SF-AC-08 | current/future-minor 每层级 | compatibility tests | FR-06 |
| SF-AC-09 | stdlib leaf;不加载十领域模块;冻结面不变 | isolation + diff | AC-04 |
| SF-AC-10 | 8 added / 0 modified / 0 deps / 回归零新增失败 | boundary + regression | AC-04 |

---

## 20. 强制实现顺序(九项 Checklist 全嵌入)

阶段二由 P&V 执行 **1-6**,Implementation Agent 从第 7 步:

1. 冻结前一致性预检(第 1/4/5/6/8/9 条):独立规则引擎 + 全负例注册表生证 + 跨用例期望一致性 + 探针负向自证;实例化镜像;helper 忠实性;调用点/签名兼容;None 哨兵审计;
2. 编写 3 测试文件 + 4 fixture(逐字节复制 §17);
3. 测试质量门禁:**GREEN 等价态(真实路径 stub)+ `--no-cache` 冷缓存**(第 7 条;RED 态结果不作依据;stub 放置/删除留痕);
4. 有效 RED(全部归因 `lima.contracts.summary` 不存在);
5. Frozen Test Commit(只推分支,严禁 PR);
6. Coordinator 出具 IMPL Assignment;
7. Implementation Agent:枚举/校验器/ArtifactLink → WorkflowSummary(S1-S5)→ FailureReport(F1-F5)→ 四 golden 逐字验证 → 8 binding functions → isolation/forbidden-key → 三 Gate → Completion Summary。

---

## 21. Done Commands

### 21.1 Baseline

```powershell
python -m compileall -q lima scripts tests
python -m unittest discover -s tests/contracts -v      # 369 PASS
python -m unittest -v tests.test_repository_source tests.test_task_failure   # 29 PASS
```

### 21.2 Slice Gate(GREEN 态 + `--no-cache`)

```powershell
python -m compileall -q lima/contracts tests/contracts
python -m unittest discover -s tests/contracts -v      # 419 ran / 0 failed
python -m ruff check --no-cache lima/contracts/summary.py tests/contracts/test_summary.py tests/contracts/test_summary_envelope.py tests/contracts/test_summary_import_isolation.py
python -m ruff check --no-cache lima/contracts tests/contracts
python -m bandit -q -r lima/contracts/summary.py
git diff --check
```

### 21.3 Compatibility Gate

```powershell
python -m unittest -v tests.test_repository_source tests.test_task_failure
python -m unittest discover -s tests -v                 # 764 = 714+50 / 1 既有 skip
```

### 21.4 File Boundary Gate

```powershell
git diff --name-only --diff-filter=ACMRTUXB <frozen-test-commit>...HEAD
```

输出恰 8 文件(产品侧仅 `lima/contracts/summary.py`)。

---

## 22. Security and Compatibility Invariants

- 来源互斥使 legacy success 结构性不可表达为 full-chain success(V5-FR-05);
- Failure 永不编码安全结论:词表与结论词表不相交、无 safe/clear/not_vulnerable、零结论字段(NFR-01 后半句最终载体);
- Summary 零结论镜像;全部类型化引用 digest 恒 `hmac.compare_digest`;未类型化 id 仅存在性;
- classification 禁 public、retention 禁 ephemeral;ID/digest/时间调用方提供;零自由文本/时间/计量/float;
- 不改十模块冻结面(18/16/15/12/12/12/27/16/29)与十三 golden;不新增权限;future-minor 不绕过任何校验。

---

## 23. Stop Conditions / Decision Request

1. 两份 IP-0009 文档未合并,或基线非 `be1b890` 后代、十一模块冻结面漂移;
2. main 出现同名 `summary.py` 或冲突 Owner(cxx 触碰 contracts);
3. 需改 forbidden 文件或扩 allowlist(含 workflow.FailureKind 修改诉求);
4. 需新增依赖/权限;
5. §10-§16 任一契约两解;
6. 四 golden 无法由 codec 复现或链不一致;
7. 需要自由文本/时间/计量/结论镜像字段,或需 PR4 接线/manifests/V5-FR-04 才能通过测试(范围上移);
8. baseline/回归失败无法归因;required tests 无法证明 AC;
9. 工作实际进入 #90/#68/PR4/closure。

---

## 24. Git, Commit and PR Contract

推荐标题 `feat: add deterministic workflow summary and failure report schemas`。PR:只写 `Implements IP-0009` + `Related to #58`;禁 auto-close;AC→Test→Result;真实命令/统计;8 added / 0 modified / 0 deps;等独立 Review 与 `merge-gate`。

---

## 25. Completion Summary Template

```markdown
## IP-0009 Completion Summary
### Result(Status / Base / Frozen / Final / Branch / Worktree)
### Scope(Added / Modified: none / Deps: none / API: lima.contracts.summary only, 19 symbols)
### Acceptance evidence(SF-AC-01..10 表)
### Commands and actual results(--no-cache GREEN 态)
### Security and compatibility(来源互斥/词表分离/lineage/隔离/回归)
### Findings and decisions
### Handoff(PR 状态/唯一下一步/禁止动作)
```

---

## 26. Maintainer Review Checklist

- [ ] 恰 8 文件;summary.py 唯一产品文件;冻结面 18/16/15/12/12/12/27/16/29 + 十三 golden 零改动;
- [ ] 19 symbols;summary→{codec,common,errors};不加载十领域模块;
- [ ] 两 schema wire(8/7 required)无漂移;FailureKind wire 等值测试通过;
- [ ] 四 golden 1333/218/535/681 B digest 一致;链 = 上游真实 digest;
- [ ] 来源互斥/scope 耦合/词表成员/排序上限 negative 全过;
- [ ] GREEN 态冷缓存 lint exit 0;forbidden-key 与词表分离测试过;
- [ ] 全量 764 = 714+50 / 1 既有 skip;File Boundary 恰 8;Completion Summary 可复现;
- [ ] PR 未关 #58;未启动 manifests/PR3/PR4/V5-FR-04/#90/#68/closure。

---

## 27. Assignment §10 十二问逐条单解(审计索引)

| # | 问题 | 单解 | 所在 |
|---|---|---|---|
| 1 | 命名/切分/共居 | 单模块 `lima/contracts/summary.py`;`lima.workflow-summary`/`lima.failure-report`;结论对共居(先例 execution) | §9/DR-01 |
| 2 | 引用结构 | Summary:5 类型化字段(2 必填按来源)+ 2 数组 + legacy ids;Failure:2 类型化(按 scope 1 必填)+ evidence ids | §14.2/14.3 |
| 3 | FailureKind 衔接 | 本地枚举 wire 值逐值相等(PlanMode 先例;不 import;零 workflow 修改) | §10/DR-02 |
| 4 | V5-AC-02 机器面 | 来源互斥引用词表 + Failure/结论词表不相交断言 + 禁键递归 | §14.2-S4/14.3-F5 |
| 5 | V5-FR-05 禁止面 | SummarySourceKind 双值 + chain⇒SO 必填 / legacy⇒全类型化禁用+ids≥1 | §14.2/DR-03 |
| 6 | 状态/不变量/豁免 | ExecutionStatus 三值;豁免五条 | §14.5 |
| 7 | 资源上限 | 256/64/256/256 逐一论证 | §14.1 |
| 8 | golden | 四件:成功摘要/legacy 摘要/失败主例/失败双形态;真实链 | §17 |
| 9 | 测试矩阵 | 50(33+13+4);isolation 含 workflow+execution 反向断言;禁键两处 | §18 |
| 10 | 错误映射 | 29 codes;八级优先级 | §16 |
| 11 | 命令/数字 | contracts 369→419;全量 714→764 | §21 |
| 12 | 环境记录 | redis-py 6.4.0 差异照登 | §21/交接书 |

---

## 28. 本 Packet 的冻结设计决策记录(Decision Records)

- **DR-IP0009-DESIGN-01(单模块结论对)**:`summary.py` 共居 WorkflowSummary + FailureReport(workflow 三 schema / execution 两 schema 共居先例;结论对同链尾、同消费者)。
- **DR-IP0009-DESIGN-02(FailureKind 衔接 = wire 值逐值相等的本地枚举)**:PlanMode≡WorkflowMode 先例(IP-0008 实战);六值即 NFR-01 点名类别(DR-IP0007-DESIGN-02 占位语义的完整兑现);不细分——V5 §5.2 "stable code" 由 owner(identifier)+ evidence ids 承载,新增更细词表 = 无冻结需求的第二真值源;"引用字面量"与"同值扩展"在本方案下同构,无两可。
- **DR-IP0009-DESIGN-03(V5-FR-05 禁止面 = 来源互斥引用词表)**:chain ⇒ security_outcome 类型化引用必填(无结论证据不得宣告链式成功);legacy_audit ⇒ 全部类型化链接禁用(legacy 流从未产生新平台 artifact)、仅未类型化 legacy ids ≥1——两个来源的引用词表不相交,"legacy success 自动映射为 full-chain success"结构性无表达;实际投影接线归 PR4。
- **DR-IP0009-DESIGN-04(Disposition 单枚举)**:V5-N01("永久 contract error 不重试;暂时性 adapter error 由外层 lease 策略重试")与 FR-N03-04("标明 permanent/retryable")是二分事实;permanent⇔non-retryable 双射使双字段退化为伪两可,单枚举 `permanent|transient` 携带全部语义。
- **DR-IP0009-DESIGN-05(零结论镜像)**:Summary 不镜像 SecurityOutcome.kind 或任何 artifact verdict(DR-IP0007-DESIGN-08);结论语义唯一真值源 = 被 digest 钉定的 SecurityOutcome artifact。
- **DR-IP0009-DESIGN-06(ExecutionStatus 三值)**:V5 §4.3 五值中 queued/running 描述在途任务(摘要按定义是终局物);blocked 是 stage 级执行状态(AttemptStatus 已冻结);终局技术维度 = succeeded/failed/cancelled。
- **DR-IP0009-DESIGN-07(未类型化 id 范式)**:legacy ids 与 evidence ids 仅存在性核对(execution 资源 id / rvr gate-evidence 先例);类型化由 PR4/manifest IP 收紧(§14.5)。
- **DR-IP0009-DESIGN-08(零自由文本/时间/计量/float 延续)**:WorkflowSummary 的 cost/gaps 由 Envelope coverage_gaps 与 aep.budget 既有表达面承载;root cause/policy 由 owner + evidence ids 承载。

---

## 29. Packet 完成定义

全部 10 AC、50 required tests、四 golden、GREEN 态冷缓存命令证据、独立 Review 与 `merge-gate` 满足后 IP-0009 实现才可标 DONE。合并后 Coordinator 在最新 main 安排 post-merge verification;**V5-FR-01 全部 schema 就绪后的 Ledger Review**(lifecycle §21)决定聚合证据路径(V5-FR-04 场景 fixtures / PR3 / PR4 / closure IP 定序)。当前 Agent 不自动继续。
