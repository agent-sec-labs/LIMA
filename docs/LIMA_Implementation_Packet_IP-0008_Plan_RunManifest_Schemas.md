# LIMA Implementation Packet IP-0008:Plan + RunManifest Schemas(执行意图对)

> Packet ID:`IP-0008`
>
> 状态:`DESIGN-FROZEN / READY-FOR-CODE WHEN THIS PACKET IS MERGED TO MAIN`
>
> Source Issue:[#58](https://github.com/agent-sec-labs/LIMA/issues/58) 的第八个独立实现切片(第七个 domain 切片,执行意图对 = 运行前计划 + 运行记录)
>
> 最低代码基线:Assignment 基线 `f3acc7284f1fe7d47bbd3f7bea45603d0f9bd592`(IP-0007 实现 PR #127 squash merge);实现基线必须是包含本 Packet 与正式交接书的最新 `origin/main`
>
> 推荐分支:`codex/ip-0008-plan-runmanifest-schemas`(依 lifecycle §9.1 从 Frozen Test Commit 派生,实现阶段 Assignment 另行出具)
>
> Owner:唯一 Implementation Agent;不得与任何活动 IP 并行修改 `lima/contracts/` 或 `tests/contracts/`(cxx 三分支 #123/#124/#125 已实证不触碰该目录)

## 需求映射(Header)

```text
Source Issue:#58
Issue specification revision:正文修订 2026-09-01T14:36:22Z(V4 基线 + V5 覆盖层,冲突以 V5 节为准);
  Delivery Ledger v27 @ 2026-09-06T04:40:10Z(定序终审:四 schema 拆分,IP-0008 = Plan+RunManifest 先行)
Covered requirements:V5-FR-01 的 Plan、RunManifest 两 schema 子集(Profile/Workflow/StageAttempt/SecurityOutcome
  已由 IP-0003/0007 交付并入账);支撑性覆盖 FR-02 的引用纪律(跨对象引用 artifact_id + content_digest +
  schema_version 三元组,经 payload 字段 + Envelope lineage 双重表达)、FR-05(两 schema 的
  minimal/full/negative/golden fixtures)、FR-06(两 schema current/future-minor 兼容)、
  NFR-02(校验上限)、AC-04(依赖隔离对新模块适用)
Not covered requirements:Summary 与 Failure schema(IP-0009 候选;若引用只允许逻辑引用或最小枚举占位
  + Decision Record,本 Packet 未引入任何占位);FR-02 manifests 子集(Task/ToolBundle/Dependency/Sandbox,
  含 MiningPlan/SandboxRunManifest 的深字段定义——V5 §5.2 表中二者属 mining/sandbox 专用 manifest,本 IP 的
  Plan/RunManifest 是跨阶段通用对,资源引用仅经未类型化 id + lineage 存在性);V5-FR-04 场景 fixtures;
  PR3 类(JSON Schema 文件/兼容矩阵/ADR)、PR4 类(legacy adapter);#90(V5-N01)全部实现职责;
  #68 生产层改造;closure IP;consumer review ×4 调度
Delivery role:domain
Issue closure impact:PARTIAL(合并后不触发 #58 closure;#58 保持 open)
Upstream IP/PR/merge commits:
  IP-0001..0006 见 Ledger(#97..#113 链)
  IP-0007 #126 `a647251` / 冻结链 v3 `52eec1e` / #127 `f3acc72`(IP-DONE,post-merge PASS @ `f3acc72`)
Activation gate:lifecycle 入口 consumer review(见 §1,已完成,无 Contract Gap)
```

---

## 0. 执行决策

当前执行队列(Ledger v27,2026-09-06):

```text
DONE
IP-0001(+R1)、IP-0002..0007(全部 IP-DONE,8/8)

NOW(只允许 1 个)
IP-0008 Plan + RunManifest Schemas(Design Frozen;文档合并后进入阶段二测试冻结)

NEXT(不得实现)
IP-0009 候选:Summary + Failure schemas(结论对;依赖本 IP)

LATER
manifests 子集(FR-02 尾)、PR3(矩阵/ADR)、PR4(legacy adapter)、V5 场景 fixtures、closure IP、
consumer review 调度(#60/#61/#66/#70)
```

本 Packet 只建立可被 #90(V5-N01 Runtime,其输入面含 WorkflowStarted/StageResult/Artifact refs/policy)与 IP-0009 消费的确定性 Plan/RunManifest 两份 Artifact 契约。它不实现调度、沙箱、工具解析、持久化或任何生产接线。

---

## 1. IP-0007 消费者评审结论(lifecycle 入口 Gate,只读)

### 1.1 已验证事实(@ main `f3acc72`,P&V 实证,2026-09-06)

- **基线复现**:contracts **323/323**、全量 **668 / 0 failed / 1 既有 skip**(post-merge 同 commit 亲跑);`ruff check --no-cache lima/contracts tests/contracts` exit 0;冻结面 18/16/15/12/12/12/**27**/29;十 golden 字节核验(六既有 + workflow 460B/`3be59c6c…`、stage_attempt 370B/`34746de4…`、alternates 1498B/`01cf64fc…`、security_outcome 589B/`bfa0b2dc…`);
- **workflow consumer review(Assignment §7-1,焦点;P&V 于 IP-0007 独立验证期通读全部 1156 行,本 Packet 期复核关键面)**:`ArtifactLink`(kind 字面量枚举 + artifact_id + content_digest + schema_version 三元组)与 `_require_lineage_provenance` 的类型化双向核对(schema_name == kind 字面量、schema_version 相等、digest 经 `hmac.compare_digest`)是**完全可复制**的本地模式——execution 模块以自有四值 ReferenceKind 重建同构类型即可,**零修改 workflow.py**;
- **引用方向裁定(无 Contract Gap 的关键论证)**:workflow 的 `ArtifactKind` 六值词表(冻结)不含 plan/run-manifest,即 workflow payload **不能**反向引用本 IP 的 artifact——这与链方向自洽:Plan(运行前,链首,只可能引用 vep)→ Workflow(执行)→ RunManifest(运行后,引用 plan + workflow + stage attempts + 未类型化资源 id);若 runtime 需在 workflow envelope 上标注 plan 关联,IP-0001 lineage 允许**非类型化额外条目**(workflow 的 `_require_lineage_provenance` 只核对 payload link、允许 extras),无需触碰冻结面;
- **三词表分区与 NON_CONCLUSION(§O4)与本 IP 的关系**:Plan/RunManifest 不携带任何结论语义——与分区纪律无交互,不新增任何安全词表(结构性远离 NFR-01 后半句,该句归 IP-0009 的 Summary/Failure);
- **身份与时间纪律**:Envelope `workflow_id`/`stage_attempt_id` 是 IP-0001 必填上下文(调用方提供);Plan/RunManifest payload **不做** payload↔envelope 身份镜像对齐(身份 = envelope artifact_id + 类型化链接;区别于 workflow/stage-attempt 的镜像规则——它们镜像的是 Envelope 专属身份字段,本对无对应物);时间字段纪律延续 DR-IP0007-DESIGN-04;
- **其余七模块适用面核对(Assignment §7-2)**:common(Envelope/ArtifactReference 额外 lineage)与 codec(digest 唯一实现)与 errors(29 codes)直接复用;evidence/profile/aep/rvr 在本对 schema 的引用词表中**均不出现**(profile 是链中产物、aep/rvr 是链后域产物,Plan 引用它们即前向引用未发生之事——fail-closed 排除,DR-IP0008-DESIGN-02);vep 经 Plan.inputs(verify_vep/repair_from_vep 模式)以类型化链接引用。**确认:execution 模块无需 import 任何领域模块。**

**结论:不存在阻塞 IP-0008 的 Contract Gap。** IP-0007 满足其 IP-DONE 的消费者评审入口条件;九模块在 IP-0008 消费视角下均无需修改。

### 1.2 本 Packet 的兼容决策(冻结)

延续 IP-0002..0007 既定模式(适用部分),并针对执行意图对扩展:

1. 只新增 `lima/contracts/execution.py`,不修改 `lima/contracts/__init__.py` 与任何既有模块;公共 API 只从 `lima.contracts.execution` 导入;
2. **依赖方向冻结:`execution.py → {codec, common, errors}`,不 import evidence/profile/aep/vep/rvr/workflow**——领域引用一律经本地 `ArtifactLink` 值类型(自有 `ReferenceKind` 四值字面量枚举)+ Envelope lineage 双重表达(workflow 模块 ArtifactLink 同构先例);identifier/digest/int 校验器本地实现(逐条等同先例);
3. 复用现有 **29** 个 `ContractErrorCode`,不扩展 `errors.py`;
4. 复用 `ArtifactEnvelope` / `decode_envelope` / `encode_envelope`;仅 inline payload;
5. schema 版本 `4.0`;未知 major fail closed;同 major 未来 minor 经各对象 `extensions` 无损 round-trip;unknown enum / required 缺失永不降级;
6. 两 schema 各自独立成 Envelope artifact:`lima.plan`、`lima.run-manifest`;
7. classification 禁 `public`;retention 禁 `ephemeral`(九模块统一先例);
8. **零自由文本、零时间字段、零资源计量、零 float**(DR-IP0007-DESIGN-04/06 纪律延续:"资源与事实清单的表达面 = 引用而非计量",DR-IP0008-DESIGN-08);
9. **planned_stages 是有序序列**(语义序即内容;不排序、不折叠;唯一性 + 词表成员校验——DR-IP0008-DESIGN-03);
10. **唯一冻结的模式×阶段耦合 = AUDIT_ONLY 排除 mine/repair**(承 DR-IP0007-DESIGN-05 的确定性论证;verify_vep/repair_from_vep 的阶段集留 #90,DR-IP0008-DESIGN-04);
11. **模式⇒输入耦合为精确双射**(V5 §4.1 结构确定性:verify_vep/repair_from_vep ⇒ 恰 vep 链接 ≥1;full_chain/audit_only ⇒ inputs 恰空——DR-IP0008-DESIGN-05);
12. **Plan 版本化 = revision ≥1 + Envelope supersedes 耦合**(编排族先例 = workflow W2;区别于域 artifact aep 的无耦合 revision);RunManifest 无 revision 字段(单次事实记录,修正走 envelope supersedes 通用机制)——DR-IP0008-DESIGN-06。

---

## 2. Design Input Manifest

| Input ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001 | Standard | 稳定开发标准(§8/§17/§12) | main `f3acc72` | 三 Agent 分工、安全不变量、验证底线 | normative | 最高优先级之一 |
| DI-002 | Standard | lifecycle | main `f3acc72` | §9.1 拓扑、§12.2 PR 契约、传输点只推分支 | normative | — |
| DI-003 | Charter | P&V 责任书 | main `f3acc72` | Packet 必答、冻结纪律、DIM 格式 | normative | — |
| DI-004 | Issue(Assignment) | PKT-IP-0008 Coordinator Assignment | Ledger v27 @ 2026-09-06 | 覆盖/不覆盖、§5 责任边界、§10 十问、七项强制 Checklist | normative | — |
| DI-005 | Issue | #58 正文 | 修订 `2026-09-01T14:36:22Z` | V5-FR-01 两 schema 子集、FR-05/06、NFR-02、AC-04 | normative | V5 节优先 |
| DI-006 | Issue(Ledger) | #58 Delivery Ledger v27 | `2026-09-06T04:40:10Z` | 定序终审(四 schema 拆分)、基线数字、七项 Checklist 登记 | normative(current) | — |
| DI-007 | Decision | DR 正本(#58 评论:5505168221/5506328396/5510460665/5513783045/5525937000/5553663314/5556097340 + v3 确认) | 2026-09-02..06 | 重冻结先例、七项 Checklist 全部条目的裁定渊源 | normative | — |
| DI-008 | Upstream IP | IP-0001..0007 Packets + 各 merge | #97..#127 | codec/Envelope/29 codes;AepReference/VepReference/ArtifactLink 三元组先例;revision 语义两先例(aep 无耦合/workflow W2 耦合);排序 vs 有序序列先例;untyped id + lineage 存在性(rvr gate-evidence)先例 | normative | — |
| DI-009 | Architecture | V5 规划文档(#58 指定 Source of truth) | 本地工作树副本 | §4.1(四模式与 VERIFY_VEP/REPAIR_FROM_VEP 的 VEP 前置)、§5.2(Artifact 清单:通用对 vs MiningPlan/SandboxRunManifest 的分层)、§13.1(N01 runtime 输入面 WorkflowStarted/StageResult/Artifact refs)、行 1270(V5-FR-01) | normative(经 #58 V5 覆盖层转正) | 与 #58 正文冲突以 #58 为准 |
| DI-010 | Code | `lima/contracts/` 九模块 | main `f3acc72` | §1 consumer review 实证;validator 风格;workflow ArtifactLink 模式 | current-behavior | 代码事实让位于 Packet 目标行为 |
| DI-011 | Test | `tests/contracts/` 全部 | main `f3acc72` | 测试风格、323 基线、golden 测试模式 | current-behavior | — |
| DI-012 | Evidence | IP-0007 POST-MERGE(`.pv_tmp/IP-0007_POST-MERGE.md`)+ 本 IP 基线复现 | 2026-09-06 | 323/668/冷缓存 ruff/冻结面/十 golden;三新 golden 预计算 | evidence | — |
| DI-013 | Issue | #90 正文(V5-N01) | `.pv_tmp/` 镜像 | runtime 消费面与豁免边界(background) | background-only | 不从 #90 扩大范围 |
| DI-014 | Evidence | IP-0007 全链记录(Packet/冻结 v1-v3/验证/PR/post-merge 于 `.pv_tmp/`) | 2026-09-05..06 | 七项 Checklist 实战先例、helper/哨兵缺陷根因 | evidence | — |

### Explicitly Rejected Inputs

| 材料 | 拒绝原因 |
|---|---|
| V5 §5.2 的 MiningPlan 深字段(hypothesis/tool refs/harness plan/oracle/resource/network policy)与 SandboxRunManifest 深字段(image digest/mounts/commands/limits/network/exit/log) | 属 FR-02 manifests 子集与 #76/#77/N06/N07 消费面;本 IP 的 Plan/RunManifest 是跨阶段通用对,资源仅经未类型化 id + lineage 存在性(rvr gate-evidence 先例) |
| Summary/Failure schema 的任何完整定义或字段并入 | IP-0009 候选;Assignment §3 明令禁止;本 Packet 零占位引入(与 FailureKind 先例的区别:本对 schema 无需失败词表) |
| Plan/RunManifest 携带 started_at/ended_at/时长/资源计量(wall_clock/tokens 等) | DR-IP0007-DESIGN-04 纪律;Envelope `created_at` 是全平台唯一时间;aep.budget 是计量唯一先例 |
| payload 携带 self-id 或 workflow_id 镜像字段 | 身份 = envelope artifact_id + 类型化链接(域 artifact aep/vep/rvr 无 self-id 先例);镜像对齐只属于 workflow/stage-attempt(其 Envelope 专属身份字段的对应物),本对无对应物 |
| 扩展 workflow.ArtifactKind 以反向引用 plan/run-manifest | workflow 27-symbol 冻结面禁改(Stop Condition);链方向自洽论证见 §1.1 |
| 未冻结 schema(sandbox-run/tool-bundle/test-plan 等)进入类型化引用词表 | fail-closed 最小词表(DR-IP0008-DESIGN-02/07);由未来 manifest IP 以新 ReferenceKind 成员扩展 |
| profile/aep/rvr 进入本对引用词表 | 链方向论证(§1.1):Plan 引用它们即前向引用;RunManifest 记录编排事实而非域结论链 |
| float confidence/severity、自由文本 goal/description 字段 | 无 float 契约;散文面越小断言越强(DR-IP0007-DESIGN-06) |
| V4 backlog 文档、未引用本地规划文档、"28/13" 笔误口径 | 历次 Packet 已登记拒绝;权威值 29/12 |

---

## 3. Iteration Hypothesis 与 Measurement

### 3.1 Hypothesis

如果执行意图被冻结为一对确定性 schema——Plan 只声明模式、版本化的有序阶段规划与(按模式精确判定的)vep 前置引用,RunManifest 只以 digest 钉死的类型化链接记录"实际执行的计划版本 + 所属 workflow + 已记录尝试 + 未类型化资源清单",且两者零结论语义、零自由文本、零时间/计量——那么"计划被静默改写而无版本链""运行记录与实际计划脱钩""资源清单伪装成安全结论"这类执行阶段真值事故在契约层就没有合法表达。

### 3.2 Measurement

- 三个固定 golden(264/120/776 bytes)生成固定 canonical bytes 与 SHA-256(§17),引用链全部由 IP-0001 codec 对上游 golden 实算(vep→plan;plan/workflow/stage-attempt×2→manifest);
- 模式⇒输入精确双射、AUDIT_ONLY 阶段排除、revision⇔supersedes 耦合、有序唯一 planned_stages、链接排序/唯一/上限、未类型化 id 的 lineage 存在性,全部非法组合 fail closed;
- 新模块导入不加载 DB/网络/Docker/LLM/service/legacy models/九个领域模块中的任何一个;
- 既有 668 个测试无新增失败。

---

## 4. Goal

实现一个 stdlib-only、无副作用、确定性、可版本演化的 `lima.contracts.execution` 叶子模块,包含:

1. 枚举:`PlanMode`(4)、`PlanStageType`(5)、`ReferenceKind`(4);
2. `ArtifactLink`(ReferenceKind 字面量 + 三元组的本地引用值类型)、`Plan`、`RunManifest`;
3. 两 schema 各自的 payload decode/encode 与 Envelope binding(共 8 个函数);
4. 三个 golden fixture、负向边界测试、import isolation 与 legacy regression。

---

## 5. Non-goals

本次明确不做(全部见 §1.2、Rejected Inputs 与 DR-IP0008-DESIGN-*,不重复展开):#90 runtime 任何实现、Summary/Failure schema、manifests(Task/ToolBundle/Dependency/Sandbox/MiningPlan/SandboxRunManifest 深字段)、场景 fixtures、legacy 适配、closure 集成、生产接线、LLM/网络/IO、时间/计量/自由文本字段、修改九个既有契约模块或任何既有测试、IP-0009。

---

## 6. 工作树与分支前置条件

Coding Agent 必须:完整阅读稳定标准、lifecycle、Implementation Agent 责任书、本 Packet、`LIMA_Coding_Agent_IP-0008_正式开发任务交接.md`、`CONTRIBUTING.md`;确认两份 IP-0008 文档均已合并到 `origin/main`;依 lifecycle §9.1 从 Frozen Test Commit(阶段二交付物指定 SHA)派生 `codex/ip-0008-plan-runmanifest-schemas` 独立干净 worktree(禁用共享根工作树与任何既有 worktree);确认 `lima/contracts/execution.py` 与 3 个测试文件、3 个 fixture 尚不存在;输出 Scope Confirmation 后再运行 baseline;不一致时停止提交 Decision Request。根工作树未跟踪文件属用户资产,不得触碰。

---

## 7. 文件边界

### 7.1 Files to Add(恰好 7 个)

```text
lima/contracts/execution.py
tests/contracts/test_execution.py
tests/contracts/test_execution_envelope.py
tests/contracts/test_execution_import_isolation.py
tests/contracts/fixtures/plan_v4_golden.json
tests/contracts/fixtures/plan_full_chain_v4_golden.json
tests/contracts/fixtures/run_manifest_v4_golden.json
```

### 7.2 Files Allowed to Modify

```text
none
```

### 7.3 Files Forbidden

除上述 7 个新增文件外全部禁止修改,特别包括:`lima/contracts/{__init__,errors,codec,common,evidence,profile,aep,vep,rvr,workflow}.py`;IP-0001..0007 的任何测试或 fixture;legacy/生产层;frontend/、requirements*.txt、pyproject.toml、.github/、PROGRESS.md;任意范围外文档。

### 7.4 Ownership 与冲突边界

`execution.py` 唯一 Owner;后续 IP 不得在本 Packet 合并前创建同名 symbol(16 个);新公共 symbol 不从 `lima.contracts` 顶层重导出;依赖方向固定 `execution.py → {codec,common,errors}`,其余 lima 模块不得 import execution(直至消费 IP 冻结其入口)。

---

## 8. Allowed / Forbidden Dependencies

`execution.py` 只允许导入:

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

测试只允许额外使用 stdlib:`hashlib`、`json`、`pathlib`、`subprocess`、`sys`、`unittest`。Forbidden:任何第三方包;`lima.contracts.{evidence,profile,aep,vep,rvr,workflow}` 与 `lima.models` 及生产层;HTTP/socket/DB/Docker/subprocess(产品)/文件系统(产品);UUID/时间/随机/环境变量;绝对路径。

---

## 9. 冻结的公共 Symbols

`lima/contracts/execution.py` 的 `__all__` 必须严格等于以下集合,不多不少(**16** 项;本清单已逐项点数,与声明一致——强制 Checklist 第 3 条):

```python
__all__ = [
    "PLAN_SCHEMA_NAME",
    "RUN_MANIFEST_SCHEMA_NAME",
    "PlanMode",
    "PlanStageType",
    "ReferenceKind",
    "ArtifactLink",
    "Plan",
    "RunManifest",
    "decode_plan_payload",
    "encode_plan_payload",
    "decode_plan_envelope",
    "encode_plan_envelope",
    "decode_run_manifest_payload",
    "encode_run_manifest_payload",
    "decode_run_manifest_envelope",
    "encode_run_manifest_envelope",
]
```

计数:2 常量 + 3 枚举 + 3 dataclass + 8 函数 = **16**。

模块常量:

```python
PLAN_SCHEMA_NAME = "lima.plan"
RUN_MANIFEST_SCHEMA_NAME = "lima.run-manifest"
```

---

## 10. 冻结枚举

所有枚举使用 `class X(str, Enum)`(允许 `# noqa: UP042`),wire value 严格固定(小写 snake/kebab,延续九模块惯例):

```python
class PlanMode(str, Enum):
    FULL_CHAIN = "full_chain"
    AUDIT_ONLY = "audit_only"
    VERIFY_VEP = "verify_vep"
    REPAIR_FROM_VEP = "repair_from_vep"

class PlanStageType(str, Enum):
    PROFILE = "profile"
    AUDIT = "audit"
    MINE = "mine"
    REPAIR = "repair"
    SUMMARIZE = "summarize"

class ReferenceKind(str, Enum):
    VULNERABILITY_EVIDENCE_PACKAGE = "lima.vulnerability-evidence-package"
    WORKFLOW = "lima.workflow"
    STAGE_ATTEMPT = "lima.stage-attempt"
    PLAN = "lima.plan"
```

语义冻结:

- `PlanMode`:wire value 与 workflow 的 `WorkflowMode` 逐值相等(本地枚举,不 import;调用方两侧字符串相等性是衔接面);
- `PlanStageType`:wire value 与 workflow 的 `StageType` 逐值相等(同上);
- `ReferenceKind`:wire value 即 schema_name 字面量;四值 = 本对 schema 的全部合法引用目标(vep = Plan 前置;workflow/stage-attempt = RunManifest 编排事实;plan = RunManifest 的执行对象);profile/aep/rvr 不入词表(DR-IP0008-DESIGN-02)。

---

## 11. Exact Constructors and Defaults

全部领域对象 `@dataclass(frozen=True, slots=True)`,defensive-copy;required 字段在前:

### 11.1 `ArtifactLink`

```python
ArtifactLink(
    kind: ReferenceKind,
    artifact_id: str,
    content_digest: str,
    schema_version: SchemaVersion,
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

### 11.2 `Plan`

```python
Plan(
    schema_version: SchemaVersion,
    workflow_mode: PlanMode,
    revision: int,
    planned_stages: tuple[PlanStageType, ...],
    inputs: tuple[ArtifactLink, ...] = (),
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

### 11.3 `RunManifest`

```python
RunManifest(
    schema_version: SchemaVersion,
    plan: ArtifactLink,
    plan_revision: int,
    workflow: ArtifactLink,
    stage_attempts: tuple[ArtifactLink, ...] = (),
    resource_artifact_ids: tuple[str, ...] = (),
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

三个导出 dataclass 均提供 `from_dict(value, *, schema_version) -> Self` 与 `to_dict()`;`from_dict` 执行 §14 全部跨字段校验;`decode_*_payload` 只是稳定公共入口。

---

## 12. Exact Wire Shapes

### 12.1 Plan payload

required fields 恰好 **4** 个:

```json
{
  "workflow_mode": "verify_vep",
  "revision": 1,
  "planned_stages": ["summarize"],
  "inputs": [{"kind": "lima.vulnerability-evidence-package", "artifact_id": "vep-0001",
              "content_digest": "<64hex>", "schema_version": "4.0"}]
}
```

### 12.2 RunManifest payload

required fields 恰好 **5** 个:

```json
{
  "plan": {"kind": "lima.plan", "artifact_id": "plan-0002", "content_digest": "<64hex>",
           "schema_version": "4.0"},
  "plan_revision": 2,
  "workflow": {"kind": "lima.workflow", "artifact_id": "wf-0001", "content_digest": "<64hex>",
               "schema_version": "4.0"},
  "stage_attempts": [],
  "resource_artifact_ids": []
}
```

### 12.3 `ArtifactLink`

```json
{"kind": "lima.plan", "artifact_id": "plan-0002", "content_digest": "<64hex>", "schema_version": "4.0"}
```

### 12.4 Extensions

4.0:任何层级(顶层、link)unknown field 以 `UNKNOWN_FIELD` 拒绝;未来 4.x 经对应对象 `extensions` 无损 round-trip;required 缺失与 unknown enum 即使未来 minor 也拒绝。

---

## 13. Scalar Validation

- `artifact_id`/`resource_artifact_ids[]`:IP-0002 identifier 规则 `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`(NFC);
- `content_digest`:`[0-9a-f]{64}`;
- `schema_version`(link 内):IP-0001 `SchemaVersion.parse` 规则;
- `revision`/`plan_revision`:int(精确类型,拒 bool),1..9223372036854775807;
- enum 字段:非 str `INVALID_FIELD_TYPE`,未知值 `UNKNOWN_ENUM_VALUE`;error message 不回显原值;
- 本模块无 bounded-text 字段;无 float(结构性禁)。

---

## 14. Array Limits,Canonical Ordering 与 Cross-field Invariants

### 14.1 数组上限与排序/有序

| Array | 上限 | 允许空 | 顺序规则 |
|---|---:|---:|---|
| Plan `planned_stages` | 16(词表 5 值 + 唯一性使实际 ≤5) | 否(≥1) | **有序序列,不排序**(序 = 计划内容);成员唯一 |
| Plan `inputs` | 16 | 视模式(见 P3) | `artifact_id` ASCII 升序、唯一 |
| RunManifest `stage_attempts` | 256 | 是 | `artifact_id` ASCII 升序、唯一 |
| RunManifest `resource_artifact_ids` | 256 | 是 | ASCII 升序、唯一 |

### 14.2 Plan 不变量

- P1 `workflow_mode ∈ PlanMode`;`planned_stages` 非空、成员 ∈ `PlanStageType`、无重复(有序保留);
- P2 **AUDIT_ONLY 排除**:`workflow_mode == audit_only` ⇒ planned_stages 不含 mine/repair,违反 → `INVALID_FIELD_VALUE $.planned_stages[i]`(唯一冻结的模式×阶段耦合;verify_vep/repair_from_vep 的阶段集留 #90 policy,DR-IP0008-DESIGN-04);
- P3 **模式⇒输入精确双射**:`workflow_mode ∈ {verify_vep, repair_from_vep}` ⇒ inputs ≥1 且每 link `kind == VULNERABILITY_EVIDENCE_PACKAGE`;`workflow_mode ∈ {full_chain, audit_only}` ⇒ inputs 恰空;违反 → `INVALID_FIELD_VALUE`(缺前置 → `$.inputs`;多余/错类 → `$.inputs[i].kind`)(DR-IP0008-DESIGN-05);
- P4 `revision` ≥1;**revision⇔supersedes 耦合(binding 阶段)**:`revision > 1` ⇔ `envelope.supersedes != None`;`supersedes.schema_name == "lima.plan"`(编排族先例 = workflow W2;DR-IP0008-DESIGN-06)。

### 14.3 RunManifest 不变量

- R1 `plan` link `kind == PLAN` 恰一(必填),`workflow` link `kind == WORKFLOW` 恰一(必填),违反 → `INVALID_FIELD_VALUE $.plan.kind` / `$.workflow.kind`;
- R2 `plan_revision` ≥1(与 plan 链接的 digest 钉死共同表达"实际执行的计划版本"——vep `source_aep_revision` 先例);
- R3 `stage_attempts` 每 link `kind == STAGE_ATTEMPT`,排序/唯一/上限同表;
- R4 `resource_artifact_ids` 为纯 id 清单(identifier 规则、排序、唯一、上限);**不做类型化 schema 断言**(sandbox/tool schema 未冻结;lineage 存在性核对见 §14.4;rvr gate-evidence 先例,DR-IP0008-DESIGN-07);
- R5 无 revision 字段(单次事实记录;修正走 Envelope supersedes 通用机制,无 payload 耦合)。

### 14.4 Provenance(Envelope binding 阶段)

- 每个内嵌 `ArtifactLink`(Plan.inputs;RunManifest.plan/workflow/stage_attempts)必须存在 `envelope.lineage` 条目:`artifact_id` 匹配、`schema_name == link.kind 字面量`、`schema_version` 相等、`content_digest` 经 `hmac.compare_digest` 相等;缺失/错 schema → `INVALID_FIELD_VALUE $.payload…`;digest 不符 → `DIGEST_MISMATCH`;
- 每个 `resource_artifact_ids[i]` 必须存在于 lineage(存在性,不类型化),缺失 → `INVALID_FIELD_VALUE $.payload.resource_artifact_ids[i]`;
- lineage 允许额外条目;tenant/snapshot/self/duplicate/conflict 由 IP-0001 拒绝。

### 14.5 明确豁免清单(留 Registry/runtime/消费侧;单解)

1. Plan revision 链单调性、supersedes 目标确为 revision-1——Registry(workflow W2 同构留白);
2. planned_stages 与实际执行的一致性、verify_vep/repair_from_vep 阶段集 policy、阶段 eligibility——#90 policy evaluator(DR-IP0008-DESIGN-04);
3. RunManifest.stage_attempts 覆盖完整性(是否穷尽该 workflow 全部尝试)——Registry/消费侧;
4. plan_revision 与所引 Plan artifact 的实际 revision 数值一致——引用不可解析,Registry/消费侧(vep source_aep_revision 同构);
5. 资源 id 对应 artifact 的 schema 合法性——未来 manifest IP 类型化后收紧。

---

## 15. Envelope Binding Contract

### 15.1 Function signatures

```python
def decode_plan_payload(value: Mapping[str, JSONValue], *, schema_version: SchemaVersion) -> Plan: ...
def encode_plan_payload(plan: Plan) -> dict[str, JSONValue]: ...
def decode_plan_envelope(data: bytes, *, limits: ContractLimits = DEFAULT_LIMITS) -> tuple[ArtifactEnvelope, Plan]: ...
def encode_plan_envelope(envelope: ArtifactEnvelope, plan: Plan, *, limits: ContractLimits = DEFAULT_LIMITS) -> bytes: ...
# run_manifest 四函数同构,分别返回/接受 RunManifest
```

### 15.2 Binding rules

`decode_*_envelope` 必须:调用 `decode_envelope`;`schema_name` 等于对应常量;inline payload only;以 envelope `schema_version` decode 对象;§14 各自不变量已于 from_dict 完成;§14.4 provenance(Plan 另核对 P4 supersedes 耦合);classification != public;retention != ephemeral;返回 `(envelope, 对象)` 不修改输入。

`encode_*_envelope` 执行相同 binding 并额外:`envelope.schema_version == 对象.schema_version`;`envelope.payload == encode_*_payload(对象)`;`compute_content_digest` 与 `envelope.content_digest` 经 `hmac.compare_digest` 相等;最终 `encode_envelope`;不自动创建/修补 Envelope。

---

## 16. Stable Error Mapping and Precedence

复用现有 **29** 个 code;优先级(九模块统一模式):

1. codec byte/UTF-8/JSON/resource;
2. top-level container/required/current unknown/schema version;
3. enum 与 scalar type;
4. scalar value/range、数组 limit/重复/词表成员;
5. 内嵌对象逐层校验(link 字段错误按其自身路径);
6. 跨字段:P2 模式×阶段 → P3 模式⇒输入 → P4 revision/supersedes → R1-R4;
7. lineage provenance(类型化链接 + 资源 id 存在性);
8. Envelope schema/payload/digest/classification/retention binding。

`field_path` 示例:

```text
$.planned_stages[2]
$.inputs[0].kind
$.plan_revision
$.stage_attempts[1].artifact_id
$.payload.resource_artifact_ids[0]
$.payload.plan.content_digest
$.supersedes
```

---

## 17. Golden Fixture

三个文件(阶段二逐字节复制,含本文权威内容;禁止更改字段、值、顺序或摘要):

```text
tests/contracts/fixtures/plan_v4_golden.json             264 bytes
tests/contracts/fixtures/plan_full_chain_v4_golden.json  120 bytes
tests/contracts/fixtures/run_manifest_v4_golden.json     776 bytes
```

全部 bytes 与 digest 已由 IP-0001 codec 在 main `f3acc72` 预计算冻结(worktree `LIMA-ip-0008-pkt-wt`);引用链使用上游 golden 真实 digest(vep `cd76622b…`、workflow `3be59c6c…`、stage_attempt `34746de4…`、alternates[0] `418c461a…` 与本文实算的 plan 摘要),构成连续证据链。

### 17.1 `plan_v4_golden.json`(264 bytes)

SHA-256:`4e49b63d3f3cb50ef302781296cabbb02e4267b0675b7922a9bd1eae4077495a`

内容 = verify_vep 计划(revision 1,planned_stages=[summarize],inputs = vep golden 真实 digest):

```json
{"inputs":[{"artifact_id":"vep-0001","content_digest":"cd76622b48d11c0300e63d7489701479c75dc2f4b06cc6c4e88af1f453061d01","kind":"lima.vulnerability-evidence-package","schema_version":"4.0"}],"planned_stages":["summarize"],"revision":1,"workflow_mode":"verify_vep"}
```

### 17.2 `plan_full_chain_v4_golden.json`(120 bytes)

SHA-256:`9390344cd8018f450d115b085b577a7c723fb0abf214c552bd2cc9de6711851c`

内容 = full_chain 计划(revision 2——envelope 向量演示 P4 supersedes 耦合;五阶段链序,有序不排序;inputs 恰空):

```json
{"inputs":[],"planned_stages":["profile","audit","mine","repair","summarize"],"revision":2,"workflow_mode":"full_chain"}
```

### 17.3 `run_manifest_v4_golden.json`(776 bytes)

SHA-256:`213fbebd48a966ee9071b5a19f385731e833b17f4d8c7c653c55b2c19eaf9cd7`

内容 = 运行记录(plan = §17.2 golden 实算摘要 + plan_revision 2;workflow = workflow golden 真实摘要;stage_attempts 按 artifact_id 升序 = alternates[0] 与 stage_attempt golden 真实摘要;资源 id 两个,存在于 envelope 向量 lineage,不类型化):

```json
{"plan":{"artifact_id":"plan-0002","content_digest":"9390344cd8018f450d115b085b577a7c723fb0abf214c552bd2cc9de6711851c","kind":"lima.plan","schema_version":"4.0"},"plan_revision":2,"resource_artifact_ids":["sandbox-run-0001","tool-bundle-0001"],"stage_attempts":[{"artifact_id":"attempt-audit-0001","content_digest":"418c461a1d82fcc9cbf6b60d1caad21e76491abe2d4f4a0a3a1a178cb15e8fb4","kind":"lima.stage-attempt","schema_version":"4.0"},{"artifact_id":"attempt-profile-0001","content_digest":"34746de4860ae5ce9ec69c43ad8c8ad596d4e79172a284bf3defc1a866edb259","kind":"lima.stage-attempt","schema_version":"4.0"}],"workflow":{"artifact_id":"wf-0001","content_digest":"3be59c6c7f1736954fbce5f1e74b4c7789ab8a1e956f4229904ea30bbe756146","kind":"lima.workflow","schema_version":"4.0"}}
```

### 17.4 Frozen envelope vectors(两 schema 各一 + plan 双形态说明)

```text
[plan §17.1] schema_name = lima.plan / artifact_id = plan-0001
  tenant-1 / task-1 / workflow_id = workflow-0001(意图上下文,调用方提供)/ stage_attempt_id = plan-emit-1
  snapshot "3"*64 / producer lima-planner / created_at 2026-09-06T00:00:00Z
  policy "5"*64 / toolchain "6"*64 / classification internal / retention standard
  content_digest = 4e49b63d3f3cb50ef302781296cabbb02e4267b0675b7922a9bd1eae4077495a
  lineage = [vep-0001 / lima.vulnerability-evidence-package / cd76622b…] / supersedes = null(revision 1 ⇒ 必须空)

[plan §17.2] schema_name = lima.plan / artifact_id = plan-0002
  其余同上 / content_digest = 9390344c…1851c
  lineage = [](inputs 空,允许空 lineage) / supersedes = plan-0000 / lima.plan / "0"*64(revision 2 ⇒ 必须非空)

[run_manifest §17.3] schema_name = lima.run-manifest / artifact_id = run-0001
  workflow_id = workflow-0001 / stage_attempt_id = summarize-emit-1
  classification sensitive / retention audit
  content_digest = 213fbebd…f9cd7
  lineage = [plan-0002 / lima.plan / 9390344c…,
             wf-0001 / lima.workflow / 3be59c6c…,
             attempt-audit-0001 / lima.stage-attempt / 418c461a…,
             attempt-profile-0001 / lima.stage-attempt / 34746de4…,
             sandbox-run-0001 / lima.sandbox-run / "7"*64(未冻结 schema,存在性核对段),
             tool-bundle-0001 / lima.tool-bundle / "8"*64(同上)]
  supersedes = null
```

---

## 18. Required Tests

测试使用 `unittest`,方法名冻结如下;可增加 helper 与更细测试,不得减少、重命名或合并。

### 18.1 `tests/contracts/test_execution.py`(29)

```text
ExecutionEnumTests
  test_wire_values_are_exact

ArtifactLinkTests
  test_round_trip_has_exact_wire_shape
  test_rejects_missing_invalid_and_mismatched_fields

PlanTests
  test_minimal_full_chain_plan_round_trip_is_valid
  test_golden_verify_vep_plan_round_trip_and_digest
  test_golden_full_chain_plan_round_trip_and_digest
  test_rejects_wrong_container_and_missing_required_fields
  test_rejects_unknown_enum_and_wrong_field_type
  test_rejects_invalid_revision
  test_rejects_duplicate_unknown_and_empty_planned_stages
  test_rejects_audit_only_mode_with_mining_or_repair_stages
  test_mode_governs_vep_inputs_required_and_forbidden
  test_rejects_inputs_outside_vocabulary_or_unsorted
  test_future_minor_round_trips_unknown_fields_at_every_level
  test_current_minor_rejects_unknown_fields_at_every_level
  test_defensive_copy_prevents_post_construction_mutation
  test_payload_has_no_confidence_severity_or_verdict_bypass_fields

RunManifestTests
  test_minimal_empty_manifest_round_trip_is_valid
  test_golden_manifest_round_trip_and_digest
  test_rejects_wrong_container_and_missing_required_fields
  test_rejects_unknown_enum_and_wrong_field_type
  test_rejects_invalid_plan_revision
  test_plan_and_workflow_link_kinds_are_required_and_exact
  test_rejects_unsorted_duplicate_and_oversize_stage_attempts
  test_resource_ids_follow_identifier_rules_sorted_unique_capped
  test_future_minor_round_trips_unknown_fields_at_every_level
  test_current_minor_rejects_unknown_fields_at_every_level
  test_defensive_copy_prevents_post_construction_mutation
  test_payload_has_no_confidence_severity_or_verdict_bypass_fields
```

`test_wire_values_are_exact` 必须断言:PlanMode 与 PlanStageType 的 wire 值分别与 `lima.contracts.workflow` 的 WorkflowMode/StageType **逐值相等**(字符串级衔接面断言,允许以硬编码清单断言,不 import workflow);ReferenceKind 四字面量精确。

`test_payload_has_no_confidence_severity_or_verdict_bypass_fields`(两处)递归断言 golden 与 minimal payload 任意层级不出现键:`confidence`、`severity`、`risk_score`、`is_safe`、`vulnerability_resolved`、`safe`、`clear`。

### 18.2 `tests/contracts/test_execution_envelope.py`(13)

```text
PlanEnvelopeTests
  test_frozen_envelope_encode_decode_is_byte_stable
  test_rejects_wrong_schema_name_and_version_mismatch
  test_rejects_blob_backed_plan
  test_revision_supersedes_coupling_enforced
  test_rejects_missing_or_mistyped_vep_lineage
  test_rejects_public_classification_and_ephemeral_retention

RunManifestEnvelopeTests
  test_frozen_envelope_encode_decode_is_byte_stable
  test_rejects_wrong_schema_name_and_version_mismatch
  test_rejects_blob_backed_run_manifest
  test_rejects_missing_or_mistyped_plan_workflow_and_attempt_lineage
  test_rejects_missing_resource_artifact_lineage
  test_rejects_public_classification_and_ephemeral_retention
  test_tampered_payload_fails_before_domain_promotion
```

### 18.3 `tests/contracts/test_execution_import_isolation.py`(4)

```text
ExecutionImportIsolationTests
  test_module_public_api_matches_frozen_symbol_set
  test_clean_process_import_has_no_db_network_docker_llm_service_or_legacy_models
  test_module_only_uses_allowed_imports
  test_import_does_not_change_lima_contracts_top_level_public_api
```

`test_clean_process_import…` 必须断言:干净子进程导入 `lima.contracts.execution` 后,`evidence`/`profile`/`aep`/`vep`/`rvr`/`workflow` 与其余 forbidden roots **均不在** `sys.modules`。

### 18.4 Minimum count

IP-0008 必须新增至少 **46** 个独立 test methods(29+13+4)。

---

## 19. Acceptance Criteria and Traceability

| AC | Required behavior | Evidence(test) | 覆盖的 Issue requirement |
|---|---|---|---|
| EX-AC-01 | 16 个 module public symbols、3 枚举 wire vocabulary(4/5/4)、衔接面 wire 等值(workflow 两枚举) | enum/object/import tests | V5-FR-01(两 schema 版本化定义)、FR-02 引用纪律 |
| EX-AC-02 | identifier/digest/int range/数组上限/排序或有序唯一 fail closed | 各对象 negative tests | NFR-02 |
| EX-AC-03 | 三 golden(264/120/776 bytes、固定 digest、byte-stable);引用链 = 上游 golden 真实 digest | golden tests | FR-05、AC-01 方法论 |
| EX-AC-04 | 模式⇒输入精确双射;AUDIT_ONLY 排除 mine/repair | P2/P3 tests | V5 §4.1(模式语义) |
| EX-AC-05 | plan revision⇔supersedes 耦合 + supersedes 目标 schema 校验 | envelope tests | FR-02、版本化语义 |
| EX-AC-06 | RunManifest 的 plan/workflow/stage_attempts 类型化 lineage;resource id 存在性(不类型化) | envelope tests | FR-02、NFR-01(无结论旁路) |
| EX-AC-07 | 两 payload 零结论/零自由文本/零时间/零计量(forbidden-key + wire 面冻结) | forbidden-key tests | NFR-01 结构面 |
| EX-AC-08 | 4.0 unknown field 拒绝(每层级);未来 4.x 无损 round-trip;unknown enum 永远拒绝 | compatibility tests | FR-06 |
| EX-AC-09 | stdlib leaf;execution→{codec,common,errors};不加载九个领域模块中任何一个;冻结面不变 | import isolation + git diff | AC-04(T-04) |
| EX-AC-10 | 7 added / 0 modified / 0 deps / 全量回归无新增失败 | file boundary + full regression | AC-04 |

---

## 20. 强制实现顺序(含一致性预检,七项强制 Checklist 全嵌入)

阶段二由 P&V 执行 **1-6**,Implementation Agent 从第 7 步开始:

1. **冻结前一致性预检**(七项 Checklist 第 1/4/5/6 条):脚本独立实现 §14 全部跨字段规则,校验三 golden 实文件 + 每个计划 arrange;构造器用例 arrange 做**实例化镜像**验证;负向 arrange 经 helper 后**仍为预期非法形态**;**helper 调用点/签名兼容 AST 扫描**(关键字实参 ∈ 声明参数集,`**kwargs` 豁免);**None 哨兵审计**(None 缺省 + is-None 自动填充 + 调用点显式 None 三条件同立即违规);预检脚本裸调用必须显式报错退出;
2. 编写 3 个测试文件 + 3 个 fixture(逐字节复制 §17 权威内容);
3. 测试自身质量门禁(compileall/ruff);**一切 lint 复证在 GREEN 等价态 + `--no-cache` 冷缓存下执行**(Checklist 第 7 条:目标模块以真实路径 stub 存在→复证→立即删除并记录 digest/时间戳;RED 态工具结果一律不得作为依据);
4. 证明有效 RED(预期失败全部归因 `lima.contracts.execution` 不存在);
5. 创建 Frozen Test Commit + digest + 数量,**只推送分支,严禁开 PR**(Checklist 第 2 条);
6. Coordinator 出具 Implementation Assignment;
7. Implementation Agent:枚举/本地校验器/ArtifactLink → Plan(P1-P4)→ RunManifest(R1-R5)→ 逐字验证三 golden → 8 个 binding functions → isolation/forbidden-key → Slice Gate → Compatibility Gate → File Boundary Gate → Completion Summary。

---

## 21. Done Commands

### 21.1 Baseline(编码前)

```powershell
python -m compileall -q lima scripts tests
python -m unittest discover -s tests/contracts -v
python -m unittest -v tests.test_repository_source tests.test_task_failure
```

预期基线(@ `f3acc72` + 本 Packet 合并):contracts **323** PASS;定向兼容 **29** PASS。

### 21.2 Slice Gate(GREEN 等价态 + 冷缓存)

```powershell
python -m compileall -q lima/contracts tests/contracts
python -m unittest discover -s tests/contracts -v
python -m ruff check --no-cache lima/contracts/execution.py tests/contracts/test_execution.py tests/contracts/test_execution_envelope.py tests/contracts/test_execution_import_isolation.py
python -m ruff check --no-cache lima/contracts tests/contracts
python -m bandit -q -r lima/contracts/execution.py
git diff --check
```

### 21.3 Compatibility Gate

```powershell
python -m unittest -v tests.test_repository_source tests.test_task_failure
python -m unittest discover -s tests -v
```

实现后预期 contracts **369**(323+46)、全量 **714**(668+46)/ 0 failed / 1 既有 skip。任何新增 failure/skip 必须解释;不能通过修改 legacy 测试解决。Python 3.11/3.12 由 CI matrix 验证。

### 21.4 File Boundary Gate

```powershell
git diff --name-only --diff-filter=ACMRTUXB <frozen-test-commit>...HEAD
git diff --check <frozen-test-commit>...HEAD
```

输出必须恰好为 7.1 的 7 个新增文件(相对 Frozen Test Commit,产品侧仅 `lima/contracts/execution.py`)。

### 21.5 Optional release-level gate

维护者或 CI 可运行 `powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 test`;普通 Agent 不因 Docker/宿主环境不可用而改变产品代码。

---

## 22. Security and Compatibility Invariants

- 两 payload 零结论语义、零自由文本、零时间、零计量、零 float;forbidden-key 递归断言;
- 模式⇒输入精确双置(verify/repair 类计划无 VEP 前置即非法;full/audit 类计划携带任何输入即非法);
- AUDIT_ONLY 计划不得规划 mine/repair 阶段;
- 一切跨 artifact 引用 = ReferenceKind 字面量 + 三元组 + Envelope lineage 双向核对(digest 恒 `hmac.compare_digest`);资源 id 仅存在性核对;
- classification 禁 public、retention 禁 ephemeral;ID/digest/时间全部由调用方提供;
- 不新增任何权限;不改变 legacy 行为与九个上游模块冻结面(18/16/15/12/12/12/27/29、十 golden);
- 不通过 future-minor extension 绕过 required、enum、耦合或 provenance。

---

## 23. Stop Conditions / Decision Request

1. 两份 IP-0008 文档尚未合并,或基线不再是 `f3acc72` 后代、九模块冻结面漂移;
2. 最新 main 已出现同名 `execution.py` 或冲突 Owner(cxx PR 开始触碰 `lima/contracts`/`tests/contracts`);
3. 需要修改任一 forbidden 文件或扩大 allowlist(含 workflow.ArtifactKind 扩展诉求);
4. 需要新增第三方依赖、I/O、网络、数据库、Docker、subprocess 或环境权限;
5. §10-§16 任一契约存在两个与上游决策同等自洽的答案;
6. 三个 frozen fixture 的 bytes/digest 无法由 IP-0001 codec 重现,或引用链与上游 golden digest 不一致;
7. 需要引入时间/计量/自由文本字段,或需要定义 Summary/Failure/manifests 深字段 schema 才能让测试通过(范围上移 → IP-0009/manifests IP);
8. baseline/全量回归失败且无法归因;required tests 无法证明某个 AC;
9. 发现工作实际进入 #90/#68 runtime、生产接线或 closure。

Decision Request 格式同 Packet 惯例。

---

## 24. Git, Commit and PR Contract

推荐 commit / PR 标题:`feat: add deterministic plan and run manifest schemas`。PR 正文:只写 `Implements IP-0008` + `Related to #58`;禁 auto-close 关键字;AC → Test → Result;真实命令、退出码、统计;7 added / 0 modified / 0 dependencies;no runtime/no summary-failure schema/no manifests/no timestamps/no free text/top-level API unchanged;等待独立 Review 与 `merge-gate`。Implementation Agent 不合并 PR、不删分支/worktree、不改 Issue。

---

## 25. Completion Summary Template

```markdown
## IP-0008 Completion Summary

### Result
- Status: DONE | NOT DONE | BLOCKED
- Base commit / Frozen Test Commit / Final commit / Branch / Worktree:

### Scope
- Added files / Modified existing files: none / Dependencies added: none
- Public API: lima.contracts.execution only (16 symbols)
- Contract deviations: none | <Decision Request>

### Acceptance evidence
| AC | Test/command | Result |
|---|---|---|
| EX-AC-01 … EX-AC-10 | | |

### Commands and actual results(命令/退出码/统计;lint 一律 --no-cache GREEN 态)
### Security and compatibility(模式⇒输入双射/AUDIT_ONLY 排除/supersedes 耦合/lineage/无结论旁路/隔离/py3.11-12/回归)
### Findings and decisions
### Handoff(PR 状态/唯一下一步/禁止动作)
```

---

## 26. Maintainer Review Checklist

- [ ] base 为 Frozen Test Commit 后代且含本 Packet;只新增 7 文件;execution.py 是唯一产品文件;
- [ ] 冻结面不变:18/16/15/12/12/12/27/29、十 golden;九个既有契约模块零改动;
- [ ] module API 恰 16 symbols;依赖 execution→{codec,common,errors};不加载任何领域模块(含 workflow);
- [ ] 两 schema wire(4/5 required 字段)与 ArtifactLink 4 字段无漂移;衔接面 wire 等值测试通过;
- [ ] 三 golden 264/120/776 bytes 与 digest 一致;引用链 = 上游 golden 真实 digest;
- [ ] 模式⇒输入双射、AUDIT_ONLY 排除、revision⇔supersedes、有序唯一 planned_stages、资源 id 存在性 negative tests 通过;
- [ ] GREEN 态冷缓存 lint(四文件 + 全目录)exit 0(RED 态结果不作为依据);
- [ ] forbidden-key 通过;current/future-minor 每层级通过;
- [ ] 全量回归无新增失败(预期 714 = 668+46);
- [ ] File Boundary 恰 7 文件;Completion Summary 可复现;独立 Review 与 merge-gate 通过;
- [ ] PR 未关闭 #58;未启动 IP-0009、manifests IP、#90/#68 runtime 或生产接线。

---

## 27. Assignment §10 十问逐条单解(审计索引)

| # | Assignment 问题 | 单解 | 所在节 |
|---|---|---|---|
| 1 | 命名与模块切分;Summary/Failure 引用方式 | 单模块 `lima/contracts/execution.py`;`lima.plan`/`lima.run-manifest`;零占位引入(无需失败词表,区别于 FailureKind 先例) | §9/DR-01 |
| 2 | Plan↔RunManifest↔Workflow 引用结构与版本语义 | RunManifest→{plan(三元组+plan_revision 镜像,vep 先例)、workflow、stage_attempts};Plan 独立(revision+supersedes 耦合,workflow W2 先例);RunManifest 无 revision | §14.2/14.3/DR-06 |
| 3 | 八类 Artifact 引用词表与 fail-closed | ReferenceKind 四值(vep/workflow/stage-attempt/plan);profile/aep/rvr 排除(链方向论证);资源 id 未类型化存在性 | §10/DR-02/07 |
| 4 | 状态/阶段词表与不变量;#90 豁免 | PlanStageType 五值 + AUDIT_ONLY 排除唯一耦合;豁免清单 §14.5 | §14.2/14.5/DR-04 |
| 5 | 资源上限逐一论证 | 16/16/256/256 + 有序唯一 planned_stages(词表 5 值收敛);NFR-02 表 §14.1 | §14.1 |
| 6 | golden:≥2 引用、混合形态、真实 digest 链 | 三 golden:verify_vep 计划(vep 链)+ full_chain 计划(rev2/空输入)+ manifest(plan+workflow+2 attempts+2 资源 id) | §17 |
| 7 | 测试矩阵与最低数量 | 46(29+13+4)≥40;import isolation 含六领域模块反向断言;禁字段递归断言两处 | §18 |
| 8 | 错误映射与优先级 | 复用 29 codes;八级优先级 | §16 |
| 9 | 命令与预期数字 | contracts 323→369;全量 668→714 | §21 |
| 10 | 环境记录 | redis-py 6.4.0 vs `>=8.1.0,<9` 差异在 RED/验证记录如实登记 | §21/交接书 |

---

## 28. 本 Packet 的冻结设计决策记录(Decision Records)

> 均为 P&V 在 Assignment 授权内的设计冻结,附先例与理由;无一属于"两个同等自洽答案"的多解状态(否则按 Assignment §13 停止)。

- **DR-IP0008-DESIGN-01(单模块承载执行意图对)**:`lima/contracts/execution.py` 同载 Plan 与 RunManifest。依据:workflow.py 三 schema 共居先例;两 schema 是同一执行回合的意图/事实对,拆分制造人为耦合边界;16 symbols 远低于包络。
- **DR-IP0008-DESIGN-02(引用词表恰四值,排除 profile/aep/rvr)**:依据链方向论证(§1.1):Plan 是链首(引用 profile/aep/rvr 即前向引用未发生之事),RunManifest 记录编排事实而非域结论链;fail-closed 最小词表是九模块一贯纪律;未来由消费 IP 以新 ReferenceKind 成员扩展(向后兼容路径同 DR-IP0007-DESIGN-03)。
- **DR-IP0008-DESIGN-03(planned_stages 有序不排序)**:序 = 计划内容(先 profile 后 audit 是语义事实),排序将抹除信息;与"确定性 wire"不冲突——canonical bytes 覆盖既有序列本身;校验唯一性 + 词表成员,不校验任何既定顺序(audit_only 排除除外)。
- **DR-IP0008-DESIGN-04(仅冻结 AUDIT_ONLY 阶段排除)**:与 workflow W1 完全同构的确定性论证("显式只审计"结构确定);verify_vep/repair_from_vep 的阶段集在 V5 无结构性确定答案 → §14.5 豁免归 #90(承 DR-IP0007-DESIGN-05)。
- **DR-IP0008-DESIGN-05(模式⇒输入精确双射)**:V5 §4.1 明文 verify_vep/repair_from_vep "从外部或历史 VEP 开始……输入必须通过 VEP schema 校验"——前置必要性结构确定;full_chain/audit_only 从快照起步、无前置 artifact——空必要性结构确定;故冻结双射而非单向要求。
- **DR-IP0008-DESIGN-06(Plan 版本化 = revision + supersedes 耦合;RunManifest 无 revision)**:编排族 vs 域 artifact 的版本语义二分(workflow W2 vs aep 无耦合)——Plan 属编排族(声明物,会被修订后重发);RunManifest 是单次事实记录(不可"修订第 1.1 版事实"),修正走 Envelope supersedes 通用机制。plan_revision 镜像 int 承 vep `source_aep_revision` 先例。
- **DR-IP0008-DESIGN-07(资源清单 = 未类型化 id + lineage 存在性)**:sandbox/tool/test-run 等 schema 属 FR-02 manifests(未冻结);rvr `evidence_artifact_ids` 的"存在性核对、不做类型化断言"是同情境先例;类型化由未来 manifest IP 收紧(§14.5-5)。
- **DR-IP0008-DESIGN-08(零时间/零计量/零自由文本)**:DR-IP0007-DESIGN-04/06 纪律延续;Assignment §5 的"资源与事实清单"定义为**引用的表达面**而非计量;计量先例唯一属 aep.budget;全平台唯一时间字段 = Envelope created_at。
- **DR-IP0008-DESIGN-09(不扩展 workflow.ArtifactKind,反向引用不成立)**:workflow 27-symbol 冻结面禁改(Stop Condition 1/7);链方向上 RunManifest 单向引用编排面即可闭环;runtime 如需在 workflow envelope 标注 plan 关联,IP-0001 lineage 额外条目(非类型化)已提供合法通道,无需触碰冻结面。

---

## 29. Packet 完成定义

只有全部 10 个 AC、46 个 required tests、三个 golden fixture、Envelope consumer test、import isolation、完整命令证据(GREEN 态冷缓存 lint)、独立 Review 和 `merge-gate` 全部满足,IP-0008 实现才能标记 DONE。

IP-0008 合并后,协调者必须在最新 `main` 上安排 post-merge verification,并让下一个消费 IP(IP-0009 候选:Summary + Failure schemas)对本模块做只读 consumer review(其 Packet 的 Design Input Manifest 入口 Gate)。当前 Agent 不自动继续下一个 IP。
