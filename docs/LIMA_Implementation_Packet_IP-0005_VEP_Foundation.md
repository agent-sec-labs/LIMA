# LIMA Implementation Packet IP-0005:Vulnerability Evidence Package(VEP)Foundation

> Packet ID:`IP-0005`
>
> 状态:`DESIGN-FROZEN / READY-FOR-CODE WHEN THIS PACKET IS MERGED TO MAIN`
>
> Source Issue:[#58](https://github.com/agent-sec-labs/LIMA/issues/58) 的第五个独立实现切片(第四个 domain 切片,Mining 侧第一个 Artifact)
>
> 最低代码基线:Assignment 基线 `5984c5c424cc27acacce89f234040528af6d2c27`(IP-0004 实现,PR #107);实现基线必须是包含本 Packet 与正式交接书的最新 `origin/main`
>
> 推荐分支:`codex/ip-0005-vep-foundation`(依 lifecycle §9.1 从 Frozen Test Commit 派生,实现阶段 Assignment 另行出具)
>
> Owner:唯一 Implementation Agent;不得与任何活动 IP 并行修改 `lima/contracts/` 或 `tests/contracts/`

## 需求映射(Header)

```text
Source Issue:#58
Issue specification revision:正文修订 2026-09-01T14:36:22Z(V4 基线 + V5 覆盖层,冲突以 V5 节为准);
  Delivery Ledger v9 @ 2026-09-02T14:12:22Z(IP-0005 定序 Ledger Review:IP-0005 = VEP Foundation)
Covered requirements:FR-02 的 VEP 子集(版本化 schema;跨对象引用 artifact_id + content_digest +
  schema_version 三元组,经 payload 字段 + Envelope lineage 双重表达);V5-FR-03 前半句的契约面
  (VEP 必须携带 machine-executable Oracle ref——schema 层冻结其最小描述符,缺 Oracle 不成 VEP);
  FR-03 的终态映射契约面(candidate|inconclusive|refuted(scope)|verified 与 D3/D4 的合法映射);
  支撑性覆盖 FR-05(VEP fixture 子集)、FR-06(本 schema current/future-minor 兼容)、
  NFR-01(blocked/timeout/OOM/tool_error 不编码为安全结论)、NFR-02(校验上限)
Not covered requirements:V5-FR-03 后半句(RVR 逐候选逐 Gate);FR-02 其余子集(RVR、Task/ToolBundle/
  Dependency/Sandbox manifests——Oracle 与 sandbox run 仅以逻辑 artifact 引用表达,不定义其 schema);
  V5-FR-01 其余子集(Workflow/StageAttempt/Outcome/Plan/RunManifest/Summary/Failure);V5-FR-04/05;
  #95 全部实现职责(CapabilityPlugin/SupportDecision/ValidationPlan/Oracle/VerificationDecision 接口、
  执行器、插件系统、conformance suite);真实沙箱执行、PoC 运行、Repair、生产接线、前端
Delivery role:domain
Issue closure impact:PARTIAL(合并后不触发 #58 closure;#58 保持 open)
Upstream IP/PR/merge commits:
  IP-0001 #97 `5cdf872` / #98 `d3e73d9` / 恢复 #102 `a0b3eea`(IP-DONE)
  IP-0002 #99 `f92122b` / #100 `4fe1def`(IP-DONE)
  IP-0003 #103 `437fe01` / Frozen v2 `573de77` / #104 `9078bb5`(IP-DONE)
  IP-0004 #105 `046d67b` / Frozen v2 `aa2e3c5`(v1 `bfe438c` 撤销留痕)/ #107 `5984c5c`(IP-DONE)
Activation gate:lifecycle 入口 consumer review(见 §1,已完成,无 Contract Gap)
```

---

## 0. 执行决策

当前执行队列(Ledger v9,2026-09-02):

```text
DONE
IP-0001(+IP-0001-R1)、IP-0002、IP-0003、IP-0004(5 IP + 1 恢复,全部 IP-DONE)

NOW(只允许 1 个)
IP-0005 Vulnerability Evidence Package(VEP)Foundation(Design Frozen;文档合并后进入阶段二)

NEXT(不得实现;IP-0005 设计期重排)
IP-0006 候选:Workflow/StageAttempt/Outcome schemas(V5-FR-01 主体)或 RVR Foundation

LATER
另一候选 schema 线 / RVR / Task/ToolBundle/Dependency/Sandbox manifests /
JSON Schema + 兼容矩阵 + ADR(Issue PR3)/ legacy adapter fixture(Issue PR4)/ closure IP
```

本 Packet 只建立可被 #95(Mining Core)、#76(Repair)、V5-N02/#91(全链路)消费的确定性 `VulnerabilityEvidencePackage` Artifact 契约。它不实现 Mining 执行、Oracle 运行、sandbox、插件系统或任何生产接线。

---

## 1. IP-0004 消费者评审结论(lifecycle 入口 Gate,只读)

### 1.1 已验证事实(@ main `5984c5c`,P&V 实证执行,2026-09-02)

- **FR-02 引用三元组可构造**:由 AEP golden payload 计算的 `source_aep = {artifact_id: "aep-0001", content_digest: "f0a98543…64705d0", schema_version: "4.0"}` 完整可表达;该三元组与 Envelope lineage 中类型化条目(schema_name == `lima.audit-evidence-package`)可做双向机器核对;
- **VEP 输入所需 AEP 语义面可读**:`AuditEvidencePackage` 的 `package_status`(sealed)、`revision`(1)、`mining_eligible_hypothesis_ids`(['hypothesis-0001'])、`audit_depth`、`audit_outcome` 均为只读可消费属性——VEP 以 `hypothesis_id` + `source_aep_revision` 精确钉住其验证对象与输入版本;
- **D3/D4 standalone 构造面(IP-0002 前瞻预留的预期消费者)可用**:D3 与 D4 `EvidenceRecord` 均可独立构造(subject_kind=vulnerability_hypothesis、polarity=supports/refutes、source_artifact_ids 指向 run/oracle 逻辑 artifact),`EvidenceLevel` wire vocabulary D0–D4 已冻结;
- **"unsealed input 不得生成 VEP"(AC-N06-06)的契约层体现(单解)**:lineage 引用只携带三元组、不携带 payload,sealed 状态无法在 VEP schema 层解析——机器可校验部分冻结为"类型化 AEP 引用存在 + digest/version 钉死"(篡改/错配 fail closed);**sealed 状态核验与 revision 单调性同为消费侧/Registry 规则**(#95/未来 Registry),与 IP-0004 把 revision 链留给 Registry 的先例同构。

**结论:不存在阻塞 IP-0005 的 Contract Gap。** IP-0004 满足其 IP-DONE 的消费者评审入口条件。

### 1.2 本 Packet 的兼容决策(冻结)

延续 IP-0002 §1.2、IP-0003 §1.2、IP-0004 既定模式(适用部分),并针对 VEP 扩展:

1. 只新增 `lima/contracts/vep.py`,不修改 `lima/contracts/__init__.py`;公共 API 只从 `lima.contracts.vep` 导入;
2. **载荷构成与依赖方向冻结**:`vep.py` import `lima.contracts.evidence`(内嵌 D3/D4 `EvidenceRecord` wire,复用其全部 scalar/数组校验器),**不 import** `lima.contracts.aep` 与 `lima.contracts.profile`——AEP 仅经类型化 lineage 引用(schema_name 字面量 `"lima.audit-evidence-package"`,IP-0004 对 profile 的同款先例)。依赖方向固定:`vep.py → {evidence, codec, common, errors}`;
3. 复用现有 **29** 个 `ContractErrorCode`,不扩展 `errors.py`;
4. 复用 `ArtifactEnvelope` / `decode_envelope` / `encode_envelope`,不创建第二套 Envelope 或 codec;仅 inline payload(blob 留给 Registry IP);
5. schema 版本 `4.0`;未知 major fail closed;同 major 未来 minor 经各对象 `extensions` 无损 round-trip;unknown enum / required 缺失永不降级;
6. 无比例字段(本 schema 无 metrics);`path_locations`/`target_location` 使用 evidence 模块 `SourceLocation`;文本/标识符/CWE/reason 规则全部复用 IP-0002 §12;
7. classification 禁 `public`;retention 禁 `ephemeral`;
8. schema name 固定 `lima.vulnerability-evidence-package`;
9. **Oracle/run 引用一律逻辑 artifact ref**(id + digest),不定义 Oracle/SandboxRun/Tool manifest schema(未来 IP);run/oracle 的 lineage schema_name 不做类型化校验(其 schema 未冻结),仅校验存在性与 digest 一致性;
10. RefutationReport/BlockedReport 是独立 Artifact 类型(#95 三选一输出),本 Packet 不定义;无法完整动态验证的对象由 #95 决定走另两类输出,VEP schema 不为其保留旁路。

---

## 2. Design Input Manifest

| Input ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001 | Standard | 稳定开发标准 | main `5984c5c` | 安全不变量、allowlist 纪律 | normative | 最高优先级之一 |
| DI-002 | Standard | lifecycle | main `5984c5c` | §9.1 拓扑、§12.2 PR 契约、§14 记录 | normative | — |
| DI-003 | Charter | P&V 责任书 | main `5984c5c` | Packet 必答、冻结纪律 | normative | — |
| DI-004 | Issue(Assignment) | PKT-IP-0005 Coordinator Assignment(2026-09-02) | 引用 Ledger v9 @14:12Z | 覆盖/不覆盖、§9 a-k、入口 Gate | normative | — |
| DI-005 | Issue | #58 正文 | 修订 `2026-09-01T14:36:22Z` | FR-02 VEP 子集、FR-03 终态映射、契约不变量节、NFR-01/02 | normative | V5 节优先 |
| DI-006 | Issue(Ledger) | #58 Ledger v9 | `2026-09-02T14:12:22Z` | 定序结论、一致性预检强制项(§9k 来源)、F-IP4-002/F-IP3-002 口径 | normative(current) | — |
| DI-007 | Decision | DECISION-DR-PMV-0001-01 / DR-IP-0003-TESTFIX-01 / DR-IP-0004-IMPL-01(issuecomment-5505168221 / 5506328396 / 5510460665) | 2026-09-02 | 恢复与重冻结先例;arrange 缺陷模式 | normative | — |
| DI-008 | Upstream IP | IP-0001/0002/0003/0004 Packets | #97/#99/#103/#105 及各 merge | codec/Envelope/29 codes;EvidenceRecord 全部规则与 D3/D4 预留;path/文本规则;类型化 lineage 先例(aep→profile);Registry 留白先例 | normative | — |
| DI-009 | Architecture | V5 规划文档(#58 指定 Source of truth) | 本地工作树副本 | §5.1/§5.2(VEP 最低内容、D3/D4 定义)、§5.1 后注(STATIC_PROPERTY/CONFIRMED_STATIC_PROPERTY)、§7.1(Mining 三选一输出)、§7.2(proof kinds)、§"Repair Gate 只接受 sealed VEP"、行 219-220/237-239 | normative(经 #58 V5 覆盖层转正) | 与 #58 正文冲突以 #58 为准 |
| DI-010 | Issue | #95 正文(V5-N06) | `2026-09-01T07:01:43Z` | 六态执行结果词汇(FR-N06-05:reproduced/not reproduced/inconclusive/blocked/tool error/policy denied)、AC-N06-05(static-property 不得声称 runtime exploitability)、AC-N06-06(digest mismatch/missing oracle/unsealed input 不得生成 VEP)、FR-N06-07(schema+provenance 完整才封装)、"VEP codec 兼容性归 #58" | background-only | 不从 #95 扩大实现范围;runtime/接口归 #95 |
| DI-011 | Issue | #61 / #68 正文 | 2026-09-01 | 上游 AEP/假设语义衔接(background) | background-only | — |
| DI-012 | Code | `lima/contracts/{common,codec,errors,evidence,profile,aep}.py` | main `5984c5c` | 当前真实 API、EvidenceRecord/SourceLocation 复用面、validator 风格 | current-behavior | 代码事实让位于 Packet 目标行为 |
| DI-013 | Test | `tests/contracts/` 全部 | main `5984c5c` | 测试风格、170/515 基线、golden 复用 | current-behavior | — |
| DI-014 | Evidence | IP-0004 POST-MERGE、Ledger v9 双重验证 | 2026-09-02 | 基线数字(170/515/1 skip)、冻结面(18/16/15/12/29、三 golden digest) | evidence | — |

### Explicitly Rejected Inputs

| 材料 | 拒绝原因 |
|---|---|
| #95 的 CapabilityPlugin/SupportDecision/ValidationPlan/Oracle/VerificationDecision 接口与 conformance suite | #95 实现职责;Assignment 明确不覆盖 |
| RVR schema、Task/ToolBundle/Dependency/Sandbox/Oracle manifest schema 任何字段草案 | 未映射子集;仅允许逻辑 artifact ref 引用 |
| RefutationReport / BlockedReport schema 设计 | #95 三选一输出的另两类,独立 Artifact,未来 IP |
| "not_reproduced ⇒ refuted" 的耦合 | "未复现"不是安全证明(NFR-01/#58);refuted_scope 必须有 refutes 证据 |
| blocked/tool_error/policy_denied 作为 verdict enum 值 | 基础设施状态不得编码为裁决;以 ReproductionOutcome 表达,永不进入 verdict 矩阵 |
| float confidence/severity、boolean is_vulnerable 类 verdict 旁路字段 | 违反 NFR-01 与无 float 契约;verdict enum + 等级矩阵是唯一裁决机制 |
| 修复建议/补丁内容字段 | 属 RVR/CandidatePatchSet(#76),VEP 只携带证据与结论 |
| 根工作树其余未跟踪规划文档 | 用户资产,未获引用 |

---

## 3. Iteration Hypothesis 与 Measurement

### 3.1 Hypothesis

如果 Mining 的输出被冻结为一个自包含、确定性、fail-closed 的 `VulnerabilityEvidencePackage` 契约——裁决只能来自 D3/D4 证据与等级矩阵、Oracle 引用强制存在且 digest 钉死、AEP 输入经类型化三元组引用、六态执行结果与裁决词表分离——那么"静态命中被当成漏洞""未复现被当成安全""缺 Oracle 的运行时漏洞升级为 verified""静态属性伪装成 runtime 可利用"这类真值事故在契约层就没有合法表达,#95/#76/V5-N02 可以只依赖 fixture 并行开发。

### 3.2 Measurement

- 固定 golden VEP 生成固定 canonical bytes(2091 bytes)与 SHA-256(`cd76622b…3061d01`);
- verdict×等级矩阵的全部非法组合、D0-D2 混入、Oracle 缺失/错配、AEP 引用缺失/错配/错 schema、悬空 run 引用、依赖环/越级、public/ephemeral Envelope 全部 fail closed;
- blocked/tool_error/policy_denied-only 的包在结构上只能 inconclusive;六态词表无 safe/clear/not_vulnerable;
- 新模块导入不加载 DB/网络/Docker/LLM/service/legacy models/aep/profile;加载 `lima.contracts.evidence`;
- 既有 515 个测试无新增失败。

---

## 4. Goal

实现一个 stdlib-only、无副作用、确定性、可版本演化的 `lima.contracts.vep` 叶子模块,包含:

1. 裁决与声明枚举:`VerificationVerdict`(candidate|inconclusive|refuted_scope|verified,#58 FR-03 词表)、`ClaimKind`(runtime_exploitability|static_property,AC-N06-05 区分)、`ReproductionOutcome`(六态,#95 FR-N06-05);
2. `AepReference`(FR-02 三元组:artifact_id + content_digest + schema_version)、`OracleReference`(oracle_artifact_id + content_digest——machine-executable Oracle 的最小描述符)、`ReproductionRun`(run_artifact_id + outcome + detail);
3. `VulnerabilityEvidencePackage`:内嵌 D3/D4 EvidenceRecord 图(subject 必须绑 hypothesis)、verdict×等级矩阵、Oracle/AEP/run 引用、位置/路径/触发条件/CWE/impact/refutation_scope;
4. VEP payload 与 IP-0001 `ArtifactEnvelope` 的 encode/decode binding(schema name、inline-only、类型化 AEP lineage、Oracle/run provenance、classification/retention、digest);
5. golden fixture、负向边界测试、import isolation 与 legacy regression。

---

## 5. Non-goals

本次明确不做:

- 不实现 Mining Core、CapabilityPlugin、ValidationPlan、Oracle 执行、VerificationDecision、sandbox、PoC 运行(#95);
- 不定义 RVR、RefutationReport、BlockedReport、Task/ToolBundle/Dependency/Sandbox/Oracle manifest schema;
- 不实现 Artifact Registry、blob、sealed 状态解析、revision 单调性(消费侧/Registry);
- 不生成 ID/digest/时间;不内联 raw 运行输出、日志、PoC 文本(run/oracle 一律逻辑引用);
- 不实现 Workflow/StageAttempt/Outcome/Plan/RunManifest/Summary/Failure schema;
- 不实现 JSON Schema 文件、兼容矩阵 artifact、ADR;
- 不修改或适配 legacy 模型;不接 API/Service/Store/Queue/Scanner/Sandbox/Registry/Frontend;
- 不调用 LLM,不访问网络/文件系统/环境变量,不执行目标仓库代码;
- 不引入 confidence/severity/risk/is_vulnerable/safe/clear 字段或任何 verdict 旁路;
- 不修改 `__init__.py`、`evidence.py`、`profile.py`、`aep.py`、`common.py`、`codec.py`、`errors.py` 或任何既有测试;
- 不实现 IP-0006 或任何顺手重构。

---

## 6. 工作树与分支前置条件

Coding Agent 必须:

1. 完整阅读稳定标准、lifecycle、Implementation Agent 责任书、本 Packet、`LIMA_Coding_Agent_IP-0005_正式开发任务交接.md`、`CONTRIBUTING.md`;
2. 确认两份 IP-0005 文档均已合并到 `origin/main`;
3. 依 lifecycle §9.1 从 Frozen Test Commit(阶段二交付物指定 SHA)派生 `codex/ip-0005-vep-foundation` 独立干净 worktree(禁用共享根工作树);
4. 确认 `lima/contracts/vep.py` 与本 Packet 的 3 个测试文件、1 个 fixture 尚不存在;
5. 输出 Scope Confirmation 后再运行 baseline;
6. baseline 或代码事实与本文不一致时停止并提交 Decision Request。

根工作树中的未跟踪规划文档属于用户资产,不得移动、删除、stash、覆盖或纳入实现 PR。

---

## 7. 文件边界

### 7.1 Files to Add(恰好 5 个)

```text
lima/contracts/vep.py
tests/contracts/test_vep.py
tests/contracts/test_vep_envelope.py
tests/contracts/test_vep_import_isolation.py
tests/contracts/fixtures/vulnerability_evidence_package_v4_golden.json
```

### 7.2 Files Allowed to Modify

```text
none
```

### 7.3 Files Forbidden

除上述 5 个新增文件外全部禁止修改,特别包括:`lima/contracts/{__init__,evidence,profile,aep,common,codec,errors}.py`;IP-0001/0002/0003/0004 的任何测试或 fixture;legacy models/service/api/task_progress/repository_scanner;frontend/、requirements*.txt、pyproject.toml、.github/、PROGRESS.md;任意范围外文档。

### 7.4 Ownership 与冲突边界

- `lima/contracts/vep.py` 在本 Packet 期间只有一个 Owner;
- 后续 IP 不得在本 Packet 合并前创建同名 symbol(12 个,见 §9);
- 新公共 symbol 不从 `lima.contracts` 顶层重导出;
- 依赖方向固定:`vep.py → evidence/codec/common/errors`;`evidence.py`、`aep.py`、`profile.py` 不得 import vep。

---

## 8. Allowed / Forbidden Dependencies

### 8.1 Allowed

`vep.py` 只允许导入:

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
lima.contracts.evidence
```

测试只允许额外使用 stdlib:`hashlib`、`pathlib`、`subprocess`、`sys`、`unittest`。

### 8.2 Forbidden

任何新增第三方包;`lima.contracts.aep`、`lima.contracts.profile`、`lima.models` 及生产层模块;HTTP/socket/DB/Docker/subprocess(产品)/文件系统(产品);UUID/当前时间/随机/环境变量;Pydantic 等第三方校验;绝对路径与 host path。

---

## 9. 冻结的公共 Symbols

`lima/contracts/vep.py` 的 `__all__` 必须严格等于以下集合,不多不少(**12** 项):

```python
__all__ = [
    "VULNERABILITY_EVIDENCE_PACKAGE_SCHEMA_NAME",
    "ClaimKind",
    "VerificationVerdict",
    "ReproductionOutcome",
    "AepReference",
    "OracleReference",
    "ReproductionRun",
    "VulnerabilityEvidencePackage",
    "decode_vep_payload",
    "encode_vep_payload",
    "decode_vep_envelope",
    "encode_vep_envelope",
]
```

模块常量:

```python
VULNERABILITY_EVIDENCE_PACKAGE_SCHEMA_NAME = "lima.vulnerability-evidence-package"
```

(注:12 = 1 常量 + 3 enum + 4 dataclass + 4 函数;以本枚举清单为准——F-IP3-002/F-IP4-002 教训。)

---

## 10. 冻结枚举

所有枚举使用 `class X(str, Enum)`(允许 `# noqa: UP042`),wire value 严格固定:

```python
class ClaimKind(str, Enum):
    RUNTIME_EXPLOITABILITY = "runtime_exploitability"
    STATIC_PROPERTY = "static_property"

class VerificationVerdict(str, Enum):
    CANDIDATE = "candidate"
    INCONCLUSIVE = "inconclusive"
    REFUTED_SCOPE = "refuted_scope"
    VERIFIED = "verified"

class ReproductionOutcome(str, Enum):
    REPRODUCED = "reproduced"
    NOT_REPRODUCED = "not_reproduced"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"
    TOOL_ERROR = "tool_error"
    POLICY_DENIED = "policy_denied"
```

语义冻结:

- `claim_kind` 声明本 VEP 的主张类型(AC-N06-05):`static_property + verified` 即 V5 的 `CONFIRMED_STATIC_PROPERTY`——**不得**通过任何字段声称 runtime 可利用性;`runtime_exploitability + verified` 要求完整 D3+D4 动态链;
- `verification_verdict` 是 #58 FR-03 词表的 VEP 侧表达,合法性由 §14 矩阵机器校验;
- `ReproductionOutcome` 是执行事实(#95 FR-N06-05 六态),与裁决分离:`blocked`/`tool_error`/`policy_denied` 是基础设施状态,**永不进入 verdict 矩阵、永不折叠为安全结论**(NFR-01);`not_reproduced` 是复现缺失,不是反驳——`refuted_scope` 必须有 refutes 证据(见 §14.2);词表结构上不存在 safe/clear/not_vulnerable。

---

## 11. Exact Constructors and Defaults

全部领域对象 `@dataclass(frozen=True, slots=True)`,defensive-copy 所有可变输入;required 无默认值字段在前:

### 11.1 `AepReference`

```python
AepReference(
    artifact_id: str,
    content_digest: str,
    schema_version: SchemaVersion,
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

### 11.2 `OracleReference`

```python
OracleReference(
    oracle_artifact_id: str,
    content_digest: str,
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

### 11.3 `ReproductionRun`

```python
ReproductionRun(
    run_artifact_id: str,
    outcome: ReproductionOutcome,
    detail: str,
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

### 11.4 `VulnerabilityEvidencePackage`

```python
VulnerabilityEvidencePackage(
    schema_version: SchemaVersion,
    verification_verdict: VerificationVerdict,
    claim_kind: ClaimKind,
    hypothesis_id: str,
    source_aep: AepReference,
    source_aep_revision: int,
    oracle: OracleReference,
    evidence: tuple[EvidenceRecord, ...],
    target_location: SourceLocation,
    impact: str | None,
    refutation_scope: str | None,
    path_locations: tuple[SourceLocation, ...] = (),
    reproduction_runs: tuple[ReproductionRun, ...] = (),
    trigger_conditions: tuple[str, ...] = (),
    cwe_ids: tuple[str, ...] = (),
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

`schema_version` 是 Envelope context,不进入 payload wire。四个 dataclass 均提供 `from_dict(value, *, schema_version) -> Self` 与 `to_dict()`(Python 3.11/3.12 兼容注解);`VulnerabilityEvidencePackage.from_dict` 复用 `EvidenceRecord.from_dict`/`SourceLocation.from_dict` 解析内嵌对象(错误 repath 至对应路径),并执行 §14 全部跨字段校验;`decode_vep_payload` 只是稳定公共入口。

---

## 12. Exact Wire Shapes

### 12.1 Top-level payload

4.0 的 required fields 恰好为以下 **14** 个(全部必填):

```json
{
  "verification_verdict": "verified",
  "claim_kind": "runtime_exploitability",
  "hypothesis_id": "hypothesis-0001",
  "source_aep": {"artifact_id": "aep-0001", "content_digest": "<64hex>", "schema_version": "4.0"},
  "source_aep_revision": 1,
  "oracle": {"oracle_artifact_id": "oracle-0001", "content_digest": "<64hex>"},
  "evidence": [],
  "reproduction_runs": [],
  "target_location": {},
  "path_locations": [],
  "trigger_conditions": [],
  "cwe_ids": [],
  "impact": null,
  "refutation_scope": null
}
```

`impact`/`refutation_scope` required-but-nullable(未知用 JSON `null`,不得省略);`evidence`/`reproduction_runs`/`path_locations`/`trigger_conditions`/`cwe_ids` 可为空数组。4.0 不允许其他字段。

### 12.2 `AepReference` / `OracleReference` / `ReproductionRun`

```json
{"artifact_id": "aep-0001", "content_digest": "f0a98543…", "schema_version": "4.0"}
{"oracle_artifact_id": "oracle-0001", "content_digest": "7a7a…"}
{"run_artifact_id": "run-0001", "outcome": "reproduced", "detail": "Deterministic PoC executed…"}
```

### 12.3 `evidence[i]`

与 IP-0002 `EvidenceRecord` wire shape 逐字段相同(全部 scalar/数组/文本规则原样生效);`target_location`/`path_locations[i]` 与 IP-0002 `SourceLocation` 相同(六字段全 required)。

### 12.4 Extensions

4.0:任何层级(顶层、aep/oracle/run)unknown field 以 `UNKNOWN_FIELD` 拒绝;内嵌 evidence/location 层级按 evidence 模块自身规则拒绝。未来 4.x:unknown optional field 在对应对象 `extensions` 无损 round-trip;required 缺失与 unknown enum 即使未来 minor 也拒绝。

---

## 13. Scalar Validation

- `source_aep_revision`:exact int(拒绝 bool),`1..9223372036854775807`;
- `artifact_id`/`oracle_artifact_id`/`run_artifact_id`/`hypothesis_id`:IP-0002 identifier 规则;
- `content_digest`(两处):`[0-9a-f]{64}`;
- `source_aep.schema_version`:IP-0001 `SchemaVersion.parse` 规则(字符串 `"<major>.<minor>"`,未知 major fail closed);
- `impact`/`refutation_scope`(非 null 时)与 `ReproductionRun.detail`:bounded text——exact str、NFC、非空、无 `Cc`、无前导/尾随空白、≤4096 UTF-8 bytes;
- `trigger_conditions`:canonical UTF-8 byte order 升序唯一、每项 ≤4096;
- `cwe_ids`:`CWE-[1-9][0-9]{0,5}` 升序唯一;
- enum 字段:非 str `INVALID_FIELD_TYPE`,未知值 `UNKNOWN_ENUM_VALUE`;error message 不回显原值。

---

## 14. Array Limits,Canonical Ordering 与 Cross-field Invariants

### 14.1 数组上限与排序

| Array | 上限 | 允许空 | 排序规则 |
|---|---:|---:|---|
| `evidence` | 256 | 是 | `evidence_id` ASCII 升序(复用 IP-0002 bundle 同款) |
| `reproduction_runs` | 64 | 是 | `run_artifact_id` ASCII 升序、唯一 |
| `path_locations` | 256 | 是 | order-significant(复现路径顺序,不排序) |
| `trigger_conditions` | 64 | 是 | canonical UTF-8 byte order 升序、唯一 |
| `cwe_ids` | 32 | 是 | ASCII 升序、唯一 |
| 记录内部数组 | 按 IP-0002 §13 | 按 IP-0002 | 按 IP-0002 |

### 14.2 证据等级与裁决矩阵(核心不变量)

先定义:`S4 = ∃ record(level=D4 ∧ polarity=supports)`;`S3 = ∃ record(level=D3 ∧ polarity=supports)`;`R = ∃ record(level ∈ {D3,D4} ∧ polarity=refutes)`。

**claim_kind = runtime_exploitability:**

| S4 | S3 | R | 允许的 verification_verdict |
|---|---|---|---|
| 0 | 0 | 0 | inconclusive |
| 0 | 1 | 0 | candidate、inconclusive |
| 0 | * | 1 | refuted_scope、inconclusive |
| 1 | 1 | 0 | verified、candidate |
| 1 | 0 | 0 | inconclusive(D4 无 D3 链,不得 verified/candidate) |
| 1 | * | 1 | inconclusive(D4 支持与反驳冲突,保留冲突) |

**claim_kind = static_property:**

| S4 | R | 允许的 verification_verdict |
|---|---|---|
| 1 | 0 | verified(即 CONFIRMED_STATIC_PROPERTY) |
| 0 | 1 | refuted_scope、inconclusive |
| 1 | 1 | inconclusive |
| 0 | 0 | inconclusive |

附加必要条件(违反 → `INVALID_FIELD_VALUE`,路径见括号):

- `verified` ⇒ `impact` 非 null(`$.impact`);
- `verified` 且 claim=runtime ⇒ `reproduction_runs` 中 ≥1 项 outcome==reproduced(`$.reproduction_runs`);
- `refuted_scope` ⇒ `refutation_scope` 非 null(`$.refutation_scope`);
- `oracle` 恒必填(§12.1;缺失即 `REQUIRED_FIELD_MISSING`)——V5-FR-03"缺 Oracle 不成 VEP"的机器化。

矩阵设计依据:无 D4 不得 verified;runtime verified 需 D3(受控复现)+ D4(影响/前提/Oracle)完整链(V5 §5.1:可执行行为类漏洞无 D3/D4 动态证据不得成为 verified);static verified 仅需确定性 Oracle 的 D4(V5 §5.1 后注);supports/refutes 在 D3/D4 层并存 ⇒ 强制 inconclusive(冲突保留,IP-0002 先例);blocked/tool_error/policy_denied/not_reproduced 不进入矩阵 ⇒ 结构上不可能被折叠为任何裁决。

### 14.3 内嵌证据约束

- `evidence[i].level ∈ {D3, D4}`;D0/D1/D2 → `INVALID_FIELD_VALUE $.evidence[i].level`(Mining bundle 与 Audit bundle 的镜像对称);
- `evidence[i].subject_kind == "vulnerability_hypothesis"`(否则 `INVALID_FIELD_VALUE $.evidence[i].subject_kind`);
- `evidence[i].subject_id == hypothesis_id`(否则 `INVALID_FIELD_VALUE $.evidence[i].subject_id`);
- 依赖 DAG(数组内):depends_on 必须存在、禁 self、禁环、依赖项 level 数值不得高于自身(IP-0002 §14.4 同款;错误路径 `$.evidence[i].depends_on_evidence_ids[j]`)。

### 14.4 Provenance(Envelope binding 阶段)

- `source_aep.artifact_id` 必须存在于 lineage,且对应条目 `schema_name == "lima.audit-evidence-package"`、`content_digest == source_aep.content_digest`、`schema_version == source_aep.schema_version`(类型化三元组双向核对);
- `oracle.oracle_artifact_id` 必须存在于 lineage,且对应条目 `content_digest == oracle.content_digest`(Oracle manifest schema 未冻结,不做类型化 schema 校验);
- `reproduction_runs[i].run_artifact_id` 与全部 `evidence[i].source_artifact_ids` 必须存在于 lineage(存在性;SandboxRun/Tool manifest schema 属未来 IP);
- lineage 允许额外条目;tenant/snapshot/self/duplicate/conflict 由 IP-0001 拒绝;
- **不做的耦合(明确豁免)**:AEP 的 sealed 状态与 revision 单调性无法从引用解析,属 #95/Registry 消费侧规则(§1.1);`not_reproduced` 不强制产生任何证据(生产者语义)。

---

## 15. Envelope Binding Contract

### 15.1 Function signatures

```python
def decode_vep_payload(value: Mapping[str, JSONValue], *, schema_version: SchemaVersion) -> VulnerabilityEvidencePackage: ...
def encode_vep_payload(package: VulnerabilityEvidencePackage) -> dict[str, JSONValue]: ...
def decode_vep_envelope(data: bytes, *, limits: ContractLimits = DEFAULT_LIMITS) -> tuple[ArtifactEnvelope, VulnerabilityEvidencePackage]: ...
def encode_vep_envelope(envelope: ArtifactEnvelope, package: VulnerabilityEvidencePackage, *, limits: ContractLimits = DEFAULT_LIMITS) -> bytes: ...
```

### 15.2 Binding rules

`decode_vep_envelope` 必须:

1. 调用 IP-0001 `decode_envelope`;
2. `schema_name == VULNERABILITY_EVIDENCE_PACKAGE_SCHEMA_NAME`;
3. inline payload only(拒绝 blob,`INVALID_FIELD_TYPE $.payload`);
4. 以 envelope `schema_version` decode package;
5. §14.4 provenance:AEP 类型化三元组核对(缺失/错 schema → `INVALID_FIELD_VALUE $.payload.source_aep.artifact_id`;digest 不符 → `DIGEST_MISMATCH $.payload.source_aep.content_digest`);Oracle(缺失 → `INVALID_FIELD_VALUE $.payload.oracle.oracle_artifact_id`;digest 不符 → `DIGEST_MISMATCH $.payload.oracle.content_digest`);run 与 evidence 来源(缺失 → `INVALID_FIELD_VALUE`,路径 `$.payload.reproduction_runs[i].run_artifact_id` / `$.payload.evidence[i].source_artifact_ids[j]`);
6. 允许额外 lineage;
7. classification != public(`INVALID_FIELD_VALUE $.classification`);
8. retention != ephemeral(`INVALID_FIELD_VALUE $.retention_class`);
9. 返回 `(envelope, package)`,不修改输入。

`encode_vep_envelope` 执行相同 binding,并额外:`envelope.schema_version == package.schema_version`;`envelope.payload == encode_vep_payload(package)`;`compute_content_digest` 与 `envelope.content_digest` 用 `hmac.compare_digest` 相等;最终调用 `encode_envelope`;不自动创建/修补 Envelope。

VEP 携带可利用性证明、PoC 引用与影响描述,属高敏感安全证据:classification 禁 public、retention 禁 ephemeral。

---

## 16. Stable Error Mapping and Precedence

复用现有 **29** 个 code,message 由 IP-0001 catalog 决定且不回显输入。映射与 IP-0004 §16 同款(required 缺失 / unknown field / 类型 / enum / 值·排序·重复·矩阵·DAG / 上限 / NFC 冲突 / digest / lineage 继承 / codec 资源),不再新增条目。优先级:

1. codec byte/UTF-8/JSON/resource;
2. top-level container/required/current unknown/schema version;
3. enum 与 scalar type(含 revision/三元组字段);
4. scalar value/range、数组 limit/order/duplicate;
5. 内嵌 evidence/location 校验(经 evidence 模块,repath 至 `$.evidence[i].*`、`$.target_location.*`、`$.path_locations[i].*`);
6. 跨字段:D3/D4-only 与 subject 绑定(§14.3)→ verdict 矩阵与附加必要条件(§14.2)→ DAG(§14.3);
7. lineage provenance(§14.4:类型化 AEP、Oracle、run/evidence 来源);
8. Envelope schema/payload/digest/classification/retention binding。

`field_path` 示例:

```text
$.verification_verdict
$.impact
$.source_aep.schema_version
$.oracle.oracle_artifact_id
$.evidence[1].level
$.evidence[0].depends_on_evidence_ids[0]
$.reproduction_runs[0].outcome
$.payload.source_aep.content_digest
$.payload.evidence[0].source_artifact_ids[1]
```

---

## 17. Golden Fixture

文件:

```text
tests/contracts/fixtures/vulnerability_evidence_package_v4_golden.json
```

要求:UTF-8;单行 canonical JSON;无 BOM;无 trailing newline;**exactly 2091 bytes**;payload SHA-256:

```text
cd76622b48d11c0300e63d7489701479c75dc2f4b06cc6c4e88af1f453061d01
```

该 bytes 与 digest 已由 IP-0001 codec 在 main `5984c5c` 预计算冻结;`source_aep.content_digest` 即 IP-0004 AEP golden 的真实 digest(证据链跨切片连续)。权威内容如下;实现者不得更改字段、值、顺序或摘要:

```json
{"claim_kind":"runtime_exploitability","cwe_ids":["CWE-78"],"evidence":[{"analysis_family":"dynamic-validation","depends_on_evidence_ids":["evidence-run-0001"],"evidence_id":"evidence-impact-0001","independence_key":"mining:impact:run-0001","level":"D4","location":null,"polarity":"supports","producer":"lima-mining","reason_codes":["ORACLE_VERIFIED"],"source_artifact_ids":["oracle-0001","run-0001"],"subject_id":"hypothesis-0001","subject_kind":"vulnerability_hypothesis","summary":"Impact, attack prerequisites, and machine oracle verified."},{"analysis_family":"dynamic-validation","depends_on_evidence_ids":[],"evidence_id":"evidence-run-0001","independence_key":"mining:repro:run-0001","level":"D3","location":null,"polarity":"supports","producer":"lima-mining","reason_codes":["RUNTIME_REPRODUCED"],"source_artifact_ids":["run-0001"],"subject_id":"hypothesis-0001","subject_kind":"vulnerability_hypothesis","summary":"Controlled-environment run reproduced the unexpected behavior."}],"hypothesis_id":"hypothesis-0001","impact":"A remote CLI argument injection allows arbitrary command execution in the deployment container.","oracle":{"content_digest":"7777777777777777777777777777777777777777777777777777777777777777","oracle_artifact_id":"oracle-0001"},"path_locations":[{"end_column":24,"end_line":20,"path":"src/cli.py","start_column":1,"start_line":20,"symbol":"main"},{"end_column":18,"end_line":10,"path":"src/example.py","start_column":5,"start_line":10,"symbol":"run_command"}],"refutation_scope":null,"reproduction_runs":[{"detail":"Deterministic PoC executed the shell metacharacter payload and observed command execution.","outcome":"reproduced","run_artifact_id":"run-0001"}],"source_aep":{"artifact_id":"aep-0001","content_digest":"f0a985432ebd11dc4b85897653cf443dc2c0b0312e453424648ebc2d164705d0","schema_version":"4.0"},"source_aep_revision":1,"target_location":{"end_column":18,"end_line":10,"path":"src/example.py","start_column":5,"start_line":10,"symbol":"run_command"},"trigger_conditions":["attacker controls the CLI argument"],"verification_verdict":"verified"}
```

### 17.1 Frozen envelope vector

```text
schema_name = lima.vulnerability-evidence-package
schema_version = 4.0
artifact_id = vep-0001
tenant_id = tenant-1 / task_id = task-1 / workflow_id = workflow-1 / stage_attempt_id = mining-1
repository_snapshot_digest = "3" * 64
producer = lima-mining
created_at = 2026-09-02T00:00:00Z
policy_digest = "5" * 64 / toolchain_digest = "6" * 64
content_digest = cd76622b48d11c0300e63d7489701479c75dc2f4b06cc6c4e88af1f453061d01
classification = sensitive / retention_class = audit
lineage[0]: lima.audit-evidence-package / 4.0 / aep-0001 / tenant-1 / "3"*64 / f0a98543…64705d0
lineage[1]: lima.oracle-script / 4.0 / oracle-0001 / tenant-1 / "3"*64 / "7" * 64
lineage[2]: lima.sandbox-run / 4.0 / run-0001 / tenant-1 / "3"*64 / "8" * 64
supersedes = null / coverage_gaps = []
```

(lineage[1]/[2] 的 schema_name 为 illustrative 逻辑名——Oracle 与 SandboxRun manifest schema 属未来 IP,VEP 对其只做存在性/digest 校验,不做类型化 schema 断言。)

---

## 18. Required Tests

测试使用 `unittest`,方法名冻结如下;可增加 helper 与更细测试,不得减少、重命名或合并。

### 18.1 `tests/contracts/test_vep.py`(26)

```text
VepEnumTests
  test_wire_values_are_exact

AepReferenceTests
  test_round_trip_has_exact_wire_shape
  test_rejects_missing_invalid_and_mismatched_fields

OracleReferenceTests
  test_round_trip_has_exact_wire_shape
  test_rejects_missing_and_invalid_fields

ReproductionRunTests
  test_round_trip_has_exact_wire_shape
  test_rejects_invalid_outcome_detail_and_missing_fields

VulnerabilityEvidencePackageTests
  test_minimal_inconclusive_package_round_trip_is_valid
  test_golden_package_round_trip_and_digest
  test_rejects_wrong_container_and_missing_required_fields
  test_rejects_unknown_enum_and_wrong_field_type
  test_rejects_static_evidence_levels
  test_evidence_subject_must_match_hypothesis
  test_verified_runtime_requires_d3_and_d4_supports_impact_and_reproduced_run
  test_verified_static_property_requires_only_d4
  test_refuted_scope_requires_refuting_evidence_and_scope_text
  test_supports_and_refutes_conflict_requires_inconclusive
  test_insufficient_evidence_forces_inconclusive_or_candidate
  test_oracle_reference_is_always_required
  test_blocked_tool_error_and_policy_denied_never_yield_verdicts
  test_rejects_unsorted_duplicate_and_oversize_arrays
  test_evidence_dependency_dag_enforced
  test_future_minor_round_trips_unknown_fields_at_every_level
  test_current_minor_rejects_unknown_fields_at_every_level
  test_defensive_copy_prevents_post_construction_mutation
  test_payload_has_no_confidence_severity_or_verdict_bypass_fields
```

`test_payload_has_no_confidence_severity_or_verdict_bypass_fields` 递归断言 golden 与 minimal payload 任意层级不出现键:`confidence`、`severity`、`risk_score`、`is_vulnerable`、`safe`、`clear`。

### 18.2 `tests/contracts/test_vep_envelope.py`(11)

```text
VepEnvelopeTests
  test_frozen_envelope_encode_decode_is_byte_stable
  test_rejects_wrong_schema_name_and_version_mismatch
  test_rejects_blob_backed_vep
  test_rejects_payload_package_and_content_digest_mismatch
  test_rejects_missing_aep_lineage_reference
  test_rejects_aep_lineage_entry_with_wrong_schema_name_or_digest
  test_rejects_missing_oracle_and_run_lineage_references
  test_allows_additional_valid_lineage
  test_inherits_cross_tenant_cross_snapshot_and_self_reference_rejection
  test_rejects_public_classification_and_ephemeral_retention
  test_tampered_payload_fails_before_domain_promotion
```

### 18.3 `tests/contracts/test_vep_import_isolation.py`(4)

```text
VepImportIsolationTests
  test_module_public_api_matches_frozen_symbol_set
  test_clean_process_import_has_no_db_network_docker_llm_service_or_legacy_models
  test_module_only_uses_allowed_imports
  test_import_does_not_change_lima_contracts_top_level_public_api
```

`test_clean_process_import…` 必须断言:干净子进程导入 `lima.contracts.vep` 后 `lima.contracts.evidence` **在** `sys.modules`,而 `lima.contracts.aep`、`lima.contracts.profile` 与其余 forbidden roots **不在**。

### 18.4 Minimum count

IP-0005 必须新增至少 **41** 个独立 test methods(26+11+4)。

---

## 19. Acceptance Criteria and Traceability

| AC | Required behavior | Evidence(test) | 覆盖的 Issue requirement |
|---|---|---|---|
| IP5-AC-01 | 12 个 module public symbols、3 个 enum wire vocabulary、4 个 exact constructors 冻结 | enum/object/import tests | FR-02(VEP 版本化定义) |
| IP5-AC-02 | 三元组/标识符/digest/revision/text/CWE scalar 与数组上限 fail closed | Aep/Oracle/Run/package negative tests | NFR-02 |
| IP5-AC-03 | golden VEP 2091 bytes、固定 digest、byte-stable;source_aep.digest = AEP golden 真实 digest | golden test | FR-05、AC-01 方法论 |
| IP5-AC-04 | 内嵌 evidence 仅 D3/D4、subject 绑 hypothesis、DAG 完整 | §14.3 tests | FR-03、NFR-01 |
| IP5-AC-05 | verdict×等级矩阵(两种 claim_kind 全行)+ verified/refuted 附加条件机器强制 | 矩阵 tests | FR-03、AC-N06-05 |
| IP5-AC-06 | Oracle 恒必填 + lineage 存在 + digest 钉死(缺 Oracle 不成 VEP) | oracle tests | V5-FR-03 前半句、AC-N06-06 |
| IP5-AC-07 | 类型化 AEP 三元组 lineage 核对;run/evidence provenance;classification/retention | envelope tests | FR-02、NFR-01 |
| IP5-AC-08 | 六态执行结果与裁决分离;blocked/tool_error/policy_denied 结构上不可产生裁决;无 confidence/severity/is_vulnerable/safe/clear/risk_score | 六态 + forbidden-key tests | NFR-01、AC-N06-05 |
| IP5-AC-09 | stdlib leaf;依赖 vep→evidence/codec/common/errors;不加载 aep/profile;冻结面不变 | import isolation + git diff | AC-04(T-04) |
| IP5-AC-10 | 5 added / 0 modified / 0 deps / 全量回归无新增失败 | file boundary + full regression | AC-04 |

---

## 20. 强制实现顺序(含冻结前一致性预检,Assignment §9k / Ledger v9)

阶段二由 P&V 执行 **1-6**,Implementation Agent 从第 7 步开始:

1. 编写测试前,先以脚本对**每个测试的 arrange 数据**逐一核对 §14 跨字段规则(等级矩阵、subject 绑定、DAG、排序、三元组/Oracle/引用完整性)——两次重冻结教训的制度化;预检脚本与结果记入 RED Evidence Record;
2. 编写 3 个测试文件 + fixture(逐字节复制 §17 权威内容);
3. 测试自身质量门禁(compileall/ruff;I001 模块缺失现象须 stub 复证);
4. 证明有效 RED(预期失败全部归因 `lima.contracts.vep` 不存在);
5. 创建 Frozen Test Commit + digest + 数量,推送传输点;
6. Coordinator 出具 Implementation Assignment;
7. Implementation Agent 从 Frozen Test Commit 开始:枚举/validators/三个引用对象 → `VulnerabilityEvidencePackage`(§14 全部跨字段校验)→ 逐字验证 golden → 4 个 binding functions → import isolation/forbidden-key → Slice Gate → Compatibility Gate → File Boundary Gate → Completion Summary。

不得先写完实现再弱化测试;测试发现 Packet 冲突时停止。

---

## 21. Done Commands

### 21.1 Baseline(编码前)

```powershell
python -m compileall -q lima scripts tests
python -m unittest discover -s tests/contracts -v
python -m unittest -v tests.test_repository_source tests.test_task_failure
```

预期基线(@ `5984c5c` + 本 Packet 合并):contracts **170** PASS;定向兼容 **29** PASS。

### 21.2 Slice Gate

```powershell
python -m compileall -q lima/contracts tests/contracts
python -m unittest discover -s tests/contracts -v
python -m ruff check lima/contracts/vep.py tests/contracts/test_vep.py tests/contracts/test_vep_envelope.py tests/contracts/test_vep_import_isolation.py
python -m ruff check lima/contracts tests/contracts
python -m bandit -q -r lima/contracts/vep.py
git diff --check
```

### 21.3 Compatibility Gate

```powershell
python -m unittest -v tests.test_repository_source tests.test_task_failure
python -m unittest discover -s tests -v
```

实现后预期 contracts **211**(170+41)、全量 **556**(515+41)/ 0 failed / 1 既有 skip。任何新增 failure/skip 必须解释;不能通过修改 legacy 测试解决。Python 3.11/3.12 由 CI matrix 验证。

### 21.4 File Boundary Gate

```powershell
git diff --name-only --diff-filter=ACMRTUXB <frozen-test-commit>...HEAD
git diff --check <frozen-test-commit>...HEAD
```

输出必须恰好为 7.1 的 5 个新增文件(相对 Frozen Test Commit,产品侧仅 `lima/contracts/vep.py`)。

### 21.5 Optional release-level gate

维护者或 CI 可运行 `powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 test`;普通 Agent 不因 Docker/宿主环境不可用而改变产品代码。

---

## 22. Security and Compatibility Invariants

- 无 D4 不得 verified;runtime verified 需 D3+D4 完整动态链;static verified 仅限确定性 Oracle 的 D4 且不得声称 runtime 可利用性;
- supports/refutes 冲突强制 inconclusive;blocked/tool_error/policy_denied/not_reproduced 永不折叠为裁决或安全结论;
- Oracle 恒必填且 digest 钉死;类型化 AEP 三元组核对;篡改/错配 fail closed;
- raw 运行输出、日志、PoC 文本不内联(一律逻辑 artifact ref);
- classification 禁 public、retention 禁 ephemeral;
- ID/digest/时间全部由调用方提供;
- 不新增任何权限;不改变 legacy 行为与四个上游 IP 冻结面(18/16/15/12/29、三 golden digest);
- 不通过 future-minor extension 绕过 required、enum、矩阵或 provenance。

---

## 23. Stop Conditions / Decision Request

出现以下任一情况必须停止:

1. 两份 IP-0005 文档尚未合并到 `origin/main`,或基线不再是 `5984c5c` 后代、冻结面(18/16/15/12/29)漂移;
2. 最新 `main` 已出现同名 `vep.py` 或冲突 Owner;
3. 需要修改任一 forbidden 文件或扩大 allowlist;
4. 需要新增第三方依赖、I/O、网络、数据库、Docker、subprocess 或环境权限;
5. §10-§16 任一契约存在两个与上游决策同等自洽的答案;
6. frozen fixture 的 2091 bytes / digest 无法由 IP-0001 codec 重现,或 source_aep digest 与 AEP golden 不一致;
7. 需要引入 float、confidence/severity、verdict 旁路、自动 ID 或放宽矩阵/Oracle/provenance 才能继续;
8. 需要实现 Mining 执行、Oracle 运行、sandbox、插件系统或定义 RVR/manifest schema 才能让测试通过;
9. baseline/全量回归失败且无法归因;required tests 无法证明某个 AC;
10. 发现工作实际进入 #95 runtime、RVR、workflow schema 或生产接线。

Decision Request 格式同 Packet 惯例(Packet/规则位置/实际代码证据/最小复现命令/为什么无法在 5-file allowlist 内解决/可选方案/影响/建议)。

---

## 24. Git, Commit and PR Contract

推荐 commit / PR 标题:`feat: add deterministic vulnerability evidence package contracts`。PR 正文:只写 `Related to #58`;禁 auto-close 关键字;AC → Test → Result;真实命令、退出码、统计;5 added / 0 modified / 0 dependencies;no runtime/no plugin/no manifest schema/top-level API unchanged;等待独立 Review 与 `merge-gate`。Implementation Agent 不合并 PR、不删分支/worktree、不改 Issue。

---

## 25. Completion Summary Template

```markdown
## IP-0005 Completion Summary

### Result
- Status: DONE | NOT DONE | BLOCKED
- Base commit / Frozen Test Commit / Final commit / Branch / Worktree:

### Scope
- Added files / Modified existing files: none / Dependencies added: none
- Public API: lima.contracts.vep only (12 symbols)
- Contract deviations: none | <Decision Request>

### Acceptance evidence
| AC | Test/command | Result |
|---|---|---|
| IP5-AC-01 … IP5-AC-10 | | |

### Commands and actual results(命令/退出码/统计)
### Security and compatibility(矩阵/DAG/Oracle/provenance/echo/隔离/py3.11-12/回归)
### Findings and decisions
### Handoff(PR 状态/唯一下一步/禁止动作)
```

---

## 26. Maintainer Review Checklist

- [ ] base 为 Frozen Test Commit 后代且含本 Packet;只新增 5 文件;vep.py 是唯一产品文件;
- [ ] 冻结面不变:18/16/15/12/29、三 golden digest;evidence/profile/aep/`__init__` 零改动;
- [ ] module API 恰 12 symbols;依赖 vep→{evidence,codec,common,errors};不加载 aep/profile;
- [ ] 14 个 top-level required 字段、内嵌 EvidenceRecord/SourceLocation wire 无漂移;
- [ ] golden 2091B/`cd76622b…`、source_aep.digest = AEP golden digest;
- [ ] 矩阵(两 claim_kind 全行)、附加条件、D3/D4-only、subject 绑定、DAG negative tests 通过;
- [ ] Oracle 恒必填 + 类型化 AEP + run/evidence provenance + classification/retention tests 通过;
- [ ] 六态分离与 forbidden-key 通过;current/future-minor 每层级通过;
- [ ] 全量回归无新增失败(预期 556 = 515+41);全目录 ruff exit 0;
- [ ] File Boundary 恰 5 文件;Completion Summary 可复现;独立 Review 与 merge-gate 通过;
- [ ] PR 未关闭 #58;未启动 IP-0006、#95 runtime 或生产接线。

---

## 27. Packet 完成定义

只有全部 10 个 AC、41 个 required tests、golden fixture、Envelope consumer test、import isolation、完整命令证据、独立 Review 和 `merge-gate` 全部满足,IP-0005 实现才能标记 DONE。

IP-0005 合并后,协调者必须在最新 `main` 上安排 post-merge verification,并让下一个消费 IP(依 Ledger 定序:IP-0006 Workflow 族或 RVR)对本模块做只读 consumer review(其 Packet 的 Design Input Manifest 入口 Gate)。当前 Agent 不自动继续下一个 IP。
