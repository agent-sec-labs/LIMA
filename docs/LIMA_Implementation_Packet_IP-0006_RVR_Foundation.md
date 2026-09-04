# LIMA Implementation Packet IP-0006:Repair Verification Report(RVR)Foundation

> Packet ID:`IP-0006`
>
> 状态:`DESIGN-FROZEN / READY-FOR-CODE WHEN THIS PACKET IS MERGED TO MAIN`
>
> Source Issue:[#58](https://github.com/agent-sec-labs/LIMA/issues/58) 的第六个独立实现切片(第五个 domain 切片,Repair 侧第一个 Artifact)
>
> 最低代码基线:Assignment 基线 `8afc594b194b9bce4cec4930901f88bbb4fdda83`(IP-0005 实现,PR #110);实现基线必须是包含本 Packet 与正式交接书的最新 `origin/main`
>
> 推荐分支:`codex/ip-0006-rvr-foundation`(依 lifecycle §9.1 从 Frozen Test Commit 派生,实现阶段 Assignment 另行出具)
>
> Owner:唯一 Implementation Agent;不得与任何活动 IP 并行修改 `lima/contracts/` 或 `tests/contracts/`

## 需求映射(Header)

```text
Source Issue:#58
Issue specification revision:正文修订 2026-09-01T14:36:22Z(V4 基线 + V5 覆盖层,冲突以 V5 节为准);
  Delivery Ledger v13 @ 2026-09-02T18:08Z(激活依据:IP-0005 IP-DONE + "IP-0006 定序终审 = RVR Foundation")
Covered requirements:FR-02 的 RVR 子集(版本化 schema;跨对象引用 artifact_id + content_digest +
  schema_version 三元组,经 payload 字段 + Envelope lineage 双重表达);V5-FR-03 后半句(RVR 逐候选逐
  Gate——"任一 mandatory Gate 非 pass ⇒ 该候选不得 verified-patch"机器化);FR-03 终态映射的 Repair 侧
  (verified-patch 的合法前置);支撑性覆盖 FR-05(RVR fixture 子集)、FR-06(本 schema 兼容)、
  NFR-01(Gate 失败/blocked 不折叠为安全结论)、NFR-02(校验上限)
Not covered requirements:CandidateManifest/ToolBundle/Task/Dependency/Sandbox manifests schema(候选与
  patch 仅逻辑 artifact 引用,#76 的 CandidateManifest 是未来 manifest IP);V5-FR-01 其余子集
  (Workflow/StageAttempt/Outcome/Plan/RunManifest/Summary/Failure);#76 全部实现职责(候选生成、
  workspace、scope policy、LLM parser);#77/#94 类 Gate 执行器与"生成者不自证"的运行时执行;
  修复发布(GitHub PR)、Mining workspace 读取、真实沙箱执行、生产接线、前端
Delivery role:domain
Issue closure impact:PARTIAL(合并后不触发 #58 closure;#58 保持 open)
Upstream IP/PR/merge commits:
  IP-0001 #97 `5cdf872` / #98 `d3e73d9` / 恢复 #102 `a0b3eea`(IP-DONE)
  IP-0002 #99 `f92122b` / #100 `4fe1def`(IP-DONE)
  IP-0003 #103 `437fe01` / Frozen v2 `573de77` / #104 `9078bb5`(IP-DONE)
  IP-0004 #105 `046d67b` / Frozen v2 `aa2e3c5` / #107 `5984c5c`(IP-DONE)
  IP-0005 #108 `69458e5` / Frozen v2 `4b1cf6b` / #110 `8afc594`(IP-DONE)
Activation gate:lifecycle 入口 consumer review(见 §1,已完成,无 Contract Gap)
```

---

## 0. 执行决策

当前执行队列(Ledger v13,2026-09-02):

```text
DONE
IP-0001(+R1)、IP-0002、IP-0003、IP-0004、IP-0005(全部 IP-DONE)

NOW(只允许 1 个)
IP-0006 Repair Verification Report(RVR)Foundation(Design Frozen;文档合并后进入阶段二)

NEXT(不得实现)
IP-0007 候选:Workflow/StageAttempt/Outcome schemas(V5-FR-01 主体)

LATER
其余 workflow 族 schema / Task/ToolBundle/Dependency/Sandbox/Candidate manifests /
JSON Schema + 兼容矩阵 + ADR(Issue PR3)/ legacy adapter fixture(Issue PR4)/ closure IP
```

本 Packet 只建立可被 #76(候选生成)、#77(Gate 执行)、#70(UI)与 V5-N02/#91 消费的确定性 `RepairVerificationReport` Artifact 契约。它不实现候选生成、Gate 执行器、沙箱、修复发布或任何生产接线。

---

## 1. IP-0005 消费者评审结论(lifecycle 入口 Gate,只读)

### 1.1 已验证事实(@ main `8afc594`,P&V 实证执行,2026-09-02)

- **VepReference 三元组可构造**:由 VEP golden payload 计算的 `source_vep = {artifact_id: "vep-0001", content_digest: "cd76622b…3cb2cac"→(VEP golden 真实值), schema_version: "4.0"}` 完整可表达;`VULNERABILITY_EVIDENCE_PACKAGE_SCHEMA_NAME` 常量使类型化 lineage 校验可行(rvr.py 按先例以字面量 `"lima.vulnerability-evidence-package"` 校验,不 import vep);
- **RVR 输入所需 VEP 语义面可读**:`verification_verdict`(verified)、`claim_kind`、`hypothesis_id`、`oracle`、`reproduction_runs` 均为只读可消费属性;**verdict 继承约束(源 VEP 须 verified)在契约层的体现 = 类型化引用 + digest 钉死**,verdict 内容不可从引用解析——同 AEP sealed / VEP 源约束先例,属 #77/Registry 消费侧规则(单解);
- **EvidenceRecord 构造面衔接点结论**:`EvidenceSubjectKind` 词表(signal/security_issue/vulnerability_hypothesis)**无 candidate 主体**——Gate 结果无法复用 `EvidenceRecord` 绑定候选,且禁止修改 evidence.py;因此 `GateResult` 必须是 RVR 本地值类型,gate 证据一律逻辑 artifact ref(结构性理由,实证成立);
- 冻结面在 main 无漂移:contracts 211/211、全量 556/0 failed/1 既有 skip、ruff 全目录 exit 0、顶层 18 / evidence 16 / profile 15 / aep 12 / vep 12 / 29 codes、四 golden(evidence 3740B、profile 2152B、aep 4235B、vep 2091B)。

**结论:不存在阻塞 IP-0006 的 Contract Gap。** IP-0005 满足其 IP-DONE 的消费者评审入口条件。

### 1.2 本 Packet 的兼容决策(冻结)

延续 IP-0002/0003/0004/0005 既定模式(适用部分),并针对 RVR 扩展:

1. 只新增 `lima/contracts/rvr.py`,不修改 `lima/contracts/__init__.py`;公共 API 只从 `lima.contracts.rvr` 导入;
2. **依赖方向冻结:`rvr.py → {codec, common, errors}`,不 import evidence/aep/vep/profile**——理由:GateResult 是本地值类型(§1.1-3 的结构性结论);VEP 引用以本地 `VepReference` 值类型 + 类型化 lineage 表达(vep 的 `AepReference` 同构先例);path/text/identifier/digest 校验器本地实现(与 profile.py 先例相同,规则逐条等同);
3. 复用现有 **29** 个 `ContractErrorCode`,不扩展 `errors.py`;
4. 复用 `ArtifactEnvelope` / `decode_envelope` / `encode_envelope`;仅 inline payload;
5. schema 版本 `4.0`;未知 major fail closed;同 major 未来 minor 经各对象 `extensions` 无损 round-trip;unknown enum / required 缺失永不降级;
6. classification 禁 `public`;retention 禁 `ephemeral`;
7. schema name 固定 `lima.repair-verification-report`;
8. **无整体 report verdict 字段**(设计决策,见 Rejected Inputs):"≥1 verified_patch 候选 ⇒ workflow 可提升 VERIFIED_PATCH"是消费侧派生规则;"无候选/全部候选失败 ≠ 漏洞不存在"(#76 FR-06)由"RVR 无任何可表达漏洞状态的字段"结构性保证;
9. **mandatory Gate 集合 = {Security Preservation, Functional Preservation} 恰好两个**(标准 §17 与 V5 §4.4 的规范表述);V5 §8.2 的 11 步执行序列属 #77/#94 runtime,其证据经 `gate.evidence_artifact_ids` 逻辑引用进入 RVR,不在契约层展开;
10. **"生成者不自证"的契约面表达**:`candidate.generator` 与每个 `gate.producer` 均为必填 identifier,且**每个 gate 的 producer 必须不等于该候选的 generator**(`INVALID_FIELD_VALUE`)——identifier 字符串相等性是可得的最强机器校验,签发级身份归 Registry/未来 IP;
11. patch/diff/raw 代码、行为差分输出、Gate 日志一律逻辑 artifact ref + digest,不内联(敏感内容)。

---

## 2. Design Input Manifest

| Input ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001 | Standard | 稳定开发标准(§8/§17/§12) | main `8afc594` | Repair 不变量、验证底线、PR 底线 | normative | 最高优先级之一 |
| DI-002 | Standard | lifecycle | main `8afc594` | §9.1 拓扑、§12.2 PR 契约、传输点只推分支不开 PR(站位裁定) | normative | — |
| DI-003 | Charter | P&V 责任书 | main `8afc594` | Packet 必答、冻结纪律 | normative | — |
| DI-004 | Issue(Assignment) | PKT-IP-0006 Coordinator Assignment | Ledger v13 @18:08Z | 覆盖/不覆盖、§9 a-j、三项强制 Checklist | normative | — |
| DI-005 | Issue | #58 正文 | 修订 `2026-09-01T14:36:22Z` | FR-02 RVR 子集、FR-03 verified-patch、契约不变量节、NFR-01/02 | normative | V5 节优先 |
| DI-006 | Issue(Ledger) | #58 Delivery Ledger v13 | `2026-09-02T18:08Z` | 定序终审、强制 Checklist 登记 | normative(current) | — |
| DI-007 | Decision | DR-PMV-0001-01 / DR-IP-0003-TESTFIX-01 / DR-IP-0004-IMPL-01 / DR-IP-0005-IMPL-01(issuecomment-5505168221 / 5506328396 / 5510460665 / 5513783045) | 2026-09-02 | 恢复/重冻结先例;实例化镜像预检裁定 | normative | — |
| DI-008 | Upstream IP | IP-0001..0005 Packets | #97/#99/#103/#105/#108 及各 merge | codec/Envelope/29 codes;VepReference 同构先例;本地校验器先例(profile);producer/六态先例(vep) | normative | — |
| DI-009 | Architecture | V5 规划文档 | 本地工作树副本(#58 指定 Source of truth) | §4.4(Verified Patch 双 preservation)、§5.2(RVR 最低内容:每候选 Gate 结果/行为差分/最终 patch/失败证据)、§8.1-8.2(候选约束与 Gate 序列——runtime 归 #77/#94)、行 368-370 | normative(经 #58 V5 覆盖层转正) | 与 #58 正文冲突以 #58 为准 |
| DI-010 | Issue | #76 正文(V4-I18) | `2026-09-01T07:20:46Z` | 候选语义:patch digest 去重、changed files/strategy/provenance、生成失败只淘汰自身、0 候选不改 VEP 结论、"生成者自证"风险(P-02) | background-only | 不从 #76 扩大实现范围 |
| DI-011 | Issue | #61 / #91 正文 | 2026-09-01 | 上游 VEP/工作流衔接(background) | background-only | — |
| DI-012 | Code | `lima/contracts/{common,codec,errors,evidence,profile,aep,vep}.py` | main `8afc594` | 当前真实 API、vep 表面、validator 风格 | current-behavior | 代码事实让位于 Packet 目标行为 |
| DI-013 | Test | `tests/contracts/` 全部 | main `8afc594` | 测试风格、211/556 基线 | current-behavior | — |
| DI-014 | Evidence | IP-0005 POST-MERGE、Ledger v13 双重验证 | 2026-09-02 | 基线数字、冻结面(18/16/15/12/12/29、四 golden) | evidence | — |

### Explicitly Rejected Inputs

| 材料 | 拒绝原因 |
|---|---|
| #76 的候选生成/workspace/scope policy/LLM parser/CandidateManifest 设计 | #76 实现职责;RVR 只验证不生成 |
| #77/#94 的 Gate 执行器与 V5 §8.2 的 11 步序列作为 mandatory Gate 集合 | runtime 归 #77/#94;契约层只固化双 preservation 结论(标准 §17/V5 §4.4 的规范表述);序列证据经逻辑引用进入 |
| 整体 report verdict / "vulnerability fixed" 字段 | 可从候选派生;且会引入表达漏洞状态的第二真值源,违反"无候选/全失败 ≠ 漏洞不存在"(#76 FR-06) |
| Gate 结果复用 EvidenceRecord | subject 词表无 candidate 主体,且禁改 evidence.py(§1.1-3 实证) |
| `source_vep_verdict` 镜像断言字段 | 引用不可解析 payload,镜像字段制造虚假保证;源 VEP 须 verified 属消费侧/Registry(先例一致) |
| RVR 层执行 scope allowlist(禁 tests/PoC/lock 路径) | allowlist 来自 VEP affected paths(不可解析);scope 校验属 #76 生成侧;RVR 只记录 changed_files |
| float confidence/severity、boolean is_fixed/vulnerability_resolved 类旁路 | 违反 NFR-01 与无 float 契约;候选 verdict 词表是唯一裁决机制 |
| 根工作树其余未跟踪规划文档 | 用户资产,未获引用 |

---

## 3. Iteration Hypothesis 与 Measurement

### 3.1 Hypothesis

如果 Repair 验证的输出被冻结为一个逐候选 × 逐 Gate 的确定性契约——每个候选恰好携带两个 mandatory preservation Gate 的结果、verified_patch 只在全部 pass 时合法、gate 执行者必须异于候选生成者、patch/差分/日志全部 digest 钉死——那么"生成者自证""跳过一个 Gate 凑绿""全失败被读成漏洞已修""单候选失败连坐"这类修复阶段真值事故在契约层就没有合法表达。

### 3.2 Measurement

- 固定 golden RVR(2 候选:verified_patch + rejected)生成固定 canonical bytes(1709 bytes)与 SHA-256(`a9a35d35…3cb2cac`);
- verdict 矩阵全部非法组合、mandatory Gate 缺失/重复、producer==generator、patch digest 跨候选重复、changed_files 非法路径/未排序/超限、悬空 VEP/patch/gate-evidence 引用、digest 错配、public/ephemeral 全部 fail closed;
- 空候选与全 rejected 报告合法且 payload 递归无任何可表达漏洞状态的字段;
- 新模块导入不加载 DB/网络/Docker/LLM/service/legacy models/evidence/aep/vep/profile;
- 既有 556 个测试无新增失败。

---

## 4. Goal

实现一个 stdlib-only、无副作用、确定性、可版本演化的 `lima.contracts.rvr` 叶子模块,包含:

1. 枚举:`GateKind`(functional_preservation|security_preservation)、`GateOutcome`(pass|failed|inconclusive|blocked|tool_error|policy_denied)、`CandidateVerdict`(verified_patch|rejected|inconclusive);
2. `VepReference`(FR-02 三元组)、`GateResult`(gate+outcome+producer+evidence refs+detail)、`CandidateVerification`(candidate_id+patch ref+strategy+changed_files+generator+gates+verdict);
3. `RepairVerificationReport`(source_vep + candidates),构造与 decode 时完成 §14 全部跨字段校验;
4. RVR payload 与 IP-0001 `ArtifactEnvelope` 的 encode/decode binding;
5. golden fixture(2 候选混合结果)、负向边界测试、import isolation 与 legacy regression。

---

## 5. Non-goals

本次明确不做(全部见 §1.2 与 Rejected Inputs,不重复展开):候选生成/scope/manifest、Gate 执行器、沙箱、修复发布、workflow 族 schema、JSON Schema/ADR、legacy 适配、生产接线、LLM/网络/IO、confidence/severity/漏洞状态字段、修改七个既有契约模块或任何既有测试、IP-0007。

---

## 6. 工作树与分支前置条件

Coding Agent 必须:完整阅读稳定标准、lifecycle、Implementation Agent 责任书、本 Packet、`LIMA_Coding_Agent_IP-0006_正式开发任务交接.md`、`CONTRIBUTING.md`;确认两份 IP-0006 文档均已合并到 `origin/main`;依 lifecycle §9.1 从 Frozen Test Commit(阶段二交付物指定 SHA)派生 `codex/ip-0006-rvr-foundation` 独立干净 worktree(禁用共享根工作树);确认 `lima/contracts/rvr.py` 与 3 个测试文件、1 个 fixture 尚不存在;输出 Scope Confirmation 后再运行 baseline;不一致时停止提交 Decision Request。根工作树未跟踪文件属用户资产,不得触碰。

---

## 7. 文件边界

### 7.1 Files to Add(恰好 5 个)

```text
lima/contracts/rvr.py
tests/contracts/test_rvr.py
tests/contracts/test_rvr_envelope.py
tests/contracts/test_rvr_import_isolation.py
tests/contracts/fixtures/repair_verification_report_v4_golden.json
```

### 7.2 Files Allowed to Modify

```text
none
```

### 7.3 Files Forbidden

除上述 5 个新增文件外全部禁止修改,特别包括:`lima/contracts/{__init__,errors,codec,common,evidence,profile,aep,vep}.py`;IP-0001..0005 的任何测试或 fixture;legacy/生产层;frontend/、requirements*.txt、pyproject.toml、.github/、PROGRESS.md;任意范围外文档。

### 7.4 Ownership 与冲突边界

`rvr.py` 唯一 Owner;后续 IP 不得在本 Packet 合并前创建同名 symbol(12 个);新公共 symbol 不从 `lima.contracts` 顶层重导出;依赖方向固定 `rvr.py → {codec,common,errors}`,其余 lima 模块不得 import rvr。

---

## 8. Allowed / Forbidden Dependencies

`rvr.py` 只允许导入:

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

测试只允许额外使用 stdlib:`hashlib`、`pathlib`、`subprocess`、`sys`、`unittest`。Forbidden:任何第三方包;`lima.contracts.{evidence,aep,vep,profile}` 与 `lima.models` 及生产层;HTTP/socket/DB/Docker/subprocess(产品)/文件系统(产品);UUID/时间/随机/环境变量;绝对路径。

---

## 9. 冻结的公共 Symbols

`lima/contracts/rvr.py` 的 `__all__` 必须严格等于以下集合,不多不少(**12** 项;本清单已逐项点数,与声明一致——强制 Checklist 第 3 条):

```python
__all__ = [
    "REPAIR_VERIFICATION_REPORT_SCHEMA_NAME",
    "GateKind",
    "GateOutcome",
    "CandidateVerdict",
    "VepReference",
    "GateResult",
    "CandidateVerification",
    "RepairVerificationReport",
    "decode_rvr_payload",
    "encode_rvr_payload",
    "decode_rvr_envelope",
    "encode_rvr_envelope",
]
```

模块常量:

```python
REPAIR_VERIFICATION_REPORT_SCHEMA_NAME = "lima.repair-verification-report"
```

---

## 10. 冻结枚举

所有枚举使用 `class X(str, Enum)`(允许 `# noqa: UP042`),wire value 严格固定:

```python
class GateKind(str, Enum):
    FUNCTIONAL_PRESERVATION = "functional_preservation"
    SECURITY_PRESERVATION = "security_preservation"

class GateOutcome(str, Enum):
    PASS = "pass"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"
    TOOL_ERROR = "tool_error"
    POLICY_DENIED = "policy_denied"

class CandidateVerdict(str, Enum):
    VERIFIED_PATCH = "verified_patch"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
```

语义冻结:

- `GateKind` 是 mandatory 集合,每个候选的 `gates` 必须恰好包含两个成员各一次(§14.2);
- `GateOutcome` 六态对齐 VEP `ReproductionOutcome` 先例;`blocked`/`tool_error`/`policy_denied` 是基础设施状态,永不折叠为安全结论(NFR-01);词表无 safe/clear/not_vulnerable;
- `CandidateVerdict`:`verified_patch` 是 FR-03/V5-FR-04 的 verified-patch 终态;`rejected` = 确定淘汰(≥1 gate failed);`inconclusive` = 无 failed 但存在 blocked/tool_error/policy_denied/inconclusive(验证未完成,可重试语义属 #77)。

---

## 11. Exact Constructors and Defaults

全部领域对象 `@dataclass(frozen=True, slots=True)`,defensive-copy;required 字段在前:

### 11.1 `VepReference`

```python
VepReference(
    artifact_id: str,
    content_digest: str,
    schema_version: SchemaVersion,
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

### 11.2 `GateResult`

```python
GateResult(
    gate: GateKind,
    outcome: GateOutcome,
    producer: str,
    evidence_artifact_ids: tuple[str, ...],
    detail: str,
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

### 11.3 `CandidateVerification`

```python
CandidateVerification(
    candidate_id: str,
    patch: PatchReference,
    strategy: str,
    changed_files: tuple[str, ...],
    generator: str,
    gates: tuple[GateResult, ...],
    verdict: CandidateVerdict,
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

其中 `PatchReference` 为模块内部值类型(不导出,不占 `__all__`):

```python
@dataclass(frozen=True, slots=True)
class PatchReference:
    patch_artifact_id: str
    content_digest: str
    extensions: dict[str, JSONValue] = field(default_factory=dict)
```

### 11.4 `RepairVerificationReport`

```python
RepairVerificationReport(
    schema_version: SchemaVersion,
    source_vep: VepReference,
    candidates: tuple[CandidateVerification, ...] = (),
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

`schema_version` 是 Envelope context,不进入 payload wire。四个导出 dataclass 均提供 `from_dict(value, *, schema_version) -> Self` 与 `to_dict()`(Python 3.11/3.12 兼容注解);`RepairVerificationReport.from_dict` 执行 §14 全部跨字段校验;`decode_rvr_payload` 只是稳定公共入口。

---

## 12. Exact Wire Shapes

### 12.1 Top-level payload

4.0 的 required fields 恰好为以下 **2** 个(全部必填;`candidates` 可为空):

```json
{
  "source_vep": {"artifact_id": "vep-0001", "content_digest": "<64hex>", "schema_version": "4.0"},
  "candidates": []
}
```

极简性依据:V5 §5.2 对 RVR 的全部内容要求(每候选 Gate 结果、行为差分、最终 patch、失败证据)均为候选级;无整体 verdict 字段是 §1.2-8 的设计决策。4.0 不允许其他字段。

### 12.2 `VepReference` / `PatchReference`

```json
{"artifact_id": "vep-0001", "content_digest": "cd76622b…", "schema_version": "4.0"}
{"patch_artifact_id": "patch-0001", "content_digest": "1111…"}
```

### 12.3 `GateResult`

```json
{
  "gate": "functional_preservation",
  "outcome": "pass",
  "producer": "lima-repair-verifier-2",
  "evidence_artifact_ids": ["diff-0001", "test-run-0001"],
  "detail": "Repository-native tests and the before/after behavioral differential passed."
}
```

### 12.4 `CandidateVerification`

```json
{
  "candidate_id": "candidate-0001",
  "patch": {"patch_artifact_id": "patch-0001", "content_digest": "<64hex>"},
  "strategy": "Deterministic shell-escape rewrite with generator run 7 provenance.",
  "changed_files": ["src/example.py"],
  "generator": "lima-repair-generator",
  "gates": [],
  "verdict": "verified_patch"
}
```

### 12.5 Extensions

4.0:任何层级(顶层、source_vep、patch、gate、candidate)unknown field 以 `UNKNOWN_FIELD` 拒绝;未来 4.x 经对应对象 `extensions` 无损 round-trip;required 缺失与 unknown enum 即使未来 minor 也拒绝。

---

## 13. Scalar Validation

- `candidate_id`/`generator`/`producer`/`artifact_id`/`patch_artifact_id`/`evidence_artifact_ids[]`:IP-0002 identifier 规则 `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`;
- `content_digest`(两处):`[0-9a-f]{64}`;
- `source_vep.schema_version`:IP-0001 `SchemaVersion.parse` 规则;
- `strategy`:bounded text 1..512;
- `detail`:bounded text 1..4096(规则同 IP-0002 §12.5:NFC、非空、无 Cc、无前导/尾随空白);
- `changed_files[]`:repo-relative path,规则与 IP-0002 `SourceLocation.path` 逐条相同(NFC、1..1024 bytes、`/` 分隔、禁首 `/`/drive/反斜杠/空段/`.`/`..`/控制字符/**禁尾随 `/`**);
- enum 字段:非 str `INVALID_FIELD_TYPE`,未知值 `UNKNOWN_ENUM_VALUE`;error message 不回显原值。

---

## 14. Array Limits,Canonical Ordering 与 Cross-field Invariants

### 14.1 数组上限与排序

| Array | 上限 | 允许空 | 排序规则 |
|---|---:|---:|---|
| `candidates` | 64 | 是 | `candidate_id` ASCII 升序、唯一 |
| 每候选 `gates` | 2(恰两成员) | 否 | `gate` wire value 升序(即 functional 在前)|
| 每候选 `changed_files` | 1024 | 是 | ASCII 升序、唯一 |
| 每 gate `evidence_artifact_ids` | 32 | 否(≥1) | ASCII 升序、唯一 |

### 14.2 Mandatory Gate 与 verdict 矩阵(核心不变量)

对每个 candidate:

1. `gates` 必须恰好包含 `functional_preservation` 与 `security_preservation` 各一次;缺失/重复/多余成员 → `INVALID_FIELD_VALUE $.candidates[i].gates`;
2. **verdict 映射**(设 `all_pass` = 全部 gate outcome==pass;`any_failed` = 存在 failed):

```text
all_pass(且无 failed)  ⇒  verdict == verified_patch(唯一合法值)
any_failed             ⇒  verdict == rejected(唯一合法值)
其余(无 failed 且非全 pass)⇒ verdict == inconclusive(唯一合法值)
```

违反 → `INVALID_FIELD_VALUE $.candidates[i].verdict`。"任一 mandatory Gate skipped/failed/blocked ⇒ 不得 verified-patch"由此机器化(缺失即畸形、非 pass 即排除);
3. **生成者不自证**:每个 gate 的 `producer != generator`,违反 → `INVALID_FIELD_VALUE $.candidates[i].gates[j].producer`;
4. **patch digest 跨候选唯一**(同 patch digest 应在生成期去重,#76 FR-02),违反 → `INVALID_FIELD_VALUE $.candidates[i].patch.content_digest`。

### 14.3 Provenance(Envelope binding 阶段)

- `source_vep.artifact_id` ∈ lineage 且对应条目 `schema_name == "lima.vulnerability-evidence-package"`、`content_digest`、`schema_version` 与三元组一致(类型化双向核对);
- 每候选 `patch.patch_artifact_id` ∈ lineage 且 digest 与 lineage 条目一致;
- 每 gate `evidence_artifact_ids[]` ∈ lineage(存在性;gate log/diff/test-run 的 schema 未冻结,不做类型化断言);
- lineage 允许额外条目;tenant/snapshot/self/duplicate/conflict 由 IP-0001 拒绝;
- 明确豁免:源 VEP verdict==verified、scope allowlist、workspace 隔离的运行时证明——消费侧/#76/#77/Registry。

---

## 15. Envelope Binding Contract

### 15.1 Function signatures

```python
def decode_rvr_payload(value: Mapping[str, JSONValue], *, schema_version: SchemaVersion) -> RepairVerificationReport: ...
def encode_rvr_payload(report: RepairVerificationReport) -> dict[str, JSONValue]: ...
def decode_rvr_envelope(data: bytes, *, limits: ContractLimits = DEFAULT_LIMITS) -> tuple[ArtifactEnvelope, RepairVerificationReport]: ...
def encode_rvr_envelope(envelope: ArtifactEnvelope, report: RepairVerificationReport, *, limits: ContractLimits = DEFAULT_LIMITS) -> bytes: ...
```

### 15.2 Binding rules

`decode_rvr_envelope` 必须:调用 `decode_envelope`;`schema_name == REPAIR_VERIFICATION_REPORT_SCHEMA_NAME`;inline payload only;以 envelope `schema_version` decode report;§14.3 provenance(VEP 类型化三元组:缺失/错 schema → `INVALID_FIELD_VALUE $.payload.source_vep.artifact_id`,digest 不符 → `DIGEST_MISMATCH $.payload.source_vep.content_digest`;patch:缺失 → `INVALID_FIELD_VALUE $.payload.candidates[i].patch.patch_artifact_id`,digest 不符 → `DIGEST_MISMATCH`;gate 证据:缺失 → `INVALID_FIELD_VALUE $.payload.candidates[i].gates[j].evidence_artifact_ids[k]`);允许额外 lineage;classification != public;retention != ephemeral;返回 `(envelope, report)` 不修改输入。

`encode_rvr_envelope` 执行相同 binding 并额外:`envelope.schema_version == report.schema_version`;`envelope.payload == encode_rvr_payload(report)`;`compute_content_digest` 与 `envelope.content_digest` 经 `hmac.compare_digest` 相等;最终 `encode_envelope`;不自动创建/修补 Envelope。

RVR 携带补丁引用、变更面与 Gate 证据,属安全敏感内容:classification 禁 public、retention 禁 ephemeral。

---

## 16. Stable Error Mapping and Precedence

复用现有 **29** 个 code;优先级(同 IP-0004/0005 模式):

1. codec byte/UTF-8/JSON/resource;
2. top-level container/required/current unknown/schema version;
3. enum 与 scalar type;
4. scalar value/range、数组 limit/order/duplicate;
5. 内嵌对象逐层校验(引用对象/gate/candidate 的字段错误按其自身路径);
6. 跨字段:mandatory Gate 完整性 → verdict 矩阵 → producer≠generator → patch digest 唯一;
7. lineage provenance(类型化 VEP、patch、gate 证据);
8. Envelope schema/payload/digest/classification/retention binding。

`field_path` 示例:

```text
$.candidates[0].verdict
$.candidates[1].gates[0].producer
$.candidates[1].patch.content_digest
$.candidates[2].changed_files[3]
$.payload.source_vep.artifact_id
$.payload.candidates[0].gates[1].evidence_artifact_ids[0]
```

---

## 17. Golden Fixture

文件:

```text
tests/contracts/fixtures/repair_verification_report_v4_golden.json
```

要求:UTF-8;单行 canonical JSON;无 BOM;无 trailing newline;**exactly 1709 bytes**;payload SHA-256:

```text
a9a35d358308a2957b9182d2ca5e503903d8c7282c6c43bb09d1680313cb2cac
```

该 bytes 与 digest 已由 IP-0001 codec 在 main `8afc594` 预计算冻结;`source_vep.content_digest` = VEP golden 真实 digest(跨切片证据链连续);内容 = 2 候选混合(candidate-0001 双 Gate pass → verified_patch;candidate-0002 security Gate failed → rejected;gates 按 wire value 升序;producer 均 ≠ generator;patch digest 唯一)。权威内容如下;实现者不得更改字段、值、顺序或摘要:

```json
{"candidates":[{"candidate_id":"candidate-0001","changed_files":["src/example.py"],"gates":[{"detail":"Repository-native tests and the before/after behavioral differential passed.","evidence_artifact_ids":["diff-0001","test-run-0001"],"gate":"functional_preservation","outcome":"pass","producer":"lima-repair-verifier-2"},{"detail":"Security oracle confirms the PoC no longer triggers and no new high-risk signals appeared.","evidence_artifact_ids":["sec-oracle-0001"],"gate":"security_preservation","outcome":"pass","producer":"lima-repair-verifier-1"}],"generator":"lima-repair-generator","patch":{"content_digest":"1111111111111111111111111111111111111111111111111111111111111111","patch_artifact_id":"patch-0001"},"strategy":"Deterministic shell-escape rewrite with generator run 7 provenance.","verdict":"verified_patch"},{"candidate_id":"candidate-0002","changed_files":["src/cli.py","src/example.py"],"gates":[{"detail":"Repository-native tests passed on the patched tree.","evidence_artifact_ids":["test-run-0002"],"gate":"functional_preservation","outcome":"pass","producer":"lima-repair-verifier-2"},{"detail":"The original PoC still triggers after applying the patch.","evidence_artifact_ids":["sec-oracle-0002"],"gate":"security_preservation","outcome":"failed","producer":"lima-repair-verifier-3"}],"generator":"lima-repair-generator","patch":{"content_digest":"2222222222222222222222222222222222222222222222222222222222222222","patch_artifact_id":"patch-0002"},"strategy":"LLM-proposed input validation at the CLI boundary.","verdict":"rejected"}],"source_vep":{"artifact_id":"vep-0001","content_digest":"cd76622b48d11c0300e63d7489701479c75dc2f4b06cc6c4e88af1f453061d01","schema_version":"4.0"}}
```

### 17.1 Frozen envelope vector

```text
schema_name = lima.repair-verification-report
schema_version = 4.0
artifact_id = rvr-0001
tenant_id = tenant-1 / task_id = task-1 / workflow_id = workflow-1 / stage_attempt_id = repair-1
repository_snapshot_digest = "3" * 64
producer = lima-repair-verifier
created_at = 2026-09-02T00:00:00Z
policy_digest = "5" * 64 / toolchain_digest = "6" * 64
content_digest = a9a35d358308a2957b9182d2ca5e503903d8c7282c6c43bb09d1680313cb2cac
classification = sensitive / retention_class = audit
lineage(8 条,均为 illustrative 逻辑 schema 名;仅 VEP 条目类型化):
  lima.vulnerability-evidence-package / vep-0001 / cd76622b…
  lima.candidate-patch / patch-0001 / "1" * 64
  lima.candidate-patch / patch-0002 / "2" * 64
  lima.gate-log / sec-oracle-0001 / "3" * 64
  lima.gate-log / sec-oracle-0002 / "4" * 64
  lima.gate-log / diff-0001 / "7" * 64
  lima.gate-log / test-run-0001 / "8" * 64
  lima.gate-log / test-run-0002 / "9" * 64
supersedes = null / coverage_gaps = []
```

---

## 18. Required Tests

测试使用 `unittest`,方法名冻结如下;可增加 helper 与更细测试,不得减少、重命名或合并。

### 18.1 `tests/contracts/test_rvr.py`(26)

```text
RvrEnumTests
  test_wire_values_are_exact

VepReferenceTests
  test_round_trip_has_exact_wire_shape
  test_rejects_missing_invalid_and_mismatched_fields

GateResultTests
  test_round_trip_has_exact_wire_shape
  test_rejects_unknown_gate_outcome_and_missing_fields
  test_rejects_empty_evidence_provenance
  test_rejects_oversize_detail

CandidateVerificationTests
  test_round_trip_has_exact_wire_shape
  test_rejects_invalid_changed_files_paths
  test_mandatory_gates_present_exactly_once
  test_verdict_matrix_all_pass_implies_verified_patch_only
  test_any_failed_gate_implies_rejected_only
  test_blocked_tool_error_policy_denied_and_inconclusive_imply_inconclusive_only
  test_generator_may_not_verify_own_candidate
  test_strategy_and_generator_validation

RepairVerificationReportTests
  test_minimal_empty_report_round_trip_is_valid
  test_golden_report_round_trip_and_digest
  test_rejects_wrong_container_and_missing_required_fields
  test_rejects_unknown_enum_and_wrong_field_type
  test_rejects_unsorted_duplicate_and_oversize_candidates
  test_patch_digests_unique_across_candidates
  test_candidate_failure_does_not_modify_vulnerability_status
  test_future_minor_round_trips_unknown_fields_at_every_level
  test_current_minor_rejects_unknown_fields_at_every_level
  test_defensive_copy_prevents_post_construction_mutation
  test_payload_has_no_confidence_severity_or_verdict_bypass_fields
```

`test_payload_has_no_confidence_severity_or_verdict_bypass_fields` 递归断言 golden 与 minimal payload 任意层级不出现键:`confidence`、`severity`、`risk_score`、`is_fixed`、`vulnerability_resolved`、`safe`、`clear`。

### 18.2 `tests/contracts/test_rvr_envelope.py`(11)

```text
RvrEnvelopeTests
  test_frozen_envelope_encode_decode_is_byte_stable
  test_rejects_wrong_schema_name_and_version_mismatch
  test_rejects_blob_backed_rvr
  test_rejects_payload_report_and_content_digest_mismatch
  test_rejects_missing_vep_lineage_reference
  test_rejects_vep_lineage_entry_with_wrong_schema_name_or_digest
  test_rejects_missing_patch_and_gate_evidence_lineage_references
  test_allows_additional_valid_lineage
  test_inherits_cross_tenant_cross_snapshot_and_self_reference_rejection
  test_rejects_public_classification_and_ephemeral_retention
  test_tampered_payload_fails_before_domain_promotion
```

### 18.3 `tests/contracts/test_rvr_import_isolation.py`(4)

```text
RvrImportIsolationTests
  test_module_public_api_matches_frozen_symbol_set
  test_clean_process_import_has_no_db_network_docker_llm_service_or_legacy_models
  test_module_only_uses_allowed_imports
  test_import_does_not_change_lima_contracts_top_level_public_api
```

`test_clean_process_import…` 必须断言:干净子进程导入 `lima.contracts.rvr` 后,`evidence`/`aep`/`vep`/`profile` 与其余 forbidden roots **均不在** `sys.modules`(本 IP 是首个不 import evidence 的 domain 切片——方向断言与 IP-0004/0005 相反)。

### 18.4 Minimum count

IP-0006 必须新增至少 **41** 个独立 test methods(26+11+4)。

---

## 19. Acceptance Criteria and Traceability

| AC | Required behavior | Evidence(test) | 覆盖的 Issue requirement |
|---|---|---|---|
| RVR-AC-01 | 12 个 module public symbols、3 个 enum wire vocabulary、4 个导出 constructors(+内部 PatchReference)冻结 | enum/object/import tests | FR-02(RVR 版本化定义) |
| RVR-AC-02 | 三元组/标识符/digest/strategy/detail/changed_files scalar 与上限 fail closed | Vep/Gate/Candidate negative tests | NFR-02 |
| RVR-AC-03 | golden RVR 1709 bytes、固定 digest、byte-stable;source_vep.digest = VEP golden 真实值 | golden test | FR-05、AC-01 方法论 |
| RVR-AC-04 | mandatory Gate 恰两成员各一次;verdict 矩阵三分支唯一合法值强制 | 矩阵 tests | V5-FR-03 后半句、FR-03 |
| RVR-AC-05 | producer≠generator(生成者不自证);patch digest 跨候选唯一 | 专 tests | §17 Repair 不变量、#76 P-02 |
| RVR-AC-06 | 类型化 VEP 三元组 lineage 核对;patch/gate 证据 provenance;classification/retention | envelope tests | FR-02、NFR-01 |
| RVR-AC-07 | 空候选/全 rejected 合法且不编码漏洞状态;无 confidence/severity/is_fixed/vulnerability_resolved/safe/clear/risk_score | 空报文 + forbidden-key tests | NFR-01、#76 FR-06 |
| RVR-AC-08 | 4.0 unknown field 拒绝(每层级);未来 4.x 无损 round-trip;unknown enum 永远拒绝 | compatibility tests | FR-06 |
| RVR-AC-09 | stdlib leaf;rvr→{codec,common,errors};不加载 evidence/aep/vep/profile;冻结面不变 | import isolation + git diff | AC-04(T-04) |
| RVR-AC-10 | 5 added / 0 modified / 0 deps / 全量回归无新增失败 | file boundary + full regression | AC-04 |

---

## 20. 强制实现顺序(含一致性预检,Assignment 强制 Checklist 第 1 条)

阶段二由 P&V 执行 **1-6**,Implementation Agent 从第 7 步开始:

1. **冻结前一致性预检**:脚本独立实现 §14 全部跨字段规则,校验 golden 实文件 + 每个计划 arrange;**构造器用例的 arrange 必须做"实例化镜像"验证**(构造器参数须为领域对象实例而非 wire dict——DR-IP-0005-IMPL-01 裁定的根因封堵);预检脚本与结果记入 RED Evidence Record;
2. 编写 3 个测试文件 + fixture(逐字节复制 §17 权威内容);
3. 测试自身质量门禁(compileall/ruff;I001 须 stub 复证);
4. 证明有效 RED(预期失败全部归因 `lima.contracts.rvr` 不存在);
5. 创建 Frozen Test Commit + digest + 数量,**只推送分支,严禁开 PR**(强制 Checklist 第 2 条);
6. Coordinator 出具 Implementation Assignment;
7. Implementation Agent:枚举/本地校验器/VepReference/PatchReference/GateResult/CandidateVerification → `RepairVerificationReport`(§14 全部校验)→ 逐字验证 golden → 4 个 binding functions → isolation/forbidden-key → Slice Gate → Compatibility Gate → File Boundary Gate → Completion Summary。

---

## 21. Done Commands

### 21.1 Baseline(编码前)

```powershell
python -m compileall -q lima scripts tests
python -m unittest discover -s tests/contracts -v
python -m unittest -v tests.test_repository_source tests.test_task_failure
```

预期基线(@ `8afc594` + 本 Packet 合并):contracts **211** PASS;定向兼容 **29** PASS。

### 21.2 Slice Gate

```powershell
python -m compileall -q lima/contracts tests/contracts
python -m unittest discover -s tests/contracts -v
python -m ruff check lima/contracts/rvr.py tests/contracts/test_rvr.py tests/contracts/test_rvr_envelope.py tests/contracts/test_rvr_import_isolation.py
python -m ruff check lima/contracts tests/contracts
python -m bandit -q -r lima/contracts/rvr.py
git diff --check
```

### 21.3 Compatibility Gate

```powershell
python -m unittest -v tests.test_repository_source tests.test_task_failure
python -m unittest discover -s tests -v
```

实现后预期 contracts **252**(211+41)、全量 **597**(556+41)/ 0 failed / 1 既有 skip。任何新增 failure/skip 必须解释;不能通过修改 legacy 测试解决。Python 3.11/3.12 由 CI matrix 验证。

### 21.4 File Boundary Gate

```powershell
git diff --name-only --diff-filter=ACMRTUXB <frozen-test-commit>...HEAD
git diff --check <frozen-test-commit>...HEAD
```

输出必须恰好为 7.1 的 5 个新增文件(相对 Frozen Test Commit,产品侧仅 `lima/contracts/rvr.py`)。

### 21.5 Optional release-level gate

维护者或 CI 可运行 `powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 test`;普通 Agent 不因 Docker/宿主环境不可用而改变产品代码。

---

## 22. Security and Compatibility Invariants

- verified_patch 仅在全部 mandatory Gate pass 时合法;任何非 pass outcome(含 blocked/tool_error/policy_denied/inconclusive)排除;
- producer≠generator 每候选每 gate 强制;
- patch digest 跨候选唯一;changed_files 为 repo-relative 受限路径;patch/diff/日志不内联;
- 空候选与全 rejected 不改变 VEP 漏洞结论(结构性:无漏洞状态字段);
- classification 禁 public、retention 禁 ephemeral;ID/digest/时间全部由调用方提供;
- 不新增任何权限;不改变 legacy 行为与五个上游 IP 冻结面(18/16/15/12/12/29、四 golden);
- 不通过 future-minor extension 绕过 required、enum、矩阵或 provenance。

---

## 23. Stop Conditions / Decision Request

1. 两份 IP-0006 文档尚未合并,或基线不再是 `8afc594` 后代、冻结面漂移;
2. 最新 main 已出现同名 `rvr.py` 或冲突 Owner;
3. 需要修改任一 forbidden 文件或扩大 allowlist;
4. 需要新增第三方依赖、I/O、网络、数据库、Docker、subprocess 或环境权限;
5. §10-§16 任一契约存在两个与上游决策同等自洽的答案;
6. frozen fixture 的 1709 bytes / digest 无法由 IP-0001 codec 重现,或 source_vep digest 与 VEP golden 不一致;
7. 需要引入 float、confidence/severity、漏洞状态字段、自动 ID 或放宽矩阵/自证禁令/provenance 才能继续;
8. 需要实现候选生成、Gate 执行器、沙箱或定义 CandidateManifest/其他 manifest schema 才能让测试通过;
9. baseline/全量回归失败且无法归因;required tests 无法证明某个 AC;
10. 发现工作实际进入 #76/#77 runtime、workflow schema 或生产接线。

Decision Request 格式同 Packet 惯例。

---

## 24. Git, Commit and PR Contract

推荐 commit / PR 标题:`feat: add deterministic repair verification report contracts`。PR 正文:只写 `Related to #58`;禁 auto-close 关键字;AC → Test → Result;真实命令、退出码、统计;5 added / 0 modified / 0 dependencies;no generator/no executor/no manifest schema/top-level API unchanged;等待独立 Review 与 `merge-gate`。Implementation Agent 不合并 PR、不删分支/worktree、不改 Issue。

---

## 25. Completion Summary Template

```markdown
## IP-0006 Completion Summary

### Result
- Status: DONE | NOT DONE | BLOCKED
- Base commit / Frozen Test Commit / Final commit / Branch / Worktree:

### Scope
- Added files / Modified existing files: none / Dependencies added: none
- Public API: lima.contracts.rvr only (12 symbols)
- Contract deviations: none | <Decision Request>

### Acceptance evidence
| AC | Test/command | Result |
|---|---|---|
| RVR-AC-01 … RVR-AC-10 | | |

### Commands and actual results(命令/退出码/统计)
### Security and compatibility(矩阵/自证禁令/patch 唯一性/provenance/echo/隔离/py3.11-12/回归)
### Findings and decisions
### Handoff(PR 状态/唯一下一步/禁止动作)
```

---

## 26. Maintainer Review Checklist

- [ ] base 为 Frozen Test Commit 后代且含本 Packet;只新增 5 文件;rvr.py 是唯一产品文件;
- [ ] 冻结面不变:18/16/15/12/12/29、四 golden;七个既有契约模块零改动;
- [ ] module API 恰 12 symbols;依赖 rvr→{codec,common,errors};不加载 evidence/aep/vep/profile;
- [ ] 2 个 top-level required 字段、四对象 wire 无漂移;
- [ ] golden 1709B/`a9a35d35…`、source_vep.digest = VEP golden;
- [ ] mandatory Gate 恰两成员、verdict 矩阵三分支、producer≠generator、patch digest 唯一 negative tests 通过;
- [ ] 类型化 VEP / patch / gate 证据 provenance 与 classification/retention tests 通过;
- [ ] 空候选合法 + forbidden-key 通过;current/future-minor 每层级通过;
- [ ] 全量回归无新增失败(预期 597 = 556+41);全目录 ruff exit 0;
- [ ] File Boundary 恰 5 文件;Completion Summary 可复现;独立 Review 与 merge-gate 通过;
- [ ] PR 未关闭 #58;未启动 IP-0007、#76/#77 runtime 或生产接线。

---

## 27. Packet 完成定义

只有全部 10 个 AC、41 个 required tests、golden fixture、Envelope consumer test、import isolation、完整命令证据、独立 Review 和 `merge-gate` 全部满足,IP-0006 实现才能标记 DONE。

IP-0006 合并后,协调者必须在最新 `main` 上安排 post-merge verification,并让下一个消费 IP(IP-0007 候选:Workflow 族 schemas)对本模块做只读 consumer review(其 Packet 的 Design Input Manifest 入口 Gate)。当前 Agent 不自动继续下一个 IP。
