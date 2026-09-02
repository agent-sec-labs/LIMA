# LIMA Implementation Packet IP-0004:Audit Evidence Package(AEP)Foundation

> Packet ID:`IP-0004`
>
> 状态:`DESIGN-FROZEN / READY-FOR-CODE WHEN THIS PACKET IS MERGED TO MAIN`
>
> Source Issue:[#58](https://github.com/agent-sec-labs/LIMA/issues/58) 的第四个独立实现切片(第三个 domain 切片)
>
> 最低代码基线:Assignment 基线 `9078bb52494075a5c6d8e7aefb544e2433cb4195`(IP-0003 实现,PR #104);实现基线必须是包含本 Packet 与正式交接书的最新 `origin/main`
>
> 推荐分支:`codex/ip-0004-aep-foundation`(依 lifecycle §9.1 从 Frozen Test Commit 派生,实现阶段 Assignment 另行出具)
>
> Owner:唯一 Implementation Agent;不得与任何活动 IP 并行修改 `lima/contracts/` 或 `tests/contracts/`

## 需求映射(Header)

```text
Source Issue:#58
Issue specification revision:正文修订 2026-09-01T14:36:22Z(V4 基线 + V5 覆盖层,冲突以 V5 节为准);
  Delivery Ledger v5 @ 2026-09-02T08:25Z(本 Assignment 激活依据)
Covered requirements:FR-02 的 AEP 子集(Audit Evidence Package 版本化 schema;跨对象引用经
  ArtifactReference / Envelope lineage);支撑性覆盖 FR-05(AEP fixture 子集)、FR-06(本 schema 的
  current/future-minor 兼容)、NFR-01(fail-closed;不编码安全结论)、NFR-02(校验上限)
Not covered requirements:FR-02 其余子集(VEP、RVR、Task/ToolBundle/Dependency/Sandbox manifests);
  V5-FR-01 其余子集(Workflow/StageAttempt/Outcome/Plan/RunManifest/Summary/Failure schemas);
  V5-FR-03/04/05 与 #58 的 V5-AC/T;#68 的全部集成职责(AuditPipeline/run_fast/run_deep、seal API、
  progress、cache、worker/retry/cancel、legacy adapter、API analysis 字段);分类器/Planner/Fusion 算法;
  生产接线与前端
Delivery role:domain
Issue closure impact:PARTIAL(合并后不触发 #58 closure;#58 保持 open)
Upstream IP/PR/merge commits:
  IP-0001 Packet #97 `5cdf872` / 实现 #98 `d3e73d9` / 恢复 #102 `a0b3eea`(POST-MERGE PASS v2)
  IP-0002 Packet #99 `f92122b` / 实现 #100 `4fe1def`(IP-DONE)
  IP-0003 Packet #103 `437fe01` / Frozen v2 `573de77` / 实现 #104 `9078bb5`(IP-DONE)
Activation gate:lifecycle 入口 consumer review(见 §1,已完成,无 Contract Gap)
```

---

## 0. 执行决策

当前执行队列(Ledger v5,2026-09-02):

```text
DONE
IP-0001(+IP-0001-R1)、IP-0002、IP-0003(4/4 IP-DONE)

NOW(只允许 1 个)
IP-0004 Audit Evidence Package(AEP)Foundation(Design Frozen;文档合并后进入阶段二冻结测试)

NEXT(不得实现)
IP-0005 候选(VEP/RVR 或 workflow schema 分解,由 Coordinator 决定)

LATER
VEP / RVR / Task/ToolBundle/Dependency/Sandbox manifests /
Workflow/StageAttempt/Outcome/Plan/RunManifest/Summary/Failure schemas /
JSON Schema + 兼容矩阵 + ADR(Issue PR3)/ legacy adapter fixture(Issue PR4)/ closure IP
```

本 Packet 只建立可被 #64(Mining Planner)、#68(Audit 集成)、#70(UI)与 V5-N02/V5-N06 消费的确定性 `AuditEvidencePackage` Artifact 契约。它不实现 Audit pipeline、seal API、revision 存储、幂等提交、progress、cache、legacy adapter 或任何生产接线(全部属 #68 与未来 Registry IP)。

---

## 1. IP-0003 消费者评审结论(lifecycle 入口 Gate,只读)

### 1.1 已验证事实(@ main `9078bb5`,P&V 实证执行,2026-09-02)

- **ArtifactReference 可构造性**:`lima.contracts.profile` 生成的 Envelope 携带 AEP 引用所需的全部 identity 字段(`schema_name`/`schema_version`/`artifact_id`/`tenant_id`/`repository_snapshot_digest`/`content_digest`);由 profile golden envelope 实际构造 `ArtifactReference(schema_name="lima.repository-profile", artifact_id="profile-0001", content_digest="ad7d53a0…c4dccc")` 成功,且该引用可置于 AEP Envelope lineage 并通过 IP-0001 的 tenant/snapshot/self 校验;
- **AEP 视角语义面可读**:`RepositoryProfile.repository_kinds`(多 kind)、`component_path`(null=整仓/路径=组件)、`support_level`、`coverage_gaps` 均为只读可消费属性;monorepo 多 component profile 对应多个 AEP 的约束由 Envelope 同 snapshot 规则承载(V5 §3.2);
- **schema identity 常量可导入**:`REPOSITORY_PROFILE_SCHEMA_NAME = "lima.repository-profile"` 为 public,使 AEP binding 可以类型化校验 lineage 中的 profile 引用(§15.2 规则 5);
- 冻结面在 main 无漂移:contracts 130/130、全量 475/0 failed/1 既有 skip、ruff 全目录 exit 0、顶层 18 / evidence 16 / profile 15 / 29 error codes、golden evidence 3740B/`1b313f8c…`、profile 2152B/`ad7d53a0…`。

**结论:不存在阻塞 IP-0004 的 Contract Gap。** IP-0003 满足其 IP-DONE 的消费者评审入口条件。

### 1.2 本 Packet 的兼容决策(冻结)

延续 IP-0002 §1.2 六项与 IP-0003 §1.2 九项(适用部分),并针对 AEP 扩展:

1. 只新增 `lima/contracts/aep.py`,不修改 `lima/contracts/__init__.py`;公共 API 只从 `lima.contracts.aep` 导入;
2. **载荷构成冻结为"内嵌"**:`aep.py` import `lima.contracts.evidence` 的冻结类型(`EvidenceDomainBundle` 等),AEP payload 以 `"evidence_domain"` 键内嵌完整 Evidence Domain bundle wire shape。依赖方向固定为 `aep.py → {evidence, codec, common, errors}`,evidence 不得反向 import aep,`aep.py` 不得 import `lima.contracts.profile`(profile 仅经 lineage 引用;理由:AEP 是 post-Audit Artifact,必须自包含 Mining 规划所需证据图,而 Registry/blob 尚不存在,纯引用形态会让 #64/#70 无法仅靠 fixture 消费);
3. 复用现有 **29** 个 `ContractErrorCode`,不扩展 `errors.py`;错误优先级沿用 IP-0002 §16 模式(见 §16);
4. 复用 `ArtifactEnvelope` / `decode_envelope` / `encode_envelope`,不创建第二套 Envelope 或 codec;
5. 仅 inline payload;blob-backed AEP 留给未来 Artifact Registry IP(V5 §"Blob/Object Store:AEP/VEP/RVR…" 为远期形态,本切片不实现);
6. schema 版本仍为 `4.0`;未知 major fail closed;同 major 未来 minor optional 字段经各对象 `extensions` 无损 round-trip(含内嵌 `evidence_domain` 各层级,复用 evidence 模块自身规则);unknown enum / required 缺失永不降级;
7. 所有计量为非负整数(basis points / counts / ms),全 schema 无 float、无 confidence/severity;
8. path 类字段无(本 schema 不含代码路径;内嵌 bundle 的 path 规则由 evidence 模块保证);
9. schema name 固定 `lima.audit-evidence-package`;
10. **revision 单调性、乱序/重复提交幂等拒绝、append-only 存储与 latest-sealed pointer 均不在本 Contract 校验**——单 Envelope 无跨 Artifact 视图,依 IP-0001 把多跳环检测留给 Registry 的先例,这些属未来 Artifact Registry / #68(本 Contract 仅校验 `revision >= 1` 且为 exact int);Envelope `supersedes` 指向前版由 IP-0001 校验 identity 一致性,"指向 n-1 版"同样留给 Registry;
11. **sealed 表达冻结在 payload 字段** `package_status: "draft" | "sealed"`(Envelope 本身由 digest 保证字节不可变;sealed 是 Audit 领域语义——"该 revision 关闭,后续变更必须产生 revision+1 并 supersedes 本版";Mining 消费者必须要求 sealed,#68/#64 侧执行,本 Contract 不拒绝 draft)。

---

## 2. Design Input Manifest

| Input ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001 | Standard | `docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md` | main `9078bb5` | 安全不变量、allowlist 纪律、验证底线 | normative | 最高优先级之一 |
| DI-002 | Standard | `docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md` | main `9078bb5` | Packet Gate、两 PR 模型、§9.1 分支拓扑、§14 记录格式 | normative | — |
| DI-003 | Charter | `docs/LIMA_PACKET_AND_VERIFICATION_AGENT_RESPONSIBILITY_CHARTER.md` | main `9078bb5` | Packet 必答清单、Manifest 结构、冻结纪律 | normative | — |
| DI-004 | Issue(Assignment) | PKT-IP-0004 Coordinator Assignment(2026-09-02 会话) | 引用 Ledger v5 @08:25Z | 覆盖/不覆盖、§9 a-i 设计问题清单、入口 Gate、文件方向 | normative | 与 Ledger 冲突以最新一致口径为准 |
| DI-005 | Issue | #58 正文(V4 + V5 覆盖层) | 修订 `2026-09-01T14:36:22Z` | FR-02 AEP 子集;契约不变量节;NFR-01/02 | normative | V5 节优先 |
| DI-006 | Issue(Ledger) | #58 Delivery Ledger v5 | `2026-09-02T08:25:28Z` | 队列、上游 IP 状态、基线 `9078bb5`、基线歧义裁定(implementation 分支从 Frozen Test Commit 派生) | normative(current) | — |
| DI-007 | Decision | DECISION-DR-PMV-0001-01(#58 评论 `issuecomment-5505168221`) | 2026-09-02 | 恢复先例、29 错误码口径 | normative | — |
| DI-008 | Decision | DECISION-DR-IP-0003-TESTFIX-01(#58 评论 `issuecomment-5506328396`) | 2026-09-02 | 重冻结先例、v1/v2 Frozen Commit 链 | normative | — |
| DI-009 | Upstream IP | IP-0001 Packet | #97 `5cdf872` / `d3e73d9` / `a0b3eea` | codec/Envelope/29 codes/版本与资源规则;Registry 留白先例(多跳环) | normative | — |
| DI-010 | Upstream IP | IP-0002 Packet | #99 `f92122b` / `4fe1def` | §1.2 六决策、§15 binding 模式、§16 错误优先级、§17 golden 方法论;EvidenceDomainBundle 16 symbols 冻结面 | normative | — |
| DI-011 | Upstream IP | IP-0003 Packet | #103 `437fe01` / `573de77` / `9078bb5` | §1.2 九决策(比例 bp、无 evidence import 等,适用部分)、gap shape 先例、consumer review 入口条件 | normative | — |
| DI-012 | Architecture | V5 规划文档 §3.1/§3.2/§5.2/§6.3 及 AEP 相关行(441/1115/1323) | 本地工作树副本(#58 指定 Source of truth) | AEP 最低内容(Signal refs/Issue clusters/Hypotheses/coverage/budget/gaps)、sealed AEP 为 Mining 输入、blob 为远期 | normative(经 #58 V5 覆盖层转正) | 与 #58 正文冲突以 #58 为准 |
| DI-013 | Issue | #68 正文(V4 + V5 覆盖层) | `2026-09-01T07:08:30Z` | AEP 语义需求:initial/deep、sealed、revision append-only/幂等(留给 #68 的部分)、"只表达值得 Mining 验证的 Hypothesis"、typed gaps、coverage/budget 表达 | background-only | 不从 #68 扩大实现范围;其集成职责明确不覆盖 |
| DI-014 | Issue | #60 / #64 正文 | 2026-09-01 | 上游 profile 消费(已入 §1)与下游 planner 消费需求(background) | background-only | — |
| DI-015 | Code | `lima/contracts/{common,codec,errors,evidence,profile}.py` | main `9078bb5` | 当前真实 API、validator 风格、EvidenceDomainBundle.from_dict 复用面 | current-behavior | 代码事实让位于 Packet 目标行为 |
| DI-016 | Test | `tests/contracts/test_*.py` 与 fixtures | main `9078bb5` | 测试风格、130/475 基线、golden 复用(evidence 3740B) | current-behavior | — |
| DI-017 | Evidence | IP-0003_POST-MERGE.md、Ledger v5 双重验证记录 | 2026-09-02 | 基线数字(130/475/1 skip)、冻结面(18/16/15/29) | evidence | — |

### Explicitly Rejected Inputs

| 材料 | 拒绝原因 |
|---|---|
| #68 的 pipeline/seal API/progress/cache/worker/retry/cancel/legacy adapter/analysis 字段设计 | #68 集成职责,Assignment 明确不覆盖;本 IP 只交付其可依赖的确定性契约 |
| V5 规划 §4 Workflow Mode/状态机、§7-9 Mining/Repair 细节 | V5-FR-01 其余子集与未来 IP |
| VEP/RVR/manifest schema 任何字段草案 | 未映射子集;依赖未冻结上游 |
| "纯引用"(AEP 仅存 bundle 引用)的载荷方案 | 与 Assignment §9b 的单解要求冲突:Registry/blob 不存在时 #64/#70 无法仅靠 fixture 消费;已冻结为内嵌(§1.2-2) |
| revision 跨 Artifact 单调性/幂等提交在 Contract 层校验的方案 | 单 Envelope 无跨 Artifact 视图;违背 IP-0001 留白先例;属 Registry/#68 |
| draft 拒绝解码、"sealed 强制 outcome=completed" 等强耦合 | draft 是合法中间态(#68 staging/seal 流程);无上游决策支持 |
| float 比例、confidence/severity、verified/safe/clear 终态词表 | 违反 v4.0 无 float 与 NFR-01"不编码安全结论" |
| 根工作树其余未跟踪规划文档 | 用户资产,未获引用 |

---

## 3. Iteration Hypothesis 与 Measurement

### 3.1 Hypothesis

如果 Audit 阶段的输出被冻结为一个自包含、确定性、fail-closed 的 `AuditEvidencePackage` 契约——内嵌完整 Evidence Domain 图、显式声明 mining eligibility 与静态支持证据的精确等价、用无安全终态的词表表达 audit outcome、并强制 coverage/budget/gap 与结论共存——那么 #64 Planner、#68 集成与 #70 UI 可以只依赖 fixture 并行开发,"静态命中被当成漏洞""空结果被当成仓库安全"“audit success 被当成 workflow success"这类通用性事故在契约层就没有合法表达。

### 3.2 Measurement

- 固定 golden AEP 生成固定 canonical bytes(4235 bytes)与固定 SHA-256(`f0a98543…64705d0`),其中内嵌的 evidence 图与 IP-0002 golden 逐字节一致;
- eligibility ≠ 全部 statically_supported 假设集、outcome 与 eligibility 矛盾、incomplete 无 gap、analyzed>in_scope、revision<1、悬空 profile 引用、lineage 中 profile 引用 schema 错配、D3/D4 混入内嵌图、public/ephemeral Envelope 全部 fail closed;
- 空结果(no_actionable_hypothesis / no_supported_attack_surface)可表达且 payload 递归无 verified/safe/clear/confidence/severity 字段;
- 新模块导入不加载 DB/网络/Docker/LLM/service/legacy models/profile;加载 `lima.contracts.evidence`(内嵌决策的直接结果);
- 既有 475 个测试无新增失败。

---

## 4. Goal

实现一个 stdlib-only、无副作用、确定性、可版本演化的 `lima.contracts.aep` 叶子模块,包含:

1. 状态/深度/结论枚举:`AuditPackageStatus`(draft|sealed)、`AuditDepth`(initial|deep)、`AuditOutcome`(completed|incomplete|no_actionable_hypothesis|no_supported_attack_surface);
2. `AuditCoverage`(in_scope_file_count / analyzed_file_count)与 `AuditBudget`(tool_runs / model_calls / model_tokens / wall_clock_ms),全非负 exact int;
3. `AuditCoverageGap`(gap_code + detail,规则与 IP-0003 ProfileCoverageGap 相同);
4. `AuditEvidencePackage`:内嵌 `EvidenceDomainBundle`、mining eligibility、revision、audit 元数据,构造与 decode 时完成全图校验;
5. AEP payload 与 IP-0001 `ArtifactEnvelope` 的 encode/decode binding(schema name、inline-only、类型化 profile lineage、evidence provenance lineage、classification/retention、digest);
6. golden fixture(内嵌 IP-0002 golden bundle)、负向边界测试、import isolation 与 legacy regression。

完成后,下游可以统一区分:

```text
evidence_domain                    完整证据图(IP-0002 冻结语义,D0-D2)
mining_eligible_hypothesis_ids     恰等于图中全部 statically_supported 假设(无隐藏、无越级)
audit_outcome                      completed / incomplete / no_actionable_hypothesis /
                                   no_supported_attack_surface —— 词表结构上无法表达"安全"
coverage + coverage_gaps           结论必须与覆盖事实共存;incomplete 必须有 gap
budget                             工具/模型/token/时间消耗(计量事实,非配额判断)
revision + package_status          revision>=1 单调性由 Registry 保证;sealed 是领域关闭语义
```

---

## 5. Non-goals

本次明确不做:

- 不实现 AuditPipeline、run_fast/run_deep、seal API、progress、Audit Cache、worker/retry/cancel、staging 与幂等提交(#68);
- 不实现 Artifact Registry、blob store、latest-sealed pointer、revision 链验证与多跳环检测(未来 Registry IP;本 Contract 仅 `revision >= 1`);
- 不实现 Signal qualification、root-cause clustering、Fusion、Planner、adaptive budget 算法(#61/#64);
- 不生成 ID、digest、时间、revision 递增或随机数;全部由调用方显式传入;
- 不实现 VEP、RVR、Task/ToolBundle/Dependency/Sandbox manifests、Workflow/StageAttempt/Outcome/Plan/RunManifest/Summary/Failure schema;
- 不实现 JSON Schema 文件、兼容矩阵 artifact、ADR(Issue PR3 类);
- 不修改或适配 legacy `Finding`/`EvidenceRecord`/`ReviewReport`,不接 API/Service/Store/Queue/Scanner/Sandbox/Registry/Frontend;
- 不调用 LLM,不访问网络/文件系统/环境变量,不执行目标仓库代码;
- 不引入 severity、confidence、risk、verified、safe、clear 或任何安全终态字段;
- 不修改 `__init__.py`、`evidence.py`、`profile.py`、`common.py`、`codec.py`、`errors.py` 或任何既有测试;
- 不实现 IP-0005 或任何顺手重构。

---

## 6. 工作树与分支前置条件

Coding Agent 必须:

1. 完整阅读稳定标准、lifecycle、Implementation Agent 责任书、本 Packet、`LIMA_Coding_Agent_IP-0004_正式开发任务交接.md` 和 `CONTRIBUTING.md`;
2. 确认两份 IP-0004 文档均已合并到 `origin/main`;
3. **依 lifecycle §9.1 与 Ledger 基线裁定,从 Frozen Test Commit(而非 main)派生 `codex/ip-0004-aep-foundation`**;具体 SHA 由阶段二交付物指定;
4. 确认 `lima/contracts/aep.py` 与本 Packet 的 3 个测试文件、1 个 fixture 尚不存在;
5. 在独立干净 worktree(禁用共享根工作树)输出 Scope Confirmation 后再运行 baseline;
6. baseline 或代码事实与本文不一致时停止并提交 Decision Request。

根工作树中的未跟踪规划文档属于用户资产,不得移动、删除、stash、覆盖或纳入实现 PR。

---

## 7. 文件边界

### 7.1 Files to Add(恰好 5 个)

```text
lima/contracts/aep.py
tests/contracts/test_aep.py
tests/contracts/test_aep_envelope.py
tests/contracts/test_aep_import_isolation.py
tests/contracts/fixtures/audit_evidence_package_v4_golden.json
```

### 7.2 Files Allowed to Modify

```text
none
```

### 7.3 Files Forbidden

除上述 5 个新增文件外全部禁止修改,特别包括:

```text
lima/contracts/__init__.py
lima/contracts/evidence.py
lima/contracts/profile.py
lima/contracts/common.py
lima/contracts/codec.py
lima/contracts/errors.py
tests/contracts/test_evidence.py / test_evidence_envelope.py / test_evidence_import_isolation.py
tests/contracts/test_profile.py / test_profile_envelope.py / test_profile_import_isolation.py
tests/contracts/test_common.py / test_codec.py / test_errors.py / test_import_isolation.py
tests/contracts/fixtures/(全部既有 fixture)
lima/models.py、lima/service.py、lima/api.py、lima/task_progress.py、lima/repository_scanner.py
frontend/、requirements*.txt、pyproject.toml、.github/、PROGRESS.md
```

若实现需要修改任一 forbidden 文件,必须停止;不能通过扩大 allowlist、复制上游类型或放宽测试继续。

### 7.4 Ownership 与冲突边界

- `lima/contracts/aep.py` 在本 Packet 期间只有一个 Owner;
- 后续 IP 不得在本 Packet 合并前创建同名 symbol(13 个,见 §9);
- 新公共 symbol 不从 `lima.contracts` 顶层重导出;下游必须 `from lima.contracts.aep import ...`;
- 依赖方向固定:`aep.py → evidence/codec/common/errors`;`evidence.py`、`profile.py` 不得 import aep。

---

## 8. Allowed / Forbidden Dependencies

### 8.1 Allowed

`aep.py` 只允许导入:

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

测试只允许额外使用 stdlib:

```text
hashlib
pathlib
subprocess
sys
unittest
```

### 8.2 Forbidden

- 任何新增第三方包;
- `lima.contracts.profile`、`lima.models`、audit/service/store/queue/scanner/sandbox/runtime/agent 模块;
- HTTP、socket、数据库、Docker SDK、subprocess(产品模块)、文件系统读取(产品模块);
- UUID、当前时间、随机数、环境变量;
- Pydantic/Marshmallow/JSON Schema 第三方实现;
- 绝对路径、host path 或 repository 内容读取。

`aep.py` 必须保持纯内存 leaf module(唯一合法的 lima 内部依赖为 codec/common/errors/evidence)。

---

## 9. 冻结的公共 Symbols

`lima/contracts/aep.py` 的 `__all__` 必须严格等于以下集合,不多不少(**13** 项):

```python
__all__ = [
    "AUDIT_EVIDENCE_PACKAGE_SCHEMA_NAME",
    "AuditPackageStatus",
    "AuditDepth",
    "AuditOutcome",
    "AuditCoverage",
    "AuditBudget",
    "AuditCoverageGap",
    "AuditEvidencePackage",
    "decode_aep_payload",
    "encode_aep_payload",
    "decode_aep_envelope",
    "encode_aep_envelope",
]
```

模块常量:

```python
AUDIT_EVIDENCE_PACKAGE_SCHEMA_NAME = "lima.audit-evidence-package"
```

不允许额外公开 helper、alias、factory、builder 或第二套异常类型。内部校验函数使用前导下划线。

---

## 10. 冻结枚举

所有枚举均使用 `class X(str, Enum)`(允许 `# noqa: UP042`),wire value 大小写严格固定:

```python
class AuditPackageStatus(str, Enum):
    DRAFT = "draft"
    SEALED = "sealed"

class AuditDepth(str, Enum):
    INITIAL = "initial"
    DEEP = "deep"

class AuditOutcome(str, Enum):
    COMPLETED = "completed"
    INCOMPLETE = "incomplete"
    NO_ACTIONABLE_HYPOTHESIS = "no_actionable_hypothesis"
    NO_SUPPORTED_ATTACK_SURFACE = "no_supported_attack_surface"
```

语义冻结:

- `package_status`:`draft` 为 Audit 进行中的合法中间态;`sealed` 表示该 revision 关闭,后续变更必须产生 `revision+1` 并经 Envelope `supersedes` 指向本版(单调性与幂等提交由 Registry/#68 保证);Mining 消费者必须要求 `sealed`(#64/#68 侧规则);
- `audit_depth`:`initial` 对应 run_fast 产物,`deep` 对应 run_deep 修订版;
- `audit_outcome` 词表**结构上无法表达安全终态**:不存在 verified/safe/clear/vulnerable 取值;`no_supported_attack_surface` 与 `no_actionable_hypothesis` 是"审计结论 + coverage 共存"下的合法非安全结论(V5 §3.2),不是"仓库安全"声明;
- `timeout/OOM/tool_error` 等基础设施状态不得编码为 outcome;工具失败以 `coverage_gaps`(typed gap)表达,#68 侧策略决定 fail closed。

---

## 11. Exact Constructors and Defaults

全部领域对象必须是 `@dataclass(frozen=True, slots=True)`,必须 defensive-copy 所有可变输入。字段顺序固定(required 无默认值在前,集合字段默认 `()`):

### 11.1 `AuditCoverage`

```python
AuditCoverage(
    in_scope_file_count: int,
    analyzed_file_count: int,
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

### 11.2 `AuditBudget`

```python
AuditBudget(
    tool_runs: int,
    model_calls: int,
    model_tokens: int,
    wall_clock_ms: int,
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

### 11.3 `AuditCoverageGap`

```python
AuditCoverageGap(
    gap_code: str,
    detail: str,
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

### 11.4 `AuditEvidencePackage`

```python
AuditEvidencePackage(
    schema_version: SchemaVersion,
    package_status: AuditPackageStatus,
    revision: int,
    audit_depth: AuditDepth,
    audit_outcome: AuditOutcome,
    evidence: EvidenceDomainBundle,
    coverage: AuditCoverage,
    budget: AuditBudget,
    repository_profile_artifact_ids: tuple[str, ...],
    mining_eligible_hypothesis_ids: tuple[str, ...] = (),
    coverage_gaps: tuple[AuditCoverageGap, ...] = (),
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

`schema_version` 是 Envelope context,不进入 payload wire;`evidence` 的 wire 键为 `evidence_domain`(§12)。

### 11.5 Frozen serialization methods

四个 AEP dataclass 都必须提供 deterministic `to_dict()`;三个 nested object 与 `AuditEvidencePackage` 必须提供:

```python
@classmethod
def from_dict(
    cls,
    value: Mapping[str, JSONValue],
    *,
    schema_version: SchemaVersion,
) -> Self: ...

def to_dict(self) -> dict[str, JSONValue]: ...
```

注解必须 Python 3.11/3.12 兼容。`AuditEvidencePackage.from_dict` 以 `EvidenceDomainBundle.from_dict(value["evidence_domain"], schema_version=…)` 复用 IP-0002 全图校验(错误 repath 到 `$.evidence_domain.*`),并执行 §14 全部跨字段校验;`decode_aep_payload` 只是稳定公共入口,不得形成第二套解析逻辑。

---

## 12. Exact Wire Shapes

### 12.1 Top-level payload

4.0 的 required fields 恰好为以下 **10** 个:

```json
{
  "package_status": "sealed",
  "revision": 1,
  "audit_depth": "deep",
  "audit_outcome": "completed",
  "evidence_domain": {"signals": [], "security_issues": [], "vulnerability_hypotheses": [], "evidence": []},
  "repository_profile_artifact_ids": ["profile-0001"],
  "mining_eligible_hypothesis_ids": [],
  "coverage": {"in_scope_file_count": 0, "analyzed_file_count": 0},
  "coverage_gaps": [],
  "budget": {"tool_runs": 0, "model_calls": 0, "model_tokens": 0, "wall_clock_ms": 0}
}
```

全部必填;`evidence_domain` 的四个数组可为空(空图只表示本包无领域对象,配合 outcome 词表表达非安全结论,不表示仓库安全);4.0 不允许其他字段。

### 12.2 `AuditCoverage`

```json
{"in_scope_file_count": 42, "analyzed_file_count": 40}
```

### 12.3 `AuditBudget`

```json
{"tool_runs": 3, "model_calls": 1, "model_tokens": 12000, "wall_clock_ms": 45000}
```

### 12.4 `AuditCoverageGap`

```json
{"gap_code": "TIER0_FILE_BUDGET_EXCEEDED", "detail": "Bandit exceeded the per-file size budget for two vendored files."}
```

### 12.5 `evidence_domain`

与 IP-0002 `EvidenceDomainBundle` payload wire shape **逐字段相同**(signals/security_issues/vulnerability_hypotheses/evidence + 其 future-minor extensions 规则),由 evidence 模块自身校验器解析;AEP 不复制、不放松其任何规则(D0-D2、subject 精确绑定、DAG、静态状态一致、path/identifier/文本限制全部原样生效)。

### 12.6 Extensions

- 4.0:任何 AEP 层级(顶层、coverage、budget、gap)出现 unknown field 都以 `UNKNOWN_FIELD` 拒绝;`evidence_domain` 内部层级按 evidence 模块自身规则拒绝;
- 未来 4.x:unknown optional field 在对应对象的 `extensions` 原位置无损 round-trip(含 evidence_domain 内部,复用 IP-0002 机制);
- extension key NFC 冲突 `DUPLICATE_SEMANTIC_FIELD`;required 缺失与 unknown enum 即使未来 minor 也拒绝。

---

## 13. Scalar Validation

- `revision`:exact int(`type(x) is int`,拒绝 bool),范围 `1..9223372036854775807`;`INVALID_FIELD_VALUE $.revision`;
- coverage/budget 六个计量:exact int(拒绝 bool),`0..9223372036854775807`;超 int64 用 `INTEGER_OUT_OF_RANGE` 之外的口径——统一为 `INVALID_FIELD_VALUE`(负数/越界)与 `INVALID_FIELD_TYPE`(bool/非 int);
- `gap_code`:`[A-Z][A-Z0-9_]{0,63}`,NFC;
- `detail`:bounded text——exact str、NFC、非空、无 `Cc`、无前导/尾随空白、≤4096 UTF-8 bytes;error message 不回显原值;
- `repository_profile_artifact_ids` 与 `mining_eligible_hypothesis_ids` 成员:IP-0002 identifier 规则 `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`;
- enum 字段:非 str 用 `INVALID_FIELD_TYPE`,未知值用 `UNKNOWN_ENUM_VALUE`。

---

## 14. Array Limits,Canonical Ordering 与 Cross-field Invariants

### 14.1 数组上限与排序

| Array | 上限 | 允许空 | 排序规则 |
|---|---:|---:|---|
| `repository_profile_artifact_ids` | 16 | 否(≥1) | ASCII 升序、唯一 |
| `mining_eligible_hypothesis_ids` | 2048 | 是 | ASCII 升序、唯一 |
| `coverage_gaps` | 256 | 是 | `(gap_code, detail 的 UTF-8 bytes)` 升序;对唯一 |
| `evidence_domain` 内部数组 | 按 IP-0002 §13 | 按 IP-0002 | 按 IP-0002 |

Contract 不隐式排序;违规以 `INVALID_FIELD_VALUE` 拒绝;超上限 `MAX_ARRAY_LENGTH_EXCEEDED`。profile 引用上限 16 的依据:monorepo 的 component profile 数由 V5 §3.2 限定为"少量 component AEP",过大即生产者建模错误。

### 14.2 Mining eligibility 精确等价(核心不变量)

设 `S = {h.hypothesis_id : h ∈ evidence_domain.vulnerability_hypotheses, h.status == statically_supported}`,则:

```text
mining_eligible_hypothesis_ids 必须恰好等于 S(作为集合)
```

- 少列(隐藏某条 statically_supported 假设)→ `INVALID_FIELD_VALUE $.mining_eligible_hypothesis_ids`;
- 多列(列入 proposed / statically_refuted / conflicting_static_evidence / insufficient_static_evidence 或不存在者)→ `INVALID_FIELD_VALUE $.mining_eligible_hypothesis_ids[i]`;
- 这使"AEP 只表达值得 Mining 验证的 Hypothesis"成为机器可校验事实:预算不足不能静默丢弃假设,必须以 coverage_gaps 表达。

### 14.3 Outcome 映射(核心不变量)

```text
mining_eligible 非空  ⇒  audit_outcome == completed                       ($.audit_outcome)
mining_eligible 为空  ⇒  audit_outcome ∈ {no_actionable_hypothesis,
                                          no_supported_attack_surface,
                                          incomplete}                       ($.audit_outcome)
audit_outcome == incomplete  ⇒  coverage_gaps 非空                         ($.coverage_gaps)
```

不做的耦合(明确豁免):`package_status` 与 outcome/depth 自由组合(draft/sealed 均可处任何 outcome);`deep` 不强制 `revision ≥ 2`(revision 语义属 Registry);`no_supported_attack_surface` 不强制 cross-artifact 核对 profile kinds(生产者 #68 语义,Contract 不越权)。

### 14.4 Coverage 一致性

`0 ≤ analyzed_file_count ≤ in_scope_file_count`;违反 → `INVALID_FIELD_VALUE $.coverage.analyzed_file_count`。

### 14.5 Provenance(Envelope binding 阶段)

- `repository_profile_artifact_ids` 每个成员必须存在于 Envelope lineage,且 lineage 中该 `artifact_id` 对应条目的 `schema_name` 必须等于 `lima.repository-profile`(类型化引用,防错配);
- `evidence_domain.evidence[*].source_artifact_ids` 每个成员必须存在于 lineage(IP-0002 规则提升到 AEP Envelope 层执行);
- lineage 允许包含额外上游 Artifact;tenant/snapshot/self/duplicate/conflict 由 IP-0001 拒绝。

---

## 15. Envelope Binding Contract

### 15.1 Function signatures

```python
def decode_aep_payload(
    value: Mapping[str, JSONValue],
    *,
    schema_version: SchemaVersion,
) -> AuditEvidencePackage: ...

def encode_aep_payload(
    package: AuditEvidencePackage,
) -> dict[str, JSONValue]: ...

def decode_aep_envelope(
    data: bytes,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> tuple[ArtifactEnvelope, AuditEvidencePackage]: ...

def encode_aep_envelope(
    envelope: ArtifactEnvelope,
    package: AuditEvidencePackage,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> bytes: ...
```

### 15.2 Binding rules

`decode_aep_envelope` 必须:

1. 调用 IP-0001 `decode_envelope`;
2. 要求 `schema_name == AUDIT_EVIDENCE_PACKAGE_SCHEMA_NAME`;
3. 要求 inline `payload`,拒绝 blob-backed envelope;
4. 以 envelope `schema_version` decode package(内嵌 evidence_domain 同版本解析);
5. 校验 `repository_profile_artifact_ids ⊆ lineage artifact_ids` 且对应条目 `schema_name == "lima.repository-profile"`;失败 `INVALID_FIELD_VALUE`,路径 `$.payload.repository_profile_artifact_ids[j]`;
6. 校验 `evidence_domain.evidence[*].source_artifact_ids ⊆ lineage artifact_ids`;失败 `INVALID_FIELD_VALUE`,路径 `$.payload.evidence_domain.evidence[i].source_artifact_ids[j]`;
7. 允许 lineage 包含额外上游 Artifact;
8. 要求 classification 不是 `public`;
9. 要求 retention 不是 `ephemeral`;
10. 返回 `(envelope, package)`,不得修改输入。

`encode_aep_envelope` 必须执行相同 binding,并额外要求:

- `envelope.schema_version == package.schema_version`;
- `envelope.payload == encode_aep_payload(package)`;
- `compute_content_digest(package payload)` 与 `envelope.content_digest` 用 `hmac.compare_digest` 相等;
- 最终调用 IP-0001 `encode_envelope`;
- 不自动创建、替换、修补 Envelope 或 supersedes。

### 15.3 Classification / retention

- allowed classification:`internal`、`sensitive`、`restricted`;forbidden:`public`;
- allowed retention:`standard`、`audit`、`legal_hold`;forbidden:`ephemeral`;
- 不匹配 `INVALID_FIELD_VALUE`,`$.classification` / `$.retention_class`。

AEP 内嵌安全命题、位置与工具证据,不得公开传输;作为 Mining/Repair 与审计日志的上游必须可审计保留。

---

## 16. Stable Error Mapping and Precedence

IP-0004 不新增错误码。所有失败使用现有 **29** 个 `ContractError` 之一,message 由 IP-0001 catalog 决定且不回显输入。

| 条件 | Error code |
|---|---|
| required field 缺失 | `REQUIRED_FIELD_MISSING` |
| current 4.0 unknown field | `UNKNOWN_FIELD` |
| wrong container/scalar/dataclass/enum instance type;bool 冒充 int | `INVALID_FIELD_TYPE` |
| unknown enum wire value | `UNKNOWN_ENUM_VALUE` |
| revision/计量范围、gap_code/detail、数组排序/重复/上限、eligibility 等价、outcome 映射、coverage 一致性非法 | `INVALID_FIELD_VALUE` |
| 超过数组上限 | `MAX_ARRAY_LENGTH_EXCEEDED` |
| 超过字符串上限 | `MAX_STRING_LENGTH_EXCEEDED` |
| extension key NFC 冲突 | `DUPLICATE_SEMANTIC_FIELD` |
| payload/package/content digest 不一致 | `DIGEST_MISMATCH` |
| Envelope tenant/snapshot/lineage 冲突 | 复用 IP-0001 `LINEAGE_*` |
| codec bytes/depth/object/string 限制 | 复用 IP-0001 resource codes |
| 内嵌 evidence_domain 的一切失败 | 复用 IP-0002 code,路径前缀 `$.evidence_domain.*` |

优先级(同一输入多违规时返回第一项):

1. codec byte/UTF-8/JSON/resource limit;
2. top-level container/required/current unknown/schema version;
3. enum 与 scalar type(含 bool 精确性);
4. scalar value/range、数组 limit/order/duplicate;
5. 内嵌 evidence_domain 校验(经 `EvidenceDomainBundle.from_dict`,repath 至 `$.evidence_domain.*`);
6. AEP 跨字段不变量(§14.2 eligibility 等价 → §14.3 outcome 映射 → §14.4 coverage 一致性);
7. lineage provenance(§14.5,类型化 profile 引用 + evidence 来源);
8. Envelope schema/payload/digest/classification/retention binding。

`field_path` 示例:

```text
$.revision
$.audit_outcome
$.coverage.analyzed_file_count
$.evidence_domain.signals[0].rule_id
$.evidence_domain.vulnerability_hypotheses[0].status
$.mining_eligible_hypothesis_ids[1]
$.payload.repository_profile_artifact_ids[0]
$.payload.evidence_domain.evidence[0].source_artifact_ids[0]
```

不得在 path 中包含真实字段值。

---

## 17. Golden Fixture

文件:

```text
tests/contracts/fixtures/audit_evidence_package_v4_golden.json
```

要求:UTF-8;单行 canonical JSON;无 BOM;无 trailing newline;**exactly 4235 bytes**;payload SHA-256:

```text
f0a985432ebd11dc4b85897653cf443dc2c0b0312e453424648ebc2d164705d0
```

该 bytes 与 digest 已由 IP-0001 codec 在 main `9078bb5` 上预计算冻结;内嵌 `evidence_domain` 与 IP-0002 golden fixture 内容逐字节一致(`1b313f8c…96c51`),`hypothesis-0001` 为 `statically_supported` 故 eligibility 恰为 `["hypothesis-0001"]`。权威内容如下;实现者不得更改字段、值、顺序或摘要:

```json
{"audit_depth":"deep","audit_outcome":"completed","budget":{"model_calls":1,"model_tokens":12000,"tool_runs":3,"wall_clock_ms":45000},"coverage":{"analyzed_file_count":40,"in_scope_file_count":42},"coverage_gaps":[{"detail":"Bandit exceeded the per-file size budget for two vendored files.","gap_code":"TIER0_FILE_BUDGET_EXCEEDED"}],"evidence_domain":{"evidence":[{"analysis_family":"static-dataflow","depends_on_evidence_ids":["evidence-issue-0001"],"evidence_id":"evidence-hypothesis-0001","independence_key":"python-dataflow:cli-to-process","level":"D2","location":{"end_column":18,"end_line":10,"path":"src/example.py","start_column":5,"start_line":10,"symbol":"run_command"},"polarity":"supports","producer":"lima-python-dataflow","reason_codes":["SOURCE_TO_SINK_PATH"],"source_artifact_ids":["tool-run-0001"],"subject_id":"hypothesis-0001","subject_kind":"vulnerability_hypothesis","summary":"A deterministic source-to-sink path reaches process execution."},{"analysis_family":"contextual-analysis","depends_on_evidence_ids":["evidence-signal-0001"],"evidence_id":"evidence-issue-0001","independence_key":"cluster:command-injection:cli-to-process","level":"D1","location":{"end_column":18,"end_line":10,"path":"src/example.py","start_column":5,"start_line":10,"symbol":"run_command"},"polarity":"supports","producer":"lima-audit","reason_codes":["CONTEXT_APPLICABLE"],"source_artifact_ids":["tool-run-0001"],"subject_id":"issue-0001","subject_kind":"security_issue","summary":"The matched sink is in a CLI trust boundary."},{"analysis_family":"sast","depends_on_evidence_ids":[],"evidence_id":"evidence-signal-0001","independence_key":"bandit:B602:src/example.py:10","level":"D0","location":{"end_column":18,"end_line":10,"path":"src/example.py","start_column":5,"start_line":10,"symbol":"run_command"},"polarity":"supports","producer":"bandit-1.9.4","reason_codes":["RULE_MATCH"],"source_artifact_ids":["tool-run-0001"],"subject_id":"signal-0001","subject_kind":"signal","summary":"Bandit reported process execution with shell semantics."}],"security_issues":[{"cwe_ids":["CWE-78"],"evidence_ids":["evidence-issue-0001"],"identity_digest":"2222222222222222222222222222222222222222222222222222222222222222","issue_id":"issue-0001","primary_location":{"end_column":18,"end_line":10,"path":"src/example.py","start_column":5,"start_line":10,"symbol":"run_command"},"reason_codes":["ROOT_CAUSE_CLUSTERED_BY_SINK"],"root_cause_class":"command-injection","signal_ids":["signal-0001"],"sink_identity":"python.subprocess.shell","trust_boundary":"cli-to-process"}],"signals":[{"analysis_family":"sast","cwe_ids":["CWE-78"],"evidence_ids":["evidence-signal-0001"],"evidence_kind":"tool-observation","fingerprint":"1111111111111111111111111111111111111111111111111111111111111111","location":{"end_column":18,"end_line":10,"path":"src/example.py","start_column":5,"start_line":10,"symbol":"run_command"},"reason_codes":["RULE_MATCH_PROCESS_EXECUTION"],"rule_id":"B602","signal_id":"signal-0001"}],"vulnerability_hypotheses":[{"capability_requirements":["python","subprocess-observer"],"claim":"Untrusted CLI input may reach a process execution sink.","critical_path":[{"end_column":24,"end_line":20,"path":"src/cli.py","start_column":1,"start_line":20,"symbol":"main"},{"end_column":18,"end_line":10,"path":"src/example.py","start_column":5,"start_line":10,"symbol":"run_command"}],"cwe_ids":["CWE-78"],"evidence_ids":["evidence-hypothesis-0001"],"hypothesis_id":"hypothesis-0001","input_constraints":["argument contains shell metacharacters"],"issue_id":"issue-0001","reason_codes":["STATIC_DATAFLOW_REACHES_PROCESS_SINK"],"required_proof_kind":"runtime_behavior","security_invariant":"Process arguments must not be interpreted by a command shell.","source_locations":[{"end_column":24,"end_line":20,"path":"src/cli.py","start_column":1,"start_line":20,"symbol":"main"}],"status":"statically_supported","target_location":{"end_column":18,"end_line":10,"path":"src/example.py","start_column":5,"start_line":10,"symbol":"run_command"},"trigger_conditions":["attacker controls the CLI argument"]}]},"mining_eligible_hypothesis_ids":["hypothesis-0001"],"package_status":"sealed","repository_profile_artifact_ids":["profile-0001"],"revision":1}
```

### 17.1 Frozen envelope vector

```text
schema_name = lima.audit-evidence-package
schema_version = 4.0
artifact_id = aep-0001
tenant_id = tenant-1
task_id = task-1
workflow_id = workflow-1
stage_attempt_id = audit-1
repository_snapshot_digest = "3" * 64
producer = lima-audit
created_at = 2026-09-02T00:00:00Z
policy_digest = "5" * 64
toolchain_digest = "6" * 64
content_digest = f0a985432ebd11dc4b85897653cf443dc2c0b0312e453424648ebc2d164705d0
classification = sensitive
retention_class = audit
lineage[0].schema_name = lima.repository-profile
lineage[0].schema_version = 4.0
lineage[0].artifact_id = profile-0001
lineage[0].tenant_id = tenant-1
lineage[0].repository_snapshot_digest = "3" * 64
lineage[0].content_digest = ad7d53a0ed22412dbbfc60d0ed9183d7e939e2d14e4eee2d9399944cb5c4dccc
lineage[1].schema_name = lima.tool-run
lineage[1].schema_version = 4.0
lineage[1].artifact_id = tool-run-0001
lineage[1].tenant_id = tenant-1
lineage[1].repository_snapshot_digest = "3" * 64
lineage[1].content_digest = "4" * 64
supersedes = null
coverage_gaps = []
```

---

## 18. Required Tests

测试必须使用 `unittest`,方法名冻结如下。可以增加 private test helpers 与更细测试,不得减少、重命名或合并以下测试。

### 18.1 `tests/contracts/test_aep.py`(25)

```text
AepEnumTests
  test_wire_values_are_exact

AuditCoverageTests
  test_round_trip_has_exact_wire_shape
  test_rejects_bool_negative_missing_and_impossible_counts

AuditBudgetTests
  test_round_trip_has_exact_wire_shape
  test_rejects_bool_negative_and_missing_values

AuditCoverageGapTests
  test_round_trip_has_exact_wire_shape
  test_rejects_invalid_code_detail_and_oversize
  test_rejects_unsorted_and_duplicate_gaps

AuditEvidencePackageTests
  test_minimal_no_actionable_package_round_trip_is_valid
  test_minimal_completed_package_round_trip_is_valid
  test_golden_package_round_trip_and_digest
  test_rejects_wrong_container_and_missing_required_fields
  test_rejects_unknown_enum_and_wrong_field_type
  test_rejects_revision_below_one_bool_and_out_of_range
  test_embedded_evidence_bundle_is_validated
  test_rejects_missing_and_non_statically_supported_eligible_hypotheses
  test_eligible_set_must_equal_full_statically_supported_set
  test_audit_outcome_mapping_enforced
  test_incomplete_outcome_requires_coverage_gaps
  test_empty_bundle_is_not_a_safety_verdict
  test_rejects_unsorted_duplicate_and_oversize_arrays
  test_future_minor_round_trips_unknown_fields_at_every_level
  test_current_minor_rejects_unknown_fields_at_every_level
  test_defensive_copy_prevents_post_construction_mutation
  test_payload_has_no_verified_safe_clear_confidence_or_severity_fields
```

`test_payload_has_no_verified_safe_clear_confidence_or_severity_fields` 必须递归断言 golden 与 minimal payload 任意层级不出现键:`verified`、`safe`、`clear`、`is_vulnerable`、`confidence`、`severity`、`trust_score`。

### 18.2 `tests/contracts/test_aep_envelope.py`(11)

```text
AepEnvelopeTests
  test_frozen_envelope_encode_decode_is_byte_stable
  test_rejects_wrong_schema_name_and_version_mismatch
  test_rejects_blob_backed_aep
  test_rejects_payload_package_and_content_digest_mismatch
  test_rejects_missing_profile_lineage_reference
  test_rejects_profile_lineage_entry_with_wrong_schema_name
  test_rejects_missing_evidence_source_lineage
  test_allows_additional_valid_lineage
  test_inherits_cross_tenant_cross_snapshot_and_self_reference_rejection
  test_rejects_public_classification_and_ephemeral_retention
  test_tampered_payload_fails_before_domain_promotion
```

### 18.3 `tests/contracts/test_aep_import_isolation.py`(4)

```text
AepImportIsolationTests
  test_module_public_api_matches_frozen_symbol_set
  test_clean_process_import_has_no_db_network_docker_llm_service_or_legacy_models
  test_module_only_uses_allowed_imports
  test_import_does_not_change_lima_contracts_top_level_public_api
```

`test_clean_process_import…` 必须断言:干净子进程导入 `lima.contracts.aep` 后,`lima.contracts.evidence` **在** `sys.modules`(内嵌决策的直接结果),而 `lima.contracts.profile` 与其余 forbidden roots **不在**。

### 18.4 Minimum count

IP-0004 必须新增至少 **40** 个独立 test methods(25+11+4)。不允许用循环把多种安全边界压缩成一个无法定位的单断言。

---

## 19. Acceptance Criteria and Traceability

| AC | Required behavior | Evidence(test) | 覆盖的 Issue requirement |
|---|---|---|---|
| IP4-AC-01 | 13 个 module public symbols、3 个 enum wire vocabulary、4 个 exact constructors 完全冻结 | enum/object/import tests | FR-02(AEP 版本化定义) |
| IP4-AC-02 | revision/计量/gap/detail/bool scalar 与数组上限 fail closed | Coverage/Budget/Gap/package negative tests | NFR-02 |
| IP4-AC-03 | golden AEP 为 4235 bytes、固定 digest、decode/encode byte-stable;内嵌图与 IP-0002 golden 一致 | golden test | FR-05(AEP fixture 子集)、AC-01 方法论 |
| IP4-AC-04 | 内嵌 evidence_domain 由 IP-0002 规则完整校验(repath;D3/D4 拒绝延续) | embedded bundle tests | FR-02、NFR-01 |
| IP4-AC-05 | eligibility 恰等于 statically_supported 集;outcome 映射与 incomplete⇒gaps 强制 | eligibility/outcome tests | NFR-01(不编码安全结论;#68 语义) |
| IP4-AC-06 | Envelope schema/version/digest/类型化 profile lineage/evidence lineage/classification/retention binding | envelope tests | FR-02(跨对象引用)、NFR-01 |
| IP4-AC-07 | 4.0 unknown field 拒绝(每层级);未来 4.x 无损 round-trip;unknown enum/required 缺失仍拒绝 | compatibility tests | FR-06 |
| IP4-AC-08 | 无 verified/safe/clear/is_vulnerable/confidence/severity/trust_score;outcome 词表结构上无安全终态 | forbidden-key + enum tests | NFR-01 |
| IP4-AC-09 | stdlib leaf;依赖方向 aep→evidence/codec/common/errors;不 import profile;顶层 API/29 codes 不变 | import isolation + git diff | AC-04(T-04)、FR-04 尊重 |
| IP4-AC-10 | 只新增 5 个 allowlist 文件,0 modified,0 deps,全量回归无新增失败 | file boundary + full regression | AC-04、Issue 级 PR 边界 |

任一 AC 无机器证据时状态不是 DONE。

---

## 20. 强制实现顺序

必须测试先行(阶段二由 P&V 冻结测试并证明 RED;Implementation Agent 从 Frozen Test Commit 开始):

1. 复核冻结测试的 RED 已由 P&V 记录;按 slice 顺序实现;
2. 常量、3 个枚举、通用 validators、`AuditCoverage`/`AuditBudget`/`AuditCoverageGap`;
3. `AuditEvidencePackage`(内嵌 bundle 解析 + §14 全部跨字段校验);
4. 逐字验证 golden fixture(4235 bytes / `f0a98543…64705d0`,内嵌图 = IP-0002 golden);
5. 4 个 encode/decode functions 与 §15 binding;
6. import isolation 与 forbidden-key 断言;
7. Slice Gate → Compatibility Gate → File Boundary Gate → Completion Summary。

不得先写完实现再弱化测试;测试发现 Packet 冲突时停止。

---

## 21. Done Commands

### 21.1 Baseline(编码前)

```powershell
python -m compileall -q lima scripts tests
python -m unittest discover -s tests/contracts -v
python -m unittest -v tests.test_repository_source tests.test_task_failure
```

预期基线(@ `9078bb5` + 本 Packet 合并):contracts **130** PASS;定向兼容 **29** PASS。若数量变化,以最新 `main` 实际结果为准并记录差异。

### 21.2 Slice Gate

```powershell
python -m compileall -q lima/contracts tests/contracts
python -m unittest discover -s tests/contracts -v
python -m ruff check lima/contracts/aep.py tests/contracts/test_aep.py tests/contracts/test_aep_envelope.py tests/contracts/test_aep_import_isolation.py
python -m ruff check lima/contracts tests/contracts
python -m bandit -q -r lima/contracts/aep.py
git diff --check
```

### 21.3 Compatibility Gate

```powershell
python -m unittest -v tests.test_repository_source tests.test_task_failure
python -m unittest discover -s tests -v
```

基线参考:实现后预期 contracts **170**(130+40)、全量 **515**(475+40)/ 0 failed / 1 既有 skip。任何新增 failure/skip 必须解释;不能通过修改 legacy 测试解决。Python 3.11/3.12 由 CI matrix 验证。

### 21.4 File Boundary Gate

```powershell
git diff --name-only --diff-filter=ACMRTUXB <frozen-base>...HEAD
git diff --check <frozen-base>...HEAD
```

第一条输出必须恰好为 7.1 的 5 个新增文件(相对 Frozen Test Commit,产品侧仅 `lima/contracts/aep.py`)。

### 21.5 Optional release-level gate

维护者或 CI 可运行 `powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 test`;普通 Agent 不因 Docker/宿主环境不可用而改变产品代码。

---

## 22. Security and Compatibility Invariants

- AEP 不编码任何安全终态:词表无 verified/safe/clear/vulnerable;`no_*` 结论必须与 coverage/gaps 共存;
- eligibility 精确等价使"隐藏支持假设"与"越级提升"都不可表达;
- D3/D4 不得经内嵌图进入 AEP;`statically_supported` 不是 runtime reproduced;
- 内嵌图、位置、命题属敏感内容:classification 禁 public、retention 禁 ephemeral;
- 类型化 profile lineage:profile 引用错配 schema 即拒绝;
- revision/ID/digest/时间/计量全部由调用方提供;Contract 不生成身份值;
- 不新增网络、磁盘、DB、Docker、subprocess、凭据或付费模型权限;
- 不改变 legacy 1.6.0 行为与 IP-0001/0002/0003 冻结面(18 顶层 / 16 evidence / 15 profile / 29 codes / 两 golden digest);
- 不通过 future-minor extension 绕过 required、enum、eligibility 或 provenance 要求。

---

## 23. Stop Conditions / Decision Request

出现以下任一情况必须停止:

1. 本 Packet 或正式交接书尚未合并到 `origin/main`,或基线不再是 `9078bb5` 后代;
2. 最新 `main` 已出现同名 `aep.py` 或冲突 Owner;
3. 需要修改任一 forbidden 文件或扩大 allowlist;
4. 需要新增第三方依赖、I/O、网络、数据库、Docker、subprocess 或环境权限;
5. §10-§16 任一契约存在两个与上游决策同等自洽的答案;
6. frozen fixture 的 4235 bytes / digest 无法由 IP-0001 codec 重现,或内嵌图与 IP-0002 golden 不一致;
7. 需要引入 float、confidence/severity、安全终态、自动 ID/revision 递增或放松 eligibility 等价才能继续;
8. 需要实现 pipeline/seal/registry/幂等提交/blob 才能让测试通过;
9. baseline/全量回归失败且无法归因;
10. required tests 无法证明某个 AC;
11. 发现工作实际进入 VEP/RVR、workflow schema、#68 集成或生产接线。

Decision Request 格式:

```text
Packet/规则位置:
实际代码证据:
最小复现命令:
为什么无法在 5-file allowlist 内解决:
可选方案:
各方案的兼容、安全、工期影响:
Agent 建议:
```

维护者更新 Packet/Decision Record 前不得越界继续。

---

## 24. Git, Commit and PR Contract

推荐 commit / PR 标题:

```text
feat: add deterministic audit evidence package contracts
```

PR 正文必须:只写 `Related to #58`;不出现任何 auto-close 关键字;附 AC → Test → Result;真实命令、退出码、passed/failed/skipped;明确 5 added / 0 modified / 0 dependencies;明确 no production integration、no pipeline/seal/registry、no top-level public API change、evidence.py 与 profile.py untouched。等待独立 Reviewer 和 `merge-gate`。

Implementation Agent 不合并自己的 PR,不删除分支/worktree,不修改 Issue。

---

## 25. Completion Summary Template

```markdown
## IP-0004 Completion Summary

### Result
- Status: DONE | NOT DONE | BLOCKED
- Base commit / Frozen Test Commit:
- Final commit:
- Branch / Worktree:

### Scope
- Added files:
- Modified existing files: none | <mark NOT DONE>
- Dependencies added: none | <mark NOT DONE unless approved>
- Public API: `lima.contracts.aep` only (13 symbols)
- Contract deviations: none | <Decision Request>

### Acceptance evidence
| AC | Test/command | Result |
|---|---|---|
| IP4-AC-01 | | |
| IP4-AC-02 | | |
| IP4-AC-03 | | |
| IP4-AC-04 | | |
| IP4-AC-05 | | |
| IP4-AC-06 | | |
| IP4-AC-07 | | |
| IP4-AC-08 | | |
| IP4-AC-09 | | |
| IP4-AC-10 | | |

### Commands and actual results
- Command / Exit code / Passed/failed/skipped:

### Security and compatibility
- Eligibility exact-set & outcome mapping fail-closed evidence:
- Embedded bundle D3/D4 & repathed rejection evidence:
- Typed profile lineage & evidence provenance evidence:
- Secret/input echo review:
- Import isolation (loads evidence; not profile):
- Python 3.11/3.12:
- Legacy regression:

### Findings and decisions
- New Findings / Approved Decisions / Open Decision Requests:

### Handoff
- PR URL/status / Exact next action / Forbidden next action:
```

---

## 26. Maintainer Review Checklist

- [ ] base 为 Frozen Test Commit 后代且包含本 Packet 合并版;
- [ ] 只新增 5 个 allowlist 文件;`aep.py` 是唯一产品文件;
- [ ] 冻结面不变:顶层 18、evidence 16、profile 15、29 codes、两 golden digest;`evidence.py`/`profile.py`/`__init__.py` 零改动;
- [ ] module public API 恰好 13 symbols;依赖方向 aep→{evidence,codec,common,errors};不 import profile;
- [ ] exact constructors/wire shapes(10 个 top-level required 字段、`evidence_domain` 内嵌)无漂移;
- [ ] golden fixture 4235 bytes、digest `f0a98543…64705d0`、内嵌图 = IP-0002 golden;
- [ ] eligibility 精确等价、outcome 映射、incomplete⇒gaps、coverage 一致性 negative tests 通过;
- [ ] Envelope 类型化 profile lineage / evidence lineage / classification / retention tests 通过;
- [ ] current/future-minor matrix(每层级)通过;
- [ ] 无 verified/safe/clear/is_vulnerable/confidence/severity/trust_score 字段;
- [ ] import isolation(含"加载 evidence、不加载 profile"方向断言)通过;
- [ ] 全量回归无新增失败(预期 515 = 475+40);全目录 ruff exit 0;
- [ ] File Boundary 恰好 5 文件;Completion Summary 可复现;独立 Review 与 `merge-gate` 通过;
- [ ] PR 未关闭 #58;未启动 IP-0005、pipeline/seal/registry 或生产接线。

---

## 27. Packet 完成定义

只有全部 10 个 AC、40 个 required tests、golden fixture、Envelope consumer test、import isolation、完整命令证据、独立 Review 和 `merge-gate` 全部满足,IP-0004 实现才能标记 DONE。

IP-0004 合并后,协调者必须在最新 `main` 上安排 post-merge verification,并让下一个消费 IP(由 Coordinator 分解:VEP/RVR 或 workflow schema)对本模块做只读 consumer review(其 Packet 的 Design Input Manifest 入口 Gate)。当前 Agent 不自动继续下一个 IP。
