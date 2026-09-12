# LIMA Implementation Packet IP-0007:Workflow Spine Schemas(Workflow / StageAttempt / SecurityOutcome)

> Packet ID:`IP-0007`
>
> 状态:`DESIGN-FROZEN / READY-FOR-CODE WHEN THIS PACKET IS MERGED TO MAIN`
>
> Source Issue:[#58](https://github.com/agent-sec-labs/LIMA/issues/58) 的第七个独立实现切片(第六个 domain 切片,首个跨阶段编排类 schema)
>
> 最低代码基线:Assignment 基线 `78aa9d87873312d7541392969015984ebb4b154c`(IP-0006 实现 #113 之后含 PR #69 redis manifest 升级);实现基线必须是包含本 Packet 与正式交接书的最新 `origin/main`
>
> 推荐分支:`codex/ip-0007-workflow-spine-schemas`(依 lifecycle §9.1 从 Frozen Test Commit 派生,实现阶段 Assignment 另行出具)
>
> Owner:唯一 Implementation Agent;不得与任何活动 IP 并行修改 `lima/contracts/` 或 `tests/contracts/`(cxx 三分支 #123/#124/#125 已实证不触碰该目录)

## 需求映射(Header)

```text
Source Issue:#58
Issue specification revision:正文修订 2026-09-01T14:36:22Z(V4 基线 + V5 覆盖层,冲突以 V5 节为准);
  Delivery Ledger v20 @ 2026-09-05T03:40:14Z(激活依据:PKT-IP-0007 由新 Coordinator takeover ACCEPTED 后派发)
Covered requirements:V5-FR-01 的 Workflow、StageAttempt、SecurityOutcome 子集(Profile 子集已由 IP-0003 交付并入账);
  支撑性覆盖 FR-02(三 schema 的版本化定义与 artifact_id + content_digest + schema_version 三元组引用);
  FR-05(三 schema 的 minimal/full/negative/golden fixtures)、FR-06(本 schema current/future-minor 兼容)、
  NFR-01 的表达面(blocked/failed/timeout/OOM/tool_error 永不编码为安全结论——结构性词表分区,
  V5-AC-02 的机器断言)、NFR-02(校验上限)、AC-04(依赖隔离对新模块适用)
Not covered requirements:V5-FR-01 剩余四 schema:Plan、RunManifest、Summary、Failure(IP-0008 候选;
  本 Packet 只允许逻辑引用或 FailureKind 最小枚举占位,见 DR-IP0007-DESIGN-02/03);FR-02 manifests 子集
  (Task/ToolBundle/Dependency/Sandbox/Candidate);PR3 类(JSON Schema 文件、版本兼容矩阵 artifact、ADR)、
  PR4 类(legacy adapter fixture)、V5-FR-04 场景 fixtures;#90(V5-N01 Workflow Runtime)的全部实现职责
  (状态机执行、持久化、API、恢复、进度、lease、policy evaluator);#68(V5-N02/FULL_CHAIN 集成)的生产层改造;
  closure IP 职责(跨 Artifact 集成、真实 Golden Path、Closure Audit)
Delivery role:domain
Issue closure impact:PARTIAL(合并后不触发 #58 closure;#58 保持 open)
Upstream IP/PR/merge commits:
  IP-0001 #97 `5cdf872` / #98 `d3e73d9` / 恢复 #102 `a0b3eea`(IP-DONE)
  IP-0002 #99 `f92122b` / #100 `4fe1def`(IP-DONE)
  IP-0003 #103 `437fe01` / Frozen v2 `573de77` / #104 `9078bb5`(IP-DONE)
  IP-0004 #105 `046d67b` / Frozen v2 `aa2e3c5` / #107 `5984c5c`(IP-DONE)
  IP-0005 #108 `69458e5` / Frozen v2 `4b1cf6b` / #110 `8afc594`(IP-DONE)
  IP-0006 #111 `e77754a` / Frozen v2 `e02e888` / #113 `57dc1ab`(IP-DONE,post-merge PASS @ `78aa9d8`)
Activation gate:lifecycle 入口 consumer review(见 §1,已完成,无 Contract Gap)
```

---

## 0. 执行决策

当前执行队列(Ledger v20,2026-09-05):

```text
DONE
IP-0001(+R1)、IP-0002、IP-0003、IP-0004、IP-0005、IP-0006(全部 IP-DONE,7/7)

NOW(只允许 1 个)
IP-0007 Workflow Spine Schemas(Design Frozen;文档合并后进入阶段二测试冻结)

NEXT(不得实现)
IP-0008 候选:Plan/RunManifest/Summary/Failure schemas(依赖本 IP)

LATER
manifests 子集(FR-02 尾)、PR3(矩阵/ADR)、PR4(legacy adapter)、V5 场景 fixtures、closure IP、
consumer review 调度(#60/#61/#66/#70)
```

本 Packet 只建立可被 #90(V5-N01 Runtime,FR-N01-01 "消费 #58 定义的 Workflow/Stage/Outcome schema")与 IP-0008 消费的确定性 Workflow/StageAttempt/SecurityOutcome 三份 Artifact 契约。它不实现状态机执行、持久化、API、恢复、进度事件或任何生产接线。

---

## 1. IP-0006 消费者评审结论(lifecycle 入口 Gate,只读)

### 1.1 已验证事实(@ main `78aa9d8`,P&V 实证执行,2026-09-05)

- **基线复现**:contracts **252/252**、全量 **597 / 0 failed / 1 既有 skip**、`ruff check lima/contracts tests/contracts` exit 0;冻结面顶层 18 / evidence 16 / profile 15 / aep 12 / vep 12 / rvr 12 / 29 error codes;六 golden 字节数与 digest 与 Ledger 记录一致(evidence 3740B/`1b313f8c…`、profile 2152B/`ad7d53a0…`、aep 4235B/`f0a98543…`、vep 2091B/`cd76622b…`、rvr 1709B/`a9a35d35…`、envelope 838B);
- **rvr consumer review(Assignment §7-1,焦点)**:`VepReference` 三元组 + `_require_lineage_provenance` 的双向核对(schema_name 字面量 `"lima.vulnerability-evidence-package"`、`schema_version` 相等、`content_digest` 经 `hmac.compare_digest`)构成完整的"本地值类型 + Envelope lineage"引用模式;`CandidateVerification` 的 per-candidate verdict/patch/gate 结构使每个 RVR artifact 可被 workflow 层以三元组 + lineage 精确钉死地引用;RVR 无整体 verdict 字段(设计性缺席),因此 workflow 层**不得也不需要**从 RVR 派生整体裁决——引用其 per-candidate 事实即可;
- **五模块适用面核对(Assignment §7-2)**:
  - evidence(D0–D4 静态侧):`EvidenceSubjectKind` 词表(signal/security_issue/vulnerability_hypothesis)无 workflow/stage 主体;AEP 已内嵌完整 `EvidenceDomainBundle`;workflow 层对 evidence 的引用一律经 AEP 间接发生,**无需 import evidence**(实证成立;禁改 evidence.py);
  - profile(pre-audit):`REPOSITORY_PROFILE_SCHEMA_NAME = "lima.repository-profile"` 字面量可用作类型化 lineage 校验;AEP 的 `repository_profile_artifact_ids`(id-list + lineage schema 核对)与 VEP/RVR 的三元组是两级引用强度先例;本 Packet 采用三元组(强形式,见 §1.2-6);
  - aep(audit 终态+revision):`package_status`(draft|sealed)、`audit_outcome`(completed|incomplete|no_actionable_hypothesis|no_supported_attack_surface)、`revision` int ≥1(跨 artifact 单调性留 Registry——本 Packet 沿用该留白先例);audit 阶段尝试的输出引用 AEP artifact 即可,终态语义不重编码;
  - vep(mining 终态+oracle):`verification_verdict`(candidate|inconclusive|refuted_scope|verified)、`AepReference` 三元组 + `source_aep_revision`(消费侧携带上游 revision 的先例);mining 阶段尝试输出引用 VEP artifact;
  - rvr(repair 终态):per-candidate `CandidateVerdict`(verified_patch|rejected|inconclusive);repair 阶段尝试输出引用 RVR artifact;
- **确认:workflow.py 无需 import 任何领域模块**。五个领域 artifact 的全部身份事实(kind 字面量、artifact_id、content_digest、schema_version)都可通过本地值类型 + Envelope lineage 表达;verdict 内容不可从引用解析——同 AEP sealed / VEP 源约束先例,属 Registry/消费侧规则(单解);
- **Envelope 身份位已预留**:`ArtifactEnvelope` 的 `workflow_id` 与 `stage_attempt_id` 是 IP-0001 冻结的必填 identifier 字段(每个 artifact 均携带);三 schema 与 Envelope 的身份对齐规则见 §14.1(单解,无需修改 common.py)。

**结论:不存在阻塞 IP-0007 的 Contract Gap。** IP-0006 满足其 IP-DONE 的消费者评审入口条件;六个模块在 IP-0007 消费视角下均无需修改。

### 1.2 本 Packet 的兼容决策(冻结)

延续 IP-0002..0006 既定模式(适用部分),并针对三 schema 扩展:

1. 只新增 `lima/contracts/workflow.py`,不修改 `lima/contracts/__init__.py`;公共 API 只从 `lima.contracts.workflow` 导入;
2. **依赖方向冻结:`workflow.py → {codec, common, errors}`,不 import evidence/aep/vep/profile/rvr**——五个领域 artifact 的引用一律经本地 `ArtifactLink` 值类型(kind 字面量枚举 + artifact_id + content_digest + schema_version 三元组)+ Envelope lineage 双重表达(vep 的 `AepReference`、rvr 的 `VepReference` 同构先例的统一推广);identifier/digest 校验器本地实现(与 aep/vep/rvr 先例逐条等同);
3. 复用现有 **29** 个 `ContractErrorCode`,不扩展 `errors.py`;
4. 复用 `ArtifactEnvelope` / `decode_envelope` / `encode_envelope`;仅 inline payload;
5. schema 版本 `4.0`;未知 major fail closed;同 major 未来 minor 经各对象 `extensions` 无损 round-trip;unknown enum / required 缺失永不降级;
6. 三个 schema 各自独立成 Envelope artifact(见 DR-IP0007-DESIGN-01):`lima.workflow`、`lima.stage-attempt`、`lima.security-outcome`;
7. classification 禁 `public`;retention 禁 `ephemeral`(三 schema 同 aep/vep/rvr 的 `_require_protected_envelope` 先例——workflow 编排名与安全结论属租户敏感内容);
8. **三 schema 均无任何自由文本字段**(见 DR-IP0007-DESIGN-06):解释性内容一律由被引用 artifact 的既有字段(detail/coverage_gaps/summary)承载;workflow 层不产生第二份可被误读为安全断言的散文;
9. **词表分区是 NFR-01 的结构性表达**:`AttemptStatus`/`FailureKind`(执行事实)与 `SecurityOutcomeKind`(安全结论)三词表两两不相交且无 safe/clear/not_vulnerable 值;`SecurityOutcomeKind` 内部再分区为 CONCLUSION(7)/NON_CONCLUSION(5),非结论类(kind ∈ {mining_skipped_by_request, mining_skipped_by_policy, mining_blocked_environment, repair_blocked_environment, full_chain_incomplete})永不要求 vep/rvr 级结论证据(见 §14.3 矩阵);
10. **retry 语义 = 新 StageAttempt artifact**:attempt 不可变,重试以更高 `attempt_number` 的新 artifact 表达;跨 artifact 的 (workflow_id, stage_type, attempt_number) 唯一性与单调性留 Registry(DR-IP0007-DESIGN-07,aep revision 先例);
11. 时间/lease/资源账本不入 payload(DR-IP0007-DESIGN-04):emission 时间 = Envelope `created_at`(IP-0001 唯一时间先例;vep ReproductionRun 无时间戳同构);start/end/lease/budget 属 #90 runtime stage record 与 aep.budget。

---

## 2. Design Input Manifest

| Input ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001 | Standard | 稳定开发标准(§8/§17/§12/§16) | main `78aa9d8` | 三 Agent 分工、安全不变量、验证底线 | normative | 最高优先级之一 |
| DI-002 | Standard | lifecycle | main `78aa9d8` | §9.1 拓扑、§12 PR 契约、传输点只推分支 | normative | — |
| DI-003 | Charter | P&V 责任书 | main `78aa9d8` | Packet 必答、冻结纪律、DIM 格式 | normative | — |
| DI-004 | Issue(Assignment) | PKT-IP-0007 Coordinator Assignment | Ledger v20 派发 @ 2026-09-05 | 覆盖/不覆盖、§5 三 schema 责任边界、§10 十一问、四项强制 Checklist | normative | — |
| DI-005 | Issue | #58 正文 | 修订 `2026-09-01T14:36:22Z` | V5-FR-01 三 schema 子集、FR-02/05/06、NFR-01/02、AC-04、V5-AC-02 | normative | V5 节优先 |
| DI-006 | Issue(Ledger) | #58 Delivery Ledger v20 | `2026-09-05T03:40:14Z` | 激活依据、定序终审、四项 Checklist 登记、基线数字 | normative(current) | — |
| DI-007 | Decision | 五份 DR 正本(#58 评论 5505168221/5506328396/5510460665/5513783045/5525937000) | 2026-09-02..03 | 重冻结先例、实例化镜像/helper 忠实性预检裁定 | normative | — |
| DI-008 | Upstream IP | IP-0001..0006 Packets + 各 merge | #97..#113 | codec/Envelope/29 codes;AepReference/VepReference 三元组先例;六态先例;revision 留白先例;排序确定性 wire | normative | — |
| DI-009 | Architecture | V5 规划文档(#58 指定 Source of truth) | 本地工作树副本 | §4.1 mode 四值、§4.2 状态机与 stage 七态、§4.3 三维终态与 12 安全终态、§4.4 Gate 规则、§5.2 Artifact 清单、§13.1 FR-N01-01(消费面) | normative(经 #58 V5 覆盖层转正) | 与 #58 正文冲突以 #58 为准 |
| DI-010 | Code | `lima/contracts/{common,codec,errors,evidence,profile,aep,vep,rvr}.py` | main `78aa9d8` | §1 consumer review 实证;validator 风格;Envelope workflow_id/stage_attempt_id 必填事实 | current-behavior | 代码事实让位于 Packet 目标行为 |
| DI-011 | Test | `tests/contracts/` 全部 19 文件 | main `78aa9d8` | 测试风格、252 基线、golden 测试模式 | current-behavior | — |
| DI-012 | Evidence | 本 IP 基线复现(§1.1)+ golden 预计算脚本 | 2026-09-05,worktree `LIMA-ip-0007-pkt-wt` | 252/597/ruff/冻结面/六 golden digest;四新 golden bytes/digest | evidence | — |
| DI-013 | Issue | #90 正文(V5-N01 Workflow Runtime) | `.pv_tmp/issue*_body.md` 镜像 | runtime 消费面边界(background) | background-only | 不从 #90 扩大范围 |
| DI-014 | Issue | #68 正文(V5-N02 集成) | 同上 | FULL_CHAIN 生产集成、AUDIT_ONLY_LEGACY 映射位置(background) | background-only | — |
| DI-015 | Evidence | PV_CONTEXT_HANDOFF_IP-0007_2026-09-05.md | 根工作树 untracked | 离场 P&V 的 §4/§5 研究结论作为起步输入(本 Packet 已独立重证) | evidence | 以远端事实为准 |

### Explicitly Rejected Inputs

| 材料 | 拒绝原因 |
|---|---|
| #90 runtime 的状态机执行/持久化/API/恢复/进度/lease/policy evaluator 设计 | #90 实现职责;本 Packet 只冻结 schema 词汇表与单 Artifact 不变量 |
| Plan/RunManifest/Summary/Failure 四 schema 的任何完整定义 | IP-0008 候选;Assignment §3 明令禁止;本 Packet 仅允许 FailureKind 最小枚举占位(DR-IP0007-DESIGN-02) |
| `AUDIT_ONLY_LEGACY` 作为 schema 枚举值 | 旧 `repository_scan` API 的兼容期映射(#68/V5-N02 生产层),非 Artifact schema 词汇 |
| StageAttempt 携带 started_at/ended_at/lease/资源账本 | Assignment §5 四要素边界;envelope `created_at` 是唯一时间先例;budget 属 aep 与 runtime(DR-IP0007-DESIGN-04) |
| SecurityOutcome 镜像 artifact verdict 的断言字段(如 `source_vep_verdict`) | 引用不可解析 payload,镜像字段制造虚假保证(vep/rvr Packet 同项拒绝先例) |
| SecurityOutcome/Workflow 的自由文本 detail/summary 字段 | 散文安全结论风险;解释内容由被引用 artifact 既有字段承载(DR-IP0007-DESIGN-06) |
| WorkflowSummary 的字段(stage outcomes/cost/gaps)并入 Workflow | WorkflowSummary 是 IP-0008 候选 artifact(V5 §5.2);混入即范围上移 |
| 未冻结 schema(snapshot manifest/patch/candidate/gate-log)进入引用词表 | fail-closed 最小词表原则;由 IP-0008 扩展(DR-IP0007-DESIGN-03) |
| float confidence/severity、boolean is_safe/vulnerability_resolved 类旁路 | 违反 NFR-01 与无 float 契约;kind 词表是唯一结论机制 |
| V4 backlog 文档与未引用的本地规划文档、`28 error codes`/`aep 13 symbols` 笔误口径 | 历次 Packet 已登记拒绝;权威值 29/12 |

---

## 3. Iteration Hypothesis 与 Measurement

### 3.1 Hypothesis

如果跨阶段编排的真值被冻结为三个确定性 schema——Workflow 只声明身份/模式/状态/已发生尝试的引用,StageAttempt 只记录阶段类型/尝试身份/输入输出 artifact 引用/结束执行状态(永不编码安全结论),SecurityOutcome 只以分了区的 kind 词表 + 强制证据引用表达终态安全结论(blocked/skipped/incomplete 类永不携带结论语义,verified 类无对应 artifact 引用即非法)——那么"基础设施失败被读成安全""没有证据的 verified""workflow 层重复裁决 artifact 终态"这类编排阶段真值事故在契约层就没有合法表达。

### 3.2 Measurement

- 四个固定 golden(370/1498/460/589 bytes)生成固定 canonical bytes 与 SHA-256(§17),其引用链全部由 IP-0001 codec 对上游 golden 实算得出(证据链连续);
- 全部 12 个 SecurityOutcomeKind 的 required/forbidden 证据矩阵、7 个 AttemptStatus 的 skip/failure/输出耦合、AUDIT_ONLY 模式排除、revision/supersedes 耦合的非法组合全部 fail closed;
- 三词表(AttemptStatus/FailureKind/SecurityOutcomeKind)两两不相交且无 safe/clear/not_vulnerable 子串——机器断言(V5-AC-02);
- 新模块导入不加载 DB/网络/Docker/LLM/service/legacy models/evidence/aep/vep/profile/rvr;
- 既有 597 个测试无新增失败。

---

## 4. Goal

实现一个 stdlib-only、无副作用、确定性、可版本演化的 `lima.contracts.workflow` 叶子模块,包含:

1. 枚举:`WorkflowMode`(4)、`WorkflowStatus`(16)、`StageType`(5)、`ArtifactKind`(6)、`AttemptStatus`(7)、`SkipReason`(2)、`FailureKind`(6)、`SecurityOutcomeKind`(12);
2. `ArtifactLink`(kind 字面量 + 三元组的统一本地引用值类型)、`Workflow`、`StageAttempt`、`SecurityOutcome`;
3. 三 schema 各自的 payload decode/encode 与 Envelope binding(共 12 个函数);
4. 四个 golden fixture、负向边界测试、import isolation 与 legacy regression。

---

## 5. Non-goals

本次明确不做(全部见 §1.2、Rejected Inputs 与 DR-IP0007-DESIGN-*,不重复展开):#90 runtime 任何实现、Plan/RunManifest/Summary/Failure 完整 schema、manifests、场景 fixtures、legacy 适配、closure 集成、生产接线、LLM/网络/IO、时间戳/lease/资源账本字段、自由文本字段、confidence/severity/漏洞状态旁路、修改八个既有契约模块或任何既有测试、IP-0008。

---

## 6. 工作树与分支前置条件

Coding Agent 必须:完整阅读稳定标准、lifecycle、Implementation Agent 责任书、本 Packet、`LIMA_Coding_Agent_IP-0007_正式开发任务交接.md`、`CONTRIBUTING.md`;确认两份 IP-0007 文档均已合并到 `origin/main`;依 lifecycle §9.1 从 Frozen Test Commit(阶段二交付物指定 SHA)派生 `codex/ip-0007-workflow-spine-schemas` 独立干净 worktree(禁用共享根工作树与任何既有 worktree);确认 `lima/contracts/workflow.py` 与 3 个测试文件、4 个 fixture 尚不存在;输出 Scope Confirmation 后再运行 baseline;不一致时停止提交 Decision Request。根工作树未跟踪文件属用户资产,不得触碰。

---

## 7. 文件边界

### 7.1 Files to Add(恰好 8 个)

```text
lima/contracts/workflow.py
tests/contracts/test_workflow.py
tests/contracts/test_workflow_envelope.py
tests/contracts/test_workflow_import_isolation.py
tests/contracts/fixtures/workflow_v4_golden.json
tests/contracts/fixtures/stage_attempt_v4_golden.json
tests/contracts/fixtures/stage_attempt_alternates_v4_golden.json
tests/contracts/fixtures/security_outcome_v4_golden.json
```

### 7.2 Files Allowed to Modify

```text
none
```

### 7.3 Files Forbidden

除上述 8 个新增文件外全部禁止修改,特别包括:`lima/contracts/{__init__,errors,codec,common,evidence,profile,aep,vep,rvr}.py`;IP-0001..0006 的任何测试或 fixture;legacy/生产层;frontend/、requirements*.txt、pyproject.toml、.github/、PROGRESS.md;任意范围外文档。

### 7.4 Ownership 与冲突边界

`workflow.py` 唯一 Owner;后续 IP 不得在本 Packet 合并前创建同名 symbol(27 个);新公共 symbol 不从 `lima.contracts` 顶层重导出;依赖方向固定 `workflow.py → {codec,common,errors}`,其余 lima 模块不得 import workflow(直至消费 IP 冻结其入口)。

---

## 8. Allowed / Forbidden Dependencies

`workflow.py` 只允许导入:

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

测试只允许额外使用 stdlib:`hashlib`、`json`、`pathlib`、`subprocess`、`sys`、`unittest`。Forbidden:任何第三方包;`lima.contracts.{evidence,aep,vep,profile,rvr}` 与 `lima.models` 及生产层;HTTP/socket/DB/Docker/subprocess(产品)/文件系统(产品);UUID/时间/随机/环境变量;绝对路径。

---

## 9. 冻结的公共 Symbols

`lima/contracts/workflow.py` 的 `__all__` 必须严格等于以下集合,不多不少(**27** 项;本清单已逐项点数,与声明一致——强制 Checklist 第 3 条):

```python
__all__ = [
    "WORKFLOW_SCHEMA_NAME",
    "STAGE_ATTEMPT_SCHEMA_NAME",
    "SECURITY_OUTCOME_SCHEMA_NAME",
    "WorkflowMode",
    "WorkflowStatus",
    "StageType",
    "ArtifactKind",
    "AttemptStatus",
    "SkipReason",
    "FailureKind",
    "SecurityOutcomeKind",
    "ArtifactLink",
    "Workflow",
    "StageAttempt",
    "SecurityOutcome",
    "decode_workflow_payload",
    "encode_workflow_payload",
    "decode_workflow_envelope",
    "encode_workflow_envelope",
    "decode_stage_attempt_payload",
    "encode_stage_attempt_payload",
    "decode_stage_attempt_envelope",
    "encode_stage_attempt_envelope",
    "decode_security_outcome_payload",
    "encode_security_outcome_payload",
    "decode_security_outcome_envelope",
    "encode_security_outcome_envelope",
]
```

计数:3 常量 + 8 枚举 + 4 dataclass + 12 函数 = **27**。

模块常量:

```python
WORKFLOW_SCHEMA_NAME = "lima.workflow"
STAGE_ATTEMPT_SCHEMA_NAME = "lima.stage-attempt"
SECURITY_OUTCOME_SCHEMA_NAME = "lima.security-outcome"
```

---

## 10. 冻结枚举

所有枚举使用 `class X(str, Enum)`(允许 `# noqa: UP042`),wire value 严格固定(全部小写 snake,延续六模块 wire 惯例;V5 §4 草图的大写名仅是方向示意):

```python
class WorkflowMode(str, Enum):
    FULL_CHAIN = "full_chain"
    AUDIT_ONLY = "audit_only"
    VERIFY_VEP = "verify_vep"
    REPAIR_FROM_VEP = "repair_from_vep"

class WorkflowStatus(str, Enum):
    ACCEPTED = "accepted"
    CLASSIFYING = "classifying"
    MATERIALIZING = "materializing"
    AUDITING = "auditing"
    AUDIT_ADJUDICATING = "audit_adjudicating"
    AUDIT_GATE = "audit_gate"
    MINING_PLANNING = "mining_planning"
    MINING_ENV_PREPARING = "mining_env_preparing"
    MINING_RUNNING = "mining_running"
    MINING_ADJUDICATING = "mining_adjudicating"
    REPAIR_GATE = "repair_gate"
    REPAIR_PLANNING = "repair_planning"
    REPAIR_CANDIDATE_GENERATION = "repair_candidate_generation"
    REPAIR_VERIFYING = "repair_verifying"
    SUMMARIZING = "summarizing"
    TERMINAL = "terminal"

class StageType(str, Enum):
    PROFILE = "profile"
    AUDIT = "audit"
    MINE = "mine"
    REPAIR = "repair"
    SUMMARIZE = "summarize"

class ArtifactKind(str, Enum):
    REPOSITORY_PROFILE = "lima.repository-profile"
    AUDIT_EVIDENCE_PACKAGE = "lima.audit-evidence-package"
    VULNERABILITY_EVIDENCE_PACKAGE = "lima.vulnerability-evidence-package"
    REPAIR_VERIFICATION_REPORT = "lima.repair-verification-report"
    WORKFLOW = "lima.workflow"
    STAGE_ATTEMPT = "lima.stage-attempt"

class AttemptStatus(str, Enum):
    NOT_STARTED = "not_started"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    SKIPPED = "skipped"
    BLOCKED = "blocked"
    FAILED = "failed"
    CANCELLED = "cancelled"

class SkipReason(str, Enum):
    BY_REQUEST = "by_request"
    BY_POLICY = "by_policy"

class FailureKind(str, Enum):
    ENVIRONMENT = "environment"
    TOOL_ERROR = "tool_error"
    TIMEOUT = "timeout"
    OUT_OF_MEMORY = "out_of_memory"
    POLICY_DENIED = "policy_denied"
    INTERNAL = "internal"

class SecurityOutcomeKind(str, Enum):
    NO_SUPPORTED_ATTACK_SURFACE = "no_supported_attack_surface"
    NO_ACTIONABLE_HYPOTHESIS = "no_actionable_hypothesis"
    MINING_SKIPPED_BY_REQUEST = "mining_skipped_by_request"
    MINING_SKIPPED_BY_POLICY = "mining_skipped_by_policy"
    MINING_BLOCKED_ENVIRONMENT = "mining_blocked_environment"
    HYPOTHESIS_NOT_REPRODUCED = "hypothesis_not_reproduced"
    VULNERABILITY_VERIFIED = "vulnerability_verified"
    REPAIR_UNSUPPORTED = "repair_unsupported"
    REPAIR_BLOCKED_ENVIRONMENT = "repair_blocked_environment"
    NO_CANDIDATE_PASSED = "no_candidate_passed"
    VERIFIED_PATCH = "verified_patch"
    FULL_CHAIN_INCOMPLETE = "full_chain_incomplete"
```

语义冻结:

- `WorkflowMode`:V5 §4.1 四模式原样;`AUDIT_ONLY_LEGACY` 是旧 API 兼容映射(#68),**不是** schema 值;
- `WorkflowStatus`:V5 §4.2 十六状态原样;唯一终态 `terminal`;转移序列合法性/policy 属 #90(逐条豁免见 §14.2);唯一冻结的模式耦合 = AUDIT_ONLY 排除八个 mining/repair 执行态(DR-IP0007-DESIGN-05);
- `StageType`:五阶段 = 冻结证据链的五个人工产物承载者(profile/aep/vep/rvr + summarize);snapshot 物化阶段不设(DR-IP0007-DESIGN-03,manifest 未冻结);
- `ArtifactKind`:wire value 即 schema_name 字面量(自描述;lineage 校验零映射表);
- `AttemptStatus`:V5 §4.2 stage 七态原样;blocked/failed/cancelled 是执行事实,**永不**进入 SecurityOutcomeKind 词表(词表 disjoint 机器断言);
- `SkipReason`:SKIPPED 的二因(by_request = AUDIT_ONLY/用户显式;by_policy = policy evaluator);
- `FailureKind`:NFR-01 点名的失败类别最小枚举占位(timeout/OOM/tool_error 字面在内;DR-IP0007-DESIGN-02);
- `SecurityOutcomeKind`:V5 §4.3 十二首期安全终态原样;分区 CONCLUSION(7)/NON_CONCLUSION(5)见 §14.3;词表无 safe/clear/not_vulnerable。

---

## 11. Exact Constructors and Defaults

全部领域对象 `@dataclass(frozen=True, slots=True)`,defensive-copy;required 字段在前:

### 11.1 `ArtifactLink`

```python
ArtifactLink(
    kind: ArtifactKind,
    artifact_id: str,
    content_digest: str,
    schema_version: SchemaVersion,
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

### 11.2 `Workflow`

```python
Workflow(
    schema_version: SchemaVersion,
    workflow_id: str,
    workflow_mode: WorkflowMode,
    status: WorkflowStatus,
    revision: int,
    stage_attempts: tuple[ArtifactLink, ...] = (),
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

### 11.3 `StageAttempt`

```python
StageAttempt(
    schema_version: SchemaVersion,
    workflow_id: str,
    stage_attempt_id: str,
    stage_type: StageType,
    attempt_number: int,
    status: AttemptStatus,
    inputs: tuple[ArtifactLink, ...] = (),
    outputs: tuple[ArtifactLink, ...] = (),
    skip_reason: SkipReason | None = None,
    failure_kind: FailureKind | None = None,
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

### 11.4 `SecurityOutcome`

```python
SecurityOutcome(
    schema_version: SchemaVersion,
    workflow_id: str,
    kind: SecurityOutcomeKind,
    workflow: ArtifactLink,
    evidence: tuple[ArtifactLink, ...] = (),
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

四个导出 dataclass 均提供 `from_dict(value, *, schema_version) -> Self` 与 `to_dict()`(Python 3.11/3.12 兼容注解);`from_dict` 执行 §14 全部跨字段校验;`decode_*_payload` 只是稳定公共入口。

---

## 12. Exact Wire Shapes

### 12.1 Workflow payload

4.0 的 required fields 恰好为以下 **5** 个(`stage_attempts` 可为空):

```json
{
  "workflow_id": "workflow-0001",
  "workflow_mode": "full_chain",
  "status": "audit_gate",
  "revision": 2,
  "stage_attempts": []
}
```

### 12.2 StageAttempt payload

required fields 恰好 **9** 个(`skip_reason`/`failure_kind` 必填出现、可为 `null`;数组可为空):

```json
{
  "workflow_id": "workflow-0001",
  "stage_attempt_id": "attempt-audit-0001",
  "stage_type": "audit",
  "attempt_number": 1,
  "status": "succeeded",
  "inputs": [],
  "outputs": [],
  "skip_reason": null,
  "failure_kind": null
}
```

### 12.3 SecurityOutcome payload

required fields 恰好 **4** 个(`evidence` 可为空;`workflow` 恰一):

```json
{
  "workflow_id": "workflow-0001",
  "kind": "full_chain_incomplete",
  "workflow": {"kind": "lima.workflow", "artifact_id": "wf-0001",
               "content_digest": "<64hex>", "schema_version": "4.0"},
  "evidence": []
}
```

### 12.4 `ArtifactLink`

```json
{"kind": "lima.repository-profile", "artifact_id": "profile-0001",
 "content_digest": "<64hex>", "schema_version": "4.0"}
```

### 12.5 Extensions

4.0:任何层级(顶层、link、三 schema)unknown field 以 `UNKNOWN_FIELD` 拒绝;未来 4.x 经对应对象 `extensions` 无损 round-trip;required 缺失与 unknown enum 即使未来 minor 也拒绝。

---

## 13. Scalar Validation

- `workflow_id`/`stage_attempt_id`/`artifact_id`:IP-0002 identifier 规则 `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`(NFC);
- `content_digest`:`[0-9a-f]{64}`;
- `schema_version`(link 内):IP-0001 `SchemaVersion.parse` 规则;
- `revision`/`attempt_number`:int(精确类型,拒 bool),1..9223372036854775807;
- enum 字段:非 str `INVALID_FIELD_TYPE`,未知值 `UNKNOWN_ENUM_VALUE`;error message 不回显原值;
- 本模块无 bounded-text 字段(§1.2-8);无 float(结构性禁)。

---

## 14. Array Limits,Canonical Ordering 与 Cross-field Invariants

### 14.1 Envelope 身份对齐(三 schema 共同)

- Workflow:`payload.workflow_id == envelope.workflow_id`,违反 → `INVALID_FIELD_VALUE $.workflow_id`;
- StageAttempt:`payload.workflow_id == envelope.workflow_id` **且** `payload.stage_attempt_id == envelope.stage_attempt_id`,违反 → 同码对应路径;
- SecurityOutcome:`payload.workflow_id == envelope.workflow_id`;
- IP-0001 已冻结的 Envelope 必填身份位(`workflow_id`/`stage_attempt_id`)因此获得 payload 侧镜像一致性;Workflow/SecurityOutcome 的 `envelope.stage_attempt_id` 是发射上下文元数据,不做 payload 耦合(单解:发射该记录的尝试身份,由 runtime 填写)。

### 14.2 数组上限、排序与跨字段不变量

| Array | 上限 | 允许空 | 排序规则 |
|---|---:|---:|---|
| Workflow `stage_attempts` | 256 | 是 | `artifact_id` ASCII 升序、唯一 |
| StageAttempt `inputs` | 64 | 是 | `artifact_id` ASCII 升序、唯一 |
| StageAttempt `outputs` | 64 | 是 | 同上 |
| SecurityOutcome `evidence` | 64 | 是 | 同上 |

**Workflow 不变量:**

- W1 `workflow_mode == audit_only` 时 `status` ∉ {mining_planning, mining_env_preparing, mining_running, mining_adjudicating, repair_gate, repair_planning, repair_candidate_generation, repair_verifying}(八值),违反 → `INVALID_FIELD_VALUE $.status`(唯一冻结的模式耦合;FULL_CHAIN 无限制;VERIFY_VEP/REPAIR_FROM_VEP 的状态集属 #90 policy——DR-IP0007-DESIGN-05 逐条豁免);
- W2 `revision` ∈ 1..INT64_MAX;`revision > 1` ⇔ `envelope.supersedes != None`(binding 阶段核对;`revision == 1` 且 supersedes 非 None → `INVALID_FIELD_VALUE $.supersedes`;`revision > 1` 且 supersedes 为 None → 同码);supersedes 目标须为 `lima.workflow`(supersedes.schema_name == WORKFLOW_SCHEMA_NAME,否则 `INVALID_FIELD_VALUE $.supersedes`);**跨 artifact revision 单调性留 Registry**(aep revision 先例,DR-IP0007-DESIGN-07);
- W3 `stage_attempts` 每 link `kind == ArtifactKind.STAGE_ATTEMPT`,违反 → `INVALID_FIELD_VALUE $.stage_attempts[i].kind`;排序/唯一/上限同表。

**StageAttempt 不变量:**

- S1 `skip_reason` required iff `status == skipped`(skipped 而无因 → `INVALID_FIELD_VALUE $.skip_reason`;非 skipped 而有因 → 同码);
- S2 `failure_kind` required iff `status ∈ {blocked, failed}`(有因禁 skip_reason 并存;其余状态禁 failure_kind);
- S3 `outputs` 非 `succeeded` 时必须为空(未完成不声明产出),违反 → `INVALID_FIELD_VALUE $.outputs`;
- S4 阶段词表矩阵(fail-closed;未知组合 → `INVALID_FIELD_VALUE`,路径指向对应 link):

| StageType | inputs 允许 kind | outputs 允许 kind | succeeded 最低要求 |
|---|---|---|---|
| profile | ∅(必须空) | repository-profile | 输出 ≥1 profile |
| audit | repository-profile | audit-evidence-package | 输入 ≥1 profile 且输出 ≥1 aep |
| mine | audit-evidence-package | vulnerability-evidence-package | 输入 ≥1 aep 且输出 ≥1 vep |
| repair | vulnerability-evidence-package | repair-verification-report | 输入 ≥1 vep 且输出 ≥1 rvr |
| summarize | 四领域 kind 任意 | ∅(必须空) | 无 |

(succeeded 最低要求与上游冻结耦合一致:aep 必含 ≥1 profile id、vep 必钉 aep、rvr 必钉 vep;summarize 产出 WorkflowSummary 属 IP-0008,故输出词表为空。)

- S5 `attempt_number` ≥1(重试 = 新 artifact,DR-IP0007-DESIGN-07)。

**SecurityOutcome 不变量:**

- O1 `workflow` link `kind == ArtifactKind.WORKFLOW` 恰一,违反 → `INVALID_FIELD_VALUE $.workflow.kind`;
- O2 `evidence` 每 link kind ∈ {REPOSITORY_PROFILE, AUDIT_EVIDENCE_PACKAGE, VULNERABILITY_EVIDENCE_PACKAGE, REPAIR_VERIFICATION_REPORT}(四领域 kind;workflow/stage-attempt 不得作为证据),违反 → `INVALID_FIELD_VALUE $.evidence[i].kind`;
- O3 kind → 证据矩阵(核心 NFR-01 机器断言;required 缺失或 forbidden 出现 → `INVALID_FIELD_VALUE`,路径 `$.kind` 或对应 link):

| kind | required | forbidden |
|---|---|---|
| no_supported_attack_surface | ≥1 aep | vep、rvr |
| no_actionable_hypothesis | ≥1 aep | vep、rvr |
| mining_skipped_by_request | ≥1 aep | vep、rvr |
| mining_skipped_by_policy | ≥1 aep | vep、rvr |
| mining_blocked_environment | ≥1 aep | vep、rvr |
| hypothesis_not_reproduced | ≥1 vep | rvr |
| vulnerability_verified | ≥1 vep | rvr |
| repair_unsupported | ≥1 vep | rvr |
| repair_blocked_environment | ≥1 vep | rvr |
| no_candidate_passed | ≥1 rvr | — |
| verified_patch | ≥1 rvr | — |
| full_chain_incomplete | — | — |

- O4 分区冻结(模块常量,测试断言):NON_CONCLUSION_KINDS = {mining_skipped_by_request, mining_skipped_by_policy, mining_blocked_environment, repair_blocked_environment, full_chain_incomplete};其余 7 个为 CONCLUSION;非结论 kind 的 required 集不含任何结论级 artifact(rvr 全禁、vep 仅 repair_blocked_environment 作为上游语境要求且该 kind 本身不重断言 vep verdict);`vulnerability_verified`/`verified_patch` 无对应 artifact 引用即非法(无证据不得宣称 verified——V5-AC-02 机器面);
- O5 词表 disjoint:AttemptStatus ∩ SecurityOutcomeKind = ∅、FailureKind ∩ SecurityOutcomeKind = ∅、三词表 wire value 均不含子串 `safe`/`clear`/`not_vulnerable`(测试机器断言,禁字段递归断言的例外:词表本身是设计机制,Assignment §10-8)。

### 14.3 明确豁免清单(留 Registry/runtime/消费侧;单解)

1. (workflow_id, stage_type, attempt_number) 跨 artifact 唯一性与 attempt_number 单调推进——Registry(aep revision 同构留白);
2. Workflow revision 链单调性、supersedes 目标确为 revision-1——Registry;
3. 状态转移序列合法性(§4.2 顺序)、AUDIT_ONLY 之外的 mode×status policy、Gate 阈值——#90 policy evaluator;
4. artifact verdict 一致性(VULNERABILITY_VERIFIED ⇒ 所引 VEP verdict==verified;VERIFIED_PATCH ⇒ 所引 RVR 含 verified_patch 候选;NO_CANDIDATE_PASSED ⇒ 全候选 rejected)——引用不可解析,Registry/消费侧(DR-IP0007-DESIGN-08);
5. sealed 性、lease/时间/资源账本——runtime;`summarize`/`verify` 类阶段的展开语义——IP-0008/#90。

### 14.4 Provenance(Envelope binding 阶段)

- 每个内嵌 `ArtifactLink`(Workflow.stage_attempts / StageAttempt.inputs+outputs / SecurityOutcome.workflow+evidence)必须存在 `envelope.lineage` 条目:`artifact_id` 匹配、`schema_name == link.kind 的字面量`、`schema_version` 相等、`content_digest` 经 `hmac.compare_digest` 相等;缺失/错 schema → `INVALID_FIELD_VALUE $.payload…`;digest 不符 → `DIGEST_MISMATCH`;
- lineage 允许额外条目;tenant/snapshot/self/duplicate/conflict 由 IP-0001 拒绝。

---

## 15. Envelope Binding Contract

### 15.1 Function signatures

```python
def decode_workflow_payload(value: Mapping[str, JSONValue], *, schema_version: SchemaVersion) -> Workflow: ...
def encode_workflow_payload(workflow: Workflow) -> dict[str, JSONValue]: ...
def decode_workflow_envelope(data: bytes, *, limits: ContractLimits = DEFAULT_LIMITS) -> tuple[ArtifactEnvelope, Workflow]: ...
def encode_workflow_envelope(envelope: ArtifactEnvelope, workflow: Workflow, *, limits: ContractLimits = DEFAULT_LIMITS) -> bytes: ...
# stage_attempt / security_outcome 两组签名同构,分别返回/接受 StageAttempt / SecurityOutcome
```

### 15.2 Binding rules

`decode_*_envelope` 必须:调用 `decode_envelope`;`schema_name` 等于对应常量;inline payload only;以 envelope `schema_version` decode 对象;§14.1 身份对齐;§14.2 各自不变量已于 from_dict 完成;§14.4 provenance(Workflow 另核对 W2 supersedes 耦合);classification != public;retention != ephemeral;返回 `(envelope, 对象)` 不修改输入。

`encode_*_envelope` 执行相同 binding 并额外:`envelope.schema_version == 对象.schema_version`;`envelope.payload == encode_*_payload(对象)`;`compute_content_digest` 与 `envelope.content_digest` 经 `hmac.compare_digest` 相等;最终 `encode_envelope`;不自动创建/修补 Envelope。

---

## 16. Stable Error Mapping and Precedence

复用现有 **29** 个 code;优先级(同 IP-0004/0005/0006 模式):

1. codec byte/UTF-8/JSON/resource;
2. top-level container/required/current unknown/schema version;
3. enum 与 scalar type;
4. scalar value/range、数组 limit/order/duplicate;
5. 内嵌对象逐层校验(link 字段错误按其自身路径);
6. 跨字段:W1 mode 耦合 → W2 revision/supersedes → S1-S4 状态耦合与词表矩阵 → O1-O3 kind 矩阵;
7. lineage provenance(全部内嵌 link 的类型化核对);
8. Envelope schema/payload/digest/classification/retention binding。

`field_path` 示例:

```text
$.stage_attempts[1].artifact_id
$.status
$.skip_reason
$.outputs[0].kind
$.evidence[2].content_digest
$.payload.workflow.kind
$.payload.inputs[0].content_digest
$.supersedes
```

---

## 17. Golden Fixture

四个文件(阶段二逐字节复制,含本文权威内容;禁止更改字段、值、顺序或摘要):

```text
tests/contracts/fixtures/stage_attempt_v4_golden.json          370 bytes
tests/contracts/fixtures/stage_attempt_alternates_v4_golden.json 1498 bytes
tests/contracts/fixtures/workflow_v4_golden.json               460 bytes
tests/contracts/fixtures/security_outcome_v4_golden.json       589 bytes
```

全部 bytes 与 digest 已由 IP-0001 codec 在 main `78aa9d8` 预计算冻结(worktree `LIMA-ip-0007-pkt-wt`,脚本 `.pv_tmp/IP-0007_PRECOMPUTE_golden.py`);引用链使用上游五 golden 的真实 digest(profile `ad7d53a0…`、aep `f0a98543…`、vep `cd76622b…`、rvr `a9a35d35…`)与本文档内实算的 stage-attempt 摘要,构成连续证据链。

### 17.1 `stage_attempt_v4_golden.json`(370 bytes)

SHA-256:`34746de4860ae5ce9ec69c43ad8c8ad596d4e79172a284bf3defc1a866edb259`

内容 = profile 尝试(succeeded,无输入,输出 = profile golden 真实 digest):

```json
{"attempt_number":1,"failure_kind":null,"inputs":[],"outputs":[{"artifact_id":"profile-0001","content_digest":"ad7d53a0ed22412dbbfc60d0ed9183d7e939e2d14e4eee2d9399944cb5c4dccc","kind":"lima.repository-profile","schema_version":"4.0"}],"skip_reason":null,"stage_attempt_id":"attempt-profile-0001","stage_type":"profile","status":"succeeded","workflow_id":"workflow-0001"}
```

### 17.2 `stage_attempt_alternates_v4_golden.json`(1498 bytes)

SHA-256:`01cf64fc7c63249abe52a95f2c9065d96ff24424332b8c2adb237c2af61cd416`

内容 = 四元素数组,覆盖混合状态(满足 Assignment §10-7 的"混合成功/失败/blocked"):audit succeeded(element digest `418c461a1d82fcc9cbf6b60d1caad21e76491abe2d4f4a0a3a1a178cb15e8fb4`,被 §17.3 workflow golden 引用)、mine blocked(failure_kind=environment)、repair failed(attempt_number=2,failure_kind=tool_error)、mine skipped(skip_reason=by_request):

```json
[{"attempt_number":1,"failure_kind":null,"inputs":[{"artifact_id":"profile-0001","content_digest":"ad7d53a0ed22412dbbfc60d0ed9183d7e939e2d14e4eee2d9399944cb5c4dccc","kind":"lima.repository-profile","schema_version":"4.0"}],"outputs":[{"artifact_id":"aep-0001","content_digest":"f0a985432ebd11dc4b85897653cf443dc2c0b0312e453424648ebc2d164705d0","kind":"lima.audit-evidence-package","schema_version":"4.0"}],"skip_reason":null,"stage_attempt_id":"attempt-audit-0001","stage_type":"audit","status":"succeeded","workflow_id":"workflow-0001"},{"attempt_number":1,"failure_kind":"environment","inputs":[{"artifact_id":"aep-0001","content_digest":"f0a985432ebd11dc4b85897653cf443dc2c0b0312e453424648ebc2d164705d0","kind":"lima.audit-evidence-package","schema_version":"4.0"}],"outputs":[],"skip_reason":null,"stage_attempt_id":"attempt-mine-0001","stage_type":"mine","status":"blocked","workflow_id":"workflow-0001"},{"attempt_number":2,"failure_kind":"tool_error","inputs":[{"artifact_id":"vep-0001","content_digest":"cd76622b48d11c0300e63d7489701479c75dc2f4b06cc6c4e88af1f453061d01","kind":"lima.vulnerability-evidence-package","schema_version":"4.0"}],"outputs":[],"skip_reason":null,"stage_attempt_id":"attempt-repair-0002","stage_type":"repair","status":"failed","workflow_id":"workflow-0001"},{"attempt_number":1,"failure_kind":null,"inputs":[],"outputs":[],"skip_reason":"by_request","stage_attempt_id":"attempt-mine-skip-0001","stage_type":"mine","status":"skipped","workflow_id":"workflow-0001"}]
```

### 17.3 `workflow_v4_golden.json`(460 bytes)

SHA-256:`3be59c6c7f1736954fbce5f1e74b4c7789ab8a1e956f4229904ea30bbe756146`

内容 = full_chain @ audit_gate、revision 2、两条 stage-attempt 引用(按 artifact_id 升序;digest 分别 = §17.2 audit element 实算摘要与 §17.1 golden 摘要——跨 Artifact 真实 digest 链):

```json
{"revision":2,"stage_attempts":[{"artifact_id":"attempt-audit-0001","content_digest":"418c461a1d82fcc9cbf6b60d1caad21e76491abe2d4f4a0a3a1a178cb15e8fb4","kind":"lima.stage-attempt","schema_version":"4.0"},{"artifact_id":"attempt-profile-0001","content_digest":"34746de4860ae5ce9ec69c43ad8c8ad596d4e79172a284bf3defc1a866edb259","kind":"lima.stage-attempt","schema_version":"4.0"}],"status":"audit_gate","workflow_id":"workflow-0001","workflow_mode":"full_chain"}
```

### 17.4 `security_outcome_v4_golden.json`(589 bytes)

SHA-256:`bfa0b2dc55940bcdadf88f8e4991adb4d762f7a8b17ded3fa8817936504ba831`

内容 = verified_patch(workflow link digest = §17.3 golden 摘要;evidence = rvr + vep golden 真实 digest,按 artifact_id 升序):

```json
{"evidence":[{"artifact_id":"rvr-0001","content_digest":"a9a35d358308a2957b9182d2ca5e503903d8c7282c6c43bb09d1680313cb2cac","kind":"lima.repair-verification-report","schema_version":"4.0"},{"artifact_id":"vep-0001","content_digest":"cd76622b48d11c0300e63d7489701479c75dc2f4b06cc6c4e88af1f453061d01","kind":"lima.vulnerability-evidence-package","schema_version":"4.0"}],"kind":"verified_patch","workflow":{"artifact_id":"wf-0001","content_digest":"3be59c6c7f1736954fbce5f1e74b4c7789ab8a1e956f4229904ea30bbe756146","kind":"lima.workflow","schema_version":"4.0"},"workflow_id":"workflow-0001"}
```

### 17.5 Frozen envelope vectors(三 schema 各一)

```text
[workflow] schema_name = lima.workflow / artifact_id = wf-0001
  tenant-1 / task-1 / workflow_id = workflow-0001 / stage_attempt_id = attempt-audit-0001
  snapshot "3"*64 / producer lima-orchestrator / created_at 2026-09-05T00:00:00Z
  policy "5"*64 / toolchain "6"*64 / classification internal / retention standard
  content_digest = 3be59c6c7f1736954fbce5f1e74b4c7789ab8a1e956f4229904ea30bbe756146
  lineage = [attempt-audit-0001 / lima.stage-attempt / 418c461a…, attempt-profile-0001 / lima.stage-attempt / 34746de4…]
  supersedes = wf-0000 / lima.workflow / "0"*64(revision 2 ⇒ 必须非空;W2)
  coverage_gaps = []

[stage_attempt] schema_name = lima.stage-attempt / artifact_id = attempt-profile-0001
  workflow_id = workflow-0001 / stage_attempt_id = attempt-profile-0001(双对齐)
  其余同上风格 / classification internal / retention standard
  content_digest = 34746de4860ae5ce9ec69c43ad8c8ad596d4e79172a284bf3defc1a866edb259
  lineage = [profile-0001 / lima.repository-profile / ad7d53a0…] / supersedes = null

[security_outcome] schema_name = lima.security-outcome / artifact_id = sec-0001
  workflow_id = workflow-0001 / stage_attempt_id = attempt-repair-0002(发射尝试)
  classification sensitive / retention audit
  content_digest = bfa0b2dc55940bcdadf88f8e4991adb4d762f7a8b17ded3fa8817936504ba831
  lineage = [wf-0001 / lima.workflow / 3be59c6c…, vep-0001 / lima.vulnerability-evidence-package / cd76622b…,
             rvr-0001 / lima.repair-verification-report / a9a35d35…] / supersedes = null
```

---

## 18. Required Tests

测试使用 `unittest`,方法名冻结如下;可增加 helper 与更细测试,不得减少、重命名或合并。

### 18.1 `tests/contracts/test_workflow.py`(44)

```text
WorkflowEnumTests
  test_wire_values_are_exact

ArtifactLinkTests
  test_round_trip_has_exact_wire_shape
  test_rejects_missing_invalid_and_mismatched_fields

WorkflowTests
  test_minimal_empty_workflow_round_trip_is_valid
  test_golden_workflow_round_trip_and_digest
  test_rejects_wrong_container_and_missing_required_fields
  test_rejects_unknown_enum_and_wrong_field_type
  test_rejects_unsorted_duplicate_and_oversize_stage_attempts
  test_rejects_non_stage_attempt_link_kinds
  test_rejects_audit_only_mode_with_mining_or_repair_status
  test_rejects_invalid_revision
  test_future_minor_round_trips_unknown_fields_at_every_level
  test_current_minor_rejects_unknown_fields_at_every_level
  test_defensive_copy_prevents_post_construction_mutation
  test_payload_has_no_confidence_severity_or_verdict_bypass_fields

StageAttemptTests
  test_minimal_not_started_attempt_round_trip_is_valid
  test_golden_stage_attempt_round_trip_and_digest
  test_alternates_golden_round_trip_and_digest
  test_rejects_wrong_container_and_missing_required_fields
  test_rejects_unknown_enum_and_wrong_field_type
  test_rejects_invalid_workflow_and_attempt_identifiers
  test_rejects_attempt_number_out_of_range
  test_succeeded_stage_type_requires_input_and_output_kinds
  test_rejects_inputs_outside_stage_vocabulary
  test_rejects_outputs_outside_stage_vocabulary_or_non_empty_when_not_succeeded
  test_skip_reason_required_iff_skipped
  test_failure_kind_required_iff_blocked_or_failed
  test_rejects_unsorted_duplicate_and_oversize_references
  test_future_minor_round_trips_unknown_fields_at_every_level
  test_current_minor_rejects_unknown_fields_at_every_level
  test_defensive_copy_prevents_post_construction_mutation

SecurityOutcomeTests
  test_minimal_full_chain_incomplete_outcome_round_trip_is_valid
  test_golden_security_outcome_round_trip_and_digest
  test_rejects_wrong_container_and_missing_required_fields
  test_rejects_unknown_enum_and_wrong_field_type
  test_workflow_link_kind_is_required_and_exact
  test_kind_evidence_matrix_required_and_forbidden_sets
  test_conclusion_kinds_require_their_evidence_kinds
  test_outcome_vocabulary_never_encodes_failure_as_safety
  test_rejects_unsorted_duplicate_and_oversize_evidence
  test_future_minor_round_trips_unknown_fields_at_every_level
  test_current_minor_rejects_unknown_fields_at_every_level
  test_defensive_copy_prevents_post_construction_mutation
  test_payload_has_no_confidence_severity_or_verdict_bypass_fields
```

`test_outcome_vocabulary_never_encodes_failure_as_safety` 必须断言:AttemptStatus/FailureKind/SecurityOutcomeKind 三词表两两不相交;三词表任意 wire value 不含子串 `safe`/`clear`/`not_vulnerable`;NON_CONCLUSION 五成员恰为 §14.2-O4 集合且与 CONCLUSION 不相交;blocked/failed/cancelled 仅存在于 AttemptStatus。

`test_payload_has_no_confidence_severity_or_verdict_bypass_fields`(两处)递归断言 golden 与 minimal payload 任意层级不出现键:`confidence`、`severity`、`risk_score`、`is_safe`、`vulnerability_resolved`、`safe`、`clear`。

### 18.2 `tests/contracts/test_workflow_envelope.py`(23)

```text
WorkflowEnvelopeTests
  test_frozen_envelope_encode_decode_is_byte_stable
  test_rejects_wrong_schema_name_and_version_mismatch
  test_rejects_payload_workflow_id_mismatch_with_envelope
  test_rejects_blob_backed_workflow
  test_revision_supersedes_coupling_enforced
  test_rejects_missing_or_mistyped_stage_attempt_lineage
  test_allows_additional_valid_lineage
  test_rejects_public_classification_and_ephemeral_retention

StageAttemptEnvelopeTests
  test_frozen_envelope_encode_decode_is_byte_stable
  test_rejects_wrong_schema_name_and_version_mismatch
  test_rejects_payload_identity_mismatch_with_envelope
  test_rejects_blob_backed_stage_attempt
  test_rejects_missing_or_mistyped_input_output_lineage
  test_inherits_cross_tenant_cross_snapshot_and_self_reference_rejection
  test_rejects_public_classification_and_ephemeral_retention
  test_tampered_payload_fails_before_domain_promotion

SecurityOutcomeEnvelopeTests
  test_frozen_envelope_encode_decode_is_byte_stable
  test_rejects_wrong_schema_name_and_version_mismatch
  test_rejects_payload_workflow_id_mismatch_with_envelope
  test_rejects_blob_backed_security_outcome
  test_rejects_missing_or_mistyped_workflow_and_evidence_lineage
  test_rejects_public_classification_and_ephemeral_retention
  test_tampered_payload_fails_before_domain_promotion
```

### 18.3 `tests/contracts/test_workflow_import_isolation.py`(4)

```text
WorkflowImportIsolationTests
  test_module_public_api_matches_frozen_symbol_set
  test_clean_process_import_has_no_db_network_docker_llm_service_or_legacy_models
  test_module_only_uses_allowed_imports
  test_import_does_not_change_lima_contracts_top_level_public_api
```

`test_clean_process_import…` 必须断言:干净子进程导入 `lima.contracts.workflow` 后,`evidence`/`aep`/`vep`/`profile`/`rvr` 与其余 forbidden roots **均不在** `sys.modules`(依赖方向断言与 IP-0006 相同模式)。

### 18.4 Minimum count

IP-0007 必须新增至少 **71** 个独立 test methods(44+23+4)。

---

## 19. Acceptance Criteria and Traceability

| AC | Required behavior | Evidence(test) | 覆盖的 Issue requirement |
|---|---|---|---|
| WS-AC-01 | 27 个 module public symbols、8 个 enum wire vocabulary(4/16/5/6/7/2/6/12)、4 个导出 constructors 冻结 | enum/object/import tests | FR-02(三 schema 版本化定义)、V5-FR-01 |
| WS-AC-02 | identifier/digest/int range/数组上限与排序 fail closed | 各对象 negative tests | NFR-02 |
| WS-AC-03 | 四 golden(370/1498/460/589 bytes、固定 digest、byte-stable);引用链 = 上游 golden 真实 digest | golden tests | FR-05、AC-01 方法论 |
| WS-AC-04 | Envelope 身份对齐(workflow_id/stage_attempt_id 镜像)与 revision⇔supersedes 耦合 | envelope tests | FR-02、NFR-01 |
| WS-AC-05 | StageType×inputs/outputs 词表矩阵 + succeeded 最低要求 fail closed | 词表 tests | V5-FR-01、FR-02 |
| WS-AC-06 | skip/failure required-iff 耦合;非 succeeded 禁 outputs | 状态耦合 tests | NFR-01、V5-AC-02 |
| WS-AC-07 | SecurityOutcome kind→证据矩阵(required/forbidden);无证据不得 verified;词表分区 + 三词表 disjoint + 无 safe/clear 子串 | 矩阵 + vocabulary tests | NFR-01、V5-AC-02(T-02) |
| WS-AC-08 | AUDIT_ONLY 排除八个 mining/repair 状态 | mode 耦合 test | V5 §4.1(AUDIT_ONLY 语义) |
| WS-AC-09 | 全部内嵌 link 的类型化 lineage 核对;classification/retention 保护 | envelope tests | FR-02、NFR-01 |
| WS-AC-10 | 4.0 unknown field 拒绝(每层级);未来 4.x 无损 round-trip;unknown enum 永远拒绝 | compatibility tests | FR-06 |
| WS-AC-11 | stdlib leaf;workflow→{codec,common,errors};不加载五领域模块;冻结面不变 | import isolation + git diff | AC-04(T-04) |
| WS-AC-12 | 8 added / 0 modified / 0 deps / 全量回归无新增失败 | file boundary + full regression | AC-04 |

---

## 20. 强制实现顺序(含一致性预检,四项强制 Checklist)

阶段二由 P&V 执行 **1-6**,Implementation Agent 从第 7 步开始:

1. **冻结前一致性预检**:脚本独立实现 §14 全部跨字段规则,校验四 golden 实文件 + 每个计划 arrange;**构造器用例的 arrange 必须做"实例化镜像"验证**(构造器参数须为领域对象实例而非 wire dict——DR-IP-0005-IMPL-01 裁定);**负向用例的 arrange 须经 helper 后仍为预期非法形态**(helper 忠实性:helper 不得含静默规范化、`**overrides` 转发须逐键演练——DR-IP-0006-IMPL-01 两类根因的封堵,Checklist 第 4 条);预检脚本与结果记入 RED Evidence Record;
2. 编写 3 个测试文件 + 4 个 fixture(逐字节复制 §17 权威内容);
3. 测试自身质量门禁(compileall/ruff;I001 须 stub 复证);
4. 证明有效 RED(预期失败全部归因 `lima.contracts.workflow` 不存在);
5. 创建 Frozen Test Commit + digest + 数量,**只推送分支,严禁开 PR**(Checklist 第 2 条);
6. Coordinator 出具 Implementation Assignment;
7. Implementation Agent:枚举/本地校验器/ArtifactLink → Workflow/StageAttempt(§14.2-W/S 全部校验)→ SecurityOutcome(§14.2-O)→ 逐字验证四 golden → 12 个 binding functions → isolation/forbidden-key → Slice Gate → Compatibility Gate → File Boundary Gate → Completion Summary。

---

## 21. Done Commands

### 21.1 Baseline(编码前)

```powershell
python -m compileall -q lima scripts tests
python -m unittest discover -s tests/contracts -v
python -m unittest -v tests.test_repository_source tests.test_task_failure
```

预期基线(@ `78aa9d8` + 本 Packet 合并):contracts **252** PASS;定向兼容 **29** PASS。

### 21.2 Slice Gate

```powershell
python -m compileall -q lima/contracts tests/contracts
python -m unittest discover -s tests/contracts -v
python -m ruff check lima/contracts/workflow.py tests/contracts/test_workflow.py tests/contracts/test_workflow_envelope.py tests/contracts/test_workflow_import_isolation.py
python -m ruff check lima/contracts tests/contracts
python -m bandit -q -r lima/contracts/workflow.py
git diff --check
```

### 21.3 Compatibility Gate

```powershell
python -m unittest -v tests.test_repository_source tests.test_task_failure
python -m unittest discover -s tests -v
```

实现后预期 contracts **323**(252+71)、全量 **668**(597+71)/ 0 failed / 1 既有 skip。任何新增 failure/skip 必须解释;不能通过修改 legacy 测试解决。Python 3.11/3.12 由 CI matrix 验证。

### 21.4 File Boundary Gate

```powershell
git diff --name-only --diff-filter=ACMRTUXB <frozen-test-commit>...HEAD
git diff --check <frozen-test-commit>...HEAD
```

输出必须恰好为 7.1 的 8 个新增文件(相对 Frozen Test Commit,产品侧仅 `lima/contracts/workflow.py`)。

### 21.5 Optional release-level gate

维护者或 CI 可运行 `powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 test`;普通 Agent 不因 Docker/宿主环境不可用而改变产品代码。

---

## 22. Security and Compatibility Invariants

- 执行事实词表(AttemptStatus/FailureKind)与安全结论词表(SecurityOutcomeKind)结构性分离且 disjoint;无 safe/clear/not_vulnerable 表达;
- vulnerability_verified/verified_patch 无对应 artifact 引用即非法;blocked/skipped/incomplete 类属 NON_CONCLUSION 分区且不携带结论语义(NFR-01/V5-AC-02);
- AUDIT_ONLY 工作流不得声明 mining/repair 执行状态;
- 非 succeeded 尝试不声明产出;skip 必有因、blocked/failed 必有失败类别;
- 一切跨 artifact 引用 = kind 字面量 + 三元组 + Envelope lineage 双向核对(digest 恒 `hmac.compare_digest`);
- classification 禁 public、retention 禁 ephemeral;ID/digest/时间全部由调用方提供;
- 不新增任何权限;不改变 legacy 行为与六个上游 IP 冻结面(18/16/15/12/12/12/29、六 golden);
- 不通过 future-minor extension 绕过 required、enum、矩阵或 provenance。

---

## 23. Stop Conditions / Decision Request

1. 两份 IP-0007 文档尚未合并,或基线不再是 `78aa9d8` 后代、八模块冻结面(18/16/15/12/12/12/29)漂移;
2. 最新 main 已出现同名 `workflow.py` 或冲突 Owner(cxx PR 开始触碰 `lima/contracts`/`tests/contracts`);
3. 需要修改任一 forbidden 文件或扩大 allowlist;
4. 需要新增第三方依赖、I/O、网络、数据库、Docker、subprocess 或环境权限;
5. §10-§16 任一契约存在两个与上游决策同等自洽的答案;
6. 四个 frozen fixture 的 bytes/digest 无法由 IP-0001 codec 重现,或引用链与上游 golden digest 不一致;
7. 需要引入 float、confidence/severity、自由文本安全结论、时间戳/lease/资源账本字段,或需要定义 Plan/RunManifest/Summary/Failure/manifests 完整 schema 才能让测试通过(范围上移 → IP-0008);
8. baseline/全量回归失败且无法归因;required tests 无法证明某个 AC;
9. 发现工作实际进入 #90/#68 runtime、生产接线或 closure。

Decision Request 格式同 Packet 惯例。

---

## 24. Git, Commit and PR Contract

推荐 commit / PR 标题:`feat: add deterministic workflow spine schemas`。PR 正文:只写 `Implements IP-0007` + `Related to #58`;禁 auto-close 关键字;AC → Test → Result;真实命令、退出码、统计;8 added / 0 modified / 0 dependencies;no runtime/no plan-manifest-summary-failure schema/no timestamps/no free text/top-level API unchanged;等待独立 Review 与 `merge-gate`。Implementation Agent 不合并 PR、不删分支/worktree、不改 Issue。

---

## 25. Completion Summary Template

```markdown
## IP-0007 Completion Summary

### Result
- Status: DONE | NOT DONE | BLOCKED
- Base commit / Frozen Test Commit / Final commit / Branch / Worktree:

### Scope
- Added files / Modified existing files: none / Dependencies added: none
- Public API: lima.contracts.workflow only (27 symbols)
- Contract deviations: none | <Decision Request>

### Acceptance evidence
| AC | Test/command | Result |
|---|---|---|
| WS-AC-01 … WS-AC-12 | | |

### Commands and actual results(命令/退出码/统计)
### Security and compatibility(词表分区/证据矩阵/身份对齐/lineage/echo/隔离/py3.11-12/回归)
### Findings and decisions
### Handoff(PR 状态/唯一下一步/禁止动作)
```

---

## 26. Maintainer Review Checklist

- [ ] base 为 Frozen Test Commit 后代且含本 Packet;只新增 8 文件;workflow.py 是唯一产品文件;
- [ ] 冻结面不变:18/16/15/12/12/12/29、六 golden;八个既有契约模块零改动;
- [ ] module API 恰 27 symbols;依赖 workflow→{codec,common,errors};不加载五领域模块;
- [ ] 三 schema wire(5/9/4 required 字段)与 ArtifactLink 4 字段无漂移;
- [ ] 四 golden 370/1498/460/589 bytes 与 digest 一致;引用链 = 上游 golden 真实 digest;
- [ ] kind→证据矩阵、状态耦合、AUDIT_ONLY 排除、revision⇔supersedes negative tests 通过;
- [ ] 身份对齐 + 类型化 lineage + classification/retention tests 通过;
- [ ] 词表分区 + 三词表 disjoint + forbidden-key 通过;current/future-minor 每层级通过;
- [ ] 全量回归无新增失败(预期 668 = 597+71);全目录 ruff exit 0;
- [ ] File Boundary 恰 8 文件;Completion Summary 可复现;独立 Review 与 merge-gate 通过;
- [ ] PR 未关闭 #58;未启动 IP-0008、#90/#68 runtime 或生产接线。

---

## 27. Assignment §10 十一问逐条单解(审计索引)

| # | Assignment 问题 | 单解 | 所在节 |
|---|---|---|---|
| 1 | 命名与 schema_name;共居 or 分列 | `lima/contracts/workflow.py`;三 schema 分列:`lima.workflow`/`lima.stage-attempt`/`lima.security-outcome`(DR-IP0007-DESIGN-01) | §9 |
| 2 | 三 schema 引用结构;attempt 身份与 Envelope 字段关系 | 分立 artifact;payload 镜像 Envelope 身份并对齐(§14.1);Workflow 以 ArtifactLink 引用 attempts | §11/§14.1 |
| 3 | 六类 Artifact 引用词表与 fail-closed | StageType×inputs/outputs 矩阵(§14.2-S4);ArtifactKind 六字面量;未知一律拒绝 | §10/§14.2 |
| 4 | SecurityOutcome 与 aep/vep/rvr 终态的层级规则 | 不重复裁决:引用不镜像 verdict(DR-IP0007-DESIGN-08);kind→证据矩阵 + 词表分区是机器断言 | §14.2-O3/O4 |
| 5 | 失败/取消/超时语义表达 | FailureKind 六值最小枚举占位(DR-IP0007-DESIGN-02)+ AttemptStatus 七态;永不编码安全结论 | §10/§14.2-S1/S2 |
| 6 | 状态词表与不变量;#90 豁免逐条 | WorkflowStatus 16 值 + AUDIT_ONLY 排除;豁免清单 §14.3(DR-IP0007-DESIGN-05) | §10/§14.2/§14.3 |
| 7 | golden:≥2 阶段混合状态 + 真实 digest 链 | 四 golden:2 阶段引用 + succeeded/blocked/failed/skipped 混合 + 上游 golden 实算 digest 链 | §17 |
| 8 | 测试矩阵与最低数量 | 71(44+23+4);import isolation 含依赖方向断言;禁字段递归断言 + 词表机制断言例外 | §18 |
| 9 | 错误映射与优先级 | 复用 29 codes;八级优先级 | §16 |
| 10 | 命令与预期数字 | contracts 252→323;全量 597→668 | §21 |
| 11 | 环境记录 | redis-py 6.4.0 vs manifest >=8.1.0,<9 差异在 RED/§14 类记录如实登记(本 Packet 验证范围零影响,基线已复现) | §21/交接书 |

---

## 28. 本 Packet 的冻结设计决策记录(Decision Records)

> 以下均为 P&V 在 Assignment 授权内的设计冻结,附先例与理由;若 Coordinator/Maintainer 否决任一条,走 Decision Request 重开。无一属于"两个同等自洽答案"的多解状态(否则已按 Assignment §13 停止)。

- **DR-IP0007-DESIGN-01(三 schema 分立)**:Workflow/StageAttempt/SecurityOutcome 各自独立成 Envelope artifact 而非共居一个 schema。依据:IP-0001 已把 `workflow_id`/`stage_attempt_id` 设为**每个** Envelope 的必填身份位(分立 artifact 才有各自身份);aep/vep/rvr 均"一 schema 一 artifact";SecurityOutcome 在时间上后于 Workflow 产生,共居需可变集合语义,违背不可变 artifact 原则。
- **DR-IP0007-DESIGN-02(FailureKind 最小枚举占位)**:Assignment §3 明示允许"最小枚举占位(以 Decision Record 论证)"。论证:NFR-01/V5-AC-02 要求 blocked/timeout/OOM/tool_error 的词表归属可机器断言,完全留白将使 S2 耦合无法实现;六值恰为 NFR-01 点名类别 + environment/policy_denied/internal(对齐 GateOutcome/ReproductionOutcome 六态先例的成员风格);不定义 FailureReport 的 stable code/permanence/retryability/owner(IP-0008)。
- **DR-IP0007-DESIGN-03(未冻结 schema 不入引用词表)**:snapshot manifest/Plan/RunManifest/Summary/Failure/CandidatePatch 不进入 ArtifactKind 与 StageType 词表(fail-closed);由 IP-0008 以新枚举成员 + 新 StageType 扩展(向后兼容:新 enum 值对 4.0 消费者是 UNKNOWN_ENUM_VALUE,符合 FR-06 演进路径)。依据:引用未冻结 schema 无法做类型化 lineage 核对;词表最小化是六模块一贯纪律。
- **DR-IP0007-DESIGN-04(无时间/lease/资源账本字段)**:Assignment §5 对 StageAttempt 的四要素枚举(阶段类型、attempt 身份、输入/输出引用、结束状态)不含时间与账本;Envelope `created_at` 是全平台唯一时间先例(vep ReproductionRun 无时间戳同构);budget 先例属 aep;runtime stage record(#90)拥有 lease/start/end。
- **DR-IP0007-DESIGN-05(仅冻结 AUDIT_ONLY 模式耦合)**:AUDIT_ONLY 排除八个 mining/repair 执行态是 V5 §4.1 的确定性语义("显式只审计");VERIFY_VEP/REPAIR_FROM_VEP 的状态子集(如是否允许 MATERIALIZING)在 V5 中无结构性确定答案,冻结将制造猜测——列为 §14.3 豁免,归 #90 policy evaluator。
- **DR-IP0007-DESIGN-06(无自由文本字段)**:三 schema 零 bounded-text。依据:workflow 层的散文是安全结论旁路的高危载体(RVR gate detail 先例仅用于执行事实);解释内容由被引用 artifact 的既有 detail/coverage_gaps 承载;字段面越小,NFR-01 断言越强。
- **DR-IP0007-DESIGN-07(跨 artifact 序号留 Registry)**:attempt_number 与 revision 的跨 artifact 单调性/唯一性不在单 Artifact 校验(aep revision 先例);单 Artifact 内仅校验 ≥1 与数组排序唯一。
- **DR-IP0007-DESIGN-08(verdict 一致性留消费侧)**:引用不可解析被引 artifact 的 payload(六模块共同前提);SecurityOutcome 不镜像不重derive artifact verdict;Registry/消费侧负责 kind 与所引 artifact 终态的一致性(同 AEP sealed/VEP 源约束先例)。

---

## 29. Packet 完成定义

只有全部 12 个 AC、71 个 required tests、四个 golden fixture、Envelope consumer test、import isolation、完整命令证据、独立 Review 和 `merge-gate` 全部满足,IP-0007 实现才能标记 DONE。

IP-0007 合并后,协调者必须在最新 `main` 上安排 post-merge verification,并让下一个消费 IP(IP-0008 候选:Plan/RunManifest/Summary/Failure schemas)对本模块做只读 consumer review(其 Packet 的 Design Input Manifest 入口 Gate)。当前 Agent 不自动继续下一个 IP。
