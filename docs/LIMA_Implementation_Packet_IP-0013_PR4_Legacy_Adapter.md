# LIMA Implementation Packet IP-0013:PR4 Legacy Adapter(Finding / EvidenceRecord 兼容层 + V5-FR-05 / AC-03 迁移接线)

> Packet ID:`IP-0013`
>
> 状态:`DESIGN-FROZEN / READY-FOR-CODE WHEN THIS PACKET IS MERGED TO MAIN`
>
> Source Issue:[#58](https://github.com/agent-sec-labs/LIMA/issues/58) 的第十三个独立实现切片(compatibility 角色:FR-07/PR4——legacy `lima.models` Finding/EvidenceRecord 与冻结契约的双向 adapter + V5-FR-05/AC-03 迁移侧行为证据)
>
> Assignment 基线:origin/main @ `0c560df66e430b87fd2976b15d7eeb5532db086e`(P&V 开工实测一致,`git ls-remote` 亲验 2026-09-11);实现基线 = 含本 Packet 与正式交接书的最新 `origin/main`
>
> 推荐分支:`codex/ip-0013-legacy-adapter`(依 lifecycle §9.1 从 Frozen Test Commit 派生)
>
> Owner:唯一 Implementation Agent;不触碰既有十三模块、PR3 产物、场景 fixture、manifests golden 与任何既有测试/fixture

## 需求映射(Header)

```text
Source Issue:#58
Issue specification revision:#58 正文 v46(body SHA-256 fd10ccf32366d0c90ca28400dcfdae56b5b10ab4c17ae81a910990b76e2439,
  V4 正文 + V5 覆盖层);Ledger Review @13(LR58-13-1,记录 SHA-256 18fc3929adc5e03d74e70974f2b5b46163ac62509b94fa7b9457937c65dcf768)
Assignment:PKT-IP-0013_PR4_PKT_ASSIGNMENT_DRAFT_2026-09-11.md(SHA-256
  a5aa9670caaefb889ba7fbe7840355c16d5517f96c8851ad3fe6ae1d238f27e5;激活 = 主会话派发,即本次)
Covered requirements:
  PR4(Implementation slices / PR plan 第 4 条):只读 legacy Finding adapter fixture;
  FR-05 尾款(legacy adapter fixture——依赖本 IP 的迁移 fixture 与行为测试);
  AC-03 / T-03 尾款("legacy consumer 仍可读取已知字段"——经 domain_to_finding 在
  future-minor 输入上的行为测试闭环);
  V5-FR-05 / V5-AC-02 迁移侧行为证据(契约禁止面已由 IP-0009 交付;本 IP 交付 adapter
  接线后的迁移侧行为证据:legacy 审计结果只能产出 source=legacy_audit 的 WorkflowSummary,
  结构性不可表达 full-chain success);
  FR-06(adapter 侧表达:current/future-minor 输入在 frozen→legacy 方向的边界行为);
  NFR-02(adapter 侧上限沿用既有 evidence/summary 域上限,不自设新限)
Not covered requirements:closure IP(IP-0014,含层次化术语表);生产接线(#68);
  #90 runtime / #76 生成器 / #77 Gate 执行器 / #66 Registry;consumer review ×4 后续
  (已由 LR58-13-1 §2 处置,无归 PR4 的未决项——见 §2 DI-013);任何既有十三模块、
  PR3 产物、场景 fixture、既有测试/fixture 修改;lima/models.py legacy 侧行为增强
Delivery role:compatibility(第十四个契约切片,非新领域 schema)
Issue closure impact:PARTIAL(完成后 #58 保持 open;FR-05 / AC-03 / V5-FR-05 由 PARTIAL
  转 SATISFIED 候选,由 Coordinator 裁定)
Upstream IP/PR/merge commits:IP-0001..0012 全链;IP-0009(契约层 V5-FR-05 禁止面,
  #131 squash 207222d);IP-0010(PR3 ADR 0027 与 schemas/v4);IP-0012(manifests,
  PR #141 squash 80feaea)
Activation gate:lifecycle 入口 Gate(见 §1,已完成:十三模块适用面核对无 Contract Gap +
  基线数字实测一致)
```

---

## 0. 执行决策

当前执行队列(Ledger v46 + LR58-13-1 §1):NOW = PKT-IP-0013(PR4)。本 Packet 只交付 compat 兼容层模块(1 个 .py)、3 个测试文件与 5 个 golden/迁移 fixture;零修改既有面,零新顶层路径(§15)。阶段二(RED + Frozen Test Commit)由 P&V 另行执行,本 Packet §13/§14 的测试矩阵与预期数字构成阶段二冻结依据。

---

## 1. 入口 Gate 结论(lifecycle,只读;@ main `0c560df`,P&V 实证 2026-09-11)

### 1.1 基线数字实测(LR58-13 登记的待复核项)

worktree `D:\BaseAIProject\LIMA-pr4-pkt-wt` @ `0c560df66e430b87fd2976b15d7eeb5532db086e` 实跑:

```text
python -m pytest tests/contracts -q   → 527 passed(与 Assignment §1 基点一致)
python -m pytest tests -q             → 871 passed, 1 skipped(与基点一致;既有 skip 数不变)
python -m ruff check --no-cache lima/contracts tests/contracts → exit 0(限定口径;
  注:lima/models.py 单独含 14 条既有 ruff 发现,属 legacy 只读面,不属本 IP 验收口径,
  亦不可修复——Must-not-modify)
```

### 1.2 十三模块适用面核对(Assignment §4-1;manifests 为第 13 模块)

基线 `lima/contracts/` 恰十三模块(codec/common/errors/evidence/profile/aep/vep/rvr/workflow/execution/summary/manifests/__init__)。adapter 触点逐模块核对:

| 模块 | 进入迁移映射面? | 实证结论 |
|---|---|---|
| evidence(IP-0002) | **是——主映射面** | legacy Finding → Signal + SecurityIssue + EvidenceRecord(P→F 方向);反向 domain_to_finding 消费同三类对象。全部用既有冻结词表(D0/D1/D2、SUPPORTS、SECURITY_ISSUE/SIGNAL subject),零新增枚举;evidence 18-symbol 冻结面禁改,compat 只 import 类型 |
| summary(IP-0009) | **是——V5-FR-05 接线面** | legacy ReviewReport → WorkflowSummary(source=legacy_audit、legacy_artifact_ids 必填 ≥1、typed links 结构性为 None)。source 互斥已由 IP-0009 冻结:legacy_audit 携带 typed link 即 INVALID_FIELD_VALUE——这正是 V5-FR-05 迁移侧行为的机器化锚点。summary 16-symbol 冻结面禁改 |
| codec(IP-0001) | 是——digest 纪律 | golden 预计算与测试对拍唯一使用 `compute_content_digest`(FR-04:codec 是 digest 唯一实现);compat 不得自行序列化算 digest |
| common(IP-0001) | 是——envelope lineage 约束登记 | 本 IP adapter 全部在 **payload 层**操作,不构造/编码 ArtifactEnvelope(见 §7 决策 D1);因此 `source_artifact_ids`/`legacy_artifact_ids` 的 lineage 存在性检查不在 adapter 内执行——这是 envelope 层职责,登记为显式边界而非 Contract Gap |
| errors | 是——错误映射 | ContractErrorCode 恰 29 成员,compat 复用全部既有 codes,零新增(errors 冻结面禁改) |
| manifests(第 13 模块) | **明确排除** | legacy Finding/ReviewReport 无任何 manifest 对应物(TaskManifest/ToolBundle/Dependency/SandboxRun 均无 legacy 字段来源);LR58-12 先例:"legacy 报告无 manifest 对应物,迁移禁止面已由 IP-0009 契约层交付"。compat 禁止 import manifests(import isolation 反向断言覆盖) |
| workflow / execution | 明确排除 | legacy 无 workflow/stage attempt/run manifest 对应物;V5-FR-05 的执行结论面只经 summary.execution_status 表达 |
| profile / aep / vep / rvr | 明确排除 | legacy 无四域对应物;Hypothesis/proof/gate 面 legacy 不可表达——列入 §7 决策 D2 的显式降级清单(结构性,非静默) |

**结论:无 Contract Gap,入口 Gate 通过。** legacy 侧全部可表达面(§7 映射表逐字段)要么 pass-through/transform,要么显式失败/显式降级;不存在"需修改既有契约才能自洽"的字段。

---

## 2. Design Input Manifest

| Input ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001..003 | Standard/Charter | 稳定标准 / lifecycle / P&V 责任书 | main `0c560df` | 分工、拓扑、冻结纪律 | normative | — |
| DI-004 | Issue(Assignment) | PKT-IP-0013_PR4_PKT_ASSIGNMENT_DRAFT_2026-09-11(SHA-256 a5aa9670…) | 2026-09-11 | 覆盖/不覆盖、§5 九问、十一项 Checklist、Stop Conditions | normative | — |
| DI-005 | Issue | #58 正文 v46(SHA fd10ccf3…2439) | v46 | PR4/FR-05/FR-06/AC-03/NFR-02/V5-FR-05/V5-AC-02 需求溯源 | normative | — |
| DI-006 | Issue(Ledger Review) | LR58-13_REVIEW_RECORD_2026-09-11(SHA 18fc3929…f768) | 2026-09-11 | @13 定序、consumer review ×4 处置表、基线数字基点、卫生裁定 | normative(current) | — |
| DI-007 | Decision | 全链 DR 正本 + IP-0009 Packet(V5-FR-05 禁止面)+ IP-0012 Packet(格式正本、D10 排除先例)+ PI-DR2/PI-DR3/AUDIT-3 条款 | 历次 | source 互斥锚点、命名与数字口径、条款沿用 | normative | — |
| DI-008 | Upstream IP | IP-0001..0012 Packets | #97..#142 | artifact 三元组先例、untyped id 先例、golden 模式、import isolation 模式 | normative | — |
| DI-009 | Architecture | PR3 ADR `docs/adr/0027-version-compatibility-policy.md` + `schemas/v4/`(13 schema + version_compatibility_matrix.json) | main `0c560df` | FR-06 current/future-minor 语义权威(未知 major 拒绝 / future minor round-trip 保留) | normative | — |
| DI-010 | Code | `lima/models.py`(legacy) + `lima/contracts/` 十三模块 | main `0c560df` | legacy 字段全集与 __post_init__ 派生规则(fingerprint 材料);冻结 validator 词表/上限 | current-behavior | legacy 代码事实只读;冻结词表为映射目标权威 |
| DI-011 | Test | `tests/contracts/` 全部 + fixtures | main `0c560df` | 测试风格、527 基线、golden 钉死模式、import isolation 模式 | current-behavior | — |
| DI-012 | Evidence | 本 IP 基线复现 + 映射可行性探针(P&V worktree 实跑) | 2026-09-11 | §1.1 数字;§7/§8 全链可行性实证(legacy→bundle→summary→legacy round-trip 探针全 PASS,含 payload digest 预计算复现) | evidence | — |
| DI-013 | Issue(LR 处置) | LR58-13 §2 consumer review ×4 处置表 | 2026-09-11 | 确认**无归 PR4 的 CR 处置项**(8 项 CR 归属:#58 Coordinator/#61/#66/#90/#91/#77/#70/IP-0014,均非本 IP);IP-0014 术语表不含 adapter 义务 | background-only(核对) | 不从处置表扩大范围 |

### Explicitly Rejected Inputs

| 材料 | 拒绝原因 |
|---|---|
| 修改 `lima/models.py` 以补齐 v4 字段 | #58 非目标明文("不在 lima/models.py 中堆叠 v4 字段");legacy 侧只读(Must-not-modify) |
| 修改 evidence/summary/errors/codec/common 或任何十三模块以"让 legacy 可无损表达" | 冻结面禁改(Stop Condition);映射缺口以显式失败/显式降级表达(§7),不以改契约消 gap |
| compat 新增 schema_name / 作为第十四个 schema 模块 | adapter 非 schema:不定义新 wire schema、不进 schemas/v4、不新增 envelope encode/decode 面(IP-0012 D10 同构排除);本 IP 不交付 schemas/v4 JSON |
| `contracts/__init__.py` re-export compat symbols | 18-symbol 冻结面禁改;消费面经 `lima.contracts.compat` 全路径 import |
| 把 legacy `confidence`(float)映射进任何冻结对象 | DR-IP0007-DESIGN-06 零 float 纪律;confidence 列入 UNMAPPED(§7 决策 D2) |
| 把 legacy `verification_state`/`severity`/`fix`/`test`/`title`/`explanation` 编码进冻结 extensions | current-minor(4.0)extensions 被既有模块 UNKNOWN_FIELD 拒绝;且会伪增冻结语义。全部列入 UNMAPPED frozenset(显式降级) |
| adapter 输出 source=chain 的 WorkflowSummary(legacy 审计结果"升级"为链结论) | V5-FR-05 明文禁止;结构性排除(§8 决策 D5) |
| adapter 构造/编码 ArtifactEnvelope 或做 lineage 存在性检查 | envelope 层职责与 lineage 约束属既有 encode/decode 面;payload 层单解(§7 决策 D1);伪 lineage 构造是范围扩张 |
| 生产接线(报告管线切换到 adapter) | #68 范围;本 IP 只交付 adapter 契约与行为证据 |
| cxx/DB/Docker/LLM/网络/fixtures import 分析器 | AC-04 依赖隔离;FR-05 明文 |

---

## 3. Iteration Hypothesis 与 Measurement

### 3.1 Hypothesis

如果 legacy Finding/EvidenceRecord/ReviewReport 与冻结契约的映射被冻结为逐字段单解表(pass-through/transform/lossy/unsupported 四态、lossy 必显式降级、unsupported 必显式失败或入 UNMAPPED 常量),identity 派生复用 legacy fingerprint 材料的完整 sha256,digest 全部经 IP-0001 codec 实算,且 legacy 审计结果在 summary 侧只能落 source=legacy_audit(IP-0009 冻结互斥),那么"legacy success 被静默升级为 full-chain success""legacy 字段被静默丢弃""迁移产物 digest 不可复现"这三类 FR-05/AC-03/V5-FR-05 风险在交付时刻即被机器拦截。

### 3.2 Measurement

- contracts 由 527 增至 527+N(N ≥ 30,精确值在 Frozen Test Commit 钉死),0F;全量由 872(871+1 skip)增至 872+N,0F,既有 skip 数不变;
- 双向 golden:legacy 输入样本 → 冻结 bundle payload golden(字节钉死);bundle → legacy dict 输出 golden;全部 digest 由 `compute_content_digest` 预计算且测试重算全等;
- round-trip 恒等:`domain_to_finding(finding_to_domain_bundle(f))` 的 fingerprint == f.fingerprint(完整 digest 前 24 hex,逐字符相等);
- V5-FR-05 负例:从 legacy ReviewReport 数据构造 CHAIN summary 的任何尝试在既有 summary 契约处 INVALID_FIELD_VALUE(机器拦截,非约定);
- import isolation:import compat 后其余域模块(profile/aep/vep/rvr/workflow/execution/manifests)不在 sys.modules;反向逐十三模块 import 后 compat 不在 sys.modules;compat 源码静态断言零禁止 import;
- AC-03 行为:future-minor(4.x, x>0)decode→encode 未知字段无损;同一输入上 domain_to_finding 仍正确读取全部已知字段。

---

## 4. Goal

交付 `lima/contracts/compat.py`(legacy ↔ 冻结契约双向 adapter)+ 3 个测试文件 + 5 个 golden/迁移 fixture。

## 5. Non-goals

closure IP、生产接线(#68)、#90/#76/#77/#66 实现、schemas/v4 JSON 导出、envelope 层 adapter、任何既有模块/PR3 产物/场景 fixture/既有测试修改、legacy 侧行为增强、runtime/持久化/网络/LLM、新 schema/新错误码/新顶层路径。

---

## 6. 工作树与分支前置条件

Coding Agent 必须:完整阅读稳定标准、lifecycle、Implementation Agent 责任书、本 Packet、`LIMA_Coding_Agent_IP-0013_正式开发任务交接.md`、CONTRIBUTING.md;确认两份 IP-0013 文档均已合并 `origin/main`;依 lifecycle §9.1 从 Frozen Test Commit(阶段二交付物指定 SHA)派生 `codex/ip-0013-legacy-adapter` 独立干净 worktree(禁共享根与既有 worktree);确认 `lima/contracts/compat.py`、3 个测试文件与 5 个 fixture 尚不存在;输出 Scope Confirmation 后再跑 baseline;不一致即停提交 Decision Request。根工作树未跟踪文件属用户资产,不得触碰。

---

## 7. 决策 D1(§5-1):模块落位 / 命名 / 依赖方向(冻结单解)

- **单文件** `lima/contracts/compat.py`(映射表 + 三个转换函数 + 常量,量级远小于 evidence.py);
- **payload 层单解**:adapter 全部操作 payload 层对象(Finding/ReviewReport ↔ EvidenceDomainBundle/WorkflowSummary),不构造 ArtifactEnvelope、不做 lineage 检查(§2 Rejected Inputs 第 8 条);
- 公开面(**冻结 symbol 清单,恰 11 项**):

```text
LEGACY_REASON_CODE: Final[str] = "LEGACY_MIGRATED"          # 迁移 reason code 哨兵
LEGACY_SOURCE_ARTIFACT_ID: Final[str] = "legacy-finding"    # payload 层来源哨兵 id
LEGACY_SENTINEL: Final[str] = "legacy-finding"              # root_cause_class/sink_identity/
                                                             # trust_boundary 哨兵字面量
UNMAPPED_LEGACY_FINDING_FIELDS: Final[frozenset[str]]       # 显式降级清单(见 D2)
UNMAPPED_FROZEN_FIELDS: Final[frozenset[str]]               # 反向显式降级清单(见 D3)
finding_to_domain_bundle(finding: Finding) -> EvidenceDomainBundle
domain_to_finding(bundle: EvidenceDomainBundle, *, issue_index: int = 0) -> Finding
review_report_to_workflow_summary(report: ReviewReport) -> WorkflowSummary
```

- **依赖方向(冻结)**:compat → {codec, common, errors, evidence(只读类型), summary(只读类型)} + `lima.models`(只读);**禁止 import** profile/aep/vep/rvr/workflow/execution/manifests 及 lima 任何其他非 contracts 模块。
- **Assignment §6 依赖清单偏差登记(DI-004 vs 本解)**:Assignment §6 列 compat → {codec, common, errors, evidence(只读类型)},未列 summary;但 §3 必须覆盖项含 V5-FR-05 迁移接线,其唯一表达载体是 summary.WorkflowSummary(IP-0009 冻结)。按优先级(Assignment 必须覆盖项 > 建议性依赖列举)唯一可解:把 summary 以与 evidence 完全相同的"只读类型"身份纳入依赖集。此为唯一解,无竞争解,故登记于 Packet 而不提 DR;compat 对 summary 同样零修改、只 import 类型与枚举。

---

## 8. 决策 D2(§5-2/§5-4):legacy → frozen 逐字段映射表(冻结单解)

**identity 派生(核心单解)**:legacy `Finding.__post_init__` 的 fingerprint 材料 `M = "%s\0%s\0%s\0%s" % (rule_id, path, line, evidence)` 是 legacy 侧唯一的确定性 identity 来源;adapter 复用同一材料计算**完整** sha256:`d = sha256(M.encode("utf-8")).hexdigest()`(64-hex)。派生 id(全部满足 identifier 词表):

```text
signal_id = f"sig-{d[:12]}"     issue_id = f"issue-{d[:12]}"     evidence_id[i] = f"ev-{d[:12]}-{i:03d}"
fingerprint(Signal) = d         identity_digest(SecurityIssue) = d
```

有损注记(显式):legacy 24-hex 截断 fingerprint **不**作为 Signal.fingerprint 保留(冻结要求 64-hex),以完整 digest 强化 identity;round-trip 时经 `d[:24]` 逐字符还原(§9 恒等式)。

**legacy Finding → EvidenceDomainBundle(恰 1 Signal + 1 SecurityIssue + (1+N) EvidenceRecord;N = len(finding.evidence_records) ≥ 1,legacy __post_init__ 保证非空)** 逐字段:

| legacy 字段 | 冻结落点 | 态 | 规则 / 失败条件(ContractError) |
|---|---|---|---|
| rule_id | Signal.rule_id;SecurityIssue 无对应 | pass-through(校验) | 必须匹配 `_RULE_ID_PATTERN`,否则 INVALID_FIELD_VALUE |
| path / line | SourceLocation(path, line, line):Signal.location、SecurityIssue.primary_location、各 record.location | pass-through(校验) | 必须通过冻结 `_validated_path`(相对、无 `\`、无盘符、无 `..`/`.`/空段、无 Cc、NFC、≤1024B)与 line ∈ [1, 2^31-1];违规即 INVALID_FIELD_VALUE——**显式失败,不改写路径** |
| evidence | ev-000(SIGNAL-subject 记录)的 summary | pass-through(校验) | bounded text(NFC、无 Cc、strip 后非空、≤4096B),否则 INVALID_FIELD_VALUE / MAX_STRING_LENGTH_EXCEEDED |
| evidence_records[i] | ev-(i+1)(SECURITY_ISSUE-subject 记录)的 summary = snippet,location = (rec.path, rec.line, rec.line) | pass-through(校验) | 同上两行规约;rec.path/line 违规同样显式失败 |
| evidence_kind | Signal.evidence_kind | pass-through(校验) | identifier 词表,否则 INVALID_FIELD_VALUE |
| source | 各 record 的 analysis_family 与 producer | pass-through(校验) | identifier 词表(legacy 默认 "local-rule" 合法),否则 INVALID_FIELD_VALUE |
| cwe | SecurityIssue.cwe_ids = (cwe,) / () | transform | 空字符串 → ();非空必须匹配 `CWE-[1-9][0-9]{0,5}`(legacy 已 upper/strip),否则 INVALID_FIELD_VALUE——**不静默丢弃非法 CWE** |
| fingerprint(24-hex) | 不保留为冻结值;identity 经 d 强化(见上) | lossy(显式) | round-trip 恒等式补偿(§9) |
| severity / title / explanation / fix / test / confidence / verification_state | 无冻结对应物 | **unsupported(显式降级)** | 冻结对象零结论镜像/零自由文本/零 float(DR-IP0007-DESIGN-04/06);入 `UNMAPPED_LEGACY_FINDING_FIELDS = frozenset({"severity","title","explanation","fix","test","confidence","verification_state"})`,文档 + 测试断言存在性——**结构性显式,非静默丢弃** |
| (无 legacy 来源)root_cause_class / sink_identity / trust_boundary | LEGACY_SENTINEL(三处同字面量) | **显式降级哨兵** | legacy 无根因/sink/边界语义;哨兵字面量冻结为 "legacy-finding"(identifier 合法);禁止从 rule_id 伪派生(会伪造语义) |
| (无 legacy 来源)各 record level / polarity | D0 / SUPPORTS | **显式降级** | legacy 证据无深度与极性语义;取最小深度 D0(绝不伪造 D1/D2)、SUPPORTS(legacy 证据构造上即支持性;REFUTES 语义 legacy 不存在,不伪造) |
| (无 legacy 来源)各 record reason_codes | (LEGACY_REASON_CODE,) | 显式降级哨兵 | 冻结要求非空;单一哨兵 "LEGACY_MIGRATED"(reason code 词表合法),可被消费方识别迁移来源 |
| (无 legacy 来源)各 record source_artifact_ids | (LEGACY_SOURCE_ARTIFACT_ID,) | 显式降级哨兵 | payload 层哨兵 "legacy-finding";envelope 层 lineage 存在性不属本层(§2/§7) |
| (无 legacy 来源)各 record independence_key | f"{rule_id}:{i:03d}" | transform(确定性派生) | ≤512B;同一 finding 内按序唯一 |
| (无 legacy 来源)SecurityIssue.signal_ids / evidence_ids | (signal_id,) / ev-001..ev-N(升序) | transform(确定性派生) | Signal.evidence_ids = (ev-000,);bundle 一致性检查(signal↔issue 绑定、排序唯一)由 EvidenceDomainBundle.__post_init__ 既有冻结逻辑兜底 |

schema_version 恒 `SchemaVersion(4, 0)`(current minor;FR-06:compat 不接受其他版本输入——bundle 输入侧的版本语义由既有 decode 面管)。

**可行性实证(DI-012)**:上述全链(含 bundle 校验、payload digest 预计算、summary 构造、反向 round-trip)已在基线 worktree 探针全 PASS(§1.1 同窗口)。

## 决策 D3(§5-3 前半):frozen → legacy 逐字段映射(冻结单解)

`domain_to_finding(bundle, *, issue_index=0) -> Finding`,以 `bundle.security_issues[issue_index]` 为目标、经其 `signal_ids[0]` 定位 Signal、经 (SECURITY_ISSUE, issue_id)-subject 记录定位证据:

| 冻结字段 | legacy 落点 | 态 | 规则 / 失败条件 |
|---|---|---|---|
| Signal.rule_id | Finding.rule_id | pass-through | — |
| issue.primary_location.path / start_line | path / line | pass-through | — |
| issue-bound 首条 record.summary | evidence | pass-through | bundle 已验证 bounded text |
| Signal.evidence_kind | evidence_kind | pass-through | — |
| issue.cwe_ids | cwe = min(cwe_ids) 或 ""(空) | **lossy(显式)** | legacy 单值字段;多 CWE 取字典序最小,其余丢弃——规则冻结且入 UNMAPPED_FROZEN_FIELDS 注记;单值/空则无损 |
| issue.identity_digest | fingerprint = identity_digest[:24] | transform | 与 legacy 24-hex 格式逐字符兼容(§9 恒等式) |
| issue.reason_codes | explanation = "; ".join(reason_codes) | transform(确定性) | bounded |
| (无冻结来源)severity | Severity.LOW | **显式降级** | 冻结无严重度;取最低档,绝不升格(与 V5-FR-05 同向保守纪律) |
| (无冻结来源)title | f"migrated:{issue_id}" | transform(哨兵前缀) | 确定性、可识别迁移来源 |
| (无冻结来源)fix / test | "unmapped:fix" / "unmapped:test" | 显式降级哨兵 | 冻结无修复/测试语义,不伪造 |
| (无冻结来源)source | "legacy-adapter" | 显式降级哨兵 | — |
| (无冻结来源)confidence / verification_state | legacy 默认(0.8 / "candidate") | **unsupported(显式降级)** | 入 `UNMAPPED_FROZEN_FIELDS = frozenset({"confidence","verification_state"})` |
| Signal.fingerprint(64-hex) / level / polarity / producer / independence_key / source_artifact_ids / 依赖图 | 无 legacy 对应物 | **unsupported(显式降级)** | 一并入 UNMAPPED_FROZEN_FIELDS;不折叠进任何 legacy 字段 |

失败条件:issue 无 signal(INVALID_FIELD_VALUE,"$.security_issues[i].signal_ids")、issue-bound 证据为空(INVALID_FIELD_VALUE)、issue_index 越界(INVALID_FIELD_VALUE)。

## 决策 D4(§5-3 后半):错误映射(29 codes 复用,零新增)

| 违规 | code(既有 29 之内) | field_path 约定 |
|---|---|---|
| legacy rule_id/source/evidence_kind 不合词表 | INVALID_FIELD_VALUE | `$.rule_id` / `$.source` / `$.evidence_kind` |
| legacy path 违规(绝对/`\`/盘符/`..`/Cc/超长) | INVALID_FIELD_VALUE / MAX_STRING_LENGTH_EXCEEDED | `$.path` |
| line 越界 | INVALID_FIELD_VALUE | `$.line` |
| evidence/snippet 空/超 4096B/含 Cc/strip 不变式 | INVALID_FIELD_VALUE / MAX_STRING_LENGTH_EXCEEDED | `$.evidence` / `$.evidence_records[i].snippet` |
| cwe 非空且不匹配 | INVALID_FIELD_VALUE | `$.cwe` |
| 空报告 / 空 findings(仅 D5) | INVALID_FIELD_VALUE | `$.findings` |
| domain_to_finding 结构缺项 | INVALID_FIELD_VALUE | §D3 所列路径 |
| NFC 归一冲突 | INVALID_UTF8 / INVALID_FIELD_VALUE | 同 evidence 求值顺序 |

求值顺序与既有模块同构:结构(type)先于语义(value)先于引用(digest/lineage);compat 对 ContractError 逐字段 repath,不自造错误文本。

## 决策 D5(§5-4):V5-FR-05 / AC-03 迁移接线与行为证据形态(冻结单解)

**V5-FR-05(结构性单解)**:`review_report_to_workflow_summary(report) -> WorkflowSummary`,恒产出:
- `source = SummarySourceKind.LEGACY_AUDIT`(唯一可能值——adapter 模块**不存在**任何产出 CHAIN 的 API;IP-0009 冻结互斥使 legacy_audit 携带 workflow/security_outcome/run_manifest/stage_attempts/evidence 任一即 INVALID_FIELD_VALUE——**禁止面是机器化的,不靠约定**);
- `execution_status = ExecutionStatus.SUCCEEDED`(显式降级注记:指 legacy 审计运行这一技术动作已完成,不编码任何安全结论;legacy 无 failed/cancelled 事实来源,不伪造);
- `legacy_artifact_ids = sorted(set(f.fingerprint for f in report.findings))`(去重升序——重复 fingerprint 折叠是**显式 lossy 规则**;空 findings 报告 INVALID_FIELD_VALUE,不产出空 legacy_audit);
- schema_version = 4.0;其余字段 None/()。

**行为证据形态(§5-4)**:
1. 迁移 fixture:legacy 输入样本(`legacy_finding_minimal.json` / `legacy_finding_full.json`,dict 形态,字节钉死)+ 冻结输出 golden 三份(`legacy_finding_domain_v4_golden.json` bundle payload、`legacy_finding_roundtrip_v4_golden.json` 反向 Finding dict、`legacy_report_workflow_summary_v4_golden.json` summary payload);全部内部 digest 由 codec 预计算,测试重算对拍;
2. 行为测试矩阵(含无法映射负例):§10;
3. **AC-03 legacy consumer 面**:future-minor(4.x, x>0)构造的 SecurityIssue(带未知 extension 字段)decode→encode 无损保留(既有面),且 `domain_to_finding` 在同一输入上正确读取全部已知字段并产出确定 Finding——"legacy consumer 仍可读取已知字段"以机器断言闭环。

**golden(5 份,满足 Assignment §5-5 的 ≥2 双向 + ≥1 有损/拒绝负例;负例以测试内联向量交付,fixture 不含非法输入)**——digest 预计算复现已在 DI-012 探针实证(bundle payload digest 可由 `compute_content_digest` 稳定重算)。

## 决策 D6(§5-5):文件边界

### Files to Add(恰好 9 个)
```text
lima/contracts/compat.py
tests/contracts/test_compat.py
tests/contracts/test_compat_migration.py
tests/contracts/test_compat_import_isolation.py
tests/contracts/fixtures/legacy_finding_minimal.json
tests/contracts/fixtures/legacy_finding_full.json
tests/contracts/fixtures/legacy_finding_domain_v4_golden.json
tests/contracts/fixtures/legacy_finding_roundtrip_v4_golden.json
tests/contracts/fixtures/legacy_report_workflow_summary_v4_golden.json
```

### Modify / Read-only / Must-not-modify
零 Modify。Read-only:十三模块全部、`lima/models.py`、既有全部测试/fixture(含 test_schema_export.py——compat 不登记 FROZEN_ARTIFACT_DIGESTS,因不交付 schemas/v4 JSON)、Dockerfile(§15 核对后零变更)、pyproject.toml。Must-not-modify 同 Assignment §6 Forbidden 全清单(十三模块、PR3 产物、场景 fixture、legacy 源、frontend/、pyproject.toml、Dockerfile)。

## 决策 D7(§5-6/§5-7):测试矩阵与命令(冻结类别与下限;精确 N 阶段二钉死)

**测试矩阵(N ≥ 30)**:

| 文件 | 类别 | 下限 | 要点 |
|---|---|---|---|
| test_compat.py | P→F 映射语义 | 12 | identity 派生恒等(d == sha256(M));派生 id 词表合法;bundle 结构(1 Signal/1 Issue/1+N ev;ev-000→SIGNAL、ev-001..→ISSUE);哨兵三字面量 + reason code + source artifact id;UNMAPPED_LEGACY_FINDING_FIELDS 存在性断言;cwe 空/合法/非法三态;D0/SUPPORTS 降级 |
| test_compat.py | P→F 负例(§5-4 无法映射负例) | 8 | rule_id 词表、绝对路径/盘符/`..`、line 越界、snippet 空/超长/Cc、cwe 非法、source 非法——各断言 code + field_path(§D4 表逐行) |
| test_compat.py | F→P 映射 | 6 | D3 逐字段(LOW/migrated 标题/unmapped 哨兵/min(cwe)/fingerprint[:24]/explanation join);UNMAPPED_FROZEN_FIELDS 断言;结构缺项负例 3 |
| test_compat_migration.py | V5-FR-05 行为 | 6 | report→summary 恒 legacy_audit + legacy_artifact_ids 排序去重;空 findings 拒绝;CHAIN 构造尝试在 summary 契约处 INVALID_FIELD_VALUE(2 变体:带 typed link / legacy_audit 缺 legacy ids);execution_status 唯一值断言 |
| test_compat_migration.py | golden + round-trip(§5-5) | 5 | 5 fixture 字节钉死 + payload digest codec 重算全等;round-trip 恒等式 `domain_to_finding(finding_to_domain_bundle(f)).fingerprint == f.fingerprint`;golden 输入→输出再生成全等 |
| test_compat_migration.py | AC-03 / FR-06 | 3 | future-minor 未知字段 decode→encode 无损 + domain_to_finding 仍读已知字段;current-minor 未知字段拒绝(既有面回归锚定) |
| test_compat_import_isolation.py | 依赖隔离(AC-04) | 4 | import compat → 其余域模块不在 sys.modules;**十三模块反向断言**(逐模块 import → compat 不在 sys.modules,13 断言 ≥1 用例);compat 源码静态断言零禁止 import;lima.models 只读(源码 diff 零)以 CI/验证期 diff 检查承载 |

**命令与预期数字(§5-7;验收一律在交付 worktree 内执行——ruff cwd 条款/AUDIT-3)**:
```text
python -m pytest tests/contracts -q        # 预期 527+N passed(0F;N ≥ 30 由冻结提交钉死)
python -m pytest tests -q                  # 预期 871+N passed, 1 skipped(= 872+N/0F/1 skip)
python -m ruff check --no-cache lima/contracts/compat.py tests/contracts/test_compat.py \
  tests/contracts/test_compat_migration.py tests/contracts/test_compat_import_isolation.py
                                           # 预期 exit 0
```

## 决策 D8(§5-8):CI 测试面(十一项 Checklist 第 11 条)

新增 9 文件全部落于既有顶层路径 `lima/contracts/` 与 `tests/contracts/fixtures/`;Dockerfile L45 `COPY tests ./tests`、L61 `CMD python -m unittest discover -s tests` 已覆盖(测试为 unittest/pytest 兼容风格,与既有 tests/contracts 同构),**零 Dockerfile 变更,无需 DR**。不新增顶层路径。

## 决策 D9(§5-9):环境记录

Windows 10 26200 + Git Bash;Python 3.12.4;ruff 经 `python -m ruff`;基线命令与数字见 §1.1/§D7;worktree `D:\BaseAIProject\LIMA-pr4-pkt-wt` 实测。无 redis/db/docker 依赖介入(contracts 面纯 stdlib;fixture 不 import DB/Docker/LLM/分析器——AC-04)。

---

## 10. PI-DR2:Packet 起草期逐断言自检记录(随 Packet,阶段一交付)

起草期对以下断言逐条自检(混层文本零容忍;引用与冻结基线逐字对齐):
1. 数字基点"527 / 871+1 skip / ruff exit 0"——本 worktree @ `0c560df` 实跑逐字核验(§1.1),非转抄;
2. "29 codes"——errors.py 逐成员清点(探针实列,与 IP-0012 §1.2 口径一致);"13 schema + matrix"——schemas/v4 目录清点;
3. "IP-0009 source 互斥使 legacy_audit 携带 typed link 即 INVALID_FIELD_VALUE"——summary.py L452-481 逐行核对;
4. legacy fingerprint 材料与 24-hex 截断——models.py L67-71 逐行核对;`_RULE_ID_PATTERN`/`_validated_path`/bounded text 规约——evidence.py 逐行核对;
5. 全部 §8/§9 映射规则——DI-012 探针在基线代码上端到端实证(bundle 校验通过、digest 重算稳定、round-trip 恒等),非纸面推导;
6. 测试文件命名与既有 13 个 `test_*_import_isolation.py` 惯例逐字对齐;fixture 命名与 `*_v4_golden.json` 惯例逐字对齐;
7. CR 处置表核对:LR58-13 §2 八项逐项过目,确认无归 PR4 项(§2 DI-013),未将任何 CR 项写入本 Packet 验收面。

## PI-DR3 与 ruff cwd 条款登记

PI-DR3(scratch GREEN 门禁永久化):阶段二 RED 前必须先在 scratch 位置证明被测实现路径 GREEN,防 RED 掩蔽;本 Packet 授权阶段二执行时逐字适用。ruff cwd 条款:全部验收命令在交付 worktree 内执行,仓库级裸命令结果不作证据。

---

## 11. 十一项强制 Checklist(阶段一登记;2-10 阶段二启用)

| # | 项 | 阶段一状态 |
|---|---|---|
| 1 | 实例化镜像 | 阶段二启用 |
| 2 | 传输点零 PR | 阶段二启用(docs-only PR 即本轮先例) |
| 3 | symbols 计数 | Packet 已冻结公开面清单(§7,恰 11 symbols);精确计数阶段二钉死 |
| 4 | helper 忠实性 | 阶段二启用(identity 材料复用 legacy 算法——§8 已冻结逐字符口径) |
| 5 | 调用点签名兼容 | 阶段二启用(新模块无既有调用点;domain_to_finding/finding_to_domain_bundle 签名已冻结) |
| 6 | None 哨兵 | 阶段二启用(summary None/() 哨兵与 exit 无关面已在 §D5 冻结) |
| 7 | GREEN 态冷缓存门禁 | 阶段二启用(ruff --no-cache 已入 §D7 命令) |
| 8 | 负例生证 | 阶段二启用(负例类别已冻结于 §D4/§D7) |
| 9 | 跨用例期望一致性 | 阶段二启用(round-trip 恒等式为跨用例锚) |
| 10 | lineage 对拍 | 阶段二启用(对拍规则 = payload digest codec 重算;envelope lineage 显式排除——§7 决策 D1) |
| 11 | CI 测试面新路径核对 | **阶段一已完成:PASS,零 Dockerfile 变更,无需 DR(§D8)** |

## 12. Stop Conditions(沿用 Assignment §9-§10,逐字有效)

不修改十三模块/legacy 源/PR3 产物/场景 fixture/既有测试;不实现 closure IP / 生产接线;不关闭 #58。特别地:§5 任一问题两解(尤其映射 lossy 语义与错误码归属——本 Packet §8/§9/§D4 已单解);legacy 字段存在无法按单解表达的结构性缺口(§1.2 已核:不存在);golden 预计算无法复现(DI-012 已实证可复现);需修改既有契约才能自洽;基线前移——任一发生即停提交 DR(`.pv_tmp/` 文件 + 回报双通道),保留现场。

## 13. 完成定义

阶段二 RED 冻结(527+N / 872+N 数字钉死,scratch GREEN 先行)→ IMPL 交付 9 文件 → 独立验证三态结论 → fast-forward → Implementation PR(lifecycle §12.2,`Related to #58`,禁 auto-close)→ post-merge。FR-05 / AC-03 / V5-FR-05 转 SATISFIED 由 Coordinator 裁定,不由本 Packet 宣布。

---

*签发:LIMA P&V Agent,2026-09-11(入口 Gate + 九问单解实证;基线 main @ `0c560df66e430b87fd2976b15d7eeb5532db086e`;Assignment SHA-256 `a5aa9670caaefb889ba7fbe7840355c16d5517f96c8851ad3fe6ae1d238f27e5` 核验一致)。*
