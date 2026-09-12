# LIMA Implementation Packet IP-0010:PR3 类 Artifact(JSON Schema 导出 + 版本兼容矩阵 + ADR)

> Packet ID:`IP-0010`
>
> 状态:`DESIGN-FROZEN / READY-FOR-CODE WHEN THIS PACKET IS MERGED TO MAIN`
>
> Source Issue:[#58](https://github.com/agent-sec-labs/LIMA/issues/58) 的第十个独立实现切片(adapter 角色:artifact 机械导出,零新语义、零契约变更)
>
> 最低代码基线:Assignment 基线 `207222d5a9f3b83038266ee866e501ea12f4ca11`(IP-0009 实现 PR #131 squash merge);实现基线 = 含本 Packet 与正式交接书的最新 `origin/main`
>
> 推荐分支:`codex/ip-0010-pr3-artifacts`(依 lifecycle §9.1 从 Frozen Test Commit 派生)
>
> Owner:唯一 Implementation Agent;本 IP 不触碰 `lima/contracts/` 任何文件

## 需求映射(Header)

```text
Source Issue:#58
Issue specification revision:正文修订 2026-09-01T14:36:22Z(V4 + V5 覆盖层);
  Delivery Ledger v37 @ 2026-09-06(聚合阶段定序:IP-0010 = PR3 类)
Covered requirements:FR-06 的矩阵 artifact 交付(九模块 × {4.0 current, future-minor} ×
  {unknown field/enum/required/major} 的机器可核对矩阵);Issue PR3 计划(JSON Schema 文件 +
  版本兼容矩阵 + ADR——Issue "File ownership" 节明文预留 schemas/v4/ 与 docs/adr/027-* 段);
  AC-04(依赖隔离对新产物适用:测试零第三方库,不引入 jsonschema)
Not covered requirements:V5-FR-04 场景 fixtures(IP-0011 候选);manifests 子集(IP-0012 候选);
  PR4 legacy adapter;closure IP;consumer review ×4 调度;任何 lima/contracts/ 产品代码修改
Delivery role:adapter(artifact 导出)
Issue closure impact:PARTIAL(合并后关闭 FR-06 的 artifact 缺口与 gates 表 PR3 行;#58 保持 open)
Upstream IP/PR/merge commits:IP-0001..0009 全链(#97..#131;冻结面
  18/16/15/12/12/12/27/16/19/29 + 十七 golden,全部 IP-DONE)
Activation gate:lifecycle 入口 consumer review(见 §1,已完成,无 Contract Gap)
```

---

## 0. 执行决策

当前执行队列(Ledger v37):NOW = IP-0010;NEXT = IP-0011 候选(V5-FR-04 场景 fixtures);LATER = manifests/PR4/closure/consumer review 调度。本 Packet 只交付静态导出 artifact 及其一致性测试,不实现任何运行时行为。

---

## 1. IP-0009 消费者评审结论(lifecycle 入口 Gate,只读)

### 1.1 已验证事实(@ main `207222d`,P&V 实证,2026-09-06)

- 基线复现:contracts **419/419**(worktree `LIMA-ip-0010-pkt-wt` 亲跑);全量 764/0F/1skip 与冷缓存 ruff exit 0 沿用同 commit post-merge 亲跑记录;冻结面 18/16/15/12/12/12/27/16/19/29、十七 golden;
- **summary consumer review(Assignment §5-1)**:P&V 于 IP-0009 验证期通读 916 行;`SummaryReferenceKind` 八字面量/来源互斥/scope 耦合均为**静态可推导面**(schema 文件的 enum 与 required 可从模块枚举与删除探针机械导出);零 summary.py 修改需求;
- **九模块 schema 面盘点(Assignment §5-2,权威清点)**:实际 schema_name 总数 = **13**(common 1 + evidence/profile/aep/vep/rvr 各 1 + workflow 3 + execution 2 + summary 2),跨 9 个模块——**Assignment 行文的"九 schema"系模块数简称;本 Packet 以 13 为准导出**(入口 Gate 事实修正,非语义变更);每个 schema 至少有一个 golden payload 可作导出自证的阳性样本(十七 golden 覆盖 13 schema);
- **Contract Gap 检查**:导出所需信息(required 集合、enum 词表、类型面、上限)全部在冻结面内可得——required 经删除探针、enum 经模块枚举全表、上限经各 Packet §14;跨字段不变量与 future-minor 容忍度为模块级行为,以矩阵 locus 列记录(非 schema 表达)——**无 Gap**。

**结论:不存在阻塞 IP-0010 的 Contract Gap。**

### 1.2 本 Packet 的兼容决策(冻结)

1. **产物形态 = 静态冻结文件 + 机器一致性测试**(DR-IP0010-DESIGN-01):13 个 JSON Schema 文件 + 1 个矩阵 JSON + 1 个 ADR,全部为 canonical 单行 JSON / markdown 字节冻结 artifact(同 golden 纪律);一致性测试从运行时侧机器断言零漂移;
2. 目录与命名:`schemas/v4/<schema_name 字面量>.json`(Issue "File ownership" 预留);矩阵 = `schemas/v4/version_compatibility_matrix.json`;ADR = `docs/adr/0027-version-compatibility-policy.md`(Issue 预留 027-040 段首号;`docs/adr/` 目录新建);
3. JSON Schema draft = **2020-12**(现行标准;`$schema` 固定);`$id` = **`urn:lima:v4:<schema_name>`**(URN 避免伪造域名;合法 URI);
4. schema 文件描述 **4.0 current-minor 结构面**:顶层 `additionalProperties: false`(对应 UNKNOWN_FIELD 拒绝)、required、enum、pattern、minItems/maxItems/minimum;**跨字段不变量、嵌套对象 unknown-field/extension 语义、future-minor 容忍、inline XOR blob 不在 schema 表达**——逐条以矩阵 `locus` 列记录为 module-enforced(DR-IP0010-DESIGN-02);
5. 矩阵 artifact = `version_compatibility_matrix.json`(canonical 单行):5 个 global_behaviors(unknown_major/future_minor/current_unknown_field/required_missing/unknown_enum,各含 expectation/code/locus)+ 13 schema 行(schema_name/schema_file/wire_version/envelope_binding)+ 3 条 notes;**生成测试以运行时探针逐格核对**(DR-IP0010-DESIGN-03);
6. ADR 只记录既有冻结决策(见 §17.7 全文),不新增决策;
7. 测试零第三方依赖:一致性测试内置 **mini-validator**(2020-12 子集:type/enum/pattern/required/properties/additionalProperties/items/minItems/maxItems/minimum/oneOf/const,stdlib 实现)——不引入 `jsonschema` 库(Assignment §7 Forbidden;DR-IP0010-DESIGN-04);
8. RED 机制:测试读取 `schemas/v4/*.json` 与 ADR——artifact 文件不存在 → FileNotFoundError,全部失败唯一归因目标产物缺失(charter §7.2 有效 RED)。

---

## 2. Design Input Manifest

| Input ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001..003 | Standard/Charter | 稳定标准/lifecycle/P&V 责任书 | main `207222d` | 分工、拓扑、冻结纪律 | normative | — |
| DI-004 | Issue(Assignment) | PKT-IP-0010 Assignment | Ledger v37 | 覆盖/不覆盖、§6 七问、十项 Checklist | normative | — |
| DI-005 | Issue | #58 正文 | `2026-09-01T14:36:22Z` | FR-06、PR3、"File ownership"(schemas/v4 + docs/adr/027-040 预留)、AC-04 | normative | — |
| DI-006 | Issue(Ledger) | #58 Ledger v37 | 2026-09-06 | 定序终审、基线数字 | normative(current) | — |
| DI-007 | Decision | 全链 DR 正本(8 条) | 2026-09-02..06 | 重冻结先例、十项 Checklist 渊源 | normative | — |
| DI-008 | Upstream IP | IP-0001..0009 Packets + 各 merge | #97..#131 | 13 schema 的 required/enum/上限/不变量推导源 | normative | — |
| DI-009 | Architecture | V5 规划文档 | 本地 | 聚合阶段语境(background) | background-only | — |
| DI-010 | Code | `lima/contracts/` 十一模块 | main `207222d` | 枚举全表、删除探针、decode 入口 | current-behavior | — |
| DI-011 | Test | tests/contracts + 十七 golden | main `207222d` | 阳性样本、419 基线 | current-behavior | — |
| DI-012 | Evidence | 设计期生成器 `.pv_tmp/IP-0010_generate.py` + 产物 `.pv_tmp/IP-0010_ARTIFACTS/`(14 文件 + ADR) | 2026-09-06 | 权威 bytes/digest(§17);自证记录(golden 校验/探针/枚举全等全 PASS) | evidence | 语义以模块为准 |

### Explicitly Rejected Inputs

| 材料 | 拒绝原因 |
|---|---|
| 生成器脚本作为产品交付物(运行时导出) | 跨字段不变量不可机械内省,生成器将成第二真值源;PR3 要求是静态 artifact 本身(DR-01) |
| jsonschema 第三方库 | Assignment §7 Forbidden;stdlib mini-validator 足够覆盖导出子集 |
| schema 内表达 mode⇒inputs/AUDIT_ONLY/revision⇔supersedes 等 if-then | 单文件静态表达制造第二份跨字段逻辑;矩阵 locus 记录(DR-02) |
| 为 future-minor 发双版本 schema 文件 | 单静态文件描述 current minor;容忍度是模块行为(ADR 0027 决策 3) |
| 修改任一 lima/contracts 模块或既有测试 | Stop Condition;零契约变更 |
| https:// 域名式 $id | 伪造域名;URN 是合法且无归属争议的 URI 形态 |

---

## 3. Iteration Hypothesis 与 Measurement

### 3.1 Hypothesis

如果 PR3 类产物被冻结为字节钉死的静态快照,且一致性测试从运行时侧机器断言(required 集合 = 删除探针、enum = 模块枚举全表、golden payload 全部通过 schema 校验、矩阵行为格 = 实际探针结果),那么"文档与代码漂移""矩阵与实现不符"这类聚合阶段事故在交付时刻即被拦截。

### 3.2 Measurement

- 14 个 artifact 的字节数与 SHA-256 与 §17 表逐一相等;
- 17 个 golden payload 全部通过对应 schema 的 mini-validator;
- 矩阵 5 行为 × 代表 schema 的运行时探针全部与 expectation 相符;
- 既有 764 测试零新增失败。

---

## 4. Goal

交付 `schemas/v4/` 下 13 个 JSON Schema 文件 + `version_compatibility_matrix.json`、`docs/adr/0027-version-compatibility-policy.md`,以及 2 个一致性测试文件(26 个冻结方法)。

---

## 5. Non-goals

PR4、manifests、场景 fixtures、closure、任何 contracts 修改、双版本 schema、运行时校验器产品化、第三方依赖。

---

## 6. 工作树与分支前置条件

依 lifecycle §9.1 从 Frozen Test Commit 派生 `codex/ip-0010-pr3-artifacts` 独立干净 worktree;确认 `schemas/`、`docs/adr/`、两测试文件不存在;Scope Confirmation 后运行 baseline;根工作树未跟踪文件为用户资产。

---

## 7. 文件边界

### 7.1 Files to Add(恰好 17 个)

```text
schemas/v4/lima.artifact-envelope.json
schemas/v4/lima.evidence-domain.json
schemas/v4/lima.repository-profile.json
schemas/v4/lima.audit-evidence-package.json
schemas/v4/lima.vulnerability-evidence-package.json
schemas/v4/lima.repair-verification-report.json
schemas/v4/lima.workflow.json
schemas/v4/lima.stage-attempt.json
schemas/v4/lima.security-outcome.json
schemas/v4/lima.plan.json
schemas/v4/lima.run-manifest.json
schemas/v4/lima.workflow-summary.json
schemas/v4/lima.failure-report.json
schemas/v4/version_compatibility_matrix.json
docs/adr/0027-version-compatibility-policy.md
tests/contracts/test_schema_export.py
tests/contracts/test_compatibility_matrix.py
```

### 7.2 Files Allowed to Modify

```text
none
```

### 7.3 Files Forbidden

`lima/contracts/` 全部十一模块;IP-0001..0009 任何测试/fixture;frontend/、pyproject.toml、requirements*.txt、.github/;任意范围外文档。

### 7.4 Ownership 与冲突边界

`schemas/v4/` 与 `docs/adr/0027` 本 IP 独占;两测试文件唯一 Owner。

---

## 8. Allowed / Forbidden Dependencies

两测试文件只允许 stdlib:`hashlib`、`json`、`pathlib`、`re`、`unittest` + 导入 `lima.contracts.{common,evidence,profile,aep,vep,rvr,workflow,execution,summary,errors}`(只读消费)。产物文件零依赖(纯数据)。Forbidden:jsonschema 及任何第三方库;网络/IO/subprocess;修改任何契约模块。

---

## 9. 冻结的公共 Symbols

本 IP 无 Python 产品模块(产物为数据/文档文件);测试文件的公共面 = 2 个模块 + 26 个冻结方法名(§18)。**Checklist 第 3 条(symbols 计数)适用形态**:13 + 1 + 1 = 15 个产物文件逐一存在且 digest 与 §17 表相等(测试机器断言)。

---

## 10. 冻结词表与推导配方(权威)

**推导配方(DR-IP0010-DESIGN-01 的机械规则,生成器已自证)**:

1. 每文件顶层:`{"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "urn:lima:v4:<literal>", "title": "<literal>", "type": "object", "properties": {...}, "required": [...], "additionalProperties": false}`,canonical 单行 JSON(sorted keys);
2. `required` = 对应 golden payload 逐键删除探针得 `REQUIRED_FIELD_MISSING` 的键集合(自证已做;与各 Packet §12 wire 字段一致);
3. enum 字段 → 模块枚举全表(definition 顺序);可空枚举(skip_reason/failure_kind/链接字段)→ `{"oneOf": [枚举, {"type": "null"}]}`;
4. 链接对象 → `{kind: 对应 ReferenceKind/ArtifactKind 枚举, artifact_id: identifier pattern, content_digest: hex64, schema_version: ^4\.\d+$}` + 四键 required;
5. identifier/digest/version/created_at 的 pattern 见 §17.1;整数 ≥1 字段(revision/attempt_number/plan_revision)→ `{"type":"integer","minimum":1}`;
6. 数组上限:envelope lineage 128/coverage_gaps 256;plan inputs 16/planned_stages {1,16};stage-attempt in/out 64;security-outcome evidence 64;run-manifest attempts/resource ids 256;workflow-summary attempts 256/evidence 64/legacy ids 256;failure-report evidence ids 256;五个早期域模块的宽松数组 maxItems 4096(结构性占位;实际上限模块执行,矩阵 locus 记录);
7. 五个早期域模块(evidence/profile/aep/vep/rvp… rvr)的结构面从 golden 键 + 类型推导(嵌套对象 `{"type":"object"}`、数组 items 宽松)——**有意宽松**(嵌套语义模块执行);
8. envelope schema:18 required(IP-0001 `_ENVELOPE_WIRE_FIELDS`)+ payload/blob_ref 可选;supersedes nullable。

**矩阵 schema**:见 §17.6 全文(5 global_behaviors + 13 行 + 3 notes)。

---

## 11. Exact Constructors and Defaults

不适用(数据文件)。测试文件内部 mini-validator 为纯函数实现(§8 白名单内)。

---

## 12. Exact Wire Shapes

产物文件自身即 wire:canonical 单行 JSON、UTF-8、无 BOM、无尾随换行、sorted keys;markdown(ADR)LF。

---

## 13. Scalar Validation

不适用(由一致性测试执行:文件存在、可解析、digest 相等、语义等价)。

---

## 14. 不变量(一致性测试的机器断言)

- **I1(digest)**:15 个产物文件字节数 + SHA-256 与 §17 表逐一相等;
- **I2(required 探针)**:每 payload schema 的 required 集合 = 运行时删除探针结果(envelope 用 `decode_envelope` 探针);
- **I3(enum 全等)**:schema 内每个 enum = 对应模块枚举的 definition 顺序成员值(逐字段映射表见测试冻结实现);
- **I4(golden 通过)**:17 个 golden payload(及 envelope golden)全部通过对应 schema 的 mini-validator;两 alternates/legacy 变体亦通过;
- **I5(负向)**:注入顶层未知键 → mini-validator 拒绝(additionalProperties:false)且模块拒绝(UNKNOWN_FIELD);未知 enum 值/缺 required 同理双拒绝;
- **I6(矩阵行为探针)**:unknown_major(5.0 → SCHEMA_UNKNOWN_MAJOR)、current unknown field、required missing、future-minor roundtrip(4.2 注入键往返保留)逐格与矩阵 expectation 相符(代表 schema 全 13);
- **I7(ADR)**:文件存在、digest 相等、包含五条冻结决策关键词。

---

## 15. Envelope Binding Contract

不适用(本 IP 无 Envelope binding;**Checklist 第 10 项 lineage 对拍 = 不适用**,按 Assignment §8 登记:产物非 Envelope artifact,无 lineage 面——一致性测试的 digest/探针/枚举对拍为其等价物)。

---

## 16. Stable Error Mapping and Precedence

不适用(产物零错误路径;一致性测试断言复用 29 codes 的运行时行为)。

---

## 17. 权威内容与 digest(逐字节复制;禁止更改)

**三重锁**:① §17 digest 表(字节权威);② 一致性测试(语义权威 = 运行时);③ 归档生成器 `.pv_tmp/IP-0010_generate.py`(DI-012;确定性复现全部 14 JSON)。实现者逐字节复制 `.pv_tmp/IP-0010_ARTIFACTS/` 下同名文件,或以生成器复现后核对 digest——任何字节差异 = Stop Condition。

### 17.1 digest 表(14 JSON + ADR)

| 文件 | 字节 | SHA-256 |
|---|---:|---|
| schemas/v4/lima.artifact-envelope.json | 1902 | 9caa48cd5e60536d78f3e37479327caa2fab7553f9bb01ed7a301809845de21d |
| schemas/v4/lima.evidence-domain.json | 615 | 224a13d304e8011ae8e80653cba65be54e1afcba6b847f52961fbaf4de8f7b8a |
| schemas/v4/lima.repository-profile.json | 1963 | 7b684654227fcb5cd774bd5e9a02c9ba31e4e8383c2bc77115d85413bdbdf9a1 |
| schemas/v4/lima.audit-evidence-package.json | 1055 | a4491c085d8f857b68c596207e0204b4f3cda19cc416cef3c6535977ea19c676 |
| schemas/v4/lima.vulnerability-evidence-package.json | 1329 | ab0b1604c9875b09fdb59163ca06584724d51b7735d5df96b507ad91a487b6a4 |
| schemas/v4/lima.repair-verification-report.json | 365 | 29f400ab05ea5df24e5e2b66f51aba4faffdab4f2fd267957dc6082e9d210c95 |
| schemas/v4/lima.workflow.json | 1345 | 149608611bf8b6de4222fe35daf29953cd9b3b23a31e1509136ed8ce8098397d |
| schemas/v4/lima.stage-attempt.json | 2076 | db39996cb83c1d9ce72a7cbb7139751c74fd81ce6deea12c1737cffda0c4514d |
| schemas/v4/lima.security-outcome.json | 1734 | ee66e8a34f344d446a54ab3ff1746c535af971bc9d229d26e08bdc3d41e44883 |
| schemas/v4/lima.plan.json | 990 | 48d242383901fafc24736acbef6effcc6390acff7b5ebb17929dd9e15ba8a73f |
| schemas/v4/lima.run-manifest.json | 1796 | 53b451de36bb77d5397d4576b3f9ae108f661ef483dc4b128824725d9648af68 |
| schemas/v4/lima.workflow-summary.json | 3560 | b72041f6921540a94f1eda7ea77b189fe4e5cb59fdfabfd36aa2bb651014970b |
| schemas/v4/lima.failure-report.json | 1925 | 63dc94fb92211717df0a8fd7a2e5852da6ea824fabf04c7ff075befe65de8e0f |
| schemas/v4/version_compatibility_matrix.json | 2876 | a0aa11f6906805790f8654dd33e48ab67a773e4b0f05c552d06cad53dc980588 |
| docs/adr/0027-version-compatibility-policy.md | 2528 | d96ccca7b10b02d058b35d417ed126dcd84c6a03a6f037f16da670bde16c47d4 |

### 17.2 代表性全文(4 schema;其余 9 个 + 矩阵的权威 bytes = 上表 digest + DI-012 归档,语义由 I1-I7 测试锁定)

**lima.artifact-envelope.json**(1902 B,`9caa48cd…`):

```json
{"$id":"urn:lima:v4:lima.artifact-envelope","$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"artifact_id":{"pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$","type":"string"},"blob_ref":{"type":"object"},"classification":{"enum":["public","internal","sensitive","restricted"],"type":"string"},"content_digest":{"pattern":"^[0-9a-f]{64}$","type":"string"},"coverage_gaps":{"items":{"type":"string"},"maxItems":256,"type":"array"},"created_at":{"pattern":"^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,6})?(Z|[+-]\\d{2}:\\d{2})$","type":"string"},"lineage":{"items":{"type":"object"},"maxItems":128,"type":"array"},"payload":{"type":"object"},"policy_digest":{"pattern":"^[0-9a-f]{64}$","type":"string"},"producer":{"pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$","type":"string"},"repository_snapshot_digest":{"pattern":"^[0-9a-f]{64}$","type":"string"},"retention_class":{"enum":["ephemeral","standard","audit","legal_hold"],"type":"string"},"schema_name":{"pattern":"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$","type":"string"},"schema_version":{"pattern":"^4\\.[0-9]+$","type":"string"},"stage_attempt_id":{"pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$","type":"string"},"supersedes":{"type":["object","null"]},"task_id":{"pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$","type":"string"},"tenant_id":{"pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$","type":"string"},"toolchain_digest":{"pattern":"^[0-9a-f]{64}$","type":"string"},"workflow_id":{"pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$","type":"string"}},"required":["schema_name","schema_version","artifact_id","tenant_id","task_id","workflow_id","stage_attempt_id","repository_snapshot_digest","producer","created_at","policy_digest","toolchain_digest","content_digest","classification","retention_class","lineage","supersedes","coverage_gaps"],"title":"lima.artifact-envelope","type":"object"}
```

**lima.plan.json**(990 B,`48d24238…`):

```json
{"$id":"urn:lima:v4:lima.plan","$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"inputs":{"items":{"properties":{"artifact_id":{"pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$","type":"string"},"content_digest":{"pattern":"^[0-9a-f]{64}$","type":"string"},"kind":{"enum":["lima.vulnerability-evidence-package","lima.workflow","lima.stage-attempt","lima.plan"],"type":"string"},"schema_version":{"pattern":"^4\\.[0-9]+$","type":"string"}},"required":["kind","artifact_id","content_digest","schema_version"],"type":"object"},"maxItems":16,"type":"array"},"planned_stages":{"items":{"enum":["profile","audit","mine","repair","summarize"],"type":"string"},"maxItems":16,"minItems":1,"type":"array"},"revision":{"minimum":1,"type":"integer"},"workflow_mode":{"enum":["full_chain","audit_only","verify_vep","repair_from_vep"],"type":"string"}},"required":["inputs","planned_stages","revision","workflow_mode"],"title":"lima.plan","type":"object"}
```

**lima.failure-report.json**(1925 B,`63dc94fb…`)与 **lima.run-manifest.json**(1796 B,`53b451de…`):全文见 DI-012 归档(结构同上模式:六值 failure_kind/scope/disposition 枚举、owner identifier、nullable 链接 oneOf、evidence ids ≤256)。

### 17.3-17.5

其余九 schema(evidence-domain/repository-profile/aep/vulnerability-evidence-package/repair-verification-report/workflow/stage-attempt/security-outcome/workflow-summary):权威 bytes = §17.1 digest + DI-012 归档;配方 §10;语义锁 I1-I7。

### 17.6 version_compatibility_matrix.json(2876 B,`a0aa11f6…`)

```json
{"current_minor":"4.0","global_behaviors":[{"code":"SCHEMA_UNKNOWN_MAJOR","expectation":"reject","id":"unknown_major","locus":"module.SchemaVersion"},{"code":null,"expectation":"unknown-fields-preserved","id":"future_minor_extension_roundtrip","locus":"module.extensions"},{"code":"UNKNOWN_FIELD","expectation":"reject","id":"current_minor_unknown_field","locus":"module+schema-file"},{"code":"REQUIRED_FIELD_MISSING","expectation":"reject","id":"required_missing","locus":"module+schema-file"},{"code":"UNKNOWN_ENUM_VALUE","expectation":"reject","id":"unknown_enum","locus":"module+schema-file"}],"matrix_version":"1","notes":["schema files describe the 4.0 current-minor structural face (additionalProperties:false at the top level)","future-minor tolerance and all cross-field invariants are module-enforced and therefore matrix-recorded, not schema-expressed","nested objects are intentionally left loose; their unknown-field and extension semantics are module-enforced"],"policy_sources":["#58 FR-06","IP-0001 Packet","ADR 0027"],"schemas":[{"envelope_binding":false,"schema_file":"schemas/v4/lima.artifact-envelope.json","schema_name":"lima.artifact-envelope","wire_version":"4.0"},{"envelope_binding":true,"schema_file":"schemas/v4/lima.audit-evidence-package.json","schema_name":"lima.audit-evidence-package","wire_version":"4.0"},{"envelope_binding":true,"schema_file":"schemas/v4/lima.evidence-domain.json","schema_name":"lima.evidence-domain","wire_version":"4.0"},{"envelope_binding":true,"schema_file":"schemas/v4/lima.failure-report.json","schema_name":"lima.failure-report","wire_version":"4.0"},{"envelope_binding":true,"schema_file":"schemas/v4/lima.plan.json","schema_name":"lima.plan","wire_version":"4.0"},{"envelope_binding":true,"schema_file":"schemas/v4/lima.repair-verification-report.json","schema_name":"lima.repair-verification-report","wire_version":"4.0"},{"envelope_binding":true,"schema_file":"schemas/v4/lima.repository-profile.json","schema_name":"lima.repository-profile","wire_version":"4.0"},{"envelope_binding":true,"schema_file":"schemas/v4/lima.run-manifest.json","schema_name":"lima.run-manifest","wire_version":"4.0"},{"envelope_binding":true,"schema_file":"schemas/v4/lima.security-outcome.json","schema_name":"lima.security-outcome","wire_version":"4.0"},{"envelope_binding":true,"schema_file":"schemas/v4/lima.stage-attempt.json","schema_name":"lima.stage-attempt","wire_version":"4.0"},{"envelope_binding":true,"schema_file":"schemas/v4/lima.vulnerability-evidence-package.json","schema_name":"lima.vulnerability-evidence-package","wire_version":"4.0"},{"envelope_binding":true,"schema_file":"schemas/v4/lima.workflow.json","schema_name":"lima.workflow","wire_version":"4.0"},{"envelope_binding":true,"schema_file":"schemas/v4/lima.workflow-summary.json","schema_name":"lima.workflow-summary","wire_version":"4.0"}],"wire_major":4}
```

### 17.7 ADR 0027 全文(2528 B,`d96ccca7…`)

见 DI-012 归档 `0027-version-compatibility-policy.md`(背景/七条决策记录/后果;决策 1-7:unknown major fail-closed、4.0 unknown field 拒绝、future-minor extension 往返为模块行为、required/enum 永不降级、major bump 仅破坏性变更、schemas/v4 快照语义与三重一致性、跨字段不变量矩阵 locus)。

---

## 18. Required Tests

### 18.1 `tests/contracts/test_schema_export.py`(18)

```text
SchemaExportInventoryTests
  test_fifteen_artifacts_exist_with_frozen_digests
  test_schema_ids_and_draft_are_exact
  test_envelope_schema_required_set_matches_module_probe
SchemaContractTests(13 个同名方法,每 schema 一个)
  test_artifact_envelope_schema_matches_runtime_contract
  test_evidence_domain_schema_matches_runtime_contract
  test_repository_profile_schema_matches_runtime_contract
  test_audit_evidence_package_schema_matches_runtime_contract
  test_vulnerability_evidence_package_schema_matches_runtime_contract
  test_repair_verification_report_schema_matches_runtime_contract
  test_workflow_schema_matches_runtime_contract
  test_stage_attempt_schema_matches_runtime_contract
  test_security_outcome_schema_matches_runtime_contract
  test_plan_schema_matches_runtime_contract
  test_run_manifest_schema_matches_runtime_contract
  test_workflow_summary_schema_matches_runtime_contract
  test_failure_report_schema_matches_runtime_contract
MiniValidatorNegativeTests
  test_mini_validator_rejects_unknown_top_level_field
  test_mini_validator_rejects_unknown_enum_and_missing_required
```

每个 `…_matches_runtime_contract`:加载 schema 文件 → mini-validator 接受对应 golden payload(含 alternates/legacy 变体)→ required 集合 == 运行时删除探针 → schema 内每个 enum == 模块枚举 definition 顺序全表(字段→枚举类映射表冻结于测试)。

### 18.2 `tests/contracts/test_compatibility_matrix.py`(8)

```text
CompatibilityMatrixTests
  test_matrix_lists_all_thirteen_schemas
  test_matrix_digest_is_frozen
  test_unknown_major_rejected_for_all_schemas
  test_unknown_field_rejected_at_current_minor_for_all_schemas
  test_required_missing_rejected_for_all_schemas
  test_future_minor_roundtrips_for_all_schemas
  test_unknown_enum_rejected_for_representative_schemas
  test_adr_records_frozen_version_policies
```

### 18.3 Minimum count

至少 **26** 个 test methods(18+8)。

---

## 19. Acceptance Criteria and Traceability

| AC | Required behavior | Evidence | Requirement |
|---|---|---|---|
| PR3-AC-01 | 15 产物文件存在、digest 与 §17.1 逐一相等 | I1 test | FR-06/PR3 |
| PR3-AC-02 | schema required/enum/结构与运行时零漂移 | 13 contract tests | FR-06、PR3 |
| PR3-AC-03 | 17 golden 全部通过对应 schema | I4 tests | FR-05/06 |
| PR3-AC-04 | 矩阵 5 行为 × 13 schema 与运行时探针相符 | matrix tests | FR-06 |
| PR3-AC-05 | 负向双拒绝(schema 文件 + 模块) | mini-validator negatives | FR-06/NFR-01 |
| PR3-AC-06 | ADR 记录五条以上冻结决策、无新决策 | ADR test | PR3 |
| PR3-AC-07 | 零第三方依赖;产物纯数据 | import 审查 + 依赖零变化 | AC-04 |
| PR3-AC-08 | 17 added / 0 modified / 回归零新增失败 | boundary + regression | AC-04 |

---

## 20. 强制实现顺序(十项 Checklist)

阶段二 P&V 执行 1-6:①预检(实例化镜像/helper 忠实性/调用点兼容/None 哨兵适用部分 + **负例生证 + 跨用例期望一致性**;lineage 对拍登记"不适用+理由");②编写 2 测试文件(方法名冻结);③GREEN 态冷缓存门禁(stub = 本 IP 无 Python 产品模块,**stub 形态 = 产物 JSON 文件置于真实路径后 ruff --no-cache + compileall**;RED 态结果不作依据);④有效 RED(测试读产物 → FileNotFoundError 全归因产物缺失);⑤Frozen Test Commit(只推分支);⑥IMPL Assignment。实现者从第 7 步:逐字节放置 15 产物文件 → 一致性测试全绿 → 三 Gate → Completion Summary。

---

## 21. Done Commands

```powershell
# Baseline:contracts 419 PASS;定向 29 PASS
# Slice Gate(GREEN 态 = 产物在位):
python -m compileall -q lima/contracts tests/contracts
python -m unittest discover -s tests/contracts -v      # 445 ran / 0 failed
python -m ruff check --no-cache tests/contracts/test_schema_export.py tests/contracts/test_compatibility_matrix.py
python -m ruff check --no-cache lima/contracts tests/contracts
python -m bandit -q -r tests/contracts/test_schema_export.py tests/contracts/test_compatibility_matrix.py
git diff --check
# Compatibility Gate:全量 790 = 764+26 / 1 既有 skip
# File Boundary:恰 17 文件,产品侧 = 15 产物(零 .py 产品文件)
```

---

## 22. Security and Compatibility Invariants

- 产物纯数据/文档,零可执行面、零新权限、零依赖;
- schema/矩阵不构成第二语义真值源(三重锁;ADR 0027 决策 6);
- 冻结面 18/16/15/12/12/12/27/16/19/29 与十七 golden 零改动;
- 不修改任何既有文件;future-minor 语义不被 schema 错误表达(locus 纪律)。

---

## 23. Stop Conditions / Decision Request

1. 两份 IP-0010 文档未合并,或基线非 `207222d` 后代、十一模块冻结面漂移;
2. 产物 digest 无法复现(生成器/归档/配方三方不一致);
3. 一致性测试发现 schema 与运行时漂移(required/enum/golden 校验失败且产物按 §17 复制无误——说明冻结面本身矛盾);
4. 需要修改任一契约模块、既有测试或引入第三方库才能自洽;
5. cxx 触碰 contracts;多解即停止提交 DR。

---

## 24. Git, Commit and PR Contract

推荐标题 `feat: add contract JSON schemas, compatibility matrix, and versioning ADR`。PR:只写 `Implements IP-0010` + `Related to #58`;禁 auto-close;17 added / 0 modified / 0 deps。

---

## 25. Completion Summary Template

同先例(8 AC 证据表;命令含 --no-cache GREEN 态;产物 digest 复验清单)。

---

## 26. Maintainer Review Checklist

- [ ] 恰 17 文件;15 产物 digest 与 §17.1 逐一相等;零 .py 产品文件;
- [ ] 契约模块与既有测试/fixture 零改动;冻结面与十七 golden 零漂移;
- [ ] 26 测试全绿(445/790);mini-validator 无第三方依赖;
- [ ] 矩阵行为探针全过;ADR 五决策在案;PR 未关 #58。

---

## 27. Assignment §6 七问逐条单解

| # | 问题 | 单解 | 所在 |
|---|---|---|---|
| 1 | 形态/位置/命名/draft | schemas/v4/<literal>.json;draft 2020-12;urn:lima:v4 $id | §1.2-2/3 |
| 2 | 导出方式 | 静态冻结文件 + 一致性测试(三重锁;DR-01) | §1.2-1 |
| 3 | 矩阵形态 | canonical 单行 JSON + 运行时探针生成测试(DR-03) | §17.6 |
| 4 | ADR 范围 | 七条既有决策,零新增 | §17.7 |
| 5 | 测试矩阵 | 26(18+8) | §18 |
| 6 | 命令/数字 | contracts 419→445;全量 764→790 | §21 |
| 7 | 环境记录 | redis-py 差异照登 | §21/交接书 |

---

## 28. 冻结设计决策记录

- **DR-IP0010-DESIGN-01(静态冻结文件,非运行时生成器)**:跨字段不变量不可从模块机械内省(是逻辑非数据),生成器产品化 = 第二真值源;PR3 交付物本身是静态 artifact;golden 纪律(字节冻结 + 测试锁定)直接适用;设计期生成器仅作确定性复现工具归档。
- **DR-IP0010-DESIGN-02(schema = 4.0 结构面;不变量/嵌套/future-minor 归矩阵 locus)**:单静态 2020-12 文件表达 if-then 会复制跨字段逻辑;future-minor 容忍是模块行为(ADR 0027 决策 3);矩阵 locus 列使执行位置无歧义。
- **DR-IP0010-DESIGN-03(矩阵 = 数据 + 探针测试)**:矩阵自身 canonical JSON;五个行为的 expectation/code/locus 由测试以真实模块探针逐格核对(非文档声明)。
- **DR-IP0010-DESIGN-04(stdlib mini-validator)**:导出子集(type/enum/pattern/required/additionalProperties/items/界限/oneOf/const)可 ~80 行 stdlib 实现;Assignment §7 明禁 jsonschema;不削弱断言强度(双拒绝测试)。
- **DR-IP0010-DESIGN-05(schema 数 = 13,非 9)**:入口 Gate 权威清点(Assignment"九 schema"为模块数简称);13 = 1+5+3+2+2;事实修正非语义变更。
- **DR-IP0010-DESIGN-06(早期五域模块结构面宽松)**:嵌套对象 type:object、数组 items 宽松、maxItems 4096 占位——嵌套 unknown-field/extension 语义与实际上限由模块执行(矩阵 notes/locus);完整嵌套 schema 化无冻结需求且会复制域逻辑。

---

## 29. Packet 完成定义

8 AC、26 tests、15 产物 digest 全等、GREEN 态命令证据、独立 Review 与 merge-gate 满足后 IP-0010 才可标 DONE。合并后 Coordinator 安排 post-merge;下一消费 IP(IP-0011 候选:V5-FR-04 场景 fixtures)的入口 Gate 含对本产物集的只读 consumer review。
