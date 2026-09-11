# LIMA Implementation Packet IP-0014:Closure IP(跨 Artifact 集成 + 真实 Golden Path 验证 + Issue Closure Audit + 文档面三项)

> Packet ID:`IP-0014`
>
> 状态:`DESIGN-FROZEN / READY-FOR-CODE WHEN THIS PACKET IS MERGED TO MAIN`
>
> Source Issue:[#58](https://github.com/agent-sec-labs/LIMA/issues/58) 的第十四个(终点)实现切片(integration/closure 角色:gates 表最后两 open 项——跨 Artifact 集成 + 真实 Golden Path 聚合证据、Issue Closure Audit;并入 CRDISP-1 文档面三项)
>
> Assignment 基线:origin/main @ `31449ee2c05a08c0ab8e8070d66d30016071ad1e`(P&V 开工实测一致,`git ls-remote` 亲验 2026-09-12);实现基线 = 含本 Packet 与正式交接书的最新 `origin/main`
>
> 推荐分支:`codex/ip-0014-closure-integration`(依 lifecycle §9.1 从 Frozen Test Commit 派生)
>
> Owner:唯一 Implementation Agent;只消费既有冻结面(十三模块 + compat + schemas/v4 + 既有 fixtures),零语义变更、零 wire 字段变更

## 需求映射(Header)

```text
Source Issue:#58
Issue specification revision:#58 正文 v47(body SHA-256
  bb01da8a80b8aa661933dbe23cda86da7b5212192874c729d3d2a1872f520a5;
  Ledger v47:20/20 SATISFIED-BY-EVIDENCE、gates 17 PASS / 2 open)
Assignment:PKT-IP-0014_PKT_ASSIGNMENT_DRAFT_2026-09-12.md(SHA-256
  d74ca3a4318d8ef95ee536852fc61cd36db378e04377a9b0d24d1dd8391e3e84;激活 = 主会话派发,即本次)
Covered requirements:
  gates 表 "跨 Artifact 集成 + 真实 Golden Path 聚合证据"(UNMAPPED → 本 IP 关闭);
  gates 表 "Issue Closure Audit + Closure Record"(OPEN → 本 IP 交付 Closure Record 草案,
    最终关闭裁定归 Coordinator/Maintainer,MANUAL-AFTER-POST-MERGE-AUDIT);
  CRDISP-1 文档面三项:CR61-02 勘误 DR、CR70-03 层次化术语表 + 前端 unknown 降级规则、
    CR70-02 "汇总 Gate"文案边界(处置表 §1 第 4/9/8 行)
Not covered requirements:#58 全部 20 需求行均已在 v47 SATISFIED-BY-EVIDENCE——本 IP 不重复
  实现任何需求行,只做终态审读聚合;任何 4.0 wire 字段/枚举变更;生产接线(#68);RAM 图/
  Audit Oracle 建议/severity/API 读模型(CR60-01/CR61-01/CR70-01 归各 owner 独立后续 IP);
  #58 Issue 关闭操作本身;各下游 Issue(#60/#61/#66/#70/#76/#77/#90/#91/#94)实现
Delivery role:integration / closure(第十五个切片,非新领域 schema,零新模块)
Issue closure impact:CLOSURE-PATH(完成后 gates 2 open → 0 open 候选;#58 仍不自动关闭,
  需 Closure Audit 通过 + Maintainer 终审 MANUAL-AFTER-POST-MERGE-AUDIT)
Upstream IP/PR/merge commits:IP-0001..0013 全链(十四交付面);CRDISP-1 处置表
  (SHA-256 4b85b8b0b3f28b1ffbf752a677ed183140991cbf5f987954b7dd1d852c0b97ce)
Activation gate:lifecycle 入口 Gate(见 §1,已完成:gates 17 PASS/2 open 逐行核对 +
  基线数字实测一致 + Golden Path 可达性探针全绿,无 Contract Gap)
```

---

## 0. 执行决策(含文档面路由单解)

当前执行队列(Ledger v47):NOW = PKT-IP-0014(closure IP)。本 Packet 只交付跨 Artifact 集成测试 + Golden Path 聚合 fixture + 运行记录 + Closure Record 草案 + 文档面三件;**零新模块、零修改既有面**(§D7 文件边界)。

**文档面路由(Assignment §3-4 强制单解,冻结)**:CR61-02 勘误 DR、CR70-03 术语表、CR70-02 文案边界注记三项,**作为 IP-0014 实现 PR 的 docs 子交付**随本 Packet 指定的 4 份 docs 文件一并合并(单 PR 单解),**不选择**先行独立 docs PR 路径。理由:(a) CRDISP-1 §4-1 将两条路径并列,但独立 docs PR 需另行 Maintainer 授权记账,单 PR 路由证据链最短;(b) 三项文本已在本 Packet 附录冻结全文,实现只是转写,无设计自由度;(c) Assignment 已把三项划入本 IP Allowed Files(docs 树)。此为唯一解,无竞争解。

---

## 1. 入口 Gate 结论(lifecycle,只读;@ main `31449ee`,P&V 实证 2026-09-12)

### 1.1 gates 表逐行核对(v47 → 实读)

对 #58 正文 v47 Integration/closure gates 表逐行清点:19 行中 **17 PASS recorded + 2 open**,与 Ledger v47 进度汇总逐字一致:

- 13 行 post-merge verification(IP-0001+R1、IP-0002..IP-0013):全部 `PASS recorded`,锚点 `a0b3eea`/`25f9aac`/`9078bb5`/`5984c5c`/`8afc594`/`78aa9d8`/`f3acc72`/`be1b890`/`207222d`/`b3627c2`/`3cba245`/`80feaea`/`31449ee`;
- consumer review ×4 行:`PASS recorded`(CRDISP-1,评论 5559621394/5559621866/5559627362/5559628163);
- PR3 行:`PASS recorded` @`b3627c2`;V5-FR-04 行:`PASS recorded` @`3cba245`;PR4 行:`PASS recorded` @`31449ee`;
- **open 仅 2 行**:跨 Artifact 集成 + 真实 Golden Path(UNMAPPED)、Issue Closure Audit + Closure Record(OPEN)——均即本 IP 交付面。

**结论:与 Ledger 无任何不符,无 Contract Gap,入口 Gate 通过。**

### 1.2 基线数字实测(worktree `D:\BaseAIProject\LIMA-ip-0014-pkt-wt` @ `31449ee`,P&V 亲跑)

```text
python -B -m pytest tests/contracts -q            → 585 passed(与 Assignment §5 基点一致)
python -B -m pytest tests -q                      → 929 passed, 1 skipped(基点一致;既有 skip 数不变)
python -B -m ruff check --no-cache lima/contracts tests/contracts
                                                  → exit 0 "All checks passed!"(限定口径;ruff cwd 条款:
                                                    一切验收命令在交付 worktree 内执行)
```

### 1.3 Golden Path 可达性探针(P&V 亲跑,阶段一取证;scratch,不入交付)

在基线 worktree 上以**纯冻结面**(compat + 各域 decode/encode + codec)端到端实跑:

1. legacy `Finding`/`ReviewReport`(经 `lima.models` 只读构造)→ `compat.finding_to_domain_bundle` → `EvidenceDomainBundle`;`compat.review_report_to_workflow_summary` → `source=LEGACY_AUDIT`/`SUCCEEDED` summary;round-trip `domain_to_finding(...).fingerprint == f.fingerprint` 恒等;bundle payload digest 经 `compute_content_digest(canonical_encode(...))` 稳定重算;
2. scenario fixtures(`scenario_no_hypothesis`/`verified`/`verified_patch`)经 `decode_*_payload(schema_version=SchemaVersion(4,0))` 全部还原为领域对象;
3. **digest 链对拍**:`digest(aep golden payload) == vep.source_aep.content_digest` = True;`digest(vep golden payload) == rvr.source_vep.content_digest` = True;
4. 负例探针:vep.source_aep.content_digest 换 `'z'*64`/短 hex/`schema_version='9.0'` → `ContractError` fail-closed;
5. **显式边界(非 Contract Gap,登记)**:把同格式合法的伪造 64-hex 填入 `source_aep.content_digest`,payload 层 decode **不拒绝**——这是冻结设计(payload 层只验格式/版本,跨 Artifact digest **存在性**核对是消费侧/聚合证据义务;与 CRDISP-1 对 #66 的 digest 语义裁定同向)。正因如此,IP-0014 的 Golden Path 测试必须**自身承担 digest 链聚合核对**(§D2),这正是本品交付价值。

---

## 2. Design Input Manifest

| Input ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001..003 | Standard/Charter | 稳定标准 / lifecycle / P&V 责任书 | main `31449ee` | 分工、拓扑、冻结纪律、阶段边界 | normative | — |
| DI-004 | Issue(Assignment) | PKT-IP-0014_PKT_ASSIGNMENT_DRAFT_2026-09-12(SHA-256 d74ca3a4…1e84) | 2026-09-12 | 范围/Not-covered、文档面三项路由、Checklist、Stop Conditions | normative | — |
| DI-005 | Issue | #58 正文 v47(SHA bb01da8a…20a5) | v47 | 20 需求行终态、gates 17/2 现状、Closure policy | normative | — |
| DI-006 | Decision | CRDISP-1 处置表(SHA 4b85b8b0…97ce) | 2026-09-11 | CR61-02/CR70-02/CR70-03 文本依据;9 CR 边界(不扩入) | normative | — |
| DI-007 | Decision | 全链 DR 正本 + PI-DR2/PI-DR3/AUDIT-3(ruff cwd)条款 + IP-0013 Packet(格式正本) | 历次 | 条款沿用、Packet 结构先例 | normative | — |
| DI-008 | Upstream IP | IP-0001..0013 Packets + Ledger IP registry | #97..#144 | 各 PR/merge SHA、双验证记录(Closure Audit 证据锚点) | normative | — |
| DI-009 | Architecture | `lima/contracts/` 十三模块 + compat + `schemas/v4/`(14 schema + matrix)+ ADR 0027 | main `31449ee` | 全部冻结面(本 IP 唯一消费面) | normative | — |
| DI-010 | Test | `tests/contracts/` 全部 + fixtures(含 scenarios/ ×6、compat 5 fixture) | main `31449ee` | 585 基线、golden 钉死模式、import isolation 模式 | current-behavior | — |
| DI-011 | Evidence | 本 IP 基线复现 + Golden Path 可达性探针(§1.2/§1.3,P&V worktree 实跑) | 2026-09-12 | 数字基点、digest 链可行、fail-closed 负例、显式边界 | evidence | — |

### Explicitly Rejected Inputs

| 材料 | 拒绝原因 |
|---|---|
| 修改十四模块任何正文/`__all__`/枚举以"让集成更顺" | 冻结面禁改(Stop Condition);探针已证纯冻结面可达,无 gap 可修 |
| 为 Golden Path 新增 wire schema/新错误码/新枚举 | 本 IP 零语义变更;集成是组合消费,不是新契约 |
| 在 payload 层给 `source_aep`/`source_vep` 加跨 Artifact digest 存在性校验 | 冻结设计把存在性核对留给消费侧(§1.3-5);改它 = 语义变更;聚合核对由本 IP 测试承担 |
| 把 20 行 SATISFIED 改写为"由 IP-0014 重新证明" | v47 证据链已闭合;本 IP 只做终态审读聚合,不重复实现 |
| 把 CR60-01/CR61-01/CR70-01(RAM 图/Oracle 建议/severity)纳入本品 | CRDISP-1 裁定"不属于本轮",归各 owner 独立后续 IP |
| 借 Closure Record 直接宣布 #58 关闭 | Closure policy = MANUAL-AFTER-POST-MERGE-AUDIT;关闭操作不在本 IP |
| 引入 DB/Docker/LLM/网络/生产服务 | AC-04 依赖隔离;Golden Path 与 AC-04 一致(fixture 驱动) |
| 修改既有 29 fixture/6 scenario/任何既有测试 | 全部 Read-only/Must-not-modify(§D7) |

---

## 3. Iteration Hypothesis 与 Measurement

### 3.1 Hypothesis

如果把跨 Artifact 集成表达为"真实 fixture 驱动、digest 链逐跳对拍、全部经 IP-0001 codec 实算"的端到端测试(legacy → compat → evidence → aep → vep → rvr → workflow/execution → summary 双终点),把 Closure Audit 表达为对 v47 已有证据锚点的逐行机器可查审读(每行带 PR/merge SHA 与可重跑命令),且两项均可由第三方在干净 worktree 用单一命令复现,那么"#58 关闭前最后两门禁"从主观判断变成可复核证据,Gates 表 2 open 即可归零候选。

### 3.2 Measurement

- contracts 由 585 增至 585+N(N ≥ 20,精确值阶段二钉死),0F;全量由 930(929+1 skip)增至 930+N,0F,既有 skip 数不变;
- digest 链:Golden Path fixture 内每一跳引用 digest(vep.source_aep、rvr.source_vep、summary typed links)与被引 artifact payload 的 codec 重算 digest **逐项相等**(机器断言,非文档约定);
- 负例:格式坏 digest、major 不匹配、legacy_audit 携带 typed link、CHAIN summary 缺 run_manifest 等 ≥6 类在冻结契约处 fail-closed;
- 复现性:Golden Path 运行记录(§D3)含命令、commit SHA、环境、逐 artifact payload digest(64-hex)、fixture 文件 SHA-256;第三方重跑输出全等;
- Closure Record:20 需求行 + 17 gates 行逐行有 SATISFIED/PASS 锚点(SHA + 证据文件),无 TBD。

---

## 4. Goal

交付:(a) 跨 Artifact 集成测试 2 个文件 + Golden Path 聚合 fixture 2 份;(b) Golden Path 运行记录 docs 1 份;(c) Closure Record 草案 docs 1 份(20 行终态审读表 + 17 gates 行);(d) 文档面三件(术语表含 CR70-02 注记、CR61-02 勘误 DR)。共恰 8 文件(4 code/fixture + 4 docs)。

## 5. Non-goals

任何 wire 变更;生产接线(#68);下游 Issue 实现;#58 关闭操作;十四模块/既有测试/既有 fixture/PR3 产物/legacy 源/frontend/pyproject/Dockerfile 修改;新模块/新 schema/新错误码;envelope 层新约束;runtime/持久化/网络/LLM。

---

## 6. 工作树与分支前置条件

Coding Agent 必须:完整阅读稳定标准、lifecycle、Implementation Agent 责任书、本 Packet、`LIMA_Coding_Agent_IP-0014_正式开发任务交接.md`、CONTRIBUTING.md;确认两份 IP-0014 文档均已合并 `origin/main`;依 lifecycle §9.1 从 Frozen Test Commit(阶段二交付物指定 SHA)派生 `codex/ip-0014-closure-integration` 独立干净 worktree(禁共享根与既有 worktree);确认 §D7 的 8 个 Add 文件尚不存在且十四模块 `__all__` 计数与 §D6 零漂移表一致;输出 Scope Confirmation 后再跑 baseline;不一致即停提交 Decision Request。根工作树未跟踪文件属用户资产,不得触碰。

---

## 7. 决策 D1(§5-1):跨 Artifact 集成测试矩阵(冻结单解)

十四模块真实组合面,以"链段 + 切面"双维组织;**全部消费真实 fixture**(既有 golden/scenarios/compat fixtures + 本 IP 新增 2 份聚合 fixture),全部 digest 经 `lima.contracts.codec.compute_content_digest`:

| # | 链段/切面 | 模块组合 | 断言要点(冻结) |
|---|---|---|---|
| M1 | legacy 入口 | models(只读)→ compat → evidence | finding→bundle 结构(1 Signal/1 Issue/1+N ev)、identity 派生恒等、round-trip fingerprint 恒等、bundle payload digest codec 重算全等 |
| M2 | legacy 审计终点 | models → compat → summary | report→summary 恒 `LEGACY_AUDIT`+`SUCCEEDED`、legacy_artifact_ids 排序去重、typed links 结构性为 None |
| M3 | 静态域 → 审计 | evidence(bundle)→ aep | aep.evidence_domain 内嵌 bundle 一致性;aep.repository_profile_artifact_ids 引用 profile |
| M4 | 审计 → 验证 | aep → vep | **digest 链对拍**:`compute_content_digest(canonical_encode(encode_aep_payload(aep))) == vep.source_aep.content_digest`;source_aep_revision 语义 |
| M5 | 验证 → 修复验证 | vep → rvr | **digest 链对拍**:`digest(vep payload) == rvr.source_vep.content_digest`;candidates 引用 hypothesis;双 Gate(functional/security)× candidate 矩阵 |
| M6 | 执行脊柱 | workflow + execution | Workflow→StageAttempt→SecurityOutcome 编排;Plan/RunManifest 的 ArtifactLink 引用形态 |
| M7 | 链终点 | workflow/execution/rvr/evidence → summary | CHAIN summary 携带 typed links(workflow/security_outcome/run_manifest/stage_attempts/evidence);六场景 summary 与 outcome 的 kind↔source 映射逐场景断言(scenarios ×6) |
| M8 | codec 贯穿 | codec × 全部 14 面 | 同一 payload 在 encode→canonical_encode→digest 与 decode 往返的稳定性;十四模块 schema_name 与 schemas/v4 ×14 对表 |
| M9 | 矩阵切面 | schemas/v4 matrix + compat | version_compatibility_matrix.json 逐 schema 行为与实测一致;compat 输入 current/future-minor 行为回归锚定 |

**负例矩阵(≥6 类,全部断言既有错误码,零新增)**:source digest 坏 hex(`INVALID_FIELD_VALUE`)、source digest 短 hex、source schema_version major 不匹配、legacy_audit 携带 typed link(`INVALID_FIELD_VALUE`)、CHAIN summary 缺必填 typed link、跨场景 outcome/summary 错配(如 no_hypothesis 场景携带 vep)。负例以测试内联向量交付,fixture 不含非法输入(先例)。

## 决策 D2(§5-2):真实 Golden Path 端到端可复现运行记录形态(冻结单解)

**双 Golden Path(单解)**:
- **Path A(链路径)**:profile → aep → vep → rvr → workflow/stage_attempts/security_outcome → CHAIN WorkflowSummary——fixture 组装自既有 golden/scenarios 的真实 payload,新增聚合 fixture `integration/golden_path_chain_v4_golden.json` 固化"逐 artifact payload + 逐跳引用 digest"的完整快照(内容 = 各 hop payload dict + 全部 digest 值,由 codec 实算,字节钉死);
- **Path B(legacy 路径)**:legacy ReviewReport → compat → EvidenceDomainBundle + LEGACY_AUDIT WorkflowSummary →(反向)Finding round-trip——聚合 fixture `integration/golden_path_legacy_audit_v4_golden.json`。

**运行记录形态(冻结字段,实现转写为 `docs/LIMA_IP-0014_Golden_Path_Run_Record.md`)**:
1. 复现命令(逐字):`python -B -m pytest tests/contracts/test_integration_golden_path.py -v` 与 `python -B -m pytest tests/contracts -q`;
2. 执行基线 commit SHA(实现 Final SHA)+ 环境(Python/ruff/OS 版本);
3. 逐 hop 表:artifact 名 → payload digest(64-hex)→ 引用核对结果(==);
4. 两份聚合 fixture 的文件 SHA-256;
5. 测试计数与全部 PASS 行。

**可复现判定**:第三方在干净 worktree @Final SHA 重跑命令,输出与记录逐字段一致(digest 全等)。**实现禁令**:记录中的任何 digest 不得手写,必须由运行时计算转写(测试内以 digest 对拍断言兜底)。

## 决策 D3(§5-3):Closure Audit 20 需求行终态审读清单(冻结单解)

交付 `docs/LIMA_IP-0014_Closure_Record.md`,结构冻结为两部分(模板 = 本 Packet 附录 A 全文,实现只转写证据列,零设计自由度):

1. **20 需求行终态审读表**:FR-01..FR-06、NFR-01/02、AC/T-01..04、V5-FR-01..05、V5-AC/T-01..03——每行五列:Requirement / v47 终态(SATISFIED-BY-EVIDENCE) / 证据锚点(PR# + merge SHA + 双验证记录文件) / 可复核命令 / 审读结论(SATISFIED 确认或例外);
2. **17 gates 行终态表**:逐 gate 的 PASS 锚点(同 v47 gates 表) + 本 IP 关闭 2 open 行的证据指针(Golden Path 运行记录 + 本 Closure Record)。

Closure Record 为**草案**——终局 Closure Audit 裁定与 #58 关闭由 Coordinator/Maintainer 按 MANUAL-AFTER-POST-MERGE-AUDIT 执行,本文件不宣布关闭(文首必须含此声明)。

## 决策 D4(§5-4a):CR61-02 勘误 DR 文本(冻结全文)

交付 `docs/LIMA_DR_CR61-02_D2状态矩阵语义勘误.md`,正文逐字 = 本 Packet **附录 B**。核心语义:IP-0002 冻结的静态状态矩阵(`has_d2_supports`/`has_d2_refutes` → `statically_supported`/`statically_refuted`/`conflicting_static_evidence`/`insufficient_static_evidence`)为 **D2-only 设计**;D1 及以下等级的反证不参与该矩阵判定(混合等级如 D2-support + D1-refute → `statically_supported` 是设计行为,非缺陷);D1 及以下反证的保留与其向 `inconclusive` 的输出是 **#61 消费侧义务,不经该矩阵表达**;若未来要改 wire 矩阵语义,须新 major + ADR(另行独立后续 IP,禁止原地修改 4.0)。

## 决策 D5(§5-4b):CR70-03 层次化术语表 + 前端 unknown 降级规则(冻结单解)

交付 `docs/LIMA_V4_契约层次化术语表与前端unknown降级规则.md`,**内含 CR70-02 文案边界注记节**(三项文档面合为两份 docs 文件 + 运行记录/Closure Record 共 4 份,见 §D7)。内容结构冻结(全部词条实测自 @`31449ee` 词表,附录 C 给出全部词条清单):

1. **静态层**(evidence):`HypothesisStatus` 五值(proposed/statically_supported/statically_refuted/conflicting_static_evidence/insufficient_static_evidence)、`EvidenceLevel` D0–D4、`EvidencePolarity` wire 仅 supports/refutes(无通用 inconclusive——消费注意事项,源自 CRDISP-1 非 CR 级 #61 条目);
2. **验证层**(vep):`VerificationVerdict` 四值(candidate/inconclusive/refuted_scope/verified)——与静态层不可混用:`hypothesis_not_reproduced`(SecurityOutcomeKind)≠ 已反驳(statically_refuted/refuted_scope);静态冲突五值 ≠ VEP inconclusive;
3. **修复验证层**(rvr):`CandidateVerdict` 三值 + `GateKind` 恰两值;**CR70-02 文案边界注记(逐字入表)**:"RVR 的'逐候选逐 Gate'以已冻结的两类**汇总 Gate**(functional_preservation / security_preservation)满足(CRDISP-1 亲验 rvr.py L229 枚举两值、L529 `len(self.gates) != 2` 强制);步骤级展示(编译/测试/PoC 逐步)不属于 #58 冻结面,归 #77/#91 后续";
4. **结论层**(summary/workflow):`SummarySourceKind`(chain/legacy_audit)互斥与 V5-FR-05 迁移禁映射、`SecurityOutcomeKind` 十二值与六场景映射、sealed AEP revision vs 最新 workflow revision 一致性属消费义务(#70 非 CR 级条目);
5. **前端 unknown 降级规则**:severity 在权威 producer/API 冻结前(#90/#91/#70 后续 IP),前端一律显示 unknown/未提供,禁止从现有契约字段伪派生(CRDISP-1 CR70-01 裁定)。

## 决策 D6(§5-5):冻结接口零漂移表(实现前置核对项)

十四面 `__all__` 计数(@`31449ee` 实测,实现开工须逐项复验一致):common 10、evidence 16、profile 15、aep 12、vep 12、rvr 12、workflow 27、execution 16、summary 19、manifests 28、codec 6、errors 2、compat 恰 8 symbols(`LEGACY_REASON_CODE`/`LEGACY_SENTINEL`/`LEGACY_SOURCE_ARTIFACT_ID`/`UNMAPPED_FROZEN_FIELDS`/`UNMAPPED_LEGACY_FINDING_FIELDS`/`domain_to_finding`/`finding_to_domain_bundle`/`review_report_to_workflow_summary`)+ `__init__` 18-symbol 冻结面;schemas/v4 = 13 schema + version_compatibility_matrix.json。本 IP 对以上**全部只读**;`decode_*_payload` 签名统一为 `(value, *, schema_version: SchemaVersion)`、`encode_*_payload` 为 `(domain) -> dict`(探针实测口径)。

## 决策 D7(§5-6):文件边界(恰好 8 个 Add,零 Modify)

### Files to Add
```text
tests/contracts/test_integration_golden_path.py
tests/contracts/test_integration_cross_module.py
tests/contracts/fixtures/integration/golden_path_chain_v4_golden.json
tests/contracts/fixtures/integration/golden_path_legacy_audit_v4_golden.json
docs/LIMA_IP-0014_Golden_Path_Run_Record.md
docs/LIMA_IP-0014_Closure_Record.md
docs/LIMA_V4_契约层次化术语表与前端unknown降级规则.md
docs/LIMA_DR_CR61-02_D2状态矩阵语义勘误.md
```

### Read-only
十四模块全部、`lima/models.py`、既有全部测试/fixture/scenarios、schemas/v4 全部、ADR 0027。

### Must-not-modify
`lima/contracts/` 既有正文、schemas/v4 既有产物、frontend/、pyproject.toml、Dockerfile、store/queue/service/api/scanner/Sandbox、`.github/`。

## 决策 D8(§5-7):测试矩阵与命令(冻结类别与下限;精确 N 阶段二钉死)

| 文件 | 类别 | 下限 | 要点 |
|---|---|---|---|
| test_integration_golden_path.py | Path A 链路径 | 8 | §D2 Path A 逐 hop decode → digest 链逐跳对拍(≥4 跳)→ CHAIN summary typed links 齐备;聚合 fixture 字节钉死 + 全部 digest codec 重算全等 |
| test_integration_golden_path.py | Path B legacy 路径 | 5 | §D2 Path B 全链 + round-trip 恒等 + LEGACY_AUDIT 唯一值 + legacy_artifact_ids 排序去重;聚合 fixture 字节钉死 |
| test_integration_golden_path.py | 负例(§D1 负例矩阵) | 6 | ≥6 类,逐类断言 code(既有 29 之内)与 field_path |
| test_integration_cross_module.py | §D1 矩阵 M1..M9 | 9 | 每链段/切面 ≥1 用例;M7 六场景 outcome↔summary 映射逐场景断言(可并入 1 用例内 6 断言组) |

**命令与预期数字(验收一律在交付 worktree 内执行——ruff cwd 条款/AUDIT-3)**:
```text
python -B -m pytest tests/contracts -q   # 预期 585+N passed(0F;N ≥ 20 由冻结提交钉死)
python -B -m pytest tests -q             # 预期 929+N passed, 1 skipped
python -B -m ruff check --no-cache lima/contracts tests/contracts
                                          # 预期 exit 0(限定口径,与基线同式)
```

## 决策 D9(§5-8):CI 测试面(十一项 Checklist 第 11 条)

新增 code 文件全部落于既有顶层路径 `tests/contracts/`(+ 新子目录 `tests/contracts/fixtures/integration/`,仍处 `tests` COPY 白名单内);docs 文件不进 CI 测试面。Dockerfile L45 `COPY tests ./tests` 已覆盖子目录,**零 Dockerfile 变更,无需 DR**。

## 决策 D10(§5-9):环境记录

Windows 10 26200 + Git Bash;Python 3.12;pytest/ruff 经 `python -B -m`;基线命令与数字见 §1.2/§D8;worktree `D:\BaseAIProject\LIMA-ip-0014-pkt-wt` 实测。零 DB/Docker/LLM/网络介入(AC-04)。

---

## 10. PI-DR2:Packet 起草期逐断言自检记录(随 Packet,阶段一交付)

1. 数字基点"585 / 929+1 skip / ruff exit 0"——本 worktree @ `31449ee` 亲跑(§1.2),非转抄;
2. "gates 17 PASS/2 open"——对 v47 gates 表逐行清点(§1.1),17+2=19 行齐;
3. 十四模块 `__all__` 计数(§D6)——逐模块 import 实测清点,compat 8 symbols 与 IP-0013 Packet/PR #144 冻结面逐字对齐;
4. 全部词表(附录 C)——@`31449ee` 逐枚举实测(`[e.value for e in Enum]`),非记忆转写;CR70-02 的"rvr.py L229 两值 / L529 强制"采信 CRDISP-1 亲验记录并注明来源;
5. Golden Path 可行性——§1.3 探针在基线代码端到端实跑(digest 链两次 True、负例三类 fail-closed、round-trip 恒等),非纸面推导;"同格式伪 digest 不被 payload 层拒绝"亦为实测发现,已按冻结设计登记为显式边界而非缺陷;
6. 20 需求行终态(附录 A)——逐行转录 v47 Requirement coverage 表,零改写终态与锚点;
7. `decode_*_payload`/`encode_*_payload` 签名口径——inspect 实测(§D6);Packet 内命令均含 `-B` 与 worktree 口径(混层文本零容忍)。

## PI-DR3 与 ruff cwd 条款登记

PI-DR3(scratch GREEN 门禁永久化):阶段二 RED 前必须先在 scratch 位置证明被测实现路径 GREEN,防 RED 掩蔽;本 Packet 授权阶段二执行时逐字适用。ruff cwd 条款(AUDIT-3):全部验收命令在交付 worktree 内执行,仓库级裸命令结果不作证据。

---

## 11. 十一项强制 Checklist(阶段一登记;2-10 阶段二启用)

| # | 项 | 阶段一状态 |
|---|---|---|
| 1 | 实例化镜像 | 阶段二启用(集成测试 arrange = 既有 fixture payload 实例化,§1.3 探针已镜像) |
| 2 | 传输点零 PR | 阶段二启用(docs-only PR 即本轮先例) |
| 3 | symbols 计数 | **阶段一已冻结**:本 IP 零新模块,核对项 = §D6 十四面零漂移表 |
| 4 | helper 忠除实性 | 阶段二启用(digest 链 helper 不得静默规范化被引 digest) |
| 5 | 调用点签名兼容 | 阶段二启用(decode/encode 签名口径已冻结 §D6) |
| 6 | None 哨兵 | 阶段二启用(LEGACY_AUDIT summary None/() 哨兵已冻结) |
| 7 | GREEN 态冷缓存门禁 | 阶段二启用(ruff --no-cache 已入 §D8) |
| 8 | 负例生证 | 阶段二启用(负例类别已冻结 §D1;§1.3 探针已首战 3 类) |
| 9 | 跨用例期望一致性 | 阶段二启用(同 (路径, wire 值) 期望码一致扫描) |
| 10 | lineage 对拍 | **阶段一已实证**(§1.3 digest 链对拍 = 本 IP 核心断言形态;阶段二扩展到聚合 fixture 全部 hop) |
| 11 | CI 测试面新路径核对 | **阶段一已完成:PASS**,零 Dockerfile 变更(§D9) |

## 12. Stop Conditions(沿用 Assignment §9-§10,逐字有效)

不修改十四模块/既有测试/既有 fixture/PR3 产物/legacy 源;不实现生产接线/下游 Issue;不关闭 #58;不做 wire 变更。特别地:任一设计问题两解;Golden Path 在实现期发现冻结面不可达(探针已证可达;若复现即 Contract Gap);聚合 fixture digest 无法由 codec 复现;基线前移;文档面三项文本与 CRDISP-1 处置结论冲突——任一发生即停提交 Decision Request(`.pv_tmp/` 文件 + 回报双通道),保留现场。

## 13. 完成定义

阶段二 RED 冻结(585+N / 930+N 数字钉死,scratch GREEN 先行)→ IMPL 交付恰 8 文件 → 独立验证三态结论 → fast-forward → Implementation PR(lifecycle §12.2,`Related to #58`,禁 auto-close)→ post-merge。gates 2 open 行关闭与 #58 终局关闭由 Coordinator 按 MANUAL-AFTER-POST-MERGE-AUDIT 裁定,不由本 Packet 宣布。

---

## 附录 A:Closure Audit 20 需求行终态审读表(模板 = 实现转写依据;锚点转录自 v47)

| Requirement | v47 终态 | 证据锚点(PR/merge SHA) | 可复核命令 | 审读结论(实现填) |
|---|---|---|---|---|
| FR-01 三对象分离 | SATISFIED-BY-EVIDENCE | #100/`4fe1def`;PASS v1+v2 | pytest tests/contracts/test_evidence.py -q | (SATISFIED 确认) |
| FR-02 RAM/AEP/VEP/RVR + manifests | SATISFIED-BY-EVIDENCE | #104/#107/#110/#113/#141;`9078bb5`/`5984c5c`/`8afc594`/`57dc1ab`/`80feaea` | pytest tests/contracts -q | 同上 |
| FR-03 D0–D4 与合法映射 | SATISFIED-BY-EVIDENCE | #100、#110/`8afc594`、#113/`57dc1ab` | 同上 | 同上 |
| FR-04 canonical codec | SATISFIED-BY-EVIDENCE | #98、#102/`a0b3eea`(v2) | 同上 | 同上 |
| FR-05 fixtures + legacy adapter | SATISFIED-BY-EVIDENCE | #98..#135、#144/`31449ee` | 同上 | 同上 |
| FR-06 兼容矩阵 | SATISFIED-BY-EVIDENCE | #133/`b3627c2`(15 digest 复核) | 同上 | 同上 |
| NFR-01 fail-closed + 非结论词表 | SATISFIED-BY-EVIDENCE | #98..#107、#131/`207222d` | 同上 | 同上 |
| NFR-02 校验上限与错误码 | SATISFIED-BY-EVIDENCE | #98、#102/`a0b3eea` | 同上 | 同上 |
| AC-01/T-01 canonical golden | SATISFIED-BY-EVIDENCE | #98、#102/`a0b3eea` | 同上 | 同上 |
| AC-02/T-02 安全矩阵 | SATISFIED-BY-EVIDENCE | #98、#100、#102 | 同上 | 同上 |
| AC-03/T-03 future-minor + legacy 可读 | SATISFIED-BY-EVIDENCE | #98、#100、#144/`31449ee` | 同上 | 同上 |
| AC-04/T-04 依赖隔离 | SATISFIED-BY-EVIDENCE | #98、#100、#102 | 同上 | 同上 |
| V5-FR-01 八 schema 全集 | SATISFIED-BY-EVIDENCE | #104、#127/`f3acc72`、#129/`be1b890`、#131/`207222d` | 同上 | 同上 |
| V5-FR-02 Hypothesis 三必带字段 | SATISFIED-BY-EVIDENCE | #100/`4fe1def` | 同上 | 同上 |
| V5-FR-03 VEP Oracle + RVR per-Gate | SATISFIED-BY-EVIDENCE | #110/`8afc594`、#113/`57dc1ab` | 同上 | 同上 |
| V5-FR-04 六状态场景 fixtures | SATISFIED-BY-EVIDENCE | #135/`3cba245`(6 digest 复核) | 同上 | 同上 |
| V5-FR-05 禁自动迁移 | SATISFIED-BY-EVIDENCE | #131/`207222d`、#144/`31449ee` | 同上 | 同上 |
| V5-AC-01/T-01 全 workflow fixtures | SATISFIED-BY-EVIDENCE | #104..#131/`207222d` | 同上 | 同上 |
| V5-AC-02/T-02 禁映射 + 词表不相交 | SATISFIED-BY-EVIDENCE | #131/`207222d` | 同上 | 同上 |
| V5-AC-03/T-03 缺项 fail closed | SATISFIED-BY-EVIDENCE | #110、#113 | 同上 | 同上 |

(实现另附 17 gates 行终态表,形态同 v47 gates 表 + 本 IP 两行关闭指针;Closure Record 文首含"草案,终局裁定归 Coordinator/Maintainer,MANUAL-AFTER-POST-MERGE-AUDIT"声明。)

## 附录 B:CR61-02 勘误 DR 全文(冻结;实现逐字转写)

```markdown
# DR-CR61-02:静态状态矩阵 D2-only 语义勘误(文档面,零代码变更)

- 编号来源:CRDISP-1 处置表 §1 第 4 行(CR61-02,consumer review #61 回复,
  评论 5559621866);裁定:需要补齐(文档勘误),不阻塞 #58 关闭。
- 对象:`lima/contracts/evidence.py` 静态状态矩阵——`has_d2_supports`/`has_d2_refutes`
  仅统计 D2 等级证据,决定 `HypothesisStatus` 的
  statically_supported / statically_refuted / conflicting_static_evidence /
  insufficient_static_evidence 四值判定。
- 语义澄清(单解):该矩阵为 **D2-only 设计**(IP-0002 冻结面,`207222d`→`31449ee`
  零修改)。D1 及以下等级的反证**不参与**该矩阵判定:混合等级组合
  (如 D2-support + D1-refute)输出 `statically_supported` 是设计行为,非缺陷。
  D1 及以下反证的保留,以及据此向验证层 `inconclusive` 的输出,是 **#61 消费侧义务,
  不经该矩阵表达**。
- 后续约束:若未来需要把混合等级语义编入 wire 矩阵,必须新 major + ADR
  (独立后续 IP,经 Coordinator 批准),禁止原地修改 4.0。
- 证据:evidence.py @`0c560df` L1472-1486(CRDISP-1 亲验)+ 可复现反例
  (D2-support + D1-refute → statically_supported,与代码一致)。
```

## 附录 C:层次化术语表全部词条清单(冻结;@`31449ee` 逐枚举实测)

| 层 | 枚举 | 值(逐字) |
|---|---|---|
| 静态层(evidence) | EvidenceLevel | D0, D1, D2, D3, D4 |
| 静态层 | EvidencePolarity | supports, refutes |
| 静态层 | EvidenceSubjectKind | signal, security_issue, vulnerability_hypothesis |
| 静态层 | HypothesisStatus | proposed, statically_supported, statically_refuted, conflicting_static_evidence, insufficient_static_evidence |
| 静态层 | RequiredProofKind | runtime_behavior, static_property, configuration_state, external_manual_required |
| 验证层(vep) | VerificationVerdict | candidate, inconclusive, refuted_scope, verified |
| 修复验证层(rvr) | GateKind | functional_preservation, security_preservation |
| 修复验证层 | CandidateVerdict | verified_patch, rejected, inconclusive |
| 结论层(summary) | SummarySourceKind | chain, legacy_audit |
| 结论层 | ExecutionStatus | succeeded, failed, cancelled |
| 结论层(workflow) | SecurityOutcomeKind | no_supported_attack_surface, no_actionable_hypothesis, mining_skipped_by_request, mining_skipped_by_policy, mining_blocked_environment, hypothesis_not_reproduced, vulnerability_verified, repair_unsupported, repair_blocked_environment, no_candidate_passed, verified_patch, full_chain_incomplete |

层次规则(冻结入表):静态层五值 ≠ 验证层四值,不可互换解读;`hypothesis_not_reproduced`(未复现)≠ 已反驳(statically_refuted / refuted_scope);`inconclusive` 仅存在于验证/修复验证层,静态层无通用 inconclusive(静态侧以 conflicting/insufficient 表达);legacy_audit 与 chain 结构性互斥(V5-FR-05);severity 冻结面不存在——前端一律 unknown/未提供。

---

*签发:LIMA P&V Agent,2026-09-12(入口 Gate + Golden Path 可达性实证;基线 main @ `31449ee2c05a08c0ab8e8070d66d30016071ad1e`;Assignment SHA-256 `d74ca3a4318d8ef95ee536852fc61cd36db378e04377a9b0d24d1dd8391e3e84` 核验一致;#58 v47 body SHA `bb01da8a…20a5` 核验一致;CRDISP-1 SHA `4b85b8b0…97ce` 核验一致)。*
