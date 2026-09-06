# LIMA Implementation Packet IP-0011:V5-FR-04 场景 fixtures(六状态跨 Artifact 组合)

> Packet ID:`IP-0011`
>
> 状态:`DESIGN-FROZEN / READY-FOR-CODE WHEN THIS PACKET IS MERGED TO MAIN`
>
> Source Issue:[#58](https://github.com/agent-sec-labs/LIMA/issues/58) 的第十一个独立实现切片(integration 角色:聚合 fixture 证据,零新 schema、零运行时)
>
> 最低代码基线:Assignment 基线 `b3627c299af170e9cb22c6e3cccb9d4c255b8844`(IP-0010 PR #133 squash);实现基线 = 含本 Packet 与正式交接书的最新 `origin/main`
>
> 推荐分支:`codex/ip-0011-scenario-fixtures`(依 lifecycle §9.1 从 Frozen Test Commit 派生)
>
> Owner:唯一 Implementation Agent;不触碰 `lima/contracts/` 十一模块、PR3 产物与任何既有测试/fixture

## 需求映射(Header)

```text
Source Issue:#58
Issue specification revision:正文修订 2026-09-01T14:36:22Z(V4 + V5 覆盖层);
  Delivery Ledger v41 @ 2026-09-06T13:57:09Z(定序:IP-0011 = V5-FR-04)
Covered requirements:V5-FR-04(fixture 覆盖 no-hypothesis、blocked、refuted、verified、
  unsupported、verified-patch 六状态——每状态 ≥1 组 golden-grade 跨 Artifact 组合 fixture +
  校验测试,真实 digest 链贯穿);FR-05(fixture 子集);V5-FR-01 聚合证据面补强(六状态链一致性)
Not covered requirements:manifests 子集(IP-0012 候选);PR4 legacy adapter;closure IP(真实
  Golden Path 运行记录与 Closure Audit);十一模块与 PR3 产物修改;#90/#68 runtime;
  consumer review ×4 调度
Delivery role:integration
Issue closure impact:PARTIAL(合并后 V5-FR-04 由 UNMAPPED 转 SATISFIED;#58 保持 open)
Upstream IP/PR/merge commits:IP-0001..0010 全链(#97..#133;冻结面
  18/16/15/12/12/12/27/16/19/29 + 十七 golden + 15 PR3 产物,全部 IP-DONE)
Activation gate:lifecycle 入口 consumer review(见 §1,已完成,无 Contract Gap)
```

---

## 0. 执行决策

当前执行队列(Ledger v41):NOW = IP-0011;NEXT = IP-0012 候选(manifests);LATER = PR4/closure/consumer review 调度。本 Packet 只交付静态场景 fixture 及其校验测试。

---

## 1. 入口 Gate 结论(lifecycle,只读;@ main `b3627c2`,P&V 实证 2026-09-06)

### 1.1 PR3 产物集 consumer review(Assignment §4-1)

- **裁定:六状态 fixture 的校验路径 = 模块 decode 全链(唯一主路径)**。论证:六状态本质是**跨字段语义状态**(aep outcome × eligibility、vep verdict 矩阵、so kind 证据耦合、summary 来源互斥)——PR3 schema 按 ADR 0027 决策 6/7 **有意不表达**跨字段不变量(locus = module);schema 面校验无法区分 no-hypothesis 与 verified(同为合法结构)。PR3 mini-validator 仅作补充性结构断言(每 payload 顶层结构合法),不作状态判定。此为单解,无双轨。
- PR3 schema 面覆盖度:13 schema 的 properties/required 完全覆盖六状态 bundle 的全部 payload 键(实测);矩阵 5 行为与 fixture 校验正交(不冲突)。

### 1.2 六状态可达性盘点(Assignment §4-2;全部经模块 decode 实证)

| 状态 | 表达组合(最小) | 冻结面标记 | 实证 |
|---|---|---|---|
| no-hypothesis | aep 变体 + security-outcome + workflow-summary | aep.audit_outcome=no_actionable_hypothesis + eligibility 空;so.kind=no_actionable_hypothesis(证据矩阵:AEP 必需/VEP+RVR 禁止);summary chain/succeeded | decode OK |
| blocked | stage-attempt + failure-report + security-outcome + workflow-summary | attempt.status=blocked+failure_kind;fr.environment/transient;so.kind=mining_blocked_environment(AEP 必需);summary chain/**failed** | decode OK |
| refuted | vep 变体 + security-outcome + workflow-summary | vep.verdict=**refuted_scope**(矩阵:D4 polarity=refutes + refutation_scope 字符串);so.kind=hypothesis_not_reproduced(VEP 必需/RVR 禁止);summary chain/failed | decode OK |
| verified | vep golden + security-outcome + workflow-summary | vep.verdict=verified(golden 原样);so.kind=vulnerability_verified(VEP 必需/RVR 禁止);summary chain/succeeded | decode OK |
| unsupported | vep golden + security-outcome + workflow-summary | so.kind=repair_unsupported(VEP 必需/RVR 禁止);summary chain/failed | decode OK |
| verified-patch | **rvr + security-outcome + workflow-summary 全部复用既有 golden** | rvr 含 verified_patch 候选;so.kind=verified_patch(RVR 必需);summary chain/succeeded(golden 三件即本状态) | decode OK |

**结论:六状态全部可达,无 Contract Gap。** 预冻结自证抓到并解决两处构造陷阱(如实记录,防 IMPL 重蹈):① aep 的 no_actionable_hypothesis 态要求 hypothesis.status 与支撑证据 polarity 一致——合法最小编辑 = D2 支撑记录 polarity 翻 refutes + hypothesis.status=statically_refuted(直接改 status 为 insufficient 会因 evidence_ids 绑定校验失败);② vep refuted_scope 态要求 D4 证据 polarity=refutes(仅改 verdict 触发矩阵拒绝)。

### 1.3 十二模块适用面

common/codec/errors 直接消费;evidence 经 aep 内嵌;profile(本六状态最小组合不含独立 profile artifact——aep 的 profile 引用保留在 golden 内容内);aep/vep/rvr/workflow/execution/summary 经各 bundle 键 decode;PR3 schema 作补充结构面。**无需 import 任何新依赖。**

---

## 2. Design Input Manifest

| Input ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001..003 | Standard/Charter | 稳定标准/lifecycle/P&V 责任书 | main `b3627c2` | 分工、拓扑、冻结纪律 | normative | — |
| DI-004 | Issue(Assignment) | PKT-IP-0011 Assignment | Ledger v41 | 覆盖/不覆盖、§5 七问、十一项 Checklist | normative | — |
| DI-005 | Issue | #58 正文 V5 节 | `2026-09-01T14:36:22Z` | V5-FR-04 六状态定义、FR-05 | normative | — |
| DI-006 | Issue(Ledger) | #58 Ledger v41 | 2026-09-06 | 定序、基线数字 | normative(current) | — |
| DI-007 | Decision | 全链 DR 正本(9 条 + DR-IP-0010-CI-01) | 历次 | Checklist 渊源、容器镜像教训 | normative | — |
| DI-008 | Upstream IP | IP-0001..0010 Packets | #97..#133 | 十七 golden 内容、verdict 矩阵、outcome 耦合、来源互斥 | normative | — |
| DI-009 | Code | 十一模块 | main `b3627c2` | decode 入口、词表 | current-behavior | — |
| DI-010 | Evidence | 六 bundle 设计期产物 `.pv_tmp/IP-0011_ARTIFACTS/`(6 文件) | 2026-09-06 | 权威 bytes/digest(§7);全 decode + 链自证 PASS | evidence | 语义以模块为准 |
| DI-011 | Test | tests/contracts + PR3 schema 面测试 | main `b3627c2` | mini-validator 复用先例 | current-behavior | — |
| DI-012 | Architecture | V5 规划文档 | 本地 | 六状态语境(background) | background-only | — |

### Explicitly Rejected Inputs

| 材料 | 拒绝原因 |
|---|---|
| 以 PR3 schema 校验替代模块 decode 作状态判定 | 六状态 = 跨字段语义,schema 有意不表达(ADR 0027 决策 6/7;§1.1 单解) |
| 新增 envelope 向量进 fixture | 场景证据在 payload 链;envelope 向量属各 golden 自身;扩大无需求 |
| 修改既有 golden 以覆盖新状态 | 冻结面禁改;新状态以**派生变体 payload** 表达(digest 链仍锚定上游 golden) |
| profile 独立 artifact 进最小组合 | 六状态最小性论证:aep 内容已含 profile 引用;独立 profile 不改变任何状态标记 |
| 引入 runtime/持久化/真实执行 | closure IP 与 #90 职责 |

---

## 3. Iteration Hypothesis 与 Measurement

### 3.1 Hypothesis

如果六状态各被冻结为一组字节钉死的跨 Artifact payload bundle(内部链接 digest 全部由 codec 对 bundle 内/上游 golden 实算),且校验测试逐 bundle 执行模块 decode 全链 + digest 链重算 + 状态标记断言,那么"某状态在真实链上不可达""fixture 与冻结词表脱节""链上 digest 断裂"这类聚合阶段风险在交付时刻即被机器拦截。

### 3.2 Measurement

- 六 bundle 的字节数与 SHA-256 与 §7 表逐一相等;
- 每 bundle 的每个 payload 经对应模块 decode 成功;每个状态标记(audit_outcome/verdict/kind/status/disposition)与 §1.2 表逐一相等;
- 每 bundle 内链接 digest == codec 重算值(链一致性);上游引用 == 上游 golden digest;
- 既有 790 测试零新增失败。

---

## 4. Goal

交付 `tests/contracts/fixtures/scenarios/` 下 6 个场景 fixture(JSON)+ 1 个校验测试文件(32 个冻结方法)。

---

## 5. Non-goals

manifests、PR4、closure、真实运行、envelope 向量、任何模块/PR3 产物/既有测试修改、新顶层路径(Checklist 11:scenarios/ 落于 tests/ 内,Dockerfile 已覆盖——无新顶层路径,零 Dockerfile 变更)。

---

## 6. 工作树与分支前置条件

lifecycle §9.1 独立干净 worktree;确认 `tests/contracts/fixtures/scenarios/` 与测试文件不存在;Scope Confirmation 后运行 baseline(419…445/29);根工作树未跟踪文件为用户资产。

---

## 7. 文件边界

### 7.1 Files to Add(恰好 7 个)

```text
tests/contracts/fixtures/scenarios/scenario_no_hypothesis_v4.json
tests/contracts/fixtures/scenarios/scenario_blocked_v4.json
tests/contracts/fixtures/scenarios/scenario_refuted_v4.json
tests/contracts/fixtures/scenarios/scenario_verified_v4.json
tests/contracts/fixtures/scenarios/scenario_unsupported_v4.json
tests/contracts/fixtures/scenarios/scenario_verified_patch_v4.json
tests/contracts/test_scenario_fixtures.py
```

### 7.2 Files Allowed to Modify

```text
none
```

### 7.3 Files Forbidden

十一模块、PR3 产物(schemas/v4 + ADR)、既有测试/fixture(含十七 golden)、frontend/、pyproject.toml、Dockerfile、.github/。

### 7.4 Checklist 第 11 条(CI 测试面)结论

`tests/contracts/fixtures/scenarios/` 位于 Dockerfile 已复制的 `tests/` 树内——**零新顶层路径,零 Dockerfile 变更**(对照 DR-IP-0010-CI-01 教训显式核对)。

---

## 8. Allowed / Forbidden Dependencies

测试只允许 stdlib:`hashlib`、`json`、`pathlib`、`unittest` + 导入 `lima.contracts.{common,codec,aep,vep,rvr,workflow,summary}`(只读)与 `tests.contracts.test_schema_export`(复用 mini-validator,先例:IP-0010 的测试间导入)。Forbidden:第三方库;网络/IO/subprocess;修改任何模块。

---

## 9. 冻结的公共面(产物计数,Checklist 第 3 条等价)

本 IP 无 Python 产品模块;**产物计数 = 6 fixture 文件逐一存在且 digest 与 §7.1' 表相等(测试机器断言)+ 1 测试文件的 32 个冻结方法名(§10)**。

---

## 10. fixture 权威内容与 digest(逐字节复制;三重锁同 IP-0010:digest + decode 测试 + DI-010 归档)

| 文件 | 字节 | SHA-256 | bundle 键 | 上游锚定 |
|---|---:|---|---|---|
| scenario_no_hypothesis_v4.json | 5179 | 061dcccd3b39889ddfd6b79e5f7f9333247a74fb20969430cf4b6109e2c74b3e | aep/security_outcome/workflow_summary | aep-nh(派生)+ wf golden |
| scenario_blocked_v4.json | 1878 | d832ea8ac90491094892d63eee480e47cb313095153953debd6c5b4186619de9 | stage_attempt/failure_report/security_outcome/workflow_summary | alternates[1] + fr golden + aep golden + wf golden |
| scenario_refuted_v4.json | 3117 | 212e4a8d27430b0b3113e9bbd14e50ab0cc89fbaf2be956a5ee791613487af84 | vep/security_outcome/workflow_summary | vep-r(派生)+ wf golden |
| scenario_verified_v4.json | 3042 | b05d365cac98386436d36b53799c951ea4c28b5b3c818bd1cbc392371d0ccbb0 | vep/security_outcome/workflow_summary | vep golden 原样 + wf golden |
| scenario_unsupported_v4.json | 3035 | f5278ad78d684648c73f163499fede835a7c11b154c5565a0dbc0748436c9fe6 | vep/security_outcome/workflow_summary | vep golden 原样 + wf golden |
| scenario_verified_patch_v4.json | 3679 | 8887c5f235f69f6884ba6c9189386486e6c105c578a343690f4835d0e4136705 | rvr/security_outcome/workflow_summary | **三 golden 原样再组合**(零派生) |

**派生规则**(权威;DI-010 归档可复现):no-hypothesis 的 aep = golden 的 D2 支撑记录 polarity→refutes + hypothesis.status→statically_refuted + eligibility→[] + outcome→no_actionable_hypothesis;refuted 的 vep = golden 的 D4 记录 polarity→refutes(summary 替换)+ verdict→refuted_scope + refutation_scope 字符串;其余 payload 按 §1.2 状态标记从 golden 复制或新构;全部链接 digest 由 codec 实算。

---

## 11. Exact Wire Shapes

每 fixture = canonical 单行 JSON,顶层键为 bundle 键(§10 表),值为对应 payload(结构同各 schema 的 wire shape);UTF-8、无 BOM、无尾随换行、sorted keys。

---

## 12-16. Scalar/Array/Envelope/Error 面

全部由模块 decode 承担(§1.1 单解);fixture 自身零校验逻辑。错误映射 = 各模块既有 29 codes(测试仅消费)。

---

## 17. Required Tests(`tests/contracts/test_scenario_fixtures.py`,恰 32 方法)

```text
ScenarioInventoryTests(8)
  test_six_scenario_files_exist_with_frozen_digests
  test_bundle_keys_match_frozen_map
  test_verified_patch_bundle_is_pure_golden_reuse
  test_all_bundles_decode_via_modules
  test_digest_chains_recompute_via_codec
  test_upstream_anchors_match_existing_goldens
  test_state_markers_match_frozen_table
  test_summary_execution_status_polarity(成功态↔succeeded,失败态↔failed)

NoHypothesisTests(4)
  test_decode_and_outcome_markers
  test_round_trip_preserves_payloads
  test_eligibility_empty_and_aep_evidence_link
  test_schema_structural_pass

BlockedTests(4)
  test_decode_and_failure_markers
  test_round_trip_preserves_payloads
  test_attempt_failure_kind_coupling
  test_schema_structural_pass

RefutedTests(4)
  test_decode_and_verdict_markers
  test_round_trip_preserves_payloads
  test_refutation_scope_required
  test_schema_structural_pass

VerifiedTests(4)
  test_decode_and_verdict_markers
  test_round_trip_preserves_payloads
  test_vep_is_golden_unchanged
  test_schema_structural_pass

UnsupportedTests(4)
  test_decode_and_kind_markers
  test_round_trip_preserves_payloads
  test_vep_required_rvr_forbidden
  test_schema_structural_pass

VerifiedPatchTests(4)
  test_decode_and_kind_markers
  test_round_trip_preserves_payloads
  test_rvr_contains_verified_patch_candidate
  test_schema_structural_pass
```

`test_schema_structural_pass` = PR3 mini-validator 对 bundle 内有对应 schema 的 payload 做结构校验(补充面,不作状态判定)。N = **32**。

---

## 18. Acceptance Criteria and Traceability

| AC | Required behavior | Evidence | Requirement |
|---|---|---|---|
| SC-AC-01 | 6 fixture 存在、digest 与 §10 逐一相等 | inventory test | V5-FR-04、FR-05 |
| SC-AC-02 | 全 bundle 模块 decode 成功 | decode tests | V5-FR-04、V5-FR-01 聚合面 |
| SC-AC-03 | 链 digest 重算一致 + 上游锚定 golden | chain tests | FR-02/FR-04 |
| SC-AC-04 | 六状态标记与 §1.2 表逐值相等 + summary 极性 | marker tests | V5-FR-04 |
| SC-AC-05 | verified_patch = 纯 golden 复用;verified/unsupported 的 vep = golden 原样 | reuse tests | 最小组合论证 |
| SC-AC-06 | PR3 结构面补充校验通过 | schema pass tests | PR3 消费 |
| SC-AC-07 | 7 added / 0 modified / 回归零新增失败 | boundary + regression | AC-04 |

---

## 19. Done Commands

```powershell
# Baseline:contracts 445 PASS;定向 29 PASS
# Slice Gate(GREEN 态 = fixture 在位):
python -m compileall -q lima/contracts tests/contracts
python -m unittest discover -s tests/contracts -v      # 477 ran / 0 failed(445+32)
python -m ruff check --no-cache tests/contracts/test_scenario_fixtures.py
python -m ruff check --no-cache lima/contracts tests/contracts
python -m bandit -q -r tests/contracts/test_scenario_fixtures.py
git diff --check
# Compatibility Gate:全量 822 = 790+32 / 1 既有 skip
# File Boundary:恰 7 文件(6 fixture + 1 测试;产品侧零 .py)
```

---

## 20. 强制实现顺序(十一项 Checklist)

阶段二 P&V 执行 1-6:①预检(B-F 扫描 + **lineage 对拍高度适用**:fixture 链 digest == codec 重算 == 上游 golden,三向对拍 + 负例生证 + 一致性);②编写测试 + 6 fixture(逐字节复制 DI-010);③GREEN 态冷缓存门禁(fixture 置于真实路径);④有效 RED(测试读 scenarios/ → FileNotFoundError 全归因 fixture 缺失);⑤Frozen Test Commit(只推分支);⑥IMPL Assignment。实现者第 7 步起:放置 6 fixture → 32 测试全绿 → 三 Gate → Completion Summary。

---

## 21. Security and Compatibility Invariants

- fixture 纯数据;零新语义/零模块修改/零新路径(Checklist 11 核对在案);
- 六状态标记全部来自冻结词表(无自造状态);失败态 summary 极性 = failed(与 V5-AC-02 一致);
- 上游 golden 零改动;PR3 产物零改动;十七 golden digest 不变。

---

## 22. Stop Conditions / Decision Request

1. 两份 IP-0011 文档未合并或基线非 `b3627c2` 后代、冻结面/PR3 产物漂移;
2. 任一 bundle 无法由模块 decode(状态不可达再现);
3. §10 digest 无法复现或链断裂;
4. 需修改既有 golden/模块/PR3 产物/新增路径或依赖才能自洽;
5. cxx 触碰 contracts;多解即停止提交 DR。

---

## 23. Git/Commit/PR、24. Completion Summary 模板、25. Maintainer Checklist

同先例(标题 `test: add six-state scenario fixtures for V5-FR-04`;PR 只写 `Implements IP-0011` + `Related to #58`,禁 auto-close;7 added / 0 modified)。

---

## 26. Assignment §5 七问逐条单解

| # | 问题 | 单解 | 所在 |
|---|---|---|---|
| 1 | 形态/位置/命名/链构造 | tests/contracts/fixtures/scenarios/scenario_<state>_v4.json;canonical 单行;codec 实算 | §7/§10 |
| 2 | 校验路径 | 模块 decode 全链(单解;schema 仅补充结构面) | §1.1 |
| 3 | 与既有 golden 关系 | verified_patch 纯复用;verified/unsupported 复用 vep;no-hypothesis/refuted 最小派生;blocked 复用 alternates+fr | §1.2/§10 |
| 4 | 测试矩阵 | 32(8+6×4) | §17 |
| 5 | 错误/数字 | 29 codes 消费;445→477、790→822 | §19 |
| 6 | CI 面(第 11 条) | scenarios/ 在 tests/ 内,零 Dockerfile 变更 | §7.4 |
| 7 | 环境记录 | redis-py 6.4.0 差异照登 | §19/交接书 |

---

## 27. 冻结设计决策记录

- **DR-IP0011-DESIGN-01(校验 = 模块 decode 单路径)**:六状态是跨字段语义状态;PR3 schema 按 ADR 0027 有意不表达之(locus = module);schema 仅作补充结构断言。
- **DR-IP0011-DESIGN-02(bundle 形态 = payload 键值组,无 envelope 层)**:场景证据在 payload 链;每 bundle 内链接 digest 双向锚定(上游 golden / bundle 内 payload);envelope 向量属各 golden 自身,不重复。
- **DR-IP0011-DESIGN-03(verified_patch 纯复用)**:rvr/security-outcome/workflow-summary 三 golden 即该状态的完整最小组合——零派生零重算,直接证明聚合可行性。
- **DR-IP0011-DESIGN-04(最小派生规则冻结)**:no-hypothesis 与 refuted 的派生编辑逐字段冻结于 §10(D2/D4 polarity 翻转 + status/verdict 联动)——防止 IMPL 自创等价变体破坏 digest。
- **DR-IP0011-DESIGN-05(失败态 summary 极性)**:blocked/refuted/unsupported 的 summary.execution_status = failed,成功态 = succeeded(V5-AC-02 一致性进 fixture)。

---

## 28. Packet 完成定义

7 AC、32 tests、6 fixture digest 全等、GREEN 态命令证据、独立 Review 与 merge-gate 满足后 IP-0011 才可标 DONE;合并后 post-merge,V5-FR-04 转 SATISFIED。下一消费 IP(IP-0012 候选:manifests)的入口 Gate 含对本 fixture 集的只读 review。
