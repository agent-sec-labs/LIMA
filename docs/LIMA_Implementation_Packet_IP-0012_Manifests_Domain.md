# LIMA Implementation Packet IP-0012:Manifests Domain(Task / ToolBundle / Dependency / Sandbox manifests)

> Packet ID:`IP-0012`
>
> 状态:`DESIGN-FROZEN / READY-FOR-CODE WHEN THIS PACKET IS MERGED TO MAIN`
>
> Source Issue:[#58](https://github.com/agent-sec-labs/LIMA/issues/58) 的第十二个独立实现切片(domain 角色:FR-02 manifests 子集——FR-02 的最后一块)
>
> Assignment 基线:origin/main @ `4619389071aef80812a77428e6fc2c509dca626b`(ADDENDUM-1 A-1 重锚定);实现基线 = 含本 Packet 与正式交接书的最新 `origin/main`
>
> 推荐分支:`codex/ip-0012-manifests-domain`(依 lifecycle §9.1 从 Frozen Test Commit 派生)
>
> Owner:唯一 Implementation Agent;不触碰既有十二模块、PR3 产物、场景 fixture 与任何既有测试/fixture

## 需求映射(Header)

```text
Source Issue:#58
Issue specification revision:正文修订 2026-09-01T14:36:22Z(V4 + V5 覆盖层);
  #58 正文 v45 @ 2026-09-09T16:12:20Z(Ledger;Execution queue NOW → PKT-IP-0012)
Assignment:PKT-IP-0012_PV_DISPATCH_PACKAGE_FINAL(正本 2026-09-06 预签 + ADDENDUM-1
  2026-09-10 重锚定 + Coordinator 会签追认 PKT-IP-0012-AMEND-1)
Covered requirements:
  FR-02 manifests 子集(Task/ToolBundle/Dependency/Sandbox 四 manifest schema 版本化定义
  + 跨对象引用纪律 artifact_id + content_digest + schema_version);
  V5 §5.2 MiningPlan/SandboxRunManifest 深字段(本 Packet 裁定并入,见 §8 决策 D2);
  FR-05 fixtures 子集(四 manifest minimal/full golden);
  FR-06(current/future-minor 行为与既有模块同构);
  NFR-02(上限,逐一论证见 §12);
  AC-04 支撑面(dependency isolation 对新模块适用)
Not covered requirements:PR4 legacy adapter;closure IP;#90 runtime / #76 生成器 / #77 Gate
  执行器实现;consumer review ×4 调度;任何既有十二模块修改;PR3 产物修改(含四 manifest 的
  schemas/v4 JSON 导出——见 §16 决策 D10-排除);场景 fixture 修改
Delivery role:domain(第十二个契约切片)
Issue closure impact:PARTIAL(完成后 #58 保持 open;FR-02 由 PARTIAL 转 SATISFIED 候选)
Upstream IP/PR/merge commits:IP-0001..0011 全链(#97..#135;冻结面
  18/16/15/12/12/12/27/16/19/29 + 15 PR3 产物 + 6 场景 fixture + 十七 golden,全部 IP-DONE)
Activation gate:lifecycle 入口 consumer review(见 §1,已完成,无 Contract Gap)

CR60-02 对应关系登记(ADDENDUM-1 A-4,需求溯源记录,不扩权、不加验收项):
  #60 consumer review 备注 CR60-02("TaskManifest 输入尚未交付(既有 #58 manifests 待办,
  不是本评审发现的实现回归)",出处 .pv_tmp/consumer_review_58/issue60.md)。本 IP 的
  Task manifest 交付即 #58 manifests 待办的一部分,与 CR60-02 直接对应:TaskManifest ↔
  CR60-02 / #60 的 TaskManifest 输入面。#60 的消费方交付节奏仍由其 owner 决定;本 Packet
  的 schema_name 冻结值 "lima.task-manifest"(§7 决策 D1)即 #60 后续引用的冻结字面量。
```

---

## 0. 执行决策

当前执行队列(Ledger v45):NOW = PKT-IP-0012。本 Packet 只交付 manifests 域契约模块(1 个 .py)、三个测试文件与 ≥8 个 golden fixture;零修改既有面,零新顶层路径(§15)。阶段二(RED + Frozen Test Commit)由 P&V 另行执行,本 Packet §13/§14 的测试矩阵与预期数字构成阶段二冻结依据。

---

## 1. 入口 Gate 结论(lifecycle,只读;@ main `4619389`,P&V 实证 2026-09-10)

### 1.1 六场景 fixture 集只读 consumer review(Assignment §4-1;IP-0011 Packet §28 链)

**裁定:六场景全部 PASS,无 Contract Gap。** 独立实证(不依赖 IP-0011 冻结测试,自行探针):

| 场景 | 字节钉死(SHA-256/size 对照 IP-0011 §10) | bundle 键 | 模块 decode + round-trip | 链闭合(内部 codec 实算 + 上游 golden 锚定) |
|---|---|---|---|---|
| scenario_no_hypothesis_v4.json | PASS(5179 / 061dcccd…) | aep, security_outcome, workflow_summary | 3/3 OK | 4 链接,0 dangling |
| scenario_blocked_v4.json | PASS(1878 / d832ea8a…) | stage_attempt, failure_report, security_outcome, workflow_summary | 4/4 OK | 7 链接(6 锚定 golden),0 dangling |
| scenario_refuted_v4.json | PASS(3117 / 212e4a8d…) | vep, security_outcome, workflow_summary | 3/3 OK | 4 链接,0 dangling |
| scenario_verified_v4.json | PASS(3042 / b05d365c…) | vep, security_outcome, workflow_summary | 3/3 OK | 4 链接,0 dangling |
| scenario_unsupported_v4.json | PASS(3035 / f5278ad7…) | vep, security_outcome, workflow_summary | 3/3 OK | 4 链接,0 dangling |
| scenario_verified_patch_v4.json | PASS(3679 / 8887c5f2…) | rvr, security_outcome, workflow_summary | 3/3 OK | 10 链接(10 锚定 golden),0 dangling |

consumer 视角对 IP-0012 的两个关键结论:
1. **六场景 bundle 零 manifests 依赖**:没有任何场景 payload 引用或假定 manifests schema 存在;manifests 新增不破坏任何场景 fixture 字节与 decode 链(实证:场景测试在基线 477 内全绿)。
2. **唯一既有 manifests 语义锚点在 execution 侧**:`tests/contracts/test_execution_envelope.py` L80-81 以 lineage 字面量 `"lima.sandbox-run"`(sandbox-run-0001)与 `"lima.tool-bundle"`(tool-bundle-0001)满足 `RunManifest.resource_artifact_ids` 的 lineage 存在性检查;`run_manifest_v4_golden.json` 的 `resource_artifact_ids = ["sandbox-run-0001", "tool-bundle-0001"]`。**这两个 schema_name 字面量是已冻结的字符串级接口**(与 PlanMode/WorkflowMode wire-value 同构先例),IP-0012 的字面量取值必须与之相等(§7 决策 D1)——这不是 Contract Gap,而是现成的钉死锚点。

### 1.2 十二模块适用面核对(Assignment §4-2)

基线 `lima/contracts/` 恰十二模块(codec/common/errors/evidence/profile/aep/vep/rvr/workflow/execution/summary/__init__);依赖方向实测(各域模块仅 import codec/common/errors,唯 aep/vep 额外 import evidence):

| 核对面 | 实证结论 |
|---|---|
| RunManifest 的 `resource_artifact_ids` 未类型化存在性 → manifests 类型化路径 | 现状:execution 只做 identifier 词表 + lineage 存在性 + 排序唯一,不检查 schema_name;lineage 侧 schema 字面量已用 `lima.sandbox-run`/`lima.tool-bundle`(test_execution_envelope L80-81)。manifests 交付后,"类型化路径"的落点 = manifests 模块自身 payload decode + 测试断言 lineage 字面量相等(§9 决策 D3);**execution 冻结面(16-symbol)零修改** |
| Plan/Workflow 的 manifest 关联面 | Plan.inputs 的 ReferenceKind 词表(4 成员)与 workflow.ArtifactKind(6 成员)均**不含** manifest kinds,两处冻结面禁改;Plan 的 resource 声明无 manifest 字段(Plan 仅 VEP prerequisites)。结论:Plan/Workflow 与 manifests 无既有类型化耦合,manifests 引用方向只能是 manifests → 既有字面量(经本地值类型),无反向依赖 |
| errors 29 codes | 逐一清点 ContractErrorCode 恰 29 成员;manifests 复用全部既有 codes,零新增(errors.py 冻结面禁改) |
| codec | `compute_content_digest` 是 digest 唯一实现(FR-04);manifests 严禁自行序列化算 digest |
| schemas/v4 | 13 份 JSON Schema + matrix 为 PR3 产物(IP-0010,冻结);登记面在 `test_schema_export.py` FROZEN_ARTIFACT_DIGESTS(**既有测试,禁改**)→ 本 IP 不交付 manifests 的 schemas/v4 JSON(§16 决策 D10-排除) |
| 外部消费 | lima/contracts 之外无 `lima.contracts` import 点(除 tests);`contracts/__init__.py` 18-symbol 冻结面**不**re-export manifests(§7 决策 D1) |

**结论:无 Contract Gap,入口 Gate 通过。**

---

## 2. Design Input Manifest

| Input ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001..003 | Standard/Charter | 稳定标准 / lifecycle / P&V 责任书 | main `4619389` | 分工、拓扑、冻结纪律 | normative | — |
| DI-004 | Issue(Assignment) | PKT-IP-0012_PV_DISPATCH_PACKAGE_FINAL(正本 + ADDENDUM-1 + 会签) | 2026-09-10 | 覆盖/不覆盖、§5 十一问、十一项 Checklist、Stop Conditions | normative | ADDENDUM-1 优先 |
| DI-005 | Issue | #58 正文(V4+V5 覆盖层) | 修订 `2026-09-01T14:36:22Z`;v45 @ 2026-09-09 | FR-02/05/06、NFR-02、AC-04、T-01..T-04 追溯 | normative | — |
| DI-006 | Issue(Ledger) | #58 Delivery Ledger v45 | 2026-09-09T16:12:20Z | Execution queue NOW → PKT-IP-0012;基线数字 | normative(current) | — |
| DI-007 | Decision | 全链 DR 正本(历次)+ DR-IP-0011-NAMING-01 | 历次 | Checklist 渊源、命名差异先例、DR-IP0008-DESIGN-02/07(最小词表)、DR-IP0007-DESIGN-04(零时间/计量)、DR-IP0007-DESIGN-06(零 float/自由文本) | normative | — |
| DI-008 | Upstream IP | IP-0001..0011 Packets(尤其 IP-0008 Rejected Inputs 的深字段预划分) | #97..#135 | ArtifactLink 三元组先例、untyped id + lineage 存在性先例、revision 语义、排序纪律 | normative | — |
| DI-009 | Architecture | V5 规划文档 §5.2/§5.3(#58 指定 Source of truth;本地工作树副本) | V5 | 四 manifest + MiningPlan/SandboxRunManifest 深字段清单、Envelope 公共字段、跨阶段零绝对路径不变量 | normative(经 #58 V5 覆盖层转正) | 与 #58 冲突以 #58 为准 |
| DI-010 | Code | `lima/contracts/` 十二模块 | main `4619389` | validator 风格、schema_name 词表、execution 字面量锚点(test_execution_envelope L80-81) | current-behavior | 代码事实让位于 Packet 目标行为 |
| DI-011 | Test | `tests/contracts/` 全部 + fixtures(含六场景) | main `4619389` | 测试风格、477 基线、golden 测试模式、mini-validator 边界 | current-behavior | — |
| DI-012 | Evidence | 本 IP 基线复现(P&V worktree 实跑) | 2026-09-10 | contracts 477/477、全量 821 passed + 1 skip(=822/0F/1 skip 口径)、ruff --no-cache exit 0、六场景探针全 PASS | evidence | — |
| DI-013 | Issue | #60 正文 + `.pv_tmp/consumer_review_58/issue60.md`(CR60-02) | 评审基线 207222d | TaskManifest ↔ CR60-02 对应关系登记 | background-only(登记) | 不从 #60 扩大范围 |
| DI-014 | Issue | #90 正文(V5-N01) | `.pv_tmp/` 镜像 | runtime 消费面与豁免边界(§11 决策 D4) | background-only | — |

### Explicitly Rejected Inputs

| 材料 | 拒绝原因 |
|---|---|
| 修改 `execution.py` 以扩展 ReferenceKind/新增 manifest kinds | execution 16-symbol 冻结面禁改(Stop Condition);类型化路径以字面量 wire-value 相等实现(§9 决策 D3,先例:PlanMode ↔ WorkflowMode) |
| 修改 `workflow.py` ArtifactKind / `_STAGE_INPUT_KINDS` / `_STAGE_OUTPUT_KINDS` 以纳入 manifests | workflow 27-symbol 冻结面禁改;Plan/Workflow 与 manifests 无既有类型化耦合(§1.2) |
| MiningPlan / SandboxRunManifest 作为独立第五、六 schema | 双解风险由 §8 决策 D2 单解消除(并入 Task/SandboxRun);独立切分将新增 schema_name、重复引用结构,且 V5 §5.2 的 Task/ToolBundle/Dependency/Sandbox 四分法与 #58 FR-02 四分法一致 |
| `repository snapshot` 独立 schema(V5 §5.2 RepositorySnapshotManifest 行) | #58 FR-02 字面为 Task/ToolBundle/Dependency/Sandbox 四 manifest;snapshot 经 Envelope `repository_snapshot_digest` 公共字段承载,不属本 IP |
| schemas/v4 JSON 导出(四 manifest 的 .json + 矩阵行 + test_schema_export 登记) | PR3 产物类(IP-0010 交付形态);登记面 test_schema_export.py 是既有测试(禁改);留待后续 PR3-类 IP(§16 决策 D10-排除) |
| `contracts/__init__.py` re-export manifests symbols | __init__ 18-symbol 冻结面禁改;消费面经 `lima.contracts.manifests` 全路径 import(§7 决策 D1) |
| float 用量/秒数、自由文本 description/notes、started_at/ended_at/时长 | DR-IP0007-DESIGN-04/06 纪律;零 float、零时间、散文面最小 |
| env 变量/秘密/host 名/URL 进 SandboxRun 或任何 manifest | NFR-01 fail-closed 与秘密纪律;network 只经 policy 枚举(§12) |
| 跨阶段绝对路径 | V5 §5.3 不变量:路径必须相对 snapshot root;mounts 强制相对路径(§8 决策 D2-S) |
| V4 backlog 文档、"28/13" 笔误口径 | 历次 Packet 已登记拒绝;权威值 29 codes / 12 模块 |

---

## 3. Iteration Hypothesis 与 Measurement

### 3.1 Hypothesis

如果四 manifest 被冻结为词表钉死、上限钉死、引用三元组(artifact_id + content_digest + schema_version)贯穿的确定性 schema,且引用链 digest 全部由 IP-0001 codec 实算锚定,manifests→RunManifest 的类型化路径以字面量 wire-value 相等 + 测试断言表达,那么"resource_artifact_ids 指向不存在的 schema""tool 校验和与来源不可信""沙箱约束被静默放宽"这类 FR-02 尾部风险在交付时刻即被机器拦截。

### 3.2 Measurement

- contracts 由 477 增至 477+N(N ≥ 40,精确值在 Frozen Test Commit 钉死),0F;
- 全量由 822(821 passed + 1 skip)增至 822+N,0F,既有 skip 数不变;
- 四 manifest golden 的内部/交叉 digest 与 codec 重算值全等;task_full ↔ tool_bundle/dependency、sandbox_run ↔ task/tool_bundle 引用链闭合;
- import isolation:import manifests 后任何域模块不在 sys.modules;import 十二模块任一后 manifests 不在 sys.modules(十二模块反向断言);
- `lima.sandbox-run` / `lima.tool-bundle` 字面量与 execution 侧测试锚点逐字符相等(§9)。

---

## 4. Goal

交付 `lima/contracts/manifests.py`(四 manifest schema)+ 3 个测试文件 + ≥8 个 golden fixture(4 manifest × minimal/full)。

## 5. Non-goals

PR4 legacy adapter、closure、#90/#76/#77 实现、schemas/v4 JSON 导出(§16)、`contracts/__init__.py` 修改、任何既有模块/PR3 产物/场景 fixture/既有测试修改、runtime/持久化/网络/LLM、时间/计量/float/自由文本字段、RepositorySnapshotManifest、PR4/CandidatePatchSet(V5 §5.2 其余行)。

---

## 6. 工作树与分支前置条件

Coding Agent 必须:完整阅读稳定标准、lifecycle、Implementation Agent 责任书、本 Packet、`LIMA_Coding_Agent_IP-0012_正式开发任务交接.md`、CONTRIBUTING.md;确认两份 IP-0012 文档均已合并 `origin/main`;依 lifecycle §9.1 从 Frozen Test Commit(阶段二交付物指定 SHA)派生 `codex/ip-0012-manifests-domain` 独立干净 worktree(禁共享根与既有 worktree);确认 `lima/contracts/manifests.py`、3 个测试文件与 8 个 golden fixture 尚不存在;输出 Scope Confirmation 后再跑 baseline;不一致即停提交 Decision Request。根工作树未跟踪文件属用户资产,不得触碰。

---

## 7. 决策 D1(§5-1):命名 / 模块切分 / schema_name 字面量(冻结单解)

- **单文件** `lima/contracts/manifests.py`(四 schema 共享 validator/词表/上限常量,总量与 evidence.py 1639 行同量级,无需分文件);
- schema_name 字面量(**冻结值**):

| 常量 | 字面量 | 取值依据 |
|---|---|---|
| `TASK_MANIFEST_SCHEMA_NAME` | `lima.task-manifest` | 对齐 #60 输入面命名"TaskManifest"(DI-013/CR60-02);schema_name pattern 兼容 |
| `TOOL_BUNDLE_SCHEMA_NAME` | `lima.tool-bundle` | **既有锚点**:test_execution_envelope L81 lineage 字面量逐字符相等 |
| `DEPENDENCY_MANIFEST_SCHEMA_NAME` | `lima.dependency-manifest` | FR-02 字面"Dependency" manifest;与 task-manifest 对称 |
| `SANDBOX_RUN_SCHEMA_NAME` | `lima.sandbox-run` | **既有锚点**:test_execution_envelope L80 lineage 字面量逐字符相等;run_manifest golden 资源 id `sandbox-run-0001` 同源 |

- 公开面:decode/encode payload + envelope 各四对(8 函数)+ 4 常量 + 领域 dataclass + 本地 `ManifestReferenceKind` 枚举;**不**经 `contracts/__init__.py` re-export(18-symbol 冻结面)。
- 依赖方向(冻结):manifests → {codec, common, errors} 只读;**禁止 import** evidence/profile/aep/vep/rvr/workflow/execution/summary 及 lima 任何非 contracts 模块。

## 8. 决策 D2(§5-1/§5-2):四 manifest 结构 + MiningPlan/SandboxRunManifest 并入裁定(冻结单解)

**裁定:V5 §5.2 的 MiningPlan 深字段并入 TaskManifest,SandboxRunManifest 深字段并入 SandboxRun manifest(即 "Sandbox" manifest = sandbox-run)。不新增第五、六 schema。** 论证:#58 FR-02 字面为四 manifest;IP-0008 Rejected Inputs 预划分的深字段恰好按 mining/sandbox 两簇归属 Task(生产者 Mining Planner,消费者 Mining Sandbox——V5 §5.2 MiningPlan 行)与 SandboxRun(生产者 Sandbox Supervisor,消费者 Adjudicator/RVR——V5 §5.2 SandboxRunManifest 行);execution 锚点字面量 `lima.sandbox-run`/`lima.tool-bundle` 也只承认四分法。独立切分将引入两套引用结构与两个新 schema_name,无新增表达力——单解成立。

引用层级(自上而下,一律经本地 `ManifestLink` = kind + artifact_id + content_digest + schema_version,模式 = execution.ArtifactLink 三元组先例,**本地重定义,不 import execution**):

- **Task → ToolBundle / DependencyManifest**(声明面:任务要用什么工具与依赖);
- **SandboxRun → Task / ToolBundle**(记录面:实际执行所依据的任务声明与工具包);
- RunManifest → manifests:经既有 untyped `resource_artifact_ids` + lineage(§9)。
- DependencyManifest 与 ToolBundle 之间不互相引用(来源/校验和各自独立声明,避免环)。

各 manifest 冻结 wire 字段(全部 NFC、零 float、零时间、零自由文本;排序唯一纪律同 execution:数组按天然键升序、违反报 `INVALID_FIELD_VALUE`):

**TaskManifest(payload)**:
```text
revision: int(>=1;>1 时 envelope.supersedes 必填且 schema_name == lima.task-manifest——Plan 先例)
hypothesis_ids: [identifier](mining 深字段①;cap 32;排序唯一;不绑 digest——AEP hypothesis
  非 artifact,untyped id 先例 = rvr gate-evidence)
tool_bundles: [ManifestLink kind=lima.tool-bundle](mining 深字段② tool refs;cap 8;排序唯一)
dependencies: [ManifestLink kind=lima.dependency-manifest](cap 8;排序唯一)
harness_commands: [[str]](mining 深字段③ harness plan;≤16 条命令、每条 ≤32 个 argv 词、
  每词 ≤512 UTF-8 字节;词必须匹配 [A-Za-z0-9_./:=,-]+——零绝对路径,零 shell 元字符)

> 注（2026-09-11, DR-1 §3-C1 勘误）：词类字符集 `[A-Za-z0-9_./:=, -]` 明确包含 U+0020（空格）；裁定正本见 PKT-IP-0012_DR1_ADJUDICATION_RECORD_2026-09-10.md。冻结测试与实现（`80feaea`）均按此口径。

oracle_kind: enum {deterministic_exit, differential_output, property_assertion}
  (mining 深字段④ oracle 的最小词表化)
network_policy: enum {deny_all, egress_allowlist}(mining 深字段⑤ resource/network policy 的
  网络面;资源面经 limits 于 SandboxRun 承载)
```

**ToolBundle(payload)**:
```text
revision: int(>=1)
entries: [{name(identifier ≤128B), checksum(64-hex sha256), size_bytes(int 0..2^63-1),
  executable(bool), license_word}]  cap 256;按 name 排序唯一
license_word: "NOASSERTION" 或 SPDX 简式标识符 [A-Za-z0-9.-]{1,64}(NFC;字面词表拒绝 URL/
  自由文本)
```

**DependencyManifest(payload)**:
```text
revision: int(>=1)
lock_digest: 64-hex(整包 lock 文件 digest)
entries: [{package(identifier), version_str(≤128B, [A-Za-z0-9.+*!~-]{1,128}),
  source_kind: enum {registry, vcs, path}, checksum(64-hex),
  offline_replay: bool}]  cap 512;按 package 排序唯一
```

**SandboxRun(payload)**:
```text
task: ManifestLink kind=lima.task-manifest(必填)
image_digest: 64-hex(镜像 digest;拒绝 tag 字符串——不可复现锚点禁入)
tool_bundles: [ManifestLink kind=lima.tool-bundle](cap 8;排序唯一)
mounts: [str](cap 64;每条 ≤512B 且必须匹配 [A-Za-z0-9_./-]+——相对 snapshot root,
  V5 §5.3 零绝对路径;拒绝 ".." 词段;排序唯一)
commands: [[str]](cap 16;每条 ≤32 词、词规约同 TaskManifest.harness_commands)
resource_limits: {cpu_seconds: int(1..2^31-1), memory_mb: int(1..2^21), max_processes: int(1..4096)}
  (三键全必填;资源计量唯一先例 aep.budget 同构——声明式上限,非运行结果)
network_policy: enum {deny_all, egress_allowlist}(与 TaskManifest 同词表;SandboxRun 值
  不得宽于 Task 声明属运行期检查(#90),契约层只冻结词表与两处一致性校验:
  task.network_policy == network_policy,不等报 INVALID_FIELD_VALUE)
exit_code: int(-128..255)| null(运行事实;null = 未运行/未捕获,绝不编码为安全结论——NFR-01)
log_artifact_ids: [identifier](cap 4;排序唯一;untyped id + lineage 存在性——run_manifest 先例)
```

envelope 绑定:每 manifest 的 encode/decode envelope 检查与 execution 同构(schema_name 匹配、inline payload、content_digest 双算 hmac.compare_digest、protected(classification != PUBLIC 且 retention != EPHEMERAL)、task/dependencies/tool_bundles 链接逐一经 lineage 双检(schema_name/schema_version 相等 + digest hmac 对拍);hypothesis_ids/log_artifact_ids 仅 lineage 存在性)。

## 9. 决策 D3(§5-3):与 execution.RunManifest 的衔接(冻结单解)

**不扩展 execution.ReferenceKind(冻结面禁改);方向 = manifests 单向指向既有字面量,衔接以 wire-value 相等实现。** 具体三点:
1. manifests 本地 `ManifestReferenceKind` 成员字面量覆盖它需要引用的**既有** schema(如未来需要引用 plan/workflow 时新增成员)与四个 manifest 自身字面量;本 IP 实际需要:lima.task-manifest、lima.tool-bundle、lima.dependency-manifest、lima.sandbox-run,恰四成员,最小词表(DR-IP0008-DESIGN-02/07 同构);
2. 类型化路径断言(测试面,冻结):decode `run_manifest_v4_golden.json` payload,断言 `resource_artifact_ids ⊆ {"sandbox-run-0001","tool-bundle-0001"}` 且按 IP-0008 envelope fixture 的 lineage schema 字面量,`lima.sandbox-run == SANDBOX_RUN_SCHEMA_NAME`、`lima.tool-bundle == TOOL_BUNDLE_SCHEMA_NAME`(逐字符相等 + 不 import execution 即可比较——字符串级接口,PlanMode/WorkflowMode 先例);
3. RunManifest 自身零改动:其 resource_artifact_ids 语义保持"未类型化 id + lineage 存在性"(execution 文档串明示"resource ids are lineage-existence-checked only, because their schemas are not frozen yet");schemas 冻结后该检查的增强属未来 IP,不属本 Packet(防范围扩张)。

## 10. 决策 D3 补充:文件边界

### Files to Add(恰好 12 个)
```text
lima/contracts/manifests.py
tests/contracts/test_manifests.py
tests/contracts/test_manifests_envelope.py
tests/contracts/test_manifests_import_isolation.py
tests/contracts/fixtures/task_manifest_v4_golden.json
tests/contracts/fixtures/task_manifest_full_v4_golden.json
tests/contracts/fixtures/tool_bundle_v4_golden.json
tests/contracts/fixtures/tool_bundle_full_v4_golden.json
tests/contracts/fixtures/dependency_manifest_v4_golden.json
tests/contracts/fixtures/dependency_manifest_full_v4_golden.json
tests/contracts/fixtures/sandbox_run_v4_golden.json
tests/contracts/fixtures/sandbox_run_full_v4_golden.json
```
### Modify / Read-only / Must-not-modify
零 Modify。Read-only:全十二模块、既有全部测试/fixture(含 test_schema_export.py、mini_validator 复用禁止——本 IP 不做 schema 面校验)、Dockerfile(§15 核对后零变更)、pyproject.toml。Must-not-modify 同 Assignment §6 Forbidden 全清单。

## 11. 决策 D4(§5-4):词表、不变量与 #90 豁免登记(冻结单解)

- identifier:`[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`(execution 同构);digest:`[0-9a-f]{64}`(不接受大写);NFC 归一;bool 精确类型检查(bool 不是 int);
- argv/mount 词规约、license_word、version_str:见 §8(全部封闭字符类,零 URL/路径穿越/shell 元字符);
- 不变量:排序唯一(全部数组);Task↔SandboxRun 的 network_policy 一致性;SandboxRun.mounts 零绝对路径零 `..`;exit_code null 语义永不折叠为安全结论(NFR-01);future-minor 未知字段 round-trip 保留 + current-minor 未知字段 UNKNOWN_FIELD 拒绝(FR-06,与既有模块同构);
- **#90 豁免清单登记**:四 manifest payload 是 #90 runtime(V5-N01)的**只读输入**;#90 不得向 payload 写入运行时状态(进度/重试/心跳);timeout/OOM/tool_error 只能经 FailureReport 词表表达,永不改写 manifest;#90 对 resource_limits/network_policy 只能收紧不能放宽(运行期策略,不属契约层校验)。

## 12. 决策 D5(§5-5):资源上限(NFR-02 逐一论证)

| 上限 | 值 | 论证 | 错误码 |
|---|---|---|---|
| hypothesis_ids | 32 | AEP 单包 hypothesis 规模上界(与 evidence 域词表规模同量级);防任务声明爆炸 | MAX_ARRAY_LENGTH_EXCEEDED |
| tool_bundles(Task/SandboxRun) | 8 | 单任务工具包数远小于 8;防引用面膨胀 | MAX_ARRAY_LENGTH_EXCEEDED |
| dependencies(Task) | 8 | 声明面按 manifest 粒度(非条目粒度);8 足够分层 | MAX_ARRAY_LENGTH_EXCEEDED |
| ToolBundle.entries | 256 | 工具包文件数上界(含分发脚手架);超出即异常包 | MAX_ARRAY_LENGTH_EXCEEDED |
| DependencyManifest.entries | 512 | SBOM 量级上界;lock 爆炸在此拦截 | MAX_ARRAY_LENGTH_EXCEEDED |
| mounts | 64 | 沙箱挂载点最小面原则 | MAX_ARRAY_LENGTH_EXCEEDED |
| commands(Task/SandboxRun) | 16 | 与 execution `_MAX_PLANNED_STAGES=16` 同构的阶段量级 | MAX_ARRAY_LENGTH_EXCEEDED |
| argv 每命令词数 | 32 | 命令行长度工程上界 | MAX_ARRAY_LENGTH_EXCEEDED |
| 词/identifier/version/license 字节 | 512/128/128/64 | MAX_STRING_LENGTH_EXCEEDED(codec 全局 256KB 之内的域级收紧) | MAX_STRING_LENGTH_EXCEEDED |
| size_bytes / cpu_seconds / memory_mb / max_processes | int64 / 1..2^31-1 / 1..2^21(=2TB MB)/ 1..4096 | 零 float;上界各自对应物理量级;INTEGER_OUT_OF_RANGE / INVALID_FIELD_VALUE | INTEGER_OUT_OF_RANGE |
| exit_code | -128..255 | POSIX/exit status 联合量级 | INVALID_FIELD_VALUE |
| 总字节/深度/对象字段 | codec ContractLimits(1MiB/32/1000/256KB) | FR-04 codec 唯一实现,域模块不自设总限 | RESOURCE_LIMIT_EXCEEDED 等 |

## 13. 决策 D6/D7(§5-6/§5-7):golden 计划与测试矩阵(冻结单解)

**golden(≥8,4 manifest × minimal/full)**:minimal = 必填最小集(空 entries 允许的 schema 用最小非空合法值);full = 全字段启用 + 交叉引用链真实 digest:
- task_manifest_full → 引用 tool_bundle_full 与 dependency_manifest_full 的 **payload digest(codec 实算)**;
- sandbox_run_full → 引用 task_manifest_full 与 tool_bundle_full 的 payload digest;
- 全部 digest 由 `compute_content_digest` 预计算(设计期算一次,字节钉死进 fixture;测试重算对拍)。fixture 文件结构 = 单 payload 对象(与既有 *_v4_golden.json 同构,非 envelope 向量)。

**测试矩阵(N ≥ 40;精确 N 与逐条清单在阶段二 Frozen Test Commit 钉死,下表为冻结类别与下限)**:

| 文件 | 类别 | 下限 | 要点 |
|---|---|---|---|
| test_manifests.py | 每 schema decode/round-trip/不变量/负例 | 20 | 4×(decode_ok、round-trip、排序唯一、上限触界、enum 未知值、字段类型/缺失/未知、词表拒绝:绝对路径/`..`/大写 digest/URL license、network_policy 一致性、exit_code 边界) |
| test_manifests_envelope.py | envelope 绑定/lineage/digest 对拍 | 8 | 4×(encode→decode 全等、digest 篡改 DIGEST_MISMATCH、lineage 缺项、PUBLIC/EPHEMERAL 拒绝) |
| test_manifests_import_isolation.py | 依赖隔离(AC-04) | 5 | import manifests → 域模块全不在 sys.modules;**十二模块反向断言**(逐模块 import → manifests 不在 sys.modules,12 断言合计 ≥1 用例);manifests 源码静态断言零禁止 import |
| test_manifests.py(续) | 类型化路径 + golden | 7 | run_manifest golden resource ids 类型化路径断言(§9-2);8 golden 字节钉死 digest;交叉引用链 codec 重算全等;future-minor round-trip 保留 |

**错误映射(§5-8,29 codes 复用,零新增)**:REQUIRED_FIELD_MISSING(缺必填)/UNKNOWN_FIELD(current-minor 未知字段)/INVALID_FIELD_TYPE/INVALID_FIELD_VALUE(词表、排序、一致性、exit_code)/UNKNOWN_ENUM_VALUE/INTEGER_OUT_OF_RANGE/MAX_ARRAY_LENGTH_EXCEEDED/MAX_STRING_LENGTH_EXCEEDED/DUPLICATE_SEMANTIC_FIELD/DIGEST_MISMATCH(lineage 对拍)/INVALID_UTF8/NFC 归一冲突——优先级同既有:结构(type)先于语义(value)先于引用(digest/lineage);同一违规多 code 竞争时以最靠近根因的字段路径报告(与 execution validator 求值顺序同构)。

## 14. 决策 D9(§5-9):命令与预期数字

```text
python -m pytest tests/contracts -q        # 预期 477+N passed(N 由冻结提交钉死)
python -m pytest tests -q                  # 预期 821+N passed, 1 skipped(= 822+N/0F/1 skip)
python -m ruff check --no-cache lima/contracts/manifests.py tests/contracts/test_manifests.py \
  tests/contracts/test_manifests_envelope.py tests/contracts/test_manifests_import_isolation.py
                                           # 预期 exit 0
```
基线复现(本 Packet 签发前 P&V 实跑,worktree @ 4619389):contracts **477 passed**;全量 **821 passed, 1 skipped**;`ruff check --no-cache lima/contracts/ tests/contracts/` exit 0。

## 15. 决策 D10(§5-10):CI 测试面(十一项 Checklist 第 11 条)

新增 12 文件全部落于既有顶层路径 `lima/contracts/` 与 `tests/contracts/fixtures/`;Dockerfile L45 `COPY tests ./tests`、L56 `COPY schemas ./schemas`、L61 `CMD python -m unittest discover -s tests` 已覆盖,**零 Dockerfile 变更,无需 DR**。不新增顶层路径(排除项:schemas/v4 JSON 导出属 PR3 类且登记面为既有测试,本 IP 不交付,见 §2 Rejected Inputs)。

## 16. 决策 D11(§5-11):环境记录

Windows 10 26200(22H2 后续)+ Git Bash;Python 3.12.4;ruff 经 `python -m ruff`;基线命令与数字见 §14;worktree `D:\BaseAIProject\LIMA-ip-0012-pkt-wt` 实测(等效路径 `D:\BaseAIProject\LIMA\BaseAIProjectLIMA-ip-0012-pkt-wt`,worktree 目录登记名)。无 redis/db/docker 依赖介入(contracts 面纯 stdlib)。

---

## 17. 十一项强制 Checklist(阶段一登记;2-10 阶段二启用)

| # | 项 | 阶段一状态 |
|---|---|---|
| 1 | 实例化镜像 | 阶段二启用 |
| 2 | 传输点零 PR | 阶段二启用(docs-only PR 即本轮先例) |
| 3 | symbols 计数 | Packet 已冻结公开面清单(§7);精确计数阶段二钉死 |
| 4 | helper 忠实性 | 阶段二启用 |
| 5 | 调用点签名兼容 | 阶段二启用(新模块无既有调用点,登记即可) |
| 6 | None 哨兵 | 阶段二启用(exit_code null 已在 §8 冻结语义) |
| 7 | GREEN 态冷缓存门禁 | 阶段二启用(ruff --no-cache 已入 §14 命令) |
| 8 | 负例生证 | 阶段二启用(负例类别已冻结于 §13) |
| 9 | 跨用例期望一致性 | 阶段二启用 |
| 10 | lineage 对拍 | 阶段二启用(对拍规则已冻结于 §8/§9) |
| 11 | CI 测试面新路径核对 | **阶段一已完成:PASS,零 Dockerfile 变更,无需 DR(§15)** |

## 18. Stop Conditions(沿用 Assignment §9,逐字有效)

不修改十二模块/PR3 产物/场景 fixture/既有测试;不实现 runtime/PR4/closure;不关闭 #58。特别地:§5 任一问题两解(本 Packet 已对全部 11 项给出单解,实现期发现两解即停)、golden 预计算无法复现、需修改既有契约才能自洽、cxx 触碰 contracts——任一发生即停提交 DR。

## 19. 完成定义

阶段二 RED 冻结(477+N/822+N 数字钉死)→ IMPL 交付 12 文件 → 独立验证三态结论 → fast-forward → Implementation PR(lifecycle §12.2,`Related to #58`,禁 auto-close)→ post-merge。FR-02 转 SATISFIED 由 Coordinator 裁定,不由本 Packet 宣布。

---

*签发:LIMA P&V Agent,2026-09-10(入口 Gate + 十一问单解实证基线 main @ `4619389071aef80812a77428e6fc2c509dca626b`)。*
