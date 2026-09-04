# LIMA Coding Agent IP-0003 正式开发任务交接书

> 任务:`IP-0003 Repository Profile / RAM Foundation`
>
> 状态:`PREPARED / AUTHORIZED WHEN BOTH IP-0003 DOCUMENTS ARE MERGED TO MAIN`
>
> 唯一施工规范:[LIMA Implementation Packet IP-0003](LIMA_Implementation_Packet_IP-0003_Repository_Profile.md)
>
> Source Issue:[#58](https://github.com/agent-sec-labs/LIMA/issues/58),仅完成第三个 slice;对 #58 影响:PARTIAL
>
> 最低代码基线:消费基线 `25f9aace3e8fe2349f50d8cb8710c79efebf58a4`;实现基线为包含 IP-0001-R1 恢复合并 `a0b3eeae303406698b849983117bb2b6db92eb3b`(PR #102)与两份 IP-0003 文档的最新 `origin/main`
>
> 推荐分支:`codex/ip-0003-repository-profile`

---

## 0. 交接书的效力与边界

本交接书已完成正式内容冻结;只有当本交接书与 IP-0003 Packet 都已合并到 `origin/main` 后,才正式授权一名 Coding Agent 实现 IP-0003。文档未合并时只允许 Review,不允许编码。

事实优先级:

1. 最新 `main` 的代码和可重复测试说明当前实现;
2. 稳定开发标准与治理规范说明长期安全、流程和权限不变量;
3. IP-0003 Packet 冻结本次目标行为、文件、symbols、wire shape、错误和测试;
4. 本交接书说明如何启动、实施、验证和离场;
5. Coordinator Assignment(#58 Ledger)说明队列与 Gate;
6. Source Issue 只提供背景,不能扩大 Packet。

冲突时不得猜测。Agent 必须保留现场并提交 Decision Request。

---

## 1. 正式授权

文档合并后唯一授权任务:

> 在最新 `main` 上新增一个 stdlib-only、无副作用、确定性、fail-closed 的 `lima.contracts.profile` 叶子模块,使 `RepositoryProfile`(kinds、languages/frameworks/package_managers/build_systems、code_roles、五类 attack-surface 清单、execution_capability、support_level、component_path、结构指标、coverage_gaps)成为完整、逐项可溯源、可版本演化的确定性 Artifact 契约,并安全绑定 IP-0001 `ArtifactEnvelope`(schema name `lima.repository-profile`、inline-only、lineage provenance、classification/retention 约束、content digest)。

本次不是 Classifier/RAM 实现(#60),不是 AEP/VEP/RVR 或任何 manifest/workflow schema,不是 JSON Schema 文件或兼容矩阵,也不是生产接线。

Agent 完成 IP-0003 后必须停止。不得自行领取 NEXT(IP-0004)。

---

## 2. 开工前必须按顺序完整阅读

1. `docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md`
2. `docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md`
3. `docs/LIMA_IMPLEMENTATION_AGENT_RESPONSIBILITY_CHARTER.md`
4. `docs/LIMA_Coding_Agent_IP-0003_正式开发任务交接.md`
5. `docs/LIMA_Implementation_Packet_IP-0003_Repository_Profile.md`
6. `CONTRIBUTING.md`
7. `lima/contracts/__init__.py`
8. `lima/contracts/errors.py`
9. `lima/contracts/codec.py`
10. `lima/contracts/common.py`
11. `lima/contracts/evidence.py`(只读参考:风格与 Envelope binding 模式;**不得 import**)
12. `tests/contracts/test_errors.py`、`test_codec.py`、`test_common.py`
13. `tests/contracts/test_evidence.py`、`test_evidence_envelope.py`、`test_evidence_import_isolation.py`(只读参考:测试风格)
14. #58 Delivery Ledger(背景:本 slice 定位与队列)

还必须只读了解以下边界,禁止复制或修改:`lima/models.py`、`lima/workspace.py`、`lima/python_dataflow.py`、`lima/semantic_retrieval.py`(#60 的实现输入)。

Packet 必须完整阅读,不能只读摘要、测试名或本交接书。

---

## 3. 已验证的仓库事实

截至本交接书生成时(P&V Agent 复验,PMV-0001 v2 + REC-IP-0001-R1):

```text
branch: main
HEAD: a0b3eeae303406698b849983117bb2b6db92eb3b(style: fix unsorted import block in IP-0001 frozen test (IP-0001-R1) (#102))
Python: 3.12.4 / Ruff: 0.16.5 / Bandit: 1.9.4
```

合并后验证(@ `a0b3eea`):

```text
python -m compileall -q lima scripts tests        → exit 0
python -m unittest discover -s tests/contracts    → 84 tests / 84 passed / 0 failed / 0 skipped
python -m ruff check lima/contracts tests/contracts → All checks passed / exit 0
python -m unittest discover -s tests              → 429 ran / 0 failed / 1 existing Windows symlink privilege skip
python -m unittest -v tests.test_repository_source tests.test_task_failure → 29 / 29 passed
```

消费者验证(Design Input Manifest §1 与 Packet §1 的依据):

- IP-0001 顶层 API(`__all__` = 18)与 **29** 个 error codes(F-IP3-002:文档"28"为笔误)保持冻结;
- `lima.contracts.evidence` 的 16 symbols 与 golden fixture(3740 bytes / `1b313f8c…96c51`)稳定;
- IP-0003 golden payload 已由 IP-0001 codec 预计算:2152 bytes / SHA-256 `ad7d53a0ed22412dbbfc60d0ed9183d7e939e2d14e4eee2d9399944cb5c4dccc`;
- Profile 是 pre-Audit Artifact,不需要也不得 import `lima.contracts.evidence`;跨 Artifact 事实经 `ArtifactReference` + Envelope lineage 表达。

这些是交接时参考证据。Implementation Agent 必须在自己的干净 worktree 中重新运行 baseline,并以实际输出为准。

---

## 4. 工作树保护与隔离分支

共享根工作树包含用户未跟踪的规划和交接文件。它们不属于 IP-0003,实现者不得:

- 删除、移动、覆盖或格式化;
- `git clean`;
- `git reset --hard`;
- 未经授权 stash;
- `git add .` 或批量加入 PR;
- 在共享根工作树直接实现功能。

确认两份 IP-0003 文档均已在远端 main 后,必须基于最新远端 main 建立独立 worktree,例如:

```powershell
git fetch origin
git merge-base --is-ancestor a0b3eeae303406698b849983117bb2b6db92eb3b origin/main
git branch --list codex/ip-0003-repository-profile
git worktree add -b codex/ip-0003-repository-profile D:\BaseAIProject\LIMA-ip-0003-wt origin/main
git -C D:\BaseAIProject\LIMA-ip-0003-wt status --short --branch
```

路径只是推荐值;若已存在,Agent 不得覆盖,必须选择新的明确路径并记录。

---

## 5. 开工前 Scope Confirmation

在任何代码编辑前,Agent 必须输出:

```text
## Scope Confirmation

Packet:IP-0003 Repository Profile / RAM Foundation(Packet 路径;证明文档合并条件已满足)
Base commit:<完整 SHA;证明包含 a0b3eea 和两份 IP-0003 文档>
工作分支:
隔离 worktree:
允许新增文件:5 个完整路径
允许修改既有文件:0 个
外部依赖:0 个
理解的 module public API:15 个 symbols,从 lima.contracts.profile 导入
理解的关键安全边界:逐项 provenance(≥1 source_artifact_id);path 禁尾随斜杠;比例 basis points 无 float;不 import evidence;classification 禁 public / retention 禁 ephemeral
理解的 Non-goals:
已运行 baseline:否(确认后立即运行)
发现的冲突或 Stop Condition:无 | <详细说明>
```

未输出 Scope Confirmation,不得编辑。

---

## 6. 唯一允许的文件范围

只允许新增:

```text
lima/contracts/profile.py
tests/contracts/test_profile.py
tests/contracts/test_profile_envelope.py
tests/contracts/test_profile_import_isolation.py
tests/contracts/fixtures/repository_profile_v4_golden.json
```

允许修改既有文件数量:`0`。

特别禁止:`lima/contracts/__init__.py`、`evidence.py`、`common.py`、`codec.py`、`errors.py`;IP-0001/IP-0002 的任何测试或 fixture;legacy models/workspace/dataflow;API/service/store/queue/scanner/sandbox/frontend;requirements、pyproject、CI、PROGRESS;任意范围外文档。

发现必须修改 forbidden 文件时立即停止。

---

## 7. 必须实现的公共 Contract(摘要)

### 7.1 Module-only public API

`lima.contracts.profile.__all__` 恰好 15 项:

```text
REPOSITORY_PROFILE_SCHEMA_NAME
RepositoryKind
CodeRole
SupportLevel
DetectionMethod
ExecutionCapability
TechnologyDeclaration
CodeRoleAssignment
AttackSurfaceEntry
ProfileCoverageGap
RepositoryProfile
decode_profile_payload
encode_profile_payload
decode_profile_envelope
encode_profile_envelope
```

不得修改 `lima.contracts.__all__`。

### 7.2 Domain chain

```text
repository_kinds        形态多值集合(unknown 排他)
languages / frameworks / package_managers / build_systems
                        TechnologyDeclaration(name + declared|inferred + provenance)
code_roles              CodeRoleAssignment(role + path(含目录前缀) + 组合证据 + provenance)
attack surface 五清单    AttackSurfaceEntry(entrypoints / external_inputs /
                        trust_boundaries / sensitive_operations / deployment_surface)
execution_capability    恰好 6 个 required bool
support_level           supported | partial | unsupported(平台承诺,非安全结论)
component_path          null=整仓;路径=组件作用域(monorepo 多 profile 共享同一 snapshot)
metrics                 file_count / total_bytes / max_file_bytes +
                        code_density_bp / binary_ratio_bp / generated_ratio_bp(0..10000)
coverage_gaps           ProfileCoverageGap(gap_code + detail)
```

### 7.3 Frozen semantics(摘要)

- 21 个 top-level required 字段;空清单合法且不编码安全结论;
- 全部数组按 Packet §14.1 排序且唯一,Contract 拒绝不排序输入;超限 `MAX_ARRAY_LENGTH_EXCEEDED`;
- kind 语义:≥1;`unknown` 排他;code 类 kind(application/library/cli/monorepo)要求 languages 非空;
- metrics:max ≤ total;file_count==0 ⇒ bytes 全 0;三个 `*_bp` ∈ 0..10000;全部禁 bool、无 float;
- 每条分类声明 `source_artifact_ids` ≥1 且必须存在于 Envelope lineage;
- path 规则与 IP-0002 `SourceLocation.path` 相同(repo-relative、禁尾随 `/`);
- schema name `lima.repository-profile`;仅 inline payload;classification 禁 `public`;retention 禁 `ephemeral`;
- 4.0 unknown field 拒绝;未来 4.x unknown optional 字段在每层级经 `extensions` 无损 round-trip;unknown enum 永远 fail closed;
- 无 confidence/severity/trust_score/is_secure/is_safe 字段;不生成 ID/digest/时间/指标。

字段、构造器、wire shape、数组上限、错误码优先级和 golden fixture 的完整定义以 Packet §8–§17 为准,不得凭本节摘要实现。

---

## 8. 明确 Non-goals

Agent 不得实现:Classifier/inventory/语言探测/code-role 判定启发式;RAM 图、entrypoint/数据流抽取、component graph 计算;AEP/VEP/RVR;Task/ToolBundle/Dependency/Sandbox manifests;Workflow/StageAttempt/Outcome/Plan/RunManifest/Summary/Failure schema;JSON Schema 文件、兼容矩阵、ADR;legacy adapter;Artifact Registry/blob;API/Service/DB/Queue/UI 接线;Mining、Repair 或 Sandbox;Pydantic/JSON Schema 库;float 指标或 confidence/severity 字段;任何模型调用、网络或目标代码执行;GitHub Issue/Label/PR merge 操作;IP-0004。

---

## 9. 开工 Baseline

Scope Confirmation 后、编辑前运行:

```powershell
python -m compileall -q lima scripts tests
python -m unittest discover -s tests/contracts -v
python -m unittest -v tests.test_repository_source tests.test_task_failure
git status --short --branch
```

参考值(@ `a0b3aac` + Packet 文档):contracts 84 PASS;定向兼容 29 PASS。以实际 base 为准并记录完整命令、退出码和数量。若 baseline 失败:不修改产品代码;证明是否为 base 既有失败;无法可靠归因时提交 Decision Request;不把环境问题隐藏为测试通过。

---

## 10. 强制开发顺序

严格按 Packet §20:

1. enum / 5 个 nested object tests 先 RED,再实现;
2. `RepositoryProfile` kinds/metrics/surface/compatibility tests 先 RED,再实现全图校验;
3. 逐字节验证 golden fixture(2152 / `ad7d53a0…c4dccc`);
4. Envelope tests 先 RED,再实现 4 个 binding functions;
5. import isolation(含不 import evidence)与 forbidden-key tests;
6. Slice Gate;
7. Compatibility / File Boundary Gate;
8. Completion Summary。

每个行为必须映射到 AC 和机器测试。不得先实现后弱化测试。

---

## 11. Frozen Golden Vector

Agent 必须逐字使用 Packet §17 fixture:

```text
file size: 2152 bytes
payload sha256: ad7d53a0ed22412dbbfc60d0ed9183d7e939e2d14e4eee2d9399944cb5c4dccc
encoding: UTF-8 / BOM: none / trailing newline: none
envelope vector: schema=lima.repository-profile, version=4.0, artifact_id=profile-0001,
  stage_attempt_id=classify-1, producer=lima-profile-classifier,
  classification=internal, retention=standard, lineage=[lima.tool-run/tool-run-0001]
```

若实际 IP-0001 canonical codec 无法重现,属于 Stop Condition,不得更改 fixture 或 digest。

---

## 12. Acceptance Criteria

必须逐项完成(Packet §19 全表):

| AC | 交付要求 |
|---|---|
| IP3-AC-01 | 15 symbols、4 enums、6 constructors exact |
| IP3-AC-02 | name/path/symbol/reason/gap/metric/bool scalar fail closed |
| IP3-AC-03 | golden 2152-byte canonical round-trip 和固定 digest |
| IP3-AC-04 | kind 多值/unknown 排他/code-kind↔languages/metrics 一致性 |
| IP3-AC-05 | 五清单 + code_roles 排序唯一、目录前缀、provenance、上限 |
| IP3-AC-06 | Envelope schema/version/payload/digest/lineage/classification/retention binding |
| IP3-AC-07 | current/future minor 每层级兼容;unknown enum fail closed |
| IP3-AC-08 | 无 confidence/severity/trust_score/is_secure/is_safe 字段 |
| IP3-AC-09 | stdlib leaf;不 import evidence;不改顶层 API/29 错误码 |
| IP3-AC-10 | 5 added / 0 modified / 0 deps / 全量回归无新增失败(预期 475) |

Packet 冻结至少 46 个新 test methods(33+9+4);不得减少或重命名 required tests。

---

## 13. Slice / Compatibility / Boundary Gates

### Slice Gate

```powershell
python -m compileall -q lima/contracts tests/contracts
python -m unittest discover -s tests/contracts -v
python -m ruff check lima/contracts/profile.py tests/contracts/test_profile.py tests/contracts/test_profile_envelope.py tests/contracts/test_profile_import_isolation.py
python -m ruff check lima/contracts tests/contracts
python -m bandit -q -r lima/contracts/profile.py
git diff --check
```

### Compatibility Gate

```powershell
python -m unittest -v tests.test_repository_source tests.test_task_failure
python -m unittest discover -s tests -v
```

### File Boundary Gate

```powershell
git diff --name-only --diff-filter=ACMRTUXB origin/main...HEAD
git diff --check origin/main...HEAD
```

输出必须恰好为 5 个 allowlist 文件。任一 existing file 被修改即 NOT DONE。

### PR Gate

- 独立 Reviewer;required `merge-gate`;只写 `Related to #58`;不使用任何自动关闭 #58 的关键字;Agent 不自合并。

---

## 14. Stop Conditions 与 Decision Request

以下情况必须停止:同名实现/Owner/branch 冲突;base 不包含 `a0b3eea` 或两份 IP-0003 文档;需要修改任一 existing/forbidden file;需要新增 dependency/I/O/权限;Packet 对 constructor/wire/排序/错误/compatibility 有多解;golden bytes/digest 不可重现;需要 float、confidence/severity、自动 ID 或放宽 provenance 才能继续;需要 classifier/RAM 图/JSON Schema 才能通过测试;baseline/回归失败无法归因;required tests 无法证明 AC;任务实际进入 AEP/VEP/RVR/manifest/workflow/生产接线;全目录 ruff 出现新违规。

必须报告(Packet §23 格式):

```text
Packet/规则位置:
实际代码证据:
最小复现命令:
为什么无法在 5-file allowlist 内解决:
可选方案及影响:
Agent 建议:
```

---

## 15. Commit 与 PR 说明

推荐 commit/PR title:

```text
feat: add deterministic repository profile contracts
```

PR 首部关联语句必须是:

```text
Related to #58
```

不要在 PR 的任何肯定、否定、注释或 checklist 中把 close/fix/resolve 类关键字与 `#58` 相邻书写。

PR 必须包含:Goal/Non-goals;5 added / 0 modified / 0 dependencies;public API 和 wire semantics;AC → Test → Result;golden bytes/digest;全部真实命令、退出码、pass/fail/skip;no production integration / no classifier / no top-level API change / evidence.py untouched;Findings/Decision Requests;回滚说明:删除 5 个新增文件即可,不影响 legacy runtime 与既有 84 contracts 测试。

---

## 16. 强制 Completion Summary

无论 DONE、BLOCKED 或中断,都必须按 Packet §25 原样输出完整 Summary。只说"测试通过"不能交接。

---

## 17. 可直接交给 Coding Agent 的任务指令

```text
你是 LIMA IP-0003 Repository Profile / RAM Foundation 的唯一 Implementation Agent。

必须按顺序完整阅读:
1. docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md
2. docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md
3. docs/LIMA_IMPLEMENTATION_AGENT_RESPONSIBILITY_CHARTER.md
4. docs/LIMA_Coding_Agent_IP-0003_正式开发任务交接.md
5. docs/LIMA_Implementation_Packet_IP-0003_Repository_Profile.md
6. CONTRIBUTING.md
7. Packet/交接书列出的 IP-0001/0002 contracts 与 tests(只读)和 #60 边界(只读)

只有在两份 IP-0003 文档已合并到 main 后才开始。基于最新 origin/main(必须包含
a0b3eeae303406698b849983117bb2b6db92eb3b、本 Packet 和正式交接书),创建独立干净 worktree 和
codex/ip-0003-repository-profile 分支。任何编辑前先输出 Scope Confirmation,再运行 baseline。

唯一允许的变更是新增 Packet 列出的 5 个文件;允许修改既有文件为 0,外部依赖为 0。公共 API 只存在于
lima.contracts.profile(15 symbols),不修改 lima.contracts.__init__、errors、codec、common、
evidence 或 legacy 业务代码,也不 import lima.contracts.evidence。

必须测试先行,实现冻结的 RepositoryKind/CodeRole/SupportLevel/DetectionMethod、
ExecutionCapability、TechnologyDeclaration、CodeRoleAssignment、AttackSurfaceEntry、
ProfileCoverageGap、RepositoryProfile 与 Envelope binding(schema name lima.repository-profile)。
逐项 provenance、path 规则(禁尾随斜杠)、basis points(无 float)、kinds 语义、metrics 一致性、
数组排序唯一、4.0/future-minor 规则全部 fail closed。完整执行 46 个 required tests、Ruff(含全目录)、
Bandit、全量 unittest(预期 475)和 file boundary gate。

遇到同名实现、文件越界、Contract 多解、golden digest(2152/ad7d53a0…c4dccc)不一致、
依赖/权限扩张、无法归因的 baseline failure 或任何 Stop Condition,立即停止并提交 Decision Request。
不得自行修改 Packet、Issue 或测试以绕过。

完成后按 Packet §25 输出完整 Completion Summary。PR 只能写 Related to #58;不得合并自己的 PR,
不得启动 IP-0004。
```

---

## 18. Maintainer 接收标准

维护者只在以下条件全部满足时接收:

- 5 个新增文件,0 个 existing modifications;
- 0 个第三方依赖和 0 个权限扩张;
- module-only 15-symbol public API;`lima.contracts.evidence` 未被 import;
- IP-0001 顶层 API(18)、29 个 error codes、IP-0002 的 16 symbols 完全不变;
- golden fixture 2152 bytes / digest `ad7d53a0…c4dccc` 正确;
- 10 个 AC 全部有机器证据;至少 46 个新增 required tests;
- kinds/metrics/provenance/surface/compatibility negative gates 通过;
- Envelope lineage/classification/retention Gate 通过;
- Ruff(含全目录 exit 0)、Bandit、diff check、全量回归(475)通过;
- Completion Summary 完整;独立 Review 和 `merge-gate` 通过;PR 未改变 #58 状态;
- 未提前实现 IP-0004、classifier 或生产接线。

---

## 19. 当前唯一下一步

> 先以独立 docs-only PR 将本交接书、IP-0003 Packet 和更新后的 `docs/DEVELOPER_HANDOFF.md` 合并到 `main`。合并后,P&V Agent 从 Packet merge commit 冻结测试并证明 RED(阶段二),再由 Coordinator 激活唯一 Implementation Agent;该 Agent 在独立干净 worktree 中输出 Scope Confirmation、复跑 baseline,并从第一个 RED test 开始。除此之外不启动并行实现任务。
