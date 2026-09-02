# LIMA Coding Agent IP-0004 正式开发任务交接书

> 任务:`IP-0004 Audit Evidence Package(AEP)Foundation`
>
> 状态:`PREPARED / AUTHORIZED WHEN BOTH IP-0004 DOCUMENTS ARE MERGED TO MAIN AND TESTS ARE FROZEN`
>
> 唯一施工规范:[LIMA Implementation Packet IP-0004](LIMA_Implementation_Packet_IP-0004_AEP_Foundation.md)
>
> Source Issue:[#58](https://github.com/agent-sec-labs/LIMA/issues/58),仅完成第四个 slice;对 #58 影响:PARTIAL
>
> 最低代码基线:Assignment 基线 `9078bb52494075a5c6d8e7aefb544e2433cb4195`(IP-0003 实现,PR #104);实现分支依 lifecycle §9.1 **从 Frozen Test Commit 派生**(SHA 由阶段二交付物指定;Ledger 2026-09-02 基线裁定:与"基于最新 origin/main"冲突时以 lifecycle 为准)
>
> 推荐分支:`codex/ip-0004-aep-foundation`

---

## 0. 交接书的效力与边界

本交接书已完成正式内容冻结;只有当本交接书与 IP-0004 Packet 都已合并到 `origin/main`、且 P&V 已交付 Frozen Test Commit 与有效 RED 证据后,才由 Coordinator 出具 Implementation Assignment 正式授权编码。此前只允许 Review。

事实优先级:最新 main 代码与可重复测试 > 稳定标准与治理规范 > IP-0004 Packet > 本交接书 > Coordinator Assignment/Ledger > Source Issue 背景。冲突时不得猜测,保留现场提交 Decision Request。

---

## 1. 正式授权

> 在指定基线上新增一个 stdlib-only、无副作用、确定性、fail-closed 的 `lima.contracts.aep` 叶子模块,使 `AuditEvidencePackage`(package_status、revision、audit_depth、audit_outcome、内嵌 `EvidenceDomainBundle`、mining eligibility、coverage/budget/gaps、类型化 profile 引用)成为完整、可版本演化的确定性 Artifact 契约,并安全绑定 IP-0001 `ArtifactEnvelope`(schema name `lima.audit-evidence-package`、inline-only、lineage、classification/retention、content digest)。

本次不是 Audit pipeline / seal API / revision 存储 / 幂等提交(#68 与未来 Registry),不是 VEP/RVR/manifest/workflow schema,不是 JSON Schema 文件,也不是生产接线。

Agent 完成 IP-0004 后必须停止,不得自行领取 NEXT。

---

## 2. 开工前必须按顺序完整阅读

1. `docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md`
2. `docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md`
3. `docs/LIMA_IMPLEMENTATION_AGENT_RESPONSIBILITY_CHARTER.md`
4. `docs/LIMA_Coding_Agent_IP-0004_正式开发任务交接.md`
5. `docs/LIMA_Implementation_Packet_IP-0004_AEP_Foundation.md`
6. `CONTRIBUTING.md`
7. `lima/contracts/{__init__,errors,codec,common,evidence,profile}.py`(evidence 必须——本 IP 内嵌其类型;profile 只读——仅经 lineage 引用,禁止 import)
8. `tests/contracts/test_evidence*.py`、`test_profile*.py`(风格与模式;只读)
9. #58 Delivery Ledger v5(背景:本 slice 定位、基线裁定)
10. #68 正文(背景:AEP 语义需求来源;其集成职责明确不在本 IP)

Packet 必须完整阅读,不能只读摘要、测试名或本交接书。

---

## 3. 已验证的仓库事实(P&V,2026-09-02)

```text
branch: main
HEAD: 9078bb52494075a5c6d8e7aefb544e2433cb4195(feat: add deterministic repository profile contracts (#104))
Python: 3.12.4 / Ruff: 0.16.5 / Bandit: 1.9.4
```

合并后验证(@ `9078bb5`,IP-0003 post-merge 双重验证):

```text
python -m compileall -q lima scripts tests          → exit 0
python -m unittest discover -s tests/contracts      → 130 tests / 130 passed / 0 failed / 0 skipped
python -m ruff check lima/contracts tests/contracts → All checks passed / exit 0
python -m unittest discover -s tests                → 475 ran / 0 failed / 1 existing Windows symlink privilege skip
python -m unittest -v tests.test_repository_source tests.test_task_failure → 29 / 29 passed
```

消费者验证(Packet §1 依据):由 profile Envelope 实际构造 `ArtifactReference(lima.repository-profile / profile-0001 / ad7d53a0…)` 成功并可置于 AEP lineage 通过 IP-0001 校验;`REPOSITORY_PROFILE_SCHEMA_NAME` 可导入支持类型化 lineage 校验;**无 Contract Gap**。

Golden 预计算(IP-0001 codec @ `9078bb5`):AEP golden payload **4235 bytes / SHA-256 `f0a985432ebd11dc4b85897653cf443dc2c0b0312e453424648ebc2d164705d0`**,内嵌 evidence 图与 IP-0002 golden(3740B / `1b313f8c…`)逐字节一致。

这些是交接时参考证据;Implementation Agent 必须在自己的干净 worktree 重新运行 baseline 并以实际输出为准。

---

## 4. 工作树保护与隔离分支

共享根工作树包含用户未跟踪的规划和交接文件,不得删除、移动、覆盖、格式化、`git clean`、`git reset --hard`、未经授权 stash、`git add .` 或在共享根工作树直接实现。

开工条件(两份 IP-0004 文档在 main + Frozen Test Commit 交付)满足后:

```powershell
git fetch origin
git merge-base --is-ancestor 9078bb52494075a5c6d8e7aefb544e2433cb4195 <frozen-test-commit>
git worktree add -b codex/ip-0004-aep-foundation D:\BaseAIProject\LIMA-ip-0004-impl-wt <frozen-test-commit>
```

(具体 Frozen Test Commit SHA 以 P&V 阶段二交付物为准;`<frozen-test-commit>` 必须是包含本 Packet 的 main 后代。)路径仅为推荐值;已存在时另选并记录。

---

## 5. 开工前 Scope Confirmation

任何编辑前必须输出:

```text
## Scope Confirmation

Packet:IP-0004 AEP Foundation(Packet 路径;证明两份文档已合并、Frozen Test Commit SHA 与 RED 记录已核对)
Base commit / Frozen Test Commit:<完整 SHA;证明包含 9078bb5 与两份 IP-0004 文档>
工作分支 / 隔离 worktree:
允许新增文件:5 个完整路径
允许修改既有文件:0 个
外部依赖:0 个
理解的 module public API:13 个 symbols,从 lima.contracts.aep 导入;依赖方向 aep→{evidence,codec,common,errors};不 import profile
理解的关键安全边界:eligibility 恰等于 statically_supported 集;outcome 词表无安全终态;incomplete⇒gaps;类型化 profile lineage;D3/D4 拒绝(内嵌图);仅 inline;classification 禁 public / retention 禁 ephemeral
理解的 Non-goals:
已运行 baseline:否(确认后立即运行)
发现的冲突或 Stop Condition:无 | <详细说明>
```

未输出 Scope Confirmation,不得编辑。

---

## 6. 唯一允许的文件范围

只允许新增(Packet §7.1):

```text
lima/contracts/aep.py
tests/contracts/test_aep.py
tests/contracts/test_aep_envelope.py
tests/contracts/test_aep_import_isolation.py
tests/contracts/fixtures/audit_evidence_package_v4_golden.json
```

(测试与 fixture 由 P&V 冻结交付;Implementation Agent 对其只读。)允许修改既有文件:`0`。

特别禁止:`lima/contracts/{__init__,evidence,profile,common,codec,errors}.py`;IP-0001/0002/0003 的任何测试或 fixture;legacy models/service/api/task_progress/repository_scanner;requirements、pyproject、CI、PROGRESS;任意范围外文档。

---

## 7. 必须实现的公共 Contract(摘要)

### 7.1 Module-only public API

`lima.contracts.aep.__all__` 恰好 **13** 项:

```text
AUDIT_EVIDENCE_PACKAGE_SCHEMA_NAME
AuditPackageStatus      # draft | sealed
AuditDepth              # initial | deep
AuditOutcome            # completed | incomplete | no_actionable_hypothesis | no_supported_attack_surface
AuditCoverage           # in_scope_file_count / analyzed_file_count
AuditBudget             # tool_runs / model_calls / model_tokens / wall_clock_ms
AuditCoverageGap        # gap_code + detail
AuditEvidencePackage
decode_aep_payload
encode_aep_payload
decode_aep_envelope
encode_aep_envelope
```

不得修改 `lima.contracts.__all__`。

### 7.2 冻结语义(摘要)

- payload 10 个 required 字段;`evidence_domain` 键内嵌完整 IP-0002 bundle wire(由 `EvidenceDomainBundle.from_dict` 原样校验、错误 repath `$.evidence_domain.*`);
- **eligibility 精确等价**:`mining_eligible_hypothesis_ids` 恰等于内嵌图中全部 `statically_supported` 假设的 id 集(多列/少列均拒绝);
- **outcome 映射**:eligible 非空 ⇒ completed;为空 ⇒ ∈{no_actionable_hypothesis, no_supported_attack_surface, incomplete};incomplete ⇒ coverage_gaps 非空;
- coverage:`0 ≤ analyzed ≤ in_scope`;revision:exact int ≥1(单调性/幂等/append-only 属 Registry/#68);全部计量非负 exact int,无 float;
- 类型化 lineage:`repository_profile_artifact_ids`(≥1,≤16)成员必须存在于 lineage 且对应条目 `schema_name == lima.repository-profile`;内嵌图 evidence 来源 ⊆ lineage;lineage 允许多余条目;
- schema name `lima.audit-evidence-package`;仅 inline;classification 禁 `public`;retention 禁 `ephemeral`;
- 4.0 unknown field 拒绝;未来 4.x 经 `extensions` 每层级无损 round-trip;unknown enum 永远 fail closed;
- 无 verified/safe/clear/is_vulnerable/confidence/severity/trust_score 字段;不生成 ID/revision/digest/时间/计量。

字段、构造器、wire shape、数组上限、错误码优先级和 golden fixture 的完整定义以 Packet §9–§17 为准,不得凭本节摘要实现。

---

## 8. 明确 Non-goals

不得实现:AuditPipeline/run_fast/run_deep、seal API、progress、Audit Cache、worker/retry/cancel、staging/幂等提交(#68);Artifact Registry/blob/latest-sealed pointer/revision 链验证;Signal qualification/clustering/Fusion/Planner(#61/#64);VEP/RVR/manifests/workflow schemas;JSON Schema/兼容矩阵/ADR;legacy adapter;API/Service/DB/Queue/UI 接线;float 指标或 confidence/severity;模型调用/网络/目标代码执行;GitHub Issue/PR 操作;IP-0005。

---

## 9. 开工 Baseline

Scope Confirmation 后、编辑前:

```powershell
python -m compileall -q lima scripts tests
python -m unittest discover -s tests/contracts -v
python -m unittest -v tests.test_repository_source tests.test_task_failure
git status --short --branch
```

参考值(@ Packet 合并后 main):contracts 130 PASS;定向 29 PASS。若 baseline 失败:不改产品代码;证明是否既有失败;无法归因提交 Decision Request。

---

## 10. 强制开发顺序

严格按 Packet §20(测试已由 P&V 冻结并证明 RED):枚举/validators/三 nested object → `AuditEvidencePackage` 跨字段校验 → 逐字验证 golden → 4 个 binding functions → import isolation/forbidden-key → Slice Gate → Compatibility Gate → File Boundary Gate → Completion Summary。每个行为必须映射 AC 与机器测试。

---

## 11. Frozen Golden Vector

逐字使用 Packet §17:

```text
file size: 4235 bytes
payload sha256: f0a985432ebd11dc4b85897653cf443dc2c0b0312e453424648ebc2d164705d0
encoding: UTF-8 / BOM: none / trailing newline: none
内嵌 evidence_domain = IP-0002 golden(1b313f8c…96c51)
envelope vector: schema=lima.audit-evidence-package, 4.0, aep-0001, audit-1, lima-audit,
  sensitive/audit, lineage=[lima.repository-profile/profile-0001/ad7d53a0…,
  lima.tool-run/tool-run-0001/"4"*64], supersedes=null
```

若 IP-0001 codec 无法重现,属 Stop Condition,不得更改 fixture 或 digest。

---

## 12. Acceptance Criteria

逐项完成(Packet §19 全表;IP4-AC-01…10)。Packet 冻结至少 **40** 个新 test methods(25+11+4);不得减少或重命名。

---

## 13. Slice / Compatibility / Boundary Gates

```powershell
# Slice Gate
python -m compileall -q lima/contracts tests/contracts
python -m unittest discover -s tests/contracts -v
python -m ruff check lima/contracts/aep.py tests/contracts/test_aep.py tests/contracts/test_aep_envelope.py tests/contracts/test_aep_import_isolation.py
python -m ruff check lima/contracts tests/contracts
python -m bandit -q -r lima/contracts/aep.py
git diff --check

# Compatibility Gate
python -m unittest -v tests.test_repository_source tests.test_task_failure
python -m unittest discover -s tests -v      # 预期 515 = 475+40 / 1 既有 skip

# File Boundary Gate(相对 Frozen Test Commit)
git diff --name-only --diff-filter=ACMRTUXB <frozen-test-commit>...HEAD   # 恰好 lima/contracts/aep.py
git diff --check <frozen-test-commit>...HEAD

# PR Gate:独立 Reviewer;required merge-gate;只写 Related to #58;禁 auto-close;不自合并
```

---

## 14. Stop Conditions 与 Decision Request

同 Packet §23(12 项),关键:基线漂移/同名冲突/越界/依赖/多解/golden 不可重现/需 float·confidence·安全终态·自动 revision/需 pipeline·seal·registry·blob/baseline 无法归因/AC 无证据/范围上移。报告格式见 Packet §23;维护者决策前不得继续。

---

## 15. Commit 与 PR 说明

推荐 commit/PR title:`feat: add deterministic audit evidence package contracts`。PR 首部关联语句必须是 `Related to #58`;不得把 close/fix/resolve 类关键字与 `#58` 相邻书写。PR 必须包含 Goal/Non-goals、5 added / 0 modified / 0 dependencies、AC → Test → Result、golden bytes/digest、全部真实命令与统计、no production integration、evidence.py 与 profile.py untouched、Findings、回滚说明(删除 5 个新增文件即可)。

---

## 16. 强制 Completion Summary

无论 DONE、BLOCKED 或中断,按 Packet §25 原样输出完整 Summary;只说"测试通过"不能交接。

---

## 17. 可直接交给 Coding Agent 的任务指令

```text
你是 LIMA IP-0004 Audit Evidence Package(AEP)Foundation 的唯一 Implementation Agent。

必须按顺序完整阅读:
1. docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md
2. docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md
3. docs/LIMA_IMPLEMENTATION_AGENT_RESPONSIBILITY_CHARTER.md
4. docs/LIMA_Coding_Agent_IP-0004_正式开发任务交接.md
5. docs/LIMA_Implementation_Packet_IP-0004_AEP_Foundation.md
6. CONTRIBUTING.md
7. Packet 列出的 lima/contracts 六个模块与 tests/contracts 既有测试(只读)

只有在两份 IP-0004 文档已合并到 main、且 Coordinator 出具 Implementation Assignment 指定 Frozen Test
Commit 后才开始。依 lifecycle §9.1 从 Frozen Test Commit(而非 main)派生 codex/ip-0004-aep-foundation
独立干净 worktree;任何编辑前输出 Scope Confirmation,再运行 baseline(contracts 预期 130 PASS)。

唯一允许的变更是新增 lima/contracts/aep.py(Packet §7.1 五文件 allowlist 中的唯一产品文件);允许修改
既有文件为 0,外部依赖为 0;冻结测试/fixture 只读。公共 API 只存在于 lima.contracts.aep(13 symbols),
依赖方向 aep→{evidence,codec,common,errors},不 import lima.contracts.profile;不改 __init__、evidence、
profile、common、codec、errors 或 legacy 业务代码。

必须实现冻结的 AuditPackageStatus/AuditDepth/AuditOutcome、AuditCoverage、AuditBudget、
AuditCoverageGap、AuditEvidencePackage 与 Envelope binding(schema name lima.audit-evidence-package)。
内嵌 evidence_domain 由 IP-0002 EvidenceDomainBundle 原样校验;eligibility 恰等于 statically_supported
集;outcome 映射与 incomplete⇒gaps 强制;类型化 profile lineage;classification 禁 public/retention 禁
ephemeral;4.0/future-minor 每层级规则 fail closed。完整执行 40 个 required tests、Ruff(含全目录)、
Bandit、全量 unittest(预期 515 = 475+40)与 file boundary gate。

遇到同名实现、文件越界、Contract 多解、golden digest(4235/f0a98543…)不可重现、依赖/权限扩张、
无法归因的 baseline failure 或任何 Stop Condition,立即停止并提交 Decision Request;不得自行修改
Packet、Issue 或冻结测试以绕过。

完成后按 Packet §25 输出完整 Completion Summary,交 P&V Agent 独立验证;不自行开 PR,不启动 IP-0005。
```

---

## 18. Maintainer 接收标准

5 新增/0 修改/0 依赖;13-symbol module API 且依赖方向正确(加载 evidence、不加载 profile);冻结面(18/16/15/29、两 golden digest)不变;golden 4235B/`f0a98543…` 且内嵌图与 IP-0002 golden 一致;10 个 AC 有机器证据;≥40 required tests;eligibility/outcome/类型化 lineage/current-future-minor negative gates 通过;Ruff(全目录 exit 0)/Bandit/diff check/全量 515 通过;Completion Summary 完整;独立 Review 与 merge-gate 通过;PR 未改变 #58 状态;未提前实现 pipeline/seal/registry 或 IP-0005。

---

## 19. 当前唯一下一步

> 先以独立 docs-only PR 将本交接书、IP-0004 Packet 和更新后的 `docs/DEVELOPER_HANDOFF.md` 合并到 `main`。合并后,P&V 依 lifecycle §9 自动进入阶段二(冻结 40 个测试 + fixture、证明 RED、交付 Frozen Test Commit 与 digest);随后由 Coordinator 出具 Implementation Assignment 激活唯一 Implementation Agent。除此之外不启动并行实现任务。
