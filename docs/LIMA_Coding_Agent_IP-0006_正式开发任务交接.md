# LIMA Coding Agent IP-0006 正式开发任务交接书

> 任务:`IP-0006 Repair Verification Report(RVR)Foundation`
>
> 状态:`PREPARED / AUTHORIZED WHEN BOTH IP-0006 DOCUMENTS ARE MERGED TO MAIN AND TESTS ARE FROZEN`
>
> 唯一施工规范:[LIMA Implementation Packet IP-0006](LIMA_Implementation_Packet_IP-0006_RVR_Foundation.md)
>
> Source Issue:[#58](https://github.com/agent-sec-labs/LIMA/issues/58),仅完成第六个 slice;对 #58 影响:PARTIAL
>
> 最低代码基线:Assignment 基线 `8afc594b194b9bce4cec4930901f88bbb4fdda83`(IP-0005 实现,PR #110);实现分支依 lifecycle §9.1 从 Frozen Test Commit 派生(SHA 由阶段二交付物指定)
>
> 推荐分支:`codex/ip-0006-rvr-foundation`

---

## 0. 交接书的效力与边界

本交接书已完成正式内容冻结;只有当本交接书与 IP-0006 Packet 都已合并到 `origin/main`、且 P&V 已交付 Frozen Test Commit 与有效 RED 证据(含 §20 一致性预检记录,含实例化镜像项)后,才由 Coordinator 出具 Implementation Assignment 正式授权编码。此前只允许 Review。

事实优先级:最新 main 代码与可重复测试 > 稳定标准与治理规范 > IP-0006 Packet > 本交接书 > Assignment/Ledger > Source Issue 背景。冲突时保留现场提交 Decision Request。

---

## 1. 正式授权

> 在指定基线上新增一个 stdlib-only、无副作用、确定性、fail-closed 的 `lima.contracts.rvr` 叶子模块,使 `RepairVerificationReport`(源 VEP 类型化三元组引用、逐候选 × 逐 Gate 矩阵、mandatory 双 preservation Gate、producer≠generator、patch digest 唯一)成为完整、可版本演化的确定性 Artifact 契约,并安全绑定 IP-0001 `ArtifactEnvelope`(`lima.repair-verification-report`、inline-only、lineage、classification/retention、digest)。

本次不是候选生成/scope policy(#76),不是 Gate 执行器(#77/#94),不是 CandidateManifest/其他 manifest schema,不是 workflow 族 schema,也不是生产接线。

Agent 完成 IP-0006 后必须停止,不得自行领取 NEXT。

---

## 2. 开工前必须按顺序完整阅读

1. `docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md`(§17 Repair 不变量重点)
2. `docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md`
3. `docs/LIMA_IMPLEMENTATION_AGENT_RESPONSIBILITY_CHARTER.md`
4. `docs/LIMA_Coding_Agent_IP-0006_正式开发任务交接.md`
5. `docs/LIMA_Implementation_Packet_IP-0006_RVR_Foundation.md`
6. `CONTRIBUTING.md`
7. `lima/contracts/{__init__,errors,codec,common}.py`(本 IP 仅依赖此四个;evidence/profile/aep/vep 只读——仅经 lineage 引用,禁止 import)
8. `tests/contracts/` 既有测试与 fixture(风格参考;只读)
9. #58 Delivery Ledger v13(背景:定序终审与三项强制 Checklist)
10. #76 正文(背景:候选语义;"最终 Gates/RVR 不在 #76")

Packet 必须完整阅读,不能只读摘要、测试名或本交接书。

---

## 3. 已验证的仓库事实(P&V,2026-09-02)

```text
branch: main @ 8afc594b194b9bce4cec4930901f88bbb4fdda83(feat: add deterministic vulnerability evidence package contracts (#110))
Python: 3.12.4 / Ruff: 0.16.5 / Bandit: 1.9.4
```

合并后验证(@ `8afc594`,IP-0005 post-merge 双重验证):

```text
python -m compileall -q lima scripts tests          → exit 0
python -m unittest discover -s tests/contracts      → 211 / 211 passed / 0 failed / 0 skipped
python -m ruff check lima/contracts tests/contracts → All checks passed / exit 0
python -m unittest discover -s tests                → 556 ran / 0 failed / 1 existing skip
python -m unittest -v tests.test_repository_source tests.test_task_failure → 29 / 29 passed
```

消费者验证(Packet §1):VepReference 三元组可构造且可类型化核对;VEP verdict 继承属消费侧/Registry(单解);`EvidenceSubjectKind` 无 candidate 主体 → GateResult 必须本地值类型;**无 Contract Gap**。

Golden 预计算(IP-0001 codec @ `8afc594`):RVR golden payload **1709 bytes / SHA-256 `a9a35d358308a2957b9182d2ca5e503903d8c7282c6c43bb09d1680313cb2cac`**,source_vep.digest = VEP golden 真实值。

这些是交接时参考证据;Implementation Agent 必须在自己的干净 worktree 重新运行 baseline 并以实际输出为准。

---

## 4. 工作树保护与隔离分支

共享根工作树未跟踪文件属用户资产,不得删除、移动、覆盖、`git clean`、`git reset --hard`、未经授权 stash、`git add .` 或在共享根工作树直接实现。

开工条件(两份 IP-0006 文档在 main + Frozen Test Commit 交付)满足后:

```powershell
git fetch origin
git merge-base --is-ancestor 8afc594b194b9bce4cec4930901f88bbb4fdda83 <frozen-test-commit>
git worktree add -b codex/ip-0006-rvr-foundation D:\BaseAIProject\LIMA-ip-0006-impl-wt <frozen-test-commit>
```

(具体 Frozen Test Commit SHA 以 P&V 阶段二交付物为准。)

---

## 5. 开工前 Scope Confirmation

任何编辑前必须输出:

```text
## Scope Confirmation

Packet:IP-0006 RVR Foundation(证明两份文档已合并、Frozen Test Commit SHA 与 RED 记录(含实例化镜像预检)已核对)
Base commit / Frozen Test Commit:<完整 SHA;证明包含 8afc594 与两份 IP-0006 文档>
工作分支 / 隔离 worktree:
允许新增文件:5 个完整路径
允许修改既有文件:0 个 / 外部依赖:0 个
理解的 module public API:12 个 symbols,从 lima.contracts.rvr 导入;依赖 rvr→{codec,common,errors};不 import evidence/aep/vep/profile
理解的关键安全边界:mandatory 双 preservation Gate 恰两成员各一次;verdict 矩阵三分支唯一合法值;producer≠generator;patch digest 跨候选唯一;changed_files 受限路径;类型化 VEP 三元组;classification 禁 public/retention 禁 ephemeral
理解的 Non-goals:
已运行 baseline:否(确认后立即运行)
发现的冲突或 Stop Condition:无 | <详细说明>
```

---

## 6. 唯一允许的文件范围

只允许新增(Packet §7.1):

```text
lima/contracts/rvr.py
tests/contracts/test_rvr.py
tests/contracts/test_rvr_envelope.py
tests/contracts/test_rvr_import_isolation.py
tests/contracts/fixtures/repair_verification_report_v4_golden.json
```

(测试与 fixture 由 P&V 冻结交付,Implementation Agent 只读。)允许修改既有文件:`0`。特别禁止:七个既有契约模块、全部既有测试/fixture、legacy/生产层、配置与 CI。

---

## 7. 必须实现的公共 Contract(摘要)

### 7.1 Module-only public API(恰 12 项)

```text
REPAIR_VERIFICATION_REPORT_SCHEMA_NAME   # "lima.repair-verification-report"
GateKind            # functional_preservation | security_preservation
GateOutcome         # pass | failed | inconclusive | blocked | tool_error | policy_denied
CandidateVerdict    # verified_patch | rejected | inconclusive
VepReference        # artifact_id + content_digest + schema_version(FR-02 三元组)
GateResult          # gate + outcome + producer + evidence_artifact_ids(≥1) + detail
CandidateVerification  # candidate_id + patch(PatchReference) + strategy + changed_files + generator + gates + verdict
RepairVerificationReport  # source_vep + candidates(可空)
decode_rvr_payload / encode_rvr_payload / decode_rvr_envelope / encode_rvr_envelope
```

不得修改 `lima.contracts.__all__`。`PatchReference` 为模块内部类型(不导出)。

### 7.2 冻结语义(摘要)

- top-level 2 个 required 字段;无整体 verdict 字段(§1.2-8 设计决策);
- **每候选 gates 恰好包含两个 mandatory 成员各一次**;verdict 矩阵:全 pass ⇒ verified_patch;任一 failed ⇒ rejected;其余 ⇒ inconclusive(各为唯一合法值);
- **每 gate producer ≠ 候选 generator**;patch content_digest 跨候选唯一;gates 按 gate wire value 升序;evidence_artifact_ids ≥1;
- changed_files 规则同 `SourceLocation.path`(禁尾随 `/`);strategy ≤512B、detail ≤4096B bounded text;
- binding:VEP 类型化三元组(schema/digest/version 双向)、patch 与 gate 证据 ∈ lineage、classification 禁 public、retention 禁 ephemeral;
- 4.0 unknown field 拒绝;未来 4.x 每层级 extensions 无损 round-trip;unknown enum 永远 fail closed。

完整定义以 Packet §9–§17 为准,不得凭本节摘要实现。

---

## 8. 明确 Non-goals

不实现:#76 候选生成/scope/CandidateManifest;#77/#94 Gate 执行器与 V5 §8.2 的 11 步序列;沙箱;修复发布;Registry/blob;workflow 族 schema;JSON Schema/兼容矩阵/ADR;legacy adapter;生产接线;float/confidence/漏洞状态字段;模型调用/网络/目标代码执行;GitHub 操作;IP-0007。

---

## 9. 开工 Baseline

```powershell
python -m compileall -q lima scripts tests
python -m unittest discover -s tests/contracts -v
python -m unittest -v tests.test_repository_source tests.test_task_failure
git status --short --branch
```

参考值:contracts 211 PASS;定向 29 PASS。baseline 失败时不改产品代码、先归因、无法归因提交 Decision Request。

---

## 10. 强制开发顺序

严格按 Packet §20 第 7 步起(1-6 由 P&V 完成,含实例化镜像预检):本地校验器/枚举/VepReference/PatchReference/GateResult/CandidateVerification → `RepairVerificationReport`(§14 全部校验)→ 逐字验证 golden(1709B/`a9a35d35…`)→ 4 个 binding functions → isolation/forbidden-key → Slice Gate → Compatibility Gate → File Boundary Gate → Completion Summary。每个行为必须映射 AC 与机器测试。

---

## 11. Frozen Golden Vector

```text
file size: 1709 bytes
payload sha256: a9a35d358308a2957b9182d2ca5e503903d8c7282c6c43bb09d1680313cb2cac
encoding: UTF-8 / BOM: none / trailing newline: none
内容:candidate-0001(双 Gate pass → verified_patch)+ candidate-0002(security failed → rejected)
source_vep.content_digest = cd76622b…3cb2cac(VEP golden 真实 digest)
envelope vector: schema=lima.repair-verification-report, 4.0, rvr-0001, repair-1,
  lima-repair-verifier, sensitive/audit, lineage 8 条(VEP 类型化 + patch/gate-log illustrative)
```

若 IP-0001 codec 无法重现,属 Stop Condition。

---

## 12. Acceptance Criteria

逐项完成 Packet §19(RVR-AC-01…10)。至少 **41** 个新 test methods(26+11+4),不得减少或重命名。

---

## 13. Slice / Compatibility / Boundary Gates

```powershell
# Slice Gate
python -m compileall -q lima/contracts tests/contracts
python -m unittest discover -s tests/contracts -v
python -m ruff check lima/contracts/rvr.py tests/contracts/test_rvr.py tests/contracts/test_rvr_envelope.py tests/contracts/test_rvr_import_isolation.py
python -m ruff check lima/contracts tests/contracts
python -m bandit -q -r lima/contracts/rvr.py
git diff --check

# Compatibility Gate(预期 597 = 556+41 / 1 既有 skip)
python -m unittest -v tests.test_repository_source tests.test_task_failure
python -m unittest discover -s tests -v

# File Boundary Gate(相对 Frozen Test Commit,恰好 lima/contracts/rvr.py)
git diff --name-only --diff-filter=ACMRTUXB <frozen-test-commit>...HEAD
git diff --check <frozen-test-commit>...HEAD

# PR Gate:独立 Reviewer;merge-gate;只写 Related to #58;禁 auto-close;不自合并
```

---

## 14. Stop Conditions 与 Decision Request

同 Packet §23(10 项)。报告格式同 Packet 惯例。

---

## 15. Commit 与 PR 说明

推荐 commit/PR title:`feat: add deterministic repair verification report contracts`。PR 首部:`Related to #58`;不得把 close/fix/resolve 类关键字与 `#58` 相邻。PR 必须含 Goal/Non-goals、5 added/0 modified/0 deps、AC→Test→Result、golden bytes/digest、全部真实命令与统计、no generator/no executor/no manifest schema、七模块 untouched、Findings、回滚说明(删除 5 个新增文件即可)。

---

## 16. 强制 Completion Summary

无论 DONE、BLOCKED 或中断,按 Packet §25 原样输出完整 Summary。

---

## 17. 可直接交给 Coding Agent 的任务指令

```text
你是 LIMA IP-0006 Repair Verification Report(RVR)Foundation 的唯一 Implementation Agent。

必须按顺序完整阅读:
1. docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md
2. docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md
3. docs/LIMA_IMPLEMENTATION_AGENT_RESPONSIBILITY_CHARTER.md
4. docs/LIMA_Coding_Agent_IP-0006_正式开发任务交接.md
5. docs/LIMA_Implementation_Packet_IP-0006_RVR_Foundation.md
6. CONTRIBUTING.md
7. Packet 列出的 lima/contracts 模块与既有测试(只读)

只有在两份 IP-0006 文档已合并到 main、且 Coordinator 出具 Implementation Assignment 指定 Frozen Test
Commit 后才开始。依 lifecycle §9.1 从 Frozen Test Commit(而非 main)派生 codex/ip-0006-rvr-foundation
独立干净 worktree;任何编辑前输出 Scope Confirmation,再运行 baseline(contracts 预期 211 PASS)。

唯一允许的变更是新增 lima/contracts/rvr.py(五文件 allowlist 中唯一产品文件);允许修改既有文件为 0,
外部依赖为 0;冻结测试/fixture 只读。公共 API 只存在于 lima.contracts.rvr(12 symbols),依赖方向
rvr→{codec,common,errors},不 import evidence/aep/vep/profile;不改 __init__ 与任何既有模块。

必须实现冻结的 GateKind/GateOutcome/CandidateVerdict、VepReference、GateResult、CandidateVerification
(含内部 PatchReference)、RepairVerificationReport 与 Envelope binding(schema name
lima.repair-verification-report)。mandatory 双 preservation Gate 恰两成员各一次、verdict 矩阵三分支
唯一合法值、producer≠generator、patch digest 跨候选唯一、类型化 VEP 三元组、classification 禁 public/
retention 禁 ephemeral 全部 fail closed。完整执行 41 个 required tests、Ruff(含全目录)、Bandit、
全量 unittest(预期 597 = 556+41)与 file boundary gate。

遇到同名实现、文件越界、Contract 多解、golden digest(1709/a9a35d35…)不可重现、依赖/权限扩张、
无法归因的 baseline failure 或任何 Stop Condition,立即停止并提交 Decision Request;不得自行修改
Packet、Issue 或冻结测试以绕过。

完成后按 Packet §25 输出完整 Completion Summary,交 P&V Agent 独立验证;不自行开 PR,不启动 IP-0007。
```

---

## 18. Maintainer 接收标准

5 新增/0 修改/0 依赖;12-symbol module API 且依赖方向正确(不加载 evidence/aep/vep/profile);冻结面(18/16/15/12/12/29、四 golden)不变;golden 1709B/`a9a35d35…` 且 source_vep.digest = VEP golden;10 个 AC 有机器证据;≥41 required tests;mandatory Gate/矩阵/自证禁令/patch 唯一性/类型化 VEP/current-future-minor negative gates 通过;Ruff(全目录 exit 0)/Bandit/diff check/全量 597 通过;Completion Summary 完整;独立 Review 与 merge-gate 通过;PR 未改变 #58 状态;未提前实现生成器/执行器/manifest/IP-0007。

---

## 19. 当前唯一下一步

> 先以独立 docs-only PR 将本交接书、IP-0006 Packet 和更新后的 `docs/DEVELOPER_HANDOFF.md` 合并到 `main`。合并后,P&V 依 lifecycle §9 自动进入阶段二(**先执行 §20 一致性预检(含实例化镜像项)**,再冻结 41 个测试 + fixture、证明 RED、交付 Frozen Test Commit 与 digest;**传输点只推分支不开 PR**);随后由 Coordinator 出具 Implementation Assignment。除此之外不启动并行实现任务。
