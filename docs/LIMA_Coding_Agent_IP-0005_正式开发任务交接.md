# LIMA Coding Agent IP-0005 正式开发任务交接书

> 任务:`IP-0005 Vulnerability Evidence Package(VEP)Foundation`
>
> 状态:`PREPARED / AUTHORIZED WHEN BOTH IP-0005 DOCUMENTS ARE MERGED TO MAIN AND TESTS ARE FROZEN`
>
> 唯一施工规范:[LIMA Implementation Packet IP-0005](LIMA_Implementation_Packet_IP-0005_VEP_Foundation.md)
>
> Source Issue:[#58](https://github.com/agent-sec-labs/LIMA/issues/58),仅完成第五个 slice;对 #58 影响:PARTIAL
>
> 最低代码基线:Assignment 基线 `5984c5c424cc27acacce89f234040528af6d2c27`(IP-0004 实现,PR #107);实现分支依 lifecycle §9.1 从 Frozen Test Commit 派生(SHA 由阶段二交付物指定)
>
> 推荐分支:`codex/ip-0005-vep-foundation`

---

## 0. 交接书的效力与边界

本交接书已完成正式内容冻结;只有当本交接书与 IP-0005 Packet 都已合并到 `origin/main`、且 P&V 已交付 Frozen Test Commit 与有效 RED 证据(含 §9k 一致性预检记录)后,才由 Coordinator 出具 Implementation Assignment 正式授权编码。此前只允许 Review。

事实优先级:最新 main 代码与可重复测试 > 稳定标准与治理规范 > IP-0005 Packet > 本交接书 > Assignment/Ledger > Source Issue 背景。冲突时保留现场提交 Decision Request。

---

## 1. 正式授权

> 在指定基线上新增一个 stdlib-only、无副作用、确定性、fail-closed 的 `lima.contracts.vep` 叶子模块,使 `VulnerabilityEvidencePackage`(verification_verdict × claim_kind × D3/D4 等级矩阵、恒必填的 machine-executable Oracle 引用、FR-0002 三元组引用 sealed AEP、六态执行结果、D3/D4 内嵌证据图)成为完整、可版本演化的确定性 Artifact 契约,并安全绑定 IP-0001 `ArtifactEnvelope`(`lima.vulnerability-evidence-package`、inline-only、类型化 lineage、classification/retention、digest)。

本次不是 Mining Core/插件/Oracle 执行/sandbox(#95),不是 RVR/RefutationReport/BlockedReport/manifest schema,不是 JSON Schema 文件,也不是生产接线。

Agent 完成 IP-0005 后必须停止,不得自行领取 NEXT。

---

## 2. 开工前必须按顺序完整阅读

1. `docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md`
2. `docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md`
3. `docs/LIMA_IMPLEMENTATION_AGENT_RESPONSIBILITY_CHARTER.md`
4. `docs/LIMA_Coding_Agent_IP-0005_正式开发任务交接.md`
5. `docs/LIMA_Implementation_Packet_IP-0005_VEP_Foundation.md`
6. `CONTRIBUTING.md`
7. `lima/contracts/{__init__,errors,codec,common,evidence}.py`(evidence 必须——本 IP 内嵌其类型;profile/aep 只读——仅经 lineage 引用,禁止 import)
8. `tests/contracts/` 既有测试与 fixture(风格参考;只读)
9. #58 Delivery Ledger v9(背景:定序结论与一致性预检强制项)
10. #95 正文(背景:六态词汇与 AC-N06-05/06;runtime 归 #95)

Packet 必须完整阅读,不能只读摘要、测试名或本交接书。

---

## 3. 已验证的仓库事实(P&V,2026-09-02)

```text
branch: main @ 5984c5c424cc27acacce89f234040528af6d2c27(feat: add deterministic audit evidence package contracts (#107))
Python: 3.12.4 / Ruff: 0.16.5 / Bandit: 1.9.4
```

合并后验证(@ `5984c5c`,IP-0004 post-merge 双重验证):

```text
python -m compileall -q lima scripts tests          → exit 0
python -m unittest discover -s tests/contracts      → 170 / 170 passed / 0 failed / 0 skipped
python -m ruff check lima/contracts tests/contracts → All checks passed / exit 0
python -m unittest discover -s tests                → 515 ran / 0 failed / 1 existing skip
python -m unittest -v tests.test_repository_source tests.test_task_failure → 29 / 29 passed
```

消费者验证(Packet §1):AEP 引用三元组可构造且与 lineage 类型化条目双向可核对;AEP sealed/revision/eligible 语义面可读;D3/D4 standalone EvidenceRecord 可构造(IP-0002 预留的预期消费者);**无 Contract Gap**(sealed 状态解析属消费侧/Registry)。

Golden 预计算(IP-0001 codec @ `5984c5c`):VEP golden payload **2091 bytes / SHA-256 `cd76622b48d11c0300e63d7489701479c75dc2f4b06cc6c4e88af1f453061d01`**,其 `source_aep.content_digest` = AEP golden 真实 digest(证据链连续)。

这些是交接时参考证据;Implementation Agent 必须在自己的干净 worktree 重新运行 baseline 并以实际输出为准。

---

## 4. 工作树保护与隔离分支

共享根工作树的未跟踪文件属用户资产,不得删除、移动、覆盖、`git clean`、`git reset --hard`、未经授权 stash、`git add .` 或在共享根工作树直接实现。

开工条件(两份 IP-0005 文档在 main + Frozen Test Commit 交付)满足后:

```powershell
git fetch origin
git merge-base --is-ancestor 5984c5c424cc27acacce89f234040528af6d2c27 <frozen-test-commit>
git worktree add -b codex/ip-0005-vep-foundation D:\BaseAIProject\LIMA-ip-0005-impl-wt <frozen-test-commit>
```

(具体 Frozen Test Commit SHA 以 P&V 阶段二交付物为准。)

---

## 5. 开工前 Scope Confirmation

任何编辑前必须输出:

```text
## Scope Confirmation

Packet:IP-0005 VEP Foundation(证明两份文档已合并、Frozen Test Commit SHA 与 RED 记录(含一致性预检)已核对)
Base commit / Frozen Test Commit:<完整 SHA;证明包含 5984c5c 与两份 IP-0005 文档>
工作分支 / 隔离 worktree:
允许新增文件:5 个完整路径
允许修改既有文件:0 个 / 外部依赖:0 个
理解的 module public API:12 个 symbols,从 lima.contracts.vep 导入;依赖 vep→{evidence,codec,common,errors};不 import aep/profile
理解的关键安全边界:verdict×等级矩阵(两种 claim_kind);Oracle 恒必填且 digest 钉死;类型化 AEP 三元组;evidence 仅 D3/D4 且 subject 绑 hypothesis;六态与裁决分离;classification 禁 public/retention 禁 ephemeral
理解的 Non-goals:
已运行 baseline:否(确认后立即运行)
发现的冲突或 Stop Condition:无 | <详细说明>
```

---

## 6. 唯一允许的文件范围

只允许新增(Packet §7.1):

```text
lima/contracts/vep.py
tests/contracts/test_vep.py
tests/contracts/test_vep_envelope.py
tests/contracts/test_vep_import_isolation.py
tests/contracts/fixtures/vulnerability_evidence_package_v4_golden.json
```

(测试与 fixture 由 P&V 冻结交付,Implementation Agent 只读。)允许修改既有文件:`0`。特别禁止:六个既有契约模块、全部既有测试/fixture、legacy/生产层、配置与 CI。

---

## 7. 必须实现的公共 Contract(摘要)

### 7.1 Module-only public API(恰 12 项)

```text
VULNERABILITY_EVIDENCE_PACKAGE_SCHEMA_NAME   # "lima.vulnerability-evidence-package"
ClaimKind            # runtime_exploitability | static_property
VerificationVerdict  # candidate | inconclusive | refuted_scope | verified
ReproductionOutcome  # reproduced | not_reproduced | inconclusive | blocked | tool_error | policy_denied
AepReference         # artifact_id + content_digest + schema_version(FR-02 三元组)
OracleReference      # oracle_artifact_id + content_digest
ReproductionRun      # run_artifact_id + outcome + detail
VulnerabilityEvidencePackage
decode_vep_payload / encode_vep_payload / decode_vep_envelope / encode_vep_envelope
```

不得修改 `lima.contracts.__all__`。

### 7.2 冻结语义(摘要)

- payload 14 个 required 字段;`impact`/`refutation_scope` required-but-nullable;
- **verdict 矩阵**(Packet §14.2,两种 claim_kind 全行):runtime verified ⇔ S3∧S4∧¬R(另需 impact + ≥1 reproduced run);static verified ⇔ S4∧¬R;refuted_scope ⇔ R∧¬S4 + scope 文本;S4∧R 或 S4(runtime)∧¬S3 ⇒ 仅 inconclusive;无 D3/D4 ⇒ 仅 inconclusive;
- evidence 仅 D3/D4、subject_kind=vulnerability_hypothesis、subject_id == hypothesis_id、数组内 DAG(存在/禁 self/禁环/依赖 level ≤ 自身);
- Oracle 恒必填;binding 层:oracle id ∈ lineage 且 digest 相等;source_aep 三元组与 lineage 条目(schema_name/`lima.audit-evidence-package`、digest、version)双向核对;run 与 evidence 来源 ⊆ lineage;
- 六态 outcome 永不进入 verdict 矩阵;无 confidence/severity/risk_score/is_vulnerable/safe/clear;
- 4.0 unknown field 拒绝;未来 4.x 每层级 extensions 无损 round-trip;unknown enum 永远 fail closed。

完整定义以 Packet §9–§17 为准,不得凭本节摘要实现。

---

## 8. 明确 Non-goals

不实现:#95 的 Mining Core/CapabilityPlugin/ValidationPlan/Oracle 执行/VerificationDecision/conformance;RVR/RefutationReport/BlockedReport;Task/ToolBundle/Dependency/Sandbox/Oracle manifest schema;Registry/blob/sealed 解析/revision 单调性;Workflow 族 schema;JSON Schema/兼容矩阵/ADR;legacy adapter;生产接线;float/confidence/severity/verdict 旁路;模型调用/网络/目标代码执行;GitHub 操作;IP-0006。

---

## 9. 开工 Baseline

```powershell
python -m compileall -q lima scripts tests
python -m unittest discover -s tests/contracts -v
python -m unittest -v tests.test_repository_source tests.test_task_failure
git status --short --branch
```

参考值:contracts 170 PASS;定向 29 PASS。baseline 失败时不改产品代码、先归因、无法归因提交 Decision Request。

---

## 10. 强制开发顺序

严格按 Packet §20 第 7 步起(1-6 由 P&V 完成,含 §9k 一致性预检):枚举/validators/三引用对象 → `VulnerabilityEvidencePackage` 跨字段校验 → 逐字验证 golden(2091B/`cd76622b…`)→ 4 个 binding functions → isolation/forbidden-key → Slice Gate → Compatibility Gate → File Boundary Gate → Completion Summary。每个行为必须映射 AC 与机器测试。

---

## 11. Frozen Golden Vector

```text
file size: 2091 bytes
payload sha256: cd76622b48d11c0300e63d7489701479c75dc2f4b06cc6c4e88af1f453061d01
encoding: UTF-8 / BOM: none / trailing newline: none
source_aep.content_digest = f0a98543…64705d0(AEP golden 真实 digest)
envelope vector: schema=lima.vulnerability-evidence-package, 4.0, vep-0001, mining-1,
  lima-mining, sensitive/audit, lineage=[lima.audit-evidence-package/aep-0001,
  lima.oracle-script/oracle-0001/"7"*64, lima.sandbox-run/run-0001/"8"*64]
```

若 IP-0001 codec 无法重现,属 Stop Condition。

---

## 12. Acceptance Criteria

逐项完成 Packet §19(IP5-AC-01…10)。至少 **41** 个新 test methods(26+11+4),不得减少或重命名。

---

## 13. Slice / Compatibility / Boundary Gates

```powershell
# Slice Gate
python -m compileall -q lima/contracts tests/contracts
python -m unittest discover -s tests/contracts -v
python -m ruff check lima/contracts/vep.py tests/contracts/test_vep.py tests/contracts/test_vep_envelope.py tests/contracts/test_vep_import_isolation.py
python -m ruff check lima/contracts tests/contracts
python -m bandit -q -r lima/contracts/vep.py
git diff --check

# Compatibility Gate(预期 556 = 515+41 / 1 既有 skip)
python -m unittest -v tests.test_repository_source tests.test_task_failure
python -m unittest discover -s tests -v

# File Boundary Gate(相对 Frozen Test Commit,恰好 lima/contracts/vep.py)
git diff --name-only --diff-filter=ACMRTUXB <frozen-test-commit>...HEAD
git diff --check <frozen-test-commit>...HEAD

# PR Gate:独立 Reviewer;merge-gate;只写 Related to #58;禁 auto-close;不自合并
```

---

## 14. Stop Conditions 与 Decision Request

同 Packet §23(10 项),关键:基线漂移/冻结面漂移、同名冲突、越界、依赖、多解、golden 不可重现、需 float/旁路/放宽矩阵/Oracle/provenance、需 runtime/manifest schema、baseline 无法归因、AC 无证据、范围上移(#95/RVR/workflow/接线)。报告格式见 Packet §23。

---

## 15. Commit 与 PR 说明

推荐 commit/PR title:`feat: add deterministic vulnerability evidence package contracts`。PR 首部:`Related to #58`;不得把 close/fix/resolve 类关键字与 `#58` 相邻。PR 必须含 Goal/Non-goals、5 added/0 modified/0 deps、AC→Test→Result、golden bytes/digest、全部真实命令与统计、no runtime/no plugin/no manifest schema、evidence/profile/aep untouched、Findings、回滚说明(删除 5 个新增文件即可)。

---

## 16. 强制 Completion Summary

无论 DONE、BLOCKED 或中断,按 Packet §25 原样输出完整 Summary。

---

## 17. 可直接交给 Coding Agent 的任务指令

```text
你是 LIMA IP-0005 Vulnerability Evidence Package(VEP)Foundation 的唯一 Implementation Agent。

必须按顺序完整阅读:
1. docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md
2. docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md
3. docs/LIMA_IMPLEMENTATION_AGENT_RESPONSIBILITY_CHARTER.md
4. docs/LIMA_Coding_Agent_IP-0005_正式开发任务交接.md
5. docs/LIMA_Implementation_Packet_IP-0005_VEP_Foundation.md
6. CONTRIBUTING.md
7. Packet 列出的 lima/contracts 模块与既有测试(只读)

只有在两份 IP-0005 文档已合并到 main、且 Coordinator 出具 Implementation Assignment 指定 Frozen Test
Commit 后才开始。依 lifecycle §9.1 从 Frozen Test Commit(而非 main)派生 codex/ip-0005-vep-foundation
独立干净 worktree;任何编辑前输出 Scope Confirmation,再运行 baseline(contracts 预期 170 PASS)。

唯一允许的变更是新增 lima/contracts/vep.py(五文件 allowlist 中唯一产品文件);允许修改既有文件为 0,
外部依赖为 0;冻结测试/fixture 只读。公共 API 只存在于 lima.contracts.vep(12 symbols),依赖方向
vep→{evidence,codec,common,errors},不 import aep/profile;不改 __init__、evidence、profile、aep、
common、codec、errors 或 legacy 代码。

必须实现冻结的 ClaimKind/VerificationVerdict/ReproductionOutcome、AepReference、OracleReference、
ReproductionRun、VulnerabilityEvidencePackage 与 Envelope binding(schema name
lima.vulnerability-evidence-package)。verdict×等级矩阵(两种 claim_kind 全行)与附加必要条件、
Oracle 恒必填、类型化 AEP 三元组、evidence 仅 D3/D4 且 subject 绑 hypothesis、DAG、六态与裁决分离、
classification 禁 public/retention 禁 ephemeral 全部 fail closed。完整执行 41 个 required tests、
Ruff(含全目录)、Bandit、全量 unittest(预期 556 = 515+41)与 file boundary gate。

遇到同名实现、文件越界、Contract 多解、golden digest(2091/cd76622b…)不可重现、依赖/权限扩张、
无法归因的 baseline failure 或任何 Stop Condition,立即停止并提交 Decision Request;不得自行修改
Packet、Issue 或冻结测试以绕过。

完成后按 Packet §25 输出完整 Completion Summary,交 P&V Agent 独立验证;不自行开 PR,不启动 IP-0006。
```

---

## 18. Maintainer 接收标准

5 新增/0 修改/0 依赖;12-symbol module API 且依赖方向正确(载 evidence、不载 aep/profile);冻结面(18/16/15/12/29、三 golden digest)不变;golden 2091B/`cd76622b…` 且 source_aep.digest = AEP golden;10 个 AC 有机器证据;≥41 required tests;矩阵/六态/Oracle/三元组/DAG/current-future-minor negative gates 通过;Ruff(全目录 exit 0)/Bandit/diff check/全量 556 通过;Completion Summary 完整;独立 Review 与 merge-gate 通过;PR 未改变 #58 状态;未提前实现 runtime/manifest/IP-0006。

---

## 19. 当前唯一下一步

> 先以独立 docs-only PR 将本交接书、IP-0005 Packet 和更新后的 `docs/DEVELOPER_HANDOFF.md` 合并到 `main`。合并后,P&V 依 lifecycle §9 自动进入阶段二(**先执行 §20 一致性预检**,再冻结 41 个测试 + fixture、证明 RED、交付 Frozen Test Commit 与 digest);随后由 Coordinator 出具 Implementation Assignment。除此之外不启动并行实现任务。
