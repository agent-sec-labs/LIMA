# LIMA Coding Agent IP-0007 正式开发任务交接书

> 文档类型:正式开发任务交接书(Implementation Handoff)
>
> 适用 Packet:`IP-0007 Workflow Spine Schemas(Workflow / StageAttempt / SecurityOutcome)`
>
> Packet 文档:`docs/LIMA_Implementation_Packet_IP-0007_Workflow_Spine_Schemas.md`(权威契约;本交接书是其执行入口,冲突以 Packet 为准)
>
> 生效条件:本交接书与 Packet 一同合并到 `main`,且 Coordinator 已签发 Implementation Assignment(阶段二 Frozen Test Commit 交付后)

## 0. 交接书的效力与边界

你是 LIMA Implementation Agent。本交接书授权你实现且仅实现 IP-0007 Packet 冻结的契约。你不重新设计 public contract,不修改 Packet/测试/fixture/oracle,不管理 PR/Issue/Ledger/PROGRESS。任何 Contract 不足或需要越界的时刻,立即停止并提交 Decision Request。

## 1. 正式授权

```text
Assignment ID:IMPL-IP-0007(由 Coordinator 在 Frozen Test Commit 后另行出具;本交接书不是实现开工凭据)
Packet:IP-0007 Workflow Spine Schemas
Packet 文档:docs/LIMA_Implementation_Packet_IP-0007_Workflow_Spine_Schemas.md
正式交接书:本文档
基线:origin/main @ 78aa9d87873312d7541392969015984ebb4b154c(IP-0006 实现 + PR #69;实现基线 = 含两份 IP-0007 文档的最新 main)
Frozen Test Commit:阶段二由 P&V 交付(预期 RED 全部归因 lima.contracts.workflow 不存在)
推荐分支:codex/ip-0007-workflow-spine-schemas(从 Frozen Test Commit 派生)
对 Source Issue 影响:PARTIAL(#58 保持 open)
```

## 2. 开工前必须按顺序完整阅读

1. `docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md`;
2. `docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md`(尤其 §9.1 拓扑);
3. `docs/LIMA_IMPLEMENTATION_AGENT_RESPONSIBILITY_CHARTER.md`;
4. IP-0007 Packet(全文,尤其 §9-§18、§20、§23);
5. 本交接书;
6. `CONTRIBUTING.md`;
7. Packet 引用的代码:`lima/contracts/{codec,common,errors}.py` 全文;`tests/contracts/test_rvr*.py`(风格先例);
8. Coordinator 的 IMPL-IP-0007 Assignment(到达后)。

## 3. 已验证的仓库事实(P&V,2026-09-05)

- 基线 `78aa9d8`:contracts **252/252**、全量 **597 / 0 failed / 1 既有 skip**(Windows symlink-privilege 常量)、`ruff check lima/contracts tests/contracts` exit 0;
- 冻结面:顶层 `lima.contracts.__all__`=18、evidence 16、profile 15、aep 12、vep 12、rvr 12、`ContractErrorCode`=29;六 golden(evidence 3740B、profile 2152B、aep 4235B、vep 2091B、rvr 1709B、envelope 838B)digest 与 #58 Ledger 一致;
- `lima/contracts/workflow.py` 与 `tests/contracts/test_workflow*.py`、四个新 fixture 在 main 不存在;
- 开放 PR 仅 #125/#124/#125 三条 cxx 分支(实证不触碰 `lima/contracts`/`tests/contracts`);
- 环境差异(如实记录,非缺陷):installed redis-py 6.4.0 vs requirements `>=8.1.0,<9`(PR #69);contracts 验证范围纯 stdlib 零影响;CI matrix 于 8.x 全绿。

## 4. 工作树保护与隔离分支

- 依 lifecycle §9.1 从 Frozen Test Commit 创建 `codex/ip-0007-workflow-spine-schemas` 独立干净 worktree;**禁用共享根工作树与任何既有 worktree**;
- 根工作树未跟踪文件(`.pv_tmp/`、规划文档、交接快照)是用户/Coordinator/P&V 资产,不得 stash/clean/add;
- 不执行 reset/clean/stash/rebase/amend/删分支/删 worktree。

## 5. 开工前 Scope Confirmation

先输出(不入 commit):

```text
## Scope Confirmation
- 两份 IP-0007 文档均在 origin/main(列出 merge commit):
- Frozen Test Commit = <SHA>(实现分支已包含):
- lima/contracts/workflow.py 不存在:
- tests/contracts/test_workflow{,_envelope,_import_isolation}.py 不存在:
- 四个 fixture 不存在:
- baseline contracts 252 / 定向 29 通过:
- 无未解决 Stop Condition:
```

任一项不成立 → BLOCKED + Decision Request。

## 6. 唯一允许的文件范围

恰好 8 个新增文件(Packet §7.1);**零修改**任何既有文件;依赖仅 §8 白名单。File Boundary Gate 输出必须恰为这 8 个路径。

## 7. 必须实现的公共 Contract(摘要)

`lima.contracts.workflow`,恰 **27** symbols(Packet §9):3 常量、8 枚举(4/16/5/6/7/2/6/12 成员,§10)、`ArtifactLink`/`Workflow`/`StageAttempt`/`SecurityOutcome`(§11 构造器)、12 个 decode/encode 函数(§15)。核心不变量(§14):Envelope 身份对齐、revision⇔supersedes 耦合、AUDIT_ONLY 状态排除、StageType 词表矩阵 + succeeded 最低要求、skip/failure required-iff、非 succeeded 禁 outputs、SecurityOutcome kind→证据矩阵 + CONCLUSION/NON_CONCLUSION 分区、全 link 类型化 lineage。四个 golden 的 bytes/digest 见 §17——**逐字节复制,不得重算更改**。

## 8. 明确 Non-goals

#90 runtime(状态机执行/持久化/API/恢复/进度/lease/policy)、Plan/RunManifest/Summary/Failure 完整 schema、manifests、时间戳/lease/资源账本字段、自由文本字段、float/confidence/severity、修改八个既有契约模块或既有测试、IP-0008。

## 9. 开工 Baseline

见 §3;完整命令与预期数字见 Packet §21(contracts 252→**323**、全量 597→**668**)。

## 10. 强制开发顺序

按 Packet §20 第 7 步:枚举与本地校验器 → `ArtifactLink` → `Workflow`/`StageAttempt`(W/S 不变量)→ `SecurityOutcome`(O 不变量)→ 四 golden 逐字验证 → 12 binding functions → isolation/forbidden-key → Slice/Compatibility/File Boundary Gates → Completion Summary。测试文件与 fixture 来自 Frozen Test Commit,**只读**。

## 11. Frozen Golden Vector

四个 fixture(Packet §17 权威内容):`stage_attempt_v4_golden.json`(370B/`34746de4…`)、`stage_attempt_alternates_v4_golden.json`(1498B/`01cf64fc…`)、`workflow_v4_golden.json`(460B/`3be59c6c…`)、`security_outcome_v4_golden.json`(589B/`bfa0b2dc…`)。引用链含上游 golden 真实 digest,禁止"修正"。

## 12. Acceptance Criteria

WS-AC-01..WS-AC-12(Packet §19)。Completion Summary 逐条给出 test/command 证据。

## 13. Slice / Compatibility / Boundary Gates

```text
# Slice Gate
python -m compileall -q lima/contracts tests/contracts
python -m unittest discover -s tests/contracts -v        # 323 ran / 0 failed
python -m ruff check lima/contracts/workflow.py tests/contracts/test_workflow.py \
  tests/contracts/test_workflow_envelope.py tests/contracts/test_workflow_import_isolation.py
python -m bandit -q -r lima/contracts/workflow.py
git diff --check

# Compatibility Gate(预期 668 = 597+71 / 1 既有 skip)
python -m unittest -v tests.test_repository_source tests.test_task_failure
python -m unittest discover -s tests -v

# File Boundary Gate(相对 Frozen Test Commit,恰好 8 文件,产品侧仅 workflow.py)
git diff --name-only --diff-filter=ACMRTUXB <frozen-test-commit>...HEAD

# PR Gate:独立 Reviewer;merge-gate;只写 Implements IP-0007 + Related to #58;禁 auto-close;不自合并
```

## 14. Stop Conditions 与 Decision Request

Packet §23 全部九条适用,特别强调:基线漂移/冻结面漂移、需要修改 forbidden 文件、需要时间戳或自由文本字段、需要定义 Plan/RunManifest/Summary/Failure/manifests 才能通过测试(范围上移)、golden 无法逐字节重现。Decision Request 格式同 Packet 惯例。

## 15. Commit 与 PR 说明

推荐标题 `feat: add deterministic workflow spine schemas`;Conventional Commit;`git commit -s`;不合并、不删分支、不动 Issue/PR 状态;final commit + Completion Summary 交 P&V。

## 16. 强制 Completion Summary

按 Packet §25 模板输出,含 12 AC 证据表、真实命令与统计、安全/兼容声明(词表分区、证据矩阵、身份对齐、lineage、无 echo、import 隔离、py3.11/3.12 由 CI matrix 覆盖、全量回归)。

## 17. 可直接交给 Coding Agent 的任务指令

```text
你是 LIMA Implementation Agent,正在实现已合并并冻结测试的 IP-0007 Workflow Spine Schemas。

必须:
1. 完整阅读稳定标准、lifecycle、Implementation Agent 责任书、IP-0007 Packet、本交接书、CONTRIBUTING.md。
2. 只新增 Packet §7.1 的 8 个文件;零修改任何既有文件。
3. 不重新设计 public contract;27 symbols、8 枚举 wire value、四 golden 逐字节冻结。
4. 核对 Frozen Test Commit;测试、fixture、Packet 全部只读。
5. 先运行 baseline 与预期 RED 复核,再按 Packet §20 顺序实现。
6. Contract 不足或需要越界时立即停止并提交 Decision Request。
7. 不修改 GitHub Issues、Delivery Ledger、PROGRESS、PR;不关闭 Source Issue。
8. 完成后把 final commit、Completion Summary 和真实测试证据交给 P&V Agent。
```

## 18. Maintainer 接收标准

Packet §26 Maintainer Review Checklist 全项通过。

## 19. 当前唯一下一步

等待 Coordinator 签发 IMPL-IP-0007 Assignment(Frozen Test Commit 交付并核验后);在此之前 Implementation Agent 不得开工。禁止动作:实现 #90 runtime、定义 Plan/RunManifest/Summary/Failure schema、修改任何既有契约模块、启动 IP-0008、合并 PR、关闭 #58。
