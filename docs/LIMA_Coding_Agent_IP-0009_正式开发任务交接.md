# LIMA Coding Agent IP-0009 正式开发任务交接书

> 适用 Packet:`IP-0009 Summary + Failure Schemas(结论对)`
>
> Packet 文档:`docs/LIMA_Implementation_Packet_IP-0009_Summary_Failure_Schemas.md`(权威契约;冲突以 Packet 为准)
>
> 生效条件:本交接书与 Packet 一同合并 `main`,且 Coordinator 已签发 Implementation Assignment

## 0. 效力与边界

你是 LIMA Implementation Agent。本交接书授权你实现且仅实现 IP-0009 Packet 冻结的契约。不重新设计 public contract,不修改 Packet/测试/fixture,不管理 PR/Issue/Ledger/PROGRESS。Contract 不足或需越界时立即停止并提交 Decision Request。

## 1. 正式授权

```text
Assignment ID:IMPL-IP-0009(Coordinator 在 Frozen Test Commit 后另行出具)
Packet 文档:docs/LIMA_Implementation_Packet_IP-0009_Summary_Failure_Schemas.md
基线:origin/main @ be1b890bed87a0610d20cc2dbe3d8eee36e7620e(IP-0008 实现 #129;实现基线 = 含两份 IP-0009 文档的最新 main)
Frozen Test Commit:阶段二由 P&V 交付(预期 RED 全部归因 lima.contracts.summary 不存在)
推荐分支:codex/ip-0009-summary-failure-schemas(从 Frozen Test Commit 派生)
对 Source Issue 影响:PARTIAL(#58 保持 open)
```

## 2. 开工前必须按顺序完整阅读

稳定标准;lifecycle(§9.1);Implementation Agent 责任书;IP-0009 Packet(全文,尤其 §9-§18、§20、§23);本交接书;CONTRIBUTING.md;`lima/contracts/{codec,common,errors}.py`;`lima/contracts/execution.py`(衔接先例;注意本模块**不 import** 它);`tests/contracts/test_execution*.py`(风格先例);Coordinator IMPL-IP-0009 Assignment(到达后)。

## 3. 已验证的仓库事实(P&V,2026-09-06)

- 基线 `be1b890`:contracts **369/369**、全量 **714 / 0 failed / 1 既有 skip**、`ruff --no-cache` exit 0;
- 冻结面:top 18 / evidence 16 / profile 15 / aep 12 / vep 12 / rvr 12 / workflow 27 / execution 16 / 29 codes;十三 golden 一致;
- `lima/contracts/summary.py` 与 `tests/contracts/test_summary*.py`、四个新 fixture 在 main 不存在;cxx 三分支不触碰 contracts;
- 环境差异:redis-py 6.4.0 vs `>=8.1.0,<9`(零影响,如实登记)。

## 4. 工作树保护与隔离分支

依 lifecycle §9.1 从 Frozen Test Commit 建独立干净 worktree;禁用共享根工作树与任何既有 worktree;未跟踪文件为用户资产;不执行 reset/clean/stash/rebase/amend/删分支/删 worktree(丢弃本人未提交编辑除外,须声明)。

## 5. 开工前 Scope Confirmation

```text
## Scope Confirmation
- 两份 IP-0009 文档均在 origin/main(merge commit):
- Frozen Test Commit = <SHA>(实现分支已包含):
- lima/contracts/summary.py 不存在:
- tests/contracts/test_summary{,_envelope,_import_isolation}.py 不存在:
- 四个 fixture(workflow_summary/workflow_summary_legacy/failure_report/failure_report_alternates)不存在:
- baseline contracts 369 / 定向 29 通过:
- 无未解决 Stop Condition:
```

## 6. 唯一允许的文件范围

恰好 8 个新增文件(Packet §7.1);零修改;依赖仅 §8 白名单。File Boundary 输出恰为 8 路径。

## 7. 必须实现的公共 Contract(摘要)

`lima.contracts.summary`,恰 **19** symbols(§9)。核心不变量(§14):**来源互斥**(chain ⇒ workflow + security_outcome 链接必填、legacy ids 必空;legacy_audit ⇒ 全部类型化链接 null/空、legacy ids ≥1——V5-FR-05 禁止面);scope 耦合(F2);FailureKind 六值与 workflow.FailureKind wire 逐值相等但本地定义;链接 kind 与字段精确绑定;类型化 lineage(digest 恒 `hmac.compare_digest`)+ 未类型化 id 存在性;保护面。四 golden 逐字节(§17)。

## 8. 明确 Non-goals

#90 runtime、PR4 legacy adapter、V5-FR-04 场景 fixtures、manifests、PR3、closure、自由文本/时间/计量/float、结论镜像字段、修改十模块或既有测试、下一 IP。

## 9. 开工 Baseline

见 §3;完整命令与预期数字见 Packet §21(contracts 369→**419**、全量 714→**764**)。

## 10. 强制开发顺序

按 Packet §20 第 7 步:枚举/校验器/ArtifactLink → WorkflowSummary(S1-S5)→ FailureReport(F1-F5)→ 四 golden 逐字 → 8 binding functions → isolation/forbidden-key → 三 Gate → Completion Summary。测试与 fixture 来自 Frozen Test Commit,**只读**。

## 11. Frozen Golden Vector

四 fixture(Packet §17):`workflow_summary_v4_golden.json`(1333B/`5df80cd4…`)、`workflow_summary_legacy_v4_golden.json`(218B/`18c1faa3…`)、`failure_report_v4_golden.json`(535B/`751bf433…`)、`failure_report_alternates_v4_golden.json`(681B/`3a016bfa…`)。禁止"修正"。

## 12. Acceptance Criteria

SF-AC-01..SF-AC-10(Packet §19),Completion Summary 逐条给证据。

## 13. Slice / Compatibility / Boundary Gates

```text
# Slice Gate(GREEN 态 + --no-cache)
python -m compileall -q lima/contracts tests/contracts
python -m unittest discover -s tests/contracts -v        # 419 ran / 0 failed
python -m ruff check --no-cache lima/contracts/summary.py tests/contracts/test_summary.py \
  tests/contracts/test_summary_envelope.py tests/contracts/test_summary_import_isolation.py
python -m bandit -q -r lima/contracts/summary.py
git diff --check
# Compatibility Gate(预期 764 = 714+50 / 1 既有 skip)
python -m unittest -v tests.test_repository_source tests.test_task_failure
python -m unittest discover -s tests -v
# File Boundary Gate(相对 Frozen Test Commit,恰 8 文件,产品侧仅 summary.py)
git diff --name-only --diff-filter=ACMRTUXB <frozen-test-commit>...HEAD
# PR Gate:独立 Reviewer;merge-gate;只写 Implements IP-0009 + Related to #58;禁 auto-close;不自合并
```

RED 态任何 lint 结果不得作为门禁复证依据(九项 Checklist 第 7 条)。

## 14. Stop Conditions 与 Decision Request

Packet §23 全部九条适用,特别:需修改 workflow.FailureKind 或任何十模块、需自由文本/结论镜像/PR4 接线才能过测试(范围上移)、golden 无法逐字节重现。

## 15. Commit 与 PR 说明

推荐标题 `feat: add deterministic workflow summary and failure report schemas`;Conventional Commit;`git commit -s`;不合并、不删分支、不动 Issue/PR;final commit + Completion Summary 交 P&V。

## 16. 强制 Completion Summary

按 Packet §25 模板,含 10 AC 证据表、真实命令(--no-cache GREEN 态)、安全/兼容声明(来源互斥、词表分离、lineage、无 echo、隔离、py3.11/3.12、回归)。

## 17. 可直接交给 Coding Agent 的任务指令

```text
你是 LIMA Implementation Agent,正在实现已合并并冻结测试的 IP-0009 Summary + Failure Schemas。

必须:
1. 完整阅读稳定标准、lifecycle、Implementation Agent 责任书、IP-0009 Packet、本交接书、CONTRIBUTING.md。
2. 只新增 Packet §7.1 的 8 个文件;零修改任何既有文件。
3. 不重新设计 public contract;19 symbols、6 枚举 wire 值、四 golden 逐字节冻结;
   FailureKind 本地定义且 wire 值与 workflow.FailureKind 逐值相等,不 import workflow/execution。
4. 核对 Frozen Test Commit;测试、fixture、Packet 全部只读。
5. 先运行 baseline 与预期 RED 复核,再按 Packet §20 顺序实现。
6. 一切 lint 复证在 GREEN 等价态 + --no-cache 下执行;RED 态结果不作依据。
7. Contract 不足或需越界时立即停止并提交 Decision Request。
8. 不修改 GitHub Issues、Delivery Ledger、PROGRESS、PR;不关闭 Source Issue。
9. 完成后把 final commit、Completion Summary 和真实测试证据交给 P&V Agent。
```

## 18. Maintainer 接收标准

Packet §26 全项通过。

## 19. 当前唯一下一步

等待 Coordinator 签发 IMPL-IP-0009 Assignment(Frozen Test Commit 核验后);此前不得开工。禁止:实现 #90/PR4、修改任何既有契约模块、启动下一 IP、合并 PR、关闭 #58。
