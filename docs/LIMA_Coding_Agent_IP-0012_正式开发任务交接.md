# LIMA Coding Agent IP-0012 正式开发任务交接书

> 适用 Packet:`IP-0012 Manifests Domain(Task / ToolBundle / Dependency / Sandbox manifests)`
>
> Packet 文档:`docs/LIMA_Implementation_Packet_IP-0012_Manifests_Domain.md`(权威契约;冲突以 Packet 为准)
>
> 生效条件:两份文档合并 `main` 且 Coordinator 签发 IMPL-IP-0012

## 0. 效力与边界

你是 LIMA Implementation Agent。只交付 IP-0012 Packet 冻结的 12 个新增文件(§10);不改 Packet/测试语义、不管理 PR/Issue/Ledger;越界即停提交 Decision Request。本阶段(阶段一)仅交付 Packet 与本交接书;你的工作在阶段二 Frozen Test Commit 合并后开始。

## 1. 正式授权

```text
Assignment ID:IMPL-IP-0012(Coordinator 另行出具)
Packet:docs/LIMA_Implementation_Packet_IP-0012_Manifests_Domain.md
基线:origin/main @ 4619389071aef80812a77428e6fc2c509dca626b(实现基线 = 含两份 IP-0012
  文档 + Frozen Test Commit 的最新 main)
Frozen Test Commit:阶段二 P&V 交付(RED = 测试读 8 个 golden fixture → 不存在)
推荐分支:codex/ip-0012-manifests-domain
对 Source Issue 影响:PARTIAL(FR-02 转 SATISFIED 候选;#58 保持 open)
```

## 2. 开工前必读

稳定标准;lifecycle(§9.1/§12.2);Implementation Agent 责任书;IP-0012 Packet 全文(尤其 §7-§16 的十一项冻结单解、§10 文件边界、§13 测试矩阵、§18 Stop Conditions);本交接书;CONTRIBUTING.md;`lima/contracts/execution.py`(validator/ArtifactLink 三元组/排序纪律的直接先例);IMPL Assignment(到达后)。

## 3. 已验证的仓库事实(P&V,2026-09-10)

- 基线 `4619389`:contracts **477 passed**、全量 **821 passed + 1 skipped**(= 822/0F/1 skip 口径)、`ruff check --no-cache lima/contracts/ tests/contracts/` exit 0;冻结面 18/16/15/12/12/12/27/16/19/29 + 15 PR3 产物 + 6 场景 fixture + 十七 golden;
- 入口 Gate PASS:六场景 fixture consumer review 全 PASS(0 dangling link);十二模块适用面核对无 Contract Gap(详见 Packet §1);
- **两个不可动摇的字面量锚点**:`tests/contracts/test_execution_envelope.py` L80-81 的 lineage 字面量 `"lima.sandbox-run"` 与 `"lima.tool-bundle"` 必须与你交付的 `SANDBOX_RUN_SCHEMA_NAME` / `TOOL_BUNDLE_SCHEMA_NAME` 逐字符相等(该文件禁改);
- `lima/contracts/manifests.py`、3 个测试文件、8 个 golden fixture 在基线不存在;
- 环境事实:Windows + Git Bash、Python 3.12.4;contracts 面纯 stdlib,无 redis/db/docker 介入。

## 4. 工作树保护与隔离分支

lifecycle §9.1 独立干净 worktree(从 Frozen Test Commit 派生);禁共享根与既有 worktree;未跟踪文件为用户资产;禁破坏性 git 操作。

## 5. 开工前 Scope Confirmation

```text
## Scope Confirmation
- 两份 IP-0012 文档均在 origin/main(merge commit):
- Frozen Test Commit = <SHA>(分支已包含):
- lima/contracts/manifests.py 与 3 测试文件与 8 golden 不存在:
- baseline contracts 477 / 全量 821+1skip / ruff exit 0:
- 无未解决 Stop Condition:
```

## 6. 唯一允许的文件范围

恰好 12 个新增文件(Packet §10 清单逐字);零修改;schemas/v4 零新增(PR3 类,Packet §2 Rejected);`contracts/__init__.py` 零改动。

## 7. 必须实现的交付(摘要)

`manifests.py` 按 Packet §7-§12 冻结字面量/字段/词表/上限逐字实现(四 schema + 本地 ManifestLink/ManifestReferenceKind + 8 对 payload/envelope 函数);测试三文件按 §13 矩阵实现(阶段二冻结的精确清单为准);8 个 golden 的交叉 digest 用 `compute_content_digest` 实算(FR-04:codec 是 digest 唯一实现)。实现期测试需要变更即停 → Decision Request,严禁同提交顺手改测试。

## 8. 明确 Non-goals

runtime/#90、PR4、closure、schemas/v4 JSON、mini-validator/schema 面校验、__init__ re-export、任何既有文件修改、时间/float/自由文本/env/秘密/URL、绝对路径、RepositorySnapshotManifest、PR4/CandidatePatchSet、consumer review ×4 调度。

## 9. 完成与 PR

Completion Summary 按 Packet §14 命令附全量输出与数字;Implementation PR 引用 `Related to #58`,严禁 Closes/Fixes/Resolves #58;停 READY-FOR-MERGE 等独立验证。

---

*LIMA P&V Agent,2026-09-10。*
