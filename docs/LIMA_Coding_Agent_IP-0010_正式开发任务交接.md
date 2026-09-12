# LIMA Coding Agent IP-0010 正式开发任务交接书

> 适用 Packet:`IP-0010 PR3 类 Artifact(JSON Schema 导出 + 版本兼容矩阵 + ADR)`
>
> Packet 文档:`docs/LIMA_Implementation_Packet_IP-0010_PR3_Artifacts.md`(权威契约;冲突以 Packet 为准)
>
> 生效条件:两份文档合并 `main` 且 Coordinator 签发 IMPL-IP-0010

## 0. 效力与边界

你是 LIMA Implementation Agent。只实现 IP-0010 Packet 冻结的产物与测试;不改 Packet/测试语义、不管理 PR/Issue/Ledger;越界即停提交 Decision Request。

## 1. 正式授权

```text
Assignment ID:IMPL-IP-0010(Coordinator 另行出具)
Packet:docs/LIMA_Implementation_Packet_IP-0010_PR3_Artifacts.md
基线:origin/main @ 207222d5a9f3b83038266ee866e501ea12f4ca11(实现基线 = 含两份 IP-0010 文档的最新 main)
Frozen Test Commit:阶段二 P&V 交付(RED = 测试读产物 FileNotFoundError)
推荐分支:codex/ip-0010-pr3-artifacts
对 Source Issue 影响:PARTIAL(#58 保持 open)
```

## 2. 开工前必读

稳定标准;lifecycle(§9.1);Implementation Agent 责任书;IP-0010 Packet(全文,尤其 §7/§10/§14/§17/§18/§20/§23);本交接书;CONTRIBUTING.md;DI-012 归档产物(`.pv_tmp/IP-0010_ARTIFACTS/` 15 文件)与生成器(`.pv_tmp/IP-0010_generate.py`);IMPL Assignment(到达后)。

## 3. 已验证的仓库事实(P&V,2026-09-06)

- 基线 `207222d`:contracts **419/419**、全量 764/0F/1skip、`ruff --no-cache` exit 0;冻结面 18/16/15/12/12/12/27/16/19/29;十七 golden 一致;
- `schemas/`、`docs/adr/`、两测试文件在 main 不存在;cxx 三分支不触碰 contracts;
- 15 个产物已在设计期生成并自证(golden 校验/required 探针/enum 全等全 PASS),权威 bytes = Packet §17.1 digest + DI-012 归档;
- 环境差异:redis-py 6.4.0 vs `>=8.1.0,<9`(零影响,照登)。

## 4. 工作树保护与隔离分支

lifecycle §9.1 独立干净 worktree;禁共享根与既有 worktree;未跟踪文件为用户资产;禁破坏性 git 操作(弃本人未提交编辑除外,须声明)。

## 5. 开工前 Scope Confirmation

```text
## Scope Confirmation
- 两份 IP-0010 文档均在 origin/main(merge commit):
- Frozen Test Commit = <SHA>(分支已包含):
- schemas/ 与 docs/adr/ 不存在;两测试文件不存在:
- baseline contracts 419 / 定向 29 通过:
- .pv_tmp/IP-0010_ARTIFACTS/ 15 文件 digest 与 Packet §17.1 相等(逐项):
- 无未解决 Stop Condition:
```

## 6. 唯一允许的文件范围

恰好 17 个新增文件(Packet §7.1:13 schema + 矩阵 + ADR + 2 测试);零修改任何既有文件;**产品侧零 .py 文件**。

## 7. 必须实现的交付(摘要)

15 个产物文件**逐字节复制** DI-012 归档(或生成器复现后 digest 核对;任何字节差异 = Stop Condition);2 个测试文件按 Packet §18 冻结的 26 方法名实现(mini-validator stdlib 实现;字段→枚举映射表冻结;I1-I7 断言全集)。

## 8. 明确 Non-goals

PR4/manifests/场景 fixtures/closure;修改契约模块或既有测试;第三方库(jsonschema 禁);双版本 schema;运行时校验器。

## 9. 开工 Baseline

见 §3;预期 contracts 419→**445**、全量 764→**790**(Packet §21)。

## 10. 强制开发顺序

按 Packet §20 第 7 步:放置 15 产物(digest 逐项复核)→ mini-validator → 13 contract tests → 矩阵 8 tests → 三 Gate → Completion Summary。测试来自 Frozen Test Commit,**只读**。

## 11. Frozen Artifact Digests

Packet §17.1(15 行表;三重锁:digest + 一致性测试 + 归档生成器)。

## 12. Acceptance Criteria

PR3-AC-01..08(Packet §19)。

## 13. Slice / Compatibility / Boundary Gates

```text
# Slice Gate(GREEN 态 = 产物在位;ruff --no-cache)
python -m compileall -q lima/contracts tests/contracts
python -m unittest discover -s tests/contracts -v        # 445 ran / 0 failed
python -m ruff check --no-cache tests/contracts/test_schema_export.py tests/contracts/test_compatibility_matrix.py
python -m bandit -q -r tests/contracts/test_schema_export.py tests/contracts/test_compatibility_matrix.py
git diff --check
# Compatibility Gate(790 = 764+26 / 1 既有 skip)
# File Boundary(恰 17 文件;产品侧 15 产物,零 .py)
# PR Gate:Implements IP-0010 + Related to #58;禁 auto-close;不自合并
```

RED 态 lint 结果不作门禁依据(Checklist 第 7 条;本 IP GREEN 态 = 产物文件在真实路径)。

## 14. Stop Conditions 与 Decision Request

Packet §23 五条,特别:产物 digest 无法复现;一致性测试发现冻结面矛盾;需改契约模块/既有测试/引入第三方库。

## 15. Commit 与 PR 说明

推荐标题 `feat: add contract JSON schemas, compatibility matrix, and versioning ADR`;`git commit -s`;final commit + Completion Summary 交 P&V。

## 16. 强制 Completion Summary

8 AC 证据表;命令(--no-cache GREEN 态);15 产物 digest 复验清单;零依赖/零修改声明。

## 17. 可直接交给 Coding Agent 的任务指令

```text
你是 LIMA Implementation Agent,正在实现已合并并冻结测试的 IP-0010 PR3 类 Artifact。

必须:
1. 完整阅读稳定标准、lifecycle、责任书、IP-0010 Packet、本交接书、CONTRIBUTING.md。
2. 只新增 Packet §7.1 的 17 个文件;零修改任何既有文件;产品侧零 .py。
3. 15 个产物逐字节复制 .pv_tmp/IP-0010_ARTIFACTS/(digest 与 Packet §17.1 逐项核对)。
4. 核对 Frozen Test Commit;测试只读;26 方法名冻结;零第三方库。
5. 一切 lint 复证在产物在位的 GREEN 态 + --no-cache 下执行。
6. digest 不符或测试与冻结面矛盾时立即停止并提交 Decision Request。
7. 不修改 GitHub Issues、Ledger、PROGRESS、PR;不关闭 Source Issue。
8. 完成后把 final commit、Completion Summary 和真实测试证据交给 P&V Agent。
```

## 18. Maintainer 接收标准

Packet §26 全项。

## 19. 当前唯一下一步

等待 IMPL-IP-0010 Assignment(Frozen Test Commit 核验后);此前不开工。禁止:修改契约模块、启动 IP-0011/manifests/PR4、合并 PR、关闭 #58。
