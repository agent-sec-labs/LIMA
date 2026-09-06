# LIMA Coding Agent IP-0011 正式开发任务交接书

> 适用 Packet:`IP-0011 V5-FR-04 场景 fixtures(六状态跨 Artifact 组合)`
>
> Packet 文档:`docs/LIMA_Implementation_Packet_IP-0011_Scenario_Fixtures.md`(权威契约;冲突以 Packet 为准)
>
> 生效条件:两份文档合并 `main` 且 Coordinator 签发 IMPL-IP-0011

## 0. 效力与边界

你是 LIMA Implementation Agent。只交付 IP-0011 Packet 冻结的 6 个 fixture 与 1 个测试文件;不改 Packet/测试语义、不管理 PR/Issue/Ledger;越界即停提交 Decision Request。

## 1. 正式授权

```text
Assignment ID:IMPL-IP-0011(Coordinator 另行出具)
Packet:docs/LIMA_Implementation_Packet_IP-0011_Scenario_Fixtures.md
基线:origin/main @ b3627c299af170e9cb22c6e3cccb9d4c255b8844(实现基线 = 含两份 IP-0011 文档的最新 main)
Frozen Test Commit:阶段二 P&V 交付(RED = 测试读 scenarios/ → FileNotFoundError)
推荐分支:codex/ip-0011-scenario-fixtures
对 Source Issue 影响:PARTIAL(V5-FR-04 将转 SATISFIED;#58 保持 open)
```

## 2. 开工前必读

稳定标准;lifecycle(§9.1);Implementation Agent 责任书;IP-0011 Packet(全文,尤其 §1/§7/§10/§17/§20/§22);本交接书;CONTRIBUTING.md;DI-010 归档(`.pv_tmp/IP-0011_ARTIFACTS/` 6 文件);`tests/contracts/test_schema_export.py`(mini-validator 复用源);IMPL Assignment(到达后)。

## 3. 已验证的仓库事实(P&V,2026-09-06)

- 基线 `b3627c2`:contracts **445/445**、全量 790/0F/1skip、`ruff --no-cache` exit 0;冻结面 18/16/15/12/12/12/27/16/19/29 + 15 PR3 产物;十七 golden;
- `tests/contracts/fixtures/scenarios/` 与 `test_scenario_fixtures.py` 不存在;cxx 三分支不触碰 contracts;
- 6 bundle 已设计期生成并自证(全模块 decode PASS + 链 digest 双向 ALL MATCH);权威 bytes = Packet §10 digest + DI-010 归档;
- 环境差异:redis-py 6.4.0 vs `>=8.1.0,<9`(零影响,照登)。

## 4. 工作树保护与隔离分支

lifecycle §9.1 独立干净 worktree;禁共享根与既有 worktree;未跟踪文件为用户资产;禁破坏性 git 操作。

## 5. 开工前 Scope Confirmation

```text
## Scope Confirmation
- 两份 IP-0011 文档均在 origin/main(merge commit):
- Frozen Test Commit = <SHA>(分支已包含):
- tests/contracts/fixtures/scenarios/ 与 test_scenario_fixtures.py 不存在:
- baseline contracts 445 / 定向 29 通过:
- .pv_tmp/IP-0011_ARTIFACTS/ 6 文件 digest 与 Packet §10 相等(逐项):
- 无未解决 Stop Condition:
```

## 6. 唯一允许的文件范围

恰好 7 个新增文件(Packet §7.1);零修改;产品侧零 .py。

## 7. 必须实现的交付(摘要)

6 fixture 逐字节复制 DI-010(digest 对照 §10);`test_scenario_fixtures.py` 按 Packet §17 的 32 冻结方法实现(inventory 8 + 每状态 4;decode/链重算/标记/round-trip/schema 结构面;mini-validator 经 `tests.contracts.test_schema_export` 复用)。

## 8. 明确 Non-goals

manifests/PR4/closure/runtime;修改模块/PR3 产物/既有 golden;新顶层路径;第三方库。

## 9-13. Baseline / 顺序 / Golden / AC / Gates

Packet §19(445→**477**、790→**822**);§20 第 7 步;§10 digest 表;SC-AC-01..07(§18);Slice/Compatibility/Boundary Gates 同 Packet §19(fixture 在位 GREEN 态 + `--no-cache`;File Boundary 恰 7 文件;PR:只写 `Implements IP-0011` + `Related to #58`,禁 auto-close)。

## 14. Stop Conditions 与 Decision Request

Packet §22 五条,特别:bundle 无法 decode(状态不可达)、digest 无法复现或链断裂、需改 golden/模块/PR3 产物。

## 15-16. Commit 与 Completion Summary

标题 `test: add six-state scenario fixtures for V5-FR-04`;`git commit -s`;模板含 7 AC 证据表 + 6 digest 复验 + 命令(--no-cache GREEN 态)。

## 17. 可直接交给 Coding Agent 的任务指令

```text
你是 LIMA Implementation Agent,正在实现已合并并冻结测试的 IP-0011 场景 fixtures。

必须:
1. 完整阅读稳定标准、lifecycle、责任书、IP-0011 Packet、本交接书、CONTRIBUTING.md。
2. 只新增 Packet §7.1 的 7 个文件;零修改任何既有文件;产品侧零 .py。
3. 6 个 fixture 逐字节复制 .pv_tmp/IP-0011_ARTIFACTS/(digest 与 Packet §10 逐项核对;
   派生规则已冻结于 §10——禁止自创等价变体)。
4. 核对 Frozen Test Commit;测试只读;32 方法名冻结;mini-validator 经测试间导入复用。
5. 一切 lint 复证在 fixture 在位的 GREEN 态 + --no-cache 下执行。
6. decode 失败/digest 不符/需越界时立即停止并提交 Decision Request。
7. 不修改 GitHub Issues、Ledger、PROGRESS、PR;不关闭 Source Issue。
8. 完成后把 final commit、Completion Summary 和真实测试证据交给 P&V Agent。
```

## 18. Maintainer 接收标准

Packet §25(Maintainer Checklist 同先例形态):恰 7 文件、6 digest 全等、32 测试全绿(477/822)、零既有改动、PR 未关 #58。

## 19. 当前唯一下一步

等待 IMPL-IP-0011 Assignment(Frozen Test Commit 核验后);此前不开工。禁止:修改任何模块/golden/PR3 产物、启动 IP-0012、合并 PR、关闭 #58。
