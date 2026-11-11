# LIMA 赛前冻结 Issue 审计

日期：2026-10-20（Asia/Shanghai）。目标：停止非必要新增开发，保留冻结、封包与材料工作。

## 审计基线与方法

- 本地分支：`codex/integration-repairs-20261018`，已提交 HEAD：`8c539211f1faa2981111bb0dea84b6dd0dab6b7d`。
- 本轮 fetch 的 GitHub main：`069f01feddde5536a38d972bf315ec3ae9fd5ac3`。
- 两者共同基线：`bd8ba3441017c3f1463cd9fe0fc9bbbf45c81ad0`；已分叉，不能把两边能力相加写成单一交付版本。
- 在线核对全部 24 个 open Issue、3 个 open PR，以及相关评论和已合并 PR #316/#317/#318/#320。
- 使用固定 main SHA 的独立临时源码快照运行 4 组工具测试；没有切换、合并、重置当前工作树，也未执行模型或目标代码。
- 工作树存在用户正在修改的 `lima/repository_scanner.py`、`lima/service.py` 和两个相关测试文件。其内容不能当作已提交冻结版，本次未编辑它们。

## 赛前暂停新增开发：新增标注 7 项

为以下 Issue 添加已有标签 `phase:post-competition`，正文顶部说明原因；保留旧正文、标题、负责人、其他标签及 open 状态。

| Issue | 暂缓内容 | 赛前保留的边界 |
|---|---|---|
| [#165](https://github.com/agent-sec-labs/LIMA/issues/165) | 全量真实模型审阅与零漏报零误报目标 | 只报告指定样本与已完成范围的真实指标；无标签不能证明零漏报 |
| [#166](https://github.com/agent-sec-labs/LIMA/issues/166) | 旧 Epic 的构建扩展、全量验收及旧合并依赖链 | 现有检测链在 main 已存在，旧文中尚未合入的描述作为历史记录保留 |
| [#181](https://github.com/agent-sec-labs/LIMA/issues/181) | 通用两层构建架构与大范围 OH 构建接入 | 固定已有可验证环境，不把通用构建完成当今天的新增前置 |
| [#182](https://github.com/agent-sec-labs/LIMA/issues/182) | compdb 与普通源码快照预算彻底解耦 | 问题未修复；实际演示必须检查构建上下文及超预算诊断，阻塞则单独修 |
| [#246](https://github.com/agent-sec-labs/LIMA/issues/246) | 已有平台结果展示的剩余 E2E/增强开发 | main 已有 PlatformCard；实际展示冒烟和演示阻塞修复保留 |
| [#289](https://github.com/agent-sec-labs/LIMA/issues/289) | Markdown/JSON 双下载完整新规格 | 本地已有 Markdown 下载、main 未合入；不重复做，复用后端导出或最终版本现成功能 |
| [#319](https://github.com/agent-sec-labs/LIMA/issues/319) | structured-v2 提示词重构、默认切换和新增开发性评测 | 与维护者已有赛后评论一致，保持现有生产默认和原始证据 |

## 已标赛后：7 项保持原状

[#321](https://github.com/agent-sec-labs/LIMA/issues/321)、[#322](https://github.com/agent-sec-labs/LIMA/issues/322)、[#323](https://github.com/agent-sec-labs/LIMA/issues/323)、[#324](https://github.com/agent-sec-labs/LIMA/issues/324)、[#325](https://github.com/agent-sec-labs/LIMA/issues/325)、[#326](https://github.com/agent-sec-labs/LIMA/issues/326)、[#327](https://github.com/agent-sec-labs/LIMA/issues/327) 均已有赛后标题、正文和标签，不重复修改。

## 已合入：4 项仅补状态，不重复开发

| Issue | 合入来源 | main 已有入口 |
|---|---|---|
| [#293](https://github.com/agent-sec-labs/LIMA/issues/293) | PR #316 | `scripts/summarize_competition_coverage.py` |
| [#312](https://github.com/agent-sec-labs/LIMA/issues/312) | PR #317 | `scripts/aggregate_competition_runs.py` |
| [#313](https://github.com/agent-sec-labs/LIMA/issues/313) | PR #318 | `scripts/export_competition_environment.py` |
| [#314](https://github.com/agent-sec-labs/LIMA/issues/314) | PR #320 | `scripts/check_competition_report_materials.py` |

Issue 仍 open；本次只注明已有实现与使用边界，未替维护者执行关闭验收。main 上工具的缺失值/未知信息不转换成成功或零值。

## 已有 PR：不重复开工

- [#311](https://github.com/agent-sec-labs/LIMA/issues/311)：PR #328 及其补丁 #330 仍 open。有限审核后决定是否纳入；可选预检工具不阻塞现有流程封包。本次未评审其完整代码或确认可合并。
- [#298](https://github.com/agent-sec-labs/LIMA/issues/298)：PR #329 仍 open。不要重复写脚本；最终冻结版本的真实干净部署检查仍保留。PR 自述的 Docker 通过不是本轮独立复验结果。

## 赛前继续

- [#291](https://github.com/agent-sec-labs/LIMA/issues/291)：文档状态与证据核对，保持原状。
- [#299](https://github.com/agent-sec-labs/LIMA/issues/299)：实际封包和缺件清单继续；正文注明通用自动打包工具不再作为今天前置，可人工白名单完成。
- [#300](https://github.com/agent-sec-labs/LIMA/issues/300)：DEMO 彩排与视频，保持原状。
- [#315](https://github.com/agent-sec-labs/LIMA/issues/315)：正文顶部同步以上分工，停止新增功能认领，优先审核、验证和交付。

24 项覆盖：新增后置 7 + 原有后置 7 + 已合入 4 + 已有 PR 2 + 交付项 3 + 协作总表 1。

## 冻结前仍需确认的版本差异

本地比共同基线多以下 5 个提交，尚未进入上述 main：

- `b491110`：仓库扫描集成修复，涉及取消/恢复、Markdown 下载、指定调查路径、C++ 失败及部分覆盖展示、Semgrep 恢复与真实证据等。
- `d21e910`：ASan SEGV 观察归一化。
- `fe8cf30`：历史实验数据集身份保留。
- `9ee3ee5`：C++ 分析快照超时回收。
- `8c53921`：Redis 长任务租约续期。

main 则已加入本地分支没有的 4 个工具及相关镜像来源改动。今天需要核对最终冻结版本是否包含需要的已有修复和工具；本次仅审计和标注，没有自动合并这些提交。

## 证据和验证

- 远端修改前快照：`issues-before.json`；原文保留，可逐项追溯。
- 具体更新内容：`annotation-plan.json`；执行脚本：`annotate-issues.ps1`（默认仅显示计划，`-Apply` 才写远端）。
- 逐项写后回读结果：`annotation-results.json`。正文、标题、open 状态、负责人和原标签均检查，新增标签仅作加法。
- GitHub 连接器写入返回 403 `Resource not accessible by integration`；改用本机 Git 已保存的现有授权调用同仓库 API，未请求新凭证，未写入或打印凭证。
- main 独立源码快照测试：`tests.test_competition_coverage`、`tests.test_competition_run_summary`、`tests.test_competition_environment`、`tests.test_competition_report_materials`。**133 项，7 skipped，其余通过，退出码 0，耗时 17.696 秒**。日志与快照身份在 `output/competition-freeze-audit-20261020/`。
- 没有关闭 Issue、改变负责人、修改产品代码、合并 PR 或执行全仓测试；没有以本轮工具单测代替真实 OH/模型/部署验收。

## 修正前轮建议

此前本地审计没有核对最新 main，将部分工具仍列为待开发；本轮以固定 main 和实际合入 PR 更正。独立离线验包、真实评测增强等已关闭裁剪项保持原决策，不因上一轮完善清单再次启动。

暂停新增开发不等于所有赛题条件已完成。正式 OH 漏洞、合法 PoC、版本影响和必交材料仍按原始赛题逐项检查，不用功能冻结替代证据。
