# 赛题提交后 Issue 关闭建议

日期：2026-10-22。用户已确认赛题提交。本次只审计并建议，未修改远端 Issue 状态。

依据：GitHub 在线 open Issue/PR、近期合并 PR，以及 fetch 后固定 main `9abe4d2c2ad7461a59b3c11cb84c87b7b00252a7` 的源码。当前本地 HEAD `4c3adfa`，工作树另有未提交修改；未将其当作 main 已交付内容。未重新运行测试或真实部署。

## 建议按 completed 关闭：4 项

| Issue | 任务 | 实现依据 |
|---|---|---|
| #293 | 覆盖摘要 | PR #316 已合并，main 有 scripts/summarize_competition_coverage.py 和 lima/competition_coverage.py |
| #312 | 多轮结果汇总 | PR #317 已合并，main 有 scripts/aggregate_competition_runs.py 和 lima/competition_run_summary.py |
| #313 | 环境清单 | PR #318 已合并，main 有 scripts/export_competition_environment.py 和 lima/competition_environment.py |
| #314 | 报告材料缺件检查 | PR #320 已合并，main 有 scripts/check_competition_report_materials.py 和 lima/competition_report_materials.py |

关闭说明引用对应 PR 与已有验收记录；原有工具范围及未验证边界保持不变。不是据此宣布 OH 漏洞或全部真实部署验收完成。

## 随本届交付结束收尾：3 项

- #299 实际封包：依据用户已提交的事实，可关闭本届交付任务；关闭前在说明中补最终包名/版本或内部归档位置。不把未开发的通用打包工具写成完成，若仍需要另开赛后任务。
- #300 DEMO/视频：若本次提交已包含视频，可按 completed 关闭并记录归档位置；若未提交视频且不再补录，按 not_planned 结束，不能仅凭“已提交”认定视频制作完成。
- #315 赛前协作总表：本届认领与交付阶段已结束，可按阶段完成关闭；链接仍开放的赛后任务，关闭总表不代表子任务全部完成。

## 建议取消旧交付形式：1 项

- #291 独立文档状态核对表：main 和本地未发现规定交付文件 docs/competition/文档状态核对表.md。若提交后不再补该表，可按 not_planned 关闭；不能按 completed 声称该表已交付。通用产品文档维护继续按新需求跟踪。

## 暂不关闭

- #298：部署 smoke 工具 PR #329 仍 open，虽 PR 自述 Docker 通过，但本轮未独立验证，也未合并。继续验收合入后再关，或明确取消该工具时按 not_planned 收尾。
- #289：PR #331 已提供 Markdown 下载，但 Issue 要求 Markdown/JSON 双格式，JSON 仍缺；保持赛后或明确裁剪剩余范围，不能按全部完成关闭。
- #246：main 已有平台展示；原 Issue 还包含双来源 E2E 与真实链验收，本轮未找到齐全证据。不按部分实现直接关 completed。
- #165/#166：全量评测及旧 Epic 尚不能称完成。若决定淘汰旧目标，应说明被哪些新任务替代，再按 not_planned/重复处理；比赛提交本身不是完成依据。
- #181/#182：构建架构与 compdb 预算缺陷仍待解决。
- #319：提示词误报评测仍待完成。
- #321–#327：已明确赛后自动构建与 PoC 工作，继续保留。

## 已经收尾及更正

- PR #328 已合并至 main，#311 已不在 open Issue 列表，不重复关单。
- PR #331 已合并；10-20 所述“本地 5 个集成修复尚未进入 main”已过时，当前 main 已含这批集成修复。
- 本建议未将“比赛已提交”扩展为所有材料和功能都通过验收。正式关单时区分 completed 与 not_planned，并保留已实现部分、未实现部分和后续任务引用。
