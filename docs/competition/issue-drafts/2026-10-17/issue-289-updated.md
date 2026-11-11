# [Frontend][E12] 任务详情下载 Markdown / JSON 报告（附 Codex 实施与人工验收清单）

## 2026-10-17 并行开发边界（本节优先于下文宽泛范围）

适合前端队友，保持现有 assignee；认领后由维护者分配，不自动换人。#246 已有组件与 API 实现（PR #261/#262 已合并），先核对它剩余的 E2E，不能重做已有卡片。

- 只拥有原正文列出的 TaskDetailPage.tsx、client.ts 和各自测试及相邻小下载 helper；不改 frontend/e2e、后端、types 合同或其他页面。
- #246 的剩余 E2E 与本任务建议由同一位前端负责人串行完成；若并行必须分别锁定上述文件和 frontend/e2e，不能各改一套 API helper。
- 不把下载 JSON 称为完整原始证据包；不依赖 E01/E06/E07/E14。沿用已有 10-19 时窗，排期由维护者决定。

---

## Problem to solve
#246 已有任务详情和平台结果展示，后端也有 GET /v1/tasks/{id}/report，但前端没有报告下载按钮。本任务补导出，不重做报告页面，不改漏洞判断。

## Proposed solution
在审计报告卡片增加“下载 Markdown”“下载 JSON”。Markdown 来自现有认证端点；JSON只导出已经加载的 task.report 对象，不导出完整task、token、input、设置或数据库内容。

### 给 Codex 的具体步骤
1. 阅读 frontend/src/features/tasks/TaskDetailPage.tsx 的 ReportCard、frontend/src/shared/api/client.ts、types.ts、client.test.ts 和 TaskDetail.report.test.tsx；核对后端report端点。
2. 在集中式api对象增加 taskReportMarkdown(taskId,signal?)，复用 request<string> 和 encodeURIComponent(taskId)。当前 request 已按Content-Type解析文本/JSON，不另写一套fetch/认证流程。如main已有等价方法则复用。
3. 按“report存在且是有效报告对象”显示按钮，不根据finding数量决定：零finding报告同样允许下载；没有report则隐藏。失败或取消任务如已有报告，也按已有访问权限允许导出。
4. Markdown请求期间仅相应按钮loading；成功后保存文本。JSON导出 task.report 的UTF-8格式化JSON，不重新计算任何状态。
5. 文件名固定 lima-task-<安全化taskId>-report.md / .json；taskId仅保留ASCII字母数字、连字符和下划线，其他字符替换成_并限制长度。API URL使用原始ID的URL编码，不能使用文件名安全化ID替代。
6. MIME使用 text/markdown;charset=utf-8 与 application/json;charset=utf-8。用Blob/object URL下载，释放object URL，防止重复点击资源泄漏；封装小download helper可放相邻文件。
7. 401沿用现有认证处理，403/404/网络异常有可见提示；不要把错误响应保存成报告。错误后按钮恢复可用，不向URL添加token。
8. 前端测试覆盖：有报告、无报告、零finding、旧格式、Unicode文本、Markdown请求认证/URL编码、JSON只含report、下载错误/状态恢复及object URL释放。补一张演示截图或短GIF。

### 文件范围
frontend/src/shared/api/client.ts、client.test.ts、frontend/src/features/tasks/TaskDetailPage.tsx、TaskDetail.report.test.tsx；必要小型下载helper及对应测试。后端和报告合同不变。

## Evidence and evaluation
- AC-01：下载Markdown与后端端点内容一致；JSON与当前task.report一致，包含证据等级但不包含task.input或token。
- AC-02：无报告不显示，零finding报告仍可下载；中文正常显示。
- AC-03：403/404/断网不生成错误文件，显示错误并恢复按钮；当前认证和URL编码保留。
- AC-04：在 frontend 运行 npm run typecheck、npm run test -- src/shared/api/client.test.ts src/features/tasks/TaskDetail.report.test.tsx、npm run build；按main现有结构核对路径，记录真实结果。

### wenxinliu52 人工验收
- [ ] 让Codex准备本地测试页面或已有授权演示任务：点两个按钮，打开文件看中文是否正常。
- [ ] JSON只包含报告，不包含登录token或提交任务的原始参数。
- [ ] 无报告任务没有按钮；零finding任务有按钮。
- [ ] 模拟接口失败时出现提示，页面仍可操作，不下载“错误页”。
- [ ] 截图中的按钮和演示结果与PR描述一致。

## Security and operational risks
JSON是API已提供的脱敏、有界报告投影，不能命名为“完整原始证据包”；PoC只作为文本下载，不执行。无新增权限、模型调用或跨租户接口。关联 #246。
## 执行方式与职责
- 负责人：wenxinliu52。代码主要由你的 Codex 完成，你负责按本 Issue 的人工验收清单检查结果；不要求你独立审查漏洞机理。
- 将整个 Issue 发给 Codex，并要求先核对当前 main、已有实现和仓库协作说明；如已有实现，补缺口，不重复开发。
- 一项任务一个分支/PR。只改本 Issue 列出的范围；确需改检测器、沙箱或冻结合同，先报告具体原因，不顺手扩大范围。
- 本 Issue 的测试使用合成数据/Mock，不配置真实模型密钥、不执行目标仓库代码。真实漏洞结论由项目维护者审核。
- PR 描述列出：实现了什么、测试命令和结果、演示命令、未验证事项。引用本 Issue；按仓库现有规则在合并后复验，不以 Codex 一句“完成”作为关闭依据。

## 交付给 wenxinliu52 的检查材料
Codex 必须提供可复制命令、实际输入/输出示例、测试原始结果和文件清单。你按人工清单操作后记录通过/不通过；遇到不一致，把原始输出交回 Codex 修复。涉及漏洞真假、CWE、修复有效性的结论交维护者判断。
