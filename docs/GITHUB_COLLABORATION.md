# LIMA GitHub 多人协作门禁

## 管理员一次性设置

在 GitHub 仓库的 **Settings → Rules → Rulesets** 中为默认分支 `main`
创建 Active ruleset，并启用：

1. Require a pull request before merging；至少 1 个 approval。
2. Require review from Code Owners。
3. Dismiss stale approvals 与 Require approval of the most recent push。
4. Require conversation resolution。
5. Require status checks，选择唯一稳定检查 `merge-gate`，并要求分支保持最新。
6. Block force pushes、Restrict deletions；管理员不设置常规绕过权限。

先让 CI 在默认分支或一个 PR 上成功运行一次，GitHub 才会在规则页面提供
`merge-gate` 作为可选检查。不要把四个矩阵名称逐个设为 Required；兼容矩阵以后
会扩展，而聚合门禁名称保持稳定。

## 三层测试责任

| 层级 | 由谁运行 | 覆盖内容 | 是否调用真实模型 |
|---|---|---|---|
| PR 快速检查 | 每位贡献者与 CI | 编译、前端语法、CI/实验合同 | 否 |
| 完整工程门禁 | CI | Windows/Linux 3.11/3.12、只读容器、安全扫描、修复约束、前端 typecheck/行覆盖率/构建、Playwright 审计生命周期 E2E（仅 Linux，Epic #33 冻结决策 4） | 否 |
| 成本型外部评测 | 管理员从 LIMA 实验中心发起 | 冻结的 repository-disjoint 数据集、真实模型、持久化 artifact | 是，显式发起 |

普通 PR 不接收 API Key，也不执行外部仓库代码。分析器、检索、仲裁或数据集发生
变化时，PR 必须说明 fingerprint 影响；旧 holdout 因漂移拒绝运行是安全门禁生效，
不能通过篡改冻结指纹强行复用。

## 修改类型与最小测试

- 前端交互：更新 `frontend/` 的 Vitest 用例并运行 `npm run typecheck`；`tests/test_frontend_ui.py` 锚定前端结构契约（T10 起 React 为唯一前端，legacy `web/` 已删除）。
- API/Service/Store：覆盖成功、权限拒绝、租户隔离和非法输入。
- 队列/实验：覆盖 ACK/重试边界、崩溃恢复、预算、模糊 LLM 调用和 artifact 完整性。
- 漏洞检测：同时提供危险样本、安全近邻和不确定形态，禁止只有单个命中样本。
- 自动修复：必须包含应修、应拒、Oracle 篡改和目标仓库测试失败场景。
- CI/工作流：保持只读权限、无 PR secrets、Action 完整 SHA 固定和稳定 `merge-gate`。

## 失败证据与复现

GitHub Actions 的每个单元测试矩阵上传 UTF-8 日志，修复约束和安全基线上传 JSON
报告。合并请求的 Evidence 区应写明本地命令、关键结果与已知限制；不要上传 `.env`、
私有仓库快照、模型密钥或未经脱敏的真实评测上下文。
