# 前端接口与文档索引

核对日期：2026-10-03。代码基线：PR #261（`feat/agent-detection-backend`）+ PR #262（`feat/frontend-agent-detection-api`，stacked 于 #261 之上）。两条 PR 合并前，`main`（`1eaffff`）仍是“仅前端”形态。

本文整理 React 管理台使用的接口，并单列 C++ 智能体检测的联调契约。实现以 `lima/api.py`、`lima/service.py` 和 `lima/repository_scanner.py` 为准；前端调用入口为 `frontend/src/shared/api/client.ts` 与各 feature 页面。本文不是全站 OpenAPI，也不替代历史设计或 V5 Implementation Packet。

## 1. 当前交付状态

PR #262 当前 stacked 于 #261 之上：分支内**同时包含**前端与后端实现。下表区分两种部署形态——仅合 #262 到旧 main（不建议）对应“旧 main”列，#261+#262 配套部署对应“本 PR 组合”列。

| 能力 | 前端 | 旧 main 后端（`1eaffff`） | 本 PR 组合（#261+#262） |
|---|---|---|---|
| 本地 / GitHub 仓库扫描端点 | 已接入 | 已有 | 已有；来源校验与异步任务框架不变 |
| `agent_detection` 请求字段 | 两种仓库来源均显式发送 | 忽略该字段 | 已实现三态矩阵、入队快照与任务局部执行 |
| 新 `cxx_agent` 能力字段 | 校验字段后才允许提交 | 不返回 | 已返回 `per_request_switch` / `llm_configured` / `analyzer_configured` / `max_agent_calls` |
| 三个具名 400 错误码 | 已解析、保留草稿并刷新能力 | 不产生 | 已实现（`error` + 稳定 `code` 并存） |
| `PLATFORM_ANALYSIS` | 已支持标签及按名称定位 | 不发出 | 已实现，位于 SAST 与语义复核之间，仅真正进入平台链时发出 |
| `collaboration.platform` 摘要 | 已显示 | 已输出 | 已输出 |
| 假设、PoC、实验日志、详情省略说明 | 已支持展开展示 | 不投影 | 已投影：脱敏、单项上限、256 KiB 完整序列化预算与省略原因 |

配套部署下上述能力可用真实报告验收；仅前端部署（对旧 main）时仓库提交会被“旧服务端”门禁阻断，PR / Diff 不受影响。完整组合验收（fake 模型双来源端到端、真实 Sidecar/模型联调）仍待执行，见 §6。

## 2. 管理台接口清单

认证开启时使用 `Authorization: Bearer <access_token>`。角色权限和租户范围由服务端检查；前端按钮可见性不能替代授权。权限列是服务端 permission 名称。

| 方法与路径 | 权限 | 返回 / 用途 | 前端调用位置 |
|---|---|---|---|
| `GET /health` | 匿名 | 健康与版本信息 | `client.ts` 的 `health()` |
| `POST /v1/auth/login` | 匿名 | token、租户、角色；认证关闭时 409 | `client.ts` 的 `login()` |
| `GET /api/repository-scans/capabilities` | `manage` | 导入、来源、分析器及模型配置 | `AuditCreatePage.tsx` |
| `POST /v1/repository-scans` | `manage` | 202，仓库扫描任务 | `audit-create/model.ts` |
| `POST /v1/reviews?async=true` | `review` | 202，PR / Diff 审查任务 | `audit-create/model.ts` |
| `GET /api/tasks` | `read` | `{tasks: [...]}`；可传 `limit` | `TaskListPage.tsx` |
| `GET /v1/tasks/{id}` | `read` | 完整任务、进度、报告、失败信息 | `client.ts` 的 `task()` |
| `GET /v1/tasks/{id}/report` | `read` | Markdown 报告；未有报告时 404 | 报告下载端点 |
| `GET /v1/tasks/{id}/feedback` | `review` | `{cases: [...]}` | `taskFeedback()` |
| `POST /v1/tasks/{id}/feedback` | `review` | 201，反馈记录结果 | `submitTaskFeedback()` |
| `POST /v1/tasks/{id}/repair-preview` | `fix` | 200，只读修复预览 | `createRepairPreview()` |
| `POST /v1/tasks/{id}/fix` | `fix` | 201，修复分支 / 提交结果 | `createFix()` |
| `POST /v1/tasks/{id}/cancel` | `review` | 202 或 404，`cancel_requested` | 已有任务控制端点 |
| `POST /v1/tasks/{id}/resume` | `review` | 202，任务恢复受理结果 | 已有任务控制端点 |
| `POST /v1/github/installations` | `manage` | 201，安装绑定信息 | `registerGithubInstallation()` |

其他管理台页面的读取入口：Skills / Settings 使用 `GET /api/skills`；Evolution 使用 `GET /v1/evolution/status`、`GET /v1/evolution/runs` 和 `GET /api/failures`；Experiments 使用 `GET /v1/experiments/catalog`、`GET /v1/experiments` 以及创建、取消和恢复实验端点。具体实验参数与权限以 `lima/api.py` 和 `ExperimentsPage.tsx` 为准，不属于本次智能体检测开关的扩展范围。

## 3. 现有仓库扫描接口

### 3.1 创建任务

`POST /v1/repository-scans`，JSON 请求体。以下是当前后端已识别的请求形式。

本地导入：

```json
{"repository_key":"team/project"}
```

GitHub 来源：

```json
{"source":{"type":"github","url":"https://github.com/team/project","ref":"main"}}
```

`repository_key` 是管理员配置导入根目录下的安全相对路径，不能提供任意绝对路径。GitHub 来源受 `LIMA_REPOSITORY_SCAN_SOURCES` 控制；`ref` 可省略，由后台解析并固定到实际 revision。浏览器不直接请求 GitHub，也不物化仓库。

服务端在存在 `source` 时走 source 分支，否则读取 `repository_key`。客户端应只选择一种形式。202 响应表示已入队，不表示检测完成：

```json
{
  "task_id":"00000000-0000-4000-8000-000000000001",
  "scan_id":"00000000-0000-4000-8000-000000000001",
  "task_type":"repository_scan",
  "repository":"team/project",
  "source":{"type":"local-import","repository_key":"team/project"},
  "state":"PENDING",
  "queue":"memory"
}
```

示例值仅说明结构；实际 source 元数据和 queue 名称以响应为准。

### 3.2 PR / Diff 审查

```http
POST /v1/reviews?async=true
Content-Type: application/json
```

```json
{"repository":"team/project","diff":"--- a/app.py\n+++ b/app.py\n...","pull_request":12}
```

`pull_request` 可省略。当前前端使用异步模式；不传 `async=true` 的现有同步接口返回 201。PR / Diff 请求不带 `agent_detection`，C++ 平台 PR 接入仍未启用（`pull_request_scan=false`）。

### 3.3 读取任务与报告

`GET /v1/tasks/{id}` 返回任务的 `state`、`input`、`progress`、`report`、`failure` 等字段。报告在任务成功后使用；仅有 202 时不要推断检测结果。

前端详情对非终态任务在创建后前 30 秒每 2 秒轮询，随后每 4 秒轮询；`SUCCESS`、`FAILED`、`CANCELLED` 停止轮询。阶段用 `progress.stage` 名称定位，兼容数字索引偏移（旧 main 为 13 阶段，无 `PLATFORM_ANALYSIS`；恢复的旧任务进度在 #261 中已归一化计数）。本 PR 组合的后端阶段为：

```text
QUEUED → RESOLVING_REVISION → CHECKING_CACHE → DOWNLOADING_ARCHIVE
→ VALIDATING_ARCHIVE → PREPARING_WORKSPACE → INVENTORY
→ DATAFLOW_ANALYSIS → AST_ANALYSIS → SAST_ANALYSIS
→ PLATFORM_ANALYSIS → SEMANTIC_TRIAGE → FINALIZING → COMPLETED
```

任务可跳过不适用阶段。全局开启 C++ 平台链后，摘要位于 `report.collaboration.platform`，包括 `mode`、`status`、`stats`、`states`、`broker`、`diagnostics`、`targets`，并可能含报告内嵌的 `v4` 预览。

## 4. 智能体检测契约（#261+#262 配套部署已实现）

本节契约已在 PR #261 实现。对旧 main 单独部署前端时以下示例不成立，不得当作当前响应。

### 4.1 按任务开关与错误码

新前端在本地和 GitHub 仓库请求中显式增加 `agent_detection: true` 或 `false`。计划中的 API 接受可选布尔字段；显式 `null`、数字和字符串均应返回 400。

| 请求值 | 默认 `off` | 默认 `auto` | 默认 `required` |
|---|---|---|---|
| 不传（旧客户端） | `off` | `auto` | `required` |
| `true` | `auto` | `auto` | `required` |
| `false` | `off` | `off` | 400，`agent-detection-required` |

显式开启还应检查模型和事实分析器配置。约定三个稳定错误码：

| `code` | 条件 | 前端处理 |
|---|---|---|
| `agent-detection-required` | 策略 required 下显式关闭 | 解释策略，保留草稿，刷新 capabilities |
| `agent-detection-unavailable` | 显式开启但未配置模型 | 提示管理员配置，保留草稿，刷新 capabilities |
| `agent-detection-analyzer-unavailable` | 显式开启但事实分析器未装配或 memory=off | 提示管理员配置，保留草稿，刷新 capabilities |

错误格式为 `{"error":"用户可读说明","code":"稳定错误码"}`；普通错误继续使用 `error`。当前后端没有这些具名响应。

入队后应持久化原始选择 `agent_detection` 和解析后的 `effective_cxx_agent_mode`；worker 与重试使用任务快照，通过局部参数运行扫描，避免改写共享 scanner 模式。模型、密钥、提示词和预算仍由管理员配置。

### 4.2 capabilities

在已有 `cxx_agent` 对象上需要新增：

```json
{
  "mode":"off",
  "per_request_switch":true,
  "llm_configured":true,
  "analyzer_configured":true,
  "max_agent_calls":40
}
```

`mode` 表示管理员默认模式；`required` 下 `per_request_switch=false`。新字段不能用旧 `configured` / `repository_scan` 替代，因为旧字段依赖全局模式，不能表达“从 off 按次启用”。配置布尔值不代表服务此刻健康；`max_agent_calls` 是平台链调用次数上限，不是金额报价或其他 LLM 功能的总预算。

当前前端行为：尚未选择时按服务端默认初始化；明确草稿选择保持；required 锁定开启，并按有效策略值发送 `true`。能力请求 pending 时允许填写并进入确认页，但提交被禁用；请求失败可重试；缺新字段或默认开启但配置不完整时暂停仓库提交。有效开关开启时必须先确认代码上下文发送和调用费用，取消不发送请求。

### 4.3 平台进度与目标详情

`PLATFORM_ANALYSIS` 位于 `SAST_ANALYSIS` 与 `SEMANTIC_TRIAGE` 之间，仅在实际进入链路时发出事件。关闭或无 C++ 来源时跳过；这不是新增任务终态，也不等于启动 Mining / Repair。

target 摘要包含 `target_id`、`path`、`line`、`state`、`cwe`、`proof`、`experiments`、`rejected_reason`，另有以下可选详情字段（#261 已投影）：

| 字段 | 展示用途 | 报告边界（已实现） |
|---|---|---|
| `hypothesis_reason` | 假设描述 | 先脱敏，整项包含或省略；单项上限 2 KiB |
| `poc_driver_code` | PoC driver 审计副本 | 先脱敏，整项包含或省略；单项上限 32 KiB；前端只显示文本 |
| `experiment_log` | 实验轮次 / 结果 | 最后 8 轮；仅投影 `round`、`stage`、`exit_code`、`error_type`、`faulting_line`、`hit` |
| `detail_omissions` | 缺字段的原因 | 如 `poc_driver_code:too-large`、`experiment_log:budget-exhausted`、`experiment_log:older-rounds-omitted` |

摘要最多 32 个目标；新增详情总预算 256 KiB，按完整 JSON 序列化字节计量（覆盖转义、字段名、容器与全量省略说明预留）；分配按正向 finding 优先、再按 target_id，摘要顺序保持原样。缺字段不代表未发生实验；脱敏 PoC 不保证可直接编译复现。

`v4.workflow_summary.execution_status`（`succeeded` / `failed` / `cancelled`）是平台链的封存执行状态：`status=completed` 只表示链路走完并产出审计载荷，scout 不可用等降级路径也会是 completed。前端以执行状态区分成功 / 失败 / 取消，不做无条件的“已完成实验与证明”声明。

旧报告没有 platform 或状态为 `disabled` 时不显示空卡片。`no-cxx-sources`、`analyzer-not-configured`、`analyzer-unavailable`、`llm-not-configured`、`review-failed` 显示运行状态；不能把不可用或零统计解释为仓库安全。

## 5. 修复预览边界

前端仅在本地导入仓库报告存在 `.py` finding、CWE 为 22/78/89 且 `automatic_repair !== false` 时显示修复预览按钮。混合报告可预览符合条件的 Python finding；C++ finding 不支持自动修复。这个可见性规则不代表该 finding 已满足后端验证条件。

`POST /v1/tasks/{id}/repair-preview` 返回 `verified-preview`、`blocked` 或 `no-repair` 等状态及 patches、verification、blocked_findings。只读预览会验证快照和修复约束，不修改导入仓库，`publication_ready=false`；它不等同于 `/fix` 发布链路。

## 6. 文档归属与联调验收

| 文档 | 用途与状态 |
|---|---|
| [README](../README.md) | 项目入口、部署和基础仓库扫描用法 |
| [本文](FRONTEND_API.md) | 当前接口清单、前后端交付差距和调用契约 |
| [智能体平台说明](AGENT_VULN_PLATFORM.md) | 现役平台架构与评测背景 |
| [C/C++ 内存分析](CXX_MEMORY_ANALYSIS.md) | Sidecar 和静态 / 动态工具部署 |
| [前端接口方案](superpowers/plans/2026-09-28-frontend-agent-detection.md) | 设计与验收依据；不能单凭方案宣称后端已交付 |
| [Issue 拆分](superpowers/plans/2026-09-30-frontend-agent-detection-issues.md) | #243–#246 分工和 #70/#91 兼容边界，保留创建时背景 |
| [旧七角色链说明](CXX_LLM_AGENT_ANALYSIS.md) | 已退役，历史参考 |

联调前先检查当前 checkout 的后端字段与执行路径，不能只看前端 fixture。验收顺序（1–3 已在 #261 的单元与集成测试覆盖；4–5 待执行）：

1. ~~补齐 capabilities、请求解析、三态模式快照和具名错误~~ 已实现；已覆盖全局 off 按次开启、auto 按次关闭、required 拒绝关闭。
2. ~~验证工厂保留 provider 默认模型及显式 C++ 模型覆盖~~ 已实现；并发任务和重试不串模式有回归测试。
3. ~~补齐阶段事件和详情投影~~ 已实现；脱敏、整项省略、最后 8 轮、优先级及完整序列化预算边界有回归测试。
4. 本地与 GitHub 来源用 fake 模型 / 物化器走通提交、202、轮询、终态和真实报告投影。
5. 使用真实模型与 Sidecar 记录在线成功或故障状态，模拟测试不能替代在线健康性验证。

文档整理时只核对源代码及链接。本提交的自动化验收应以当前 checkout 的测试输出为准，不沿用之前未提交工作区的后端测试数量。V5 页面按 #70 默认只读摘要，PoC 与日志需要受权限控制的按需读取；本文旧任务报告契约不替代该设计。
