# C++ 智能体检测前端调用接口契约（草案）

> 文档类型：接口契约草案（DRAFT，未评审）
>
> 目标：C++ 分支（`codex/cxx-llm-agent-detection`，PR #183）合并入 main 后，前端可通过现有仓库扫描流程按需调用 C++ 智能体检测（平台链）。
>
> 设计原则：**不新开端点、不改任务生命周期**——完全复用 `/v1/repository-scans` 入口、任务模型、任务中心轮询和报告渲染，只补"按次触发"缺口。使用流程与 LIMA 现有仓库扫描一致。
>
> 状态：2026-09-25 与 Maintainer 确认三项设计决策后成稿，待评审。

## 1. 已冻结的设计决策

| # | 决策 | 结论 |
|---|---|---|
| 1 | 费用授权模型 | 跟随 LIMA 当前逻辑：不新增授权体系。仅 `manage` 权限管理员可提交扫描（现有门槛），打开开关后提交前做一次计费二次确认（对齐"外部评测"交互先例）。不引入 `repository-grants` 式新授权门。 |
| 2 | 前端暴露粒度 | 只暴露"智能体检测"一个开关，内部映射平台链（`agent_orchestrator.run_platform_review`）。legacy 链（`cxx_agents.py`）不出现在用户面。`required` 模式不暴露给前端。 |
| 3 | GitHub source 适用性 | 跟随 LIMA 当前逻辑：开关对 `repository_key` 与 `source`（GitHub 导入）一视同仁，与现有 LLM 语义复核行为一致；管理员如需禁 GitHub 来源，用现成的 `LIMA_REPOSITORY_SCAN_SOURCES` 在来源层控制。 |

## 2. 请求契约：`POST /v1/repository-scans`

新增一个可选字段：

```json
{
  "repository_key": "team/project",
  "agent_detection": true
}
```

| 字段 | 类型 | 语义 |
|---|---|---|
| `agent_detection` | bool，可选 | `true` = 本次扫描启用智能体检测，映射平台链 mode=`auto`；不传或 `false` = 本次不跑平台链。确定性静态三层链不受此字段影响，继续跟随服务端 `cxx_memory_mode` 配置。 |

语义细则：

- **缺省 = 跟随服务端默认**：新增 env `LIMA_CXX_PLATFORM_DEFAULT`（默认 `off`），与现有 `LIMA_CXX_*` env 模型同构；
- **只影响本任务**：per-request 覆盖写入 task input，供 worker 与审计回放，不改全局状态；
- **选 `auto` 不选 `required` 的理由**：`auto` 语义为"LLM 失败 → 诚实弃权 → 任务照常完成"，对前端用户友好；`required` 会把任务跑失败，仅保留给 CLI / 服务端配置使用。

## 3. 错误语义（fail-fast，不静默）

| 场景 | 返回 |
|---|---|
| `agent_detection` 非 bool 类型 | `400`（对齐现有请求校验风格） |
| `agent_detection: true` 但服务端未配置可用 LLM | `400` + 错误码 `agent-detection-unavailable`。用户明确要求智能体检测时不得静默降级为纯静态扫描。 |
| 其他 | 与现有扫描接口完全一致（`202` + 任务 ID） |

## 4. 能力协商：`GET /api/capabilities`

`cxx_agent` / platform 节点新增两个字段供前端渲染：

```json
{
  "cxx_agent": {
    "available": true,
    "per_request_switch": true,
    "llm_configured": true
  }
}
```

`llm_configured: false` 时前端禁用开关（置灰 + "未配置模型"提示），不发无效请求。

## 5. 响应与报告：零改动

- 任务模型、轮询（`GET /v1/tasks/{id}`）、状态机全部复用；
- 报告中的 `collaboration.platform` 载荷（假设、PoC driver、实验日志、Scout/Specialist/Critic 统计、broker 裁决）已存在，前端新增 PlatformCard 渲染（照 `UafV2Card`（`frontend/src/features/tasks/TaskDetailPage.tsx:639`）的模式，仅在报告携带该字段时渲染）。

## 6. 前端用户视角完整流程

```
登录 → 仓库扫描页 → 选 repository_key（或填 GitHub source）
  → 看到"智能体检测"开关（默认=服务端配置；llm_configured=false 时置灰）
  → 打开 → 弹窗："本次扫描将调用 LLM 分析 C/C++ 代码，按用量计费，确认？"
  → 提交 → 任务中心轮询（与现有流程一致）
  → 报告页：findings 带 verification_state + UafV2Card + PlatformCard（新增）
```

C++ findings 恒为 `automatic_repair=false`：前端对 cxx findings 不显示"生成修复预览"入口（或显示"不支持"），需在实现时核实现有行为。

## 7. 实现落点

| 层 | 文件 | 改动 |
|---|---|---|
| API | `lima/api.py:483`（`/v1/repository-scans` 分支） | 解析 `agent_detection`，类型校验，无 LLM 时 `400` |
| Service | `lima/service.py` `enqueue_repository_scan` / `enqueue_repository_scan_source` | 传递字段、写入 task input |
| Scanner | `lima/repository_scanner.py` 平台分支 | 读 task 级模式替代全局 settings |
| 配置 | `lima/config.py` | 新增 `LIMA_CXX_PLATFORM_DEFAULT`（默认 `off`） |
| capabilities | `lima/service.py:960-1004` | 声明 `per_request_switch` / `llm_configured` |
| 前端 | 提交表单开关 + 计费确认弹窗 + PlatformCard | 参照外部评测交互与 UafV2Card |
| 契约文档 | #125 遗留的 capabilities 契约文档重落 | 与本契约一并落库 |

## 8. 测试要求

1. API 层：`agent_detection` 类型校验（非 bool → 400）；未配 LLM + `true` → 400 `agent-detection-unavailable`；
2. 隔离性：per-request 覆盖只影响本任务，不污染后续任务与服务端默认；
3. 端到端：fake LLM 走通「提交（带开关）→ 轮询 → 报告 → UafV2Card + PlatformCard」；
4. 回归：`agent_detection` 缺省时行为与现状完全一致（零行为变化断言）。

## 9. 边界与非目标

- 不暴露 legacy 链与 `required` 模式；
- 不新增授权体系（决策 1）；
- 不修改 Sidecar 四接口（`/v1/analyze`、`/v1/uaf-facts`、`/v1/repro`、`/health`）——本契约只涉及主服务层；
- 修复预览 / Draft PR 不适用于 C++ findings（`automatic_repair=false`）。
