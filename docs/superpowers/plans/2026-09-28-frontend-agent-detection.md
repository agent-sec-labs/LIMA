# 前端智能体检测接口方案

日期：2026-09-28
核对基线：2026-09-29 当前工作区 `chore/c01-registry-vocabulary`（含 PR #225 退役与 C0.1 注册表化）；实施前复核目标分支
状态：接口方案已按现有代码修订，待实施

2026-10-02 交付核对：`feat/frontend-agent-detection-api` 的 `7938bbf` 已提交前端部分，
当前 checkout 尚不包含本文 §3 的后端配套实现。当前接口与差距以
[前端接口与文档索引](../../FRONTEND_API.md) 为准；下文保留设计及验收要求，
不能将方案中的示例响应视作当前服务端输出。

## 1. 目标

让前端用户通过现有仓库扫描流程按需开启 C++ 智能体检测链。不新开端点、不改任务生命周期、不改轮询机制。管理员配置服务端模型、Sidecar 与默认模式；用户在扫描表单里看到本次任务的实际默认状态，启用时确认可能产生的模型调用，再到任务中心查看进度与结果。

## 2. 已冻结的设计决策

2026-09-25 与维护者确认三项：

| # | 决策 | 结论 |
|---|---|---|
| 1 | 费用授权 | 不新增授权体系。仅 manage 权限可提交（现有门槛）；本次启用智能体检测时，提交前弹一次模型调用确认，包括默认已启用的情况 |
| 2 | 前端粒度 | 只暴露"智能体检测"一个开关，内部映射平台链；required 模式不暴露 |
| 3 | GitHub source | 与 repository_key 一视同仁，来源层控制用现有 LIMA_REPOSITORY_SCAN_SOURCES |

## 3. 后端改动

### 3.1 API 层（lima/api.py）

`POST /v1/repository-scans` 请求体新增可选布尔字段。它与本地 `repository_key`、已有 GitHub `source` 两种来源都兼容，且只影响仓库扫描，不扩展到 PR/diff 审查：

```json
{
  "repository_key": "team/project",
  "agent_detection": true
}
```

GitHub 请求示例：`{"source":{"type":"github","url":"https://github.com/team/project","ref":"main"},"agent_detection":true}`。

| 请求值 | 服务端 `cxx_agent_mode=off` | `auto` | `required` |
|---|---|---|---|
| 不传（旧客户端） | off | auto | required |
| `true` | auto | auto | required |
| `false` | off | off | 400 `agent-detection-required` |

这样旧客户端保持原有默认行为；新前端对两种仓库来源都显式提交布尔值，关闭开关不会意外继承管理员的 `auto` 默认。`required` 是服务端策略，前端不提供这一模式选项；该模式下开关显示为开启且不可关闭，提交前仍显示模型调用确认。

校验与错误响应：

- 非 bool（含字符串、数字、`null`）返回 400；不把 `1` 当作 `true`。
- 显式 `true` 且 `resolved_llm()` 为空：400 `agent-detection-unavailable`；显式 `true` 且 `cxx_memory_mode=off` 或未装配事实分析器：400 `agent-detection-analyzer-unavailable`。不传字段的旧客户端继续沿用原有 auto 降级语义。配置检查不声称远端模型或 Sidecar 此刻健康；运行时故障仍由任务状态与 `collaboration.platform.status` 表达。
- 这三种具名 400 在现有 `{"error":"..."}` 基础上增加稳定的 `code` 字段，保留 `error` 供旧客户端读取。前端 API 客户端解析并保留 `code`，用于准确提示和刷新 capabilities；普通 `ValueError` 的既有响应格式保持不变。

### 3.2 Service 层（lima/service.py）

- 两个入队入口都接受 `agent_detection`，在入队时解析一次有效模式，将原始选择（未传为 `null`）与 `effective_cxx_agent_mode` 一起写入持久化 task input；队列重试沿用该快照，不重新套用后来的全局设置。
- worker 从 task input 读取有效模式，并以任务局部参数传入 `RepositoryScanner.scan()` / 平台分支；禁止临时改写共享 `self.repository_scanner.cxx_agent_mode`。预算工厂和 LLM 工厂应按服务端配置装配，不能再因启动时全局模式为 off 而缺席，否则“全局 off、本次 true”仍无法运行。模型、提示词、预算仍只由管理员设置决定。
- 保持 `RepositoryScanner.__init__` 的现有默认模式，以兼容直接调用 scanner 的旧路径；service 显式传任务模式。对两个并发任务分别使用 auto/off 做隔离测试。
- `GET /api/repository-scans/capabilities` 的 `cxx_agent` 节点保留现有字段，新增：

```json
{
  "per_request_switch": true,
  "llm_configured": true,
  "analyzer_configured": true,
  "max_agent_calls": 40
}
```

`mode` 表示服务端默认模式；`per_request_switch` 在 `required` 时为 `false`，其他模式为 `true`。`llm_configured` 仅表示 `resolved_llm()` 非空，`analyzer_configured` 以实际 adapter 的 `analyze_uaf_facts` 能力为准，两者都不是健康探测。现有 `configured` / `repository_scan` 原本依赖全局 mode，不能拿来判断“本次从 off 开启”是否可用；前端使用新增字段门禁。`max_agent_calls` 来自 `settings.cxx_agent_max_calls`，文案写“最多 N 次模型调用”，不把调用次数冒充货币费用估算。

### 3.3 任务进度透出

`GET /v1/tasks/{id}` 已返回持久化的 `progress`，`TaskDetailPage` 已通过轮询展示阶段列表和进度条。本方案不重建这两部分。缺口是平台链运行时没有独立事件，页面可能长时间停在 `SAST_ANALYSIS`。

在 `task_progress.py` 的阶段顺序中加入 `PLATFORM_ANALYSIS`（位于 `SAST_ANALYSIS` 与 `SEMANTIC_TRIAGE` 之间），在真正进入平台链前发出“正在进行 C++ 智能体检测”。同步更新前端 `TaskStage` 与阶段标签。第一版只保证当前阶段可见，不承诺 target/实验轮次、百分比或耗时预测；关闭或无 C++ 来源时跳过此阶段。继续使用现有任务轮询，不增加 WebSocket/SSE。

### 3.4 报告载荷（lima/repository_scanner.py）

当前 `collaboration.platform.targets` 只有前 32 个目标的摘要：`target_id`、`path`、`line`、`state`、`cwe`、`proof`、`experiments`、`rejected_reason`。运行时的假设、PoC driver 和逐轮日志尚未持久化，前端不能凭现有报告下钻。

为保留“无需额外 API”的设计，在这 32 条摘要上添加**可选且有界的展示字段**：`hypothesis_reason`、`poc_driver_code`、`experiment_log`、`detail_omissions`（省略原因代码数组）。`proof` 沿用现有键名，不再另造 `proof_verdict`；`experiments` 仍是总轮数，日志可因边界只显示部分。每个日志 entry 只选择 `round`、`stage`、`exit_code`、`error_type`、`faulting_line`、`hit` 等已验证字段。自由文本先经过现有隐私脱敏，再按 UTF-8 字节预算入报告：单目标假设最多 2 KiB、PoC driver 最多 32 KiB、日志保留最后 8 轮，新增详情总计最多 256 KiB。详情预算按“正向 finding 优先、再按 `target_id`”确定性分配，但摘要顺序保持原样。单项超限或总预算耗尽时省略整项，在 `detail_omissions` 中写入 `字段名:too-large` 或 `字段名:budget-exhausted`；日志省略较早轮次时写入 `experiment_log:older-rounds-omitted`。不能展示被截断为不可运行代码的 PoC；既有 `v4` 载荷预算不受影响。`poc_driver_code` 是脱敏后的审计展示副本，前端仅以文本渲染，不执行，也不把它标成可直接复现的完整 PoC。

扩展后的单条目标示例（仅示意字段；缺失的可选字段不代表实验未发生）：

```json
{
  "target_id": "target-1",
  "path": "src/example.cpp",
  "line": 42,
  "state": "runtime-confirmed",
  "cwe": "CWE-416",
  "proof": "PASS",
  "experiments": 1,
  "rejected_reason": "",
  "hypothesis_reason": "释放后再次使用对象",
  "poc_driver_code": "int main() { int *p = new int(1); delete p; return *p; }",
  "experiment_log": [{"round": 1, "stage": "run", "exit_code": 1, "error_type": "heap-use-after-free", "faulting_line": 42, "hit": true}],
  "detail_omissions": []
}
```

## 4. 前端改动

### 4.1 类型与提交载荷

`frontend/src/shared/api/types.ts` 当前没有 `RepositoryScanRequest` / `CxxAgentCapabilities` 类型；`frontend/src/features/audit-create/model.ts` 的 `buildSubmitPayload()` 才是实际请求构造点。在两处同步补齐，不只声明一个未被调用的接口。

```typescript
type RepositoryScanRequest =
  | { repository_key: string; source?: never; agent_detection: boolean }
  | { source: { type: "github"; url: string; ref?: string }; repository_key?: never; agent_detection: boolean };
```

`buildSubmitPayload()` 只在仓库模式的本地与 GitHub 分支增加 `agent_detection`；PR/diff 分支不增加此字段。新前端总是显式提交 `true` 或 `false`，API 的“可选”仅为兼容旧客户端。

### 4.2 扫描表单（frontend/src/features/audit-create/）

在 `AuditDraft`、Zod 校验及草稿缓存中新增 `agentDetection: boolean`，仅在仓库模式显示一个“智能体检测”开关。已有 GitHub 来源表单直接复用这个开关。

- capabilities 加载成功后，用 `cxx_agent.mode !== "off"` 初始化尚未由用户修改的开关；草稿中已明确修改的选择不被异步响应覆盖。`required` 时保持开启、不可关闭，并说明这是服务端策略。capabilities 加载失败时，仓库提交暂停并提供重试，避免在未知默认模式下绕过确认；PR/diff 审查不受影响。
- `llm_configured` 或 `analyzer_configured` 为 false 时，禁止用户从 off 开启；如果默认已开启，也暂停提交并提示管理员修复配置。`per_request_switch` 控制能否切换；这些字段不代表服务健康，最终以后端受理为准。
- 在“确认范围”页点“开始安全审计”时，如果本次有效开关为开启，先弹一次确认框，说明配置的模型可能接收代码上下文、可能产生调用费用，并显示“最多 N 次模型调用”。取消则不提交；确认后才发送 202 请求。关闭时直接提交 `false`。即使开启状态来自管理员默认值，也必须确认。
- 提交遇到具名 400 时保留草稿、显示对应提示并刷新 capabilities；不要把失败误当成已创建任务。

### 4.3 结果展示（frontend/src/features/tasks/TaskDetailPage.tsx）

现有 `UafV2Card` 已渲染 UAF v2 审计块。新增 `PlatformCard` 展示 `collaboration.platform` 载荷：

- 基本统计：线索数、目标数、finding 数、实验数，以及 `scout_calls + specialist_calls + critic_calls` 的模型调用数
- 目标审计表（前 32 个）：target_id、path:line、状态、CWE、实验次数、证明结论
- findings 列表已按 verification_state 标注（现有行为）
- 旧报告无 `platform` 时不渲染；新报告即使关闭平台链也会有 `{mode:"off",status:"disabled"}`，此时不显示空卡片。其他非完成状态（如 `no-cxx-sources`、`analyzer-not-configured`、`llm-not-configured`）显示真实状态，不展示虚假的零发现结论。

### 4.4 目标审计细节下钻

PlatformCard 的目标审计表中每条 target 可展开，按报告中实际可用的字段展示：

- **假设描述**：可选 `hypothesis_reason`
- **PoC driver 展示副本**：可选 `poc_driver_code`，只作为文本/代码块渲染，不执行；脱敏后的代码不承诺可直接编译复现
- **实验日志**：可选 `experiment_log` 数组，展示后端保留的轮次与 stage、exit_code、error_type、faulting_line、hit
- **证明结论**：现有 `proof` 字段（PASS/REFUTED/空）
- **拒绝理由**：非正向状态的 `rejected_reason` 字段

数据来自扩展后的 `collaboration.platform.targets`，不额外调用 API。详情因预算缺失时显示 `detail_omissions`，不把缺失字段误读成“无实验”或“无假设”。

### 4.5 任务进度展示

沿用现有 `StageTimeline`、`detailRefetchInterval` 和任务列表进度展示；只增加 `PLATFORM_ANALYSIS` 的类型与中文标签。阶段结束或任务失败、取消时遵循现有轮询与终态展示逻辑，不增加第二套进度组件。

### 4.6 capabilities 类型

```typescript
interface CxxAgentCapabilities {
  mode: "off" | "auto" | "required";
  repository_scan: boolean;
  pull_request_scan: boolean;
  per_request_switch: boolean;
  llm_configured: boolean;
  analyzer_configured: boolean;
  max_agent_calls: number; // 调用次数上限，不是货币费用
  configured: boolean;
  automatic_repair: boolean;
}
```

将其接入现有 `ScanCapabilitiesPayload`。旧服务端缺少新增字段时关闭按需开启入口并提示需要更新服务端，不根据旧 `configured` 值猜测可用性。

### 4.7 修复预览入口

现有报告页只要是仓库任务且有 finding 就显示“生成修复预览”，与 C++ finding 的 `automatic_repair=false` 不一致。调整**按钮可见性**，仅当本地导入报告中存在后端预览器支持的 Python finding（当前 `CWE-22/78/89`，且 `automatic_repair !== false`）时显示；混合报告仍可对符合条件的 finding 预览。后端修复预览与 Draft PR 实现保持原样，其校验仍是最终门禁。

## 5. 测试策略

### 5.1 后端单元测试

| 场景 | 断言 |
|---|---|
| 字段不传，默认 off/auto/required | 分别快照 off/auto/required；旧客户端行为不变 |
| `true`，全局 off | 任务 mode 为 auto，真实预算/LLM 工厂可用；后续任务不受影响 |
| `false`，全局 auto | 本次为 off，后续任务仍按 auto；不产生平台模型调用 |
| `false`，全局 required | 400，`code=agent-detection-required` |
| `"yes"`、`1`、`null` | 400，不创建任务 |
| 显式 `true` + 无 LLM / memory=off | 对应 `agent-detection-unavailable` / `agent-detection-analyzer-unavailable`，同时保留 `error` 文本 |
| 本地 `repository_key` 与 GitHub `source` | 相同的开关、入队快照和 worker 行为 |
| 两任务并发 auto/off、任务重试 | 模式互不串扰，重试仍使用入队时的有效模式 |
| capabilities | mode、per_request_switch、llm_configured、analyzer_configured、max_agent_calls 与设置一致；不假装已做健康探测 |
| 平台进度 | 实际运行时出现 `PLATFORM_ANALYSIS`；终态和失败仍沿用现有 progress 契约 |
| 平台报告 | off 仍可保存 disabled 摘要；开启时前 32 条目标详情可选且脱敏、字节预算有效、超限原因可见；旧字段 `proof` 保持 |

### 5.2 前端测试

| 场景 | 断言 |
|---|---|
| 默认 off / auto / required | 分别显示关闭 / 开启 / 锁定开启；开启状态提交前均需确认 |
| capabilities 未加载、失败或字段缺失 | 不盲提仓库扫描；显示重试/更新提示，PR/diff 流程不受影响 |
| 用户关闭默认 auto | 本地与 GitHub 提交体均带 `agent_detection:false`，不弹调用确认 |
| 用户开启默认 off | 最终提交前弹确认，显示调用上限与可能费用；取消不发送请求，确认后带 `true` |
| 缺模型或分析器 | 从 off 开启不可用，提示原因；后端具名 400 保留草稿并刷新 capabilities |
| 旧报告无 platform 或新报告 disabled | PlatformCard 不渲染；其他非完成状态显示状态提示 |
| target 展开与详情超限 | 有界的假设、PoC 展示副本、日志和现有 `proof` 正确显示；缺失时显示原因，不渲染可执行内容 |
| EXECUTING 平台阶段 | 复用现有时间线显示 `PLATFORM_ANALYSIS`，无重复进度组件 |
| 只有 C++ finding / 混合报告 | 前者不显示修复预览按钮；后者有合格 Python finding 时仍显示 |

### 5.3 端到端

在启用 Sidecar 事实分析器的测试环境中用 fake LLM 与 fake GitHub materializer 走通本地与 GitHub 两种来源：确认 → 提交 `agent_detection:true` → 202 → 轮询看见 `PLATFORM_ANALYSIS` → SUCCESS → 报告含非 disabled 的 `collaboration.platform`，finding 带 `verification_state`。另测 `false` 不调用模型、启用但无 C++ 来源时返回真实 `no-cxx-sources` 状态。真实模型与真实 Sidecar 的在线健康性不由 fake 测试宣称。

## 6. 实施顺序

1. 后端请求校验、模式解析与 task input 快照；落实任务局部 scanner 模式和启动时 off 的依赖装配；完成双来源、并发、重试测试。
2. 后端 capabilities、具名 400、`PLATFORM_ANALYSIS` 事件与有界报告详情；完成契约、隐私和字节预算测试。
3. 前端类型、草稿/提交载荷、capabilities 门禁与提交前确认；覆盖默认 auto/required 和 GitHub 来源。
4. 前端 PlatformCard、可选详情、阶段标签与修复预览按钮门禁；覆盖旧报告和非完成状态。
5. fake LLM 端到端、前后端回归，再在可用的真实 Sidecar/模型环境验证健康与失败提示。

建议按后端契约与前端消费拆为两个 PR，前端 PR 以已合并的后端契约为基础。原“约 3 天”没有覆盖报告详情、并发隔离和回归环境，实施前按测试夹具与运行环境重新估时。

## 7. 非目标

- 不暴露 required 模式
- 不新增授权体系
- 不修改 Sidecar 四接口（/v1/analyze、/v1/uaf-facts、/v1/repro、/health）
- 不修改后端修复预览算法或 Draft PR 流程；只修正前端按钮可见性，C++ finding 仍为 `automatic_repair=false`
- 不做 PR/diff 审查接入（backlog，等后续需求明确）
- 不重做已有的 GitHub source 输入表单；只为现有 GitHub 提交体增加同一个开关
- 不做流式实时进度（第一版只做阶段标签，不做 WebSocket/SSE）

## 8. 与 V5 全链路的衔接

本方案先接入现有 `/v1/repository-scans` 和任务详情页，属于当前仓库扫描路径。它不改变 #91 规划的新 `FULL_CHAIN` 默认入口，也不把“启用 C++ 智能体检测”解释成自动启动 Mining 或 Repair。#91 接入旧 API 时，应把已持久化的 `effective_cxx_agent_mode` 映射到 Audit 阶段的 C++ 检测配置；`PLATFORM_ANALYSIS` 是 Audit 内部阶段，不是新的工作流终态。未传 `agent_detection` 的旧请求继续遵循服务端默认模式。

当前版本按第 3.4 节在旧任务报告里保留有界、脱敏的 PoC/实验展示副本。#70 的 Issue-centric 页面要求默认只加载摘要，PoC 和日志按权限、按需获取。因此 V5 读模型不得把旧报告中的详情直接并入默认列表或详情响应；应先确定受权限控制的按需读取契约，再把目标审计摘要映射到 V5 视图。迁移期间旧报告仍可由旧任务详情页读取，前端不持久化 PoC 或源码。#70、#91 开始修改共享文件前，需确认合并顺序与单一集成负责人。
