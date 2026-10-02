# 前端接入 C++ 智能体检测：建议提交的 issue

2026-10-02 状态核对：当前分支 `7938bbf` 已提交前端部分，后端配套尚不在当前
checkout 中；完整交付未验收。现有接口和待配套契约见
[前端接口与文档索引](../../FRONTEND_API.md)。以下 Problem / Proposed solution
保留 issue 创建时的背景与计划，不作为已完成状态清单。

依据：[前端智能体检测接口方案](2026-09-28-frontend-agent-detection.md)。以下四项已于 2026-09-30 在 GitHub 创建：[#243](https://github.com/agent-sec-labs/LIMA/issues/243)、[#244](https://github.com/agent-sec-labs/LIMA/issues/244)、[#245](https://github.com/agent-sec-labs/LIMA/issues/245)、[#246](https://github.com/agent-sec-labs/LIMA/issues/246)。

## 初稿分组

1. 后端支持按任务开启智能体检测。
2. 报告保存智能体审计详情。
3. 扫描表单增加开关和调用确认。
4. 任务详情展示结果、进度，并修正修复预览入口。

## 文案检查

- 初稿只写了组件名称，看不出现在为什么不能用。最终版补上当前行为和用户会遇到的问题。
- "费用预估"容易被理解成金额报价。最终版只承诺展示模型调用次数上限。
- 单列端到端测试会产生一张没有独立用户结果的票。最终版把它放进第 4 项的验收条件。
- #166 是 C++ 检测链的既有跟踪项，#70 和 #91 属于 V5 全链路改造。新票与它们建立关联，但不重复承诺其范围。

建议按第 1 项、第 2 项、第 3 项、第 4 项的顺序集成。第 2 项和第 3 项可以在后端接口固定后并行开发；第 4 项依赖前面三项。`lima/service.py`、`lima/api.py`、`lima/task_progress.py` 与 #91 的文件边界重叠，`frontend/src/shared/api/types.ts`、`client.ts`、`TaskDetailPage.tsx` 与 #70 重叠。当前旧任务报告可以保留有界详情；#70 的 V5 页面默认只消费摘要，PoC 和日志必须有受权限控制的按需读取契约。#91 应把任务级 C++ 模式映射到 Audit 内部，不改变 `FULL_CHAIN` 默认入口或擅自启动 Mining/Repair。开始实施前确认 #70/#91 是否已激活，并为重叠文件指定单一集成负责人。

## 已创建的 issue

### Issue 1（#243）：仓库扫描支持按任务启用 C++ 智能体检测

**标题**：`[Feature]: 仓库扫描支持按任务启用 C++ 智能体检测`

**Problem to solve**

`POST /v1/repository-scans` 目前忽略 `agent_detection`。Service 在启动时固定 scanner 的模式和依赖，默认 `off` 时无法让某一次扫描单独运行平台链；改动共享 scanner 的字段还会让并发任务串扰。

**Proposed solution**

在本地 `repository_key` 和 GitHub `source` 两种请求中接受可选布尔字段。未传时沿用服务端默认，`true` 为本次启用，`false` 为本次关闭；全局 `required` 时拒绝 `false`。入队时保存原始选择和 `effective_cxx_agent_mode`，worker 与重试都使用这份快照，通过任务局部参数运行 scanner。预算和 LLM 工厂按服务端配置装配，不依赖启动时的全局模式。capabilities 增加 `per_request_switch`、`llm_configured`、`analyzer_configured`、`max_agent_calls`。具名 400 同时返回 `error` 和稳定的 `code`，分别使用 `agent-detection-required`、`agent-detection-unavailable`、`agent-detection-analyzer-unavailable`。平台链开始时写入 `PLATFORM_ANALYSIS` 进度事件。

**Evidence and evaluation**

- 覆盖 off/auto/required 与未传/true/false 的模式矩阵；`"yes"`、`1`、`null` 返回 400 且不入队。
- 全局 off、本次 true 能真正调用 fake LLM；全局 auto、本次 false 不调用模型。并发任务互不影响，重试仍用入队时的模式。
- 本地和 GitHub 来源得到相同的开关行为；进度轮询可看到 `PLATFORM_ANALYSIS`。旧客户端未传字段时行为保持原样。

**Security and operational risks**

继续使用现有 `manage` 权限。客户端不能指定模型、端点或预算；配置检查不等于远端健康检查。保留原有 `error` 字段，避免旧客户端失去错误说明。

**Primary scope**：Agent/runtime architecture

**关系**：关联 #166。与 #91 的 API、service 和进度文件重叠，实施前确认排期。

### Issue 2（#244）：报告保存有界的智能体审计详情

**标题**：`[Feature]: 在平台报告中保存可下钻的目标审计详情`

**Problem to solve**

`collaboration.platform.targets` 目前只保留前 32 个目标的摘要。运行时虽然有假设、PoC driver 和实验日志，任务完成后前端无法从报告中展示这些证据。

**Proposed solution**

在现有目标摘要中增加可选的 `hypothesis_reason`、`poc_driver_code`、`experiment_log` 和 `detail_omissions`。证明结论继续使用已有的 `proof`，不再增加同义字段。自由文本先脱敏，再按 UTF-8 字节计量：单目标假设最多 2 KiB，PoC driver 最多 32 KiB，日志保留最后 8 轮，新增详情总计不超过 256 KiB。超限时省略整项，用 `字段名:too-large`、`字段名:budget-exhausted` 或 `experiment_log:older-rounds-omitted` 记录原因。优先保留正向 finding 的详情；既有摘要和 `v4` 载荷预算不受影响。

**Evidence and evaluation**

- 用包含 33 个目标、超长 PoC、超长假设和多轮实验的 fixture 验证排序、数量与预算。
- 报告中没有未脱敏的凭据；缺失详情时能区分未记录、单项过大和总预算耗尽。
- 旧字段 `proof`、`experiments`、`rejected_reason` 及无目标、disabled、失败状态的报告保持兼容。

**Security and operational risks**

PoC 是不可信代码。报告渲染链只处理脱敏后的展示副本，不执行它，也不声称脱敏副本可以直接复现漏洞；原有受控复现工作台的执行行为不在本 Issue 中变更。详情预算不能挤占已有 `v4` 预算。与 #70 的按需加载要求合并前须统一契约。

**Primary scope**：Audit and vulnerability detection

**关系**：依赖 #243 固定任务级模式与报告路径。`repository_scanner.py` 与 #243 有文件重叠，顺序合并。

### Issue 3（#245）：扫描表单提供智能体检测开关与提交确认

**标题**：`[Feature]: 仓库扫描表单提供 C++ 智能体检测开关`

**Problem to solve**

现有表单能提交本地仓库和 GitHub 仓库，但不能选择是否运行 C++ 智能体链。若服务端默认是 `auto`，只把一个默认关闭的开关加到页面上仍会误导用户：不传字段会继承 `auto`，可能在未确认调用费用的情况下运行模型。

**Proposed solution**

给仓库扫描草稿增加布尔选择，并根据 capabilities 初始化：off 为关闭，auto 为开启，required 为锁定开启。新前端始终向两种仓库来源显式提交 `true` 或 `false`；PR/diff 审查不带该字段。启用时在最终提交前确认模型可能接收代码上下文、可能产生调用费用，并显示 `max_agent_calls` 的调用次数上限。capabilities 加载失败或缺少新字段时暂停仓库提交并提供重试。后端返回具名 400 时保留草稿并刷新 capabilities。

**Evidence and evaluation**

- 默认 off/auto/required、用户改动草稿后 capabilities 才返回、页面返回再进入等场景保持正确状态。
- 确认框取消后没有请求；确认后本地与 GitHub 请求体都带 `agent_detection:true`。关闭默认 auto 时提交 `false`，不弹调用确认。
- 缺模型或分析器时不能从 off 开启；PR/diff 表单行为不变。

**Security and operational risks**

前端提示不是授权门禁，后端仍执行 `manage` 权限和请求校验。`max_agent_calls` 是调用次数上限，不是金额报价。不要把模型配置、密钥或代码写入浏览器持久存储。

**Primary scope**：Frontend and product experience

**关系**：依赖 #243 的请求与 capabilities 契约。与 #70 的前端共享文件重叠，实施前确认排期。

### Issue 4（#246）：任务详情展示平台结果并完成端到端验收

**标题**：`[Feature]: 任务详情展示 C++ 智能体检测结果和阶段`

**Problem to solve**

任务详情目前没有平台链审计卡片。平台链运行时进度会停留在上一个分析阶段；只有 C++ finding 的仓库报告也会显示"生成修复预览"，点击后只能得到无修复结果。

**Proposed solution**

在现有任务详情页沿用任务轮询和 `StageTimeline`，增加 `PLATFORM_ANALYSIS` 标签。新增 PlatformCard，展示平台状态、统计、前 32 个目标摘要和可选详情。无 `platform` 的旧报告及 disabled 状态不显示空卡片；不可用或失败状态显示原因。PoC 只作为文本展示。#70 的 V5 页面只默认读取摘要，PoC 和日志须按权限、按需获取，不直接复用此页的详情读取方式。修复预览按钮仅在本地报告存在 `.py` finding、CWE 为 22/78/89 且 `automatic_repair !== false` 时显示；混合报告仍可预览合格的 Python finding。不修改后端修复算法。

**Evidence and evaluation**

- 组件测试覆盖旧报告、disabled、no-cxx-sources、失败、详情被省略、长路径和混合 finding。
- fake LLM 与 fake GitHub materializer 分别走通本地和 GitHub 提交：确认、202、平台进度、SUCCESS、`collaboration.platform` 与 finding 的 `verification_state`。关闭开关时没有模型调用。
- 真实 Sidecar/模型可用时再做一次现场验证，记录运行状态及失败提示；fake 测试不代替健康性验证。

**Security and operational risks**

前端不执行 PoC，不把 PoC 或源码写入 localStorage、URL 或日志。页面不根据空统计推断仓库安全，也不把 `max_agent_calls` 显示为货币费用。

**Primary scope**：Frontend and product experience

**关系**：依赖 #243、#244、#245。与 #70 的 `TaskDetailPage.tsx` 和共享 API 类型重叠，实施前确认排期。

四项都可关联同一份方案。第 4 项承担组合验收，因此无需再开一张只有"跑通 E2E"内容的 issue。#185 处理 CWE 类别扩展，本组 issue 不重复该范围。

## 已发布到现有 issue 的兼容说明

以下两段已于 2026-09-30 发布，并核对了远端正文：[参见 #70 评论](https://github.com/agent-sec-labs/LIMA/issues/70#issuecomment-5905442823)、[参见 #91 评论](https://github.com/agent-sec-labs/LIMA/issues/91#issuecomment-5905454566)。GitHub 集成写入返回 403，本次使用本机 Git Credential Manager 中的凭据调用 GitHub REST API；本文档不保存 token。

评论初稿只说“和 C++ 检测接入保持兼容”，没有指出接口边界。检查后把旧任务与 V5 的读取方式、任务级模式映射和共享文件排期写清楚，避免让实施者猜测“兼容”的含义。

### #70：V5 Issue-centric 前端

> C++ 智能体检测会先接入现有 `/v1/repository-scans` 与旧任务详情页。旧任务报告计划保存有界、脱敏的目标详情，供旧页面展示。
>
> V5 Issue-centric 页面仍按 #70 的约定默认只取摘要。PoC driver 和实验日志不要随列表或默认详情响应返回；需要查看时，再走有权限校验的按需读取接口。旧报告中的展示副本不能直接当作 V5 默认读模型，也不应写入浏览器持久存储。
>
> 新接入将涉及 `frontend/src/shared/api/types.ts`、`client.ts`、`TaskDetailPage.tsx`。这些文件与 #70 重叠，开工前请确认合并顺序和单一集成负责人。

### #91：V5 FULL_CHAIN 集成

> C++ 智能体检测会先作为现有 `/v1/repository-scans` 的任务级选项接入。`agent_detection` 未传时继续使用服务端默认模式；入队后保存 `effective_cxx_agent_mode`，worker 和重试使用同一份任务快照。
>
> #91 将旧扫描 API 接入 `FULL_CHAIN` 时，请把该模式映射到 Audit 内部的 C++ 检测配置。`PLATFORM_ANALYSIS` 是 Audit 内部的进度阶段，不是新的工作流终态。用户开启 C++ 检测也不等于要求启动 Mining 或 Repair；`FULL_CHAIN` 的默认入口与阶段边界仍以 #91 为准。
>
> 新接入将涉及 `lima/service.py`、`lima/api.py`、`lima/task_progress.py`。这些文件与 #91 重叠，开工前请确认合并顺序和单一集成负责人。
