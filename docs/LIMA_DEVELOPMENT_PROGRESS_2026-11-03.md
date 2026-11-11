# LIMA 开发进度（2026-11-03）

核对基线：远端 `main`，提交 `e50ad5f67a9eb82c7ca907996d73f93fdd62e9fe`（合并 PR #350）。依据为已合并代码、GitHub Issue 当前状态、Build Agent 计划及本轮复审记录；本次没有重新运行真实仓库试点。

## 总体判断

LIMA 已有仓库审计、证据报告、受限 Python 修复和 C/C++ 智能体分析基础。最近一轮开发重点是 Build Agent：隔离构建、策略与工具、Agent 状态机、上下文包校验、三方消费接口、服务调度及前端展示均已合入 main。

当前阶段是“基础实现已落地，部署消费与真实试点待收尾”。尚不能称为“用户提交任意仓库即可自动构建、检测、PoC、修复的完整闭环”。首期范围仍是指定组件的 Linux/CMake analysis-context，不是整仓编译、测试和安装，也不包含 OpenHarmony GN/hb 自动构建。

## 最近已合并的开发切片

| 切片 | Issue / PR | 已落地内容 | 当前判断 |
|---|---|---|---|
| S1 | #336 / #343 | 共享容器执行原语、隔离构建执行器、资源与取消控制 | 实现已合入 |
| S2 | #337 / #344 | 请求/计划/结果契约、策略校验、受控构建工具 | 实现已合入 |
| S3 | #338 / #345 | Build Agent 规划、有界修订与预算控制 | 实现已合入 |
| S4A | #339 / #346 | 产物完整性与快照绑定校验、只读分析视图 | 实现已合入 |
| S4B | #340 / #347 | facts、repro、Specialist 的统一 TU 上下文消费代码 | 实现已合入；受部署能力限制 |
| S5 | #341 / #348 | 服务端调度、off/auto/required、持久化、前端构建状态 | 实现已合入 |
| S6 夹具部分 | #342 / #349 | CMake 夹具、真实包与 resolver 交接、安全负例、编译器检查及说明 | 夹具部分完成，不能代表真实全链验收 |
| 消费接线补齐 | #350 | service → scanner → orchestrator 传递、统一能力门控、required 阻断、消费标记 | 已合入；标准 HTTP Sidecar 仍未实现包交付 |

此前 #334 已提供人工容器完整构建入口；它与审计任务中的自动 Build Agent 是不同入口。此前 #316–#332 中的覆盖统计、运行摘要、环境记录、报告材料、preflight 和部署修复也已进入主线；这些工程产物不自动证明赛题漏洞案例已验收。

## #350 合并后的实际行为

构建成功后，service 加载并验证上下文包，构造分析视图。只有分析器适配器声明支持 verified package 时，才允许交给相关检测阶段。

- 支持消费时：facts、Specialist 契约与复现 digest 使用同一视图；最终消费标记还要求平台完成且摘要为 `verified-package`。
- 标准独立 HTTP Sidecar：当前没有跨进程包传输/注册通道，也未声明支持，因此本地视图构造成功不等于远端可消费。
- service 的 auto 模式：记录 `verified-context-not-consumable`，清除视图、关闭依赖上下文的平台阶段，继续其余扫描；不是完整 C++ 智能体流程继续执行。
- service 的 required 模式：同样关闭该依赖阶段，并标记 `blocking=true`、`consumed_by_analysis=false`。
- 直接调用 orchestrator 的默认上下文路径：能力不足时三方一起回退，避免混用构建参数。

因此，这次合并完成了接线与安全门控，但没有完成标准跨进程部署上的真实构建上下文消费。

## 验证证据与局限

- PR #350 当前 head `1eb067b` 的 CI run [41567694071](https://github.com/agent-sec-labs/LIMA/actions/runs/41567694071) 已全部通过：12/12。包含 Windows/Linux Python 3.11/3.12、Sidecar 集成、只读容器、前端及 E2E 等检查。
- 上轮独立快照复审执行八个相关测试模块：238 passed、1 skipped。
- 新增测试执行三方编排循环，但分析器、模型传输及复现工作台使用替身；真实 sealed view 不等于真实部署端到端。
- #349 的构建夹具使用 fake executor；有真实编译器的 TU 检查不能替代真实 Docker 构建、远端消费及隔离 PoC 全链。
- 上述 CI 是 PR head 的验证，不另行宣称合并提交已重新执行完整验收。

## 尚缺的关键交付

| 优先顺序 | 工作 | 验收终点 |
|---|---|---|
| 1 | 标准 Sidecar 的跨进程上下文交付 | Sidecar 校验包与 snapshot/artifact 身份并确认可消费；未确认时保持降级/阻断 |
| 2 | API 到报告的真实小夹具全链 | 真实任务入队 → Build Agent/容器 → 包交付 → facts/Specialist/repro → 新隔离容器 PoC → 报告，保留证据 |
| 3 | 冻结一个真实仓库组件试点 | 固定 commit、TU、镜像/依赖/预算，记录 compdb 条目、TU 可解析率、Clang 结果、人工介入、耗时与费用 |
| 4 | 补齐正负对照与功能回归 | 若采用已知漏洞：脆弱版同一 PoC 3/3、修复版 0/3，并验证正常功能；无发现不等于安全 |
| 5 | 更新状态与说明 | 文档、Epic、Issue 与实际能力一致，明确实现完成和验收完成的区别 |

建议先以小夹具打通真实跨进程链路，再做 ResInsight 等冻结组件试点。首期不同时扩张到 GN/hb、任意 Dockerfile 或通用整仓构建平台。

## Issue 与文档需要同步的地方

- [#335 Build Agent Epic](https://github.com/agent-sec-labs/LIMA/issues/335) 仍开放，S1–S6 清单全部未勾选，但 #336–#342 已关闭。应更新各层实现状态；真实消费与试点完成前不宜仅因子项关闭就关闭 Epic。
- [#342](https://github.com/agent-sec-labs/LIMA/issues/342) 当前是 closed/completed，但正文要求真实试点及完整消费/PoC。已合并测试能支持夹具部分，不能覆盖全部验收；建议重开该 Issue，或新建明确关联的剩余验收 Issue 并说明原项只完成夹具切片。
- `docs/BUILD_AGENT_USER_FLOW.md` 仍写“截至 S5”“扫描器没有接入视图”等旧状态；应更新为 #350 的实际能力门控及跨进程缺口。#350 PR 正文也保留“构造视图即消费”的早期描述。
- [#181](https://github.com/agent-sec-labs/LIMA/issues/181)、[#182](https://github.com/agent-sec-labs/LIMA/issues/182) 仍开放。两层架构已有大量基础实现，但 FileInterface 115 TU、OH 构建接入以及大仓库预算回归仍需逐项留证，不能随 #350 自动视为完成。
- [#165](https://github.com/agent-sec-labs/LIMA/issues/165)、[#166](https://github.com/agent-sec-labs/LIMA/issues/166) 的部分文字仍为历史状态；应围绕当前范围和可测标签重定验收，不把局部零发现称为全仓零漏报。
- 其他开放项包括 #298 部署 smoke、#246 平台展示剩余验收、#289 双格式前端报告下载、#319 structured-v2 误报评估、#315 协作跟踪。它们有历史冻结说明；需按最新 main 核对后再排期，不能单凭 Issue 开放就判为完全未实现。

## LIMA 全局与赛题边界

README 与交接规范仍把 1.6.0 定位为仓库审计/报告及早期修复的过渡基线。Python 有受限 CWE-22/78/89 修复与验证路径；C/C++ 当前重点是分析和证据验证，不宣称自动修复。完整 Audit → Mining → Verified Repair 仍是目标态。

赛题交付还须独立核对真实 OpenHarmony 目标、版本影响、可执行 PoC、正常业务回归、报告和演示。Build Agent 的通用基础设施通过测试，不能替代这些漏洞级材料。本次未重新审计历史 OH 样本或录制新的演示，不对其完成数量作新结论。

## 下一阶段建议

先完成“跨进程交付 + 小夹具真实全链”的一个明确交付，再冻结真实组件做试点；根据失败数据决定后续依赖和构建系统扩展。同时修正文档与 Issue 状态，避免继续把已实现接口重复开发，或把尚未验收的能力写成已完成。

本次仅新增本进度记录；未改动已有未提交源码，未修改 GitHub Issue 或评论。
