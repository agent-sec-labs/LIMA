# LIMA 全局审计：构建上下文到审计报告

日期：2026-11-05。

## 基线与结论

审计基线为 `origin/main`（`62dbbd69e899baac8243f3e04efaa5dc6f36576b`，已包含 #353）与 #354 候选提交 `fcd098562001d1d610134c86e3a92e15cde1ea72` 的虚拟合并树 `e6444da740063aac769c3439f3ae1a38729eb5d9`。#354 尚未合并；本报告不把候选能力视为已经上线。

本轮沿构建请求、包校验、跨进程注册、facts 消费、报告及清理链路检查，并核对标准部署和产品声明。发现三项应优先修改的正确性问题，以及部署与资源回收方面的缺口。这些问题横跨已有代码和 #354 接线，不能全部归因于 #354。通过已有测试和 CI，不足以证明该链路已经满足端到端验收。

本轮未修改生产代码，也未执行合并或发布评论。未对整个 LIMA 所有模块作穷尽审计。

## 1. P1：上下文实际不可用，报告仍声称已消费

位置：`lima/service.py:1982`、`lima/repository_scanner.py:821`，以及 orchestrator 的 facts 获取和空结果路径。

复现中，产物注册成功后、facts 请求前移除了注册，模拟 Sidecar 重启或容量淘汰。真实 facts 接口返回 `extraction: unavailable`、`verified-view-not-registered`、`ast_complete: false` 和 `cfg_complete: false`；但 auto 和 required 两种模式均产出：

- `consumed_by_analysis: true`；
- 平台 `completed`、工作流 `succeeded`，required 未阻断；
- AEP 的 `coverage_gaps` 为空。

当前消费标志依据所选 `verified-package` 模式与平台完成状态推导，没有确认消费者实际取得了有效上下文。无 lead 的正常结束路径又会遮蔽 facts 的不可用状态。问题不是“零发现”本身，而是报告与实际证据不一致。

建议：按 TU 记录实际消费回执和上下文可用性，将 facts 的缺口传入平台报告与 AEP。auto 应明确降级；required 应阻断依赖上下文的阶段，或明确标记其未完成。只有收到有效消费证据，才能显示“已消费”。

## 2. P1：请求的构建目标缺失，仍判定构建成功

位置：`lima/build_tools.py:342`、`lima/build_agent.py:434`；范围选择位于 `lima/service.py:1531`、`:1689` 和 `lima/repository_scanner.py:830`。

复现请求 `app/required.cpp`，执行器导出的有效包仅包含 `app/main.cpp`。真实 BuildAgent 校验路径仍返回 `SUCCEEDED`，`coverage` 为 null。包可解析、版本正确，不等于请求的目标已覆盖；终态校验没有核对 `BuildRequest.target_units`。

服务构建请求还取文件清单前 4 个 C++ 文件，消费阶段改用包内全部 TU，扫描阶段另按请求路径或前 16 个文件选择。三种范围可能不一致，尤其影响用户指定文件的任务。

建议：持久化同一份任务目标清单，由构建、facts 和扫描共同使用；终态必须校验请求 TU 的覆盖情况。缺失目标应失败或明确部分完成，并将未覆盖清单写入报告。不能通过换用包内 TU 来隐式缩小原始请求。

## 3. P1：容量淘汰会删除仍被运行任务持有的视图

位置：`cxx_analyzer/server.py:136–160`。

淘汰按最旧快照进行，没有排除 `_VIEW_HOLDERS` 非空的视图，而且会一并删掉 holder。探针将快照上限降到 1，先注册并持有 A，再注册 B，观察到 A 和其 holder 被淘汰。该探针验证了容量分支，不代表已在默认 64 快照、128 MiB 阈值下完成压力测试。

这会让正在执行的 facts / Specialist / repro 失去上下文，也可触发问题 1。

建议：活跃租约不得参与普通淘汰；容量全部被活跃任务占用时，原子拒绝新注册并给出容量诊断。结合租约到期和续租处理崩溃任务，避免永久占用。

## 4. 部署阻碍：标准 Compose 尚不能直接承载启用后的 Build Agent

位置：`lima/build_executor.py:298–306`、`Dockerfile` runtime 阶段、`docker-compose.yml:33–54`、`lima/config.py:196`。

执行器调用宿主 `docker` CLI，但标准应用镜像没有对应 CLI，Compose 也未配置构建执行通道。同时应用根文件系统为只读，默认产物目录 `output/build-artifacts` 位于 `/app` 下，没有相应可写挂载。

这是启用 Build Agent 的部署前置条件缺失；功能默认关闭，不意味着标准 LIMA 启动整体失效。本轮依据配置和代码确认，未实际运行 Docker 构建。

建议：提供隔离构建 worker 或明确支持的宿主执行方式，定义可信调用通道、可写的任务产物存储和权限，并提供可执行的部署验收步骤。不要把向 Web 应用直接挂载宿主 Docker socket 当作默认修复方案。配置检查还应覆盖 C++ analyzer 是否启用，避免只开启 build mode 却无法交付消费。

## 5. P2：注册和清理缺少失败闭环，holder 资源没有独立上限

位置：`lima/service.py:1704–1715`、`:1741–1751`、`:1794–1803`、`:1893–1899`，以及 Sidecar 注册与 holder 管理。

已验证的故障场景：

- 服务端提交注册后丢失响应，客户端认为交付失败，没有调用清理；服务端 holder 继续存在。
- DELETE 返回失败，调用方忽略返回值，没有重试，holder 残留。
- 同一 digest 注册 1,000 个不同 holder，只占一个快照和少量 member bytes，现有快照和成员字节上限无法限制 holder 元数据增长。
- HTTP 模式消费准备阶段还会向本进程注册表写一份视图；远程释放路径不会同步释放该本地副本，需等后续淘汰。

建议：使用同一执行 token 做幂等注册和有界补偿清理，记录释放失败并重试；同时提供租约到期/续租，覆盖进程崩溃和请求乱序。增加每视图及全局 holder 数量/字节预算。只有明确采用进程内分析器时才注册本地视图。

## 6. P2：文档、生产规划能力和产物保留策略需要对齐

- `docs/BUILD_AGENT_USER_FLOW.md:66–72` 仍写“尚未接入实际消费”。这对当前 main 的旧切片有历史依据，但在 #354 合并时必须同步更新，并区分注册成功、实际消费和覆盖完整。
- 生产工厂返回 `_deterministic_build_model`（`lima/service.py:232`、`:1443`），目前是固定 CMake 流程。框架具备 Agent Loop，不等于生产已接入模型驱动的构建规划与失败修订。应准确描述当前支持范围；是否接入真实规划模型可另行立项。
- `build_artifacts_retention_days=30` 目前仅见配置声明、加载和校验，没有找到执行清理的实现。应补清理机制或明确其尚未生效；清理必须避开运行任务持有的包。
- #353 把 Discovery 单窗口降至 16 KiB，仍最多 8 个窗口；扫描目标也有数量上限。这些属于有界执行策略，应在覆盖清单中持续展示已覆盖、未覆盖和原因，不能把预算内完成表达成全仓完整审计。

项目 README 已明确完整 Audit → Mining → Repair 闭环仍是目标、当前聚焦 Python Golden Path。上述 C++ 接线完成后，也不应据此宣布全平台闭环完成。

## 验证证据与边界

证据目录：`output/lima-global-audit-2026-11-05/`。

- `integrated/audit_runtime_probes.py`、`integrated/audit-runtime-probes.json`：目标缺失与注册丢失后的报告真实性复现。
- `registry/probe_registry_lifecycle.py`、`registry/probe_registry_lifecycle.result.json`：活跃淘汰、响应丢失、释放失败及 holder 增长探针。
- `audit-integration-tests.log`：虚拟合并基线相关测试 **228 passed, 1 skipped**。
- #354 候选 CI run `42023409829` 已观察到成功。

目标缺失探针使用模拟执行器导出真实有效包；报告探针提供已知有效的构建结果，并在 facts 前注入注册丢失，facts、扫描和报告路径实际执行。模型响应使用固定空 lead 以隔离问题。本轮没有执行真实 Docker、Clang、模型推理或真实试点仓库的端到端验收，也未做 Redis 故障注入。已有测试通过并不能覆盖上述新增探针揭示的问题；不同测试集合存在重叠，不累加通过数量。

## 建议修改顺序

1. 先修报告真实性和请求目标覆盖契约，防止“成功”含义失真。
2. 再修活跃视图保护、租约回收和 holder 预算，保证并发与异常恢复。
3. 补支持的部署执行方式、产物存储与清理，同步用户文档。
4. 用一个正常仓库和一个失败仓库验收完整链路，至少覆盖指定 TU 缺失、Sidecar 重启、容量已满、响应丢失和 required 阻断，再扩大试点。
