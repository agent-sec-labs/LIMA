# Build Agent 用户流程

本文说明 LIMA 构建智能体（Build Agent）从用户提交仓库到检测消费编译上下文的完整流程，以及各环节的可见状态。

## 什么时候需要 Build Agent

LIMA 的 C/C++ 检测需要编译参数（include 路径、宏定义、语言标准）才能准确解析目标代码。如果快照内已有 `compile_commands.json`（CMake 导出），检测会直接使用。当快照内没有编译数据库、或者需要确保检测使用的是当前配置的构建环境时，Build Agent 可以在沙箱容器里自动准备。

## 用户操作

在创建审计页面（`/audit/new`），选择仓库来源后会出现**构建智能体模式**下拉：

| 选项 | 含义 |
|------|------|
| 跟随服务端默认 | 不发送该字段，由 `LIMA_BUILD_AGENT_MODE` 环境变量决定（默认关闭） |
| 关闭 | 仅使用快照内已有的构建信息（现有行为） |
| 自动构建 | 尝试在沙箱容器里准备编译上下文；失败时继续静态扫描但报告缺口 |
| 必须构建 | 构建失败时拒绝进入依赖编译上下文的检测阶段 |

选择后提交即可。构建在服务端后台执行，浏览器关闭不影响。

## 构建流程

```
提交任务（模式冻结在 task_input 与队列消息中）
  → 快照建立（GitHub 物化或本地导入）
  → Build Agent 在快照上运行（沙箱容器、禁网、资源限额）
      识别构建文件 → 提出候选 BuildPlan → 策略校验 → 依赖准备
      → CMake configure → 导出上下文包 → 校验
  → BuildResult 摘要持久化到任务记录
  → 检测继续（当前的消费链接线状态见下文）
```

### 策略校验

模型输出的构建计划必须通过程序化安检才会执行：

- 计划必须绑定请求的快照哈希和组件范围
- 可执行文件必须在部署批准的白名单内
- CMake 参数只允许 configure 语义（不允许 `--build`、`-E` 工具模式等）
- 镜像必须来自部署批准的依赖集（可选摘要 pin）
- 预算是冻结的，模型不能上调

### 产物与证据

构建的每次尝试在产物根目录（`LIMA_BUILD_ARTIFACTS_ROOT`，默认 `output/build-artifacts`）下按 `task_id/run-N/attempt-M/` 隔离。产物包括：

- `package/`：经验证的上下文包（编译数据库 + 生成头文件）
- `logs/`：每个步骤的有界日志
- `steps/`：步骤级执行记录

BuildResult 摘要（状态、包引用、尝试次数、失败码、证据引用）持久化到任务记录的 `build_agent_result` 字段。

## 任务详情展示

任务详情页显示**构建智能体**卡片，三种状态：

| 状态 | 颜色 | 含义 |
|------|------|------|
| 构建成功 | 绿色 | 上下文已准备并校验；是否被检测消费取决于 `consumed_by_analysis` 字段 |
| 构建失败（已降级） | 橙色 | auto 模式下构建未完成，检测降级为不依赖编译上下文的静态路径 |
| 构建失败（已阻断） | 红色 | required 模式下构建未完成，依赖上下文的检测阶段被拒绝执行 |

卡片显示模式、尝试次数和失败码。降级和阻断状态附带说明文字，明确这不是安全结论。

## 当前的消费链状态

截至本切片（S5），构建产物已准备好并经过校验，但**尚未接入检测阶段的实际消费**（`consumed_by_analysis: false`）。具体而言：

- facts / repro / Specialist 的 **verified-package 消费代码**已实现（S4B），包括共享 resolver、封存成员铺设、三方参数一致
- 但服务端的扫描流程 **还没有把构建产物注册到分析器的视图注册表**，因此检测阶段目前仍走 `snapshot-compdb` 或 `heuristic` 路径
- 完整的检测消费接线（sidecar 进程的视图注册、扫描器接收 verified-package 输入）是端到端试点（S6）的工作

## 部署配置

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `LIMA_BUILD_AGENT_MODE` | `off` | 服务端默认模式 |
| `LIMA_BUILD_AGENT_IMAGE` | （空） | 批准的构建镜像；为空时 auto/required 报 `build-not-configured` |
| `LIMA_BUILD_ARTIFACTS_ROOT` | `output/build-artifacts` | 产物根目录 |
| `LIMA_BUILD_ARTIFACTS_RETENTION_DAYS` | `30` | 产物保留天数 |
| `LIMA_BUILD_CONCURRENCY` | `1` | 同时执行的构建容器数上限 |
| `LIMA_BUILD_AGENT_ALLOW_REPOSITORY_ROOT` | `true` | 是否允许 `-S .`（整仓 configure） |

## 什么时候需要人工介入

以下情况 Build Agent 会停止并报告 `NEEDS_ATTENTION`，需要人工处理：

- 仓库需要的依赖不在部署批准的依赖集内
- 仓库使用的构建系统不在支持的 adapter 列表内（当前仅 `cmake-linux`）
- 构建预算耗尽（默认 3 次尝试、8 次模型调用、总计 1800 秒）
- 快照内没有 C++ 源文件（`build-no-cxx-units`）

人工处理后可以重新提交任务。
