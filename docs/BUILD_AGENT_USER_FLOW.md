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
      → CMake configure → 导出上下文包 → 校验请求 TU 覆盖
  → BuildResult 摘要持久化到任务记录
  → 注册只读分析视图 → facts / repro / Specialist 消费回执
  → 检测与报告
```

### 策略校验

模型输出的构建计划必须通过程序化安检才会执行：

- 计划必须绑定请求的快照哈希和组件范围
- 成功包必须覆盖请求的每个翻译单元；缺失目标返回 `target-units-missing`，不会发布构建成功
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

构建成功只说明包已通过快照、内容和请求 TU 覆盖校验；它不等于检测已经使用该包。服务会为可验证包注册只读视图，facts、repro 和 Specialist 各自通过共享 resolver 消费。`consumed_by_analysis` 只能由实际的消费者回执和可用上下文得出，不能仅由“选择了 verified-package 模式”推断。

若视图不可用、目标 TU 没有可解析上下文或消费者没有回执，报告必须保留覆盖缺口：auto 模式明确降级，required 模式拒绝依赖上下文的阶段。这些状态不是安全结论。

当前生产规划器是确定性的受限 CMake 流程，并非通用 LLM 自主修订器。每个任务仍受请求目标、扫描窗口和上下文预算限制；任务报告应展示已覆盖、未覆盖及原因，预算内完成不能表述为全仓完成审计。

构建输入有独立清单和摘要，不仅依赖审计文件指纹。默认拒绝符号链接、Windows junction/reparse point，排除 `.env`、常见凭据、版本控制及缓存/构建输出目录；普通构建资源不受审计扩展名白名单限制。默认上限为 50,000 个文件、单文件 32 MiB、总量 512 MiB；收集和复制也受取消与总时间预算约束。清单保存为每次尝试的 `inputs.json`。恢复复用和检测消费前会重新核对摘要；缺少该摘要的历史成功结果会重新构建。

启用 Build Agent 后，旧工具分析接口只执行 `source-only`，因为它不能绑定已验证制品摘要；依赖上下文的 facts / Specialist / repro 仍由平台链接收同一制品。被阻断的工具层会明确写入报告。构建失败或未消费也会进入任务总警告，required 阻断不会再显示为“无覆盖缺口”。

报告中的仓库代码执行标记来自执行器回执：进入沙箱执行尝试即标记为已进入执行，即使随后失败或超时；输入校验失败不算执行。报告同时区分宿主与构建沙箱，不把“未在宿主运行”写成“未执行仓库代码”。

## 部署配置

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `LIMA_BUILD_AGENT_MODE` | `off` | 服务端默认模式 |
| `LIMA_BUILD_AGENT_IMAGE` | （空） | 批准的构建镜像；为空时 auto/required 报 `build-not-configured` |
| `LIMA_BUILD_ARTIFACTS_ROOT` | `output/build-artifacts` | 产物根目录 |
| `LIMA_BUILD_ARTIFACTS_RETENTION_DAYS` | `30` | 产物保留策略参数；不单独承诺自动清理作业已启用 |
| `LIMA_BUILD_CONCURRENCY` | `1` | 同时执行的构建容器数上限 |
| `LIMA_BUILD_AGENT_ALLOW_REPOSITORY_ROOT` | `true` | 是否允许 `-S .`（整仓 configure） |

Build Agent 在执行前检查宿主 Docker CLI、Docker daemon 和产物根目录的实际写入能力。失败码分别为 `docker-cli-unavailable`、`docker-daemon-unavailable` 和 `build-artifacts-unwritable`。标准只读 Compose 不提供此执行通道；启用前请按[宿主部署指南](BUILD_AGENT_HOST_DEPLOYMENT.md)配置。

产物保留不在服务运行期间自动删除。管理员须停止所有 worker 后运行离线维护命令；默认只输出 dry-run，删除需要 `--apply --workers-stopped`。命令仅处理任务库中状态已明确为 `SUCCESS`、`FAILED` 或 `CANCELLED`、超过保留期且不含链接/联接点的直属任务目录。详见[宿主部署指南](BUILD_AGENT_HOST_DEPLOYMENT.md#6-离线清理构建产物)。

## 什么时候需要人工介入

以下情况 Build Agent 会停止并报告 `NEEDS_ATTENTION`，需要人工处理：

- 仓库需要的依赖不在部署批准的依赖集内
- 仓库使用的构建系统不在支持的 adapter 列表内（当前仅 `cmake-linux`）
- 构建预算耗尽（默认 3 次尝试、8 次模型调用、总计 1800 秒）
- 快照内没有 C++ 源文件（`build-no-cxx-units`）

人工处理后可以重新提交任务。
