# ResInsight 前后端联调验收记录

日期：2026-10-18（Asia/Shanghai）。结论：**部分通过，不能按全功能可用验收。**

> 本文保留初轮验收结果；后续修复及复验见 [联调修复记录](INTEGRATION_REPAIRS_2026-10-18.md)。

目标仓库：`D:\paper\油气数据\油气工业软件源码\ResInsight`。本次未修改目标源码、原 `.env`、冻结评测数据或既有 Docker 容器配置；未调用远程模型、未向 GitHub 发布内容。

## 验收环境与证据

- 原本地实例：`127.0.0.1:18082`，保留上一轮的真实页面扫描与反馈记录。
- 新认证验收实例：`127.0.0.1:18084`，独立 SQLite，远程模型明确关闭；本地测试账号 `acceptance-admin`，测试密码 `Acceptance-local-only-2026`，仅用于当前本机实例。
- 新只读 Sidecar：`lima-resinsight-acceptance`，现有本地镜像 `lima-cxx-analyzer:local`，仅将指定 ResInsight 目录只读挂载为 `/repositories/ResInsight`，监听 `127.0.0.1:18090`。未启动目标项目构建或测试。
- 新仓库任务：`02a69939-826d-4887-8c0c-dc88ce4f5e20`，真实后端与 Sidecar 执行，耗时约 2 分 48 秒。
- 取消任务复现：`4a42e3ed-3d1f-45d2-a15b-f08f5f596b60`，使用现已停止的独立 `18083` 实例，完整响应证据已落盘。
- 验收脚本与响应：[`output/integration-resinsight`](../output/integration-resinsight/)，包括 `api-acceptance.json`（原始首轮）、`api-acceptance-final.json`（增加修复后目录复验和 C++ 语义验收）、`cancellation-acceptance.json`、任务 JSON、截图和日志。

## 功能矩阵

| 功能 | 实际操作与结果 | 结论 |
|---|---|---|
| 登录与匿名访问限制 | 无 token 读业务接口为 401；错误密码为 401；正确账号登录为 200。浏览器可登录，刷新后会话保留 | 通过；登录后的查询刷新另见缺陷 |
| 本地仓库扫描 | 页面键 `ResInsight`、提交、轮询、终态与报告展示走通；新认证实例创建任务为 202，最终 SUCCESS | 链路通过，覆盖不完整 |
| 任务列表与详情 | 页面显示真实的 ResInsight 仓库任务和 OPM/ResInsight Diff 任务 | 通过 |
| PR / Diff 审查 | 从目标 `RiaMain.cpp` 的真实 Qt exec 调用构造只读验收 Diff；异步提交、SUCCESS、报告下载走通，未修改目标文件或实际 PR | Diff API 链路通过；真实 GitHub PR 尚未验收 |
| Markdown 报告下载 | 新仓库和 Diff 任务的报告接口均为 200 | API 通过；页面仍无下载按钮 |
| 反馈提交与回读 | 页面提交 Qt exec 误报说明，显示“误报已记录”和历史；新认证实例反馈 POST 为 201、GET 为 200 | 通过 |
| 系统能力、模型设置 | 浏览器显示真实本地规则模式与 Skill；API 为 200 | 通过读取展示；不包含模型实际推理 |
| 高级实验状态 | 浏览器与 evolution/status、runs、failures 接口可读取真实状态 | 读取通过；未执行演进激活 |
| 外部评测目录 | 首轮连接断开；修复后在线接口 200、列出 3 个数据集，浏览器下拉框可显示 | 修复后通过 |
| 后台实验创建、执行、取消与恢复 | 当前可用目录只有 Python pilot/calibration 数据集，没有指定 ResInsight 的兼容案例清单；未越过目标范围运行其他仓库。路径越界和无模型模式请求均按预期拒绝 | 正向全流程未验收；边界测试通过 |
| 普通仓库任务取消 | POST cancel 为 202 / cancel_requested=true；最终仍 SUCCESS，数据库 cancel_requested=1 | **未通过** |
| 普通任务恢复 | 已完成 Diff 的 resume 返回 202 并维持 SUCCESS；未获得成功取消的仓库任务，未证明取消后恢复可用；前端也无操作入口 | 仅幂等边界通过；正向恢复未验收 |
| 修复预览 | 新仓库任务调用为 400：`repair preview requires a complete bounded repository snapshot`；Diff 任务也按类型边界被拒绝 | **被扫描截断阻塞**；未验证正向修复预览 |
| 修复分支发布 | 对仓库扫描调用 fix 为 400；无 autofix 授权的带 PR 编号验收任务为 403。未创建远程分支或提交 | 拒绝边界通过；正向发布未验收 |
| C++ source-only | 真实 Sidecar 接到任务，Semgrep 进程完成、returncode=0，覆盖 3,002 个 C/C++ 源文件；但诊断为 `Semgrep JSON was rejected` | **未通过结果验收** |
| C++ build-backed / ASan | health 明确 build_available=false、test_configured=false、trusted_build_context_generation_available=false；报告诊断 build-not-configured、sanitizer-not-configured | 环境阻塞 |
| C++ 智能体与仓库语义复核 | 独立实例未配置远程模型，显式 agent_detection=true 返回具名 400；页面开关禁止开启 | 不可用边界通过；正向模型链未验收 |
| GitHub 仓库与安装绑定 | 当前 source 为 local-import；OPM/ResInsight GitHub 来源请求按预期 400；非法 installation_id 为 400。未执行远程安装绑定或 Webhook 发布 | 正向链路未验收 |
| 指定 investigate_paths | 本轮未增加页面/HTTP透传；当前页面仍无输入，API 创建仓库任务也未提取该字段，服务层支持不能视为前后端贯通 | 未贯通 |

## 尚未通过的关键项

1. **C++ 输出未被接受，却仍标为完成。** `report.collaboration.cxx_memory.status=completed`，Semgrep tool_run 也为 completed，但 diagnostics 包含 `Semgrep JSON was rejected`。这是工具进程退出成功，不能等同于解析与证据链成功。报告页面没有把这条 C++ 诊断显著展示出来。此轮不能据此认定 C++ 已完成有效检测，更不能把缺少 C++ 发现解释为安全。具体 JSON 被拒绝的原因尚未定位。
2. **取消请求未终止仓库扫描。** 复现响应见 `cancellation-acceptance.json`；202 仅代表请求被记录。
3. **登录后未自动恢复查询。** 首次未登录导致能力查询失败；浏览器登录成功后，创建页仍停留“无法读取服务端智能体检测配置”，手动点“重试”才恢复。证据：`login-stale-capabilities.png`。
4. **默认上限导致部分覆盖及预览阻塞。** 扫描 3,150 个文件、20,971,520 字节；17 项 file-size-limit、4,093 项 total-size-limit。修复预览要求完整有界快照，因此拒绝当前任务。
5. **Qt exec 通用规则误报。** `QCoreApplication::instance()->exec()` 与 `msgBox.exec()` 被作为 SEC-EVAL 候选；这是 Qt 事件循环/对话框语义，不能直接当成代码注入。本轮报告的 100 项均为需要复核，0 项证据已验证。
6. **入口缺失。** 普通任务取消/恢复、Markdown 下载没有页面操作，指定分析路径未贯通。系统能力页仅依据共享模型配置显示“规则 + LLM 证据融合”，不能说明特定仓库任务的语义复核已开启。

## 本轮修复与验证

修复 `lima/experiments.py` 的目录读取边界：先检查候选 JSON 根是否为对象，再交给严格 manifest 加载器。列表根文件被跳过，合法清单继续列出。补充 `tests/test_experiments.py` 回归。修复留在目录层，未改变分析器指纹或冻结数据集。

- 修复后真实 `GET /v1/experiments/catalog`：200，3 个数据集；浏览器下拉框已复验。
- 最终选取 10 个相关后端测试文件：**133 passed in 20.60s**，含 API 安全、实验、任务进度/失败、修复、仓库扫描、智能体模式、investigation、GitHub 以及 real-world 评估回归；命令结果在 `backend-acceptance-tests.log`。其中模拟模型/物化器的测试只证明测试条件下的逻辑，不替代在线验收。
- 上一轮前端构建与 72 项前端测试通过；本轮没有修改前端代码，未重复宣称新的浏览器 E2E 套件全通过。
- `git diff --check` 通过。

建议先处理 C++ JSON 解析与状态传递、仓库取消行为和登录查询刷新，再补齐扫描覆盖及正向修复；之后配置真实模型、可信构建环境与 ResInsight 专用实验清单，继续验收剩余链路。
