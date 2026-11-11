# LIMA 第二轮全局审计修复记录

对应问题：[修复后全局复审](LIMA_GLOBAL_REAUDIT_2026-11-06.md)。日期：2026-11-06。

本次在当前工作树修复该报告的四类问题，保留上一轮未提交修改和用户原有文档变更。没有提交、推送、合并或发布 GitHub 评论。

## 1. 构建输入边界

新增 `lima/build_inputs.py`，将构建输入与审计扩展名清单分开处理：

- 仅收集根目录内的普通文件；拒绝符号链接、Windows junction/reparse point 及解析后越界路径，复制前后检查路径组件。清单生成后根目录或子目录被替换为链接，同样拒绝。
- 排除 `.env` / `.env.*`、常见凭据、VCS、缓存和已有构建输出；`.git` 普通文件也排除。CMakeLists 和普通 `.dat` 等构建资源仍保留。
- 默认限制 50,000 个文件、单文件 32 MiB、总量 512 MiB。流式读取时校验实际字节数，处理文件增长；收集和复制都受取消与共享时间预算约束。不可读子树不能被遍历器静默忽略。
- 每次尝试保存 `inputs.json`，记录相对文件名、字节数和 SHA-256，并生成独立 `build_input_digest`。复制过程也纳入临时目录清理；输入拒绝不会启动隔离 session。

摘要通过 Executor → Tool → BuildAgent → Service 持久化。恢复复用和消费前均重新核对实际输入；即使审计指纹未变，构建资源变更也会使旧包失效。没有输入摘要的历史成功记录不再直接复用。

这提供内容和路径边界校验，不代表对拥有同等宿主权限、可持续并发篡改整个文件系统的对手建立了新的操作系统隔离边界。

## 2. required 与工具分支门禁

`RepositoryScanner.scan` 新增任务级 `cxx_allowed_layers`，与实例默认请求层求交，报告记录 requested / effective / blocked layers。被全部禁止时不调用分析器；被部分禁止时保留结果并标记 partial，不修改共享 scanner 配置。

Build Agent 启用时，旧分析接口只允许 `source-only`，因为该接口不能绑定已验证制品摘要。依赖上下文的 facts / Specialist / repro 继续通过已绑定制品的平台链执行。required 构建失败不再向旧接口请求 build-backed / sanitizer-confirmed。

同时修复 Workspace 对 Windows reparse point 的枚举与读取检查，使其覆盖目录、文件和路径中间组件；跳过的 reparse point 进入覆盖警告。

## 3. 总状态与执行声明

构建阻断、失败和未消费会进入总 completion warnings。required 失败可以保留已完成的 source-only 结果，但不会再显示“无影响覆盖的跳过”。

执行器记录是否已进入沙箱执行尝试，跨尝试累积；超时或失败不会把已有回执抹掉。此标记保守地表示仓库代码可能已经执行，不保证命令完成。报告不再固定声明 `repository_code_executed=false`，并区分宿主与 build-sandbox。输入阶段拒绝、取消或预算耗尽则不算进入执行。

## 4. 并发产物目录

在通过构建准入后，使用目录的原子创建预留 `run-N`；遇到并发占用就递增重试。不同执行不会再因“枚举后取 max+1”的交错共用一个目录。构建信号量在服务实例初始化时建立，消除首次并发调用的惰性初始化竞态。

本次保证产物目录独立；没有改写整个 Redis 队列的执行权 fencing 或所有任务状态转换协议。

## 验证

证据目录：`output/lima-reaudit-fixes-2026-11-06/`。

- 专项集成：`focused-tests.log`，144 通过、1 跳过；之后补充根目录替换拒绝用例，输入及服务回归合计 13 项通过。
- 新输入边界测试包含本机实际 Windows junction；scanner/workspace 新测试已转换为 CI 能收集的 unittest。
- 服务测试覆盖 required 请求层、总警告、执行回执、同任务并发目录，以及构建资源变化后的恢复和消费拒绝。
- 源码编译和 `git diff --check` 通过。新模块及新增测试 Ruff 通过；`lint-delta.json` 确认涉及的既有大型模块没有新增 lint 违规。
- 全量测试：`full-suite.log`，**3,723 项、41 跳过、其余全部通过**，耗时 397.062 秒，无失败或错误。此轮已包含最后补充的根目录替换拒绝用例。

### 容器验证限制

已准备 `docker_acceptance.py`，检查真实 CMake 中 `.env` 不可见、普通资源可见、遗漏 TU 失败，以及 junction 在启动执行前被拒绝。本机 Docker Linux Engine 当前不可用，实际尝试返回 daemon 连接失败，未能完成本轮真实容器验收。尝试启动 Docker Desktop 后仍不可用；随后停止命令确认 Desktop 未运行，恢复初始状态。不能把上一轮 Docker 成功结果当作本轮新复制逻辑的成功验证。

本轮没有执行真实模型推理、Redis 重领故障注入或大仓端到端试点。另有自动修复发布链的独立审计候选保存在 `output/lima-reaudit-2026-11-06/golden-path/REPORT.md`；它们不属于本次四项修复，未在本记录中声明已经解决。
