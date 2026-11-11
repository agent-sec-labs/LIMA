# LIMA 修复后全局复审

日期：2026-11-06。基线：`D:\Projects\LIMA` 当前工作树，包含上一轮尚未提交的全局审计修复；HEAD 为 `fcd098562001d1d610134c86e3a92e15cde1ea72`。本轮没有修改生产代码、合并或发布评论。

本轮关注系统边界是否一致：进入构建容器的文件、required 门禁、任务总状态、并发执行与产物身份。重新核对注册表生命周期，并抽查 Python Repair Preview 的快照和验证入口。不是对所有语言、漏洞规则、动态 Mining 和发布流程的穷尽审计。

## 结论

仍有需要修改的地方。上一轮修复了实际 facts 消费回执、目标覆盖和注册表生命周期，但没有覆盖构建输入复制、工具分支门禁和总进度汇总。建议先处理下面两项 P1，再处理两项 P2。

## 1. P1：构建工作拷贝与受审计快照边界不一致

位置：`lima/build_executor.py:518–519`；本地导入入口 `lima/service.py:1327–1343`；文件清单筛选 `lima/workspace.py:172–244`。

BuildExecutor 对传入目录直接使用默认 `shutil.copytree(snapshot, work_copy)`。它没有按已验证的文件清单复制，也没有在复制边界拒绝链接或 Windows junction。沙箱挂载的是这个工作拷贝，因此“Docker 只挂工作拷贝”不能阻止在挂载之前已被复制进来的仓库外字节。

已用全由探针创建的无敏感数据目录验证：

- 审计文件清单只有 `app/main.cpp`；`.env` 被标为 `sensitive-config` 排除。
- 在快照内创建指向快照外自建目录的 Windows junction。
- 修改外部哨兵文本后，快照指纹不变。
- 实际 BuildExecutor 的工作拷贝同时包含 `.env` 哨兵和外部哨兵，junction 已被物化为普通目录，执行器仍返回成功。

适用条件是本地导入目录或直接调用执行器时存在这些文件/链接；不能据此声称 GitHub 归档链接校验也已被绕过。本次未读取任何真实敏感文件。执行器和文件复制真实运行，容器 session 用现有测试适配器替代，未声称此探针启动了真实 Docker。

同一复制路径还会复制被审计大小、扩展名和目录策略排除的内容。复制发生在负责清理的 `try/finally` 之前，且复制过程没有逐文件预算/取消检查；这是同一输入边界需要一起处理的部分。

建议：定义明确的构建输入清单，覆盖实际所需的构建脚本、源文件及资源，而不是盲目照搬审计扩展名白名单。对实际复制的所有输入做路径包含性、symlink/reparse-point、敏感文件、字节预算和内容身份校验；复制也应支持取消，并纳入清理的 `try/finally`。实际构建输入的身份应可追溯，不能只依赖未覆盖这些字节的审计指纹。

## 2. P1：required 构建失败只关闭平台分支，仍请求构建及 sanitizer 工具层

位置：`lima/service.py:1937–1942`、`lima/repository_scanner.py:1047–1057`。

构建缺失时，服务只把任务级 `cxx_agent_mode` 设为 off。扫描器前面的 C++ 工具分支由共享 `cxx_memory_mode` 控制，不读取这项任务级门禁，仍调用 analyzer 的 `analyze`。

已通过真实入队、handler、scanner 和任务存储路径复现：

```json
{
  "build_agent_mode": "required",
  "failure_code": "build-not-configured",
  "blocking": true,
  "platform": {"mode": "off", "status": "disabled"},
  "analyzer_layer_requests": [
    ["source-only", "build-backed", "sanitizer-confirmed"]
  ]
}
```

构建结果和 analyzer 返回值用固定适配器隔离外部执行；证据证明请求仍被发出，不代表本探针实际进行了编译或 ASan 实验。

建议：将“该任务允许执行哪些层”作为统一任务级决策，同时约束平台和工具链。required 上下文缺失时，拒绝 `build-backed` / `sanitizer-confirmed`；如果允许继续 `source-only`，应在请求和报告中明确保留该范围及阻断原因。不要通过修改共享 scanner 配置实现任务级门禁。

## 3. P2：报告的总完成状态和代码执行标记仍与实际情况不一致

位置：`lima/service.py:1989`、`:2147–2177`；展示位置 `frontend/src/features/tasks/TaskDetailPage.tsx:168–194`。

同一 required 失败探针中，构建卡片为 `blocking: true`，任务最终却是 `SUCCESS`，`progress.detail.completion` 为：

```json
{"status": "completed", "warning_count": 0}
```

任务成功可以表示 handler 正常结束，但用户看到的总完成横幅据此显示“本次执行没有影响覆盖范围的跳过”。汇总只考虑 inventory、C++ 工具状态和部分平台状态，没有合并 build gap；平台被关闭后也不会进入平台失败警告分支。它与构建卡片相互矛盾。

另外，`import_policy.repository_code_executed` 被硬编码为 false。启用 Build Agent 后，CMake configure 会解释仓库提供的构建脚本；即便是在隔离容器内执行，也不能把“没有在宿主执行”表示成“没有执行仓库代码”。该项为源代码确认，未单独执行完整任务的真实 Docker 报告探针。

建议：把构建失败、消费缺失和阻断统一纳入总完成状态；区分“请求处理完成”与“要求的审计范围完成”。代码执行声明应区分宿主与沙箱，并从真实执行记录生成。

## 4. P2：同一任务并发构建会使用同一个产物目录

位置：`lima/service.py:1570–1583`、`lima/build_executor.py:500–519`。

服务通过枚举 `run-*` 再取 `max + 1` 分配构建目录，没有原子占位或跨进程锁。已在同一 task、并发额度 2 的两次 `_run_build_agent` 调用中，用 barrier 固定合法交错，观察到两次 BuildAgent 都收到 `shared/run-1`。

探针真实执行服务端的目录分配逻辑，只替换了 BuildAgent，本轮没有实测产物混写或篡改后的错误接受。确定的问题是两个执行共用命名空间；真实 executor 的非空目录检查同样是检查后再创建，不能作为原子预留。

Redis 租约重领时旧 handler 仍可能运行，这是上一轮已经针对注册 holder 处理过的场景；视图持有 token 独立，并不意味着磁盘产物也独立。

建议：用执行唯一 ID 或原子创建/锁定机制预留目录，保证重领、重试及多实例下每次执行都有独立路径；持久化当前执行与其产物的对应关系，防止旧执行覆盖新执行的任务结果。

## 已复核且本轮没有新发现的部分

- 注册表：同快照多制品、同 holder 重注册、其他制品租约过期与默认槽切换。最小运行探针表明 B 到期不会删除仍被持有的 A，默认槽也保留正确身份。
- 上轮已修的 facts 不可用回执、终态请求 TU 覆盖、holder 容量保护及租约关闭顺序，在相关回归中未出现新失败。
- Python 修复入口仍区分只读静态预览和发布资格；未将其已声明尚未完成的长期平台目标列为缺陷。本轮没有进行完整 Python Mining/Repair 的动态验收。

## 证据与限制

证据目录：`output/lima-reaudit-2026-11-06/`。

- `build_copy_probe.py` / `build-copy-results.json`：实际复制边界探针。
- `service_probes.py` / `service-results.json`：required 门禁、总完成状态和并发 run 路径探针。
- `targeted-tests.log`：本轮相关回归 **58 通过**。

上一轮最终全量测试为 3,704 项、41 跳过、无失败；本轮未修改生产代码，因此没有重复执行全量测试。以上新探针说明现有通过的测试集仍有边界覆盖缺口。本轮没有执行真实 Redis 重领、远程 CI、真实模型推理或大仓全流程验收。
