# LIMA 修复发布链整改记录

日期：2026-11-06。对应审计：[自动修复发布链](LIMA_GLOBAL_REPAIR_PUBLICATION_AUDIT_2026-11-06.md)。本次继续在当前工作树修改，保留此前未提交修复和用户文档；没有提交、推送、合并，也没有写入真实 GitHub 仓库。

## 1. 发布绑定审计提交

服务入口现在要求 SUCCESS 的 PR 审计任务、既有租户仓库修复授权，以及任务输入中完整的 40 位审计 head SHA。不能用失败任务保留的旧报告发布，也不能从当前 PR head 补造历史审计来源。

`SafeFixer.create_fix_commits(..., expected_source_sha=...)` 在读取源码前和首次写入前分别核对 live head。取件、完整归档和提交父节点始终使用该审计 SHA；来源变化返回 `repair-source-stale`，不写 GitHub。提交消息、草稿标题与正文均记录固定来源。

## 2. 发布统一经过实际验证门禁

拟发布文件必须有支持的修复 manifest。旧 hardcoded-secret / debug-print 无 manifest 的路径不再发布，保留本地补丁规划能力；同一文件的混合规则仍按现有修复引擎的延后原因记录，不把未应用的规则写成已修复。

发布要求配置仓库测试命令，并执行完整归档验证。编译、逐项独立安全 Oracle、差分复扫和仓库测试都必须真实通过；总 `passed` 和每条 check 必须是布尔 true。Sandbox 的 configured / executed / stop_confirmed / passed 必须全部为 true，并附带合法实际镜像 ID。缺失、矛盾或部分成功的检查不能通过。

草稿正文从真实 checks 和回执逐条生成，检查名中的控制字符会转义。管理台仅在返回实际 branch 时提示成功；门禁阻断则明确提示未创建，保留原有确认步骤。

## 3. 仓库测试仅在隔离容器内执行

`RepairVerifier.verify_worktree` 不再直接调用宿主测试进程。新 `DockerRepairTestSandbox`：

- 检查批准镜像并解析实际 sha256 ID，禁止自动拉取，固定 Python bootstrap，不转发宿主环境变量。
- 将原验证树复制到独立 staging，拒绝链接、Windows junction/reparse point、不可读及非普通输入；限制 20,000 个文件和 200 MiB 实际复制字节，不改原树权限。
- 规范 staging 为非 root 可读，以只读方式挂载；在容器 tmpfs 中建立可写的一次性副本。入口工作目录为已存在的 `/work`，复制完成后切换到仓库目录。
- 使用非 root、只读根文件系统、无网络、cap-drop ALL、no-new-privileges；限制 CPU、内存、PID、输出和共享总超时。镜像检查、输入准备和测试执行都消耗同一时间预算，截止后不启动执行；迟到成功也不能通过。
- 复用有界输出与 stop/kill 确认机制。未确认停止、无效 runner 回执或运行失败均不能通过；用户可见错误不暴露宿主路径。

通过 `LIMA_REPAIR_SANDBOX_IMAGE` 配置批准镜像；未配置或不可用时明确失败，不回退到宿主。标准只读 Compose 仍没有 Docker 执行通道，部署要求见 [修复发布门禁](REPAIR_PUBLICATION_GATES.md)。本次没有向 Web 容器挂载 Docker socket，也没有改动用户实际 `.env`。

## 验证记录

证据目录：`output/lima-repair-publication-fixes-2026-11-06/`。

- 新回归覆盖缺少/过期 SHA、验证期间 SHA 变化、legacy 无 manifest、无测试命令、伪通过/矛盾 checks、缺失镜像回执、零写拒绝，以及前端阻断提示。
- Sandbox 回归覆盖无镜像不执行宿主哨兵、非 root 可读 staging 且原权限不变、实际 Windows junction、超时前拒绝执行、迟到成功不能通过、权限/网络/只读参数和停止确认。
- `focused-tests.log`：后端专项 76 通过、2 跳过；随后补充错误原因显示回归，发布/沙箱/功能测试再次 35 通过、1 跳过。这些集合有重叠，不累加。
- `frontend-tests.log`：前端全量 **87 通过**；TypeScript 检查与生产构建通过，保留现有打包体积提示。
- 后端全量：`full-suite.log`，**3,747 项、42 跳过、其余全部通过**，耗时 330.429 秒，无失败或错误。
- 源码编译、`git diff --check` 和新增模块/测试 Ruff 通过；`lint-delta.json` 核对涉及的既有大模块未引入新增 lint 违规。

`regression-results.json` 确认：旧 SHA 返回 source-stale，legacy 返回 manifest-missing，两者 GitHub 写入次数为 0；无镜像的测试不会写宿主工作树外哨兵。独立只读集成复核未发现新的可触发遗漏。

### 验证限制

本轮 `docker-smoke-result.json` 返回 `repair-sandbox-image-unavailable`、`executed=false`、宿主哨兵未变；本机引擎/批准镜像当前不可用，因此没有完成真实容器的成功路径验收。没有为此修改 Docker 配置或启动 Desktop。

既有功能修复测试通过显式的 tests-only runner 对受信合成仓库运行真实断言，保留“错误修复不能发布”的功能检查；该辅助不被生产代码导入，也不是宿主执行回退。它不能代替真实容器验收。本轮未在真实 GitHub 创建提交/PR，也未做真实大仓、模型或 Redis 故障注入。
