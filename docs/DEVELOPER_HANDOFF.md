# LIMA 开发者交接与上手指南

本文面向第一次接触 LIMA 的开发者，目标是帮助你快速建立正确的项目心智模型，
找到修改入口，并在不破坏安全边界、评测完整性和多人协作约束的前提下交付代码。

> 基线：`main@5471a56`（2026-08-28，PR #23 合并后；同窗口合入 #22 API 安全边界修复）  
> 当前版本：`lima.__version__ == "1.6.0"`  
> 远程仓库：<https://github.com/agent-sec-labs/LIMA>  
> 实时任务状态以 GitHub Issue 的标签和维护者意见为准；本文的状态表只是交接快照。

## 1. 开始编码前先记住这几件事

1. **LIMA 是证据驱动的仓库安全 Agent，不是通用聊天 Agent。** 默认本地模式不调用
   远程模型；LLM 只负责可选的语义增强，不能替代静态证据。
2. **不要执行待审计仓库的代码。** 仓库导入、扫描和快照处理必须把目标代码当作不可信数据。
3. **远程 GitHub 扫描已可用但默认关闭。** `LIMA_REPOSITORY_SCAN_SOURCES`
   （默认 `local-import`）控制接受来源；启用 `github`/`both` 后
   `POST /v1/repository-scans` 接受 `{"source": {"type": "github", ...}}`，
   物化只发生在异步 worker（请求路径零网络），缓存命中时整条流水线零网络。
   Epic #17 剩余 T5/T6/T7。
4. **候选告警不能直接触发自动修复。** 只有已验证、受支持且通过安全 Oracle 的
   CWE-22、CWE-78、CWE-89 修复才可能进入修复闭环。
5. **一个 Issue、一个责任边界、一个 PR。** 不要顺手重构其他模块，也不要开发
   `status:blocked` 或已被他人认领的任务。
6. **不能因为本机缺少工具就跳过验证。** 使用独立虚拟环境或隔离 Docker 环境补齐
   Ruff、Bandit 等工具，并在 PR 中记录真实运行结果。

## 2. 推荐阅读顺序

不要一开始逐行通读全部源码。按下面顺序阅读，通常可以在 30–60 分钟内进入状态：

1. 本文：掌握代码地图、边界和工作流。
2. [README](../README.md)：阅读“快速开始”“服务端仓库扫描”“完整生产模式”“API”和“架构”。
3. [贡献指南](../CONTRIBUTING.md)：确认分支、提交、测试和安全变更要求。
4. [GitHub 多人协作门禁](GITHUB_COLLABORATION.md)：理解 `merge-gate` 和按修改类型选测试。
5. 你准备认领的 GitHub Issue：Issue 中的 Ownership、Avoid modifying、依赖和验收条件
   优先于个人实现偏好。
6. 只有涉及研究、评测或长期规划时，再阅读 [LIMA Roadmap](../LIMA_ROADMAP.md) 和
   `docs/V1_*` 系列报告。

## 3. 五分钟项目地图

```text
LIMA/
├─ lima/                 Python 应用、分析器、Agent、存储和集成代码
├─ tests/                unittest 测试；测试文件通常与 lima/ 模块一一对应
├─ web/                  无独立构建步骤的 HTML/CSS/JavaScript 管理台
├─ skills/               内置动态 Skill manifest 与隔离执行代码
├─ scripts/              扫描、评测、CI 和 Docker PowerShell 入口
├─ evaluation_data/      冻结/校准数据集；修改前必须理解指纹与 holdout 规则
├─ repositories/         本地授权仓库导入区；内容默认忽略且不得提交
├─ output/               报告和 CI artifact；默认忽略且不得作为源码提交
├─ docs/                 架构校准、评测和协作文档
├─ docker-compose.yml    PostgreSQL、Redis、LIMA 生产形态
├─ Dockerfile            base、test、real-eval、runtime 多阶段镜像
├─ pyproject.toml        包元数据、Python 版本、Ruff 和 pytest 配置
└─ requirements.txt      运行依赖；Bandit 在运行依赖中，Ruff 需单独安装到开发环境
```

### 3.1 两条主要业务链路

PR diff 审查链路：

```text
API / GitHub Webhook
        ↓
ApiHandler (lima/api.py)
        ↓
ReviewService (lima/service.py)
        ↓
TaskQueue（本地线程池或 Redis Streams）
        ↓
ReviewHarness + MultiAgentCoordinator
        ↓
规则 Reviewer / 可选 LLM / Skill / Evidence / Arbiter
        ↓
TaskStore（SQLite 或 PostgreSQL）
        ↓
JSON / Markdown 报告 / 可选 GitHub 评论
```

当前仓库扫描链路：

```text
repository_key
        ↓
RepositoryImportPolicy（限制在管理员导入根目录）
        ↓
异步任务
        ↓
RepositoryWorkspace（只读、有界、不跟随符号链接）
        ↓
Python AST + 跨文件数据流 + Bandit + 本地规则
        ↓
证据融合 / 可选语义复核
        ↓
持久化报告 + 只读修复预览
```

Epic #17 的目标链路是：

```text
RepositorySource
        ↓
RepositoryMaterializer
        ↓
不可变 RepositorySnapshot
        ↓
RepositoryCache
        ↓
RepositoryWorkspace
        ↓
Scan / Triage
        ↓
可选的隔离 RepairWorkspace
```

目前只有第一层 `RepositorySource` 契约与第三层 `RepositoryCache`（issue #12，T3）已经落地。
`RepositoryCache` 是独立模块：身份为 `provider + canonical identity + resolved_revision`
（不可变 commit SHA 或内容指纹），提供 `lookup/reserve/publish/touch/pin/cleanup`，
尚未接入服务编排。不要把 `canonical_name=owner/repo` 重新解释为服务器路径，
也不要在扫描器中直接加入下载逻辑；缓存接线属于 T4（issue #13）。

### 3.2 Finding 的证据等级

`RepositoryScanner` 按以下顺序理解验证强度：

```text
candidate
  < syntax-verified
  < corroborated
  < dataflow-verified
  < confirmed
```

多个工具在相同 `path + line + CWE` 上的结果会被融合。`--verified-only` 安全门禁只处理
已经获得语法、多工具、数据流或人工确认的结果，避免低证据候选直接阻断流水线。

## 4. 模块职责与修改入口

| 领域 | 首先阅读 | 主要职责 | 典型测试 |
|---|---|---|---|
| 程序入口/API | `lima/__main__.py`, `lima/api.py` | HTTP 路由、认证、输入输出、静态前端 | `test_service.py`, `test_production_features.py` |
| 总编排 | `lima/service.py` | 组装依赖、创建任务、队列投递、扫描/审查/实验编排 | `test_service.py`, `test_repository_import.py` |
| 配置 | `lima/config.py`, `.env.example` | `.env`、环境变量、默认值和校验 | `test_config.py` |
| 认证与隔离 | `lima/auth.py` | 登录、JWT、RBAC、租户身份 | `test_production_features.py` |
| 任务模型 | `lima/models.py`, `lima/store.py` | Finding、Report、状态、SQLite 持久化 | 多个 service/runtime 测试 |
| 生产存储 | `lima/postgres_store.py` | PostgreSQL 版 TaskStore 合同 | `test_production_features.py` |
| 队列 | `lima/task_queue.py` | ACK、租约、重试、DLQ、本地/Redis 后端 | `test_production_features.py` |
| PR diff 审查 | `lima/diff_parser.py`, `lima/reviewer.py` | unified diff 解析、本地规则和可选 LLM Reviewer | `test_diff_parser.py`, `test_reviewer.py` |
| Agent 编排 | `lima/agents.py`, `lima/runtime.py`, `lima/harness.py` | 计划、并行专家、证据、仲裁、checkpoint、预算 | `test_multi_agent_collaboration.py`, `test_runtime_memory_context.py` |
| 上下文/记忆 | `lima/context_manager.py`, `lima/memory.py` | 上下文压缩、租户级记忆、过期清理 | `test_runtime_memory_context.py` |
| 仓库来源契约 | `lima/repository_source.py` | GitHub/local-import 规范化；不联网、不物化 | `test_repository_source.py` |
| 本地导入边界 | `lima/repository_import.py` | `repository_key` 归一化和根目录逃逸防护 | `test_repository_import.py` |
| 快照缓存 | `lima/repository_cache.py` | 不可变 RepositorySnapshot 的有界缓存：TTL、配额、LRU、并发物化去重、原子发布 | `test_repository_cache.py` |
| GitHub 物化 | `lima/repository_materializer.py` | ref 解析钉死为不可变 SHA、codeload 加固下载、归档预算/防穿越/防 symlink、发布到 RepositoryCache | `test_repository_materializer.py` |
| 有界工作区 | `lima/workspace.py` | 文件枚举、大小预算、敏感路径/符号链接过滤、指纹 | `test_workspace.py` |
| 仓库扫描 | `lima/repository_scanner.py` | AST、数据流、SAST 和规则结果融合 | `test_workspace.py`, `test_sast.py` |
| Python 分析 | `lima/python_analyzer.py`, `lima/python_dataflow.py` | Python AST 与同/跨文件 source-to-sink | `test_python_dataflow.py` |
| SAST | `lima/sast.py` | Bandit 适配、路径校验、结果归一化 | `test_sast.py` |
| 语义复核 | `lima/semantic_retrieval.py`, `lima/repository_triage.py` | 有界候选检索、模型合同、证据仲裁 | `test_semantic_retrieval.py`, `test_repository_triage.py` |
| 修复闭环 | `lima/security_repair.py`, `lima/verifier.py`, `lima/fixer.py` | 约束型补丁、Oracle、测试门禁和 GitHub 发布 | `test_security_repair.py` |
| 只读修复预览 | `lima/repair_preview.py` | 固定快照上的补丁预览，不修改导入仓库 | `test_repository_import.py` |
| GitHub 集成 | `lima/github.py` | Webhook 签名、API 客户端、GitHub App | `test_github.py` |
| Skill | `lima/skills.py`, `lima/skill_runner.py`, `lima/skill_evolution.py` | manifest、签名、隔离运行、回放门禁 | `test_skills.py`, `test_skill_evolution.py` |
| 评测/实验 | `lima/experiments.py`, `lima/real_world_evaluation.py`, `lima/evaluation_harness.py` | 冻结数据集、快照、预算、artifact 和指标 | `test_experiments.py`, `test_real_world_evaluation.py` |
| 前端 | `web/index.html`, `web/app.js`, `web/app.css` | 管理台、任务、扫描、实验和修复预览 | `test_frontend_ui.py`, `node --check` |

经验法则：从对应测试开始读，先找到成功路径和拒绝路径，再进入实现文件。安全模块的
“为什么拒绝”往往比“如何成功”更重要。

## 5. 运行形态与状态存储

| 模式 | 数据库 | 队列 | 默认地址 | 适用场景 |
|---|---|---|---|---|
| 本地主机 | SQLite (`LIMA_DB_PATH`) | 内存 ACK 队列 | `127.0.0.1:8080` | 快速开发、单进程调试 |
| Docker Compose | PostgreSQL | Redis Streams | `127.0.0.1:18080` | 完整工程验证、长期运行 |

配置优先级：进程环境变量 > 项目根目录 `.env` > `lima/.env`。新的配置统一使用
`LIMA_*`；代码会兼容旧 `EVOAGENT_*`，但 `LIMA_*` 同名值始终优先。

Compose 中 `security-agent_postgres_data` 和 `security-agent_redis_data` 是品牌迁移期间
故意保留的外部卷名，用于避免破坏已有数据。不要因为名字旧就重命名或删除。

## 6. 首次环境准备

### 6.1 前置工具

- Git；
- Python 3.11 或 3.12；
- Docker Desktop（推荐，确保 Linux containers 和 Docker Engine 已启动）；
- Node.js（只需执行前端 JavaScript 语法检查）；
- PowerShell 7 或 Windows PowerShell 5.1。

### 6.2 克隆和换行设置（Windows）

```powershell
git clone https://github.com/agent-sec-labs/LIMA.git
Set-Location LIMA
git config --local core.autocrlf false
git config --local core.eol lf
git status --short --branch
```

仓库通过 `.gitattributes` 和 `.editorconfig` 将普通文本统一为 LF，仅 `.bat`、`.cmd`
固定为 CRLF。不要通过关闭 `core.safecrlf` 来隐藏换行问题。

### 6.3 推荐：Docker 快速启动

```powershell
powershell -ExecutionPolicy Bypass -File scripts/lima.ps1 bootstrap
powershell -ExecutionPolicy Bypass -File scripts/lima.ps1 test
powershell -ExecutionPolicy Bypass -File scripts/lima.ps1 up
powershell -ExecutionPolicy Bypass -File scripts/lima.ps1 ps
```

访问 <http://127.0.0.1:18080>。停止和查看日志：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/lima.ps1 logs
powershell -ExecutionPolicy Bypass -File scripts/lima.ps1 down
```

`bootstrap` 生成本地 `.env` 中需要的随机数据库密码、认证密钥和管理员密码；`.env`
不得提交。运行 `up` 会幂等创建兼容数据卷。

### 6.4 可选：主机虚拟环境

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install ruff
python -m lima
```

本地主机默认监听 <http://127.0.0.1:8080>。未配置远程 Provider 时使用确定性本地
Reviewer，不需要任何模型 Key。

## 7. 配置与费用安全

- 永远不要提交 `.env`、Token、私钥、导入仓库、生产报告或个人数据。
- 应用代码的 `LIMA_REPOSITORY_SCAN_LLM_MODE` 安全默认值是 `off`。
- `.env.example` 作为工程联调模板显式写了 `auto`。复制模板并配置真实 Provider 后，
  每次存在候选的仓库扫描可能发生一次有界远程调用。无需语义复核时必须改回 `off`。
- `required` 模式下模型缺失、失败或输出合同无效会使扫描失败；`auto` 会保留本地结果，
  但相关对象降级为 `needs_review`。
- 普通 PR 和 CI 不接收模型 Key，也不得自动运行付费外部评测。
- 真实模型实验必须由管理员显式发起，固定数据集、预算、模型身份和 artifact 路径。

## 8. 标准开发流程

### 8.1 认领任务

1. 在 GitHub Issue 中确认状态、依赖、Ownership 和 Avoid modifying。
2. 只选择未被认领的 `status:ready` Issue。
3. 先留言认领，由维护者分配并更新为 `status:in-progress`。
4. 如果需要修改另一个活跃任务拥有的文件，先在 Epic 中协调。

### 8.2 建立分支

```powershell
git switch main
git pull --ff-only origin main
git switch -c feat/<short-description>
```

按变更类型使用 `feat/`、`fix/`、`docs/` 或 `test/`。每个分支只解决一个逻辑任务。

### 8.3 实现顺序

1. 把 Issue 的 Acceptance criteria 翻译成测试清单。
2. 先写危险输入、权限拒绝、边界/失败用例，再实现成功路径。
3. 保持公共合同小而明确；下载、存储、扫描、修复和发布使用不同权限边界。
4. 更新与用户行为、配置或安全不变量相关的文档。
5. 运行与改动范围匹配的测试和完整门禁，不要只运行新增的单个测试。

### 8.4 提交和 PR

```powershell
git status --short
git diff --check
git diff
git add <明确的文件列表>
git diff --cached --check
git diff --cached
git commit -s -m "feat: describe the logical change"
git push --set-upstream origin <branch-name>
```

PR 必须填写 Summary、Security impact、Verification、Evidence、Experiment integrity 和
Review notes，禁止保留空模板描述直接合并。创建 PR 时必须在描述中使用
`Closes #<issue>`（或 `Fixes #<issue>`）绑定对应 Issue，使其在合并时自动关闭；
Issue 改造完成、`merge-gate` 通过并合并后，必须回头确认对应 Issue 已关闭且第 11 节
状态表已同步，不允许出现已实现的 Issue 长期未关闭的情况。

PR 描述以 [PR #18](https://github.com/agent-sec-labs/LIMA/pull/18) 为基准格式，标题使用
`[T<编号>] <英文祈使句概括>`（非任务类 PR 用 `docs:`/`fix:`/`test:` 前缀）：

```markdown
Closes #<issue>

## Summary

- <动词开头，一条描述一个行为变化或安全不变量，不写叙述性文字>

## Validation

- Ruff <版本>: passed
- Bandit: no issues identified, no skipped findings
- Windows full regression: <N>/<N> passed
- <按改动补充 Docker 定向回归、required-SAST verified-high gate 等>
```

模板小节可按改动性质裁剪（纯文档 PR 可省略 Security impact 与 Experiment
integrity），但 `Closes` 绑定、行为式 Summary 和量化 Validation 三项不可省略，
且 Validation 只允许出现真实运行过的命令与结果。

仓库近期 PR 使用线性 squash 历史；一个逻辑 PR 通常选择 **Squash and merge**。
禁止直接推送、强推或删除 `main`。

## 9. 验证矩阵

### 9.1 所有代码 PR 的基础检查

```powershell
python -m compileall -q lima scripts tests
python -m unittest discover -s tests -v
node --check web/app.js
git diff --check
```

对修改过的 Python 文件运行独立质量和安全检查：

```powershell
python -m ruff check <changed-python-files>
python -m bandit -q <changed-python-files>
```

如果当前环境未安装工具，创建 `.venv` 或临时隔离容器安装后执行；“未安装，因此未运行”
不是完成状态。Bandit 发现的问题必须结合上下文审查，不得为了绿灯盲目增加 `# nosec`。

**当前质量债基线（`main@80b0ee1`）：** 全仓 `ruff check lima scripts tests` 在 Ruff
0.16.5 下会报告 1216 条历史问题，原生 `bandit -q -r lima scripts` 会报告 25 条 Low、
16 条 Medium、0 条 High 并以状态码 1 退出；Ruff 尚未接入 `merge-gate`。这不等于可以
跳过检查，也不应在业务 PR 中批量执行 `ruff --fix` 或增加 blanket `# nosec`。正确做法是：

1. 对本次修改的 Python 文件实际运行 Ruff 和 Bandit；
2. 确保没有新增未解释的问题，并在 PR Evidence 中区分历史基线与新增结果；
3. 全仓格式化、类型现代化和安全告警清理应建立独立 Issue、分批修复并接入 CI；
4. CI 的安全结论以项目扫描器的证据融合和 `--fail-on high --verified-only` 门禁为准，
   但这不能替代对原生 Bandit Medium 告警的人工审查。

### 9.2 与 CI 一致的完整门禁

```powershell
powershell -ExecutionPolicy Bypass -File scripts/lima.ps1 test

python scripts/run_repair_evaluation.py `
  --format json `
  --output output/repair-evaluation.json `
  --min-constraint-accuracy 1.0

python scripts/scan_repository.py . `
  --sast required `
  --format json `
  --exclude-dir tests `
  --exclude-dir evaluation_data `
  --output output/ci-security-audit.json `
  --fail-on high `
  --verified-only
```

GitHub Actions 的稳定 Required Check 是 `merge-gate`。它汇总：

- `quality-contracts`：编译、Node 语法、CI/前端/实验合同；
- `unit-tests`：Windows/Linux × Python 3.11/3.12；
- `repair-constraints`：修复约束准确率必须为 1.0；
- `container-tests`：只读容器和数据卷初始化；
- `security-baseline`：Bandit 必须可用，已验证高危回归失败关闭。

不要把矩阵中的每个动态 Job 名单独设为 Required Check。

### 9.3 按修改领域补充测试

| 修改范围 | 至少运行 |
|---|---|
| Web | `tests.test_frontend_ui` + `node --check web/app.js` |
| API/Service/Auth/Store | `tests.test_service tests.test_production_features`，覆盖成功、拒绝、租户隔离和非法输入 |
| 队列/实验 | `tests.test_production_features tests.test_experiments`，覆盖 ACK、重试、恢复、预算和模糊调用 |
| 仓库来源/导入 | `tests.test_repository_source tests.test_repository_import`，覆盖恶意 URL、路径逃逸和无网络访问 |
| Workspace/扫描/SAST | `tests.test_workspace tests.test_sast tests.test_python_dataflow`，包含危险样本、安全近邻和不确定形态 |
| 语义检索/复核 | `tests.test_semantic_retrieval tests.test_repository_triage tests.test_real_world_evaluation` |
| 自动修复 | `tests.test_security_repair tests.test_repair_evaluation`，包含应修、应拒、Oracle 篡改和目标测试失败 |
| Skill | `tests.test_skills tests.test_skill_evolution`，注意源码 checksum 的 LF 规范化 |
| CI/Docker | `tests.test_ci_contract` + Docker test target，保持只读权限和 Action SHA 固定 |

使用模块名运行精简测试的示例：

```powershell
python -m unittest -v `
  tests.test_repository_source `
  tests.test_repository_import
```

## 10. 不能破坏的安全不变量

### 仓库获取和扫描

- `/repositories` 是管理员提供的有界只读导入根目录，不是任意文件浏览入口。
- 拒绝绝对路径、`..`、隐藏路径段、符号链接/目录联接逃逸。
- 扫描器不得执行仓库代码、安装仓库依赖或触发 Git hooks。
- Workspace 必须保持文件数量、单文件大小、总字节数和 UTF-8 文本限制。
- 远程 V1 只允许 GitHub HTTPS 语义；拒绝 `file://`、SSH、`git://`、任意主机和私网 URL。
- 移动分支/ref 必须先解析为不可变 commit SHA；发布的 Snapshot 不得原地修改。

### 认证、存储和队列

- 所有任务、反馈、记忆、Skill 和仓库权限必须按 tenant 隔离。
- Token、API Key、认证头不得进入任务、报告、缓存 metadata、日志或 artifact。
- Redis 消息只在完成、安全重投或进入 DLQ 后 ACK；基础设施错误应留给租约恢复。
- Webhook 必须验证 HMAC、时间窗、delivery 幂等和 payload 绑定。

### 修复和 GitHub 写操作

- 未验证候选不得触发修复。
- 自动修复要求租户对目标仓库持有显式 `auto_fix` 授权（`POST /v1/repository-grants`）；
  零授权租户对 `/v1/tasks/{id}/fix` fail-closed，只读审查不受影响。
- GitHub App installation 登记只能由 `manage` 权限通过 `POST /v1/github/installations`
  完成（`GET /github/setup` 仅做无副作用重定向，登记绑定注册者租户并写入审计）。
- 修复模板必须保持 CWE 专属不变量和最小 diff。
- 编译、独立安全 Oracle、全仓差分复扫、授权仓库原生测试任一失败时，不得产生 GitHub 写操作。
- 普通本地修复不能修改源 Snapshot、`/repositories` 或远程 GitHub。
- 分支、commit、Draft PR 发布必须是后续显式权限边界，不得隐藏在扫描/预览流程中。

### 评测完整性

- 冻结 holdout 的 commit、归档 SHA-256、标签、顺序和 analyzer fingerprint 不得为通过测试而篡改。
- 分析器漂移导致旧 holdout 拒绝运行，属于安全门禁生效；应创建明确标注的 calibration 数据或新的 repository-disjoint holdout。
- 外部评测不能执行目标仓库代码，也不能在普通 CI 中联网或产生模型费用。

## 11. 当前 Epic 和可接手任务

状态快照日期：**2026-08-28**。开始工作前请重新打开
[Epic #17](https://github.com/agent-sec-labs/LIMA/issues/17) 核对实时标签、负责人和评论。

| 任务 | 当前状态 | 交接说明 |
|---|---|---|
| [T1 #10](https://github.com/agent-sec-labs/LIMA/issues/10) RepositorySource | Closed | PR #18 已合并；契约在 `repository_source.py`，不得在此层联网或物化文件 |
| [T2 #11](https://github.com/agent-sec-labs/LIMA/issues/11) GitHub Materializer | 本地已实现 | 契约在 `repository_materializer.py`（ref 钉死/加固下载/发布到 RepositoryCache）；未接服务编排，接线属于 T4 |
| [T3 #12](https://github.com/agent-sec-labs/LIMA/issues/12) Snapshot Cache | Closed | PR #23 已合并；契约在 `repository_cache.py`（lookup/reserve/publish/touch/pin/cleanup/stats）；`LIMA_REPOSITORY_CACHE_*` 配置已定义但 T4 接线前不生效 |
| [T4 #13](https://github.com/agent-sec-labs/LIMA/issues/13) Async Scan Integration | 本地已实现 | worker 侧 github 物化 + pin + 扫描；`LIMA_REPOSITORY_SCAN_SOURCES` 门禁；缓存命中零网络 |
| [T5 #14](https://github.com/agent-sec-labs/LIMA/issues/14) Runtime Storage | 本地已实现 | `lima-repository-cache` 具名卷挂载 `/var/lib/lima/repository-cache`（跨副本共享）；`lima-repair-workspace` 卷声明保留给 T7，不挂载 lima 服务；`__ephemeral__` 魔值 → tmpdir；unmanaged 缓存根启动告警 |
| [T6 #15](https://github.com/agent-sec-labs/LIMA/issues/15) GitHub Source UI | 本地已实现 | 扫描向导支持 GitHub 来源（capabilities 门禁、ref 钉死警告、`{"source": {...}}` envelope、报告展示 resolved_revision）；浏览器零 `api.github.com` 调用 |
| [T7 #16](https://github.com/agent-sec-labs/LIMA/issues/16) RepairWorkspace | 本地已实现 | 契约在 `repair_workspace.py`（compose 持 pin/子集拷贝/预算/fail-closed/dispose 幂等）；service 仅薄接线 `compose_repair_workspace`；compose 挂载 `lima-repair-workspace` 卷；未接 GitHub 写 API，未修改源 Snapshot |

依赖关系：

```text
T1（已完成） ──► T2 ──┐
             └─► T3 ──┼──► T4
             └─► T6   │
T5 ─────────────► T2 / T3 / T7
Snapshot contract ─────► T7
```

准备接手 T5/T6/T7 时，先在 Issue 留言；不要因为代码看起来独立就跳过认领流程。

## 12. 常见误区和排障入口

### “输入了 GitHub URL，为什么仍提示本地仓库不存在？”

当前 UI 会让人误以为后端已经支持远程 GitHub 仓库，但正式物化链路尚未完成。当前
`POST /v1/repository-scans` 仍以本地 `repository_key` 调用 `RepositoryImportPolicy`。
使用现有功能时，必须先把授权仓库放到 `repositories/team/project`，再提交 `team/project`。

### `repositories/README.md` 中为什么出现 `EVOAGENT_REPOSITORY_IMPORT_PATH`？

这是品牌迁移兼容名称。新配置统一使用 `.env.example` 中的
`LIMA_REPOSITORY_IMPORT_PATH`；代码暂时会把旧 `EVOAGENT_*` 提升到新的命名空间。

### `required SAST engine bandit is unavailable`

当前命令选择了 `--sast required`，Bandit 缺失时必须失败关闭。确认运行命令所用的
Python 环境已经执行 `python -m pip install -r requirements.txt`，或使用项目 Docker 镜像。
不要改成 `auto` 来伪造 CI 通过。

### Docker 启动时报外部 volume 不存在

先运行：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/lima.ps1 bootstrap
powershell -ExecutionPolicy Bypass -File scripts/lima.ps1 up
```

`up` 会幂等创建两个兼容卷。不要手动删除已有卷，因为其中可能有任务、账号和队列数据。

### 修改 bootstrap 管理员密码后仍无法登录

Bootstrap 管理员只在用户名尚不存在时创建。已有同名用户的密码不会在重启时被覆盖。
检查实际连接的是 SQLite 还是 PostgreSQL，以及是否复用了旧数据卷。

### 扫描结果比预期少

检查报告中的 `workspace.truncated`、`file_coverage`、`byte_coverage` 和 `skipped`。
Workspace 会跳过敏感配置、二进制、非 UTF-8、符号链接、超限文件和低优先级目录。
不要在未读诊断信息前先扩大资源上限。

### PowerShell 出现 `LF will be replaced by CRLF`

```powershell
git config --local core.autocrlf false
git config --local core.eol lf
git add --renormalize .
git status --short
```

执行 `--renormalize` 后若出现大量非预期修改，先停止提交并检查 `.gitattributes`；不要
用关闭安全警告的方式掩盖问题。

## 13. PR 完成定义

一个 PR 只有同时满足下列条件才算完成：

- 对应 Issue 已认领、依赖已满足、修改未越过 Ownership 边界；
- 验收条件都能映射到代码或测试证据；
- 危险输入、安全近邻、权限拒绝和失败路径有回归测试；
- Ruff、Bandit、相关单测、完整单测和适用的 Docker/安全门禁实际运行，新增问题均已解决
  或在 Evidence 中给出可复核解释；
- 没有秘密、私有仓库、个人数据、无解释生成物或付费调用；
- 用户可见行为、配置和安全不变量已更新文档；
- PR 描述记录命令、结果、已知限制、迁移影响和评测指纹影响；
- `merge-gate` 全部通过，评审意见和对话已解决，Code Owner 已批准。

## 14. 下次交接时需要更新什么

交接人离开任务前，应更新本文顶部基线和第 11 节状态，并留下：

1. 已合并、待评审、进行中和 blocked 的 Issue/PR 链接；
2. 当前分支、最后一个安全提交和未提交文件；
3. 实际运行过的验证命令、通过/失败结果和 artifact 位置；
4. 新增配置、数据库/卷迁移和回滚方式；
5. 已知缺陷、临时兼容逻辑和不能删除的历史资产；
6. 真实模型调用、费用、数据集身份和 fingerprint 变化；
7. 下一位开发者可以立即执行的最小下一步。

不要只写“CI 通过”或“功能完成”。一份合格的交接必须让下一位开发者无需私聊原作者，
就能复现环境、理解风险、找到代码入口并判断任务是否真的完成。
