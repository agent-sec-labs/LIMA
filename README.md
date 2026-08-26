# 砺码 · LIMA

<p align="center"><img src="web/lima-mark.svg" width="88" alt="砺码 LIMA Logo"></p>

**LIMA — LLM-powered Intelligent Mining & Auto-repair for Repositories**

砺码 LIMA 是面向研发团队、安全工程师与应用安全研究者的仓库级安全 Agent。项目按 **工程 70% / 科研 30%** 推进，主链路是：

> 代码/PR 获取 → 静态分析候选 → 数据流/多工具证据确认 → 结构化审计报告 → 最小修复 → 隔离验证 → 人工审批

首个可交付版本聚焦 Python 仓库和命令注入、路径遍历、SQL 注入、危险反序列化、认证/授权误用、敏感信息泄漏等常见高风险问题。默认本地模式不调用任何远程模型；LLM 是可选的语义增强层，不是事实来源。证据不足的结果会降级为人工复核，不追求“全语言、全 CWE、零误报、自动发现通用零日”等当前不可信的目标。

完整定位、论文证据和实施阶段见 [LIMA_ROADMAP.md](LIMA_ROADMAP.md)。从旧版本升级时，
请同时阅读 [品牌与配置迁移说明](docs/LIMA_BRAND_MIGRATION.md)。
Logo 的设计语义、色彩与使用规范见 [品牌视觉规范](docs/LIMA_BRAND_ASSETS.md)。

> 以证据审代码，以闭环修漏洞。Audit with evidence. Repair with confidence.

- 审查统一 diff，输出结构化问题、修复建议和测试建议
- GitHub `pull_request` webhook（`opened`、`reopened`、`synchronize`）
- OpenAI 兼容模型；未配置模型时自动使用确定性的本地规则审查器
- SQLite 保存任务状态、执行轨迹和最终报告
- JSON API 与 Markdown 报告
- webhook HMAC-SHA256 签名校验，以及可选的 GitHub PR 评论回写
- Web 管理台、任务 Dashboard 与 Prometheus 指标
- 安全、可靠性、AI 和动态 Skill Agent 并行协作
- 独立分支上的保守型自动修复提交
- PostgreSQL、Redis 生产模式
- 失败案例回流、提示词评测、版本激活与回滚
- 自研 Agent Runtime、持久化 checkpoint、执行预算与任务断点续跑
- 带 Tool Registry、参数 Schema 校验和结构化 Observation 的有界 Agent Loop
- 覆盖任务、工具、反馈、记忆、观察与 Diff 的统一 Context Window 和逐轮压缩
- Working/Episodic/Semantic 分层记忆、租户级检索、任务归档与过期清理
- Redis Streams ACK、Worker 租约、指数退避重试和死信队列
- Webhook delivery 幂等、重放时间窗与评论 upsert
- 用户登录、RBAC、租户/仓库隔离和不可变管理审计
- 动态 Skill manifest 校验、签名校验和隔离进程沙箱
- 自动修复后的编译/测试门禁、灰度发布与影子流量
- OpenTelemetry Trace、Prometheus 指标和持久化告警
- Python 跨文件静态 import def-use/source-to-sink 验证，覆盖动态执行、命令、SQL、危险反序列化与路径汇点
- 自动修复资格门禁：候选告警不得直接改代码，只有已验证且受支持的确定性规则可以进入修复
- CWE-78/CWE-89/CWE-22 约束型最小修复：argv 去 shell、驱动参数化 SQL、规范化路径根目录包含校验
- 修复发布闭环：不可变 commit SHA 取件、独立 AST Oracle、全仓前后差分复扫、原生测试和 Draft PR 人工审批
- 快照固定的只读修复预览：管理台展示最小 diff、根因、不变量、Oracle 和拒修理由，不修改导入仓库
- 可复现修复约束评测：按 CWE 统计验证修复率、正确拒修率、Oracle 通过率和不安全补丁逃逸率

## 快速开始

推荐使用 Docker 隔离运行。首次启动会生成仅保存在本机 `.env` 中的随机数据库密码、认证密钥和管理员密码，不会生成或调用远程 LLM API Key：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/lima.ps1 bootstrap
powershell -ExecutionPolicy Bypass -File scripts/lima.ps1 test
powershell -ExecutionPolicy Bypass -File scripts/lima.ps1 up
```

启动后用 bootstrap 输出的管理员账号访问 `http://127.0.0.1:18080`。主机端口可通过 `.env` 中的 `LIMA_HTTP_PORT` 修改，容器内部端口保持 `8080`。常用操作：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/lima.ps1 ps
powershell -ExecutionPolicy Bypass -File scripts/lima.ps1 logs
powershell -ExecutionPolicy Bypass -File scripts/lima.ps1 repair-eval -Format markdown
powershell -ExecutionPolicy Bypass -File scripts/lima.ps1 down
```

容器中的应用以固定非 root 用户运行，根文件系统只读，丢弃 Linux capabilities，并只把 Web 端口绑定到本机。

项目镜像默认从 AWS Public ECR 的 Docker Official Images 镜像拉取，并锁定 manifest digest，以规避部分网络环境中 `auth.docker.io` 的 DNS/IPv6 连接异常，同时避免使用来源不明的公共镜像站。

无需服务、数据库或 API Key，也可以先对本地授权仓库运行确定性安全基线：

```powershell
python scripts/scan_repository.py D:\path\to\repository --sast auto --format markdown --output output\audit.md
python scripts/scan_repository.py D:\path\to\repository --sast required --format json --fail-on high --verified-only
python scripts/scan_repository.py . --exclude-dir tests --exclude-dir evaluation_data
```

扫描器不会跟随符号链接，默认忽略 `.git`、虚拟环境、依赖/构建/输出目录、服务端仓库导入区和 `.env`，并限制文件数、单文件大小与总读取量。数据集和测试夹具可用重复的 `--exclude-dir` 排除。`--fail-on` 可用于 CI 安全门禁；`--verified-only` 让门禁只处理 `syntax-verified`、多工具印证、数据流验证或人工确认的 Finding，避免未验证候选直接阻断流水线。Python 使用 AST、有界数据流与 Bandit 混合检测，并按 `path + line + CWE` 融合证据。`--sast auto` 在工具不可用时安全降级，`--sast required` 适合要求 SAST 必须成功的 CI。

当前数据流验证会一次性解析仓库内所有 Python 文件，并支持模块顶层函数之间的同文件调用和静态跨文件导入：`import module`、`import module as alias`、`from module import function` 及包内相对导入。它会追踪 Web/CLI/环境来源、赋值、字符串/路径变换、实参到形参、辅助函数返回值和五类危险汇点，证据中的每一步均保留真实文件与行号。调用深度默认限制为 4；循环调用、深度超限、名称遮蔽、重复模块名、动态导入和无法解析的调用会被统计并保守降级，不会误标为 `dataflow-verified`。当前不解析类方法、运行时猴子补丁、通配符导入和反射派发。

四组精简基线可以直接复现：

```powershell
# AST-only
python scripts/scan_repository.py D:\path\to\repository --sast off --dataflow off
# AST + Bandit
python scripts/scan_repository.py D:\path\to\repository --sast required --dataflow off
# AST + repository dataflow
python scripts/scan_repository.py D:\path\to\repository --sast off --dataflow on
# Hybrid + Verifier（默认工程配置）
python scripts/scan_repository.py D:\path\to\repository --sast required --dataflow on
```

推荐直接使用隔离容器扫描任意本地授权仓库；目标仓库只读挂载，扫描容器禁用网络并丢弃全部 capabilities，报告默认写入项目的 `output` 目录：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/lima.ps1 scan `
  -Repository D:\path\to\repository -Format markdown -Sast required -Dataflow on `
  -FailOn high -VerifiedOnly -ExcludeDir tests,evaluation_data
```

### 服务端仓库扫描

管理台现在提供“仓库扫描”入口，并将扫描状态、Finding、CWE、多来源证据和验证状态持久化到任务中心。为了避免任意服务器文件读取，API 不接受绝对路径，只接受管理员预先配置目录下的相对 `repository_key`。

Docker 默认把项目的 `repositories` 目录只读挂载为导入根目录。使用步骤：

1. 将有权审计的项目放入 `repositories\\team\\project`，或在 `.env` 中将 `LIMA_REPOSITORY_IMPORT_PATH` 指向单独的宿主机目录。
2. 重新运行 `powershell -ExecutionPolicy Bypass -File scripts/lima.ps1 up`。
3. 登录管理台，在“仓库扫描”中提交 `team/project`。
4. 扫描成功后，在任务报告中点击“生成修复预览”；预览只处理已验证的 CWE-22/78/89 Finding，不写入目标目录。

只有拥有 `manage` 权限的管理员可以创建扫描任务。绝对路径、`..`、隐藏目录段和解析后逃逸导入根目录的符号链接/目录联接会被拒绝。扫描器不会导入或执行目标仓库代码，并受文件数、单文件大小和总读取量限制。

对应 API：

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:18080/v1/repository-scans `
  -Headers $headers -ContentType 'application/json' `
  -Body (@{repository_key='team/project'} | ConvertTo-Json)
```

扫描任务会保存路径和内容哈希组成的仓库快照指纹。修复预览前会重新计算指纹；扫描后只要目标仓库发生变化，旧任务就会拒绝生成补丁，必须重新扫描。预览只执行编译、AST 安全 Oracle 和全仓静态差分复扫，并明确返回 `publication_ready=false`；原生测试、原子 commit 和 Draft PR 仍只在 GitHub PR 修复闭环执行。

#### 可选的生产语义复核

应用在变量缺失时采用安全缺省值 `LIMA_REPOSITORY_SCAN_LLM_MODE=off`，不会因为只配置了通用 LLM Provider 就自动产生费用。当前 `.env.example` 已显式选择 `auto` 作为工程联调模板；复制模板后会对每项存在候选的仓库扫描产生一次有界远程调用。部署者必须在知晓代码证据会发送给所选模型供应商后保留 `auto`，否则应改回 `off`。启用“语义候选 → 模型批量 verdict → 混合仲裁”时使用：

```env
LIMA_REPOSITORY_SCAN_LLM_MODE=auto
LIMA_REPOSITORY_SCAN_LLM_TIMEOUT_SECONDS=60
LIMA_REPOSITORY_SCAN_LLM_MAX_CANDIDATES=6
LIMA_REPOSITORY_SCAN_LLM_MAX_CONTEXT_CHARS=36000
LIMA_REPOSITORY_SCAN_LLM_MAX_COMPLETION_TOKENS=3000
```

`auto` 对每项仓库扫描最多执行一次有界批量请求；超时、网络失败、缺失 verdict 或输出契约无效时，任务仍保存本地扫描结果，但相关对象强制进入 `needs_review`，绝不自动放行。`required` 使用相同预算，但模型失败会使扫描任务失败；该失败属于永久失败，不会由任务队列重复请求并增加费用。发送给模型的证据上下文只包含选中的 Python 函数片段，不包含 API Key、`.env`、完整仓库或被忽略路径；API Key 仅作为供应商请求的认证头使用，报告只保存供应商、模型、Token 用量、时延、Prompt 哈希和有界证据摘要。

只有确定性 mitigation 不变量与有效模型 clean verdict 对全部评估对象一致时，`auto_clear` 才可能为 `true`。模型单方面声称 clean、没有语义候选或零 Finding 都不是安全证明。

#### 脱离 ChatGPT 的持久化外部实验

LIMA 可以把 repository-disjoint 数据集作为后台实验提交给独立的 `lima:experiment:stream`。实验由 PostgreSQL/SQLite 记录状态，由 Redis Streams 或本地 ACK 队列交付；浏览器、PowerShell 或 ChatGPT 退出后不影响已启动任务。Docker Compose 将最终和中间 artifact 写入宿主机 `output/experiments/<run-id>`，固定快照缓存保存在独立 Docker volume。

管理员登录网页后可直接进入“外部评测”：三步选择已审核数据集、确定性/检索/真实 LLM 模式和不可变预算。页面每 5 秒读取数据库状态，以进度条、预算卡片、逐案例表格和自然语言指标显示结果；取消、断点恢复和可能重复计费的模糊 LLM 重试均有明确二次确认。“一键加载示例”只在浏览器演示，不创建任务、不调用远程服务。

```powershell
$body = @{
  dataset = 'popular_external_holdout_v2.json'
  mode = 'llm-retrieval'
  max_llm_calls = 20
  max_total_tokens = 100000
} | ConvertTo-Json

$experiment = Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:18080/v1/experiments `
  -Headers $headers -ContentType 'application/json' -Body $body

Invoke-RestMethod -Headers $headers `
  "http://127.0.0.1:18080/v1/experiments/$($experiment.run_id)"
```

Runner 按案例执行“固定快照 → 扫描/检索 → 可选 LLM → 原子 artifact”，已完成案例在恢复和最终聚合时不会再次扫描或调用模型。模型请求发出后若进程在结果落盘前中断，案例会进入 `AMBIGUOUS`、实验进入 `NEEDS_ATTENTION`；系统不会自动重试并产生重复费用。管理员确认后才能向 `/v1/experiments/{id}/resume` 提交 `{"allow_ambiguous_retry":true}`。预算属于冻结实验身份；预算耗尽后必须创建更高预算的新实验，不能修改原运行。API Key、`.env` 和认证头不进入数据库或实验包。

5 仓库 v2 清单的选样证据、固定 commit、归档 SHA-256、资源排除项、预注册顺序和冻结基线见 [v1.6 外部评测预注册与结果](docs/V1_6_EXTERNAL_HOLDOUT_PREREGISTRATION.md)。两个冻结实验已经结束；其逐例结果已用于改进 v1.7，因此原 v2 清单只保留为历史 external baseline，后续复跑使用明确标注的 calibration 副本，不能重新宣称外部泛化。检索根因、实现变更和校准指标见 [v1.7 检索校准报告](docs/V1_7_RETRIEVAL_CALIBRATION.md)。下一次外部结论必须冻结全新的 repository-disjoint v3。

多人协作的分层 CI、Required Check 与按修改类型选择测试的方法见 [GitHub 多人协作门禁](docs/GITHUB_COLLABORATION.md)。普通 PR 不注入模型 Key，也不会触发付费外部评测；管理员只需把稳定的 `merge-gate` 设置为 Required Status Check。

如果不使用 Docker，请创建独立虚拟环境：

项目使用 Python 3.11。先安装锁定范围内的运行依赖，并在同一个 PowerShell 窗口中配置本地管理员：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

$bytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$env:LIMA_AUTH_REQUIRED = 'true'
$env:LIMA_AUTH_SECRET = [Convert]::ToBase64String($bytes)
$env:LIMA_BOOTSTRAP_ADMIN_USERNAME = 'admin'
$env:LIMA_BOOTSTRAP_ADMIN_PASSWORD = '<替换为至少 10 个字符的密码>'

python -m lima
```

不要直接使用示例占位符作为密码或密钥。环境变量只对当前 PowerShell 及其子进程生效；修改配置后需要停止并重新启动 LIMA。

Bootstrap 管理员只在用户名尚不存在时创建；已有同名用户的密码不会在重启时被覆盖。

非 Docker 模式默认监听 `127.0.0.1:8080`；Docker Compose 模式默认访问 `http://127.0.0.1:18080/`。前端会在业务 API 返回未授权状态后显示登录层。登录状态保存在当前浏览器的 `localStorage` 中；需要重新登录时可以点击退出，或清除站点数据。

API 调用需要先登录并携带 Bearer Token：

```powershell
$session = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/v1/auth/login `
  -ContentType 'application/json' `
  -Body (@{username='admin'; password='<你的密码>'} | ConvertTo-Json)
$headers = @{Authorization="Bearer $($session.access_token)"}
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/v1/reviews `
  -Headers $headers `
  -ContentType 'application/json' `
  -Body (@{
    repository = 'demo/api'
    pull_request = 12
    diff = "diff --git a/app.py b/app.py`n--- a/app.py`n+++ b/app.py`n@@ -1 +1,2 @@`n+password = 'secret'`n+eval(user_input)"
  } | ConvertTo-Json)
```

查询任务：

```powershell
Invoke-RestMethod -Headers $headers http://127.0.0.1:8080/v1/tasks/<task-id>
Invoke-WebRequest -Headers $headers http://127.0.0.1:8080/v1/tasks/<task-id>/report
```

运行测试：

```powershell
python -m unittest discover -s tests -v
```

## 模型配置

默认 `LIMA_LLM_PROVIDER=local`，此时只运行确定性的本地规则 Agent，不会调用大模型。

DeepSeek 官方 API（按 Token 计费）：

```powershell
$env:LIMA_LLM_PROVIDER = 'deepseek'
$env:LIMA_DEEPSEEK_API_KEY = '<deepseek-api-key>'
python -m lima
```

通过 OpenRouter 使用有速率限制、可用性可能变化的 DeepSeek 免费模型：

```powershell
$env:LIMA_LLM_PROVIDER = 'openrouter-deepseek-free'
$env:LIMA_OPENROUTER_API_KEY = '<openrouter-api-key>'
python -m lima
```

如果指定的免费 DeepSeek 版本下线，可将 `LIMA_LLM_MODEL` 改为 OpenRouter 当前提供的其他 `:free` 模型，或把 Provider 改为 `openrouter-free` 让免费路由自动选择可用模型。

任意其他 OpenAI Chat Completions 兼容端点使用 `custom`：

```powershell
$env:LIMA_LLM_PROVIDER = 'custom'
$env:LIMA_LLM_BASE_URL = 'https://example.com/v1'
$env:LIMA_LLM_API_KEY = '<token>'
$env:LIMA_LLM_MODEL = '<model-name>'
```

密钥只通过环境变量读取，不要提交到仓库。

项目启动时会自动读取项目根目录的 `.env`，也兼容 `lima/.env`；系统环境变量优先于 `.env` 文件。推荐将以下内容写入根目录 `.env`（该文件已被 `.gitignore` 忽略）：

```env
LIMA_LLM_PROVIDER=deepseek
LIMA_DEEPSEEK_API_KEY=你的真实APIKey
```

## 评测与提示词进化

服务启动时会建立基础验证集和隐藏回归集。候选提示词不会接受调用方提供的“回归分数”作为上线依据，而是：

1. 使用当前提示词和候选提示词分别回放同一批验证 Diff；
2. 计算精确率、召回率、F1、严重级别正确率、高风险召回率、干净样本正确率和执行成功率；调用失败会按漏报或失败的干净样本计分；
3. 候选必须在验证集达到最小提升，并通过隐藏集的分数、精确率、召回率和高风险召回率非退化门禁；
4. 没有配置大模型，或验证集、隐藏集样本不足时只保存候选，状态为 `deferred`；
5. 评测记录包含提示词和数据集 SHA-256 指纹，隐藏集只持久化聚合指标，不暴露案例明细；
6. 没有新增有效反馈信号时不会重复创建内容相同的候选版本；
7. 所有评测运行、版本、指标和激活决定均持久化，可回滚。

可通过 `POST /v1/evaluation/cases` 增加版本化样本，`split` 支持 `train`、`validation` 和 `holdout`。样本名称和内容绑定且不可覆盖；修订样本必须使用新名称，重复提交相同内容则保持幂等。期望结果可选填 `rule_id`，用于避免“同一行但错误类别”的结果被算作命中。`POST /v1/evolution/auto` 会从未解决反馈生成候选并执行同样的真实回放门禁。

仓库还提供可复现的受控离线进化证明：它只从 Validation 仓库的确认漏报中提取经过格式校验的 `rule_id`，自动生成 Prompt v2，然后在仓库完全隔离的 Holdout 上回放并保存真实版本链、`evolution_runs`、数据指纹和报告：

```powershell
python scripts/run_prompt_evolution_proof.py
```

输出位于 `output/prompt-evolution-proof/`。该实验用于证明“反馈驱动的提示词版本确实改变 Agent 行为并通过隐藏集门禁”，数据来源仍是 `synthetic-controlled`，因此生产来源门禁保持失败；它不应被表述为外部 LLM 权重提升或真实公开 PR 上的生产效果。

## Skill 自进化

Skill 自进化与提示词进化是两套独立版本链。系统不会把反馈直接拼成 Python 执行，而是生成无主机权限的声明式 Skill artifact。artifact 可以新增确认漏报规则或移除确认误报规则，并包含父版本、内容 SHA-256、评测分数和激活状态。

`POST /v1/skill-evolution/auto` 从当前租户未解决反馈生成候选。漏报反馈应携带 `finding.rule_id`、`severity`、`path` 和 `line`；系统优先使用 `finding.evidence`，缺失时从原任务 Diff 的对应新增行提取字面匹配证据。候选只有在 Validation 获得最小提升、受保护指标不退化且 Holdout 非退化时才会自动激活并解析所使用的反馈。被拒绝或样本不足的版本仍会保存供审计，但不会进入审查链路。

也可以向 `POST /v1/skill-evolution/propose` 提交人工构造的候选：

```json
{
  "skill_name": "evolved-review",
  "artifact": {
    "name": "evolved-review",
    "description": "Confirmed project-specific review rules",
    "rules": [{
      "rule_id": "SEC-DANGEROUS-CALL",
      "severity": "high",
      "match": "dangerous_call(data)",
      "title": "Dangerous call",
      "explanation": "A confirmed unsafe API was added.",
      "fix": "Use the constrained API.",
      "test": "Add a regression test."
    }]
  }
}
```

激活后服务会把 `evolved-review@<version>` 作为真实 specialist 加入当前租户的 `MultiAgentCoordinator`。artifact、激活版本、进化运行和运行时注入均按租户隔离；重启、`/v1/skills/reload` 和版本回滚都会从数据库恢复相应 artifact。Skill 名称必须以 `evolved-` 开头，规则只支持新增行上的受限字面匹配，不支持任意代码、正则表达式或主机权限。

相关门禁可通过以下环境变量调整：

- `LIMA_EVAL_MIN_CASES`：验证集最少样本数；
- `LIMA_EVAL_MIN_HOLDOUT_CASES`：隐藏集最少样本数；
- `LIMA_EVAL_MAX_CASES`：每个数据分区单次最多回放样本数；
- `LIMA_EVAL_MIN_IMPROVEMENT`：验证集最小分数提升；
- `LIMA_EVAL_MAX_METRIC_REGRESSION`：受保护指标允许的最大退化，默认 `0`。

## GitHub Webhook

项目使用“GitHub 仓库 Webhook + 公网转发 + fine-grained PAT”接收 PR 事件，不需要创建或安装 GitHub App：

```text
GitHub Pull request 事件
        │
        ▼
https://<公网域名>/webhooks/github
        │  公网转发
        ▼
http://127.0.0.1:8080/webhooks/github
        │
        ▼
LIMA 创建异步审查任务
```

### 1. 配置 LIMA

先生成一个 Webhook Secret，并根据需要配置 GitHub fine-grained personal access token：

```powershell
$webhookBytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($webhookBytes)
$env:LIMA_GITHUB_WEBHOOK_SECRET = [Convert]::ToBase64String($webhookBytes)

# 私有仓库、PR 评论回写或自动修复需要；只审查公开仓库且不回写时可以不配置。
$env:LIMA_GITHUB_TOKEN = '<GitHub fine-grained PAT>'

# 默认关闭。设为 true 后，审查完成时更新或创建 PR 评论。
$env:LIMA_AUTO_POST_REVIEW = 'true'

python -m lima
```

Webhook Secret 用于验证 GitHub 请求头中的 HMAC-SHA256 签名，不能与登录用的 `LIMA_AUTH_SECRET` 混用。Webhook 请求不携带管理台 Bearer Token；`/webhooks/github` 使用签名而不是用户登录进行认证。

fine-grained PAT 只授权需要接入的仓库，并按功能授予最小权限：

- 读取私有仓库 PR Diff：`Contents: Read`、`Pull requests: Read`；
- 回写审查评论：`Pull requests: Read and write`；
- 创建自动修复分支和提交：`Contents: Read and write`、`Pull requests: Read and write`。

只接收 Webhook 但不访问私有仓库、不回写评论且不执行自动修复时，可以不设置 PAT。密钥必须在启动 LIMA 前设置，修改后需要重启服务。

### 2. 建立公网转发

GitHub 无法访问 `127.0.0.1`，需要把公网 HTTPS 地址转发到本地 `http://127.0.0.1:8080`。任选一种已安装的转发工具，例如：

```powershell
# Cloudflare Quick Tunnel
cloudflared tunnel --url http://127.0.0.1:8080

# 或 ngrok
ngrok http 8080
```

命令启动后会显示一个形如 `https://example.trycloudflare.com` 或 `https://example.ngrok-free.app` 的公网 HTTPS 地址。保持 LIMA 和转发进程同时运行。临时公网地址通常会在转发工具重启后变化，变化后必须同步更新 GitHub Webhook 的 Payload URL。

上述快捷转发会把 8080 端口上的管理台和 API 一并暴露到公网，因此必须保持 `LIMA_AUTH_REQUIRED=true`，并使用强管理员密码和随机 `LIMA_AUTH_SECRET`。长期部署建议通过反向代理只公开 `/webhooks/github`（以及按需公开 `/health`），不要向公网暴露整个管理台。

### 3. 在 GitHub 仓库中添加 Webhook

进入目标仓库的 **Settings → Webhooks → Add webhook**，填写：

- **Payload URL**：`https://<公网域名>/webhooks/github`；
- **Content type**：`application/json`；
- **Secret**：与 `LIMA_GITHUB_WEBHOOK_SECRET` 完全相同；
- **SSL verification**：保持启用；
- **Which events would you like to trigger this webhook?**：选择 **Let me select individual events**，只勾选 **Pull requests**；
- **Active**：保持勾选。

LIMA 会处理 `opened`、`reopened` 和 `synchronize` 三种 PR 动作；其他 `pull_request` 动作会正常接收但被忽略。服务会根据 payload 中的 `diff_url` 下载 Diff，并异步创建审查任务。

### 4. 验证连接

先确认本地服务和公网地址都能访问健康检查：

```powershell
Invoke-RestMethod http://127.0.0.1:8080/health
Invoke-RestMethod https://<公网域名>/health
```

然后新建 PR、重新打开 PR，或向 PR 推送一次提交。在 GitHub 的 **Settings → Webhooks → Recent Deliveries** 中应看到 `/webhooks/github` 返回 `202`；管理台的任务中心随后会出现对应审查任务。如果失败，优先检查公网转发进程是否仍在运行、Payload URL 是否包含 `/webhooks/github`、Secret 是否一致，以及 PAT 是否有目标仓库权限。

默认只在管理台保存结果。只有 `LIMA_AUTO_POST_REVIEW=true` 时才会向 PR 回写评论。

自动修复只覆盖可以证明安全不变量的窄形态。CWE-78 仅处理固定可执行文件和独立动态参数，生成 argv 并显式设置 `shell=False`；CWE-89 仅处理能够确定 DB-API 参数风格、且动态内容只处于值位置的 `execute`；CWE-22 仅处理有模块级静态根目录或 `lima: trusted-path-root=<name>` 审计注解的路径拼接。动态命令、Shell 运算符、动态表/列名、未知数据库驱动、未证明可信的根目录会明确 abstain，不做猜测性修改。

安全类修复必须配置目标仓库的回归测试命令，例如在 `.env` 中设置：

```dotenv
LIMA_REPAIR_TEST_COMMAND=python -m unittest discover -s tests
```

未配置测试命令时，检测和补丁规划仍可工作，但 CWE-78/CWE-89/CWE-22 修复会在发布门禁处失败，不会创建 commit 或 PR。发布前依次执行编译、独立 AST 安全 Oracle、完整仓库差分复扫和原生测试；全部通过后才从固定的 PR commit SHA 创建单个原子提交与 Draft PR，仍需人工批准。CWE-22 模板会在解析符号链接后检查规范路径包含关系，但无法跨平台消除“检查后到打开前”文件系统并发变更的 TOCTOU 风险；高对抗文件系统场景还需要 OS 沙箱或 descriptor-relative open。

### 修复约束评测

使用固定数据指纹的一键评测：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/lima.ps1 repair-eval `
  -Format markdown -Output output\repair-evaluation.md
```

v1 数据集包含 18 个 synthetic-controlled 用例：CWE-22、CWE-78、CWE-89 各 6 个，每类包含 3 个应修和 3 个应拒场景。当前 Windows 与无网络只读 Docker 结果一致：验证修复率 100%、正确拒修率 100%、Oracle 通过率 100%、不安全补丁逃逸率 0%。这些指标只评估“Finding 已经被数据流或人工确认后”的修复约束，不代表真实仓库检测召回率或通用漏洞修复率；真实样本扩展仍是下一阶段工作。

### 真实项目成对评测

`evaluation_data/real_world_security_cases.json` 固定了三个公开漏洞及其修复版本：aiohttp CVE-2024-23334（CWE-22）、Django CVE-2020-7471（CWE-89）和 GitPython CVE-2026-42215（CWE-78）。每个样本同时固定漏洞 commit、修复 commit、GitHub codeload 归档 SHA-256、已知修复文件和上游来源。归档哈希不一致、路径穿越、压缩炸弹或符号链接都不会进入扫描工作区。

一键运行公开快照获取、快速全仓库成对扫描和断网真实项目 Oracle：

```powershell
Set-Location D:\BaseAIProject\LIMA
powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 real-eval
```

结果写入：

- `output/real-world-fetch.json`
- `output/real-world-fast-baseline.json`
- `output/real-world-retrieval.json`
- `output/real-world-oracles.json`

首轮 v1.2 pilot 的确定性结果是：3 个漏洞的已知文件召回率 0%、修复版本特异度 100%、成对区分率 0%。Linux 命名卷快速 AST 档总耗时约 7.65 秒；直接使用 Windows 快照缓存约 39 秒；深度 AST + 跨文件数据流档约 221 秒。现有分析器仍未覆盖框架路径规范化、ORM 参数表达式和 Git 选项规范化三类语义。这个失败结果是后续 LLM 分诊与语义检索的真实基线，不应被 synthetic-controlled 的 100% 修复约束分数替代。

当前自动化真实项目 Oracle 覆盖 1/3：GitPython 漏洞版本返回不安全、修复版本返回安全，成对通过率 100%，Linux 命名卷隔离运行约 0.56 秒。aiohttp 的完整源码构建测试矩阵和 Django PostgreSQL 测试矩阵作为未执行覆盖缺口单独报告，不会被算作补丁失败。

配置远程模型后，先运行一次脱敏的安全代码探针。探针验证 Provider、JSON 输出契约、Token 统计和时延，不打印 Key：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 llm-probe
```

探针通过后运行 6 次真实调用（3 个漏洞版本 + 3 个修复版本）：

```powershell
# 编辑 D:\BaseAIProject\LIMA\.env，至少配置一个真实 Provider 和 Key。
powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 llm-eval
```

v1.3.1 不再把上游修复文件直接交给模型。系统先对整个受限仓库进行 label-blind 语义检索，再构建最小证据包：风险不变量锚点、父类模板渲染、验证调用点和最终规范化/执行点。LLM 必须返回候选中真实存在的 `path + symbol`，格式违规会被严格判为失败。DeepSeek V4 在该有界分类任务中按[官方思考模式文档](https://api-docs.deepseek.com/zh-cn/guides/thinking_mode/)关闭默认思考模式，避免推理 Token 吞掉 JSON 输出；[官方 JSON 输出文档](https://api-docs.deepseek.com/guides/json_mode/)也说明接口偶尔可能返回空内容，因此错误报告会保留脱敏后的 `finish_reason`、Token 和时延证据。

当前固定数据集的真实结果：候选路径、漏洞符号和修复符号 Recall@K 均为 100%；漏洞版风险不变量召回率与修复版缓解不变量命中率均为 100%；DeepSeek `deepseek-v4-flash` 的 6 次调用 API 成功率、输出契约有效率、漏洞召回率、修复版特异度和成对区分率均为 100%。总计 12,688 tokens，平均 LLM 时延约 1.78 秒，P95 约 2.29 秒。相对首轮宽上下文思考模式，Token 从 54,312 降低 76.6%，平均时延从 40.63 秒降低 95.6%。原始可审计报告位于 `output/v1.3.1-dataflow-llm-eval/real-world-llm-retrieval-ab.json`。

这些数字只覆盖 3 个专门针对 CWE-22/78/89 设计的公开成对案例，规则是在已知失败上工程化形成的，不应宣称为通用漏洞检测准确率或零日能力。下一阶段必须扩展未参与规则设计的外部 holdout。LLM 容器可以访问模型 API，但不执行被测仓库代码；项目 Oracle 则在无网络、只读文件系统、无 Linux capabilities 且不注入 `.env` 的独立容器中运行。模型分类本身永远不能越过确定性修复 Oracle 和仓库测试门禁。

完整的版本消融、逐例根因、复现命令和有效性边界见 [v1.3.1 真实项目评测报告](docs/V1_3_1_REAL_WORLD_EVALUATION.md)。

### v1.4 热门项目外部 Holdout

v1.4 新增 5 个 repository-disjoint 的热门项目漏洞/修复对：pip、rembg、yt-dlp、PraisonAI 和 Calibre-Web。选样要求 `stars >= 1000` 或 `watchers >= 100`，覆盖 CWE-22、CWE-78、CWE-89；完整 commit、归档 SHA-256、热度快照、排除原因和冻结分析器指纹均记录在 `evaluation_data/popular_external_holdout.json`。分析器或缓存目录树发生漂移会 fail-closed。

```powershell
# 断网确定性扫描与 label-blind 检索基线。
powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 popular-eval `
  -Output output\v1.4-popular-holdout

# 5 个漏洞版 + 5 个修复版的真实 LLM 评测。
powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 popular-llm-eval `
  -Output output\v1.4-popular-holdout
```

冻结结果没有复现开发集的高分：路径 Recall@K 为 20%，目标符号 Recall@K 为 0%，真实 LLM 漏洞召回和严格成对区分均为 0%，修复版特异度为 80%；但 10/10 API 调用和 10/10 JSON 契约均成功。系统没有让未验证候选进入修复，拒修策略遵从率为 100%。这证明主链路可运行，也证明当前通用检索/根因判断仍不具备可发布效果。

Docker named volume 将 5 对真实 LLM 主链路从 Windows bind mount 的约 2258.86 秒降至 43.64 秒，检索平均耗时从约 86.84 秒降至 0.89 秒。主机回归为 134 passed、1 skipped，Docker Linux 为 135 tests 全通过，运行服务健康端点返回 v1.4.0。完整样本、原始指标、失败诊断、有效性边界和下一迭代门禁见 [v1.4 热门项目外部 Holdout 报告](docs/V1_4_POPULAR_EXTERNAL_HOLDOUT.md)。

### v1.5 通用检索与混合冲突仲裁

v1.4 的 5 个案例已经参与本轮根因分析，因此 v1.5 将其明确重分类为 calibration set，保留原始冻结报告但不再用它们宣称外部泛化。新清单 `evaluation_data/popular_calibration_v1.json` 同时绑定 v1.4 基线指纹、来源 holdout 清单哈希和 v1.5 分析器指纹。

本轮把仓库预算、生产源码优先级、AST source/sink/sanitizer 语义、文件与符号多阶段检索、逐候选批量 LLM verdict、严格身份契约和风险冲突仲裁连成一条链。最终 5 个热门仓库校准结果为：目标文件/符号/证据包命中率和漏洞风险不变量召回均为 100%；纯 LLM API 与契约有效率 100%，目标漏洞召回 80%、修复目标特异性 80%、成对区分 60%；混合策略对漏洞目标的 non-clear 率 100%、修复目标自动清除率 80%、安全成对区分率 80%，目标人工复核率 7.14%。Calibre-Web 修复提交仍把未校验的 `order` 方向拼入 SQL，因此保持告警而不为指标强行标安全。

```powershell
# 不调用远程模型，复现检索与不变量校准。
powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 calibration-eval

# 使用 .env 中已配置的真实模型，运行 5 个漏洞版 + 5 个修复版。
powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 calibration-llm-eval
```

完整指标、逐例处置、架构变化、复现方式和有效性边界见 [v1.5 架构校准报告](docs/V1_5_ARCHITECTURE_CALIBRATION.md)。下一次可用于泛化结论的实验必须重新选择未参与开发的 5–10 个 repository-disjoint 热门项目，并在运行前冻结分析器和快照。

## 完整生产模式

```powershell
Copy-Item .env.example .env
# 编辑 .env，至少设置随机 LIMA_AUTH_SECRET（不少于 32 字节）
# 和唯一的 LIMA_BOOTSTRAP_ADMIN_PASSWORD（不少于 10 个字符）。
docker compose up --build
```

Compose 缺少上述两个安全变量时会拒绝启动，并且默认只把服务绑定到宿主机
`127.0.0.1:18080`。Compose 会启动 PostgreSQL、Redis 和 LIMA。未配置数据库和
Redis 的非容器运行模式会自动退回 SQLite 与进程内线程队列，适合本地演示。

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/health` | 健康检查 |
| `POST` | `/v1/auth/login` | 登录并获取租户绑定的短期 Bearer Token |
| `POST` | `/v1/reviews` | 创建同步审查任务 |
| `POST` | `/v1/reviews?async=true` | 创建异步审查任务 |
| `GET` | `/v1/tasks/{id}` | 获取状态、轨迹和报告 |
| `GET` | `/v1/tasks/{id}/report` | 获取 Markdown 报告 |
| `GET` | `/v1/tasks/{id}/feedback` | 获取该已完成任务的反馈历史 |
| `POST` | `/v1/tasks/{id}/fix` | 创建自动修复分支和提交 |
| `POST` | `/v1/tasks/{id}/repair-preview` | 为完成的仓库扫描生成快照固定、只读的验证修复预览 |
| `POST` | `/v1/tasks/{id}/feedback` | 回流误报、漏报或坏修复 |
| `POST` | `/v1/tasks/{id}/cancel` | 请求取消任务 |
| `POST` | `/v1/tasks/{id}/resume` | 从最近 checkpoint 续跑任务 |
| `POST` | `/v1/experiments` | 创建可恢复的 repository-disjoint 后台实验 |
| `GET` | `/v1/experiments` | 查询当前租户的实验列表 |
| `GET` | `/v1/experiments/{id}` | 查询实验、逐案例状态和最终结果 |
| `POST` | `/v1/experiments/{id}/cancel` | 请求在下一个案例边界取消实验 |
| `POST` | `/v1/experiments/{id}/resume` | 恢复失败实验；模糊 LLM 调用必须显式授权重试 |
| `POST` | `/webhooks/github` | 接收 GitHub PR webhook |
| `POST` | `/v1/skills/reload` | 动态重新加载 Skill |
| `POST` | `/v1/evolution/auto` | 从失败案例生成并评测提示词版本 |
| `POST` | `/v1/evolution/propose` | 评测指定提示词候选版本 |
| `GET/POST` | `/v1/evaluation/cases` | 查询或增加版本化评测样本 |
| `GET` | `/v1/evolution/status` | 查询模型与评测门禁就绪状态 |
| `GET` | `/v1/evolution/runs` | 查询持久化的新旧版本评测记录 |
| `POST` | `/v1/skills/{name}/versions/{version}/activate` | 激活或回滚版本 |
| `POST` | `/v1/skill-evolution/auto` | 从确认反馈生成、回放并门禁 Skill 候选 |
| `POST` | `/v1/skill-evolution/propose` | 评测指定声明式 Skill artifact |
| `GET` | `/v1/skill-evolution/status?skill_name={name}` | 查询 Skill 门禁与激活版本 |
| `GET` | `/v1/skill-evolution/runs` | 查询 Skill 进化运行与指标 |
| `GET` | `/v1/skill-evolution/{name}/versions` | 查询 Skill artifact 版本链 |
| `POST` | `/v1/skill-evolution/{name}/versions/{version}/activate` | 激活或回滚 Skill artifact |
| `GET` | `/metrics` | Prometheus 文本指标 |
| `GET` | `/api/alerts` | 查询租户告警 |
| `GET` | `/api/audit` | 查询租户审计日志 |
| `GET` | `/api/queue/dead-letters` | 查询死信任务 |
| `POST` | `/v1/queue/dead-letters/replay` | 重放死信任务 |
| `GET/POST` | `/api/deployments/llm-review`、`/v1/deployments/llm-review` | 查询或配置灰度/影子发布 |

`POST /v1/reviews` 的 `diff` 最大默认 1 MiB；单任务默认最多 8 步、120 秒。可通过环境变量调整，详见 `.env.example`。

完成审查后，可在任务详情的“审查反馈”区域提交 `false_positive`、`missed_issue` 或 `bad_fix`。接口要求任务已成功完成，并会将反馈按任务、租户保存；`missed_issue` 建议附带 `finding.rule_id`、`path` 和 `line`，以便后续候选学习准确的检查目标。

## 架构

```text
HTTP / GitHub Webhook
        │
        ▼
 ReviewService ── TaskStore(SQLite / PostgreSQL)
        │
        ▼
 ReviewHarness (LIMA Runtime / checkpoint / resume / budget / trace)
        │
        ├── DiffParser
        ├── Redis Streams / ACK / lease / retry / DLQ
        ├── ContextManager (unified token budget / iterative context compression)
        ├── MemoryManager (working / episodic / semantic / consolidation / expiry)
        └── MultiAgentCoordinator
              ├── Planner：按语言、文件和风险域分解任务
              ├── Specialists（并行）
              │     ├── 独立 Security Rule Agent
              │     ├── 独立 Reliability Rule Agent
              │     ├── OpenAI-compatible LLM Agent
              │     └── dynamically loaded Skills
              ├── Agent Loop：Plan / Tool / Observe / Final，带工具 Schema、步骤与时间预算
              ├── Critic → Reflection：质疑并把修订请求交回原 Agent
              ├── Evidence Agent：独立复核新增行证据
              ├── Verifier：执行置信度、证据和修复安全门禁
              └── Arbiter：合并冲突并裁决最终 findings
```

Harness 由项目内 `AgentRuntime` 控制状态流转：`PENDING → PLANNING → EXECUTING → REVIEWING → SUCCESS`。LLM Specialist 在有界 Agent Loop 中依据 Tool Registry 暴露的参数 Schema 选择 Diff 搜索、变更行读取、文件列表和记忆检索工具；Runtime 在调用前校验参数，并把结果或错误写成结构化 Observation。ContextManager 每轮重新组合任务、工具 Schema、Critic 反馈、历史记忆、最新 Observation 与风险排序后的 Diff，共享统一 Token 预算。MemoryManager 按租户与仓库检索历史经验，任务结束后把裁决摘要归档为 Episodic Memory、释放 Working Memory，并在 Recall 前清理过期记录。步骤和时间预算耗尽后，Agent 进入既有重试/交接流程。协作协议仍为 `规划 → 初审 → 质疑 → 反思/补证 → 验证 → 裁决`，消息、工具观察、重试、任务交接和最终裁决均随任务持久化。

## 参与贡献

欢迎通过 Issue 和 Pull Request 参与开发。请先阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 与
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。普通回归测试不需要真实大模型密钥；请勿在
Issue、提交、日志或 PR 中粘贴 `.env`、私有仓库代码和个人数据。

安全漏洞请不要公开提交 Issue，按照 [SECURITY.md](SECURITY.md) 使用 GitHub 私密漏洞
报告渠道。第三方依赖和评测数据边界见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
及 [evaluation_data/README.md](evaluation_data/README.md)。

## 许可证

LIMA 自有代码、文档、测试、UI、标注与工具按 [Apache License 2.0](LICENSE) 发布。
维护者主要将本项目用于求职展示、安全研究与开源学习；项目按“原样”提供，不构成
漏洞检测率、自动修复安全性、生产适用性或合规性的保证。上游代码片段与第三方材料
继续适用其各自的原始许可证。
