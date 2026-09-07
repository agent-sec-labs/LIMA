# C/C++ LLM Agent 检测

LIMA 的 C/C++ 检测在传统三层（Semgrep / Clang / ASan，见
`docs/CXX_MEMORY_ANALYSIS.md`）之外，提供一条真实大模型多 Agent 检测管线：模型是
真实检测者，但所有模型输出都按不可信输入处理——重新绑定可信快照、按严格 Schema
校验、越界即整轮拒绝。支持 CWE-787（越界写）、CWE-125（越界读）、CWE-416（释放后
使用）和 CWE-415（重复释放）。**C/C++ Finding 永不自动修复**：所有 Agent 产出的
Finding `automatic_repair` 恒为 `False`，报告、修复预览、SafeFixer 和 Web 修复按钮
都排除这类结果，修复必须由开发者人工完成。

## 隐私边界：外部模型会读取代码

`auto`/`required` 模式下，配置的 Provider 会收到以下数据：快照内 C/C++ 源码片段
（工具读取的真实行）、检索锚点与角色任务描述、Agent 之间的结构化中间产物。私有仓库
接入前必须确认这一点：把代码发给外部 LLM Provider 等同于把代码交给该 Provider 的
处理范围。系统提示词只含角色名与工具目录；密钥、评测标签、CVE 描述、fix diff 与
ground truth 永不进入模型上下文。温度固定为 0，提示词模板标识固定为
`lima-cxx-agent-system-v1`（报告 `collaboration.cxx_agent.prompt` 与评测报告身份
清单都记录该标识及提示词分片哈希）。

## 两种入口

| 入口 | 检索 | 快照绑定 | 说明 |
|---|---|---|---|
| 整仓扫描 | `retrieve_repository`：从分配/释放/长度 API/调用邻域种子做无标签候选排序 | `workspace.inventory()` 指纹，`collaboration.cxx_agent.snapshot_sha256` | 管理员导入的完整仓库快照 |
| Pull Request | `retrieve_pull_request`：修改行映射到所在符号再扩展，共用同一套种子与预算 | PR head 完整 SHA；GitHub 固定 SHA 获取 | 降级链见下文 |

两种入口共用同一协作协议（Planner → 三个独立 Specialist → Critic → Evidence →
Verifier → Arbiter）与同一 Finding Schema。Specialist 相互独立：初始阶段不可见其他
Agent 或工具结果；共识必须六个键全部一致（CWE、path、symbol、resource 位置、机制、
trigger 交集），标题与 CWE-only 相似度永不构成共识。

## 模式与任务状态

```dotenv
LIMA_CXX_AGENT_MODE=auto            # off / auto / required
LIMA_CXX_AGENT_MODEL=               # 缺省回退 LIMA_LLM_MODEL
LIMA_CXX_AGENT_MAX_CALLS=40
LIMA_CXX_AGENT_MAX_CONTEXT_FILES=12
LIMA_CXX_AGENT_MAX_CONTEXT_LINES=1200
LIMA_CXX_AGENT_MAX_OUTPUT_BYTES=1048576
LIMA_CXX_AGENT_TIMEOUT_SECONDS=600
LIMA_CXX_AGENT_PARALLELISM=3
LIMA_CXX_AGENT_DIALOGUE_ROUNDS=2
LIMA_CXX_AGENT_MAX_CANDIDATES=100
```

| 模式 | 语义 |
|---|---|
| `off` | 零 LLM 行为，等价既有管线；`collaboration.cxx_agent.status = disabled` |
| `auto` | LLM 不可用时继续其他扫描，状态记 `llm-unavailable`，工具层证据保留 |
| `required` | Provider 未配置或管线失败时任务直接失败；绝不以“无漏洞”冒充成功 |

`required` 模式必须配置 `LIMA_CXX_AGENT_MODEL`（或 `LIMA_LLM_MODEL`），否则配置校验
直接拒绝。状态判定以“零成功模型轮次且存在角色降级”为准，不把空分配跳过误报为成功。

## 预算与费用

所有角色共享一个任务级预算：调用次数（calls）、上下文文件数（context_files）、上下文
行数（context_lines）与输出字节（output_bytes）。每次网络往返前先扣一次调用额度且
失败不退还；每个完成内容按 UTF-8 字节数扣减输出额度，超限响应未解析即丢弃。

**费用是近似值**：v1 不读取 Provider 的 token 计数，用量是“输出字节代理”
（`token_accounting: "bytes-proxy"`）。报告中的 `usage.calls / context_files /
context_lines / output_bytes` 是实际消耗的下界视图；货币成本（`cost_usd`）在评测
报告中恒为 `null` 并附 diagnostic，因为字节代理无法换算成账单。

## 验证状态与 verified-only 门禁

| 状态 | 含义 | 通过 verified-only 门禁 |
|---|---|---|
| `llm-candidate` | 仅单一 Specialist 断言，无独立佐证 | 否 |
| `agent-corroborated` | 至少两个独立 Specialist 六键完全一致 | 是 |
| `tool-corroborated` | 与 Sidecar 工具证据绑定到同一候选身份 | 是 |
| `runtime-confirmed` | ASan 运行时证据确认 | 是 |
| `human-confirmed` | 人工确认 | 是 |
| `needs-human-review` | 降级壳（CWE 不可判读）或无法安全绑定 | 否 |

验证状态由确定性代码（共识 + 工具证据绑定 + source-mode 上限）写入，永不由模型
投票产生；Diff-only 模式所有状态封顶在 `llm-candidate`。verified-only 门禁只放行
四个已验证状态，输出按（path, line, symbol, candidate_id）稳定排序；单 Agent 或
Diff-only 最高只能是 `llm-candidate`，这类结果不能作为门禁通过依据。

## 降级链与诊断词表

PR 入口按可用性降级：GitHub 固定 head SHA 获取（完整树）→ 本地 `local-source`
提供 head 快照 → Diff-only（仅有 diff 文本，状态封顶）。整仓入口在 `auto` 下
Provider 失败时保留传统扫描结果并记录 `llm-unavailable`。

`collaboration.cxx_agent.diagnostics` 只允许固定词表，Provider 原文错误串永不进入
报告：

| 诊断码 | 触发 |
|---|---|
| `llm-unavailable` | Provider/传输失败导致管线降级 |
| `budget-exhausted` | 任务级任一预算耗尽，后续角色跳过 |
| `context-truncated` | 检索候选未被上下文预算覆盖，如实记录 |
| `cancelled` | 任务在阶段之间被取消 |
| `protocol-error` | 模型回复连续两轮不符合严格 Schema |

## 已知局限

- **v1 评测集是合成版本对**：`evaluation_data/cxx_llm_agent_cases.json` 的四个
  vulnerable/fixed 对是本仓库自有的合成 C 样例（Apache-2.0，标注于每个 case 的
  `license` 字段），不是真实 CVE。合成与固定样本结果不代表真实项目完整检测能力，
  不得用于宣称生产召回率或零日能力。
- **PR 本地接线局限**：`local` 模式依赖管理员侧提供完整 head 快照
  （`LocalCommitSource`）；没有 GitHub 凭证也没有本地快照时只能降级 Diff-only，
  所有状态封顶 `llm-candidate`。
- **bytes-proxy 计量**：见上节，token/费用是字节代理近似，不是 Provider 账单。
- **上下文解析为近似**：C/C++ 上下文索引用正则提取函数边界、类型与调用
  （如 `\bname\s*\(` 后缀匹配），不处理宏展开、模板实例化与条件编译；解析失败
  记为 coverage 缺口而不是猜测。候选行号与符号以快照绑定为准。
- **快照扫描集诚实性**：Sidecar 已在快照根写入仅注释的 `.semgrepignore`，停用
  Semgrep 内置默认忽略表（`tests/`、`doc/` 等），使实际扫描集与已验证清单一致；
  该文件不计入快照清单与指纹（与 `build/` 目录同为运行时脚手架），对协议零影响。

## 固定版本对评测（无标签）

`evaluation_data/cxx_llm_agent_cases.json` 为每个 CWE 固定一对合成 vulnerable/fixed
版本。每个 case 固定：`id`、`cwe`、`origin`（`synthetic`，结构上保留 `repository`
表单用于未来真实仓库 case：`project` + 两个 40 位提交 + HTTPS 归档 SHA-256）、
`affected`（path/symbol）、两版本本地 fixture 目录与**内容 SHA-256**（换行归一化，
跨 checkout 稳定）、选样理由与许可证标注。

**无标签红线**：case 文档是评测侧资产，绝不进入检索或管线输入——管线只收到 fixture
工作区本身，expected 身份、选样理由、许可证与固定哈希停留在评测器里打分。测试
（`tests.test_cxx_llm_agent_evaluation.UnlabeledIsolationTests`）通过录制
`CxxContextIndex.build` 的实际入参证明：索引输入就是 fixture 目录与其文件集合，且
case 标识、内容哈希、理由、许可证字样不出现在任何模型上下文中。

评测器 `scripts/run_cxx_llm_agent_evaluation.py` 对每个 case 的两版本各跑一遍真实
repository 扫描链（`RepositoryScanner` + 真实 `CxxAgentCoordinator` + 严格
`CxxLLMClient`，模型由参数指定；测试注入 Fake client，零网络）。打分完全在管线外：
Agent Finding 命中固定（cwe, path, symbol）视为该版本检测命中。

### 指标定义

| 指标 | 定义 | 零分母行为 |
|---|---|---|
| `confusion_matrix` | 仅 `status=completed` 的版本计入：vuln 命中=TP、vuln 漏=FN、fixed 报出=FP、fixed 安静=TN | 不适用（计数） |
| `verified_confusion_matrix` | 同上，但命中要求 `verification_state` 属于四个已验证状态 | 不适用（计数） |
| `precision` / `recall` / `f1` | 原始混淆矩阵派生 | `null` + diagnostic |
| `verified_precision` / `verified_recall` / `verified_f1` | 已验证混淆矩阵派生 | `null` + diagnostic |
| `pair_accuracy` | 成对正确（vuln 命中且 fixed 安静）/两版本均完成的 case 数 | `null` + diagnostic；退化 case 逐个记 diagnostic 且不计入 |
| `completed_coverage` | `completed` 版本数 / 总版本数 | `null` + diagnostic |
| `usage.*` | 每版本 budget 消耗（calls/context_files/context_lines/output_bytes），总与均值 | 总恒为数；均值 `null` + diagnostic |
| `cost_usd` | 恒 `null`：字节代理无法换算账单，恒附 diagnostic | 恒 `null` |
| `latency_seconds` | 每版本真实扫描链耗时（总/均值） | 总恒为 0；均值 `null` + diagnostic |
| `verification_state_counts` / `verified_only_total` | 终态候选按状态聚合 | 不适用（计数） |

任何分母为 0 的比率指标输出 JSON `null` 加 diagnostic，绝不伪造 0/0=0。每个版本的
revision record 保存：expected/counted/status/predicted、目标身份与命中数、全部
Agent Finding（含验证状态与 `automatic_repair`）、状态计数、usage、耗时、快照指纹与
完整 `collaboration` 载荷。**全部聚合指标可仅由 `cases[].revisions` 重算**（测试
`MetricTests.test_revision_records_recompute_every_aggregate_metric` 逐项断言）。
身份清单固定记录：模型、Provider、`lima-cxx-agent-system-v1` 模板标识与提示词分片
哈希、`analyzer_fingerprint()`、C++ Agent 管线组件指纹、case 数据 SHA-256。

真实网络只发生在评测脚本运行时；普通 PR 的 CI 只跑 Fake-LLM 合同测试。

## CI 触发矩阵

| 事件 | 执行内容 |
|---|---|
| `pull_request` / `push` | 仅既有测试与 Fake-LLM 合同测试（`tests.test_cxx_llm_agent_evaluation` 随全量执行），零真实模型调用 |
| `workflow_dispatch` | `cxx-llm-agent-evaluation` job：按 case 矩阵各评一对固定版本，上传原始结构化报告与身份清单 artifact |
| `schedule`（每周三） | 同上 |

job 内所有评测步骤再挂 `if: github.event_name != 'pull_request'` 双保险。

### CI 接线（启用真实模型 job）

仓库合同（`tests.test_ci_contract`）要求 `ci.yml` 保持 secretless：工作流文件内不得
出现 `secrets.*` 引用。因此该 job 出厂不带凭证，未配置时以 `provider-not-configured`
跳过。启用步骤：

1. 在仓库 Variables 配置 `LIMA_LLM_BASE_URL`、`LIMA_LLM_PROVIDER`（可选）与
   `LIMA_CXX_AGENT_MODEL` 或 `LIMA_LLM_MODEL`（固定模型，进入报告身份清单）；
2. 在 job 的两个 `env:` 块各增加一行，把与 `lima/config.py` Provider 环境同名的密钥
   变量绑定到仓库 Secret，形如 `LIMA_LLM_API_KEY: ${{ secrets.LIMA_LLM_API_KEY }}`
   （DeepSeek 用 `LIMA_DEEPSEEK_API_KEY`，OpenRouter 用
   `LIMA_OPENROUTER_API_KEY`）；
3. 同步收窄 `tests.test_ci_contract.test_workflow_is_secretless_and_pins_every_action`
   的断言范围（例如只对非评测 job 禁止凭证引用），并让守卫步骤改为校验密钥非空后
   硬失败，而不是跳过。

本地手动评测直接运行（读取同一组 `LIMA_LLM_*` 环境变量，`--provider-url /
--provider-key / --model` 可显式覆盖）：

```powershell
$env:LIMA_LLM_PROVIDER="deepseek"; $env:LIMA_DEEPSEEK_API_KEY="..."; $env:LIMA_LLM_MODEL="deepseek-v4-flash"
python scripts/run_cxx_llm_agent_evaluation.py `
  --cases evaluation_data/cxx_llm_agent_cases.json `
  --output output/cxx-llm-agent-evaluation.json `
  --max-cases 1
```
