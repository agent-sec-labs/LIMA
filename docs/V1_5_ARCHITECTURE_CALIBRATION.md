# LIMA v1.5 架构校准与混合冲突仲裁

## 结论

v1.4 指标差的首因是系统架构，不是 API 或 JSON 契约，也不能简单归因于模型能力。当时 5 个漏洞提交中只有 1 个目标文件进入候选，目标符号 0 个进入模型上下文；模型没有机会判断其余根因。v1.5 修复工作区预算和语义检索后，目标文件、目标符号和最终证据包命中率均达到 100%，说明首要瓶颈已经解除。

剩余错误才主要落在模型语义判断和样本标签边界：DeepSeek `deepseek-v4-flash` 仍把 yt-dlp 模板插值分支误认为被 fallback `shell_quote` 保护；Calibre-Web 的所谓修复提交仍让请求派生的排序方向进入 `text()`，系统应保留残余风险而不是迎合标签。因此工程策略是“证据一致才自动清除，发生冲突则人工复核”，而不是继续堆提示词或冒充模型准确率 100%。

## 数据身份与防泄漏

- 原始冻结清单：`evaluation_data/popular_external_holdout.json`。
- v1.5 校准清单：`evaluation_data/popular_calibration_v1.json`。
- 校准分析器 SHA-256：`717697c044ffe7d6a39021156e2572830d9c4ac954b9a08c26bc5b34b964d0a3`。
- 数据规模：pip、rembg、yt-dlp、PraisonAI、Calibre-Web，共 5 个 repository-disjoint 漏洞/修复对。
- 热度门槛：`stars >= 1000` 或 `watchers >= 100`，覆盖 CWE-22、CWE-78、CWE-89。

这些案例的失败已经影响 v1.5 规则、提示和仲裁设计，所以只能报告 calibration 指标。原 v1.4 报告保持不变；原 holdout 清单在分析器漂移后会 fail-closed，避免“测后调参”仍被包装成未见测试。

## 针对性架构改造

1. 工作区先统计全部可读源码，再按 `src/app/lib/package/packages`、普通源码、测试/示例分层进入固定文件和字节预算，同时输出文件与字节覆盖率。PraisonAI 的目标源码不再被 examples 抢占预算。
2. 检索从案例关键词改为 AST API 语义：路径规范化/包含关系、shell 执行与模板插值、SQL 结构化 token、request/CLI/config 等信任边界。
3. 采用文件级召回、符号级排序、调用边邻居和安全不变量证据包四阶段检索；生产文件优先，同文件同类别限制主候选数，避免单个高分文件垄断 Top-K。
4. 函数代码片段按真实 AST 边界提取，防止前一个函数的信号泄漏；`Text()`、控制台 `cursor/column` 等非 SQL 命名只有出现数据库 API 上下文才进入 SQL 候选。
5. LLM 从“一次只能挑一个候选”改成对证据包每个 `FILE/SYMBOL` 各返回一个 verdict。缺失、重复、错误 CWE 或身份不匹配均使契约失败。
6. 模型省略类限定名时，只允许在同一路径唯一可消歧的情况下规范化，并记录原始短名与完整符号；歧义短名仍拒绝。
7. 提示明确区分模板占位符分支和无占位符 fallback：后者的 shell quote 不能证明前者的 metadata 转换安全。
8. 新增 `agreement-required-for-auto-clear-v1` 仲裁：风险不变量与模型 clean 冲突时进入 `needs_review`；缓解不变量与模型 clean 同时成立才 `clear`；模型告警或双方确认风险则保持 `alert`。

## 最终实测指标

报告：`output/v1.5-popular-calibration/calibration-llm-retrieval.json`。

| 层次 | 指标 | v1.4 冻结结果 | v1.5 校准结果 |
|---|---:|---:|---:|
| 检索 | 漏洞目标路径 Recall@K | 20% | 100% |
| 检索 | 漏洞目标符号 Recall@K | 0% | 100% |
| 证据包 | 漏洞目标符号命中率 | 未记录 | 100% |
| 不变量 | 漏洞风险召回 | 20% | 100% |
| 不变量 | 修复缓解命中 | 0% | 80% |
| LLM | API 成功率 | 100% | 100% |
| LLM | 输出契约有效率 | 100% | 100% |
| LLM | 目标漏洞召回 | 0% | 80% |
| LLM | 修复目标特异性 | 80% | 80% |
| LLM | 目标成对区分 | 0% | 60% |
| 混合仲裁 | 漏洞目标 non-clear | 未实现 | 100% |
| 混合仲裁 | 修复目标自动清除 | 未实现 | 80% |
| 混合仲裁 | 安全成对区分 | 未实现 | 80% |
| 混合仲裁 | 目标人工复核率 | 未实现 | 7.14% |

最后一次运行共 10 次真实 API 调用，使用 41,588 tokens；平均 LLM 时延 6.96 秒，P95 10.04 秒；端到端 113.14 秒。批量 verdict 增加了输出 token 和时延，但解决了“一个无关候选掩盖目标根因”的结构性漏报，并能把整仓其他真实发现与目标修复评分分开。

## 逐案例解释

| 案例 | 纯 LLM 漏洞/修复 | 混合处置 | 解释 |
|---|---|---|---|
| pip CWE-22 | 正确 / 正确 | 成对通过 | `commonprefix` 风险与 `commonpath` 缓解均被正确识别；固定快照中的其他告警不再错误惩罚目标修复。 |
| rembg CWE-22 | 正确 / 正确 | 成对通过 | 三个 `download_models` 目标都进入证据包并逐一判定。 |
| yt-dlp CWE-78 | 漏判 / 正确 | 漏洞进入复核、修复清除 | 模型仍错误信任 fallback quote；风险不变量阻止自动放行。 |
| PraisonAI CWE-78 | 正确 / 正确 | 成对通过 | 生产源码优先级解决 20 MiB 预算被 examples 占满的问题。 |
| Calibre-Web CWE-89 | 正确 / 仍告警 | 不自动清除 | 列名被 allowlist，但请求派生的 `order` 方向仍进入 SQL 结构；按残余风险处理。 |

## 复现

在 `D:\BaseAIProject\LIMA` 运行：

```powershell
# 断网确定性检索与不变量报告。
powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 calibration-eval

# 使用根目录 .env 中的真实 API 配置。
powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 calibration-llm-eval

# 全量 Docker 回归。
powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 test
```

v1.5 校准时的最终验证：宿主机 `149 passed, 1 skipped`；Docker Linux `150 tests` 全部通过。API key 只由 `.env` 注入 LLM 容器，不写入报告；被测仓库代码不会由 LLM 评估容器执行。

## 主服务处置闭环补充（2026-08-25）

本报告原先标记的主服务断点已经完成第一阶段工程闭环：离线评估和生产报告现在共用 `lima/adjudication.py` 中的 `agreement-required-for-auto-clear-v1` 契约，`ReviewReport` 会持久化 `policy`、报告级处置、逐项处置、原因、计数和 `auto_clear`。该对象已接入 PR 多 Agent 复核结果、整仓扫描结果、任务数据库、Markdown 报告和网页审计结果页。

运行时语义保持失败关闭：

- PR 最终保留的发现已经通过 critic、独立证据、修复可行性、verifier 和 arbiter 门禁，处置为 `alert`，但不篡改原始 `verification_state`。
- 整仓扫描中 `syntax-verified`、`corroborated`、`dataflow-verified`、`confirmed` 风险处置为 `alert`；普通 candidate 处置为 `needs_review`。
- 没有发现时仍是 `needs_review` 和 `auto_clear=false`，因为“没有命中当前检测器”不是正向安全证据。
- 只有显式安全评估对象同时具备确定性 mitigation 不变量和有效模型 clean verdict，且所有对象均为 `clear` 时，报告才允许 `auto_clear=true`。
- 旧任务缺少处置对象时，后端恢复和前端渲染都使用兼容的 fail-closed 推导，不把旧数据静默升级为安全结论。

网页不再要求用户解读 JSON：结果页新增报告级“确认告警 / 需要复核 / 证据通过”结论卡、三类计数、逐发现处置原因和策略说明；“未发现”空状态明确提示这不等于绝对安全。Markdown 导出同步包含同一证据处置段落。

本次隔离验证未调用远程模型 API：Windows 宿主机 `172 tests` 全部通过，`1 skipped`（当前主机不支持目录 symlink）；`python -m compileall` 与 `node --check web/app.js` 均通过。这里验证的是运行时契约、持久化与界面闭环，不新增或冒充外部泛化指标。

## 生产语义复核迭代（2026-08-26）

主服务现已接入“标签盲语义检索 → 有界证据包 → 单次模型批量 verdict → 混合仲裁 → Finding/报告/UI”链路。变量缺失时仍安全缺省为 `off`；当前工程联调模板和本地配置已显式选择 `auto`。部署者必须知晓选中的代码证据会发送给模型供应商，再通过 `LIMA_REPOSITORY_SCAN_LLM_MODE=auto|required` 启用。每项仓库扫描最多一次请求，并分别限制超时、候选数、上下文字符和最大输出 Token。

- `auto`：模型或网络失败、输出契约无效、verdict 缺失时保留本地扫描结果，新增 `needs_review` 处置并记录脱敏诊断；不会重试远程调用或自动放行。
- `required`：相同异常使仓库任务永久失败，任务队列不再重复请求。
- 风险不变量与模型漏洞 verdict 一致时生成或复用人类可读 Finding；若与已有数据流 Finding 重合，则通过 fingerprint 合并处置，避免重复计数。
- 缓解不变量与有效模型 clean verdict 一致，且本地扫描没有其他告警/复核项时，才允许报告 `auto_clear=true`。
- 前端和 Markdown 同时展示模式、状态、供应商/模型、证据候选数、Token、时延及逐符号语义证据；API Key 仅用于认证头，不进入证据上下文、任务或报告。

此前 Windows 跳过的是“符号链接逃逸”集成测试，因为普通 Windows 进程通常没有创建 symlink 的权限。测试现改用无需管理员权限的 NTFS junction 执行相同真实路径逃逸场景；junction 创建失败会直接导致测试失败，不再静默跳过。最终隔离回归为 Windows `182 tests` 全部通过、`0 skipped`，`python -m compileall`、`node --check web/app.js` 通过。

随后使用不包含 LIMA 或用户项目内容的最小合成 CWE-78 样本完成一次真实 DeepSeek 烟雾测试：`deepseek-v4-flash` 返回有效批量契约，`contract_errors=[]`，用量为 581 prompt + 228 completion = 809 tokens，模型时延 2161.821 ms；风险不变量与模型结论一致，最终处置为 `alert`、`auto_clear=false`。出于代码外发授权边界，本轮没有把 LIMA 自身代码发送给外部供应商。因此该结果只证明真实 API 连通性、JSON 契约和仲裁工程链路，不是 LIMA 或热门仓库上的漏洞检测效果指标。

在用户明确授权具体外发范围后，又对 LIMA 自身执行了一次生产同构的有界真实调用。标签盲检索完整解析 81 个 Python 文件、859 个函数，解析错误为 0；检索器产生 20 个候选，只向 DeepSeek 发送排序后的 6 个函数证据片段，共 26,118 个上下文字符，没有发送 `.env`、API Key 或完整仓库。`deepseek-v4-flash` 返回有效批量契约，`contract_errors=[]`，Prompt SHA-256 为 `d5a98d0062dd6d5069b625f6f5525780376d80b4b1b499d471b82247bc96a96c`；用量为 6,711 prompt + 1,135 completion = 7,846 tokens，模型时延 7471.229 ms，端到端耗时 8217.027 ms。

6 个语义对象的混合处置为 `clear=1`、`needs_review=5`、`alert=0`，没有生成新的 Finding，报告级处置为 `needs_review`、`auto_clear=false`。这说明真实仓库链路、逐候选契约和失败关闭策略均已贯通，也说明系统没有把“零新增告警”包装成安全证明。LIMA 自审不具备独立 ground truth，不能据此报告准确率、召回率或零日发现能力；其用途是生产链路烟雾验证，外部泛化指标仍必须来自代码冻结后的 repository-disjoint holdout。

生产语义复核迭代当时的分析器 SHA-256 为 `55ae5d43e6914893c21ddc90f73114af15ebaa6b47b8047c297468cc245c19e1`；fingerprint 组件已补入 `adjudication.py` 和 `repository_triage.py`，后续修改处置或生产语义链路都会使外部 holdout 自动拒绝旧冻结身份。

## 持久化外部实验执行器迭代

repository-disjoint 评测不再要求 ChatGPT、浏览器或发起命令的终端持续监视。主服务新增独立实验队列 `lima:experiment:stream`、实验运行/逐案例数据库记录和固定 artifact 目录；Docker Compose 把 `output/experiments` 挂载为可写持久目录，并使用独立 snapshot cache volume。实验在创建时冻结数据集文件 SHA-256、案例规范化 SHA-256、分析器 SHA-256、模式、供应商/模型身份和调用/Token 预算。

Runner 每次只处理一个固定案例，在每个边界原子写入 `manifest.json`、`state.json`、`events.jsonl`、`cases/<id>/fetch.json`、`cases/<id>/result.json`，全部案例完成后才生成 `reports/summary.json`、Markdown、`checksums.sha256` 和 `COMPLETE.json`。最终聚合把已校验的案例结果注入原评测器，不重新扫描、下载或调用模型，因此恢复不会改变指标口径或重复计费。

本地确定性失败可以从最后一个完整案例继续；LLM 请求开始前先持久化 `LLM_IN_FLIGHT`。如果进程在响应提交前中断，案例转换为 `AMBIGUOUS`，实验转换为 `NEEDS_ATTENTION`，不会由队列自动重试。管理员必须显式提交 `allow_ambiguous_retry=true` 才能承担潜在的重复调用。每个成对案例预留两次调用，达到调用预算或已记录 Token 预算后在下一个案例前转换为 `BUDGET_EXHAUSTED`。API Key、`.env`、认证头和完整仓库均不进入实验记录。

本迭代修改了评测聚合组件，因此当前分析器 SHA-256 更新为 `bf81ba2cf0719bd62b7b9b2bf3b621571a6a38fe5b6e79374c3cdc2e36f1e5f1`；旧外部 holdout 继续按设计拒绝漂移后的分析器。新的 5–10 仓库清单必须在代码冻结后绑定当时重新计算的指纹，不能机械沿用本文数值。Windows 与 Linux 只读、非 root 容器全量回归均为 `191 tests` 全部通过、`0 skipped`；新增 9 项实验测试覆盖原子 artifact、逐例恢复、模糊 LLM 阻断、显式重试、调用预算、数据/路径漂移和无重复聚合。镜像预创建并授权 `/experiments` 与 `/experiment-cache`，避免后台任务运行后才因非 root 卷权限失败。

## 多人协作门禁与实验中心迭代

网页新增面向管理员的“外部评测”三步向导：目录 API 只返回数据集名称、角色、数量、模式与文件 SHA-256，不暴露 holdout 案例标签；运行列表和详情将状态、进度、调用/Token 预算、逐案例记录和数值指标转换为表格与自然语言。页面轮询只读取数据库，关闭页面不会影响队列；取消、恢复以及可能重复计费的 `AMBIGUOUS` 重试都经过二次确认。示例实验只存在于浏览器，不写数据库或调用模型。

GitHub Actions 改为稳定 `merge-gate` 聚合门禁：快速契约、Windows/Linux Python 3.11/3.12、修复约束、只读容器和安全基线任一失败，聚合检查都会失败而不是因依赖跳过被误判为可合并。CI 权限固定为 `contents: read`，不使用 `pull_request_target`、仓库 Secret 或远程 LLM；所有 GitHub 官方 Action 绑定完整提交 SHA。单元测试 UTF-8 日志保留 14 天，安全与修复 JSON 证据保留 30 天。管理员只需在 Ruleset 中要求唯一稳定检查 `merge-gate`，兼容矩阵调整不会破坏分支规则。

当前 Windows CI 证据 Runner 与 Linux 只读、非 root 容器均为 `197 tests` 全部通过、`0 skipped`；修复约束门禁、镜像内 `required` Bandit 安全基线、Compose 解析、JavaScript 语法和 diff 格式检查通过。真实浏览器验收覆盖三步向导、示例报告、5 秒轮询和 390×844 响应式布局；期间发现并修复示例 UUID 被真实后端轮询导致的 404，复验控制台无错误。本轮没有调用远程模型，也没有改变分析器指纹。

## v1.6 外部 Holdout 冻结

上述下一阶段已经完成预注册，但尚未运行检测器或查看效果结果。新清单 `evaluation_data/popular_external_holdout_v2.json` 包含 Gradio、ComfyUI、Pillow、Airflow、LangChain 五个与开发/校准集仓库互斥的公开修复对，覆盖 CWE-22、CWE-78、CWE-89，并绑定当前 `bf81ba2c...` 分析器。10 个固定 ZIP 均通过 100 MiB 下载、30,000 成员、400 MiB 解压和单顶层目录约束，ground-truth 文件与稳定符号在成对版本中存在。MLflow 候选因两个 ZIP 均约 169 MB 被 fail-closed 排除，没有通过放宽边界强行纳入。

完整选样证据、清单/案例 SHA-256、逐归档哈希、运行顺序、必报指标和污染边界见 `docs/V1_6_EXTERNAL_HOLDOUT_PREREGISTRATION.md`。后续先连续完成冻结的 `retrieval` 与 `llm-retrieval` 两次后台实验，中间不得根据逐例结果修改分析器；一旦使用结果迭代，v2 必须转为 calibration，不能继续宣称未见外部测试。

## 有效性边界与下一阶段

- 这是 5 个已参与开发的校准案例，不是 v1.5 外部泛化成绩，也不能证明零日发现能力。
- `hybrid_vulnerable_non_clear=100%` 表示已知漏洞没有被自动清除，其中允许 `needs_review`；它不是“模型召回 100%”。人工复核率必须和 non-clear 一起报告，防止用“全部送人工”虚增安全指标。
- 主服务已支持对安全候选运行语义检索和模型批量 verdict，变量缺失时安全缺省为 `off`，当前联调配置显式为 `auto`；启用后仍不能仅凭零 Finding 或模型单方面 clean 给出 `clear`。受控真实 API 烟雾测试已经完成，下一步应冻结代码与数据身份并开展新的外部 holdout。
- 下一批泛化测试必须在代码冻结后选取 5–10 个全新 repository-disjoint 热门仓库，预先固定 commit、归档 SHA-256、ground truth、分析器指纹和排除规则。若新 holdout 的目标符号召回明显下降，优先扩展语言/API 语义索引；若证据包命中而模型仍错，比较模型或增加人工复核，不继续针对单例堆特判。
