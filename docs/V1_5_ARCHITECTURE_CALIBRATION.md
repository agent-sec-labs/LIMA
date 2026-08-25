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

最终验证：宿主机 `149 passed, 1 skipped`；Docker Linux `150 tests` 全部通过。API key 只由 `.env` 注入 LLM 容器，不写入报告；被测仓库代码不会由 LLM 评估容器执行。

## 有效性边界与下一阶段

- 这是 5 个已参与开发的校准案例，不是 v1.5 外部泛化成绩，也不能证明零日发现能力。
- `hybrid_vulnerable_non_clear=100%` 表示已知漏洞没有被自动清除，其中允许 `needs_review`；它不是“模型召回 100%”。人工复核率必须和 non-clear 一起报告，防止用“全部送人工”虚增安全指标。
- 当前冲突仲裁已进入真实仓库评估链路；主服务的 PR/仓库扫描运行时还需在下一迭代接入同一处置对象和 UI 状态，不能仅凭本报告宣称生产部署完成。
- 下一批泛化测试必须在代码冻结后选取 5–10 个全新 repository-disjoint 热门仓库，预先固定 commit、归档 SHA-256、ground truth、分析器指纹和排除规则。若新 holdout 的目标符号召回明显下降，优先扩展语言/API 语义索引；若证据包命中而模型仍错，比较模型或增加人工复核，不继续针对单例堆特判。
