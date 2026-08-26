# LIMA v1.7 仓库级安全检索校准报告

## 结论

v1.6 的真实外部评测证明后台实验、固定快照、远程 API、预算、恢复和 artifact 完整性链路可以工作，但效果瓶颈不在模型接口，而在模型之前：目标函数没有进入 top-K 或 6 项证据包，模型根本看不到需要判断的代码。

v1.7 在不读取漏洞标签进行运行时检索、不硬编码仓库名/文件名/CVE 的前提下，针对可泛化的 AST 语义和证据预算进行校准。相同 5 个仓库只能作为 post-hoc calibration，不能继续作为 external holdout。最终无 API 校准复验中，漏洞路径、漏洞符号、8 项证据包目标符号、修复版符号、风险不变量与修复不变量均达到 5/5。最终真实模型校准的漏洞召回、修复版特异度和成对区分分别为 4/5、5/5、4/5；唯一模型漏报被混合仲裁 fail-closed 地送入人工复核。

## 数据身份与边界

- 历史外部清单：`evaluation_data/popular_external_holdout_v2.json`
- 历史清单规范化 SHA-256：`3a45b1138a5863ea4db6bb13b804f7eef4c3122fbcd5bc6bf176a0828ae181f4`
- v1.6 冻结分析器：`bf81ba2cf0719bd62b7b9b2bf3b621571a6a38fe5b6e79374c3cdc2e36f1e5f1`
- 校准清单：`evaluation_data/popular_external_calibration_v2.json`
- v1.7.1 校准清单规范化 SHA-256：`e587d44778163f519476b765bedd826611a11ca9e77a7e306b63f6a5d35586f6`
- 校准案例 SHA-256：`5640777521a02ec3bbf20144e52a6038a31ea40a6c47d2f1c03de4d58cded3e1`
- v1.7.1 当前校准分析器：`68d9e3b08b1d47b271814b4ef8dae570979a8cd94ff1146458329c7b3204412a`
- 数据角色：`calibration`
- 范围：5 个 Python 热门仓库，CWE-22 × 2、CWE-78 × 2、CWE-89 × 1

这里的 `5/5` 是对已观察案例的工程验收，不是无偏准确率估计，也不证明零日发现、全语言或全 CWE 泛化。新的外部主张需要另行预注册且仓库不重叠的 v3。

## v1.6 冻结基线

两个持久化实验都达到 `SUCCEEDED`，每个实验 5/5 案例和 15/15 artifact 校验和通过：

| 实验 | Run ID | 远程调用 | Token | 结果 |
|---|---|---:|---:|---|
| retrieval | `7c9b790e-7a27-4fa3-a530-e2e9b99383ca` | 0 | 0 | 工程闭环通过 |
| llm-retrieval | `fabdd46c-dae2-4c37-bfbc-f9040ee5d270` | 10/10 成功 | 35,002 | 契约 10/10 有效，Key 未落盘 |

| 指标 | v1.6 基线 | 计数 |
|---|---:|---:|
| 漏洞路径 Recall@24 | 0.20 | 1/5 |
| 漏洞符号 Recall@24 | 0.00 | 0/5 |
| 6 项证据包目标符号召回 | 0.00 | 0/5 |
| 修复版目标符号 Recall@24 | 0.00 | 0/5 |
| 漏洞风险不变量召回 | 0.60 | 3/5 |
| 修复缓解不变量命中 | 0.20 | 1/5 |
| 确定性漏洞文件召回 | 0.20 | 1/5 |
| 确定性修复版特异度 | 0.80 | 4/5 |
| 确定性成对区分 | 0.00 | 0/5 |
| LLM 目标漏洞召回 | 0.00 | 0/5 |
| LLM 目标修复特异度 | 0.00 | 0/5 |
| LLM 固定快照整体 clean | 0.60 | 3/5 |
| LLM 目标成对区分 | 0.00 | 0/5 |

API 与契约全部成功、目标判断却为零，说明不能先归咎模型能力。逐例检查显示 Gradio、ComfyUI、Airflow、LangChain 的目标符号未进入证据上下文；Pillow 的漏洞方法虽然被找到，但类级标签与方法级候选被错误当成不匹配。

## 根因与工程修改

1. **嵌套符号缺失**：旧遍历只覆盖顶层函数和类方法，漏掉方法内部注册的异步路由。现在递归产生稳定限定名，例如 `ModelFileManager.add_routes.get_model_preview`。
2. **符号层级过严**：ground truth 可以稳定标注类或父边界，候选通常落到具体方法。评分现在允许候选是标注符号的后代，但不允许反向模糊匹配。
3. **根因语义不完整**：补充文件对象 provenance、请求路径最终包含性、SQL 结构化 clause、解释器模板插值、结构化解析后动态分发和平台文件打开等 AST 信号与成对风险/缓解不变量。
4. **超大仓库 top-K 饥饿**：提高 SQL 结构片段相对于通用 `execute/query` 噪声的优先级，使 Airflow 的 `partition_clause` 边界进入固定 K=24，而未扩大检索 K。
5. **证据包被同类噪声占满**：证据包从 6 调整为 8，先保留类别代表、稀有风险/缓解不变量和第二独立锚点，再补关系邻居与普通候选。上下文仍受 36,000 字符硬上限约束。
6. **过宽动态分发规则**：只有同一函数先出现 `json/orjson/ujson.loads` 或 `yaml.safe_load`，随后动态 `getattr`，才作为 CWE-78 的结构化分发证据；普通反射不会被高分误判为修复。
7. **显式 REPL 压过隐蔽注入**：变量被 f-string、拼接、百分号或 `format` 嵌入 `exec/eval` 源码时增加解释器模板插值信号，使注入根因优先于预期存在的 REPL。
8. **测试代码挤占生产证据**：候选与语义邻居统一让生产路径优先于 `test/tests`，避免回归用例比真实边界更早进入证据包。
9. **文件 provenance 被拆成孤立片段**：将文件模型、入站 cache/validation consumer、marker-aware helper 和下游动态分发的文件读取 sink 建模为一条有类型的跨符号流；证据包为该链预留有界槽位。
10. **输入与输出 cache 边界混淆**：只有入站 `preprocess/input` 或带上传目录检查的 cache consumer 生成 provenance 风险/缓解不变量；postprocess/streaming 输出流不再被错误转移成入站风险。
11. **命令字符串等同于执行**：CWE-78 要求显示的 shell/interpreter 调用边；结构化平台 API 覆盖旧 builder 且 builder 不可达时，不再仅凭返回命令字符串报警。
12. **Windows checkout 改写分析器身份**：分析器组件统一在 LF 规范化后计算指纹，CRLF/LF checkout 现在具有同一身份；新增回归测试直接对两种换行计算并要求相等。

所有规则只依赖源码结构和通用安全语义，没有仓库、路径、CVE 或 ground-truth 特例。

## v1.7 无 API 校准验收

使用同一批已缓存、SHA 固定的 10 个快照，关闭网络和 SAST/dataflow 扩展，在只读容器中运行 repository-wide label-blind retrieval：

| 指标 | v1.7 校准 | 计数 |
|---|---:|---:|
| 漏洞路径 Recall@24 | 1.00 | 5/5 |
| ground-truth 文件 inventory recall | 1.00 | 5/5 |
| 漏洞符号 Recall@24 | 1.00 | 5/5 |
| 8 项证据包目标符号召回 | 1.00 | 5/5 |
| 修复版目标符号 Recall@24 | 1.00 | 5/5 |
| 漏洞风险不变量召回 | 1.00 | 5/5 |
| 修复缓解不变量命中 | 1.00 | 5/5 |
| 平均候选数 | 23.9 | 239/10 snapshots |
| 平均检索时延 | 2,928.438 ms | 10 snapshots |
| P95 检索时延 | 5,987.054 ms | 10 snapshots |

最终持久化 retrieval run 为 `ff0c683d-48e8-4fb2-9474-fcf73c02766d`：`SUCCEEDED`、5/5 案例、0 warning、15/15 artifact 校验和通过、未持久化 secret。该运行绑定修复前的原始字节指纹 `fe7c4b6257db1efd0c839c7c3dc6ffc11d06e82556e89b1e26ac1fa4a5765264`。v1.7.1 只把指纹输入规范化为 LF，不改变扫描、检索、Prompt 或仲裁行为；当前跨平台指纹为 `68d9e3b08b1d47b271814b4ef8dae570979a8cd94ff1146458329c7b3204412a`。确定性检测器仍只命中 1/5 漏洞文件并在 1 个固定版本报警；本轮没有修改扫描规则，因此不能把检索改善包装成端到端检测改善。

## v1.7 真实模型与混合仲裁验收

最终持久化 `llm-retrieval` run 为 `c87ce826-9a22-4c86-b3e3-2f0cf41bc2f7`：`SUCCEEDED`、5/5 案例、10/10 API 调用成功、10/10 输出契约有效、0 warning、15/15 artifact 校验和通过、未持久化 secret。模型为本机 `.env` 配置的 DeepSeek provider；最终报告只记录 provider/model、prompt hash、Token 和判定，不记录 API Key。

| 指标 | 最终校准 | 计数 |
|---|---:|---:|
| LLM API 成功率 | 1.00 | 10/10 |
| LLM 输出契约有效率 | 1.00 | 10/10 |
| LLM 目标漏洞召回 | 0.80 | 4/5 |
| LLM 目标修复版特异度 | 1.00 | 5/5 |
| LLM 目标成对区分 | 0.80 | 4/5 |
| 固定快照整体 clean | 0.60 | 3/5 |
| 混合仲裁成对安全区分 | 0.80 | 4/5 |
| 混合仲裁目标人工复核率 | 0.20 | 3/15 decisions |
| Prompt tokens | 45,560 | 10 calls |
| Completion tokens | 15,169 | 10 calls |
| Total tokens | 60,729 | 10 calls |

逐例中 Airflow、ComfyUI、LangChain 和 Pillow 的 LLM 漏洞/修复成对判断均正确。Gradio 的 `meta` 缺失会绕过 marker-aware cache helper，随后默认-bearing `FileData` 进入组件 `_process_single_file` 的 `open(..., "rb")`；证据包已同时给出模型、入口、helper 与两个真实 read sink，但当前模型仍保守漏报。混合仲裁检测到风险不变量与 LLM clean 冲突，将 Gradio 两个目标符号送入复核，修复版本则由显式 `model_validate(..., context={"validate_meta": True})` 缓解证据支持。

Pillow 的 LLM 成对判断正确；混合仲裁仍对固定版本中未执行的 legacy `get_command` 保持复核，因为类级 ground-truth 会匹配该方法，而该方法本身缺少独立确定性 mitigation。这个结果是有意的 fail-closed 边界，不能把模型 clean 单方面升级为自动安全证明。

迭代中还执行了 5 轮、每轮 4 次的 Gradio/Pillow 定向诊断探针，共 105,829 tokens；这些是 post-hoc 调试成本，不计入上表最终持久化运行。第一版持久化 v1.7 run `42cc7e43-c1c8-4d72-bd85-3cd582d68a77` 使用 56,842 tokens，目标漏洞召回/修复特异度/成对区分为 0.80/0.80/0.60；最终版本把后两项提升到 1.00/0.80，主要收益来自 Pillow 不可达命令 builder 的执行边约束。所有这些结果仍是校准，不是新的 external holdout 结论。

## 工程验收

- Windows：208 tests，全部通过。
- Docker/Linux：208 tests，全部通过。
- 运行态：服务重建成功，`/health` 返回 `ok`。
- 数据身份：案例 SHA-256 `5640777521a02ec3bbf20144e52a6038a31ea40a6c47d2f1c03de4d58cded3e1`，v1.7.1 清单规范化 SHA-256 `e587d44778163f519476b765bedd826611a11ca9e77a7e306b63f6a5d35586f6`，分析器 SHA-256 `68d9e3b08b1d47b271814b4ef8dae570979a8cd94ff1146458329c7b3204412a`。

## 后续门禁

1. Windows 与 Linux 全量单元测试必须通过，校准清单谱系测试必须验证历史 holdout 身份和当前 analyzer 指纹。
2. 已使用后台实验 Runner 固化 v1.7 retrieval 与 `llm-retrieval` artifact；后续任何重跑必须创建新 run，不得覆盖本报告记录的两个 run。
3. LLM 校准用于检查“证据已可见后”的模型判别能力，不用于新的泛化宣传。若失败，优先改 Prompt/仲裁或引入人工复核，不反复用同一 5 例堆规则。
4. 冻结全新的 repository-disjoint v3；仓库、CVE、提交对、资源限制、分析器指纹和预算必须在任何运行前确定。
5. v3 对外至少同时报告检索、LLM 目标判别、确定性扫描、修复资格、Oracle 和人工复核率，避免用单一满分指标掩盖系统边界。
