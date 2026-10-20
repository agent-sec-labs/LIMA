# Specialist 提示词拆分试点报告（2026-10-18）

结论先说：这次对照不建议把 structured 提示词设为默认。剔除被污染的 overflow-direct 整组后，structured 正例确认 15/15（legacy 14/15），但负例误报 3/15 对 8/15，踩了计划里"负例误报总数不增加"这条硬门槛；同驱动判别双方打平（各 12/15），structured 此前的判别优势完全来自被剔除的污染组，不再成立。按计划第五任务的裁定规则，本轮保留内容不变的结构拆分（legacy 逐字节重建已验证一致），structured 作为可选 profile 留在代码里，误报问题留给后续独立对照。小样本（有效配对 60 次分析），不做任何显著性宣称。

## 实验设置

- 计划文件：`docs/superpowers/plans/2026-10-18-specialist-prompt-split-pilot.md`。
- A 组 = legacy 全提示词（10454 字符，SHA-256 `000cbb56…`，与任务一基线导出逐字节一致）；B 组 = structured 通用判据加四张机制卡（4968 字符，`common:v1` + lifetime/bounds/null/integer），不加载组件配方。
- 6 组配对案例（生命周期 2、越界 2、空值 1、整数到内存 1），4 开发 + 2 保留；每案例漏洞版与修复版各独立跑 3 次、两个 profile 交错，共 72 次目标分析，先 24 次开发集排接线再跑余下 48 次。
- 配对比较口径（2026-10-19 修订）：overflow-direct 的"修复版"在试点适配中被引入 `count=0 → buf[-1]` 的真实堆下溢读，不再是有效修复对照。该组正、负两侧全部 12 条记录从配对指标中整组剔除（含分母），有效配对为 5 组 60 次分析。原始 72 条记录全量保留在运行目录，未做任何改动。
- 模型声明（重要偏差）：基线记录的 gemini-3.7-flash@8045 在执行时已不可用（端口无监听，8046 网关报"模型不存在"）。实际使用 8046 网关上的 glm-5.3-flash。该网关对任何生成有 60 秒硬上限（上游 504），GLM-5.x 系默认推理在 Specialist 量级回复上必然超时，因此通过平台既有的 request_params 通道关闭 thinking（`{"thinking": {"type": "disabled"}}`）。temperature 0、json_object、max_tokens 8192 为传输层固定值。以上全部写入 `identity.json`。A/B 两组共用同一模型同一参数，组内对比有效；但与基线模型不同，跨批次外推要小心。
- 工作台：真实 ASan 隔离容器（landlock + 进程隔离健康检查通过），oracle 对照组 6/6 通过后才放行模型批次。
- 运行产物：`output/specialist-pilot/run-dev-2026-10-18/`（72 条记录、全量 `summary.json`、配对口径 `summary-paired.json`、identity、盲审目录 `poc-review-blind/`）。

## 指标（配对口径，剔除 overflow-direct 整组）

| 指标 | legacy | structured |
| --- | --- | --- |
| 正例运行时确认 | 14/15 | 15/15 |
| 同驱动版本判别（3 次重放全过） | 12/15 | 12/15 |
| 负例误报（语义级） | 3/15 | 8/15 |
| 负例运行时确认级误报 | 0 | 0 |
| 传输/网关错误 | 1 | 0 |
| Schema 失败（缺 cwe 字段） | 0 | 0 |
| 中位调用数（specialist+critic，全 72 次） | 2.0 | 2.0 |
| 中位实验数（正例，全 72 次） | 2.0 | 1.5 |
| 中位耗时（全部，秒，全 72 次） | 27.4 | 28.6 |

调用、实验与耗时按全 72 次统计（成本指标不受对照有效性影响，保留全样本）。两种口径都可从运行目录直接复算：`summary.json` 是脚本产出的全量统计（含被剔除组，正例 17/18 与 18/18、判别 14/18 与 15/18），`summary-paired.json` 是配对口径（记录了剔除对象与原因，72 条中用 60 条）。任何人可用 `python scripts/run_specialist_prompt_pilot.py --output output/specialist-pilot/run-dev-2026-10-18 --summarize-existing --exclude-case "overflow-direct=<原因>"` 从原始记录重新生成后者，该模式不触碰记录与 `summary.json`，也不发起模型或工作台调用。

## PoC 合法性审阅（非完全盲审，见限制）

41 个 runtime-confirmed 驱动全部人工过目，结论：均为契约内调用（多数自带界内负对照），没有自造释放、重复销毁或故障路径桩替换，双方均无非法 PoC 计入发现。

审阅状态如实说明：2026-10-18 的第一轮审阅文件名带 legacy/structured 标签，不满足计划的盲审要求。2026-10-19 补做了第二轮盲审复核对：41 份驱动按哈希化匿名名重排（案例名保留以便核对 API 契约，A/B 标签存于单独的 `_key.json`，裁决完成后才揭盲聚合），逐份按机械标准复核，结论与第一轮一致（41/41 合法）。裁决记录见 `poc-review-blind/verdicts.json`。限制：两轮是同一审阅者，第一轮已看过带标签版本，标签残余影响无法归零；且记录文件中的 `manual_validity` 字段保持脚本写入的 `pending` 未回填。按计划原验收条件，本轮人工核验按"有限审阅（带二次盲化复核）"计，不宣称完成盲审验收。

## 逐例要点

- uaf-direct、null-deref-direct、cleanup-release、indexed-read、narrow-size 的漏洞版双方都稳定确认。
- structured 的负例误报集中在 narrow-size（3/3）、indexed-read（2/3）、cleanup-release（2/3）：修复版明明有守卫，它仍给出 semantic-supported 级假设。legacy 在 narrow-size 和 indexed-read 的修复版上 3 次全部弃权。机制卡鼓励"先成形一个具体假设"，但没有配对的抑制条件，这是最说得通的解释；这属于可解释的退化，但按计划不因此返工提示词（保留集不许看结果后调，10 月 20 日封包）。
- overflow-direct（已整组剔除）：其"修复版"被双方 6/6 打穿（运行时确认级）。这不是误报——适配该案例时引入的读回语句在 count=0 时构成真实的 `buf[-1]` 堆下溢读，模型用契约内输入 `frame_write(0)` 合法触达并正确归类 CWE-125。该组修复版已不适合作为负例，源码修掉 count=0 下溢前不得再进任何批次。

## 门槛核对（计划第五任务）

- 硬约束测试全过：`tests/test_agent_orchestrator.py`、`tests/test_agent_repro_tools.py`、`tests/test_platform_evaluation.py`、`tests/test_agent_scale.py`、`tests/test_specialist_knowledge.py`、`tests/test_specialist_prompt_pilot.py` 共 173 通过（其中 2 项为 2026-10-19 复核后新增：漏洞包附录不自动进 structured 的边界测试、配对汇总剔除与参数解析测试）。
- 无新增已确认非法 PoC：过（41/41 合法，见上方审阅状态与限制）。
- 负例误报总数不增加：不过（3/15 到 8/15）。
- 有效版本判别总数不下降：过（12/15 对 12/15，持平；剔除污染组后 structured 无判别优势）。
- 中位调用数与实验数不增加、耗时无异常：过（调用持平、实验略少、耗时相当；structured 提示词本身更短，字节数普遍更低）。

## 环境与工具修复记录（本轮执行中动过的东西）

- `lima/specialist_knowledge.py`、`tests/test_specialist_knowledge.py`（Codex 已建，任务二三完成；legacy 逐字节一致性已复核）。2026-10-19 追加收紧：structured 通用模式不再自动追加任何漏洞包的提示词附录（原实现对注册表中所有非 memory 包盲式追加；当前注册表只有 memory 故无实际影响，但未来新增组件包会未经显式选择泄入通用模式）。组件包附录今后必须经 component 显式选择接入，防回归测试已加（fake 包注册后 structured 不含其附录、legacy 仍含，锁定两层边界）。当轮渲染文本逐字节不变。
- `scripts/run_specialist_prompt_pilot.py`、`tests/test_specialist_prompt_pilot.py`：oracle 驱动统一改为调用后 `return 0`（原先 `return fn(...)` 会把修复版按设计返回的 -1 变成退出码 255，撞上"修复版必须干净退出"的判定）；overflow-direct 与 null-deref-direct 改为带适配说明的试点专有源码（写死 -O1 下写后不读会被死存储消除、可能为 null 的无条件加载会被 UB 利用整体删掉，真实缺陷在固定旗标下根本不会发生）；快照键带代次目录前缀，多代冻结快照可共存在一个容器挂载下。
- `lima/agent_repro_tools.py`（加回归测试）：sidecar 的 ASan 解析把 SEGV 类截成裸 "SEGV"，而运行时词表匹配的是完整短语 "segv on unknown address"，导致经 repro 工作台验证的空指针 PoC 永远无法命中 CWE-476。观察转换层恢复类短语，词表与分析器契约未动。
- 基础设施（不入库）：Docker Desktop 对新建容器的端口发布全部失效（老绑定还活着），分析器改经 `docker exec` stdio 中继访问（`output/specialist-pilot/relay.py`，127.0.0.1:18093）；网关 60 秒生成上限与 thinking 禁用如上。

## 回退与后续

- 回退 profile 就是 legacy：`build_specialist_prompt(profile="legacy")` 逐字节重建原提示词，编排器默认行为未变。
- 后续若要救 structured：负例误报集中在"修复版有守卫仍给假设"，值得单独做一轮只收紧通用判据负例面的对照；机制卡按需选择（本轮固定全载）也留作独立实验。
- overflow-direct 修复版源码应修掉 count=0 下溢后再进任何后续批次。
- 新增漏洞包前，组件附录的显式接入边界已收紧并有测试锁定；新包接入时须走 component 选择路径而不是依赖注册即加载。

## 2026-10-19 补充：structured 判据 v2 开发集诊断

在上轮复核意见后，对 structured 的通用规则做了一次窄改动，legacy 文本和生产默认均未改变：要求按“真实入口 → 外部输入控制与传递 → 守卫和可达条件 → 目标操作 → 安全后果”逐环给源码位置；链条缺失或被反证时，只保留为待证线索；实验同时写清支持和推翻假设的观测，并把可疑代码、目标侧运行错误和安全影响分开。

使用同一 glm-5.3-flash 网关、temperature 0、关闭 thinking，在新目录 `output/specialist-pilot/run-structured-v2-2026-10-19/` 重跑开发分区三次重复。overflow-direct 按上文原因整组从配对汇总移除，原始记录仍保留。可复算工件为该目录的 `summary-paired.json`，完整模型与环境身份在 `identity.json`。

这轮只是开发集诊断，不是独立验收。36 条有效配对分析中，fixed 版被判为 `semantic-supported` 的次数为 legacy 5/9、structured-v2 3/9；漏洞版为 8/9 和 9/9。方向上看，v2 的语义误报较少，正例支持没有下降。但隔离工作台本轮有 51 条 `transport-failed` 观察，两个 profile 的 `runtime_confirmed` 与 `raw_discriminations` 均为 0；因此这轮没有证明 PoC 能运行，也没有证明版本判别改善。所有记录的 `manual_validity` 仍是 `pending`。这些计数不能替代上轮的正式门槛，也不能据此把 v2 设为默认。

下一步应先修复或确认试点工作台的传输问题，再用未参与提示词调整的独立样本验证；structured-v2 暂留为候选，legacy 继续默认。

### 传输问题定位与有效路径重跑

检查后确认，上述首轮 structured-v2 记录不能用于运行效果判断：工作台返回 `snapshot_rejected`，客户端将 HTTP 400 归一成 `C/C++ analyzer is unavailable`。原因是旧 `snapshots/manifest.json` 中的 `repository_key` 只有 `p...`，而 Sidecar 把 `output/specialist-pilot` 挂载为 `/repositories`，需要 `snapshots/p...` 才能定位源码。用补齐前缀的同一快照做单次 ASan 请求后，返回正常 `run`、退出码 0。

随后用新快照根和正确的 `--analyzer-url http://127.0.0.1:18093` 完成了三次开发集重跑。有效工件在 `output/specialist-pilot/run-structured-v2-fixed-workbench-2026-10-19/`，其中 48 条原始记录包括 overflow-direct；按配对口径排除该组后为 36 条。配对结果：漏洞版 runtime-confirmed 为 legacy 8/9、structured-v2 9/9；fixed 版语义支持为 legacy 2/9、structured-v2 4/9；同驱动原始判别为 8 次和 5 次。模型超时错误 2 次，均在 legacy；工作台 transport-failed 为 0。驱动合法性仍未人工裁定，36 条 `manual_validity` 均为 `pending`，所以不能把同驱动次数称为已审定的有效判别。

这次有效路径的开发集结果没有显示 v2 降低负例误报：fixed 版的语义支持次数反而高于 legacy。它在漏洞版多确认 1 次，但样本少且有模型超时，不能据此声称整体改善。structured-v2 继续作为候选，legacy 继续默认。脚本现已增加快照仓库键前缀校验；再次遇到旧清单会立即报错，而不是把路径错误伪装成工作台不可用。

## 局限

- 有效配对 60 次分析、5 组合成配对案例，样本量只够方向性判断，计划明令不做显著提升宣称。
- 开发集 4 组中有 3 组直接或间接改写过（oracle 适配），不是独立测试集；保留集 2 组（indexed-read、narrow-size）未参与任何调优。
- 模型从基线的 gemini-3.7-flash 换成 glm-5.3-flash（thinking 关闭），A/B 组内有效，不代表其他模型上的结论。
- 人工 PoC 审阅为同一审阅者的两轮（第一轮带标签、第二轮盲化复核），非独立盲审；记录字段未回填。
- 工作台存在偶发 ASan 运行时启动段错误（PIE 布局类，运行器已有三次重试，个别重放轮全灭），对双方等概率，计入原始记录未剔除。
