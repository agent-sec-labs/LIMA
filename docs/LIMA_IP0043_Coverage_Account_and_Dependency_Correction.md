# IP-0043 覆盖账与依赖图订正（V5-AC-02 / K5 / R7 口径）

- 日期：2026-10-01。配套实现：IP-0043-C2（`benchmarks/v4/baseline/lf_baseline.py`、`lf_observation.py`、`expert_review.py`、`scripts/run_lf_baseline.py`、`scripts/run_expert_review.py`；契约记录见 `docs/LIMA_Implementation_Packet_IP-0043_LF_Local_Baseline.md`）。
- 依据：Coordinator Assignment CA-IP-0043-v1.0（R5/R7、C2 Allowed Files 第 7 项）、第十轮裁定 §3-§6、第九轮事实底料 `.pv_tmp/CRITICAL_PATH_FACTS_2026-10-01.md`（B-A/B-D 节）。
- 本文是**账目与依赖登记**，不宣称任何未证条款完成；生产 root-cause producer 缺口按依赖登记（owner/输入/产生点/AC），不伪称已证。

## 1. V5-AC-02 覆盖账（候选产生 → 选择 → 未选去向 → 模型处理）

### 1.1 `CANDIDATE_FILE_CAP=12` 两面证明（保留既有证据，不冒充新证）

- **请求构造面（cap 存在）**：`real_run.CANDIDATE_FILE_CAP=12`（`benchmarks/v4/baseline/real_run.py` L178；`b1_source.py` L93 同值）是每个模型请求文档的**候选文件选取上限**（每请求最多 12 个候选文件文本进入请求构造）。既有冻结测试 `tests/test_v4_baseline_v5_negatives.py`（L545 披露断言 `"CANDIDATE_FILE_CAP=12"`）与 IP-0043 新增 K5 文件 `tests/test_v4_baseline_identity_modes.py::TestV5AC02CoverageAccount::test_candidate_cap_two_sided_and_unselected_destination` 共同钉死：walk 面返回全部 15 个文件（`_walk_python_files` 无上限截断），选择面恰取 12（`_select_candidate_texts`）。cap 只约束请求输入，不约束处理。
- **处理面（cap 不截断 findings）**：**unselected** 对象的去向 = 扫描器面全量保留。同测试以 15 个同构 finding 验证：超出 cap 的候选文件对应的 finding 全部出现在 `RepositoryScanner` 的 findings 里（15/15，路径集合全等）；b1-real 实测 raw_candidates=24>12 亦为既有旁证（2026-10-01 批报告）。请求 cap 与 V5-AC-02"禁止隐藏处理上限"条款不冲突：禁令针对模型处理 finding 数上限，cap 针对单请求输入文件数。
- **诚实边界**：以上是离线可验证的两面证明。真实批"模型/队列对全量候选的完整处理"由 b1-real 既有证据（`pr3d-b1-real-2026-10-01`，real_post_count=5==ledger_calls=5）按其覆盖范围承载，不以本账冒充为"全量处理已证"。

### 1.2 零调用 workload 的模型处理账（IP-0043 新证）

- LF 本地基线（`run_lf_local_baseline_suite`）是零模型调用 workload：结构上无 wire client、无请求构造、无审批面；每个样本 prompt_tokens/completion_tokens/cost_micro_usd 恒为整数 0，套件 `model_calls == 0`。
- 模型处理面记账：零调用 workload 的"模型处理量 = 0"，来源 = `zero-model-calls-by-construction`（结构证明），由 `lf-local-observation-v1.json` 的 `model_usage` 面独立呈报（K5 文件 `test_zero_call_model_processing_and_dependency_registration` 为冻结验收面）。
- 注记：零模型使用**不**表示本地算力与真人时间免费（companion `model_usage.cost_note` 强制携带）；本地资源非货币成本不可折算，提供方实收 UNKNOWN（历史批同口径）。

## 2. K5 逐模式身份无关注（IP-0043 新测试面，冻结于 v13）

- 四模式 × 四身份变体（baseline/rename/repath/非语义 metadata）× 语义正反例（真阳性 os.system 真阴性 subprocess.run 参数数组）：
  - `deterministic`：判定/聚合指标跨身份变体恒等，身份面（dataset 名/dataset_sha256/manifest_sha256）诚实不同；repath（同字节内容换缓存目录）身份面恒等。
  - `retrieval`：注入确定性 content-keyed fake retriever；候选面仅随语义内容变化（8 次调用恰两 content digest），vulnerable/fixed 双面 path_hit/symbol_hit 真实可判。
  - `llm`：fake client **捕获实际输入** `triage(root, ground_truth_paths)`，按其真实读取的内容回答正/反例；捕获面跨身份变体恒等；纯 llm 响应不含 adjudication 面。
  - `llm-retrieval`：fake client 捕获 `triage_candidate_batch(candidates)` 候选集合；响应携带的 `adjudication` 被消费（dispositions 随内容 keyed 正/反例翻转），并由冻结 `adjudicate_evidence` 独立复算逐字节相等。
- 诚实边界：注入 fake 证明的是零网络零凭据下的局部可判定性质（判定上下文/候选集合/adjudication 消费身份无关），不宣称模型随机输出绝对恒等；生产 Prompt/评分/retrieval 策略零改动。

## 3. 依赖图订正（资源观测与真人计时 = baseline 侧收口）

旧依赖推断（"先裁 A1 即可解锁原生领域/资源链，再做 LlamaFactory 批"）不成立（第十轮裁定 §2/§3）。订正后的依赖图：

1. **资源观测**：不以 VEP/RVR 产生为前提。`report.py` L1405 起的 resources 绑定（domain 块唯一来源、缺席恒三键 null+unavailable）是**旧 v2 默认面**，保持零变化；IP-0043 以**独立 companion 文档**（`lf-local-observation-v1.json`，五重回指+per-attempt 资源面+测量语义注明+零调用模型面）在新 profile 上收口资源观测——修订范围仅限新 companion，不外溢旧 v2 默认。Windows 无 `resource` 模块/无 `/proc/self/io` 的面 = null+原因，禁 0 替代/猜值/fake source。**收口方 = baseline 侧（本 IP）**。
2. **真人计时/复核**：不以离线工程为串行前置。`expert_review.py` + `scripts/run_expert_review.py` 复用冻结 `ExpertTimingSession` 五键 sidecar 协议（reviewer 只存 sha256、事件状态机、单调钟），verdict 走冻结四值词表（agree/disagree/partially-agree/needs-more-evidence）+独立版本化 receipt；事件唯一去重防"一份事件复制到多 result 令时间倍增"；无真人回传 ⇒ sessions=0/active unavailable 如实（agents 不代真人计时/判断，绝对边界）。**收口方 = baseline 侧（本 IP，工具与入口）**；真人执行归 C-final 真人。
3. **root-cause Issue/Hypothesis/VEP/RVR 的生产语义（登记，不伪称已证）**：`lima/platform_contracts.py` 的构造器链（`finding_to_vep` L409-586、`_aep_finding_objects` L625-841、`platform_review_to_aep` L844-984、`seal_platform_review` L1221-1283）属 C++ agent 平台链，且 seal docstring 自认 "Report-embedded preview, not an artifact store...no independent artifact persistence"；`patch_outcome_to_rvr` "has no runtime caller yet"。baseline 链（B1/LF Python 扫描）与其正交：B1/B1-real 离线配置显式关闭平台分支，Signal/Issue 只经 compat legacy projection 产生，hypotheses/vep/rvr/stage 全 unavailable（b1-real 实测）。**A1/A2/A3（PR3e V5 Field Source Table §4）均不能凭模型 JSON 或专家填写产生真实动态验证 VEP、Repair RVR**——该裁定维持。
4. **Mining VEP / Repair RVR 挂现有生产 Issue（缺叶登记：owner/输入/产生点/AC）**：

   | 缺叶 | 挂靠（API 实测 2026-10-01 全部 open） | owner | 输入 | 产生点 | AC（要点） |
   | --- | --- | --- | --- | --- | --- |
   | 真实证据驱动的通用闭环（Mining VEP / Repair RVR 的生产产生点） | #85 `[EPIC][V5] 真实证据驱动的 Audit → Mining → Verified Repair 通用闭环`（子项 #59 任务 SLO/资源预算/成本遥测、#62 CWE-798 场景化降噪与语义证据、#79 跨仓库试点验收与 V5 Core Go/No-Go） | Maintainer（EPIC 裁量）；#57 Done 条款要求"在 #85 记录 #59/#62/#79 可消费的 fixture/digest"（该记录尚未在 #85 落地） | 真实 Audit→Mining→Repair 执行证据（非报告内嵌 preview）；可消费的稳定 fixture/digest = `evaluation_data/v4/fixture_registry.json` canonical 字节+逐条目 tree fingerprint（稳定性由 `tests/test_v4_baseline_fixtures.py` L486/L519/L630 三方法承载） | 生产平台链的独立 artifact store（现缺：scanner 仅内嵌 preview，RVR 无 runtime caller） | 按 #85/#59/#62/#79 各自正文 AC；#79 含 V5 Core Go/No-Go；缺叶不由本 IP 包办、不宣完成 |

   未观测到 #57↔{#59,#62,#79,#85} 依赖环（#57→Blocks→{#59,#62,#79} 与 Depends 为同一边两方向；#85 对 #57 是正文重写权，非依赖边）。
5. **不用任何"待裁 A1"总称包办**：本账所有缺口按上表 owner/输入/产生点/AC 逐项登记；不以任何单一"待裁"总称吸收未证面。

## 4. R7 计数口径声明（强制：447 与 596 不可直接比较）

- **scanner 面（本 IP LF 本地基线的期望口径）**：对 sealed snapshot 以生产 `RepositoryWorkspace(5000, 512KiB, 20MiB)` 只读亲测——`inventory.files`=**447**（measured），skipped={'file-size-limit':7,'sensitive-config':1,'unsupported-extension':141}，truncated=False，total_bytes=2,588,042。LF scanner 面期望：scanned_files=**447**、coverage_gap=**7**（reasons={'file-size-limit':7}；`_COVERAGE_AFFECTING_SKIPS` 七类口径，report.py L182-192——unsupported-extension/sensitive-config 不计入 coverage_gap）。
- **real-world payload 面（旧 09-28 报告口径）**：`49de84cec230e26f-report-1.json` counts.scanned_files=**596**，是真实世界评测载荷面的另一计数口径。snapshot 全量 = 596 文件 / 13,746,820 B（<20MiB 不触总量界；9 文件>512KiB，其中 7 个以 file-size-limit 计入 coverage gap、2 个先命中 unsupported-extension）。
- **声明**：447（scanner 面）与 596（payload 面）是**不同计数口径**，不可直接对比（compar）、不得强行对齐、不得互相冒充；任何报告/矩阵引用时必须并注口径。此声明同时写入 Packet（R7 口径声明节）。
- C-final 期望可观测值（Coordinator 亲测预置，供核对、非硬断言）：scanned_files=447、coverage_gap=7（file-size-limit×7）。
- **平台物化面注（DR-IP-0043-CFINAL §6 预告，随链接跳过修复登记）**：LF 套件按 Packet §3.1 平台文本行约定物化（每个 `\n` 写为 `os.linesep`），故 Windows 物化面 `total_bytes`=**2,657,168**（CRLF 平台面）vs 上述 R7 raw 面 2,588,042（LF 字节面）——这是**平台物化面差异，非缺陷**；文件计数、跳过分类与两口径结论均不受行尾约定影响，scanned_files=**447**/coverage_gap=**7** 在 raw 诊断面与平台物化面上预期**同成立**。

## 5. 账目状态（三态）

- 已证（离线可验证）：cap 两面、unselected 全量保留、零调用模型面（0+来源）、K5 四模式身份无关（注入面）、companion 资源面 null+原因、receipt 事件唯一去重。
- 已证（既有证据按其范围承载）：真实批模型调用与队列处理（b1-real 2026-10-01）、fixture/digest 稳定性（fixtures 三测试）。
- 未证（依赖登记，不宣称）：生产 root-cause producer（Mining VEP / Repair RVR 独立 artifact store，挂 #85 及子项）、真人复核事件（C-final 真人执行，当前 sessions=0 如实）、提供方实收（UNKNOWN）。
