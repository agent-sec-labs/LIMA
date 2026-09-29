# LIMA PR3-e V5 指标逐字段来源表（IP-0037 C1 交付；R7 承载）

- 文档 ID：`LIMA_PR3e_V5_Field_Source_Table` v1.0（2026-09-29；IP-0037 Packet=`docs/LIMA_Implementation_Packet_IP-0037_Batch_Protocol.md` §7.7 的唯一展开载体）。
- 授权出处：第四轮授权阶段 D 第 1 条（"沿真实数据流逐字段追踪 Signal、Issue、Hypothesis、VEP、RVR、stage_outcome、专家分钟：从扫描器/评估器产生，到 evaluator payload，再到报告及回指 digest。形成逐字段'真实来源/当前缺口/可验证证据'表"——I-5 出处成立，CA-IP-0037-v1.0 R7）。
- 代码基线：main=`ddb8675fc13e081cff0a7ce151849e64f6fdf85b`（本 P&V 会话逐锚亲读；行号以该基线为准）。
- 纪律（与 AC-5 一致）：本表只登记**已实现且可离线复现**的事实与**如实标注的缺口**；不写常数、不以 synthetic 冒充真实扫描、无来源→null+`unavailable`；表内不宣称任何未验证状态。

## 0. 当前真实入口的唯一事实（先行，全表上下文）

当前 PR3 真实运行入口是 `benchmarks/v4/baseline/real_run.py` 的 **llm-bounded-triage**：

- 每次调用构造**有界候选上下文**：`_walk_python_files` 全量遍历（WALK_ENTRY_CAP=5000 防失控）后 `_select_candidate_texts` 取 `[:CANDIDATE_FILE_CAP]`（=12，L150；**请求构造参数，非处理/复核上限**），MAX_CONTEXT_CHARS=36000/CANDIDATE_CHAR_CAP=6000 截断；
- 模型输出契约为**每候选单二元 verdict**：`{"is_vulnerable": bool, "cwe": str|null, "path": str|null, "reason": str}`（`_VERDICT_FIELDS` L179-181 冻结；response_format=json_object/thinking disabled/max_tokens=8000）；
- evaluator payload（`_GuardedRealEvaluator.build_payload()` L1345-1373）：schema_version=2、mode="llm-bounded-triage"、`metrics={"cases": 1}`、`results[0].deterministic.total_findings={"bounded-candidate-files": scanned}`、workspace 逐 revision `files/scanned/skipped{"unselected": files-scanned}`；
- **payload 无 `domain` 子块** → 报告层一切 domain 来源面保持 null+`unavailable`（IP-0036 R2.3 接线规则的缺席分支）。

报告投影唯一消费点：`benchmarks/v4/baseline/report.py` `build_baseline_report`（L1244-）经 `_recognize_evaluator_payload`（识别为 "real-world" v2）与 `_validated_domain_block`（L1132-1170：在场必须合规否则 `EVALUATOR_PAYLOAD_INVALID` fail-closed；缺席→None）。

## 1. 逐字段来源表（三列制；恰十行）

| # | 字段（报告面） | 真实来源（产生点：模块/函数/数据流位置） | 当前缺口（为何不可得/仅部分可得） | 可验证证据（离线可复现断言/测试/工件指针） |
| --- | --- | --- | --- | --- |
| 1 | **Signal**（`counts.signals`：{value,projection} 三值形态） | 唯一机器来源=report.py `build_baseline_report` domain 子块 `domain.signals`（IP-0036 R2.3 接线；scanner 路径另有 `EvidenceDomainBundle` 派生面）。数据流：信号产生点（扫描器/评估器）→ payload `domain` 块 → counts 投影 → 报告 → `sources[].payload_sha256` 回指 | llm-bounded-triage 的单二元 verdict **不产生信号计数**（无信号概念）；真实运行 payload 无 domain 块 → 现状 (None,"unavailable")。两次真实运行（2026-09-27/28）报告该面均为 null+unavailable | report.py L1346-1356（domain→measured 分支）/L1360-1364（缺席→unavailable 分支）亲读；冻结测试 tests/test_v4_baseline_report.py `test_realworld_domain_block_wires_measured_faces`/`test_domain_absent_keeps_unavailable_everywhere`；两批真实运行报告工件（`D:\BaseAIProject\LIMA-real-runs\**`，字段级 null+unavailable） |
| 2 | **Issue**（`counts.security_issues`） | 同 Signal：`domain.security_issues`（domain 子块；scanner 路径 bundle 派生面） | 同上：单二元 verdict 每候选至多一个漏洞判定，不产生"安全议题"分级计数；真实运行现状 null+unavailable | 同上锚+`_validated_domain_block` 对五 int 键（signals/security_issues/hypotheses/vep/rvr）的合规校验（L1153-1156）；冻结测试同上 |
| 3 | **Hypothesis**（`counts.hypotheses`） | 同构：`domain.hypotheses`；scanner 路径 `bundle.vulnerability_hypotheses` 派生（DR-IP-0036-PV-2：bundle 在场优先于 domain） | Audit 阶段假设产生点（Repository 语义剪枝→Evidence-backed Hypothesis）未接入真实运行入口；真实运行现状 null+unavailable | report.py L1318-1332（bundle 优先分支）；冻结测试 `test_bundle_precedence_over_domain_counts` |
| 4 | **VEP**（顶层 `vep`：{value,projection}） | **唯一**来源=`domain.vep`（DR-IP-0036-PV-2：vep/rvr/stage_outcome/resources 恒以 domain 为唯一来源）。VEP 本体=Vulnerability Evidence Package，产生点应为 Mining 沙箱动态验证（目标态 Golden Path） | Mining 阶段未接入真实运行路径：无 VEP 产生点→无 domain 块→现状 (None,"unavailable")。**不是编码缺口而是阶段缺席**（如实登记，不以 synthetic 冒充） | report.py L1415-1419（domain measured）/L1428-1431（缺席 unavailable）亲读；冻结测试 `test_vep_rvr_stage_outcome_null_discipline`；两批真实运行报告字段级核对 |
| 5 | **RVR**（顶层 `rvr`） | 唯一来源=`domain.rvr`。RVR 本体=Repair Verification Report，产生点应为独立 Repair 沙箱（Security+Functional Preservation Gates） | Repair 阶段未接入真实运行路径：无 RVR 产生点→现状 (None,"unavailable")。同 VEP 为阶段缺席 | 同上锚；`_validated_domain_block` 五 int 键含 vep/rvr；冻结测试同上 |
| 6 | **stage_outcome**（顶层三键映射 audit/mining/repair，每值 {value,projection}，值域闭集 completed/skipped/failed/inconclusive） | 唯一来源=`domain.stage_outcome` 三键闭集（词表=DR-IP-0036-PV-1） | 真实运行路径无 domain 块→三键全 (None,"unavailable")（现状诚实保持；"阶段结局"需各阶段产生点存在） | report.py L1416-1418/L1429-1431；`_STAGE_OUTCOME_VALUES` 词表校验（L1160-1163）；冻结测试 `test_schema_v2_surface_and_v1_rejected`/`test_vep_rvr_stage_outcome_null_discipline` |
| 7 | **专家分钟**（`expert.active_time_ms_total`/`sessions`/`reviewer_digests`） | 真人流程：`benchmarks/v4/baseline/expert_timing.py` `ExpertTimingSession`（开始/暂停/恢复/结束，ns 时间戳）→ `.expert-timing.json` sidecar（5 键：schema_version/run_spec_digest/reviewer_digest/active_time_ms/events；reviewer 身份只以 SHA-256 摘要出现）→ report.py `_gate_sidecar`（run_spec_digest 配对门）→ expert 块聚合 | 真实运行路径**零真人专家事件**→sessions=0/active_time_ms_total=None/reviewer_digests=[]（缺席纪律：不得以模型调用或合成事件填充）；协议已可用（IP-0036 专家包）但无执行证据 | `docs/LIMA_PR3e_Expert_Review_Package.md` 示例 sidecar（字面通过现行 `_gate_sidecar`/`_validate_sidecar_artifact`——本 P&V 前序会话双验证亲验）；冻结测试 `test_expert_package_example_sidecar_passes_frozen_validators`；两批真实运行报告 expert 块缺席核对 |
| 8 | **原始候选**（`compression_chain.raw_candidates`） | llm-bounded-triage：real_run.py `_select_candidate_texts`（`[:CANDIDATE_FILE_CAP]`=12 请求构造）→ `build_payload` `total_findings={"bounded-candidate-files": scanned}` → report.py real-world 分支 `raw_candidates += sum(deterministic["total_findings"].values())`（L1379-1381） | **语义缺口（如实登记）**：该值=**有界候选文件数**（≤12），非全仓原始告警数——真"raw"候选（扫描器全量 findings）在当前入口不存在；raw_candidates 是十行中唯一在真实运行路径 measured 的候选面，但其语义边界必须如此披露 | real_run.py L150/L1041-1078 亲读；冻结测试 tests/test_v4_baseline_v5_negatives.py 探针 3（`test_runner_face_cap_is_request_construction_parameter`：`_walk_python_files` 全量返回+`_select_candidate_texts` 恰取 12）；两批真实运行报告 raw_candidates==bounded 候选数 |
| 9 | **压缩队列**（`compression_chain`：deterministic_alerts/confirmed/inconclusive/两级 ratio_basis_points） | 完整链的来源=raw→deterministic→confirmed 分级产生点（scanner 路径：`finding.verification_state` 分级→report.py L1308-1326；e2e 路径：metrics tp/fp） | llm-bounded-triage 单二元 verdict **无确定性告警/确认分级**→真实运行路径 chain 中 deterministic_alerts/confirmed/inconclusive 及两级比率全 None（仅 raw_candidates measured；`_ratio_link` 对 None 输入产出 None 链）——"压缩"语义在当前入口不可观测 | report.py L1436-1450（chain 构造）/L1300-1326（scanner 分级先例）亲读；冻结测试 test_report 现有 chain 断言；两批真实运行报告 chain 字段级核对 |
| 10 | **资源指标**（`resources`：prompt_tokens/completion_tokens/cost_micro_usd 三键） | 唯一报告侧来源=payload `domain.resources` 三键（IP-0036 R2.3）。注意数据流分离：BudgetLedger 的 usage 记账（budget 面，ledger.json）**不进**报告 resources 面——两面上报与预算门禁隔离 | 真实运行 payload 无 domain.resources→三键 None（现状诚实保持）。usage 事实存在于 ledger/attempts 证据面（budget 结算），但按冻结数据流不得自行桥接进报告 | report.py L1420-1426/L1432-1436 亲读；IP-0036 Packet §7.1.1-3；冻结测试 `test_realworld_domain_block_wires_measured_faces`（resources 接线面）/`test_domain_absent_keeps_unavailable_everywhere` |

## 2. 覆盖核对（行集恰十行）

Signal / Issue / Hypothesis / VEP / RVR / stage_outcome / 专家分钟 / 原始候选 / 压缩队列 / 资源指标 —— 与第四轮授权阶段 D 第 1 条列举的字段族逐一对应（Signal-Issue-Hypothesis 三计数位、VEP/RVR/stage_outcome 三阶段位、专家分钟、原始候选/压缩队列两候选位、资源指标）；无增行无缺行。

## 3. 缺口汇总（呈报前事实面）

1. **模型输出契约面**：单二元 verdict 无信号/议题/假设/多 finding 结构 → counts 三面与任何多信号面在真实运行路径不可 measured（行 1-3）。
2. **阶段缺席面**：Mining（VEP）/Repair（RVR/stage_outcome.repair）产生点未接入 → 恒 unavailable（行 4-6）。
3. **扫描语义面**：raw 候选/确定性分级产生点缺席 → 压缩链仅 raw（有界语义）可测（行 8-9）。
4. **人工面**：专家分钟协议可用、执行缺席（行 7）；资源指标报告面缺席而预算面在场（行 10）。

## 4. DR-IP-0037-01 草案（Decision Request；不实现、不自行造语义；呈报 Maintainer 决策）

**对象**：V5 来源表识别的模型输出契约与扫描语义缺口（§3-1/§3-3）的承接路径。两组选项组内互斥（每验收面只允许一个来源）；组间可组合。

### 组 A：模型输出契约扩展（对象=`_VERDICT_FIELDS` 单二元 verdict 与 counts 三面接线）

| 选项 | 语义 | 影响面 | 验收形态（示意，非实现承诺） |
| --- | --- | --- | --- |
| **A1** | 扩展 verdict 为多 finding 契约：每候选返回 `{findings: [{signal, cwe, path, reason, confidence?}, …]}`（上限钉扎，fail-closed） | 响应契约/检查点族/错误面扩展（新 IP+Packet 冻结）；预算维度随 token 增长重估；`_VERDICT_FIELDS` 冻结面显式演进 | fake transport 多 finding 响应→domain 块构造→counts.signals/issues/hypotheses measured 且与脚本值恒等 |
| **A2** | 保持二元 verdict + 独立多信号 evaluator 轮：第二请求轮（不同 prompt/候选集）专职产生 signals/hypotheses 计数，verdict 轮不变 | 编排新增轮次；attempt 计量与真实批结算细则（决策包 v4 联动）；预算工件维度扩展 | 独立轮计数写入 domain 块→counts 面 measured；verdict 轮行为逐字节保持 |
| **A3** | V5 指标仅人工专家供给：domain 块由专家/操作者按签发协议手工构造并随证据链登记，模型契约零扩展 | 零模型契约改动；需 domain 块签发/防篡改协议（谁可签发、如何回指 digest）；流程文档+工件协议新 IP | 签发的 domain 块经 `_validated_domain_block` 合规→measured；来源登记（签发者摘要）入证据面 |

### 组 B：扫描语义扩展（对象=raw 候选/确定性分级产生点）

| 选项 | 语义 | 影响面 | 验收形态（示意） |
| --- | --- | --- | --- |
| **B1** | 接入本地扫描器作为 raw 候选产生点：`RepositoryScanner` findings→raw_candidates/deterministic_alerts，llm triage 仅对 top 候选 | real_run 入口编排扩展（扫描轮+triage 轮）；压缩链分级语义启用；`raw_candidates` 语义从"有界候选文件数"迁移 | raw>deterministic 两级比率 measured 且与扫描器输出恒等；triage 轮行为保持 |
| **B2** | 维持 llm-bounded-triage 单入口：raw_candidates 语义保持"有界候选文件数"并在报告 declarations/文档明示 | 零代码；语义钉扎入文档（本表 §1 行 8 已如实登记） | declarations/文档一致性断言；报告面持续 null+unavailable 纪律 |

### 推荐（呈报供裁定，不构成裁定）

- 组 A：短期 **A3**（最小授权面、零契约改动，与第四轮零真实调用边界一致）；A1/A2 待真实批授权与预算重估后另裁。
- 组 B：短期 **B2**（如实语义钉扎）；中期 **B1** 是补齐 raw/压缩链缺口的唯一机器路径，建议随 Mining 阶段接入规划合并裁定。

### 呈报边界

本草案不预设结论、不实现任何选项；任何选项的采纳均需新 IP（Packet 冻结+测试冻结+实现），本叶（IP-0037）零实现。表内全部"现状"描述与 ddb8675 实现一致（无未验证宣称）。

（表完；版本 v1.0。）
