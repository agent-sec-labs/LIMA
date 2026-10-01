# LIMA Implementation Packet — IP-0041 B1 真实入口使能（#251，一次性 signal-storm pilot 准备叶，C1-C3 零真实调用）

- Packet ID：IP-0041；版本 v1.0（2026-10-01）。
- Coordinator Assignment：CA-IP-0041-v1.0（2026-10-01；范围权威含附录 R1-R7，全文转录见 §15；Intent Record `.pv_tmp/INTENT_RECORD_IP-0041_REAL_ENTRY_2026-10-01.md`（M1-M46/F1-F7/P1-P4/Q1-Q5）由其裁定；**本 Assignment 为唯一裁定权威，本 Packet 全文转录不得改义**）。
- Source Issue：#251（open，V4-I01，2026-10-01T02:54:48Z 建，AC-1..AC-5，parent #57 保持 open/PR3 未勾；正文经派发消息所附 create_issue_ip0041.py BODY 转录消费——本 P&V 会话按第八轮授权离线运行【零网络】，未独立 GET Issue 正文；#251 需求语义以 CA §Goal and Scope + 第八轮裁定 §三-§八 逐字为权威，Scope 1-9/AC-1..AC-5/Non-goals 与裁定逐字一致——Coordinator 2026-10-01 亲核该脚本与远程 #251）。
- Operating Mode：SHADOW（治理链路）；Execution Authorization：MAINTAINER_AUTHORIZED（2026-10-01 第八轮；**一次性 pilot attempt_policy={cold:1, warm:4, max_attempts:5}、成功路径恰 5 次真实模型 POST、硬上限 5、失败保守计数、不重试不补次不另开目录**；九类 72 次不批准；第六轮 5/5 已耗尽不复用）。**本 Assignment（C1+C2）及 C3 全程零真实模型调用、零网络、零付费、零凭据注入、零远端写**；一次性真实 pilot 不在本 Assignment 授权内（C-final/主会话，R6）。
- 裁定全文：`.pv_tmp/ZCODE_LONG_TASK_B1_REAL_INTEGRATION_RULING_2026-10-01.md` §一-§九（内容 SHA-256 `9b2258c11334f45e8aae2ad545354a1836d6248afc57c2df85448b72ca09dacd`，Intent Record 绑定）。
- Base SHA（完整 40 位，C1 基线）：`20e51e34635337a8712d0d4b7784bde3ed42b2ed`（= PR #250 merge；本 P&V 会话 2026-10-01 于 worktree 亲验 `git rev-parse HEAD` 同 SHA、`git status --short` 干净）。
- 基线产物指纹（本 P&V 会话 `git ls-tree HEAD` 程序化复核）：real_run.py `d542c697`、b1_source.py `9b188073`、budget.py `6c783848`、fixtures.py `700ec4fc`；四冻结测试文件 test_v4_baseline_real_run.py `18bfb4c2`（112 方法）/ test_v4_baseline_b1_source.py `a3b4c8fc`（20）/ test_v4_baseline_report.py `86f584cb`（38）/ test_v4_baseline_v5_negatives.py `6887f9fa`（9）；Dockerfile `18a23d25`；IP-0040 Packet（先例）已入库。
- 冻结前基线绿（REVERIFIED 2026-10-01 亲验，`.pv_tmp/B1_REVERIFIED_IP-0040_2026-10-01/REVERIFIED_RECORD.md` §2.D）：四冻结文件 **179 passed**（20+112+38+9）；全量 discover **2748 OK / skipped=24**（279.280s，exit 0）；signal-storm 独立直扫锚 **24 findings 全 candidate**、malicious-layout=4、library=1；注册表 `SYNTHETIC_FIXTURE_KEYS` 12 合成键 + 1 external = 13。
- 本 Packet 的角色：Implementation（阶段 C3）的唯一实现依据；冻结验收测试面（§8/§9，新文件 `tests/test_v4_baseline_b1_real.py`，冻结版本 v11 = v10' 之后序号）的唯一语义来源；P&V 独立验证的基准；裁定 §六精确工件离线双证（C-final 阶段，另授）的规格来源。

## 0. 交付物角色声明（强制，先于一切）

1. 本 Packet 与 Dockerfile 恰 +1 行 COPY 是 P&V 的 C1 交付物；**新测试文件 `tests/test_v4_baseline_b1_real.py`（v11，≤26 方法）+ 恰 7 个授权同步点（§7.7）是 P&V 的 C2 交付物（Frozen Test Commit）**；`benchmarks/v4/baseline/b1_real.py`（新公共入口 `run_b1_real_baseline_suite`）与 `real_run.py` 的 §7.4 点名例外（E0-E4）是 **Implementation 的 C3 交付物**。边界不得互换：Implementation 不得修改本 Packet/测试；P&V 不实现产品功能。
2. **零真实调用绝对禁令（C1-C3 与 CI 全程）**：任何真实模型调用（含一次 POST）、网络下载、付费动作、真实凭据注入 = 绝对停（Stop 1）。模型层验证只用注入式 fake transport（孪生纪律，§7.1）；CI 永远零付费模型请求（PC1 延续）。
3. **一次性 pilot 效力与本叶分离**：本叶交付的是"入口使能 + 离线精确孪生 + 负例 + 回归"的**代码能力与证明**；真实 pilot（裁定 §七临调用门）是 C-final 后主会话专属。离线孪生证明的是入口/门/绑定行为，**不是 pilot 成功贯通**；`insufficient_sample`（{1,4} < 3c+5w 充分门）是诚实统计态非失败。
4. **冻结面零回退**：IP-0024..0040 一切冻结面零回退；`b1_source.py` 离线入口及 model_calls=0 契约只读（不得就地变成付费入口）；`budget.py` 维度/门序/结算语义、旧 canary/首败逻辑、旧 estimate 常量、transport、身份允许集、模型契约（请求名/base_url/thinking/max_tokens=8000/请求体上限/二元输出契约）、旧描述子、旧批准工件、旧公共入口 `run_real_baseline_suite` 九参数签名与 order 1-9 全部冻结（§7.4 例外清单外零 hunk）。
5. **旧闭集不增字段**：旧五件套证据（approval/ledger/machine_profile/attempts/manifest）、旧 b1 manifest/report 闭集零增字段；B1 真实绑定经独立 companion 工件承载（§7.5，R3）。
6. **主会话职责（非本 PR 面）**：合并/推送/PR/Issue 评论等一切远端写；一次性真实 pilot（裁定 §七）；#57 Delivery Ledger 更新（pilot 终局后只提升"B1 新入口在真实传输下贯通"一行，PR3 不勾选）。ER 不得复现真实 pilot（裁定 §四）。

## 1. 需求映射（Packet 头）

```text
Source Issue：#251（open；AC-1..AC-5；正文经派发消息所附 create_issue_ip0041.py BODY 转录，本会话离线未独立 GET）
Issue specification revision：2026-10-01 创建版（Scope 1-9/AC-1..AC-5/Non-goals 与第八轮裁定逐字一致；Delivery Ledger 待主会话持久化）
Covered requirements：FR-01..FR-08（编号规范化见下表；语义=CA §Goal and Scope+裁定 §三-§八 逐字，不改义）、AC-1..AC-5（本叶 PR 面内可证部分）、NFR-01..NFR-04
Not covered requirements：任何真实模型调用/网络下载/付费/凭据注入；九类付费批（72 次不折抵）；A1/A2/A3；真实 Mining/Repair；真人分钟；Signal/Issue/Hypothesis 原生语义升级、scanner verification_state 变更、模型全局二元判定当逐 finding 结论；lima/** 与 scanner 规则/标签/匹配评分/holdout 修改；budget.py 维度/门序/结算放松；旧 canary/首败放松；旧 estimate 常量与全局保守预留改写；b1_source.py 离线入口及 model_calls=0 契约改动；旧入口参数化或默认语义变化；旧 real-pilot/large-repo 描述子修改或批准工件复用；旧 112/38/9/20 方法语义弱化；模型契约扩展（换模型/扩身份集/改 prompt/追加轮次/改 max_tokens=8000/改请求体上限/改二元输出）；#57 关闭/PR3 勾选；signal-storm pilot 算九类样本；批后脱敏/封存/专家包/#57 更新（裁定 §八，pilot 终局后另行）；裁定 §七临调用门与一次性真实 pilot 执行（C-final/主会话）
Delivery role：capability-slice（B1 真实入口使能：受审真实传输原语复用 + 本地 scanner 来源绑定 + companion 证据 + 七维门 + 一次性 {1c+4w} pilot 准备，本叶全程零真实调用）
Issue closure impact：PARTIAL（IP-0041 完成 ≠ #251 完成 ≠ #57 完成；"B1 新入口在真实传输下贯通"需 C-final 真实 pilot 证据后方可提升）
Upstream IP/PR/merge commits：基线=IP-0040/#249 收口（PR #250 merge 20e51e34，main lima-ci run 36753579501 attempt 2 success）；直接消费面=real_run.py 真实守护链（IP-0032..0039）、budget.py 七维门（IP-0031）、b1_source.py 离线 B1 契约（IP-0040）、report.py scanner 类型路径（IP-0029/IP-0040）、fixtures.py 13 键注册表（IP-0030/0036）；先例 IP-0039（第十一键 real-pilot 描述子与授权同步点）
```

| 需求（规范化） | 内容（语义=CA/裁定原文，不改义） | 本 Packet 承载 | 验收面（§8 方法） |
| --- | --- | --- | --- |
| FR-01（=Scope 1） | 新显式 B1 真实公共入口 `run_b1_real_baseline_suite`（新文件 b1_real.py），复用既有真实 approval/预算/身份/请求体/transport/canary/首败/截止/结算/取消基元；不复制缺门禁 HTTP 驱动；不串联两批合并目录；real_run.py 仅最小受审演进（新描述子限定 hook，Packet 点名）；旧公共入口默认语义/旧描述子/旧审批/旧请求契约/旧预算门/旧统计规则冻结；b1_source.py 离线入口及 model_calls=0 契约不变 | §7.2/§7.4 | M1、M2、M20、M21、M22、M23 |
| FR-02（=Scope 2） | companion 工件优先独立：经真实 suite 的 RunSpec/RunResult/attempt/approval/ledger/request-body/snapshot digest 形成完整绑定；旧 ledger/manifest/report 闭集不随意增字段；版本区分演进默认不触发 | §7.5 | M8、M10、M11、M12 |
| FR-03（=Scope 3） | 本次专属真实描述子（第十二键）：approval_type、唯一 run_name、date/retrieval_date=2026-10-01（Asia/Shanghai；跨日未启动须重新受审）、fixture_key=archetype/signal-storm、workload、scanner config、source contract/version、stop_on_first_failure；signal-storm 本地物化不误入网络下载；不修改 real-pilot/large-repo 旧批准 | §7.3/§7.6 | M6、M7、M13、M14 |
| FR-04（=Scope 4） | 一个批准范围/一个预算账本/一套全局 attempt 序号；先校验后物化/扫描/请求体/POST；POST 前任何失败=零 POST；首败后零新 POST；scanner/模型上下文/receipt 绑同一实际 snapshot；scanner 配置禁 LLM/platform/网络/code-exec；cold attempt-0=初始物化+scanner 执行（cold_reset.performed=False、materialization_count=1）；warm 1-4 复用同 snapshot/扫描/请求体（receipt 明确 scanner_reexecuted/scanner_result_reused/snapshot_reused/request_body_rebuilt） | §7.4(E3)/§7.5 | M8、M9、M16、M17 |
| FR-05（=Scope 5） | 七维逐值冻结（§7.6 表，不得增加）；198000 μUSD=US$0.198 内部冻结公式批上限非账单承诺；SDK/transport 自动重试关闭；所有实际 POST 由计数器独立审计；新 B1 路径扫描/来源物化占用允许 Packet 登记的保守估算分支，仍服从七维及既有预算门；无法在限额内证明可执行则零真实 POST 并呈报差额 | §7.6 | M3、M4、M5 |
| FR-06（=Scope 6） | 模型契约沿用（deepseek-v4-flash/身份集/base_url/thinking/max_tokens=8000/请求体上限/二元输出）；临调用门（价格页/仓外目录/凭据进程内注入/首请求即 attempt-0 canary/无额外连通性请求）——**本叶只承载其离线可测面与登记，执行属 C-final/主会话** | §7.4/§7.6 | M1、M18、M21 |
| FR-07（=Scope 7） | 报告走真实 scanner 类型路径；scanned_files/coverage/raw_candidates=合并后 findings 与直接扫描逐值一致（5 重复样本不求和成 120）；Signal/Issue legacy_projection；Hypothesis/VEP/RVR/未执行阶段/resources/专家缺席 unavailable 纪律；模型层费用/usage 真实 ledger/attempts 如实记账；整个真实 suite 准确写实际 POST 数（禁总 model_calls=0 或 offline-proof 误导标记） | §7.5.4/§7.5.5 | M2、M9、M11 |
| FR-08（=Scope 8） | 精确工件离线双证（最终描述子/七维/日期/workload 的无付费效力孪生+fake transport+全新空目录执行到报告；成功路径逐值+全负例面+回归）——**本叶交付其冻结测试面（v11）与实现；C-final 阶段由 P&V 在独立 worktree 执行**（R6） | §8/§9/§13 | M1-M20 + C2 Done Commands |
| FR-09（=Scope 9） | 批后（脱敏/封存/费用三层/专家包/#57 单行提升）——**完全 Not covered 本叶**（裁定 §八，pilot 终局后另行） | §4/§17 | 无（登记缺口） |
| AC-1 | 入口贯通：新真实入口从全新空目录、经真实 approval/预算门/身份/transport，以 {1c+4w} 授权形状完成执行（离线精确孪生逐值证明；一次真实 pilot 在 C-final） | §7.1/§7.2 | M1、M3、M5 |
| AC-2 | 预算受审：七维逐值写入批准工件与离线孪生；真实执行不超限、失败与未知 POST 保守计数；SDK 重试关闭、独立计数器审计 | §7.6 | M2、M3、M4、M5 |
| AC-3 | 来源绑定：scanner→receipt→RunResult→报告全链绑同一 snapshot，digest 交叉核验可回指；报告计数与直扫逐值一致且不求和 | §7.5 | M8-M12 |
| AC-4 | 投影诚实：三态投影与 unavailable 纪律；真实 suite 记实际 POST 数与真实 usage；费用三层不混淆 | §7.5.4/§7.5.5 | M2、M9 |
| AC-5 | 冻结面零回退：旧 real_run 112/报告 38/负例 9/B1 20 行为零变化；b1_source.py 离线契约不变；全量 discover 无回退 | §7.4/§7.8 | M13-M23 + C2 Done Commands |
| NFR-01 | 真实计数面：独立 POST 计数器（包装 transport，POST-only 计数）；manifest/result 面记录真实传输计数与 usage；禁 model_calls=0/offline-proof 误导 | §7.5.5 | M2 |
| NFR-02 | 离线/secretless 纪律：新文件零环境读、零网络根 import（lazy b1_source import 除外，其自身离线）、无凭据；测试源自扫描（PC1） | §6/§10 | M24、M25 |
| NFR-03 | 日期钉扎：date_pin=retrieval_date_pin="2026-10-01"（Asia/Shanghai）；孪生工件内日期面与描述子钉扎逐字一致（漂移=负例）；跨日失效条款（§12 Stop 5 逐字） | §7.3/§12 | M6、M14 |
| NFR-04 | workload 身份分离：B1 真实 workload `b1-real-signal-storm-v1` 进入 scanner config 文档 digest ⇒ run identity；与离线 `b1-offline-scanner-v1` 及历史 pilot 分属不同 workload 不可比 | §7.3/§7.5.2 | M6、M7 |

**Not-covered（全团队不得扩张）**：见上文 Not covered requirements 段与 §12 Stop Conditions（= CA §Not covered 全部）。

## 2. Design Input Manifest

| # | 输入 | 类型/版本/位置 | 消费方式 | Authority |
| --- | --- | --- | --- | --- |
| DI-001 | CA-IP-0041-v1.0 | `.pv_tmp/COORDINATOR_ASSIGNMENT_IP-0041_2026-10-01.md`（2026-10-01） | 范围权威；附录 R1-R7 转录见 §15；本 Packet 逐条承载 | normative |
| DI-002 | Intent Record INTENT-REC-2026-10-01-B1-REAL-ENTRY-001 | `.pv_tmp/INTENT_RECORD_IP-0041_REAL_ENTRY_2026-10-01.md`（M1-M46/F1-F7/P1-P4/Q1-Q5） | 授权语义（M10-M35 决定性语义、F2 download/storage 同值推断、F3 独立直扫真值、S1 双入口对照表建议）；关键事实全部经本会话代码亲核（DI-005..DI-011） | normative（经 Assignment 消费） |
| DI-003 | 第八轮裁定（Maintainer 已下达生效） | `.pv_tmp/ZCODE_LONG_TASK_B1_REAL_INTEGRATION_RULING_2026-10-01.md` §一-§九（SHA-256 `9b2258c1…dacd`） | §0/§7/§8/§12 的授权依据；§三七维表、§四入口使能、§五执行顺序与来源证明、§六离线双证、§七临调用门、§八批后逐字承载 | normative |
| DI-004 | Source Issue #251 | open，V4-I01，2026-10-01 建，AC-1..AC-5，parent #57（经派发消息所附 create_issue_ip0041.py BODY 转录；本会话零网络未独立 GET） | 需求语义经 CA §Goal and Scope+裁定消费（FR-01..09 规范化不改义） | normative（经转录消费） |
| DI-005 | benchmarks/v4/baseline/real_run.py @20e51e34 | blob `d542c697`（本会话亲读并逐锚复核，零漂移：`__all__` 六符号 L151-158；REQUEST_BODY_BYTE_CAP=100_000 L175、MAX_TOKENS=8000 L176、CANDIDATE_FILE_CAP=12 L178、WALK_ENTRY_CAP=5000 L180、_WALL_ESTIMATE_MS=1_200_000 L190、_DOWNLOAD/_STORAGE_ESTIMATE_BYTES L191-192、_CANARY_CHECK_KEYS 五键 L210-216；_APPROVAL_FIELDS 十二键 L261-274、_ATTEMPT_POLICY_FIELDS L296-302、模型/价格钉扎 L319-341；_SYNTHETIC_ARTIFACT_KEYS 九键 L360-370、real-pilot 常量 L372-385、_synthetic_artifact_descriptor L388-410、_build_artifact_family L413-457、REAL_RUN_ARTIFACT_FAMILY L467-469；RealRunErrorCode 十一码闭集 L474-486；RealSuiteResult L651-677；_ApprovalContract 尾默认 L679-709；loader _require_exact_keys L889/date pin L897-900/retrieval pin L953-957/budget→BudgetSpec L974-982/fixture_key+stop_on_first_failure 尾默认 L1059-1064/attempt_policy 校验（cold≥1、warm≥1、max_attempts==cold+warm、canary_required is True、canary_first_attempt==0）；_urllib_transport L1273（单次 urlopen，无重试循环）；_walk_python_files L1304-1330、_select_candidate_texts L1333-1341；_GuardedRealEvaluator L1366-1456（kw-only batch_shape=None L1404、stop_on_first_failure L1444）；首败停止门 L1579-1584、index-1 canary 检查单 L1585-1591、reserve L1594；_estimate_for L1677-1694；attempt-0 分支+cold_reset 观察 L1705-1753；_materialize L1917（fixture_key 分支 L1919 本地物化零下载）；_build_request_body L2148-2185（temperature=0/max_tokens=8000/json_object/thinking disabled）；build_payload L1517（real-world v2 dict）；_run_shaped_repeats L2636-2720；run_real_baseline_suite L2723-2734 九参数、order (1)-(9) L2771-2898；{5,5} 路由 L2810-2819；_write_core_evidence L2576-2634（五件套+attempts/attempt-{i:02d}.json） | §7.4 例外锚、§7.2 入口镜像、§7.6 路由/估算、§7.5 证据布局 | current-behavior（冻结面，只读） |
| DI-006 | benchmarks/v4/baseline/budget.py @20e51e34 | blob `6c783848`（亲读：BUDGET_DIMENSIONS 七维序 L52-60、_BOOK_DIMENSIONS L64-66、BudgetSpec batch≥per_run 逐维校验 L213-216、REAL_RUN_GATE_UNLOCKED=False L286、reserve 门序 L380-444+（per_run.calls→per_run 非成本维→batch.calls→batch 非成本维→cost 四判）、at-cap inclusive 语义 L380-393） | §7.6 七维与门序（不放松）；at-cap 证明 | current-behavior（只读） |
| DI-007 | benchmarks/v4/baseline/b1_source.py @20e51e34 | blob `9b188073`（亲读：`__all__` 七符号 L76-84、B1_WORKLOAD="b1-offline-scanner-v1" L87、CANDIDATE_FILE_CAP=12 L93；_RECEIPT_KEYS 十六键 L118-135、_MANIFEST_KEYS 二十一键 L139-161、attempt 文档三键 L164-171、四错误码 L181-187；_scan_snapshot 显式离线配置 L325-353（sast/cxx/agent/LLM 全关、dataflow on、workspace limits 显式）；_wire_fingerprint=report 冻结指纹规则逐字 L375-393；run_b1_source_baseline_suite L435-447（kw-only 十参数，model_calls 恒 0）；scanner config 文档构造 L503-527（workload/fixture_key/snapshot_tree/seed/cold/warm/scanner 禁用清单/workspace limits，digest=compute_content_digest）；verify_b1_evidence L782-879 交叉核验面） | §7.4(E3) hook 复用其冻结 _scan_snapshot；§7.5 receipt 十六键语义/companion 先例；§7.3 config 文档形状 | current-behavior（冻结契约，只读） |
| DI-008 | benchmarks/v4/baseline/fixtures.py @20e51e34 | blob `700ec4fc`（亲读：SYNTHETIC_FIXTURE_KEYS 12 合成键 L101-117 含 archetype/signal-storm、EXTERNAL_IDENTITY_KEYS 1 L118；materialize_fixture/compute_tree_fingerprint 跨 tempdir 稳定） | §7.3 fixture_key 值域、§7.5 snapshot 指纹 | current-behavior（只读消费） |
| DI-009 | tests/test_v4_baseline_real_run.py @20e51e34 | blob `18bfb4c2`（112 方法亲数；inspect.signature 三锚 L2427/L3928/L4007 亲读；_ARTIFACT_FAMILY_KEYS L574-588、_SYNTHETIC_ARTIFACT_KEYS 过滤 L589-596、_FROZEN_ERROR_CODES L552、`set(messages)==set(RealRunErrorCode)` L5600、test_artifact_family_catalog_frozen_ten_keys L3944（len==11 L3953、subTest L3954-3962）、test_real_pilot_catalog_eleven_keys_and_field_sets L5506（len==11 L5516）、at-cap 先例 test_ten_reserves_pass_and_eleventh_refused_at_cap L2235） | §7.7 授权同步点 S1-S4；错误码族不可扩展的证据（L552/L5600）；§8 arrange 样式先例 | current-behavior（冻结面） |
| DI-010 | tests/test_v4_baseline_v5_negatives.py + tests/test_v4_baseline_b1_source.py @20e51e34 | v5_negatives `6887f9fa`（9 方法；test_zero_budget_artifact_naming_discipline_scan L555（排除元组 L571、len==9 L573）、test_artifact_family_matches_fixture_registry L584（排除 L601）亲读）；b1_source `a3b4c8fc`（20 方法；_ARTIFACT_FAMILY_KEYS frozenset L217-231；M16 test_b1_old_static_surfaces_frozen 消费 L1261-1263 亲读） | §7.7 授权同步点 S5-S7 | current-behavior（冻结面） |
| DI-011 | Dockerfile @20e51e34 | blob `18a23d25`（亲读：L71=IP-0040 Packet COPY 行（grep -n 亲验）=本叶恰 +1 行插入锚，新行落 L72；L83 存在 `COPY --chown=lima:lima benchmarks ./benchmarks`——benchmarks/ 打包面已天然覆盖 b1_real.py，无需新增打包行） | C1 +1 行落位依据 | current-behavior |
| DI-012 | IP-0040 Packet + REVERIFIED 记录 | `docs/LIMA_Implementation_Packet_IP-0040_B1_Source_Wiring.md`（结构/冻结面先例）；`.pv_tmp/B1_REVERIFIED_IP-0040_2026-10-01/REVERIFIED_RECORD.md`（signal-storm=24 findings 全 candidate、malicious-layout=4、library=1；179 passed/2748 OK/24 skip 亲验 2026-10-01） | §7.5 receipt/不求和先例；§8 24 锚真值口径（独立直扫为最终真值，非硬抄 24） | evidence |
| DI-013 | IP-0039 先例 | 第十一键 real-pilot/large-repo 描述子（L372-385/L441-456 组装先例）+ 授权同步点先例（"预授权排除演进"：S2/S5/S6 三处排除清单同型） | §7.3 第十二键沿此先例；§7.7 授权点结构 | normative（先例） |
| DI-014 | worktree/分支 | `D:\BaseAIProject\LIMA-ip-0041-wt`，分支 `codex/ip-0041-b1-real-entry` @20e51e34（本会话 `git rev-parse HEAD`+`status --short` 亲验=干净） | §5.5 提交链拓扑 | evidence |

事实优先级冲突处理：CA-IP-0041-v1.0 与裁定原文冲突时以 CA 为准并提交 Decision Request；代码事实与 CA 锚不一致时如实登记（OBS）不自行改义。**本会话已逐锚亲核 CA §Frozen Interfaces 1-11 与 R1-R7 全部行号：零漂移**（含 Dockerfile L71、S5=L571/L573、S6=L601、三 inspect 锚、b1_source L118-135/L164-171/L181-187）。

## 3. Explicitly Rejected Inputs

| # | 被拒输入 | 拒绝理由 |
| --- | --- | --- |
| 1 | 把真实 HTTP callback 塞入 `run_b1_source_baseline_suite` 离线入口 | 裁定 §二：注入式回调不受真实 approval/BudgetLedger/canary/首败门约束，会造成已付费请求不按真实模型调用记账；b1_source.py 离线契约只读 |
| 2 | 在 b1_real.py 复制一套缺少门禁的 HTTP 驱动（自带 POST 循环/自带门） | 裁定 §四/R1.1：必须复用冻结 order 1-9 真实链；新入口只做前相/后相 |
| 3 | 串联两个独立批后把目录合并称作同一证据链（如另跑离线 B1 目录再贴到真实批） | 裁定 §四/§五；一个批准范围/一个账本/一套全局 attempt 序号 |
| 4 | 参数化旧入口 `run_real_baseline_suite` 承载 B1（加 hook 开关参数） | R1：旧入口九参数签名被三 inspect.signature 锚钉死；参数化引入旧路径证明负担 |
| 5 | 复用 real-pilot/large-repo 描述子或其批准工件承载 signal-storm | R2/裁定 §四：不得复用；新专属描述子+新批准工件 |
| 6 | scanner 输出改变模型上下文选择（scanner 引导候选） | R3.2：冻结确定性 walk（L1304-1341）零变化；CANDIDATE_FILE_CAP=12 保持纯请求构造参数；改上下文须 DR（改 prompt 风险，裁定 §三禁改 prompt） |
| 7 | 报告计数按 5 重复样本求和（24×5=120）或 cap 截断 findings | 裁定 §五/IP-0040 §7.6.7：单次扫描快照投影；cap 仅作用请求构造 |
| 8 | 在旧 ledger/manifest/report/attempts 闭集内塞 B1 来源字段 | R3.3：companion 独立工件是默认出路；旧闭集零增字段；确不能表达才允许版本区分演进（默认不触发） |
| 9 | 整个真实 suite 输出总 model_calls=0 或 offline-proof 标记 | 裁定 §五：如实记实际 POST 数；扫描组件 0 模型调用仅可作为组件级声明 |
| 10 | b1_real.py 内含任何数字预算常量（100000/198000 等） | R4.1：七维数值唯一来源=最终批准工件 budget 面；b1_real 不含数字预算、不放松任何一维 |
| 11 | scanner 执行放在 guarded 窗口之外（如 post-phase 扫描替代窗口内扫描，或 transport 包装内扫描） | R1.2(a)/裁定 §五：scanner 必须在预留与截止保护内、POST 前恰一次；transport 包装内扫描会误入 REAL_RUN_TRANSPORT_FAILED taxonomy 且不受截止检查 |
| 12 | 新增 RealRunErrorCode（如 REAL_RUN_SCANNER_FAILED）承载 scanner 失败 | 十一码闭集被旧测试钉死（_FROZEN_ERROR_CODES L552 + set 相等 L5600，DI-009）；表外旧测试修改=Stop 4。scanner 失败经冻结 Exception 纪律传播（§7.4 E3），B1 语义类型化在 b1_real 自有错误族（§7.2.3） |
| 13 | 依赖环境变量默认值的扫描配置；任何网络/LLM/platform/会执行仓库代码的验证路径 | 裁定 §五/Stop 6；scanner 配置=b1_source._scan_snapshot 冻结显式离线配置逐字复用 |
| 14 | 跨日执行旧日期钉扎/倒签日期/修改旧批准工件顶替 | R7：2026-10-01 跨日失效条款（§12 Stop 5 逐字） |
| 15 | 预计缓存优惠抵减内部预留；以延迟推断缓存 hit、以 usage hit/miss 推断全局冷启动 | 裁定 §三/§八；费用三层口径不混淆（K3） |
| 16 | 第六轮 sealed 目录（`D:\BaseAIProject\LIMA-real-runs\**`）及第七轮原件任何写入 | 裁定 §八/Stop 2 |
| 17 | `docs/LIMA_PR3e_V5_Field_Source_Table.md` 的 B1 行（real_run 入口编排扩展/扫描轮+triage 轮）作为实现依据 | 历史规划快照；本叶以 CA R1-R7 与本 Packet §7 为准（沿 IP-0040 拒绝先例 #15） |

## 4. Goal / Non-goals

**Goal**：在 IP-0040 版产品（main=20e51e34）上建立受审 **B1 真实公共入口**：新文件 `benchmarks/v4/baseline/b1_real.py`（公共入口 `run_b1_real_baseline_suite`，§7.2 契约），以第十二键描述子（§7.3）驱动冻结 order 1-9 真实链（`real_run.run_real_baseline_suite(artifact_key="real-pilot/signal-storm")`，§7.1），scanner 在 cold attempt-0 guarded 窗口内恰执行一次（§7.4 E3）、warm 1-4 复用同 snapshot/扫描/请求体，B1 真实绑定经独立 companion 工件（b1-real-attempts/b1-real-manifest.json，§7.5）完整可回指，报告走真实 scanner 类型路径且计数与独立直扫逐值一致、不求和，七维逐值由批准工件驱动（§7.6）且 {1,4} 路由/canary 五项 index-1 映射/max_attempts=5 at-cap 全部经既有冻结机制，整个 suite 如实记实际 POST 数（独立计数器）。全部交付在零真实调用约束下经离线精确孪生与负例证明（冻结测试 v11，§8），为 C-final 一次性 signal-storm 真实 pilot（{1c+4w}=5 POST）提供受审代码路径。

**Non-goals**：见 §1 Not-covered（CA 原文）。真实 pilot 执行（裁定 §七）、批后（§八）、九类批（§九）均不在本 Assignment/本叶 C1-C3 授权内；合并/推送/远端写、#57 Ledger 更新不在本 Assignment 授权内。

## 5. 文件边界（CA §Workspace and Ownership；C1 恰 1 Add+1 Modify；C2 恰 1 Add+3 旧文件授权点；C3 恰 1 Add+1 Modify（预裁定）；零 Delete；单 PR `codex/ip-0041-b1-real-entry` → main）

### 5.1 Files to Add

| 文件 | Owner/阶段 | 说明 |
| --- | --- | --- |
| `docs/LIMA_Implementation_Packet_IP-0041_B1_Real_Entry.md` | P&V（C1，本文件） | 本 Packet；承载 CA 全部验收语义+R1-R7 裁定+第十二键/入口契约/companion 契约/七维表/授权同步点表/测试矩阵 v11/Stop Conditions |
| `tests/test_v4_baseline_b1_real.py` | P&V（C2，冻结 v11） | B1 真实入口验收面新测试文件（≤26 方法八簇，§8）；对三旧文件的修改仅限 §7.7 授权同步点恰 7 点 |
| `benchmarks/v4/baseline/b1_real.py` | Implementation（C3） | 唯一新公共入口文件 `run_b1_real_baseline_suite` + `verify_b1_real_evidence`（§7.2 契约）；离线/secretless；stdlib+冻结上游模块只读 import |

### 5.2 Files Allowed to Modify

| 文件 | Owner/阶段 | 边界 |
| --- | --- | --- |
| `Dockerfile` | P&V（C1，与 Packet 同一提交） | **恰 +1 行**：`COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0041_B1_Real_Entry.md ./docs/`（插 L71 IP-0040 Packet COPY 行后，新行落 L72——本会话 grep -n 亲验）；既有行零改动。基线 blob `18a23d25` |
| `benchmarks/v4/baseline/real_run.py` | Implementation（C3，预裁定） | **默认零修改**；仅允许本 Packet §7.4 点名登记的 additive 例外 **E0-E4**（逐项符号/门条件/默认关闭证明）；不得触及公共签名（九参数）、order 1-9 语义、旧十一键行为、旧审批/请求契约/预算门/统计规则/错误码族/`__all__` 六符号。基线 blob `d542c697` |
| `tests/test_v4_baseline_real_run.py` / `tests/test_v4_baseline_v5_negatives.py` / `tests/test_v4_baseline_b1_source.py` | P&V（C2，仅授权同步点） | 恰 §7.7 表 S1-S7 七点（旧值→新值逐字）；表外任何 hunk=Stop 4 |

### 5.3 Read-only Reference Files（只读消费）

`benchmarks/v4/baseline/` 其余全部模块与各级 `__init__.py`（budget.py、report.py、run.py、orchestrate.py、fixtures.py、collect.py、expert_timing.py、offline_flow.py、b1_source.py——绝对只读）；`lima/**`（绝对只读）；`evaluation_data/v4/baseline_manifest.json` 与 fixture_registry.json；IP-0024..0040 Packet、批准工件、V5 来源表、决策包、裁定文件；`.pv_tmp/` 各记录（含 REVERIFIED）。

### 5.4 Files Forbidden（diff 必空；Done Commands 逐 blob 守护）

`lima/**`（绝对）；`benchmarks/v4/baseline/` 除 b1_real.py（Add）与 real_run.py（E0-E4 点名 hunk）外一切文件；`budget.py`/`report.py`/`run.py`/`orchestrate.py`/`fixtures.py`/`collect.py`/`expert_timing.py`/`offline_flow.py`/`b1_source.py`/各级 `__init__.py`；`tests/` 除 §7.7 授权点外一切既有文件与方法（含 v10' b1_source 20 方法除 S7 常量外、旧 112/38/9 除 S1-S6 外）；旧真实批准工件与历史 run 产物（`D:\BaseAIProject\LIMA-real-runs\**` 及一切封存树零写入）；`docs/` 其余全部；`evaluation_data/**`（除只读消费）；`scripts/**`；`pyproject.toml`/`.github/**`/前端；`.pv_tmp/**` 不提交（RED 日志仅存主仓库 `.pv_tmp/RED_IP-0041_2026-10-01/`）。

### 5.5 提交链拓扑（CA §Handoff；冻结）

C1 = 本 Packet + Dockerfile 恰 1 行（1 Add + 1 Modify，同一提交，提交信息逐字 `[IP-0041][PV] Add Implementation Packet IP-0041 (B1 real entry) and Dockerfile copy line`）→ 主会话 PR（`Related to #251`，无自动关闭关键字；不关联关闭 #57）合并，**C2 基线=main 上 C1 合并后完整 40 位 SHA（主会话记录；worktree rebase/重置到该 SHA 后开工）** → C2 = tests/test_v4_baseline_b1_real.py 新文件落定 + 恰 7 授权同步点（1 Add + 3 Modify；**Frozen Test Commit**；提交信息逐字 `[IP-0041][PV] Freeze acceptance tests v11 (RED)`；RED 证据先于冻结落盘并独立日志归档主仓库 `.pv_tmp/RED_IP-0041_2026-10-01/`）→ C3 = b1_real.py（1 Add）+ real_run.py（E0-E4 点名 hunk，1 Modify）（提交前缀 `[IP-0041][IMPL]`；必须以 C2 为祖先；正式指派以 CA-IP-0041-v1.1 为准）→ C4（P&V 独立验证+PR；如触发 ALLOWED_ONCE/修复提交须引用编号）。单 PR；不 push（合并/推送/评论由主会话按 Maintainer 授权执行，P&V/IMPL 零远端写）。

### 5.6 与其他活动 IP 的冲突分析

无并行活动 IP 占用本切片路径（IP-0041 编号由 CA 分配）。本叶触碰 real_run.py（E0-E4）与三旧测试文件（恰 7 授权点）——均为 CA 显式授权且逐 hunk 登记；b1_source.py/fixtures.py/budget.py/report.py 等其余共享核心零触碰。

## 6. 依赖、网络、文件系统与权限边界

- **依赖**：零新增第三方依赖；b1_real.py 只 import stdlib + 冻结上游模块（benchmarks.v4.baseline.{real_run,b1_source,fixtures,budget} 与 lima.contracts.codec canonical_encode/compute_content_digest——最终 import 清单由 C3 在此集合内落定，零新第三方）。测试文件零新增第三方 import（unittest/tempfile/pathlib/json/hashlib 等 stdlib+冻结上游）。
- **网络**：C1-C3 与 CI 全程零网络/零下载/零付费/零凭据（Stop 1 绝对停）；模型层验证只用注入式 fake transport（孪生）；真实网络仅存在于 C-final 真实 pilot 的 guarded transport（本叶不执行）。
- **文件系统**：companion 与证据只写调用方提供的空输出目录（真实入口的一次性输出根门 L2774-2790 既有纪律；测试写 tempdir）；sealed 目录（`D:\BaseAIProject\LIMA-real-runs\**`）只读零写入；不读环境变量/配置/.env（scanner 配置显式传参，无环境默认）。
- **数据库/容器/远端写**：无数据库；容器面仅 Dockerfile +1 COPY 行（本 Packet 文档）；零远端写（不 push、不开 PR、不关 Issue、不改 Ledger 远端状态）。
- **凭据**：入口 `api_key` 参数仅按冻结 evaluator 纪律进程内构造 Authorization 头（不打印/不落盘/不进证据；结构 only field path 先例）；C1-C3 一律 fake transport + 测试假密钥字面量，永不注入真实凭据。
- **clock**：计时只经冻结 `_monotonic` seam；digest/身份/计数面零时钟依赖、零真实 sleep。

## 7. 实现契约细化（Packet 定稿；R1-R4 落位）

### 7.1 冻结数据流（R1.1 默认组合的具体化：b1_real.py 如何驱动 order 1-9 与 scanner 时机）

```text
[前相 b1_real.py]
(0a) 入口校验：approval 文档按 artifact_key="real-pilot/signal-storm" 经冻结 loader 装载校验
     （approval_path, api_key 透传）；补充执法：attempt_policy 形状恰 {cold:1, warm:4,
     max_attempts:5, canary_required:True, canary_first_attempt:0}（loader 已校验五键闭集
     与 max_attempts==cold+warm/canary 语义；入口再钉扎授权形状，非 {1,4,5} ⇒
     B1_REAL_INPUT_INVALID，零 POST）；绑定块漂移（workload/scanner 配置 digest/source
     contract/version 与第十二键目录值不符）⇒ B1_REAL_INPUT_INVALID。
(0b) 独立 POST 计数器：transport 包装（transport=None ⇒ 包装 real_run._urllib_transport
     （只读 import）；调用方注入 ⇒ 包装注入件）。包装仅计数 payload 非空的调用（POST-only，
     GET 不计——signal-storm 本地物化零 GET），其余逐字委托。零行为差异；计数供 NFR-01 审计面。
[真实链 real_run.py 冻结 order 1-9，经 run_real_baseline_suite(approval_path, api_key,
 output_root=…, spec_mapping=…, transport=<计数包装>, timeout_seconds=…, manifest_path=…,
 sources=…, artifact_key="real-pilot/signal-storm") 驱动]
(1) approval 装载校验（第十二键描述子驱动：approval_type/run_name 新钉扎、date=2026-10-01
    pin、七维 budget→BudgetSpec、attempt_policy {1,4,5}）
(2) 一次性输出根门 → (3) timeout 门（timeout_seconds×1000 ≤ per_run.wall_ms=1200000 ⇒ 
    调用方 timeout_seconds ≤ 1200；默认 120 合法） → (4) manifest → (5) _materialized 预建
(6) BudgetLedger + _GuardedRealEvaluator（batch_shape=(1,4)——{1,4}≠{5,5} 冻结路由）
(7) _run_shaped_repeats：attempt-0 mode="cold"（初始物化+请求体构造+**scanner 恰一次（E3，
    预留与截止窗口内、POST 前）**+cold_reset 观察{performed:False, materialization_count:1}
    +attempt-0 POST=首请求即 canary 样本）；index-1（首个 warm）入口跑五项 canary 检查单
    （L1585-1591，任一失败 latch）；warm 1-4 复用同 snapshot/扫描结果/请求体（POST）
(8) 五件套证据（approval.json/ledger.json/machine_profile.json/attempts/attempt-{i:02d}.json/
    manifest.json，_write_core_evidence L2576-2634）+ 聚合 RunResult（insufficient_sample 如实）
(9) 报告：guarded.build_payload() 在 B1 绑定且扫描在场时返回 RepositoryScanResult（E4 门）
    ⇒ build_baseline_report 走 scanner 类型路径（IP-0040 §7.1 数据流复用）；RealSuiteResult
[后相 b1_real.py]
(10) 后相核验与 companion 落盘：读回证据（approval bytes digest/各 attempt 文档/各
     RunResult/ledger/report）；对持久化 _materialized/snapshot 做独立复扫
     （b1_source._scan_snapshot，只读、零模型调用）交叉核验 scanner_payload_sha256；
     snapshot_tree_sha256 三方相等（receipt==cold_reset 观察==持久化树重算）；投影检查
     （报告计数==独立直扫、不求和、真实 POST 计数面）；不符 ⇒ B1RealError typed 拒绝
     （§7.2.3 码集），companion 不落盘（fail closed）
(11) companion 落盘：b1-real-attempts/b1-real-attempt-{i:02d}.json ×5（§7.5.3 二十三键）+
     b1-real-manifest.json（§7.5.4 闭集）；返回 B1RealSuiteResult（§7.2.2）
```

禁止形态（R1.1/§3）：复制缺门禁 HTTP 驱动；串联两独立批合并目录；scanner 置于 guarded 窗口外；b1_real 自带预算数字。

### 7.2 新入口契约：`run_b1_real_baseline_suite`（R1；新文件 benchmarks/v4/baseline/b1_real.py）

#### 7.2.1 签名（冻结草案；最终以 C3 落地、测试 inspect 断言钉死）

```python
def run_b1_real_baseline_suite(
    approval_path: str | pathlib.Path,
    api_key: str,
    *,
    output_root: str | pathlib.Path,
    spec_mapping: object,
    transport: typing.Callable | None = None,
    timeout_seconds: int = 120,
    manifest_path: str | pathlib.Path | None = None,
    sources: object = None,
) -> "B1RealSuiteResult"
```

- 八参数（2 位置 + 6 keyword-only），镜像冻结真实入口减去 `artifact_key`（**入口内部钉扎 `"real-pilot/signal-storm"`，不暴露该参数**——专用入口即第十二键入口）。
- `transport=None` 默认 ⇒ 计数包装 `real_run._urllib_transport`（只读 import；C1-C3 一律由调用方注入 fake transport）；`timeout_seconds` 受冻结 (3) 门约束（≤1200）。
- **不含任何数字预算常量、不含 seed/cold/warm/workload 参数**（绑定唯一来源=第十二键目录 + 批准工件；运行时漂移=typed 拒绝，负例簇 M14）。
- `__all__`（恰五符号，冻结）：`B1RealError`、`B1RealErrorCode`、`B1RealSuiteResult`、`run_b1_real_baseline_suite`、`verify_b1_real_evidence`。

#### 7.2.2 结果类型 `B1RealSuiteResult`（frozen dataclass，slots）

RealSuiteResult 十六面逐字镜像（run_name/approval_digest/run_spec_digest/attempt_count/status/result_paths/aggregate_path/aggregate_sha256/report_path/report_sha256/ledger_snapshot/model/system_fingerprint_baseline/canary_status/evidence_paths/real_run 恒 True）+ B1 判别与绑定面（frozen，slots）：`b1_real`（常量 True 判别）、`artifact_key`、`fixture_key`、`workload`、`snapshot_tree_sha256`、`scanner_config_sha256`、`scanner_payload_sha256`、`scanner_executions`（int 观察计数，成功路径=1）、`real_post_count`（**int 实际 POST 数，独立计数器观察；禁止常量 0、禁止 model_calls=0 语义**）、`companion_manifest_path`、`companion_manifest_sha256`、`source_receipts_digest`、`source_contract`、`source_contract_version`。

#### 7.2.3 错误族（新入口自有，闭集恰五码；str-enum+稳定消息+结构 only field_path，先例纪律；不嵌 payload/数值/主机路径；b1_source 四码与 real_run 十一码零改动）

| 码 | 语义 |
| --- | --- |
| `B1_REAL_INPUT_INVALID` | 前相执法：approval 非第十二键绑定/attempt_policy 形状非 {1,4,5}/绑定块（workload、scanner 配置 digest、source contract/version）与目录值漂移 |
| `B1_REAL_RECEIPT_INVALID` | companion receipt/manifest malformed、键集不符、digest 非十六进制 64 |
| `B1_REAL_BINDING_MISMATCH` | 交叉绑定失败：snapshot/请求体/RunResult/attempt 文档/ledger/suite 关联不符；源缺失/篡改/别的 snapshot 或 RunSpec 回填 |
| `B1_REAL_SCANNER_DIGEST_MISMATCH` | scanner payload digest 链不符（receipt vs 报告 sources digest vs `_wire_fingerprint` 独立重算） |
| `B1_REAL_PROJECTION_MISMATCH` | 投影面不符：报告计数与独立直扫不一致/求和面/真实 POST 计数面不一致/日期面与钉扎漂移 |

`verify_b1_real_evidence(output_root)`（公共读取核验入口）：重读 companion+证据逐项复算（receipts digest、scanner digest 独立重扫重算、RunResult/ledger/approval 内容 digest、指针有效性、投影面）；任何不符 ⇒ 上表 typed 拒绝（fail closed，不降级 unavailable）。

### 7.3 第十二键描述子（R2 定稿；沿 IP-0039 第十一键先例）

1. **键名（Packet 定稿）**：`"real-pilot/signal-storm"`（采纳 CA 建议值；不得复用 `real-pilot/large-repo`）。加入 `REAL_RUN_ARTIFACT_FAMILY`（十一键→十二键闭集；授权同步点 §7.7 恰为此 7 点）。**合成键保持 9 个**（新键为非合成描述子键——其溯源是 signal-storm 派生而非独立 registry 键，必须加入 S2/S5/S6 排除清单，IP-0039"预授权排除演进"先例）。
2. **字段集（恰 16 字段闭集 = 七基础 ∪ IP-0039 四 R2 字段 ∪ B1 新增五字段）**：
   - **七基础**（五溯源= `_synthetic_artifact_descriptor("archetype/signal-storm", registry_fingerprint)` 派生逐字（L388-410）+ approval identity 替换）：`repository="lima-synth/signal-storm"`、`requested_name="lima-synth/signal-storm"`、`commit_sha=<sha256("lima-synth-artifact:archetype/signal-storm:<registry-fingerprint>")[:40] 确定性派生>`、`tarball_url="https://lima-synth.invalid/signal-storm/tar.gz/<commit_sha>"（RFC 2606 .invalid，永不获取）`、`tarball_filename="lima-synth-signal-storm-{commit_sha}.tar.gz"`；`approval_type`/`run_name` 替换为新钉扎（下行）。
   - **IP-0039 四 R2 字段**：`fixture_key="archetype/signal-storm"`（在描述子 ⇒ `_materialize` L1919 合成本地物化分支——**机制保证不误入网络下载**，负例 M14 双重保证）、`date_pin="2026-10-01"`、`retrieval_date_pin="2026-10-01"`（R7；批准工件 `date`/`pricing.retrieval_date` 经既有 pin 机制 L897-900/L953-957 逐字校验，零新校验面）、`stop_on_first_failure=True`（首败门生效）。
   - **B1 新增五字段（键名与值域，Packet 定稿）**：
     | 键 | 值（冻结） | 值域/语义 |
     | --- | --- | --- |
     | `workload` | `"b1-real-signal-storm-v1"` | B1 真实 workload 标签；进入 scanner config 文档 ⇒ digest ⇒ run identity（NFR-04）；与离线 `b1-offline-scanner-v1` 及历史 pilot 分属不同 workload |
     | `scanner_config_ref` | `"b1-source-offline-scan-v1"` | 冻结扫描配置族引用：hook 复用 `b1_source._scan_snapshot`（L325-353 显式离线配置逐字——sast/cxx/agent/LLM 全关、dataflow on、workspace limits 显式） |
     | `scanner_config_sha256` | `compute_content_digest(<B1 真实 scanner config 文档>)` | 64-hex 确定性派生：文档键集与 b1_source L503-527 同形（workload/fixture_key/snapshot_tree_sha256=signal-storm registry fingerprint/seed=0/cold_count=1/warm_count=4/scanner 禁用清单/workspace limits），canonical 编码 SHA-256（M7 独立重算锚） |
     | `source_contract` | `"b1-real-source-binding"` | B1 真实来源绑定契约身份串（本 Packet §7.5 契约） |
     | `source_contract_version` | `1` | int 契约版本 |
3. **approval_type / run_name 新钉扎（Packet 定稿；唯一性声明）**：`approval_type="PR3D-B1-REAL-ENTRY-ONE-SHOT"`、`run_name="pr3d-b1-real-signal-storm-2026-10-01"`。**唯一性**：与既有全部 run_name/approval_type 零冲突（亲验：`pr3d-real-2026-09-28`/`PR3D-REAL-RUN-LIMITED`（L346-347）、`pr3d-real-pilot-2026-09-30`/`PR3D-REAL-PILOT-ONE-SHOT`（L382-383）、`pr3e-offline-proof-{archetype}`/`PR3E-OFFLINE-PROOF-ZERO-BUDGET`（L352/L407）——前缀 `PR3D-B1-REAL-ENTRY-`/`pr3d-b1-real-` 与日期 2026-10-01 均为本次专属）；M7 断言全集唯一。
4. **装载**：loader 经 `descriptor.get` 尾默认读取 B1 字段（R2 逐字："loader 经 descriptor.get 尾默认读取，零新校验分支于旧键"）；批准工件 schema 零变化（`_APPROVAL_FIELDS` 十二键文档闭集不变——B1 字段在目录侧，不在工件侧）。**十一旧键字段集逐字不变**（十键七字段 + real-pilot 十一字段）。
5. **绑定门（hook 等的门条件，§7.4 E1-E3）**：descriptor 同时含 `workload` 与 `source_contract` ⇒ B1 绑定生效；两键仅存在于第十二键目录项（十一旧键永不携带——缺省关闭证明的目录面）。

### 7.4 real_run.py 演进例外清单（R1.2；**非零例外，恰 5 项 E0-E4**；逐项符号/门条件/默认关闭证明；清单外任何 hunk=Stop 8）

**R1.2(b) 来源收集 hook 与 R1.2(c) 估算分支的裁定**：来源收集 **零启用**（后相 b1_real 从盘上证据+独立复扫完整推导 receipt，无需 real_run 内收集面）；估算分支 **real_run 零新分支**（扫描 wall 位于 attempt-0 已预留窗口内——reserve（L1594）先于 attempt 体、attempt wall 计时（L1607-1612 finally）含扫描、ledger settle 的 elapsed wall 记账含扫描时间，七维 wall 面已机械覆盖；companion 工件字节的显式登记面=b1_real companion manifest 的 `companion_bytes_total`/`scanner_phase` 键（§7.5.4），其一切数值 ≤ 既有 `_STORAGE_ESTIMATE_BYTES`/`_WALL_ESTIMATE_MS` 预留，M4 断言）。

| # | 符号（real_run.py） | 内容 | 门条件 | 默认关闭证明 |
| --- | --- | --- | --- | --- |
| E0 | 新增模块常量块（IP-0039 L372-385 同款独立块）+ `_build_artifact_family`（L413-457）尾部 append 第十二项 | `_B1_REAL_ARTIFACT_KEY`/`_B1_REAL_FIXTURE_KEY`/`_B1_REAL_APPROVAL_TYPE_PIN`/`_B1_REAL_RUN_NAME_PIN`/`_B1_REAL_DATE_PIN`/`_B1_REAL_RETRIEVAL_DATE_PIN`/`_B1_REAL_WORKLOAD`/`_B1_REAL_SCANNER_CONFIG_REF`/`_B1_REAL_SOURCE_CONTRACT`/`_B1_REAL_SOURCE_CONTRACT_VERSION` 常量 + 目录第十二项组装（signal-storm 七基础派生逐字 + 替换 + 四 R2 + 五 B1 字段） | 无（纯加项；R2 裁定"第十二键加入 REAL_RUN_ARTIFACT_FAMILY"） | 既有十一项字节等同（S1-S7 授权同步恰因加键触碰计数/集合断言）；新常量不入 `__all__`（六符号不变，L151-158） |
| E1 | `_load_and_validate_approval` 尾部（L1055-1064 区域）+ `_ApprovalContract` 尾默认字段 `b1_source_binding: dict[str, object] \| None = None`（L679-709 尾默认先例） | descriptor 同时含 `workload` 与 `source_contract` ⇒ `b1_source_binding={五 B1 字段快照}`；否则尾默认 None | descriptor 键存在性（仅第十二键携带） | 旧键构造字节等同（`stop_on_first_failure` L1064 尾默认同型先例）；零新校验分支于旧键（R2 逐字） |
| E2 | `_GuardedRealEvaluator.__init__`（L1366-1456）追加 `self._b1_binding = approval.b1_source_binding` 与 `self._b1_scan_result = None` 等状态初始化 | 绑定属性与扫描状态槽 | 纯赋值 | 无分支；旧键路径字节等同 |
| E3 | `_run_attempt`（L1705-1734）`if index == 0:` 分支：`self._prepare_request(record)` 与 cold_reset 观察之后、`self._chat(...)` 之前；新私有方法 `_b1_execute_scanner(record, deadline_ms)` | **scanner 执行 hook（R1.2(a)）**：门 `self._b1_binding is not None and self._b1_scan_result is None`（恰一次；仅 cold attempt-0 进入 index==0，warm/后续永不）；行为：lazy `import benchmarks.v4.baseline.b1_source` → 调其冻结 `_scan_snapshot(self._snapshot_dir)`（**同一实际 snapshot**——请求体候选 walk 的同一棵树）；扫描后 `_past_deadline(record.wall_anchor, deadline_ms)` 截止检查（超时按既有截止纪律失败，零 POST）；结果存 `self._b1_scan_result` | `b1_source_binding` 非 None（仅第十二键） | 模块级 import 清单零变化（L102-149 亲验——lazy import 只在门内触发）；旧键永不进分支；scanner 异常原样传播经冻结 Exception 纪律成失败样本（run.py `run_baseline_attempt` 捕获 Exception→失败样本持久化→循环继续/stop_on_first_failure=True 后续全拒 REAL_RUN_BATCH_STOPPED 首因保留——**零 POST、零新 RealRunErrorCode**（十一码闭集被 L552/L5600 钉死，§3 拒绝 #12），B1 语义类型化在 b1_real 错误族/终局面 |
| E4 | `_GuardedRealEvaluator.build_payload`（L1517-1545）门化返回 | **报告 payload 门（R3.4"报告走真实 scanner 类型路径"的链内落位）**：门 `self._b1_binding is not None and self._b1_scan_result is not None` ⇒ 返回 `self._b1_scan_result`（RepositoryScanResult）⇒ order (9) `build_baseline_report(summary, payload)` 走 scanner 类型分支（IP-0040 §7.1 数据流复用：counts/coverage/raw_candidates/压缩链/scanner sources digest/scanner-kind 报告） | B1 绑定且扫描在场 | 旧键（及扫描缺席的失败终局）返回冻结 real-world v2 dict **逐字**（字节等同）；报告对失败终局如实呈现模型观测面，B1 投影纪律由后相 typed 拒绝/记录（不伪造 scanner 面） |

**旧公共入口默认语义零变化的机械证明（四层，R1.3）**：① `inspect.signature` 三锚（test L2427/L3928/L4007）+ 新文件镜像锚全绿；② 旧 112 方法除授权同步点外全绿（授权点 RED 恰因第十二键缺席；C3 后全绿）；③ 新文件负例：十一旧键目录项永不含 `workload`/`source_contract`（字段集断言）+ 旧键（real-pilot/large-repo）孪生经真实入口运行报告 kind=real-world v2、零 companion、绑定 None（M20 缺省关闭断言；沿 L1404 `batch_shape=None`/L1444 `stop_on_first_failure` 默认 False 字节等同先例的证明模式）；④ diff/blob 守护：real_run.py 若有修改，逐 hunk 对照 E0-E4（含新私有方法体与常量块），清单外 hunk=Stop 8。

### 7.5 scanner 接线、companion 工件与报告（R3 定稿）

#### 7.5.1 执行时机（R3.1）

scanner 在 cold attempt-0 内、快照物化+解包完成后、请求体构造同窗口（E3 落位：`_prepare_request` 之后 `_chat` 之前）执行**恰一次**（预留与截止保护内；扫描失败/截止失败在 POST 前 ⇒ 零 POST——E3 传播纪律）；`cold_reset.performed=False`、`materialization_count=1` 如实（L1711-1719 机制既有，{1,4} 形状下 attempt-0 即初始物化 cold）。warm 1-4 复用同一 snapshot/扫描结果/请求体（冻结 else 分支 L1722-1727：`snapshot_reused=True`、请求体不重建）。scanner 配置=显式离线（`b1_source._scan_snapshot` L325-353 逐字复用：LLM/platform/网络/code-exec 全禁）；scanner/模型上下文/receipt 绑**同一实际 snapshot**（receipt `snapshot_tree_sha256` == cold_reset 观察 L1749 同值 == 持久化 `_materialized/snapshot` 树重算——三方交叉可证）。

#### 7.5.2 与模型请求候选选择的关系（R3.2）

**冻结确定性 walk（`_select_candidate_texts` L1333）零变化；scanner 输出不改变模型上下文选择。** `CANDIDATE_FILE_CAP=12` 保持纯请求构造参数（报告计数不受其截断——IP-0040 M10 先例；signal-storm 24 findings 全范围入报告）。同 snapshot 绑定以 digest 相等证明，不以"scanner 驱动上下文"证明；scanner 引导候选选择 ⇒ 超出本裁定须 DR（§3 拒绝 #6）。

#### 7.5.3 companion source_receipt（R3.3；独立工件；**键集恰 23 键 = b1_source 十六键语义全保留 + 七真实绑定键**，不收缩 CA R3 语义）

每 attempt 一份 `b1-real-attempts/b1-real-attempt-{i:02d}.json`（i=0..4），键集（顺序冻结）：

```text
—— b1_source 十六键（L118-135 语义全保留）——
snapshot_tree_sha256       物化快照树指纹（==cold_reset 观察==持久化树重算，三方相等）
fixture_key                "archetype/signal-storm"
fixture_manifest_sha256    注册表该键条目指纹（b1_source._registry_fingerprint 同源语义）
analyzer_name              扫描器身份串（scan 后 reviewer，b1_source 同款派生）
analyzer_fingerprint       compute_content_digest({analyzer_name, scanner_config_sha256})（b1_source 同款）
scanner_config_sha256      B1 真实 scanner config 文档 canonical SHA-256（文档本体入 b1-real-manifest）
seed                       int（目录钉扎 0）
workload                   "b1-real-signal-storm-v1"
run_spec_digest            RunSpec/RunResult 关联（64-hex，与聚合/报告一致）
attempt_index              int（全局序 0..4）
mode                       "cold" | "warm"（{1,4}：0=cold，1-4=warm）
scanner_payload_sha256     ==报告 sources scanner digest==_wire_fingerprint 独立重算（交叉核验面）
scanner_reexecuted         bool（attempt-0 True / warm False）
scanner_result_reused      bool（attempt-0 False / warm True）
snapshot_reused            bool（attempt-0 False / warm True）
request_body_rebuilt       bool（attempt-0 True / warm False；冻结 state_reuse 词表）
—— 七真实绑定新增键（R3.3 语义逐项落位；裁定 §五"对应 RunResult/账本及真实 suite 关联"）——
approval_sha256            sha256(approval.json 原始字节)（==RealSuiteResult.approval_digest）
request_body_sha256        sha256(body_bytes)（==cold_reset 观察 request_body_sha256 L1749）
run_result_name            该 attempt 对应 RunResult 文件名（"{d16}-run-{n}.json"，输出根内）
run_result_sha256          该 RunResult 文件内容 SHA-256（可核验摘要，非裸指针）
attempt_document_name      真实 suite attempt 文档指针（"attempts/attempt-{i:02d}.json"）
suite_run_name             "pr3d-b1-real-signal-storm-2026-10-01"（真实 suite 关联）
ledger_sha256              suite ledger.json 内容 SHA-256（账本关联）
```

#### 7.5.4 companion manifest `b1-real-manifest.json`（closed 键集，冻结）

`schema_version=1`、`workload`、`run_name`、`artifact_key`、`approval_sha256`、`run_spec_digest`、`attempt_count`、`cold_count=1`、`warm_count=4`、`fixture_key`、`fixture_manifest_sha256`、`snapshot_tree_sha256`、`analyzer_name`、`analyzer_fingerprint`、`scanner_config`（完整文档）、`scanner_config_sha256`、`seed`、`source_contract`、`source_contract_version`、`scanner_payload_sha256`、`scanner_executions`（成功路径=1）、`scanner_phase`（估算登记面：`{"executions":1,"reuses":4,"window":"attempt-0-guarded","wall_registration":"inside-attempt0-wall-reservation"}`——扫描 wall 归属 attempt-0 wall 预留的显式登记，无伪造的扫描专属 wall 数值）、`source_receipts`（按 attempt 序全列 5 份）、`source_receipts_digest`（=SHA-256(canonical_encode(source_receipts))）、`failures`（[] 或失败码列表）、`real_post_count`（**int 实际 POST 数，独立计数器观察**）、`ledger_calls`（账本 calls 面，交叉）、`companion_bytes_total`（companion 工件字节合计，≤ `_STORAGE_ESTIMATE_BYTES` 预留的登记面）、`transport_face`（"injected" | "default-urllib"）、`declarations`（闭集：`"b1-real-suite-actual-post-count-recorded"`、`"signal-storm-local-materialization-zero-download"`、`"one-time-pilot-shape-one-cold-four-warm"`、`"not-nine-category-sample"`、`"scanner-component-zero-model-calls"`（组件级声明））。

**诚实计数面（裁定 §五/R3.4）**：companion 与结果面**无 `model_calls` 键、无 "offline-proof"/"zero-model-calls" 全局声明**（`scanner-component-zero-model-calls` 仅组件级）；`real_post_count`/`ledger_calls` 如实记录实际传输计数；manifest/result 面记录真实 usage（经 ledger snapshot 与 attempts 面）。

#### 7.5.5 工件布局与命名（与一切既有族零碰撞）

```text
{输出根}/
  approval.json  ledger.json  manifest.json  machine_profile.json   （冻结五件套，零增字段）
  attempts/attempt-{i:02d}.json                              （冻结，零增字段）
  _materialized/{tarball,snapshot}/                          （冻结）
  {d16}-run-1..5.json  {d16}-run-6.json  {d16}-report-1.json  （冻结 RunResult/聚合/报告命名）
  b1-real-attempts/b1-real-attempt-{i:02d}.json              （companion receipt，本叶新增）
  b1-real-manifest.json                                       （companion manifest，本叶新增）
```

`b1-real-attempts/`/`b1-real-manifest.json` 与 `-run-`/`-report-`/`.expert-timing`/`attempts/`/`_materialized/`/`b1-attempts/`/`b1-manifest.json`（b1_source 离线族）/`-synthetic-`（offline_flow 族）**零碰撞**（前缀 `b1-real-` 独占；M10 断言）；companion 落盘于真实链返回后（不污染 `_run_shaped_repeats` 的 before/after 差异窗口）。

**绑定方式**：canonical 编码+SHA-256 内容摘要绑定（仓内 fingerprint 纪律，不引入非对称签名）；读取交叉核验不符 fail-closed typed（§7.2.3 码集；b1_source 四码与 real_run 十一码不动）。**旧五件套证据、旧 b1 manifest/report 闭集零增字段**；版本区分演进默认不触发（companion 可完整表达绑定——若实现发现不能表达 ⇒ Stop 7 提交 DR，不得就地改旧闭集）。

#### 7.5.6 报告与投影（R3.4）

报告经 E4 门走真实 scanner 类型路径：`scanned_files`/`coverage_gap(+reasons)`/`raw_candidates`/`deterministic_alerts`/`inconclusive`/`signals`/`security_issues` = 合并后 findings 单次扫描快照投影，与独立实际直扫逐值一致（24 为 signal-storm 真值——**以独立直扫为最终真值，非硬抄数字**，F3）；**5 重复样本不求和成 120**（IP-0040 §7.6.7 复用：聚合仅沿冻结 from_mapping 对计时面做百分位；attempt_count==5 如实）。Signal/Issue legacy_projection；Hypothesis/VEP/RVR/未执行阶段/resources/专家缺席沿 IP-0040 §7.2 冻结纪律 unavailable（不填 0、不构造空 bundle、二元 verdict 不作 root-cause 分级）。模型层费用/usage 在真实 ledger/attempts 如实记账（IP-0033 decoupled accounting 既有）；传输状态、scanner 来源、canary、预算、统计、报告投影分别呈报（§7.2.2 结果面+companion 面）。

### 7.6 七维预算、估算分支记账与 {1,4} 路由（R4 定稿）

#### 7.6.1 七维逐值表（裁定 §三表格逐字；唯一来源=最终批准工件 budget 面——loader L974-982 → BudgetSpec → BudgetLedger 门；b1_real.py 不含任何数字预算常量、不放松任何一维）

| 维度（budget.py L52-60 冻结序） | per_run / per-attempt | batch |
| --- | ---: | ---: |
| cost_micro_usd | 100000 | 198000 |
| calls | 1 | 5 |
| prompt_tokens | 150000 | 500000 |
| completion_tokens | 8000 | 40000 |
| wall_ms | 1200000 | 6000000 |
| download_bytes | 250000000 | 250000000 |
| storage_bytes | 500000000 | 500000000 |

#### 7.6.2 内部一致性核算（Packet 登记，非新公式；M4 独立复算断言）

- **成本**：attempt-0 冻结估算 prompt=REQUEST_BODY_BYTE_CAP=100000、completion=MAX_TOKENS=8000（L1677-1687），按冻结价格 300000/1200000 μUSD/百万（L341-342/L344 区域钉扎亲验）⇒ 最坏成本 = 100000×0.3 + 8000×1.2 = 30000+9600 = **39600 μUSD/attempt**；×5 = **198000 = batch 上限**（裁定 §三"内部冻结公式的批上限"机械对账；warm 估算 prompt=len(body_bytes)≤100000 不超过该公式）。
- **wall**：per_run 1200000 == 冻结 `_WALL_ESTIMATE_MS`（L190）；batch 6000000 = 5×1200000。
- **prompt**：per_run 150000 ≥ 冻结 attempt-0 估算 100000；batch 500000 = 5×100000。
- **completion**：per_run 8000 == MAX_TOKENS（L176）；batch 40000 = 5×8000。
- **download/storage**：per_run==batch（一次性本地物化、warm 复用同快照——F2 推断，逐值转录不"修正"）；物化走合成本地路径零下载（L1919 机制）。
- **BudgetSpec 逐维 batch≥per_run** 校验（L213-216）对同值维度平凡成立。

#### 7.6.3 估算分支记账（R4.2）

scanner 与来源物化占用发生在 **attempt-0 已预留窗口内**：reserve（L1594）先于 attempt 体 ⇒ 扫描在预留内；attempt wall 计时（finally L1607-1612）含扫描 ⇒ ledger settle 的 elapsed wall 记账含扫描时间；deadline 检查对扫描阶段同样生效（E3 显式 `_past_deadline`）；scanner 读写同一 materialized snapshot，其字节面已被 attempt-0 storage 预留（`_STORAGE_ESTIMATE_BYTES`=500M，L192）覆盖；companion 工件字节经 §7.5.4 `companion_bytes_total` 显式登记（≤ 预留）。**real_run.py 零新增估算分支、零改全局 estimate 常量、零放松门序**（§7.4 裁定）。若记账后无法在固定限额内证明可执行：保持零真实 POST 并呈报精确差额（Stop 9）。

#### 7.6.4 {1,4} 路由与 canary 五项映射（R4.3；§Frozen 2/3 逐字落位）

- **路由**：attempt_policy={cold:1, warm:4, max_attempts:5}（loader 五键闭集校验：cold≥1/warm≥1/max_attempts==cold+warm/canary_required is True/canary_first_attempt==0——亲验 L1016-1028）经冻结路由（非 {5,5} ⇒ `batch_shape=(1,4)` 进 `_run_shaped_repeats`，L2810-2819/L2636）执行恰 1 cold + 4 warm = 5 次调用；per_run.calls=1 与"每 attempt 一个 run_id、各 book ≤1 call"既有记账一致。**无新路由语义（{1,4} 路由已被冻结测试覆盖，real-pilot 先例）。**
- **canary 五项 index-1 映射（Packet 显式登记，非语义变更）**：裁定 §七"第一请求即 attempt-0 canary；五项全过才继续四个 warm"的机械落位=冻结 index-1 检查单（L1585-1591）：attempt-0 先行 POST（首请求即 canary 样本），首个 warm（index 1）入口处跑五键检查单（`_CANARY_CHECK_KEYS` L210-216：usage_within_reservation/identity_matches/attempt0_digest_verified/batch_margin_positive/canary_sample_success），任一失败 latch 后续全部拒绝；**{1,4} 形状下该纪律逐字成立**。
- **首败门**：`stop_on_first_failure=True`（第十二键）⇒ 首败后零新 POST（REAL_RUN_BATCH_STOPPED，首因保留，L1579-1584）。
- **SDK/transport 自动重试关闭**：`_urllib_transport` 单次 `urlopen` 无重试循环（L1273-1302 亲验）；Packet 登记声明 + 独立计数器审计面（§7.1 (0b) 计数包装——POST-only 计数，与 ledger calls 交叉，M2）。
- **max_attempts=5=硬上限（at-cap 拒绝声明）**：第 6 次调用拒绝——既有 at-cap 语义（batch.calls=5 时第 6 次 reserve `BATCH_BUDGET_EXCEEDED`，inclusive 语义 L380-393；冻结测试 `test_ten_reserves_pass_and_eleventh_refused_at_cap` L2235 同型）+ 入口形状执法（非 {1,4,5} ⇒ `B1_REAL_INPUT_INVALID`，M5）。离线孪生验证：5 fake POST/ledger.calls=5/计划形状 1/4/scanner 首执一次 warm 复用四次/零预算拒绝面。

### 7.7 授权同步点表（C2 允许的全部旧测试修改；= CA R2 附表 **逐字转录**；表外任何旧测试 hunk=Stop 4）

| # | 文件/位置（本会话亲验行号） | 方法/常量 | 旧值 → 新值 |
|---|---|---|---|
| S1 | tests/test_v4_baseline_real_run.py L574-588 | 模块常量 `_ARTIFACT_FAMILY_KEYS` | 11 键元组 → +第十二键（12 键） |
| S2 | tests/test_v4_baseline_real_run.py L589-596 | `_SYNTHETIC_ARTIFACT_KEYS` 过滤 | 排除元组 +第十二键（合成键保持 9 个） |
| S3 | tests/test_v4_baseline_real_run.py L3944 `test_artifact_family_catalog_frozen_ten_keys` | L3953 `len(catalog)==11` + L3954-3962 subTest 分支 | len==12；新键字段集分支（`_DESCRIPTOR_FIELDS` 七基础 ∪ IP-0039 四 R2 字段 ∪ B1 新增五字段，闭集=16 字段） |
| S4 | tests/test_v4_baseline_real_run.py L5506 `test_real_pilot_catalog_eleven_keys_and_field_sets` | L5516 `len(catalog)==11` | len==12（L5515 set 断言随 S1 常量自动成立；L5517 合成键循环随 S2 自动排除） |
| S5 | tests/test_v4_baseline_v5_negatives.py L571 `test_zero_budget_artifact_naming_discipline_scan` | 排除元组 | +第十二键（离线证明命名纪律域保持九合成键；L573 len==9 不变） |
| S6 | tests/test_v4_baseline_v5_negatives.py L601 `test_artifact_family_matches_fixture_registry` | 排除元组 | +第十二键（registry 匹配域保持九合成键） |
| S7 | tests/test_v4_baseline_b1_source.py L217-231 | 模块常量 `_ARTIFACT_FAMILY_KEYS` frozenset | 11 键 → 12 键（M16 `test_b1_old_static_surfaces_frozen` L1261-1263 set 相等断言随常量同步） |

**探针排除先例说明（R2 逐字）**：S2/S5/S6 沿 IP-0039"预授权排除演进"先例——新键为非合成描述子键（其溯源是 signal-storm 派生而非独立 registry 键），必须加入排除，否则离线证明命名纪律断言（要求 approval_type=零预算族）与 registry 匹配断言（assertIn(key, entries)）会错误作用于新键。S3/S4 的 count 断言是加键的唯一硬碰撞（两处 len==11）；S1/S7 是 set 相等断言的常量面。**冻结前该表逐字入 Packet（本表即冻结记录）；表外任何旧测试 hunk=Stop。**

### 7.8 旧路径零变化回归锚（A4/A5）

- `run_real_baseline_suite` 九参数签名（L2723-2734）与 order 1-9（L2771-2898）零变化（M21 三锚镜像+新文件镜像）；real_run `__all__` 六符号（L151-158）不变；`RealRunErrorCode` 十一码闭集不变（L474-486；L552/L5600 钉死）；`REAL_RUN_GATE_UNLOCKED is False`（L286）；`CANDIDATE_FILE_CAP==12`（L178）；`REAL_RUN_ARTIFACT_FAMILY` 十二键闭集（S1/S7 同步后）；旧十一键描述子字段集逐字不变。
- b1_source 离线契约面不变（M23）：`__all__` 七符号、`run_b1_source_baseline_suite` 十参数签名、`_RECEIPT_KEYS` 十六键、model_calls 恒 0 契约、`verify_b1_evidence` 在场。
- 旧 112/20/38/9 方法除 §7.7 授权点外零触碰零同步；C2 冻结提交上：旧 real_run 110 绿+2 授权点 RED、b1_source 19 绿+1 授权点 RED、report 38+v5_negatives 9 全绿（CA Done Commands 口径）；全量 discover 无回退（基线 2748 OK/24 skip + 新文件 RED 计入）。

## 8. 测试矩阵 v11（R5；新文件 `tests/test_v4_baseline_b1_real.py`，恰 25 方法 ≤26 上界，八簇；旧文件仅 §7.7 七点）

### 8.1 新增方法（25 个；`grep -c "    def test_"` 口径=25）

| 方法 | 簇 | 覆盖 | 断言面（冻结） | RED 态（对未修改产品 20e51e34：real_run 十一键态 + b1_real.py 不存在） |
| --- | --- | --- | --- | --- |
| `test_b1_real_entry_full_chain_offline_twin`（M1） | 1 | FR-01/FR-08/AC-1 | 孪生批准工件（第十二键+七维+{1,4,5}+date 2026-10-01）+注入 fake transport+全新空目录：恰 5 fake POST/5 attempt（0=cold、1-4=warm mode 标签）/ledger.calls==5/五件套证据+attempts 文档齐全/聚合 insufficient_sample/{d16}-report-1.json 落盘且 kind="scanner"/companion 5 receipt+manifest 落盘/B1RealSuiteResult 全面（含 real_post_count==5、b1_real is True）；零 GET/零下载字节（本地物化） | **RED**（ModuleNotFoundError: benchmarks.v4.baseline.b1_real——模块缺席锚，IP-0040 §9.3 先例；懒加载 per-test import） |
| `test_b1_real_post_count_honesty_face`（M2） | 1 | NFR-01/FR-07/AC-4 | 独立计数器（POST-only 包装）==ledger calls==real_post_count==5；companion manifest 无 model_calls 键、无 offline-proof 声明、`scanner-component-zero-model-calls` 仅组件级；transport_face/injected；SDK 无重试（fake transport 恰 5 次调用，无额外连通性请求） | **RED**（模块缺席） |
| `test_b1_real_seven_dimensions_per_value_from_approval`（M3） | 2 | FR-05/AC-2 | 孪生工件七维逐值装载：BudgetSpec per_run/batch ×7 维（§7.6.1 表逐值，从工件装载面断言非产品常量）；ledger snapshot per_run/batch 面一致；b1_real 源不含数字预算常量（源 AST 字面量扫描） | **RED**（模块缺席） |
| `test_b1_real_internal_reconciliation_and_estimate_registration`（M4） | 2 | FR-05/AC-2 | 198000=5×39600（100000×0.3+8000×1.2）独立复算对账；batch wall=5×1200000、prompt 5×100000、completion 5×8000；attempt-0 估算面（prompt==REQUEST_BODY_BYTE_CAP==100000、completion==MAX_TOKENS==8000）；companion `companion_bytes_total` ≤ storage 预留、`scanner_phase` 登记面（wall_registration 归属 attempt-0 预留） | **RED**（模块缺席） |
| `test_b1_real_at_cap_and_shape_enforcement`（M5） | 2 | FR-05/AC-2 | at-cap 语义：BudgetLedger 冻结面独立 arrange（batch.calls=5 时第 6 次 reserve 拒绝 BATCH_BUDGET_EXCEEDED——inclusive 语义，L2235 先例同型）；入口形状执法：{2,4}/{5,5} 形状工件 ⇒ B1_REAL_INPUT_INVALID 零 POST；max_attempts==cold+warm 冻结校验透传 | **RED**（模块缺席） |
| `test_b1_real_twelfth_descriptor_field_set_and_pins`（M6） | 3 | FR-03/AC-1/NFR-03/04 | `REAL_RUN_ARTIFACT_FAMILY` 12 键闭集；第十二键 16 字段闭集逐值（五溯源==signal-storm 合成派生逐字重算、approval_type/run_name 新钉扎、fixture_key、date_pin=retrieval_date_pin="2026-10-01"、stop_on_first_failure is True、workload、scanner_config_ref、scanner_config_sha256、source_contract、source_contract_version==1）；十一旧键字段集不变（10×7+real-pilot 11） | **RED**（行为缺失：目录 11 键无第十二键——直接读 real_run 面，断言失败归因于键缺席） |
| `test_b1_real_descriptor_derivation_deterministic`（M7） | 3 | FR-03/NFR-04 | scanner_config_sha256 独立重算（按 §7.3 config 文档形状 canonical 重算==目录值）；commit_sha 派生公式重算（sha256("lima-synth-artifact:archetype/signal-storm:<registry-fingerprint>")[:40]）；registry fingerprint 交叉（fixtures.load_registry）；run_name/approval_type 全目录唯一性 | **RED**（行为缺失：键缺席） |
| `test_b1_real_scanner_once_cold_attempt0_warm_reuse`（M8） | 4 | FR-04/AC-3 | attempt-00 cold_reset{performed:False, materialization_count:1}；warm×4 无 cold_reset 且 state_reuse.snapshot_reused=True；companion receipts 复用词表：attempt-0{scanner_reexecuted:True, scanner_result_reused:False, snapshot_reused:False, request_body_rebuilt:True}、warm×4 全反；scanner_executions==1；snapshot_tree_sha256 三方相等（receipt==cold_reset 观察==持久化 _materialized/snapshot 树重算） | **RED**（模块缺席） |
| `test_b1_real_report_matches_independent_direct_scan`（M9） | 4 | FR-04/FR-07/AC-3/AC-4 | 独立直扫（b1_source._scan_snapshot 扫新物化 signal-storm）为最终真值：报告 scanned_files/coverage_gap(+reasons)/raw_candidates/deterministic_alerts/inconclusive/signals/security_issues 逐值==独立复算；signal-storm==24 findings 全 candidate（独立直扫真值口径，非硬抄）；**attempt_count==5 而 raw_candidates==单次扫描值（非 120，不求和）**；分区不变量 raw==det+incon | **RED**（模块缺席） |
| `test_b1_real_receipt_key_set_and_companion_layout`（M10） | 4 | FR-02/AC-3 | receipt 键集恰 §7.5.3 二十三键（set 相等）；b1-real-manifest closed 键集恰 §7.5.4；工件命名族零碰撞断言（b1-real-attempts/b1-real-manifest vs -run-/-report-/attempts//_materialized//b1-attempts//b1-manifest.json/-synthetic-/.expert-timing） | **RED**（模块缺席） |
| `test_b1_real_digest_cross_chain`（M11） | 5 | FR-02/FR-07/AC-3 | receipt.scanner_payload_sha256==报告 sources scanner digest==_wire_fingerprint(独立复扫)重算；request_body_sha256==cold_reset.request_body_sha256；approval_sha256==sha256(approval.json 字节)；run_result_sha256==RunResult 文件内容 digest 重算（每 attempt 指针有效）；ledger_sha256==ledger.json 内容 digest；suite_run_name/attempt_document_name 指针有效且与 attempts 文档一致；analyzer_fingerprint 重算 | **RED**（模块缺席） |
| `test_b1_real_companion_verifier_pass_and_tamper_fail_closed`（M12） | 5 | FR-02/AC-3/AC-5 | verify_b1_real_evidence 通过态（孪生目录逐项复算全过）；篡改负例：receipt 键值→B1_REAL_RECEIPT_INVALID/B1_REAL_BINDING_MISMATCH；manifest source_receipts_digest→B1_REAL_BINDING_MISMATCH；scanner_payload_sha256→B1_REAL_SCANNER_DIGEST_MISMATCH；RunResult 回填→B1_REAL_BINDING_MISMATCH（typed 不降级 unavailable；subTest） | **RED**（模块缺席） |
| `test_b1_real_rejects_old_or_unknown_descriptor_misuse`（M13） | 6 | AC-5 | 旧描述子批准工件（real-pilot/large-repo 形状/钉扎）喂 B1 入口 ⇒ B1_REAL_INPUT_INVALID 零 POST；未知键（"real-pilot/ghost"）⇒ 冻结 loader APPROVAL_ARTIFACT_INVALID 透传（$ 结构路径） | **RED**（模块缺席） |
| `test_b1_real_rejects_fixture_workload_config_date_drift`（M14） | 6 | FR-03/AC-5/NFR-03 | 孪生工件逐项漂移：date=2026-10-02 ⇒ 冻结 date pin 拒绝（L897-900 透传）；retrieval_date 漂移 ⇒ 同（L953-957）；workload/scanner 配置 digest/source_contract_version 漂移 ⇒ B1_REAL_INPUT_INVALID；fixture_key 漂移（非 signal-storm）⇒ 拒绝；signal-storm 不误入网络下载（transport 计数仅 POST、零 GET、download_bytes==0——机制+负例双重保证） | **RED**（模块缺席） |
| `test_b1_real_nonempty_output_and_source_missing_tampered`（M15） | 6 | AC-5 | 非空输出根 ⇒ REAL_RUN_OUTPUT_NOT_EMPTY 透传零 POST；源缺失（删 _materialized/snapshot 后验）⇒ typed 拒绝；持久化 snapshot 树篡改 ⇒ 后相绑定 B1_REAL_BINDING_MISMATCH；别的 snapshot/RunSpec 回填（换 receipt/换 RunResult 文件）⇒ typed 拒绝 | **RED**（模块缺席） |
| `test_b1_real_scanner_failure_zero_post`（M16） | 6 | FR-04/AC-5 | scanner 失败注入（patch b1_source._scan_snapshot raise）：**零 POST**（计数器==0）；attempt-00 失败样本保留首因；后续全部 REAL_RUN_BATCH_STOPPED（stop_on_first_failure=True）；companion 不落盘/入口 typed 终局（B1RealError 面）；无新 RealRunErrorCode（taxonomy 不变断言） | **RED**（模块缺席） |
| `test_b1_real_cold_side_failure_first_cause_kept`（M17） | 6 | AC-5 | attempt-0 transport 失败 ⇒ 恰 1 POST 后零新 POST（计数器==1）、首因 REAL_RUN_TRANSPORT_FAILED 保留于 attempt-00、后续 REAL_RUN_BATCH_STOPPED；usage 缺失/身份漂移型 ⇒ REAL_RUN_USAGE_MISSING/REAL_RUN_IDENTITY_CHANGED taxonomy 透传（冻结码族） | **RED**（模块缺席） |
| `test_b1_real_warm_side_canary_and_response_failures`（M18） | 6 | FR-06/AC-5 | index-1（首个 warm）canary 检查单：五键面（usage 超 reservation/身份不符等注入）⇒ REAL_RUN_CANARY_FAILED latch、后续全拒、canary_status 面；warm 响应契约失败 ⇒ REAL_RUN_RESPONSE_INVALID；五项全过才继续（成功路径 M1 对照） | **RED**（模块缺席） |
| `test_b1_real_budget_deadline_refusal_and_cancellation`（M19） | 6 | AC-2/AC-5 | 零预算工件（全 0 维）⇒ 首次 reserve 拒绝零 POST（BudgetGateError 透传 taxonomy）；截止拒绝面（超时注入）；取消（BaseException 注入 transport）⇒ partial 五件套证据+原异常重抛+无 companion+无 RealSuiteResult（IP-0035 纪律透传） | **RED**（模块缺席） |
| `test_b1_real_old_paths_never_enable_new_hooks`（M20） | 6 | FR-01/AC-5 | 旧键（real-pilot/large-repo）孪生经冻结真实入口（fake transport）：报告 kind=real-world v2（**非** scanner）、零 companion 工件、目录字段集断言：十一旧键均不含 workload/source_contract（缺省关闭证明）；估算/来源新面缺席 | **按设计通过**（现行产品即目标行为——旧路径锚；C3 后仍绿守护不回归） |
| `test_b1_real_old_entry_signature_and_all_frozen`（M21） | 7 | FR-01/AC-5 | `inspect.signature(run_real_baseline_suite)` 三锚镜像（参数序 `_ENTRY_PARAM_ORDER` 口径/keyword-only 集/artifact_key 默认==external/llamafactory-replay）；real_run `__all__` 六符号 | **按设计通过**（旧路径锚） |
| `test_b1_real_static_surfaces_twelve_key_and_offline_contract`（M22） | 7 | AC-5 | 分组：① `REAL_RUN_ARTIFACT_FAMILY` set==12 键镜像（与 S1/S7 常量同步的新文件独立镜像）→ **RED（第十二键缺席，授权点一致归因）**；② REAL_RUN_GATE_UNLOCKED is False、CANDIDATE_FILE_CAP==12、real_run 十一码族不变、b1_source `__all__` 七符号/十参数签名/model_calls 恒 0 契约面 → 按设计通过 | **分组归因**（①RED/②通过） |
| `test_b1_real_b1_source_offline_entry_unchanged`（M23） | 7 | AC-5 | b1_source 离线契约面：`run_b1_source_baseline_suite` 签名 kw-only 十参数逐字、`verify_b1_evidence` 可调用在场、`_RECEIPT_KEYS` 十六键消费面（经 verify 路径）；离线入口零真实传输（model_calls==0 契约引用） | **按设计通过**（旧路径锚） |
| `test_b1_real_packet_doc_and_dockerfile_copy_line`（M24） | 8 | 纪律探针（IP-0040 M18 先例） | 本 Packet 在 docs/ 且 Dockerfile 恰一行 COPY 本 Packet（无第二行；新行 L72）；b1_real.py 无需新增打包行（benchmarks COPY L83 已覆盖，DI-011） | **按设计通过**（C1 文档先落） |
| `test_b1_real_sources_offline_and_secretless`（M25） | 8 | NFR-02/PC1 | 本测试文件自身源 AST 扫描（无网络根 import/无环境读/无 secret 形 token）；b1_real.py 存在时同款扫描+real_run 新 hunk 面（E0-E4 外零新 import 根）；缺席时产品组以缺文件 arrange 失败归因（方法内分组） | **分组归因**（自扫描组通过；产品组 RED=文件缺席） |

### 8.2 簇覆盖对照（CA C2 Acceptance 1 八簇 → 方法）

簇1 入口全链离线孪生→M1、M2；簇2 七维逐值→M3、M4、M5（at-cap/估算分支）；簇3 第十二键描述子→M6、M7；簇4 scanner 来源绑定→M8、M9、M10（receipt 键集）；簇5 digest 交叉→M11、M12（companion 验证器）；簇6 负例簇→M13-M20（未知/旧描述子误用、fixture/workload/config/source-version/date 漂移、非空目录、源缺失/篡改/回填、资源许可不足（M19 零预算）、scanner 失败、首轮与 warm 的 transport/响应/usage/身份失败、预算/截止拒绝、取消、首败后零新 POST 且首因保留、**缺省旧路径不启用新 hook（M20）**）；簇7 旧路径锚回归→M21、M22、M23（inspect.signature 三锚镜像/`__all__`/REAL_RUN_GATE_UNLOCKED/CANDIDATE_FILE_CAP/b1_source 离线契约）；簇8 纪律探针→M24、M25（docs+Dockerfile 恰一行/PC1 自扫描）。

### 8.3 RED 形态（C2 冻结前，对未修改产品 20e51e34 版或 C1 合并后 SHA；逐方法归因账）

- **21 方法 RED**：M1-M19（19 方法：18 模块缺席锚 + M6/M7 行为缺失键缺席归因——M6/M7 直接读 real_run 目录面，RED 归因=第十一键态目录无第十二键）+ M22①（12 键镜像组 RED——授权点一致）+ M25（产品组 RED）。模块缺席锚=`ModuleNotFoundError: No module named 'benchmarks.v4.baseline.b1_real'`（懒加载 per-test import，失败=模块缺席非 arrange/import/lint 错误）。
- **3 方法按设计通过**：M20、M21、M23（旧路径回归锚；现行产品即目标行为）+ M24（C1 文档先落）——即 4 方法含 M24；其中 M20/M21/M23/M24 全绿、M22②/M25 自扫描组绿。
- **授权同步点方法的冻结态 RED/GREEN 精确账（CA C2 Acceptance 2 逐字落位）**：`test_artifact_family_catalog_frozen_ten_keys`（len==12 对 11 键产品 RED）；`test_real_pilot_catalog_eleven_keys_and_field_sets`（同）→ RED；`test_b1_old_static_surfaces_frozen`（12 键 frozenset vs 11 键目录 set 不等）→ RED；`test_zero_budget_artifact_naming_discipline_scan`/`test_artifact_family_matches_fixture_registry`（排除元组排除一个尚不存在的键=no-op）→ **按设计 GREEN**（其同步为 C3 绿态所必需）；其余 110 real_run + 19 b1_source + 9 v5_negatives + 38 report 全绿。
- 逐方法归因表强制（先落盘、再 hash、再引用，归档主仓库 `.pv_tmp/RED_IP-0041_2026-10-01/`）；Pre-Freeze Harness Gate 八项（§10）。

### 8.4 PC 纪律（IP-0033..0040 同款标配）

PC1=新增测试源 secret-token/网络-token 拼接扫描+AST import 根扫描（M25）+产品源扫描（b1_real.py 存在时）；PC2=arrange 经冻结校验器（孪生批准工件经冻结 loader 接受面构造；receipt/spec 构造一律经 canonical_encode 或直接产品入口）；PC3=派生数值断言（七维=装载面非产品常量、24=独立直扫真值、digest=冻结指纹规则独立重算、39600/198000=公式独立复算，不硬抄实现值——M3/M4/M7/M9/M11）。

## 9. 冻结测试面演进程序与提交/证据链（R5；六条件退化适用+授权同步点恰 7 点）

1. **对象唯一**：新文件 `tests/test_v4_baseline_b1_real.py` 一次（v11，恰 25 方法 ≤26 上界）+ 恰 §7.7 七授权点；其余旧文件与产品禁区模块零 hunk（Done Commands 逐 blob 守护）。
2. **逐 hunk 归因**：新文件每方法映射 §1 需求表与裁定编号（R1-R4/裁定 §三-§六），§8.1 已逐条登记；七授权点旧值→新值逐字（§7.7）。
3. **禁止弱化**：不删除任何负例；新文件自身不得含 skip/xfail/条件降级断言；授权点外旧断言零触碰。
4. **版本链保留**：v10' 历史blob（real_run 18bfb4c2/v5_negatives 6887f9fa/b1_source a3b4c8fc/report 86f584cb）永久在链；v11 blob 由 C2 冻结时登记。
5. **RED 先于冻结**：C2 冻结前按 §8.3 取得有效 RED 并独立日志归档（主仓库 `.pv_tmp/RED_IP-0041_2026-10-01/`，先落盘、再 hash、再引用）；冻结基线=main 上 C1 合并后完整 SHA（主会话记录；worktree rebase/重置到该 SHA 后开工）。
6. **角色纪律**：演进只在 C2 由 P&V 执行；Implementation 结构性零参与测试修改；C2 冻结提交后本 Assignment 的 ALLOWED_ONCE（§11）仅覆盖一次纯测试机械缺陷。

**Pre-Freeze Harness Gate（冻结前必须全部通过；IP-0040 §10 八项同款）**：① 新文件可完整 import 与 collect（零加载期错误）；② 最小 NotImplemented 桩模块验证全部 fixture/arrange/参数组合执行到产品行为断言处（区分 fixture 缺陷 vs 行为缺失；桩置临时目录）；③ fixture 签名/参数数量/subTest 构造不被 ModuleNotFoundError 掩蔽；④ Ruff 一律 `--no-cache`；⑤ Ruff 在产品模块缺席态与最小桩存在态分别运行并双双通过（isort first-party 分类依赖模块存在性）；⑥ 临时桩不入冻结提交（删除后 `git status` 证明）；⑦ RED 逐项归因于缺失产品行为；⑧ 方法预算 25（≤26 上界，CA R5）。

**提交链与证据归档（冻结）**：C1 提交信息逐字 `[IP-0041][PV] Add Implementation Packet IP-0041 (B1 real entry) and Dockerfile copy line`；C2 提交信息逐字 `[IP-0041][PV] Freeze acceptance tests v11 (RED)`；C3 前缀 `[IP-0041][IMPL]`（以 C2 为祖先）；RED 日志归档主仓库 `.pv_tmp/RED_IP-0041_2026-10-01/`（不提交）；`AC → 测试 → 结果` 表框架：AC-1→M1/M3/M5；AC-2→M2/M3/M4/M5/M19；AC-3→M8-M12；AC-4→M2/M9；AC-5→M13-M23+Done Commands（每行 C4 填实际命令与结果）。

## 10. ALLOWED_ONCE（一次性机械测试修正授权；CA §Mechanical Test Correction Allowance 全文转录）

`ALLOWED_ONCE`（随 CA-IP-0041-v1.0 一次性给出）。C2 冻结后，P&V 可在不新增 Coordinator 调用的情况下自行纠正**一次**纯测试机械缺陷并重新冻结（v11→v11'），条件全部满足：① 不改变产品语义、公共接口、稳定错误码或文件范围（含 Dockerfile 行数与授权同步点表范围）；② 仅限 fixture/arrange/import/lint/测试基础设施错误；③ 旧 Frozen Commit 保留；④ 修正前缺陷证据（原始 traceback 独立日志）、修正后有效 RED、新 Frozen Commit 完整记录；⑤ Implementation 未参与测试修改。涉及产品行为、验收语义或文件范围（含新增/删除授权同步点）时仍必须提交 Decision Request；授权仅一次，用尽即止。

## 11. Done Commands（C2 冻结前在 worktree 执行并留日志；`PYTHONUTF8=1`；CA §Acceptance and Validation 逐字+守护面）

```bash
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_real_run        # 110 绿 + 2 授权点 RED（S3/S4）
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_b1_source        # 19 绿 + 1 授权点 RED（S7→M16）
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_report tests.test_v4_baseline_v5_negatives   # 38+9 全绿
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_b1_real -v       # 新文件 RED（逐方法归因 §8.3）
PYTHONUTF8=1 python -m unittest discover -s tests                       # 基线 2748 OK/24 skip 口径核对（含新文件 RED 计入）
PYTHONUTF8=1 python -m compileall -q benchmarks tests
PYTHONUTF8=1 python -m ruff check --no-cache tests/test_v4_baseline_b1_real.py
git -C /d/BaseAIProject/LIMA-ip-0041-wt diff --stat 20e51e34..HEAD      # C1 恰 1Add+1Mod；C2 累计 1Add+1Mod+1Add+3授权点
git -C /d/BaseAIProject/LIMA-ip-0041-wt diff --name-only 20e51e34..HEAD -- lima/   # 必空
# 守护（C4/主会话）：real_run.py 逐 hunk 对照 §7.4 E0-E4（清单外 hunk=Stop 8）；
# b1_source/budget/report/run/orchestrate/fixtures/collect/expert_timing/offline_flow/__init__ blob 不变；
# 四冻结测试文件除 §7.7 七点外零 hunk；RED 归档先落盘后 hash 后引用
```

C1 验收命令（本提交上执行）：`git diff --stat 20e51e34..HEAD` 恰 2 文件（1 Add docs + 1 Mod Dockerfile +1 行）；`git diff 20e51e34..HEAD -- Dockerfile | grep -c "^+"` ==2（+++头+新行）；`git diff --name-only 20e51e34..HEAD -- lima/ benchmarks/ tests/` 必空；`python -m compileall -q docs` 无输出（docs 无 py）。

成功判据：全部按预期形态通过（授权点方法的 RED 是成功判据的一部分，逐条归因正确）；diff 只落在 Allowed Files；失败判据：任何命令非预期退出、任何越界文件、任何 `lima/**` diff、授权点外旧测试任何 hunk、任何对冻结面的语义弱化。

## 12. Stop Conditions（触发即停并落盘 Decision Request 到主仓库 `.pv_tmp/DR_IP-0041_*.md`；★=绝对停；CA §Known Gaps and Stop Conditions 全部 11 条+R7 逐字）

0. 派发前再核验失败：#251 正文/标签/远程状态与本地捕获不一致，或基线 SHA 上 main 出现冲突性实现（含 IP-0041 编号被占用）。
1. ★ 任何真实模型调用尝试（含一次 POST）/真实凭据注入/网络下载/付费动作（C1-C3 与 CI 全程）= 绝对停。
2. ★ `lima/**` 任何写 = 停；sealed 目录（`D:\BaseAIProject\LIMA-real-runs\**` 及一切封存树，含第六/七轮原件）任何写入 = 停。
3. ★ `budget.py` 维度/门序/结算语义、旧 canary/首败逻辑、旧 estimate 常量、transport、身份允许集、模型契约（请求名/base_url/thinking/max_tokens=8000/请求体上限/二元输出）、旧描述子、旧批准工件的任何 diff = 停。
4. ★ 授权同步点表（§7.7）之外的旧测试修改 = 停；以改测试消失败 = 停。
5. **日期钉扎（R7 逐字）**：新描述子 date_pin/retrieval_date_pin=2026-10-01（Asia/Shanghai）。**跨日（Asia/Shanghai 自然日越过 2026-10-01）而一次性真实 pilot 尚未启动时，本描述子与七维授权失效，须重新受审修订（新日期钉扎+新批准工件）后方可执行；不得以旧日期钉扎跨日执行、不得倒签。** C1-C3 离线阶段不受此条失效影响，但孪生工件内日期面必须与描述子钉扎逐字一致（漂移=负例簇之一，M14）。
6. scanner 配置依赖环境变量默认值、或任何网络/LLM/platform/会执行仓库代码的验证路径被启用 = 停；signal-storm 因新键误入网络下载 = 停（机制上由 fixture_key 分支 L1919 保证，测试须有负例 M14）。
7. 需要修改 `b1_source.py` 离线契约/model_calls=0 语义、或在旧 ledger/manifest/report 闭集内塞 B1 来源字段才能表达绑定 = 停（先提交 DR；companion 独立工件是默认出路，R3）。
8. real_run.py 演进超出"additive+新描述子限定+Packet 点名（§7.4 E0-E4）"边界（触及公共签名/order 1-9/旧描述子行为/错误码族/`__all__`）= 停。
9. 七维无法在固定限额内保守证明可执行（含扫描/来源物化占用记账后）= 保持零真实 POST 并呈报精确差额，不自动扩大预算（裁定 §三）。
10. 同根因两轮有新证据修复仍失败 / 授权文本与代码事实矛盾 / 规格无法兼容 = 落盘 DR 后停依赖部分，完成其余工作。
11. 需要消耗 Maintainer 决策的事项（预算 ≤1，预期 0）；方法数超预算（>26）或簇覆盖缺口；discover skipped 集出现未登记变化（基线 24）。

## 13. PR 与 Completion Summary 契约（CA §Handoff）

- C1 PR（主会话）：单 PR `codex/ip-0041-b1-real-entry` → main；标题禁 close 族关键词与编号组合；正文含 C1 commit SHA（完整 40 位）、变更文件清单（恰 1 Add+1 Modify）、Dockerfile 恰 +1 行证明、"Related to #251."（仅此关联；不得关联关闭 #57；无自动关闭关键字）。
- C4 Implementation PR（P&V 组装）：`Implements IP-0041` + `Related to #251` + Packet 路径与 C1 合并 SHA + Frozen Test Commit 与实现 commit + Covered FR/AC/NFR 与未覆盖声明 + 文件/依赖变化 + `AC → 测试 → 结果` 表 + 实际命令/环境/统计/skip/artifact + Verification Verdict + Decision/Findings/known limitations + Issue closure impact：PARTIAL + "This PR does not auto-close the Source Issue."；提交前缀 `[IP-0041][PV]`/`[IP-0041][IMPL]`/`[IP-0041][CI]`；C3 必须以 C2 为祖先；修复提交须引用 Stop/DR/ALLOWED_ONCE 编号。合并/推送/评论由主会话按 Maintainer 授权执行；P&V/IMPL 零远端写；分支 head CI 与审查过门后才合并，合并后核验 merge SHA 的 main CI success。
- Completion Summary 必含：FR-01..08/NFR-01..04 逐条证据索引（测试 ID）、AC-1..5 判定（满足/不满足/未验证三态）、C1/C2/C3 提交 SHA 与 blob 记录、RED 归档路径与逐方法归因计数（预期 21 RED/4 按设计通过+2 分组，§8.3）、基线实际值（179 passed/2748 OK/24 skip）、零真实调用声明（fake transport 计数≠真实调用；real_post_count 语义）、Dockerfile 恰 +1 行证明、第十二键/入口/companion/七维冻结决定引用（§7/§16）、K 缺口状态。
- 传递时必须携带被否决的决定及理由（§3 全部 17 项转录传递）：不把真实 HTTP callback 塞入离线入口（§3#1）、不复制无门禁 HTTP 驱动（#2）、不串联两批合并目录（#3）、不参数化旧入口（#4）、scanner 不改模型上下文选择（#6）、候选选择保持冻结 walk、不复用旧 pilot 描述子/批准工件（#5）、不在旧闭集内加 B1 字段（#8）、不新增 RealRunErrorCode（#12）、不复制完整失败日志。

## 14. 范围裁定 R1-R7 转录（CA-IP-0041-v1.0 附录 R 全文，逐字）

- **R1（Q1 入口拓扑）**：新文件+新公共入口组合冻结基元；real_run.py 仅允许 additive 新描述子限定 hook，例外必须 Packet 点名。——裁定：新文件 `benchmarks/v4/baseline/b1_real.py`，公共入口名 `run_b1_real_baseline_suite`（最终名称由 Packet 冻结，但必须保持"新文件+新公共入口"形态）。组合方式裁定为分层最小边界：1. **默认组合**：b1_real.py 只读 import real_run/budget/b1_source 冻结原语，其入口最终驱动冻结 order 1-9 真实链（以 `artifact_key=<第十二键>` 走 `run_real_baseline_suite` 或由 Packet 在同等门序下点名等价组合），B1 专属前相（批准工件制备/入口校验）与后相（companion receipt 落盘/交叉核验/来源投影检查）在 b1_real.py 内。**禁止**：复制缺少门禁的 HTTP 驱动；串联两个独立批后把目录合并称作同一证据链（裁定 §四）。2. **real_run.py 受审演进例外**（仅当默认组合不能表达时启用，Packet 逐项点名）：additive、**新描述子限定**的私有 hook——(a) scanner 执行 hook：cold attempt-0 物化后、同一预留/截止窗口内执行一次 scanner（裁定 §五"在预留和截止保护内进行本地物化、B1 scanner、请求体构造及模型 POST"——scanner 必须在 guarded 窗口内，这是必须进 real_run.py 组合面的原因）；(b) 来源收集 hook；(c) 估算分支（R4）。每个例外：逐 hunk 登记（符号/门条件/默认关闭证明），既有语句与公共签名零变化，旧十一键永不进入新分支。3. **旧公共入口默认语义零变化的机械证明**（四层）：① inspect.signature 三锚（test L2427/L3928/L4007）与新文件镜像锚全绿；② 旧 112 方法除授权同步点外全绿（授权点 RED 恰因第十二键缺席，C3 后全绿）；③ 新文件负例：十一旧键描述子永不携带新 hook 门字段（默认关闭断言，沿 L1444/L1579 `stop_on_first_failure` 默认 False 与 L1404 `batch_shape=None` 字节等同先例的证明模式）；④ diff/blob 守护：real_run.py 若有修改，逐 hunk 对照 Packet 例外清单，清单外 hunk=Stop 8。——依据：裁定 §四；`_GuardedRealEvaluator` 私有 kw-only 载面先例（L1404 batch_shape、L1444 stop_on_first_failure）；IP-0040 R3。
- **R2（Q2 第十二键描述子）**：沿 IP-0039 第十一键先例加入 REAL_RUN_ARTIFACT_FAMILY；授权同步点表恰 7 点（默认非空）。——裁定：第十二键（建议键名 `real-pilot/signal-storm`，最终由 Packet 冻结；不得复用 `real-pilot/large-repo`）加入 `REAL_RUN_ARTIFACT_FAMILY`。字段集沿 IP-0039 先例扩展：**七基础字段**（五溯源字段=archetype/signal-storm 合成派生逐字（`_synthetic_artifact_descriptor` L388-410），approval_type/run_name 替换为本次专属新钉扎——run_name 唯一、不得与任何既有 run_name 冲突）+ **IP-0039 四 R2 字段**（fixture_key="archetype/signal-storm"、date_pin="2026-10-01"、retrieval_date_pin="2026-10-01"、stop_on_first_failure=True）+ **B1 新增字段**（workload、scanner config 引用/digest、source contract/version——精确键名由 Packet 冻结，loader 经 `descriptor.get` 尾默认读取，零新校验分支于旧键）。日期经既有 date_pin/retrieval_date_pin 机制驱动校验（L897-900/L955）；fixture_key 在描述子 ⇒ synthetic 本地物化路径（L1919），signal-storm 不误入网络下载由机制+负例双重保证。**十一旧键字段集逐字不变**。——授权同步点表=S1-S7（§7.7 逐字转录）；探针排除先例说明（S2/S5/S6 沿 IP-0039"预授权排除演进"先例）；冻结前该表逐字入 Packet；表外任何旧测试 hunk=Stop。——依据：裁定 §四；IP-0039 第十一键先例；Q2 触点 Coordinator 全文件亲扫。
- **R3（Q3 scanner 接线与 receipt 绑定）**：cold attempt-0 窗口内扫描一次、warm 复用；companion 独立工件；模型上下文选择冻结不变。——裁定：1. **执行时机**：scanner 在 cold attempt-0 内、快照物化+解包完成后、请求体构造前后同窗口执行**恰一次**（预留与截止保护内；裁定 §五"扫描、来源校验、预留、请求体或截止失败发生在 POST 前时，必须零 POST"——扫描失败在 POST 前即 typed 失败、零 POST）；`cold_reset.performed=False`、`materialization_count=1` 如实（L1711-1719 机制既有）。warm 1-4 复用同一 snapshot/扫描结果/请求体，receipt 记 `scanner_reexecuted=False`/`scanner_result_reused=True`/`snapshot_reused=True`/`request_body_rebuilt=False`（沿冻结 state_reuse 词表，b1_source 十六键先例）。scanner 配置=显式离线（b1_source `_scan_snapshot` L325-353 同款：LLM/platform/网络/code-exec 全禁），scanner/模型上下文/receipt 绑**同一实际 snapshot**（receipt `snapshot_tree_sha256`==cold_reset 观察 L1749 同值——交叉可证）。2. **与模型请求候选选择的关系**：**冻结确定性 walk（`_select_candidate_texts` L1333）零变化；scanner 输出不改变模型上下文选择**。`CANDIDATE_FILE_CAP=12` 保持纯请求构造参数（报告计数不受其截断——IP-0040 M10 先例；signal-storm 24 findings 全范围入报告）。同 snapshot 绑定以 digest 相等证明，不以"scanner 驱动上下文"证明。若 Packet 认为需要 scanner 引导的候选选择 → 超出本裁定，须 DR。3. **companion source_receipt**：**独立 companion 工件**（输出目录内 B1 专属工件族，命名由 Packet 冻结、与 `-run-`/`-report-`/`attempts/`/`b1-attempts/` 零碰撞），键集=b1_source 十六键（L118-135 语义全保留）+ 真实绑定新增键：approval digest、实际模型 request-body digest（sha256(body_bytes)）、RunResult/run_spec_digest 关联、真实 suite 关联（run_name/attempt 文档指针）——**精确键集由 Packet 冻结，不得收缩语义**。绑定=canonical 编码+SHA-256 摘要（仓内 fingerprint 纪律）；读取交叉核验不符 fail-closed typed（新入口自有错误族，码集 Packet 冻结；b1_source 四码不动）。**旧五件套证据（approval/ledger/machine_profile/attempts/manifest）、旧 b1 manifest/report 闭集零增字段**；仅当 companion 确不能表达必要绑定时允许新 B1 路径限定的版本区分演进（Packet 点名文件/字段/旧测试同步范围后冻结——默认不触发）。4. **报告**：走真实 scanner 类型路径（build_baseline_report kind="scanner"，IP-0040 §7.1 数据流复用）；scanned_files/coverage/raw_candidates=合并后 findings 与独立直扫逐值一致（24 为真值；**5 重复样本不求和成 120**——IP-0040 §7.6.7 不求和规则复用）；Signal/Issue legacy_projection；Hypothesis/VEP/RVR/未执行阶段/resources/专家缺席 unavailable 纪律沿 IP-0040 §7.2。**整个真实 suite 如实记实际 POST 数**（manifest/result 面记录真实传输计数与 usage；禁止输出总 model_calls=0 或 offline-proof 误导标记——b1_source 的 model_calls=0 常量是离线入口专属，真实入口不得复用该字段语义，Packet 冻结真实计数面字段名）。——依据：裁定 §四/§五；b1_source `_wire_fingerprint`（L375-393）与 report 规则一致性先例；IP-0040 R4/DR-PV-3 十六键先例。
- **R4（Q4 七维与估算分支）**：七维不放松；扫描/物化占用在已预留窗口内记账，新估面 Packet 登记且服从七维；{1,4} 经 approval.attempt_policy 路由验证。——裁定：1. **七维逐值**（裁定 §三表格逐字，per_run/batch）：cost_micro_usd 100000/198000、calls 1/5、prompt_tokens 150000/500000、completion_tokens 8000/40000、wall_ms 1200000/6000000、download_bytes 250000000/250000000、storage_bytes 500000000/500000000。来源=最终批准工件 budget 面（loader L974-982 → BudgetSpec → BudgetLedger 门），**b1_real.py 不含任何数字预算常量、不放松任何一维**。内部一致性（Packet 登记，非新公式）：per_run.wall_ms=1200000==冻结 `_WALL_ESTIMATE_MS`（L190）；batch.wall=6000000=5×1200000；prompt per_run 150000≥冻结 attempt-0 估算 REQUEST_BODY_BYTE_CAP=100000；batch 500000=5×100000；completion 8000==MAX_TOKENS；成本 198000=5×39600（100000×0.3+8000×1.2 μUSD）。2. **估算分支记账**：scanner 与来源物化占用发生在 **attempt-0 已预留窗口内**（预留 wall=per_run.wall_ms、storage=500M 常量 L190-192——scanner 读写同一 materialized snapshot，其字节面已被该预留覆盖；deadline 检查对扫描阶段同样生效）。**允许**的新增保守估算分支仅限：companion 工件字节/扫描阶段 wall 的显式登记面（新描述子限定，R1 例外 (c)），其一切数值 ≤ 既有七维预留，不改全局 estimate 常量、不放松门序。**若记账后无法在固定限额内证明可执行：保持零真实 POST 并呈报精确差额**（Stop 9）。3. **{1,4} 路由验证**：attempt_policy={cold:1,warm:4,max_attempts:5} 经冻结路由（非 {5,5} ⇒ `batch_shape=(1,4)` ⇒ `_run_shaped_repeats`，L2814-2819/L2636）执行恰 1 cold+4 warm=5 次调用；per_run.calls=1 与"每 attempt 一个 run_id、各 book ≤1 call"的既有记账一致；canary 五项在首个 warm（index 1）入口运行（R1/§Frozen 3 映射）；首败门 stop_on_first_failure=True 生效（首败后零新 POST，REAL_RUN_BATCH_STOPPED）；SDK/transport 自动重试关闭（urllib 默认无重试，Packet 登记声明+独立计数器审计面）；max_attempts=5=硬上限（第 6 次调用拒绝——既有 at-cap 语义，冻结测试 `test_ten_reserves_pass_and_eleventh_refused_at_cap` 同型）。离线孪生验证：5 fake POST/ledger.calls=5/计划形状 1/4/scanner 首执一次 warm 复用四次/零预算拒绝面。——依据：裁定 §三；budget.py L52-60/L380-444 门序亲读；real_run L1677-1694 估算常量亲读。
- **R5（Q5 测试预算与冻结面）**：新文件 tests/test_v4_baseline_b1_real.py（v11），≤26 方法；授权同步点表默认非空（=R2 附表）。——裁定：新验收面承载于新文件 `tests/test_v4_baseline_b1_real.py`（冻结版本 v11 = v10' 之后序号）；**新增方法上限 26**（`grep -c "    def test_"` 口径），八簇覆盖见 Acceptance C2 第 1 项。**授权同步点表默认非空**：恰 R2 附表 7 点（S1-S7），逐点旧值→新值登记；表外旧文件零 hunk；不删除任何负例；六条件程序退化适用（条件 1"对象唯一"=新文件一次 + 恰 7 授权点）。RED 形态与授权点 RED/GREEN 精确账见 Acceptance C2 第 2 项；Pre-Freeze Harness Gate 沿 IP-0040 §10 八项。——依据：CA-IP-0040 R5 先例+本叶差异；方法数 26 vs IP-0040 的 24：本叶多出"七维逐值"与"真实计数面"两簇，预算相应放宽 2，仍为上界非目标值。
- **R6（Q6 C-final 与 pilot 门禁归属）**：离线双证归 P&V；一次性真实 pilot 归主会话；ER 不复现真实 pilot。——裁定：裁定 §六精确工件离线双证（最终新描述子/七维/日期/workload 的无付费效力孪生：正式新入口+fake transport+全新空目录执行到报告；成功路径逐值验证 + 全负例面 + 回归旧 112/B1 20/报告 38/负例 9/cold-reset/取消面/全量 discover）= **C-final 阶段 P&V 任务，在独立 worktree、实现验证通过后、合并前执行**（后续 CA 授权）。裁定 §七一次性真实 pilot（临调用门/价格页读取（cache-miss 输入 ≤US$0.30/百万、输出 ≤US$1.20/百万，与冻结价格钉 300000/1200000 μUSD/百万一致）/仓外一次性空目录/凭据进程内注入/首请求即 attempt-0 canary/五项全过才继续 4 warm/无额外连通性请求）= **主会话在 Maintainer 授权下、全部门禁（含 §六双证）通过且合并后干净检出上执行**；**ER/复核者不得再次执行真实 pilot 做"独立复现"**（裁定 §四）；批后脱敏/封存/专家包/#57 更新（§八）随 pilot 终局另行。本 Assignment（C1+C2）对上述均只预排归属，不提前授权。——依据：裁定 §四/§六/§七；CA-IP-0040 R7 先例。
- **R7（Q7 日期钉扎）**：date_pin=retrieval_date_pin=2026-10-01（Asia/Shanghai）；跨日未启动须重新受审。——裁定：第十二键描述子 `date_pin` 与 `retrieval_date_pin` 均冻结为 **"2026-10-01"**（实际签定与检索日，Asia/Shanghai 时区口径）；批准工件 `date` 与 `pricing.retrieval_date` 经既有 pin 校验机制（L897-900/L955）与之逐字相等。**跨日失效条款**（写入 Packet 与 Stop Conditions 5）：Asia/Shanghai 自然日越过 2026-10-01 而一次性真实 pilot 尚未启动 ⇒ 本描述子与七维授权耗尽态之外另需**重新受审修订**（新日期钉扎、新批准工件、复核七维与价格页），不得以旧钉扎跨日执行、不得倒签日期、不得修改 real-pilot/large-repo 或任何旧批准工件顶替。C1-C3 离线阶段不受失效条款影响（离线孪生不消耗 pilot 效力），但孪生工件内日期面必须与描述子钉扎逐字一致（漂移=负例簇之一）。——依据：裁定 §四；IP-0039 date_pin/retrieval_date_pin 机制先例。

## 15. Decision Record（P&V 定稿决策；CA 授权范围内的冻结裁量）

| # | 决策 | 时间 | 依据 |
| --- | --- | --- | --- |
| DR-IP-0041-PV-1 | 第十二键最终键名 = **`real-pilot/signal-storm`**（采纳 CA 建议值；real-pilot/* 非合成族命名先例；不得复用 real-pilot/large-repo） | 2026-10-01 | R2"建议键名……最终由 Packet 冻结" |
| DR-IP-0041-PV-2 | approval_type=`PR3D-B1-REAL-ENTRY-ONE-SHOT`、run_name=`pr3d-b1-real-signal-storm-2026-10-01`（新钉扎；与既有四族 run_name/approval_type 全集零冲突——亲验 L346-347/L352/L382-383/L407；M7 断言唯一性） | 2026-10-01 | R2"approval_type/run_name 替换为本次专属新钉扎——run_name 唯一" |
| DR-IP-0041-PV-3 | B1 新增五字段键名定稿：`workload="b1-real-signal-storm-v1"`、`scanner_config_ref="b1-source-offline-scan-v1"`、`scanner_config_sha256`（B1 真实 config 文档 canonical digest，§7.3 形状）、`source_contract="b1-real-source-binding"`、`source_contract_version=1`；绑定门=workload∪source_contract 双键存在性（仅第十二键携带） | 2026-10-01 | R2"B1 新增字段……精确键名由 Packet 冻结"；裁定 §四"workload、scanner config、source contract/version"；IP-0039 尾默认读取先例 |
| DR-IP-0041-PV-4 | real_run.py 例外清单定稿=**恰 5 项 E0-E4**（§7.4）；R1.2(b) 来源收集 hook **零启用**（后相从盘上证据+独立复扫完整推导）；R1.2(c) 估算分支 **real_run 零新分支**（登记面=companion manifest `companion_bytes_total`/`scanner_phase`，数值 ≤ 既有预留） | 2026-10-01 | R1.2"仅当默认组合不能表达时启用"；R4.2"允许的……仅限显式登记面"；既有预留机械覆盖亲验（L1594/L1607-1612/L190-192） |
| DR-IP-0041-PV-5 | E4（build_payload 门化返回 RepositoryScanResult）登记为 R1.2(a) 的完成面：R3.4"报告走真实 scanner 类型路径"在链内的唯一最小落位（备选拒绝：order-9 后另写第二报告=报告面歧义+order-9 报告失实；后相重建报告=证据链分裂）。旧键/扫描缺席回落冻结 dict 逐字 | 2026-10-01 | R3.4；R1.2(a)；build_payload 单一报告消费点亲验（L2859） |
| DR-IP-0041-PV-6 | scanner 失败 **零新增 RealRunErrorCode**：十一码闭集被旧测试钉死（L552 `_FROZEN_ERROR_CODES`/L5600 set 相等，DI-009 亲验）——scanner 异常经冻结 Exception 纪律传播（失败样本+零 POST+首败门首因保留），B1 语义类型化在 b1_real 自有错误族与终局面 | 2026-10-01 | Stop 3/4（错误码族与表外旧测试不可动）；裁定 §五"扫描失败在 POST 前即 typed 失败、零 POST"（typed 落位=入口族） |
| DR-IP-0041-PV-7 | companion receipt 键集定稿=**恰 23 键**（b1_source 十六键语义全保留 + 七真实绑定键 approval_sha256/request_body_sha256/run_result_name/run_result_sha256/attempt_document_name/suite_run_name/ledger_sha256——覆盖 CA R3.3 全部点名 + 裁定 §五账本关联；无一处收缩语义） | 2026-10-01 | R3.3"精确键集由 Packet 冻结，不得收缩语义"；裁定 §五 receipt 必含清单 |
| DR-IP-0041-PV-8 | companion 布局命名定稿：`b1-real-attempts/b1-real-attempt-{i:02d}.json` + `b1-real-manifest.json`（与全部既有工件族零碰撞，§7.5.5；真实计数面字段名定稿 `real_post_count`/`ledger_calls`/`companion_bytes_total`/`transport_face`，无 model_calls 键） | 2026-10-01 | R3.3"命名由 Packet 冻结、零碰撞"；R3.4"Packet 冻结真实计数面字段名" |
| DR-IP-0041-PV-9 | 新入口签名=八参数（镜像冻结入口减 artifact_key，内部钉扎第十二键；无 seed/shape/workload 参数——绑定唯一来源=目录+批准工件）；`__all__` 恰五符号；错误族恰五码（§7.2.3） | 2026-10-01 | R1.1 默认组合；IP-0040 §7.4 签名先例；结构 only field path 先例 |
| DR-IP-0041-PV-10 | 独立 POST 计数器=transport 计数包装（POST-only 计数、逐字委托、零行为差异；transport=None 时包装 real_run._urllib_transport 只读 import）——裁定 §三"所有实际 POST 由计数器独立审计"的机械落位 | 2026-10-01 | 裁定 §三/R4.3；`_urllib_transport` 单次 urlopen 无重试亲验（L1273-1302） |
| DR-IP-0041-PV-11 | 测试矩阵 v11 定稿=**恰 25 方法**（≤26 上界；八簇全覆盖 §8.2；预算余量 1 留给机械修正弹性不预支） | 2026-10-01 | R5 ≤26；责任书 §3.1 方法预算纪律 |
| DR-IP-0041-PV-12 | Dockerfile 插入锚=L71（IP-0040 Packet COPY 行，grep -n 亲验）后，新行落 **L72**；b1_real.py 不新增打包行（benchmarks COPY L83 已覆盖） | 2026-10-01 | CA §C1 Allowed Files；DI-011 亲读 |
| DR-IP-0041-PV-13 | 孪生批准工件制备属测试 arrange（C2 文件内，PC2 经冻结 loader 接受面构造）；生产批准工件制备属 C-final/主会话（Maintainer 授权），b1_real 前相只做装载+形状/绑定执法（B1_REAL_INPUT_INVALID），不制造授权 | 2026-10-01 | R1.1"前相（批准工件制备/入口校验）"——制备分工按授权链落位；裁定 §七（批准工件=临调用门面） |

**观察项（不移交实现、不构成验收面）**：

- **OBS-1（行号复核结论）**：本会话逐锚亲核 CA §Frozen Interfaces 1-11 与 R1-R7 全部代码/测试/Dockerfile 行号（DI-005..DI-011），**零实质漂移**（含 S5=L571/L573、S6=L601、三 inspect 锚 L2427/L3928/L4007、`_select_candidate_texts` L1333、`_ATTEMPT_DOCUMENT_KEYS` L164-171、Dockerfile L71）。CA R2 附表原文行号引用（如"L897-900/L955"）中 retrieval pin 实际跨 L953-957（descriptor.get 行在 L955）——同一机制块内，无验收语义影响，以实际为准登记。
- **OBS-2**：#251 正文本会话未独立 GET（第八轮零网络授权）；需求语义经派发消息所附 create_issue_ip0041.py BODY 转录消费（DI-004）。主会话派发 C3 前如需逐字复核 AC-1..AC-5，可只读 GET 复核与本 Packet §1 映射一致性。
- **OBS-3**：timeout_seconds 门（order (3)）要求 `timeout_seconds×1000 ≤ per_run.wall_ms=1200000` ⇒ 调用方须传 ≤1200；默认 120 合法。登记供 C-final 临调用门与 C2 孪生 arrange 引用。

## 16. 已知缺口（不阻塞本 Packet；如实保留，不得消解成 0 或 measured）

- **K1 合并前告警计数无产生点**（沿 IP-0040 K1）；生产扫描器只读，raw_candidates=合并后级别。
- **K2 VEP/RVR/Mining/Repair/真人分钟**：本叶后仍 unavailable；模型层资源第三层费用（提供方账单）UNKNOWN 不默认 0。
- **K3 离线孪生证明的是入口/门/绑定行为，不是 pilot 成功贯通**；真实 pilot 终局（成功/失败）在 C-final 后才存在；`insufficient_sample` 是诚实统计态非失败；B1 真实 workload 与历史 pilot/离线 B1 分属不同 workload 不可比。
- **K4 九类 72 次不在本轮**；signal-storm pilot 不折抵九类样本；类间停止规则未裁定。
- **K5 #57 只允许在 pilot 终局后提升"B1 新入口在真实传输下贯通"一行**；PR3 不勾选；批后脱敏/封存/专家包/#57 更新（裁定 §八）随 pilot 终局另行。
- **K6 裁定 §六精确离线双证与 §七真实 pilot 均 C-final/主会话**（R6 归属预排，本 Assignment 不授权执行）。

## 17. 附录：双入口对照表（Intent Record S1 建议；便于 ER 与 M28"缺省旧路径不启用"机械核验）

| 面 | `run_b1_source_baseline_suite`（b1_source.py，IP-0040 冻结） | `run_b1_real_baseline_suite`（b1_real.py，本叶新增） |
| --- | --- | --- |
| 性质 | 独立离线入口（零模型调用） | 受审真实入口（复用冻结真实链；C1-C3 以 fake transport 孪生验证） |
| 描述子/工件键 | 无 artifact family 参与（fixture_key 参数直选 12 合成键） | 第十二键 `real-pilot/signal-storm`（16 字段；批准工件经冻结 loader） |
| 预算/门 | 零预算离线（无 BudgetLedger 门） | 七维批准工件驱动 BudgetLedger（reserve/settle/at-cap/canary/首败/截止/取消全门） |
| transport | 注入式回调（model_calls 恒 0；**禁止塞真实 callback**） | 计数包装（fake 孪生 / C-final 真实 guarded urllib）；POST-only 独立计数 |
| scanner | 每 cold attempt 重扫（b1-attempts/b1-manifest.json，model_calls=0 契约） | cold attempt-0 guarded 窗口内恰一次（E3）、warm 复用；companion b1-real-*（真实计数面，无 model_calls 键） |
| 记账/计数 | model_calls=0 常量（离线专属语义） | real_post_count/ledger_calls 如实（禁 model_calls=0/offline-proof） |
| 报告 | scanner kind（离线） | scanner kind（E4 门，真实链 order 9）+ 真实 ledger/attempts 模型观测面分立呈报 |
| 旧路径影响 | 零（冻结只读） | real_run.py E0-E4 点名 hunk；旧十一键字节等同（四层证明 §7.4） |

（Packet 完；版本 v1.0。Contract 语义变更须同步 Packet 版本与 AC。）
