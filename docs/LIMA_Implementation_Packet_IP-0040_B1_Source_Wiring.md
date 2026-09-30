# LIMA Implementation Packet — IP-0040 B1 机器来源接线（#249，离线叶，零真实调用）

- Packet ID：IP-0040；版本 v1.0（2026-09-30）。
- Coordinator Assignment：CA-IP-0040-v1.0（2026-09-30；范围权威 R1-R7，全文转录见 §15；Intent Record `.pv_tmp/INTENT_RECORD_IP-0040_2026-09-30.md`（M1-M11/F1-F9/P1-P4/Q1-Q5，裁定 SHA-256 111c161d…）由其裁定；**本 Assignment 为唯一裁定权威，本 Packet 全文转录不得改义**）。
- Source Issue：#249（open，V4-I01，2026-09-30 建，AC-1..AC-5，parent #57 保持 open；正文经 CA-IP-0040-v1.0 转录消费——本 P&V 会话按第七轮授权离线运行【零网络】，未独立 GET Issue 正文；#249 需求语义以 CA §Goal and Scope + 裁定 §四/§五 逐字为权威，AC-1..AC-5 编号消费自 CA §Authoritative Inputs #1）。
- Operating Mode：SHADOW；Execution Authorization：MAINTAINER_AUTHORIZED（2026-09-30 第七轮 B1；本轮模型 API 调用预算=0、真实 POST=0、零网络、零付费、零远端写；第六轮 5/5 已耗尽不复用；裁定文件 `.pv_tmp/ZCODE_LONG_TASK_B1_SOURCE_WIRING_RULING_2026-09-30.md` §一-§八）。
- Base SHA（完整 40 位）：`fa91085e80fe509d881bc9ce0194e86d8ecbf0c4`（= PR #248 merge；本 P&V 会话亲验 worktree HEAD 与 git status 干净）。
- 基线产物指纹（`git ls-tree fa91085e` 本 P&V 会话程序化复核，清单归档 `.pv_tmp/RED_IP-0040_2026-09-30/baseline.txt`）：real_run.py `d542c697`、report.py `e30a5f17`、run.py `d29928e5`、orchestrate.py `8655067e`、budget.py `6c783848`、collect.py `063ecb41`、expert_timing.py `dd7aa365`、offline_flow.py `0f2916c8`、fixtures.py `700ec4fc`、`__init__.py` `1c478346`；lima/repository_scanner.py `b2896a99`、workspace.py `927b27b6`、contracts/compat.py `a5870737`；三冻结测试文件 real_run `18bfb4c2`/report `86f584cb`/v5_negatives `6887f9fa`；十冻结测试文件 `4cde7bdf`/`edd4c62b`/`edb2391b`/`35e6ec6a`/`ca019d50`/`8e8ab0dcb`（manifest）/`539d2fb3`/`86f584cb`/`0a44cf7d`（result）/`6887f9fa`；Dockerfile `0ea1dd2f`；IP-0039 Packet `e796d6af`；两批准工件 `2e2473cd`/`3702c04a`；V5 来源表 `587ef5e1`；`baseline_manifest.json` `7ecb39f8`。
- 冻结前基线绿（本 P&V 会话 C0 亲跑 2026-09-30，归档 `.pv_tmp/RED_IP-0040_2026-09-30/baseline.txt` + `discover_stderr.txt`）：test_real_run **112/112 OK（111.413s）**；report+v5_negatives **47/47 OK（2.140s）**（report 38、v5_negatives 9，方法数 grep 亲数）；十冻结测试文件 **322/322 OK（39.756s）**；全量 discover **2728 OK / skipped=24（340.810s，exit 0）**——与派发预期 2728/24 逐字一致。
- 本 Packet 的角色：Implementation（阶段 C3）的唯一实现依据；冻结验收测试面（§9/§10，新文件 tests/test_v4_baseline_b1_source.py，冻结版本 v10）的唯一语义来源；P&V 独立验证（C4）的基准。

## 0. 交付物角色声明（强制，先于一切）

1. 本 Packet（本文件）与 Dockerfile 恰 +1 行 COPY 是 P&V 的 C1 交付物；**新测试文件 `tests/test_v4_baseline_b1_source.py`（v10，≤24 方法）是 P&V 的 C2 交付物（Frozen Test Commit）**；`benchmarks/v4/baseline/b1_source.py`（唯一新产品文件，公共入口 `run_b1_source_baseline_suite`）是 **Implementation 的 C3 交付物**。边界不得互换：Implementation 不得修改本 Packet/测试；P&V 不实现产品功能。
2. **零真实调用绝对禁令（本 Assignment 范围内）**：本叶全程（含分支上、CI 内、pre-merge"顺手验证"）禁止任何真实模型调用、网络下载、付费动作、真实凭据注入。模型层验证只用注入式 fake transport（§7.6）；CI 永远零付费模型请求（PC1 延续）。
3. **本叶不触发 v3 部分原生来源契约、不改 domain/report schema**（R2 判据冻结，§7.3）：report.py 冻结消费面零改动；dict payload 的 domain 整组闭集（report.py L1147-1187）**B1 不得构造**（裁定 §四(b)）。
4. **冻结面零回退**：IP-0024..0039 一切冻结面零回退；`budget.py`/`orchestrate.py`/`run.py`/`collect.py`/`expert_timing.py`/`offline_flow.py`/`report.py`/`fixtures.py`/`real_run.py`/各级 `__init__.py` 与 `lima/**` 全部只读（C3 默认零修改，例外见 §5.2）；`run_real_baseline_suite` 签名与 order 1-9、canary/首败停止门/身份允许集/预算门/estimate 常量/旧描述子/批准工件冻结。
5. **合成 fixture 的 measured 证明的是接线行为，不是九类现实验收**（裁定 §六/K3）：离线全链执行 ≠ 九类真实验收；B1 报告与历史 bounded-triage pilot 分属不同 workload，不得比较成性能/降噪改善。
6. **主会话职责（非本 PR 面；P&V/Implementation 不得代行）**：合并/推送/PR 操作/Issue 评论等一切远端写；§六任务（实际零调用 scanner 执行+专家复核包）为 C-final 阶段任务，本 Assignment 只预排归属不提前授权；#57 Delivery Ledger 与逐行矩阵更新。

## 1. 需求映射（Packet 头）

```text
Source Issue：#249（open；AC-1..AC-5；正文经 CA-IP-0040-v1.0 转录，本会话离线未独立 GET）
Issue specification revision：2026-09-30 创建版（CA §Authoritative Inputs #1；#249 无评论、Delivery Ledger 待初始化）
Covered requirements：FR-01、FR-02、FR-03、FR-04、FR-05、AC-1..AC-5（PR 面内部分）、NFR-01、NFR-02（编号规范化见下表；语义=CA §Goal and Scope+裁定 §四/§五 逐字，不改义）
Not covered requirements：任何真实模型调用/网络下载/付费动作/真实凭据注入；A 组演进（多 finding 响应契约扩展、第二模型轮、人工 domain 冒充 measured）；九类付费批；lima/** 任何修改；budget.py/预算门/estimate 常量/transport/模型身份允许集/canary/首败停止门/旧真实描述子/历史批准工件任何改动；v3 部分原生来源契约与 domain/report schema 演进（R2 判据冻结为"足够"，P2 条件授权休眠）；旧入口 run_real_baseline_suite 参数化或任何行为变化；旧 pilot 描述子复用；#57 关闭/PR3 勾选；九类真实验收宣称；VEP/RVR/Mining/Repair/真人分钟的任何 measured 宣称
Delivery role：capability-slice（B1 机器来源接线：真实本地 RepositoryScanner 输出 → 正式 B1 入口 → RunResult/报告来源投影 → 来源 receipt 可回指，全部离线零调用）
Issue closure impact：PARTIAL（IP-0040 完成 ≠ #249 完成 ≠ #57 完成 ≠ 完整 V5 Done；B1 接线完成和完整 V5 Done 分开判定）
Upstream IP/PR/merge commits：基线=IP-0039/#247 收口（PR #248 merge fa91085e，main lima-ci run 36708869915 success）；直接消费面=report.py scanner 类型路径（IP-0029 冻结）、run.py/orchestrate.py 冻结原语（IP-0027/0028）、fixtures.py 13 键注册表（IP-0030/0036）、real_run.py 冻结门（IP-0032..0039）；先例 IP-0031 offline_flow（离线套件结构）、IP-0036 v5_negatives（真实 scanner 离线探针样式）
```

| 需求（规范化） | 内容（语义=CA/裁定原文，不改义） | 本 Packet 承载 | 验收面（§9 方法） |
| --- | --- | --- | --- |
| FR-01 | 正式 B1 入口：新公共函数 `run_b1_source_baseline_suite`（新文件 b1_source.py），从全新空目录跑通到 RunResult/报告/来源 receipt；真实本地 RepositoryScanner 离线扫描合成 fixture；直接实际 scanner 输出与报告同范围计数逐值一致；sources/digest 能回指真实 payload；不能只构造一个手工 domain dict | §7.4/§7.5/§7.6 | M1、M2、M20（裁定 §五.1） |
| FR-02 | 逐字段五件事来源契约冻结（产生点/对象与计数定义/计数范围/完整性与投影规则/可回指 digest）；raw_candidates=扫描器输出 findings 数（合并去重后），合并前数=登记缺口；三态分清（有效→measured 或 legacy_projection；缺席→unavailable；无效→fail closed 不得吞成 unavailable）；不把静态 dataflow-verified 升格为动态确认 | §7.2 | M2、M6、M7、M8（裁定 §四/§五.3） |
| FR-03 | 来源 receipt 与身份绑定：attempt 文档 additive 子块 `source_receipt`（最小键集 §7.6.3）+ manifest 聚合 `source_receipts_digest`；canonical 编码+SHA-256 内容摘要绑定；读取交叉核验不符即 fail-closed typed 错误；同 snapshot 多样本计数不求和；扫描重跑 vs 复用与 snapshot/请求体/提供方缓存分别记录 | §7.6 | M13、M14、M19、M20、M5（裁定 §四/§五.2） |
| FR-04 | 边界样本与不截断：docs-content/test-heavy/signal-storm；findings>6、>12 时扫描输出不被请求构造 cap 截断；身份无关性仍过；malicious-layout 不执行仓库代码、不越界读写；dependency-blocked 如实报告缺口 | §7.7 | M9、M10、M11、M12（裁定 §五.5） |
| FR-05 | 旧路径零变化回归：旧 112 方法行为回归、旧描述子装载兼容、旧 {5,5}/shaped 路径、canary/首败门、V5 缺席纪律、CI 无 Secret/无付费回归；新增数另数 | §7.8 | M15、M16、M17、M18（裁定 §五.7） |
| AC-1 | B1 入口全链从空目录到 RunResult/报告/receipt，计数同范围逐值一致，sources/digest 回指 | §7.4-§7.6/§9 | M1+M2+M20 + C0/C4 回归 |
| AC-2 | 规范化来源字节稳定（同 snapshot/config/seed）；snapshot/analyzer-config/workload 变化→identity/digest 变化；篡改 payload/receipt/RunResult 绑定 fail closed | §7.6.4/§7.6.5 | M3、M4、M5 |
| AC-3 | 源三态（有效/缺席/无效）与真实完整零 finding vs 扫描失败/截断/解析失败可区分，后者不伪装 clean 或 measured 0 | §7.2/§7.7 | M6、M7、M8 |
| AC-4 | 只有兼容 Finding 来源时保留 legacy_projection/Hypothesis unavailable；缺 Mining/Repair 时 VEP/RVR 保持 unavailable；不能用空 bundle/零值占位绕过；cold/warm 复用与来源绑定经 fake transport 验证（3c+5w，真实 POST=0） | §7.2/§7.6/§7.6.6 | M7、M13、M14、M19 |
| AC-5 | 旧路径回归+边界样本+v10 冻结纪律（≤24 新方法、八簇、授权同步点空表） | §7.8/§9/§10 | M9-M18 + Done Commands |
| NFR-01 | 新 workload/来源语义进入 run identity：身份派生面=workload+snapshot_tree+analyzer config+seed（合法变化产生新 digest，不为跨版本同 digest 屏蔽）；B1 报告与 pilot 报告分属不同 workload 不可比 | §7.6.4 | M3、M4 |
| NFR-02 | 全部扫描调用显式离线配置：禁 LLM/platform/网络下载/会执行仓库代码的验证路径；不依赖环境变量默认值；stdlib+冻结上游模块；secretless；零环境读 | §7.5 | M1（离线配置文档断言）、M11、M17（PC1） |

**Not-covered（全团队不得扩张）**：见上文 Not covered requirements 段与 §12 Stop Conditions（= CA §Not covered 全部七项）。

## 2. Design Input Manifest

| # | 输入 | 类型/版本/位置 | 消费方式 | Authority |
| --- | --- | --- | --- | --- |
| DI-001 | CA-IP-0040-v1.0 | `.pv_tmp/COORDINATOR_ASSIGNMENT_IP-0040_2026-09-30.md`（2026-09-30） | 范围权威；R1-R7 全文转录见 §15；本 Packet 逐条承载 | normative |
| DI-002 | Intent Record IR-IP-0040-B1-SOURCE-WIRING-2026-09-30 | `.pv_tmp/INTENT_RECORD_IP-0040_2026-09-30.md`（M1-M11/F1-F9/P1-P4/Q1-Q5） | 授权语义（B1 路线/A 组冻结/五件事/raw_candidates 级别/三态 fail-closed/receipt 入证据链/lima 只读）；F1-F9 决定性事实全部经本会话代码亲核（见 DI-005..DI-011） | normative（经 Assignment 消费） |
| DI-003 | 第七轮裁定（Maintainer 采纳稿） | `.pv_tmp/ZCODE_LONG_TASK_B1_SOURCE_WIRING_RULING_2026-09-30.md` §一-§八 | §0/§7/§8/§12 的授权依据；§四两项关键事实与 §五七项验收清单逐字转录（§7.1/§8） | normative |
| DI-004 | Source Issue #249 | open，V4-I01，2026-09-30 建，AC-1..AC-5，parent #57（经 CA 转录；本会话零网络未独立 GET） | 需求语义经 CA §Goal and Scope+裁定 §四/§五 消费（FR-01..05 规范化不改义） | normative（经 Assignment 转录） |
| DI-005 | benchmarks/v4/baseline/report.py @fa91085e | blob `e30a5f17`（本会话亲读：L86-88 schema v2；L114-122 `_COUNT_KEYS` 七键；L125-126 `_PROJECTIONS`/`_SOURCE_KINDS`；L130-139 `_CHAIN_FIELDS` 六键+`_RATIO_LINK_FIELDS`；L182-192 `_COVERAGE_AFFECTING_SKIPS` 7 类；L201-206 `_VERIFICATION_STATES` 五态+三分区；L962-988 `_gate_summary`（isinstance BaselineRunSummary+aggregate digest 交叉核验）；L1069-1095 `_recognize_evaluator_payload`（scanner=dict 判 `report`/`inventory` 属性）；L1098-1144 `_validate_scanner_payload`（findings list[Finding]+五态词表+collaboration.scanned_files/skipped+inventory.to_dict callable）；L1147-1187 `_validated_domain_block`（六键整组闭集）；L1190-1206 `_fingerprint`（sorted-key 紧凑 UTF-8 JSON+SHA-256）；L1209-1218 `_skip_face`；L1221-1241 `_ratio_link`（floor bp、分母 0→ratio null）；L1298-1344 scanner 分支（逐字段产生点）；L1395-1433 evidence_domain/vep/rvr/stage/resources 面；L1435-1487 文档组装+`_freeze_document`） | §7.2 逐字段五件事的逐行依据；词表边界（9 态 vs 5 态） | current-behavior（冻结消费面，只读） |
| DI-006 | lima/repository_scanner.py @fa91085e | blob `b2896a99`（本会话亲读：L52-65 `VERIFICATION_RANK` 九态；L73-81 `COVERAGE_AFFECTING_SKIPS`；L108-115 `RepositoryScanResult{report,inventory}`+`to_dict`；L170-172 `_semantic_key=(path,line,cwe or rule_id)`；L174-214 `_merge_finding`（合并去重+状态 max-rank 升格）；L606-851 `scan`（inventory→dataflow→逐文件 AST/规则→SAST→cxx→platform→合并排序→ReviewReport.collaboration L822-848：scanned_files=len(inventory.files)、workspace_truncated、parse_errors 计数、skipped 排序）） | §7.2 raw_candidates 合并后级别（F3）；§7.5 离线禁用清单；malicious-layout 不执行依据（全部路径静态） | current-behavior（只读事实） |
| DI-007 | lima/workspace.py @fa91085e | blob `927b27b6`（亲读：L57-106 `WorkspaceInventory`（fingerprint=逐文件 path/size/sha256 排序摘要；to_dict 十键含 truncated）；L109-138 `RepositoryWorkspace`（max_files=5000/max_file_bytes=512KiB/max_total_bytes=20MiB 默认，构造参数显式）；L168-260 inventory walk+skip 分类） | §7.2 inventory 边界披露（workspace_truncated/解析失败/非 Python 跳过/依赖不可用） | current-behavior（只读事实） |
| DI-008 | lima/contracts/compat.py @fa91085e | blob `a5870737`（亲读：L170-230 `finding_to_domain_bundle`：1 Finding→1 Signal+1 SecurityIssue+EvidenceRecord(D0/SUPPORTS/LEGACY_MIGRATED)；验证阶梯不进投影） | §7.2 signals/security_issues=legacy_projection 的计数定义（每 finding 恰 1+1） | current-behavior（只读事实） |
| DI-009 | benchmarks/v4/baseline/{run,orchestrate,offline_flow}.py @fa91085e | blobs `d29928e5`/`8655067e`/`0f2916c8`（亲读：run.py L226-331 `run_baseline_attempt`（门序+Exception 体捕获→失败样本持久化→返回；write_result_file L170-223 互斥命名）；orchestrate.py L145-154 `BaselineRunSummary`、L220-305 `run_repeats`（对称 N cold+N warm→from_mapping 聚合）；offline_flow.py L288-378 `run_offline_baseline_suite`（离线套件结构先例：fixture 物化→guarded evaluator→run_repeats→marker→report）） | §7.6 入口组合裁定（B1 自有 attempt 循环复用 run_baseline_attempt/from_mapping/write_result_file，见 DR-IP-0040-PV-2） | current-behavior（冻结原语，只读） |
| DI-010 | benchmarks/v4/baseline/fixtures.py @fa91085e | blob `700ec4fc`（亲读：L101-117 `SYNTHETIC_FIXTURE_KEYS` 13 键含 archetype/{docs-content,test-heavy,signal-storm,malicious-layout,dependency-blocked}；L712-725 `compute_tree_fingerprint`（相对路径排序内容摘要——跨 tempdir 稳定）；L775-796 `materialize_fixture`/`verify_fixture`；L846-869 注册表条目） | §7.6 快照物化与 snapshot_tree_sha256 确定性；§7.7 边界样本 | current-behavior（只读消费） |
| DI-011 | benchmarks/v4/baseline/real_run.py @fa91085e | blob `d542c697`（亲读：L2723-2734 `run_real_baseline_suite` 签名（旧测试 inspect.signature 钉死）；L1517-1545 `build_payload`（real-world v2 `llm-bounded-triage`，无 domain）；L2494-2573 `_build_manifest_document`；L2576-2630 五件套证据） | §7.8 旧路径零变化锚；不复用 pilot 描述子依据 | current-behavior（冻结面，只读） |
| DI-012 | lima/baseline_run_spec.py + lima/baseline_run_result.py @fa91085e | spec：七顶层字段闭集（repositories/datasets/analyzer_fingerprint/config_digest/seed/machine_profile），fingerprint=64-hex、seed=int64；result：**至少 3 cold+5 warm 成功才 sufficient_sample**（docstring 亲读） | §7.6.4 身份派生面（经既有 config_digest/analyzer_fingerprint/seed 面，零 schema 改动）；3c+5w 形状依据 | current-behavior（只读） |
| DI-013 | 三冻结测试文件 @fa91085e | test_v4_baseline_real_run.py `18bfb4c2`（112 方法；L2425-2432/L3927-3931/L4006-4009 inspect.signature 锚亲读）；test_v4_baseline_report.py `86f584cb`（38 方法；`_scan_payload` arrange L286-303、`_scanner_payload_digest` L399-401 亲读）；test_v4_baseline_v5_negatives.py `6887f9fa`（9 方法；`_scan_findings` 真实 scanner 离线探针 L156-160、CANDIDATE_FILE_CAP 探针 L349-369 亲读） | §7.8 旧路径锚；§9 新文件 arrange 样式先例 | current-behavior（冻结面，零修改） |
| DI-014 | C0 基线实测 | `.pv_tmp/RED_IP-0040_2026-09-30/baseline.txt`+`discover_stderr.txt`（本会话 2026-09-30 亲跑：112/47/322 全绿；discover 2728 OK skipped=24 exit 0） | §10 条件 5 基线态证明 | evidence |
| DI-015 | worktree/分支 | `D:\BaseAIProject\LIMA-ip-0040-wt`，分支 `codex/ip-0040-b1-wiring` @fa91085e（本会话 `git rev-parse HEAD`+`status --short` 亲验=干净） | §5.5 提交链拓扑落位 | evidence |
| DI-016 | Dockerfile @fa91085e | blob `0ea1dd2f`（亲读：L70=IP-0039 Packet COPY 行=本叶恰 +1 行插入位；**L83 存在 `COPY --chown=lima:lima benchmarks ./benchmarks`——与 CA §Workspace"不含 benchmarks/"的括注字面不符，见 OBS-1**） | C1 +1 行落位依据 | current-behavior |

事实优先级冲突处理：CA-IP-0040-v1.0 与裁定原文冲突时以 CA 为准并提交 Decision Request（Stop 14）；代码事实与 CA 锚不一致时如实登记（OBS）不自行改义。

## 3. Explicitly Rejected Inputs

| # | 被拒输入 | 拒绝理由 |
| --- | --- | --- |
| 1 | v3 部分原生来源契约 / domain/report schema 演进（部分字段 native measured） | R2 判据冻结：scanner 类型路径足够实现本叶全部目标字段（判据与触发条件登记见 §7.3）；P2 条件授权休眠。dict domain 整组闭集会强制 vep/rvr/hypotheses 一并 measured（裁定 §四(b)） |
| 2 | 修改生产扫描器强造"合并前告警数"采集面 | 裁定 §四：拿不到合并前数就保留缺口（K1）；lima/** 只读（Stop 2） |
| 3 | 参数化旧入口 `run_real_baseline_suite` 承载 B1 | R3：旧入口签名被 inspect.signature 钉死；新入口使"旧调用点零 diff"退化为 real_run.py 零修改即可证 |
| 4 | 复用旧 pilot 描述子或其授权承载 B1 workload | R3/裁定 §四：B1 用合成 fixture 快照、零预算离线 workload；新 workload 静默用于原有批准工件=禁区 |
| 5 | 把静态 dataflow-verified 升格为动态确认；一个 Finding/候选文件/is_vulnerable=true 直接等同 root-cause Issue/Hypothesis | 裁定 §二/§四：deterministic_alerts 沿既有 verification_state 语义；不得伪测量 |
| 6 | 填 vep=0/rvr=0/伪造 stage_outcome/空 bundle 零值占位通过校验 | 裁定 §四(b)：domain 整组闭集不能表达"只有扫描计数"；B1 不得构造该块（Stop 条件） |
| 7 | 覆盖 inventory 内文件写成"无限制全仓扫描"；不同范围数字相除 | 裁定 §四：inventory 文件/字节/条目边界、workspace_truncated、解析失败、非 Python 跳过、依赖不可用全部披露 |
| 8 | 同一 snapshot 8 个样本求和成 8 倍漏洞数量 | 裁定 §四：样本与计数聚合规则冻结前确定（§7.6.7：不求和） |
| 9 | 让仓库名决定漏洞判定（identity 超出校验/获取/去重/呈报用途） | 裁定 §四：身份无关性（M10） |
| 10 | fake transport 次数写成真实调用；离线全链执行当九类真实验收 | 裁定 §五.6/§六：不让 fake 的次数写成真实调用；K3 |
| 11 | 依赖环境变量默认值的扫描配置；启用网络/LLM/platform/会执行仓库代码的验证路径 | 裁定 §三/§五；CA Stop（§12 绝对停五条之五） |
| 12 | 需 findings 截断/请求构造 cap 才能通过；报告候选文件数与全扫描 findings 数混用 | 裁定 §四/§五.5：cap 是请求构造参数（CANDIDATE_FILE_CAP=12），报告计数必须全范围 |
| 13 | 独立推进 R1 再拆分（两叶） | R1 裁定单叶；触发条件（a)(b)(c) 未命中即不拆（命中即停并上报） |
| 14 | 触碰 sealed 目录（`D:\BaseAIProject\LIMA-real-runs\**`）；按 ledger 值补旧报告 resources 缺口 | 裁定 §六/CA Stop：封存树零写入；历史 pilot usage 只是其原 workload 的封存事实 |
| 15 | `docs/LIMA_PR3e_V5_Field_Source_Table.md` 的 B1 行（"raw_candidates 语义从'有界候选文件数'迁移；real_run 入口编排扩展（扫描轮+triage 轮）"）作为本叶实现依据 | 该行为历史规划快照（v3 方向）：本叶 R2 判据冻结为 scanner 类型路径+新入口，real_run.py 零修改、报告 schema 零改动；历史表按"新版本说明 supersedes"处理（裁定 §七），不原地删改 |

## 4. Goal / Non-goals

**Goal**：在 IP-0039 版产品（main=fa91085e）上把现有本地 `RepositoryScanner` 的真实输出接入正式 B1 入口，形成"真实扫描器输出 → evaluator payload → RunResult/报告来源投影 → 来源 receipt 可回指"的离线零调用全链：新增唯一产品文件 `benchmarks/v4/baseline/b1_source.py`（公共入口 `run_b1_source_baseline_suite`，§7.6 契约），V5 字段按 measured / legacy_projection / unavailable 三态如实投影（§7.2 逐字段五件事），来源 receipt 经 attempt 文档 additive 子块+manifest 聚合入证据链与身份派生面（§7.6.3-§7.6.5），报告与历史 bounded-triage pilot 分属不同 workload 不可比（NFR-01）。全部离线：零真实调用、零网络、零付费、CI 零付费模型请求。

**Non-goals**：见 §1 Not-covered（CA 原文）。真实扫描执行+专家复核包= C-final 阶段（§六任务，主会话授权下）；合并/推送/远端写、#57 Ledger 更新不在本 Assignment 授权内。

## 5. 文件边界（CA R6：C1 恰 1 Add+1 Modify；C2 恰 1 Add；C3 恰 1 Add；零 Delete；单 PR `codex/ip-0040-b1-wiring` → main）

### 5.1 Files to Add

| 文件 | Owner/阶段 | 说明 |
| --- | --- | --- |
| `docs/LIMA_Implementation_Packet_IP-0040_B1_Source_Wiring.md` | P&V（C1，本文件） | 本 Packet；承载 CA R1-R7 全部裁定+逐字段五件事来源契约（§7.2）+取舍判据冻结（§7.3）+B1 入口契约（§7.6）+七项验收清单（§8）+测试矩阵 v10（§9）+六条件演进与空授权同步表（§10）+K 缺口（§17）+P&V 定稿决策（§16） |
| `tests/test_v4_baseline_b1_source.py` | P&V（C2，冻结 v10） | B1 验收面新测试文件（≤24 方法八簇，§9）；不动 v9' 112/38/9 任何旧方法 |
| `benchmarks/v4/baseline/b1_source.py` | Implementation（C3） | 唯一新产品文件；公共入口 `run_b1_source_baseline_suite`（§7.6 契约）；离线/secretless/stdlib+冻结上游模块只读 import |

### 5.2 Files Allowed to Modify

| 文件 | Owner/阶段 | 边界 |
| --- | --- | --- |
| `Dockerfile` | P&V（C1，与 Packet 同一提交） | **恰 +1 行**：`COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0040_B1_Source_Wiring.md ./docs/`（插 L70 IP-0039 Packet COPY 行后）；既有行零改动。基线 blob `0ea1dd2f3353beacb7ff81dd352f0a9b9af4adc1` |

**C3 产品边界（预裁定，本 Assignment 不授权执行）**：`benchmarks/v4/baseline/{real_run,report,run,orchestrate,fixtures,budget,collect,expert_timing,offline_flow,__init__}.py` 与 `lima/**` 只读 import，**零修改为默认**；任何例外必须 additive-only、Packet 点名、逐项登记，且不得触及公共签名或冻结行为（R3）。本 Packet **不点名任何例外**（预期 C3 全部落在新文件 b1_source.py 内）。测试/fixture 文件只读（C2 后）。

### 5.3 Read-only Reference Files（只读消费）

`benchmarks/v4/baseline/` 全部既有模块与各级 `__init__.py`（冻结原语 `run_baseline_attempt`/`write_result_file`/`result_from_mapping`/`BaselineRunSummary`/`build_baseline_report`/`write_report_file`/`materialize_fixture`/`load_registry`/`compute_tree_fingerprint`/`canonical_encode`/`compute_content_digest` 只读消费）；`lima/**`（RepositoryScanner/RepositoryWorkspace/WorkspaceInventory/RepositoryScanResult/Finding/ReviewReport/finding_to_domain_bundle）；`evaluation_data/v4/baseline_manifest.json`；IP-0024..0039 Packet、两份批准工件、V5 来源表、决策包、裁定文件；`.pv_tmp/` 各记录。

### 5.4 Files Forbidden（diff 必空；Done Command 6/7 逐 blob 守护）

`benchmarks/v4/baseline/` 既有全部模块与各级 `__init__.py`（C3 前）；`tests/` 其余全部既有文件（**含 v9' 三冻结测试文件 112/38/9——本叶授权同步点表为空，零触碰**）；`lima/**`（绝对）；`evaluation_data/**`；`scripts/**`；`docs/` 其余全部（含历史 Packet/批准工件/V5 表）；`pyproject.toml`/`requirements.txt`/`.github/**`/`.gitignore`/`.gitattributes`/前端；`.pv_tmp/**` 不提交（RED 日志仅存 `.pv_tmp/RED_IP-0040_2026-09-30/`）。

### 5.5 提交链拓扑（CA §Handoff；冻结）

C1 = 本 Packet + Dockerfile 恰 1 行（1 Add + 1 Modify，同一提交，前缀 `[IP-0040][PV]`）→ C2 = tests/test_v4_baseline_b1_source.py 新文件落定（1 Add；**Frozen Test Commit**；提交信息逐字 `[IP-0040][PV] Freeze acceptance tests v10 (RED)`；RED 证据先于冻结落盘并独立日志归档 `.pv_tmp/RED_IP-0040_2026-09-30/`；冻结基线=main 上 C1 合并后 SHA）→ C3 = b1_source.py（1 Add，前缀 `[IP-0040][IMPL]`；必须以 C2 为祖先）→ C4（P&V 独立验证+PR；如触发 ALLOWED_ONCE/修复提交须引用编号）。单 PR；不 push（合并/推送/评论由主会话按 Maintainer 授权执行，P&V/IMPL 零远端写）。

### 5.6 与其他活动 IP 的冲突分析

无并行活动 IP 占用本切片路径（IP-0040 编号未占用，CA §Authoritative Inputs）。本叶不触碰任何其他 IP 的演进对象：v9' 三冻结测试文件零触碰（授权同步点表=空，§10）；real_run.py/report.py 等全部既有模块零修改（C3 全部落在新文件）。**本叶无冻结面演进**（新文件承载全部验收面；历史文档零改动）。

## 6. 依赖、网络、文件系统与权限边界

- **依赖**：零新增第三方依赖；b1_source.py 只 import stdlib+冻结上游模块（benchmarks.v4.baseline.{run,orchestrate,report,fixtures,budget?} 与 lima.{workspace,repository_scanner,models,contracts.codec,contracts.compat,baseline_run_spec,baseline_run_result}——最终 import 清单由 C3 在此集合内落定，零新第三方）。测试文件零新增第三方 import（unittest/tempfile/pathlib/json/hashlib 等 stdlib+冻结上游）。
- **网络**：全离线；本叶全程任何真实网络/下载/付费调用/真实凭据注入=Stop（绝对停）。CI 零付费模型请求（PC1）。
- **文件系统**：证据文件只写调用方提供的空输出目录（测试写 tempdir）；快照物化入内部临时工作区（**绝不写 output_dir**，offline_flow 先例）；sealed 目录（`D:\BaseAIProject\LIMA-real-runs\**`）只读零写入；不读环境变量/配置/.env。
- **数据库/容器/远端写**：无数据库；容器面仅 Dockerfile +1 COPY 行（Packet 文档）；零远端写（不 push、不开 PR、不关 Issue、不改 Ledger 远端状态）。
- **凭据**：B1 入口无 api_key 参数（零模型调用 workload）；永不注入真实凭据；fake transport 为纯注入对象。
- **clock**：默认真实 platform sources 的 wall/cpu 读数只进样本计时面（与 offline_flow 同纪律）；计数/digest/身份面零时钟依赖、零真实 sleep。

## 7. 实现契约细化（Packet 定稿；R2/R3/R4 落位）

### 7.1 冻结数据流（裁定 §四"沿实际数据流逐字段调查"的落位）

```text
合成 fixture（fixtures.py 13 键注册表，materialize_fixture → 内部临时工作区）
  → RepositoryWorkspace(root, 显式 limits)                       [lima/workspace.py]
  → workspace.inventory() = WorkspaceInventory                   [truncated/skipped/边界]
  → RepositoryScanner(显式离线配置, §7.5).scan(workspace)         [lima/repository_scanner.py]
      findings 以 (path, line, cwe or rule_id) 语义键合并去重（L170-214）
  → RepositoryScanResult{report: ReviewReport, inventory}        [evaluator payload 对象]
  → finding_to_domain_bundle 兼容转换（1 Finding → 1 Signal + 1 SecurityIssue, D0/SUPPORTS/LEGACY_MIGRATED）
  → build_baseline_report(summary, evaluator_payload=RepositoryScanResult)  [report.py kind="scanner" 分支]
  → BaselineReport（counts/compression_chain/coverage/sources 三态投影）
  → write_report_file / write_result_file（RunResult 聚合经冻结 from_mapping）
  → sources digest = _fingerprint({**report.to_dict(), "workspace": inventory.to_dict()})   [可回指]
  → 每 attempt 来源 receipt（§7.6.3）→ b1-manifest 聚合 → 身份派生面（§7.6.4）
```

### 7.2 逐字段来源契约（裁定 §四"五件事"逐字段冻结）

**通用计数范围原则（A3）**：下列每一字段的分子分母同 snapshot（同一物化快照树）、同 analyzer+config（同一离线配置文档 digest）、同 seed；分母为 0 沿 `_ratio_link` 冻结规则（保留计数、ratio null 非 0）。报告候选文件数（≤CANDIDATE_FILE_CAP=12 请求构造参数）、模型复核数、全扫描 findings 数**分别登记、不得混用或相除**。

**通用三态规则（FR-02/AC-3）**：source 有效→该字段的冻结投影（measured 或 legacy_projection）；source 缺席→honest null+unavailable；source 在场但 malformed（非 Finding 对象/词表外状态/契约键缺失/digest 不符/绑定不符）→**fail closed**（EVALUATOR_PAYLOAD_INVALID / B1 typed 错误），不得吞成 unavailable。

| 字段 | ①产生点（report.py 行锚，本会话亲读） | ②对象与计数定义 | ③计数范围 | ④完整性与投影 | ⑤可回指 digest |
| --- | --- | --- | --- | --- | --- |
| `compression_chain.raw_candidates` | L1309 `raw_candidates = len(findings)`（findings=evaluator_payload.report.findings） | **扫描器输出 findings 数（合并去重后级别）**：RepositoryScanner 已按 `(path,line,cwe or rule_id)` 语义键合并（scanner L170-214），len 为合并后条目数；**合并前告警数无产生点=登记缺口 K1，不得强造采集面** | 同 snapshot/analyzer/config/seed 的全 findings | 有效→整数值（int，scanner 路径永非 None）；无效→fail closed；缺席（非 scanner 路径）→null | sources scanner digest（下行⑤规则）可复算回指该计数 |
| `compression_chain.deterministic_alerts` | L1310-1312 `sum(1 for state in states if state in _DETERMINISTIC_STATES)` | 状态 ∈ {corroborated, dataflow-verified, confirmed} 的 findings 数（L206 `_DETERMINISTIC_STATES`） | 同上 | 同上；**不把静态 dataflow-verified 升格为动态确认**（语义沿 scanner verification_state，不重解释） | 同上 |
| `compression_chain.confirmed` | L1313 `sum(1 for state in states if state == "confirmed")` | 状态 == "confirmed"（唯一确认态，L205） | 同上 | 同上 | 同上 |
| `compression_chain.inconclusive` | L1314-1316 `sum(1 for state in states if state in _INCONCLUSIVE_STATES)` | 状态 ∈ {candidate, syntax-verified}（L204，"提出但从未被佐证"） | 同上 | 同上 | 同上 |
| 分区不变量 | L199-200 注释冻结 | `raw_candidates == deterministic_alerts + inconclusive`（三分区互斥穷尽） | 同上 | M2/M7 断言 | — |
| `compression_chain.candidates_to_deterministic` / `deterministic_to_confirmed` | L1461-1466 `_ratio_link(deterministic_alerts, raw_candidates)` / `_ratio_link(chain_confirmed, deterministic_alerts)`；实现 L1221-1241 | floor 基点（`numerator*10000//denominator`）；**分母 0→两计数保留、ratio null（绝不 0）**；任一缺席→全 null 三键 | 与对应计数严格同范围同分母 | 同上 | 同上 |
| `counts.scanned_files` | L1317 `report.collaboration["scanned_files"]`；产生=scanner L824 `len(inventory.files)` | inventory 内实际纳入扫描的文件数（**"覆盖 inventory 内的文件"≠无限制全仓扫描**，见 coverage_gap 与 workspace 边界披露） | 同 snapshot 的 inventory | 有效→(int, **measured**)；collaboration 缺键/类型错→fail closed（L1123-1128） | 同上 |
| `counts.coverage_gap` + `coverage_gap_reasons` | L1318 `_skip_face(report.collaboration["skipped"])`；实现 L1209-218 | 7 类 coverage-affecting skips（L182-192：symlink/unreadable/file-size-limit/file-limit/total-size-limit/binary/non-utf8）计数和 + 逐 reason 计数（sorted；ignored-directory/unsupported-extension 属既定扫描范围不算覆盖损失——scanner L70-72 冻结决策） | 同上 | 有效→(int, **measured**)+reasons dict；非 int/负数→fail closed | 同上 |
| `counts.signals` / `counts.security_issues` | L1302-1307/L1330-1334（无 bundle 分支）：`sum(len(finding_to_domain_bundle(f).signals/.security_issues) for f in findings)`；compat L170+ | 每 Finding 经兼容转换恰 1 Signal + 1 SecurityIssue（EvidenceLevel.D0、Polarity.SUPPORTS、LEGACY_REASON_CODE="LEGACY_MIGRATED"；验证阶梯不进投影）→计数==len(findings) | 同上 | 有效→(int, **legacy_projection**)——legacy Finding 兼容转换**必须保留 legacy_projection，不得标 measured**；缺席→null+unavailable | 同上（bundle is None 为 B1 恒定条件——B1 不构造 bundle/domain） |
| `counts.hypotheses` | L1335 `(None, "unavailable")`（无 bundle） | 扫描器 Finding 路径**无 Hypothesis 产生点**；不得以 0 冒充 | — | 缺席→null+**unavailable**（不得用空 bundle/零值占位绕过） | — |
| `vep` / `rvr` / `stage_outcome` | L1425-1428（domain is None 分支）：`(None,"unavailable")`×2 + 三 stage 全 (None,"unavailable") | 未执行 Mining/Repair→无产生点；**未执行≠完整观测零产出，不得报 measured 0** | — | 缺席→null+**unavailable**；唯一例外=确实执行且完整观测到零产出（本叶不存在该情形） | — |
| `resources`（prompt_tokens/completion_tokens/cost_micro_usd） | L1429-1433 domain 缺席分支 | 本叶模型调用=0；提供方账单/第三层费用缺失 | — | 全 null+unavailable（**不默认 0**；模型使用为 0 必须有禁用配置+零调用证据=M13/M17，数值本身不写 0 占位） | — |
| `expert`（active_time_ms_total/sessions/reviewer_digests） | L1399-1405/L1468-1472 | 无真人事件：sessions=len(sidecars)=0、active_time null、digests [] | — | 缺席→honest null/0/[]（sessions=0 是"零真人事件"的诚实计数，非 measured 冒充） | — |
| `evidence_domain` / `legacy_projection` | L1395 `evidence_domain = "v2" if bundle is not None else "legacy"`；L1443 | bundle 恒 None→"legacy"/True | — | 如实 | — |
| `sources[].{kind:"scanner", payload_sha256}` | L1340-1344：wire=`{**report.to_dict(), "workspace": inventory.to_dict()}`；`_fingerprint(wire)`（sorted-key 紧凑 UTF-8 JSON→SHA-256，L1190-1206） | 来源指纹=整个 scanner wire payload 的规范化字节摘要 | 同 snapshot 全量 | **可回指**：同 payload 重算必等值（M1/M3）；与 receipt `scanner_payload_sha256` 交叉核验（M20） | 即本列 |
| `run_spec_digest`/`aggregate_sha256`/`attempt_count`/`automation.*` | L1438/L271-1272 聚合面 | RunSpec/RunResult 聚合身份（3c+5w→sufficient_sample） | 全 attempts | 经冻结 BaselineRunSummary 门（L962-988） | aggregate.content_digest |

### 7.3 两项关键事实与取舍判据冻结（R2；裁定 §四(a)(b) 逐字承载）

**(a)** report.py 已有 scanner payload 路径（L1098-1144 深校验；L1298-1344 投影），能消费真实 `RepositoryScanResult`，产生扫描文件/coverage gap/raw_candidates/确定性分级及压缩链；Signal/Issue 的 Finding 兼容转换默认是 legacy_projection，Hypothesis 没有来源时 unavailable。**优先复用这条真实类型路径，不为了显示 measured 注入人工构造的 EvidenceDomainBundle。**

**(b)** 当前 dict payload 的 domain 是整组闭集（L1147-1187）：signals/security_issues/hypotheses/vep/rvr 为非负整数，stage_outcome 三键齐全；合规 domain 会将整组阶段字段投影为 measured。它不能直接表达"只已有扫描计数，Mining/Repair 缺席"。**因此不得填 vep=0/rvr=0 或伪造 stage_outcome 来通过校验。如果 scanner 类型路径足够实现本叶目标，保持 domain/report schema 不动**；确需部分原生来源时，新增版本区分的部分来源契约及相应投影，只提升有来源的字段，保持旧 v2 domain 的严格校验及旧默认输出语义（=R2 休眠授权）。

**取舍判据冻结（R2 逐字）**：本叶全部目标字段可在 `RepositoryScanner.scan → RepositoryScanResult → build_baseline_report(kind="scanner")` 路径上推导——raw_candidates=len(findings)（合并后）、确定性分级沿五态闭集、scanned_files/coverage_gap measured、压缩链同范围同分母规则、来源 digest=_fingerprint(report+inventory)、signals/security_issues legacy_projection、hypotheses/vep/rvr/stage_outcome null+unavailable。**结论：domain/report schema 零改动；report.py 冻结消费面零改动；P2 条件授权休眠**。再演进触发条件（=R1(a)(b)(c)，命中任一即停止单叶推进并按 Maintainer 预授权上报）：(a) 某 mandatory 报告字段在 scanner 对象路径上无任何可加性推导；(b) 出现必须"部分字段 native measured"的语义需求；(c) 需求的计数级别不同于合并后 findings 级别且无法以登记缺口如实披露。

**词表边界（F4，冻结）**：scanner `VERIFICATION_RANK` 九态 {candidate, syntax-verified, corroborated, tool-corroborated, dataflow-verified, build-verified, fact-verified, runtime-confirmed, confirmed}（scanner L52-65）vs report 冻结 `_VERIFICATION_STATES` **五态闭集** {candidate, syntax-verified, corroborated, dataflow-verified, confirmed}（report L201-203）。**本叶离线配置发射 ⊆ {candidate, syntax-verified, corroborated, dataflow-verified} ⊂ 冻结五态**；任何超出冻结五态的状态（tool-corroborated/build-verified/fact-verified/runtime-confirmed）到达报告→report L1112-1117 fail closed（EVALUATOR_PAYLOAD_INVALID），不吞成 unavailable。离线禁用清单（§7.5）正是使该不变量成立的机械保证（SAST/cxx/platform/LLM 全关后仅 AST/规则/静态 dataflow 路径可发射）。

### 7.4 B1 入口契约：签名与结果类型（R3）

新文件 `benchmarks/v4/baseline/b1_source.py`，公共入口（全部 keyword-only；`__all__` 至少含 `run_b1_source_baseline_suite` 与读取核验入口 `verify_b1_evidence`，最终清单由 C3 冻结登记）：

```python
def run_b1_source_baseline_suite(
    *,
    output_dir: str | pathlib.Path,
    machine_profile: object,                                   # 必填，显式传入（不读环境）
    fixture_key: str = "archetype/minimal-python-repository",  # 13 键注册表内合成键
    seed: int = 0,
    cold_count: int = 3,                                       # 正 int；3=最小充分门
    warm_count: int = 5,                                       # 正 int；5=充分门
    workload: str = "b1-offline-scanner-v1",                   # B1_WORKLOAD 冻结常量默认值
    transport: typing.Callable[[dict], dict] | None = None,    # 注入式 fake transport（§7.6.6）
    manifest_path: str | pathlib.Path | None = None,           # 冻结默认 manifest
    sources: object = None,                                    # PlatformSources 注入缝
) -> "B1SuiteResult"
```

- `output_dir` 必须**已存在且为空目录**，否则 typed 错误 `B1_OUTPUT_NOT_EMPTY`（一次性证据目录纪律；测试用 tempdir）。
- `machine_profile` 必填（无默认、无环境读）：进入 spec 七字段闭集的 machine_profile 面。
- `fixture_key` 必须是 `SYNTHETIC_FIXTURE_KEYS` 内合成键（13 键；外部键→冻结 fixtures 错误透传）；物化入**内部临时工作区**（绝不写 output_dir）。
- `seed`/`cold_count`/`warm_count`/`workload` 为身份与形状面（§7.6.4）；cold_count≥1、warm_count≥1（非正 int→typed 拒绝）。
- `B1SuiteResult`（frozen dataclass，slots）：`run_spec_digest`、`attempt_count`、`status`、`result_paths`（tuple）、`aggregate_path`、`aggregate_sha256`、`report_path`、`report_sha256`、`manifest_path`、`manifest_sha256`、`source_receipts_digest`、`fixture_key`、`snapshot_tree_sha256`、`scanner_config_sha256`、`scanner_payload_sha256`、`workload`、`scanner_executions`（int 计数）、`transport_calls`（int 计数）、`model_calls`（**常量 0**）、`b1`（**常量 True**，与 OfflineSuiteResult.synthetic/RealSuiteResult.real_run 同款判别纪律）。
- 有效 spec 的 repositories/datasets 面取自加载的冻结 manifest（默认 `evaluation_data/v4/baseline_manifest.json`）；三身份面（analyzer_fingerprint/config_digest/seed）由入口**确定性派生**（§7.6.4），不从调用者抄袭。

### 7.5 离线配置显式禁用清单（NFR-02；裁定 §三"明确的离线配置"逐字承载）

`RepositoryScanner` 构造**显式传参**（绝不依赖任何默认值与环境变量）：

| 构造参数 | 冻结值 | 禁用对象 |
| --- | --- | --- |
| `sast_mode` | `"off"` | SAST 引擎（BanditAdapter 等，工具佐证态 tool-corroborated 产生面） |
| `sast_adapters` | `[]`（空列表，显式） | 同上（适配器实例零构造） |
| `cxx_memory_mode` | `"off"` | C/C++ 内存分析（build-verified/fact-verified 产生面） |
| `cxx_memory_adapter` | `None`（显式） | 同上 |
| `cxx_agent_mode` | `"off"` | 平台智能体链（runtime-confirmed 产生面；会执行仓库代码的验证路径） |
| `cxx_agent_budget_factory` | `None`（显式） | 同上 |
| `cxx_uaf_llm_factory` | `None`（显式） | 平台 LLM（零 LLM 调用） |
| `dataflow_enabled` | `True`（静态跨文件数据流，纯本地 AST，离线安全） | —（其产出 dataflow-verified ∈ 冻结五态） |
| `reviewers` | 默认 `SecurityRuleReviewer()`（显式构造传入） | — |
| `should_cancel` | `None` | — |

`RepositoryWorkspace` 构造显式传 limits（`max_files=5000`、`max_file_bytes=512*1024`、`max_total_bytes=20*1024*1024`——数值即冻结默认值但**显式传入**），extensions/ignored_directories 用冻结默认。**禁 LLM、禁 platform、禁网络下载、禁会执行仓库代码的验证路径、零环境读、零凭据**。完整 config 文档（含本清单与 workload/fixture_key/snapshot_tree_sha256/seed/cold/warm）canonical 编码入 b1-manifest（§7.6.3），其 SHA-256=`scanner_config_sha256`。

### 7.6 来源 receipt、身份派生与 cold/warm 语义（R4/NFR-01/裁定 §四）

#### 7.6.1 执行序（冻结；任一步失败=零 attempt 零文件或按 attempt 纪律保留失败样本）

(1) output_dir 空目录门 → (2) manifest 装载（冻结默认/路径）→ (3) fixture 注册表校验+物化入内部临时工作区+`snapshot_tree_sha256=compute_tree_fingerprint`（与注册表 `_shape_fingerprint(key)` 交叉核验，不符=fail closed）→ (4) 离线 config 文档构建+digest → (5) 有效 spec 构建（repositories/datasets 来自 manifest；analyzer_fingerprint/config_digest/seed 派生）→ (6) **cold attempt 0..cold-1：每 attempt 重新物化快照+重执行 scanner**；每 attempt 经冻结 `run_baseline_attempt`（mode="cold"，execute=B1 attempt 体）→ (7) **warm attempt cold..cold+warm-1：复用最后一次 cold 扫描结果与快照**（同样经 run_baseline_attempt，mode="warm"）→ (8) 聚合经冻结 `result_from_mapping`+`write_result_file` → (9) 报告经 `build_baseline_report(summary, scan_result)`（bundle/domain 恒不构造）+`write_report_file` → (10) B1 attempt 文档（含 receipt）与 b1-manifest 落盘 → (11) 返回 `B1SuiteResult`。attempt 体抛 Exception→冻结 run_baseline_attempt 纪律（失败样本持久化、循环继续）；BaseException→持久化该 attempt 后原样重抛（IP-0035 纪律沿用）。

#### 7.6.2 证据布局（输出目录内；`{d16}`=run_spec_digest 前 16 hex）

```text
{d16}-run-1..N.json        每 attempt RunResult（冻结命名，run_baseline_attempt 写出）
{d16}-run-{N+1}.json       聚合 RunResult（write_result_file）
{d16}-report-1.json        基线报告（write_report_file）
b1-attempts/attempt-{i:02d}.json   B1 attempt 文档（closed 键：schema_version=1、run_spec_digest、source_receipt）
b1-manifest.json           B1 manifest（closed 键集，下行）
```

（`b1-attempts/`/`b1-manifest.json` 与 `-run-`/`-report-`/`-synthetic-`/`.expert-timing` 家族零碰撞。）

#### 7.6.3 `source_receipt` 最小键集（R4 冻结；Packet 精化键名=合并派发清单与 R4 清单的并集，不收缩语义）

```text
snapshot_tree_sha256       物化快照树指纹（compute_tree_fingerprint；==注册表 _shape_fingerprint）
fixture_key                合成 fixture 键
fixture_manifest_sha256    注册表该键条目的指纹（溯源）
analyzer_name              扫描器身份串（scan 后 report.reviewer，如 "repository-hybrid:python-ast+python-dataflow"）
analyzer_fingerprint       spec 身份面（64-hex，§7.6.4 派生）
scanner_config_sha256      完整离线 config 文档 canonical SHA-256（文档本体入 b1-manifest）
seed                       int
workload                   "b1-offline-scanner-v1"（默认；逐字入 receipt）
run_spec_digest            RunSpec/RunResult 关联（64-hex）
attempt_index              int（全局序 0..N-1）
mode                       "cold" | "warm"
scanner_payload_sha256     ==报告 sources scanner digest 推导规则（L1340-1344）——交叉核验面
scanner_reexecuted         bool（cold=True / warm=False）
scanner_result_reused      bool（cold=False / warm=True）
snapshot_reused            bool（cold=False / warm=True）
request_body_rebuilt       bool（cold=True / warm=False；沿用冻结 state_reuse 词表语义）
```

b1-manifest closed 键集：`schema_version=1`、`workload`、`run_spec_digest`、`attempt_count`、`cold_count`、`warm_count`、`fixture_key`、`fixture_manifest_sha256`、`snapshot_tree_sha256`、`analyzer_name`、`analyzer_fingerprint`、`scanner_config`（完整文档）、`scanner_config_sha256`、`seed`、`scanner_payload_sha256`、`source_receipts`（按 attempt 序全列）、`source_receipts_digest`（=SHA-256(canonical_encode(source_receipts))）、`failures`（[] 或失败码列表）、`transport_calls`、`model_calls`（常量 0）、`declarations`（含 `"b1-offline-zero-model-calls"`、`"synthetic-fixture-wiring-not-real-acceptance"`）。

**绑定方式（R4 逐字承载）**：canonical 编码 + SHA-256 内容摘要绑定（与仓内 fingerprint 纪律一致，不引入非对称签名）；manifest 携带 `source_receipts_digest`；**读取时交叉核验，不符即 fail-closed typed 错误（不得降级 unavailable）**。`verify_b1_evidence(output_dir)`（公共读取核验入口）逐项复算：每 attempt 文档 receipt 可解析、manifest digest==重算、每 receipt `scanner_payload_sha256`==报告 sources scanner digest（同 payload 重算）、receipt `run_spec_digest`==attempt 文档与报告一致；任何不符→typed 错误。typed 错误族（`B1SourceError(ValueError)`+稳定码+结构 only field_path，先例纪律）：`B1_OUTPUT_NOT_EMPTY`、`SOURCE_RECEIPT_INVALID`、`SOURCE_BINDING_MISMATCH`、`SCANNER_DIGEST_MISMATCH`（恰四码，尾序冻结；不嵌 payload/数值）。

#### 7.6.4 身份派生面（NFR-01）

有效 spec 三身份面**确定性派生**（零环境、零时钟、零调用者抄袭）：
- `config_digest = SHA-256(canonical_encode(scanner_config 文档))`，文档含 workload、fixture_key、snapshot_tree_sha256、seed、cold_count、warm_count、§7.5 禁用清单 → **workload/snapshot/analyzer config 变化 ⇒ config_digest ⇒ run_spec_digest 变化**（M4）；
- `analyzer_fingerprint = SHA-256(canonical_encode({"analyzer_name": <scan 后 reviewer 串>, "scanner_config_sha256": <上值>}))`；
- `seed = seed`（参数逐字）。
同 snapshot/config/seed ⇒ 规范化来源字节稳定（scanner wire digest 与 run_spec_digest 逐字节重算相等，M3）。receipt 绑定信息经 config_digest（含 snapshot_tree/workload）与 source_receipts_digest（manifest 聚合）进入规范化摘要与证据链——**不只是未签定说明文字**。身份使用点仅限校验/获取/去重/呈报（M10 身份无关性）。B1 报告与历史 bounded-triage pilot 分属不同 workload（NFR-01 合法新身份），**不得比较成性能/降噪改善**。

#### 7.6.5 篡改 fail closed（AC-2）

对已落盘证据的任何篡改（payload 字节、receipt 键值、manifest 聚合 digest、attempt↔receipt↔report 绑定）在 `verify_b1_evidence` 读取核验下→`SOURCE_RECEIPT_INVALID`/`SOURCE_BINDING_MISMATCH`/`SCANNER_DIGEST_MISMATCH` typed 拒绝（M5）；报告构建侧 payload 篡改→report 冻结 EVALUATOR_PAYLOAD_INVALID/DIGEST_MISMATCH（M6 复用冻结面）。

#### 7.6.6 cold/warm、扫描重跑 vs 复用与 fake transport（裁定 §四/§五.6 逐字承载）

- **cold**：每 attempt 快照重新物化（snapshot_reused=False）、scanner 重新执行（scanner_reexecuted=True/scanner_result_reused=False）、请求体重建（request_body_rebuilt=True）。
- **warm**：复用最后一次 cold 的快照与扫描结果（snapshot_reused=True/scanner_reexecuted=False/scanner_result_reused=True/request_body_rebuilt=False）。**scanner 重跑、snapshot 复用、请求体复用、提供方缓存四者分别记录**（receipt 三 bool + B1 无提供方缓存面=模型层恒零）。
- **fake transport（注入式，验证未来接线）**：`transport(request_document) -> response mapping`，每 attempt 至多调用一次；请求文档=canonical 编码的 {workload, fixture_key, snapshot_tree_sha256, candidate 文件选择（≤CANDIDATE_FILE_CAP=12——**请求构造参数，非处理上限**；findings>12 不被截断，M9/M10）, attempt_index, mode}；**任何 measured 报告字段不得从 fake 响应派生**（wiring 验证 only）；`transport_calls` 计数如实入 manifest/result；`model_calls` 恒 0（**不让 fake 的次数写成真实调用**，M13）。transport=None（默认）=模型层整层缺席，receipt 与 manifest 面仍完整。

#### 7.6.7 样本聚合规则（裁定 §四"不得被求和成 8 倍"）

同一 snapshot 的 N 个样本（3c+5w）**不求和**：报告 counts/compression_chain/coverage 恒为**单次扫描快照投影**（==直接 scanner 输出，M2/M19）；聚合仅沿冻结 `from_mapping` 规则对 wall/cpu 计时面做百分位（3c+5w 成功⇒sufficient_sample）；attempt_count=len(samples) 如实。

### 7.7 边界样本契约（FR-04；裁定 §五.5）

- **docs-content / test-heavy / signal-storm**（fixture 注册表键）：全链执行，计数与直接 scanner 输出逐值一致（M9）；signal-storm findings 数 >12（>6 亦然）时报告 raw_candidates==全扫描 findings 数，**不被请求构造 cap 截断**（M10；cap 仅作用于请求文档的候选文件选择，两范围分别登记）。
- **身份无关性**：快照计数/digest 只由内容决定（compute_tree_fingerprint 相对路径算法）；重命名物化目录/tempdir 路径不改变任何计数或 digest（M3 附带；M10 断言）。
- **malicious-layout**：离线配置（§7.5）下扫描纯静态（AST/规则/静态 dataflow），**不执行仓库代码**（无 exec/eval/subprocess 作用于 fixture 内容；平台/SAST/cxx 链全关）、**不越界读写**（RepositoryWorkspace 无 symlink 跟随、路径不出 root；b1_source 只写 output_dir 与内部 tempdir，M11 + PC1 源扫描）。
- **dependency-blocked**：如该 fixture 产生依赖不可用面，经 inventory/coverage faces **如实披露**（缺口保留，不消解成 0/measured；M12）。
- **真实完整零 finding vs 失败可区分（AC-3）**：`archetype/empty-repository`（或零 finding fixture）→raw_candidates==0 为**完整扫描的 measured 0**（scanned_files/inventory 非空边界如实）；扫描失败/截断/解析失败各有诚实区分面（inventory.truncated/workspace_truncated、python_parse_errors/dataflow_parse_errors>0、coverage skips 原因、attempt failure_code）——**后者不得伪装 clean 或 measured 0**（M8）。

### 7.8 旧路径零变化回归锚（FR-05/裁定 §五.7）

- `run_real_baseline_suite` 签名（九参数含 artifact_key 尾参）与 order 1-9 零变化（M15 inspect.signature 镜像旧锚）；real_run `__all__` 与 `REAL_RUN_ARTIFACT_FAMILY` 十一键（含 real-pilot/large-repo）、`REAL_RUN_GATE_UNLOCKED=False`、CANDIDATE_FILE_CAP=12、首败停止门常量零变化（M16）。
- 旧 112/38/9 方法零触碰零同步（授权同步点表=空，§10）；C2 冻结提交上旧三文件全绿+十冻结文件 322 全绿+discover 全绿（Done Commands 2/3）。
- V5 缺席纪律：B1 报告无来源字段保持 null+unavailable（M7）；CI 无 Secret/无付费回归（PC1+discover）。

## 8. 七项验收清单（裁定 §五 逐字转录；验收语义权威）

1. 正式 B1 入口从全新空目录跑通到 RunResult/报告/来源 receipt；直接实际 scanner 输出与报告的同范围计数逐值一致；sources/digest 能回指真实 payload；不能只构造一个手工 domain dict。
2. 同 snapshot/config/seed 的规范化来源字节稳定；snapshot/analyzer/config/workload 改变则 identity/digest 变化；篡改 payload、receipt 或 RunResult 绑定 fail closed。
3. 扫描源有效、源缺席、源无效；真实完整零 finding 与扫描失败/截断/解析失败有清楚区别，后者不能伪装 clean 或 measured 0。
4. 只有兼容 Finding 来源时保留 legacy_projection/Hypothesis unavailable；有真实原生对象时仅对应字段 measured；缺 Mining/Repair 时 VEP/RVR 保持 unavailable；不能用空 bundle 或零值占位绕过。
5. docs-content、test-heavy、signal-storm 等边界样本；findings>6、>12 时扫描输出不被请求构造 cap 截断。身份无关性仍过；malicious-layout 不执行仓库代码、不越界读写；dependency-blocked 如实报告缺口。
6. 声明并验证新 workload 的 cold/warm 复用与来源绑定；模型层用 fake transport，可跑正式 3c+5w 形状验证未来接线，但本轮全部真实 POST=0。不让 fake 的次数写成真实调用。
7. 旧 112 方法行为回归、旧描述子装载兼容、旧 {5,5}/shaped 路径、canary/首败门、V5 缺席纪律和 CI 无 Secret/无付费回归。新增数另数；如旧方法必须同步，仅限 Packet 授权点。

（"如旧方法必须同步，仅限 Packet 授权点"——本 Packet 授权点=空表，§10。）

## 9. 测试矩阵 v10（R5：新文件 `tests/test_v4_baseline_b1_source.py`，恰 ≤24 新方法，八簇；旧 112/38/9 零触碰）

### 9.1 新增方法（20 个；`grep -c "    def test_"` 口径=20；预算 ≤24）

| 方法 | 簇（CA Acceptance 1 八簇） | 覆盖 | 断言面（冻结） | RED 态（对未修改产品 fa91085e，无 b1_source.py） |
| --- | --- | --- | --- | --- |
| `test_b1_entry_full_chain_from_empty_directory`（M1） | 1 | FR-01/AC-1 | 空输出目录→RunResult 每 attempt 文件+聚合+报告+b1-attempts/b1-manifest 全落盘；receipt 每 attempt 在场；config 文档断言 §7.5 禁用清单逐项；`B1SuiteResult` 面（model_calls==0、b1 is True）；sources 含恰一条 kind=="scanner" 且 digest==冻结指纹规则重算 | **RED**（ModuleNotFoundError: benchmarks.v4.baseline.b1_source——模块缺席锚） |
| `test_b1_counts_match_direct_scanner_output`（M2） | 1 | FR-01/FR-02/AC-1 | 独立物化同 fixture→真实 `RepositoryScanner`（§7.5 同款显式离线配置）直扫→逐值一致：raw_candidates/deterministic_alerts/confirmed/inconclusive/scanned_files/coverage_gap(+reasons)/signals/security_issues==直接输出复算；分区不变量 raw==det+incon；压缩链两 ratio==floor 复算 | **RED**（模块缺席） |
| `test_b1_identity_bytes_stable_same_inputs`（M3） | 2 | AC-2/NFR-01 | 两次独立全链（不同 tempdir）同 fixture/config/seed：run_spec_digest、scanner_payload_sha256、报告 sources digest、snapshot_tree_sha256 逐字节相等（规范化来源字节稳定；tempdir 路径无关） | **RED**（模块缺席） |
| `test_b1_identity_changes_on_snapshot_config_workload_seed`（M4） | 2 | AC-2/NFR-01 | 四个变化各自⇒run_spec_digest 变化（且 scanner_config_sha256 对 config/workload/snapshot 变化敏感）：换 fixture（snapshot 变）、dataflow_enabled=False（config 变）、workload 标签变、seed 变——逐一 subTest | **RED**（模块缺席） |
| `test_b1_tampered_evidence_fail_closed`（M5） | 3 | AC-2/FR-03 | 落盘后篡改：receipt 键值→`SOURCE_RECEIPT_INVALID`/`SOURCE_BINDING_MISMATCH`；manifest source_receipts_digest→`SOURCE_BINDING_MISMATCH`；receipt scanner_payload_sha256→`SCANNER_DIGEST_MISMATCH`（typed，不降级 unavailable；三 subTest） | **RED**（模块缺席） |
| `test_b1_source_states_valid_absent_invalid`（M6） | 4 | AC-3/FR-02 | 三态：有效=真实 RepositoryScanResult→measured/legacy_projection 面；缺席=real-world v2 dict payload（无 domain）→scanner 专属面 unavailable（冻结 report 面）；无效=Finding 带"runtime-confirmed"（∈scanner 九态、∉report 冻结五态）→EVALUATOR_PAYLOAD_INVALID fail closed **不吞成 unavailable** | **RED**（模块缺席；无效面用冻结 report 面 arrange——方法内按断言组归因，无效/缺席组对现行产品按设计通过、B1 组 RED） |
| `test_b1_projection_honesty_faces`（M7） | 5 | AC-4/FR-02 | signals/security_issues==len(findings) 且 projection=="legacy_projection"；hypotheses (None,"unavailable")；vep/rvr/stage_outcome 三键全 (None,"unavailable")；resources 三键 None；expert sessions==0/active None/digests []；evidence_domain=="legacy"；报告无任何 domain 构造（bundle is None 路径） | **RED**（模块缺席） |
| `test_b1_zero_finding_measured_zero_vs_failure_distinguishable`（M8） | 5 | AC-3/FR-02 | 零 finding fixture（empty-repository）全链：raw_candidates==0 且 scanned/coverage 面 measured 如实（完整零 finding）；对照面（同一测试内构造）：inventory truncated/workspace_truncated=True、parse_errors>0、coverage skip 原因在场——四类面与"clean 0"机器可区分，无伪装 | **RED**（模块缺席；对照面用冻结 arrange 归因） |
| `test_b1_boundary_samples_three_archetypes`（M9） | 6 | FR-04/AC-5 | docs-content/test-heavy/signal-storm 三 fixture 全链（subTest）：计数==各自直接 scanner 输出复算；报告/RunResult/receipt 完整；无 fixture 越键 | **RED**（模块缺席） |
| `test_b1_signal_storm_not_truncated_by_request_cap`（M10） | 6 | FR-04/裁定§五.5 | signal-storm findings>12：报告 raw_candidates==直接输出（>12 全保留）；请求构造面（manifest/receipt 或 transport 请求文档）候选文件选择 ≤CANDIDATE_FILE_CAP==12（两范围分别登记不混用）；身份无关性：重命名物化根目录不改计数/digest | **RED**（模块缺席） |
| `test_b1_malicious_layout_static_only_no_escape`（M11） | 6 | FR-04/NFR-02 | malicious-layout 全链：正常完成、计数==直接输出；b1_source 源码 PC1 扫描（无网络根 import、无环境读、无 exec/eval/subprocess 作用于扫描内容）；输出目录外零写（仅 output_dir+内部 tempdir） | **RED**（模块缺席；PC1 组对缺席文件按 arrange 失败归因） |
| `test_b1_dependency_blocked_gap_reported_honestly`（M12） | 6 | FR-04 | dependency-blocked fixture 全链：完成或如实 typed 失败皆可，但**不得**消解缺口为 0/measured——inventory/coverage/workspace 边界面逐项与直接 scanner 输出一致 | **RED**（模块缺席） |
| `test_b1_cold_warm_fake_transport_three_plus_five`（M13） | 7 | AC-4/FR-03/裁定§五.6 | fake transport（计数器对象）注入：恰 3 cold+5 warm=8 attempts（attempt_count==8）；transport_calls==8、**model_calls==0**（fake 次数≠真实调用）；receipt 每 attempt 在场且 mode/attempt_index 正确（0..2 cold/3..7 warm）；聚合 status=="sufficient_sample" | **RED**（模块缺席） |
| `test_b1_scanner_reexecution_vs_reuse_semantics`（M14） | 7 | FR-03/AC-4 | 8 份 receipt：cold 三份 {scanner_reexecuted:True, scanner_result_reused:False, snapshot_reused:False, request_body_rebuilt:True}；warm 五份全反；scanner_payload_sha256 八份全同（同 snapshot 同 config 字节稳定）；scanner_executions 计数==cold_count | **RED**（模块缺席） |
| `test_b1_sample_aggregation_no_summation`（M19） | 7 | FR-03/裁定§四 | 同 snapshot 8 样本：报告 raw_candidates/counts/compression_chain==单次扫描值（非 8 倍）；attempt_count==8；聚合只作用于计时面（sufficient_sample 百分位） | **RED**（模块缺席） |
| `test_b1_receipt_key_set_and_manifest_digest`（M20） | 7 | FR-03/AC-2 | receipt 键集恰 §7.6.3 十六键（set 相等）；b1-manifest closed 键集恰 §7.6.3；source_receipts_digest==canonical 重算；verify_b1_evidence 通过态返回一致绑定 | **RED**（模块缺席） |
| `test_b1_old_entry_signature_unchanged`（M15） | 8 | FR-05/AC-5 | `inspect.signature(run_real_baseline_suite)` 参数序/keyword-only 集/artifact_key 默认==冻结（镜像旧锚）；real_run `__all__` 不变 | **按设计通过**（现行产品即目标行为；旧路径回归锚） |
| `test_b1_old_static_surfaces_frozen`（M16） | 8 | FR-05/AC-5 | REAL_RUN_ARTIFACT_FAMILY 十一键闭集不变（含 real-pilot/large-repo 七+四字段）；REAL_RUN_GATE_UNLOCKED is False；CANDIDATE_FILE_CAP==12；offline_flow `__all__`/入口签名不变 | **按设计通过**（同上） |
| `test_b1_packet_doc_in_repo_with_container_copy_line`（M18） | 8 | 纪律探针（IP-0036 R6.5 先例） | 本 Packet 在 docs/ 且 Dockerfile 恰一行 COPY 本 Packet（无第二行） | **按设计通过**（C1 文档先落） |
| `test_b1_test_sources_offline_and_secretless`（M17） | 8 | PC1 | 本测试文件自身源 AST 扫描：无网络根 import、无环境读、无 secret 形 token；b1_source.py 存在时同款扫描（缺席时该组以缺文件 arrange 失败归因——方法内分组） | **部分按设计通过**（自扫描组过；产品组 RED=文件缺席） |

### 9.2 簇覆盖对照（CA Acceptance 第 1 项八簇 → 方法）

簇1 B1 入口空目录全链→M1；报告计数与直接 scanner 输出同范围逐值一致→M2（+M9 各 fixture）；簇2 规范化字节稳定+变化→M3/M4；簇3 篡改 fail closed→M5；簇4 源三态→M6；簇5 投影如实+零 finding 可区分→M7/M8；簇6 边界样本→M9/M10/M11/M12；簇7 cold/warm+来源绑定→M13/M14/M19/M20；簇8 旧路径回归锚→M15/M16/M17/M18。（簇 5 第 4 项验收"只有兼容 Finding 来源时保留 legacy_projection"=M7；V5 缺席纪律=M7+M16。）

### 9.3 RED 形态（Add 型新模块 IP；逐方法归因）

对**未修改产品（fa91085e 版，b1_source.py 不存在）**运行 v10（C1 已落库后、C2 冻结前）：

- **16 方法 RED**（M1-M14、M19、M20）：`ModuleNotFoundError: No module named 'benchmarks.v4.baseline.b1_source'`——**新模块缺席锚**（IP-0031/0032 同型先例；lazy per-test import，失败=模块缺席非 arrange/import/lint 错误）。
- **3 方法按设计通过**（M15/M16/M18）：旧路径回归锚与 C1 文档探针（现行产品即目标行为/文档先落）。
- **1 方法分组归因**（M17）：自扫描组通过；产品源扫描组因文件缺席 arrange 失败（如实归因）。
- **M6 方法内按断言组归因**：B1 组 RED（模块缺席）；缺席/无效组对现行冻结 report 面按设计通过（如实登记）。
- **Pre-Freeze Harness Gate（§10 条件 5 前置）**：以**临时最小桩模块**（NotImplementedError 级别+签名骨架）验证全部 fixture/arrange/参数组合执行到产品行为断言处（区分 fixture 缺陷 vs 行为缺失）；桩不入冻结提交（删除后 `git status` 证明）；RED 逐项归因于缺失产品行为。
- 逐方法"RED 失败/按设计通过"归因表强制（归档 `.pv_tmp/RED_IP-0040_2026-09-30/`）；基线态证明=C0（112/47/322/discover 2728/24）。
- C2 后自跑：ruff（--no-cache，产品缺席态+最小桩存在态双态）/compileall/旧三测试文件绿（Done Commands 1-4）。

### 9.4 PC 纪律（IP-0033..0039 同款标配）

PC1=新增测试源 secret-token/网络-token 拼接扫描+AST import 根扫描（M11/M17）；PC2=arrange 经冻结校验器（spec/receipt 构造一律经冻结 from_mapping/canonical_encode 路径或直接产品入口）；PC3=派生数值断言（计数==直接 scanner 输出独立复算、digest==冻结指纹规则独立重算，不硬抄实现值——M1/M2/M3/M20）。

## 10. 冻结测试面演进程序（本叶=纯新增文件；六条件退化适用+空授权同步表）

**冲突裁定**：本叶验收面全部落在**新文件** `tests/test_v4_baseline_b1_source.py`（冻结版本 v10；"v10"=v9' 之后的新冻结版本序号，112+38+9 旧方法零触碰）。**授权同步点表=空表**：本叶对 v9' 三冻结测试文件（18bfb4c2/86f584cb/6887f9fa）与十冻结文件（322 方法）零 hunk、零常量同步、零断言修改；`_VERIFICATION_STATES` 五态/_COUNT_KEYS/_CHAIN_FIELDS/`_PROJECTIONS` 等 report 冻结面零触碰（R2 判据=scanner 路径足够）。**若实现需要修改任何旧测试才能通过→Stop 6**（唯一出路=Decision Request 授权同步点后再演进）。

**六条件（IP-0033..0039 程序退化适用于纯新增；任一不满足=Stop）**：

1. **对象唯一**：仅新增一文件一次（v10，恰 20 方法 ≤24 上界）；旧三文件+十冻结文件与全部产品禁区模块 blob 逐字不变（Done Command 6/7 守护）。
2. **逐 hunk 归因**：新文件每个方法映射 §1 需求表与裁定编号（R2-R5/裁定 §四/§五），§9.1 表已逐条登记。
3. **禁止弱化**：无旧断言可弱化（零旧文件触碰）；新文件自身不得含 skip/xfail/条件降级断言。
4. **版本链保留**：v9' 三文件历史 blob（18bfb4c2/86f584cb/6887f9fa）永久在链；v10 blob 由 C2 冻结时登记于提交与验证记录。
5. **RED 先于冻结**：C2 冻结前对新文件按 §9.3 取得有效 RED 并留档（独立日志归档 `.pv_tmp/RED_IP-0040_2026-09-30/`，逐方法归因）；冻结基线=main 上 C1 合并后 SHA（主会话记录；worktree rebase/重置到该 SHA 后开工）。
6. **角色纪律**：演进只在 C2 由 P&V 执行；Implementation 结构性零参与测试修改；C2 冻结提交后本 Assignment 的 ALLOWED_ONCE（§11）仅覆盖本文件面的机械缺陷（合计一次）。

**Pre-Freeze Harness Gate（冻结前必须全部通过）**：①新文件可完整 import 与 collect（零加载期错误）；②最小桩验证全部 fixture/helper/参数组合执行到产品行为断言处（§9.3）；③fixture 签名/参数数量/subTest 构造不被 ModuleNotFoundError 掩蔽；④Ruff `--no-cache`；⑤Ruff 在**产品模块缺席态**与**最小桩模块存在态**分别运行并双双通过（isort first-party 分类依赖模块存在性）；⑥临时桩不入冻结提交；⑦RED 逐项归因于缺失产品行为；⑧方法预算 20（≤24 上界，CA R5）。

**ER 复核面**：逐方法复核 §9.1 断言与 AC 映射、独立复跑 RED 归因、复核空授权同步表（零旧文件 hunk）。

## 11. ALLOWED_ONCE（一次性机械测试修正授权；CA §Mechanical Test Correction Allowance 全文转录）

`ALLOWED_ONCE`（随 CA-IP-0040-v1.0 一次性给出）。C2 冻结后，P&V 可在不新增 Coordinator 调用的情况下自行纠正**一次**纯测试机械缺陷并重新冻结（v10→v10'），条件全部满足：①不改变产品语义、公共接口、稳定错误码（含 §7.6.3 四码）或文件范围（含 Dockerfile 行数）；②仅限 fixture/arrange/import/lint/测试基础设施缺陷；③旧 Frozen Commit 保留；④修正前缺陷证据（原始 traceback 独立日志）、修正后有效 RED、新 Frozen Commit 完整记录；⑤Implementation 未参与测试修改。涉及产品行为、验收语义或文件范围→Decision Request；授权仅一次，用尽即止。

## 12. Stop Conditions（触发即停并提交 Decision Request；CA §Known Gaps and Stop Conditions 全文+绝对停五条标 ★）

0. 派发前再核验失败：#249 正文/标签/远程状态与本地捕获不一致，或基线 SHA 上 main 出现冲突性实现（含 IP-0040 编号被占用）。
1. ★**任何真实模型调用尝试（含一次 POST）=绝对停；凭据注入=绝对停。**
2. ★**`lima/**` 任何写=停；sealed 目录（`D:\BaseAIProject\LIMA-real-runs\**` 及一切封存树）任何写入=停。**
3. ★**预算门/estimate 常量/transport/身份允许集/canary/首败门/旧描述子/批准工件的任何 diff=停。**
4. ★**授权同步点表之外的旧测试修改=停；以改测试消失败=停。**
5. ★**扫描配置依赖环境变量默认值、或任何网络/LLM/platform/会执行仓库代码的验证路径被启用=停。**
6. 需要 findings 截断/请求构造 cap 才能通过=停；需要填 domain 整组闭集或空 bundle 才能通过=停；旧 112/38/9/322 或 v9' 三文件任何 hunk、或 report.py 冻结面（五态/七键/六键/投影词表）任何变化才能交付=停。
7. R1 再拆分触发条件命中（§7.3 (a)(b)(c) 任一）=停止单叶推进，按 Maintainer 预授权两叶边界上报。
8. 方法数超预算（>24）或簇覆盖缺口；十冻结文件回归/全量 discover 出现非预期失败；skipped 集出现未登记变化（基线 24）。
9. 六条件/Pre-Freeze Harness Gate 任一不满足；出现"弱化断言才能通过"；弱化判定争议→DR。
10. 授权文本与实现需求冲突（含 CA 与裁定原文语义矛盾、裁定间互斥、或 CA 代码锚与 main 事实不符且影响验收语义——如 OBS-1 型差异影响落位）——不得自行改写授权或裁定。
11. 需要新第三方依赖，或非注入式外部输入/真实 sleep 驱动的测试。
12. 实现中发现证据/代码间新矛盾影响验收语义（如 scanner 离线配置在冻结五态外发射、receipt 交叉核验与报告推导规则不一致）——记录并提交，不得静默。
13. 需要消耗 Maintainer 决策的任何事项（预算 ≤1，预期 0）。
14. 同根因两轮有新证据修复仍失败 / 规格无法兼容=落盘 DR 后停依赖部分，完成其余工作。

## 13. Done Commands（worktree 根执行；`PYTHONUTF8=1`；成功判据=全绿/为空/恰 1+1+1 Add+1 Modify/blob 不变/ancestry exit 0）

```bash
# 0. 预冻结基线（C2 之前登记；本轮已执行并归档 .pv_tmp/RED_IP-0040_2026-09-30/baseline.txt）：
#    test_real_run 112/112 OK；report+v5_negatives 47/47 OK（38+9）；十冻结文件 322/322 OK；
#    discover 2728 OK / skipped=24（exit 0）——与派发预期 2728/24 逐字一致
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_real_run
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_report tests.test_v4_baseline_v5_negatives
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline tests.test_v4_baseline_budget tests.test_v4_baseline_cli tests.test_v4_baseline_collection tests.test_v4_baseline_fixtures tests.test_v4_baseline_manifest tests.test_v4_baseline_offline_flow tests.test_v4_baseline_report tests.test_v4_baseline_result tests.test_v4_baseline_v5_negatives
PYTHONUTF8=1 python -m unittest discover -s tests
# 1. RED 证据（C2 冻结前，对未修改产品 fa91085e 版/或 C1 合并后 SHA 的产品面）：
#    新文件 20 方法=16 RED+3 按设计通过+1 分组（M17/M6 组内归因）；独立日志归档
#    .pv_tmp/RED_IP-0040_2026-09-30/（先落盘、再 hash、再引用）
# 2. 定向（C2 冻结时按设计 RED——见 §9.3；C3 后全绿；总方法 20）
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_b1_source -v
# 3. 旧三测试文件+十冻结文件+全量 discover 回归（C2 冻结提交上：112/47/322 全绿+discover 全绿
#    skipped 集与基线一致 24）
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_real_run
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_report tests.test_v4_baseline_v5_negatives
PYTHONUTF8=1 python -m unittest discover -s tests
# 4. 字节编译；ruff（--no-cache；产品缺席态+最小桩存在态双态；bandit 选做如实登记）
PYTHONUTF8=1 python -m compileall -q benchmarks tests
PYTHONUTF8=1 python -m ruff check --no-cache tests/test_v4_baseline_b1_source.py
PYTHONUTF8=1 python -m ruff check --no-cache benchmarks/v4/baseline/b1_source.py tests/test_v4_baseline_b1_source.py   # C3 后
# 5. CI 面（C3 后）：python scripts/run_ci_tests.py
# 6. diff 守护：恰 1 Add（Packet C1）+1 Modify（Dockerfile 恰 +1 行）+1 Add（测试 C2）+1 Add（b1_source C3）；
#    .pv_tmp/** 与输出目录不在 diff；lima/** diff 必空
git diff --name-status fa91085e80fe509d881bc9ce0194e86d8ecbf0c4...HEAD
git diff fa91085e80fe509d881bc9ce0194e86d8ecbf0c4...HEAD -- Dockerfile   # 恰 +1 行
git diff --name-only fa91085e80fe509d881bc9ce0194e86d8ecbf0c4...HEAD -- lima/   # 空
# 7. blob 守护：C0 清单（baseline.txt）所列全部 blob 与 HEAD 一致（唯四例外=Dockerfile 演进行、
#    新增三文件）；report/real_run/run/orchestrate/budget/collect/expert_timing/offline_flow/
#    fixtures/__init__/lima-三件/十三测试文件/manifest json/历史文档逐 blob 不变
git ls-tree fa91085e80fe509d881bc9ce0194e86d8ecbf0c4 -- <守护清单> 与 HEAD 对比
# 8. ancestry：fa91085e → C1 → C2(冻结，信息逐字 [IP-0040][PV] Freeze acceptance
#    tests v10 (RED)) → C3 → (C4) 各段 merge-base --is-ancestor exit 0
```

## 14. PR 与 Completion Summary 契约（CA §Handoff）

- PR：单 PR `codex/ip-0040-b1-wiring` → main；标题禁 close 族关键词与编号组合；正文含 Final SHA（完整 40 位）、变更文件清单（对照恰 3 Add+1 Modify）、Done Commands 实际输出摘要（0-8）、满足/不满足/未验证逐条、RED 归档路径与 blob 记录（新文件 v10 blob、Dockerfile 0ea1dd2f→）、AC→测试→结果表、"This PR does not auto-close the Source Issue."、"Related to #249."（仅此关联；不得关联关闭 #57）；提交前缀 `[IP-0040][PV]`/`[IP-0040][IMPL]`/`[IP-0040][CI]`；C3 必须以 C2 冻结提交为祖先（Done Command 8）；C-final 后修复提交必须引用 Stop/DR/ALLOWED_ONCE 编号。合并/推送/评论由主会话按 Maintainer 授权执行；P&V/IMPL 零远端写；分支 head CI 与审查过门后才合并，合并后核验 merge SHA 的 main CI success。
- 传递时必须携带被否决的决定：v3 契约不触发（R2 判据冻结）、旧入口不参数化（R3）、不复用 pilot 描述子（R3/裁定 §四）及理由；不复制完整失败日志。
- Completion Summary 必含：FR-01..05/NFR-01..02 逐条证据索引（测试 ID）、AC-1..5 判定、C1/C2/C3 提交 SHA 与 blob 记录、RED 归档路径与逐方法归因计数（预期 16 RED/3 按设计通过/1 分组）、C0 基线实际值（112/47/322/2728+24）、零真实调用声明（model_calls==0+fake transport 计数≠真实调用）、Dockerfile 恰 +1 行证明、逐字段来源/投影/缺口矩阵引用（§7.2）、K1-K5 缺口状态、§16 OBS 状态。

## 15. 范围裁定 R1-R7 转录（CA-IP-0040-v1.0 附录 R 全文）

- **R1（Q1 拓扑）：裁定单叶 IP-0040。**依据：F7 亲验成立——report.py L1298-1344 的 scanner 类型路径已可达本叶全部可测目标（计数/分级/覆盖/压缩链/digest measured + legacy_projection 保留 + Hypothesis/VEP/RVR unavailable），拆两叶的唯一解耦收益（隔离 report.py 消费面演进）随 R2 判据冻结而消失；拆分将使 Packet/冻结/PR/post-merge 治理成本翻倍并制造人为依赖边。再拆分触发条件（登记，命中任一即停止单叶推进并按 Maintainer 预授权拆分）：(a) 某 mandatory 报告字段在 scanner 对象路径上无任何可加性推导；(b) 出现必须"部分字段 native measured"的语义需求（dict domain 整组闭集会强制 vep/rvr/hypotheses 一并 measured）；(c) 需求的计数级别不同于合并后 findings 级别且无法以登记缺口如实披露。若触发：叶 A=版本区分的部分来源契约+report 投影演进（Packet 点名 report.py 文件/字段/词表/旧测试变化），叶 B=B1 入口接线，序 A→B，均在本次零调用授权内。
- **R2（Q2 判据冻结）：裁定"scanner 类型路径足够"成立，v3 部分契约不触发。**判据（冻结）：本叶全部目标字段可在 `RepositoryScanner.scan → RepositoryScanResult → build_baseline_report(kind="scanner")` 路径上推导——raw_candidates=len(findings)（合并后）、确定性分级沿五态闭集、scanned_files/coverage_gap measured、压缩链同范围同分母规则、来源 digest=_fingerprint(report+inventory)、signals/security_issues legacy_projection、hypotheses/vep/rvr/stage_outcome null+unavailable。结论：domain/report schema 零改动；report.py 冻结消费面零改动；P2 条件授权休眠（触发条件=R1(a)(b)(c)，未来命中时另立 IP）。
- **R3（Q3 入口形态）：新公共入口，不参数化旧入口。**新文件 `benchmarks/v4/baseline/b1_source.py`，公共函数 `run_b1_source_baseline_suite`。依据：旧入口签名被冻结测试 `inspect.signature` 钉死（test_v4_baseline_real_run.py L2427/L3928/L4007），参数化必然引入旧路径证明负担与旧测试同步点；新入口使"旧调用点零 diff"退化为 real_run.py 零修改即可证。形态约束：走正式 RunResult（`from_mapping`/`write_result_file`）与报告链（`build_baseline_report` scanner kind）；B1 workload 标签入 run identity（NFR-01 合法变化）；不复用 pilot 描述子（B1 用合成 fixture 快照，零预算离线 workload）；扫描配置显式离线（显式构造参数，禁 LLM/platform/网络/code-exec 验证路径，不依赖环境变量默认值）；内部组合（复用 `run.py`/`orchestrate.py` 冻结原语 vs B1 自有 attempt 循环）由 Packet 在文件边界内裁定，例外修改 real_run.py 须 additive-only 且逐项登记。
- **R4（Q4 receipt 载体）：attempt 文档 additive 子块 `source_receipt` + manifest 聚合，摘要入 run identity 派生面。**B1 自有 attempt 文档（由 b1_source 写出）每份携带 `source_receipt` 子块，最小键集（Packet 冻结前可精化键名，不得收缩语义）：`snapshot_tree_sha256`、`fixture_key`、`fixture_manifest_sha256`、`analyzer_name`、`scanner_config_sha256`（完整 config 文档入 manifest）、`seed`、`workload`（如 `b1-offline-scanner-v1`）、`run_spec_digest`、`attempt_index`、`mode`、`scanner_payload_sha256`（须与报告 sources 的 scanner digest 推导规则交叉核验）、`scanner_reexecuted`/`scanner_result_reused`、`snapshot_reused`、`request_body_rebuilt`（沿用冻结 state_reuse 词表）。签名方式：canonical 编码 + SHA-256 内容摘要绑定（与仓内 fingerprint 纪律一致，不引入非对称签名）；manifest 携带 `source_receipts_digest`；读取时交叉核验，不符即 fail-closed typed 错误（不得降级 unavailable）。同 snapshot 多样本计数不得求和。
- **R5（Q5 测试预算）：新增 ≤24 方法（v10 = 112 基础上加新），旧方法同步仅限授权点。**八簇见 Acceptance 第 1 项。默认期望授权同步点为零（设计不动旧文件）；若 Packet 必须引入（如共享文档 exact-key 断言），必须在冻结前列出并逐项登记旧值→新值与授权依据（先例：IP-0039 `test_artifact_family_catalog_frozen_ten_keys` 授权同步），不删除负例。
- **R6（F 文件边界与提交链）**：见 Workspace and Ownership（C1 docs-only → C2 冻结 v10 RED → C3 IMPL 预裁定边界 → C4 独立验证/PR/合并/post-merge）。Dockerfile 默认零改动（COPY 面已核验不含 benchmarks/）。
- **R7（G §六职责归属）**：实际零调用 scanner 执行（真实 `RepositoryScanner`、新 snapshot-copy、sealed 目录只读）与专家复核包（绑定实际 finding/来源 digest/计时协议/reviewer 摘要；无真人事件 sessions=0、active time unavailable）为 C-final 阶段任务，由 P&V 在主会话授权下、实现验证通过后执行；本 Assignment 不提前授权。

## 16. Decision Record（P&V 定稿决策；CA 授权范围内的冻结裁量）

| # | 决策 | 时间 | 依据 |
| --- | --- | --- | --- |
| DR-IP-0040-PV-1 | 新验收面承载于**新文件** `tests/test_v4_baseline_b1_source.py`（v10 序号=新冻结版本；不动 v9' 112/38/9）；授权同步点表=空 | 2026-09-30 | CA R5/§C2 Allowed Files："新测试文件 tests/test_v4_baseline_b1_source.py（及 Packet 点名的 B1 专用 fixture）"；R5"默认期望授权同步点为零（设计不动旧文件）" |
| DR-IP-0040-PV-2 | B1 attempt 循环=**自有循环复用冻结原语**（`run_baseline_attempt` 逐 attempt + `result_from_mapping` 聚合 + `write_result_file`），不复用 `run_repeats`：run_repeats 冻结为对称 N cold+N warm，而正式 3c+5w 形状不对称；自有循环零触碰任何冻结模块（R3 授权 Packet 裁定内部组合） | 2026-09-30 | R3"内部组合……由 Packet 在文件边界内裁定"；orchestrate.py L220-305 亲读（repeat 对称）；baseline_run_result 3+5 充分门亲读 |
| DR-IP-0040-PV-3 | receipt 键集=**R4 清单∪派发清单**的十六键（派发八键为 R4 子集——`analyzer_fingerprint` 为派发独有，并入；无一处收缩语义） | 2026-09-30 | R4"最小键集（Packet 冻结前可精化键名，不得收缩语义）"；CA A4"Packet 可在冻结前精化键名" |
| DR-IP-0040-PV-4 | workload 入口=keyword-only 参数（冻结默认 `"b1-offline-scanner-v1"`，即 R4 示例值）：使 M4 可经公共入口验证 workload⇒digest 敏感性；无付费效力面（零模型调用），不构成 workload 漂移通道 | 2026-09-30 | R4 示例值；裁定 §四"新 workload/来源语义必须进入 run identity"；§五.2 workload 变化→digest 变化验收 |
| DR-IP-0040-PV-5 | 有效 spec 身份面由入口**确定性派生**（config_digest=SHA-256(config 文档含 workload/fixture/snapshot_tree/seed/shape)；analyzer_fingerprint=SHA-256(analyzer 身份文档)；seed=参数），repositories/datasets 取自冻结 manifest——零 schema 改动实现"workload+snapshot_tree+analyzer config+seed 入 identity"（CA A4/NFR-01） | 2026-09-30 | CA A4"run identity 派生面声明 workload+snapshot_tree+analyzer config+seed（NFR-01 合法变化）"；baseline_run_spec 七字段闭集只读事实（DI-012） |
| DR-IP-0040-PV-6 | Dockerfile 插入锚=L70（IP-0039 Packet COPY 行）后（CA §C1 Allowed Files+派发 B 项同锚；IP-0039 DR-PV-6 先例） | 2026-09-30 | 本会话亲读 Dockerfile L70 |
| DR-IP-0040-PV-7 | 方法数=恰 20（≤24）：簇 7 拆 4（cold/warm 形状/重跑复用/聚合不求和/receipt 键集与 digest）、簇 6 拆 4（三样本/不截断/malicious/dependency）、簇 8 拆 4（签名锚/静态面/文档探针/PC1）——行为覆盖优先于方法数压缩 | 2026-09-30 | CA R5 ≤24；本责任书 §3.1 方法预算纪律 |
| DR-IP-0040-PV-8 | 词表边界负例（M6 无效组）用 Finding 构造 `verification_state="runtime-confirmed"`（∈scanner VERIFICATION_RANK 九态、∉report 冻结五态）到达报告→EVALUATOR_PAYLOAD_INVALID：这是"离线发射 ⊆冻结集"不变量的对偶面证明（若 B1 离线配置失控发射越集状态，同一门拦截） | 2026-09-30 | CA §Frozen Interfaces 5（"超出即 fail closed"）；report L1112-1117 亲读 |
| DR-IP-0040-PV-9 | typed 错误族=恰四码 `B1_OUTPUT_NOT_EMPTY`/`SOURCE_RECEIPT_INVALID`/`SOURCE_BINDING_MISMATCH`/`SCANNER_DIGEST_MISMATCH`（str-enum+稳定消息+结构 only field_path，先例纪律；不嵌 payload/数值/主机路径） | 2026-09-30 | R4"fail-closed typed 错误"；BaselineReportError/RealRunError 先例（DI-005/DI-011） |

**观察项（不移交实现、不构成验收面）**：

- **OBS-1（字面差异，flagged 提交 Coordinator）**：CA §Workspace/R6 括注"已核验 Dockerfile COPY 面只含 lima/、skills/、指定 scripts，**不含 benchmarks/**"与 main 事实不符——Dockerfile **L83** 存在 `COPY --chown=lima:lima benchmarks ./benchmarks`（本会话亲读，blob 0ea1dd2f）。该差异**不影响本叶任何裁定**（打包面默认零改动结论不变；本叶仅 Packet 文档 +1 COPY 行；b1_source.py 位于 benchmarks/ 内，镜像 COPY 面已天然覆盖，无需新增打包行）；按 Stop 10"代码锚与 main 事实不符→登记不自行改义"处理，提交 Coordinator 知悉/勘误。
- **OBS-2**：#249 正文本会话未独立 GET（第七轮零网络授权）；需求语义经 CA-IP-0040-v1.0 转录消费（DI-004）。主会话派发 C3 前如对 AC-1..AC-5 有逐字核验需求，可只读 GET 复核与本 Packet §1 映射的一致性。
- **OBS-3**：C0 全量 discover 实际值=**2728 OK / skipped=24**，与派发预期逐字一致，无 Stop 8 差异（skipped 集与 IP-0039 后基线一致）。

## 17. 已知缺口（不阻塞本 Packet；如实保留，不得消解成 0 或 measured）

- **K1 合并前告警计数无产生点**（F3）：生产扫描器只读，findings 已按 (path,line,cwe/rule_id) 合并；raw_candidates=合并后级别，合并前数=登记缺口。
- **K2 VEP/RVR/Mining/Repair/真人分钟**：本叶后仍 unavailable；模型层资源第三层费用 UNKNOWN（不默认 0）。
- **K3 B1 合成 fixture 的 measured 证明的是接线行为**，不是九类现实验收；离线全链执行≠九类真实验收；B1 报告与历史 bounded-triage pilot 分属不同 workload 不可比。
- **K4 #57 PR3 不勾选**；九类真实验收宣称不在本叶。
- **K5 §六任务未执行**（实际零调用 scanner 执行+专家复核包=C-final 阶段，主会话授权下；本 Assignment 只预排归属）。

（Packet 完；版本 v1.0。Contract 语义变更须同步 Packet 版本与 AC。）
