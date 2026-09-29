# LIMA Implementation Packet — IP-0037 工件签定批次协议（#239 / #57 PR3-d-real 批次形状+cold 重置接入+V5 来源表，零真实调用）

- Packet ID：IP-0037；版本 v1.0（2026-09-29）。
- Coordinator Assignment：CA-IP-0037-v1.0（2026-09-29；Intent Record `.pv_tmp/INTENT_RECORD_IP-0037_2026-09-29.md` 的 M1-M5/F1-F12/I-1..I-5 与主会话裁定点 A-H 由其 R1-R11 裁定；R1-R11 转录见 §15）。
- Source Issue：#239（open；parent #57 保持 open，PR3 不勾选；正文 Scope 1-6 / Non-goals / AC-1..5 由 Coordinator 经 GitHub API 只读 GET 亲取，范围以 CA-IP-0037-v1.0 §Authoritative Inputs #2 为权威转录——本 P&V 会话零网络，未直取远程正文，远程再核验归主会话派发前完成；API dump 存 `.pv_tmp/issue239_api.json`）。
- Operating Mode：SHADOW；Execution Authorization：MAINTAINER_AUTHORIZED（2026-09-29 第四轮；**本任务模型 API 调用预算=0；本 IP 离线交付全程零真实调用/零网络下载/零付费/零远端写**；GitHub 只读 GET 与本地离线测试可继续；不创建具付费效力批准工件；不注入凭据；CI 永远零真实调用）。
- Base SHA（完整 40 位）：`ddb8675fc13e081cff0a7ce151849e64f6fdf85b`（= origin/main = 本地 main = worktree 分支起点，本 P&V 会话亲验）。
- 基线产物指纹（`git ls-tree ddb8675fc13e081cff0a7ce151849e64f6fdf85b` 本 P&V 会话亲验，与 CA §Exact Baseline 逐字一致）：real_run.py blob `cef7a75b0bbcfc2c41f41e78b9e3b32316fac70c`；test_real_run.py blob `d5cabc08034f4dbc7fd8ee931cb8686ae4531b1e`；Dockerfile blob `6928a16238e41228238ff760598fee212f390969`；守护 blob——budget `6c783848`、orchestrate `8655067e`、run `d29928e5`、collect `063ecb41`、expert_timing `dd7aa365`、offline_flow `0f2916c8`、`__init__` `1c478346`、report `e30a5f17`、fixtures `700ec4fc`；十冻结测试文件 `4cde7bdf`（test_v4_baseline）/`edd4c62b`（budget）/`edb2391b`（cli）/`35e6ec6a`（collection）/`ca019d50`（fixtures）/`8e8ab0dc`（manifest）/`539d2fb3`（offline_flow）/`86f584cb`（report）/`0a44cf7d`（result）/`b4a3a076`（v5_negatives）；`baseline_manifest.json` `7ecb39f8`、`python_mvp_support_matrix.json` `3ea94fcf`。
- 本 Packet 的角色：Implementation（阶段 C3）的唯一实现依据；冻结验收测试面（§9/§10，tests/test_v4_baseline_real_run.py v6→v7）的唯一语义来源；ER 复核与 P&V 独立验证的基准。

## 0. 交付物角色声明（强制，先于一切）

1. 本 Packet（本文件）、V5 逐字段来源表（`docs/LIMA_PR3e_V5_Field_Source_Table.md`）与 Dockerfile 恰 2 行 COPY 是 P&V 的 C1 交付物；tests/test_v4_baseline_real_run.py v6→v7 演进（76→90 方法）是 P&V 的 C2 交付物（Frozen Test Commit）；`benchmarks/v4/baseline/real_run.py`（R2/R3/R4/R6 全部实现面）是 **Implementation 的 C3 交付物**。边界不得互换：Implementation 不得修改本 Packet/来源表/测试；P&V 不实现产品功能。
2. **零真实调用绝对禁令（本 Assignment 范围内）**：本 IP 离线交付全程（含分支上、CI 内、pre-merge"顺手验证"）禁止任何真实模型调用、网络下载、付费动作、任何新付费效力批准工件。全部形状/计数/cold 接线验收以离线注入（fake transport/确定性 clock patch/测试构造工件文档）证明；CI 永远零付费模型请求（NFR 延续）。
3. **真实批次执行不在本叶**：本叶只交付"可按准确次数执行的真实测试方案"的承载与离线证明；真实 pilot/正式批另行授权与工件（第四轮授权边界；K1）。任何"已可真实执行"的宣称超出本叶验收面。
4. 冻结面零回退：IP-0024..0036 一切冻结面零回退（§7 各"不变面"节）；`budget.py`/`orchestrate.py`/`run.py`/`collect.py`/`expert_timing.py`/`offline_flow.py`/`report.py`/`fixtures.py`/各级 `__init__.py` **零字节**；canary 清单五项键名/判定式/latch 触发与 index==1 检查时机零改动；预算语义只紧不松；`REAL_RUN_GATE_UNLOCKED`/`require_real_run_unlock` 锁面不触碰。
5. **跨批授权诚实性（M4/R5）**：无跨批总授权机制、无共享门、无全局账本（本叶明文不实现假总授权机制）；每批单独授权+单独工件+每 suite 独立 `BudgetLedger`；跨批总额仅由操作者复核程序（§7.5，规范性契约非代码）承载。不得宣称代码强制跨批总额。

## 1. 需求映射（Packet 头）

```text
Source Issue：#239（open；Scope 1-6 / Non-goals / AC-1..5，经 CA-IP-0037-v1.0 转录）
Issue specification revision：2026-09-29 创建版正文（Scope 1-6 / AC-1..5；Packet ID 占用检查 2026-09-29 由 Coordinator 完成：git grep/log 零命中）
Covered requirements：FR-01、FR-02、FR-03、FR-04、FR-05、FR-06、AC-1、AC-2、AC-3、AC-4、AC-5
Not covered requirements：任何真实模型调用/网络下载/付费动作；新付费效力批准工件；真实 pilot/正式批执行；#57 关闭或 PR3 勾选；#239 关闭（叶合并≠Issue 完成）；#223/#234/#237 重开；orchestrate.py/budget.py/run.py/collect.py/expert_timing.py/offline_flow.py/report.py/fixtures.py/各级 __init__.py 修改；十个冻结测试文件；RealRunErrorCode 十成员/11 检查点/SF-01/身份三形态/请求形状/canary 五项/D1-D8/_estimate_for/预算语义/transport 4 参/证据五件套/G5 子块键集语义变更；旧 {5,5} 路径改义；跨批总授权/共享门/全局账本机制；V5 表识别的模型输出契约/扫描语义变更的实现；真实专家事件
Delivery role：hardening + adapter（PR3-d-real 批次协议切片：形状泛化/形状驱动器/cold 重置接线/离线负例矩阵/跨批诚实登记/V5 来源表，全部离线）
Issue closure impact：PARTIAL（IP-0037 完成 ≠ #239/#57 完成 ≠ 真实批次完成；V5 表内 unavailable 缺口待 DR 呈报后另行叶实现——K4）
Upstream IP/PR/merge commits：CONSUMES IP-0036（main 链 PR #238 merge 9b1eee7 → main=ddb8675；工件族 `REAL_RUN_ARTIFACT_FAMILY`/`reset_cold_state` 独立入口/负例基座为本叶消费面）；先例 IP-0033..0036（冻结测试面六条件演进程序）
```

FR-01..FR-06 为 #239 "Scope (this slice)" 1-6 的规范化编号（语义不变，CA §Goal and Scope）。

| 需求 | 内容（规范化语义） | 本 Packet 承载 | 验收面 |
| --- | --- | --- | --- |
| FR-01 | 工件签定批次形状：attempt_policy 校验泛化（cold≥1/warm≥1 int、max_attempts==cold+warm、canary_required True、canary_first_attempt 0；旧 {5,5,10} 合法实例逐字节不改义）；七维 budget 由工件签定（pilot 工件 batch.calls=5 等） | §7.2（R3）/§7.3（R2） | N2/N3/N5/N6（AC-1/AC-3/AC-4） |
| FR-02 | 形状驱动器：非 {5,5} 形状恰执行 cold+warm 次 frozen `run_baseline_attempt`（逐 attempt 复用冻结门禁/taxonomy/结果文件），聚合构造 BaselineRunSummary；{5,5} 零改动走原 `run_repeats` | §7.4（R6）/§7.3（R2） | N1/N2/N9/N12（AC-1/AC-4） |
| FR-03 | cold 重置接入形状驱动循环：首冷=物化；后续冷=缓存 tarball 重解包+请求体重建+树/请求体摘要+materialization_count+attempt 文档 additive `cold_reset` 观测键；warm=复用记录；reset 失败→typed 失败不得计为 cold 成功 | §7.5（R4/R6 接线） | N4/N9/N13（AC-2） |
| FR-04 | 离线负例矩阵（fake transport，CI 零真实调用）：形状篡改拒绝；第 6/9 次越界拒付零传输；cold 缺重置不得标称；shaped canary 失败零后续 POST；无 usage 不记零；旧 5+5 路径全量回归；失败/超时/取消/latch/部分记账 fail-closed 保持 | §8/§9 | N3/N5/N6/N7/N8/N10/N11/N12 + 既有 76 方法（AC-3/AC-4） |
| FR-05 | 跨批授权诚实性：不实现假总授权机制；docs 登记"每批单独授权+批间操作者复核已封存账本" | §7.6（R5） | N11（AC-3 之双批隔离面）+ 本 Packet §7.6 文本 |
| FR-06 | V5 指标逐字段来源表（docs 交付）：三列制十行；如实记录"当前真实入口只有有界 12 候选 triage+单二元 verdict"；无来源 null+unavailable；需要的扫描语义/输出契约变更形成精确 Decision Request 呈报（不自行造语义） | A2 来源表文档 | A2 入库+Dockerfile COPY 行（AC-5） |
| AC-1 | 形状准确执行：pilot 1c+4w 恰 5 POST、正式批 3c+5w 恰 8 POST（fake transport 计数断言；非失败冒充）；聚合/证据/报告全链在形状路径同构产出 | §7.4/§9 | N1/N2 |
| AC-2 | cold 接线可验证：每 cold attempt 的重置/摘要/计数/观测键在场；缺重置不得标称 cold；warm 复用记录在场 | §7.5/§9 | N4/N9/N13 |
| AC-3 | 越界与篡改 fail-closed：第 6/9 次零传输拒付；形状篡改拒绝；canary latch 保持（shaped 路径） | §8/§9 | N3/N5/N6/N7/N8/N11 |
| AC-4 | 旧路径兼容：{5,5,10} 工件行为逐字节保持（既有全量测试零改动通过）；{5,5} 路由钉扎（零 snapshot-cold-* 目录/15 键 attempt 文档） | §7.3/§9 | 既有 76 方法+N12 |
| AC-5 | 来源表入库且与实现一致；DR（如需）精确呈报 | A2 | A2 文档+N14 纪律承载（来源表无未验证宣称） |

**Not-covered（全团队不得扩张；= CA §Not covered 1-7 全文）**：任何真实模型调用、网络下载、付费动作（含分支上/CI 内/pre-merge"顺手验证"）；任何新付费效力批准工件；真实 pilot/正式批执行。#57 关闭或 PR3 勾选；#239 关闭（叶合并≠Issue 完成）；#223/#234/#237 重开。`orchestrate.py`/`budget.py`/`run.py`/`collect.py`/`expert_timing.py`/`offline_flow.py`/`report.py`/`fixtures.py`/各级 `__init__.py` 任何字节；十个冻结测试文件（本叶非演进面，322 方法参照值）。`RealRunErrorCode` 十成员/`BaselineOrchestrationErrorCode`；11 检查点与 field_path 映射；SF-01 谓词；身份三形态；请求形状（thinking/max_tokens=8000/≤100000 UTF-8 字节）；`CANDIDATE_FILE_CAP=12` 等全部既有 cap 常量数值；`_REPEAT_COUNT=5` 数值与 {5,5} 路径语义（AC-4）；canary 清单五项键名/判定式/latch 触发与 index==1 检查时机；D1-D8 结算表；`_estimate_for` 估计策略；预算语义（只紧不松）；transport 注入契约 4 参；证据五件套文件名与写出纪律；`state_reuse`/`provider_cache`/`timings` 观测子块键集（G5）；`reset_cold_state` 方法签名与五键返回文档；`__all__` 六符号；`run_real_baseline_suite` 签名（本叶零参数变更）。跨批总授权/共享门/全局账本机制；对"代码强制跨批总额"的任何宣称。V5 表内识别的模型输出契约/扫描语义变更的实现（docs-only+精确 DR 呈报）；真实专家事件；`lima/**`/`scripts/**`/前端/`pyproject.toml`/`requirements.txt`/`.github/**`/`.gitignore`/`.gitattributes`；`evaluation_data/**` 全部（本叶零数据产物）；不提交任何输出目录/密钥/run 产物。历史 Packet/两份批准工件/决策包文本修改。

## 2. Design Input Manifest

| # | 输入 | 版本/位置 | 消费方式 |
| --- | --- | --- | --- |
| 1 | CA-IP-0037-v1.0 | `.pv_tmp/COORDINATOR_ASSIGNMENT_IP-0037_2026-09-29.md` | 范围权威；R1-R11 全文转录见 §15；本 Packet 逐条承载 |
| 2 | Intent Record INTENT-IP-0037-20260929-v1 | `.pv_tmp/INTENT_RECORD_IP-0037_2026-09-29.md` | M1-M5 授权语义（M1 治理/M2 批次形状/M3 cold 接入/M4 跨批诚实性/M5 有辨别力负例）；F1-F12 决定性事实；I-1..I-5 待裁点（全部由 CA R2-R7 裁定：I-1→R2、I-2→R3、I-3→R4、I-4→R5、I-5 出处成立→R7） |
| 3 | Maintainer 第四轮授权 | Intent Record 头部（预算=0；M1-M5 原文逐字保全于 Agent 原文）+ 阶段 D 第 1 条（V5 来源表出处） | §0/§12/§14 的授权依据；§7.6 跨批诚实性依据（M4）；§5.6 演进依据（M2/M3） |
| 4 | Source Issue #239 正文 | CA §Authoritative Inputs #2（Coordinator GitHub API 只读 GET 亲取，`.pv_tmp/issue239_api.json`；本 P&V 零网络） | Scope 1-6/Non-goals/AC-1..5（经 CA 规范化为 FR-01..06） |
| 5 | IP-0036 Packet | `docs/LIMA_Implementation_Packet_IP-0036_PR3e_Offline_Integration.md` @ddb8675 | 结构先例（§5.6 演进登记/§10 六条件/§13 Done Commands/§15 R 转录/§16 DR 体例）；§7.4.1 工件族 10 键/§7.4.3 零预算拒付/§7.5.1 cold 语义/§7.5.2 `reset_cold_state` 冻结签名与五键返回/§7.5.4 per-cold 目录 `snapshot-cold-{n}`/§7.5.5 G5 键集边界——**§7.5.2"attempt 文档 15 键不变"句（Packet L264）=本叶 §5.6 显式覆盖登记对象（R4）** |
| 6 | CA-IP-0036-v1.0 | `.pv_tmp/COORDINATOR_ASSIGNMENT_IP-0036_2026-09-28.md` | 结构先例（R 裁定体例/Allowed Files 表/ALLOWED_ONCE/Stop/Done Commands/PR 纪律） |
| 7 | real_run.py @ddb8675 | blob `cef7a75b`（本 P&V 会话亲读关键面：L167 `_REPEAT_COUNT=5`；L268-274 `_ATTEMPT_POLICY_FIELDS` 五键；L345-406 工件族构造与 `REAL_RUN_ARTIFACT_FAMILY`；L755-758 `_require_int_pin`（`type() is int`+等值钉）；L905-916 attempt_policy 逐 pin 校验（cold/warm==5、max==10、canary_required is True、canary_first_attempt==0）；L1377-1429 `__call__`（mode 标签 `index < _REPEAT_COUNT` 边界、index==1 canary、`_estimate_for`）；L1487-1504 `_estimate_for`（index==0 vs 其余）；L1506-1529 `_run_attempt`（index==0 物化 vs 其余复用分支）；L1934-1978 `reset_cold_state`（五键返回文档、`snapshot-cold-{n}`、零 GET、download_ms=None 纪律）；L2304-2361 `_write_core_evidence`（attempts/ 逐 attempt 文档写出）；L2363-2510 入口 `run_real_baseline_suite`（L2444 每 suite 新建 `BudgetLedger`；L2453-2457 `run_repeats` 调用点=R2 路由改造对象；L2458-2479 BaseException 取消路径不吞噬原样重抛）） | §7.2-§7.5 演进对象的逐行依据 |
| 8 | orchestrate.py @ddb8675（禁区） | blob `8655067e`（L220-303 `run_repeats` 亲读：cold 0..repeat-1/warm repeat..2*repeat-1 全局索引、聚合恰经 `result_from_mapping`+`write_result_file` 同构、`result_paths` 目录前后差集、`BaselineRunSummary` 七字段） | §7.4 形状驱动器同构模板 |
| 9 | run.py @ddb8675（禁区） | blob `d29928e5`（L226- `run_baseline_attempt` 亲读：frozen 单 attempt 门禁栈/异常纪律——Exception→保留 taxonomy 失败样本继续、BaseException→持久化后原样重抛） | §7.4 形状驱动器逐 attempt 复用的冻结基元 |
| 10 | tests/test_v4_baseline_real_run.py @ddb8675 | blob `d5cabc08`（v6；76 方法；本 P&V 会话 C0 亲跑 76/76 OK @ddb8675，见 Design Input #18；文件头 v1..v6 演进链注记；`_FakeTransport`/`_RawBodyTransport`/`_chat_response`/`_build_tarball`/`_JumpClock` arrange 基建与 `_RealRunTestCase` helpers（`write_artifact`/`write_synthetic_artifact`/`run_entry`/`read_attempt` 等）全在文件内——R1 单文件演进依据） | §9/§10 演进基础 |
| 11 | Dockerfile @ddb8675 | blob `6928a162`（docs COPY 块亲读：IP-0036 三行簇末行=`docs/LIMA_PR3e_Expert_Review_Package.md`（L66）=本叶恰 +2 行插入位） | C1 +2 行落位依据 |
| 12 | 守护 blob（`git ls-tree ddb8675` 本 P&V 会话程序化复核） | 与 CA §Authoritative Inputs #11 逐字一致（Packet 头基线指纹节） | Done Command 7 blob 守护清单 |
| 13 | report.py / collect.py / fixtures.py / expert_timing.py @ddb8675（禁区） | blobs `e30a5f17`/`063ecb41`/`700ec4fc`/`dd7aa365`（A2 来源表撰写所需关键面亲读：`_REPORT_FIELDS` 19 键/`compression_chain` 五键/`_EXPERT_FIELDS` 三键/domain 子块接线（L1169/L1290-1400 投影）/`_recognize_evaluator_payload`/real-world payload `total_findings`→raw_candidates 聚合/PlatformSources） | A2 三列制"真实来源"列的逐字段代码锚 |
| 14 | worktree/分支 | 主会话已建 `D:/BaseAIProject/LIMA-ip-0037-wt`（分支 `codex/ip-0037-batch-protocol` @ddb8675；tracked 面干净，本 P&V 会话亲验 `git status`） | §5 提交链拓扑的落位 |

哈希真值来源：`git ls-tree ddb8675fc13e081cff0a7ce151849e64f6fdf85b -- <paths>`（本 P&V 会话程序化复核，与 CA §Exact Baseline 一致）。

## 3. Explicitly Rejected Inputs

| # | 被拒输入 | 拒绝理由 |
| --- | --- | --- |
| 1 | attempt_policy 形状白名单 {{5,5},{1,4},{3,5}} | R3 裁定理由②③：授权语义在工件不在校验器（白名单≠已授权，是假保证）；白名单使未来每个已授权新形状都要求代码变更+再冻结。开区间裁定为终局，不得重试 |
| 2 | 复核产物"闭合新测试文件"（如 tests/test_v4_baseline_batch_shapes.py Add） | R1 裁定依据①②：新方法 arrange 基建已在 test_v4_baseline_real_run.py 文件内；v6→v7 单文件演进链是 IP-0033..0036 既定可审计先例。被否决替代方案不得重试 |
| 3 | `cold_reset` 值形态=完整五键内嵌（state_reuse/timings 内嵌）或外部证据文件引用 | R4 被否决值形态：双真相源与发散风险；证据五件套是冻结面不得发明新证据文件。四键闭集为终局 |
| 4 | 任何形式的跨批共享门/全局账本/总额校验代码 | R5 被否决替代方案：M4 明文禁止（假总授权机制）；docs 程序（§7.6）是唯一载体 |
| 5 | 修改 orchestrate.py/run.py 使 `run_repeats` 支持非对称形状 | CA Not-covered 3 + Stop 2：冻结基元只读消费；形状驱动器在 real_run.py 私有承载（R6） |
| 6 | `run_real_baseline_suite` 签名/`__all__`/`_REPEAT_COUNT` 数值/{5,5} 路径任何行为变化 | CA Not-covered 4 + Stop 4：AC-4 逐字节保持；路由在函数体内（R2），零参数变更 |
| 7 | 新增 `RealRunErrorCode` 成员或新错误面 field_path | R3 错误面零变化：拒绝仍为既有 `APPROVAL_ARTIFACT_INVALID` 沿 `$.attempt_policy.*`；零新增错误码 |
| 8 | cold 接线改 `state_reuse`/`provider_cache`/`timings` 子块键集（G5）、`reset_cold_state` 签名/五键返回文档、RunSpec、结算/预算策略 | CA Not-covered 4 + Stop 13：R4/R6 均在键集不变路径内（cold_reset 是顶层 additive 键） |
| 9 | 第 6/9 次越界测试以"失败冒充"计数（以失败 attempt 的 POST 计数充当成功面） | M2 明文"非失败冒充"+AC-1：成功路径计数断言；越界面独立为 N5/N6 |
| 10 | V5 来源表内直接实现模型输出契约/扫描语义扩展，或表内宣称未验证状态 | R7 + Stop 15：docs-only+末节 DR 草案呈报；AC-5"与实现一致"禁止未验证宣称 |
| 11 | 第 6 个变更文件、Dockerfile 超 2 行、触碰 `lima/**`/`scripts/**`/`evaluation_data/**`/十冻结测试文件 | R1 + Stop 5：Allowed Files 终形=恰 2 Add+3 Modify |
| 12 | 以 synthetic 冒充真实扫描计数/专家分钟；domain 缺席写常数 | #239 Scope 6 + IP-0036 §0.4 诚实纪律延续：无来源→null+unavailable |
| 13 | 吞噬/转换/延迟重抛 BaseException；形状驱动器包装 `run_baseline_attempt` 逸出的 BaseException | R6-③ + Stop 16：驱动器自身不捕获；入口层既有 try/except 对两路径同等生效 |

## 4. Goal / Non-goals

**Goal**：在 IP-0036 版产品（main=ddb8675）上把已交付的离线能力变为"可按准确次数执行的真实测试方案"并以受审查单 PR 入库：①attempt_policy 校验泛化（开区间；旧 {5,5,10} 合法实例逐字节不改义）；②入口路由（{5,5}→`run_repeats` 原路径逐字节零改动；其他合法形状→新私有形状驱动器）；③形状驱动器恰执行 cold+warm 次 frozen `run_baseline_attempt`、聚合同构构造 `BaselineRunSummary`；④cold 重置接入形状驱动循环（首冷=物化；后续冷=reset 语义接线+additive `cold_reset` 观测键；warm=复用；reset 失败→typed 失败）；⑤离线负例矩阵（篡改/越界/缺重置/canary latch/无 usage/双批隔离全 fail-closed）；⑥跨批授权诚实性 docs 登记（含操作者复核程序）；⑦V5 指标逐字段来源表（三列制十行+末节精确 DR 草案）。全部离线交付：零真实调用、零付费、CI 零付费模型请求。

**Non-goals**：见 §1 Not-covered 段（CA 原文）。真实 pilot/正式批执行、真实专家事件、V5 表识别的契约缺口实现不在本 Assignment 授权内。

## 5. 文件边界（CA R1：恰 2 Add + 3 Modify；零 Delete；单 PR `codex/ip-0037-batch-protocol` → main）

### 5.1 Files to Add（恰 2）

| 文件 | Owner/阶段 | 说明 |
| --- | --- | --- |
| `docs/LIMA_Implementation_Packet_IP-0037_Batch_Protocol.md` | P&V（C1，本文件） | 本 Packet；承载 CA R1-R11 全部裁定+§5.6 冻结面演进依据登记（含 R4 对 IP-0036 §7.5.2"15 键不变"的显式覆盖）+§7.6 操作者跨批复核程序+机械判据清单 |
| `docs/LIMA_PR3e_V5_Field_Source_Table.md` | P&V（C1，与 Packet 同一提交） | V5 逐字段来源表（R7：三列制/恰十行/现状如实/末节 DR 草案；docs-only 零实现） |

### 5.2 Files Allowed to Modify（恰 3）

| 文件 | Owner/阶段 | 边界 |
| --- | --- | --- |
| `Dockerfile` | P&V（C1，与两 docs 同一提交） | **恰 +2 行**：两条 `COPY --chown=lima:lima docs/<file> ./docs/`（A1 Packet/A2 来源表，按此位序插 `docs/LIMA_PR3e_Expert_Review_Package.md` 行【L66】后）；既有行零改动。基线 blob `6928a16238e41228238ff760598fee212f390969` |
| `tests/test_v4_baseline_real_run.py` | P&V（C2，冻结面演进 v6→v7；76→90） | R8 演进+新增恰 14 方法（§9）；六条件程序（§10）；基线 blob `d5cabc08034f4dbc7fd8ee931cb8686ae4531b1e` 永久在链 |
| `benchmarks/v4/baseline/real_run.py` | Implementation（C3） | R2/R3/R4/R6 全部实现面（形状泛化+路由+形状驱动器+cold 重置接线+cold_reset 观测键）。基线 blob `cef7a75b0bbcfc2c41f41e78b9e3b32316fac70c` |

### 5.3 Read-only Reference Files（只读消费）

`benchmarks/v4/baseline/` 其余全部模块（budget/orchestrate/run/collect/expert_timing/offline_flow/report/fixtures）与各级 `__init__.py`（`run_repeats`/`run_baseline_attempt`/`BaselineRunSummary`/`BudgetLedger` 冻结基元只读消费）；`lima/baseline_run_result.py`/`lima/baseline_run_spec.py`（只读导入面）；IP-0024..0036 Packet、两份批准工件（2026-09-27/28）、决策包；`evaluation_data/**` 全部；`.pv_tmp/` 各记录；`D:\BaseAIProject\LIMA-real-runs\**`（两批证据，只读）。

### 5.4 Files Forbidden（diff 必空；Done Command 7 逐 blob 守护）

`benchmarks/v4/baseline/` 其余全部模块与各级 `__init__.py`；`tests/` 其余全部既有文件（十个 v4 冻结测试文件 322 方法与其他）；`evaluation_data/**` 全部（含 baseline_manifest.json/python_mvp_support_matrix.json/两批真实运行目录）；`lima/**`；`scripts/**`；`docs/` 其余全部（含历史 Packet、批准工件、决策包）；`pyproject.toml`/`requirements.txt`/`.gitignore`/`.gitattributes`/`.github/**`/前端；不提交任何输出目录/密钥/run 产物。

### 5.5 提交链拓扑（CA §Handoff/Done Command 8；冻结）

C1 = 两 docs + Dockerfile 恰 2 行（2 Add + 1 Modify，同一提交，前缀 `[IP-0037][PV]`）→ C2 = test_v4_baseline_real_run.py v6→v7 落定（1 Modify；Frozen Test Commit；提交信息**必须含** `"[IP-0037][PV] Freeze acceptance tests v7 (RED)"` 字样；RED 证据先于冻结落盘并独立日志归档 `.pv_tmp/RED_IP-0037_2026-09-29/`）→ C3 = real_run.py（1 Modify，前缀 `[IP-0037][IMPL]`；**必须以 C2 为祖先**，Done Command 8）→ C-final（P&V 独立验证；如触发 ALLOWED_ONCE/修复提交须引用编号，前缀 `[IP-0037][CI]` 或所属角色前缀）。单 PR；不 push（合并/推送/评论由主会话按 Maintainer 授权执行，P&V/IMPL 零远端写）。

### 5.6 与其他活动 IP 的冲突分析（冻结面演进依据登记）

无并行活动 IP 占用本切片路径（IP-0037 编号未占用，CA §Authoritative Inputs #2 占用检查）。**冻结面演进依据显式登记（IP-0033..0036 Packet §5.6 先例）= 2026-09-29 第四轮 Maintainer 授权（#239 Scope 1-5）**，演进对象与覆盖登记：

1. **attempt_policy 校验谓词**（real_run.py L905-916）：pin（cold==5/warm==5/max==10）→ 开区间（R3）。`_ATTEMPT_POLICY_FIELDS` 五键闭集与键序不变；错误码 `APPROVAL_ARTIFACT_INVALID` 与 field_path `$.attempt_policy.*` 不变；`_require_int_pin` 的 `type() is int` 纪律沿用到新谓词（bool 陷阱拒绝）。
2. **入口路由**（real_run.py L2453-2457 调用点）：`(cold,warm)==(5,5)` → 既有 `run_repeats(spec_mapping, manifest, guarded, root, repeat=_REPEAT_COUNT, sources=sources)` 调用点**逐字节零改动**；其他合法形状 → R6 私有驱动器（R2）。`run_real_baseline_suite` 签名零变化；`_ENTRY_PARAM_ORDER`/`_ENTRY_KEYWORD_ONLY` 不变。
3. **`_run_shaped_repeats` 私有函数**（新；R6 冻结签名，§7.4.1）：不入 `__all__`（六符号逐字冻结）。
4. **guarded evaluator 形状携带**：`__call__` mode 标签边界（现钉 `index < _REPEAT_COUNT`）与 `_run_attempt` cold/warm 分支判据必须由已校验形状驱动；默认构造（形状 (5,5)）行为**逐字节保持**（内部携带机制如私有 kw-only 形状参数由 Packet 定稿登记；公开签名零变化；R6 实现边界）。
5. **`_AttemptRecord` additive 可选字段 `cold_reset` + `to_document()` 发射规则**（R4，§7.5.2）：**本条即对 IP-0036 Packet §7.5.2"attempt 文档 15 键不变"（该文 L264 附近原句）的显式覆盖登记**——演进为"非形状驱动路径 15 键不变；形状驱动路径 cold attempt 16 键（additive 单一顶层键 `cold_reset`）"。演进依据=第四轮授权 M3"attempt 记录 additive cold_reset 观测键"（additive-only）；G5 子块键集（state_reuse/provider_cache/timings）仍零变化。IP-0036 Packet 文本本身零改动（历史文档不改写；本节为唯一覆盖登记处）。
6. **新 import 白名单**（real_run.py，均既有符号，零新第三方依赖）：`run_baseline_attempt`（自 `benchmarks.v4.baseline.run` 或经 orchestrate 模块属性）、`from_mapping as result_from_mapping`（`lima.baseline_run_result`）、`write_result_file`（`benchmarks.v4.baseline.run`）——超出即 Stop 9。
7. **测试面**：tests/test_v4_baseline_real_run.py v6→v7（§10 六条件；恰 14 新方法，76→90）。
8. **Dockerfile**：恰 +2 行（A1/A2 COPY；插入位=L66 后）。

历史文档零改动；本节即唯一演进依据登记处。IP-0024..0036 一切其余冻结面禁止触碰。

## 6. 依赖、网络、文件系统与权限边界

- **依赖**：零新增第三方依赖。产品侧唯一获准新 import=§5.6-6 三符号（既有符号再导入或经模块属性消费）。测试文件（M2）零新增 import（新增方法全部复用文件内既有 arrange 基建与已导入符号）。
- **网络**：测试全离线、fake transport（内存 tarball GET+脚本化 chat POST）/确定性 clock patch/预置缓存；永不触网（既有 `_forbidden_network_roots` 断言延续）。**本 IP 离线交付期间任何真实网络/下载/付费调用 = Stop Condition 1（绝对禁令）**。本 P&V 会话零网络（Packet 制作与冻结全程本地；CA 已完成远程只读核验）。
- **文件系统**：证据文件只写调用方提供的一次性输出目录（离线测试写 tempdir）；库内除 §5.1/§5.2 五文件外零写入；不读环境变量/配置/.env（h1 钉扎面保持）。
- **数据库/容器/远端写**：无数据库；容器面仅 Dockerfile +2 COPY 行；零远端写（不 push、不开 PR、不关 Issue、不改 Ledger 远端状态——合并/推送/评论由主会话按 Maintainer 授权另行核发）。
- **凭据**：api_key 仍为显式必填参数，永不落盘/入日志/入错误消息/入证据（e2/rd5/a3 探针面保持）；本叶零真实调用故 api_key 永不被真实使用（fake transport 面证明）。
- **clock**：`_monotonic` 模块缝（IP-0035 冻结）继续是唯一 wall 时源；本叶零新时源、零真实 sleep。

## 7. 实现契约细化（Packet 定稿；R2/R3/R4/R5/R6 全部落位）

### 7.1 规范性声明（先行）："形状良构 ≠ 批次授权"

attempt_policy 开区间校验（R3）只回答"形状良构"（cold≥1/warm≥1 int/max==和/canary 钉），**不授予任何调用额度**。每批调用授权由工件签定的七维预算承载（pilot 工件 batch.calls=5、正式批工件 batch.calls=8 等），`BudgetLedger` 精确执行、越界拒付（N5/N6）。一个良构形状配零预算工件=零调用（IP-0036 §7.4.3(a) 先例延续）。四层承接"未授权形状"之虑：本声明（Packet 显式登记）、篡改负例矩阵（N3）、三已知形状逐形状钉扎（N1/N2/N6）、开区间成员 {2,2} 良构性钉扎（N6，防未来静默重引入白名单）。

### 7.2 real_run.py：attempt_policy 校验泛化（R3；FR-01）

**谓词（冻结，开区间）**：

```text
type(policy["cold"]) is int and policy["cold"] >= 1
type(policy["warm"]) is int and policy["warm"] >= 1
type(policy["max_attempts"]) is int and policy["max_attempts"] == cold + warm
policy["canary_required"] is True
type(policy["canary_first_attempt"]) is int and policy["canary_first_attempt"] == 0
```

- type 精确判定沿既有 `_require_int_pin` 的 `type() is int` 纪律（bool 陷阱拒绝：`True` 是 bool 非 int）。
- **错误面零变化**：任何违规仍为既有 `APPROVAL_ARTIFACT_INVALID`；field_path 沿 `$.attempt_policy.cold`/`$.attempt_policy.warm`/`$.attempt_policy.max_attempts`/`$.attempt_policy.canary_required`/`$.attempt_policy.canary_first_attempt`；`_ATTEMPT_POLICY_FIELDS` 五键闭集与键序不变；零新增错误码。
- **旧 {5,5,10} 是开区间内合法实例**（5≥1/5≥1/10==5+5/True/0），加载与执行逐字节不改义（AC-4；既有 76 方法零改动通过）。
- 裁定理由全文登记（R3）：①第四轮授权 M2/Scope 1 原文逐字给出开区间谓词——白名单是授权文本中不存在的额外限制，实施者无权加设；②授权语义在工件不在校验器（每批调用授权由七维预算承载，ledger 精确执行、越界拒付——校验器放宽形状类不授予任何调用额度）；③白名单使未来每个已授权新形状都要求代码变更+再冻结，治理成本翻倍而安全增益为零；④"未授权形状 silently 合法"之虑由 §7.1 四层承接。

### 7.3 real_run.py：入口路由（R2；FR-01/FR-02/AC-4）

- 路由判据冻结为**仅 attempt_policy 形状**：加载契约的 `(cold, warm) == (5, 5)` → 既有 `run_repeats(spec_mapping, manifest, guarded, root, repeat=_REPEAT_COUNT, sources=sources)` 调用点（L2455-2457）**逐字节零改动**；任何其他合法形状 → `_run_shaped_repeats`（§7.4）。
- **与工件键（合成/llamafactory）、七维预算数值、run_name 一概无关**——合成工件键配 {5,5,10} 工件仍走旧路径（N12 钉扎）。
- 路由读数来源=已通过 §7.2 校验的契约内 attempt_policy 值（**不得二次解析分叉**——不得从文档原文或另一解析路径重读形状）。
- 测试双路径各自钉扎：{5,5} 路由钉扎方法（N12：行为等价旧路径+零 `snapshot-cold-*` 目录+15 键 attempt 文档）；形状驱动路径由 pilot/正式批方法族（N1/N2）钉扎。

### 7.4 real_run.py：形状驱动器 `_run_shaped_repeats`（R6；FR-02）

#### 7.4.1 冻结签名

```python
def _run_shaped_repeats(
    spec_mapping, manifest, guarded, output_dir, *, cold, warm, sources=None
) -> BaselineRunSummary
```

私有函数，**不入 `__all__`**（六符号逐字冻结；测试经模块属性访问——本条为 Packet 定稿登记）。`cold`/`warm` 为已通过 §7.2 校验的形状分量（驱动器不重复校验形状；R6-④）。

#### 7.4.2 语义（冻结）

1. **恰 `cold+warm` 次 frozen `run_baseline_attempt` 调用**：cold 索引 `0..cold-1` mode="cold"、warm 索引 `cold..cold+warm-1` mode="warm"（与 `run_repeats` 的全局索引约定同构）。
2. **聚合恰经 frozen `result_from_mapping`+`write_result_file` 同构**：samples 按 attempt_index 排序、schema_version=1、digest 前缀下一空闲序号（`{digest16}-run-{cold+warm+1}.json` 聚合文件）；`result_paths` 目录前后差集同构；返回自构造 `BaselineRunSummary` 七字段同构（attempts/result_paths/aggregate/aggregate_path/aggregate_sha256/status）。**聚合状态语义沿冻结统计规则（`lima/baseline_run_result.py` `_COLD_MIN_SUCCESSES=3`/`_WARM_MIN_SUCCESSES=5`，只读禁区零改动）**：全成功正式批 {3,5}（3c+5w）恰达下限→`sufficient_sample`；全成功 pilot {1,4}（1c<3）与 {2,2}（2<3 且 2<5）→`insufficient_sample`（诚实统计判定，非失败——"非失败冒充"判据=全部 attempt 文档 outcome=="success"/error_code None/canary passed/POST 计数恰等，Packet §9.1 逐方法登记）。
3. **cancellation 语义与现有路径一致**：驱动器自身**不捕获** `run_baseline_attempt` 逸出的 BaseException（该基元已持久化该 attempt 后原样重抛）；入口层既有 try/except（settle_cancelled→五件套部分证据→原样重抛）不变且对两路径同等生效。
4. **不重复校验形状**（形状合法性已由 §7.2 入口校验面承载）。

#### 7.4.3 cold attempt 接线（冻结；FR-03）

- **index 0**=既有物化路径（`_run_attempt` index==0 分支逐字节保持）；本 attempt 的 `cold_reset` 观测=（performed=False, materialization_count=1, 树摘要, 请求体摘要）（§7.5.2）。
- **cold index>0**=reset 语义接入：经 `reset_cold_state` 同源机制（重解包至 `snapshot-cold-{n}`+请求体重建）后执行本 attempt 的 `_chat`；`state_reuse`=(materialized=True, snapshot_reused=False, request_body_rebuilt=True)（四键含 process_identity，G5 键集不变）；`cold_reset`=(performed=True, materialization_count 递增, 两摘要)（§7.5.2）；零传输 GET、download_ms=None 纪律。
- **reset 失败→typed RealRunError 失败（settle→保留失败样本，驱动循环继续），不得计为 cold 成功**：该 attempt outcome=failure 且 `cold_reset.performed` 不得为 true（观测上 materialized 如实为非 True——失败相位未完成物化）（N7）。
- **warm attempt**：既有复用路径+`state_reuse`=(False, True, False)，`cold_reset` 缺席。

#### 7.4.4 实现边界（冻结）

- guarded evaluator 的 mode 标签边界（`__call__` 现钉 `index < _REPEAT_COUNT`）与 `_run_attempt` 的 cold/warm 分支判据必须由已校验形状驱动；**默认构造（形状 (5,5)）行为逐字节保持**（内部携带机制如私有 kw-only 形状参数由 Packet 定稿登记——形态由 Implementation 在此前提下定稿一次并在 Completion Summary 登记；公开签名零变化）。
- canary 检查保持在 index==1（任一合法形状 cold≥1/warm≥1 ⟹ max≥2，index 1 恒存在；N8 钉扎 shaped 路径 latch）。
- `_estimate_for` 估计策略零变化（cold>0 沿既有非零索引分支；body_bytes 为重建成后确定性等值——与首次构造恒等，N4 摘要恒等断言的依据）。
- **{5,5} 走原 `run_repeats` 零改动（R2）**。

### 7.5 real_run.py：`cold_reset` 观测键与键集边界（R4；FR-03/AC-2）

#### 7.5.1 覆盖登记（IP-0036 §7.5.2"15 键不变"的显式演进）

IP-0036 §7.5.2 的"attempt 文档 15 键不变"叶内冻结显式演进为："**非形状驱动路径 15 键不变；形状驱动路径 cold attempt 16 键**"（additive 单一顶层键 `cold_reset`）。依据=第四轮授权 M3（additive-only）；`state_reuse`/`provider_cache`/`timings` 子块键集零变化（G5 不变路径保持；`cold_reset` 是顶层 additive 键，不是任何子块的新键）。

#### 7.5.2 在场规则与值形状（冻结）

**在场规则**：键在场当且仅当形状驱动路径的 cold attempt（含 index 0）；形状驱动路径的 warm attempt 与一切 {5,5} 旧路径 attempt 该键**缺席**（键不在文档中——非"键在场值为 None"；N13 钉扎 16/15/15 矩阵）。

**值形状（四键闭集，dict）**：

```json
{
  "performed": false,
  "materialization_count": 1,
  "snapshot_tree_sha256": "<64-hex>",
  "request_body_sha256": "<64-hex>"
}
```

- `performed`：index 0（初始物化）=false；cold>0（可验证重置）=true。**使"缺重置不得标称 cold 成功"可机械断言**（reset 失败→typed 失败→outcome=failure 且 performed 不得为 true）。
- `materialization_count`：本 attempt 重置相位完成后的物化计数（初始物化=1，每次重置 +1）；把"真实 cold 计数=物化重置次数"契约逐 attempt 携带（跨 attempt 单调 1,2,3,… 可断言；与 `reset_cold_state` 五键返回文档同源）。
- `snapshot_tree_sha256`：本 attempt 所用快照树摘要（`compute_tree_fingerprint` 冻结算法；重置 attempt 与首次物化恒等——重解包确定性）。
- `request_body_sha256`：本 attempt 所用请求体字节摘要（重建成后与首次构造恒等）。

**被否决的值形态（不得重试）**：①完整五键内嵌（state_reuse/timings 已是 attempt 文档顶层块，内嵌造成双真相源与发散风险）；②外部文件引用（证据五件套是冻结面，不得发明新证据文件）。

#### 7.5.3 键集边界（不变面）

`reset_cold_state` 方法签名与五键返回文档逐字不动；`state_reuse`/`provider_cache`/`timings` 子块键集（G5）零变化；RunSpec/预算/结算策略零触碰（K3：形状驱动 cold attempt 的真实批结算细则归决策包 v4/未来真实批 DR）。若实现需要改上述任何面 → Stop 13 + Decision Request。

### 7.6 跨批授权诚实性与操作者复核程序（R5；FR-05；规范性契约非代码）

**跨批授权诚实性声明（冻结登记）**：

1. 本产品**无跨批总授权机制、无共享门、无全局账本**；不实现任何假总授权机制（M4 明文）。
2. **每批单独授权+单独工件**：每个批次（pilot/正式批）由其各自的批准工件独立授权（attempt_policy 形状+七维预算由工件签定）；`run_real_baseline_suite` 每 suite 新建独立 `BudgetLedger`（L2444 保持），账本从零起算、不继承任何先前批次的已耗额度（N11 行为证明）。
3. 批次间状态隔离由既有一次性目录门承载：批次 2 指向批次 1 的已封存 output_root → `REAL_RUN_OUTPUT_NOT_EMPTY` @ `$.output_root` 拒绝、零传输调用（N11-③）。
4. **本叶代码只能证明"每批账本独立且各自 fail-closed"**；不得宣称代码强制跨批总额。

**操作者复核程序（规范性契约，非代码；M4/R5-③）**：

1. 全部批次封存后（各 run 目录证据五件套写毕），操作者逐一打开各已封存 run 目录的 `ledger.json`。
2. 对每个 run 读取 `batch.calls`（该批实际记账调用数）并求和。
3. 将求和结果与 Maintainer 本轮授权声明的总量**人工比对**（授权文本为唯一真值源）。
4. 任何超出（求和 > 授权总量）即停：保留全部证据、不启动新批、上报 Maintainer（该程序发现的是授权纪律违规，不是产品缺陷——产品按设计只保证单批 fail-closed）。
5. 本程序是跨批总额的唯一承载机制；不得以任何自动化/代码化"总额校验"替代（Stop 14）。

### 7.7 V5 逐字段来源表（R7；FR-06/AC-5；docs 交付，P&V C1）

载体=`docs/LIMA_PR3e_V5_Field_Source_Table.md`（A2；docs-only，零实现）。三列制（冻结）：`真实来源（产生点：模块/函数/数据流位置）| 当前缺口（为何不可得/仅部分可得）| 可验证证据（离线可复现断言/测试/工件指针）`；行集恰十行（Signal/Issue/Hypothesis/VEP/RVR/stage_outcome/专家分钟/原始候选/压缩队列/资源指标）；现状如实记录（当前真实入口=llm-bounded-triage 有界 12 候选+单二元 verdict；domain 子块缺席→null+unavailable 纪律；专家分钟缺席纪律保持）；末节=精确 DR 草案（模型输出契约扩展与扫描语义扩展两组互斥选项，呈报 Maintainer 决策，不自行造语义）。表内不得宣称未验证状态（AC-5）。全部代码锚见 Design Input #13。

## 8. 离线负例矩阵（FR-04/AC-3；全 fake transport，CI 零真实调用）

| # | 负例 | 断言面（冻结） | 方法 |
| --- | --- | --- | --- |
| 1 | 形状篡改拒绝矩阵 | cold=0/warm=0/负数/非 int（str）/bool 陷阱（True）/max≠cold+warm（{5,5,9}）→ `APPROVAL_ARTIFACT_INVALID` 精确 `$.attempt_policy.*` field_path；canary_required False/canary_first_attempt=1 同拒 | N3 |
| 2 | pilot 满额后第 6 次 guarded 调用越界 | 5 成功后第 6 次 → `BATCH_BUDGET_EXCEEDED` @ `$.budget.batch.calls`、零传输（chat_calls 不变） | N5 |
| 3 | 正式批 8 后第 9 次 | 同上（8 成功后第 9 次） | N6 |
| 4 | cold 缺重置不得标称 | 注入 reset 失败（删除缓存 tarball）→ 该 attempt typed 失败、outcome=failure、materialized 非 True、cold_reset.performed 非 true；suite 继续 fail-closed（warm 复用路径不受污染） | N7 |
| 5 | shaped canary latch | attempt-0 触发清单失败（usage 超预约）→ index1 清单拒 → 余下零 POST、`REAL_RUN_CANARY_FAILED` | N8 |
| 6 | 双批隔离 | 批 1 满额封存→批 2 独立目录独立 ledger 从零起算不继承（同进程两 suite 互不影响）；伪造复用批 1 输出目录→一次性目录门拒绝零调用 | N11 |
| 7 | 无 usage 不记零（shaped） | shaped 路径 warm attempt 缺 usage → `REAL_RUN_USAGE_MISSING` 违规、非零记账；violations 计数+1 | N14 |
| 8 | 旧 10 次路径全量回归 | 既有 76 方法零改动全绿即证（AC-4） | 既有 76 |

（失败/超时/取消/latch/部分记账 fail-closed 保持由既有 76 方法承载——本叶零弱化。）

## 9. 测试矩阵（M2 单文件面；R8 预算：76 存留+恰 14 新增=90；基线 76）

### 9.1 新增方法（14 个；类=TestBatchShapeProtocol 新类，挂 `TestArtifactFamilyAndColdReset` 之后）

| 方法 | 覆盖 | 断言面（冻结） |
| --- | --- | --- |
| `test_batch_protocol_static_surface_frozen` | FR-01/AC-4/R6/§5.6 | 静态面：`_REPEAT_COUNT==5` 不变；`__all__` 六符号；`_ATTEMPT_POLICY_FIELDS` 五键序；`RealRunErrorCode` 十成员；`_run_shaped_repeats` 在场且签名冻结（参数序 == (spec_mapping, manifest, guarded, output_dir)+kw-only (cold, warm, sources=None)；inspect 复核） |
| `test_pilot_shape_executes_exactly_five_posts` | FR-01/FR-02/AC-1/R2/R3/R6 | 工件 {cold:1,warm:4,max:5}+batch.calls=5 变体：fake transport chat_calls==5（成功路径非失败冒充判据：5 件 attempt 文档全 outcome=="success"/error_code None/canary passed）；attempt 文档恰 5 件；mode 序列==["cold"]+["warm"]*4；canary 在 index1 通过；aggregate 在场（`{digest16}-run-6.json` 聚合+result_paths run-1..5）；status=="insufficient_sample"（冻结统计规则 1c<3 如实判定，§7.4.2） |
| `test_formal_batch_executes_exactly_eight_posts` | FR-01/FR-02/AC-1/R2/R3/R6 | 工件 {3,5,8}+batch.calls=8：chat_calls==8、status=="sufficient_sample"（3c+5w 恰达冻结下限）、attempt 文档 8 件、mode 序列 cold×3+warm×5、ledger batch calls==8 |
| `test_formal_batch_cold_reset_chain_observability` | FR-03/AC-2/R4/R6 | cold attempts 0/1/2 各有 `cold_reset` 键：attempt0 {performed:False, count:1}、attempt1 {performed:True, count:2}、attempt2 {performed:True, count:3}（count 单调 1→2→3）；树摘要/请求体摘要与首次物化恒等（PC3 复算：`compute_tree_fingerprint(snapshot)` 与 sha256(chat_payloads[0])）；`snapshot-cold-2`/`snapshot-cold-3` 目录在场；cold>0 state_reuse==(T,F,T)；warm 3-7 无 cold_reset 且 state_reuse==(F,T,F)；download_calls==1（重置零 GET） |
| `test_shape_tamper_matrix_rejected` | FR-01/AC-3/R3 | 篡改矩阵逐 subTest：cold=0/warm=0/cold=-3/warm="4"/cold=True/max=9（{5,5,9}）/canary_required=False/canary_first_attempt=1 → 逐例 `APPROVAL_ARTIFACT_INVALID` + 精确 `$.attempt_policy.<键>` field_path（loader 面，零传输） |
| `test_open_interval_shape_two_two_executes` | FR-01/AC-1/R3 | {2,2,4} 良构合法钉扎：加载执行恰 4 POST、attempt 4 件、mode 序列 cold×2+warm×2、status=="insufficient_sample"（冻结统计规则 2<3 如实，§7.4.2）（防未来静默重引入白名单）；对照面 {2,3,6}（max≠和）→ `APPROVAL_ARTIFACT_INVALID` @ `$.attempt_policy.max_attempts` |
| `test_pilot_sixth_guarded_call_refused_zero_transport` | FR-04/AC-3/R5/R6 | pilot 契约直接构造 evaluator+`_run_shaped_repeats` 驱动 5 次全成功（5 POST；canary 清单所需 attempt-0 结果文件由驱动循环写出）→ 第 6 次 guarded() → `BudgetGateError`（`BATCH_BUDGET_EXCEEDED` @ `$.budget.batch.calls`）零传输（chat_calls 仍 5）；被拒 attempt 记账 outcome=failure |
| `test_formal_batch_ninth_guarded_call_refused_zero_transport` | FR-04/AC-3/R5/R6 | 正式批契约同构：`_run_shaped_repeats` 驱动 8 次成功后第 9 次 guarded() → 同拒付、零传输 |
| `test_cold_reset_failure_not_claimed_as_cold_success` | FR-03/AC-2/R4/R6 | {3,5} 入口运行+首 POST 后删除缓存 tarball（注入 transport 钩子）→ cold attempt 1/2 typed 失败：outcome=="failure"、failure_code=="EXECUTION_ERROR"、state_reuse.materialized 非 True、cold_reset.performed 非 true；suite 继续 fail-closed（warm 3-7 仍成功；总 POST==6==1+0+0+5；status=="insufficient_sample"——cold 成功仅 1<3 如实） |
| `test_shaped_canary_failure_latches_zero_follow_on_posts` | FR-04/AC-3/R6 | {1,4}+attempt-0 usage 超预约 → index1 清单拒 → canary failed；chat_calls==1（余下零 POST）；attempts 1-4 全 `REAL_RUN_CANARY_FAILED`；status insufficient_sample |
| `test_dual_batch_ledger_isolation_and_root_reuse_refused` | FR-05/AC-3/R5 | 同进程双批：批 1（pilot 工件+独立 root）恰 5 POST 成功封存；批 2（独立工件+独立 root）独立 ledger 从零起算（再恰 5 POST 成功=不继承证明；两 run ledger.json 各自 batch.calls==5）；伪造批 3 复用批 1 输出目录 → `REAL_RUN_OUTPUT_NOT_EMPTY` @ `$.output_root` 零传输 |
| `test_default_shape_routes_to_run_repeats_verbatim` | FR-02/AC-4/R2 | 既有 {5,5,10} 工件走原路径：10 POST、`{digest16}-run-11.json` 聚合序号/result_paths run-1..10 与基线一致、零 `snapshot-cold-*` 目录、attempt 文档全 15 键（无 cold_reset）；合成键配 {5,5} 工件同走旧路径（路由与工件键无关锚） |
| `test_cold_reset_key_presence_matrix` | FR-03/AC-2/R4 | 三态矩阵：shaped cold attempt 文档 16 键（cold_reset 四键闭集在场）；shaped warm attempt 15 键（cold_reset 缺席——键不在文档，非 None 值）；{5,5} 旧路径 attempt 全 15 键 |
| `test_shaped_missing_usage_violation_not_zero` | FR-04/AC-3/R8⑫ | {1,4} shaped：index≥2 的 warm attempt 返回无 usage → `REAL_RUN_USAGE_MISSING`（outcome failure、violations==1）；成功 attempts 的 consumed 记账不含该 attempt 的任何零值伪记（ledger consumed==成功 attempts 的脚本值之和，PC3 复算） |

### 9.2 (b) 类值更新（全部由 R2-R7 裁定驱动，无一处实现便利）

模块 docstring 追加 v7 演进段（演进链注记）；新常量纯增量（`_PILOT_COLD=1`/`_PILOT_WARM=4`/`_FORMAL_COLD=3`/`_FORMAL_WARM=5`/`_TWO_TWO_COLD=2` 等形状常量与 shaped 工件构造 helper，全部为新增私有 arrange 基建）。**既有 76 方法零改动、零弱化**（旧 10 次路径回归即 AC-4 证据）。

### 9.3 RED 形态（Modify 型 IP；产品已存在；逐方法归因）

对**未修改产品（ddb8675 版）**运行 v7（C1 已落库后、C2 冻结前）：

- **泛化缺席面**（N1/N2/N4/N7/N8/N9[6th]/N10[9th] via 直接构造、N11、N13、N14 及 {2,2} 面）：非 {5,5} 工件被现行 pin 校验（L907-910 cold/warm==5、max==10）拒绝 → `APPROVAL_ARTIFACT_INVALID` @ `$.attempt_policy.cold` → 方法失败=新能力缺席（泛化校验/驱动器/cold_reset 键缺失）。
- **静态面**（`test_batch_protocol_static_surface_frozen`）：`_run_shaped_repeats` 缺席（getattr None）→ RED；其余静态锚（`_REPEAT_COUNT`/`__all__`/错误码族）按设计通过（同方法内混合态，逐断言归因）。
- **守卫性负例**（`test_shape_tamper_matrix_rejected`）：现行 loader 对全部篡改例同拒（同码同 field_path）→ **按设计通过**（如实归因）。
- **旧路径钉扎**（`test_default_shape_routes_to_run_repeats_verbatim`）：{5,5} 现行为即目标行为 → **按设计通过**。
- 逐方法"RED 失败/按设计通过"归因表强制（归档 `.pv_tmp/RED_IP-0037_2026-09-29/`）；基线态证明=C0（76/322/2684 绿）。

## 10. 冻结测试面演进程序（M2 单文件适用；CA R8 六条件全文；正式 Packet 级一次性授权）

**冲突裁定**：IP-0037 的产品语义变更（形状泛化/路由/形状驱动器/cold 接线）必然触碰 IP-0032..0036 冻结测试面 `tests/test_v4_baseline_real_run.py`。**裁定：允许该文件以受控方式演进至冻结版本 v7**（先例=IP-0033/0034/0035/0036 Packet §10）。演进是产品语义驱动（非机械缺陷），ALLOWED_ONCE 不适用、不得以其消化——授权依据=CA-IP-0037-v1.0 R8+本节。**演进依据=2026-09-29 第四轮 Maintainer 授权（#239 Scope 1-5；§5.6 登记）。**

**演进六条件（任一不满足=Stop Condition 7）**：

1. **对象唯一**：仅 M2 一文件一次（v6→v7，76→90）；其余九个 v4 冻结测试文件（322 方法）与全部产品禁区模块 blob 逐字不变（Done Command 7 守护）。IP-0024..0035 冻结面=禁止。
2. **逐 hunk 归因**：每个 hunk 必须映射到 #239 FR-01..06/AC-1..5 之一或 CA 裁定编号（R2/R3/R4/R5/R6/R8）并在 Packet 登记（§9.1 表已登记：14 新增方法逐条；§9.2 (b) 类更新→R8/R2-R7 驱动）。
3. **禁止弱化**：既有 76 方法断言不得删除或放松（fail-closed 门禁、泄露探针、hygiene、`__all__`/签名/数值守卫全部保留）；只允许 (a) 新增断言/方法、(b) 因显式登记的语义变更而更新的期望值。**本轮 (b) 类值更新清单见 §9.2（全部由 R2-R7 裁定驱动）**；"演进既有方法只加不断言"——既有方法体零改动。弱化判定争议 → Decision Request。
4. **版本链保留**：v1..v6 历史 blob（含 `d5cabc08`）与历史提交永久在链；Packet 记录基线与演进 blob（v7 blob 由 C2 冻结时登记于提交与验证记录）。
5. **RED 先于冻结**：C2 冻结前，M2 对未修改产品（ddb8675 版）运行并留档 RED 证据（独立日志文件归档 `.pv_tmp/RED_IP-0037_2026-09-29/`，每方法 traceback 可定位），逐方法登记"RED 失败/按设计通过"归因（§9.3）。
6. **角色纪律**：演进只在 C2 由 P&V 执行；Implementation 结构性零参与测试修改；C2 冻结提交后本 Assignment 的 ALLOWED_ONCE（§11）仅覆盖本文件面的机械缺陷（合计一次）。

**Pre-Freeze Harness Gate（冻结前必须全部通过；本 Packet 级强制）**：①测试文件可完整 import 与 collect（零加载期错误）；②新增 fixture/helper/参数组合经最小桩或对现行产品的受控行为执行到断言处（区分 fixture 缺陷与行为缺失——泛化缺席致 loader 拒绝即行为缺失锚；arrange 本身不得有独立缺陷：shaped 工件文档除 attempt_policy/batch.calls 外全部复用冻结 repo 工件构造器）；③Ruff `--no-cache` 在产品模块缺席态与最小桩模块存在态分别运行并双双通过（isort 的 first-party 分类依赖模块存在性，单态通过不可作为证据）；④临时桩（如有）位于临时目录且不入冻结提交；⑤RED 逐项归因于缺失产品行为，不来自 arrange/import/lint 失败；⑥方法预算 90（76+恰 14）不超。

**ER 复核面**：ER 将逐 hunk 复核演进正当性（条件 2/3）、独立复跑 RED 归因、复核 §9 矩阵断言与 AC 映射。

## 11. ALLOWED_ONCE（一次性机械测试修正授权；CA §Mechanical Test Correction Allowance 全文转录）

C2 冻结后，P&V 可在不新增 Coordinator 调用的情况下自行纠正**一次**纯测试机械缺陷并重新冻结（v7→v7'），条件全部满足：①不改产品语义、公共接口、稳定错误码或文件范围（含 Dockerfile 行数）；②仅限 fixture/arrange/import/lint/测试基础设施缺陷；③旧 Frozen Commit 保留；④修正前缺陷证据（原始 traceback 独立日志）、修正后有效 RED、新 Frozen Commit 完整记录；⑤Implementation 未参与测试修改。涉及产品行为、验收语义或文件范围 → Decision Request；本授权与 §10 演进授权互不折抵、合计适用一次机械修正事件。

## 12. Stop Conditions（触发即停并提交 Decision Request；CA §Known Gaps and Stop Conditions 全文转录）

0. 派发前再核验失败：#239 正文/标签/远程状态与本地捕获不一致，或 Base SHA 上 main 出现冲突性实现（含 IP-0037 编号被占用）。
1. **任何真实网络/下载/付费调用（含分支上/CI 内/pre-merge"顺手验证"）——绝对禁令。**
2. 需要修改 budget.py/orchestrate.py/run.py/collect.py/expert_timing.py/offline_flow.py/report.py/fixtures.py/`__init__.py`/`lima/**`/十冻结测试文件/`evaluation_data/**` 任何字节才能交付；或需要 run_repeats/run_baseline_attempt 基元行为变更。
3. 需要放松任何 fail-closed 门禁/钉扎/既有断言/canary 五项/预算语义；需要 transport 契约偏离 4 参；需要新增 `RealRunErrorCode`/`BaselineOrchestrationErrorCode` 成员或新错误面 field_path。
4. 需要触碰 Do Not Touch 路径、第 6 个变更文件、或 Dockerfile 超 2 行。
5. 需要触碰 Do Not Touch 路径、第 6 个变更文件、或 Dockerfile 超 2 行（与 4 重复处以上游 CA 原文为准——**实施提示：CA 原文第 5 条为"需要触碰 Do Not Touch 路径、第 6 个变更文件、或 Dockerfile 超 2 行"，第 4 条为"`run_real_baseline_suite` 签名变更、`__all__` 变更、`_REPEAT_COUNT` 数值变更、{5,5} 路径任何行为变化、或 `_estimate_for`/D1-D8/检查点序变更"；本 Packet 按语义分列如下**）。**4'.** 需要 `run_real_baseline_suite` 签名变更、`__all__` 变更、`_REPEAT_COUNT` 数值变更、{5,5} 路径任何行为变化、或 `_estimate_for`/D1-D8/检查点序变更。
6. 方法数超预算（90）；十冻结文件回归/全量 discover 出现非预期失败。
7. 六条件演进程序任一不满足，或出现"弱化既有断言才能通过"的 hunk；弱化判定争议→DR。
8. 授权文本与实现需求冲突（含本 Assignment 裁定与 Maintainer 授权原文语义矛盾、或裁定间互斥——如 R3 开区间与"每批单独授权"表述冲突解读）——不得自行改写授权或裁定。
9. 需要新第三方依赖，或新 import 超出 Packet 登记白名单（§5.6-6 所列三符号+既有导入面），或非注入式外部输入/真实 sleep 驱动的测试。
10. 实现中发现证据/代码间新矛盾影响验收语义（如 {5,5} 路径无法在零改动下与形状驱动共存）——记录并提交，不得静默。
11. 需要消耗 Maintainer 决策的任何事项（预算 ≤1，预期 0）。
12. **任何形态需要携带可用请求能力或 api_key 通道的新工件，或任何具付费调用效力的工件。**
13. cold 接线需要改 state_reuse/provider_cache/timings 子块键集（G5）、`reset_cold_state` 签名/五键返回文档、RunSpec、或结算/预算策略（R4/R6 均在键集不变路径内；否则 DR）。
14. 跨批需要任何共享状态/共享门/全局账本机制才能"通过测试"（M4 明文禁止；§7.6 docs 程序是唯一载体）。
15. V5 来源表需要实现任何模型输出契约/扫描语义变更才能"一致"（必须走 A2 末节 DR 呈报，不得实现）。
16. 需要吞噬/转换/延迟重抛 BaseException（IP-0035 R4.3 延续）或丢弃证据；**{5,5} 行为变化即停**（含任何使既有 76 方法失败的改动）；**跨批共享门是禁区**（任何以共享状态通过的测试=违例）。

## 13. Done Commands（worktree `D:/BaseAIProject/LIMA-ip-0037-wt` 根执行；Windows 设 `PYTHONUTF8=1`；成功判据=全绿/为空/恰 2 Add+3 Modify/blob 不变/ancestry exit 0）

```bash
# 0. 预冻结基线（C2 之前登记；本轮已执行并归档 .pv_tmp/RED_IP-0037_2026-09-29/baseline*.txt）：
#    test_real_run 76/76 OK；十冻结测试文件 322/322 OK；全量 discover 全绿（skipped 集与 IP-0036 后基线一致）
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_real_run -v
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline tests.test_v4_baseline_budget tests.test_v4_baseline_cli tests.test_v4_baseline_collection tests.test_v4_baseline_fixtures tests.test_v4_baseline_manifest tests.test_v4_baseline_offline_flow tests.test_v4_baseline_report tests.test_v4_baseline_result tests.test_v4_baseline_v5_negatives
PYTHONUTF8=1 python -m unittest discover -s tests
# 0b. RED 证据（C2 冻结前，对未修改 real_run.py @ddb8675）：独立日志归档
#     （.pv_tmp/RED_IP-0037_2026-09-29/）+ 逐方法归因表（R8；"RED 失败/按设计通过"）
# 1. 定向文件（C2 冻结时按设计 RED 且逐方法归因；C-final 后全绿；90 方法）
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_real_run -v
# 2. 十冻结文件回归（322 必须全绿；命令同 Done Command 0 第二行）
# 3. 全量 discover 回归（绿；skipped 集与基线一致；CI 零付费断言延续）
PYTHONUTF8=1 python -m unittest discover -s tests
# 4. 字节编译；5. ruff（--no-cache；bandit 选做，如实登记）
PYTHONUTF8=1 python -m compileall -q benchmarks tests
PYTHONUTF8=1 python -m ruff check --no-cache benchmarks/v4/baseline/real_run.py tests/test_v4_baseline_real_run.py
# 6. diff 守护：恰 2 Add（Packet/V5 来源表）+ 3 Modify（Dockerfile/real_run/test_real_run）；
#    Dockerfile diff 恰 +2 行
git diff --name-status ddb8675fc13e081cff0a7ce151849e64f6fdf85b...HEAD
git diff ddb8675fc13e081cff0a7ce151849e64f6fdf85b...HEAD -- Dockerfile   # 恰 +2 行
# 7. blob 守护：budget(6c783848)/orchestrate(8655067e)/run(d29928e5)/collect(063ecb41)/
#    expert_timing(dd7aa365)/offline_flow(0f2916c8)/__init__(1c478346)/report(e30a5f17)/
#    fixtures(700ec4fc) + 十冻结测试文件(4cde7bdf/edd4c62b/edb2391b/35e6ec6a/ca019d50/
#    8e8ab0dc/539d2fb3/86f584cb/0a44cf7d/b4a3a076) + baseline_manifest.json(7ecb39f8)/
#    python_mvp_support_matrix.json(3ea94fcf) + lima/** 与基线一致；
#    real_run(cef7a75b)/test_real_run(d5cabc08)/Dockerfile(6928a162)
#    登记为"演进文件"（从 blob 记录在案，至 blob 由 C2/C3 登记）
git ls-tree ddb8675fc13e081cff0a7ce151849e64f6fdf85b -- <守护清单> 与 HEAD 对比
# 8. ancestry：ddb8675 → C1 → C2(冻结) → C3 → (C-final) 各段 merge-base --is-ancestor exit 0
```

PC1-PC3 标配（IP-0033..0036 同款）：PC1 新增测试源 secret-token/网络-token 拼接扫描（fake transport 零真实主机；文件级自扫由既有 `test_new_test_sources_offline_and_secretless`（v5_negatives 文件，冻结）与既有 hygiene 方法延续）；PC2 arrange 经冻结校验器（shaped 工件文档经 `write_artifact` 深拷贝 repo 冻结工件后仅变异 attempt_policy/batch 维——与 `_load_and_validate_approval` 同源构造）；PC3 派生数值断言（POST 计数/摘要/计数期望一律复算或关系断言：树摘要复用 `compute_tree_fingerprint`、请求体摘要复算 sha256(chat_payloads[0])、ledger consumed 由脚本 usage 值复算——不硬抄实现值）。

## 14. PR 与 Completion Summary 契约（CA §Handoff）

- PR：单 PR `codex/ip-0037-batch-protocol` → main；标题禁 close 族关键词与编号组合（含否定句）；正文含 Final SHA（完整 40 位）、变更文件清单（对照恰 2 Add+3 Modify）、Done Commands 实际输出摘要（0/0b+1-8）、满足/不满足/未验证逐条、RED 归档路径与 blob 演进记录（real_run cef7a75b→、test_real_run d5cabc08→、Dockerfile 6928a162→）、下一责任人（P&V[C-final 独立验证] → ER → Coordinator 合并判定 → post-merge → 叶审计）；PR 必须写明 "This PR does not auto-close the Source Issue." 与 "Related to #239."（仅此关联形式；不得关联关闭 #57）。提交前缀 `[IP-0037][PV]`/`[IP-0037][IMPL]`/`[IP-0037][CI]`；C-final 后修复提交必须引用 Stop/DR/ALLOWED_ONCE 编号；实现提交（C3）以 C2 冻结提交为祖先（Done Command 8）。合并/推送/评论由主会话按 Maintainer 授权执行，P&V/IMPL 零远端写；本 Assignment 不授予任何合并/关闭判定。#239/#57 状态不受本叶合并直接影响（PARTIAL）。
- Completion Summary 必含：FR-01..06 逐条证据索引（测试 ID）、AC-1..5 判定、blob 演进记录与 C1/C2/C3 提交 SHA、RED 归档路径与逐方法归因计数、C0 基线实际值（76/322/全量 discover 实际值）、零真实调用声明、Dockerfile 恰 +2 行证明、pilot/正式批计数证据摘要（5/8 POST/cold_reset 链/越界拒付）、K1-K5 已知缺口状态。

## 15. 范围裁定 R1-R11 转录（CA-IP-0037-v1.0 决定性内容）

- **R1（文件拓扑与提交链；裁定点 F）**：**单叶单 PR，恰 2 Add + 3 Modify，测试并入既有文件，不建新测试文件**。裁定依据：①新增方法（≤14）全部钉扎 real_run.py 行为，其 arrange 基建（`_FakeTransport` 族/approval 文档构造器/确定性时钟 patch）已在 test_v4_baseline_real_run.py 文件内——新文件要么重复数百行基建、要么跨文件导入测试私有类（脆弱且本身成为新冻结面）；②v6→v7 单文件演进链是 IP-0033..0036 既定可审计先例，拆分使 blob 守护与六条件归因翻倍而不降低任何冻结面风险；③90 方法预算在单文件可控范围。**被否决的替代方案（不得重试）**：`tests/test_v4_baseline_batch_shapes.py`（Add）独立承载——否决理由如上①②。提交链：**C1（P&V：A1+A2+M1 同一提交）→ C2（P&V：M2 冻结提交，Frozen Test Commit）→ C3（Implementation：M3）→ C-final（P&V 独立验证；如触发 ALLOWED_ONCE/修复提交须引用编号）**；C3 必须以 C2 为祖先（Done Command 8）。
- **R2（I-1 路由判据；裁定点 A）**：`run_real_baseline_suite` 内的路由判据冻结为**仅 attempt_policy 形状**：加载契约的 `(cold, warm) == (5, 5)` → 既有 `run_repeats(spec_mapping, manifest, guarded, root, repeat=_REPEAT_COUNT, sources=sources)` 调用点**逐字节零改动**；任何其他合法形状 → R6 形状驱动器。**与工件键（合成/llamafactory）、七维预算数值、run_name 一概无关**——例如合成工件键配 {5,5,10} 工件仍走旧路径。测试双路径各自钉扎（M2 新增：{5,5} 路由钉扎方法=行为等价旧路径+零 `snapshot-cold-*` 目录+15 键 attempt 文档；形状驱动路径由 pilot/正式批方法族钉扎）。路由读数来源=已通过 R3 校验的契约内 attempt_policy 值（不得二次解析分叉）。
- **R3（I-2 泛化语义；裁定点 B）**：**开区间**（`type(cold) is int and cold>=1`；`type(warm) is int and warm>=1`；`type(max_attempts) is int and max_attempts == cold+warm`；`canary_required is True`；`canary_first_attempt == 0`——type 精确判定沿既有 `_require_int_pin` 的 `type() is int` 纪律，bool 陷阱拒绝）。裁定理由（登记入 Packet=§7.2）：①第四轮授权 M2/Scope 1 原文逐字给出开区间谓词——白名单是授权文本中不存在的额外限制，实施者无权加设；②授权语义在工件不在校验器：每批调用授权由工件签定的七维预算承载（pilot 工件 batch.calls=5 等），ledger 精确执行、越界拒付——校验器放宽形状类不授予任何调用额度；③白名单使未来每个已授权新形状都要求代码变更+再冻结，治理成本翻倍而安全增益为零（形状 ∈ 白名单 ≠ 已授权，白名单给出的是假保证）；④"未授权形状 silently 合法"之虑由四层承接：Packet 显式登记**"形状良构 ≠ 批次授权"**规范性声明（§7.1）、篡改负例矩阵、三已知形状逐形状钉扎、开区间成员 {2,2} 良构性钉扎（防未来静默重引入白名单）。**错误面零变化**：拒绝仍为既有 `APPROVAL_ARTIFACT_INVALID`，field_path 沿 `$.attempt_policy.*` 五键（`_ATTEMPT_POLICY_FIELDS` 五键闭集与键序不变；零新增错误码）。**被否决的替代方案（不得重试）**：白名单 {{5,5},{1,4},{3,5}}——理由②③。
- **R4（I-3 cold_reset 观测键；裁定点 C）**：attempt 证据文档（`to_document()`）增设 **additive 单一顶层键 `cold_reset`**，把 IP-0036 §7.5.2 的"attempt 文档 15 键不变"叶内冻结显式演进为"非形状驱动路径 15 键不变；形状驱动路径 cold attempt 16 键"（新 Packet §5.6/§7.5.1 登记此覆盖，依据=第四轮授权 M3"attempt 记录 additive cold_reset 观测键"；additive-only）。**在场规则（冻结）**：键在场当且仅当形状驱动路径的 cold attempt（含 index 0）；形状驱动路径的 warm attempt 与一切 {5,5} 旧路径 attempt 该键**缺席**。**值形状（冻结四键闭集，dict）**：`performed`（index 0=false；cold>0=true）/`materialization_count`（本 attempt 重置相位完成后的物化计数；初始 1，每次重置 +1）/`snapshot_tree_sha256`（64-hex，compute_tree_fingerprint）/`request_body_sha256`（64-hex）。裁定理由：`performed` 使"缺重置不得标称 cold 成功"可机械断言；`materialization_count` 把"真实 cold 计数=物化重置次数"契约逐 attempt 携带（跨 attempt 单调可断言）；两摘要兑现 M3"树与请求体摘要"且与 `reset_cold_state` 五键返回文档同源。**被否决的值形态**：①完整五键内嵌（state_reuse/timings 已是 attempt 文档顶层块，内嵌造成双真相源与发散风险）；②外部文件引用（证据五件套是冻结面，不得发明新证据文件）。`state_reuse`/`provider_cache`/`timings` 子块键集零变化（G5 不变路径保持；cold_reset 是顶层 additive 键）。
- **R5（I-4 跨批负例；裁定点 D）**：**N4 形态**——①**每批独立账本隔离负例**（M2 新增，全 fake transport）：双批同进程运行——批 1（pilot 工件+独立 output_root）恰 5 POST 成功；批 2（独立工件+独立 output_root）账本从零起算（ledger 基线 calls=0；批 2 自身预算独立核放，**不继承批 1 已耗额度**）；②**伪造/篡改跨批共享状态 fail-closed**：批 2 指向批 1 的 output_root → 既有一次性目录门 `REAL_RUN_OUTPUT_NOT_EMPTY` @ `$.output_root` 拒绝、零传输调用；同进程双 suite 的 `BudgetLedger` 实例独立性断言（无模块级共享账本状态可篡改）；③**docs 诚实登记**（A1 承载=§7.6）：跨批授权诚实性声明+**操作者复核程序**（规范性契约非代码）；**不实现任何共享门机制；不得宣称代码强制跨批总额**。**被否决的替代方案（不得重试）**：任何形式的跨批共享门/全局账本/总额校验代码——M4 明文禁止（假总授权机制）。
- **R6（形状驱动器；裁定点 E）**：`benchmarks/v4/baseline/real_run.py` 新增**私有函数 `_run_shaped_repeats`**（不入 `__all__`；冻结签名）：
  ```python
  def _run_shaped_repeats(
      spec_mapping, manifest, guarded, output_dir, *, cold, warm, sources=None
  ) -> BaselineRunSummary
  ```
  语义（冻结）：①恰 `cold+warm` 次 frozen `run_baseline_attempt` 调用——cold 索引 `0..cold-1` mode="cold"、warm 索引 `cold..cold+warm-1` mode="warm"（与 `run_repeats` 的全局索引约定同构）；②聚合**恰经 frozen `result_from_mapping`+`write_result_file` 同构**（samples 按 attempt_index 排序、schema_version=1、digest 前缀下一空闲序号；`result_paths` 目录前后差集同构）；返回自构造 `BaselineRunSummary` 七字段同构；③**cancellation 语义与现有路径一致**：驱动器自身**不捕获** `run_baseline_attempt` 逸出的 BaseException；入口层既有 try/except（settle_cancelled→五件套部分证据→原样重抛）不变且对两路径同等生效；④不重复校验形状。**{5,5} 走原 `run_repeats` 零改动（R2）**。**cold attempt 接线（冻结）**：index 0=既有物化路径（`_run_attempt` index==0 分支逐字节保持；cold_reset=performed False/count 1/两摘要）；cold index>0=**reset 语义接入**：经 `reset_cold_state` 同源机制（重解包至 `snapshot-cold-{n}`+请求体重建）后执行本 attempt 的 `_chat`，`state_reuse`=(materialized=True, snapshot_reused=False, request_body_rebuilt=True)（四键含 process_identity，G5 键集不变）、cold_reset=(performed=True, count 递增, 两摘要)、零传输 GET、download_ms=None 纪律；**reset 失败→typed RealRunError 失败（settle→保留失败样本），不得计为 cold 成功**（outcome=failure 且 cold_reset.performed 不得为 true）。**warm attempt**：既有复用路径+`state_reuse`=(False, True, False)，cold_reset 缺席。**实现边界**：guarded evaluator 的 mode 标签边界（`__call__` 现钉 `index < _REPEAT_COUNT`）与 `_run_attempt` 的 cold/warm 分支判据必须由已校验形状驱动——默认构造（形状 (5,5)）行为**逐字节保持**（内部携带机制如私有 kw-only 形状参数由 Packet 定稿登记；公开签名零变化）；canary 检查保持在 index==1（任一合法形状 cold≥1/warm≥1 ⟹ max≥2，index 1 恒存在）；`_estimate_for` 估计策略零变化（cold>0 沿既有非零索引分支，body_bytes 为重建成后确定性等值）。
- **R7（V5 逐字段来源表；裁定点 G；I-5 出处成立）**：载体=A2（docs-only，零实现）。三列制（冻结）：`真实来源（产生点：模块/函数/数据流位置）| 当前缺口（为何不可得/仅部分可得）| 可验证证据（离线可复现断言/测试/工件指针）`。行集（恰十行）：Signal / Issue / Hypothesis / VEP / RVR / stage_outcome / 专家分钟 / 原始候选 / 压缩队列 / 资源指标。现状如实记录（必载）：当前真实入口=llm-bounded-triage——有界 12 候选（`CANDIDATE_FILE_CAP=12` 请求构造参数，非处理上限）+ 每候选单二元 verdict（is_vulnerable）；payload v2 `total_findings`=bounded-candidate-files、`metrics.cases`=1；VEP/RVR/stage_outcome 于真实运行路径=无 domain 块→null+projection "unavailable"（不写常数、不以 synthetic 冒充）；专家分钟缺席纪律保持。末节=精确 Decision Request 草案（不实现）：模型输出契约扩展与扫描语义扩展两组**互斥选项**（每组选项给出语义/影响面/验收形态），呈报 Maintainer 决策；表内不得宣称未验证状态（AC-5"与实现一致"）。
- **R8（测试面演进；裁定点 F/H）**：M2 v6→v7，76 存留零弱化 + 新增 ≤14（合计 ≤90），沿用 IP-0033..0036 六条件程序（对象唯一/逐 hunk 归因/禁弱化【(b) 类值更新全部由 R2-R7 裁定驱动】/版本链保留【v1..v7 blob 永久在链】/RED 先于冻结且逐方法归因/角色纪律——演进只在 C2 由 P&V 执行）。新增必含清单（十二类）：①pilot {1,4} 成功恰 5 POST；②正式批 {3,5} 成功恰 8 POST（含 snapshot-cold-2/-3、摘要恒等、count 1→2→3 单调、warm (F,T,F)）；③形状篡改矩阵（精确 field_path）；④开区间良构钉扎（{2,2}）；⑤pilot 第 6 次越界零传输；⑥正式批第 9 次同上；⑦cold 缺重置不得标称；⑧shaped canary latch；⑨双批隔离；⑩{5,5} 路由钉扎；⑪cold_reset 在场/缺席矩阵；⑫无 usage 不记零（shaped）。RED 形态=能力缺席，逐方法归因表强制（{5,5} 路由钉扎与旧路径回归项按设计通过）。
- **R9（Done Commands）**：§13（0/0b+1-8）。
- **R10（Stop Conditions 与 ALLOWED_ONCE）**：§12（0-16）/§11。
- **R11（升级条款）**：Implementation 出现跨冻结模块语义约束、同一根因两轮有新证据修复仍失败、疑似规格矛盾 → 停止并提交 DR；如裁定升级目标档位 `glm-5.3 / max`，实际切换须新建/重新配置会话并取得 SESSION-RUNTIME-VERIFIED（派发文本声明不构成运行切换），文件边界/测试冻结/验收标准不变。

## 16. Decision Record（P&V 定稿决策；CA 授权范围内的冻结裁量）

| # | 决策 | 时间 | 依据 |
| --- | --- | --- | --- |
| DR-IP-0037-PV-1 | 14 个新方法全部落位单一新类 `TestBatchShapeProtocol`（挂 `TestArtifactFamilyAndColdReset` 后），不拆第二新类；shaped 工件 arrange 复用既有 `write_artifact` 深拷贝构造器+新增模块级形状常量与 shaped 工件 helper（纯增量） | 2026-09-29 | R1 单文件演进+R8 必含清单十二类的最小方法划分；§9.1 表为逐方法断言面冻结登记 |
| DR-IP-0037-PV-2 | 第 6/9 次越界方法（N5/N6）采用直接构造 evaluator（g3/g4 构造先例）+前 N 次经冻结私有驱动器 `_run_shaped_repeats` 驱动（成功路径计数），再第 N+1 次**直接** `guarded()` 断言 `BudgetGateError`（`BATCH_BUDGET_EXCEEDED` @ `$.budget.batch.calls`）与零传输。前 N 次不得绕过驱动器直接逐调 `guarded()`：canary 清单第 4 项 `attempt0_digest_verified` 校验编排写出的 `*-run-1.json` 结果文件（real_run.py `_verify_attempt0_digest`），纯直接调用在 index1 清单必败并 latch（本 P&V 会话 Pre-Freeze 探针 C 亲证）——经驱动器（其逐 attempt 走 `run_baseline_attempt`）结果文件恰在场；越界的那一次不经 `run_baseline_attempt` 包装（其 Exception→失败样本语义会使 BudgetGateError 被吞为样本，无法断言拒付异常面） | 2026-09-29 | R8-⑤⑥"第 6/9 次 guarded 调用越界拒付零传输"；入口层无法在同一 ledger 上发起第 N+1 次（一次性目录门+每 suite 新建 ledger）；run.py 冻结异常纪律（L285-291：Exception 体保留为失败样本）；Pre-Freeze Harness Gate 探针（.pv_tmp/RED_IP-0037_2026-09-29/probe_arrange.log） |
| DR-IP-0037-PV-3 | cold 缺重置方法（N7）的注入钩子=chat 侧 transport 子类在首次 POST 时删除缓存 tarball（此刻物化已完成、tarball 已缓存；后续 cold reset 重解包必失败）；warm 复用路径不读 tarball 故不受污染 | 2026-09-29 | R6 接线语义"reset 失败→typed 失败"；注入式（Stop 9 禁真实外部输入）；与 `_FakeTransport` 既有子类先例（`_ClockJumpChatTransport`）同构 |
| DR-IP-0037-PV-4 | shaped canary latch 方法（N8）的清单失败形态选用 attempt-0 usage 超预约（`prompt_tokens=_REQUEST_BYTE_CAP*2` 先例），非 verdict 失败：使 canary 失败归因单一（usage_within_reservation False），不与 D1 结算面耦合 | 2026-09-29 | R8-⑧"shaped canary 失败→零后续 POST+REAL_RUN_CANARY_FAILED latch"；既有 `test_canary_usage_over_reservation_latches_with_nine_errors` arrange 同构 |
| DR-IP-0037-PV-5 | {2,2} 良构钉扎（N6）与 {2,3,6} max≠和拒绝对照合于同一方法（合法面+违规面互证开区间语义）；篡改矩阵方法（N3）仅收编"新旧校验器同 field_path"的案例（{5,5,9} max 案例承载 max 维），{2,3,6} 的新语义拒绝面归 N6——使 N3 在 RED 期整体"按设计通过"可归因 | 2026-09-29 | R8-③④+§9.3 RED 归因纪律（逐方法单一归因态） |
| DR-IP-0037-PV-6 | 无 usage 方法（N14）注入位=index 2 起（避开 index 0/1 canary 面）：{1,4} 形状下 index 2 为 warm attempt，断言 `REAL_RUN_USAGE_MISSING`+violations==1+ledger consumed 仅含成功 attempts 脚本值（PC3 复算） | 2026-09-29 | R8-⑫+既有 `test_missing_usage_is_violation_with_reservation_released` 的 DR-1 fixture correction 先例（只有第二及以后调用可缺 usage） |
| DR-IP-0037-PV-7 | `{5,5}` 路由钉扎（N12）以行为面证明（聚合文件序号族 run-1..run-11、result_paths、零 snapshot-cold-*、15 键 attempt 文档、mode 序列）+合成键 {5,5} 对照（R2"与工件键无关"锚）；不注入路由探针（不锁定内部路由机制的实现细节） | 2026-09-29 | R2"测试双路径各自钉扎"；测试验证行为不锁定无关实现细节（责任书 §7.1） |
| DR-IP-0037-PV-8 | manifest.json 的 `cold_count`/`warm_count` 顶层键在形状驱动路径下的取值**本 Packet 不裁定、测试不钉扎**（R2-R6 均未涉；现行实现写死 `_REPEAT_COUNT`）：v7 测试不对其做任何断言；该面的诚实性（shaped 批 manifest 计数是否应等于工件形状）登记为本 Packet 观察项 OBS-1，移交 C-final 证据复核与 Coordinator（如需语义裁定则 DR） | 2026-09-29 | R6 冻结面仅涉驱动器/聚合同构/取消/canary/estimate；§1 Not-covered 与 Frozen Interfaces 均未含 manifest 计数语义；P&V 无权创设新验收语义（责任书 §5.2/Stop 8） |

**观察项（不移交实现、不构成验收面）**：

- **OBS-1**（DR-IP-0037-PV-8）：`_build_manifest_document` 现将 `cold_count`/`warm_count` 写死为 `_REPEAT_COUNT`（real_run.py L2278-2279）。形状驱动路径下该两键若保持 5/5，与实际执行形状（如 1c+4w/3c+5w）不一致（证据诚实性张力）；若改为形状派生，则属 {5,5} 路径外的行为演进。CA R1-R11 未裁定此面。本 Packet 不测试、不裁定；C-final 复核时对 shaped 批 manifest 计数与 attempt_count 的一致性做证据级检查并按需提交 Decision Request。
- **OBS-2**：双批隔离方法（N11）以行为证明（批 2 成功=不继承+两 ledger.json 各自 calls 计数+目录门拒绝）承载"同进程两 suite `BudgetLedger` 实例独立性"；不通过内部属性探针断言实例身份（避免锁定实现细节）。

## 17. 已知缺口（不阻塞本 Packet；CA K1-K5 同构登记）

- **K1** 零真实批次执行：本叶全部形状证明为 fake transport 离线证明；真实 pilot/正式批另行授权与工件（第四轮授权边界）。
- **K2** 跨批总额仅操作者复核（§7.6 程序），无代码强制——如实登记，不得宣称代码强制总额。
- **K3** 形状驱动 cold attempt 的真实批结算细则（重置 attempt 计量差异）归决策包 v4/未来真实批 DR；本叶估计/结算策略零变化。
- **K4** V5 表识别的模型输出契约/扫描语义缺口维持 unavailable 现状，待 A2 末节 DR 呈报后另行叶实现；本叶 docs-only。
- **K5** 开区间形状类中 {1,4}/{3,5}/{2,2}/{5,5} 已钉扎，其余合法形状良构但未逐形状测试（开区间裁定 R3 的如实边界）。

（Packet 完；版本 v1.0。Contract 语义变更须同步 Packet 版本与 AC。）
