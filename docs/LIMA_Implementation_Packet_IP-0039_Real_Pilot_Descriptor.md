# LIMA Implementation Packet — IP-0039 真实 pilot 专属描述子+范围限定日期钉扎+首败停止门（#247，离线叶，零真实调用）

- Packet ID：IP-0039；版本 v1.0（2026-09-30）。
- Coordinator Assignment：CA-IP-0039-v1.0（2026-09-30；Intent Record `.pv_tmp/INTENT_RECORD_IP-0039_2026-09-30.md` 的 M1-M9/F1-F9/I1-I5 由其 R1-R11 裁定；R1-R11 转录见 §15；**本 Assignment 为唯一裁定权威，本 Packet 全文转录不得改义**）。
- Source Issue：#247（open；parent #57 保持 open，关联 #241（closed）；正文 Scope 1-4 / Non-goals / AC-1..4 由 Coordinator 经 GitHub API 只读 GET 亲取，范围以 CA §Authoritative Inputs #2 为权威转录，API dump 存 `.pv_tmp/issue247_api.json`——本 P&V 会话离线消费 CA 转录，零网络）。
- Operating Mode：SHADOW；Execution Authorization：MAINTAINER_AUTHORIZED（2026-09-30 第六轮"一次性真实 pilot 与证据收口"授权：裁定文件 `.pv_tmp/ZCODE_LONG_TASK_REAL_PILOT_RULING_2026-09-30.md` §3 已由 Maintainer 采纳发送；**本叶零真实调用/零付费/零远端写/零凭据注入；不签发具付费效力批准工件；真实执行=主会话在裁定 §5 全部门禁后另行启用，不在本 Assignment 授权面内**）。
- Base SHA（完整 40 位）：`352646bf25313ed3d1ef11e43fa1e57fffbca89f`（= origin/main = 本地 main = worktree 分支起点，本 P&V 会话亲验）。
- 基线产物指纹（`git ls-tree 352646bf...` 本 P&V 会话程序化复核，与 CA §Authoritative Inputs #9 逐字一致）：real_run.py blob `d363e457cb79913a627cfda6ce5848557233fc07`；test_real_run.py blob `50f78bd6128b2b95d3452639e7b1ea40b1365e3e`；Dockerfile blob `2ce873d3e0343a4e5d87d55587d3176b607155b7`；守护 blob——budget `6c783848`、orchestrate `8655067e`、run `d29928e5`、collect `063ecb41`、expert_timing `dd7aa365`、offline_flow `0f2916c8`、`__init__` `1c478346`、report `e30a5f17`、fixtures `700ec4fc`；十冻结测试文件 `4cde7bdf`/`edd4c62b`/`edb2391b`/`35e6ec6a`/`ca019d50`/`8e8ab0dc`/`539d2fb3`/`86f584cb`/`0a44cf7d`/`b4a3a076`；IP-0038 Packet `6b7f89f3`、V5 表 `587ef5e1`、批准工件 `2e2473cd`/`3702c04a`；`baseline_manifest.json` `7ecb39f8`。
- 冻结前基线绿（本 P&V 会话 C0 亲跑，2026-09-30，归档 `.pv_tmp/RED_IP-0039_2026-09-30/baseline.txt` 与 `discover_stderr.txt`）：test_real_run **97/97 OK（42.999s）**；十冻结测试文件 **322/322 OK（42.297s）**；全量 discover **2713 OK / skipped=24（254.925s，exit 0）**（与派发预期 2713/24 逐字一致；IP-0038 后基线 2706+24，+7=v8 新增方法，skip 集不变）。
- 本 Packet 的角色：Implementation（阶段 C3）的唯一实现依据；冻结验收测试面（§9/§10，tests/test_v4_baseline_real_run.py v8→v9）的唯一语义来源；ER 复核与 P&V 独立验证（C-final，含 R7 离线副本全链实际执行）的基准。

## 0. 交付物角色声明（强制，先于一切）

1. 本 Packet（本文件）与 Dockerfile 恰 +1 行 COPY 是 P&V 的 C1 交付物；tests/test_v4_baseline_real_run.py v8→v9 演进（97→112 方法）是 P&V 的 C2 交付物（Frozen Test Commit）；`benchmarks/v4/baseline/real_run.py`（R2/R3/R4 全部实现面=恰五处）是 **Implementation 的 C3 交付物**。边界不得互换：Implementation 不得修改本 Packet/测试；P&V 不实现产品功能。
2. **零真实调用绝对禁令（本 Assignment 范围内）**：本叶全程（含分支上、CI 内、pre-merge"顺手验证"）禁止任何真实模型调用、网络下载、付费动作、真实凭据注入、任何具付费效力批准工件。全部验收以离线注入（fake transport/确定性 clock patch/测试构造工件文档）证明；CI 永远零付费模型请求（PC1 延续）。
3. **真实 pilot 执行不在本叶**：本叶交付"真实 pilot 开工前的三件最小受审变更"（专属描述子/日期钉扎/首败停止门）+离线副本验收面；真实 ≤5 POST pilot=主会话在裁定 §5 门禁后另行一次性启用（第六轮边界：本叶停在真实 pilot 门前）。
4. **冻结面零回退**：IP-0024..0038 一切冻结面零回退（§7 各"不变面"节与 CA §Frozen Interfaces）；`budget.py`/`orchestrate.py`/`run.py`/`collect.py`/`expert_timing.py`/`offline_flow.py`/`report.py`/`fixtures.py`/各级 `__init__.py` 零字节（停止门靠既有"逐 attempt 捕获继续"驱动，run.py 零改——CA §Authoritative Inputs #6 亲读确认）；estimate 常量与 `_estimate_for` 接线零改动；calls/cost/canary 门零放松。
5. **真实工件不入库**（裁定 §4/§7）：真实批准工件的签发/封存/执行登记=主会话在裁定 §5 门后职责；本叶任何角色不得在 PR/分支/CI 上携带任何真实工件或离线副本（离线副本仅存 `.pv_tmp/OFFLINE_TWIN_IP-0039_2026-09-30/`，R7）。
6. **主会话职责（非本 PR 面；P&V/Implementation 不得代行）**：①合并/推送/PR 操作/Issue 评论等一切远端写；②真实 pilot 执行（裁定 §5 门禁后一次性授权）；③真实工件签发与封存；④#57 Delivery Ledger 与逐行矩阵更新；⑤跨日时对 date_pin/retrieval_date_pin 的受审修订（R5）。

## 1. 需求映射（Packet 头）

```text
Source Issue：#247（open；Scope 1-4 / Non-goals / AC-1..4，经 CA-IP-0039-v1.0 转录；API dump .pv_tmp/issue247_api.json）
Issue specification revision：2026-09-30T08:13:52Z 创建版正文（未再编辑；Packet ID 占用检查 2026-09-30 由 Coordinator 完成：git grep IP-0039 352646bf 零命中）
Covered requirements：FR-01、FR-02、FR-03、FR-04、AC-1、AC-2、AC-3、AC-4（PR 面内部分）
Not covered requirements：任何真实模型调用/网络下载/付费动作/真实凭据注入；任何具付费效力批准工件的签发或提交；真实 pilot 执行；#57 关闭或 PR3 勾选；#247 关闭（叶合并≠Issue 完成）；#241 重开；预算扩大、estimate 常量与 _estimate_for 接线、budget.py/orchestrate.py/run.py/collect.py/expert_timing.py/offline_flow.py/report.py/fixtures.py/各级 __init__.py 任何字节；lima/**；scripts/**；前端；pyproject.toml/requirements.txt/.github/**/.gitignore/.gitattributes；evaluation_data/** 全部；ledger/manifest/report 任何新增字段；V5 指标来源/扫描器/模型响应契约/数据标签改动；模型身份钉扎（served forms/base_url/request name/prompt/thinking/max_tokens=8000/请求体上限）任何变化；旧十描述子任何字段值改写；旧 {5,5} 路径与既有 shaped 路径（含停止门不启用时）任何行为变化；历史 Packet（IP-0036/0037/0038）、两份批准工件、V5 来源表、决策包文本修改；不提交任何输出目录/密钥/run 产物/.pv_tmp/**
Delivery role：governance + capability-slice（#247 真实 pilot 开工前三件最小受审变更：专属描述子/范围限定日期钉扎/首败停止门，全部离线）
Issue closure impact：PARTIAL（IP-0039 完成 ≠ #247 完成 ≠ #57 完成 ≠ 真实 pilot 完成；真实执行与真实工件=主会话独立授权登记）
Upstream IP/PR/merge commits：CONSUMES IP-0038（main 链 PR #242 merge=352646bf；planned_cold_count/planned_warm_count property 面、v8 冻结测试链 97 方法、_PREFLIGHT 七维数值向量（=裁定 §2 数值表）为本叶直接消费面）；先例 IP-0033..0038（冻结测试面六条件演进程序）
```

FR-01..FR-04 为 #247 "Scope (this slice)" 1-4 的规范化编号（语义不变，CA §Goal and Scope）。

| 需求 | 内容（规范化语义） | 本 Packet 承载 | 验收面 |
| --- | --- | --- | --- |
| FR-01 | 真实 pilot 专属描述子：新 family key `real-pilot/large-repo`（真实批准类型 `PR3D-REAL-PILOT-ONE-SHOT`、唯一 `run_name`、large-repo fixture 显式绑定本地物化、身份钉扎不变；旧 offline-proof 描述子不得改写为真实批准） | §7.1（R2） | M1（N1）、M3（N3）、M13（N10）（AC-1） |
| FR-02 | 范围严格限定的日期钉扎：新描述子携带专属 `date_pin`/`retrieval_date_pin`（Asia/Shanghai；旧族默认 2026-09-28 逐字节零变化；仍为逐字比较，不接受任意日期） | §7.2（R2.4/R5） | M4（N4）、M3（N3）（AC-1） |
| FR-03 | 首败停止门（仅真实 pilot 路径）：任一已发生的 transport/响应契约/usage/身份/预算/截止失败后不再发起新的真实 POST（新码 `REAL_RUN_BATCH_STOPPED`；首个真实原因保留；后续未执行 attempt 诚实标注；不误称 canary；旧描述子/旧 {5,5}/既有 shaped 路径语义零变化） | §7.3（R3）/§7.4（R4） | M5-M11（N5/N6/N7/N13）、M12（N8）（AC-2） |
| FR-04 | 离线验收：新描述子无付费效力离线副本（与最终真实工件逐值一致）经正式入口+fake transport+空目录执行到报告+全负例矩阵 | §7.5（R5/R7）/§8 | M3（N3）、M13/M14（N9-N12）、C-final 离线副本（R7）（AC-3） |
| AC-1 | 新描述子离线副本过全门（含日期钉扎）；fixture 本地物化零 GET；旧十描述子与旧工件校验逐字节不变 | §7.1/§7.2/§9 | M1+M3+M4+既有 96 方法零改动通过+v8 全绿回归 |
| AC-2 | 六类后续失败注入→首败后零新增 POST、首因保留、后续样本 REAL_RUN_BATCH_STOPPED 诚实标注；旧路径语义零变化 | §7.3/§8/§9 | M5-M10（N5/N6/N13）、M11（N7）、M12（N8）+{5,5} 回归 |
| AC-3 | 离线验收全断言面+负例矩阵通过；CI 零真实调用；blob/diff 守护；离线副本全链实际执行归档 `.pv_tmp/OFFLINE_TWIN_IP-0039_2026-09-30/` | §8/§13 | M3-M15 + C-final 离线副本（P&V） |
| AC-4 | v8→v9 受控演进零弱化（六条件+唯一授权同步集+归因表）；skipped 集如实登记 | §9/§10 | M2 同步集+归因表+Done Commands 1-3 |

**Not-covered（全团队不得扩张；= CA §Not covered 1-6 全文）**：见上文 Not covered requirements 段与 §12 Stop Conditions。

## 2. Design Input Manifest

| # | 输入 | 版本/位置 | 消费方式 |
| --- | --- | --- | --- |
| 1 | CA-IP-0039-v1.0 | `.pv_tmp/COORDINATOR_ASSIGNMENT_IP-0039_2026-09-30.md` | 范围权威；R1-R11 全文转录见 §15；本 Packet 逐条承载 |
| 2 | Intent Record IR-IP-0039-2026-09-30 | `.pv_tmp/INTENT_RECORD_IP-0039_2026-09-30.md` | M1-M9 授权语义（第六轮：本叶零真实调用/停在真实 pilot 门前/三件最小变更）；F1-F9 决定性事实（F4 BudgetGateError 透传不 latch=停止门补齐缺口依据；F6 更正：#247"旧十一描述子"系笔误=旧十键）；I1-I5 全部由 CA R2-R6 裁定 |
| 3 | Maintainer 第六轮授权（裁定文件） | `.pv_tmp/ZCODE_LONG_TASK_REAL_PILOT_RULING_2026-09-30.md` §3（三件最小变更逐项边界）+§2（七维预算数值表+attempt_policy {cold:1,warm:4,max_attempts:5}+POST 硬上限 5）+§4（离线验收断言面+八类负例矩阵逐字） | §0/§7/§8/§12 的授权依据；§7.5 数值真值源；§8 负例矩阵逐字来源 |
| 4 | Source Issue #247 正文 | `.pv_tmp/issue247_api.json`（Coordinator GitHub API 只读 GET 亲取；本 P&V 离线消费 CA 转录） | Scope 1-4/Non-goals/AC-1..4（经 CA 规范化为 FR-01..04） |
| 5 | IP-0038 交付面 | PR #242 merge=352646bf（本 P&V 会话 `git log` 亲验：576802a [PV] Freeze v8 → 18e1595 [IMPL] → 352646b merge）；Packet `docs/LIMA_Implementation_Packet_IP-0038_Preflight_Calibration.md`（blob `6b7f89f3`） | 结构先例（§5.6 演进登记/§10 六条件/§13 Done Commands/§15 R 转录/§16 DR 体例/付费效力机械判据）；§7.3.1 数值表=_PREFLIGHT 常量面为本叶直接消费面（本会话逐值亲核一致） |
| 6 | real_run.py @352646bf | blob `d363e457`（本 P&V 会话亲读关键面：L334-356 身份/定价/族钉扎常量（`_PRICING_RETRIEVAL_DATE_PIN="2026-09-28"` L341、`_APPROVAL_TYPE_PIN`/`_RUN_NAME_PIN` L346-347、`_ZERO_BUDGET_FAMILY_VALUE` L352）；L356-436 十键目录构建（`_DEFAULT_ARTIFACT_KEY` L356、`_SYNTHETIC_ARTIFACT_KEYS` 九键 L360-370、`_synthetic_artifact_descriptor` 派生规则 L373-395、`_build_artifact_family` L398-424、`REAL_RUN_ARTIFACT_FAMILY` L432、`_SYNTHETIC_SET` L436）；L439-487 十码 enum+`_STABLE_MESSAGES`；L803-1003 `_load_and_validate_approval`（未知键 `$` 拒绝 L824-826、`$.date` 硬钉 "2026-09-28" L851、`$.pricing.retrieval_date` 钉 `_PRICING_RETRIEVAL_DATE_PIN` L900-904、fixture_key 分派 L1002）；L1327-1438 `_GuardedRealEvaluator.__init__`/property 面；L1472-1518 `__call__`（latch 检查 L1492-1493 → index==1 canary L1494-1500 → reserve L1502-1509（BudgetGateError 置 failure_code="EXECUTION_ERROR" 后透传） → attempt-0 estimate L1510-1517）；L1530-1546 `_typed`；L1552-1568 `_timeout_failure`（EXECUTION_TIMEOUT）；L1586-1603 `_estimate_for`；L1605-1644 `_run_attempt`（`except RealRunError → _settle → raise` L1642-1644）；L1710-1757 `_settle`（身份 latch L1749-1755）；L2161-2197 `_chat`（transport OSError→TRANSPORT_FAILED/TimeoutError→EXECUTION_TIMEOUT L2179-2190、post-call deadline recheck L2192-2196）；L2199-2313 `_parse_response`（usage 缺失 L2295-2298、身份漂移 L2305-2313）；L2352-2373 `_run_canary_checklist`；L2403-2482 `_build_manifest_document`（failures 列表 L2423-2429 逐 record 收录 failure_code 非 None 者；canary 块 L2463-2466）；L2545-2629 `_run_shaped_repeats`（逐 attempt 调 `run_baseline_attempt`，Exception 体不中断循环）；L2632-2643 `run_real_baseline_suite` 签名（`artifact_key` kw-only 尾参） | §7.1/§7.2/§7.3/§7.4 演进对象与冻结契约的逐行依据 |
| 7 | run.py @352646bf（禁区） | blob `d29928e5`；L226-331 `run_baseline_attempt`（本 P&V 会话亲读确认：`execute()` 的 Exception 体被捕获→分类→持久化失败结果文件→返回（仅 BaseException 重抛）——**停止门靠既有"逐 attempt 捕获继续"驱动，无需改 run.py**） | §7.3.4 驱动面依据 |
| 8 | tests/test_v4_baseline_real_run.py @352646bf | blob `50f78bd6`（v8；**97 方法，本 P&V 会话亲数（grep -c "    def test_"=97）且 C0 亲跑 97/97**；`_FROZEN_ERROR_CODES` 十码 L513-526；`_ARTIFACT_FAMILY_KEYS` 十键 L532-543 与 `_SYNTHETIC_ARTIFACT_KEYS` 派生 L544-546（过滤条件=仅排除 default key——R6 指定演进点）；`_DESCRIPTOR_FIELDS` 七字段 L549-559；静态锚 `test_frozen_taxonomy_checkpoints_and_canary_static_anchors` L3724-3740（enum 对常量比较，方法体无需改）与 `test_artifact_family_catalog_frozen_ten_keys` L3767-3785（**唯一需就地同步的旧方法**：len==10 L3773+全键七字段循环 L3774-3776）；`_PREFLIGHT_PER_RUN`/`_PREFLIGHT_BATCH` L604-621（=裁定 §2 数值表逐值一致，本会话亲核）；末类 `TestPreflightCalibration` L4840-5299=新类插入位；L4042/L4299/L4626 为常量相对断言（同步后在实现面上自动通过，方法体零改）；arrange 基建 `_FakeTransport` 族/`_ClockJumpChatTransport`/`_JumpClock`/`patch_monotonic`/`write_synthetic_artifact`/`_preflight_policy`/`_synthetic_commit_sha` 全在文件内——R1 单文件演进依据） | §9/§10 演进基础 |
| 9 | Dockerfile @352646bf | blob `2ce873d3`（docs COPY 块亲读：IP-0038 Packet COPY 行=L69=本叶恰 +1 行插入位；派发文本与 CA M1 同锚（"插 IP-0038 Packet 行后"=L69 后），无字面差异） | C1 +1 行落位依据 |
| 10 | 守护 blob（`git ls-tree 352646bf` 本 P&V 会话程序化复核） | 与 CA §Authoritative Inputs #9 逐字一致（见 Packet 头基线指纹节） | Done Command 7 blob 守护清单 |
| 11 | worktree/分支 | 主会话已建 `D:/BaseAIProject/LIMA-ip-0039-wt`（分支 `codex/ip-0039-real-pilot-desc` @352646bf；本 P&V 会话 `git rev-parse HEAD`+`status --short` 亲验=干净） | §5.5 提交链拓扑的落位 |
| 12 | 裁定 §4 断言面原文 | 裁定文件 §4（成功路径验证逐字+八类负例逐字） | §8 机械判据矩阵逐字来源（"不得复用旧预演作为新描述子通过的证据——必须新执行"→C-final 离线副本程序） |

哈希真值来源：`git ls-tree 352646bf25313ed3d1ef11e43fa1e57fffbca89f -- <paths>`（本 P&V 会话程序化复核，与 CA 一致）。

## 3. Explicitly Rejected Inputs

| # | 被拒输入 | 拒绝理由 |
| --- | --- | --- |
| 1 | 全族统一十/十一字段可选默认值（旧目录表示面改写） | R2 被否决替代方案①：旧十键校验输出逐字节不变的最强保证=新字段根本不进入旧描述子字典（`.get` 缺省即旧值） |
| 2 | 新键沿用 `archetype/large-repo` 并靠 approval_type 区分 | R2 被否决②：键即分派面，混用破坏 fixture_key 语义与十六进制负例 |
| 3 | 查表钉扎（loader 内另立 key→date 映射表） | R2 被否决③：绕过目录单一真值源 |
| 4 | 新描述子的 fixture 溯源字段另造新值 | R2 被否决④：与所绑 fixture 实际来源不符，溯源不诚实；冻结=逐字复用 `_synthetic_artifact_descriptor("archetype/large-repo", fingerprint)` 派生值 |
| 5 | 停止门判定面=approval_type 等值比较 | R3 被否决①：命名耦合；裁定=数据标志字段 `stop_on_first_failure` |
| 6 | 在 `_run_shaped_repeats`/`run.py` 驱动层拦截 | R3 被否决②：改冻结模块，Stop 5 |
| 7 | 停止后吞噬异常或改写首因 record 的 error_code | R3 被否决③：证据纪律违规 |
| 8 | 复用 `self._latched` 作停止粘滞位 | R3.3 绝对否决：会使停止后的后续 attempt 命中 canary latch 检查而误标 REAL_RUN_CANARY_FAILED（M3/M4 禁止的"误称 canary"）；独立 `self._batch_stopped` |
| 9 | 独立新建 `tests/test_v4_real_pilot_descriptor.py`；把真实工件或离线副本提交入库 | R1 被否决替代方案（arrange 基建在既有文件内；v3..v8 单文件演进链为既定可审计先例；裁定 §4：不提交批准工件——离线副本仅 `.pv_tmp`） |
| 10 | 第 5 个变更文件、Dockerfile 超 1 行、触碰禁区路径 | R1 + Stop 5/7：Allowed Files 终形=恰 1 Add+3 Modify |
| 11 | ledger/manifest/report 新增字段、`run_real_baseline_suite` 签名变更、`__all__` 变更、`_REPEAT_COUNT` 变更、canary 清单项/时机/latch 语义变更、路由判据偏离"仅 attempt_policy 形状"、十旧码任何顺序/值/消息变化 | CA Not-covered 4 + Stop 6；canary 交互仅用既有值（R4.3） |
| 12 | 接受非逐字日期匹配/通配/区间日期；让 2026-09-28 以外的 date 在旧键下通过或 2026-09-30 以外的 date 在新键下通过 | R5/Stop 3：日期钉扎任何放松即停 |
| 13 | 以任何真实网络/下载/付费调用/凭据注入"顺手验证"新键 | Stop 1/4 绝对禁令 |
| 14 | `.pv_tmp` 离线副本用于真实 transport/真实凭据/离开 `.pv_tmp` | R7 防御条件 a + Stop 4：绝对停并升级 Maintainer |
| 15 | 吞噬/转换/延迟重抛 BaseException、丢弃/改写已发生失败证据 | IP-0035 R4.3 延续 + Stop 15 |
| 16 | 跨日自行改 date_pin/retrieval_date_pin/run_name/七维数值 | R5/Stop 16：数值钉扎归 Maintainer 受审修订 |

## 4. Goal / Non-goals

**Goal**：在 IP-0038 版产品（main=352646bf）上完成真实 pilot 开工前的三件最小受审变更并以受审查单 PR 入库：①**真实 pilot 专属描述子**——新 family key `real-pilot/large-repo`（§7.1：十一键闭集目录、七旧字段+恰四新字段、五个 fixture 溯源字段逐字复用 large-repo 派生值、`approval_type="PR3D-REAL-PILOT-ONE-SHOT"`、`run_name="pr3d-real-pilot-2026-09-30"`）；②**范围严格限定的日期钉扎**——新描述子携带专属 `date_pin`/`retrieval_date_pin`（2026-09-30，Asia/Shanghai；旧族默认 2026-09-28 逐字节零变化；仍为逐字比较，§7.2）；③**首败停止门（仅真实 pilot 路径）**——任一已发生的 transport/响应契约/usage/身份/预算/截止失败后不再发起新的真实 POST（§7.3：门位置/触发面/独立粘滞位/首因保留；§7.4：新码 `REAL_RUN_BATCH_STOPPED` 十一码演进+canary 交互语义）。离线验收=新描述子无付费效力离线副本（与最终真实工件逐值一致，§7.5）经正式入口+fake transport+空目录执行到报告+全负例矩阵（§8）。全部离线：零真实调用、零付费、CI 零付费模型请求。

**Non-goals**：见 §1 Not-covered 段（CA 原文）。真实 pilot 执行、真实工件签发与封存、合并/推送/远端写、#57 Ledger 更新不在本 Assignment 授权内。

## 5. 文件边界（CA R1：恰 1 Add + 3 Modify；零 Delete；单 PR `codex/ip-0039-real-pilot-desc` → main）

### 5.1 Files to Add（恰 1）

| 文件 | Owner/阶段 | 说明 |
| --- | --- | --- |
| `docs/LIMA_Implementation_Packet_IP-0039_Real_Pilot_Descriptor.md` | P&V（C1，本文件） | 本 Packet；承载 CA R1-R11 全部裁定（新键/新字段闭集/日期钉扎/停止门/十一码演进/canary 语义/数值表/离线副本边界）+§5.6 同构冻结面演进依据登记（六条件程序）+机械判据清单（§8）+K 缺口登记（§17）+P&V 定稿决策（§16） |

### 5.2 Files Allowed to Modify（恰 3）

| 文件 | Owner/阶段 | 边界 |
| --- | --- | --- |
| `Dockerfile` | P&V（C1，与 Packet 同一提交） | **恰 +1 行**：`COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0039_Real_Pilot_Descriptor.md ./docs/`（插 L69 IP-0038 Packet COPY 行后）；既有行零改动。基线 blob `2ce873d3e0343a4e5d87d55587d3176b607155b7` |
| `tests/test_v4_baseline_real_run.py` | P&V（C2，冻结面演进 v8→v9；97→112） | R6 演进+新增恰 15 方法（§9）；六条件程序（§10）；97 旧方法零改动+唯一授权同步集（1 静态锚方法恰三 hunk+2 文件级常量）。基线 blob `50f78bd6128b2b95d3452639e7b1ea40b1365e3e` 永久在链 |
| `benchmarks/v4/baseline/real_run.py` | Implementation（C3） | **恰五处面**（R2/R3/R4）：①新描述子常量+目录条目（§7.1.2）；②loader 三处取值改 descriptor 驱动（date/retrieval/fixture_key，§7.2.2）；③`_ApprovalContract` 追加 `stop_on_first_failure: bool = False`（§7.2.3）；④评估器携带态两个私有属性（§7.3.3）；⑤`__call__` 停止门块+enum/消息表各一条（§7.3.2/§7.4.1）。零其他改动（零新 import、零公共签名变化、`__all__` 不变）。基线 blob `d363e457cb79913a627cfda6ce5848557233fc07` |

### 5.3 Read-only Reference Files（只读消费）

`benchmarks/v4/baseline/` 其余全部模块（budget/orchestrate/run/collect/expert_timing/offline_flow/report/fixtures）与各级 `__init__.py`（`run_repeats`/`run_baseline_attempt`/`reset_cold_state`/`_run_shaped_repeats`/`BudgetLedger`/`BudgetGateError` 冻结基元只读消费）；`lima/baseline_run_result.py`（聚合统计规则只读）；IP-0024..0038 Packet、两份批准工件、决策包、裁定文件；`evaluation_data/**` 全部；`.pv_tmp/` 各记录。

### 5.4 Files Forbidden（diff 必空；Done Command 7 逐 blob 守护）

`benchmarks/v4/baseline/` 其余全部模块与各级 `__init__.py`；`tests/` 其余全部既有文件（十个 v4 冻结测试文件 322 方法与其他）；`evaluation_data/**` 全部；`lima/**`；`scripts/**`；`docs/` 其余全部（含 IP-0036/0037/0038 Packet、两份批准工件、V5 表）；`pyproject.toml`/`requirements.txt`/`.github/**`/`.gitignore`/`.gitattributes`/前端；`.pv_tmp/**` 不提交（离线副本与日志仅存 `.pv_tmp/OFFLINE_TWIN_IP-0039_2026-09-30/` 与 `.pv_tmp/RED_IP-0039_2026-09-30/`）。

### 5.5 提交链拓扑（CA §Handoff/Done Command 8；冻结）

C1 = Packet + Dockerfile 恰 1 行（1 Add + 1 Modify，同一提交，前缀 `[IP-0039][PV]`）→ C2 = test_v4_baseline_real_run.py v8→v9 落定（1 Modify；Frozen Test Commit；提交信息**逐字** `[IP-0039][PV] Freeze acceptance tests v9 (RED)`；RED 证据先于冻结落盘并独立日志归档 `.pv_tmp/RED_IP-0039_2026-09-30/`）→ C3 = real_run.py（1 Modify，前缀 `[IP-0039][IMPL]`；**必须以 C2 为祖先**，Done Command 8）→ C-final（P&V 独立验证+R7 离线副本全链实际执行；如触发 ALLOWED_ONCE/修复提交须引用编号）。单 PR；不 push（合并/推送/评论由主会话按 Maintainer 授权执行，P&V/IMPL 零远端写）。

### 5.6 与其他活动 IP 的冲突分析（冻结面演进依据登记）

无并行活动 IP 占用本切片路径（IP-0039 编号未占用，CA §Authoritative Inputs #2 占用检查）。**冻结面演进依据显式登记（IP-0033..0038 Packet §5.6 先例）= 2026-09-30 第六轮 Maintainer 授权（裁定 §3 a/b/c + #247 Scope 1-3）+CA-IP-0039-v1.0**，演进对象与覆盖登记：

1. **`REAL_RUN_ARTIFACT_FAMILY` 目录**：十键→十一键（新增 `real-pilot/large-repo`；closed catalog）；新描述子=七字段+{fixture_key, date_pin, retrieval_date_pin, stop_on_first_failure}（11 字段）；旧十描述子七字段七值逐字节不变（构建代码路径零改动——新键以独立常量+条目加入，`_build_artifact_family` 既有十键派生路径零改动）。
2. **`_load_and_validate_approval` 三处取值**：`$.date`/`$.pricing.retrieval_date` 期望值与 `fixture_key` 分派改 descriptor 驱动（§7.2.2；旧键输出逐字节不变；仍逐字比较）。
3. **`_ApprovalContract`** 追加 `stop_on_first_failure: bool = False`（私有 dataclass，非公共接口；`__all__` 六符号不变）。
4. **`RealRunErrorCode`** 追加 `REAL_RUN_BATCH_STOPPED`（第 11 成员，尾位）+`_STABLE_MESSAGES` 对应条目（§7.4.1 定稿文案）。
5. **`_GuardedRealEvaluator`**：`__init__` 两个私有属性 + `__call__` 停止门块（§7.3.2/§7.3.3）。
6. **测试面**：tests/test_v4_baseline_real_run.py v8→v9（§10 六条件；恰 15 新方法+唯一授权同步集，97→112）。
7. **Dockerfile**：恰 +1 行（A1 COPY；插入位=L69 后）。

历史文档零改动；本节即唯一演进依据登记处。IP-0024..0038 一切其余冻结面禁止触碰。

## 6. 依赖、网络、文件系统与权限边界

- **依赖**：零新增第三方依赖；**real_run.py 零新 import**（CA Stop 7 明文"预期零新 import"；新常量/字段/enum 成员/比较逻辑全部语言内置面）。测试文件（M2）零新增 import（新增方法全部复用文件内既有 arrange 基建与已导入符号）。
- **网络**：测试全离线、fake transport/确定性 clock patch/本地合成工件；永不触网（既有 `_forbidden_network_roots` 断言延续）。**本 IP 全程任何真实网络/下载/付费调用/真实凭据注入=Stop Condition 1/4（绝对禁令）**。本 P&V 会话零网络（Packet 制作与冻结全程本地；CA 已完成远程只读核验）。
- **文件系统**：证据文件只写调用方提供的一次性输出目录（离线测试写 tempdir）；库内除 §5.1/§5.2 四文件外零写入；离线副本仅存 `.pv_tmp/OFFLINE_TWIN_IP-0039_2026-09-30/`（不提交、不复制入库）；不读环境变量/配置/.env。
- **数据库/容器/远端写**：无数据库；容器面仅 Dockerfile +1 COPY 行；零远端写（不 push、不开 PR、不关 Issue、不改 Ledger 远端状态——合并/推送/评论由主会话按 Maintainer 授权另行核发）。
- **凭据**：api_key 仍为显式必填参数，永不落盘/入日志/入错误消息/入证据；本叶零真实调用故 api_key 永不被真实使用（fake transport 面证明；离线副本用合成 key 并标注 `offline-rehearsal-no-paid-effect`）。
- **clock**：`_monotonic` 模块缝（IP-0035 冻结）继续是唯一 wall 时源；本叶零新时源、零真实 sleep（截止负例经既有 `patch_monotonic`+`_JumpClock` 确定性 arrange）。

## 7. 实现契约细化（Packet 定稿；R2/R3/R4/R5/R7 落位）

### 7.1 FR-01：真实 pilot 专属描述子（R2）

#### 7.1.1 冻结契约：目录终形（C3-①）

- **新键**：`real-pilot/large-repo`（与既有 `archetype/large-repo` 为不同键）。目录 `REAL_RUN_ARTIFACT_FAMILY` 十键→**十一键**（closed catalog）。
- **新字段闭集（恰 4 个）**：`fixture_key`、`date_pin`、`retrieval_date_pin`、`stop_on_first_failure`。新描述子=既有七字段+此四字段（共 11 字段）；**旧十描述子保持恰七字段、七值逐字节不变**（构建代码路径零改动）。
- **新描述子字段值**（全部逐字钉扎）：

| 字段 | 值 | 依据 |
| --- | --- | --- |
| `repository` | `"lima-synth/large-repo"` | 逐字复用 `_synthetic_artifact_descriptor("archetype/large-repo", fingerprint)` 派生值（R2.3） |
| `requested_name` | `"lima-synth/large-repo"` | 同上 |
| `commit_sha` | `sha256("lima-synth-artifact:archetype/large-repo:<registry-fingerprint>")[:40]` | 同上（同一 registry 指纹、同一派生规则、零新派生机制——fixture 即该合成 fixture，溯源诚实） |
| `tarball_url` | `"https://lima-synth.invalid/large-repo/tar.gz/<commit_sha>"` | 同上（RFC 2606 `.invalid`，永不 fetchable） |
| `tarball_filename` | `"lima-synth-large-repo-{commit_sha}.tar.gz"` | 同上（`{commit_sha}` 占位符模板形） |
| `approval_type` | `"PR3D-REAL-PILOT-ONE-SHOT"` | R2.3 定稿 |
| `run_name` | `"pr3d-real-pilot-2026-09-30"` | R2.3/R5 定稿 |
| `fixture_key` | `"archetype/large-repo"` | R2.3（显式绑定既有确定性合成 fixture） |
| `date_pin` | `"2026-09-30"` | R5（Asia/Shanghai；=第六轮签定/检索证据日） |
| `retrieval_date_pin` | `"2026-09-30"` | R5（同上） |
| `stop_on_first_failure` | `True`（Python `bool`；派发摘要字面 `"true"` 为布尔值的字符串渲染，以 CA R2.3/R2.5 为准——见 §16 DR-IP-0039-PV-1） | R2.3/R3 |

- **模块常量形（名可等价，不进 `__all__`）**：`_REAL_PILOT_ARTIFACT_KEY`/`_REAL_PILOT_APPROVAL_TYPE_PIN`/`_REAL_PILOT_RUN_NAME_PIN`/`_REAL_PILOT_DATE_PIN`/`_REAL_PILOT_RETRIEVAL_DATE_PIN`（R2.3 建议）。新条目加入 `REAL_RUN_ARTIFACT_FAMILY` 的方式=独立常量+目录条目（实现细节，R11 不升级决策）；既有 `_build_artifact_family` 的十键派生路径零改动。
- **身份钉扎不变**：新键沿用全部模型钉扎（request name/served forms/base_url/prompt/thinking/max_tokens=8000/请求体上限）——loader 对 `$.model.*`/`$.pricing.source_url`/`$.pricing.basis` 等共享钉扎的比较零改动。
- **本地物化路径**：`fixture_key="archetype/large-repo"` 经 §7.2.2 分派直达 `_materialize_synthetic_fixture`→`materialize_fixture("archetype/large-repo")`，**绝不外部下载**（`fixture_key is not None` 分支，L1828；N3 断言 download channel 零 GET）。

#### 7.1.2 旧族兼容断言级（AC-1）

旧十描述子目录输出与旧工件校验结果**逐字节不变**：旧十键仍恰七字段、七值逐字节（llamafactory 七钉扎+九合成派生）；旧键 loader 输出（date/retrieval/fixture_key 三处 `.get` 缺省=旧值）逐字节不变。冻结测试 M1（N1）钉扎；既有 96 方法零改动通过+v8 全绿回归为第二重证据（AC-4）。

### 7.2 FR-02：loader 三处 descriptor 驱动化+`_ApprovalContract` 新字段（R2.4/R2.5/R5）

#### 7.2.1 日期钉扎数值（R5 定稿）

`date_pin="2026-09-30"`、`retrieval_date_pin="2026-09-30"`（时区 **Asia/Shanghai**；=第六轮签定/检索证据日）；`run_name="pr3d-real-pilot-2026-09-30"`。**仍为逐字比较**（`_require_str_pin`）：新键下 date/retrieval 任一不符→`APPROVAL_ARTIFACT_INVALID`（对应 `$.date`/`$.pricing.retrieval_date`），无任何宽容。**跨日纪律**：未启用真实调用而跨日时，主会话对两 pin 走受审修订（新工件新值，重新离线验收），不得放松校验或以通配/区间替代（Stop 3/16）。

#### 7.2.2 冻结契约：三处取值改 descriptor 驱动（C3-②；旧键输出零变化）

1. `$.date` 期望值：`"2026-09-28"` → `descriptor.get("date_pin", "2026-09-28")`（L851）。
2. `$.pricing.retrieval_date` 期望值：`_PRICING_RETRIEVAL_DATE_PIN` → `descriptor.get("retrieval_date_pin", _PRICING_RETRIEVAL_DATE_PIN)`（L900-904）。
3. `fixture_key` 分派：`artifact_key if artifact_key in _SYNTHETIC_SET else None` → `descriptor["fixture_key"] if "fixture_key" in descriptor else (artifact_key if artifact_key in _SYNTHETIC_SET else None)`（L1002）——旧合成键结果=自身（同前）、旧默认键=None（同前）、新键="archetype/large-repo"（本地物化）。
4. `$.approval_type`/`$.run_name` 已是 descriptor 取值比较（L848/L850），机制零改动。

#### 7.2.3 冻结契约：`_ApprovalContract` 追加字段（C3-③）

`_ApprovalContract` 追加尾字段 `stop_on_first_failure: bool = False`（带默认；loader 传 `descriptor.get("stop_on_first_failure", False)`；旧路径构造结果不变；私有 dataclass 非公共接口，`__all__` 六符号不变）。

### 7.3 FR-03：首败停止门（R3）

#### 7.3.1 判定面与位置（C3-⑤）

判定面=**新描述子标志字段 `stop_on_first_failure`**（数据而非命名耦合；静态锚可断言字段闭集）。门位置=`_GuardedRealEvaluator.__call__` 内，**恰在 canary latch 检查（L1492-1493）之后、index==1 canary 清单与 reserve 之前**。冻结代码块（R3.1 逐字）：

```python
if self._stop_on_first_failure and (
    self._batch_stopped
    or any(prior.failure_code is not None for prior in self.records[:-1])
):
    self._batch_stopped = True
    raise self._typed(record, RealRunErrorCode.REAL_RUN_BATCH_STOPPED)
```

遍历语义=**任一先前 record 带 failure_code**（当前 record 在该点 failure_code 恒为 None，等价遍历全部 records 可接受，Packet 注记等价性）。

#### 7.3.2 触发面（六类失败全覆盖）

机械依据=它们最终都在 record.failure_code 留痕：transport（`_typed`→EXECUTION_ERROR，`$.transport`）、响应契约（同）、usage 缺失（同，`$.usage`）、身份（`_typed`→EXECUTION_ERROR+`_settle` L1749-1755 置 canary latch——身份失败后本就 latch，停止门为其超集面；其后续 attempt 的诚实可观测形态见 §16 DR-IP-0039-PV-2）、**预算（reserve 处 `BudgetGateError` 置 failure_code="EXECUTION_ERROR" 后透传——既有不 latch 缺口即 F4，本门补齐）**、**截止（`_timeout_failure` 置 "EXECUTION_TIMEOUT"）**。

#### 7.3.3 携带态（C3-④）

`__init__` 两个私有属性：`self._stop_on_first_failure`（取 `approval.stop_on_first_failure`）与 `self._batch_stopped = False`（初始）。**置 latch=门私有粘滞位 `self._batch_stopped`——不是 canary `self._latched`**（绝对否决复用 `self._latched`：会使停止后的后续 attempt 命中 canary latch 检查而误标 REAL_RUN_CANARY_FAILED）。停止后：后续每次 `__call__` 一律 raise `REAL_RUN_BATCH_STOPPED`、**零 reserve、零 POST、零 canary 清单执行**；`run_baseline_attempt` 既有"Exception 捕获→分类→持久化→返回"驱动循环继续收尾（零改 run.py）。

#### 7.3.4 记账/证据面（零新机制）

经 `_typed` booking（outcome="failure"/failure_code="EXECUTION_ERROR"/error_code="REAL_RUN_BATCH_STOPPED"/error_field_path="$"（批级结构-only 根路径，R3.4 定稿））；停止的 attempt 无 reserve 无 usage→**无结算调用**（与既有 canary-latch 后续 raise 同构）；attempt 文档与 manifest `failures` 列表（L2423-2429 逐 record 收录）自动承载——**首个真实原因的 record/条目保持其原 code 不变（首因保留），后续被阻 attempt 以新码标注**。停止门触发不改变任何已发生 attempt 的结算结果。

#### 7.3.5 门禁用=旧路径逐字节不变（AC-2）

`_stop_on_first_failure` False（旧十键/旧 {5,5}/既有 shaped）→该分支永不进入，行为逐字节不变（N8 回归+既有 96 方法零改动通过）。

### 7.4 FR-03：十一码演进+canary 清单交互（R4）

#### 7.4.1 enum 追加与消息定稿（C3-⑤）

`RealRunErrorCode.REAL_RUN_BATCH_STOPPED = "REAL_RUN_BATCH_STOPPED"`（**追加于 `REAL_RUN_CANARY_FAILED` 之后=第 11 成员；既有十成员顺序与值逐字不变**）。`_STABLE_MESSAGES` 新条目（R4.1 定稿，不嵌数值、与 canary 可区分、与既有文风一致）：

```python
RealRunErrorCode.REAL_RUN_BATCH_STOPPED: (
    "A real-pilot failure was already recorded; the first-failure stop"
    " gate blocks every further call in this batch."
),
```

（对比 canary：`"The canary check failed; no further real calls are permitted in this batch."`——主语与谓词均不同，无数字。）

#### 7.4.2 canary 清单交互语义（R4.3；仅用既有值，不新增字段/枚举值）

首败先于 index==1 时，停止门在清单执行前 raise→`_run_canary_checklist` 从未运行→manifest `canary.status` 保持**既有初始值 `"failed"`**、`canary.checks` 保持**既有初始空 dict `{}`**。依据：该面**今日已存在**（attempt-0 取消路径 settle_cancelled 后证据面即 status="failed"+checks={}——既有诚实形态，非新造语义）；五键 checks dict="已评估且失败"，空 dict="从未评估"，机器可区分。**规范性登记**：status="failed" 无 checks **不得**解读为"canary 运行且失败"；首个真实原因在 attempts/manifest failures 以其原 code 呈现，后续为 BATCH_STOPPED，无一误标 canary。attempt-0 成功而清单某项失败（如 batch_margin arrange）时清单照常运行→CANARY_FAILED latch 既有语义在新键下保持（N7）。

#### 7.4.3 身份失败交互（R3.2/K4；flagged——见 §16 DR-IP-0039-PV-2）

身份失败经 `_settle` L1749-1755 置 `self._latched=True`（既有 D4 语义，冻结不可改）。在 R3.1 钉扎的门位置（latch 检查之后）下，身份失败的后续 attempt 在 `__call__` 顶部命中既有 latch 检查→`REAL_RUN_CANARY_FAILED`（既有身份 latch 语义），非 BATCH_STOPPED；零新增 POST 与首因保留不受影响（裁定 §3c 的两项硬要求均满足）。K4 括注"后续=BATCH_STOPPED，非 CANARY_FAILED"在该门位置下机械不可达——P&V 冻结诚实可观测形态（§9 M7）并 flag 提交 Coordinator（DR-IP-0039-PV-2 + OBS-1）；Coordinator 如裁定改为"门先于 latch 检查"或其他形态，须以 CA 勘误（v1.1+）授权重新冻结相应方法。

### 7.5 FR-04：数值真值源+离线副本边界（R5/R7）

#### 7.5.1 七维/policy 数值表（冻结；=裁定 §2 表=IP-0038 Packet §7.3=_PREFLIGHT 常量，本 P&V 会话逐值亲核一致）

| 维度（BUDGET_DIMENSIONS 序） | per_run | batch |
| --- | ---: | ---: |
| cost_micro_usd | 100,000 | 198,000 |
| calls | 1 | 5 |
| prompt_tokens | 150,000 | 500,000 |
| completion_tokens | 8,000 | 40,000 |
| wall_ms | 1,200,000 | 6,000,000 |
| download_bytes | 250,000,000 | 250,000,000 |
| storage_bytes | 500,000,000 | 500,000,000 |

attempt_policy：`{"cold": 1, "warm": 4, "max_attempts": 5, "canary_required": true, "canary_first_attempt": 0}`（pilot 计划形状）。真实 POST 硬上限 5。约束验证沿用 IP-0038 Packet §7.3.2（逐维 batch≥per_run、batch≥首轮最坏预留、五次累计含容、零门放松）。

#### 7.5.2 离线副本（无付费效力；R7）

C-final 由 P&V 以 `.pv_tmp/OFFLINE_TWIN_IP-0039_2026-09-30/` 内工件执行——与最终真实工件**逐值一致**（七维=§7.5.1 表、policy {1,4,5}、run_name、fixture 绑定、date/retrieval=2026-09-30、模型钉扎逐字），仅 transport（fake 注入）/凭据（合成 key）/审批生效状态（标注 `offline-rehearsal-no-paid-effect`）隔离；经正式入口 `run_real_baseline_suite(artifact_key="real-pilot/large-repo")`+空目录执行到报告；断言面=N3 同款核对表，登记于 Verification Report（裁定 §4"不得复用旧预演作为新描述子通过的证据"——必须新执行）。归档输出与日志，不入库、不进 PR diff。

#### 7.5.3 付费效力机械判据（沿 IP-0038 R4，规范性）

工件具付费调用效力**当且仅当三条件同时成立**：(1)真实凭据可用；(2)真实 transport 入口（非 fake 注入的实际网络出口可用）；(3)审批链生效（进入真实审批/授权链，非演练标注）。离线副本三条件零成立→不构成"签发具付费效力批准工件"。防御性条件：a)绝不用于真实 transport/真实凭据（违反=绝对停，Stop 4）；b)仅存 `.pv_tmp` 不提交不复制入库；c)带 offline 标注；d)数值与冻结内联 fixture 逐值一致（单一真值源=§7.5.1 表）。**真实工件不入库**（裁定 §4/§7）：主会话在裁定 §5 门后另行签发与封存；本叶任何角色不得在 PR/分支/CI 上携带。

## 8. 离线负例与机械判据矩阵（FR-04/AC-2/AC-3；裁定 §4 逐字；全 fake transport，CI 零真实调用）

裁定 §4 成功路径断言面（逐字承载=N3/M3）：**恰 5 fake POST、5 件 attempt 文档、ledger.calls=5、manifest 计划形状 1/4、零预算拒绝、warm 复用 4；attempt-0 的 cold_reset.performed=False、materialization_count=1，performed=True 的计数为 0；无来源 V5 字段保持 null+unavailable，聚合按冻结规则为 insufficient_sample**；另：下载通道零 GET、run_name/日期/模型钉扎逐值经装载与全链隐式证明。

裁定 §4 八类负例（逐字承载；"以实际可达错误面断言零新增 POST，允许装载期先拒绝，不强求不可达的错误码。验证拒绝后无真实能力、无隐含 SDK 重试"——零新增 POST 由 transport 计数断言承载）：

| # | 负例面（裁定 §4 原文） | 冻结断言（可达错误面） | 方法 |
| --- | --- | --- | --- |
| 1 | 未知描述子 | `artifact_key="real-pilot/unknown"` 等→`APPROVAL_ARTIFACT_INVALID`/`$`，零 POST/零 GET | M13（N9） |
| 2 | 错误 run_name（新键下） | `$.run_name`；错 approval_type→`$.approval_type`；零 POST | M13（N10） |
| 3 | 日期/检索日期不符 | 新键拒 2026-09-28（`$.date`/`$.pricing.retrieval_date`，逐字拒绝无宽容）；旧键（默认+合成各一）拒 2026-09-30 的 date 与 retrieval_date（旧族默认零变化负证） | M4（N4） |
| 4 | 预算缺一维 | 诚实面=维度键删除→loader 精确键集门 `APPROVAL_ARTIFACT_INVALID @ $.budget.<level>`（零 POST/零 GET）；`BUDGET_SPEC_INVALID` 透传面=第 5 类 batch<per_run 装载期拦截（字面"缺一维→BUDGET_SPEC_INVALID"的机械核验见 §16 DR-IP-0039-PV-3） | M14（N11a/b） |
| 5 | 资源许可不足 | per_run=表值+batch.download=249,999,999→装载期 `BudgetGateError(BUDGET_SPEC_INVALID) @ $.budget.batch.download_bytes` 透传（零 POST/零 GET）；两级均 249,999,999→首轮 reserve `RUN_BUDGET_EXCEEDED @ $.budget.per_run.download_bytes` 拒付零 POST（per_run 门先于 batch 门——冻结门序；字面 `BATCH_BUDGET_EXCEEDED` 首轮不可达性沿用 IP-0038 DR-3，见 §16 DR-IP-0039-PV-3；新键下后续 attempt=BATCH_STOPPED） | M14（N11c） |
| 6 | 非空输出目录（新键） | `REAL_RUN_OUTPUT_NOT_EMPTY`，零 POST | M13（N12） |
| 7 | canary 首响应失败 | attempt-0 首响应失败（如 usage 缺失）→零后续 POST、清单从未运行（canary.status="failed"+checks=={}）、后续 attempt=REAL_RUN_BATCH_STOPPED（非 CANARY_FAILED 误标）；attempt-0 成功+清单失败→CANARY_FAILED latch、零后续 POST（既有语义在新路径不回退） | M10（N6）/M11（N7） |
| 8 | 后续 warm 的 transport/响应/usage/身份失败与预算/截止拒绝 | 六类注入（M5-M9）：各自首败后零新增 POST（transport 计数不增）；首因 attempt 的 error_code 保持原码；后续 attempt 文档=REAL_RUN_BATCH_STOPPED（error_field_path="$"）——身份类诚实形态见 §16 DR-IP-0039-PV-2；manifest failures 逐条核对（首因+后续新码，无 CANARY_FAILED 误标〔身份类=既有 D4 latch 语义，flagged〕） | M5-M9（N5） |

## 9. 测试矩阵（M2 单文件面；R6 预算：97 存留+恰 15 新增=112 ≤113 上界；基线 97）

### 9.1 新增方法（15 个；恰一个新类 `TestRealPilotDescriptorAndStopGate(_RealRunTestCase)`，置于 `TestPreflightCalibration` 之后、`if __name__` 之前）

| 方法（N 映射） | 覆盖 | 断言面（冻结） | RED 态（对未修改 real_run.py @352646bf） |
| --- | --- | --- | --- |
| `test_real_pilot_catalog_eleven_keys_and_field_sets`（N1） | FR-01/AC-1 | 十一键闭集（set 相等+len==11）；旧十键恰七字段七值逐字节（llamafactory 七钉扎与九合成派生复断言）；新键=七字段+恰四新字段且值逐字钉扎（§7.1.1 表；溯源五字段==`archetype/large-repo` 按公式独立派生值——PC3 双源）；`stop_on_first_failure is True` | **RED**（目录十键；十一键集合不等） |
| `test_real_pilot_error_code_eleven_members_and_messages`（N2） | FR-03/AC-2 | enum 十一值==_FROZEN_ERROR_CODES（更新后）；`list(enum)[-1]=="REAL_RUN_BATCH_STOPPED"`（尾位）且前十==冻结十序；`_STABLE_MESSAGES` 恰覆盖十一码；新消息逐字==定稿文案、不含数字、≠canary 消息；十旧码消息逐字不变 | **RED**（enum 十枚举 vs 常量十一） |
| `test_real_pilot_offline_twin_full_chain_positive`（N3） | FR-01/FR-02/FR-04/AC-1/AC-3 | §8 成功路径断言面全量（恰 5 fake POST/5 件 attempt/ledger.calls=5/violations=0/manifest 1/4+failures==[]+attempt_count==5/canary passed/warm 复用 4/cold_reset performed=False count=1+performed=True 计 0/下载通道零 GET/consumed.download=0+released=250M+存储关系/聚合 insufficient_sample（PC3 关系断言）/报告 V5 无来源字段全 null+unavailable/run_name==pr3d-real-pilot-2026-09-30） | **RED**（新键不解析→`$` 拒绝；IP-0034 同型能力缺席锚） |
| `test_real_pilot_date_pinning_dual_regime`（N4） | FR-02/AC-1 | 新键半：接受 2026-09-30/2026-09-30（loader 直载成功+contract 钉扎面）；新键拒 2026-09-28 date（`$.date`）与 retrieval（`$.pricing.retrieval_date`）——逐字拒绝无宽容。旧键半：默认键与合成键（`archetype/application`）拒 2026-09-30 的 date 与 retrieval_date（旧族默认零变化负证）。方法内按断言组归因（新键半 RED/旧键半按设计通过） | **RED**（新键半 4 组失败；旧键半 4 组通过） |
| `test_real_pilot_stop_gate_transport_failure`（N5-transport） | FR-03/AC-2 | 新键+{1,4}：attempt-0 注入 `ConnectionError`→首因=REAL_RUN_TRANSPORT_FAILED（`$.transport`）保留；attempt-1..4=REAL_RUN_BATCH_STOPPED（error_field_path="$"）；chat_calls==1（零新增 POST）；manifest failures 逐条核对；canary.status=="failed"+checks=={}（清单从未运行）；被阻 attempt 零结算（N13 断言组：ledger batch.calls==1） | **RED**（新键不解析） |
| `test_real_pilot_stop_gate_contract_and_usage_failures`（N5-契约+usage） | FR-03/AC-2 | 双 subTest：verdict_shape 失败体→首因=REAL_RUN_RESPONSE_INVALID；usage 缺失体→首因=REAL_RUN_USAGE_MISSING（`$.usage`）；各自后续=BATCH_STOPPED、chat_calls==1、首因保留、manifest failures 逐条核对、无 CANARY_FAILED | **RED**（同上） |
| `test_real_pilot_stop_gate_identity_drift_first_cause_kept`（N5-身份；§16 DR-2 flagged） | FR-03/AC-2 | attempt-0 成功（baseline 置位）+attempt-1 指纹漂移→首因=REAL_RUN_IDENTITY_CHANGED（`$.identity`）保留；chat_calls==2（首败后零新增 POST）；后续 attempt=REAL_RUN_CANARY_FAILED（**既有 D4 身份 latch 语义——R3.1 门位置下的诚实可观测形态，K4 字面"BATCH_STOPPED"不可达，flagged**）；零 BATCH_STOPPED 误标首因；manifest failures 逐条核对 | **RED**（新键不解析） |
| `test_real_pilot_stop_gate_budget_refusal_mid_batch`（N5-预算） | FR-03/AC-2 | 新键+{1,4}+batch.calls=2：attempt-0/1 成功（chat_calls==2）；attempt-2 reserve→`BATCH_BUDGET_EXCEEDED @ $.budget.batch.calls`（首因保留——F4 缺口：既有面不 latch，无门时 attempt-3/4 将再次 POST 后被拒）；attempt-3/4=REAL_RUN_BATCH_STOPPED（零新增 POST）；manifest failures==[BATCH_BUDGET_EXCEEDED, BATCH_STOPPED, BATCH_STOPPED] | **RED**（新键不解析） |
| `test_real_pilot_stop_gate_deadline_timeout`（N5-截止） | FR-03/AC-2 | `patch_monotonic`+`_JumpClock`+`_ClockJumpChatTransport(chat_jump_ms=1_200_000)`：attempt-0 post-call deadline recheck→EXECUTION_TIMEOUT/failure_code（首因保留）；后续=BATCH_STOPPED；chat_calls==1；零真实 sleep | **RED**（新键不解析） |
| `test_real_pilot_stop_gate_precedes_canary_checklist`（N6） | FR-03/AC-2 | attempt-0 失败（usage 缺失 arrange）→清单从未运行：manifest canary.status=="failed" 且 checks=={}；attempt-1..4=REAL_RUN_BATCH_STOPPED（非 CANARY_FAILED）；chat_calls==1 | **RED**（新键不解析；六类 arrange 均可，冻结取 usage 面） |
| `test_real_pilot_canary_latch_preserved_on_new_key`（N7） | FR-03/AC-2 | attempt-0 成功+清单失败 arrange（prompt_tokens 超预留→usage_within_reservation False）→attempt-1..4=REAL_RUN_CANARY_FAILED、latch、chat_calls==1（零后续 POST；既有语义在新路径不回退；门不干扰：清单照常运行） | **RED**（新键不解析） |
| `test_real_pilot_stop_gate_inactive_on_old_keys`（N8） | FR-03/AC-2（回归） | 旧合成键 `archetype/large-repo`+pilot 形状，attempt-2 注入 transport 失败→attempt-3/4 照常执行（chat_calls==5=全批）、零 BATCH_STOPPED、manifest failures==[attempt-2 原码]；停止门不作用于旧键 | **按设计通过**（既有行为回归；基线即目标行为） |
| `test_real_pilot_negative_matrix_loader_and_output_root`（N9+N10+N12） | FR-01/FR-04/AC-3 | 未知键 `real-pilot/unknown`→`APPROVAL_ARTIFACT_INVALID/$`（零 POST/GET）；新键错 run_name→`$.run_name`；新键错 approval_type→`$.approval_type`；新键非空输出目录→`REAL_RUN_OUTPUT_NOT_EMPTY`（零 POST） | **RED**（N10/N12 组：新键不解析先于目标错误面；N9 组按设计通过） |
| `test_real_pilot_negative_budget_faces`（N11a/b/c） | FR-04/AC-3 | (a) 删 `budget.batch.wall_ms` 键→`APPROVAL_ARTIFACT_INVALID @ $.budget.batch`（loader 精确键集门；零 POST/GET）；(b) batch.download=249,999,999（per_run=表值）→`BudgetGateError(BUDGET_SPEC_INVALID) @ $.budget.batch.download_bytes` 透传（装载期；零 POST/GET）；(c) 两级均 249,999,999→首轮 reserve `RUN_BUDGET_EXCEEDED @ $.budget.per_run.download_bytes` 拒付零 POST、ledger.calls==0、新键下 attempt-1..4=BATCH_STOPPED | **RED**（新键不解析） |
| `test_real_pilot_stopped_attempts_zero_ledger_face`（N13） | FR-03/AC-2 | 停止后账本面：transport 首败 arrange 下 ledger.json batch.calls==1（仅 attempt-0 预留）、被阻 attempt 零 reserve 零记账零 usage（attempt 文档 usage None、结算面仅含已真实发生的 attempt）；与 M5 同 arrange 独立断言组 | **RED**（新键不解析） |

### 9.2 (b) 类值更新（唯一授权同步集；全部由 R2/R4 裁定驱动，无一处实现便利）

1. **文件级常量 `_FROZEN_ERROR_CODES`**：十值→十一值（追加 `"REAL_RUN_BATCH_STOPPED"`；闭集只增不减）。方法体 L3724/L4042/L4299/L4626 均为常量相对断言，**零方法体改动**自动同步。
2. **文件级常量 `_ARTIFACT_FAMILY_KEYS`**：十键→十一键（追加 `"real-pilot/large-repo"`）；`_SYNTHETIC_ARTIFACT_KEYS` 派生过滤由"仅排除 default key"改为"排除 `external/llamafactory-replay` 与 `real-pilot/large-repo` 两键"（K6/R6——否则九键派生被污染，L3794/L3906 迭代错）。
3. **静态锚 `test_artifact_family_catalog_frozen_ten_keys` 就地同步**（唯一授权就地改动的旧方法，**恰三 hunk**）：①`len(catalog), 10`→`11`；②全键字段集循环改为分支（旧键==七字段/新键==七字段+R2 四字段，经 `_DESCRIPTOR_FIELDS | _REAL_PILOT_EXTRA_FIELDS`）；③方法头注释键集注记更新（十键→十一键闭集）。闭集只增不减。
4. 新增 arrange 基建（纯增量）：`_REAL_PILOT_KEY`/`_REAL_PILOT_APPROVAL_TYPE`/`_REAL_PILOT_RUN_NAME`/`_REAL_PILOT_DATE_PIN`/`_REAL_PILOT_RETRIEVAL_DATE_PIN`/`_REAL_PILOT_EXTRA_FIELDS`/`_REAL_PILOT_STOP_MESSAGE` 常量与 `_real_pilot_descriptor()`（按公式独立派生溯源五字段——PC3 双源，不读目录、不硬抄实现值）与 `_real_pilot_mutate()`（deepcopy repo 文档仅变异新键钉扎面+attempt_policy/budget 七维——与 `_preflight_policy` 同源纪律）helper；模块 docstring 追加 v9 演进段（演进链注记，版本链条件）。**其余 96 方法与全部既有断言逐字节不变**。

### 9.3 RED 形态（Modify 型 IP；产品已存在；逐方法归因）

对**未修改产品（352646b 版）**运行 v9（C1 已落库后、C2 冻结前）：

- **新类 15 方法**：14 方法 RED（M1-M11/M13-M15——新键不解析→`$` 拒绝〔IP-0034 同型能力缺席锚：arrange 文档本身合法（按公式派生钉扎），失败=loader 对新键的目录缺失拒绝，非 arrange/import/lint 错误〕；M1/M2 静态锚=十一键/十一码缺席）；M12（N8）按设计通过（既有行为回归）。M4 方法内按断言组归因（新键半 RED/旧键半通过）；M13 内 N9 组通过、N10/N12 组 RED。
- **旧方法因授权同步在基线红（4 个，如实归因为授权同步——十一码/十一键缺席）**：`test_frozen_taxonomy_checkpoints_and_canary_static_anchors`（L3724，enum 十 vs 常量十一）、`test_artifact_family_catalog_frozen_ten_keys`（L3767，三 hunk 同步后 len/set 十一 vs 目录十）、`test_offline_full_chain_synthetic_key_with_fake_transport`（L3962，其尾 L4042 常量相对断言）、`test_batch_protocol_static_surface_frozen`（L4288，其 L4299 常量相对断言）。**其余 93 旧方法通过**（含 L3787/L3838 合成派生迭代——`_SYNTHETIC_ARTIFACT_KEYS` 过滤 hunk 使其按设计绿（K6）；L4626 `assertIn` 对增集保持通过）。
- 逐方法"RED 失败/按设计通过"归因表强制（归档 `.pv_tmp/RED_IP-0039_2026-09-30/`）；基线态证明=C0（97/322/discover 实际值绿）。
- C2 后自跑（Done Command 1 定向+4 编译/lint）：v9 在基线上按设计 RED；C-final 后全绿（112 方法）。

## 10. 冻结测试面演进程序（M2 单文件适用；CA R4.2/R6 六条件全文；正式 Packet 级一次性授权）

**冲突裁定**：IP-0039 的产品语义变更（目录十一键/loader 三处/停止门/十一码）必然触碰 IP-0032..0038 冻结测试面 `tests/test_v4_baseline_real_run.py`。**裁定：允许该文件以受控方式演进至冻结版本 v9**（先例=IP-0033..0038 Packet §10）。演进是产品语义驱动（非机械缺陷），ALLOWED_ONCE 不适用、不得以其消化——授权依据=CA-IP-0039-v1.0 R4.2/R6+本节。**演进依据=2026-09-30 第六轮 Maintainer 授权（裁定 §3 a/b/c+#247 Scope 1-3；§5.6 登记）。**

**演进六条件（任一不满足=Stop Condition 9）**：

1. **对象唯一**：仅 M2 一文件一次（v8→v9，97→112）；其余十个 v4 冻结测试文件（322 方法）与全部产品禁区模块 blob 逐字不变（Done Command 7 守护）。IP-0024..0037 冻结面=禁止。
2. **逐 hunk 归因**：每个 hunk 必须映射到 #247 FR-01..04/AC-1..4 之一或 CA 裁定编号（R2/R3/R4/R5/R6）并在 Packet 登记（§9.1 表已登记：15 新增方法逐条；§9.2 (b) 类更新→R2/R4/R6 驱动）。
3. **禁止弱化**：既有 97 方法断言不得删除或放松（fail-closed 门禁、泄露探针、hygiene、`__all__`/签名/数值守卫全部保留）；只允许 (a) 新增断言/方法、(b) 因显式登记的语义变更而更新的期望值（§9.2 唯一授权同步集：1 静态锚方法恰三 hunk+2 文件级常量）。**R4.2 唯一授权同步集之外的旧方法断言需要修改才能通过→Stop 9。**弱化判定争议 → Decision Request。
4. **版本链保留**：v1..v8 历史 blob（含 `50f78bd6`）与历史提交永久在链；Packet 记录基线与演进 blob（v9 blob 由 C2 冻结时登记于提交与验证记录）。
5. **RED 先于冻结**：C2 冻结前，M2 对未修改产品（352646b 版）运行并留档 RED 证据（独立日志文件归档 `.pv_tmp/RED_IP-0039_2026-09-30/`，每方法 traceback 可定位），逐方法登记"RED 失败/按设计通过"归因（§9.3）。
6. **角色纪律**：演进只在 C2 由 P&V 执行；Implementation 结构性零参与测试修改；C2 冻结提交后本 Assignment 的 ALLOWED_ONCE（§11）仅覆盖本文件面的机械缺陷（合计一次）。

**Pre-Freeze Harness Gate（冻结前必须全部通过；本 Packet 级强制）**：①测试文件可完整 import 与 collect（零加载期错误）；②新增 fixture/helper/参数组合经对现行产品的受控行为执行到断言处（区分 fixture 缺陷与行为缺失——新键缺席致 `$` 拒绝即行为缺失锚；arrange 本身不得有独立缺陷：新键工件除钉扎面/attempt_policy/budget 七维外全部复用冻结 repo 工件构造器，溯源五字段按冻结派生公式独立复算——PC2/PC3）；③Ruff `--no-cache` 在产品模块缺席态与最小桩模块存在态分别运行并双双通过（isort 的 first-party 分类依赖模块存在性，单态通过不可作为证据）；④临时桩（如有）位于临时目录且不入冻结提交；⑤RED 逐项归因于缺失产品行为，不来自 arrange/import/lint 失败；⑥方法预算 112（97+恰 15）不超 113 上界。

**ER 复核面**：ER 将逐 hunk 复核演进正当性（条件 2/3）、独立复跑 RED 归因、复核 §9 矩阵断言与 AC 映射。

## 11. ALLOWED_ONCE（一次性机械测试修正授权；CA §Mechanical Test Correction Allowance 全文转录）

C2 冻结后，P&V 可在不新增 Coordinator 调用的情况下自行纠正**一次**纯测试机械缺陷并重新冻结（v9→v9'），条件全部满足：①不改产品语义、公共接口、稳定错误码（含 R4.1 新码与文案）或文件范围（含 Dockerfile 行数）；②仅限 fixture/arrange/import/lint/测试基础设施缺陷；③旧 Frozen Commit 保留；④修正前缺陷证据（原始 traceback 独立日志）、修正后有效 RED、新 Frozen Commit 完整记录；⑤Implementation 未参与测试修改。涉及产品行为、验收语义或文件范围 → Decision Request；本授权与 R6 演进授权互不折抵、合计适用一次机械修正事件。

## 12. Stop Conditions（触发即停并提交 Decision Request；CA §Known Gaps and Stop Conditions 全文）

0. 派发前再核验失败：#247 正文/标签/远程状态与本地捕获不一致，或 Base SHA 上 main 出现冲突性实现（含 IP-0039 编号被占用）。
1. **任何真实网络/下载/付费调用/真实凭据注入（含分支上/CI 内/pre-merge"顺手验证"）——绝对禁令。**
2. **旧十描述子/{5,5}/既有 shaped 路径语义任何变化即停**（含旧键校验输出、旧 manifest/attempt 字节、旧 fixture_key 分派结果、停止门在旧键上生效）。
3. **日期钉扎任何放松即停**：接受非逐字匹配、通配/区间日期、或以任何方式让 2026-09-28 以外的 date 在旧键下通过/2026-09-30 以外的 date 在新键下通过。
4. **`.pv_tmp` 离线副本被用于真实 transport、真实凭据或离开 `.pv_tmp`——绝对停并升级 Maintainer；任何具付费效力或携带可用请求能力的新工件出现在 PR/分支/CI——绝对停。**
5. 需要修改 budget.py/orchestrate.py/run.py/collect.py/expert_timing.py/offline_flow.py/report.py/fixtures.py/`__init__.py`/`lima/**`/十冻结测试文件/`evaluation_data/**` 任何字节才能交付；或需要冻结基元（run_repeats/run_baseline_attempt/reset_cold_state/_run_shaped_repeats）行为变更。
6. 需要 ledger/manifest/report 新增任何字段、`run_real_baseline_suite` 签名变更、`__all__` 变更、`_REPEAT_COUNT` 数值变更、canary 清单项/时机/latch 语义变更、路由判据偏离"仅 attempt_policy 形状"、或十旧错误码任何顺序/值/消息变化。
7. 需要触碰 Do Not Touch 路径、第 5 个变更文件、Dockerfile 超 1 行、transport 契约偏离 4 参、或 real_run.py 需要任何新 import（预期零新 import）。
8. 方法数超预算（总 >113 或新增 >16）；十冻结文件回归/全量 discover 出现非预期失败；skipped 集出现未登记变化。
9. 六条件演进程序任一不满足；出现"弱化既有断言才能通过"的 hunk；或 R4.2 唯一授权同步集之外的旧方法断言需要修改（闭集只增不减原则违例）；弱化判定争议→DR。
10. 授权文本与实现需求冲突（含本 Assignment 裁定与裁定 §2/§3 原文语义矛盾、裁定间互斥、或 R5 数值表与主会话已发布材料冲突）——不得自行改写授权或裁定。
11. 需要新第三方依赖，或非注入式外部输入/真实 sleep 驱动的测试。
12. 实现中发现证据/代码间新矛盾影响验收语义（如停止门与身份 latch 交互产生双结算、或新键 fixture 物化路径与预期不符）——记录并提交，不得静默。
13. 需要消耗 Maintainer 决策的任何事项（预算 ≤1，预期 0；R11 决策降噪条款先行）。
14. 离线副本执行中出现 R7 三条件任一可能成立的迹象（凭据可用/真实出口/审批链生效）。
15. 需要吞噬/转换/延迟重抛 BaseException（IP-0035 R4.3 延续）或丢弃/改写已发生失败证据。
16. 跨日或其他需要改动 R5 定稿数值（date/retrieval/run_name/七维）的情况——数值钉扎归 Maintainer 受审修订，本叶不得自行改值。

## 13. Done Commands（worktree `D:/BaseAIProject/LIMA-ip-0039-wt` 根执行；Windows 设 `PYTHONUTF8=1`；成功判据=全绿/为空/恰 1 Add+3 Modify/blob 不变/ancestry exit 0）

```bash
# 0. 预冻结基线（C2 之前登记；本轮已执行并归档 .pv_tmp/RED_IP-0039_2026-09-30/baseline.txt）：
#    test_real_run 97/97 OK（42.999s）；十冻结测试文件 322/322 OK（42.297s）；
#    全量 discover 实际值登记（预期 2713/24；skipped 集与 IP-0038 后基线一致）
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_real_run -v
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline tests.test_v4_baseline_budget tests.test_v4_baseline_cli tests.test_v4_baseline_collection tests.test_v4_baseline_fixtures tests.test_v4_baseline_manifest tests.test_v4_baseline_offline_flow tests.test_v4_baseline_report tests.test_v4_baseline_result tests.test_v4_baseline_v5_negatives
PYTHONUTF8=1 python -m unittest discover -s tests
# 0b. RED 证据（C2 冻结前，对未修改 real_run.py @352646bf）：独立日志归档
#     （.pv_tmp/RED_IP-0039_2026-09-30/）+ 逐方法归因表（R6；"RED 失败/按设计通过"）
# 1. 定向文件（C2 冻结时按设计 RED——14 新方法+4 旧锚方法归因授权同步；C-final 后全绿；总方法 112）
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_real_run -v
# 2. 十冻结文件回归（322 必须全绿；命令同 Done Command 0 第二行）
# 3. 全量 discover 回归（绿；skipped 集与基线一致；CI 零付费断言延续）
PYTHONUTF8=1 python -m unittest discover -s tests
# 4. 字节编译；ruff（--no-cache；bandit 选做，如实登记）
PYTHONUTF8=1 python -m compileall -q benchmarks tests
PYTHONUTF8=1 python -m ruff check --no-cache benchmarks/v4/baseline/real_run.py tests/test_v4_baseline_real_run.py
# 5. 离线副本全链实际执行（C-final，P&V）：.pv_tmp 工件（R5 数值逐值+合成 key+
#    offline-rehearsal-no-paid-effect 标注）经正式 run_real_baseline_suite(
#    artifact_key="real-pilot/large-repo")+fake transport，空输出目录→报告；
#    输出与日志归档 .pv_tmp/OFFLINE_TWIN_IP-0039_2026-09-30/；
#    断言面=N3 同款核对表，登记于 Verification Report；全程零真实网络
# 6. diff 守护：恰 1 Add（Packet）+ 3 Modify（Dockerfile/real_run/test_real_run）；
#    Dockerfile diff 恰 +1 行；.pv_tmp/** 与输出目录不在 diff
git diff --name-status 352646bf25313ed3d1ef11e43fa1e57fffbca89f...HEAD
git diff 352646bf25313ed3d1ef11e43fa1e57fffbca89f...HEAD -- Dockerfile   # 恰 +1 行
# 7. blob 守护：budget(6c783848)/orchestrate(8655067e)/run(d29928e5)/collect(063ecb41)/
#    expert_timing(dd7aa365)/offline_flow(0f2916c8)/__init__(1c478346)/report(e30a5f17)/
#    fixtures(700ec4fc) + 十冻结测试文件(4cde7bdf/edd4c62b/edb2391b/35e6ec6a/ca019d50/
#    8e8ab0dc/539d2fb3/86f584cb/0a44cf7d/b4a3a076) + IP-0038 Packet(6b7f89f3)/
#    V5 表(587ef5e1)/批准工件(2e2473cd,3702c04a) + evaluation_data/v4/
#    baseline_manifest.json(7ecb39f8) + lima/** 与基线一致；
#    real_run(d363e457)/test_real_run(50f78bd6)/Dockerfile(2ce873d3)
#    登记为"演进文件"（从 blob 记录在案，至 blob 由 C2/C3 登记）
git ls-tree 352646bf25313ed3d1ef11e43fa1e57fffbca89f -- <守护清单> 与 HEAD 对比
# 8. ancestry：352646bf → C1 → C2(冻结，信息逐字 [IP-0039][PV] Freeze acceptance
#    tests v9 (RED)) → C3 → (C-final) 各段 merge-base --is-ancestor exit 0
```

PC1-PC3 标配（IP-0033..0038 同款）：PC1 新增测试源 secret-token/网络-token 拼接扫描（fake transport 零真实主机；文件级自扫由既有 hygiene 方法延续）；PC2 arrange 经冻结校验器（新键工件文档经 `write_artifact` 深拷贝冻结工件后仅变异新键钉扎面/attempt_policy/budget 维——与 `_load_and_validate_approval` 同源构造）；PC3 派生数值断言（新键溯源五字段/commit sha 一律按冻结公式复算；POST 计数/manifest 值/insufficient_sample 复算或关系断言，不硬抄实现值）。

## 14. PR 与 Completion Summary 契约（CA §Handoff）

- PR：单 PR `codex/ip-0039-real-pilot-desc` → main；标题禁 close 族关键词与编号组合（含否定句，如 "does not close #247/#57" 亦禁用编号组合形）；正文含 Final SHA（完整 40 位）、变更文件清单（对照恰 1 Add+3 Modify）、Done Commands 实际输出摘要（0/0b+1-8，含 5 的离线副本归档路径与核对表）、满足/不满足/未验证逐条、RED 归档路径与 blob 演进记录（real_run d363e457→、test_real_run 50f78bd6→、Dockerfile 2ce873d3→）、下一责任人（P&V[C-final 独立验证+离线副本执行] → ER → Coordinator 合并判定（无预授权停 READY-FOR-MERGE） → 主会话授权合并 → post-merge → 叶审计）、"This PR does not auto-close the Source Issue."、"Related to #247."（仅此关联形式；不得关联关闭 #57/#241）；提交前缀 `[IP-0039][PV]`/`[IP-0039][IMPL]`/`[IP-0039][CI]`；C-final 后修复提交必须引用 Stop/DR/ALLOWED_ONCE 编号；实现提交（C3）以 C2 冻结提交为祖先（Done Command 8）。合并/推送/评论由主会话按 Maintainer 授权执行，P&V/IMPL 零远端写；本 Assignment 不授予任何合并/关闭判定。#247/#57 状态不受本叶合并直接影响（PARTIAL）；真实执行与真实工件=主会话在裁定 §5 门后独立登记，本叶合并不构成其完成证据。
- Completion Summary 必含：FR-01..04 逐条证据索引（测试 ID）、AC-1..4 判定、blob 演进记录与 C1/C2/C3 提交 SHA、RED 归档路径与逐方法归因计数（预期 14 新方法 RED/1 新方法按设计通过/4 旧锚方法授权同步 RED）、C0 基线实际值（97/322/discover 实际值）、零真实调用声明、Dockerfile 恰 +1 行证明、离线副本证据摘要（恰 5 POST/manifest 1/4/consumed.download=0/released=250M/零预算拒绝/V5 unavailable）、K1-K6 已知缺口状态、§16 flagged 事项状态（尤其 DR-IP-0039-PV-2 的 Coordinator 确认请求）。

## 15. 范围裁定 R1-R11 转录（CA-IP-0039-v1.0 决定性内容）

- **R1（文件拓扑与提交链）**：**单叶单 PR，恰 1 Add + 3 Modify，测试并入既有文件，不建新测试文件**（依据沿用 CA-IP-0037/0038 R1：arrange 基建 `_FakeTransport` 族/工件构造器在文件内；v3..v8 单文件演进链为既定可审计先例）。提交链：**C1（P&V：A1+M1 同一提交）→ C2（P&V：M2 冻结提交，Frozen Test Commit，信息逐字 `[IP-0039][PV] Freeze acceptance tests v9 (RED)`）→ C3（Implementation：M3，以 C2 为祖先）→ C-final（P&V 独立验证+离线副本全链实际执行；如触发 ALLOWED_ONCE/修复提交须引用编号）**。**被否决的替代方案（不得重试）**：独立新建 `tests/test_v4_real_pilot_descriptor.py`；把真实工件或离线副本提交入库（裁定 §4：不提交批准工件——离线副本仅 `.pv_tmp`）。
- **R2（I1 描述子形态；裁定点 A）**：**裁定=按需字段集（Option 1：loader 对新字段仅在新键下要求），非全族统一可选字段默认值**。依据：旧十键校验输出逐字节不变的最强保证=新字段根本不进入旧描述子字典（`.get` 缺省即旧值），全族统一字段会改写目录构建面与十描述子的表示。冻结契约：1.**新键** `real-pilot/large-repo`（与既有 `archetype/large-repo` 为不同键）；目录 `REAL_RUN_ARTIFACT_FAMILY` 十键→**十一键**（closed catalog）。2.**新字段闭集（恰 4 个）**：`fixture_key`、`date_pin`、`retrieval_date_pin`、`stop_on_first_failure`；新描述子=既有七字段+此四字段（共 11 字段）；**旧十描述子保持恰七字段、七值逐字节不变**。3.**新描述子字段值**：五个 fixture 溯源字段逐字复用 `_synthetic_artifact_descriptor("archetype/large-repo", fingerprint)` 派生值（同一 registry 指纹、同一派生规则、零新派生机制——fixture 即该合成 fixture，溯源诚实）；差异仅 `approval_type="PR3D-REAL-PILOT-ONE-SHOT"`、`run_name="pr3d-real-pilot-2026-09-30"`、`fixture_key="archetype/large-repo"`、`date_pin="2026-09-30"`、`retrieval_date_pin="2026-09-30"`、`stop_on_first_failure=True`；建议模块常量形 `_REAL_PILOT_ARTIFACT_KEY`/`_REAL_PILOT_APPROVAL_TYPE_PIN`/`_REAL_PILOT_RUN_NAME_PIN`/`_REAL_PILOT_DATE_PIN`/`_REAL_PILOT_RETRIEVAL_DATE_PIN`（不进 `__all__`）。4.**loader 三处 descriptor 驱动化（旧键输出零变化）**：`$.date`→`descriptor.get("date_pin", "2026-09-28")`；`$.pricing.retrieval_date`→`descriptor.get("retrieval_date_pin", _PRICING_RETRIEVAL_DATE_PIN)`；`fixture_key` 分派→`descriptor["fixture_key"] if "fixture_key" in descriptor else (artifact_key if artifact_key in _SYNTHETIC_SET else None)`（旧合成键=自身、旧默认键=None、新键="archetype/large-repo" 本地物化，**绝不外部下载**）；`$.approval_type`/`$.run_name` 已是 descriptor 取值比较，机制零改动；仍为逐字比较（`_require_str_pin`），**不接受任意日期、不放松任何校验**。5.**`_ApprovalContract`** 追加 `stop_on_first_failure: bool = False`（尾字段带默认；loader 传 `descriptor.get("stop_on_first_failure", False)`；旧路径构造结果不变）。**被否决（不得重试）**：①全族统一十/十一字段可选默认值；②新键沿用 `archetype/large-repo` 并靠 approval_type 区分；③查表钉扎；④溯源字段另造新值。
- **R3（I2 停止门判定面与机械边界；裁定点 B）**：**裁定=新描述子标志字段 `stop_on_first_failure`**（判定面=数据而非命名耦合；静态锚可断言字段闭集；未来真实族扩展不被迫共享 approval_type 判定）。冻结契约：1.**位置**：`__call__` 内恰在 canary latch 检查（L1492-1493）之后、index==1 canary 清单与 reserve 之前插入（代码块逐字见 §7.3.1；遍历语义=任一先前 record 带 failure_code，当前 record 在该点 failure_code 恒为 None，等价遍历全部 records 可接受）。2.**触发面（六类失败全覆盖，机械依据=它们最终都在 record.failure_code 留痕）**：transport（`_typed`→EXECUTION_ERROR）、响应契约（同）、usage 缺失（同）、身份（`_typed`→EXECUTION_ERROR+`_settle` 置 canary latch——身份失败后本就 latch，停止门为其超集面）、预算（reserve 处 `BudgetGateError` 置 failure_code="EXECUTION_ERROR" 后透传——既有不 latch 缺口即 F4，本门补齐）、截止（`_timeout_failure` 置 "EXECUTION_TIMEOUT"）。3.**置 latch=门私有粘滞位 `self._batch_stopped`（`__init__` 初始 False）——不是 canary `self._latched`**；**被否决（绝对）：复用 `self._latched`**——会使停止后的后续 attempt 命中 canary latch 检查而误标 `REAL_RUN_CANARY_FAILED`。停止后：后续每次 `__call__` 一律 raise `REAL_RUN_BATCH_STOPPED`、零 reserve、零 POST、零 canary 清单执行；`run_baseline_attempt` 既有"Exception 捕获→分类→持久化→返回"驱动循环继续收尾（零改 run.py）。4.**记账/证据面（零新机制）**：经 `_typed` booking（outcome="failure"/failure_code="EXECUTION_ERROR"/error_code="REAL_RUN_BATCH_STOPPED"/error_field_path="$"）；停止的 attempt 无 reserve 无 usage→无结算调用；attempt 文档与 manifest failures 自动承载——首个真实原因保持原 code（首因保留），后续被阻 attempt 以新码标注；停止门触发不改变任何已发生 attempt 的结算结果。5.**门禁用（旧十键/旧 {5,5}/既有 shaped）=`_stop_on_first_failure` False→该分支永不进入，行为逐字节不变**（AC-2；N8 回归）。**被否决（不得重试）**：①判定面=approval_type 等值比较；②在 `_run_shaped_repeats`/`run.py` 驱动层拦截；③停止后吞噬异常或改写首因 record 的 error_code。
- **R4（I3 十一码演进+canary 清单交互；裁定点 C）**：1.**enum 追加** `REAL_RUN_BATCH_STOPPED`（追加于 `REAL_RUN_CANARY_FAILED` 之后=第 11 成员；既有十成员顺序与值逐字不变）；**消息表定稿**：`"A real-pilot failure was already recorded; the first-failure stop gate blocks every further call in this batch."`（与 canary 消息主语谓词均不同，无数字）。2.**六条件程序**：①enum 追加（尾位）；②`_STABLE_MESSAGES` 新条目；③`_FROZEN_ERROR_CODES` 追加（十→十一；方法体 L3724/L4042/L4299/L4626 均为常量相对断言，零方法体改动自动同步）；④静态锚 `test_frozen_taxonomy_checkpoints_and_canary_static_anchors` 经③同步；⑤静态锚 `test_artifact_family_catalog_frozen_ten_keys` 就地同步（**唯一授权就地改动的旧方法，恰三 hunk**：len 10→11、全键字段集循环改为分支、（如需）键集注释更新；闭集只增不减）；⑥Packet 冻结面演进依据登记（依据=裁定 §3c+#247 Scope 3；六条件逐条落账）。任何其他旧方法的断言需要修改才能通过→Stop 9。3.**canary 清单交互语义（仅用既有值，不新增字段/枚举值）**：首败先于 index==1 时，停止门在清单执行前 raise→`_run_canary_checklist` 从未运行→manifest `canary.status` 保持既有初始值 `"failed"`、`canary.checks` 保持既有初始空 dict `{}`（该面今日已存在——attempt-0 取消路径同形态；五键 checks dict="已评估且失败"，空 dict="从未评估"，机器可区分）；status="failed" 无 checks **不得**解读为"canary 运行且失败"；首个真实原因以原 code 呈现，后续为 BATCH_STOPPED，**无一误标 canary**；attempt-0 成功而清单某项失败时清单照常运行→CANARY_FAILED latch 既有语义在新键下保持（N7）。
- **R5（I4 数值定稿；裁定点 D）**：`date_pin="2026-09-30"`、`retrieval_date_pin="2026-09-30"`（时区 Asia/Shanghai；=第六轮签定/检索证据日）；`run_name="pr3d-real-pilot-2026-09-30"`；仍为逐字比较：新键下 date/retrieval 任一不符→`APPROVAL_ARTIFACT_INVALID`，无任何宽容。**跨日纪律**：未启用真实调用而跨日时，主会话对两 pin 走受审修订（新工件新值，重新离线验收），不得放松校验或以通配/区间替代（Stop 3）。**离线副本与未来真实工件的七维/policy 数值真值源=裁定 §2 表**（与 IP-0038 Packet §7.3/_PREFLIGHT 常量逐值一致）：per_run=100000/1/150000/8000/1200000/250000000/500000000；batch=198000/5/500000/40000/6000000/250000000/500000000；attempt_policy={cold:1,warm:4,max_attempts:5,canary_required:true,canary_first_attempt:0}；真实 POST 硬上限 5。
- **R6（I5 测试面演进 v8→v9；裁定点 E）**：恰**一个新类 `TestRealPilotDescriptorAndStopGate(_RealRunTestCase)`**（置于 `TestPreflightCalibration` 之后、`if __name__` 之前）。**97 旧方法零改动原则+唯一授权同步集**：除 R4.2-⑤ 的一个静态锚方法（恰三 hunk）与两个文件级常量（`_FROZEN_ERROR_CODES`+1 值；`_ARTIFACT_FAMILY_KEYS`+1 键且 `_SYNTHETIC_ARTIFACT_KEYS` 派生过滤改为排除两非合成键）外，**其余 96 方法与全部既有断言逐字节不变**。六条件程序沿用 IP-0033..0038（对象唯一/逐 hunk 归因/禁弱化（闭集只增不减）/版本链保留 v1..v9/RED 先于冻结且逐方法归因/演进只在 C2 由 P&V 执行）。**新增必含清单（N1-N13）**：N1 静态锚-目录（十一键闭集；旧十键恰七字段七值逐字节；新键七+恰四新字段逐字钉扎；新键五溯源字段==large-repo 派生值）；N2 静态锚-错误面（enum 十一值==_FROZEN_ERROR_CODES；_STABLE_MESSAGES 恰覆盖十一码；新消息无数字≠canary；十旧码顺序/消息逐字不变）；N3 离线副本全链正例（恰 5 fake POST/5 件 attempt/ledger.calls=5/manifest 1/4/零预算拒绝/warm 复用 4/cold_reset performed=False+count=1+performed=True 计 0/下载通道零 GET/V5 null+unavailable/insufficient_sample）；N4 日期钉扎双态（新键接受 2026-09-30/2026-09-30；新键拒 2026-09-28；旧键（默认+合成各一）拒 2026-09-30 的 date 与 retrieval_date）；N5 停止门六类失败注入（transport/契约/usage/身份/预算/截止：首败后零新增 POST+首因保留+后续 BATCH_STOPPED+粘滞位不复用 canary）；N6 停止门先于 canary（清单从未运行：status="failed"+checks=={}、后续无 CANARY_FAILED）；N7 新键下 canary latch 保持（attempt-0 成功+清单失败→CANARY_FAILED latch、零后续 POST）；N8 停止门不作用于旧键（shaped 合成键中途失败→后续照常执行、零 BATCH_STOPPED）；N9 负例-未知描述子（`APPROVAL_ARTIFACT_INVALID`/`$`）；N10 负例-错误 run_name（`$.run_name`）/错 approval_type（`$.approval_type`）；N11 负例-预算面（缺一维→`BUDGET_SPEC_INVALID` 透传通道；download_bytes=249,999,999→首轮 reserve 拒付零 POST——可达错误面形态见 §16 DR-IP-0039-PV-3）；N12 负例-非空输出目录（`REAL_RUN_OUTPUT_NOT_EMPTY`）；N13 停止后账本面（被阻 attempt 零 reserve 零记账）。新增合计 **≥12 且 ≤16**（N1-N13 可合并/拆分组织）；总方法数 **≤113**。**RED 锚=N1/N2/N3/N4(新键半)/N5/N6/N7/N10/N11/N12/N13**（未修改 real_run.py @352646bf 时：新键不解析→`$` 拒绝/目录十键/码十枚举/停止门缺席）；**N4(旧键半)/N8/N9=按设计通过**——逐方法"RED 失败/按设计通过"归因表强制（N4 双态方法内按断言组归因）。
- **R7（离线副本与真实工件边界）**：离线副本（无付费效力）C-final 由 P&V 以 `.pv_tmp/OFFLINE_TWIN_IP-0039_2026-09-30/` 内工件执行——与最终真实工件逐值一致（七维=裁定 §2 表、policy {1,4,5}、run_name、fixture 绑定、date/retrieval=2026-09-30、模型钉扎逐字），仅 transport/凭据/审批生效状态隔离；经正式入口+空目录执行到报告；断言面=N3 同款核对表，登记于 Verification Report（"不得复用旧预演作为新描述子通过的证据"——必须新执行）；归档输出与日志，不入库、不进 PR diff。付费效力机械判据（沿 IP-0038 R4，入 Packet 规范性）：三条件同时成立（真实凭据/真实 transport 入口/审批链生效）才具付费效力；离线副本三条件零成立；防御性条件 a-d（§7.5.3）。真实工件不入库（裁定 §4/§7）。
- **R8（Done Commands）**：§13（0/0b+1-8）。
- **R9（Stop Conditions 与 ALLOWED_ONCE）**：§12（0-16）/§11。
- **R10（升级条款）**：Implementation 出现跨冻结模块语义约束、同一根因两轮有新证据修复仍失败、疑似规格矛盾 → 停止并提交 DR；如裁定升级目标档位 `glm-5.3 / max`，实际切换须新建/重新配置会话并取得 SESSION-RUNTIME-VERIFIED（派发文本声明不构成运行切换），文件边界/测试冻结/验收标准不变。
- **R11（决策降噪）**：新常量命名、目录条目构建形（独立 builder vs 内联字典）、`_batch_stopped` 粘滞位与 any() 扫描的冗余取舍、测试类内部组织=实现细节，不升级 Maintainer 决策；仅产品行为存在多个合理答案时才 DR——本 Assignment R3.2 已裁定身份失败为停止门超集面，无需再请示。

## 16. Decision Record（P&V 定稿决策；CA 授权范围内的冻结裁量）

| # | 决策 | 时间 | 依据 |
| --- | --- | --- | --- |
| DR-IP-0039-PV-1 | `stop_on_first_failure` 描述子值=Python `bool True`（冻结）；派发摘要中 `stop_on_first_failure:"true"` 的引号字符串形态为该布尔值的摘要渲染，以 CA R2.3（`stop_on_first_failure=True`）/R2.5（`bool = False` 默认）/R3（标志字段判定）为准。测试静态锚断言 `descriptor["stop_on_first_failure"] is True`（bool 恒等，拒绝字符串 `"true"`） | 2026-09-30 | CA 为唯一裁定权威（派发明示"CA-IP-0039-v1.0——范围权威 R1-R11，严格执行"）；R2.5 类型签名 `bool` |
| DR-IP-0039-PV-2 | **N5-身份类诚实可观测形态（flagged，提交 Coordinator 确认）**：R3.1 钉扎门位置（latch 检查之后）+既有 D4 身份 latch（`_settle` L1749-1755 置 `self._latched=True`，冻结不可改）⟹ 身份失败（index≥1 漂移）后的后续 attempt 在 `__call__` 顶部命中既有 latch 检查→`REAL_RUN_CANARY_FAILED`，**非 BATCH_STOPPED**；K4 括注与 R6-N5 身份行"后续=BATCH_STOPPED，非 CANARY_FAILED"在 R3.1 门位置下机械不可达（P&V 对 352646b 亲读 `_chat`/`_parse_response`/`_settle`/`__call__` 逐帧核验：身份失败必经 `_settle` 置 latch，latch 检查先于门）。冻结诚实面（M7）：首因=REAL_RUN_IDENTITY_CHANGED 保留、首败后零新增 POST（chat_calls 冻结）、后续=REAL_RUN_CANARY_FAILED（既有 D4 latch 语义，与旧键行为一致=AC-2 兼容面）、零 BATCH_STOPPED 误标首因、manifest failures 逐条核对。裁定 §3c 两项硬要求（不再发起真实 POST/保留首个真实原因/不捏造）均满足；R3.2 自身明文"身份失败后本就 latch，停止门为其超集面"与本形态一致。Coordinator 如需 K4 字面形态（后续=BATCH_STOPPED），须裁定门位置改于 latch 检查之前或身份失败不 latch——两者均为 CA 变更，须以 CA 勘误（v1.1+）授权重新冻结 M7 | 2026-09-30 | Stop 10/12（裁定间互斥/证据-代码新矛盾须记录提交，不得自行改写）；R3.1 位置逐字钉扎+R3.2"超集面"表述+不变面"CANARY_FAILED latch 语义"；§16 OBS-1 同 IP-0038 OBS-2 先例（flagged 冻结+Coordinator 保留改采权） |
| DR-IP-0039-PV-3 | **N11 预算负例可达错误面（沿 IP-0038 DR-3 裁定形态）**：①"缺一维"字面=维度键删除→loader 精确键集门 `_require_exact_keys` 先拒：`APPROVAL_ARTIFACT_INVALID @ $.budget.<level>`（零 POST/零 GET）；`BUDGET_SPEC_INVALID` 透传面=batch<per_run 装载期 BudgetSpec 拦截（batch.download=249,999,999 而 per_run=表值→`BUDGET_SPEC_INVALID @ $.budget.batch.download_bytes`）。②"download_bytes=249,999,999→首轮 reserve `BATCH_BUDGET_EXCEEDED`"字面经可加载工件不可达（per_run 门先于 batch 门——budget.py 冻结门序；IP-0038 §16 DR-3 探针亲证同形态）；首轮可达面=两级均 249,999,999→`RUN_BUDGET_EXCEEDED @ $.budget.per_run.download_bytes` 拒付零 POST；**真正可达的 `BATCH_BUDGET_EXCEEDED` 中途面**=batch.calls=2 arrange（M8：attempt-2 reserve 拒付、后续 BATCH_STOPPED——同时承载 F4"预算失败不 latch"缺口的停止门证明）。裁定 §4"以实际可达错误面断言零新增 POST，允许装载期先拒绝，不强求不可达的错误码"明文授权本形态 | 2026-09-30 | 裁定 §4 逐字；IP-0038 Packet §16 DR-IP-0038-PV-3 先例（Coordinator 已接受）；budget.py L213-217/L380-494 冻结门序（禁区不可改） |
| DR-IP-0039-PV-4 | 新增方法数=恰 15（97→112 ≤113 上界）：N5 六类拆 5 方法（transport/契约+usage/身份/预算/截止——契约与 usage 同为响应面非 latch 类合并双 subTest）；N9+N10+N12 合并 1 方法（loader 级负例族）；N13 独立 1 方法（账本面）。新类内 N 映射表见 §9.1 | 2026-09-30 | R6 预算 ≥12 且 ≤16、总 ≤113；IP-0038 DR-PV-7 逐方法单一归因态纪律 |
| DR-IP-0039-PV-5 | 新键工件 arrange 的真值源=测试内按冻结派生公式独立复算（`_synthetic_commit_sha("archetype/large-repo", registry_fingerprint)`+`_synthetic_artifact_descriptor` 模板规则），不读产品目录、不硬抄实现值（PC3 双源）；工件构造经 `write_artifact` 深拷贝冻结 repo 工件后仅变异新键钉扎面/attempt_policy/budget 七维（PC2）。RED 态 arrange 有效性：文档本身合法，失败=loader 对新键的目录缺失 `$` 拒绝（IP-0034 同型能力缺席锚先例） | 2026-09-30 | PC2/PC3 标配；IP-0034 §RED 先例；R2.3"同一派生规则" |
| DR-IP-0039-PV-6 | Dockerfile 插入锚=L69（IP-0038 Packet COPY 行）后（CA M1 精确锚；派发文本同锚"插 IP-0038 Packet 行后"，无字面差异——不适用 IP-0038 DR-4 型登记） | 2026-09-30 | CA M1；本 P&V 会话亲读 Dockerfile L69 |

**观察项（不移交实现、不构成验收面）**：

- **OBS-1**：DR-IP-0039-PV-2 为 flagged 字面差异（不改 R3.1/R3.2 裁定语义，仅登记 K4/N5-身份括注在钉扎门位置下的不可达字面的诚实可观测形态）；Coordinator 如需改采其他形态（门先于 latch 检查/身份失败不 latch），须以 CA 勘误（v1.1+）授权重新冻结 M7——本 Packet 冻结面在此之前保持本节形态。
- **OBS-2**：C-final 离线副本（R7）由 P&V 以 `.pv_tmp/OFFLINE_TWIN_IP-0039_2026-09-30/` 工件执行；其核对表与 N3 断言面一致性由 Verification Report 承载；本 Packet 不为离线副本另设验收方法。
- **OBS-3**：C0 全量 discover 实际值=**2713 OK / skipped=24**，与派发预期逐字一致，无 Stop 8 差异（skipped 集=IP-0038 后基线不变）；首轮管道式捕获因 stdout 缓冲丢失摘要行，已以独立 stderr 捕获重跑复核（`discover_stderr.txt`）。

## 17. 已知缺口（不阻塞本 Packet；CA K1-K6 同构登记）

- **K1** 零真实批次：本叶全部证明为 fake transport 离线双证；真实 pilot（≤5 POST）由主会话在裁定 §5 门禁后另行启用（第六轮边界：本叶停在真实 pilot 门前）。
- **K2** 真实工件未签发：离线副本仅为无付费效力孪生（R7）；真实工件的签发/封存/执行登记=主会话职责，不在本叶 PR 面。
- **K3** 日期钉扎时效：date_pin/retrieval_date_pin=2026-09-30；若真实启用跨日，需主会话受审修订（R5）；本叶不放松任何校验。
- **K4** 停止门覆盖面=record.failure_code 留痕的六类失败（R3.2）；canary latch 与停止门为叠加面——**身份失败在 R3.1 门位置下的诚实后续形态=既有 D4 latch 的 CANARY_FAILED（DR-IP-0039-PV-2 flagged；K4 括注字面不可达）**。
- **K5** canary "未评估"形态=既有 status "failed"+空 checks（R4.3）；若未来需要显式 not_run 枚举须新 DR（不新增字段原则）。
- **K6** `_SYNTHETIC_ARTIFACT_KEYS` 测试侧派生过滤需排除两非合成键（R6）；模块侧常量保持九键不变。

（Packet 完；版本 v1.0。Contract 语义变更须同步 Packet 版本与 AC。）
