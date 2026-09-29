# LIMA Implementation Packet — IP-0038 开工前校准（#241 DR-PV-8/DR-0037-01 落地+预算选项 b 校准+强制开工预演，零真实调用）

- Packet ID：IP-0038；版本 v1.0（2026-09-29）。
- Coordinator Assignment：CA-IP-0038-v1.0（2026-09-29；Intent Record `.pv_tmp/INTENT_RECORD_IP-0038_2026-09-29.md` 的 M1-M6/F1-F9/S1-S3 与待裁点 Q1-Q4 由其 R1-R10 裁定；R1-R10 转录见 §15）。
- Source Issue：#241（open；parent #57 保持 open，PR3 不勾选；正文 Scope 1-6 / Non-goals / AC-1..5 由 Coordinator 经 GitHub API 只读 GET 亲取，范围以 CA-IP-0038-v1.0 §Authoritative Inputs #2 为权威转录，API dump 存 `.pv_tmp/issue241_api.json`——本 P&V 会话离线读取该 dump，零网络）。
- Operating Mode：SHADOW；Execution Authorization：MAINTAINER_AUTHORIZED（2026-09-29 第五轮"真实 pilot 开工前校准"授权：**模型 API 调用预算=0**；不注入真实 API 凭据、不签发具付费效力批准工件、不发送模型请求；GitHub 只读 GET 与本地离线测试可继续；零真实调用/零付费/零远端写；全程停在真实 5 次 pilot 门之前；CI 永远零真实调用）。
- Base SHA（完整 40 位）：`ae613ce3d514edded68688d1a0141f665a666570`（= origin/main = 本地 main = worktree 分支起点，本 P&V 会话亲验）。
- 基线产物指纹（`git ls-tree ae613ce3...` 本 P&V 会话程序化复核，与 CA §Authoritative Inputs #12 逐字一致）：real_run.py blob `1febb80e342142e4bf633ec3e3cc81f7e0668fb9`；test_real_run.py blob `8246b1c513163c164d49026eec416b48a3286679`；Dockerfile blob `22fcd3990653d361a028205b1f738434beb28d3d`；守护 blob——budget `6c783848`、orchestrate `8655067e`、run `d29928e5`、collect `063ecb41`、expert_timing `dd7aa365`、offline_flow `0f2916c8`、`__init__` `1c478346`、report `e30a5f17`、fixtures `700ec4fc`；IP-0037 Packet `568c2c0c`、V5 表 `587ef5e1`、批准工件 `2e2473cd`/`3702c04a`；`baseline_manifest.json` `7ecb39f8`、`python_mvp_support_matrix.json` `3ea94fcf`。
- 冻结前基线绿（本 P&V 会话 C0 亲跑，2026-09-29，归档 `.pv_tmp/RED_IP-0038_2026-09-29/baseline*.txt`）：test_real_run **90/90 OK（29.911s）**；十冻结测试文件 **322/322 OK（40.821s）**；全量 discover **2706 OK / skipped=24（264.160s）**（IP-0037 v7 冻结时为 2692/24；+14=v7' 批次协议方法，skip 集不变）。
- 本 Packet 的角色：Implementation（阶段 C3）的唯一实现依据；冻结验收测试面（§9/§10，tests/test_v4_baseline_real_run.py v7'→v8）的唯一语义来源；ER 复核与 P&V 独立验证（C-final，含 R4 预演实际执行）的基准。

## 0. 交付物角色声明（强制，先于一切）

1. 本 Packet（本文件）与 Dockerfile 恰 +1 行 COPY 是 P&V 的 C1 交付物；tests/test_v4_baseline_real_run.py v7'→v8 演进（90→97 方法）是 P&V 的 C2 交付物（Frozen Test Commit）；`benchmarks/v4/baseline/real_run.py`（R2 全部实现面）是 **Implementation 的 C3 交付物**。边界不得互换：Implementation 不得修改本 Packet/测试；P&V 不实现产品功能。
2. **零真实调用绝对禁令（本 Assignment 范围内）**：本叶全程（含分支上、CI 内、pre-merge"顺手验证"）禁止任何真实模型调用、网络下载、付费动作、真实凭据注入、任何具付费效力批准工件。全部校准/预演验收以离线注入（fake transport/确定性 clock patch/测试构造工件文档）证明；CI 永远零付费模型请求。
3. **真实 pilot 执行不在本叶**：本叶只交付"pilot 开工前校准+开工预演离线双证"；真实 5 次 pilot 另行授权与工件（第五轮边界：停在真实 pilot 门前；K2）。
4. **冻结面零回退**：IP-0024..0037 一切冻结面零回退（§7 各"不变面"节与 CA §Frozen Interfaces）；`budget.py`/`orchestrate.py`/`run.py`/`collect.py`/`expert_timing.py`/`offline_flow.py`/`report.py`/`fixtures.py`/各级 `__init__.py` 零字节；首轮 estimate 常量与 `_estimate_for(0)` 接线零改动（R5 永固）；calls/cost/canary 门零放松。
5. **主会话职责（非本 PR 面；P&V/Implementation 不得代行）**：决策包 v6 发布（仅单类 5 次 pilot，数值逐值引用本 Packet §7.3 数值表）；`POST_MERGE_VERIFICATION_IP-0037` 重建落盘（标注"重建于 2026-09-29，原文件从未落盘，#239 Closure 的引用失效"）；#239 勘误评论；#241 Delivery Ledger 持久化；合并/推送/评论等一切远端写。

## 1. 需求映射（Packet 头）

```text
Source Issue：#241（open；Scope 1-6 / Non-goals / AC-1..5，经 CA-IP-0038-v1.0 转录；API dump .pv_tmp/issue241_api.json）
Issue specification revision：2026-09-29T05:12:04Z 创建版正文（未再编辑；Packet ID 占用检查 2026-09-29 由 Coordinator 完成：git grep IP-0038 零命中）
Covered requirements：FR-01、FR-02、FR-03、FR-04、FR-05、FR-06、AC-1、AC-2、AC-3、AC-4、AC-5（PR 面内部分）
Not covered requirements：任何真实模型调用/网络下载/付费动作/真实凭据注入；任何具付费效力批准工件；真实 pilot 执行；#57 关闭或 PR3 勾选；#241 关闭（叶合并≠Issue 完成）；#239 重开或其勘误评论（主会话职责）；决策包 v6 撰写与发布（主会话；本 Packet 数值表是真值源）；budget.py/orchestrate.py/run.py/collect.py/expert_timing.py/offline_flow.py/report.py/fixtures.py/各级 __init__.py 修改；十个冻结测试文件；real_run.py 既有冻结面（见 §7 不变面）；ledger/manifest/report 新增字段；evaluation_data/**；lima/**；scripts/**；前端；历史 Packet/批准工件/V5 表/决策包文本修改
Delivery role：calibration + governance（#241 pilot 开工前校准切片：两 DR 落地/预算选项 b 数值钉扎/预演双证/诚实披露，全部离线）
Issue closure impact：PARTIAL（IP-0038 完成 ≠ #241 完成 ≠ #57 完成 ≠ 真实 pilot 完成；AC-5 的记录重建落盘与 #239 勘误=主会话 PR 外动作，不因本叶合并自动满足）
Upstream IP/PR/merge commits：CONSUMES IP-0037（main 链 PR #240 merge=ae613ce3；形状路由 L2696-2708/评估器携带态 L1348-1358/cold_reset 观测键/负例基座/v7' 90 方法回归面为本叶消费面）；先例 IP-0033..0037（冻结测试面六条件演进程序）
```

FR-01..FR-06 为 #241 "Scope (this slice)" 1-6 的规范化编号（语义不变，CA §Goal and Scope）。

| 需求 | 内容（规范化语义） | 本 Packet 承载 | 验收面 |
| --- | --- | --- | --- |
| FR-01 | DR-IP-0037-PV-8 落地：manifest cold_count/warm_count=批准的计划形状（attempt_policy 派生：pilot 1/4、正式 3/5、旧 5/5 兼容逐字节）；逐 attempt 实际成功/失败与 cold_reset 证据分离在场；序号标签≠已成功重置 | §7.1（R2）/§5.6 | N1（M1/M2）、N2（M3）、N6（M6）（AC-1） |
| FR-02 | DR-IP-0037-01 落地（规范性登记，零产品语义变更）：pilot 沿用有界 12 候选 triage+二元 verdict；无真实来源 V5 字段保持 null+unavailable；pilot≠九类验收；人工≠机器实测 | §7.2 | N2 报告断言组（M3）（AC-3 之 V5 面） |
| FR-03 | 预算校准（选项 b）：pilot 工件 batch.download=250,000,000/storage=500,000,000（许可上限恰覆盖单次首轮保守预留）；首轮预留不改 0；calls/cost/canary 门零放松；七维数值表唯一真值源=本 Packet | §7.3（R5） | N4 静态钉扎（M5）、N7 双源一致（M7）、N2 全链（M3）（AC-2） |
| FR-04 | 强制开工预演双证：冻结测试内联精确工件全断言 + 实际离线执行（空目录→报告、正式入口、fake transport）；另测 canary 失败零后续/资源超限零 POST/旧 5/5 回归 | §7.5（R4）/§8/§9 | N2（M3）、N3（M4）、既有 v7' L4537（④）（AC-3） |
| FR-05 | 区分面：许可上限 vs 实际合成下载=0——既有 released 桶如实记账（consumed.download=0/released=250,000,000）+文档面承载；零新字段 | §7.4（R3） | N2 断言组（M3）（AC-2） |
| FR-06 | 诚实记录：Packet 如实登记 IP-0037 post-merge 记录缺失缺口（K1 披露）；重建落盘与 #239 勘误=主会话职责（PR 外） | §0.5/§17 | 本 Packet 文本（AC-5 PR 面内部分） |
| AC-1 | manifest 计划形状三态逐值正确（pilot 1/4、正式 3/5、旧 5/5 逐字节）；attempt 级实际证据分离在场 | §7.1/§9 | M1（RED 锚）/M2/M3 |
| AC-2 | 精确工件过首轮 reserve（零预算拒绝恰 5 POST；consumed.download=0/released=250M；ledger.calls=5）；超限工件首轮零 POST 拒付；estimate 常量零改动 | §7.3/§8/§9 | M3/M4/M5/M7 |
| AC-3 | 预演双证：冻结测试全断言面 + 实际离线执行（空目录→报告）日志归档 `.pv_tmp/REHEARSAL_IP-0038_2026-09-29/`；CI 零真实调用 | §7.5/§13-5 | M3 + C-final 预演（P&V） |
| AC-4 | 旧 5/5 回归零变化；既有 90 测试零改动通过（v7'→v8 演进零弱化） | §10 | M2 + 既有 90 方法零改动全绿 |
| AC-5 | 记录重建诚实（PR 面内=本 Packet 披露登记；落盘与勘误=主会话 PR 外动作，完成判定待主会话动作后在 Ledger 记录） | §0.5/§17 | 本 Packet §17-K1 |

**Not-covered（全团队不得扩张；= CA §Not covered 1-7 全文）**：任何真实模型调用、网络下载、付费动作、真实凭据注入（含分支上/CI 内/pre-merge"顺手验证"）；任何具付费效力批准工件；真实 pilot 执行。#57 关闭或 PR3 勾选；#241 关闭（叶合并≠Issue 完成）；#239 重开或其勘误评论（主会话职责）。`budget.py`/`orchestrate.py`/`run.py`/`collect.py`/`expert_timing.py`/`offline_flow.py`/`report.py`/`fixtures.py`/各级 `__init__.py` 任何字节；十个冻结测试文件（test_v4_baseline/budget/cli/collection/fixtures/manifest/offline_flow/report/result/v5_negatives）。`RealRunErrorCode` 十成员与 `_STABLE_MESSAGES`；11 检查点与 `_CHECKPOINT_FIELD_PATHS`；SF-01；身份三形态；请求形状（thinking disabled/max_tokens=8000/≤100000 字节）；`CANDIDATE_FILE_CAP=12` 等全部 cap 常量；`_REPEAT_COUNT=5` 与 {5,5} 路径全部行为（逐字节，AC-4）；canary 清单五项/index==1 时机/latch；D1-D8 结算表；`_estimate_for` 估计策略与 `_WALL_ESTIMATE_MS`/`_DOWNLOAD_ESTIMATE_BYTES`/`_STORAGE_ESTIMATE_BYTES` 常量数值（R5 永固）；七维预算门语义（只紧不松）；transport 注入契约 4 参；证据五件套文件名与写出纪律；`state_reuse`/`provider_cache`/`timings` 子块键集；`cold_reset` 四键闭集；`reset_cold_state` 签名与五键返回文档；`_run_shaped_repeats` 签名；`run_real_baseline_suite` 签名与路由判据（形状唯一判据）；`__all__` 六符号。ledger/manifest/report 任何新增字段。决策包 v6 撰写与发布。历史 Packet（IP-0036/0037）、两份批准工件、V5 来源表、Decision Pack v3/v4/v4-ERRATUM/v5 文本修改；不提交任何输出目录/密钥/run 产物/`.pv_tmp/**`。

## 2. Design Input Manifest

| # | 输入 | 版本/位置 | 消费方式 |
| --- | --- | --- | --- |
| 1 | CA-IP-0038-v1.0 | `.pv_tmp/COORDINATOR_ASSIGNMENT_IP-0038_2026-09-29.md` | 范围权威；R1-R10 全文转录见 §15；本 Packet 逐条承载 |
| 2 | Intent Record IR-IP-0038-2026-09-29 | `.pv_tmp/INTENT_RECORD_IP-0038_2026-09-29.md` | M1-M6 授权语义（第五轮：预算=0/停在 pilot 门前/两 DR 逐字/选项 b/预演/诚实重建）；F1-F9 决定性事实；Q1-Q4 全部由 CA R2-R6 裁定 |
| 3 | Maintainer 第五轮授权 | Intent Record 头部（授权原文逐字保全于 Agent 原文/派发记录）+ #241 正文 | §0/§7/§12/§14 的授权依据；§7.3 数值表依据；§7.5 预演依据 |
| 4 | Source Issue #241 正文 | `.pv_tmp/issue241_api.json`（Coordinator GitHub API 只读 GET 亲取；本 P&V 离线读取 dump 复核） | Scope 1-6/Non-goals/AC-1..5（经 CA 规范化为 FR-01..06）；两 DR 逐字裁定源文本 |
| 5 | IP-0037 Packet | `docs/LIMA_Implementation_Packet_IP-0037_Batch_Protocol.md` @ae613ce3（blob `568c2c0c`） | 结构先例（§5.6 演进登记/§10 六条件/§13 Done Commands/§15 R 转录/§16 DR 体例）；§16 **DR-IP-0037-PV-8 与观察项 OBS-1=本叶 §5.6 显式覆盖/落地登记对象**；R2 路由/R4 cold_reset 值形状/R6 形状驱动器语义为本叶直接消费面 |
| 6 | real_run.py @ae613ce3 | blob `1febb80e`（本 P&V 会话亲读关键面：L191-192 `_DOWNLOAD_ESTIMATE_BYTES=250_000_000`/`_STORAGE_ESTIMATE_BYTES=500_000_000`；L1348-1358 `_batch_shape` 携带与 `_cold_count` None→`_REPEAT_COUNT` 解析；L1397-1418 既有六个只读 `@property` 面（canary_status/canary_checks/baseline_model/baseline_fingerprint/tarball_sha256/coverage_gap）；L1568-1585 `_estimate_for(0)` 首轮接线（prompt=REQUEST_BODY_BYTE_CAP/completion=MAX_TOKENS/download/storage 四维取常量、wall 取 per_run.wall_ms）；L2386-2455 `_build_manifest_document` 已消费 guarded property 面，**L2439-2440 `"cold_count": _REPEAT_COUNT, "warm_count": _REPEAT_COUNT` 写死=R2 演进对象**；L2696-2708 路由自已校验文档一次性读取 attempt_policy 派生 batch_shape（绝不二次解析纪律的先例）；L2719-2738 双路径调用；L2761-2762 `build_baseline_report`+`write_report_file` 报告面；取消路径不吞噬 BaseException） | §7.1 演进对象与 R2 契约的逐行依据 |
| 7 | budget.py @ae613ce3（禁区） | blob `6c783848`；`BUDGET_DIMENSIONS` 七维序（cost/calls/prompt/completion/wall/download/storage）；`BudgetSpec.__post_init__` L213-217（batch<dim<per_run<dim → `BUDGET_SPEC_INVALID`）；`reserve` 门序 L380-494（per_run 门先于 batch 门、逐维顺序、at-cap 含容语义、worst-case cost 公式） | §7.3 约束验证与 §8 N3 双面的冻结代码依据 |
| 8 | report.py @ae613ce3（禁区） | blob `e30a5f17`；L125 `_PROJECTIONS={"measured","legacy_projection","unavailable"}`、L171-176 `_DOMAIN_BLOCK_FIELDS` 六键闭集、L1359-1433 无 domain 块的 null+unavailable 投影、L1435-1487 报告文档构造 | §7.2 DR-0037-01 可验证断言面的代码锚 |
| 9 | 钉扎工件族数值 | `docs/LIMA_PR3d_Real_Run_Approval_2026-09-28.md`（blob `3702c04a`）per_run 七维=100000/1/150000/8000/1200000/250000000/500000000 | §7.3 per_run 面不变依据（与 2026-09-27 族一致） |
| 10 | tests/test_v4_baseline_real_run.py @ae613ce3 | blob `8246b1c5`（v7'；**90 方法/30 类，本 P&V 会话 C0 亲跑 90/90 OK（29.911s）**；文件头 v1..v7 演进链注记；`_FakeTransport` 族/`_shaped_policy`/`write_synthetic_artifact`/`patch_monotonic`/`_JumpClock` arrange 基建与 `_RealRunTestCase` helpers 全在文件内——R1 单文件演进依据；`TestBatchShapeProtocol`（L4120）=末类=新类插入位；`test_shaped_canary_failure_latches_zero_follow_on_posts`（L4537）=④复用面） | §9/§10 演进基础 |
| 11 | Dockerfile @ae613ce3 | blob `22fcd399`（docs COPY 块亲读：IP-0037 两行簇末行=`docs/LIMA_PR3e_V5_Field_Source_Table.md`（L68）=本叶恰 +1 行插入位，CA M1 精确锚） | C1 +1 行落位依据 |
| 12 | 守护 blob（`git ls-tree ae613ce3` 本 P&V 会话程序化复核） | 与 CA §Authoritative Inputs #12 逐字一致（见 Packet 头基线指纹节） | Done Command 7 blob 守护清单 |
| 13 | worktree/分支 | 主会话已建 `D:/BaseAIProject/LIMA-ip-0038-wt`（分支 `codex/ip-0038-preflight` @ae613ce3；`git status` 干净亲验） | §5 提交链拓扑的落位 |
| 14 | Pre-Freeze 探针（本 P&V 会话） | `.pv_tmp/RED_IP-0038_2026-09-29/probe_n1_old_manifest.py`（对未修改产品亲跑；输出存同目录） | §9 N1-old 内联期望文档与 N3 双面形态的实证依据（§16 DR-2/DR-3） |

哈希真值来源：`git ls-tree ae613ce3d514edded68688d1a0141f665a666570 -- <paths>`（本 P&V 会话程序化复核，与 CA 一致）。

## 3. Explicitly Rejected Inputs

| # | 被拒输入 | 拒绝理由 |
| --- | --- | --- |
| 1 | manifest 构造器内再读 `approval.document["attempt_policy"]`（二次解析） | R2 被否决替代方案①：路由已在 L2696-2708 对同一已校验文档一次性读取；manifest 只消费评估器携带态（property 面），不得重读文档 |
| 2 | 向 `_build_manifest_document` 暴露原始 `_batch_shape` tuple | R2 被否决替代方案②：把 None-分支引入 manifest 面+跨私有属性访问破坏 property 面先例（L1397-1418） |
| 3 | manifest 新增 `actual_*` 计数字段或任何 ledger/report 区分键 | R2 被否决③+R3：键集闭破坏；consumed/released 两桶已完整承载区分（F5），无信息增益 |
| 4 | 首轮预留改 0 或调低 `_DOWNLOAD_ESTIMATE_BYTES`/`_STORAGE_ESTIMATE_BYTES`/`_WALL_ESTIMATE_MS`/`_estimate_for(0)` 接线 | R5 永固+Stop 2：不把首轮预留改成 0 是授权明文；任何改动即绝对停 |
| 5 | 以工件数值/新校验路径/绕门方式放松 calls/cost/canary 门 | 授权明文"calls/cost/canary 门零放松"+Stop 3 |
| 6 | 以 CI 内联测试替代实际离线执行、演练工件提交入库、或以非正式入口/脚本旁路驱动演练 | R4 被否决①②③：#241 Scope 4 明文双证；diff 守护拒绝；必须经 `run_real_baseline_suite` |
| 7 | 独立新建 `tests/test_v4_preflight_calibration.py` | R1 被否决替代方案（沿用 CA-IP-0037 R1 依据：arrange 基建在既有文件内；v7' 单文件演进链是既定可审计先例） |
| 8 | 第 5 个变更文件、Dockerfile 超 1 行、触碰 `lima/**`/`scripts/**`/`evaluation_data/**`/十冻结测试文件/其余 baseline 模块 | R1 + Stop 5/7：Allowed Files 终形=恰 1 Add+3 Modify |
| 9 | `run_real_baseline_suite` 签名变更、`__all__` 变更、`_REPEAT_COUNT` 数值变更、{5,5} 路径任何行为变化、路由判据偏离"仅 attempt_policy 形状"、新增错误码或新 field_path | CA Not-covered 4 + Stop 6 |
| 10 | 对 {1,4} attempt-0 断言/实现 `cold_reset.performed=True` 以凑足"performed=True 恰 1"字面 | §16 DR-IP-0038-PV-2：违反 DR-PV-8 自身（序号标签≠已成功重置）与 IP-0037 冻结值形状（index 0=false）、击穿 v7' 冻结方法；诚实面=恰 1 件 cold_reset 观测（attempt-0，performed=False，materialization_count=1），performed=True 计数=0 |
| 11 | 对"batch.download=249,999,999 工件"断言首轮 `BATCH_BUDGET_EXCEEDED @ $.budget.batch.download_bytes` 字面形态 | §16 DR-IP-0038-PV-3：该面经可加载工件不可达（BudgetSpec batch≥per_run 在装载期拦截；per_run 门先于 batch 门）——冻结的是两个真实 fail-closed 面（§8-3） |
| 12 | 吞噬/转换/延迟重抛 BaseException、丢弃证据、以 synthetic 冒充真实扫描计数、domain 缺席写常数 | IP-0035 R4.3/#239 Scope 6/IP-0037 §0.4 诚实纪律延续 + Stop 16 |
| 13 | `.pv_tmp` 演练件用于真实 transport/真实凭据/离开 `.pv_tmp` | R4 防御条件 a + Stop 4：绝对停并升级 Maintainer |
| 14 | 决策包 v6 另立数值或与本 Packet §7.3 表冲突 | R5：七维数值表唯一真值源=本 Packet；冲突=Stop 10（不得双真值源） |

## 4. Goal / Non-goals

**Goal**：在 IP-0037 版产品（main=ae613ce3）上完成 pilot 真实开工前的全部校准并以受审查单 PR 入库：①DR-IP-0037-PV-8 落地——`_GuardedRealEvaluator` 新增两个类内只读 property（`planned_cold_count`/`planned_warm_count`，不进 `__all__`），`_build_manifest_document` 的 cold_count/warm_count 由写死 `_REPEAT_COUNT` 改为携带态派生（pilot 1/4、正式 3/5、旧 {5,5} 兼容逐字节不变）；②DR-IP-0037-01 规范性登记（零产品语义变更）+预演断言面（V5 无来源字段 unavailable）；③预算选项 b 校准——pilot 工件 batch.download=250,000,000/storage=500,000,000（恰覆盖单次首轮保守预留；区别于实际合成下载=0 的如实记账），首轮预留不改 0，calls/cost/canary 零放松，七维数值表唯一真值源=本 Packet §7.3；④强制开工预演双证——冻结测试内联精确工件全断言面 + P&V 实际离线执行（空目录→报告、正式入口、fake transport，归档 `.pv_tmp/REHEARSAL_IP-0038_2026-09-29/`）；⑤诚实记录——K1 缺口披露（重建与勘误=主会话职责）。全部离线：零真实调用、零付费、CI 零付费模型请求。

**Non-goals**：见 §1 Not-covered 段（CA 原文）。真实 pilot 执行、决策包 v6 发布、记录重建落盘与 #239 勘误、合并/推送/远端写不在本 Assignment 授权内。

## 5. 文件边界（CA R1：恰 1 Add + 3 Modify；零 Delete；单 PR `codex/ip-0038-preflight` → main）

### 5.1 Files to Add（恰 1）

| 文件 | Owner/阶段 | 说明 |
| --- | --- | --- |
| `docs/LIMA_Implementation_Packet_IP-0038_Preflight_Calibration.md` | P&V（C1，本文件） | 本 Packet；承载 CA R1-R10 全部裁定+两 DR 逐字落地（§7.1/§7.2）+预算数值表唯一真值源（§7.3）+区分面（§7.4）+付费效力机械判据与预演双证程序（§7.5）+§5.6 冻结面演进依据登记（manifest 计划形状派生对"写死 `_REPEAT_COUNT`"的显性覆盖=IP-0037 OBS-1 的落地裁定）+K1-K5 缺口登记（含 IP-0037 post-merge 记录缺失披露）+机械判据清单（§8） |

### 5.2 Files Allowed to Modify（恰 3）

| 文件 | Owner/阶段 | 边界 |
| --- | --- | --- |
| `Dockerfile` | P&V（C1，与 Packet 同一提交） | **恰 +1 行**：`COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0038_Preflight_Calibration.md ./docs/`（插 L68 `docs/LIMA_PR3e_V5_Field_Source_Table.md` 行后——CA M1 精确锚；派发摘要"IP-0037 Packet 行后"与 CA L68 锚的微小字面差异按 CA 执行并在 §16 DR-4 登记）；既有行零改动。基线 blob `22fcd3990653d361a028205b1f738434beb28d3d` |
| `tests/test_v4_baseline_real_run.py` | P&V（C2，冻结面演进 v7'→v8；90→97） | R6 演进+新增恰 7 方法（§9）；六条件程序（§10）；旧 90 方法零改动。基线 blob `8246b1c513163c164d49026eec416b48a3286679` 永久在链 |
| `benchmarks/v4/baseline/real_run.py` | Implementation（C3） | **恰两处**：①`_GuardedRealEvaluator` 新增两个类内只读 property（R2，§7.1.2）；②`_build_manifest_document` 的 cold_count/warm_count 两值改派生（R2，§7.1.3）。零其他改动（含零新 import、零新错误码、零签名变化）。基线 blob `1febb80e342142e4bf633ec3e3cc81f7e0668fb9` |

### 5.3 Read-only Reference Files（只读消费）

`benchmarks/v4/baseline/` 其余全部模块（budget/orchestrate/run/collect/expert_timing/offline_flow/report/fixtures）与各级 `__init__.py`（`run_repeats`/`run_baseline_attempt`/`BaselineRunSummary`/`BudgetLedger` 冻结基元只读消费）；`lima/baseline_run_result.py`（`_COLD_MIN_SUCCESSES`/`_WARM_MIN_SUCCESSES` 只读）与 `lima/contracts/codec.py`（canonical_encode 只读）；IP-0024..0037 Packet、两份批准工件、决策包；`evaluation_data/**` 全部；`.pv_tmp/` 各记录。

### 5.4 Files Forbidden（diff 必空；Done Command 7 逐 blob 守护）

`benchmarks/v4/baseline/` 其余全部模块与各级 `__init__.py`；`tests/` 其余全部既有文件（十个 v4 冻结测试文件 322 方法与其他）；`evaluation_data/**` 全部；`lima/**`；`scripts/**`；`docs/` 其余全部（含 IP-0036/0037 Packet、两份批准工件、V5 表）；`pyproject.toml`/`requirements.txt`/`.github/**`/`.gitignore`/`.gitattributes`/前端；`.pv_tmp/**` 不提交（预演工件与日志仅存 `.pv_tmp/REHEARSAL_IP-0038_2026-09-29/`）。

### 5.5 提交链拓扑（CA §Handoff/Done Command 8；冻结）

C1 = Packet + Dockerfile 恰 1 行（1 Add + 1 Modify，同一提交，前缀 `[IP-0038][PV]`）→ C2 = test_v4_baseline_real_run.py v7'→v8 落定（1 Modify；Frozen Test Commit；提交信息**必须含** `"[IP-0038][PV] Freeze acceptance tests v8 (RED)"` 字样；RED 证据先于冻结落盘并独立日志归档 `.pv_tmp/RED_IP-0038_2026-09-29/`）→ C3 = real_run.py（1 Modify，前缀 `[IP-0038][IMPL]`；**必须以 C2 为祖先**，Done Command 8）→ C-final（P&V 独立验证+R4 预演实际执行；如触发 ALLOWED_ONCE/修复提交须引用编号）。单 PR；不 push（合并/推送/评论由主会话按 Maintainer 授权执行，P&V/IMPL 零远端写）。

### 5.6 与其他活动 IP 的冲突分析（冻结面演进依据登记）

无并行活动 IP 占用本切片路径（IP-0038 编号未占用，CA §Authoritative Inputs #2 占用检查）。**冻结面演进依据显式登记（IP-0033..0037 Packet §5.6 先例）= 2026-09-29 第五轮 Maintainer 授权（#241 Scope 1）+DR-IP-0037-PV-8**，演进对象与覆盖登记：

1. **`_build_manifest_document` 的 `cold_count`/`warm_count` 两值**（real_run.py L2439-2440）：写死 `_REPEAT_COUNT` → 携带态派生（`guarded.planned_cold_count`/`guarded.planned_warm_count`，R2）。manifest 键集、键序、序列化通道零变化（值级派生）。**本条即对 IP-0037 Packet §16 DR-IP-0037-PV-8/OBS-1（"本 Packet 不裁定、测试不钉扎"的观察项）的落地裁定登记**：该面已由 #241 Scope 1/DR-PV-8 裁定为计划形状语义，IP-0038 测试面（N1）钉扎之；IP-0037 Packet 文本本身零改动（历史文档不改写；本节为唯一覆盖登记处）。
2. **`_GuardedRealEvaluator` 新增两个类内只读 property**（`planned_cold_count`/`planned_warm_count`；与 L1397-1418 既有 property 面同构；不进 `__all__`，公开入口签名零变化；R2）。语言内置面，预期零新 import。
3. **测试面**：tests/test_v4_baseline_real_run.py v7'→v8（§10 六条件；恰 7 新方法，90→97）。
4. **Dockerfile**：恰 +1 行（A1 COPY；插入位=L68 后，CA M1）。

历史文档零改动；本节即唯一演进依据登记处。IP-0024..0037 一切其余冻结面禁止触碰（含 manifest 其余十五键、attempt 文档键集、cold_reset 四键闭集值形状、{5,5} 路径、estimate 常量族）。

## 6. 依赖、网络、文件系统与权限边界

- **依赖**：零新增第三方依赖；零新 import（property 为语言内置面）。测试文件（M2）零新增 import（新增方法全部复用文件内既有 arrange 基建与已导入符号——`ast`/`math`/`inspect`/`hashlib`/`canonical_encode` 等已在导入面）。
- **网络**：测试全离线、fake transport/确定性 clock patch/本地合成工件；永不触网（既有 `_forbidden_network_roots` 断言延续）。**本 IP 全程任何真实网络/下载/付费调用/真实凭据注入=Stop Condition 1/4（绝对禁令）**。本 P&V 会话零网络（Packet 制作与冻结全程本地；CA 已完成远程只读核验）。
- **文件系统**：证据文件只写调用方提供的一次性输出目录（离线测试写 tempdir）；库内除 §5.1/§5.2 四文件外零写入；演练工件仅存 `.pv_tmp`（不提交、不复制入库）；不读环境变量/配置/.env。
- **数据库/容器/远端写**：无数据库；容器面仅 Dockerfile +1 COPY 行；零远端写（不 push、不开 PR、不关 Issue、不改 Ledger 远端状态——合并/推送/评论由主会话按 Maintainer 授权另行核发）。
- **凭据**：api_key 仍为显式必填参数，永不落盘/入日志/入错误消息/入证据；本叶零真实调用故 api_key 永不被真实使用（fake transport 面证明；演练工件用合成 key 并标注 `offline-rehearsal-no-paid-effect`）。
- **clock**：`_monotonic` 模块缝（IP-0035 冻结）继续是唯一 wall 时源；本叶零新时源、零真实 sleep（N1-old 确定性 arrange 经既有 `patch_monotonic`+`_JumpClock`）。

## 7. 实现契约细化（Packet 定稿；R2/R3/R4/R5 落位）

### 7.1 DR-IP-0037-PV-8 落地（R2；FR-01/AC-1）

#### 7.1.1 裁定逐字（转录源=#241 Scope 1 + Intent Record M；Maintainer 2026-09-29 裁定，授权原文逐字保全于 Agent 原文/派发记录）

> manifest 的 cold_count/warm_count 表示**批准的计划形状**（从工件 attempt_policy 派生：pilot 写 1/4、正式批写 3/5、旧 5/5 兼容不变）；逐 attempt 的真实成功/失败与 cold_reset 证据分别记录（attempt 文档既有面）；**序号标签不得当作已成功的本地重置**。

语义登记（规范性）：cold_count/warm_count=批准的计划形状，非实际成功计数；逐 attempt 实际证据分离在 attempts/ 文档（outcome/failure_code/cold_reset 观测键）；"实际 cold 数"由 `materialization_count` 携带（IP-0036 语义：the real cold count is this number, never the mode label）。

#### 7.1.2 冻结契约：`_GuardedRealEvaluator` 两个类内只读 property（C3-①）

```python
@property
def planned_cold_count(self) -> int:
    """The approved planned cold count carried from the validated shape."""
    if self._batch_shape is None:
        return _REPEAT_COUNT
    return self._batch_shape[0]

@property
def planned_warm_count(self) -> int:
    """The approved planned warm count carried from the validated shape."""
    if self._batch_shape is None:
        return _REPEAT_COUNT
    return self._batch_shape[1]
```

- 与既有 L1397-1418 property 面同构（类内、只读、零参数）；**不进 `__all__`**（六符号逐字冻结）；测试经类属性访问（`isinstance(getattr(_GuardedRealEvaluator, "planned_cold_count", None), property)` 与实例取值）。
- 取值=携带形状的解析值：`_batch_shape` tuple → `(batch_shape[0], batch_shape[1])`；`_batch_shape is None`（默认构造/{5,5}，L1355-1358 已携带）→ `(_REPEAT_COUNT, _REPEAT_COUNT)`。
- 零新 import、零签名变化、零对 `_batch_shape` 之外状态的读取。

#### 7.1.3 冻结契约：`_build_manifest_document` 派生（C3-②）

- L2439-2440 由 `"cold_count": _REPEAT_COUNT, "warm_count": _REPEAT_COUNT` 改为 `"cold_count": guarded.planned_cold_count, "warm_count": guarded.planned_warm_count`。
- **manifest 其余键、键序、写出通道（`_write_core_evidence` → `canonical_encode`）零改动**；`_build_manifest_document` 签名与其余函数体零改动。
- **纪律**：manifest 构造器绝不二次读取/解析 `approval.document`（路由已在 L2696-2708 对同一已校验文档一次性读取 attempt_policy 派生 batch_shape 并携带入评估器；manifest 只消费评估器携带态）。测试 N6 以源级断言（AST）钉扎：构造器体内不出现 `attempt_policy`、不出现 `_REPEAT_COUNT`、必须经 `guarded.planned_*` 属性读取。

#### 7.1.4 旧 {5,5} 兼容断言级（F4；AC-4）

{5,5} 工件场景下产出的 manifest 文档**逐键逐值全等且写出的 manifest.json 字节与改动前一致**——冻结测试 N1-old 以完整内联期望文档（全 17 键、全值，确定性 arrange：`patch_monotonic`+常值 `_JumpClock`）+ `canonical_encode(expected) == manifest.json 字节` 断言承载。已序列化面为排序键 canonical JSON（`codec.canonical_encode` sort_keys=True，字节级即全序），故"含键序"由字节一致断言承载；文档级另断言解析文档键序=排序序（Pre-Freeze 探针亲证，Design Input #14）。既有 v7' 90 方法零改动通过为第二重兼容证据（AC-4）。

### 7.2 DR-IP-0037-01 落地（R7-②；FR-02；规范性登记，零产品语义变更）

裁定逐字（转录源=#241 Scope 2；Maintainer 2026-09-29 裁定）：

> pilot 继续使用现有有界 12 候选 triage 与二元 verdict；Signal/Issue/Hypothesis/VEP/RVR/stage_outcome 无真实来源时保持 null+unavailable；pilot 不作为九类 V5 或全仓扫描验收；人工填写不得冒充机器实测。裁定记录入 Packet。

- **落地形态=本节规范性登记+预演断言面**（N2 报告断言组：report.py `_PROJECTIONS`/`_DOMAIN_BLOCK_FIELDS` 面上，无 domain 块的真实运行报告五计数控位+vep/rvr+三 stage 控位全 `{"value": None, "projection": "unavailable"}`、resources 三键全 None、expert.active_time_ms_total None、evidence_domain="legacy"）。**零产品语义变更**——V5 现状已由 IP-0037 A2（V5 逐字段来源表）如实登记，本叶不实现任何模型输出契约/扫描语义扩展。
- 有界 triage 面（`CANDIDATE_FILE_CAP=12` 请求构造参数+每候选单二元 verdict is_vulnerable）与"pilot≠九类验收""人工≠机器实测"为治理性纪律：任何以 pilot/预演产物冒充九类 V5 验收或人工填写冒充机器实测的宣称均无效（本 Packet 为裁定记录载体）。

### 7.3 预算选项 b 数值表（R5；FR-03/AC-2；**七维向量唯一真值源**）

#### 7.3.1 数值表（冻结；决策包 v6 逐值引用，不得另立数值）

| 维度（BUDGET_DIMENSIONS 序） | per_run | batch（pilot 工件） | batch 定稿依据（DR-IP-0038-PV-1） |
| --- | --- | --- | --- |
| cost_micro_usd | 100,000 | **198,000** | =5×首轮最坏成本预留 39,600（ceil(300,000×100,000/1M)+ceil(1,200,000×8,000/1M)） |
| calls | 1 | **5** | 仅单类 5 次 pilot（授权钉扎；=1c+4w） |
| prompt_tokens | 150,000 | **500,000** | =5×REQUEST_BODY_BYTE_CAP(100,000) |
| completion_tokens | 8,000 | **40,000** | =5×MAX_TOKENS(8,000) |
| wall_ms | 1,200,000 | **6,000,000** | =5×per_run.wall_ms(1,200,000) |
| download_bytes | 250,000,000 | **250,000,000** | =首轮保守预留常量（恰等，零余量；授权钉扎） |
| storage_bytes | 500,000,000 | **500,000,000** | =首轮保守预留常量（恰等，零余量；授权钉扎） |

- per_run 七维=钉扎工件族值不变（2026-09-27/28 授权族，Authoritative Inputs #8/#9）。
- attempt_policy：`{"cold": 1, "warm": 4, "max_attempts": 5, "canary_required": true, "canary_first_attempt": 0}`（pilot 计划形状）。

#### 7.3.2 约束验证（冻结；逐维核验，本 P&V 会话亲算+探针亲证）

1. **每维 batch ≥ per_run（`BudgetSpec` 纪律）**：198,000≥100,000 ✓；5≥1 ✓；500,000≥150,000 ✓；40,000≥8,000 ✓；6,000,000≥1,200,000 ✓；250,000,000=250,000,000（恰等，合法） ✓；500,000,000=500,000,000（恰等，合法） ✓。
2. **每维 batch ≥ 单次首轮最坏预留**：cost 198,000≥39,600 ✓；prompt 500,000≥100,000 ✓；completion 40,000≥8,000 ✓；wall 6,000,000≥1,200,000 ✓；download 250,000,000=250,000,000（**恰等边界含容**——reserve 门 at-cap 含容语义（budget.py L384-386/L439-444）：`reserved+consumed+estimate == cap` 通过，`>` 拒绝） ✓；storage 500,000,000=500,000,000（恰等含容） ✓。
3. **五次累计含容（{1,4} 全成功路径）**：completion 5×8,000=40,000 恰等含容 ✓；wall 5×1,200,000=6,000,000 恰等含容 ✓；cost 39,600+4×(小 prompt+8,000) ≤ 198,000 ✓；prompt 100,000+4×body ≤ 500,000 ✓；download/storage 仅 attempt-0 预留一次 ✓。探针（Design Input #14）亲证：全链恰 5 POST、零预算拒绝、violations=0。
4. **不放松任何门**：calls 门（batch.calls=5，第 6 次即拒）、cost 门（198,000 上限）、canary 门（index==1 清单+latch）全部原样；首轮 estimate 常量与 `_estimate_for(0)` 接线零改动（N4 静态钉扎）。

#### 7.3.3 决策包 v6 关系（K3）

决策包 v6（主会话发布）逐值引用本表，不得另立数值；发布前后数值冲突 → Stop 10/DR（不得双真值源）。冻结内联 fixture（N2/N7）与 `.pv_tmp` 演练件（C-final）逐值相同（单一真值源）。

### 7.4 区分面（R3；FR-05；最小面——零新字段）

"许可上限 vs 实际合成物化下载=0"的区分呈现：

1. **记账面（既有机制，零新机制）**：账本既有 released 桶如实记账——合成工件路径成功运行 `consumed.download_bytes=0`、`released.download_bytes=250,000,000`（预留全额释放；探针亲证）。N2 断言组钉扎；存储维关系断言 `released.storage_bytes == 500,000,000 - consumed.storage_bytes`（PC3）。
2. **文档面**：本 Packet §7.3 承载校准说明；决策包 v6（主会话发布）逐值引用。

**不在 ledger/report/manifest 新增任何区分字段**；ledger/report schema 零改动（report.py 在禁区）。被否决替代方案见 §3-3。

### 7.5 预演双证程序与付费效力边界（R4；FR-04/AC-3）

#### 7.5.1 证一（永久回归面；冻结测试内联 fixture）

R5 数值表的完整七维精确工件（§7.3.1 表+{1,4,5} attempt_policy），arrange 经冻结校验器同源构造（`write_synthetic_artifact`/`write_artifact` 变异后由 `_load_and_validate_approval` 校验加载——PC2）；承载"精确工件可过门"全断言面（N2/N7）。

#### 7.5.2 证二（实际离线执行；C-final，P&V）

P&V 在 C-final 以 `.pv_tmp` 演练工件（与内联 fixture **逐值相同**的七维数值、合成 api_key、工件内标注 `offline-rehearsal-no-paid-effect`）经正式 `run_real_baseline_suite` 入口+注入 fake transport，从空输出目录执行到报告；输出目录与执行日志归档 `.pv_tmp/REHEARSAL_IP-0038_2026-09-29/`（不提交入库；PR diff 不含；断言面与 N2 一致，核对表入 Verification Report，作为 AC-3 第二证）。

#### 7.5.3 付费效力机械判据（规范性；入 Packet）

工件具付费调用效力**当且仅当三条件同时成立**：

1. **真实凭据可用**（真实 API key/凭据通道在场）；
2. **真实 transport 入口**（非 fake 注入的默认网络出口实际可用）；
3. **审批链生效**（工件进入真实审批/授权链，非演练标注）。

**预演不构成**：三条件零成立（合成 key、fake transport 注入、离线+`offline-rehearsal-no-paid-effect` 标注）。

#### 7.5.4 边界裁定与防御条件（Coordinator 本人作出；回 Maintainer 条款不触发）

持久化 `.pv_tmp` 演练件**未触及**"不签发具付费效力批准工件"禁令——机械判据三条件零成立，且其与冻结测试内联 fixture 同类（结构合法、效力为零）。防御性条件四条：

- a) 绝不用于真实 transport/真实凭据（违反=绝对停，Stop 4）；
- b) 仅存 `.pv_tmp`，不提交、不复制入库；
- c) 工件标注 `offline-rehearsal-no-paid-effect`；
- d) 与冻结 fixture 数值逐值一致（单一真值源）。

执行中出现任一条件可能成立的迹象 → 绝对停+升级 Maintainer。

## 8. 离线负例与机械判据矩阵（FR-03/FR-04/AC-2/AC-3；全 fake transport，CI 零真实调用）

| # | 面 | 断言（冻结） | 方法 |
| --- | --- | --- | --- |
| 1 | 计划形状三态 | pilot {1,4}+数值表 → manifest cold_count=1/warm_count=4（含 attempt 级实际证据分离在场：attempt-0 cold_reset 观测在场 performed=False/count=1，warm 文档无 cold_reset）；正式 {3,5}+batch.calls=8 → 3/5；旧 {5,5} → 完整内联期望文档逐键逐值全等+序列化字节一致 | N1（M1/M2） |
| 2 | 预演全链（AC-3 核心） | 数值表精确工件+large-repo 合成 key+fake transport+空 temp 目录→报告：恰 5 POST、恰 5 件 attempt 文档、ledger.calls=5、consumed.download_bytes=0、released.download_bytes=250,000,000、恰 1 件 cold_reset 观测（attempt-0：performed=False、materialization_count=1；performed=True 计数=0——DR-PV-8 诚实面，§16 DR-2）、warm 4 件 state_reuse 复用（materialized=False/snapshot_reused=True/request_body_rebuilt=False）、零预算拒绝（5/5 success、manifest failures=[]、violations=0）、canary passed、聚合状态=insufficient_sample（{1,4} 按冻结规则诚实，非失败——全 success 证非失败冒充）、manifest 1/4、报告 V5 无来源字段全 unavailable（五计数位+vep/rvr+三 stage+resources 三键+expert.active_time_ms_total None+evidence_domain legacy） | N2（M3） |
| 3 | 资源超限拒付（双面） | (a) per_run=数值表、batch.download=249,999,999 → 工件在装载期被 `BUDGET_SPEC_INVALID @ $.budget.batch.download_bytes` 拒绝（batch<per_run 矛盾配置止于 BudgetSpec 构造），零 POST/零 GET；(b) 两级 download 均 249,999,999（其余同数值表）→ 首轮 reserve 即拒：`RUN_BUDGET_EXCEEDED @ $.budget.per_run.download_bytes`（per_run 门先于 batch 门——冻结门序），5 件 attempt 全 typed 失败、零 POST、ledger.calls=0。两面共同承载 #241 Scope 4"工件 batch.download<250M 首轮零 POST 拒付"（字面 BATCH 面不可达性见 §16 DR-3） | N3（M4） |
| 4 | estimate 常量静态钉扎 | `_DOWNLOAD_ESTIMATE_BYTES==250_000_000`、`_STORAGE_ESTIMATE_BYTES==500_000_000`、`_WALL_ESTIMATE_MS==1_200_000`（模块属性）+`_estimate_for(0)` 接线 AST 级钉扎（index==0 分支 CallEstimate 五关键字：prompt=REQUEST_BODY_BYTE_CAP/completion=MAX_TOKENS/wall=self._approval.budget_spec.per_run.wall_ms/download=_DOWNLOAD_ESTIMATE_BYTES/storage=_STORAGE_ESTIMATE_BYTES——防隐性放松） | N4（M5） |
| 5 | canary 失败零后续 POST | 既有 v7' `test_shaped_canary_failure_latches_zero_follow_on_posts`（L4537）承载（回归性复用不新增；N2 断言 canary passed 成功面）；Packet 归因表登记其通过 | 既有 v7' L4537 |
| 6 | manifest 派生纪律 | `planned_cold_count`/`planned_warm_count` 为 `_GuardedRealEvaluator` 类内 property（isinstance 复核）；不进 `__all__`；直接构造取值三态（batch_shape=None→(5,5)；(1,4)→1/4；(3,5)→3/5）；`_build_manifest_document` 源级（AST）：经 `guarded.planned_*` 属性读取、体内不出现 `attempt_policy`（不二次解析）与 `_REPEAT_COUNT`（不写死） | N6（M6） |
| 7 | 数值表双源一致 | 以测试内常量复刻的 §7.3.1 表构造的工件通过 `_load_and_validate_approval`；加载后 `budget_spec.per_run/batch` 逐维与表全等；约束关系组（batch≥per_run 逐维；prompt≥REQUEST_BODY_BYTE_CAP；completion≥MAX_TOKENS；wall≥per_run.wall_ms；cost≥首轮成本预留 39,600（复算）；download/storage==模块 estimate 常量） | N7（M7） |

## 9. 测试矩阵（M2 单文件面；R6 预算：90 存留+恰 7 新增=97；基线 90）

### 9.1 新增方法（7 个；恰一个新类 `TestPreflightCalibration(_RealRunTestCase)`，置于 `TestBatchShapeProtocol` 之后、`if __name__` 之前）

| 方法 | 覆盖 | 断言面（冻结） | RED 态 |
| --- | --- | --- | --- |
| `test_manifest_planned_shape_pilot_and_formal` | N1（FR-01/AC-1，§7.1） | pilot：数值表工件（repo key 变异 {1,4,5}+七维表）全链 → manifest cold_count==1/warm_count==4、attempt_count==5、attempt-0 cold_reset 在场（performed is False、materialization_count==1）、warm 文档无 cold_reset（实际证据分离在场）；formal：{3,5}+batch.calls=8 → manifest 3/5、attempt_count==8 | **RED**（基线写死 5/5） |
| `test_manifest_old_shape_full_document_byte_identical` | N1-old（FR-01/AC-4，§7.1.4） | {5,5} 默认工件+常值 `_JumpClock` 确定性 arrange → manifest 与完整内联期望文档（17 键全值：approval_digest/baseline_sha/tarball_sha256/指纹 token/coverage_gap/batch_remaining 七维/batch_wall_ms=0/deadline/canary 等，全部 PC3 派生）逐键逐值全等、解析键序=排序序、`canonical_encode(expected)==manifest.json` 字节一致 | 按设计通过（现行为即目标行为） |
| `test_pilot_rehearsal_full_chain_offline_report` | N2（FR-02/FR-03/FR-04/FR-05/AC-2/AC-3，§7.2/§7.4/§8-2） | §8-2 全断言面（large-repo 合成 key+数值表工件+空 temp 目录→报告；恰 5 POST/5 件 attempt/ledger.calls=5/consumed.download=0/released.download=250M/存储 released 关系/cold_reset 恰 1 件 attempt-0 performed=False count=1 且 performed=True 计数 0/warm 4 复用/零预算拒绝/violations=0/canary passed/status=insufficient_sample+全 success/manifest 1/4/报告 V5 unavailable 全位） | **RED**（manifest 5/5 断言失败） |
| `test_download_ceiling_one_byte_short_refused_zero_posts` | N3（FR-03/AC-2，§8-3） | 双 subTest：(a) batch.download=249,999,999（per_run 不变）→ `BudgetGateError(BUDGET_SPEC_INVALID) @ $.budget.batch.download_bytes`，零 POST/零 GET；(b) 两级均 249,999,999 → 首轮 reserve 拒付 `RUN_BUDGET_EXCEEDED @ $.budget.per_run.download_bytes`，5 件 attempt typed 失败、chat/download 计数均 0、ledger.calls==0 | 按设计通过（既有 fail-closed 门） |
| `test_estimate_constants_and_first_round_wiring_pinned` | N4（FR-03/AC-2，§8-4） | 模块三常量数值 + `_estimate_for(0)` 接线 AST 钉扎（五关键字逐一：Name/Attribute 形态精确匹配） | 按设计通过（常量与接线在场） |
| `test_manifest_derivation_discipline_carried_state_only` | N6（FR-01/AC-1，§8-6） | property 存在性（isinstance property）+不进 `__all__`+直接构造三态取值（None→(5,5)/(1,4)/(3,5)）+`_build_manifest_document` 源级三断言（经 guarded.planned_* 读携带态/无 attempt_policy/无 _REPEAT_COUNT） | **RED**（property 缺席+构造器写死） |
| `test_numeric_table_artifact_loader_dual_source` | N7（FR-03/AC-2，§8-7） | 数值表常量复刻工件经 `_load_and_validate_approval` 加载成功；budget_spec 两级逐维==表；约束关系组全过（§8-7 清单，成本预留 39,600 测试内复算） | 按设计通过（loader 校验既有） |

### 9.2 (b) 类值更新（全部由 R2-R5 裁定驱动，无一处实现便利）

模块 docstring 追加 v8 演进段（演进链注记）；新常量纯增量（`_PREFLIGHT_PER_RUN`/`_PREFLIGHT_BATCH` 数值表复刻、`_PREFLIGHT_REHEARSAL_KEY="archetype/large-repo"`、`_PREFLIGHT_ONE_BYTE_SHORT=249_999_999`、内联期望文档 ordered canary 键序等 arrange 基建）与 mutate helper `_preflight_policy(cold, warm, *, batch=None, per_run=None)`（deepcopy repo 文档仅变异 attempt_policy/budget——与 `_shaped_policy` 同源纪律）。**既有 90 方法零改动、零弱化**（旧 10 次路径回归即 AC-4 证据）。

### 9.3 RED 形态（Modify 型 IP；产品已存在；逐方法归因）

对**未修改产品（ae613ce3 版）**运行 v8（C1 已落库后、C2 冻结前）：

- **RED 锚（3 方法）**：`test_manifest_planned_shape_pilot_and_formal`（manifest 写死 5/5，cold_count==1 断言失败）；`test_pilot_rehearsal_full_chain_offline_report`（同锚，manifest 1/4 断言失败）；`test_manifest_derivation_discipline_carried_state_only`（property 缺席+构造器写死 `_REPEAT_COUNT`）——均为缺失计划形状派生能力（C3 交付物缺席），非 arrange/import/lint 失败。
- **按设计通过（4 方法）**：`test_manifest_old_shape_full_document_byte_identical`（{5,5} 现行为即目标行为，探针亲证）；`test_download_ceiling_one_byte_short_refused_zero_posts`（既有 fail-closed 门，探针亲证双面）；`test_estimate_constants_and_first_round_wiring_pinned`（常量与接线在场）；`test_numeric_table_artifact_loader_dual_source`（loader 校验既有）。
- **④canary 面**：v7' `test_shaped_canary_failure_latches_zero_follow_on_posts` 零改动通过（归因表登记）。
- 逐方法"RED 失败/按设计通过"归因表强制（归档 `.pv_tmp/RED_IP-0038_2026-09-29/`）；基线态证明=C0（90/322/2706+24 绿）。

## 10. 冻结测试面演进程序（M2 单文件适用；CA R6 六条件全文；正式 Packet 级一次性授权）

**冲突裁定**：IP-0038 的产品语义变更（manifest 计划形状派生）必然触碰 IP-0032..0037 冻结测试面 `tests/test_v4_baseline_real_run.py`。**裁定：允许该文件以受控方式演进至冻结版本 v8**（先例=IP-0033..0037 Packet §10）。演进是产品语义驱动（非机械缺陷），ALLOWED_ONCE 不适用、不得以其消化——授权依据=CA-IP-0038-v1.0 R6+本节。**演进依据=2026-09-29 第五轮 Maintainer 授权（#241 Scope 1/4；§5.6 登记）。**

**演进六条件（任一不满足=Stop Condition 9）**：

1. **对象唯一**：仅 M2 一文件一次（v7'→v8，90→97）；其余十个 v4 冻结测试文件（322 方法）与全部产品禁区模块 blob 逐字不变（Done Command 7 守护）。IP-0024..0036 冻结面=禁止。
2. **逐 hunk 归因**：每个 hunk 必须映射到 #241 FR-01..06/AC-1..5 之一或 CA 裁定编号（R2/R3/R4/R5/R6）并在 Packet 登记（§9.1 表已登记：7 新增方法逐条；§9.2 (b) 类更新→R6/R2-R5 驱动）。
3. **禁止弱化**：既有 90 方法断言不得删除或放松（fail-closed 门禁、泄露探针、hygiene、`__all__`/签名/数值守卫全部保留）；只允许 (a) 新增断言/方法、(b) 因显式登记的语义变更而更新的期望值。**本轮 (b) 类值更新清单见 §9.2（全部由 R2-R5 裁定驱动）**；既有方法体零改动。弱化判定争议 → Decision Request。
4. **版本链保留**：v1..v7' 历史 blob（含 `8246b1c5`）与历史提交永久在链；Packet 记录基线与演进 blob（v8 blob 由 C2 冻结时登记于提交与验证记录）。
5. **RED 先于冻结**：C2 冻结前，M2 对未修改产品（ae613ce3 版）运行并留档 RED 证据（独立日志文件归档 `.pv_tmp/RED_IP-0038_2026-09-29/`，每方法 traceback 可定位），逐方法登记"RED 失败/按设计通过"归因（§9.3）。
6. **角色纪律**：演进只在 C2 由 P&V 执行；Implementation 结构性零参与测试修改；C2 冻结提交后本 Assignment 的 ALLOWED_ONCE（§11）仅覆盖本文件面的机械缺陷（合计一次）。

**Pre-Freeze Harness Gate（冻结前必须全部通过；本 Packet 级强制）**：①测试文件可完整 import 与 collect（零加载期错误）；②新增 fixture/helper/参数组合经对现行产品的受控行为执行到断言处（区分 fixture 缺陷与行为缺失——计划形状缺席致 manifest 5/5 即行为缺失锚；arrange 本身不得有独立缺陷：校准工件除 attempt_policy/budget 七维外全部复用冻结 repo/合成工件构造器；Pre-Freeze 探针已亲证全部 arrange 面，Design Input #14）；③Ruff `--no-cache` 在产品模块缺席态与最小桩模块存在态分别运行并双双通过（isort 的 first-party 分类依赖模块存在性，单态通过不可作为证据）；④临时桩（如有）位于临时目录且不入冻结提交；⑤RED 逐项归因于缺失产品行为，不来自 arrange/import/lint 失败；⑥方法预算 97（90+恰 7）不超。

**ER 复核面**：ER 将逐 hunk 复核演进正当性（条件 2/3）、独立复跑 RED 归因、复核 §9 矩阵断言与 AC 映射。

## 11. ALLOWED_ONCE（一次性机械测试修正授权；CA §Mechanical Test Correction Allowance 全文转录）

C2 冻结后，P&V 可在不新增 Coordinator 调用的情况下自行纠正**一次**纯测试机械缺陷并重新冻结（v8→v8'），条件全部满足：①不改产品语义、公共接口、稳定错误码或文件范围（含 Dockerfile 行数）；②仅限 fixture/arrange/import/lint/测试基础设施缺陷；③旧 Frozen Commit 保留；④修正前缺陷证据（原始 traceback 独立日志）、修正后有效 RED、新 Frozen Commit 完整记录；⑤Implementation 未参与测试修改。涉及产品行为、验收语义或文件范围 → Decision Request；本授权与 R6 演进授权互不折抵、合计适用一次机械修正事件。

## 12. Stop Conditions（触发即停并提交 Decision Request；CA §Known Gaps and Stop Conditions 全文）

0. 派发前再核验失败：#241 正文/标签/远程状态与本地捕获不一致，或 Base SHA 上 main 出现冲突性实现（含 IP-0038 编号被占用）。
1. **任何真实网络/下载/付费调用/真实凭据注入（含分支上/CI 内/pre-merge"顺手验证"）——绝对禁令。**
2. **首轮 estimate 常量任何改动即停**：`_WALL_ESTIMATE_MS`/`_DOWNLOAD_ESTIMATE_BYTES`/`_STORAGE_ESTIMATE_BYTES` 数值或 `_estimate_for(0)` 取值接线任何变化。
3. **calls/cost/canary 任何放松即停**（含以工件数值、新校验路径或绕门方式放松）。
4. **`.pv_tmp` 演练件被用于真实 transport、真实凭据或离开 `.pv_tmp`——绝对停并升级 Maintainer。**
5. 需要修改 budget.py/orchestrate.py/run.py/collect.py/expert_timing.py/offline_flow.py/report.py/fixtures.py/`__init__.py`/`lima/**`/十冻结测试文件/`evaluation_data/**` 任何字节才能交付；或需要 run_repeats/run_baseline_attempt/`reset_cold_state`/`_run_shaped_repeats` 基元行为变更。
6. 需要 ledger/manifest/report 新增任何字段、`run_real_baseline_suite` 签名变更、`__all__` 变更、`_REPEAT_COUNT` 数值变更、{5,5} 路径任何行为变化、路由判据偏离"仅 attempt_policy 形状"、新增错误码或新 field_path。
7. 需要触碰 Do Not Touch 路径、第 5 个变更文件、Dockerfile 超 1 行、或 transport 契约偏离 4 参。
8. 方法数超预算（总 >100 或新增 >10）；十冻结文件回归/全量 discover 出现非预期失败。
9. 六条件演进程序任一不满足，或出现"弱化既有断言才能通过"的 hunk；弱化判定争议→DR。
10. 授权文本与实现需求冲突（含本 Assignment 裁定与 Maintainer 授权原文语义矛盾、裁定间互斥、或 R5 数值表与主会话已发布的决策包 v6 冲突）——不得自行改写授权或裁定。
11. 需要新第三方依赖，或 real_run.py 需要任何新 import（property 为语言内置面，预期零新 import），或非注入式外部输入/真实 sleep 驱动的测试。
12. 实现中发现证据/代码间新矛盾影响验收语义（如 {5,5} manifest 无法在派生路径下逐字节保持）——记录并提交，不得静默。
13. 需要消耗 Maintainer 决策的任何事项（预算 ≤1，预期 0）。
14. **任何形态需要携带可用请求能力或 api_key 通道的新工件，或任何具付费调用效力的工件。**
15. 预演实际执行中出现 R4 三条件任一可能成立的迹象（凭据可用/真实出口/审批链生效）。
16. 需要吞噬/转换/延迟重抛 BaseException（IP-0035 R4.3 延续）或丢弃证据。

## 13. Done Commands（worktree `D:/BaseAIProject/LIMA-ip-0038-wt` 根执行；Windows 设 `PYTHONUTF8=1`；成功判据=全绿/为空/恰 1 Add+3 Modify/blob 不变/ancestry exit 0）

```bash
# 0. 预冻结基线（C2 之前登记；本轮已执行并归档 .pv_tmp/RED_IP-0038_2026-09-29/baseline*.txt）：
#    test_real_run 90/90 OK（29.911s）；十冻结测试文件 322/322 OK（40.821s）；
#    全量 discover 2706 OK / skipped=24（264.160s）
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_real_run -v
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline tests.test_v4_baseline_budget tests.test_v4_baseline_cli tests.test_v4_baseline_collection tests.test_v4_baseline_fixtures tests.test_v4_baseline_manifest tests.test_v4_baseline_offline_flow tests.test_v4_baseline_report tests.test_v4_baseline_result tests.test_v4_baseline_v5_negatives
PYTHONUTF8=1 python -m unittest discover -s tests
# 0b. RED 证据（C2 冻结前，对未修改 real_run.py @ae613ce3）：独立日志归档
#     （.pv_tmp/RED_IP-0038_2026-09-29/）+ 逐方法归因表（R6；"RED 失败/按设计通过"）
# 1. 定向文件（C2 冻结时按设计 RED（恰 3 方法）且逐方法归因；C-final 后全绿；97 方法）
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_real_run -v
# 2. 十冻结文件回归（322 必须全绿；命令同 Done Command 0 第二行）
# 3. 全量 discover 回归（绿；skipped 集与基线一致=24；CI 零付费断言延续）
PYTHONUTF8=1 python -m unittest discover -s tests
# 4. 字节编译；ruff（--no-cache；bandit 选做，如实登记）
PYTHONUTF8=1 python -m compileall -q benchmarks tests
PYTHONUTF8=1 python -m ruff check --no-cache benchmarks/v4/baseline/real_run.py tests/test_v4_baseline_real_run.py
# 5. 预演实际执行（C-final，P&V）：.pv_tmp 演练工件（R5 数值表逐值+合成 key+
#    offline-rehearsal-no-paid-effect 标注）经正式 run_real_baseline_suite+fake transport，
#    空输出目录→报告；输出与日志归档 .pv_tmp/REHEARSAL_IP-0038_2026-09-29/；
#    断言面=N2 同款核对表，登记于 Verification Report（AC-3 第二证）；全程零真实网络
# 6. diff 守护：恰 1 Add（Packet）+ 3 Modify（Dockerfile/real_run/test_real_run）；
#    Dockerfile diff 恰 +1 行；.pv_tmp/** 与输出目录不在 diff
git diff --name-status ae613ce3d514edded68688d1a0141f665a666570...HEAD
git diff ae613ce3d514edded68688d1a0141f665a666570...HEAD -- Dockerfile   # 恰 +1 行
# 7. blob 守护：budget(6c783848)/orchestrate(8655067e)/run(d29928e5)/collect(063ecb41)/
#    expert_timing(dd7aa365)/offline_flow(0f2916c8)/__init__(1c478346)/report(e30a5f17)/
#    fixtures(700ec4fc) + 十冻结测试文件(4cde7bdf/edd4c62b/edb2391b/35e6ec6a/ca019d50/
#    8e8ab0dc/539d2fb3/86f584cb/0a44cf7d/b4a3a076) + IP-0037 Packet(568c2c0c)/
#    V5 表(587ef5e1)/批准工件(2e2473cd,3702c04a) + evaluation_data/v4/
#    baseline_manifest.json(7ecb39f8)/python_mvp_support_matrix.json(3ea94fcf)
#    + lima/** 与基线一致；real_run(1febb80e)/test_real_run(8246b1c5)/Dockerfile(22fcd399)
#    登记为"演进文件"（从 blob 记录在案，至 blob 由 C2/C3 登记）
git ls-tree ae613ce3d514edded68688d1a0141f665a666570 -- <守护清单> 与 HEAD 对比
# 8. ancestry：ae613ce3 → C1 → C2(冻结) → C3 → (C-final) 各段 merge-base --is-ancestor exit 0
```

PC1-PC3 标配（IP-0033..0037 同款）：PC1 新增测试源 secret-token/网络-token 拼接扫描（fake transport 零真实主机；文件级自扫由既有 hygiene 方法延续）；PC2 arrange 经冻结校验器（校准工件文档经 `write_artifact`/`write_synthetic_artifact` 深拷贝冻结工件后仅变异 attempt_policy/budget 维——与 `_load_and_validate_approval` 同源构造）；PC3 派生数值断言（manifest 期望文档的 digest/token/计数/batch_remaining 一律复算或关系断言：approval_digest=sha256(工件字节)、tarball_sha256=sha256(happy tarball)、指纹 token=_sf01_token、成本=math.ceil 价格公式复算、存储 released=预留-实际——不硬抄实现值）。

## 14. PR 与 Completion Summary 契约（CA §Handoff）

- PR：单 PR `codex/ip-0038-preflight` → main；标题禁 close 族关键词与编号组合（含否定句）；正文含 Final SHA（完整 40 位）、变更文件清单（对照恰 1 Add+3 Modify）、Done Commands 实际输出摘要（0/0b+1-8，含 5 的预演归档路径与核对表）、满足/不满足/未验证逐条、RED 归档路径与 blob 演进记录（real_run 1febb80e→、test_real_run 8246b1c5→、Dockerfile 22fcd399→）、下一责任人（P&V[C-final 独立验证+预演执行] → ER → Coordinator 合并判定 → post-merge → 叶审计）；PR 必须写明 "This PR does not auto-close the Source Issue." 与 "Related to #241."（仅此关联形式；不得关联关闭 #57/#239）；提交前缀 `[IP-0038][PV]`/`[IP-0038][IMPL]`/`[IP-0038][CI]`；C-final 后修复提交必须引用 Stop/DR/ALLOWED_ONCE 编号；实现提交（C3）以 C2 冻结提交为祖先（Done Command 8）。合并/推送/评论由主会话按 Maintainer 授权执行，P&V/IMPL 零远端写；本 Assignment 不授予任何合并/关闭判定。#241/#57 状态不受本叶合并直接影响（PARTIAL）；#239 勘误与 IP-0037 post-merge 重建=主会话职责。
- Completion Summary 必含：FR-01..06 逐条证据索引（测试 ID）、AC-1..5 判定（AC-5 区分 PR 面内/主会话 PR 外部分）、blob 演进记录与 C1/C2/C3 提交 SHA、RED 归档路径与逐方法归因计数（预期 3 RED/4 按设计通过+1 既有复用）、C0 基线实际值（90/322/2706+24）、零真实调用声明、Dockerfile 恰 +1 行证明、预演证据摘要（恰 5 POST/manifest 1/4/consumed.download=0/released=250M/零预算拒绝/V5 unavailable）、K1-K5 已知缺口状态、§16 flagged 事项状态。

## 15. 范围裁定 R1-R10 转录（CA-IP-0038-v1.0 决定性内容）

- **R1（文件拓扑与提交链）**：**单叶单 PR，恰 1 Add + 3 Modify，测试并入既有文件，不建新测试文件**。依据沿用 CA-IP-0037 R1（arrange 基建 `_FakeTransport` 族/工件构造器/确定性时钟 patch 在文件内；v7' 单文件演进链是 IP-0033..0037 既定可审计先例）。**被否决的替代方案（不得重试）**：独立新建 `tests/test_v4_preflight_calibration.py`。提交链：**C1（P&V：A1+M1 同一提交）→ C2（P&V：M2 冻结提交，Frozen Test Commit）→ C3（Implementation：M3，以 C2 为祖先）→ C-final（P&V 独立验证+R4 预演实际执行；如触发 ALLOWED_ONCE/修复提交须引用编号）**。
- **R2（Q1 manifest 计划形状派生；裁定点 A）**：**形态=新增类内只读 property，非暴露原始 `_batch_shape`，非二次解析**。冻结契约：`_GuardedRealEvaluator` 新增两个只读 `@property`——`planned_cold_count: int`、`planned_warm_count: int`（与既有 L1397-1418 property 面同构；**不进 `__all__`**，公开入口签名零变化）；取值=携带形状的解析值：`batch_shape` 为 tuple → `(batch_shape[0], batch_shape[1])`；`batch_shape is None`（默认构造/{5,5}）→ `(_REPEAT_COUNT, _REPEAT_COUNT)`。`_build_manifest_document` 的 `"cold_count"`/`"warm_count"`（L2439-2440）由写死 `_REPEAT_COUNT` 改为 `guarded.planned_cold_count`/`guarded.planned_warm_count`；manifest 其余键、键序、写出通道零改动。**纪律**：manifest 构造器绝不二次读取/解析 `approval.document`（路由已在 L2696-2708 对同一已校验文档一次性读取；manifest 只消费评估器携带态）。**旧 {5,5} 兼容断言级（F4）**：{5,5} 工件场景下产出的 manifest 文档**逐键逐值全等（含键序）且写出的 manifest.json 字节与改动前一致**——冻结测试以完整内联期望文档（全键、键序、全值）+ 序列化字节一致断言承载（确定性 arrange）；既有 v7' 90 方法零改动通过为第二重兼容证据。语义登记（DR-IP-0037-PV-8 逐字落地，入 Packet）：cold_count/warm_count=批准的计划形状，非实际成功计数；逐 attempt 实际证据分离在 attempts/ 文档；序号标签不得当作已成功的本地重置。**被否决的替代方案（不得重试）**：①manifest 构造器内再读 `approval.document["attempt_policy"]`（二次解析，违反纪律）；②向构造器暴露原始 `_batch_shape` tuple（把 None-分支引入 manifest 面+跨私有属性访问破坏 property 面先例）；③manifest 新增 actual_* 计数字段（键集闭破坏，与 R3 冲突）。
- **R3（Q2 区分面；裁定点 B）**：**最小面——零新字段**。"许可上限 vs 实际合成物化下载=0"的区分呈现=①**记账面**：账本既有 released 桶如实记账（成功路径 `consumed.download_bytes=0`、`released.download_bytes=250,000,000`——既有机制，F5 亲验成立，零新机制；冻结测试 N4 断言）；②**文档面**：Packet（A1）承载校准说明；决策包 v6（主会话发布）逐值引用 Packet 数值表。**不在 ledger/report/manifest 新增任何区分字段**；ledger/report schema 零改动（report.py 在禁区）。**被否决的替代方案（不得重试）**：ledger 或 report 新增 `actual_download_bytes`/派生标记类区分键（范围扩张+冻结面破坏+无信息增益——consumed/released 两桶已完整承载该区分）。
- **R4（Q3 预演双证载体与付费效力边界；裁定点 C）**：**证一（永久回归面）**=冻结测试内联 fixture（R5 数值表完整七维精确工件，arrange 经冻结校验器同源构造（PC2），承载"精确工件可过门"全断言）；**证二（实际离线执行）**=P&V 在 C-final 以 `.pv_tmp` 演练工件（与内联 fixture 逐值相同、合成 api_key、`offline-rehearsal-no-paid-effect` 标注）经正式 `run_real_baseline_suite`+fake transport 从空输出目录执行到报告，归档 `.pv_tmp/REHEARSAL_IP-0038_2026-09-29/`（不提交；断言面与 N6 一致，核对表入 Verification Report）。**付费效力机械判据（入 Packet，规范性）**：工件具付费调用效力当且仅当三条件**同时**成立：(1) 真实凭据可用；(2) 真实 transport 入口；(3) 审批链生效。**预演不构成**：三条件零成立。**边界裁定（Coordinator 本人作出；回 Maintainer 条款不触发）**：持久化 `.pv_tmp` 演练件未触及"不签发具付费效力批准工件"禁令。防御性条件四条：a) 绝不用于真实 transport/真实凭据（违反=绝对停，Stop 4）；b) 仅存 `.pv_tmp`，不提交、不复制入库；c) 工件标注 `offline-rehearsal-no-paid-effect`；d) 与冻结 fixture 数值逐值一致。**被否决的替代方案（不得重试）**：①以 CI 内联测试替代实际执行；②演练工件提交入库；③演练以非正式入口/脚本旁路驱动。
- **R5（预算选项 b 数值钉扎与七维向量真值源）**：**永固钉扎**：pilot 工件 `batch.download_bytes=250,000,000`、`batch.storage_bytes=500,000,000`（许可上限恰好覆盖单次首轮保守预留，零余量）、`batch.calls=5`；**首轮预留不改 0**——estimate 常量与 `_estimate_for(0)` 接线零改动（N4 静态钉扎）；calls/cost/canary 门零放松。**七维向量唯一真值源=Packet（A1）数值表**：per_run 七维=钉扎工件族值不变；batch 其余四维由 P&V 在 C1 定稿（约束：每维 batch≥per_run、每维 batch≥首轮最坏预留、不放松任何门；定稿值逐值登记 Packet）；决策包 v6 逐值引用该表不得另立数值；冲突 → Stop 10。**资源超限负例**：`batch.download_bytes=249,999,999`（恰差 1）工件 → 首轮零 POST 拒付（既有 fail-closed 门，按设计通过；可达拒绝面的机械核验见 §16 DR-3）。
- **R6（Q4 测试面演进 v7'→v8；裁定点 D）**：恰**一个新类 `TestPreflightCalibration(_RealRunTestCase)`**（置于 `TestBatchShapeProtocol` 之后）；旧 **90 方法零改动**（AC-4）；六条件程序沿用 IP-0033..0037。**新增必含清单（N1-N7）**：N1 pilot {1,4} manifest 计划形状=1/4（含 attempt 级实际证据分离在场断言）；N2 正式批 {3,5} manifest 计划形状=3/5；N3 旧 {5,5} manifest 逐字节回归（R2 断言级）；N4 v6 精确工件（R5 数值表）过首轮 reserve、零预算拒绝、跑完恰 5 POST、`consumed.download_bytes=0`/`released.download_bytes=250,000,000`、`ledger.calls=5`；N5 资源超限工件（249,999,999）首轮零 POST 拒付（精确错误面）；N6 预演全链断言（空目录→报告；V5 无来源字段 projection=unavailable；恰 5 件 attempt 证据；`cold_reset.performed=True` 恰 1；warm 复用 4；manifest 1/4）；N7 estimate 常量静态钉扎。**④canary 失败零后续 POST**：已由 v7' L4537 覆盖——回归性复用不新增。新增合计 **≥7 且 ≤10**，总方法数 **≤100**。**RED 锚=N1/N2/N6**（本 Packet §9.3 具体化为恰 3 方法）；其余按设计通过——逐方法归因表强制。（字面注记：R6-N6"performed=True 恰 1"与 N5"BATCH_BUDGET_EXCEEDED @ batch 面"两处字面表述经机械核验不可达/与 DR-PV-8 冲突，其诚实可达形态冻结于 §8-2/§8-3，登记于 §16 DR-2/DR-3 提交 Coordinator 确认。）
- **R7（两 DR 逐字落地与 Packet 承载清单）**：A1 必载：①DR-IP-0037-PV-8 逐字裁定（转录源=Intent Record M 保存版+#241 Scope 1；落地=R2）；②DR-IP-0037-01 逐字裁定（#241 Scope 2；落地形态=Packet 规范性登记+预演断言面，零产品语义变更）；③R3 区分面+R5 数值表；④R4 付费效力机械判据；⑤K1-K5 缺口登记（含 IP-0037 post-merge 记录缺失与 #239 引用失效披露）；⑥§5.6-同构"冻结面演进依据登记"。
- **R8（Done Commands）**：§13（0/0b+1-8）。
- **R9（Stop Conditions 与 ALLOWED_ONCE）**：§12（0-16）/§11。
- **R10（升级条款）**：Implementation 出现跨冻结模块语义约束、同一根因两轮有新证据修复仍失败、疑似规格矛盾 → 停止并提交 DR；如裁定升级目标档位 `glm-5.3 / max`，实际切换须新建/重新配置会话并取得 SESSION-RUNTIME-VERIFIED（派发文本声明不构成运行切换），文件边界/测试冻结/验收标准不变。

## 16. Decision Record（P&V 定稿决策；CA 授权范围内的冻结裁量）

| # | 决策 | 时间 | 依据 |
| --- | --- | --- | --- |
| DR-IP-0038-PV-1 | batch 其余四维定稿=**每 attempt 最坏预留 ×5**：cost 198,000（=5×39,600）、prompt 500,000（=5×100,000）、completion 40,000（=5×8,000）、wall 6,000,000（=5×1,200,000）；download/storage=授权钉扎常量恰等（250M/500M）。约束验证逐维通过（§7.3.2），completion/wall 五次累计恰等含容（at-cap 通过语义），prompt/cost 相对实际留有正余量 | 2026-09-29 | R5/K4 授权自由度；最坏预留基准（`_estimate_for(0)` 四维常量+成本公式复算）与 5 次 pilot 形状的乘积是最小无放松取值；探针亲证全链零预算拒绝 |
| DR-IP-0038-PV-2 | **N2 cold 证据诚实面（flagged，提交 Coordinator 确认）**：#241 Scope 4 与 CA R6-N6 的字面"`cold_reset.performed=True` 恰一件"对 {1,4} pilot **不可实现**——IP-0037 冻结值形状（Packet §7.5.2：index 0 初始物化 performed=False，True 仅 cold>0 可验证重置）+v7' 冻结方法 `test_formal_batch_cold_reset_chain_observability`（attempt-0 performed False/count 1 钉扎）+DR-PV-8 自身"序号标签不得当作已成功的本地重置"（把 attempt-0 物化标称 performed=True 恰是该 DR 禁止的谎报）。冻结诚实面：恰 1 件 cold_reset 观测在 attempt-0（performed=False、materialization_count=1——"实际 cold 重置证据=1"的诚实承载）、performed=True 计数==0（负向断言防造假）、warm 4 件复用 | 2026-09-29 | DR-PV-8 语义优先于其 Scope 4 括注的字面；CA Not-covered 4（cold_reset 值形状冻结）+Stop 6；探针亲证（Design Input #14 probe B：attempt-0 performed=False/count=1）；不冻结不可实现断言（否则 C3 永久 RED 或被迫违反冻结面） |
| DR-IP-0038-PV-3 | **N3 双面形态（flagged，提交 Coordinator 确认）**：字面"首轮 reserve `BATCH_BUDGET_EXCEEDED @ $.budget.batch.download_bytes`"经可加载工件**不可达**——per_run 保持数值表 250M 时 `BudgetSpec`（batch≥per_run，budget.py L213-217）在装载期即拒（`BUDGET_SPEC_INVALID` 同 field_path，探针 C1 亲证）；两级均降 249,999,999 时 per_run 门先于 batch 门（reserve L403-422 先于 L424-444，探针 C2 亲证：`RUN_BUDGET_EXCEEDED @ $.budget.per_run.download_bytes`、5 件 typed 失败、零 POST、ledger.calls=0）。冻结两面共同承载 #241 Scope 4 原文"工件 batch.download<250M 首轮零 POST 拒付"（其原文未指定错误码面） | 2026-09-29 | 冻结代码门序与 BudgetSpec 纪律（禁区不可改）；探针 C1/C2 输出归档；CA R5"既有 fail-closed 门，按设计通过" |
| DR-IP-0038-PV-4 | Dockerfile 插入锚=**L68（V5 表行）后**（CA M1 精确锚）；派发摘要"IP-0037 Packet 行后"（=L67）为摘要性表述，两锚同在 IP-0037 两行簇内、差异仅一行位次，按 CA 执行 | 2026-09-29 | 派发明示"CA-IP-0038-v1.0——范围权威 R1-R10，严格按其执行"；CA M1 含精确行锚 |
| DR-IP-0038-PV-5 | N1-old 逐字节承载形态=完整内联期望文档（17 键全值，PC3 派生：approval_digest=sha256(repo 工件字节)、tarball_sha256=sha256(happy tarball)、指纹 token=_sf01_token("fp-stable-001")、coverage_gap=len(files)-.py 数、batch_remaining 七维=限值-复算 consumed、成本=math.ceil 价格公式）+`canonical_encode(expected)==manifest.json 字节`+解析键序=排序序；确定性 arrange=既有 `patch_monotonic`+常值 `_JumpClock`（batch_wall_ms=0、wall consumed=0）。已序列化面为排序键 canonical JSON，"含键序"由字节一致（全序）承载——如实登记 | 2026-09-29 | R2/F4 断言级；Pre-Freeze 探针 A 亲证（canonical 字节一致=True、全部派生值命中）；IP-0035 时序缝先例 |
| DR-IP-0038-PV-6 | ④canary 失败零后续 POST：不新增方法；v7' `test_shaped_canary_failure_latches_zero_follow_on_posts`（L4537）为登记回归面；N2 断言 canary passed（成功面） | 2026-09-29 | R6 明文"已由 v7' L4537 覆盖——回归性复用不新增" |
| DR-IP-0038-PV-7 | 新增方法数=恰 7（90→97），N1 拆为 pilot+formal（M1）与 old（M2）两方法承载三态（pilot/formal 同为计划形状派生 RED 锚、old 为兼容绿面，归因单一）；N5 并入既有 v7' 方法不新增 | 2026-09-29 | R6 预算 ≥7 且 ≤10、总 ≤100；§9.3 逐方法单一归因态纪律（IP-0037 DR-PV-5 先例） |

**观察项（不移交实现、不构成验收面）**：

- **OBS-1**：C-final 预演（证二）由 P&V 以 `.pv_tmp` 演练工件执行；其核对表与 N2 断言面一致性由 Verification Report 承载（R4）；本 Packet 不为预演另设验收方法。
- **OBS-2**：DR-IP-0038-PV-2/DR-IP-0038-PV-3 为 flagged 字面差异（不改裁定语义，仅登记不可达字面的诚实可达形态）；Coordinator 如需改采其他形态（例如另裁 per_run.download 同降语义或 storage 维负例），须以 CA 勘误（v1.1+）授权重新冻结相应方法——本 Packet 冻结面在此之前保持本节形态。

## 17. 已知缺口（不阻塞本 Packet；CA K1-K5 同构登记）

- **K1** `POST_MERGE_VERIFICATION_IP-0037` 从未落盘（F2/亲验）：重建落盘与 #239 勘误评论=**主会话职责（非本 PR 面）**；本 Packet 仅做披露登记；IP-0037 的 IP-DONE 判定与 #239 Closure 引用修复待重建记录落盘后复核。同目录存在合并前 `VERIFICATION_REPORT_IP-0037_2026-09-29.md`——不得混同冒充。
- **K2** 零真实批次：本叶全部证明为 fake transport 离线双证；真实 pilot（5 次）另行授权与工件（第五轮边界：停在真实 pilot 门前）。
- **K3** 决策包 v6 未发布（主会话）：七维数值真值源已裁定在本 Packet §7.3，v6 逐值引用；发布前后数值冲突=Stop 10。
- **K4** batch 其余四维数值已在 C1 定稿（DR-IP-0038-PV-1），如实登记——开区间数值选择的如实边界。
- **K5** 区分面无机器可读字段（R3 裁定为文档面+既有 released 桶）；未来如需机器可读区分须新 DR。

（Packet 完；版本 v1.0。Contract 语义变更须同步 Packet 版本与 AC。）
