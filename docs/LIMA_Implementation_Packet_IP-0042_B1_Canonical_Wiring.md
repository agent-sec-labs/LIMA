# LIMA Implementation Packet — IP-0042 B1 canonical 来源接线（#254，B1 canonical source wiring 缺陷修复叶，C1-C2 零真实调用）

- Packet ID：IP-0042；版本 v1.0（2026-10-01）。
- Coordinator Assignment：CA-IP-0042-v1.0（2026-10-01；范围权威含附录 R1-R6，全文转录见 §14；**本 Assignment 为唯一裁定权威，本 Packet 全文转录不得改义**）。
- Source Issue：#254（open，V4-I01，2026-10-01 建，AC-1..AC-5，parent #57 保持 open/PR3 未勾；#251 closed 不重开；正文经派发消息所附 `create_issue_ip0042.py` BODY 转录消费——本 P&V 会话按第九轮授权离线运行【零网络】，未独立 GET Issue 正文；Scope 1-7/AC-1..5/Non-goals 与第九轮裁定逐字一致——Coordinator 2026-10-01 亲核该脚本）。
- Operating Mode：SHADOW（治理链路）；Execution Authorization：MAINTAINER_AUTHORIZED（2026-10-01 第九轮；**本轮真实模型请求/真实 transport POST 上限=0，不签发付费效力工件**；不安排新 pilot；九类 72 次批不批准；第八轮 5/5 已耗尽不复用；第八轮 ALLOWED_ONCE 已用尽不可借）。**本 Assignment（C1+C2）全程零真实模型调用、零网络、零付费、零凭据注入、零远端写。**
- 授权链：Maintainer 第九轮裁定（`.pv_tmp/ZCODE_LONG_TASK_BASELINE_CLOSURE_CRITICAL_PATH_2026-10-01.md` §一-§七；**§二=本叶唯一权威**；§三区分力证明；§四便携核验包；§五/§六矩阵与勘误；§七执行纪律）→ Issue #254 → CA-IP-0042-v1.0 → 本 Packet。
- 技术根因权威：`.pv_tmp/ROUND9_INDEPENDENT_PATH_DIGEST_AUDIT_2026-10-01.md`（§2 双根复现+规范化 digest `80b08fb01dba6f7dae251295886b35370bcbbd5d9ce9cacc91656f6664380099`、差异字段恰 `$.repository`/`$.workspace.root`；§3 接线遗漏定位；§4 三处能力表述纠正）。
- Base SHA（完整 40 位，C1 基线）：`9a15898333b23b2b1ad8edf7dbf173d39fa3336c`（= PR #253 merge；本 P&V 会话 2026-10-01 于 worktree 亲验 `git rev-parse HEAD` 同 SHA、`git status --short` 干净）。
- 基线产物指纹（本 P&V 会话 `git ls-tree HEAD` 程序化复核）：Dockerfile `69ec7cc81a36`；real_run.py `202d8d2ca818`、b1_source.py `9b188073788b`、b1_real.py `2761daa1ee1a`、report.py `e30a5f17f84d`；五冻结测试文件 test_v4_baseline_real_run.py `b9f9b4a9d3eb`（112 方法）/ test_v4_baseline_b1_source.py `a5c587d70555`（20）/ test_v4_baseline_report.py `86f584cb4b85`（38）/ test_v4_baseline_v5_negatives.py `6c86e936b85d`（9）/ test_v4_baseline_b1_real.py `6c6054c7a387`（25，v11'）；v11' Frozen Test Commit `ceea4d60`（本地 `git log` 亲验在链）。
- 旧 sealed 工件兼容对象（本会话只读亲验，零写入）：`D:\BaseAIProject\LIMA-real-runs\pr3d-b1-real-2026-10-01\`——`b1-real-manifest.json` 30 键（=当前 `_MANIFEST_KEYS` 旧集逐键）、`source_contract_version=1`、`scanner_payload_sha256` 前缀 `a7c20067`（raw-path 值）；`b1-real-attempts/` 5 件 receipt 各 23 键；manifest 与 receipt 均无 `canonical_source_contract_version` 键。
- 冻结前基线绿（主会话 2026-10-01 亲验，CA §Authoritative Inputs 引用）：四旧文件 **179 passed**（112+20+38+9）；b1_real 25 方法（v11'）；全量 discover **2773 OK / skipped=24**。
- 本 Packet 的角色：Implementation（阶段 C3，以 CA-IP-0042-v1.1 正式指派为准）的唯一实现依据；冻结验收测试面（§8，`tests/test_v4_baseline_b1_real.py` 原地演进，冻结版本 **v12** = v11' 之后序号）的唯一语义来源；P&V 独立验证与 C4 证明/便携包/DERIVED（另授）的规格来源。

## 0. 交付物角色声明（强制，先于一切）

1. 本 Packet 与 Dockerfile 恰 +1 行 COPY 是 P&V 的 C1 交付物；**`tests/test_v4_baseline_b1_real.py` 原地演进（v12：恰 3 同步点 S1-S3 + ≤12 新方法）是 P&V 的 C2 交付物（Frozen Test Commit）**；`benchmarks/v4/baseline/b1_real.py` 与 `real_run.py` 的 §7.1 点名例外（**real_run.py 演进例外清单=恰 E3 一 hunk**）是 **Implementation 的 C3 交付物**。边界不得互换：Implementation 不得修改本 Packet/测试；P&V 不实现产品功能。
2. **零真实调用绝对禁令（C1-C4 与 CI 全程）**：任何真实模型调用（含一次 POST）、网络下载、付费动作、真实凭据注入 = 绝对停（Stop 1）。本叶不存在任何真实调用授权。
3. **本叶修复的是 canonical 来源接线，不产生新证据效力**：不产生任何新真实 pilot 证据；第八轮既有 24 findings/legacy_projection/unavailable/无真人事件边界不变；跨目录 replay 等值证明在 C4 离线完成后才成立；历史 raw digest 是当时封存的有效内容事实，不覆写、不按新规范重新解释（审计 §3）。
4. **冻结面零回退**：IP-0024..0041 一切冻结面零回退；`b1_source.py` 本叶**只读**（零修改——R1.5）；`report.py`/`budget.py`/`run.py`/`orchestrate.py`/`fixtures.py`/`collect.py`/`offline_flow.py` 与各级 `__init__.py` 零 diff（R1 裁定 E4 零代码改动；确需例外先 DR）；旧公共入口 `run_real_baseline_suite` 九参数签名/order 1-9/旧十一键描述子行为/transport/预算 estimate/身份允许集/批准族/canary/首败/截止/取消门语义全部冻结。
5. **不新增错误码/declaration/公共符号**：`B1RealErrorCode` 五码闭集（b1_real.py L227-234+消息 L241-257）不新增；`_DECLARATIONS` 五条（L192-198）不新增；`__all__` 五符号（L69-75）不变；`run_b1_real_baseline_suite` 八参数签名（L554-564）不变；`schema_version` 保持 1。
6. **主会话职责（非本 PR 面）**：合并/推送/PR/Issue 评论等一切远端写；C4 便携包/DERIVED 的 durable 保存（副本/清单校验后才清理 worktree；未跟踪/ignored 资料先保存）；#254 Delivery Ledger 持久化。

## 1. 需求映射（Packet 头）

```text
Source Issue：#254（open；AC-1..AC-5；正文经派发消息所附 create_issue_ip0042.py BODY 转录，本会话零网络未独立 GET）
Issue specification revision：2026-10-01 创建版（Scope 1-7/AC-1..AC-5/Non-goals 与第九轮裁定逐字一致）
Covered requirements：Scope 1-6（编号规范化见下表；语义=CA §Goal and Scope+裁定 §二-§四 逐字，不改义）、AC-1..AC-5（本叶 C1-C4 各段分别承载，逐段标注）
Not covered requirements：任何真实模型调用/网络下载/付费/凭据注入；新 pilot；九类付费批（72 次不折抵）；全局付费调度器；B1 real 扩展 3c/5w（#57 关键路径表登记项，不借本修复顺带实现）；b1_source.py 规则修改（只读 import；确需最小例外先具名 DR）；旧默认入口/transport/预算 estimate/身份允许集/批准族/canary/首败/截止/取消门语义变化；lima/**、holdout 标签、Prompt、匹配/评分、生产 Mining/Repair 逻辑；删字段/按当前样本重排 findings/放松来源绑定/改生产分析器/固定路径或设 seed 掩盖绝对路径差异；v9/#57 勘误与 CLOSURE_CRITICAL_PATH_MATRIX 的编制与落盘（#254 Scope 7，随文档另行交付，不在 C1-C3 PR 面内——本 Packet 只登记其存在与归属）；重开 #251/重跑第六至八轮；旧 sealed 目录任何写入（含 DERIVED 不得写回原目录）
Delivery role：defect-fix（B1 canonical 来源接线：E3 单点 canonical 存储 + 后相/验证器同规则 + 显式契约版本与旧新兼容 + 受审证明与便携证据）
Issue closure impact：PARTIAL（IP-0042 完成 ≠ #254 完成 ≠ #57 完成；AC-4/AC-5 的执行证据在 C4/文档交付后方完整）
Upstream IP/PR/merge commits：基线=IP-0041/#251 收口（PR #253 merge 9a15898，main lima-ci success）；直接消费面=b1_real.py 真实入口与 companion 工件（IP-0041）、real_run.py B1 gated hook（IP-0041 E0-E4）、b1_source.py canonical 投影（IP-0040，只读复用）、report.py scanner 源规则（IP-0029/IP-0040，零改动）；先例 Packet=IP-0041（结构/DR-PV 风格/授权同步点先例）
```

| 需求（规范化） | 内容（语义=CA/裁定原文，不改义） | 本 Packet 承载 | 验收面（§8 方法 / 执行段） |
| --- | --- | --- | --- |
| FR-01（=Scope 1 canonical 统一） | 修复 hook/后相/验证器三处接线，优先复用既有 `b1_source._canonical_payload` 投影（零修改 b1_source）；只消除已证明的非语义物化路径差异（保留全部 findings/排序/inventory/coverage/失败/协作裁定字段；不删字段/不按当前样本重排/不放松来源绑定/不改生产分析器）；canonical 来源 digest 与当次 execution/context digest 用途分清（语义身份由身份字段钉扎） | §7.1/§7.3/§7.4 | N-A1/N-A2/N-A3/N-C2/N-C3/N-D1 + C3 产品 + C4 证明 |
| FR-02（=Scope 2 版本化与兼容） | 显式契约/算法版本；旧 raw-path 工件旧规则验证、新版新规则；版本分支由可验证版本+元数据选择；缺失/错配/篡改/身份漂移 fail closed，禁止"失败就换算法" | §7.2 | N-B1/N-B2/N-B3 + C4 sealed 复验 |
| FR-03（=Scope 3 测试契约同步） | canonical 路径标签、digest 算法/契约版本、旧新兼容所必需的既有测试同步——Packet 冻结前列出具名方法、旧/新语义与独立反例；不借第八轮 ALLOWED_ONCE（已用尽）；不改预算/门序/失败终局/来源完整性/零网络零凭据断言 | §8（R4 附表逐字） | C2（S1-S3 + 新方法 + 冻结 v12） |
| FR-04（=Scope 4 区分力离线证明） | 双根/跨进程/双 PYTHONHASHSEED/独立重算（非产品自证）/四类负例/旧 sealed 只读复验/旧入口无新 hook 副作用/24-legacy_projection-unavailable-不求和-零 finding 区分不变 | §7.5（C4 证明计划） | C4（预排归属；可测子集入 N-簇） |
| FR-05（=Scope 5 便携补充核验包） | sealed 目录之外的小型包：相对路径清单/规范版本/执行与派生来源说明/核验脚本；显式只读封存根参数；无工作区绝对路径依赖；不读 .env/不加载密钥/不请求模型；重算清单检测缺失/额外；直接重算 snapshot tree；覆盖/未覆盖分列；结构性脱敏与真实密钥字节检查分开 | §7.6.1-§7.6.2 | C4（预排归属） |
| FR-06（=Scope 6 DERIVED 件） | 为第八轮目录生成 canonical 补充证明于新目录，绑定原目录清单/原文件 SHA-256/执行 commit 9a15898/当前投影版本；不改写旧 receipt/manifest/source digest/授权摘要；不称派生件为当时已执行 | §7.6.3 | C4（预排归属） |
| FR-07（=Scope 7 勘误与矩阵） | v9 五项追加勘误；#57 能力边界勘误；CLOSURE_CRITICAL_PATH_MATRIX 全条款逐行八列+拓扑序+A-D 结论——**文档交付，不在本 PR 面**（本 Packet 只登记存在与归属） | §4/§16 | 无（登记缺口；随文档另行交付） |
| AC-1 canonical 统一 | 双根/跨进程/双 hash seed 下 canonical 来源字节与 identity 相等（独立重算证实）；差异字段清单与修复前实测一致（仅非语义路径面） | §7.1/§7.4/§7.5 | N-A1-N-A4/N-C2 + C4 |
| AC-2 版本化兼容 | 旧 raw-path 工件按旧规则验证通过（第八轮 sealed 目录只读复验）；新工件新规则；版本缺失/错配/篡改 fail closed（负例） | §7.2 | N-B1-N-B3/T10/T11(S1-S3) + C4 |
| AC-3 冻结面零回退 | 旧入口/门/预算/报告语义零变化；v11' 及全部旧面回归绿；canonical 与 execution digest 用途分清 | §7.7/§8 | 23 零触碰方法 + 四旧文件 + Done Commands |
| AC-4 便携包与 DERIVED | 包可脱离工作区与 .env 独立运行（只读封存根参数）；DERIVED 件绑定链完整；旧件零改写 | §7.6 | C4（执行证据） |
| AC-5 矩阵与勘误 | 全条款矩阵逐行八列+拓扑序+下一真实动作；v9/#57 勘误以追加方式落盘/评论 | §4（登记归属） | 文档交付（非本 PR 面） |

**Not-covered（全团队不得扩张）**：见上文 Not covered requirements 段与 §12 Stop Conditions（= CA §Not covered 全部）。

## 2. Design Input Manifest

| # | 输入 | 类型/版本/位置 | 消费方式 | Authority |
| --- | --- | --- | --- | --- |
| DI-001 | CA-IP-0042-v1.0 | `.pv_tmp/COORDINATOR_ASSIGNMENT_IP-0042_2026-10-01.md`（2026-10-01） | 范围权威；附录 R1-R6 转录见 §14；本 Packet 逐条承载 | normative |
| DI-002 | 第九轮裁定（Maintainer 已采纳生效） | `.pv_tmp/ZCODE_LONG_TASK_BASELINE_CLOSURE_CRITICAL_PATH_2026-10-01.md` §一-§七 | §二（唯一权威）/§三（区分力证明）/§四（便携核验包）/§五§六（矩阵勘误归属登记）/§七（执行纪律）逐字承载 | normative |
| DI-003 | 独立审计 | `.pv_tmp/ROUND9_INDEPENDENT_PATH_DIGEST_AUDIT_2026-10-01.md` | 技术根因权威：§2 双根复现（raw_equal=False/normalized_equal=True/differing_fields 恰两字段）、§3 接线遗漏定位（real_run.py:1879/b1_real.py:683/:981）、§4 三处能力表述纠正 | normative（技术根因） |
| DI-004 | Source Issue #254 | open，V4-I01，2026-10-01 建，AC-1..AC-5，parent #57（经派发消息所附 create_issue_ip0042.py BODY 转录；本会话零网络未独立 GET） | 需求语义经 CA §Goal and Scope+裁定消费（FR-01..07 规范化不改义） | normative（经转录消费） |
| DI-005 | benchmarks/v4/baseline/b1_source.py @9a15898 | blob `9b188073788b`（本会话亲读逐锚复核：`_scan_snapshot` L325-353 显式离线配置；`_canonical_payload` L356-372（`dataclasses.replace` 仅替换 `report.repository` 与 `inventory.root` 为标签，findings/collaboration/adjudication/inventory 统计共享只读引用零再派生——docstring+实现亲读）；`_wire_fingerprint` L375-393（sorted-key compact UTF-8 JSON + SHA-256，report.py 冻结指纹规则独立转录）；离线 suite canonical 链 L572-574；`run_b1_source_baseline_suite` L435-447 kw-only 入口） | §7.1 只读复用面；§7.4 转录规范的规则源；**本叶对该文件零修改** | current-behavior（冻结契约，只读） |
| DI-006 | benchmarks/v4/baseline/real_run.py @9a15898 | blob `202d8d2ca818`（亲读：E3 hook `_b1_execute_scanner` L1855-1888，门=`_b1_binding is None or _b1_scan_result is not None: return`（L1876-1877），存储点 L1879 `result = b1_source._scan_snapshot(self._snapshot_dir)` + L1888 `self._b1_scan_result = result`——**当前存原始结果，本叶唯一 real_run 修改对象**；调用点 L1837 cold attempt-0 窗口内 POST 前；E4 报告门 `build_payload` L1620-1630（门 L1629-1630 返回 `self._b1_scan_result`，旧键回落 real-world v2 dict 逐字）；绑定槽 L1572-1573；第十二键常量 L398-407（`_B1_REAL_FIXTURE_KEY="archetype/signal-storm"`/`_B1_REAL_SOURCE_CONTRACT="b1-real-source-binding"`/`_B1_REAL_SOURCE_CONTRACT_VERSION=1`）；描述子组装 L514-530（fixture_key 在 L516）；`_ApprovalContract.artifact_key` L780/`b1_source_binding` L788——**hook 可从 `REAL_RUN_ARTIFACT_FAMILY[artifact_key]["fixture_key"]` 取 canonical 标签，无需扩展绑定块**；物化目录名 `lima-synth-` 前缀 L2173；`__all__` 六符号 L151-158） | §7.1 E3 点名 hunk；标签派生路径 | current-behavior（冻结面，唯一点名例外） |
| DI-007 | benchmarks/v4/baseline/b1_real.py @9a15898 | blob `2761daa1ee1a`（亲读：`__all__` 五符号 L69-75；形状常量 `_COLD_COUNT=1/_WARM_COUNT=4/_ATTEMPT_COUNT=5` L95-97；`_FIXTURE_KEY` L84/`_WORKLOAD` L87/`_SEED` L98；`_RECEIPT_KEYS` 23 键 L116-140+`_RECEIPT_KEY_SET` L141；`_MANIFEST_KEYS` 30 键 L145-176+`_MANIFEST_KEY_SET` L177；`_SCANNER_PHASE` L182-187；`_DECLARATIONS` 五条 L192-198；`B1RealErrorCode` 五码 L227-234+消息 L241-257；`B1RealSuiteResult` L286-330；`_scan_faces` L416+`_projection_matches` L442（L416-477 消费 findings/collaboration 面，canonical 中性）；`_validate_receipt` L478-527（L481 receipt 键集闭集）；入口 `run_b1_real_baseline_suite` 八参数 L554-564；前相执法 L581-635（approval_type/run_name pin、{1,4,5} 形状、scanner config digest、五键绑定块等值）；后相复扫 L681-689（**L683-684 当前对原始复扫直接 `_wire_fingerprint`**）；receipt 组装 L728-756（`scanner_payload_sha256: wire_digest` raw 语义）；验证器 `verify_b1_real_evidence` L860-1140（manifest 闭集等值 L882；`_SCANNER_PHASE`/`_DECLARATIONS` 常量对照 L919-930；**复扫 L981-982 当前 raw**；digest 链 L985-1011；receipts digest L1018-1024；指针绑定 L1028-1111） | §7.1/§7.2 C3 修改面全部锚点 | current-behavior（本叶 C3 主修改对象） |
| DI-008 | benchmarks/v4/baseline/report.py @9a15898 | blob `e30a5f17f84d`（亲读：scanner 源规则 L1338-1344 `wire = {**report.to_dict(), "workspace": evaluator_payload.inventory.to_dict()}` → `_fingerprint(wire)`——**E3 存 canonical ⇒ 报告 sources payload_sha256 自动为 canonical digest，report.py 零改动**；`_SOURCE_KINDS` L126） | §7.1 R1.2 E4 零改动论证 | current-behavior（只读） |
| DI-009 | tests/test_v4_baseline_b1_real.py @9a15898 | blob `6c6054c7a387`（亲读：25 方法亲数；模块镜像 `_B1_REAL_RECEIPT_KEYS` L268-296（23 键 frozenset）/`_B1_REAL_MANIFEST_KEYS` L297-330（30 键）/`_SCANNER_PHASE_FACE` L331/`_B1_REAL_DECLARATIONS` L337；T10 L1170（闭集断言 L1179/L1182、schema_version==1 与 contract pins L1183-1187）；T11 L1213（断言面 L1221-1225：独立复扫 `direct_scan` 后**直接** `_wire_fingerprint`（raw）==报告 sources digest==receipts digest）；T24 L1773-1783 Dockerfile 断言按文件名 `count(...IP-0041...)==1`——不受本叶新 COPY 行影响（亲读）；既有 arrange helper：run_twin/direct_scan/companion_receipts/companion_manifest/report_of/b1_source/b1_real/product_source） | §8 R4 附表 S1-S3 同步对象；N-簇方法载体 | current-behavior（冻结面，C2 唯一演进文件） |
| DI-010 | tests/test_v4_baseline_b1_source.py @9a15898 | blob `a5c587d70555`（20 方法亲数；canonical 独立镜像先例 `scanner_wire_digest` L345-368——标签替换后哈希，测试侧自建 dict 非产品别名） | T11 同步样式先例；§7.4 转录规范的测试镜像先例 | current-behavior（冻结面，零触碰） |
| DI-011 | 四旧冻结测试文件 @9a15898 | real_run `b9f9b4a9d3eb`（112）/b1_source `a5c587d70555`（20）/report `86f584cb4b85`（38）/v5_negatives `6c86e936b85d`（9）——本会话 grep 复核：`_wire_fingerprint` 零出现；`_canonical_payload` 唯一文字出现=b1_source 测试 L349 docstring（canonical 镜像 helper 文档串，非 import/调用/符号引用）；b1_real 闭集零功能引用 | C2 零触碰证明的 grep 依据 | current-behavior（冻结面，零触碰） |
| DI-012 | 旧 sealed 工件 `D:\BaseAIProject\LIMA-real-runs\pr3d-b1-real-2026-10-01\` | 本会话只读亲验（零写入）：manifest 30 键=当前旧集逐键、`source_contract_version=1`、raw digest `a7c20067…`；5 receipt 各 23 键；无 canonical 版本键；`VERIFY_CREDENTIALS_pr3d-b1-real-2026-10-01.py` 依赖工作区清单+读 `.env`（非便携，审计 §4.2——本叶不修改该脚本） | §7.2 V1 族兼容分支的实物依据；§7.6 DERIVED 绑定链对象；C4 只读复验对象 | evidence（只读） |
| DI-013 | IP-0041 Packet + v11' 冻结链 | `docs/LIMA_Implementation_Packet_IP-0041_B1_Real_Entry.md`（结构/DR-PV 风格/授权同步点先例）；v11' Frozen Test Commit `ceea4d60`（本地 git log 亲验）；FINAL_REPORT_ROUND8 背景 | 本 Packet 章节骨架先例；零触碰基线声明 | normative（先例） |
| DI-014 | lima/repository_scanner.py + lima/models.py + lima/workspace.py @9a15898 | `RepositoryScanResult.to_dict` L108-115、`ReviewReport.to_dict`（九键）、`Finding.to_dict`（asdict+severity 值化）、`EvidenceRecord` 十二字段、`WorkspaceInventory.to_dict`（十键，含 files 四键/skipped 排序/coverage round 6/fingerprint 树指纹——路径无关） | §7.4 canonical wire 完整字段集合转录源（只读） | current-behavior（只读） |
| DI-015 | Dockerfile @9a15898 | blob `69ec7cc81a36`（亲读：L72=IP-0041 Packet COPY 行（grep -n 亲验）=本叶恰 +1 行插入锚，新行落 L73；L85 `COPY --chown=lima:lima benchmarks ./benchmarks` 已覆盖 b1_real.py 打包面） | C1 +1 行落位依据 | current-behavior |

事实优先级冲突处理：CA-IP-0042-v1.0 与裁定原文冲突时以 CA 为准并提交 Decision Request；代码事实与 CA 锚不一致时如实登记（OBS）不自行改义。**本会话已逐锚亲核 CA §Frozen Interfaces 1-7 与 R1-R6 全部行号：实质零漂移**（记录性边界差异见 §15 OBS-1）。

## 3. Explicitly Rejected Inputs（被否决决定，转录传递）

| # | 被拒输入 | 拒绝理由 |
| --- | --- | --- |
| 1 | 双存 raw+canonical（hook 同时保存两份或 receipt 同时携带两 digest） | R1.1：双存扩大受审面且 raw 面无语义承载（审计 §2 差异字段实证仅两标签字段）；实际物化身份已由 snapshot_tree_sha256/cold_reset 观察/request_body_sha256 独立钉扎 |
| 2 | 修改 `b1_source.py` 规则（投影/指纹/离线配置） | R1.5/裁定 §二"优先不改已有 b1_source 规则"；本叶只读 import；确需最小例外先具名 DR 列 hunk |
| 3 | 扩展 `b1_source_binding` 绑定块（加 canonical 标签字段） | R1.1：标签经描述子 fixture_key 派生（`REAL_RUN_ARTIFACT_FAMILY[artifact_key]["fixture_key"]`），旧 sealed approval 的绑定块与描述子等值面保持不动 |
| 4 | 新增 B1RealErrorCode / 新增 `_DECLARATIONS` 条目 / `__all__` 变更 / b1_real 入口签名变更 | R2：五码闭集被 v11' 冻结测试以码值消费（12 处引用亲数）；版本键自描述，无必要 |
| 5 | 给报告 sources 加版本标注（report.py 或报告闭集任何 diff） | R2.2：report.py 及报告闭集零触碰（R1.2 E4 零代码改动；canonical 随 payload 自然生效） |
| 6 | 参数化旧入口 `run_real_baseline_suite`（加 canonical 开关参数） | CA Not covered：旧入口签名/order 1-9 冻结；新语义仅在既有 B1 gated hook 内 |
| 7 | 把旧 sealed 目录复验做成依赖机器绝对路径的单测 | R4：冻结测试必须 hermetic/CI 可移植（IP-0041 全部 tempfile 先例）；旧族兼容在单测以合成旧族工件证明，真实 sealed 复验归 C4 执行证据 |
| 8 | 借用第八轮 ALLOWED_ONCE 额度做冻结后机械修正 | 裁定 §二"上一轮 ALLOWED_ONCE 已用尽，本轮不借用其额度"；本 Assignment NOT_ALLOWED（§10 逐字） |
| 9 | 复制完整失败日志 / 覆写历史 sealed 件 / DERIVED 写回原目录 | CA Handoff/Stop 2；审计 §3"历史 raw digest 仍是当时封存的有效内容事实，不应覆写" |
| 10 | 以固定路径、单一 seed、删字段、重排 findings、改生产分析器让 hash 相等 | 裁定 §二明令禁止；发现新真实非确定性→保留最小差异再处置（Stop 7），不预先扩大修改面 |
| 11 | "失败就换算法"式验证器（先试 canonical 失败再回落 raw，或反之） | R2.3/裁定 §二：版本分支必须由可验证元数据（闭集键形+版本字段）先于一切 digest 比较选择 |
| 12 | 把"零产品 import"当作便携性充分条件 | 审计 §4.2/R5.3：旧 VERIFY 脚本零产品 import 但依赖工作区清单+读 .env；便携=显式根参数+无工作区依赖+无凭据读取 |
| 13 | 便携包声称重新验证了真实密钥字节零命中 | 裁定 §四：本轮未加载密钥；历史脱敏检查只能引用记录+hash |
| 14 | 把 B1 real 固定 {1,4,5}+scanner 恰一次表述为 3c/5w 组合能力；AC-03 与 V5-AC-03 混写 | 审计 §4.1/§4.3；R6.3 能力表述三处纠正的承接（防倒退登记） |
| 15 | 在本修复中顺带实现 3c/5w/九类描述子/付费调度器/A1 schema 扩展 | CA Not covered/Stop 10：范围外能力登记依赖表，不借修复牵引 |

## 4. Goal / Non-goals

**Goal**：在 IP-0041 版产品（main=9a15898）上把真实 B1 执行、报告来源、后相复扫与验证器统一到**同一明确版本**的 canonical 规则：E3 hook 单点存 canonical 投影（标签=描述子 fixture_key 派生路径，R1）；E4/report.py 零代码改动（报告仅两标签字段变值，三层证明面）；后相复扫（b1_real L681-689）与验证器复扫（L981-982）同规则 canonical 化；显式契约版本 `_CANONICAL_SOURCE_CONTRACT_VERSION="b1-canonical-source-v1"` 入 manifest/receipts 各一键（31/24 键 V2 族）；V1 旧族（30/23 键逐字保留）由键形+既有版本字段选择按旧 raw 规则验证，混合/未知/错配/篡改/身份漂移 fail closed（五码闭集映射，R2）；测试契约同步（恰 3 同步点）+新增 ≤12 方法冻结 v12（R4）；C4 区分力证明（双根/跨进程/双 seed/独立重算/四类负例/旧 sealed 只读复验）与便携核验包+DERIVED 件（仓外新目录，R5）；旧面 179+25 零回退（R6）。

**Non-goals**：见 §1 Not-covered（CA 原文）。勘误与矩阵（Scope 7）为文档交付另行处理；C3 产品实现以 CA-IP-0042-v1.1 正式指派为准（本 Assignment 只预裁定边界，§5.3）；C4 执行以后续授权为准（本 Packet 冻结其规格）。

## 5. 文件边界与提交链（CA §Workspace and Ownership；C1 恰 1 Add+1 Modify；C2 恰 1 文件原地演进；C3 预裁定 b1_real.py+real_run.py；零 Delete；单 PR `codex/ip-0042-canonical-wiring` → main）

### 5.1 Files to Add

| 文件 | Owner/阶段 | 说明 |
| --- | --- | --- |
| `docs/LIMA_Implementation_Packet_IP-0042_B1_Canonical_Wiring.md` | P&V（C1，本文件） | 本 Packet；承载 CA 全部验收语义+R1-R6 裁定+canonical 统一面/版本设计/标签语义/独立转录规范/测试契约同步表/C4 证明计划/便携包与 DERIVED 规格/回归面/Stop Conditions |

### 5.2 Files Allowed to Modify

| 文件 | Owner/阶段 | 边界 |
| --- | --- | --- |
| `Dockerfile` | P&V（C1，与 Packet 同一提交） | **恰 +1 行**：`COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0042_B1_Canonical_Wiring.md ./docs/`（插 L72 IP-0041 Packet COPY 行后，新行落 L73——本会话 grep -n 亲验）；既有行零改动（IP-0039/0040/0041 每 Packet 恰一行先例；T24 断言按文件名计数==1 不受新行影响，本会话亲读 T24 L1773-1783 复核）。基线 blob `69ec7cc81a36` |
| `tests/test_v4_baseline_b1_real.py` | P&V（C2，原地演进冻结 v12） | **仅限三类 hunk**：① 模块镜像常量 `_B1_REAL_RECEIPT_KEYS`（L268-296，23→24 键）与 `_B1_REAL_MANIFEST_KEYS`（L297-330，30→31 键）各 +`canonical_source_contract_version`（§8 S1）；② 方法 T10（L1170）与 T11（L1213）按 §8 S2/S3 同步旧→新语义；③ 新增 ≤12 方法（§8 N-簇定稿 11 方法）。`grep -c "    def test_"` 口径新总数 ≤37（定稿 36）。基线 blob `6c6054c7a387` |
| `benchmarks/v4/baseline/b1_real.py` | Implementation（C3，预裁定；正式指派以 CA-IP-0042-v1.1 为准） | canonical 化后相复扫（L681-689）、验证器复扫与版本分支（L860-1140 区）、receipt/manifest 组装（+版本键）、canonical 版本常量与 V1 旧族键集常量（§7.1/§7.2）。五码闭集/`_DECLARATIONS`/`__all__`/入口签名/schema_version=1/前相执法 L581-635/`_projection_matches`/`_scan_faces` 全部不变 |
| `benchmarks/v4/baseline/real_run.py` | Implementation（C3，预裁定） | **仅 E3 hook 体一处 hunk**（L1855-1888 内，存储点 L1879-1888 改存 canonical 投影，§7.1.1）；E4 build_payload 门（L1620-1630）**零代码改动**；公共签名/order 1-9/旧十一键描述子/旧审批/请求契约/预算门零触碰。基线 blob `202d8d2ca818` |

### 5.3 Read-only Reference Files（只读消费）

`benchmarks/v4/baseline/` 其余全部模块与各级 `__init__.py`（**b1_source.py/report.py/budget.py/run.py/orchestrate.py/fixtures.py/collect.py/expert_timing.py/offline_flow.py——绝对只读**，C3 预期零触碰）；`lima/**`（绝对只读）；`tests/` 除 §5.2 授权点外一切既有文件与方法（四旧文件 112+20+38+9 绝对零触碰；T1-T9/T12-T25 共 23 方法零触碰）；`D:\BaseAIProject\LIMA-real-runs\**` 一切既有文件（只读；DERIVED 与便携包只写新目录）；IP-0024..0041 Packet、批准工件、裁定/审计/决策包记录；`.pv_tmp/` 各记录。

### 5.4 Files Forbidden（diff 必空；Done Commands 逐 blob 守护）

`lima/**`（绝对）；`benchmarks/v4/baseline/` 除 b1_real.py 与 real_run.py（恰 E3 一 hunk）外一切文件；`tests/` 除 §5.2 三类授权 hunk 外一切（含四旧文件任何 hunk、23 零触碰方法任何 hunk、任何负例删除或弱化）；旧真实批准工件与历史 run 产物（`D:\BaseAIProject\LIMA-real-runs\**` 及一切封存树零写入）；`docs/` 其余全部；`evaluation_data/**`（除只读消费）；`scripts/**`（含旧 VERIFY_CREDENTIALS 脚本——非便携定性保留不改）；`pyproject.toml`/`.github/**`/前端；`.pv_tmp/**` 不提交（RED 日志仅存主仓库 `.pv_tmp/RED_IP-0042_2026-10-01/`）。

### 5.5 提交链拓扑（CA §Handoff；冻结）

C1 = 本 Packet + Dockerfile 恰 1 行（1 Add + 1 Modify，同一提交，提交信息逐字 `[IP-0042][PV] Add Implementation Packet IP-0042 (B1 canonical source wiring) and Dockerfile copy line`）→ 主会话 PR（`Related to #254`，无自动关闭关键字；不关联 #57/#251 状态）合并，**C2 基线=main 上 C1 合并后完整 40 位 SHA（主会话记录；worktree rebase/重置到该 SHA 后开工）** → C2 = tests/test_v4_baseline_b1_real.py 原地演进（恰 1 文件 Modify；**Frozen Test Commit**；提交信息逐字 `[IP-0042][PV] Freeze acceptance tests v12 (RED)`；RED 证据先于冻结落盘并独立日志归档主仓库 `.pv_tmp/RED_IP-0042_2026-10-01/`）→ C3 = b1_real.py + real_run.py（恰 E3 一 hunk；提交前缀 `[IP-0042][IMPL]`；必须以 C2 为祖先；正式指派以 CA-IP-0042-v1.1 为准）→ C4（P&V 独立验证 + 证明 + 便携包/DERIVED；如触发 DR/修复提交须引用编号）。单 PR；不 push（合并/推送/评论由主会话按 Maintainer 授权执行，P&V/IMPL 零远端写）。

### 5.6 与其他活动 IP 的冲突分析

无并行活动 IP 占用本切片路径（IP-0042 编号由 CA 分配）。本叶触碰 real_run.py（恰 E3 一 hunk）、b1_real.py（canonical 接线）与 tests/test_v4_baseline_b1_real.py（恰 3 同步点+新方法）——均为 CA 显式授权且逐 hunk 登记；b1_source.py/report.py/fixtures.py/budget.py 等其余共享核心零触碰。

## 6. 依赖、网络、文件系统与权限边界

- **依赖**：零新增第三方依赖；C3 产品 import 清单零新增根（canonical 复用=只读 import 既有 `b1_source._canonical_payload`/`_wire_fingerprint`，real_run.py 内 lazy import 面不变）；C2 测试零新增第三方 import（unittest/tempfile/pathlib/json/hashlib/subprocess 等 stdlib+冻结上游——跨进程方法用 `subprocess` 起 `python -c`，不引入新依赖根）；便携核验脚本（C4）自含 stdlib-only 转录规则，零产品 import 亦零工作区依赖。
- **网络**：C1-C4 与 CI 全程零网络/零下载/零付费/零凭据（Stop 1 绝对停）；模型层验证只用注入式 fake transport（沿 IP-0041 孪生纪律）；跨进程证明用本地子进程，无网络。
- **文件系统**：测试写 tempdir（hermetic/CI 可移植，IP-0041 全部 tempfile 先例）；**不依赖 `D:\BaseAIProject\LIMA-real-runs\` 机器绝对路径**（旧族兼容以合成旧族工件单测证明；真实 sealed 复验归 C4 只读执行记录）；sealed 目录零写入；DERIVED/便携包只写 `D:\BaseAIProject\LIMA-real-runs\` 下新目录（§7.6.2 定稿名）。
- **数据库/容器/远端写**：无数据库；容器面仅 Dockerfile +1 COPY 行（本 Packet 文档）；零远端写（不 push、不开 PR、不关 Issue、不改 Ledger 远端状态）。
- **凭据**：C1-C4 零凭据注入；便携包不读 `.env`、不加载任何当前/历史模型密钥（§7.6.2）；本轮未加载任何密钥，不得声称重验任何真实密钥的字节零命中。
- **clock/seed**：digest/身份/族别面零时钟依赖；`PYTHONHASHSEED` 变化不得影响 canonical digest（跨进程双 seed 证明即检验此边界）；固定路径或设 seed 不得成为掩盖绝对路径差异的修复（Stop 7）。

## 7. 实现契约细化（Packet 定稿；R1-R3 落位 + A2 独立转录规范）

### 7.1 canonical 统一面（R1）：E3 单点存储 canonical 投影；E4 零改动；后相/验证器同规则；b1_source 零修改

#### 7.1.1 E3 hook 改存 canonical 投影（单存，不双存；real_run.py 演进例外清单=恰此一 hunk）

- **修改点（唯一）**：`_b1_execute_scanner`（real_run.py L1855-1888）存储段——现行 L1879 `result = b1_source._scan_snapshot(self._snapshot_dir)` … L1888 `self._b1_scan_result = result` 改为对扫描结果先投影再存储：

```python
label = REAL_RUN_ARTIFACT_FAMILY[self._approval.artifact_key]["fixture_key"]
payload = b1_source._canonical_payload(result, label)
self._b1_scan_result = payload
```

- **标签派生路径（Packet 定稿，DR-IP-0042-PV-5）**：`label = REAL_RUN_ARTIFACT_FAMILY[self._approval.artifact_key]["fixture_key"]`（module 内直引目录常量；`_ApprovalContract.artifact_key` L780 可达，描述子 L516 已载 `fixture_key="archetype/signal-storm"`）——**与 b1_source 离线 suite 标签规则同源同值**（L572 `_canonical_payload(scan, fixture_key)`）。**不扩展 `b1_source_binding` 绑定块**（旧 sealed approval 的绑定块与描述子等值面保持不动）。
- **门条件不变**：`if self._b1_binding is None or self._b1_scan_result is not None: return`（L1876-1877 逐字保留）；仅 cold attempt-0 进入（调用点 L1837 窗口内、POST 前）；scanner 异常传播/截止检查纪律逐字保留（扫描失败在 POST 前 ⇒ 零 POST）。
- **默认关闭证明**：旧十一键绑定块为 `None` 永不进分支（T20 单测+C4 执行双证）；模块级 import 清单零变化（lazy import 只在门内触发）。
- **不双存 raw+canonical**（§3 拒绝 #1）：双根原始 wire 差异仅 `$.repository`/`$.workspace.root` 两字段（审计 §2 递归全 wire 比较实证），raw 绝对路径无证据承载任何语义；实际物化身份已由 `snapshot_tree_sha256`/`cold_reset` 观察/`request_body_sha256` 独立钉扎（T8 三方等值锚既有），报告无需保留绝对路径。
- **real_run.py 演进例外清单=恰 E3 一 hunk**（逐 hunk 登记：符号 `_b1_execute_scanner`/门条件不变/默认关闭证明如上）；E4（L1620-1630）/公共签名/order 1-9/旧十一键描述子行为/预算门零触碰。**表外任何 hunk=Stop 5。**

#### 7.1.2 E4 build_payload 门零代码改动与"报告语义不变"三层证明面（R1.2）

E4 门（L1629-1630 返回 `self._b1_scan_result`）**零代码改动**：其返回存储槽随存储值自然变 canonical——报告走 scanner 类型路径时 `payload_sha256` 由 report.py L1338-1344 从 payload 计算，自动为 canonical digest；报告仅两标签字段变值。**"报告语义不变"证明面（三层，Packet 冻结）**：

1. **投影面证明**：`_canonical_payload` 仅 `dataclasses.replace` 两标签字段（`report.repository`/`inventory.root`），findings/collaboration/adjudication/inventory 统计共享只读引用、零再派生零丢弃（b1_source L356-372 docstring+实现亲读，DI-005）。
2. **测试面独立反证**：T9 faces 对照（counts/compression_chain/coverage/unavailable 纪律）与 canonical 无关，冻结前后均绿——独立反证报告投影面不被本叶改动。
3. **C4 实测证明**：双根报告除两标签外逐值一致+差异字段清单与审计一致（仅非语义路径面 `$.repository`/`$.workspace.root`；记录实际差异字段，不只抄预期 hash——裁定 §三.3）。

旧键（及扫描缺席的失败终局）报告回落冻结 real-world v2 dict **逐字**（字节等同；T20 锚）。

#### 7.1.3 后相复扫 canonical 化（b1_real.py L681-689；R1.3）

现行 L683-684 `scan = b1_source._scan_snapshot(snapshot_dir)` + `wire_digest = b1_source._wire_fingerprint(scan)`（对原始复扫直接指纹）改为：

```python
scan = b1_source._scan_snapshot(snapshot_dir)
payload = b1_source._canonical_payload(scan, _FIXTURE_KEY)
wire_digest = b1_source._wire_fingerprint(payload)
```

receipt `scanner_payload_sha256` 与报告 sources digest 随之为 canonical 值。`_projection_matches`/`_scan_faces`（L416-477）只消费 findings/collaboration 面，canonical 中性，**零改动**。

#### 7.1.4 验证器复扫 canonical 化+按工件族分支（b1_real.py L981-982 与 L860-1140 区；R1.4）

验证器复扫（L981-982）同规则 canonical 化，**且按工件族分支**（R2，§7.2.3 分支次序）：新族工件按 canonical 规则+版本核验；旧族工件按旧 raw 规则核验；分支由可验证元数据（闭集键形+版本字段）**先于一切 digest 比较**选择，禁止"失败就换算法"。

#### 7.1.5 b1_source 零修改（R1.5）

离线 suite 全链已 canonical（L572-574 亲验）；`_canonical_payload`/`_wire_fingerprint` 只读复用；B1 离线 suite 自身的 canonical 使用即对照面（同 fixture/配置 ⇒ 离线与真实两入口 canonical wire digest 相等——N-A4 跨入口等值锚）。

### 7.2 契约/算法版本设计与旧新兼容分支（R2）

#### 7.2.1 版本常量（Packet 定稿，DR-IP-0042-PV-1）

b1_real.py 新增私有常量：

```python
_CANONICAL_SOURCE_CONTRACT_VERSION: typing.Final[str] = "b1-canonical-source-v1"
```

（采纳 CA 建议命名与值；字符串承载族+序号；**保持私有——`__all__` 五符号不变**；不入 `_DECLARATIONS`。）**第十二描述子的 `source_contract="b1-real-source-binding"`/`source_contract_version=1`（绑定契约对）不动**：它钉扎的是绑定块合同而非 digest 规则，改动会无谓牵动 M/T6 描述子 pin（测试 L1005-1011 亲读）、绑定块等值面与旧 sealed approval 对照。

#### 7.2.2 入工件字段与键集族常量（Packet 定稿，DR-IP-0042-PV-2）

- companion manifest +`canonical_source_contract_version`（**30→31 键**）；每张 receipt +同键（**23→24 键**）——receipt 自描述，单件可判族。版本键追加于各元组尾部，其余键序不动（S1 同步面）。
- 生产面常量 `_RECEIPT_KEYS`/`_MANIFEST_KEYS` 原地演进为 V2 族（24/31 键；`_RECEIPT_KEY_SET`/`_MANIFEST_KEY_SET` 随之）；V1 旧族以新私有常量 `_LEGACY_RECEIPT_KEYS`/`_LEGACY_MANIFEST_KEYS` **逐字保留**（=当前 23/30 元组含序；派生 `_LEGACY_RECEIPT_KEY_SET`/`_LEGACY_MANIFEST_KEY_SET` frozenset 供验证器族分支）。
- **报告 sources 不加版本标注**（report.py 及报告闭集零触碰）；`B1RealSuiteResult` 字段集不变（Packet 裁定不新增 additive 版本字段——版本在 companion 工件自描述，DR-IP-0042-PV-6）；便携包与 DERIVED 件携带该版本值（§7.6）；`schema_version` 保持 1；`_DECLARATIONS` 不新增。

#### 7.2.3 验证器分支次序（受审兼容策略；Packet 定稿，DR-IP-0042-PV-7）

`verify_b1_real_evidence` 读 manifest 后**先定族、后核验**，分支先于一切 digest 比较（先于现行 L882 闭集等值的旧位置）：

1. 键集==V1（`set(manifest)==_LEGACY_MANIFEST_KEY_SET`）**且** `source_contract_version==1` ⇒ **旧族，按旧 raw 规则核验**（复扫不投影直接 `_wire_fingerprint`；不要求 canonical 版本键——"V1 工件缺新版本键"是族标记而非版本缺失失败）。第八轮 sealed 目录 `pr3d-b1-real-2026-10-01` 即此族（manifest 30 键/版本 1/raw digest `a7c20067…` Coordinator 与本 P&V 会话只读亲验）。
2. 键集==V2（`set(manifest)==_MANIFEST_KEY_SET`，31 键）⇒ **新族**：先核 `canonical_source_contract_version`（manifest 与每张 receipt 逐件一致且==当前常量；receipt 键集==V2 24 键），再按 canonical 规则核 digest 链（复扫先 `_canonical_payload(scan, _FIXTURE_KEY)` 投影再 `_wire_fingerprint`）。
3. **其余一切键形（混合/部分/未知）⇒ fail closed**（`B1_REAL_RECEIPT_INVALID`）。

新族工件的版本缺失（键集要求下不可能缺）/错配/篡改/身份漂移全部 fail closed；运行内后相（L681-689 起）产出的恒为 V2 新工件，`_validate_receipt`（L478-527）按生产面 V2 键集执法不变。

#### 7.2.4 违例→五码映射表（R2.4；不新增码，Packet 冻结成表）

| 违例 | 错误码（五码闭集） |
| --- | --- |
| manifest 键集非 V1 非 V2（混合/部分/未知键形） | `B1_REAL_RECEIPT_INVALID` |
| receipt 键集与所选族不符（含 V2 缺版本键、混合键集） | `B1_REAL_RECEIPT_INVALID` |
| V2 工件 `canonical_source_contract_version` 缺失/未知值/非法值（manifest 或任一 receipt） | `B1_REAL_RECEIPT_INVALID` |
| V2 canonical digest 链不符（receipt/manifest/报告 sources vs 独立 canonical 重算） | `B1_REAL_SCANNER_DIGEST_MISMATCH` |
| V1 族按旧 raw 规则 digest 链不符（raw 复扫重算 vs 工件值） | `B1_REAL_SCANNER_DIGEST_MISMATCH` |
| receipts↔manifest 版本不一致（跨面身份漂移） | `B1_REAL_BINDING_MISMATCH` |
| 标签/身份字段不符（fixture_key/workload/analyzer 身份漂移） | `B1_REAL_BINDING_MISMATCH` |

对应裁定 §二"版本缺失、错配、篡改、身份漂移 fail closed"四类。五码族（L227-234+消息 L241-257）逐字不变。

### 7.3 标签语义与 digest 用途分界表（R3）

1. **标签来源（Packet 定稿=DR-IP-0042-PV-5）**：稳定标签=第十二描述子 `fixture_key`（`"archetype/signal-storm"`）——即 fixture/source 身份，与 b1_source 离线 suite 的标签规则**同源同值**（L572）。**标签禁取清单**：run_name、执行日期/时间、绝对根目录、临时目录、`lima-synth-` 前缀物化路径（real_run L2173 物化目录名含临时路径成分，明确排除）。标签经描述子派生不经绑定块（§7.1.1），前相执法（L581-635）零改动。
2. **RunSpec/执行身份钉扎不变**：`run_spec_digest`/`approval_sha256`/`request_body_sha256`/`run_result_sha256`/`ledger_sha256`/`snapshot_tree_sha256`/analyzer_fingerprint 各自独立钉扎，不因 canonical 化合并或弱化。
3. **digest 用途分界表（R3.3 四行表逐字冻结）**：

   | 字段 | 用途 | 跨目录期望 |
   | --- | --- | --- |
   | canonical source digest（receipts/manifest `scanner_payload_sha256`、报告 sources `payload_sha256`） | 来源身份：内容+分析器配置+seed 的路径无关投影 | 同 fixture/config/seed ⇒ **相等**（本叶目标） |
   | `snapshot_tree_sha256`（+cold_reset 观察） | 实际物化树绑定（执行上下文身份） | 同 fixture 字节 ⇒ 相等；绑实际树，篡改检测 |
   | `run_spec_digest`/`approval_sha256`/`request_body_sha256`/`run_result_sha256`/`ledger_sha256` | 当次执行/上下文身份样本 | **不要求相等**（逐 run 独立）；漂移=绑定失败 |
   | wall/usage/时间戳 | 独立 samples | 不要求相等（裁定 §二"不要求不同运行的 wall/usage/时间戳或整批文件字节完全相同"） |

4. **标签替换不碰撞**：不同标签对同一内容 ⇒ 不同 canonical digest；同标签不同内容 ⇒ 不同 digest（N-C2 负例，裁定 §三.4"标签替换不得使不同来源碰撞"）。

### 7.4 canonical wire digest 规则独立转录规范（A2；供测试镜像、便携包、独立核验器三方独立重算——**不能只让产品函数与其别名互证**，裁定 §三.3）

**规范名**：`b1-canonical-source-v1`（与 §7.2.1 版本常量同值）。**输入**：一次 `b1_source._scan_snapshot` 扫描结果 `RepositoryScanResult(report, inventory)`（或等价的报告+工作区盘点对）与稳定标签 `label`（=fixture_key，如 `"archetype/signal-storm"`）。

**第一步（两标签替换）**：`report.repository := label`；`inventory.root := label`。仅此两字段；findings/collaboration/adjudication/inventory 统计与文件清单共享只读引用，不重派生、不丢弃、不重排。

**第二步（wire 对象构造）**：`wire = {**report.to_dict(), "workspace": inventory.to_dict()}`。完整字段集合（@9a15898 亲读 DI-014 冻结）：

- report 顶层九键：`repository`、`pull_request`（int 或 null）、`summary`、`risk`、`findings`（列表）、`files_reviewed`（列表）、`reviewer`、`collaboration`（dict）、`adjudication`（dict）。
- `findings[]` 每项 24 键（Finding.to_dict = asdict + severity 枚举值化）：`rule_id`、`severity`（枚举值串）、`title`、`explanation`、`path`（相对路径）、`line`、`evidence`、`fix`、`test`、`confidence`、`cwe`、`source`、`evidence_kind`、`fingerprint`、`verification_state`、`evidence_records`（列表）、`language`、`symbol`、`analysis_mode`、`automatic_repair`、`candidate_id`、`agent_role`、`trigger_path`（列表）。
- `findings[].evidence_records[]` 每项 12 键（EvidenceRecord asdict）：`source`、`kind`、`path`、`line`、`snippet`、`rule_id`、`cwe`、`confidence`、`language`、`symbol`、`analysis_mode`、`tool_run_id`。
- `workspace` 十键（WorkspaceInventory.to_dict）：`root`（已替换为 label）、`files`（列表，每项四键 `path`/`size`/`sha256`/`line_count`，path 为相对路径）、`skipped`（按键排序的 dict）、`total_bytes`、`discovered_files`、`discovered_bytes`、`file_coverage`（round(x,6) 浮点）、`byte_coverage`（round(x,6) 浮点）、`truncated`、`fingerprint`（工作区树指纹：对 files 按 path 排序逐件以 `path\0size\0sha256\n` 字节串喂 SHA-256——**路径无关，不含 root**）。

**第三步（编码）**：`json.dumps(wire, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")`（sorted-key compact UTF-8 JSON，stdlib 默认数值串行化）。

**第四步（摘要）**：SHA-256 hexdigest（64 小写十六进制）。

**路径无关性依据**：findings[].path、workspace.files[].path、workspace.fingerprint 均为相对面；唯一携带物化绝对路径的字段即被替换的 `$.repository`/`$.workspace.root` 两处（审计 §2 递归比较实证 differing_fields 恰为此两字段）。**独立实现要求**：测试镜像（N-A3）、便携核验脚本（C4）、独立核验器须按本规范自行构造 wire 并哈希（沿 `tests/test_v4_baseline_b1_source.py::scanner_wire_digest` L345-368 镜像样式——测试侧自建 dict，非 import 产品函数）；报告 sources digest 同规则（report.py L1338-1344 从 payload 计算即此规范的产品面）。

### 7.5 C4 证明计划（R5.1/裁定 §三；P&V C-final-C4 阶段在独立 worktree 执行，本 Assignment 只预排归属不授权执行）

1. **双根等值**：两个不同空根目录，用正式 B1 入口（`run_b1_real_baseline_suite` + 孪生批准工件）及精确 offline/fake 工件（**fake transport，零真实 transport/key**）运行：相同 fixture/source/config/toolchain/seed 的 canonical 来源字节与 identity 相等（§7.4 规范独立重算证实）；当次 samples（wall/usage）与 context（run_spec/ledger digest）独立保留；raw wire 断言不等（证明差异真实存在且被规范化消除，非双空根巧合）。
2. **跨进程+双 PYTHONHASHSEED**：至少另起进程复核，并使用两个不同 `PYTHONHASHSEED`（审计 §2"新回归仍应覆盖跨进程/不同 hash seed"）；固定路径或设 seed 不得成为掩盖绝对路径差异的修复；若发现新的真实非确定性 ⇒ 保留最小差异再处置（Stop 7），不预先扩大修改面。
3. **独立重算**：按 §7.4 冻结规范独立实现 canonical wire/hash（受审规范输入/完整字段集/编码规则成文；非产品函数与其别名互证）；记录实际差异字段清单（预期仅 `$.repository`/`$.workspace.root`，与审计一致），不只抄一个预期 hash。
4. **四类负例**：语义内容变更；配置/工具指纹变更；旧新版字段错配；snapshot/source/receipt 篡改——各证 fail closed（码映射 §7.2.4）或 identity 变化；标签替换不碰撞（同内容换标签 ⇒ digest 变；同标签换内容 ⇒ digest 变）。
5. **旧 sealed 目录只读复验**：`pr3d-b1-real-2026-10-01\` 按旧 raw 规则验证通过（R2 旧族分支的实物证据；**只读，零写入**）；旧入口无新 hook 副作用（缺省旧十一键走 real-world payload/无 companion——T20 单测+C4 执行双证）。
6. **区分不变**：24/legacy_projection/unavailable/无真人事件等事实保持；不把 5 attempts 求和成 120 findings；空 finding 的 measured 0 与扫描失败继续区分。
7. **回归与记录纪律**：targeted+全量回归与改动相称；记录先落盘、再哈希、再引用（裁定 §三.5）。

**hermetic 纪律（R4 逐字承接）**：冻结测试必须 hermetic/CI 可移植（不依赖 `D:\BaseAIProject\LIMA-real-runs\` 机器绝对路径；IP-0041 全部 tempfile 先例）——旧族兼容在单测中以**合成旧族工件**证明，真实 sealed 目录复验在 C4 以只读执行记录证明。

### 7.6 便携核验包与 DERIVED 规格（R5.2-R5.4；P&V C4 产出、仓外新目录、主会话 durable 保存）

#### 7.6.1 新目录名（Packet 定稿，DR-IP-0042-PV-3）

- 便携核验包：`D:\BaseAIProject\LIMA-real-runs\b1-canonical-portable-2026-10-01\`（采纳 CA R5.2 建议值）。
- 第八轮目录 DERIVED 件：`D:\BaseAIProject\LIMA-real-runs\pr3d-b1-real-2026-10-01-derived\`（采纳 CA 建议值）。
- **零覆写任何既有文件**；两目录互不为旧目录；主会话负责 durable 保存（包在仓外已满足"不随 managed worktree 删除而消失"；副本/清单校验后才清理 worktree；未跟踪/ignored 资料先保存——裁定 §四）。PR 面内只携带仓内文档引用（包位置+清单 hash），不复制包体入仓。

#### 7.6.2 便携包技术要求（R5.3 逐条冻结）

1. 携带相对路径清单+规范版本（§7.2.1 常量值 `b1-canonical-source-v1`）+执行/派生来源说明+核验脚本。
2. 支持显式指定只读封存根目录参数（sealing root 以参数传入，非硬编码）。
3. 无工作区绝对路径依赖（脱离 `D:\BaseAIProject\LIMA` 工作区可运行）。
4. 不读 `.env`、不加载任何当前/历史模型密钥、不请求模型（零网络）。
5. 重算文件清单并检测缺失/额外文件（对照包内清单逐件 SHA-256）。
6. **直接重算 snapshot tree**（按冻结树指纹规则重算 `snapshot_tree_sha256`，非仅比较三个宣称相同的字符串）。
7. 对规范化 scanner 来源（§7.4 规范独立重算）/receipt/报告/ledger 的核验**覆盖与未覆盖范围分别说明**。
8. 结构性脱敏检查与当次真实密钥字节检查**分开**（本轮未加载密钥，不得声称重新验证了任何真实密钥的字节零命中；历史检查只以记录+hash 引用）。
9. 不复制模型 Secret/原始 Authorization、不扩大公开源码暴露。
10. 不把核验工具扩成新产品框架（一次性核验脚本，不入 `lima/**`/`benchmarks/**`）。
11. **零产品 import 不作为便携性充分条件**（审计 §4.2 教训——便携=显式根参数+无工作区依赖+无凭据读取三条件齐备；包内脚本自含 §7.4/树指纹/内容摘要的转录实现）。

#### 7.6.3 DERIVED 件绑定链（R5.4 逐字冻结）

为第八轮目录生成 canonical 补充证明于新目录（§7.6.1），绑定链=**原 47 件清单（`run_file_hashes.txt` 既有）+原文件 SHA-256+原执行 commit `9a15898333b23b2b1ad8edf7dbf173d39fa3336c`+当前投影版本（`b1-canonical-source-v1`）**；不改写旧 receipt/manifest/source digest/授权摘要；**不称派生件为当时已执行的新入口**（标注 DERIVED+生成时间+规则版本）。

### 7.7 回归面锚（R6）

1. **冻结回归面**：`test_v4_baseline_real_run` 112 / `test_v4_baseline_b1_source` 20 / `test_v4_baseline_report` 38 / `test_v4_baseline_v5_negatives` 9 **零回退、零 hunk**；`test_v4_baseline_b1_real` 25 方法中 23 零触碰（冻结前后均绿）、T10/T11 同步后于 C3 转绿（RED→GREEN 因产品实现，非测试弱化）；新方法（定稿 11）C3 后全绿；全量 discover 保持 **2773 OK/skipped=24** 基线口径（新方法计入后相应增加 OK 数，skipped 集零未登记变化）；compileall+ruff 双态通过。
2. **C4 回归面**（预排）：上述全部 + 干净 main post-merge 复跑（记录先落盘、再哈希、再引用）；旧 sealed 目录只读复验按旧规则通过（R2 旧族分支实物证据）；缺省旧入口无新 hook 副作用（T20 单测+C4 执行双证）；v11' 不受影响方法零触碰由 C2 diff 证明（`git diff --stat` 恰 1 文件）。
3. **能力表述三处纠正的承接**（审计 §4，非本叶测试面但登记防倒退）：B1 real 固定 {1,4,5} 且 scanner 恰一次（L95-97/T8 锚）不被表述为 3c/5w 组合能力；便携包与"零产品 import"分开表述（§7.6.2 第 11 条）；AC-03 与 V5-AC-03 前缀分清（属 Scope 7 矩阵交付面）。

## 8. 测试契约同步表（R4；冻结版本 **v12**；单文件原地演进；本节含 R4 附表逐字转录）

### 8.1 同步点附表（C2 允许的全部既有测试修改；= CA R4 附表 **逐字转录**；旧值→新值逐项）

| # | 位置 | 对象 | 旧语义 → 新语义 | 独立反例 |
| --- | --- | --- | --- | --- |
| S1 | L268-296 / L297-330 模块镜像 | `_B1_REAL_RECEIPT_KEYS`（23 键）→ 24 键；`_B1_REAL_MANIFEST_KEYS`（30 键）→ 31 键 | 各 +`canonical_source_contract_version`；其余键序不动 | 混合/缺版本键键集 ⇒ `B1_REAL_RECEIPT_INVALID` |
| S2 | T10 `test_b1_real_receipt_key_set_and_companion_layout`（L1170） | 闭集=23/30 键；schema_version==1；contract pins（L1183-1187） | 闭集随镜像=24/31（版本键在集）；schema_version/contract pins **断言不动** | 旧族合成工件在验证器走旧规则分支（族别行为，非本方法断言面）；缺键 ⇒ INVALID（T12(a) 既有形态沿用） |
| S3 | T11 `test_b1_real_digest_cross_chain`（L1213，断言面 L1221-1225） | 独立复扫 `_scan_snapshot` 后**直接** `_wire_fingerprint`（raw）==报告 sources digest==receipts `scanner_payload_sha256` | 独立复扫后先 `_canonical_payload(scan, "archetype/signal-storm")` 投影再 `_wire_fingerprint`（沿 `test_v4_baseline_b1_source.py::scanner_wire_digest` L345-368 镜像样式）==报告/manifest/receipts digest | **raw 投影指纹 ≠ canonical 指纹**（断言两者不等——证明投影实际生效，防"假 canonical"）；请求体/审批/账本 digest 断言不动 |

### 8.2 零触碰清单（R4 逐字转录）

**零触碰清单**：T1-T9、T12-T25 共 **23 方法**任何 hunk 禁止（T12 篡改四面 (a)-(e) 语义在 24 键闭集下自动保持；T9 faces canonical 中性；T20 旧键不启用新 hook 不变；T22 五码族/`__all__` 锚不变；T24 IP-0041 文件名计数==1 不受 Dockerfile 新行影响）。**四旧文件（real_run 112/b1_source 20/report 38/v5_negatives 9）零触碰**（Coordinator grep 亲验无 `_wire_fingerprint`/`_canonical_payload`/b1_real 闭集引用；canonical 修复不触旧键路径——旧键绑定块 None 永不进 B1 分支）。

### 8.3 新增方法定稿拆分（N-簇；预算 ≤12，定稿 **11 方法**；新总数 25+11=36 ≤37）

**CA 建议簇（R4 逐字）**：N-A canonical 等值（4）：双根等值（两空根+正式入口+fake transport：canonical 字节/digest/来源 identity 相等；raw wire 断言不等；samples/context 独立保留）；跨进程+两不同 `PYTHONHASHSEED`（子进程驱动，检验修复边界——审计 §2"新回归仍应覆盖跨进程/不同 hash seed"）；独立转录交叉核对（测试侧规则镜像非产品自证）；跨入口等值锚（b1_source 离线 suite 的 signal-storm scan digest == 真实入口 canonical digest——同 fixture/同 `_scan_snapshot` 配置 ⇒ 同 canonical wire）。N-B 版本族（3）：旧族合成工件按旧 raw 规则验证通过（含 raw digest 路径）；新族版本错配/未知值 fail closed；receipts↔manifest 版本不一致/混合键集 fail closed（码映射按 R2.4）。N-C 篡改与标签（3）：canonical digest 篡改 fail closed；标签替换不碰撞（同内容换标签 ⇒ digest 变；同标签换内容 ⇒ digest 变）；报告 payload 无绝对路径（`repository`==标签）+旧键 payload 仍 real-world v2。N-D 锚（1-2）：E3 单点存储/扫描恰一次面（`scanner_executions==1` 既有语义上叠加 canonical 面）；b1_source canonical 规则零改动锚（离线 suite digest 与描述子 `scanner_config_sha256` 等值面不变）。

**Packet 定稿方法表（DR-IP-0042-PV-4；断言面冻结；负例断言必须钉扎具体错误码与结构 field path——防"恰巧 fail closed"假绿）**：

| 方法（定稿名） | 簇 | 覆盖 | 断言面（冻结） | 冻结态预期（产品=main 9a15898 现状，raw 三处接线仍在） |
| --- | --- | --- | --- | --- |
| `test_b1_real_canonical_two_root_equivalence`（N-A1） | A | FR-01/AC-1 | 两空根目录经正式入口+fake transport 各跑一次：两 run 的 canonical 来源 digest（工件面）相等、来源 identity（fixture/analyzer/config）相等；**raw wire 指纹断言不等**（差异真实存在）；samples（wall/usage）与 context（run_spec/ledger digest）独立保留断言 | **RED**（产品 digest 为 raw：两根 raw digest 不等 ⇒ 等值断言失败；归因=canonical 化缺席） |
| `test_b1_real_canonical_cross_process_and_hash_seeds`（N-A2） | A | FR-01/AC-1 | 子进程（`subprocess` 起 python）在两个不同 `PYTHONHASHSEED` 下各跑双根等值面；canonical digest 跨进程跨 seed 相等；hash seed 变化不影响 canonical 面 | **RED**（同根因：raw digest 跨根不等） |
| `test_b1_real_canonical_independent_transcription_cross_check`（N-A3） | A | FR-01/AC-2/A2 | 测试侧按 §7.4 规范自建 wire（非 import 产品函数）重算 canonical digest ==工件 digest 链（receipts/manifest/报告 sources）；独立重算与产品值逐位相等 | **RED**（transcription canonical ≠ 产品 raw 工件 digest；归因=canonical 化缺席） |
| `test_b1_real_cross_entry_canonical_equivalence_anchor`（N-A4） | A | FR-01/AC-1 | b1_source 离线 suite（signal-storm，同 `_scan_snapshot` 配置）的 canonical scan digest == 真实入口工件 canonical digest（同 fixture/配置 ⇒ 同 canonical wire）；**叠加零改动锚面**：离线 suite digest 与其 §7.4 转录重算相等、描述子 `scanner_config_sha256` 与 config 文档重算相等（b1_source/描述子等值面不变——CA N-D 第二锚并入本方法，DR-IP-0042-PV-4） | **RED**（真实入口 digest 为 raw ≠ 离线 canonical；归因=接线缺席；零改动锚子面绿） |
| `test_b1_real_v1_family_verified_under_legacy_raw_rules`（N-B1） | B | FR-02/AC-2 | 合成旧族工件（V1：30/23 键、raw digest 按 §7.4 前的 raw 规则计算）⇒ 验证器按旧 raw 规则验证**通过**（含 raw digest 复扫路径）；**误标探针**：同一 V1 树仅给 manifest 加 canonical 版本键改 V2 键形而 digest 保持 raw ⇒ 必须在版本/digest 面 fail closed（具体码+path 钉扎，证明不静默套新规范） | **RED**（误标探针：现行产品在 manifest 闭集处失败，path=`$.b1_real_manifest`≠版本/digest 面精确 path；归因=族分支缺席；V1 通过子面绿） |
| `test_b1_real_v2_version_mismatch_unknown_fail_closed`（N-B2） | B | FR-02/AC-2 | V2 形工件 `canonical_source_contract_version` 错配/未知值（如 `"b1-canonical-source-v0"`/未知串）⇒ `B1_REAL_RECEIPT_INVALID` 于版本字段精确 path（码+path 钉扎） | **RED**（现行产品闭集失败 path 不同；归因=版本核验缺席） |
| `test_b1_real_version_inconsistency_and_mixed_keyset_fail_closed`（N-B3） | B | FR-02/AC-2 | receipts↔manifest 版本不一致（某 receipt 值漂移）/混合键集（receipt 缺版本键）⇒ 按 §7.2.4 映射码+精确 path fail closed（subTest 逐例） | **RED**（同根因；归因=族分支与逐件版本核验缺席） |
| `test_b1_real_canonical_digest_tamper_fail_closed`（N-C1） | C | FR-02/AC-2 | V2 工件 canonical digest 链篡改（receipt/manifest `scanner_payload_sha256` 或报告 sources 改一位）⇒ `B1_REAL_SCANNER_DIGEST_MISMATCH` 于被篡改面精确 path | **RED**（V2 形工件现行产品闭集 `B1_REAL_RECEIPT_INVALID` 码不同；归因=canonical 验证路径缺席） |
| `test_b1_real_label_replacement_no_collision`（N-C2） | C | FR-01/R3.4 | 真实入口工件 digest==以工件标签按 §7.4 转录重算值（等值面）；不碰撞两面：同内容换标签 ⇒ digest 变；同标签换内容 ⇒ digest 变（独立构造扫描对） | **RED**（等值面：产品 raw digest ≠ 标签派生 canonical 转录；归因=canonical 化缺席；不碰撞性质面绿） |
| `test_b1_real_report_payload_label_and_no_absolute_path`（N-C3） | C | FR-01/AC-1 | 报告 payload `repository`==标签（"archetype/signal-storm"）、报告 wire 无绝对路径/临时目录串；旧键（real-pilot/large-repo）孪生 payload 仍 real-world v2（守护子面） | **RED**（现行产品报告 repository=物化绝对路径；归因=E3 存 raw；旧键子面绿） |
| `test_b1_real_e3_single_storage_canonical_face`（N-D1） | D | FR-01/AC-1 | `scanner_executions==1` 既有语义上叠加 canonical 面：存储恰一份 canonical 投影（报告 sources digest==canonical 重算==receipt 值）、扫描恰一次（attempt-0）、无第二份 raw 存储 | **RED**（现行产品存 raw；归因=E3 未投影） |

**簇覆盖对照**：N-A（等值/跨进程/独立转录/跨入口+零改动锚）→N-A1-4；N-B（版本族正负例）→N-B1-3；N-C（篡改/标签/报告面）→N-C1-3；N-D（E3 单点存储锚）→N-D1。预算声明：**"新增 ≤12"为上界非目标值（簇覆盖为验收，方法数为预算）**；定稿 11 方法（≤12），余 1 槽为 C2 冻结前弹性；C2 冻结后任何增改须 DR（§10 NOT_ALLOWED）。

### 8.4 RED/GREEN 精确账（冻结时，产品=main `9a15898` 现状；逐方法归因落盘后才可冻结）

- **RED（13 方法）**：T10（产品仍写 23/30 键 ⇒ `set(receipt)`≠24 键镜像，原因=版本键缺席）、T11（产品 digest 为 raw ⇒ canonical 指纹≠工件 digest，原因=canonical 化缺席）、全部 11 新方法（能力缺席——canonical 等值/版本 fail-closed/标签锚因产品未实现而 RED，逐方法归因见 §8.3 末列）。
- **GREEN**：其余 23 方法全绿（T12 验证器对当前产品自身旧族工件仍通过——按设计 GREEN；T9 faces 与 canonical 无关；T22 五码族/`__all__` 锚不变；T24 IP-0041 文件名计数==1 不受 Dockerfile 新行影响）+四旧文件全绿（112+20+38+9=179 passed）。
- 逐方法归因表强制（先落盘、再 hash、再引用，归档主仓库 `.pv_tmp/RED_IP-0042_2026-10-01/`）；Pre-Freeze Harness Gate 沿 IP-0040 §10 八项（§9）。
- **PC 纪律（IP-0033..0041 同款标配）**：PC1=新方法源 secret-token/网络-token 拼接扫描+AST import 根扫描；PC2=arrange 经冻结校验器（孪生批准工件经冻结 loader 接受面构造；V1/V2 合成工件经明确标注的合成路径构造）；PC3=派生数值断言（canonical digest=§7.4 规范独立重算非硬抄实现值；raw≠canonical 反例=两规则分别独立重算后断言不等）。

### 8.5 AC → 测试 → 结果表框架（C4/主会话填实际结果）

| AC | 测试/证据面 | 结果（待填） |
| --- | --- | --- |
| AC-1 canonical 统一 | N-A1/N-A2/N-A3/N-A4/N-C2/N-C3/N-D1（C2 冻结→C3 绿）+ C4 双根/跨进程/双 seed/独立重算记录 | 待 C3/C4 |
| AC-2 版本化兼容 | T10/T11（S1-S3 同步）、N-B1/N-B2/N-B3 + C4 旧 sealed 只读复验记录 | 待 C3/C4 |
| AC-3 冻结面零回退 | 23 零触碰方法 + 四旧文件 179 + Done Commands + C2 diff 恰 1 文件 | 待 C2/C3 |
| AC-4 便携包与 DERIVED | §7.6 规格 + C4 包/DERIVED 清单 hash 与 durable 保存记录 | 待 C4 |
| AC-5 矩阵与勘误 | Scope 7 文档交付（非本 PR 面；Packet 登记归属） | 待文档交付 |

## 9. 冻结测试面演进程序与提交/证据链（六条件退化程序适用声明 + 提交链）

1. **对象唯一（A5 声明）**：`tests/test_v4_baseline_b1_real.py` 单文件原地演进一次（v12 = v11' 之后序号）+ **恰 2 方法（T10/T11）+ 1 组模块镜像常量（S1）授权点**（直接授权=裁定 §二测试契约同步授权，无须逐 hash 变化重新请示）+ 新增 ≤12 方法（定稿 11）；其余旧文件与产品禁区模块零 hunk（Done Commands 逐 blob 守护）。
2. **逐 hunk 归因**：同步点旧值→新值逐字（§8.1）；每新方法映射 §1 需求表与裁定编号（R1-R4/裁定 §二-§四，§8.3 已逐条登记）。
3. **禁止弱化**：不删除任何负例；新方法不得含 skip/xfail/条件降级断言；零触碰面任何 hunk=Stop 4。
4. **版本链保留**：v11' 历史 blob `6c6054c7a387` 永久在链；v12 blob 由 C2 冻结时登记。
5. **RED 先于冻结**：C2 冻结前按 §8.4 取得有效 RED 并独立日志归档（主仓库 `.pv_tmp/RED_IP-0042_2026-10-01/`，先落盘、再 hash、再引用）；冻结基线=main 上 C1 合并后完整 SHA（主会话记录；worktree rebase/重置到该 SHA 后开工）。
6. **角色纪律**：演进只在 C2 由 P&V 执行；Implementation 结构性零参与测试修改；冻结后任何测试缺陷（含纯机械缺陷）一律 Decision Request（§10）。

**Pre-Freeze Harness Gate（冻结前必须全部通过；IP-0040 §10 八项同款）**：① 演进后文件可完整 import 与 collect（零加载期错误）；② 最小 NotImplemented 桩验证全部 fixture/arrange/参数组合（含 V1/V2 合成工件构造与 subTest）执行到产品行为断言处（区分 fixture 缺陷 vs 行为缺失；桩置临时目录）；③ fixture 签名/参数数量/subTest 构造不被 ModuleNotFoundError 掩蔽；④ Ruff 一律 `--no-cache`；⑤ Ruff 在产品模块缺席态与最小桩存在态分别运行并双双通过（isort first-party 分类依赖模块存在性）；⑥ 临时桩不入冻结提交（删除后 `git status` 证明）；⑦ RED 逐项归因于缺失产品行为（§8.4 逐方法归因账）；⑧ 方法预算 36（≤37 上界）。

**提交链与证据归档（冻结）**：C1 提交信息逐字 `[IP-0042][PV] Add Implementation Packet IP-0042 (B1 canonical source wiring) and Dockerfile copy line`；C2 提交信息逐字 `[IP-0042][PV] Freeze acceptance tests v12 (RED)`；C3 前缀 `[IP-0042][IMPL]`（以 C2 为祖先）；RED 日志归档主仓库 `.pv_tmp/RED_IP-0042_2026-10-01/`（不提交）。

## 10. Mechanical Test Correction Allowance（CA §Mechanical Test Correction Allowance 全文转录）

`NOT_ALLOWED`。第九轮裁定 §二明令"上一轮 ALLOWED_ONCE 已用尽，本轮不借用其额度"，且未签发新的机械修正授权；测试契约同步本身已是直接授权（R4 附表），冻结后发现的任何缺陷——包括纯机械缺陷——一律提交 Decision Request（列明缺陷证据、最小修正、两态 RED 等价证明），由 Coordinator 裁定后以 Assignment 修订执行。

## 11. Done Commands（worktree 执行并留日志；`PYTHONUTF8=1`）

C1 验收命令（本提交上执行）：

```bash
git -C /d/BaseAIProject/LIMA-ip-0042-wt diff --stat 9a15898..HEAD     # 恰 2 文件（1 Add docs + 1 Mod Dockerfile +1 行）
git -C /d/BaseAIProject/LIMA-ip-0042-wt diff 9a15898..HEAD -- Dockerfile | grep -c "^+"   # ==2（+++头+新行）
git -C /d/BaseAIProject/LIMA-ip-0042-wt diff --name-only 9a15898..HEAD -- lima/ benchmarks/ tests/   # 必空
```

C2 冻结前 Done Commands（CA §Acceptance and Validation 逐字；在 worktree 执行并留日志）：

```bash
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_real_run         # 112 全绿（零触碰证明）
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_b1_source         # 20 全绿（零触碰证明）
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_report tests.test_v4_baseline_v5_negatives   # 38+9 全绿
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_b1_real -v        # 23 绿 + T10/T11 RED + 新方法 RED（逐方法归因 §8.4）
PYTHONUTF8=1 python -m unittest discover -s tests                        # 基线 2773 OK/24 skip 口径核对（含 RED 计入）
PYTHONUTF8=1 python -m compileall -q benchmarks tests
PYTHONUTF8=1 python -m ruff check --no-cache tests/test_v4_baseline_b1_real.py
git -C /d/BaseAIProject/LIMA-ip-0042-wt diff --stat 9a15898..HEAD        # C1 1Add+1Mod；C2 恰 1 文件
git -C /d/BaseAIProject/LIMA-ip-0042-wt diff --name-only 9a15898..HEAD -- lima/ benchmarks/   # C2 阶段必空
```

成功判据：上述全部按预期形态通过（T10/T11/新方法 RED 是成功判据的一部分，逐条归因正确）；diff 只落在 Allowed Files。失败判据：任何命令非预期退出、任何越界文件、四旧文件任何 hunk、23 零触碰方法任何 hunk、任何对预算/门序/失败终局/来源完整性/零网络零凭据断言的弱化。

## 12. Stop Conditions（触发即停并落盘 Decision Request 到主仓库 `.pv_tmp/DR_IP-0042_C1_*.md`；★=绝对停；CA §Known Gaps and Stop Conditions 11 条逐字 + NOT_ALLOWED）

登记缺口（CA 逐字，如实保留不得消解）：

- 本叶修复的是 canonical **来源接线**；不产生任何新真实 pilot 证据；第八轮既有 24 findings/legacy_projection/unavailable/无真人事件边界不变；跨目录 replay 等值证明在 C4 离线完成后才成立。
- B1 real 组合入口 3c/5w、九类样本、真实账单核对、真人分钟仍是 #57 缺口（由 Scope 7 矩阵另行登记，非本叶交付）。
- 便携核验包证明的是字节/清单/canonical 重算一致性与结构脱敏，**本轮未加载任何密钥，不得声称重新验证了任何真实密钥的字节零命中**（裁定 §四；历史脱敏检查只能引用记录+hash）。

Stop Conditions（CA 逐字）：

1. ★ 任何真实模型调用尝试（含一次 POST）/真实凭据注入/网络下载/付费动作 = 绝对停。本叶不存在任何真实调用授权。
2. ★ 旧 sealed 目录（`D:\BaseAIProject\LIMA-real-runs\` 下一切既有文件，含第六/七/八轮原件与 `pr3d-b1-real-2026-10-01\**`）任何写入 = 停；DERIVED 件与便携包只写入**新**目录（R5）。
3. ★ `lima/**` 任何写 = 停；`b1_source.py`/`report.py`/`budget.py` 及其余产品文件任何 diff（C3 预裁定表外）= 停（canonical 复用确需最小例外→具名 DR 列 hunk，不得先改后补）。
4. ★ R4 附表之外的旧测试修改（含 23 零触碰方法、四旧文件、任何负例删除或弱化）= 停；以改测试消失败 = 停；不借 IP-0041 已用尽的 ALLOWED_ONCE。
5. real_run.py 演进超出"恰 E3 hook 体一 hunk"边界（E4 应零改动；触及公共签名/order 1-9/旧描述子行为/预算门）= 停。
6. 新增 B1RealErrorCode（五码闭集）/新增 `_DECLARATIONS` 条目/`__all__` 变更/b1_real 入口签名变更 = 停（R2 裁定为不新增）。
7. 发现修复需要固定路径、设置单一 seed、删除字段、重排 findings 或改生产分析器才能让 hash 相等 = 停（裁定 §二明令禁止；若发现新的真实非确定性，保留最小差异再处置，不预先扩大修改面——裁定 §三.2）。
8. 版本分支无法由可验证元数据选择、或出现"失败就尝试另一算法"的实现形态 = 停。
9. 同根因两轮有新证据修复仍失败 / 授权文本与代码事实矛盾 / 规格无法兼容 = 落盘 DR 后停依赖部分，完成其余工作（DR 须列不可同时满足条款及最小选项，不能只因测试红而降级——裁定 §二末段）。
10. 范围外能力（3c/5w/九类描述子/付费调度器/A1 schema 扩展等）被实现需要牵引 = 停并登记依赖表，不借本修复顺带实现。
11. discover skipped 集出现未登记变化（基线 24）；新增方法超预算（>12，即文件总数 >37）；需要消耗 Maintainer 决策的事项（预算 ≤1，预期 0——本叶无预算面变更）。

（第 12 项纪律=§10 Mechanical Test Correction Allowance `NOT_ALLOWED` 逐字：冻结后任何测试缺陷含纯机械缺陷一律 Decision Request，不自行修正、不借旧额度。）

## 13. PR 与 Completion Summary 契约（CA §Handoff）

- C1 PR（主会话）：单 PR `codex/ip-0042-canonical-wiring` → main；标题禁 close 族关键词与编号组合；正文含 C1 commit SHA（完整 40 位）、变更文件清单（恰 1 Add+1 Modify）、Dockerfile 恰 +1 行证明、"Related to #254."（仅此关联；不关联 #57/#251 状态；无自动关闭关键字）。
- C3 Implementation PR（P&V 组装）：`Implements IP-0042` + `Related to #254` + Packet 路径与 C1 合并 SHA + Frozen Test Commit 与实现 commit + Covered FR/AC 与未覆盖声明 + 文件/依赖变化 + `AC → 测试 → 结果` 表（§8.5）+ 实际命令/环境/统计/skip + Verification Verdict + Decision/Findings/known limitations + Issue closure impact：PARTIAL + "This PR does not auto-close the Source Issue."；提交前缀 `[IP-0042][PV]`/`[IP-0042][IMPL]`；C3 必须以 C2 为祖先；修复提交须引用 Stop/DR 编号。合并/推送/评论由主会话按 Maintainer 授权执行；P&V/IMPL 零远端写；分支 head CI 与审查过门后才合并，合并后核验 merge SHA 的 main CI success。
- Completion Summary 必含：FR-01..07 逐条证据索引（测试 ID/C4 记录）、AC-1..5 判定（满足/不满足/未验证三态）、C1/C2/C3 提交 SHA 与 blob 记录、RED 归档路径与逐方法归因计数（预期 13 RED/23+179 GREEN，§8.4）、基线实际值（179 passed/2773 OK/24 skip）、零真实调用声明、Dockerfile 恰 +1 行证明、canonical 统一面/版本设计/标签语义/新目录名冻结决定引用（§7/§15）、§16 缺口状态。
- 传递时必须携带被否决的决定及理由（§3 全部 15 项转录传递）：不双存 raw+canonical、不改 b1_source 规则、不扩绑定块、不新增错误码/declaration、不给报告 sources 加版本标注、不参数化旧入口、不把 sealed 复验做成依赖机器绝对路径的单测、不借 ALLOWED_ONCE、不复制完整失败日志、不"失败就换算法"、不以固定路径/seed/删字段/重排/改分析器凑 hash、"零产品 import"≠便携、不声称重验密钥零命中、不混写 AC-03/V5-AC-03、不借修复牵引范围外能力。

## 14. 范围裁定 R1-R6 转录（CA-IP-0042-v1.0 附录 R 全文，逐字）

- **R1（Q1 canonical 统一面）：E3 单点存储 canonical 投影；E4 零改动；后相/验证器同规则；b1_source 零修改**。——裁定：1. **E3 hook 改存 canonical 投影（单存，不双存）**：`_b1_execute_scanner` 内（real_run.py L1879-1888）将存储改为 `payload = b1_source._canonical_payload(result, label)`，`self._b1_scan_result = payload`；标签 `label` 从第十二描述子派生——`REAL_RUN_ARTIFACT_FAMILY[self._approval.artifact_key]["fixture_key"]`（=`"archetype/signal-storm"`，描述子 L521 已载，合同字段 L780 可达），**不扩展 `b1_source_binding` 绑定块**（旧 sealed approval 的绑定块与描述子等值面保持不动）。不双存 raw+canonical：双根原始 wire 差异**仅** `$.repository`/`$.workspace.root` 两字段（审计 §2 递归全 wire 比较实证），raw 绝对路径无证据承载任何语义；实际物化身份已由 `snapshot_tree_sha256`/`cold_reset` 观察/`request_body_sha256` 独立钉扎（T8 三方等值锚既有），报告无需保留绝对路径。2. **E4 build_payload 门零代码改动**：其返回存储槽（L1629-1630），随存储值自然变 canonical——报告走 scanner 类型路径时 `payload_sha256` 由 report.py L1338-1344 从 payload 计算，自动为 canonical digest；报告仅两标签字段变值。**"报告语义不变"证明面**（Packet 冻结，三层）：① `_canonical_payload` 仅 `dataclasses.replace` 两标签字段，findings/collaboration/adjudication/inventory 统计共享只读引用（b1_source L359-372 docstring+实现亲读）；② T9 faces 对照（counts/compression_chain/coverage/unavailable 纪律）与 canonical 无关、冻结前后均绿——独立反证；③ C4 实测双根报告除两标签外逐值一致+差异字段清单与审计一致（仅非语义路径面）。3. **后相复扫（b1_real.py L681-689）**：独立复扫后先投影再指纹——`payload = b1_source._canonical_payload(scan, _FIXTURE_KEY)`；`wire_digest = b1_source._wire_fingerprint(payload)`；receipt `scanner_payload_sha256` 与报告 sources digest 随之为 canonical 值。`_projection_matches`/`_scan_faces`（L416-477）只消费 findings/collaboration 面，canonical 中性，零改动。4. **验证器复扫（L981-982）**：同规则 canonical 化，**且按工件族分支**（R2）：新族工件按 canonical 规则+版本核验；旧族工件按旧 raw 规则核验；分支由可验证元数据（闭集键形+版本字段）先于一切 digest 比较选择，禁止"失败就换算法"。5. **b1_source 零修改**：离线 suite 全链已 canonical（L572-574 亲验）；`_canonical_payload`/`_wire_fingerprint` 只读复用；B1 离线 suite 自身的 canonical 使用即对照面（同 fixture/配置 ⇒ 离线与真实两入口 canonical wire digest 相等——N-簇新增跨入口等值锚，见 R4）。6. **real_run.py 演进例外清单=恰 E3 一 hunk**（逐 hunk 登记：符号 `_b1_execute_scanner`/门条件不变（`_b1_binding` 限定，旧键默认关闭由 T20+C4 双证）/默认关闭证明=旧十一键绑定块为 None 永不进分支）；E4/公共签名/order 1-9/预算门零触碰。——依据：裁定 §二"优先复用既有 canonical 投影，将真实 B1 执行、报告来源、后相复扫和验证器统一到同一个明确版本的规则……只消除已证明的非语义物化路径差异"；审计 §2 差异字段实证（仅两字段）与 §3 接线遗漏定位；b1_source L356-393/L572-574、real_run L1620-1630/L1855-1888、b1_real L681-689/L981-982 亲读；双存方案被否决——双存扩大受审面且 raw 面无语义承载（差异字段实证）。
- **R2（Q2 契约/算法版本）：新增私有 canonical 版本常量（值 `b1-canonical-source-v1`）入 manifest+receipts 各一键；旧族由键形+既有版本字段选择；五码闭集不新增**。——裁定：1. **版本常量**：b1_real.py 新增私有常量 `_CANONICAL_SOURCE_CONTRACT_VERSION: typing.Final[str] = "b1-canonical-source-v1"`（字符串承载族+序号；最终命名/值由 Packet 冻结，但必须保持私有——`__all__` 五符号不变）。**第十二描述子的 `source_contract="b1-real-source-binding"`/`source_contract_version=1`（绑定契约对）不动**：它钉扎的是绑定块合同而非 digest 规则，改动会无谓牵动 M/T6 描述子 pin、绑定块等值面与旧 sealed approval 对照（T6 L1009-1011 亲读，零触碰由此保住）。2. **入工件字段**：companion manifest +`canonical_source_contract_version`（30→31 键）；每张 receipt +同键（23→24 键）——receipt 自描述，单件可判族。**报告 sources 不加版本标注**（report.py 及报告闭集零触碰，R1.2）；`B1RealSuiteResult` 字段集默认不变（Packet 可冻结 additive 版本字段，非必需）；便携包与 DERIVED 件携带该版本值（R5）。3. **旧族选择元数据（受审兼容策略）**：产品保留旧键集常量（V1 族：23/30 键逐字=当前元组）并引入新键集（V2 族：24/31 键）。验证器分支次序：读 manifest → 键集==V1 且 `source_contract_version==1` ⇒ **旧族，按旧 raw 规则**（第八轮 sealed 目录 `pr3d-b1-real-2026-10-01` 即此族，manifest 30 键/版本 1/raw digest `a7c20067…` Coordinator 只读亲验）；键集==V2 ⇒ 新族，先核 `canonical_source_contract_version == 当前常量`（receipts 与 manifest 逐件一致），再按 canonical 规则核 digest 链；**其余一切键形（混合/部分/未知）⇒ fail closed**。旧族选择依据=可验证元数据（闭集键形+既有版本字段），"V1 工件缺新版本键"是族标记而非版本缺失失败；新族工件的版本缺失（键集要求下不可能缺）/错配/篡改/身份漂移全部 fail closed。4. **错误码映射（不新增码）**：五码闭集（L227-234）保持——键形/族别/版本值非法 ⇒ `B1_REAL_RECEIPT_INVALID`；canonical digest 链不符 ⇒ `B1_REAL_SCANNER_DIGEST_MISMATCH`；跨面身份漂移（receipt↔manifest 版本不一致、标签/身份字段不符）⇒ `B1_REAL_BINDING_MISMATCH`。逐违例→码映射由 Packet 冻结成表（对应裁定 §二"版本缺失、错配、篡改、身份漂移 fail closed"四类）。——依据：裁定 §二"必须有显式契约/算法版本和受审兼容策略。旧 raw-path 工件仍按旧规则验证，不静默套新规范……版本分支必须由可验证的版本与元数据选择，不能'失败就尝试另一算法'；版本缺失、错配、篡改、身份漂移 fail closed"；sealed manifest 30 键/版本 1 实物亲验（若直接替换 `_MANIFEST_KEY_SET` 无分支，旧目录在 L882 闭集等值处误失败——分支必须先行）；五码族被 v11' 冻结测试以码值消费（T12/T13/T15 等 12 处 `B1RealErrorCode` 引用亲数），新增码必触同步面且无必要；`schema_version` 保持 1（T10 L1183 断言不动）。
- **R3（Q3 canonical 标签语义）：标签=fixture/source 身份（描述子 fixture_key）；身份仍由独立字段钉扎；用途分界表**。——裁定：1. **标签来源**：稳定标签=第十二描述子 `fixture_key`（`"archetype/signal-storm"`）——即 fixture/source 身份，与 b1_source 离线 suite 的标签规则**同源同值**（L572 `_canonical_payload(scan, fixture_key)`）。**禁止**取 run_name、执行日期/时间、绝对根目录、临时目录、`lima-synth-` 前缀物化路径（real_run L2173 物化目录名含临时路径成分，明确排除）。标签经描述子派生不经绑定块（R1.1），前相执法零改动。2. **RunSpec/执行身份钉扎不变**：`run_spec_digest`/`approval_sha256`/`request_body_sha256`/`run_result_sha256`/`ledger_sha256`/`snapshot_tree_sha256`/analyzer_fingerprint 各自独立钉扎，不因 canonical 化合并或弱化。3. **digest 用途分界表**（Packet 逐字冻结）：〔四行表见 §7.3.3 逐字〕。4. **标签替换不碰撞**：不同标签对同一内容 ⇒ 不同 canonical digest；同标签不同内容 ⇒ 不同 digest（N-簇负例，裁定 §三.4"标签替换不得使不同来源碰撞"）。——依据：裁定 §二"稳定标签取 fixture/RunSpec 的来源身份，不取绝对根目录、临时目录、run_name 或本次时间。输入内容、analyzer/config/工具链/seed 等语义身份仍须被相应身份字段钉扎"与"canonical 来源 digest 与当次 execution/context digest 分清用途"；b1_source L572 同源先例；审计 §2（`_canonical_payload(scan, "archetype/signal-storm")` 复现手法即此标签）。
- **R4（Q4 测试契约同步清单——直接授权）：恰 3 同步点（2 方法+1 组常量，单文件）；其余 23 方法与四旧文件零触碰；新增 ≤12 方法；冻结 v12**。——裁定：测试契约同步授权（裁定 §二末段直接授权，无须逐 hash 变化重新请示）承载于 `tests/test_v4_baseline_b1_real.py` **原地演进**，冻结版本 **v12**（=v11' 之后序号）。方法编号 T1-T25 按文件序（与派发消息 M 编号一致：T1=孪生、T11=digest 交叉、T12=篡改）。同步点附表（S1-S3）、零触碰清单、N-簇建议、RED/GREEN 精确账——**逐字转录于 §8.1/§8.2/§8.3 引文与 §8.4**。——依据：裁定 §二测试契约同步授权（"Packet 在冻结前列出具名方法、旧/新语义及独立反例；……不允许改掉预算、门序、失败终局、来源完整性或零网络/零凭据断言"）；§三.1-§四证明面；Coordinator 逐方法亲读 T1-T25 与四旧文件 grep 交叉；b1_source 测试 canonical 镜像先例（L345-368）；"新增 ≤12"为上界非目标值（簇覆盖为验收，方法数为预算）。
- **R5（Q5 证明/便携包/DERIVED 归属）：区分力证明=P&V C-final（独立 worktree）；便携包+DERIVED=P&V C4 产出、仓外新目录、主会话 durable 保存**。——裁定：1. **§三区分力离线证明归属**：P&V，**C-final 阶段**（C3 实现验证通过后、合并前），在独立 worktree 执行（沿 CA-IP-0041 R6 先例）。内容=裁定 §三.1-§五逐项（§7.5 逐条承载）。2. **便携补充核验包+DERIVED 件归属**：P&V 于 C4 产出（同一独立 worktree 会话），存放于 `D:\BaseAIProject\LIMA-real-runs\` 下**新同级目录**（建议 `b1-canonical-portable-2026-10-01\`（核验包）与 `pr3d-b1-real-2026-10-01-derived\`（第八轮目录 DERIVED 件）——最终目录名由 Packet 冻结）；**零覆写任何既有文件**；主会话负责 durable 保存；PR 面内只携带仓内文档引用（包位置+清单 hash），不复制包体入仓。3. **便携包技术要求**（Packet 逐条冻结=§7.6.2 十一条）。4. **DERIVED 件**：为第八轮目录生成 canonical 补充证明于新目录，绑定原目录清单+原文件 SHA-256（47 件清单既有）+原执行 commit `9a15898333b23b2b1ad8edf7dbf173d39fa3336c`+当前投影版本（R2）；不改写旧 receipt/manifest/source digest/授权摘要；**不称派生件为当时已执行的新入口**（标注 DERIVED+生成时间+规则版本）。——依据：裁定 §三/§四全文；§七"沿用已建立角色即可"；CA-IP-0041 R6 C-final 预排先例；审计 §4.2 对旧 VERIFY 脚本的非便携定性。
- **R6（Q6 回归面）：旧面 179+25 零回退；23 方法零触碰；discover 2773/24 口径；sealed 只读复验入 C4**。——裁定：1. **冻结回归面**（§7.7.1 逐字承载）。2. **C4 回归面**（预排，§7.7.2 逐字承载）。3. **能力表述三处纠正的承接**（审计 §4，非本叶测试面但 Packet 须登记防倒退，§7.7.3 承载）。——依据：裁定 §三.5"运行与改动相称的 targeted 测试，以及仓库必需的全量/CI 检查"、§四 sealed 只读；主会话 2026-10-01 冻结基线记录（112/20/38/9/25、2773 OK/24 skip）；Coordinator 亲数四旧文件方法数与 T1-T25 逐方法归位。

## 15. Decision Record（P&V 定稿决策；CA 授权范围内的冻结裁量）

| # | 决策 | 时间 | 依据 |
| --- | --- | --- | --- |
| DR-IP-0042-PV-1 | canonical 版本常量定稿：`_CANONICAL_SOURCE_CONTRACT_VERSION: typing.Final[str] = "b1-canonical-source-v1"`（私有；`__all__` 五符号不变；不入 `_DECLARATIONS`；采纳 CA 建议命名与值） | 2026-10-01 | R2.1"最终命名/值由 Packet 冻结，但必须保持私有" |
| DR-IP-0042-PV-2 | 键集族常量方向定稿：生产面 `_RECEIPT_KEYS`/`_MANIFEST_KEYS` 原地演进为 V2（24/31 键，`canonical_source_contract_version` 追加于元组尾、其余键序不动；`_RECEIPT_KEY_SET`/`_MANIFEST_KEY_SET` 随之）；V1 旧族以新私有常量 `_LEGACY_RECEIPT_KEYS`/`_LEGACY_MANIFEST_KEYS` 逐字保留（=当前 23/30 元组含序）+派生 `_LEGACY_*_KEY_SET` frozenset 供族分支；`schema_version` 保持 1；`B1RealSuiteResult` 字段集不变（不新增 additive 版本字段——版本在 companion 工件自描述） | 2026-10-01 | R2.2/R2.3"产品保留旧键集常量（V1 族逐字）并引入新键集（V2 族）"；"Packet 可冻结 additive 版本字段，非必需"——裁量不新增 |
| DR-IP-0042-PV-3 | 新目录名定稿：便携核验包=`D:\BaseAIProject\LIMA-real-runs\b1-canonical-portable-2026-10-01\`；DERIVED 件=`D:\BaseAIProject\LIMA-real-runs\pr3d-b1-real-2026-10-01-derived\`（均采纳 CA R5.2 建议值；零覆写既有文件） | 2026-10-01 | R5.2"最终目录名由 Packet 冻结" |
| DR-IP-0042-PV-4 | N-簇定稿拆分=**11 方法**（N-A×4/N-B×3/N-C×3/N-D×1；新总数 36 ≤37 上界；余 1 槽为 C2 冻结前弹性）；CA N-D 第二锚（b1_source canonical 规则零改动锚）并入 N-A4 作叠加断言面（离线 suite digest 转录重算+描述子 scanner_config_sha256 等值面），N-D1 独立承载 E3 单点存储 canonical 面；**全部 11 新方法冻结态 RED**（负例断言钉扎具体错误码+结构 field path，防"恰巧 fail closed"假绿；N-B1 以"V1 误标 V2 必拒"探针取得真实 RED） | 2026-10-01 | R4"Packet 定稿拆分，建议簇"+RED/GREEN 精确账（RED=全部新方法）+Acceptance C2.2 精确枚举 |
| DR-IP-0042-PV-5 | E3 标签派生路径定稿：`label = REAL_RUN_ARTIFACT_FAMILY[self._approval.artifact_key]["fixture_key"]`（module 内直引目录常量；real_run.py 内无需 self 前缀修饰）；与 b1_source 离线 suite L572 同源同值；不扩绑定块 | 2026-10-01 | R1.1/R3.1 |
| DR-IP-0042-PV-6 | 验证器分支次序定稿（R2.3 具体化）：读 manifest → ①键集==V1 且 source_contract_version==1 ⇒ 旧族 raw 规则；②键集==V2 ⇒ 先核 canonical_source_contract_version（manifest 与每张 receipt 逐件一致==当前常量）再 canonical digest 链；③其余一切键形 ⇒ `B1_REAL_RECEIPT_INVALID` fail closed。分支先于一切 digest 比较（先于现行 L882 闭集等值位置）；运行内后相产出恒为 V2；违例→码映射表=§7.2.4 | 2026-10-01 | R1.4/R2.3/R2.4；sealed 30 键实物亲验（分支必须先行） |
| DR-IP-0042-PV-7 | 独立转录规范冻结于 §7.4（规范名=b1-canonical-source-v1；输入/两标签替换/完整字段集合（report 九键/findings 24 键/evidence_records 12 键/workspace 十键含 files 四键）/编码 sorted-key compact UTF-8 JSON+SHA-256/路径无关性依据）；测试镜像（N-A3）、便携包（C4）、独立核验器三方按此规范自行实现，非产品函数与其别名互证 | 2026-10-01 | A2/裁定 §三.3；DI-005/DI-014 亲读 |
| DR-IP-0042-PV-8 | Dockerfile 插入锚=L72（IP-0041 Packet COPY 行，grep -n 亲验）后，新行落 **L73**；b1_real.py/real_run.py 不新增打包行（benchmarks COPY L85 已覆盖） | 2026-10-01 | CA §C1 Allowed Files；DI-015 亲读 |
| DR-IP-0042-PV-9 | V1 合成旧族工件的单测形态（hermetic）：测试内合成 30/23 键工件（raw digest 按 raw 规则计算），不依赖 `D:\BaseAIProject\LIMA-real-runs\` 机器绝对路径；真实 sealed 复验归 C4 只读执行证据 | 2026-10-01 | R4"旧 sealed 只读复验不做冻结单测"逐字 |

**观察项（不移交实现、不构成验收面）**：

- **OBS-1（行号复核结论）**：本会话逐锚亲核 CA §Frozen Interfaces 1-7 与 R1-R6 全部代码/测试/Dockerfile 行号（DI-005..DI-015），**实质零漂移**。记录性边界差异 3 处（均同块内端点 ±1 行、无验收语义影响，以 worktree 实际为准登记）：①`_RECEIPT_KEYS` 元组实际 L116-140、`_RECEIPT_KEY_SET` 在 L141（CA 记 L116-141——区间含派生常量行，非漂移）；②`_MANIFEST_KEYS` 实际 L145-176、`_MANIFEST_KEY_SET` 在 L177（CA 记 L145-177，同上）；③验证器 `_SCANNER_PHASE`/`_DECLARATIONS` 常量对照块实际 L919-930（CA 记 L920-931——transport_face 检查始于 L931，块起点差 1 行）。另：CA R2 引"描述子 L521 已载 fixture_key"——实际 L516（`b1_real["fixture_key"] = _B1_REAL_FIXTURE_KEY`，同组装块内）；CA Frozen 5 记 T11 断言面"L1222-1225"——实际 L1221-1225（`persisted_scan` 行在 L1221，同断言块）。
- **OBS-2（四旧文件 grep 复核）**：`_canonical_payload` 在 tests/test_v4_baseline_b1_source.py L349 有一处 docstring 文字出现（canonical 镜像 helper `scanner_wire_digest` 的文档串——即 T11 同步样式先例本体，非 import/调用/符号引用）；`_wire_fingerprint` 与 b1_real 闭集在四旧文件零功能引用。与 CA"Coordinator grep 亲验"结论一致（功能面零引用）。
- **OBS-3（sealed 只读亲验）**：本会话对 `pr3d-b1-real-2026-10-01\` 只读复核（manifest 30 键逐键=旧集/source_contract_version=1/raw digest `a7c2006763e5b854…`/5 receipt 各 23 键/两处均无 canonical 版本键）——与 CA Frozen 7 一致；本会话零写入。
- **OBS-4（Issue 正文来源）**：#254 正文本会话未独立 GET（第九轮零网络授权）；需求语义经派发消息所附 create_issue_ip0042.py BODY 转录消费（DI-004）。主会话派发 C3 前如需逐字复核 AC-1..AC-5，可只读 GET 复核与本 Packet §1 映射一致性。
- **OBS-5（RED/GREEN 账的精确化）**：CA R4 总括句"全部新方法（能力缺席）RED"与本 Packet §8.4 一致（定稿 11 方法全 RED）；其成立依赖 §8.3 定稿的断言面设计——负例断言钉扎码+path、N-B1 误标探针、N-C2/N-A4/N-C3 的等值锚面。若 C2 实现中发现某方法无法取得真实 RED（断言面被迫退化为"恰巧 fail closed"），不得以弱断言凑 RED——按 Stop 9 落 DR。

## 16. 已知缺口（不阻塞本 Packet；如实保留，不得消解成 0 或 measured）

- **K1**：本叶修复 canonical 来源接线，不产生新真实 pilot 证据；第八轮既有 24 findings/legacy_projection/unavailable/无真人事件边界不变；跨目录 replay 等值证明在 C4 离线完成后才成立。
- **K2**：B1 real 组合入口 3c/5w、九类样本、真实账单核对、真人分钟仍是 #57 缺口（Scope 7 矩阵另行登记，非本叶交付）。
- **K3**：便携核验包证明字节/清单/canonical 重算一致性与结构脱敏；本轮未加载任何密钥，不得声称重新验证任何真实密钥的字节零命中（历史检查只引用记录+hash）。
- **K4**：v9/#57 勘误与 CLOSURE_CRITICAL_PATH_MATRIX（#254 Scope 7）为文档另行交付，不在 C1-C3 PR 面内（本 Packet 只登记存在与归属）。
- **K5**：C3 产品实现与 C4 证明/便携包/DERIVED 均未在本 Assignment 授权内执行（分别以 CA-IP-0042-v1.1 与后续授权为准；本 Packet 已冻结其边界与规格）。

（Packet 完；版本 v1.0。Contract 语义变更须同步 Packet 版本与 AC。）
