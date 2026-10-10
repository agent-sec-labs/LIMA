# Implementation Packet IP-0023 — Monorepo Component Graph & Per-Component Profile/RAM（#60-CLOSURE-A 首片）

> 文档类型：Implementation Packet（P&V 制作；本版为 **D1 跨层契约修订（D1X）** 产物——只修订 Packet 文档，未写测试/产品/schema、未冻结；v5 = v4.1 之上的 **五项跨层契约集中修订**，落 CL-01..05 全部五项裁定 + 机械收尾）
>
> Packet 版本：`IP-0023-PACKET/v5`（**v5 跨层契约修订版**，2026-10-10：Maintainer 指令 `MR-60-PR282-CROSS-LAYER-CORRECTION-20261010/v1` §四/§六 + Coordinator Assignment `ASSIGN-60-CLOSURE-A-PKT-D1X_v1`（SHA-256 `86bfc69880836c028444d428f605ca4666a28259648f472746e0085fc40e0025`，读取前重算一致）授权——五项修订：**CL-01** 元数据丢失进入完整性判据与三态唯一分类（§0.4/§5.1.7/§5.2.4，T8 触发 + 唯一决策表）；**CL-02** 精确源码视图与自身元数据视图区分（§0.4/§4.3.1/§5.2.1，双清单视图单解）；**CL-03** 全仓有效三池自实际调用方约束求得（§0.4/§5.4.4，对应值 min 单解）；**CL-04** 计量真实 IO 与保守常数倍上界（§0.4/§5.4.4-IO，读取尝试口径）；**CL-05** 发现/读取/发布/provenance 五计量域一致（§0.4/§5.1.8/INV-OWN-3/V7/canonical/consumer 联合改写）；+机械收尾（W-1 fingerprint 归属修正、v4.1 头部 SF-5 表述如实化、#62 断言恢复、测试计划随动）。语义面修订=上述五项集中落地；冻结面（54 帽/candidate_id/旧 digest/GAP 10 码/#58 契约/旧 golden/DEFAULT_EXTENSIONS）零触碰；测试计划 #62 恢复小预算断言并删除"默认调用方"限定语、#63 按新 IO 上界公式随动重写、#30/#61 等随动、增补 #64-#73；**v5 supersedes v4.1**（v4.1 = 同文件 @`af916ac3dad7e7176b3724469323d9c64eddacff`，SHA-256 `05d71103797a350b2dc3785c9e7da6d568ae2a3edad53964ed8cb3d1f33cd040`，原样保留在提交历史，不重写、不删除）；v4.1（**v4 文字修订版**，2026-10-09：MR-60-PR282-FINALIZATION-20261009/v1 §五"同范围缺陷修正"授权的单一批次 Report Correction `SF-60-IP-0023-D1F-1..4`——①§5.6.3/§5.1.7 gap detail 与通道键值域交集的承载字段单解澄清+计数归属；②§5.4.4 有效池语义补注（+#62 限定语）；③§5.8 提示材料准入继承 IP-0019 声明；④两处 v2 提交 SHA 补全 40 位。**语义面/冻结面零变更；测试计划仅 #62 断言加"默认调用方"限定语（v5 按 ER D1F addendum-1 SF-5 如实化该表述并撤销该限定语）**；v4 基线 = 同文件 @`5d550fd28cbd5f00ed4b5942e8ffa7c017a1f965`，SHA-256 `33b2b2d6aa68e8ff3ec926f5e7a127e40bada7b7f2a4feb3d1434075808a5651`，原样保留在提交历史，不重写、不删除）；**v4 supersedes v3**（v3 = 同文件 @`d55a9f298e88dd5a656437e10cc93c64cd69ad9d`，SHA-256 `1b07cc65c9855d05fa3361c5953a73f8ebd66069ac37898e5b58704605e427cf`，原样保留在提交历史，不重写、不删除）；**v3 supersedes v2**（v2 = 同文件 @`176d22f9eff77ffd14949c86b5f7aea5487edaf8`，SHA-256 `19915a7a9a6807afe88a2c417d96e2550281f3255475543e4bf8300613d52453`，原样保留在提交历史，不重写、不删除）；**v2 supersedes v1**（v1 = 同文件 @`41c899ef10be682e52d61ab0f92e4bef11aed27c`，SHA-256 `e9702fe2bbf403f58a60afa07400cb0ef7fe4aca1cd1d20f736195048d1f7f9f`，原样保留在提交历史，不重写、不删除）。v1→v2 修订依据：Maintainer 指令 `MR-60-PR282-GOAL-CORRECTION-20261009/v1`（§五 R60-01..08、§六 测试计划、§七 custody、§八 呈审）+ Coordinator Assignment `ASSIGN-60-CLOSURE-A-PKT-D1R_v1`（SHA-256 `30a0e9198bd3914e3c2ea511f8d5ad523addabd1496dc654ce755d03d61c040a`）+ `MDR-60-PR282-GOAL-CORRECTION-20261009-v1`（逐项处置见 §0.1）。v2→v3 修订依据：同指令 §五/§九 + ER Record `ERR-60-IP-0023-D1R-2026-10-09-v1` 三项 Shadow Finding 的最小回应（探针证据 SHA 见 DI-022 与附 C；逐项处置见 §0.2）。**v3→v4 修订依据**：Maintainer 指令 `MR-60-PR282-FINALIZATION-20261009/v1`（§四 五项已采纳产品裁定 = 本版 P60-V3-01..05 裁定内容来源；§六 测试计划要求）+ Coordinator Assignment `ASSIGN-60-CLOSURE-A-PKT-D1F_v1`（SHA-256 `2774bd4333c3974fb6369e7f9492bb3a6bf0e46ad9233d93a541aa5bfa2ebf8a`，D1F 唯一任务合同，读取前重算一致）+ 配套规划 `docs/LIMA_Issue60_PR282_v3_Rulings_and_Delivery_Plan_2026-10-09.md` + `MDR-60-PR282-FINALIZATION-20261009-v1`（逐项处置见 §0.3；离线消费探针证据见 DI-027 与附 D）。**v4.1→v5 修订依据**：Maintainer 指令 `MR-60-PR282-CROSS-LAYER-CORRECTION-20261010/v1`（正文 `.pv_tmp/issue60-resume-2026-10-09/authorization/v5/CROSS_LAYER_BODY.md`，SHA-256 `5a584cf5d24e6382ad174ca7336c427ddff101d96f1cce993adad6a867d56213`，读取前重算一致；§四 CL-01..05 五项裁定 = 本版修订内容来源；§六 兼容边界与机械收尾）+ Coordinator Assignment `ASSIGN-60-CLOSURE-A-PKT-D1X_v1`（SHA-256 `86bfc69880836c028444d428f605ca4666a28259648f472746e0085fc40e0025`，D1X 唯一任务合同，读取前重算一致；取代 D1F 成为当前活动 Assignment）+ 配套规划 `docs/LIMA_Issue60_PR282_v41_Code_Review_and_Delivery_Plan_2026-10-10.md`（SHA-256 `0d7f79a5882576bd5d7efb801317fdae758c49568249a4fe0282418afa08691f`）+ `MDR-60-PR282-CROSS-LAYER-20261010-v1`（SHA-256 `412e82e7a715e3c0266f9207d0e4a2dd002f999518d3667ef6014a2f6af3e680`；逐项处置见 §0.4；本轮反例证据见 DI-031 与附 E）。
>
> 状态：`D1X-REVISION / PENDING-REVIEW`（**未冻结的修订待审态**：v5 = v4.1 + CL-01..05 跨层契约集中修订，仍待 Coordinator readiness 逐项核五项 D1 出口、ER 独立语义反证与 Maintainer 对修订后具体 PR head 的合并批准；获批合并进 main 并由 Coordinator 标 `PACKET-MERGED` 前，本状态行不得改标为任何"可进入实现"表述——判据见 §13）
>
> Exact base：修订基线 = 分支 `codex/ip-0023-monorepo-packet` @`af916ac3dad7e7176b3724469323d9c64eddacff`（Packet v4.1 提交 = PR #282 当前 head；v4 @`5d550fd…`、v3 @`d55a9f29…`、v2 @`176d22f9…`、v1 @`41c899ef…` 在其下保留）；产品/冻结面基线 = `fbbbd619fb0b96efbbb903916ab46dc0daed2214`（origin/main；v5 开工 `git fetch origin` 亲验未前移，2026-10-10；PR head 对 main 的 diff 恰为本文档一个新增——开工 `git diff --name-only fbbbd619...HEAD` 亲验 docs-only，v5 修订后保持）
>
> 制作人：lima-packet-verification（v1：Assignment `ASSIGN-60-CLOSURE-A-PKT-D1_v1`，任务 `PKT-IP-0023-D1`；v2：Assignment `ASSIGN-60-CLOSURE-A-PKT-D1R_v1`，任务 `PKT-IP-0023-D1R`，2026-10-09；v3：同 D1R Assignment 范围内的最小修订——Maintainer 指令 `MR-60-PR282-GOAL-CORRECTION-20261009/v1` §五/§九 授权，闭合 ER Record `ERR-60-IP-0023-D1R-2026-10-09-v1` 三项 Shadow Finding，2026-10-09，不需新 Assignment；v4：Assignment `ASSIGN-60-CLOSURE-A-PKT-D1F_v1`，任务 `PKT-IP-0023-D1F`，2026-10-09，Maintainer 指令 `MR-60-PR282-FINALIZATION-20261009/v1` §五 授权（MAINTAINER_AUTHORIZED/SHADOW）；**v5：Assignment `ASSIGN-60-CLOSURE-A-PKT-D1X_v1`，任务 `PKT-IP-0023-D1X`，2026-10-10，Maintainer 指令 `MR-60-PR282-CROSS-LAYER-CORRECTION-20261010/v1` §五 授权（MAINTAINER_AUTHORIZED/SHADOW；Mechanical Test Correction Allowance=NOT_ALLOWED——本阶段无冻结测试，该授权属未来 D2）**）
>
> 编号依据：`ALLOC-IP-0023-60-CLOSURE-A/v1`（Coordinator，2026-10-09，基线 fbbbd619；2026-10-09 编号四查通过；IP-0023 = #60-CLOSURE-A 首片编号，**不是整个 Issue 的 closure 编号**）
>
> 上游决策：Maintainer 批复 `MR-60-RESUME-APPROVAL-20261009/v1` §五/§六（批复正文 SHA-256 `e4bcc9c3772fecddd7a3dc67e232aa56bd1d46aede643f2dcdbe5eda5cabbbbc`）+ 修订指令 `MR-60-PR282-GOAL-CORRECTION-20261009/v1`（正文 SHA-256 `4f7134551994f521f94f722eb9ef5a41b2f8da85246aca2b6edbdd1f220edd89`；§五/§九 兼作 v3 授权）+ 收口指令 `MR-60-PR282-FINALIZATION-20261009/v1`（正文 SHA-256 `02133d0978e4b08389af3c7139541bbd4cb997e177804cb6faa4176fcd8402e3`；§四 五裁定 = v4 修订内容来源；§五 角色链；§六 测试计划——**其 Goal/安全基线/停止条件继续有效，除被 v5 修订或收紧处**）+ **跨层修订指令 `MR-60-PR282-CROSS-LAYER-CORRECTION-20261010/v1`（正文 SHA-256 `5a584cf5d24e6382ad174ca7336c427ddff101d96f1cce993adad6a867d56213`；§四 CL-01..05 = v5 修订内容来源；§六 兼容边界与机械收尾；只替代 FINALIZATION 中被本文具体更正的规则及当前呈审结论，其余继续有效）**+ ER Record `ERR-60-IP-0023-D1R-2026-10-09-v1`（v3 修订对象，探针证据见 DI-022/附 C；**其 v1/addendum-1 的 B2 结论按 CL-03 三个口径更正、"全部承重主张未被推翻/可直接进入 D2"泛化结论被本轮反例限定——台账侧更正，历史记录保留不销毁，P&V 不改远端历史**）；恢复审计 `RESUME-AUDIT-60-2026-10-09_v1` + addendum-1/2；PI-DR1..PI-DR6 全部生效
>
> 阶段边界：本版仍只交付设计（D1 跨层收口）。验收测试文件、有效 RED、Frozen Test Commit 属 D2，另行 Assignment 派发；本阶段无 Frozen Test Commit，Mechanical Test Correction Allowance = NOT_ALLOWED（D1R/D1F/D1X 均明示——该授权是未来 D2 的一次性选项，本轮不得引用、类比或预支）。D2 冻结、Implementation、独立验证、合并、post-merge、IP-DONE、M2..M7 均未授权。

---

## 0. Header（生命周期 §8）

```text
Source Issue：#60（[V4-I04][P0] Repository Profile、RAM 与安全语义清单，V5 覆盖层版）
Issue specification revision：2026-10-09 live 正文（v1 制作时 GitHub API 亲取；body SHA-256
  477ad50cd383d22dbbbefce3a71e1a2250abd89d01218c6e1d94e6c1fd9f8180；含 V5 覆盖层、
  7/6/4 勘误后 Delivery Ledger、ENTRY60-RESUME-1/v1、ALLOC-IP-0023-60-CLOSURE-A/v1）
Covered requirements（本 IP 只声明自身贡献，且仅此贡献；D1R 未缩减目标）：
  V5-FR-03 前半句（monorepo 输出 component graph——嵌套组件识别、每组件 Profile/RAM、
    组件间依赖/歧义/未解析/未知导入关系 + provenance、重复模块名与相对导入处理、monorepo golden）
  AC-01/T-01 的 monorepo 维度（monorepo/重复模块/相对导入 fixture 下已解析与未解析调用
    均有 provenance、Top-N 顺序可重放——经每组件全链 + 图承载实现）
  V5-AC-01/V5-T-01 的 monorepo 维度（monorepo 形态输出 RepositoryProfile/code roles/
    support level/execution capability/coverage gap——每组件维度）
  V5-AC-02/V5-T-02 的后半句（monorepo 按 component 生成 profile/RAM）
  FR-02/FR-03/FR-04/NFR-01 的组件维度复验（复用三层冻结公共接口，每组件重放；
    不改三层语义，仅声明组件维度复验贡献）
Not covered requirements（相邻但明确不在本 IP；A 自身的新正确性/隐私/预算回归必须在 A 解决，
  不得转移到 B/C/D——R60-04 尤其如此）：
  V5-FR-03 后半句（docs/content 与 unsupported 安全停止端到端——机器可读 gap/停止结果）→ #60-CLOSURE-B
  V5-AC-02/V5-T-02 前半句（docs/unsupported 安全停止、不能输出"未发现漏洞"）→ #60-CLOSURE-B
  T-03/AC-03/NFR-02/V5-FR-04/V5-AC-03 端到端安全负例与 F3（_safe_path TOCTOU）/F4
    （回包/时间上限的强制约束与聚合墙钟证明）→ #60-CLOSURE-C（F3/F4 路线归切片 C，
    本片零 workspace 改动；本片不宣称任何已证明的聚合墙钟上界）
  FR-01 全跳过原因内部逐项留痕（公开面维持 reason→count）→ #60-CLOSURE-D
  DR-LINT-0022-A 六处 lint 正式处理 → #60-CLOSURE-D
  #64/#68 公共 Contract 消费验证与下游接线（含 full semantic payload 的下游消费）→
    #60-CLOSURE-D / 下游 Issue（本片只闭合"仅凭公开 Artifact 可取得并核对五类事实"）
  #58 字段/schema 任何改动（本 IP 零修改 lima/contracts/**）
  version_compatibility_matrix 注册（BG-60-01 维持默认不注册；本 IP 新 schema 同样不注册）
  整个 Issue Closure（IP-0023 DONE 不能据此关闭 #60）
Delivery role：closure-first-slice（monorepo 组件层：嵌套识别 + 单一归属 + 每组件全链 +
  独立版本化图承载 + 公开 Artifact 消费闭合）
Issue closure impact：PARTIAL
Upstream IP/PR/merge commits：IP-0016（#167 @fd219724）、IP-0018（#170 @cc17662）、
  IP-0019（#174 @e000e6f）、IP-0021（#179 @30bdfaa）、IP-0022（#180 @dfa0f85）；
  全部冻结消费面经恢复审计 §6 consumer review 43/43 PASS + 本 Packet §3 亲验复核
Upstream ruling：ALLOC-IP-0023-60-CLOSURE-A/v1；MR-60-RESUME-APPROVAL-20261009/v1 §五/§六；
  MR-60-PR282-GOAL-CORRECTION-20261009/v1 §四/§五/§六
```

本 Packet 只声明 IP-0023 自身贡献。它不宣称 #60 任何端到端 AC 整体满足、不宣称 B/C/D 切片完成、不以 Packet 文档完成声称产品已交付。

---

## 0.1 D1R 变更记录（R60-01..08 逐项处置；行号均指 v1 @41c899ef）

每项格式：原规则（v1 行号）→ 反例（review_probe_results.json，SHA-256 `90f3d975…acb8a4`）→ 修订规则（v2 节）→ 对应验收（测试符号/命令）→ 剩余限制（如实）。（本表为 v2 时点处置记录；v3 对 T6 判据（R60-06 行"主仓 cap 截断"已扩为"cap 截断或准入跳过"）及排序/构造器措辞的 ER 增补与勘误见 §0.2；**v4 对 R60-03 行聚合模型调用包络（默认 128 提案）的否决与重设计见 §0.3 P60-V3-05——如有出入，以 §0.2/§0.3 与正文 v4 版为准。**）

| # | 原规则（v1） | 反例 | 修订规则（v2） | 对应验收 | 剩余限制 |
|---|---|---|---|---|---|
| R60-01 | 候选范围="根+一级子目录"（§5.1.1 L192），示例却用 `component:services/api`（§5.1.2 L203）；测试 #1–#6 全平铺形态（L574-579） | RULE-01：`services/api/pyproject.toml`、`packages/core/pyproject.toml` 按字面规则均不在候选集 | 锚点=主 workspace 已准入 inventory 中 manifest 类文件（封闭名集）的 POSIX 父目录，**任意深度**；组件边界证据=manifest+静态 workspace/build 配置+源码/导入证据组合（§5.1.1/§5.1.2/§5.1.5） | C1 类 `test_detect_components_nested_services_packages` 等（§6 表 1-10）；D1R 探针 D1-RULE01（设计推导+实跑 inventory） | 调用方 ignore 集/扩展策略裁剪掉的 manifest 不可发现（策略继承语义，如实声明）；不支持形态以 typed gap 承载（§5.1.5） |
| R60-02 | "锚定目录互不嵌套⇒至多一归属"（§5.1.1 L194、§5.1.3 L210-213），但根组件用普通 `RepositoryWorkspace(仓库根)`（§5.2.1 L235），递归吸入子组件文件 | API-01：根 workspace 看到 `a/main.py`（root_modules=2），子组件再计 1——计数/所有权与构建输入不一致 | 最深锚点前缀精确归属（仓库级坐标，in-module 单解）+ 组件 workspace 构造（锚点根 + 继承五参数 + 嵌套锚点名 ignore）+ **所有权不变量**：构建后逐文件比对组件扫描集与精确切片，分歧→`unbuilt_components` typed 承载，不出错误数据（§5.1.3/§5.2.1） | C1 类 `test_component_counts_match_build_inputs`、`test_root_component_excludes_child_files`（§6 #9/#10）；D1R 探针 D2-API01/D7-COLLISION | 祖先组件的 Profile 层 manifest 候选仍含其一级子目录内嵌套组件 manifest（确定性、有界，已知限度）；名字碰撞目录触发不变量分歧→typed 承载——彻底消除需共享层支持（DR-IP-0023-02 草案随交接报告，不进 v2 正文为既成事实） |
| R60-03 | 从路径重建默认 workspace（§5.2.1 L235）；每组件默认预算 5000/512KiB/20MiB + 每组件独立 SemanticBudgets（§5.4.4 L431-434）＝变相扩预算；§5.7 L550 称"公共入口合法使用" | API-02：父 workspace 1/30/30 且忽略 a；子 workspace 5000/524288/20971520 且忽略规则丢失 | 组件 workspace **继承调用方全部五个策略参数**（max_files/max_file_bytes/max_total_bytes/extensions/ignored_directories）；主仓未准入输入不得因组件切分重新准入（隔离不变量强制）；~~聚合模型调用包络 `max_total_model_calls`（默认 128=16×8）作为显式新预算设计呈审~~（**v4 否决**：默认 128 被 `MR-60-PR282-FINALIZATION-20261009/v1` §四 P60-V3-05 否决——全仓默认 8、模型默认 off、聚合 token 池三口径区分，见 §0.3/§5.4.4）；资源计量口径显式（§5.4.4）；墙钟降级为"F4 未闭合、不宣称聚合上界"（§5.4.4 末） | C3 类 `test_policy_inheritance_all_five_params`、`test_no_readmission_under_caller_caps`、`test_aggregate_model_call_envelope` 等（§6 #19-#25，#21 已按 v4 重写）；D1R 探针 D3-API02 | 调用方 cap 收紧导致组件扫描集与精确切片分歧时，该组件 typed 不构建（不扩权优先于多产出；v4 起分歧类归 `unbuilt` reason=cap-divergence，§5.2.1）；F4/聚合墙钟未闭合（归 C） |
| R60-04 | 坐标分离（§5.2.1 L248）+ 准入仅覆盖 unassigned/evidence 路径（§5.8 L562-564，测试 #26 L599） | API-03：整仓 `secrets/main.py` 被拒（0 模块+gap）；根重设为 secrets 后局部坐标 `main.py` 被采纳（1 模块）——坐标变换绕过准入 | **仓库级坐标先准入、后建组件视图**：主仓 inventory（工作区级准入）→ 锚点准入（is_secret_shaped_path@仓库级）→ 归属划分 → 组件视图；锚点级准入使组件坐标下 Profile 准入与仓库级**等价**（§5.2.1 时序 + §5.8 公开面准入规则表：component_id/root_dir/manifests/unassigned/evidence/scan_summary/unknown_imports/digests/candidate_ids 逐项） | C4 类 `test_repo_level_admission_before_component_views`、`test_all_public_surfaces_admission_rules`、`test_secret_gap_reason_count_no_filename`（§6 #26-#29）；D1R 探针 D4-API03 | 启发式非穷尽声明保留（不改成"零泄漏"）；reason→count/内部无原文件名口径保留；内部 family 级全 vocabulary 留痕归 D |
| R60-05 | anchors=剥离前缀后第一级目录名（§5.3.2 L283-284，src/alpha 与 src/beta 同得 `src`）；`T ∉ anchors` 一律归外部无边无 gap（§5.3.3 L292-303，测试 #10-#14 L583-587） | RULE-02：A `import beta` → 无边、无 gap（被伪装成外部/未知） | **模块根解析**替代目录首段臆断：模块根=组件根 ∪ 构建配置声明目录（封闭键集）∪ 含包/模块内容的直接子目录 `src`；顶层名表（含 namespace）；解析优先级 自身→唯一他组件→歧义；**已知外部（stdlib 冻结集 ∪ manifest 静态声明依赖名）与未知导入区分**，未知入 `unknown_imports` typed 承载；相对导入按包上下文解析；动态 import 位点自计 `dynamic_import_site_count`（§5.3.1-§5.3.3）；与 `lima/python_dataflow.py` 只读语义对照（§5.3.5） | C2 类 `test_module_resolution_src_layout_cross_component` 等（§6 #11-#18）；D1R 探针 D6-RULE02 | 构建配置识别键集封闭（未识别配置→回退根+src 约定+未知承载）；stdlib 集为冻结快照（跨解释器版本稳定优先于穷尽）；不执行/install/sys.path 探测 |
| R60-06 | complete=False 封闭两触发（§5.2.4 L265-269）与 edge-limit 置 False（§5.3.4 L310-311）矛盾；"真实无依赖"不要求 gaps 空（L265-267）；解析失败靠"组件 RAM 继承"（§5.3.1 L276） | API-04：`parse_error_files=1` 而 RAM `coverage_gaps=[]`——"底层继承"不成立 | **单一封闭触发集 T1-T7**（组件数/python-file-limit/edge-limit/图自计 parse_error/图自计 read_failure/主仓 cap 截断/unbuilt 非空），全文唯一定义（§5.2.4）；三态判据表修订：空边集+缺口 ≠ 真实无依赖（机械可查）；解析/读失败由图层级 `ComponentScanSummary` 自计承载（不依赖"底层继承"四字）（§5.2.4/§5.3.1） | C5 类 `test_dependencies_complete_unified_triggers`、`test_parse_error_carried_in_graph`、`test_empty_edge_set_with_gap_not_no_dep` 等（§6 #30-#34）；D1R 探针 D5-API04 | read_failure 在静态快照下难以确定性构造（TOCTOU 类，归 F3/C）——承载字段保留、触发入封闭集、测试以默认零值+相邻触发覆盖并如实声明 |
| R60-07 | fixtures/golden "P&V 独占"却"Implementation 有效 RED 后产出、提交前经 P&V 核对 digest 链"（§4.2 L154-162）＝实现定义自身预期；测试 #7 断言"各 envelope content_digest 互异"（L580；§5.2.1 L245、§5.6.4 L537 同口径；§8 L645/§13 L698 依赖之） | API-05：不同组件根、相同局部内容 → content_digest 完全相等（`e11772ff…` 两例同值）——互异不是合法普遍不变量 | **Oracle 独立**：全部 expected/golden 由 P&V 在实现前独立产出并冻结（最小独立重算例：人工推导组件集/边/计数/三态 + 既有公共 `compute_content_digest` 对手写 canonical dict 独立重算 digest）；Implementation 只产产品代码与 schema，不生成/改期望；**删除"互异"断言**，替换为：相同内容两组件摘要**允许相等**且 component_id 可区分、内容变化→摘要变化、关联篡改被识别；D2 计划写入有效 RED + scratch/reference 非自相矛盾验证（PI-DR2 流程）；方法数=规划参考（§4.2/§6 注记/§13） | C6 类 `test_identical_content_components_equal_digest_allowed`、`test_component_identity_keyed_association`、`test_content_change_digest_changes`、`test_golden_expected_from_independent_oracle`（§6 #35-#41） | golden 全量 digest 值依赖既有公共 digest 函数的独立重算（该函数属既有冻结面，非新实现）；scratch/reference 细化在 D2 执行 |
| R60-08 | payload 只携带每组件三 digest，消费者"重放三段构建复算"（§5.4.6 L456；§5.5 L504-510、§5.6.3 L531、§5.6.4 L537 未闭合只凭公开 Artifact 的消费） | （设计缺口——违背"阶段间经版本化 Artifact 交换事实"；非探针反例） | **公开 Artifact 消费闭合**：图 payload 自身携带 scan_summary/semantic_topn/built/键控 digest 引用；每组件完整 Profile=既有 #58 envelope、完整 RAM=既有 IP-0021 RAM wire payload（阶段 Artifact 并行交换），图以 component_id 键控关联三 digest；消费例全程不重跑构建、不依赖构建者内存（§5.4.6/§5.4.8）；validator 单解清单十维（§5.4.8）；Unicode/字符集口径与输入范围声明一致 | C7 类 `test_consumer_obtains_all_facts_from_public_artifacts` + validator 检查测试（§6 #42-#49，覆盖 §5.4.8 V1-V10 十维）；§8 验收命令 | full semantic payload 的下游消费归 D/#64/#68（本片承载 ranked_candidate_ids+digest）；#58/54 帽/旧 digest/matrix 零扩展（若 ER 认定承载不足 → 具体 DR，不留不可消费摘要列表） |

R60-09（记录补齐）不属本 Assignment：归主会话/Coordinator 一次性最小处理（指令 §七）；P&V 未为此修改任何索引/登记文件。

## 0.2 v3 变更记录（ER Record `ERR-60-IP-0023-D1R-2026-10-09-v1` 三项 Shadow Finding 逐项处置）

每项格式：Shadow Finding（探针证据）→ 处置（落位节）→ 对应验收（测试符号）→ 剩余限制（如实）。修订范围仅限本表三项的最小回应（+随动的测试符号表增补与引用修正）；v2 其余设计零改动。（本表为 v3 时点处置记录；**v4 已按 P60-V3-04 将 SF-2 的四类盲点收口为元数据通道默认正例（§5.1.1/§5.1.7 重写，#54 断言改写）——如有出入，以正文 v4 版与 §0.3 为准。**）

| # | Shadow Finding（证据） | 处置（v3 落位） | 对应验收 | 剩余限制 |
|---|---|---|---|---|
| SF-1 | T 集盲区（产品缺陷）：E1 实跑 `skipped={non-utf8:1,file-size-limit:1,binary:1}` 且 `truncated=False` 时 T1-T7 全不触发 → `dependencies_complete=True`，三个 `.py` 在图输出零承载——与 §5.2.4"除 T1-T7 外无置 False 来源/不静默排除"矛盾 | **选纳入路线（fail-closed）**：T6 判据保守纳入主仓 `skipped` 中 `file-size-limit`/`binary`/`non-utf8`/`unreadable` 任一键计数 >0（公开 skipped 计数可支撑，无需 DR——"未看见不能成为安全证明"）；T6 触发时图 `coverage_gaps` 逐键落 `INVENTORY_SKIPPED`（detail `reason=<键>; count=N`，无文件名）；其余跳过原因逐项声明豁免+理由（§5.2.4；§5.1.1/§5.6.3 随动） | `test_admission_skipped_py_t6_incomplete_and_carried`（§6 #53） | `skipped` 公开计数无扩展名维度——非 `.py` 文件的 binary/non-utf8/file-size-limit/unreadable 跳过同样触发 T6（保守取向，如实声明）；四类豁免原因不触发 T6 属显式声明范围 |
| SF-2 | 锚点名集默认策略盲点（报告修正+验收缺口）：DEFAULT_EXTENSIONS 37 项无 `.txt/.cfg/.mod/.xml` → `requirements*.txt`/`setup.cfg`/`go.mod`/`pom.xml` 四类默认策略下恒不可准入为锚点；且冻结层 `_manifest_candidates` 用 raw os.listdir 绕过扩展策略——同一文件可作组件 Profile 的 manifest 证据却永不能锚定，不对称未披露 | §5.1.1 精确声明默认策略盲点：九类 kind 中默认可锚定五类（pyproject/cargo_toml/package_json/environment_yml/setup_py），**requirements/setup_cfg/go_mod/pom_xml 四类默认永不可锚定**（归宿=unassigned+skipped 计数可见，不产组件不编造）；与 `_manifest_candidates` 的"可作证据、不可作锚点"不对称显式披露（§3.1/§3.3 基座）；锚点通道**不**绕开扩展策略（绕开/扩 DEFAULT 列为 DR-IP-0023-03 备选，§13，默认不做） | `test_default_extension_anchor_blindspot_unassigned`（§6 #54） | 默认策略盲点为如实声明的范围限制（非需求缩减）；四类默认可锚定化需 DR（选项见 §13.5） |
| SF-3 | 三处措辞（无语义后果）：①§5.1.2"component:. 因 `.`(0x2E) 排序最前"为假（段字符集含 `-`(0x2D)）；②§5.2.1 extensions"构造器内部与 DEFAULT 的并集幂等"为假（构造器为 None→DEFAULT 的 **or 替换**；ignored_directories 才是恒并集）；③INV-OWN-2 的"秘密形态拒绝 `.py` 计数"独立项与 python_file_count/unassigned 划分未限定，可误读为双重计数 | 三句勘误（源码 @fbbbd619 亲验）：①排序仅为 component_id 字典序、根组件**不保证最前**（`-`(0x2D)<`.`(0x2E)，稳定性来自排序键单解）；②extensions=or 替换非并集、ignored_directories=恒与 DEFAULT_IGNORED_DIRECTORIES 并集、有效值回灌构造幂等；③INV-OWN-2 收敛为两项互斥完备划分式并废除独立秘密项（秘密形态已准入 `.py` 含于 python_file_count 或 unassigned_file_count，不另立第三项）（§5.1.2/§5.1.3/§5.2.1） | 既有 #9（INV-OWN-2 守恒）/#30（T 表驱动）随动覆盖；无新增方法 | 无 |

## 0.3 v4 变更记录（P60-V3-01..05 五裁定逐项处置；`MR-60-PR282-FINALIZATION-20261009/v1` §四 + D1F Assignment §P）

每项格式（指令 §八第 3 条四段式 + 未来部分）：原问题（v3 @d55a9f29 行号）→ 采纳裁定（指令 §四）→ 修订规则（v4 落位节）→ 真实 API/源码/参考证据（@fbbbd619 亲验；探针见 DI-027/附 D）→ D2 验收锚 → 仍属未来实现的部分（如实，不以"无 TBD"代替）。（本表为 v4 时点处置记录；**v5 对 P60-V3-01 行的共享层白名单按 CL-02 扩充为双清单视图（W-1 双参数 + W-2 并集过滤，§4.3.1 v5 版），激活条件随版本链改为本 Packet v5 获批；P60-V3-05 行的聚合池/读上界细节被 CL-03/CL-04 修订——如有出入，以正文 v5 版与 §0.4 为准。**）

| # | 原问题（v3） | 采纳裁定 | 修订规则（v4 落位） | 真实证据（亲验） | D2 验收锚 | 仍属未来实现 |
|---|---|---|---|---|---|---|
| P60-V3-01 | §5.2.1（L298-327）组件视图 = 继承五参数 + `ignored_directories \| {子锚点 basename}` 的 basename-ignore：名字碰撞目录触发 INV-OWN-1 分歧 → typed 不构建（已知限度 (ii)）；祖先组件 Profile 层 `_manifest_candidates` 混入子组件 manifest（已知限度 (i)）——二者被当作默认完成方案 | 采纳 DR-IP-0023-02 精确视图目标：选**文件清单视图**（P&V 冻结单解，弃路径级排除方案——单一机制即约束三入口，无需双份簿记）；所有权按最深合法锚点；三入口（inventory/读取/_manifest_candidates）全链约束；父 Profile 不纳入子组件 manifest；同名非子锚点目录 = 正例；`unbuilt` 收缩为真拒绝/资源耗尽/无法成视图三类可区分 | §5.2.1 重写：`RepositoryWorkspace(root, 五参数继承, admitted_files=精确切片文件集)`；INV-OWN-1 由构造成立+事后机械复核；§5.2.1-new 三入口调用链小节（公开签名/缺省兼容/预算/测试锚逐项）；§5.1.3 INV-OWN-3（manifest 元数据所有权）；§4.3.1 条件性共享层 additive 白名单（workspace `admitted_files` + inventory `_manifest_candidates` 过滤，本轮零实现）；已知限度 (i)(ii) 撤销 | `inventory.py` L392-417 `_manifest_candidates` raw `os.listdir` 不消费 inventory 文件集/不读 ignored_directories/无扩展过滤（仅给 inventory 加排除参数不构成约束——三入口须显式覆盖）；`workspace.py` L112-137 构造器五参数现状；v3 D7-COLLISION 探针（basename 分歧机械可检） | `test_detect_components_same_name_dir_not_nested_anchor_builds`、`test_parent_component_profile_manifest_excludes_child`、INV-OWN-1/2/3 守恒扩展（#9/#10 扩展+#55/#56） | 共享层 additive 白名单两项（激活条件=本 Packet v4 获 Maintainer 批准合并；获批前实现层仍以白名单外零触碰为界）；受限态组件视图与 INV-OWN-3 的产品实现全部属 D2 后 |
| P60-V3-02 | §5.4.7 消费示例四点缺陷（L639/L643/L644/无 semantic 核对）；§5.4.3 L548 "不 import ram_schema" 与 §5.4.6 "产出 RAM wire" 矛盾；wire 产出未声明传实际生效 budgets/options | 只读复用 ram_schema 公共接口（不复制/不重定义摘要、gap、execution_required 规则）；消费示例四点修正并**逐字采用指令 §四内嵌 API 基准代码**；产出 wire 传实际生效 profile/ram budgets 与 semantic_options，禁回填默认；有效配置承载写入接口与返回结构 | §5.4.3 依赖方向 +`lima.audit.ram_schema`（只读复用）；§5.4.7 消费示例整体替换为内嵌基准（逐字）+ 外围叙述；§5.4.6 三 digest 核对路径重写（facts/semantic 两函数对 entry 槽、wire digest 只对 identity.wire_digest、gaps 两 section+execution_required 复算）+ 有效配置承载（`ComponentBuildResult` 携带 effective 配置、payload build 段自洽、无默认回填）；§5.6.3 改写 | `ram_schema.py` L268-377（`ram_wire_payload(…, *, profile_budgets/ram_budgets/semantic_options=None)` 预算/options 进 build 段→wire digest，None=层默认=回填即自洽破坏点）、L495-505/L551-595（两摘要重组函数）、L454-486（wire digest=build+三身份摘要，wire_digest 槽不参与）、L236-258（execution_required 10 码全集/9 触发/OFF 永不触发）；`profile.py` L1238-1254（`decode_profile_envelope(data: bytes)`）；`semantic_prioritizer.py` L623-660（两冻结 digest 形与 wire 重组一一对应）；**离线消费探针对 golden application.json 实跑 12/12 过**（附 D：validate 通过、facts=84fec013…/semantic=8aecae4e…两摘要复算、wire=b92a2aa4… 且 ≠facts digest、顶层无 coverage_gaps、execution_required 复算一致、篡改被拒、bytes 解码/JSON 对象被拒） | `test_consumer_obtains_all_facts_from_public_artifacts`（#42 重写：bytes 解码+三摘要分别核对+gaps 两 section+execution_required 复算+篡改被拒）、`test_component_ram_wire_effective_config_no_default_backfill`（#57）；#36/#47 随动 | 真实 graph 的端到端消费（D2 绑定真实 graph payload 后）；本轮探针仅验证"已有部分"（既有 golden+既有公共 API），不声明未实现的 graph 已可调用 |
| P60-V3-03 | §5.4.3 L495-501 MonorepoBudgets 允许任意 ≥1 正整数，而 §5.4.8 V8/§5.5 schema 把数量 cap 固定在默认值（16/4096/…）——矛盾；`semantic_topn` ≤20 cap 与 SemanticOptions `top_n=1..100` 冲突；零额度降级路径未定义非法对象防线 | 默认值/合法域/硬上限**三分离**（构造期校验=合法域、schema maxItems=独立硬上限）；`max_components=17`/`top_n=21`/紧 cap 唯一行为；图承载对齐 `top_n=1..100`（默认 20 非帽）；零额度降级不构造非法 SemanticBudgets/不填伪 digest/不删已得事实，部分产物过自身 validator | §5.4.3 MonorepoBudgets 重写（每字段 默认/域/帽 三列）；§5.4.4-new 参数边界行为表（逐样例唯一判定）；§5.4.8 V7/V8 + §5.5 表统一（schema maxItems=域帽；`semantic_topn` 增 `top_n` 承载字段，ranked cap=top_n 实际生效值，schema maxItems 100）；§5.4.4 降级路径细化 | `semantic_prioritizer.py` L80（`SEMANTIC_MAX_TOP_N=100`）、L258-268（`top_n` 域 [1,100] 越界 ValueError）、L221-246（SemanticBudgets 全字段正值+总量≥prompt+output 构造校验——`max_llm_calls=0` 非法即冻结事实）；`ram_schema.py` L379-452（validator 六步完整性=部分产物过自身 validator 的可执行面） | `test_monorepo_budgets_invariants`（#24 重写：三分离）、`test_parameter_boundary_unique_behavior`（#58）、`test_partial_products_pass_own_validators`（#59）；#7/#46 随动 | 域帽具体数值（64/16384/1024/4096/…）属本 Packet 冻结设计但产品实现与 schema 落盘在 D2 后；动态 schema 校验路线已被弃（单解=静态独立硬帽） |
| P60-V3-04 | §5.1.1 L237 四类（requirements*/setup.cfg/go.mod/pom.xml）默认永不可锚定的声明式盲点 + §3.3 单集合表述"发现范围=已准入 inventory"；ER addendum-1 判定该盲点为"声明承载而非消除" | 采纳 DR-IP-0023-03 受控元数据通道方向（备选→已采纳设计；选项 B 触 DEFAULT_EXTENSIONS 仍禁止）：九类 manifest 默认策略正例（四类原盲点尤其）；两个输入集合（可分析源码集/可只读发现的 manifest 元数据集）分离，各自准入/所有权/计数/provenance；封闭只读有预算；严格 admitted-only 策略可选且不被悄悄失效；跳过计数分通道；不重新准入源码 | §5.1.7 新增"受控 manifest 元数据通道"设计节（九类封闭名集、默认/严格两策略、数量+字节预算、分通道跳过计数、只读安全边界全列）；§5.1.1 盲点声明重写为通道默认正例；§5.1.3 两集合判据表+INV-OWN-3；§13.5 DR-IP-0023-03 改已采纳方向；#54 断言改写（默认正例+严格负例） | `workspace.py` L11+（`DEFAULT_EXTENSIONS` 37 项不含 .txt/.cfg/.mod/.xml——通道绕开的是"锚点可见性"而非源码准入）；`inventory.py` L147-150+L392-417（`_MANIFEST_EXACT_NAMES` 8 类+`requirements*.txt` 模式=九类来源，值重述）；ER addendum-1（`c9402a9d…88a8`）"声明承载而非消除"判定 | `test_manifest_metadata_default_positive_and_strict_negative`（#54 重写）、`test_manifest_channel_no_source_readmission`（#60）、`test_two_input_sets_counts_and_provenance_separated`（#61） | 通道的产品实现（含 `ComponentManifestRef.source` 字段、metadata 预算字段）属 D2 后；本轮仅设计冻结；调用方严格策略的公共参数形态在 D2 定稿签名时锁定（语义本轮锁定） |
| P60-V3-05 | §5.4.4 L554 默认 `max_total_model_calls=128`（=16×8）提案；聚合 token 无池设计；三口径（单次预估/每组件额度/全仓累计）未区分；读放大无计量 | **128 否决**：模型默认 off；启用 fake/获准客户端时**全仓默认调用额度 8**（尝试次数口径，超时/失败计入）；更高=显式配置+政策授权（本轮不授予）；聚合 token 池（数值/单位/预调用计量/预留/耗尽/失败行为；保守默认 ≤ 调用方 SemanticBudgets 对应值）；三口径区分不改旧 SemanticBudgets；耗尽=静态事实+确定性 Top-N+typed gap+三摘要可验证；读放大计量+可核验上界 | §5.4.4 整节重写：聚合模型调用包络（默认 8、尝试口径、政策授权点）；聚合 token 池三字段（默认=单组件 SemanticBudgets 值，不放大）；三口径声明（含冻结代码行号锚）；降级语义（BUDGET_EXHAUSTED detail 口径、不造非法对象、部分产物自洽）；§5.4.4-new 计量小节（重扫/AST/manifest 三类读取的累计次数/字节计量与公式上界；`ResourceMetering` 结果承载）；§0.1 R60-03 行、§6 #21/#24、§13.3 随动 | `semantic_prioritizer.py` L439-470（每组件语义内部：L451 `calls_made >= max_llm_calls`、L456/L459-460/L463-465 三项**单次预调度预估校验**、L469-470 墙钟——全部每组件口径）、L221-246（SemanticBudgets 定义=每组件语义）、L344-345（`_estimate_tokens=ceil(chars/4)` 冻结估算器）——旧字段无一是全仓累计池（v3 L554 的 128 即被否决对象）；附 D 探针（golden build.semantic.budgets=每组件 8/24000/4096/28096/120 实测） | `test_aggregate_model_call_envelope`（#21 重写）、`test_aggregate_token_pool_exhaustion_typed_degradation`（#62）、`test_read_amplification_metered_and_bounded`（#63）；#25 随动 | 真实模型客户端永不入本片（政策授权另批）；聚合墙钟/F3/F4 物理强制上界仍归 C（本片不宣称）；计量承载的产品实现属 D2 后 |

## 0.4 v5 变更记录（CL-01..05 五项跨层契约修订逐项处置；`MR-60-PR282-CROSS-LAYER-CORRECTION-20261010/v1` §四 + D1X Assignment §P）

每项格式（指令 §四前言四段式 + 已授权选择点 + 未来部分）：旧反例（探针 ID+实测值，`review_probe_results.json` @`a7c73a58`，v4.1 行号锚）→ 采纳裁定（指令 §四）→ 唯一修订规则（v5 落位节）→ 源码/真实 API/参考证据（@fbbbd619 或本轮探针）→ D2 验收锚 → 仍属未来实现的部分（如实）。**五项规则联合演算一致（§5.9），不各改一句后互相冲突。**

| # | 旧反例（v4.1 定位） | 采纳裁定 + 选择点 | 唯一修订规则（v5 落位） | 源码/真实 API/参考证据 | D2 验收锚 | 仍属未来实现 |
|---|---|---|---|---|---|---|
| CL-01 | **RULE-COMPLETE**（字面规则推演）：根 pyproject+两子 setup.cfg、S2 数量帽漏第二锚点后 T1-T7 全 False、`truncated=False`、`metadata-manifest-limit:1`，却 `dependencies_complete=True` 且同时命中三态表"真实无依赖"与"证据不足"两行（v4.1 §5.1.7 L328-330 / §5.2.4 L424-446 / L637） | S2 证据丢失事件进入完整性判据；数量/字节停止、读/解码失败 fail-closed；政策主动拒绝与证据丢失逐类归置；唯一 completeness 决策表及分类优先级；**选择点（T 集扩展 vs discovery 状态改造）：选定 T 集扩展（新增 T8），discovery 状态字段不扩语义** | §5.2.4：封闭触发集扩为 **T1-T8**（T8=S2 元数据证据丢失：通道跳过计数中 `metadata-manifest-limit`/`metadata-byte-limit`/`unreadable`/`non-utf8` 任一键>0 或对应 BUDGET_EXHAUSTED gap）；三态分类改写为**优先级式唯一决策表**（解析失败>证据不足>真实无依赖，单遍历机械可判，全合取含 `dependencies_complete==True`）；§5.1.7 通道跳过七键逐键归类（四键=证据丢失入 T8；`ignored-directory`/`sensitive-filename`/`symlink`=政策豁免，准入范围显式；严格策略下通道未运行不产生丢失事件）；`discovery.truncated` 语义不扩（仍=组件数截断，L637 限度由 T8 专属承载消除）；承载=既有 typed gap（detail reason+count）+通道计数双承载对账（count 相等、字段分列）；payload/validator（V7）/消费说明同义 | 反例夹具四变体（数量帽/字节帽/读失败/解码失败）在 v5 决策表下逐一演算：T8 触发→complete=False→"真实无依赖"全合取不成立→唯一落入"证据不足"（§5.9 演算 4）；本轮参考模拟探针复核（附 E）；`inventory.py` L603-649 旧 Profile `GAP_BUDGET_EXHAUSTED(reason=manifest-index)` 先例=同构落图级完整性规则 | `test_metadata_loss_count_cap_incomplete_not_real_no_deps`（#64）+ 字节帽/读失败/解码失败三变体各一负例（#65-#67）+ partial payload 公开消费正例（#68，与 CL-05 联合） | T8 触发与决策表的产品实现、partial payload 真实消费绑定属 D2 后；read_failure 静态快照下难确定性构造的既有声明保留（以可构造变体+默认零值覆盖并如实声明） |
| CL-02 | **API-META**（冻结 API 实测+字面 W-2 过滤模拟）：夹具 main.py+requirements.txt=`flask==3.0`，旧 Profile `frameworks=[flask]`/`package_managers=[pip]`；字面 W-2 的 S1 成员过滤后 `W2_manifest_candidates=[]`、两项事实均空（v4.1 L243-244 / L317） | 源码视图保持 S1 精确切片；Profile 对本组件获准 manifest 元数据有单独受控读权限/候选范围；父不读子 manifest；S2-only 不重新准入源码；**选择点（两类 allowlist / 受控 metadata 载体 / 等价方案）：选定两类 allowlist（双清单视图）** | §4.3.1 W-1 增第二 keyword-only 参数 `metadata_files`（组件获准自身 manifest 清单，=该组件 manifests[] 的组件内坐标集）：受限态 `inventory()` 仍仅 `admitted_files`（S1 切片不动）；`read_text`/`absolute_file` 准入=`admitted_files ∪ metadata_files`；W-2 `_manifest_candidates` 受限过滤集=同一并集；缺省 None 逐字节同旧；S2-only 仍不计 python_file_count/不进 AST/不进 Profile inventory 维度（§5.1.7 不变）；九类"可发现"与"旧解析器支持何种信息"分开声明（§5.1.8）；全部读入口/能力边界/调用链/兼容论证/预算计量落更新的 W-1/W-2 表（§4.3.1 重写） | `inventory.py` L392-417 `_manifest_candidates` 独立 os.listdir 不消费 inventory 文件集=旧 Profile 能取得自身 manifest 事实的机制（API-META 所复现）；L1085-1094 Profile 链先 inventory 再 manifest+源码读取；v5 双清单字面模拟：`admitted_files=[main.py]`、`metadata_files=[requirements.txt]`→候选=[requirements.txt]→flask/pip 保留（附 E 参考模拟；反例不可达） | `test_profile_own_manifest_facts_preserved_under_s1_view`（#69）、`test_parent_child_distinct_requirements_isolated`（#70）、`test_s2only_not_source_readmitted`（#71）；strict/secret/ignored/symlink 负例沿用 #54/#55/#56/#60 扩展 | W-1/W-2 双清单的共享层实现属条件白名单（激活=本 Packet v5 获批合并）；受限态组件视图与 Profile 自身元数据读取的产品实现全部 D2 后 |
| CL-03 | **API-POOL**（冻结 API+全仓池 proxy）：caller `SemanticBudgets(2, 1000/500/1500)`，四次组件构建 8 次尝试逐次护栏全过，按 v4.1 估算与预扣规则全仓累计预留 prompt=1684/output=2048/total=3732 三项均超 caller 对应值而默认池 24000/4096/28096 未耗尽（v4.1 L691-692——L692 补注"先触发的总是口径 1/2 护栏"被反例限定） | 聚合层不得把"逐次护栏仍通过"解释为"累计约束满足"；保守缺省 effective 三池分别 ≤ 实际生效 SemanticBudgets 对应值；**选择点（实际调用方派生默认 / 对应值 min）：选定对应值 min**；较大 caller 不自动扩池；显式提高单列政策授权；预扣/不足/不退/零额度降级/effective 承载单一规则；不得构造 `max_llm_calls=0` | §5.4.4 重写聚合池节：requested（MonorepoBudgets.aggregate_max_*，默认 24000/4096/28096）/default（层默认常数=同值）/effective（**= min(requested 三字段, 实际生效 SemanticBudgets 对应字段)**，计算函数+四类对照表）三值定义；有效池在调度前生效——1684/2048/3732 调度在 min 下不可达（caller 1000/500/1500→effective=1000/500/1500，第 2 次尝试 output 剩余 244<256 即止）；预调用估算/预扣/remaining 不足/失败不退/零额度合法降级（无 client 形态+typed gap+不造非法对象）/effective 配置承载（wire build 段与 payload build.monorepo_budgets 均为 effective 值）/摘要承载（计量不进任何 digest）单一规则；模型 off 不消耗池、不误伤静态事实（SEMANTIC_MODEL_OFF 不计入依赖证据口径不变） | `semantic_prioritizer.py` L221-246（SemanticBudgets 正值约束——`max_llm_calls=0` 不可构造）、L439-470（逐次护栏全部每组件口径——旧字段无一全仓累计池）；API-POOL 反例在 min 规则下重演：累计截止于 212/256/468 ≤ 1000/500/1500（附 E 参考模拟）；ER v1/addendum-1 B2 三口径更正=台账侧动作（主会话/Coordinator 执行，P&V 不改远端历史） | `test_aggregate_token_pool_exhaustion_typed_degradation`（#62 **恢复自定义小预算断言**——删除"默认调用方"限定语，小 caller 累计截止+typed gap+静态事实与确定性 Top-N 保留+有效 build 配置一致）、`test_effective_pools_min_caller_graph_scheduling`（#72，默认/小/大/显式更高四类对照的 graph 级调度，非单独数学表） | 真实模型客户端与更高额度的政策授权另批（本轮不授予）；effective 池的 graph 调度产品实现属 D2 后 |
| CL-04 | **API-IO**（冻结 API 实测）：单 main.py 无 manifest 无错误，指定三段链路（预检 inventory→Profile→RAM）`Path.read_bytes` 实测 5 次（预检/Profile inventory/Profile source/RAM inventory/RAM source），切片文件数=1，v4.1 L706 上界=1 被超（图 AST 与 S2 尚未计入；现有 workspace 无读取缓存） | 分别定义 distinct files/读取尝试次数/成功字节/通道阶段归属四种单位；计入 inventory、Profile source/manifest、RAM source、graph AST、S2 通道及失败/unbuilt 前已发生工作；保守常数倍上界优先；**选择点：选定保守常数倍上界；快照缓存=可选设计项、零实现、本轮不采纳**（§4.3.2 列明采纳前置要件，不入白名单） | §5.4.4-IO 整节重写：**IO 计量域表**（S0 主仓 inventory/S1 预检/S2 Profile inventory/S3 Profile manifest/S4 Profile source/S5 RAM inventory/S6 RAM source/S7 图 AST/S8 S2 通道，九阶段尝试计量+成功字节+distinct files 由集合计数承载）；`ResourceMetering` 六字段重写为尝试口径（含失败尝试与 unbuilt 前已发生）；上界公式替换 L706：`component_rescan_read_attempts ≤ 5×Σ(全部锚定组件切片文件数)`（.py 每文件链内 5 次、非 .py 4 次，常数 5 封顶）+ `profile_manifest_read_attempts ≤ Σ(组件 manifest 候选数)` + `metadata_channel_read_attempts ≤ max_metadata_manifests` + `ast_read_attempts ≤ 归属 .py 总数` + `main_inventory_read_attempts ≤ discovered_files`；全链 `total ≤ 7×discovered + 2×manifests_discovered + max_metadata_manifests`（保守合成式，7=主仓 1+组件链 5+AST 1）；成功字节 ≤ 尝试数×max_file_bytes；预算截断=各通道既有 cap 触发即停+typed gap（无独立新 IO 预算，上界由公式封闭）；不为上界削正常画像、重复读全计量 | `workspace.py` L202-256（inventory/read_text 均实际 read_bytes、无缓存）、`ram.py` L429/L465-469（RAM 重执行 inventory+逐候选读取）、`inventory.py` L1085-1094（Profile 链先 inventory 再 manifest+源码）——单 main.py 5 次读取由该结构机械复现（API-IO 实测）；v5 上界对实测账成立：三段链 5 ≤ 5×1，全链 7 ≤ 7×1+0+0（附 E 参考模拟复核单位与路径） | `test_read_amplification_metered_and_bounded`（#63 按新公式随动重写：真实新链路累计读取含失败/unbuilt，断言真实计量与保守上界，防只数 distinct paths） | 快照缓存零实现（若未来采纳须先 Packet 修订+白名单条目，§4.3.2 前置要件已列）；F3/F4 墙钟与真实模型物理强制上界不宣称（归 C）；计量产品实现属 D2 后 |
| CL-05 | **RULE-COUNT**（字面规则推演）：①单根 pyproject 同属 S1/S2：通道发现=1、provenance 单值=`source-inventory`、metadata-channel 来源计数=0，v4.1 L838 V7 要求 1=0；②根 Cargo.toml 仅 `[workspace]` 不产根组件（L274）却仍属"已发现 manifest"，L299 INV-OWN-3 划分等式 1=0+0 不可满足；秘密锚点数被当文件数（单位混用） | 修正 `metadata_manifest_count` 冲突含义；发现/尝试读取/成功读取/S2-only 来源/最终发布条目各自计量域及映射；同名字段全链唯一语义；不得只计发布条目放弃通道预算、不藏条目追平数字；**选择点（哪些计量进 payload）：选定——发现域四计数字段进 payload 且进 canonical dict（digest 防篡改）；读取尝试/成功字节只进 metering（ResourceMetering，不进 payload/digest）** | §5.1.8 新增**五计量域联合参考表**（发现/尝试读/成功读/S2-only 来源/发布 × overlap/多 manifest 同锚点/协作 manifest/拒绝/截断/strict 全组合）；`metadata_manifest_count` 单义化=S2 通道发现总数（**含 S1∩S2 重叠成员**；预算消耗同口径）；新字段 `manifests_discovered_count`（S1∪S2 去重）/`collaboration_manifest_count`/`overflow_manifest_count` 进 DiscoveryResult+payload+canonical dict；**INV-OWN-3 重写**：manifests_discovered_count == Σ_C\|manifests(C)\| + collaboration_manifest_count + overflow_manifest_count（文件级、无秘密项——秘密子树段级剪枝先于枚举不属发现域，锚点拒绝计数独立承载不混单位）；**V7 重写**（守恒式+`metadata_manifest_count ≤ manifests_discovered_count`+`Σ(S2-source 发布) ≤ metadata_manifest_count`+gap detail 与通道计数对账相等）；预算口径（通道发现含重叠成员计满 max_metadata_manifests）、canonical projection/digest（四计数字段入 canonical）、consumer（§5.4.7 外围收尾）同步改写 | 反例①在 v5 下：manifests_discovered=1==Σ\|manifests\|(1)+0+0 ✓、Σ(S2-source 发布)=0 ≤ metadata_manifest_count=1 ✓（映射表：重叠成员发布 source=source-inventory=发布事实来源视图，与发现计量域分离——不再 1=0）；反例②：协作 manifest 进 collab 项，等式 1==0+1+0 ✓；多 manifest 同锚点按文件计；秘密锚点不进发现域（单位混用消除）；（§5.9 演算 2；附 E 参考模拟） | `test_v7_v8_overlap_and_collab_manifest_metering_domains`（#73：overlap/协作/截断失败的发现计量、归属计量正例；篡改负例仍拒）+ 与 CL-01 partial payload 公开消费联合断言（#68） | 计数字段与联合参考表的产品实现、validator 新判据、真实 consumer 绑定属 D2 后；`metadata_channel_skipped` 保持 payload 承载但不进 canonical（经 V7 对账+词表校验承载，不宣称 digest 级防篡改——如实声明） |

---

## 1. Goal / Non-goals

### Goal

1. 新增 `lima/audit/component_graph.py`：确定性、只读、stdlib-only 的 monorepo 组件层——**嵌套**组件识别（manifest 锚定 + 静态 workspace/build 配置 + 包结构/导入证据组合，仓库级坐标、有界、确定顺序）、**单一真实归属**（最深锚点前缀精确划分 + 机器可校验所有权不变量；**精确文件清单视图**（§5.2.1，P60-V3-01 冻结单解）约束 inventory/读取/_manifest_candidates 三入口）、每组件 Profile/RAM/semantic 全链（**复用三层冻结公共接口** `build_repository_profile` / `build_python_ram_facts` / `build_semantic_top_n`，组件 workspace 继承调用方策略；**RAM wire 产出/校验/消费只读复用 `lima.audit.ram_schema` 公共接口**（P60-V3-02，不复制不重定义其摘要、gap、execution_required 规则））、组件间依赖分析（resolved / ambiguous / unresolved 边 + **未知导入 typed 承载**，AST import 证据 + provenance）、**仓库级秘密形态准入先于坐标变换**、**统一完整性触发集**、**受控 manifest 元数据通道**（P60-V3-04，九类默认正例、两输入集合分离）、**聚合预算新设计（fail-closed；全仓默认 8 次尝试口径 + 聚合 token 池，P60-V3-05）**；
2. 新增 `schemas/v4/lima.component-graph.json`：独立版本化 component graph wire schema（**不注册 version_compatibility_matrix**，BG-60-01 口径），携带仅凭公开 Artifact 即可消费/核对全部五类事实的承载；
3. 图与每组件产物经独立 digest 关联（`component_graph_digest` 64-hex + 每组件三 digest 键控关联；相同内容不同组件允许摘要相等——身份用 component ID/坐标/版本表达），**沿用 IP-0019 B-10 独立承载先例**（DI-007：v4 RepositoryProfile 非空 extensions 即拒）；
4. monorepo golden fixture（可重放、排序稳定、输入顺序无关；**expected 由 P&V 独立产出并在实现前冻结**，不由实现输出定义）。

### Non-goals

- 不修改 `lima/audit/__init__.py`（`__all__` 54 帽零触碰，见 §5.6.1）；
- 不修改三层冻结面 `lima/audit/{inventory,ram,semantic_prioritizer}.py`、`lima/audit/ram_schema.py`、既有 tests/audit 全部测试与 fixtures、既有 schemas/v4 15 文件、`lima/contracts/**`、`lima/workspace.py`——**唯一例外**：§4.3.1 条件性共享层 additive 白名单（`lima/workspace.py` 双清单视图参数（v5：`admitted_files`+`metadata_files`） + `lima/audit/inventory.py` `_manifest_candidates` 并集受限过滤；DR-IP-0023-02+CL-02 已采纳目标的落点，激活条件=本 Packet v5 获 Maintainer 批准合并；**本轮零实现**，白名单外的一切共享层修改仍禁止）；`lima.audit.ram_schema` 只读复用其公共接口（P60-V3-02 授权，非修改）；
- 不把图挂入 `RepositoryProfile` / `AttackSurfaceEntry.extensions` / RAM wire payload / 任何 #58 envelope（B-10 + Assignment 冻结约束）；
- 不扩展 digest 家族既有成员语义（ram_facts/semantic_config/semantic_result/prompt/model/wire 六 digest 原样；新增的 `component_graph_digest` 是独立新成员，不改不动旧成员）；
- 不执行、不 import、不安装目标项目；不通过目标脚本补证据；不引入网络/付费模型调用（semantic 默认 off；有界离线 fake client 仅限设计反证与测试，不调真实模型——指令 §五 R60-03）；
- 不处理 F3/F4 强制约束与聚合墙钟证明、安全停止端到端、FR-01 全 vocabulary 内部留痕、#64/#68 消费接线（见 §0 Not covered）。

---

## 2. Design Input Manifest

| Input ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001 | Standard | `docs/LIMA_PACKET_AND_VERIFICATION_AGENT_RESPONSIBILITY_CHARTER.md` | main @fbbbd619 | Packet 结构、Manifest/Rejected 要件、RED/冻结/验证边界 | normative | 最高优先级之一，冲突时停止 |
| DI-002 | Standard | `docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md` | main @fbbbd619 | 不执行/路径有界/fail-closed 不变量、验证命令底线 | normative | 同上 |
| DI-003 | Standard | `docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md` §8/§9 | main @fbbbd619 | Packet Gate 全清单、分支拓扑、禁自动关闭关键字 | normative | 同上 |
| DI-004 | Decision | Coordinator Assignment `ASSIGN-60-CLOSURE-A-PKT-D1_v1`（SHA-256 `5a118ea9603c67663a63c17da7db203a705edecddd60ed0f06c77b5f2d573b82`）+ **`ASSIGN-60-CLOSURE-A-PKT-D1R_v1`（SHA-256 `30a0e9198bd3914e3c2ea511f8d5ad523addabd1496dc654ce755d03d61c040a`，D1R 唯一任务合同，读取前重算一致）**；D1R 明示：D1_v1 的 Goal/Frozen Interfaces/安全基线/停止条件继续有效，除本文明确修订或收紧处 | 2026-10-09 | v2 范围（R60-01..08 逐项修订要求、T 节七类测试计划、Acceptance 1-7、停点） | normative（唯一任务合同） | 与其他输入冲突时以 Assignment 为准并提交 Decision Request |
| DI-005 | Decision | `ALLOC-IP-0023-60-CLOSURE-A/v1`（#60 Ledger 恢复记录条目内，live 亲取） | 2026-10-09 | IP-0023 编号有效性、首片范围、禁令与失效条款 | normative | 编号失效（对端先占用）→ 停止上报 |
| DI-006 | Issue | Source Issue #60 live 正文 + Delivery Ledger | 2026-10-09 API 亲取（v1 制作时；body SHA-256 `477ad50c…f8180`） | L28 AC-01、L65 边界矩阵、L77 V5-FR-03、L82-83 V5-AC-01/02、Ledger 7/6/4 覆盖矩阵与切片归属 | normative（需求范围） | V5 覆盖层优先于 V4 正文 |
| DI-007 | Decision | 恢复审计链：`RESUME-AUDIT-60-2026-10-09_v1`（SHA-256 `74ad8c13…9b71`）+ addendum-1（`852e2d05…7e7ef`）+ addendum-2（`e9dbbb58…1bd31`） | 2026-10-09，SHA 全部重算一致 | workspace 漂移定性、五 IP 消费面结论（43/43）、切片归属表、停点条款修订版、开放 PR #266/#281 零交集 | normative | — |
| DI-008 | Decision | Maintainer 批复 `MR-60-RESUME-APPROVAL-20261009/v1`（正文 SHA-256 `e4bcc9c3…cabb`） | 2026-10-09 | §五（D1 边界）、§六（七条产品目标与设计边界、已否决路线、安全基线） | normative | 已否决路线不得重试 |
| DI-009 | Upstream IP | IP-0016 Packet v1.2（`docs/LIMA_Implementation_Packet_IP-0016_Repository_Profile_Layer1.md`，@fbbbd619 亲读） | main @fbbbd619 | manifest 候选口径（D4）、`build_repository_profile` 签名与 sentinel digest、LF 口径（DR-IP-0016-02/PI-DR6） | normative（先例+接口） | 只读消费 |
| DI-010 | Upstream IP | IP-0018 Packet v1.1 + IP-0019 Packet v1.2（含 B-10/DI-007 独立承载先例、candidate_id 冻结编码、SemanticBudgets 勘误值 28,096） | main @fbbbd619 亲读 | 每组件 RAM/semantic 复用路径、B-10 承载先例、降级语义 | normative（先例+接口） | 只读消费 |
| DI-011 | Upstream IP | IP-0021 Packet v1.1（wire schema 先例、GAP_CODES_ALL 10 码、execution_required 9 码定案、golden matrix 模式、matrix 不注册先例）+ IP-0022 Packet v6（`is_secret_shaped_path` 准入口径、R1 终案 reason→count、manifest-index 稳定标识先例、AdmissionSkipRecord） | main @fbbbd619 亲读 | wire schema 风格、gap 复用口径、隐私准入、NFR-01 五面口径 | normative（先例+接口） | 只读消费 |
| DI-012 | Code | 三层冻结面 + ram_schema + `__init__.py`：`lima/audit/{inventory,ram,semantic_prioritizer,ram_schema,__init__}.py`（@fbbbd619，§3.1 逐符号 import 亲验；`__all__` 恰 54 项 + 冻结断言；**两层入口 `isinstance(workspace, RepositoryWorkspace)` 硬校验 + 自行调用 `workspace.inventory()`——R60-02/03 设计的可行性边界**） | @fbbbd619 | 全部公共签名/常量/预算默认值/错误语义的精确消费面 | normative（接口冻结） | 漂移 → DR 停点 |
| DI-013 | Code | `lima/workspace.py`（@fbbbd619 亲验：构造器五策略参数 max_files/max_file_bytes/max_total_bytes/extensions/ignored_directories；`ignored_directories` 按**目录名**剪枝、无路径级排除；`inventory()` 递归扫描 root 并返回 `files` + `skipped: dict[reason→count]` 公开计数字段；`read_text` 有界 UTF-8 无换行归一；`_safe_path` 边界）+ `lima/contracts/profile.py`（`encode/decode_profile_envelope`、`_validated_path`、`_validated_extensions` v4 非空 extensions 拒绝、`RepositoryKind.MONOREPO="monorepo"`）+ `lima/contracts/codec.py::compute_content_digest` + `lima/contracts/errors.py::ContractError`（UNKNOWN_FIELD/INVALID_FIELD_TYPE/INVALID_FIELD_VALUE） | @fbbbd619 | 输入域口径、策略继承可行性、#58 契约消费、错误码复用、独立 digest 重算 | normative（契约冻结）+ current-behavior（workspace） | workspace 行为以当前 main 为准，不当作隐式新能力 |
| DI-014 | Test | tests/audit 既有 10 测试文件（235 用例基线锚，含 IP-0022 51 例回归锚）+ 五形态 golden + `fixtures/repo_shapes.py` helper 先例 | @fbbbd619 亲验文件清单 | 回归零破坏边界、fixture 构造模式 | normative（回归锚） | 计数变化需解释（addendum-2 §3 修订版），不删测试追平 |
| DI-015 | Decision | PI-DR1..PI-DR6 | Ledger 2026-09-12/13 | arrange 平台中立（LF 钉死）、冻结前非 Windows 完整跑一次、PR 禁 close 关键字、PI-DR2 scratch/reference 非自相矛盾流程（R60-07 D2 计划引用） | normative | — |
| DI-016 | Decision | DR 链：DR-IP-0016-01/02、DR-TOPN-01、DR-IP-0021-0102（DR-1/DR-2）、DR-IP-0022-01/02/03/04、DR-C1、IP-0024 Packet §0.1/DI-013 | Ledger + docs @fbbbd619 | digest sentinel、LF 重冻结先例、B 组批准值、9 码触发、准入/R1 终案、编号预留依据 | normative | — |
| DI-017 | Decision | **Maintainer 修订指令 `MR-60-PR282-GOAL-CORRECTION-20261009/v1`**（机械抽取正文 `.pv_tmp/issue60-resume-2026-10-09/authorization/v3/PR282_CORRECTION_BODY.md`，SHA-256 `4f7134551994f521f94f722eb9ef5a41b2f8da85246aca2b6edbdd1f220edd89`，读取前重算一致） | 2026-10-09 | §五 R60-01..08 修订方向、§六 七类测试计划与 ER 承重主张、§二 本轮允许/不允许、§八 呈审终点 | normative（最高需求权威） | 与 v1 设计冲突处以指令为准 |
| DI-018 | Review | **回顾文档 `docs/LIMA_Issue60_Goal_Process_and_PR282_Retrospective_2026-10-09.md`**（SHA-256 `00483bd67ada7352c6f077c6d26dafcc465f6285faee2b106b0c936e87c6658b`，main 工作区） | 2026-10-09 | §5 R60-01..08 行号锚点（本 Packet §0.1 引用）、§8 长程约束、需求映射表 | normative（背景裁定建议） | — |
| DI-019 | Evidence | **反例证据**：`output/issue60-pr282-retrospective-2026-10-09/review_probe_results.json`（SHA-256 `90f3d975f18ea2e479dd6631c40508a17883afb58eaac073a1471ac3eeacb8a4`）+ `github_snapshot.json`（`9b24579a12f44902a306a10450524a7209a6990d157ad734a5d1ad5abc44d81d`）+ `review_probe.py`（5 API case 用 fbbbd619 真实公共 API、2 RULE case 只执行 Packet 字面规则；**不得替代产品验收**——指令 §三） | 2026-10-09，SHA 重算一致 | R60-01..08 反例定义、D1R 设计探针输入集（§附） | normative（反例基准） | — |
| DI-020 | Decision | **MDR 登记 `published/MDR-60-PR282-GOAL-CORRECTION-20261009-v1.md`**（SHA-256 `759a9225f58af509cf32e38417c9e3bd54d7f2a22df4773c9d1b8260db953403`，重算一致） | 2026-10-09 | R60-01..09 语义登记（§三） | normative | — |
| DI-021 | Code | `lima/python_dataflow.py`（@fbbbd619 只读亲验：`PythonDataflowAnalyzer.analyze_project(files: dict[path→text])` 纯静态、`_module_name` 由全路径派生点分模块名、结果含 `parse_errors/dynamic_import_sites/ambiguous_modules` 计数）——**只读语义参照**（R60-05：比较模块解析语义一致性；不作为代码依赖，见 §5.3.5） | @fbbbd619 | 模块解析语义对照声明 | current-behavior（参照） | 不引入新依赖方向 |
| DI-022 | Finding | **ER Record `ERR-60-IP-0023-D1R-2026-10-09-v1`**（v3 修订对象；本体由主会话另存，未亲读——如实声明；要点经派发消息传递）+ 其探针证据全文亲验：`%TEMP%/er_probe_ip0023_d1r_results.json`（SHA-256 `d34b1b505b263f060762478bf59fd50d875bde250b2e85f362c6c421e1fbae1c`）+ `%TEMP%/er_probe_refine_results.json`（`12d63e5ffbdfb09823d5300195155a26de0c85aafc81da5dffa5638dae88c26d`）+ 两探针脚本（`7a4e485d89c9189325f040e292c6a4c9692569b1cd389d7c551cc80a60b3ce5a` / `7d53a372885a32998b4ab668c01a5cd7b47b86e755f58502e26a5534d4f998a0`，E1/E2 断言与 v2 字面规则逐项核对）+ 授权链 `MR-60-PR282-GOAL-CORRECTION-20261009/v1` §五/§九 | 2026-10-09，SHA 重算一致 | v3 三项 SF 修订（§0.2 → §5.1.1/§5.1.2/§5.1.3/§5.2.1/§5.2.4/§5.6.3/§6/§11/§13） | normative（v3 修订范围合同） | 探针结果只作设计证据，不替代产品验收（指令 §三同口径）；ER Record 正文与探针不一致时停止上报 |
| DI-023 | Decision | **Maintainer 收口指令 `MR-60-PR282-FINALIZATION-20261009/v1`**（机械抽取正文 `.pv_tmp/issue60-resume-2026-10-09/authorization/v4/FINALIZATION_BODY.md`，SHA-256 `02133d0978e4b08389af3c7139541bbd4cb997e177804cb6faa4176fcd8402e3`，读取前重算一致） | 2026-10-09 | §四 五项已采纳产品裁定（P60-V3-01..05 裁定内容与内嵌 API 基准代码来源）、§二 授权与禁止、§五 角色链、§六 测试计划 | normative（最高需求权威） | 与 v3 设计冲突处以指令为准（128 默认预算等已否决项不得重试） |
| DI-024 | Decision | **配套规划 `docs/LIMA_Issue60_PR282_v3_Rulings_and_Delivery_Plan_2026-10-09.md`**（main 工作区，SHA-256 `75798f8ba6bbae5b8379b3a33a9db5f2aa0491f8751c7b36cadaca8d6be48e95`，本轮重算一致） | 2026-10-09 | §2 五项问题证据/处置/验收出口表（本 Packet §0.3 逐条引用）、§4 M1 推进定义 | normative（背景裁定建议+证据索引） | — |
| DI-025 | Decision | **MDR 登记 `published/MDR-60-PR282-FINALIZATION-20261009-v1.md`**（SHA-256 `9cd79d20775317d904f651c385c03fd6019ccd0a5d6f55c89caf68d06bdb4a1c`，重算一致） | 2026-10-09 | §三 五裁定语义登记、§四 授权边界、§五 P&V D1 边界 | normative | — |
| DI-026 | Decision | **Coordinator Assignment `ASSIGN-60-CLOSURE-A-PKT-D1F_v1`**（SHA-256 `2774bd4333c3974fb6369e7f9492bb3a6bf0e46ad9233d93a541aa5bfa2ebf8a`，读取前重算一致；取代 D1R 成为当前活动 Assignment，D1/D1R 未撤销其 Goal/Frozen Interfaces/安全基线/停止条件继续有效除本文明确修订处） | 2026-10-09 | v4 范围（P60-V3-01..05 逐项修订要求+逐字 API 基准、T 节测试计划方向、Acceptance 1-8、停点收紧） | normative（唯一任务合同） | 与其他输入冲突时以 Assignment 为准并提交 Decision Request |
| DI-027 | Evidence | **ER 链收口证据 + v4 离线消费探针**：`ERR-60-IP-0023-D1R-2026-10-09-v1` 本体（SHA-256 `4fac90eeec6c5a3a76a89d950eca244c9623230a2c56c67aaa2cc430b8a60e3d`，本轮重算一致——v4 起本体已归档可亲读）+ addendum-1（`c9402a9df80fa7bcd9a0cabba809fe43ec2fc02134ebaf10826f2f754ad588a8`，重算一致；其"四类 manifest 盲点是声明承载而非消除"判定 = P60-V3-04 收口对象）+ 本轮探针 `%TEMP%/ip0023_d1f_consumption_probe.py`（SHA-256 `74a346184228f2d3352667c6500c6cf97520d1dea781bb6add2b575f130d0882`）与 `%TEMP%/ip0023_d1f_consumption_probe_results.json`（`b60447e0709b465a332f9d71ebfc8c2171fc2ea671a72e8ca0037858408b76ce`；12/12 过；探针对象 = 既有 golden `tests/audit/fixtures/golden_matrix/golden/application.json`，SHA-256 `23c0f3ce0ea44dbccfc5b6a9cedefc8badc968eb4ea268b6436bd8e4c1240ceb`；详见附 D） | 2026-10-09，SHA 重算一致 | P60-V3-02 消费示例"已有部分"的 D1 设计证据（区分"已有行为实测"与"D2 待绑定"）；P60-V3-04 盲点判定基座 | normative（设计证据；不替代产品验收） | 探针结果只证明既有公共 API 行为，不声明未实现的 graph 已可调用 |

| DI-028 | Decision | **Maintainer 跨层修订指令 `MR-60-PR282-CROSS-LAYER-CORRECTION-20261010/v1`**（机械抽取正文 `.pv_tmp/issue60-resume-2026-10-09/authorization/v5/CROSS_LAYER_BODY.md`，SHA-256 `5a584cf5d24e6382ad174ca7336c427ddff101d96f1cce993adad6a867d56213`，读取前重算一致） | 2026-10-10 | §四 CL-01..05 五项集中裁定（v5 修订内容与选择点授权来源）、§六 兼容边界与同轮机械收尾、§七 有限退出条件 | normative（最高需求权威） | 与 v4.1 设计冲突处以指令为准（被否决口径不得重试） |
| DI-029 | Decision | **配套规划 `docs/LIMA_Issue60_PR282_v41_Code_Review_and_Delivery_Plan_2026-10-10.md`**（main 工作区，SHA-256 `0d7f79a5882576bd5d7efb801317fdae758c49568249a4fe0282418afa08691f`，本轮重算一致） | 2026-10-10 | §3 调用结构图+源码行号锚、§4 五项合并前修正（反例+行号+修订方向+退出证据——§0.4 主要素材）、§7 D2 必须验证组合 | normative（背景裁定建议+证据索引） | — |
| DI-030 | Decision | **MDR 登记 `published/MDR-60-PR282-CROSS-LAYER-20261010-v1.md`**（SHA-256 `412e82e7a715e3c0266f9207d0e4a2dd002f999518d3667ef6014a2f6af3e680`，重算一致；§四 五裁定语义登记、§五 授权/禁止、§十 分层汇总——已授权选择点与"偏好/探索性设想"分层以该记录为索引，内容权威回到指令原文） | 2026-10-10 | CL-01..05 选择点授权层级索引 | normative | — |
| DI-031 | Evidence | **本轮反例证据**：`output/issue60-pr282-v41-review-2026-10-10/review_probe.py`（SHA-256 `883770c77580ab8e44232a71f78fe766f93209113639091f30471fcc220e35ea`）与 `review_probe_results.json`（`a7c73a58a205f208acc4d974245539e36cd412f767c34ca6752af5feb5b41043`，读取前重算一致）；探针 ID：API-IO/API-META/API-POOL（冻结公共 API 实测或实测量+字面规则模拟）、RULE-COMPLETE/RULE-COUNT（字面 Packet 规则推演）；`workspace_has_fingerprint=false`（机械收尾第 1 条事实基座）；v5 交付前离线复跑 exit=0 且行为字段一致（附 E） | 2026-10-10，SHA 重算一致 | CL-01..05 反例定义与 v5 修订的不可达性复核输入（§0.4/§3.7/§5.9；新参考模拟探针见附 E） | normative（反例基准；不替代产品验收） | — |
| DI-032 | Decision | **Coordinator Assignment `ASSIGN-60-CLOSURE-A-PKT-D1X_v1`**（SHA-256 `86bfc69880836c028444d428f605ca4666a28259648f472746e0085fc40e0025`，读取前重算一致；取代 D1F 成为当前活动 Assignment，D1/D1R/D1F 未撤销、其 Goal/Frozen Interfaces/安全基线/停止条件继续有效除本文明确修订处；Mechanical Test Correction Allowance=NOT_ALLOWED） | 2026-10-10 | v5 范围（CL-01..05 逐项四段式要求+已授权选择点+旧反例不回归清单+机械收尾+D1 出口）、Acceptance、停点 | normative（唯一任务合同） | 与其他输入冲突时以 Assignment 为准并提交 Decision Request |

### Explicitly Rejected Inputs

- 任何需要修改 `lima/workspace.py` 或共享输入/安全层才能表达的方案**作为默认设计**（F3 路线归 #60-CLOSURE-C；**v4：DR-IP-0023-02 已采纳，其共享层 additive 需求已全部具体化为 §4.3.1 白名单两项并以 Packet 获批为激活条件——v5：白名单扩充为双清单视图（CL-02），激活条件=本 Packet v5 获批；白名单外的共享层修改仍在此拒绝**）；
- 任何扩展 `lima/audit/__init__.py.__all__` 54 帽、私加 #58 Profile 字段、借 `AttackSurfaceEntry.extensions` / RAM wire payload / 任何未知 extensions 携带图的方案（B-10 + `_validated_extensions` 冻结语义冲突）；
- 已否决路线（累计，不得重试）：D1_v1 原清单（prompt/wire 层掩码 path；full-payload digest 扩展；公开 redact:sha8/家族计数；摘要检查前置于结构检查；IP-0022 单 PR 流程例外；借 extensions 携带图）+ **本轮反例否决**（指令 §二/D1R Known Gaps）：从路径重建默认 workspace 覆盖调用方策略（API-02）；以目录首段推导 import 锚点（RULE-02）；坐标变换后再准入/仅覆盖部分公开面（API-03）；"底层继承"当作解析失败 gap 的证明（API-04）；组件 content_digest 互异断言（API-05）；实现后产 golden 自证（R60-07）；消费者重跑构建获取事实（R60-08）；**v4 追加否决**（指令 §四 P60-V3-05/FINALIZATION §二）：默认 `max_total_model_calls=128`（按组件数自动放大的旧提案）；basename-ignore 组件视图 + 合法组件 typed 不构建作为默认完成方案（P60-V3-01）；组件层复制/重定义 ram_schema 摘要与 gap 规则、禁止组件层 import ram_schema（P60-V3-02：矛盾表述废除，只读复用为唯一路线）；`DEFAULT_EXTENSIONS` 增补 .txt/.cfg/.mod/.xml（P60-V3-04 选项 B）；**v5 追加否决**（指令 §四 CL-01..05 / D1X）：以"逐次护栏仍通过"解释为"全仓累计约束满足"的聚合池补注口径（API-POOL 否决——v4.1 L692 补注撤销）；把 distinct files 当累计 IO 的读取上界口径（API-IO 否决——v4.1 L706 公式废除）；manifest 计量"只计发布条目"或藏掉发现条目追平数字（RULE-COUNT 否决）；W-1/W-2 以单一 S1 集合过滤全部读入口致自身 manifest 候选清空（API-META 否决）；"gap 非空但 complete=True 且同时命中真实无依赖与证据不足"的完整性口径（RULE-COMPLETE 否决）；把 `fingerprint()` 挂到 `RepositoryWorkspace` 的表述与凭空新增共享层兼容接口（冻结实测 `hasattr(RepositoryWorkspace,"fingerprint")==False`——机械收尾第 1 条）；快照缓存作为默认路径（未采纳的可选设计项，零实现——§4.3.2；任何缓存不得跨组件/策略污染或逃过预算）；
- `lima/python_dataflow.py`、`lima/semantic_retrieval.py` 的**代码依赖**（v2 仅将前者作只读语义参照文档化，§5.3.5；semantic 链复用指 `lima.audit.semantic_prioritizer` 公共入口；组件层 import 扫描自带最小 AST 解析，不引入对共享模块的新依赖方向）；
- 修改 `repository_kinds` monorepo 判定语义（inventory 冻结行为；本片组件图与 kinds 分类各自表述，见 §5.1.6）；
- #266（OpenHarmony pilot）与 #281（offline preflight）的任何文件/语义面（恢复审计 addendum-2 §5 四查③亲验与 #60 预期路径零交集；#281 的 profile_consumer 仅为只读参考，不作为本片验收依据）；
- #94 轨道全部路径、IP-0020 vault、IP-0024..IP-0043 baseline 轨道、BG-IP-0016-01/BG-60-01 处置（OPEN 项归置权在 Coordinator，本片不清偿不扩大）；
- 任何聊天记录、调研文档推断、快照外时点数据（以 §2 Manifest 所列 live/锚定输入为准）。

---

## 3. Current code baseline（P&V 亲验誊录，@fbbbd619）

本阶段（D1R）按 D1R Assignment §Acceptance 第 6 条执行：不重跑全量产品测试（引用恢复审计 §5 真实数字为基线锚），对 Packet 引用的冻结符号/常量做只读核对（import 亲验或源码誊录，禁止执行目标项目样本）。

### 3.1 三层冻结面 + ram_schema 消费面（DI-012，import 亲验）

- **Layer 1（inventory）**：`build_repository_profile(workspace, *, tenant_id, task_id, workflow_id, stage_attempt_id, artifact_id, repository_snapshot_digest, producer="lima.audit.inventory", policy_digest=<sentinel e3b0c442…b855>, toolchain_digest=<sentinel>, options: ProfileInventoryOptions|None)` → `ProfileBuildResult{profile, envelope, provenance_anchor_ids, admission_skips}`；`ProfileInventoryOptions{budgets=ProfileBudgets(), schema_version=SchemaVersion(4,0)}`；`ProfileBudgets{manifest_max_bytes=262_144, max_manifest_files=64}`；`is_secret_shaped_path`（段级检测，`tests/secrets/x.py`→True / `tests/tokenizer/x.py`→False 亲验；`secrets/pyproject.toml`/`secrets/main.py`→True、`main.py`→False 亲验）；`AdmissionSkipRecord{index, reason, family}`（内部留痕，无文件名）。**入口行为（R60-02/03/04 承重）**：`isinstance(workspace, RepositoryWorkspace)` 硬校验（鸭子类型视图不可注入）；内部自行 `workspace.inventory()` 与 `_manifest_candidates(workspace)`（`os.listdir` root+一级子目录，**不读 ignored_directories**）。
- **Layer 2（ram）**：`build_python_ram_facts(workspace, *, budgets=None)` → `RamFactsBuildResult{facts, provenance_anchor_ids, admission_skips}`；`RamBudgets{max_python_files=512, max_key_flows=256, max_unresolved_edges=1024}`；`PythonRamFacts` 11 字段（含 `counters: Mapping[str,int]`——`parse_error_files`、`modules_indexed` 等在此）；`ram_facts_digest(facts)`（64-hex）。**入口行为同上**：isinstance 硬校验 + 自行 `workspace.inventory()`；py 候选排序后先过 `_secret_shape_family` 准入（路径=该 workspace 相对坐标），拒绝计数入 `INVENTORY_SKIPPED`（detail `reason=sensitive-filename; count=N`）；`>max_python_files` 截断入 `BUDGET_EXHAUSTED`（detail `reason=python-file-limit; count=…`）。
- **Layer 3（semantic）**：`build_semantic_top_n(facts, *, options=None, model_client=None)`；`SemanticOptions{top_n=20, weights, seed=0, budgets, model_id="unset", prompt_template, tie_break="kind-path-symbol-ordinal"}`；`SemanticBudgets{max_llm_calls=8, max_prompt_tokens_estimate=24_000, max_output_tokens_estimate=4_096, max_total_tokens_estimate=28_096, max_wall_time_seconds=120}`；`candidate_id("sensitive-sink","a/b.py",None,0) == "sensitive-sink:a/b.py:-#0"`（冻结编码亲验）；`semantic_result_digest(result, *, input_facts_digest=None)`；模型默认 off（`model_id="unset"` 或无 client → 零调用零网络）。
- **Schema 层（ram_schema）**：`GAP_CODES_ALL` 恰 10 码（AMBIGUOUS_DISPATCH / BUDGET_EXHAUSTED / DYNAMIC_IMPORT / INVENTORY_SKIPPED / MANIFEST_PARSE_ERROR / NO_LANGUAGES_DETECTED / SEMANTIC_MALFORMED_OUTPUT / SEMANTIC_MODEL_OFF / SEMANTIC_MODEL_TIMEOUT / UNSUPPORTED_LANGUAGE）；`GAP_EXECUTION_REQUIRED_TRIGGERS = GAP_CODES_ALL - {"SEMANTIC_MODEL_OFF"}` 恰 9 码；`PROVENANCE_ANCHOR_CHAIN=("inventory","ram-facts","semantic-prioritizer")`；`ram_wire_payload` / `validate_ram_wire_payload` / `ram_wire_digest` / `execution_required_from_gaps` / `load_ram_wire_schema`。**v4 增补（P60-V3-02 只读复用消费面，@fbbbd619 亲验，行号=本 worktree 源码）**：`ram_wire_payload(ram_result, semantic_result, *, profile_budgets=None, ram_budgets=None, semantic_options=None)`（L268-377）——预算/options 进 `build` 段从而进 wire digest，`None`=层默认（**回填默认即 wire 自洽破坏点**：build 段与实际构建配置不一致时 wire_digest 校验必失配）；wire 顶层键恰 8（schema_version/model_kind/build/ram/semantic/identity/provenance/execution_required，**无顶层 coverage_gaps**），gaps 在 `ram.coverage_gaps` 与 `semantic.coverage_gaps`（每项含 `gap_code`），顶层 `execution_required={"required": bool, "trigger_gap_codes": list}`；`validate_ram_wire_payload`（L379-452）六步完整性（路径→ranked 绑定→facts/config/result/model 四 digest→wire_digest 收尾）；`ram_wire_digest`（L454-486）= `compute_content_digest(build 段+三身份摘要)`，wire_digest 槽自身不参与、对诚实载荷等于内嵌值、**恒不等于 ram_facts_digest**；`ram_facts_digest_from_wire`（L495-505）= `compute_content_digest(payload["ram"])`；`semantic_result_digest_from_wire`（L551-595）按 `semantic_prioritizer._result_digest` 冻结形（config_digest+input_facts_digest+ranked 六字段+total_candidates+coverage_gaps）重组重算；`execution_required_from_gaps`（L236-258）10 码全集外抛 ValueError、9 触发码、`SEMANTIC_MODEL_OFF` 永不触发。
- **manifest 候选机制（inventory 私有，值重述不 import）**：`_MANIFEST_EXACT_NAMES` = {Cargo.toml, environment.yml, go.mod, package.json, pom.xml, pyproject.toml, setup.cfg, setup.py} + `requirements*.txt` 模式；候选 = 根目录 + 一级子目录（os.listdir 后 sorted；**这是 inventory 冻结旧行为，不授权本片组件层沿用浅层限制**——R60-01）；候选匹配**不施加扩展/忽略策略与秘密形态过滤**（raw os.listdir 名集匹配——v3 曾以此披露"可作证据、不可作锚点"不对称；**v4：该不对称叙述已由 §5.1.7 元数据通道设计取代**（九类默认可锚定+两输入集合分离），此行仅保留冻结事实本身作为 P60-V3-01 三入口约束的锚（§3.6））；`_record_manifest_error` 用 `manifest-index=<排序下标>` 稳定标识（DR-IP-0022-04 A 定稿版，不泄漏敏感文件名）。
- **monorepo kind 判定（inventory 冻结行为，亲验 `_repository_kinds`）**：`has_languages and len(manifest_subdirs) >= 2` → `RepositoryKind.MONOREPO`（wire 值 `"monorepo"`，#58 IP-0003 §10 冻结）。

### 3.2 `lima/audit/__init__.py` 现状（DI-012）

134 行；`__all__` 恰 54 项 = IP-0016 段 `[0:11]` + IP-0018 段 `[11:20]` + IP-0019 段 `[20:44]` + IP-0021 段 `[44:54]`（字母序段追加先例）；docstring 内冻结断言说明 ``len(__all__) == 54``。本 Packet 对该文件**零修改**（§5.6.1）。

### 3.3 workspace 口径（DI-013；恢复审计 §4② 定性移交，全部 @fbbbd619 亲验）

- 构造器 `RepositoryWorkspace(root, *, max_files=5_000, max_file_bytes=512KiB, max_total_bytes=20MiB, extensions=None→DEFAULT_EXTENSIONS, ignored_directories=None→∅∪DEFAULT_IGNORED_DIRECTORIES)`——**五策略参数即策略继承的公共载体（R60-03）**；构造语义（v3 勘误锚定，源码亲验）：`extensions` 为 **None/空→DEFAULT 的 or 替换**（非空入参完全生效、**不与 DEFAULT 并集**），`ignored_directories` 为**恒与 DEFAULT_IGNORED_DIRECTORIES 并集**（非 None 亦并集）；
- `inventory()`：os.walk topdown、`followlinks=False`；目录按**名字** ∈ ignored_directories 剪枝（无路径级排除——R60-02 设计边界）；文件级跳过原因 closed 词表（ignored-directory/symlink/sensitive-config/unsupported-extension/unreadable/file-size-limit/file-limit/total-size-limit/binary/non-utf8）；候选按 `_candidate_priority`（low-priority/source-root/其余 + 相对路径）排序后过 cap；返回 `WorkspaceInventory{files: list[WorkspaceFile], skipped: dict[reason→count]（**公开**）, total_bytes, discovered_files/bytes, truncated}`——**主仓准入与截断状态对组件层可观察（R60-03/04/06 依据）**；
- `read_text` = 有界（≤max_file_bytes）`read_bytes().decode("utf-8")`，无 universal-newline 归一（保留 CRLF）；`absolute_file`=`_safe_path`（相对、不越界、常规文件）；`DEFAULT_EXTENSIONS` 37 项（含 C++/构建类；**不含 `.txt`/`.cfg`/`.mod`/`.xml`——requirements*.txt/setup.cfg/go.mod/pom.xml 四类 manifest 文件默认策略下不可准入为 (S1) inventory 成员（v4：此冻结事实不变，但其"锚点不可见"后果已由 §5.1.7 元数据通道 (S2) 收口为默认正例——两输入集合分离）；含 `.toml`/`.json`/`.yml`/`.py`——pyproject/Cargo/package.json/environment.yml/setup.py 五类默认可准入**）、`DEFAULT_FILENAMES` 6 项（不含任何 manifest 名）、`WorkspaceFile` 第 4 字段 `line_count`、`fingerprint()`=逐文件 path/size/sha256——**输入域扩容为既有事实，本片不依赖新扩展进入 inventory**；`inventory()` 截断（`truncated=True`）仅在 file-limit/total-size-limit 跳过计数时置位（源码亲验——§5.2.4 T6 逐键承载恒非空的依据）；
- F3（_safe_path TOCTOU）未闭合，归 #60-CLOSURE-C。

### 3.4 基线数字（恢复审计 §5 Coordinator 实跑 @fbbbd619，锚定引用非本轮重跑）

contracts `617 OK` / audit `235 OK 0 skip`（含 IP-0022 51 例回归锚）/ evidence_privacy `244 OK 3 skip` / workspace+dataflow `44 OK` / `ruff check --no-cache lima/audit` 净 / `ruff check --no-cache lima/audit tests/audit` 恰 DR-LINT-0022-A 六处（B009×1 + B017×5，全在 tests/audit/test_ip_0022_fix.py）零漂移 / CI 完整入口 `3006 OK 24 skip`（全环境类）。数字为基线锚，按 addendum-2 §3 修订版停点条款执行：计数变化需解释，不单独构成停点；不得删测试/改 Oracle 追平。

### 3.5 反例索引（DI-019；七例 SHA 锚定于 `90f3d975…acb8a4`）

API-01（根 workspace 吸入子组件文件：root_modules=2 / child=1）、API-02（子 workspace 重置策略：1/30/30+ignore a → 5000/524288/20971520+丢失）、API-03（坐标重设绕过准入：整仓 0 模块+gap → rebased 1 模块）、API-04（`parse_error_files=1` 而 facts `coverage_gaps=[]`）、API-05（不同组件根同内容 → content_digest 相等）、RULE-01（`services/api`、`packages/core` 不在"根+一级"候选集）、RULE-02（src 布局 anchors 同为 `src`，`import beta` 无边无 gap）。处置映射见 §0.1；D1R 设计探针复跑结果见附录 B。

### 3.6 P60-V3-01..05 衔接事实（v4 新增；@fbbbd619 亲验 + 本轮离线探针实测）

- **`_manifest_candidates` 三入口事实（P60-V3-01）**：`lima/audit/inventory.py` L392-417 `_manifest_candidates(workspace)` 直接 `os.listdir(root)` 枚举根+一级子目录做名集匹配（`_MANIFEST_EXACT_NAMES` L147-150 + `requirements*.txt` 模式），**不消费 inventory 的精确文件集合、不读 ignored_directories、不施加扩展/秘密过滤**——故"仅给 inventory 加排除参数"不构成对 Profile manifest 候选入口的约束；三入口（inventory 扫描集合 / read_text 等全部读取入口 / `_manifest_candidates`）必须显式分别覆盖（§5.2.1）。
- **消费链事实（P60-V3-02，§3.1 增补段同源）**：`decode_profile_envelope(data: bytes, *, limits) -> (ArtifactEnvelope, RepositoryProfile)`（`lima/contracts/profile.py` L1238-1254；`ArtifactEnvelope.content_digest` 公共字段）；`semantic_prioritizer.py` L623-660 `_config_digest_payload`/`_result_digest` 冻结形状与 wire 重组函数一一对应——RAM wire 已含完整 semantic 数据的证据。
- **参数域事实（P60-V3-03）**：`semantic_prioritizer.py` L80 `SEMANTIC_MAX_TOP_N: Final[int] = 100`、L258-268 `top_n` 非 [1,100] 整数抛 ValueError（默认 20 只是默认不是帽）；L221-246 `SemanticBudgets` 全字段正值校验 + `max_total_tokens_estimate >= max_prompt + max_output` 构造校验——`max_llm_calls=0` 的 SemanticBudgets **不可构造**（零额度降级不得造非法对象的冻结面依据）。
- **三口径事实（P60-V3-05）**：`SemanticBudgets{max_llm_calls=8, max_prompt_tokens_estimate=24_000, max_output_tokens_estimate=4_096, max_total_tokens_estimate=28_096, max_wall_time_seconds=120}` 是**每组件**语义的冻结面（Packet §3.1 L163 誊录一致）；`semantic_prioritizer.py` L439-470 的预调度校验（L451 调用数、L456 prompt 预估、L459-460 输出预估、L463-465 总量预估、L469-470 墙钟）全部在**每组件语义遍历内部**执行——`max_total_tokens_estimate` 是单次预调度预估校验字段，**不是**全仓累计池；v3 §5.4.4 L554 的 128 默认提案即被 P60-V3-05 否决的对象。
- **离线消费探针实测（P60-V3-02 D1 设计证据，DI-027；详见附 D）**：对既有 golden `tests/audit/fixtures/golden_matrix/golden/application.json`（SHA-256 `23c0f3ce0ea44dbccfc5b6a9cedefc8badc968eb4ea268b6436bd8e4c1240ceb`）实跑指令内嵌 API 基准的"已有部分"——`validate_ram_wire_payload` 通过；`ram_facts_digest_from_wire` 复算 `84fec0134159f33e…` 与 `identity.ram_facts_digest` 相等；`semantic_result_digest_from_wire` 复算 `8aecae4e63146bfc…` 相等；`ram_wire_digest` 复算 `b92a2aa40fc9b4c9…` 与 `identity.wire_digest` 相等且 **≠ ram_facts_digest**；顶层无 coverage_gaps（ram 段 n=0、semantic 段 n=1=`SEMANTIC_MODEL_OFF`）；`execution_required_from_gaps` 复算 `{'required': False, 'trigger_gap_codes': []}` 与顶层一致；篡改 `semantic.ranked[0].score` → ContractError；`SEMANTIC_MODEL_OFF` 永不触发、全集外码 ValueError；`decode_profile_envelope` bytes 入参语义成立（合成样本经公共 API 构建，`envelope.content_digest=913d8d6ea58ee291…`），传 JSON 对象（非 bytes）在契约边界被拒。**以上为"已有行为实测"；真实 graph payload 的端到端消费属 D2 绑定**。

### 3.7 CL-01..05 衔接事实（v5 新增；本轮反例探针 @a7c73a58 + 指令/规划行号锚 + 冻结源码 @fbbbd619 亲验）

- **主 inventory 跳过键与截断语义（CL-01 S1 侧既有口径）**：`workspace.py` L202-256 `inventory()` 跳过键封闭词表 10 键（ignored-directory/symlink/sensitive-config/unsupported-extension/unreadable/file-size-limit/file-limit/total-size-limit/binary/non-utf8），`truncated=True` 仅在 file-limit/total-size-limit 计数时置位——S1 侧证据丢失已由 T6 承载（§5.2.4），S2 侧缺口即 T8 的设计对象。
- **旧 Profile manifest 读取先例（CL-01 同构基座）**：`inventory.py` L603-649 `_load_manifests` 已有 `GAP_BUDGET_EXHAUSTED` + `manifest-index` detail 先例——S2 通道事件同构落图级完整性规则（同义不同段是 v5 要消除的缺陷形态）。
- **`_manifest_candidates` 独立性（CL-02 机制基座）**：`inventory.py` L392-417 独立 `os.listdir` 根+一级目录做名集匹配，不消费 inventory 文件集、不施加扩展/秘密过滤——这正是旧 Profile 能取得自身 manifest 事实、而字面 S1 过滤清空候选的机制（API-META 实测：`source_inventory=[main.py]`、`old_manifest_candidates=[requirements.txt]`、旧 Profile `frameworks=[flask]`/`package_managers=[pip]`，字面 W-2 过滤后 `W2_manifest_candidates=[]`、两事实均空）；L1085-1094 `build_repository_profile` = inventory() → `_manifest_candidates` → `_load_manifests`（经 `absolute_file`+`read_text`）→ 源码证据（L714-735）。
- **读取链实测（CL-04 机制基座）**：API-IO 实测单 main.py 三段链 `Path.read_bytes` 5 次（预检 inventory/Profile inventory/Profile source/RAM inventory/RAM source）；`workspace.py` L202-256 inventory 与 read_text 均实际 read_bytes 且无读取缓存；`ram.py` L429 `build_python_ram_facts` 重新执行 `workspace.inventory()` 并在 L465-469 逐候选 `_read_python_text`——五次读取由该公共链结构机械复现，非实现偏差。
- **SemanticBudgets 三口径（CL-03 基座）**：`semantic_prioritizer.py` L221-246 SemanticBudgets 全字段正整数约束（`max_llm_calls=0` 不可构造）、`max_total_tokens_estimate ≥ prompt+output`；L439-470 预调度校验全部每组件口径——旧字段无一全仓累计池（口径三为本片新增）；API-POOL 实测：caller 1000/500/1500 下 8 次尝试逐次护栏全过、按 v4.1 规则累计预留 1684/2048/3732 三项超 caller 对应值（`cumulative_exceeds_caller=[true,true,true]`）而默认池剩 22316/2048/24364——"旧护栏保留即满足新增默认约束"被反证。
- **Packet 规则间冲突（CL-05 对象）**：v4.1 L274/L299/L339/L634/L838 均为 Packet 文本自身——冲突在规则之间，无需触碰产品代码即可消解；修订后 V7 的"集合成员/来源字段"词义必须有 payload 可表达的机械判据（指令 §四 CL-05 原义）。
- **fingerprint 归属（机械收尾第 1 条事实）**：本轮探针 `workspace_has_fingerprint=false`（probe 断言 `not hasattr(RepositoryWorkspace, "fingerprint")`）——`fingerprint()` 属 **WorkspaceInventory**（inventory 结果对象），非 RepositoryWorkspace 方法；v5 §4.3.1/§5.2.1 相关表述修正，不凭空新增共享层接口。

---

## 4. Files boundary（冻结单解；D2 冻结与 Implementation 将据此执行）

### 4.1 Files to Add（产品与数据产物，Implementation Agent 拥有）

| # | 文件 | 说明 |
|---|---|---|
| 1 | `lima/audit/component_graph.py` | 唯一产品代码文件（§5 全部实现） |
| 2 | `schemas/v4/lima.component-graph.json` | component graph wire schema（独立版本 2.0——v2 设计的承载字段集；**不注册 matrix**） |

### 4.2 Test/Fixture Files（P&V 独占，D2 创建，Implementation 禁改）

| # | 文件 | 说明 |
|---|---|---|
| 3 | `tests/audit/test_component_graph.py` | 组件识别/单一归属/策略继承/模块解析/完整性/隐私/消费闭合/wire 负例（§6 C1-C7） |
| 4 | `tests/audit/test_monorepo_golden.py` | monorepo golden 可重放 + 独立 Oracle 摘要核对（§6 C6） |
| 5 | `tests/audit/fixtures/monorepo/__init__.py` | fixture 包 |
| 6 | `tests/audit/fixtures/monorepo/shapes.py` | monorepo repo 形态构造（LF 钉死；沿用 `repo_shapes.workspace_with` 模式；含嵌套/src 布局/同内容双组件/秘密形态负例专用形态） |
| 7 | `tests/audit/fixtures/monorepo/golden/monorepo.json` | monorepo golden（**P&V 在实现前独立产出并冻结的预期载体——R60-07：内容=独立推导预期（人工推导的组件/边/计数/三态 + 既有公共 `compute_content_digest` 对手写 canonical dict 的独立重算），不是实现输出的回填**；D2 Frozen Test Commit 内提交） |

### 4.3 Product Files Allowed to Modify

**无条件修改：无**。`lima/audit/__init__.py` 本 IP 零修改（与 IP-0019/0021/0022 的"纯追加 re-export"边界不同：本 IP 新公共符号不经 `lima.audit` 命名空间 re-export，见 §5.6.1 单解）。

### 4.3.1 条件性共享层 additive 白名单（DR-IP-0023-02 已采纳目标的落点；v5 按 CL-02 扩充为双清单视图；激活条件=本 Packet v5 获 Maintainer 批准合并；**本轮零实现**，白名单外共享层修改一律仍属禁止）

P60-V3-01 精确视图 + CL-02 双清单视图方案（§5.2.1）所需的**全部**共享层 additive 能力，逐项列入（精确到文件 + 函数/字段/参数 + 旧默认兼容论证 + 调用链 + 冻结测试影响 + 预算计量）。指令边界原文："允许设计新增模块内适配及必要共享层 additive 能力，但未来实现文件、接口、调用链和旧默认兼容须具体列出；当前不提前修改它们"；"本次采纳目标不等于已经批准未具体化的共享层实现"；"不要在实现时才发现需要新共享层参数"（CL-02）。

| # | 文件 | additive 变更（函数/字段/参数） | 旧默认兼容论证 | 调用链 | 冻结测试影响 | 预算计量 |
|---|---|---|---|---|---|---|
| W-1 | `lima/workspace.py` | `RepositoryWorkspace.__init__` 新增两个 keyword-only 参数：①`admitted_files: Iterable[str] \| None = None`（源码视图 S1 精确切片，workspace 相对 POSIX 路径集合）；②`metadata_files: Iterable[str] \| None = None`（**自身元数据视图（v5/CL-02）**：本组件获准 manifest 文件清单，= 该组件 `manifests[]` 的组件内坐标集，由 INV-OWN-3 划分唯一确定——**不含子组件 manifest**）。存为 `self._admitted_files`/`self._metadata_files: frozenset[str] \| None`（None=不受限）+ 公开只读属性 `admitted_files`/`metadata_files`。受限态语义（**双清单视图**）：`inventory()` 发现文件集**仅限 `admitted_files` 成员**（walk 期间过滤，集合外文件不发现、不计入 skipped、不进 discovered/total 统计——其统计已在仓库级主 workspace 完成；`metadata_files` **不进 inventory 结果**——源码视图不被元数据视图扩大）；`read_text`/`absolute_file`（`_safe_path` 边界之上）读取准入 = `admitted_files ∪ metadata_files` 成员（其余相对路径按既有越界错误口径拒绝，fail-closed，不新增错误类型）；`WorkspaceInventory.fingerprint()`（inventory **结果对象**的方法，非 `RepositoryWorkspace` 属性——冻结实测 `hasattr(RepositoryWorkspace,"fingerprint")==False`）在受限态自然仅覆盖 `admitted_files` 文件集（inventory 已受限所致），**不新增任何共享层 fingerprint 接口** | 两参数缺省 `None` 时构造、inventory、read_text、absolute_file、跳过词表、cap 截断行为**逐字节同旧默认**（既有全部调用点零改动——tests/audit 既有 235 例与五形态 golden 不触及受限态）；参数仅收紧可见集/读取准入，不放宽任何边界（`_safe_path`/扩展/忽略/秘密语义原样）；`metadata_files` 成员不改变 inventory 语义（零 S1 侧影响） | `build_monorepo_profile → 每组件 RepositoryWorkspace(root, 五参数继承, admitted_files=精确切片, metadata_files=本组件 manifests 组件内坐标集) → 三层公共入口（内部各自 workspace.inventory() / workspace.read_text）`——入口 (a) inventory 仅受 admitted_files、入口 (b) 读取受并集、入口 (c) 见 W-2（§5.2.1 三入口表） | 既有冻结测试零影响（None 缺省不变）；D2 新增测试覆盖受限态（#9/#10/#55/#56 扩展锚 + #69/#70/#71 双清单锚） | inventory 受限态 cap（max_files/max_total_bytes）作用于切片自身，溢出→truncated→unbuilt(cap-divergence)；`metadata_files` 读取经 `read_text` 有界（≤max_file_bytes），每次读取计入 **S3 阶段尝试计量**（§5.4.4-IO）；通道发现/读取的 S8 计量归主通道（§5.1.7），与 S3 分列 |
| W-2 | `lima/audit/inventory.py` | `_manifest_candidates(workspace)` 增量尊重受限态双清单：候选输出过滤为属于 `admitted_files ∪ metadata_files` 的路径（先列后滤或等效剪枝，语义=过滤）——旧 Profile 对本组件 manifest 的候选可见性由此保持（CL-02：API-META 反例的实质修复点；父组件切片不含子组件 manifest 且子 manifest ∉ 父 metadata_files → 父候选天然不含子 manifest） | 缺省 None（不受限）时 `os.listdir` 名集匹配行为逐字节同旧（既有 Profile 构建调用点全部不受限）；过滤只收窄候选，不新增候选来源、不改 `manifest-index` 稳定标识语义、不施加扩展/秘密过滤于受限集成员之外（受限集成员已过 §5.1.7 通道准入） | `build_monorepo_profile → build_repository_profile(component_ws) → _manifest_candidates(component_ws) → _load_manifests`（经 `absolute_file`+`read_text`，即入口 (b) 并集准入）——入口 (c) Profile manifest 候选由此约束（P60-V3-01 裁定 + CL-02 自身元数据保留） | 既有冻结测试零影响；D2 新增 #56（父 Profile 候选不含子组件 manifest=INV-OWN-3(c)）+ #69（自身 manifest 事实保留）+ #70（父子隔离） | 候选数 ≤ 该组件 manifest 名集命中数；每候选读取 1 次尝试计入 S3 阶段计量；ProfileBudgets 既有约束照旧（manifest_max_bytes/max_manifest_files） |

**白名单明确不含**（仍属禁止）：`DEFAULT_EXTENSIONS`/`DEFAULT_FILENAMES`/`DEFAULT_IGNORED_DIRECTORIES` 任何改动（P60-V3-04 选项 B 禁止）；`_safe_path` 语义变化（仅新增集合成员校验层）；`read_text` 编码/换行语义；`_repository_kinds` 判定；`lima/audit/__init__.py`；三层其余行为；`ram_schema` 任何修改（只读复用，非修改）；**任何形式的内容快照/读取缓存接口（§4.3.2 可选设计项未采纳，零实现）**；任何把 `fingerprint` 挂到 `RepositoryWorkspace` 或为兼容性新增共享层 fingerprint 接口的变更（机械收尾第 1 条）。

### 4.3.2 可选设计项（未采纳）：快照内容缓存（CL-04；零实现，不入白名单）

快照缓存（对重复读取的内容快照复用，消除 §5.4.4-IO 所计量的真实重复 IO）是 CL-04 显式移交的**可选设计项**，本 Packet **不采纳**（默认零缓存、全计量如实，上界按保守常数倍公式给出）。**未来若采纳，必须先经 Packet 修订并将下列要件具体列入 §4.3.1 白名单后经 Maintainer 批准，当前零实现**：(i) 视图键（= 调用方 workspace 身份 + 策略五参数有效值 + `admitted_files`/`metadata_files` 集合——跨组件/跨策略不得命中同一缓存条目）；(ii) 不可变内容身份（缓存值=只读快照内容+其确定性摘要，命中不改变任何 digest 输入）；(iii) 失败/截断语义（读取失败不缓存、cap 截断不缓存、缓存未命中回退真实读取且计入计量）；(iv) 默认兼容（缺省关闭，关闭态行为与计量逐字节同无缓存路径）；(v) 未来允许修改的共享层接口精确清单（文件+函数/参数+调用链+冻结测试影响+预算计量归属）。**任何缓存不得跨组件/策略污染或逃过预算**（缓存命中仍计 1 次逻辑读取归属，预算帽按逻辑读取计）。

### 4.4 Read-only Reference

三层冻结面 `lima/audit/{inventory,ram,semantic_prioritizer,ram_schema}.py`、`lima/audit/__init__.py`、`lima/workspace.py`、`lima/contracts/**`、`schemas/v4/**` 既有 15 文件、`scripts/run_ci_tests.py`、tests/audit 既有 10 测试文件与全部既有 fixtures（`fixtures/{repo_shapes.py, library_profile_golden.json, ram/, semantic/, golden_matrix/}`）、五 IP Packet 与 DR 链文档、本 Packet（v4.1/v4/v3/v2 与 v1 历史）。**只读语义参照**：`lima/python_dataflow.py`（§5.3.5 对照声明，不 import）。**v4 注（v5 沿用）**：`lima/workspace.py` 与 `lima/audit/inventory.py` 的读取态不变；其**未来修改权**仅限 §4.3.1 白名单两项（v5：双清单视图；激活条件=本 Packet v5 获批；激活前等同 Forbidden；§4.3.2 缓存接口未采纳不在其列）；`lima.audit.ram_schema` 公共接口**只读复用**（P60-V3-02 授权——import 并调用公共函数非修改）。

### 4.5 Files Forbidden

除 §4.1/§4.2 与 §4.3.1 白名单（条件激活）外的一切路径；特别冻结：`lima/audit/__init__.py`（54 帽）、三层+ram_schema 模块（ram_schema 只读复用除外）、既有 tests/audit 测试与 fixtures（含 `test_ip_0022_fix.py` 六处 DR-LINT-0022-A 登记处）、`schemas/v4/version_compatibility_matrix.json` 与既有 14 schema 文件、`lima/contracts/**`、`lima/workspace.py`（§4.3.1 W-1 白名单激活前；`DEFAULT_EXTENSIONS` 等默认值**永远**在本 IP 禁改——P60-V3-04 选项 B 禁止，不随白名单激活而解禁）、`lima/python_dataflow.py`、`lima/semantic_retrieval.py`、scanner/service/api/store/sandbox/frontend、`.zcode/**`、`.github/**`、#94/#266/#281/baseline 轨道路径、`docs/**`（本 Packet 阶段 D1F 定稿后）、根检出与全部历史 worktree、`main` 分支。

### 4.6 Symbol-to-File Map（全部新增公共符号均在 `lima/audit/component_graph.py`）

见 §5.4.7 模块级 `__all__` 导出清单（**恰 46 项** = 23 个类型/函数/图常量 + 9 个 manifest kind 常量 + 2 个 v2 新增类型 + 12 个 v4 新增常量/类型：4 UNBUILT_REASON + 3 MANIFEST_SOURCE + 3 MANIFEST_POLICY + `ResourceMetering` + `UnbuiltComponentRecord`；**v5 零新增公开符号**——CL-01..05 修订均落在字段/判据/规则层（`ResourceMetering` 字段重写、`ComponentGraph`/`ComponentDiscoveryResult` 增字段），公开名集合不变）。

### 4.7 冲突分析

与 #266（30 文件）与 #281（6 新增文件）文件级零交集（恢复审计 addendum-2 §5 亲验；本 Packet 预期路径 `lima/audit/component_graph.py`、`schemas/v4/lima.component-graph.json`、`tests/audit/{test_component_graph,test_monorepo_golden}.py`、`tests/audit/fixtures/monorepo/**` 均不在两 PR diff 内）。与 B/C/D 切片边界按 §0 Not-covered 划分，无重叠 Owner。

---

## 5. 冻结设计（D1R Assignment §R 逐项落位 + D1_v1 §六 1-7 继承）

### 5.1 组件识别（R60-01；嵌套发现，仓库级坐标，只读有界确定）

#### 5.1.1 发现范围与锚点集合（冻结单解；替代 v1 "根+一级子目录"）

- **证据来源（组合，不单凭目录名；两个输入集合，P60-V3-04）**：锚点 = **两个输入集合**的并（去重）：(S1) 主 workspace **已准入 inventory** 中 manifest 类文件（封闭名集，值重述 inventory 冻结口径：`_MANIFEST_EXACT_NAMES` 8 类 + `requirements*.txt` 模式）的 POSIX 父目录，任意深度（`services/api`、`packages/core` 均落入——RULE-01 消除）；(S2) **受控 manifest 元数据通道**（§5.1.7）按同一封闭名集只读发现的 manifest 元数据文件的 POSIX 父目录。锚点的仓库级路径先过 `is_secret_shaped_path` 准入（下条）。组件层对 (S1) **不另起 os.walk**（发现范围 = 调用方主 workspace 的已准入集合，有界 = 调用方 cap，确定顺序 = 路径 sorted）；对 (S2) 的枚举受 §5.1.7 通道预算与安全边界约束（这是本 Packet 明示的有限发现权限，非源码准入）。
- **默认策略下九类全部可锚定（v4 重写，P60-V3-04；替代 v3/SF-2 四类盲点声明）**：封闭名集九类 kind（pyproject/setup_py/setup_cfg/requirements/environment_yml/package_json/go_mod/cargo_toml/pom_xml）在**约定默认策略**下全部可识别为锚点证据——其中 requirements\*.txt/setup.cfg/go.mod/pom.xml 四类经 (S2) 元数据通道默认识别（v3 的"默认永不可锚定"盲点由通道收口，ER addendum-1"声明承载而非消除"的判定不再适用）；其余五类默认经 (S1) 已准入集合识别（`.toml/.json/.yml/.py` 在 DEFAULT_EXTENSIONS 内）。调用方**严格 admitted-only 策略**（§5.1.7）可选：仅 (S1) 可锚点（回到源码准入单通道），该选择不被悄悄失效。**通道不支持的情形（盲点声明仅保留于此）**：封闭名集之外的文件（如 `Gemfile`/`composer.json`/`build.gradle`）不是任何输入集合的 manifest 证据——不支持属范围声明而非漏识别；如需支持属新需求（经 Packet 修订/DR，不把漏识别写成 golden）。
- **静态 workspace/build 配置证据（封闭规则集，只读静态解析）**：仓库根（`""` 锚点）的 manifest 若声明 workspace 协作语义——pyproject.toml 含非空 `tool.uv.workspace.members` 或 `tool.pdm.workspace`；package.json 含非空 `workspaces` 数组；Cargo.toml 含 `[workspace]` 表且**无** `[package]` 表——则该 manifest 为 **workspace 协作 manifest**，**不产生根组件**（其成员经自身 manifest 锚定）。除此之外的 manifest 一律为组件 manifest（含根级 pyproject 含 `[project]` 者——根组件，见 5.1.3 嵌套归属）。解析失败/未识别形态 → 按组件 manifest 保守处理（确定性默认）。
- **同目录多 manifest 归并**：同锚点目录多个 manifest 归并为同一组件，`manifests` 列表按 path 排序全记。
- **锚点准入（R60-04 前置）**：锚点目录的仓库级路径（`锚点/` + 任一子段探测）先过 `is_secret_shaped_path`——命中者**不准入为锚点**（不产组件、不进任何公开面），`INVENTORY_SKIPPED` gap（detail `reason=sensitive-filename; count=N`，N=被拒锚点数；不泄漏目录名）。
- **发现预算与截断**：发现候选数以主仓 inventory 为上界（调用方 cap 有界）；组件数 > `MonorepoBudgets.max_components`（默认 16）→ 按 component_id 序取前 16 + `BUDGET_EXHAUSTED`（detail `reason=component-limit; count=<溢出>`）+ `truncated=True` + `dependencies_complete=False`（触发集 T1，§5.2.4）。
- **不支持/受削形态（typed 承载，不静默排除）**：调用方 ignored_directories 剪枝掉的子树内 manifest（策略继承语义，(S1) 随 `skipped` 计数可见、(S2) 随通道跳过计数可见——两通道计数**分列**不合并，§5.1.7）；调用方**严格 admitted-only 策略**下源码集合 (S1) 不含的 manifest 类型（如 extensions={".py"} 时 .toml 不可见→无锚点，全仓 unassigned 如实呈现——严格策略的显式选择，非漏识别）；调用方显式禁用元数据通道（§5.1.7 严格策略）时 (S2) 关闭，四类原盲点类 manifest 不再默认可锚定（显式选择，计数与策略声明承载）；主仓 cap 截断或准入跳过（`truncated=True` 或 §5.2.4 T6 所列任一 skipped 键 >0）→ 发现不完整，触发 T6；秘密形态锚点 → 上述 gap。**以上均为范围声明而非需求缩减：无任何 Maintainer 批准的"仅一级目录"豁免，17 项原始/V5 mandatory 不删不降。**

#### 5.1.2 稳定 component ID（冻结单解）

```text
component_id = "component:" + <已准入锚点目录的 repo-relative POSIX 路径>
根目录组件   = "component:."
嵌套组件     = "component:services/api" / "component:packages/core"（POSIX 正斜杠多段，
               无尾斜杠、无 "." / ".." 段，段字符集 [A-Za-z0-9._\-]）
```

无碰撞可重放：锚点集合由已准入 manifest 文件的父目录唯一确定（sorted 枚举）；同目录归并单组件；ID 由目录路径一一映射。`components` 按 `component_id` 字符串码点升序排序（sorted 单解，稳定）；**v3 勘误（SF-3①）**：根组件 `"component:."` **不保证排序最前**——段字符集含 `-`(0x2D) 及数字/大写字母（均 < `.`(0x2E)），如 `component:-x`、`component:0a` 排其前；稳定性来自排序键单解，不依赖根组件居首。

#### 5.1.3 文件归属（单一真实归属，精确单解；R60-02）

- **归属规则（仓库级坐标，in-module 精确计算）**：已准入文件 f 的归属 = 路径前缀包含 f 的**最深**已准入锚点（锚点 a 拥有 f ⟺ f 以 `a+"/"` 开点或 f 位于 a 目录内；取路径深度最大者；根锚点 `""` 的前缀即一切路径，故天然涵盖所有未被更深锚点包含的文件——根组件存在时不存在"无前缀"文件）。无任何锚点包含 f（即不存在根锚点 `""` 且无其他锚点前缀命中）→ **unassigned**。
- **归属唯一性**：最深前缀规则在任意嵌套锚点树上单解、可机械复算（D1R 探针 D1/D2/D7 复算验证）；目录名仅为路径计算输入，**不产生任何依赖边**（边唯一来源 = AST import 证据，§5.3）。
- `python_file_count` = 该组件归属的已准入 `.py` 文件数；`is_empty = (python_file_count == 0)`（空组件如实保留、`is_empty=True`，不编造边、不剔除）。非 `.py` 已准入文件同样按归属规则划入组件构建输入（Profile inventory 维度），但不计入 `python_file_count`、不产 Python import 边。
- **unassigned 文件**：`unassigned_files` 列表（repo-relative POSIX 排序，仅 `.py`，cap = `max_unassigned_files`，超限截断 + `BUDGET_EXHAUSTED` gap）+ `unassigned_file_count` 完整计数（不受 cap 影响）。列表准入：路径先过 `is_secret_shaped_path`（命中者不入列表仅计数，§5.8）。零组件仓库 = 全部已准入 `.py` 落 unassigned，`components=()`、`edges=()`——不因零组件报错。
- **共同文件两义分别落位**：(a) "被多组件引用" = 跨组件 import 边的多条 evidence（文件归属仍唯一）；(b) "无法唯一归属" = unassigned 集。最深前缀规则下不存在第三种归属歧义（**v4/P60-V3-01**：名字碰撞目录在文件清单视图下不再产生构建隔离分歧——其文件按最深前缀正常归属并入切片、组件正常构建，"同名非子锚点目录"是**正例**（D2 锚 #55）；`unbuilt` 收缩为真拒绝/资源耗尽/无法成合法视图三类，见 §5.2.1）。
- **守恒不变量（INV-OWN-2，测试锚）**：Σ(已构建组件 python_file_count) + Σ(unbuilt 组件 python_file_count) + unassigned_file_count = 主仓已准入 `.py` 总数（逐文件可复算；三项按归属划分**互斥完备**）。**v3 勘误（SF-3③）**：v2 原式第四项"秘密形态拒绝 `.py` 计数"废除——秘密形态已准入 `.py`（已过工作区级准入）按归属**已含于** python_file_count（组件内者，如 `app/secrets/cred.py`）或 unassigned_file_count（未归属者，仅计数不入列表，§5.8），另立独立项会造成双重计数误读；RAM 层段级准入拒绝（E5：app_ram_modules=1 而归属 `.py`=3）不影响归属计数——归属与公开列表准入是两个口径，互不抵扣。
- **manifest 元数据所有权不变量（INV-OWN-3，v4 新增、**v5 按 CL-05 重写 (a)**，P60-V3-01/04；测试锚）**：(a) **划分与守恒（文件级，v5 重写——消除 RULE-COUNT ② 的单位混用与协作 manifest 无归属冲突）**：`manifests_discovered_count == Σ_C |manifests(C)| + collaboration_manifest_count + overflow_manifest_count`——每个已发现的**非协作、非溢出** manifest 文件属于恰一个组件的 `manifests` 列表（= 其锚定的组件；含 built=false 组件）；workspace 协作 manifest（§5.1.1，不产根组件）计入 `collaboration_manifest_count`，T1 截断溢出组件的 manifests 计入 `overflow_manifest_count`——两类**显式差额字段**承载，不藏条目追平数字；**秘密形态子树的 manifest 不属发现域**（通道段级剪枝先于文件枚举、S1 侧 sensitive-config 跳过），锚点拒绝计数（单位=锚点）独立承载于 INVENTORY_SKIPPED detail、不参与本文件级等式；逐文件可复算、互斥完备（§5.1.8 联合参考表=逐组合映射）；(b) **父子隔离**：嵌套子组件的 manifest **不得**出现在祖先组件（含根组件）的 `manifests` 列表（键=path 精确比对，机械可查）；(c) **Profile 层一致性（v5 经双清单视图强化）**：祖先组件 Profile 构建的 manifest 候选（§4.3.1 W-2 按 `admitted_files ∪ metadata_files` 过滤后）不含嵌套子组件 manifest——子组件 manifest 既不在父 admitted_files（属子切片）也不在父 metadata_files（父 metadata_files=父自身 manifests[]，由 (a) 划分不含子 manifest），双清单构造性隔离；(b) 与 (c) 是"父组件 Profile 不纳入子组件 manifest"裁定的两个可机械核对承载（图级 manifests 字段 + 层内候选行为）；(d) **来源可分（v5 语义澄清）**：`manifests[].source` ∈ {"source-inventory","metadata-channel"} 表达**发布事实的来源视图**（双集合成员单值取 `source-inventory`，(S1) 优先）——与发现计量域分离（重叠成员计入 `metadata_manifest_count` 但发布 source=source-inventory；`Σ(metadata-channel 发布) ≤ metadata_manifest_count`，差额映射见 §5.1.8，不再要求两数相等——RULE-COUNT ① 消除）。

#### 5.1.4 解析依据不足与不执行

- 归属证据不足（无已准入锚点前缀）→ unassigned 如实记录，不按目录名猜测组件；
- 依赖解析依据不足 → 边三态 + 未知导入承载（5.3），不编造依赖；
- **不执行目标项目补证据**：零 importlib 目标代码、零 subprocess、零网络、零 sys.path 探测（模块静态断言，§6 C7）；manifest 与 `.py` 只经 `workspace.read_text()` 有界读取后静态解析（`tomllib`/`ast.parse`，IP-0016 setup.py 先例）。

#### 5.1.5 适用输入范围与不支持形态声明（冻结）

任意 `RepositoryWorkspace` 快照（含非 monorepo）：零组件/单组件（仅根 manifest，图 = 单组件零边，合法输出）/多组件/嵌套组件/根 workspace 协作 manifest。图分析面向已准入 `.py`（Python 平台，Golden Path 口径与三层一致）；其他语言文件进入组件 Profile 的 inventory 维度（既有行为），不产组件间 Python import 边。**不支持/受削形态一律 typed 承载（§5.1.1 末）+ 范围声明，不静默排除**；确需削减 mandatory 支持 → 具体需求 DR + Maintainer 明确批准（默认继续完成目标）。

#### 5.1.6 与 `repository_kinds` 的关系（不重算、不修改）

monorepo kind 判定是 inventory 冻结行为（作用于全仓单仓构建）。本片每组件构建使用组件 workspace（其内部一般无嵌套 manifest 子目录，组件 profile 通常不判 monorepo——如实呈现，不修正）；全仓维度 kind 分类由既有 `build_repository_profile(全仓 workspace)` 独立承载（现状行为，零改动）。组件图与 kinds 各自表述，互不覆写。

#### 5.1.7 受控 manifest 元数据通道（v4 新增，P60-V3-04；DR-IP-0023-03 已采纳方向的本片设计，冻结单解）

**定位**：本通道是对九类 manifest 的**有限只读发现权限**，用于组件边界证据与静态声明依赖名（§5.3.3 P4b）——**不扩大源码准入**：通道发现的 manifest 文件不进入 (S1) 可分析源码集合（不计入 python_file_count、不被 AST 扫描、不进组件 Profile 的 inventory 维度——除非其扩展恰在调用方扩展策略内且经主仓 inventory 已准入，此时同一路径双集合成员、来源字段按判据表单值规则取值——单值取 `source-inventory`（(S1) 优先，见下判据表 provenance 行））；**不重新准入被主 workspace 拒绝的源码**（D2 锚 #60）。

**封闭名集（九类，值重述 inventory 冻结口径 §3.1，不 import 私有符号）**：`_MANIFEST_EXACT_NAMES` 8 类精确名 {Cargo.toml, environment.yml, go.mod, package.json, pom.xml, pyproject.toml, setup.cfg, setup.py} + `requirements*.txt` fnmatch 模式（九类 kind 枚举 §5.4.2）。名集**封闭**：集合外文件（含 `Gemfile`/`composer.json`/`build.gradle` 等）不是本通道对象（不支持=范围声明，§5.1.1）。

**两策略（调用方可选，不悄悄失效）**：
- **默认策略 `metadata-channel`**：通道开启。九类（尤其 requirements\*.txt/setup.cfg/go.mod/pom.xml 四类原盲点）在约定默认策略下可识别为锚点证据（§5.1.1 (S2)）——**正例**（D2 锚 #54 前半）。
- **严格策略 `admitted-only`**：通道关闭，锚点证据仅 (S1) 主仓已准入 inventory（回到 v2/v3 单通道语义）。严格策略一经指定，任何 (S2) 发现不得进入锚点/manifests/依赖声明——不因默认值或内部回退失效（**负例**，D2 锚 #54 后半）。
- 策略参数形态（keyword，缺省=默认策略）：公开签名经 `detect_components` / `build_monorepo_profile` 的 `manifest_policy: str = "metadata-channel"` 参数承载（枚举两值，外值 `ValueError`；D2 定稿签名时锁定，语义本轮锁定）。

**枚举与读取（封闭、只读、有界）**：通道枚举 = 仓库根起 `os.walk(topdown, followlinks=False)`，逐目录剪枝：目录名 ∈ 调用方 `ignored_directories`（按名，与 workspace 口径一致）、任一路径段命中 `is_secret_shaped_path`（段级，仓库级坐标）、symlink 目录（不跟随即天然剪枝）；仅收集命中封闭名集的**常规文件**（symlink 文件拒绝）。读取 = 每文件经主 workspace `read_text`（有界 ≤`max_file_bytes`、UTF-8、`_safe_path` 边界）——**优先复用已准入快照的读取通道，不另开裸文件 IO**（`read_text` 对仓库内相对路径的读取本不受扩展策略限制——扩展策略只作用于 inventory 发现（§3.3 亲验），故**通道自身零共享层 additive 需求**，§4.3.1 白名单与它无关；组件层自有 os.walk 即本条明示的有限发现权限，非 (S1) 源码准入通道）。静态解析 = `tomllib`/逐行 regex（§5.3.3 P4b 同口径）+ workspace/build 协作键识别（§5.1.1）；**不执行构建脚本**；静态边界证据按明确组合规则处理（manifest 存在性 + 静态声明内容），不把非 Python 图边能力纳入本片。

**预算（数量+字节，P60-V3-03 三分离口径）**：`max_metadata_manifests`（默认 64 / 合法域 1..1024 / schema 硬帽 1024——通道**发现**的 manifest 文件数上界，含与 S1 重叠成员——CL-05 发现域口径，§5.1.8）与 `max_metadata_total_bytes`（默认 1 MiB=1_048_576 / 合法域 ≥1 / 语义=通道累计读取字节预算；逐文件另受 `max_file_bytes` 上界）。任一预算触发：停止进一步发现/读取 + `BUDGET_EXHAUSTED` gap（detail `reason=metadata-manifest-limit; count=<溢出>` 或 `reason=metadata-byte-limit; count=<溢出字节>`）+ 已得静态事实保留（fail-closed 部分产物，过自身 validator，§5.4.4）+ **`dependencies_complete=False`（v5/CL-01：经 T8 触发，§5.2.4 唯一决策表——数量/字节停止属 S2 证据丢失，不得报成"真实无依赖"；截断点前已发现/已读事实照常发布，未发现者不虚构）**。

**跳过计数（分通道，不改写主 inventory 事实；v5/CL-01 逐键归类）**：通道自有 `metadata_channel_skipped: dict[reason→count]`（封闭词表：`ignored-directory` / `sensitive-filename` / `symlink` / `unreadable` / `non-utf8` / `metadata-manifest-limit` / `metadata-byte-limit`），与主仓 `skipped` **分列呈现**、不合并、不回写——主 inventory 事实（reason→count）不被通道追平或改写（D2 锚 #61 前半）；**gap detail 与通道键同值同现时的计数归属（v4.1 勘正补注，v5 增对账）**：各计各的承载字段——图 gap detail 侧计入 `coverage_gaps` 对应 detail 的 count、通道侧计入 `metadata_channel_skipped` 对应键的 count，两侧分列、不合并、不重复计数；**v5 对账规则**：同一 reason 在两承载同时出现时 count 必相等（validator V7 核对，§5.4.8）。**逐键归类（政策主动拒绝 vs 证据丢失，机械可判）**：①`metadata-manifest-limit`/`metadata-byte-limit`（预算截断）/`unreadable`（非预期读取失败）/`non-utf8`（解码失败）四键 = **证据丢失** → 触发 **T8**（§5.2.4），complete=False，不进"真实无依赖"分支；②`ignored-directory`（调用方忽略策略）/`sensitive-filename`（秘密形态隐私准入——准入范围=段级 `is_secret_shaped_path`，显式且封闭）/`symlink`（不跟随安全策略，与 S1 豁免同口径）三键 = **政策主动拒绝**（显式选择，非意外丢失）→ 不触发 T8，计数可见 + 范围声明承载；③**严格策略 `admitted-only`**：通道整体关闭属调用方显式选择——通道未运行不产生任何丢失事件（四类原盲点不可锚定为选择结果，非证据丢失，不以此触发 T8；策略声明与计数承载，§5.1.7 两策略节）。策略豁免均有明确准入范围，不把意外丢失伪装为选择（丢失类=四键封闭集，其余一律入丢失类处理——键集扩展须 Packet 修订）。

**两输入集合的准入/所有权/计数/provenance 判据（机械可核对）**：

| 维度 | (S1) 可分析源码集合 | (S2) manifest 元数据集合 |
|---|---|---|
| 准入 | 仅经主仓 workspace 工作区级准入（ignored/symlink/sensitive-config/extension/size/binary/non-utf8 + cap） | 仅经通道封闭名集 + 通道剪枝规则（ignored 按名/秘密段/symlink/常规文件）+ 通道双预算 |
| 所有权 | 最深锚点前缀归属（§5.1.3） | 每 manifest 属于其锚定的组件（父目录=锚点）；** INV-OWN-3**（§5.1.3） |
| 计数 | `python_file_count` / `unassigned_file_count` / 主仓 `skipped` | 每组件 `manifests[]`（含 `source` 字段）+ `metadata_manifest_count`（图级，**单义=S2 通道发现总数，含 S1∩S2 重叠成员**——v5/CL-05）+ `metadata_channel_skipped` + 发现域 `manifests_discovered_count` 等（§5.1.8 联合参考表） |
| provenance | workspace 层级准入链（既有语义） | `ComponentManifestRef.source ∈ {"source-inventory","metadata-channel"}`（同一路径双集合成员时=`source-inventory`，(S1) 优先单值——**source 表达发布事实的来源视图，与发现计量域分离**（v5/CL-05：重叠成员计入 metadata_manifest_count 但发布 source=source-inventory，不再要求二者相等）；通道/Profile 读取计量入 `ResourceMetering`（§5.4.4-IO S3/S8 阶段归属） |

**安全边界（全尊重，逐项）**：调用方明确禁止（ignored_directories 按名剪枝；严格 admitted-only=显式禁用通道）；秘密形态（路径段级 `is_secret_shaped_path`——命中目录/文件不入通道任何输出，仅 `sensitive-filename` 计数）；symlink（目录不跟随、文件拒绝）；仓库边界（`_safe_path`/`read_text` 有界通道，不越 root）；不可变 Snapshot（通道纯只读，零写盘零执行零网络）。

### 5.1.8 五计量域与联合参考表（v5 新增，CL-05；全文唯一——与 CL-01 丢失事件、CL-02 双视图读取、CL-04 IO 阶段归属可对账）

**五个计量域（各自单义，同名字段全链唯一语义）**：

| 域 | 定义（单义） | 承载 |
|---|---|---|
| D1 发现 | S1∪S2 去重后的 manifest **文件**发现总数（路径级；主仓 inventory 截断/准入跳过时=实际发现值，S1 侧丢失经 T6 承载） | `manifests_discovered_count`（payload+canonical） |
| D2 通道发现 | S2 通道枚举命中的 manifest 文件数（**含 S1∩S2 重叠成员**；预算消耗同口径——max_metadata_manifests 按 D2 计满） | `metadata_manifest_count`（payload+canonical；与 D1 关系恒有 D2 ≤ D1） |
| D3 尝试读取 | 各阶段读取**尝试**次数（含失败尝试与 unbuilt/截断前已发生；不含枚举目录本身） | `ResourceMetering`（metering-only，不进 payload/digest；§5.4.4-IO 九阶段归属） |
| D4 成功读取 | 成功读取字节累计（失败尝试 0 字节） | `ResourceMetering.read_success_bytes`（metering-only） |
| D5 最终发布 | 进入 payload `components[].manifests[]` 的条目（含 built=false 组件——ComponentInfo 不论构建成败均承载 manifests；不含协作/截断溢出/未发现者） | `manifests[]`（payload+canonical 经 components 投影）+ 守恒式差额字段 |

**联合参考表（组合 × 域映射；每一组合在五域的归属唯一、机械可判）**：

| 组合 | D1 发现 | D2 通道发现 | D3 尝试读 | D5 发布条目 | manifests[].source | 守恒项 |
|---|---|---|---|---|---|---|
| S1-only 组件 manifest（如子目录 pyproject 经 S1 准入） | +1 | 不计（通道未命中或命中即转 overlap 行） | S3 每 Profile 候选读 1 次 | 组件 manifests[] | `source-inventory` | Σ_C\|manifests(C)\| |
| S2-only 组件 manifest（requirements\*.txt/setup.cfg/go.mod/pom.xml 默认策略） | +1 | +1 | S8 通道读 1 次 + S3 Profile 读 1 次（重复读全计量，CL-04） | 组件 manifests[] | `metadata-channel` | Σ_C\|manifests(C)\| |
| S1∩S2 overlap（如根 pyproject.toml：.toml 在 DEFAULT_EXTENSIONS 内且通道命中） | +1（去重） | +1 | S8 1 次 + S3 1 次 | 组件 manifests[] | `source-inventory`（发布事实来源视图=S1；**与 D2 计数分离——RULE-COUNT ① 消除：不再要求 D2==Σ(metadata-channel 发布)**） | Σ_C\|manifests(C)\| |
| workspace 协作 manifest（根 Cargo.toml 仅 [workspace] 等，§5.1.1——不产根组件） | +1 | 命中通道则 +1 | S8 1 次（协作语义判定必读）；Profile 侧无归属组件故无 S3 | **不进任何组件 manifests**，计 `collaboration_manifest_count` | —（无发布条目） | `collaboration_manifest_count` |
| 秘密形态子树内 manifest | **不计**（通道段级剪枝先于文件枚举、S1 侧 sensitive-config 跳过——不属发现域，计数不外泄；锚点拒绝计数=INVENTORY_SKIPPED `reason=sensitive-filename`，单位=锚点，不与文件数混用——RULE-COUNT ② 单位混用消除） | 不计 | 0（未枚举即剪枝，无读取尝试） | 不发布 | — | 无（不在等式内） |
| T1 组件数截断溢出组件的 manifests | +1/文件 | 命中通道则 +1/文件 | 已发生者计入（截断前发现/读取照实计量） | 不进 components（组件被截断），计 `overflow_manifest_count`；complete=False(T1) | — | `overflow_manifest_count` |
| 通道预算截断（数量/字节帽） | 截断点前已发现者 +1/文件；其后**不发现**（未发现者不虚构、不追平） | 同左 | 已尝试者计入 | 截断前已归属者照常发布 | 按集合成员 | 丢失经 **T8**（§5.2.4）+ gap detail count==通道键 count 对账承载 |
| 读取失败/解码失败（unreadable/non-utf8） | +1（枚举命中即发现、锚定成立） | 命中通道则 +1 | S8 尝试 1 次（失败计入）、S3 1 次 | 组件 manifests[] 保留（发布的是发现事实；解析无静态事实=部分产物） | 按集合成员 | 丢失经 **T8**；成功字节计 0 |
| 多 manifest 同锚点 | 每文件独立 +1 | 逐文件 | 每文件各计 | 同组件 manifests[] 全记（按 path 排序） | 逐文件按集合成员 | Σ 按文件数（锚点归并不改变文件级计数） |
| 严格策略 admitted-only | S1 manifests 照常 | **0**（通道关闭=显式选择，非丢失，不触发 T8） | S8=0；S3 仅 S1 候选 | 组件 manifests[]（仅 S1 成员） | `source-inventory` | 守恒式照常成立 |
| 主仓 cap 截断/准入跳过（T6） | 实际发现值（S1 侧不完整） | 不受影响 | S0 照实 | 已发现者照常 | 按集合成员 | S1 侧丢失经 **T6**（§5.2.4）承载 |

**守恒等式（INV-OWN-3(a) v5 重写，文件级、payload 机械可核）**：`manifests_discovered_count == Σ_C |manifests(C)| + collaboration_manifest_count + overflow_manifest_count`（三项差额字段 payload+canonical 承载；无秘密项——秘密子树不在发现域；validator V7 核对，§5.4.8）。**辅助不等式**：`metadata_manifest_count ≤ manifests_discovered_count`；`Σ_C |{m ∈ manifests(C): m.source=="metadata-channel"}| ≤ metadata_manifest_count`（差额=overlap 发布条目转 source-inventory + 协作/溢出中的通道命中者，逐组合映射见上表——不藏条目、不虚构）。

**九类"可发现"与"旧解析器支持何种信息"分开声明（CL-02）**：(a) **可发现（D1/D2 域）**=九类封闭名集（§5.1.7）文件在两输入集合的发现资格——发现≠解析；(b) **旧 Profile 解析器已支持的静态信息提取（读取/解析域）**=`build_repository_profile` 经 `_load_manifests` 对 manifest 候选能取得的既有静态事实（框架/包管理器等维度，逐 kind 的支持程度=inventory 冻结行为，值重述不重定义）——本片经双清单视图（CL-02）保证候选可见性与读取权限，从而**至少保持**旧 Profile 已能从本组件 manifest 获得的静态框架/包管理事实；(c) **本片新增解析（§5.3.3 P4b 封闭集）**=pyproject `[project].dependencies` 依赖名 + `requirements*.txt` 行首名两处（不扩成九语言依赖解析）；(d) 通道对 go_mod/pom_xml 等其他 kind 的使用=锚点/workspace 协作语义判定 + 旧 Profile 既有解析维度，不新增依赖解析能力（范围声明，非漏识别）。

### 5.2 每组件 Profile/RAM/semantic 全链（R60-02/R60-03/R60-04；复用公共接口 + 策略继承 + 隔离不变量）

#### 5.2.0 构建时序（冻结；R60-04 准入时序单解）

```text
(1) 仓库级准入（唯一入口，调用方策略）：main_inventory = workspace.inventory()
    —— 工作区级准入（ignored/symlink/sensitive-config/extension/size/binary/non-utf8）
      在仓库级坐标完成；skipped 计数与 truncated 状态公开可读（T6 触发源）。
(2) 锚点发现与锚点准入（§5.1.1，仓库级坐标：is_secret_shaped_path）。
(3) 归属划分（§5.1.3，精确最深前缀，仓库级坐标）。
(4) 组件视图构造（§5.2.1，继承策略）+ 隔离不变量校验（逐文件，仓库级映射比对）。
(5) 图级 import 扫描（§5.3.1，经主 workspace.read_text，仓库级坐标）。
(6) 每组件三段链（Profile/RAM/semantic，经组件 workspace，组件内坐标——
      准入等价性见 §5.2.1 证明）。
任何组件级/图级公开输出所含路径，或为仓库级坐标且已过 (1)(2) 准入，
或为组件内坐标且其仓库级原像已过 (1)(2) 准入——无第三种来源。
```

#### 5.2.1 组件视图构造与所有权不变量（v4 重写，P60-V3-01；精确文件清单视图，冻结单解）

**方案选定（P&V 冻结单解）**：在"完整文件清单视图"与"路径级排除视图"两者中选定**文件清单视图（explicit file-list view）**——组件 workspace 以 `admitted_files=精确归属切片` 构造（§4.3.1 W-1 additive 白名单，激活条件=本 Packet v5 获批），用**单一机制**同时约束三入口，弃路径级排除方案（其只影响 walk 剪枝，读取入口需另加校验、双份簿记且无法表达"恰好这个集合"）。**v5/CL-02 增补（双清单视图）**：源码视图保持 S1 精确切片不动；组件对**自身获准 manifest 元数据**另经第二清单 `metadata_files`（=该组件 `manifests[]` 的组件内坐标集，由 INV-OWN-3 划分唯一确定，不含子组件 manifest）取得受控读取/候选可见性——W-1 双清单 + W-2 并集过滤是三入口约束的完整单解（API-META 反例实质修复，§5.1.8 判据表）。

```python
# 每组件（component_id 序遍历，未超 max_components 截断的全部处理）：
component_ws = RepositoryWorkspace(
    workspace.root if root_dir == "" else workspace.root / root_dir,
    max_files=workspace.max_files,               # 五参数全部继承（R60-03；API-02 消除）
    max_file_bytes=workspace.max_file_bytes,
    max_total_bytes=workspace.max_total_bytes,
    extensions=workspace.extensions,
    ignored_directories=workspace.ignored_directories,   # 原样继承；不再并集子锚点 basename
    admitted_files=<精确归属切片：主仓已准入文件中归属本组件者的组件内相对 POSIX 路径集>,
    metadata_files=<本组件 manifests[] 的组件内相对 POSIX 路径集（v5/CL-02 自身元数据视图；
                    不含子组件 manifest——INV-OWN-3 划分唯一确定；不进 inventory 结果>)
if {map_to_repo(f) for f in component_ws.inventory().files} != ownership_slice(root_dir):
    # 隔离不变量（INV-OWN-1）事后机械复核（受限态下由构造保证成立；此处防御性复核
    # 捕获：继承 cap 在受限态截断切片（cap-divergence）/ 锚点根无法解析为常规目录
    # （view-unformable）/ 防御性准入拒绝（admission-refused）—— 三类 typed 可区分）：
    unbuilt_components += [UnbuiltComponentRecord(component_id, reason=<三类之一>)]  # T7
    continue
profile_result   = build_repository_profile(component_ws, **六 ID 参数原样透传,
                        producer="lima.audit.component_graph",
                        policy_digest=..., toolchain_digest=...,
                        options=profile_options)            # 复用 IP-0016 入口
ram_result       = build_python_ram_facts(component_ws, budgets=effective_ram_budgets)
semantic_result, effective_semantic_options = _semantic_stage(   # 复用 IP-0019 入口；
    ram_result.facts, semantic_options,                      # 聚合包络/token 池 §5.4.4；
    model_client, remaining_pool_state)                      # 返回实际生效 options（禁回填默认）
ram_wire         = ram_wire_payload(ram_result, semantic_result,
                        profile_budgets=effective_profile_budgets,   # 实际生效值（P60-V3-02）
                        ram_budgets=effective_ram_budgets,
                        semantic_options=effective_semantic_options) # 只读复用 ram_schema 公共接口
```

**三入口约束调用链（P60-V3-01 裁定落位；每入口：机制/公开签名/缺省兼容/预算/测试锚）**：

| 入口 | 约束机制（调用链） | 公开签名（承载参数） | 缺省兼容（不传新参数） | 预算 | D2 测试锚 |
|---|---|---|---|---|---|
| (a) inventory 扫描集合（**源码视图**） | `component_ws.inventory()` 在受限态仅返回 `admitted_files` 成员（§4.3.1 W-1；`metadata_files` 不进 inventory 结果——源码视图不被元数据视图扩大）→ 三层入口内部各自调用的 `workspace.inventory()` 全部受限 | `RepositoryWorkspace.__init__(root, *, max_files, max_file_bytes, max_total_bytes, extensions, ignored_directories, admitted_files=None, metadata_files=None)` | 两参数 `None` → 构造/inventory/统计逐字节同旧默认（既有调用点零改动） | 受限态 cap（max_files/max_total_bytes）作用于切片自身；溢出→truncated→INV-OWN-1 分歧→unbuilt(cap-divergence) | #9/#10（INV-OWN-1/2 扩展）、#55、#71（S2-only 不进源码视图） |
| (b) read_text/全部读取入口 | `component_ws.read_text(p)` 在受限态对 `p ∉ admitted_files ∪ metadata_files` 按既有越界错误口径拒绝（`_safe_path` 边界之上的成员校验层；**双清单并集准入**——自身 manifest 可读、子组件 manifest 与一切集合外路径不可读）；图层级 AST 读取不经组件视图（主 workspace 仓库级，本就受主仓准入约束） | 同上（`admitted_files`+`metadata_files` 一并约束 `read_text`/`absolute_file`；`WorkspaceInventory.fingerprint()` 为 inventory 结果对象方法、受限态自然仅覆盖 admitted 集——`RepositoryWorkspace` 无 fingerprint 属性（§3.7），不新增共享层接口） | 同上（None 不增设任何拒绝） | 每读取 ≤`max_file_bytes`（既有）；读取尝试/字节计量入 `ResourceMetering`（§5.4.4-IO：S2-S6 组件链/S3 manifest 阶段归属） | #55/#56（读取边界随切片）、#63、#69/#70（自身 manifest 可读+父子隔离） |
| (c) Profile 层 manifest 候选 | `build_repository_profile(component_ws) → inventory._manifest_candidates(component_ws)` 在受限态过滤为 `admitted_files ∪ metadata_files` 成员（§4.3.1 W-2）——`_manifest_candidates` 本不消费 inventory 文件集（§3.6/§3.7 衔接事实），故必须显式经此白名单项约束；父组件候选=自身 manifest（子 manifest ∉ 父双清单） | 无新公开签名（经 `admitted_files`/`metadata_files` 间接承载；W-2 为 inventory 内部函数行为） | None → `os.listdir` 名集匹配逐字节同旧 | 每候选 1 次读取尝试（S3 计量）；每组件 ProfileBudgets 既有约束照旧（manifest_max_bytes/max_manifest_files） | #56（父 Profile 不纳入子组件 manifest=INV-OWN-3(c)）、#69（自身 manifest 事实保留）、#70 |

- **策略继承（R60-03 冻结，不变）**：不从路径重建默认 workspace；五参数逐一取自调用方 workspace 的公开属性（extensions/ignored_directories 为其**有效值** frozenset。**v3 勘误（SF-3②）保留**：构造器对 extensions 是 **None/空→DEFAULT_EXTENSIONS 的 or 替换、非与 DEFAULT 的并集**——非空入参完全生效；ignored_directories 则**恒与 DEFAULT_IGNORED_DIRECTORIES 并集**（§3.3 源码亲验））。**v4 变化**：`ignored_directories` 不再并集"子锚点 basename"（basename-ignore 机制废除——名字碰撞目录文件在切片内正常扫描，正例构建）；`admitted_files` 为新增第六构造维度（白名单 W-1），主仓未准入输入不因组件切分重新准入：**组件视图文件集 = 主仓已准入集 ∩ 归属切片 ⊆ 主仓已准入集，由构造强制**（INV-OWN-1 降为事后机械复核）。**v5/CL-02 增补**：`metadata_files` 为第七构造维度（白名单 W-1 第二参数）——只扩大 `read_text`/`absolute_file`/W-2 候选的**受控元数据读取面**（自身 manifest），不改变 inventory 文件集（源码视图零影响）、不重新准入任何源码（S2-only 不计 python_file_count/不进 AST/不进 Profile inventory 维度，§5.1.7）；其成员恰为本组件 `manifests[]`（INV-OWN-3 划分），父组件集合不含子组件 manifest（父子隔离由清单构造成立）。
- **INV-OWN-1（机器可校验，测试锚 #9；v4 语义）**：`map_to_repo(component_ws.inventory().files) == 精确归属切片`（逐文件集合相等；`map_to_repo(p) = root_dir + "/" + p`，根组件恒等映射）。受限态下**由构造成立**；仍保留为独立机械复核（防实现漂移/继承 cap 截断），分歧即 typed unbuilt（不出错误数据）。成立 ⇒ ComponentInfo 计数、Profile、RAM、Top-N、图 evidence **五处输入集合一致**。
- **unbuilt 三类语义（P60-V3-01 裁定；`UnbuiltComponentRecord{component_id, reason}`，reason 封闭枚举）**：`cap-divergence`（继承 cap 在受限态截断切片：`inventory().truncated==True` 或集合不等且归因于 cap——真资源耗尽类）；`view-unformable`（锚点根路径无法解析为可枚举常规目录等无法形成合法视图类）；`admission-refused`（防御性：构建期发现锚点/切片准入失效——正常时序下不可达，保留以防 TOCTOU 类漂移，原因字段如实）。**真拒绝、资源耗尽、无法成合法视图三类可机械区分**（reason 字段），`unbuilt` 不再承载任何"同名目录"类假分歧（v3 已知限度 (ii) 撤销）。
- **准入等价性（R60-04 证明，不变）**：对已准入锚点 a，其组件 workspace 相对坐标下任一文件路径的**目录段与文件名段** = 仓库级坐标对应段（仅丢失 a 之上的段，而已准入锚点无秘密形态段——§5.1.1 锚点准入）；`is_secret_shaped_path`/`_secret_shape_family` 按段判定 ⇒ 组件内 Profile/RAM 准入与仓库级准入对同一文件**判定一致**（API-03 的 rebased 重新采纳不可达——D1R 探针 D4-API03）。
- **六 ID 参数**对每组件原样透传同一组值；`policy_digest`/`toolchain_digest` 默认 sentinel（DR-IP-0016-01 口径）；`producer` 固定 `"lima.audit.component_graph"`（调用方不可覆盖）。
- **坐标分离（保留冻结声明）**：每组件三段产物内路径 = 组件内相对坐标（与单仓行为一致）；图与边证据、unassigned、锚点、manifest refs 一律仓库级 repo-relative POSIX；映射 `仓库路径 = root_dir + "/" + 组件内路径` 确定可复算（payload 消费核对用，§5.4.6）。
- **v3 已知限度 (i)(ii) 的处置（v4 撤销）**：(i) 祖先组件 Profile 层 manifest 候选混入子组件 manifest——由入口 (c)（W-2 受限过滤）消除，撤销项；残余：**白名单激活前**（本 Packet v5 获批前——v4 起为激活条件、v5 沿用并扩充白名单为双清单）实现层不得使用受限态，此期间限度 (i) 依旧存在于"实现禁区"而非设计（设计单解已定）；(ii) 名字碰撞目录 typed 不构建——由文件清单视图消除（正例 #55），撤销项。两项不再是默认完成方案的终点（P60-V3-01 裁定原文达成）。

#### 5.2.2 provenance（冻结单解）

- 每组件三段 `provenance_anchor_ids` 原样保留（`("inventory",)` / `("ram-facts",)` / `("semantic-prioritizer",)`）——逐层断言（与 golden_matrix 先例同）；
- 组件身份 provenance = `ComponentInfo.manifests`（manifest 路径 + kind 枚举，仓库级坐标）；
- 边 provenance = evidence 位点列表（`EdgeEvidence{path, line, imported_name}`，排序去重 cap）；
- 图级 `provenance_anchor_ids = ("component-graph",)`（新 anchor，独立承载；**不修改** `ram_schema.PROVENANCE_ANCHOR_CHAIN` 冻结三元组）。

#### 5.2.3 断开的组件（disconnected）

无任何入边/出边的非空组件 = 图中孤立节点，**如实呈现**（`components` 含该节点，`edges` 无引用）；空组件同。不编造连接、不删除节点、不加"孤立"特殊标记（孤立性由 edges 可推导）。

#### 5.2.4 三态区分与统一完整性（R60-06；单规件，全文唯一；**v5/CL-01 唯一 completeness 决策表吸收并替代 v4.1 触发集表+三态表两处表述**）

**`dependencies_complete = False` 的封闭触发集（全文唯一定义，v1 L265-269 与 L310-311 矛盾消除；v5 扩为 T1-T8）：**

| 触发 | 判据（机械可查） |
|---|---|
| T1 组件数截断 | `discovery.truncated == True`（组件数 > max_components） |
| T2 组件内 .py 截断 | 任一已构建组件 `ram_result.facts.coverage_gaps` 含 `BUDGET_EXHAUSTED` 且 detail 以 `reason=python-file-limit` 开头 |
| T3 边数截断 | 边数超 `max_edges` 被截断（§5.3.4） |
| T4 解析失败 | 图层级 `parse_error_file_count` 总计 > 0（§5.3.1 自计，不依赖底层继承——API-04） |
| T5 读取失败 | 图层级 `read_failure_file_count` 总计 > 0（同上；静态快照下难构造，保留触发并如实声明） |
| T6 主仓 cap 截断或准入跳过 | 主仓 `inventory.truncated == True` 或 `skipped` 中 {`file-limit`, `total-size-limit`, `file-size-limit`, `binary`, `non-utf8`, `unreadable`} 任一键计数 >0（发现与证据输入不完整；**v3/ER SF-1**：保守纳入后四键——E1 实跑证明 v2 判据下 oversize/non-utf8/binary `.py` 跳过时 T1-T7 全不触发、"已看见全部输入"成为无据断言） |
| T7 隔离分歧 | `unbuilt_components` 非空（v4：`UnbuiltComponentRecord` 三类 reason——cap-divergence/view-unformable/admission-refused，P60-V3-01） |
| **T8 S2 元数据证据丢失（v5/CL-01 新增）** | `metadata_channel_skipped` 中 {`metadata-manifest-limit`, `metadata-byte-limit`, `unreadable`, `non-utf8`} 任一键计数 >0，**或**图 `coverage_gaps` 含 `BUDGET_EXHAUSTED` 且 detail 以 `reason=metadata-manifest-limit`/`reason=metadata-byte-limit` 开头（双承载任一命中即触发；两承载同现时 count 必相等——§5.1.7 对账规则）。**政策主动拒绝不入本触发**（`ignored-directory`/`sensitive-filename`/`symlink` 三键=显式策略豁免；严格策略下通道未运行不产生丢失事件——逐键归类见 §5.1.7）。触发时：数量/字节停止、读取/解码失败有部分事实与具体计数、`dependencies_complete=False`、**不得报成"真实无依赖"**；截断前已得静态事实保留（部分产物过自身 validator） |

除 T1-T8 外无任何置 False 的来源；evidence/unassigned 列表截断不置 False（gap 承载，与 v1 §5.3.4 口径统一）；**模型 off / 聚合模型调用/token 池耗尽等非依赖证据状态不触发任何 T、不改变 `dependencies_complete`**（`SEMANTIC_MODEL_OFF` 与 `aggregate-*-limit` gap 不计入依赖证据——已有静态事实/AST 边不受误伤，§5.4.4 降级语义）。**T6 承载（v3，ER SF-1）**：T6 触发时图 `coverage_gaps` 对全部计数>0 的 T6 键**逐键**落 `INVENTORY_SKIPPED`（detail `reason=<键名>; count=<计数>`，如 `reason=non-utf8; count=1`；reason→count、无文件名——R1 口径）——按 workspace 冻结行为 `truncated=True` 必伴 `file-limit`/`total-size-limit` 键计数>0（§3.3 源码口径），故 T6 触发时逐键承载恒非空，E1 的"图输出零承载"形态不可达。**T8 承载（v5）**：双承载（图 gap detail + `metadata_channel_skipped` 键）计数相等、字段分列（§5.1.7 对账规则）——预算截断键经 `BUDGET_EXHAUSTED`（detail `reason=metadata-manifest-limit; count=N` / `reason=metadata-byte-limit; count=N`）、通道读取/解码失败键（`unreadable`/`non-utf8`）经 `INVENTORY_SKIPPED`（detail `reason=<通道键名>; count=N`，与 T6 键同构承载）逐键落图 `coverage_gaps`；`discovery.truncated` 语义**不扩**（仍=组件数截断 T1 专属——v4.1 L637 的"truncated 只反映组件数截断"限度由 T8 专属触发消除，元数据截断状态不再挤入 truncated 字段）。**跳过原因逐项处置（主仓封闭词表 10 键全归类 + 通道七键归类，无静默项）**：主仓 `file-limit`/`total-size-limit`/`file-size-limit`/`binary`/`non-utf8`/`unreadable` → **入 T6**；`ignored-directory`/`unsupported-extension` → **豁免**（调用方或默认扩展/忽略策略的**显式选择**，属策略语义而非证据丢失——计入 T6 将使一切含 `.png`/`.md` 等文件的仓库恒不完整；计数经 `skipped` 公开可见 + §5.1.1 范围声明承载）；`sensitive-config` → **豁免**（工作区级准入语义：该类文件不得进入任何输出，计数可见）；`symlink` → **豁免**（与单仓 RAM 行为口径一致，避免双标准；计数可见）；通道七键归类见 §5.1.7（四键入 T8、三键豁免、严格策略不触发）。**保守性如实声明**：`skipped` 公开计数无扩展名维度，非 `.py` 文件的 binary/non-utf8/file-size-limit/unreadable 跳过同样触发 T6——fail-closed 取向（未看见的输入不能成为完整性证明），宁可过度判"证据不足"。

**唯一 completeness/三态决策表（v5/CL-01：优先级式单遍历分类，吸收/替代 v4.1 三态判据表；构建器、DiscoveryResult、payload、validator、测试计划与消费说明同义引用本表，不得另写冲突补注）：**

分类对象=**无 resolved 出边**的组件（有 resolved 出边 = 有依赖，非三态对象）；分类函数单遍历、按优先级取**唯一**值：

| 优先级 | 状态 | 判据（机械可查，自上而下首个命中） |
|---|---|---|
| P1 | 解析失败 | 该组件存在 `status ∈ {"ambiguous","unresolved"}` 的出边 |
| P2 | 证据不足 | 不满足 P3 全合取（任一不成立即命中）：图 `dependencies_complete == True`（T1-T8 全不触发）**且** `unassigned_file_count == 0` **且** 该组件 `scan_summary.parse_error_file_count == 0` **且** `read_failure_file_count == 0` **且** 该组件无 `unknown_imports` 记录 **且** 该组件无参与边（`SEMANTIC_MODEL_OFF` 及聚合模型/token gap 不计入依赖证据——模型状态非依赖证据） |
| P3 | 真实无依赖 | P1/P2 均未命中（P2 全合取成立） |

**互斥完备与唯一性（RULE-COMPLETE 消除）**：三分按优先级取首个命中——谓词重叠时分类仍唯一；P3 全合取含 `dependencies_complete == True`，故 T8（及任何 T）触发时 P3 不可能命中，"gap 非空但 complete=True 且同时命中真实无依赖与证据不足两行"的形态不可达；`dependencies_complete` 单值（T1-T8 封闭集）+ 优先级决策表 = 全文唯一定义（v4.1 L442/L444 两行可同时命中的歧义消除）。**空边集伴随缺口 ≠ 真实无依赖**（P3 全合取使二者互斥，机械可查；测试锚 #32/#64-#67）。

**解析/读失败 typed 承载（R60-06 交付；替代 v1"底层继承"表述）**：图层级 AST 扫描（§5.3.1）自计每组件 `ComponentScanSummary{component_id, parse_error_file_count, read_failure_file_count, dynamic_import_site_count}`（计数 only，无路径无源码正文；API-04 关系：RAM `counters.parse_error_files` 存在而 facts gaps 可空——v2 不依赖 RAM gap 继承，图自计并触发 T4）。若 D2 冻结期发现需新 GAP 码 → 具体 DR（不私改 `GAP_CODES_ALL`/9 码触发；**v5：T8 复用既有 `BUDGET_EXHAUSTED`/`INVENTORY_SKIPPED` 码 + detail 承载，无新 GAP 码需求**——通道 unreadable/non-utf8 失败经 `INVENTORY_SKIPPED` detail `reason=<键>; count=N` 承载，预算截断经 `BUDGET_EXHAUSTED` detail 承载，均不触 GAP 集）。

### 5.3 模块解析（R60-05；模块根解析替代目录首段臆断，未知导入有承载）

#### 5.3.1 证据采集（图层级，主 workspace，仓库级坐标）

- 扫描对象 = 全部**归属** `.py` 文件（按仓库级路径 sorted）；unassigned `.py` 不产边（`unassigned_file_count>0` 显式声明证据缺口）；
- 解析方式 = `ast.parse(workspace.read_text(path))`（主 workspace 有界读取）；**parse 失败自计** `parse_error_file_count`（触发 T4），**读失败自计** `read_failure_file_count`（触发 T5），**动态 import 位点自计** `dynamic_import_site_count`（封闭检测集：`ast.Call` 且函数名为 `importlib.import_module` / `importlib.util` 动态装载形态 / `__import__`；不产边）；收集 `ast.Import`（各 alias 顶级名）与 `ast.ImportFrom`（module 名 + level）；
- 证据位点 = `EdgeEvidence{path: 仓库级 repo-relative, line: 1 基行号, imported_name: import 的名字}`（imported_name 是标识符/点号串，非源码正文——NFR-01 相容）；
- 与 `python_dataflow.py` 的关系：**只读语义参照**（§5.3.5），本层不 import 该模块（依赖方向不变）。

#### 5.3.2 模块根解析（module roots；冻结单解）

组件 C（锚点 `root_dir`，组件内坐标）的**模块根集合** R(C)（确定序：组件根在前，其余按路径升序）：

- (a) **组件根本身**（flat 布局：包/模块直接位于组件根）；
- (b) **构建配置声明的目录**（封闭键集，静态解析组件自身 manifest）：pyproject.toml `[tool.setuptools.packages.find] where`（值或值列表）、`[tool.setuptools.package-dir]` 值中的目录部分、`[tool.hatch.build.targets.wheel] packages` 路径的公共父目录——解析失败/键缺失 → 不贡献（保守回退 (a)/(c)，未知导入承载兜底）；
- (c) **内容证据支持的 `src` 直接子目录**：组件根的直接子目录 `src`，当且仅当其直接内容含 ≥1 包（含 `__init__.py` 的子目录）或 ≥1 `.py` 模块（src 布局约定 + 内容证据，非目录名臆断——RULE-02 消除：`A/src/alpha`、`B/src/beta` 下顶层名 `alpha`/`beta` 分别归属 A/B，D1R 探针 D6-RULE02）。

**顶层名表（name table）**：对每组件 C，`names(C)` = {各模块根直接子项的导入名}——含 `__init__.py` 的子目录（regular package，名=目录名）、模块根直接子 `.py`（名=去扩展名）、模块根直接子**无** `__init__.py` 目录（**namespace package 候选**，名=目录名，证据较弱但仍可解析；同多名跨组件 → ambiguous）。构建仓库级名→组件集映射表（确定序，sorted）。

#### 5.3.3 边推导规则（封闭枚举；优先级显式）

对归属文件中的每条绝对 import（顶级名 T，非 "." 开头）：

| 情形（按序判定，优先级冻结） | 判定 | 承载 |
|---|---|---|
| P1 `T ∈ names(C源)`（**先命中自身**） | 组件内依赖 | 无边（属该组件 RAM 范围；自身定义的名字优先于跨组件同名——静态单解声明） |
| P2 `T ∈ names(C')` 唯一 `C'≠C源` | 跨组件 resolved | 边 (C→C', status="resolved", imported_name=T) |
| P3 `T ∈ names(≥2 组件)` | 重复模块名歧义 | 边 (C→target=None, status="ambiguous")；候选集不入边；歧义范围由名表可复算 |
| P4a `T ∈ stdlib 冻结集` | **已知外部（stdlib）** | 无边、无承载（确定外部；集为模块内冻结字面量快照，值锚定来源注释，跨解释器版本稳定优先） |
| P4b `T ∈ 该组件 manifest 静态声明依赖名`（封闭解析：pyproject `[project].dependencies` 依赖名 + `requirements*.txt` 行首名，regex `^[A-Za-z0-9_.\-]+`；解析失败不贡献） | **已知外部（三方，有证据）** | 无边、无 unknown 承载 |
| P5 其余 | **未知导入**（无法区分未声明三方/仓库内无法定位/拼写错误） | `unknown_imports` 记录 {source_component_id, imported_name, count}（排序去重 cap `max_edges` 同预算；**不产边、不伪称外部**） |

对相对 import（`level ≥ 1`，**包上下文优先**）：

- 包上下文 = 导入文件经其 `__init__.py` 链与所属模块根推导的包序列（文件在包内：level=1 → 当前包，level=2 → 父包，依此类推）；文件不在任何包内（模块根直接子 `.py`）→ 物理路径上下文（当前目录基准）；目标 = 上下文向上 `level-1` 层 + module 路径，仓库坐标；
- 目标落回本组件子树（`.py` 存在或包 `__init__.py` 存在）→ 无边；落另一已准入锚点子树且存在 → 边 resolved；不存在（含越出仓库根）→ 边 (C→None, status="unresolved")；落秘密形态路径 → 不入 evidence（§5.8 准入）。

#### 5.3.4 去重、排序与 cap（冻结单解）

- resolved 边键 = `(source, target)`；ambiguous/unresolved 边键 = `(source, status, imported_name)`；同键多证据聚合进 `evidence`；
- `evidence` 按 `(path, line, imported_name)` 排序去重，每边 cap = `max_edge_evidence`，超限截断 + `BUDGET_EXHAUSTED`（detail `reason=edge-evidence-limit; count=<溢出>`）；
- `edges` 按 `(source_component_id, status, target_component_id or "", imported_name)` 升序；总数 cap = `max_edges`，超限截断 + gap（detail `reason=edge-limit; count=<溢出>`）+ **T3 置 `dependencies_complete=False`（引用 §5.2.4 触发集，不另立口径）**；
- `unknown_imports` 按 `(source_component_id, imported_name)` 排序去重，cap = `max_edges`（共享），超限截断 + gap（detail `reason=unknown-import-limit; count=<溢出>`）。

#### 5.3.5 与既有 `python_dataflow` 解析语义的对照（只读声明，R60-05 交付）

`PythonDataflowAnalyzer._module_name` 以**全路径**派生点分模块名（单一名空间、每文件必归属、`__init__.py` 判包）；本组件层为**多根名空间**（每组件独立模块根集合，顶层名对组件解析）。语义差异如实声明：dataflow 回答"该文件叫什么名"，组件层回答"该顶层名由哪个组件定义"；两者均纯静态、零执行、零 sys.path 探测。不引入对 `python_dataflow` 的 import 依赖（值/语义对照，非代码复用）。

### 5.4 独立版本化 component graph 承载（Assignment §六.3 / R60-08；B-10 先例）

#### 5.4.1 数据结构（frozen dataclass，全部在 `lima/audit/component_graph.py`）

```python
@dataclass(frozen=True)
class ComponentManifestRef:
    path: str            # 仓库级 repo-relative manifest 路径（已发现：S1 已准入或 S2 通道）
    manifest_kind: str   # COMPONENT_MANIFEST_KIND_* 枚举值（5.4.2）
    source: str          # v4 新增（P60-V3-04 provenance 分离）；v5/CL-05 语义澄清：
                         # "source-inventory"（S1 主仓已准入）| "metadata-channel"（S2 通道发现）；
                         # 双集合成员时取 "source-inventory"（S1 优先单值）——source 表达**发布事实
                         # 的来源视图**，与发现计量域分离（重叠成员计入 metadata_manifest_count
                         # 但发布 source=source-inventory；不再要求两计数相等——§5.1.8）

@dataclass(frozen=True)
class EdgeEvidence:
    path: str            # 仓库级 repo-relative POSIX（.py 文件，已准入）
    line: int            # 1 基
    imported_name: str   # import 顶级名或相对导入点号串

@dataclass(frozen=True)
class ComponentInfo:
    component_id: str    # "component:." / "component:<锚点相对路径（可多段）>"
    root_dir: str        # ""（根）或锚点 repo-relative 路径（可多段）
    manifests: tuple[ComponentManifestRef, ...]   # 按 path 排序（INV-OWN-3 划分/父子隔离）
    python_file_count: int
    is_empty: bool

@dataclass(frozen=True)
class ComponentScanSummary:          # v2 新增（R60-06：图层级自计承载）
    component_id: str
    parse_error_file_count: int      # T4 触发源（计数 only，无路径）
    read_failure_file_count: int     # T5（同上；静态快照下通常 0，字段保留）
    dynamic_import_site_count: int   # 动态 import 位点计数（不产边）

@dataclass(frozen=True)
class UnknownImportRecord:           # v2 新增（R60-05：未知导入 typed 承载）
    source_component_id: str
    imported_name: str
    count: int                       # 该名字的 import 位点数（evidence 同构口径）

@dataclass(frozen=True)
class UnbuiltComponentRecord:        # v4 新增（P60-V3-01：unbuilt 三类可区分）
    component_id: str
    reason: str                      # UNBUILT_REASON_* 封闭枚举（5.4.2）：
                                     # "cap-divergence"（资源耗尽）| "view-unformable"
                                     # （无法成合法视图）| "admission-refused"（真拒绝，防御性）

@dataclass(frozen=True)
class ComponentEdge:
    source_component_id: str
    target_component_id: str | None    # resolved 非 None；ambiguous/unresolved 为 None
    status: str                        # COMPONENT_EDGE_STATUS_*（5.4.2）
    imported_name: str
    evidence: tuple[EdgeEvidence, ...] # 排序去重 cap（5.3.4）

@dataclass(frozen=True)
class ResourceMetering:              # v4 新增 P60-V3-05；**v5 重写（CL-04）：计量域=读取尝试次数（含失败尝试与 unbuilt 前已发生）+ 成功字节；阶段归属分列（§5.4.4-IO 九阶段表）；distinct files 不在此重复承载（由 discovered/切片/归属计数承载，§5.1.8 D1 域）**
    main_inventory_read_attempts: int       # S0 主仓 inventory（每已发现文件 1 次尝试，含需读后跳过者）
    component_rescan_read_attempts: int     # S1+S2+S4+S5+S6 每组件链累计（预检/Profile inventory+source/RAM inventory+source；含 unbuilt 组件截断前已发生）
    profile_manifest_read_attempts: int     # S3 每组件 Profile manifest 候选读取（含双清单视图 metadata_files 读取与失败尝试）
    ast_read_attempts: int                  # S7 图层级 AST 读取（主 workspace，每归属 .py 1 次）
    metadata_channel_read_attempts: int     # S8 §5.1.7 通道 manifest 读取（含失败尝试）
    read_success_bytes: int                 # 全链成功读取字节累计（失败尝试计 0 字节；确定性量）

@dataclass(frozen=True)
class ComponentGraph:
    components: tuple[ComponentInfo, ...]              # 按 component_id 升序
    edges: tuple[ComponentEdge, ...]                   # 按 5.3.4 排序
    unassigned_files: tuple[str, ...]                  # 排序，cap，已过准入
    unassigned_file_count: int
    unknown_imports: tuple[UnknownImportRecord, ...]   # 排序去重 cap（5.3.4）
    scan_summaries: tuple[ComponentScanSummary, ...]   # 按 component_id 升序
    unbuilt_components: tuple[UnbuiltComponentRecord, ...]  # v4：三类 reason 可区分（T7）
    dependencies_complete: bool                        # 触发集 T1-T8（§5.2.4）
    coverage_gaps: tuple[ProfileCoverageGap, ...]      # gap_code 复用 10 码全集值重述（5.6.3）
    manifests_discovered_count: int                    # v5（CL-05 D1 域）：S1∪S2 去重发现总数（文件级）
    metadata_manifest_count: int                       # v5（CL-05 D2 域）：S2 通道发现总数（含重叠成员；与
                                                       # ComponentDiscoveryResult 同名同义——全链唯一语义）
    collaboration_manifest_count: int                  # v5：协作 manifest 差额项（守恒式 §5.1.3/§5.1.8）
    overflow_manifest_count: int                       # v5：T1 截断溢出组件 manifests 差额项
    provenance_anchor_ids: tuple[str, ...] = (COMPONENT_GRAPH_PROVENANCE_ANCHOR,)
```

#### 5.4.2 枚举（Final 常量，冻结单解）

```python
COMPONENT_GRAPH_SCHEMA_VERSION: Final[str] = "2.0"    # v2 承载字段集（v1 未实现未发布，无迁移；v4 字段集仍称 2.0——从未实现/发布，无迁移负担）
COMPONENT_GRAPH_SCHEMA_NAME: Final[str] = "lima.component-graph"
COMPONENT_GRAPH_SCHEMA_FILE: Final[Path] = Path("schemas") / "v4" / "lima.component-graph.json"
COMPONENT_GRAPH_PROVENANCE_ANCHOR: Final[str] = "component-graph"
COMPONENT_EDGE_STATUS_RESOLVED: Final[str] = "resolved"
COMPONENT_EDGE_STATUS_AMBIGUOUS: Final[str] = "ambiguous"
COMPONENT_EDGE_STATUS_UNRESOLVED: Final[str] = "unresolved"
COMPONENT_EDGE_STATUSES: Final[frozenset[str]] = frozenset({"resolved","ambiguous","unresolved"})
COMPONENT_MANIFEST_KIND_*: Final[str]  # 九值："pyproject" / "setup_py" / "setup_cfg" /
                                       # "requirements" / "environment_yml" / "package_json" /
                                       # "go_mod" / "cargo_toml" / "pom_xml"（对齐 manifest 候选口径）
UNBUILT_REASON_CAP_DIVERGENCE: Final[str] = "cap-divergence"      # v4（P60-V3-01 三类）
UNBUILT_REASON_VIEW_UNFORMABLE: Final[str] = "view-unformable"
UNBUILT_REASON_ADMISSION_REFUSED: Final[str] = "admission-refused"
UNBUILT_REASONS: Final[frozenset[str]] = frozenset({...三者...})
COMPONENT_MANIFEST_SOURCE_INVENTORY: Final[str] = "source-inventory"   # v4（P60-V3-04）
COMPONENT_MANIFEST_SOURCE_METADATA_CHANNEL: Final[str] = "metadata-channel"
COMPONENT_MANIFEST_SOURCES: Final[frozenset[str]] = frozenset({...两者...})
MANIFEST_POLICY_METADATA_CHANNEL: Final[str] = "metadata-channel"  # v4 默认策略（§5.1.7）
MANIFEST_POLICY_ADMITTED_ONLY: Final[str] = "admitted-only"        # v4 严格策略
MANIFEST_POLICIES: Final[frozenset[str]] = frozenset({...两者...})
# 模块私有（不入 __all__）：_STDLIB_TOP_LEVEL_NAMES（冻结字面量快照，§5.3.3 P4a）
```

#### 5.4.3 公共函数签名（冻结单解）

```python
@dataclass(frozen=True)
class MonorepoBudgets:
    # v4 重写（P60-V3-03/05）：每字段 默认值 / 合法域 / 硬上限 三分离。
    # 构造期校验（__post_init__）= 合法域（type is int 且域内，否则 ValueError）；
    # schema maxItems（§5.5）= 独立硬上限（= 各域上界；单解：静态独立硬帽，弃动态 schema 校验——
    # 保持 schema 静态可独立校验、不与 payload 内容耦合）；运行截断（builder）= 有效 budgets。
    # 三者不相同时行为唯一：合法域内输入一律接受；产物计数 ≤ min(有效预算, 硬帽)；
    # 超硬帽的负载只能来自非法构造/篡改 → 构造期 ValueError 或 validator 拒绝。
    max_components: int = 16            # 默认 16 | 合法域 1..64 | schema maxItems 64
    max_edges: int = 4_096              # 默认 4096 | 合法域 1..16_384 | schema maxItems 16384
    max_edge_evidence: int = 64         # 默认 64 | 合法域 1..1_024 | schema maxItems 1024
    max_unassigned_files: int = 256     # 默认 256 | 合法域 1..4_096 | schema maxItems 4096
    max_total_model_calls: int = 8      # v4（P60-V3-05）：全仓累计**尝试次数**口径，默认 8
                                        #（128 提案已否决）；合法域 1..512；非列表无 schema maxItems；
                                        # >8 的取值=显式配置+政策授权（未来审批点，本轮不授予）
    aggregate_max_prompt_tokens: int = 24_000     # v4 聚合 token 池（prompt 预估口径，单位=token）；
    aggregate_max_output_tokens: int = 4_096      # **v5/CL-03：三字段=requested（请求值）**——有效三池
    aggregate_max_total_tokens: int = 28_096      # effective = min(requested 对应字段, 实际生效
                                                  # SemanticBudgets 对应字段)（§5.4.4 计算函数与四类
                                                  # 对照表）；合法域 1..1_000_000（三字段独立）；域内
                                                  # 约束 total ≥ prompt+output（构造校验，与
                                                  # SemanticBudgets L242-246 同构）；默认=层默认常数
                                                  # 24000/4096/28096（保守不放大，P60-V3-05）；
                                                  # 高于保守默认的实际使用=显式配置+政策授权（§13.3）
    max_metadata_manifests: int = 64    # v4（P60-V3-04）：§5.1.7 通道数量预算
    max_metadata_total_bytes: int = 1_048_576     # 通道字节预算（默认 1 MiB | 合法域 ≥1）

@dataclass(frozen=True)
class ComponentDiscoveryResult:
    components: tuple[ComponentInfo, ...]
    unassigned_files: tuple[str, ...]
    unassigned_file_count: int
    metadata_manifest_count: int                        # v4 起 (S2) 通道发现总数；**v5/CL-05 单义化：含
                                                        # S1∩S2 重叠成员**（两集合计数分离、与 D5 发布域
                                                        # 分离——§5.1.8；与 ComponentGraph 同名同义）
    metadata_channel_skipped: Mapping[str, int]         # v4：通道分列跳过计数（§5.1.7 词表+逐键归类）
    manifests_discovered_count: int                     # v5（CL-05 D1 域）：S1∪S2 去重发现总数（文件级）
    collaboration_manifest_count: int                   # v5：协作 manifest 数（发现已读、不产组件、不进
                                                        # 任何组件 manifests——守恒差额项）
    overflow_manifest_count: int                        # v5：T1 截断溢出组件的 manifests 数（守恒差额项）
    coverage_gaps: tuple[ProfileCoverageGap, ...]
    truncated: bool                      # 组件数超 max_components（语义不扩——元数据截断经 T8，§5.2.4）
    provenance_anchor_ids: tuple[str, ...] = (COMPONENT_GRAPH_PROVENANCE_ANCHOR,)

@dataclass(frozen=True)
class ComponentBuildResult:
    component: ComponentInfo
    profile_result: ProfileBuildResult
    ram_result: RamFactsBuildResult
    semantic_result: SemanticTopNResult
    ram_wire: Mapping[str, object]                     # v4（P60-V3-02）：该组件 RAM wire payload
                                                       #（ram_wire_payload 只读复用产出，已含 build 段）
    effective_profile_budgets: ProfileBudgets          # v4：实际生效配置（何者被保存的机械承载）
    effective_ram_budgets: RamBudgets
    effective_semantic_options: SemanticOptions        # 聚合调整后的实际值（禁回填 None/层默认）

@dataclass(frozen=True)
class MonorepoProfileBuildResult:
    discovery: ComponentDiscoveryResult
    per_component: tuple[ComponentBuildResult, ...]   # 按 component_id 升序（实际构建的组件）
    graph: ComponentGraph
    metering: ResourceMetering                        # v4（P60-V3-05）：读放大计量（§5.4.4-IO）
    provenance_anchor_ids: tuple[str, ...] = (COMPONENT_GRAPH_PROVENANCE_ANCHOR,)

def detect_components(workspace: RepositoryWorkspace, *,
                      budgets: MonorepoBudgets | None = None,
                      manifest_policy: str = MANIFEST_POLICY_METADATA_CHANNEL,
                      ) -> ComponentDiscoveryResult

def build_monorepo_profile(workspace: RepositoryWorkspace, *,
                           tenant_id: str, task_id: str, workflow_id: str,
                           stage_attempt_id: str, artifact_id: str,
                           repository_snapshot_digest: str,
                           policy_digest: str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                           toolchain_digest: str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                           profile_options: ProfileInventoryOptions | None = None,
                           ram_budgets: RamBudgets | None = None,
                           semantic_options: SemanticOptions | None = None,
                           monorepo_budgets: MonorepoBudgets | None = None,
                           manifest_policy: str = MANIFEST_POLICY_METADATA_CHANNEL,
                           model_client: SemanticModelClient | None = None,
                           ) -> MonorepoProfileBuildResult

def component_graph_digest(graph: ComponentGraph) -> str        # 64-hex（5.4.5）
def component_graph_payload(result: MonorepoProfileBuildResult) -> dict   # wire payload（5.4.6）
def validate_component_graph_payload(payload: Mapping[str, object]) -> None  # fail-closed ContractError（5.4.8）
def load_component_graph_schema() -> dict                       # 只读加载 schema 文件（零网络）
```

**行为约束（v4 修订，冻结）**：stdlib-only + 既有 audit/contracts/workspace 模块；依赖方向 `lima.audit.component_graph → {lima.audit.inventory, lima.audit.ram, lima.audit.semantic_prioritizer, lima.audit.ram_schema, lima.contracts.*, lima.workspace}`（复用公共构建接口与 `is_secret_shaped_path`；**只读复用** `lima.audit.ram_schema` 公共接口——`ram_wire_payload` / `validate_ram_wire_payload` / `ram_facts_digest_from_wire` / `semantic_result_digest_from_wire` / `ram_wire_digest` / `execution_required_from_gaps`——用于每组件 RAM wire 的产出、校验与消费核对；**不复制、不重定义其摘要、gap、execution_required 规则，不修改该模块既有行为**——P60-V3-02 裁定，废除 v3 "不 import ram_schema" 表述）；`detect_components`/`build_monorepo_profile` 入参非 `RepositoryWorkspace` → `ContractError(INVALID_FIELD_TYPE)`；`manifest_policy` ∉ MANIFEST_POLICIES → `ValueError`（fail-closed，严格策略不被悄悄失效）；非 str 六 ID / 非 64-hex digest 按 IP-0016 同口径 fail-closed（异常由底层传播，本层不吞不改）；模型路径失败不抛出到调用方（IP-0019 §5.0 部分结果语义）；纯函数确定性——无时钟/随机/env/网络/写盘（`metering` 只计读取次数与字节，均为确定量）。

#### 5.4.4 预算语义单解（v4 重写，P60-V3-05 + P60-V3-03；fail-closed）

- **策略继承（第一原则，不变）**：组件视图五参数 + `admitted_files` 继承调用方（§5.2.1）；主仓未准入输入不重新准入（构造强制 + INV-OWN-1 事后复核，分歧→typed unbuilt(cap-divergence)）；调用方 cap 收紧时"不扩权优先于多产出"。
- **聚合模型调用包络（v4 重写；128 提案否决）**：**模型默认 off**——`model_client is None`（默认）→ 零调用零网络（与 IP-0019 缺省一致）；启用 fake/未来获准客户端时**全仓默认调用额度 8**（`MonorepoBudgets.max_total_model_calls` 默认 128→8，字段语义=**全仓累计尝试次数**口径：每次向 client 发起的调用计 1 次，**超时/失败尝试计入**，不用成功数代替尝试数）；**更高额度须显式配置并取得政策授权**——本 Packet 只冻结技术合法域（1..512）与默认 8，>8 的实际使用是未来审批点（本轮不授予真实模型调用权限；fake client 仅限离线设计反证与测试）。执行：按 component_id 序构建；每组件生效调用额度 = `min(该组件 SemanticBudgets.max_llm_calls, 剩余聚合尝试额度)`（`dataclasses.replace` 公共构造合法对象）；剩余归零后的组件 semantic 阶段以无 client 形态执行（确定性 Top-N 保留，模型补充跳过）+ `BUDGET_EXHAUSTED`（detail `reason=aggregate-model-call-limit; count=<溢出组件数>`）——机器可读截断，无静默。
- **聚合 token 池与 effective 三池（v4 新增，**v5/CL-03 重写——v4.1"池不构成额外授权/先触发的总是口径 1/2 护栏"补注被 API-POOL 反例限定并撤销**）**：`aggregate_max_prompt_tokens` / `aggregate_max_output_tokens` / `aggregate_max_total_tokens`（单位=token，**预估口径**）。**requested / default / effective 三值定义（单解）**：①**requested** = MonorepoBudgets 三字段配置值（调用方可显式设置；合法域 1..1_000_000、total ≥ prompt+output 构造校验）；②**default** = 层默认常数 24_000/4_096/28_096（未显式配置时的 requested 值；=单组件 SemanticBudgets 默认对应值）；③**effective** = **min(requested 对应字段, 实际生效 SemanticBudgets 对应字段)**（计算函数 `_effective_aggregate_pools(monorepo_budgets, effective_semantic_budgets) -> tuple[int, int, int]`，每构建求值一次；"实际生效 SemanticBudgets"= 本次构建传入 `semantic_options.budgets`（None 时=层默认 24000/4096/28096）经聚合层收紧前的调用方有效值）。**保守缺省保证**：effective 三池分别 ≤ 本次实际生效 SemanticBudgets 对应值（min 单调）；**较大 caller 不自动扩池**（effective ≤ requested 恒成立）；**显式提高额度/池=政策授权单列**（requested 高于保守默认的实际使用须显式配置+未来审批点，本轮默认路径不含——§13.3）。**API-POOL 可达调度的关闭**：caller 1000/500/1500 时 effective=1000/500/1500，逐次预扣后第 2 次尝试（output 剩余 244 < 预估 256）即停止——v4.1 语义下累计 1684/2048/3732 超 caller 的调度在 v5 规则下**不可达**。
- **聚合调度单一规则（v5/CL-03：预调用估算/扣减、remaining 不足、失败不退、零额度合法降级、effective 配置承载、摘要承载——全文唯一，不另写补注）**：(i) **预调用估算与扣减**：每次尝试调度前按冻结估算器口径（`_estimate_tokens=ceil(chars/4)` 同构，模块内私有实现或公共等价）预估 prompt/output tokens（输出=每候选常数×批量，与冻结层同构）；对 effective 三池的**剩余量**逐项校验（prompt 剩余 ≥ 预估 prompt、output 剩余 ≥ 预估 output、total 剩余 ≥ 预估 prompt+output）；任一不足 → **该尝试不调度**（不再进入 client 调用），组件按无 client 形态降级（确定性 Top-N 保留）+ typed gap `BUDGET_EXHAUSTED(reason=aggregate-token-pool-limit; count=<跳过尝试数>)`；三项均足 → 调度并从三池**预扣**（prompt+output 同扣、total 同扣）；(ii) **remaining 不足**：不调度新尝试（上述 (i) 口径），已得静态事实/AST 边/确定性 Top-N 全保留，聚合模型/token gap 不触发任何 T、不改 `dependencies_complete`（非依赖证据状态——§5.2.4）；(iii) **失败不退**：已预扣额度不退还（尝试已发生；与"超时/失败计入尝试数"同口径），client 异常按 IP-0019 部分结果语义降级不外抛；(iv) **零额度合法降级**：effective 三池（或聚合尝试额度）归零后，后续组件 semantic 以无 client 形态执行——**不构造 `SemanticBudgets(max_llm_calls=0)`**（非法对象，L221-246 正值校验冻结）、不回填层默认、不填伪 digest、不删已得事实（§5.4.4 参数边界表零额度行 + 降级自洽）；(v) **effective 配置承载**：wire `build` 段与图 payload `build.monorepo_budgets` 均携带 **effective 值**（min 推导后的实际生效配置；回填 requested/None 即与实际构建不一致、wire_digest 失配）；(vi) **摘要承载**：effective 配置值（确定性）进 wire build 段从而进 wire_digest；实际计量/池剩余（运行量）不进任何 digest——确定性优先。**模型 off**（`model_client is None`）：零尝试零消耗（三池零扣减）、`SEMANTIC_MODEL_OFF` 语义不变、静态事实不受影响。
- **三口径区分声明（P60-V3-05 裁定；亲读冻结代码行号锚）**：本设计区分三个互不混淆的口径——(口径 1) **旧单次预估校验**：`SemanticBudgets.max_prompt_tokens_estimate/max_output_tokens_estimate/max_total_tokens_estimate`，在每组件语义遍历内部逐次调度前校验（`semantic_prioritizer.py` L456/L459-460/L463-465），是**单次调用的预估护栏**，冻结不变；(口径 2) **每组件调用额度**：`SemanticBudgets.max_llm_calls`（每组件 ≤8 次尝试，L451 校验），语义不变（聚合层只经 replace 收紧不放宽）；(口径 3) **全仓累计池（本片新增）**：`max_total_model_calls` 尝试次数池 + 三 token 累计池（effective 口径，v5）——**旧 SemanticBudgets 无任何字段实现此口径**（`max_total_tokens_estimate` 不是全仓累计池——它是口径 1 的单次预估上界）；本片不改旧 SemanticBudgets 定义。**聚合层不得把"口径 1/2 逐次护栏仍通过"解释为"口径 3 累计约束满足"**（API-POOL 反例的教训：8 次尝试逐次护栏全过而累计 1684/2048/3732 超 caller 对应值——口径 3 必须由 effective 三池独立强制，v4.1 依赖"护栏先行"的补注已撤销）。
- **四类对照表（v5/CL-03 D1 出口：默认/小 caller/大 caller/显式更高，graph 级调度非单独数学表——D2 锚 #72）**：

| 情形 | 实际生效 SemanticBudgets（prompt/output/total） | requested 聚合池 | effective 三池 | 全仓调度行为（唯一） |
|---|---|---|---|---|
| 默认调用方 | 24000/4096/28096（层默认） | 24000/4096/28096 | min=24000/4096/28096 | 正常调度；三池=层默认；模型 off 时零消耗 |
| 小 caller（API-POOL 夹具） | 1000/500/1500 | 24000/4096/28096 | **1000/500/1500** | 累计截止在 caller 对应值内（第 2 次尝试 output 剩余 244<256 即止）；截止后 typed gap `aggregate-token-pool-limit` + 静态事实/确定性 Top-N 保留；1684/2048/3732 调度不可达 |
| 大 caller | 50000/8192/58192 | 24000/4096/28096 | **24000/4096/28096**（min 封顶） | 不自动扩池；行为同默认池 |
| 显式更高配置 | X（caller 语义生效） | 显式 >默认（政策授权点） | min(requested, X) | 显式配置+政策授权单列（§13.3），本轮默认路径不含；有效配置如实承载 |
- **参数边界行为表（P60-V3-03 裁定；逐样例唯一判定 + D2 锚）**：

| 样例 | 判定 | 唯一行为 | D2 锚 |
|---|---|---|---|
| `max_components=17` | 接受（域 1..64 内） | 组件数 ≤17 → 全构建无截断；>17 → 按 component_id 序保留前 17 + `BUDGET_EXHAUSTED(reason=component-limit; count=溢出)` + `truncated=True` + T1 | #58 |
| `max_components=0/-1/非 int/65` | 拒绝 | 构造期 `ValueError`（合法域校验），无部分产物 | #24/#58 |
| `top_n=21`（SemanticOptions） | 接受（冻结域 1..100 内，L258-268） | 每组件 ranked 承载 21 项；图 `semantic_topn.top_n=21`、`ranked_candidate_ids` 长度 ≤21（cap=top_n 实际生效值，默认 20 非帽）；schema maxItems 100 通过 | #58 |
| `top_n=0/101` | 拒绝（既有冻结行为） | `SemanticOptions` 构造期 `ValueError`（本层传播不重定义） | #58 |
| 调用方紧 cap（如 max_files=3、切片 5 文件） | 接受 + typed 降级 | 组件 inventory 受限态在 cap 处截断 → INV-OWN-1 分歧 → `unbuilt(cap-divergence)`；不扩权、不报错、主仓事实不变 | #20/#58 |
| `max_total_model_calls=1`（fake client） | 接受 | 全仓恰 1 次尝试；其后组件无 client 降级 + `aggregate-model-call-limit` gap | #21/#62 |
| 聚合 token 池耗尽（剩余 < 本次预估） | 接受 + typed 降级 | 不调度该尝试；已扣不退；静态事实+确定性 Top-N 保留 | #62 |
| 零额度降级（聚合尝试与 token 双归零） | 接受 + typed 降级 | **不构造** `SemanticBudgets(max_llm_calls=0)`（非法，L221-246 正值校验冻结）——降级=组件 semantic 以无 client 形态执行（确定性 Top-N 保留）+ 图级 typed gap；**不填伪 digest**（digests 槽=该组件真实产物摘要，semantic_result_digest 为确定性排序的真实摘要）；**不删已得 Profile/RAM/确定性排序**；部分产物过自身 validator（§下"降级自洽"） | #59/#62 |
- **降级自洽（P60-V3-03 第 4 点）**：耗尽/截断形态的部分产物——图 payload 过 `validate_component_graph_payload`、每组件 wire 过 `validate_ram_wire_payload`（两者皆公共 validator）；`built`/status、coverage_gaps、build 段有效配置（含聚合调整后的实际 semantic 配置——**不得回填 None/层默认**，回填即 wire_digest 自洽失配，§3.6 衔接事实）与三摘要自洽；**额度耗尽保留静态事实与确定性 Top-N**、增准确 typed gap/status（`BUDGET_EXHAUSTED` detail 口径如上）；**图依赖证据（AST 边）与模型补充状态（semantic 段/gap）区分**——无模型补充 ≠ 无组件依赖（三态判据表 §5.2.4 中 `SEMANTIC_MODEL_OFF` 不计入依赖证据的既有口径保持）。
- **IO 计量域与可核验上界（`§5.4.4-IO` 小节；v4 新增 P60-V3-05，**v5/CL-04 整节重写——v4.1 `component_rescan_file_reads ≤ Σ(已构建组件切片文件数)` 公式被 API-IO 反例否决并废除**；`ResourceMetering`（§5.4.1 v5 六字段）承载于 `MonorepoProfileBuildResult.metering`，不进 wire payload/digest——observability 载体，D2 以公式断言核验）**。**四种单位（不混用）**：(u1) **distinct files**=逻辑文件数（由 discovered/切片/归属/manifests 计数承载，§5.1.8 D1/D5 域）；(u2) **读取尝试次数**=各阶段 `read_bytes`/`read_text` 尝试累计（**含失败尝试与 unbuilt/截断前已发生的工作**——不只数成功 built）；(u3) **成功读取字节**=成功尝试的字节累计（失败尝试计 0）；(u4) **通道/阶段归属**=每次尝试唯一归属下表九阶段之一（与 CL-05 D3 域同一定义）。**九阶段归属表（完整旧公共链 + 本片新增，逐阶段尝试构成与上界）**：

| 阶段 | 触发者（调用链） | 尝试构成 | 阶段上界（保守常数） |
|---|---|---|---|
| S0 主仓 inventory | build 入口 §5.2.0(1) | 每已发现文件 1 次尝试（含需读后才判跳过者） | ≤ discovered_files |
| S1 每组件预检 inventory | §5.2.1 INV-OWN-1 复核 `component_ws.inventory()` | 每切片文件 1 次 | ≤ Σ_C\|slice(C)\|（全部锚定组件，含 unbuilt——截断前已发生照计） |
| S2 每组件 Profile inventory | `build_repository_profile` 内部 inventory | 每切片文件 1 次 | ≤ Σ_C\|slice(C)\| |
| S3 每组件 Profile manifest 读取 | Profile 内部 `_manifest_candidates`→`_load_manifests`（含双清单 metadata_files 候选） | 每候选 manifest 1 次（含被拒/失败） | ≤ Σ_C(组件 manifest 名集命中数) |
| S4 每组件 Profile source 读取 | Profile 源码证据（L714-735） | 每切片文件 1 次 | ≤ Σ_C\|slice(C)\| |
| S5 每组件 RAM inventory | `build_python_ram_facts` 内部 inventory（L429） | 每切片文件 1 次 | ≤ Σ_C\|slice(C)\| |
| S6 每组件 RAM source 读取 | RAM 逐候选 `_read_python_text`（L465-469） | 每切片 `.py` 1 次 | ≤ Σ_C\|slice_py(C)\| |
| S7 图 AST 读取 | §5.3.1 主 workspace | 每归属 `.py` 1 次 | ≤ 归属 `.py` 总数 |
| S8 S2 通道 manifest 读取 | §5.1.7 通道 `read_text` | 每通道命中 manifest 1 次（含失败） | ≤ max_metadata_manifests（D2 域口径） |

  **保守常数倍上界（替换 v4.1 L706 公式；机械可查、D2 锚 #63 断言）**：`component_rescan_read_attempts（=S1+S2+S4+S5+S6）≤ 5 × Σ_C |slice(C)|`（.py 每文件链内恰 5 次尝试、非 .py 恰 4 次——无 RAM source 读取；常数 5 封顶覆盖两类）；`main_inventory_read_attempts ≤ discovered_files`；`profile_manifest_read_attempts ≤ Σ_C(组件 manifest 名集命中数) ≤ manifests_discovered_count + 候选拒绝数`；`ast_read_attempts ≤ 归属 .py 总数`；`metadata_channel_read_attempts ≤ max_metadata_manifests`；**全链合成式**：`总尝试 ≤ 7 × discovered_files + 2 × manifests_discovered_count + max_metadata_manifests`（7=主仓 1+组件链 5+图 AST 1，对 `.py` 每文件最坏 7 次、非 `.py` 5 次——常数 7 封顶；2=通道+Profile 各 1 次/manifest；对 API-IO 夹具：三段链实测 5 ≤ 5×1、全链 7 ≤ 7×1+0+0 ✓——单位与路径经冻结底层实际读取探针对齐）；`read_success_bytes ≤ 总尝试 × max_file_bytes`。**超界即实现缺陷**（真实计量 > 公式上界 → 断言失败）。**截断规则**：各通道既有 cap（max_files/max_total_bytes/max_file_bytes/max_metadata_manifests/max_metadata_total_bytes/ProfileBudgets）触发即停 + 对应 typed gap（§5.1.1/§5.1.7/本节），无第三种静默行为；**不为满足上界削正常画像、重复读不漏计量、不伪造已取得的事实**（S8+S3 对同一 manifest 的重复读取如实双计——§4.3.2 缓存未采纳，零缓存零去重）。**A 自身新增的读放大（S1-S6 组件链+S8 通道）由本计量+上界给出设计与验收；聚合墙钟与真实客户端物理强制上界不宣称**（F3/F4 归 #60-CLOSURE-C，边界保留）。
- **fail-closed（不静默截断，不变；v5 增 T8）**：组件数/边/evidence/unassigned/未知导入/元数据通道/聚合调用/聚合 token 各类 cap 全部 typed gap（§5.1.1/§5.1.7/§5.3.4/本节）；预算耗尽一律返回部分事实 + typed gap + 对应 complete 触发（T1/T3/T7/T8——依赖证据类 cap；聚合模型调用/token 池为非依赖证据状态，不触发 T、不改 complete，§5.2.4），不报错、不吞。
- **墙钟（降级表述，不变）**：F4 未闭合——本 Packet 不宣称任何已证明的聚合墙钟上界；每组件 `max_wall_time_seconds` 语义照旧由 IP-0019 承载（口径 1/2 内），聚合墙钟治理归 F4/#60-CLOSURE-C（无全局时钟入 digest，确定性优先）。
- **与 `max_manifest_files`（BG-IP-0016-01）的关系（更新）**：组件层锚点发现的 manifest 内容读取受 §5.1.7 通道双预算约束（数量+字节，显式新预算非隐式扩容）；每组件 Profile 构建内部仍受其自身 ProfileBudgets 约束（既有行为）。BG-IP-0016-01 保持 OPEN，本片不清偿不扩大。

#### 5.4.5 canonical bytes 与 graph digest（冻结单解）

```text
component_graph_digest = compute_content_digest(canonical_dict)
canonical_dict = {
  "components": [每组件规范 dict（component_id/root_dir/
                  manifests[{path,kind,source}]/              # v4：source ∈ 两值（INV-OWN-3(d)）
                  python_file_count/is_empty）——按序],
  "edges": [每边规范 dict（source_component_id/target_component_id|null/status/
             imported_name/evidence[{path,line,imported_name}]）——按序],
  "unknown_imports": [{source_component_id, imported_name, count}]，      # v2
  "scan_summaries": [{component_id, parse_error_file_count,
                      read_failure_file_count, dynamic_import_site_count}]，# v2
  "unbuilt_components": [{component_id, reason}]，            # v4：三类 reason 记录（T7）
  "unassigned_files": [...], "unassigned_file_count": N,
  "dependencies_complete": bool,
  "coverage_gaps": [{"gap_code","detail"}...]   # 排序 (gap_code, detail)
  "manifests_discovered_count": N,               # v5/CL-05：D1 发现域（文件级）
  "metadata_manifest_count": N,                  # v5/CL-05：D2 通道发现域（含重叠成员）
  "collaboration_manifest_count": N,             # v5：守恒差额项
  "overflow_manifest_count": N                   # v5：守恒差额项
}
# v4 注（v5 修订）：metadata_channel_skipped/build 段有效 budgets/metering 仍为 payload
# 承载但**不进 canonical dict**（metering 结果对象承载；有效 budgets 经 V8 与计数交叉
# 核对而非 digest 绑定；metadata_channel_skipped 经 V7 词表+对账承载，不宣称 digest 级
# 防篡改——如实声明）。**v5/CL-05：发现域四个标量计数字段（上列）进 canonical dict**——
# 守恒等式参与字段获 digest 级防篡改（篡改任一参与字段→V9 失配拒绝；D3/D4 尝试/字节计量
# 不进 payload 亦不进 canonical，metering-only）。identity 字段集 = v2 冻结口径 + v4 三处
# 扩展 + v5 四计数字段（schema 从未实现/发布，无迁移负担）。
```

- canonical JSON = `lima.contracts.codec.compute_content_digest` 口径（IP-0018/0019 digest 先例），恒 64-hex；**不含** digest 自身、时钟、耗时、环境；
- 与 digest 家族的关系（冻结声明）：`component_graph_digest` 是**独立新成员**；既有六 digest 语义与算法零改动、零交叉（图 digest 不进任何 envelope、不进 RAM wire payload、不参与 wire_digest 计算）；
- **独立重算（R60-07）**：消费者可对手写/独立构造的 canonical dict（不经产品代码）调用同一既有公共 `compute_content_digest` 复算核对——Oracle 独立于 `component_graph` 实现。

#### 5.4.6 与组件 Profile/RAM 的关联及公开 Artifact 消费闭合（v4 重写，P60-V3-02；R60-08 基础上修正核对路径）

- **键控关联（不变）**：`component_graph_payload(result)` 的 `components[]` 以 `component_id` 为键携带 `{built, digests{profile_content_digest, ram_facts_digest, semantic_result_digest}|null, scan_summary, semantic_topn{model_id, top_n, ranked_candidate_ids[]}}`；三 digest 全部可由**公开 Artifact** 复算核对（见下），不要求重跑目标构建、不依赖构建者内存对象。
- **每组件完整事实的公开承载（不扩 #58/54 帽/旧 digest/matrix）**：
  - 完整 Profile = 既有 #58 公共契约产物：`profile_result.envelope` 经既有 `encode_profile_envelope` 序列化的版本化 envelope（既有 schema `lima.repository-profile.json` / `lima.artifact-envelope.json` 校验）；消费侧经 `decode_profile_envelope(profile_bytes)`（**bytes 入参**，返回 `(ArtifactEnvelope, RepositoryProfile)`，`envelope.content_digest` 公共字段）；
  - 完整 RAM = 既有 IP-0021 公共产物：`ComponentBuildResult.ram_wire`（构建侧 `ram_wire_payload` 只读复用产出）或其序列化形态（既有 schema 校验）；**三摘要核对路径（v4 修正，逐字对齐指令 §四 P60-V3-02 内嵌基准）**：`ram_facts_digest_from_wire(ram_wire) == entry["digests"]["ram_facts_digest"]`（facts 摘要对 facts 槽）；`semantic_result_digest_from_wire(ram_wire) == entry["digests"]["semantic_result_digest"]`（semantic 摘要——RAM wire 已含完整 semantic 数据，无需另建契约）；`ram_wire_digest(ram_wire) == ram_wire["identity"]["wire_digest"]`（**wire digest 只与 wire 自身 identity.wire_digest 比较，绝不与 ram_facts_digest 比较**——两类摘要不同构造，v3 示例的跨类比较是类别错误）；**gaps 取自 `ram`/`semantic` 两 section 的 `coverage_gaps`**（顶层无 coverage_gaps），经 `execution_required_from_gaps` 复算后与顶层 `execution_required` 核对；全部经 `validate_ram_wire_payload` 先行校验；
  - semantic 摘要消费 = 图 payload 自身承载 `semantic_topn{model_id, top_n, ranked_candidate_ids[]}`（**v4：cap=top_n 实际生效值（1..100，对齐冻结 SemanticOptions 合法域；默认 20 只是默认不是帽）**，`top_n` 字段随承载使 validator 可核对 `len(ranked_candidate_ids) ≤ top_n`；`candidate_id` 冻结编码）；**full semantic payload 的下游消费归 #60-CLOSURE-D/#64/#68 真实 fixture（Not-covered 声明）**；
  - 路径坐标映射：`仓库路径 = root_dir + "/" + 组件内路径`（root_dir="" 恒等）——payload 消费侧可核对组件产物坐标与图证据坐标的对应（component_id→Artifact 关联的坐标面）；
  - 阶段 Artifact 交换形态：monorepo 阶段的公开 Artifact 集 = 1 个 graph payload + N 组每组件公开产物（profile envelope + RAM wire payload），全部经既有公共 schema/函数校验，阶段间交换不依赖内存对象（系统约束落位）；**消费者只拿公开产物，不持有 workspace、不重跑构建、不接收构建者私有内存**。
- **有效配置承载（v4 新增，P60-V3-02 第 4 点；v5/CL-03 增 effective 池口径）**：构建侧产出每组件 RAM wire 时**传入实际生效**的 `profile_budgets` / `ram_budgets` / `semantic_options`（聚合额度调整每组件配置时经 `dataclasses.replace` 得到的实际值；**不得**在额度变化后回填 `None`/层默认——回填即 build 段与实际构建不一致、wire_digest 校验失配，§3.6）；"何种有效配置被保存、Artifact 如何产出"由两层承载：(a) `ComponentBuildResult.effective_*` 三字段（结果对象，构建者侧机械可核对）；(b) wire `build` 段（进入 wire_digest 的公开自洽面）+ 图 payload `build.monorepo_budgets`（**有效聚合预算——v5：聚合 token 三字段为 min(requested, caller) 推导后的 effective 值**（§5.4.4），V8 与计数交叉核对）——payload build 段与 wire build 段自洽（每组件 semantic 配置一致）。
- **消费冻结面重申（不变+）**：graph validator（§5.4.8 十维）、图摘要独立重算（V9）、component_id→Artifact 关联、相对坐标映射（`仓库路径 = root_dir + "/" + 组件内路径`）、承重字段篡改验收（V9+每组件 wire validator 篡改拒绝）；**消费规则至少等价于指令 §四 P60-V3-02 内嵌示例**（§5.4.7 逐字采用；断言语义不得弱于它）。

#### 5.4.7 公共消费路径（v4 重写，P60-V3-02；`__all__` 导出与消费基准）

模块级 `__all__`（**恰 46 项** = v3 34 + v4 新增 12，字母序，封闭清单——实现不得增删公开名，D2 冻结测试逐一锁定；**v5 零新增公开符号**——修订落字段/判据层，公开名集合与 v4 相同）：

```text
COMPONENT_EDGE_STATUSES, COMPONENT_EDGE_STATUS_AMBIGUOUS, COMPONENT_EDGE_STATUS_RESOLVED,
COMPONENT_EDGE_STATUS_UNRESOLVED, COMPONENT_GRAPH_PROVENANCE_ANCHOR, COMPONENT_GRAPH_SCHEMA_FILE,
COMPONENT_GRAPH_SCHEMA_NAME, COMPONENT_GRAPH_SCHEMA_VERSION,
COMPONENT_MANIFEST_KIND_CARGO_TOML, COMPONENT_MANIFEST_KIND_ENVIRONMENT_YML,
COMPONENT_MANIFEST_KIND_GO_MOD, COMPONENT_MANIFEST_KIND_PACKAGE_JSON,
COMPONENT_MANIFEST_KIND_POM_XML, COMPONENT_MANIFEST_KIND_PYPROJECT,
COMPONENT_MANIFEST_KIND_REQUIREMENTS, COMPONENT_MANIFEST_KIND_SETUP_CFG,
COMPONENT_MANIFEST_KIND_SETUP_PY,
COMPONENT_MANIFEST_SOURCES, COMPONENT_MANIFEST_SOURCE_INVENTORY,
COMPONENT_MANIFEST_SOURCE_METADATA_CHANNEL,
MANIFEST_POLICIES, MANIFEST_POLICY_ADMITTED_ONLY, MANIFEST_POLICY_METADATA_CHANNEL,
UNBUILT_REASONS, UNBUILT_REASON_ADMISSION_REFUSED, UNBUILT_REASON_CAP_DIVERGENCE,
UNBUILT_REASON_VIEW_UNFORMABLE,
ComponentBuildResult, ComponentDiscoveryResult, ComponentEdge, ComponentGraph,
ComponentInfo, ComponentManifestRef, ComponentScanSummary, EdgeEvidence,
MonorepoBudgets, MonorepoProfileBuildResult, ResourceMetering, UnbuiltComponentRecord,
UnknownImportRecord,
build_monorepo_profile, component_graph_digest, component_graph_payload,
detect_components, load_component_graph_schema, validate_component_graph_payload
```

构建与消费示例（公共接口，非内部窥探；**消费段不持有 workspace、不重跑构建、不接收构建者私有内存**）：

```python
# 构建侧（一次性）
from lima.workspace import RepositoryWorkspace
from lima.audit.component_graph import (build_monorepo_profile,
    component_graph_payload, validate_component_graph_payload)

ws = RepositoryWorkspace(snapshot_root)               # 调用方策略在此生效并被全程继承
result = build_monorepo_profile(ws, tenant_id=..., task_id=...,
    workflow_id=..., stage_attempt_id=..., artifact_id=...,
    repository_snapshot_digest=...)                   # semantic 默认 off（零模型调用）
payload = component_graph_payload(result)             # 组件清单+边+未知导入+scan 摘要+
                                                      # 键控三 digest+semantic_topn+图 digest
validate_component_graph_payload(payload)             # fail-closed 契约校验（5.4.8 十维）
```

**消费基准（v4：`MR-60-PR282-FINALIZATION-20261009/v1` §四 P60-V3-02 内嵌代码，逐字采用；对每个 `built==true` 的 `entry in payload["components"]` 执行——`profile_bytes`/`ram_bytes` 为该组件已落盘的公开 Artifact 字节，`entry` 为图 payload 键控条目。断言语义不得弱于本基准；外围叙述（循环/读取/图摘要重算）见基准后注）**：

```python
import json
from lima.contracts.profile import decode_profile_envelope
from lima.audit.ram_schema import (
    validate_ram_wire_payload,
    ram_facts_digest_from_wire,
    semantic_result_digest_from_wire,
    ram_wire_digest,
    execution_required_from_gaps,
)

envelope, profile = decode_profile_envelope(profile_bytes)
ram_wire = json.loads(ram_bytes)
validate_ram_wire_payload(ram_wire)
assert envelope.content_digest == entry["digests"]["profile_content_digest"]
assert ram_facts_digest_from_wire(ram_wire) == entry["digests"]["ram_facts_digest"]
assert semantic_result_digest_from_wire(ram_wire) == entry["digests"]["semantic_result_digest"]
assert ram_wire_digest(ram_wire) == ram_wire["identity"]["wire_digest"]
gap_codes = [
    gap["gap_code"]
    for section in ("ram", "semantic")
    for gap in ram_wire[section]["coverage_gaps"]
]
required, triggers = execution_required_from_gaps(gap_codes)
assert ram_wire["execution_required"] == {
    "required": required, "trigger_gap_codes": list(triggers)
}
```

基准外围（消费方自己的叙述，不弱化基准断言）：逐 `built` 条目执行上块（`profile_bytes = read_artifact(f"{entry['component_id']}.profile.json")` 等消费方读取；`entry["digests"]` 三槽即图键控关联）；图级收尾 = canonical 投影独立重算 `compute_content_digest(canonical_dict_from(payload)) == payload["identity"]["component_graph_digest"]`（R60-07，篡改任一参与字段必失配——**v5：发现域四计数字段在 canonical 投影内**，§5.4.5）+ scan_summary 与组件产物计数自洽核对 + **manifest 计量域核对（v5/CL-05：守恒等式 `manifests_discovered_count == Σ|manifests| + collaboration_manifest_count + overflow_manifest_count` 与 `metadata_manifest_count ≤ manifests_discovered_count` 按 payload 机械复算——与 validator V7 同式）** + 坐标映射抽查（`仓库路径 = root_dir + "/" + 组件内路径`）。**D1 设计证据标注**：本基准的"已有部分"（validate 通过、facts/semantic 两摘要复算、wire digest 自洽且 ≠facts digest、顶层无 coverage_gaps、execution_required 复算、篡改被拒、bytes 解码语义）已于 D1F 对既有 golden `tests/audit/fixtures/golden_matrix/golden/application.json` 离线实跑验证（12/12 过，§3.6/附 D）——**已有行为实测；D2 再绑定真实 graph payload 的端到端消费（本 Packet 不声明未实现的 graph 已可调用）**。

（示例中 `read_artifact`/`canonical_dict_from` 为消费侧占位叙述：前者是消费方自己的 Artifact 读取，后者为 canonical 投影——产品冻结面仅 §5.4.3 签名；v3 示例的 `profile_envelope_content_digest` 占位已由基准内 `envelope.content_digest` 公共字段访问取代。）

#### 5.4.8 validator 单解（`validate_component_graph_payload` 行为清单，fail-closed）

| # | 检查维度 | 行为（违规 → `ContractError`） |
|---|---|---|
| V1 | 未知字段 | 任意层级未知字段 → `UNKNOWN_FIELD`（schema `additionalProperties:false` 全层级 + 运行时同口径） |
| V2 | 枚举/const | `schema_version`/`model_kind` const；`status` ∈ 三值；`manifest_kind` ∈ 九值；`provenance` const 单元序列 |
| V3 | ID 唯一性 | `components[].component_id` 全局唯一；边键/`unknown_imports` 键唯一 |
| V4 | 目标存在 | 边 `target_component_id`（非 null）∈ components；`unknown_imports.source_component_id`、`scan_summaries.component_id`、`unbuilt_components[]` ∈ components |
| V5 | 路径合法与秘密形态 | 全部路径字段满足 repo-relative POSIX 模式（无 NUL/绝对/`..`/首尾斜杠，UTF-8）；任一路径字段命中 `is_secret_shaped_path` → 拒绝（公开面零秘密形态路径） |
| V6 | 排序去重 | components / edges / evidence / unassigned / unknown_imports / unbuilt / manifests / scan_summaries 各自按 §5.3.4/§5.1 规定序排列且去重 |
| V7 | 数量与跨字段（**v5/CL-05 重写计量域判据**） | `unassigned_file_count ≥ len(unassigned_files)`；`is_empty ⇔ python_file_count==0`；`digests` 非 null ⇔ `built==true`；`built==false` ⇔ 该 id ∈ `unbuilt_components`（v4：记录含 `reason ∈ UNBUILT_REASONS`）；`unbuilt_components` 非空 ⇒ `dependencies_complete==false`；**`semantic_topn.top_n ∈ 1..100`（冻结域）且 `len(ranked_candidate_ids) ≤ top_n`**（v4：cap=top_n 实际生效值，默认 20 非帽）；`manifests[].source ∈ COMPONENT_MANIFEST_SOURCES`、同组件 manifests 按 path 去重；**守恒等式（INV-OWN-3(a)）：`manifests_discovered_count == Σ_C\|manifests(C)\| + collaboration_manifest_count + overflow_manifest_count`**；**计量域不等式：`metadata_manifest_count ≤ manifests_discovered_count`、`Σ_C\|{m: m.source=="metadata-channel"}\| ≤ metadata_manifest_count`**（差额映射=§5.1.8 联合参考表——overlap 转单值发布/协作/溢出中的通道命中者；不再要求 `metadata_manifest_count == Σ(S2 来源 manifests 数)`——RULE-COUNT ① 消除）；**对账：同一 reason 在 `coverage_gaps` detail 与 `metadata_channel_skipped` 同现时 count 相等**（§5.1.7）；`metadata_channel_skipped` 键 ∈ §5.1.7 词表 |
| V8 | cap（三分离统一，v4/P60-V3-03；v5 增 effective 口径） | **schema maxItems = 独立硬上限（合法域上界），不再固定在默认值**：components ≤64 / edges ≤16384 / 每边 evidence ≤1024 / unassigned ≤4096 / unknown_imports ≤16384 / 每组件 manifests ≤1024 / `ranked_candidate_ids` ≤100；**validator 另对有效 budgets 交叉核对**（payload `build.monorepo_budgets` 为 **effective 值**承载——v5/CL-03：聚合 token 三字段=min(requested, caller) 推导后的实际生效值）：components ≤ 有效 `max_components`、edges+unknown_imports ≤ 有效 `max_edges`、evidence ≤ 有效 `max_edge_evidence`、unassigned 列表 ≤ 有效 `max_unassigned_files`、`metadata_manifest_count` ≤ 有效 `max_metadata_manifests`（D2 通道发现域含重叠成员的预算消耗口径）——合法构建（构造期域校验+运行截断）恒双过；仅非法构造/篡改可越（构造期 ValueError 或此处拒绝） |
| V9 | 图 digest 自洽重算 | 由 payload 字段投影 canonical dict（§5.4.5 键集）经既有公共 `compute_content_digest` 重算 == `identity.component_graph_digest`；任一参与字段被篡改 → 失配拒绝 |
| V10 | digest 形态 | 全部 digest 字段 64-hex 小写；`line ≥ 1`；`count ≥ 1`（unknown_imports）/ ≥0（scan 计数） |

**Unicode/字符集口径（与输入支持范围一致）**：输入侧支持范围 = 主仓 inventory 可准入的 UTF-8 可解码路径（non-utf8 上游已跳过——workspace 冻结行为）；payload 路径原样保留（无归一化），段字符集除 component_id 的 `[A-Za-z0-9._\-]` 限制外允许合法 Unicode 字母/数字（V5 模式校验）；**不宣称"任意 workspace"都能正常输出**——声明范围之外的形态由上游跳过计数与 typed gap 承载。

### 5.5 wire schema（`schemas/v4/lima.component-graph.json`）

结构风格沿 `lima.repository-architecture-model.json` 先例（draft 2020-12、顶层 `additionalProperties:false`、required 全列、集合字段 `maxItems` 上界）。字段映射（每字段 ← 冻结产物，无凭空字段）：

| schema 路径 | 来源 | 约束 |
|---|---|---|
| `schema_version` | `COMPONENT_GRAPH_SCHEMA_VERSION` | const `"2.0"` |
| `model_kind` | `COMPONENT_GRAPH_SCHEMA_NAME` | const `"lima.component-graph"` |
| `components[].component_id / root_dir / python_file_count / is_empty` | `ComponentInfo` | component_id = `"component:"` + 锚点 repo-relative 路径（根为 `"."`；段字符集 `[A-Za-z0-9._\-]`、多段嵌套、无 `..` 段——regex 按此单解书写于 schema）；root_dir 同段字符集或 `""`；is_empty 恒 `python_file_count==0`（V7） |
| `components[].manifests[].{path, manifest_kind, source}` | `ComponentManifestRef`（v4：+source） | kind ∈ 九值 const 枚举；source ∈ {"source-inventory","metadata-channel"} const 枚举；按 path 升序；path 过 V5 模式+秘密形态拒绝 |
| `components[].built` | INV-OWN-1 结果 | bool；与 digests/unbuilt 交叉校验（V7） |
| `components[].digests.{profile_content_digest, ram_facts_digest, semantic_result_digest}` | 5.4.6 键控关联 | 64-hex；`built=false` 时为 null（V7） |
| `components[].scan_summary.{parse_error_file_count, read_failure_file_count, dynamic_import_site_count}` | `ComponentScanSummary` | int ≥0；与图级 `scan_summaries` 同项相等（V7） |
| `components[].semantic_topn.{model_id, top_n, ranked_candidate_ids[]}` | 每组件 semantic 摘要（v4：+top_n） | **top_n ∈ 1..100（冻结域对齐，默认 20 非帽）；ranked maxItems 100 且 len ≤ top_n（V7）**；candidate_id 冻结编码形态；`built=false` 时 null |
| `edges[].{source_component_id, target_component_id, status, imported_name, evidence[]}` | `ComponentEdge` | target 可 null（resolved 时必非 null 且 ≠ source；ambiguous/unresolved 时必 null——V7）；status ∈ 三值；evidence[].{path,line,imported_name}，line ≥ 1，path 过 V5 |
| `unknown_imports[].{source_component_id, imported_name, count}` | `UnknownImportRecord` | count ≥ 1；排序去重；maxItems 16384（=域帽，v4） |
| `unassigned_files[] / unassigned_file_count` | `ComponentGraph` | 排序字符串（过准入）；count ≥ len(list)；maxItems 4096（=域帽，v4） |
| `scan_summaries[]` | `ComponentScanSummary` | 按 component_id 升序；与 components 逐项对应 |
| `unbuilt_components[].{component_id, reason}` | `UnbuiltComponentRecord`（v4） | reason ∈ 三值 const 枚举（cap-divergence/view-unformable/admission-refused）；component_id ⊆ components；`built=false` 恰对应 |
| `dependencies_complete` | `ComponentGraph` | bool；触发集 T1-T8 唯一（§5.2.4 唯一决策表；T8=S2 元数据证据丢失） |
| `coverage_gaps[].{gap_code, detail}` | `ProfileCoverageGap.to_dict()` | gap_code pattern `[A-Z][A-Z0-9_]{0,63}` 且 ∈ 10 码全集（值重述；wire 侧一律经 ram_schema 公共函数，§5.6.3 v4） |
| `metadata_manifest_count` / `metadata_channel_skipped{reason→count}` | `ComponentDiscoveryResult`（v4 起；**v5/CL-05 单义化**） | count ≥0；`metadata_manifest_count`=S2 通道发现总数（**含 S1∩S2 重叠成员**；≠发布条目数——§5.1.8）；skipped 键 ∈ §5.1.7 七词表（逐键归类见该节）；两集合计数分列（不改写主仓 `skipped`——后者不入本 payload） |
| `manifests_discovered_count` / `collaboration_manifest_count` / `overflow_manifest_count` | `ComponentDiscoveryResult` + `ComponentGraph`（v5 新增） | int ≥0（`manifests_discovered_count ≥ 1` 当存在任何 manifest）；守恒等式 V7 核对；**进 canonical dict（V9 digest 保护，§5.4.5）** |
| `build.monorepo_budgets.{十字段}` | 有效 MonorepoBudgets（v4：有效配置公开承载；**v5：聚合 token 三字段为 effective 值**） | 各字段=实际生效值（合法域内；token 三字段=min(requested, caller) 推导后——§5.4.4）；V8 与集合计数交叉核对；requested/默认回填禁止（§5.4.6——回填即 wire_digest 失配） |
| `identity.component_graph_digest` | `component_graph_digest(graph)` | 64-hex；V9 自洽重算 |
| `provenance.provenance_anchor_ids[]` | `("component-graph",)` | const 单元序列 |

版本语义：`"2.0"` 是 component graph 承载自身第 2 版（**v1.0 从未实现/发布/合并，无迁移兼容负担**——版本号跟随 Packet v2 起的字段集；**v4 字段集（manifests.source / unbuilt reason / semantic_topn.top_n / metadata 计数 / build.monorepo_budgets）与 v5 字段集（manifests_discovered_count / collaboration_manifest_count / overflow_manifest_count 发现域计数字段；metadata_manifest_count 单义化）均在 "2.0" 内扩展**——该 schema 从未发布，无消费者可破坏）；文件置于 `schemas/v4/` 沿用工程布局，但**不注册** `version_compatibility_matrix.json`（BG-60-01 口径维持；`tests/contracts/test_compatibility_matrix.py` 只以 matrix 文件行为枚举源，IP-0021 §3.4 先例，新增未注册 schema 不触及 contracts 617）。

### 5.6 兼容约束（Assignment §六.4；逐项冻结声明）

#### 5.6.1 `lima/audit/__init__.py.__all__` 54 帽——零触碰单解

- **处置**：本 IP **不修改** `lima/audit/__init__.py`。新公共符号仅经 `lima.audit.component_graph` 模块级 `__all__` 导出（§5.4.7）；
- **与 54 帽的关系**：帽（含冻结断言 `len(__all__) == 54`）原样成立；`import lima.audit` 零新副作用；
- **不扩帽的理由与备选**：扩帽=触及冻结面（需 DR 获批前不实现）。默认方案自足；"追加 re-export" 列为 **DR-IP-0023-01 备选草案**（随交接报告，不进实现范围）。

#### 5.6.2 candidate_id 与 digest 家族

- `candidate_id` 冻结编码零改动；component_id 是**新命名空间**（`"component:"` 前缀，槽位结构不同，无碰撞）；
- 既有六 digest 算法与取值零改动；新增 `component_graph_digest` 独立成员（5.4.5）；**不扩展全 payload digest、不改 wire_digest 输入**（已否决路线不重试）；
- **相同内容不同组件允许摘要相等**（API-05 事实；v1 §5.2.1/§5.6.4"互异"表述废除）：身份与关联一律经 component_id/root_dir/键控 digest 引用表达，不以摘要互异为不变量（§5.4.6/§6 C6）。

#### 5.6.3 GAP 码全集与 execution_required 语义（v4 修订，P60-V3-02）

- `GAP_CODES_ALL` 10 码**不新增、不改名**。**v4 边界改写（废除 v3 "不 import ram_schema" 表述）**：图**自身** `coverage_gaps` 的构造可继续**值重述**码字面量（图 gap 是图级新字段，非 wire 复用——`ProfileCoverageGap` 公共类型构造）；而**每组件 RAM wire 的产出/校验/消费一律调用 `lima.audit.ram_schema` 真实公共函数**（`ram_wire_payload` / `validate_ram_wire_payload` / `ram_facts_digest_from_wire` / `semantic_result_digest_from_wire` / `ram_wire_digest` / `execution_required_from_gaps`），**不复制、不重定义其摘要、gap、execution_required 规则，不修改该模块既有行为**。使用码：`BUDGET_EXHAUSTED`（v4 八类 cap：component/edge/edge-evidence/unassigned/unknown-import/aggregate-model-call/aggregate-token-pool/metadata-manifest-or-byte；**v5/CL-01：metadata-manifest-limit/metadata-byte-limit 两 detail 同时是 T8 触发源**——§5.2.4，complete=False 经 T8 而非 gap 本身）、`INVENTORY_SKIPPED`（①秘密形态拒绝：锚点与文件名准入，detail `reason=sensitive-filename; count=N`，R1 终案 reason→count；②**T6 主仓 cap 截断/准入跳过（v3/ER SF-1）**：逐键 detail `reason=<skipped 键名>; count=N`，§5.2.4；③**T8 通道读取/解码失败（v5/CL-01）**：通道 `unreadable`/`non-utf8` 键逐键 detail `reason=<通道键名>; count=N`，与 `metadata_channel_skipped` 对账相等——**经承载字段分列单解可分**（v4.1 勘正"值域不相交"表述：两值域存在交集——`sensitive-filename`/`non-utf8`/`unreadable`/`metadata-manifest-limit`/`metadata-byte-limit`；同值时以承载字段区分，分列呈现、不合并、不回写，计数归属见 §5.1.7）；
- **独立新字段，非新 GAP 码**（v2 承载 + v4 增补：`UnbuiltComponentRecord.reason`、`metadata_channel_skipped`、`ResourceMetering`）——不触 `GAP_CODES_ALL` 冻结面与 9 码触发集推导；若 D2 发现确需新码 → 具体 DR；
- `execution_required` 9 码触发语义零改动：图 payload **不承载**该字段（每组件值由既有 `execution_required_from_gaps` 对该组件 RAM wire 的 ram/semantic 两 section gaps 复算——消费基准 §5.4.7 逐字采用）。

#### 5.6.4 #58 Contract 与 v4 schema/旧 golden

- `encode/decode_profile_envelope`、`encode_envelope`、`ArtifactReference`/`ArtifactEnvelope`、`AttackSurfaceEntry`/`ProfileCoverageGap`、`_validated_path`、v4 非空 extensions 拒绝语义：**全部只读消费**（ProfileCoverageGap 作为图 gap 公共类型构造；组件 Profile envelope 经既有 encode 产出，语义 = 同一 artifact 下的组件子剖面）；
- **不私加 #58 Profile 字段、不借 extensions 携带图**（B-10）；图不进任何 envelope；
- 六 ID 每组件透传兼容论证（修订）：#58 envelope 校验按单 envelope 独立（artifact_id 无跨 envelope 全局唯一性断言）；相同局部内容的组件 envelope content_digest **可以相等**（API-05），下游以 component_id 关联区分——不影响旧消费者（只消费全仓单 envelope / RAM wire）；
- schemas/v4 既有 15 文件与 matrix 零改动；**旧 golden（五形态 + library_profile_golden）期望值零改动**。

#### 5.6.5 TaskManifest 消费面衔接

RAM wire 以 TaskManifest 消费面衔接的既有口径不变；`build_monorepo_profile.repository_snapshot_digest` 与全仓单仓构建取同值（组件层不重定义快照语义）。

### 5.7 输入与确定性（恢复审计 §4② 移交口径落位 + D1R 修订）

- **workspace 输入域扩容**：组件识别与每组件构建均在**当前 main workspace 口径**下工作；本片不把扩容当隐式新能力——不依赖任何新扩展进入 inventory；新 fixture 扩展名集合显式（5.7.1）；
- **CRLF**：`read_text` 保留 CRLF（当前行为）；AST 行号按保留 CRLF 原文计算；本片 fixture 全 LF（5.7.1）；`line_count` 字段存在但本片不消费其值；
- `fingerprint()`/skip 词表/`_safe_path` 边界语义未变（F3 归 CLOSURE-C）；
- **确定性判据（冻结）**：同一 workspace 快照 + 同一 budgets/options 两次独立构建 ⇒ `component_graph_digest` 相等、`components`/`edges`/`unassigned`/`unknown_imports`/`scan_summaries`/`unbuilt_components` 逐字段相等、每组件三 digest 相等、**发现域四计数字段（manifests_discovered/metadata_manifest/collaboration/overflow）相等、`ResourceMetering` 六计数值相等（v5：读取尝试/成功字节为确定量——同一快照的读取次数与字节不依赖时序/env）**；**输入顺序变化**（目录枚举顺序/文件写入顺序不同、内容相同的两个快照目录）⇒ 结果不变——全部枚举入口（manifest 候选/锚点/组件/文件/边/evidence/未知导入）一律 sorted，禁 mtime/权限/随机/env/时钟；
- **跨 workspace/共享安全层改动（v4 修订 P60-V3-01；v5 按 CL-02 扩充）**：本片设计对共享层的**全部**需求已具体化为 §4.3.1 条件性 additive 白名单两项（W-1 workspace `admitted_files`+`metadata_files` 双清单视图参数 / W-2 `_manifest_candidates` 并集受限过滤；DR-IP-0023-02 已采纳目标 + CL-02 自身元数据视图的落点）——**激活条件=本 Packet v5 获 Maintainer 批准合并，本轮零实现**；白名单外共享层修改（含 §4.3.2 未采纳的缓存接口）仍零需求且禁止（不再出现"必须改共享层"与"共享层零触碰"并存的自相矛盾表述）；D1R 探针 D2/D3/D7 实证的继承构造与机械校验仍是受限态的可行性基座；若 D2/实现期发现白名单外必须改 `lima/workspace.py` 才能表达的语义 → 停止并单列 DR（附调用链与理由）。

#### 5.7.1 fixture 口径约束（冻结）

- 新 fixture（`tests/audit/fixtures/monorepo/shapes.py`）文本写入一律 `newline="\n"` 钉死 LF（PI-DR1）；路径断言用 POSIX 字面量；
- **扩展名集合显式声明**：monorepo fixture 仅含 `.py` 文件 + manifest 文件名（经已准入 inventory 通道）；不含 C++/构建类扩展文件、不含 CRLF 文件；**秘密形态文件名仅存在于专用隐私负例形态**（C4 类），其断言只验证"不入公开面 + gap 计数"，不在任何期望列表中断言其路径；
- fixture 构造沿用 `repo_shapes.workspace_with` 模式（临时目录 + `RepositoryWorkspace`，零网络零执行）；嵌套/src 布局/同内容双组件/祖先-嵌套/名字碰撞形态均在 shapes.py 显式构造（§6 各类引用）。

### 5.8 安全基线（Assignment §六 末段 + R60-04；全程）

- **准入时序（冻结单解）**：仓库级坐标先准入、后建组件视图（§5.2.0 六步时序；任何组件级/图级公开输出所含路径均在仓库级坐标过 `is_secret_shaped_path` 或其组件内坐标的仓库级原像已过准入）；
- **公开面准入规则表（R60-04 交付；逐项）**：

| 公开面 | 准入规则 |
|---|---|
| `component_id` / `root_dir` | 源自已准入锚点（锚点路径已过 `is_secret_shaped_path`，§5.1.1）；字符集 pattern（V5） |
| `manifests[].path` | 已准入 inventory 内 manifest（工作区级准入 + 秘密形态双过） |
| `unassigned_files[]` | 仓库级路径过 `is_secret_shaped_path`；命中者不入列表、仅计数，`INVENTORY_SKIPPED` gap reason→count |
| `edges[].evidence[].path` | 同上（归属 `.py` 已准入 + 秘密形态过滤） |
| `unknown_imports[].imported_name` | 标识符/点号串（非源码正文、非路径） |
| `scan_summaries` / `unbuilt_components` | 纯计数与 component_id（无路径无源码） |
| `semantic_topn.ranked_candidate_ids` | candidate_id 冻结编码（含组件内路径坐标——该文件已过仓库级准入，准入等价 §5.2.1） |
| `digests` / `identity` / `provenance` | 无路径承载 |

- **R1 口径保留**：公开 reason→count；内部 `AdmissionSkipRecord`（family 级、无原文件名）不入任何公开面；**启发式非穷尽声明保留**（`is_secret_shaped_path` 为启发式，不宣称零泄漏——残余治理归 C）；
- **提示材料准入（继承声明，v4.1 补注 SF-60-IP-0023-D1F-3）**：提示材料准入继承 IP-0019 冻结面——模型 off 默认（`model_client is None` → 零调用零网络，§5.4.4）、本片零新提示面（不新增任何提示材料准入路径、词表或例外）、fake client 仅计尝试数（不产生真实提示材料外发，仅入全仓尝试口径计数，§5.4.4）；
- 不执行/不 import/不安装目标项目（AST 断言 + 行为负例：恶意 setup.py marker 文件不存在）；模块静态断言：零网络 import（socket/urllib/requests/http）、零 subprocess、零 os.environ、零文件写、零 sys.path 变更；
- fail-closed 与有界读取：全部入参类型/值校验抛 `ContractError`/`ValueError`；读取一律经 workspace 有界通道；**无掩码 path 方案、不改旧 digest 家族**（已否决路线不重试）。

### 5.9 联合演算正例与旧反例不回归（v5 新增，CL-01..05 联合；D1 出口"不只证明可以列出锚点"的落位）

**六个联合正例（builder→payload→validator→consumer 全链无矛盾；D2 锚括注）**：

1. **S2-only 自身 Profile（API-META 修复形态）**：夹具 main.py + requirements.txt=`flask==3.0`——发现：manifests_discovered=1（requirements.txt，S2-only，D2 域=1）；构建：根组件 admitted_files={main.py}、metadata_files={requirements.txt}→inventory=[main.py]（python_file_count=1，requirements 不计入）、W-2 候选=[requirements.txt]（并集成员）、Profile `frameworks=[flask]`/`package_managers=[pip]` 保留；计量：S8=1（通道读）+ S3=1（Profile 读）双计；payload：manifests[].source="metadata-channel"、守恒 1==1+0+0；validator V7 守恒/词表通过；consumer 按 §5.4.7 基准消费。（#69）
2. **S1∩S2 overlap（RULE-COUNT ① 修复形态）**：单根 pyproject.toml（.toml ∈ DEFAULT_EXTENSIONS 且通道命中）——manifests_discovered=1、metadata_manifest_count=1（含重叠）、发布 manifests[0].source="source-inventory"（单值发布来源视图）；守恒 1==1+0+0 ✓、Σ(metadata-channel 发布)=0 ≤ 1 ✓（差额=overlap 单值发布，映射表行 3）——**不再 1=0**；digest：发现域计数字段进 canonical（§5.4.5）。（#73）
3. **父子隔离（CL-02/P60-V3-01 联合）**：根 requirements.txt（父）+ services/requirements.txt（子）——父 metadata_files={requirements.txt}、子={services/requirements.txt 的子内坐标 requirements.txt}；父 W-2 候选不含子 manifest（既不在父 admitted 也不在父 metadata——INV-OWN-3(a) 划分）；两组件 Profile 各自取得自身 facts、互不串证据；守恒 2==1+1+0+0。（#70/#56）
4. **metadata 截断（RULE-COMPLETE 修复形态）**：根 pyproject + 两子 setup.cfg、max_metadata_manifests=2——发现 2、T8 触发（metadata-manifest-limit count=1：BUDGET_EXHAUSTED gap detail 与 metadata_channel_skipped 同键同值）、complete=False（T8）、三态唯一"证据不足"（P3 全合取含 complete==True 不成立、P1 无歧义边）；已发现组件照常发布、守恒 2==2+0+0；partial payload 过 validator、每组件 wire 过 validate_ram_wire_payload、consumer 基准可消费（无 client 模型路径零池消耗）。（#64/#68）
5. **较小 caller（API-POOL 修复形态）**：caller SemanticBudgets(2, 1000/500/1500)、fake client 四组件——effective 三池=1000/500/1500（min）；逐次预扣后第 2 次尝试 output 剩余 244<256 停止（累计 212/256/468 ≤ caller 三值）；停止后静态事实+确定性 Top-N 保留、BUDGET_EXHAUSTED(reason=aggregate-token-pool-limit)、dependencies_complete 不受影响（非依赖证据状态）；wire build 段/payload build.monorepo_budgets=effective 值（回填 requested 即 wire_digest 失配）。（#62/#72）
6. **完整真实读取账（API-IO 对齐）**：单 main.py 无 manifest——S0=1、S1/S2/S4/S5/S6 各=1（component_rescan_read_attempts=5）、S7=1、S3=S8=0；实测三段链 5 次（≤5×1）+主仓 1+AST 1=全链 7 ≤ 7×1+0+0 ✓；metering 六计数全确定量进 ResourceMetering（不进 payload/digest）。（#63）

**旧反例不回归（v2/v3/v4/v4.1 有效闭合成果；推导抽查）**：①API-01（根吸入子文件）——最深锚点归属+admitted_files 切片未变，v5 双清单只增受控元数据读取面、不改 inventory 归属（§5.2.1 入口 (a) 不变）；②API-02（子 workspace 重置策略）——五参数继承+第七维度不放宽任何边界（metadata_files 仅限 manifest 名集成员）；③API-03（坐标重设绕过准入）——仓库级先准入时序（§5.2.0）未动，metadata_files 成员=已过 §5.1.7 通道准入（含秘密段剪枝）的 manifest；④API-04（parse_error 零承载）——T4 图自计未动；⑤API-05（digest 互异）——canonical v5 只增四个计数字段、身份/关联口径不变；⑥RULE-01/RULE-02——任意深度锚点+模块根解析未动；⑦P60-V3-01..05 有效成果——精确视图三入口（v5 强化而非削弱：入口 (b)(c) 并集准入仍 ⊆ 主仓准入 ∪ 自身 manifest）、公开消费（基准逐字保留+计量域核对增补）、秘密准入（通道剪枝+双清单成员过准入）、参数三分离（域帽不变）、模型 off 默认+全仓 8 尝试（CL-03 只收紧不放宽：effective=min）；⑧v4.1 SF-1..4 闭合（T6 键集、盲点正例、INV-OWN-2 划分、carrier-field 单解）——T8 是新增独立触发不改 T1-T7；通道跳过计数归属（v4.1 勘正）增对账相等不改分列。本轮五反例在 v5 规则下全部不可达（§0.4 逐项演算 + 附 E 参考模拟）。

---

## 6. 测试矩阵（D2 冻结计划：FR→AC→T→预定测试符号；本阶段不写测试文件）

**方法预算注记（v5 重写，P60-V3/D1X T 节口径；方法数=规划数非帽）**：**版本演化：v1 33（规划参考）→ v2 52（七类"不配合算法"样例重排）→ v3 54（ER 三 SF 增补 #53/#54）→ v4 计划 63（#21/#24/#42/#54 四行原地重写 + 增补 #55-#63）→ v5 计划 73**（v5 = 63 − 0 删除 + #62 恢复自定义小预算断言并删除"默认调用方"限定语、#63 按 CL-04 新 IO 上界公式随动重写、#30/#61 等受影响旧行随动改写 + 增补 #64-#73 十项 CL-01..05 正负例）。数字不是目标也不是帽：不为保持数量删除反例，也不靠重复用例增加进度。超出 35 的逐类覆盖收益见各类括注（反例与五项跨层裁定暴露的承重行为必须有自己的语义覆盖，不以方法数帽换安全）。回归锚（contracts 617 / audit 235 / 五形态 golden 零改动 / DR-LINT-0022-A 六处恰存）经命令覆盖（§8），不计入新增方法数。断言一律**从需求推导**（V5-FR-03/AC-01/NFR-01/R1 终案/P60-V3-01..05/CL-01..05 裁定等），不从算法实现推导。

| # | 类别（方法数） | 预定测试符号（`test_file::test_symbol`） | 断言要点（需求来源） | 追踪 |
|---|---|---|---|---|
| 1 | C1 组件发现与计数一致（11 = v2 10 + v3 SF-2 一；收益：RULE-01/API-01 两反例的语义覆盖，嵌套/归属/守恒不再依赖平铺巧合；#54 默认扩展锚点盲点为声明锚） | `test_component_graph.py::test_detect_components_nested_services_packages` | `services/api`、`packages/core` 落入组件集；component_id/root_dir/manifests/排序 | V5-FR-03、R60-01 |
| 2 | | `…::test_detect_components_multiple_manifests_same_dir` | 同目录多 manifest 归并单组件 | V5-FR-03 |
| 3 | | `…::test_detect_components_root_only_and_zero_component` | 仅根 manifest→单组件零边；零 manifest→components=()+unassigned | V5-FR-03、边界 |
| 4 | | `…::test_detect_components_workspace_manifest_not_component` | 根 workspace 协作 manifest（uv/pdm/workspace 键）不产根组件；成员组件仍识别 | V5-FR-03 |
| 5 | | `…::test_detect_components_unassigned_files` | 根无锚点时散 `.py` 落 unassigned（列表排序+count）；不编造组件 | AC-01、三态 |
| 6 | | `…::test_detect_components_empty_component` | 有 manifest 零 `.py`→is_empty=True 保留 | V5-FR-03 |
| 7 | | `…::test_detect_components_max_components_truncation` | 17 组件→前 16+BUDGET_EXHAUSTED(reason=component-limit)+truncated+complete=False(T1) | 预算 fail-closed |
| 8 | | `…::test_detect_components_secret_shaped_anchor_suppressed` | `secrets/` 锚点不准入；INVENTORY_SKIPPED reason=sensitive-filename; count=N；无目录名泄漏 | NFR-01、R60-04 |
| 9 | | `…::test_component_counts_match_build_inputs` | INV-OWN-1：每组件计数/Profile 输入/RAM 输入/Top-N 输入/图 evidence 五处输入集合逐文件一致；INV-OWN-2 守恒；**v4 扩展：INV-OWN-3 manifest 划分/父子隔离/来源可分（P60-V3-01/04）；v5 随动：INV-OWN-3(a) 新守恒式（manifests_discovered == Σ\|manifests\| + collaboration + overflow，CL-05）** | R60-02、AC-01、P60-V3-01/04、CL-05 |
| 10 | | `…::test_root_component_excludes_child_files` | API-01 输入集：根组件 RAM 不计子组件文件；跨组件模块计数不重复；**v4 扩展：文件清单视图下根/子切片精确（admitted_files 构造性隔离）** | R60-02、FR-02 复验、P60-V3-01 |
| 11 | C2 模块解析与未知区分（8；收益：RULE-02 反例 + 未知导入三态可观察） | `…::test_module_resolution_src_layout_cross_component` | RULE-02 输入集：A `import beta`→resolved 边 A→B（src 布局模块根解析） | R60-05、AC-01 |
| 12 | | `…::test_module_resolution_build_config_declared_root` | pyproject setuptools `where`/`package-dir` 声明目录成为模块根 | R60-05 |
| 13 | | `…::test_module_resolution_namespace_package` | 无 `__init__.py` 目录作 namespace 名解析；跨组件可产边；多名跨组件→ambiguous | R60-05 |
| 14 | | `…::test_relative_import_package_context` | 包上下文（`__init__` 链）相对导入解析；跨组件 resolved；越出仓库→unresolved | AC-01（相对导入） |
| 15 | | `…::test_duplicate_module_name_self_first_and_ambiguous` | P1 自身优先无边；P3 多组件命中→ambiguous（target=None，不向候选画边） | AC-01（重复模块名） |
| 16 | | `…::test_unknown_import_carried_not_external` | P5：非 stdlib/未声明/未定位导入入 `unknown_imports`；无边且**不伪称外部** | R60-05、三态 |
| 17 | | `…::test_known_external_stdlib_and_declared_deps` | P4a/P4b：stdlib 与 manifest 声明依赖名→无边无承载 | R60-05 |
| 18 | | `…::test_dynamic_import_sites_carried` | 封闭检测集位点→dynamic_import_site_count；不产边 | FR-05、三态 |
| 19 | C3 策略与预算不扩权（7；收益：API-02 反例 + 聚合包络新设计的机器可读验证） | `…::test_policy_inheritance_all_five_params` | API-02 输入集：组件视图五策略参数逐一==调用方有效值；ignore 集不丢失 | R60-03、NFR-01 |
| 20 | | `…::test_no_readmission_under_caller_caps` | 调用方 max_files=1：全输出不得含未准入文件；分歧组件 typed 不构建（不扩权优先） | R60-03 |
| 21 | | `…::test_aggregate_model_call_envelope` | **v4 重写（P60-V3-05）**：默认（无 client）零调用零网络；注入有界离线 fake client：全仓默认 8 次**尝试**口径（超时/失败尝试计入——fake client 制造 timeout/异常后尝试计数不回退）；第 9 次起组件 typed 降级 `BUDGET_EXHAUSTED(reason=aggregate-model-call-limit)`+静态事实保留；component_id 序确定 | R60-03、AC-02、P60-V3-05 |
| 22 | | `…::test_budget_caps_edge_evidence_unassigned_unknown` | 四类列表 cap 截断+typed gap（detail reason/count）不静默 | 预算 fail-closed |
| 23 | | `…::test_invalid_inputs_fail_closed` | 非 workspace/坏 budgets（0/负/非 int）/非 str 六 ID/空 digest→ContractError/ValueError | fail-closed |
| 24 | | `…::test_monorepo_budgets_invariants` | **v4 重写（P60-V3-03 三分离）**：MonorepoBudgets 每字段 默认值（16/4096/64/256/8/24000/4096/28096/64/1MiB）/ 合法域（1..64 等）/ 硬上限（schema maxItems=域上界）三分离——域内接受、域外（0/负/非 int/越上界）构造期 ValueError；total ≥ prompt+output 同构校验 | 预算单解、P60-V3-03 |
| 25 | | `…::test_budget_exhaustion_partial_facts` | 各截断形态返回部分事实+对应 gap+complete 触发（T1/T3/T7 对号） | fail-closed、R60-03 |
| 26 | C4 秘密形态与坐标变换（4；收益：API-03 反例的全公开面机械扫描） | `…::test_repo_level_admission_before_component_views` | API-03 输入集：`secrets/` 不产组件、`secrets/main.py` 不入任何组件 RAM/Profile/图面；整仓输出 0 模块语义保持+gap | R60-04、NFR-01 |
| 27 | | `…::test_all_public_surfaces_admission_rules` | 对序列化 payload 全文机械执行 §5.8 准入表（逐公开面字段过 `is_secret_shaped_path`）→零命中 | R60-04、NFR-01 |
| 28 | | `…::test_secret_gap_reason_count_no_filename` | gap detail 形态 `reason=sensitive-filename; count=N`；公开面无原文件名/目录名 | NFR-01（R1 终案） |
| 29 | | `…::test_no_masked_paths_no_old_digest_changes` | payload 路径为真实 repo-relative POSIX（无 redact: 前缀/掩码）；旧 digest 家族成员不出现于图承载 | 边界（已否决路线） |
| 30 | C5 完整性与缺口（6 = v2 5 + v3 SF-1 一；收益：API-04 反例 + v1 矛盾触发的唯一化；#53 T6 准入跳过为 E1 反例的承载锚） | `…::test_dependencies_complete_unified_triggers` | **v5 随动（CL-01）**：T1-T**8** 表驱动逐触发置 False（T8=通道 metadata-manifest-limit/metadata-byte-limit/unreadable/non-utf8 四键或对应 gap）；T 集外（evidence/unassigned 列表截断/聚合模型与 token gap/SEMANTIC_MODEL_OFF 等）不置 False；T6 判据含 §5.2.4 六键封闭集；三态优先级式唯一分类抽查（解析失败>证据不足>真实无依赖） | R60-06、FR-05、CL-01 |
| 31 | | `…::test_parse_error_carried_in_graph` | API-04 输入集：图层级 parse_error_file_count=1+T4；三态=证据不足非无依赖 | R60-06 |
| 32 | | `…::test_empty_edge_set_with_gap_not_no_dep` | 空边集+缺口（unassigned/unknown/parse）→判据表输出"证据不足"；真实无依赖仅在全合取下成立 | R60-06 |
| 33 | | `…::test_read_failure_carrier_default_and_trigger` | read_failure_file_count 默认 0、入 T5 封集；静态快照不可确定性构造的负例如实声明（不造假绿） | R60-06、诚实声明 |
| 34 | | `…::test_failure_family_observability` | 扫描/解析/动态/歧义/预算/敏感准入各失败族在图输出有可观察 typed 承载（表驱动） | FR-05 |
| 35 | C6 摘要与身份分离（7；收益：API-05 反例 + Oracle 独立性） | `…::test_identical_content_components_equal_digest_allowed` | API-05 输入集：同内容两组件三摘要**相等**且 component_id 不同可区分 | R60-07、FR-04 |
| 36 | | `…::test_component_identity_keyed_association` | payload 以 component_id 键控关联三 digest；交换两组件 digest（篡改关联）→validator 拒绝 | R60-07、R60-08 |
| 37 | | `…::test_content_change_digest_changes` | 单组件内容变化→其 digest 变+图 digest 变；他组件 digest 不变 | FR-04 复验 |
| 38 | | `test_monorepo_golden.py::test_golden_expected_from_independent_oracle` | golden JSON == P&V 独立预期（人工推导组件/边/计数/三态 + 既有公共 `compute_content_digest` 对手写 canonical dict 独立重算），**非实现输出回填** | R60-07、AC-01 |
| 39 | | `…::test_golden_monorepo_replay_and_topn` | 两次独立构建 digest 相等+每组件 ranked candidate_id 序列逐位相等 | AC-01（可重放） |
| 40 | | `…::test_golden_monorepo_provenance_chain` | 图 anchor=("component-graph",)+每组件三段 anchor 链+manifests provenance | AC-01（provenance） |
| 41 | | `…::test_golden_tamper_detected` | 篡改 golden 任一参与字段→digest 失配被识别 | R60-07 |
| 42 | C7 公开 Artifact 消费自洽（11+1；收益：R60-08 消费闭合与 validator 十维） | `test_component_graph.py::test_consumer_obtains_all_facts_from_public_artifacts` | **v4 重写（P60-V3-02 四点核对）**：仅凭 payload+每组件 envelope/RAM wire（无 workspace/不重跑构建/无内存对象）：①bytes 解码（`decode_profile_envelope(profile_bytes)`→`envelope.content_digest`==profile 槽）；②三摘要分别核对（`ram_facts_digest_from_wire`==facts 槽、`semantic_result_digest_from_wire`==semantic 槽、`ram_wire_digest`==`identity.wire_digest` 且 ≠facts digest）；③gaps 取自 ram/semantic 两 section+`execution_required_from_gaps` 复算==顶层；④篡改被拒（ranked score/envelope payload→ContractError/DIGEST_MISMATCH）+坐标映射+图摘要独立重算 | R60-08、P60-V3-02、系统约束 |
| 43 | | `…::test_validator_unknown_fields` | 未知顶层/嵌套字段→ContractError(UNKNOWN_FIELD)（V1） | fail-closed |
| 44 | | `…::test_validator_enums_and_digest_format` | 枚举外 status/kind、非 64-hex、line<1→ContractError(INVALID_FIELD_VALUE)（V2/V10） | fail-closed |
| 45 | | `…::test_validator_uniqueness_target_existence_ordering` | ID 唯一/目标存在/各集合排序去重违规→拒绝（V3/V4/V6） | fail-closed |
| 46 | | `…::test_validator_cross_field_and_caps` | is_empty⇔count、digests⇔built、unbuilt⇒complete=False、count≥len、maxItems cap（V7/V8） | fail-closed |
| 47 | | `…::test_validator_graph_digest_recompute` | 任一参与字段篡改→canonical 重算失配→拒绝（V9） | R60-07/08 |
| 48 | | `…::test_validator_secret_shaped_path_rejected` | payload 注入秘密形态路径（任一公开面）→拒绝（V5） | R60-04 |
| 49 | | `…::test_validator_unicode_and_charset_range` | 合法 Unicode 路径按声明范围通过；NUL/绝对路径/`..`/越界 charset 拒绝；不宣称任意 workspace（V5/V10） | R60-08 |
| 50 | | `…::test_no_execution_marker_absent` | 恶意 setup.py/import 副作用 fixture：构建前后 marker 不存在 | NFR-02 清单层复验、V5-FR-04 |
| 51 | | `…::test_static_no_network_no_env_no_syspath` | AST 断言零网络/subprocess/os.environ/文件写/sys.path 变更 import | V5-FR-04 |
| 52 | | `…::test_determinism_and_input_order_invariance` | 同快照两次构建全字段相等；同内容不同写入顺序两快照→digest 相等（含嵌套/unknown/unbuilt 字段） | AC-01、FR-04 |
| 53 | C5 完整性与缺口（**v3 增补，ER SF-1**） | `test_component_graph.py::test_admission_skipped_py_t6_incomplete_and_carried` | E1 输入集（根 pyproject.toml + good.py + oversize/non-utf8/binary `.py` 各一）：`dependencies_complete=False`（T6：file-size-limit/binary/non-utf8 键>0）+ coverage_gaps 含 INVENTORY_SKIPPED 逐键 `reason=<键>; count=N`（无文件名）+ 三文件不入 components/unassigned_files/edges evidence 任何公开面 + INV-OWN-2 守恒（三者不计入已准入总数）；豁免键（ignored-directory/unsupported-extension/sensitive-config/symlink）不触发 T6 的对照断言 | R60-06、ER SF-1、fail-closed |
| 54 | C1 组件发现与计数一致（**v3 增补 ER SF-2 → v4 重写，P60-V3-04**） | `test_component_graph.py::test_manifest_metadata_default_positive_and_strict_negative` | **默认正例**：仅 setup.cfg / requirements\*.txt / go.mod / pom.xml manifest（四类原盲点）+ 散 `.py` 的仓库，默认策略（metadata-channel）下**可锚定**——组件正常构建、manifests[].source="metadata-channel"、散 `.py` 归属正确；九类各一形态全覆盖（尤其四类原盲点）；**严格负例**：同仓库 `manifest_policy="admitted-only"` 下 components=()（通道关闭不悄悄失效）、散 `.py` 落 unassigned、主仓 `skipped["unsupported-extension"]` 计数可见、通道跳过计数与主仓计数分列 | R60-01、ER SF-2、P60-V3-04 |
| 55 | C1' 精确视图正例（**v4 增补，P60-V3-01**） | `test_component_graph.py::test_detect_components_same_name_dir_not_nested_anchor_builds` | 同名非子锚点目录 = **正例可构建**：锚点 `a/b` 与无关目录 `a/other/b/`（同名 `b`、非嵌套锚点）并存——`a/other/b/` 内文件按最深前缀归属 `a`（或就近锚点）正常入切片、组件正常构建、**不进 unbuilt**（v3 名字碰撞 typed 不构建撤销）；INV-OWN-1/2 守恒（v3 D7-COLLISION 输入集转为正例基座） | P60-V3-01、R60-02 |
| 56 | C1' 精确视图正例（**v4 增补，P60-V3-01**） | `test_component_graph.py::test_parent_component_profile_manifest_excludes_child` | 父组件 Profile 不纳入子组件 manifest：根+子组件（`services/`）形态——子组件 manifest 不在根组件 `manifests`（INV-OWN-3(b) 键级比对）；根组件 Profile 构建的 manifest 候选（W-2 受限过滤后）不含 `services/pyproject.toml`（INV-OWN-3(c) 层内行为）；manifests[].source 与实际集合一致（INV-OWN-3(d)） | P60-V3-01、P60-V3-04 |
| 57 | C7 公开 Artifact 消费自洽（**v4 增补，P60-V3-02**） | `test_component_graph.py::test_component_ram_wire_effective_config_no_default_backfill` | 聚合额度变化后每组件 wire `build` 段 = **实际生效** profile/ram budgets 与 semantic_options（`dataclasses.replace` 后的值），非 None/层默认；`ComponentBuildResult.effective_*` 与 wire build 段逐字段相等；wire_digest 自洽（回填默认必失配的机械验证）；图 payload `build.monorepo_budgets` = 有效聚合预算 | P60-V3-02 |
| 58 | C3' 参数边界（**v4 增补，P60-V3-03**） | `test_component_graph.py::test_parameter_boundary_unique_behavior` | `max_components=17`：≤17 全构建、>17 截断到 17+gap(component-limit)+T1（唯一行为）；`top_n=21`：ranked 承载 21 项+semantic_topn.top_n=21+schema maxItems 100 通过；`top_n=0/101`：SemanticOptions 冻结 ValueError 传播；紧 cap：unbuilt(cap-divergence) 唯一归宿；各拒绝样例构造期 ValueError | P60-V3-03 |
| 59 | C3'/C5' 部分产物自洽（**v4 增补，P60-V3-03**） | `test_component_graph.py::test_partial_products_pass_own_validators` | 耗尽/截断形态（组件截断/边截断/聚合归零/通道预算触发）的部分产物：图 payload 过 `validate_component_graph_payload`、每组件 wire 过 `validate_ram_wire_payload`；built/status/gap/build 段有效配置/三摘要自洽；零额度不构造 `max_llm_calls=0` 的 SemanticBudgets（构造即 ValueError 断言）、不填伪 digest、不删已得 Profile/RAM/确定性排序 | P60-V3-03、P60-V3-05 |
| 60 | C4' 通道不扩权（**v4 增补，P60-V3-04**） | `test_component_graph.py::test_manifest_channel_no_source_readmission` | 元数据通道发现不重新准入源码：(S2) 发现的 requirements.txt/setup.cfg 等**不进** (S1) 语义——不计 python_file_count、不被 AST 扫描、不进组件 Profile inventory 维度（除非扩展策略内且已准入，此时 source="source-inventory"）；主仓 `skipped` 事实不被通道改写/追平（分列呈现）；通道对秘密形态/ignored/symlink/越界的剪枝全负例（计数可见、无路径） | P60-V3-04、NFR-01 |
| 61 | C1'' 两集合分离（**v4 增补，P60-V3-04；v5 随动重写（CL-05）**） | `test_component_graph.py::test_two_input_sets_counts_and_provenance_separated` | 两输入集合计数/provenance 分离核对（**v5 计量域口径**）：`metadata_manifest_count`=S2 通道发现总数（**含重叠成员**，≠发布条目数）；`metadata_manifest_count ≤ manifests_discovered_count`、`Σ(metadata-channel 发布) ≤ metadata_manifest_count`；INV-OWN-3(a) 新守恒式（manifests_discovered == Σ\|manifests\| + collaboration + overflow——文件级，无秘密项）；`metadata_channel_skipped` 七词表封闭、与主仓 skipped 分列、gap detail 对账相等；同路径双集合成员单值 source="source-inventory" | P60-V3-04、CL-05 |
| 62 | C3'' 聚合 token 池（**v4 增补 P60-V3-05；v5 重写（CL-03）——恢复自定义小预算断言（删除 v4.1"默认调用方"限定语）**） | `test_component_graph.py::test_aggregate_token_pool_exhaustion_typed_degradation` | 聚合 token 池（fake client + 小池）：**自定义小 caller（SemanticBudgets 2/1000/500/1500）下 effective 三池=min=1000/500/1500，全仓累计截止在 caller 对应值内（API-POOL 的 1684/2048/3732 调度不可达断言）**；预调用预估计量、预扣不退还（失败尝试额度已耗）；耗尽后新尝试不调度、组件 typed 降级 `BUDGET_EXHAUSTED(reason=aggregate-token-pool-limit)`；静态事实+确定性 Top-N 保留；三摘要/wire 仍可验证（与 #59 同一自洽面的池口径）；有效 build 配置一致（wire build 段/payload build.monorepo_budgets=effective 值，回填 requested/默认即失配） | P60-V3-05、CL-03 |
| 63 | C5'' 读放大计量（**v4 增补 P60-V3-05；v5 随动重写（CL-04 新公式）**） | `test_component_graph.py::test_read_amplification_metered_and_bounded` | `ResourceMetering` v5 六计数器（尝试口径）与保守常数倍上界机械核对：`component_rescan_read_attempts ≤ 5×Σ(切片文件数)`、`main_inventory_read_attempts ≤ discovered_files`、`profile_manifest_read_attempts ≤ Σ(候选数)`、`ast_read_attempts ≤ 归属 .py 数`、`metadata_channel_read_attempts ≤ max_metadata_manifests`、全链 ≤ `6×discovered + 2×manifests_discovered + max_metadata_manifests`、`read_success_bytes ≤ 尝试×max_file_bytes`；**真实新链路累计读取含失败/unbuilt 前已发生（不只数成功 built）；防只数 distinct paths（单文件多阶段多次读取必须如实累加——API-IO 的 5 次为基线形态）**；超界=实现缺陷（断言失败）；截断规则唯一（各通道既有 cap 达界即停+typed gap） | P60-V3-05、CL-04 |
| 64 | C8'' 元数据丢失完整性（**v5 增补，CL-01 数量帽变体**） | `test_component_graph.py::test_metadata_loss_count_cap_incomplete_not_real_no_deps` | RULE-COMPLETE 夹具（根 pyproject+两子 setup.cfg+S2 数量帽漏第二锚点）：T8 触发（metadata-manifest-limit 键计数>0 与 BUDGET_EXHAUSTED gap detail 同键同值对账）、`dependencies_complete=False`、三态唯一分类=**证据不足**（不进"真实无依赖"分支——P3 全合取失败）、截断前已发现组件照常发布、守恒式成立（发现数=实际发现值不虚构） | CL-01、fail-closed |
| 65 | C8'' 元数据丢失完整性（**v5 增补，CL-01 字节帽变体**） | `test_component_graph.py::test_metadata_loss_byte_cap_incomplete` | S2 字节帽（max_metadata_total_bytes 小值）截断：同 #64 断言面（T8=metadata-byte-limit 键+gap 对账、complete=False、唯一"证据不足"、部分事实保留） | CL-01 |
| 66 | C8'' 元数据丢失完整性（**v5 增补，CL-01 非预期读取失败变体**） | `test_component_graph.py::test_metadata_loss_read_failure_t8` | 通道 manifest 读取失败（unreadable）：T8 触发（INVENTORY_SKIPPED `reason=unreadable; count=N` 与通道键对账）、发现/锚定/发布保留（枚举命中即发现）、解析无静态事实=部分产物、complete=False、唯一"证据不足" | CL-01 |
| 67 | C8'' 元数据丢失完整性（**v5 增补，CL-01 解码失败变体**） | `test_component_graph.py::test_metadata_loss_decode_failure_t8` | 通道 manifest non-utf8 解码失败：同 #66 断言面（`reason=non-utf8`）；与主仓 T6 同名键的承载分列对照（通道侧 vs 主仓侧计数互不合并） | CL-01 |
| 68 | C8''/C7 元数据丢失 partial payload 公开消费（**v5 增补，CL-01+CL-05 联合**） | `test_component_graph.py::test_metadata_loss_partial_payload_public_consumption` | #64-#67 任一截断/失败形态的 partial 产物：图 payload 过 `validate_component_graph_payload`、每组件 wire 过 `validate_ram_wire_payload`、§5.4.7 消费基准对 built 条目可执行（三摘要核对/execution_required 复算）、守恒式与对账在 partial 形态下仍成立——**公开 decoder/validator 消费 partial 事实不被"完整性 False"阻断** | CL-01、CL-05、R60-08 |
| 69 | C9'' 自身元数据视图（**v5 增补，CL-02**） | `test_component_graph.py::test_profile_own_manifest_facts_preserved_under_s1_view` | main.py+requirements.txt（S2-only）默认策略：组件 Profile **frameworks/package_managers 静态事实保留**（flask/pip——API-META 修复）；requirements 不计 python_file_count、不进 inventory 文件集、不进 AST（源码视图不被元数据视图扩大）；manifests[].source="metadata-channel"；读取计量 S3+S8 双计 | CL-02 |
| 70 | C9'' 父子元数据隔离（**v5 增补，CL-02**） | `test_component_graph.py::test_parent_child_distinct_requirements_isolated` | 根 requirements.txt（flask）+ services/requirements.txt（另一个不同依赖）：父 Profile 只取得父 manifest 事实、子只取得子的（互不串证据）；父 metadata_files/W-2 候选不含子 manifest（INV-OWN-3(b)(c)）；守恒式 2==1+1 | CL-02、P60-V3-01 |
| 71 | C9'' S2-only 不重新准入（**v5 增补，CL-02**） | `test_component_graph.py::test_s2only_not_source_readmitted` | S2-only manifest 文件：不计 python_file_count、不被 AST 扫描、不进组件 Profile inventory 维度（除非扩展策略内且经主仓准入——此时 source="source-inventory" 且进 admitted_files）；strict/secret/ignored/symlink 负例随行（通道剪枝计数可见、无路径——沿用 #54/#60 扩展） | CL-02、P60-V3-04 |
| 72 | C3'' 四类对照 graph 级调度（**v5 增补，CL-03**） | `test_component_graph.py::test_effective_pools_min_caller_graph_scheduling` | 四类对照（默认/小 caller 1000-500-1500/大 caller/显式更高 requested）在**真实 graph 调度**（非单独数学表）下的唯一行为：effective=min(requested, caller) 三池逐类断言；小 caller 累计截止在 caller 值内+typed gap+静态事实与确定性 Top-N 保留；大 caller 不扩池（=requested 默认）；显式更高=政策授权点语义承载（本轮默认路径不含）；停止后 typed gap 与有效 build 配置一致 | CL-03 |
| 73 | C10'' V7/V8 计量域（**v5 增补，CL-05**） | `test_component_graph.py::test_v7_v8_overlap_and_collab_manifest_metering_domains` | overlap（S1∩S2：D2 计数含重叠、发布 source=source-inventory、`Σ(metadata-channel 发布) ≤ metadata_manifest_count`）；协作 manifest（Cargo.toml 仅 [workspace]：不产根组件、计入 collaboration_manifest_count、守恒式成立——RULE-COUNT ② 修复）；T1 溢出/通道截断/失败的发现计量与归属计量正例（截断行=实际发现值+T8 承载）；多 manifest 同锚点按文件计；**篡改负例仍拒**（改计数字段→V7 守恒失配或 V9 digest 失配） | CL-05 |

PI-DR 落实：PI-DR1（LF 钉死/POSIX 断言/零平台权限依赖）；PI-DR4 模块缺席 RED 锚（新测试 import `lima.audit.component_graph` 失败为 RED 锚**之一**——不代替语义覆盖）；**PI-DR2 scratch/reference 流程（R60-07 D2 计划）**：D2 冻结前须以 scratch 参考实现或等价独立参考验证验收测试非自相矛盾、能接纳合规结果（存在满足全部断言的合法输出），并记录于 Frozen Test Commit；PI-DR6 冻结前非 Windows 平台完整跑一次并记录 run SHA；PI-DR5 PR 禁自动关闭关键字。

## 7. AC traceability（正向+反向 100%）

| Requirement | 本 IP 贡献声明 | Test（§6 #） |
|---|---|---|
| V5-FR-03（前半句：monorepo 输出 component graph） | 嵌套组件识别 + 边三态 + 未知导入承载 + 独立承载 + 每组件三段 | #1-#18、#42-#49、#54-#56、#60-#61 |
| AC-01/T-01（monorepo/重复模块/相对导入维度：provenance + Top-N 可重放） | golden（独立 Oracle）+ 边三态 + 确定性 | #11-#15、#38-#41、#52 |
| V5-AC-01/V5-T-01（monorepo 维度：Profile/roles/support/execution capability/gap） | 每组件 Profile 全字段（复用 IP-0016 规则） | #3、#9-#10、#38-#40 |
| V5-AC-02/V5-T-02（后半句：monorepo 按 component 生成 profile/RAM） | `build_monorepo_profile` 每组件全链（单一归属） | #9-#10、#21 |
| FR-02/03/04/NFR-01（组件维度复验） | 复用三层公共接口逐组件重放（策略继承+隔离不变量） | #9-#10、#19-#21、#26-#29、#35-#37、#52、#55-#56 |
| FR-05（typed gaps / 三态可观察） | 统一完整性触发集 + scan/unknown/unbuilt 承载 + T6 准入跳过承载（v3）+ 部分产物自洽（v4） | #16、#18、#30-#34、#53、#59、#62 |
| 预算/安全基线 | 聚合包络 fail-closed（全仓 8 尝试+token 池，v4）+ 参数边界三分离（v4）+ 读放大计量（v4）+ 隐私/no-execution/静态断言 | #7、#19-#25、#50-#51、#57-#63 |
| P60-V3-01..05 裁定锚（v4 新增行） | 精确视图/消费链修正/参数三分离/元数据通道/全仓资源约束逐裁定 | #9-#10（扩展）、#21/#24/#42/#54（重写）、#55-#63 |
| CL-01..05 跨层契约锚（**v5 新增行**） | 元数据丢失完整性/双清单视图/effective 三池/真实 IO 计量/五计量域一致 | #30/#61/#62/#63（随动重写）、#64-#73（增补）；联合正例 §5.9 六项 |

反向：§6 每个测试符号唯一指向上表行（D2 冻结时以 `test_file::test_symbol` 表落档）。本 IP 不宣称：AC-01 整体满足、V5-FR-03 后半句（安全停止）、T-03 端到端、F3/F4、#64/#68 消费。

## 8. 验收命令（Done Commands；D2/Implementation/验证共用，全部在交付 worktree 根执行）

```text
# slice（新增用例全绿，0 skip；v5 计划 73 方法 = v4 63 + #62/#63 恢复与随动重写 + #30/#61 随动 + 增补 #64-#73——§6 注记：方法数=规划数非帽）
python -B -m unittest tests.audit.test_component_graph tests.audit.test_monorepo_golden -v
# tests/audit 全量回归（基线锚 235 @fbbbd619；含 IP-0022 51 例回归锚；计数变化需解释、不得删测试追平）
python -B -m unittest discover -s tests/audit -q
# contracts 回归（基线锚 617 @fbbbd619）
python -B -m unittest discover -s tests/contracts -q
# lint（lima/audit 净；audit+tests/audit 恰 DR-LINT-0022-A 六处=B009×1+B017×5 全在 test_ip_0022_fix.py，零新增）
python -B -m ruff check --no-cache lima/audit
python -B -m ruff check --no-cache lima/audit tests/audit
python -B -m bandit -q lima/audit/component_graph.py        # 零 finding
python -B -m compileall -q lima tests                       # exit 0
# CI 完整入口（ci.yml 同款；基线锚 3006 OK 24 skip @fbbbd619，全环境类 skip，#60 验收面零 skip）
python -B scripts/run_ci_tests.py
# 边界
git diff --check                                           # 干净
git diff --name-only --diff-filter=ACMRTUXB                # 恰为 §4 Add 7 文件（__init__.py 必不在列）
# 契约单点
python -B -c "import lima.audit as a; assert len(a.__all__) == 54"   # 54 帽零触碰锚
python -B -c "import lima.audit"                                      # 零副作用
sha256sum schemas/v4/lima.component-graph.json tests/audit/fixtures/monorepo/golden/monorepo.json  # 与冻结记录一致
```

**平台实跑计划**：Windows 本机（RED/GREEN + 上述全组）；**PI-DR6**——D2 冻结前在非 Windows 平台（GitHub Actions Linux runner，临时验证分支 workflow_dispatch，先例 `pv/ip-0022-freeze-pidr6` run 34826215469）完整跑一次新增测试集，记录 run SHA 与结论入 Frozen Test Commit 记录；安全关键用例不得用 skip 充当 PASS（#33 的不可构造负例以显式声明处理，不造绿）。

**Post-merge**（Coordinator 指令后）：上述 mandatory 全组在最新 origin/main 复跑，输出 `POST-MERGE PASS/FAIL`。

## 9. Stop Conditions / Decision Request

1. 组件识别需跨 manifest/路径组合证据而现有公共承载（workspace 只读 inventory + read_text）无法表达 → Contract Gap 停点，提 DR（选项+推荐+兼容影响+草案），不发明扩展字段；
2. 任何需要修改 `lima/workspace.py`、`lima/contracts/**`、三层+ram_schema 冻结面、既有 tests/audit 文件、schemas/v4 既有 15 文件才能满足本 Packet 的情形 → 停点（共享层改动单列 DR 附调用链与理由；**v4：§4.3.1 白名单两项（DR-IP-0023-02 已采纳目标）是唯一预呈的共享层 additive 集；v5：白名单扩充为双清单视图（CL-02），激活条件=本 Packet v5 获批，白名单外仍走本停点**；F3 路线归 #60-CLOSURE-C）；
3. 触及冻结约束的新设计（54 帽扩帽、digest 家族语义、GAP 码新增、execution_required 语义、#58 字段、v4 schema/旧 golden 期望值）→ 具体 DR 获批前不实现、不留 TBD 空位；
4. 与 #266/#281 出现文件或语义冲突迹象（含远端分支前移触及 #60 敏感路径）→ 停止上报 Coordinator；
5. 基线前移：开工时已核验 fbbbd619 未前移；后续阶段（D2/Implementation）开工时重新 `git fetch origin`，前移涉冻结产品面/共享输入层/Contract·fixtures → 按批复 §四分类补核验，涉 #60 敏感路径上报复核后开工；
6. 回归计数与基线锚（617/235/3006+24skip）不符 → 按实际覆盖变化与失败内容判断（addendum-2 §3 修订版）：计数变化须可追溯，不单独构成停点；真实失败按停点纪律上报；**不得删测试/改 Oracle/改期望值追平数字**；
7. 实现期发现需改冻结测试 → 先 Decision Request（缺陷证据+影响面+建议方案），获授权后走 Packet 修订 → 撤销旧冻结 → 重新 RED → 新 Frozen Test Commit；禁止同提交悄悄修测试；
8. IP-0023 编号被对端轨道登记占用（ALLOC 失效条款）→ 停止上报；
9. **（D1R 新增）R60-01..08 修订方案在 D2/实现期确需触及 54 帽、digest 家族、#58、v4 schema/旧 golden、GAP 码全集、execution_required 语义、`lima/workspace.py`/共享接口任一项 → 停在具体 DR**（选项+推荐+兼容影响+调用链），获批前不写入实现为既成事实。

## 10. 回滚与兼容影响

- **纯新增交付**：产品面恰 2 新文件，测试面 5 新文件；零修改既有任何文件（含 `__init__.py`）⇒ 回滚 = revert 单个实现 PR，无迁移、无数据兼容问题；
- **旧消费者零影响论证**：54 帽原样、六 digest 原样、GAP 10 码与 9 码触发原样、#58 契约零改动、v4 schema 既有 15 文件与 matrix 零改动、五形态旧 golden 期望值零改动、错误目录既有码值零改动——既有消费路径行为逐字节不变（tests/audit 235 + tests/contracts 617 + golden 全绿为证）；
- **schema 版本共存**：`lima.component-graph.json` 独立版本 `"2.0"`（v1.0 未实现未发布，无迁移）、不注册 matrix——旧消费者不可见该文件；未来注册属 BG-60-01 口径（Maintainer 另决 + DR）；
- **回滚不降低门禁**：不涉及 Evidence Level/Gate/raw-secret/FULL_CHAIN 任何维度。

## 11. 危险与失败矩阵（危险输入 × 失败模式处置表）

| 危险输入 | 失败模式 | 处置（承载/行为） | Test |
|---|---|---|---|
| 嵌套组件（services/api、packages/core） | 浅层规则漏识别 | 任意深度锚点（已准入 manifest 父目录）；识别不了→unassigned/gap 如实 | #1 |
| 根组件与子组件并存 | 根构建吸入子组件文件（API-01） | 继承策略组件视图+嵌套锚点名 ignore+INV-OWN-1 逐文件校验 | #9、#10 |
| 名字碰撞目录（祖先子树内与嵌套锚点同名） | ~~同名剪枝过度排除~~（v4：basename-ignore 废除） | **正例可构建**（文件清单视图：碰撞目录文件按最深前缀入切片正常扫描，不进 unbuilt——P60-V3-01）；`unbuilt` 仅承载 cap-divergence/view-unformable/admission-refused 三类（reason 可区分） | #55（正例）、#9 |
| 空仓库 / 零 manifest | 无组件边界证据 | components=()、edges=()、unassigned 计数如实；不报错 | #3 |
| 根 workspace 协作 manifest | 误产根组件/双计 | workspace 键集识别→不产根组件 | #4 |
| 调用方 cap 收紧（max_files=1 等） | 组件切分重新准入（API-02 反向） | 五参数继承+admitted_files 构造性隔离+INV-OWN-1 复核；分歧组件 typed 不构建（v4：unbuilt reason=cap-divergence，三类可区分） | #19、#20、#58 |
| ≥17 组件 | 聚合放大 | 前 16+BUDGET_EXHAUSTED+complete=False（T1） | #7 |
| src 布局（src/alpha vs src/beta） | 锚点同名 `src`、跨组件导入丢失（RULE-02） | 模块根解析（构建配置+src 内容证据）；顶层名表跨组件 resolved | #11、#12 |
| 两组件同名顶层包 | import 目标不唯一 | P1 自身优先；P3 ambiguous（target=None） | #15 |
| namespace 包（无 `__init__.py`） | 漏解析或误歧义 | namespace 名候选可解析；多名跨组件→ambiguous | #13 |
| 未知导入（非 stdlib/未声明/未定位） | 伪装成外部无边无 gap（RULE-02 隐患） | P5 `unknown_imports` typed 承载；三态可观察 | #16、#32 |
| 相对导入越界/目标缺失 | 解析失败 | 包上下文解析；unresolved 边（target=None） | #14 |
| 语法错误文件 | RAM counter 有值而 gap 空（API-04） | 图层级自计 parse_error_file_count（T4）+scan_summary 承载 | #31 |
| 读取失败（保留触发） | 静默丢证据 | read_failure_file_count（T5）；静态快照不可构造性如实声明 | #33 |
| 组件内动态 import | 静态不可解 | dynamic_import_site_count 自计；不产边 | #18 |
| 恶意 setup.py / import 副作用 | 执行风险 | 零执行（tomllib/ast.parse/存在性检查）；marker 负例 | #50、#51 |
| 秘密形态目录/文件名（secrets/ 等） | 坐标变换绕过准入（API-03） | 仓库级先准入：锚点拒绝+公开面准入表+validator V5；reason→count | #8、#26-#28、#48 |
| CRLF 文件 | 行号口径漂移 | 行号按保留 CRLF 原文计算；fixture 全 LF | （并入 #52） |
| symlink / 二进制 / 超大 / 非 UTF-8 / 不可读文件 | workspace 跳过后图输出零承载（E1：v2 判据下 complete=True + 三个 `.py` 隐形） | binary/non-utf8/file-size-limit/unreadable 入 T6 + 逐键 INVENTORY_SKIPPED `reason=<键>; count=N`（无文件名）；ignored-directory/unsupported-extension/sensitive-config/symlink 声明豁免 + 计数可见（§5.2.4 十键全归类） | #30、#53 |
| 仅 setup.cfg / requirements*.txt / go.mod / pom.xml manifest 的仓库 | ~~默认扩展策略下永不可锚定~~（v4：四类盲点由元数据通道收口，P60-V3-04） | **默认策略（metadata-channel）下可锚定正例**（§5.1.7 受控通道：封闭名集只读发现、双预算、分列跳过计数、不扩源码准入）；严格 admitted-only 策略=通道关闭负例（不悄悄失效）；DEFAULT_EXTENSIONS 零改动（选项 B 禁止） | #54（重写：正例+负例）、#60、#61 |
| 聚合模型/token 额度耗尽（fake client 下） | 静默丢 semantic 或回填默认配置 | 全仓 8 次尝试口径+聚合 token 池预扣不退；**v5/CL-03：effective 三池=min(requested, caller)——较小 caller 累计截止在 caller 对应值内（1684/2048/3732 调度不可达）**；耗尽=typed gap（aggregate-model-call-limit / aggregate-token-pool-limit）+静态事实+确定性 Top-N 保留+三摘要/wire 可验证；不构造非法 SemanticBudgets、不回填默认/requested（回填即 wire_digest 失配） | #21（重写）、#59、#62（恢复）、#72 |
| 每组件重扫/AST/manifest 读放大 | 无界或未计量的重复读取；或把 distinct files 当累计 IO 低报计量（API-IO：单文件三段链实测 5 次 > 旧上界 1） | **v5/CL-04**：`ResourceMetering` 六计数器（尝试口径，含失败/unbuilt 前已发生）+九阶段归属表+保守常数倍上界（`component_rescan ≤ 5×Σ切片`、全链 ≤ `6×discovered+2×manifests+max_metadata_manifests`、bytes ≤ 尝试×max_file_bytes）+各通道既有 cap 达界即停；重复读全计量（通道+Profile 对同一 manifest 双计）；不削正常画像 | #63（重写） |
| S2 元数据证据丢失（数量帽/字节帽/读失败/解码失败） | "gap 非空但 complete=True 且同时命中真实无依赖与证据不足"（RULE-COMPLETE）；未扫描依赖被当作已排除 | **v5/CL-01**：T8 触发（通道四键+对应 gap 双承载对账）→complete=False→三态优先级唯一分类"证据不足"；部分事实保留+partial payload 公开可消费；政策主动拒绝（ignored/secret/symlink/严格策略）与证据丢失逐键归类、豁免有明确准入范围 | #30（随动）、#64-#68 |
| 组件自身 manifest 元数据被 S1 过滤清空（API-META：flask/pip 丢失） | W-1/W-2 单一 S1 过滤致 Profile 自身 manifest 候选=[]、静态事实变空 | **v5/CL-02**：双清单视图（admitted_files 源码切片 + metadata_files 自身 manifest）——Profile 候选/读取按并集准入；S2-only 不重新准入源码；父不读子 manifest（清单构造性隔离） | #69-#71、#56 |
| manifest 计数域混用（overlap/协作 manifest/秘密锚点/T1 溢出） | V7 要求 1=0（RULE-COUNT ①）；协作 manifest 无归属致划分等式不可满足（②）；锚点数当文件数 | **v5/CL-05**：五计量域+联合参考表；metadata_manifest_count 单义（含重叠）；守恒式（发现==Σ发布+collab+overflow，文件级）；秘密子树不属发现域；差额字段显式承载不藏条目 | #61（重写）、#73 |
| manifest 静态解析失败 | 模块根/依赖证据缺失 | 保守回退（根+src 约定+unknown 承载）；Profile 层既有 MANIFEST_PARSE_ERROR 不受影响 | #12、#16 |
| 非 workspace 入参 / 非法预算值 / 空 digest | 类型违约 | ContractError/ValueError fail-closed | #23、#24 |
| 边/evidence/unassigned/未知导入超量 | 无界放大 | cap+typed gap（count 如实），无静默截断 | #22 |
| payload 篡改（未知字段/枚举外/坏 digest/乱序/换 digest/注入秘密路径） | 契约违约 | validator V1-V10 一律 ContractError；digest 自洽重算 | #43-#49 |
| 相同内容不同组件 | digest"互异"假断言（API-05） | 允许相等；component_id 键控关联；篡改关联被拒 | #35、#36 |
| 目录枚举顺序不定 | 结果漂移 | 全枚举入口 sorted；输入顺序不变性断言 | #52 |

## 12. Completion Summary / PR contract

- Completion Summary 必含：base/final commit、修改文件与公共符号清单（§5.4.7 的 `__all__` 逐项）、AC→Test→Result 表（§7 + §6 符号）、§8 全部命令实际输出与统计（含计数与退出码）、schema 与 golden 文件 SHA-256、文件边界自查（`__init__.py` 未改动证明；§4.3.1 白名单实施时另附：白名单内 diff 恰为两项（W-1 双参数 + W-2 并集过滤）、缺省 None 行为不变的既有测试证据）、**R60-01..08 + P60-V3-01..05 + CL-01..05 逐项实现对照**（实现行为 → §0.1/§0.3/§0.4 修订规则 → 对应测试符号；CL-01..05 各含反例不可达的实测证据——#64-#73）、真实 IO 计量账（`ResourceMetering` 实测值 vs 保守上界公式，CL-04）、已知限制（v4 起：monorepo golden 单形态、Python-only 组件边、安全停止/T-03/F3/F4 归 B/C、FR-01 全 vocabulary 留痕归 D、full semantic 下游消费归 D、真实模型客户端不入本片、聚合墙钟不宣称——~~祖先组件 manifest 证据范围限度、名字碰撞 typed 不构建~~两项已由 v4 精确视图撤销；v5 增：`metadata_channel_skipped` 不进 canonical（非 digest 级防篡改——V7 对账+词表承载，如实声明）、通道读取失败静态快照下难确定性构造（#66/#67 以可构造变体覆盖））；
- Implementation PR：`Implements IP-0023` + `Related to #60`；正文含 Packet merge commit、Frozen Test Commit、covered/not-covered（§0）、AC 矩阵、命令实测、Verdict、`This PR does not auto-close the Source Issue.`；**禁止** close/fix/resolve 与 #60 组合（PI-DR5）；
- Packet docs PR（主会话在 Coordinator readiness 复核与 ER 反证后执行）：docs-only，恰含本 Packet 修改（同文件 v1→v4 提交链），`Related to #60`，禁自动关闭关键字；合并批准逐项请求 Maintainer（随包呈交：五项处置、公开消费实证、实际验证/未验证、真实 head/base/diff/CI、共享层方案及兼容影响、资源上界、尚待决定事项——指令 §八）；PR 正文重写围绕最终问题与行为，说明实际验证/未验证（含 D1R/D1F 探针为设计证据而非产品验收）。

## 13. Packet 完成定义与 Open Decisions

- 本 Packet 关键 TBD 数 = 0；状态 `D1X-REVISION / PENDING-REVIEW`——**不标 READY-FOR-CODE**；`READY-FOR-CODE` 当且仅当：本文档（v5 或后续修订版）合并进 main（Coordinator 标 `PACKET-MERGED`）且 D2 按 §6 计划完成有效 RED（含 PI-DR2 scratch/reference 非自相矛盾验证）与 PI-DR6 双平台记录；
- **Open Decisions（呈审项，非实现阻塞、非 TBD 空位；v5 改写）**：
  1. DR-IP-0023-01（备选，维持）：`lima.audit` 命名空间追加 re-export（=扩 54 帽）——默认不扩帽，草案随交接报告；
  2. **DR-IP-0023-02（已采纳目标，P60-V3-01 + CL-02/指令裁定）**：精确组件视图+自身元数据视图的共享层 additive 白名单已具体化为 §4.3.1 两项（**v5：W-1 workspace `admitted_files`+`metadata_files` 双清单 / W-2 `_manifest_candidates` 并集受限过滤**）——方案取舍已冻结（文件清单视图+双清单元数据视图，弃路径级排除与受控载体方案：单一机制约束三入口且保持旧 Profile 自身 manifest 事实）；**激活条件=本 Packet v5 获 Maintainer 批准合并**（采纳目标不等于已批准未具体化的共享层实现——白名单外仍禁止）；激活后消除 v3 已知限度 (i)(ii)（§5.2.1）；
  3. ~~聚合模型调用包络 `max_total_model_calls=128` 呈审项~~（**v4 关闭：128 已被指令 §四 P60-V3-05 否决**，列入已否决路线不得重试）；改立**政策审批点（v5/CL-03 口径）**：`max_total_model_calls > 8` 或 **requested** 聚合 token 池高于保守默认（24000/4096/28096）的实际使用须显式配置+政策授权（未来审批点，本轮不授予；**effective 恒 = min(requested, caller)——显式提高 requested 不会使 effective 超过 caller 对应值**，技术合法域已冻结 §5.4.3，非开放设计项）；
  4. **快照内容缓存（v5/CL-04 移交的可选设计项，未采纳）**：本片默认零缓存、全计量如实（保守常数倍上界）；未来若采纳须先 Packet 修订并按 §4.3.2 五要件（视图键/不可变内容身份/失败截断/默认兼容/共享层接口清单）列入白名单经 Maintainer 批准——当前零实现、不入白名单；
  5. BG-IP-0016-01 / BG-60-01 / DR-LINT-0022-A 维持 OPEN（归置权在 Coordinator）；F4 聚合墙钟未闭合（归 #60-CLOSURE-C）；
  6. **DR-IP-0023-03（已采纳方向，P60-V3-04/指令 §四裁定）**：受控 manifest 元数据通道为本片已采纳设计（§5.1.7 冻结单解）——选项取舍：通道化变体（组件层封闭名集只读元数据发现，两输入集合分离），**选项 B（`DEFAULT_EXTENSIONS` 增补 .txt/.cfg/.mod/.xml）明确禁止不采**（触 workspace 冻结面且改变全仓 inventory 行为与既有 golden）；九类默认正例+严格 admitted-only 负例的验收锚 #54/#60/#61；如 Maintainer 认为通道预算/策略默认值需调整，经 Packet 修订实施（设计已具体化，无开放式备选残留）。
- 后续阶段（D2 冻结测试、Implementation、独立验证、ER、合并、post-merge、IP-DONE、M2..M7）均未授权，另行 Assignment/派发。

---

## 附 A. 本 Packet 制作证据摘要（D1R，全部本轮亲验）

- 基线：`git fetch origin` 后 `origin/main = fbbbd619fb0b96efbbb903916ab46dc0daed2214`（未前移）；修订基线 worktree `D:/BaseAIProject/LIMA-60-closure-a-pv-wt`（分支 `codex/ip-0023-monorepo-packet`，开工 HEAD=`41c899ef10be682e52d61ab0f92e4bef11aed27c`，`git status --porcelain` 为空）；Packet v1 SHA-256 重算一致（`e9702fe2…f7f9f`）；
- 输入 SHA-256 重算一致（全部亲验）：D1R Assignment `30a0e919…c040a`、指令正文 `4f713455…edd89`、回顾 `00483bd6…658b`、probe results `90f3d975…acb8a4`、github snapshot `9b24579a…4d81d`、MDR `759a9225…3403`、D1_v1 Assignment `5a118ea9…73b82`；
- 冻结面只读核对（@fbbbd619，import/源码亲验，零目标项目执行）：§3.1 全部签名/常量/默认值（含 **两层入口 isinstance 硬校验 + 自行 inventory()**——R60-02/03 可行性边界）；workspace 构造器五策略参数/`inventory()` 公开 skipped 计数/按名剪枝无路径级排除（§3.3）；`is_secret_shaped_path` 对 `secrets/pyproject.toml`、`secrets/main.py`、`main.py` 的取值亲验；`PythonDataflowAnalyzer.analyze_project`/`_module_name` 只读参照（§5.3.5）；schemas/v4 15 文件清单；
- 本阶段未执行：产品代码/测试/schema 修改、全量产品测试重跑（基线数字引用恢复审计 §5）、远端写、冻结（D2 另行）、推送（本轮派发要求不 push；Assignment 允许推送以 Coordinator 后续指令为准）。

## 附 B. D1R 设计探针（设计证据，非产品验收）

- 探针：系统临时目录 `design_probe_v2_d1r.py`（本轮自写，只读仓库、fixture 全在系统临时目录、零网络零目标执行；运行时 = 归档基线 `output/issue60-pr282-retrospective-2026-10-09/baseline-runtime`，`_review_base_sha.txt` 校验 fbbbd619）；结果 JSON：`%TEMP%/design_probe_v2_d1r_results.json`，断言 7/7 全过；
- 输出明确区分：**设计推导**（D1-RULE01 段落规则于真实 inventory 之上复算、D6-RULE02 模块根规则字面推导）与**已有公共 API 实跑**（D2/D3/D4/D5/D7 使用 fbbbd619 真实 `RepositoryWorkspace`/`build_python_ram_facts`/`is_secret_shaped_path` + v2 构造规则）；
- 结论（方向性，产品验证归 D2）：D1 `services/api`、`packages/core` 均可识别（RULE-01 消除）；D2 根组件构建输入=精确切片、v2 根 RAM 计 1 模块（v1 构造计 2——API-01 消除）；D3 组件视图五策略参数==调用方（API-02 消除）；D4 秘密形态锚点被拒、rebased 视图不可达（API-03 消除）；D5 图层级 parse 计数可自计（API-04 承载补齐）；D6 `import beta` → resolved 边 A→B（RULE-02 消除）；D7 名字碰撞分歧机械可检（unbuilt 承载可行）。

## 附 C. v3 修订制作证据（ER 闭合轮，2026-10-09，全部本轮亲验）

- **授权与范围**：Maintainer 指令 `MR-60-PR282-GOAL-CORRECTION-20261009/v1` §五/§九（ER 揭示的真实承重缺陷由责任角色按验收规则解决；最小修订不需新 Assignment）+ 主会话派发（Operating Mode=SHADOW / MAINTAINER_AUTHORIZED）；修订对象 = Packet v2 @`176d22f9eff77ffd14949c86b5f7aea5487edaf8`（文件 SHA-256 `19915a7a9a6807afe88a2c417d96e2550281f3255475543e4bf8300613d52453`，开工重算一致）；恰好一个新 commit（叠加于 v2 之上），不 push；变更范围仅 §0.2 所列三项 SF 最小回应 + 随动测试符号表/引用修正。
- **基线**：v3 开工 `git fetch origin` 后 `origin/main = fbbbd619fb0b96efbbb903916ab46dc0daed2214`（未前移，与 v2 开工一致）；worktree HEAD=`176d22f9`、`git status --porcelain` 开工时为空。
- **ER 证据亲验**：探针结果 `%TEMP%\er_probe_ip0023_d1r_results.json`（SHA-256 `d34b1b505b263f060762478bf59fd50d875bde250b2e85f362c6c421e1fbae1c`）与 `%TEMP%\er_probe_refine_results.json`（`12d63e5ffbdfb09823d5300195155a26de0c85aafc81da5dffa5638dae88c26d`）及两探针脚本（`7a4e485d89c9189325f040e292c6a4c9692569b1cd389d7c551cc80a60b3ce5a` / `7d53a372885a32998b4ab668c01a5cd7b47b86e755f58502e26a5534d4f998a0`）全文读取；E1（T6 判据逐字复算：`truncated or file-limit>0 or total-size-limit>0` 于真实 workspace 上不触发）与 E2（`".txt" in ws.extensions == False`、requirements.txt 计入 `unsupported-extension`）断言与输出逐项核对。ER Record 本体（`ERR-60-IP-0023-D1R-2026-10-09-v1`）由主会话另存、本轮未亲读（如实声明；处置依派发要点 + 探针证据独立可核）。
- **冻结面源码亲验（@fbbbd619，只读，SF 事实基座）**：`DEFAULT_EXTENSIONS` 恰 37 项、不含 .txt/.cfg/.mod/.xml（含 .toml/.json/.yml/.py）；构造器 `extensions=(extensions or DEFAULT_EXTENSIONS)`（or 替换）与 `ignored_directories=DEFAULT_IGNORED_DIRECTORIES ∪ 入参`（恒并集）；`inventory()` 的 `truncated=True` 仅在 file-limit/total-size-limit 跳过计数处置位；`_manifest_candidates` raw `os.listdir` 名集匹配、无扩展过滤；跳过原因词表恰 10 键（§3.3）。
- **本轮未执行**：产品代码/测试/schema 修改、冻结（D2 另行 Assignment）、全量产品测试重跑（基线锚沿用 §3.4）、远端推送。

## 附 D. v4 修订制作证据（D1F 收口轮，2026-10-09，全部本轮亲验）

- **授权与范围**：Maintainer 指令 `MR-60-PR282-FINALIZATION-20261009/v1`（§四 五裁定 + §五 角色链 + §六 测试计划）+ Coordinator Assignment `ASSIGN-60-CLOSURE-A-PKT-D1F_v1`（SHA-256 `2774bd4333c3974fb6369e7f9492bb3a6bf0e46ad9233d93a541aa5bfa2ebf8a`，读取前重算一致，D1F 唯一任务合同）+ 主会话派发（Operating Mode=SHADOW / MAINTAINER_AUTHORIZED）；修订对象 = Packet v3 @`d55a9f298e88dd5a656437e10cc93c64cd69ad9d`（文件 SHA-256 `1b07cc65c9855d05fa3361c5953a73f8ebd66069ac37898e5b58704605e427cf`，开工 `git show d55a9f29:…` 重算一致）；恰好一个新 commit（叠加于 v3 之上），不 push（派发指令；Assignment 允许推送以 Coordinator 后续指令为准）；变更范围 = P60-V3-01..05 全部五项（§0.3）+ T 节测试计划修订（#21/#24/#42/#54 重写 + #55-#63 增补）+ 要件随动（DI-023..027/§3.6/§4.3.1/§5.x/§7/§8/§11/§12/§13）。
- **基线（D1F 开工亲验）**：`git fetch origin` 后 `origin/main = fbbbd619fb0b96efbbb903916ab46dc0daed2214`（未前移，与 D1R/v3 开工一致）；worktree `D:/BaseAIProject/LIMA-60-closure-a-pv-wt`（分支 `codex/ip-0023-monorepo-packet`）HEAD=`d55a9f29…`、开工 `git status --porcelain` 为空；`git diff --name-only fbbbd619...HEAD` 恰为本文档一个文件（docs-only——本 worktree 产品代码与归档 baseline-runtime（`_review_base_sha.txt` 校验 fbbbd619）逐字节同源，离线探针以此为准）。
- **输入 SHA-256 重算一致（D1F Acceptance 第 8 条，全部亲验）**：D1F Assignment `2774bd43…ebf8a`、FINALIZATION_BODY `02133d0978e4b08389af3c7139541bbd4cb997e177804cb6faa4176fcd8402e3`、配套规划 `75798f8b…8e95`、MDR-FINALIZATION `9cd79d20…41c`、Packet v3 `1b07cc65…27cf`、ERR 本体 `4fac90ee…0e3d`（**本轮全文亲读**——96 行，SF-1/2/3 与六主张反证表核对）、ERR addendum-1 `c9402a9d…88a8`（亲读，L42"声明承载而非消除"判定核对）、D1R Assignment `30a0e919…c040a`、D1 Assignment `5a118ea9…73b82`。
- **冻结面源码亲验（@fbbbd619 同源 worktree，只读，零目标执行）**：`inventory.py` L392-417（`_manifest_candidates` raw os.listdir 三入口事实）+ L147-150（`_MANIFEST_EXACT_NAMES`）；`ram_schema.py` L74-92/L236-258/L268-377/L379-452/L454-486/L495-505/L551-595（§3.1 v4 增补段全部行号锚）；`semantic_prioritizer.py` L80/L221-246/L258-268/L344-345/L439-470/L623-660（三口径+域校验+两冻结 digest 形）；`contracts/profile.py` L1238-1254（bytes 入参）；`workspace.py` L11+/L112-137（DEFAULT_EXTENSIONS 37 项、五参数构造器）。
- **离线消费探针（P60-V3-02 D1 设计证据，DI-027）**：脚本 `%TEMP%\ip0023_d1f_consumption_probe.py`（SHA-256 `74a346184228f2d3352667c6500c6cf97520d1dea781bb6add2b575f130d0882`）、结果 `%TEMP%\ip0023_d1f_consumption_probe_results.json`（SHA-256 `b60447e0709b465a332f9d71ebfc8c2171fc2ea671a72e8ca0037858408b76ce`；12/12 过，exit 0）。对象 = 既有 golden `tests/audit/fixtures/golden_matrix/golden/application.json`（SHA-256 `23c0f3ce0ea44dbccfc5b6a9cedefc8badc968eb4ea268b6436bd8e4c1240ceb`）+ 合成样本（系统临时目录、经公共 API `build_repository_profile`/`encode_profile_envelope` 构建，零目标执行零网络零模型）。**指令内嵌 API 基准代码逐字实跑**其"已有部分"：validate 通过；facts 摘要复算 `84fec0134159f33e…`==identity 槽；semantic 摘要复算 `8aecae4e63146bfc…`==identity 槽；wire digest 复算 `b92a2aa40fc9b4c9…`==identity.wire_digest 且 **≠ ram_facts_digest**；顶层无 coverage_gaps（ram n=0/semantic n=1=SEMANTIC_MODEL_OFF）；`execution_required_from_gaps` 复算 `{'required': False, 'trigger_gap_codes': []}`==顶层；篡改 ranked score → ContractError；OFF 永不触发、全集外码 ValueError；`decode_profile_envelope(bytes)` 成功（content_digest `913d8d6ea58ee291…` 公共字段）、JSON 对象（非 bytes）被拒。**定性：以上全部为"已有行为实测"（既有 golden+既有公共 API），非"graph 产品实测"——真实 graph payload 的端到端消费属 D2 绑定（本 Packet 不声明未实现的 graph 已可调用）。**
- **本轮未执行**：产品代码/测试/schema 修改、冻结（D2 另行 Assignment——指令 §二明禁）、全量产品测试重跑（基线锚沿用 §3.4；指令 §Acceptance 8 明示不重跑）、远端推送、台账/PR 正文/登记文件修改（归主会话/Coordinator）。

## 附 E. v5 修订制作证据（D1X 跨层修订轮，2026-10-10，全部本轮亲验）

- **授权与范围**：Maintainer 指令 `MR-60-PR282-CROSS-LAYER-CORRECTION-20261010/v1`（正文 `authorization/v5/CROSS_LAYER_BODY.md`，SHA-256 `5a584cf5d24e6382ad174ca7336c427ddff101d96f1cce993adad6a867d56213`，读取前重算一致；§四 CL-01..05 + §六 机械收尾）+ Coordinator Assignment `ASSIGN-60-CLOSURE-A-PKT-D1X_v1`（SHA-256 `86bfc69880836c028444d428f605ca4666a28259648f472746e0085fc40e0025`，读取前重算一致，D1X 唯一任务合同；Mechanical Test Correction Allowance=NOT_ALLOWED）+ 主会话派发（Operating Mode=SHADOW / MAINTAINER_AUTHORIZED）；修订对象 = Packet v4.1 @`af916ac3dad7e7176b3724469323d9c64eddacff`（文件 SHA-256 `05d71103797a350b2dc3785c9e7da6d568ae2a3edad53964ed8cb3d1f33cd040`，开工重算一致）；恰好一个新 commit（叠加于 v4.1 之上），不 push（派发指令；Assignment 允许的推送归 Coordinator readiness 后主会话统一执行）；变更范围 = CL-01..05 全部五项（§0.4）+ 机械收尾第 1-4 条 + 要件随动（DI-028..032/§3.7/§4.3.1-4.3.2/§5.1.7-5.1.8/§5.2.1/§5.2.4/§5.4.1/§5.4.3/§5.4.4/§5.4.5/§5.4.6/§5.4.7/§5.4.8/§5.5/§5.6.3/§5.7/§5.9/§6/§7/§8/§11/§12/§13）。
- **基线（D1X 开工亲验）**：`git fetch origin` 后 `origin/main = fbbbd619fb0b96efbbb903916ab46dc0daed2214`（未前移，与 v4/v4.1 开工一致）；worktree `D:/BaseAIProject/LIMA-60-closure-a-pv-wt`（分支 `codex/ip-0023-monorepo-packet`）HEAD=`af916ac3…`、开工 `git status --porcelain` 为空；`git diff --name-only fbbbd619...af916ac3` 恰为本文档一个文件（docs-only；v5 修订后交付前复核保持）。
- **输入 SHA-256 重算一致（D1X Acceptance"必须运行（开工时）"，全部亲验）**：指令正文 `5a584cf5…6213`、规划 v41 `0d7f79a5…91f`、MDR-CROSS-LAYER `412e82e7…e680`、探针脚本 `883770c7…35ea`、探针结果（原锚定件）`a7c73a58…043`、D1F Assignment `2774bd43…bf8a`、D1R `30a0e919…c040a`、D1 `5a118ea9…3b82`、前轮探针结果 `90f3d975…b8a4`、Assignment D1X `86bfc698…0025`、Packet v4.1 `05d71103…d040`。
- **冻结面源码锚（沿用 Coordinator 亲读 @fbbbd619，本轮经 Assignment §P 衔接事实消费；主仓根检出 HEAD=`202529d0…` 非 main 基线，未用作推断）**：`workspace.py` L202-256；`inventory.py` L392-417/L603-649/L714-735/L1085-1094；`ram.py` L429/L465-469；`semantic_prioritizer.py` L221-246/L439-470。
- **反例探针交付前复跑（D1X Acceptance"必须运行（交付前）"）**：`python output/issue60-pr282-v41-review-2026-10-10/review_probe.py`（主仓根离线，exit=0）；行为字段与锚定件 `a7c73a58…` 逐项一致——API-IO `slice_files=1/actual_file_reads=5/packet_rescan_bound=1`、API-META `W2_manifest_candidates=[]`+旧 Profile flask/pip、API-POOL `cumulative_precharge=[1684,2048,3732]/cumulative_exceeds_caller=[true,true,true]/any_per_call_guard_violated=false`、RULE-COMPLETE `dependencies_complete=true` 且两行同真、RULE-COUNT `V7_equality_passes=false`、`workspace_has_fingerprint=false`（夹具目录按预期变化 `inert-fixtures-p4ijzq_2`，比较行为字段不比较全字节哈希）；本轮复跑结果自 SHA-256 `3a51e33596d05d3f7c368b5818a77abb07166f8a14b293bd8d25e2228099b159`。**定性：该探针复现的是 v4.1 字面规则与冻结公共 API 的旧行为——五反例在 v4.1 规则下仍可达（证据有效），在 v5 规则下不可达（见下条参考模拟）**。
- **新参考模拟探针（"参考模拟"，DI-031 补充；审阅临时区，不入 commit）**：脚本 `%TEMP%\ip0023_d1x_reference_probe.py`（SHA-256 `16d305d8dabfd1fb1c09770cb4ed25a08833c775e613ff216cb137197d10d4c3`）与结果 `%TEMP%\ip0023_d1x_reference_probe_results.json`（`dffcd0bb554accfa61559daea0e4c787f300b460253fca4841d4ca26f7811029`；5/5 组全过，exit 0，两次运行结果哈希一致=确定性）。**边界声明：纯 v5 字面规则推演（SIM-CL01..05），零目标执行、零网络、零模型、夹具全为脚本内合成数据，不冒充产品验收**。覆盖：SIM-CL01 四丢失变体（数量帽/字节帽/读失败/解码失败）T8 触发+complete=False+唯一"证据不足"+对账相等、政策键豁免；SIM-CL02 双清单过滤恢复自身 manifest 候选与 flask/pip、S1 切片不动、父子隔离；SIM-CL03 min 三池（默认/小/大/显式四类对照）、小 caller 截止 212/256/468 ≤ 1000/500/1500、v4.1 的 1684/2048/3732 调度复现为对照；SIM-CL04 尝试口径账（API-IO 三段链 5=5×1、全链 7 ≤ 7×1+0+0；含 unbuilt 前预检与失败尝试计数的双组件/失败变体 ≤ 保守上界）；SIM-CL05 守恒式六组合（overlap/协作/秘密剪枝/多 manifest 同锚点/T1 溢出/严格策略）+ v4.1 V7 的 1=0 复现为对照。
- **机械收尾执行记录**：①W-1 fingerprint 归属修正（§4.3.1/§5.2.1/§3.7——`RepositoryWorkspace` 无 fingerprint 属性实测为据，归属 WorkspaceInventory，零新增共享层接口）；②v4.1 头部 SF-5 表述如实化（头部版本链内 v4.1 批次描述改为"语义面/冻结面零变更；测试计划仅 #62 断言加默认调用方限定语"，v5 头部记述与正文实际 diff 一致）；③测试计划随 CL 增补（#62 恢复小预算断言并删除限定语、#63 新公式重写、#30/#61 随动、#64-#73 增补、受影响旧行同步）；④方法数口径（v5 计划 73=规划数非帽，§6 注记版本演化如实）。第 5 条（PR 正文/索引/NOW/registry/superseded 指针/ER B2 台账更正）归主会话/Coordinator，P&V 未执行——交接材料提供素材（本 Packet §0.4 CL-03 行与上游决策节的 B2 更正声明即素材）。
- **本轮未执行**：产品代码/测试/schema 修改、冻结（D2 另行 Assignment——指令 §二明禁）、全量产品测试重跑（基线锚沿用 §3.4）、远端推送（派发指令；PR #282 新 head 的推送与正文更新归 readiness 后主会话）、台账/PR 正文/登记文件修改（归主会话/Coordinator）。
