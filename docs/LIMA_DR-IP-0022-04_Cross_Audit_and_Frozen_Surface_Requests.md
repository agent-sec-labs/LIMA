# DR-IP-0022-04 — 完整契约交叉审查与集中修订（Maintainer 四项核清）

> 文档类型：Decision Record（P&V 呈报，Coordinator/Maintainer 裁定）
>
> 状态：**OPEN**（本 DR 自身记录的 v4 修订已按 Assignment 授权落 Packet；A'（建议优先）/A（备选）/B 三项**待裁定，未获批不实施**；含 XAUDIT-FIX 轮勘正——见 §4）
>
> 关联：DR-IP-0022-01/-02/-03；Packet `IP-0022-PACKET/v4`；`LIMA_IP-0022_XAUDIT_Matrices_v1.md`；Assignment `IP-0022-PV-XAUDIT/v1`（PKT-IP-0022-XAUDIT，2026-09-13）
>
> 基线：main=`30bdfaa`（行为口径）；PR head 契约底本=`3735cbe`（docs/ip-0022-packet）

## 0. 背景

Maintainer 驳回 PR #180 第二次并指令"不要只针对上一条反馈打补丁"：先两张全量矩阵、再独立证伪、再全套验证、最后一次性提交。本轮 P&V 独立复验了主会话全部五项探针（结论见矩阵一附注；其中第 2 项探针结论被勘正为**真实泄漏面**，非防御巧合）。

## 1. 已按授权落在 Packet v4 的裁定（Packet 自有范围，不需新 DR）

1. **段级检测**（核清 1）：`is_secret_shaped_path` 由 basename 扩为**路径每一段**（目录段+basename 任一命中即拒）。依据：实测敏感目录段在 main 泄漏 code_roles 与 RAM（X1/X2）。属 Packet 自有新接口（v3 定义、未冻结），升级无冻结冲突。误伤面：段级关键词族对目录名（如 `keys/`、`secrets/`）按启发式超集口径整目录排除并计数，M1' 误伤负例集补段级形态（`tokenizer/`、`keyboard/` 等不命中）。
2. **AdmissionSkip 语义定稿**（核清 2）：
   - **跨命中去重**：同一 repo-relative path 在同一 build result 内（entrypoint 过滤 + code role 过滤）只计一次 `sensitive-filename`；Profile 与 RAM 两个 build result 各自独立计数（各自公开 gap 通道，语义=各自候选集的拒绝数）。
   - **计数先于 gap 生成**：不变量——`admission_skips`/`inventory.skipped` 的写入必须发生在 `_skip_reason_gaps`（Profile）/`_coverage_gaps`（RAM）构造之前；D2 冻结测试以断言 "typed gap 存在且 count 正确" 承载（X5-1/X5-2）。
   - **RAM-only 路径**：不经 Profile 单独构建 RAM 时同样过滤 + `RamFactsBuildResult.admission_skips` 留痕（X5-2；记录不含原文件名，无 `path` 字段）。
   - **扫描内序号确定性来源**：`AdmissionSkipRecord.index` = 该 build 的**过滤前 sorted 候选全序枚举下标**（Profile：`sorted(evidence)` 键序；RAM：`sorted(item.path for .py)` 序），0 基，与 `candidate_id` 的 ordinal 无关（candidate_id 为 Do-not-touch）。同输入同序号，可复现。
3. **wire path 规则强化**（核清 3 前半）：v3 path 检查对 #58 `_validated_path` 存在两处**弱于**（空段/点段、控制字符），v4 补齐（逐条对照见矩阵二附注）。属 Packet v3 自有新检查的强化，无冻结冲突。
4. **MINIMAL_PAYLOAD 五摘要定稿**（核清 4）：v3 "prompt/model 槽位 D2 定稿" 的悬念定稿为**五槽全真值**（含 `prompt_digest=digest(默认模板)`）；独立全零占位拒绝负例 G2-2 保留；旧负例"预期错误"核对表落矩阵文档（14 类全部先于摘要层失败，无误伤）。

## 2. 冻结面变更请求（待裁定，未获批前不实施、不暗改）

### DR-04-A'：manifest 候选准入过滤（**建议优先项**，Coordinator 证伪产出的最小替代）

- **方案**：在 `_manifest_candidates`/`_load_manifests` 的 manifest 命名判定后，对整条候选路径执行段级 `is_secret_shaped_path`；命中即跳过该 manifest（不解析、不进 gap）并计入 `sensitive-filename` skip 通道（复用 §3.4 词汇表与 §3.3 留痕）。
- **统一闭合 I3/I4a/I5 三面**（parse-error detail / read-failure detail / 超限 detail 均不再有机会携带敏感命名路径——候选在 detail 生成点之前被剔除）。
- **零冻结面触碰**：不改 IP-0016 detail 模板、零测试锚定修订、零 golden 影响（fixtures golden 对 `manifest=` 模板零锚定，Coordinator 全树 grep 亲验）；只改 `inventory.py`（已在 Packet Modify 集）。
- **取舍（如实声明）**：敏感命名 manifest 整体不解析——其 languages/package_managers/frameworks 声明随之丢失，与敏感命名代码文件同口径（宁可少声明不泄漏）；skip 计数使损失可观测。
- **呈 Maintainer 裁定**。

### DR-04-A：manifest gap detail 模板脱敏（备选，触碰 IP-0016 冻结面）

- **证据**：main 实测（probe P2/P2e/P2f、X3-1/X3-2 RED）——`MANIFEST_PARSE_ERROR` detail=`manifest={relative_path}; error=<ErrType>` 与 `BUDGET_EXHAUSTED` manifest 超限 detail 同模板，把**含敏感目录段/敏感 basename 的完整仓库相对路径**写入公开 Profile coverage_gaps（→ to_dict → wire）。主会话"未泄漏"结论系 FAKESECRET 哨钉口径假阴性（其样本 `secrets/pyproject.toml` 的目录段 "secrets" 实际已公开）。
- **请求**：授权将 `_record_manifest_error` 与 manifest 超限分支的 detail 改为不携带原文路径（建议：`manifest=<redacted:sensitive-shaped>` 命中启发式时替换，未命中保留原文；或统一 `manifest-index=<i>; error=<ErrType>`）。
- **影响面（Coordinator 全树 grep 亲验的完整清单）**：`manifest=` detail 模板被三处冻结测试锚定——`tests/audit/test_budget_exhaustion_e2e.py`、`tests/audit/test_fr05_gap_encoding.py`、`tests/evidence_privacy/test_models.py`；fixtures golden **零锚定**。获批需同步修订上述三处断言。
- **与 A' 的关系**：A' 为零冻结面触碰的最小替代、建议优先；A 保留为备选（若 Maintainer 认为敏感命名 manifest 的声明信息不应整体丢弃，可选 A 的精准脱敏）。两者均呈 Maintainer 裁定，未获批前不实施、不暗改。
- **不批的影响**：R-1 残余风险维持，NFR-01 维持 PARTIAL（现有口径本就如此记账，不额外恶化）。

### DR-04-B：wire 校验序列扩第七项 candidate_id 一致性（触碰 IP-0021 冻结校验序列）

- **证据**：`_result_digest` payload 的 `ranked` 子集**不含 kind/path/symbol**（semantic_prioritizer.py:640-660 亲验）——只改 `semantic.ranked[i].kind/path/symbol` 而不动 candidate_id 时，ram/config/result/model/wire 五摘要**全部保持有效**，main 与 v3 均接受（X4-1/2/3 RED 复现）。
- **请求**：授权在 `validate_ram_wire_payload` 追加第七项（六步序列之后、与摘要检查同段）：对每个 ranked item 校验 `candidate_id ≡ f"{kind}:{path}:{symbol if symbol is not None else '-'}#{ordinal}"`——实现为 prefix=`f"{kind}:{path}:"` 前缀匹配 + `tail.rsplit("#",1)` 得 (symbol 槽, 非负数字 ordinal) 等值比对。ordinal ≥ 0（real-chain 实测 `#0` 起）。golden/real-chain 零误伤已证（矩阵二附注）；IP-0021 冻结负例 `candidate_id_pattern_violation` 不受影响（X4-0 锚）。
- **不批的影响**：wire 的 kind/path/symbol 三字段保持"仅结构校验 + path 规则"绑定，篡改不可检出（R-9 残余风险，已入矩阵二）。

## 3. 范围外事项（如实声明，不提请变更）

- rationale/frameworks/model_id 自由文本面（矩阵一 I9、残余风险 R-2）；防恶意重签（R-3）；直调内部 API（R-4）；启发式非穷尽（R-5）；wire path 长度 cap 宽度差异（R-6）；`DEFAULT_IGNORED_DIRECTORIES` 不含敏感目录名（R-8，防御位置按 §12.3 否决路线留在准入层）。
- requirements* manifest 无内容校验是结构性事实（非防御承诺），其内容关键词面记 I9/I4b。

## 4. 验证证据（摘要，全文见 Packet v4 §9 与矩阵文档）

- RED D1'''：`_red_proof` 34 failed（v3 的 23 例 + 新 X 系 11 例）+ 3 锚通过。**勘正（PKT-IP-0022-XAUDIT-FIX，Coordinator 独立证伪）**：X3-2 首版存在两处 arrange 缺陷（不存在的 kwarg `profile_budgets`；`GHP_BASENAME[12:]` 切片把 `ghp_` 前缀切失、敏感子串从未进入断言面）——首版"无 arrange 型失败"表述不实。已修正为 `options=ProfileInventoryOptions(budgets=ProfileBudgets(manifest_max_bytes=1))` + 完整 token 文件名，重跑后 X3-2 失败签名=目标缺失型（`manifest budget detail carries a secret-shaped basename: ['manifest=requirements-ghp_aaa….txt; bytes=8; limit=1']`，与 Coordinator 独立复现一致），全量恢复 34 failed / 3 passed。
- 回归：`tests/audit tests/contracts` 801 passed；golden matrix 15 passed（@main 等同代码；FIX 轮复跑记录在案）。
- goldens 零命中：v4 段级启发式对 fixtures 全量 JSON 路径值与 tests 源文件路径零命中；新 wire 检查（段级 path 规则 + candidate_id 一致性）对 real-chain payload 零违例（3 repo 形态）。
- 双平台：Windows 本机 + PI-DR6 预演（见 Packet v4 §9.4）。

## 5. 裁定请求

请 Coordinator/Maintainer 对 §2 **A'（建议优先）/ A（备选）** 与 **B** 作出 获批/否决 裁定；B 维持建议获批（必要且充分已证：`_result_digest` 不含 kind/path/symbol 的绑定缺口 + real-chain 零误伤）。获批则并入 Packet v4 对应条目的 mandatory 集（当前标【DR-04-A/B】），否决则维持残余风险记账。其余 §1 项已按 Assignment 授权落 Packet v4，无需另行裁定。
