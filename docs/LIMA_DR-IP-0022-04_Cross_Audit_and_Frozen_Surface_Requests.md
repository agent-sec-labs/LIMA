# DR-IP-0022-04 — 完整契约交叉审查与集中修订（Maintainer 四项核清 + R4 三问题修订）

> 文档类型：Decision Record（P&V 呈报，Coordinator/Maintainer 裁定）
>
> 状态：**OPEN（R4 修订版）**——§1 已按授权落 Packet v4/v5；§2 三项中 **A' 已撤回（否决记录在案）**、**A 定稿版** 与 **B 重写版** 均**待重审**，未获批不实施；含 XAUDIT-FIX 与 R4 两轮勘正（§4）
>
> 关联：DR-IP-0022-01/-02/-03；Packet `IP-0022-PACKET/v5`；`LIMA_IP-0022_XAUDIT_Matrices_v1.md`（R4 修订）；Assignment `IP-0022-PV-XAUDIT/v1`、`IP-0022-PV-R4/v1`（PKT-IP-0022-R4，2026-09-13）
>
> 基线：main=`30bdfaa`（行为口径）；分支 head（lima/** 与 main 等同）
>
> R4 修订依据：Maintainer 复审三问题（①B 碰撞缺陷 ②RED 证据不可复现 ③矩阵漏 entrypoints.symbol 出口）+ 已定方向（A' 撤回 / A 定稿 / B 重写待审）。

## 0. 背景

Maintainer 驳回 PR #180 第二次并指令"不要只针对上一条反馈打补丁"：先两张全量矩阵、再独立证伪、再全套验证、最后一次性提交。XAUDIT 轮完成矩阵与 D1''' RED；**R4 轮**：Maintainer 复审认定 PR 不能合并、本 DR 现稿不能整体批准，指出三问题并定三项 DR 方向，本版为一次性修订。

## 1. 已按授权落在 Packet 的裁定（Packet 自有范围，不需新 DR）

1. **段级检测**（核清 1）：`is_secret_shaped_path` 由 basename 扩为**路径每一段**（目录段+basename 任一命中即拒）。依据：实测敏感目录段在 main 泄漏 code_roles 与 RAM（X1/X2）。属 Packet 自有新接口（v3 定义、未冻结），升级无冻结冲突。误伤面：段级关键词族对目录名（如 `keys/`、`secrets/`）按启发式超集口径整目录排除并计数，M1' 误伤负例集补段级形态（`tokenizer/`、`keyboard/` 等不命中）。
2. **AdmissionSkip 语义定稿**（核清 2）：
   - **跨命中去重**：同一 repo-relative path 在同一 build result 内（entrypoint 过滤 + code role 过滤）只计一次 `sensitive-filename`；Profile 与 RAM 两个 build result 各自独立计数（各自公开 gap 通道，语义=各自候选集的拒绝数）。v5 补：script **名称**过滤的去重键 = script 名称本身（名称非路径，独立于 path 去重集）。
   - **计数先于 gap 生成**：不变量——`admission_skips`/`inventory.skipped` 的写入必须发生在 `_skip_reason_gaps`（Profile）/`_coverage_gaps`（RAM）构造之前；D2 冻结测试以断言 "typed gap 存在且 count 正确" 承载（X5-1/X5-2；v5 起 X5-2 同时断言**公开 coverage_gaps 携带 `reason=sensitive-filename; count=N`**，不再只查内部 skip 记录）。
   - **RAM-only 路径**：不经 Profile 单独构建 RAM 时同样过滤 + `RamFactsBuildResult.admission_skips` 留痕（X5-2；记录不含原文件名，无 `path` 字段）。
   - **扫描内序号确定性来源**：`AdmissionSkipRecord.index` = 被过滤候选列表**自身的过滤前 sorted 全序枚举下标**（Profile code roles：`sorted(evidence)` 键序；Profile script 名称（v5）：`sorted(summary.scripts)` 键序；RAM：`sorted(item.path for .py)` 序），0 基，与 `candidate_id` 的 ordinal 无关（candidate_id 为 Do-not-touch）。同输入同序号，可复现。**A' 撤回波及核查（R4）**：三处枚举体均为真实候选列表，定义成立；A' 所犯"对不在 inventory 的 manifest 候选套用 inventory 序号"失效模式已被 §2-A' 撤回消除（矩阵 R4 附注 2）。
3. **wire path 规则强化**（核清 3 前半）：v3 path 检查对 #58 `_validated_path` 存在两处**弱于**（空段/点段、控制字符），v4 补齐（逐条对照见矩阵二附注）。属 Packet v3 自有新检查的强化，无冻结冲突。
4. **MINIMAL_PAYLOAD 五摘要定稿**（核清 4）：v3 "prompt/model 槽位 D2 定稿" 的悬念定稿为**五槽全真值**（含 `prompt_digest=digest(默认模板)`）；独立全零占位拒绝负例 G2-2 保留；旧负例"预期错误"核对表落矩阵文档（14 类全部先于摘要层失败，无误伤）。
5. **script 名称准入过滤（R4 问题 3，v5 新增，Packet 自有范围不需新 DR）**：manifest scripts 键为任意 TOML 字符串（inventory.py:360-365 仅 isinstance 校验），敏感命名名（`token_FAKESECRET123`）原文进入 `entrypoints[i].symbol`（S1/S4/S8，probe P-R4-2 亲证；解析目标良性，path 面过滤不可达）。处置=**纳入 IP-0022 修复**：`_build_entrypoints` scripts 分支对名称执行同一启发式（单段语义），命中不入 entrypoints、计 `sensitive-filename` skip（与文件名同口径）；负例 X7-1/X7-2。依据：与敏感命名文件名同威胁面、同防御口径，且无冻结面触碰。

## 2. 冻结面变更请求（A'/A/B）

### DR-04-A'：manifest 候选准入过滤 —— **撤回（R4，Maintainer 否决）**

- **否决理由（如实记录）**：(i) 敏感命名 manifest 整体不解析 ⇒ 其 languages/package_managers/frameworks 声明被丢弃（信息损失超出必要）；(ii) 其 skip 序号设计依赖 `sorted(evidence)` 枚举，而 requirements*.txt 等通配 manifest 不在默认 inventory extensions、不在该枚举内 ⇒ **序号定义失效**；(iii) 综合后 A' 的"零冻结面触碰"优势不足以抵消上述缺陷。
- **撤回落位**：Packet v5 §3.2 删除第四过滤点；X3-1/X3-2 改锚 **DR-04-A 定稿版**；序号定义波及核查见 §1.2 与矩阵 R4 附注 2（Packet §3.3 不受影响）。A' 不再呈请裁定。

### DR-04-A：manifest gap detail 稳定标识 —— **定稿版（待重审）**

- **证据**：main 实测（probe P2/P2e/P2f、X3-1/X3-2 RED）——`MANIFEST_PARSE_ERROR` detail=`manifest={relative_path}; error=<ErrType>` 与 `BUDGET_EXHAUSTED` manifest 超限 detail=`manifest={relative_path}; bytes=…; limit=…` 同携路径模板，把**含敏感目录段/敏感 basename 的完整仓库相对路径**写入公开 Profile coverage_gaps（→ to_dict → wire）。主会话"未泄漏"结论系 FAKESECRET 哨钉口径假阴性（其样本 `secrets/pyproject.toml` 的目录段 "secrets" 实际已公开）。
- **定稿设计（R4，满足三约束：不含原路径/文件名、确定性可重放、不依赖被否决序号源）**：
  - detail 模板改为 **`manifest-index=<i>; error=<ErrType>`**（解析失败/读取失败共用）与 **`manifest-index=<i>; bytes=<n>; limit=<m>`**（超限）；`<i>` = 该 manifest 在 `_manifest_candidates(workspace)` **sorted 候选枚举中的 0 基下标**（inventory.py:265-289：root 固定名+requirements 通配，再 level-1 目录同规则，整体 `sorted()`——requirements*.txt 天然在内，与被否决的 `sorted(evidence)` 序号源无关）。
  - 覆盖三类：解析失败（TOMLDecodeError/JSONDecodeError/ParsingError 等）、读取失败（OSError/UnicodeDecodeError）、超限（manifest_max_bytes / manifest 文件数上限触发处如引用 relative_path 一并替换）。
  - **取舍（如实声明）**：`<i>` 是**同树确定性标识**而非跨版本稳定内容标识——仓库树变更（增删候选）会使下标漂移；gap detail 的用途是诊断提示而非内容寻址，此取舍可接受；如需跨版本稳定性须引入内容派生标识（被本设计有意回避，见下）。
  - **为何不用 kind+短 hash**：R1 否决 `sha256(basename)[:8]` 的理由之一"易猜测"在 manifest 公开 detail 场景的威胁模型确有不同（hash 不含原文、preimage 不可行），但短 hash 仍构成**路径确认预言机**（外部消费者可对猜测路径离线比对确认，如确认 `secrets/pyproject.toml` 的存在性）——ordinal 无此面、且实现更简，无需为绕开 R1 否决理由另作论证；故定稿取 ordinal，不提请 hash 变体。
- **锚定清单（R4 勘误后）**：DR-04 v1 称"三处冻结测试锚定"不准确——`tests/evidence_privacy/test_models.py` 的 `manifest=`（:118）是 `SanitizedPayload` 字段关键字实参，**不锚定 detail 模板**（R4 亲验）。真实锚定集 = **2 文件 4 断言**，逐处修订形式：
  | 文件:行 | 现断言 | 修订后 |
  |---|---|---|
  | tests/audit/test_fr05_gap_encoding.py:103 | `("MANIFEST_PARSE_ERROR", "manifest=pyproject.toml; error=TOMLDecodeError")` | `("MANIFEST_PARSE_ERROR", "manifest-index=0; error=TOMLDecodeError")`（唯一 manifest 候选 → 0） |
  | tests/audit/test_fr05_gap_encoding.py:110 | `("MANIFEST_PARSE_ERROR", "manifest=package.json; error=JSONDecodeError")` | `("MANIFEST_PARSE_ERROR", "manifest-index=0; error=JSONDecodeError")` |
  | tests/audit/test_fr05_gap_encoding.py:121 | `("MANIFEST_PARSE_ERROR", "manifest=pkg/pyproject.toml; error=TOMLDecodeError")` | `("MANIFEST_PARSE_ERROR", "manifest-index=0; error=TOMLDecodeError")`（该用例候选集仅此一个 manifest） |
  | tests/audit/test_budget_exhaustion_e2e.py:87 | `f"manifest=pyproject.toml; bytes={…}; limit=16"` | `f"manifest-index=0; bytes={…}; limit=16"` |
  fixtures golden 零锚定（Coordinator 全树 grep 亲验，维持）。
- **负例**：X3-1（解析/读取失败 detail 无原路径且含 `manifest-index=<i>; error=`）、X3-2（超限 detail 无敏感 basename）——已入库 RED（D1''''），基线失败签名=泄漏型目标缺失。
- **不批的影响**：R-1 残余风险维持，NFR-01 维持 PARTIAL。

### DR-04-B：wire 校验序列扩第七项 candidate_id 一致性 —— **重写版（待重审）**

- **证据（v1 维持）**：`_result_digest` payload 的 `ranked` 子集**不含 kind/path/symbol**（semantic_prioritizer.py:640-660 亲验）——只改 `semantic.ranked[i].kind/path/symbol` 而不动 candidate_id 时，ram/config/result/model/wire 五摘要**全部保持有效**，main 与 v3 均接受（X4-1/2/3 RED 复现）。
- **碰撞缺陷（R4 问题 1，v1 公式作废）**：`candidate_id()` 规则 `symbol or '-'`（prioritizer:336）使 `symbol=None` 与 `symbol='-'` 生成**同一 ID**——互换二者既不改变 ID 也不改变任何摘要，v1 公式的"三字段全绑定"不成立。#58 契约接受 `symbol='-'`（AttackSurfaceEntry 构造成功，Maintainer 亲验）。
- **生产链定源（R4 逐一定源，probe P-R4-1/P-R4-3 实证）**：ranked symbol 的全部生产源 = RAM 五清单——entrypoints：`ast.FunctionDef.name`（Python 标识符，不可能含 `-`）；external_sources：包裹函数名（标识符）或 None；trust_boundaries/sensitive_sinks：None；unresolved_edges：`_call_name()`（点分标识符）或哨兵 `"<dynamic-call>"`。**唯一能产出字面 `'-'` 的生产路径是 Profile `_build_entrypoints` 的 script 名**（任意 TOML 键；P-R4-1 实测 `[project.scripts] "-"=...` → `entrypoints.symbol='-'`），但 Profile entrypoints **不是** RAM/semantic ranked 的输入（ranked 仅由 facts 五清单派生，prioritizer:525-585）⇒ **ranked 生产链永不产出 `symbol='-'` 字面值**。
- **请求（重写版公式）**：授权在 `validate_ram_wire_payload` 追加第七项（六步序列之后、与摘要检查同段），对每个 `semantic.ranked[i]`：
  1. **消歧前置规则**：`symbol == "-"` 字面值 → 拒绝（`ContractError(INVALID_FIELD_VALUE, "$.semantic.ranked[i].symbol")`）——wire 序列化中 candidate_id 槽位 `'-'` **严格且唯一**对应 `symbol is None`（序列化值 `null`）；
  2. **一致性比对**：`candidate_id ≡ f"{kind}:{path}:{symbol if symbol is not None else '-'}#{ordinal}"`——prefix=`f"{kind}:{path}:"` 前缀匹配 + `tail.rsplit("#",1)` 得（symbol 槽 = symbol 或 `'-'`，非负数字 ordinal）等值比对；违例 `$.semantic.ranked[i].candidate_id`。
  - 安全性：生产链定源（上）证明拒绝 `'-'` 字面值零误伤（golden/real-chain 复核维持：real-chain payload 零 `symbol=='-'`）；IP-0021 冻结负例 `candidate_id_pattern_violation` 不受影响（X4-0 锚）。
  - 负例：X4-1/2/3（三字段一致性）+ **X4-7（新）**：`symbol` None→`'-'` 互换篡改（candidate_id 与五摘要均不变）必须被拒——RED 已证 main 接受（probe P-R4-4）。
  - 若裁定改为 candidate_id 生成公式本身去歧（如换槽位哨兵），则属 IP-0019 冻结面重冻结（大 DR），本 DR 不请求该变更。
- **不批的影响**：wire 的 kind/path/symbol 三字段保持"仅结构校验 + path 规则"绑定，含 None↔`'-'` 互换在内的篡改不可检出（R-9 残余风险，矩阵二）。

## 3. 范围外事项（如实声明，不提请变更）

- rationale/frameworks/model_id 自由文本面（矩阵一 I9、残余风险 R-2）；防恶意重签（R-3）；直调内部 API（R-4）；启发式非穷尽（R-5，含 Unicode 同形变体）；wire path 长度 cap 宽度差异（R-6）；`DEFAULT_IGNORED_DIRECTORIES` 不含敏感目录名（R-8，防御位置留在准入层）。
- Profile 层 `symbol='-'` 良性字面值（#58 契约面）：不修（无 candidate_id 域、非敏感形态，I13n 记录性事实）。
- requirements* manifest 无内容校验是结构性事实（非防御承诺），其内容关键词面记 I9/I4b。
- DR-03/DR-02 状态链：R4 核对无波及（矩阵 R4 附注 3），状态不变。

## 4. 验证证据（摘要，全文见 Packet v4 §9 / v5 §9.5 与矩阵文档）

- RED D1''''（R4）：`_red_proof` **37 failed / 3 passed**（v3 的 23 例 + X 系 14 例）+ 3 锚通过。新增签名：X4-7 `Exception not raised`（None↔`'-'` 翻转被接受）；X7-1 敏感 script 名原文入 entrypoints.symbol；X7-2 skip gap 缺失。X3-2 XAUDIT-FIX 勘正维持有效。
- **可复现性（R4 问题 2 处置）**：v3 的 23 用例文件此前未提交，本轮全量底稿入库（`_red_proof/` 4 文件）；**干净 checkout**（`git archive <head>` 解包空目录）原样复跑：37 failed / 3 passed、801 passed、golden 15 passed，与工作树逐项一致。`_red_proof` 性质与管理办法见 Packet v5 §4a（D2 冻结底稿、不在 pytest testpaths、CI 不执行、D2 迁移后归档）。
- 回归：`tests/audit tests/contracts` 801 passed；golden matrix 15 passed。
- goldens 零命中与 real-chain 零误伤：v4 结论维持；v5 新检查（script 名启发式、`symbol=='-'` 拒绝）对 real-chain payload 与 fixtures 零命中/零违例（P-R4-3 源追踪 + MINIMAL_PAYLOAD 复核）。
- 双平台：Windows 本机 + PI-DR6 预演（Packet v4 §9.4）维持；R4 增量用例为纯字符串/纯构造断言，平台无关。

## 5. 裁定请求

请 Coordinator/Maintainer 对 §2 **A（定稿版：`manifest-index` 稳定标识 + 2 文件 4 断言锚定修订清单）** 与 **B（重写版：`'-'` 槽位消歧 + 一致性公式 + X4-7）** 作出 获批/否决 裁定（A' 已撤回，不再呈请）。获批则并入 Packet v5 对应条目 mandatory 集（当前标【DR-04-A/B】），否决则维持残余风险记账（R-1 / R-9）。§1 各项（含 v5 script 名称准入）已按 Assignment 授权落 Packet，无需另行裁定。
