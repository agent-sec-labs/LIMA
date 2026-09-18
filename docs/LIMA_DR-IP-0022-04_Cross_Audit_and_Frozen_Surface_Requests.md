# DR-IP-0022-04 — 完整契约交叉审查与集中修订（Maintainer 四项核清 + R4 三问题修订）

> 文档类型：Decision Record（P&V 呈报，Coordinator/Maintainer 裁定）
>
> 状态：**OPEN（R6 修订版）**——§1 已按授权落 Packet v4/v5；§2 三项中 **A' 已撤回（否决记录在案）**、**A 定稿版** 维持待重审（本轮不动，仅交叉引用更新）、**B 升 v3 后已获 Maintainer 批准（裁定 1+2，RESOLVED-MAINTAINER，R6 落地）**——入口域收窄 + wire 校验器消歧转为 mandatory；含 XAUDIT-FIX 与 R4 两轮勘正（§4）
>
> 关联：DR-IP-0022-01/-02/-03；Packet `IP-0022-PACKET/v5`（R5+R6 修订）；`LIMA_IP-0022_XAUDIT_Matrices_v1.md`（R4+R5 修订）；Assignment `IP-0022-PV-XAUDIT/v1`、`IP-0022-PV-R4/v1`、`IP-0022-PV-R5/v1`、`IP-0022-PV-R6/v1`（PKT-IP-0022-R4 / R5 / R6，2026-09-13）
>
> 基线：main=`30bdfaa`（行为口径）；分支 head R5 起含 _red_proof R5 增量（lima/** 与 main 等同）
>
> R4 修订依据：Maintainer 复审三问题（①B 碰撞缺陷 ②RED 证据不可复现 ③矩阵漏 entrypoints.symbol 出口）。**R5 修订依据**：Maintainer 复现 + 主会话亲验的公共 API 往返契约问题——R4 的 B 重写版"wire 层一律拒绝 '-'"会使一组**合法 #58 输入的生成—校验往返**无法通过（§2-B v3 证据），Maintainer 给出"入口域收窄 + 类型化拒绝"框架，本版定稿呈报。

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

### DR-04-B：公共 API 往返契约——入口域收窄 + candidate_id 一致性 —— **v3，RESOLVED-MAINTAINER（R6：裁定 1+2 批准）**

- **Maintainer 裁定（2026-09-13 入 #60 Ledger，R6 落地记录）**：
  - **裁定 1+2 均批准**：`build_semantic_top_n` 与 `ram_wire_payload` 指定入口对字面 `symbol="-"` 类型化拒绝（错误码 INVALID_FIELD_VALUE + 定位路径 `$.facts.<section>[i].symbol` / `$.semantic_result.ranked[i].symbol`）；wire 校验器同步拒绝并检查候选 ID 一致性（第七项消歧 + 一致性公式维持 v3 设计）。
  - **定性**：本裁定为**有意收窄 #60 两个公开入口的输入域**（可观察行为变更），非修改 #58 通用条目契约——`AttackSurfaceEntry(symbol='-')` 作为 #58 契约形态仍然合法，只是这两个入口不再接受它。
  - **不变项**：`candidate_id` 冻结编码（`symbol or '-'` 槽位）不变；Profile 层对 `-` 的接受行为不变（I13n 维持）；DR-04-A 维持 manifest-index 定稿呈报（另行重审）。
  - **冻结测试要求（R6 已落地）**：X8-1 展开为五类 facts 清单（entrypoints / external_sources / sensitive_sinks / trust_boundaries / unresolved_edges）各至少一例，逐例断言准确错误码（ContractError + INVALID_FIELD_VALUE）与准确字段位置（`$.facts.<section>[i].symbol`）；sinks/boundaries 现产 symbol 全 None，以 dataclasses.replace 注入 `symbol='-'` 构造条目验证入口校验通用性。X8-2/X4-7/X8-0 保留；X4 系（X4-1/2/3 绑定负例 + X4-0 冻结模式锚）无退化复核维持。
  - **文档要求（兼容性措辞，R6 已落地）**："仓内正常扫描产物不受影响"（五源定源 P-R4-3 + golden/real-chain 零命中证据）；"仓外依赖 `symbol='-'` 输入的调用方将收到类型化拒绝——有意收窄的兼容性影响，**不声称零影响**"。
  - **B-2 备选（改 candidate_id 编码 = IP-0019 重冻结）：未采纳，留档**——裁定 1+2 获批后 B-2 不再需要；如未来重新评估须另立大 DR。
  - **授权范围**：本裁定仅授权契约方向与 Packet/测试修订；实施（含 D2 冻结迁移）按 Packet 流程另行推进。

- **往返契约缺陷（R5 新证据，v2"wire-only 拒绝"方案作废的原因）**：#58 契约接受 `AttackSurfaceEntry(symbol='-')`，且这是一组**合法的公开 API 输入**。端到端实证（Maintainer 复现 + 主会话亲验 + P&V 本轮亲验 probe P-R5-1/P-R5-2/P-R5-3，`_red_proof/probe_r5.py`）：
  - **P-R5-1**：携带 `symbol='-'` 条目的 facts → `build_semantic_top_n` **接受**（无字段级校验）→ `ram_wire_payload` **接受**（仅 isinstance 入口校验）→ `validate_ram_wire_payload` **通过**——**当前 main 上该合法输入的生成—校验往返完整成立**，wire 序列化携带 `symbol='-'`；
  - **P-R5-2**：None 形态与 `'-'` 形态生成**完全相同**的 candidate_id 集合（交集含 `entrypoint:danger.py:-#0` 等，`candidate_id()` 规则 `symbol or '-'` @prioritizer:336）；
  - **P-R5-3**：None→`'-'` 篡改后五摘要全部保持有效、validate 通过（碰撞缺陷端到端复现，X4-7 RED 基础）。
  - **结论**：v2 重写版的"wire 层一律拒绝 '-'（R4 生产链定源证零误伤）"论证只覆盖**默认扫描链**（扫描产物 ranked symbol 全源 = 标识符 ∪ None ∪ `"<dynamic-call>"`，P-R4-3 维持有效），**不足以覆盖"构造输入携带合法 '-'"这一公开 API 用法**——若仅 wire 层拒绝，这组合法输入会变成"能生成、不能校验"的中间态，破坏往返契约。"默认扫描链不产生 '-'"不能证明公共契约零误伤。
- **推荐方案（入口域收窄 + 类型化拒绝，R6 起为已批准定稿）**：
  1. **`build_semantic_top_n` 入口校验（IP-0019 冻结公开入口的行为变更）**：facts 五清单（entrypoints / external_sources / sensitive_sinks / trust_boundaries / unresolved_edges）中任何条目 `symbol == "-"` 字面值 → `ContractError(INVALID_FIELD_VALUE, "$.facts.<section>[i].symbol")`（错误码对齐 ram_schema 既有 INVALID_FIELD_VALUE 惯例；pointer 采用 `$.` JSON 路径风格 + 实参名前缀，与 `ram_wire_payload` 的 `$.ram_result`/`$.semantic_result` 入口指针惯例一致——**建议实现时若与 IP-0019 现有异常消息惯例冲突，以 IP-0019 惯例为准并回报**）；
  2. **`ram_wire_payload` 入口校验（IP-0021 冻结公开入口的行为变更）**：`semantic_result.ranked` 中任何 `symbol == "-"` → `ContractError(INVALID_FIELD_VALUE, "$.semantic_result.ranked[i].symbol")`——防御直接手工构造 `SemanticTopNResult` 的调用方（该入口是 wire semantic 段的唯一其他公开生产者）；
  3. **`validate_ram_wire_payload` 第七项消歧规则（维持 v2 设计）**：wire 层 `symbol == "-"` 一律拒绝（`$.semantic.ranked[i].symbol`）——上游两入口已拒，wire 出现 `'-'` 必为异常/篡改，入口拒绝与 wire 拒绝**分工一致而非冗余**（入口负例 X8-1/X8-2，wire 负例 X4-7）；None↔`'-'` 互换篡改因此被拒；
  4. **candidate_id 冻结编码不变**：`symbol or '-'` 槽位维持——歧义由入口拒绝消除（`'-'` 字面值进不了系统后，槽位 `'-'` 严格对应 None），IP-0019 golden/collision 冻结面零触碰；
  5. **往返保证（显式契约声明）**：被允许的输入（默认扫描产物 + 构造输入中 symbol≠'-' 的 #58 合法条目）完成生成—校验往返；`symbol='-'` 在**入口处**被类型化拒绝（fail-closed、错误码+路径可诊断），不再产生"能生成不能校验"的中间态。GREEN 锚 X8-0（真实临时仓全链往返）在基线与实现后均绿。
- **入径核查（R5 Stop Condition 亲验，全树 grep + 逐源阅读）**：能携带 `symbol='-'` 进入 wire 的公开入径共三条，全部纳入本设计——(i) `build_semantic_top_n(facts)`（ranked 候选仅由 facts 五清单派生，`_collect_candidates` @prioritizer:522-585 逐源亲验）；(ii) `ram_wire_payload(ram_result, semantic_result)` 的直构 `SemanticTopNResult` 参数（isinstance 后无字段校验，ram_schema:276-278 亲验）；(iii) wire dict 直入 `validate_ram_wire_payload`（被规则 3 覆盖）。`lima/semantic_retrieval.py:1279` 的 `SemanticCandidate` 是检索层同名异类（不同模块、不在 wire 路径），非入径。
- **兼容性与冻结面裁定记录（R6：裁定 1+2 已获批，原文呈报保留如下）**：
  - **输入域收窄 = 可观察行为变更**：IP-0019 `build_semantic_top_n` 与 IP-0021 `ram_wire_payload` 两个**冻结公开入口**，此前接受的 `symbol='-'` 输入此后被 typed 拒绝（该输入形态本身是 #58 契约合法的）——**获 Maintainer 批准（裁定 1）**；
  - **正常扫描产物零影响**：五源定源在案（P-R4-3 维持）——默认扫描链永不产出 ranked `symbol='-'`；golden fixtures 与 real-chain payload 零命中（v4/v5 复核维持）；
  - **裁定 1（门控）**：~~待裁~~ **已获批**——授权对上述两个冻结公开入口执行输入域收窄（规则 1/2）；
  - **备选方案 B-2（未采纳，留档）**：改 candidate_id 冻结编码消歧（如 `'-'` 转义或换 None 哨兵）= **IP-0019 冻结面重冻结**（golden 期望值与 collision 断言全量变更，大 DR）——裁定 1+2 获批后**不再需要，未采纳**，仅留档供未来对照；如重新评估须另立大 DR。
  - **裁定 2（随裁定 1 一并）**：~~待裁~~ **已获批**——wire 层第七项消歧 + 一致性公式（v2 设计维持：prefix 匹配 + `rsplit("#",1)` 得 symbol 槽与非负数字 ordinal 等值比对，违例 `$.semantic.ranked[i].candidate_id`）。
- **测试映射（_red_proof 底稿已入库，RED D1'''''' = 43 failed / 4 passed，R6 展开后）**：X8-0 真实扫描全链往返 GREEN 锚（基线即绿）；**X8-1a..e 五类 facts 清单各一例**（R6 展开）——`build_semantic_top_n` 入口 '-' typed 拒绝，逐例断言准确错误码（`ContractError.code is INVALID_FIELD_VALUE`）与准确字段位置（`$.facts.<section>[i].symbol`）；sensitive_sinks/trust_boundaries 现产 symbol 全 None，以 dataclasses.replace 注入（五清单同构 `AttackSurfaceEntry`，验证入口校验对清单通用）；X8-2 `ram_wire_payload` 直构结果入口 '-' typed 拒绝（同码 + `$.semantic_result.ranked[i].symbol`）；X4-7 wire 层 None→`'-'` 篡改必拒（RED 维持，与入口负例分工）；X4-1/2/3 三字段一致性绑定（RED 维持，无退化）；X4-0 锚（IP-0021 冻结 candidate_id 模式，含非数字 ordinal）不受影响。
- **不批的影响（历史呈报项，裁定已获批、此条不再适用）**：若当初不批，wire 的 kind/path/symbol 三字段保持"仅结构校验 + path 规则"绑定，含 None↔`'-'` 互换在内的篡改不可检出（R-9 残余风险，矩阵二）；且 `'-'` 合法构造输入的往返缺陷维持现状。**R6 现状**：裁定 1+2 获批，R-9 将随实现消除（IP-0022 实施后）。

## 3. 范围外事项（如实声明，不提请变更）

- rationale/frameworks/model_id 自由文本面（矩阵一 I9、残余风险 R-2）；防恶意重签（R-3）；直调内部 API（R-4）；启发式非穷尽（R-5，含 Unicode 同形变体）；wire path 长度 cap 宽度差异（R-6）；`DEFAULT_IGNORED_DIRECTORIES` 不含敏感目录名（R-8，防御位置留在准入层）。
- Profile 层 `symbol='-'` 良性字面值（#58 契约面）：不修（无 candidate_id 域、非敏感形态，I13n 记录性事实）。**R5 注记**：DR-04-B v3 的入口域收窄只作用于 facts/ranked 域（`build_semantic_top_n` 入参 facts 五清单与 `SemanticTopNResult.ranked`），**不触碰 Profile `_build_entrypoints` 的 symbol 契约面**（`[project.scripts] "-"=...` 仍按 #58 接受，I13n 维持）。
- requirements* manifest 无内容校验是结构性事实（非防御承诺），其内容关键词面记 I9/I4b。
- DR-03/DR-02 状态链：R4 核对无波及（矩阵 R4 附注 3），状态不变。

## 4. 验证证据（摘要，全文见 Packet v4 §9 / v5 §9.5-9.7 与矩阵文档）

- **RED D1''''''（R6，Maintainer 裁定落地展开）**：`_red_proof` **43 failed / 4 passed**（R5 的 39 failed / 4 passed 基础上，X8-1 展开为五类清单各一例 +4 failed；4 个通过项 = GREEN 锚 X8-0 + X4-0 + X6×2）。全部新失败签名 = `ContractError not raised`（目标缺失型，非 arrange 缺陷；构造通道复用 fixtures/repo_shapes 绿色路径 + probe_r5 同构造探针）。回归锚 `tests/audit tests/contracts` 801 passed、golden 15 passed（R6 本轮工作树亲跑）。
- RED D1'''''（R5 增量，维持记录）：`_red_proof` 39 failed / 4 passed（X8-1/X8-2 两例 RED + X8-0 GREEN 锚）。
- **R5 探针证据（`_red_proof/probe_r5.py`，P&V 亲验）**：P-R5-1 合法 '-' 条目全链往返 **PASSED**；P-R5-2 None/'-' candidate_id 集合**非空交集**（碰撞实证）；P-R5-3 None→`'-'` wire 篡改 **ACCEPTED**（X4-7 基础维持）。
- RED D1''''（R4，维持）：37 failed / 3 passed 记录在案（签名见 §2-B 与 Packet §9.5）。
- **可复现性（R4 问题 2 处置）**：v3 的 23 用例文件此前未提交，本轮全量底稿入库（`_red_proof/` 4 文件）；**干净 checkout**（`git archive <head>` 解包空目录）原样复跑：37 failed / 3 passed、801 passed、golden 15 passed，与工作树逐项一致。`_red_proof` 性质与管理办法见 Packet v5 §4a（D2 冻结底稿、不在 pytest testpaths、CI 不执行、D2 迁移后归档）。
- 回归：`tests/audit tests/contracts` 801 passed；golden matrix 15 passed。
- goldens 零命中与 real-chain 零误伤：v4 结论维持；v5 新检查（script 名启发式、`symbol=='-'` 拒绝）对 real-chain payload 与 fixtures 零命中/零违例（P-R4-3 源追踪 + MINIMAL_PAYLOAD 复核）。
- 双平台：Windows 本机 + PI-DR6 预演（Packet v4 §9.4）维持；R4 增量用例为纯字符串/纯构造断言，平台无关。

## 5. 裁定请求

~~请 Coordinator/Maintainer 对 §2 A 与 B 作出裁定。~~ **R6 更新：B（v3）已获 Maintainer 批准（裁定 1+2，RESOLVED-MAINTAINER，裁定要点与落地记录见 §2-B 头部）；其 mandatory 化已同步 Packet v5-R6。A（定稿版：`manifest-index` 稳定标识 + 2 文件 4 断言锚定修订清单）维持待重审呈报（本轮不动）。A' 已撤回，不再呈请。§1 各项（含 v5 script 名称准入）已按 Assignment 授权落 Packet，无需另行裁定。
