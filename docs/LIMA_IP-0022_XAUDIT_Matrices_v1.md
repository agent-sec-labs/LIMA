# IP-0022 XAUDIT 可核查矩阵（PKT-IP-0022-XAUDIT，2026-09-13；R4 修订 2026-09-13；R5 修订 2026-09-13；R6 附注 2026-09-13）

> 文档类型：审查矩阵（P&V 制作，供 Maintainer 逐行核查）
>
> 依据：Assignment `IP-0022-PV-XAUDIT/v1` → `IP-0022-PV-R4/v1` → `IP-0022-PV-R5/v1` → `IP-0022-PV-R6/v1`；Packet `IP-0022-PACKET/v5`（含 R5/R6 修订）；DR-IP-0022-04（R6 修订版）
>
> 行为口径：main=`30bdfaa13ac72572d65ccb2567ae8702923c4187`（实测）；v3=Packet v3 修复后；v4=Packet v4 修复后；**v5=Packet v5 修复后（R4：+ script 名称准入（I13）、candidate_id `'-'` 槽位消歧（X4-7）；DR-04-A' 撤回）**；**v5+R5=DR-04-B v3 修复后（入口域收窄：`build_semantic_top_n` / `ram_wire_payload` 两公开入口 typed 拒绝 `symbol='-'`；wire 拒绝维持）**；标注【DR-04-X】者为未获批不实施（**R6 附注：DR-04-B v3 已获 Maintainer 批准裁定 1+2（RESOLVED-MAINTAINER），其矩阵条目转 mandatory；仅 DR-04-A 定稿版仍待重审**）
>
> 本文档全部"main 实测"结论均由 `_red_proof/probe_xaudit.py`、`_red_proof/probe_r4.py`、`_red_proof/probe_r5.py`、`_red_proof/test_ip_0022_xaudit_red.py`（D1'''）与 `_red_proof` 探针脚本在本 worktree（lima/** 与 main 等同）复现。

## 矩阵一：输入来源 → 公开输出 → 拦截点 → 负例

公开输出面（在 v3"五面"基础上按携带通道细分）：
- **S1** Profile entrypoints；**S2** Profile code_roles；**S3** Profile coverage_gaps detail（含 MANIFEST_PARSE_ERROR / BUDGET_EXHAUSTED / INVENTORY_SKIPPED 模板）；**S4** Profile `to_dict()` 全文序列化（= S1∪S2∪S3∪声明面）；**S5** RAM facts 六清单 + labels/rule_ids/cwes + coverage_gaps；**S6** Top-N ranked（candidate_id/kind/path/symbol/…）；**S7** 模型 prompt 文本；**S8** wire payload（ram 段 = S5 全量、semantic 段 = S6 + total + gaps、build 段、identity、provenance、execution_required）。

| # | 输入来源 | 公开面 | main 实测行为 | v3 修复后 | v4 修复后 | 负例（测试 ID） |
|---|---|---|---|---|---|---|
| I1 | 敏感 **basename** 代码文件（`tests/token_FAKESECRET123.py`、`ghp_….py`） | S2/S4/S5/S6/S7/S8 | **泄漏**：code_roles（CodeRole.TEST）、RAM sensitive_sinks、Top-N、prompt、wire 全链携带 | basename 准入过滤（§3.2 三点），五面拦截 | 同 v3；跨命中去重（X5-1） | G1-1/2/3、M2-M10（D1'' 已冻结面）；X5-1 |
| I2 | 敏感 **目录段**、良性 basename（`tests/secrets/anything.py`、`secrets/danger.py`） | S2/S4/S5/S6/S7/S8 | **泄漏**：实测 `tests/secrets/anything.py` 入 code_roles；`secrets/danger.py` 入 RAM sinks（probe P-X1/P-X2） | **仍泄漏**（v3 仅查 basename） | **检测扩为路径每段**（§3.1 v4）：任一段命中即拒；与 I1 同面拦截 | X1（code_roles 段泄漏）、X2（RAM 段泄漏） |
| I3 | 敏感目录内 **固定名 manifest 解析失败**（`token/pyproject.toml` 非 UTF-8 / 坏 TOML） | S3 → S4 → S8 | **泄漏**：`MANIFEST_PARSE_ERROR` detail=`manifest=token/pyproject.toml; error=UnicodeDecodeError`（IP-0016 冻结模板 `manifest={relative_path}`，probe P2f 实测） | v3 未覆盖（准入过滤不作用于 manifest gap） | v4 同（A' 已在 R4 撤回） | 【DR-04-A 定稿版，待重审】detail 改 `manifest-index=<i>; error=<ErrType>`（i=`_manifest_candidates` sorted 枚举下标，含原路径/文件名零片段），未获批前维持现状并记入残余风险 R-1 | X3-1 |
| I4a | 敏感命名 **requirements 通配 manifest**，内容损坏（非 UTF-8 / stat 失败） | S3 → S4 → S8 | **泄漏**：实测 `manifest=requirements-ghp_AAAA….txt; error=UnicodeDecodeError`（probe P2e） | v3 未覆盖 | v4 同（A' 已撤回） | 【DR-04-A 定稿版】同 I3（读取失败 detail 同模板替换） | X3-1 变体（requirements 形态，见矩阵附注） |
| I4b | 敏感命名 requirements 通配 manifest，正常可读内容（任意文本，含"坏"依赖行） | S3/S4 | **不泄漏文件名**：`_parse_manifest` 对 requirements* 不做结构校验（只 `package_managers.add("pip")` 常量锚 + 按行扫框架关键词），文件名不进任何公开面（probe P2b/P2c 实测 gaps 为空） | 同 main | 同 main（**结构性事实，非防御承诺**：不校验 ⇒ 无错误通道 ⇒ 无文件名携带；代价是内容关键词可进 frameworks 声明，属内容自由文本面 I9） | 无负例（记录性事实） |
| I5 | 超限 manifest（敏感命名，`manifest_max_bytes` 触发） | S3 → S4 | **泄漏**：`BUDGET_EXHAUSTED` detail=`manifest={relative_path}; bytes=…`（inventory.py `_load_one_manifest`，实测见 X3-2 arrange） | v3 未覆盖 | v4 同（A' 已撤回） | 【DR-04-A 定稿版】detail 改 `manifest-index=<i>; bytes=…; limit=…` | X3-2 |
| I6 | RAM candidates（全部 `.py`，含敏感命名/敏感目录段） | S5 → S6 → S7 → S8 | 泄漏（D1'' M2 实测：`ghp_….py` 入 sensitive_sinks） | v3 §3.2.3 过滤（basename） | 段级过滤 + RAM-only 构建同样留痕（`RamFactsBuildResult.admission_skips`） | M2-M5、X2、X5-2 |
| I7 | semantic 候选（由 RAM facts 派生） | S6/S7 | 随 I6 泄漏 | 上游过滤后不出现 | 同 v3；直调 `build_semantic_top_n` 处理已构造 facts 仍属内部 API 误用，不设防（Known Gap，§2） | M6/M7 |
| I8 | manifest scripts 声明的入口目标解析到敏感路径（`cli = "pkg.token_x:main"`） | S1 → S4 → S8 | **可泄漏**：`_resolve_script_target` 按 module 逐段回退解析，不查敏感形态 | v3 §3.2.1 过滤（script-declared 与 root-convention 同滤） | 段级过滤同滤 | M7 |
| I9 | 自由文本：模型 rationale、manifest/源码内容关键词（frameworks 声明）、model_id | S6/S8、S4、S8 build | rationale 有 `_bounded_rationale` 三重防线（NFC+去控制字符+`_SECRET_TOKEN_PATTERN`+代码片段模式+512B 截断，malformed 回落 fallback）；frameworks 关键词与 model_id 无秘密筛 | 同 main（rationale 防线属 IP-0018/0019 冻结面，本 IP 不改） | 同 main；**范围外声明**：`_SECRET_TOKEN_PATTERN` 是五 token 形状冻结子集，非启发式超集——模型把秘密文本写进 rationale 且非五形状时可能通过；model_id 为配置面非仓库输入。NFR-01 保持 PARTIAL 的依据之一 | 无新负例（DR-04 §范围外清单） |
| I10 | Profile 声明面（languages/package_managers/frameworks/kinds） | S4 | 值均为封闭词表或常量锚（`pip`、`go-modules` 等），不携带文件名/路径；frameworks 关键词见 I9 | 同 main | 同 main | 无（结构性事实） |
| I11 | Profile entrypoints（root-convention 固定名 `cli.py/main.py/__main__.py`） | S1 | **结构性不含敏感命名**：候选集是固定名常量，敏感命名文件进不了 root-convention（probe P5 实测 `cli_ghp_*.py` → entrypoints 空）；但**目录段**可经 script 解析进入（I8） | 同 main（结构性）+ I8 过滤 | 同 v3 | M7（script 路径）、无 root-convention 负例（结构性） |
| I12 | RAM 候选**读取失败**通道（ram.py:300 `_GAP_INVENTORY_SKIPPED detail=reason=read-failed; file={relative_path}`） | S5 coverage_gaps → S8 | detail 模板携带不可读 .py 的**全路径**——但非 UTF-8 文件在 workspace 层已被排除（reason=non-utf8，不进 `inventory.files`），read-failed 仅剩枚举后 OSError 窗口，实测不可达（P3b：非 UTF-8 敏感命名 .py → RAM gaps 为空、路径零出现） | **闭合依据**：v4 过滤在 `candidates` 枚举处（§3.2.3），敏感形态候选在读循环**之前**即被剔除——`_read_python_text` 仅作用于过滤后候选，故 read-failed 模板永无敏感命名路径可携带（结构性前置，非巧合） | 同 v3 + RAM-only 构建同样前置（X5-2） | P3b 探针（记录性事实）；M2（前置过滤正例） |
| I13 | **manifest scripts 名称**（`[project.scripts]` 键，任意 TOML 字符串，inventory.py:360-365 仅 isinstance 校验） | S1 entrypoints.symbol → S4 → S8 | **泄漏**：`token_FAKESECRET123 = "pkg.cli:main"` → `entrypoints.symbol='token_FAKESECRET123'` 原文公开（probe P-R4-2 亲证；解析目标 `pkg/__init__.py` 良性，v4 path 面过滤不可达——泄漏源是名称不是路径） | v3/v4 均未覆盖（过滤只作用 path） | **v5 纳入修复**：script 名称准入过滤（同一启发式作用于名称字符串，单段语义），命中不入 entrypoints、计 `sensitive-filename` skip（公开 count 通道，与文件名同口径）；良性名（safe_cli/cli）不受影响 | X7-1（S1/S4 排除 + 良性锚）、X7-2（skip 计数） |

| I13n | script 名 `'-'` 字面值（`[project.scripts] "-" = ...`） | S1 entrypoints.symbol | **可产出**：`entrypoints.symbol='-'`（probe P-R4-1 实测，#58 契约接受）——良性数据（非敏感形态），且 **Profile entrypoints 不是 RAM/semantic ranked 的输入**（ranked 仅由 RAM facts 五清单派生，prioritizer:525-585），故不构成 candidate_id `'-'` 槽位碰撞的生产路径；ranked symbol 全源 = 标识符 ∪ None ∪ `"<dynamic-call>"`（P-R4-3） | 不设防（非泄漏） | 同 main（#58 冻结契约原样，无 candidate_id 域；**R5 注记：DR-04-B v3 的入口收窄只作用于 facts/ranked 域，Profile `_build_entrypoints` 的 `'-'` script 名维持 #58 接受——ranked 域的消歧安全性由入口 typed 拒绝承担，不再单靠"生产链不产出"论证**，见 P-R5-1） | 记录性事实（P-R4-1/P-R4-3/P-R5-1；X4-7/X8 的安全性依据） |


矩阵一附注（主会话五项探针观察的独立复验与解释）：

1. **code_roles 泄漏复现** ✓：`tests/token_FAKESECRET123.py` → CodeRole.TEST（main 实测，X1/G1-1 同 shape）。成因：`_code_role_assignments` 迭代 `sorted(evidence)` 无过滤。
2. **`secrets/pyproject.toml` 坏 TOML "未泄漏"——探针结论需勘正**：主会话以 FAKESENTINEL 子串判定"未泄漏"，属**哨兵口径假阴性**。实测 gap detail=`manifest=secrets/pyproject.toml; error=TOMLDecodeError`——目录段 "secrets" **已进入公开 Profile coverage_gaps**（probe P2）。既非 manifest 候选构造限制，也非防御语义，而是 IP-0016 冻结 detail 模板的**真实泄漏面**（→ DR-04-A）。
3. **`requirements-ghp_….txt` 坏内容不触发 MANIFEST_PARSE_ERROR** ✓ 属实且**按构造必然**：requirements* 分支无内容解析器（`_parse_manifest` 仅 `add("pip")` + 行级关键词），MANIFEST_PARSE_ERROR 只由 stat/read 失败（OSError/UnicodeDecodeError）或特定解析器异常（TOMLDecodeError/JSONDecodeError/ParsingError）触发；正常内容时 package_managers evidence 为常量锚 `pip`，不携带文件名。但**读取失败路径会泄漏全文件名**（P2e 实测）。
4. **`DEFAULT_IGNORED_DIRECTORIES` 不含敏感目录名** ✓（workspace.py:19-25 亲验）：目录级遍历防御缺位是事实；v4 以准入层段级检测补位（与已否决的"workspace.py 遍历层 skip"路线不冲突——过滤仍在 lima/audit 准入点）。
5. **entrypoints 来源=固定名** ✓（`_ROOT_ENTRY_CANDIDATES` 常量 + scripts 解析）：结构性不含敏感命名，非防御承诺（I11）；敏感路径可经 scripts 解析进入（I8/M7 已设防）。

## 矩阵二：wire 字段 → 绑定机制 → 篡改变体

绑定机制图例：**[Struct]**=IP-0021 冻结结构校验（键封闭/类型/词表/cap/rank 连续/平行数组/枚举）；**[Path]**=路径规则（v3 引入，v4 强化）；**[CID]**=candidate_id 一致性（v4；**R6：DR-04-B 裁定 2 已批准，mandatory**；v5+R5：`'-'` 槽位消歧由入口域收窄保证）；**[Entry]**=公开入口 typed 拒绝（R5 新增；**R6：DR-04-B 裁定 1 已批准，mandatory**）；**[RamD]**=ram_facts_digest 重算（ram 段 canonical 全量）；**[CfgD]**=semantic_config_digest 重算；**[RstD]**=semantic_result_digest 重算；**[MdlD]**=model_digest 重算（v3/G2b）；**[WireD]**=wire_digest 传输头（build+三 identity 摘要 re-wrap，末位）。

| wire 字段 | 绑定机制 | 篡改变体与拦截点（测试 ID） |
|---|---|---|
| `schema_version` / `model_kind` | [Struct] const | 改值 → `$.schema_version`/`$.model_kind`（既有冻结负例） |
| `build.profile_budgets.*` / `build.ram_budgets.*` | [Struct] 正整数 + [WireD]（build 段整体入 wire_digest re-wrap） | 改值不同步 wire_digest → 末位 [WireD]（M16 陈旧摘要）；同步重算 wire_digest 洗白 → 该面**接受**（传输头语义，§3.5 定位声明：非认证） |
| `build.semantic.top_n/seed/tie_break/weights/budgets` | [Struct] 范围/const/词表 + [CfgD] + [WireD] | 改值不同步 → [CfgD] `$.identity.semantic_config_digest`；同步三摘要+wire_digest 整体重算 → 接受（自洽重签，非认证面） |
| `build.semantic.model_id` | [Struct] str + [CfgD]（入 config payload）+ [MdlD] + [WireD] | 改值不同步 model_digest → [MdlD] `$.identity.model_digest`（G2-1）；不同步 config → [CfgD]（M18 helper 等值锚） |
| `ram.entrypoints/external_sources/sensitive_sinks/trust_boundaries/unresolved_edges[i].path` | [Struct] str + [Path] + [RamD] | `/abs`（M11）、`C:` 盘符（M12）、`..` 段（M13）；v4 强化：`a//b` 空段、`./x` 点段、控制字符（X4-4/5/6）；仅改 path 且同步 RamD+WireD 重算 → 接受（自洽重签） |
| `ram.…[i].symbol/reason_codes/source_artifact_ids` | [Struct] + [RamD] | 篡改不同步 → [RamD] `$.identity.ram_facts_digest`（M17 同步洗白变体：同步 RamD 仍需动 identity → [WireD] 末位拦截；M17 实测） |
| `ram.source_labels/sink_rule_ids/sink_cwes` | [Struct] 平行数组长度一致 + [RamD] | 长度错位（既有冻结负例）；篡改不同步 → [RamD] |
| `ram.key_flows[i].sink_rule_id/steps` | [Struct] cap≤步数上限 + [RamD] | 超 cap（既有冻结负例）；内容篡改 → [RamD] |
| `ram.coverage_gaps[i].gap_code/detail`、`ram.counters.*` | [Struct] GAP_CODE 模式/非负 + [RamD] | gap_code 模式违例（既有）；detail 篡改 → [RamD]（M17 系） |
| `semantic.ranked[i].rank/score/category/rationale/key_flow_steps/candidate_id` | [Struct] rank 连续/词表/候选 ID 模式 + [RstD]（六字段子集入 result digest payload） | rank 断号、category 出词表、candidate_id 模式（既有冻结负例）；篡改不同步 → [RstD]（M17s 同步洗白仍被 [WireD] 末位拦截） |
| `semantic.ranked[i].kind/path/symbol` | [Struct] str/None + **[Path]**（path）+ **[CID]**（v4：candidate_id ≡ `f"{kind}:{path}:{symbol if symbol is not None else '-'}#{ordinal}"`，ordinal ≥ 0 数字；**v5+R5 消歧（DR-04-B v3）**：槽位 `'-'` **严格且唯一**对应 `symbol is None`——该不变量由**入口域收窄保证**（`'-'` 字面值在两公开入口被 typed 拒绝，见新增行），wire 层 `symbol == "-"` 一律拒绝与入口一致）+ [RstD]（经 candidate_id 传递） | **关键缺口（main 与 v3 均不设防）**：`_result_digest` payload 不含 kind/path/symbol——改 kind/path/symbol 而不动 candidate_id，三摘要与 wire_digest 全部保持有效！**v5 勘正（Maintainer 问题 1）**：`symbol or '-'` 使 `symbol=None` 与 `symbol='-'` 生成同一 ID——None↔`'-'` 互换不动 ID 亦不动任何摘要（X4-7 RED：main 接受，probe P-R4-4/P-R5-3），三字段绑定不闭合；**R5 勘正（往返契约）**：R4 的"生产链定源零误伤"只覆盖默认扫描链——#58 合法条目 `symbol='-'` 在 main 上**完成全链往返**（probe P-R5-1：两入口接受 + validate 通过），故消歧必须落在**入口拒绝**而非仅 wire 拒绝（否则该合法输入"能生成不能校验"）；v5+R5 [CID] + 入口收窄补绑（X4-1/2/3 + X4-7 wire 负例 + X8-1/X8-2 入口负例 + X8-0 往返 GREEN 锚）。安全性：默认扫描产物零影响（P-R4-3 源追踪维持；golden/real-chain 零命中维持） |
| **入口域：facts 五清单条目 `symbol == "-"`（合法 #58 形态）经 `build_semantic_top_n` / 直构 `SemanticTopNResult` 经 `ram_wire_payload`** | **[Entry]（R5 新增图例：公开入口 typed 拒绝；R6：DR-04-B 裁定 1 已批准（RESOLVED-MAINTAINER），mandatory）**：`ContractError(INVALID_FIELD_VALUE, "$.facts.<section>[i].symbol")` / `ContractError(INVALID_FIELD_VALUE, "$.semantic_result.ranked[i].symbol")`；入径核查（probe/源码亲验，Packet §9.6）：携带 '-' 进 wire 的公开入径仅此两条 + wire dict 直入 validate（[CID] 覆盖），`lima/semantic_retrieval.py` 的 `SemanticCandidate` 为检索层同名异类非入径 | **main 现状**：两入口均**接受**（X8-1/X8-2 RED），'-' 载荷生成且 validate 通过（P-R5-1）；**v5+R5 后**：入口 typed 拒绝（fail-closed 可诊断），往返保证 = 被允许输入全链往返（X8-0）+ '-' 入口拒绝（X8-1/2）+ wire 必拒一致性（X4-7，入口已拒则 wire '-' 必为异常/篡改）。**影响面声明**：输入域收窄 = IP-0019/IP-0021 两冻结公开入口可观察行为变更（此前接受的合法 '-' 形态被拒），~~需 Maintainer 裁定~~ **R6：已获批（裁定 1+2，2026-09-13）**；备选 B-2（改 candidate_id 编码）= IP-0019 重冻结，**未采纳留档**（DR-04-B v3 §2-B）。**R6 兼容性措辞**：仓内正常扫描产物不受影响；仓外依赖 `symbol='-'` 输入的调用方将收到类型化拒绝——有意收窄的兼容性影响，不声称零影响 |
| `semantic.total_candidates` / `semantic.coverage_gaps` | [Struct] ≥len(ranked) / GAP_CODE + [RstD] | 篡改不同步 → [RstD] |
| `identity.ram_facts_digest` | [Struct] hex64 + 重算比对（B'） | 单字符篡改（M15）；全零占位（G2-2） |
| `identity.semantic_config_digest` | [Struct] hex64 + [CfgD] 重算 | 同上族（M15/M18） |
| `identity.semantic_result_digest` | [Struct] hex64 + [RstD] 重算（含 input_facts_digest=RamD 重算值，双重绑定 ram 段） | 同上族 |
| `identity.prompt_digest` | [Struct] hex64 + 传递性绑定（不可从 wire 复原：prompt 模板不在 wire 中；经 [CfgD] 中 `prompt_digest` 槽位约束——改 prompt_digest 槽即破坏 [CfgD] 重算） | 篡改 identity.prompt_digest → [CfgD] 失配（M15 族）；注：模板本身真值口径=MINIMAL_PAYLOAD 迁移取 `digest(默认模板)`（X6） |
| `identity.model_digest` | [Struct] hex64 + [MdlD] 重算（G2b） | G2-1 |
| `identity.wire_digest` | [Struct] hex64 + [WireD] 末位重算 | 不同步（M15 族）；**同步洗白变体**（M17/M17s：载荷篡改+全部摘要同步重算）→ 若篡改仍违反 [Path]/[CID]/[Struct] 则拦截，否则接受（非认证，§3.5） |
| `provenance.provenance_anchor_ids` | [Struct] const 链等值 | 错序/错值（既有冻结负例） |
| `execution_required.required/trigger_gap_codes` | [Struct] 类型 + 由 ram/semantic 两段 gap_codes **推导等值**（`execution_required_from_gaps`） | 不一致（既有冻结负例）；篡改 gap 代码同时改推导 → 需同步 [RamD]/[RstD]/[WireD]，纯结构面无独立摘要（设计如此：执行位是 gaps 的纯函数） |

### 路径规则不弱于 AttackSurfaceEntry 契约的逐条对照（核清第 3 项）

`lima/contracts/profile.py::_validated_path`（#58，IP-0016 冻结）拒绝：非 str / 空 / >_MAX_PATH_BYTES / 含 Cc 控制字符 / `/` 开头 / 含 `\` / `^[A-Za-z]:` 盘符 / 任一 `/` 段 ∈ {"", ".", ".."}；构造侧另做 NFC 归一（返回归一值）。

| 契约条款 | v3 wire path 检查 | v4 wire path 检查 |
|---|---|---|
| 非 str / 空 | ✓ | ✓ |
| `\` / 前导 `/` / 盘符 | ✓ | ✓ |
| `..` 段 | ✓（仅 ".."） | ✓（"", ".", ".." 全集） |
| 空段（`a//b`）、`.` 段（`./x`） | **✗ 弱于** | ✓（X4-4/5） |
| Cc 控制字符 | **✗ 弱于** | ✓（X4-6） |
| >_MAX_PATH_BYTES 超长 | ✗（记入残余风险：cap 属上限防御，hex64/结构 cap 已限列表规模；不弱化安全性，属宽度差异，DR-04 记录不单独提请） | 同 v3 |
| NFC 归一 | 构造侧已归一（facts 经 dataclass）；wire 侧不归一只拒绝（拒绝 ≠ 弱化：非 NFC 输入被拒而不是被接受） | 同 |

结论：v4 后 wire path 规则除"超长 cap"外逐条不弱于契约；超长差异已记录（矩阵二附注）。

### MINIMAL_PAYLOAD 迁移与旧负例"预期错误"核对表（核清第 4 项）

迁移定稿（v4 §3.5）：identity **五摘要全真值**——ram_facts_digest=`compute_content_digest(payload["ram"])`、semantic_config_digest=`semantic_config_digest(SemanticOptions())`、semantic_result_digest=以 payload 自身 semantic 段按 `_result_digest` 形状重算、prompt_digest=`compute_content_digest(默认 prompt_template)`、model_digest=`compute_content_digest(model_id)`；wire_digest 随迁（X6 迁移兼容锚：五值互异、非占位、可重算，实测通过）。**独立保留**全零占位拒绝负例 G2-2（不因迁移正例存在而删除）。X6 证明迁移可构造；D2 落库时正例断言"自洽载荷通过"。

旧负例逐个核对（`tests/audit/test_ram_schema.py`，均在 digest 检查**之前**的结构层失败，末位约束保证不被摘要错误"误伤通过"）：

| 既有负例 | 预期错误 | 迁移后仍因预期错误失败 |
|---|---|---|
| unknown_top_level_field / unknown_nested_field_in_ram_entry | UNKNOWN_FIELD | ✓（键封闭先于一切摘要） |
| wrong_scalar_type | INVALID_FIELD_TYPE | ✓ |
| category_outside_vocabulary | UNKNOWN_ENUM_VALUE | ✓ |
| rank_not_consecutive_from_one | INVALID_FIELD_VALUE `$.semantic.ranked` | ✓ |
| identity_digest_not_hex64 | INVALID_FIELD_VALUE `$.identity.*`（格式层，先于重算比对） | ✓ |
| sink_rule_ids/sink_cwes_length_mismatch | INVALID_FIELD_VALUE 平行数组 | ✓ |
| trigger_gap_code_outside_frozen_set / unsorted_duplicated | INVALID_FIELD_VALUE | ✓ |
| provenance_chain_wrong_order | INVALID_FIELD_VALUE | ✓ |
| key_flow_steps_over_cap | MAX_ARRAY_LENGTH_EXCEEDED | ✓ |
| gap_code_pattern_violation | INVALID_FIELD_VALUE | ✓ |
| top_n_out_of_range | INVALID_FIELD_VALUE | ✓ |
| missing_required_section | REQUIRED_FIELD_MISSING | ✓ |
| candidate_id_pattern_violation | INVALID_FIELD_VALUE（IP-0021 冻结模式，含非数字 ordinal——X4-0 锚复验） | ✓ |
| execution_required_inconsistent_with_gaps | INVALID_FIELD_VALUE | ✓ |

全部 14 类负例的失败点均位于追加的摘要/路径/一致性检查之前，无"被更早摘要错误误伤通过"或"预期错误被掩盖"情形；唯一被迁移改变行为的用例是 `test_minimal_payload_validates` 正例本身（DR-01 授权 + DR-03 §1(a) 升级，v4 定稿五摘要）。

## 残余风险清单（范围外，逐条）

1. **R-1 manifest gap detail 模板携带全路径**（I3/I4a/I5）：IP-0016 冻结面，DR-04-A 定稿版（`manifest-index=<i>` 稳定标识，R4 修订）提请重审；未获批前 `manifest={relative_path}` 原样公开。A'（候选准入过滤）已撤回（DR-04 §2-A' 否决记录）。
2. **R-2 rationale/内容自由文本**（I9）：`_SECRET_TOKEN_PATTERN` 五形状子集非启发式超集；模型生成文本中的新形态秘密可过 malformed 回落之外的筛；frameworks 关键词、model_id 同属自由文本配置面。
3. **R-3 防恶意重签**：摘要自洽比对非认证（§3.5 定位声明；持有 canonical 编码者可整体重算）。
4. **R-4 直调内部 API**：`build_semantic_top_n` 处理已构造 facts 不设防（Known Gap §2）。
5. **R-5 启发式非穷尽**：新形态文件名/目录段可漏检（§2 残余风险声明，NFR-01 PARTIAL 依据）。**显式例证（Coordinator 证伪探针）**：Unicode 同形/组合字符变体不命中——如西里尔 е（U+0435）的 `sеcrets/`（关键词族大小写不敏感但对 ASCII 字面量锚定，非 NFC 归一化比对），本轮亲验 `re.search` 不命中；`is_secret_shaped_path` 不做 Unicode 同形折叠，此类变体属范围外漏检面。
6. **R-6 wire path 无长度 cap**（矩阵二附注）：与 #58 契约的宽度差异，结构性 cap 已限列表项数。
7. **R-7 FR-01 PARTIAL**：`admission_skips` 内部留痕首版仅覆盖 `sensitive-filename` 一类 reason。
8. **R-8 workspace 遍历层**：`DEFAULT_IGNORED_DIRECTORIES` 不含敏感目录名（事实维持）；防御位置在 lima/audit 准入层（v4 段级），非遍历层（否决路线 §12.3）。

## R4 附注（PKT-IP-0022-R4，2026-09-13）

1. **DR-04 锚定清单勘误**：DR-04 v1 称 `manifest=` detail 模板被三处冻结测试锚定，其中 `tests/evidence_privacy/test_models.py` 经本轮逐行复核**不锚定该模板**——其 `manifest=` 出现（:118）是 `SanitizedPayload(manifest=m, ...)` 的字段关键字实参，与 gap detail 模板无关（R4 亲验，全树 grep 复核）。真实锚定集 = **2 文件 4 断言**：`tests/audit/test_fr05_gap_encoding.py`（:103/:110/:121）与 `tests/audit/test_budget_exhaustion_e2e.py`（:87）；逐处修订形式见 DR-04 §2-A（定稿版）。
2. **A' 撤回的波及核查**：A' 否决理由之一（skip 序号对不在 `sorted(evidence)` 枚举内的 manifest 候选定义失效）不波及 Packet §3.3 的 `AdmissionSkipRecord.index` 定义——code-role/RAM/script 三处枚举体均为各自被过滤候选的真实列表；A' 失效模式随 Packet v4 §3.2 第四过滤点删除而消除（Packet v5 §3.2 撤回记录）。
3. **DR-03/02 无波及**（核对）：DR-03 裁定面（G1 code_roles 过滤、B' 迁移/model_digest、R1 终案）与 DR-02（启发式超集、路线 B'）均不依赖 manifest detail 模板或 manifest 候选序号；A' 撤回与 A 定稿版不改变其结论，状态链不变。

## R5 附注（PKT-IP-0022-R5，2026-09-13）

1. **往返契约证据（DR-04-B v3 事实基础，P&V 亲验）**：`_red_proof/probe_r5.py` 三探针——P-R5-1：#58 合法条目 `symbol='-'` 经 `build_semantic_top_n` → `ram_wire_payload` → `validate_ram_wire_payload` **全链通过**（ranked 携带 `'-'`）；P-R5-2：None 与 `'-'` 形态 candidate_id 集合非空交集（`entrypoint:danger.py:-#0` 等四类）；P-R5-3：None→`'-'` wire 篡改 ACCEPTED。结论：R4"生产链定源零误伤"只覆盖默认扫描链，"扫描链不产生 '-'"不足以证明公共契约零误伤——消歧须落在入口（DR-04-B v3 推荐方案）。
2. **入径核查（Stop Condition）**：携带 `'-'` 进 wire 的公开入径共三条（`build_semantic_top_n(facts)` / `ram_wire_payload` 直构 `SemanticTopNResult` / wire dict 直入 validate），全部纳入 v3 设计；`lima/semantic_retrieval.py:1279` 的 `SemanticCandidate` 为检索层同名异类，非入径（全树 grep + 逐源亲验，Packet §9.6）。
3. **RED D1'''''**：`_red_proof` **39 failed / 4 passed**（新增 X8-1/X8-2 两例目标缺失型 RED：两入口当前接受 '-'；X8-0 真实扫描全链往返 GREEN 锚通过）；回归锚 801 + golden 15 维持。
4. **RED D1''''''（R6）**：`_red_proof` **43 failed / 4 passed**（X8-1 展开为五类 facts 清单各一例 X8-1a..e，逐例准确错误码 INVALID_FIELD_VALUE + 准确字段位置 `$.facts.<section>[i].symbol`；X8-2 同口径增强；签名均目标缺失型）；回归锚 801 + golden 15 维持（R6 工作树亲跑）。
