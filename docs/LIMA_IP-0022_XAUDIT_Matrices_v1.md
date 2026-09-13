# IP-0022 XAUDIT 可核查矩阵（PKT-IP-0022-XAUDIT，2026-09-13）

> 文档类型：审查矩阵（P&V 制作，供 Maintainer 逐行核查）
>
> 依据：Assignment `IP-0022-PV-XAUDIT/v1`；Packet `IP-0022-PACKET/v4`；DR-IP-0022-04
>
> 行为口径：main=`30bdfaa13ac72572d65ccb2567ae8702923c4187`（实测）；v3=Packet v3 修复后；v4=Packet v4 修复后（含 DR-04-A/B 门控项，标注【DR-04-X】者为未获批不实施）
>
> 本文档全部"main 实测"结论均由 `_red_proof/probe_xaudit.py`、`_red_proof/test_ip_0022_xaudit_red.py`（D1'''）与 `_red_proof` 探针脚本在本 worktree（@3735cbe，lima/** 与 main 等同）复现。

## 矩阵一：输入来源 → 公开输出 → 拦截点 → 负例

公开输出面（在 v3"五面"基础上按携带通道细分）：
- **S1** Profile entrypoints；**S2** Profile code_roles；**S3** Profile coverage_gaps detail（含 MANIFEST_PARSE_ERROR / BUDGET_EXHAUSTED / INVENTORY_SKIPPED 模板）；**S4** Profile `to_dict()` 全文序列化（= S1∪S2∪S3∪声明面）；**S5** RAM facts 六清单 + labels/rule_ids/cwes + coverage_gaps；**S6** Top-N ranked（candidate_id/kind/path/symbol/…）；**S7** 模型 prompt 文本；**S8** wire payload（ram 段 = S5 全量、semantic 段 = S6 + total + gaps、build 段、identity、provenance、execution_required）。

| # | 输入来源 | 公开面 | main 实测行为 | v3 修复后 | v4 修复后 | 负例（测试 ID） |
|---|---|---|---|---|---|---|
| I1 | 敏感 **basename** 代码文件（`tests/token_FAKESECRET123.py`、`ghp_….py`） | S2/S4/S5/S6/S7/S8 | **泄漏**：code_roles（CodeRole.TEST）、RAM sensitive_sinks、Top-N、prompt、wire 全链携带 | basename 准入过滤（§3.2 三点），五面拦截 | 同 v3；跨命中去重（X5-1） | G1-1/2/3、M2-M10（D1'' 已冻结面）；X5-1 |
| I2 | 敏感 **目录段**、良性 basename（`tests/secrets/anything.py`、`secrets/danger.py`） | S2/S4/S5/S6/S7/S8 | **泄漏**：实测 `tests/secrets/anything.py` 入 code_roles；`secrets/danger.py` 入 RAM sinks（probe P-X1/P-X2） | **仍泄漏**（v3 仅查 basename） | **检测扩为路径每段**（§3.1 v4）：任一段命中即拒；与 I1 同面拦截 | X1（code_roles 段泄漏）、X2（RAM 段泄漏） |
| I3 | 敏感目录内 **固定名 manifest 解析失败**（`token/pyproject.toml` 非 UTF-8 / 坏 TOML） | S3 → S4 → S8 | **泄漏**：`MANIFEST_PARSE_ERROR` detail=`manifest=token/pyproject.toml; error=UnicodeDecodeError`（IP-0016 冻结模板 `manifest={relative_path}`，probe P2f 实测） | v3 未覆盖（准入过滤不作用于 manifest gap） | 【DR-04-A】detail 路径 redact（替换为不含原文的定长哨兵/错误类型保留），未获批前维持现状并记入残余风险 | X3-1 |
| I4a | 敏感命名 **requirements 通配 manifest**，内容损坏（非 UTF-8 / stat 失败） | S3 → S4 → S8 | **泄漏**：实测 `manifest=requirements-ghp_AAAA….txt; error=UnicodeDecodeError`（probe P2e） | v3 未覆盖 | 【DR-04-A】同 I3 | X3-1 变体（requirements 形态，见矩阵附注） |
| I4b | 敏感命名 requirements 通配 manifest，正常可读内容（任意文本，含"坏"依赖行） | S3/S4 | **不泄漏文件名**：`_parse_manifest` 对 requirements* 不做结构校验（只 `package_managers.add("pip")` 常量锚 + 按行扫框架关键词），文件名不进任何公开面（probe P2b/P2c 实测 gaps 为空） | 同 main | 同 main（**结构性事实，非防御承诺**：不校验 ⇒ 无错误通道 ⇒ 无文件名携带；代价是内容关键词可进 frameworks 声明，属内容自由文本面 I9） | 无负例（记录性事实） |
| I5 | 超限 manifest（敏感命名，`manifest_max_bytes` 触发） | S3 → S4 | **泄漏**：`BUDGET_EXHAUSTED` detail=`manifest={relative_path}; bytes=…`（inventory.py `_load_one_manifest`，实测见 X3-2 arrange） | v3 未覆盖 | 【DR-04-A】同 I3 | X3-2 |
| I6 | RAM candidates（全部 `.py`，含敏感命名/敏感目录段） | S5 → S6 → S7 → S8 | 泄漏（D1'' M2 实测：`ghp_….py` 入 sensitive_sinks） | v3 §3.2.3 过滤（basename） | 段级过滤 + RAM-only 构建同样留痕（`RamFactsBuildResult.admission_skips`） | M2-M5、X2、X5-2 |
| I7 | semantic 候选（由 RAM facts 派生） | S6/S7 | 随 I6 泄漏 | 上游过滤后不出现 | 同 v3；直调 `build_semantic_top_n` 处理已构造 facts 仍属内部 API 误用，不设防（Known Gap，§2） | M6/M7 |
| I8 | manifest scripts 声明的入口目标解析到敏感路径（`cli = "pkg.token_x:main"`） | S1 → S4 → S8 | **可泄漏**：`_resolve_script_target` 按 module 逐段回退解析，不查敏感形态 | v3 §3.2.1 过滤（script-declared 与 root-convention 同滤） | 段级过滤同滤 | M7 |
| I9 | 自由文本：模型 rationale、manifest/源码内容关键词（frameworks 声明）、model_id | S6/S8、S4、S8 build | rationale 有 `_bounded_rationale` 三重防线（NFC+去控制字符+`_SECRET_TOKEN_PATTERN`+代码片段模式+512B 截断，malformed 回落 fallback）；frameworks 关键词与 model_id 无秘密筛 | 同 main（rationale 防线属 IP-0018/0019 冻结面，本 IP 不改） | 同 main；**范围外声明**：`_SECRET_TOKEN_PATTERN` 是五 token 形状冻结子集，非启发式超集——模型把秘密文本写进 rationale 且非五形状时可能通过；model_id 为配置面非仓库输入。NFR-01 保持 PARTIAL 的依据之一 | 无新负例（DR-04 §范围外清单） |
| I10 | Profile 声明面（languages/package_managers/frameworks/kinds） | S4 | 值均为封闭词表或常量锚（`pip`、`go-modules` 等），不携带文件名/路径；frameworks 关键词见 I9 | 同 main | 同 main | 无（结构性事实） |
| I11 | Profile entrypoints（root-convention 固定名 `cli.py/main.py/__main__.py`） | S1 | **结构性不含敏感命名**：候选集是固定名常量，敏感命名文件进不了 root-convention（probe P5 实测 `cli_ghp_*.py` → entrypoints 空）；但**目录段**可经 script 解析进入（I8） | 同 main（结构性）+ I8 过滤 | 同 v3 | M7（script 路径）、无 root-convention 负例（结构性） |

矩阵一附注（主会话五项探针观察的独立复验与解释）：

1. **code_roles 泄漏复现** ✓：`tests/token_FAKESECRET123.py` → CodeRole.TEST（main 实测，X1/G1-1 同 shape）。成因：`_code_role_assignments` 迭代 `sorted(evidence)` 无过滤。
2. **`secrets/pyproject.toml` 坏 TOML "未泄漏"——探针结论需勘正**：主会话以 FAKESENTINEL 子串判定"未泄漏"，属**哨兵口径假阴性**。实测 gap detail=`manifest=secrets/pyproject.toml; error=TOMLDecodeError`——目录段 "secrets" **已进入公开 Profile coverage_gaps**（probe P2）。既非 manifest 候选构造限制，也非防御语义，而是 IP-0016 冻结 detail 模板的**真实泄漏面**（→ DR-04-A）。
3. **`requirements-ghp_….txt` 坏内容不触发 MANIFEST_PARSE_ERROR** ✓ 属实且**按构造必然**：requirements* 分支无内容解析器（`_parse_manifest` 仅 `add("pip")` + 行级关键词），MANIFEST_PARSE_ERROR 只由 stat/read 失败（OSError/UnicodeDecodeError）或特定解析器异常（TOMLDecodeError/JSONDecodeError/ParsingError）触发；正常内容时 package_managers evidence 为常量锚 `pip`，不携带文件名。但**读取失败路径会泄漏全文件名**（P2e 实测）。
4. **`DEFAULT_IGNORED_DIRECTORIES` 不含敏感目录名** ✓（workspace.py:19-25 亲验）：目录级遍历防御缺位是事实；v4 以准入层段级检测补位（与已否决的"workspace.py 遍历层 skip"路线不冲突——过滤仍在 lima/audit 准入点）。
5. **entrypoints 来源=固定名** ✓（`_ROOT_ENTRY_CANDIDATES` 常量 + scripts 解析）：结构性不含敏感命名，非防御承诺（I11）；敏感路径可经 scripts 解析进入（I8/M7 已设防）。

## 矩阵二：wire 字段 → 绑定机制 → 篡改变体

绑定机制图例：**[Struct]**=IP-0021 冻结结构校验（键封闭/类型/词表/cap/rank 连续/平行数组/枚举）；**[Path]**=路径规则（v3 引入，v4 强化）；**[CID]**=candidate_id 一致性（v4，【DR-04-B】）；**[RamD]**=ram_facts_digest 重算（ram 段 canonical 全量）；**[CfgD]**=semantic_config_digest 重算；**[RstD]**=semantic_result_digest 重算；**[MdlD]**=model_digest 重算（v3/G2b）；**[WireD]**=wire_digest 传输头（build+三 identity 摘要 re-wrap，末位）。

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
| `semantic.ranked[i].kind/path/symbol` | [Struct] str/None + **[Path]**（path）+ **[CID]**（v4：candidate_id ≡ `f"{kind}:{path}:{symbol or '-'}#{ordinal}"`，ordinal ≥ 0 数字）+ [RstD]（经 candidate_id 传递） | **关键缺口（main 与 v3 均不设防）**：`_result_digest` payload 不含 kind/path/symbol——改 kind/path/symbol 而不动 candidate_id，三摘要与 wire_digest 全部保持有效！v4 [CID] 补绑：prefix=`kind:path:`、tail=`rsplit("#",1)` → (symbol or "-") + 非负数字 ordinal（X4-1/2/3；实测 real-chain 零误伤） |
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

1. **R-1 manifest gap detail 模板携带全路径**（I3/I4a/I5）：IP-0016 冻结面，DR-04-A 提请；未获批前 `manifest={relative_path}` 原样公开。
2. **R-2 rationale/内容自由文本**（I9）：`_SECRET_TOKEN_PATTERN` 五形状子集非启发式超集；模型生成文本中的新形态秘密可过 malformed 回落之外的筛；frameworks 关键词、model_id 同属自由文本配置面。
3. **R-3 防恶意重签**：摘要自洽比对非认证（§3.5 定位声明；持有 canonical 编码者可整体重算）。
4. **R-4 直调内部 API**：`build_semantic_top_n` 处理已构造 facts 不设防（Known Gap §2）。
5. **R-5 启发式非穷尽**：新形态文件名/目录段可漏检（§2 残余风险声明，NFR-01 PARTIAL 依据）。
6. **R-6 wire path 无长度 cap**（矩阵二附注）：与 #58 契约的宽度差异，结构性 cap 已限列表项数。
7. **R-7 FR-01 PARTIAL**：`admission_skips` 内部留痕首版仅覆盖 `sensitive-filename` 一类 reason。
8. **R-8 workspace 遍历层**：`DEFAULT_IGNORED_DIRECTORIES` 不含敏感目录名（事实维持）；防御位置在 lima/audit 准入层（v4 段级），非遍历层（否决路线 §12.3）。
