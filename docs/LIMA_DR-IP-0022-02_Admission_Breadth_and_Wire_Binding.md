# Decision Record DR-IP-0022-02：拦截口径启发式超集 + wire 载荷完整性绑定（重开 DR-IP-0022-01 的两项修订）

- DR 编号：DR-IP-0022-02（2026-09-13，PKT-IP-0022-D1R2，Assignment `IP-0022-PV-P1R2/v1`；Coordinator 裁定 DR-IP-0022-02/v1 经主会话转达授权）
- 触发事件：Maintainer 驳回 PR #180；驳回面（经 Coordinator 复核）含 F1 拦截口径不足（`token_FAKESECRET123.py`、`sk_live_ABC123xyztoken.py` 不被五 token 形状口径命中）与 F2 wire 校验未绑定载荷内容
- 上游关系：重开 DR-IP-0022-01（其状态行已同步改写为 REOPENED，存活/被替代条款见 §4）；Packet 升版 `IP-0022-PACKET/v2`
- 状态：RESOLVED-COORDINATOR（两项子提案——§3.5 残余风险记录口径与 §5 R1 内部留痕方案——标注**提案待 Maintainer 终裁**）

## 1. F1 契约修订：拦截口径改为启发式超集

### 1.1 新口径（冻结单解）

`is_secret_shaped_path(path)` 对 basename 启用**启发式超集**检测，三族判据任一命中即拒绝：

1. **关键词族**（段边界匹配，容忍复数）：basename 的任一 `[_\-.]`（或串首/串尾）界定的段等于（或复数形式等于）`token|secret|key|password|passwd|credential|apikey|api_key|private[_-]?key`（不区分大小写）。段边界限定使 `tokenizer.py`、`keyboard_layout.py`、`monkey_patch.py`、`keynote.md` 不命中（误伤负例集，冻结断言）。
2. **服务商前缀族**：`sk_live_` / `sk_test_` / `AKIA[0-9A-Z]{16}` / `ghp_[0-9A-Za-z]{36,}` / `gho_[0-9A-Za-z]{36,}` / `github_pat_[0-9A-Za-z_]{20,}` / `xox[baprs]-[0-9A-Za-z-]{10,}` / `id_(rsa|dsa|ecdsa|ed25519)([._\-][0-9A-Za-z_.\-]*)?`（SSH 私钥命名族，复审补录——Coordinator 实测 `id_rsa.pem` 为原冻结集唯一 POS 漏项）/ JWT `eyJ…`（同 `_SECRET_TOKEN_PATTERN` 口径）/ `-----BEGIN [A-Z ]*PRIVATE KEY-----`。
3. **高熵段族**：basename 含 ≥20 字符的无分隔 base62 连续段（`(?<![A-Za-z0-9])[A-Za-z0-9]{20,}(?![A-Za-z0-9])`）。

冻结 regex（Packet v2 §3 逐字收录，实现以此为准）：

```python
_SECRET_FILENAME_PATTERN = re.compile(
    r"(?i:(^|[_\-.])(token|secret|key|password|passwd|credential|apikey|api_key|private[_-]?key)s?([_\-.]|$))"
    r"|sk_live_[0-9A-Za-z]+"
    r"|sk_test_[0-9A-Za-z]+"
    r"|AKIA[0-9A-Z]{16}"
    r"|ghp_[0-9A-Za-z]{36,}"
    r"|gho_[0-9A-Za-z]{36,}"
    r"|github_pat_[0-9A-Za-z_]{20,}"
    r"|xox[baprs]-[0-9A-Za-z-]{10,}"
    r"|id_(rsa|dsa|ecdsa|ed25519)([._\-][0-9A-Za-z_.\-]*)?"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}"
    r"|(?<![A-Za-z0-9])[A-Za-z0-9]{20,}(?![A-Za-z0-9])"
)
```

### 1.2 超集断言（替代 DR-IP-0022-01 的逐字符等值断言）

冻结测试不再断言与 `_SECRET_TOKEN_PATTERN` 等值，改为：**五 token 形状全命中**（超集下界）+ **两驳回样本必命中**（`token_FAKESECRET123.py`、`sk_live_ABC123xyztoken.py`）+ **误伤负例集必不命中**（`tokenizer.py`、`tokenization.py`、`keyboard_layout.py`、`monkey_patch.py`、`keynote.md`、`api.py` 及 golden fixture 名等——Packet v2 §6 M1' 为定稿冻结集）。

### 1.3 公开面与绕过路径（写实）

- **公开面**（Packet v2 §0 明写）：NFR-01 保护面 = prompt 文本 + RAM facts / Top-N / wire payload（保守维持 v1 四层承诺，不收窄）。
- **绕过路径**：直接调用语义层（`build_semantic_top_n`）处理已构造 facts 属内部 API 误用——候选已越过准入点，本 IP 不防御；`semantic_prioritizer` 为冻结 Do-not-touch（Known Gaps 记录）。
- **goldens 零命中核验**（本 DR 制作期亲验，2026-09-13）：启发式对 `tests/audit/fixtures/golden_matrix/**`（五形状全部路径）与 `repo_shapes.py` 全量文件名**零命中**；唯一 fixture 命中为 IP-0018 `ram/shapes.py:192` 的 `secret.py`（`SECRET_REPO`，本身即秘密形态语义命名，非 golden；其冻结用例 `test_no_secret_in_facts` 在新行为下保持绿——断言"秘密值不入 facts"，准入拒绝后平凡满足且防御增强）。未触发停止条件。

### 1.4 残余风险声明（提案，待 Maintainer 终裁；逐字进入 Packet v2 §2 与 PR 模板）

> 本修复将秘密形态文件名拦截从五类已知 token 形状扩展为启发式检测（关键词/前缀家族/高熵段），覆盖已知样本与常见服务商格式，但不构成穷尽式秘密检测；未能命中的新形态仍可能进入审计产物。NFR-01 在本 IP 的贡献应记录为"已知形状与常见启发式口径下的文件名泄漏面关闭"，不得记录为 NFR-01 零泄漏已修复。

## 2. F2 校验目标修订：路线 B'（载荷完整性由 identity digest 重算比对承担）

### 2.1 可行性核验结论（制作期实证，@30bdfaa，2026-09-13）

Coordinator 授权先行验证，结果**两项均可行，无需降级**：

- **(i) ram_facts_digest**：`ram.py:415-430` 的 digest payload 与 wire `ram` 段（`ram_schema.py:446-462`）字段集与取值逐项对齐（`compute_content_digest` 为 canonical 排序，键序无关）。实证：`compute_content_digest(payload["ram"]) == ram_facts_digest(facts)` = True。
- **(ii) semantic_result_digest**：`_config_digest_payload`（prioritizer:624-638）所需 `top_n/weights/tie_break/seed/budgets` 全部在 wire `build.semantic`，`prompt_digest` 取 `identity.prompt_digest`，`model_digest` = `compute_content_digest(build.semantic.model_id)`（与 `identity.model_digest` 等值）；`_result_digest`（:640-660）所需 `ranked`（六字段子集）、`total_candidates`、`coverage_gaps` 全部在 wire `semantic` 段，`input_facts_digest` 取 (i) 重算值。实证：config 重算 = True、result 重算 = True。**不降级为仅 ranked 路径绑定。**

### 2.2 冻结接口（Packet v2 §3 F2 节收录）

`validate_ram_wire_payload` 在既有结构校验后、按以下顺序追加（wire_digest 检查保持末位——DR-IP-0022-01 R-2 约束延续）：

1. path 检查（v1 F2(i) 不变）；
2. `ram_facts_digest_from_wire(payload)`（新增 dict 侧 helper，`compute_content_digest(payload["ram"])`，序列化口径与 ram.py:415 对齐）≠ `identity.ram_facts_digest` → `ContractError(INVALID_FIELD_VALUE, "$.identity.ram_facts_digest")`；
3. `semantic_config_digest_from_wire(payload)` ≠ `identity.semantic_config_digest` → 同法 `$.identity.semantic_config_digest`；
4. `semantic_result_digest_from_wire(payload)`（input_facts_digest 取步骤 2 重算值）≠ `identity.semantic_result_digest` → `$.identity.semantic_result_digest`；
5. `identity.wire_digest` 重算比对（v1 F2(ii)）→ 末位。

冻结测试断言：三个新 helper 对同一已构建链的真实 payload 重算值分别等于 `ram_facts_digest(facts)` / `semantic_config_digest(options)` / `semantic_result_digest(result, input_facts_digest=…)`。

### 2.3 校验目标声明（Packet v2 明写）

- `wire_digest` = **传输头校验**（覆盖 build + identity 槽位），不验证载荷内容；
- 载荷完整性由 identity digest 重算比对承担：**ram 段全覆盖；semantic 段全覆盖**（ranked/total_candidates/coverage_gaps + config 绑定；§2.1 实证支持）；
- 不改任何 digest 值、不改 `ram_wire_digest` 算法、不触发 IP-0021 重冻结。

### 2.4 新负例 M17（+ semantic 变体）

- **M17**：篡改 `ram.sensitive_sinks[i].path` 为另一合法 repo-relative POSIX 路径 + 以 `ram_wire_digest(payload)` 同步重算并回填 `identity.wire_digest` → 校验**仍须失败**（`$.identity.ram_facts_digest`，证明"同步刷新传输头摘要不能洗白载荷篡改"）。
- **M17-semantic**：同法篡改 `semantic.ranked[0].rationale` + 同步 wire_digest → 仍须失败（`$.identity.semantic_result_digest`）。
- 两例在 D1' RED 中均以"ContractError not raised"签名失败（基线亲验）。

### 2.5 已否决路线补录

**full-payload digest 扩展**（改 `ram_wire_digest` 算法使 wire_digest 覆盖全部载荷——连带 golden 全量变更与 IP-0021 重冻结）：除非 B' 被证不可行不得启用；启用即新 DR。本 DR §2.1 已证 B' 可行，故该路线维持否决。

## 4. DR-IP-0022-01 的重开与条款处置

状态改写（DR-01 状态行）：`REOPENED（由 DR-IP-0022-02 于 2026-09-13 重开；原 PROPOSED 于 ENTRY60 复审期生效为 RESOLVED，因合并驳回发现 F1/F2 缺口重开；存活条款见 DR-IP-0022-02 §4）`。

- **存活条款**（继续有效）：不改 candidate_id / digest 算法 / golden 期望值；skip 汇总 count-only 公开口径（待 R1 终裁）；`_skip_reason_gaps` 分流零改动；缺口 1/2 的既有冻结断言授权修订（minimal-payload arrange 回填 + 词汇表扩词，含 R-2 末位约束）；已否决路线（prompt/wire 层掩码、workspace.py 遍历层 skip、逐文件枚举被拒路径）。
- **被替代条款**：五 token 形状逐字符等值口径（→ §1 启发式超集）；"四层不出现"的绝对承诺措辞（→ 加 §1.4 残余限定）；F2 校验范围"仅 path + wire_digest"（→ §2 五步序列）；`_SECRET_FILENAME_PATTERN` 等值断言（→ §1.2 超集断言）。

## 3. R1 整合（提案，待 Maintainer 终裁；Packet v2 §11 为执行面）

- **公开面**：count-only 汇总（`reason=sensitive-filename; count=N`，模板不变）+ shape 家族计数（`families=keyword:1` 式后缀，仅报家族名，不含任何文件名原文——家族后缀入 detail 属本提案的一部分，未获批则维持纯 count-only）。
- **FR-01 逐项满足面（内部记录）**：准入拒绝处生成 `AdmissionSkipRecord(redacted_id=f"redact:{sha256(basename.encode())[:8]}", family=…)`，挂载于 `ProfileBuildResult` / `RamFactsBuildResult` 新增默认空字段 `admission_skips`（`lima/audit` 层 dataclass，非 contracts 载体、不入 wire payload；默认 `()` 保持既有构造合法）。内部留痕不含原文件名。
- **否决分支**：若 Maintainer 否决 → 回退纯 count-only，并明示修订 FR-01 满足面声明（不新增 `admission_skips` 字段）。

## 5. 影响面与验收耦合

- 产品面与 Packet v2 §3/§6 一致：`lima/audit/{inventory,ram,ram_schema,__init__}.py`；冻结测试面 = `tests/audit/test_ip_0022_fix.py`（新）+ DR-01 已授权的两处既有断言修订；semantic_prioritizer / contracts / schemas / golden 零改动。
- 验收：Packet v2 §6 用例矩阵 M1'-M17(s) 全绿 + 回归锚（tests/audit+contracts 801、golden matrix 15、`git diff 30bdfaa -- tests/audit/fixtures schemas` 为空）。
- PI-DR6：D2 冻结前非 Windows 平台完整跑一次（含 M1' 误伤负例集的平台无关性——纯字符串断言，无平台依赖）。
