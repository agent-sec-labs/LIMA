# Implementation Packet IP-0022 — #60-Fix：关闭前阻断修复（F1 秘密形态文件名准入期拒绝 + F2 wire 校验器加固）

> 文档类型：Implementation Packet（P&V 制作）
>
> Packet 版本：`IP-0022-PACKET/v4`
>
> 修订历史：v1（2026-09-13，PKT-IP-0022-D1，commit 70946e1）；v1 微修（PKT-IP-0022-D1R，R-1/R-2，commit 00093396）；v2（PKT-IP-0022-D1R2，DR-IP-0022-02/v1）；v3（PKT-IP-0022-D1R3，DR-IP-0022-03）；**v4（2026-09-13，PKT-IP-0022-XAUDIT，DR-IP-0022-04：Maintainer 四项核清——段级检测（§3.1）、AdmissionSkip 语义定稿（§3.2/§3.3）、wire path 规则补齐两处弱于 + candidate_id 一致性【DR-04-B 门控】（§3.5）、MINIMAL_PAYLOAD 五摘要全真值定稿（§3.5）+ X 系负例（§6）+ RED D1'''（§9）+ 两张可核查矩阵（随批文档）**。
>
> 状态：`READY-FOR-CODE`（TBD = 0；DR-04-A/B 两项**冻结面变更请求待裁定**，未获批前不实施且不属 mandatory——见 DR-IP-0022-04 §2）
>
> Exact base：`30bdfaa13ac72572d65ccb2567ae8702923c4187`（origin/main，IP-0021 merge）
>
> 制作人：lima-packet-verification（Assignment `IP-0022-PV-P1/v1` → `P1R2/v1` → `P1R3/v1`，任务标识 `PKT-IP-0022-D1` / `D1R2` / `D1R3`，2026-09-13）
>
> 上游决策：COORD `ENTRY60-CLOSURE-1/v1`（拆分方案 α）；DR-IP-0022-01（REOPENED）；DR-IP-0022-02（REOPENED-by-03 / 部分 SUPERSEDED）；DR-IP-0022-03（RESOLVED-MAINTAINER）；**DR-IP-0022-04（OPEN，v4 执行依据；A/B 冻结面请求待裁定）**；PI-DR1..PI-DR6 全部生效
>
> 随批文档：DR-IP-0022-01、DR-IP-0022-02、DR-IP-0022-03、**DR-IP-0022-04**、C1 勘误（`LIMA_DR-C1_ENTRY60-CLOSURE-1_Erratum_2026-09-13.md`）、**`LIMA_IP-0022_XAUDIT_Matrices_v1.md`（两张可核查矩阵 + 探针复验 + 残余风险清单）**

---

## 0. Header（生命周期 §8）

```text
Source Issue：#60（[V4-I04][P0] Repository Profile、RAM 与安全语义清单，V5 覆盖层版）
Issue specification revision：2026-09-13 Issue #60 正文（含 ENTRY60-CLOSURE-1 入账；API 亲取复核）
公开面定义（v3，五面）：NFR-01 保护面 = Profile（entrypoints + code_roles，含 to_dict() 全文序列化）+ RAM facts + Top-N + prompt 文本 + wire payload
Covered requirements（本 IP 只声明自身贡献）：
  NFR-01 扩展口径（DR-01 存活 + DR-02 §1 + DR-03 §2/§3）：启发式超集口径下的秘密形态文件名不在五面出现——贡献记 PARTIAL（Maintainer 终裁，§2），不得记"零泄漏已解决"
  FR-04 补全（DR-02 §2 路线 B' + DR-03 §4 + DR-04 §1/§2-B）：wire 载荷完整性 = path 拒绝（v4 段级规则对齐 #58 不弱于）+ ram/semantic/model identity digest 重算比对 + candidate_id↔kind/path/symbol 一致性【DR-04-B 门控】 + wire_digest 传输头校验（末位）；认证定位见 §3.5
  FR-01（R1 终案，§3.3）：公开面 reason→count；内部扫描内序号留痕——覆盖全部跳过原因前记 PARTIAL
Not covered requirements：F3 workspace _safe_path TOCTOU、F4 回包/时间不设防（→ IP-0023 closure 负例）；S4b/T-03/V5 端到端；#64/#68 消费验证；防恶意重签认证（§3.5 定位声明）；直调语义层（build_semantic_top_n）处理已构造 facts 的内部 API 误用防御（Known Gaps §2）；穷尽式秘密检测
Delivery role：hardening-fix（冻结面内最小防御 + 冻结测试面 DR 授权修订）
Issue closure impact：PARTIAL（解除两项关闭前阻断；Issue 关闭权在 Coordinator/Maintainer；NFR-01/FR-01 均按 PARTIAL 口径入 Ledger）
Upstream IP/PR/merge commits：IP-0016（fd219724）、IP-0018（cc17662）、IP-0019（e000e6f）、IP-0020（#176）、IP-0021（30bdfaa，#179）；PR #180 两次驳回（修订对象）
Upstream ruling：ENTRY60-CLOSURE-1/v1 + DR-IP-0022-02/v1 + DR-IP-0022-03（已否决路线见 §12）
```

## Design Input Manifest

1. 三份治理正典（P&V 责任书 v1.1、开发交接标准、生命周期）；2. Coordinator Assignment `IP-0022-PV-P1/v1` / `P1R2/v1` / `P1R3/v1`（含 DR-02 六项指令与 DR-03 Maintainer 二次驳回落地指令）；3. Issue #60 正文（GitHub API 亲取，含 ENTRY60-CLOSURE-1）；4. 四层冻结面 @30bdfaa（`lima/audit/**`、`tests/audit/**`、`schemas/v4/**`）；5. 既有 Packet IP-0016/0018/0019/0020/0021；6. DR 链（DR-IP-0022-01/-02/-03、DR-IP-0021-0102、DR-IP-0020-2/3、DR-IP-0016-02）；7. PI-DR1..DR6；8. 主会话三重亲验记录 + 两次驳回面（两样本、code_roles 泄漏复现、MINIMAL_PAYLOAD 零占位与 217f735a 重算值）。

## Explicitly Rejected Inputs

- prompt / wire 层掩码 path（ENTRY60-CLOSURE-1 否决）。
- full-payload digest 扩展（改 `ram_wire_digest` 算法、golden 全量变更、IP-0021 重冻结）——B' 已证可行，维持否决（§12）。
- `lima/workspace.py` 遍历层 skip；逐文件枚举被拒路径原文；`redact:<sha256(basename)[:8]>` 内部短标识与公开面 shape 家族计数（Maintainer 终裁否决，DR-03 §3）。
- F3/F4 修复草案（→ IP-0023）；`schemas/v4/**` 增改；`lima/contracts/**` 增改。

## 1. Goal / Non-goals

### Goal

1. **F1 准入期拒绝（启发式超集口径，三过滤点）**：AttackSurfaceEntry/CodeRoleAssignment 候选生成处——profile `_build_entrypoints`、**profile `_code_role_assignments`（v3 新增，G1）**、RAM `candidates` 文件集——以 `is_secret_shaped_path`（三族判据，§3.1）检测 basename，拒绝进入候选集/角色集，skip reason `sensitive-filename` 汇总（公开面 reason→count；内部扫描内序号留痕，§3.3）。
2. **F2 载荷完整性绑定（路线 B' + model_digest）**：`validate_ram_wire_payload` 六步序列——path 检查 → `ram_facts_digest` → `semantic_config_digest` → `semantic_result_digest` → **`model_digest`（v3 新增，G2b）** → `wire_digest`（**末位**，DR-01 R-2 约束延续）。
3. 冻结测试面 DR 授权修订：词汇表扩词；`MINIMAL_PAYLOAD` 迁移为四 digest 自洽正例（G2a）。

### Non-goals

- 不改 `candidate_id` 生成规则、任何 digest 算法与取值、golden fixtures 及期望值（回归锚：五形状 golden 原样通过）。
- 不改 `lima/audit/semantic_prioritizer.py`（含 `_SECRET_TOKEN_PATTERN` 本体与 `_render_prompt`）、`lima/contracts/**`、`lima/workspace.py`、`schemas/v4/**`、scanner/service、#64/#68 接线。
- 不做 F3/F4（→ IP-0023）；不宣称穷尽式秘密检测与防恶意重签认证（§2/§3.5）。

## 2. 残余风险与记账口径（Maintainer 终裁）与 Known Gaps

> **残余风险声明（逐字，进入 PR 模板与 Ledger）：本修复将秘密形态文件名拦截从五类已知 token 形状扩展为启发式检测（关键词/前缀家族/高熵段），覆盖已知样本与常见服务商格式，但不构成穷尽式秘密检测；未能命中的新形态仍可能进入审计产物。NFR-01 在本 IP 的贡献应记录为"已知形状与常见启发式口径下的文件名泄漏面关闭"，不得记录为 NFR-01 零泄漏已修复。**

**记账口径（DR-03 §3，终裁）**：IP-0022 对 NFR-01 的贡献**只记 PARTIAL**（启发式非穷尽 + 补上 Profile 泄漏面后仍不得写"零泄漏已解决"）；Ledger NFR-01 行在 IP-DONE 时按 PARTIAL 口径入账。FR-01 记 PARTIAL，直至内部逐项留痕覆盖全部跳过原因（§3.3）。

Known Gaps（写实）：

- **绕过路径**：直调语义层 `build_semantic_top_n` 处理已构造 facts，属内部 API 误用——候选已越过准入点，本 IP 不防御（`semantic_prioritizer` 为冻结 Do-not-touch）。v3 注记：此条不减轻上游过滤义务——G1 证明"把面列举成 Known Gap"不能替代对每个公开输出面的实际过滤，故 v3 补全 code_roles 过滤点。
- 高熵段判据的误伤/漏检权衡：≥20 字符无分隔 base62 为经验阈值（对全部 golden fixture 与 tests/audit 文件名字面量零误伤，v3 制作期复验，§9；唯一 fixture 命中为 IP-0018 `SECRET_REPO` 的 `secret.py`，语义上本即秘密形态命名，其冻结用例保持绿）。

## 3. 冻结接口清单（实现必须逐字对齐）

### 3.1 F1 — 检测口径与 helper（DR-02 §1.1 + 9bd6159 复审补录 `id_` 族）

`lima/audit/inventory.py` 新增：

```python
_SECRET_FILENAME_PATTERN: Final[re.Pattern[str]] = re.compile(
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

def is_secret_shaped_path(path: str) -> bool:
    """Heuristic superset check on the basename (DR-IP-0022-02 §1, DR-IP-0022-03 §2)."""
```

- **v4 段级语义**：对 path 的**每一段**（目录段 + basename，`path.split("/")` 全集）执行 search，任一段命中即 True；非 str/空串返回 False；从 `lima/audit/__init__.py` 导出。
- 断言口径：**超集断言**（五 token 形状全命中 + 两驳回样本 + `id_rsa.pem`/`id_ed25519` 命中 + §6 M1' 误伤负例集不命中 + **段级形态**：`tests/secrets/anything.py` 命中、`tests/tokenizer/anything.py` 不命中）；不与 `_SECRET_TOKEN_PATTERN` 等值。
- shape 家族归类仅用于内部留痕 `family` 字段（§3.3），不入公开输出。

### 3.2 F1 — 准入过滤点（v3：三处）

1. `_build_entrypoints(summary, inventoried)`：命中者不生成 entrypoint（script-declared 与 root-convention 同滤）。
2. **`_code_role_assignments(evidence, entry_targets, gaps)`（v3 新增，G1）**：迭代 `sorted(evidence)` 时跳过 `is_secret_shaped_path(relative_path)` 为 True 的路径，不生成 `CodeRoleAssignment`，计入 `inventory.skipped["sensitive-filename"]`。排序（`(role.value, path)`）与 `_MAX_CODE_ROLE_ASSIGNMENTS` cap/overflow 逻辑零改动（DR-03 §2 核验，无契约冲突）。
3. `build_python_ram_facts` 的 `candidates`（@ram.py:364-365）：过滤后进入 RAM 派生，五清单与 key_flows/labels 全部不含命中路径。
- 三点均保持 sorted 次序，过滤不得重排（ordinal 属 candidate_id，禁止漂移）。
- **v4 跨命中去重（DR-04 §1.2）**：同一 repo-relative path 在同一 build result 内只计一次 `sensitive-filename`（entrypoint 过滤与 code role 过滤共享去重集）；Profile 与 RAM 两个 build result 各自独立计数（语义=各自候选集的拒绝数）。**RAM-only 构建**（不经 Profile）同样过滤并留痕（§3.3）。
- **【DR-04-A' 门控】第四过滤点（manifest 候选）**：`_manifest_candidates`/`_load_manifests` 命名判定后对整条候选路径执行段级 `is_secret_shaped_path`，命中即跳过并计入 sensitive-filename skip 通道——统一闭合 MANIFEST_PARSE_ERROR / 读取失败 / 超限三类 detail 的文件名携带面（I3/I4a/I5，矩阵一）；零 IP-0016 冻结模板改动、零测试锚定修订（三处锚定清单见 DR-04 §2-A，A' 不触碰）、零 golden 影响；取舍=敏感命名 manifest 声明整体丢失（与代码文件同口径，损失经 skip 计数可观测）。未获批前不实施。

### 3.3 F1 — skip 汇总与内部留痕（R1 终案，DR-03 §3）

- **公开面（批准）**：仅 `reason → count`——`inventory.skipped["sensitive-filename"]` → 既有 `_skip_reason_gaps` 通道 → `GAP_INVENTORY_SKIPPED`，detail=`reason=sensitive-filename; count=N`（模板不变）。无 shape 家族输出。
- **内部逐项记录（终案设计）**：`AdmissionSkipRecord(index: int, reason: str, family: str)`——**扫描内序号 + reason + family，不带原文件名，不含任何 basename 派生摘要**（sha8 方案被否决）。挂载于 `ProfileBuildResult.admission_skips` / `RamFactsBuildResult.admission_skips`（默认 `()`，`lima/audit` 层 dataclass，不入 wire、不改 contracts）。
- **v4 序号与次序定稿（DR-04 §1.2）**：`index` = 该 build **过滤前 sorted 候选全序枚举下标**（Profile：`sorted(evidence)` 键序；RAM：`sorted(item.path for item in files if .py)` 序），0 基，与 `candidate_id` 的 ordinal 无关（candidate_id 为 Do-not-touch），同输入同序号可复现；`admission_skips`/`inventory.skipped` 写入必须发生在 `_skip_reason_gaps`（Profile）/`_coverage_gaps`（RAM）构造之前（不变量，X5 负例承载）。
- **FR-01 记 PARTIAL**：内部逐项留痕当前仅覆盖 `sensitive-filename` 一类；覆盖全部跳过原因（binary/size/limit/… 全 vocabulary）前 FR-01 满足面记 PARTIAL。

### 3.4 F1 — 词汇表扩展（DR-01 存活授权）

`_SKIP_REASONS` 增 `"sensitive-filename"`（第 11 词）；`SKIP_REASON_TO_GAP_DETAIL` 同步；`tests/audit/test_fr05_gap_encoding.py::FROZEN_SKIP_REASONS` 同步（集合等值断言强度不降）。

### 3.5 F2 — 校验序列（DR-02 §2.2 + DR-03 §4，路线 B'）

`lima/audit/ram_schema.py` 新增三个 dict 侧 helper（DR-02 §2.1 实证等值）：

1. `ram_facts_digest_from_wire(payload)`：`compute_content_digest(payload["ram"])`（对齐 ram.py:415-430）。
2. `semantic_config_digest_from_wire(payload)`：以 `build.semantic` + `identity.prompt_digest` + `compute_content_digest(build.semantic.model_id)` 按 `_config_digest_payload`（prioritizer:624-638）形状重组。
3. `semantic_result_digest_from_wire(payload)`：以 `semantic.ranked`（六字段子集）、`total_candidates`、`coverage_gaps` + `config_digest` + `input_facts_digest=（1 的重算值）` 按 `_result_digest`（prioritizer:640-660）形状重组。

`validate_ram_wire_payload` 在既有结构校验后依序追加（**六步**）：

- **path 检查（v4 强化，对齐 #58 `_validated_path` 段级语义不弱于）**：ram 五清单 entry 与 `semantic.ranked` 每项 path：非空 str、无 `\`、非 `/` 开头、无 `^[A-Za-z]:` 盘符、**无 Cc 控制字符、任一 `/` 段 ∉ {"", ".", ".."}**（v3 缺后两条，系弱于 #58 契约，v4 补齐；长度 cap 差异记残余风险 R-6）；违例 `ContractError(INVALID_FIELD_VALUE, "$.ram.<section>[i].path" / "$.semantic.ranked[i].path")`。
- **【DR-04-B 门控】candidate_id 一致性检查（第七项，获批后 mandatory）**：每个 `semantic.ranked[i]` 校验 `candidate_id ≡ f"{kind}:{path}:{symbol if symbol is not None else '-'}#{ordinal}"`——prefix=`f"{kind}:{path}:"` 前缀匹配 + `tail.rsplit("#",1)` 得（symbol 槽 = symbol 或 "-"，非负数字 ordinal）；违例 `$.semantic.ranked[i].candidate_id`。依据：`_result_digest` payload 不含 kind/path/symbol（semantic_prioritizer.py:640-660），无此检查时三字段篡改五摘要全不设防（X4 RED 复现）。real-chain 与 golden 零误伤已证（§9）。未获批前维持残余风险 R-9。
- `ram_facts_digest_from_wire(payload) != identity.ram_facts_digest` → `$.identity.ram_facts_digest`。
- `semantic_config_digest_from_wire(payload) != identity.semantic_config_digest` → `$.identity.semantic_config_digest`。
- `semantic_result_digest_from_wire(payload) != identity.semantic_result_digest` → `$.identity.semantic_result_digest`。
- **`compute_content_digest(payload["build"]["semantic"]["model_id"]) != identity.model_digest` → `$.identity.model_digest`（v3 新增，G2b；口径 = semantic_prioritizer.py:636，DR-03 §1(b) 核验无矛盾）。`prompt_digest` 不可从 wire 复原，经 config 比对传递性绑定。**
- `identity.wire_digest != ram_wire_digest(payload)` → `$.identity.wire_digest`（**末位**）。

**校验目标与认证定位声明**：`wire_digest` = 传输头校验（build + identity 槽位），不验证载荷内容；载荷完整性由 identity digest 重算比对承担（ram 段全覆盖；semantic 段全覆盖；model_id 绑定）。**摘要比对只证明字段自洽（防意外损坏/传输错配），不能当作防恶意重签的认证**（持有 canonical 编码能力者可整体重算；防重签不在本 IP 威胁模型内）。不改任何 digest 值，不触发 IP-0021 重冻结。

**MINIMAL_PAYLOAD 迁移（G2a，DR-01 授权条目升级；v4 定稿五摘要全真值）**：`tests/audit/test_ram_schema.py::MINIMAL_PAYLOAD`（定义 @:79，identity @:128-135，`HEX64="0"*64` @:39）identity **五个摘要槽全部改为真值**：`ram_facts_digest=compute_content_digest(payload["ram"])`、`semantic_config_digest=semantic_config_digest(SemanticOptions())`、`semantic_result_digest`=以 payload 自身 semantic 段按 `_result_digest` 形状重算（input_facts_digest 取 ram 槽重算值）、`prompt_digest=compute_content_digest(默认 prompt_template)`（不可从 wire 复原，真值口径即模板 digest）、`model_digest=compute_content_digest(model_id)`；`wire_digest` 随迁重算。正例断言"自洽载荷通过"；**独立保留**全零占位拒绝负例（G2-2）；既有结构/词表/rank 类负例逐个复核仍因预期原因失败（14 类核对表见矩阵文档"预期错误核对表"；末位约束保障摘要层不前置）。v4 迁移兼容锚 X6（五值互异、非占位、可重算）已在 D1''' 实测通过。

### 3.6 明确不改（Do-not-touch）

`candidate_id()`、`_render_prompt`、`_SECRET_TOKEN_PATTERN` 本体、`semantic_prioritizer.py` 全文件、`ram_wire_digest` 算法、golden fixtures、`schemas/v4/**`、`lima/contracts/**`、`lima/workspace.py`、其余 `lima/**`。

## 4. 文件边界

| 类别 | 文件 |
|---|---|
| Add | `tests/audit/test_ip_0022_fix.py`（D2 冻结落库；D1/D1'/D1'' 已 scratch RED） |
| Modify | `lima/audit/inventory.py`（§3.1-§3.4 含 `_code_role_assignments` 过滤 + `AdmissionSkipRecord`）、`lima/audit/ram.py`（§3.2.3 过滤 + `admission_skips`）、`lima/audit/ram_schema.py`（§3.5）、`lima/audit/__init__.py`（导出） |
| Modify（DR 授权冻结测试面修订，D2） | `tests/audit/test_fr05_gap_encoding.py`（扩词）、`tests/audit/test_ram_schema.py`（`MINIMAL_PAYLOAD` 四 digest 自洽迁移，用例 @:223-224；摘要检查末位约束 DR-01 R-2） |
| Read-only | 其余 `tests/**`、`schemas/**`、`docs/**` 既有文件、`lima/**` 其余 |
| Must-not-modify | `lima/contracts/**`、`schemas/v4/version_compatibility_matrix.json`、`lima/workspace.py`、`#94` 轨道一切（PR #178 零交集） |

## 5. 行为约束与恢复要求

- 网络禁止；文件系统仅测试临时 workspace；无数据库/容器/远端写。
- 确定性：过滤保持 sorted 次序与 ordinal 稳定；code_roles 排序/cap 语义零改动；digest helper 为纯函数。
- 危险/边界必验：三族判据正反例（M1'）、四层+Profile 排除（M2-M10、G1-1/2）、entrypoint script 目标（M7）、绝对路径双形态与 `..` 逃逸（M11-M14）、传输头同步洗白（M17/M17s）、摘要篡改/陈旧/model_digest 篡改（M15/M16/G2-1）、占位 digest 拒绝与自洽正例（G2-2+迁移正例）。
- 停止条件：需改 candidate_id/golden digest 才能表述的用例 ⇒ 停止提交 DR；B' canonical 隐藏不等价（D2 实现期若发现）⇒ 停止回报；启发式命中任一 golden fixture ⇒ 停止细化重提；code_roles 排序/cap 契约冲突（已核验无）⇒ 停止回报；冻结测试需变更 ⇒ 先 DR。

## 6. 最低用例矩阵（冻结测试集，23 例 + 迁移正例 + 回归锚）

RED 四轮证明：D1（16 例）、D1'（18 例）、D1''（23 例）、**D1'''（34 例，本版：v3 的 23 例 + X 系 11 例新负例）**，签名均为目标行为缺失（§9）。

| # | ID（D2 冻结名可微调，语义不得变） | 断言 |
|---|---|---|
| M1' | secret_shaped_path_helper_is_heuristic_superset | 超集断言：五 token 形状全命中；两驳回样本命中；前缀族扩展（gho_/sk_test_/github_pat_/xoxb-/id_rsa.pem/id_ed25519）命中；关键词族（my_secret/secrets/api_key/apikey/password_reset/credential_store/key.pem）命中；高熵段命中；误伤负例集（tokenizer/tokenization/keyboard_layout/monkey_patch/keynote/api/danger/safe/cli/application/library_profile_golden.json）不命中；basename 语义（pkg/ 前缀）+ **v4 段级语义（tests/secrets/x.py 命中、tests/tokenizer/x.py 不命中）** |
| M2-M10 | 同 v1 | RAM facts 三形状排除、词汇表扩词、typed gap count=1、entrypoint script 目标排除（safe 锚）、Top-N 排除、prompt 排除（model_id 激活捕获）、wire payload 排除 |
| M11-M16 | 同 v1 | 绝对 POSIX / Windows 盘符 / `..` 逃逸（entry 与 ranked）/ 摘要单字符篡改 / build 变更后陈旧摘要 |
| M17/M17s | 同 v2 | ram path / semantic rationale 篡改 + wire_digest 同步回填 → 仍失败 |
| M18 | digest_helpers_recompute_true_chain_digests | 三 helper 重算值 == 真实链 digest；`compute_content_digest(build.semantic.model_id) == identity.model_digest`（v3 增后半） |
| G1-1 | profile_code_roles_exclude_secret_shaped_filename | `tests/token_FAKESECRET123.py` 不入 code_roles（v3 新增） |
| G1-2 | profile_serialization_free_of_secret_shaped_filename | `profile.to_dict()` 全文无秘密文件名（v3 新增） |
| G1-3 | profile_secret_filename_skip_counted | code_roles 过滤计入 `reason=sensitive-filename; count=1` typed gap |
| G2-1 | model_digest_tamper_rejected | `identity.model_digest` 单字符篡改 → ContractError（v3 新增） |
| G2-2 | minimal_payload_placeholder_digests_rejected | 全零占位 MINIMAL_PAYLOAD 被拒（RED 形式；基线宽松为反锚） |
| G2-P | minimal_payload_self_consistent_migration_validates | **五 digest** 自洽迁移正例通过（D2 迁移后既有正例改造，基线与实现后均绿——迁移兼容锚，非 RED；X6 已在 D1''' 预证） |
| X1 | sensitive_directory_segment_excluded_from_code_roles | 敏感**目录段**（tests/secrets/anything.py）不入 code_roles（v4） |
| X2 | sensitive_directory_segment_excluded_from_ram | 敏感目录段（secrets/danger.py）不入 RAM 任何清单（v4） |
| X3-1/X3-2 | manifest_gap_detail_free_of_sensitive_path | MANIFEST_PARSE_ERROR / manifest 超限 detail 不携带敏感形态路径（**【DR-04-A'/A 门控】**，A'=manifest 候选准入过滤为建议优先项（零冻结面触碰），A=detail 脱敏为备选；获批任一后 mandatory；RED 已证 main 泄漏，X3-2 经 XAUDIT-FIX 勘正为目标缺失签名） |
| X4-1/2/3 | wire_candidate_id_kind_path_symbol_consistency | candidate_id 与 kind/path/symbol（含 symbol 槽、非负数字 ordinal）一致（**【DR-04-B 门控】**）；X4-0 锚：非数字 ordinal 由 IP-0021 冻结模式拒绝（基线即绿，防弱化） |
| X4-4/5/6 | wire_path_segment_rules | 空段（a//b）、`.` 段（./x）、Cc 控制字符 path 拒绝（v4 补齐 #58 契约两处弱于） |
| X5-1 | admission_skip_counted_once_per_path | 同一 path 命中 entrypoint+code role 只计一次（count=1、恰一个 typed gap） |
| X5-2 | ram_only_build_records_admission_skips | RAM-only 构建留痕 admission_skips（无 path 字段） |
| X6 | minimal_payload_five_digests_true_valued | 五摘要槽互异、非占位、可重算（迁移兼容锚，基线即绿） |
| R1-R2 | 回归锚 | golden matrix 15 绿 + `tests/audit`+`tests/contracts` 801 绿 |
| R3 | goldens 零命中核验锚 | 启发式（含 `id_` 族）对 golden 全部路径/repo_shapes 文件名零命中 |

注：M18/R3/G2-P/X4-0/X6 在 scratch 集中以实证与制作期扫描承担，D2 冻结集须补齐为可执行用例。

## 9.4 RED 证明（D1'''，v4）

- 测试文件：`_red_proof/test_ip_0022_xaudit_red.py`（X 系）+ 既有 `_red_proof/test_ip_0022_fix_red.py`（v3 的 23 例，签名复验不变）。命令：`python -m pytest _red_proof -q` @main 等同代码。结果：**34 failed / 3 passed**——X 系新签名：X1 `sensitive directory segment leaked into code_roles: ['tests/secrets/anything.py']`；X2 `['danger.py', 'secrets/danger.py']`（RAM sinks）；X3-1 `manifest parse-error detail carries the raw path: [… 'manifest=token/pyproject.toml; error=UnicodeDecodeError']`；X3-2 `manifest budget detail carries a secret-shaped basename: ['manifest=requirements-ghp_aaa….txt; bytes=8; limit=1']`；X4 系 `ContractError not raised`；X5-1 `expected exactly one gap: []`；X5-2 `admission_skips` 缺失。3 个通过项均为锚（X4-0 冻结模式锚、X6 两迁移兼容锚），非 RED。
- **勘正（PKT-IP-0022-XAUDIT-FIX，Coordinator 独立证伪轮）**：X3-2 首版有两处 arrange 缺陷（不存在的 kwarg `profile_budgets`，正确入参 `options=ProfileInventoryOptions(budgets=ProfileBudgets(manifest_max_bytes=1))`；`GHP_BASENAME[12:]` 切片切失 `ghp_` 前缀、敏感子串未进断言面），首版"无 arrange 型失败"表述对 X3-2 不成立、曾致全量短暂 33 failed / 4 passed。已修正并重跑：34 failed / 3 passed、X3-2 签名为目标缺失型（与 Coordinator 独立复现一致）。其余 33 例经本轮复跑确认无 arrange 型失败。
- **五项探针独立复验**（矩阵一附注）：第 2 项结论勘正——`secrets/pyproject.toml` 坏 TOML 的目录段 **"secrets" 实际泄漏**于 MANIFEST_PARSE_ERROR detail（哨兵口径假阴性），系 IP-0016 冻结模板泄漏面（DR-04-A）；`requirements-ghp_*.txt` 坏内容不触发 parse error 属构造性事实（无内容校验器），但**读取失败路径泄漏全文件名**（`manifest=requirements-ghp_AAAA….txt; error=UnicodeDecodeError`）。
- **goldens 零命中（v4 段级口径）**：fixtures 全量 JSON 路径值与 tests 源文件路径对段级启发式零命中（v3 已知 `ram/shapes.py:192 secret.py` 字面量命中维持既有结论：语义即秘密命名，IP-0018 冻结用例绿）。
- **新 wire 检查零误伤**：段级 path 规则 + candidate_id 一致性（ordinal ≥ 0）对 3 种 real-chain wire payload 零违例，且既有 `validate_ram_wire_payload` 全绿。
- 回归：`tests/audit tests/contracts` 801 passed；golden matrix 15 passed。
- **PI-DR6 双平台（D1''' 轮，已执行）**：Windows 本机全量 + docker Linux（python:3.12-slim，Linux x86_64，`pytest tests/audit tests/contracts` = 801 passed +318 subtests、golden 15 passed、`_red_proof` = 34 failed / 3 anchors——与 Windows 完全一致，平台无关实证）+ 临时分支 `pv/ip-0022-xaudit-pidr6`（@d32fd2e）GitHub Actions Linux CI 完整跑，run 34763112315 **completed/success**（https://github.com/agent-sec-labs/LIMA/actions/runs/34763112315）。

## 7. 缺口查证结论（v1 结论维持，行号经 R-1 勘正）

- 缺口 1：存在 1 处宽松接受冻结断言——`test_ram_schema.py::test_minimal_payload_validates`（@:223-224；MINIMAL_PAYLOAD @:79，identity @:128-135）。DR-01 授权 + DR-03 §1(a) 升级为四 digest 自洽迁移。
- 缺口 2：skip reason 词汇表为封闭冻结枚举（`test_fr05_gap_encoding.py:43-53,135`）。DR-01 授权扩词。

## 8. 验收命令与判定

```bash
python -m pytest tests/audit tests/contracts -q        # ≥801+23+X passed（X = v4 非 DR 门控新负例 X1/X2/X4-4..6/X5；X3/X4-1..3 随 DR-04-A/B 裁定计入），0 failed, 0 new skip
python -m pytest tests/audit/test_golden_matrix.py -q  # 15 passed（golden 原样）
```

判定依据：M1'-M18 + G1/G2 系全绿；R1-R3 全绿；`git diff 30bdfaa -- tests/audit/fixtures schemas` 为空；ruff/bandit 零新 finding。PI-DR6：D2 冻结前至少一个非 Windows 平台完整跑一次（M1'/G 系为纯字符串/纯构造断言，平台无关）。

## 9. RED 证明（D1 + D1' + D1''）

- D1（16 例）与 D1'（18 例）记录于 v1/v2 §9（commit 70946e1/00093396/4aa507c 轮）。
- **D1''（本版）**：测试文件 `D:\BaseAIProject\LIMA-ip-0022-pv-wt\_red_proof\test_ip_0022_fix_red.py`（scratch）。命令：`python -m pytest _red_proof/test_ip_0022_fix_red.py -q` @30bdfaa worktree。结果：**23 failed / 0 passed**——新增五例签名：G1-1 `True is not false : secret-shaped filename leaked into Profile code_roles: ['tests/token_FAKESECRET123.py']`（独立复现主会话证据）；G1-2 `profile.to_dict()` 全文含 FAKESECRET（泄漏全文在案）；G1-3 typed gap 缺失；G2-1/G2-2 `ContractError not raised`（model_digest 与占位 digest 均不设防）。M1' 扩展（id_ 正例）与既有 18 例签名不变。无 arrange 型失败。
- 非 sabotage：同 worktree `tests/audit tests/contracts` = **801 passed**；golden matrix 15 passed。
- **G2(a) 复现**：`compute_content_digest(MINIMAL_PAYLOAD["ram"]) = 217f735a671baea2…` ≠ 嵌入 `"0"*64`（与主会话亲验一致）；`HEX64 = "0"*64`（@:39）亲验。
- **goldens 零命中复验（含 `id_` 族）**：`tests/audit` 文件名字面量 128 个扫描唯一命中 `ram/shapes.py:192 secret.py`；fixtures 全量字符串（118 个，golden JSON 含）命中 19 项 = 18 个 64-hex digest 值 + `secret.py`，path-like 命中仅 `secret.py`（非 golden）。未触发停止条件。

## 10. Completion Summary / PR 要求

PR 描述必须含：F1/F2 需求映射（§0）、§2 残余风险声明逐字 + NFR-01/FR-01 **PARTIAL** 记账口径、§3.5 认证定位声明、冻结接口落位、验收命令输出摘要、golden 零改动 diff 证据、DR-01/02/03 授权修订落位（含 MINIMAL_PAYLOAD 四 digest 自洽迁移）、PI-DR6 非 Windows 记录。禁止任何自动关闭 #60 的关键字。

## 11. R1 终案（Maintainer 终裁，DR-03 §3）

- 公开面：仅 `reason → count` 汇总；无家族计数、无文件名、无派生摘要。
- 内部逐项：`AdmissionSkipRecord(index, reason, family)`——扫描内序号 + reason + family，不带原文件名；挂载于两个 build result 的 `admission_skips` 默认空字段。
- FR-01 记 PARTIAL，直至留痕覆盖全部跳过原因 vocabulary。

## 12. 已否决路线（不得重试）

1. prompt / wire 层掩码 path（ENTRY60-CLOSURE-1）。
2. full-payload digest 扩展（改 `ram_wire_digest` 算法、golden 全量变更、IP-0021 重冻结）。
3. `lima/workspace.py` 遍历层 skip；逐文件枚举被拒路径原文。
4. 摘要检查前置于结构/path 检查（DR-01 R-2 末位约束）。
5. `redact:<sha256(basename)[:8]>` 内部短标识与公开面 shape 家族计数（Maintainer 终裁否决，DR-03 §3）。
6. 把摘要自洽比对当防恶意重签认证使用（DR-03 §1(c) 定位声明）。
