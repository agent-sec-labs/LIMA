# Implementation Packet IP-0022 — #60-Fix：关闭前阻断修复（F1 秘密形态文件名准入期拒绝 + F2 wire 校验器加固）

> 文档类型：Implementation Packet（P&V 制作）
>
> Packet 版本：`IP-0022-PACKET/v5`
>
> 修订历史：v1（2026-09-13，PKT-IP-0022-D1，commit 70946e1）；v1 微修（PKT-IP-0022-D1R，R-1/R-2，commit 00093396）；v2（PKT-IP-0022-D1R2，DR-IP-0022-02/v1）；v3（PKT-IP-0022-D1R3，DR-IP-0022-03）；v4（PKT-IP-0022-XAUDIT，DR-IP-0022-04）；**v5（2026-09-13，PKT-IP-0022-R4，Assignment `IP-0022-PV-R4/v1`：Maintainer 复审三问题一次性修订——①DR-04-B 公式重写（symbol `'-'` 槽位消歧，§3.5）+ 生产链定源（§3.5 附源追踪）+ X4-7 负例；②`_red_proof` 全量底稿纳入提交（§4a，可从 PR 原样复现，RED D1'''' = 37 failed / 3 passed，§9.5）；③script **名称**准入过滤（entrypoints.symbol 出口，§3.2.4）+ X7 负例 + X5-2 补公开 coverage gap 计数断言；DR-04-A' 撤回落 Packet（§3.2 删第四过滤点，X3 锚定 A 定稿版）**；**v5-R5 修订（2026-09-13，PKT-IP-0022-R5，Assignment `IP-0022-PV-R5/v1`：DR-04-B 升 v3——公共 API 往返契约（入口域收窄 + 类型化拒绝，§3.5 重写）；新增 `_red_proof/test_ip_0022_r5_red.py`（X8-0 往返 GREEN 锚 + X8-1/X8-2 入口负例）与 `probe_r5.py`（P-R5-1/2/3 亲验）；RED D1''''' = 39 failed / 4 passed（§9.6）；DR-04-A 部分不动**）。
>
> 状态：`READY-FOR-CODE`（TBD = 0；DR-04-A（定稿版）**待重审**、DR-04-B **v3 停在裁定点**——待 Maintainer 裁定两个冻结公开入口（IP-0019 `build_semantic_top_n` / IP-0021 `ram_wire_payload`）的**输入域收窄**，未获批前不实施且不属 mandatory——见 DR-IP-0022-04 §2-B）
>
> Exact base：`30bdfaa13ac72572d65ccb2567ae8702923c4187`（origin/main，IP-0021 merge）
>
> 制作人：lima-packet-verification（Assignment `IP-0022-PV-P1/v1` → `P1R2/v1` → `P1R3/v1` → `IP-0022-PV-XAUDIT/v1` → `IP-0022-PV-R4/v1`，任务标识 `PKT-IP-0022-D1` / `D1R2` / `D1R3` / `XAUDIT` / `R4`，2026-09-13）
>
> 上游决策：COORD `ENTRY60-CLOSURE-1/v1`（拆分方案 α）；DR-IP-0022-01（REOPENED）；DR-IP-0022-02（REOPENED-by-03 / 部分 SUPERSEDED）；DR-IP-0022-03（RESOLVED-MAINTAINER）；**DR-IP-0022-04（OPEN，R5 修订版：A' 撤回 / A 定稿版待重审 / B v3 停在裁定点——待裁定输入域收窄）**；PI-DR1..PI-DR6 全部生效
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

### 3.2 F1 — 准入过滤点（v5：四点 = v3 三点 + v5 script 名称点）

1. `_build_entrypoints(summary, inventoried)`：**path 面**——script-declared 的解析目标与 root-convention 命中者不生成 entrypoint；**名称面（v5 新增，X7）**——script-declared 分支对 script **名称**（manifest scripts 键）执行 `is_secret_shaped_path(name)`（同一启发式作用于名称字符串——名称无 `/`，语义等同单段检测），命中即跳过该 entrypoint 生成并计入 `sensitive-filename` skip（`inventory.skipped["sensitive-filename"]` → `_skip_reason_gaps` 通道）。依据：script 名是任意 TOML 字符串键（inventory.py:360-365 仅 isinstance 校验），敏感命名名可原文进入 `entrypoints[i].symbol`（S1/S4/S8，probe P-R4-2 亲证；解析目标 `pkg/__init__.py` 为良性，path 面过滤不可达）；良性锚：`safe_cli`/`cli` 不受影响（X7-1 同时断言）。
2. **`_code_role_assignments(evidence, entry_targets, gaps)`（v3 新增，G1）**：迭代 `sorted(evidence)` 时跳过 `is_secret_shaped_path(relative_path)` 为 True 的路径，不生成 `CodeRoleAssignment`，计入 `inventory.skipped["sensitive-filename"]`。排序（`(role.value, path)`）与 `_MAX_CODE_ROLE_ASSIGNMENTS` cap/overflow 逻辑零改动（DR-03 §2 核验，无契约冲突）。
3. `build_python_ram_facts` 的 `candidates`（@ram.py:364-365）：过滤后进入 RAM 派生，五清单与 key_flows/labels 全部不含命中路径。
4. ~~manifest 候选过滤点（v4 【DR-04-A'】）~~ **v5 撤回**：Maintainer 复审否决 A'（丢弃 manifest 声明 + 其 skip 序号对非 inventory 候选定义失效——requirements*.txt 不在默认 inventory extensions，`sorted(evidence)` 枚举不含 manifest），Packet 删除该过滤点；manifest detail 携带面改由 **DR-04-A 定稿版**（`manifest-index` 稳定标识，见 DR-IP-0022-04 §2-A）处置，X3-1/X3-2 锚定 A 定稿版。
- 各过滤点均保持 sorted 次序，过滤不得重排（ordinal 属 candidate_id，禁止漂移）。
- **v4 跨命中去重（DR-04 §1.2）**：同一 repo-relative path 在同一 build result 内只计一次 `sensitive-filename`（entrypoint path 过滤与 code role 过滤共享按 path 键的去重集）；**script 名称过滤的去重键 = script 名称本身**（名称非路径，独立于 path 去重集；同名多目标或同目标多名各自按名去重）。Profile 与 RAM 两个 build result 各自独立计数（语义=各自候选集的拒绝数）。**RAM-only 构建**（不经 Profile）同样过滤并留痕（§3.3），且公开 coverage_gaps 同步携带 `reason=sensitive-filename; count=N`（X5-2 v5 增强断言）。
- **A' 撤回对序号定义的波及核查（v5，如实记录）**：§3.3 的 `AdmissionSkipRecord.index` 对 Profile code-role 候选取 `sorted(evidence)` 枚举下标、对 RAM 取 sorted `.py` 序——两个枚举体均为真实 inventory 文件集，定义成立，不受 A' 否决影响；A' 失效模式（对不在 inventory 的 manifest 候选套用 inventory 序号）随过滤点删除一并消除；v5 新增 script 名称过滤的序号取**其自身候选枚举**（过滤前 `sorted(summary.scripts)` 键序下标，§3.3），遵循"index = 被过滤候选列表自身的过滤前 sorted 全序下标"原则，不依赖 `sorted(evidence)`。

### 3.3 F1 — skip 汇总与内部留痕（R1 终案，DR-03 §3）

- **公开面（批准）**：仅 `reason → count`——`inventory.skipped["sensitive-filename"]` → 既有 `_skip_reason_gaps` 通道 → `GAP_INVENTORY_SKIPPED`，detail=`reason=sensitive-filename; count=N`（模板不变）。无 shape 家族输出。
- **内部逐项记录（终案设计）**：`AdmissionSkipRecord(index: int, reason: str, family: str)`——**扫描内序号 + reason + family，不带原文件名，不含任何 basename 派生摘要**（sha8 方案被否决）。挂载于 `ProfileBuildResult.admission_skips` / `RamFactsBuildResult.admission_skips`（默认 `()`，`lima/audit` 层 dataclass，不入 wire、不改 contracts）。
- **v4 序号与次序定稿（DR-04 §1.2；v5 复核维持 + script 枚举补充）**：`index` = 该 build **过滤前 sorted 候选全序枚举下标**（Profile code roles：`sorted(evidence)` 键序；Profile script 名称（v5）：`sorted(summary.scripts)` 键序；RAM：`sorted(item.path for item in files if .py)` 序），0 基，与 `candidate_id` 的 ordinal 无关（candidate_id 为 Do-not-touch），同输入同序号可复现；`admission_skips`/`inventory.skipped` 写入必须发生在 `_skip_reason_gaps`（Profile）/`_coverage_gaps`（RAM）构造之前（不变量，X5 负例承载）。v5 附注：三处枚举体均为各自被过滤候选的真实列表，A' 否决所针对的"对非 inventory 候选套用 inventory 序号"失效模式不适用于此（§3.2 第 4 点撤回记录）。
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
- **【DR-04-B 门控（v5-R5 版=DR-04-B v3，**停在裁定点：待 Maintainer 裁定输入域收窄**）】公共 API 往返契约——入口域收窄 + candidate_id 一致性（获批后 mandatory）**：
  - **往返契约事实（R5 亲验，probe P-R5-1/2/3）**：#58 合法条目 `symbol='-'` 在当前 main 上完成完整往返（两入口接受 + validate 通过）；None 与 `'-'` 碰撞出相同 candidate_id；None→`'-'` 篡改 validate 通过。故修复必须**在入口处**类型化拒绝，而非仅 wire 层拒绝（后者会把该合法输入变成"能生成不能校验"的中间态）。
  - **入口域收窄（两项，均为冻结公开入口的可观察行为变更，待裁定）**：(1) `build_semantic_top_n`：facts 五清单任何条目 `symbol == "-"` → `ContractError(INVALID_FIELD_VALUE, "$.facts.<section>[i].symbol")`（pointer 风格对齐 `ram_wire_payload` 入口惯例；与 IP-0019 既有异常惯例冲突时以 IP-0019 为准并回报）；(2) `ram_wire_payload`：`semantic_result.ranked` 任何 `symbol == "-"` → `ContractError(INVALID_FIELD_VALUE, "$.semantic_result.ranked[i].symbol")`（防御直构 `SemanticTopNResult` 的调用方——入径核查（§9.6）：携带 '-' 进 wire 的公开入径仅此三条，`lima/semantic_retrieval.py` 的 `SemanticCandidate` 为检索层同名异类，不在 wire 路径）。
  - **wire 第七项（消歧 + 一致性公式，维持 v5 设计）**：`symbol == "-"` 一律拒绝（`$.semantic.ranked[i].symbol`，入口已拒则 wire 出现 '-' 必为异常/篡改——与入口规则分工一致）；`candidate_id ≡ f"{kind}:{path}:{symbol if symbol is not None else '-'}#{ordinal}"` 前缀匹配 + `rsplit("#",1)` 等值比对，违例 `$.semantic.ranked[i].candidate_id`。
  - **candidate_id 冻结编码不变**（`symbol or '-'` 槽位维持；歧义由入口拒绝消除）；**Profile 层 symbol='-' 不触碰**（I13n）。
  - **往返保证**：被允许输入（扫描产物 + symbol≠'-' 构造输入）全链往返；`'-'` 入口 typed 拒绝（X8-0 GREEN 锚 / X8-1/X8-2 入口负例 / X4-7 wire 负例 / X4-1..3 绑定负例 / X4-0 冻结模式锚）。
  - **兼容性**：正常扫描产物零影响（五源定源 P-R4-3 + golden/real-chain 零命中维持）；备选 B-2（改 candidate_id 编码 = IP-0019 重冻结）不推荐、仅呈对照（DR-04-B v3）。未获批前维持残余风险 R-9。
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
| Add | `tests/audit/test_ip_0022_fix.py`（D2 冻结落库；D1..D1'''' 已 `_red_proof` RED）；**`_red_proof/` 全量底稿（v5 起纳入提交，见 §4a）** |
| Modify | `lima/audit/inventory.py`（§3.1-§3.4 含 `_code_role_assignments` 过滤 + `AdmissionSkipRecord`）、`lima/audit/ram.py`（§3.2.3 过滤 + `admission_skips`）、`lima/audit/ram_schema.py`（§3.5）、`lima/audit/__init__.py`（导出） |
| Modify（DR 授权冻结测试面修订，D2） | `tests/audit/test_fr05_gap_encoding.py`（扩词）、`tests/audit/test_ram_schema.py`（`MINIMAL_PAYLOAD` 四 digest 自洽迁移，用例 @:223-224；摘要检查末位约束 DR-01 R-2） |
| Read-only | 其余 `tests/**`、`schemas/**`、`docs/**` 既有文件、`lima/**` 其余 |
| Must-not-modify | `lima/contracts/**`、`schemas/v4/version_compatibility_matrix.json`、`lima/workspace.py`、`#94` 轨道一切（PR #178 零交集） |

### 4a. `_red_proof/` 底稿的提交范围与管理办法（v5，问题 2 处置）

- **提交范围（PR #180 统一口径）**：本 PR 范围 = `docs/**`（Packet/DR/矩阵/勘误）+ `_red_proof/**`（RED 证明底稿）。此前分支只提交了 X 系文件而 v3 的 23 用例文件未入库，致 `_red_proof` 全量不可从 PR 复现、PR 自称 docs-only 与实际内容不符——v5 起全部底稿（`test_ip_0022_fix_red.py` 23 例、`test_ip_0022_xaudit_red.py` 14 例、`test_ip_0022_r5_red.py` 3 例、`probe_xaudit.py`、`probe_r4.py`、`probe_r5.py`）入库，`python -m pytest _red_proof -q` 可从 PR 原样复现 **39 failed / 4 passed**（R5 计数；干净 checkout 复核见 §9.5/§9.6）。
- **性质声明**：`_red_proof/` 是 **D2 冻结测试的底稿（draft-of-freeze）**，不是运行时产品代码。pytest 配置 `testpaths=["tests"]`（pyproject.toml:41）不含 `_red_proof`，CI 与常规验收命令均不收集、不执行；其内容在 D2 阶段逐例迁入 `tests/audit/test_ip_0022_fix.py` 正式冻结。
- **管理办法**：D2 迁移完成并经独立验证后，`_red_proof/` 整体归档（移出仓库或在独立 commit 中删除，由 Coordinator 在 D2 验收时裁定）；迁移前保持只读（P&V 冻结底稿，Implementation 不得修改）。
- **证据索引（可复现命令与前置条件）**：任意 clone PR 分支（head SHA 见 §9.5/§9.6）→ `pip install -r requirements.txt`（无网络外呼，测试全部本地）→ `python -m pytest _red_proof -q` → 预期 `39 failed, 4 passed`；回归锚 `python -m pytest tests/audit tests/contracts -q` → `801 passed`；`python -m pytest tests/audit/test_golden_matrix.py -q` → `15 passed`；探针 `python _red_proof/probe_r4.py`、`python _red_proof/probe_xaudit.py`、`PYTHONPATH=. python _red_proof/probe_r5.py` → 输出与 §9.5/§9.6 摘要逐行一致。

## 5. 行为约束与恢复要求

- 网络禁止；文件系统仅测试临时 workspace；无数据库/容器/远端写。
- 确定性：过滤保持 sorted 次序与 ordinal 稳定；code_roles 排序/cap 语义零改动；digest helper 为纯函数。
- 危险/边界必验：三族判据正反例（M1'）、四层+Profile 排除（M2-M10、G1-1/2）、entrypoint script 目标（M7）、绝对路径双形态与 `..` 逃逸（M11-M14）、传输头同步洗白（M17/M17s）、摘要篡改/陈旧/model_digest 篡改（M15/M16/G2-1）、占位 digest 拒绝与自洽正例（G2-2+迁移正例）。
- 停止条件：需改 candidate_id/golden digest 才能表述的用例 ⇒ 停止提交 DR；B' canonical 隐藏不等价（D2 实现期若发现）⇒ 停止回报；启发式命中任一 golden fixture ⇒ 停止细化重提；code_roles 排序/cap 契约冲突（已核验无）⇒ 停止回报；冻结测试需变更 ⇒ 先 DR。

## 6. 最低用例矩阵（冻结测试集，23 例 + 迁移正例 + 回归锚）

RED 六轮证明：D1（16 例）、D1'（18 例）、D1''（23 例）、D1'''（34 例）、D1''''（37 例）、**D1'''''（39 例，R5：+ X8-1/X8-2 两例入口负例；X8-0 为 GREEN 锚非 RED）**，签名均为目标行为缺失（§9/§9.5/§9.6）。

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
| X3-1/X3-2 | manifest_gap_detail_free_of_sensitive_path | MANIFEST_PARSE_ERROR / manifest 超限 detail 不携带敏感形态路径，且携带 `manifest-index=<i>` 稳定标识（**【DR-04-A 定稿版门控，待重审】**；A' 已撤回；RED 已证 main 泄漏；X3-2 经 XAUDIT-FIX 勘正为目标缺失签名） |
| X4-1/2/3 | wire_candidate_id_kind_path_symbol_consistency | candidate_id 与 kind/path/symbol（含 symbol 槽、非负数字 ordinal）一致（**【DR-04-B v3 门控，待裁定输入域收窄】**）；X4-0 锚：非数字 ordinal 由 IP-0021 冻结模式拒绝（基线即绿，防弱化） |
| X4-4/5/6 | wire_path_segment_rules | 空段（a//b）、`.` 段（./x）、Cc 控制字符 path 拒绝（v4 补齐 #58 契约两处弱于） |
| X4-7 | wire_candidate_id_none_dash_disambiguation | `symbol` None↔`'-'` 互换篡改（candidate_id 与五摘要均不变）被拒——`symbol == "-"` 字面值 wire 层拒绝，槽位 `'-'` ≡ `symbol is None`（v5 新增；**R5 定位为 wire 层负例，与入口负例 X8-1/2 分工**；RED：main 接受该翻转） |
| X8-0 | real_scan_round_trip_validates | 真实临时仓 scan → build_python_ram_facts → build_semantic_top_n → ram_wire_payload → validate 全链往返通过（**GREEN 锚**，基线与实现后均绿——往返保证的正例面；R5 新增） |
| X8-1 | build_semantic_top_n_rejects_dash_symbol_entry | facts 五清单任何条目 `symbol == "-"` → 入口 `ContractError(INVALID_FIELD_VALUE, "$.facts.<section>[i].symbol")` typed 拒绝（**【DR-04-B v3 门控：待裁定输入域收窄】**；RED：main 接受且往返通过，probe P-R5-1） |
| X8-2 | ram_wire_payload_rejects_dash_symbol_ranked | 直构 `SemanticTopNResult.ranked` 携带 `symbol == "-"` → 入口 typed 拒绝（**【DR-04-B v3 门控】**；RED：main 接受；防御直构调用方） |
| X5-1 | admission_skip_counted_once_per_path | 同一 path 命中 entrypoint+code role 只计一次（count=1、恰一个 typed gap） |
| X5-2 | ram_only_build_records_admission_skips | RAM-only 构建留痕 admission_skips（无 path 字段）**且公开 coverage_gaps 携带 `reason=sensitive-filename; count=1`**（v5 增强断言） |
| X7-1/X7-2 | sensitive_script_name_admission | 敏感命名 script **名称**不入 `entrypoints[i].symbol`/`to_dict()`（良性名 safe_cli 保留）；skip 经公开通道计数（`count=1`、恰一个 typed gap）（v5 新增；RED：main 原文泄漏，probe P-R4-2） |
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

## 9.5 RED 证明（D1''''，v5 / PKT-IP-0022-R4）

- 测试文件：`_red_proof/test_ip_0022_xaudit_red.py`（14 例，v5 增 X4-7、X7-1、X7-2 三例并增强 X3-1/X5-2 断言）+ `_red_proof/test_ip_0022_fix_red.py`（v3 的 23 例，签名复验不变）。命令：`python -m pytest _red_proof -q`。结果：**37 failed / 3 passed**（D1''' 34 failed 基础上 +3，均为新增目标缺失型；3 个通过项仍为锚：X4-0、X6 两例）。
- **新失败签名（逐例目标缺失型，非 arrange 缺陷）**：X4-7 `Exception not raised`（wire 接受 symbol None→`'-'` 翻转，candidate_id 与五摘要均不变——碰撞缺陷复现）；X7-1 `True is not false : sensitive script name leaked into entrypoints.symbol: ['safe_cli', 'token_FAKESECRET123']`；X7-2 `0 != 1 : expected exactly one skip gap: []`；X5-2 增强断言（公开 coverage gap）随首断言（admission_skips 缺失）失败；X3-1 增强（manifest-index 存在）随首断言（原路径泄漏）失败。
- **可复现性（问题 2 处置）**：v3 的 23 用例文件此前未提交（34/3 不可从 PR 复现的原因），本轮全部底稿入库（commit `6f90375`）；**干净 checkout 复核**（`git archive <head>` 解包至空目录后原样运行）：`_red_proof` = 37 failed / 3 passed、`tests/audit tests/contracts` = 801 passed、golden = 15 passed，与工作树逐项一致。
- **探针证据（probe_r4.py，入库）**：P-R4-1 script 名 `'-'` → Profile entrypoints.symbol=`'-'`（Profile 层生产路径实证）；P-R4-2 敏感 script 名原文进 entrypoints.symbol + to_dict（解析目标良性，path 面过滤不可达）；P-R4-3 RAM 全链观察 symbol 集 = 标识符 ∪ {`"<dynamic-call>"`}，无 `'-'` 字面值；P-R4-4 wire 接受 None→`'-'` 翻转（X4-7 RED 基础）。
- 回归：`tests/audit tests/contracts` 801 passed；golden matrix 15 passed（工作树 + 干净 checkout 双跑）。

## 9.6 RED 证明（D1'''''，v5-R5 / PKT-IP-0022-R5）

- 测试文件：`_red_proof/test_ip_0022_r5_red.py`（X8-0/X8-1/X8-2 三例）+ 既有两组底稿（签名复验不变）。命令：`python -m pytest _red_proof -q`。结果：**39 failed / 4 passed**（D1'''' 37 failed 基础上 +2；第 4 个通过项 = 新 GREEN 锚 X8-0 + 既有 3 锚 X4-0/X6×2）。
- **新失败签名（逐例目标缺失型）**：X8-1 `ContractError not raised by build_semantic_top_n`（main 接受 symbol='-' facts，往返通过）；X8-2 `ContractError not raised by ram_wire_payload`（main 接受直构 '-' ranked 结果）。无 arrange 型失败（构造路径复用 fixtures/repo_shapes 绿色通道 + probe_r5 同构造三探针通过）。
- **R5 探针（`_red_proof/probe_r5.py`，P&V 亲验）**：P-R5-1 合法 '-' 条目全链往返 **PASSED**（ranked_symbols 含 `'-'`）；P-R5-2 None 与 `'-'` candidate_id 集合**非空交集**（`entrypoint:danger.py:-#0` 等四类）；P-R5-3 None→`'-'` wire 篡改 **ACCEPTED**。运行为 `PYTHONPATH=. python _red_proof/probe_r5.py`（模块路径需仓库根）。
- **入径核查（Stop Condition 亲验）**：携带 `symbol='-'` 进 wire 的公开入径共三条——`build_semantic_top_n(facts)`（`_collect_candidates` @prioritizer:522-585 逐源：五清单全部直接取 entry.symbol）、`ram_wire_payload` 直构 `SemanticTopNResult`（ram_schema:276-278 仅 isinstance）、wire dict 直入 validate。`lima/semantic_retrieval.py:1279` 的 `SemanticCandidate` 为检索层同名异类（不同 dataclass，不在 wire 路径）。三条入径全部纳入 DR-04-B v3 设计。
- 回归：`tests/audit tests/contracts` 801 passed；golden matrix 15 passed（R5 本轮工作树亲跑；R5 增量用例为纯构造断言，平台无关）。

## 7. 缺口查证结论（v1 结论维持，行号经 R-1 勘正）

- 缺口 1：存在 1 处宽松接受冻结断言——`test_ram_schema.py::test_minimal_payload_validates`（@:223-224；MINIMAL_PAYLOAD @:79，identity @:128-135）。DR-01 授权 + DR-03 §1(a) 升级为四 digest 自洽迁移。
- 缺口 2：skip reason 词汇表为封闭冻结枚举（`test_fr05_gap_encoding.py:43-53,135`）。DR-01 授权扩词。

## 8. 验收命令与判定

```bash
python -m pytest tests/audit tests/contracts -q        # ≥801+23+X passed（X = 非 DR 门控新负例 X1/X2/X4-4..6/X5/X7 + GREEN 锚 X8-0；X3/X4-1..3/X4-7/X8-1/X8-2 随 DR-04-A/B 裁定计入），0 failed, 0 new skip
python -m pytest tests/audit/test_golden_matrix.py -q  # 15 passed（golden 原样）
# RED 底稿可复现（D2 实现前）：git clone PR 分支后
python -m pytest _red_proof -q                          # 39 failed / 4 passed（D1'''''，§9.5-§9.6）
```

判定依据：M1'-M18 + G1/G2 系全绿；R1-R3 全绿；`git diff 30bdfaa -- tests/audit/fixtures schemas` 为空；ruff/bandit 零新 finding。PI-DR6：D2 冻结前至少一个非 Windows 平台完整跑一次（M1'/G 系为纯字符串/纯构造断言，平台无关）。

## 9. RED 证明（D1 + D1' + D1''）

- D1（16 例）与 D1'（18 例）记录于 v1/v2 §9（commit 70946e1/00093396/4aa507c 轮）。
- **D1''（本版）**：测试文件 `D:\BaseAIProject\LIMA-ip-0022-pv-wt\_red_proof\test_ip_0022_fix_red.py`（scratch）。命令：`python -m pytest _red_proof/test_ip_0022_fix_red.py -q` @30bdfaa worktree。结果：**23 failed / 0 passed**——新增五例签名：G1-1 `True is not false : secret-shaped filename leaked into Profile code_roles: ['tests/token_FAKESECRET123.py']`（独立复现主会话证据）；G1-2 `profile.to_dict()` 全文含 FAKESECRET（泄漏全文在案）；G1-3 typed gap 缺失；G2-1/G2-2 `ContractError not raised`（model_digest 与占位 digest 均不设防）。M1' 扩展（id_ 正例）与既有 18 例签名不变。无 arrange 型失败。
- 非 sabotage：同 worktree `tests/audit tests/contracts` = **801 passed**；golden matrix 15 passed。
- **G2(a) 复现**：`compute_content_digest(MINIMAL_PAYLOAD["ram"]) = 217f735a671baea2…` ≠ 嵌入 `"0"*64`（与主会话亲验一致）；`HEX64 = "0"*64`（@:39）亲验。
- **goldens 零命中复验（含 `id_` 族）**：`tests/audit` 文件名字面量 128 个扫描唯一命中 `ram/shapes.py:192 secret.py`；fixtures 全量字符串（118 个，golden JSON 含）命中 19 项 = 18 个 64-hex digest 值 + `secret.py`，path-like 命中仅 `secret.py`（非 golden）。未触发停止条件。

## 10. Completion Summary / PR 要求

PR 描述必须含：F1/F2 需求映射（§0）、§2 残余风险声明逐字 + NFR-01/FR-01 **PARTIAL** 记账口径、§3.5 认证定位声明、冻结接口落位、验收命令输出摘要、golden 零改动 diff 证据、DR-01/02/03 授权修订落位（含 MINIMAL_PAYLOAD 四 digest 自洽迁移）、PI-DR6 非 Windows 记录、**提交范围如实声明（docs + `_red_proof/` D2 冻结底稿及其管理办法，§4a）与 RED 可复现命令（`python -m pytest _red_proof -q` → 39 failed / 4 passed）**。禁止任何自动关闭 #60 的关键字。

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
