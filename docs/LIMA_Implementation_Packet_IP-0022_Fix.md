# Implementation Packet IP-0022 — #60-Fix：关闭前阻断修复（F1 秘密形态文件名准入期拒绝 + F2 wire 校验器加固）

> 文档类型：Implementation Packet（P&V 制作）
>
> Packet 版本：`IP-0022-PACKET/v2`
>
> 修订历史：v1（2026-09-13，PKT-IP-0022-D1，commit 70946e1）；v1 微修（PKT-IP-0022-D1R，Coordinator DR 复核定案 RESOLVED + R-1/R-2，commit 00093396）；v2（2026-09-13，PKT-IP-0022-D1R2，DR-IP-0022-02/v1）：F1 拦截口径改启发式超集（§3.1）、F2 升级为路线 B' 载荷完整性绑定（§3.5）、公开面/绕过路径/残余风险写实（§0/§2）、R1 整合（§11）、用例矩阵 M1'/M17（§6）、RED 重证 D1'（§9）。
>
> 状态：`READY-FOR-CODE`（TBD = 0；两项子提案——§2 残余风险记录口径与 §11 R1 内部留痕方案——待 Maintainer 终裁，不阻塞 D2 冻结范围，否决分支已定义）
>
> Exact base：`30bdfaa13ac72572d65ccb2567ae8702923c4187`（origin/main，IP-0021 merge）
>
> 制作人：lima-packet-verification（Assignment `IP-0022-PV-P1/v1` → `IP-0022-PV-P1R2/v1`，任务标识 `PKT-IP-0022-D1` / `PKT-IP-0022-D1R2`，2026-09-13）
>
> 上游决策：COORD `ENTRY60-CLOSURE-1/v1`（拆分方案 α）；DR-IP-0022-01（REOPENED，存活条款经 DR-IP-0022-02 §4 处置）；**DR-IP-0022-02/v1**（Coordinator 授权，本版执行依据）；PI-DR1..PI-DR6 全部生效
>
> 随批文档：DR-IP-0022-01、DR-IP-0022-02、C1 勘误（`LIMA_DR-C1_ENTRY60-CLOSURE-1_Erratum_2026-09-13.md`）

---

## 0. Header（生命周期 §8）

```text
Source Issue：#60（[V4-I04][P0] Repository Profile、RAM 与安全语义清单，V5 覆盖层版）
Issue specification revision：2026-09-13 Issue #60 正文（含 ENTRY60-CLOSURE-1 入账；API 亲取复核）
公开面定义（v2 明写）：NFR-01 保护面 = prompt 文本 + RAM facts / Top-N / wire payload（保守维持 v1 四层，不收窄）
Covered requirements（本 IP 只声明自身贡献）：
  NFR-01 扩展口径（DR-IP-0022-01 存活 + DR-IP-0022-02 §1 修订）：启发式超集口径下的秘密形态文件名不在四层出现（残余限定见 §2）
  FR-04 补全（DR-IP-0022-02 §2 路线 B'）：wire 载荷完整性 = path 拒绝 + ram/semantic identity digest 重算比对 + wire_digest 传输头校验（末位）
Not covered requirements：F3 workspace _safe_path TOCTOU、F4 回包/时间不设防（→ IP-0023 closure 负例）；S4b/T-03/V5 端到端；#64/#68 消费验证；R1 终裁；直调语义层（build_semantic_top_n）处理已构造 facts 的内部 API 误用防御（Known Gaps §2）；穷尽式秘密检测
Delivery role：hardening-fix（冻结面内最小防御 + 冻结测试面 DR 授权修订）
Issue closure impact：PARTIAL（解除两项关闭前阻断；Issue 关闭权在 Coordinator/Maintainer）
Upstream IP/PR/merge commits：IP-0016（fd219724）、IP-0018（cc17662）、IP-0019（e000e6f）、IP-0020（#176）、IP-0021（30bdfaa，#179）；PR #180 驳回（修订对象）
Upstream ruling：ENTRY60-CLOSURE-1/v1 + DR-IP-0022-02/v1（已否决路线见 §12：prompt/wire 层掩码 path、full-payload digest 扩展等）
```

## Design Input Manifest

1. 三份治理正典（P&V 责任书 v1.1、开发交接标准、生命周期）；2. Coordinator Assignment `IP-0022-PV-P1/v1` + `IP-0022-PV-P1R2/v1`（含 DR-IP-0022-02/v1 六项指令）；3. Issue #60 正文（GitHub API 亲取，含 ENTRY60-CLOSURE-1）；4. 四层冻结面 @30bdfaa（`lima/audit/**`、`tests/audit/**`、`schemas/v4/**`）；5. 既有 Packet IP-0016/0018/0019/0020/0021；6. DR 链（DR-IP-0022-01/-02、DR-IP-0021-0102、DR-IP-0020-2/3、DR-IP-0016-02）；7. PI-DR1..DR6；8. 主会话三重亲验记录 + Maintainer 驳回面（两样本 `token_FAKESECRET123.py`、`sk_live_ABC123xyztoken.py`）。

## Explicitly Rejected Inputs

- prompt / wire 层掩码 path（ENTRY60-CLOSURE-1 否决）。
- full-payload digest 扩展（改 `ram_wire_digest` 算法、golden 全量变更、IP-0021 重冻结）——B' 已证可行（DR-IP-0022-02 §2.1），该路线维持否决（§12）。
- `lima/workspace.py` 遍历层 skip；逐文件枚举被拒路径原文（count-only 公开面）。
- F3/F4 修复草案（→ IP-0023）；`schemas/v4/**` 增改；`lima/contracts/**` 增改。

## 1. Goal / Non-goals

### Goal

1. **F1 准入期拒绝（启发式超集口径）**：AttackSurfaceEntry 候选生成处（profile `_build_entrypoints` + RAM `candidates` 文件集）以 `is_secret_shaped_path`（三族判据：段边界关键词 / 服务商前缀家族 / ≥20 字符无分隔 base62 高熵段——DR-IP-0022-02 §1.1 冻结 regex）检测 basename，拒绝进入候选集，skip reason `sensitive-filename` 汇总（count-only + 提案中的 shape 家族，§11）。
2. **F2 载荷完整性绑定（路线 B'）**：`validate_ram_wire_payload` 追加五步序列——path 检查 → `ram_facts_digest` 重算比对 → `semantic_config_digest` 重算比对 → `semantic_result_digest` 重算比对（input 取前步重算值）→ `wire_digest` 重算比对（**末位**，DR-IP-0022-01 R-2 约束延续）。
3. 冻结测试面 DR 授权修订（词汇表扩词、minimal-payload arrange 回填；见 DR-IP-0022-01 存活条款）。

### Non-goals

- 不改 `candidate_id` 生成规则、任何 digest 算法与取值、golden fixtures 及期望值（回归锚：五形状 golden 原样通过）。
- 不改 `lima/audit/semantic_prioritizer.py`（含 `_SECRET_TOKEN_PATTERN` 本体与 `_render_prompt`）、`lima/contracts/**`、`lima/workspace.py`、`schemas/v4/**`、scanner/service、#64/#68 接线。
- 不做 F3/F4（→ IP-0023）；不宣称穷尽式秘密检测（§2）。

## 2. 残余风险声明与 Known Gaps（v2 新增；残余声明为提案待 Maintainer 终裁）

> **残余风险声明（逐字，进入 PR 模板）：本修复将秘密形态文件名拦截从五类已知 token 形状扩展为启发式检测（关键词/前缀家族/高熵段），覆盖已知样本与常见服务商格式，但不构成穷尽式秘密检测；未能命中的新形态仍可能进入审计产物。NFR-01 在本 IP 的贡献应记录为"已知形状与常见启发式口径下的文件名泄漏面关闭"，不得记录为 NFR-01 零泄漏已修复。**

Known Gaps（写实）：

- **绕过路径**：直调语义层 `build_semantic_top_n` 处理已构造 facts，属内部 API 误用——候选已越过准入点，本 IP 不防御（`semantic_prioritizer` 为冻结 Do-not-touch）。
- 高熵段判据的误伤/漏检权衡：≥20 字符无分隔 base62 为经验阈值（对全部 golden fixture 与 tests/audit 文件名字面量零误伤，制作期亲验；唯一 fixture 命中为 IP-0018 `SECRET_REPO` 的 `secret.py`，语义上本即秘密形态命名，其冻结用例保持绿）。

## 3. 冻结接口清单（实现必须逐字对齐）

### 3.1 F1 — 检测口径与 helper（DR-IP-0022-02 §1.1 冻结 regex）

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
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}"
    r"|(?<![A-Za-z0-9])[A-Za-z0-9]{20,}(?![A-Za-z0-9])"
)

def is_secret_shaped_path(path: str) -> bool:
    """Heuristic superset check on the basename (DR-IP-0022-02 §1)."""
```

- `is_secret_shaped_path`：basename（`path.rsplit("/", 1)[-1]`）执行 `_SECRET_FILENAME_PATTERN.search`；非 str/空串返回 False。从 `lima/audit/__init__.py` 导出。
- 断言口径：**超集断言**（五 token 形状全命中 + 两驳回样本命中 + §6 M1' 误伤负例集不命中）；不再与 `_SECRET_TOKEN_PATTERN` 等值。
- shape 家族归类（供 §11 内部留痕与提案中的家族计数）：`keyword` / `provider-prefix` / `high-entropy`（实现以逐族子 regex 判定，家族与 regex 同源）。

### 3.2 F1 — 准入过滤点（与 v1 相同，两处）

- `_build_entrypoints(summary, inventoried)`：`inventoried` 中命中者不生成 entrypoint（script-declared 与 root-convention 同滤）。
- `build_python_ram_facts` 的 `candidates`（@ram.py:364-365）：过滤后进入 RAM 派生，五清单与 key_flows/labels 全部不含命中路径。
- 保持 `sorted` 次序，过滤不得重排（ordinal 属 candidate_id，禁止漂移）。

### 3.3 F1 — skip 汇总与内部留痕（R1 提案，待终裁）

- 公开面：`inventory.skipped["sensitive-filename"]` → 既有 `_skip_reason_gaps` 通道 → `GAP_INVENTORY_SKIPPED`，detail=`reason=sensitive-filename; count=N`（模板不变）；提案中的家族后缀（如 `; families=keyword:1`）仅在 Maintainer 批准 §11 后加入。
- 内部留痕（提案）：`AdmissionSkipRecord(redacted_id: str, family: str)`（`redacted_id=f"redact:{sha256(basename.encode())[:8]}"`，不含原文件名）挂载于 `ProfileBuildResult.admission_skips` / `RamFactsBuildResult.admission_skips`（默认 `()`，`lima/audit` 层 dataclass，不入 wire payload、不改 contracts）。否决分支：不新增该字段，FR-01 满足面声明明示修订。

### 3.4 F1 — 词汇表扩展（DR-IP-0022-01 存活授权）

`_SKIP_REASONS` 增 `"sensitive-filename"`（第 11 词）；`SKIP_REASON_TO_GAP_DETAIL` 同步；`tests/audit/test_fr05_gap_encoding.py::FROZEN_SKIP_REASONS` 同步（集合等值断言强度不降）。

### 3.5 F2 — 校验序列（DR-IP-0022-02 §2.2，路线 B'）

`lima/audit/ram_schema.py` 新增三个 dict 侧 helper（序列化口径对齐冻结源；冻结测试断言与真实链 digest 相等）：

1. `ram_facts_digest_from_wire(payload) -> str`：`compute_content_digest(payload["ram"])`（对齐 ram.py:415-430；实证等值，DR-02 §2.1(i)）。
2. `semantic_config_digest_from_wire(payload) -> str`：以 `build.semantic`（top_n/weights/tie_break/seed/budgets）+ `identity.prompt_digest` + `compute_content_digest(build.semantic.model_id)` 按 `_config_digest_payload`（prioritizer:624-638）形状重组（实证等值，DR-02 §2.1(ii)）。
3. `semantic_result_digest_from_wire(payload) -> str`：以 `semantic.ranked`（rank/candidate_id/score/category/rationale/key_flow_steps 六字段）、`total_candidates`、`coverage_gaps` + `config_digest=identity.semantic_config_digest`（经 2 比对后）+ `input_facts_digest=（1 的重算值）` 按 `_result_digest`（prioritizer:640-660）形状重组。

`validate_ram_wire_payload` 在既有结构校验后依序追加：

- **path 检查**（v1 F2(i) 不变）：ram 五清单 entry 与 `semantic.ranked` 每项 path：非空 str、无 `\`、非 `/` 开头、无 `^[A-Za-z]:` 盘符、无 `..` 段；违例 `ContractError(INVALID_FIELD_VALUE, "$.ram.<section>[i].path" / "$.semantic.ranked[i].path")`。
- `ram_facts_digest_from_wire(payload) != identity.ram_facts_digest` → `ContractError(INVALID_FIELD_VALUE, "$.identity.ram_facts_digest")`。
- `semantic_config_digest_from_wire(payload) != identity.semantic_config_digest` → `$.identity.semantic_config_digest`。
- `semantic_result_digest_from_wire(payload) != identity.semantic_result_digest` → `$.identity.semantic_result_digest`。
- `identity.wire_digest != ram_wire_digest(payload)` → `$.identity.wire_digest`（**末位**）。

校验目标声明：`wire_digest` = 传输头校验（build + identity 槽位），不验证载荷内容；载荷完整性由 identity digest 重算比对承担（ram 段全覆盖；semantic 段全覆盖——ranked/total/coverage_gaps + config 绑定）。不改任何 digest 值，不触发 IP-0021 重冻结。

### 3.6 明确不改（Do-not-touch）

`candidate_id()`、`_render_prompt`、`_SECRET_TOKEN_PATTERN` 本体、`semantic_prioritizer.py` 全文件、`ram_wire_digest` 算法、golden fixtures、`schemas/v4/**`、`lima/contracts/**`、`lima/workspace.py`、其余 `lima/**`。

## 4. 文件边界

| 类别 | 文件 |
|---|---|
| Add | `tests/audit/test_ip_0022_fix.py`（D2 冻结落库；D1/D1' 已 scratch RED） |
| Modify | `lima/audit/inventory.py`（§3.1-§3.4 + `AdmissionSkipRecord`〔提案获批后〕）、`lima/audit/ram.py`（§3.2 过滤 + `admission_skips`〔同前〕）、`lima/audit/ram_schema.py`（§3.5）、`lima/audit/__init__.py`（导出） |
| Modify（DR 授权冻结测试面修订，D2） | `tests/audit/test_fr05_gap_encoding.py`（`FROZEN_SKIP_REASONS` 扩词）、`tests/audit/test_ram_schema.py`（`test_minimal_payload_validates` @:223-224 arrange 回填真 `wire_digest`；摘要检查末位约束 DR-01 R-2） |
| Read-only | 其余 `tests/**`、`schemas/**`、`docs/**` 既有文件、`lima/**` 其余 |
| Must-not-modify | `lima/contracts/**`、`schemas/v4/version_compatibility_matrix.json`、`lima/workspace.py`、`#94` 轨道一切（PR #178 零交集） |

## 5. 行为约束与恢复要求

- 网络禁止；文件系统仅测试临时 workspace；无数据库/容器/远端写。
- 确定性：过滤保持 sorted 次序与 ordinal 稳定；digest helper 为纯函数。
- 危险/边界必验：三族判据正反例（M1'）、三 token 形状文件名四层排除（M2-M4/M8-M10）、高熵段、entrypoint script 目标（M7）、绝对路径双形态与 `..` 逃逸（M11-M14）、传输头同步洗白攻击（M17/M17-semantic）、摘要篡改与陈旧摘要（M15/M16）。
- 停止条件：需改 candidate_id/golden digest 才能表述的用例 ⇒ 停止提交 DR；B' 序列化隐藏不等价（本版已实证等值，若 D2 实现期发现 canonical codec 差异）⇒ 停止回报；启发式命中任一 golden fixture ⇒ 停止细化重提；冻结测试需变更 ⇒ 先 DR。

## 6. 最低用例矩阵（冻结测试集，18 例 + 回归锚）

RED 已两轮证明：D1（16 例，commit 70946e1 轮）与 D1'（18 例，本版，M1' 重写 + M17/M17-semantic 新增），签名均为目标行为缺失（§9）。

| # | ID（D2 冻结名可微调，语义不得变） | 断言 |
|---|---|---|
| M1' | secret_shaped_path_helper_is_heuristic_superset | 超集断言：五 token 形状全命中；两驳回样本（`token_FAKESECRET123.py`、`sk_live_ABC123xyztoken.py`）命中；前缀族扩展（gho_/sk_test_/github_pat_/xoxb-）命中；关键词族（my_secret/secrets/api_key/apikey/password_reset/credential_store/key.pem）命中；高熵段（≥20 base62）命中；误伤负例集（tokenizer/tokenization/keyboard_layout/monkey_patch/keynote/api/danger/safe/cli/application/library_profile_golden.json）不命中；basename 语义（pkg/ 前缀） |
| M2-M10 | 同 v1（M2-M10） | RAM facts 三形状排除（ghp_/AKIA/JWT）、词汇表扩词、typed gap count=1、entrypoint script 目标排除（safe 锚）、Top-N 排除、prompt 排除（model_id 激活 + 捕获）、wire payload 排除 |
| M11-M16 | 同 v1（M11-M16） | 绝对 POSIX / Windows 盘符 / `..` 逃逸（entry 与 ranked）/ 摘要单字符篡改 / build 变更后陈旧摘要——均 ContractError |
| M17 | payload_tamper_with_synced_wire_digest_still_rejected | 篡改 `ram.sensitive_sinks[0].path` 为合法相对路径 + `ram_wire_digest` 同步回填 → 仍失败（`$.identity.ram_facts_digest`） |
| M17s | semantic_ranked_tamper_with_synced_wire_digest_still_rejected | 篡改 `semantic.ranked[0].rationale` + 同步回填 → 仍失败（`$.identity.semantic_result_digest`） |
| M18 | digest_helpers_recompute_true_chain_digests | 三 helper 对真实链 payload 重算值 == `ram_facts_digest(facts)` / `semantic_config_digest(options)` / `semantic_result_digest(result, input_facts_digest=…)` |
| R1-R2 | 回归锚 | `tests/audit/test_golden_matrix.py` 15 绿（golden 原样）+ `tests/audit`+`tests/contracts` 801 绿 |
| R3 | goldens 零命中核验锚 | 启发式对 golden_matrix 五形状全部路径与 repo_shapes 全量文件名零命中（fixture 常量集断言，防实现期 pattern 悄然放宽致 golden 漂移） |

注：M18/R3 在 D1' scratch 集中未单列（M18 由 DR-02 §2.1 可行性实证承担、R3 由制作期扫描承担），D2 冻结集须补齐为可执行用例。

## 7. 缺口查证结论（v1 结论维持，行号经 R-1 勘正）

- 缺口 1：存在 1 处宽松接受冻结断言——`tests/audit/test_ram_schema.py::test_minimal_payload_validates`（用例 @:223-224；`MINIMAL_PAYLOAD` 定义 @:79，identity 占位 digest @:128-135，`wire_digest` @:134）。DR-01 授权修订 + R-2 末位约束（§3.5）。
- 缺口 2：skip reason 词汇表为封闭冻结枚举（`test_fr05_gap_encoding.py:43-53,135`）。DR-01 授权扩词。

## 8. 验收命令与判定

```bash
python -m pytest tests/audit tests/contracts -q        # ≥801+18 passed, 0 failed, 0 new skip
python -m pytest tests/audit/test_golden_matrix.py -q  # 15 passed（golden 原样）
```

判定依据：M1'-M18 全绿；R1-R3 全绿；`git diff 30bdfaa -- tests/audit/fixtures schemas` 为空；ruff/bandit 零新 finding。PI-DR6：D2 冻结前至少一个非 Windows 平台完整跑一次（记录 SHA 与结论；M1' 为纯字符串断言，平台无关）。

## 9. RED 证明（D1 + D1'）

- D1（v1 轮）：16 例全失败于缺失目标行为；`tests/audit`+`tests/contracts` 801 绿 + golden 15 绿（记录于 v1 §9，commit 70946e1/00093396 轮）。
- **D1'（本版）**：测试文件 `D:\BaseAIProject\LIMA-ip-0022-pv-wt\_red_proof\test_ip_0022_fix_red.py`（scratch，不入库；SHA-256 见 Handoff）。命令：`python -m pytest _red_proof/test_ip_0022_fix_red.py -q` @30bdfaa worktree。结果：**18 failed / 0 passed**——M1'（AttributeError：helper 不存在）+ M2-M16（v1 签名不变：泄漏全文 / ContractError not raised / 词汇表缺失 / typed gap 缺失）+ M17/M17s（`AssertionError: ContractError not raised`——基线对"同步洗白"完全不设防的直接证据）。无 arrange 型失败。
- 非 sabotage：同 worktree `tests/audit tests/contracts` = **801 passed**；golden matrix 15 passed。
- **goldens 零命中核验**（制作期亲验）：启发式 regex 扫描 `tests/audit/fixtures`（golden JSON 全部字符串值 + 四个 shapes.py 文件名字面量）——golden 内 18 个命中串全部为 64-hex digest **值**（非路径字段），文件名/路径字段零命中；`tests/audit/**` 全部文件名字面量扫描唯一命中 `ram/shapes.py:192` `secret.py`（IP-0018 SECRET_REPO，非 golden，语义上本即秘密形态命名，其冻结用例在新行为下保持绿）。未触发停止条件。

## 10. Completion Summary / PR 要求

PR 描述必须含：F1/F2 需求映射（§0/§2）、§2 残余风险声明逐字段、冻结接口落位（§3）、验收命令输出摘要、golden 零改动 diff 证据、DR-01/02 授权修订落位、PI-DR6 非 Windows 记录、§11 提案的终裁状态。禁止任何自动关闭 #60 的关键字。

## 11. R1 整合（提案，待 Maintainer 终裁）

- 公开面：count-only 汇总（`reason=sensitive-filename; count=N`）+ shape 家族计数后缀（`families=keyword:1` 式，仅家族名，无文件名原文）——家族后缀未获批则维持纯 count-only。
- FR-01 逐项满足面（内部记录）：`AdmissionSkipRecord(redacted_id=f"redact:{sha256(basename)[:8]}", family=…)` 挂载于 `ProfileBuildResult.admission_skips` / `RamFactsBuildResult.admission_skips`（默认 `()`；`lima/audit` 层，不入 wire、不改 contracts）。
- 否决分支：回退纯 count-only + 明示修订 FR-01 满足面声明，不新增字段。

## 12. 已否决路线（不得重试）

1. prompt / wire 层掩码 path（ENTRY60-CLOSURE-1）。
2. full-payload digest 扩展（改 `ram_wire_digest` 算法、golden 全量变更、IP-0021 重冻结）——B' 已证可行（DR-02 §2.1 实证），维持否决；启用即新 DR。
3. `lima/workspace.py` 遍历层 skip；逐文件枚举被拒路径原文。
4. 摘要检查前置于结构/path 检查（DR-01 R-2 末位约束）。
