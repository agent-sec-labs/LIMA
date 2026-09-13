# Implementation Packet IP-0022 — #60-Fix：关闭前阻断修复（F1 秘密形态文件名准入期拒绝 + F2 wire 校验器加固）

> 文档类型：Implementation Packet（P&V 制作）
>
> Packet 版本：`IP-0022-PACKET/v1`
>
> 修订历史：v1（2026-09-13，PKT-IP-0022-D1）
>
> 状态：`READY-FOR-CODE`（TBD = 0）
>
> Exact base：`30bdfaa13ac72572d65ccb2567ae8702923c4187`（origin/main，IP-0021 merge）
>
> 制作人：lima-packet-verification（Assignment `IP-0022-PV-P1/v1`，任务标识 `PKT-IP-0022-D1`，2026-09-13）
>
> 上游决策：COORD `ENTRY60-CLOSURE-1/v1`（Maintainer 预审 4 发现 + 主会话/Coordinator 三重亲验；拆分方案 α：IP-0022=Fix，IP-0023=closure）；DR-IP-0022-01（随本 Packet 同批，见 §DR 摘要与 `LIMA_DR-IP-0022-01_Secret_Filename_Admission.md`）；PI-DR1..PI-DR6 全部生效
>
> 随批文档：DR-IP-0022-01 正文、C1 勘误（`LIMA_DR-C1_ENTRY60-CLOSURE-1_Erratum_2026-09-13.md`）

---

## 0. Header（生命周期 §8）

```text
Source Issue：#60（[V4-I04][P0] Repository Profile、RAM 与安全语义清单，V5 覆盖层版）
Issue specification revision：2026-09-13 Issue #60 正文（含 ENTRY60-CLOSURE-1 入账；经 Assignment 派发包传递，API 亲取复核）
Covered requirements（本 IP 只声明自身贡献）：
  NFR-01 扩展口径（DR-IP-0022-01 固化）：秘密形态文件名不得出现在 RAM facts / Top-N / prompt 文本 / wire payload 四层
  FR-04 补全（wire 校验器加固）：validate_ram_wire_payload 路径 repo-relative POSIX 拒绝 + identity.wire_digest 重算一致性
Not covered requirements：F3 workspace _safe_path TOCTOU、F4 回包/时间不设防（→ IP-0023 closure 负例）；S4b/T-03/V5 端到端；#64/#68 消费验证；R1 终裁；monorepo 维度；任何 NFR-02 端到端宣称
Delivery role：hardening-fix（冻结面内最小防御 + 冻结测试面 DR 授权修订）
Issue closure impact：PARTIAL（解除两项关闭前阻断；Issue 关闭权在 Coordinator/Maintainer）
Upstream IP/PR/merge commits：IP-0016（fd219724）、IP-0018（cc17662）、IP-0019（e000e6f）、IP-0020（#176）、IP-0021（30bdfaa，#179）
Upstream ruling：ENTRY60-CLOSURE-1/v1（含已否决路线：prompt/wire 层掩码 path——不得重试）
```

## Design Input Manifest

1. `docs/LIMA_PACKET_AND_VERIFICATION_AGENT_RESPONSIBILITY_CHARTER.md`（v1.1）；2. `docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md`；3. `docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md`；4. Coordinator Assignment `IP-0022-PV-P1/v1`（含时序拆分说明）；5. Issue #60 正文（GitHub API 亲取，2026-09-13 版，含 ENTRY60-CLOSURE-1 §167-172）；6. 四层冻结面 @30bdfaa（`lima/audit/{inventory,ram,ram_schema,semantic_prioritizer}.py`、`tests/audit/**`、`schemas/v4/**`）；7. 既有 Packet IP-0016/0018/0019/0020/0021；8. DR 链（DR-IP-0021-0102、DR-IP-0020-2/3、DR-IP-0016-02 等）；9. PI-DR1..DR6；10. 主会话三重亲验记录（F1/F2/F3/F4 实证，经 Assignment 传递）。

## Explicitly Rejected Inputs

- 已否决路线：在 prompt / wire 层掩码 path（ENTRY60-CLOSURE-1 明示——等价改 candidate_id/wire digest/golden，重冻结三层）。本 Packet 全文不含任何掩码式修复。
- "把 skip 记录下沉到 `lima/workspace.py` 文件遍历层"的方案：不在裁定路线（裁定路线=AttackSurfaceEntry 准入处）；且 workspace.py 非四层冻结面，本 IP 不改。
- F3/F4 修复方案草案（→ IP-0023）。
- `schemas/v4/lima.repository-architecture-model.json` 增改（F2 路径/摘要拒绝在代码校验器实现，schema 文件零改动，避免 schema 语义变更连带 Packet 版本升级）。

## 1. Goal / Non-goals

### Goal

1. **F1 准入期拒绝**：在 AttackSurfaceEntry 候选生成处（profile 入口点构建 + RAM facts 候选文件集）检测秘密形态文件名（口径=`_SECRET_TOKEN_PATTERN` 的五 token 形状，作用于 basename），拒绝其进入候选集，并以 skip reason `sensitive-filename` 计入 `inventory.skipped` 汇总（经既有 `_skip_reason_gaps` 通道自动浮现 `GAP_INVENTORY_SKIPPED` typed gap，detail=`reason=sensitive-filename; count=N`）。
2. **F2 wire 校验器加固**：`validate_ram_wire_payload` 增加 (i) 所有承载 path 的字段（ram 五清单 entry、semantic.ranked）必须 repo-relative POSIX（拒绝绝对路径与 `..` 逃逸）；(ii) `identity.wire_digest` 必须等于 `ram_wire_digest(payload)` 重算值。
3. 冻结测试面 DR 授权修订（缺口 1/2，见 §7 与 DR-IP-0022-01）。

### Non-goals

- 不改 `candidate_id` 生成规则、`ram_wire_digest` 摘要算法、golden fixtures 及其期望值（合法 golden 五形状必须原样通过——回归锚）。
- 不改 `lima/audit/semantic_prioritizer.py`（含 `_SECRET_TOKEN_PATTERN` 本体与 `_render_prompt`；下游三层中 Top-N/semantic 层零改动）。
- 不改 `lima/contracts/**`、`lima/workspace.py`、`schemas/v4/**`、scanner/service、#64/#68 接线。
- 不做 F3/F4（→ IP-0023）。

## 2. 需求映射（Issue #60 → 本 IP）

| 来源 | 内容 | 本 IP 贡献 |
|---|---|---|
| NFR-01（经 DR-IP-0022-01 扩展） | 审计产物不得泄漏秘密材料 | 秘密形态**文件名**四层不出现（准入拒绝）；不宣称内容级泄漏面全部关闭 |
| FR-04（wire schema） | fail-closed 校验 | 路径与摘要一致性两维度补全 |
| ENTRY60-CLOSURE-1 F1 | Top-N/prompt 原样透传秘密文件名 | 准入期拒绝，路由 α |
| ENTRY60-CLOSURE-1 F2 | validate 无路径拒绝/无重算比对 | 校验器两检查项 |

## 3. 冻结接口清单（实现必须逐字对齐）

### F1

1. `lima/audit/inventory.py` 新增模块级：
   - `_SECRET_FILENAME_PATTERN: Final[re.Pattern[str]]`——regex 源**逐字符等于** `lima/audit/semantic_prioritizer._SECRET_TOKEN_PATTERN.pattern`（复制定义，不改 semantic_prioritizer；冻结测试断言两者 `pattern` 相等）。
   - `is_secret_shaped_path(path: str) -> bool`——对 path 的 basename（`path.rsplit("/", 1)[-1]`）执行 `_SECRET_FILENAME_PATTERN.search`；空串/非 str 返回 False（fail-open 到 False 之外一律 True 由 pattern 决定）。从 `lima/audit/__init__.py` 导出。
2. 准入过滤点（两处）：
   - `_build_entrypoints(summary, inventoried)`：`inventoried` 中 `is_secret_shaped_path` 为 True 的路径不生成 entrypoint（script-declared 解析结果与 root-convention 候选同样过滤）。
   - `build_python_ram_facts` 的 `candidates` 列表（`.py` 文件集，@ram.py:364-365）：过滤后再进入 RAM 派生，保证五清单（entrypoints/external_sources/sensitive_sinks/trust_boundaries/unresolved_edges）与 key_flows/labels 全部不含秘密形态路径。
3. skip 汇总：两处过滤各把被拒计数 `+1` 写入对应 `workspace.inventory().skipped["sensitive-filename"]`（`build_repository_profile` 与 `build_python_ram_facts` 各自持有一次 inventory 调用，各自计数；profile 侧经 `_skip_reason_gaps` → `GAP_INVENTORY_SKIPPED` typed gap 自动汇总，detail 复用 `_SKIP_DETAIL_TEMPLATE`）。
4. 词汇表扩展（DR-IP-0022-01 授权）：`_SKIP_REASONS` 增加 `"sensitive-filename"`；`SKIP_REASON_TO_GAP_DETAIL` 同步；非预算类、非 unsupported 分支——`_skip_reason_gaps` 逻辑零改动即正确分流。

### F2（`lima/audit/ram_schema.py`，仅校验器函数体）

5. `validate_ram_wire_payload` 在既有结构校验后追加：
   - **path 检查**：对 `ram.{sensitive_sinks,entrypoints,external_sources,trust_boundaries,unresolved_edges}` 每个 entry 与 `semantic.ranked` 每个 item 的 `path` 字段：非空 str、不含 `\`、不以 `/` 开头、不含 Windows 盘符前缀（`^[A-Za-z]:`）、任一路径段不等于 `..`。违例抛 `ContractError`，`INVALID_FIELD_VALUE`，路径定位 `$.ram.<section>[i].path` / `$.semantic.ranked[i].path`。
   - **摘要一致性**：`payload["identity"]["wire_digest"] != ram_wire_payload 重算口径` 即抛 `ContractError(INVALID_FIELD_VALUE, "$.identity.wire_digest")`；重算调用现有 `ram_wire_digest(payload)`（该函数零改动）。
6. `ram_wire_payload` / `ram_wire_digest` / digest 算法 / `_SCHEMA_VERSION` / schema 文件：零改动。

### 明确不改（Do-not-touch，实现侧）

`candidate_id()`（@semantic_prioritizer:333）、`_render_prompt`、`_SECRET_TOKEN_PATTERN` 本体、`lima/audit/semantic_prioritizer.py` 全文件、golden fixtures（`tests/audit/fixtures/golden_matrix/**`、`library_profile_golden.json`、`ram/shapes.py`、`semantic/shapes.py`）、`schemas/v4/**`、`lima/contracts/**`、`lima/workspace.py`、其余 `lima/**`。

## 4. 文件边界

| 类别 | 文件 |
|---|---|
| Add | `tests/audit/test_ip_0022_fix.py`（冻结测试，D2 轮落库；D1 已在 scratch 完成有效 RED，见 §6） |
| Modify | `lima/audit/inventory.py`（§3.1/§3.2/§3.4 + `__init__.py` 导出）、`lima/audit/ram.py`（§3.2 第二过滤点）、`lima/audit/ram_schema.py`（§3.5）、`lima/audit/__init__.py`（导出） |
| Modify（DR-IP-0022-01 授权的冻结测试面修订，D2 随 Frozen Test Commit） | `tests/audit/test_fr05_gap_encoding.py`（`FROZEN_SKIP_REASONS` 增 `"sensitive-filename"`）、`tests/audit/test_ram_schema.py`（`test_minimal_payload_validates` 的 arrange 修订：占位 `wire_digest` 先以 `ram_wire_payload` 重算值回填再校验，或 fixture 常量改为重算真值——两案取一，D2 定稿） |
| Read-only | 其余 `tests/**`、`schemas/**`、`docs/**` 既有文件、`lima/**` 其余 |
| Must-not-modify | `lima/contracts/**`、`schemas/v4/version_compatibility_matrix.json`、`lima/workspace.py`、`#94` 轨道一切（与开放 PR #178 零交集已核：本 IP 不触碰 IP-0020 packet 所辖文件） |

## 5. 行为约束与恢复要求

- 网络访问：禁止（既有冻结口径）。文件系统：仅测试临时 workspace（`workspace_with`）。无数据库/容器/远端写。
- 确定性：过滤顺序必须保持 `sorted` 语义不变（`candidates = sorted(...)` 后过滤，保持其余文件次序与 ordinal 不变——ordinal 是 candidate_id 组成部分，禁止因过滤重排）。
- 危险/边界必须验证：三种 token 形状（ghp_/AKIA/JWT——另两形状见 §6 用例 M9 说明）、basename 多级路径（`pkg/<token>.py`）、非秘密文件零误伤、绝对路径（POSIX 与 Windows 盘符）、`..` 逃逸（根级与嵌套）、摘要篡改（单字符翻转与 build 变更后陈旧摘要）。
- 停止条件（实现期）：出现需改 candidate_id/golden digest 才能表述的用例 ⇒ 停止，提交 Decision Request；冻结测试需变更 ⇒ 先 DR。

## 6. 最低用例矩阵（冻结测试集，≥14）

RED 已于 D1 全量证明（16 例全失败于缺失目标行为；证据见 §9）。正式冻结集 = 下表 + 既有套件回归锚。

| # | ID（D2 冻结名可微调，语义不得变） | 断言 |
|---|---|---|
| M1 | secret_shaped_path_helper_matches_frozen_pattern | `is_secret_shaped_path` 真/假例 + `_SECRET_FILENAME_PATTERN.pattern == _SECRET_TOKEN_PATTERN.pattern` |
| M2 | ram_facts_exclude_ghp_shaped_filename | 五清单无 ghp_ 路径（含非空 arrange 锚） |
| M3 | ram_facts_exclude_akia_shaped_filename | 同上 AKIA 形状 |
| M4 | ram_facts_exclude_jwt_shaped_filename | 同上 JWT 形状（BEGIN PRIVATE KEY 形状 Windows 文件名非法，以注释说明，不以文件名用例覆盖；口径等价由 M1 的 pattern 等值断言保证） |
| M5 | skip_reason_vocabulary_includes_sensitive_filename | `SKIP_REASON_TO_GAP_DETAIL` 含 `sensitive-filename`（与 test_fr05_gap_encoding 修订联动） |
| M6 | secret_filename_skip_reported_as_typed_gap | profile `GAP_INVENTORY_SKIPPED` detail=`reason=sensitive-filename; count=1` |
| M7 | profile_entrypoints_exclude_manifest_script_secret_target | script 目标解析至秘密形态文件不生成 entrypoint（safe 目标仍生成——arrange 锚） |
| M8 | topn_ranked_board_excludes_secret_shaped_filename | ranked board 无秘密路径 |
| M9 | prompt_text_excludes_secret_shaped_filename | scripted model 捕获的全部 prompt 不含 token（model_id 非 unset 激活） |
| M10 | wire_payload_excludes_secret_shaped_filename | `json.dumps(payload)` 不含 token |
| M11 | wire_absolute_posix_path_rejected | `/etc/app/danger.py` → ContractError |
| M12 | wire_windows_drive_absolute_path_rejected | `C:\repo\danger.py` → ContractError |
| M13 | wire_parent_traversal_path_rejected | `../danger.py` 与 `pkg/../../danger.py` → ContractError |
| M14 | wire_traversal_in_ranked_path_rejected | `semantic.ranked[0].path="../outside/danger.py"` → ContractError |
| M15 | wire_embedded_digest_mismatch_rejected | 单字符翻转 `identity.wire_digest` → ContractError |
| M16 | wire_stale_digest_after_build_change_rejected | `build.semantic.seed += 1` 后未更新摘要 → ContractError |
| R1 | 回归锚 | `tests/audit/test_golden_matrix.py` 15 用例全绿（五形状 golden 原样通过=不改 digest 的直接证据）+ `tests/audit`+`tests/contracts` 801 全绿 |

## 7. 缺口查证结论（Assignment 指定前置核验）

- **缺口 1（宽松接受断言）：存在 1 处**。`tests/audit/test_ram_schema.py::WireFormatPositiveTests::test_minimal_payload_validates`（@:232-233）断言 `MINIMAL_PAYLOAD`（identity 六 digest 全为同一占位 HEX64 常量）通过校验——与 F2(ii) 直接冲突。真实链 payload、golden、e2e 均携带真实 digest（`test_golden_matrix.py:150` 已断言一致性），不受影响。处置：并入 DR-IP-0022-01 授权清单，D2 修订 arrange（先回填重算 wire_digest 再校验），断言强度不降。既有正例无任何绝对路径/traversal 断言（fixtures 全为相对 POSIX 路径）——F2(i) 与既有冻结面零冲突。
- **缺口 2（skip reason 词汇表）：封闭枚举已冻结**。`tests/audit/test_fr05_gap_encoding.py:43-53` `FROZEN_SKIP_REASONS`（10 词）与 `:135` 断言 `frozenset(SKIP_REASON_TO_GAP_DETAIL) == FROZEN_SKIP_REASONS`；产品侧 `inventory.py:95-105` 同集合。新增 `sensitive-filename` 必须双侧同步并修订该冻结断言——DR 授权扩词，detail 模板复用 `_SKIP_DETAIL_TEMPLATE`（零新模板）。

## 8. 验收命令与判定

```bash
python -m pytest tests/audit tests/contracts -q        # ≥801+16 passed, 0 failed, 0 new skip
python -m pytest tests/audit/test_golden_matrix.py -q  # 15 passed（golden 原样）
```

判定依据：M1-M16 全绿；R1 全绿；`git diff 30bdfaa -- tests/audit/fixtures schemas` 为空（golden/schema 零改动）；ruff/bandit 零新 finding（沿用 IP-0016 门禁口径）。PI-DR6：D2 冻结前测试集须在至少一个非 Windows 平台完整跑过一次（记录 SHA 与结论）。

## 9. RED 证明（D1，本 Packet 的 Test-First 证据）

- 测试文件：`_red_proof/test_ip_0022_fix_red.py`（worktree scratch，不入 Packet commit；D2 移植至 `tests/audit/test_ip_0022_fix.py` 冻结）。
- 命令：`python -m pytest _red_proof/test_ip_0022_fix_red.py -q` @30bdfaa worktree。
- 结果：**16 failed**（M1-M16 全失败），失败签名全部为目标行为缺失：(a) 6 例 `AssertionError: True is not false` + 泄漏路径/载荷全文（含 prompt 描述符泄漏全文——独立复现主会话 F1 实证）；(b) 6 例 `AssertionError: ContractError not raised`（F2 全部）；(c) 1 例 `AttributeError: no attribute 'is_secret_shaped_path'`；(d) 1 例词汇表缺失；(e) 2 例 typed gap/entrypoint 缺失。无 arrange 型失败（每个 arrange 路径均有 sanity 锚或在既有冻结套件中同路径绿）。
- 非 sabotage 证明：同一 worktree `python -m pytest tests/audit tests/contracts -q` = **801 passed**（= 基线 184+617，0 改动）；golden matrix 15 passed 单独复核。

## 10. Completion Summary / PR 要求

PR 描述必须含：F1/F2 需求映射（§2）、冻结接口落位（§3）、验收命令输出摘要、golden 零改动 diff 证据、DR-IP-0022-01 执行情况（词汇表与 minimal-payload 断言修订落位 commit）、PI-DR6 非 Windows 平台跑测记录。禁止任何自动关闭 #60 的关键字（"fix #60" 等）。

## 11. R1 附注（DR-IP-0022-01 §6 摘引）

若 Maintainer 否决"skip reason 汇总"口径的变体处理（如要求逐文件枚举被拒路径），该变体本身可能引入新的泄漏通道（被拒文件名逐字入 gap detail）——DR 已预判并建议维持 count-only 汇总；变更需新 DR，不在本 Packet 范围。
