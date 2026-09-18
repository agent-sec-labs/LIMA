# Decision Record DR-IP-0022-03：Profile 泄漏面补全（G1）+ B' 正例迁移与 model_digest 绑定（G2）+ 两项终裁落地

- DR 编号：DR-IP-0022-03（2026-09-13，PKT-IP-0022-D1R3，Assignment `IP-0022-PV-P1R3/v1`；Maintainer 二次驳回指令经主会话转达授权）
- 触发事件：Maintainer 二次驳回 PR #180（两点缺口 G1/G2，主会话已亲验成立，本 DR 制作期独立复现）
- 上游关系：DR-IP-0022-02（RESOLVED-COORDINATOR → **REOPENED-by-03 / 部分 SUPERSEDED**，见 §5）；DR-IP-0022-01（维持 REOPENED，存活条款不变）；Packet 升版 `IP-0022-PACKET/v3`
- 状态：RESOLVED-MAINTAINER（两项终裁——NFR-01 PARTIAL 记账口径与 R1 公开/内部面方案——由 Maintainer 定口径，本 DR 落地）

## 1. 二次驳回缺口与亲验证据

### G1：F1 漏 Profile `code_roles` 公开面

- **事实**：`lima/audit/inventory.py::_code_role_assignments`（:772-800 输出路径）把 `tests/token_FAKESECRET123.py` 以 `CodeRole.TEST`（reason_codes 含 `PATH_TEST_DIR`/`NOT_IMPORTED_BY_PROD`，有 test config manifest 时另含 `MANIFEST_TEST_CONFIG`）写入公开 Profile `code_roles`。
- **本 DR 独立复现**（@30bdfaa，2026-09-13，D1'' RED 运行）：`{"tests/token_FAKESECRET123.py": …}` → `code_roles=[(TEST, 'tests/token_FAKESECRET123.py')]`，`profile.to_dict()` 全文序列化含 `FAKESECRET`——泄漏=True（与主会话临时仓库复现一致）。
- **判定**：NFR-01 不豁免 Profile；Packet v2 只过滤 entrypoint 与 RAM 候选属修复边界不完整。

### G2：B' 正例迁移不相容 + `model_digest` 槽位未绑定

- **(a) MINIMAL_PAYLOAD 不自洽**：`tests/audit/test_ram_schema.py::MINIMAL_PAYLOAD`（定义 @:79）identity 六 digest 全为 `HEX64 = "0"*64`（@:39；identity 块 @:128-135）。本 DR 复现：B' 口径重算 ram 段 digest = `217f735a671baea2…` ≠ 嵌入零占位——只回填 `wire_digest` 不足以使该冻结正例在 B' 下通过，四个 digest（`ram_facts_digest`/`semantic_config_digest`/`semantic_result_digest`/`wire_digest`）须一并改为**彼此一致的真实重算值**（构造自洽最小载荷），并逐个检查既有负例仍因预期原因失败（结构/词表/rank 类负例与摘要无关；末位约束 DR-01 R-2 延续）。
- **(b) `identity.model_digest` 未入 B' 比对**：源码口径核验（无矛盾，停止条件未触发）——`semantic_prioritizer.py:636` `"model_digest": compute_content_digest(options.model_id)`，经 `:744-759` 进入 `SemanticTopNResult.model_digest` 并写入 wire identity。故重算口径 = `compute_content_digest(payload["build"]["semantic"]["model_id"])`（canonical 编码 str；实证：真实链 payload `digest("unset") = ac66e3bc…` == `identity.model_digest`）。`prompt_digest` 不可从 wire 复原（prompt_template 不在 wire），但其经 `semantic_config_digest` 比对传递性绑定（`semantic_config_digest_from_wire` 以 `identity.prompt_digest` 为输入，篡改它将同时改变重算值 → 与嵌入 `semantic_config_digest` 失配被拒）。
- **(c) 认证定位声明（如实写入校验目标声明）**：B' 摘要重算比对只证明**字段自洽**（防意外损坏与传输错配），**不能当作防恶意重签的认证**——持有 canonical 编码能力的恶意构造者可整体重算全部摘要；防重签不在本 IP 威胁模型内（对抗性来源治理属上游 #64/#68 与 closure 范围）。

## 2. G1 修复边界（Packet v3 §3.2 第三过滤点）

- `_code_role_assignments` 生成处：`is_secret_shaped_path(relative_path)` 为 True 的路径不生成 `CodeRoleAssignment`，计入 `inventory.skipped["sensitive-filename"]`（与 entrypoint/RAM 两过滤点同一 reason 通道）。
- 排序/cap 语义核验（停止条件未触发）：过滤发生在 `sorted(evidence)` 迭代内，剩余 assignments 的 `(role.value, path)` 排序与 `_MAX_CODE_ROLE_ASSIGNMENTS` cap/overflow 逻辑零改动；仅含秘密形态文件的仓的 assignments 数减少，属修复目标本身。
- 公开面（Packet v3 §0）：**五面**——Profile（entrypoints + code_roles 全文序列化）+ RAM facts + Top-N + prompt 文本 + wire payload。
- 新增负例：code_roles 不含秘密路径（G1-1）、`profile.to_dict()` 全文无秘密文件名（G1-2）、skip 计入 typed gap（G1-3）。

## 3. 两项终裁落地（Maintainer 已定口径，不再是提案）

### NFR-01：PARTIAL 记账

采纳诚实残余风险声明（DR-02 §1.4 逐字保留），且 IP-0022 对 NFR-01 的贡献**只记 PARTIAL**：启发式非穷尽 + 补上 Profile 泄漏面后仍不得写"零泄漏已解决"。Ledger NFR-01 行在 IP-DONE 时按 PARTIAL 口径入账（本 DR 与 Packet v3 §2 先行固化表述）。

### R1：公开面 reason→count；内部扫描内序号；无 sha8 短标识

- **公开面（批准）**：仅 `reason → count` 汇总（`reason=sensitive-filename; count=N`，模板不变）。**不批准** shape 家族计数入公开输出。
- **内部逐项记录（改设计）**：移除 `AdmissionSkipRecord(redacted_id="redact:<sha256(basename)[:8]>")` 设计——8-hex 截断摘要易猜测、同名碰撞、且只覆盖 sensitive-filename 不覆盖 FR-01 全部跳过项。改为：**扫描内序号 + reason、不带原文件名**（如 `(index=17, reason="sensitive-filename")`，挂载于 `ProfileBuildResult.admission_skips` / `RamFactsBuildResult.admission_skips` 默认空字段，`lima/audit` 层，不入 wire）。
- **FR-01 记 PARTIAL**：内部逐项记录在覆盖所有跳过原因（binary/size/limit/… 全 vocabulary）之前，FR-01 满足面记 PARTIAL。

## 4. B' 序列增补（Packet v3 §3.5）

`validate_ram_wire_payload` 校验序列在 `semantic_result_digest` 比对之后、`wire_digest`（末位）之前插入：

- `compute_content_digest(payload["build"]["semantic"]["model_id"]) != identity.model_digest` → `ContractError(INVALID_FIELD_VALUE, "$.identity.model_digest")`。

新负例：`identity.model_digest` 单字符篡改（G2-1）；`MINIMAL_PAYLOAD` 零占位被拒（G2-2，RED 形式）+ 自洽迁移正例（D2 构造，须既有负例逐个复核仍因预期原因失败）。校验目标声明追加 §1(c) 认证定位。

## 5. DR 链状态处置

- **DR-IP-0022-02**：`RESOLVED-COORDINATOR` → **REOPENED（by DR-IP-0022-03，2026-09-13）**。部分 SUPERSEDED：§3 R1 方案（redact:sha8 + 家族计数提案）被 Maintainer 终裁替代（本 DR §3）；§1/§2 口径由本 DR §1/§2/§4 增补（启发式 regex 本体含 9bd6159 补录的 `id_` SSH 私钥族，继续有效）。存活：启发式超集口径与超集断言、B' 路线与三 helper、M17 双负例、已否决路线清单。
- **DR-IP-0022-01**：维持 REOPENED（存活条款清单不变，见 DR-02 §4；其 F2 校验范围条款随 B' 增补同步扩展至 model_digest）。

## 6. 影响面与验收耦合

- 产品 Modify 面不变（`lima/audit/{inventory,ram,ram_schema,__init__}.py`），inventory 增 code_roles 过滤；冻结测试面新增 G1-1/2/3、G2-1/2 与迁移正例；DR-01 已授权两处既有断言修订的 minimal-payload 条目由"回填 wire_digest"升级为"四 digest 自洽重算"。
- 验收：Packet v3 §6 矩阵（M1'-M18 + G1/G2 系）全绿 + 回归锚（801、golden 15、`git diff 30bdfaa -- tests/audit/fixtures schemas` 为空）+ goldens 零命中复验（含 `id_` 族，本 DR 制作期复验：唯一 path-like 命中仍仅 `secret.py`）。
- PI-DR6：D2 冻结前非 Windows 平台完整跑一次。
