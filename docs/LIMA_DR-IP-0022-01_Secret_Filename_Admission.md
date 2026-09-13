# Decision Record DR-IP-0022-01：秘密形态文件名准入期拒绝（NFR-01 扩展口径 + 冻结面授权修订）

- DR 编号：DR-IP-0022-01（Contract Gap 裁定 + 冻结测试面修订授权，随 IP-0022 Packet v1 同批）
- 提出人：lima-packet-verification（PKT-IP-0022-D1，2026-09-13，Assignment `IP-0022-PV-P1/v1`）
- 上游裁定：COORD `ENTRY60-CLOSURE-1/v1`（方案 α：IP-0022=Fix IP，F1 路由=准入期拒绝；已否决：prompt/wire 层掩码 path）
- 状态：PROPOSED（待 Coordinator/Maintainer 复核；Packet IP-0022-PACKET/v1 §3/§7 为其执行面）

## 1. 裁定对象

1. **Contract Gap**：NFR-01（审计产物不得泄漏秘密材料）字面未区分"文件内容"与"文件名"。现状：`_SECRET_TOKEN_PATTERN`（`lima/audit/semantic_prioritizer.py:184-190`，五 token 形状：AKIA / BEGIN PRIVATE KEY / ghp_ / xox* / JWT）仅作用于 rationale 内容掩码（`_bounded_rationale` @:365）；文件名自 AttackSurfaceEntry 起原样透传全部四层。
2. **授权修订**（两项，均系冻结面变更，非授权即不可为）：缺口 1/2 对应的既有冻结断言修订 + skip reason 词汇表扩词。

## 2. 依据（实现证据链）

1. 主会话实证（Assignment 传递，三重亲验之一）：注入 `token_FAKESECRET123.py` 为 entrypoint → Top-N 泄漏 True；`_render_prompt` 描述符含 candidate_id/path（@semantic_prioritizer:375-385）。
2. 本次 P&V 独立复现实证（@30bdfaa，D1 RED 运行输出）：
   - RAM facts：`ghp_{'a'*36}.py` 同步入 sensitive_sinks/external_sources/trust_boundaries/key_flows（RED 输出全文在案）；
   - prompt：`_render_prompt` 渲染的 descriptors JSON 含 `"path":"ghp_aaa….py"`（M9 失败消息全文）；
   - wire payload：`ram_wire_payload` 序列化含秘密路径（M10 失败消息全文）；
   - profile entrypoints：manifest script 目标解析至秘密形态文件即生成 `ENTRY_SCRIPT_DECLARED` entry（M7 失败消息全文）。
3. 判定：与 NFR-01 目的（审计面零秘密泄漏）冲突，属 Contract Gap，关闭前阻断（ENTRY60-CLOSURE-1 已裁定归 IP-0022）。

## 3. 结论（冻结单解）

1. **NFR-01 扩展口径**：秘密形态文件名（basename 命中 `_SECRET_TOKEN_PATTERN` 口径）不得出现在 RAM facts / Top-N ranked / prompt 文本 / wire payload 四层任何位置。
2. **修复路线 = 准入期拒绝**（路由 α）：AttackSurfaceEntry 候选生成处（profile `_build_entrypoints` + RAM `candidates` 文件集）检测并拒绝进入候选集；被拒文件计入 `inventory.skipped["sensitive-filename"]`，经既有 `_skip_reason_gaps` 通道以 `GAP_INVENTORY_SKIPPED`（detail=`reason=sensitive-filename; count=N`）汇总——count-only，**不逐文件枚举**（逐字枚举被拒文件名本身即新泄漏通道）。
3. **明确不改**：`candidate_id` 生成规则、`ram_wire_digest` 算法与 identity 摘要口径、golden fixtures 及期望值。理由：合法 fixture 无秘密形态文件名（已核验 `tests/audit/fixtures/**` 全量，仅 `ram/shapes.py:193` 内容级 `AKIAIOSFODNN7EXAMPLE` 字符串，非文件名，且内容掩码已有 `_bounded_rationale` 覆盖），准入过滤对 goldens 零影响（R1 回归锚=golden matrix 15 用例原样通过）。
4. **口径复用方式**：`inventory._SECRET_FILENAME_PATTERN` 逐字符复制 `semantic_prioritizer._SECRET_TOKEN_PATTERN`（冻结测试断言两者 `pattern` 相等）；不修改 semantic_prioritizer（下游三层零改动裁定的落实）。

## 4. 影响面

- 产品：`lima/audit/inventory.py`（pattern/helper/入口过滤/词汇表）、`lima/audit/ram.py`（候选过滤）、`lima/audit/__init__.py`（导出）；`semantic_prioritizer`/`ram_schema` digest 语义/schema 文件零改动（F2 校验器加固为独立条目，不依赖本 DR，但同 IP 交付）。
- 冻结测试面（本 DR 授权范围，D2 随 Frozen Test Commit 落地）：
  - **缺口 2 查证结论：词汇表为封闭冻结枚举**——`tests/audit/test_fr05_gap_encoding.py:43-53` `FROZEN_SKIP_REASONS`（10 词）+ `:135` 集合等值断言；产品侧 `inventory.py:95-105` 同集合。授权：双侧同步增 `"sensitive-filename"`（第 11 词），detail 模板复用 `_SKIP_DETAIL_TEMPLATE`，`_skip_reason_gaps` 分流逻辑零改动。断言强度不降（仍为全量集合等值断言）。
  - **缺口 1 查证结论：存在 1 处宽松接受冻结断言**——`tests/audit/test_ram_schema.py::test_minimal_payload_validates`（@:232-233，`MINIMAL_PAYLOAD` identity 六 digest 全为占位 HEX64）依赖"校验器不重算比对"的宽松行为，与 F2(ii) 冲突。授权：D2 修订该用例 arrange——校验前将 `identity.wire_digest` 回填为 `ram_wire_digest(payload)` 重算值（其余占位 digest 保持，断言语义不变：合法结构 payload 通过）。真实链/golden/e2e 正例不受影响（均携带真实 digest，`test_golden_matrix.py:150` 已断言一致性）；既有正例无绝对路径/traversal 断言，F2(i) 零冲突。
- 消费方：#64/#68（Mining）无接口变化（wire 字段集不变）。

## 5. 已否决路线（不得重试）

1. prompt/wire 层掩码 path（ENTRY60-CLOSURE-1：改 candidate_id/golden digest，等价重冻结三层）。
2. `lima/workspace.py` 遍历层 skip（不在裁定路线；workspace.py 非冻结面，本 IP 不改）。
3. 逐文件枚举被拒路径（见 §3.2）。

## 6. R1 附注（变体处理预案）

若 Maintainer 终裁（R1）否决 count-only 汇总口径，要求更细粒度：任何"逐字携带被拒文件名"的变体须先评估其自身的泄漏通道；若要求"聚合 shape 分类"（如仅报 token 家族 ghp_/AKIA/JWT/…，不含原文），可作为词汇表 detail 模板的受控扩展，须新 DR + 本 DR 状态转 SUPERSEDED，不在本 Packet 范围。

## 7. 验收耦合

本 DR 生效以 Packet `IP-0022-PACKET/v1` §6 用例矩阵 M1-M10、M5/M6（词汇表与 typed gap）与 R1 回归锚全绿为准；Frozen Test Commit（D2）须含缺口 1/2 两处授权修订的落位 diff。
