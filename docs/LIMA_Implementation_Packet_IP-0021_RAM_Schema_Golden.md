# Implementation Packet IP-0021 — RAM Wire Schema / Golden Matrix / Budget End-to-End（#60-S4a）

> 文档类型：Implementation Packet（P&V 制作）
>
> Packet 版本：`IP-0021-PACKET/v1`
>
> 状态：`READY-FOR-CODE`（TBD = 0）
>
> Exact base：`e000e6f794bb01312ff7c75a388177a951e6e028`（origin/main，含 IP-0016/0017/0018/0019/0020 交付）
>
> 制作人：lima-packet-verification（Assignment `IP-0021-PV-P1/v1`，任务标识 `PKT-IP-0021-D1`，2026-09-13）
>
> 上游决策：COORD `ENTRY60-S4-1/v1`（consumer review ADEQUATE + 边界裁定 + S4a 切分）；PI-DR1..PI-DR6 全部生效

---

## 0. Header（生命周期 §8）

```text
Source Issue：#60（[V4-I04][P0] Repository Profile、RAM 与安全语义清单，V5 覆盖层版）
Issue specification revision：2026-09-12 Issue #60 正文（V5 覆盖层版；Delivery Ledger 更新至 2026-09-13，IP-0021 行已登记、切分记录在 open decisions——经 Assignment 派发包传递）
Covered requirements（本 IP 只声明自身贡献）：
  FR-04 剩余（RAM wire schema 化：profile/RAM facts/Top-N 字段全集入 schema；参数/seed/budget/provenance 入 schema；identity 稳定断言口径=三 digest 组合）
  FR-05 剩余（GAP_MANIFEST_PARSE_ERROR 编码断言补全、unsupported 子集 typed gap 编码、execution_required typed 承载——语义提案见 §5.4，待 Coordinator 复核）
  AC-01/T-01 本 IP 子集（五类 repo 形态全链 golden fixtures：profile+RAM+Top-N，provenance 链 + Top-N 顺序可重放断言；monorepo 维度不在本 IP）
  V5-AC-01 剩余（非 monorepo 维度）
  预算端到端（三层 ProfileBudgets/RamBudgets/SemanticBudgets 跨层 fixture 断言）
  IP-0019 移交项归置（gap① generic-exception 冻结测试面补全；gap⑤ IP-0019 Packet §3.1 勘误——随本 Packet docs 批次同 commit，见 §5.8）
Not covered requirements：component graph / monorepo 维度（V5-FR-03 全量 → #60-S4 后续或 backlog BG-60-01）、安全停止端到端（→ closure）、FR-05 的 Mining 消费接线（→ #64/#68）、`lima/contracts/` 任何修改、version_compatibility_matrix 注册（禁区，BG-60-01 backlog）、既有 schemas/v4 14 文件、下游 #64/#68 接线、scanner/service、AC-03/T-03 与 NFR-02 端到端（→ closure）
Delivery role：domain（schema/验证模块 + 测试矩阵与 golden fixtures + 文档勘误）
Issue closure impact：PARTIAL
Upstream IP/PR/merge commits：IP-0016（merge fd219724）、IP-0018（merge cc17662）、IP-0019（merge e000e6f，含 IP-0018 v1.1 勘误先例 #172）、IP-0020（Packet #173 @1a98fee）
Upstream ruling：ENTRY60-S4-1/v1（IP-0021 = #60-S4a；四条边界裁定见 §4）
```

本 Packet 只声明 IP-0021 自身贡献。AC-01/T-01 的 monorepo 维度、端到端安全负例与全量 AC 满足归 #60-S4 后续与 closure，本 Packet 不宣称。

---

## 1. Goal / Non-goals

### Goal

1. 新增 `schemas/v4/lima.repository-architecture-model.json`：RAM wire schema，承载 profile 摘要 + RAM facts 全集 + semantic Top-N 的字段全集，参数（top_n/weights/tie_break）、seed、三层 budgets、provenance anchors 与 identity（三 digest）入 schema；
2. 新增 `lima/audit/ram_schema.py`：schema 侧验证与组合模块——纯函数构建 wire payload、执行 schema 校验（fail-closed `ContractError`）、计算 wire digest、派生 `execution_required` typed 承载；
3. FR-05 剩余补全：`GAP_MANIFEST_PARSE_ERROR` 编码断言、unsupported 子集 typed gap 编码断言、`execution_required` typed 承载（§5.4 提案，冻结单解待 Coordinator 复核后生效）；
4. AC-01/T-01（非 monorepo）：五类 repo 形态（application/library/CLI/docs/test-heavy）全链 golden fixtures 与可重放断言；
5. 三层预算跨层端到端 fixture 断言；
6. IP-0019 移交项归置：gap①（generic-exception 回归补强用例入测试矩阵）、gap⑤（IP-0019 Packet §3.1 勘误 v1.2，同 commit docs 批次）。

### Non-goals

- 不修改 `lima/contracts/**`、既有 schemas/v4 14 文件、`schemas/v4/version_compatibility_matrix.json`（未注册即本 schema 的合法状态；注册是独立决策 BG-60-01）；
- 不修改 `lima/audit/{inventory,ram,semantic_prioritizer}.py`（三层冻结面只读消费）；
- 不做 component graph / monorepo 维度（→ #60-S4 后续）；
- 不做 Mining 层 `execution_required` 消费（#64/#68 接线，本 IP 只冻结承载语义）；
- 不把任何新字段塞入 `RepositoryProfile`/`AttackSurfaceEntry`/`ProfileCoverageGap` extensions（DR-TOPN-01 B-10：v4 非空 extensions 即拒，不得借 schema 化反向放开）。

---

## 2. Design Input Manifest

| Input ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001 | Standard | `docs/LIMA_PACKET_AND_VERIFICATION_AGENT_RESPONSIBILITY_CHARTER.md` | main @e000e6f | Packet 结构、冻结/验证边界 | normative | — |
| DI-002 | Standard | `docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md` | main @e000e6f | 不执行/路径有界/fail-closed 不变量 | normative | — |
| DI-003 | Standard | `docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md` §8/§9 | main @e000e6f | Packet Gate 全清单、禁自动关闭 | normative | — |
| DI-004 | Decision | Coordinator Assignment `IP-0021-PV-P1/v1`（含 ENTRY60-S4-1/v1 全文：consumer review ADEQUATE、四条边界裁定、S4a 切分、Not-covered） | 2026-09-13 | 范围、文件边界、禁区清单 | normative | 唯一上游裁定 |
| DI-005 | Issue | Source Issue #60 正文（V5 覆盖层版）+ Delivery Ledger（IP-0021 行、open decisions 切分记录，经 Assignment 传递） | 2026-09-13 | FR-04/FR-05/AC-01/V5-AC-01 文本 | normative | V5 覆盖层优先 |
| DI-006 | Upstream IP | 三层冻结面：`lima/audit/inventory.py`、`lima/audit/ram.py`、`lima/audit/semantic_prioritizer.py`（44 符号、三 digest、candidate_id、GAP 码全集、三层 Budgets）@e000e6f | @e000e6f 亲验 | §3/§5 全部消费面 | normative（接口） | 只读消费；漂移 → DR |
| DI-007 | Upstream IP | `lima/audit/__init__.py` @e000e6f：104 行、`__all__` 44 项（IP-0016 11 + IP-0018 9 + IP-0019 24），分段断言先例 `[0:11]`/`[11:20]`/`[20:44]` | @e000e6f 亲验 | §5.7 纯追加方案 | normative | — |
| DI-008 | Code | `lima/contracts/profile.py`：`_validated_extensions`/`_reject_current_minor_nested_extensions`（v4 非空 extensions 即 `UNKNOWN_FIELD`）；`lima/contracts/codec.py` `compute_content_digest`；`lima/contracts/errors.py` `ContractError` | @e000e6f | B-10 禁挂 extensions、digest 口径、fail-closed 异常类型 | normative（#58 冻结契约） | — |
| DI-009 | Contract 先例 | `schemas/v4/lima.repository-profile.json`（draft 2020-12、`additionalProperties:false`、required 全列、maxItems 4096 上界风格）+ tests/contracts 无目录枚举断言（亲验：`test_compatibility_matrix.py` 只枚举 matrix 文件自身行） | @e000e6f | §5.1 schema 结构风格；Add 合法性 | normative（风格） | — |
| DI-010 | Packet 先例 | IP-0016（golden/LF 口径、`tests/audit/fixtures/repo_shapes.py` 模式）、IP-0018（预算模式、勘误 v1.1 先例 #172）、IP-0019（§3.1 消费面、降级矩阵） | main @e000e6f | §5.5 golden 矩阵、§5.6 预算矩阵、§5.8 勘误格式 | normative（先例） | — |
| DI-011 | Decision | PI-DR1..PI-DR6 | Ledger | 测试平台中立、冻结前非 Windows 完整跑一次、PR 关键字 | normative | — |
| DI-012 | Upstream IP | tests/audit 既有 5 测试文件（107 用例，含 IP-0018 修正版 `test_ram_facts.py`、IP-0019 `test_semantic_prioritizer.py` L816-817 分段断言 `[20:]` 封顶教训） | @e000e6f 亲跑 | §6 测试矩阵零改动边界、回归基线 107 | normative | — |
| DI-013 | Upstream IP | IP-0019 移交项：gap①（generic-exception 冻结测试面）、gap⑤（§3.1 字面差异）——Assignment §"IP-0019 移交项归置" | 2026-09-13 | §5.4.3、§5.8 | normative | — |

### Explicitly Rejected Inputs

- 任何把 RAM/semantic 字段挂入 `RepositoryProfile.extensions` 或既有 envelope schema 的方案——与 `_validated_extensions` 冻结语义冲突（DI-008、B-10）；
- 任何对 `version_compatibility_matrix.json` 的注册尝试——Coordinator 明示禁区（BG-60-01 backlog），且 `test_matrix_lists_all_thirteen_schemas` 等用例以 matrix 文件为唯一枚举源，注册会改 617 冻结面；
- "修改既有 tests/audit 5 文件以适配新断言"的方案——Assignment 边界裁定 3：新增测试独立文件；
- IP-0020 vault/audit 轨道的任何文件与决策（平行轨道，非本 IP 输入）；
- #94 轨道全部路径（`lima/evidence_privacy/`、`tests/evidence_privacy/`、`docs/LIMA_Issue_94_*`）。

---

## 3. Current code baseline（亲验誊录，@e000e6f）

### 3.1 三层冻结面消费面（DI-006）

- **Layer 1（inventory）**：`PROFILE_PROVENANCE_ANCHOR="inventory"`；`GAP_UNSUPPORTED_LANGUAGE="UNSUPPORTED_LANGUAGE"`、`GAP_BUDGET_EXHAUSTED="BUDGET_EXHAUSTED"`、`GAP_MANIFEST_PARSE_ERROR="MANIFEST_PARSE_ERROR"`、`GAP_NO_LANGUAGES_DETECTED="NO_LANGUAGES_DETECTED"`、`GAP_INVENTORY_SKIPPED="INVENTORY_SKIPPED"`；`SKIP_REASON_TO_GAP_DETAIL`（11 skip reasons，模板 `reason={reason}; count={count}`；`file-limit`/`file-size-limit`/`total-size-limit` → BUDGET_EXHAUSTED，`unsupported-extension` → UNSUPPORTED_LANGUAGE，其余 → INVENTORY_SKIPPED）；`ProfileBudgets{manifest_max_bytes=262144, max_manifest_files=64}`；`ProfileBuildResult{profile, envelope, provenance_anchor_ids}`。
- **Layer 2（ram）**：`RAM_PROVENANCE_ANCHOR="ram-facts"`；`GAP_DYNAMIC_IMPORT`/`GAP_AMBIGUOUS_DISPATCH`；`RamBudgets{max_python_files=512, max_key_flows=256, max_unresolved_edges=1024}`；`PythonRamFacts{entrypoints, external_sources, source_labels, sensitive_sinks, sink_rule_ids, sink_cwes, trust_boundaries, key_flows, unresolved_edges, coverage_gaps, counters}`；`ram_facts_digest(facts) -> str`（canonical dict → `compute_content_digest`，64-hex）。**口径注记（勘误依据，DI-013）**：`sink_rule_ids`/`sink_cwes` 与 `sensitive_sinks` 按索引一一对应；**`key_flows` 不与 sensitive_sinks 索引对应**——flows 按 `(sink_rule_id, steps)` 独立排序且受 `max_key_flows` 截断（sinks 本身不截断），IP-0019 Packet §3.1"按索引一一对应"表述为字面差异（→ §5.8 勘误；semantic 层按 ordinal 的关联是位置回退近似，属已冻结行为，本 IP 不改）。
- **Layer 3（semantic）**：`SEMANTIC_PROVENANCE_ANCHOR="semantic-prioritizer"`；`SEMANTIC_MAX_TOP_N=100`；`GAP_SEMANTIC_MODEL_OFF/TIMEOUT/MALFORMED_OUTPUT`；值重述 `_GAP_BUDGET_EXHAUSTED="BUDGET_EXHAUSTED"`；九 category 词汇表；`SemanticWeights`（9 非负整数字段）、`SemanticBudgets{max_llm_calls=8, max_prompt_tokens_estimate=24000, max_output_tokens_estimate=4096, max_total_tokens_estimate=28096, max_wall_time_seconds=120}`（total ≥ prompt+output 构造期不变量）、`SemanticOptions{top_n=20, weights, seed=0, budgets, model_id="unset", prompt_template, tie_break="kind-path-symbol-ordinal"}`、`SemanticCandidate{candidate_id, kind, path, symbol, score, rank, category, rationale, key_flow_steps}`、`SemanticTopNResult{ranked, total_candidates, coverage_gaps, prompt_digest, model_digest, config_digest, result_digest, provenance_anchor_ids}`、`candidate_id(kind,path,symbol,ordinal)`（`{kind}:{path}:{symbol|-}#{ordinal}`）、`semantic_config_digest(options)`、`semantic_result_digest(result, *, input_facts_digest=None)`、`build_semantic_top_n(facts, *, options=None, model_client=None)`。
- **GAP 码全集（本 IP 消费，不得新增/改名）**：`BUDGET_EXHAUSTED`、`INVENTORY_SKIPPED`、`MANIFEST_PARSE_ERROR`、`NO_LANGUAGES_DETECTED`、`UNSUPPORTED_LANGUAGE`（L1）；`DYNAMIC_IMPORT`、`AMBIGUOUS_DISPATCH`（L2）；`SEMANTIC_MODEL_OFF`、`SEMANTIC_MODEL_TIMEOUT`、`SEMANTIC_MALFORMED_OUTPUT`（L3）。共 10 码。

### 3.2 `__init__.py` 现状（DI-007）

104 行；`__all__` 44 项 = IP-0016 段 `[0:11]` + IP-0018 段 `[11:20]` + IP-0019 段 `[20:44]`；既有分段断言：`test_ram_facts.py` L322 `__all__[:11]`/L324 `__all__[11:20]`，`test_semantic_prioritizer.py` L816 `__all__[:20]`/L817 `__all__[20:]`（后者是封顶教训来源：本 IP 新断言必须用 `[20:44]` 有界段）。

### 3.3 基线实测（亲跑，worktree `D:\BaseAIProject\LIMA-ip-0021-pv-wt` @e000e6f）

- `python -m unittest discover -s tests/contracts -q` → **Ran 617 tests, OK**（与预期一致）；
- `python -m unittest discover -s tests/audit -q` → **Ran 107 tests, OK (0 skip)**（与 Assignment 预期一致）；
- `python -m unittest discover -s tests -q` → **Ran 1223 tests, OK (skipped=1)**（预存 symlink 环境 skip；与预期一致）。

### 3.4 与预期的偏差核验

无偏差。Coordinator 边界裁定 1（tests/contracts 无目录枚举断言）已亲验复核：`test_compatibility_matrix.py` 只从 `version_compatibility_matrix.json` 行集枚举，新增未注册 schema 文件不触及 617。不触发 DR。

---

## 4. Files boundary（Coordinator 裁定冻结，ENTRY60-S4-1/v1）

- **Files to Add（阶段二，本阶段仅设计）**：
  - `schemas/v4/lima.repository-architecture-model.json`（唯一新 schema；**不注册 matrix**）；
  - `lima/audit/ram_schema.py`（唯一产品代码文件）；
  - `tests/audit/test_ram_schema.py`、`tests/audit/test_fr05_gap_encoding.py`、`tests/audit/test_golden_matrix.py`、`tests/audit/test_budget_exhaustion_e2e.py`；
  - `tests/audit/fixtures/golden_matrix/__init__.py`、`tests/audit/fixtures/golden_matrix/shapes.py`、`tests/audit/fixtures/golden_matrix/golden/*.json`（五形态 golden fixtures，Implementation 产出的合法数据产物）。
- **Product Files Allowed to Modify**：`lima/audit/__init__.py` —— 仅限"纯追加 re-export"（§5.7）；既有 `[0:44]` 前缀、import 行、docstring 既有语句零改动。
- **Files Forbidden**：除上述外的一切路径；特别冻结：`lima/contracts/**`、`schemas/v4/version_compatibility_matrix.json`、schemas/v4 既有 14 文件、`lima/audit/{inventory,ram,semantic_prioritizer}.py`、tests/audit 既有 5 测试文件（`test_profile_contract_encoding.py`、`test_profile_inventory.py`、`test_profile_security.py`、`test_ram_facts.py`、`test_semantic_prioritizer.py`）、tests/audit 既有 fixtures（`repo_shapes.py`、`library_profile_golden.json`、`ram/`、`semantic/`）、#94 轨道、`.zcode/**`。
- **本阶段（D1）已交付 docs 批次**：本 Packet 主件 + IP-0019 Packet v1.2 勘误（§5.8，同 commit）。

---

## 5. 冻结设计

### 5.1 RAM wire schema（`schemas/v4/lima.repository-architecture-model.json`）

结构风格沿 `lima.repository-profile.json` 先例（DI-009）：draft 2020-12、顶层 `additionalProperties:false`、required 全列、集合字段 `maxItems: 4096`、紧凑单对象。字段全集与三层冻结面映射表（每个 schema 字段 ← 冻结产物字段；无任何凭空字段）：

| schema 路径 | 来源（冻结产物.字段） | 约束 |
|---|---|---|
| `schema_version` | 字面 `"4.0"`（对齐 `ProfileInventoryOptions.schema_version`） | const 字符串 |
| `model_kind` | 字面 `"lima.repository-architecture-model"` | const |
| `build.profile_budgets.{manifest_max_bytes, max_manifest_files}` | `ProfileBudgets` 两字段 | 正整数 |
| `build.ram_budgets.{max_python_files, max_key_flows, max_unresolved_edges}` | `RamBudgets` 三字段 | 正整数 |
| `build.semantic.top_n` / `seed` / `tie_break` / `model_id` | `SemanticOptions` 四字段 | top_n ∈ [1,100]；seed ≥ 0；tie_break const `"kind-path-symbol-ordinal"`；model_id 字符串 |
| `build.semantic.weights.{sink_flow_command, sink_flow_sql, sink_flow_eval, sink_flow_path, sink_flow_deserialization, entrypoint, external_source, trust_boundary, unresolved_edge}` | `SemanticWeights` 九字段 | 非负整数 |
| `build.semantic.budgets.{max_llm_calls, max_prompt_tokens_estimate, max_output_tokens_estimate, max_total_tokens_estimate, max_wall_time_seconds}` | `SemanticBudgets` 五字段 | 正整数（total ≥ prompt+output 由模块校验，schema 层正整数） |
| `ram.entrypoints/external_sources/sensitive_sinks/trust_boundaries/unresolved_edges[]` | `PythonRamFacts` 五个 `AttackSurfaceEntry` 元组（`to_dict()`：path/symbol/reason_codes/source_artifact_ids） | `symbol` 可 null；repo-relative POSIX |
| `ram.source_labels[]` / `sink_rule_ids[]` / `sink_cwes[]` | `PythonRamFacts` 三并行元组 | 字符串数组；`sink_rule_ids`/`sink_cwes` 与 `sensitive_sinks` 等长（模块校验） |
| `ram.key_flows[].{sink_rule_id, steps[]}` | `RamKeyFlow` | steps ≤ 12（`_MAX_TRACE_STEPS` 口径） |
| `ram.coverage_gaps[].{gap_code, detail}` | `PythonRamFacts.coverage_gaps`（`ProfileCoverageGap.to_dict()`） | gap_code pattern `[A-Z][A-Z0-9_]{0,63}` |
| `ram.counters{}` | `PythonRamFacts.counters`（八键定名：ambiguous_modules/cross_file_edges/dynamic_import_sites/functions_indexed/interprocedural_edges/modules_indexed/parse_error_files/unresolved_calls） | 非负整数 |
| `semantic.ranked[].{candidate_id, kind, path, symbol, score, rank, category, rationale, key_flow_steps[]}` | `SemanticCandidate` 十字段 | category ∈ 九词汇表 const 枚举；rank 从 1 连续；candidate_id 模式 `{kind}:{path}:{symbol\|-}#{ordinal}` |
| `semantic.total_candidates` | `SemanticTopNResult.total_candidates` | 非负整数 |
| `semantic.coverage_gaps[]` | `SemanticTopNResult.coverage_gaps` | 同上 gap 结构 |
| `identity.ram_facts_digest` | `ram_facts_digest(facts)` | 64-hex |
| `identity.semantic_config_digest` / `identity.semantic_result_digest` | `semantic_config_digest(options)` / `result_digest` | 64-hex |
| `identity.prompt_digest` / `identity.model_digest` | `SemanticTopNResult.prompt_digest/model_digest` | 64-hex |
| `identity.wire_digest` | `ram_wire_digest(payload)`（本 IP 新增，§5.2） | 64-hex |
| `provenance.provenance_anchor_ids[]` | 三层链 `("inventory","ram-facts","semantic-prioritizer")` 顺序冻结 | const 序列 |
| `execution_required.{required, trigger_gap_codes[]}` | 派生（§5.4） | required: bool；trigger_gap_codes ⊆ 10 码全集，去重升序 |

**identity 稳定断言口径（冻结单解）**：RAM wire 的 identity = 三 digest 组合 `(ram_facts_digest, semantic_config_digest, semantic_result_digest)`——同 workspace 快照 + 同三层 budgets + 同 semantic options 下两次独立构建，三 digest 逐一相等 **且** Top-N `candidate_id` 序列逐位相等；`wire_digest` 是三 digest + build 配置的 `compute_content_digest` 再封装（canonical JSON、64-hex、不含耗时/时钟/环境）。

### 5.2 `lima/audit/ram_schema.py` 冻结接口

```python
RAM_WIRE_SCHEMA_NAME: Final[str] = "lima.repository-architecture-model"
RAM_WIRE_SCHEMA_FILE: Final[Path] = Path("schemas") / "v4" / "lima.repository-architecture-model.json"
GAP_CODES_ALL: Final[frozenset[str]]         # 10 码全集（值重述，不 import 三层模块）
GAP_EXECUTION_REQUIRED_TRIGGERS: Final[frozenset[str]]   # §5.4 提案表
PROVENANCE_ANCHOR_CHAIN: Final[tuple[str, str, str]] = ("inventory", "ram-facts", "semantic-prioritizer")

def execution_required_from_gaps(gap_codes: Iterable[str]) -> tuple[bool, tuple[str, ...]]
def ram_wire_payload(ram_result, semantic_result, *, profile_budgets=None, ram_budgets=None, semantic_options=None) -> dict
def validate_ram_wire_payload(payload: Mapping[str, object]) -> None      # fail-closed：ContractError
def ram_wire_digest(payload: Mapping[str, object]) -> str                # 64-hex
def load_ram_wire_schema() -> dict                                        # 只读加载 schema 文件（相对 repo root 定位，零网络）
```

冻结行为约束：stdlib-only；依赖方向只到 `lima.contracts` 与三层数据类的类型检查（`isinstance`），**不得 import** `lima.audit.{inventory,ram,semantic_prioritizer}` 的构建函数（验证模块与构建模块解耦，与既有层间方向一致）；`validate_ram_wire_payload` 对未知字段/类型错/枚举外值/长度不并行/rank 不连续/digest 非 64-hex 一律 `ContractError`（fail-closed，绝不静默修正）；`ram_wire_payload` 纯函数确定性（无时钟/随机/环境/网络/写盘）；`execution_required_from_gaps` 对全集外 gap_code raise `ValueError`。

### 5.3 `__init__.py` 追加方案（§4 Modify 边界内）

在 `semantic_prioritizer` import 块之后追加一个 `from lima.audit.ram_schema import (...)` 块，`__all__` 末尾追加按字母序的 9 个新名：`GAP_CODES_ALL`、`GAP_EXECUTION_REQUIRED_TRIGGERS`、`PROVENANCE_ANCHOR_CHAIN`、`RAM_WIRE_SCHEMA_FILE`、`RAM_WIRE_SCHEMA_NAME`、`execution_required_from_gaps`、`load_ram_wire_schema`、`ram_wire_digest`、`ram_wire_payload`、`validate_ram_wire_payload`（10 名，如实现期签名微调以 §5.2 为准，数量 K 以冻结测试记录为准）。docstring 首行后可追加一句说明。追加后 `python -c "import lima.audit"` 零副作用。分段断言扩展（新测试文件内，**不动既有文件**）：`__all__[:44]` 与既有 44 项逐一相等 + `__all__[44:44+K]` 恰为新符号（有界段，IP-0018 封顶教训：禁用 `[44:]` 裸尾断言之外不得改写既有 `[20:]` 断言——既有文件不动，其 `[20:]` 断言天然因追加而失败的问题由** Coordinator 边界裁定 3 + 停点条款 §9.6 处理**：实现前须先按 DR 流程更新该断言或由本 Packet 冻结测试以兼容方式覆盖，见 §9 停点 6）。

> **勘误（制作时发现，不阻塞）**：`test_semantic_prioritizer.py` L817 `assertEqual(audit.__all__[20:], IP0019_NEW_SYMBOLS)` 在任何后续 `__init__.py` 追加后必然失败。这是 Assignment 边界裁定 2 预告的"分段断言须同步扩展"的具体落点：既有文件属禁区（裁定 3），故该断言更新必须走冻结测试变更授权流程（§9 停点 6 + DR），本 Packet 阶段二冻结测试将把"更新 `IP0019_NEW_SYMBOLS` 比较为 `[20:44]` 有界段"列为**需 Coordinator 授权的最小测试变更项**，一并在 Decision Request 中提交。

### 5.4 `execution_required` 语义提案（**待 Coordinator 复核**；冻结单解后生效）

**承载**：仅存在于 RAM wire envelope 的 `execution_required` typed 字段（`required: bool` + `trigger_gap_codes: tuple[str, ...]` 去重升序）；不进 `RepositoryProfile`、不进 `ProfileCoverageGap.extensions`、不新增 GAP 码。

**规则表（提案）**——`required = (出现的 gap_code 集合 ∩ 触发集) ≠ ∅`，`trigger_gap_codes = 交集元素升序`：

| GAP 码 | 置位 execution_required | 依据 |
|---|---|---|
| `BUDGET_EXHAUSTED`（任一层 detail） | **是** | 截断 ⇒ 静态覆盖不完整，需执行/深挖补全 |
| `INVENTORY_SKIPPED` | **是** | 文件被跳过 ⇒ 覆盖洞 |
| `MANIFEST_PARSE_ERROR` | **是** | 构建/依赖元数据未知 |
| `NO_LANGUAGES_DETECTED` | **是** | 语言层无信号 ⇒ 静态面失效 |
| `UNSUPPORTED_LANGUAGE` | **是** | 子集不受支持 ⇒ 静态面缺失 |
| `DYNAMIC_IMPORT` | **是** | 静态调用图不可解 |
| `AMBIGUOUS_DISPATCH` | **是** | 静态分发不可解 |
| `SEMANTIC_MODEL_OFF` | **是**（保守：语义覆盖不完整；note 语义与 not-an-absence-of-risk 一致） | L3 降级 |
| `SEMANTIC_MODEL_TIMEOUT` | **是** | L3 降级 |
| `SEMANTIC_MALFORMED_OUTPUT` | **是** | L3 降级 |

即**提案 A（保守全触发）**：任一 typed gap ⇒ `required=True`；零 gap ⇒ `required=False, trigger_gap_codes=()`。**备选提案 B（窄触发）**：仅静态覆盖性 gap（前 7 码）触发，L3 语义降级三码不置位（理由：语义层是补充视图，模型 off 是默认态，全触发会使默认 CI 构建恒 True，削弱信号）。P&V 建议 **A**（fail-closed 一致性：任何覆盖缺口都不应被解释为"无需进一步执行"），但承认 B 的信噪比论证；**由 Coordinator 单解裁定后写入冻结测试**，未裁定前阶段二不冻结该面的测试（列入 §9 停点 5）。

**FR-05 剩余同步断言**：`GAP_MANIFEST_PARSE_ERROR` 在 manifest 损坏 fixture 下以冻结 detail 模式出现（现有 `_load_one_manifest` 行为，只补断言不改行为）；unsupported 子集：`unsupported-extension` skip reason → `UNSUPPORTED_LANGUAGE` typed gap（`SKIP_REASON_TO_GAP_DETAIL` 映射断言，含 11 reasons 全表 + 三分桶正确性）；generic-exception 回归（IP-0019 gap①）：含裸/宽 `except` 形态的 fixture 在 RAM/semantic 链下 facts 稳定、gap 编码不漂移（回归补强，不改语义）。

### 5.5 AC-01/T-01 golden matrix（非 monorepo，五形态全链）

沿用 IP-0016 `repo_shapes.py` 的 LF 口径模式（`workspace_with` 临时目录 + `RepositoryWorkspace`，`\n` 写入、零网络零执行）。五形态（`tests/audit/fixtures/golden_matrix/shapes.py` 冻结定义，每形态 ≥ 4 文件、含各自特征信号）：

| 形态 | 特征信号（设计下限） |
|---|---|
| `application` | 框架 manifest（如 requirements.txt + fastapi 关键词）+ endpoint 装饰 + external source + tainted sink |
| `library` | setup/pyproject + 无 endpoint + 少量 sink（对齐既有 `library_profile_golden.json` 风格） |
| `cli` | `__main__.py`/argparse 入口 + 命令执行 sink |
| `docs` | 无 .py 或极少 .py + markdown 为主（低代码密度；可触发 NO_LANGUAGES_DETECTED 或极小语言集——按冻结实现行为定 golden） |
| `test-heavy` | tests/ 占比高 + mock/dynamic import（可触发 DYNAMIC_IMPORT） |

每形态 golden 断言（`tests/audit/fixtures/golden_matrix/golden/<shape>.json`）：全链 profile（`build_repository_profile`）→ RAM（`build_python_ram_facts`）→ Top-N（`build_semantic_top_n`，默认 options，模型 off 路径）三段产物对 golden 逐字段相等（profile 段沿 IP-0016 golden 口径；RAM/semantic 段按 §5.1 映射表投影后比较）+ `provenance_anchor_ids` 链逐层断言（`("inventory",)`/`("ram-facts",)`/`("semantic-prioritizer",)`）+ wire payload（§5.2）三 digest 与 golden 相等 + **Top-N 可重放**：同输入两次独立全链构建，三 digest 全等且 `ranked[*].candidate_id` 序列逐位相等。golden JSON 由 Implementation 在有效 RED 后从冻结实现产出（合法数据产物），提交前经 P&V 核对 digest 链。

### 5.6 预算端到端矩阵（三层跨层）

| 触发层 | 触发方式（fixture + 显式 budgets） | 断言 |
|---|---|---|
| L1 ProfileBudgets | 多 manifest 文件 > `max_manifest_files`；超大 manifest > `manifest_max_bytes` | profile 层 `BUDGET_EXHAUSTED` gap（detail 含 limit/reason）且不阻断 L2/L3 |
| L2 RamBudgets | .py 文件数 > `max_python_files`；flows > `max_key_flows`；edges > `max_unresolved_edges` | 各自 detail（python-file-limit/key-flow-limit/unresolved-edge-limit + count） |
| L3 SemanticBudgets | `max_llm_calls` < batch 数 / prompt 估算超限 / output 估算超限 / total 超限（fake client 注入，CI 零网络零付费） | `SEMANTIC_*` 降级 + `BUDGET_EXHAUSTED(detail 含 note=...not-an-absence-of-risk)` |
| 组合 | L1+L2+L3 同一 fixture 同时触发 | 三层 gap 共存、排序稳定（gap_code,detail 升序）、三 digest 两次构建全等（预算配置值入 identity、实际耗时不入） |
| 不变量 | 全矩阵统一 | 每条预算配置值变更 ⇒ `semantic_config_digest`/`wire_digest` 变化；同配置重跑 ⇒ digest 相等 |

### 5.7 冻结接口清单（阶段二冻结对象汇总）

`ram_schema.py` 全部公共符号（§5.2）+ schema 文件本身（SHA-256 记录）+ 五 golden JSON + `execution_required` 规则表（Coordinator 裁定版本）+ 既有 107 用例回归基线。

### 5.8 IP-0019 移交项 gap⑤：Packet v1.2 勘误（同 commit docs 批次）

沿用 IP-0018 v1.1 勘误先例（#172，inline 修正 + 版本历史）：`docs/LIMA_Implementation_Packet_IP-0019_Semantic_TopN.md` 版本升至 **v1.2**，修正 §3.1 首条关键口径中"`sink_rule_ids`/`sink_cwes`/`key_flows` 与条目按索引一一对应（并行元组）"为准确表述——`sink_rule_ids`/`sink_cwes` 索引一一对应；`key_flows` 按 `(sink_rule_id, steps)` 独立排序且受 `max_key_flows` 截断（sinks 不截断），与 `sensitive_sinks` **无**索引对应。证据：`ram.py` L250-268（findings 排序键 `(path,line,rule_id)` vs flows 排序键 `(sink_rule_id,steps)` + 截断只作用于 flows）。纯文档修正，不改任何已冻结验收语义与命令；§5.2.1 的 ordinal 关联语义为已冻结实现行为，勘误仅纠正 Packet 描述文字。

---

## 6. 测试矩阵（阶段二冻结计划；本阶段不写测试）

| 文件（全部新增） | 最低用例 | 覆盖 |
|---|---|---|
| `test_ram_schema.py` | 24 | schema 文件加载且 const/required/maxItems 自洽（≥4）；`validate_ram_wire_payload` 正例（五形态之一 wire）+ 负例（未知字段/类型错/枚举外 category/rank 断号/摘要非 64-hex/并行长度不匹配 → `ContractError`，≥10）；`ram_wire_payload` 确定性（两次构建 payload 相等 + digest 相等，2）；`ram_wire_digest` 64-hex 且随配置变化（2）；`__init__` 追加与分段断言 `[0:44]`+`[44:44+K]`（2）；入口 fail-closed（非法入参类型 → ContractError/ValueError，≥2）；导入零副作用（1） |
| `test_fr05_gap_encoding.py` | 12 | `GAP_MANIFEST_PARSE_ERROR` 编码断言（损坏 JSON/YAML manifest → 码 + 冻结 detail，≥3）；unsupported 子集 typed gap（11 skip reasons 全表三分桶映射断言 + `unsupported-extension` fixture 端到端，≥4）；`execution_required` 规则表全 10 码逐码单测 + 空 gap 负例 + 集外码 ValueError（≥4，**Coordinator 裁定前此面不冻结**）；generic-exception 回归（gap①，≥2） |
| `test_golden_matrix.py` | 15 | 五形态 × (全链 golden 逐字段 + provenance 链)（≥5）+ 五形态 × Top-N 可重放（digest 全等 + candidate_id 序列相等）（≥5）+ wire 三 digest 入 golden（≥3）+ LF 口径/零执行零网络断言（≥2） |
| `test_budget_exhaustion_e2e.py` | 12 | §5.6 矩阵逐行（L1×2、L2×3、L3×4、组合×1、digest 不变量×2） |

合计最低 **63** 个新用例。PI-DR 落实：平台中立（`pathlib`/POSIX 断言、LF 写入）；PI-DR4 模块缺席 RED 锚（新测试 import `lima.audit.ram_schema` 失败即天然 RED）；PI-DR6 冻结前非 Windows 平台完整跑一次并记录。

### 6.1 回归基线

tests/audit `107 → 107+63=170`（0 skip）；contracts 617 不变（本 IP 不触 contracts）；全量 `1223 → 1286`（1 预存 skip）。**例外**：`test_semantic_prioritizer.py` L817 `[20:]` 断言（§5.3 勘误）——按停点 6 处理，授权变更后该文件属"最小授权修改"，计入 DR 记录。

---

## 7. AC → Test 映射

| AC/需求 | 贡献声明 | Test（§6） | 判定 |
|---|---|---|---|
| FR-04 剩余（schema 化 + identity 口径） | wire schema 字段全集 + 三 digest 口径 | `test_ram_schema.py` 全组 + `test_golden_matrix.py` 可重放组 | 全绿 |
| FR-05 剩余 | MANIFEST_PARSE_ERROR/unsupported 断言 + execution_required typed 承载 | `test_fr05_gap_encoding.py` | 全绿（execution_required 面待裁定后冻结） |
| AC-01/T-01（非 monorepo） | 五形态全链 golden + 可重放 | `test_golden_matrix.py` | 全绿 |
| V5-AC-01（非 monorepo 维度） | 同上子集 | `test_golden_matrix.py` | 全绿 |
| 预算端到端 | 三层 + 组合 + 不变量 | `test_budget_exhaustion_e2e.py` | 全绿 |
| IP-0019 gap①/⑤ | 回归用例 + Packet v1.2 勘误 | `test_fr05_gap_encoding.py` + docs diff | 全绿 + docs 合并 |

---

## 8. Acceptance commands（阶段二冻结与阶段三验证共用）

```text
python -m unittest tests.audit.test_ram_schema -v
python -m unittest tests.audit.test_fr05_gap_encoding -v
python -m unittest tests.audit.test_golden_matrix -v
python -m unittest tests.audit.test_budget_exhaustion_e2e -v
python -m unittest discover -s tests/audit -q      → Ran 107+N tests, OK（N≥63；0 skip；三层冻结面不可回归）
python -m unittest discover -s tests/contracts -q  → Ran 617 tests, OK（不可回归）
python -m unittest discover -s tests -q            → Ran 1223+N, OK (skipped=1)
python -m compileall -q lima                        → exit 0
python -m ruff check lima/audit/ram_schema.py lima/audit/__init__.py schemas tests/audit/test_ram_schema.py tests/audit/test_fr05_gap_encoding.py tests/audit/test_golden_matrix.py tests/audit/test_budget_exhaustion_e2e.py tests/audit/fixtures/golden_matrix/  → 零 finding
python -m bandit -q lima/audit/ram_schema.py        → 零 finding
git diff --check                                    → 干净
git diff --name-only --diff-filter=ACMRTUXB         → 恰为 §4 Add + __init__.py（+ DR 授权的 test_semantic_prioritizer.py 最小变更，如获准）
sha256sum schemas/v4/lima.repository-architecture-model.json + golden/*.json → 与冻结记录一致
```

Compatibility/boundary：`python -c "import lima.audit as a; assert a.__all__[:44]==[...既有 44 项...] and len(a.__all__)==44+K"`；`python -c "import lima.audit"` 零副作用。

Post-merge（main 复验）：上述 mandatory 全组。

---

## 9. Stop Conditions / Decision Request

1. 发现必须修改 `lima/contracts/**`、matrix、既有 schemas/v4 14 文件、三层 audit 模块或既有 5 测试文件（除 §5.3/§6.1 勘误项）才能承载 → Contract Gap 停点；
2. 三层冻结面（§3.1 消费面）在最新 main 漂移 → 停点；
3. 基线命令结果与 §3.3 不符（环境问题）→ 停止上报；
4. Coordinator 未裁定 §5.4 提案 A/B 而阶段二到期 → execution_required 测试面保持未冻结并上报，不自行择一；
5. golden 产出与冻结实现行为矛盾（如 docs 形态语言检测行为不定）→ 保留现场，提交 DR；
6. **冻结测试变更预登记**：`test_semantic_prioritizer.py` L817 `[20:]` 断言在 `__init__.py` 追加后必然失败（§5.3 勘误）——阶段二开始前 P&V 将就该文件的最小授权修改（`[20:]` → `[20:44]`）提交 Decision Request，未获授权不动该文件。

## 10. Completion Summary / PR contract

- Completion Summary 必含：base/final commit、修改文件与公共符号清单、AC→Test→Result 表（§7）、§8 命令实际输出、schema 与 golden 文件 SHA-256、文件边界自查、已知限制（schema 未注册 matrix=BG-60-01；monorepo 维度未覆盖；execution_required 消费归 #64/#68）。
- Implementation PR：`Implements IP-0021` + `Related to #60`；正文含 Packet merge commit、Frozen Test Commit、贡献声明与 Not-covered、`This PR does not auto-close the Source Issue.`；**禁止** close/fix/resolve + #60 组合（PI-DR5）。
- Packet docs PR（主会话执行）：`docs: freeze IP-0021 RAM schema and golden matrix packet`，`Related to #60`，含本 Packet 主件 + IP-0019 Packet v1.2 勘误。

## 11. Packet completion definition

`READY-FOR-CODE` 当且仅当：TBD=0（现满足）、§5.4 提案已明确标注"待 Coordinator 复核"且不阻塞其余面（现满足）、文档/`git diff --check` 通过、阶段二按 §6 计划完成有效 RED 与 PI-DR6 双平台记录。合并后 Coordinator 标 `PACKET-MERGED`，派发阶段二（PKT-IP-0021-D2）。

## 12. Open Decisions 移交（不阻塞本 IP）

- `execution_required` 触发集单解（提案 A/B，§5.4）→ Coordinator 复核（主会话转呈）；
- `test_semantic_prioritizer.py` L817 断言最小变更授权 → DR（§9.6）；
- schema matrix 注册 → BG-60-01 backlog；
- monorepo component graph / V5-FR-03 全量 → #60-S4 后续；
- `execution_required` Mining 消费接线 → #64/#68。

---

## 附：本 Packet 制作证据摘要

- Baseline 三组命令亲跑 @e000e6f（worktree `D:\BaseAIProject\LIMA-ip-0021-pv-wt`，分支 `docs/ip-0021-packet`，2026-09-13）：617 OK / 107 OK 0 skip / 1223 OK 1 预存 skip。
- 三层冻结面逐行亲验：`lima/audit/__init__.py`（104 行 44 项）、`ram.py` L250-268 key_flows 排序/截断（§5.8 勘误证据）、`semantic_prioritizer.py` 全公共面、`inventory.py` GAP 常量与 `SKIP_REASON_TO_GAP_DETAIL`。
- tests/contracts 无目录枚举断言亲验（`test_compatibility_matrix.py` 只枚举 matrix 文件行集）——新增未注册 schema 不破坏 617。
- 分段断言先例亲验：`test_ram_facts.py` L322/L324、`test_semantic_prioritizer.py` L816-817（`[20:]` 裸尾断言 = §9.6 预登记项）。
- Issue #60 正文与 Ledger 状态经 Assignment `IP-0021-PV-P1/v1` 传递（DI-005）；IP-0018 v1.1 勘误先例 diff 亲验（#172 dc6a50e）。
