# Implementation Packet IP-0019 — Semantic Prioritizer / Top-N（#60-S3）

> 文档类型：Implementation Packet（P&V 制作）
>
> Packet 版本：`IP-0019-PACKET/v1.2`
>
> 修订历史：v1.1（2026-09-13，DR-IP-0019-01，裁定 DR-IP-0019-0102 选项 A）：§5.3 `max_total_tokens_estimate` 默认值 `28_000` → `28_096`，保留构造期不变量（total ≥ prompt+output）；DR-TOPN-01 批准值 24,000 / 4,096 / 120s 不变。
>
> 修订历史：v1.2（2026-09-13，勘误 PKT-ERRATUM-IP-0019-02，随 IP-0021 Packet docs 批次）：§3.1 字面差异修正——原文"`sink_rule_ids`/`sink_cwes`/`key_flows` 与条目按索引一一对应（并行元组）"不准确；实测（`lima/audit/ram.py` `_collect_sink_facts`）：仅 `sink_rule_ids`/`sink_cwes` 与 `sensitive_sinks` 按索引一一对应，`key_flows` 按 `(sink_rule_id, steps)` 独立排序且受 `max_key_flows` 截断（sinks 本身不截断），与 `sensitive_sinks` 无索引对应。纯文档修正，不改任何已冻结验收语义与命令；§5.2.1 的 ordinal 关联是已冻结实现行为，勘误仅纠正描述文字。
>
> 状态：`READY-FOR-CODE`（TBD = 0）
>
> Exact base：`dd324915f9b35c70cfd4b254b06d1759c35fb13d`（origin/main，含 IP-0016/0017/0018 交付）
>
> 制作人：lima-packet-verification（Assignment `IP-0019-PV-P1/v1`，任务标识 `PKT-IP-0019-D1`，2026-09-13）
>
> 上游决策：DR-TOPN-01 修订批准（Maintainer 2026-09-13 全文随 Assignment 派发）+ COORD-60S3-ENTRY_RULING-2026-09-13

---

## 0. Header（生命周期 §8）

```text
Source Issue：#60（[V4-I04][P0] Repository Profile、RAM 与安全语义清单，V5 覆盖层版）
Issue specification revision：2026-09-12 Issue #60 正文（V5 覆盖层版，API 快照；Delivery Ledger 更新至 2026-09-13，IP-0019=PROPOSED 行亲取）
Covered requirements：FR-03（语义层仅补充 category/rationale/rank，不动 Tier 0/provenance/不造边）、FR-04（本 IP 子集：Top-N N/权重/tie-break/seed/预算配置值/prompt+model digest 写入独立语义承载并参与 identity，同输入输出 identity 稳定）、AC-02/T-02（LLM off/timeout/malformed 降级——确定性保留 + semantic gap）、NFR-01（语义层复验：路径 repo-relative、无源码正文/Secret）
Not covered requirements：FR-01/FR-02（已 SATISFIED：IP-0016/IP-0018）、FR-04 的 RAM schema/golden envelope 绑定（→ #60-S4）、FR-05 其余子集与 execution_required Mining 消费（→ #60-S4）、AC-01/T-01 golden matrix（→ #60-S4 + closure）、AC-03/T-03 与 NFR-02 端到端（→ closure）、V5-FR-03/V5-AC-02（→ #60-S4）、V5-FR-04/V5-AC-03 端到端（→ closure）、scanner/service 接线（不在 #60 范围）、#58 契约修改（本 IP 零修改 contracts）
Delivery role：domain（语义优先级补充层 + Top-N 榜单 + 降级 gap）
Issue closure impact：PARTIAL
Upstream IP/PR/merge commits：IP-0016（merge fd219724）、IP-0018（Packet #169 @49c87d3、merge cc17662）、IP-0017（merge dd324915，contracts 617）
Upstream ruling：COORD-60S3-ENTRY_RULING-2026-09-13（IP-0019 = #60-S3）；DR-TOPN-01 修订批准（A-1..A-5 + B 组修订，逐条映射见 §1.1）
```

本 Packet 只声明 IP-0019 自身贡献：语义优先级补充层、Top-N 榜单层、降级 typed gap 与语义 identity 承载。它**不**宣称 AC-01 golden matrix、T-03 端到端安全负例或 FR-05 全集已满足；#64/#68 的公共 Contract 消费验证归 closure。

---

## 1. Goal / Non-goals

### Goal

新增 `lima/audit/semantic_prioritizer.py`：以 `PythonRamFacts`（IP-0018 冻结输出）为唯一事实来源，构建**两层数据结构**——基础 facts 层原样保留（Tier 0 全集不动）+ Top-N 榜单层（≤N 的语义补充排序视图），产出独立承载对象 `SemanticTopNResult`（自带 digest，**不触碰** `RepositoryProfile`/`extensions`），并在模型 off/timeout/malformed/预算耗尽时降级为确定性保留 + typed semantic gap（AC-02/T-02）。

### 1.1 DR-TOPN-01 逐条落实映射表（Assignment 专项验收）

| DR 条目 | 批准内容（摘要） | 本 Packet 冻结条款 |
|---|---|---|
| A-1 | N 默认 20、区间 1–100、硬上限 100；为 #60 初期工程默认值，不以 #64 Tier 1 数量为契约依据 | §5.1（`SemanticOptions.top_n`，默认 20，校验 1..100，`SEMANTIC_MAX_TOP_N=100`）；依据区措辞见 §5.1 注 |
| A-2 | max_llm_calls=8 / max_prompt_tokens_estimate=24000 / max_wall_time_seconds=120；显式启用、默认 disabled、测试 fake 注入、CI 零付费调用零网络；预算配置值入身份摘要、实际耗时不入；输出/总 token 硬边界 + 调用前拦截 | §5.3（`SemanticBudgets` 六字段）、§5.4（显式启用机制 + 默认 disabled）、§5.5（四调用前检查点）、§5.7（digest 组合式：含全部预算配置值、不含耗时）、§6（静态断言零网络/零付费调用） |
| A-3/A-4 | 部分结果 + 确定性兜底；SEMANTIC_MODEL_OFF / SEMANTIC_MODEL_TIMEOUT / SEMANTIC_MALFORMED_OUTPUT + 复用 BUDGET_EXHAUSTED（值重述不 import inventory）；预算耗尽不得解释为"没有风险" | §5.6（gap 编码与降级矩阵）、§5.6.4（detail 强制携带 `note=semantic-coverage-incomplete; not-an-absence-of-risk`） |
| A-5 (a)-(e) | Top-N 五规则；"候选<N/已满 N 无 gap"仅指不**新增**预算耗尽 gap，此前 off/timeout/malformed gap 保留（gap 累积语义）；Tier 0 全集在基础 RAM 层，不塞进榜单 | §5.6.5（五规则逐条 + 累积语义）、§5.2（两层数据结构 + Tier 0 保留声明） |
| B-7 修订 | path:symbol 非唯一候选 ID（同文件多条 symbol=None 亲验）；须无碰撞可重放 + 碰撞测试 | §5.2.1（四元组候选 ID 冻结定义 + 三性质证明）、§6（碰撞场景用例组） |
| B-10 修订 | v4 RepositoryProfile extensions 非空即拒；语义字段不得挂入；S3 用独立语义结果承载 + 自身 digest；S4 schema 接入另行验证 | §5.2.2（`SemanticTopNResult` 独立承载）、§5.7（自身 digest）、§1 Non-goals（不触碰 contracts/profile） |
| B-6 | 排序键/tie-break 冻结、seed 默认零随机 | §5.2.3、§5.1（seed 语义） |
| B-8 | 独立模块 semantic_prioritizer.py；semantic/静态双 digest 分离；prompt/model digest 入承载 | §4（文件/符号）、§5.7 |
| B-9 | RamBudgets/SemanticBudgets 命名隔离 | §5.3 |

### Non-goals

- 不修改 `lima/contracts/**`（#58 冻结面零改动；v4 extensions 拒绝语义是约束而非待改缺陷）；
- 不把语义字段挂入 `RepositoryProfile`/`AttackSurfaceEntry.extensions`（B-10 修订；schema 化归 #60-S4）；
- 不做 RAM schema adapter、golden fixtures、monorepo component graph、`execution_required`（→ #60-S4）；
- 不接线 scanner/service/API；不消费 `lima/semantic_retrieval.py`（见 Explicitly Rejected Inputs）；
- 不修改 IP-0016/0018 任何已交付产品文件（ram.py/inventory.py/tests 只读）；
- 不 import/执行目标代码、不联网、不读环境变量、不产生任何真实模型调用。

---

## 2. Design Input Manifest

| Input ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001 | Standard | `docs/LIMA_PACKET_AND_VERIFICATION_AGENT_RESPONSIBILITY_CHARTER.md` | main @dd324915 | Packet 结构、冻结/验证边界 | normative | — |
| DI-002 | Standard | `docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md` | main @dd324915 | 不执行/路径有界/fail-closed 不变量 | normative | — |
| DI-003 | Standard | `docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md` §8/§9 | main @dd324915 | Packet Gate 全清单、分支拓扑、禁自动关闭 | normative | — |
| DI-004 | Decision | Coordinator Assignment `IP-0019-PV-P1/v1`（含 DR-TOPN-01 修订批准全文 + COORD-60S3-ENTRY_RULING-2026-09-13 + PKT-ERRATUM-IP-0018-01 授权） | 2026-09-13 | 范围、文件边界、A/B 组批准值、勘误授权 | normative | 唯一上游裁定 |
| DI-005 | Issue | Source Issue #60 正文 + Delivery Ledger（API 快照 2026-09-13，亲取，见证据 E-2） | 2026-09-13 | FR-03/FR-04/AC-02/NFR-01 文本、Ledger IP-0019=PROPOSED | normative | V5 覆盖层优先 |
| DI-006 | Upstream IP | IP-0018 冻结面：`lima/audit/ram.py`、`lima/audit/__init__.py`（20 项 `__all__`）、tests/audit 既有四文件 @dd324915；PM-IP-0018-1 | @dd324915 | `PythonRamFacts`/`RamFactsBuildResult`/`ram_facts_digest` 消费面、`__init__.py` 纯追加边界、68→64 用例回归基线 | normative（接口） | 只读消费 |
| DI-007 | Code | `lima/contracts/profile.py` @dd324915：`AttackSurfaceEntry`、`ProfileCoverageGap`（gap_code pattern `[A-Z][A-Z0-9_]{0,63}`）、`_validated_extensions` L192-193 + `_reject_current_minor_nested_extensions`（v4 非空 extensions 即 `UNKNOWN_FIELD` 拒绝） | @dd324915 | B-10 依据：禁挂 extensions；gap_code 合法性 | normative（#58 冻结契约） | — |
| DI-008 | Code | `lima/audit/inventory.py` @dd324915：`GAP_BUDGET_EXHAUSTED`/`GAP_INVENTORY_SKIPPED` Final 常量、`ProfileBudgets` | @dd324915 | BUDGET_EXHAUSTED 值重述（不 import）、命名隔离参照 | current-behavior | 值漂移 → DR |
| DI-009 | Code | `lima/audit/ram.py` @dd324915：`_collect_sink_facts`（同文件多条 symbol=None sensitive sink）、`_collect_trust_boundaries`（全部 symbol=None）、`_collect_external_sources`（symbol 可 None） | @dd324915 亲验 | B-7 依据：path:symbol 非唯一 | current-behavior | — |
| DI-010 | Code | `lima/contracts/codec.py` `compute_content_digest` | @dd324915 | 全部 digest 计算（canonical JSON → 64-hex） | normative | — |
| DI-011 | Decision | PI-DR1..PI-DR6 | Ledger 2026-09-12/13 | 测试平台中立、冻结前非 Windows 完整跑一次 | normative | — |
| DI-012 | Decision | DR-IP-0016-01（digest sentinel 语义） | Ledger | §5.7 digest 恒非空 64-hex 口径 | normative | 本 IP 全 digest 均 `compute_content_digest` 产物 |

### Explicitly Rejected Inputs

- `lima/semantic_retrieval.py`（`SecuritySemanticRetriever`）——纯确定性无 LLM I/O 的**只读参考**；本 IP 的语义信号来自 LLM 补充层而非检索器词表。消费它会把 FR-03 的"语义补充"与已冻结的检索权重耦合，未获裁定授权，不采用。
- #64/#68/Tier-1 数量类文档——A-1 明示不以 #64 Tier 1 数量为 N 的直接契约依据；仅背景。
- `docs/LIMA_V5_真实测试驱动的通用全链路实施重基线与Issue闭环规划.md` 阶段名——编号以 NUM-ERRATUM-01 协议与入口裁定为准。
- 任何"把语义字段塞入 RepositoryProfile.extensions 或新增 envelope schema"的方案——与 `_validated_extensions`/`_reject_current_minor_nested_extensions` 冻结语义冲突（DI-007），且 B-10 修订已裁定独立承载。
- IP-0018 Packet v1 中"`__all__` 12 项 / len==21"表述——实测 11 项/20（见 PKT-ERRATUM-IP-0018-01，随本批次勘误），本 Packet §8 基线以实测为准。
- IP-0017/#94 轨道、BG-IP-0016-01 backlog——平行/移交项，非本 IP 输入。

---

## 3. Current code baseline（亲验誊录，@dd324915）

### 3.1 IP-0018 消费面（DI-006，逐字段）

`lima/audit/ram.py` 公开：`RAM_PROVENANCE_ANCHOR="ram-facts"`、`GAP_DYNAMIC_IMPORT`、`GAP_AMBIGUOUS_DISPATCH`、`RamBudgets{max_python_files=512, max_key_flows=256, max_unresolved_edges=1024}`、`RamKeyFlow{sink_rule_id, steps}`、`PythonRamFacts{entrypoints, external_sources, source_labels, sensitive_sinks, sink_rule_ids, sink_cwes, trust_boundaries, key_flows, unresolved_edges, coverage_gaps, counters}`、`RamFactsBuildResult{facts, provenance_anchor_ids}`、`build_python_ram_facts(workspace, *, budgets=None)`、`ram_facts_digest(facts) -> str`（canonical dict → `compute_content_digest`，64-hex）。

关键口径（本 Packet 设计前提，不修改）：

- `sensitive_sinks` 由 findings 按 `(path, line, rule_id)` 排序后逐条构造，**symbol 一律 None**——同一文件可有多条、且 `sink_rule_ids`/`sink_cwes` 与条目按索引一一对应（并行元组；v1.2 勘误：`key_flows` 不在此列——flows 按 `(sink_rule_id, steps)` 独立排序且受 `max_key_flows` 截断而 sinks 不截断，与 `sensitive_sinks` 无索引对应；§5.2.1 的 ordinal 关联是位置回退近似而非一一对应）；
- `trust_boundaries` 每条 symbol=None（文件级去重并集）；`external_sources` 的 symbol 为最近包围函数名，可为 None；
- `unresolved_edges` symbol=callee 呈现名，同文件同名可多条；
- 全部元组已按冻结序排序；两次构建同快照同预算 ⇒ facts 与 digest 相等（IP-0018 §5.1.7 冻结）。

### 3.2 B-7 亲验记录（DI-009）

`ram.py` L253：`entries = [_entry(item.path, None, _REASON_SENSITIVE_SINK) for item in findings]`——sensitive sinks 全部 symbol=None；L242：trust boundaries 全部 symbol=None。⇒ `path:symbol` 二元组在同一文件多条敏感操作（如同文件 `os.system` + `eval` 两 findings，或两条 FLOW-COMMAND）时碰撞。B-7 修订成立，候选 ID 规则见 §5.2.1。

### 3.3 B-10 亲验记录（DI-007）

`profile.py` L192-193：`_validated_extensions` 对 `_is_current_minor`（v4.0）且非空 extensions 抛 `ContractError(UNKNOWN_FIELD)`；`_reject_current_minor_nested_extensions` 对 profile 全部嵌套对象 extensions 同拒。⇒ 语义补充字段（category/rationale/rank）不可挂入 RepositoryProfile/AttackSurfaceEntry/ProfileCoverageGap.extensions 的**wire 语义**（内存构造不触发 version 检查但 wire 化必拒；且 #58 语义上 extensions 保留给 minor 演进）。B-10 修订成立，独立承载见 §5.2.2。

### 3.4 基线实测（与 Assignment 预期的偏差记录）

- `python -m unittest discover -s tests/contracts -q` → **Ran 617 tests, OK**（与预期一致）；
- `python -m unittest discover -s tests/audit -q` → **Ran 64 tests, OK (0 skip)**。Assignment 预期"68"为 grep 假阳性：`tests/audit/test_profile_inventory.py` L167-168/L407/L439 有 4 处 `def test` 出现在 fixture 源码字符串内，非测试方法。实测逐模块 32+23+5+4=64，无 skip。**本 Packet §8 一律以 64 为回归基线**；该差异不构成停点（套件全绿），已在本节留痕并回报主会话。
- `python -m unittest discover -s tests -q` → **Ran 1180 tests, OK (skipped=1)**（预存 symlink 环境 skip；本机 stderr 含其他套件正常日志输出）。

### 3.5 与预期的偏差核验

除 §3.4 计数勘误外，Assignment 预告的 API 面与实际无偏差；DR-TOPN-01 批准值与冻结面无矛盾（预算拦截在 fail-closed 下可实现，见 §5.5——拦截动作是"停止发起下一调用 + 降级 gap"，不是异常抛出路径）。不触发 DR。

---

## 4. Files boundary（Coordinator 裁定冻结）

- **Files to Add**：`lima/audit/semantic_prioritizer.py`（唯一产品代码文件）。
- **Product Files Allowed to Modify**：`lima/audit/__init__.py` —— 仅限"纯追加 re-export"：在既有 import 块与 `__all__` 列表**末尾**追加 §4.1 冻结的新公共符号；不得改动既有 20 个 `__all__` 条目、既有 import 行、docstring 既有语句（可追加一句说明 semantic 层；有歧义则保持原样）。
- **Test/Fixture Files Owned by P&V（阶段二独占，本阶段不创建）**：`tests/audit/test_semantic_prioritizer.py`、`tests/audit/fixtures/semantic/*`。
- **Read-only Reference**：`lima/audit/ram.py`、`lima/audit/inventory.py`、`lima/python_dataflow.py`、`lima/workspace.py`、`lima/contracts/**`、`lima/models.py`、tests/audit 既有四文件、`lima/semantic_retrieval.py`（仅参考，不 import）。
- **Files Forbidden**：除上述 Add/Modify 外的一切路径；特别冻结：`lima/audit/{ram,inventory}.py`、tests/audit 既有四测试文件、`lima/contracts/**`、`schemas/**`、`lima/semantic_retrieval.py`（禁 import 禁修改）、`.zcode/**`、#94 轨道全部路径。

### 4.1 Symbol-to-File Map（全部新增符号均在 `lima/audit/semantic_prioritizer.py`）

| Symbol | 种类 |
|---|---|
| `SEMANTIC_PROVENANCE_ANCHOR: Final[str] = "semantic-prioritizer"` | 常量 |
| `SEMANTIC_MAX_TOP_N: Final[int] = 100` | 常量 |
| `GAP_SEMANTIC_MODEL_OFF: Final[str] = "SEMANTIC_MODEL_OFF"` | 常量 |
| `GAP_SEMANTIC_MODEL_TIMEOUT: Final[str] = "SEMANTIC_MODEL_TIMEOUT"` | 常量 |
| `GAP_SEMANTIC_MALFORMED_OUTPUT: Final[str] = "SEMANTIC_MALFORMED_OUTPUT"` | 常量 |
| `_GAP_BUDGET_EXHAUSTED: Final[str] = "BUDGET_EXHAUSTED"`（值重述，禁 import inventory/ram 之外的 gap 常量来源） | 常量 |
| `SEMANTIC_CATEGORY_*` 九个类别常量（§5.2.4 词表） | 常量 |
| `SemanticBudgets`（frozen dataclass，§5.3） | 类型 |
| `SemanticWeights`（frozen dataclass，§5.2.3） | 类型 |
| `SemanticOptions`（frozen dataclass，§5.1） | 类型 |
| `SemanticCandidate`（frozen dataclass，§5.2.2） | 类型 |
| `SemanticTopNResult`（frozen dataclass，§5.2.2） | 类型 |
| `SemanticModelClient`（typing.Protocol，§5.4） | 类型 |
| `build_semantic_top_n(facts, *, options=None, model_client=None) -> SemanticTopNResult` | 函数 |
| `semantic_config_digest(options) -> str` | 函数 |
| `semantic_result_digest(result) -> str` | 函数 |
| `candidate_id(kind, path, symbol, ordinal) -> str`（公开，便于冻结测试直测 ID 规则） | 函数 |

依赖方向：`lima.audit.semantic_prioritizer` → `lima.audit.ram`（类型与 digest 复用）、`lima.contracts.{profile,codec}`、`lima.contracts.errors`。stdlib-only 除此之外；**无网络库、无 subprocess、无 os.environ、无文件写、无第三方依赖**。

`lima/audit/__init__.py` 追加 re-export：上述公开符号（不含 `_GAP_BUDGET_EXHAUSTED` 下划线私有项）按字母序段追加于 `__all__` 既有 20 项之后；追加后 `python -c "import lima.audit"` 零副作用。

---

## 5. Design Contracts（FR-03 + FR-04 子集 + AC-02 + NFR-01）

### 5.0 输入与总流程（冻结单解）

```python
def build_semantic_top_n(
    facts: PythonRamFacts, *,
    options: SemanticOptions | None = None,
    model_client: SemanticModelClient | None = None,
) -> SemanticTopNResult
```

1. 校验 `isinstance(facts, PythonRamFacts)` 否则 `ContractError(INVALID_FIELD_TYPE)`（fail-closed）；`options is None` 取 `SemanticOptions()`；`model_client` 非 None 时须实现协议方法，否则 `ContractError(INVALID_FIELD_TYPE)`。
2. **基础层不动**：`facts` 全部字段只读消费，Tier 0 全集（五清单 + key flows + 既有 coverage_gaps + counters）原样保留在 `PythonRamFacts` 中，语义层不回写、不过滤、不重排它。
3. 构建候选集（§5.2.1）→ 确定性打分排序（§5.2.3）→ 若模型启用且注入 client：按批调用、逐调用前过 §5.5 四检查点 → 校验模型输出（§5.4.3）→ 组装 Top-N 榜单层 → 产出 semantic gaps（§5.6）→ 计算双 digest（§5.7）。
4. 任何模型路径失败都**不抛出到调用方**（部分结果 + 兜底，A-3）；只有入参契约违约才抛 `ContractError/ValueError`。

### 5.1 `SemanticOptions`（FR-04 参数承载，A-1）

```python
@dataclass(frozen=True)
class SemanticOptions:
    top_n: int = 20                      # 1..100（SEMANTIC_MAX_TOP_N），否则 ValueError
    weights: SemanticWeights = field(default_factory=SemanticWeights)
    seed: int = 0                        # ≥0；默认 0 = 零随机（B-6）
    budgets: SemanticBudgets = field(default_factory=SemanticBudgets)
    model_id: str = "unset"              # 模型标识字符串（不发起调用，仅入 digest）
    prompt_template: str = _DEFAULT_PROMPT_TEMPLATE   # 冻结默认模板（§5.4.2）
    tie_break: str = "kind-path-symbol-ordinal"       # 唯一合法值（常量校验，非自由文本）
```

- **A-1 定位措辞（冻结）**：`top_n` 默认 20 与上限 100 是 **#60 的初期工程默认值（early engineering default of Issue #60）**，不是 #64 Tier 1 数量的直接契约依据；#64 消费时经自身 Contract 覆盖配置。
- `seed` 语义冻结：当前排序纯确定性（零随机），seed 仅作为 identity 参数记录并参与 digest，为未来允许的受控 tie-break 随机化预留；本 IP 内改变 seed **不得**改变输出榜单（测试断言 seed=0 与 seed=7 输出榜单与 result 中 ranked 部分逐字段相等，仅 digest 不同）。

### 5.2 两层数据结构与候选 ID（A-5 / B-7 / B-10）

#### 5.2.0 两层数据结构（冻结声明）

- **基础 facts 层** = `PythonRamFacts` 全集（Tier 0），由 IP-0018 冻结语义持有；本 IP 返回值不包含也不复制它，消费者以 `(facts, semantic_result)` 二元组持有两层。Tier 0 全集保留在基础 RAM 层，**不是**塞进 Top-N 榜单。
- **Top-N 榜单层** = `SemanticTopNResult.ranked: tuple[SemanticCandidate, ...]`，长度 ≤ N，仅为语义补充排序视图；榜单层永远不替代基础层（测试断言：任何降级路径下 `facts` 的 digest 与语义层调用前相等）。

#### 5.2.1 候选集与无碰撞候选 ID（B-7 冻结定义）

候选集 = 基础层五类 AttackSurfaceEntry 清单逐条映射 + 与 sensitive sink 同索引的 key flow 附着：

| kind（冻结字面量） | 来源元组 | 附着 |
|---|---|---|
| `"sensitive-sink"` | `facts.sensitive_sinks` | 同索引 `sink_rule_ids[i]`/`sink_cwes[i]`/`key_flows[i].steps` |
| `"entrypoint"` | `facts.entrypoints` | — |
| `"external-source"` | `facts.external_sources` | 同索引 `source_labels[i]` |
| `"trust-boundary"` | `facts.trust_boundaries` | — |
| `"unresolved-edge"` | `facts.unresolved_edges` | — |

**候选 ID 规则（冻结单解）**：

```text
candidate_id(kind, path, symbol, ordinal) = f"{kind}:{path}:{symbol if symbol is not None else '-'}#{ordinal}"
```

`ordinal` = 该条目在其来源元组中的 0 基索引（元组已由 IP-0018 冻结排序）。

三性质证明（构造性）：

1. **同输入同 ID**：`PythonRamFacts` 由 IP-0018 §5.1.7 冻结为同快照同预算 ⇒ facts 逐字段相等 ⇒ 各元组与索引相等 ⇒ ID 集相等（传递确定性，不引入新随机源）。
2. **不同条目不同 ID（无碰撞）**：ID 四元组中 kind 划分来源元组；ordinal 在元组内唯一 ⇒ `(kind, ordinal)` 已唯一，path/symbol 仅增强可读性与抗重排。同文件多条 symbol=None 的敏感操作因 ordinal 不同而不碰撞；跨 kind 的同 path 条目因 kind 前缀不碰撞。
3. **排序稳定**：榜单排序键（§5.2.3）含 candidate ID 末位（kind 顺序 + ordinal），全键相等 ⇔ 同一候选，排序全序无并列歧义。

#### 5.2.2 独立承载结构（B-10 冻结）

```python
@dataclass(frozen=True)
class SemanticCandidate:
    candidate_id: str
    kind: str
    path: str                    # repo-relative POSIX（继承 AttackSurfaceEntry 校验结果）
    symbol: str | None
    score: int                   # 确定性打分（§5.2.3）
    rank: int                    # 1 基，榜单内唯一、连续
    category: str                # §5.2.4 词表常量值
    rationale: str               # ≤512 字节 NFC 有界文本；确定性兜底文案或模型补充
    key_flow_steps: tuple[str, ...]  # 仅 sensitive-sink 非空，元素 "path:line"，无源码正文

@dataclass(frozen=True)
class SemanticTopNResult:
    ranked: tuple[SemanticCandidate, ...]          # ≤ top_n
    total_candidates: int                          # 候选全集大小（Tier 0 规模声明）
    coverage_gaps: tuple[ProfileCoverageGap, ...]  # 仅语义层新 gap（§5.6）
    prompt_digest: str                             # 64-hex
    model_digest: str                              # 64-hex
    config_digest: str                             # 64-hex（§5.7）
    result_digest: str                             # 64-hex（§5.7）
    provenance_anchor_ids: tuple[str, ...] = (SEMANTIC_PROVENANCE_ANCHOR,)
```

- 语义字段（category/rationale/rank/score）**只存在于本结构**；不构造、不修改任何 `RepositoryProfile`/`AttackSurfaceEntry`，不改任何 Tier 0 条目的 `source_artifact_ids`/`reason_codes`（FR-03：不删 Tier 0、不改 provenance）。
- `rationale`/`category` 由模型补充时须过 §5.4.3 校验；任何校验失败 → 该候选回落确定性兜底（不删除候选，FR-03）。
- 禁止榜单层出现候选集之外的 candidate_id（模型不得凭空创建条目/调用边；越权 ID 一律按 malformed 处理，FR-03"不造边"）。

#### 5.2.3 确定性打分与排序（B-6 冻结）

```python
@dataclass(frozen=True)
class SemanticWeights:   # 全部 int ≥0，__post_init__ 逐字段校验，否则 ValueError
    sink_flow_command: int = 80
    sink_flow_sql: int = 80
    sink_flow_eval: int = 90
    sink_flow_path: int = 70
    sink_flow_deserialization: int = 70
    entrypoint: int = 60
    external_source: int = 50
    trust_boundary: int = 40
    unresolved_edge: int = 30
```

- sensitive-sink 候选 score = 按 `sink_rule_ids[i]`（FLOW-EVAL/FLOW-COMMAND/FLOW-SQL/FLOW-PATH/FLOW-DESERIALIZATION）映射的对应权重；其余 kind 用 kind 权重。score **完全由静态事实 + 配置权重决定，模型输出不得影响 score/rank**（FR-03 核心不变量；模型只补 category/rationale）。
- 排序键（冻结全序）：`(-score, kind_order, path, symbol or "", ordinal)`；`kind_order`：sensitive-sink=0, entrypoint=1, external-source=2, trust-boundary=3, unresolved-edge=4。截断到 `top_n`。
- 同输入同配置 ⇒ ranked 逐字段相等（确定性测试锚点）。

#### 5.2.4 category 词表（冻结九值）

`SEMANTIC_CATEGORY_COMMAND_EXECUTION="command-execution"`、`..._SQL_INJECTION="sql-injection"`、`..._CODE_EXECUTION="code-execution"`、`..._PATH_TRAVERSAL="path-traversal"`、`..._DESERIALIZATION="deserialization"`、`..._EXTERNAL_INPUT="external-input"`、`..._ENTRYPOINT="entrypoint"`、`..._TRUST_BOUNDARY="trust-boundary"`、`..._UNRESOLVED_EDGE="unresolved-edge"`。确定性兜底映射：sink 按 rule_id、external-source→external-input、entrypoint→entrypoint、trust-boundary→trust-boundary、unresolved-edge→unresolved-edge。模型补充的 category 必须 ∈ 词表，否则该候选按 malformed 处理（§5.4.3）。

### 5.3 `SemanticBudgets`（A-2 + B-9 命名隔离）

```python
@dataclass(frozen=True)
class SemanticBudgets:   # 全部 int，__post_init__ 逐字段 type is int 校验
    max_llm_calls: int = 8                  # ≥1
    max_prompt_tokens_estimate: int = 24_000    # ≥1
    max_output_tokens_estimate: int = 4_096     # ≥1（A-2 增补：单次调用输出估算硬边界）
    max_total_tokens_estimate: int = 28_096     # ≥1（A-2 增补：单次调用 输入+输出 总量硬边界；v1.1 勘误见修订历史）
    max_wall_time_seconds: int = 120        # ≥1
    # 不变量：max_total_tokens_estimate ≥ max_prompt_tokens_estimate
    #         + max_output_tokens_estimate，否则 ValueError（保证两上界可同时满足）
```

- 与 `ProfileBudgets`/`RamBudgets` 完全命名隔离（B-9），互不 import。
- **全部六个配置值参与 `config_digest`；实际耗时/实际 token 消耗不参与任何 digest**（A-2；§5.7 冻结）。
- token 为**估算**：估算函数 `_estimate_tokens(text) = max(1, ceil(len(text)/4))`（冻结口径；UTF-8 字符数/4，不冒充精确 tokenizer）。输入 token 估算不冒充精确费用上限——正因如此 A-2 增补输出/总 token 硬边界与 §5.5 调用前拦截，把"估算失控"截断在调用发生之前。

### 5.4 模型调用面（A-2 显式启用 + 默认 disabled + fake 注入）

#### 5.4.1 显式启用机制（冻结单解）

模型调用**当且仅当**同时满足：(1) 调用方显式传入实现协议的 `model_client`；(2) `options.model_id != "unset"`。二者缺一 → 模型关闭（零调用，零网络尝试），产出 `SEMANTIC_MODEL_OFF` gap（§5.6.1）。不存在环境变量、配置文件、类属性等隐式启用通道（静态断言：模块无 `os.environ`/`getenv` 读取）。普通测试与 CI 不注入真 client ⇒ 默认路径**零真实调用、零付费、零网络**。

#### 5.4.2 端口协议与默认 prompt（B-8）

```python
class SemanticModelClient(Protocol):
    def complete(self, prompt: str, *, timeout_seconds: int) -> str: ...
```

- 本模块**只定义协议**，不提供任何网络实现、不内置 SDK；真实 client 由未来接线（#68 或后续 IP）注入。冻结测试使用确定性 fake（脚本化返回/异常注入）。
- 默认 `prompt_template`（冻结文本，含候选 descriptor 占位）：每批将候选的 `candidate_id/kind/path/symbol/category-词表/rule_id` 序列化为 JSON 数组嵌入模板；**模板与嵌入内容均不含源码正文**（candidates 本身无正文，NFR-01 继承）。`prompt_digest = compute_content_digest(prompt_template)`（模板文本，不含运行时候选数据）。
- `model_digest = compute_content_digest(model_id)`。
- 调用按批组织：每批 ≤ `max(1, max_llm_calls)` 中一批（实现自由），但**每次** `complete` 前必须逐条过 §5.5 四检查点；`timeout_seconds` 取 `budgets.max_wall_time_seconds` 剩余量与单次上限的较小值。

#### 5.4.3 模型输出校验（malformed 判定）

期望输出为 JSON 对象数组，每项 `{candidate_id, category, rationale}`；校验规则（任一失败即该批 malformed）：

1. JSON 可解析为 list，且非空批不返回空 list 以外的结构性缺省；
2. 每项含上述三键，值类型正确；`candidate_id` ∈ 本批候选 ID 集（防造边/防幻觉条目）；
3. `category` ∈ §5.2.4 词表；`rationale` 经有界文本化（NFC、strip、截断 512 字节、剔除控制字符）后非空。

malformed 处理：该批全部候选回落确定性兜底 category/rationale（候选不删除），追加**一条** `SEMANTIC_MALFORMED_OUTPUT` gap（detail 记 `batch=<批序号>; offending=<首错键>`，不含模型原文——防泄漏与摘要膨胀）。off/timeout 同理为单条 gap（§5.6）。第一批 malformed **不阻止**后续批（预算允许时继续；A-3 部分结果语义）。

### 5.5 调用前拦截检查点（A-2 冻结；fail-closed 实现）

每次发起 `complete` **之前**按序检查，任一不过 ⇒ 不发起该次及后续全部调用，进入预算停止路径（§5.6.4），已得部分结果保留：

1. `calls_made < budgets.max_llm_calls`；
2. `prompt_estimate = _estimate_tokens(本批 prompt)` 且 `prompt_estimate ≤ budgets.max_prompt_tokens_estimate`；
3. `budgets.max_output_tokens_estimate ≥ 1`（构造期已保证）且本批按上限输出估算 `≤ budgets.max_output_tokens_estimate`；
4. `prompt_estimate + budgets.max_output_tokens_estimate ≤ budgets.max_total_tokens_estimate`；
5. `time.monotonic() - start < budgets.max_wall_time_seconds`（墙钟仅用于拦截判定，**不入任何 digest/输出字段**；start 取 `build_semantic_top_n` 进入模型路径的瞬间）。

拦截动作 = "停止发起下一调用 + 降级 gap"，不是向调用方抛异常——预算属于可降级资源边界（A-3/A-4），与入参契约违约的 `ContractError` 路径区分。耗时超限由拦截点 5 兜底；client 内部超时由协议异常路径（§5.6.2）兜底，双层防"测试平台慢 ≠ 语义超时"误判。

### 5.6 降级矩阵与 gap 编码（A-3/A-4/A-5；AC-02/T-02）

#### 5.6.1 off

触发：§5.4.1 任一条件不满足。输出：完整确定性榜单（全部候选确定性 category/兜底 rationale，截断 top_n）+ `ProfileCoverageGap(GAP_SEMANTIC_MODEL_OFF, detail="reason=model-disabled; candidates=<total_candidates>")`。

#### 5.6.2 timeout

触发：client `complete` 抛 `TimeoutError`（含子类）。输出：已完成批的部分补充 + 其余候选兜底 + `gap(GAP_SEMANTIC_MODEL_TIMEOUT, detail="reason=model-timeout; batch=<n>")`；**停止**后续调用（timeout 是终止性事件，与 malformed 不同）。

#### 5.6.3 malformed

见 §5.4.3：部分结果 + 兜底 + 单条 `GAP_SEMANTIC_MALFORMED_OUTPUT`；后续批继续。

#### 5.6.4 budget exhaustion

触发：§5.5 任一检查点拦截。输出：部分结果 + 兜底 + `gap(BUDGET_EXHAUSTED, detail="reason=semantic-budget; stage=<llm-calls|prompt-tokens|output-tokens|total-tokens|wall-time>; pending=<未处理候选数>; note=semantic-coverage-incomplete; not-an-absence-of-risk")`。

**detail 语义措辞冻结（A-4）**：`note=semantic-coverage-incomplete; not-an-absence-of-risk` 强制出现——预算耗尽只声明"语义排序覆盖不完整"，**不得**被解释为"没有风险"。

#### 5.6.5 降级矩阵（全分支冻结；gap 列为**新增** gap，此前已发生的 gap 一律保留）

| # | 模型路径 | 候选充足性 | 输出形状 | 新增 gap | 此前 gap 保留 |
|---|---|---|---|---|---|
| D1 | off | 候选 < N | 确定性榜单（全部候选），rank 连续 | MODEL_OFF | —（基础层 gap 不在本结构，见注） |
| D2 | off | 候选 ≥ N | 确定性榜单截断 N | MODEL_OFF | — |
| D3 | timeout @批 k | 任意 | 前 k-1 批补充 + 其余兜底 | MODEL_TIMEOUT | 是（off 不可能先于调用，无冲突） |
| D4 | malformed @批 k | 任意 | k 批兜底 + 其余照常 | MALFORMED_OUTPUT | 是 |
| D5 | budget 停止 @批 k | 停止时榜单已含 ≥ N 候选（候选充足且截断已完成） | 部分补充 + 兜底，榜单仍 N 条 | **无**（A-5(e)：已满 N 不新增预算 gap） | 是（D3/D4 已发 gap 保留） |
| D6 | budget 停止 @批 k | 停止时仍有待补充候选（pending>0，最终榜单 < 全集补充） | 部分补充 + 兜底，榜单 ≤ N | BUDGET_EXHAUSTED（detail 含 pending） | 是（gap 累积语义） |
| D7 | malformed @批 k 后 budget 停止 | pending>0 | 部分兜底 | MALFORMED_OUTPUT + BUDGET_EXHAUSTED（两条，按 (gap_code, detail) 序共存） | 是 |
| D8 | 正常完成 | 候选 < N | 全候选补充，榜单 = 候选全集 | **无**（A-5(d)：候选<N 无预算 gap） | 是（若曾有 D4） |

注：基础层（IP-0018）coverage_gaps 属 `PythonRamFacts`，语义层不复制不删除；"gap 累积"指 `SemanticTopNResult.coverage_gaps` 内各语义 gap 互不覆盖、全部保留，且全部排序 `sorted((gap_code, detail))`（契约序）。

A-5 五规则落位：(a) 排序键与截断 → §5.2.3；(b) tie-break 全序无并列 → §5.2.1 性质 3 + §5.2.3；(c) seed 零随机 → §5.1；(d) 候选<N 无新增预算 gap → D8；(e) 已满 N 无新增预算 gap → D5；(d)(e) 均以"仅指不**新增**预算耗尽 gap，此前 off/timeout/malformed gap 保留"为前提（D5/D7/D8 右列）。

### 5.7 Digest 组合式（FR-04 identity；B-8 双 digest 分离）

```text
prompt_digest = compute_content_digest(options.prompt_template)
model_digest  = compute_content_digest(options.model_id)

config_digest = compute_content_digest({
    "top_n": options.top_n,
    "weights": {字段名: 值, 按字段名字典序},
    "tie_break": options.tie_break,
    "seed": options.seed,
    "budgets": {max_llm_calls, max_prompt_tokens_estimate,
                max_output_tokens_estimate, max_total_tokens_estimate,
                max_wall_time_seconds},          # 六个配置值全量，无耗时
    "prompt_digest": prompt_digest,
    "model_digest": model_digest,
})

result_digest = compute_content_digest({
    "config_digest": config_digest,
    "input_facts_digest": ram_facts_digest(facts),
    "ranked": [candidate 规范 dict（rank/candidate_id/score/category/rationale/
               key_flow_steps；不含任何时间戳/耗时/调用计数）],
    "total_candidates": ...,
    "coverage_gaps": [...],
})
```

- **identity 稳定（FR-04 冻结判据）**：同一 `facts` + 同一 `options` ⇒ `config_digest`、`result_digest`、`ranked` 全部相等（与是否发生过 timeout/耗时长短无关——耗时既不入 digest 也不入 ranked）。
- **耗时排除（A-2）**：`time.monotonic` 结果只存在于拦截判定局部变量，任何输出字段/digest 载荷不包含它（测试断言：构造两次运行，人为令 fake 慢速/快速，digest 相等）。
- 双 digest 分离（B-8）：`prompt_digest`/`model_digest` 独立可复算（消费者不必重放完整 config 即可核对 prompt/model 溯源）；二者再入 `config_digest`。
- 全部 digest 经 `compute_content_digest`，恒 64-hex（DR-IP-0016-01 口径，DI-012）。
- 本 IP 不产出 ArtifactEnvelope（golden envelope 绑定归 #60-S4；同 IP-0018 §5.4 立场）。

### 5.8 NFR-01 复验契约（语义层）

- `SemanticCandidate.path` 只来自 `facts` 的既有 entry path（IP-0018 已过 `_validated_path`），模块不新增路径来源；
- prompt 与 rationale 不含源码正文/Secret：模板与 descriptor 仅含 candidate_id/kind/path/symbol/词表 category/rule_id；模型返回的 rationale 过有界文本化后仍须通过"不含 fixture 源码行非平凡子串、不含 secret 样式 token"断言（失败即 malformed 回落）；
- 模块静态断言：无网络 import（socket/urllib/requests/http）、无 subprocess、无 os.environ、无文件写（ruff + bandit + AST 级 import 断言，比文本 grep 强）。

---

## 6. Test matrix（阶段二冻结计划；类别 × 最低用例数）

| 类别 | 最低数 | 覆盖内容（→ AC/FR/DR） |
|---|---|---|
| 降级矩阵分支全覆盖 | 10 | §5.6.5 D1–D8 各≥1（D5、D7 各拆"此前 gap 保留"独立断言）；断言输出形状 + gap 组合 + gap detail 含 note 措辞（AC-02/T-02、A-3/A-4/A-5） |
| 候选 ID 碰撞 | 4 | 同文件多条 symbol=None sensitive sink（≥3 条同 path）ID 互异；trust-boundary+sensitive-sink 同 path 跨 kind 不碰撞；同输入两次构建 ID 集相等；ID 排序稳定（同分全并列时榜单序确定）（B-7） |
| 确定性与 identity | 5 | 同 facts+options 两次构建 ranked/config_digest/result_digest 相等；seed=0 vs 7 榜单相等仅 digest 不同；改 N/权重/任一预算配置值 ⇒ config_digest 改变；fake 慢速 vs 快速 ⇒ digest 相等（耗时排除）；digest 64-hex（FR-04、A-2、B-6/B-8） |
| 打分与 Top-N | 4 | 权重默认序（eval>command=sql>path=deser>entrypoint…）；tie-break 全序（构造并列）；top_n 截断；top_n=100 边界 + 101 拒绝 + 0/负数拒绝（A-1） |
| 预算拦截 | 5 | max_llm_calls=1 第二批前拦截；prompt 超估拦截；output/total 拦截各一；墙钟拦截（fake 注入 monotonic）；`max_total < prompt+output` 构造 ValueError（A-2、§5.5） |
| 禁付费调用/零网络 | 3 | 默认路径（无 client 或 model_id="unset"）fake 计数为 0 + MODEL_OFF gap；AST 断言模块无网络/subprocess/environ/写 import；`model_id` 不参与任何调用决策以外的副作用（A-2、§5.4.1、§5.8） |
| FR-03 不变量 | 4 | 调用前后 `ram_facts_digest(facts)` 相等（Tier 0 不动）；模型返回越权 candidate_id ⇒ malformed 且无新条目；模型不能改变 score/rank（fake 返回试图抬分 ⇒ 榜单不变）；rationale 泄漏源码/secret 样式 ⇒ malformed 回落（FR-03、NFR-01） |
| malformed 细分 | 3 | 非 JSON / category 出词表 / rationale 空或超界截断（§5.4.3） |
| 回归与边界 | 3 | `import lima.audit` 后既有 20 项 `__all__` 前缀与顺序不变且新符号追加；tests/audit 既有 64 用例 0 回归；非 PythonRamFacts 入参/坏 options → ContractError/ValueError fail-closed |

合计最低 41 个新用例（`tests/audit/test_semantic_prioritizer.py`）。PI-DR 落实：

- **PI-DR1（arrange 平台中立）**：fixture 写入 `newline="\n"`；断言路径用 POSIX 字面量；不依赖平台权限/大小写；
- **PI-DR6（双平台）**：冻结前在非 Windows 平台（CI Linux runner）完整跑一次新增测试集并记录 run SHA；Windows 本机 RED/GREEN 同步记录（阶段二计划详见交接返回消息）；
- PI-DR2..DR5 按标准门禁（ruff/bandit 零 finding、PR 无自动关闭关键字、diff 恰为 allowlist）。

## 7. AC traceability

| Requirement | 测试 ID 计划（阶段二冻结时定稿） | 断言要点 |
|---|---|---|
| FR-03 | test_fr03_tier0_immutable / test_fr03_no_invented_candidates / test_fr03_model_cannot_rescore / test_fr03_rationale_leak_fallback | §5.2.0/§5.2.2/§5.4.3/§5.8 |
| FR-04（子集） | test_identity_stable / test_seed_semantics / test_config_digest_sensitivity / test_digest_excludes_elapsed / test_digest_hex64 | §5.1/§5.7 |
| AC-02/T-02 | test_degradation_D1..D8 组 / test_gap_accumulation / test_budget_gap_not_absence_of_risk | §5.6 |
| B-7 | test_candidate_id_collision_sinks / _cross_kind / _replay / _order | §5.2.1 |
| A-1 | test_top_n_default_and_bounds | §5.1 |
| A-2 | test_budget_checkpoints 组 / test_no_paid_call_default / test_no_network_static / test_budget_values_in_digest | §5.3/§5.4/§5.5/§5.7 |
| B-10 | test_independent_carrier_no_profile_extensions（断言模块零 RepositoryProfile 构造、SemanticTopNResult 字段自足） | §5.2.2 |
| NFR-01 | test_no_source_text_or_secret / test_paths_repo_relative | §5.8 |

---

## 8. Commands（逐条精确 + 预期；阶段二/实现/验证共用）

Baseline（@dd324915，本 Packet 制作时已亲跑通过，见证据 E-1）：

```text
python -m unittest discover -s tests/contracts -q   → Ran 617 tests, OK
python -m unittest discover -s tests/audit -q       → Ran 64 tests, OK (0 skip)
python -m unittest discover -s tests -q             → Ran 1180 tests, OK (skipped=1, 预存)
```

（Assignment 预告的 audit=68 为 grep 假阳性，见 §3.4；本 Packet 以实测 64 为回归基线。）

Slice / mandatory（实现完成后）：

```text
python -m unittest tests.audit.test_semantic_prioritizer -v        → 全部新用例 OK，0 skip
python -m unittest discover -s tests/audit -q                     → Ran 64+N tests, OK（IP-0016/0018 冻结面不可回归）
python -m unittest discover -s tests -q                           → Ran 1180+N, OK (skipped=1)
python -m compileall -q lima                                       → exit 0
python -m ruff check lima/audit/semantic_prioritizer.py lima/audit/__init__.py tests/audit/test_semantic_prioritizer.py  → 零 finding
python -m bandit -q lima/audit/semantic_prioritizer.py             → 零 finding
git diff --check                                                   → 干净
git diff --name-only --diff-filter=ACMRTUXB                        → 恰为 lima/audit/semantic_prioritizer.py + lima/audit/__init__.py + tests/audit/test_semantic_prioritizer.py (+ fixtures/semantic/*)
```

Compatibility/boundary：`python -c "import lima.audit as a; assert a.__all__[:20]==[...IP-0016+0018 既有 20 项...] and len(a.__all__)==20+K"`（K=§4.1 追加符号数；既有前缀不变）。

Post-merge（main 上复验）：上述 mandatory 全组 + contracts 617。

---

## 9. Stop Conditions / Decision Request

停止并提交 Decision Request 的情形：

1. 实现期发现 DR-TOPN-01 批准值与冻结面矛盾（如预算拦截在 fail-closed 语义下不可实现——本 Packet §3.5 已核验可实现，若实现推翻该核验即停）；
2. 发现必须修改 `lima/contracts/**`、`lima/audit/{ram,inventory}.py`、tests/audit 既有四文件或 #94 轨道文件才能满足本 Packet（Contract Gap 停点）；
3. `PythonRamFacts` 消费面（§3.1）在最新 main 漂移（口径失效）；
4. 基线命令结果与本 Packet §8 记录不符（环境问题）；
5. IP-0019 编号被对端轨道登记/占用（入口裁定失效条款）；
6. 冻结测试需变更：先向 Coordinator 提交 Decision Request（缺陷证据 + 影响面 + 建议方案），获授权后走 Packet 修订 → 撤销旧冻结 → 重新 RED → 新 Frozen Test Commit；不得在实现提交中顺手改测试。

## 10. Completion Summary / PR contract

- Completion Summary 必含：base/final commit、修改文件与公共符号清单、AC→Test→Result 表（§7 ID）、§8 命令实际输出与统计、文件边界自查、已知限制（含"真实模型 client 接线未包含，模型路径由 fake 验证"声明）。
- Implementation PR：`Implements IP-0019` + `Related to #60`；正文含 Packet merge commit、Frozen Test Commit、FR-03/FR-04 子集/AC-02/NFR-01 贡献声明与 Not-covered 清单、AC 矩阵、`This PR does not auto-close the Source Issue.`；**禁止** close/fix/resolve + #60 组合（PI-DR5）。
- Packet docs PR（主会话执行）：`docs: freeze IP-0019 semantic prioritizer Top-N packet`，`Related to #60`，含本 Packet 主件 + IP-0018 Packet 勘误（PKT-ERRATUM-IP-0018-01，纯文档）。

## 11. Packet completion definition

本 Packet `READY-FOR-CODE` 当且仅当：TBD=0（现满足）、§1.1 DR 映射表全覆盖（现满足）、文档/链接/`git diff --check` 通过、阶段二冻结测试按 §6 计划完成有效 RED 与 PI-DR6 双平台记录。合并后由 Coordinator 标 `PACKET-MERGED`，随后派发阶段二（PKT-IP-0019-D2）。

## 12. Open Decisions 移交（不阻塞本 IP）

- RAM schema 化（语义承载入 wire schema）、golden envelope 绑定、`execution_required`、parse-error gap → #60-S4；
- 真实模型 client 网络实现与接线（含付费授权流程）→ #68/后续 IP（本 IP 仅冻结端口协议与预算拦截语义）；
- BG-IP-0016-01 backlog → 维持 IP-0018 §12 移交状态，不并入本 IP。

---

## 附：本 Packet 制作证据摘要

- Baseline 三组命令亲跑：617 OK / 64 OK 0 skip / 1180 OK 1 预存 skip（@dd324915，worktree `D:\BaseAIProject\LIMA-ip-0019-pv-wt` 分支 `docs/ip-0019-packet`，2026-09-13）。
- audit 64 vs 预告 68 差异定位：`tests/audit/test_profile_inventory.py` L167-168/L407/L439 fixture 字符串内 `def test` 假阳性 4 处；逐模块实测 32+23+5+4=64，0 skip。
- Issue #60 正文经 GitHub API 亲取（含 Delivery Ledger IP-0019=PROPOSED 行）。
- §3.1–§3.3 全部签名/行为自 `dd324915` 工作树逐行誊录亲验（ram.py `_collect_sink_facts`/`_collect_trust_boundaries`、profile.py `_validated_extensions` L192-193）。
