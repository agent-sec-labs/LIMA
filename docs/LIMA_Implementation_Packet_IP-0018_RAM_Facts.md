# Implementation Packet IP-0018 — Python RAM Facts（#60-S2）

> 文档类型：Implementation Packet（P&V 制作）
>
> Packet 版本：`IP-0018-PACKET/v1`
>
> 状态：`READY-FOR-CODE`（TBD = 0）
>
> Exact base：`fd219724076380448163d818f9ca26a3d5a5d945`（origin/main，含 IP-0016 交付与 #94 evidence_privacy）
>
> 制作人：lima-packet-verification（Assignment `IP-0018-PV-P1/v1`，任务标识 `PKT-IP-0018-D1`，2026-09-13）

---

## 0. Header（生命周期 §8 / 入口裁定第 1 项）

```text
Source Issue：#60（[V4-I04][P0] Repository Profile、RAM 与安全语义清单，V5 覆盖层版）
Issue specification revision：2026-09-12 Issue #60 正文（V5 覆盖层版，API 快照，含 Delivery Ledger 2026-09-13 更新）
Covered requirements：FR-02（六要素全部）、FR-05（子集：dynamic import、ambiguous dispatch 两个新 gap 类别）、NFR-01（RAM facts 层复验）
Not covered requirements：FR-01（已由 IP-0016 满足）、FR-03、FR-04（→ #60-S3）、FR-05 其余子集（parse-error-of-python-source 的 gap 编码归 #60-S4）、AC-01/T-01（→ #60-S4 + closure）、AC-02/T-02（→ #60-S3）、AC-03/T-03 与 NFR-02 端到端（→ closure）、V5-FR-03/V5-AC-02（→ #60-S4）、V5-FR-04/V5-AC-03 端到端复验（→ closure）、scanner/service 接线（不在 #60 范围）
Delivery role：foundation+facts
Issue closure impact：PARTIAL
Upstream IP/PR/merge commits：IP-0016（Packet PR #151 @2124e9e、v1.1 #152 @2b1a319、Frozen Tests 049328e、Implementation PR #167、merge fd219724、PM-IP-0016-1 PASS）
Upstream ruling：COORD-60S2-ENTRY_RULING-2026-09-13（编号原子分配 IP-0018 = #60-S2；consumer review 初审 PASS）
```

本 Packet 只声明 IP-0018 自身贡献：它交付 Python RAM 六要素静态事实层与两个调用图级 typed gap 类别。它**不**宣称 AC-01 golden matrix、Top-N 可重放（FR-04）或 T-03 端到端安全负例已满足。

---

## 1. Goal / Non-goals

### Goal

新增 `lima/audit/ram.py`：从 `lima.workspace.RepositoryWorkspace` 的有界只读快照出发，复用 `lima.python_dataflow.PythonDataflowAnalyzer` 的静态事实，确定性地派生并输出 FR-02 六要素（entrypoint、external source、sensitive sink、trust boundary、key flow、unresolved edge）与 FR-05 两个新 gap 类别（DYNAMIC_IMPORT、AMBIGUOUS_DISPATCH），全部路径 repo-relative、不含源码正文与 Secret（NFR-01）。

### Non-goals

- 不实现语义排序/Top-N/identity 稳定 envelope（FR-03/FR-04 → #60-S3/S4）；
- 不做 RAM schema adapter、golden fixtures、monorepo component graph（V5-FR-03 → #60-S4）；
- 不接线 `repository_scanner`/`service`/API；
- 不修改 IP-0016 任何已交付文件（inventory.py、tests/audit 既有三测试文件只读）；
- 不 import/执行目标代码、不联网、不安装依赖。

---

## 2. Design Input Manifest

| Input ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001 | Standard | `docs/LIMA_PACKET_AND_VERIFICATION_AGENT_RESPONSIBILITY_CHARTER.md` | main @fd219724 | Packet 结构、冻结/验证边界 | normative | — |
| DI-002 | Standard | `docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md` | main @fd219724 | 安全不变量（不执行、路径有界、fail-closed）、§12 验证标准 | normative | — |
| DI-003 | Standard | `docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md` | main @fd219724 | §8 Packet Gate 全清单、状态机、PR 禁自动关闭 | normative | — |
| DI-004 | Decision | Coordinator Assignment `IP-0018-PV-P1/v1` + `COORD-60S2-ENTRY_RULING-2026-09-13`（编号分配、范围、文件边界裁定，全文见 #60 Delivery Ledger open decisions） | 2026-09-13 | 范围、文件边界冻结、GAP 编码待核验点 | normative | 唯一上游裁定，不冲突 |
| DI-005 | Issue | Source Issue #60 正文（V5 覆盖层版 + Delivery Ledger 2026-09-13） | API 快照 2026-09-13（亲取，见证据 E-2） | FR-02/FR-05/NFR-01 需求文本、Ledger 状态 | normative | V5 覆盖层优先于 V4 正文 |
| DI-006 | Upstream IP | IP-0016 冻结面：`lima/audit/{__init__,inventory}.py` @fd219724；tests/audit 三测试文件（@049328e 含于 fd219724）；PM-IP-0016-1 | @fd219724 | 消费 `RepositoryProfile` 契约类型、GAP_* 常量语义、`__init__.py` 纯追加边界 | normative（接口）/ current-behavior（实现） | 只读消费，不修改 |
| DI-007 | Code | `lima/python_dataflow.py` @fd219724 | @fd219724（本 Packet §3 逐字段誊录） | 六要素数据来源（analyze_project 结果与实例状态） | current-behavior | API 面偏差 → 记差异/DR（见 §3.3） |
| DI-008 | Decision | DR-IP-0016-01（digest sentinel）+ DR-IP-0016-02 / PI-DR6（冻结测试平台中立）；PI-DR1..PI-DR6 | Ledger 记录 2026-09-12/13 | digest 语义、测试平台中立门禁、arrange 规则 | normative | 本 Packet 不引入 digest 字段则 DR-IP-0016-01 不触发（见 §5.4 裁定） |
| DI-009 | Code | `lima/contracts/profile.py` @fd219724（`AttackSurfaceEntry`、`ProfileCoverageGap`、`_REASON_CODE_PATTERN = [A-Z][A-Z0-9_]{0,63}`） | @fd219724 | 六要素载体类型、新 gap_code/reason_code 合法性 | normative（#58 冻结契约） | — |
| DI-010 | Code | `lima/workspace.py` @fd219724（`RepositoryWorkspace.inventory()/read_text()/fingerprint()`） | @fd219724 | 有界只读文件访问入口 | current-behavior | — |
| DI-011 | Review | Coordinator consumer review 初审记录（PASS，随 COORD-60S2-ENTRY_RULING-2026-09-13）：IP-0016 接口可承载 #60-S2 需求；残留复核点=GAP 枚举扩展点、ProfileBudgets 是否需 RAM 侧预算对象 | 2026-09-13 | §5 裁定依据；本 Packet 做逐字段复核（§5.5），不重做裁定 | background-only（裁定本体） | 复核推翻初审 → Contract Gap DR 停点；本次复核结论=不推翻（§5.5） |

### Explicitly Rejected Inputs

- `docs/LIMA_V5_真实测试驱动的通用全链路实施重基线与Issue闭环规划.md` 的路线图阶段名（#60-S2/S3/S4）——仅作历史背景；编号与范围以 NUM-ERRATUM-01 协议与入口裁定为准，阶段名不得替代 IP-0018 正式编号。
- IP-0017 分支/PR #168 相关文档（#94 轨道）——平行轨道，不属于本 IP 输入。
- BG-IP-0016-01 backlog（max_manifest_files 溢出边界、frameworks manifest 字面差异）——Coordinator 裁定不并入本 IP；本 Packet 不扩展 IP-0016 验收面（Open Decisions 移交 §12）。
- 任何"Top-N 默认值/预算来源"的聊天讨论——FR-04 归 #60-S3，本 Packet 不冻结该值。
- `lima/semantic_retrieval.py`——FR-03 数据源，#60-S3 才消费，本 IP 不引用。

---

## 3. Current code baseline（亲验誊录，@fd219724）

### 3.1 python_dataflow 消费面（DI-007，逐字段）

模块级公开常量（词表，运行时按引用消费、不复制）：

```python
DIRECT_SOURCE_CALLS: dict[str, str]        # {"input","builtins.input","os.getenv"} → label
REQUEST_SOURCE_SUFFIXES: dict[str, str]    # {"args.get","form.get","values.get","cookies.get","headers.get","GET.get","POST.get","get_json"} → label
REQUEST_SOURCE_ATTRIBUTES: dict[str, str]  # {"data","json","body","stream"} → label
ENDPOINT_DECORATORS: set[str]              # {"route","api_route","get","post","put","patch","delete","websocket"}
```

类型（全部 `lima/python_dataflow.py`）：

```python
@dataclass(frozen=True) class FlowStep:  path: str; line: int; kind: str; snippet: str
@dataclass               class TaintTrace: label: str; steps: list[FlowStep]  # steps ≤12
@dataclass               class PythonDataflowResult:
    findings: list[Finding]; parse_error: str; functions_indexed: int;
    interprocedural_edges: int; truncated_calls: int; unresolved_calls: int;
    modules_indexed: int; cross_file_edges: int; dynamic_import_sites: int;
    ambiguous_modules: int; parse_errors: dict[str, str]
@dataclass(frozen=True) class ModuleInfo:     name: str; path: str; tree: ast.Module; lines: tuple[str, ...]; is_package: bool
@dataclass(frozen=True) class FunctionSymbol: key: str; module: str; name: str; path: str; node: ast.FunctionDef | ast.AsyncFunctionDef
@dataclass(frozen=True) class Sink:           rule_id: str; cwe: str; severity: Severity; title: str; explanation: str; fix: str; test: str; argument: ast.AST
class PythonDataflowAnalyzer:
    def __init__(self, max_call_depth: int = 4) -> None: ...   # <1 raise ValueError
    def analyze(self, path: str, content: str) -> PythonDataflowResult
    def analyze_project(self, files: dict[str, str]) -> PythonDataflowResult
```

`analyze_project` 之后**实例上的公开状态属性**（非下划线前缀，本 Packet 冻结为消费面；坐标一律 repo-relative POSIX 路径）：

```python
dynamic_import_sites: set[tuple[str, int]]          # (path, lineno)，__import__/importlib.import_module
unresolved_call_sites: set[tuple[str, int, str]]    # (path, lineno, callee 呈现名)
modules: dict[str, ModuleInfo]; module_functions: dict[str, dict[str, FunctionSymbol]]
call_edges: set[tuple[str, str, str, int]]; cross_file_call_edges: set[...]
```

`Finding`（`lima/models.py`）：`rule_id`（FLOW-EVAL/FLOW-COMMAND/FLOW-SQL/FLOW-DESERIALIZATION/FLOW-PATH）、`cwe`、`path`、`line`、`evidence`、`evidence_records`、`fingerprint`。

已知口径（誊录为设计前提，不修改）：analyzer 仅索引模块顶层函数；`PythonDataflowResult` 只含 dynamic_import_sites/ambiguous_modules 的**计数**，站点明细只在实例属性/`parse_errors`。模块名重复时全部同名模块被剔除出索引（`modules` 只收唯一候选）。

### 3.2 IP-0016 消费面（DI-006/DI-009）

`lima/audit/__init__.py`（33 行，12 个 `__all__` 条目）纯追加 re-export 边界；`lima/audit/inventory.py`：`PROFILE_PROVENANCE_ANCHOR="inventory"`、五个 `GAP_*` Final 常量、`SKIP_REASON_TO_GAP_DETAIL`、`ProfileBudgets`、`ProfileInventoryOptions`、`ProfileBuildResult{profile,envelope,provenance_anchor_ids}`、`build_repository_profile(workspace, *, tenant_id, task_id, workflow_id, stage_attempt_id, artifact_id, repository_snapshot_digest, producer=..., policy_digest=..., toolchain_digest=..., options=None)`。

`lima/contracts/profile.py`：`AttackSurfaceEntry{path, reason_codes, source_artifact_ids, symbol=None, extensions}`（path 经 `_validated_path` 强制 repo-relative、禁 `\` 与盘符）、`ProfileCoverageGap{gap_code, detail, extensions}`（gap_code 须匹配 `[A-Z][A-Z0-9_]{0,63}`）、`RepositoryProfile`（`entrypoints/external_inputs/trust_boundaries/sensitive_operations` 均为 `tuple[AttackSurfaceEntry, ...]`）。

### 3.3 与预期的偏差核验

Assignment 预告的 API 面与实际**无重大偏差**；两处口径差异已在上文誊录并纳入设计（顶层函数索引口径、gap 计数 vs 站点明细）。不触发 DR。

---

## 4. Files boundary（Coordinator 裁定冻结）

- **Files to Add**：`lima/audit/ram.py`（唯一产品代码文件）。
- **Product Files Allowed to Modify**：`lima/audit/__init__.py` —— 仅限"纯追加 re-export"：在既有 import 块与 `__all__` 列表**末尾**追加 §5.3 冻结的新公共符号；不得改动既有 12 个 `__all__` 条目、既有 import 行、模块 docstring 的既有语句（docstring 首行可追加一句说明 ram 层，属追加语义；如 Implementation 判断有歧义，保持 docstring 原样）。
- **Test/Fixture Files Owned by P&V（阶段二独占，本阶段不创建）**：`tests/audit/test_ram_facts.py`、`tests/audit/fixtures/ram/*`。
- **Read-only Reference**：`lima/python_dataflow.py`、`lima/workspace.py`、`lima/audit/inventory.py`、`lima/contracts/**`、`lima/models.py`、tests/audit 既有三文件（`test_profile_contract_encoding.py`、`test_profile_inventory.py`、`test_profile_security.py`）。
- **Files Forbidden**：除上述 Add/Modify 外的一切路径；特别冻结：`lima/audit/inventory.py`、tests/audit 既有三测试文件、`schemas/**`、`.zcode/**`、#94 轨道全部路径（`lima/evidence_privacy/`、`tests/evidence_privacy/`、`docs/LIMA_Issue_94_*`、IP-0017 分支/PR #168 相关）。

### Symbol-to-File Map（全部新增符号均在 `lima/audit/ram.py`）

| Symbol | 种类 |
|---|---|
| `RAM_PROVENANCE_ANCHOR: Final[str] = "ram-facts"` | 常量 |
| `GAP_DYNAMIC_IMPORT: Final[str] = "DYNAMIC_IMPORT"` | 常量 |
| `GAP_AMBIGUOUS_DISPATCH: Final[str] = "AMBIGUOUS_DISPATCH"` | 常量 |
| `RamBudgets`（frozen dataclass） | 类型 |
| `RamKeyFlow`（frozen dataclass） | 类型 |
| `PythonRamFacts`（frozen dataclass） | 类型 |
| `RamFactsBuildResult`（frozen dataclass） | 类型 |
| `build_python_ram_facts(workspace, *, budgets=None) -> RamFactsBuildResult` | 函数 |
| `ram_facts_digest(facts: PythonRamFacts) -> str` | 函数 |

依赖方向：`lima.audit.ram` → `lima.workspace`、`lima.python_dataflow`、`lima.contracts.{profile,codec}`、`lima.models`（类型引用）。stdlib-only 除此之外；不新增第三方依赖、不联网、不落盘写。

---

## 5. Design Contracts（FR-02 六要素 + FR-05 gap 编码 + NFR-01）

### 5.0 输入与总流程（冻结单解）

```python
def build_python_ram_facts(
    workspace: RepositoryWorkspace, *,
    budgets: RamBudgets | None = None,
) -> RamFactsBuildResult
```

1. 校验 `isinstance(workspace, RepositoryWorkspace)` 否则 `ContractError(INVALID_FIELD_TYPE)`（fail-closed，同 IP-0016 口径）；`budgets is None` 时取 `RamBudgets()`。
2. `inventory = workspace.inventory()`；候选文件 = inventoried 中后缀 `.py` 的文件，按 path 字典序排序；超过 `budgets.max_python_files` 时截断并追加 `GAP_BUDGET_EXHAUSTED` gap（detail=`reason=python-file-limit; count=<溢出数>`，复用 IP-0016 常量语义）。
3. 逐文件 `workspace.read_text(path)` 取文本（skip 原因/读取失败的文件直接跳过，不猜默认；每个跳过文件追加 `GAP_INVENTORY_SKIPPED` detail=`reason=read-failed; file=<path>`——单解、fail-closed）。
4. `analyzer = PythonDataflowAnalyzer(max_call_depth=4)`（默认值冻结）；`result = analyzer.analyze_project(files)`；保留 analyzer 实例供 §5.1.6 / §5.2 消费。
5. 依 §5.1 派生六要素；依 §5.2 产出 gap；构造 `PythonRamFacts`；返回 `RamFactsBuildResult(facts=..., provenance_anchor_ids=(RAM_PROVENANCE_ANCHOR,))`。

`PythonDataflowResult.parse_errors` 中的文件**不参与**任何要素派生；本 IP 不为 Python 源语法错误发新 gap 类别（归 #60-S4，见 Not covered）。

### 5.1 FR-02 六要素 Design Contract

载体约定：entrypoint / external source / sensitive sink / trust boundary 四类事实条目使用 #58 冻结类型 `AttackSurfaceEntry`，`source_artifact_ids=(RAM_PROVENANCE_ANCHOR,)`，`extensions={}`；排序一律 `(path, symbol or "")` 字典序（`AttackSurfaceEntry` 契约要求 reason_codes/source_artifact_ids 有序去重，构造时照办）。**任何要素不得包含源码正文**（FlowStep.snippet 不进入输出）。

#### 5.1.1 entrypoint

- 数据来源：`analyzer.modules` 的各 `ModuleInfo.tree` 自行 `ast.walk`（不依赖 analyzer 只索引顶层函数的口径），收集**任意嵌套层级**（含类方法）的 `FunctionDef/AsyncFunctionDef`，其任一 decorator 的 call-name 末段 ∈ `lima.python_dataflow.ENDPOINT_DECORATORS`（运行时引用该公开集合，不复制）。
- 派生规则（冻结单解）：每个命中函数 → `AttackSurfaceEntry(path=<模块文件 path>, symbol=<函数名>, reason_codes=("RAM_ENDPOINT_DECORATED",))`。
- 输出形态：`PythonRamFacts.entrypoints: tuple[AttackSurfaceEntry, ...]`。
- 测试锚点：fastapi 风格 `@app.get("/x")` 装饰函数被收录（含类方法）；无装饰器仓库该元组为空。

#### 5.1.2 external source

- 数据来源：对同一批 `ModuleInfo.tree` 的 `ast.walk`，命中以下三种站点之一（词表运行时引用 python_dataflow 公开映射，label 取其 value）：
  1. `ast.Call` 的 `_call_name`（复用 `lima.python_dataflow._call_name` 的等价逻辑；因带下划线不可导入，**在 ram.py 内实现同语义的 call-name 拼接**，语义=Attribute 链+Name 反向 join，冻结于此）∈ `DIRECT_SOURCE_CALLS`；
  2. `ast.Call` 其 func 为 Attribute 且完整名以 `REQUEST_SOURCE_SUFFIXES` 的键结尾（如 `request.args.get`）；
  3. `ast.Attribute` 的完整名末段 ∈ `REQUEST_SOURCE_ATTRIBUTES`。
- 派生规则：每个站点 → `AttackSurfaceEntry(path, symbol=<最近包围函数名，无则为 None>, reason_codes=("RAM_EXTERNAL_SOURCE",))`；label 写入 facts 的独立结构（见输出形态）。
- 输出形态：`external_sources: tuple[AttackSurfaceEntry, ...]` 加 `source_labels: tuple[str, ...]`（与条目一一对应、同序，元素为词表 label，如 `"request query parameter"`）。
- 测试锚点：`os.getenv("X")`、`request.args.get("q")`、`request.json` 各产生一条；普通本地变量赋值不产生。

#### 5.1.3 sensitive sink

- 数据来源：`result.findings`（仅数据流可达的 sink——evidence-backed 口径，与"任意疑似 sink 调用"区分，本裁定冻结为前者）。
- 派生规则：每个 `Finding` → `AttackSurfaceEntry(path=finding.path, symbol=None, reason_codes=("RAM_SENSITIVE_SINK",))`，同时把 `rule_id`/`cwe` 记入独立并行元组 `sink_rule_ids`/`sink_cwes`（与条目同序）。
- 输出形态：`sensitive_sinks: tuple[AttackSurfaceEntry, ...]`、`sink_rule_ids: tuple[str, ...]`、`sink_cwes: tuple[str, ...]`。
- 测试锚点：`os.system(request.args.get("cmd"))` 产生 FLOW-COMMAND sink 条目；纯常量 `os.system("ls")` 不产生（无 taint）。
- 词表口径誊录：sink 规则集合 = python_dataflow `_sink` 现行为（FLOW-EVAL/CWE-95、FLOW-COMMAND/CWE-78、FLOW-SQL/CWE-89、FLOW-DESERIALIZATION/CWE-502、FLOW-PATH/CWE-22）；通过 findings 间接消费，不复制其实现。

#### 5.1.4 trust boundary

- 派生规则（冻结单解）：trust boundary = 信任跨越位置的文件级事实 = entrypoint 条目（网络暴露面）与 external source 条目（不可信数据进入面）所在 `(path)` 去重并集；每个 path 一条 `AttackSurfaceEntry(path, symbol=None, reason_codes=("RAM_TRUST_BOUNDARY",))`。
- 输出形态：`trust_boundaries: tuple[AttackSurfaceEntry, ...]`。
- 测试锚点：仅含 endpoint 的仓库与仅含 `os.getenv` 的仓库各产生对应 path 的一条；两者同文件时仍恰一条（去重）。

#### 5.1.5 key flow

- 数据来源：`result.findings` 的 `evidence_records`（`EvidenceRecord` 中的 trace 步骤；Implementation 阶段以 tests 冻结实际字段路径——本 Packet 冻结语义为"source→sink 的有序步骤序列（path,line）"，不含 snippet/正文）。
- 派生规则：每个 Finding 一条 `RamKeyFlow`：

```python
@dataclass(frozen=True)
class RamKeyFlow:
    sink_rule_id: str
    steps: tuple[str, ...]   # 每元素 "path:line"（POSIX repo-relative），按数据流顺序，≤12 步（TaintTrace 上界）
```

- 排序：`(sink_rule_id, steps)` 字典序；超过 `budgets.max_key_flows` 时截断并追加 `GAP_BUDGET_EXHAUSTED` detail=`reason=key-flow-limit; count=<溢出数>`。
- 输出形态：`key_flows: tuple[RamKeyFlow, ...]`。
- 测试锚点：source→sink 两步以上流至少记录首末两站；不含任何源码片段字符串。

#### 5.1.6 unresolved edge

- 数据来源：`analyzer.unresolved_call_sites`（实例属性，`(path, line, callee_name)`）。
- 派生规则：每个站点 → `AttackSurfaceEntry(path, symbol=<callee_name>, reason_codes=("RAM_UNRESOLVED_CALL",))`；超过 `budgets.max_unresolved_edges` 截断 + `GAP_BUDGET_EXHAUSTED` detail=`reason=unresolved-edge-limit; count=<溢出数>`。
- 输出形态：`unresolved_edges: tuple[AttackSurfaceEntry, ...]`。
- 测试锚点：调用未定义/未导入名字的仓库产生带 callee symbol 的条目；全可解析仓库为空。

#### 5.1.7 汇总对象与确定性

```python
@dataclass(frozen=True)
class PythonRamFacts:
    entrypoints: tuple[AttackSurfaceEntry, ...]
    external_sources: tuple[AttackSurfaceEntry, ...]
    source_labels: tuple[str, ...]
    sensitive_sinks: tuple[AttackSurfaceEntry, ...]
    sink_rule_ids: tuple[str, ...]
    sink_cwes: tuple[str, ...]
    trust_boundaries: tuple[AttackSurfaceEntry, ...]
    key_flows: tuple[RamKeyFlow, ...]
    unresolved_edges: tuple[AttackSurfaceEntry, ...]
    coverage_gaps: tuple[ProfileCoverageGap, ...]
    counters: mapping 冻结视图（dynamic_import_sites、ambiguous_modules、unresolved_calls、modules_indexed、functions_indexed、interprocedural_edges、cross_file_edges、parse_error_files 计数，取名与 PythonDataflowResult 同名，parse_error_files=len(result.parse_errors)）

@dataclass(frozen=True)
class RamFactsBuildResult:
    facts: PythonRamFacts
    provenance_anchor_ids: tuple[str, ...]

@dataclass(frozen=True)
class RamBudgets:   # 复核 DI-011 残留点②，见 §5.5
    max_python_files: int = 512
    max_key_flows: int = 256
    max_unresolved_edges: int = 1024
    # __post_init__：逐字段 type is int 且 >0，否则 ValueError（同 ProfileBudgets 口径）
```

`ram_facts_digest(facts) -> str`：对 `PythonRamFacts` 的规范序列（各元组按上文冻结序；`counters` 按键名字典序；经 `lima.contracts.codec.compute_content_digest`）计算 64-hex digest。**确定性冻结**：同一 workspace 快照 + 同一 budgets ⇒ 两次构建的 facts 相等且 digest 相等；无时钟、无随机、无环境变量输入。

### 5.2 FR-05 两个新 gap 类别的编码裁定（入口裁定待核验点 ② / DI-011 残留点①）

**裁定：新增两个独立常量 `GAP_DYNAMIC_IMPORT="DYNAMIC_IMPORT"`、`GAP_AMBIGUOUS_DISPATCH="AMBIGUOUS_DISPATCH"`（定义在 `lima/audit/ram.py`），不复用 IP-0016 五个 `GAP_*`。**

理由：

1. IP-0016 的五个 GAP 语义绑定 inventory 层失败模式（语言/预算/manifest/跳过），其 detail 文案与 SKIP_REASON 映射已冻结；dynamic import 与 ambiguous dispatch 是**调用图层的正向观察**（"分析覆盖受限的事实"），语义正交。
2. `ProfileCoverageGap.gap_code` 契约接受任意 `[A-Z][A-Z0-9_]{0,63}` 字符串（DI-09 亲验），新增类别无需改 #58 契约、无需 IP-0016 变更——即"扩展点在常量层而非枚举层"，与 consumer review 初审"接口可承载"结论逐字段一致。
3. `GAP_BUDGET_EXHAUSTED` **复用** IP-0016 常量（同语义：预算截断），detail 用 IP-0016 的 `reason=...; count=...` 模板。

产出规则：

- dynamic import：`len(analyzer.dynamic_import_sites) > 0` ⇒ 一条 `ProfileCoverageGap(gap_code=GAP_DYNAMIC_IMPORT, detail=f"reason=dynamic-import; count={n}")`（n=站点数；站点坐标已在 analyzer 实例上，本 IP 不入 detail，保持与 IP-0016 detail 模板一致的简洁口径）。
- ambiguous dispatch：`result.ambiguous_modules > 0` ⇒ `ProfileCoverageGap(gap_code=GAP_AMBIGUOUS_DISPATCH, detail=f"reason=ambiguous-module; count={n}")`。语义誊录：同名模块多候选时 analyzer 剔除全部候选（§3.1），该 count 即被剔除的重复模块名数。
- `execution_required` 标志：`PythonRamFacts.counters` 不含执行语义；FR-05 的 `execution_required` Mining 消费字段归 #60-S4 RAM schema adapter（Not covered）。本 IP 的 gap 均为纯静态 typed gap。

### 5.3 `lima/audit/__init__.py` 纯追加 re-export 清单（冻结）

在既有 import 块末尾追加：

```python
from lima.audit.ram import (
    GAP_AMBIGUOUS_DISPATCH,
    GAP_DYNAMIC_IMPORT,
    RAM_PROVENANCE_ANCHOR,
    PythonRamFacts,
    RamBudgets,
    RamFactsBuildResult,
    RamKeyFlow,
    build_python_ram_facts,
    ram_facts_digest,
)
```

`__all__` 列表在既有 12 项之后按字母序段追加上述 9 个名字。既有条目、顺序、docstring 既有语句不动。追加后 `python -c "import lima.audit"` 必须零副作用（不触发任何文件/网络操作）。

### 5.4 envelope / digest 裁定（DI-008 复核）

本 IP **不产出 ArtifactEnvelope**：FR-04 的 identity/seed/prompt/model digest 归 #60-S3，golden envelope 绑定归 #60-S4；此时引入 envelope 会预冻结 #60-S3 的开放参数。因此 DR-IP-0016-01 的 sentinel 语义在本 IP 仅体现为"不引入 digest 字段"；`ram_facts_digest` 是纯函数、恒非空 64-hex（`compute_content_digest` 保证）。若 Review 认为必须提前 envelope 化 → Decision Request，不得在实现期自行添加。

### 5.5 Consumer review 初审逐字段复核（DI-011，不重做裁定）

| 初审字段 | 复核结论 | 证据 |
|---|---|---|
| RepositoryProfile 契约类型可承载 RAM 事实 | 成立：五张攻击面清单字段与 `AttackSurfaceEntry`（symbol/reason_codes/source_artifact_ids/extensions）恰好覆盖六要素中四类列表型要素；key flow 用独立 frozen dataclass 表达 | §3.2；profile.py @fd219724 |
| GAP 枚举可扩展 | 成立且方式确认：扩展点在**模块级 Final 常量**而非封闭 enum；`ProfileCoverageGap.gap_code` 为 pattern 校验字符串 | `_REASON_CODE_PATTERN` @profile.py:69 |
| ProfileBudgets 是否需 RAM 侧预算对象 | 需要，且独立定义：ProfileBudgets 校验器绑定 manifest 语义字段名（manifest_max_bytes/max_manifest_files），不适用；冻结新增 `RamBudgets`（§5.1.7） | inventory.py:207-218 |
| `build_repository_profile` 可被 RAM 层复用 | 本 IP 不调用（六要素可仅从 python_dataflow+workspace 派生）；留给 #60-S4 schema adapter 组合。不构成推翻 | §5.0 |

复核结论：**不推翻 COORD-60S2-ENTRY_RULING-2026-09-13 初审**，无 Contract Gap DR。

### 5.6 NFR-01 复验契约

- 全部输出 path 来自 workspace inventory 的 repo-relative POSIX 路径；`AttackSurfaceEntry` 构造时 `_validated_path` 再拦一道（绝对路径/`..`/反斜杠/盘符抛 ContractError）。
- `RamKeyFlow.steps` 只含 `path:line` 字符串；`PythonRamFacts` 任何字段不得含源码正文（测试断言：对已知 fixture，facts 的序列化文本中不出现 fixture 源码行的非平凡子串与任何 secret 样式 token）。
- 模块无 network import（socket/requests/urllib 等）、无文件写、无 os.environ 读取（ruff+bandit+测试 import 边界断言）。

---

## 6. Test matrix（阶段二冻结计划；类别 × 最低用例数）

| 类别 | 最低数 | 覆盖内容（→ AC/FR） |
|---|---|---|
| 调用图派生（六要素各≥2） | 12 | endpoint 装饰（含类方法）、source 三型、tainted sink、trust boundary 去重、key flow 首末站、unresolved call（FR-02） |
| gap 类别 | 5 | DYNAMIC_IMPORT、AMBIGUOUS_DISPATCH、BUDGET_EXHAUSTED（files/key-flows/edges 三截断）、read-failed skip（FR-05 子集） |
| 确定性 | 3 | 同快照两次构建 facts 相等且 digest 相等；digest 64-hex；facts 构造的契约校验负例（绝对 path/空 reason_codes → ContractError）（NFR-01+确定性） |
| 与 profile 集成回归 | 2 | `import lima.audit` 后 IP-0016 公共 API 12 符号仍在 `__all__` 且顺序不变；既有 tests/audit 32 用例 0 回归（文件边界） |
| 安全负例 | 4 | 恶意 setup.py 不执行（无网络/无写盘断言）、secret 样式 token 不入 facts、源码正文不入 facts、非 workspace 入参 fail-closed（NFR-01/部分 NFR-02 复验） |

合计最低 26 个新用例（`tests/audit/test_ram_facts.py`）。PI-DR 落实：

- **PI-DR1（arrange 平台中立）**：fixture 文本写入显式 `newline="\n"` 钉死 LF；路径断言用 POSIX 字面量；不依赖平台权限/大小写语义。
- **PI-DR6（双平台）**：冻结前在非 Windows 平台（CI Linux runner）完整跑一次新增测试集，记录 run SHA 与结论入 Frozen Test Commit 记录；Windows 本机 RED/GREEN 同步记录。
- PI-DR2..DR5 按标准门禁执行（ruff/bandit 零 finding；PR 无自动关闭关键字；diff 恰为 allowlist 文件）。

## 7. AC traceability

| Requirement | 测试 ID 计划（阶段二冻结时定稿） | 断言要点 |
|---|---|---|
| FR-02 entrypoint | test_ram_facts::test_entrypoint_decorated / test_entrypoint_class_method / test_entrypoint_empty | §5.1.1 |
| FR-02 external source | test_external_source_env / test_external_source_request / test_external_source_attribute / test_external_source_negative | §5.1.2 |
| FR-02 sensitive sink | test_sensitive_sink_tainted / test_sensitive_sink_constant_negative | §5.1.3 |
| FR-02 trust boundary | test_trust_boundary_union_dedup / test_trust_boundary_from_source_only | §5.1.4 |
| FR-02 key flow | test_key_flow_steps / test_key_flow_no_source_text / test_key_flow_budget | §5.1.5 |
| FR-02 unresolved edge | test_unresolved_edge_symbol / test_unresolved_edge_empty / test_unresolved_edge_budget | §5.1.6 |
| FR-05 子集 | test_gap_dynamic_import / test_gap_ambiguous_dispatch / test_gap_budget_exhausted_variants | §5.2 |
| NFR-01 | test_determinism_digest / test_no_host_path / test_no_source_text_or_secret / test_fail_closed_inputs | §5.6 |

---

## 8. Commands（逐条精确 + 预期；阶段二/实现/验证共用）

Baseline（@fd219724，本 Packet 制作时已亲跑通过，见证据 E-1）：

```text
python -m unittest discover -s tests/contracts -q   → Ran 617 tests, OK
python -m unittest discover -s tests/audit -q       → Ran 32 tests, OK (0 skip)
python -m unittest discover -s tests -q             → Ran 1072 tests, OK (skipped=1, 预存 symlink 环境 skip)
```

Slice / mandatory（实现完成后）：

```text
python -m unittest tests.audit.test_ram_facts -v                     → 全部新用例 OK，0 skip
python -m unittest discover -s tests/audit -q                        → Ran 32+N tests, OK（IP-0016 冻结面不可回归）
python -m unittest discover -s tests -q                              → Ran 1072+N, OK (skipped=1)
python -m compileall -q lima                                          → exit 0
python -m ruff check lima/audit/ram.py lima/audit/__init__.py tests/audit/test_ram_facts.py  → 零 finding
python -m bandit -q lima/audit/ram.py                                 → 零 finding
git diff --check                                                      → 干净
git diff --name-only --diff-filter=ACMRTUXB                           → 恰为 lima/audit/ram.py + lima/audit/__init__.py + tests/audit/test_ram_facts.py (+ fixtures)
```

Compatibility/boundary：`python -c "import lima.audit as a; assert a.__all__[:12]==[...IP-0016 既有 12 项...] and len(a.__all__)==21"`（既有前缀不变）。

Post-merge（main 上复验）：上述 mandatory 全组 + contracts 617。

---

## 9. Stop Conditions / Decision Request

停止并提交 Decision Request 的情形：

1. 实现期发现 `PythonDataflowAnalyzer` 实例状态属性（`unresolved_call_sites`/`dynamic_import_sites`/`modules`）在最新 main 被改名/私有化（DI-007 口径漂移）；
2. 发现必须修改 `inventory.py`、tests/audit 既有三文件或 #94 轨道文件才能满足本 Packet；
3. 六要素任一派生规则出现多解或与 #58 契约校验冲突（Contract Gap）；
4. 基线命令结果与本 Packet §8 记录不符（环境问题）；
5. 发现 IP-0018 编号被对端轨道登记/占用（入口裁定失效条款）。

冻结测试需变更时：先向 Coordinator 提交 Decision Request（缺陷证据 + 影响面），获授权后走 Packet 修订 → 重新 RED → 新 Frozen Test Commit，不得在实现提交中顺手改测试。

## 10. Completion Summary / PR contract

- Completion Summary 必含：base/final commit、修改文件与公共符号清单、AC→Test→Result 表（§7 ID）、§8 命令实际输出与统计、文件边界自查、已知限制。
- Implementation PR：`Implements IP-0018` + `Related to #60`；正文含 Packet merge commit、Frozen Test Commit、FR-02/FR-05 子集/NFR-01 贡献声明与 Not-covered 清单、AC 矩阵、`This PR does not auto-close the Source Issue.`；**禁止** close/fix/resolve + #60 组合（PI-DR5）。
- Packet docs PR（主会话执行）：`docs: freeze IP-0018 Python RAM facts packet`，`Related to #60`，仅含本 Packet 文档。

## 11. Packet completion definition

本 Packet `READY-FOR-CODE` 当且仅当：TBD=0（现满足）、文档/链接/`git diff --check` 通过、阶段二冻结测试按 §6 计划完成有效 RED 与 PI-DR6 双平台记录。合并后由 Coordinator 标 `PACKET-MERGED`，随后派发阶段二（PKT-IP-0018-D2）。

## 12. Open Decisions 移交（不阻塞本 IP）

- Top-N 默认值与预算语义（FR-04）→ #60-S3，owner 已记 Ledger（lima-packet-verification）。
- Python 源 parse-error 的 typed gap 编码与 `execution_required` Mining 消费字段 → #60-S4 schema adapter。
- BG-IP-0016-01（IP-0016 边界路径覆盖缺口）→ 由届时 Coordinator 决定并入 #60-S3/S4 或 closure 前测试扩充 Packet；不并入本 IP。

---

## 附：本 Packet 制作证据摘要

- Baseline 三组命令亲跑：617 OK / 32 OK 0 skip / 1072 OK 1 预存 skip（@fd219724，worktree `D:\BaseAIProject\LIMA-ip-0018-pv-wt`，2026-09-13）。
- Issue #60 正文经 GitHub API 亲取（含 Delivery Ledger IP-0018=PROPOSED 行与 COORD-60S2-ENTRY_RULING-2026-09-13 全文）。
- §3 全部签名自 `fd219724` 工作树逐行誊录。
