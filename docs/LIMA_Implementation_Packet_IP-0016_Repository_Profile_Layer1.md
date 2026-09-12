# LIMA Implementation Packet IP-0016：Repository Profile Layer 1（deterministic inventory adapter + typed coverage gap + #58 RepositoryProfile 契约编码）

> Packet 版本：`IP-0016-PACKET/v1`
> 状态：`DESIGN-FROZEN / PENDING-MERGE`（Packet docs PR 合并进 `main` 后，由 Coordinator 标记 `PACKET-MERGED`，方可进入阶段二测试冻结）
> 制作：LIMA Packet & Verification Agent（阶段一，Assignment `IP-0016-PV-P1/v1`，任务标识 `PKT-IP-0016-D1`，2026-09-12）
> 阶段边界：本 Packet 只交付设计。验收测试文件、有效 RED、Frozen Test Commit 属阶段二，在 Packet 进 `main` 后另行执行（见 §14 阶段二执行计划）。

## 需求映射（Header）

```text
Source Issue：#60（[V4-I04][P0] Repository Profile、RAM 与安全语义清单，V5 覆盖层版）
Issue specification revision：2026-09-12 Issue #60 正文 API 快照（Delivery Ledger 标记同值）
Covered requirements（本 IP 声明的贡献，且仅此贡献）：
  - FR-01（确定性 inventory：语言/框架线索/入口/配置/依赖清单/测试/生成文件识别 + 每个跳过项 reason）
  - FR-05 子集（仅清单层三源：unsupported language、budget exhaustion、manifest 层 parse error → typed coverage gap）
  - NFR-01（路径 repo-relative；禁 host path / 源码全文 / Secret 进入输出）
  - NFR-02 清单层子集（只读、不执行目标代码、不 import 目标包、不安装依赖、不联网）
  - V5-FR-01（Profile 先于 RAM：本 IP 交付 Profile 生成层，模块不依赖任何 RAM 概念）
  - V5-FR-02（code role 基于路径 + manifest + import/build/test 配置的组合证据）
  - V5-T-01 的 profile 维度（application/library/CLI/docs/test-heavy fixtures 输出
    RepositoryProfile + code roles + support level + execution capability + coverage gap）
Not covered requirements（相邻但明确不在本 IP）：
  - FR-02 全部（symbol/call graph、Source/Sink、trust boundary、key flow、unresolved edge）
  - FR-03（语义 prioritizer）
  - FR-04（语义排序与 Top-N；其默认值/预算来源锚定记入 Open Decisions 移交，不阻塞本 Packet）
  - FR-05 中依赖调用图的 gap 源（dynamic import、ambiguous dispatch 级别）
  - AC-01/T-01 的 RAM golden matrix、AC-02/T-02 semantic degradation
  - AC-03/T-03 恶意样本端到端（本 IP 仅验证清单路径不执行；共享 fixture 的端到端归 closure IP）
  - V5-FR-03（monorepo component graph 与 docs/unsupported 安全停止语义）——本 IP 仅输出
    repository_kinds 含 monorepo/docs_content 的分类与 support_level/gap，不输出 component graph，
    也不实现"安全停止"行为
  - V5-AC-02/T-02、V5-AC-03/T-03 端到端
  - 一切产品实现之外的能力（scanner/service/API/store/sandbox/frontend 接线）
Delivery role：foundation
Issue closure impact：PARTIAL
Upstream：#58 contracts @ 7734e58（lima/contracts/、schemas/v4/、tests/contracts/ 及 fixtures，全部只读）
          + Issue #60/#94 kickoff checklists @ 1358e85（PR #148）
```

## 0. 入口 Gate 与基线实证（P&V 亲验，2026-09-12，worktree `D:\BaseAIProject\LIMA-ip-0016-pv-wt` @ `1358e85`）

| 命令（cwd = worktree 根） | 实测结果 | 判定 |
|---|---|---|
| `python -m unittest discover -s tests/contracts -q` | `Ran 617 tests in 5.293s / OK` | 与 Ledger 登记的 617 OK 一致 |
| `python -m unittest tests.test_workspace tests.test_python_dataflow` | `Ran 40 tests in 3.814s / OK` | 基线绿 |
| `ls lima/audit tests/audit` | 两者均不存在 | PI-DR4"模块缺席"RED 锚定前提成立 |

环境：Windows 10（10.0.26200），Git Bash，Python 以 `python` 调用（版本由阶段二 RED 记录补全精确 `python -V` 输出）。

### Current code baseline 亲验记录（Issue §"Current code baseline" vs 实际代码）

- `lima/workspace.py`：`RepositoryWorkspace(root, *, max_files=5000, max_file_bytes=512KiB, max_total_bytes=20MiB, extensions=None, ignored_directories=None)`；`inventory() -> WorkspaceInventory`（`files: list[WorkspaceFile(path,size,sha256)]`、`skipped: dict[str,int]` 按 reason 计数、`discovered_files/bytes`、`truncated`、`fingerprint()`）；`read_text(rel)` / `absolute_file(rel)` / `iter_text()`。跳过 reason 现有词汇：`ignored-directory`、`symlink`、`sensitive-config`、`unsupported-extension`、`unreadable`、`file-size-limit`、`file-limit`、`total-size-limit`、`binary`、`non-utf8`。与 Issue 描述一致，无偏差。
- `lima/python_dataflow.py`：`ModuleInfo(name,path,tree,lines,is_package)`、`FunctionSymbol(key,module,name,path,node)`、`PythonDataflowAnalyzer(max_call_depth).analyze_project(files: dict[str,str]) -> PythonDataflowResult`（暴露 parse_errors、动态 import 位点、未解析调用位点等）。与 Issue 描述一致。本 IP 仅将其视为后续 RAM IP 的只读背景，不在本 IP 消费。
- `lima/semantic_retrieval.py`：仅背景，本 IP 不引用。
- 差异结论：无重大偏差，不需要 Decision Request。

## 1. Design Input Manifest

| ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001 | Standard | `docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md` | @1358e85 | 安全不变量（§17）、验证命令底线（§12）、PR 文案（§13）、Python 3.11/3.12 | normative | 最高优先级之一，冲突时停止 |
| DI-002 | Standard | `docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md` | @1358e85 | §8 Packet Gate 全清单、§9 Tests-Frozen Gate、§12 PR Contract、状态机 | normative | 同上 |
| DI-003 | Standard | `docs/LIMA_PACKET_AND_VERIFICATION_AGENT_RESPONSIBILITY_CHARTER.md` | @1358e85 | Packet 结构、RED/冻结/验证边界 | normative | 同上 |
| DI-004 | Issue | Issue #60 正文（含 V5 覆盖层与 Delivery Ledger） | 2026-09-12 API 快照；`Last verified main: 1358e85` | FR/NFR/AC/V5-* 范围与 Not-covered 划分 | normative（需求范围） | V5 覆盖层优先于 V4 正文；再与本 Packet 冲突时以 Packet 为准并上报（DI-001 §5） |
| DI-005 | Decision | Coordinator STATE60-1 裁定（Assignment `IP-0016-PV-P1/v1`） | 2026-09-12 | 本 IP 覆盖/不覆盖清单、worktree、阶段边界 | normative（执行授权） | 与 DI-004 冲突时以 Assignment 为准并提交 Decision Request |
| DI-006 | Upstream IP | `lima/contracts/profile.py`、`lima/contracts/common.py`、`lima/contracts/codec.py`、`lima/contracts/errors.py` | @7734e58（含于基线 1358e85） | 输出契约的全部字段/枚举/校验/编码语义 | normative（契约冻结） | 不可扩展、不可重定义；承载不了需求 → Contract Gap 停点 |
| DI-007 | Upstream IP | `schemas/v4/lima.repository-profile.json`、`tests/contracts/fixtures/repository_profile_v4_golden.json` | @7734e58 | wire 格式基准与 golden 基准 | normative（契约冻结） | 同 DI-006 |
| DI-008 | Checklist | `docs/LIMA_Issue_60_Coding_Agent_Kickoff_Checklist.md` | @1358e85（SHA-256 `1724b0221359584413e9a5612ac136cd09e6a3d187f49c717abb82d37919632a`） | §1 复用规则、§2 第一层范围、§3 边界 | normative | 与 DI-004 冲突时按事实优先级（DI-004/DI-005 优先）并记录 |
| DI-009 | Code | `lima/workspace.py`、`lima/python_dataflow.py`（+ `tests/test_workspace.py`、`tests/test_python_dataflow.py`） | @1358e85 | inventory 数据源 API 面（§0 亲验记录） | current-behavior | 代码说明"当前是什么"，不推翻本 Packet 目标行为 |
| DI-010 | Decision | PI-DR1..PI-DR5（Assignment §Authoritative Inputs 第 8 条） | 2026-09-12 | 逐断言自检、scratch GREEN 证明、验收命令 worktree 内执行、模块缺席 RED、PR 禁 close 关键字 | normative | 写入 §13/§14 |
| DI-011 | Code | `lima/semantic_retrieval.py` | @1358e85 | 仅背景（本 IP 不消费） | background-only | 不产生任何 Contract |

### Explicitly Rejected Inputs

- Issue #60 V4 正文中"输出 RAM / Top-N / execution_required 可被 Mining 消费"等表述——属后续 IP（DI-004 V5 覆盖层与 DI-005 划定的 Not covered），本 Packet 不据其设计任何 RAM 字段。
- 任何建议新增/修改 #58 契约字段的讨论性材料（含聊天记录）——违反 DI-006 冻结，一律拒绝。
- `lima/repository_scanner.py` 及 #68 集成方案——Issue 明确"当前 Issue 不修改"。
- #94 轨道全部路径与文档——并行轨道，文件不相交原则下拒绝引用。

## 2. Iteration Hypothesis 与 Measurement

- Hypothesis：在 #58 冻结契约之上，仅用 `RepositoryWorkspace` 的有界只读 inventory + 少量受控 `read_text`（manifest 文件），可以在不执行、不联网、不 import 目标包的前提下，为五类典型 repo 形态产出完整、可编码（envelope round-trip）、确定可重放的 `RepositoryProfile`，并把所有跳过/无法识别/预算不足表达为 typed coverage gap。
- Measurement：
  - 五类 fixture（application/library/CLI/docs/test-heavy）各产出 1 份 golden profile，SHA-256 digest 在两次独立构建间一致（确定性可重放）；
  - 跳过项 reason 100% 进入 `coverage_gaps`（无静默跳过）；
  - `tests/contracts` 回归保持 617 OK + 0 fail；
  - 全部输出 payload 中路径 100% repo-relative，host root 字符串零出现（负例断言）；
  - 恶意 setup.py fixture 构建前后副作用 marker 文件不存在（零执行证明）。

## 3. Goal

新增 `lima/audit/inventory.py`：一个确定性、只读、stdlib-only 的仓库清单适配器，输入 `RepositoryWorkspace`（已物化的快照目录），输出可直接经 `lima/contracts/profile.py` 编码的 `RepositoryProfile`，并支持构造满足 `encode_profile_envelope` 全部绑定校验的 `ArtifactEnvelope`。

## 4. Non-goals

- 不做 symbol/call graph、Source/Sink、trust boundary 内容抽取（五个 attack-surface 清单中，本 IP 只填 `entrypoints` 的清单层入口候选，`external_inputs`/`trust_boundaries`/`sensitive_operations`/`deployment_surface` 一律输出空元组——留给 RAM facts IP）。
- 不做语义排序、Top-N、LLM 参与。
- 不做 monorepo component graph（component_path 恒为 `None`；monorepo 仅作为 repository_kinds 分类结果出现）。
- 不做 docs/unsupported 的"安全停止"行为语义（只产出 support_level 与 gap）。
- 不接线 scanner/service/API/store/sandbox/frontend；不建 workflow/任务编排。
- 不修改 #58 任何契约、schema、fixture。

## 5. 决策 D1：模块落位与依赖方向（冻结单解）

```text
lima/audit/__init__.py      ← 仅 re-export 本 Packet 公共 API，禁止其他逻辑
lima/audit/inventory.py     ← 全部实现，仅依赖 stdlib + lima.contracts.{common,profile,codec,errors} + lima.workspace
依赖方向（冻结）：lima.audit.inventory → {lima.contracts.*, lima.workspace}
禁止：lima.audit 反向被 lima.contracts 引用；lima.audit 不 import lima.python_dataflow /
      semantic_retrieval / scanner / service / api / store（V5-FR-01：Profile 层零 RAM/语义依赖，
      阶段二以 import 面断言测试固化）
```

## 6. 决策 D2：公共 API 与 Symbol-to-File Map（冻结单解）

全部公共 symbol 落在 `lima/audit/inventory.py`，由 `lima/audit/__init__.py` re-export：

| Symbol | 形态 | 冻结语义 |
|---|---|---|
| `PROFILE_PROVENANCE_ANCHOR` | `Final[str] = "inventory"` | 本层全部 `source_artifact_ids` 的唯一取值（见 D3） |
| `GAP_UNSUPPORTED_LANGUAGE` | `Final[str] = "UNSUPPORTED_LANGUAGE"` | gap_code 常量 |
| `GAP_BUDGET_EXHAUSTED` | `Final[str] = "BUDGET_EXHAUSTED"` | 同上 |
| `GAP_MANIFEST_PARSE_ERROR` | `Final[str] = "MANIFEST_PARSE_ERROR"` | 同上 |
| `GAP_NO_LANGUAGES_DETECTED` | `Final[str] = "NO_LANGUAGES_DETECTED"` | 空仓库/纯不可识别内容时兜底 |
| `GAP_INVENTORY_SKIPPED` | `Final[str] = "INVENTORY_SKIPPED"` | 其余 workspace skip reason（symlink/binary/non-utf8/ignored-directory/sensitive-config/unreadable）的统一 gap_code（映射见 D6） |
| `SKIP_REASON_TO_GAP_DETAIL` | `Final[Mapping[str, str]]` | workspace `skipped` reason 词表 → gap detail 文案（冻结映射，见 D6） |
| `ProfileBudgets` | frozen dataclass | `manifest_max_bytes: int = 262_144`、`max_manifest_files: int = 64`；`__post_init__` 校验正值，非法抛 `ValueError` |
| `ProfileInventoryOptions` | frozen dataclass | `budgets: ProfileBudgets = ProfileBudgets()`、`schema_version: SchemaVersion = SchemaVersion(4, 0)` |
| `ProfileBuildResult` | frozen dataclass | `profile: RepositoryProfile`、`envelope: ArtifactEnvelope`、`provenance_anchor_ids: tuple[str, ...]` |
| `build_repository_profile` | `def build_repository_profile(workspace: RepositoryWorkspace, *, tenant_id: str, task_id: str, workflow_id: str, stage_attempt_id: str, artifact_id: str, repository_snapshot_digest: str, producer: str = "lima.audit.inventory", policy_digest: str = "", toolchain_digest: str = "", options: ProfileInventoryOptions \| None = None) -> ProfileBuildResult` | 唯一入口；语义见 D3–D8；任何入参类型不合法抛 `ContractError`/`ValueError`，绝不静默纠正 |
| `build_profile_envelope` | 内部函数（非 re-export，测试经 `build_repository_profile` 观察） | 组装 envelope 并过 `encode_profile_envelope` 全部校验 |

不新增其他公共 symbol；内部辅助函数前缀 `_`。`policy_digest`/`toolchain_digest` 允许空串（`ArtifactEnvelope` 校验语义允许，阶段二以契约测试固化空串路径）。

## 7. 决策 D3：证据与 Provenance 编码（冻结单解）

- `RepositoryProfile` 内一切 evidence-bearing 条目（languages/frameworks/package_managers/build_systems/code_roles/entrypoints）的 `source_artifact_ids` 恒为 `("inventory",)`（`_validated_identifier` 词形合法，且非空、排序要求平凡满足）。
- envelope 的 `lineage` 恰含一个 `ArtifactReference`，其 `artifact_id == "inventory"`，其余必填字段（artifact_type、created_at、digest 等）由实现按 `lima/contracts/common.py::ArtifactReference` 校验语义填充确定性值；`_require_source_lineage` 因此必然通过。
- rationale：本层尚无上游 artifact 可引用；引入更多 anchor 属契约语义扩张，拒绝。若 Coordinator 需要 per-manifest provenance，属后续 IP 的 Contract 变更，不在本 Packet。

## 8. 决策 D4：确定性清单识别规则（冻结单解；阈值与词表逐项钉死）

数据源两路，均只读：
1. `workspace.inventory()`（文本代码文件、大小、skip 计数）；
2. 受控 manifest 读取：候选集合 = 根目录及一级子目录下的 `pyproject.toml`、`setup.py`、`setup.cfg`、`requirements*.txt`、`environment.yml`、`package.json`、`go.mod`、`Cargo.toml`、`pom.xml`（存在性经 `workspace.absolute_file()` 边界校验后 `workspace.read_text()` 读取；单文件超过 `budgets.manifest_max_bytes` 或候选数超过 `max_manifest_files` → `GAP_BUDGET_EXHAUSTED`，不读该文件）。`setup.py` 只做 `ast.parse` 提取元数据，**绝不 exec/import**。

识别规则（全部规则只产生 `DetectionMethod.DECLARED`（来自 manifest）或 `INFERRED`（来自扩展名/路径），无其他来源）：

- **languages**：按 inventory 文件扩展聚合（`.py`→`Python`，`.js/.jsx/.ts/.tsx`→`JavaScript`/`TypeScript`，`.go`→`Go`，`.rs`→`Rust`，`.java`→`Java`，其他扩展不计）；manifest 声明的语言（pyproject `requires-python`、go.mod、Cargo.toml）以 DECLARED 加入。名称须过 `_TECHNOLOGY_NAME_PATTERN`。
- **frameworks**：仅从 manifest/源文件 import 行的确定性子串线索推断（INFERRED）：`fastapi`、`flask`、`django`、`pytest`（pytest 记 framework）、`react`（package.json dependencies）；词表冻结如上，命中才输出，不做任何网络探测（V5-FR-04）。
- **package_managers / build_systems**：`requirements*.txt`→`pip`；`pyproject.toml` 含 `[build-system]`→`build_systems` 增 `setuptools`/`hatchling`/`poetry-core`（按 `requires` 首个匹配，无匹配则不增）；`package.json`→`npm`；`go.mod`→`go-modules`；`Cargo.toml`→`cargo`。
- **repository_kinds**（可多值，按 wire 值排序）：`pyproject/setup` 含 `project.scripts` 或根目录 `cli.py`/`__main__.py` → `cli`；存在 `src/`+`pyproject` 且无 scripts → `library`；有 `app/`、`main.py`、wsgi/asgi 线索 → `application`；无任何代码语言但 `.md/.rst` 占多数 → `docs_content`；一级子目录 ≥2 个各自含独立 manifest → `monorepo`；以上全不命中 → `unknown`（且仅此一种情况允许 `unknown`，遵守"UNKNOWN 不得与其他 kind 并存"）。
- **entrypoints**：manifest `project.scripts` 每个入口一条（path 为 manifest 所在 package 的 `__init__.py` 或最接近候选，symbol=入口名）；无 manifest 时根 `main.py`/`cli.py`/`__main__.py` 各一条（symbol=None）。
- **execution_capability**（六布尔，全部由确定性规则给出，无默认猜值）：`buildable`=存在构建 manifest（pyproject[build-system]/setup.py/go.mod/Cargo/package.json）；`testable`=存在 tests/ 目录或 pytest 配置或 test-heavy kind；`requires_network`/`requires_services`/`requires_gpu`/`requires_external_credentials` 恒 `False`（清单层看不到运行时证据，宁可保守记 False 并由 gap 声明局限——False 表示"未发现证据要求"，不是安全结论）。
- **support_level**：`languages` 含 Python 且 manifest 可读 → `supported`；Python 但 manifest 缺失/损坏 → `partial`（+对应 gap）；无 Python 但有其他受支持语言线索 → `partial` + `UNSUPPORTED_LANGUAGE` gap（本平台当前 Golden Path 仅 Python）；完全无语言 → `unsupported` + `NO_LANGUAGES_DETECTED` gap。注意：`unsupported` 是支持承诺声明，不是"安全停止"行为（后者 V5-FR-03 归后续 IP）。
- **结构指标**：`file_count`/`total_bytes`/`max_file_bytes` 取自 inventory（inventoried 集合；`file_count==0 ⇒ total_bytes==0 ∧ max_file_bytes==0`，与 `__post_init__` 一致）；`code_density_bp` = 代码扩展文件字节 / inventoried 总字节 ×10000；`binary_ratio_bp` 由 `skipped["binary"]`/`non-utf8` 计数推导（`binary+non-utf8 跳过字节无记录 → 以计数比例近似并记录 gap？否——冻结：以 (binary+non_utf8 计数)/(discovered_files) 上取整 ×10000 封顶`）；`generated_ratio_bp` 由 `code_roles` 中 GENERATED 角色文件数占比。
- **确定性**：禁止读取 mtime/权限/随机源/环境变量；遍历顺序一律按路径排序；同一 workspace 快照 + 同一 options 两次构建的 `profile.to_dict()` 与 envelope `content_digest` 必须逐字节一致。

## 9. 决策 D5：code role 组合证据（V5-FR-02，冻结单解）

每条 `CodeRoleAssignment` 的 `reason_codes`（排序去重，词形 `[A-Z][A-Z0-9_]{0,63}`）必须来自至少两个独立证据类：

- 路径类：`PATH_TEST_DIR`（tests/testing 目录内）、`PATH_DOCS_DIR`、`PATH_EXAMPLE_DIR`、`PATH_PATTERN_GENERATED`（文件名匹配 `*.pb.py`、`*_pb2.py`、`.min.js`、`*_generated.py`）；
- manifest 类：`MANIFEST_TEST_CONFIG`（pytest/unittest 配置、tox/nox）、`MANIFEST_PACKAGES_EXCLUDED`（pyproject `tool.setuptools.packages.find.exclude` 命中）、`MANIFEST_BUILD_TARGET`（build 输出目录如 build/dist 命中 workspace 默认忽略表）；
- import/entry 类：`ENTRY_SCRIPT_DECLARED`（被 project.scripts 指向）、`NOT_IMPORTED_BY_PROD`（低置信，禁止单独定角色）。

冻结规则：GENERATED/TEST/DOCUMENTATION/EXAMPLE 角色至少需 1 个路径类 + 1 个非路径类 reason；单一证据只能产生保守分类（不输出该角色的 assignment，可留 gap 不要求）。`code_roles` 按 `(role.value, path)` 排序输出；cap 2048 超限时截断并追加 `GAP_BUDGET_EXHAUSTED`。

## 10. 决策 D6：coverage gap 词表与映射（FR-05 子集 + FR-01 跳过 reason，冻结单解）

- workspace `skipped` 计数非零的每个 reason 恰好生成一条 `ProfileCoverageGap`：`gap_code` 映射冻结——`file-limit`/`total-size-limit`/`file-size-limit` → `GAP_BUDGET_EXHAUSTED`；`unsupported-extension` 且仓库无任何受支持语言 → 归入 `UNSUPPORTED_LANGUAGE`（否则忽略该 reason，不产 gap）；其余 reason（`symlink`/`binary`/`non-utf8`/`ignored-directory`/`sensitive-config`/`unreadable`）→ `gap_code="INVENTORY_SKIPPED"`（新增常量 `GAP_INVENTORY_SKIPPED="INVENTORY_SKIPPED"`，加入 §D2 常量表）。`detail` = `"reason=<r>; count=<n>"`，≤4096 字节。
- manifest 读取/解析失败（OSError、TOML 语法错误、setup.py `ast.parse` SyntaxError）→ 每文件一条 `GAP_MANIFEST_PARSE_ERROR`，detail 含 repo-relative 文件名与异常类别（不含异常全文，避免泄漏路径/内容）。
- `coverage_gaps` 按 `(gap_code, detail bytes)` 排序；cap 256，超限截断并替换为单条 `GAP_BUDGET_EXHAUSTED`（detail 注明截断）。

## 11. 决策 D7：安全与权限契约（NFR-01/NFR-02/V5-FR-04，冻结单解）

- 模块顶层禁止 `import subprocess/socket/urllib/requests/http` 等；网络调用零；`setup.py` 仅 `ast.parse`；不 `importlib` 目标代码；不安装依赖（阶段二以 AST/静态断言 + 行为负例双证）。
- 所有进入 profile 的 path 一律 `workspace.inventory()` 的 repo-relative 路径或 manifest 相对路径；envelope/payload 序列化结果中不得出现 `str(workspace.root)`、绝对路径形态（`/`开头、盘符、`\\`）、任何文件内容正文、`.env`/secret 值。
- 错误语义 fail-closed：入参非法、路径逃逸、manifest 超预算 → 抛错或转 gap，绝不吞异常填默认值。
- 磁盘只读：除读取外无任何写操作（fixture 副作用 marker 负例证明）。

## 12. 文件边界（冻结单解）

### Files to Add（Implementation Agent 拥有，product allowlist，恰好 2 个）
- `lima/audit/__init__.py`
- `lima/audit/inventory.py`

### Test/Fixture Files（P&V 独占，阶段二创建，Implementation 禁改）
- `tests/audit/__init__.py`
- `tests/audit/test_profile_inventory.py`（识别/指标/确定性/gap）
- `tests/audit/test_profile_contract_encoding.py`（envelope 编码/round-trip/golden/schema）
- `tests/audit/test_profile_security.py`（不执行/不联网/路径/内容泄漏负例 + import 面断言）
- `tests/audit/fixtures/`（golden JSON 与共享 repo 形态 fixture 构造脚本；恶意样本仅此目录内由测试临时目录构建）

### Read-only Reference
- `lima/contracts/**`、`schemas/v4/**`、`tests/contracts/**`、`lima/workspace.py`、`lima/python_dataflow.py`、`lima/semantic_retrieval.py`、本 Packet。

### Files Forbidden
- `lima/` 下除 allowlist 2 文件外一切文件；`scanner/service/api/store/sandbox/frontend`；`.zcode/**`；#94 轨道路径（`lima/evidence_privacy/`、`scripts/audit_sensitive_artifacts.py`、`docs/LIMA_Issue_94_*`）；`docs/**`（本 Packet 阶段一已定稿）；`main` 分支。

### 冲突分析
与 IP-0015（#94 轨道）文件集完全不相交；与 #59/#92/#66/#71 并行轨道不相交；无共享可变文件。

## 13. 测试矩阵与 AC 追踪（类别与下限冻结；精确用例 ID/数量由阶段二 Frozen Test Commit 钉死）

| 矩阵类别（最低用例数） | 代表场景 | 断言要点（oracle/golden） | 追踪 |
|---|---|---|---|
| 形态识别（≥7） | application、library、CLI（project.scripts）、docs-only、test-heavy（tests 为主）、namespace package（PEP420 无 `__init__.py`）、单文件 | kinds/languages/support_level/execution_capability 与冻结规则逐字段一致；V5-T-01 profile 维度 | FR-01、V5-FR-02、V5-T-01 |
| 边界（≥6） | 空仓库、无 Python、隐藏文件、symlink、二进制、超预算（max_files=1 截断） | 对应 typed gap 恰好出现、detail 含 reason/count；profile 其余字段保守值 | FR-01、FR-05 子集、NFR-02 清单层 |
| manifest 层（≥3） | TOML 语法错误、setup.py 语法错误、manifest 超单文件预算 | `GAP_MANIFEST_PARSE_ERROR`/`GAP_BUDGET_EXHAUSTED`；不中断整体 profile 产出 | FR-05 子集 |
| code role 证据（≥3） | tests/ 目录+pytest 配置、`*_pb2.py`、build/ 输出 | 组合 reason_codes≥2；排序；单证据不定角色 | V5-FR-02 |
| 确定性（≥2） | 同一 fixture 两次构建；不同 mtime 不影响 | `to_dict()` 相等、content_digest 相等 | FR-01（确定性）、NFR-01 |
| 契约编码（≥3） | 小 fixture golden profile；envelope round-trip（encode→decode_profile_envelope 还原）；schema/v4 校验通过 | golden JSON 逐字节比对（P&V 生成并冻结 digest）；lineage/provenance/protected-classification 校验生效 | FR-01、V5-FR-01（Profile 先于 RAM：`lima.audit.inventory` import 面零 RAM/语义模块依赖，AST 断言） |
| 安全负例（≥4） | 恶意 setup.py（写 marker 文件副作用）、import side effect 模块、payload 全文搜索 host root/盘符/源码正文、模块静态断言（禁 subprocess/socket/urllib/importlib 目标导入） | marker 不存在；泄漏零命中；静态断言过 | NFR-01、NFR-02 清单层、V5-FR-04 |
| 回归 | `tests/contracts` 全量 + `tests.test_workspace` + `tests.test_python_dataflow` | 617+40 OK | Ledger contract 回归 gate |

AC traceability（正向+反向 100%）：FR-01→形态/边界/确定性/编码；FR-05 子集→边界+manifest；NFR-01→确定性+安全负例；NFR-02 清单层→安全负例+边界；V5-FR-01→编码（import 面断言）+API 返回 `RepositoryProfile`；V5-FR-02→code role 证据；V5-T-01 profile 维度→五类形态 fixture。每个测试 ID 反向唯一指向上述行——阶段二以 `test_file::test_symbol` 表格落档。

## 14. 阶段二执行计划（设计文本；本阶段不写测试文件）

1. 前置：Packet docs PR 合并进 `main`（Coordinator 标 `PACKET-MERGED`）。
2. 在 P&V integration branch（`codex/ip-0016-integration`）创建 §12 测试文件与 golden fixture（fixture 由临时 scratch 实现跑出 golden 前先在 scratch 目录（不入 commit）验证规则可实现且 GREEN 可达——PI-DR2）。
3. RED（PI-DR4 锚定）：在 `main`+Packet merge commit 上运行 `python -m unittest discover -s tests/audit -v`，预期全部用例以 `ModuleNotFoundError: No module named 'lima.audit'`（或 ImportError）失败；逐条核对失败原因均为模块缺席，无 arrange/环境/断言自伤（PI-DR1：逐断言与冻结文件交叉自检记录附于冻结 commit message/证据）。同时跑 baseline 命令记录 617 OK。
4. 测试质量门禁：`python -m compileall -q tests/audit`、`python -m ruff check tests/audit`。
5. 创建 Frozen Test Commit（仅 §12 测试/fixture 文件），记录 40 位 SHA、各文件 SHA-256、required test count。
6. 交 Coordinator 激活 Implementation Agent；验收命令一律在交付 worktree 内执行（PI-DR3）。

## 15. 验收命令（Done Commands，全部在交付 worktree 根执行；PI-DR3）

```powershell
# baseline（预期 617 OK）
python -m unittest discover -s tests/contracts -q
# slice（阶段二钉死精确计数；此处为下限预期：全部 PASS，0 skip）
python -m unittest discover -s tests/audit -v
# 回归（预期 40 OK）
python -m unittest tests.test_workspace tests.test_python_dataflow -v
# 兼容/全量回归（预期全绿，无新增 fail）
python -m unittest discover -s tests -q
# 质量/边界门禁
python -m compileall -q lima tests
python -m ruff check lima/audit tests/audit
python -m bandit -q lima/audit
git diff --check
git diff --name-only --diff-filter=ACMRTUXB   # 必须恰好 = §12 allowlist ∪ 阶段二测试集
```

判定依据：每条命令的预期输出如注；任一 fail/unexplained skip ⇒ 不得 PASS。post-merge：合并后在最新 `origin/main` 复跑 baseline+slice+回归三组，输出 `POST-MERGE PASS/FAIL`。

## 16. Stop Conditions / Decision Request

- #58 契约无法承载本 Packet 任一冻结规则（如字段 cap 与规则冲突）→ Contract Gap 报告停点，交 Coordinator/Maintainer；不得发明扩展字段。
- 与 #94 轨道出现文件冲突迹象 → 停止上报。
- 开工清单与 Issue 正文冲突且事实优先级无法唯一裁决 → Decision Request。
- 基线命令异常（contract tests 非 617 OK）→ 停止上报环境问题。
- 实现期发现需改冻结测试 → 先 Decision Request，授权后走 Packet 修订→重新 RED→重新冻结，禁止同提交悄悄修测试。
- Top-N 默认值/预算来源缺锚 → 不阻塞本 IP，仅记 Open Decisions 移交 semantic IP。

## 17. Completion Summary / PR Contract

Implementation Agent Completion Summary 至少含：base/final commit、修改文件与公共 symbol、AC→Test→Result 表（`test_file::test_symbol`）、§15 全部命令实测输出（含计数与退出码）、文件边界自查、安全/依赖/权限变化（应为零）、已知限制。Implementation PR（P&V 形成）：标题 `<type>: deterministic repository profile layer 1 (IP-0016)` 风格且**禁用 close/fix/resolve 关键字**（PI-DR5）；正文含 `Implements IP-0016`、`Related to #60`、Packet/merge commit、Frozen Test Commit 与实现 commit、covered/not-covered requirements、AC 矩阵、命令实测、Verdict、`This PR does not auto-close the Source Issue.`。

## 18. Packet 完成定义与 Open Decisions

- 本 Packet 关键 TBD 数 = 0，状态 `READY-FOR-CODE`（生效以 Packet docs PR 合并为前提）。
- Open Decisions（移交，不阻塞）：
  1. FR-04 Top-N 默认值与预算来源——owner: Coordinator（semantic IP 前锚定）；
  2. per-manifest provenance anchor（是否将 `"inventory"` 细化为逐 manifest artifact id）——属 #58 契约语义变更，需 Contract Gap 流程，本 Packet 显式不做。

## 19. Coding Agent 正式交接书（阶段二完成冻结后随 Assignment 生效；本节为契约文本）

- 交付对象：Implementation Agent（由 Coordinator 指派）；分支拓扑按 lifecycle §9.1（integration → Frozen Test Commit → implementation）。
- 交接内容清单：Packet 本文档（merge commit）、Frozen Test Commit（SHA+digests+required test count）、product allowlist = §12 恰好 2 文件、预期 RED 结果、§15 全部命令、§16 Stop Conditions、§17 模板。
- 硬性约束复述：只改 allowlist；不重设计公共 API；不新增依赖/网络/文件系统/凭据权限；冻结测试/fixture/Packet 只读；Contract 不足立即停止提 Decision Request；不碰 Issue/Ledger/PR/PROGRESS；完成后交 final commit + Completion Summary 给 P&V。
