# LIMA Implementation Packet IP-0003:Repository Profile / RAM Foundation

> Packet ID:`IP-0003`
>
> 状态:`DESIGN-FROZEN / READY-FOR-CODE WHEN THIS PACKET IS MERGED TO MAIN`
>
> Source Issue:[#58](https://github.com/agent-sec-labs/LIMA/issues/58) 的第三个独立实现切片(第二个 domain 切片)
>
> 最低代码基线:消费基线 `25f9aace3e8fe2349f50d8cb8710c79efebf58a4`(Assignment 指定);实现基线必须是包含本 Packet、正式交接书与恢复合并 `a0b3eeae303406698b849983117bb2b6db92eb3b`(IP-0001-R1 / PR #102)的最新 `origin/main`
>
> 推荐分支:`codex/ip-0003-repository-profile`
>
> Owner:唯一 Implementation Agent;不得与任何活动 IP 并行修改 `lima/contracts/` 或 `tests/contracts/`

## 需求映射(Header)

```text
Source Issue:#58
Issue specification revision:正文修订 2026-09-01T14:36:22Z(V4 基线 + V5 覆盖层,冲突以 V5 节为准);
  Delivery Ledger 更新至 2026-09-02T05:57:51Z(DECISION-DR-PMV-0001-01)
Covered requirements:FR-02 的 RAM/Repository Profile 子集;V5-FR-01 的 Profile 子集;
  支撑性覆盖:FR-05 的 RepositoryProfile fixture 子集、FR-06/NFR-01/NFR-02 对本 schema 的适用部分
Not covered requirements:FR-02 其余子集(AEP/VEP/RVR、Task/ToolBundle/Dependency/Sandbox manifests);
  V5-FR-01 其余子集(Workflow/StageAttempt/Outcome/Plan/RunManifest/Summary/Failure);
  V5-FR-02(IP-0002 已交付)、V5-FR-03/04/05;FR-01/FR-03/FR-04(IP-0001/IP-0002 已交付部分不再变更);
  AC-04 对新模块同样适用但 Issue 级聚合证据仍 PARTIAL
Delivery role:domain
Issue closure impact:PARTIAL(合并后不触发 #58 closure;#58 保持 open)
Upstream IP/PR/merge commits:
  IP-0001 Packet PR #97 `5cdf872` / Implementation PR #98 `d3e73d9`
  IP-0002 Packet PR #99 `f92122b` / Implementation PR #100 `4fe1def`
  IP-0001-R1 Recovery PR #102 `a0b3eea`(DECISION-DR-PMV-0001-01)
Activation gate:PMV-0001 两份 POST-MERGE PASS(IP-0001 v2、IP-0002 v2 @ `a0b3eea`,已满足)
```

---

## 0. 执行决策

当前执行队列(2026-09-02,DECISION-DR-PMV-0001-01 之后):

```text
DONE
IP-0001 Contract Foundation(+IP-0001-R1 hardening,POST-MERGE PASS v2)
IP-0002 Evidence Domain(POST-MERGE PASS v2;consumer review 由本 Packet §1 承接)

NOW(只允许 1 个)
IP-0003 Repository Profile / RAM Foundation(Design Frozen;文档合并后授权编码)

NEXT(不得实现)
IP-0004 Audit Evidence Package(AEP)Foundation — 依赖本 IP

LATER
VEP / RVR / Task/ToolBundle/Dependency/Sandbox manifests /
Workflow/StageAttempt/Outcome/Plan/RunManifest/Summary/Failure schemas /
JSON Schema + 兼容矩阵 + ADR(Issue PR3)/ legacy adapter fixture(Issue PR4)/ closure IP
```

本 Packet 只建立可被 #60(Classifier/RAM)、#64(Planner)、#68(Audit 集成)与 V5-N07(#96 Environment Plan)消费的确定性 `RepositoryProfile` Artifact 契约。它不实现分类器、inventory 工具、语言探测、RAM 图抽取或 component graph 算法,不改变任何现有生产行为。

---

## 1. IP-0002 消费者评审结论(lifecycle 入口 Gate,只读)

### 1.1 已验证事实

在 `main@a0b3eea`(IP-0001-R1 之后)上已验证(PMV-0001 v1/v2 + REC-IP-0001-R1,证据见 `.pv_tmp/PMV-0001_IP-000{1,2}_POST-MERGE*.md` 与 `REC-IP-0001-R1_DELIVERY.md`):

- `EvidenceDomainBundle` 的 16 个 public symbols、5 个 enum wire vocabulary 与 4 个 envelope binding 函数自 `4fe1def` 起在 main 上字节稳定;`lima.contracts.evidence.__all__` 恰好 16 项;
- golden fixture 3740 bytes / SHA-256 `1b313f8c…96c51` 在 main 上重放一致;`decode_evidence_envelope → encode_evidence_envelope` byte-stable;
- IP-0001 顶层 API(`__all__` = 18)与 `ContractErrorCode` = **29**(F-IP3-002:文档"28"为笔误,以 enum/catalog 为准)保持冻结;
- contracts 套件 84/84、全量 429 / 0 failed / 1 既有 Windows symlink skip;
- **对本 IP 的关键结论:`RepositoryProfile` 是 pre-Audit Artifact(由 Classifier/RAM 在 Evidence Domain 之前生成),其 schema 不需要、也不得 import `lima.contracts.evidence` 的任何类型**;跨 Artifact 事实一律通过 IP-0001 `ArtifactReference` + Envelope `lineage` 表达,与 IP-0002 的 `source_artifact_ids → lineage` 模式同构。

不存在阻塞 IP-0003 的 Contract Gap。IP-0002 满足其 IP-DONE 的消费者评审入口条件。

### 1.2 本 Packet 的兼容决策(冻结)

延续 IP-0002 §1.2 六项决策并针对 Profile 扩展,以下决定是本 Packet 的冻结 Contract:

1. 只新增 `lima/contracts/profile.py`,不修改 `lima/contracts/__init__.py`;公共 API 只从 `lima.contracts.profile` 导入;
2. `profile.py` 不 import `lima.contracts.evidence`;依赖方向固定为 `profile.py → {codec, common, errors}`,与 `evidence.py` 平行无交叉;
3. 复用现有 **29** 个 `ContractErrorCode`,不扩展 `errors.py`;
4. 复用 `ArtifactEnvelope` / `decode_envelope` / `encode_envelope`,不创建第二套 Envelope 或 codec;
5. Profile 只接受 inline payload;blob-backed Profile 留给 Artifact Registry IP;
6. schema 版本仍为 `4.0`;未知 major fail closed;同 major 未来 minor optional 字段经各对象 `extensions` 无损 round-trip;unknown enum / required 缺失永不降级;
7. 所有比例字段使用 basis points(有符号单位整数 0..10000),全 schema 无 float(v4.0 codec 契约);
8. path 校验语义与 IP-0002 `SourceLocation.path` 完全相同:repo-relative、NFC、1..1024 bytes、`/` 分隔、禁首 `/`、禁反斜杠/drive/UNC、禁空段/`.`/`..`、禁控制字符、**禁尾随 `/`**(目录前缀语义用无尾随斜杠的路径表达,如 `tests`);
9. schema name 固定 `lima.repository-profile`。

---

## 2. Design Input Manifest

| Input ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001 | Standard | `docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md` | main `a0b3eea` | 安全不变量、allowlist 纪律、实现规则、PR 底线命令 | normative | 最高优先级之一 |
| DI-002 | Standard | `docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md` | main `a0b3eea` | Packet Gate、两 PR 模型、禁 auto-close、§14 记录格式 | normative | — |
| DI-003 | Charter | `docs/LIMA_PACKET_AND_VERIFICATION_AGENT_RESPONSIBILITY_CHARTER.md` | main `a0b3eea` | Packet 必答清单、Design Input Manifest 结构、测试冻结纪律 | normative | — |
| DI-004 | Issue(Assignment) | PKT-IP-0003 Coordinator Assignment(2026-09-02 会话) | 引用 spec rev 2026-09-01T14:36:22Z;消费基线 `25f9aac` | 覆盖范围、明确不覆盖清单、激活 Gate、文件建议(`profile` 域模块 + `test_profile*`)、PARTIAL 定性 | normative | 与 Ledger 冲突时以 Assignment+Ledger 最新一致口径为准 |
| DI-005 | Issue | #58 正文(V4 基线 + V5 覆盖层) | 修订 `2026-09-01T14:36:22Z` | FR-02 Profile 子集;契约不变量节("RAM…只引用不可变 Artifact ID/digest"、Canonical JSON、兼容规则、资源上限);NFR-01/02 | normative | V5 节优先于 V4 节 |
| DI-006 | Issue(Ledger) | #58 Delivery Ledger | `2026-09-02T05:57:51Z` 裁决评论 | 队列(NOW/NEXT/LATER)、Gate、F-IP3-002(29 codes) | normative(current) | — |
| DI-007 | Decision | DECISION-DR-PMV-0001-01(#58 持久化评论) | `2026-09-02T05:57:50Z` | IP-0001-R1 授权、Gate 释放条件、29 错误码口径 | normative | — |
| DI-008 | Upstream IP | IP-0001 Packet(`docs/LIMA_Implementation_Packet_IP-0001_Contract_Foundation.md`) | PR #97 `5cdf872` / merge `d3e73d9` | codec/Envelope/错误目录/版本规则/资源上限的权威定义 | normative | — |
| DI-009 | Upstream IP | IP-0002 Packet(`…IP-0002_Evidence_Domain.md`) | PR #99 `f92122b` / merge `4fe1def` | §1.2 六项兼容决策、§15 Envelope binding 模式、§16 错误优先级、§17 golden 方法论、§18 测试结构 | normative | — |
| DI-010 | Architecture | `docs/LIMA_V5_真实测试驱动的通用全链路实施重基线与Issue闭环规划.md` §3.1、§3.2、§5.2、§14.4 | 本地工作树副本(#58 指定 Source of truth) | RepositoryProfile 字段清单、kind 多值语义、code roles、execution capability、support level、component 多 profile 约束 | normative(经 #58 V5 覆盖层转正) | 与 #58 正文冲突以 #58 为准 |
| DI-011 | Issue | #60 正文(V4 + V5 覆盖层) | `2026-09-01T05:37:31Z` | 消费者需求输入:code roles 组合证据、execution capability、coverage gap、monorepo component(只约束 schema 表达能力,不实现) | background-only | 不从 #60 扩大实现范围 |
| DI-012 | Code | `lima/contracts/{common,codec,errors,evidence}.py` | main `a0b3eea` | 当前真实 API、validator 实现风格、path/text/enum 处理复用 | current-behavior | 代码事实让位于 Packet 目标行为 |
| DI-013 | Test | `tests/contracts/test_*.py` | main `a0b3eea` | 测试风格、命名、断言模式、84 基线 | current-behavior | — |
| DI-014 | Evidence(Finding) | PMV-0001 v1/v2 记录、REC-IP-0001-R1 交付记录 | 2026-09-02,`.pv_tmp/` | 基线数字(84/429/1 skip)、29 codes、Gate 满足证明 | evidence | — |
| DI-015 | Finding | F-IP2-003(`rule_id` charset)、F-IP2-004(`.gitattributes`) | PR #100 记录 | 本 IP technology name charset 设计输入(含 `+`/`-`);`.gitattributes` 不适用于本 IP(fixture 为 LF 单行) | background-only | 维护者级决策不自行扩大 |

### Explicitly Rejected Inputs

| 材料 | 拒绝原因 |
|---|---|
| V4 backlog 文档中 RAM/AEP/VEP/RVR 一揽子 schema 设计(`LIMA_V4_多人协作需求拆分与Issue_Backlog.md`、`LIMA_V4_Issue代码级实施约束与测试矩阵.md`) | 被 #58 V5 覆盖层与 Assignment 边界取代;AEP/VEP/RVR/manifests 不在本 IP |
| V5 规划文档 §4 Workflow Mode/状态机与 §7-9 Mining/Repair 细节 | 属 V5-FR-01 其余子集与未来 IP;仅 §3/§5/§14.4 被 DI-010 采用 |
| "28 个错误码"口径(IP-0002 Packet §1.1、部分 PR 文案) | F-IP3-002 判定为 off-by-one 笔误;机器验证 29 |
| `lima/workspace.py`、`python_dataflow.py`、`semantic_retrieval.py` 接口细节 | #60 的实现输入;本 IP 只交付 schema,不消费这些模块 |
| 根工作树未跟踪的其余本地规划文档(`LIMA_可信审计挖掘修复闭环_迭代规划.md` 等) | 未被 Assignment 引用;background-only,不进入 Contract |
| PR #98 正文中不可复现的 ruff exit 0 记录 | 证据不可复现(PMV-0001 v1);以机器复验为准 |
| 任何 float 比例、字符串百分比、自动补全默认值的字段方案 | 违反 v4.0 无 float 契约与"禁止默认值伪装"不变量 |

---

## 3. Iteration Hypothesis 与 Measurement

### 3.1 Hypothesis

如果 Repository Profile 的分类结果(kind、语言/框架、code roles、attack surface、execution capability、support level)被冻结为一个确定性、无副作用、逐项可溯源(source artifact lineage)的版本化 Artifact 契约,那么 #60 的 Classifier/RAM、#64 的 Planner、#68 的 Audit 集成与 V5-N07 的 Environment Plan Resolver 可以只依赖 fixture 并行开发,并且"docs 仓库被制造固定复核""unsupported 语言输出未发现漏洞"这类通用性事故在契约层就有唯一表达(kind=docs_content、support_level=unsupported + coverage_gaps),而不是散落在各消费者里的 if 分支。

### 3.2 Measurement

- 固定 golden profile 生成固定 canonical bytes(2152 bytes)与固定 SHA-256(`ad7d53a0…c4dccc`);
- 输入数组顺序、Unicode 表示或构造后外部 mutation 不产生隐式语义漂移;
- 缺 required、未知 enum、非法 path/标识符/比例范围、kinds 与 languages 矛盾、metrics 矛盾、悬空 source_artifact_ids、public/ephemeral Envelope 全部 fail closed;
- 空 surface / 空 languages(docs 类)合法且不编码任何安全结论;
- 新模块导入不加载 DB、网络、Docker、LLM、service、scanner、legacy models,也不加载 `lima.contracts.evidence`;
- 既有 429 个测试无新增失败。

---

## 4. Goal

实现一个 stdlib-only、无副作用、确定性、可版本演化的 `lima.contracts.profile` 叶子模块,包含:

1. 分类枚举 `RepositoryKind`(7 值,多 kind 合法)、`CodeRole`(8 值)、`SupportLevel`(3 值)、`DetectionMethod`(2 值);
2. `ExecutionCapability`:恰好 6 个 required bool(buildable/testable/requires_network/requires_services/requires_gpu/requires_external_credentials);
3. `TechnologyDeclaration`:languages/frameworks/package_managers/build_systems 条目(name + declared|inferred + ≥1 source artifact);
4. `CodeRoleAssignment`:role + path(文件或目录前缀)+ 组合证据 reason codes + provenance;
5. `AttackSurfaceEntry`:entrypoints/external_inputs/trust_boundaries/sensitive_operations/deployment_surface 五类清单条目(path + symbol? + reason codes + provenance);
6. `ProfileCoverageGap`:机器可读 gap_code + detail;
7. 结构指标:file_count/total_bytes/max_file_bytes + code_density_bp/binary_ratio_bp/generated_ratio_bp(basis points);
8. `RepositoryProfile`:单 payload 全图校验(排序唯一、kind 语义、metrics 一致性、extensions 版本规则)+ `component_path`(null=整仓,路径=组件作用域,支撑 monorepo 多 profile);
9. Profile payload 与 IP-0001 `ArtifactEnvelope` 的 encode/decode binding(schema name、inline-only、lineage、classification/retention、digest);
10. golden fixture、负向边界测试、import isolation 与 legacy regression。

完成后,下游可以统一区分:

```text
repository_kinds        = 这个仓库(或组件)是什么形态(可多值)
languages/frameworks/…  = 用什么技术构建,每项声明 detected 方式与证据
code_roles              = 哪些路径是什么角色(生产/测试/生成/第三方…)
attack surface 五清单    = 入口、外部输入、信任边界、敏感操作、部署面在哪
execution_capability    = 能否构建/测试,需要什么环境
support_level           = 平台对它的支持承诺(SUPPORTED/PARTIAL/UNSUPPORTED)
coverage_gaps           = 本 profile 哪里没看清(gap_code + detail)
```

---

## 5. Non-goals

本次明确不做:

- 不实现 Classifier、inventory、语言/框架探测、code-role 判定或任何启发式(#60);
- 不实现 RAM 图、entrypoint/数据流抽取、component graph 计算(#60;component 仅以 `component_path` 表达作用域);
- 不生成 ID、digest、时间或随机数;`file_count` 等指标由调用方显式传入;
- 不实现 AEP、VEP、RVR、TaskManifest、ToolBundleManifest、DependencySnapshot、SandboxRunManifest schema;
- 不实现 Workflow、StageAttempt、SecurityOutcome、MiningPlan、RunManifest、Summary、Failure schema(V5-FR-01 其余子集);
- 不实现 JSON Schema 文件、版本兼容矩阵 artifact 或 ADR(Issue PR3 类未来 IP);
- 不修改或适配 legacy `Finding`/`EvidenceRecord`/`ReviewReport`,不接 API/Service/Store/Queue/Scanner/Sandbox/Registry/Frontend;
- 不调用 LLM,不访问网络/文件系统/环境变量,不执行目标仓库代码或 setup hook;
- 不引入 severity、confidence、risk score、trust score 或任何安全结论字段;
- 不修改 `lima/contracts/__init__.py`、`evidence.py`、`common.py`、`codec.py`、`errors.py` 或任何既有测试;
- 不实现 IP-0004(AEP)或任何顺手重构。

---

## 6. 工作树与分支前置条件

Coding Agent 必须:

1. 完整阅读稳定标准、本 Packet、`LIMA_Coding_Agent_IP-0003_正式开发任务交接.md` 和 `CONTRIBUTING.md`;
2. 确认两份 IP-0003 文档均已合并到 `origin/main`,且 base 包含 `a0b3eeae303406698b849983117bb2b6db92eb3b`(IP-0001-R1);
3. 确认 `lima/contracts/profile.py` 与本 Packet 的 3 个测试文件、1 个 fixture 尚不存在;
4. 从最新 `origin/main` 建立独立干净 worktree 与 `codex/ip-0003-repository-profile` 分支;
5. 先输出 Scope Confirmation,再运行 baseline(§21.1);
6. baseline 或代码事实与本文不一致时停止并提交 Decision Request。

根工作树中的未跟踪规划文档属于用户资产,不得移动、删除、stash、覆盖或纳入实现 PR。

---

## 7. 文件边界

### 7.1 Files to Add(恰好 5 个)

```text
lima/contracts/profile.py
tests/contracts/test_profile.py
tests/contracts/test_profile_envelope.py
tests/contracts/test_profile_import_isolation.py
tests/contracts/fixtures/repository_profile_v4_golden.json
```

### 7.2 Files Allowed to Modify

```text
none
```

### 7.3 Files Forbidden

除上述 5 个新增文件外全部禁止修改,特别包括:

```text
lima/contracts/__init__.py
lima/contracts/evidence.py
lima/contracts/common.py
lima/contracts/codec.py
lima/contracts/errors.py
tests/contracts/test_evidence.py
tests/contracts/test_evidence_envelope.py
tests/contracts/test_evidence_import_isolation.py
tests/contracts/test_common.py
tests/contracts/test_codec.py
tests/contracts/test_errors.py
tests/contracts/test_import_isolation.py
tests/contracts/fixtures/evidence_domain_bundle_v4_golden.json
tests/contracts/fixtures/artifact_envelope_v4_golden.json
lima/models.py
lima/workspace.py
lima/python_dataflow.py
lima/semantic_retrieval.py
lima/repository_scanner.py
lima/service.py
lima/api.py
lima/store.py
lima/postgres_store.py
lima/task_queue.py
frontend/
requirements*.txt
pyproject.toml
.github/
PROGRESS.md
```

若实现需要修改任一 forbidden 文件,必须停止;不能通过扩大 allowlist、复制 IP-0001/0002 类型或放宽测试继续。

### 7.4 Ownership 与冲突边界

- `lima/contracts/profile.py` 在本 Packet 期间只有一个 Owner;
- IP-0004 及后续 IP 不得在本 Packet 合并前创建同名 symbol(`RepositoryProfile`、`RepositoryKind` 等 15 个);
- 新公共 symbol 不从 `lima.contracts` 顶层重导出;下游必须 `from lima.contracts.profile import ...`;
- `profile.py` 与 `evidence.py` 是平行叶子模块,互不 import;未来聚合导出必须使用独立 Packet。

---

## 8. Allowed / Forbidden Dependencies

### 8.1 Allowed

`profile.py` 只允许导入:

```text
collections.abc.Mapping
copy
dataclasses
enum
hmac
re
typing
unicodedata

lima.contracts.codec
lima.contracts.common
lima.contracts.errors
```

测试只允许额外使用 stdlib:

```text
hashlib
pathlib
subprocess
sys
unittest
```

### 8.2 Forbidden

- 任何新增第三方包;
- `lima.contracts.evidence`、`lima.models`、audit/service/store/queue/scanner/sandbox/runtime/agent 模块;
- HTTP、socket、数据库、Docker SDK、subprocess(产品模块)、文件系统读取(产品模块);
- UUID、当前时间、随机数、环境变量;
- Pydantic/Marshmallow/JSON Schema 第三方实现;
- 绝对路径、host path 或 repository 内容读取。

`profile.py` 必须保持纯内存 leaf module。

---

## 9. 冻结的公共 Symbols

`lima/contracts/profile.py` 的 `__all__` 必须严格等于以下集合,不多不少(15 项):

```python
__all__ = [
    "REPOSITORY_PROFILE_SCHEMA_NAME",
    "RepositoryKind",
    "CodeRole",
    "SupportLevel",
    "DetectionMethod",
    "ExecutionCapability",
    "TechnologyDeclaration",
    "CodeRoleAssignment",
    "AttackSurfaceEntry",
    "ProfileCoverageGap",
    "RepositoryProfile",
    "decode_profile_payload",
    "encode_profile_payload",
    "decode_profile_envelope",
    "encode_profile_envelope",
]
```

模块常量:

```python
REPOSITORY_PROFILE_SCHEMA_NAME = "lima.repository-profile"
```

不允许额外公开 helper、alias、factory、builder 或第二套异常类型。内部校验函数使用前导下划线。

---

## 10. 冻结枚举

所有枚举均使用 `class X(str, Enum)`(允许 `# noqa: UP042` 注释,与 `evidence.py` 一致),wire value 大小写严格固定:

```python
class RepositoryKind(str, Enum):
    APPLICATION = "application"
    LIBRARY = "library"
    CLI = "cli"
    DOCS_CONTENT = "docs_content"
    MONOREPO = "monorepo"
    DATASET_ASSET = "dataset_asset"
    UNKNOWN = "unknown"

class CodeRole(str, Enum):
    PRODUCTION = "production"
    TEST = "test"
    EXAMPLE = "example"
    DEV_TOOL = "dev_tool"
    GENERATED = "generated"
    VENDORED = "vendored"
    CONFIG = "config"
    DOCUMENTATION = "documentation"

class SupportLevel(str, Enum):
    SUPPORTED = "supported"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"

class DetectionMethod(str, Enum):
    DECLARED = "declared"
    INFERRED = "inferred"
```

语义冻结:

- `repository_kinds` 是多值集合:仓库可同时是 `[monorepo, cli, library]`;
- `unknown` 只能单独出现,不得与其他 kind 组合(§14.1);
- `support_level` 是平台支持承诺,不是仓库属性,也不是安全结论;`UNSUPPORTED` 必须伴随 coverage gap 由生产者表达(本 Contract 校验排序/唯一,不强制该耦合,见 §14.5);
- `detection`:`declared` = 来自 manifest/lockfile/config 等声明性证据;`inferred` = 启发式推断;两者都必须携带 ≥1 `source_artifact_ids`。

---

## 11. Exact Constructors and Defaults

全部领域对象必须是 `@dataclass(frozen=True, slots=True)`,必须 defensive-copy 所有可变输入。字段顺序固定如下(required 无默认值的字段在前,集合字段默认 `()` 或 `None`,与 IP-0002 风格一致):

### 11.1 `ExecutionCapability`

```python
ExecutionCapability(
    buildable: bool,
    testable: bool,
    requires_network: bool,
    requires_services: bool,
    requires_gpu: bool,
    requires_external_credentials: bool,
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

六个 bool 全部 required、wire 必填;必须用 `type(x) is bool` 精确校验(拒绝 `0/1/None/"true"`)。

### 11.2 `TechnologyDeclaration`

```python
TechnologyDeclaration(
    name: str,
    detection: DetectionMethod,
    source_artifact_ids: tuple[str, ...],
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

### 11.3 `CodeRoleAssignment`

```python
CodeRoleAssignment(
    role: CodeRole,
    path: str,
    reason_codes: tuple[str, ...],
    source_artifact_ids: tuple[str, ...],
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

`path` 可以是文件路径或目录前缀(无尾随 `/`);role 对该 path 及其子树的适用语义由消费者定义。

### 11.4 `AttackSurfaceEntry`

```python
AttackSurfaceEntry(
    path: str,
    reason_codes: tuple[str, ...],
    source_artifact_ids: tuple[str, ...],
    symbol: str | None = None,
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

### 11.5 `ProfileCoverageGap`

```python
ProfileCoverageGap(
    gap_code: str,
    detail: str,
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

### 11.6 `RepositoryProfile`

```python
RepositoryProfile(
    schema_version: SchemaVersion,
    repository_kinds: tuple[RepositoryKind, ...],
    execution_capability: ExecutionCapability,
    support_level: SupportLevel,
    component_path: str | None,
    file_count: int,
    total_bytes: int,
    max_file_bytes: int,
    code_density_bp: int,
    binary_ratio_bp: int,
    generated_ratio_bp: int,
    languages: tuple[TechnologyDeclaration, ...] = (),
    frameworks: tuple[TechnologyDeclaration, ...] = (),
    package_managers: tuple[TechnologyDeclaration, ...] = (),
    build_systems: tuple[TechnologyDeclaration, ...] = (),
    code_roles: tuple[CodeRoleAssignment, ...] = (),
    entrypoints: tuple[AttackSurfaceEntry, ...] = (),
    external_inputs: tuple[AttackSurfaceEntry, ...] = (),
    trust_boundaries: tuple[AttackSurfaceEntry, ...] = (),
    sensitive_operations: tuple[AttackSurfaceEntry, ...] = (),
    deployment_surface: tuple[AttackSurfaceEntry, ...] = (),
    coverage_gaps: tuple[ProfileCoverageGap, ...] = (),
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

`schema_version` 是 Envelope context,不进入 payload wire。所有 tuple 字段构造后必须真实存储为 tuple;dict/nested 对象必须 defensive-copy。

### 11.7 Frozen serialization methods

六个 dataclass 都必须提供 deterministic `to_dict()`;五个 nested object 与 `RepositoryProfile` 必须提供:

```python
@classmethod
def from_dict(
    cls,
    value: Mapping[str, JSONValue],
    *,
    schema_version: SchemaVersion,
) -> Self: ...

def to_dict(self) -> dict[str, JSONValue]: ...
```

`Self` 表示对应具体 class 的返回类型;注解写法必须 Python 3.11/3.12 兼容,不引入 typing extension。`from_dict` 负责 required/unknown/type/enum/extension 校验;`RepositoryProfile.from_dict` 还必须执行 §14 全图校验;`decode_profile_payload` 只是稳定公共入口,不得形成第二套解析逻辑。

---

## 12. Exact Wire Shapes

### 12.1 Top-level payload

4.0 的 required fields 恰好为以下 21 个(全部必填;数组可为空):

```json
{
  "repository_kinds": ["application", "cli"],
  "languages": [],
  "frameworks": [],
  "package_managers": [],
  "build_systems": [],
  "code_roles": [],
  "entrypoints": [],
  "external_inputs": [],
  "trust_boundaries": [],
  "sensitive_operations": [],
  "deployment_surface": [],
  "execution_capability": {},
  "support_level": "supported",
  "component_path": null,
  "file_count": 0,
  "total_bytes": 0,
  "max_file_bytes": 0,
  "code_density_bp": 0,
  "binary_ratio_bp": 0,
  "generated_ratio_bp": 0,
  "coverage_gaps": []
}
```

空数组合法,只表示"该清单没有条目",不表示仓库安全、分析完整或 `NO_SUPPORTED_ATTACK_SURFACE`;安全/覆盖结论由未来 AEP/Workflow Artifact 结合 coverage 产生。4.0 不允许其他字段。`component_path` 为 `null`(整仓)或 repo-relative 路径(组件作用域);monorepo 的多个 component profile 是多个独立 Artifact,共享同一 snapshot digest(Envelope 层约束)。

### 12.2 `TechnologyDeclaration`

```json
{
  "name": "python",
  "detection": "declared",
  "source_artifact_ids": ["tool-run-0001"]
}
```

### 12.3 `CodeRoleAssignment`

```json
{
  "role": "production",
  "path": "src/cli.py",
  "reason_codes": ["PATH_PATTERN_SRC"],
  "source_artifact_ids": ["tool-run-0001"]
}
```

`reason_codes` 表达 #60 V5-FR-02 要求的"路径、manifest、import/build/test 配置的组合证据"的机器可读形式。

### 12.4 `AttackSurfaceEntry`

```json
{
  "path": "src/cli.py",
  "reason_codes": ["CLI_ENTRY_SCRIPT"],
  "source_artifact_ids": ["tool-run-0001"],
  "symbol": "main"
}
```

`symbol` required-but-nullable:未知时用 JSON `null`,不得省略、不得用空字符串。五类清单(entrypoints、external_inputs、trust_boundaries、sensitive_operations、deployment_surface)共用该 shape。

### 12.5 `ExecutionCapability`

```json
{
  "buildable": true,
  "testable": true,
  "requires_network": false,
  "requires_services": false,
  "requires_gpu": false,
  "requires_external_credentials": false
}
```

六个字段全部 required,无默认值语义(V5:"禁止用默认值伪装成已识别事实")。

### 12.6 `ProfileCoverageGap`

```json
{
  "gap_code": "FRAMEWORK_DETECTION_PARTIAL",
  "detail": "Dynamic framework imports were not resolved."
}
```

### 12.7 Extensions

- 4.0:任何层级出现 unknown field 都以 `UNKNOWN_FIELD` 拒绝;
- 未来 4.x:unknown optional field 必须原位置无损保存在对应对象的 `extensions`,并 round-trip;
- extension key 与 known field NFC 归一后冲突时 `DUPLICATE_SEMANTIC_FIELD`;
- required 字段即使未来 minor 也不能缺失;unknown enum 即使未来 minor 也 fail closed。

---

## 13. Scalar Validation

### 13.1 Technology name

`TechnologyDeclaration.name` 与所有 `source_artifact_ids` 成员:

- name:exact `str`,NFC 后完整匹配 `[A-Za-z0-9][A-Za-z0-9._:+/-]{0,127}`(含 `+`(c++)、`-`、`.`、`:`、`_`;`#` 类名称必须由生产者转写为 ASCII 别名如 `csharp`),最多 128 UTF-8 bytes;
- `source_artifact_ids` 成员:IP-0002 identifier 规则 `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`;
- 不自动 lower-case、不自动 trim;非 canonical 输入直接拒绝。

### 13.2 Reason code / gap code

- `[A-Z][A-Z0-9_]{0,63}`,NFC;
- `reason_codes` 对 CodeRoleAssignment 与 AttackSurfaceEntry 均至少 1 项;ASCII 升序、唯一;
- code 是机器解释,不得把路径、secret、仓库名或自然语言塞入。

### 13.3 Bounded text

`AttackSurfaceEntry.symbol`(非 null 时)与 `ProfileCoverageGap.detail`:

- exact `str`,NFC,非空;
- 禁止 Unicode category `Cc`;
- 不自动 strip;前导/尾随空白非法;
- `symbol` ≤ 512 UTF-8 bytes;`detail` ≤ 4096 UTF-8 bytes;
- error message 不回显原值。

### 13.4 Repository-relative path

`component_path`(非 null 时)、`CodeRoleAssignment.path`、`AttackSurfaceEntry.path` 与 IP-0002 `SourceLocation.path` 完全相同的规则:exact `str`、NFC、1..1024 bytes、必须 `/` 分隔、禁首 `/`、禁 Windows drive/UNC、禁反斜杠、禁空段/`.`/`..`、禁控制字符、**禁尾随 `/`**、不访问文件系统、不自动 resolve。空字符串非法(`component_path` 用 `null` 表达整仓)。

### 13.5 Metrics

`file_count`、`total_bytes`、`max_file_bytes`:exact int(拒绝 bool),`0..9223372036854775807`。
`code_density_bp`、`binary_ratio_bp`、`generated_ratio_bp`:exact int(拒绝 bool),`0..10000`(basis points,1 bp = 0.01%)。

### 13.6 Bool

`ExecutionCapability` 六字段:exact `type(x) is bool`,拒绝 int/None/str。

---

## 14. Array Limits,Canonical Ordering 与 Cross-field Invariants

### 14.1 数组上限与排序

| Array | 上限 | 允许空 | 排序规则 |
|---|---:|---:|---|
| `repository_kinds` | 8 | 否(≥1) | wire value ASCII 升序、唯一 |
| `languages` | 64 | 是 | `name` ASCII 升序、唯一 |
| `frameworks` | 64 | 是 | `name` ASCII 升序、唯一 |
| `package_managers` | 32 | 是 | `name` ASCII 升序、唯一 |
| `build_systems` | 32 | 是 | `name` ASCII 升序、唯一 |
| `code_roles` | 2048 | 是 | `(role wire value, path)` ASCII 升序;对唯一 |
| `entrypoints` | 256 | 是 | `(path, symbol or "")` ASCII 升序;对唯一 |
| `external_inputs` | 256 | 是 | 同上 |
| `trust_boundaries` | 256 | 是 | 同上 |
| `sensitive_operations` | 256 | 是 | 同上 |
| `deployment_surface` | 256 | 是 | 同上 |
| 每个 `source_artifact_ids` | 32 | 否(≥1) | ASCII 升序、唯一 |
| 每个 `reason_codes` | 64 | 否(≥1) | ASCII 升序、唯一 |
| `coverage_gaps` | 256 | 是 | `(gap_code, detail 的 UTF-8 bytes)` 升序;对唯一 |

Contract 不隐式排序;未按规定排序/含重复的输入以 `INVALID_FIELD_VALUE` 拒绝(重复 kind 用同 code);超上限用 `MAX_ARRAY_LENGTH_EXCEEDED`。surface 数组统一 256 上限的依据:inline payload 受 `max_input_bytes`(默认 1 MiB)约束;超限清单必须由生产者转为 coverage gap,不得静默截断(与 V5 §3.2 预算哲学一致)。

### 14.2 Kind 语义约束

1. `repository_kinds` 至少 1 项;
2. `unknown` 不得与任何其他 kind 同时出现(`INVALID_FIELD_VALUE`,`$.repository_kinds[i]`);
3. 若 kinds 包含 `application`、`library`、`cli`、`monorepo` 任意之一,则 `languages` 必须非空(`INVALID_FIELD_VALUE`,`$.languages`)——代码形态仓库不可能零语言;`docs_content`/`dataset_asset`/纯 `unknown` 允许空 languages。

### 14.3 Metrics 一致性

1. `max_file_bytes <= total_bytes`(`$.max_file_bytes`);
2. `file_count == 0` 时 `total_bytes == 0` 且 `max_file_bytes == 0`(`$.total_bytes` / `$.max_file_bytes`);
3. 三个 `*_bp` 与三个计量字段的组合不强制其他耦合(如 code_density 与 languages 的关系由生产者语义决定)。

### 14.4 Provenance

所有 `TechnologyDeclaration`、`CodeRoleAssignment`、`AttackSurfaceEntry` 的 `source_artifact_ids` 至少 1 项;Envelope binding(§15)要求它们全部存在于 lineage。无 provenance 的分类声明被拒绝(fail closed,禁止默认值伪装)。

### 14.5 不做的耦合(明确豁免)

- `support_level == "unsupported"` 不强制 coverage_gaps 非空:平台耦合语义属生产者(#60)策略,Contract 只保证两者可独立表达且均被完整校验;
- `component_path` 不强制 kinds 包含 `monorepo`:组件作用域允许用于任何仓库形态;
- code_roles 与 surface 数组之间不做路径包含性校验:清单间一致性由生产者与消费者(#60/#64)负责,Contract 不越权实现分类算法。

---

## 15. Envelope Binding Contract

### 15.1 Function signatures

```python
def decode_profile_payload(
    value: Mapping[str, JSONValue],
    *,
    schema_version: SchemaVersion,
) -> RepositoryProfile: ...

def encode_profile_payload(
    profile: RepositoryProfile,
) -> dict[str, JSONValue]: ...

def decode_profile_envelope(
    data: bytes,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> tuple[ArtifactEnvelope, RepositoryProfile]: ...

def encode_profile_envelope(
    envelope: ArtifactEnvelope,
    profile: RepositoryProfile,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> bytes: ...
```

### 15.2 Binding rules

`decode_profile_envelope` 必须:

1. 调用 IP-0001 `decode_envelope`;
2. 要求 `schema_name == REPOSITORY_PROFILE_SCHEMA_NAME`;
3. 要求 inline `payload`,拒绝 blob-backed envelope;
4. 以 envelope `schema_version` decode profile;
5. 要求全部 `source_artifact_ids`(technology/code-role/attack-surface 条目)存在于 envelope `lineage.artifact_id`;缺失用 `INVALID_FIELD_VALUE`,路径 `$.payload.<array>[i].source_artifact_ids[j]`;
6. 允许 lineage 包含额外上游 Artifact;
7. 要求 classification 不是 `public`;
8. 要求 retention 不是 `ephemeral`;
9. 返回 `(envelope, profile)`,不得修改输入。

`encode_profile_envelope` 必须执行相同 binding,并额外要求:

- `envelope.schema_version == profile.schema_version`;
- `envelope.payload == encode_profile_payload(profile)`;
- `compute_content_digest(profile payload)` 与 `envelope.content_digest` 用 `hmac.compare_digest` 相等;
- 最终调用 IP-0001 `encode_envelope`;
- 不自动创建、替换或修补 Envelope。

### 15.3 Classification / retention

- allowed classification:`internal`、`sensitive`、`restricted`;forbidden:`public`;
- allowed retention:`standard`、`audit`、`legal_hold`;forbidden:`ephemeral`;
- 不匹配用 `INVALID_FIELD_VALUE`,`field_path` 分别为 `$.classification` / `$.retention_class`。

Profile 携带仓库结构、入口与部署面等侦察敏感元数据,不得公开传输;作为下游规划输入须可审计,不得临时丢弃。

### 15.4 Lineage

- `source_artifact_ids` 只保存 logical artifact ID;tenant、snapshot、schema 与 content digest 由 Envelope lineage `ArtifactReference` 提供;
- IP-0001 已拒绝跨 tenant、跨 snapshot、自引用、重复与冲突 lineage,本模块不复制这些判断;
- raw inventory 输出、LLM response、日志或代码片段不得内联为 Profile 字段。

---

## 16. Stable Error Mapping and Precedence

IP-0003 不新增错误码。所有失败使用现有 `ContractError`(**29** 个 code 之一),message 由 IP-0001 catalog 决定且不得回显输入。

| 条件 | Error code |
|---|---|
| required field 缺失 | `REQUIRED_FIELD_MISSING` |
| current 4.0 unknown field | `UNKNOWN_FIELD` |
| wrong container/scalar/dataclass/enum instance type;bool 字段非 exact bool | `INVALID_FIELD_TYPE` |
| unknown enum wire value | `UNKNOWN_ENUM_VALUE` |
| path/name/symbol/reason/gap/metric/range/order/duplicate/kind 语义/metrics 一致性非法 | `INVALID_FIELD_VALUE` |
| 超过数组上限 | `MAX_ARRAY_LENGTH_EXCEEDED` |
| 超过字符串上限 | `MAX_STRING_LENGTH_EXCEEDED` |
| extension key NFC 冲突 | `DUPLICATE_SEMANTIC_FIELD` |
| payload/profile/content digest 不一致 | `DIGEST_MISMATCH` |
| Envelope tenant/snapshot/lineage 冲突 | 复用 IP-0001 对应 `LINEAGE_*` |
| codec bytes/depth/object/string 限制 | 复用 IP-0001 对应 resource code |

同一输入违反多条规则时按以下优先级返回第一项:

1. byte/UTF-8/JSON/resource limit(codec);
2. top-level/container/required/current unknown/schema version;
3. enum 与 scalar type(含 bool 精确性);
4. scalar value、path、name、range、array limit/order/duplicate;
5. kind 语义(unknown 组合、code-kind↔languages)与 metrics 一致性;
6. source lineage reference(binding 阶段);
7. Envelope schema/payload/digest/classification/retention binding。

`field_path` 使用 JSONPath-like structural path,例如:

```text
$.repository_kinds[1]
$.languages[0].name
$.code_roles[2].path
$.entrypoints[0].symbol
$.execution_capability.buildable
$.code_density_bp
$.coverage_gaps[0].gap_code
$.payload.entrypoints[0].source_artifact_ids[0]
```

不得在 path 中包含真实字段值。

---

## 17. Golden Fixture

文件:

```text
tests/contracts/fixtures/repository_profile_v4_golden.json
```

要求:UTF-8;单行 canonical JSON;无 BOM;无 trailing newline;**exactly 2152 bytes**;payload SHA-256:

```text
ad7d53a0ed22412dbbfc60d0ed9183d7e939e2d14e4eee2d9399944cb5c4dccc
```

该 bytes 与 digest 已由 IP-0001 codec 在 `main@a0b3eea` 上预先计算并冻结。权威内容如下;实现者不得为让测试通过而更改字段、值、顺序或摘要:

```json
{"binary_ratio_bp":1250,"build_systems":[{"detection":"declared","name":"setuptools","source_artifact_ids":["tool-run-0001"]}],"code_density_bp":8200,"code_roles":[{"path":"src/cli.py","reason_codes":["PATH_PATTERN_SRC"],"role":"production","source_artifact_ids":["tool-run-0001"]},{"path":"src/example.py","reason_codes":["PATH_PATTERN_SRC"],"role":"production","source_artifact_ids":["tool-run-0001"]},{"path":"tests","reason_codes":["TEST_CONFIG_DISCOVERY"],"role":"test","source_artifact_ids":["tool-run-0001"]}],"component_path":null,"coverage_gaps":[{"detail":"Dynamic framework imports were not resolved; framework detection for src/example.py remains inferred.","gap_code":"FRAMEWORK_DETECTION_PARTIAL"}],"deployment_surface":[{"path":"Dockerfile","reason_codes":["CONTAINER_IMAGE_DECLARED"],"source_artifact_ids":["tool-run-0001"],"symbol":null}],"entrypoints":[{"path":"src/cli.py","reason_codes":["CLI_ENTRY_SCRIPT"],"source_artifact_ids":["tool-run-0001"],"symbol":"main"},{"path":"src/example.py","reason_codes":["MODULE_MAIN_GUARD"],"source_artifact_ids":["tool-run-0001"],"symbol":"run_command"}],"execution_capability":{"buildable":true,"requires_external_credentials":false,"requires_gpu":false,"requires_network":false,"requires_services":false,"testable":true},"external_inputs":[{"path":"src/cli.py","reason_codes":["CLI_ARGUMENT_READ"],"source_artifact_ids":["tool-run-0001"],"symbol":"main"}],"file_count":42,"frameworks":[{"detection":"inferred","name":"click","source_artifact_ids":["tool-run-0001"]}],"generated_ratio_bp":0,"languages":[{"detection":"declared","name":"python","source_artifact_ids":["tool-run-0001"]}],"max_file_bytes":38210,"package_managers":[{"detection":"declared","name":"pip","source_artifact_ids":["tool-run-0001"]}],"repository_kinds":["application","cli"],"sensitive_operations":[{"path":"src/example.py","reason_codes":["PROCESS_EXECUTION_SINK"],"source_artifact_ids":["tool-run-0001"],"symbol":"run_command"}],"support_level":"supported","total_bytes":512000,"trust_boundaries":[{"path":"src/cli.py","reason_codes":["CLI_TO_PROCESS_BOUNDARY"],"source_artifact_ids":["tool-run-0001"],"symbol":null}]}
```

Golden 语义要点(测试必须断言):双 kind(application+cli)、declared/inferred 混合 technology、目录前缀 code role(`tests`)、null symbol 的 trust boundary 与 deployment surface、非空 coverage gap、metrics 满足 §14.3。

### 17.1 Frozen envelope vector

Envelope integration test 使用:

```text
schema_name = lima.repository-profile
schema_version = 4.0
artifact_id = profile-0001
tenant_id = tenant-1
task_id = task-1
workflow_id = workflow-1
stage_attempt_id = classify-1
repository_snapshot_digest = "3" * 64
producer = lima-profile-classifier
created_at = 2026-09-02T00:00:00Z
policy_digest = "5" * 64
toolchain_digest = "6" * 64
content_digest = ad7d53a0ed22412dbbfc60d0ed9183d7e939e2d14e4eee2d9399944cb5c4dccc
classification = internal
retention_class = standard
lineage[0].schema_name = lima.tool-run
lineage[0].schema_version = 4.0
lineage[0].artifact_id = tool-run-0001
lineage[0].tenant_id = tenant-1
lineage[0].repository_snapshot_digest = "3" * 64
lineage[0].content_digest = "4" * 64
supersedes = null
coverage_gaps = []
```

---

## 18. Required Tests

测试必须使用 `unittest`,方法名冻结如下。可以增加 private test helpers,不得减少、重命名或合并这些测试。

### 18.1 `tests/contracts/test_profile.py`(33)

```text
ProfileEnumTests
  test_wire_values_are_exact

TechnologyDeclarationTests
  test_round_trip_has_exact_wire_shape
  test_rejects_missing_required_fields
  test_rejects_unknown_enum_and_wrong_field_type
  test_rejects_invalid_name_and_unsorted_duplicate_arrays
  test_rejects_empty_source_provenance

CodeRoleAssignmentTests
  test_round_trip_has_exact_wire_shape
  test_rejects_missing_and_unknown_fields
  test_rejects_unsorted_duplicate_and_oversize_pairs
  test_allows_directory_prefix_paths

AttackSurfaceEntryTests
  test_round_trip_with_null_and_present_symbol
  test_rejects_invalid_paths_symbols_and_reason_codes
  test_rejects_unsorted_duplicate_pairs

ExecutionCapabilityTests
  test_round_trip_has_exact_six_bool_wire_shape
  test_rejects_missing_bool_and_non_bool_values

ProfileCoverageGapTests
  test_round_trip_has_exact_wire_shape
  test_rejects_invalid_code_detail_and_duplicates

RepositoryProfileTests
  test_minimal_profile_round_trip_is_valid
  test_golden_profile_round_trip_and_digest
  test_rejects_empty_unknown_mixed_and_unsorted_repository_kinds
  test_rejects_code_kind_without_languages
  test_rejects_invalid_metrics_ranges_and_impossible_totals
  test_rejects_file_count_zero_with_nonzero_bytes
  test_rejects_wrong_container_and_missing_required_fields
  test_component_path_scoping_round_trip
  test_rejects_absolute_and_parent_component_paths
  test_empty_surface_arrays_are_valid_and_distinct_from_safety_verdicts
  test_rejects_oversize_arrays_with_max_array_length_exceeded
  test_future_minor_round_trips_unknown_fields_at_every_level
  test_current_minor_rejects_unknown_fields_at_every_level
  test_defensive_copy_prevents_post_construction_mutation
  test_payload_has_no_confidence_severity_or_safety_verdict_fields
```

`test_payload_has_no_confidence_severity_or_safety_verdict_fields` 必须递归断言 golden 与 minimal payload 任意层级不出现键:`confidence`、`severity`、`trust_score`、`is_secure`、`is_safe`。

### 18.2 `tests/contracts/test_profile_envelope.py`(9)

```text
ProfileEnvelopeTests
  test_frozen_envelope_encode_decode_is_byte_stable
  test_rejects_wrong_schema_name_and_version_mismatch
  test_rejects_blob_backed_profile
  test_rejects_payload_profile_and_content_digest_mismatch
  test_rejects_missing_source_artifact_lineage
  test_allows_additional_valid_lineage
  test_inherits_cross_tenant_cross_snapshot_and_self_reference_rejection
  test_rejects_public_classification_and_ephemeral_retention
  test_tampered_payload_fails_before_domain_promotion
```

### 18.3 `tests/contracts/test_profile_import_isolation.py`(4)

```text
ProfileImportIsolationTests
  test_module_public_api_matches_frozen_symbol_set
  test_clean_process_import_has_no_db_network_docker_llm_service_or_legacy_models
  test_module_only_uses_allowed_imports
  test_import_does_not_change_lima_contracts_top_level_public_api
```

`test_module_only_uses_allowed_imports` 必须额外断言 `lima.contracts.evidence` 未被 `profile` 导入(干净子进程 `sys.modules` 检查)。

### 18.4 Minimum count

IP-0003 必须新增至少 **46** 个独立 test methods(33+9+4)。可以增加更细的测试,但不允许用循环把多种安全边界压缩成一个无法定位的单断言。

---

## 19. Acceptance Criteria and Traceability

| AC | Required behavior | Evidence(test) | 覆盖的 Issue requirement |
|---|---|---|---|
| IP3-AC-01 | 15 个 module public symbols、4 个 enum wire vocabulary、6 个 exact constructors 完全冻结 | enum/object/import tests | FR-02(Profile 可版本化定义)、V5-FR-01 |
| IP3-AC-02 | name、path、symbol、reason/gap code、metric、bool scalar 校验与资源上限 fail closed | Technology/CodeRole/AttackSurface/ExecutionCapability/Gap negative tests | NFR-02、FR-02 |
| IP3-AC-03 | golden profile 为 2152 bytes、固定 digest、decode/encode byte-stable | golden test | FR-05(Profile fixture 子集)、AC-01 方法论 |
| IP3-AC-04 | kind 多值/unknown 排他/code-kind↔languages/metrics 一致性全部强制 | kinds/metrics tests | FR-02、NFR-01 |
| IP3-AC-05 | 五类 attack surface + code_roles 排序唯一、目录前缀、provenance、上限 | surface/code-role tests | FR-02、#60 V5-AC-01 的 schema 表达能力 |
| IP3-AC-06 | Profile payload 与 Envelope schema/version/digest/lineage/classification/retention 一致 | envelope tests | FR-02(跨对象引用 `artifact_id`+lineage)、NFR-01 |
| IP3-AC-07 | 4.0 unknown field 拒绝;未来 4.x optional field 每层级无损 round-trip;unknown enum/required 缺失仍拒绝 | compatibility tests | FR-06 |
| IP3-AC-08 | 无 confidence/severity/trust_score/is_secure/is_safe 字段 | forbidden-key recursive assertion | NFR-01(不编码安全结论) |
| IP3-AC-09 | stdlib-only leaf;不 import evidence;不改 IP-0001 顶层 API、错误码(29)或 wire contract | import isolation + git diff | AC-04(T-04 依赖隔离)、FR-04 尊重 |
| IP3-AC-10 | 只新增 5 个 allowlist 文件,0 existing modifications,0 dependencies,全量测试无新增失败 | file boundary + full regression | AC-04、Issue 级 PR 边界 |

反向追踪:每个 required test 至少映射一个 AC;每个 AC 至少一个 required test;Issue requirement → AC 见末列。任一 AC 无机器证据时状态不是 DONE。

---

## 20. 强制实现顺序

必须测试先行,按以下 slice:

1. 建立 3 个测试文件框架 + golden fixture(逐字节复制 §17 权威内容)与 `test_profile.py` 的 enum/nested-object RED tests;
2. 在 `profile.py` 实现常量、4 个枚举、通用 validators 与 5 个 nested object(`ExecutionCapability`/`TechnologyDeclaration`/`CodeRoleAssignment`/`AttackSurfaceEntry`/`ProfileCoverageGap`);
3. 为 `RepositoryProfile` 的 kinds/metrics/surface/compatibility 写 RED tests,再实现全图校验;
4. 逐字验证 frozen golden fixture(2152 bytes / `ad7d53a0…c4dccc`);
5. 为 Envelope binding 写 RED tests,再实现 4 个 encode/decode functions;
6. 写 import isolation 与 forbidden-key tests;
7. 运行 Slice Gate;
8. 运行 Compatibility Gate、全量回归和 File Boundary Gate;
9. 输出完整 Completion Summary。

不得先写完实现再补测试。测试发现 Packet 冲突时停止,不得修改 frozen fixture 或放宽断言。

---

## 21. Done Commands

### 21.1 Baseline(编码前)

```powershell
python -m compileall -q lima scripts tests
python -m unittest discover -s tests/contracts -v
python -m unittest -v tests.test_repository_source tests.test_task_failure
```

预期基线(@ `a0b3eea` + 本 Packet 合并):contracts 84 PASS;定向兼容 29 PASS。若数量变化,以最新 `main` 实际结果为准并记录差异。

### 21.2 Slice Gate

```powershell
python -m compileall -q lima/contracts tests/contracts
python -m unittest discover -s tests/contracts -v
python -m ruff check lima/contracts/profile.py tests/contracts/test_profile.py tests/contracts/test_profile_envelope.py tests/contracts/test_profile_import_isolation.py
python -m ruff check lima/contracts tests/contracts
python -m bandit -q -r lima/contracts/profile.py
git diff --check
```

第二条 ruff(全目录)自 IP-0001-R1(`a0b3eea`)起必须 exit 0;本 IP 不得使其回退。

### 21.3 Compatibility Gate

```powershell
python -m unittest -v tests.test_repository_source tests.test_task_failure
python -m unittest discover -s tests -v
```

基线参考(@ `a0b3eea`):429 tests / 0 failed / 1 既有 Windows symlink privilege skip(本 IP 合并后应为 475 = 429 + 46)。任何新增 failure/skip 必须解释;不能通过修改 legacy 测试解决。Python 3.11/3.12 由 CI matrix 验证;本机缺少某版本时如实记录。

### 21.4 File Boundary Gate

```powershell
git diff --name-only --diff-filter=ACMRTUXB origin/main...HEAD
git diff --check origin/main...HEAD
```

第一条输出必须恰好为 7.1 的 5 个新增文件,不得出现 modified existing file。

### 21.5 Optional release-level gate

维护者或 CI 可运行 `powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 test`。普通 Agent 不因 Docker/宿主环境不可用而擅自改变产品代码。

---

## 22. Security and Compatibility Invariants

- 不可信 repository 数据只能以 repo-relative 路径、受限文本、枚举与 Artifact refs 表达;不内联源码、日志、secret 或 host 路径;
- 错误信息不得回显原始 payload、name、path value、detail 或 snippet;
- Profile 不编码任何安全结论:support_level 是平台承诺,空清单不是"无风险",unknown kind 不是"安全";
- 每条分类声明(technology/code role/attack surface)必须携带 ≥1 lineage provenance;无 provenance 拒绝;
- public/ephemeral Envelope 不得承载 Profile;
- 未知 major、unknown enum、digest mismatch、跨 tenant/snapshot 引用 fail closed;
- 所有 ID、digest、时间、指标由调用方提供;模块不生成任何身份值;
- 不新增网络、磁盘、DB、Docker、subprocess、凭据或付费模型权限;
- 不改变 legacy 1.6.0 行为与 IP-0001/0002 冻结 API(29 错误码、18 顶层 symbols、16 evidence symbols);
- 不通过 future-minor extension 绕过 required fields、enum validation 或 provenance 要求。

---

## 23. Stop Conditions / Decision Request

出现以下任一情况必须停止:

1. 本 Packet 或正式交接书尚未合并到 `origin/main`,或 base 不包含 `a0b3eea`;
2. 最新 `main` 已出现同名 `profile.py` 或其他 Owner 的冲突实现;
3. 需要修改 `__init__.py`、`evidence.py`、common、codec、errors 或任一 forbidden 文件;
4. 需要新增第三方依赖、I/O、网络、数据库、Docker、subprocess 或环境权限;
5. exact constructor、wire shape、enum、数组排序、错误优先级或 future-minor 行为存在两个合理答案;
6. frozen fixture 的 2152 bytes 或 digest `ad7d53a0…c4dccc` 无法由 IP-0001 codec 重现;
7. 需要引入 float 指标、confidence/severity 类字段、自动生成 ID/digest 或放宽 provenance 要求才能继续;
8. 需要实现 classifier/inventory/RAM 图/component graph/JSON Schema 文件才能让测试通过;
9. baseline/全量回归失败且无法归因;
10. Packet 测试不能证明某个 AC;
11. 发现工作实际需要 AEP/VEP/RVR、manifest、workflow schema 或生产接线;
12. 全目录 ruff(§21.2 第二条)在本 IP 改动后出现非本 IP 文件的新违规。

Decision Request 格式:

```text
Packet/规则位置:
实际代码证据:
最小复现命令:
为什么无法在 5-file allowlist 内解决:
可选方案:
各方案的兼容、安全、工期影响:
Agent 建议:
```

维护者更新 Packet/Decision Record 前不得越界继续。

---

## 24. Git, Commit and PR Contract

推荐 commit / PR 标题:

```text
feat: add deterministic repository profile contracts
```

PR 正文必须:

- 只写 `Related to #58`;不出现任何会自动关闭 #58 的 keyword;
- 附 AC → Test → Result;
- 附真实命令、退出码、passed/failed/skipped;
- 明确 5 added / 0 modified / 0 dependencies;
- 明确 no production integration、no classifier implementation、no top-level public API change、evidence.py untouched;
- 等待独立 Reviewer 和 `merge-gate`。

Implementation Agent 不合并自己的 PR,不删除分支/worktree,不修改 Issue。

---

## 25. Completion Summary Template

```markdown
## IP-0003 Completion Summary

### Result
- Status: DONE | NOT DONE | BLOCKED
- Base commit:
- Final commit:
- Branch:
- Worktree:

### Scope
- Added files:
- Modified existing files: none | <mark NOT DONE>
- Dependencies added: none | <mark NOT DONE unless approved>
- Public API: `lima.contracts.profile` only (15 symbols)
- Contract deviations: none | <Decision Request>

### Acceptance evidence
| AC | Test/command | Result |
|---|---|---|
| IP3-AC-01 | | |
| IP3-AC-02 | | |
| IP3-AC-03 | | |
| IP3-AC-04 | | |
| IP3-AC-05 | | |
| IP3-AC-06 | | |
| IP3-AC-07 | | |
| IP3-AC-08 | | |
| IP3-AC-09 | | |
| IP3-AC-10 | | |

### Commands and actual results
- Command:
  - Exit code:
  - Passed/failed/skipped:

### Security and compatibility
- Fail-closed scalar/cross-field behavior:
- Provenance enforcement:
- Envelope lineage/classification binding:
- Secret/input echo review:
- Import isolation (incl. no evidence import):
- Python 3.11/3.12:
- Legacy regression:

### Findings and decisions
- New Findings:
- Approved Decisions:
- Open Decision Requests:

### Handoff
- PR URL/status:
- Exact next action:
- Forbidden next action:
```

---

## 26. Maintainer Review Checklist

- [ ] base 包含 `a0b3eea`(IP-0001-R1)与两份 IP-0003 文档;
- [ ] 只新增 5 个 allowlist 文件;
- [ ] `lima.contracts.__all__`(18)、29 个 error codes、`evidence.py`(16 symbols)全部未变;
- [ ] module public API 恰好 15 symbols;`lima.contracts.evidence` 未被 import;
- [ ] exact constructors/wire shapes(21 个 top-level required 字段)无漂移;
- [ ] golden fixture 2152 bytes、无 BOM/newline、digest `ad7d53a0…c4dccc`;
- [ ] current/future-minor matrix(每层级)通过;
- [ ] kinds 语义、metrics 一致性、排序唯一、provenance、上限 negative tests 通过;
- [ ] Envelope schema/digest/lineage/classification/retention tests 通过;
- [ ] 无 confidence/severity/trust_score/is_secure/is_safe 字段;
- [ ] import isolation 与 no dependency 通过;
- [ ] 全量回归无新增失败(预期 475 = 429 + 46);
- [ ] 全目录 ruff(`lima/contracts tests/contracts`)exit 0;
- [ ] File Boundary Gate 恰好 5 文件;
- [ ] Completion Summary 可复现;
- [ ] 独立 Review 与 `merge-gate` 通过;
- [ ] PR 未关闭 #58;
- [ ] 未启动 IP-0004、classifier 或生产接线。

---

## 27. Packet 完成定义

只有全部 10 个 AC、46 个 required tests、golden fixture、Envelope consumer test、import isolation、完整命令证据、独立 Review 和 `merge-gate` 全部满足,IP-0003 实现才能标记 DONE。

IP-0003 合并后,协调者必须在最新 `main` 上安排 post-merge verification,并让 IP-0004(AEP)对本模块做只读 consumer review(其 Packet 的 Design Input Manifest 入口 Gate)。当前 Agent 不自动继续 IP-0004。
