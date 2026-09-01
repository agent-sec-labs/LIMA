# LIMA Implementation Packet IP-0002：Evidence Domain

> Packet ID：`IP-0002`
>
> 状态：`DESIGN-FROZEN / READY-FOR-CODE WHEN THIS PACKET IS MERGED TO MAIN`
>
> Source Issue：[#58](https://github.com/agent-sec-labs/LIMA/issues/58) 的第二个独立实现切片
>
> 最低代码基线：`d3e73d977c33857e309cd5bc4df64310f29533b3`（PR #98）；实际实现基线必须是包含本 Packet 与正式交接书的最新 `origin/main`
>
> 推荐分支：`codex/ip-0002-evidence-domain`
>
> Owner：唯一 Implementation Agent；不得与 IP-0003 并行修改 `lima/contracts/` 或 `tests/contracts/`

---

## 0. 执行决策

当前执行队列冻结为：

```text
DONE
IP-0001 Contract Foundation

NOW（只允许 1 个）
IP-0002 Evidence Domain（Design Frozen；文档合并后授权编码）

NEXT（不得实现）
IP-0003 Repository Profile / RAM Foundation

LATER
Audit adapters / clustering / fusion / AEP / Mining / Repair / Sandbox / Registry / UI
```

本 Packet 只建立可被后续 Audit、Mining Planner 和 Artifact schema 消费的 Evidence Domain。它不把 legacy 扫描结果接入新模型，不实现聚类、融合或裁决算法，也不改变任何现有生产行为。

---

## 1. IP-0001 消费者评审结论

### 1.1 已验证事实

在 `main@d3e73d9` 上已经验证：

- `lima/contracts/` 的 canonical codec、`SchemaVersion`、`ArtifactReference` 和 `ArtifactEnvelope` 可以承载任意受限 JSON object payload；
- Evidence payload 经 `compute_content_digest → ArtifactEnvelope → encode_envelope → decode_envelope → encode_envelope` 后内容、摘要和字节保持一致；
- 合并后的 39 个 contracts 测试全部通过；
- 全量测试为 384 个，0 failed，1 个既有 Windows symlink privilege skip；
- `lima.contracts.__all__`、`ContractErrorCode` 的 28 个 wire values 和 common wire shape 已由 IP-0001 冻结。

消费者验证的最小 payload：

```json
{"evidence":[],"security_issues":[],"signals":[],"vulnerability_hypotheses":[]}
```

该 payload 在现有 `ArtifactEnvelope` 中完成了 795-byte 空 lineage 示例的确定性重放。不存在阻塞 IP-0002 的 Contract Gap。

### 1.2 本 Packet 的兼容决策

为保持 IP-0001 稳定并减少 IP-0002/IP-0003 的共享文件冲突，本切片冻结以下决定：

1. 只新增 `lima/contracts/evidence.py`，不修改 `lima/contracts/__init__.py`；
2. IP-0002 的公共 API 从 `lima.contracts.evidence` 导入，不增加 `lima.contracts` 顶层导出；
3. 复用现有 28 个 `ContractErrorCode`，不扩展 `errors.py`；
4. 复用 `ArtifactEnvelope.schema_name/schema_version/payload/lineage`，不创建第二套 Envelope 或 codec；
5. Evidence Domain 当前只接受 inline payload；blob-backed Evidence package 留给 Artifact Registry/AEP Packet；
6. 当前 schema 版本仍为 `4.0`；未知 4.x optional 字段按 IP-0001 规则保留，未知 major fail closed。

这些决定不是临时实现建议，而是本 Packet 的冻结 Contract。

---

## 2. Iteration Hypothesis 与 Measurement

### 2.1 Hypothesis

如果先冻结 `Signal → SecurityIssue → VulnerabilityHypothesis → EvidenceRecord` 的纯领域模型、引用完整性和 Envelope binding，那么后续 Audit adapter、root-cause clustering、Evidence Fusion 与 Mining Planning 可以针对同一份确定性契约独立开发，而不会把 legacy `Finding`、自由文本 LLM 输出或置信度当成跨阶段事实。

### 2.2 Measurement

本假设通过以下事实证明：

- 一组最小但完整的 D0→D1→D2 Evidence graph 能生成固定 canonical bytes 和固定 SHA-256；
- 输入对象和数组顺序、Unicode 表示或构造后外部 mutation 不会产生隐式语义漂移；
- 缺失 subject、悬空引用、循环依赖、错误状态提升、D3/D4 伪造和 lineage 缺失均 fail closed；
- `statically_supported` 永远不能编码成 verified vulnerability；
- 新模块导入不加载 DB、网络、Docker、LLM、service、scanner 或 legacy models；
- 既有 384 个测试无新增失败。

---

## 3. Goal

实现一个 stdlib-only、无副作用、确定性、可版本演化的 Evidence Domain leaf module，包含：

1. 代码位置 `SourceLocation`；
2. 原始观察 `Signal`；
3. 根因聚类单元 `SecurityIssue`；
4. 可执行验证命题 `VulnerabilityHypothesis`；
5. 支持/反驳关系 `EvidenceRecord`；
6. 在一个 payload 内校验全图的 `EvidenceDomainBundle`；
7. Evidence payload 与 IP-0001 `ArtifactEnvelope` 之间的 encode/decode binding；
8. D0–D4 的全局 wire vocabulary，但本 Audit Evidence bundle 只允许 D0–D2；
9. golden fixture、负向边界测试、import isolation 和 legacy regression。

完成后，下游必须能够明确区分：

```text
Signal                    = 某个工具或语义分析产生的原始观察
SecurityIssue             = 对同一根因/边界/危险 sink 的调查单元
VulnerabilityHypothesis   = 需要 Mining 或确定性 Oracle 验证的命题
EvidenceRecord            = 支持或反驳某个 subject 的可追溯证据
```

---

## 4. Non-goals

本次明确不做：

- 不实现 AST/Dataflow/Bandit/Semgrep/CodeQL/LLM 到 Signal 的 adapter；
- 不实现 Signal identity、Issue identity、root-cause clustering、dedup、Fusion 或 Adjudication 算法；
- 不生成 ID、fingerprint、identity digest、时间或随机数；调用方必须显式传入；
- 不实现 `QualifiedSignal`、Rule Applicability 或 severity ceiling；
- 不实现 Repository Profile、RAM、AEP、VEP、RVR、Workflow、Stage、Manifest 或 Failure schema；
- 不允许 D3/D4 在本 bundle 中成立；D3/D4 的 Oracle、Sandbox run 和 impact binding 由未来 VEP Packet 冻结；
- 不实现 vulnerability boolean、`is_vulnerable`、`verified`、`clear`、自动关闭或人工队列；
- 不引入 severity 或浮点 confidence 字段；
- 不修改或适配 legacy `Finding`、`EvidenceRecord`、`ReviewReport`；
- 不接 API、Service、Store、Queue、Scanner、Sandbox、Registry、Frontend 或数据库；
- 不调用 LLM，不访问网络，不运行 Docker，不读取环境变量，不执行目标代码；
- 不增加 JSON Schema 文件或第二套 canonical codec；
- 不检测自由文本中所有可能的 secret；本 schema 通过不提供 raw snippet 字段、限制大小和 Envelope classification 降低风险，完整脱敏属于后续治理 Packet；
- 不修改 GitHub Issue、Label、Milestone 或其他远端状态；
- 不实现 IP-0003 或任何顺手重构。

---

## 5. 工作树与分支前置条件

Coding Agent 必须：

1. 完整阅读稳定标准、`PROGRESS.md`、本 Packet、正式交接书和 `CONTRIBUTING.md`；
2. 确认本 Packet 与 `LIMA_Coding_Agent_IP-0002_正式开发任务交接.md` 已存在于 `origin/main`，否则不得编码；
3. 确认当前 base 包含 `d3e73d977c33857e309cd5bc4df64310f29533b3`；
4. 确认 `lima/contracts/evidence.py` 与本 Packet 的 4 个测试/fixture 文件尚不存在；
5. 从包含两份 IP-0002 文档的最新 `origin/main` 建立独立干净 worktree 和 `codex/ip-0002-evidence-domain`；
6. 先输出 Scope Confirmation，随后运行 baseline；
7. baseline 或代码事实与本文不一致时停止并提交 Decision Request。

根工作树中的未跟踪规划文档属于用户资产，不得移动、删除、stash、覆盖或纳入实现 PR。

---

## 6. 文件边界

### 6.1 Files to Add（恰好 5 个）

```text
lima/contracts/evidence.py
tests/contracts/test_evidence.py
tests/contracts/test_evidence_envelope.py
tests/contracts/test_evidence_import_isolation.py
tests/contracts/fixtures/evidence_domain_bundle_v4_golden.json
```

### 6.2 Files Allowed to Modify

```text
none
```

### 6.3 Files Forbidden

除上述 5 个新增文件外全部禁止修改，特别包括：

```text
lima/contracts/__init__.py
lima/contracts/common.py
lima/contracts/codec.py
lima/contracts/errors.py
tests/contracts/test_common.py
tests/contracts/test_codec.py
tests/contracts/test_errors.py
tests/contracts/test_import_isolation.py
lima/models.py
lima/adjudication.py
lima/repository_triage.py
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

若实现需要修改任一 forbidden 文件，必须停止。不能通过扩大 allowlist、复制 legacy 模型或放宽测试继续。

### 6.4 Ownership 与冲突边界

- `lima/contracts/evidence.py` 在本 Packet 期间只有一个 Owner；
- IP-0003 不得在 IP-0002 合并前创建同名 symbol；
- 新公共 symbol 不从 `lima.contracts` 顶层重导出；
- 下游在本阶段必须使用 `from lima.contracts.evidence import ...`；
- 任何未来聚合导出必须使用独立 Packet，不得追补到本 PR。

---

## 7. Allowed / Forbidden Dependencies

### 7.1 Allowed

`evidence.py` 只允许导入：

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

测试只允许额外使用 stdlib：

```text
ast
copy
hashlib
pathlib
subprocess
sys
unittest
```

### 7.2 Forbidden

- 任何新增第三方包；
- `lima.models`、audit/service/store/queue/scanner/sandbox/runtime/agent 模块；
- HTTP、socket、数据库、Docker SDK、subprocess（产品模块）、文件系统读取（产品模块）；
- UUID、当前时间、随机数、环境变量；
- Pydantic/Marshmallow/JSON Schema/canonical-json 第三方实现；
- 绝对路径、host path 或 repository 内容读取。

`evidence.py` 必须保持纯内存 leaf module。

---

## 8. 冻结的公共 Symbols

`lima/contracts/evidence.py` 的 `__all__` 必须严格等于以下集合，不多不少：

```python
__all__ = [
    "EVIDENCE_DOMAIN_SCHEMA_NAME",
    "EvidenceLevel",
    "EvidencePolarity",
    "EvidenceSubjectKind",
    "HypothesisStatus",
    "RequiredProofKind",
    "SourceLocation",
    "EvidenceRecord",
    "Signal",
    "SecurityIssue",
    "VulnerabilityHypothesis",
    "EvidenceDomainBundle",
    "decode_evidence_payload",
    "encode_evidence_payload",
    "decode_evidence_envelope",
    "encode_evidence_envelope",
]
```

模块常量：

```python
EVIDENCE_DOMAIN_SCHEMA_NAME = "lima.evidence-domain"
```

不允许额外公开 helper、alias、factory、builder 或第二套异常类型。

---

## 9. 冻结枚举

所有枚举均使用 `class X(str, Enum)`，wire value 大小写严格固定。

```python
class EvidenceLevel(str, Enum):
    D0 = "D0"
    D1 = "D1"
    D2 = "D2"
    D3 = "D3"
    D4 = "D4"

class EvidencePolarity(str, Enum):
    SUPPORTS = "supports"
    REFUTES = "refutes"

class EvidenceSubjectKind(str, Enum):
    SIGNAL = "signal"
    SECURITY_ISSUE = "security_issue"
    VULNERABILITY_HYPOTHESIS = "vulnerability_hypothesis"

class HypothesisStatus(str, Enum):
    PROPOSED = "proposed"
    STATICALLY_SUPPORTED = "statically_supported"
    STATICALLY_REFUTED = "statically_refuted"
    CONFLICTING_STATIC_EVIDENCE = "conflicting_static_evidence"
    INSUFFICIENT_STATIC_EVIDENCE = "insufficient_static_evidence"

class RequiredProofKind(str, Enum):
    RUNTIME_BEHAVIOR = "runtime_behavior"
    STATIC_PROPERTY = "static_property"
    CONFIGURATION_STATE = "configuration_state"
    EXTERNAL_MANUAL_REQUIRED = "external_manual_required"
```

Evidence Level 的语义固定为：

| Level | 含义 | 本 Packet 是否允许写入 bundle | 允许结论 |
|---|---|---:|---|
| D0 | 工具原始命中或模式证据 | 是 | Signal only |
| D1 | 代码角色、局部语义和规则适用性支持 | 是 | Contextual candidate |
| D2 | source/sink、控制流、数据流或安全不变量的确定性静态证据 | 是 | Static hypothesis |
| D3 | 受控环境中可重复触发非预期行为 | 否，保留 wire vocabulary | 未来 VEP |
| D4 | 影响、攻击前提和机器 Oracle 均验证 | 否，保留 wire vocabulary | 未来 verified vulnerability |

D3/D4 出现在 `EvidenceDomainBundle` 时必须以 `INVALID_FIELD_VALUE` 拒绝，`field_path` 指向具体 `$.evidence[i].level`。这避免 Audit 阶段伪造动态证明。

---

## 10. Exact Constructors and Defaults

全部领域对象必须是 `@dataclass(frozen=True, slots=True)`，必须 defensive-copy 所有可变输入。

### 10.1 `SourceLocation`

```python
SourceLocation(
    path: str,
    start_line: int,
    end_line: int,
    start_column: int | None = None,
    end_column: int | None = None,
    symbol: str | None = None,
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

### 10.2 `EvidenceRecord`

```python
EvidenceRecord(
    evidence_id: str,
    subject_kind: EvidenceSubjectKind,
    subject_id: str,
    level: EvidenceLevel,
    polarity: EvidencePolarity,
    analysis_family: str,
    producer: str,
    independence_key: str,
    summary: str,
    source_artifact_ids: tuple[str, ...],
    reason_codes: tuple[str, ...],
    location: SourceLocation | None = None,
    depends_on_evidence_ids: tuple[str, ...] = (),
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

### 10.3 `Signal`

```python
Signal(
    signal_id: str,
    fingerprint: str,
    rule_id: str,
    analysis_family: str,
    evidence_kind: str,
    location: SourceLocation,
    evidence_ids: tuple[str, ...],
    reason_codes: tuple[str, ...],
    cwe_ids: tuple[str, ...] = (),
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

### 10.4 `SecurityIssue`

```python
SecurityIssue(
    issue_id: str,
    identity_digest: str,
    root_cause_class: str,
    sink_identity: str,
    trust_boundary: str,
    primary_location: SourceLocation,
    signal_ids: tuple[str, ...],
    evidence_ids: tuple[str, ...],
    reason_codes: tuple[str, ...],
    cwe_ids: tuple[str, ...] = (),
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

### 10.5 `VulnerabilityHypothesis`

```python
VulnerabilityHypothesis(
    hypothesis_id: str,
    issue_id: str,
    status: HypothesisStatus,
    claim: str,
    security_invariant: str,
    required_proof_kind: RequiredProofKind,
    capability_requirements: tuple[str, ...],
    target_location: SourceLocation,
    source_locations: tuple[SourceLocation, ...],
    critical_path: tuple[SourceLocation, ...],
    trigger_conditions: tuple[str, ...],
    input_constraints: tuple[str, ...],
    evidence_ids: tuple[str, ...],
    reason_codes: tuple[str, ...],
    cwe_ids: tuple[str, ...] = (),
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

### 10.6 `EvidenceDomainBundle`

```python
EvidenceDomainBundle(
    schema_version: SchemaVersion,
    signals: tuple[Signal, ...] = (),
    security_issues: tuple[SecurityIssue, ...] = (),
    vulnerability_hypotheses: tuple[VulnerabilityHypothesis, ...] = (),
    evidence: tuple[EvidenceRecord, ...] = (),
    extensions: dict[str, JSONValue] = field(default_factory=dict),
)
```

`schema_version` 是 Envelope context，不进入 payload wire；它用于 current/future-minor 字段规则。所有 tuple 字段在构造后必须真实存储为 tuple；所有 dict/对象必须 defensive-copy。

### 10.7 Frozen serialization methods

六个 dataclass 都必须提供 deterministic `to_dict()`；五个 nested object 和 bundle 必须提供以下 exact classmethod 形态：

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

这里的 `Self` 表示对应具体 class 的返回类型；实现必须使用 Python 3.11/3.12 均兼容的注解写法，不得为此引入 typing extension。`from_dict` 负责 required/unknown/type/enum/extension 校验，`to_dict` 输出精确 wire shape 并 defensive-copy。`EvidenceDomainBundle.from_dict` 还必须执行第 14 节全图校验；`decode_evidence_payload` 只是稳定公共入口，不得形成第二套解析逻辑。

---

## 11. Exact Wire Shapes

### 11.1 Top-level payload

4.0 的 required fields 恰好为：

```json
{
  "signals": [],
  "security_issues": [],
  "vulnerability_hypotheses": [],
  "evidence": []
}
```

四个字段必须存在且必须是 array；空数组合法，只表示此 payload 没有领域对象，不表示仓库安全、审计完整或 `NO_ACTIONABLE_HYPOTHESIS`。安全终态必须由未来 AEP/Workflow Artifact 结合 coverage 产生。4.0 不允许其他字段。

### 11.2 `SourceLocation`

```json
{
  "path": "src/example.py",
  "start_line": 10,
  "end_line": 10,
  "start_column": 5,
  "end_column": 18,
  "symbol": "run_command"
}
```

六个字段全部 required；未知 column 或 symbol 使用 JSON `null`，不得省略、不得用 0 或空字符串代替。

### 11.3 `EvidenceRecord`

```json
{
  "evidence_id": "evidence-signal-0001",
  "subject_kind": "signal",
  "subject_id": "signal-0001",
  "level": "D0",
  "polarity": "supports",
  "analysis_family": "sast",
  "producer": "bandit-1.9.4",
  "independence_key": "bandit:B602:src/example.py:10",
  "summary": "Bandit reported process execution with shell semantics.",
  "source_artifact_ids": ["tool-run-0001"],
  "reason_codes": ["RULE_MATCH"],
  "location": {},
  "depends_on_evidence_ids": []
}
```

`location` required，但可为 `null`。不得嵌入 raw source snippet、完整工具日志、PoC 输出、凭据或 host absolute path；这些内容只能通过受控 Artifact/Blob reference 表达。

### 11.4 `Signal`

```json
{
  "signal_id": "signal-0001",
  "fingerprint": "<64 lowercase hex>",
  "rule_id": "B602",
  "analysis_family": "sast",
  "evidence_kind": "tool-observation",
  "location": {},
  "evidence_ids": ["evidence-signal-0001"],
  "reason_codes": ["RULE_MATCH_PROCESS_EXECUTION"],
  "cwe_ids": ["CWE-78"]
}
```

### 11.5 `SecurityIssue`

```json
{
  "issue_id": "issue-0001",
  "identity_digest": "<64 lowercase hex>",
  "root_cause_class": "command-injection",
  "sink_identity": "python.subprocess.shell",
  "trust_boundary": "cli-to-process",
  "primary_location": {},
  "signal_ids": ["signal-0001"],
  "evidence_ids": ["evidence-issue-0001"],
  "reason_codes": ["ROOT_CAUSE_CLUSTERED_BY_SINK"],
  "cwe_ids": ["CWE-78"]
}
```

`SecurityIssue` 不包含 severity、confidence、修复建议或漏洞真值。

### 11.6 `VulnerabilityHypothesis`

```json
{
  "hypothesis_id": "hypothesis-0001",
  "issue_id": "issue-0001",
  "status": "statically_supported",
  "claim": "Untrusted CLI input may reach a process execution sink.",
  "security_invariant": "Process arguments must not be interpreted by a command shell.",
  "required_proof_kind": "runtime_behavior",
  "capability_requirements": ["python", "subprocess-observer"],
  "target_location": {},
  "source_locations": [],
  "critical_path": [],
  "trigger_conditions": [],
  "input_constraints": [],
  "evidence_ids": ["evidence-hypothesis-0001"],
  "reason_codes": ["STATIC_DATAFLOW_REACHES_PROCESS_SINK"],
  "cwe_ids": ["CWE-78"]
}
```

`statically_supported` 只是 Mining eligibility 输入，不是 verified vulnerability。

### 11.7 Extensions

- 4.0：任何层级出现 unknown field 都以 `UNKNOWN_FIELD` 拒绝；
- 未来 4.x：unknown optional field 必须原位置无损保存在对应对象的 `extensions`，并 round-trip；
- extension key 与 known field NFC 归一后冲突时使用 `DUPLICATE_SEMANTIC_FIELD`；
- required 字段即使未来 minor 也不能缺失；
- unknown enum 即使未来 minor 也必须 fail closed。

---

## 12. Scalar Validation

### 12.1 Identifier

下列字段使用 ASCII identifier：所有 `*_id`、`producer`、`analysis_family`、`evidence_kind`、`root_cause_class`、`sink_identity`、`trust_boundary`、`capability_requirements[]`。

规则：

```text
[A-Za-z0-9][A-Za-z0-9._:-]{0,127}
```

- 必须是 exact `str`；
- NFC 后验证；
- 空字符串、空白、斜杠、反斜杠和控制字符非法；
- identifier 不自动 lower-case，不自动修剪；非 canonical 输入直接拒绝。

`rule_id` 必须完整匹配 `[A-Za-z0-9][A-Za-z0-9._:+/-]{0,255}`；该 ASCII pattern 已排除空白、反斜杠和控制字符，不再附加仓库专用规则名白名单。

### 12.2 Digest

`fingerprint` 和 `identity_digest` 必须是 exactly 64 lowercase hex：

```text
[0-9a-f]{64}
```

Contract 只校验格式；具体 identity material 和生成算法属于 #61，IP-0002 不自行计算或验证其业务含义。

### 12.3 CWE

- 格式：`CWE-[1-9][0-9]{0,5}`；
- array 可以为空，表示尚未可靠分类；
- 必须 ASCII 升序、唯一；
- 不接受小写、裸数字、`CWE-0`、空字符串或重复；
- 不通过默认值伪造 CWE。

### 12.4 Reason code

- 格式：`[A-Z][A-Z0-9_]{0,63}`；
- `reason_codes` 对 Signal/Issue/Hypothesis/Evidence 均至少 1 项；
- 必须 ASCII 升序、唯一；
- code 是机器解释，不得把路径、secret、仓库名或自然语言塞入 reason code。

### 12.5 Bounded text

`summary`、`claim`、`security_invariant`、`trigger_conditions[]`、`input_constraints[]`、`independence_key` 使用以下规则：

- exact `str`，NFC；
- 非空；
- 禁止 Unicode category `Cc` 控制字符；
- 不自动 strip；前导/尾随空白非法；
- `summary/claim/security_invariant/condition/constraint` 每项最多 4096 UTF-8 bytes；
- `independence_key` 最多 512 UTF-8 bytes；
- error message 不回显原值。

`trigger_conditions`、`input_constraints` 是 set-like 数组，必须按 canonical UTF-8 byte order 升序且唯一；`critical_path` 和 `source_locations` 是 order-significant，不排序。

### 12.6 Repository-relative path

`SourceLocation.path`：

- exact `str`、NFC、1–1024 UTF-8 bytes；
- 必须使用 `/`；
- 禁止 `/` 开头、Windows drive/UNC、反斜杠、空 segment、`.`、`..`、NUL 和控制字符；
- 不访问文件系统，不解析 symlink；
- 不自动替换 separator 或 resolve；非 canonical path 直接拒绝。

`symbol` 为 `null` 或 1–512 UTF-8 bytes 的 bounded text。

### 12.7 Line and column

- exact int，拒绝 bool；
- line 范围 `1..2147483647`；
- column 必须同时为 `null` 或同时为范围内 int；
- `end_line >= start_line`；
- 同一行且 column 非 null 时 `end_column >= start_column`；
- 未知位置不得用 0/-1 填充。

---

## 13. Array Limits and Canonical Ordering

| Array | 最大项数 | 是否允许空 | 排序规则 |
|---|---:|---:|---|
| `signals` | 10,000 | 是 | `signal_id` ASCII 升序 |
| `security_issues` | 2,048 | 是 | `issue_id` ASCII 升序 |
| `vulnerability_hypotheses` | 2,048 | 是 | `hypothesis_id` ASCII 升序 |
| `evidence` | 10,000 | 是 | `evidence_id` ASCII 升序 |
| 每个 `evidence_ids` | 1,024 | 否 | ASCII 升序、唯一 |
| `signal_ids` | 1,024 | 否 | ASCII 升序、唯一 |
| `source_artifact_ids` | 32 | 否 | ASCII 升序、唯一 |
| `depends_on_evidence_ids` | 64 | 是 | ASCII 升序、唯一 |
| `reason_codes` | 64 | 否 | ASCII 升序、唯一 |
| `cwe_ids` | 32 | 是 | ASCII 升序、唯一 |
| `capability_requirements` | 32 | 否 | ASCII 升序、唯一 |
| `source_locations` | 64 | 是 | 保留 source→sink 业务顺序 |
| `critical_path` | 256 | 是 | 保留控制/调用路径顺序 |
| `trigger_conditions` | 64 | 是 | canonical UTF-8 byte order、唯一 |
| `input_constraints` | 64 | 是 | canonical UTF-8 byte order、唯一 |

Contract 不隐式排序 set-like 或顶层数组。未按规定排序的输入以 `INVALID_FIELD_VALUE` 拒绝；这避免同一语义因工具返回顺序不同产生不同 digest。order-significant 数组保持原顺序。

超过上限使用 `MAX_ARRAY_LENGTH_EXCEEDED`；重复或未排序使用 `INVALID_FIELD_VALUE`；`field_path` 指向具体数组或违规元素。

---

## 14. Evidence Graph Invariants

`EvidenceDomainBundle` 必须在构造和 decode 时完整校验以下规则。

### 14.1 Identity

1. 每个类型内部 ID 唯一；
2. `signal_id`、`issue_id`、`hypothesis_id`、`evidence_id` 四个 namespace 之间也必须全局唯一；
3. duplicate/collision 使用 `INVALID_FIELD_VALUE`；
4. Contract 不根据行号或字段自动生成/修改 ID。

### 14.2 Subject binding

1. 每个 Evidence 的 `subject_kind + subject_id` 必须指向 bundle 内存在的对象；
2. 每个 Signal、Issue、Hypothesis 的 `evidence_ids` 必须非空；
3. subject 声明的 `evidence_ids` 必须与实际指向该 subject 的 Evidence ID 集合完全一致；
4. 不允许 orphan Evidence，也不允许 subject 隐藏未列出的 Evidence；
5. 同一个 Evidence 只能绑定一个 subject；
6. polarity 必须保留，不能相互抵消或自动删除。

### 14.3 Signal / Issue / Hypothesis references

1. `SecurityIssue.signal_ids[]` 必须全部存在；
2. Signal 可以暂未进入任何 Issue，也可以在 Fusion 前被多个候选 Issue 引用；本 Contract 不决定聚类算法；
3. `VulnerabilityHypothesis.issue_id` 必须存在；
4. Hypothesis 的每个 `cwe_id` 必须存在于所属 Issue 的 `cwe_ids`；Issue CWE 为空时 Hypothesis CWE 也必须为空；
5. Signal CWE 不强制等于 Issue CWE，避免 Contract 越权实现分类算法；
6. Issue primary location、Hypothesis target/source/path 不强制等同于 Signal location；它们表达不同层级事实。

### 14.4 Evidence dependency DAG

1. dependency 必须指向 bundle 内 Evidence；
2. 不允许 self dependency；
3. 不允许任意长度循环；
4. `depends_on` Evidence level 的数值不得高于当前 Evidence level；
5. 多个 Evidence 可以共享同一 dependency；
6. `independence_key` 相同是合法的相关证据事实，不得自动去重或增加独立证据计数；Fusion 算法必须在 #61 实现。

### 14.5 Static status consistency

只统计绑定当前 Hypothesis 的 Evidence：

```text
D2 supports present?  D2 refutes present?  允许的 status
no                    no                  proposed | insufficient_static_evidence
yes                   no                  statically_supported
no                    yes                 statically_refuted
yes                   yes                 conflicting_static_evidence
```

- D0/D1 不足以形成 `statically_supported` 或 `statically_refuted`；
- conflict 不能编码为 supported、refuted、clear 或 false；
- `statically_supported` 不得被解释为 runtime reproduced 或 vulnerability verified；
- 基础设施 blocked/inconclusive 不在本 schema 中伪装成 Evidence polarity；其状态属于未来 Workflow/Mining Artifact。

---

## 15. Envelope Binding Contract

### 15.1 Function signatures

```python
def decode_evidence_payload(
    value: Mapping[str, JSONValue],
    *,
    schema_version: SchemaVersion,
) -> EvidenceDomainBundle: ...

def encode_evidence_payload(
    bundle: EvidenceDomainBundle,
) -> dict[str, JSONValue]: ...

def decode_evidence_envelope(
    data: bytes,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> tuple[ArtifactEnvelope, EvidenceDomainBundle]: ...

def encode_evidence_envelope(
    envelope: ArtifactEnvelope,
    bundle: EvidenceDomainBundle,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> bytes: ...
```

### 15.2 Binding rules

`decode_evidence_envelope` 必须：

1. 调用 IP-0001 `decode_envelope`；
2. 要求 `schema_name == EVIDENCE_DOMAIN_SCHEMA_NAME`；
3. 要求 inline `payload`，拒绝 blob-backed envelope；
4. 以 envelope `schema_version` decode bundle；
5. 要求 Evidence 引用的每个 `source_artifact_id` 都存在于 envelope `lineage.artifact_id`；
6. 允许 lineage 包含额外上游 Artifact；
7. 要求 classification 不是 `public`；
8. 要求 retention 不是 `ephemeral`；
9. 返回 `(envelope, bundle)`，不得修改输入。

`encode_evidence_envelope` 必须执行相同 binding，并额外要求：

- `envelope.schema_version == bundle.schema_version`；
- `envelope.payload == encode_evidence_payload(bundle)`；
- `compute_content_digest(bundle payload)` 与 `envelope.content_digest` 使用 `hmac.compare_digest` 相等；
- 最终调用 IP-0001 `encode_envelope`；
- 不自动创建、替换或修补 Envelope。

### 15.3 Classification / retention

Evidence Domain 可能包含安全位置和验证命题：

- allowed classification：`internal`、`sensitive`、`restricted`；
- forbidden classification：`public`；
- allowed retention：`standard`、`audit`、`legal_hold`；
- forbidden retention：`ephemeral`。

不匹配使用 `INVALID_FIELD_VALUE`，field path 分别为 `$.classification` 或 `$.retention_class`。

### 15.4 Lineage

- `source_artifact_ids` 只保存 logical artifact ID；tenant、snapshot、schema 和 content digest 由 Envelope lineage 的 `ArtifactReference` 提供；
- IP-0001 已拒绝跨 tenant、跨 snapshot、自引用、重复和冲突 lineage；IP-0002 不复制这些判断；
- 缺少 source lineage 使用 `INVALID_FIELD_VALUE`，路径指向 `$.payload.evidence[i].source_artifact_ids[j]`；
- raw tool output、LLM response、日志或代码片段不得内联为 Evidence 字段。

---

## 16. Stable Error Mapping and Precedence

IP-0002 不新增错误码。所有失败必须使用现有 `ContractError`，message 由 IP-0001 catalog 决定且不得回显输入。

| 条件 | Error code |
|---|---|
| required field 缺失 | `REQUIRED_FIELD_MISSING` |
| current 4.0 unknown field | `UNKNOWN_FIELD` |
| wrong container/scalar/dataclass/enum instance type | `INVALID_FIELD_TYPE` |
| unknown enum wire value | `UNKNOWN_ENUM_VALUE` |
| path/token/digest/CWE/range/order/duplicate/reference/status 非法 | `INVALID_FIELD_VALUE` |
| 超过数组上限 | `MAX_ARRAY_LENGTH_EXCEEDED` |
| 超过字符串上限 | `MAX_STRING_LENGTH_EXCEEDED` |
| extension key NFC 冲突 | `DUPLICATE_SEMANTIC_FIELD` |
| payload/bundle/content digest 不一致 | `DIGEST_MISMATCH` |
| Envelope tenant/snapshot/lineage 冲突 | 复用 IP-0001 对应 `LINEAGE_*` |
| codec bytes/depth/object/string 限制 | 复用 IP-0001 对应 resource code |

同一输入同时违反多条规则时按以下优先级返回第一项：

1. byte/UTF-8/JSON/resource limit；
2. top-level/container/required/current unknown/schema version；
3. enum 和 scalar type；
4. scalar value、path、range、array limit/order/duplicate；
5. 全局 ID collision；
6. subject、Signal/Issue/Hypothesis 和 source lineage reference；
7. Evidence dependency DAG；
8. Hypothesis static status consistency；
9. Envelope schema/payload/digest/classification/retention binding。

`field_path` 使用 JSONPath-like structural path，例如：

```text
$.signals[0].location.path
$.security_issues[0].signal_ids[1]
$.vulnerability_hypotheses[0].status
$.evidence[2].depends_on_evidence_ids[0]
$.payload.evidence[0].source_artifact_ids[0]
```

不得在 path 中包含真实字段值。

---

## 17. Golden Fixture

文件：

```text
tests/contracts/fixtures/evidence_domain_bundle_v4_golden.json
```

要求：

- UTF-8；
- 单行 canonical JSON；
- 无 BOM；
- 无 trailing newline；
- exactly 3740 bytes；
- payload SHA-256：

```text
1b313f8ce082fd1721805c4eb6d232e104dabaa9e427f9a3f4699659b3796c51
```

权威内容如下；实现者不得为让测试通过而更改字段、值、顺序或摘要：

```json
{"evidence":[{"analysis_family":"static-dataflow","depends_on_evidence_ids":["evidence-issue-0001"],"evidence_id":"evidence-hypothesis-0001","independence_key":"python-dataflow:cli-to-process","level":"D2","location":{"end_column":18,"end_line":10,"path":"src/example.py","start_column":5,"start_line":10,"symbol":"run_command"},"polarity":"supports","producer":"lima-python-dataflow","reason_codes":["SOURCE_TO_SINK_PATH"],"source_artifact_ids":["tool-run-0001"],"subject_id":"hypothesis-0001","subject_kind":"vulnerability_hypothesis","summary":"A deterministic source-to-sink path reaches process execution."},{"analysis_family":"contextual-analysis","depends_on_evidence_ids":["evidence-signal-0001"],"evidence_id":"evidence-issue-0001","independence_key":"cluster:command-injection:cli-to-process","level":"D1","location":{"end_column":18,"end_line":10,"path":"src/example.py","start_column":5,"start_line":10,"symbol":"run_command"},"polarity":"supports","producer":"lima-audit","reason_codes":["CONTEXT_APPLICABLE"],"source_artifact_ids":["tool-run-0001"],"subject_id":"issue-0001","subject_kind":"security_issue","summary":"The matched sink is in a CLI trust boundary."},{"analysis_family":"sast","depends_on_evidence_ids":[],"evidence_id":"evidence-signal-0001","independence_key":"bandit:B602:src/example.py:10","level":"D0","location":{"end_column":18,"end_line":10,"path":"src/example.py","start_column":5,"start_line":10,"symbol":"run_command"},"polarity":"supports","producer":"bandit-1.9.4","reason_codes":["RULE_MATCH"],"source_artifact_ids":["tool-run-0001"],"subject_id":"signal-0001","subject_kind":"signal","summary":"Bandit reported process execution with shell semantics."}],"security_issues":[{"cwe_ids":["CWE-78"],"evidence_ids":["evidence-issue-0001"],"identity_digest":"2222222222222222222222222222222222222222222222222222222222222222","issue_id":"issue-0001","primary_location":{"end_column":18,"end_line":10,"path":"src/example.py","start_column":5,"start_line":10,"symbol":"run_command"},"reason_codes":["ROOT_CAUSE_CLUSTERED_BY_SINK"],"root_cause_class":"command-injection","signal_ids":["signal-0001"],"sink_identity":"python.subprocess.shell","trust_boundary":"cli-to-process"}],"signals":[{"analysis_family":"sast","cwe_ids":["CWE-78"],"evidence_ids":["evidence-signal-0001"],"evidence_kind":"tool-observation","fingerprint":"1111111111111111111111111111111111111111111111111111111111111111","location":{"end_column":18,"end_line":10,"path":"src/example.py","start_column":5,"start_line":10,"symbol":"run_command"},"reason_codes":["RULE_MATCH_PROCESS_EXECUTION"],"rule_id":"B602","signal_id":"signal-0001"}],"vulnerability_hypotheses":[{"capability_requirements":["python","subprocess-observer"],"claim":"Untrusted CLI input may reach a process execution sink.","critical_path":[{"end_column":24,"end_line":20,"path":"src/cli.py","start_column":1,"start_line":20,"symbol":"main"},{"end_column":18,"end_line":10,"path":"src/example.py","start_column":5,"start_line":10,"symbol":"run_command"}],"cwe_ids":["CWE-78"],"evidence_ids":["evidence-hypothesis-0001"],"hypothesis_id":"hypothesis-0001","input_constraints":["argument contains shell metacharacters"],"issue_id":"issue-0001","reason_codes":["STATIC_DATAFLOW_REACHES_PROCESS_SINK"],"required_proof_kind":"runtime_behavior","security_invariant":"Process arguments must not be interpreted by a command shell.","source_locations":[{"end_column":24,"end_line":20,"path":"src/cli.py","start_column":1,"start_line":20,"symbol":"main"}],"status":"statically_supported","target_location":{"end_column":18,"end_line":10,"path":"src/example.py","start_column":5,"start_line":10,"symbol":"run_command"},"trigger_conditions":["attacker controls the CLI argument"]}]}
```

### 17.1 Frozen envelope vector

Envelope integration test使用：

```text
schema_name = lima.evidence-domain
schema_version = 4.0
artifact_id = aep-0001
tenant_id = tenant-1
task_id = task-1
workflow_id = workflow-1
stage_attempt_id = audit-1
repository_snapshot_digest = "3" * 64
producer = lima-audit
created_at = 2026-09-01T00:00:00Z
policy_digest = "5" * 64
toolchain_digest = "6" * 64
content_digest = 1b313f8ce082fd1721805c4eb6d232e104dabaa9e427f9a3f4699659b3796c51
classification = sensitive
retention_class = audit
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

测试必须使用 `unittest`，方法名冻结如下。可以增加 private test helpers，不得减少、重命名或合并这些测试。

### 18.1 `tests/contracts/test_evidence.py`

```text
EvidenceEnumTests
  test_wire_values_are_exact

SourceLocationTests
  test_valid_location_round_trip
  test_rejects_absolute_parent_backslash_empty_and_control_paths
  test_rejects_bool_zero_negative_and_reversed_ranges
  test_requires_column_pair_and_valid_symbol
  test_future_minor_preserves_extensions_and_current_minor_rejects_them

EvidenceObjectTests
  test_signal_round_trip_has_exact_wire_shape
  test_security_issue_round_trip_has_exact_wire_shape
  test_vulnerability_hypothesis_round_trip_has_exact_wire_shape
  test_evidence_record_round_trip_has_exact_wire_shape
  test_rejects_missing_required_fields
  test_rejects_unknown_enum_and_wrong_field_type
  test_rejects_invalid_digest_identifier_rule_cwe_and_reason_code
  test_rejects_control_oversize_and_noncanonical_text
  test_rejects_unsorted_duplicate_and_oversize_set_arrays
  test_defensive_copy_prevents_post_construction_mutation

EvidenceBundleTests
  test_empty_bundle_round_trip_is_valid
  test_golden_bundle_round_trip_and_digest
  test_rejects_unsorted_top_level_arrays_and_duplicate_ids
  test_rejects_cross_namespace_id_collision
  test_rejects_missing_and_mismatched_subject_binding
  test_rejects_unknown_issue_signal_hypothesis_and_evidence_reference
  test_rejects_evidence_self_dependency_cycle_and_higher_level_dependency
  test_allows_shared_dependency_and_correlated_independence_key
  test_rejects_hypothesis_cwe_outside_issue
  test_static_status_requires_matching_d2_polarity
  test_d0_d1_cannot_promote_static_status
  test_rejects_d3_and_d4_in_audit_evidence_bundle
  test_preserves_conflicting_support_and_refutation
  test_future_minor_round_trips_unknown_fields_at_every_level
  test_current_minor_rejects_unknown_fields_at_every_level
  test_payload_has_no_confidence_severity_is_vulnerable_clear_or_verified_fields
```

### 18.2 `tests/contracts/test_evidence_envelope.py`

```text
EvidenceEnvelopeTests
  test_frozen_envelope_encode_decode_is_byte_stable
  test_rejects_wrong_schema_name_and_version_mismatch
  test_rejects_blob_backed_evidence_domain
  test_rejects_payload_bundle_and_content_digest_mismatch
  test_rejects_missing_source_artifact_lineage
  test_allows_additional_valid_lineage
  test_inherits_cross_tenant_cross_snapshot_and_self_reference_rejection
  test_rejects_public_classification_and_ephemeral_retention
  test_tampered_payload_fails_before_domain_promotion
```

### 18.3 `tests/contracts/test_evidence_import_isolation.py`

```text
EvidenceImportIsolationTests
  test_module_public_api_matches_frozen_symbol_set
  test_clean_process_import_has_no_db_network_docker_llm_service_or_legacy_models
  test_module_only_uses_allowed_imports
  test_import_does_not_change_lima_contracts_top_level_public_api
```

### 18.4 Minimum count

IP-0002 必须新增至少 45 个独立 test methods。可以增加更细的测试，但不允许用循环把多种安全边界压缩成一个无法定位的单断言。

---

## 19. Acceptance Criteria and Traceability

| AC | Required behavior | Evidence |
|---|---|---|
| IP2-AC-01 | 16 个 module public symbols、5 个 enum wire vocabulary、6 个 exact constructors 完全冻结 | enum/object/import tests |
| IP2-AC-02 | path、位置、identifier、digest、CWE、reason、text 和资源上限 fail closed | SourceLocation + object negative tests |
| IP2-AC-03 | golden bundle 为 3740 bytes、固定 digest、decode/encode byte-stable | golden test |
| IP2-AC-04 | ID、subject、Issue/Signal/Hypothesis、Evidence dependency 全图无悬空、隐藏、循环或越级依赖 | bundle graph tests |
| IP2-AC-05 | D0/D1/D2 和 polarity 正确约束 static status；conflict 被保留；D3/D4 不可在 Audit bundle 中伪造 | status/level tests |
| IP2-AC-06 | Evidence payload 与 Envelope schema/version/digest/lineage/classification/retention 一致 | envelope tests |
| IP2-AC-07 | 4.0 unknown field 拒绝，未来 4.x optional field 在所有层级无损 round-trip，unknown enum/required 缺失仍拒绝 | compatibility tests |
| IP2-AC-08 | 无 confidence/severity/boolean truth/clear/verified 字段，无 raw snippet 字段 | exact wire shape + forbidden-key recursive assertion |
| IP2-AC-09 | 模块为 stdlib-only leaf import，不更改 IP-0001 顶层 API、错误码或 wire contract | import isolation + git diff |
| IP2-AC-10 | 只新增 5 个 allowlist 文件，0 existing modifications，0 dependencies，全量测试无新增失败 | file boundary + full regression |

任一 AC 无机器证据时状态不是 DONE。

---

## 20. 强制实现顺序

必须测试先行，按以下 slice：

1. 建立 4 个测试/fixture 文件和 `test_evidence.py` 的 enum/location RED tests；
2. 在 `evidence.py` 实现常量、枚举、通用 validators 和 `SourceLocation`；
3. 为 `EvidenceRecord/Signal/SecurityIssue/VulnerabilityHypothesis` 写 exact shape 与 negative RED tests，再实现；
4. 为 bundle reference graph、cycle 和 status 写 RED tests，再实现 `EvidenceDomainBundle`；
5. 生成并逐字验证 frozen golden fixture；
6. 为 Envelope binding 写 RED tests，再实现四个 encode/decode functions；
7. 写 import isolation 和 forbidden-key tests；
8. 运行 Slice Gate；
9. 运行 Compatibility Gate、全量回归和 File Boundary Gate；
10. 输出完整 Completion Summary。

不得先写完实现再补测试。测试发现 Packet 冲突时停止，不得修改 frozen fixture 或放宽断言。

---

## 21. Done Commands

### 21.1 Baseline（编码前）

```powershell
python -m compileall -q lima scripts tests
python -m unittest discover -s tests/contracts -v
python -m unittest -v tests.test_repository_source tests.test_task_failure
```

预期基线：contracts 39 PASS；定向兼容 29 PASS。若数量变化，以最新 `main` 实际结果为准并记录差异。

### 21.2 Slice Gate

```powershell
python -m compileall -q lima/contracts tests/contracts
python -m unittest discover -s tests/contracts -v
python -m ruff check lima/contracts/evidence.py tests/contracts/test_evidence.py tests/contracts/test_evidence_envelope.py tests/contracts/test_evidence_import_isolation.py
python -m bandit -q -r lima/contracts/evidence.py
git diff --check
```

### 21.3 Compatibility Gate

```powershell
python -m unittest -v tests.test_repository_source tests.test_task_failure
python -m unittest discover -s tests -v
```

基线参考：384 tests，0 failed，1 个 Windows symlink privilege 既有 skip。任何新增 failure/skip 必须解释；不能通过修改 legacy 测试解决。

Python 3.11/3.12 应由 CI matrix 验证；本机缺少某版本时如实记录，不得声称已实测。

### 21.4 File Boundary Gate

```powershell
git diff --name-only --diff-filter=ACMRTUXB origin/main...HEAD
git diff --check origin/main...HEAD
```

第一条输出必须恰好为 6.1 的 5 个新增文件，不得出现 modified existing file。

### 21.5 Optional release-level gate

维护者或 CI 可运行：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 test
```

普通 Agent 不因 Docker/宿主环境不可用而擅自改变产品代码。

---

## 22. Security and Compatibility Invariants

- 不可信 repository 数据只能以相对路径、受限文本和 Artifact refs 表达；
- 错误信息不得回显原始 payload、summary、claim、path value、secret 或 snippet；
- Audit Evidence 不能编码 verified/clear/false；
- D3/D4 不能由本模块生成或接受；
- `statically_refuted` 必须有 D2 refuting evidence，不能由 LLM clean verdict 单独产生；
- conflict、unknown、insufficient、blocked 不得被静默折叠；
- Evidence source 必须出现在同 tenant/snapshot Envelope lineage；
- public/ephemeral Envelope 不得承载 Evidence Domain；
- 未知 major、unknown enum、digest mismatch 和 cross-boundary reference fail closed；
- 所有 ID、时间、fingerprint 和 identity digest 由调用方提供；
- 不新增网络、磁盘、DB、Docker、subprocess、凭据或付费模型权限；
- 不改变 legacy 1.6.0 行为；
- 不通过 future-minor extension 绕过 required fields 或 enum validation。

---

## 23. Stop Conditions / Decision Request

出现以下任一情况必须停止：

1. 本 Packet 或正式交接书尚未合并到 `origin/main`；
2. 最新 `main` 已出现同名 `evidence.py` 或其他 Owner 的冲突实现；
3. 授权基线不包含 PR #98 合并提交；
4. 需要修改 `__init__.py`、common、codec、errors 或任一 forbidden 文件；
5. 需要新增第三方依赖、I/O、网络、数据库、Docker、subprocess 或环境权限；
6. exact constructor、wire shape、enum、错误优先级或 future-minor 行为存在两个合理答案；
7. frozen fixture 的 3740 bytes 或 digest 无法由 IP-0001 codec 重现；
8. 只能允许 D3/D4、增加 vulnerability boolean、severity/confidence 或削弱 graph validation 才能继续；
9. baseline/全量回归失败且无法归因；
10. Packet 测试不能证明某个 AC；
11. 发现工作实际需要 adapter、Fusion、AEP/VEP 或生产接线。

Decision Request 格式：

```text
Packet/规则位置：
实际代码证据：
最小复现命令：
为什么无法在 5-file allowlist 内解决：
可选方案：
各方案的兼容、安全、工期影响：
Agent 建议：
```

维护者更新 Packet/Decision Record 前不得越界继续。

---

## 24. Git, Commit and PR Contract

推荐 commit：

```text
feat: add deterministic evidence domain contracts
```

推荐 PR 标题：

```text
feat: add deterministic evidence domain contracts
```

PR 正文必须：

- 只写 `Related to #58`；
- 不出现任何会自动关闭 #58 的 keyword；
- 附 AC → Test → Result；
- 附真实命令、退出码、passed/failed/skipped；
- 明确 5 added / 0 modified / 0 dependencies；
- 明确 no production integration、no D3/D4 promotion、no top-level public API change；
- 等待独立 Reviewer 和 `merge-gate`。

Implementation Agent 不合并自己的 PR，不删除分支/worktree，不修改 Issue。

---

## 25. Completion Summary Template

```markdown
## IP-0002 Completion Summary

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
- Public API: `lima.contracts.evidence` only
- Contract deviations: none | <Decision Request>

### Acceptance evidence
| AC | Test/command | Result |
|---|---|---|
| IP2-AC-01 | | |
| IP2-AC-02 | | |
| IP2-AC-03 | | |
| IP2-AC-04 | | |
| IP2-AC-05 | | |
| IP2-AC-06 | | |
| IP2-AC-07 | | |
| IP2-AC-08 | | |
| IP2-AC-09 | | |
| IP2-AC-10 | | |

### Commands and actual results
- Command:
  - Exit code:
  - Passed/failed/skipped:

### Security and compatibility
- Fail-closed graph behavior:
- D3/D4 promotion prevention:
- Envelope lineage/classification binding:
- Secret/input echo review:
- Import isolation:
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

- [ ] base 包含 `d3e73d9`；
- [ ] 只新增 5 个 allowlist 文件；
- [ ] `lima.contracts.__all__` 和 28 个 IP-0001 error codes 未改变；
- [ ] module public API 恰好 16 symbols；
- [ ] exact constructors/wire shapes 无漂移；
- [ ] golden fixture 3740 bytes、无 BOM/newline、digest 正确；
- [ ] current/future-minor matrix 通过；
- [ ] graph reference、cycle、status、D3/D4 negative tests 通过；
- [ ] Envelope schema/digest/lineage/classification/retention tests 通过；
- [ ] 无 confidence/severity/verified/clear/is_vulnerable/raw snippet 字段；
- [ ] import isolation 和 no dependency 通过；
- [ ] 全量回归无新增失败；
- [ ] File Boundary Gate 恰好 5 文件；
- [ ] Completion Summary 可复现；
- [ ] 独立 Review 与 `merge-gate` 通过；
- [ ] PR 未关闭 #58；
- [ ] 未启动 IP-0003 或生产接线。

---

## 27. Packet 完成定义

只有全部 10 个 AC、有界负向测试、golden fixture、Envelope consumer test、import isolation、完整命令证据、独立 Review 和 `merge-gate` 全部满足，IP-0002 才能标记 DONE。

IP-0002 合并后，协调者必须在最新 `main` 上做 post-merge verification，并让 IP-0003 对 `EvidenceDomainBundle` 做只读消费者评审。当前 Agent 不自动继续 IP-0003。
