# LIMA Implementation Packet IP-0001：Contract Foundation

> 本文是 Coding Agent 的规范性任务输入，不是新的 GitHub Issue，也不修改现有 Issue。
> Source Issue：[GitHub #58](https://github.com/agent-sec-labs/LIMA/issues/58)（仅作需求来源；#58 仍是 Size L 的设计容器）。
> Packet 状态：`READY-FOR-CODE`
> Delivery queue：`NOW`（全局 WIP=1）
> 预计规模：1 个 Coding Agent，1 个 PR，1～3 个工作日
> 冻结日期：2026-09-01
> 代码基线：`agent-sec-labs/LIMA main@13c8e88469dacf738420a037d31b9033ede45d43`
> 代码事实说明：`bf7d79d..13c8e88` 之间只有规划、Issue 模板和文档变更，生产代码基线未变化。

---

## 0. 执行决策

当前不再扩充或修改 GitHub Issues。现有 Epic/Issues 继续作为方向和需求库存，Coding Agent 只消费经过冻结的 Implementation Packet。

恢复队列固定为：

```text
NOW（只允许 1 个）
IP-0001 Contract Foundation

NEXT（尚未 Ready-for-Code，不得实现）
IP-0002 Evidence Domain
IP-0003 Repository Profile / RAM Foundation

LATER
其余 Audit / Mining / Repair / Sandbox / Registry / Frontend 工作
```

IP-0001 是 #58 的第一个实施切片，不等于完成 #58，也不得以 `Closes #58` 关闭 #58。

---

## 1. 为什么这是当前最小关键路径

当前代码中不存在 `lima/contracts/` 或 `tests/contracts/`。现有 `lima/models.py` 的 `EvidenceRecord`、`Finding`、`ReviewReport` 服务于 legacy 扫描结果，不能作为 Audit、Mining、Repair 三阶段交换契约。直接开发 RAM、AEP、VEP、RVR、Workflow 或 Sandbox，会迫使各实现者自行决定序列化、版本、摘要和错误语义。

本切片只解决一个不确定性：

> LIMA 能否先建立一个确定性、无副作用、可拒绝篡改和不兼容输入的最小 Artifact 契约底座？

若答案为是，后续 Packet 才能复用同一 Envelope、codec 和错误目录；若答案为否，应在该小切片内修正，而不是让错误传播到所有阶段。

### 1.1 Iteration Hypothesis

如果 Artifact 的 Envelope、canonical encoding、digest 和失败语义被固定为一个 stdlib-only 包，那么后续领域模型可以基于 fixture 并行开发，不再各自实现 JSON/digest，也不必修改 `lima/models.py`、store、service 或 API。

### 1.2 Measurement

- 相同语义 JSON 的 canonical bytes 与 digest 一致率：100%。
- 本 Packet 定义的非法输入拒绝率：100%。
- `lima.contracts` 导入期间 DB、网络、Docker、LLM、生产 service 加载次数：0。
- 修改现有生产 Python 文件数量：0。
- 新增外部依赖数量：0。
- 指定测试与全量现有单测通过率：100%。

---

## 2. Goal

本次只完成：

1. 建立 `lima.contracts` Python 包；
2. 实现稳定的 Contract error 类型和错误码；
3. 实现受资源限制的 canonical JSON 子集 codec；
4. 实现 `SchemaVersion`、Artifact reference、blob reference 与 `ArtifactEnvelope`；
5. 实现 inline payload / blob reference 二选一和 content digest 校验；
6. 提供 golden、negative、round-trip、资源边界与 import-isolation 单测；
7. 暴露冻结的最小公共 API。

---

## 3. Non-goals

本次明确不做：

- 不实现 `Signal`、`SecurityIssue`、`VulnerabilityHypothesis`；
- 不实现 RAM、AEP、VEP、RVR 或任何 Workflow/Stage schema；
- 不实现 JSON Schema 文件或 legacy adapter；
- 不接 SQLite/PostgreSQL、Artifact Registry、Blob Store 或缓存；
- 不修改 API、Service、Queue、Scanner、Sandbox 或前端；
- 不调用 LLM，不访问网络，不运行 Docker，不读取环境变量；
- 不生成 artifact ID、时间或随机数；这些值必须由调用方显式传入；
- 不修改或替换 legacy `Finding`、`EvidenceRecord`、`ReviewReport`；
- 不验证跨多个 Artifact 的完整有向图环；本次只拒绝 self-reference、重复与单 Envelope 内的引用冲突；
- 不为未来领域对象设计字段；领域字段属于后续 Packet；
- 不新增第三方 canonical JSON 库；v4.0 使用本文冻结的可移植 JSON 子集。

遇到 Non-goal 所需能力时必须停止并提交 Decision Request，不得“顺手实现”。

---

## 4. 工作树与分支前置条件

Coding Agent 开始前必须确认：

```powershell
git fetch origin
git switch main
git pull --ff-only origin main
git rev-parse HEAD
git status --short
```

要求：

- `HEAD` 至少包含 `13c8e88469dacf738420a037d31b9033ede45d43`；
- 从最新 `main` 创建独立分支，建议 `feat/contract-foundation`；
- 不在 `codex/v4-issue-contract-hardening` 或其他规划分支上实现；
- 若工作树包含用户未提交文件，不得删除、覆盖或纳入本 PR；
- 开工前运行第 15.1 节 baseline commands，并记录结果。

若远端 `main` 已新增 `lima/contracts/` 或 `tests/contracts/`，立即停止；Packet 必须重新核对文件 Owner，不允许覆盖他人实现。

---

## 5. 文件边界

### 5.1 Files to Add

```text
lima/contracts/__init__.py
lima/contracts/errors.py
lima/contracts/codec.py
lima/contracts/common.py
tests/contracts/__init__.py
tests/contracts/test_errors.py
tests/contracts/test_codec.py
tests/contracts/test_common.py
tests/contracts/test_import_isolation.py
tests/contracts/fixtures/artifact_envelope_v4_golden.json
```

### 5.2 Files Allowed to Modify

```text
无
```

本切片全部使用新增文件。若 setuptools 包发现、测试发现或 lint 需要修改现有文件，先证明原因并停止请求维护者决策；不得自行扩大 allowlist。

### 5.3 Files Forbidden

除第 5.1 节明确列出的文件外全部只读，特别禁止：

```text
lima/models.py
lima/task_progress.py
lima/task_failure.py
lima/store.py
lima/postgres_store.py
lima/task_queue.py
lima/service.py
lima/api.py
lima/repository_*.py
lima/workspace.py
lima/adjudication.py
lima/security_repair.py
lima/repair_*.py
requirements.txt
pyproject.toml
Dockerfile
docker-compose.yml
frontend/
schemas/
docs/LIMA_Implementation_Packet_IP-0001_Contract_Foundation.md
```

禁止批量格式化或修复历史 Ruff/Bandit 债务。

### 5.4 Ownership

- `lima/contracts/{errors,codec,common}.py`：本 Packet 唯一 Owner；
- legacy model、持久化和业务接线：无写权限；
- 同一时间不得启动第二个 Agent 修改 `lima/contracts/`；
- Review Agent 只审查，不直接修补；修补返回原 Coding Agent。

### 5.5 Symbol-to-File Map

| File | 唯一职责与 Symbols |
|---|---|
| `lima/contracts/errors.py` | `ContractErrorCode`、stable message catalog、`ContractError` |
| `lima/contracts/codec.py` | `JSONValue`、`ContractLimits`、`DEFAULT_LIMITS`、`canonical_decode`、`canonical_encode`、`compute_content_digest` |
| `lima/contracts/common.py` | version constants、`SchemaVersion`、两个 Enum、`ArtifactReference`、`ArtifactBlobReference`、`ArtifactEnvelope`、`decode_envelope`、`encode_envelope` |
| `lima/contracts/__init__.py` | 仅从上述模块重导出冻结 public API；不包含实现逻辑 |

依赖方向固定为：

```text
errors.py
   ↑
codec.py
   ↑
common.py
   ↑
__init__.py
```

禁止反向 import、循环 import 或把实现重新放入 `__init__.py`。

---

## 6. Allowed / Forbidden Dependencies

### 6.1 Allowed

仅允许 Python 3.11+ 标准库：

```text
collections.abc
copy
dataclasses
datetime
enum
hashlib
hmac
json
re
typing
unicodedata
```

测试额外允许：

```text
pathlib
subprocess
sys
unittest
```

### 6.2 Forbidden

```text
pydantic / marshmallow / jsonschema
psycopg / sqlite3 / redis
requests / urllib / socket
docker / subprocess（生产包中）
lima.models / lima.service / lima.store / lima.api
LLM/provider/Agent 模块
filesystem I/O（生产包中）
环境变量、系统时间、随机数、UUID 自动生成
```

`lima.contracts` 必须是纯内存、确定性、无副作用的 leaf package。

---

## 7. 冻结的公共 Symbols

`lima/contracts/__init__.py` 只能重导出以下 Symbols；不得新增“方便使用”的 public helper：

```python
CURRENT_SCHEMA_MAJOR: Final[int]
CURRENT_SCHEMA_MINOR: Final[int]
DEFAULT_LIMITS: Final[ContractLimits]

JSONValue: TypeAlias

class ContractErrorCode(str, Enum): ...
class ContractError(ValueError): ...

@dataclass(frozen=True, slots=True)
class ContractLimits: ...

@dataclass(frozen=True, slots=True)
class SchemaVersion: ...

class ArtifactClassification(str, Enum): ...
class RetentionClass(str, Enum): ...

@dataclass(frozen=True, slots=True)
class ArtifactReference: ...

@dataclass(frozen=True, slots=True)
class ArtifactBlobReference: ...

@dataclass(frozen=True, slots=True)
class ArtifactEnvelope: ...

def canonical_decode(data: bytes, *, limits: ContractLimits = DEFAULT_LIMITS) -> JSONValue: ...
def canonical_encode(value: JSONValue, *, limits: ContractLimits = DEFAULT_LIMITS) -> bytes: ...
def compute_content_digest(value: JSONValue | bytes, *, limits: ContractLimits = DEFAULT_LIMITS) -> str: ...
def decode_envelope(data: bytes, *, limits: ContractLimits = DEFAULT_LIMITS) -> ArtifactEnvelope: ...
def encode_envelope(envelope: ArtifactEnvelope, *, limits: ContractLimits = DEFAULT_LIMITS) -> bytes: ...
```

`__all__` 必须与上述 public symbols 完全一致。内部校验函数使用前导下划线，不对外导出。

### 7.1 Exact Constructors and Defaults

公共构造器、字段顺序与默认值固定如下；Coding Agent 不得调整参数顺序、改成 keyword-only 或增加 factory/service 参数：

```python
@dataclass(frozen=True, slots=True)
class ContractLimits:
    max_input_bytes: int = 1_048_576
    max_depth: int = 32
    max_array_items: int = 10_000
    max_object_fields: int = 1_000
    max_string_bytes: int = 262_144


class ContractError(ValueError):
    def __init__(
        self,
        code: ContractErrorCode,
        field_path: str = "",
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class SchemaVersion:
    major: int
    minor: int


@dataclass(frozen=True, slots=True)
class ArtifactReference:
    schema_name: str
    schema_version: SchemaVersion
    artifact_id: str
    tenant_id: str
    repository_snapshot_digest: str
    content_digest: str
    extensions: dict[str, JSONValue] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ArtifactBlobReference:
    blob_id: str
    content_digest: str
    size_bytes: int
    media_type: str
    extensions: dict[str, JSONValue] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ArtifactEnvelope:
    schema_name: str
    schema_version: SchemaVersion
    artifact_id: str
    tenant_id: str
    task_id: str
    workflow_id: str
    stage_attempt_id: str
    repository_snapshot_digest: str
    producer: str
    created_at: str
    policy_digest: str
    toolchain_digest: str
    content_digest: str
    classification: ArtifactClassification
    retention_class: RetentionClass
    payload: dict[str, JSONValue] | None = None
    blob_ref: ArtifactBlobReference | None = None
    lineage: tuple[ArtifactReference, ...] = ()
    supersedes: ArtifactReference | None = None
    coverage_gaps: tuple[str, ...] = ()
    extensions: dict[str, JSONValue] = field(default_factory=dict)
```

`extensions` 是内存中的 forward-compatibility 容器，不是名为 `extensions` 的 wire 字段。`to_dict()` 将其中键值合并回对象本层；若 extension 与已知字段冲突，返回 `DUPLICATE_SEMANTIC_FIELD`。

---

## 8. Canonical JSON v4.0 Contract

### 8.1 JSONValue

允许的值域：

```python
None | bool | int | str | list[JSONValue] | dict[str, JSONValue]
```

冻结规则：

- 整数必须在有符号 64 位范围 `[-9223372036854775808, 9223372036854775807]`；
- 所有 `float`（包括有限值、NaN、Infinity、-Infinity）均拒绝；
- v4.0 不允许 binary float，避免不同语言/运行时产生不同摘要；需要小数的后续领域字段必须使用有单位整数，例如 basis points、milliseconds 或 bytes；
- 不允许 tuple、set、bytes、自定义对象、Enum 实例或隐式 `default=str`；
- object key 必须是字符串；
- 字符串和值、object key 均先规范化为 Unicode NFC；
- raw duplicate key 和 NFC 后碰撞的 key 都拒绝；
- JSON whitespace、字段顺序、LF/CRLF 不影响 decode 后的 canonical bytes；
- 输出使用 UTF-8、`ensure_ascii=False`、sorted keys、紧凑 separators，不附加 BOM 或尾随换行；
- 不得使用 `json.dumps(..., default=str)`。

### 8.2 Depth 定义

- 顶层 scalar 的 depth 为 0；
- 顶层 object/list 的 depth 为 1；
- 每进入一层 object/list，depth 加 1；
- `[[]]` 的 depth 为 2；
- 超过上限而不是等于上限时拒绝。

### 8.3 Default Resource Limits

`ContractLimits` 字段和默认值固定为：

| 字段 | 默认值 | 语义 |
|---|---:|---|
| `max_input_bytes` | 1,048,576 | decode 原始 bytes 与 encode 最终 bytes 的上限 |
| `max_depth` | 32 | object/list 最大嵌套深度 |
| `max_array_items` | 10,000 | 每个 array 的元素上限 |
| `max_object_fields` | 1,000 | 每个 object 的字段上限 |
| `max_string_bytes` | 262,144 | 单个 NFC 字符串或 key 的 UTF-8 字节上限 |

所有 limit 必须为正整数；非法 `ContractLimits` 在构造时抛出 code 为 `INVALID_LIMIT` 的 `ContractError`。不得通过截断输入“通过”校验。

### 8.4 Digest

```text
sha256(canonical UTF-8 bytes)
→ 64 位小写十六进制，不带 sha256: 前缀
```

- `compute_content_digest(JSONValue)` 对 canonical bytes 求摘要；
- `compute_content_digest(bytes)` 对原始 bytes 求摘要；
- `compute_content_digest(bytes)` 同样执行 `max_input_bytes`，超限返回 `RESOURCE_LIMIT_EXCEEDED`；
- 不接受 `bytearray`、文件对象或字符串形式 bytes；
- `content_digest` 只覆盖 inline payload 或 blob 原始内容，不覆盖 Envelope transport metadata；
- consumer 必须同时校验 Envelope 结构和 `content_digest`，不得只相信调用方提供的摘要。

---

## 9. Common Contract

### 9.1 SchemaVersion

字段：

```python
major: int
minor: int
```

行为：

- wire format 固定为字符串 `"<major>.<minor>"`；
- major 必须 `>=1`，minor 必须 `>=0`，均不得是 bool；
- 当前实现版本固定 `4.0`；
- major 非 4：`SCHEMA_UNKNOWN_MAJOR`；
- `4.0` 的未知字段：`UNKNOWN_FIELD`；
- `4.n (n>0)` 的未知 optional 字段保存在各对象的 `extensions` 中并原样语义 round-trip；
- 直接构造 `4.0` 对象时 `extensions` 非空同样返回 `UNKNOWN_FIELD`，不能绕过 wire validation；
- 同 major 新增 required 字段属于破坏性变更，禁止；必须升级 major；
- extension key 仍执行 UTF-8、NFC、duplicate 和资源限制。

Public methods：

```python
@classmethod
def parse(cls, value: object) -> SchemaVersion: ...

def __str__(self) -> str: ...
```

### 9.2 ArtifactClassification

wire values 固定为：

```text
public
internal
sensitive
restricted
```

### 9.3 RetentionClass

wire values 固定为：

```text
ephemeral
standard
audit
legal_hold
```

未知 enum fail closed，不得降级到默认值。

### 9.4 ArtifactReference

字段固定为：

```python
schema_name: str
schema_version: SchemaVersion
artifact_id: str
tenant_id: str
repository_snapshot_digest: str
content_digest: str
extensions: dict[str, JSONValue]
```

Public methods：

```python
@classmethod
def from_dict(cls, value: Mapping[str, JSONValue]) -> ArtifactReference: ...

def to_dict(self) -> dict[str, JSONValue]: ...
```

Reference 必须携带 tenant 和 snapshot identity，使 Envelope 可以在不访问 Registry 的情况下拒绝明显的跨 tenant/cross-snapshot 引用。

### 9.5 ArtifactBlobReference

字段固定为：

```python
blob_id: str
content_digest: str
size_bytes: int
media_type: str
extensions: dict[str, JSONValue]
```

Public methods：

```python
@classmethod
def from_dict(
    cls,
    value: Mapping[str, JSONValue],
    *,
    envelope_version: SchemaVersion,
) -> ArtifactBlobReference: ...

def to_dict(self) -> dict[str, JSONValue]: ...
```

约束：

- `blob_id` 是逻辑 ID，不是路径或 URL；
- wire contract 不接受本地绝对路径、`file://` 或下载 URL；
- `size_bytes` 范围为 `0..9223372036854775807`；
- `media_type` 必须匹配 `^[a-z0-9][a-z0-9!#$&^_.+-]{0,62}/[a-z0-9][a-z0-9!#$&^_.+-]{0,62}$`，总长度不超过 127 ASCII bytes；
- Blob 获取、鉴权和 digest 重算属于后续 Artifact Registry Packet。

### 9.6 ArtifactEnvelope

字段固定为：

```python
schema_name: str
schema_version: SchemaVersion
artifact_id: str
tenant_id: str
task_id: str
workflow_id: str
stage_attempt_id: str
repository_snapshot_digest: str
producer: str
created_at: str
policy_digest: str
toolchain_digest: str
content_digest: str
classification: ArtifactClassification
retention_class: RetentionClass
payload: dict[str, JSONValue] | None
blob_ref: ArtifactBlobReference | None
lineage: tuple[ArtifactReference, ...]
supersedes: ArtifactReference | None
coverage_gaps: tuple[str, ...]
extensions: dict[str, JSONValue]
```

Public methods：

```python
@classmethod
def from_dict(cls, value: Mapping[str, JSONValue]) -> ArtifactEnvelope: ...

def to_dict(self) -> dict[str, JSONValue]: ...
```

Canonical wire fields 使用上面的 snake_case 名称。`schema_name` 是 Artifact type 的唯一规范字段；禁止同时增加 `artifact_type`。这解决当前规划文档中 `schema_name`/`artifact_type` 的歧义。

### 9.7 Field Validation

- `ArtifactReference` wire required fields：`schema_name`、`schema_version`、`artifact_id`、`tenant_id`、`repository_snapshot_digest`、`content_digest`；
- `ArtifactBlobReference` wire required fields：`blob_id`、`content_digest`、`size_bytes`、`media_type`；
- `ArtifactEnvelope` wire required fields：从 `schema_name` 到 `retention_class` 的 15 个 base 字段（包含 `content_digest`），以及 `lineage`、`supersedes`、`coverage_gaps`；此外 `payload`/`blob_ref` 必须恰有一项；
- `from_dict()` 不使用 dataclass 默认值掩盖缺失的 wire required 字段；构造器默认值只用于受信调用方显式构造新 Envelope；
- `schema_name`：小写 ASCII，匹配 `^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`，最多 128 bytes；
- 所有 `*_id` 和 `producer`：非空、最多 128 UTF-8 bytes、无控制字符；ID 匹配 `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`；
- 所有 digest：严格匹配 `^[0-9a-f]{64}$`；
- `created_at`：输入只接受 `YYYY-MM-DDTHH:MM:SS`、可选 1～6 位小数秒、随后大写 `Z` 或 `±HH:MM`；拒绝 lowercase `z`、naive datetime、offset seconds、超过 6 位小数和 leap second；规范化为 UTC、固定六位微秒的 `YYYY-MM-DDTHH:MM:SS.ffffffZ`；
- `payload` 必须是 object；
- `payload` 与 `blob_ref` 必须且只能存在一个；
- inline payload 的 `content_digest` 必须等于 `compute_content_digest(payload)`；
- blob 的 Envelope `content_digest` 必须等于 `blob_ref.content_digest`；
- `lineage` 最多 128 项；`coverage_gaps` 最多 256 项；
- coverage gap 必须非空、NFC、无控制字符、每项最多 1,024 UTF-8 bytes，重复项拒绝；
- `to_dict()` 必须始终输出 `lineage`、`supersedes`、`coverage_gaps`；
- wire 输出只包含 `payload` 或 `blob_ref` 中实际存在的一项，不输出另一个 null 字段；
- construction/decode 必须 defensive-copy nested payload/extensions；调用方后续修改原 dict 不得改变 Envelope 的 `to_dict()`、equality 或 digest 结果。

`from_dict()` 与 `to_dict()` 的 field names 和 wire shape 是 public contract。解析过程中不得忽略未知字段、拼写错误或 extra positional data。

### 9.8 Lineage Invariants

对 `lineage` 和 `supersedes`：

- referenced `artifact_id` 不得等于当前 Envelope `artifact_id`；
- referenced `tenant_id` 必须等于 Envelope `tenant_id`；
- referenced `repository_snapshot_digest` 必须等于 Envelope 的 snapshot digest；
- lineage 中完全相同的 reference 拒绝；
- lineage 中相同 artifact ID 对应不同 digest/schema identity 时拒绝；
- `supersedes` 与 lineage 内相同 ID 的 identity 不一致时拒绝；
- 不联网、不查 store；多跳 cycle 检测属于 Artifact Registry，不能在本 Packet 中伪造。

---

## 10. Stable Error Contract

### 10.1 ContractError

```python
class ContractError(ValueError):
    code: ContractErrorCode
    field_path: str

    def to_dict(self) -> dict[str, str]: ...
```

`to_dict()` 固定输出：

```json
{
  "code": "<stable enum value>",
  "field_path": "<JSONPath-like path or empty string>",
  "message": "<catalog-owned stable English message>"
}
```

错误中禁止包含 raw payload、secret、完整输入、绝对路径或 `repr(value)`。`field_path` 只允许结构位置，例如 `$.lineage[0].tenant_id`。

### 10.2 ContractErrorCode

wire values 固定为：

```text
INVALID_LIMIT
INVALID_UTF8
INVALID_JSON
TOP_LEVEL_NOT_OBJECT
DUPLICATE_FIELD
DUPLICATE_SEMANTIC_FIELD
UNSUPPORTED_VALUE_TYPE
INTEGER_OUT_OF_RANGE
REQUIRED_FIELD_MISSING
UNKNOWN_FIELD
INVALID_FIELD_TYPE
INVALID_FIELD_VALUE
UNKNOWN_ENUM_VALUE
SCHEMA_VERSION_INVALID
SCHEMA_UNKNOWN_MAJOR
RESOURCE_LIMIT_EXCEEDED
MAX_DEPTH_EXCEEDED
MAX_ARRAY_LENGTH_EXCEEDED
MAX_OBJECT_FIELDS_EXCEEDED
MAX_STRING_LENGTH_EXCEEDED
INLINE_OR_BLOB_REQUIRED
INLINE_AND_BLOB_CONFLICT
DIGEST_MISMATCH
LINEAGE_DUPLICATE
LINEAGE_CONFLICT
LINEAGE_SELF_REFERENCE
LINEAGE_TENANT_MISMATCH
LINEAGE_SNAPSHOT_MISMATCH
COVERAGE_GAP_DUPLICATE
```

同一非法输入只能选择最具体的错误码。优先顺序：raw bytes/resource → JSON syntax/duplicate → generic JSON type/limit → version/required/unknown field → field type/value/enum → inline/blob → digest → lineage/coverage。

错误码与 public message 一一固定如下：

| Code | Stable message |
|---|---|
| `INVALID_LIMIT` | `Contract resource limit is invalid.` |
| `INVALID_UTF8` | `Input is not valid UTF-8.` |
| `INVALID_JSON` | `Input is not valid JSON.` |
| `TOP_LEVEL_NOT_OBJECT` | `Envelope input must be a JSON object.` |
| `DUPLICATE_FIELD` | `JSON object contains a duplicate field.` |
| `DUPLICATE_SEMANTIC_FIELD` | `JSON object contains fields that normalize to the same name.` |
| `UNSUPPORTED_VALUE_TYPE` | `Value type is not supported by canonical JSON v4.0.` |
| `INTEGER_OUT_OF_RANGE` | `Integer is outside the signed 64-bit range.` |
| `REQUIRED_FIELD_MISSING` | `A required contract field is missing.` |
| `UNKNOWN_FIELD` | `Contract contains an unknown field for this schema version.` |
| `INVALID_FIELD_TYPE` | `Contract field has an invalid type.` |
| `INVALID_FIELD_VALUE` | `Contract field has an invalid value.` |
| `UNKNOWN_ENUM_VALUE` | `Contract field contains an unknown enum value.` |
| `SCHEMA_VERSION_INVALID` | `Schema version is invalid.` |
| `SCHEMA_UNKNOWN_MAJOR` | `Schema major version is not supported.` |
| `RESOURCE_LIMIT_EXCEEDED` | `Contract input exceeds the byte limit.` |
| `MAX_DEPTH_EXCEEDED` | `Contract input exceeds the nesting depth limit.` |
| `MAX_ARRAY_LENGTH_EXCEEDED` | `Contract array exceeds the item limit.` |
| `MAX_OBJECT_FIELDS_EXCEEDED` | `Contract object exceeds the field limit.` |
| `MAX_STRING_LENGTH_EXCEEDED` | `Contract string exceeds the UTF-8 byte limit.` |
| `INLINE_OR_BLOB_REQUIRED` | `Envelope requires inline payload or a blob reference.` |
| `INLINE_AND_BLOB_CONFLICT` | `Envelope cannot contain both inline payload and a blob reference.` |
| `DIGEST_MISMATCH` | `Declared content digest does not match authoritative content.` |
| `LINEAGE_DUPLICATE` | `Envelope lineage contains a duplicate reference.` |
| `LINEAGE_CONFLICT` | `Envelope lineage contains conflicting identities for one artifact.` |
| `LINEAGE_SELF_REFERENCE` | `Envelope cannot reference itself.` |
| `LINEAGE_TENANT_MISMATCH` | `Envelope reference belongs to a different tenant.` |
| `LINEAGE_SNAPSHOT_MISMATCH` | `Envelope reference belongs to a different repository snapshot.` |
| `COVERAGE_GAP_DUPLICATE` | `Envelope contains a duplicate coverage gap.` |

`str(error)` 必须等于 stable message；不得拼接 field value。字段位置只通过 `error.field_path` 和 `to_dict()` 暴露。

---

## 11. Golden Fixture

`tests/contracts/fixtures/artifact_envelope_v4_golden.json` 必须是无 BOM、无尾随换行的 canonical 单行 JSON。其 inline payload 固定为：

```json
{"coverage":{"files":3},"kind":"contract-foundation"}
```

payload canonical SHA-256 固定为：

```text
567791dedb5a4052163ab8fcc5e7abc3ff71008fa1ec690c8fa739dfe14822d7
```

Envelope fixture 固定值：

| 字段 | 值 |
|---|---|
| `schema_name` | `lima.contract_foundation_fixture` |
| `schema_version` | `4.0` |
| `artifact_id` | `artifact-contract-foundation-0001` |
| `tenant_id` | `tenant-test` |
| `task_id` | `task-test` |
| `workflow_id` | `workflow-test` |
| `stage_attempt_id` | `stage-attempt-test` |
| `repository_snapshot_digest` | 64 个 `1` |
| `producer` | `lima.contracts.tests` |
| `created_at` | `2026-09-01T00:00:00.000000Z` |
| `policy_digest` | 64 个 `2` |
| `toolchain_digest` | 64 个 `3` |
| `content_digest` | 上述 payload digest |
| `classification` | `internal` |
| `retention_class` | `standard` |
| `lineage` | `[]` |
| `supersedes` | `null` |
| `coverage_gaps` | `[]` |

Golden test 必须证明：

```python
raw = fixture.read_bytes()
envelope = decode_envelope(raw)
assert encode_envelope(envelope) == raw
assert compute_content_digest(envelope.payload) == envelope.content_digest
```

---

## 12. Required Tests

所有测试使用 `unittest`，测试 Symbol 名称不得自行改写。一个 AC 可以有多个 test，但下面的 test 不得缺失。

### 12.1 `tests/contracts/test_errors.py`

```text
ContractErrorTests.test_every_error_code_has_stable_message
ContractErrorTests.test_to_dict_has_exact_public_shape
ContractErrorTests.test_error_does_not_render_raw_value
ContractLimitsTests.test_defaults_are_frozen
ContractLimitsTests.test_rejects_bool_zero_negative_and_non_integer_limits
```

### 12.2 `tests/contracts/test_codec.py`

```text
CanonicalCodecTests.test_key_order_and_json_whitespace_are_stable
CanonicalCodecTests.test_lf_crlf_and_indentation_decode_to_same_bytes
CanonicalCodecTests.test_unicode_nfc_is_stable_for_keys_and_values
CanonicalCodecTests.test_rejects_unpaired_unicode_surrogate
CanonicalCodecTests.test_rejects_raw_duplicate_field
CanonicalCodecTests.test_rejects_unicode_semantic_duplicate_field
CanonicalCodecTests.test_rejects_finite_float_nan_and_infinity
CanonicalCodecTests.test_rejects_non_string_key_and_unsupported_python_type
CanonicalCodecTests.test_rejects_integer_outside_signed_64_bit
CanonicalCodecTests.test_enforces_input_and_output_byte_limits
CanonicalCodecTests.test_enforces_depth_limit_at_exact_boundary
CanonicalCodecTests.test_enforces_array_object_and_string_limits
CanonicalCodecTests.test_rejects_invalid_utf8_bom_and_trailing_json
CanonicalCodecTests.test_digest_matches_frozen_payload_vector
CanonicalCodecTests.test_bytes_digest_uses_raw_bytes
```

### 12.3 `tests/contracts/test_common.py`

```text
SchemaVersionTests.test_parses_and_renders_4_0
SchemaVersionTests.test_rejects_bool_negative_malformed_and_unknown_major
ArtifactEnvelopeTests.test_golden_inline_envelope_round_trip
ArtifactEnvelopeTests.test_blob_reference_round_trip
ArtifactEnvelopeTests.test_requires_exactly_one_inline_or_blob
ArtifactEnvelopeTests.test_rejects_missing_required_and_unknown_current_minor_field
ArtifactEnvelopeTests.test_future_minor_preserves_unknown_optional_fields
ArtifactEnvelopeTests.test_rejects_unknown_enum_and_invalid_identifier
ArtifactEnvelopeTests.test_normalizes_equivalent_timezone_to_utc_microseconds
ArtifactEnvelopeTests.test_rejects_naive_or_invalid_datetime
ArtifactEnvelopeTests.test_rejects_inline_and_blob_digest_mismatch
ArtifactEnvelopeTests.test_rejects_lineage_self_duplicate_and_conflicting_identity
ArtifactEnvelopeTests.test_rejects_cross_tenant_and_cross_snapshot_reference
ArtifactEnvelopeTests.test_rejects_duplicate_and_oversize_coverage_gap
ArtifactEnvelopeTests.test_defensive_copy_prevents_post_construction_mutation
ArtifactEnvelopeTests.test_wire_shape_has_no_artifact_type_alias
```

### 12.4 `tests/contracts/test_import_isolation.py`

```text
ContractImportIsolationTests.test_public_api_matches_frozen_symbol_set
ContractImportIsolationTests.test_clean_process_import_has_no_db_network_docker_or_service_modules
ContractImportIsolationTests.test_contract_modules_only_use_allowed_imports
```

Import isolation test 应在干净 Python 子进程中 `import lima.contracts` 后检查 forbidden module roots 未进入 `sys.modules`。测试本身可以使用 subprocess；生产 contracts 包不能。

---

## 13. Acceptance Criteria 与 Traceability

| AC | 可机器验证的结果 | Required tests |
|---|---|---|
| `IP1-AC-01` | 相同语义 JSON 的字段顺序、空白、LF/CRLF、Unicode 表示不改变 canonical bytes/digest | codec key/line-ending/NFC/digest tests |
| `IP1-AC-02` | 非法 UTF-8、重复字段、float、超限结构均返回稳定错误码 | codec negative/resource tests |
| `IP1-AC-03` | Envelope inline/blob 严格二选一且 digest 不匹配 fail closed | common content/digest tests |
| `IP1-AC-04` | 未知 major 拒绝；4.0 typo 拒绝；未来 4.x optional 字段无损保留 | version/current/future-minor tests |
| `IP1-AC-05` | self、重复、冲突、跨 tenant、跨 snapshot reference 全部拒绝 | lineage tests |
| `IP1-AC-06` | Golden fixture decode→encode byte-for-byte 相同 | golden round-trip test |
| `IP1-AC-07` | 导入 contracts 不触发生产层、网络、DB、Docker、LLM | import isolation tests |
| `IP1-AC-08` | 不修改任何现有生产文件、不增加依赖 | git diff/file allowlist review |
| `IP1-AC-09` | 新 tests、兼容回归与全量现有 unittest 通过 | Done Commands |

任何 AC 失败，Packet 状态为 Not Done；不得通过删除测试、放宽错误或把异常转换为默认值绕过。

---

## 14. 实现顺序

Coding Agent 必须按以下小步推进：

1. 新建 package/test directories 和空 `__init__.py`；
2. 先写 `test_errors.py`，实现 stable error catalog；
3. 写 codec negative/golden tests，再实现 `codec.py`；
4. 写 Envelope/reference tests，再实现 `common.py`；
5. 写 public API/import isolation tests，再冻结 `lima/contracts/__init__.py`；
6. 运行定向 tests 与 Ruff/Bandit；
7. 运行兼容回归和全量 unittest；
8. 检查 git diff 仅包含 allowlist；
9. 输出第 18 节 Completion Summary，等待 review。

禁止先写大段实现再补测试；禁止创建第二套 codec helper。

---

## 15. Done Commands

### 15.1 Baseline（编码前）

```powershell
python -m compileall -q lima scripts tests
python -m unittest -v tests.test_repository_source tests.test_task_failure
git status --short
```

当前核验基线（2026-09-01，Python 3.12.4）：上述 29 个定向测试通过；全量 `python -m unittest discover -s tests -v` 共运行 345 tests，其中 344 passed、1 个 Windows symlink privilege 既有 skip、0 failed，耗时 52.688 秒。Agent 必须在自己的实际基线重新运行，不得复制本结果冒充验证。

### 15.2 Slice Gate（每次改动后）

```powershell
python -m compileall -q lima/contracts tests/contracts
python -m unittest discover -s tests/contracts -v
python -m ruff check lima/contracts tests/contracts
python -m bandit -q -r lima/contracts
```

### 15.3 Compatibility Gate

```powershell
python -m unittest -v tests.test_repository_source tests.test_task_failure
python -m unittest discover -s tests -v
git diff --check
```

### 15.4 File Boundary Gate

```powershell
git diff --name-only --diff-filter=ACMRTUXB
```

输出必须是第 5.1 节 allowlist 的子集。出现任何现有生产文件、依赖文件、配置、前端或规划文档即失败。

### 15.5 Optional Release Gate

本切片无 Docker、数据库、网络、API 或前端行为变化，不把完整容器门禁作为本地 Done 的前置；PR 仍必须等待仓库 `merge-gate`。

---

## 16. Security / Compatibility Invariants

- 非法或不兼容输入 fail closed，不返回部分 Envelope；
- digest 比较使用 `hmac.compare_digest`；
- error payload 不回显输入内容；
- canonicalization 不执行对象方法、不使用 `default=str`；
- 没有网络、磁盘、环境变量、系统时间或随机副作用；
- legacy import 和行为完全不变；
- Python 3.11 与 3.12 均兼容，不使用 Python 3.12 专属 `type` alias 语法；
- 新 package 可由 setuptools 现有 `include = ["lima*"]` 自动发现，不为此修改 `pyproject.toml`；
- future minor round-trip 只承诺保留 optional extension；新增 required 字段必须升级 major；
- unknown enum、unknown major、digest mismatch 永不自动降级或填默认值。

---

## 17. Stop Conditions / Decision Request

Coding Agent 遇到以下任一情况必须停止编码并报告，不得自行设计：

1. 最新 main 已存在同名 package、Symbol 或活跃 Owner；
2. 需要修改第 5.1 节之外的文件；
3. 需要第三方依赖；
4. 下游需求必须使用 binary float、自动 ID/time 或绝对路径；
5. 本文两个规范性规则互相矛盾；
6. 无法在不导入生产层的情况下实现；
7. 全量回归出现与本切片相关的失败；
8. 安全测试只能通过放宽限制、吞掉错误或删除断言解决。

Decision Request 必须包含：

```text
阻塞规则/段落：
实际代码证据：
最小复现命令：
为什么无法在 allowlist 内解决：
可选方案及兼容/安全影响：
建议：
```

在维护者明确决策前不得继续扩大实现。

---

## 18. Coding Agent Completion Summary 模板

```markdown
## IP-0001 Completion Summary

### Result
- Status: DONE | NOT DONE | BLOCKED
- Base commit:
- Final commit:

### Changed files
- Added:
- Modified outside allowlist: none | <explain and mark NOT DONE>

### Public API
- Exported symbols:
- Contract deviations: none | <Decision Request link>

### Acceptance evidence
- IP1-AC-01:
- IP1-AC-02:
- IP1-AC-03:
- IP1-AC-04:
- IP1-AC-05:
- IP1-AC-06:
- IP1-AC-07:
- IP1-AC-08:
- IP1-AC-09:

### Commands and actual results
- compileall:
- contract tests:
- Ruff:
- Bandit:
- compatibility tests:
- full unittest:
- git diff --check:
- file boundary:

### Security review
- Raw input/secret reflected in errors: no
- Network/DB/Docker/LLM authority added: no
- New dependency: no
- Fail-closed cases verified:

### Known limitations
- Multi-hop lineage cycle validation deferred to Artifact Registry.
- Domain Artifact schemas are not part of IP-0001.

### Follow-up readiness
- IP-0002 may be refined only after this PR is merged and public API is consumer-reviewed.
```

PR 不得使用 `Closes #58`；建议正文使用 `Implements IP-0001 under #58`，#58 只有全部后续 slices 完成后才可关闭。

---

## 19. Maintainer Review Checklist

- [ ] Base commit 与最新 main 一致；
- [ ] diff 只包含文件 allowlist；
- [ ] public symbols 与签名完全一致；
- [ ] 没有新增 public helper 或隐式依赖；
- [ ] float、duplicate、Unicode、resource limit 拒绝真实生效；
- [ ] Envelope inline/blob、digest、version 和 lineage fail closed；
- [ ] golden fixture byte-for-byte round-trip；
- [ ] error 不回显 raw value；
- [ ] import isolation 在干净子进程验证；
- [ ] 指定 tests、全量 unittest、Ruff、Bandit 和 diff check 有真实结果；
- [ ] 未修改 legacy models/store/service/API/frontend；
- [ ] Completion Summary 完整；
- [ ] 未关闭 #58；
- [ ] 只有合并并完成 consumer review 后才开始冻结 IP-0002。

---

## 20. Packet 完成定义

本文档自身达到 `READY-FOR-CODE` 的条件：

- Goal、Non-goals、Files、Owner、Symbols、Contracts、Errors 已冻结；
- 所有资源上限、枚举、版本和 wire 语义有唯一答案；
- Required tests 精确到文件和 Symbol；
- Done Commands 可在当前仓库运行；
- 没有关键 TBD；
- 不要求 Coding Agent 重新设计架构；
- 实现范围为全新增 leaf package，冲突与回滚面最小。

一旦 Coding Agent 发现本文仍存在必须由其自行决定的关键设计，IP-0001 自动退回 `NEEDS-DESIGN`，不得边猜边实现。
