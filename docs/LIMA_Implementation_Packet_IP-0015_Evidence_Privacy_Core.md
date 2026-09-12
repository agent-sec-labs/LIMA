# LIMA Implementation Packet IP-0015：Evidence Privacy Core（Feature Slice S1-Core：分类/策略核心 + 租户隔离 HMAC 指纹 + fail-closed 统一入口）

- Packet 版本：1.0（2026-09-12，P&V 起草，状态 DESIGN-FROZEN / PENDING-MERGE）
- 制作：LIMA Packet & Verification Agent（运行模型：无法核验——本环境未提供可验证的运行元数据）
- 依据：Coordinator 裁定 COORD-IP94-R1（`.pv_tmp/COORD-IP94-RECOVERY_AND_SLICING_2026-09-12.md` §A–§F，Maintainer 授权）

## 需求映射（Header）

| 字段 | 值 |
|---|---|
| Source Issue | agent-sec-labs/LIMA #94 `[V5-N05][P0] 敏感 Evidence 脱敏、分级、保留与导出治理`（远程正文亲验 2026-09-12，updated_at **2026-09-12T12:02:54Z**，已含 Delivery Ledger） |
| spec revision | Issue 正文 2026-09-12T12:02:54Z 版 + kickoff checklist `docs/LIMA_Issue_94_Coding_Agent_Kickoff_Checklist.md`（sha256 `e86e17935bf3e0d51707b661378095ab7fb3bf642fcfa31947342c719e2707ac`，PR #148 已合并，亲验一致） |
| Covered requirements | FR-N05-01；FR-N05-02（仅接口面与 fail-closed 拒绝语义）；FR-N05-03；FR-N05-07；NFR-N05-01；NFR-N05-02（骨架）；NFR-N05-03；NFR-N05-04（digest 部分）；AC/T-N05-02；AC/T-N05-04；AC/T-N05-03 核心子集（短值/Unicode/二进制/Base64/URL credential/私钥的指纹-分类核心处理；全量文本/二进制扫描适配留 IP-0016）；SEC-N05-01..04（正文 Security/reliability/observability/compatibility 区段命名锚点，语义不改，仅命名） |
| Not covered | FR-N05-04 vault adapter（IP-0017 仅定 port，本 IP 完全不做）；FR-N05-05/FR-N05-06（IP-0016/0017）；AC/T-N05-01 全量（多 sink 场景）、AC/T-N05-05（API/export/UI fixture）、AC/T-N05-06（历史审计）；一切生产接线（#66/#68/#70 集成）；`scripts/audit_sensitive_artifacts.py` |
| Delivery role | Feature Slice S1-Core |
| Issue closure impact | **PARTIAL**（#94 关闭需 S1+S2+S3 全部完成，见 Ledger gates G1–G4） |
| Upstream | #58 终态 merge commit `7734e585ec0b3a10873f58c917fd134c12e6e8a1`；统一开发基线 origin/main = **`1358e85c2fec9db4bfb2ff2f679f4e237e79104a`**（PR #148 合并后，亲验 `git rev-parse origin/main`） |

本 IP 的贡献声明仅限上表 covered 列；底层 contract 就绪不等于上层端到端 AC 满足。

## 2. Design Input Manifest

| # | 输入 | 锚点（blob SHA @ origin/main 1358e85c，P&V 亲验 `git ls-tree`） | 消费方式 |
|---|---|---|---|
| DI-001 | `lima/contracts/common.py`：`ArtifactClassification`（public/internal/sensitive/restricted，L309-315）、`RetentionClass`（L318-324）、`ArtifactEnvelope`（含 `tenant_id`/`policy_digest`，L480-503）、`decode_envelope`/`encode_envelope` | `3a5efd09186543b68592e8758c9c7a48fa36a346` | 只读复用：分类枚举不重建；语义参照 |
| DI-002 | `lima/contracts/codec.py`：canonical codec（NFC 归一、sorted-key compact UTF-8）、`ContractLimits`、`compute_content_digest`、`canonical_encode` | `a442076db6f193a3b362cc6caf6d53d4f76570b8` | 只读复用：指纹输入归一与 policy digest 计算 |
| DI-003 | `lima/contracts/errors.py`：`ContractError`/`ContractErrorCode` typed error 模式（code + field_path，构造即冻结） | `87e806183961297918b4fa6079ae2f8302f8ce1b` | 只读参照：PrivacyError 同型设计原则 |
| DI-004 | `lima/contracts/evidence.py`（evidence domain 契约，1639 行） | `924692f6b9336657f7a475737244fdb3e2969d25` | 只读参照：payload 形态认知 |
| DI-005 | `schemas/v4/lima.artifact-envelope.json` | `2f617922a1b79ce693ca4e2850ea9a5b0f8a5a84` | 只读：wire schema 边界 |
| DI-006 | `schemas/v4/lima.evidence-domain.json` | `7a1b284537bc85cd0400a843da882926c5a96fbf` | 只读：同上 |
| DI-007 | `tests/contracts/fixtures/artifact_envelope_v4_golden.json` | `d0d12487bd8eda8696c2763fd1d9e52f3f8df7db` | 只读：回归基线组成 |
| DI-008 | Issue #94 远程正文（含 Delivery Ledger，updated 2026-09-12T12:02:54Z） | GitHub API 只读亲验（2026-09-12） | 需求唯一来源（FR/NFR/AC/T 稳定 ID） |
| DI-009 | Coordinator 裁定 COORD-IP94-R1（§A.4 锚点、§B 边界、§C 切分、§E Assignment） | `.pv_tmp/COORD-IP94-RECOVERY_AND_SLICING_2026-09-12.md`（本地文件，基线外控制面） | 派发权威 |
| DI-010 | `docs/LIMA_Issue_94_Coding_Agent_Kickoff_Checklist.md` | worktree 内 sha256 `e86e1793…70ac`（亲验 `sha256sum`） | 首轮交付要求（矩阵文档） |
| DI-011 | `docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md` §8/§9/§9.1/§12（Packet Gate / Tests-Frozen Gate / 分支拓扑 / PR Contract） | origin/main 树内（docs/） | 流程权威 |
| DI-012 | `docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md`、`docs/LIMA_PACKET_AND_VERIFICATION_AGENT_RESPONSIBILITY_CHARTER.md`、`CONTRIBUTING.md` | origin/main 树内 | 标准/责任书/贡献规范 |
| DI-013 | 基线绿性亲测：`python -m pytest tests/contracts -q` @ worktree 1358e85c → **617 passed**（2026-09-12） | 本 worktree 实跑 | RED/GREEN 对照基线 |
| DI-014 | 模板参照：IP-0012/0013/0014 Packet 与交接书（结构模板，无语义继承） | origin/main docs/ | 文档结构 |

**裁定 §A.4 锚点复核**：上表 DI-001..DI-007 的 blob SHA 与裁定 §A.4 表逐项一致（裁定时点 7734e58 与当前 1358e85 之间这些文件未变），无 main 漂移。

### Explicitly Rejected Inputs

- Issue #66/#68/#70 正文及其派生设计（生产接线属后续轨道，本 IP 只做契约层，不消费其实现细节）。
- #60 轨道（kickoff checklist #60 部分、IP-0016 起编号归属）与任何并行轨道文档。
- `lima/report.py`/`store.py`/`postgres_store.py` 的现状代码作为"兼容目标"——它们仅是问题陈述的证据（Issue Evidence 区），本 IP 不修改、不模仿其输出格式。
- 任何提出新建分类枚举、独立序列化规则、独立摘要规则、raw-secret 例外通道、feature-flag 回滚保存原文的设想（与裁定 §E 与 Issue Non-goals 冲突，一律拒绝）。
- Internet 上的第三方脱敏库设计（不引入新依赖；实现仅用标准库 + #58 contracts）。

## 3. Iteration Hypothesis 与 Measurement

- Hypothesis：在 #58 冻结契约（classification/envelope/codec/typed error）之上，可以用一个纯标准库、无 IO 的 `lima/evidence_privacy/` 核心模块交付"分类 + 租户隔离指纹 + fail-closed 统一入口"，使 AC/T-N05-02、AC/T-N05-04 与 AC/T-N05-03 核心子集在 contract 层可测，并为 IP-0016 的内容适配提供唯一依赖原语。
- Measurement：冻结测试全绿（含 tests/contracts 617 回归）；`sanitize_for_sink` 对全部负例（未知 sink/缺 key/策略异常/超限）均以 stable PrivacyError 拒绝且错误对象序列化后不含原值子串；同租户指纹逐字节稳定、跨租户指纹不同（≥1000 随机值对零碰撞之外的统计断言退化为确定性断言：同 key 同值恒等、异 key 同值必不等）。

## 4. Goal

1. 新增 `lima/evidence_privacy/` 包（7 个文件，见 §7 Symbol-to-File Map），交付：
   - 数据模型：`EvidencePayload`、`SinkContext`、`TenantPolicy`、`SanitizedPayload`、`ClassificationManifest`、`FingerprintRecord`、`PrivacyLimits`；
   - 分类核心：把 payload 的敏感度判定映射到 #58 `ArtifactClassification` 四级（不新建枚举）；
   - 租户隔离 HMAC 指纹（§8.3 精确语义）；
   - 策略解析与 policy digest（复用 `compute_content_digest`）；
   - 统一入口 `sanitize_for_sink(EvidencePayload, SinkContext, TenantPolicy) -> SanitizedPayload`（`ClassificationManifest` 挂在 `SanitizedPayload.manifest`），或抛 stable `PrivacyError`（fail-closed）。
2. 交付两份矩阵（本 Packet 附录 A/B）作为后续 IP 的设计输入。

## 5. Non-goals

- 不做任何 sink 适配（store/log/Prompt/API/export 的实际拦截）；不做 vault_port（IP-0017）；不做内容扫描器全量实现（嵌套 JSON 递归 redaction 的**扫描策略接口**在本 IP 定义，深度遍历器实现与文本/日志/diff/Prompt 适配在 IP-0016）；不做审计脚本；不改任何既有产品文件；不做生产接线；不引入第三方依赖。

## 6. 工作树与分支前置条件

- 基线：origin/main = `1358e85c2fec9db4bfb2ff2f679f4e237e79104a`（开工前 `git rev-parse origin/main` 复核；若前移且 `lima/contracts/**`、`schemas/v4/**`、`tests/contracts/**`、两份开工清单任一 blob 变化 → 停止上报）。
- 分支拓扑按 lifecycle §9.1：`codex/ip-0015-integration`（P&V）→ Frozen Test Commit → `codex/ip-0015-implementation`（Implementation）。
- 开工命令（Implementation，在 Packet 合并后的新 worktree）：
  ```bash
  cd <交付 worktree 根目录>
  git rev-parse origin/main   # 必须等于 Packet merge commit，记录之
  python -m pytest tests/contracts -q   # 基线必须 617 passed
  ```

## 7. Symbol-to-File Map（冻结）

| 文件（全部 Add，禁止改名/拆并） | 符号 |
|---|---|
| `lima/evidence_privacy/__init__.py` | 公共 API 再导出：`EvidencePayload, SinkContext, TenantPolicy, SanitizedPayload, ClassificationManifest, FingerprintRecord, PrivacyLimits, PrivacyError, PrivacyErrorCode, sanitize_for_sink, compute_fingerprint, classify_payload, SINK_KINDS`；`__all__` 恰为此集合 |
| `lima/evidence_privacy/errors.py` | `PrivacyErrorCode(str, Enum)`（值全大写下划线，见 §8.6）、`PrivacyError(Exception)`（字段：`code: PrivacyErrorCode`、`field_path: str = ""`、`context: Mapping[str, JSONValue]`——只允许类型名/长度/枚举名等非原值元数据） |
| `lima/evidence_privacy/models.py` | `EvidencePayload`、`SinkContext`、`TenantPolicy`、`SanitizedPayload`、`ClassificationManifest`、`FingerprintRecord`、`PrivacyLimits`（dataclass，见 §8.1/§8.2） |
| `lima/evidence_privacy/fingerprint.py` | `compute_fingerprint(value: str | bytes, *, tenant_id: str, tenant_key: bytes) -> str`；内部 `_derive_tenant_key` |
| `lima/evidence_privacy/classifier.py` | `classify_payload(payload: EvidencePayload, policy: TenantPolicy) -> ClassificationManifest`（含每值分类与整体 envelope 级 classification 归并） |
| `lima/evidence_privacy/policy.py` | `TenantPolicy.resolve(...)`（类方法工厂：构造即校验）、`policy_digest(policy) -> str`、`DEFAULT_POLICY` 常量、`SINK_KINDS: frozenset[str]` |
| `lima/evidence_privacy/port.py` | `sanitize_for_sink(payload, sink, policy) -> SanitizedPayload`（唯一入口；线程安全、无 IO、无全局状态、纯标准库） |

命名与既有包一致（参考 `lima/contracts/` 的模块划分），禁止在包外新增任何产品文件。

## 8. 精确契约

### 8.1 数据模型（models.py，全部 frozen dataclass + `__post_init__` 校验，仿 #58 风格）

```python
EvidencePayload:
    payload_kind: str            # "structured_json" | "text" | "bytes"（IP-0015 必须接受三者；扫描深度仅 IP-0016 全量）
    value: JSONValue | str | bytes
    media_type: str = ""         # 信息性，不参与指纹
SinkContext:
    sink_kind: str               # 必须属于 SINK_KINDS；未知值 → PrivacyError(UNKNOWN_SINK)
    purpose: str = ""            # 信息性
TenantPolicy:
    policy_version: str          # 非空、ASCII 可打印
    limits: PrivacyLimits
    preview_enabled: bool = False
    preview_max_chars: int = 2   # 仅 preview_enabled 时生效；0..4
    sink_allowlist: frozenset[str] = SINK_KINDS
SanitizedPayload:
    sink_kind: str
    tenant_id: str
    manifest: ClassificationManifest
    redacted_value: JSONValue | str | bytes   # 与 payload_kind 同形态；敏感位置替换为 FingerprintRecord 表达
ClassificationManifest:
    classification: ArtifactClassification        # 来自 #58 枚举（DI-001）
    retention_class: RetentionClass               # 默认 STANDARD；LEGAL_HOLD/AUDIT 由 policy 语义映射
    policy_version: str
    policy_digest: str                            # 64 hex（见 8.4）
    entries: tuple[FingerprintRecord, ...]
    created_at: str                               # UTC ISO-8601，NFC
FingerprintRecord:
    fingerprint: str          # 32 小写 hex（见 8.3）
    value_kind: str           # "string"|"bytes"|"int"|"bool"|"null"|"structured"
    length: int               # 字符串=NFC 后 Unicode 码点数；bytes=字节数；structured=canonical 字节数
    preview: str | None       # 默认 None；启用时 ≤ preview_max_chars 个原值前缀字符 + "…"，仅当 length >= 8
PrivacyLimits:                # 全部正 int，构造即校验
    max_depth: int = 32
    max_payload_bytes: int = 1_048_576
    max_string_bytes: int = 262_144
    max_items: int = 10_000
    max_processing_ms: int = 1_000
```

### 8.2 统一入口行为（port.py）

`sanitize_for_sink(payload, sink, policy) -> SanitizedPayload`，按序执行，任一步失败即抛 `PrivacyError` 并终止（不得部分输出、不得回退原文）：

1. 参数类型校验（非模型类型 → `INVALID_FIELD_TYPE`）；
2. `sink.sink_kind not in policy.sink_allowlist` → `UNKNOWN_SINK`（FR-N05-02 fail-closed）；
3. tenant key 缺失/空/非 bytes → `MISSING_TENANT_KEY`（SEC-N05-01 衍生）；tenant_id 非法（空或 >128 字节）→ `INVALID_FIELD_VALUE`；
4. 大小/深度/条目预算（对 `payload.value` 预扫，规则与 `ContractLimits` 同型）→ `RESOURCE_LIMIT_EXCEEDED` / `MAX_DEPTH_EXCEEDED` 等；
5. 截止时间：入口处记录 `time.monotonic()`，每处理 256 个条目检查一次，超 `max_processing_ms` → `TIME_BUDGET_EXCEEDED`（NFR-N05-02 骨架）；
6. 分类 + 指纹生成（classifier.py；策略解析异常→ `POLICY_ERROR`）；
7. 组装 `SanitizedPayload`：敏感位置替换为 `FingerprintRecord`，非敏感位置按 canonical 规则 NFC 归一后保留。
8. 成功路径结果必须满足：原值任何 ≥4 字符的敏感子串不出现在返回对象、其 `repr()`、其 canonical JSON 序列化中（DoD "repr(payload) 绕过检查" 的契约层实现）。

### 8.3 租户隔离 HMAC 指纹（NFR-N05-01 / FR-N05-03，精确语义）

- 输入归一：`str` → Unicode NFC 后 UTF-8 字节；`bytes` → 原样；`int/bool/null` → canonical JSON 文本字节；`structured` → `canonical_encode(...)` 字节（复用 DI-002，禁止另写序列化）。
- 密钥派生：`derived = HMAC-SHA256(key=tenant_key, msg=b"lima.evidence_privacy.tenant-key.v1\x00" + tenant_id.encode("utf-8"))`。
- 指纹：`fingerprint = HMAC-SHA256(key=derived, msg=b"lima.evidence_privacy.fingerprint.v1\x00" + normalized_value_bytes)[:16].hex()` → **32 个小写 hex 字符**（截断 16 字节）。
- 域分隔串 `...v1` 为冻结常量，写入 `fingerprint.py` 模块级 `Final`，不得拼接调用方输入。
- 可测试定义：
  - 同租户稳定性：同 `tenant_id`+`tenant_key`+同归一值 → 逐字节相等（AC/T-N05-02 去重依据）；
  - 跨租户不可关联：同值、不同 `tenant_id` 或不同 `tenant_key` → 指纹必不相等；且不暴露任何可与无钥计算（如裸 SHA-256(value)）比对的信息——测试断言 `fingerprint != hashlib.sha256(value_bytes).hexdigest()[:32]`；
  - 不可逆性：输出 128 bit 截断 HMAC，无原值通道；`FingerprintRecord` 全字段均为元数据。
- NFC 归一差异（如 NFD 输入）必须产出相同指纹（同租户）；这点直接复用 DI-002 的归一语义。

### 8.4 策略 digest（NFR-N05-04）

`policy_digest(policy)` = `compute_content_digest(policy.digest_source())`，其中 `digest_source()` 返回冻结字段序的 dict：`{"policy_version":…, "limits":{…五项…}, "preview_enabled":…, "preview_max_chars":…, "sink_allowlist":sorted(…)}`。同语义策略 → 同 digest；`ClassificationManifest.policy_digest` 每次结果必携带。

### 8.5 资源与权限契约

- 纯内存、无网络、无文件系统写、无数据库、无子进程；仅 import 标准库与 `lima.contracts.*`。
- 密钥（tenant_key）只作为参数在内存中出现：不得写入返回值、异常、日志调用、模块级全局（SEC-N05-01）。
- 不读取环境变量（部署 secret 管理属集成轨道）。

### 8.6 错误契约（errors.py，typed，仿 DI-003）

`PrivacyErrorCode` 枚举值（冻结，全大写）：
`INVALID_FIELD_TYPE`, `INVALID_FIELD_VALUE`, `UNKNOWN_SINK`, `MISSING_TENANT_KEY`, `POLICY_ERROR`, `RESOURCE_LIMIT_EXCEEDED`, `MAX_DEPTH_EXCEEDED`, `MAX_ITEMS_EXCEEDED`, `MAX_STRING_LENGTH_EXCEEDED`, `TIME_BUDGET_EXCEEDED`, `UNSUPPORTED_PAYLOAD_KIND`, `INTERNAL_REDACTION_FAILURE`。

- `PrivacyError.__str__` 输出仅含 code、field_path、受控 context 键名与**非原值**元数据（长度、类型名、枚举名）；任何构造路径都不接受原始敏感值（NFR-N05-03 / SEC anchor "计数事件不含原值"的契约层形态：`context` 可携带 `{"value_length": n, "value_kind": "string"}`）。
- adapter 内部未预期异常统一包裹为 `INTERNAL_REDACTION_FAILURE`，不外泄 traceback 中的值（调用方拿到的是包裹后的稳定错误）（AC/T-N05-04）。

### 8.7 分类核心（classifier.py）

- IP-0015 冻结"最小可信缺省"：`classify_payload` 对显式标记字段（payload 顶层键名匹配策略保留列表外的 `secret/token/key/password/credential/private_key` 模式，大小写不敏感）判 `SENSITIVE`；含私钥 PEM 头 `-----BEGIN ... PRIVATE KEY-----` 或 URL credential（`scheme://user:pass@`）形态的文本值判 `RESTRICTED`；其余按 policy 缺省 `INTERNAL`；整体 classification 取 entries 最高级（public<internal<sensitive<restricted，序即 #58 枚举定义序）。
- 枚举值、顺序、wire 值一律来自 `lima.contracts.common.ArtifactClassification`（DI-001 L309-315），本包不定义平行枚举（FR-N05-01）。
- 完整内容扫描（嵌套遍历策略钩子已在本 IP 预留 `TenantPolicy` 扩展点之外的实现细节不冻结）属 IP-0016；本 IP 的扫描深度受 `PrivacyLimits` 约束并对超出者 fail-closed。

### 8.8 兼容契约（SEC-N05-04）

- 本包不写 envelope、不改 schema；legacy 读取能力不受影响（零接触）。新 SanitizedPayload 天然携带 classification + policy digest。无任何回滚开关可绕过 sanitize 输出原值（与 Issue rollback 条款一致：紧急处置=停止写入，而非降级保存原文）。

## 9. 文件边界（裁定 §B，冻结）

**Files to Add（产品，8 项中本 IP 恰好 7 个 + 测试目录；vault_port.py/redactor.py/audit 脚本不在本 IP）**
- `lima/evidence_privacy/__init__.py`、`errors.py`、`models.py`、`fingerprint.py`、`classifier.py`、`policy.py`、`port.py`
- `tests/evidence_privacy/**`（P&V 拥有并冻结，见 §10）

**Product Files Allowed to Modify**：无。仅允许上述 7 个新增文件自身的自迭代修复。

**Test-Fixture Files Owned by P&V**：`tests/evidence_privacy/` 全部（含短值/Unicode/二进制/Base64/URL credential/私钥/超深/超大/超时输入的 inline fixture；独立 `.json` fixture 仅当超过 inline 合理性时才新增，路径 `tests/evidence_privacy/fixtures/`）。

**Read-only**：`lima/contracts/**`、`schemas/v4/**`、`tests/contracts/**`、`lima/report.py`、`lima/store.py`、`lima/postgres_store.py`、`docs/**`（Packet/交接书/清单）。

**Forbidden / Do-not-touch**：数据库 schema、service、API、frontend、LLM client、现有业务 pipeline、生产写入路径接线、#58 冻结枚举与公共契约、`scripts/audit_sensitive_artifacts.py`（尚不存在，本 IP 不得创建）、`.github/**`、`requirements*.txt`（禁止新依赖）。

## 10. 测试冻结计划（阶段二执行的期望；本轮不冻结）

### 10.1 文件布局与最小用例数

| 文件（P&V 所有） | 覆盖需求 | 最少用例数 |
|---|---|---|
| `tests/evidence_privacy/test_models.py` | 模型校验、非法构造 | 8 |
| `tests/evidence_privacy/test_fingerprint.py` | NFR-N05-01、FR-N05-03、AC/T-N05-02 | 12 |
| `tests/evidence_privacy/test_classifier.py` | FR-N05-01、AC/T-N05-03 核心子集 | 10 |
| `tests/evidence_privacy/test_policy.py` | NFR-N05-04、SEC-N05-04 | 6 |
| `tests/evidence_privacy/test_port_sanitize.py` | FR-N05-02、FR-N05-07、AC/T-N05-04、SEC-N05-02/03 | 14 |
| `tests/evidence_privacy/test_limits.py` | NFR-N05-02（深度/大小/条目/超时） | 8 |
| `tests/evidence_privacy/test_error_hygiene.py` | NFR-N05-03、SEC anchor | 8 |
| `tests/evidence_privacy/test_value_kinds.py` | AC/T-N05-03 核心子集（短值/Unicode NFC-NFD/二进制/Base64/URL credential/私钥） | 10 |

合计 ≥ 76 个用例。每条断言在注释中锚定需求 ID（`# FR-N05-07: ...`）。

### 10.2 预期 RED 形态（PI-DR4）

`lima/evidence_privacy/` 模块缺席 → 收集期 `ImportError`/`ModuleNotFoundError`；RED 报告必须附加"逐断言锚定表"：把每个测试文件的每个断言映射到需求 ID 与缺失符号，不得以一个导入错误笼统覆盖。可行做法：测试文件顶部用 `pytest.importorskip` 之外的标准 import（保持失败可见），另附 P&V 起草的 RED 清单文档说明每条断言对应的缺失交付。

### 10.3 scratch 骨架 GREEN 证明（PI-DR2，冻结前执行、不入交付）

1. 在 scratch 目录（worktree 外临时目录，如 `%TEMP%/ip0015-scratch`）实现最小骨架：7 个文件、符号齐全、行为最小可过（指纹用真实 HMAC 语义必须一次到位，其余可为空实现+显式 `NotImplementedError` 仅当对应断言尚未冻结）；
2. `cp -r tests/evidence_privacy <scratch>/tests/` 后 `python -m pytest tests/evidence_privacy -q` 于 scratch 内实跑，确认无 collection error 且断言语义可达 GREEN（针对已写断言）；
3. 记录命令与输出到 RED 证据文档；scratch 目录用后销毁，绝不进入 commit。

### 10.4 回归命令（含 #58 基线）

```bash
cd <交付 worktree 根目录>
python -m pytest tests/contracts tests/evidence_privacy -q
# 预期：tests/contracts 617 passed（基线数字，DI-013）+ tests/evidence_privacy 全绿、0 skip
python -m pytest tests/contracts -q   # 单独重跑亦须 617 passed
```

## 11. 验收命令（全部钉死在交付 worktree 内执行；PI-DR3）

| 类别 | 命令（cwd = 交付 worktree 根） | 判定 |
|---|---|---|
| baseline | `git rev-parse HEAD && python -m pytest tests/contracts -q` | HEAD = Frozen Test Commit 祖先链上；617 passed |
| slice | `python -m pytest tests/evidence_privacy -q` | 全绿，0 skip，用例数 ≥ §10.1 下限合计 |
| regression | `python -m pytest tests/contracts tests/evidence_privacy -q` | 全绿 |
| boundary | `python - <<'PY'`（探针脚本：负例四连——未知 sink/空 tenant_key/超深 dict/超大字符串——断言抛 `PrivacyError` 且 `str(exc)` 不含原值） | 4/4 拒绝且无泄漏子串 |
| compatibility | `python -c "import lima.contracts.common as c; print([e.value for e in c.ArtifactClassification])"` | `['public','internal','sensitive','restricted']`（未被改动） |
| post-merge（P&V 阶段三） | 在干净 worktree 于 merge commit 重跑 slice+regression | 全绿 |

Python 解释器：`python`（3.12.x，基线亲测可用）。

## 12. AC traceability（逐条）

| 需求 | 测试（文件::断言组） | 证据等级 |
|---|---|---|
| FR-N05-01 | test_classifier.py（枚举来源、整体归并、显式敏感键、PEM/URL credential 判 RESTRICTED） | contract |
| FR-N05-02（接口面） | test_port_sanitize.py（SINK_KINDS 内成功、白名单缩减、UNKNOWN_SINK 拒绝、入口唯一性） | contract |
| FR-N05-03 | test_fingerprint.py + test_models.py（FingerprintRecord 字段=fingerprint/kind/length/preview；preview 缺省 None） | contract |
| FR-N05-07 | test_port_sanitize.py（策略异常→POLICY_ERROR、内部异常包裹 INTERNAL_REDACTION_FAILURE、无原文回退路径断言：失败路径返回值不存在即抛错） | contract |
| NFR-N05-01 | test_fingerprint.py（同租户稳定、跨租户必异、≠裸 SHA-256、NFC/NFD 同指纹） | contract |
| NFR-N05-02（骨架） | test_limits.py（超深/超大/超条目/超时全 fail-closed） | contract |
| NFR-N05-03 | test_error_hygiene.py（所有错误 code 的 str/repr/canonical 序列化不含 ≥4 字符原值子串；计数式 context 只含长度与类型） | contract |
| NFR-N05-04（digest） | test_policy.py（同策略同 digest、变更任一字段 digest 变、manifest 必携带） | contract |
| AC/T-N05-02 | test_fingerprint.py（同租户去重=同指纹；跨租户不同指纹） | contract |
| AC/T-N05-04 | test_port_sanitize.py（注入抛异常的 stub 策略/monkeypatch classifier → 拒绝且不落原文） | contract |
| AC/T-N05-03 核心子集 | test_value_kinds.py（6 类值各至少 1 正例 1 边界） | contract |
| SEC-N05-01 | test_error_hygiene.py + §8.5 禁全局/日志/环境变量（静态断言：模块源码不含 `logging`/`os.environ`/`open(`，用 inspect 源码扫描测试） | contract |
| SEC-N05-02 | test_limits.py 超时用例 + test_port_sanitize.py 包裹用例 | contract |
| SEC-N05-03 | test_error_hygiene.py（本 IP 无 vault；锚点以"错误/事件不含原值"统一覆盖，vault disabled 合同测试在 IP-0017） | contract |
| SEC-N05-04 | test_policy.py + compatibility 命令（零 schema 接触由 Read-only 边界与 diff 审计保证） | contract |

## 13. Stop Conditions

1. 发现 #58 契约缺口（分类/Envelope/codec 语义不足以表达上述任一契约）→ 停止，产出 Contract Gap 报告交 Coordinator；不得在 Packet 或实现中自行补契约。
2. 基线漂移（§6 复核失败）→ 停止上报。
3. 冻结前 scratch 骨架无法证明 GREEN 可达 → 升级 Coordinator。
4. 实现期间认为需要改冻结测试/Oracle → 先提 Decision Request，未授权不得动。
5. 同一根因两轮修复失败或疑似规格矛盾 → 升级 glm-5.3/max。
6. 命名冲突（IP-0015 被占用、`lima/evidence_privacy/` 出现他人提交）→ 停止上报。

## 14. Completion Summary 模板（Implementation 必填）

- Final commit 完整 SHA + 分支名；基线 merge commit SHA；
- FR→AC→T 追踪表（完整稳定 ID `[V5-N05 / #94] FR-N05-xx` 形式）；
- 实际测试命令与输出摘要（§11 全表逐行）；
- 关键 digest：policy digest 示例值、指纹示例（脱敏展示）、tests 文件 sha256 清单；
- 文件边界确认：仅 7 个新增产品文件 + 0 个修改；`git diff --stat` 附上；
- 已知限制（本 IP 未做内容扫描全量等）与 follow-up（IP-0016/0017）；
- 确认未修改 Read-only/Forbidden 文件、未引入新依赖、未写任何 IO。

## 15. Packet completion definition

本 Packet 达成：覆盖裁定 §E 全部指定需求且零 TBD；两份矩阵（附录 A/B）覆盖开工清单要求格点并标注 IP-0015/0016 归属；测试冻结计划含最小用例数、RED 形态、PI-DR2 scratch 步骤、回归命令；验收命令全部钉死 cwd；交接书（`docs/LIMA_Coding_Agent_IP-0015_正式开发任务交接.md`）就绪。Packet PR 合并后由 Coordinator 标记 PACKET-MERGED，方可进入阶段二（测试冻结）。

## 附录 A：敏感数据类型矩阵（开工清单首轮交付）

| 数据类型 | 典型形态 | 默认 classification | IP-0015 处理（指纹/分类核心） | IP-0016 处理（内容适配） |
|---|---|---|---|---|
| 短 secret（<8 字符） | `"pk_live_1A"` | SENSITIVE | 指纹+类型+长度；preview 强制 None（length<8） | 短值上下文检测 |
| 普通 secret/token | `"ghp_xxxx…"` | SENSITIVE | 指纹+类型+长度；preview 可选 ≤2 字符 | 嵌套 JSON 递归扫描 |
| URL credential | `https://user:pass@host/p` | RESTRICTED | 形态识别 + 指纹 | 文本/日志中 URL 提取 |
| private key（PEM） | `-----BEGIN RSA PRIVATE KEY-----` | RESTRICTED | PEM 头识别 + 指纹（多行整体归一） | diff/Prompt 中 PEM 块定位 |
| Base64 编码秘密 | `"c2VjcmV0…"≥32 字符` | SENSITIVE | 按二进制/字符串指纹 | base64 解码判定 + 上下文 |
| 二进制秘密 | bytes blob | SENSITIVE | bytes 指纹（原样字节） | 二进制扫描适配 |
| Unicode 文本含秘密 | NFD/NFC 混合 | SENSITIVE | NFC 归一后指纹（NFD 同指纹） | Unicode 段落扫描 |
| 嵌套 JSON 中的秘密 | 深层字段 | SENSITIVE | 敏感键名模式（大小写不敏感）+ 指纹 | 深度遍历器全量实现 |
| 异常消息中的秘密 | traceback 文本 | RESTRICTED | 文本整体指纹（保守） | 异常栈结构化提取 |
| 日志行中的秘密 | logfmt/自由文本 | RESTRICTED | 同上（保守整体指纹） | 行级正则适配 |
| diff 中的秘密 | +/- 行 | RESTRICTED | 同上 | diff hunk 适配 |
| Prompt/LLM evidence 中的秘密 | 对话片段 | RESTRICTED | 同上 | Prompt 段适配 |

"保守整体指纹"指 IP-0015 对无法结构化定位的文本输入，缺省将可疑整段按敏感处理并指纹化（宁可过度脱敏，不漏）；精确分段留 IP-0016。

## 附录 B：输出场景矩阵

| 场景（sink_kind 冻结值） | IP-0015 | IP-0016 | 说明 |
|---|---|---|---|
| `storage`（入库/持久化前） | 接口+fail-closed | conformance suite + 接线指南 | 生产接线归 #66 |
| `log`（日志） | 接口+fail-closed | 行级适配 | |
| `prompt`（LLM 输入） | 接口+fail-closed | Prompt 适配 | 禁 raw 例外通道 |
| `api`（API 响应） | 接口+fail-closed | API fixture 无泄漏验证 | 接线归 #68/#70 |
| `export`（导出） | 接口+fail-closed | 导出 fixture 验证 | |
| `vault`（raw 保留） | **不设**（IP-0017 定义 port，默认 disabled） | — | FR-N05-04 归 IP-0017 |

`SINK_KINDS = frozenset({"storage","log","prompt","api","export"})` 为 IP-0015 冻结集合；未知值一律 `UNKNOWN_SINK` 拒绝。
