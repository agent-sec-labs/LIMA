# LIMA Implementation Packet IP-0020：Vault/Audit（Feature Slice S3：vault port 默认 disabled 合同 + 历史 Artifact 只读审计）

- Packet 版本：1.1（2026-09-13，P&V 起草，状态 DESIGN-FROZEN / PENDING-MERGE；v1.0 同日发布。v1.0 → v1.1 修订：按 Coordinator PR #173 评审裁定 COORD-IP0020-PACKET_PR_REVIEW 2026-09-13 + AI Reviewer 提前检查 REVIEW-IP-0020-SECBOUNDARY_EARLYCHECK 发现项 **F-1（MINOR）**——§8.2.3 指纹需租户凭据 vs §8.3 脚本 CLI 无租户参数 vs §9 T4 表述的租户凭据未定义缺口，采用"固定离线租户"方案修订：新增 §8.3.8、改写 §9 T4、更新 §11.1 断言组、§11.5 补 Windows 路径变体用例（非阻塞建议采纳）。其余内容零改动）
- 制作：LIMA Packet & Verification Agent（运行模型：无法核验——本环境未提供可验证的运行元数据）
- 依据：Coordinator 裁定 COORD-IP94-S3-ENTRY_RULING-2026-09-13（`.pv_tmp/COORD-IP94-S3-ENTRY_RULING_2026-09-13.md`，Assignment 正本 = 其 §D，Assignment 编号 `IP-0020-PKT-P1/v1`；编号登记 = 其 §C.2）

## 1. 需求映射（Header）

| 字段 | 值 |
|---|---|
| Source Issue | agent-sec-labs/LIMA #94 `[V5-N05][P0] 敏感 Evidence 脱敏、分级、保留与导出治理`（远程正文亲验 2026-09-13，updated_at **2026-09-13T05:51:10Z**；Ledger 已登记 IP-0020 = #94-S3 Vault/Audit，G3 OPEN，安全 Reviewer = 当前 Codex AI 会话（AI 审查如实登记），G3 收口需 Maintainer 书面 sign-off） |
| spec revision | Issue 正文 2026-09-13T05:51:10Z 版（含 Delivery Ledger 13/17 SATISFIED + 1 PARTIAL + 3 PLANNED、G1/G2 PASS、G3/G4 OPEN）+ kickoff checklist `docs/LIMA_Issue_94_Coding_Agent_Kickoff_Checklist.md` §2 第三层（L39–40）/ §3（L44–50，"只读审计脚本"、"审计结果不含原始秘密"） |
| Covered requirements | **FR-N05-04**（raw vault 可选 adapter：仅端口定义 + 安全约束合同测试——默认 disabled、无凭证/无后端即拒绝、任何误启用路径 fail-closed；**不做**实际存储实现）；**FR-N05-06**（历史 Artifact 只读审计 + 迁移**计划性**信息——可执行只读审计入口 `scripts/audit_sensitive_artifacts.py`，报告只含位置/fingerprint/kind/length/policy digest，绝不打印秘密，不执行删除或迁移）；**NFR-N05-04 审计侧**（审计输出携带 policy_version/policy_digest；审计过程只读，不改写历史 classification、不修改输入 fixture）；**AC/T-N05-06**（历史扫描只报告位置/digest：fixture 含敏感原值样本，断言审计报告/stdout/错误信息均无原值） |
| Not covered | vault 实际存储后端实现（仅 port + 默认 disabled 合同）；生产接线（#66 持久化 / #68 service / #70 API 等一切 schema/service/API/frontend/LLM client/业务 pipeline）；任何删除/迁移**执行**能力（实际删除需独立审批 Issue，本 IP 仅产出计划性 report）；#66/#68/#70 正文及派生设计；既有冻结面的任何修改（13 符号 / 12 枚举 / 五 SINK_KINDS / 既有 154 用例）；G3 安全 Review sign-off（Maintainer 书面结论为最终权威）；G4 Closure Audit |
| Delivery role | Feature Slice S3（Vault/Audit，#94 Ledger 仅剩三个 PLANNED 项的唯一归属 IP） |
| Issue closure impact | **CLOSURE-CANDIDATE**（S3 完成 → #94 Registered IP = 3/3；按治理注明：**非关闭许可**——G3 保持 OPEN 直至 Maintainer 书面 sign-off，G4 Closure Audit 由 Coordinator 另行执行，#94 关闭仍走 MANUAL-AFTER-POST-MERGE-AUDIT） |
| Upstream | IP-0015（Evidence Privacy Core）merge `e895079a1b43980bc35532bfd46c5cdbd8d3cae2`（PR #155）+ IP-0017（Content Conformance）merge `dd324915f9b35c70cfd4b254b06d1759c35fb13d`（PR，S2 证据锚）；统一开工基线 origin/main = **`dc6a50efd7b70f419883e66e334a782b9a84b6ba`**（PR #172，`git diff dd32491 dc6a50e -- lima/ tests/` 为空——本 Packet 亲验） |

本 IP 的贡献声明仅限上表 covered 列；vault/审计合同测试全绿不等于 #94 关闭（G3/G4 独立收口）。本 Packet 不宣称任何生产端到端能力（vault 存储、真实历史库扫描接线）已满足。

## 2. Design Input Manifest

| # | 输入 | 锚点（blob SHA，P&V 亲验 `git ls-tree origin/main` @ dc6a50e，2026-09-13；与裁定 §A.1 @ dd32491 逐一等值） | 消费方式 |
|---|---|---|---|
| DI-001 | `lima/evidence_privacy/content_scan.py` | `46be42f1a09dc0a24a35cb0dd8cc887a6b461fc4` | 只读复用：5 冻结符号——`BASE64_MIN_LENGTH`、`is_bare_base64_secret`、`find_base64_spans`（审计"位置"定位原语）、`REDACTED_SEGMENT_TEMPLATE`、`redact_text_segments`（纯函数、无 IO 先例） |
| DI-002 | `lima/evidence_privacy/port.py` | `ab497be27d680fbb528104c8863ea4d860ebaee9` | 只读消费：`sanitize_for_sink` fail-closed 包装语义（L175–213）；新 vault port 不得绕过或复用为旁路 |
| DI-003 | `lima/evidence_privacy/classifier.py` | `86a561f391d377f75c50db31df5805575526b199` | 只读参照：`_collect_entries` 的 field_path 语义（结构化"位置"表达可消费的既有先例） |
| DI-004 | `lima/evidence_privacy/errors.py` | `e8f9f7bdad2cd048a3d317097476bba5f06f5fa9` | 只读消费：12 枚举值冻结；vault 拒绝路径复用既有错误族（§8.1.4），不新增枚举 |
| DI-005 | `lima/evidence_privacy/fingerprint.py` | `d090ff6ba83b0210a18ed4d033614af4bec83798` | 只读复用：`compute_fingerprint`（审计 finding 的 digest；租户隔离语义沿用） |
| DI-006 | `lima/evidence_privacy/models.py` | `32e4cd53314f78396710b9a4498c4283f4f7d91c` | 只读消费：`SinkContext`/`TenantPolicy`/`FingerprintRecord`（value-free、preview 默认关闭——审计 finding 模型同型约束）；**不得反向给冻结 record 加字段**（裁定 §A.3 备注） |
| DI-007 | `lima/evidence_privacy/policy.py` | `4012d933e640c8d857e8480f5865fa89c559e686` | 只读消费：`SINK_KINDS` 五值、`policy_digest`/`DEFAULT_POLICY_VERSION`（经模块路径消费，O-1）——审计报告的 policy 证据字段来源 |
| DI-008 | `lima/evidence_privacy/__init__.py` | `ef21f161f0c63b99a8a1cd6060a5efc3b3758654` | 只读：`__all__` 保持 13 项；新模块经 `lima.evidence_privacy.vault_port` / `lima.evidence_privacy.audit` 模块路径消费（扩 `__all__` 须 DR，§10） |
| DI-009 | `tests/evidence_privacy/` 15 文件 @ dc6a50e（`__init__.py`=e69de29b…5391、`test_base64_refinement.py`=08376855…c2d8、`test_classifier.py`=8cee2190…0517、`test_conformance_cycles.py`=6abdd11a…363a、`test_conformance_limits_matrix.py`=cb95f042…d4ce、`test_conformance_sinks.py`=315fc937…1f30、`test_content_forms.py`=38ac47b0…9627、`test_error_hygiene.py`=3a9be6d8…85e2、`test_fingerprint.py`=dfda7f1f…abbe4、`test_fixture_no_leak.py`=73a175ee…f89a、`test_limits.py`=1d7f5700…108a、`test_models.py`=c94c0f5f…8ed4、`test_policy.py`=08908d9e…b10a、`test_port_sanitize.py`=945d2df1…d41f、`test_value_kinds.py`=7b360294…1a89） | 冻结测试，只读不得修改（§11.6）；154 用例为回归底线（下限不减少） |
| DI-010 | Issue #94 远程正文（updated 2026-09-13T05:51:10Z，含 Delivery Ledger、IP-0020 登记、G3 条款与 Reviewer 登记） | GitHub API 只读亲验（2026-09-13） | 需求唯一来源（FR/NFR/AC/T 稳定 ID） |
| DI-011 | Coordinator 裁定 COORD-IP94-S3-ENTRY_RULING-2026-09-13（§A consumer review / §B 切分 + T1–T5 / §C 编号登记 / §D Assignment / §E 风险） | `.pv_tmp/COORD-IP94-S3-ENTRY_RULING_2026-09-13.md`（本地基线外控制面） | 派发权威 |
| DI-012 | IP-0017 Packet v1.0 + IP-0015 Packet v1.1 | `docs/LIMA_Implementation_Packet_IP-0017_Content_Conformance.md`=a5b42207…12a9、`docs/LIMA_Implementation_Packet_IP-0015_Evidence_Privacy_Core.md`（main 树内） | §7 符号冻结 / §9 边界惯例模板；上游契约依据（记录性引用） |
| DI-013 | 开工清单 | `docs/LIMA_Issue_94_Coding_Agent_Kickoff_Checklist.md` = `42957cfa8e2269a7205cc40680a043e242fcca7d` @ dc6a50e | §2 第三层（L39–40）/ §3（L44–50）边界与验收 |
| DI-014 | 生命周期 `docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md`=385c3e74…072a（§8/§9/§9.1/§12）、开发与交接标准 `59d8d27c…3e98e`、P&V 责任书、CONTRIBUTING.md | origin/main docs/ 树内 @ dc6a50e | 流程权威 |
| DI-015 | 基线绿性亲测（本 worktree @ dc6a50e，2026-09-13 亲跑）：`python -m pytest tests/contracts -q` → **617 passed**；`python -m pytest tests/evidence_privacy -q` → **154 passed**；合计 771 passed | 本 worktree 实跑 | RED/GREEN 对照基线 |
| DI-016 | PI-DR 沉淀（PI-DR2 scratch / PI-DR3 cwd 钉死 / PI-DR4 RED / PI-DR6-bis 双 runner，经 IP-0016/IP-0017 Packet 惯例） | IP-0017 Packet §10（main 树内） | 测试冻结计划条款来源 |

### Explicitly Rejected Inputs

- Issue #66/#68/#70 正文及派生设计（生产接线：持久化、service、API、frontend、LLM client、业务 pipeline）——与 S3 无关且被裁定 §B.2 排除。
- #60 轨道全部文档与 IP-0019 Packet（仅共享基线 SHA，不共享任何规格）。
- 任何要求 vault 落地真实存储/凭证/网络后端的方案（FR-N05-04 的"adapter 实现"归后续生产接线 IP，本 IP 只交付 port 合同）。
- 任何审计路径获得写/删/迁能力的方案（T3 威胁面，见 §9）；"迁移计划"只能以 report 文本形态存在。
- 任何修改 13 冻结符号、既有 12 枚举值、五 `SINK_KINDS`、`__all__` 13 项、错误 str/repr 语义的方案（含"给 `FingerprintRecord` 加位置字段"——裁定 §A.3 备注：位置载体必须是 S3 新增类型）。
- 任何以新增 sink_kind（如 "vault"）把 vault 注入 `sanitize_for_sink` 生产链路的方案（裁定 §A.3：vault 不以 sink_kind 形式注入）。
- 第三方脱敏/扫描/参数解析库（禁止新依赖；实现仅标准库 + `lima.contracts.*` + 本包）。
- 任何 raw-secret 例外通道、审计降级为 Audit-only、feature-flag 回滚保存原文的设想。
- 改动 `tests/evidence_privacy/` 既有 15 文件以"腾出"新断言空间的方案（新断言一律进新测试文件）。

## 3. Iteration Hypothesis 与 Measurement

- Hypothesis：在 IP-0015+IP-0017 冻结公共面之上，仅通过**新增** `vault_port.py`（端口合同）、`audit.py`（只读审计模型与扫描函数）、`scripts/audit_sensitive_artifacts.py`（只读 CLI）三个文件，零修改 `lima/evidence_privacy/` 既有 8 文件与既有 15 测试文件，即可闭合 FR-N05-04 / FR-N05-06 / NFR-N05-04 审计侧 / AC/T-N05-06。
- Measurement：新合同测试全绿（双 runner）；既有 154+617 零回退；vault 默认 disabled 下任何取用路径均 `PrivacyError` 且错误无原值；审计 fixture（含已知敏感原值）扫描后 stdout/报告/错误信息经原值清单 grep 断言零命中，fixture 内容与 mtime 不变；报告携带 policy_version/policy_digest 与逐 finding 的位置/fingerprint/kind/length。

## 4. Goal

1. 交付 vault port 合同（FR-N05-04）：`VaultPortConfig`（默认 disabled）+ 配置校验 + 唯一取用入口；启用须显式配置且本 IP 内**无已注册后端**（`VAULT_BACKEND_PORT_NAMES` 为空集），一切取用 fail-closed（§8.1）。
2. 交付历史只读审计（FR-N05-06）：统一"位置"模型 `AuditLocation`、value-free `AuditFinding`、携带 policy 证据的 `AuditReport`，text/structured 两族纯函数扫描入口（§8.2）。
3. 交付可执行只读审计脚本 `scripts/audit_sensitive_artifacts.py`（§8.3）：离线目录扫描 → JSON 报告（stdout 或显式 `--output`），零原值、零 fixture 写入。
4. 交付 Security Boundary 章节的五项威胁（T1–T5）各自至少一条冻结测试断言（§9）。

## 5. Non-goals

- 不做 vault 存储实现、凭证管理、TTL 执行、加密落地、audit access 落地（这些是后端 adapter 义务，port 合同只表达约束）。
- 不做生产接线；不新增 sink_kind；不接数据库/service/API/frontend。
- 不执行删除/迁移；报告中的迁移信息仅为计划性文本（`recommended_action` 常量）。
- 不改 13 冻结符号签名、既有 12 枚举、`SINK_KINDS`、`PrivacyLimits` 默认值、指纹域分隔常量、`policy_digest` 字段序、`__all__` 13 项。
- 不引入新依赖；库模块（`vault_port.py`/`audit.py`）零 IO/零网络/零环境变量/零子进程（IO 仅限脚本层的只读文件访问 + 显式报告输出路径）。

## 6. 工作树与分支前置条件

- 统一开工基线：origin/main = `dc6a50efd7b70f419883e66e334a782b9a84b6ba`（Packet 合并前须复核未前移；若前移且 `lima/evidence_privacy/**` 8 文件 blob 或 `tests/evidence_privacy/**` 15 文件 blob 任一变化 → 停止上报）。
- 分支拓扑按 lifecycle §9.1：`codex/ip-0020-packet`（本 Packet docs PR）→ `codex/ip-0020-frozen-tests`（P&V 冻结测试）→ Frozen Test Commit → `codex/ip-0020-implementation`（Implementation）。
- 开工命令（后续阶段，在 Packet 合并后的新 worktree）：
  ```bash
  cd <交付 worktree 根目录>
  git rev-parse origin/main    # 必须等于 Packet merge commit，记录之
  python -m pytest tests/contracts -q         # 基线必须 617 passed
  python -m pytest tests/evidence_privacy -q  # 基线必须 154 passed（既有冻结面）
  ```

## 7. Symbol-to-File Map（冻结）

### 7.1 新增文件（Add）

| 文件 | 符号（冻结命名与签名） |
|---|---|
| `lima/evidence_privacy/vault_port.py` | `VAULT_PORT_DISABLED_MESSAGE: Final[str] = "vault port is disabled by default; enabling requires an approved backend adapter (out of scope for IP-0020)"`；`VaultBackendDescriptor`（frozen dataclass：`name: str`、`supports_ttl: bool`、`supports_encryption: bool`、`supports_audit_access: bool`）；`VAULT_BACKEND_PORT_NAMES: Final[frozenset[str]] = frozenset()`（本 IP 无已注册后端）；`VaultPortConfig`（frozen dataclass：`enabled: bool = False`、`backend: str | None = None`、`ttl_seconds: int | None = None`、`encryption_required: bool = True`、`audit_access_required: bool = True`；全部字段带默认值且默认构成"关闭"态）；`validate_vault_config(config: VaultPortConfig) -> None`（§8.1.3 校验规则）；`acquire_vault_access(config: VaultPortConfig, *, sink: SinkContext, policy: TenantPolicy) -> NoReturn`（唯一取用入口；本 IP 任何输入下必抛 `PrivacyError`，§8.1.4） |
| `lima/evidence_privacy/audit.py` | `AuditLocation`（frozen dataclass：`source_path: str`、`field_path: str | None = None`、`span: tuple[int, int] | None = None`——统一"位置"模型，§8.2.2）；`AuditFinding`（frozen dataclass：`location: AuditLocation`、`fingerprint: str`、`value_kind: str`、`length: int`；**无 preview、无任何原值字段**）；`AuditReport`（frozen dataclass：`policy_version: str`、`policy_digest: str`、`findings: tuple[AuditFinding, ...]`、`artifact_count: int`、`recommended_action: str = "manual-review-and-approved-migration-issue"`——计划性迁移信息，常量，不可携带可执行回调）；`audit_text(source_path: str, text: str, policy: TenantPolicy, *, tenant_id: str, tenant_key: bytes) -> tuple[AuditFinding, ...]`；`audit_structured(source_path: str, value: object, policy: TenantPolicy, *, tenant_id: str, tenant_key: bytes) -> tuple[AuditFinding, ...]`；`build_audit_report(findings: Mapping[str, tuple[AuditFinding, ...]], policy: TenantPolicy) -> AuditReport`（键 = artifact source_path；内嵌 policy_version/policy_digest）；`audit_report_to_json(report: AuditReport) -> str`（canonical JSON 序列化，value-free） |
| `scripts/audit_sensitive_artifacts.py` | 可执行只读 CLI（§8.3）：`python scripts/audit_sensitive_artifacts.py <target-dir> [--output <report-path>] [--pretty]`；`main(argv: Sequence[str] | None = None) -> int`；模块 docstring 标明 IP-0020 与只读契约 |

本 IP 恰好新增 2 个库模块 + 1 个脚本 + 新测试文件 + 审计 fixture 目录（§11）；禁止在上述清单之外新增任何产品文件（裁定 §B.3/B.4 最小性）。

### 7.2 既有 8 文件（零修改，冻结）

`lima/evidence_privacy/` 既有 `__init__.py`、`classifier.py`、`content_scan.py`、`errors.py`、`fingerprint.py`、`models.py`、`policy.py`、`port.py` 一律**零修改**（blob 见 DI-001…DI-008）。`__init__.py` 的 `__all__` 保持 13 项——新符号一律经模块路径 `lima.evidence_privacy.vault_port` / `lima.evidence_privacy.audit` 消费；若实现期间确需扩 `__all__` → 先停，走 §10 DR 条款。

### 7.3 判定"修改是否越界"的准绳

diff 中不得出现：对既有 8 文件任何行的增删改（本 IP 对它们是纯只读）；`scripts/` 既有脚本的任何修改；既有测试文件任何修改。允许：仅 §7.1 三处新增 + §11 新测试文件与 fixture 目录。

## 8. 精确契约

### 8.1 vault port 合同（FR-N05-04）

1. **默认关闭**：`VaultPortConfig()` 无参构造即"关闭"态（`enabled=False`）；不存在任何使 `enabled` 默认为真的构造路径；模块级无全局可变状态、无环境变量读取、无单例"自动启用"钩子。
2. **符号卫生**：`vault_port.py` 内任何函数签名不得接受 secret 材料（无 `secret`/`raw`/`credential`/`token` 形参；`VaultPortConfig` 字段不含值载荷）。vault port 是配置与合同层，不是数据通道。
3. **`validate_vault_config` 规则（冻结）**——违反任一即抛 `PrivacyError(POLICY_ERROR, field_path="vault.<字段>", context={"enabled": …, "backend": <name-or-None>} 型元数据)`：
   - `enabled=False` → 一律通过（关闭态即安全态，其余字段不触发错误）；
   - `enabled=True` 且 `backend is None` → 拒绝；
   - `enabled=True` 且 `backend not in VAULT_BACKEND_PORT_NAMES` → 拒绝（本 IP 该集合为空，故**一切启用均被拒绝**——fail-closed 的结构性保证，而非逐点 if）；
   - `enabled=True` 且 `ttl_seconds is None` 或 `ttl_seconds <= 0` → 拒绝；
   - `enabled=True` 且 `not encryption_required` → 拒绝；
   - `enabled=True` 且 `not audit_access_required` → 拒绝；
   - `backend is not None` 且 `enabled=False` → 拒绝（"配置了后端却未启用"是配置漂移信号，视为误启用前兆，fail-closed）。
4. **`acquire_vault_access` 语义（冻结）**：先 `validate_vault_config(config)`，再复用 `port` 的 sink/tenant 校验语义（`sink.sink_kind in policy.sink_allowlist` 否则 `UNKNOWN_SINK`；tenant 凭据缺失/非法 → `MISSING_TENANT_KEY`/`INVALID_FIELD_VALUE`——**不得**以"vault 特例"放宽任何校验）；全部通过后仍必须抛 `PrivacyError(INTERNAL_REDACTION_FAILURE, field_path="vault.access", context={"reason": "no registered backend"})`。返回类型 `NoReturn`：本 IP 内该函数**不存在成功返回路径**。任何"启用即绕过 sanitize_for_sink"的路径 = 违规（§9 T1/T5 断言锁定）。
5. **错误卫生**：vault 路径抛出的 `PrivacyError` str/repr/context 不得含任何原值子串（context 仅允许 enabled/backend 名/ttl/limit 型元数据）。

### 8.2 只读审计合同（FR-N05-06 + NFR-N05-04 审计侧 + AC/T-N05-06）

1. **纯函数纪律**：`audit_text`/`audit_structured`/`build_audit_report`/`audit_report_to_json` 一律纯函数、无 IO、无网络、无环境变量、无子进程（`redact_text_segments` 先例）；`audit.py` 不 import `vault_port`，不定义任何写/删/迁符号。
2. **统一"位置"模型（`AuditLocation`，冻结）**：
   - `source_path`：artifact 标识（fixture 相对路径或调用方显式标签，字符串，仅此用途）；
   - `field_path`：结构化值的点分路径（`"records[3].token"` 形态，消费 DI-003 既有 field_path 语义；text 输入取 `None`）；
   - `span`：NFC 文本上的半开 `(start, end)` 码点区间（消费 `find_base64_spans` 语义；结构化整值候选取 `(0, len(value))`，部分候选取 span 于该字符串值内）。
   三字段组合唯一表达任意 artifact 内位置；**不新增**更多位置类型即满足全需求（此即"统一模型"，由本 Packet 冻结）。
3. **value-free 不变式**：`AuditFinding`/`AuditReport` 的任何字段、其 str/repr、`audit_report_to_json` 输出，均不得含被扫描原值或其 ≥4 字符子串；fingerprint 经 `compute_fingerprint`（租户隔离语义同 DI-005）；无 preview。
4. **检测谓词族（冻结，与 IP-0017 同源）**：text 输入跑 `find_base64_spans`，每个满足 `is_bare_base64_secret` 谓词的 span 产一条 finding（kind="string"）；structured 输入深度遍历（dict/list），对每个 string 先整值谓词、后 span 谓词，逐命中产 finding（`field_path` 记录路径）。检测只增信息、不修改输入：`audit_*` 不得改写传入对象（NFR-N05-04 "classification 不被审计改写"的库层表达——审计根本不产 classification）。
5. **policy 证据**：`build_audit_report` 必须内嵌 `DEFAULT_POLICY_VERSION`（或 policy 实际 version）与 `policy_digest(policy)`（经模块路径消费，O-1）——NFR-N05-04 审计侧。
6. **计划性迁移信息**：`recommended_action` 为常量字符串（指向"人工复核 + 独立审批迁移 Issue"），不携带回调/路径/命令；报告即"迁移计划"的信息载体，无执行语义。

### 8.3 审计脚本合同（`scripts/audit_sensitive_artifacts.py`）

1. CLI：`python scripts/audit_sensitive_artifacts.py <target-dir> [--output <report-path>] [--pretty]`；`<target-dir>` 必须是显式传入的本地目录（不默认扫仓库、不接受 URL、不递归出 `<target-dir>` 之外）。
2. 行为：遍历 `<target-dir>` 内 `*.json`（按 `audit_structured`，`json.loads` 解析失败 → 该文件计一条 finding？**否**——解析失败跳过该文件并在 stderr 记 `{"file": …, "error": "unparseable-json"}` 型一行警示，不中断、不计 finding）与 `*.txt`（按 `audit_text`，UTF-8 严格解码，失败同样跳过+警示）；汇总为单份 `AuditReport`。
3. 输出：默认 JSON 打印到 stdout；`--output` 显式路径时写入该文件（该路径**不得**位于 `<target-dir>` 内或等于其中任何文件——违反即参数错误退出非零）。exit 0 = 扫描完成（有无 finding 均为 0；参数/IO 错误非零）。
4. **只读证明义务**：脚本对 `<target-dir>` 只以只读模式打开文件；不创建/修改/删除 `<target-dir>` 内任何内容（验收以 fixture 内容 hash + mtime 前后不变证明，§12）。
5. 零原值义务：stdout、报告文件、stderr 警示行均不得含任何被扫描文件中的敏感原值或其 ≥4 字符子串（验收以已知原值清单 grep 断言，§12）。
6. 依赖：仅标准库（argparse/json/pathlib/sys）+ `lima.evidence_privacy.audit`/`content_scan`；不 import 数据库/service/网络模块；无 `shell=True`、无 `eval`/`exec`。
7. 不修改 `scripts/` 既有脚本；本脚本自身不进入任何生产 pipeline（手动/CI 只读调用）。
8. **离线租户上下文（F-1 修订，冻结）**：脚本指纹一律以文档化固定离线租户计算——`tenant_id = "offline-audit"`，tenant_key 为 Packet 文档化的固定字节常量 `b"lima-offline-audit.v1"`（实现为脚本层私有常量 `module-level Final`，非凭据材料、不来自环境/文件/网络）。**离线指纹仅在该固定离线上下文内稳定：不与在线系统指纹（在线租户凭据所产）可关联，不可作为跨租户对比/关联依据**——此声明必须同步体现在报告 JSON 语义中：报告顶层固定携带 `"tenant_context": "offline-audit"`（标识性字符串常量，非凭据），消费方据此可区分离线/在线指纹域。脚本 CLI 不接受任何租户参数。

### 8.4 资源与权限契约（延续 IP-0015 §8.5 / IP-0017 §8.8）

库模块纯内存、无网络、无文件系统访问、无数据库、无子进程、无环境变量；仅 import 标准库与 `lima.contracts.*`、本包。脚本层 IO 仅限 §8.3.4 规定的只读扫描 + 显式报告输出。`requirements*.txt` Forbidden（禁新依赖）。

## 9. Security Boundary（独立章节，Maintainer 2026-09-13 指令③；供 AI Reviewer 提前检查与 Maintainer 合并前独立审查）

威胁模型总述：本 IP 引入三个新攻击面——vault 配置入口（若被误启用将成为 raw-secret 通道）、审计输出通道（报告/stdout/stderr/错误栈是秘密离开系统的最短路径）、审计执行通道（若获得写能力即违反"不删不迁"）。以下五项每项含：威胁描述 / 攻击面 / 防护措施（契约级）/ 对应冻结测试断言计划 / Reviewer 检查要点。

### T1 vault 误启用（默认 disabled 被绕过/环境变量旁路）

- **威胁描述**：攻击者或配置漂移使 vault 在未走审批的情况下处于"可用"态，raw secret 经 vault 通道绕过 `sanitize_for_sink`。
- **攻击面（代码路径/配置入口）**：`vault_port.py` 全部公共符号；模块级状态；环境变量；`VaultPortConfig` 各字段默认值；`validate_vault_config` 分支；未来后端注册点 `VAULT_BACKEND_PORT_NAMES`。
- **防护措施（契约级）**：§8.1.1 默认关闭无旁路构造；§8.1.3 结构性 fail-closed（启用校验以"后端集合为空"兜底，任何启用必被拒绝，且"配后端未启用"亦拒绝）；§8.1.2 签名不收 secret；模块无环境变量读取、无全局可变状态。
- **对应冻结测试断言计划**（§11.1 `test_vault_port_disabled.py`）：默认构造 enabled=False；`validate_vault_config` 九条分支逐条断言（含 backend-set-disabled 拒绝、ttl 缺失/非正拒绝、关加密/关审计拒绝）；`acquire_vault_access` 对默认配置、对 `enabled=True`+伪造后端名、对合法 sink/policy 组合全部抛 `PrivacyError` 且无成功返回；monkeypatch `VAULT_BACKEND_PORT_NAMES` 注入名字仍因 ttl/encryption 校验次序 fail-closed（次序由实现自由，但任何注入下不得出现成功返回——断言 NoReturn）；模块源码 grep 断言无 `os.environ`/`getenv`。
- **Reviewer 检查要点**：diff 中 vault 相关只有 §7.1 三文件与测试；`vault_port.py` 无 import 网络/存储/环境模块；`sanitize_for_sink` 与 `vault_port` 之间无相互 import（port.py 不 import vault_port，零修改即结构性证明）；报告类符号不引用 vault。

### T2 审计泄漏原值（审计报告/日志/stdout/错误栈打印秘密）

- **威胁描述**：审计的本意是发现秘密，其输出（finding、报告 JSON、stdout、stderr 警示、异常栈）反而成为秘密外泄通道。
- **攻击面**：`AuditFinding`/`AuditReport` 字段与 repr；`audit_report_to_json`；脚本 stdout/stderr/`--output` 文件；JSON 解码/IO 异常路径的 traceback。
- **防护措施**：§8.2.3 value-free 不变式（字段白名单：位置/fingerprint/kind/length/policy 证据）；fingerprint 为 HMAC 摘要；§8.3.5 零原值义务；错误路径只报文件名与错误类别，不报内容。
- **对应冻结测试断言计划**（§11.1 `test_readonly_audit.py`）：对含已知原值（裸 Base64 秘密、深层 token、PEM 行、Unicode 混排）的 fixture 跑库函数与脚本子进程，断言 finding 元组、`audit_report_to_json` 输出、脚本 stdout/stderr、报告文件对原值清单逐项 grep 零命中（含 ≥4 字符子串抽查）；异常路径（目录不存在/坏 JSON）错误输出零原值；`AuditFinding` 无 `preview` 属性（`assert not hasattr`）。
- **Reviewer 检查要点**：`audit.py` 与脚本中无 f-string 直接内插被扫描内容；无 `print(value/text/content)` 形态调用；repr 自查——对任一 finding `assert 原值 not in repr(finding)`。

### T3 越界删除/迁移（审计路径获得写/删/迁能力）

- **威胁描述**：审计入口被扩展为"顺手清理"，获得对历史 artifact 的写/删/迁能力，违反 FR-N05-06"不执行删除或迁移"。
- **攻击面**：脚本对 `<target-dir>` 的文件操作；`AuditReport.recommended_action` 若可携带可执行载荷；`audit.py` 若含 IO 符号。
- **防护措施**：§8.2.1 纯函数纪律（audit.py 零 IO）；§8.2.6 `recommended_action` 为常量字符串；§8.3.4 只读打开 + 报告路径不得落在扫描目录内；无 `shutil`/`os.remove`/`unlink`/`rename` 调用。
- **对应冻结测试断言计划**：脚本前后 fixture 目录逐文件 sha256 + mtime 不变；`--output` 指向目录内路径 → 非零退出且未创建文件；模块源码 grep 断言 `audit.py`/脚本无 `open(..., "w"/"a"/"x")`（除显式报告路径分支）、无 remove/unlink/rmtree/rename。
- **Reviewer 检查要点**：脚本全部 `open` 调用模式参数审计；报告写路径规范化后与扫描目录做包含关系判定。

### T4 跨租户读取（审计绕过租户隔离读取他人 fingerprint/位置关联）

- **威胁描述**：审计报告把不同租户的 fingerprint/位置拼在一份可横向对比的载体里，或以错误 tenant_key 计算 fingerprint，破坏"跨租户不可关联"。
- **攻击面**：`audit_*` 的 `tenant_id`/`tenant_key` 参数；报告聚合（多 artifact 单报告）；脚本对多租户数据混扫；脚本层指纹的租户凭据来源（F-1 缺口原址）。
- **防护措施**：fingerprint 一律经 `compute_fingerprint`（DI-005 租户隔离语义沿用——换 key 指纹必变）；`AuditReport` 不含 tenant_id/tenant_key 字段（报告按单次调用单租户产出；跨租户聚合不在本 IP）；脚本使用 §8.3.8 固定离线租户（`"offline-audit"` + 文档化常量 `b"lima-offline-audit.v1"`——文档化常量，非凭据材料），报告以 `"tenant_context": "offline-audit"` 显式标识离线指纹域，与在线系统指纹不可关联、不可作跨租户对比依据。
- **对应冻结测试断言计划**：同一 text/structured 输入换 `tenant_key` → 全部 fingerprint 变化且位置不变；同 key 重复调用 → fingerprint 稳定（同租户可识别重复内容）；`AuditReport` 字段集合断言（无 tenant_id/tenant_key 字段）；**离线指纹一致性（F-1）**——同一 fixture：脚本子进程输出的 fingerprint ≡ 库函数（`audit_text`/`audit_structured`）以固定离线租户凭据计算的值 ≢ 以任何其他租户凭据计算的值。
- **Reviewer 检查要点**：审计调用链上不存在绕过 `compute_fingerprint` 的自造摘要；报告 JSON schema 字段白名单与 §7.1 一致。

### T5 默认关闭旁路（conformance fixture 意外依赖 vault 开启才能通过）

- **威胁描述**：测试或 conformance fixture 隐式依赖 vault 启用（如 fixture 造数据用 vault、断言经 vault 通道），使"默认关闭"成为纸面属性。
- **攻击面**：新测试文件的 fixture 构造；`scripts/audit_sensitive_artifacts.py` 对 vault 的 import；CI 命令。
- **防护措施**：§8.3.6 脚本依赖白名单不含 vault_port；测试计划 §11 明确全部 fixture 用标准库构造；本 IP 无任何代码路径成功启用 vault（T1 结构性保证），故不存在可依赖的"开启态"。
- **对应冻结测试断言计划**：`import lima.evidence_privacy.vault_port as vp; assert vp.VAULT_BACKEND_PORT_NAMES == frozenset()`；`audit` 模块与脚本模块 `sys.modules` 检查不引用 vault_port（或源码 grep 无该 import）；全测试套（154+新）在完全不 touch vault 的默认状态下通过即旁路不存在的经验证据。
- **Reviewer 检查要点**：新测试文件无 `vault_port` import（除 `test_vault_port_disabled.py` 自身）；脚本 `--help` 输出无 vault 相关参数。

## 10. Packet 内显式 DR 条款（Add-only 增量授权边界）

### DR-IP-0020-1：`__all__` 扩展与新增类型的后置授权（默认不启用）

- **默认方案**：`__init__.py` 零修改，新符号经模块路径消费（§7.2）。若实现或下游证明必须扩 `__all__`（或需给 `AuditLocation` 增加字段、给脚本增加参数语义变更），必须先停止并向 Coordinator 提 Decision Request；获授权后：更新本 Packet（版本 +1）→ 重走 RED → 重冻结。既有 13 项 `__all__` 与 12 枚举任何情况下不得改动。
- **位置模型扩展**：若未来出现 `AuditLocation` 三字段表达不了的位置形态（如字节偏移、压缩容器内偏移），属新 Packet/DR 范围；本 IP 内三字段即终态。

## 11. 测试冻结计划（阶段二执行的期望；本轮不冻结）

### 11.1 文件布局与最小用例数（全部 P&V 所有，均为新文件）

| 文件 | 覆盖需求 | 最少用例数 |
|---|---|---|
| `tests/evidence_privacy/test_vault_port_disabled.py` | FR-N05-04、§8.1、§9 T1/T5 | 12（默认关闭态 1 + validate 九分支 9 + acquire NoReturn 双配置 2；含源码卫生 grep 断言计入用例） |
| `tests/evidence_privacy/test_readonly_audit.py` | FR-N05-06、NFR-N05-04 审计侧、AC/T-N05-06、§8.2、§8.3、§9 T2/T3/T4/T5 | 14（text 扫描 2 + structured 深层/field_path 2 + value-free/repr/JSON 零原值 3 + 租户隔离/稳定 2 + report policy 证据 1 + 脚本子进程：exit 0+stdout 零原值 1 + fixture hash/mtime 不变 1 + `--output` 落目录内拒绝 1（含 §11.5 Windows 路径变体）+ 坏 JSON 跳过零泄漏 1；**离线指纹一致性（F-1，§9 T4）**：脚本 fingerprint ≡ 库函数以 §8.3.8 固定离线租户计算值 ≢ 其他租户计算值——断言并入脚本子进程组与租户隔离组，不另增最低用例数） |

合计 ≥ 26 个新用例；既有 154 + 新 ≥26 = ≥180（evidence_privacy 目录）。每条断言注释锚定需求 ID 与 Packet 契约小节号（`# FR-N05-04 §8.1.3: ...`，PI-DR1）。

### 11.2 审计 fixture（新增目录，冻结位置）

`tests/evidence_privacy/fixtures/audit_samples/`：`sample.json`（嵌套结构含裸 Base64 token、深层 secret 键、URL credential 文本值）、`log_excerpt.txt`（日志行 + traceback + 混排 Unicode + 裸 Base64 span）、`broken.json`（非法 JSON，供跳过路径）、`CLEAN` 不设——每文件顶部注释列出"已知敏感原值清单"（测试内以常量复述并 grep 断言，注释与常量一致由测试自校验）。fixture 写入显式钉死 LF（`open(..., "wb")` + `\n`，PI-DR6 交叉适用）。fixture 属 P&V 阶段二交付物（测试资产），非实现产物。

### 11.3 预期 RED 形态（PI-DR4）

- 两测试文件对现实现均为 `ModuleNotFoundError`（`lima.evidence_privacy.vault_port` / `lima.evidence_privacy.audit` 不存在）与脚本文件不存在（子进程用例 FileNotFoundError）——缺失交付触发，非 arrange 缺陷。
- 阶段二须逐文件标注 RED 清单（缺失符号/文件 → 用例），并附逐断言锚定表（断言 → 需求 ID → 缺失符号/行为）。

### 11.4 scratch 骨架 GREEN 证明（PI-DR2，冻结前执行、不入交付）

worktree 外临时目录（如 `%TEMP%/ip0020-scratch`）实现最小骨架：`vault_port.py`/`audit.py` 全符号 + 脚本最小实现（fingerprint 必须真实 HMAC 语义一次到位）；`cp -r tests/evidence_privacy <scratch>/tests/` 后双 runner 实跑确认无 collection error 且断言语义可达 GREEN；记录命令与输出到 RED 证据文档；scratch 用后销毁，绝不进入 commit。

### 11.5 双 runner 条款（PI-DR6-bis，冻结）

进入 Frozen Test Commit 的全部新测试必须同时满足 `python -m pytest tests/evidence_privacy -q` 与 `python -m unittest discover -s tests/evidence_privacy -t .` 可收集、可执行、结论一致；禁止 pytest 专有 API（`fixture`/`parametrize`/`importorskip`），测试类继承 `unittest.TestCase`；断言不隐式依赖平台行为（路径分隔统一 `pathlib`、大小写、权限语义）；mtime 断言允许精度 ≥1s 的比较（避免 FS 时间戳粒度假红），fixture 内容不变以 sha256 为准。`--output` 越界判定断言须以 `Path(...).resolve()` 规范化后做包含关系判定，并覆盖 Windows 变体（大小写不同、正反斜杠混用、`..` 段）——各变体均须判越界（v1.1 采纳 Coordinator 非阻塞建议）。

### 11.6 回归命令（cwd 钉死 = 交付 worktree 根；PI-DR3）

```bash
cd <交付 worktree 根目录>
python -m pytest tests/contracts -q                    # 617 passed（DI-015 基线）
python -m pytest tests/evidence_privacy -q             # 154 既有 + 新套件全绿，0 skip
python -m unittest discover -s tests/evidence_privacy -t .   # OK（双 runner）
```

## 12. 验收命令（全部钉死 cwd = 交付 worktree 根）

| 类别 | 命令 | 判定 |
|---|---|---|
| baseline | `git rev-parse HEAD && python -m pytest tests/contracts -q` | HEAD 在 Frozen Test Commit 祖先链上；617 passed |
| slice-pytest | `python -m pytest tests/evidence_privacy -q` | 全绿 0 skip，总数 = 154 + ≥26 |
| slice-unittest | `python -m unittest discover -s tests/evidence_privacy -t .` | OK |
| regression | `python -m pytest tests/contracts tests/evidence_privacy -q` | 全绿 |
| audit-script | `python scripts/audit_sensitive_artifacts.py tests/evidence_privacy/fixtures/audit_samples` | exit 0；stdout 为合法 JSON 报告；对 fixture 注释中的原值清单逐项 `grep -F` stdout → 零命中 |
| audit-readonly | 运行前后 `find tests/evidence_privacy/fixtures/audit_samples -type f -exec sha256sum {} +` 与 `stat` mtime | 逐文件 sha256 相等；mtime 不减不变（§9 T3） |
| audit-report-output | `python scripts/audit_sensitive_artifacts.py <fixture-dir> --output <tmp>/r.json` 后 grep 报告文件 | 报告含 `policy_version`/`policy_digest`/findings 位置字段；原值清单零命中；fixture 目录无新文件 |
| vault-disabled | `python -c "from lima.evidence_privacy.vault_port import VAULT_BACKEND_PORT_NAMES; assert VAULT_BACKEND_PORT_NAMES == frozenset(); print('ok')"` | `ok` |
| frozen-symbols | `python -c "import lima.evidence_privacy as p; print(len(p.__all__), sorted(p.__all__))"` | `13` + 13 符号集合不变（vault/audit 不入 `__all__`） |
| frozen-blobs | `git ls-tree HEAD lima/evidence_privacy/` | 既有 8 文件 blob 与 DI-001…DI-008 逐一相等（零修改证明） |
| post-merge（P&V 阶段三） | 干净 worktree 于 merge commit 重跑 slice-pytest + slice-unittest + regression + audit-script | 全绿 |

Python 解释器：`python`（3.12.x，基线亲测可用）。

## 13. AC traceability（逐条）

| 需求 | 测试（文件::断言组） | 证据等级 |
|---|---|---|
| FR-N05-04 | test_vault_port_disabled.py（默认关闭、validate 九分支、acquire NoReturn、源码卫生） | contract |
| FR-N05-06 | test_readonly_audit.py（text/structured 扫描、脚本子进程、fixture 只读证明、计划性 recommended_action） | integration |
| NFR-N05-04（审计侧） | test_readonly_audit.py（report 携带 policy_version/policy_digest；audit_* 不改写输入对象断言） | contract |
| AC/T-N05-06 | test_readonly_audit.py（原值清单对 stdout/报告/repr/错误输出 grep 零命中） | integration |
| Security Boundary T1–T5 | §9 各项"对应冻结测试断言计划"逐条落位两测试文件（T1→vault 12 例；T2/T3/T4→audit 各断言组；T5→两文件各含禁依赖断言） | contract + integration |

## 14. Stop Conditions（裁定 §D + 本 Packet 条款）

1. 发现需改 13 符号 / 12 枚举 / `__all__` / 既有 154 用例 / 既有 8 文件才能承载 → 停止，提 Decision Request。
2. 审计脚本任何路径需打印原值或写存储/fixture 才能满足某解释 → 停止上报，不得以改测试消除。
3. 发现需生产接线或新增 sink_kind 才能满足 FR → DR，禁止自行扩界。
4. 基线漂移（§6 复核失败：origin/main 前移且锚定 blob 变化）→ 停止。
5. 编号 IP-0020 被其他轨道持有登记记录 → 停止，回 Coordinator。
6. 疑似规格矛盾 / 同根因两轮失败 → 升级 glm-5.3/max。
7. 冻结后需改冻结测试/Oracle → 先提 Decision Request，未授权不得动（P&V 责任书 §3）。
8. 需启用 §10 DR 条款（扩 `__all__`/位置模型扩展）→ 先 DR，授权后重走 RED。
9. scratch 骨架无法证明 GREEN 可达 → 升级 Coordinator。

## 15. Completion Summary 模板（Implementation 必填）

- Final commit 完整 SHA + 分支名；Frozen Test Commit SHA 与 Packet merge commit SHA；
- FR→AC→T 追踪表（完整稳定 ID `[V5-N05 / #94] FR-N05-xx` 形式，逐条映射本 Packet §13）；
- 实际测试命令与输出摘要（§12 全表逐行，含双 runner 与 audit-script/readonly 三连）；
- 关键 digest：policy_digest 示例、一条 finding 的 fingerprint 示例（脱敏展示）、新文件 sha256 清单、fixture sha256 前后对照；
- 文件边界确认：`git diff --stat`（预期：3 新增（vault_port.py/audit.py/脚本）+ 2 新测试文件 + fixtures 目录，0 越界）；`git ls-tree` 证明既有 8 文件 blob 零变化；
- Security Boundary 自查：T1–T5 逐项确认（引用 §9 检查要点）；
- 已知限制（vault 无后端实现、审计检测谓词族限于 Base64/敏感形态、不做生产接线、迁移仅为计划性文本）与 follow-up（生产接线 IP、独立审批迁移 Issue、#66 解锁）；
- 确认未修改 Read-only/Forbidden 文件、未引入新依赖、库模块零 IO、未动既有 154 冻结用例。

## 16. Packet completion definition

本 Packet 达成：覆盖裁定 §B.1 全部 covered 需求（FR-N05-04 / FR-N05-06 / NFR-N05-04 审计侧 / AC/T-N05-06 / Security Boundary 章节）且零 TBD；vault port（§8.1）与只读审计（§8.2/§8.3，含统一位置模型 §8.2.2）精确契约冻结；Security Boundary T1–T5 独立成章供 Reviewer/Maintainer 引用；测试冻结计划含最小用例数（2 文件 × ≥12/≥14）、fixture 位置与只读证明义务、RED 形态、PI-DR2 scratch、双 runner 条款（PI-DR6-bis）、回归命令（617+154+新，cwd 钉死）；验收命令全表钉死 cwd；交接书（`docs/LIMA_Coding_Agent_IP-0020_正式开发任务交接.md`）就绪。Packet PR 合并后由 Coordinator 标记 PACKET-MERGED，方可进入阶段二（测试冻结，另行 Assignment）。本 Packet 为 CLOSURE-CANDIDATE 交付物，不构成 #94 关闭许可。
