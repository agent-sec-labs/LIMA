# LIMA Implementation Packet IP-0020：Vault/Audit（Feature Slice S3：vault port 默认 disabled 合同 + 历史 Artifact 只读审计）

- Packet 版本：**1.4**（2026-09-13，P&V erratum rev.3，状态 DESIGN-FROZEN-REVISED / PENDING-MERGE；开工基线前移至 origin/main = `30bdfaa13ac72572d65ccb2567ae8702923c4187`（IP-0021 #179，与 #94 零文件交集）；本分支 rebase 至新基线（零冲突），commit 映射：`493caeb→333e376`、`eab3365→00c4939`。**v1.3 → v1.4 修订**：按 Maintainer 三项二次修订指令 R6-R8（已入 Issue #94 Ledger 决策日志 2026-09-13）：R6 source_path 唯一合法形态收紧为 `^a(0|[1-9][0-9]{0,3})$`（a0–a9999，与 `max_files_per_scan=10_000` 一一对应封闭；字符白名单任何变体已证伪并废止，§17.D1'.3、§18 #20）；R7 读取统一为四步单一序列——`os.open`（POSIX O_NOFOLLOW）→ `fstat(fd)`↔`entry.stat(follow_symlinks=False)` 比对 → **同一 fd** 经 `os.fdopen` 执行 `read(LIMIT+1)` → with 关闭；禁 `open(path,"rb")`/重开/`read_bytes()`/`st_size` 预检（§17.F5'-R2.1'、§17.B2'-R3、§18 #22）；R8 预算触顶**即停**：`incomplete_reasons` 恰一条 `"scan:file-budget:truncated-at=a{n>}"`（字节同型）、stderr 单行汇总、非逐文件条目，报告规模有界（§17.F5'-R2.2'、§18 #23）。此前 v1.3：按 Maintainer 对 PR #178 的五项修订指令 R1-R5（已入 Issue #94 Ledger 决策日志 2026-09-13；规格增量正本 = COORD-IP0020-R1R5_SPEC_ADDENDUM_2026-09-13，P&V 逐项落实）：R1 `TenantAuditContext` repr=False + 自定义 `__repr__` 仅含 tenant_id_len/tenant_key_len，构造异常链全查零 key（§17.D2'-R1、§18 #17）；R2 句柄限量读取 `f.read(LIMIT+1)`（禁 `read_bytes()`/st_size 预检）+ 目录级 `max_files_per_scan=10_000`/`max_total_bytes_per_scan=104_857_600`（§17.F5'-R2、§18 #18）；R3 定稿机制 A——`os.open`（POSIX 叠加 O_NOFOLLOW）+ `fstat(fd)` 与 `entry.stat(follow_symlinks=False)` 比对 `(st_dev, st_ino)`，不一致或 st_ino==0 一律 fail-closed（symlink-risk），v1.2 "Windows 注明残余 TOCTOU" 条款废止（§17.B2'-R3、§18 #19）；R4 库侧 source_path 白名单 `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` → `INVALID_FIELD_VALUE("source_path")`（新增 §17.D1'.3、§18 #20）；R5 derived_key 定稿（HMAC-SHA256(tenant_key, b"lima.evidence_privacy.tenant-key.v1\x00"+tenant_id.utf8)，对齐 fingerprint.py 实物）+ `.pv_tmp` 权威引用替换为 §17 自含 + Ledger 锚点（§17.D2'-R5、§18 #21、R5.3 替换清单）。**顺序裁定**：预备 Frozen v3（commit 2a47a1e，分支 codex/ip-0020-frozen-tests-v3）仅为预备 RED 证据；正式 Frozen v3-final 于本 Packet 合并后在合并 main 上重建并重证 RED。此前 v1.2：**v1.1 → v1.2 修订（erratum，修订非删除）**：按 Maintainer 修订裁定 **DR-IP-0020-4R**（裁定正本 = Issue #94 Ledger 决策日志 2026-09-13（Maintainer DR-IP-0020-4R 修订裁定，稳定仓库锚点）；契约增量规格 = 本 Packet §17（自含权威）；erratum commit = 本修订合并 commit SHA（合并时回填）。裁定精神：暂不整组批准 DR-IP-0020-4，六项修订执行——D1' 位置模型 v2（成员序号路径 + 全携带面零原值）、D2' `TenantAuditContext` 聚合入口租户绑定（混合 fail-closed、内部长标签双重防漏出、零 finding 批次覆盖）、D3' 脚本 per-run 随机密钥（禁固定密钥回流）、F4' vault 错误 backend 元数据化、B2' symlink 边界 + Linux 权威负例、F5' 预算分层 + `status`/`incomplete_reasons` + exit 3；附随 F6' Ruff 清零、G3' `classify_payload` 空租户 fail-closed）。修订落点：§8.1.3/§8.1.5（F4'）、§8.2（D1'/D2'/F5' 库层）、§8.3（D1'.2/D3'/B2'/F5' 脚本层）、§9 T2/T4（携带面与租户隔离升级）、§11/§12（断言面与验收命令）、新增 **§17 v1.2 契约增量规格（逐小节）与 §18 断言映射总表（修订非删除，逐条"旧 → 新"映射）**。被 v1.2 替代的 v1.1 条款在本节内以 **[v1.2-replaced]** 标注保留原文（修订非删除），冲突时以 §17/§18 为准。既有 8 文件零修改边界、`__all__` 13 项、`PrivacyErrorCode` 12 值锚定不动（红线 5；`audit.py` 扩 `TenantAuditContext` 属 DR-IP-0020-1 后置授权情形，DR-IP-0020-4R 即授权，见 §17.D2'）。此前：v1.1（2026-09-13，P&V 起草，状态 DESIGN-FROZEN / PENDING-MERGE；v1.0 同日发布。v1.0 → v1.1 修订：按 Coordinator PR #173 评审裁定 COORD-IP0020-PACKET_PR_REVIEW 2026-09-13 + AI Reviewer 提前检查 REVIEW-IP-0020-SECBOUNDARY_EARLYCHECK 发现项 **F-1（MINOR）**——§8.2.3 指纹需租户凭据 vs §8.3 脚本 CLI 无租户参数 vs §9 T4 表述的租户凭据未定义缺口，采用"固定离线租户"方案修订：新增 §8.3.8、改写 §9 T4、更新 §11.1 断言组、§11.5 补 Windows 路径变体用例（非阻塞建议采纳）。其余内容零改动）
- 制作：LIMA Packet & Verification Agent（运行模型：无法核验——本环境未提供可验证的运行元数据）
- 依据：Coordinator 裁定 COORD-IP94-S3-ENTRY_RULING-2026-09-13（原 `.pv_tmp/COORD-IP94-S3-ENTRY_RULING_2026-09-13.md` 为过程性证据，非权威；Assignment 正本以 PR #173 合并 commit 中的 Packet v1.0 §依据 为准；Assignment 编号 `IP-0020-PKT-P1/v1` 即仓库内可 grep 锚点；编号登记见其 §C.2）

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
| DI-011 | Coordinator 裁定 COORD-IP94-S3-ENTRY_RULING-2026-09-13（§A consumer review / §B 切分 + T1–T5 / §C 编号登记 / §D Assignment / §E 风险） | 过程性证据（原 `.pv_tmp/COORD-IP94-S3-ENTRY_RULING_2026-09-13.md`，非权威）；权威 = PR #173 合并 commit 内 Packet v1.0 §依据 | 派发权威 |
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

> **[v1.2 修订 / DR-IP-0020-4R F4']** §8.1.3 的 `_rejection`/Rule 4 context 与 §8.1.5 错误卫生升级：context 中 `"backend": config.backend`（原文）**替换**为 `{"backend_len": len(config.backend) if config.backend is not None else None, "backend_registered": config.backend in VAULT_BACKEND_PORT_NAMES if config.backend is not None else False}`——错误信息不得回显 backend 原文；断言升级为 `PrivacyError` 的 `str()`/`repr()` 不含 backend 原文（含 FAKE_BACKEND 合成名）且 context 含 `backend_len`/`backend_registered` 键。详见 §17.F4'。其余 §8.1 条款不变。

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

> **[v1.2 修订 / DR-IP-0020-4R D1'/D2'/F5']** 本节以下四点被 §17 替代/扩展：
> (a) §8.2.2 的 `field_path`"点分路径（`"records[3].token"` 形态）"**替换**为成员序号路径（`m<n>`/`[n]` 段，文档序，不含字段名与值；顶层标量根 `field_path=None`）——见 §17.D1'.1（被替代原文保留 [v1.2-replaced] 于 §17）；
> (b) §8.2.4 与 §7.1 中 `audit_text`/`audit_structured`/`build_audit_report` 的 keyword-only `tenant_id`/`tenant_key` 参数**移除**，唯一租户入口改为 `TenantAuditContext`（构造即校验；混合租户聚合 → `POLICY_ERROR(field_path="report.tenant_mixing")`；`AuditFinding` 增内部 `_tenant_tag`（64 hex，`repr=False` + 序列化白名单排除，双重防漏出；仅聚合校验用，任何用途不进输出））——见 §17.D2'；
> (c) §8.2.3 value-free 不变式**扩面**：除原值与 ≥4 字符子串外，明文**键名**与明文**文件名**亦为零命中对象（携带面 = `AuditFinding` 四字段 + `AuditLocation` 三字段 + repr + 报告 JSON 全键 + stderr 警示行）——见 §17.D1'.2；
> (d) 新增库层预算（typed 拒绝）：遍历深度 > `PrivacyLimits().max_depth`（32）→ `PrivacyError(MAX_DEPTH_EXCEEDED, field_path=<序号路径>, context={"depth": d, "max_depth": 32})`（预算前置消除裸 `RecursionError`）；单次 `audit_text`/`audit_structured` findings 总数 > `max_items`（10_000）→ `PrivacyError(RESOURCE_LIMIT_EXCEEDED, field_path="findings", context={"max_items": 10000})`——见 §17.F5'。
> 其余 §8.2 条款（纯函数纪律、检测谓词族、policy 证据、recommended_action 常量）不变。

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

> **[v1.2 修订 / DR-IP-0020-4R D1'.2/D3'/B2'/F5']** 本节以下各点被 §17 替代/扩展：
> (a) §8.3.2/§8.3.5 的 stderr 警示 `{"file": …}` 形态**替换**为 `{"artifact": "a<n>", "error": <category>}`（文件级警示与任何异常路径**零文件名**；被替代原文保留 [v1.2-replaced] 于 §17）；
> (b) 报告 `source_path` 不再是文件名，改为工件序号 `a<n>`（目标目录内符合后缀过滤的文件**字典序** 0 基编号；symlink 亦占工件序号）；
> (c) §8.3.3 exit code 语义扩展：`0` = 完成且完整；`1` = 报告写失败（维持）；`2` = 参数/IO 参数错误（维持）；**新增 `3` = 完成但有未完成项**（`status:"incomplete"` 的正常退出路径，非错误退出；消费者必须检查 `status`/`incomplete_reasons`）；
> (d) §8.3.8 固定离线租户常量方案**废止**：脚本每次运行生成 `tenant_key = secrets.token_bytes(32)`（per-run 随机），`tenant_id = "offline-audit"`；`OFFLINE_TENANT_KEY`（`b"lima-offline-audit.v1"`）常量**删除**且禁止回流（红线 4）；报告顶层 `tenant_context` 值定稿 `"offline-audit/random-per-run"`；报告顶层新增必含 `status`（`"complete"`|`"incomplete"`）与 `incomplete_reasons`（非空当且仅当存在 unparseable-json/undecodable-text/symlink-skipped/resource-limit 各类未完成项）；单文件字节数 > `max_payload_bytes`（1_048_576）→ 可识别跳过（stderr `resource-limit` + `incomplete_reasons` 记 `"a<n>:resource-limit"`），**禁止静默超限跳过与"零发现即完成"假象**；
> (e) 遍历改 `os.scandir`；`entry.is_symlink()` → 跳过 + `{"artifact": "a<n>", "error": "symlink-skipped"}` + `incomplete_reasons` 记录；读取采用 R3 定稿机制 A（`os.open` + POSIX `O_NOFOLLOW` + `fstat(fd)`/`entry.stat(follow_symlinks=False)` 的 `(st_dev, st_ino)` 比对，不一致或 `st_ino==0` 一律 fail-closed `symlink-risk`；v1.2 "Windows 注明残余 TOCTOU" 条款废止，见 §17.B2'-R3）；`target_dir` 本身或中间目录解析后为 symlink → stderr `error: target-dir must not be a symlink path` + exit 2（调用方传入路径允许回显）。
> 详见 §17.D1'.2/D3'/B2'/F5'。其余 §8.3 条款（CLI 形态、只读证明、依赖白名单、不进生产 pipeline）不变。

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

> **[v1.2 修订 / DR-IP-0020-4R D1'（替代 DR4-D1 1A）]** 零原值携带面由"值与 ≥4 字符子串"扩至**明文键名与明文文件名**；`field_path` 采用成员序号路径（不含字段名），报告 `source_path`/stderr 警示采用工件序号 `a<n>`（不含文件名）；任何携带面（finding 四字段、location 三字段、repr、报告 JSON 全键、stderr）对 fixture 明文键名/值/文件名零命中。维护者裁定不批准 1A（8 位 HMAC 截断指纹可猜测、可能碰撞，不构成安全边界）。断言计划见 §17.D1'.2 与 §18 表 #2/#13。

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

> **[v1.2 修订 / DR-IP-0020-4R D2'/D3'（替代 DR4-D2 2A、DR4-D3 3A）]** 防护升级为结构性：审计批次/聚合入口绑定 `TenantAuditContext`（旧 keyword-only `tenant_id`/`tenant_key` 移除，签名级强制防绕过）；混合租户 findings 进入同一报告 → `POLICY_ERROR(field_path="report.tenant_mixing", context={"distinct_tenant_tags": n})` fail-closed；零 finding 批次仍执行 context 有效性绑定；内部 `_tenant_tag`（64 hex）仅用于聚合一致性校验，`repr=False` + 序列化白名单双重排除，任何用途不进输出（不批准 2A：短 tag 写报告会形成新关联标识）。脚本离线指纹改 per-run 随机密钥（不批准 3A：完整性标识不得暗示防篡改；不得恢复公开固定密钥），跨运行不可比；`tenant_context = "offline-audit/random-per-run"`。断言计划见 §17.D2'/D3' 与 §18 表 #4/#5/#6/#11。

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

> **[v1.2 修订 / DR-IP-0020-4R]** 本节为 v1.0/v1.1 期计划文本，保留为历史（修订非删除）。**v1.2 生效的测试面 = Frozen Test Commit v3**（分支 `codex/ip-0020-frozen-tests-v3`，基线 `c5b375e`，负例对 c5b375e 逐条 RED 先行）：修订对象为既有三测试文件（`test_readonly_audit.py`/`test_vault_port_disabled.py`/`test_classifier.py`——注意：v1.0/v1.1 期"新断言一律进新测试文件、既有测试只读"的边界被 DR-IP-0020-4R 显式放宽为"断言修订（修订非删除，逐条映射）"），fixture 扩展（键名=敏感值样本、文件名=敏感值样本、深嵌套/超大文件在测试内临时生成）；每条修订/新增断言注释锚定 DR-IP-0020-4R 条目（D1'/D2'/D3'/B2'/F4'/F5'/G3'/F6'）。完整"旧 → 新"断言映射见 §18；Ruff 清零（F6'）随 v3 测试修订一并执行（格式类，断言语义不变）。

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

> **[v1.2 修订 / DR-IP-0020-4R]** 上表命令在 v1.2 下的判定增量：(1) `audit-script` 行 exit code 判定改为——fixture 目录含 broken.json（unparseable-json）→ **exit 3** 且 stdout 报告 `status:"incomplete"`、`incomplete_reasons` 非空；纯净临时目录 → exit 0 且 `status:"complete"`；(2) stdout/报告/stderr grep 零命中清单在原值之外**加入明文键名与明文文件名**（fixture 头部注释清单同扩）；(3) `slice-pytest`/`slice-unittest` 计数以 Frozen v3 后的实际用例数为准（双 runner 计数一致）；(4) 新增 `ruff check . && ruff format --check .` 清零（F6'）。§17/§18 为验收断言权威。

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

## 17. v1.2 契约增量规格（DR-IP-0020-4R erratum 正本；修订非删除）

> 本章为 DR-IP-0020-4R 六项修订裁定（D1'/D2'/D3'/F4'/B2'/F5' + 附随 F6'/G3'）**及 Maintainer R1-R5 修订指令（2026-09-13）**的落地规格；本节即权威规格（自含），上游依据 = Issue #94 Ledger 决策日志 2026-09-13（DR-IP-0020-4R 与 R1-R5 指令）。原 `.pv_tmp/COORD-IP0020-DR4R_RULING_AND_V12_SPEC_2026-09-13.md` 与 `.pv_tmp/COORD-IP0020-R1R5_SPEC_ADDENDUM_2026-09-13.md` 为过程性证据，非权威。与 §7.1/§8/§9 v1.1 原文冲突处以本章为准；被替代原文即 §8/§9 内 [v1.2-replaced] 语境下的 v1.1 表述，语义继承关系见 §18。总则：全部修订复用既有 `PrivacyErrorCode`（12 值冻结不动）；`lima/evidence_privacy` 既有 8 文件中 `models.py`/`errors.py`/`fingerprint.py`/`policy.py`/`port.py`/`content_scan.py` 仍零修改，本轮授权修订对象 = `audit.py`/`classifier.py`/`vault_port.py` + 脚本（IP-0020 新增三产品文件 + 脚本）。所有签名变化均显式列出并进入 §18。

### 17.D1'.1 位置模型 v2：确定性成员序号路径（替代 §8.2.2 field_path 条款）

**field_path 编码（冻结）**：
- JSON object 成员：按文档序（insertion order；`json.loads` 保序）取 0 基成员序号，段写作 `m<n>`（如 `m0`、`m13`）。
- JSON array 元素：0 基索引，段写作 `[n]`（如 `[2]`）。
- 段拼接：对象段间以 `.` 连接，数组段紧跟（无点）。规范形式示例：顶层 object 的第 1 个成员是 list，其第 3 个元素是 object 的第 2 个成员 → `m0[2].m1`。`m0.m3` 合法；`m0[2]m1` 不合法。
- **顶层无容器（标量根）**：`audit_structured` 收到 str/int/bool/null 顶层值时 `field_path = None`，仅以 span 定位（与 text 模式一致）；bytes/非容器输入同此。
- **顶层 array**：从 `[n]` 起始（如 `[0]`、`[1].m2`）。
- **空 object / 空 array**：无子节点被访问，不产生任何路径段；空容器本身不产生 finding。
- **重复键**：以文档序位置为准（后出现同键即新序号），确定性不受影响。
- **field_path 完全无键名无值**：任何键名、值、键名子串不得出现于 field_path（断言锁定：repr/JSON 全文对 fixture 明文键名与值零命中）。

**人工复现语义（规范文案，写入实现文档字符串/Packet）**：定位 = `source_path`（工件序号，见 17.D1'.2）+ 序号路径 + span。复现方法："按 JSON 文档序数该路径第几个成员：自根容器起，`m<n>` 表示当前 object 按出现顺序的第 n 个（0 基）成员，`[n]` 表示当前 array 的第 n 个（0 基）元素；span 为该成员字符串值 NFC 规范化后半开码点区间。"

**[v1.2-replaced 原文]** §8.2.2 field_path 条款 v1.1 原文："`field_path`：结构化值的点分路径（`"records[3].token"` 形态，消费 DI-003 既有 field_path 语义；text 输入取 `None`）"——该"点分字段名"表示被上表替代（安全意图继承：位置定位由序号路径承担，原值携带面消除；裁定理由：不批准 1A——长度+8 位 HMAC 截断指纹可猜测、可能碰撞，不构成安全边界；替代要求 = 不含字段名的确定性位置表示）。

### 17.D1'.2 source_path 工件序号化与原值携带面全面排查（替代/扩展 §8.3.2、§8.3.5、§9 T2）

文件名本身可携带秘密（如 `token_<secret>.json`）。**裁定处置（定稿）**：脚本层 `source_path` 采用工件序号化——报告中 `source_path` 不再是文件名，改为 `a<n>`（按扫描顺序——目标目录内符合后缀过滤的文件**字典序**——0 基编号；字典序确定性、与实现无关）。**不采用报告附录映射表**（附录会把文件名原文带回报告，与 D1' "任何携带面不得带出原值"冲突，否决）。理由：操作者对自己目录有本地知识，`a<n>` + 字典序规则足以本地复现；报告消费者不需要也不应获得文件名。这与 D1'.1 的 field_path 序号化构成同一位置模型（"序号 + 可本地复现规则，报告侧零原值"）。

- **stderr 警示行**：文件级警示（unparseable-json / undecodable-text / symlink-skipped / resource-limit）一律使用 `a<n>` 工件序号，不得输出文件名。stderr JSON 形态 `{"artifact": "a3", "error": "unparseable-json"}`。**[v1.2-replaced 原文]** §8.3.2 v1.1 的 `{"file": …, "error": …}` 形态废止。
- **异常路径**：脚本任何未捕获异常的 message 不得含文件名/路径/内容（异常处理统一捕获后转 `(a<n>, error-category)`）；`--output` 写失败与 target-dir 参数错误仅涉及调用方自己传入的路径，允许回显，维持现状 exit 2/1。
- **finding repr / JSON 全字段排查清单**（负例逐面锁定）：`AuditFinding` 四字段 + `AuditLocation` 三字段 + 报告 JSON 全部顶层键（artifact_count / findings / policy_digest / policy_version / recommended_action / status / incomplete_reasons / tenant_context）——repr 与序列化输出对 fixture 的明文键名、明文值、明文文件名**全部零命中**。
- **span**：保留（码点区间，无原值）。

### 17.D1'.3 库侧 source_path 工件标识契约（R4 + R6 收紧，Maintainer 指令 2026-09-13）

`audit.py` 全部公开函数（`audit_text`/`audit_structured`/`build_audit_report` 消费的 `source_path` 与 `AuditLocation.source_path`）执行**入口校验**：

- **[v1.3-replaced 原文，R6 废止]** "合法形态：`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`……选择通用安全字符集而非强制 `a\d+`：库不应假设调用方编号方案"——字符白名单任何变体（含"安全字符集 + 长度"）已由 Maintainer 证伪：`sample.json` 合法则 `sk_live_ABC123` 亦合法，字符白名单不能证明标识不含秘密。
- **R6 定稿（冻结）**：唯一合法形态 `^a(0|[1-9][0-9]{0,3})$`（`a` 后接 0 或 1–9999 的无前导零十进制，即 a0–a9999）。性质：(1) 与脚本工件序号同域，受 `max_files_per_scan = 10_000`（镜像 `PrivacyLimits.max_items`，实物 models.py:86）上界约束，合法值域恰封闭于 a0–a9999；(2) 字符集仅 `a`+数字——任何字母组合的秘密形态（`sk_live_*`）、任何真实文件名、任何调用方自由文本（含 `.`/`_`/`-`/`..`/路径分隔符/盘符/空白/非 ASCII）均非法，即"不可承载原值的位置标识形态"，非字符黑名单；(3) 库调用方（脚本）天然传 `a<n>`；测试直传任何非 `a<n>` 形态一律拒绝。
- 违规 → `PrivacyError(INVALID_FIELD_VALUE, field_path="source_path", context={"len": len(value), "reason": "artifact-id"})`——**context 不含原值**（errors.py 契约：context 仅非值元数据）。
- **[v1.3-replaced 原文，R6 废止]** "兼容：既有测试直传的 `sample.json`/`log_excerpt.txt` 等值合规"——v1.4 下这些值**非法**；既有点状值断言按 §18 行 #20 映射改写为非法负例或迁移 `a<n>`（非删除）。

### 17.D2' 租户边界 v2：`TenantAuditContext`（替代 §8.2.2/§8.2.4/§8.2.5 租户入口、§9 T4 部分）

**新类型（audit.py；DR-IP-0020-1 后置授权情形——本 DR 即授权扩入 `audit.py` 的 `__all__`；`lima/evidence_privacy/__init__.py` 的 13 项 `__all__` 仍不动，`TenantAuditContext` 经模块路径 `lima.evidence_privacy.audit` 消费）**：

```python
@dataclass(frozen=True, slots=True, repr=False)
class TenantAuditContext:
    tenant_id: str
    tenant_key: bytes

    def __repr__(self) -> str:
        return (
            f"TenantAuditContext(tenant_id_len={len(self.tenant_id)}, "
            f"tenant_key_len={len(self.tenant_key)})"
        )
```

**R1（Maintainer 指令，2026-09-13）tenant_key 防泄漏面（冻结）**：`repr=False` 关闭自动 repr；自定义 `__repr__` **仅含长度元数据**（tenant_id_len/tenant_key_len），不含 tenant_id 原文与 tenant_key 任何字节；未覆写 `__str__` 时 `str()` 回落 `__repr__`，str/repr 双面同锁。指纹化标识形态**不采用**（避免额外 HMAC 与新的可关联标识，与 D2' "不批准 2A"精神一致）。构造校验异常零 key（实物核对结论，断言锁定而非改实现）：`MISSING_TENANT_KEY` 无 context；`INVALID_FIELD_VALUE` context 仅 `{"value_kind": type(x).__name__}`；断言覆盖 `repr(ctx)`/`str(ctx)`、构造失败 `PrivacyError` 的 `str`/`repr`/`context` 序列化、`__cause__`/`__context__`/`traceback.format_exception` 全链，对 key 原文与其 hex 形态、tenant_id 原文零命中（§18 行 #17）。

构造校验（fail-closed，复用既有枚举）：`tenant_key` 非 bytes 或空 → `PrivacyError(MISSING_TENANT_KEY, field_path="tenant_key")`；`tenant_id` 空/非 str/UTF-8 超 128 字节 → `PrivacyError(INVALID_FIELD_VALUE, field_path="tenant_id")`（与 port.py 既有语义一致）。

**签名修订（冻结）**：
- `audit_text(source_path: str, text: str, policy: TenantPolicy, *, context: TenantAuditContext) -> tuple[AuditFinding, ...]`
- `audit_structured(source_path: str, value: object, policy: TenantPolicy, *, context: TenantAuditContext) -> tuple[AuditFinding, ...]`
- `build_audit_report(context: TenantAuditContext, findings: Mapping[str, tuple[AuditFinding, ...]], policy: TenantPolicy) -> AuditReport`
- 旧 keyword-only `tenant_id`/`tenant_key` 参数**移除**（上下文是唯一租户入口——签名级强制，防止绕过；旧 keyword 调用形态 → `TypeError`）。

**内部长标签（不输出；R5 公式冻结）**：`AuditFinding` 增字段 `_tenant_tag: str = field(repr=False)`，其中 `derived_key = HMAC-SHA256(tenant_key, b"lima.evidence_privacy.tenant-key.v1\x00" + tenant_id.encode("utf-8"))`（与 `fingerprint.py` 实物 `_TENANT_KEY_DOMAIN`/`_derive_tenant_key` 一致，推荐 import 复用，fingerprint.py 零修改），`_tenant_tag = HMAC-SHA256(derived_key, b"audit.tenant-tag.v1" + tenant_id.encode("utf-8")).hexdigest()`（64 hex = 32 字节；域分隔串与 fingerprint 域及 tenant-key 域均不同，互不可关联）。仅用于聚合一致性校验，**任何用途不得进入输出**。测试以同公式独立重算做跨实现一致性断言（不导出 tag 本身，§18 行 #21）。

**双重防漏出机制（冻结断言锁定）**：(1) `field(repr=False)`——`repr(AuditFinding)` 不含该字段；(2) 序列化白名单排除——`_finding_payload`（与脚本报告组装）为显式字段白名单，不含 `_tenant_tag`；测试断言 repr 与 JSON 序列化输出对该标签值零命中。

**聚合校验（含零 finding 批次）**：`build_audit_report` 校验**全部** findings 的 `_tenant_tag` 与 context 派生标签一致；`findings` 为空映射时仍执行 context 有效性绑定（构造即校验天然覆盖零 finding 批次；另以空映射调用负例锁定）。不一致 → `PrivacyError(POLICY_ERROR, field_path="report.tenant_mixing", context={"distinct_tenant_tags": <n>})`（n = 去重后标签数，非值元数据）。

**报告零租户信息**：`AuditReport` 与其 JSON 不含 tenant_id / tenant_key / tenant_tag / 任何租户可关联标识（§9 T4 断言修订为"无明文租户字段且无任何标签输出"）。

### 17.D3' 离线指纹 v2：per-run 随机密钥（替代 §8.3.8）

- 脚本每次运行生成 `tenant_key = secrets.token_bytes(32)`；`tenant_id = "offline-audit"`（固定标识，非密钥）。`compute_fingerprint` 本身不做密钥推导变更（`fingerprint.py` 零修改），随机性完全在脚本层注入；**不引入 HKDF**（直接 32 字节随机密钥即满足），不得引入环境/文件/网络取密。
- **同次运行一致性（断言锁定）**：同值出现 N 次 → N 个 fingerprint 全同（同次运行可去重）；报告 fingerprint 为小写 hex 字符串形态（与 `compute_fingerprint` 冻结输出形态一致，P&V 定稿：不额外锁定长度，避免与 `fingerprint.py` 冻结面冲突）。"脚本 ≡ 库"强比对废止（测试无法取脚本内 per-run 密钥；导出密钥 = 新携带面，不推荐，已在裁定 §⑤-2 呈报 Maintainer）。
- **跨运行不稳定断言（新增，对 c5b375e RED）**：同一 fixture 目录，两次子进程运行 → 报告 fingerprint 集合**不同**（当前 main 为固定密钥，两次运行指纹相同）。
- **报告 `tenant_context` 值定稿**：`"offline-audit/random-per-run"`。
- **文档声明（规范文案）**："离线指纹仅在单次脚本运行内可用于去重与一致性核对；跨运行不可比（每次运行使用独立随机密钥）；不提供保密性、防猜测或防篡改语义；与在线租户指纹域不可关联。跨运行比对需求须另立 DR 提出受保护密钥方案与场景。"
- 旧常量 `OFFLINE_TENANT_KEY`（`b"lima-offline-audit.v1"`）**删除**；红线 4：任何公开常量密钥不得回流为指纹密钥（测试以源码卫生 grep 锁定）。

**[v1.2-replaced 原文]** §8.3.8 v1.1 全条（固定离线租户常量方案）废止；`tenant_context` 值由 `"offline-audit"` 改为 `"offline-audit/random-per-run"`。

### 17.F4' vault 错误卫生（替代 §8.1.3 context 形态、§8.1.5 部分）

`_rejection` 与 Rule 4 的 context：`"backend": config.backend` → `{"backend_len": len(config.backend) if config.backend is not None else None, "backend_registered": config.backend in VAULT_BACKEND_PORT_NAMES if config.backend is not None else False}`。断言升级（对 c5b375e RED）：`PrivacyError` 的 `str()`/`repr()` 不含 `FAKE_BACKEND`（或任意合成 backend 原文）串；context 含 `backend_len`/`backend_registered` 键。

### 17.F5' 审计预算 v2（§8.2/§8.3 新增条款；不批准"超限静默跳过"）

**预算依据 = `PrivacyLimits` 既有默认（实物核对 @ models.py）**：`max_depth=32`、`max_payload_bytes=1_048_576`（1 MiB）、`max_string_bytes=262_144`、`max_items=10_000`、`max_processing_ms=1_000`（时间维度本轮不纳入，见裁定 §⑤-5）。

**库层（audit.py）——typed 拒绝，复用既有枚举**：
- 深度：遍历深度 > 32（`PrivacyLimits().max_depth`）→ `PrivacyError(MAX_DEPTH_EXCEEDED, field_path=<序号路径>, context={"depth": d, "max_depth": 32})`；预算前置消除裸 `RecursionError`（断言：深嵌套输入 → typed error，非 RecursionError；对 c5b375e RED——现裸 RecursionError）。
- 结果数：单次 `audit_text`/`audit_structured` findings 总数 > 10_000（`max_items`）→ `PrivacyError(RESOURCE_LIMIT_EXCEEDED, field_path="findings", context={"max_items": 10000})`。

**脚本层——可识别跳过，禁止静默**：
- **[v1.3-replaced 原文，R7 统一废止]** "`with open(path, \"rb\") as f: data = f.read(...)`"的分立读取表述与 §17.B2'-R3 的"以同一 fd 做 R2.1 句柄限量读取"分立表述统一替代为 **§17.F5'-R2.1' 四步序列**（见下）：
- **§17.F5'-R2.1'（R7 定稿，唯一规范步骤，禁任何二次打开）**：(1) `fd = os.open(path, os.O_RDONLY | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0))`；(2) `st_fd = os.fstat(fd)` 与遍历时 `entry.stat(follow_symlinks=False)` 比较 `(st_dev, st_ino)`，不一致或 `st_ino == 0` → 关闭 fd → `symlink-risk` fail-closed 跳过（语义继承 §17.B2'-R3）；(3) **同一 fd** 经 `os.fdopen(fd, "rb")`（fdopen 接管所有权，不得再 `os.close`）执行 `read(PrivacyLimits().max_payload_bytes + 1)`，超限 → resource-limit 跳过（单文件语义不变）；(4) with 块结束即关闭（fdopen 析构路径唯一）。**禁止项（源码卫生锁定）**：`open(path, "rb")`、验证后重开、`path.read_bytes()`、`st_size` 预检；grep 断言——读取相关 `open(` 仅允许 `os.open(`/`os.fdopen(` 形态；行为测试锁定——monkeypatch 包装 `builtins.open`/`os.open` 计数，每文件至多一次 `os.open`、零 `builtins.open`（含 symlink-risk 与超限跳过路径），§18 行 #22。以句柄实际读取字节数判长（`len(data) > max_payload_bytes` → 该文件可识别跳过：stderr `{"artifact": "a<n>", "error": "resource-limit"}`；`incomplete_reasons` 增 `"a<n>:resource-limit"`）。**禁止** `path.read_bytes()` 全量读后判长（main 现状 scripts/audit_sensitive_artifacts.py:67 即此形态，RED 点）；禁止以 `stat().st_size` 预检替代（stat 可被竞态替换，FIFO/proc 类 st_size 无意义）。上限取值经 `PrivacyLimits()` 实例（= 1_048_576，实物 @ models.py），不硬编码字面量。
- **目录级预算（R2 定稿，仅脚本层，不入 `PrivacyLimits`/库签名）**：`max_files_per_scan = 10_000`（镜像 `max_items` 基数上界）；`max_total_bytes_per_scan = 104_857_600`（= max_payload_bytes × 100，聚合上界 100 MiB）。**[v1.3-replaced 原文，R8 废止]** "任一预算触顶后后续文件逐个按 resource-limit 可识别跳过（同型 stderr + `a<n>:resource-limit`；聚合面另记一条目录级原因）"——逐项语义废止（极大目录下扫描时间与报告大小无界）。**§17.F5'-R2.2'（R8 定稿）触顶即停 + 有界输出**：文件预算——扫描枚举达到 10,000 后**立即停止枚举与逐项处理**，`incomplete_reasons` 追加**恰好一条** `"scan:file-budget:truncated-at=a{n}"`（n = 截断时最后已分配工件序号，≤ a9999，定长有界）；字节预算同理——累计读取字节超 104,857,600 后停止处理后续文件，追加恰好一条 `"scan:byte-budget:truncated-at=a{n}"`（计数口径继承 v1.3：被跳过文件按 LIMIT+1 计入）；stderr 截断时输出**单行**汇总警示（同上字符串格式），非逐文件；`status:"incomplete"` + exit 3 不变；报告规模因此有界（findings ≤ 已处理文件产出，reasons ≤ 事件常数）；不得 exit 1/2、不得静默；单文件超限 resource-limit 语义（R2.1' 第 3 步）不变。断言见 §18 行 #18/#23。
- **报告顶层 `status` 字段（新增，必含）**：`"complete"` | `"incomplete"`。任何跳过/拒读发生 → `"incomplete"` 且 `incomplete_reasons` 非空（含 unparseable-json / undecodable-text / symlink-skipped / resource-limit 各类）。禁止：存在未完成项时 `status:"complete"` 或呈现"零发现即完成"。
- **exit code 定稿**：`0` = 完成且完整；`1` = 报告写失败（维持）；`2` = 参数/IO 参数错误（维持）；`3` = 完成但有未完成项（status=incomplete 的正常退出路径，非错误退出——报告已成功产出且可读，消费者必须检查 `status`/`incomplete_reasons`）。
- 总量/字符串预算（max_string_bytes 等）由库层既有限制路径覆盖，本轮不新增脚本层复制检查（如扫描中遇 `MAX_STRING_LENGTH_EXCEEDED` 类 typed error，按文件级可识别跳过处理，同类目 `resource-limit`）。

### 17.B2' 链接边界（§8.3 修订）

- **遍历**：`os.scandir(target)`；`entry.is_symlink()` → 跳过 + stderr `{"artifact": "a<n>", "error": "symlink-skipped"}`（symlink 亦占工件序号，保证序号稳定）+ `incomplete_reasons` 记录。不跟随目录内 symlink（无论指向文件或目录）。
- **读取**：POSIX 用 `os.open(path, os.O_RDONLY | os.O_NOFOLLOW)` 后 `os.read` 防 TOCTOU（O_NOFOLLOW 只挡最终组件 symlink）。
- **[v1.2-replaced 原文，R3 废止]** "Windows 回退：先 `entry.is_symlink()` 检查再 open；注明残余 TOCTOU 窗口，以 Linux CI 负例为权威"——该条款废止。**R3 定稿（机制 A，两平台同构）**：`flags = os.O_RDONLY | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0)`；`fd = os.open(path, flags)`（POSIX O_NOFOLLOW 先行拦截最终组件 symlink）；`fst = os.fstat(fd)` 与遍历时取得的 `est = entry.stat(follow_symlinks=False)` 比对 `(st_dev, st_ino)`：一致且 `est.st_ino != 0` → 按 **§17.F5'-R2.1' 四步序列**以同一 fd 经 `os.fdopen` 限量读取（**[v1.3-replaced]** 原"以同一 fd 做 R2.1 句柄限量读取"分立表述统一并入 R2.1'，禁任何二次打开）；否则 **fail closed**——关闭 fd、跳过、stderr `{"artifact": "a<n>", "error": "symlink-risk"}`、`incomplete_reasons` 增 `"a<n>:symlink-risk"`、`status:"incomplete"`（该文件零内容进入任何输出）；"验证不可行"（Windows `st_ino == 0`）与"验证失败"同权，均不读取、不宣称完成。`symlink-risk` 为新增 stderr/`incomplete_reasons` 字符串类目（不动 `PrivacyErrorCode` 12 值冻结）。Windows `st_ino` 可用性为实现期验证项：Implementation 须 Windows 实测典型 NTFS 路径 `st_ino != 0`；若普遍为 0 致全量 fail-closed，须提交 DR 附证据，不得私自放宽。总断言：任何 `symlink-risk`/`symlink-skipped`/`resource-limit`/`unparseable-json`/`undecodable-text` 出现 ⇒ `status != "complete"` 且 exit == 3（§18 行 #19）。
- **目录本身为 symlink**（target_dir 或中间目录解析后为链接）→ 拒绝：stderr `error: target-dir must not be a symlink path` + exit 2（参数错误，允许回显调用方传入路径）。
- **Linux 负例（CI 实跑，权威）**：目录内 symlink 指向目录外文件 → 断言：外部文件未被读取（内容零出现在任何输出）、symlink-skipped 警示存在、status=incomplete。
- 源码卫生断言（全平台）：脚本含 `is_symlink`/`scandir`/`O_NOFOLLOW`（POSIX 分支）使用；无 `shutil`/`os.remove`/`unlink`/`rename`（既有 T3 断言保留）。

### 17.G3' 空租户密钥 fail-closed（classify 面，G3 阻断项）

- **现状（裁定亲验）**：`sanitize_for_sink` 路径已有 `MISSING_TENANT_KEY`（port.py/vault_port.py）；缺口在 `classify_payload` 公开面——keyword-only `tenant_id: str = ""` / `tenant_key: bytes = b""` 缺省走无租户确定性模式。
- **修复规格（冻结）**：`classify_payload` 缺省或传入空租户（`tenant_id == ""` 或 `tenant_key == b""` 或类型非法）→ 抛 `PrivacyError(MISSING_TENANT_KEY, field_path="classify.tenant")`。显式传入有效租户（非空 str + 非空 bytes）方可分类。
- **兼容影响（裁定亲验核对）**：调用面 `port.py:199` 经 `sanitize_for_sink` 调用且租户已前置校验非空——不受影响；`lima/conformance` 无 `classify_payload` 直接调用；audit/script 本轮已强制 `TenantAuditContext`——不受影响。受影响冻结断言：`tests/evidence_privacy/test_classifier.py` 的无租户调用（helper `_manifest` :24 传导 :32/:37/:44/:53/:60/:66-68/:100；:80-82、:91-93 直接调用）→ 逐条映射为"期望 `MISSING_TENANT_KEY`"或补显式有效租户（断言修订非删除，见 §18 表 #12）。
- **迁移说明**：`classify_payload` 不再支持无租户确定性模式；需要分类的调用方必须提供有效租户上下文。

### 17.F6' Ruff 清零

现有发现为测试文件格式类，非断言语义；随 Frozen Test Commit v3 测试修订一并 `ruff format`/`ruff check --fix`，断言语义不变（§18 表标注"格式修订，无语义变化"）。

## 18. v1.2 断言映射总表（修订非删除；逐文件 grep 补全版，基线 c5b375e）

> 红线 1：所有旧断言修订逐条"旧 → 新"映射并注明安全意图继承；无对应新断言的旧断言不移除。行号 @ c5b375e。

| # | 旧断言（文件::用例 @ c5b375e） | 新断言（Frozen v3） | 修订理由 / 意图继承 | DR 锚 |
|---|---|---|---|---|
| 1 | `test_readonly_audit.py::test_audit_structured_deep_field_paths`（:174-184，明文键名出现于 field_path，`"deep" in p`） | 成员序号路径断言（段形态 `m<n>`/`[n]` regex 锁定；deep/whole-value 行为保留：深层路径存在、整值 span (0, len) 存在）+ 明文键名零出现 | 位置定位意图由序号路径继承，原值携带面消除 | D1' |
| 2 | 同文件 value-free/repr/JSON 组（:200-231 三例，仅值清单） | 扩 fixture（键名=敏感值样本 `secret_keyname.json`、文件名=敏感值样本）后 repr/JSON/报告全键/**stderr** 对明文键名、值、文件名零命中（携带面清单见 17.D1'.2） | T2 意图由"字段白名单"升级为"全携带面零原值" | D1'.2 |
| 3 | 同文件 `test_report_field_set_whitelist`（:222-231，AuditReport 五字段） | 字段集修订为含 `status`/`incomplete_reasons`；`AuditFinding` 字段集含 `_tenant_tag`（repr/序列化零出现，表 #4） | 报告字段演进；"零租户信息输出"意图继承 | D2'/F5' |
| 4 | §9 T4 租户隔离组（:237-263，`tenant_id=`/`tenant_key=` keyword 调用） | 全部迁移 `TenantAuditContext` 形态；新增：混合租户 → `POLICY_ERROR(field_path="report.tenant_mixing")` 负例；零 finding 批次（空映射）context 绑定负例；`_tenant_tag` repr=False + JSON 零出现断言；旧 keyword 调用 → `TypeError` 断言 | 隔离意图由"无字段"升级为"聚合入口结构性拒绝" | D2' |
| 5 | 同文件 :317/:344（`tenant_context == "offline-audit"`） | 期望值改 `"offline-audit/random-per-run"` | 报告自标注随机域，防跨运行误比对 | D3' |
| 6 | 同文件 `test_script_offline_fingerprint_consistency`（:431-473，固定密钥脚本≡库强比对） | 改为：同次运行内同值去重一致（同值 N 次 → fingerprint 全同）+ hex 形态断言；**新增跨运行不稳定**（两次子进程 → 指纹集不同，对 c5b375e RED）；"≢其他租户"子句随固定密钥废止 | 去重用途保留，跨运行可比性显式去除（17.D3'） | D3' |
| 7 | `test_vault_port_disabled.py` validate 分支 3-9（:63-113）与 acquire fake-backend（:130-139）——context 含 `backend` 原文未断言 | 改/增断言：context 含 `backend_len`/`backend_registered` 键；`str()`/`repr()` 不含 `FAKE_BACKEND`（强度升级） | 错误卫生意图继承并升级 | F4' |
| 8 | 两文件源码卫生 grep 组（:289-302、:413-429） | 扩：脚本含 `is_symlink`/`scandir`/`O_NOFOLLOW`（POSIX 分支）；**无固定密钥常量回流**（`lima-offline-audit.v1` 零出现）；深嵌套 typed error 行为断言（表 #14）锁定无裸 RecursionError 泄漏路径 | 链接边界/密钥卫生/预算 | B2'/D3'/F5' |
| 9 | 脚本只读组（hash/mtime，:324-330） | 保留原断言；并入 B2' Linux 负例（symlink 拒读、外部目标零读取——Windows 条件执行标注）与 resource-limit 可识别跳过负例 | 只读意图继承 | B2'/F5' |
| 10 | （新增）旧 main 报告无 `status` 字段 | 报告必含 `status`；有跳过（broken.json 存在）→ `"incomplete"` + `incomplete_reasons` 非空 + exit 3；纯净目录 → `"complete"` + exit 0 | 禁静默跳过 | F5' |
| 11 | 同文件全部 `audit_text`/`audit_structured`/`build_audit_report` 旧签名调用（grep :141/:159/:177/:191/:202/:214/:240/:255/:274/:417/:443-473 共 13 处） | 全部改 `context=TenantAuditContext(...)` 调用形态；新增"旧 keyword 形态 → TypeError"断言 | 签名级强制（唯一租户入口） | D2' |
| 12 | `test_classifier.py` 无租户 classify 调用（:23-24 helper 传导 :32/:37/:44/:53/:60/:66-68/:100；:80-82、:91-93 直接调用） | helper 增有效租户参数（既有分类行为断言全保留）；:80/:91 两处直接调用逐条映射为期望 `MISSING_TENANT_KEY(field_path="classify.tenant")` 负例；新增空 key/非法类型变体 | 断言修订非删除；fail-closed 意图（G3 阻断项） | G3' |
| 13 | 同文件 `test_script_skips_broken_json_with_warning`（:397-411，断言 `"broken.json" in stderr`） | stderr 改 `{"artifact": "a<n>", "error": "unparseable-json"}` 断言 + **文件名零出现**（含 broken.json 与敏感值文件名）+ exit 3 + status incomplete | stderr 携带面零原值 | D1'.2/F5' |
| 14 | （新增）深嵌套输入无既有断言（现裸 `RecursionError`） | 深度 40 嵌套 → `MAX_DEPTH_EXCEEDED` typed error（context 含 depth/max_depth），非 RecursionError | 预算前置，typed 拒绝 | F5' |
| 15 | `--output` 内拒绝组（:347-395 保留）与 §8.3.3 v1.1 "有无 finding 均为 0" | 保留；exit 语义按 17.F5' 四值扩展（0/1/2/3），目录 symlink → exit 2 负例新增 | 参数错误路径维持，未完成项新增可识别退出 | F5'/B2' |
| 16 | Ruff 格式问题所在断言（三测试文件格式类） | `ruff format`/`ruff check --fix` 后语义不变 | 格式修订，无语义变化 | F6' |
| 17 | （无——`TenantAuditContext` 为 v1.2 新类型，main 不存在） | 新增负例组：repr/str(ctx) 与构造失败 `PrivacyError` 的 str/repr/context 序列化/异常链全文（含 `__cause__`/`__context__`/`traceback.format_exception`）对 tenant_key 原文与 hex 零命中、tenant_id 原文零命中；`repr=False` + 长度元数据 repr 形态锁定（§17.D2'-R1） | R1（对 c5b375e 无 RED 意义——类型不存在，属新面新锁） | R1 |
| 18 | 脚本 `read_bytes()` 全量读（scripts/audit_sensitive_artifacts.py:67，无对应断言） | 新增：1 MiB+1B → resource-limit 跳过（句柄读取形态，源码 grep 无 `read_bytes()`，对 c5b375e RED）；恰 1 MiB 正常读（边界含）；10_001 文件目录 → 第 10_001 起 resource-limit + `scan:file-budget` + incomplete + exit 3；合计 >100 MiB → `scan:byte-budget` 同型；预算触顶后报告仍成功产出（§17.F5'-R2） | R2；预算意图（F5'）由单文件扩至目录级，禁静默继承 | R2 |
| 19 | §17.B2' v1.2 草案"Windows 注明残余 TOCTOU"表述（main 无对应实现断言） | 改/新增：`os.open`+`os.fstat`+`(st_dev,st_ino)` 比对机制（源码 grep `os.fstat`/`st_ino`）；注入 stat 不一致 → 跳过 + `symlink-risk` + incomplete + 内容零泄漏；`st_ino==0` → fail closed；总断言：任何 symlink-risk/skipped/resource-limit/unparseable/undecodable 出现 ⇒ status != complete 且 exit==3；Windows 实测 st_ino 可用性为实现期验证项（§17.B2'-R3） | R3；B2' 链接边界意图继承，"注明竞态仍宣称完成"被 fail-closed 替代 | R3 |
| 20 | （无——source_path 入口校验不存在；v1.3 行内容被 R6 收紧） | 修订（R6）：合法形态仅 `^a(0|[1-9][0-9]{0,3})$`（正例 `a0`/`a123`/`a9999`）；`sk_live_xxx`、`sample.json`、`artifact.main-2`、路径/盘符/`..`/超长/空串/非 ASCII → `INVALID_FIELD_VALUE(field_path="source_path")` 且 str(exc) 不含原值；v1.3 "artifact.main-2/sample.json 合法" 类断言按映射改写为非法负例或迁移 `a<n>`（非删除）（§17.D1'.3） | R4+R6；D1'.2 原值携带面意图由字符白名单收紧为"不可承载原值的标识形态" | R4/R6 |
| 22 | v1.3 #18/#19 R2 `open(path,"rb")` 与 R3 `os.open` 分立描述冲突 | 新增：同句柄锁定——grep 读取相关 `open(` 仅 `os.open(`/`os.fdopen(` 形态、无 `read_bytes`/`st_size` 预检；行为——wrap `builtins.open`/`os.open` 计数，每文件至多 1 次 `os.open`、0 次 `builtins.open`（含 symlink-risk 与超限跳过路径）（§17.F5'-R2.1'） | R7；竞态防护意图由分立条款统一为单一序列 | R7 |
| 23 | v1.3 #18 预算触顶后逐文件 resource-limit 警示 | 新增：有界输出——10,005 文件 tempdir → exit 3、status incomplete、`incomplete_reasons` 恰 1 条 `scan:file-budget:truncated-at=a<n>`、无逐项 a10000+ 条目、stderr 单行汇总（字节预算同型恰 1 条）；输出规模上界为代理断言（reasons/stderr 行数 + findings 数）（§17.F5'-R2.2'） | R8；F5' 禁静默意图继承，输出规模有界化 | R8 |
| 21 | §17.D2' v1.2 草案 `derived_key` 用而未定义；Packet 引用 `.pv_tmp` 正本 | 新增：derived_key = HMAC-SHA256(tenant_key, b"lima.evidence_privacy.tenant-key.v1\x00" + tenant_id.utf8)（与 fingerprint.py 实物一致）；tag 公式独立重算一致性；Packet 文档卫生 grep（`.pv_tmp` 仅"过程性证据"语境）（§17.D2'-R5） | R5；D2' 标签语义补全 + 权威锚点入库 | R5 |

**fixture 增量（Frozen v3，`tests/evidence_privacy/fixtures/audit_samples/`）**：新增 `secret_keyname.json`（键名 = 已知敏感原值 #3、值 = 原值 #2，头部 `_known_values_header` 自校验）与文件名 = 敏感原值 #1 的 JSON 样本（内容仅 clean 值 + 头部清单）；深嵌套（深度 40）与超大文件（1 MiB + 1 字节，tempdir 内生成、不落盘 fixture）为测试内构造。既有 `sample.json`/`log_excerpt.txt`/`broken.json`/`clean_note.txt` 零修改。

**授权与红线（随 v1.2 生效）**：本轮修订属 DR-IP-0020-4R 授权（"断言修订非删除"显式放宽 v1.0/v1.1"既有测试只读"边界——仅限上述三测试文件与 fixture 扩展）；红线 1-5（映射、负例先行对 c5b375e RED、禁静默跳过、禁固定密钥回流、8 文件/`__all__`/12 枚举不动）绝对遵守。
