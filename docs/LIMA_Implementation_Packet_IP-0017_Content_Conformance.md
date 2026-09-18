# LIMA Implementation Packet IP-0017：Content Conformance（Feature Slice S2：多内容形态适配 + 五 sink conformance 全量 + 资源上限矩阵全量 + D-1 循环引用 typed error + 裸 Base64 细化）

- Packet 版本：1.0（2026-09-12，P&V 起草，状态 DESIGN-FROZEN / PENDING-MERGE）
- 制作：LIMA Packet & Verification Agent（运行模型：无法核验——本环境未提供可验证的运行元数据）
- 依据：Coordinator 裁定 COORD-IP94-S2-ENTRY_RULING_2026-09-12（`.pv_tmp/COORD-IP94-S2-ENTRY_RULING_2026-09-12.md`，Assignment 正本 = 其 §D，Assignment 编号 `IP-0017-PKT-P1/v1`）

## 1. 需求映射（Header）

| 字段 | 值 |
|---|---|
| Source Issue | agent-sec-labs/LIMA #94 `[V5-N05][P0] 敏感 Evidence 脱敏、分级、保留与导出治理`（远程正文亲验 2026-09-12，updated_at **2026-09-12T16:40:33Z**，已含 Delivery Ledger；IP registry 已登记 IP-0017 = PACKET-DRAFTING） |
| spec revision | Issue 正文 2026-09-12T16:40:33Z 版 + kickoff checklist `docs/LIMA_Issue_94_Coding_Agent_Kickoff_Checklist.md`（§2 第三层、§3 边界与验收） |
| Covered requirements | **FR-N05-02 conformance 侧**（统一 redaction port 五 sink 场景全量 conformance）；**FR-N05-05 全量**（多内容形态适配：嵌套 JSON 深度遍历全量、text/日志行/diff/Prompt 段/异常栈形态适配、二进制扫描 conformance）；**NFR-N05-02 全量**（嵌套/循环/超深/超大/超条目/超时上限矩阵全 fail-closed，含 D-1 循环引用 typed error）；**AC/T-N05-01 全量**（五 sink conformance，语义按裁定 O-3：同一接口在五种 SinkContext 下输出一致安全 + 场景内容形态适配，无 per-sink 差异行为）；**AC/T-N05-03 全量**（短值/Unicode/二进制/Base64/URL credential/私钥全场景，含 DR-IP-0015-02 裸 Base64 默认级别细化）；**AC/T-N05-05 全量**（API/export fixture 无泄漏验证） |
| Not covered | FR-N05-04 vault adapter（port 定义与默认 disabled 合同测试均归 #94-S3）；FR-N05-06 历史只读审计与迁移计划（#94-S3）；NFR-N05-04 审计侧（历史 classification 不被静默重写的只读审计面，#94-S3；本 IP 仅继续携带 policy digest）；AC/T-N05-06（#94-S3）；`scripts/audit_sensitive_artifacts.py`（尚不存在，不得创建）；一切生产接线（#66/#68/#70）；UI fixture；安全 Reviewer sign-off（G3） |
| Delivery role | Feature Slice S2（Content Conformance suite） |
| Issue closure impact | **PARTIAL**（S2 完成 → G2 可评估；G3/G4 仍 OPEN，#94 保持 open，Closure policy MANUAL-AFTER-POST-MERGE-AUDIT） |
| Upstream | IP-0015（Evidence Privacy Core）merge `e895079a1b43980bc35532bfd46c5cdbd8d3cae2`（PR #155）；#58 契约经其传递（终态 `7734e585ec0b3a10873f58c917fd134c12e6e8a1`）；统一开工基线 origin/main = **`fd219724076380448163d818f9ca26a3d5a5d945`**（IP-0016 merge，PR #167；亲验 `git rev-parse origin/main`） |

本 IP 的贡献声明仅限上表 covered 列；conformance suite 全绿不等于 #94 关闭（G3/G4 属 #94-S3 与 Closure Audit）。本 Packet 不宣称任何上层端到端 AC（如生产 sink 实际拦截）已满足。

## 2. Design Input Manifest

| # | 输入 | 锚点（blob SHA，P&V 亲验 `git ls-tree`，2026-09-12） | 消费方式 |
|---|---|---|---|
| DI-001 | `lima/evidence_privacy/__init__.py` | `ef21f161f0c63b99a8a1cd6060a5efc3b3758654` @ e895079（main fd21972 等值） | 只读复用：13 冻结符号与 `__all__` 恰好集合 |
| DI-002 | `lima/evidence_privacy/classifier.py` | `faba01136239baa5e59a4c4b0b51cd319bf9375c` @ e895079 | 修改对象（Add-only 规则见 §7）；`_collect_entries`/`_redact_node` 为适配挂载点 |
| DI-003 | `lima/evidence_privacy/errors.py` | `e8f9f7bdad2cd048a3d317097476bba5f06f5fa9` @ e895079 | 只读消费：12 枚举值冻结；Add-only 增量须经 DR 条款（§9.1） |
| DI-004 | `lima/evidence_privacy/fingerprint.py` | `d090ff6ba83b0210a18ed4d033614af4bec83798` @ e895079 | 只读复用：`compute_fingerprint` 供 base64/段落级指纹调用；域分隔常量不动 |
| DI-005 | `lima/evidence_privacy/models.py` | `32e4cd53314f78396710b9a4498c4283f4f7d91c` @ e895079 | 只读消费：`PAYLOAD_KINDS`/`SinkContext`/`SanitizedPayload` 形态约束适配层必须遵守 |
| DI-006 | `lima/evidence_privacy/policy.py` | `4012d933e640c8d857e8480f5865fa89c559e686` @ e895079 | 只读消费：`SINK_KINDS` 五值、`policy_digest`（经模块路径消费，O-1） |
| DI-007 | `lima/evidence_privacy/port.py` | `e9f57bec78bcbf42ae3dba16bdb4e755f30793b0` @ e895079 | 修改对象（Add-only 规则见 §7）：D-1 修复落点（`_prescan`，L69-142） |
| DI-008 | `tests/evidence_privacy/` 9 文件 @ e895079（`__init__.py`=e69de29…5391、`test_classifier.py`=8cee219…0517、`test_error_hygiene.py`=3a9be6d…85e2、`test_fingerprint.py`=dfda7f1…ab e4（完整 `dfda7f1f7301ca7d353a8811288222b5c7aabbe4`）、`test_limits.py`=1d7f570…0a1、`test_models.py`=c94c0f5…8ed4、`test_policy.py`=08908d9…b10a、`test_port_sanitize.py`=945d2df…d41f、`test_value_kinds.py`=7b36029…1a89；main fd21972 全部等值） | 只读参照：text 全值记录行为、text 关键词 SENSITIVE、URL credential/PEM RESTRICTED 等既有断言锁定面 | 冻结测试，不得修改（§10） |
| DI-009 | `lima/contracts/common.py`=3a5efd09…a346、`codec.py`=a442076d…70b8、`errors.py`=87e8061…2ce1（@ fd21972） | 只读复用：分类枚举、canonical codec、typed error 原则 |
| DI-010 | Issue #94 远程正文（updated 2026-09-12T16:40:33Z，含 Delivery Ledger 与 IP-0017 登记） | GitHub API 只读亲验（2026-09-12） | 需求唯一来源（FR/NFR/AC/T 稳定 ID） |
| DI-011 | Coordinator 裁定 COORD-IP94-S2-ENTRY_RULING_2026-09-12（§A consumer review / §B 切分 / §C 编号 / §D Assignment / §E 风险） | `.pv_tmp/COORD-IP94-S2-ENTRY_RULING_2026-09-12.md`（本地基线外控制面） | 派发权威 |
| DI-012 | IP-0015 Packet v1.1（含 DR-IP-0015-04 勘误记录与附录 A/B 矩阵） | `docs/LIMA_Implementation_Packet_IP-0015_Evidence_Privacy_Core.md`（main 树内） | 上游契约与矩阵归属参照（记录性引用，不修改） |
| DI-013 | DR-IP-0015-01（SinkContext 挂载）、DR-IP-0015-02（裸 Base64 不锁定、细化归 S2）裁定文本 | `.pv_tmp/COORD-IP0015-TESTS_FROZEN_REVIEW_2026-09-12.md` §2（本地基线外控制面） | 解释性决定继承 |
| DI-014 | DR-IP-0016-01/02 记录（PI-DR2 scratch GREEN / PI-DR6 平台中立沉淀） | `.pv_tmp/DR-IP-0016-01_RECORD.md`、`DR-IP-0016-02_RECORD.md` | PI-DR 沉淀参照 |
| DI-015 | kickoff checklist | `docs/LIMA_Issue_94_Coding_Agent_Kickoff_Checklist.md` @ fd21972（blob `42957cfa8e2269a7205cc40680a043e242fcca7d`） | §2 第三层 / §3 边界与验收 |
| DI-016 | 生命周期 §8/§9/§9.1/§12、开发与交接标准、P&V 责任书、CONTRIBUTING.md | origin/main docs/ 树内 | 流程权威 |
| DI-017 | 基线绿性亲测（本 worktree @ fd21972，2026-09-12 亲跑）：`python -m pytest tests/contracts -q` → **617 passed**；`python -m pytest tests/evidence_privacy -q` → **78 passed**；`python -m unittest discover -s tests/evidence_privacy -t .` → **OK** | 本 worktree 实跑 | RED/GREEN 对照基线 |
| DI-018 | D-1 缺陷探针（本 worktree @ fd21972，2026-09-12 亲跑）：自引用 dict + `PrivacyLimits(max_depth=100000)` → **裸 RecursionError 从 `sanitize_for_sink` 逃逸**（`_prescan` 在 §8.2 try 块之外）；默认 limits 下自引用 dict → MAX_DEPTH_EXCEEDED（正确）；非循环 3000 层嵌套 + max_depth=100000 → 裸 RecursionError；自引用 list → 裸 RecursionError | 本 worktree 探针脚本实跑 | D-1 修复契约（§8.3）的 RED 依据 |

### Explicitly Rejected Inputs

- IP-0015 Packet/交接书/勘误的历史文本作为可变规格（记录性引用为主；其"IP-0016/IP-0017"字样按 DR-IP-0015-04 统一解释为 #94-S2/#94-S3，本 IP 即 #94-S2 的全局编号落位）。
- 任何要求 per-sink 差异行为的设计（O-3：五 sink 在 port 层除 allowlist 外无差异化语义；AC/T-N05-01 的正确读法是"同一接口 × 五种 SinkContext 输出一致安全"，当前证据不支持 per-sink 读法）。
- 任何修改 13 冻结符号签名、既有 12 枚举值、错误 str/repr 语义的方案（裁定 §D Stop Condition 1）。
- Issue #66/#68/#70 正文及派生设计（生产接线）；#60 轨道全部文档。
- 第三方脱敏/扫描库（禁止新依赖；实现仅标准库 + `lima.contracts.*` + 本包）。
- 任何 raw-secret 例外通道、feature-flag 回滚保存原文、审计降级为 Audit-only 的设想。
- 改动 `tests/evidence_privacy/` 既有 9 文件以"腾出"新断言空间的方案（冻结测试只读；新断言一律进新套件文件）。

## 3. Iteration Hypothesis 与 Measurement

- Hypothesis：在 IP-0015 冻结公共面（13 符号 + 12 错误码 + 五 sink）之上，仅通过（a）新增 `content_scan.py` 适配模块、（b）对既有 7 文件的 Add-only 修改（D-1 循环/栈安全护栏、裸 Base64 判定、text 段落级扫描挂载），即可交付"同一接口 × 全量内容形态 × 全量资源矩阵 × 五场景 fixture"的 conformance 能力，且不改动任何既有冻结断言。
- Measurement：新增 conformance 套件全绿（双 runner：pytest + unittest discover）；既有 `tests/evidence_privacy` 78 用例与 `tests/contracts` 617 用例零回退；全部负例（循环/超深/超大/超条目/超时/未知 sink）以 stable `PrivacyError` 拒绝且错误对象及其 canonical 序列化不含原值子串；五 sink 同输入输出仅 `sink_kind` 字段差异；API/export fixture 递归无泄漏。

## 4. Goal

1. 修复 D-1：循环引用（含间接环、dict/list 混合环）在任何合法 `PrivacyLimits` 配置下以 stable `PrivacyError` 拒绝；`sanitize_for_sink` 任何代码路径不得让裸 `RecursionError` 逃逸（§8.3 精确契约）。
2. 交付 DR-IP-0015-02 裸 Base64 默认级别细化：可解码裸 Base64（≥32 字符）默认判 SENSITIVE 并指纹化，含上下文规则（§8.4）。
3. 交付多内容形态适配（FR-N05-05）：嵌套 JSON 深度遍历全量矩阵、text 段落级扫描（日志行/diff/Prompt 段/异常栈同一谓词族）、二进制扫描 conformance（§8.5）。
4. 交付五 sink conformance 套件与 API/export fixture 无泄漏验证（AC/T-N05-01/05；§8.6）。
5. 交付全量资源上限矩阵 conformance（NFR-N05-02：深/大/条目/超时/循环；O-2 超时可触达设计；§8.3/§8.7）。

## 5. Non-goals

- 不做 vault port（含其默认 disabled 合同测试，归 #94-S3）；不做历史只读审计/迁移计划；不做生产接线（#66/#68/#70）；不做 UI fixture；不做安全 Review sign-off。
- 不改 13 冻结符号签名、既有 12 枚举值、错误语义、`SINK_KINDS`、`PrivacyLimits` 五字段默认值、指纹域分隔常量、`policy_digest` 字段序。
- 不引入新依赖；不做任何 IO/网络/环境变量/子进程。
- 不修改 `tests/evidence_privacy/` 既有 9 文件与 `tests/contracts/**`。

## 6. 工作树与分支前置条件

- 统一开工基线：origin/main = `fd219724076380448163d818f9ca26a3d5a5d945`（Packet 合并前须复核未前移；若前移且 `lima/evidence_privacy/**`、`lima/contracts/**`、`tests/contracts/**`、开工清单任一 blob 变化 → 停止上报）。
- 分支拓扑按 lifecycle §9.1：`codex/ip-0017-integration`（P&V 冻结测试）→ Frozen Test Commit → `codex/ip-0017-implementation`（Implementation）。
- 开工命令（Implementation，在 Packet 合并后的新 worktree）：
  ```bash
  cd <交付 worktree 根目录>
  git rev-parse origin/main   # 必须等于 Packet merge commit，记录之
  python -m pytest tests/contracts -q          # 基线必须 617 passed
  python -m pytest tests/evidence_privacy -q    # 基线必须 78 passed（既有冻结面）
  ```

## 7. Symbol-to-File Map（冻结）

### 7.1 新增文件（Add）

| 文件 | 符号（冻结命名） |
|---|---|
| `lima/evidence_privacy/content_scan.py` | `BASE64_MIN_LENGTH: Final[int] = 32`；`is_bare_base64_secret(text: str) -> bool`（谓词契约见 §8.4）；`find_base64_spans(text: str) -> tuple[tuple[int, int], ...]`（NFC 文本上的极大候选 span，左闭右开）；`REDACTED_SEGMENT_TEMPLATE: Final[str] = "[[REDACTED:{fingerprint}]]"`；`redact_text_segments(value: str, policy: TenantPolicy, *, tenant_id: str, tenant_key: bytes) -> tuple[str, tuple[FingerprintRecord, ...]]`（返回占位替换后的 NFC 文本与逐段 `FingerprintRecord`；纯函数、无 IO、仅标准库 + 本包） |

本 IP 恰好新增 1 个产品文件；禁止在 `lima/evidence_privacy/` 之外新增任何产品文件，禁止新增第二个适配模块（规模论证见裁定 §B 最小性）。

### 7.2 既有 7 文件的修改规则（Add-only，冻结）

**13 冻结符号签名（`ClassificationManifest, EvidencePayload, FingerprintRecord, PrivacyError, PrivacyErrorCode, PrivacyLimits, SINK_KINDS, SanitizedPayload, SinkContext, TenantPolicy, classify_payload, compute_fingerprint, sanitize_for_sink`）的公共签名、`__init__.py` 的 `__all__` 恰好集合、既有 12 个 `PrivacyErrorCode` 值、错误 str/repr 无原值语义、`PrivacyLimits` 五字段默认值、指纹域分隔常量、`policy_digest` 字段序——一律不动。**

| 文件 | 允许的修改（Add-only 语义） |
|---|---|
| `__init__.py` | **不得修改**（新增模块经 `lima.evidence_privacy.content_scan` 模块路径消费，`__all__` 保持 13 项——O-1 同型约束） |
| `port.py` | D-1 修复：`_prescan` 增加环检测（已见 `id()` 集）与栈安全护栏（迭代遍历或有效深度上限），使 §8.3 契约成立；`sanitize_for_sink` 主体步骤序不变 |
| `classifier.py` | 挂载 base64 判定与 text 段落扫描：（a）`_collect_entries`/`_redact_node` 对满足 §8.4 谓词的 string 位置判 SENSITIVE（整值候选 → 位置替换为 `FingerprintRecord`；部分候选 → span 替换）；（b）text 路径在既有整值规则（RESTRICTED/关键词 SENSITIVE，冻结）之后、INTERNAL 之前增加段落扫描分支（§8.5.2）；（c）整体 severity 归并规则不变 |
| `errors.py` | 仅当 §9.1 DR 条款授权后可 Add-only 追加枚举值；默认方案不改 |
| `models.py` / `policy.py` / `fingerprint.py` | 预期零修改；仅当 §9.1 DR 条款授权后可 Add-only 增量（如新增策略字段必须同步 Packet 版本与 digest 契约） |

### 7.3 判定"修改是否越界"的准绳

diff 中不得出现：既有函数/方法的签名变更、既有枚举成员删除或改值、`__all__` 集合变更、`PrivacyLimits` 默认值变更、域分隔常量变更、`digest_source()` 字段序变更、既有异常构造路径的语义变更。允许：新增私有辅助函数、在既有函数体内**追加**分支（不得反转既有分支的判定结果——既有冻结测试 78 用例是回归底线）。

## 8. 精确契约

### 8.1 冻结接口（消费不修改）

13 公共符号 + `policy.py` 模块级 `policy_digest`/`DEFAULT_POLICY`/`DEFAULT_POLICY_VERSION`（经模块路径消费，O-1）；`SINK_KINDS = frozenset({"storage","log","prompt","api","export"})`；`PrivacyErrorCode` 既有 12 值；`fingerprint.py` 域分隔 `Final` 常量；`PrivacyLimits` 五字段默认值（32 / 1_048_576 / 262_144 / 10_000 / 1_000）；错误 str/repr 无原值语义。

### 8.2 五 sink conformance 语义（AC/T-N05-01，按裁定 O-3 冻结读法）

1. 同一 `EvidencePayload` × 同一 `TenantPolicy` × 五种 `SinkContext(sink_kind=k)`（k 遍历 `SINK_KINDS`，tenant 凭据相同）→ 五个 `SanitizedPayload` 满足：`manifest`（除 `created_at` 外）逐字段相等；`redacted_value` 相等；仅 `sink_kind` 字段随 k 变化。无任何 per-sink 差异行为。
2. allowlist 缩减：`sink_allowlist` 去掉 k 后，sink_kind=k 的调用 → `PrivacyError(UNKNOWN_SINK)`（既有语义，conformance 侧全量断言五值各一次）。
3. tenant 隔离不变式跨五 sink 成立：换 `tenant_key` → 同一位置的指纹必变（复用 DI-004 语义）。
4. **若实现期间发现 Issue 语义需要 per-sink 差异行为 → 停止，按 O-3 提 Decision Request（本 Packet 已按"无差异"读法冻结，不得自行实现差异）。**

### 8.3 D-1 修复契约（NFR-N05-02 循环 + fail-closed 外延）

1. **环检测**：输入 `payload.value` 中任何 dict/list 出现直接或间接自引用（含 dict→list→dict 混合环）时，`sanitize_for_sink` 必须抛 `PrivacyError`，错误码 = **`MAX_DEPTH_EXCEEDED`（复用既有枚举，见 §9.1 DR-1 选择）**，且该结果在**任何**合法 `PrivacyLimits`（含 `max_depth` 极大值）下成立。默认 limits 下既有行为（深度护栏先行触发 MAX_DEPTH_EXCEEDED）保持不变。
2. **无裸 RecursionError 逃逸**：对任何合法 `PrivacyLimits` 配置与任何通过 `EvidencePayload` 构造的输入，`sanitize_for_sink` 的结果只有两种：返回 `SanitizedPayload`，或抛 `PrivacyError`。抛出裸 `RecursionError`（或任何未被包裹为 `INTERNAL_REDACTION_FAILURE`/ typed code 的异常自 prescan 路径逃逸）即违规。具体地：非循环但深度超过解释器递归容量的嵌套输入，允许实现二选一——成功返回，或 fail-closed 抛 `PrivacyError(MAX_DEPTH_EXCEEDED)`；不得 RecursionError。
3. 实现自由度（不冻结）：`_prescan` 可改为迭代遍历 + 已见 `id()` 集；或保留递归但增加栈安全有效上限（`min(max_depth, 安全上限)`，安全上限须保证 classifier/redact 二次遍历同样不触栈上限——例如 prescan 计算实际深度并在超安全上限时以 MAX_DEPTH_EXCEEDED 拒绝）。classifier/`_redact_node` 的遍历只需保证"prescan 已放行的输入必不触栈"。
4. 错误卫生不变式延续：D-1 修复产生的错误，其 str/repr/context 不得含原值子串（context 只允许 `{"limit":…, "actual":…}` 型元数据；环检测不得把环上对象 repr 进 context）。

### 8.4 裸 Base64 细化契约（DR-IP-0015-02 归属项，AC/T-N05-03）

1. **谓词（冻结）**：字符串 s（先 NFC 归一）满足全部条件即为"裸 Base64 秘密候选"：
   - `len(s) >= 32`（NFC 码点数）；
   - 字符集属于严格 Base64 字母表 `[A-Za-z0-9+/]`，可选地以 1–2 个 `=` 结尾；
   - `len(s) % 4 == 0`；
   - `base64.b64decode(s, validate=True)` 成功（标准库，无宽容解码）。
   下称该谓词 `is_bare_base64_secret(s)`。解码内容本身不做进一步判定（不解套递归扫描——嵌套编码不在本 IP 契约内，未检出风险由保守 SENSITIVE 级别覆盖）。
2. **默认级别**：无敏感键上下文的裸 Base64 整值候选 → **SENSITIVE**（附录 A 缺省级别；保守方向）。位置替换为 `FingerprintRecord`（value_kind="string"），整体 severity 按 #58 枚举序归并。
3. **上下文规则（冻结优先序，值形态胜出原则延续）**：
   - RESTRICTED 形态（PEM 头 / URL credential）优先于一切——整值或包含 RESTRICTED 形态的值仍按既有冻结规则判 RESTRICTED（既有行为不变）；
   - 敏感键上下文（键名匹配 `secret/token/key/password/credential/private_key`，大小写不敏感）下的值 → SENSITIVE（既有行为不变；值本身是否 Base64 不影响级别）；
   - 无上下文且满足 §8.4.1 谓词 → SENSITIVE（**本 IP 新增**，DR-IP-0015-02 细化落点；IP-0015 冻结测试对此未下断言，加法空间成立）；
   - 其余 → INTERNAL（既有缺省，不变；短于 32 或不可解码的 Base64 形态字符串维持 INTERNAL）。
4. **部分候选（span 级）**：更长字符串（structured 值或 text）内嵌的极大候选 span（`find_base64_spans`，在 NFC 文本上取最长匹配，重叠取先出现者）满足谓词时，仅该 span 被脱敏：structured 位置返回原字符串中 span 替换为 `REDACTED_SEGMENT_TEMPLATE.format(fingerprint=…)` 后的字符串；text 见 §8.5.2。非候选部分原样保留（NFC）。

### 8.5 多内容形态适配契约（FR-N05-05）

#### 8.5.1 structured_json（嵌套全量矩阵）

- 既有递归遍历（`_collect_entries`/`_redact_node`）语义保持：任意深度、dict/list 任意混合、键名与值形态判定与 redaction 逐位置一致（classify 与 build_redacted_value 的指纹逐字节相同——既有不变式，conformance 全量断言）。
- 矩阵钉死：深度边界（`max_depth=d` 时深度 d 合法、d+1 → MAX_DEPTH_EXCEEDED，至少取 d∈{1, 2, 31, 32, 33} 抽样）；嵌套 list-of-dict-of-list；同键多形态；深度极限处的敏感值仍被检出（深度不削弱检测）。
- §8.4 base64 判定在全深度矩阵内一致生效（含深层裸 Base64 值）。

#### 8.5.2 text（日志行/diff/Prompt 段/异常栈，同一谓词族）

- **既有整值规则冻结不动**（锁定面）：整值含 PEM 头或 URL credential → RESTRICTED 整值 `FingerprintRecord`；整值含敏感关键词 → SENSITIVE 整值 `FingerprintRecord`；否则进入本 IP 新增分支——
- **段落扫描分支（新增）**：对 NFC 归一后的文本运行 `find_base64_spans`；存在满足 §8.4.1 谓词的 span 时：整体 classification = SENSITIVE；`redacted_value` = 各 span 替换为 `[[REDACTED:<32hex>]]` 后的**字符串**（保持 `SanitizedPayload.redacted_value` 的 `str` 形态，符合 DI-005 冻结模型）；每个被替换 span 生成一条 `FingerprintRecord`（指纹对象 = span 文本，租户隔离语义同 DI-004）追加进 `manifest.entries`。无候选 span → INTERNAL，返回 NFC 原文（既有行为）。
- 形态无关性：日志行（logfmt `k=v` 空格分隔）、unified diff（`+/-` 行）、Prompt 对话片段、Python traceback 文本——四种形态使用**同一谓词族**（PEM/URL cred/敏感关键词/裸 Base64 span），不按 `media_type` 分叉（`media_type` 冻结为信息性字段）。形态差异仅体现在 conformance 测试的代表性样本矩阵（§10.1），不体现在实现分支。
- 日志行 `token=abc` 类输入由敏感关键词整值规则覆盖（"token" 子串命中）——这是既有冻结行为，本 IP 不改为 k=v 精确定位（避免动锁定面；精确 logfmt 定位若未来需要，属新 Packet）。

#### 8.5.3 bytes（二进制扫描 conformance）

- 既有行为冻结：整值 SENSITIVE + `FingerprintRecord`（value_kind="bytes"，指纹输入为原样字节）。conformance 矩阵：含 PEM 文本的 bytes、含高熵块的 bytes、空边界长度的 bytes、超 `max_payload_bytes` 的 bytes（→ RESOURCE_LIMIT_EXCEEDED）。不新增二进制内容解析（保守整值策略即合规，附录 A"binary secret"行）。

### 8.6 fixture 无泄漏契约（AC/T-N05-05）

- API 场景：构造 API 响应形态的 structured_json（嵌套用户对象 + 各类别秘密：短 secret、token、URL credential、PEM、裸 Base64、二进制 media 内嵌 base64 文本），`sanitize_for_sink(sink_kind="api")` 后：对返回对象做**递归遍历**（dict/list/str/bytes/FingerprintRecord 全节点），断言任何 ≥4 字符的原秘密子串不出现在任何节点的 `str()`/`repr()`，亦不出现在 `canonical_encode(redacted_value)` 结果中。
- export 场景：同构 fixture（导出 bundle 形态：多记录数组 + 元数据头），`sink_kind="export"` 同断言；并与 api 场景断言仅 `sink_kind` 差异（§8.2.1 的实例化）。
- 错误路径无泄漏：全部负例（超限/环/未知 sink）的异常 str/repr 不含原值子串（既有 hygiene 契约在 conformance 输入族上重放）。

### 8.7 资源上限矩阵契约（NFR-N05-02 全量 + O-2）

| 维度 | 输入构造（冻结） | 判定 |
|---|---|---|
| 超深 | 深度 = `max_depth+1` 的嵌套 dict（含 list 混合抽样） | `MAX_DEPTH_EXCEEDED` |
| 超大字符串 | NFC 字节数 = `max_string_bytes+1` 的 str | `MAX_STRING_LENGTH_EXCEEDED` |
| 超大 payload | bytes 长度 = `max_payload_bytes+1` | `RESOURCE_LIMIT_EXCEEDED` |
| 超条目 | 条目数 = `max_items+1` 的扁平 list | `MAX_ITEMS_EXCEEDED` |
| 超时（O-2） | `PrivacyLimits(max_processing_ms=1, max_items=1_000_000)` + 扁平 list ≥ **200,000** 个小 int 条目（item 数 > 256 使 checkpoint 可达；200k 次 prescan 步进在任何常规硬件上耗时 > 1ms，保证首个超限 checkpoint 必然命中） | `TIME_BUDGET_EXCEEDED` |
| 循环 | §8.3（默认 limits 与 `max_depth=100000` 两种配置；dict 环/list 环/混合环） | `MAX_DEPTH_EXCEEDED`（typed），无 RecursionError |
| 合法边界内 | 深度恰 = `max_depth`、条目恰 = `max_items`、字符串恰 = `max_string_bytes` | 成功返回（不误拒） |

边界值选取说明：`max_items` 检查在 `state["items"] > max_items` 时触发（port.py L76），故"恰等于"合法；深度检查 `depth > max_depth`（L124），同理。实现不得改变这些比较语义（Add-only）。

### 8.8 资源与权限契约（延续 IP-0015 §8.5）

纯内存、无网络、无文件系统写、无数据库、无子进程、无环境变量；仅 import 标准库（新增允许：`base64`）与 `lima.contracts.*`、本包。tenant_key 只作内存参数。`requirements*.txt` Forbidden（禁新依赖）。

## 9. Packet 内显式 DR 条款（Add-only 增量授权边界）

### 9.1 DR-IP-0017-1：循环引用错误码选择（本 Packet 裁定）

- **裁定**：D-1 循环引用拒绝**复用既有 `MAX_DEPTH_EXCEEDED`**，不新增枚举值。理由：环在语义上即"无界深度"，与既有深度护栏错误同族；避免冻结面增量。
- **Add-only 后备**：仅当实现证明复用在语义上不可行（例如需要区分"配置过深"与"环"两类排障信号）时，允许 Add-only 追加 `PrivacyErrorCode` 新值（如 `CYCLIC_INPUT_REJECTED`），但必须先停止并向 Coordinator 提 Decision Request，获授权后：更新本 Packet（版本 +1）与 §10 断言 → 重走 RED → 重冻结。既有 12 枚举值任何情况下不得改动。
- **策略字段**：同理，任何新增 `TenantPolicy` 字段（如 base64 检测开关）须先 DR；本 Packet v1.0 的 base64 细化为**无条件生效**（无开关——与"无 feature-flag 回滚"原则一致）。

## 10. 测试冻结计划（阶段二执行的期望；本轮不冻结）

### 10.1 文件布局与最小用例数（全部 P&V 所有，均为新文件）

| 文件 | 覆盖需求 | 最少用例数 |
|---|---|---|
| `tests/evidence_privacy/test_conformance_sinks.py` | AC/T-N05-01、FR-N05-02 conformance 侧、§8.2 | 10 |
| `tests/evidence_privacy/test_conformance_cycles.py` | NFR-N05-02 循环、D-1、§8.3 | 6 |
| `tests/evidence_privacy/test_conformance_limits_matrix.py` | NFR-N05-02 全量矩阵、§8.7（含 O-2 超时与合法边界内不误拒） | 10 |
| `tests/evidence_privacy/test_content_forms.py` | FR-N05-05、§8.5（嵌套矩阵/text 四形态/bytes） | 12 |
| `tests/evidence_privacy/test_base64_refinement.py` | AC/T-N05-03 全量、DR-IP-0015-02、§8.4（短值/Unicode/二进制/URL credential/私钥/base64 上下文优先序） | 8 |
| `tests/evidence_privacy/test_fixture_no_leak.py` | AC/T-N05-05、§8.6（api/export fixture 递归无泄漏 + 错误路径无泄漏） | 8 |

合计 ≥ 54 个新用例；既有 78 + 新 ≥54 = ≥132。每条断言在注释中锚定需求 ID 与 Packet 契约小节号（`# AC/T-N05-01 §8.2.1: ...`，PI-DR1）。fixture 一律 inline；仅当超合理性时新增 `tests/evidence_privacy/fixtures/`（写入显式钉死 LF，二进制模式 + `\n`）。

### 10.2 预期 RED 形态（PI-DR4）

- `test_conformance_cycles.py` / `test_conformance_limits_matrix.py`（环用例）：现实现抛裸 `RecursionError` → 断言 `PrivacyError(MAX_DEPTH_EXCEEDED)` 失败（缺失交付 = D-1 修复）。
- `test_base64_refinement.py` / `test_content_forms.py`：现实现对裸 Base64 判 INTERNAL / text 段落返回原文 → SENSITIVE/占位替换断言失败；`from lima.evidence_privacy.content_scan import ...` → `ModuleNotFoundError`（缺失交付 = content_scan 模块）。
- `test_conformance_sinks.py` / `test_fixture_no_leak.py`：五 sink 输出一致性与无泄漏在现实现上部分已绿（接口侧 IP-0015 交付）——这部分属"回归性断言"，其 GREEN 不抵扣缺失交付；冻结时 RED 清单须逐文件标注哪些断言 RED（缺失交付触发）、哪些 GREEN（回归锚），不得以整体 GREEN 掩盖。
- RED 报告附逐断言锚定表（断言 → 需求 ID → 缺失符号/行为）。

### 10.3 scratch 骨架 GREEN 证明（PI-DR2，冻结前执行、不入交付）

1. 在 worktree 外临时目录（如 `%TEMP%/ip0017-scratch`）实现最小骨架：`content_scan.py` 全符号 + `port.py`/`classifier.py` 的 D-1/base64/段落最小实现（指纹必须真实 HMAC 语义一次到位）；
2. `cp -r tests/evidence_privacy <scratch>/tests/` 后在 scratch 内实跑 `python -m pytest tests/evidence_privacy -q` 与 `python -m unittest discover -s tests/evidence_privacy -t .`，双 runner 确认无 collection error 且断言语义可达 GREEN；
3. 记录命令与输出到 RED 证据文档；scratch 用后销毁，绝不进入 commit。

### 10.4 双 runner 条款（PI-DR6-bis，冻结）

进入 Frozen Test Commit 的全部新测试必须同时满足：
```bash
python -m pytest tests/evidence_privacy -q
python -m unittest discover -s tests/evidence_privacy -t .
```
均可收集、可执行、结论一致（禁止 pytest-only 依赖：不得用 `pytest.fixture`/`parametrize`/`importorskip` 等 pytest 专有 API，测试类继承 `unittest.TestCase`）。fixture 文件写入显式钉死 LF（`open(..., "wb")` + `\n`，PI-DR6 交叉适用）；断言不得隐式依赖平台行为（路径分隔、大小写文件系统、权限语义）。

### 10.5 回归命令（cwd 钉死 = 交付 worktree 根；PI-DR3）

```bash
cd <交付 worktree 根目录>
python -m pytest tests/contracts -q                    # 617 passed（DI-017 基线）
python -m pytest tests/evidence_privacy -q             # 既有 78 + 新套件全绿，0 skip
python -m unittest discover -s tests/evidence_privacy -t .   # OK（双 runner）
```

## 11. 验收命令（全部钉死 cwd = 交付 worktree 根）

| 类别 | 命令 | 判定 |
|---|---|---|
| baseline | `git rev-parse HEAD && python -m pytest tests/contracts -q` | HEAD = Frozen Test Commit 祖先链上；617 passed |
| slice-pytest | `python -m pytest tests/evidence_privacy -q` | 全绿 0 skip，总数 = 78 既有 + ≥54 新 |
| slice-unittest | `python -m unittest discover -s tests/evidence_privacy -t .` | OK（PI-DR6-bis） |
| regression | `python -m pytest tests/contracts tests/evidence_privacy -q` | 全绿 |
| boundary-D1 | 探针脚本：自引用 dict/list（默认 limits 与 max_depth=100000）+ 3000 层非循环嵌套 | 全部 `PrivacyError` 或成功（3000 层），无 RecursionError；str(exc) 无原值 |
| boundary-limits | 探针：超深/超字符串/超 payload/超条目/超时（§8.7 表五行） | 五行各按表判定 code |
| frozen-symbols | `python -c "import lima.evidence_privacy as p; print(len(p.__all__), sorted(p.__all__))"` | `13` + 13 符号集合不变 |
| enum | `python -c "from lima.evidence_privacy.errors import PrivacyErrorCode as E; print(len(list(E)))"` | ≥12（既有 12 值原样；若 §9.1 后备生效则 =13 且经 DR 授权记录） |
| compatibility | `python -c "import lima.contracts.common as c; print([e.value for e in c.ArtifactClassification])"` | `['public','internal','sensitive','restricted']` |
| post-merge（P&V 阶段三） | 干净 worktree 于 merge commit 重跑 slice-pytest + slice-unittest + regression | 全绿 |

Python 解释器：`python`（3.12.x，基线亲测可用）。

## 12. AC traceability（逐条）

| 需求 | 测试（文件::断言组） | 证据等级 |
|---|---|---|
| FR-N05-02（conformance 侧） | test_conformance_sinks.py（五 sink 输出一致、allowlist 缩减 ×5、tenant 隔离跨五 sink） | contract + integration |
| FR-N05-05 | test_content_forms.py（嵌套深度矩阵、text 四形态、bytes 矩阵）+ test_base64_refinement.py（span 级） | integration |
| NFR-N05-02（全量） | test_conformance_cycles.py（D-1）+ test_conformance_limits_matrix.py（深/大/条目/超时/合法边界） | integration |
| AC/T-N05-01 | test_conformance_sinks.py（§8.2 全部四条） | integration |
| AC/T-N05-03（全量） | test_base64_refinement.py（六类值全场景 + §8.4 优先序四层） | integration |
| AC/T-N05-05 | test_fixture_no_leak.py（api/export 递归无泄漏 + 错误路径） | integration |

## 13. Stop Conditions（裁定 §D 五条 + 本 Packet 条款）

1. 发现需改 13 符号签名/既有枚举值/错误语义才能承载 conformance → 停止，提 Decision Request。
2. 发现 AC/T-N05-01 要求 per-sink 差异行为（O-3 读法分歧）→ 停止提 DR。
3. 基线漂移（§6 复核失败）→ 停止。
4. 编号 IP-0017 被 #60 轨道先行登记 → 停止，回 Coordinator 重分配。
5. 疑似规格矛盾 / 同根因两轮失败 → 升级 glm-5.3/max。
6. 冻结后需改冻结测试/Oracle → 先提 Decision Request，未授权不得动（P&V 责任书 §3）。
7. 实现认为需启用 §9.1 Add-only 后备（新枚举/新策略字段）→ 停止提 DR，授权后重走 RED。
8. scratch 骨架无法证明 GREEN 可达 → 升级 Coordinator。

## 14. Completion Summary 模板（Implementation 必填）

- Final commit 完整 SHA + 分支名；Frozen Test Commit SHA 与基线 merge commit SHA；
- FR→AC→T 追踪表（完整稳定 ID `[V5-N05 / #94] FR-N05-xx` 形式，逐条映射本 Packet §12）；
- 实际测试命令与输出摘要（§11 全表逐行，含双 runner 与 D-1 探针）；
- 关键 digest：policy digest 示例、base64 span 指纹示例（脱敏展示）、新旧测试文件 sha256 清单；
- 文件边界确认：`git diff --stat`（预期：1 新增产品文件 + 既有 7 文件中 port.py/classifier.py Add-only 修改 + 0 越界）；13 冻结符号 diff 审计说明；
- 已知限制（嵌套编码不解套、logfmt 精确定位未做、vault/审计归 S3）与 follow-up（#94-S3）；
- 确认未修改 Read-only/Forbidden 文件、未引入新依赖、未写任何 IO、未动既有 78 冻结用例。

## 15. Packet completion definition

本 Packet 达成：覆盖裁定 §B 全部 covered 需求（FR-N05-02 conformance 侧 / FR-N05-05 / NFR-N05-02 全量 / AC/T-N05-01/03/05 全量）且零 TBD；D-1 修复契约（§8.3）与 DR-IP-0017-1（§9.1 Add-only 边界）显式冻结；测试冻结计划含最小用例数、RED 形态（区分缺失交付 RED 与回归锚 GREEN）、PI-DR2 scratch 步骤、双 runner 条款（PI-DR6-bis）、回归命令（617+78+新套件，cwd 钉死）；验收命令全表钉死 cwd；交接书（`docs/LIMA_Coding_Agent_IP-0017_正式开发任务交接.md`）就绪。Packet PR 合并后由 Coordinator 标记 PACKET-MERGED，方可进入阶段二（测试冻结，另行 Assignment）。

## 附录 A：S2 conformance 断言矩阵（与 §8 对照，供阶段二冻结测试展开）

| 内容形态 × 场景 | storage | log | prompt | api | export |
|---|---|---|---|---|---|
| 嵌套 JSON（含深层敏感键/裸 Base64） | §8.2.1 一致性 + §8.5.1 检出 | 同左 | 同左 | + §8.6 fixture 无泄漏 | + §8.6 fixture 无泄漏 |
| text：logfmt 行 | §8.5.2 谓词族（关键词整值/base64 span） | 同左 | 同左 | 同左 | 同左 |
| text：unified diff（含 PEM 块） | RESTRICTED 整值（冻结） | 同左 | 同左 | 同左 | 同左 |
| text：Prompt 片段（含 URL credential） | RESTRICTED 整值（冻结） | 同左 | 同左 | 同左 | 同左 |
| text：traceback | §8.5.2 谓词族 | 同左 | 同左 | 同左 | 同左 |
| bytes（高熵/PEM 文本） | SENSITIVE 整值（冻结，§8.5.3） | 同左 | 同左 | 同左 | 同左 |
| 负例（环/超深/超大/超条目/超时/未知 sink） | §8.3/§8.7 fail-closed，错误无泄漏（五 sink 同判定） | 同左 | 同左 | 同左 | 同左 |
