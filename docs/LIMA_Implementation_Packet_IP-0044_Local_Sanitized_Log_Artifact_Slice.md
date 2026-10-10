# LIMA Implementation Packet — IP-0044 本机脱敏日志 Artifact 存取（首片）

- Packet 版本：`1.0`（2026-10-10；状态 `DESIGN-FROZEN / PENDING-MERGE`，docs-only PR 呈审对象）
- Assignment：`ASN-D1-IP-0044-66-LOCAL-LOG/v1`（2026-10-10；授权指针 `MR-66-LOCAL-LOG-FIRST-20261010/v1`）
- 编制角色：Packet & Verification Agent（运行模型：无法核验——未取得可独立核验的运行元数据，
  TELEMETRY-MISSING / RUNTIME-UNVERIFIED，不伪造）
- 设计探针：`.pv_tmp/issue66-local-log-2026-10-10/probes/`（P1–P4 实测记录，可复现；下文标注
  「设计探针实测（probe Px，可复现）」处均以该记录为据）

## 1. Header

```text
Source Issue：#66（Artifact Registry 与不可变对象存储；OPEN；labels feature/security/area:storage/priority:high/status:blocked，本片不动 labels）
Issue specification revision：正文 updated_at 2026-09-11T17:39:36Z（V4 FR/NFR/AC/T + V5 覆盖层；V5 节与前文冲突时以 V5 为准）
Delivery role：vertical-slice（#66 首片）
Issue closure impact：PARTIAL（首片完成 ≠ #66 关闭；说明书 §5 清单仍是 mandatory 缺口）
Covered requirements（本片贡献，均为部分/设计层，零 SATISFIED）：FR-01/02/03/04、NFR-01/02、AC-01..03（本机 SQLite/日志子集）、V5-FR-01/02/03/04、V5-AC-01..03（逐条见 §9 映射表）
Not covered requirements：FR-05（migration registry）、FR-06（retention/pin/删除）及 PostgreSQL/report_json 迁移/TTL/GC/tombstone/lineage DAG/多领域 dispatch/S3/生产接线（说明书 §5 全清单）
Upstream IP/PR/merge commits：#58 契约基线与 #94 隐私核心已并入 main `fbbbd619fb0b96efbbb903916ab46dc0daed2214`（本 Packet exact base；详见 §2 DI-007/DI-008）
```

用户可观察结果（首片完成后的真实行为）：调用者提交一份有界 UTF-8 日志及真实租户/任务上下文 →
经真实 #94 storage policy 净化 → 只保存获准内容（净化后字节）并返回既有 `ArtifactReference` →
另一进程重启后仅凭引用与访问上下文读回同一已封存字节并核验身份/权限/大小/摘要。失败不返回未校验
内容、不退回保存原文、不以内联巨型 JSON 降级。

D1 交付性质声明：本文是**设计冻结**——零产品实现、零冻结测试、零 CI 产品证据。D2 才冻结验收测试
与有效 RED；Implementation 只能在 Packet 合并 + 测试冻结 + 有效 RED + Coordinator IMPL Assignment +
主会话真实派发五条件齐备后启动。

## 2. Design Input Manifest 与 Explicitly Rejected Inputs

### 2.1 Design Input Manifest

| ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001 | Standard | `docs/ZCODE_LONG_TASK_ISSUE66_LOCAL_LOG_ARTIFACT_AND_DELIVERY_2026-10-10.md` | SHA-256 `947fa9fb…a3b`（本 Packet 编制时亲算一致） | §4 最小行为、§5 边界、§6 顺序、§7 审阅面、§9 反过度设计 | normative（Maintainer 指令正文） | 最高优先级；与其他输入冲突时以本文为准 |
| DI-002 | Architecture | `docs/LIMA_Issue66_Minimal_Local_Artifact_and_Parallel_Plan_2026-10-10.md` | SHA-256 `0b9facf8…4ef4`（亲算一致） | 首片功能边界、§5.1–5.3 协议雏形、验收组 1–7 | 设计输入（已确认方向，非已批准 Packet） | 与 DI-001 冲突时从 DI-001 |
| DI-003 | Decision | `.pv_tmp/issue66-local-log-2026-10-10/intent/Maintainer_Intent_MR-66-LOCAL-LOG-FIRST-20261010_v1.md` | SHA-256 `e1de6fff…3c84`，状态 READY-FOR-COORDINATOR | 三项既定选择、授权边界、未决事项归属 | evidence（不构成新授权） | 与 DI-001 冲突时从 DI-001 |
| DI-004 | Finding | `.pv_tmp/issue66-local-log-2026-10-10/INDEX.md`（任务索引） | 2026-10-10 快照（SHA-256 `eead37ac…d845`） | 恢复事实、开放 PR 零交集、工作区边界 | evidence | 过时时以远端实时刷新为准 |
| DI-005 | Issue | #66 正文（V4+V5）与评论 5559178921/5559627362/5638380471 | spec revision 2026-09-11T17:39:36Z（快存 `recovery/issue66_body.txt`，6342 chars） | 18 个 requirement ID、原 Issue 提交点文字、Add/Modify/Read-only 文件面 | normative（需求真值；V5 优先） | 与 DI-001 冲突处以 V5 节与 DI-001 处置声明为准（见 §4.2 呈批项） |
| DI-006 | Standard | 治理文档三份 + 三角色责任书（`docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md`、`docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md`、`docs/LIMA_MAIN_SESSION_CONTROL_PLANE_PLAYBOOK.md`、三份责任书） | main `fbbbd619` | Packet 结构、PR 契约、角色边界 | normative | 无冲突 |
| DI-007 | Code | `lima/contracts/{common,codec,errors}.py` @ `fbbbd619` | git blob（`git show fbbbd619:<path>` 亲验，见 §2.2 关键复核） | Envelope/Reference/BlobReference/codec/limits 复用契约 | current-behavior + normative（冻结 wire 面） | 只读复用，不改 |
| DI-008 | Code | `lima/evidence_privacy/{port,models,policy,classifier,content_scan,fingerprint,errors}.py` @ `fbbbd619` | git blob 亲验 | sanitize_for_sink 语义、输出形态、PrivacyLimits、policy_digest | current-behavior + normative | 只读复用，不改 |
| DI-009 | Code | `lima/store.py`、`lima/repository_cache.py` @ `fbbbd619` | git blob 亲验 | 只读参考：单事务建表、reserve/publish/abort、原子写+fsync 模式 | background-only（模式参考，不复制 trust domain） | 不混用 repository snapshot 生命周期 |
| DI-010 | Code | `lima/contracts/profile.py:1183`、`lima/audit/inventory.py` @ `fbbbd619` | git blob 亲验 | 下一片边界登记（`_require_inline_payload` 拒 blob-backed；`inventory.fingerprint()` ≠ `to_dict()` canonical 摘要） | background-only | 本片不展开 |
| DI-011 | Decision | Coordinator Assignment `ASN-D1-IP-0044-66-LOCAL-LOG/v1` 及附录 A/B/C | SHA-256 `d7c91f05…b976` | 20 条冻结清单、18-ID 映射基线、文件边界、验收判据、已收敛取舍 8 项 | normative（Assignment） | 与本派发矛盾时以 Assignment 为准并上报 |
| DI-012 | Finding | 设计探针 P1–P4 记录 `.pv_tmp/issue66-local-log-2026-10-10/probes/PROBE_LOG.md` + 3 个脚本 | 2026-10-10 实测（38 PASS / 0 FAIL，EXIT=0 全部） | 形态判定、digest 实测、绑定实测、双预算、fail-closed、4 条如实观察 | evidence（已有 API 实测；PASS ≠ 产品正确） | 与源码矛盾时停并上报（本轮无） |

### 2.2 关键源码复核（@fbbbd619 git 对象，本 Packet 编制时亲验）

`sanitize_for_sink(EvidencePayload, SinkContext, TenantPolicy)`（port.py，fail-closed）；sink allowlist
`{"storage","log","prompt","api","export"}`（policy.py:17-19）；text 输出形态（classifier.py
`build_redacted_value`：PEM/URL 凭据→RESTRICTED 或敏感关键词→SENSITIVE 均返回 `FingerprintRecord`；
bare-Base64 span→占位符替换 str；其余→NFC str）；`PrivacyLimits`（models.py:83-87：32/1 MiB/256 KiB/
10k/1000ms）；`ContractLimits`（codec.py:38-43：1 MiB/32/10k/1k/256 KiB）；
`compute_content_digest(bytes)=raw SHA-256 hex`（codec.py:187-196，受 max_input_bytes 上限）；
Envelope 规则（common.py：schema name pattern/≤128B、identifier pattern、64-hex digest、payload XOR
blob_ref、`content_digest==blob_ref.content_digest` hmac 比较、lineage 同租户/同快照/禁自环、4.0 禁
extensions）；`TaskStore._init` 单事务 `CREATE TABLE IF NOT EXISTS`；`RepositoryCache`
reserve/publish/abort + 原子写 + 目录 fsync。与 Assignment 附录 C 一致，无出入。

### 2.3 Explicitly Rejected Inputs

| 被否决项 | 理由 | 出处 |
|---|---|---|
| 单 IP 全承载 #66 全范围（blob+双库+迁移+retention+lineage+S3+接线一次交付） | 显著扩大实现与验收面；首片必须保留的是可信"保存成功"核心保证 | DI-002 §3；DI-001 §5；DI-011 §2 Not-covered |
| prompt/展示/wire 层掩码替代存储前净化 | 净化点必须前置于任何持久化（隐私必须在持久化之前），消费层掩码无法保证 SQLite/磁盘/错误信息无 raw Secret | DI-001 §4.2、§7 隐私组 |
| 机械沿用原 Issue「事务写 SEALED metadata→原子 rename」顺序 | 存在读者见 SEALED 而 blob 未就位的可见窗口；本 Packet 采用 blob 先行协议（元素保留、顺序调整，见 §4.2 呈批项） | DI-001 §4.4；DI-002 §3 问题 2 |
| 先实现 S3 SDK / 多后端配置框架 / 插件注册器 / 动态 schema 平台 | 过度设计；首片兼容性靠行为契约保证 | DI-001 §4.1、§9 |
| 全局跨租户 blob 去重或经错误信息泄露他租户对象 | 跨租户必须 blob 隔离 + 拒绝结果不可区分 | DI-001 §4.3 |
| Artifact store 不可用时回退 inline 巨型 JSON / 旧 task report_json | V5-FR-04 明令禁止静默降级 | DI-005 V5 节 |
| #66 旧 consumer review（5559627362）作为"存储已实现"证据 | 旧评审只证明 #58 foundation 足够，不证明存储存在；本轮以源码/探针为据 | DI-001 §2；DI-012 |
| 修改共享契约（contracts/evidence_privacy）或既有 schema 版本/公共字段/默认预算以适配本片 | 文件边界禁改；新类型走新增文件 | DI-001 §3；DI-011 §6 |
| 根检出 HEAD 作为源码依据 | 根检出落后；一律以 `fbbbd619` git 对象读取 | DI-001 §2；DI-004 |
| 用 canonical JSON 摘要或 metadata 整体身份充当封存字节摘要 | digest 必须来自实际净化后封存字节（bytes 入口） | DI-001 §4.1；probe P2 |

## 3. Goal / Non-goals

**Goal**（对齐 Assignment §2 与说明书 §1）：在 `fbbbd619` 之上新增 `lima/artifacts/`，交付
「脱敏 UTF-8 日志 Artifact 存取」的本机可运行闭环：真实净化前置、blob/metadata 双介质明确提交点、
跨进程重启读回并独立核验、租户隔离、幂等/并发语义、有限资源与路径防护、故障点可诊断；配
`tests/artifacts/` 行为验收（D2 冻结）与 `python -m lima.artifacts.demo` 本机示例。

**Non-goals（本片不做，均为顺序安排而非删除 mandatory）**：PostgreSQL；历史 report_json 迁移；
TTL/GC/pin/tombstone/删除接口；lineage DAG 与多领域 dispatch；S3 后端与 SDK；service/API/UI/queue
接线；真实模型客户端；migration registry（FR-05）；retention 规则执行（FR-06）；真实 Profile
hydration/provenance（下一片，§5 末段边界登记）；多用户身份体系（触发即 DR）；跨租户共享。

## 4. 协议：类型契约、提交点与状态机（Assignment §7 条款 1–5、12–16）

### 4.1 冻结的类型身份（条款 1、2、3、4、5、6）

| 冻结项 | 值 | 依据/复核 |
|---|---|---|
| schema name | `lima.sanitized-log` | 匹配 `_SCHEMA_NAME_PATTERN`，18 字节 ≤128B；与 main `fbbbd619` 既有 18 个 `lima.*` schema name（`*_SCHEMA_NAME` 常量口径亲验，并经 ER 独立复核一致——见 ERR-IP-0044-D1-v1 第 25 项/SF-01；`lima.audit.inventory` 为 producer 锚点非 schema name）零冲突；命名遵循仓库 `lima.<dotted>` 惯例；设计探针实测（probe P3，可复现）通过契约校验 |
| schema version | `4.0`（`SchemaVersion(4,0)`；仅此一个值，4.1+ 在本片 get/stage 均拒绝） | 4.0 是禁 extensions 的当前次版本；首片不引入未知次版本面 |
| 编码 | UTF-8（封存字节 = 净化后 str 的 `encode("utf-8")`） | 条款 10 字节语义；probe P2 |
| media type（blob_ref.media_type） | `text/plain` | 契约 `_MEDIA_TYPE_PATTERN` 不接受 `; charset=` 参数（亲验 common.py:60-62）；UTF-8 编码作为本片不变量单列，不写入 media type |
| digest | `compute_content_digest(sealed_bytes)`（raw SHA-256 hex，bytes 入口） | 条款 3；probe P2 实测：span 替换例 raw `9e240e77…` ≠ 净化后 `6193c3da…`；同字节稳定 |
| wire 容器 | 复用 `ArtifactEnvelope`/`ArtifactReference`/`ArtifactBlobReference` + `encode_envelope`/`decode_envelope`；payload XOR blob_ref（本片恒 blob-only） | 条款 2；probe P3 往返 930 字节 canonical JSON 全等、重编码稳定 |
| lineage/supersedes | 仅空 `lineage=()`、`supersedes=None`；非空/supersedes 非 None 在 stage 入口拒绝（`UNSUPPORTED_LINEAGE`） | 条款 5；**设计探针实测（probe P3-C）**：契约层接受合法非空 lineage ⇒ 拒绝必须落产品层 |
| classification/retention 接受面 | 接受 = `redacted_value` 为 **str** 且 `classification ∈ {internal, sensitive}`（str 形态可达的全部类别）且 `retention_class == standard`；三条件任一不满足（RESTRICTED、整值 SENSITIVE/RESTRICTED 的 FingerprintRecord 形态、bytes/JSON 形态、非 standard retention）→ `UNSUPPORTED_REDACTED_FORM`，零内容落盘 | 条款 6、9；probe P1 四形态实测；不把"保存了字段"冒充已实现 retention（EXPIRED/LEGAL_HOLD 等行为未实现即拒绝） |
| 上下文 | tenant/task/workflow/attempt/snapshot/producer/policy/toolchain 全部必填真实值（identifier/digest 校验）；禁止全零或占位 | 条款 4；probe P3 以非全零真实上下文构造通过 |

补充：`repository_snapshot_digest`/`toolchain_digest` 为 64-hex（由调用方按其真实快照/工具链身
份计算）；`policy_digest` 必须等于实测 `policy_digest(policy)`（probe P1/P3 一致性实测）；
`created_at` 由 store 在 seal 时生成 UTC RFC3339（契约归一化 `.ffffffZ`）。

### 4.2 提交点协议与对原 Issue 文字的处置（条款 15——呈批项 DR-PACKET-1）

**本片冻结协议**（seal 路径，任一步失败即中止且不返回成功引用）：

```text
stage_log(text, producer)
  S0  入口预检：text 为 str 且 UTF-8 可编码（lone surrogate → INVALID_TEXT_ENCODING，
      零内容）；输入 UTF-8 字节数 ≤ max_input_bytes（INPUT_BUDGET_EXCEEDED）；
      producer 各字段通过 identifier/digest 校验；store 已用尽 live-staging/容量额度则拒绝
  S1  真实净化：sanitize_for_sink(EvidencePayload("text", text, "text/plain"),
      SinkContext("storage", tenant…), policy)  ← 原文只在有界内存
  S2  形态/策略校验：redacted_value 必须 str（FingerprintRecord/bytes/JSON →
      UNSUPPORTED_REDACTED_FORM，零内容）；manifest.classification/retention ∈ 接受面；
      manifest.tenant_id == store tenant；manifest.policy_digest == 实测 policy digest
  S3  attempt-scoped staging：staging_id/artifact_id 系统生成；净化后字节写入
      root/staging/<staging_id>/content.bin（O_CREAT|O_EXCL + fsync）；
      seal_attempts 行 STAGING（单事务）
  S4  完整校验：从 staged 字节重读并计算 len(bytes) 与 compute_content_digest(bytes)；
      净化后字节数 ≤ max_sealed_bytes（SEALED_BUDGET_EXCEEDED）；
      expected_content_digest（如给）必须等于实测（SEAL_DIGEST_MISMATCH）
seal_log(handle)
  P1  发布不可变 blob：root/blobs/<tenant_id>/<d[:2]>/<d>/blob.bin 经
      同目录临时文件 + fsync + 原子 rename（os.replace）发布；已存在同 digest 文件则
      复用（租户内内容寻址去重，仅 blob 层）；rename 后目录 fsync（Linux）/
      平台声明（Windows，见 §7.4）
  P2  SQLite 单事务（BEGIN IMMEDIATE）提交可见 SEALED metadata：insert artifacts 行、
      seal_attempts STAGING→SEALED、staging 文件目录标记可清理（不自动删）
  P3  返回 SealedLogArtifact(reference, envelope)   ← 成功可见点 = P2 commit
get_log(reference)
  G1  权限/身份：store 绑定的受信租户 vs reference.tenant_id/schema/version；
      租户不符 → ARTIFACT_NOT_FOUND（与不存在不可区分，零跨租户信息）
  G2  状态：仅 SEALED 行可读（未知 id/未封存 → ARTIFACT_NOT_FOUND）
  G3  实物核验：读取实际 blob 字节（有界），重算 size 与 compute_content_digest 与
      metadata/envelope/blob_ref 三方比对（BLOB_MISSING/BLOB_CORRUPT/BLOB_SIZE_MISMATCH）；
      decode_envelope 校验绑定（契约 DIGEST_MISMATCH 等保持透传语义）
  G4  返回 (content, envelope, reference)——先验证后返回，绝不返回未核验字节
```

**对 #66 原文「先写临时 blob→fsync/verify→事务写 SEALED metadata→原子 rename」的处置声明（呈批
项 DR-PACKET-1，随本 Packet 请 Maintainer 批准）**：本片**保留原文全部四个元素**（临时写、
fsync/verify、事务化 SEALED metadata、原子 rename），但把**原子 rename 移到 metadata 事务之
前**（即 P1→P2），不机械沿用原文顺序。理由与证明：成功可见点唯一化为「SQLite 提交可见 SEALED
metadata」（P2）；由于 rename（P1）先于该点完成，任何读者在看到 SEALED 引用之时 blob 必已完整发
布且可验证——**读者无不完整可见窗口**。若按原文顺序（metadata 先可见、rename 后行），存在
「metadata 已 SEALED 而 blob 尚未就位」窗口，get 只能对已可见引用返回失败。崩溃残留对照：
本协议在 P1 后 P2 前崩溃留下**可诊断 orphan blob**（无 metadata，读者不可见、不返回成功引用），
reconcile 分类仍覆盖原文要求的 orphan/metadata-only 集合（metadata-only 仅由外部删除/损坏产生，
同样被诊断）。**覆盖范围**：本处置针对本片本机 SQLite+文件后端；未来 PostgreSQL/S3 适配器必须在
同一不变量（读者永不见"SEALED 而内容未完整发布"）下重新推导其提交点证明，不继承本结论。

### 4.3 状态机与故障点状态矩阵（条款 12、16）

Artifact metadata 状态本片仅使用 `STAGING`、`SEALED`（FR-02 允许集的子集；`QUARANTINED/EXPIRED/
DELETING` 不出现：corruption 不改状态、在 G3 读时 fail closed，recovery 只诊断/隔离（可将损坏
blob 文件移入 root/quarantine/，不动 metadata、不虚造 SEALED）、不自动删除）。

| 故障点 | blob 实物 | metadata（SQLite） | 重启后分类 | get 行为 |
|---|---|---|---|---|
| S0–S2 中崩溃 | 无任何写入 | 无行 | 干净 | 无引用存在 |
| S3 staging 写中崩溃 | 部分 staging 文件 | 无行（content.bin 写中）或 STAGING 行（行事务已提交后） | `staging`（未完成） | 该 staging 无引用可 get |
| S3 完成后、P1 前 | staging 完整 | STAGING 行 | `staging` | 同上 |
| P1 临时文件写/fsync 中 | publish 临时文件 | STAGING 行 | `orphan`（临时） | 无 SEALED 行 |
| P1 rename 后、P2 前 | 最终 blob 就位 | STAGING 行、无 artifacts 行 | `orphan`（blob 无 SEALED metadata） | 调用者从未获得引用；伪造 id → ARTIFACT_NOT_FOUND |
| P2 事务中崩溃 | 最终 blob 就位 | 事务原子：有 artifacts(SEALED) 行或无 | 有行=完全成功；无行=上一种 orphan | 有行则 get 正常且 G3 全过；无行 NOT_FOUND |
| P2 后、P3 返回前 | 就位 | SEALED | 完全成功 | 同 staging 幂等重试返回同一 artifact |
| SEALED 后 blob 被外部删除/篡改/截断 | 缺失/异字节 | SEALED | `metadata-only` / `corrupt` | BLOB_MISSING / BLOB_CORRUPT（fail closed，metadata 不丢，不返回未核验内容） |

get 永远执行 G3 实物核验，绝不只信 SEALED 字符串（条款 16；另据**设计探针实测（probe P3-A）**：
wire 上保持内部一致的 digest 篡改能通过契约层——契约层看不到字节，故 G3 的字节级重算比对是
mandatory 不可省略）。`inspect()`（recovery 入口）输出上述四类分类（staging/orphan/
metadata-only/corrupt）+ 计数，不删除、不重构、不虚造。

### 4.4 身份键、幂等与并发（条款 14）

- **Artifact 身份键** = `(tenant_id, artifact_id)`；`artifact_id = "art-" + uuid4hex(32)`（系统生
  成，identifier 合法）。**同字节 ≠ 同身份**：不同 stage 调用各自生成 artifact_id，即使封存字节
  相同也是不同 Artifact；metadata 身份、上下文（task/attempt/policy）、身份绑定不因 blob 去重合并。
- **blob 键** = `blobs/<tenant_id>/<digest[:2]>/<digest>`，`blob_id == content_digest`（64-hex，
  identifier 合法）。blob 复用仅发生在**同租户同字节**（内容寻址 + 租户目录隔离）；跨租户同字节
  各自独立 blob 文件，无全局去重。
- **同请求幂等**：同一 staging handle 的 seal 重复/并发调用返回**同一** SealedLogArtifact——由
  P2 的单事务 + `seal_attempts.staging_id` 唯一约束裁决，后到者在事务内读到胜者已写的
  artifact_id 并原样返回；不产生第二个 artifact。
- **并发重复 seal（不同 staging、同字节/不同字节）**：各自独立 artifact；blob 文件层内容由
  digest 决定，天然一致；无 ACL 放宽面（本片 ACL 即租户绑定，无运行时放宽接口）。
- **metadata 冲突**：同 `(tenant_id, artifact_id)` 已存在且字段值不一致 → `METADATA_CONFLICT`
  拒绝，绝不覆盖（UUID 下实际不可达，仍冻结为唯一约束违反路径的稳定语义）。
- **首片无公共 delete/update**（条款 14 末句）；SEALED 内容及其租户/身份绑定不可修改（无任何
  UPDATE 路径）。

### 4.5 权限与信任边界（条款 13）

- 信任边界 = 受控本机进程：`LocalArtifactStore.open(root, tenant=TrustedTenantContext(...))` 在
  打开时绑定受信租户身份（tenant_id + tenant_key；key 仅驻内存，绝不持久化、绝不入错误信息）。
- 调用者**不能**逐调用传入租户字符串充当身份；`reference.tenant_id` 只是声明，G1 以 store 绑定
  的受信租户比对，不符即 `ARTIFACT_NOT_FOUND`（与不存在同错误，杜绝存在性泄露）。
- 权限执行点 = metadata 查询（G1/G2）与读取入口（G3），双层；无跨租户共享、无运行时 ACL 放宽。
- 需要多用户身份体系、真实认证来源时必须提 DR（六类升 Maintainer 之一）；本片不声称防御拥有同
  等 OS 权限的恶意本机用户（见 §7.4 平台声明）。

## 5. 精确文件与符号（Assignment §9.5；exact files 由 D2/IMPL Assignment 最终冻结，本节为 Packet 冻结的允许面与符号规划）

### 5.1 Files

| 类别 | 路径 | 说明 |
|---|---|---|
| Add（产品） | `lima/artifacts/__init__.py` | 公共导出：`LocalArtifactStore`、`TrustedTenantContext`、`ProducerContext`、`ArtifactStoreLimits`、`StagedLogHandle`、`SealedLogArtifact`、`ArtifactStoreError`、`ArtifactStoreErrorCode`、`SANITIZED_LOG_SCHEMA_NAME` 等 schema 常量 |
| Add（产品） | `lima/artifacts/schema.py` | 冻结类型身份常量 + `build_sanitized_log_envelope(...)`（校验型构造器）+ `decode_sanitized_log_envelope(bytes)`（decode+schema_name/version 校验） |
| Add（产品） | `lima/artifacts/context.py` | `TrustedTenantContext`、`ProducerContext`（frozen dataclass，fail-closed 校验） |
| Add（产品） | `lima/artifacts/limits.py` | `ArtifactStoreLimits`（frozen dataclass，默认值=§7.1 表，域校验 fail-closed） |
| Add（产品） | `lima/artifacts/errors.py` | `ArtifactStoreError`/`ArtifactStoreErrorCode`（§6.1 稳定错误面；错误串永不包含日志正文/凭据/绝对路径） |
| Add（产品） | `lima/artifacts/staging.py` | `StagedLogHandle` + staging 写入/校验原语（S0–S4） |
| Add（产品） | `lima/artifacts/metadata.py` | SQLite 层：`_init` 单事务建表（版本化 `PRAGMA user_version=1`、幂等可重开）、seal 事务、查询（租户作用域） |
| Add（产品） | `lima/artifacts/local_store.py` | `LocalArtifactStore`（open/stage_log/seal_log/get_log/inspect/close；blob IO 与 metadata 分离） |
| Add（产品） | `lima/artifacts/recovery.py` | `inspect` 诊断（staging/orphan/metadata-only/corrupt 分类报告）与隔离移动（不删不重构） |
| Add（产品） | `lima/artifacts/demo.py` | `python -m lima.artifacts.demo --root <dir>`：本机可运行示例（进程内 stage→seal→get + 子进程重开读回 + 独立 digest 复算） |
| Add（测试，D2 冻结名称/符号/计数） | `tests/artifacts/__init__.py` + `tests/artifacts/test_*.py` | 方法族与最小覆盖数见 §8；exact 文件/符号 D2 冻结 |
| Modify | 无（本片零修改既有文件） | 首片不改 `lima/store.py` 等；V5-FR-01 迁移义务留在 #66 后续 |
| Read-only | `lima/contracts/`、`lima/evidence_privacy/`、`lima/audit/`、workspace、cache、`lima/store.py`/`postgres_store.py`/`repository_cache.py`、service/auth、Docker/compose、#60 全部工作面、其余一切 | 只读复用/参考 |
| Forbidden | 共享契约任何修改；既有 schema 版本/公共字段/默认预算/全局 registry；`lima/persistence/migrations.py`（FR-05 后续片）；除上述 Add 面外的任何新增仓库文件 | Assignment §6 |

实现期文件面按 #66 Add 面收敛到 `lima/artifacts/` + `tests/artifacts/` + 新 schema 新增文件；
不新增 `ports.py`/`retention.py` 框架性文件（防过度设计）。依赖约束：仅 Python 标准库
（sqlite3/uuid/pathlib/hmac/hashlib 等）+ 既有 `lima.contracts`/`lima.evidence_privacy`；禁网络、
禁新第三方依赖、禁容器、禁远端写。

### 5.2 Symbol-to-File Map（公共符号）

| Symbol | File |
|---|---|
| `SANITIZED_LOG_SCHEMA_NAME`/`SANITIZED_LOG_SCHEMA_VERSION`/`SANITIZED_LOG_MEDIA_TYPE`/`SANITIZED_LOG_ENCODING`/`build_sanitized_log_envelope`/`decode_sanitized_log_envelope` | `lima/artifacts/schema.py` |
| `TrustedTenantContext`/`ProducerContext` | `lima/artifacts/context.py` |
| `ArtifactStoreLimits` | `lima/artifacts/limits.py` |
| `ArtifactStoreError`/`ArtifactStoreErrorCode` | `lima/artifacts/errors.py` |
| `StagedLogHandle` | `lima/artifacts/staging.py` |
| `LocalArtifactStore`（`open`/`stage_log`/`seal_log`/`get_log`/`inspect`/`close`） | `lima/artifacts/local_store.py` |
| `SealedLogArtifact` | `lima/artifacts/local_store.py`（或 schema.py，D2 定；字段：`reference`/`envelope`/`content`） |
| `StoreHealthReport`（inspect 返回） | `lima/artifacts/recovery.py` |
| `main`（demo 入口） | `lima/artifacts/demo.py` |

### 5.3 冻结签名（条款 12；P&V 依真实接口确定）

```python
class LocalArtifactStore:
    @classmethod
    def open(cls, root: Path, *, tenant: TrustedTenantContext,
             limits: ArtifactStoreLimits | None = None) -> LocalArtifactStore
    def stage_log(self, *, text: str, producer: ProducerContext) -> StagedLogHandle
    def seal_log(self, handle: StagedLogHandle, *,
                 expected_content_digest: str | None = None) -> SealedLogArtifact
    def get_log(self, reference: ArtifactReference) -> SealedLogArtifact
    def inspect(self) -> StoreHealthReport
    def close(self) -> None
```

- 全部关键字参数（store 打开参数与 stage 入参）；`stage_log` 返回的 handle 一次性有效（seal 后
  不可再用于新 seal 的身份变更，仅幂等重读）。
- `get_log` 返回的 `SealedLogArtifact.content` 为**已验证**封存字节；`seal_log` 返回值 content
  置空（b""）以避免重复持有——业务需要内容时走 get。
- 业务只取得 ref/已验证内容/稳定错误，不接触 blob 绝对路径（路径仅存在于 store 内部与
  bounded 诊断计数中）。

## 6. 状态/错误/权限语义（Assignment §7 条款 8、11、13、16）

### 6.1 稳定错误码表（`ArtifactStoreErrorCode`，wire 值冻结）

| code | 触发条件 | 副作用保证 |
|---|---|---|
| `INVALID_ARGUMENT` | 参数类型/形状错误（非 str text、非法 producer 字段、非 ArtifactReference 等） | 零写入 |
| `INVALID_TEXT_ENCODING` | text 非 UTF-8 可编码（lone surrogate 等） | 零写入（S0 预检；据 probe P4.2e：裸 UnicodeEncodeError 会逃出隐私端口，故必须前置） |
| `INPUT_BUDGET_EXCEEDED` | 输入 UTF-8 字节数 > max_input_bytes | 零写入 |
| `SEALED_BUDGET_EXCEEDED` | 净化后封存字节数 > max_sealed_bytes | staging 可留诊断行，无 blob 发布 |
| `SANITIZATION_FAILED` | 隐私端口 PrivacyError（含 MISSING_TENANT_KEY/UNKNOWN_SINK/MAX_STRING_LENGTH_EXCEEDED 等，bounded context 携带 privacy_code） | 零内容落盘、无 staging 内容文件 |
| `UNSUPPORTED_REDACTED_FORM` | redacted_value 非 str（FingerprintRecord/bytes/JSON）或 classification/retention 不在接受面 | 零内容落盘、不取回原文、不声称已保存全文 |
| `UNSUPPORTED_LINEAGE` | 非空 lineage/supersedes 进入 stage | 零写入 |
| `UNSUPPORTED_SCHEMA` | get 的 schema name/version 非 `lima.sanitized-log`/`4.0` | 只读失败 |
| `STAGING_NOT_FOUND`/`STAGING_STATE_INVALID` | handle 未知/已失效（非本 store、已 abort） | 只读失败 |
| `SEAL_DIGEST_MISMATCH` | expected_content_digest ≠ 实测 | 不发布、不提交 |
| `ARTIFACT_NOT_FOUND` | 未知 artifact_id、未封存、**或租户不符（不可区分）** | 只读失败；绝不泄露他租户对象存在性 |
| `BLOB_MISSING` | SEALED 行存在但 blob 文件缺失（metadata-only） | metadata 不丢；不返回内容 |
| `BLOB_CORRUPT` | 实际字节 digest 不匹配（篡改/截断后字节数仍相同等） | fail closed；可隔离不改状态 |
| `BLOB_SIZE_MISMATCH` | 实际 size ≠ 记录 size_bytes | 同上 |
| `METADATA_CORRUPT` | metadata 行/envelope 无法解码或互相矛盾 | fail closed；报告分类 |
| `METADATA_CONFLICT` | 身份键冲突且字段不一致 | 拒绝，不覆盖 |
| `CAPACITY_EXCEEDED` | 总容量（含 staging/orphan）或对象数超限 | 拒绝新写；不自动清理活对象 |
| `CONCURRENCY_LIMIT_EXCEEDED` | 并发 seal 超 max_concurrent_seals | 拒绝新 seal（不排队无限等） |
| `PATH_POLICY_VIOLATION` | 解析路径越出私有 root、symlink/junction 命中发布/读取路径 | 拒绝该 IO；零越界访问 |
| `IO_ERROR` | 磁盘满/权限拒绝/IO 异常（bounded：仅异常类型与 errno 级元数据） | 稳定失败；不回显日志原文 |
| `INTERNAL_STORAGE_ERROR` | 不可预期异常兜底（bounded：仅异常类型） | 稳定失败；不回显内容 |

契约层 `ContractError`（如 decode 时的 DIGEST_MISMATCH）在 get 路径被映射为上表对应存储错误
（G3 阶段的契约 digest 失败→`BLOB_CORRUPT`/`METADATA_CORRUPT`），不把原始异常文本透传给业务。
所有错误信息只含：code、field 级定位、`{"limit","actual","privacy_code","exception_type"}` 式
bounded 元数据——**无日志正文、无 tenant_key/token/Secret、无主机绝对路径**（条款 11）。

### 6.2 权限校验入口

两处强制：metadata 查询（G1/G2，租户等值过滤在 SQL 谓词中）与读取入口（G3 实物核验）。ref 自带
tenant 与调用者传入字符串均不作为身份认证依据（§4.5）。

## 7. 预算与资源（Assignment §7 条款 10、17、18、19、20）

### 7.1 预算数值表（默认值 + 合法域 + 来源）

| 预算 | 默认 | 合法域（open 时可调范围） | 来源/依据 |
|---|---|---|---|
| 单条日志输入 UTF-8 字节 `max_input_bytes` | 262,144 | [1, 262,144] | `min(PrivacyLimits.max_string_bytes, ContractLimits.max_string_bytes)`=256 KiB（取交集，**不得扩大**） |
| 净化后封存字节 `max_sealed_bytes` | 262,144 | [0, 262,144] | 同上交集（净化可能改变字节数：span 替换为 45 字符占位符，probe P4.1d）。注脚：**预算内输入可能因净化占位符膨胀触发本预算**——ER 对抗探针实测 262,119 B 输入膨胀至 365,378 B → `SEALED_BUDGET_EXCEEDED`（稳定失败、无数据丢失、无降级；ERR-IP-0044-D1-v1 SF-07） |
| envelope wire 字节 `max_envelope_bytes` | 1,048,576 | 固定 | `ContractLimits.max_input_bytes`（encode_envelope 上限） |
| blob 对象数 `max_blob_objects` | 10,000 | [1, 1,000,000] | 首片新存储预算（合法域内 operator 可调） |
| 并发 live staging `max_live_staging` | 256 | [1, 10,000] | 首片新存储预算 |
| 总容量 `max_total_blob_bytes`（**含 staging/orphan/quarantine**） | 512 MiB | [1 MiB, 64 GiB] | 首片新存储预算；计入所有占用，空日志不绕对象数、并发不绕额度 |
| 并发 seal `max_concurrent_seals` | 8 | [1, 64] | 首片新存储预算 |
| 单次 get 读放大 `max_read_bytes_per_get` | = max_sealed_bytes + max_envelope_bytes | 随前两者 | 有界读取；无公共 list 接口，inspect 为 operator 诊断、受对象数上界约束 |

预算检查分两层（条款 10）：**输入预算**（S0，对原始 text 的 UTF-8 字节数）与**净化后字节预算**
（S4，对 staged 净化字节）分别执行，大小一律按 UTF-8 字节数（**设计探针实测（probe P4.2）**：
1 emoji=1 字符/4 字节、6 CJK 字符=18 字节、100 emoji=100 字符/400 字节——字符计数与字节计数必
须分离）。默认限额触发实例实测：262,145 字节 → `MAX_STRING_LENGTH_EXCEEDED {limit:262144,
actual:262145}`（probe P4.1）。容量不足拒绝新写（`CAPACITY_EXCEEDED`）：不无限积累、不自动清理
活对象、不 fallback 到旧 task report_json、不回退 inline。既有 privacy/codec 限制零扩大。

### 7.2 路径与键（条款 18）

- 存储键全部系统生成：`blobs/<tenant_id>/<d[:2]>/<d>/blob.bin`、`staging/<staging_id>/content.bin`、
  `quarantine/…`、`metadata.sqlite3`；API 面无任何调用者路径参数。
- tenant_id 受契约 identifier pattern 约束（首字符必为字母数字，`/`、纯 `..` 不可构造），仍执行
  防御性终点校验：每次 IO 前 `Path.resolve()` 结果必须 `is_relative_to(root.resolve())`，否则
  `PATH_POLICY_VIOLATION`。Windows 文件名规范化声明：identifier 允许的 `:` 在 Win32 路径语义下
  触发 OSError → `IO_ERROR` fail-closed（无逃逸）；尾随 `.`/空格的名称规范化混叠仅致**同 digest
  同字节**的 blob 目录混叠、无跨租户信息泄露（D2 路径组测试覆盖；见 ERR-IP-0044-D1-v1 SF-04）。
- symlink/junction/hardlink：发布/读取路径上的符号链接与 junction 拒绝（Linux `O_NOFOLLOW` 等
  价语义；Windows 显式 reparse-point 检查）；发布使用同目录临时文件 + `os.replace` 原子改名（同
  卷原子）；blob 发布后只读打开。hardlink 到同内容 blob 文件无害（内容寻址）；威胁是替换，由上
  述独占创建/只读打开缓解。
- 受控 root：`root/` 与子目录以最小权限创建（POSIX 0o700；Windows 继承 ACL 并声明限制）。
  **不声称防御同等 OS 权限的恶意本机用户**（条款 18 末句）。

### 7.3 SQLite schema（条款 19）

- 文件：`root/metadata.sqlite3`；`PRAGMA journal_mode=WAL`、`busy_timeout=10000`、
  `foreign_keys=ON`（参考 `TaskStore` 连接纪律：每操作一连接、异常回滚、finally close）。
- 版本化：`PRAGMA user_version=1`（本片唯一版本）；初始建表在**单事务**内执行
  `CREATE TABLE IF NOT EXISTS artifacts / seal_attempts / artifact_store_meta`（幂等、可重开；
  模式参考 `TaskStore._init`，只读借鉴）。不建跨数据库迁移框架（FR-05 归后续片）。
- 表结构（实现细节，P&V 自决、D2/IMPL 可微调列组织，但下列语义列与唯一约束冻结）：
  `artifacts(artifact_id PK, tenant_id, task_id, workflow_id, stage_attempt_id,
  repository_snapshot_digest, schema_name, schema_version, producer, policy_digest,
  toolchain_digest, content_digest, blob_id, size_bytes, media_type, classification,
  retention_class, created_at, sealed_at, state, envelope_wire TEXT)`；
  `seal_attempts(staging_id PK, artifact_id, tenant_id, stage_attempt_id, state, created_at,
  updated_at, blob_id, content_digest)`；`artifact_store_meta(key PK, value)`。
  所有查询以 `tenant_id = <store 绑定租户>` 为谓词（G1）。
- `envelope_wire` 存 `encode_envelope` 的 canonical JSON 文本（envelope 本身无日志正文）。

### 7.4 崩溃/重启验证与平台分层声明（条款 20）

- 验证方式：**真实子进程 + 真 kill**（非模拟）：测试在子进程内于各协议步（S3 后/P1 前/P1 后/P2
  前/P2 后）设置标记文件，父进程观测标记后调用 `subprocess.Popen.kill()`（Windows=
  TerminateProcess；Linux=SIGKILL）终止，再以**新进程**重开 root/SQLite 断言 §4.3 矩阵。
- 持久化分层声明：本片验证与保证**进程崩溃**层面（进程死、OS 活）；API 边界 fsync（文件级
  `os.fsync`；Linux 目录 fsync；Windows 无目录 fsync API，仅文件级）尽力缩小 OS 缓存窗口；
  **不声称**文件系统/物理断电层面的跨平台原子性或持久性证明。Windows 与 Linux 都必须实际运行
  kill/重启验收（缺平台保留实际缺口，不以 skip 冒充通过）。

## 8. 测试方法与最小覆盖数 + 独立 Oracle（对齐说明书 §7 七组）

**D2 才冻结实际测试文件名/符号/计数**；本节冻结方法族与最小覆盖数（合计 35 个测试方法，符合
P&V 冻结预算上限）。探针/本表 PASS 均不构成产品实现证据。

| 组（说明书 §7） | 方法族 | 最小数 | 必含反例 |
|---|---|---|---|
| 隐私 | 真实 storage policy 净化；磁盘/DB/错误信息中无 raw Secret（含 SQLite 全文扫描）；缺 key/policy、净化失败、UNSUPPORTED_REDACTED_FORM 时零内容写入（目录快照对比） | 5 | FingerprintRecord 形态拒绝且零落盘 |
| 真实闭环 | 同进程 stage→seal→get；**新进程**重开 root/SQLite 读回同字节；独立 digest 复算；envelope/blob_ref/reference 三方绑定校验 | 4 | 字节级全等断言（非仅 digest 相等） |
| 权限与输入 | 错租户（== NOT_FOUND 不可区分）、错 type/version、非空 lineage/supersedes、未封送 id、缺失/损坏 blob 拒绝；拒绝不泄露他租户 | 6 | 伪造 ref / 篡改 wire digest |
| 不可变与重试 | 同 handle 重复 seal 幂等；并发 seal（线程/进程）单胜者；同字节不同 staging → 不同 artifact_id 同 blob；METADATA_CONFLICT 不覆盖 | 4 | 并发窗口内无双重提交 |
| 故障与恢复 | 真子进程 kill 于 S3 后/P1 前/P1 后/P2 前/P2 后五点（两平台）；重启诊断分类正确；部分/缺失内容不作为成功返回 | 6 | 无假 SEALED 断言 |
| 资源与路径 | 0-byte、Unicode 字节边界（单 emoji/多字节）、输入超限、净化后超限、对象数/总容量（含 staging/orphan 计入）、并发额度、路径穿越/symlink 拒绝、满盘/权限（模拟注入） | 6 | 空对象不绕对象数；失败不变空成功 |
| 持久化边界 | SQLite 无日志正文/凭据（全库扫描）；metadata/ref 有界；store 不可用无 inline/旧 report_json 降级；contracts/privacy 既有测试回归 + #60 面零触碰 | 4 | 契约兼容（import 面/wire 面） |

**独立 Oracle 要求**（D2 交付，禁止复用被测实现路径）：
1. digest 复算：`hashlib.sha256(sealed_bytes).hexdigest()` 直接计算，不经 `lima` codec；
2. 绑定校验：独立 JSON 遍历 envelope wire dict，验证 `content_digest==blob_ref.content_digest`、
   size、media type、schema 身份（不经 `decode_envelope`）；
3. 重启复读：独立子进程读文件字节做全等比较（不经 `get_log`）；
4. kill 时序：父进程独立观测标记文件（不在子进程内自证）。

## 9. Traceability

### 9.1 #66 requirement ID 逐行映射（18 ID；**无一条 SATISFIED**——D1 零产品证据；状态语义：
PARTIAL=本片冻结其中本机 SQLite/日志子集行为、余下归后续片与 D2+ 证据；DESIGN-ONLY=本片仅设计
层冻结、实现证据归后续；NOT-COVERED=本片不做）

| ID | 状态 | 本片贡献与理由 | 下一 Owner |
|---|---|---|---|
| FR-01 | PARTIAL | stage 仅建 attempt-scoped handle（净化已完成、staging 只含净化内容）；seal 在 size/type/schema/digest 全过后返回 immutable ref | 后续片扩展非日志类型 |
| FR-02 | PARTIAL | 状态机实现 STAGING→SEALED 子集（QUARANTINED/EXPIRED/DELETING 不出现、corruption 不改状态）；SEALED 内容/身份绑定无任何覆盖路径 | 后续片补 QUARANTINED/EXPIRED 转移与 ACL 面 |
| FR-03 | PARTIAL | 提交点协议（§4.2）明确 crash points；`inspect` 输出 staging/orphan/metadata-only/corrupt 四类；不静默伪造内容 | 后续片补 expired-with-reference 分类与自动 reconcile |
| FR-04 | PARTIAL | get 强制 tenant/type/schema/digest（G1–G3）；租户不符不可区分拒绝；本片无 lineage 查询（空 lineage only，非空拒绝） | 后续片补 list_lineage/DAG/自环跨租户边 |
| FR-05 | NOT-COVERED | 本片仅版本化幂等建表（PRAGMA user_version+单事务 IF NOT EXISTS），非 migration registry；#67/#65 入口不存在 | 后续片（migration registry slice） |
| FR-06 | NOT-COVERED | 无 retention/pin/删除接口（首片无公共 delete/update）；容量满拒绝新写而非清理 | 后续片（retention slice） |
| NFR-01 | PARTIAL | 0-byte 到上限可验证（探针 P4.2a 实测 0-byte 路径）；超限落盘前终止（双预算）；路径/symlink/junction 防护（§7.2）；case collision 由内容寻址键 + 大小写保持文件系统声明覆盖 | 后续片补满盘演练平台面 |
| NFR-02 | PARTIAL | Blob IO 与 SQLite metadata 分离、业务仅 ref/字节/错误；本片仅本地 backend、不写 S3 SDK/配置框架；S3-compatible Port 语义由行为契约保证 | 后续片（S3 adapter） |
| AC-01/T-01 | PARTIAL | §4.3 矩阵 + §8 故障组（五 kill 点、两平台、真子进程）；无假 SEALED 断言 | D2+ 实证 |
| AC-02/T-02 | PARTIAL | 同 handle 幂等、并发 seal 单胜者、租户隔离、无 ACL 放宽面（§4.4）；同字节≠同身份 | D2+ 实证 |
| AC-03/T-03 | PARTIAL | corrupt/missing blob、路径逃逸 fail closed 且 metadata 不丢（§6.1）；lineage 自环由契约层拒绝（源码复核：common.py `LINEAGE_SELF_REFERENCE`）、跨租户由契约层拒绝（探针 P3-B）+ 本片空 lineage only；Redis 不在链路（本片无 Redis 依赖，天然不丢事实） | D2+ 实证 |
| V5-FR-01 | PARTIAL | 新增 artifact 路径只存 metadata+blob ref（envelope_wire 无正文，§7.3）；**历史 report_json 迁移不在本片**（#66 仍是唯一迁移 Owner） | 后续片（迁移 slice） |
| V5-FR-02 | DESIGN-ONLY | seal 前强制 #94 policy 冻结于协议 S1（前置任何持久化；探针 P1 实测真实调用面）；实现证据归 D2+/IMPL | IMPL |
| V5-FR-03 | PARTIAL | digest verification 冻结为 G3 必检（探针 P3-A 证明不可省略）；retention class 校验接受面；lineage query/tombstone 未实现（明确拒绝非空 lineage） | 后续片 |
| V5-FR-04 | DESIGN-ONLY | 无 inline 降级路径冻结于错误语义（CAPACITY_EXCEEDED/IO_ERROR 均拒绝，绝不回退 inline 巨型 JSON/旧 report_json）；实现证据归后续 | IMPL |
| V5-AC-01/V5-T-01 | PARTIAL | DB 只存 metadata/blob ref + seal 前强制 #94 + 不内联（§4.2/§7.3/§8 持久化边界组） | D2+ 实证 |
| V5-AC-02/V5-T-02 | PARTIAL | digest verify、跨 tenant/type mismatch 按契约工作（§6.1）；retention/tombstone/lineage query 未覆盖 | 后续片 |
| V5-AC-03/V5-T-03 | PARTIAL | blob/store 中断、partial write、重复 seal 可恢复且不返回未封存 Artifact（§4.3 矩阵 + §8） | D2+ 实证 |

分布统计：PARTIAL 14；NOT-COVERED 2（FR-05/06）；DESIGN-ONLY 2（V5-FR-02/04）；SATISFIED 0。

### 9.2 Assignment §7 条款 1–20 覆盖索引

| 条款 | 冻结位置 | 条款 | 冻结位置 |
|---|---|---|---|
| 1（类型身份） | §4.1 表 | 11（不持久化敏感物） | §6.1 错误面 + §7.3 |
| 2（复用契约） | §4.1 wire 行 | 12（stage/seal/get+入口） | §4.2、§5.3、`demo.py` |
| 3（digest 来源） | §4.1 digest 行（探针 P2） | 13（信任边界） | §4.5、§6.2 |
| 4（真实上下文） | §4.1 上下文行 | 14（身份/幂等/并发） | §4.4 |
| 5（lineage 空集） | §4.1 lineage 行（探针 P3-C） | 15（提交点协议+处置） | §4.2（DR-PACKET-1） |
| 6（classification 相容） | §4.1 接受面行（探针 P1） | 16（故障点矩阵） | §4.3 |
| 7（真实净化调用） | §4.2 S1（探针 P1） | 17（资源上限） | §7.1 |
| 8（失败零落盘） | §4.2 S2、§6.1 | 18（路径与键） | §7.2 |
| 9（str-only 接受面） | §4.1/§6.1（探针 P1） | 19（SQLite schema） | §7.3 |
| 10（双预算） | §7.1（探针 P4） | 20（崩溃/重启验证） | §7.4 |

## 10. 平台命令骨架（实际命令面 D2 冻结；此处冻结骨架与平台义务）

**基线（合并前基线健康，两平台同）**

```bash
git fetch origin && git rev-parse origin/main        # 基线 SHA 声明
python -m compileall -q lima tests
python -m unittest discover -s tests -v              # 既有套件全绿（contracts/privacy/audit/#60 面零回归）
```

**slice（本片验收面）**

```bash
python -m unittest discover -s tests/artifacts -v   # D2 冻结的测试集
python -m ruff check lima/artifacts tests/artifacts
python -m bandit -q lima/artifacts
```

**integration（真实闭环示例）**

```bash
python -m lima.artifacts.demo --root "$TMP/ip0044-demo"   # 进程内闭环 + 子进程重开 + 独立 digest 复算
```

**boundary（文件边界 gate）**

```bash
git diff --name-only <base>..HEAD                    # 只允许 lima/artifacts/** 与 tests/artifacts/**（实现期）
git diff --check
```

**compatibility（契约兼容）**

```bash
python -m unittest discover -s tests -v              # 含既有 contracts/privacy 测试
python - <<'PY'
import lima.contracts.common, lima.evidence_privacy.port  # import 面未变
PY
```

**kill/重启（真子进程；两平台各自运行，缺平台记实际缺口）**

```text
Windows（PowerShell/Git Bash）：
  python -m tests.artifacts.crash_harness --point post_publish --root <tmp>
    （父进程：subprocess.Popen(...); 观测标记文件; child.kill()/taskkill /PID <pid> /T /F;
      新进程重开 root/SQLite 断言 §4.3 矩阵）
Linux：同 harness，父进程 os.kill(pid, SIGKILL)；其余一致
```

**post-merge（合并后在最新 main）**

```bash
python -m unittest discover -s tests/artifacts -v && python -m unittest discover -s tests -v
python -m lima.artifacts.demo --root <fresh tmp>
```

### 10.1 D2 收敛义务（登记，不改本 Packet 冻结语义；来源 ERR-IP-0044-D1-v1）

以下三项经 ER 独立审阅登记为 D2 冻结测试/符号/文档时必须收敛的义务（均为 P3 文字/API 语义级，
不影响本 Packet 冻结协议与承重结论）：

1. **SF-05（abort 载体）**：`STAGING_STATE_INVALID` 的「已 abort」触发条件需要明确的 abort 载
   体——候选方案：`close()` 全量中止 live staging 并使 handle 失效；D2 Assignment 冻结为单值
   （或删除该触发条件）。
2. **SF-06（crash harness 命名统一）**：§10 kill 骨架的 `tests.artifacts.crash_harness` 模块名
   与 §5.1 测试命名面（`tests/artifacts/test_*.py`）须在 D2 冻结时统一（harness 可为测试辅助
   模块，但命名归属须单值）。
3. **SF-08（判空语义提示）**：`SealedLogArtifact.content` 为双语义（seal 恒 `b""`、get 返回已
   验证字节）——demo 与错误语义文档须提示调用方以 `envelope.blob_ref.size_bytes`（而非
   `content == b""`）判空，避免与合法 0-byte Artifact 混淆。

## 11. Decision Request 区（随 Packet 呈批）

1. **DR-PACKET-1（既有呈批项，Assignment §11.1 方向）**：提交点协议对 #66 原文
   「先写临时 blob→fsync/verify→事务写 SEALED metadata→原子 rename」的处置——本 Packet 采用
   保留全部元素、把原子 rename 前移到 metadata 事务之前的等价重排，并给出读者无不完整可见窗
   口的证明与覆盖范围声明（§4.2）。请 Maintainer 在本 Packet head 批准时一并裁定该处置。
2. 其余：无新增 DR。六类升 Maintainer 事项（跨租户共享/真实身份来源/删除合规/默认部署/公共
   Contract/Profile 来源身份）本轮均未触发；SQLite 内部表结构、文件组织、实现手段按
   Assignment §11.6 由责任角色在批准范围内自决。

## 12. 完成定义（Packet 完成本身，非产品完成）

本 Packet 视为完成，当且仅当：
1. 12 节齐备、20 条冻结项全部落地为可验证契约（§9.2 索引无空洞）、18-ID 映射表无 SATISFIED；
2. 无 TBD/多解；关键冻结值（schema name/version/media type、签名、错误码表、预算表、提交点协
   议、状态矩阵）均有源码复核或设计探针实测支撑并标注出处；
3. 设计探针 P1–P4 在 `.pv_tmp/issue66-local-log-2026-10-10/probes/` 留有输入/命令/输出/脚本，
   可复现，如实观察未被粉饰；
4. docs-only commit 落在 `codex/issue66-local-log-packet`（基点 `fbbbd619`），
   `git diff --name-only fbbbd619..HEAD` 仅本文一份新 md，工作树 clean，`git diff --check` 干净；
5. PR 呈审以具体 head 为准（`Related to #66`、无任何自动关闭关键字），停在审批点。

产品完成定义不在本文：需 D2 冻结测试 + 有效 RED + IMPL + 独立验证 + post-merge，且 #66 整体关闭
仍需完整 Closure Audit 与明确授权（首片完成 ≠ #66 DONE）。
