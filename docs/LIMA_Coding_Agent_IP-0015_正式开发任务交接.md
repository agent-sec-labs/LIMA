# LIMA Coding Agent IP-0015 正式开发任务交接（Feature Slice S1-Core：Evidence Privacy Core）

> 状态：等待 Packet 合并 + 冻结测试（阶段二）完成后，由 Coordinator 激活本交接书。冻结前本文件仅为框架与边界声明。
> 权威依据：`docs/LIMA_Implementation_Packet_IP-0015_Evidence_Privacy_Core.md`（下称 Packet）；裁定 COORD-IP94-R1。

## 1. 你要交付什么

- 在 `codex/ip-0015-implementation` 分支（自 Frozen Test Commit 创建）实现恰好 7 个新增产品文件：`lima/evidence_privacy/{__init__,errors,models,fingerprint,classifier,policy,port}.py`，符号清单以 Packet §7 为准，禁止改名/拆并/增删。
- 行为契约逐条按 Packet §8：统一入口 `sanitize_for_sink`、租户隔离 HMAC 指纹（域分隔串 + 16 字节截断 + 32 hex）、fail-closed 错误集（Packet §8.6 枚举值逐字冻结）、`PrivacyLimits` 骨架、policy digest 复用 `compute_content_digest`。
- 仅用标准库 + `lima.contracts.*`；零 IO、零网络、零全局状态。

## 2. 你不能做什么

- 不改 `lima/contracts/**`、`schemas/v4/**`、`tests/contracts/**`、`tests/evidence_privacy/**`、`docs/**`、`requirements*.txt`、`.github/**` 及任何既有产品文件（Packet §9 边界逐字有效）。
- 不做 vault、不做内容扫描全量、不做 sink 适配与生产接线、不建 `scripts/audit_sensitive_artifacts.py`（全部属 IP-0016/0017）。
- 不新建分类枚举/序列化/摘要规则；不改冻结测试；失败不得通过改测试消除。
- 不创建/合并 PR，不改 Issue #94 与 Ledger。

## 3. 关键技术口径（Packet §8 速览）

- 指纹：`HMAC-SHA256(derived_key, b"lima.evidence_privacy.fingerprint.v1\0" + NFC归一值字节)[:16].hex()`；`derived_key = HMAC-SHA256(tenant_key, b"lima.evidence_privacy.tenant-key.v1\0" + tenant_id)`。
- fail-closed 四类必拒：未知 sink / 缺 tenant key / 策略异常 / 超限（深度、大小、条目、时间）。
- 错误对象任何序列化形态不得含原值子串；NFC/NFD 同租户同指纹。

## 4. 流程（lifecycle §9.1/§12.2）

1. 从 Frozen Test Commit（SHA 由 Coordinator 在激活时提供）创建 `codex/ip-0015-implementation`；
2. 运行 Packet §11 全部 mandatory 命令（cwd = 你的交付 worktree 根）；
3. 交付 Final Implementation Commit + 按模板填写的 Completion Summary（Packet §14），停在 READY-FOR-VERIFICATION；PR 由 P&V 创建。

## 5. Completion Summary 必含

见 Packet §14 八项（Final SHA、追踪表、命令输出、digest 清单、边界确认、已知限制、follow-up、零 IO 确认）。

## 6. Stop Conditions

Packet §13 逐字有效；任何冻结面变更先经 Coordinator Decision Request。
