# LIMA Coding Agent IP-0020 正式开发任务交接（框架）

> 状态：FRAMEWORK（Packet PR 合并后由 Coordinator 派发阶段二/三时补齐阶段特定字段；本文件当前版本随 Packet v1.0 一同评审）
> Assignment 依据：`IP-0020-PKT-P1/v1`（COORD-IP94-S3-ENTRY_RULING-2026-09-13 §D）
> 权威 Packet：`docs/LIMA_Implementation_Packet_IP-0020_Vault_Audit.md` v1.0（本交接书与其冲突时以 Packet 为准）

## 1. 任务定位

- IP-0020 = #94-S3（Vault/Audit，Feature Slice S3）；上游 IP-0015（e895079）+ IP-0017（dd32491）；统一开工基线 origin/main = Packet merge commit（起草时为 `dc6a50efd7b70f419883e66e334a782b9a84b6ba`，开工时以 `git rev-parse origin/main` 实测为准并记录）。
- 交付角色：vault port 默认 disabled 合同（不做存储实现）+ 历史 Artifact 只读审计（`audit.py` + `scripts/audit_sensitive_artifacts.py`）+ Security Boundary T1–T5 对应冻结断言。
- closure impact = **CLOSURE-CANDIDATE**：S3 完成 → #94 Registered IP = 3/3，但**不构成关闭许可**；G3 需 Maintainer 书面 sign-off，G4 Closure Audit 由 Coordinator 另行执行。
- 本 IP 不做：vault 存储后端、生产接线（#66/#68/#70）、删除/迁移执行、既有冻结面任何修改。

## 2. 阶段与授权（逐阶段另行派发，不得跨越）

| 阶段 | 执行者 | 分支 | 产出 | 止点 |
|---|---|---|---|---|
| 二、测试冻结 | P&V | `codex/ip-0020-frozen-tests` | 有效 RED + Frozen Test Commit（含 fixtures） | 输出冻结记录，不写产品代码 |
| 三、实现 | Implementation | `codex/ip-0020-implementation`（基线 = Frozen Test Commit） | Final Commit | Completion Summary（Packet §15 模板） |
| 独立验证 | P&V | 干净 worktree @ Final SHA | 满足/不满足/未验证 | 不做合并判断 |

## 3. 实现要点速览（详见 Packet §7/§8/§9）

1. **只新增 3 个产品文件**：`lima/evidence_privacy/vault_port.py`、`lima/evidence_privacy/audit.py`、`scripts/audit_sensitive_artifacts.py`（符号与签名冻结于 Packet §7.1）。
2. **既有 `lima/evidence_privacy/` 8 文件零修改**；`__init__.py` 的 `__all__` 保持 13 项（新符号经模块路径消费；扩 `__all__` 须先走 Packet §10 DR）。
3. **vault 合同**：默认 disabled、`VAULT_BACKEND_PORT_NAMES` 为空集 → 一切启用结构性 fail-closed；`acquire_vault_access` 本 IP 内 `NoReturn`；签名不收 secret 材料（Packet §8.1）。
4. **审计合同**：纯函数、value-free（无 preview/原值字段）、统一位置模型 `AuditLocation(source_path, field_path, span)`、报告携带 policy_version/policy_digest、`recommended_action` 为常量（Packet §8.2）。
5. **脚本红线**：只读打开扫描目录；stdout/stderr/报告零原值；报告输出路径不得落在扫描目录内；不 import 网络/DB/vault（Packet §8.3）。
6. **不可动**：13 冻结符号、12 枚举、五 SINK_KINDS、既有 154 用例、`scripts/` 既有脚本、`tests/contracts/**`。

## 4. 开工检查单（Implementation 阶段三）

- [ ] `git rev-parse origin/main` = Packet merge commit；`python -m pytest tests/contracts -q` = 617 passed；`python -m pytest tests/evidence_privacy -q` = 154 既有全绿 + 新套件 RED 状态确认（实现前必须 RED 可见，PI-DR4）。
- [ ] 通读 Packet v1.0 全文（尤其 §7.3 越界准绳、§8.1–8.3 契约、§9 Security Boundary T1–T5、§10 DR 边界、§14 Stop Conditions）。
- [ ] 双 runner 条款（PI-DR6-bis）：新测试 pytest 与 unittest discover 双可执行（Packet §11.5）。

## 5. 验收命令（cwd = 交付 worktree 根）

见 Packet §12 全表（baseline / slice-pytest / slice-unittest / regression / audit-script / audit-readonly / audit-report-output / vault-disabled / frozen-symbols / frozen-blobs / post-merge）。

## 6. Completion Summary 必含项

见 Packet §15 模板；另须声明：未启用 §10 DR 条款（或附 DR 授权记录）、未修改既有冻结测试与 8 个库文件（附 `git ls-tree` blob 对照）、T1–T5 逐项自查、`git diff --stat` 附上。

## 7. 停止条件

Packet §14 九条。任何停止：保留现场，产出 Decision Request（责任书格式），不猜测、不先行修改。
