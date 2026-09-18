# LIMA Coding Agent IP-0017 正式开发任务交接（框架）

> 状态：FRAMEWORK（Packet PR 合并后由 Coordinator 派发阶段二/三时补齐阶段特定字段；本文件当前版本随 Packet v1.0 一同评审）
> Assignment 依据：`IP-0017-PKT-P1/v1`（COORD-IP94-S2-ENTRY_RULING_2026-09-12 §D）
> 权威 Packet：`docs/LIMA_Implementation_Packet_IP-0017_Content_Conformance.md` v1.0（本交接书与其冲突时以 Packet 为准）

## 1. 任务定位

- IP-0017 = #94-S2（Content Conformance，Feature Slice S2）；上游 IP-0015（e895079）；统一开工基线 origin/main = Packet merge commit（起草时为 `fd219724076380448163d818f9ca26a3d5a5d945`，开工时以 `git rev-parse origin/main` 实测为准并记录）。
- 交付角色：在 IP-0015 冻结公共面之上补全 conformance 能力：D-1 循环引用 typed error、裸 Base64 细化（DR-IP-0015-02）、多内容形态适配（新增 `content_scan.py` + 既有 7 文件 Add-only 修改）、五 sink conformance、全量资源上限矩阵、API/export fixture 无泄漏。
- 本 IP 不做：vault port、历史只读审计、生产接线、UI fixture、审计侧 NFR-N05-04（归 #94-S3）。

## 2. 阶段与授权（逐阶段另行派发，不得跨越）

| 阶段 | 执行者 | 分支 | 产出 | 止点 |
|---|---|---|---|---|
| 二、测试冻结 | P&V | `codex/ip-0017-integration` | 有效 RED + Frozen Test Commit | 输出冻结记录，不写产品代码 |
| 三、实现 | Implementation | `codex/ip-0017-implementation`（基线 = Frozen Test Commit） | Final Commit | Completion Summary（Packet §14 模板） |
| 独立验证 | P&V | 干净 worktree @ Final SHA | 满足/不满足/未验证 | 不做合并判断 |

## 3. 实现要点速览（详见 Packet §7/§8）

1. **只新增 1 个产品文件**：`lima/evidence_privacy/content_scan.py`（符号清单冻结于 Packet §7.1）。
2. **既有 7 文件 Add-only**：`__init__.py` 零修改；`port.py`（D-1：环检测 + 栈安全）；`classifier.py`（base64 判定 + text 段落扫描挂载）；`errors.py`/`models.py`/`policy.py`/`fingerprint.py` 预期零修改（Add-only 增量须经 Packet §9.1 DR 条款授权）。
3. **不可动**：13 冻结符号签名、`__all__` 恰好集合、既有 12 枚举值、错误 str/repr 语义、`PrivacyLimits` 默认值、域分隔常量、`digest_source()` 字段序、既有 78 冻结用例与 `tests/contracts/**`。
4. **负例底线**：任何输入要么 `SanitizedPayload` 要么 `PrivacyError`；裸 `RecursionError` 逃逸即违规（Packet §8.3）。

## 4. 开工检查单（Implementation 阶段三）

- [ ] `git rev-parse origin/main` = Packet merge commit；`python -m pytest tests/contracts -q` = 617 passed；`python -m pytest tests/evidence_privacy -q` = 78 passed（既有）+ 新 conformance 套件 RED 状态确认（实现前必须 RED 可见，PI-DR4）。
- [ ] 通读 Packet v1.0 全文（尤其 §7.3 越界准绳、§8.3 D-1、§8.4 base64 谓词、§9.1 DR 边界、§13 Stop Conditions）。
- [ ] 双 runner 条款（PI-DR6-bis）：新测试 pytest 与 unittest discover 双可执行（Packet §10.4）。

## 5. 验收命令（cwd = 交付 worktree 根）

见 Packet §11 全表（baseline / slice-pytest / slice-unittest / regression / boundary-D1 / boundary-limits / frozen-symbols / enum / compatibility / post-merge）。

## 6. Completion Summary 必含项

见 Packet §14 模板；另须声明：未启用 §9.1 Add-only 后备（或附 DR 授权记录）、未修改既有冻结测试、`git diff --stat` 附上。

## 7. 停止条件

Packet §13 八条（裁定 §D 五条 + 冻结面变更需 DR + Add-only 后备需 DR + scratch 不可 GREEN 升级）。任何停止：保留现场，产出 Decision Request（责任书格式），不猜测、不先行修改。
