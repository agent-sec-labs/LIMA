# Erratum Note: DR-IP-0016-01（IP-0016 Packet v1 → v1.1）

- DR 编号：DR-IP-0016-01（P&V 阶段二中止时提交，2026-09-12）
- 裁定：Coordinator，2026-09-12，选项 A 采纳（Assignment `DR-IP-0016-01-EXEC/v1`，任务标识 `DR-IP-0016-01-EXEC`）
- 勘误对象：`docs/LIMA_Implementation_Packet_IP-0016_Repository_Profile_Layer1.md`（底本 main@`2124e9e4984a6d1c809aa3e82cf2cf28822abc25`，Packet v1）

## 1. 矛盾证据链（缺陷事实）

Packet v1 §6 D2 冻结记载："`policy_digest`/`toolchain_digest` 允许空串（`ArtifactEnvelope` 校验语义允许，阶段二以契约测试固化空串路径）"，且签名默认值为 `""`。实际契约语义与之矛盾：

1. `lima/contracts/common.py` L59：`_DIGEST_PATTERN: Final = re.compile(r"[0-9a-f]{64}")`——仅接受 64 位小写十六进制，空串必然失配；
2. 同文件 L150-156：`_validate_digest` 对失配值抛 `ContractError(ContractErrorCode.INVALID_FIELD_VALUE)`；
3. 同文件 L553-563：`ArtifactEnvelope.__post_init__` 对 `repository_snapshot_digest`/`policy_digest`/`toolchain_digest`/`content_digest` 统一走 `_validate_digest`，无空串豁免；
4. P&V 亲验探针（2026-09-12，worktree 根，Python 3.12.4）：以 `policy_digest=""` 构造 `ArtifactEnvelope` → `ContractError Contract field has an invalid value.`；
5. 契约基线：`python -m unittest discover -s tests/contracts -q` → `Ran 617 tests in 4.848s / OK`（exit 0），证明当前契约套件即语义真值，无待合的空串豁免变更。

推论：按 v1 条款固化的"空串路径"契约测试在任何符合 §5/§6 的实现下不可 GREEN（PI-DR2 不可达），构成 Packet §16 第 1 条 Stop Condition 意义上的冻结条款缺陷。

## 2. Coordinator 裁定文本（选项 A 采纳）

- 默认形态：保留关键字参数与默认值（不改为必填），默认值改为 sentinel digest `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`（= sha256(b"")）。
- 空串入参非法：传空串抛 `ContractError`，实现不做任何替换或纠正。
- 选项 B（实现内 sentinel 替换 + gap 声明）不采纳：与 D2/D7 fail-closed 文义冲突，引入静默纠正路径。
- 选项 C（#58 契约允许空串 digest）不采纳留档：涉及上游冻结契约变更，影响面最大，超出本 IP 边界。

### 转录勘误说明（执行时发现）

派发消息（`DR-IP-0016-01-EXEC/v1`）中给出的 sentinel 字符串为 `e3b0c44298fc1c149afbf4c8996fb924ca495991b7852b855`（49 个字符），既非 64-hex，也不等于裁定所锚定的 sha256(b"")。裁定文本自述"（= sha256(b\"\")）"，故裁定意图唯一对应的值为标准空摘要 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`（64-hex，P&V 与 Coordinator 均重算一致）。本勘误按后者执行；49 字符串判定为派发转录截断，如 Coordinator 对此有异议请按 Decision Request 流程回退本 commit。

## 3. v1 → v1.1 差异清单（逐条）

| # | 位置 | v1 | v1.1 | 对应裁定细则 |
|---|---|---|---|---|
| 1 | 头部版本区 | `IP-0016-PACKET/v1` | `IP-0016-PACKET/v1.1`，新增变更记录行 | e |
| 2 | §6 D2 `build_repository_profile` 行 | `policy_digest: str = "", toolchain_digest: str = ""` | 两默认值改为 sentinel `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | a |
| 3 | §6 表格后说明段 | "`policy_digest`/`toolchain_digest` 允许空串（`ArtifactEnvelope` 校验语义允许，阶段二以契约测试固化空串路径）" | 替换为 Coordinator 冻结措辞：必须 64-hex；缺省取 sentinel（sha256(b"")，语义『无策略/工具链摘要』）；传空串属非法入参抛 `ContractError`，不做任何替换或纠正 | b、c |
| 4 | §8 repository_kinds 段末 | 无 | 新增 DR-IP-0016-01 附带裁定：docs_content 路径验收测试允许以自定义 `extensions`（含 `.md`/`.rst`）构造 `RepositoryWorkspace`，属合法测试 arrange，不构成对 DEFAULT_EXTENSIONS 的修改 | f |

"空串"残留处理清单（细则 d）：全文 grep "空串" 在 v1 仅命中 §6 表格后说明段一处（旧语义），已随差异 #3 整体替换；v1.1 中新出现的"空串"字样（"传空串属非法入参""显式传空串"）均为新语义表述。§8/§13 无其他"空串"表述，无需处理。

不变量自查：需求映射（covered/not-covered）、§12 文件边界（product allowlist 两文件 + P&V 测试集）、§5/§7/§9/§10/§11 及 §8 其余冻结条款逐字未动。

## 4. 勘误后阶段二重启条件（PKT-IP-0016-D2R）

1. 本勘误 commit 合并进 `main`（Packet v1.1 成为 Contract 真值），Coordinator 标记 PACKET-MERGED(v1.1)；
2. P&V 按 v1.1 重新派发阶段二（Assignment 版本升级为 PKT-IP-0016-D2R 系），在 worktree 复核 Packet v1.1 文档 SHA-256 与基线；
3. 阶段二契约测试矩阵按 v1.1 §6 落两条用例：(a) 省略 policy_digest/toolchain_digest → envelope 字段值等于 sentinel；(b) 显式传空串 → `ContractError(INVALID_FIELD_VALUE)`；
4. 其余阶段二流程（PI-DR1..DR5、scratch GREEN、有效 RED、Frozen Test Commit）按 Packet §14 不变。
