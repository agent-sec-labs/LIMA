# LIMA Implementation Packet — IP-0030 Baseline Fixture Family（基线数据 fixture 家族 + 注册表 + LlamaFactory 物化预检登记）

- Packet ID：IP-0030（Source Issue #219；Parent #57 PR3-c dataset-fixture slice）
- 依据：Coordinator Assignment CA-IP-0030-v1.0（2026-09-26，快轨 Intent+Coordinator 合并轮，一轮 Assignment 全裁定 R1-R12）；Intent Record INTENT-RECORD-IP-0030-2026-09-26（READY-FOR-COORDINATOR，同轮产出）
- 精确基线（Exact Baseline）：`58da3fc1c29317ca7c30fff6b8a33482832c234c`（= origin/main = PR #218 合并点 = IP-0029 post-merge PASS）
- 工作分支 / worktree：`codex/ip-0030-baseline-fixtures` @ `D:\BaseAIProject\LIMA-ip0030-wt`
- 授权：Maintainer 长程授权（2026-09-26；Operating Mode SHADOW；Execution Authorization: MAINTAINER_AUTHORIZED）
- 本 Packet 由 P&V 制作；shape 清单、fingerprint 算法、注册表 schema 与冻结文本、错误码逐字消息、公共符号面与签名、测试矩阵方法切分为 P&V 在 CA R1-R12 边界内的冻结细化（§7-§8；偏离本 Packet 冻结面 = Stop Condition 8）
- P&V 记录性裁定（不改产品语义的算术/ASCII/签名细化）见 §12 Decision Record；其中 DR-PV-1（test-heavy 文件数 14 对 CA 摘要列 13）需要 Coordinator 在激活实现前过目

## 0. 交付物角色声明（强制，先于一切）

本 Packet 是 IP-0030 的唯一实现依据。P&V 交付物恰为本 Packet 与冻结验收测试 `tests/test_v4_baseline_fixtures.py`（2 个 Add 路径，C1/C2）。实现交付物恰为 2 个 Add 路径：`benchmarks/v4/baseline/fixtures.py`（生成器模块，R1/R5/R6/R7/R9/R11 公共面）与 `evaluation_data/v4/fixture_registry.json`（由 `write_registry` 生成的注册表数据身份记录，12 条目）。本切片零 Modify：diff 恰 4 个 Add 路径；两 IP-0026 冻结 JSON blob（`7ecb39f82f0a03de84fb0881142c60059ddee30e` / `3ea94fcf6c49acf133245cef88e53d2734de71e6`）必须不变。任何超出 = Stop Condition。实现者不得修改本 Packet 与冻结测试；测试缺陷走 Decision Request（或一次性 ALLOWED_ONCE，§11）。**冻结测试只测行为与不变量，不锁定实现细节；fixture 树与注册表是 Implementation 的合法数据交付物（本 Packet 明确规定其生成来源），不属于"冻结验收面不可改"的范畴。**

## 1. 需求映射（Packet 头）

#219 "Scope (this slice)" 1-6 规范化为 FR-01..FR-06（语义不变，CA-IP-0030-v1.0）；AC 沿用 #219 原文 AC-1..AC-4。本 Packet 只声明本切片的贡献（fixture 存在 ≠ baseline 已跑；PR3-c 完成 ≠ #57 完成）。

| ID | #219 出处 | 本轮交付 | 验收承载 |
| --- | --- | --- | --- |
| FR-01 | Scope 1 | 空仓 fixture `archetype/empty-repository`：零文件空目录物化 + 注册表语义声明（无 .git 元数据、无 README 占位；fingerprint=空串哨兵） | TestFixtureMaterialization（empty 两方法）/ TestFailClosedNegatives（空仓伪装负例） |
| FR-02 | Scope 2 | 最小 Python 仓 fixture `archetype/minimal-python-repository`（3 文件最小可扫描结构） | TestFixtureMaterialization（结构精确性） |
| FR-03 | Scope 3 | 九类 V5 archetype fixture（application/library/cli/docs-content/test-heavy/monorepo/large-repo/malicious-layout/dependency-blocked），全部合成、自包含、离线确定性生成 | TestFixtureMaterialization + TestDeterminism + TestOfflineHygiene |
| FR-04 | Scope 4 | fixture 注册表 `evaluation_data/v4/fixture_registry.json`：12 条目（11 synthetic + 1 external-identity），schema 见 §7.7（R9 冻结） | TestRegistryContract + TestDeterminism（write_registry 字节稳定且等于在库工件） |
| FR-05 | Scope 5 | 支持矩阵一致性：两 IP-0026 JSON 零字节改动、gap 行如实保留；升级延后声明三落点（注册表自描述字段 + 本 Packet §7.7 + PR 正文冻结句 §7.8）；LlamaFactory 物化预检登记（不下载） | TestRegistryContract + TestLlamaFactoryIdentityRegistration + Done Commands 5/6/6b |
| FR-06 | Scope 6 | 测试：存在性/结构/确定性（两度生成字节一致）/fingerprint 重算/完整性/fail-closed 负例；全离线 | tests/test_v4_baseline_fixtures.py 全部 34 方法 |

**AC 映射**：AC-1（11 fixture 全部存在〔=shape+生成器+注册表在库〕、确定性生成、fingerprint 可重算）→ TestFixtureMaterialization + TestDeterminism；AC-2（注册表与支持矩阵一致更新；如实升级**或保留**，不虚构）→ TestRegistryContract + TestLlamaFactoryIdentityRegistration + R3 延后声明（§7.7）；AC-3（全离线、正例 + fail-closed 负例）→ TestFailClosedNegatives + TestOfflineHygiene；AC-4（六上游冻结面 213 方法〔70+33+28+26+27+29〕零改动）→ Done Commands 0/2/6/6b + diff 边界（命令 5）。

**Not-covered（本切片明确不处理，全团队不得扩张；= CA §Not-covered 1-8）**：
1. PR3-d：LlamaFactory 内容实际下载与真实扫描、cold/warm 真实对照、V5-AC-01 真实验收、真实 token/cost、evaluator 输出真实落盘与 CLI 接线、真实 run 预算上限数值（= 预留 Maintainer 决策）。
2. PR3-e：V5-AC-02/03、VEP/RVR/terminal outcome 扩展、支持矩阵行实际升级与再冻结（本切片只交付延后声明）。
3. 修改 `evaluation_data/v4/baseline_manifest.json`、`evaluation_data/v4/python_mvp_support_matrix.json`（IP-0026 冻结面）；合成 fixture 或 external 身份进入 manifest v1。
4. 修改扫描器/Prompt/标签/split/默认 analyzer/生产逻辑；`lima/**`、`scripts/**`；frozen holdout。
5. 修改 `benchmarks/v4/baseline/__init__.py`、`collect.py`、`run.py`、`orchestrate.py`、`report.py`、`expert_timing.py` 及 `benchmarks/__init__.py`、`benchmarks/v4/__init__.py`。
6. 六冻结测试文件（70+33+28+26+27+29=213）零改动零追加；提交任何 run 产物或物化 fixture 树（测试一律 tempfile/tempdir）。
7. 新依赖（psutil 等）、网络、Secret、付费 LLM；fixture 内容中任何真实下载行为。
8. #219/#57 关闭判断、#57 PR3 行勾选（合并后由 Coordinator 按证据推进，仅实际证明项）。

## 2. Design Input Manifest

| 输入 | 版本 / SHA | 消费方式 |
| --- | --- | --- |
| CA-IP-0030-v1.0 | `.pv_tmp/COORDINATOR_ASSIGNMENT_IP-0030_2026-09-26.md`（2026-09-26） | 范围权威；R1-R12 全文照录进 §13 |
| Intent Record INTENT-RECORD-IP-0030-2026-09-26 | `.pv_tmp/INTENT_RECORD_IP-0030_2026-09-26.md` | 需求语义 M1-M10/I1-I5/A1-A5/Q1-Q9 |
| Source Issue #219 | open，status:in-progress，作者 AttentionYourCode；2026-09-26 GitHub API 匿名只读亲验（CA §证据清单 2） | Scope 1-6 / Non-goals / AC-1..4 / Packet 占用 |
| Parent #57 | open；FR-06/V5-FR-01/V5-AC-01..03/PR 追踪表 | external 条目 needs-decision 纪律；九类 archetype 清单 |
| 六冻结测试文件 @58da3fc | test_v4_baseline `4cde7bdf0a76f56a2e1504483470dda4fbc3fef7`（70）/ test_v4_baseline_result `0a44cf7d41bee4756de966e77e88e5439ed386a5`（33）/ test_v4_baseline_manifest `8e8ab0dcb9fdea5a8b0a216610c5bd5dae2c92b9`（28）/ test_v4_baseline_collection `35e6ec6a497719be5495048600ea1db6802d9fc4`（27）/ test_v4_baseline_cli `edb2391bfcf3592739a3ac48e1fa5e9ddd752c60`（26）/ test_v4_baseline_report `b53176f5af0acf9322bfbaefd002612605fda4df`（29）＝ **213** | AC-4 回归基线（C2 冻结前 P&V 亲跑全绿）；测试风格镜像（`_forbidden_source_tokens` 拼接、deliverable-missing RED 锚点、subTest 组织） |
| IP-0026 两冻结 JSON @58da3fc | baseline_manifest.json blob `7ecb39f82f0a03de84fb0881142c60059ddee30e`；python_mvp_support_matrix.json blob `3ea94fcf6c49acf133245cef88e53d2734de71e6` | 只读不写不 import（R2 零消费）；blob 不变是合并门禁（Done Command 6b）；矩阵钉死断言 = R3 决定性依据 |
| tests/test_v4_baseline_manifest.py L78-84 / L486-571 / L639-651 @58da3fc | 同上 blob 8e8ab0dc | `_REQUIRED_GAP_CAPABILITY_KEYS` 三键、`test_llamafactory_gap_entry_is_unsupported_with_full_sha`、`test_registration_notes_cover_exactly_the_excluded_frozen_files`、`test_llamafactory_identity_absent_from_manifest_present_in_matrix`——注册表必须独立新文件的证据 |
| `lima/contracts/codec.py` @58da3fc | blob `a442076db6f193a3b362cc6caf6d53d4f76570b8` | `canonical_encode`（sorted-key/compact/UTF-8/无尾随换行/NFC）——注册表 JSON 写出的唯一 canonical 编码来源（R9；fixtures.py 唯一允许的产品 import）；测试侧独立复用同一冻结实现校验在库工件 |
| `benchmarks/v4/baseline/__init__.py` @58da3fc | blob `1c478346d7543f6c7f64d5d71081c612ca50fb55` | 零改动 marker；子模块直接导入先例（`benchmarks/__init__.py` `bc7e36cb1dbe56078d0a542717a5aba8080bb283` / `benchmarks/v4/__init__.py` `653d4db467eb2e0e26a0995a40ec6069521fc399` 同） |
| fixture 形态先例 @58da3fc | tests/audit/fixtures/golden_matrix/shapes.py blob `da43cbbf61080103f8a6738d1f5eda34a4ec8e2d`；tests/audit/fixtures/repo_shapes.py blob `4cf5b04b60d080a55be229f037aabe0c84f0c714` | dict 形状 + 按需物化形态（审计侧先例，独立家族不 import 不复制）；`_SENTINEL_EMPTY_DIGEST` 空树哨兵同款语义 |
| 错误族先例 | `lima/baseline_run_spec.py`（BaselineRunSpecErrorCode/BaselineRunSpecError + `_STABLE_MESSAGES` + `field_path`）；IP-0024/0025/0027/0029 同款 | §7.1 错误族形状与逐字消息风格 |
| 环境事实 @58da3fc | `.gitattributes` blob `9fbb7aff7aaf36c2d32a0fe9c15f06eaef1776b5`（`* text=auto eol=lf`）；`.github/workflows/ci.yml` blob `7d023925b8c21c79124d2101cb2dcddc37525a60`（quality-contracts 15min + unit 2OS×2py 25min）；pyproject.toml blob `c52d1dab873a6b9238d8956e7eb2d015f8dce4c0`（ruff E,F,I,B,UP,S ignore S101；line-length 100） | 显式 LF 字节写依据；CI 预算依据（R6）；ruff 门依据 |
| LlamaFactory 预检 | Coordinator 2026-09-26 独立复验（commit API 301→200、canonical=hiyouga/LlamaFactory、committer date 2026-08-27T10:50:56Z、codeload tarball HEAD 200、Apache-2.0） | R8 external 条目全部身份字段来源 |
| 格式先例 | docs/LIMA_Implementation_Packet_IP-0029_Baseline_Report_Projection.md @58da3fc blob `0efd28bf27764255148fa89db51a24e6e11fc6a2` | Packet 结构模板 |

哈希真值来源：`git ls-tree -r 58da3fc1c29317ca7c30fff6b8a33482832c234c -- <paths>`（P&V 2026-09-26 程序化复制，未手抄）。冻结前基线绿：P&V 在 C2 之前亲跑六冻结文件回归（Done Command 0）：`Ran 213 tests ... OK`（exit 0，2026-09-26，worktree @58da3fc）。

## 3. Explicitly Rejected Inputs

1. **静态 fixture 树整树入库**——被拒（R1）：确定性只能证明"提交字节没变"，无法证明复现性；305 文件大树违背连续四轮 ≤4 Add 路径的小 diff 纪律；`.gitattributes` eol 往返依赖显式字节写入消除。
2. **注册表进 baseline manifest v1**——被拒（R2 三条硬依据）：冻结测试断言 manifest 恰 3 数据集；条目契约要求 repository + 40 位 commit_sha（合成 fixture 无 pinned 公开 commit，注册即虚构数据源）；IP-0027 role 门消费 manifest，新条目改变冻结 wiring 输入。
3. **给 python_mvp_support_matrix.json 加 registry 注记 / 升级 gap 行**——被拒（R3 决定性依据）：`test_llamafactory_gap_entry_is_unsupported_with_full_sha` 钉死 level=="unsupported"；`_REQUIRED_GAP_CAPABILITY_KEYS` 钉死 gap 三行；`test_registration_notes_cover_exactly_the_excluded_frozen_files` 钉死 registration_notes 恰四文件。升级延后 PR3-e。
4. **注册表落位 benchmarks/ 下**——被拒（R2）：数据身份记录归 `evaluation_data/v4/`（IP-0026 先例）；PR3-e evidence 指针需仓库内可解析路径。
5. **空仓 README 占位 / 伪造 .git 目录**——被拒（R4）：非空伪装空仓正是 #219 负例语义；仓库内不可嵌套 git 元数据。
6. **malicious fixture 引用真实 CVE 编号、真实凭据、可达主机、可用载荷**——被拒（R7；测试负例承载 TestOfflineHygiene）。
7. **external 条目伪造 fingerprint / 在本切片下载任何 LlamaFactory 内容**——被拒（R8）：仓库内无其字节，任何 digest 都是伪造；fingerprint=null 是诚实缺席。
8. **fixtures.py 消费 manifest/矩阵（import 或读取）**——被拒（R2/R9）：注册表独立、零 wiring 改动；测试断言源零 manifest/matrix 引用。
9. **"物化到仓库内固定路径"的便捷入口**——被拒（R1 PR3-d 消费契约预留）：物化目标必须是调用方提供的空目录，防 run 产物入库。
10. **随机源 / 时钟源 / float / 新依赖 / 网络 / Secret**——被拒（R6/R9/AC-3）：确定性纪律与全离线边界。
11. **修改六冻结测试文件、两 IP-0026 JSON、任何既有 tracked 文件**——被拒（AC-4 / Do Not Touch）。
12. **"test-heavy 文件数上界 13"的字面读法**——被拒（DR-PV-1，§12）：与 CA R5 自身枚举（3 源文件 + 10 测试文件 + pytest.ini = 14）及 R10 冻结比值（测试:源 ≥ 10:3）矛盾；采枚举为准（14）。

## 4. Goal / Non-goals

**Goal**：交付全离线、合成自包含、确定性可复现的基线 fixture 家族与登记体系：11 个合成 fixture（空仓 + 最小 Python 仓 + 九类 V5 archetype）+ 1 条 LlamaFactory 物化预检登记（external-identity，不下载内容），全部登记进新注册表 `evaluation_data/v4/fixture_registry.json`；零字节改动 IP-0026 两冻结 JSON；为 PR3-d（真实重放/物化下载）与 PR3-e（V5 验收、矩阵行升级再冻结）提供数据基座。零修改任何既有 tracked 文件（本切片全 Add）。

**Non-goals**：见 §1 Not-covered（= CA §Not-covered 全文）。

## 5. 冻结接口消费清单（本轮只消费，零改动）

1. 两 IP-0026 JSON（blob 7ecb39f8/3ea94fcf @58da3fc）：只读不写不 import（R2 零消费）；blob 不变是合并门禁。
2. `lima.contracts.codec.canonical_encode`：注册表 JSON 写出的唯一 canonical 编码来源（R9；fixtures.py 唯一允许的产品 import；测试侧同源复用校验在库工件字节）。
3. `benchmarks/v4/baseline/__init__.py`（blob 1c478346）：零改动 marker；`benchmarks.v4.baseline.fixtures` 子模块直接导入。
4. 六冻结测试文件 213 方法（blob 4cde7bdf/0a44cf7d/8e8ab0dc/35e6ec6a/edb2391b/b53176f5）：零改动零追加；所有新测试进新文件 `tests/test_v4_baseline_fixtures.py`。
5. 空 digest 哨兵 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`（tests/audit/fixtures/repo_shapes.py `_SENTINEL_EMPTY_DIGEST` 先例）：empty fixture fingerprint 取同值（语义同源；测试侧以 `hashlib.sha256(b"").hexdigest()` 独立重算为 Oracle，不 import 该测试模块）。
6. #57 FR-06 身份字符串 `hiyouga/LLaMA-Factory` + `7fcf5b3b130e5713b52415bb7404c476fada9c8c`：external 条目逐字承载（含 canonical 双记，R8）。

## 6. 文件边界（= Assignment §Workspace Allowed Files，恰 4 路径，全部 Add；逐路径 git add）

**Add — P&V（C1/C2，本阶段交付）**：
1. `docs/LIMA_Implementation_Packet_IP-0030_Baseline_Fixture_Family.md`（本文档）。
2. `tests/test_v4_baseline_fixtures.py`（C2 冻结测试，unittest 风格，**34 方法 ≤ 35**，§8 矩阵）。

**Add — Implementation（C3+）**：
3. `benchmarks/v4/baseline/fixtures.py`——§7 公共面；shape 单一事实源、确定性物化（显式 LF 字节写）、fingerprint 计算/校验、注册表生成/加载校验、closed 错误族；禁止：网络、随机/时钟源、manifest/矩阵消费、float、改任何既有文件。
4. `evaluation_data/v4/fixture_registry.json`——由 `write_registry` 生成的注册表（12 条目，§7.7 schema；canonical JSON/LF）；提交的是生成产物，**生成命令与两度运行字节一致证据**须进 Completion Summary（`write_registry` 输出 == 在库字节，冻结测试 TestDeterminism 承载）。

**Do Not Touch（diff 必空）**：`lima/**`、`scripts/**`、`evaluation_data/v4/baseline_manifest.json`、`evaluation_data/v4/python_mvp_support_matrix.json`、`evaluation_data/**` 其余既有文件、`benchmarks/v4/baseline/__init__.py`、`collect.py`、`expert_timing.py`、`orchestrate.py`、`run.py`、`report.py`、`benchmarks/__init__.py`、`benchmarks/v4/__init__.py`、六冻结测试文件（零改动零追加）、`pyproject.toml`/`requirements.txt`/`.gitignore`/`.gitattributes`/`.github/**`、其余一切 tracked 文件；不提交任何物化 fixture 树 / run 产物（测试一律 tempfile/tempdir）。

## 7. 交付物规范（Implementation 必须满足的行为契约；公共符号面在此冻结）

### 7.0 模块落位与导入面（R1/R11 冻结 + DR-PV-3）

新文件 `benchmarks.v4.baseline.fixtures`，本切片唯一产品模块。包 `__init__.py` 零改动；消费面一律 `from benchmarks.v4.baseline import fixtures` / `import benchmarks.v4.baseline.fixtures` 直接导入子模块（marker 先例）。冻结测试对被测模块采用**惰性导入**（测试方法内导入），使模块缺席 RED 锚点逐用例可观察（tests/audit/fixtures 先例）。

**fixtures.py 导入白名单（冻结；冻结测试 AST 断言）**：
- stdlib 根：`dataclasses`、`enum`、`hashlib`、`json`、`pathlib`、`re`、`typing`。（CA R11 例示清单为 hashlib/json/pathlib/dataclasses/typing；`enum` 为 R11 自身封闭错误码族〔str, enum.Enum，IP-0024/0025/0027/0029 同款先例〕所必需，`re` 为 64/40-hex 形状校验所用——均为 stdlib，"仅 stdlib"语义不变；见 §12 DR-PV-3。）
- 产品：`lima.contracts.codec`（**唯一**允许的产品 import；仅用于 `canonical_encode`）。
- 禁止：相对导入（level>0）；`random`、`time`、`datetime`、`os`、`secrets`、`socket`、`urllib`、`requests` 及一切网络/随机/时钟/环境模块（确定性纪律；冻结测试断言禁集与白名单双重）。
- fixture 内容字符串中的 `os.getenv(...)`、`subprocess`、`eval(`、`exec(`、`pickle.loads(` 等为**惰性文本**（永不执行的 shape 数据），不构成导入。

### 7.1 错误族（R11 + P&V 冻结逐字消息）

`BaselineFixtureError(ValueError)`：属性 `code: BaselineFixtureErrorCode`、`field_path: str`（structure-only 位置报告，如 `$.fixtures[3].fingerprint`）；渲染消息**恰为**下列目录条目，不嵌载荷、秘密、字段值、本机路径（IP-0024 风格）。`BaselineFixtureErrorCode(str, enum.Enum)` 成员名与 wire 值一致（`# noqa: UP042` 先例同款注释可选）。封闭码目录（6 码，逐字消息冻结）：

| code | message（逐字） |
| --- | --- |
| `UNKNOWN_FIXTURE_KEY` | `The requested fixture key is not part of the frozen baseline fixture family.` |
| `EXTERNAL_IDENTITY_NOT_MATERIALIZABLE` | `An external-identity registry entry has no materializable synthetic tree in this repository.` |
| `MATERIALIZE_TARGET_NOT_EMPTY` | `The materialization target directory is not empty.` |
| `MATERIALIZE_TARGET_UNAVAILABLE` | `The materialization target directory cannot be created or used.` |
| `FIXTURE_FINGERPRINT_MISMATCH` | `The materialized tree does not match the frozen fixture fingerprint.` |
| `INVALID_REGISTRY` | `The fixture registry document violates the frozen registry schema.` |

错误触发面（冻结）：
- `UNKNOWN_FIXTURE_KEY`：`materialize_fixture`/`verify_fixture` 收到不在 `FIXTURE_KEYS` 的键。
- `EXTERNAL_IDENTITY_NOT_MATERIALIZABLE`：`materialize_fixture`/`verify_fixture` 收到 `EXTERNAL_IDENTITY_KEYS` 中的键（external 条目无合成树）。
- `MATERIALIZE_TARGET_NOT_EMPTY`：物化目标目录已存在且含任何条目。
- `MATERIALIZE_TARGET_UNAVAILABLE`：目标存在但不是目录、或目录无法创建（含父路径不可创建）；`verify_fixture` 的 root 不存在或不是目录（防空仓假阳性：缺失目录不得按"零文件树"与空哨兵相等——DR-PV-5）。
- `FIXTURE_FINGERPRINT_MISMATCH`：`verify_fixture` 重算 fingerprint ≠ 该键 shape 的冻结 fingerprint（内容漂移、缺文件、多文件均触发；比较目标为模块内 shape 推导值，与注册表值同源）。
- `INVALID_REGISTRY`：`load_registry` 的任何失败——文件缺失/不可读、JSON 解析失败、**重复对象键**（必须以 duplicate-key 检测解析，不得静默取后者）、顶层/条目字段缺失或未知、键集 ≠ `FIXTURE_KEYS`（含重复键）、synthetic fingerprint 非 64 位小写 hex、external fingerprint 非 null、`file_count`/`declared_size_bytes` 非非负 int（bool 排除）。

### 7.2 公共符号面与签名（R11 + P&V 冻结）

`fixtures.__all__` 恰为下列 9 名（字母序）：

```python
__all__ = [
    "EXTERNAL_IDENTITY_KEYS",
    "FIXTURE_KEYS",
    "SYNTHETIC_FIXTURE_KEYS",
    "compute_tree_fingerprint",
    "load_registry",
    "materialize_fixture",
    "registry_relative_path",
    "verify_fixture",
    "write_registry",
]
```

模块内公开可导入但不在 `__all__`（R11 未列，测试直接 import）：`BaselineFixtureError`、`BaselineFixtureErrorCode`、`FixtureMaterialization`。

签名与语义（冻结）：

```python
FIXTURE_KEYS: Final[tuple[str, ...]]            # 12 键，冻结顺序（下）
SYNTHETIC_FIXTURE_KEYS: Final[tuple[str, ...]]  # 前 11 键
EXTERNAL_IDENTITY_KEYS: Final[tuple[str, ...]]  # ("external/llamafactory-replay",)
registry_relative_path: Final[str]              # "evaluation_data/v4/fixture_registry.json"

@dataclass(frozen=True, slots=True)
class FixtureMaterialization:
    key: str            # 请求键
    root: pathlib.Path  # 解析后的绝对目标路径
    file_count: int     # 物化常规文件数（empty=0）
    size_bytes: int     # 全部文件字节之和（empty=0）
    fingerprint: str    # compute_tree fingerprint（empty=空树哨兵）

def materialize_fixture(key: str, target: pathlib.Path | str) -> FixtureMaterialization: ...
def compute_tree_fingerprint(root: pathlib.Path | str) -> str: ...
def verify_fixture(key: str, root: pathlib.Path | str) -> FixtureMaterialization: ...
def load_registry(path: pathlib.Path | str | None = None) -> dict: ...
def write_registry(path: pathlib.Path | str) -> bytes: ...
```

**`FIXTURE_KEYS` 冻结顺序**（= 注册表 `fixtures` 列表顺序）：
`archetype/empty-repository`、`archetype/minimal-python-repository`、`archetype/application`、`archetype/library`、`archetype/cli`、`archetype/docs-content`、`archetype/test-heavy`、`archetype/monorepo`、`archetype/large-repo`、`archetype/malicious-layout`、`archetype/dependency-blocked`、`external/llamafactory-replay`。

**`materialize_fixture`**：键校验（UNKNOWN/EXTERNAL 两码）→ 目标解析（UNAVAILABLE/NOT_EMPTY 两码）→ 逐文件 `mkdir(parents=True, exist_ok=True)` 后 `write_bytes(content.encode("utf-8"))`（**显式 LF 字节写**，shape 文本只含 `\n`；与 git 归一化无关）→ 返回 `FixtureMaterialization`（fingerprint 由物化树现算）。empty shape：仅创建目标目录本身（零文件）。不提供"物化到仓库内固定路径"的便捷入口（R1）。

**`verify_fixture`**：fail-closed——键校验同上；root 必须是存在目录（否则 UNAVAILABLE）；重算树 fingerprint 与该键 shape 冻结 fingerprint 比较，不一致抛 `FIXTURE_FINGERPRINT_MISMATCH`；一致返回重算的 `FixtureMaterialization`。**不返回 bool**。

**`load_registry`**：零参调用读 `<repo_root>/evaluation_data/v4/fixture_registry.json`，`<repo_root>` 锚定为模块文件 `pathlib.Path(__file__).resolve().parents[3]`；可选 `path` 参数供注入畸形注册表的负例测试（R10"对 load_registry 注入"；DR-PV-4）。任何读取/解析/校验失败 → `INVALID_REGISTRY`（§7.1）。成功返回校验后的顶层 dict。

**`write_registry`**：从模块内 shape 与 external 条目构造 12 条目文档（§7.7），`lima.contracts.codec.canonical_encode` 编码为 canonical 字节（UTF-8、sorted-key、compact、无 BOM、无尾随换行），`write_bytes` 写入 `path`，返回所写字节。synthetic 条目的 `fingerprint` 由 shape 映射直接按 §7.3 算法计算（与物化树重算值不变量相等）。

### 7.3 fingerprint 算法（R9 冻结）

`compute_tree_fingerprint(root)`：

1. `root = pathlib.Path(root)`；枚举 root 下所有**常规文件**（`rglob("*")` 且 `is_file()`；物化树无符号链接/非常规文件）。
2. 每文件取相对路径的 POSIX 形式：`f.relative_to(root).as_posix()`（平台无关，Windows 上同为 `/` 分隔）。
3. 相对路径字符串集合按字典序升序排序（纯 ASCII 路径，Python `sorted` 语义冻结）。
4. 摘要输入 = 依序拼接每个文件：`path.encode("utf-8") + b"\x00" + 文件内容字节 + b"\x00"`。
5. 返回 `hashlib.sha256(摘要输入).hexdigest()`（小写 64-hex）。
6. **空树**（零文件）→ `sha256(b"")` = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`（R4 哨兵；tests/audit/fixtures/repo_shapes.py `_SENTINEL_EMPTY_DIGEST` 同值先例，不 import）。

不变量：shape 映射上按同算法直接计算的结果 == 物化树重算结果 == 注册表条目 `fingerprint`（测试三向对表承载）。

### 7.4 11 个合成 fixture 的逐文件冻结清单（R5 展开；P&V 逐字冻结）

**形态**：`fixtures.py` 内 `_SHAPES: dict[str, str 的映射]`——每键一个 `dict[str, str]`（POSIX 相对路径 → 全 ASCII/LF 文本内容），单一事实源；`materialize_fixture` 按字节显式 LF 物化（R1）。物化树不入库。**文件清单（路径集合）、文件数、结构/计数/关键 token 逐字冻结**；单个文件的字面措辞在满足关键 token 与计数约束下由 C3 定（内容契约 latitude）。**命名纪律（R5）**：一切包名/仓名用 `synth*` 前缀虚构名；不得出现真实公开仓名、真实组织名、真实 CVE 编号、真实内部域名、可访问 URL（唯一允许的主机形态为 RFC 2606 `.invalid` 域）；内容与 tests/audit/fixtures/golden_matrix/shapes.py 字节不同（独立家族，不 import 不复制）。**全部文件全 ASCII（字节值 ≤ 0x7F）、LF（无 `\r`）、无二进制**（测试逐文件断言）。

逐键规格（文件数列为**冻结精确值**；`文本:` 后为关键 token 契约）：

**`archetype/empty-repository`（0 文件）**：空 dict；物化=仅创建目标目录；fingerprint=空树哨兵。注册表 `notes` 见 §7.7（R4 语义声明）。

**`archetype/minimal-python-repository`（3 文件）**：
| 路径 | 内容契约 |
| --- | --- |
| `pyproject.toml` | 含 `[project]`、`name = "synth-minimal-pkg"`、`version = "0.1.0"` |
| `src/minimal_pkg/__init__.py` | 包标记（可为空或纯 docstring） |
| `src/minimal_pkg/core.py` | 恰一个纯函数 `def evaluate(value: int) -> int`，返回 `value + 1` 形状 |

**`archetype/application`（6 文件）**：
| 路径 | 内容契约 |
| --- | --- |
| `requirements.txt` | 恰两行 pin：`synth-web==1.0.0`、`synth-validation==0.4.0` |
| `pyproject.toml` | `[project]` + `name = "synth-app"` |
| `app.py` | `def main() -> int` + `if __name__ == "__main__":` 入口形状 |
| `synth_app/__init__.py` | 包标记 |
| `synth_app/api.py` | 一个路由装饰器形状：`@app.get("/health")` 装饰返回静态值的函数 |
| `synth_app/config.py` | 函数内 `os.getenv("SYNTH_APP_CONFIG")` 配置读取形状（惰性文本） |

**`archetype/library`（5 文件）**：
| 路径 | 内容契约 |
| --- | --- |
| `setup.cfg` | `[metadata]` + `name = synth-lib` + `version = 1.0.0` |
| `synth_lib/__init__.py` | 包标记 |
| `synth_lib/core.py` | 一个纯函数 `def compute(value: int) -> int` |
| `synth_lib/loader.py` | `import pickle` + 惰性 `def load(payload: bytes)` 返回 `pickle.loads(payload)` 形状 |
| `README.md` | `# synth-lib` 标题 + 一句说明 |

**`archetype/cli`（4 文件）**：
| 路径 | 内容契约 |
| --- | --- |
| `synth_cli/__main__.py` | `if __name__ == "__main__":` + argparse 入口调用形状 |
| `synth_cli/main.py` | `def build_parser()`（`argparse.ArgumentParser(prog="synth-cli")`）+ 子命令分发函数 |
| `synth_cli/commands.py` | ≥1 个子命令处理函数 |
| `pyproject.toml` | 含 `[project.scripts]` 段（`synth-cli` 控制台入口声明） |

**`archetype/docs-content`（6 文件）**：
| 路径 | 内容契约 |
| --- | --- |
| `README.md` | `# synth-docs` |
| `mkdocs.yml` | `site_name: synth-docs` + 列出三页 docs 的 nav |
| `docs/index.md` / `docs/guide.md` / `docs/reference.md` | 短 markdown 文档（各 ≥1 标题） |
| `tools/build_docs.py` | 平凡纯函数 `def build() -> str` 返回常量（文档占多数、Python 极少数的覆盖形态） |

**`archetype/test-heavy`（14 文件；DR-PV-1）**：
| 路径 | 内容契约 |
| --- | --- |
| `src/synth_core/__init__.py` | 包标记 |
| `src/synth_core/logic.py` | `def combine(left: int, right: int) -> int` 纯函数 |
| `src/synth_core/store.py` | `class InMemoryStore`（纯 dict get/set 方法） |
| `tests/` 下恰 10 个 `test_*.py`：`test_logic.py`、`test_store.py`、`test_logic_edges.py`、`test_store_edges.py`、`test_logic_props.py`、`test_store_props.py`、`test_logic_errors.py`、`test_store_errors.py`、`test_integration.py`、`test_regression.py` | pytest 风格 `def test_*()` + 平凡 assert（惰性文本） |
| `pytest.ini` | `[pytest]` + `testpaths = tests` |

测试:源 = 10:3（R10 断言 ≥ 10:3）。文件总数 3+10+1 = **14**（CA R5 摘要列"13"为算术笔误——明细枚举与 10:3 比值优先；见 §12 DR-PV-1）。

**`archetype/monorepo`（11 文件）**：
| 路径 | 内容契约 |
| --- | --- |
| `pyproject.toml`（根） | 含 `workspace` 声明字样 |
| `README.md` | `# synth-monorepo` |
| `packages/alpha/pyproject.toml` | `name = "synth-alpha"` |
| `packages/alpha/alpha_pkg/__init__.py` + `packages/alpha/alpha_pkg/module.py` | 包标记 + 一个纯函数模块 |
| `packages/beta/pyproject.toml` | `name = "synth-beta"` |
| `packages/beta/beta_pkg/__init__.py` + `packages/beta/beta_pkg/module.py` | 同上 |
| `services/gateway/pyproject.toml` | `name = "synth-gateway"` |
| `services/gateway/gateway_pkg/__init__.py` + `services/gateway/gateway_pkg/module.py` | 同上 |

**`archetype/large-repo`（305 文件；R6）**：
| 路径 | 内容契约 |
| --- | --- |
| 根恰 5 文件：`README.md`（`# synth-bulk`）、`pyproject.toml`（`name = "synth-bulk"`）、`.gitignore`（含 `__pycache__/`）、`LICENSE.txt`（**明示合成占位、非真实许可授予**的短文本）、`Makefile`（一个 no-op `check:` 目标） | — |
| `synth_bulk/module_000.py` … `synth_bulk/module_299.py`（恰 300 个） | 索引模板：docstring `Synthetic bulk module {i:03d} ...` + 常量 `MODULE_INDEX = {i}` + 纯函数 `def scale_index(factor: int) -> int: return MODULE_INDEX * factor`（i = 0..299） |

边界（冻结）：文件数恰 305；全部文件总字节 ≤ **262144**（256KB）；生成=纯索引函数（无随机/环境/时间依赖）；单次物化墙钟 < 2s。

**`archetype/malicious-layout`（6 文件；R7）**：每文件**首行**为统一头注释（ASCII 形态，DR-PV-2）：
`# SYNTHETIC INERT BASELINE FIXTURE -- NOT A REAL VULNERABILITY`
| 路径 | 内容契约 |
| --- | --- |
| `setup.py` | `download_url` 声明形状（值指向 `.invalid` 域）+ 惰性 `exec(` 调用形状 |
| `synth_risk/paths.py` | `"../"` 穿越字符串拼接形状 |
| `synth_risk/eval_sample.py` | `eval(` 外部输入形状（变量承载，无真实可解载荷） |
| `synth_risk/shell.py` | `subprocess` + `shell=True` 用户输入形状 |
| `synth_risk/deser.py` | `pickle.loads(` 载荷形状 |
| `NOTICE.md` | 合成惰性声明（非真实漏洞、无真实目标） |

**`archetype/dependency-blocked`（4 文件）**：
| 路径 | 内容契约 |
| --- | --- |
| `requirements.txt` | 恰一行 `synth-internal-core==9.9.9`（不可解析 pin） |
| `pyproject.toml` | 含源 `git+https://git.internal.invalid/synth/pkg.git`（**RFC 2606 .invalid 域**） |
| `constraints.txt` | 含 `synth-internal-core==9.9.9` 约束行 |
| `src/synth_blocked/__init__.py` | 包标记 |

**冻结精确文件数表**（测试 `_EXPECTED_FILE_COUNTS` 同值）：empty 0 / minimal-python 3 / application 6 / library 5 / cli 4 / docs-content 6 / test-heavy 14 / monorepo 11 / large-repo 305 / malicious-layout 6 / dependency-blocked 4。

### 7.5 malicious 安全边界（R7 逐字）

**允许**：真实漏洞**模式**的合成文本形状——路径穿越字符串、`eval`/`exec` 调用形状、`subprocess shell=True` 形状、`pickle.loads` 形状、setup.py 下载执行声明形状——全部为**永不执行**的静态文本，带统一 SYNTHETIC INERT 头注释，仓库内无任何执行路径（fixture 文件不被 import、不进 pyproject 包发现范围——`[tool.setuptools.packages.find] include=["lima*"]` 已天然排除）。
**禁止**：真实 CVE 编号/真实漏洞利用文章文本；可用的完整利用载荷（shellcode、可复现的攻击链、可解出的恶意构造）；真实凭据/token/密钥字符串；任何指向真实主机的 URL/IP；真实项目路径。测试含禁止内容负例（TestOfflineHygiene：无 `CVE-`、无真实域、无 token 形状）。

### 7.6 注册表 schema 与冻结文本（R9/R3/R8 + P&V 逐字冻结）

**顶层字段恰 5**：`schema_version`（=1，int）、`registry_id`（="lima-baseline-fixture-registry"）、`relationship_to_support_matrix`（R3 冻结文本，下）、`offline_note`（冻结文本，下）、`fixtures`（12 条目列表，顺序 = `FIXTURE_KEYS`）。

**`relationship_to_support_matrix`（R3 冻结文本，逐字）**：

> This registry is intentionally decoupled from evaluation_data/v4/baseline_manifest.json and evaluation_data/v4/python_mvp_support_matrix.json: both files remain byte-identical to their IP-0026 frozen state because their content is pinned by the frozen acceptance tests tests/test_v4_baseline_manifest.py, so the matrix gap rows archetype/empty-repository, archetype/minimal-python-repository, and archetype/llamafactory-replay are honestly retained as unsupported. Upgrading those rows is deferred to #57 PR3-e, where it will land together with a new matrix version and a re-freeze of the matrix tests; nothing in this registry claims support levels for the matrix.

**`offline_note`（冻结文本，逐字）**：

> All synthetic fixtures in this registry are LIMA-authored, self-contained, and materialized deterministically offline by benchmarks/v4/baseline/fixtures.py: no network access, no secret, no paid model call, and no upstream repository content is involved. The single external-identity entry registers provenance metadata only and downloads nothing in this slice.

**synthetic 条目字段恰 10**（每条）：

| 字段 | 冻结值/形状 |
| --- | --- |
| `key` | 键名（11 synthetic 键之一） |
| `kind` | `"synthetic-fixture"` |
| `purpose` | `"baseline archetype: <短名>"`（短名 = 键去掉 `archetype/` 前缀；如 `baseline archetype: empty-repository`） |
| `origin` | `"synthetic-lima-authored"`（全集恰此值——反伪装身份字段） |
| `license` | `"Apache-2.0 (LIMA-authored synthetic content)"` |
| `generation` | `{"mode": "deterministic-script", "entrypoint": "benchmarks.v4.baseline.fixtures.materialize_fixture"}`（恰 2 键） |
| `fingerprint` | 64 位小写 hex（§7.3；empty=哨兵） |
| `file_count` | int ≥ 0（= §7.4 冻结精确值） |
| `declared_size_bytes` | int ≥ 0（= 全部文件内容字节和；empty=0） |
| `notes` | 非空 str（逐条冻结文本，下） |

**synthetic `notes` 逐字冻结文本**：
- empty-repository（R4 原文）：`zero-entry working-tree snapshot; no .git metadata (nested git repositories are not representable inside this repository); empty semantics asserted by zero materialized files`
- minimal-python-repository：`smallest scannable Python project: one packaging manifest plus one package holding one pure function`
- application：`application shape: two pinned dependency declarations, a main-entry module, one route-decorator module, and an os.getenv configuration read`
- library：`library shape: packaging metadata, a pure core module, a lazy pickle.loads loader sample, and a README`
- cli：`cli shape: argparse entrypoint, subcommand dispatch, and a [project.scripts] console entry`
- docs-content：`documentation-dominant shape: four markdown documents plus mkdocs.yml with one trivial Python doc builder`
- test-heavy：`test-dominant shape: ten test modules against three source modules plus pytest.ini (test-to-source ratio 10:3)`
- monorepo：`workspace shape: root workspace manifest and README with three subprojects (packages/alpha, packages/beta, services/gateway), each a packaging manifest plus a package with one module`
- large-repo：`bounded large-repository shape: 305 files (5 root files plus 300 synth_bulk modules), total bytes at most 262144, generated as pure functions of the module index`
- malicious-layout：`inert synthetic samples of vulnerable code patterns; every file carries the SYNTHETIC INERT BASELINE FIXTURE header and nothing in this fixture is executable evidence`
- dependency-blocked：`unresolvable-dependency shape: one unresolvable version pin and one RFC 2606 .invalid git source; no reachable host is referenced`

**external 条目字段恰 10**（R8 全集；`fingerprint` 允许 null 且**仅** external 允许 null）。external 条目全文（逐字冻结，canonical JSON 之外按字段呈现）：

```json
{
  "key": "external/llamafactory-replay",
  "kind": "external-identity",
  "identity": {
    "repository_requested": "hiyouga/LLaMA-Factory",
    "canonical_repository": "hiyouga/LlamaFactory",
    "commit_sha": "7fcf5b3b130e5713b52415bb7404c476fada9c8c"
  },
  "fetch": {
    "method": "codeload-tarball",
    "url": "https://codeload.github.com/hiyouga/LLaMA-Factory/tar.gz/7fcf5b3b130e5713b52415bb7404c476fada9c8c"
  },
  "precheck": {
    "date": "2026-09-26",
    "commit_api": "301-redirect-then-200 to hiyouga/LlamaFactory",
    "tarball_head": "200"
  },
  "license": "Apache-2.0 (upstream SPDX; hiyouga/LlamaFactory repository license)",
  "fingerprint": null,
  "fingerprint_note": "no content bytes exist in this repository; digest deferred to PR3-d materialization",
  "materialization": "deferred-to-PR3-d",
  "notes": "Identity registration only: this slice performs no download and this repository holds zero content bytes for this identity; the real run budget remains a reserved Maintainer decision. The fetch URL is recorded once under the requested repository name hiyouga/LLaMA-Factory; the equivalent canonical-name codeload URL (hiyouga/LlamaFactory at the same commit) is intentionally not duplicated here. If commit 7fcf5b3b130e5713b52415bb7404c476fada9c8c cannot be materialized at PR3-d execution time, #57 FR-06 requires escalating #57 to needs-decision; substituting the latest main branch or any moving ref is forbidden."
}
```

子对象键集冻结：`identity` 恰 `{repository_requested, canonical_repository, commit_sha}`（commit_sha 全 40 位小写 hex）；`fetch` 恰 `{method, url}`（注册表内唯一 URL——请求名 URL，canonical 等价性记于 notes 而不重复 URL）；`precheck` 恰 `{date, commit_api, tarball_head}`。`fingerprint` 恰 `null` + `fingerprint_note` 逐字；`materialization` 恰 `"deferred-to-PR3-d"`。**行为边界**：`materialize_fixture`/`verify_fixture` 对该键 fail-closed 抛 `EXTERNAL_IDENTITY_NOT_MATERIALIZABLE`；fixtures.py 全模块不含任何网络代码（hygiene 源扫描承载）。

**注册表写出**：`write_registry` 经 `lima.contracts.codec.canonical_encode`（唯一 canonical 来源；UTF-8、sorted-key、compact、无 BOM、无尾随换行、LF-only）；在库工件字节 == `canonical_encode(load_registry())` == 两度 `write_registry` 输出（三向字节一致，测试承载）。注册表是**数据身份记录**（类比 manifest），不是 run 产物，按 Allowed File 4 提交。

### 7.7 PR 纪律冻结句（R3/R7；P&V 在 Draft PR 正文逐字写入）

**R3 冻结句（逐字）**：

> The two IP-0026 artifacts evaluation_data/v4/baseline_manifest.json and evaluation_data/v4/python_mvp_support_matrix.json are byte-identical to their frozen state (blob 7ecb39f82f0a03de84fb0881142c60059ddee30e / 3ea94fcf6c49acf133245cef88e53d2734de71e6); the support-matrix gap rows are honestly retained as unsupported because the frozen acceptance tests pin the matrix content, and the row upgrade is deferred to #57 PR3-e together with a new matrix version and a re-freeze of the matrix tests.

**R7 安全声明句（逐字）**：

> The malicious-layout fixture contains only inert synthetic text samples of vulnerable code patterns, each file headed by the SYNTHETIC INERT BASELINE FIXTURE marker, with no real CVE identifier, no real credential, no reachable host (only RFC 2606 .invalid domains), and no usable exploit payload; no fixture file is ever imported or executed by the test or tooling chain.

PR/commit/branch 标题不含自动关闭关键词与 #219/#57 组合（否定句同样禁止；"Related to" only）。

### 7.8 Completion Summary 必含

final SHA、变更文件（对照 4 Allowed Files）、AC→Test→Result 映射、实际命令与统计（含 6b blob 值）、边界检查（diff 恰 4 Add、无物化树入库）、`write_registry` 两度运行字节一致证据、已知限制（Ledger gap 行口径）、Stop Condition 状态（预期全未触发）。

## 8. 冻结测试矩阵（R10；tests/test_v4_baseline_fixtures.py，34 方法 ≤ 35）

RED 锚点：`benchmarks.v4.baseline.fixtures` 子模块缺席（测试内惰性导入 → 每用例 `ModuleNotFoundError: No module named 'benchmarks.v4.baseline.fixtures'`）；注册表工件缺席的用例以 `required deliverable artifact is missing: evaluation_data/v4/fixture_registry.json` 显式 fail（IP-0026 先例）。测试一律 tempfile/tempdir，全离线，模块级导入仅 stdlib + `lima.contracts.codec`。

| 类 | AC/FR | # | 方法（名称冻结） |
| --- | --- | ---: | --- |
| TestFixtureMaterialization | AC-1 / FR-01..03 | 8 | `test_materializes_all_eleven_synthetic_fixtures_with_declared_counts`；`test_empty_repository_materializes_zero_files_with_sentinel`；`test_minimal_python_repository_structure_is_exact`；`test_archetype_key_files_and_content_tokens`（application/library/cli/docs-content/malicious-layout/dependency-blocked 六类 subTest）；`test_test_heavy_fixture_is_test_dominant`；`test_monorepo_fixture_has_three_subprojects`；`test_large_repo_fixture_respects_frozen_bounds`；`test_materialized_files_are_ascii_and_lf_only` |
| TestDeterminism | AC-1 / FR-03..04 | 5 | `test_two_materializations_are_byte_identical`；`test_registry_fingerprints_match_recomputed_tree_digests`；`test_fingerprint_matches_independent_algorithm_oracle`（测试内独立重实现 §7.3 算法 + 空树哨兵）；`test_fingerprints_distinct_across_keys_and_stable_across_runs`；`test_write_registry_bytes_stable_and_match_committed_artifact` |
| TestRegistryContract | AC-2 / FR-04..05 | 6 | `test_registry_top_level_schema_fields`；`test_registry_keys_form_closed_set_matching_fixture_keys`；`test_synthetic_entries_carry_frozen_field_set_and_values`；`test_external_entry_carries_frozen_r8_field_set`；`test_registry_artifact_is_canonical_bytes`；`test_module_consumes_no_manifest_or_matrix` |
| TestFailClosedNegatives | AC-3 / FR-06 | 7 | `test_unknown_fixture_key_rejected_with_stable_message`；`test_external_identity_key_not_materializable`；`test_non_empty_or_unavailable_target_rejected`；`test_verify_rejects_fingerprint_drift`；`test_verify_rejects_missing_or_extra_files`；`test_invalid_registry_rejected_by_load`（5 subTest：未知键/缺键/重复 JSON 键/坏 hex/external 非 null）；`test_empty_entry_declares_exact_zero_and_sentinel`（空仓伪装负例化） |
| TestOfflineHygiene | AC-3 / FR-06 | 5 | `test_no_network_tokens_in_module_test_or_registry`（拼接防自匹配先例）；`test_registry_contains_exactly_one_url`；`test_malicious_fixture_contains_no_real_world_artifacts`；`test_module_imports_within_frozen_whitelist`（AST；无 random/time/datetime/os/secrets 等随机时钟源）；`test_synthetic_fixture_bytes_contain_no_real_identities` |
| TestLlamaFactoryIdentityRegistration | AC-2 / FR-05 | 3 | `test_identity_dual_registration_fields`；`test_fetch_and_precheck_registration`；`test_fingerprint_null_and_materialization_deferred` |

错误码消息逐字断言在 TestFailClosedNegatives 各触发点承载（str(err) == §7.1 目录条目）。

## 9. 验收命令全文（Done Commands 0-8；worktree 根执行；Windows 设 `PYTHONUTF8=1`）

```bash
# 0. 冻结前基线绿（C2 之前先跑一次并登记；213 方法）
python -m unittest tests.test_v4_baseline tests.test_v4_baseline_result \
  tests.test_v4_baseline_manifest tests.test_v4_baseline_collection \
  tests.test_v4_baseline_cli tests.test_v4_baseline_report -v

# 1. 定向新测试（C2 冻结时全 RED 且归因 benchmarks.v4.baseline.fixtures 缺席；C-final 后全绿）
python -m unittest tests.test_v4_baseline_fixtures -v

# 2. 六冻结文件回归（70+33+28+26+27+29=213 必须全绿）
python -m unittest tests.test_v4_baseline tests.test_v4_baseline_result \
  tests.test_v4_baseline_manifest tests.test_v4_baseline_collection \
  tests.test_v4_baseline_cli tests.test_v4_baseline_report -v

# 3. 编译
python -m compileall -q benchmarks tests

# 4. 质量门禁（新 py 文件）
python -m ruff check benchmarks/v4/baseline/fixtures.py tests/test_v4_baseline_fixtures.py

# 5. 文件边界：恰等于 Allowed Files 4 路径（全 Add，零 Modify/零 Delete）
git diff --name-status 58da3fc1c29317ca7c30fff6b8a33482832c234c...HEAD

# 6. 冻结面守护（预期空）：IP-0026 两 JSON + 六冻结测试 + 既有模块
git diff --stat 58da3fc1c29317ca7c30fff6b8a33482832c234c...HEAD -- \
  evaluation_data/v4/baseline_manifest.json evaluation_data/v4/python_mvp_support_matrix.json \
  tests/test_v4_baseline.py tests/test_v4_baseline_result.py tests/test_v4_baseline_manifest.py \
  tests/test_v4_baseline_collection.py tests/test_v4_baseline_cli.py tests/test_v4_baseline_report.py \
  lima scripts benchmarks/v4/baseline/__init__.py benchmarks/v4/baseline/collect.py \
  benchmarks/v4/baseline/run.py benchmarks/v4/baseline/orchestrate.py benchmarks/v4/baseline/report.py

# 6b. 两冻结 JSON blob SHA 不变（预期 7ecb39f82f0a03de84fb0881142c60059ddee30e / 3ea94fcf6c49acf133245cef88e53d2734de71e6）
git ls-tree HEAD -- evaluation_data/v4/baseline_manifest.json evaluation_data/v4/python_mvp_support_matrix.json

# 7. 产物守护（预期空；测试一律 tempfile，物化树不入库）
git diff --name-only 58da3fc1c29317ca7c30fff6b8a33482832c234c...HEAD -- 'evaluation_data/v4/fixtures*'

# 8. ancestry（P&V 终验；<Frozen-Test-Commit-SHA> 由 C2 登记）
git merge-base --is-ancestor 58da3fc1c29317ca7c30fff6b8a33482832c234c <Frozen-Test-Commit-SHA> && \
git merge-base --is-ancestor <Frozen-Test-Commit-SHA> HEAD
```

成功判据：命令 1 全绿（34 方法）、2 全绿 213、3 无输出、4 无发现、5 恰 4 Add 路径、6/6b/7 为空且 blob 不变、8 exit 0。失败即 Stop Condition 对应处置。

## 10. Stop Conditions（停止并提交 Decision Request）

1. 需要触碰任何 Do Not Touch 路径，或第 5 个及以后 Allowed File（含"只给矩阵加一行注记"——R3 已裁定，走 DR 不许绕）。
2. 某 archetype 的最小充分规格无法在不虚构/不伪装的前提下确定。
3. fingerprint 算法在 Windows/Linux 物化路径上出现不可调和不一致（契约必须平台无关）。
4. 测试方法数无法压进 35 且无法合并断言（冻结前）；或 213 冻结回归出现非预期失败。
5. 需要网络、Secret、付费模型、新依赖、随机/时钟源、float、manifest/矩阵消费。
6. 发现 IP-0030 占用冲突，或 base SHA 之后 main 出现冲突性实现。
7. LlamaFactory 预检复验出现与 R8 登记矛盾的事实（如 SHA 突然不可达）→ 按原文转 needs-decision 评估，不得自行换 SHA。
8. schema 字段/错误码与本 Packet §7 冻结清单冲突且无法照录（Packet 冻结面 = 本文件；偏离 = 回到 Coordinator）。
9. 需要消耗 Maintainer 决策的任何事项（预算 ≤1，预期 0）。

## 11. Mechanical Test Correction Allowance（ALLOWED_ONCE）

随 CA-IP-0030-v1.0 一次性授出。P&V 可在不新增 Coordinator 调用的情况下自行纠正一次纯测试机械缺陷并重新冻结，条件五项全满足：①不改产品语义、公共接口、稳定错误码或文件范围；②仅限 fixture/arrange/import/lint/测试基础设施缺陷；③旧 Frozen Commit 保留；④修正前缺陷证据、修正后有效 RED、新 Frozen Commit 完整记录；⑤Implementation 未参与测试修改。涉及产品行为、验收语义或文件范围（含 DR-PV-1 的 test-heavy 文件数）→ Decision Request，不得以本授权消化。

## 12. Decision Record

无未决 DR（Q1-Q9 已由 CA R1-R12 全裁定）。以下为 P&V 在 CA 边界内的**记录性细化裁定**（不改产品语义；Coordinator 激活实现前过目，否决任一条即转 Decision Request 并重新冻结）：

- **DR-PV-1（test-heavy 文件数 14，非 13）**：CA R5 表"文件数上界 13"与其同格明细枚举（3 源文件 + 10 测试文件 + pytest.ini = 14）及 R10 冻结比值（测试:源 ≥ 10:3）内部矛盾。裁决依据：摘要列与明细枚举冲突时明细优先；任何其他取舍必破明文清单（减测试文件破 10:3；去 pytest.ini 或减源文件破明文枚举）。冻结测试断言 file_count == 14。此裁定改变验收数字（13→14），超出 ALLOWED_ONCE 范围，**需要 Coordinator 在激活 C3 前确认**。
- **DR-PV-2（malicious 头注释 ASCII 形态）**：CA R7 头注释文本含 em dash（U+2014），与 R5"全部 ASCII"规则冲突；采 `--`（双连字符）替代：`# SYNTHETIC INERT BASELINE FIXTURE -- NOT A REAL VULNERABILITY`。ASCII 规则优先（可测硬约束）。
- **DR-PV-3（导入白名单补 `enum`/`re`）**：CA R11 例示 stdlib 清单（hashlib/json/pathlib/dataclasses/typing）不含 `enum`/`re`，但 R11 自身冻结的封闭错误码族（str, enum.Enum，IP-0024/0025/0027/0029 同款）需要 `enum`，64/40-hex 形状校验需要 `re`。两者均 stdlib，"仅 stdlib + 唯一产品 import lima.contracts.codec"语义不变。
- **DR-PV-4（`load_registry` 可选 `path` 参数）**：R11 例示 `load_registry()` 与 R10"对 load_registry 注入"畸形注册表负例并存；冻结签名为 `load_registry(path=None)`——零参调用语义完整保留（默认读 `registry_relative_path` 锚定模块 parents[3]），可选参数是负例注入的唯一不落地仓库路径的实现方式。
- **DR-PV-5（`verify_fixture` 对缺失 root 抛 UNAVAILABLE）**：若缺失目录按"零文件树"处理将与空仓哨兵相等（假阳性）；故 root 不存在或非目录 → `MATERIALIZE_TARGET_UNAVAILABLE`。
- **DR-PV-6（Packet 文件名）**：派发消息摘要中出现 `..._Baseline_Fixture_Registry.md`，与 CA 两次出现的 `..._Baseline_Fixture_Family.md` 不一致；CA 为范围权威，采 Family。

## 13. CA R1-R12 全文照录（CA-IP-0030-v1.0 §范围裁定，逐字）

### R1（Q1）fixture 形态终裁：确定性生成脚本，fixture 树不入库

**裁定：生成式**——`benchmarks/v4/baseline/fixtures.py` 内以 `dict[str, str]`（path→内容，全 ASCII/LF）定义 11 个 shape（单一事实源），`materialize_fixture(key, target)` 按字节显式写 LF 物化到目标目录；**物化树不提交进版本库**（仅注册表 JSON 入库）。否决纯静态树整树入库。理由：
1. **确定性可证而非可假定**：AC-1 要求"确定性生成、fingerprint 可重算"——生成式可测试两度物化字节全等 + 重算 fingerprint 对表；静态树只能证明"提交的字节没变"，无法证明复现性，且任何检出版本的 eol/编辑器漂移只能事后发现。
2. **仓库纪律与体积**：large-repo 有界合成（R6：305 文件）+ test-heavy/monorepo 等合计数百文件入库将制造巨型 PR，违背本程序连续三轮（IP-0027/28/29，各 ≤4 Add 路径）的小 diff 纪律；`.gitattributes` `* text=auto eol=lf` 往返依赖显式字节写入消除（生成器 `write_bytes` 显式 LF，物化结果与 git 归一化无关）。
3. **CI**：unit 矩阵 2 OS × 2 py（25 分钟上限）下，秒级生成无压力；入库反而拖慢四份检出。
4. **Issue 明文允许**：#219 Scope 4"生成方式（确定性脚本或静态树）"两形态之一；AC-1 措辞倾向生成式。
5. **消费一致性**：PR3-d 扫描器消费时经同一生成器物化进 tempdir/workspace，与测试同路径，无第二套事实源。
6. 仓库内先例：tests/audit/fixtures/golden_matrix/shapes.py 即"dict 形状 + 按需物化"形态（审计侧），本裁定将其引入基线侧。

**PR3-d 消费契约预留**（本切片不实现）：fixture 物化目标必须是调用方提供的空目录；不提供"物化到仓库内固定路径"的便捷入口（防 run 产物入库）。

### R2（Q2）注册表落位与文件形态：`evaluation_data/v4/fixture_registry.json`，独立于 manifest v1

**裁定**：注册表为单一新 JSON 文件 `evaluation_data/v4/fixture_registry.json`（与两冻结 JSON 同目录、不同文件；由 fixtures.py 的 `write_registry(path)` 一次性生成、Implementation 运行后提交——注册表是**数据身份记录**（类比 manifest），不是 run 产物）。否决落位 benchmarks/ 下。理由：数据身份归 `evaluation_data/v4/`（IP-0026 先例）；PR3-e 矩阵升级条目的 evidence 指针必须是仓库内可解析路径（冻结测试 `test_supported_entries_cite_resolvable_repository_evidence` 的契约形状）。

**与 manifest v1 的边界（禁止进入，三条硬依据）**：①冻结测试 `test_registers_exactly_the_three_frozen_datasets_with_bound_roles` 断言 manifest 恰 3 数据集；②manifest 条目契约要求 repository + 全 40 位小写 commit_sha——合成 fixture 无 pinned 公开 commit，注册即虚构数据源（IP-0026 Packet R4 同款禁令）；③IP-0027 role 门消费 manifest，新条目会改冻结 wiring 的输入。注册表**不被** role 门/manifest/orchestrate 消费——独立文件、零 wiring 改动（IP-0029 R9"零 manifest 消费"纪律在本切片延续：fixtures.py 不 import manifest/矩阵）。

### R3（Q5→Scope 5）矩阵关系终裁：两 JSON 零字节改动；gap 行如实保留；升级延后声明三落点

**裁定**：`python_mvp_support_matrix.json` 与 `baseline_manifest.json` 零字节改动（blob 3ea94fcf / 7ecb39f8 在合并后必须不变——P&V 终验命令）。#219 Scope 5"支持矩阵更新"在本切片取 **AC-2 明文允许的"如实保留"路径**，升级延后至 PR3-e（届时以新矩阵版本 + 冻结测试再冻结周期落地）。**决定性依据（冻结测试钉死矩阵内容，升级即破冻结面）**：
- `test_llamafactory_gap_entry_is_unsupported_with_full_sha`（tests/test_v4_baseline_manifest.py L547-557）断言 `capabilities["archetype/llamafactory-replay"]["level"] == "unsupported"`——把该行升 supported 直接打破 213 冻结面；
- `_REQUIRED_GAP_CAPABILITY_KEYS = ("archetype/empty-repository", "archetype/minimal-python-repository", "archetype/llamafactory-replay")`（L78-82）——gap 三行必须保留；
- `test_registration_notes_cover_exactly_the_excluded_frozen_files`（L558-571）断言 registration_notes 恰覆盖 4 个固定文件——给矩阵加 registry 注记即打破。

**延后声明三落点**（缺一不可）：①注册表顶层自描述字段 `relationship_to_support_matrix`（R9 冻结文本：两 JSON 不变、gap 行保留原因=矩阵内容被 IP-0026 冻结测试钉死、升级于 PR3-e 随矩阵版本升级与测试再冻结统一落地）——使注册表单独可读即自洽；②C1 Packet 专节；③PR 正文一句冻结句（P&V 在 Draft PR 时写入，文本由 Packet 冻结）。不采纳"本切片给矩阵加 registry 引用注记"——见上第三条钉死依据。

### R4（Q3）空仓 fixture 形态：零文件空目录 + 注册表语义声明

**裁定**：`archetype/empty-repository` 的 shape = **空 dict（零文件）**；物化结果=仅创建目标目录本身；fingerprint = `sha256(b"")` 哨兵 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`（tests/audit/fixtures/repo_shapes.py `_SENTINEL_EMPTY_DIGEST` 同款先例）。注册表条目 `notes` 声明："zero-entry working-tree snapshot; no .git metadata (nested git repositories are not representable inside this repository); empty semantics asserted by zero materialized files"。否决 README 占位（非空伪装空仓——正是 #219 负例语义，R10 负例测试覆盖）；否决伪造 .git 目录。测试断言物化后目录存在且 `iterdir()` 为空、file_count=0、fingerprint=哨兵。

### R5（Q4 前段）11 个合成 fixture 的身份键与逐类最小充分规格（内容契约，P&V 在 Packet 逐字冻结 shape 清单）

注册键（稳定、与矩阵既有键风格一致）：`archetype/empty-repository`、`archetype/minimal-python-repository`、`archetype/application`、`archetype/library`、`archetype/cli`、`archetype/docs-content`、`archetype/test-heavy`、`archetype/monorepo`、`archetype/large-repo`、`archetype/malicious-layout`、`archetype/dependency-blocked`（11 个 synthetic）+ `external/llamafactory-replay`（R8）。最小充分规格（每类目的=给扫描器可辨识的结构信号；文件数上界硬约束，全部 ASCII、LF、无二进制）：

| 键 | 文件数上界 | 最小充分内容 |
| --- | ---: | --- |
| empty-repository | 0 | 见 R4 |
| minimal-python-repository | 3 | `pyproject.toml`（name/version 最小）+ `src/minimal_pkg/__init__.py` + `src/minimal_pkg/core.py`（1 纯函数） |
| application | 6 | `requirements.txt`（2 声明）+ `pyproject.toml` + 入口 `app.py`（`if __name__ == "__main__"`）+ `synth_app/api.py`（1 路由装饰器形状）+ `synth_app/__init__.py` + `synth_app/config.py`（os.getenv 配置读取） |
| library | 5 | `setup.cfg`/`pyproject.toml` 其一 + `synth_lib/__init__.py` + `synth_lib/core.py` + `synth_lib/loader.py`（`pickle.loads` 惰性样本）+ `README.md` |
| cli | 4 | `synth_cli/__main__.py`（argparse 入口）+ `synth_cli/main.py`（子命令分发）+ `synth_cli/commands.py` + `pyproject.toml`（`[project.scripts]`） |
| docs-content | 6 | `README.md` + `mkdocs.yml` + `docs/index.md` + `docs/guide.md` + `docs/reference.md` + 1 个平凡 `tools/build_docs.py`（文档占多数、Python 极少数的覆盖形态） |
| test-heavy | 13 | `src/synth_core/__init__.py` + `src/synth_core/logic.py` + `src/synth_core/store.py` + `tests/test_logic.py` 等 **10 个测试文件**（测试:源 ≥ 10:3）+ `pytest.ini` |
| monorepo | 11 | 根 `pyproject.toml`（workspace 声明）+ 3 子项目（`packages/alpha`、`packages/beta`、`services/gateway`）各含 `pyproject.toml` + 包 `__init__.py` + 1 模块（3×3）+ 根 `README.md` |
| large-repo | 305 | 5 个根文件（README/pyproject/.gitignore/LICENSE 文本/Makefile 其一）+ **300 个** `synth_bulk/module_000.py`…`module_299.py`，内容=纯索引确定性函数（docstring + 1 函数 + 索引派生常量），总字节 ≤256KB |
| malicious-layout | 6 | 逐文件 "SYNTHETIC INERT BASELINE FIXTURE — NOT A REAL VULNERABILITY" 头注释；样本：`setup.py`（download_url+exec 声明形状、惰性）+ `synth_risk/paths.py`（`../` 穿越字符串拼接）+ `synth_risk/eval_sample.py`（`eval` 外部输入形状）+ `synth_risk/shell.py`（`subprocess` `shell=True` 用户输入形状）+ `synth_risk/deser.py`（`pickle.loads` 网络载荷形状）+ `NOTICE.md`（合成惰性声明） |
| dependency-blocked | 4 | `requirements.txt`（不可解析 pin，如 `synth-internal-core==9.9.9`）+ `pyproject.toml`（`git+https://git.internal.invalid/synth/pkg.git` 源，**RFC 2606 .invalid 域**）+ `constraints.txt` + `src/synth_blocked/__init__.py` |

**命名纪律**：一切包名/仓名用 `synth_*` 前缀虚构名；不得出现任何真实公开仓名、真实组织名、真实 CVE 编号、真实内部域名、可访问 URL。内容与 tests/audit/fixtures/golden_matrix/shapes.py 的形状**字节不同**（独立家族，不 import 不复制）。

（P&V 注：本表 test-heavy 行"上界 13"与同行枚举 3+10+1=14 矛盾，已在 §7.4/§12 DR-PV-1 按明细优先裁决为 14；其余十类上界与枚举一致。）

### R6（Q4 后段）large-repo 有界合成的数值边界

**裁定**：**305 文件、总字节 ≤256KB、生成墙钟 <2s（单物化）**。生成方式=纯函数于索引（无随机源、无环境依赖、无时间依赖）；"有界"声明写入注册表条目（`declared_size_bytes` + `file_count` 字段）。依据：CI unit 矩阵四份并行 × 每次 ≤2s 生成无压力；256KB 上界排除任何"近似真实仓库下载"的伪装空间；300 文件足以构成 large-repo 的结构信号（扫描器跳过/预算行为在 PR3-d 才消费）。

### R7（Q5→Q6）malicious-layout 安全边界（允许/禁止清单，Packet 逐字冻结）

**允许**：真实漏洞**模式**的合成文本形状——路径穿越字符串、`eval`/`exec` 调用形状、`subprocess shell=True` 形状、`pickle.loads` 形状、setup.py 下载执行声明形状——全部为**永不执行**的静态文本，带统一 SYNTHETIC INERT 头注释，仓库内无任何执行路径（fixture 文件不被 import、不进 pyproject 包发现范围——`[tool.setuptools.packages.find] include=["lima*"]` 已天然排除）。
**禁止**：真实 CVE 编号/真实漏洞利用文章文本；可用的完整利用载荷（shellcode、可复现的攻击链、可解出的恶意构造）；真实凭据/token/密钥字符串；任何指向真实主机的 URL/IP；真实项目路径。测试含禁止内容负例（R10：源扫描断言无 `CVE-`、无真实域、无 token 形状）。

### R8（Q7）LlamaFactory 物化登记形态：external-identity 条目（登记不下载）

**裁定**：注册表第 12 条 `external/llamafactory-replay`，`kind="external-identity"`，字段（P&V 逐字冻结）：
- `identity`: `{"repository_requested": "hiyouga/LLaMA-Factory", "canonical_repository": "hiyouga/LlamaFactory", "commit_sha": "7fcf5b3b130e5713b52415bb7404c476fada9c8c"}`——**双记**：#57 原文身份 + canonical 重定向身份（亲验：API 301 → full_name=hiyouga/LlamaFactory；commit 存在，committer date 2026-08-27T10:50:56Z）。不双记则 PR3-d 复现时身份歧义。
- `fetch`: `{"method": "codeload-tarball", "url": "https://codeload.github.com/hiyouga/LLaMA-Factory/tar.gz/7fcf5b3b130e5713b52415bb7404c476fada9c8c"}`（请求名 URL；canonical 名 URL 等价可达，注册表记一行、notes 记等价性）。
- `precheck`: `{"date": "2026-09-26", "commit_api": "301-redirect-then-200 to hiyouga/LlamaFactory", "tarball_head": "200"}`。
- `license`: `"Apache-2.0 (upstream SPDX; hiyouga/LlamaFactory repository license)"`。
- `fingerprint`: **`null`** + `fingerprint_note`: "no content bytes exist in this repository; digest deferred to PR3-d materialization"——诚实缺席，禁止伪造 digest。
- `materialization`: `"deferred-to-PR3-d"`；`notes`: 明示本切片不下载、真实 run 预算=预留 Maintainer 决策、若 SHA 不可物化 #57 转 needs-decision 禁止换 latest main（#57 FR-06 原文纪律）。
**行为边界**：`materialize_fixture("external/llamafactory-replay", …)` 必须抛 `EXTERNAL_IDENTITY_NOT_MATERIALIZABLE`（fail-closed，R10 负例）；fixtures.py 全模块**不含任何网络代码**（urllib/requests/socket 禁止，hygiene 源扫描覆盖）。

### R9（Q2 后段→Scope 4）注册表 schema 冻结

顶层：`schema_version`(=1)、`registry_id`(="lima-baseline-fixture-registry")、`relationship_to_support_matrix`（R3 冻结文本）、`offline_note`（全离线/合成声明）、`fixtures`(12 条)。
synthetic 条目字段：`key`、`kind`("synthetic-fixture")、`purpose`（"baseline archetype: <名称>"）、`origin`("synthetic-lima-authored"——反伪装身份字段，测试断言全集恰此值)、`license`("Apache-2.0 (LIMA-authored synthetic content)")、`generation`(`{"mode": "deterministic-script", "entrypoint": "benchmarks.v4.baseline.fixtures.materialize_fixture"}`)、`fingerprint`(64-hex)、`file_count`(int≥0)、`declared_size_bytes`(int)、`notes`(str，empty fixture 的语义声明在 R4)。
external 条目字段：R8 全集（kind="external-identity"；fingerprint 允许 null 且仅 external 允许 null）。
**fingerprint 算法冻结**：`sha256` 于"按 POSIX 相对路径字典序排序的每个文件：utf-8(path) + b"\x00" + 内容字节 + b"\x00" 的串联"；空树=`sha256(b"")` 哨兵（R4）。注册表 JSON 本身由 `write_registry` 以 canonical JSON 写出（仅经 `lima.contracts.codec.canonical_encode` 或等价冻结实现——P&V 在 Packet 定实现并冻结；UTF-8、无尾随空白、LF）。
**键唯一性/封闭集**：12 键恰等于 fixtures.py 的 `FIXTURE_KEYS`；注册表加载校验（`load_registry`）fail-closed：未知键/缺键/重复键/fingerprint 形状非法（synthetic 非 64-hex、external 非 null）→ `INVALID_REGISTRY`。

### R10（Q8）测试组织：单新文件 `tests/test_v4_baseline_fixtures.py`，≤35 方法

unittest 风格，RED 锚点=`benchmarks.v4.baseline.fixtures` 子模块缺席（import/属性失败）。类↔AC 映射与方法预算（合计 30-34）：
- `TestFixtureMaterialization`（AC-1，~8）：11 键各物化到 tempdir；逐类结构断言（关键文件存在/计数；empty=零文件；large-repo=305 且 ≤256KB；test-heavy 测试:源 ≥10:3；monorepo=3 子项目）；全 ASCII/LF 字节断言（无 b"\r"）。
- `TestDeterminism`（AC-1，~4）：11 键两度物化字节全等（逐文件 digest 对表）；fingerprint 重算==注册表；同键两次 fingerprint 相等、异键 fingerprint 互异。
- `TestRegistryContract`（AC-2，~6）：schema 形状（顶层四字段+12 条）；键封闭集==FIXTURE_KEYS；synthetic origin 全集断言；external 条目 R8 字段逐项（双记身份/SHA/URL/precheck/license/null fingerprint）；`relationship_to_support_matrix` 文本在；manifest v1 与矩阵 blob 未被消费（fixtures.py 源零 manifest/matrix import）。
- `TestFailClosedNegatives`（AC-3，~7）：未知键→`UNKNOWN_FIXTURE_KEY`；external 键物化→`EXTERNAL_IDENTITY_NOT_MATERIALIZABLE`；目标目录非空→`MATERIALIZE_TARGET_NOT_EMPTY`；篡改物化文件后 verify→`FIXTURE_FINGERPRINT_MISMATCH`（fingerprint 漂移拒绝）；缺一个文件后 verify→同款 mismatch；注册表缺键/重复键/坏 fingerprint 形状→`INVALID_REGISTRY`（对 load_registry 注入）；"非空伪装空仓"：注册表 empty 条目物化出任何文件即 fail（结构断言负例化）。
- `TestOfflineHygiene`（AC-3，~5）：fixtures.py+测试文件+注册表 JSON 源扫描：无网络 token（拼接防自匹配，先例 `_forbidden_source_tokens`）；注册表内 URL 恰 1 处=external fetch URL，synthetic 条目零 URL；malicious 禁止内容扫描（无 `CVE-`、无非 `.invalid` 真实域、无 token 形状）；无 `random`/`time`/`os.urandom` 于 fixtures.py（确定性纪律：无随机源/时钟源 import）。
- `TestLlamaFactoryIdentityRegistration`（AC-2，~3）：R8 身份/fetch/precheck 逐字段断言（含 canonical 双记、SHA 全 40 位小写、fingerprint 恰 null）。
**方法数上限 35**：无法压进且无法合并断言→Stop Condition（冻结前）。测试一律 tempfile/tempdir，不提交任何物化树。

（P&V 注：R10 顶层说"顶层四字段"，与 R9 顶层五字段（schema_version/registry_id/relationship_to_support_matrix/offline_note/fixtures）不一致——R9 为 schema 冻结条，采 R9 五字段；§7.6 已照录。）

### R11（Q1 尾→Scope 6/Done Commands）错误族与公共面冻结

- 错误族：`BaselineFixtureError`（fixtures.py 定义），closed codes：`UNKNOWN_FIXTURE_KEY` / `EXTERNAL_IDENTITY_NOT_MATERIALIZABLE` / `MATERIALIZE_TARGET_NOT_EMPTY` / `MATERIALIZE_TARGET_UNAVAILABLE` / `FIXTURE_FINGERPRINT_MISMATCH` / `INVALID_REGISTRY`。逐字稳定消息由 C1 Packet 冻结（IP-0024/0025/0027/0029 风格）。
- 公共符号面（`fixtures.__all__`，C1 冻结签名）：`FIXTURE_KEYS`、`SYNTHETIC_FIXTURE_KEYS`、`EXTERNAL_IDENTITY_KEYS`、`materialize_fixture(key, target)`（返回 materialization 结果对象：key/root/file_count/size_bytes/fingerprint）、`compute_tree_fingerprint(root)`、`verify_fixture(key, root)`（mismatch 抛错，不返回 bool——fail-closed）、`load_registry()`、`registry_relative_path`、`write_registry(path)`。
- 依赖纪律：fixtures.py 仅 stdlib（hashlib/json/pathlib/dataclasses/typing）；不 import lima 产品模块（除经 Packet 冻结的 canonical 写出实现引用 `lima.contracts.codec`，该 import 为唯一允许的产品 import）；`benchmarks/v4/baseline/__init__.py` 零改动（marker 先例，子模块直接导入）。

### R12（M9/M10）调用/时间/决策预算与 PR 纪律

- 每叶子 ≤8 调用 / ≤75 分钟 / ≤1 Maintainer 决策（预期 0——Q1-Q9 已全部本裁定消化；出现新决策事件=Stop Condition）。
- 单 PR；PR/commit/branch 标题不含自动关闭关键词与 #219/#57 组合（否定句同样禁止；"Related to" only）；PR 正文含 R3 冻结句与 R7 安全声明句（文本 C1 冻结）。

## 14. Handoff（各阶段填写）

- C1 Packet SHA：见最终交付记录（本文件 commit：`[IP-0030][PV] Add implementation packet for baseline fixture registry`）。
- C2 Frozen Test Commit SHA / 测试文件 SHA-256 / 方法数：见 P&V 冻结记录（`[IP-0030][PV] Freeze acceptance tests for baseline fixture registry (RED)`）。
- C3+ Implementation：Base = Frozen Test Commit SHA；Done Commands 0-7 全绿/为空 + Completion Summary → 交 P&V 独立验证（含命令 8 ancestry）。
- 验证 → Coordinator READY-FOR-MERGE 判定（P&V 不合并；Draft PR 正文含 §7.7 两冻结句）。
