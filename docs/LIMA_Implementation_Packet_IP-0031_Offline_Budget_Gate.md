# LIMA Implementation Packet — IP-0031 Offline Flow & Budget Gate（#221 离线执行接线 + 预算门禁 + 决策包子叶）

- Packet ID：IP-0031（Source Issue #221；Parent #57 PR3-d offline-execution & budget-gate 离线子叶）
- 依据：Coordinator Assignment CA-IP-0031-v1.0（2026-09-27，快轨 Intent+Coordinator 合并轮，一轮 Assignment 原则 R1-R14 一次全裁定）；Intent Record INTENT-RECORD-IP-0031-2026-09-27（READY-FOR-COORDINATOR，同轮产出）
- 精确基线（Exact Baseline）：`e8661fa25e45072bd81bf1013ed21b7c4a92d18b`（= main = PR #183 cxx 轨道合并点；PR3-a/b/c merges #216/#218/#220 全为祖先）
- 工作分支 / worktree：`codex/ip-0031-offline-budget-gate` @ `D:\BaseAIProject\LIMA-ip0031-wt`（C2 Frozen Test Commit 自 C1 commit 派生；C3+ 自 Frozen Test Commit 精确 SHA 派生）
- 授权：Maintainer 方案 B（2026-09-27；Operating Mode SHADOW · ACTIVE: DISABLED · Execution Authorization: MAINTAINER_AUTHORIZED；本轮真实付费预算 0 micro-USD、真实下载/扫描/模型调用授权无）
- 本 Packet 由 P&V 于 C1 制作并冻结；公共符号面/签名/逐字错误消息目录/记账语义/检查序/marker schema/合成 payload 与 usage 公式/套件执行序为 P&V 在 CA R1-R14 边界内的冻结细化（§7-§9）。偏离本 Packet 冻结面 = Assignment Stop Condition 11
- 状态：READY-FOR-CODE（C2 冻结测试就绪后生效；关键字段无 TBD）

## 0. 交付物角色声明（强制，先于一切）

本 Packet 是 IP-0031 的唯一实现依据。P&V 交付物恰为 4 个 Add 路径中的前 4 号：本 Packet（C1）、决策包 `docs/LIMA_PR3d_Real_Run_Budget_Decision_Pack.md`（C1，作者归属 P&V，CA R4）、冻结测试 `tests/test_v4_baseline_budget.py`（C2，30 方法）与 `tests/test_v4_baseline_offline_flow.py`（C2，21 方法）。实现交付物恰为 2 个 Add 路径：`benchmarks/v4/baseline/budget.py`（预算门禁与真实运行锁，R2/R3/R5/R9/R11）与 `benchmarks/v4/baseline/offline_flow.py`（离线套件组合层，R6/R7/R8/R11）。**本切片零 Modify：diff 恰 6 Add 路径、零 Modify/零 Delete；七冻结测试文件 247 方法零改动零追加；三冻结 JSON 与既有六模块 blob 不变。**任何超出 = Assignment Stop Condition 4。实现者不得修改本 Packet、决策包与冻结测试；测试缺陷走 Decision Request（或一次性 ALLOWED_ONCE，§11）。冻结测试只测行为与不变量，不锁定实现细节。

## 1. 需求映射（Packet 头）

```text
Source Issue：#221（open，status:in-progress，作者 AttentionYourCode；2026-09-27 GitHub API 亲验）
Issue specification revision：2026-09-27 创建版正文（Scope 1-6 / Non-goals / AC-1..4 / Packet IP-0031 占用 / 方案 B 授权头）
Covered requirements：FR-01、FR-02、FR-03、FR-04、FR-05、FR-06、AC-1、AC-2、AC-3、AC-4
Not covered requirements：PR3-d 真实执行保留项全部、PR3-e 全部（见 §1 Not-covered）
Delivery role：vertical-slice（#57 PR3-d offline 子叶）
Issue closure impact：PARTIAL（IP-0031 完成 ≠ PR3-d 完成 ≠ #221/#57 完成）
Upstream IP/PR/merge commits：IP-0024..IP-0030 全链；PR #216（IP-0028）/#218（IP-0029）/#220（IP-0030）merge 均为 e8661fa 祖先
```

#221 "Scope (this slice)" 1-6 规范化为 FR-01..FR-06（语义不变，CA-IP-0031-v1.0）；AC 沿用 #221 原文 AC-1..AC-4。本 Packet 只声明本切片的贡献（离线模拟 ≠ 真实测量；门禁锁定态 ≠ 真实运行可用；IP-0031 完成 ≠ PR3-d 完成 ≠ #57 完成）。

| ID | #221 出处 | 本轮交付 | 验收承载 |
| --- | --- | --- | --- |
| FR-01 | Scope 1 | 离线接线：orchestrate（run_repeats）→ evaluator 注入边界（guarded fake）→ collect（PlatformSources 注入）→ RunResult → build_baseline_report/write_report_file → load_registry/materialize_fixture（IP-0030）类型化数据流；fake evaluator + 合成 usage 全链验证 | TestOfflineSuiteEndToEnd（6 方法）+ PC2 arrange 校验 |
| FR-02 | Scope 2 | 默认拒绝门禁：两新模块零网络代码/零 Secret 读取/付费路径不存在；真实运行入口唯一行为=REAL_RUN_LOCKED（锁定常量 REAL_RUN_GATE_UNLOCKED=False，无解锁路径）；CI 离线/无 Secret/无付费 | TestGateHygiene（3 方法）+ TestOfflineHygiene（3 方法） |
| FR-03 | Scope 3 | 预算门禁骨架：BudgetSpec（单 run+批次两级、七维度）、预留/消耗/回收三态记账、预调用检查（开销不可预先界定→拒）、调用后核对（usage 缺失→VIOLATION fail closed 不记 0）、失败/取消回收（已耗保留、calls 永不回收）、None≠0 | TestBudgetSpecValidation + TestReserveAndConsume + TestLedgerInvariants |
| FR-04 | Scope 4 | 离线模拟：5 cold+5 warm（repeat=5，⊇3/5 最小充分）经 fake evaluator 全链走通；失败 run 保留 taxonomy、insufficient_sample、身份/digest 关联；synthetic 标记 sidecar（不冒充、不进 #57 真实验收） | TestFailureRetention（3）+ TestSyntheticMarkerContract（5） |
| FR-05 | Scope 5 | 预算决策包工件（十一节结构、数值只许公式或字面 UNKNOWN、反编造静态扫描、UNKNOWN+最小授权清单；不编造定价） | `docs/LIMA_PR3d_Real_Run_Budget_Decision_Pack.md` + TestDecisionPackArtifact（4） |
| FR-06 | Scope 6 | 测试：零预算/恰达上限/超单 run/超总/缺 usage/未知价格/取消失败记账/门禁拒绝时外部调用=0（注入计数器证）；正例+fail-closed 负例；两新文件各 ≤35 方法 | TestFailClosedNegatives（11）+ TestFailureCancelAccounting（4）+ TestOfflineHygiene 套件级计数器 |

**AC 映射**：AC-1（离线端到端 fake evaluator + 合成 usage；全程零网络/零 Secret/零付费）→ TestOfflineSuiteEndToEnd + TestOfflineHygiene；AC-2（负例全 fail closed typed error；拒绝时外部调用=0；None≠0）→ TestFailClosedNegatives + 计数器断言（含套件级）+ TestGateHygiene；AC-3（模拟结果显著标记 synthetic；失败 run 保留；身份/digest 关联可复核）→ TestSyntheticMarkerContract + TestFailureRetention；AC-4（决策包落盘 UNKNOWN 如实；七冻结面 247 零改动）→ TestDecisionPackArtifact + Done Commands 0/2/7 + diff 边界（命令 6）。

**Not-covered（本切片明确不处理，全团队不得扩张；= CA §Not-covered 1-8）**：
1. PR3-d 真实执行保留项：真实 LlamaFactory 下载/扫描/重放、真实模型调用、真实 token/cost 测量、真实 run 预算数值与门禁解锁（需未来独立 Maintainer 授权+数值预算；本轮预算 0 micro-USD、ACTIVE 0/2）。
2. PR3-e：V5 九类真实验收、VEP/RVR/terminal outcome 扩展、支持矩阵行实际升级与再冻结、#85 登记、#57 聚合 Closure。
3. 修改扫描器/Prompt/标签/split/默认 analyzer/生产 Audit/Queue/Sandbox/Repair/Frontend 逻辑；frozen holdout。
4. 修改 `lima/**`、`scripts/**`（含三 CLI 脚本接线——离线接线经库级组合交付，CA R1）、benchmarks 既有六模块、`benchmarks/**/__init__.py`、`evaluation_data/v4/` 三 JSON（blob `7ecb39f8`/`3ea94fcf`/`493f3da5` 不变）。
5. 报告 declarations 枚举扩展或 RunResult/报告 schema 任何字段增改（IP-0025/0029 冻结面）；CLI 三脚本新参数/新接线。
6. 七冻结测试文件（70+33+28+26+27+29+34=247）零改动零追加；提交任何 run 产物/输出目录（测试一律 tempfile/tempdir）。
7. 新依赖、网络、Secret、付费 LLM、容器镜像/Dockerfile 变更（根 Dockerfile L68 已 COPY 整个 benchmarks 包，新子模块自动包含——2026-09-27 亲验，无需变更）。
8. #221/#57 关闭判断、#57 PR3 行勾选（合并后由 Coordinator 按证据推进，仅实际证明项）。

## 2. Design Input Manifest

| 输入 | 版本 / SHA | 消费方式 |
| --- | --- | --- |
| CA-IP-0031-v1.0 | `.pv_tmp/COORDINATOR_ASSIGNMENT_IP-0031_2026-09-27.md`（2026-09-27） | **范围权威**；R1-R14 全文照录进 §13；本 Packet 一切冻结细化以其为上位约束 |
| Intent Record INTENT-RECORD-IP-0031-2026-09-27 | `.pv_tmp/INTENT_RECORD_IP-0031_2026-09-27.md` | 需求语义 M1-M10/I1-I5/A1-A5/Q1-Q10；决定性发现（run_repeats 差集窗口、e2e 形状为合成 payload 唯一最小面） |
| Source Issue #221 | open，status:in-progress，作者 AttentionYourCode，0 评论；2026-09-27 GitHub API 匿名只读亲验（CA §Authoritative Inputs） | Scope 1-6 / Non-goals / AC-1..4 / Packet IP-0031 占用 / 方案 B 授权头（0 micro-USD、无下载授权、ACTIVE 0/2） |
| Parent #57 | open；FR-01..06/NFR-01/02/V5 段亲验 | NFR-02 预算上限机制落点（本切片交付锁定态骨架）；synthetic 产物排除清单（真实验收/immutable before baseline） |
| 七冻结测试文件 @e8661fa | test_v4_baseline `4cde7bdf0a76f56a2e1504483470dda4fbc3fef7`（70）/ test_v4_baseline_result `0a44cf7d41bee4756de966e77e88e5439ed386a5`（33）/ test_v4_baseline_manifest `8e8ab0dcb9fdea5a8b0a216610c5bd5dae2c92b9`（28）/ test_v4_baseline_collection `35e6ec6a497719be5495048600ea1db6802d9fc4`（26）/ test_v4_baseline_cli `edb2391bfcf3592739a3ac48e1fa5e9ddd752c60`（27）/ test_v4_baseline_report `b53176f5af0acf9322bfbaefd002612605fda4df`（29）/ test_v4_baseline_fixtures `34b397b700daabe58317180fd15f4c72658fdb66`（34）＝ **247** | AC-4 回归基线（C2 冻结前 P&V 亲跑全绿）；测试风格镜像（token 拼接 hygiene、deliverable-missing RED 锚点、subTest 组织、arrange helper 基类） |
| 上游六模块 @e8661fa | orchestrate `8655067e180ffafc2ee2e8b0ca93f5531201e344` / run `d29928e5ea7d4a737d937e6496a0f24a850dea7d3` / report `3615a75d77849a26072e6517345fe15437072cf2` / collect `063ecb41e4f472e9fa7f575f7ccc358809c0f6db` / expert_timing `dd7aa3654df58382425af9dfb02cbefb7ebf0b9b` / fixtures `0e4fb11fb07a7cf76658df673bd4cde685c60ce4`；`benchmarks/v4/baseline/__init__.py` `1c478346d7543f6c7f64d5d71081c612ca50fb55` | 只读消费面（R8 冻结清单）；注入边界（execute 参数、usage 通道）、result_paths 差集+int 排序、declarations 恰一值、`-run-`/`-report-`/`.expert-timing` 探测族、load_registry/materialize_fixture——逐段亲读（CA §证据清单 4-7） |
| lima 契约层 @e8661fa | baseline_run_spec `4d55dd60583093cd612953bb3d8c51a5986f2808` / baseline_run_result `aafd02b653e0bd8e5eaada00703a0d98968ece6a` / contracts/codec `a442076db6f193a3b362cc6caf6d53d4f76570b8` | spec 校验（spec 经 run_repeats 内部过 `from_mapping`）、聚合 sufficient/insufficient 门（3 cold/5 warm）、`_MACHINE_PROFILE_FIELDS` 八字段（决策包 §7 对齐）、canonical_encode/compute_content_digest（marker 唯一 canonical 写出来源） |
| 冻结数据面 @e8661fa | baseline_manifest.json `7ecb39f82f0a03de84fb0881142c60059ddee30e`（恰 3 数据集）/ python_mvp_support_matrix.json `3ea94fcf6c49acf133245cef88e53d2734de71e6` / fixture_registry.json `493f3da55722a2a1e9720048600ea1db6802d9fc4`（IP-0030 产物：12 键=11 synthetic+external/llamafactory-replay deferred-to-PR3-d） | 只读消费（manifest 默认路径解析进套件；registry 只读校验+fixture 物化）；blob 不变是合并门禁（Done Command 7） |
| CI/环境 @e8661fa | scripts/run_ci_tests.py L16 `unittest discover -s tests`；根 Dockerfile L68 `COPY --chown=lima:lima benchmarks ./benchmarks`；pyproject ruff E,F,I,B,UP,S ignore S101、line-length 100 | Done Command 3 回归集合；镜像无需变更依据（R14）；ruff 门 |
| 先例与教训 | IP-0030 CA/Intent（.pv_tmp 2026-09-26）；IP-0029/0030 两次机械修正史（commit `d14151a`/`58bd1a5`） | PC1-PC3 三项静态预检（冻结前置硬门）与 ALLOWED_ONCE 收紧的直接依据；连续四轮零 Modify 先例（IP-0027..0030） |
| 错误族先例 | IP-0024/0025/0027/0028/0029/0030 六连：closed code 目录 + `field_path` + 逐字稳定消息 + 独立 ValueError 子类 | §7.1 BudgetGateError 形状（不子类化/复用既有错误类） |

哈希真值来源：`git ls-tree -r e8661fa25e45072bd81bf1013ed21b7c4a92d18b -- <paths>`（P&V 2026-09-27 程序化复制，未手抄；见 §14 证据清单）。冻结前基线绿：P&V 在 C2 之前亲跑七冻结文件回归（Done Command 0，247 全绿）+ 全量 discover（Done Command 0b）并登记。

## 3. Explicitly Rejected Inputs

| 被拒输入 | 拒绝理由 |
| --- | --- |
| 修改 `orchestrate.py`/`run.py`/`report.py`/`scripts/**` 以接线离线套件 | CA R1 三依据否决：execute/usage 通道已是冻结注入边界；上游全为 tracked 冻结面（Modify 破坏 247 冻结纪律与连续四轮零 Modify 先例）；确需修改 = Stop Condition 6 |
| synthetic 标记进入 RunResult 样本层或报告 schema（含 declarations 扩展） | 亲验 fail closed：`_SAMPLE_FIELDS` 17 键封闭 + `_reject_unknown_fields`（baseline_run_result L48-61/L320/L415-416）；报告 `_check_exact_fields` 未知键拒绝（report L549-552）且 declarations 逐字冻结恰一值（L72/L646-650）；IP-0029 封闭枚举不可扩 |
| 真实运行门禁的"解锁参数/环境变量开关/配置文件" | CA R5：本切片唯一合法行为=REAL_RUN_LOCKED；不存在解锁代码路径；任何解锁机制=未来独立授权+代码变更 |
| 给决策包填写任何未实测定价/估算数值（"参考价/约/大约"式数字） | CA R4 反编造纪律 + Assignment Stop Condition 5；未知即字面 UNKNOWN+最小授权清单 |
| usage 缺失记 0 / None 当 0 / pricing 填 0 冒充已知价 | #221 Scope 3 原文语义（违规非零）；CA R2/R3；Assignment Stop Condition 5 |
| 非对称精确 3 cold+5 warm 编排（重写 run_repeats 聚合） | CA R7：run_repeats 冻结 N+N；repeat=5 ⊇ 3/5 最小充分门即满足 #221 Scope 4 读法；重写=复制聚合逻辑违反复用纪律 |
| IP-0029/0030 前两轮的"冻结后机械修正"路径作为常态手段 | 本轮 PC1-PC3 为冻结前置硬门；缺失或失效不属于机械缺陷，不得以 ALLOWED_ONCE 消化（CA §Mechanical Test Correction Allowance 末段） |

## 4. Goal / Non-goals

**Goal**：在既有离线基线组件（IP-0024..IP-0030）之间交付 ① 离线端到端类型化数据流（orchestrate → 注入 fake evaluator → collect → RunResult → report → fixture 注册表）；② 默认 fail closed 的真实运行门禁（本轮锁定态）；③ 单 run/批次两级预算门禁骨架（预调用检查/预留/调用后核对/失败取消记账；usage 缺失=违规非 0；None≠0）；④ 离线模拟 5 cold+5 warm（⊇3/5 最小充分样本）全链验证（失败 run 保留、insufficient_sample、身份与 digest 关联、synthetic 显著标记）；⑤ 下一次真实运行决策所需的预算决策包（UNKNOWN 如实标注+最小授权清单）。为 PR3-d 真实执行（未来独立授权+数值预算）与 PR3-e（V5 验收）预置门禁与决策基座。

**Non-goals**：见 §1 Not-covered 1-8（全团队不得扩张）。

## 5. 文件边界（CA R1：恰 6 Add 路径、零 Modify、零 Delete）

### 5.1 Files to Add

| # | 路径 | Owner | 阶段 | 内容 |
| --- | --- | --- | --- | --- |
| 1 | `docs/LIMA_Implementation_Packet_IP-0031_Offline_Budget_Gate.md` | P&V | C1（已交付） | 本 Packet |
| 2 | `docs/LIMA_PR3d_Real_Run_Budget_Decision_Pack.md` | P&V | C1（已交付） | 预算决策包（R4 十一节；作者归属 P&V） |
| 3 | `tests/test_v4_baseline_budget.py` | P&V | C2（已交付，冻结） | budget 门禁面冻结测试（30 方法 ≤35） |
| 4 | `tests/test_v4_baseline_offline_flow.py` | P&V | C2（已交付，冻结） | 离线接线/marker/决策包/hygiene 面冻结测试（21 方法 ≤35） |
| 5 | `benchmarks/v4/baseline/budget.py` | Implementation | C3+ | 预算门禁与真实运行锁（§7 冻结契约） |
| 6 | `benchmarks/v4/baseline/offline_flow.py` | Implementation | C3+ | 离线套件组合层（§8 冻结契约） |

### 5.2 Product Files Allowed to Modify

无（Modify=零，无豁免清单；Assignment Stop Condition 4）。

### 5.3 Read-only Reference Files（只读消费，证据锚点见 §2）

`benchmarks/v4/baseline/orchestrate.py`（run_repeats/BaselineRunSummary/BaselineOrchestrationError）、`run.py`（run_baseline_attempt/validate_role_bindings/write_result_file/FROZEN_DATASET_BINDINGS）、`collect.py`（PlatformSources/classify_failure/FAILURE_TAXONOMY_CODES/elapsed_ms）、`report.py`（build_baseline_report/write_report_file/from_mapping/BASELINE_REPORT_DECLARATIONS）、`expert_timing.py`、`fixtures.py`（load_registry/materialize_fixture/FIXTURE_KEYS/SYNTHETIC_FIXTURE_KEYS）、`lima/baseline_run_spec.py`、`lima/baseline_run_result.py`（from_mapping/_COLD_MIN_SUCCESSES/_WARM_MIN_SUCCESSES/_SAMPLE_FIELDS）、`lima/contracts/codec.py`（canonical_encode/compute_content_digest）、`evaluation_data/v4/` 三 JSON、七冻结测试文件。

### 5.4 Files Forbidden（diff 必空；Done Command 7 全列）

七冻结测试文件；`benchmarks/v4/baseline/` 既有六模块与 `__init__.py`；`benchmarks/__init__.py`、`benchmarks/v4/__init__.py`；`lima/**`；`scripts/**`；`evaluation_data/` 既有全部文件；`pyproject.toml`/`requirements.txt`/`.gitignore`/`.gitattributes`/`.github/**`/Dockerfile 系；其余一切 tracked 文件；不提交任何 run 产物/输出目录/物化 fixture 树（测试一律 tempfile）。

### 5.5 Symbol-to-File Map

| Symbol | 文件 | 类别 |
| --- | --- | --- |
| `BudgetGateErrorCode`（七成员）、`BudgetGateError`、`BUDGET_DIMENSIONS`、`BudgetLimits`、`BudgetSpec`、`CallEstimate`、`CallUsage`、`Pricing`、`BudgetLedger`、`LedgerSnapshot`、`REAL_RUN_GATE_UNLOCKED`、`require_real_run_unlock` | `benchmarks/v4/baseline/budget.py` | 公共（`__all__` 见 §7.2） |
| `EvaluatorOutcome`、`synthetic_e2e_payload`、`synthetic_call_usage`、`make_fake_evaluator`、`FakeEvaluator`、`run_offline_baseline_suite`、`OfflineSuiteResult`、`write_synthetic_marker` | `benchmarks/v4/baseline/offline_flow.py` | 公共（`__all__` 见 §8.1） |
| guarded evaluator 构造（`_guard_with_budget` 建议名，内部） | `benchmarks/v4/baseline/offline_flow.py` | 内部（测试不直接引用） |

### 5.6 与其他活动 IP 的冲突分析

无并行活动 IP 占用 `benchmarks/v4/baseline/` 或 `tests/test_v4_baseline*`（IP-0031 占用检查：`git log --all --grep=IP-0031` 0 命中、docs/ 0 命中——2026-09-27 亲验）。base SHA 之后 main 无冲突性实现（Assignment Stop Condition 10 监控）。

## 6. 依赖、网络、文件系统与权限边界

- **stdlib-only**（两新模块）：`dataclasses`/`enum`/`json`/`math`/`pathlib`/`typing`（budget.py 另有 `time`——仅 `monotonic_ns` 默认时钟；offline_flow.py 另有 `tempfile`——套件内部 workspace）。禁随机源（random/secrets）、禁网络（socket/urllib/requests/http.client）、禁 `os.environ`（零 Secret 读取；一切外部输入注入）。
- **产品 import 白名单（offline_flow.py）**：`benchmarks.v4.baseline.budget`（本切片兄弟模块：BudgetLedger/CallEstimate 等）、`benchmarks.v4.baseline.orchestrate`（`run_repeats` + 公共错误类 `BaselineOrchestrationError`/`BaselineOrchestrationErrorCode`，仅用于 manifest 不可读的冻结错误语义）、`benchmarks.v4.baseline.report`（build_baseline_report/write_report_file）、`benchmarks.v4.baseline.fixtures`（load_registry/materialize_fixture）、`lima.contracts.codec`（canonical_encode/compute_content_digest——**唯一 lima import**）。
- **产品 import 白名单（budget.py）**：仅 stdlib（零 benchmarks/lima import）。
- **文件系统**：仅写调用方提供的 `output_dir`（run/report/marker 文档，exclusive 写）与套件内部 `tempfile.TemporaryDirectory`（fixture workspace——绝不物化进 output_dir，防 run_repeats 差集窗口污染与产物入库）。测试一律 tempfile/tempdir，零仓库写入。
- **网络/数据库/容器/远端写**：全禁（CI 离线/无 Secret/无付费）。付费路径不存在（唯一 evaluator 是注入的 fake）。
- **时钟**：默认 `time.monotonic_ns`，构造参数 `now_ns: Callable[[], int]` 可注入；不读取任何真实运行状态。

## 7. budget.py 冻结契约（CA R2/R3/R5/R9/R11）

### 7.1 错误族（R9 封闭七码 + 逐字消息；照录后不可漂移）

```python
class BudgetGateErrorCode(str, enum.Enum):
    BUDGET_SPEC_INVALID = "BUDGET_SPEC_INVALID"
    RUN_BUDGET_EXCEEDED = "RUN_BUDGET_EXCEEDED"
    BATCH_BUDGET_EXCEEDED = "BATCH_BUDGET_EXCEEDED"
    COST_NOT_PRE_BOUNDED = "COST_NOT_PRE_BOUNDED"
    USAGE_MISSING = "USAGE_MISSING"
    BUDGET_USAGE_INVALID = "BUDGET_USAGE_INVALID"
    REAL_RUN_LOCKED = "REAL_RUN_LOCKED"
```

| code | 逐字消息 | 触发 |
| --- | --- | --- |
| `BUDGET_SPEC_INVALID` | "The budget specification is invalid for this schema version." | 维度非 int/负数/bool；batch<per_run 分量；estimate 字段值非法 |
| `RUN_BUDGET_EXCEEDED` | "The per-run budget cap would be exceeded by this call." | 零预算首笔；恰达上限后下一笔；超单 run 任一维度（含壁钟已耗门） |
| `BATCH_BUDGET_EXCEEDED` | "The batch budget cap would be exceeded by this call." | 多 run 累计超批次任一维度 |
| `COST_NOT_PRE_BOUNDED` | "The cost of this call cannot be pre-bounded because pricing is unknown or incomplete." | 价格未知（pricing 任一维度 None）/estimate token 维度缺界 |
| `USAGE_MISSING` | "Usage was not reported for a completed call; missing usage is a violation, not zero." | usage 为 None 或三必报字段任一 None（不记 0，预留保留） |
| `BUDGET_USAGE_INVALID` | "Reported usage values are invalid for this schema version." | usage 值非 int/负数/bool；usage 载体非 CallUsage |
| `REAL_RUN_LOCKED` | "Real-run execution is locked; a future Maintainer authorization with a numeric budget is required." | 任何真实运行入口请求（本切片唯一行为） |

`BudgetGateError(ValueError)`（独立类，不子类化/复用既有错误类——IP-0028 先例）：属性 `code: BudgetGateErrorCode` + `field_path: str`；`__init__(code, field_path="")` 对非枚举成员/非 str 抛 `TypeError`；消息=目录逐字值、绝不嵌入任何数值/payload/secret（六连先例形状）。

### 7.2 公共符号面与签名（R11；`__all__` 逐字冻结）

```python
__all__ = [
    "BudgetGateError", "BudgetGateErrorCode", "BudgetLimits", "BudgetSpec",
    "BUDGET_DIMENSIONS", "CallEstimate", "CallUsage", "Pricing",
    "BudgetLedger", "LedgerSnapshot", "REAL_RUN_GATE_UNLOCKED",
    "require_real_run_unlock",
]
```

（`BUDGET_DIMENSIONS` 为 P&V 对 R11 清单的补充冻结——七维度序的唯一定义来源，检查序与快照键序依赖它；语义不改。）

```python
BUDGET_DIMENSIONS: Final[tuple[str, ...]] = (
    "cost_micro_usd", "calls", "prompt_tokens", "completion_tokens",
    "wall_ms", "download_bytes", "storage_bytes",
)
# 七维度=费用/调用数/Token（prompt 与 completion 两维）/运行时长/可控资源（download 与 storage 两维）。
# 顺序冻结：Spec 校验、reserve 检查序、快照维度键序均以此为准。

@dataclasses.dataclass(frozen=True, slots=True)
class BudgetLimits:
    cost_micro_usd: int
    calls: int
    prompt_tokens: int
    completion_tokens: int
    wall_ms: int
    download_bytes: int
    storage_bytes: int
    # __post_init__：每维度 type(x) is int（bool/float/str 拒）且 >= 0；
    # 违规 → BudgetGateError(BUDGET_SPEC_INVALID, "$.budget_limits.<dim>")。
    # 零预算合法：全 0 可构造（构造不报错；首笔 reserve 即拒——FR-06 负例）。

@dataclasses.dataclass(frozen=True, slots=True)
class BudgetSpec:
    per_run: BudgetLimits
    batch: BudgetLimits
    # __post_init__：按 BUDGET_DIMENSIONS 序逐一校验 batch[dim] >= per_run[dim]；
    # 违规 → BUDGET_SPEC_INVALID，field_path="$.budget.batch.<dim>"（如 $.budget.batch.cost_micro_usd）。
    # 非 BudgetLimits 成员 → TypeError（结构误用）。
    # 上限是显式 int，不存在 None 上限——未设上限=不引入该维度约束的行为不存在
    #（与 None≠0 正交：上限必填，None 只出现在 usage/pricing 侧且一律拒绝/视为未知）。

@dataclasses.dataclass(frozen=True, slots=True)
class CallEstimate:
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    wall_ms: int | None = None
    download_bytes: int | None = None
    storage_bytes: int | None = None
    # 纯载体；值校验在 reserve：非 None 值须 type(x) is int、非 bool、>= 0，
    # 违规 → BUDGET_SPEC_INVALID，field_path="$.estimate.<field>"。
    # None = 本笔调用未申报该维度上界（token 维 None → COST_NOT_PRE_BOUNDED，见 7.4）。

@dataclasses.dataclass(frozen=True, slots=True)
class CallUsage:
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    cost_micro_usd: int | None = None
    wall_ms: int | None = None
    download_bytes: int | None = None
    storage_bytes: int | None = None
    # 纯载体；判定在 record_usage（7.5）。判缺与否看 prompt/completion/cost 三必报字段；
    # None 仅在 wall/download/storage 维为合法缺席（按 0 记账面值，不改变"缺 usage=违规"判定）。

@dataclasses.dataclass(frozen=True, slots=True)
class Pricing:
    prompt_token_price_micro_usd_per_million: int | None = None
    completion_token_price_micro_usd_per_million: int | None = None
    # 每 token 维 int >= 0 或 None（None=价格未知，绝不视为免费/零）。
    # 非 None 值非 int/bool/负数 → BUDGET_SPEC_INVALID，field_path="$.pricing.<field>"。

REAL_RUN_GATE_UNLOCKED: bool = False
# 模块级冻结常量；本切片唯一合法值 False。无 setter、无环境变量开关、无解锁代码路径（R5；
# 源扫描断言由测试承载）。解锁=未来独立授权+数值预算+代码变更三前置（决策包 §11）。

def require_real_run_unlock() -> None:
    # 本切片无条件抛 BudgetGateError(REAL_RUN_LOCKED, "$.real_run_gate")。
    # 不读任何状态、不接受任何参数、不存在任何放行路径。
```

### 7.3 LedgerSnapshot 形状（测试断言唯一入口）

```python
@dataclasses.dataclass(frozen=True, slots=True)
class LedgerSnapshot:
    per_run: dict[str, dict[str, object]]  # run_id -> 账本（见下）
    batch: dict[str, object]               # 批级账本（见下）
    violations: int                        # USAGE_MISSING 事件累计（唯一计数来源）
# 账本形状（per_run 每值与 batch 同构）：
#   {"reserved": {六维度: int}, "consumed": {六维度: int}, "released": {六维度: int}, "calls": int}
# 六维度键序 = BUDGET_DIMENSIONS 去掉 "calls"（calls 独立计数，永不回收）。
# snapshot() 每次返回全新深拷贝嵌套 dict；经返回值改动不可能污染账本内部状态。
```

### 7.4 BudgetLedger.reserve 检查序（冻结线性化；零预算首笔=RUN_BUDGET_EXCEEDED `$.budget.per_run.calls`）

```python
class BudgetLedger:
    def __init__(self, spec: BudgetSpec, pricing: Pricing, *,
                 now_ns: typing.Callable[[], int] = time.monotonic_ns) -> None: ...
    # 构造时记录 start_ns = now_ns()（壁钟已耗基准）；spec/pricing 非正确类型 → TypeError；
    # run_id 规则：非空 str，否则 TypeError。
    def reserve(self, run_id: str, estimate: CallEstimate) -> None: ...
    def record_usage(self, run_id: str, usage: CallUsage | None) -> None: ...
    def record_failure(self, run_id: str, usage: CallUsage | None = None) -> None: ...
    def snapshot(self) -> LedgerSnapshot: ...
```

`reserve(run_id, estimate)` 逐步检查序（先拒先得；任一步拒=零入账、calls 不变）：

1. `run_id` 非空 str / `estimate` 为 CallEstimate 实例（否则 `TypeError`）；estimate 字段值校验（BUDGET_SPEC_INVALID `$.estimate.<field>`）。
2. **per_run 非 cost 维度门**（序 = calls → prompt_tokens → completion_tokens → wall_ms → download_bytes → storage_bytes）：
   - `calls`：该 run `calls 计数 + 1 > per_run.calls` → `RUN_BUDGET_EXCEEDED` `$.budget.per_run.calls`；
   - token/download/storage 维：`reserved + consumed + estimate值(None 按 0) > per_run.<dim>` → `RUN_BUDGET_EXCEEDED` `$.budget.per_run.<dim>`；
   - `wall_ms`：先**已耗壁钟门**——`(now_ns() - start_ns) // 1_000_000 >= per_run.wall_ms` 即拒（同 code，`$.budget.per_run.wall_ms`）；再 estimate 门（同上算术）。
3. **batch 非 cost 维度门**（同序，对批级账本与批级 calls 总数）→ `BATCH_BUDGET_EXCEEDED` `$.budget.batch.<dim>`。
4. **cost 不可预先界定门**（R3 封闭判定，绝不视为免费/零）：`pricing.prompt_token_price_micro_usd_per_million is None` → `COST_NOT_PRE_BOUNDED` `$.pricing.prompt_token_price_micro_usd_per_million`；completion 价 None → 同 code `$.pricing.completion_token_price_micro_usd_per_million`；`estimate.prompt_tokens is None` → 同 code `$.estimate.prompt_tokens`；`estimate.completion_tokens is None` → 同 code `$.estimate.completion_tokens`（此序）。
5. **cost 维度上限门**：worst-case cost（§7.6 公式）对 per_run → `RUN_BUDGET_EXCEEDED` `$.budget.per_run.cost_micro_usd`；对 batch → `BATCH_BUDGET_EXCEEDED` `$.budget.batch.cost_micro_usd`。
6. **入账**：per-run 与 batch 的 `reserved[六维] += estimate 值(None 按 0)+cost 估计`；该 run 未决预留队列追加本笔条目；该 run `calls += 1`、批级 `calls += 1`（**立即计数、永不回收**）。

**"恰达上限"语义**：`reserved+consumed+estimate == cap` 放行（含等号，全维度含 cost）；下一笔拒（R9 冻结；FR-06 正负例同源）。

### 7.5 record_usage / record_failure 记账语义（三态；None≠0）

`record_usage(run_id, usage)`（调用后核对）：
1. `usage is None` → `USAGE_MISSING` `$.usage`（violations+1；**不得记 0**；该笔预留保留为已占用——保守语义，本条为冻结文本）。
2. `usage` 非 CallUsage 实例（且非 None）→ `BUDGET_USAGE_INVALID` `$.usage`。
3. 字段扫描（序 = prompt_tokens → completion_tokens → cost_micro_usd → wall_ms → download_bytes → storage_bytes，首个违规即抛）：
   - 三必报字段（prompt/completion/cost）为 None → `USAGE_MISSING` `$.usage.<field>`（violations+1；账面零变动；预留保留）；
   - 任一字段非 None 且 `type(x) is not int`/bool/负数 → `BUDGET_USAGE_INVALID` `$.usage.<field>`；
   - wall/download/storage 为 None → 合法缺席，按 0 记账面值（不触发违规）。
4. 通过后入账：弹出该 run **最旧**未决预留（FIFO）：`consumed[六维] += usage 值(None 按 0)`（per-run 与 batch 双侧）；`released[六维] += max(0, 预留值 - usage 值)`（未耗差额自然回收）；`reserved[六维] -= 预留值`。无未决预留时 usage 仍入 consumed（诚实记账）、released 不变。**record_usage 不做上限复核**（reserve 预检是唯一门；超限耗用诚实入账，下一笔 reserve 自然被拒）。

`record_failure(run_id, usage=None)`（失败/取消）：
1. **回收该笔预留**：弹出最旧未决预留（若有）：`released[六维] += max(0, 预留值 - 已耗部分)`；`reserved[六维] -= 预留值`。
2. 若带部分 usage（CallUsage 实例，否则 TypeError；字段值校验同 7.5.3 但**全部字段允许 None**=未耗部分按 0）：该部分入 `consumed`（**已耗保留**）。
3. **calls 计数不回收**（拨出的调用就是拨出的调用）。无未决预留时为账面 no-op（仅入账给定部分 usage，若有）。
4. 此后该 run 后续 reserve 仍按 caps 正常检查（calls 已耗不回收 ⇒ calls 门以累计计数判定）。

### 7.6 worst-case cost 公式（R3 逐字冻结；决策包 §9 与此逐字一致）

```text
worst_case_cost_micro_usd =
    ceil(price_p × estimate.prompt_tokens / 1_000_000)
  + ceil(price_c × estimate.completion_tokens / 1_000_000)
```

（整数向上取整，stdlib `math.ceil` 实现；`price_p`/`price_c` 为 Pricing 两维度。）不可预先界定的封闭判定：① pricing 任一维度 None；② estimate 任一 token 维度缺界（None）——一律 `COST_NOT_PRE_BOUNDED`，**绝不视为免费/零**（None≠0 的定价侧体现）。token 维度同时做数量检查（超剩余 cap → RUN_BUDGET_EXCEEDED 对应维度 field_path）。

### 7.7 预算测试标准测价（测试 arrange 冻结值，非产品常量）

`Pricing(1_000_000, 1_000_000)`（每百万 token 一百万 micro-USD = 每 token 恰 1 micro-USD）⇒ worst-case cost 恰等于 `prompt_tokens + completion_tokens`（ceil 消失）；测试期望值由独立内联表达式重算（`_oracle_*` 先例），不复用产品实现。

## 8. offline_flow.py 冻结契约（CA R6/R7/R8/R11）

### 8.1 公共符号面（R11 六符号 + P&V 补充冻结一个纯函数；名字与参数集冻结）

```python
__all__ = [
    "EvaluatorOutcome", "FakeEvaluator", "OfflineSuiteResult",
    "make_fake_evaluator", "run_offline_baseline_suite",
    "synthetic_call_usage", "synthetic_e2e_payload", "write_synthetic_marker",
]
```

（`synthetic_call_usage` 为 R11 清单外的 P&V 补充冻结：guard 的紧上界 estimate 与"ledger consumed=10 笔合成 usage 逐维和"断言（AC-1 机器证据）都依赖该确定性纯函数可独立调用；`FakeEvaluator` 为 make_fake_evaluator 返回类型，一并导出以便类型标注。语义不改、参数集最小。）

### 8.2 evaluator 协议与合成数据（R8 冻结）

```python
@dataclasses.dataclass(frozen=True, slots=True)
class EvaluatorOutcome:
    payload: object                 # 合成 e2e payload（§8.3）
    usage: budget.CallUsage         # 合成 usage（§8.4）

def synthetic_e2e_payload() -> dict: ...   # 返回新构造 dict（冻结字面值见 §8.3）

def synthetic_call_usage(call_index: int) -> budget.CallUsage: ...
    # attempt 索引的确定性纯函数（call_index 从 0 起）：
    #   prompt_tokens    = 1000 + 10 * i
    #   completion_tokens = 500 +  5 * i
    #   cost_micro_usd    =  10 +  1 * i
    #   wall_ms           =  50 +  1 * i
    #   download_bytes = 0, storage_bytes = 0
    # 10 笔（i=0..9）逐维和：prompt=10045, completion=5225, cost=145, wall=545（PC3：断言以公式导出，禁裸字面量）。

class FakeEvaluator:
    calls: int                      # 调用计数（AC-2 注入计数器）
    def __call__(self) -> EvaluatorOutcome: ...
    def peek_estimate(self) -> budget.CallEstimate: ...
        # 下一笔调用的紧上界（= synthetic_call_usage(self.calls) 的五维 token/时/资源值）

def make_fake_evaluator(*, failures: dict[int, BaseException] | None = None) -> FakeEvaluator: ...
    # failures: {0-based 调用序号: 异常实例}——第 i 次调用抛出该异常（计数先 +1 再抛；
    # 失败注入变体，异常原样上抛由 run_baseline_attempt 分类入 taxonomy 样本保留）。
    # 成功调用返回 EvaluatorOutcome(synthetic_e2e_payload(), synthetic_call_usage(self.calls - 1))。
```

套件对 `evaluator` 参数的结构要求（冻结）：callable 且暴露 `peek_estimate() -> CallEstimate` 与 `calls: int`（即 FakeEvaluator 协议）；不满足 → `TypeError`。

### 8.3 合成 e2e payload（冻结字面值；e2e 形状为唯一最小面——scanner 需真实 findings 对象树、real-world 需 v2 结构）

```python
{
    "schema_version": 1,
    "name": "lima-offline-synthetic-e2e",
    "metrics": {"tp": 3, "fp": 1, "fn": 2},
    "by_split": {
        "validation": {"tp": 3, "fp": 1, "fn": 2},
        "holdout": {"tp": 3, "fp": 1, "fn": 2},
    },
    "case_results": [],
    "dataset": {"name": "lima-offline-synthetic-e2e-dataset", "source_kinds": ["synthetic"]},
}
```

结构识别依据（亲验 report.py `_recognize_evaluator_payload` L944-970 / `_is_e2e_shape` L894-905）：`schema_version==1` + 五键齐 + `metrics.tp/fp/fn` 非负 int；e2e 分支只读 metrics tp/fp/fn（`raw_candidates = tp + fp = 4`）。

### 8.4 套件主函数（R7 签名冻结）

```python
def run_offline_baseline_suite(
    spec_mapping, *,
    output_dir,
    evaluator,                       # FakeEvaluator 协议（§8.2）
    budget_spec,                     # budget.BudgetSpec（必填 kwarg，无默认——任何场景不得隐式获得"无限/免费"预算）
    pricing,                         # budget.Pricing（必填 kwarg，无默认）
    repeat=5,                        # 默认 5 ⇒ 5 cold+5 warm=10 attempts（⊇3/5 最小充分，R7 裁定）
    sources=None,                    # collect.PlatformSources 注入（转发 run_repeats；None=真实平台源）
    manifest_path=None,              # None ⇒ 冻结默认 evaluation_data/v4/baseline_manifest.json 只读解析
    fixture_key="archetype/minimal-python-repository",
) -> OfflineSuiteResult: ...
```

**执行序（冻结，①-⑦）**：① `load_registry()`（IP-0030 消费：12 键注册表只读校验）；② `materialize_fixture(fixture_key, workspace)` 到套件内部 `tempfile.TemporaryDirectory` workspace（绝不物化进 output_dir——防 run_repeats 差集窗口污染与产物入库；registry 校验失败/键不可物化原样上抛 `BaselineFixtureError`）；③ 构造 guarded evaluator（gate-before-invoke，见 §8.5）与 `BudgetLedger(budget_spec, pricing)`（默认时钟）；④ `run_repeats(spec_mapping, manifest, guarded, output_dir, repeat=repeat, sources=sources)`（manifest 由 `manifest_path=None` → 冻结默认路径解析；不可读 → `BaselineOrchestrationError(MANIFEST_UNREADABLE, "$.manifest_path")`——复用 orchestrate 公共错误类；spec 校验/role 门经 run_repeats 内部真实走过）；⑤ summary 返回后写 synthetic 标记 sidecar（R6 硬约束：**必须**在 run_repeats 返回**之后**——窗口内出现非 `-run-{int}` 名字破坏 result_paths 差集+int 排序）；⑥ `build_baseline_report(summary, evaluator_payload)`（payload=首个成功调用的 payload；无成功调用则 `synthetic_e2e_payload()`）→ `write_report_file(report, output_dir)`；⑦ 返回 `OfflineSuiteResult`。

**失败注入变体（冻结）**：evaluator 第 k 次调用抛异常 → guarded 记 `record_failure` 后原样上抛 → run_baseline_attempt 分类入 taxonomy 样本保留（EXECUTION_ERROR/EXECUTION_TIMEOUT/EXECUTION_CANCELLED），聚合照常（all-or-nothing sufficient/insufficient）；cold 成功 <3 或 warm 成功 <5 → status=`insufficient_sample`（`from_mapping` 冻结门，3/5）。**预算门拒绝（BudgetGateError）同经 taxonomy 路径保留为 EXECUTION_ERROR 样本，套件不中止**（诚实可观察；evaluator 计数器=0 是拒绝证明）。

### 8.5 guarded evaluator（R5 gate-before-invoke；调用序冻结）

```text
wrapper() =
  run_id = f"attempt-{c}"            # c = 该 guard 的 0-based 调用序号（= attempt_index，逐次顺序执行）
  try: ledger.reserve(run_id, evaluator.peek_estimate())
  except BudgetGateError: raise       # 未入账、不 record_failure（无预留可收）——被包裹 callable 未被调用
  try: outcome = evaluator()
  except BaseException as exc: ledger.record_failure(run_id); raise
  ledger.record_usage(run_id, outcome.usage)
  return outcome.payload
```

"外部调用=0"的证明形态：拒绝场景 fake evaluator `calls == 0`；正例场景 `calls == reserve 成功次数`。不采信网络层抓包/防火墙证据。

### 8.6 synthetic 标记 sidecar（R6 载体终裁）

```python
def write_synthetic_marker(document: dict, output_dir: str | pathlib.Path) -> pathlib.Path: ...
```

- **命名族**：`{run_spec_digest[:16]}-synthetic-{n}.json`（与 `-run-{n}.json`/`-report-{n}.json`/`.expert-timing.json` 三族零碰撞——`_RESULT_NAME_PATTERN` 只认 `-run-`（report.py L170）、write_result_file 只探测 `-run-` 两族（run.py L198-203）、write_report_file 只探测 `-report-` 族（L1272-1309），亲验）。
- **写出**：`canonical_encode(document)`（`lima.contracts.codec`，注册表同款先例）exclusive 写出。
- **序号语义（冻结，镜像 write_report_file 探测机制）**：`n` 取最小正整数槽位，探测序：槽位空闲 → 写入；槽位已持有**字节相同**副本 → 幂等返回该路径（不覆盖、不报错、不追加）；槽位持有**异字节** → 探测下一槽（`n+1`）。
- **marker schema（Packet 逐字冻结；七键封闭）**：

```python
{
    "marker_version": 1,
    "marker_type": "synthetic-offline-run",
    "run_spec_digest": <64-hex，与 summary.aggregate.run_spec_digest 逐字相等>,
    "aggregate_sha256": <64-hex，与 summary.aggregate_sha256 逐字相等>,
    "attempt_count": <int = len(summary.attempts)>,
    "budget_ledger_digest": <64-hex = compute_content_digest(
        {"per_run": snapshot.per_run, "batch": snapshot.batch, "violations": snapshot.violations}
    )，snapshot 取自写 marker 时的 BudgetLedger>,
    "declarations": [
        "excluded-from-v5-and-immutable-baseline",
        "not-real-acceptance-evidence",
        "offline-fake-evaluator",
        "synthetic-usage",
    ],  # 封闭集（排序冻结），不可增删
}
```

- **目录命名约定（建议级，非门禁）**：操作者宜用 `synthetic-` 前缀输出目录；机器可查载体以 sidecar 为准。
- **进程内隔离**：`OfflineSuiteResult.synthetic = True` 常量字段（无 False 路径）；独立类型，非 BaselineRunResult/BaselineRunSummary 子类。

### 8.7 OfflineSuiteResult（frozen dataclass，slots；字段全集冻结）

```python
@dataclasses.dataclass(frozen=True, slots=True)
class OfflineSuiteResult:
    run_spec_digest: str          # = summary.aggregate.run_spec_digest
    attempt_count: int            # = len(summary.attempts)（repeat=5 ⇒ 10）
    status: str                   # = summary.status（sufficient_sample | insufficient_sample）
    result_paths: tuple[pathlib.Path, ...]   # 每 attempt 一个 {digest16}-run-{n}.json
    aggregate_path: pathlib.Path
    aggregate_sha256: str         # 与 marker.aggregate_sha256 逐字相等
    report_path: pathlib.Path
    report_sha256: str
    marker_path: pathlib.Path
    marker_sha256: str            # marker 文件字节 SHA-256
    ledger_snapshot: budget.LedgerSnapshot
    evaluator_calls: int          # = evaluator.calls（AC-2 计数器）
    fixture_key: str
    fixture_file_count: int       # = FixtureMaterialization.file_count
    fixture_fingerprint: str      # = FixtureMaterialization.fingerprint（与注册表条目逐字相等）
    synthetic: bool               # 常量 True
```

## 9. 决策包契约（CA R4；工件=Allowed File #2，本 Packet 同期落盘）

独立文档 `docs/LIMA_PR3d_Real_Run_Budget_Decision_Pack.md`（不内嵌 Packet——面向未来授权轮次会被修订）。作者归属=P&V（C1）；Implementation 不写文档。十一节结构（节标题逐字冻结，测试断言）：

1. `## 1. Document Header`（doc id/version/date/status=`DRAFT-PENDING-AUTHORIZATION`）
2. `## 2. Candidate Models`（model/provider/version/pricing source/pricing date 列结构在，值 UNKNOWN）
3. `## 3. Pricing Sources and Dates`（UNKNOWN + 最小授权）
4. `## 4. Per-Run Estimates`（attempts/run=10 可写死：5 cold+5 warm，orchestrate 冻结语义；tokens/call、wall_ms、download bytes、storage bytes = UNKNOWN）
5. `## 5. Recommended Caps`（per_run/batch 七维度——估算×安全系数的符号式；数值 UNKNOWN）
6. `## 6. Over-Cap Behavior`（引用 budget.py typed error fail closed 语义——已交付机制的引用，可写）
7. `## 7. Machine Profile`（八字段对齐 `BaselineRunSpec._MACHINE_PROFILE_FIELDS`；目标机未指定 → UNKNOWN）
8. `## 8. Failed Run Handling`（taxonomy 保留 EXECUTION_ERROR/TIMEOUT/CANCELLED + 预留回收/已耗保留语义引用）
9. `## 9. Auditable Budget Formulas`（与 §7.6 公式逐字一致 + 批次聚合式）
10. `## 10. UNKNOWN Ledger`（逐项数值=UNKNOWN + 取得该数值的最小授权动作：谁批/做什么/一次还是持续）
11. `## 11. Authorization Request Checklist`（数值预算 + Maintainer 批准工件 + 门禁解锁须未来代码变更（本切片锁定）三项前置）

**反编造纪律（冻结）**：任何数值单元格只能是公式符号或字面 `UNKNOWN`；禁止"约/大约/参考价"式数字；禁止把合成示例 cap 写成真实估算；零预算事实以文字（"zero micro-USD"）表述，不用数字+货币单位邻接写法。静态测试扫描（TestDecisionPackArtifact）：必备节标题在、UNKNOWN 标注在位（定价/估算/机器 profile）、无未标注的美元/微美元数字字面量（token 拼接防自匹配，PC1）。

## 10. 测试矩阵（CA R10；两文件 1:1 模块映射；方法数 30+21=51 ∈ 预算 46-58，各 ≤35）

RED 锚点=各自 `import benchmarks.v4.baseline.budget` / `benchmarks.v4.baseline.offline_flow` 失败（lazy per-test import，两文件独立可 RED）。unittest 风格；一切外部输入注入（时钟/evaluator/计数器/spec/payload/sources）；tempfile/tempdir 零仓库写入。不触碰冻结面的测试（决策包静态校验、PC2 arrange 校验）在 RED 期按设计通过（其交付物=C1 文档/冻结上游，已存在）——RED 证据中逐项登记。

### 10.1 文件 A `tests/test_v4_baseline_budget.py`（30 方法）

| 类 | 方法数 | FR/AC | 方法清单 |
| --- | --- | --- | --- |
| TestBudgetSpecValidation | 5 | FR-03 | s1 七维度 int-only（bool/float/str 拒，subTest）；s2 负数拒；s3 batch<per_run 分量拒（field_path `$.budget.batch.<dim>`）；s4 零预算全 0 可构造；s5 LedgerSnapshot/账本字段全集（§7.3 形状） |
| TestReserveAndConsume | 4 | FR-03 正例 | r1 预留入账（reserved=estimate 六维 + calls=1）；r2 usage 入账 consumed、预留释放差额（released=max(0,res-usage)）；r3 calls 计数跨 run 累计（per-run 与批级）；r4 恰达上限放行（==cap 通过，含 cost 维） |
| TestFailClosedNegatives | 11 | FR-06/AC-2 负例矩阵 | n1 零预算首笔拒（RUN_BUDGET_EXCEEDED `$.budget.per_run.calls`；快照全零=calls 计数 0 的账面证明）；n2 恰达后下一笔拒；n3 超 per_run cost 拒（`$.budget.per_run.cost_micro_usd`）；n4 超 per_run tokens/calls 各拒（subTest 维度 field_path）；n5 壁钟已耗门拒（注入时钟，`$.budget.per_run.wall_ms`）；n6 超 batch 拒（两 run 累计，`$.budget.batch.<dim>`）；n7 缺 usage 必报字段→USAGE_MISSING 且账面不变（violations+1、预留保留不记 0）；n8 usage=None→同；n9 pricing None/缺 completion 维→COST_NOT_PRE_BOUNDED（非免费，subTest 两态）；n10 require_real_run_unlock→REAL_RUN_LOCKED（REAL_RUN_GATE_UNLOCKED is False、无状态读取）；n11 usage 负数/bool→BUDGET_USAGE_INVALID |
| TestFailureCancelAccounting | 4 | FR-06 取消失败记账 | f1 record_failure 回收预留（reserved→0、released+=res）；f2 带部分 usage 的失败=已耗保留（consumed+=部分、released+=差）；f3 calls 永不回收（失败后计数不变）；f4 回收后同 run 后续 reserve 仍按 caps 正常判（calls 门以累计计数拒） |
| TestGateHygiene | 3 | AC-2 锁定态 | g1 REAL_RUN_GATE_UNLOCKED is False（bool 常量）；g2 两新模块源扫描无网络 import（AST；token 拼接 PC1；扫描器正例+自身负例双态验证）；g3 两新模块无 os.environ/无解锁 setter（源扫描 + AST：REAL_RUN_GATE_UNLOCKED 唯一赋值为 False 常量） |
| TestLedgerInvariants | 3 | FR-03 不变量 | i1 reserved/consumed/released 恒等式（序列后 reserved==0、consumed==sum usage、released==sum max(0,res-usage)）；i2 注入时钟 wall_ms 门（单调计数时钟驱动已耗门）；i3 LedgerSnapshot 与操作序列一致（脚本化 ops 后快照=期望账本） |

### 10.2 文件 B `tests/test_v4_baseline_offline_flow.py`（21 方法）

| 类 | 方法数 | FR/AC | 方法清单 |
| --- | --- | --- | --- |
| TestOfflineSuiteEndToEnd | 6 | AC-1/FR-01 | e1 默认 repeat=5 → 10 attempts（cold 0-4/warm 5-9，PC3 基数=2×repeat）、status=sufficient_sample、目录文件集=11×`-run-`+1×`-report-1`+1×`-synthetic-1`、result_paths 序；e2 报告经 report.from_mapping 往返再冻结字节相同；e3 ledger consumed=10 笔合成 usage 逐维和（公式导出，PC3）+ evaluator_calls==10 + 快照 calls==10 + reserved==0 + violations==0；e4 registry 12 键只读消费（=len(FIXTURE_KEYS)，PC3）+ fixture 物化到 workspace 非 output_dir（fixture_fingerprint==注册表条目、output_dir 仅四族 JSON）；e5 PC2——arrange spec mapping 喂冻结校验器（spec from_mapping + validate_baseline_manifest + validate_role_bindings + manifest 3 数据集=bindings 全集）；e6 PC2——合成 payload 经 build_baseline_report 真实路径（run_repeats 直构 summary + 测试本地 payload 字面值；raw_candidates==tp+fp） |
| TestFailureRetention | 3 | AC-3/FR-04 | t1 注入失败 evaluator → 样本保留 taxonomy 码（EXECUTION_ERROR）；t2 cold 成功<3 → insufficient_sample（5 cold 全败变体）；t3 身份/digest 关联（marker.aggregate_sha256==summary==report；run_spec_digest 三方一致==spec digest） |
| TestSyntheticMarkerContract | 5 | AC-3/FR-04 | m1 marker schema 七键全集+marker_type/declarations 封闭集+双 digest hex64+budget_ledger_digest 重算一致；m2 canonical 字节（文件字节==canonical_encode(解析文档)）；m3 字节相同重写幂等（同路径返回、不覆盖不报错、不追加）；m4 异字节占用下一序号（槽 1 异字节 → 槽 2）；m5 run/report 文档本身不含 synthetic 字段（样本 17 键封闭 + 报告 declarations 仍恰冻结单值——IP-0029 面负例守护） |
| TestDecisionPackArtifact | 4 | AC-4/FR-05 | d1 两文档存在（Packet+决策包）；d2 必备节标题全集（11 节+status 字面值）；d3 UNKNOWN 标注在位（候选模型行/每 run 估算/机器 profile）；d4 反编造扫描（无数字+货币单位邻接字面量；扫描器 PC1 正例+自身负例双态验证） |
| TestOfflineHygiene | 3 | AC-1 | h1 offline_flow.py 无网络 import（AST，PC1）；h2 offline_flow.py 无 os.environ（源扫描，PC1）；h3 套件级拒绝场景 evaluator 计数器=0（零/微预算 spec → 10 EXECUTION_ERROR 样本、insufficient_sample、evaluator_calls==0、快照零入账）——与文件 A 呼应的套件路径证 |

### 10.3 PC1-PC3 静态预检（C2 冻结前置硬门；IP-0029/0030 两次机械修正教训的制度化）

- **PC1 自扫描 token 拼接一致性**：一切 hygiene 禁词表以拼接构造（如 `"sock" + "et"`、`"os." + "environ"`、`"micro" + "-USD"`），防测试源自身匹配；每个扫描器在测试内以"故意违规的正例字符串 + 自身源码负例"双态验证后方可用于冻结断言。
- **PC2 arrange 路径与冻结 shape 一致**：一切 arrange 产物（spec mapping、e2e payload、manifest、registry）至少各有一条测试把 arrange 结果喂给**冻结校验器本身**（`lima.baseline_run_spec.from_mapping` + `validate_baseline_manifest` + `validate_role_bindings` / `build_baseline_report` 真实路径 / `load_registry`）——arrange 漂移在冻结前暴露。
- **PC3 断言基数与 fixture 全集一致**：一切基数断言（12 注册表键、11 synthetic、3 datasets、10 attempts、17 样本字段、3/5 最小充分）必须同时等于冻结常量/冻结源导出值（`len(FIXTURE_KEYS)`、`len(SYNTHETIC_FIXTURE_KEYS)`、`len(FROZEN_DATASET_BINDINGS)`、`len(_SAMPLE_FIELDS)`、`_COLD_MIN_SUCCESSES`/`_WARM_MIN_SUCCESSES`、合成 usage 公式求和），禁止只写裸字面量。

预检证据（命令+输出）随 C2 Frozen Test Commit 一并交回；缺失=冻结无效（不得以 ALLOWED_ONCE 消化）。

## 11. ALLOWED_ONCE（一次性机械测试修正授权；CA 原文条件五项）

P&V 可在不新增 Coordinator 调用的情况下自行纠正一次纯测试机械缺陷并重新冻结，条件全部满足：①不改产品语义、公共接口、稳定错误码或文件范围；②仅限 fixture/arrange/import/lint/测试基础设施缺陷；③旧 Frozen Commit 保留；④修正前缺陷证据、修正后有效 RED、新 Frozen Commit 完整记录；⑤Implementation 未参与测试修改。涉及产品行为、验收语义或文件范围 → Decision Request。**PC1-PC3 预检缺失或失效不属于"机械缺陷"。授权仅一次，用尽即止。**

## 12. Stop Conditions（CA 13 条照录；触发即停并提交 Decision Request）

1. 任何情形需要真实付费、真实网络下载、真实扫描或真实模型调用（本轮预算 0 micro-USD、授权无）——包括"只跑一次真实调用验证门禁"。
2. 任何情形需要产生真实运行结论、或以 synthetic 数据冒充真实测量（含进入 #57 真实验收口径的任何表述）。
3. 任何情形需要解锁真实运行门禁、变更 REAL_RUN_GATE_UNLOCKED、或激活 ACTIVE（本切片仅锁定态可交付）。
4. 需要触碰任何 Do Not Touch 路径，或第 7 个及以后 Allowed File。
5. 需要 usage 缺失记 0 / None 当 0 / 编造定价数值 / 给决策包填任何未实测数字才能让测试通过。
6. synthetic 标记看似必须进入 RunResult/报告 schema（unknown field 或 declarations 扩展）才能满足 AC-3；或接线看似必须修改 orchestrate/run/report/scripts（R1 已裁定组合路径，偏离=DR）。
7. run_repeats 窗口内写文件的时序冲突无法以"run_repeats 返回后写 sidecar"化解（R6 硬约束）。
8. 测试方法数无法压进每文件 35 且无法合并断言（冻结前）；或 247 冻结回归/全量 discover 出现非预期失败。
9. 需要新依赖、网络、Secret、随机源、非注入式时钟读取真实运行状态。
10. 发现 IP-0031 占用冲突，或 base SHA 之后 main 出现冲突性实现。
11. schema 字段/错误码/逐字消息与 R2/R9 冻结清单冲突且无法照录。
12. 决策包在不编造数值前提下无法填齐 R4 必填结构。
13. 需要消耗 Maintainer 决策的任何事项（预算 ≤1，预期 0）。

## 13. 范围裁定 R1-R14 转录（CA-IP-0031-v1.0 原文照录）

**R1（Q1）Allowed Files 终形：恰 6 路径全 Add、Modify=零；新模块组合而非修改 orchestrate。**交付形态=两个新模块 + 两个新测试文件 + 两份新文档，恰 6 Add 路径、零 Modify/零 Delete（清单见 §5.1）。否决扩展 orchestrate.py/report.py/scripts 接线（三依据）：① `run_repeats(spec_mapping, manifest, execute, output_dir, *, repeat, sources)` 的 `execute` 参数与 `run_baseline_attempt` 的 `prompt_tokens/completion_tokens/cost_micro_usd` 参数就是冻结的注入/usage 通道（orchestrate.py L177-305、run.py L226-240 亲验），组合即可全链接线，修改无必要；② 上游六模块与 scripts/** 全为 tracked 冻结面，任何 Modify 破坏 247 冻结纪律与连续四轮零 Modify 先例（IP-0027..0030）；③ 若发现"必须改 orchestrate/run/report 才能接线"→ Stop Condition 6（DR），不得以"最小豁免"自行扩权。**Modify=零，无豁免清单。**

**R2（Q2）budget.py 契约：两级七维度 BudgetSpec + 三态 BudgetLedger。**BudgetLimits（frozen dataclass，int-only，`type(x) is int` 且 bool 拒绝，全 ≥0）：`cost_micro_usd`、`calls`、`prompt_tokens`、`completion_tokens`、`wall_ms`、`download_bytes`、`storage_bytes`。零预算合法（构造不报错；首笔 reserve 即拒）。BudgetSpec（frozen）：`per_run` + `batch`；构造校验 batch 每维度 ≥ per_run 对应维度（`BUDGET_SPEC_INVALID`，field_path 如 `$.budget.batch.cost_micro_usd`）。上限是显式 int，不存在 None 上限。BudgetLedger（显式三态记账，全 int，None 不入账）：`reserve(run_id, estimate)`（检查序：①真实运行门（仅真实入口路径）；②per_run 维度→RUN_BUDGET_EXCEEDED；③batch→BATCH_BUDGET_EXCEEDED；④cost 不可预先界定→COST_NOT_PRE_BOUNDED；通过→记预留并 **calls 计数立即+1（永不回收）**）；`record_usage(run_id, usage)`（usage 缺失/None→USAGE_MISSING fail closed 不得记 0、该笔预留保留为已占用——保守语义；值非 int/负数/bool→BUDGET_USAGE_INVALID；通过→consumed += actual、reserved -= 该笔预留、未耗差额自然回收）；`record_failure(run_id, usage=None)`（回收该笔预留；带部分 usage 则该部分入 consumed（已耗保留）；calls 不回收；此后该 run 后续 reserve 仍按 caps 正常检查）；LedgerSnapshot（frozen 返回对象：per_run/batch 两级 reserved/consumed/released/calls 逐维度账目 + violation 计数——测试断言唯一入口）。壁钟以注入式单调时钟执行（gate 构造参数 `now_ns: Callable[[], int]`，默认 `time.monotonic_ns`）；pre-call 壁钟检查=已耗壁钟 ≥ cap 即拒（RUN_BUDGET_EXCEEDED `$.budget.per_run.wall_ms`）。

**R3（Q3 前段）计价与"开销不可预先界定"。**Pricing（frozen dataclass）：`prompt_token_price_micro_usd_per_million: int`、`completion_token_price_micro_usd_per_million: int`（均 ≥0 int；价格缺失维度=None 或整表 None=价格未知）。worst-case cost 公式逐字冻结（见 §7.6）。不可预先界定的封闭判定：① pricing 任一维度 None；② estimate 任一 token 维度缺界（None）→ 一律 `COST_NOT_PRE_BOUNDED`，绝不视为免费/零。token 维度同时做数量检查（超剩余 cap → RUN_BUDGET_EXCEEDED 对应维度 field_path）。决策包可复核公式与此式逐字一致。

**R4（Q10）决策包：独立文档、P&V 于 C1 撰写、结构冻结、UNKNOWN 反编造纪律。**（全文见 §9 与决策包本体；作者归属=P&V——全部必填内容只依赖已冻结管线契约，不依赖 C3 实现；Implementation 不写文档。测试做静态校验，文档先在库不影响有效 RED——RED 锚点=模块 import 失败。）

**R5（Q5）默认拒绝门禁与"外部调用=0"。**budget.py 模块级冻结常量 `REAL_RUN_GATE_UNLOCKED: bool = False`（本轮唯一合法值）；公共函数 `require_real_run_unlock()` 在本切片无条件抛 `REAL_RUN_LOCKED`——不存在解锁参数、环境变量开关、解锁代码路径（源扫描断言无 setter/无 os.environ 解锁读取，hygiene 测试承载）。解锁=未来独立授权+数值预算+代码变更（三前置写入决策包 §11）。budget.py 与 offline_flow.py 全模块零网络代码（禁 socket/urllib/requests/http client import）；零 Secret 读取（禁 os.environ）；付费路径不存在（唯一 evaluator 是注入的 fake）。外部调用=0 的证明形态：guarded evaluator 调用序=gate 检查在前、被包裹 callable 在后；测试以注入计数器证（fake evaluator 携带调用计数，拒绝场景 counter==0、正例场景 counter==reserve 成功次数）。不采信网络层抓包/防火墙证据。

**R6（Q6）synthetic 标记载体终裁：独立 canonical sidecar（不进 RunResult/报告 schema）。**约束（亲验，决定性）：RunResult 样本层 17 键封闭且逐层 `_reject_unknown_fields`；报告未知键 fail closed 且 `declarations` 逐字冻结恰一值 `("baseline_mode_legacy_report_parameters_inert",)`——IP-0029 封闭枚举不可扩。裁定载体：`{run_spec_digest[:16]}-synthetic-{n}.json` canonical sidecar，exclusive 写出+字节相同幂等+异字节下一槽（§8.6）；与三族零碰撞（write_result_file 只探测 `-run-` 两族、report 探测 `-report-` 族、`_RESULT_NAME_PATTERN` 只认 `-run-`——亲验）。写出时序（硬约束）：必须在 run_repeats 返回之后写（差集+int 排序窗口）。marker schema 七键（§8.6 逐字冻结）。目录命名约定建议级。进程内隔离：OfflineSuiteResult 携带 `synthetic=True` 常量字段。

**R7（Q4/Q7）离线套件函数与"3 cold/5 warm"消解：repeat=5（5c+5w ⊇ 3/5）。**run_repeats 冻结语义=N+N；from_mapping sufficient 门=≥3 cold 成功+≥5 warm 成功。离线套件默认与测试一律 repeat=5 → 10 attempts。Packet 冻结此读法并声明：非对称精确 3+5 属 PR3-d 真实运行编排关注点，本切片不重写 run_repeats 聚合。套件主函数签名冻结（§8.4）；执行序①-⑦冻结；失败注入变体；budget_spec 与 pricing 为必填 kwarg（无默认）——显式性纪律。

**R8（Q1 尾/Q4）offline_flow 与上游只读消费契约；合成 payload 形状。**消费面全部只读零修改（§5.3/§6）；合成 evaluator 协议（§8.2）；合成 payload=e2e dict（§8.3——结构识别与投影路径亲验）；合成 usage=attempt 索引确定性纯函数（§8.4——ledger consumed=10 笔逐维和为 AC-1 机器证据）。

**R9（Q4 后段）typed error 族冻结（closed set + 逐字消息）。**七码逐字消息目录（§7.1 照录）；"恰达上限"语义：`reserved+consumed+estimate == cap` 放行（含等号），下一笔拒。

**R10（Q8）测试组织：两新文件（1:1 模块映射先例），各 ≤35；PC1-PC3 三项静态预检为 C2 冻结前置硬门。**（§10 全文；文件 A 预算 26-32/上限 35——本 Packet 定 30；文件 B 预算 20-26/上限 35——本 Packet 定 21。）

**R11 公共符号面与依赖纪律。**budget.__all__ / offline_flow.__all__（§7.2/§8.1；offline_flow 名字可由 Packet 微调、参数集与语义不变——本 Packet 未微调 R11 原名，仅按其授权补充导出 `synthetic_call_usage`/`FakeEvaluator`）。依赖纪律：两新模块 stdlib-only；唯一 lima import=`lima.contracts.codec`；禁网络/Secret/随机源；`benchmarks/v4/baseline/__init__.py` 零改动（blob `1c478346`，子模块直接导入先例）。

**R12（Q9）Done Commands 回归范围终裁：七文件定向必跑 + 全量 discover 必跑。**（§14 命令 2/3；全量 discover 是既有 CI 验收面，跳过=把回归风险转嫁给 CI。）

**R13（M10）PR/commit/预算纪律。**单 PR；commit/PR/branch 标题不含 close 族关键词与 #221/#57 编号组合（含否定句）；commit 前缀 `[IP-0031][PV]`/`[IP-0031][IMPL]`；每叶子 ≤8 调用 / ≤75 分钟 / ≤1 Maintainer 决策（预期 0）。PR 正文含 synthetic 隔离声明句与真实运行锁定声明句（§15 冻结文本）。

**R14 环境与镜像裁定。**worktree `D:\BaseAIProject\LIMA-ip0031-wt` @ `codex/ip-0031-offline-budget-gate`（建于 e8661fa，亲验）；Windows 执行设 `PYTHONUTF8=1`。Dockerfile/镜像无需变更（根 Dockerfile L68 `COPY --chown=lima:lima benchmarks ./benchmarks` 已整包复制，新子模块自动进镜像——亲验；本切片零新顶层路径、零 scripts 改动、零数据文件）。

## 14. Done Commands（worktree 根执行；Windows 设 `PYTHONUTF8=1`；成功判据=全绿/为空/恰 6 Add/blob 不变/ancestry exit 0）

```bash
# 0. 冻结前基线绿（C2 之前跑一次并登记；247 方法）
python -m unittest tests.test_v4_baseline tests.test_v4_baseline_result \
  tests.test_v4_baseline_manifest tests.test_v4_baseline_collection \
  tests.test_v4_baseline_cli tests.test_v4_baseline_report \
  tests.test_v4_baseline_fixtures -v

# 0b. 冻结前全量 CI discover 集合基线（登记；失败项须为既有状态而非本切片引入）
python -m unittest discover -s tests -v

# 1. 定向新测试（C2 冻结时全 RED 且归因 benchmarks.v4.baseline.budget/.offline_flow 缺席；C-final 后全绿；各文件 ≤35 方法）
python -m unittest tests.test_v4_baseline_budget tests.test_v4_baseline_offline_flow -v

# 2. 七冻结文件回归（70+33+28+26+27+29+34=247 必须全绿）
python -m unittest tests.test_v4_baseline tests.test_v4_baseline_result \
  tests.test_v4_baseline_manifest tests.test_v4_baseline_collection \
  tests.test_v4_baseline_cli tests.test_v4_baseline_report \
  tests.test_v4_baseline_fixtures -v

# 3. 全量 CI discover 集合回归（R12；cxx 轨道在内）
python -m unittest discover -s tests -v

# 4. 编译
python -m compileall -q benchmarks tests

# 5. 质量门禁（新 4 个 py 文件）
python -m ruff check benchmarks/v4/baseline/budget.py \
  benchmarks/v4/baseline/offline_flow.py \
  tests/test_v4_baseline_budget.py tests/test_v4_baseline_offline_flow.py

# 6. 文件边界：恰等于 Allowed Files 6 路径（全 Add，零 Modify/零 Delete）
git diff --name-status e8661fa25e45072bd81bf1013ed21b7c4a92d18b...HEAD

# 7. 冻结面守护（预期空）+ blob 不变（三 JSON 7ecb39f8/3ea94fcf/493f3da5；七测试 4cde7bdf/0a44cf7d/8e8ab0dc/35e6ec6a/edb2391b/b53176f5/34b397b7；六模块 8655067e/d29928e5/3615a75d/063ecb41/dd7aa365/0e4fb11f；__init__ 1c478346）
git diff --stat e8661fa25e45072bd81bf1013ed21b7c4a92d18b...HEAD -- \
  lima scripts benchmarks/v4/baseline/__init__.py benchmarks/v4/baseline/collect.py \
  benchmarks/v4/baseline/run.py benchmarks/v4/baseline/orchestrate.py \
  benchmarks/v4/baseline/report.py benchmarks/v4/baseline/expert_timing.py \
  benchmarks/v4/baseline/fixtures.py benchmarks/__init__.py benchmarks/v4/__init__.py \
  evaluation_data tests/test_v4_baseline.py tests/test_v4_baseline_result.py \
  tests/test_v4_baseline_manifest.py tests/test_v4_baseline_collection.py \
  tests/test_v4_baseline_cli.py tests/test_v4_baseline_report.py \
  tests/test_v4_baseline_fixtures.py Dockerfile .github pyproject.toml
git ls-tree HEAD -- evaluation_data/v4/baseline_manifest.json \
  evaluation_data/v4/python_mvp_support_matrix.json evaluation_data/v4/fixture_registry.json

# 8. ancestry（P&V 终验；<Frozen-Test-Commit-SHA> 由 C2 登记）
git merge-base --is-ancestor e8661fa25e45072bd81bf1013ed21b7c4a92d18b <Frozen-Test-Commit-SHA> && \
  git merge-base --is-ancestor <Frozen-Test-Commit-SHA> HEAD
```

ruff 一律 `--no-cache` 执行（P&V 验证与 Implementation 自检均然；陈旧缓存会假通过）。Pre-Freeze Harness Gate（P&V C2 冻结前五项，charter §3.1）：① 两测试文件完整 collect + 有效 RED（缺席态）；② 双态 stub 沙箱（两模块最小桩存在于临时目录副本，全部方法执行到行为断言处）；③ ruff 双态（缺席态+桩态）`--no-cache` 双过；④ compileall；⑤ 247+ 全量 discover 回归绿。

## 15. PR 与 Completion Summary 契约

**PR 正文必含冻结句（逐字）**：
- "All artifacts produced by the offline suite in this PR are synthetic offline validation outputs; they are not real measurements and must not be counted toward the real cold/warm evidence, AC-03, the V5 acceptance, or the immutable before baseline of the parent issue."
- "Real-run execution stays locked: the only behavior of the real-run entry point in this slice is REAL_RUN_LOCKED, and unlocking requires a future Maintainer authorization with a numeric budget plus a code change."
- "This PR does not auto-close the Source Issue."
- "Related to #221."（仅此关联形式；标题/正文任何位置禁 close/fix/resolve 族与 #221/#57 组合，含否定句）

**Completion Summary 必含**：final SHA；变更文件（对照 6 Allowed Files）；AC→Test→Result 表（AC-1..4 逐条）；实际命令与统计（Done Commands 0-7 全列，含两测试文件方法数 30/21、247 回归结果、全量 discover 结果、命令 7 blob 值）；边界检查（命令 6 恰 6 Add）；已知限制（零真实执行、锁定态、骨架估算、synthetic 排除清单）；Stop Condition 状态（13 条逐一"未触发"）；建议下一步（不自行激活）。

## 16. Packet Completion Definition

本 Packet 满足：无关键字段 TBD；R1-R14 全部转录入 §13 并在 §5-§10 落为可执行边界；FR-01..06/AC-1..4 正反向映射完整（§1/§10）；Done Commands 0-8 可执行（§14）；Stop Conditions 13 条在案（§12）；C1 双文档与 C2 冻结测试（RED 有效+PC1-PC3 证据+Harness Gate 五项）随本 Packet 交付后，Implementation 可直接派发。状态：READY-FOR-CODE。
