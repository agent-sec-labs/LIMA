# LIMA Implementation Packet — IP-0028 Baseline CLI Repeat Orchestration（CLI 接线 + 重复执行编排聚合 + IP-0027 两边界勘误）

> Packet ID：IP-0028
> Packet 版本：1.0（2026-09-26，阶段 P / C1 单次提交，不回填）
> 状态：**PHASE-P-IN-PROGRESS**（C2 Frozen Test Commit 落盘后 READY-FOR-CODE 由 commit SHA 链与
> #214 Delivery Ledger 反映——SHADOW 模式单 PR 拓扑，影子证据锚点 = C1/C2 commit SHA）
> Packet 作者：lima-packet-verification（P&V）
> Coordinator Assignment：CA-IP-0028-v1.0（2026-09-26；本 Packet 的约束权威，R1-R10 全文照录登记于 §13）
> 精确基线：`98b8a35e4fbc8f11d809ec7ad2b571c10248ded5`（完整 40 位 = PR #215 合并点 = origin/main，P&V 亲验
> worktree HEAD = 该 SHA，tracked 零修改）
> 工作分支：`codex/ip-0028-cli-baseline`（worktree `D:\BaseAIProject\LIMA-ip0028-wt`）
> Source Issue：#214（叶子，open，[V4-I01][P0] PR3-a）；Parent #57 仅背景，保持打开
> Frozen Test Commit：C2（本 Packet 提交后由 P&V 产生；精确 SHA、RED 证据与验收面摘要登记于 C2 commit
> message 与 P&V 阶段 P 交付记录，本文件按"单次提交"纪律不回填）

---

## 0. 交付物角色声明（强制，先于一切）

本切片 Allowed Files 恰 7 路径（CA §Workspace）：P&V 阶段产物 2 个（本 Packet + C2 冻结测试
`tests/test_v4_baseline_cli.py`）；Implementation 阶段产物 5 个（Add 1：`benchmarks/v4/baseline/orchestrate.py`；
Modify 4：`benchmarks/v4/baseline/run.py`（**仅限 §8 R8/R9 勘误枚举范围**）与三 `scripts/run_*.py`（**仅限 §7.6
接线模板**））。**`orchestrate.py` 与四处 Modify 是 Implementation（阶段 C3+）的实现交付物，不是 P&V
fixture。** P&V 的交付物只有本 Packet（C1）与冻结测试文件（C2）。

本轮**零 `lima/**` 改动、零 `evaluation_data/**` 改动、零 `collect.py`/`expert_timing.py`/`__init__.py`
改动、零四个冻结测试文件改动（含零追加）**。若实施中发现"必须超出 §6/§9 枚举范围才能满足验收"：
停止，提交 Decision Request，不得静默扩张。

## 1. 需求映射（Packet 头）

```text
Source Issue：#214（父 #57）
Issue specification revision：2026-09-26 创建版正文（Coordinator GitHub API 匿名亲验：Scope 1-6、
  Non-goals、AC-1..4、Packet IP-0028 占用检查）
Covered requirements：FR-01…FR-06、AC-1…AC-4（本切片范围；FR-06 为声明式受限部分，见 §14）
Not covered requirements：见 §5 Non-goals（= Assignment Not-covered 11 条全文照录）
Delivery role：vertical-slice（#57 PR3-a：CLI 接线与重复执行聚合）
Issue closure impact：PARTIAL（#214 按 Ledger 走 MANUAL-AFTER-POST-MERGE-AUDIT；本 IP 不宣告任何 Issue 完成）
Upstream IP/merge commits：IP-0024（lima/baseline_run_spec.py）、IP-0025（lima/baseline_run_result.py）、
  IP-0026（evaluation_data/v4/baseline_manifest.json，merge 2f4b8bb）、IP-0027（benchmarks/v4/baseline/
  三模块 + 26 冻结用例，merge abd9d02；Packet 勘误 fd37d4e / merge 98b8a35）——均在基线内冻结，本轮只读
  消费；唯一例外 = §8 对 run.py 两处点的受控勘误（Maintainer T1/T2 显式授权）
```

FR-01..FR-06 为 Coordinator 对 #214 "Scope (this slice)" 1-6 的规范化编号（语义不变，CA-IP-0028-v1.0 §Goal）；
AC-1..AC-4 沿用 Issue 原文编号。

| ID | 内容（#214 Scope 1-6） | 本 Packet 贡献方式 |
|---|---|---|
| FR-01 | 三脚本 CLI 接线（仅新增 `--run-spec`/`--baseline-output`/`--repeat` 三参数 + 调用现有 evaluator/原语）；无新参数时默认行为逐字节等价（AC-1） | §7.1 参数面 + §7.6 三脚本接线模板 + §7.7 三层等价证明（R1/R2/R3/R6） |
| FR-02 | 重复执行编排与聚合：N cold + N warm、attempt_index 全局分配、多样本聚合件落盘、nearest-rank p50/p95、3/5 下限不足 → `insufficient_sample`（消费 IP-0025 冻结聚合，不另造实现） | §7.3 `run_repeats`（R4/R5）；聚合只经冻结 `lima.baseline_run_result.from_mapping` |
| FR-03 | 历史保护：每次 attempt 独立 result 不覆盖；失败 run 写入 failure taxonomy 并保留；聚合含失败样本 | 复用 IP-0027 writer/taxonomy 零改动；§7.3 编排语义（R5） |
| FR-04 | SF-01 入口：CLI 编排入口在首次执行前过完整门栈（spec 层 → 冻结 manifest 交叉 → role 门）；自洽角色对调/移动引用/缩写 SHA/指纹漂移四类零执行负例 | §7.2 适配层门栈一次性前置 + §10 SF-01 负例（R7） |
| FR-05 | 两边界裁定落地 + 测试：(a) sidecar 碰撞孤儿 result；(b) 错误 field_path 含完整本机路径（IP-0027 界面勘误） | §8 IP-0027 interface erratum（R8/R9 精确枚举） |
| FR-06 | 全离线默认 CI：无网络、无 Secret、无付费模型、无新依赖；卫生源扫描 | §6 导入方向冻结 + §10 卫生测试（R10） |

| ID | 内容（#214 验收） | 验证方式 |
|---|---|---|
| AC-1 | 三脚本无新参数行为逐字节等价 | TestLegacyEquivalence ×3（stdout 字面量 + 退出码 + 编排入口零调用）+ TestScriptWiring ×3 + Done Command 6b 结构逐 hunk 审查（R6 三层） |
| AC-2 | `--repeat` 编排满足 3/5 下限语义；percentile nearest-rank；聚合件只经冻结 from_mapping 产出 | TestOrchestrationSemantics（N=5 sufficient + nearest-rank 手算抽查；N=3/N=1 insufficient 四 percentile null；N=2 计数/命名/索引） |
| AC-3 | attempt 件与聚合件独占创建、同 spec 重跑总新增文件、失败样本带 taxonomy 保留在聚合中；SF-01 四类零执行负例全过 | TestOrchestrationSemantics（重跑/失败保留/BaseException）+ TestGateStackNegatives（execute=0、文件=0） |
| AC-4 | 冻结面与生产扫描语义零改动；run.py 改动恰在 R8/R9 枚举范围内；全离线 | Done Commands 5/6/6b/7（边界与冻结面 diff）+ TestWriterErratum + TestPublicSurfaceAndHygiene |

## 2. Design Input Manifest

| Input ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001 | Standard | `docs/LIMA_PACKET_AND_VERIFICATION_AGENT_RESPONSIBILITY_CHARTER.md` | 基线 98b8a35 内版本 | P&V 角色边界、Pre-Freeze Harness Gate、RED/冻结纪律 | normative | 无冲突 |
| DI-002 | Issue | Source Issue #214 正文（Scope 1-6、Non-goals、AC-1..4、Packet 段） | 2026-09-26 创建版（Coordinator API 匿名亲验转述于 Assignment） | FR-01..06、AC-1..4 | normative | 无冲突 |
| DI-003 | Issue | Parent #57（FR-02/03 原文、File ownership、Required tests、PR plan） | 基线 98b8a35（Assignment 亲验） | Modify 权限三脚本"仅可新增三参数并调用现有 evaluator"（R2 解释登记见 §13 R2）、PR3 未勾 | 边界 normative / 其余 background | 字面 "--output" 与既有报告参数冲突 → 以 CA R2 裁定为准 |
| DI-004 | Decision | CA-IP-0028-v1.0 全文（R1-R10、Allowed Files 7 路径、验收命令全文、Stop Conditions、ALLOWED_ONCE） | 2026-09-26 | 本切片全部边界与裁定 | normative（本切片最高活动权威） | 与历史文档冲突时以 Assignment 为准 |
| DI-005 | Intent | `.pv_tmp/INTENT_RECORD_IP-0028_2026-09-26.md`（INTENT-IP-0028-20260926-01；M1-M10/I1-I7/A1-A5/Q1-Q7） | 2026-09-26 | 需求语义、授权原文、取证（I1 聚合须组合多样本、I2 --output 碰撞、I3 注入范式、I5 边界位点） | normative（经 Assignment 消费） | 无冲突 |
| DI-006 | Code | `benchmarks/v4/baseline/run.py`（323 行全文亲读 @ 98b8a35：`write_exclusive` L154-166（L165 `str(path)`）、`write_result_file` L169-215（L189 `str(directory)`、L191-194 单名占用探测、L196/204-209 先 result 后 sidecar）、`run_baseline_attempt` L218-322（L255 `str(directory)`、门序 metric→目录→spec→manifest 交叉→role 门→才执行、samples=[sample] 单样本、BaseException 落盘后重抛） | 98b8a35 | §8 勘误位点精确枚举；§7.2/§7.3 复用面 | normative（冻结契约，勘误例外见 §9） | 无冲突 |
| DI-007 | Code | `lima/baseline_run_result.py`（555 行全文亲读 @ 98b8a35：`_COLD_MIN_SUCCESSES=3`/`_WARM_MIN_SUCCESSES=5` L67-68、field_path 口径 L124-126、nearest-rank L457-461、`from_mapping` L517-555 all-or-nothing、`to_canonical_value`/`canonical_bytes`/`content_digest` L487-514） | 98b8a35 | FR-02 聚合唯一实现来源（本切片不得另造，C6） | normative（冻结契约，只读） | 无冲突 |
| DI-008 | Code | `lima/baseline_run_spec.py`（752 行 @ 98b8a35：`from_mapping` L629-651、`load_baseline_run_spec` L654-669（str 路径；malformed JSON → INVALID_FIELD_VALUE "$"）、`validate_baseline_manifest` L672-752（无 role 比对）、`BaselineRunSpec.to_canonical_value` L598） | 98b8a35 | §7.2 适配层 spec 加载与门栈 | normative（冻结契约，只读） | 无冲突 |
| DI-009 | Code | `benchmarks/v4/baseline/collect.py`（255 行 @ 98b8a35：closed 10 码、稳定消息 L87-92 亲验无路径——`"The requested output directory is unavailable."` / `"The requested output path already exists and is never overwritten."`） | 98b8a35 | §7.0/§8 错误族复用与消息真值；**整文件零改动** | normative（冻结契约，只读） | 无冲突 |
| DI-010 | Data | `evaluation_data/v4/baseline_manifest.json`（3 datasets / 13 entries @ 98b8a35） | 98b8a35 | manifest 默认路径真值；测试正例共享工件；FROZEN_DATASET_BINDINGS 注册表真值（IP-0027 Packet §7.3.1 + fd37d4e 勘误后） | normative（冻结数据，只读） | 无冲突 |
| DI-011 | Code | 三脚本全文亲读 @ 98b8a35：`scripts/run_e2e_evaluation.py`（argparse L135-147，`--dataset`/`--output-dir`/`--reuse-dataset`；main() 无参、返回 None、底部 `main()` 无 SystemExit 包裹）、`scripts/run_real_world_evaluation.py`（L123-140，既有 `--output` L130 报告路径默认 ""，`--cache` L129；main(argv)->int）、`scripts/run_repair_evaluation.py`（L60-69，既有 `--output` L66；main(argv)->int） | 98b8a35 | R2 碰撞事实、§7.6 接线位点与逐脚本模板差异（ROOT 类型/main 形态） | normative（受 CA Modify 授权约束） | 无冲突 |
| DI-012 | Test | 四冻结测试文件（157 方法亲验 @ 98b8a35）：`tests/test_v4_baseline.py`（70）/`test_v4_baseline_manifest.py`（28）/`test_v4_baseline_result.py`（33）/`test_v4_baseline_collection.py`（26，`_CountingExecute` L140、四类零执行负例 L433-492、深拷贝变异、`_fake_sources` 注入、卫生扫描 L320、OUTPUT_* 断言仅 code 无 field_path L764-771/L799-806 亲核） | 98b8a35 | §10 测试组织与负例范式参照；§8.3 向后兼容论证；回归基线 | normative（冻结测试，只读，零改动含零追加） | 无冲突 |
| DI-013 | Decision | 先例：IP-0027 Packet（`docs/LIMA_Implementation_Packet_IP-0027_Baseline_Collection_Foundation.md`，结构/单次提交/ALLOWED_ONCE 纪律）、IP-0026 Packet、fd37d4e 勘误（`docs/LIMA_Erratum_IP-0027_Packet_Fingerprint_Transcription.md`——哈希真值程序化复制粘贴纪律） | 98b8a35 | 本 Packet 结构、erratum 纪律、§9 登记方式 | normative（流程先例） | 无冲突 |
| DI-014 | Finding | 本轮 P&V 亲验（worktree @ 98b8a35，2026-09-26）：冻结回归 157 方法 `OK`（0.262s，exit 0）；三脚本源码卫生 token（os.environ/getenv/socket/urllib/requests）零命中；`tests/`、`scripts/` 均无 `__init__.py`（脚本加载须 importlib 按路径）；`lima/console.py::configure_utf8_stdio` 对无 `reconfigure` 的 StringIO 无操作（redirect_stdout 下安全）；`BaselineRunSpec.to_canonical_value` 存在（L598）；`evaluation_harness.comparison_summary` 对哨兵 harness 结果的最小键集亲测可运行；Python 3.12.4 / ruff 0.16.5 / bandit 1.9.4；三脚本 legacy 等价预期字面量已在 worktree 外沙箱由当前（未改动）脚本程序化推导（§7.7/§10） | 2026-09-26 | 冻结前基线绿、测试机制、等价字面量真值 | evidence | 无冲突 |
| DI-015 | Standard | `docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md`、`docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md` | 基线 98b8a35 | 交付流程、Completion Summary、PR 文案约束 | normative（流程） | 无冲突 |

## 3. Explicitly Rejected Inputs

1. **任何 `lima/**` 产品代码改动**（含在冻结契约上加 role 比对、为 orchestrate 添加 lima 侧辅助）——聚合、
   校验、canonical 编码全部经冻结函数完成；改冻结语义 = Stop Condition 第 5 条（升级 Maintainer）。
2. **`benchmarks/v4/baseline/collect.py` / `expert_timing.py` / 三个 `__init__.py` 的任何改动**——错误族闭合
   10 码不可加成员；编排层新 typed error 族定义于 `orchestrate.py`（§7.0），不复用不子类化冻结 error 类。
3. **统一顶层新命令 / 新 scripts 文件 / 第 4 个 CLI 参数名**（含 `--manifest`、分立 cold/warm 计数、
   `--reviewer` 类）——R1 排除 + Stop Condition 第 3 条；与 #57 File ownership 字面冲突。
4. **复用 `--output` 按 `--run-spec` 有无变义**（Intent Q2 选项 b）——R2 明文否决（模式分裂语义、run_e2e 无
   `--output` 无法给出一致面、破坏 AC-1）。
5. **另造聚合/percentile/编码实现或绕开 `from_mapping` 手工拼 status**——C6/AC-2；聚合件 status/percentiles
   只能由冻结 `lima.baseline_run_result.from_mapping` 计算。
6. **为 attempt 供给 `prompt_tokens`/`completion_tokens`/`cost_micro_usd` 或经 CLI 写 expert sidecar**——
   Not-covered 4/8：编排层一律 None、不传 expert_session（诚实缺席，不虚构计量）。
7. **计数类报告字段（Signal/Issue/Hypothesis、压缩率、legacy projection、专家分钟入报告）**——PR3-b；
   不进 RunResult 本体也不进 sidecar（本切片无报告面）。
8. **psutil 或任何新依赖；网络/环境读取/Secret**——R10；orchestrate import 白名单见 §6（导入方向冻结）。
9. **四个冻结测试文件的任何修改（含追加测试）与任何 run 产物/RunSpec 工件提交**——冻结 digest 与 RED 证据
   链不可破坏；测试临时输出一律 tempfile。
10. **`run.py` 超出 §8 R8/R9 枚举的任何改动**（含"顺带重构"、新 import、签名/错误码/消息改动）——Stop
    Condition 第 2 条。
11. **新数据集/fixture 创作或负例专用 fixture 数据文件**——反过拟合纪律：负例基于冻结 manifest 与 spec
    arrange 的深拷贝变异；正例与真实冻结 manifest 共享同一工件。

## 4. Goal / Non-goals

**Iteration hypothesis**：#57 PR3-a 的"CLI 接线与重复执行聚合"可以完全由"1 个共享编排模块
`benchmarks/v4/baseline/orchestrate.py` + 三脚本各一处参数面接线（add_baseline_arguments + 早退分支）+
`run.py` 两处勘误（§9）"离线交付：`--run-spec`/`--baseline-output`/`--repeat` 驱动同一 RunSpec 的 N cold +
N warm 重复执行（attempt 件经冻结 `run_baseline_attempt` 写出），聚合件经冻结 `from_mapping` 组装、经现有
`write_result_file` 落盘（共享 digest 前缀顺延序号）；SF-01 门栈在编排入口一次性前置（四类零执行负例）；
无新参数时三脚本 legacy 行为逐字节等价（三层证明）。**measurement** = C2 冻结时有效 RED
（`benchmarks.v4.baseline.orchestrate` 子模块缺席，模块级 import `ModuleNotFoundError`，collection 成功）→
阶段 C3+ 实现后定向新测试全绿 + 冻结回归 157 全绿 + `git diff` 相对基线恰为 7 个 Allowed Files。

**Goal**：(a) 三脚本一致基线参数面（三参数 + 正值守卫 + 目录必填 fail closed）；(b) 重复执行编排
（全局 attempt_index、门栈前置、Exception 继续 / BaseException 落盘后重抛、partial 不聚合）；(c) 多样本
聚合件（只经冻结 from_mapping；nearest-rank p50/p95；3/5 下限 all-or-nothing；共享前缀顺延序号落盘）；
(d) SF-01 编排级零执行负例（四类）；(e) IP-0027 两边界勘误落地（§8）；(f) AC-1 逐字节等价（三层证明）；
(g) 全离线、无 Secret、无付费、无新依赖。

**Non-goals**（= Assignment Not-covered 11 条全文照录；全团队不得扩张）：

1. LlamaFactory `7fcf5b3b130e5713b52415bb7404c476fada9c8c` 真实重放与物化（独立叶子；FR-06
   needs-decision 门；本切片零真实 run）。
2. FR-04/FR-05 报告面（Signal/Issue/Hypothesis 计数、压缩率、legacy projection、专家分钟入报告）——PR3-b；
   不进 RunResult 本体也不进 sidecar。
3. FR-06 数据集覆盖扩展（空仓、最小 Python 仓 fixture 创作）——PR3-c。
4. 真实 token/cost 实测与真实 cold/warm 缓存态控制——PR3-d；本切片 attempt 的
   `prompt_tokens/completion_tokens/cost_micro_usd` 一律 None（诚实缺席，不虚构），cold/warm 区分仅由冻结
   mode 字段承载。
5. 预算上限的数值与检查机制（Q7 裁定：本切片仅声明式；数值与 enforcement 留 PR3-d，届时需 Maintainer 定
   数值）。
6. 修改扫描器、Prompt、标签、数据 split、默认 analyzer、生产 Audit/Queue/Sandbox/Repair/Frontend 逻辑；
   `lima/**`、`evaluation_data/**`、`benchmarks/v4/baseline/collect.py`、`expert_timing.py` 任何改动。
7. 统一顶层新命令/新 scripts 文件（R1 裁定排除）；第 4 个 CLI 参数名（含 --manifest、分立 cold/warm
   计数）——出现即 Stop Condition。
8. expert timing 会话的 CLI 接线（本切片 orchestration 不传 expert_session，不写 sidecar）。
9. 提交任何 run 产物/RunSpec 工件进版本库（测试一律 tempfile）。
10. psutil 或任何新依赖（argparse 为 stdlib，允许）。
11. #214/#57 关闭判断、#57 PR3 行勾选（合并后由 Coordinator 按证据推进，仅实际证明项）。

## 5. 冻结接口消费清单（本轮只消费，零改动；行号 = 98b8a35 亲读）

| 接口 | 消费方 | 消费方式 |
|---|---|---|
| `lima.baseline_run_spec.load_baseline_run_spec`（L654-669） | orchestrate 适配层 | spec 文件加载（str 路径；malformed JSON → `BaselineRunSpecError(INVALID_FIELD_VALUE, "$")` 冻结语义透传） |
| `lima.baseline_run_spec.validate_baseline_manifest`（L672-752） | orchestrate 适配层门 2 | 冻结交叉（fingerprint/身份/内部 role 交叉/重复仓库）冻结码透传 |
| `lima.baseline_run_spec.BaselineRunSpec.to_canonical_value`（L598） | orchestrate 适配层 | 已验证 spec 的 canonical dict 作为 `run_repeats` 的 spec_mapping（每 attempt `from_mapping` 幂等重验、digest 一致） |
| `lima.baseline_run_spec.BaselineRunSpecError`/`ErrorCode` | orchestrate / 脚本分支 | 门 1/2 失败原样上抛；脚本分支捕获渲染；**不得捕获后改码** |
| `lima.baseline_run_result.from_mapping`（L517-555） | orchestrate 聚合 | **唯一**聚合组装入口：`{"schema_version": 1, "run_spec_digest": <digest>, "samples": [2N 样本 dict]}`；status/percentiles 只由其计算 |
| `lima.baseline_run_result.BaselineRunResult` | orchestrate | attempt 结果与聚合结果载体；`canonical_bytes()`/`content_digest()`；`samples[0]`（_FrozenMapping `.items()`）取样本 dict |
| `lima.baseline_run_result.BaselineRunResultError` | 脚本分支 | 捕获渲染（聚合组装理论失败路径） |
| `benchmarks.v4.baseline.run.run_baseline_attempt`（L218-322） | orchestrate `run_repeats` | 每 attempt 调用（内部再过全部门，幂等无害）；**签名与门序零改动** |
| `benchmarks.v4.baseline.run.write_result_file`（L169-215，§8 勘误后） | orchestrate 聚合落盘 | 聚合件经现有 writer 落盘（复用不修改）：独占创建、canonical bytes、共享前缀顺延序号（R8 后含双占用探测） |
| `benchmarks.v4.baseline.run.validate_role_bindings` / `FROZEN_DATASET_BINDINGS`（L60-141） | orchestrate 适配层门 3 | SF-01 role 门（注册表第三方真值） |
| `benchmarks.v4.baseline.collect.BaselineCollectionError`/`ErrorCode`（closed 10 码） | orchestrate / 脚本分支 | 目录不可得（`OUTPUT_DIRECTORY_UNAVAILABLE`，field_path `$.output_dir`）复用冻结码；脚本分支捕获渲染 |
| `evaluation_data/v4/baseline_manifest.json`（@ 98b8a35） | orchestrate 默认 manifest 路径 + 测试正例 | 只读加载；默认路径冻结见 §7.2 |


**冻结注册表真值（`FROZEN_DATASET_BINDINGS`，逐字取自 `evaluation_data/v4/baseline_manifest.json`，本表由 P&V 脚本程序化生成——fd37d4e 纪律）：**

| dataset name | role | fingerprint |
|---|---|---|
| `lima-popular-python-calibration-v1` | `calibration` | `049d69b25731e51f75a800c5c406ab2d8faef1257d7dacfb275f9734b407b986` |
| `lima-popular-python-external-holdout-v2` | `external-holdout` | `23d4ef1da097e6af3d1099546d3cb6167b8964ecdc23f546ad5a835f342b284a` |
| `lima-real-world-pilot-v1` | `development` | `7d88728caca8bc3387802b7bdaa09b59e5ffe1fede21a71c3d314bd63eb0c106` |

**SF-01 盲区继承声明**：`validate_baseline_manifest` 不比对 spec/manifest 两侧 dataset role（IP-0027 Packet
亲证 L729-739）；编排层门 3 = `validate_role_bindings`，与 IP-0027 runner 内门一致（幂等）。

## 6. 文件边界（= Assignment §Workspace Allowed Files，恰 7 路径）

**Add — P&V 阶段产物（C1/C2）：**

1. `docs/LIMA_Implementation_Packet_IP-0028_Baseline_CLI_Repeat_Orchestration.md` — 本文件（C1）。
2. `tests/test_v4_baseline_cli.py` — 本轮唯一新测试文件（C2 冻结，27 方法 ≤ 35 上限，§10）。

**Add — Implementation 阶段产物（C3+）：**

3. `benchmarks/v4/baseline/orchestrate.py` — 共享编排模块（§8 公共面；禁止另造聚合/编码/错误族、网络/
   环境读取、修改冻结契约语义）。

**Modify — Implementation 阶段产物（C3+）：**

4. `benchmarks/v4/baseline/run.py` — **仅限 §8 R8/R9 勘误范围**：(a) `write_result_file` 序号分配双占用
   探测（恰 1 处循环条件）+ 对应 docstring 行；(b) 三处 field_path 字面量（L165→`"$.output_path"`、
   L189→`"$.output_dir"`、L255→`"$.output_dir"`）+ 对应 docstring 更新。**其余零改动**（无新 import、无
   签名/错误码/消息改动）。
5. `scripts/run_e2e_evaluation.py` — 仅限：`add_baseline_arguments(parser)` 一行 + parse 后
   `if args.run_spec is not None:` 早退分支（§7.6 模板：惰性 import、输入制备一次、execute 闭包、错误呈现
   与摘要行、`sys.exit(2)`/`return`）。
6. `scripts/run_real_world_evaluation.py` — 同 5（`return 2`/`return 0` 形态）。
7. `scripts/run_repair_evaluation.py` — 同 5（`return 2`/`return 0` 形态）。

**Read-only**：`lima/**`（全部）、`evaluation_data/**`（全部）、四个冻结测试文件、`pyproject.toml`/
`requirements.txt`、`scripts/run_ci_tests.py`（unittest discover 自动纳入新测试文件）。

**Do Not Touch（diff 必空，Done Command 6 全列）**：`lima/**`、`evaluation_data/**`、
`benchmarks/v4/baseline/collect.py`、`benchmarks/v4/baseline/expert_timing.py`、
`benchmarks/__init__.py`、`benchmarks/v4/__init__.py`、`benchmarks/v4/baseline/__init__.py`、四个冻结测试
文件（零改动零追加）、其余 scripts、`pyproject.toml`/`requirements.txt`/`.gitignore`/`.gitattributes`、其余
一切 tracked 文件；不提交 run 产物；GitHub Issue/PR/Ledger 远端状态。

**Symbol-to-File Map（公共符号面冻结——Implementation 不得重设计、不得改名、不得扩公共面）：**

| 文件 | 公共符号（`__all__` 恰为此集） |
|---|---|
| `benchmarks/v4/baseline/orchestrate.py` | `add_baseline_arguments`、`BaselineOrchestrationError`、`BaselineOrchestrationErrorCode`、`BaselineRunSummary`、`run_baseline_from_args`、`run_repeats` |
| 其余全部文件 | 公共符号面零变化（run.py 六符号、collect.py 十一符号、expert_timing.py 一符号均不动） |

**导入方向冻结（无环）**：`orchestrate.py` → stdlib（恰 `argparse`/`dataclasses`/`json`/`pathlib`/`typing`）
+ 只读四方 `lima.baseline_run_spec`、`lima.baseline_run_result`、`benchmarks.v4.baseline.collect`、
`benchmarks.v4.baseline.run`；三脚本 → 基线分支内惰性 import `orchestrate`（+ 分支内惰性 import 三个冻结
error 类）；`orchestrate.py` **禁止** import `expert_timing`、`lima.contracts.codec`（digest 经 result 对象
间接取得）、任何 scripts 模块。

**冲突分析**：7 路径在基线均无占用（`orchestrate.py` 不存在亲验；三脚本与 run.py 为 Modify 授权路径；两个
P&V 产物为全新文件）；路径集合两两不重叠；Assignment 亲验无其他活动 IP 占用。暂存纪律：只逐路径
`git add <精确路径>`；禁止 `git add .` / `-A` / `-u`。

## 7. 交付物规范（Implementation 必须满足的行为契约）

### 7.0 编排层 typed error 族（定义于 `orchestrate.py`，模块内唯一新 error 族）

- `BaselineOrchestrationErrorCode(str, enum.Enum)`：**恰 3 成员，value == name**（闭合集，测试冻结）：

  | 成员 | 稳定消息（模块内 catalog，逐字冻结） | 触发语义 |
  |---|---|---|
  | `BASELINE_OUTPUT_REQUIRED` | `"A baseline run requires the --baseline-output directory."` | `args.run_spec` 非 None 而 `args.baseline_output` 为 None（任何执行/文件之前） |
  | `INVALID_REPEAT_COUNT` | `"The baseline repeat count must be a positive integer."` | repeat 非 int 或 < 1（argparse 已挡 CLI 面；本层防御直接 API 调用） |
  | `MANIFEST_UNREADABLE` | `"The baseline manifest file could not be read."` | manifest 文件缺失/不可读/UTF-8 或 JSON 解析失败 |

- `BaselineOrchestrationError(ValueError)`：属性 `code: BaselineOrchestrationErrorCode`、`field_path: str`
  （结构化定位，如 `"$.baseline_output"`）；同一 code 渲染同一稳定消息（catalog；不内嵌原始 payload/路径/
  secret）；构造器 `__init__(code, field_path="")`。**不得继承或复用** `BaselineCollectionError`/
  `BaselineRunSpecError`/`BaselineRunResultError`（独立类，风格对齐 IP-0027 先例）。field_path 冻结值：
  `BASELINE_OUTPUT_REQUIRED → "$.baseline_output"`、`INVALID_REPEAT_COUNT → "$.repeat"`、
  `MANIFEST_UNREADABLE → "$.manifest_path"`。
- **呈现归一（R5 综合）**：脚本基线分支捕获四族
  （`BaselineOrchestrationError` + 三冻结族）→ 同一 stderr 行格式（§8.5）+ 退出码 2。Assignment R5 列举的
  三冻结族为门栈可传播族；本 Packet 依据同一裁定内"稳定 typed CLI 错误 + 精确格式 Packet 冻结"的委派，将
  新族并入同一渲染路径（否则 `BASELINE_OUTPUT_REQUIRED` 无法以退出码 2 呈现）。

### 7.1 `add_baseline_arguments(parser: argparse.ArgumentParser) -> None`

恰添加三参数（三脚本同一面，R2）：

```python
parser.add_argument("--run-spec", default=None,
                    help="Path to a baseline run spec JSON; switches the script to baseline mode.")
parser.add_argument("--baseline-output", default=None,
                    help="Existing directory for baseline result files (required with --run-spec).")
parser.add_argument("--repeat", type=_positive_int, default=5,
                    help="Executions per mode (N cold then N warm); default 5.")
```

其中 `_positive_int`（模块私有函数）为 argparse `type`：`int(value)`，非整数或 `<= 0` →
`argparse.ArgumentTypeError` → `parse_args` 以 `SystemExit(2)` 失败（任何执行发生前）。默认值冻结：
`--run-spec` None / `--baseline-output` None / `--repeat` 5（int）。help 文本须声明既有报告参数
（`--output`/`--output-dir`）在基线模式下惰性（ignored）。

### 7.2 `run_baseline_from_args(args, *, execute, sources=None, manifest_path=None) -> BaselineRunSummary`

CLI 适配层。读取 `args` 恰三属性：`run_spec`、`baseline_output`、`repeat`（由 add_baseline_arguments 添加）。
操作序（冻结，任一步失败 = 零 execute 调用 + 零文件写出）：

1. 参数组合门：`args.run_spec is not None and args.baseline_output is None` →
   `BaselineOrchestrationError(BASELINE_OUTPUT_REQUIRED, "$.baseline_output")`。
2. repeat 门：`type(args.repeat) is not int or args.repeat < 1` →
   `BaselineOrchestrationError(INVALID_REPEAT_COUNT, "$.repeat")`。
3. spec 加载：`load_baseline_run_spec(args.run_spec)`（冻结 `BaselineRunSpecError` 原样透传，含 malformed
   JSON → `INVALID_FIELD_VALUE "$"`）。
4. manifest 加载：`manifest_path` 默认
   `pathlib.Path(__file__).resolve().parents[3] / "evaluation_data" / "v4" / "baseline_manifest.json"`
   （模块级私有常量；deterministic、离线、无环境读取）；读字节 + UTF-8 + `json.loads`；
   `OSError`/`UnicodeDecodeError`/`ValueError` → `BaselineOrchestrationError(MANIFEST_UNREADABLE,
   "$.manifest_path")`。
5. 门栈一次性前置（冻结序）：`validate_baseline_manifest(manifest, spec)` →
   `run.validate_role_bindings(spec, manifest)`（两冻结码原样透传）。
6. 目录门：`pathlib.Path(args.baseline_output).is_dir()` 为假 →
   `BaselineCollectionError(OUTPUT_DIRECTORY_UNAVAILABLE, "$.output_dir")`（复用冻结码；field_path 为
   structure-only，R9 口径）。
7. 委托：`run_repeats(spec.to_canonical_value(), manifest, execute, args.baseline_output,
   repeat=args.repeat, sources=sources)` 并返回其结果。

### 7.3 `run_repeats(spec_mapping, manifest, execute, output_dir, *, repeat=5, sources=None) -> BaselineRunSummary`

重复执行编排（R3/R4/R5）。算法（冻结）：

1. repeat 门：`type(repeat) is not int or repeat < 1` → `BaselineOrchestrationError(INVALID_REPEAT_COUNT,
   "$.repeat")`（零执行零文件）。
2. 目录快照：`before = {p.name for p in pathlib.Path(output_dir).iterdir()}`（目录不存在时由首个 attempt 的
   目录门以 `OUTPUT_DIRECTORY_UNAVAILABLE` fail closed，零执行）。
3. N cold：`for i in range(repeat): run_baseline_attempt(spec_mapping, manifest, execute, output_dir,
   attempt_index=i, mode="cold", sources=sources)`。
4. N warm：`for i in range(repeat): run_baseline_attempt(..., attempt_index=repeat + i, mode="warm",
   sources=sources)`（全局唯一 attempt_index 0..2N-1，满足冻结 DUPLICATE_ATTEMPT_INDEX 门）。
   每 attempt 结果按执行顺序收集为 `attempts` 列表；**不捕获**任何异常：`Exception` 已由冻结 runner 转为
   taxonomy 样本并返回（编排继续）；`BaseException` 由冻结 runner 落盘该 attempt 后原样重抛（编排终止、
   **不写聚合件**、不构造 summary）；门/CLOCK 类 typed error 同样原样上抛。
5. 聚合组装（只经冻结 from_mapping，绝不手工拼 status/percentiles）：
   `aggregate = result_from_mapping({"schema_version": 1, "run_spec_digest": attempts[0].run_spec_digest,
   "samples": [dict(result.samples[0].items()) for result in
   sorted(attempts, key=lambda r: r.samples[0]["attempt_index"])]})`。
   （全部 2N 样本含失败样本；run_spec_digest 全 attempt 一致由构造保证。）
6. 聚合落盘（复用现有 writer，不修改）：`artifacts = write_result_file(aggregate, output_dir)`
   （不带 expert_session）→ 共享 digest 前缀下顺延序号（典型 2N+1；§8.1 R8 后序号分配考虑 result+sidecar 双
   占用）。
7. attempt 路径推导（仅依赖公开行为，独占创建保证唯一性）：
   `after = {p.name for p in pathlib.Path(output_dir).iterdir()}`；`new_names = after - before -
   {artifacts.result_path.name}`；`result_paths = tuple(sorted((pathlib.Path(output_dir) / name for name in
   new_names), key=lambda p: int(p.stem.rsplit("-", 1)[1])))`（按序号升维 = attempt 执行顺序）。
8. 返回 `BaselineRunSummary(attempts=tuple(attempts), result_paths=result_paths, aggregate=aggregate,
   aggregate_path=artifacts.result_path, aggregate_sha256=artifacts.result_sha256,
   status=aggregate.status)`。

**编排层不传** `prompt_tokens`/`completion_tokens`/`cost_micro_usd`（None）与 `expert_session`（None，不写
sidecar）——诚实缺席（Not-covered 4/8）。

### 7.4 `BaselineRunSummary`（frozen dataclass，字段精确冻结）

```python
@dataclasses.dataclass(frozen=True, slots=True)
class BaselineRunSummary:
    """Paths, artifacts, and aggregate of one orchestrated baseline run."""
    attempts: tuple[BaselineRunResult, ...]
    result_paths: tuple[pathlib.Path, ...]
    aggregate: BaselineRunResult
    aggregate_path: pathlib.Path
    aggregate_sha256: str
    status: str
```

字段序与名称冻结（测试以 `dataclasses.fields` 断言）；`status` 由 `run_repeats` 以 `aggregate.status`
构造（语义测试断言 `summary.status == summary.aggregate.status`）；仅 `run_repeats` 构造。

### 7.5 CLI 呈现格式（逐字冻结；stdout 摘要行 + stderr 错误行 + 退出码）

- 成功（编排完成即成功——**含 `insufficient_sample`**：样本充足性是数据状态，诚实记录于 status，不作为失败）：
  stdout 一行：`baseline: status={status} attempts={2N} aggregate={aggregate_path} sha256={aggregate_sha256}`
  （Python 实现：`print("baseline: status=%s attempts=%d aggregate=%s sha256=%s" % (summary.status,
  len(summary.attempts), summary.aggregate_path, summary.aggregate_sha256))`）。
- 门/参数/聚合 typed 错误：stderr 一行：`baseline error: {code} {field_path}`（实现：
  `print("baseline error: %s %s" % (error.code.value, error.field_path), file=sys.stderr)`）+ 退出码 **2**。
- `BaseException`（取消/中断/exit）：不捕获，原样传播（Python 默认退出语义）。
- 编排完成退出码 **0**。

### 7.6 三脚本接线模板（R2/R5/R6；逐脚本冻结——允许的 diff 恰为这些形状）

通用要素（三脚本一致）：`add_baseline_arguments(parser)` 一行插在既有 argparse 参数定义之后、
`parse_args` 之前；早退分支插在 `parse_args` **之后、任何 legacy 工作之前**；分支内**惰性 import**
（`from benchmarks.v4.baseline.orchestrate import BaselineOrchestrationError, run_baseline_from_args` +
`from benchmarks.v4.baseline.collect import BaselineCollectionError` +
`from lima.baseline_run_spec import BaselineRunSpecError` +
`from lima.baseline_run_result import BaselineRunResultError`）；输入制备一次（不进 attempt）；execute 闭包
体 = 现有 evaluator 计算调用（语义零改动）；legacy 报告渲染/写盘不进基线模式；错误呈现与摘要行按 §7.5。

**(a) `scripts/run_e2e_evaluation.py`**（ROOT 为 str；`main()` 无参、返回 None、底部无 SystemExit 包裹 →
分支用 `sys.exit(2)` 与裸 `return`）：

```python
    if args.run_spec is not None:
        from benchmarks.v4.baseline.collect import BaselineCollectionError
        from benchmarks.v4.baseline.orchestrate import (
            BaselineOrchestrationError,
            run_baseline_from_args,
        )
        from lima.baseline_run_result import BaselineRunResultError
        from lima.baseline_run_spec import BaselineRunSpecError

        if args.reuse_dataset:
            cases = load_jsonl(args.dataset)
        else:
            cases = generate_controlled_pr_cases()
            write_jsonl(args.dataset, cases)

        def _baseline_execute():
            baseline = EndToEndEvaluationHarness().run(
                baseline_reviewer(), cases, "single-agent-baseline"
            )
            return EndToEndEvaluationHarness(repairer=FixtureRepairer()).run(
                candidate_reviewer(), cases, "multi-agent-candidate"
            )

        try:
            summary = run_baseline_from_args(
                args,
                execute=_baseline_execute,
                manifest_path=os.path.join(
                    ROOT, "evaluation_data", "v4", "baseline_manifest.json"
                ),
            )
        except (
            BaselineOrchestrationError,
            BaselineCollectionError,
            BaselineRunSpecError,
            BaselineRunResultError,
        ) as error:
            print(
                "baseline error: %s %s" % (error.code.value, error.field_path),
                file=sys.stderr,
            )
            sys.exit(2)
        print(
            "baseline: status=%s attempts=%d aggregate=%s sha256=%s"
            % (
                summary.status,
                len(summary.attempts),
                summary.aggregate_path,
                summary.aggregate_sha256,
            )
        )
        return
```

execute 闭包组成（冻结）：attempt 体 = 该脚本 legacy 评估段的两条 evaluator 语句**原样**（baseline harness
run 后 candidate harness run——"现有 evaluator 计算调用"在 run_e2e 上由这两条语句构成，语义零改动；解释登记
于 §13 R5 条目）；数据集制备（reuse/load 或 generate+write）一次于编排前。

**(b) `scripts/run_real_world_evaluation.py`**（ROOT 为 `pathlib.Path`；`main(argv=None) -> int` →
`return 2` / `return 0`）：

```python
    if args.run_spec is not None:
        from benchmarks.v4.baseline.collect import BaselineCollectionError
        from benchmarks.v4.baseline.orchestrate import (
            BaselineOrchestrationError,
            run_baseline_from_args,
        )
        from lima.baseline_run_result import BaselineRunResultError
        from lima.baseline_run_spec import BaselineRunSpecError

        dataset = load_real_world_dataset(
            args.dataset, allow_unpinned_archives=args.mode == "fetch"
        )
        evaluator = RealWorldSecurityEvaluator(
            SnapshotStore(args.cache),
            scanner=RepositoryScanner(
                sast_mode="off", dataflow_enabled=args.dataflow == "on"
            ),
            oracle_runner=RealProjectOracleRunner(
                ROOT / "scripts" / "run_real_project_oracle.py"
            ),
            llm_client=_llm_client() if args.mode in {"llm", "llm-retrieval"} else None,
        )

        def _baseline_execute():
            if args.mode == "fetch":
                return evaluator.fetch(dataset)
            if args.mode == "oracle":
                return evaluator.run_oracle_matrix(dataset)
            return evaluator.run(
                dataset, mode=args.mode, run_oracles=args.run_oracles
            )

        try:
            summary = run_baseline_from_args(
                args,
                execute=_baseline_execute,
                manifest_path=str(
                    ROOT / "evaluation_data" / "v4" / "baseline_manifest.json"
                ),
            )
        except (
            BaselineOrchestrationError,
            BaselineCollectionError,
            BaselineRunSpecError,
            BaselineRunResultError,
        ) as error:
            print(
                "baseline error: %s %s" % (error.code.value, error.field_path),
                file=sys.stderr,
            )
            return 2
        print(
            "baseline: status=%s attempts=%d aggregate=%s sha256=%s"
            % (
                summary.status,
                len(summary.attempts),
                summary.aggregate_path,
                summary.aggregate_sha256,
            )
        )
        return 0
```

execute 闭包组成（冻结）：输入制备一次 = 数据集加载 + evaluator 构造（既有参数语义逐字）；attempt 体 =
既有模式分派的**单次** evaluator 调用（fetch / run_oracle_matrix / run 三选一，与 legacy 分派同构）。

**(c) `scripts/run_repair_evaluation.py`**（ROOT 为 str；`main(argv=None) -> int` → `return 2` /
`return 0`；分支结构同 (b)，差异点）：

```python
        dataset = load_repair_dataset(args.dataset)
        evaluator = RepairConstraintEvaluator()

        def _baseline_execute():
            return evaluator.run(dataset)
```

manifest 行用 `os.path.join(ROOT, "evaluation_data", "v4", "baseline_manifest.json")`；错误呈现与摘要行
（§7.5）与 (b) 逐字相同（含 `return 2` / `return 0`）。

**退出码语义（三脚本一致）**：基线分支编排完成 → 脚本退出码 0（(a) 经裸 `return`（main 返回 None，
进程退出 0）；(b)/(c) `return 0`）；typed 错误 → (a) `sys.exit(2)`；(b)/(c) `return 2`；无 `--run-spec` →
legacy 行为逐字节不变（AC-1）。

### 7.7 AC-1 三层等价证明（R6，缺一不可）

1. **结构层**（P&V 审查，Done Command 6b）：三脚本 diff 只允许"§7.1 三参数（经 add_baseline_arguments）+
   §7.6 早退分支"；legacy 代码体零改动（无既有行修改/删除/移动）。P&V 逐 hunk 审查并在 Verification
   Report 登记。
2. **行为层**（冻结测试 TestLegacyEquivalence ×3）：evaluator 边界打桩（patch 脚本模块命名空间内的
   evaluator 符号返回哨兵结果）+ legacy argv 调 `main`，断言 stdout 等于预期字面量（§10 冻结真值，由
   **当前（基线态）脚本程序化推导**）与退出码等于预期字面量，且编排入口零调用（patch
   `benchmarks.v4.baseline.orchestrate.run_baseline_from_args` 断言 call_count == 0）。
3. **参数层**（冻结测试 TestBaselineArgumentSurface + TestScriptWiring ×3）：add_baseline_arguments 面
   （默认值/类型/正值拒绝）；三脚本 wiring（`--run-spec` 路径下 patch 编排入口捕获参数、断言 legacy 路径
   未进入（evaluator 哨兵炸弹零触发）、断言退出码与摘要行）。

## 8. IP-0027 interface erratum（R8/R9 受控勘误——Maintainer T1/T2 显式授权）

> 登记纪律：本节为 IP-0027 已交付面的受控勘误登记（对象、依据、结论、影响面、测试、向后兼容证明）；
> **不**修改 IP-0027 Packet 文档本身（冻结证据不可回写），**不**另开独立勘误 PR（单 PR 拓扑约束）。先例参
> 照 fd37d4e。授权原文：T1"由 Coordinator 在 CLI 接线前明确裁定并给出测试"；T2"不得把现有'低严重度'当作
> 免于处理的依据"（INTENT-IP-0028-20260926-01 §Maintainer 技术偏好）。

### 8.1 边界 a（R8）：`write_result_file` 序号分配双占用探测

- **对象（精确枚举）**：`benchmarks/v4/baseline/run.py` 的 `write_result_file` 序号分配循环（基线 L191-194，
  现仅探测 `{prefix}-run-{n}.json`）——**恰 1 处循环条件**修改 + 该函数 docstring 中描述序号分配的语句更新
  （"smallest positive integer not yet taken" 处补双占用语义）。其余零改动。
- **依据**：现状先独占写 result（L196）再独占写 sidecar（L204-209）；sidecar 名已被占用时 result 已落盘即抛
  `OUTPUT_PATH_ALREADY_EXISTS`，留下孤儿 result 且占用序号——违反编排完整性且把"调用者拿到错误却产生了产物"
  的矛盾状态留给 CLI 层。候选评估（Intent A1）：(ii) 调序只转移孤儿不消除；(iii) 回滚与"失败 run 保留"直觉
  冲突且需定义清理边界；(iv) 透出不修被 T2 禁止。(i) 与 writer 现有确定性命名/最小空闲序号/从不覆盖设计最
  自洽。
- **结论（冻结）**：序号 n 视为被占用当且仅当 `{prefix}-run-{n}.json` **或**
  `{prefix}-run-{n}.expert-timing.json` 任一存在（占用判定只依赖目录现状，不依赖本次是否带
  expert_session——确定性更强、可测）。副作用（接受并测试）：仅存 sidecar 无 result 的残留目录会让后续无
  sidecar 写入也跳过该序号——无害（单调、不覆盖）。
- **测试（必须，§10 TestWriterErratum）**：①预置仅 sidecar-1 → 带 session 调 `write_result_file` → 无异
  常，result-2 + sidecar-2 落盘，预置 sidecar-1 字节不动，无孤儿；②预置仅 sidecar-1 → 不带 session 调用 →
  result 落在 run-2；③`run_baseline_attempt` 带 session 进入同态目录 → 完整 attempt 落 run-2，无异常。
- **影响面**：`run.py` 内 1 处循环条件 + docstring；`collect.py`/`expert_timing.py`/错误码/消息零改动。

### 8.2 边界 b（R9）：错误 field_path 含完整本机路径 → structure-only

- **对象（精确枚举）**：`benchmarks/v4/baseline/run.py` 三处 field_path 构造（基线行号）：`write_exclusive`
  L165 `str(path)`、`write_result_file` 目录检查 L189 `str(directory)`、`run_baseline_attempt` 目录检查 L255
  `str(directory)`——**恰 3 个字面量**替换 + 对应 docstring 更新（如有描述）。其余零改动。
- **依据**：IP-0025 对 field_path 的定位是 structure-only position reporting
  （`baseline_run_result.py` L124-126 亲证："Use field_path for structure-only position reporting such as
  $.samples[0].mode"）；错误对象若进入公开日志/报告即泄漏本机路径结构（#57"公开报告只保存摘要和哈希"；
  Intent E4）。本轮亲证：`collect.py` 稳定消息目录（L87-92）本身**不含路径**——路径只在 field_path 字段泄
  漏；目录路径由操作者经 CLI 自供，从 field_path 移除不损失可操作性。候选 (ii) 截断/相对化引入新的不确定
  性，否决。
- **结论（冻结字面量）**：`write_exclusive` → `"$.output_path"`；两处目录检查 → `"$.output_dir"`。稳定消息
  与错误码零改动（`collect.py` 整文件零改动）；路径信息不进 message、不进 field_path。§7.2 适配层目录门与
  §7.0 新族 field_path 同一口径。
- **测试（必须，§10 TestWriterErratum）**：断言两错误码的 field_path 等于上述字面量
  （`write_result_file` 与 `run_baseline_attempt` 两个入口分别断言 `$.output_dir`；`write_exclusive` 断言
  `$.output_path`）、`str(exception)` 与 IP-0027 目录消息逐字一致（DI-009 两条真值）、异常渲染文本不含所供
  路径子串（无盘符/反斜杠/分隔符泄漏）。
- **影响面**：`run.py` 内 3 个字面量 + docstring；26 个冻结用例回归必绿（本轮亲核：IP-0027 冻结测试对
  OUTPUT_* 两码只断言 code，无 field_path 断言——`test_write_exclusive_refuses_existing_path` L764-771、
  `test_result_filenames_are_digest_prefixed_monotonic_without_timestamps` L799-806、
  `test_runner_rejects_invalid_metric_params_before_execution` 目录子用例 L521-531）。

### 8.3 向后兼容证明（26 个 IP-0027 冻结用例）

- R8：双占用探测在**空目录**（全部既有用例的路径）与"仅 result 存在"目录上行为与单名探测逐字节一致
  （result 不存在且 sidecar 不存在 ⇔ 旧条件 result 不存在）；既有用例只断言 code 与文件名
  （`test_result_filenames_...` 空目录 1→2；`test_runner_writes_sidecar_alongside_result` 空目录 run-1 对；
  `test_second_execution_writes_new_file_preserving_history` 空目录 1→2）。
- R9：冻结用例对 OUTPUT_* 两码无 field_path 断言（亲核 L764-771/L799-806/L521-531）；消息目录位于
  `collect.py`（零改动）→ 渲染文本不变。
- 结论：26/26 用例在勘误后语义不变；157 方法回归（Done Command 2）为机械验证。

## 9. Done Commands（= Assignment §8 验收命令全文，在 worktree 根执行，Windows 设 PYTHONUTF8=1）

```bash
# 1. 定向新测试（C2 冻结时全 RED 且归因 benchmarks.v4.baseline.orchestrate 缺席；C-final 后全绿）
python -m unittest -v tests.test_v4_baseline_cli
# 2. 四冻结文件回归（70+28+33+26=157 必须全绿；C2 之前先跑一次作为冻结前基线绿）
python -m unittest -v tests.test_v4_baseline tests.test_v4_baseline_manifest tests.test_v4_baseline_result tests.test_v4_baseline_collection
# 3. 编译
python -m compileall -q lima benchmarks tests scripts
# 4. 质量门禁（新增/修改 py 文件）
python -m ruff check --no-cache benchmarks/v4/baseline/orchestrate.py benchmarks/v4/baseline/run.py \
  scripts/run_e2e_evaluation.py scripts/run_real_world_evaluation.py scripts/run_repair_evaluation.py \
  tests/test_v4_baseline_cli.py
python -m bandit -q benchmarks/v4/baseline/orchestrate.py benchmarks/v4/baseline/run.py
# 5. 文件边界：恰等于 Allowed Files 7 路径
git diff --name-only 98b8a35e4fbc8f11d809ec7ad2b571c10248ded5..HEAD
# 6. 冻结面/生产面守护（预期空）：lima/evaluation_data/collect/expert_timing/四冻结测试/配置文件
git diff 98b8a35e4fbc8f11d809ec7ad2b571c10248ded5..HEAD -- lima evaluation_data \
  benchmarks/v4/baseline/collect.py benchmarks/v4/baseline/expert_timing.py \
  benchmarks/__init__.py benchmarks/v4/__init__.py benchmarks/v4/baseline/__init__.py \
  tests/test_v4_baseline.py tests/test_v4_baseline_manifest.py tests/test_v4_baseline_result.py \
  tests/test_v4_baseline_collection.py pyproject.toml requirements.txt .gitignore .gitattributes
# 6b. run.py 勘误范围审查：diff 必须仅含 §8.1(a)/§8.2(b,c) 枚举改动（P&V 逐 hunk 审查并在 Verification Report 登记）
git diff 98b8a35e4fbc8f11d809ec7ad2b571c10248ded5..HEAD -- benchmarks/v4/baseline/run.py
# 7. 产物守护（预期空）
git diff --name-only --diff-filter=A 98b8a35e4fbc8f11d809ec7ad2b571c10248ded5..HEAD -- 'benchmarks/v4/baseline/results*' '*.json' ':!docs' ':!tests'
# 8. ancestry（P&V 终验；<Frozen-Test-Commit-SHA> 由 C2 登记）
git merge-base --is-ancestor <Frozen-Test-Commit-SHA> HEAD && echo ANCESTRY-OK
```

成功判据（全部满足才算本切片 GREEN）：AC-1 三脚本无新参数行为逐字节等价（§7.7 三层证明齐备）；AC-2 编排
满足 3/5 下限语义（默认 N=5 → sufficient 可达；N<5 → 诚实 insufficient）、percentile nearest-rank（对注入
wall times 的手算抽查）、聚合件只经冻结 from_mapping 产出；AC-3 attempt 件与聚合件独占创建、同 spec 重跑
总新增文件、失败样本带 taxonomy 保留在聚合中、SF-01 四类零执行负例全过（execute=0、文件=0）；AC-4 冻结面
与生产扫描语义零改动、run.py 改动恰在 §8 枚举范围内、全离线（卫生扫描 + 无新依赖）。

失败判据（任一命中即未达标）：任一负例未以预期稳定码拒绝或发生执行/文件产出；R8 场景仍产生孤儿 result 或
覆盖任何既有文件；任一 OUTPUT_* 错误渲染含路径子串；legacy 等价用例 stdout/退出码与预期不符；冻结面 diff
非空；run.py diff 超出勘误枚举；测试方法数 >35；出现网络/Secret/付费/新依赖/float 度量；聚合实现绕开
from_mapping；提交 run 产物。

## 10. 测试矩阵（`tests/test_v4_baseline_cli.py`，C2 冻结，27 方法 ≤ 35 上限）

组织：unittest 风格、单文件；模块级 import = stdlib + 冻结 `lima.baseline_run_spec`/
`lima.baseline_run_result` + `from benchmarks.v4.baseline import collect, orchestrate, run`（模块级产品
import → RED 形态见下）；正例 fixture = 真实冻结 `evaluation_data/v4/baseline_manifest.json` + 名义 spec
arrange（名义值同 IP-0027 先例：`analyzer_fingerprint="a"*64`、`config_digest="b"*64`、`seed=20260925`、
声明式 machine profile）；负例全部深拷贝变异，不新建 fixture 数据文件；三脚本经 importlib 按路径加载
（`scripts/` 无 `__init__.py`，DI-014 亲验）并按名缓存；测试临时输出一律 tempfile；CI 经
`scripts/run_ci_tests.py`（unittest discover）自动纳入。

**RED 形态（Assignment §8 第 8 项）**：C2 冻结时 `benchmarks.v4.baseline` 包存在而 `orchestrate` 子模块
缺席，测试文件被 runner 正常发现（collection 成功），但模块 import 在
`from benchmarks.v4.baseline import collect, orchestrate, run` 语句处以
`ModuleNotFoundError: No module named 'benchmarks.v4.baseline.orchestrate'` 失败（逐条可归因；镜像 IP-0027
冻结头先例）→ `python -m unittest tests.test_v4_baseline_cli` → `Ran 1 test / FAILED (errors=1)`、exit 1；
不得是测试语法/环境/依赖损坏（缺席态 `python -m py_compile` 通过 + Pre-Freeze Harness Gate 桩沙箱证明
arrange 有效共同证明缺席是唯一失败源）。

**legacy 等价预期字面量（冻结真值；2026-09-26 由基线态（未改动）三脚本在 worktree 外沙箱程序化推导，
DI-014）**：

- run_e2e（stdout 四行；前两行 path 前缀为运行期 tempdir 值，模板冻结）：
  `dataset: {dataset_path}` / `report: {output_dir}/evaluation-report.json`（os.path.join 语义）/
  `baseline F1=50.0% candidate F1=75.0% high-risk recall=75.0% clean accuracy=75.0%` /
  `safe fix=50.0% e2e fix=25.0%`；返回 None（进程退出 0）。哨兵 harness 结果（两份，metrics/dataset/
  by_split/repair_* 最小键集）冻结于测试内。
- run_real_world（JSON 渲染逐字）：`{\n  "metrics": {\n    "cases": 1\n  },\n  "marker":
  "real-world-sentinel"\n}\n`；退出码 0。
- run_repair（JSON 渲染逐字）：`{\n  "metrics": {\n    "constraint_accuracy": 1.0,\n    "cases": 0\n  },\n
  "marker": "repair-sentinel"\n}\n`；退出码 0。

负例面与覆盖对照（Assignment 测试矩阵 1-8 → 测试锚点）：

| # | Assignment 矩阵项 | 测试锚点（方法） |
|---|---|---|
| 1 | 参数面：默认值/类型；--repeat 0/-1/非整数 → SystemExit(2)；--run-spec 无 --baseline-output → 稳定错误零执行零文件 | TestBaselineArgumentSurface.test_baseline_argument_defaults_and_types / test_repeat_guard_rejects_non_positive_and_non_integer / test_run_spec_without_baseline_output_fails_closed |
| 2 | 三脚本 wiring ×3（patch 编排入口、捕获参数、返回码、legacy 零进入） | TestScriptWiring.test_e2e_script_wires_baseline_mode / test_real_world_script_wires_baseline_mode / test_repair_script_wires_baseline_mode |
| 3 | 三脚本 legacy 等价 ×3（AC-1 行为层） | TestLegacyEquivalence.test_e2e_legacy_stdout_and_exit_unchanged / test_real_world_legacy_stdout_and_exit_unchanged / test_repair_legacy_stdout_and_exit_unchanged |
| 4 | 编排语义 9 项 | TestOrchestrationSemantics.test_two_repeats_execute_four_attempts_and_aggregate_naming（N=2：execute 4、文件 4+1、run-1..5、cold 0..1/warm 2..3）/ test_three_repeats_yield_insufficient_with_null_percentiles（N=3）/ test_five_repeats_yield_sufficient_with_nearest_rank_percentiles（N=5 注入 sources、手算 p50/p95、聚合 bytes==canonical_bytes、SHA-256 独立重算）/ test_single_repeat_runs_two_attempts_without_error（N=1）/ test_rerun_same_spec_adds_files_preserving_history / test_failed_attempt_keeps_taxonomy_and_orchestration_continues / test_base_exception_persists_attempt_then_propagates_without_aggregate / test_missing_output_directory_fails_closed_before_execution |
| 5 | SF-01 四类零执行负例（1 方法 4 subTest，R7） | TestGateStackNegatives.test_sf01_four_negatives_fail_closed_with_zero_execution_zero_files（自洽角色对调/移动引用/缩写 SHA/指纹漂移；经 `run_baseline_from_args` + 临时 spec/manifest 文件） |
| 6 | 边界 a（R8 三测试）与边界 b（R9 断言含无路径泄漏） | TestWriterErratum.test_sidecar_only_collision_with_session_writes_next_sequence / test_sidecar_only_collision_without_session_writes_next_sequence / test_attempt_with_session_in_occupied_directory_writes_run_two / test_output_error_field_paths_are_structure_only_without_path_leak |
| 7 | 卫生：源扫描（测试文件+orchestrate+三脚本）无网络/Secret token；import 白名单 | TestPublicSurfaceAndHygiene.test_offline_hygiene_source_scan / test_orchestrate_import_whitelist |
| 8 | RED 形态（模块级 import → ModuleNotFoundError）+ 公共面/默认 manifest 路径 | 模块级 import 语句本身；TestPublicSurfaceAndHygiene.test_baseline_run_summary_surface（frozen dataclass 字段面）/ test_adapter_end_to_end_with_default_manifest_path（manifest_path=None 正例走通默认路径）；TestScriptWiring.test_script_baseline_error_rendering（stderr 行格式 + 退出码 2） |

| Test class | 方法数 | 覆盖点 |
|---|---:|---|
| TestBaselineArgumentSurface | 3 | 默认值/类型（--run-spec/--baseline-output None、--repeat 5 int）；--repeat 0/-1/"abc" → SystemExit(2)；--run-spec 无 --baseline-output → BASELINE_OUTPUT_REQUIRED、零执行零文件 |
| TestScriptWiring | 4 | 三脚本基线分支 wiring（编排入口捕获 args/execute/manifest_path、摘要行、退出码、legacy 哨兵炸弹零触发、输入制备恰一次）；脚本级错误呈现（stderr `baseline error: <CODE> <field_path>` + 退出码 2） |
| TestLegacyEquivalence | 3 | AC-1 行为层：legacy argv + evaluator 边界打桩 → stdout 逐字面量 + 退出码 + 编排入口零调用 |
| TestOrchestrationSemantics | 8 | N=2/N=3/N=5/N=1 语义；nearest-rank 手算抽查；聚合 bytes/digest；重跑新增不覆盖；失败 taxonomy 保留且编排继续；BaseException 落盘后重抛无聚合件；目录缺失 fail closed 零执行 |
| TestGateStackNegatives | 1 | SF-01 四类（4 subTest）：typed error（按门栈层次）+ execute=0 + 文件=0 |
| TestWriterErratum | 4 | R8 ①②③；R9 field_path 字面量 + 消息逐字 + 无路径泄漏（三入口） |
| TestPublicSurfaceAndHygiene | 4 | orchestrate import 白名单（ast）；卫生源扫描（自扫+orchestrate+三脚本）；BaselineRunSummary 字段面（frozen/slots/字段序）；默认 manifest 路径端到端正例（N=1） |
| **合计** | **27** | ≤ 35 上限 |

反过拟合：负例基于冻结 manifest/spec arrange 的深拷贝变异；正例与真实冻结 manifest 文件共享同一工件；采集源
全部注入 fake（`_repeat_sources` 按 attempt 供给 wall 时长）；等价字面量由基线态脚本程序化推导；不锁定内部
容器类型与实现细节（行为断言为主；result_paths 排序键为公开文件名序号）。

## 11. Stop Conditions（停止并提交 Decision Request 给 Coordinator；= Assignment §Known Gaps and Stop Conditions）

1. 需要触碰任何 Do Not Touch 路径，或第 8 个及以后 Allowed File。
2. `run.py` 需要超出 §8 R8/R9 枚举范围的任何改动；或 `collect.py`/`expert_timing.py` 需要任何改动。
3. 需要第 4 个 CLI 参数名（含 --manifest、分立 cold/warm 计数、--reviewer 类）——与 #57 File ownership
   字面冲突。
4. 需要为 attempt 供给 token/cost/expert 计量（会虚构证据）或经 CLI 写 expert sidecar。
5. 聚合无法仅经冻结 `from_mapping` 完成，或需改 IP-0024/0025 冻结语义（升级 Maintainer，占 ≤1 决策预算）。
6. AC-1 离线等价证明在某脚本不可行（legacy 路径纠缠）——不得以弱化测试消化。
7. 测试方法数无法压进 35 且无法合并断言（冻结前）；或 157 冻结回归出现非预期失败。
8. 需要网络、Secret、付费模型、psutil 或任何新依赖。
9. base SHA 之后 main 出现冲突性实现或 IP-0028 占用冲突。
10. 任一 SF-01 负例无法在零执行零文件形态下成立；需求冲突无法唯一解决。

**Mechanical Test Correction Allowance：ALLOWED_ONCE**（Assignment 一次性授出，不得出错后补写）。P&V 可
在不新增 Coordinator 调用的情况下自行纠正一次纯测试机械缺陷并重新冻结，条件五项全满足：①不改产品语义、
公共接口、稳定错误码或文件范围；②仅限 fixture/arrange/import/lint/测试基础设施缺陷（含脚本模块加载机制类
缺陷）；③旧 Frozen Commit 保留；④修正前缺陷证据、修正后有效 RED、新 Frozen Commit 完整记录；
⑤Implementation 未参与测试修改。涉及产品行为、验收语义或文件范围 → Decision Request，不得以本授权消化。

## 12. 已知缺口与诚实声明（Ledger gap 行来源）

零真实 run：execute 闭包的真实 evaluator 调用仅在 evaluator 边界打桩下测试；真实 token/cost 为 None；
cold/warm 缓存态不控制（mode 标注语义）；expert_session/sidecar 不经 CLI；预算上限仅声明（数值与检查留
PR3-d；CLI help 与本 Packet 声明"真实仓库/模型 run 仅手动触发且须预算上限；数值上限未定，由后续叶子经
Maintainer 确定后实施检查"——不虚构 enforcement）；聚合件离线发现依赖 summary/最后多样本文件约定（PR3-b
消费时再固化）；Windows RSS/IO None 语义继承 IP-0027；run_e2e 的 attempt 体含两条 evaluator 语句（§7.6(a)
解释登记）。

## 13. Decision Record（Coordinator 裁定登记，R1-R10 全文照录，依据 CA-IP-0028-v1.0）

| 裁定 | 内容（全文照录） | 依据 | 落点 |
|---|---|---|---|
| R1 | **"单一 CLI 入口"形态：单一编排模块 + 三脚本一致参数面，不建统一顶层命令。** FR-02 "单一 CLI 入口" 落地为一个共享编排模块 `benchmarks/v4/baseline/orchestrate.py`（全部基线 CLI 逻辑的唯一实现）+ 三个脚本上完全一致的参数面（同一 `add_baseline_arguments` 添加同一组参数）。不新建顶层统一命令。理由：① #57 File ownership 的 Add 清单（benchmarks/v4/baseline/、manifest、tests/test_v4_baseline.py、基准说明/结果模板）不含任何新 scripts 文件；Modify 清单点名三脚本"仅可新增三参数并调用现有 evaluator"——顶层新入口两个清单都不容纳。② #214 是 #212 纠偏（SR-IP-0027-01）后的权威承接 Issue，其三脚本口径即当前权威表述（Intent I4）。③ "每个评测入口有唯一、一致的参数面"满足 FR-02 的可用性目标；单模块实现保证语义单源。后果登记：#57 FR-02 的"真实重放执行"部分仍留 PR3-d；本切片交付的是入口与编排。 | Q1；#57 File ownership | §0、§6、§7 |
| R2 | **`--output` 碰撞：新参数定名 `--baseline-output`，三脚本统一，既有报告参数原语义保留。** 基线模式参数面 = `--run-spec`（str，默认 None，出现即切换基线模式）/ `--baseline-output`（str，默认 None，基线模式下必填，指向 result 落盘目录，必须已存在，无默认值——承 IP-0027 writer "no default directory" 立场，缺失或不存在 → `OUTPUT_DIRECTORY_UNAVAILABLE` fail closed）/ `--repeat`（int，默认 5，argparse 层正值守卫：≤0 或非整数 → argparse 错误 SystemExit(2)，任何执行发生前）。既有 `--output`（run_real_world L130、run_repair L66，报告文件路径语义，默认 ""）与 `--output-dir`（run_e2e L141）零改动；基线模式下这些报告参数惰性（ignored，help 与 Packet 显式声明）。选项取舍：(b) 复用 `--output` 按 --run-spec 有无变义——否决（同参数名模式分裂语义直接违反"不得破坏既有 --output 报告语义与 AC-1 等价"；run_e2e 根本无 `--output`，(b) 无法给出一致面）；(a)+(c) 新参数 `--baseline-output` 三脚本统一——采纳（最小破坏、AC-1 平凡成立、单一一致参数面）。**字面与精神登记**：#57 "仅可新增 --run-spec、--output、--repeat 参数"解读为基线模式参数面，其中 "--output" 指基线结果输出；因具体拼写 `--output` 在两脚本上已被既有报告语义占用（亲验 L130/L66，先于本切片存在），而 Maintainer 现行约束禁止破坏该语义，基线输出的具体拼写定为 `--baseline-output`。本裁定行使 Q2 的委派授权（"裁定精确参数名与语义"），不消耗 Maintainer 决策。 | Q2；I2/E3 | §7.1、§3 |
| R3 | **`--repeat` ↔ cold/warm 映射与 3/5 下限行为：单值双模式，默认 5，不足自然 `insufficient_sample` 不报错。** `--repeat N` = 每模式执行次数：一次基线调用执行 N 次 cold（attempt_index 0..N-1）再 N 次 warm（attempt_index N..2N-1，全局唯一，满足冻结 DUPLICATE_ATTEMPT_INDEX 门）。N 为正整数，默认 5（满足 warm 下限 5 的最小单值，同时 ≥3 cold 下限；单标量无法表达 3/5 分立计数，分立参数属第 4 参数名，禁止）。N 低于下限（如 3：cold 足、warm 不足）不是参数错误：正常执行、聚合自然得出 `insufficient_sample`（IP-0025 all-or-nothing 冻结语义；"不冒充稳定 SLO"由显式状态承载，不靠拒绝执行）。N=1 提供快速单执行路径（聚合 insufficient，符合 Intent I1：单样本天然不足）。门失败与执行失败区别对待：门失败（spec/manifest/role/目录）→ 零执行 typed error；执行体 Exception 失败 → taxonomy 样本、编排继续；BaseException（取消/中断/exit）→ 该 attempt 落盘后原样 re-raise，编排终止、不写聚合件。 | Q3；I1/A4 | §7.3 |
| R4 | **聚合件落盘形态：多样本 BaselineRunResult 经现有 writer 落盘，共享 digest 前缀顺延序号。** ① 每 attempt 一份 result 文件（由冻结 `run_baseline_attempt` 内部经 `write_result_file` 写出，本切片不改此路径）：`{digest[:16]}-run-{n}.json`、单样本、`insufficient_sample`——预期且诚实（Intent I1）。② 聚合件 = 一个多样本 BaselineRunResult：全部 2N 个样本（含失败样本，按 attempt_index 排序）以冻结 `lima.baseline_run_result.from_mapping` 重新冻结（输入 = schema_version 1 + run_spec_digest（= spec.content_digest()）+ 各 attempt 样本 canonical dict；status/percentiles 由 from_mapping 计算，绝不手工拼）；经现有 `write_result_file` 落盘（复用不修改），因此与 attempt 件共享 digest 前缀并取得该前缀下下一个空闲序号（典型为 2N+1；R8 修复后序号分配考虑 result+sidecar 双占用）。独占创建、canonical bytes、SHA-256 封存、永不覆盖全部继承。③ 不设独立命名方案（如 `-aggregate` 后缀）——那需要改 IP-0027 writer 命名面。聚合件的消费契约：编排返回值 `BaselineRunSummary`（含 aggregate 路径与 SHA-256）+ CLI 冻结摘要行打印路径；离线发现规则 = 该前缀下多样本（samples 数 > 1）且由本次调用写入的最后一份文件。PR3-b 报告叶子消费 summary/路径。④ partial 不聚合：仅当 2N 个 attempt 全部完成（成功或 taxonomy 记录）才写聚合件；BaseException 中断 → 只留已写 attempt 件，无聚合件。⑤ `BaselineRunSummary`（frozen dataclass，精确字段由 C1 Packet 冻结，建议含：attempts 元组、result_paths 元组、aggregate、aggregate_path、aggregate_sha256；status 派生自 aggregate.status）。脚本退出码：编排完成即 0（含 insufficient_sample——样本充足性是数据状态，诚实记录于 status；门失败/参数错误非 0，见 R6 错误呈现）。 | Q4；I1/E2 | §7.3、§7.4、§7.5 |
| R5 | **执行编排语义（新模块 `benchmarks/v4/baseline/orchestrate.py` 公共面）。** 单文件 orchestrate.py，公共面（Coordinator 建议名，C1 Packet 冻结最终签名）：`add_baseline_arguments(parser) -> None`（按 R2 添加三参数，含 --repeat 正值守卫 type）；`run_baseline_from_args(args, *, execute, sources=None, manifest_path=None) -> BaselineRunSummary`（CLI 适配层：校验参数组合（--run-spec 存在 ⇒ --baseline-output 必填，违反 → 稳定 typed CLI 错误、零执行零文件）；经冻结 load_baseline_run_spec 加载 spec；加载 manifest（默认路径 deterministic、离线、无环境读取——精确默认由 Packet 冻结，建议脚本侧显式传 ROOT 相对路径）；门栈一次性前置（spec_from_mapping → validate_baseline_manifest → validate_role_bindings，全部通过才进入编排，零执行保证在编排层成立）；然后调 run_repeats）；`run_repeats(spec_mapping, manifest, execute, output_dir, *, repeat=5, sources=None) -> BaselineRunSummary`（N cold + N warm 循环调冻结 run_baseline_attempt（每 attempt 再过一遍门栈是幂等的，无害）；按 R3/R4 组装并落盘聚合件）。编排层不传 prompt_tokens/completion_tokens/cost_micro_usd（None）与 expert_session（None，不写 sidecar）——诚实缺席（Not-covered 4/8）。脚本侧接线模板（三脚本同一形状）：parse_args 后、任何 legacy 工作之前：`if args.run_spec is not None:` 分支内惰性 import run_baseline_from_args 并调用（惰性 import 保证 legacy 导入行为零变化，AC-1 加固）；分支内构造 execute 闭包。execute 闭包原则：①输入制备一次/调用（数据集加载/生成按既有参数语义在编排前完成一次，不进 attempt）；②attempt 体 = 一次现有 evaluator 计算调用（语义零改动）；③legacy 报告渲染/写盘不进基线模式（--baseline-output 是基线模式唯一输出通道，杜绝 2N 次覆盖 legacy 报告）。每脚本闭包精确组成由 C1 Packet 冻结。CLI 错误呈现：脚本基线分支捕获 BaselineCollectionError / BaselineRunSpecError / BaselineRunResultError → stderr 一行稳定格式 + 退出码 2（精确格式 Packet 冻结）；BaseException 原样传播。**P&V 落地注记（本 Packet 权限内）**：(α) "一次现有 evaluator 计算调用"在 run_e2e 上由该脚本 legacy 评估段的两条 evaluator 语句原样构成（baseline harness run + candidate harness run）——该脚本的"现有 evaluator 计算"即此两条语句，选其一子集反而改变所测工作负载语义；(β) 稳定 typed CLI 错误落地为 §7.0 新族 BaselineOrchestrationError（闭合 3 码），脚本分支捕获集合 = 该族 + Assignment 列举三冻结族，同一 §7.5 渲染路径与退出码 2（否则参数组合违例无法以退出码 2 呈现，违反 R5 自身）。 | Q4/Q5 派发；M1/M2 | §7.0-§7.6 |
| R6 | **默认行为逐字节等价的证明形态：三层证明，缺一不可。** ①结构层：三脚本 diff 只允许"新增 argparse 三行（经 add_baseline_arguments）+ parse 后一个 `if args.run_spec is not None:` 早退分支 + 分支内惰性 import"；legacy 代码体零改动（P&V 逐行 diff 审查，Done Command 6 断言）。②行为层：冻结测试含三脚本 legacy 等价用例——在 evaluator 边界打桩（patch 脚本模块命名空间内的 evaluator 符号返回哨兵结果），legacy argv 调 main，断言 stdout 字节与退出码等于预期字面量（桩结果 → 渲染输出，经未触碰的 legacy 渲染路径），且编排入口零调用。③参数层：add_baseline_arguments 面测试（默认值/类型/正值拒绝）+ 三脚本 wiring 测试（--run-spec 路径下 patch 编排入口捕获参数、断言 legacy 路径未进入）。 | AC-1/M10 | §7.7、§10 |
| R7 | **CLI 级零执行负例。** 四个负例类（自洽角色对调、移动引用、缩写 SHA、指纹漂移）在编排入口（run_baseline_from_args，以临时 spec 文件 + 变异 manifest 副本驱动）断言：typed error（错误族与稳定码按门栈层次）、execute 调用次数 0、输出目录零文件。复用 tests/test_v4_baseline_collection.py 的深拷贝变异 + _CountingExecute + 零执行零文件断言先例（L140/L433/L484-492）；负例不新造 fixture 数据文件，正例与真实冻结 manifest 共享同一工件。 | M4/SF-01；I3 | §7.2、§10 |
| R8 | **sidecar 碰撞孤儿 result：序号分配双占用探测（写前预约 result 与 sidecar 两个名字）。** 裁定对象：benchmarks/v4/baseline/run.py 的 write_result_file 序号分配（现 L191-194 仅探测 result 名）。依据：现状先独占写 result（L196）再独占写 sidecar（L204-209）；sidecar 名已被占用时 result 已落盘即抛 OUTPUT_PATH_ALREADY_EXISTS，留下孤儿 result 且占用序号——违反编排完整性且把"调用者拿到错误却产生了产物"的矛盾状态留给 CLI 层。候选评估（Intent A1）：(ii) 调序只转移孤儿，不消除；(iii) 回滚与"失败 run 保留"直觉冲突且需定义清理边界；(iv) 透出不修，被 Maintainer 明令禁止（T2："不得把'低严重度'当作免于处理的依据"）。(i) 与 writer 现有确定性命名/最小空闲序号/从不覆盖设计最自洽。结论：序号 n 视为被占用当且仅当 `{prefix}-run-{n}.json` 或 `{prefix}-run-{n}.expert-timing.json` 任一存在（占用判定只依赖目录现状，不依赖本次是否带 expert_session——确定性更强、可测）。副作用（接受并测试）：仅存 sidecar 无 result 的残留目录会让后续无 sidecar 写入也跳过该序号——无害（单调、不覆盖）。测试（必须）：①预置仅 sidecar-1 → 带 session 调 write_result_file → 无异常，result-2 + sidecar-2 落盘，预置 sidecar-1 字节不动，无孤儿；②预置仅 sidecar-1 → 不带 session 调用 → result 落在 run-2；③run_baseline_attempt 带 session 进入同态目录 → 完整 attempt 落 run-2，无异常。影响面：run.py 内 1 处循环条件 + docstring；collect.py/expert_timing.py/错误码/消息零改动。26 个既有冻结用例（IP-0027）回归必绿（本轮亲核：相关用例只断言 code 与文件名，不断言序号分配内部）。 | Q5/T1/T2；A1(i)；I5 | §8.1、§10 |
| R9 | **错误 field_path 含完整本机路径：改为 structure-only field_path。** 裁定对象：run.py 三处 field_path 构造：write_exclusive（L165 str(path)）、write_result_file 目录检查（L189 str(directory)）、run_baseline_attempt 目录检查（L255 str(directory)）。依据：IP-0025 对 field_path 的定位是 structure-only position reporting（baseline_run_result.py L124-126 亲证）；错误对象若进入公开日志/报告即泄漏本机路径结构（#57 "公开报告只保存摘要和哈希"；Intent E4）。本轮亲证：collect.py 稳定消息目录（L87-92）本身不含路径——路径只在 field_path 字段泄漏；目录路径由操作者经 CLI 自供，从 field_path 移除不损失可操作性。候选 (ii) 截断/相对化引入新的不确定性，否决。结论：write_exclusive → "$.output_path"；两处目录检查 → "$.output_dir"。稳定消息与错误码零改动（collect.py 整文件零改动）。路径信息不进 message、不进 field_path。测试（必须）：断言两错误码的 field_path 等于上述字面量（write_result_file 与 run_baseline_attempt 两个入口分别断言 $.output_dir）、消息与 IP-0027 目录逐字一致、异常渲染文本不含所供路径子串（无盘符/反斜杠/分隔符泄漏）。影响面：run.py 内 3 个字面量 + docstring；26 个冻结用例回归必绿（本轮亲核：冻结测试对 OUTPUT_* 两码只断言 code，无 field_path 断言）。**勘误登记（两边界合并一条）**：R8/R9 构成对 IP-0027 已交付面的受控勘误——Maintainer 已显式授权（T1，接线前裁定；T2，不得以低严重度免处理）。登记位置：IP-0028 C1 Packet 专设"IP-0027 interface erratum"节（§8：对象、依据、结论、影响面、测试、向后兼容证明），不修改 IP-0027 Packet 文档本身（冻结证据不可回写），不另开独立勘误 PR（单 PR 拓扑约束）。先例参照 fd37d4e（勘误纪律）。 | Q6/T1/T2；A2(i)；I5/E4 | §8.2、§8.3、§10 |
| R10 | **预算上限与离线默认。** 本切片仅声明式：CLI help 与 Packet 声明"真实仓库/模型 run 仅手动触发且须预算上限；数值上限未定，由后续叶子经 Maintainer 确定后实施检查"。不实现检查机制（数值未定 + 离线不可测 + 检查属 PR3-d NFR-02 手动面）。登记为已知缺口，不虚构 enforcement。离线默认：新模块与测试 stdlib-only（orchestrate 允许 argparse/dataclasses/json/pathlib/typing + 只读 import lima.baseline_run_spec / lima.baseline_run_result / benchmarks.v4.baseline.collect / benchmarks.v4.baseline.run）；测试文件自扫 + orchestrate.py + 三脚本源码扫描网络/Secret token（本轮亲核三脚本源码当前零命中，扫描可行）；镜像 IP-0027 _forbidden_source_tokens 手法（token 拼接避免自匹配）。 | Q7 + FR-06；M6 | §7.1（help 声明）、§12、§10 |

## 14. Completion Summary 模板（Implementation 交付时）与 PR 纪律

```text
IP / 状态：IP-0028 / VERIFICATION
Base / Frozen Test Commit / final commit：<SHA 列表>
修改文件：恰为 5 个 Implementation 路径（orchestrate.py Add + run.py + 三脚本 Modify，对照 §6 Allowed Files）
AC → Test → Result：逐 AC 附命令与输出摘要（§9 全量：命令 1 全绿 27 方法、命令 2 全绿 157、命令 3-8 通过/为空）
实际命令与统计：§9 命令 1-7 输出摘要 + ruff/bandit 零告警 + 命令 6b run.py diff 逐 hunk 对照 §8 枚举
安全/权限/依赖变化：无（stdlib-only；零网络；零 Secret；零新依赖；orchestrate import 面 == §6 导入方向冻结）
已知限制与未完成项：§12 清单
是否满足 Stop Condition：否
下一步建议：P&V 独立验证（不自行激活）
```

PR 纪律：单一 Implementation PR（Draft→Ready→merge，不 amend/force/squash）；正文含 `Implements
IP-0028`、`Related to #214`（及 `Related to #57` 如需背景引用）、Packet/Frozen Test/final commit SHA、
AC→Test→Result 表、"This PR does not auto-close the Source Issue."；**严禁 close/fix/resolve 关键字与
#214/#57 编号组合（否定句同样禁止）**；不修改 Issue/Ledger；交付后不建 PR（P&V 验证 PASS 后按授权形成）。

## 15. Packet completion definition

- 本 Packet 关键字段无 TBD；§7 行为契约（公共符号面与签名、闭合 3 码与逐字消息、适配层 7 步操作序、
  run_repeats 8 步算法、BaselineRunSummary 字段序、CLI 摘要/stderr/退出码逐字格式、三脚本接线模板与 execute
  闭包组成、import 白名单）与 §8 勘误枚举（R8 恰 1 循环 + docstring；R9 恰 3 字面量 + docstring）已完整冻
  结，Implementation 无需再做语义决策，只做命名面与行为的忠实实现。
- 状态 `READY-FOR-CODE` 的激活条件：C2 Frozen Test Commit 落盘（精确 SHA、测试文件 digest、required
  test count = 27、有效 RED 证据交回 Coordinator）+ 主会话登记后派发阶段 C3+。
- 本 Packet 为 vertical-slice 贡献（#57 PR3-a）；#214/#57 保持打开；本 IP 不宣告任何 Issue 完成。
- 本文件按"单次提交"纪律于 C1 落盘，后续不回填 C2 SHA（冻结证据以 C2 commit message 与 #214 Delivery
  Ledger 为准）。
- 哈希/指纹纪律（fd37d4e 教训）：本文件引用的全部指纹与 SHA 均程序化复制自源文件；C1 提交前由 P&V 以脚本
  断言 Packet 内指纹与 `evaluation_data/v4/baseline_manifest.json` 真值逐字一致（见 P&V 阶段 P 交付记录）。
