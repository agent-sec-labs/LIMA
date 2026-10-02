# 真人复核证据对修复与基线移交（2026-10-02 follow-up）

> 范围：`ZCODE_LONG_TASK_REVIEW_PAIR_FIX_AND_BASELINE_HANDOFF_2026-10-02.md`
> 授权下的范围明确修复。零真实模型调用、零真实 transport POST、零凭据、零付费、
> 零新增外部下载。#57 保持 open、PR3 未勾选、真实人类 sessions=0。

## 1. 修复了什么（唯一产品缺陷）

IP-0043 交付的 `scripts/run_expert_review.py` 在内存生成 timing sidecar 后只落盘
receipt：一次完成的会话在输出目录只留一件 JSON；向尚不存在的目录输出时，要到
start/finish 全部完成后才报保存失败。本修复交付证据对（evidence pair）：

- **配对/核验模块** `benchmarks/v4/baseline/expert_review_pair.py`：
  - `prepare_session`：**start 前门禁**——冻结 review-set 加载；可选
    `--review-set-sha256` 文件级钉扎（字节篡改拒绝）；review-set 全文与 findings
    的 canonical dry-run（DR-IP-0043-CFINAL-FLOAT 的 fail-early 预检落地：含
    float 的 review-set 在真人计时开始前被拒，不再等 finish 后才崩）；内部
    `findings_digest` 一致性；输出目录按明确规则创建（父目录存在时新建单层叶子；
    已有合法目录可复用；文件/缺父/不可写一律拒绝）+ 真实写探针。
  - `persist_timing_sidecar`：**事件先行**——冻结五键 canonical sidecar 以内容
    寻址名 `expert-timing-sidecar-v1-{sha256[:16]}.json` 独占落盘（同字节重试可
    复用、异字节拒绝、绝不覆盖）。
  - `attach_verdict_receipt`：receipt 走冻结 `write_review_receipt`（键集/去重/
    版本命名不变），随后**两件立即读回**并对账；只有一件=未完成残留，永不计入。
  - `verify_pair` / `verify_session_directory`：**只读独立核验**——重放冻结事件
    状态机、单调时钟、finish 终态；从落盘字节复算 `sidecar_sha256`/
    `events_digest`/active time；核对 reviewer_digest、review-set digest、来源绑
    定三元组、coverage/unreviewed。一项不一致即拒绝，不输出"人分钟有效"。
  - `verified_human_sidecar_documents`：**报告输入门**——先全量核验，再按**配对
    receipt 的 synthetic 标记**过滤；裸 sidecar 永不进入（冻结五键无类型标记的
    已知边界由此收口）。
  - `derive_expert_review_report`：**显式派生报告流**——只读重建 sealed 输入
    （run 文件→冻结 summary 面；sealed tarball→冻结生产物化+重扫，重建 scanner
    digest 必须等于 sealed 钉扎值），核验证据对→排除 synthetic→
    `build_baseline_report(expert_sidecars=仅真人)`→新目录落盘；sealed 报告前后
    哈希必须相等；派生记录逐 digest 落盘。
- **CLI**：`scripts/run_expert_review.py` 重写为编排层（门禁→计时→sidecar 先行
  →**finish 后 verdict 确认**〔`--verdict` 仅作兼容预填建议，永不等同复核后确认；
  未确认则 sidecar 留为未完成残留、不写 receipt〕→receipt 配对→诚实汇总）；
  新增 `scripts/verify_expert_review.py` 一条只读核验命令（含 `--derive-report`
  显式派生模式）。
- **冻结面不动**：`expert_timing.py` 五键协议、`write_review_receipt` 只写
  receipt 职责、receipt schema v1、旧 report v2 默认语义、真实调用预算门全部保持
  （冻结测试 `tests/test_v4_baseline_expert_review.py` 逐字未改、全绿）。

## 2. 验证与证据位置

- 新测试 `tests/test_v4_baseline_expert_review_pair.py`（18 方法）：新目录一条命
  令端到端+独立 active time 复算+reviewer-id 零泄漏；pause/resume 排除；同事件重
  放 EVENT_DUPLICATE；篡改 events/active_time/digest 逐面拒绝且人类汇总不增；
  丢 sidecar/丢 receipt=PAIR_INCOMPLETE/PAIR_INVALID 语义；synthetic 配对验证通
  过但被一切人类面排除；`--verdict` 预填 EOF=未确认→无 receipt；派生流（mini
  sealed 基线）复现 sealed 报告且排除 synthetic、sealed 前后逐位一致、目标目录
  冲突/绑定篡改拒绝。
- 新测试 `tests/test_v4_baseline_nonlf_scanner_generality.py`（6 方法）：见 §3。
- **真实 R2 演示**（仓外 `D:\BaseAIProject\LIMA-real-runs\pr3d-expert-review-pair-demo-2026-10-02\`）：
  - `sessions\`：一条 synthetic 会话绑定**真实 R2 review-set**（钉扎
    `bd3695d6…` 通过）；核验命令输出 `human_sessions: 0 / synthetic_sessions: 1 /
    human_active_time_ms_total: None`（记录 `.pv_tmp\EXPERT_PAIR_DEMO_2026-10-02\verify_out.txt`）。
  - `derived\`：派生报告 `c5545434f14e9dde-report-1.json`（sha256
    `a270f827e698e419…` **与 sealed 报告逐位相等**——零真人分钟下派生链复现
    sealed）；重建 scanner digest==sealed `870fdee5…` 双源等值；派生记录
    `expert-review-derivation-v1.json` 全 digest 在档
    （`derive_out.txt`）。
  - **sealed 对账**：R2 全部 21 件（runs×9+report+attempts×8+binding+observation+
    review-set）演示前后逐件 SHA-256 相等（`.pv_tmp\EXPERT_PAIR_DEMO_2026-10-02\sealed_before.json`）。
- CLI 真命令冒烟（piped synthetic 输入）通过后清理；真实人类 sessions 全程=0。

## 3. 通用性有限验证（§四，不做框架改造）

- **LF 固定值所在层盘点**：仓库/SHA/数据集/canonical label 的固定值全部位于
  LF benchmark 适配层 `benchmarks/v4/baseline/lf_baseline.py`
  （`LF_TARGET_COMMIT_SHA=7fcf5b3b…`、`LF_DATASET_NAME/ROLE`、
  `LF_CANONICAL_LABEL=external/llamafactory-replay@7fcf5b3b`、`LF_WORKLOAD`、
  行尾转换与链接跳过的物化规则）及 sealed 工件/fixture 注册表；**生产规则层
  （`lima/repository_scanner.py`、`python_analyzer.py`、`python_dataflow.py`、
  `reviewer.py`、`workspace.py`）零 LF 身份串**（负例测试固化；Prompt/评分/过滤/
  fusion 无 LF 特例——B1 全禁平台、scanner 无 Prompt 面）。样本身份仅作
  provenance，不是安全判定条件；未发现生产判定中的仓库特例，无需 follow-up。
- **两个非 LF 小样本**（`tests/test_v4_baseline_nonlf_scanner_generality.py`）：
  - `pylib-mini`（Python 库型）：正例 eval/shell=True/硬编码密钥 + 安全近邻
    json.loads/shell=False/仅名称引用；走生产 `RepositoryScanner` 显式离线配置
    （不拷贝 scanner、不改规则、不伪装 LF、源字节直写不套 LF 行尾转换）；语义
    面恰为三正例（CWE-95/78/798），analyzer 身份串
    `repository-hybrid:python-ast+python-dataflow` 钉扎。
  - `docs-tests-mini`（文档/测试型）：盘点面 4 文件（json/conf/py；`.md` 如实
    落在 `unsupported-extension` skip 面，非 coverage-affecting），findings=0 为
    **measured 0**（与扫描失败区分：扫描完成、reviewer 面、零丢弃）。
  - **身份无关**：改名/搬目录后语义面（findings/scanned_files）恒等、provenance
    面（repository/root 标签）如实不同、树摘要跨物化稳定且字节敏感；
    **内容跟随**：正例→安全近邻恰使该 finding 消失、其余不动。
  - **边界**：小样本仅证共同扫描路径可复用与身份无关；不宣称跨真实仓库
    release pass、统计泛化、VEP/RVR 或完整 V5 生产能力。四模式注入证明按已证
    范围保留；旧 `870fdee5…` 不被新结果覆盖。

## 4. 可消费移交表（§五）

主表现值（每行权威状态列开头状态词自动复算）：**19 条款 = verified 11 / partial
7 / blocked 1**（第十轮呈报"partial 6"系复算误差，勘误已追加至 #57；真人工具
修复不提升 FR-05 实测状态——仍缺真人事件）。

| 消费者（Issue） | 所需上游 slice | 文件/fixture/digest | 现已满足 | 真实未满足项 |
|---|---|---|---|---|
| #61 Evidence Fusion/Issue/Hypothesis | Signal/Issue 产生点+去重/分级（A1 DR 裁定后实现叶） | report v2 三态面+`finding_to_domain_bundle`；B1/LF measured 面 | schema+legacy projection 接线（FR-04 verified）；b1-real 24/LF 27 实测计数 | Hypothesis/Signal→Issue 原生产生点不存在；V5-FR-03 生产能力缺口 |
| #75 CWE-22 Mining VEP | VEP 报告字段真实值（V5-FR-03）+Mining 插件输入 | report v2 `vep` 面（现 unavailable）；`platform_contracts` 构造器=C++ 域 preview | vep 字段+null 纪律在位（partial） | baseline 侧 VEP 产生点不存在（DR-IP-0037-01 pilot 维持 null）；Mining 插件未开工 |
| #77 Repair RVR | RVR 报告字段真实值+修复验证 gate 输入 | report v2 `rvr` 面（现 unavailable）；`patch_outcome_to_rvr` 无 runtime caller | rvr 字段+null 纪律在位（partial） | baseline 侧 RVR 产生点不存在；repair gate 链未接 baseline |
| #91 FULL_CHAIN 集成 | 上述产生点落位后的产物契约 | `lima/contracts` 版本契约（#58 已闭环交付） | 契约层可用（artifact_id+digest+schema_version） | 无 baseline 真实 VEP/RVR/Issue 产物可集成 |
| #59 遥测消费方（非 Mining/RVR Owner） | 见 §5 开工条件 | — | 见 §5 | 见 §5 |
| #62 CWE-798 语义降噪（非 Owner） | 语义证据输入 | LF 26 SEC-HARDCODED-SECRET 实测样本（`21aa06ec…`） | 静态事实供给 | 语义降噪逻辑本体（#62 自身范围） |
| #79 跨仓库最终 gate（非 Owner） | 九类真实批+A1/VEP/RVR | 矩阵 V5-AC-01（blocked） | 无 | 全部上游 |

已封存可消费件：fixture_registry canonical 字节+逐条目 tree fingerprint（可独立
复算）；LF R2 全 21 件（`c5545434…` 前缀，scanner `870fdee5…`/aggregate
`bf108f8f8…`/findings `21aa06ec…`）；b1 系 report/`9068e23d…`；before 声明 v1。
#57 整体未 Done ≠ 已封存 slice 不可消费；下游 Ready 仍须满足自身其他依赖。

## 5. #59 开工条件核对（仅核对，不实现）

| 条件 | 证据 | 结论 |
|---|---|---|
| #57 指标字典 | 报告 v2 计数面 `_COUNT_KEYS`（signals/security_issues/hypotheses/confirmed/inconclusive/scanned_files/coverage_gap）+三态投影词表（measured/legacy_projection/unavailable）；#57 矩阵各行口径 | **满足**（v2 面内封闭；A1 新增字段属演进另行裁定） |
| #57 machine profile | LF 链 `--machine-profile` 已入运行身份面（R2 执行记录） | **满足** |
| #58 run/attempt 契约 | #58 已 closed；`lima/baseline_run_result`（attempt_index/mode/outcome/taxonomy/canonical bytes/digest）在库、两批真实+LF 批实测 | **满足** |
| 统计窗口/单位/缺失值语义 | nearest-rank p50/p95（≥3c/≥5w、insufficient_sample）；ms/字节/μUSD 整数单位；缺失=None+unavailable（绝无假 0） | **满足** |

**结论：READY**（四项开工条件均有可核验证据）。#59 自身 FR/NFR（SLO 字典、
CostLedger、TelemetryRecorder Port 等）仍须其自己的 IP 切片交付；本任务不解锁
#62/#79，V4 Ready 与 V5 覆盖层不混谈。

## 6. 真人操作说明（可直接使用）

见本文 §6 与最终呈报；一条真人执行命令（**不带 `--synthetic`**）：

```
python scripts/run_expert_review.py ^
  --review-set D:\BaseAIProject\LIMA-real-runs\pr3d-lf-local-baseline-2026-10-01-r2\review-set-lf-local-baseline-2026-10-01.json ^
  --review-set-sha256 bd3695d6b6091955bb28180e73eb12c2c75d0a8c696ec1da9bec7f741319e2fb ^
  --reviewer-id <真人自选> ^
  --output-dir D:\BaseAIProject\LIMA-real-runs\expert-review-human-return-<日期>
```

回传两件（sidecar+receipt）后一条只读核验命令：

```
python scripts/verify_expert_review.py ^
  --sessions-dir <同一输出目录> ^
  --review-set D:\BaseAIProject\LIMA-real-runs\pr3d-lf-local-baseline-2026-10-01-r2\review-set-lf-local-baseline-2026-10-01.json
```
