# #57 基线结论报告（面向产品负责人，2026-10-02）

> 一页结论。证据明细与逐条索引见文末链接；不需要先读 receipt 或哈希清单即可理解本文。

## 当前系统能测什么（已交付能力）

对任意固定输入（合成 fixture 或固定 SHA 的公开仓库快照），系统能离线完成：

1. **真实本地扫描**：生产 `RepositoryScanner` 逐文件 AST+规则+跨文件数据流分析，输出候选告警（rule/CWE/行号/证据片段）、盘点文件数、覆盖缺口与全部跳过原因。
2. **重复执行与统计**：同一 RunSpec 下 3 次冷执行（每次重新物化+重扫）+5 次热执行（复用上次扫描结果），nearest-rank p50/p95，样本不足如实标 `insufficient_sample`。
3. **来源绑定与可复算**：每个数字可回指到 run_spec_digest/aggregate/scanner payload 的 SHA-256 链；独立核验命令可复核。
4. **失败保留**：失败 run 以 taxonomy 保留，不覆盖历史。
5. **诚实记账**：每个报告字段三选一标注 measured / legacy_projection / unavailable；模型关闭时调用量记 0，未执行的能力绝不记成成功。

## 主要结论

- **九类 fixture 结构/运行基线：9/9 通过**（application/library/cli/docs-content/test-heavy/monorepo/large-repo/malicious-layout/dependency-blocked，各 3c+5w、`sufficient_sample`、零模型调用、独立核验 PASS；合成 fixture 告警面：malicious-layout 4 条、library 1 条，其余 0——0 是扫描完成的 measured 0，不是没跑）。
- **公开仓库（LlamaFactory 固定 SHA）现状：扫描与统计链全部正常（447 文件/27 候选/8 attempts），但 27 条候选告警经 AI 静态技术复核判定为范围限定的误报（27/27）**。即：**当前系统的规则检测质量差，存在严重误报**；这不影响基线交付（测量、来源、覆盖、失败保留、候选与结论对应关系均已如实记录），但检测有效性需要后续规则修复，不能靠扩大样本或增加调用次数自愈。
- **候选告警 ≠ 复核结论**：AI 复核是静态技术判断（分析类型=源码 AST+语义阅读，适用范围=仅这 27 条，依据见链接），未冒充真人事件或动态验证；27 条误报的结论也不能推断整个仓库安全、无漏报或发布门通过。
- **warm 语义**：每类 8 attempts 对应 3 次真实扫描执行（cold 重扫、warm 复用结果）——如实测量了两种路径，不是 8 次独立扫描。

## 已知规则问题（两个通用根因，未修复、如实登记）

1. **调用名构造丢失接收者**：`Evaluator().eval()` 中对象方法被误判为内置动态执行（`lima/python_analyzer.py:21` 调用名拼接丢接收者）。
2. **凭据判定只看名称子串+字面量长度**：`tokenizer.padding_side`、`<|vision_start|>` 模型标记、`SERVICE_PASSWORD_ENV="SERVICE_PASSWORD"` 名称引用等被误报 SEC-HARDCODED-SECRET（无凭据语义上下文检查）。

处置边界：本次**不改 scanner 规则、不加白名单、不删误报样本**；修复属独立后续工作（通用规则修复+正负例回归），归 #62/#61 相关负责人，不在本基线收口内自动展开。

## 未测范围 / 不宣称的能力

- 真人复核分钟（sessions=0、time=unavailable 如实；可选效率指标，不阻塞收口）。
- 九类**真实公开仓库**验收、九类**在线模型**效果验收（两者明确后置，未标 verified）。
- Hypothesis/VEP/RVR/terminal outcome 的生产产生点（报告一律 unavailable；生产正确性归 #61/#75/#77，后置不阻塞）。
- Mining/Repair/动态执行引擎、跨仓库发布 gate（#77/#79 等既有归属）。
- 全仓人工标注 precision/recall（27 条复核结论不能外推）。

## 最短复核命令

```bash
# 九类证据独立核验（任选一类，目录 RR=D:\BaseAIProject\LIMA-real-runs）
python -c "import sys; sys.path.insert(0,'.'); from benchmarks.v4.baseline.b1_source import verify_b1_evidence as v; [print(c, v(r'pr3d-nine-class-baseline-2026-10-02/'+c)) for c in ['application','library','cli','docs-content','test-heavy','monorepo','large-repo','malicious-layout','dependency-blocked']]"

# LF R2 固定仓基线报告读取（现状记录）
python -c "import json;d=json.load(open(r'pr3d-lf-local-baseline-2026-10-01-r2/c5545434f14e9dde-report-1.json'));print(d['counts'],d['compression_chain'],d['expert'])"
```

## 证据索引

| 证据 | 位置 |
|---|---|
| 九类逐类运行工件+汇总+执行记录 | `LIMA-real-runs/pr3d-nine-class-baseline-2026-10-02/`（每类 runs×9+report+manifest+receipts；`nine-class-summary.json`；`EXECUTION_RECORD.md`） |
| LF 固定仓 R2 全 21 件（sealed） | `LIMA-real-runs/pr3d-lf-local-baseline-2026-10-01-r2/` |
| 27 条告警 AI 复核（逐条判断+探针+脚本） | `.pv_tmp/AI_REVIEW_LF_R2_2026-10-02/`（CONCLUSION.md/findings-review.json/verification.json） |
| 假绿修正与非 LF 样本 | `tests/test_v4_baseline_nonlf_scanner_generality.py`（4 候选含 1 已知误报，逐 path/rule/line 断言） |
| 证据对修复（真人入口） | PR #260（`eeb006c`）+ `docs/LIMA_Expert_Review_Evidence_Pair_Followup_2026-10-02.md` |
| 历史真实模型批（与本基线分开） | `LIMA-real-runs/pr3d-b1-real-2026-10-01/` 等（历史授权，本轮零调用） |
