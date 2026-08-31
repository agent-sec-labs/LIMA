# LIMA V4 Issues：代码级实施约束与测试矩阵

> 状态：Implementation Contract Baseline
> 适用范围：V4-I01–V4-I27 / GitHub #57–#84（不含编号空洞 #69）
> 事实基线：`main@379e832`；若主线符号发生变化，认领者必须先更新对应 Issue，不能静默偏离。

## 0. 全局开发契约

1. `V4-I02/#58` 是跨阶段 Schema 的唯一 Owner。下游只能消费 versioned fixture；改变字段语义必须先回到 #58。
2. `V4-I09/#68` 是 Audit 主链路 `lima/service.py`、`lima/api.py`、`lima/repository_scanner.py` 的唯一 Phase 1 Integration Owner。
3. `V4-I12/#66` 先引入 Artifact 持久化端口和迁移入口；之后 #67 才能增加 Attempt/Lease 持久化，避免同时编辑 `store.py` 与 `postgres_store.py`。
4. `V4-I14/#71` 是 `Dockerfile`、根 `docker-compose.yml` 和 Sandbox Policy 的唯一 Phase 2 Owner；#74 只提供依赖构建器和网络策略数据，不直接改根 Compose。
5. `V4-I18/#76` 只生成候选；`V4-I19/#77` 只裁决候选。候选生成模块不得导入最终 Gate 的内部实现。
6. Audit、Mining、Repair 不依赖隐式 Agent 记忆传递事实，只交换 RAM/AEP/VEP/RVR、Manifest 和 Artifact ID。
7. `timeout`、`OOM`、依赖缺失、网络失败、工具崩溃和 Schema 不兼容都是 typed infrastructure failure，永不映射为 `safe`、`refuted` 或 `verified`。
8. 新模块先提交纯函数/Port/fixture 测试；高冲突接线最后提交。一个 PR 不得同时修改两个阶段的领域算法。
9. 所有缓存键至少绑定 tenant、repository snapshot、schema major、tool/rule/policy digest；可变 Sandbox 状态不得缓存。
10. 标准测试命令为 `python -m unittest discover -s tests -v`、`python -m ruff check .`、`npm test -- --run`、`npm run build`；Docker/Soak/真实仓库测试使用显式手动工作流，不进入普通无 Secret CI。

## 0.1 高冲突文件锁

| 文件/目录 | 首要 Owner | 允许后续修改的条件 |
|---|---|---|
| `lima/service.py`、`lima/api.py`、`lima/repository_scanner.py` | #68 | #68 合并后，后续 Issue 只修改自己新增端点的最小接线，并在 Epic #85 留言 |
| `lima/store.py`、`lima/postgres_store.py` | #66 | #66 先提供 migration/metadata port；#67、#65 按依赖顺序追加，不并行编辑 `_init` |
| `lima/task_queue.py` | #67 | #84 只有 Gated 决策通过且 #67 已合并后才能改 |
| `lima/models.py` | #58 禁止改写 | V4 模型放在 `lima/contracts/`；兼容 adapter 由 #68 维护 |
| `lima/metrics.py`、`lima/observability.py` | #59 | 其他 Issue 只调用 recorder，不新增 Prometheus label |
| `Dockerfile`、`docker-compose.yml` | #71 | #72/#84 顺序化变更，必须基于 #71 的 profile/volume contract |
| `lima/repair_workspace.py`、`lima/security_repair.py` | #76 | #77 只包装 `RepairVerifier`，不得改候选策略 |
| `lima/verifier.py` | #77 | #76 只把候选作为输入，不调用 verifier 私有方法 |
| `frontend/src/shared/api/types.ts`、`client.ts` | #70 | 类型以 #58/#68 fixture 生成或手写镜像；后端 Issue 不改前端 |

---

<!-- ISSUE_BODY:57 START -->
## Status / Size

`V4-I01` · Phase 0 · `status:ready` · Size M

## Problem and observable outcome

在任何架构改造前冻结当前系统的速度、资源、费用、告警压缩率和专家时间基线。结果必须回答：LIMA 是否减少人工复核，而不是只报告扫描数量。非目标：修改扫描器、调参追指标、引入付费 CI 或重新标注 holdout。

## Current code baseline

- `lima/evaluation_harness.py`: `dataset_fingerprint`、`one_to_one_match`、`EndToEndEvaluationHarness`。
- `lima/real_world_evaluation.py`: `analyzer_fingerprint`、`load_real_world_dataset`、`SnapshotStore`、`RealWorldSecurityEvaluator`。
- `lima/repair_evaluation.py`: `RepairConstraintEvaluator`。
- `scripts/run_e2e_evaluation.py`、`run_real_world_evaluation.py`、`run_repair_evaluation.py`。
- 复用 `evaluation_data/` 的公开、固定、repository-disjoint 数据；不得改写 frozen holdout。

## File ownership and collision boundary

- **Add**: `benchmarks/v4/baseline/`、`evaluation_data/v4/baseline_manifest.json`、`tests/test_v4_baseline.py`、基准说明/结果模板。
- **Modify only when necessary**: 上述 `scripts/run_*` 的参数适配；不得改变评分语义。
- **Read-only**: `lima/repository_scanner.py`、`service.py`、`store.py`、现有 holdout 文件。
- **Must not modify**: Audit/Queue/Sandbox/Repair/Frontend 生产逻辑。

## Contract inputs, outputs, and invariants

- 输入 `BaselineRunSpec`: repository URL/name、固定 commit SHA、dataset fingerprint、analyzer fingerprint、config digest、seed、cold/warm、machine profile。
- 输出 `BaselineRunResult`: wall time p50/p95、queue wait、CPU time、peak RSS、IO bytes、LLM token/estimated cost、Signal/Issue/Hypothesis 数、expert minutes、precision/recall proxy、failure taxonomy。
- JSON 以 UTF-8、稳定 key 顺序和 SHA-256 封存；缺字段、moving ref、dataset drift、analyzer drift 必须 fail closed。
- 公开报告只保存摘要和哈希，不保存私有源码、原始 Secret、模型凭据或生产日志。

## Implementation slices / PR plan

- [ ] PR1：冻结支持矩阵、公开样本清单、机器规格和 manifest 校验。
- [ ] PR2：实现无业务侵入的计时/资源/Token/人工时间采集与稳定 JSON 输出。
- [ ] PR3：加入 LlamaFactory 高噪声基线、cold/warm 对照、报告模板和 secretless smoke。

## Required tests and boundary matrix

- `tests/test_v4_baseline.py`: 同 commit/config/seed 字节稳定；seed/config/工具指纹变化必改变 digest。
- 覆盖空仓库、无 Python 文件、扫描失败、LLM 关闭/超时/429、部分指标缺失、重复运行、clock 非单调保护。
- 数据集篡改、moving ref、重复 repository、holdout 与 calibration 交叉必须拒绝。
- smoke 必须断言无网络、无付费 LLM、无 Secret；完整运行只允许显式手动触发。
- 验收：LlamaFactory 固定 commit 可重放；输出 Signal→Issue 压缩前基线和专家分钟数；执行 `python -m unittest tests.test_v4_baseline tests.test_evaluation_harness tests.test_real_world_evaluation -v`。

## Dependencies / merge / rollback

无前置；Blocks #59、#62、#79。仅新增 benchmark 数据和脚本，回滚为删除新入口；不得通过修改 analyzer 获得更好数字。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:57 END -->

---

<!-- ISSUE_BODY:58 START -->
## Status / Size

`V4-I02` · Phase 0 · `status:ready` · Size L · **merge-first contract issue**

## Problem and observable outcome

冻结 Signal→SecurityIssue→VulnerabilityHypothesis 以及 RAM/AEP/VEP/RVR/Manifest 的版本契约，使三个阶段可只依赖 fixture 并行开发。非目标：重写现有 `Finding`/`ReviewReport`、接数据库、运行 Docker/LLM 或实现领域算法。

## Current code baseline

- `lima/models.py`: `EvidenceRecord`、`Finding`、`ReviewReport` 仅作为 legacy adapter 输入。
- `lima/task_progress.py`、`task_failure.py`: 当前进度和失败语义参考，不作为跨阶段 Artifact schema。
- `lima/adjudication.py`: 现有 disposition 语义参考。

## File ownership and collision boundary

- **Add**: `lima/contracts/{common,evidence,audit,mining,repair,sandbox,errors,codec}.py`、`schemas/v4/`、`tests/contracts/`、`docs/adr/027-*` 至 `040-*` 中实际需要的 ADR。
- **Modify only**: `lima/contracts/__init__.py` 的公开导出。
- **Read-only**: `lima/models.py`、`task_progress.py`、`task_failure.py`。
- **Must not modify**: store、queue、service、api、scanner、Sandbox、前端。

## Contract inputs, outputs, and invariants

- `ArtifactEnvelope`: `artifact_id`、`artifact_type`、`schema_version`、`tenant_id`、`repository_snapshot`、`producer`、`created_at`、`content_digest`、`policy_digest`、`toolchain_digest`、`lineage[]`、`coverage_gaps[]`。
- Evidence Level 固定 D0–D4；`SecurityIssue` 与 `Hypothesis` 分离；`inconclusive`/`blocked` 不能编码为 false。
- RAM/AEP/VEP/RVR、TaskManifest、ToolBundleManifest、DependencySnapshot、SandboxRunManifest 只引用不可变 Artifact ID/digest。
- Canonical JSON：UTF-8、sorted keys、紧凑 separators、拒绝 NaN/Infinity/重复语义字段；digest 覆盖权威内容但不覆盖传输层缓存头。
- 兼容规则：未知 major fail closed；同 major 的未知 optional 字段可保留并 round-trip；required 字段缺失拒绝；lineage 自环/跨 tenant 拒绝。
- 资源上限：schema 校验必须限制输入字节、嵌套深度、数组长度和字符串长度。

## Implementation slices / PR plan

- [ ] PR1：Common Envelope、Evidence/Issue/Hypothesis、canonical codec 和错误码。
- [ ] PR2：RAM/AEP/VEP/RVR 及 Task/Tool/Dependency/Sandbox manifests。
- [ ] PR3：JSON Schema、golden/negative fixtures、版本兼容矩阵和 ADR。
- [ ] PR4：只读 legacy `Finding` adapter fixture；生产接线留给 #68。

## Required tests and boundary matrix

- 每个 schema：最小合法、完整合法、required 缺失、错误 enum/type、未知 major、未来 minor、oversize/deep nesting。
- canonical digest：dict 顺序、LF/CRLF、Unicode、时区、浮点非法值、重复 lineage、字段篡改。
- 安全边界：tenant 不匹配、snapshot 不匹配、digest 不匹配、lineage 自环、Artifact 类型错配全部 fail closed。
- round-trip 必须保留未知 optional 字段；fixture 不 import DB/Docker/LLM/分析器。
- 执行 `python -m unittest discover -s tests/contracts -v` 和 `python -m ruff check lima/contracts tests/contracts`。

## Dependencies / merge / rollback

无前置；Blocks 除 #57 外全部 V4 核心任务。Schema 一旦被下游消费只能新增兼容 minor；破坏性改动必须新 major + ADR，不允许原地改 fixture。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:58 END -->

---

<!-- ISSUE_BODY:59 START -->
## Status / Size

`V4-I03` · Phase 0 · `status:blocked` · Size M

## Problem and observable outcome

建立可按 task/run/stage/tool/model/artifact 关联的 SLO、资源预算和成本账单，为停止策略、容量规划与 Go/No-Go 提供数据。遥测关闭或失败不得改变安全结论。

## Current code baseline

- `lima/metrics.py`: `Metrics.inc/timer/prometheus`，当前仅进程内低维指标。
- `lima/observability.py`: `Observability.span`、`AlertManager`。
- `lima/service.py`: `ScanProgressTracker` 和 `_execute_repository_scan` 是后续埋点调用方。
- `lima/task_progress.py`: durable stage snapshot；不得把高基数明细塞进 progress。

## File ownership and collision boundary

- **Modify**: `lima/metrics.py`、`lima/observability.py`。
- **Add**: `lima/telemetry/{events,recorder,cost,resources}.py`、`tests/test_v4_telemetry.py`、SLO 文档。
- **Read-only**: service/scanner/queue/sandbox；这些模块由 #68/#67/#71 后续调用公共 recorder。
- **Must not modify**: 业务控制流、store schema、前端。

## Contract inputs, outputs, and invariants

- `StageTelemetryEvent`: task/run/attempt/stage、outcome、duration、resource delta、tool/model identity digest、cache/dependency/artifact counters、budget stop reason。
- Prometheus label 只允许固定低基数枚举；task/repository/tenant/tool version 放结构化事件，不作为 label。
- `CostLedger` 以 attempt 记录 prompt/completion token、工具 CPU 秒、存储/网络字节和 estimated cost；重试与缓存命中单列，不能重复计费。
- recorder 为 no-op safe：异常被吞入内部诊断但不影响 verdict；所有文本先走 `sanitize`。

## Implementation slices / PR plan

- [ ] 定义事件/账单模型、低基数 label allowlist 和 no-op recorder。
- [ ] 扩展 Metrics/Observability adapter 与资源采样器。
- [ ] 提供调用示例 fixture；生产埋点分别由 #68/#67/#71 接入。
- [ ] 输出 SLO 指标字典、Dashboard 查询和预算停止原因表。

## Required tests and boundary matrix

- success/retry/cache-hit/cancel/timeout/OOM/tool-failure/LLM-429 事件互斥且账单不重复。
- 并发 recorder 线程安全；负值、counter 回退、未知 label、高基数 label、超长字符串拒绝或归一化。
- Token/费用缺失保持 `unknown`，不得默认为 0；凭据、仓库路径、源码片段不进入 metrics/log。
- 遥测 exporter 抛异常、关闭、采样丢失时业务返回保持一致。
- 执行 `python -m unittest tests.test_v4_telemetry tests.test_task_progress -v`。

## Dependencies / merge / rollback

Depends #57、#58；可与 #60/#61/#63/#65/#66 并行。先合并公共 recorder，再允许 Integration Issues 埋点。默认可通过配置关闭；回滚只移除调用，不删除已产生的历史指标。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:59 END -->

---

<!-- ISSUE_BODY:60 START -->
## Status / Size

`V4-I04` · Phase 1 · `status:blocked` · Size L

## Problem and observable outcome

在不执行目标仓库、不安装依赖的前提下生成 Repository Architecture Model（RAM）和安全语义清单，将全仓压缩为高价值分析路径，同时显式保留未覆盖区域。

## Current code baseline

- `lima/workspace.py`: `RepositoryWorkspace.inventory/read_text` 提供有界、安全、确定性的只读文件访问。
- `lima/python_dataflow.py`: `ModuleInfo`、`FunctionSymbol`、调用边和未解析调用可作为 Python 静态事实来源。
- `lima/semantic_retrieval.py`: `SecuritySemanticRetriever` 的函数级语义信号只读参考。
- `lima/repository_scanner.py`: 后续 #68 集成，当前 Issue 不修改。

## File ownership and collision boundary

- **Add**: `lima/audit/{inventory,ram,semantic_prioritizer}.py`、`tests/audit/test_ram.py`、RAM fixtures。
- **Modify only**: `lima/audit/__init__.py`。
- **Read-only**: workspace、python_dataflow、semantic_retrieval。
- **Must not modify**: scanner/service/api/store/sandbox/frontend；不得 `import` 或执行仓库代码。

## Contract inputs, outputs, and invariants

- 输入：#58 的 repository snapshot/TaskManifest、受限 inventory、语言/文件预算。
- 输出 RAM：language/framework、entrypoints、external sources、sensitive sinks、trust boundaries、key flows、function/call edges、Top-N paths、`coverage_gaps`、`execution_required`、model/prompt provenance。
- 排序必须确定：相同 snapshot/policy/seed 输出相同 identity；LLM 只能补充/排序语义，不得删除 Tier 0 或伪造静态事实。
- parse error、dynamic import、ambiguous module、budget exhaustion 必须进入 gap；“未看见”不能成为安全证明。

## Implementation slices / PR plan

- [ ] 仓库语言/框架/入口/配置/测试资产清单和 deterministic inventory adapter。
- [ ] Python symbol/call graph、Source/Sink/边界/关键流程抽取。
- [ ] 语义优先级和 Top-N 路径，保留静态 provenance 与 gap。
- [ ] RAM schema adapter、golden fixtures 和大仓库预算行为。

## Required tests and boundary matrix

- 空仓库、无 Python、单文件、package、namespace package、monorepo、重复模块名、相对导入、动态导入、语法错误。
- symlink/超大/二进制/隐藏/生成文件遵循 workspace 策略；路径必须 repo-relative，不能泄漏 host path。
- 恶意 `setup.py`/import side effect 证明不会执行；依赖缺失不触发下载。
- Top-N tie 稳定、预算截断可重放、LLM off/failure 不删除确定性结果。
- 执行 `python -m unittest tests.audit.test_ram tests.test_workspace tests.test_python_dataflow -v`。

## Dependencies / merge / rollback

Depends #58；复用 #10–#13 已有工作。可与 #61/#63/#65/#66 并行；Blocks #64/#68/#75。纯新增叶模块，回滚不影响现有扫描。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:60 END -->

---

<!-- ISSUE_BODY:61 START -->
## Status / Size

`V4-I05` · Phase 1 · `status:blocked` · Size L

## Problem and observable outcome

把 AST、数据流、SAST 和语义判断归一为 Signal，按根因聚类成 SecurityIssue，再生成可验证 Hypothesis；896 类原始命中必须压缩为可解释调查单元，而不是简单相加置信度。

## Current code baseline

- `lima/models.py`: legacy `Finding/EvidenceRecord` adapter 输入。
- `lima/sast.py`: `SastRunResult/BanditAdapter`。
- `lima/python_dataflow.py`: `TaintTrace/Sink/PythonDataflowResult`。
- `lima/repository_triage.py`: `RepositoryTriageOutcome`。
- `lima/adjudication.py`: disposition 规则参考；不能直接提升动态证据等级。

## File ownership and collision boundary

- **Add**: `lima/audit/{signals,adapters,issue_cluster,fusion,hypothesis}.py`、`tests/audit/test_fusion.py`。
- **Read-only**: models/sast/python_dataflow/repository_triage/adjudication。
- **Must not modify**: scanner/service/api/store/frontend、RAM 算法。
- legacy adapter 的生产接线由 #68 完成。

## Contract inputs, outputs, and invariants

- 输入：#58 Signal schema；每条 Signal 必须含 source/tool identity、rule/CWE、位置、symbol、evidence kind、provenance、支持/反驳方向和 coverage gap。
- `SecurityIssue.identity` 由 normalized repo path + sink identity + root-cause class + trust boundary 生成；行号漂移不能无条件产生新 Issue。
- 同一工具/同一规则的重复命中属于相关证据，不能提升独立证据计数；相互冲突必须保留。
- 输出 Hypothesis 包含 Source→Sink/关键控制流、触发条件、输入约束、安全不变量、建议 Oracle、支持/反驳证据和缺口。
- 静态/语义证据最高只能形成待 Mining 假设；自动关闭必须引用确定性反证及其适用范围。

## Implementation slices / PR plan

- [ ] AST/Dataflow/Bandit/Semantic legacy adapters 与稳定 Signal identity。
- [ ] 根因聚类、相关性分组、确定性去重和顺序无关合并。
- [ ] Evidence Fusion 状态机：support/refute/gap/conflict。
- [ ] Hypothesis 生成和 adjudication reason；提供 896 类回放 fixture。

## Required tests and boundary matrix

- 输入顺序、工具顺序、重复批次、行号小幅漂移不改变 Issue identity。
- 同 sink 不同 source、同 source 不同 sink、同位置不同 CWE、路径大小写/分隔符、缺 symbol/缺 CWE 正确分离。
- AST+Bandit 重复不虚增；独立 dataflow 可提高支持度；反证冲突不得自动 clear。
- malformed/oversize Signal、未知工具、跨 snapshot/tenant、digest 错误 fail closed。
- 执行 `python -m unittest tests.audit.test_fusion tests.test_sast tests.test_adjudication -v`。

## Dependencies / merge / rollback

Depends #58；可与 #60/#63/#65/#66 并行；Blocks #62/#64/#68/#75。纯新增叶模块；identity 算法发布后改变必须提供 migration/alias 说明。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:61 END -->

---

<!-- ISSUE_BODY:62 START -->
## Status / Size

`V4-I06` · Phase 1 · `status:blocked` · Size M

## Problem and observable outcome

针对当前 LlamaFactory 中大量 CWE-798 命中，区分协议 Token、模型名、fixture、placeholder、canary 与真实硬编码凭据，显著减少人工队列，同时保持真实 Secret 召回。非目标：通用 Secret Scanner、自动轮换或把不确定项判安全。

## Current code baseline

- `lima/python_analyzer.py`: `PythonAstSecurityAnalyzer` 的字面量规则。
- `lima/sast.py`: Bandit finding adapter。
- `lima/repository_scanner.py`: legacy Finding 汇合，由 #68 接线。
- `tests/test_workspace.py`、`tests/test_sast.py`: AST/SAST 精度边界。

## File ownership and collision boundary

- **Add**: `lima/audit/rules/hardcoded_secret.py`、`evaluation_data/v4/cwe798/`、`tests/audit/test_cwe798.py`。
- **Read-only**: python_analyzer/sast/models；通过 #61 Signal adapter 接入。
- **Must not modify**: 通用 fusion、scanner/service/api/frontend、真实凭据检测基线数据。

## Contract inputs, outputs, and invariants

- 输入：CWE-798 Signal、repo-relative context、symbol/config provenance；不得把完整 Secret 发送到 LLM，模型上下文使用类型、长度、字符类和不可逆摘要。
- 输出 `SecretSemanticAssessment`: `credential`、`protocol-token`、`fixture`、`placeholder`、`canary`、`unknown`，包含 deterministic facts、semantic rationale、scope 和 confidence。
- 只有可证明的协议常量/placeholder 可形成 deterministic refute；`unknown` 保持 review/mining gap。
- allowlist 必须绑定语义形态和使用上下文，禁止仅按变量名、字符串值或仓库名全局放行。

## Implementation slices / PR plan

- [ ] 建立正例、安全近邻、不确定样本与 LlamaFactory 固定 commit 回放集。
- [ ] 实现 credential/token 词法形态和协议上下文确定性分类。
- [ ] 实现最小化语义证据包与不确定回退。
- [ ] 通过 #61 adapter 输出 support/refute/gap，并生成降噪对照报告。

## Required tests and boundary matrix

- 覆盖真实 API key/password/private-key 片段、短 token、UUID、模型 ID、MIME/tokenizer 常量、测试 fixture、`${ENV}`/`changeme`、base64、拼接字符串、跨行字符串。
- 同一字面量在生产路径与 tests/examples 中不得无条件同判；注释、文档和死代码必须保留 provenance。
- 变量名欺骗、allowlist 子串、Unicode/转义、大小写、熵阈值边界、超长文本、解析失败必须 fail closed。
- 日志、Artifact、LLM fixture 不得出现真实 Secret；使用 canary 并扫描输出泄漏。
- 验收以 Issue-level precision、recall proxy 和 Review Queue reduction 对比 #57；执行 `python -m unittest tests.audit.test_cwe798 tests.test_workspace tests.test_sast -v`。

## Dependencies / merge / rollback

Depends #57/#58/#61；Blocks #79。若 Issue-level precision 没有改善，不扩充 Audit 工具。规则默认 feature flag 关闭，回滚恢复 candidate，不得批量标记 safe。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:62 END -->

---

<!-- ISSUE_BODY:63 START -->
## Status / Size

`V4-I08` · Phase 1 · `status:blocked` · Size L

## Problem and observable outcome

为 parse、tool result、RAM、evidence cluster 和 bounded LLM result 建立确定性 Audit Cache 与增量失效，降低重复扫描时延；缓存只复用不可变分析结果，绝不复用 Mining/Repair 可变状态。

## Current code baseline

- `lima/repository_cache.py`: `RepositoryCache`、`CacheKeyIdentity`、`lookup/reserve/publish/pin/cleanup`，是只读 repository snapshot cache。
- `lima/real_world_evaluation.py`: `SnapshotStore` 的 digest 校验参考。
- `tests/test_repository_cache.py`: 原子发布、并发、TTL、边界逃逸现有覆盖。

## File ownership and collision boundary

- **Add**: `lima/audit/{cache,analysis_cache,invalidation}.py`、`tests/audit/test_analysis_cache.py`。
- **Read-only**: `lima/repository_cache.py` 内部实现；只消费其 immutable snapshot identity。
- **Must not modify**: store、service/api、Mining/Repair、root volumes；生产接线由 #68。

## Contract inputs, outputs, and invariants

- cache key = tenant scope + repository snapshot digest + artifact/schema major + analyzer/tool/rule/prompt/model/policy/config digest + normalized unit identity。
- value 必须是 #58 合法 Artifact payload 或其 digest；写入采用 staging→digest verify→atomic publish；partial 永不可见。
- invalidation graph 明确 file→parse→tool/RAM→cluster→LLM 的依赖；任何未知依赖或版本变化按 miss 处理。
- 跨 tenant 默认隔离；允许公共开源 cache 必须有独立 policy 和无敏感内容证明。

## Implementation slices / PR plan

- [ ] 通用 immutable AnalysisCache port、key codec 和 value validation。
- [ ] parse/tool/RAM/fusion/LLM namespace 与 single-flight。
- [ ] 文件级增量依赖图、失效解释和 cache diagnostics。
- [ ] cold/warm benchmark adapter；#68 负责主链路接入。

## Required tests and boundary matrix

- key 的每个维度单独变化均 miss；字段顺序/LF-CRLF 等规范化等价输入命中。
- concurrent same-key 只执行一次；producer crash、staging orphan、digest mismatch、disk full、lock timeout 不暴露半成品。
- 删除/重命名/新增文件、依赖边变化、unknown analyzer version、policy rollback 正确失效。
- tenant A 不能读 tenant B；Secret/源码受 retention/ACL 约束；Mining/Repair 类型拒绝写入。
- cold/warm 指标可重放；执行 `python -m unittest tests.audit.test_analysis_cache tests.test_repository_cache -v`。

## Dependencies / merge / rollback

Depends #58/#60/#61；复用 #12 snapshot cache；Blocks #68/#78。纯新增层，默认 disabled；回滚只造成 cache miss，不改变 verdict 或删除 repository snapshot。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:63 END -->

---

<!-- ISSUE_BODY:64 START -->
## Status / Size

`V4-I07` · Phase 1 · `status:blocked` · Size M

## Problem and observable outcome

实现 Fast/Deep Audit 和 Tier 0/1/2 的预算、优先级与停止策略，使用户先看到高价值结果，系统在证据充分、无边际收益或预算耗尽时可解释地停止。

## Current code baseline

- `lima/runtime.py`: `RuntimeBudgetExceeded`、`AgentRuntime`、`AgentLoop` 的 step/token 预算参考。
- `lima/task_progress.py`: 当前扫描阶段；由 #68 扩展 V4 revision/progress。
- #60 RAM、#61 SecurityIssue/Hypothesis 是唯一规划输入。

## File ownership and collision boundary

- **Add**: `lima/audit/{planner,budget,scheduler_policy}.py`、`tests/audit/test_planner.py`。
- **Read-only**: runtime/task_progress；不得复用 runtime 私有状态作为 AuditPlan。
- **Must not modify**: queue、service/api、sandbox、leaf analyzer；#68 集成。

## Contract inputs, outputs, and invariants

- 输入：RAM、SecurityIssues/Hypotheses、Tool capabilities、SLO/budget、policy digest、previous revision summary。
- 输出 `AuditPlan`: Tier 0 全仓固定工具；Tier 1 Top 10–20 Issues；Tier 2 Top 3–5 Hypotheses；每步工具/LLM/time/output/resource budget 和 stop condition。
- 排序只使用可审计特征；tie 稳定。预算耗尽输出 `coverage_gap/budget_exhausted`，不能生成安全结论。
- Fast Path 不等待 Mining/Repair；LLM 429/timeout 只降级语义步骤，确定性 Tier 0 继续。

## Implementation slices / PR plan

- [ ] Budget ledger、原子 reserve/commit/release 和 stop reason enum。
- [ ] Tier ranking、稳定 tie-breaker、资源池和 per-tool quota。
- [ ] evidence-sufficient/no-yield/budget/cancel 停止策略。
- [ ] Fast/Deep revision fixture 和 deterministic replay。

## Required tests and boundary matrix

- 0/负/极小/超大预算、并发 reserve、重试退款/不退款、cache hit、cancel race、clock 超时。
- RAM/Issue 空、相同分数、缺 severity、未知工具、工具撤销、LLM 429、输出超限。
- Tier 0 永不因语义剪枝被删；Tier 1/2 上限严格；相同输入计划字节稳定。
- stop 后不得继续调用工具；每个未执行步骤有 reason/gap。
- 执行 `python -m unittest tests.audit.test_planner tests.test_runtime_memory_context -v`。

## Dependencies / merge / rollback

Depends #59/#60/#61；Blocks #68。纯新增策略层，#68 以 feature flag 接入；回滚到固定 Tier 0 仍保留 gap，不回退为“全量告警即漏洞”。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:64 END -->

---

<!-- ISSUE_BODY:65 START -->
## Status / Size

`V4-I11` · Phase 1 · `status:blocked` · Size M

## Problem and observable outcome

建立 Security Case Candidate v0，把专家正/负反馈、工具失败和 inconclusive 归一为可追溯候选；候选仅用于评测和后续知识库，不提升当前任务证据等级。

## Current code baseline

- `lima/service.py`: `record_feedback` 当前把反馈写入 failure cases。
- `lima/store.py`/`postgres_store.py`: `record_failure_case`、`list_task_failure_cases`。
- `lima/memory.py`: tenant/repository scoped recall 仅作隔离参考，不作为权威 Case Store。
- `frontend/src/features/tasks/TaskDetailPage.tsx`: 现有反馈入口，由 #70 负责 UI。

## File ownership and collision boundary

- **Add**: `lima/knowledge/{candidates,ports,feedback_adapter}.py`、`tests/knowledge/test_candidates.py`。
- **Phase A read-only**: service/store/api；先交付 domain + in-memory port fixture。
- **Phase B after #66/#68**: 仅通过 Artifact Registry adapter 持久化；若需修改 `record_feedback`，必须在 #68 合并后做一个独立 integration PR。
- **Must not modify**: 向量/RAG、全量检索、evidence fusion、Evidence Level。

## Contract inputs, outputs, and invariants

- Candidate kinds: confirmed-positive、confirmed-negative、inconclusive、tool-failure；状态 draft→reviewed→promoted/rejected→revoked。
- 必填 provenance：tenant、snapshot、task/issue/hypothesis/artifact digest、actor type、label source、created_at、scope、quality、fingerprint。
- 原始 Signal、单次 LLM 总结或匿名无依据反馈不能 promoted；跨 tenant 默认不可见。
- revoke 立即阻止新检索/评测使用，历史 run 仍通过 digest 可重放。

## Implementation slices / PR plan

- [ ] Domain model、fingerprint、状态机、repository port 和 fixtures。
- [ ] 将现有 feedback payload 归一化为 Candidate，不改变当前 feedback API。
- [ ] #66 后实现 Artifact-backed adapter；#68 后做最小 service 接线。
- [ ] 导出评测用只读集合和 provenance/quality 报告。

## Required tests and boundary matrix

- positive/negative/inconclusive/tool-failure、重复反馈、冲突标签、撤销、非法状态跳转。
- 跨 tenant/repository/snapshot 查找拒绝；缺 actor/provenance/digest、未来 schema、篡改 payload fail closed。
- 同一 Case 幂等；并发 promote 只有一个权威版本；revoke 后不进入新 run。
- 确认 Candidate 不改变源任务 adjudication/Evidence Level。
- 执行 `python -m unittest tests.knowledge.test_candidates tests.test_service tests.test_runtime_memory_context -v`。

## Dependencies / merge / rollback

Domain depends #58/#61；持久化 depends #66；生产接线在 #68 后。Blocks #80。回滚停止生成新 Candidate，不删除已封存 Artifact；不得回写历史 verdict。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:65 END -->

---

<!-- ISSUE_BODY:68 START -->
## Status / Size

`V4-I09` · Phase 1 · `status:blocked` · Size L · **唯一 Audit backend Integration Issue**

## Problem and observable outcome

把 repository snapshot、RAM、Tier 0 静态工具、Issue Fusion、Fast/Deep Planner 和 Audit Cache 接入现有异步扫描，产出 initial/deep AEP。AEP 只表达值得 Mining 验证的 Hypothesis，不把静态命中直接声明为漏洞。

## Current code baseline

- `lima/service.py`: `ReviewService.repository_scan_capabilities`、`_enqueue_scan_task`、`_process_repository_scan`、`_process_github_repository_scan`、`_execute_repository_scan`、`ScanProgressTracker`。
- `lima/repository_scanner.py`: `RepositoryScanner.scan` 和 legacy `RepositoryScanResult`。
- `lima/api.py`: `GET /api/tasks`、`GET /v1/tasks/{id}`、`POST /v1/repository-scans`。
- `lima/task_progress.py`: durable progress；`store.update_task_progress/failure`。

## File ownership and collision boundary

- **Modify**: `lima/service.py`、`lima/api.py`、`lima/repository_scanner.py`、`lima/task_progress.py` 的 V4 stage 常量、repository scan integration tests。
- **Add**: `lima/audit/pipeline.py`、`lima/audit/legacy_adapter.py`、AEP API fixtures。
- **Read-only**: #59/#60/#61/#63/#64 leaf internals、#66 Artifact port。
- **Must not modify**: leaf 算法、store schema、queue implementation、sandbox、frontend。

## Contract inputs, outputs, and invariants

- Pipeline：Snapshot→Inventory/RAM→Tier0 Signals→SecurityIssue/Hypothesis→initial AEP→Deep Plan→revised AEP。
- `GET /v1/tasks/{id}` 增加可选 `analysis`: RAM ref、AEP latest/sealed revisions、issue summary、coverage gaps；旧字段保持兼容。
- AEP revision append-only；失败/取消不得覆盖已 seal revision。每次重试以 attempt id 产生 staging output，幂等提交同一 digest。
- 部分工具失败记录 typed gap；required Tier 0 失败按策略 fail closed；LLM 失败不丢确定性结果。
- 任何 Artifact/API 输出不得含 host path、凭据、原始完整源码或未授权 tenant 数据。

## Implementation slices / PR plan

- [ ] PR1：pipeline adapter + fixture，仅消费 #58/#60/#61/#64，不改 API。
- [ ] PR2：initial AEP、Artifact seal、progress/retry/cancel/cache 接线。
- [ ] PR3：Deep revision、API response 和 backward-compatible legacy report projection。
- [ ] PR4：integration/failure/cache/performance tests；前端 fixture 交给 #70。

## Required tests and boundary matrix

- offline GitHub/local import、cache miss/hit、empty repo、partial parse、Tier0 unavailable、LLM off/timeout/429、budget exhausted。
- enqueue/worker restart/retry/cancel 在各阶段；重复消息不产生重复 AEP；失败不覆盖 sealed revision。
- API 旧客户端忽略新字段；tenant/RBAC、404、invalid Artifact、unknown schema、oversize response。
- 30–60 秒出现 RAM/progress；参考机 M 仓库 Fast Audit p95 ≤ 5 分钟；性能失败记录而非放宽安全门。
- 执行 `python -m unittest tests.test_repository_scan_integration tests.test_repository_import tests.test_task_progress tests.test_api_security -v`。

## Dependencies / merge / rollback

Depends #59–#64/#66 及既有 #34–#37；Blocks #70/#78/#79。以 `LIMA_V4_AUDIT_ENABLED=false` 默认兼容旧路径，启用后双写/对比一个版本；回滚保留已封存 AEP，仅停止新 pipeline。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:68 END -->

---

<!-- ISSUE_BODY:70 START -->
## Status / Size

`V4-I10` · Phase 1 · `status:blocked` · Size L · **唯一 V4 frontend Integration Issue**

## Problem and observable outcome

把结果界面从原始 Finding 列表改为 Issue-centric 渐进式工作台，明确区分 candidate、inconclusive、dynamically verified 和 Verified Patch；刷新后可恢复，终态停止轮询。

## Current code baseline

- `frontend/src/shared/api/types.ts`、`client.ts`: 当前 Task/Scan/Repair 类型和 Bearer client。
- `frontend/src/features/tasks/TaskDetailPage.tsx`、`model.ts`: 报告、Evidence、反馈和 polling。
- `TaskListPage.tsx`、`router/index.tsx`: 列表与路由。
- `TaskCenter.test.tsx`、`TaskDetail.report.test.tsx`: 现有行为保护。

## File ownership and collision boundary

- **Add**: `frontend/src/features/security-analysis/{model,AuditOverview,IssueList,IssueDetail,MiningPanel,RepairMatrix}.tsx` 及同目录测试。
- **Modify**: `shared/api/types.ts`、必要的 `client.ts`、`TaskDetailPage.tsx`、`router/index.tsx`；只由本 Issue 负责。
- **Read-only**: backend、store、Sandbox、#68 JSON fixtures。
- **Must not modify**: 旧 backend 算法或为 UI 便利改变 schema；不存在的字段必须显式 empty/unknown。

## Contract inputs, outputs, and invariants

- 只消费 #68 的 optional `analysis`、AEP revisions、SecurityIssue/Hypothesis、typed gaps；Mining/Repair 只显示 Artifact 状态。
- UI 标签映射：static candidate ≠ verified vulnerability；inconclusive ≠ safe；repair candidate ≠ verified patch。
- RBAC/tenant 由服务端权威；前端不持久化源码、Secret、PoC 原文或 Sandbox token。
- Polling 依据 lifecycle + artifact terminal state；刷新/直达路由从 API 重建，不依赖内存。

## Implementation slices / PR plan

- [ ] API type/fixture 与纯 model derivation，覆盖未知/旧 payload。
- [ ] RAM/coverage/AEP revision/Issue list/detail 渐进式视图。
- [ ] Mining evidence、Gate 状态、Repair candidate matrix 与 typed retry action。
- [ ] 路由恢复、polling、a11y、Vitest/Playwright；不在一个 PR 同时改所有页面。

## Required tests and boundary matrix

- initial AEP 后 deep revision 到达、顺序乱序/重复 revision、刷新、404/403/500、网络断开/恢复、取消/失败/成功。
- 0/1/1000 Issues、长路径/Unicode、缺字段/未来 enum、oversize evidence 摘要、分页。
- 文案断言禁止 candidate→verified、inconclusive→safe；无动态证据不显示“漏洞成立”。
- 键盘导航、焦点、ARIA、色彩之外状态提示；终态不轮询，运行态退避。
- 执行 `cd frontend && npm test -- --run && npm run build`，以及 Linux Playwright lifecycle 场景。

## Dependencies / merge / rollback

Depends #68 和既有 #38–#42；可在 #58/#68 fixture 后提前开发。新路由/面板以 capability gate 控制；旧 Task detail 保留兼容 projection，回滚不改后端数据。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:70 END -->

---

<!-- ISSUE_BODY:66 START -->
## Status / Size

`V4-I12` · Phase 2 · `status:blocked` · Size L · **唯一 MVP Artifact store/migration Owner**

## Problem and observable outcome

实现不可变、内容寻址、可校验、可恢复的 Artifact Registry，作为三阶段唯一事实交换通道；元数据与 blob 的部分失败不能产生“已封存”假象。

## Current code baseline

- `lima/store.py`/`postgres_store.py`: 当前 SQLite/PostgreSQL 双实现，schema 在 `_init` 内创建。
- `lima/repository_cache.py`: content-addressed、reserve/publish/pin/cleanup 的文件系统安全模式参考，但不是 Artifact Store。
- `docker-compose.yml`: PostgreSQL 与现有 volumes；由 #71 负责后续根 Compose。

## File ownership and collision boundary

- **Add**: `lima/artifacts/{models,ports,local_store,metadata,retention,recovery}.py`、`lima/persistence/migrations.py`、`tests/artifacts/`。
- **Modify exclusively until merged**: `lima/store.py`、`lima/postgres_store.py` 的 migration hook 和 Artifact metadata adapter。
- **Read-only**: repository_cache；不得把 repository snapshot 与 Artifact blob 混成同一 trust domain。
- **Must not modify**: queue/sandbox/audit/mining/repair/service/api/root compose。

## Contract inputs, outputs, and invariants

- API：`stage(payload, envelope)`→staging handle；`seal(handle, expected_digest)`→immutable ArtifactRef；`get/ref/list_lineage/expire/reconcile`。
- 状态仅 `STAGING|SEALED|QUARANTINED|EXPIRED|DELETING`；只有 SEALED 可跨阶段引用。
- blob key 使用 SHA-256 + artifact type/schema；metadata 记录 tenant、producer、snapshot、size、retention、lineage、ACL、created/sealed time。
- 协议：先写临时 blob→fsync/verify→事务写 SEALED metadata→原子 rename；失败由 reconcile 判断 orphan/metadata-only，不能静默修复 digest。
- Artifact 不可覆盖；同 tenant/type/digest 幂等返回同内容，但 lineage/ACL 不得被较弱请求扩大。
- Redis 永不作为权威 Artifact/metadata；本地文件存储提供 S3-compatible Port，不在 MVP 实现自研对象存储。

## Implementation slices / PR plan

- [ ] migration registry，使后续 Issue 可新增表而不并行改两个 store `_init`。
- [ ] Artifact domain/Port/local content-addressed store 和路径防护。
- [ ] SQLite/PostgreSQL metadata adapter、原子 seal 和 tenant ACL。
- [ ] retention/reference/reconcile、orphan/partial recovery 和 S3 Port contract fixture。

## Required tests and boundary matrix

- 0-byte/最大/超限 Artifact、digest mismatch、type/schema mismatch、重复 seal、并发同 digest、不同 tenant 同 digest。
- kill points：blob 前/写中/rename 后/metadata commit 前后；重启 reconcile 不出现假 SEALED。
- 路径穿越、symlink/hardlink、case collision、磁盘满、权限拒绝、corrupt blob、lineage 自环/跨 tenant。
- TTL 与 active reference/pin；删除 race、late reader、orphan cleanup；Redis down 不丢事实。
- SQLite/PostgreSQL 行为契约相同；执行 `python -m unittest discover -s tests/artifacts -v` 和现有 store/cache tests。

## Dependencies / merge / rollback

Depends #58；Blocks #65/#67/#71/#72/#75–#80。migration 必须向前兼容：旧任务表不改语义；回滚应用版本不得删除新表/blob，最多停止新写并保持只读恢复工具。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:66 END -->

---

<!-- ISSUE_BODY:67 START -->
## Status / Size

`V4-I13` · Phase 2 · `status:blocked` · Size L · **唯一 V4 queue/attempt Owner**

## Problem and observable outcome

把现有 best-effort worker 投递扩展为 durable lease、attempt-scoped output、幂等权威提交和崩溃恢复，使 Worker/API/Scheduler 重启或重复消息不会产生两个权威结果或双重费用。

## Current code baseline

- `lima/task_queue.py`: `TaskQueue.submit/_deliver/_schedule_retry/_redis_worker/_reclaim_stale`，支持 memory/Redis 与 DLQ。
- `lima/runtime.py`: checkpoint 恢复参考。
- `lima/store.py`/`postgres_store.py`: task/checkpoints/cancel；必须基于 #66 migration hook 顺序追加。
- `tests/test_task_failure.py`、`test_production_features.py`: retry/DLQ/recovery 现有语义。

## File ownership and collision boundary

- **Modify**: `lima/task_queue.py`；#66 合并后通过 migration registry 增加 attempt/lease metadata adapter。
- **Add**: `lima/worker_runtime/{lease,attempt,idempotency,recovery}.py`、`tests/worker_runtime/`。
- **Read-only**: Audit/Mining/Repair/Sandbox 业务；它们只消费 `WorkAttempt` Port。
- **Must not modify**: root compose、Artifact store 内部、service/api 业务语义、frontend。

## Contract inputs, outputs, and invariants

- `WorkEnvelope`: immutable task manifest ref、message id、idempotency key、attempt id、not-before、lease policy。
- 状态 `QUEUED→LEASED→RUNNING→COMMITTING→SUCCEEDED|FAILED|CANCELLED|ABANDONED`；CAS + fencing token 防止 stale worker 提交。
- attempt 只能写自己的 staging Artifact；权威提交要求 Artifact 已 seal 且 task 未被其他 fencing token 终结。
- delivery 至少一次；结果有效一次；费用 ledger 按 idempotency/attempt 去重。
- infrastructure failure 与 security verdict 分表述；retry policy 只依据 typed failure，不解析异常文本。

## Implementation slices / PR plan

- [ ] WorkEnvelope、lease/heartbeat/fencing/idempotency domain 和 migration。
- [ ] memory backend deterministic tests，再实现 Redis adapter；保持现有 submit 兼容 facade。
- [ ] attempt output→Artifact seal→CAS authoritative commit。
- [ ] reclaim/cancel/retry/DLQ/restart recovery 与 operator diagnostics。

## Required tests and boundary matrix

- kill before/after lease、upload、seal、commit；heartbeat delay、clock skew、stale worker、lease expiry race。
- duplicate/reordered message、same idempotency different payload、retry exhaustion、permanent failure、cancel at every state。
- API/Scheduler/Worker/Redis restart；Redis unavailable/reconnect；memory backend 不声称 durable HA。
- 两 worker 竞争只有一个 authoritative result/cost；staging orphan 可由 #66 回收。
- 执行 `python -m unittest discover -s tests/worker_runtime -v`、`tests.test_task_failure`、`tests.test_production_features`。

## Dependencies / merge / rollback

Depends #66，复用 #34/#35；Blocks #71/#72/#78。先 migration/domain，再 queue adapter；不得与 #66 并行编辑 store。feature flag 可回退旧单机 queue，但存在 RUNNING attempt 时禁止降级，必须 drain 或 cancel。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:67 END -->

---

<!-- ISSUE_BODY:71 START -->
## Status / Size

`V4-I14` · Phase 2 · `status:blocked` · Size L · **唯一 Supervisor/root Docker Policy Owner**

## Problem and observable outcome

建立单机 Worker Supervisor 管理 Audit、Mining、Repair 一次性 Sandbox，以 R--/RX-/RWX 最小权限强制三阶段信任边界；三个 Sandbox 不直连、不共享可写卷。

## Current code baseline

- `docker-compose.yml`/`Dockerfile`: 当前单 `lima` runtime，read-only rootfs、cap_drop、repository/cache/repair volumes。
- `lima/repair_workspace.py`: 有界 disposable copy 参考，不是 Sandbox supervisor。
- `lima/runtime.py`: AgentRuntime 不是 OS 隔离边界。
- `lima/task_queue.py`: #67 提供 WorkAttempt/lease。

## File ownership and collision boundary

- **Add**: `lima/sandbox/{profiles,manifest,supervisor,runner,collector,cleanup}.py`、`docker/sandbox/`、`tests/sandbox/`。
- **Modify exclusively**: `Dockerfile`、根 `docker-compose.yml`、必要的 `lima/config.py` sandbox settings。
- **Read-only**: #66 Artifact Port、#67 WorkAttempt Port、各阶段领域算法。
- **Must not modify**: Audit/Mining/Repair/Dependency/Tool Registry 内部。

## Contract inputs, outputs, and invariants

- 生命周期 `prepare→run→collect→seal→destroy`；每步产生 `SandboxRunManifest` 和 typed state。
- R-- Audit：只读 source/inbox，无目标代码执行；RX- Mining：只读 snapshot + executable scratch/outbox；RWX Repair：只写 disposable copy/outbox。
- 默认 network none；N0/N1/N2/N3 由显式 policy grant 决定。Sandbox 无 Control Plane/DB/Object Store/GitHub 长期凭据。
- mount allowlist、non-root、read-only rootfs、cap drop、no-new-privileges、PID/CPU/RSS/disk/time/output 限制；Manifest 越权 fail closed。
- collect 只接受 outbox 内声明文件并校验大小/type/digest；销毁失败隔离 worker node，不能复用污染环境。

## Implementation slices / PR plan

- [ ] Profile/Manifest validator 和 pure policy tests。
- [ ] Supervisor/runner/collector/cleanup Port + fake backend。
- [ ] Linux container backend、镜像/volume/network/resource policy。
- [ ] WorkAttempt/Artifact 接入、crash cleanup 和操作审计；平台兼容矩阵。

## Required tests and boundary matrix

- 读/写/执行矩阵对每个 profile 穷举；越权 mount、host path、socket、device、capability、network、secret env 拒绝。
- timeout/OOM/PID bomb/disk full/output flood/forked late process/cancel/Supervisor restart。
- symlink/hardlink/outbox escape、TOCTOU、恶意 filename、digest mismatch、cleanup failure/node quarantine。
- 三阶段不可通过 shared writable volume/localhost/控制平面互传；Audit 执行项目应失败。
- unit/fake backend 进普通 CI；Linux Docker integration 显式 job，执行 `python -m unittest discover -s tests/sandbox -v`。

## Dependencies / merge / rollback

Depends #66/#67；Blocks #73–#78。根 Compose/Dockerfile 在本 Issue 合并期间加文件锁。新 Supervisor 默认 off，shadow run 后切换；回滚前必须 drain attempts 和销毁 Sandbox，不删除 Artifact。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:71 END -->

---

<!-- ISSUE_BODY:73 START -->
## Status / Size

`V4-I15` · Phase 2 · `status:blocked` · Size M

## Problem and observable outcome

建立 Tool Registry v0、固定 Tool Bundle 和按需检索，只向当前任务加载少量已批准、digest-pinned 工具；不允许把 Registry 全量挂载或依据历史成功率自动确认漏洞。

## Current code baseline

- `lima/runtime.py`: 当前进程内 `AgentTool/ToolRegistry`，只校验参数 schema，无持久风险/版本治理。
- `lima/sast.py`: `BanditAdapter` 是首个确定性工具 adapter 参考。
- `lima/skills.py`/`skill_evolution.py`: manifest checksum/激活语义参考，但 V4 Tool 不等同可执行 Skill。

## File ownership and collision boundary

- **Add**: `lima/tool_registry/{models,registry,retrieval,policy,adapters}.py`、`tool_manifests/v0/`、`tests/tool_registry/`。
- **Modify narrowly**: `lima/runtime.py` 只增加兼容 facade/导入，不能保留两个权威 Registry。
- **Read-only**: Sandbox policy、业务 planner、Skill evolution。
- **Must not implement**: 自动下载、自动批准、任意 shell command、Tool Evolution。

## Contract inputs, outputs, and invariants

- ToolManifest 必填 name/version/source/digest/license/language/CWE/capability/risk/argv template/dependencies/input-output schema/resource/network/provenance。
- 状态 `QUARANTINED|APPROVED|REVOKED`；只有 APPROVED 且 digest 匹配可进入 Bundle；revoked 立即禁止新任务。
- ToolBundleManifest 绑定 task/hypothesis/sandbox profile/policy，Top-K retrieval 可解释、确定、有限。
- command 使用 argv 数组与 placeholder schema，禁止 shell interpolation；Registry 不保存凭据。

## Implementation slices / PR plan

- [ ] manifest/schema/状态机/digest/license/risk validator。
- [ ] registry + approved/revoked storage Port 和基础 Semgrep/Bandit/test/Harness manifests。
- [ ] language/attack-surface/Hypothesis Top-K retrieval 与 Bundle seal。
- [ ] runtime compatibility adapter；真实执行由 #71 Sandbox runner。

## Required tests and boundary matrix

- duplicate name/version、digest drift、unknown field/version、missing license/source、revoked/quarantined、risk/profile mismatch。
- argv injection、placeholder escape、relative executable、network requirement、oversize output contract 必须拒绝。
- Top-K tie 稳定；language/CWE mismatch 不返回；Registry 10k 条仍不全量装载。
- 历史成功率只影响排序且不能改变 Evidence Level；Bundle replay digest 稳定。
- 执行 `python -m unittest discover -s tests/tool_registry -v` 和现有 runtime/skills tests。

## Dependencies / merge / rollback

Depends #58 和 #71 profile contract；可与 #74 的 resolver 叶模块并行。Blocks #74/#75。旧 runtime ToolRegistry facade 保留一个版本；回滚禁止新 Bundle，已封存 Bundle 仍可审计重放。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:73 END -->

---

<!-- ISSUE_BODY:74 START -->
## Status / Size

`V4-I16` · Phase 2 · `status:blocked` · Size L

## Problem and observable outcome

将 Python lock/manifest 解析为 digest-pinned Dependency Snapshot 和离线 wheelhouse，使 Mining/Repair 在断网时重建相同环境，并为缓存缺失、私有依赖、sdist/build backend 等给出 typed failure。

## Current code baseline

- `pyproject.toml`/`requirements.txt`: LIMA 自身依赖格式参考。
- `lima/repository_materializer.py`: 受控网络、redirect、大小/摘要错误语义参考。
- `lima/task_failure.py`: 当前集中 failure catalog 只读；V4 failure 放入 #58 manifest，不并行改此文件。
- #71 N0/N1 profile 和 #73 Tool manifest 是唯一执行/工具输入。

## File ownership and collision boundary

- **Add**: `lima/dependencies/{detect,plan,resolver,snapshot,wheelhouse,policy,errors}.py`、`docker/dependency-builder/`、`tests/dependencies/`。
- **Modify only after #71**: 独立 dependency builder 配置；不得直接改根 Compose/Dockerfile。
- **Read-only**: sandbox supervisor、task_failure、Mining/Repair。
- **Must not implement**: Sandbox 内公网 pip、凭据透传、未哈希依赖、自动 sdist 执行。

## Contract inputs, outputs, and invariants

- 输入：repository snapshot、`pyproject/requirements/poetry/pdm/uv` lock manifests、Python/platform policy、N0/N1 grant。
- 输出 `ResolutionPlan` 和 `DependencySnapshot`: interpreter/platform tags、normalized requirements、wheel digests、index provenance、build decisions、unsupported gaps、snapshot digest。
- Builder 可在受控 N1 获取；Mining/Repair Sandbox 仅 N0 从只读 wheelhouse 安装。before/after 必须使用同 Snapshot digest。
- pure wheel 优先；sdist/VCS/path/private dependency 默认 typed blocked，除非独立已批准 builder policy；摘要不匹配永久失败。
- 凭据只在 broker 短时使用，不写 manifest/cache/log/wheel metadata。

## Implementation slices / PR plan

- [ ] manifest detection/normalization、platform matrix 和 deterministic ResolutionPlan。
- [ ] wheelhouse builder + hash/license/source verification + content-addressed cache。
- [ ] offline installer/verification 和 #71 profile adapter。
- [ ] failure matrix、rebuild/replay、cache/credential isolation tests。

## Required tests and boundary matrix

- empty/no deps、requirements/constraints/extras/markers、conflict、duplicate、editable/VCS/path/private、sdist、build backend、yanked/missing wheel。
- Python/platform mismatch、hash mismatch、index outage/redirect/TLS/timeout/429、cache poisoning、concurrent build、disk full。
- N0 捕获任何 DNS/socket 尝试；N1 只到 allowlisted proxy；Secret 扫描 manifest/log/cache。
- before/after Snapshot digest 一致；tampered wheel/reused other tenant cache 拒绝。
- 执行 `python -m unittest discover -s tests/dependencies -v`；网络/Docker matrix 显式 job。

## Dependencies / merge / rollback

Depends #58/#71/#73；Blocks #75/#77。新 resolver 默认 fail closed；不得回退为 Sandbox 公网安装。回滚保留不可变 Snapshot/wheelhouse，停止新解析。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:74 END -->

---

<!-- ISSUE_BODY:75 START -->
## Status / Size

`V4-I17` · Phase 3 · `status:blocked` · Size L · **唯一 MVP Mining 纵向切片**

## Problem and observable outcome

以 CWE-22 路径遍历完成 Hypothesis→Harness→Oracle→VEP 的真实执行闭环。只有稳定观察到越界文件访问/路径逃逸等安全影响才能达到高动态证据等级；静态猜测、超时和环境失败不得确认漏洞。

## Current code baseline

- `lima/python_dataflow.py`/`semantic_retrieval.py`: Source→Sink 与 containment invariant 事实来源，只读。
- `lima/harness.py`: 现有 ReviewHarness 不是 Mining harness，仅参考状态持久化。
- `lima/repository_scanner.py`: AEP 上游由 #68 提供。
- #71 Sandbox、#73 Tool Bundle、#74 Dependency Snapshot 是唯一执行基础设施。

## File ownership and collision boundary

- **Add**: `lima/mining/{planner,harness,oracle,executor,minimizer,vep}.py`、`lima/mining/cwe22.py`、`tests/mining/`、`evaluation_data/v4/cwe22/`。
- **Read-only**: audit/sandbox/tool_registry/dependencies；只调用公开 Port。
- **Must not modify**: Repair、其他 CWE、Supervisor policy、依赖 resolver、原 repository snapshot。

## Contract inputs, outputs, and invariants

- 输入只接受 sealed AEP/Hypothesis、ToolBundle、DependencySnapshot、RX- Sandbox policy；snapshot/digest/tenant 必须一致。
- Harness 定义入口、输入生成、setup、positive/negative control、观察点和 resource budget；禁止外网和真实系统路径。
- CWE-22 Oracle 使用 Sandbox 内 canary root/outside marker，观测 resolved path、open/access result 和 side effect；symlink/absolute/encoding 变体在 policy 内。
- Evidence D0–D4：D3/D4 必须有成功正向、negative control、重复性和可观察 impact；否则 `inconclusive|blocked|refuted(scope)`。
- VEP 包含位置/调用路径/触发条件/输入约束/PoC或Harness/实际输出/coverage/环境工具版本/安全不变量/机器 Oracle/重放命令。

## Implementation slices / PR plan

- [ ] CWE-22 fixture corpus、Oracle contract、safe canary filesystem。
- [ ] Hypothesis→Harness planner 和 bounded executor。
- [ ] positive/negative control、repeat/minimize/coverage 和状态机。
- [ ] VEP seal + clean-room replay；不启动 Repair 集成。

## Required tests and boundary matrix

- 真阳性/安全 containment/不可执行；`../`、absolute、mixed separators、URL/double encoding、Unicode、symlink、TOCTOU、nonexistent path、read-only/write sink。
- Harness syntax/setup/test failure、dependency missing、timeout/OOM/output flood/coverage unavailable 必须 blocked/inconclusive。
- negative control 也越界、Oracle marker 预先存在、环境污染、跨 run 残留必须拒绝确认。
- VEP tamper、snapshot/tool/dependency mismatch、重放不同结果 fail closed；支持样本 replay ≥90%，D3/D4 已知 false confirmation=0。
- 执行 `python -m unittest discover -s tests/mining -v`；RX- Docker replay 为显式 Linux job。

## Dependencies / merge / rollback

Depends #60/#61/#66/#71/#73/#74；Blocks #76/#79/#83。未达 replay/false-confirmation 门不启动 Repair 或新增 CWE。回滚停止新 Mining，已 seal VEP 保持可重放且不降级为静态 finding。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:75 END -->

---

<!-- ISSUE_BODY:76 START -->
## Status / Size

`V4-I18` · Phase 3/4 · `status:blocked` · Size L · **Repair candidate generation Owner**

## Problem and observable outcome

从 sealed VEP 在全新 disposable Repair workspace 生成默认 2、最多 3 个最小、可解释、彼此隔离的候选；不让单一 LLM Patch 成为事实，也不通过关闭功能/改依赖逃避 PoC。

## Current code baseline

- `lima/repair_workspace.py`: `RepairWorkspace.compose/read_text/write_text/dispose`、`repair_relevant_paths`。
- `lima/security_repair.py`: `PythonSecurityRepairEngine.repair` 和 CWE-22/78/89 deterministic planners。
- `lima/repair_preview.py`: 只读 preview 参考。
- `tests/test_repair_workspace.py`、`test_security_repair.py`: workspace/patch 边界基线。

## File ownership and collision boundary

- **Modify**: `lima/repair_workspace.py`、`lima/security_repair.py` 的兼容扩展；不得改变现有支持规则默认行为。
- **Add**: `lima/repair/{candidates,generator,patch_scope,manifest}.py`、`tests/repair/test_candidates.py`。
- **Read-only**: VEP/#74 snapshot/#71 RWX Port。
- **Must not modify**: `lima/verifier.py`、最终 Gates/RVR、GitHub 发布、原 snapshot/cache。

## Contract inputs, outputs, and invariants

- 输入仅 sealed VEP + exact repository/dependency/tool/policy digests；不得读取 Mining 可变 workspace/进程/未封存日志。
- 每候选拥有独立 fresh copy、candidate id、patch digest、changed files/lines、strategy/provenance、assumptions 和 generation cost。
- 默认 deterministic template + LLM diversity；LLM 输出先解析为 patch proposal，不能直接写原仓。
- scope allowlist 来自 VEP affected path/call path；禁止修改 tests 以隐藏失败、锁文件/依赖、权限、安全配置、Oracle/PoC，除非 VEP 明确批准且另有解释。
- 候选失败只淘汰自身；没有候选不等于漏洞不存在。

## Implementation slices / PR plan

- [ ] CandidateManifest、scope policy、fresh workspace factory 和 isolation tests。
- [ ] 将现有 PythonSecurityRepairEngine 包装为 deterministic candidate。
- [ ] bounded LLM proposal→parse→scope check，生成第二/第三策略。
- [ ] patch digest/explanation/cost seal；将 candidates 交 #77，不运行最终裁决。

## Required tests and boundary matrix

- 0/1/2/3 候选、重复候选去重、一个生成器失败、LLM malformed/oversize/timeout。
- 候选间不可见写入；原 snapshot/cache/GitHub 不变；workspace exception/cancel 后销毁。
- 拒绝改 requirements/lock/CI/tests/PoC/Oracle、删除功能、吞异常、扩大 root、硬编码攻击输入。
- CWE-22 safe/unsafe fixtures、multi-file patch、line ending/Unicode、symlink/path escape、patch apply conflict。
- 执行 `python -m unittest tests.repair.test_candidates tests.test_repair_workspace tests.test_security_repair -v`。

## Dependencies / merge / rollback

Depends #75，复用 #16；Blocks #77。#76 合并前锁定 repair_workspace/security_repair；#77 只能消费 CandidateManifest。feature flag 关闭时保留现有 preview，不发布任何“verified”状态。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:76 END -->

---

<!-- ISSUE_BODY:77 START -->
## Status / Size

`V4-I19` · Phase 3/4 · `status:blocked` · Size L · **Repair verification/adjudication Owner**

## Problem and observable outcome

在独立、干净的 Repair Sandbox 中以固定 Gate 顺序淘汰不可编译、仍可利用、引入回归或扩大风险的候选，只输出同时满足 Security Preservation 与 Functional Preservation 的 Verified Patch 和 RVR。

## Current code baseline

- `lima/verifier.py`: `RepairVerifier.verify_contents/verify_worktree/verify_archive/verify_differential`。
- `lima/security_repair.py`: candidate strategy 只读。
- `lima/service.py`: `create_fix` 当前 GitHub write flow 不在本 Issue 自动启用。
- `tests/test_security_repair.py`: 现有 oracle/archive/GitHub write gate 基线。

## File ownership and collision boundary

- **Modify**: `lima/verifier.py`，只扩展可组合 Gate adapter，保持 legacy API。
- **Add**: `lima/repair/{gates,verification,behavior_diff,rvr}.py`、`tests/repair/test_gates.py`。
- **Read-only**: #76 generator/candidates、#75 VEP、#71 Sandbox、#74 DependencySnapshot。
- **Must not modify**: candidate 生成策略、GitHub 自动发布、原 PoC/Oracle、依赖 resolver。

## Contract inputs, outputs, and invariants

- 输入：sealed VEP、CandidateManifest、same DependencySnapshot、fresh RWX run；任何 digest/tenant/snapshot mismatch 拒绝。
- Gate 固定：scope→patch apply→parse/compile→原项目测试→关键业务回归→原 PoC/Oracle→独立静态/差分扫描→行为差分→必要 re-fuzz。
- 每 Gate 状态 `PASS|FAIL|BLOCKED|TIMEOUT|ERROR|NOT_APPLICABLE(reason)`；mandatory 非 PASS 即候选淘汰，不能跳过后仍 verified。
- Security Oracle 必须证明原 impact 消失，而非只改变异常文本；Functional baseline 必须使用修复前已记录行为。
- RVR append-only，包含命令 argv、环境/工具/依赖 digest、日志摘要、退出码、coverage、diff、裁决 reason；不包含 Secret。

## Implementation slices / PR plan

- [ ] Gate protocol/result matrix、scope/compile/test adapters。
- [ ] PoC/Security Oracle、static/diff scan、behavior diff 和 optional re-fuzz。
- [ ] candidate adjudicator + RVR seal/replay。
- [ ] adversarial candidates 与 legacy `RepairVerifier` compatibility；不接 GitHub publish。

## Required tests and boundary matrix

- 合法修复、仍可利用、只拦原 PoC、禁用功能、吞异常、改 tests/依赖/Oracle、引入新 CWE、非确定性/flaky test。
- Gate timeout/OOM/tool missing/output malformed、NOT_APPLICABLE 误用、cancel、Sandbox crash 全部不 verified。
- 修复前 baseline 失败、测试为空、PoC 不稳定、behavior nondeterministic 必须 blocked 并解释。
- RVR tamper/重放、顺序、same snapshot/deps、候选隔离；Verified Patch Yield 基准 ≥50%，已知回归逃逸=0，关键 replay ≥90%。
- 执行 `python -m unittest tests.repair.test_gates tests.test_security_repair tests.test_production_features -v`。

## Dependencies / merge / rollback

Depends #66/#74/#76；Blocks #78/#79/#83。新 verified 状态默认 capability gate 关闭；回滚只停止新验证，不把既有 candidate 升级或删除 RVR。GitHub 发布需另一个显式授权 Issue。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:77 END -->

---

<!-- ISSUE_BODY:72 START -->
## Status / Size

`V4-I20` · Phase 4 · `status:blocked` · Size M

## Problem and observable outcome

建立 H1 PostgreSQL/Artifact 备份、恢复、引用一致性和灾难演练，实测 RPO/RTO；SQLite 明确只用于开发。非目标：自研数据库复制协议或为追指标隐藏恢复差距。

## Current code baseline

- `docker-compose.yml`: PostgreSQL volume、repository/artifact相关 volumes；必须基于 #71 合并版本。
- `lima/store.py`/`postgres_store.py`: 权威 task metadata；#66 增加 Artifact metadata。
- `tests/test_repository_storage_deployment.py`: volume/trust-domain 合同。

## File ownership and collision boundary

- **Add**: `docs/operations/backup-restore.md`、`deployment/backup/`、`scripts/backup_*`、`scripts/restore_*`、`tests/test_backup_restore_contract.py`。
- **Modify only after #71**: 根 Compose 的 backup sidecar/volume 最小接线；不得重写 Sandbox profiles。
- **Read-only**: 业务 schema/queue/Artifact algorithms。
- **Must not modify**: analyzer、试点标签、Redis 作为权威备份源。

## Contract inputs, outputs, and invariants

- 备份集绑定 PostgreSQL base backup/WAL（或托管等效）、Artifact blob/version、schema/config/tool manifest/key version 和统一 restore point id。
- Artifact metadata 与 blob 必须通过 digest/reference reconciliation；缺 blob/metadata、跨时间点引用不能宣布恢复成功。
- Secret 使用外部 secret backup policy，不写仓库/日志；备份加密、访问审计、保留和删除策略明确。
- restore 必须到隔离环境，验证后才能切换；禁止覆盖唯一生产副本。

## Implementation slices / PR plan

- [ ] 数据分类、备份矩阵、RPO/RTO、责任和 restore point manifest。
- [ ] PostgreSQL PITR/托管等效与 Artifact versioning/backup scripts。
- [ ] 隔离 restore + consistency checker + smoke replay。
- [ ] 故障演练 runbook、证据模板、季度 schedule；Compose 接线最后提交。

## Required tests and boundary matrix

- full+incremental/WAL、空库、大 Artifact、进行中 staging、删除/TTL、key rotation、schema 前后版本。
- corrupt/missing/truncated backup、wrong key、partial WAL、metadata/blob 时间错位、磁盘满/权限失败。
- 恢复后 task→Artifact→lineage 引用一致、sample AEP/VEP/RVR digest/replay；Redis 全丢仍可恢复权威事实。
- 实测 H1 RPO≤5min、RTO≤30min 或记录真实差距，不伪造；测试脚本不得碰生产路径。

## Dependencies / merge / rollback

Depends #66/#67；可与 #71/#74 叶模块并行，但 root Compose 修改在 #71 后。Blocks #78/#84。脚本先 dry-run；任何恢复切换必须人工授权，回滚为切回原隔离前副本。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:72 END -->

---

<!-- ISSUE_BODY:78 START -->
## Status / Size

`V4-I21` · Phase 4 · `status:blocked` · Size L

## Problem and observable outcome

建立 API/Queue/Worker/Artifact/DB 联合 micro、smoke、baseline、stress、spike、8–24h soak、fault 和 adversarial resource 门禁，量化容量拐点、背压与残留资源，而不是用压测脚本修改核心算法。

## Current code baseline

- `/health`、`/metrics`、`/v1/repository-scans`、`/v1/tasks/{id}`。
- `TaskQueue`、Artifact Store、Supervisor、Repair Gate 分别由 #67/#66/#71/#77 提供。
- `lima/metrics.py`/#59 SLO recorder 是唯一指标定义来源。

## File ownership and collision boundary

- **Add**: `benchmarks/v4/load/`、k6 scenarios、Worker load generator、fault fixtures、result schema/report。
- **Read-only**: production API/queue/worker/artifact/db algorithms。
- **Must not modify**: 核心业务以“通过压测”；发现瓶颈必须另开最小修复 Issue。

## Contract inputs, outputs, and invariants

- workload mix 固定 60% Audit、25% Mining、10% Repair、5% replay/ops；cold/warm cache 与 LLM/dependency normal/rate-limit/down 分层。
- RunSpec 绑定 commit/config/machine/dataset/workload/seed；RunResult 记录 throughput、p50/p95/p99、error/backpressure、queue depth、resource/cost、orphan/leak、一致性错误。
- generator 使用公开 synthetic fixture，不上传私有源码/Secret；结果不能把环境失败当业务失败。

## Implementation slices / PR plan

- [ ] micro/smoke/baseline workload + deterministic data generator。
- [ ] stress/spike/backpressure + 1×/5× capacity threshold。
- [ ] soak/leak/orphan detector + failure injection matrix。
- [ ] report comparator、CI smoke/manual heavy workflow 和 bottleneck issue template。

## Required tests and boundary matrix

- 0/1×/5×、burst、slow client、large response、duplicate request、cancel storm、mixed tenants。
- Worker/API/DB/Redis restart、network partition、Artifact latency/disk full、LLM 429/down、dependency cache miss。
- 断言 Control Plane 可响应、背压不崩溃、重复投递无双权威结果、无持续 Sandbox/lease/blob orphan。
- 1× error<1%；5× 显式背压；8–24h 无增长性泄漏；每个拐点可用同 RunSpec 重放。

## Dependencies / merge / rollback

Depends #59/#68/#67/#71/#77；Blocks #79/#84。普通 CI 只 smoke，heavy workflow 显式手动且有成本上限；删除 benchmark 不影响生产，但结果 Artifact 必须保留用于决策审计。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:78 END -->

---

<!-- ISSUE_BODY:79 START -->
## Status / Size

`V4-I22` · Phase 4 · `status:blocked` · Size L · **MVP release gate**

## Problem and observable outcome

在 5–10 个 repository-disjoint 真实 Python 仓库上证明 LIMA 实际减少专家时间、保持高风险召回，并通过性能/恢复/证据/修复门；输出 GO、CONDITIONAL GO 或 NO-GO 和停止投资项。

## Current code baseline

- #57 BaselineRunSpec/Result、现有 `RealWorldSecurityEvaluator` 与 frozen dataset integrity。
- #62 CWE-798 降噪、#68 Fast Audit、#70 UI、#75 VEP、#77 RVR、#72/#78 运维证据。
- `lima/experiments.py`: run/cancel/resume/budget/dataset drift 语义参考。

## File ownership and collision boundary

- **Add**: `evaluation_data/v4/pilot_manifest.json`、`benchmarks/v4/pilot/`、脱敏结果与 `docs/v4-mvp-go-no-go.md`。
- **Read-only**: analyzers、labels、holdout fingerprint、生产算法、历史结果。
- **Must not modify**: 为通过门槛临时调规则/Prompt、重标 holdout、逐条人工删除告警。

## Contract inputs, outputs, and invariants

- Pilot manifest 固定 repository/commit、license/consent、language/framework/size/CWE coverage、dataset role 和 reviewer protocol；仓库间 disjoint。
- 双盲/一致复核记录 expert minutes、Review Queue reduction、高风险 recall proxy、VEP replay、Verified Patch Yield、latency/cost/recovery、失败分类。
- 公开报告只含脱敏摘要和 immutable digests；私有试点必须 tenant 隔离且不得进入公共 Case Library。
- 决策规则预注册，缺失/失败指标不能按 0 或通过处理。

## Implementation slices / PR plan

- [ ] 预注册样本选择、人工协议、指标/阈值和停止条件。
- [ ] 自动 run/replay/计时/失败分类与结果 seal。
- [ ] 至少两名 reviewer 的分歧处理和人工时间统计。
- [ ] 生成决策报告、逐门证据链接和 Gated Issues 解锁/关闭建议。

## Required tests and boundary matrix

- duplicate/同 fork/相同代码仓库、moving ref、license/consent 缺失、dataset role 冲突、analyzer drift 拒绝。
- reviewer 中断/分歧/漏计时、部分仓库失败、LLM/网络成本缺失、VEP/RVR 不可重放必须显式降级。
- 至少 3 个仓库减少专家时间；Review Queue 下降≥60%；高风险召回不低于 #57；性能/恢复/证据门全部通过。
- 不允许完成闭环仍需专家逐条筛全部原始告警；执行 pilot integrity unit tests + 显式真实仓库 workflow。

## Dependencies / merge / rollback

Depends #57/#62/#68/#70/#75/#77/#72/#78。输出控制 #80–#84 是否解锁。报告不可覆写；修订产生新 version，NO-GO 不自动删除平台能力但冻结扩展投资。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:79 END -->

---

<!-- ISSUE_BODY:80 START -->
## Status / Size

`V4-I23` · Post-MVP · `status:gated` · Size L

## Start gate

不得实现，直到 #79 给出 GO/CONDITIONAL GO，且 #65 Candidate provenance/撤销、#66 Artifact ACL/retention 已通过。启动前必须在本 Issue 记录目标查询、数据分类、租户可见性和非目标；否则保持 gated。

## Problem and observable outcome

把经过审核的正例、负例、inconclusive 和工具失败 Case 建成结构化/全文可检索库，帮助规划与评测；历史 Case 只能提供相似性和策略建议，不能提升当前证据等级。

## Current code baseline

- `lima/knowledge/candidates.py`（#65）和 Artifact Registry（#66）是唯一权威输入。
- `lima/memory.py`/`semantic_retrieval.py` 只作为 tenant isolation/检索排序参考，不直接迁移未审核记忆。
- `store.py/postgres_store.py` 的全文索引接入必须使用 #66 migration registry。

## File ownership and collision boundary

- **Add**: `lima/knowledge/{library,index,search,quality}.py`、`tests/knowledge/test_library.py`。
- **Modify after gate**: 通过 migration registry 增加 PostgreSQL full-text metadata；API 接线单独 PR，避免与其他 service/api 改动并行。
- **Must not modify**: Evidence Fusion/Level、当前 task verdict、向量/RAG（属于 #81）、跨租户默认策略。

## Contract inputs, outputs, and invariants

- 仅 `PROMOTED` 且未 revoke Candidate 可入库；Case version immutable，包含 provenance/quality/scope/language/CWE/fingerprint/tenant visibility。
- Search 输入 query + tenant/language/CWE/scope/top-k；输出 CaseRef、match features、quality、negative/conflict signals，不返回未授权原文。
- positive 与 negative 同权参与排序解释；revocation 在新查询立即生效，历史 run 通过 digest 重放。
- 搜索结果不能修改 Hypothesis confidence/Evidence Level；Planner 必须标注 `historical_hint`。

## Implementation slices / PR plan

- [ ] gate ADR、Case promotion/revocation/library Port。
- [ ] structured filter + PostgreSQL FTS/in-memory test adapter。
- [ ] ranking/explanation/quality/negative evidence 与 API read model。
- [ ] benchmark、ACL/leak、rollback 和 operator tools。

## Required tests and boundary matrix

- promote/reject/revoke/version、duplicate/conflict、missing provenance、quality threshold、future schema。
- tenant/language/CWE/scope filter 组合、0/top-k/oversize query、Unicode、same fingerprint different tenant。
- revoked/negative 不被遗漏；结果顺序稳定；p95≤150ms 的基准注明数据规模。
- 泄漏测试覆盖 title/snippet/log/cache；检索不改变当前 adjudication。

## Dependencies / merge / rollback

Depends #65/#66/#79。功能以 capability gate 默认 off；回滚停止查询并保留 immutable Case，索引可重建，不删除权威 Artifact。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:80 END -->

---

<!-- ISSUE_BODY:83 START -->
## Status / Size

`V4-I24` · Post-MVP · `status:gated` · Size L

## Start gate

只有 #79 GO/CONDITIONAL GO、#75 CWE-22 VEP replay/false-confirmation 门和 #77 Verified Patch Yield 门全部通过，才可启动。每个新 CWE 必须另建子 Issue；本 Issue 作为跟踪器，不允许一个 PR 同时实现多个 CWE。

## Problem and observable outcome

按独立纵切扩展 CWE-78、CWE-89 和授权绕过等 Python 场景；每个 CWE 都有自己的 Source/Sink、触发模型、Harness、Oracle、VEP、Repair strategy 和回归门，不能复用不适用 Oracle。

## Current code baseline

- `lima/security_repair.py`: 已有 CWE-78/89 deterministic repair 只能作为候选策略参考，不证明动态影响。
- `lima/python_dataflow.py`、`semantic_retrieval.py`: 现有 Source/Sink/Invariant。
- `lima/mining/cwe22.py`（#75）与 Repair Gates（#77）提供插件 Port。

## File ownership and collision boundary

- **Add per child**: `lima/mining/cwe_<id>.py`、专用 Harness/Oracle、`evaluation_data/v4/cwe_<id>/`、独立 tests。
- **Modify after #76/#77**: 通过公开 plugin registry 增加 repair/gate adapter；不得交叉改 CWE-22 逻辑。
- **Must not modify**: 通用 Evidence Level、Oracle 基类语义、别的 CWE fixture/threshold。

## Contract inputs, outputs, and invariants

- 子 Issue 必须冻结 threat model、source/sink、impact oracle、negative controls、unsupported cases、tool/dependency needs 和安全 sandbox policy。
- CWE-78 观察进程 argv/side effect，不能仅匹配 shell 字符；CWE-89 观察 SQL 结构变化/绑定，不能连接真实生产 DB；授权绕过需要确定身份/资源/策略状态机。
- 新 CWE 的 Evidence/Gate threshold 单独评测，不能用总体平均掩盖 false confirmation。

## Implementation slices / PR plan

- [ ] 先开一个 CWE 子 Issue + ADR + fixture/oracle review。
- [ ] Mining plugin + VEP replay；门未过即停止。
- [ ] Repair strategies + RVR gates；门未过不发布。
- [ ] 再决定下一个 CWE，禁止并行扩张导致共享文件冲突。

## Required tests and boundary matrix

- 每 CWE：真阳性、安全近邻、不可执行、环境失败、Oracle 自身假阳性、最小化/replay、修复过拟合。
- CWE-78 覆盖 argv/shell/dynamic executable/platform；CWE-89 覆盖参数值/动态结构/driver paramstyle/transaction；授权覆盖 deny/allow/tenant/resource ownership。
- 每个 CWE 单独达到 replay、known false confirmation=0 和 yield 门；跨 CWE fixture 不误触发。

## Dependencies / merge / rollback

Depends #75/#77/#79/#80。每个 child plugin 可独立 feature flag/revoke；回滚单一 CWE 不影响已验证 CWE-22 或其他插件。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:83 END -->

---

<!-- ISSUE_BODY:84 START -->
## Status / Size

`V4-I25` · Post-MVP · `status:gated` · Size XL / **必须先拆子 Issues**

## Start gate

只有 #78 证明目标 SLO 在单节点不能达到、#72 恢复/一致性通过、#79 批准 Beta 运维成本，才能启动。启动后先提交 ADR；未选定队列方案前不得改 `task_queue.py`、Compose 或部署配置。

## Problem and observable outcome

针对已量化瓶颈评估并实施 Beta HA、多实例 Worker 和可选 Redis/消息队列；保持 Lease/Attempt/幂等与 Artifact 不可变契约。Redis 不得成为未经设计的唯一事实库。

## Current code baseline

- `lima/task_queue.py`/#67 WorkAttempt lease/fencing。
- #66 Artifact metadata、#72 backup/restore、#71 Supervisor/root Compose。
- 当前 `docker-compose.yml` 已含 Redis，但只代表现有 queue/cache 基础，不证明 HA。

## File ownership and collision boundary

- **ADR only first**: 比较 PostgreSQL queue、Redis Streams、专用 broker、托管方案及“不做 HA”。
- Go 后拆至少：queue adapter、scheduler/API HA、worker distribution、deployment/observability、failover drill 五个子 Issues，各自文件锁。
- `task_queue.py` 由 queue child 独占；根 Compose/Kubernetes 由 deployment child 独占；store schema 通过 migration registry。
- **Must not modify**: Audit/Mining/Repair 算法、Artifact immutability、fencing/idempotency 语义。

## Contract inputs, outputs, and invariants

- 权威 task/attempt/artifact 状态必须有明确 store；Redis 若可丢，重建路径必须演练；若作为 queue，delivery/fencing/retention/backup 责任写入 ADR。
- 网络分区、重复/乱序、leader change、rolling upgrade 下最多一个 authoritative result，且 cost 不重复。
- API 99.9% 等目标必须基于定义窗口/依赖范围；不能以忽略失败请求达标。

## Implementation slices / PR plan

- [ ] ADR + benchmark/cost/failure model，作二次 Go/No-Go。
- [ ] 按选型创建互斥文件 Owner 的子 Issues，不在本跟踪 Issue 直接提交实现。
- [ ] shadow/dual-run、failover、rolling upgrade、backup/restore。
- [ ] capacity/availability 对照和运维 Runbook。

## Required tests and boundary matrix

- node/API/worker/broker/DB failure、network partition、clock skew、duplicate/reordered、consumer lag、retention、rolling upgrade/version skew。
- Redis flush/restart/partial loss 不丢权威事实；stale worker fencing；Artifact commit 一致。
- 与 H1 基线比较吞吐、可用性、RPO/RTO、成本/复杂度；收益不达预注册阈值则 NO-GO。

## Dependencies / merge / rollback

Depends #72/#78/#79 及 #67。每个子能力可独立回滚；切换 queue/store 前必须 drain/dual-read 验证，禁止强制 reset 或丢弃运行中 attempt。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:84 END -->

---

<!-- ISSUE_BODY:81 START -->
## Status / Size

`V4-I26` · Post-MVP · `status:gated` · Size M · **实验，不进入生产关键路径**

## Start gate

#80 的结构化/全文检索已上线并形成 baseline，且 #79 允许继续知识库投资。实验前冻结 repository-disjoint query set、泄漏测试、指标和停止条件。

## Problem and observable outcome

比较 PostgreSQL FTS、pgvector 与 hybrid RAG 对 Tool/Harness/Case Top-K 和专家调查时间的增益；没有显著收益或出现 false transfer/泄漏时关闭实验。

## Current code baseline

- #80 `CaseSearch` 是 baseline 和唯一生产接口。
- `lima/semantic_retrieval.py` 的 bounded evidence packet 作为上下文预算参考。
- `lima/real_world_evaluation.py` 的 repository-disjoint/fingerprint 规则作为实验完整性参考。

## File ownership and collision boundary

- **Add**: `benchmarks/v4/rag/`、`lima/knowledge/vector_experiment.py`、`tests/knowledge/test_rag_experiment.py`。
- **Optional isolated migration**: 独立 pgvector 实验表/索引，不改 #80 权威 Case 数据。
- **Must not modify**: production `CaseSearch` 默认路径、Evidence Level、current verdict、公共 Case ACL。

## Contract inputs, outputs, and invariants

- RunSpec 固定 embedding model/digest、index config、query set、top-k、tenant policy、seed、baseline。
- 结果记录 recall@k/MRR、调查时间、latency/cost、false transfer、跨 tenant/repository leakage。
- 检索上下文只返回授权摘要/Artifact ref；embedding/input 不发送私有内容到未批准 provider。
- 指标门：Top-K ≥10% 或调查时间下降≥15%，且 false transfer/leak 不增加；否则 NO-GO。

## Implementation slices / PR plan

- [ ] 预注册 query/candidate split 和 FTS baseline。
- [ ] 离线 vector index + exact model provenance。
- [ ] hybrid ranking/ablation/leak tests。
- [ ] 报告与二次 Go/No-Go；未通过不接生产 API。

## Required tests and boundary matrix

- empty/duplicate/negative/revoked Case、embedding failure/drift、index stale/corrupt、top-k 边界、Unicode/long query。
- tenant/repository disjoint、相似但不适用 CWE/framework、poisoned Case、provider failure/timeout/cost cap。
- baseline 与实验使用相同 query set；禁止调 query/label 追指标；结果可重放。

## Dependencies / merge / rollback

Depends #80/#79。实验 feature flag 默认 off；删除 vector index 可完全回到 FTS，权威 Case/Artifact 不受影响。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:81 END -->

---

<!-- ISSUE_BODY:82 START -->
## Status / Size

`V4-I27` · Post-MVP · `status:gated` · Size XL / **方向选择跟踪器，不直接实现**

## Start gate

#79 GO/CONDITIONAL GO 后，必须基于真实失败分类只选择一个方向：新语言、强隔离后端、Tool Evolution 或 N3 网络。每个方向另建 ADR + 子 Epic/Issues；本 Issue 不接受混合实现 PR。

## Problem and observable outcome

在不降低三阶段信任边界的前提下扩展平台能力。投入必须由试点缺口和收益证明，而不是“可能有用”。

## Current code baseline

- #73 Tool Registry approval/revocation、#71 Sandbox profiles、#74 N0/N1、#75/#77 Python vertical slice。
- `lima/skill_evolution.py` 是 declarative skill 经验参考，不能直接等同 Tool Evolution。
- 当前 Python analyzer/dataflow/repair 是语言专属，不允许伪装通用。

## File ownership and collision boundary

- **新语言**: 新 `lima/languages/<lang>/` + 独立 fixtures/Oracle/benchmark；不得在 Python 模块堆条件分支。
- **强隔离**: 新 `lima/sandbox/backends/<backend>.py`；保持 #71 Profile Port，不改领域算法。
- **Tool Evolution**: 新 quarantine/benchmark/approval pipeline；不得自动批准或直接执行生成工具。
- **N3 网络**: 新 broker/grant/audit 模块；Sandbox 不持长期凭据，短时限域授权。
- 根 Compose、公共 contracts、Evidence Level 的修改必须各自单独 Issue 和 Owner。

## Contract inputs, outputs, and invariants

- 所有方向必须维持 Artifact-only stage communication、immutable provenance、tenant isolation、typed failure 和 fail-closed verdict。
- 新工具先 QUARANTINED→offline benchmark→human/政策 APPROVED；来源/version/digest/license/SBOM 可追溯。
- N3 grant 绑定 task/tool/domain/method/bytes/TTL/attempt，默认拒绝，响应封存摘要并脱敏。
- 新语言必须有独立 Source/Sink/Harness/Oracle/Repair/Gate，不能复用 Python 指标宣称支持。

## Implementation slices / PR plan

- [ ] 从 #79 failure taxonomy 选择唯一方向并写 ADR/收益门。
- [ ] 建子 Epic，拆 contract/backend/integration/benchmark/operations，设置互斥文件 Owner。
- [ ] 先 shadow/quarantine，安全与收益门通过后再 production capability gate。
- [ ] 未达门槛关闭该方向，不影响 MVP。

## Required tests and boundary matrix

- 每方向必须有 positive/negative/failure/abuse/replay/rollback；不能只测 happy path。
- Tool provenance poisoning、Sandbox escape、network exfiltration、cross-tenant、version drift、revoke、budget exhaustion。
- 新语言单独 precision/replay/yield；新 backend 与 #71 conformance suite；N3 默认无网和 grant expiry。

## Dependencies / merge / rollback

Depends #73/#79，具体方向另有前置。每个 capability 独立 flag/revoke；失败回滚不得改变既有 Python/N0/N1/MVP 契约。

Source of truth: `docs/LIMA_V4_Issue代码级实施约束与测试矩阵.md`。
<!-- ISSUE_BODY:82 END -->

## 1. Issue Definition of Ready / Done

### Ready

- 前置 contract 已合并，正文中的路径和符号已在最新 `main` 复核。
- Labels 中只能有一个状态；`ready` 表示依赖、fixture、文件锁和 reviewer 都已就绪。
- 每条验收标准已映射到测试文件/命令，且不存在“实现后再决定 Oracle”的表述。
- 高冲突文件已由唯一 Owner 认领；并行 PR 只修改新增叶模块。

### Done

- 所有 mandatory/negative/failure/security/concurrency 测试通过；未知或不可执行情况保持 gap/blocked。
- PR 只触碰 allowlist；任何例外在 Epic #85 留有协调记录。
- Artifact/Schema/API/DB 变更含 version、migration、backward compatibility 和 rollback evidence。
- 指标/日志/fixture 无 Secret、host path、私有源码或跨 tenant 数据。
- 文档、fixture、运行命令和输出 digest 可由另一名贡献者重放。
