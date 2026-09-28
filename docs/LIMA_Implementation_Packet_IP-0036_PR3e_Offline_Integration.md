# LIMA Implementation Packet — IP-0036 PR3-e Offline Integration（#237 / #57 PR3-e 离线集成，零真实调用）

- Packet ID：IP-0036；版本 v1.0（2026-09-28）。
- Coordinator Assignment：CA-IP-0036-v1.0（2026-09-28；Intent Record `.pv_tmp/INTENT_RECORD_IP-0036_2026-09-28.md` 的 M1-M9/F1-F14/N1-N7/S1-S5/I-1..8 与主会话裁定点 A-I 由其 R1-R12 裁定；R1-R12 转录见 §15）。
- Source Issue：#237（open；parent #57 保持 open，PR3 不勾选；正文 Scope 1-8 / Non-goals / AC-1..5 由 Coordinator 经 GitHub API 亲取，范围以 CA-IP-0036-v1.0 §Authoritative Inputs #2 为权威转录——本 P&V 会话零网络，未直取远程正文，远程再核验归主会话派发前完成）。
- Operating Mode：SHADOW；Execution Authorization：MAINTAINER_AUTHORIZED（2026-09-28 第三轮；**本任务模型 API 调用预算=0；本 IP 离线交付全程零真实调用/零网络下载/零付费/零远端写**；GitHub/官方文档只读核验与本地离线测试可继续；旧批额度不复用）。
- Base SHA（完整 40 位）：`10465010de05a759c339a491531707ff6e6619dc`（= origin/main = 本地 main；PR #236 merge ∈ HEAD；tracked 面干净，本 P&V 会话亲验）。
- 基线产物指纹（`git ls-tree 1046501d...` 本 P&V 会话亲验，与 CA §Exact Baseline 逐字一致）：report.py blob `3615a75d77849a26072e6517345fe15437072cf2`；fixtures.py blob `0e4fb11fb07a7cf76658df674cd4e685c60ce4e0`；real_run.py blob `0d6db453c3c16adb834c2a67a8641e15f1fed5b8`；fixture_registry.json blob `493f3da55722a2a1e97200b4a1bc05f256952722`；Dockerfile blob `fcade9c95dcfe4504d4ba1247c3c46edd51f0344`；test_report blob `b53176f5af0acf9322bfbaefd002612605fda4df`；test_fixtures blob `34b397b700daabe58317180fd15f4c72658fdb66`；test_real_run blob `d982bdd888875c73608b6019e2f29dabf5e1be77`；守护 blob——budget `6c783848`、orchestrate `8655067e`、collect `063ecb41`、run `d29928e5`、expert_timing `dd7aa365`、offline_flow `0f2916c8`、`__init__` `1c478346`、七禁区测试文件 `4cde7bdf`/`edd4c62b`/`edb2391b`/`35e6ec6a`/`8e8ab0dc`/`539d2fb3`/`0a44cf7d`、baseline_manifest.json `7ecb39f8`、python_mvp_support_matrix.json `3ea94fcf`。
- 本 Packet 的角色：Implementation（阶段 C3/C4/C5）的唯一实现依据；冻结验收测试四文件面（§9/§10）的唯一语义来源；ER 复核与 P&V 独立验证的基准。

## 0. 交付物角色声明（强制，先于一切）

1. 本 Packet（本文件）、矩阵 v2（`docs/LIMA_PR3e_Requirement_Matrix_v2.md`）、专家复核包（`docs/LIMA_PR3e_Expert_Review_Package.md`）与 Dockerfile 恰 3 行 COPY 是 P&V 的 C1 交付物；四个冻结测试文件面（test_report v1→v2 演进、test_fixtures 演进、test_real_run v5→v6 演进、新文件 test_v4_baseline_v5_negatives）是 P&V 的 C2 交付物；`benchmarks/v4/baseline/fixtures.py`+`evaluation_data/v4/fixture_registry.json`（C3）、`benchmarks/v4/baseline/report.py`（C4）、`benchmarks/v4/baseline/real_run.py`（C5）的实现是 **Implementation 的交付物**。边界不得互换：Implementation 不得修改本 Packet/矩阵/专家包/测试；P&V 不实现产品功能。
2. **零真实调用绝对禁令（本 Assignment 范围内）**：本 IP 离线交付全程（含分支上、CI 内、pre-merge"顺手验证"）禁止任何真实模型调用、网络下载、付费动作、任何新付费效力批准工件。全部验收以离线注入（fake transport / fake opener / 注入 clock / 预置缓存）证明；CI 永远零付费模型请求（NFR-02 延续）。
3. 冻结面零回退：IP-0024..0035 一切冻结面零回退（§7 各"不变面"节）；`budget.py`/`orchestrate.py`/`run.py`/`collect.py`/`expert_timing.py`/`offline_flow.py`/各级 `__init__.py` **零字节**；canary 清单五项键名/判定式/latch 触发零改动；预算语义只紧不松；`REAL_RUN_GATE_UNLOCKED=False`/`require_real_run_unlock` 锁面不触碰。
4. 诚实纪律（#237 Scope 2/6 明文）：不写常数、不以 synthetic 冒充真实扫描；无来源→null+`unavailable`；无真人专家事件→专家分钟缺席（sessions=0/active_time_ms_total=None），不得以模型调用或合成事件填充；mode 序号 0-4 不得宣称为 5 次真实 cold（DR-IP-0035-01 硬条件）。

## 1. 需求映射（Packet 头）

```text
Source Issue：#237（open；Scope 1-8 / Non-goals / AC-1..5，经 CA-IP-0036-v1.0 转录）
Issue specification revision：2026-09-28 创建版正文（Scope 1-8 / AC-1..5；Packet ID 占用检查已由 Coordinator 完成）
Covered requirements：FR-01、FR-02、FR-03、FR-04、FR-05、FR-06、FR-07、FR-08、AC-1、AC-2、AC-3、AC-4、AC-5
Not covered requirements：任何真实模型调用/网络下载/付费动作；新付费效力批准工件；#57 关闭或 PR3 勾选；#237 关闭（叶合并≠Issue 完成）；#223/#234 重开；九类真实扫描/真实批次；thinking/请求形状/身份三形态/SF-01/十码/11 检查点语义变更；mode 标签语义变更；CANDIDATE_FILE_CAP 数值变更；真实专家事件；决策包 v4 编制（主会话）
Delivery role：integration（PR3-e 离线集成切片：schema v2/负例双探针/signal-storm/专家包/cold 重置/入口泛化，全部离线）
Issue closure impact：PARTIAL（IP-0036 完成 ≠ #237/#57 完成 ≠ 真实批次完成；矩阵 v2 中依赖真实运行/人工专家的行保持部分/未证实——K6）
Upstream IP/PR/merge commits：IP-0035（PR #236 merge 1046501d = 基线）；DR-IP-0035-01 修订裁定（`.pv_tmp/DR-IP-0035-01_RULING_2026-09-28.md`：cold=可验证本地状态重置；IP-0036 义务=cold 重置程序+探针）；CONSUMES IP-0027（expert_timing/collect 面）、IP-0029（report 面）、IP-0030（fixtures/注册表面）、IP-0031/0032/0033/0034/0035（real_run 面）
```

FR-01..FR-08 为 #237 "Scope (this slice)" 1-8 的规范化编号（语义不变，CA §Goal and Scope）。

| 需求 | 内容（规范化语义） | 本 Packet 承载 | 验收面 |
| --- | --- | --- | --- |
| FR-01 | 逐行矩阵 v2：六列含完成门禁，行=#57 原生 FR/NFR/AC + V5-FR-01..05 + V5-AC/T-01..03，锚行含空仓/最小仓/LlamaFactory 固定 SHA/repository-disjoint 标注样本/九类 archetype；与实现一致（无未验证宣称） | §4/矩阵 v2 文档 | AC-5；A4 纪律探针（docs 在库+3 COPY 行）+ PR Done Commands |
| FR-02 | V5 报告 schema：vep/rvr/stage_outcome 三 additive 顶层字段+schema_version 1→2；Signal/Issue/Hypothesis/原始候选/压缩队列/资源指标真实来源规则接线（payload v2 可选 domain 子块；null=unavailable 纪律；不写常数不以 synthetic 冒充）；coverage_gap_reasons 语义保持文件级 skip 专用 | §7.1 | M2 演进+新增（AC-1） |
| FR-03 | 隐藏上限负例（双面）：审查/扫描面 N>6 且 >12 全保留无"固定 6 条"式截断；runner 面 CANDIDATE_FILE_CAP=12 如实披露为请求构造参数非复核上限；固定上限普查表如实登记 | §7.6/§8.1 | A4 探针一（AC-2） |
| FR-04 | holdout 身份无关性负例：改名/换路径/非语义元数据三形态不进入产品判断条件（判定与聚合恒等、身份面如实不同；identity 消费点限于校验/去重/获取键/呈报） | §8.2 | A4 探针二（AC-2） |
| FR-05 | signal-storm fixture：第 12 合成 archetype（确定性生成器/注册表第 13 条目/digest/幂等/边界/inert 头/关系注记 additive） | §7.2 | M3 演进+新增（AC-3） |
| FR-06 | 专家复核包：真人流程（开始/暂停/恢复/结束→ExpertTimingSession→.expert-timing.json sidecar）+逐字段表+示例 sidecar 字面通过现行冻结校验器+缺席纪律声明；无 api_key/付费通道 | 专家包文档+§7.3 | M2 新增（示例 sidecar 经冻结校验器）+ A4 纪律探针（AC-3） |
| FR-07 | cold 重置/warm 复用程序：可执行本地状态重置（从已缓存 tarball 重新解包+重建请求体；零传输 GET；state_reuse=(T,F,T)；download_ms=None 纪律）；可独立调用入口；真实 cold 计数=物化重置次数；产品默认批次行为不变 | §7.5 | M4 新增（AC-4） |
| FR-08 | 真实入口泛化：冻结工件族目录（10 键）+入口恰一个 kw-only 参数（默认路径逐字节保持）+逐工件钉扎校验+未知键 fail-closed+零预算工件离线证明（拒付面+离线全链面）+门禁零放松+零预算工件命名纪律 | §7.4/§7.5.x | M4 新增（AC-4） |
| AC-1 | vep/rvr/stage_outcome 在场且 null 纪律正确；全部指标位可追溯（measured 有 domain 依据/否则 unavailable）；test_report 演进零弱化 | §7.1/§10 | M2 全文件 |
| AC-2 | 固定上限不存在可证（扫描面 N 全保留+runner 面 12=请求构造参数+普查表零隐藏上限）；holdout 三形态身份无关可证 | §7.6/§8 | A4 探针一/二 |
| AC-3 | signal-storm 确定性+digest 登记（13 条目字节一致）；专家复核包示例 sidecar 通过冻结校验器；缺席纪律保持 | §7.2/§7.3 | M3 新增+M2 新增 |
| AC-4 | 入口泛化（默认路径逐字节不变+九合成键逐工件钉扎+未知键 fail-closed）；零预算拒付面+离线全链面；门禁零放松逐项断言；cold 重置程序+每 attempt 状态探针；CI 离线绿 | §7.4/§7.5 | M4 新增+Done Commands |
| AC-5 | 矩阵 v2 入库（六列/五类/锚行/完成门禁）且与实现一致（无未验证宣称） | §4 | 矩阵 v2 文档+A4 纪律探针 |

**Not-covered（全团队不得扩张；= CA §Not covered 1-7 全文）**：任何真实模型调用、网络下载、付费动作（含分支上/CI 内/pre-merge"顺手验证"）；任何新付费效力批准工件；批 A/B/85 次调用（决策包 v3 不获批准部分维持不批准）。#57 关闭或 PR3 勾选；#237 关闭（叶合并≠Issue 完成）；#223/#234 重开（除非新事实推翻——按 #237 §Non-goals）；九类真实扫描/真实批次（另行授权与工件）。thinking/请求形状（含 `{"thinking":{"type":"disabled"}}`、response_format、max_tokens=8000、请求体 ≤100000 UTF-8 字节）/身份三形态/SF-01 谓词与 token 语法/`RealRunErrorCode` 十成员/11 检查点与 field_path 映射语义变更；mode 标签语义（0-4 cold/5-9 warm）变更；`CANDIDATE_FILE_CAP=12` 数值变更（它是已披露请求构造参数，R6 只证语义不改值）。budget.py/orchestrate.py/run.py/collect.py/expert_timing.py/offline_flow.py/各级 `__init__.py` 任何字节；其余七个 v4 冻结测试文件（298 方法）；`evaluation_data/v4/baseline_manifest.json` 与 `python_mvp_support_matrix.json`（IP-0026 冻结工件）零字节；历史 Packet/两份批准工件/决策包文本修改；2026-09-27/28 两批运行数据（只读）。canary 清单五项键名/判定式/latch 触发；预算语义放松（只紧不松）；`REAL_RUN_GATE_UNLOCKED`/`require_real_run_unlock` 锁面触碰；通配仓库或默认联网。`lima/**` 任何字节（负例探针是测试侧只读消费 lima 机制，不是修改 lima）；`scripts/**`、前端、`pyproject.toml`/`requirements.txt`/`.github/**`/`.gitignore`/`.gitattributes`；不提交任何输出目录/密钥/run 产物。决策包 v4 编制（主会话）；真实专家事件。

## 2. Design Input Manifest

| # | 输入 | 版本/位置 | 消费方式 |
| --- | --- | --- | --- |
| 1 | CA-IP-0036-v1.0 | `.pv_tmp/COORDINATOR_ASSIGNMENT_IP-0036_2026-09-28.md` | 范围权威；R1-R12 全文转录见 §15；本 Packet 逐条承载 |
| 2 | Intent Record INTENT-IP-0036-20260928-v1 | `.pv_tmp/INTENT_RECORD_IP-0036_2026-09-28.md` | M1-M9 授权语义；F1-F14 决定性事实（F3 report 零三面/F5 fixtures signal-storm 零命中/F6 入口钉扎/F9 冻结测试面 66+298）；N1-N7 推断（N5 完成门禁=可机械检查判据）；S1-S5 建议（全部采纳：S1 参数化工件描述+逐工件钉扎/S2 零预算工件区隔命名+机械判据/S3 负例新文件/S4 signal-storm 第 12 archetype/S5 cold 重置独立入口） |
| 3 | Maintainer 第三轮授权 | Intent Record 头部（预算=0/批 A/B/85 不批准/载体与合并门禁/#57 不关） | §0/§12/§14 的授权依据 |
| 4 | Source Issue #237 正文 | CA §Authoritative Inputs #2（Coordinator GitHub API 亲取，`.pv_tmp/issue237_api.json`；本 P&V 零网络） | Scope 1-8/Non-goals/AC-1..5（经 CA 规范化为 FR-01..08） |
| 5 | #57 矩阵评论 issuecomment-5867392527 | `.pv_tmp/issue57_matrix_comment.json`（Coordinator API 亲取；本 P&V 零网络） | 矩阵 v2 行集基线（两表逐行移植+IP-0036 更新）；V5-FR-03/04、V5-AC/T-01..03 缺口实锤与移交 5 项↔#237 Scope 2-6 对应 |
| 6 | DR-IP-0035-01 修订裁定 | `.pv_tmp/DR-IP-0035-01_RULING_2026-09-28.md` | §7.5 cold 语义的硬条件来源（cold=可验证本地重置/warm=记录复用/0-4 序号禁称 5 真实 cold/缓存观测+结论限制/禁改 prompt） |
| 7 | IP-0035 Packet | `docs/LIMA_Implementation_Packet_IP-0035_Time_Governance.md` @1046501d | 结构先例与现行冻结契约：§7.1 不变面、§7.5 state_reuse 四键、§7.6 timings、§10 六条件演进程序、§17 G5 预登记（"后续叶改变重置/复用策略时观测面如实变化、键集语义不变"——本叶 §7.5 兑现该路径） |
| 8 | report.py @1046501d | blob `3615a75d`（1426 行全文本 P&V 亲读） | §7.1 演进对象：`_REPORT_FIELDS` 16 键、counts 7 键、`_PROJECTIONS` 三值、`_SIDECAR_FIELDS` 5 键、`_recognize_evaluator_payload`、`build_baseline_report` 投影、`_gate_sidecar`/`_validate_sidecar_artifact`、resources 面 null-only 现状 |
| 9 | fixtures.py @1046501d | blob `0e4fb11f`（930 行全文亲读） | §7.2 演进对象：11 合成 key+1 external、`_SYNTHETIC_NOTES`、`write_registry`/`load_registry` 闭集校验、`_shape_fingerprint`、`_RELATIONSHIP_TO_SUPPORT_MATRIX`、malicious-layout inert 头先例、large-repo `_bulk_module_text` 纯索引先例 |
| 10 | real_run.py @1046501d | blob `0d6db453`（2194 行全文亲读） | §7.4/§7.5 演进对象：L102-293 pin 常量、`CANDIDATE_FILE_CAP=12` L129、loader 逐 pin（L635-805）、`_walk_python_files`/`_select_candidate_texts`（L1041-1078）、`__call__` state_reuse 初始化（L1215-1227）、`_run_attempt` 分支（L1337-1360）、`_materialize` destination `llamafactory-{sha}.tar.gz`（L1478-1479/L1558-1560）、入口（L2056-2194） |
| 11 | expert_timing.py @1046501d | blob `dd7aa365`（150 行全文亲读） | §7.3 专家包协议来源：ExpertTimingSession 状态机/sidecar 5 键/canonical 编码 |
| 12 | collect.py（只读禁区） | blob `063ecb41`（255 行亲读） | R2.4 事实校正采纳：int-or-None `require_metric` 门与 `PlatformSources` 可注入源已在场，资源接线在 report 侧 payload 域块完成，collect 零字节 |
| 13 | 冻结测试面 @1046501d | test_report blob `b53176f5`（29 方法全文亲读）、test_fixtures blob `34b397b7`（34 方法全文亲读）、test_real_run blob `d982bdd8`（66 方法全文亲读） | §9/§10 演进基础 |
| 14 | 注册表/矩阵工件 | `evaluation_data/v4/fixture_registry.json` blob `493f3da5`（12 条目亲读）；`baseline_manifest.json` blob `7ecb39f8`、`python_mvp_support_matrix.json` blob `3ea94fcf`（IP-0026 冻结，零字节） | §7.2 注册表演进；禁区守护 |
| 15 | Dockerfile @1046501d | blob `fcade9c9`（docs COPY 块亲读，L55-75） | C1 +3 行落位依据（IP-0035 Packet 行=L63 后插入） |
| 16 | 下游消费亲验（CA 输入 #16） | test_v4_baseline_offline_flow（blob `539d2fb3`，禁区）L410-419 派生式注册表断言；offline_flow/report 消费面 L450-454 按键取值 | 13 条目后仍绿（前提=注册表 JSON 与模块同步再生成）；新增顶层键不破坏下游 |
| 17 | 负例探针勘察（CA 输入 #17 + 本 P&V 会话亲验复核） | ①上限面：`repository_scanner.py` findings 零 `[:N]` 截断（本会话 grep `[:6]`/`[:12]` 零命中亲验）；仅 `semantic_retrieval.py` L666 证据包候选 `[:5]` 与 `cxx_memory.py` L158 `MAX_UAF_TRANSLATION_UNITS=16`（均具名披露）；runner 面 `_walk_python_files` 全量返回、`_select_candidate_texts` 取 `[:CANDIDATE_FILE_CAP]`。②holdout 面：`real_world_evaluation.py` 亲读——`load_real_world_dataset`=校验面；`RealWorldSecurityEvaluator.run`（L1140-）identity 消费点=case id 聚合去重键/snapshot 获取键/`_dataset_identity` 呈报；判定面 `scanner.scan`+`_matching_findings`+repair 只消费内容与 ground truth；`SnapshotStore(root, opener=...)` opener 可注入（内存 zip）+缓存命中路径零网络——离线探针注入点干净（本会话亲验） | §8 探针设计依据；§7.6 普查表 |
| 18 | 预冻结基线绿（C0，本 P&V 会话亲跑 @1046501d） | `.pv_tmp/RED_IP-0036_2026-09-28/baseline.txt` + 三份日志 | 三冻结测试文件 129/129 OK（92.7s）；九冻结文件 298/298 OK（46.5s）；全量 discover 2650 OK（skipped=24，331.5s）——与 CA 参照值逐项一致 |
| 19 | 专家包示例 sidecar 校验（本 P&V 会话亲验） | 2026-09-28 本会话以 `ExpertTimingSession` 构造示例并经 report.py 现行 `_gate_sidecar`/`_validate_sidecar_artifact` 双验证通过（含三个负例对照证明校验器确实在判） | §7.3 示例 sidecar 的合法性依据；M2 新增测试的验收面对象 |

哈希真值来源：`git ls-tree 10465010de05a759c339a491531707ff6e6619dc -- <paths>`（本 P&V 会话程序化复核，与 CA §Exact Baseline 一致）。

## 3. Explicitly Rejected Inputs

| # | 被拒输入 | 拒绝理由 |
| --- | --- | --- |
| 1 | vep/rvr/stage_outcome 混入 counts 7 键闭集 | R2.1：counts 是基线计数位（IP-0029 冻结 7 键闭集）；VEP/RVR/阶段结局是流水线阶段指标面，必须为 additive 顶层字段 |
| 2 | schema v2 支持 v1/v2 双解析宽容 | R2.2/Stop 14：v1 文档在 v2 严格解析下以既有 `SCHEMA_VERSION_INVALID` fail-closed 属诚实版本化（K1），不新增错误码、不做宽容解析 |
| 3 | 修改 collect.py 承载资源接线 | R2.4（Intent I-8 事实校正采纳）：collect=IP-0027 面，int-or-None 门与可注入源已在场；接线在 report 侧 payload 域块完成，collect 零字节 |
| 4 | 修改两批真实运行报告文件（v1→v2 迁移/改写/重读消费方） | K1：报告为终态产物，无重读路径（Coordinator 亲验 grep 零命中）；不迁移不改写 |
| 5 | 修改 `CANDIDATE_FILE_CAP=12` 数值或将 runner 面改造为"无上限" | CA Not-covered 3：12 是已披露请求构造参数，R6 只证语义（请求构造参数非处理上限）不改值；`_walk_python_files` 保持全量返回现状 |
| 6 | 真实网络下载/真实 sleep/真实模型调用驱动的验证 | Stop 1 绝对禁令；负例全部注入式（fake opener/fake transport/预置缓存） |
| 7 | 以 synthetic fixture 冒充真实扫描计数、以模型调用或合成事件填充专家分钟 | #237 Scope 2/6 明文；§0.4 诚实纪律；专家包缺席纪律 |
| 8 | 默认批次行为改为"每 attempt 重置"或 mode 标签重定义 | R8.1 否决：默认批次行为不变（5 cold+5 warm 标签、attempt-0 物化/attempts 1-9 复用）；mode 语义是 orchestrate 冻结面 |
| 9 | cold 重置需要改 state_reuse/provider_cache/timings 键集或 RunSpec 或结算策略 | R8.4/Stop 13：G5 键集不变路径（本 Packet §7.5 全部在该路径内）；否则 M9 DR |
| 10 | 通配仓库工件目录（非闭集 10 键）、默认联网、复制九份入口 | R9.1（S1 采纳：参数化工件描述+逐工件钉扎校验）；M5 明文禁止"因测试方便改为通配仓库或默认联网"；Stop 4 |
| 11 | 零预算证明工件携带可用请求能力或 api_key 通道；新工件具付费调用效力 | R9.4/Stop 12（I-2 硬边界）；冻结证据五件套文件名是 IP-0032 冻结面不改（其族判别值即为区隔） |
| 12 | 新增 `RealRunErrorCode`/`BaselineReportErrorCode`/`BaselineFixtureErrorCode` 成员 | CA Not-covered 3/Stop 3：未知工件键用既有 `APPROVAL_ARTIFACT_INVALID`+structure-only field_path；域块违规用既有 `EVALUATOR_PAYLOAD_INVALID` |
| 13 | 修改 `_RELATIONSHIP_TO_SUPPORT_MATRIX` 既有句或升级 IP-0026 矩阵工件行 | R3.5：只允许 additive 一句；矩阵工件保持字节冻结（既有句仍真）；IP-0026 工件零字节 |
| 14 | 第 13 个变更文件、Dockerfile 超 3 行、触碰 `lima/**`/`scripts/**`/禁区测试文件 | R1/Stop 5/Stop 2：Allowed Files 终形=恰 4 Add+8 Modify；负例探针是测试侧只读消费 |
| 15 | 修改 `evaluation_data/` 除 `fixture_registry.json` 外任何字节 | R1/M6：注册表恰由 `write_registry()` 再生成；其余 evaluation_data 全部只读 |

## 4. Goal / Non-goals

**Goal**：在 IP-0035 版产品（main=1046501d）上一次性补齐 PR3-e 全部离线缺口并以受审查单 PR 入库：①逐行矩阵 v2（六列含完成门禁）入 docs；②V5 报告 schema 补 vep/rvr/stage_outcome 三 additive 顶层字段+schema_version 1→2+real-world v2 payload 可选 domain 子块来源接线（null=unavailable 纪律；不写常数、不以 synthetic 冒充）；③固定上限与 holdout 身份无关性双负例探针（新测试文件）；④signal-storm 第 12 合成 archetype 入注册表+digest（13 条目）；⑤真人可用专家复核包+计时流程（无真人事件→缺席）；⑥可执行本地 cold 重置/warm 复用程序+离线探针（DR-IP-0035-01 义务）；⑦真实入口与工件族泛化（九类合成 archetype+llamafactory 共 10 键闭集；门禁零放松；零预算工件离线证明；不创建付费效力批准工件）。全部离线交付：零真实调用、零付费、零新额度、CI 永远零付费模型请求。

**Non-goals**：见 §1 Not-covered 段（CA 原文）。真实批次执行、真实专家事件、九类真实扫描不在本 Assignment 授权内（本轮零真实调用）；矩阵 v2 中依赖真实运行/人工专家的行保持部分/未证实（K6）。

## 5. 文件边界（CA R1：恰 4 Add + 8 Modify；零 Delete；单 PR `codex/ip-0036-pr3e-offline` → main）

### 5.1 Files to Add（恰 4）

| 文件 | Owner/阶段 | 说明 |
| --- | --- | --- |
| `docs/LIMA_Implementation_Packet_IP-0036_PR3e_Offline_Integration.md` | P&V（C1，本文件） | 本 Packet；承载 CA R1-R12 全部裁定+§7 冻结契约+§7.6 普查表+§16 决策记录 |
| `docs/LIMA_PR3e_Requirement_Matrix_v2.md` | P&V（C1，与 Packet 同一提交） | 矩阵 v2（R4：六列+五类目标行+锚行+完成门禁=可机械检查判据；R6.3 普查表结论入矩阵） |
| `docs/LIMA_PR3e_Expert_Review_Package.md` | P&V（C1，与 Packet 同一提交） | 专家复核包（R5.5：真人流程/逐字段表/示例 sidecar（字面通过现行冻结校验器）/与 report.py 冻结形状兼容性说明/缺席纪律声明；无 api_key/付费通道） |
| `tests/test_v4_baseline_v5_negatives.py` | P&V（C1 骨架/完整实现落库，C2 冻结；方法预算 ≤12） | 负例双探针+纪律符合性探针（R6.2/R6.3/R6.5；全离线、fake opener/注入源、零真实 sleep、不触网） |

### 5.2 Files Allowed to Modify（恰 8）

| 文件 | Owner/阶段 | 边界 |
| --- | --- | --- |
| `Dockerfile` | P&V（C1，与三 docs 同一提交） | **恰 +3 行**：三条 `COPY --chown=lima:lima docs/<file> ./docs/`（A1 Packet/A2 矩阵 v2/A3 专家包，按此位序插 IP-0035 Packet 行【L63】后）；既有行零改动。基线 blob `fcade9c95dcfe4504d4ba1247c3c46edd51f0344` |
| `tests/test_v4_baseline_report.py` | P&V（C2，冻结面演进 v1→v2；29→≤38） | R2.5 演进断言+专家包示例 sidecar 校验探针；六条件程序（§10.1）；基线 blob `b53176f5af0acf9322bfbaefd002612605fda4df` 永久在链 |
| `tests/test_v4_baseline_fixtures.py` | P&V（C2，冻结面演进；34→≤42） | signal-storm+13 条目注册表演进；六条件程序（§10.2）；基线 blob `34b397b700daabe58317180fd15f4c72658fdb66` 永久在链 |
| `tests/test_v4_baseline_real_run.py` | P&V（C2，冻结面演进 v5→v6；66→≤76） | 工件族/入口泛化/cold 重置演进；六条件程序（§10.3）；基线 blob `d982bdd888875c73608b6019e2f29dabf5e1be77` 永久在链 |
| `benchmarks/v4/baseline/fixtures.py` | Implementation（C3） | R3 全部实现面（§7.2：新 archetype+注册表机制演进） |
| `evaluation_data/v4/fixture_registry.json` | Implementation（C3，与 fixtures.py 同一提交） | **恰由 `write_registry()` 再生成**（13 条目；schema_version=1 不变）；Done Command 10 字节一致守护；`evaluation_data/` 其余零触碰 |
| `benchmarks/v4/baseline/report.py` | Implementation（C4） | R2 全部实现面（§7.1：schema v2 三新顶层面+domain 来源接线） |
| `benchmarks/v4/baseline/real_run.py` | Implementation（C5） | R8/R9 全部实现面（§7.4/§7.5：工件族+入口泛化+cold 重置程序） |

### 5.3 Read-only Reference Files（只读消费）

`benchmarks/v4/baseline/` 其余六模块（budget/orchestrate/collect/run/expert_timing/offline_flow）与各级 `__init__.py`；IP-0024..0035 Packet、两份批准工件（2026-09-27/2026-09-28）、CANARY_DECISION_PACK；`evaluation_data/**`（除 §5.2 登记的注册表再生成）；`lima/**`（负例探针只读消费 `RepositoryScanner`/`RepositoryWorkspace`/`RealWorldSecurityEvaluator`/`SnapshotStore`/`load_real_world_dataset`）；`.pv_tmp/` 各记录；`D:\BaseAIProject\LIMA-real-runs\**`（两批证据，只读）。

### 5.4 Files Forbidden（diff 必空；Done Command 7 逐 blob 守护）

`benchmarks/v4/baseline/` 其余六模块与各级 `__init__.py`；`tests/` 其余七个 v4 冻结测试文件（298 方法）与 `tests/` 其他既有文件；`evaluation_data/**` 其余全部（含 baseline_manifest.json/python_mvp_support_matrix.json/两批真实运行目录）；`lima/**`；`scripts/**`；`docs/` 其余全部（含历史 Packet、批准工件、决策包）；`pyproject.toml`/`requirements.txt`/`.gitignore`/`.gitattributes`/`.github/**`/前端；不提交任何输出目录/密钥/run 产物。

### 5.5 提交链拓扑（CA §Handoff/Done Command 8；冻结）

C1 = 三 docs + Dockerfile 恰 3 行 + 新测试文件（4 Add + 1 Modify，同一提交，前缀 `[IP-0036][PV]`）→ C2 = 四冻结测试文件面落定（3 Modify + A4 最终化；提交信息**必须含** `"[IP-0036][PV] Freeze acceptance tests (RED)"` 字样；RED 证据先于冻结落盘并独立日志归档 `.pv_tmp/RED_IP-0036_2026-09-28/`）→ C3 = fixtures.py+fixture_registry.json（1+1 Modify，前缀 `[IP-0036][IMPL]`）→ C4 = report.py（1 Modify）→ C5 = real_run.py（1 Modify）→ C-final 之后允许且仅允许修复提交（前缀 `[IP-0036][CI]` 或所属角色前缀），每次必须引用 Stop/DR/ALLOWED_ONCE 编号。单 PR；实现提交必须以 C2 冻结提交为祖先（Done Command 8）。

### 5.6 与其他活动 IP 的冲突分析（冻结面演进依据登记）

无并行活动 IP 占用本切片路径（IP-0036 编号未占用，Intent F2）。**冻结面演进依据显式登记（IP-0033/IP-0034/IP-0035 Packet §5.6 先例）= 2026-09-28 第三轮 Maintainer 授权（#237 Scope 2/5/7/8）+ DR-IP-0035-01 义务**，演进对象：① report.py `_REPORT_FIELDS` 16→19 键与 `BASELINE_REPORT_SCHEMA_VERSION` 1→2（R2.1/R2.2）+ real-world v2 payload 可选 domain 子块形状与合规规则（R2.3）；② fixtures.py `SYNTHETIC_FIXTURE_KEYS` 11→12、`_SYNTHETIC_NOTES`/`_build_shapes` 各 +1、`_RELATIONSHIP_TO_SUPPORT_MATRIX` additive 一句（R3）；③ real_run.py 工件族目录（10 键冻结）+逐工件钉扎校验+`run_real_baseline_suite` +1 kw-only 参数（默认=llamafactory，既有行为逐字节保持，签名演进=§7.4.2）+cold 重置独立入口（§7.5）+tarball 目标名模板化（llamafactory 键名逐字保持）；④ 测试面四文件（M2 v1→v2/M3/M4 v5→v6 演进+A4 新增，§10 六条件）；⑤ `evaluation_data/v4/fixture_registry.json` 数据产物演进（write_registry 再生成——实现产物交付，非 fixture 禁区违例；仅此一个 evaluation_data 文件）。历史文档零改动；本节即唯一演进依据登记处。IP-0024..0035 一切其余冻结面禁止触碰。

## 6. 依赖、网络、文件系统与权限边界

- **依赖**：零新增第三方依赖。产品侧唯一获准新 import=`from benchmarks.v4.baseline.fixtures import ...`（real_run.py，C5；用途=工件族 commit_sha 派生消费注册表指纹与重置观测的树摘要 `compute_tree_fingerprint`——只消费公共符号 `load_registry`/`compute_tree_fingerprint`，不触私有形状函数；本条为本 Packet 登记的 import 白名单增量，超出即 Stop 9）。`fixtures.py`（C3）零新增 import。`report.py`（C4）零新增 import。测试文件：M2/M3/M4 零新增 import（纯增量常量/方法）；A4 获准新 import=`RepositoryScanner`（`lima.repository_scanner`）、`RepositoryWorkspace`（`lima.workspace`）、`RealWorldSecurityEvaluator`/`SnapshotStore`/`load_real_world_dataset`（`lima.real_world_evaluation`）+ 已预登记的 `benchmarks.v4.baseline.*` 与 stdlib（R6 探针只读消费 lima 评估面——CA Stop 9 预登记）。
- **网络**：测试全离线、fake transport/fake opener（内存 zip）/预置缓存、永不触网（既有 `_forbidden_network_roots` 断言延续+A4 自扫）。**本 IP 离线交付期间任何真实网络/下载/付费调用 = Stop Condition 1（绝对禁令）**。本 P&V 会话零网络（Packet 制作与冻结全程本地；CA 已完成远程核验）。
- **文件系统**：证据文件只写调用方提供的一次性输出目录（离线测试写 tempdir）；库内除 §5.1/§5.2 十二文件外零写入；不读环境变量/配置/.env（h1 钉扎面保持）。
- **数据库/容器/远端写**：无数据库；容器面仅 Dockerfile +3 COPY 行；零远端写（不 push、不开 PR、不关 Issue、不改 Ledger 远端状态——合并/推送/评论由主会话按 Maintainer 授权另行核发）。
- **凭据**：api_key 仍为显式必填参数，永不落盘/入日志/入错误消息/入证据（e2/rd5/a3 探针面保持）；零预算工件无 api_key 通道（§7.4.4）。
- **clock**：`_monotonic` 模块缝（IP-0035 冻结）继续是唯一 wall 时源；本叶零新时源、零真实 sleep。

## 7. 实现契约细化（Packet 定稿；R2/R3/R5/R6/R8/R9 全部落位）

### 7.1 report.py：V5 报告 schema v2（R2；FR-02/AC-1）

#### 7.1.1 演进面（本授权显性演进；依据=§5.6-①）

1. **三 additive 顶层字段**（顺序冻结，追加于既有 16 键之后）：`_REPORT_FIELDS` 16→19 = 既有 16 键逐字 + `("vep", "rvr", "stage_outcome")`。形态：
   - `vep`/`rvr`：`{"value": int | None, "projection": str}` 三值形态（`_PROJECTIONS` 三值不变：measured/legacy_projection/unavailable）；value=exact int ≥0 或 None。
   - `stage_outcome`：冻结三键映射 `{"audit": {...}, "mining": {...}, "repair": {...}}`，每值 `{"value": str | None, "projection": str}`；值域为本 Packet 定稿冻结的闭集词表（DR-IP-0036-PV-1）：**`("completed", "skipped", "failed", "inconclusive")`**（三阶段共用；completed=该阶段运行至终态；skipped=该阶段被显式未配置/未执行；failed=该阶段运行且以失败终态；inconclusive=该阶段运行但无可判定终态）。无来源时 value=None+projection="unavailable"。
   - `to_canonical_value`/`from_mapping`/`_freeze_document` 严格校验同步演进：三新面键集闭集、unknown-field 拒绝、`(projection=="unavailable") == (value is None)` 配对纪律（与 counts 同构）、stage_outcome 值域校验（非词表值=`INVALID_FIELD_VALUE`）。
2. **版本**：`BASELINE_REPORT_SCHEMA_VERSION` **1→2**。严格校验下 v1 文档以既有 `SCHEMA_VERSION_INVALID` fail-closed（不新增错误码；K1 登记）。`BASELINE_REPORT_DECLARATIONS` 逐字不动；`BaselineReportErrorCode` 十二成员与 `_STABLE_MESSAGES` 逐字不动。
3. **来源接线（规则冻结，非常数）**：recognized 评估 payload（e2e v1 与 real-world v2 两种 dict 形态）增设**可选** `domain` 子块（冻结键集）：`signals`/`security_issues`/`hypotheses`/`vep`/`rvr` 各 exact int ≥0；`stage_outcome` 三键闭集词表（每键值 ∈ §7.1.1-1 词表）；可选 `resources` 子块三键（prompt_tokens/completion_tokens/cost_micro_usd）各 exact int ≥0。规则：
   - **在场则必须合规**（未知键/类型违规/负值/词表外值/缺 stage 键=违规）→ 既有 `EVALUATOR_PAYLOAD_INVALID` fail-closed（零新增错误码）；
   - **合规 → 对应面 measured**：signals/security_issues/hypotheses（覆盖 real-world+e2e 路径当前的 unavailable）、vep/rvr（value=域值）、stage_outcome（value=域值）、resources 面三字段由 domain.resources 接线（字段形状不变：三键 int|None；无 domain.resources 时三字段保持 null——现状诚实保持）；
   - **缺席 → null+"unavailable"**（现状诚实保持；不写常数、不以 synthetic 冒充）；
   - **优先级（DR-IP-0036-PV-2，冻结）**：`EvidenceDomainBundle` 在场时 signals/security_issues/hypotheses 保持 bundle 派生（bundle 是更完整证据域源；domain 不覆盖 bundle 派生面）；vep/rvr/stage_outcome/resources 恒以 domain 为唯一来源。scanner 路径 bundle 派生面与 e2e/real-world 其余投影规则不变（domain 接线是唯一新规则）。
   - **语义映射记载**：`coverage_gap_reasons` 语义保持文件级 skip 专用，不混入 schema 缺口语义——缺位由 projection="unavailable" 承载（本条即该映射的登记处）。
4. **collect.py 零字节**（R2.4）：资源接线在 report 侧 payload 域块完成。
5. **不变面（违例即验收失败）**：`__all__` 十二符号；counts 7 键三值形态与闭集；`_PROJECTIONS`/`_SOURCE_KINDS`/`_EVIDENCE_DOMAINS`/`_AGGREGATE_STATUSES`；sidecar 5 键（`_gate_sidecar`/`_validate_sidecar_artifact` 冻结形状——专家包兼容性前提，本叶 report 演进**不触碰** `_SIDECAR_FIELDS`）；compression_chain/expert/automation 面形状；e2e/scanner 投影规则；`from_mapping` 严格闭集纪律；`_COVERAGE_AFFECTING_SKIPS`/`_VERIFICATION_STATES` 转录；write_report_file/find_run_artifacts 发现契约；错误码族与 `_STABLE_MESSAGES`；imports 白名单（既有；零新增）。

#### 7.1.2 测试面（R2.5）

test_report v1→v2 演进（29→≤38；§10.1 六条件；(b) 类值更新清单：测试常量 `_REPORT_FIELDS` 16→19、`_ALLOWED_DOC_STRINGS` +词表四词、`test_report_surface_frozen` 的 `BASELINE_REPORT_SCHEMA_VERSION` 1→2、`test_schema_name_and_version_invalid_rejected` 的非法版本探针 2→1——全部由 R2.1/R2.2 驱动）。新增必含：三新面在场与 null 纪律、schema_version=2 与 v1 fail-closed、domain 块合规→measured/缺席→unavailable/违规→fail-closed 三态、resources 接线、专家包示例 sidecar 通过冻结校验器（R5.5 验收面）。逐方法落位见 §9.1。

### 7.2 fixtures.py：signal-storm 第 12 合成 archetype（R3；FR-05/AC-3）

1. **键与注册表**：`archetype/signal-storm` 为**第 12 合成 archetype**（`SYNTHETIC_FIXTURE_KEYS` 11→12，追加于元组末位；注册表第 13 条目；`FIXTURE_KEYS` 13 键闭集）。`evaluation_data/v4/fixture_registry.json` 恰由 `write_registry()` 再生成（schema_version=1 不变——条目同构 additive；Done Command 10 守护）。
2. **生成器（冻结语义）**：确定性生成器（纯索引函数，无随机/时钟/网络，先例=large-repo `_bulk_module_text`）。形态语义=大量低价值 signal：N 个惰性模式文件（**N>12**；N 的具体数值由 Implementation 定稿一次并随形状冻结——测试一律从物化树派生期望，不硬抄），**每文件恰一个**惰性命令注入模式位点（`os.system(...)` 形态、常量良性参数、CWE-78 可判定——为 R6 上限负例提供原料），每文件带 SYNTHETIC INERT 头（`_MALICIOUS_INERT_HEADER` 先例=malicious-layout）。
3. **边界（冻结）**：全 ASCII/LF；总字节上限沿 large-repo 同量级（≤262144）；无 URL（`test_registry_contains_exactly_one_url` 保持恰一 URL=外部条目）；无真实身份 token（`_REAL_IDENTITY_TOKENS` 全缺席）。
4. **注册表机制演进**：`_SYNTHETIC_NOTES` +1 条（登记上述语义）；`_build_shapes` +1 形状；`_shape_fingerprint` 冻结摘要算法零变化；`BaselineFixtureErrorCode` 六成员+`_STABLE_MESSAGES` 逐字（零新增错误码）；materialize/verify 契约与 fail-closed 语义零变化；既有 11 形状与 external 条目逐字。
5. **关系注记（R3.5 冻结）**：`_RELATIONSHIP_TO_SUPPORT_MATRIX` **只允许 additive 一句**：登记 PR3-e 需求级矩阵位于 `docs/LIMA_PR3e_Requirement_Matrix_v2.md` 而 IP-0026 工件矩阵保持字节冻结（既有句零删除——矩阵工件行仍未升级，注记仍真）。
6. **不变面**：`__all__` 八符号；imports 白名单（零新增）；`compute_tree_fingerprint` 冻结摘要算法；注册表校验闭集纪律（`len(entries)==len(FIXTURE_KEYS)` 随 13 键同步）；offline hygiene 面（无网络 token/无随机时钟 import）。

### 7.3 专家复核包（R5.5；FR-06/AC-3；docs 交付，P&V C1）

载体=`docs/LIMA_PR3e_Expert_Review_Package.md`。内容（冻结清单）：①真人流程（开始/暂停/恢复/结束，ns 时间戳纪律 → `ExpertTimingSession` 状态机）；②sidecar 协议逐字段表（`.expert-timing.json` 5 键：schema_version/run_spec_digest/reviewer_digest/active_time_ms/events；reviewer 身份只以 SHA-256 摘要出现）；③**示例 sidecar（完整 JSON）必须字面通过 report.py 现行 `_gate_sidecar`/`_validate_sidecar_artifact` 冻结形状校验**——本 P&V 会话已以 `ExpertTimingSession` 构造并经双验证器亲验通过（含负例对照；Design Input #19）；验收面=M2 新增测试解析包内示例并断言通过（Packet 静态断言+测试小例双承载）；④与 report.py 冻结形状校验兼容性说明（本叶 report 演进不触碰 `_SIDECAR_FIELDS` 五键——sidecar schema 零变更）；⑤缺席纪律（无真人事件→expert sessions=0、active_time_ms_total=None；**不得以模型调用或合成事件填充**）；⑥包不含任何 api_key/付费通道；本叶零真人事件（K4）。

### 7.4 real_run.py：工件族与入口泛化（R9；FR-08/AC-4）

#### 7.4.1 冻结工件族目录（R9.1；DR-IP-0036-PV-3）

real_run.py 新增模块级公开常量 **`REAL_RUN_ARTIFACT_FAMILY`**（closed dict，恰 10 键）：九类合成 archetype（`archetype/application`、`archetype/library`、`archetype/cli`、`archetype/docs-content`、`archetype/test-heavy`、`archetype/monorepo`、`archetype/large-repo`、`archetype/malicious-layout`、`archetype/dependency-blocked`）+ `external/llamafactory-replay`。**不入 `__all__`**（`__all__` 六符号逐字不动；测试经模块属性访问——本条为 Packet 定稿登记）。每描述子冻结七键闭集：

| 键 | llamafactory 描述子（逐字=现行钉） | 合成描述子（一次性定稿冻结） |
| --- | --- | --- |
| `repository` | `hiyouga/LlamaFactory` | `lima-synth/<archetype>`（ASCII，archetype=裸名，如 `lima-synth/application`） |
| `requested_name` | `hiyouga/LLaMA-Factory` | 同 `repository` |
| `commit_sha` | `7fcf5b3b130e5713b52415bb7404c476fada9c8c` | 由 fixture 树指纹确定性派生的 40-hex（派生式见下；**非 git commit**——文档明示） |
| `tarball_url` | `https://codeload.github.com/hiyouga/LlamaFactory/tar.gz/7fcf5b3b…` | RFC 2606 `.invalid` URL（永不 fetchable，披露）：`https://lima-synth.invalid/<archetype>/tar.gz/<commit_sha>` |
| `tarball_filename` | `llamafactory-{commit_sha}.tar.gz`（与现状逐字节一致） | `lima-synth-<archetype>-{commit_sha}.tar.gz`（`{commit_sha}` 占位符展开） |
| `approval_type` | `PR3D-REAL-RUN-LIMITED`（现行文档身份钉逐字） | `PR3E-OFFLINE-PROOF-ZERO-BUDGET`（族判别值；禁 Approval/approval 字样——R9.4①） |
| `run_name` | `pr3d-real-2026-09-28`（现行逐字） | `pr3e-offline-proof-<archetype>`（offline-proof 显式标记——R9.4②） |

**commit_sha 派生式（DR-IP-0036-PV-4，冻结；测试按此复算=PC3）**：

```python
commit_sha = hashlib.sha256(
    ("lima-synth-artifact:" + key + ":" + registry_fingerprint).encode("utf-8")
).hexdigest()[:40]
```

其中 `key`=该合成 fixture 键（如 `archetype/application`），`registry_fingerprint`=该键在 `load_registry()` 条目的 64-hex `fingerprint`。

**逐工件钉扎校验（S1——非复制九份入口）**：loader 按所选工件键（§7.4.2）取描述子，校验文档 `upstream` 四钉（repository/requested_name/commit_sha/tarball_url 逐字等于描述子值）与文档身份钉（approval_type/run_name 逐字等于描述子值）；共享钉（schema_version=1/date/authorized_by/baseline_sha/model 五钉/pricing/预算构造/machine_profile/attempt_policy）不变（与现行逐字同）。`tarball_filename` 模板决定 `_materialize` 的 destination 文件名（llamafactory 键展开结果与现状逐字节一致）。未知 key → 既有 `APPROVAL_ARTIFACT_INVALID` + structure-only field_path（`$`；零新增错误码）。

#### 7.4.2 入口参数化（R9.2）

`run_real_baseline_suite` 新增**恰一个 kw-only 参数** `artifact_key: str = "external/llamafactory-replay"`（DR-IP-0036-PV-5；追加于签名末位（`sources` 之后）；`_ENTRY_PARAM_ORDER`/`_ENTRY_KEYWORD_ONLY` 随之演进=§10.3 (b) 类值更新）。默认路径全部现行行为逐字节保持（66 测试面既有断言零改动——除签名钉本身）；签名演进登记于 §5.6-③。

#### 7.4.3 零预算离线证明（R9.3；AC-4 验收分解裁定）

两面合并=AC-4"零预算工件下离线全链"的验收语义：
- **(a) 零预算工件拒付面**：对每个合成工件键以零预算文档（calls=0/cost=0 全维零，g1 既有 arrange 形态）运行入口→首 reserve fail-closed（IP-0031 零预算态，`RUN_BUDGET_EXCEEDED` @ `$.budget.per_run.calls`）→证据 calls=0/cost=0、零传输调用（零预算下物化不可达=如实部分链；**不作**全链宣称）。
- **(b) 离线全链面**：注入 fake transport+测试构造预算工件（既有离线测试模式）证明物化→重置→观测面全链（§7.5.3 探针承载）。

#### 7.4.4 零预算工件命名纪律（R9.4；五条机械判据清单——A4/M4 测试承载）

1. 新文件族与族判别值**禁 "Approval"/"approval" 字样**：族判别值=`PR3E-OFFLINE-PROOF-ZERO-BUDGET`（§7.4.1 表）；冻结证据五件套文件名是 IP-0032 冻结面**不改**——approval.json 内承载的是被加载输入文档的逐字记录，其族判别值（approval_type 值）即为区隔，本 Packet 如实登记该边界。
2. offline-proof 显式标记：合成描述子 run_name 含 `offline-proof`。
3. 文档内**无 api_key 通道**：零调用/零付费效力；入口 api_key 参数为冻结签名，零预算运行中永不被使用（注入面证明零传输调用）。
4. calls=0/cost=0 逐维断言（§7.4.3(a) 探针）。
5. CI 断言零付费模型请求（既有 NFR-02 面延续+A4/M4 新探针：全部注入式、无网络 import、fake transport 零真实调用）。

**任何形态若需携带可用请求能力或 api_key 通道 → Stop 12 + Decision Request（I-2 硬边界）。**

#### 7.4.5 门禁零放松逐项断言（R9.5；M4 新增承载）

固定 commit/数据角色/模型身份/七维预算/canary 五项/失败留证/Secret 隔离，在 M4/A4 新增中以断言钉扎（尤其合成工件键路径下身份钉与预算门行为与 llamafactory 路径同构——同一 loader、同一七维校验、同一 canary 清单、同一证据五件套）。

### 7.5 real_run.py：cold 重置/warm 复用程序（R8；FR-07/AC-4；DR-IP-0035-01 义务；G5 路径兑现）

#### 7.5.1 语义（冻结）

cold attempt=从**已缓存 tarball 重新解包**（新 per-cold snapshot 目录，命名见 7.5.4）+**重建请求体**；download 仅首次（重置 attempt 零传输 GET、零下载字节）；warm=现状明确复用（snapshot_reused）。**产品默认批次行为不变**（5 cold+5 warm 标签、attempt-0 物化/attempts 1-9 复用、G5 观测面如实标注现状）——重置程序以**可独立调用入口**交付，未来真实批按 DR-IP-0035-01 结构（每类 3 次可验证 cold+5 warm）调用。**否决"改为默认批次行为"**（R8.1）。

#### 7.5.2 可独立调用入口（DR-IP-0036-PV-6，冻结符号与签名）

**`_GuardedRealEvaluator.reset_cold_state(self) -> dict[str, object]`**（类名不重命名；公开方法形态=CA R8.1 建议之二；测试经 `module._GuardedRealEvaluator` 构造或实例调用）。行为：①从已缓存 tarball（`_tarball_dir` 内该工件的目标文件）重新解包到新 per-cold snapshot 目录；②重跑 `_prepare_request` 重建请求体；③返回观测文档（键集冻结，恰五键）：

```python
{
  "state_reuse": {  # 四键集与语义零变化（G5）
      "materialized": True, "snapshot_reused": False,
      "request_body_rebuilt": True, "process_identity": <_digest_token 形态>,
  },
  "timings": {"extract_ms": <int>=0, "download_ms": None, "attempt_wall_ms": <int>=0},
  "snapshot_tree_sha256": <64-hex>,       # 重物化快照树摘要（compute_tree_fingerprint）
  "request_body_sha256": <64-hex>,        # 重建请求体字节摘要
  "materialization_count": <int>,         # 本 evaluator 已完成的物化次数（初始物化=1，每次重置 +1）
}
```

- `download_ms=None` 纪律：相位未执行（重置零 GET）——None 纪律，绝不伪造 0；`extract_ms` 已执行相位如实 int ≥0；`attempt_wall_ms` 端到端实测。
- **不新增任何键**到 state_reuse/provider_cache/timings 观测子块（G5 键集不变路径；attempt 文档 15 键不变）。
- **真实 cold 计数规则（规范性契约，非统计代码）**：真实 cold 计数=物化重置次数=`materialization_count`（=初始物化 1+重置次数）。未来真实批"每类 3 次 cold"必须由 3 次可验证重置承载（materialization_count 达 4：1 初始+3 重置）。

#### 7.5.3 离线探针（M4 新增承载）

注入 fake transport 下证明：重置后 snapshot 新目录物化且树摘要与原物化一致（`snapshot_tree_sha256`==首次物化树摘要）；请求体字节与首次构造恒等（`request_body_sha256`==首次请求体摘要；确定性）；state_reuse 三元组翻转 (T,F,T)；零 GET 调用（transport download_calls 不变）；extract/download/timings None 纪律；重复重置确定性（同摘要、不同 per-cold 目录、materialization_count 递增）；"每 attempt 状态"=重置前后 attempt 序列的 state_reuse 全序列断言（默认序列 (T,F,T)+(F,T,F)×9 不变+重置观测 (T,F,T)）。

#### 7.5.4 per-cold 目录命名（冻结）

初始物化=现行 `_materialized/snapshot`（逐字保持）；第 k 次重置（k=1,2,…）→ `_materialized/snapshot-cold-{n}`，n=该次重置完成后的 `materialization_count`（首次重置 → `snapshot-cold-2`）。默认批次运行不创建任何 `snapshot-cold-*` 目录。

#### 7.5.5 键集边界（R8.4）

本路径无需 Maintainer 决策（G5 键集不变、RunSpec/预算语义零触碰）；若实现需要改 state_reuse 键集/RunSpec/结算策略 → Stop 13 + M9 DR。本叶重置入口不触结算（K3）。

### 7.6 固定上限普查表（R6.4；FR-03；Packet 必载，矩阵 v2 承接）

本 P&V 会话对离线可判定路径（`benchmarks/v4/baseline/*` 与 `lima/` 评估面）以 grep 普查全部固定数值选择/上限常量并分类（与 CA 输入 #17 一致，本会话亲验复核）：

**A. 披露有界参数（具名+语义披露；零改动，修改其语义=另行决策）**：

| 参数 | 位置 | 语义 |
| --- | --- | --- |
| `CANDIDATE_FILE_CAP=12` | real_run.py L129 | 请求构造参数：每请求候选文件数上限（`_select_candidate_texts` 取 `[:12]`）；非处理/复核上限（`_walk_python_files` 全量返回；R6.2-② 证明） |
| `CANDIDATE_CHAR_CAP=6000` | real_run.py L130 | 每候选文件读入字符上限（请求构造） |
| `MAX_CONTEXT_CHARS=36000` | real_run.py L128 | 每请求上下文总字符上限 |
| `WALK_ENTRY_CAP=5000` | real_run.py L131 | 目录遍历访问条目上限（防失控遍历；非 findings 上限） |
| `MEMBER_COUNT_CAP=30000` | real_run.py L135 | 归档成员数上限（安全解包） |
| `MEMBER_BYTE_CAP=50000000` | real_run.py L136 | 单成员字节上限（安全解包） |
| 下载字节上限 | 预算维度 `per_run.download_bytes`（工件声明，现行 250,000,000） | 每 attempt 下载字节上限（流式逐块执行中检查） |
| 证据包候选 `[:5]` | semantic_retrieval.py L666 | 语义检索证据包候选数（具名披露的有界选择参数） |
| `MAX_UAF_TRANSLATION_UNITS=16` | cxx_memory.py L158 | UAF 分析翻译单元上限（具名披露） |

**B. 隐藏上限**：普查结论=**不存在"固定 6 条"式未披露复核/处理上限**（`repository_scanner.py` findings 零 `[:N]` 截断、adjudication 零截断——本会话 grep 亲验；审查面 findings/taxonomy/复核计数在有界工作区内无上限截断）。若实现期间发现新的疑似隐藏上限 → 如实登记+Stop 10 呈报，不得静默。

## 8. 负例双探针（R6.2/R6.3；FR-03/FR-04/AC-2；载体=tests/test_v4_baseline_v5_negatives.py）

### 8.1 探针一：固定上限不存在（双面）

- **①审查/扫描面（生产纯函数判定路径，注入点干净——CA #17 勘察+本会话亲验）**：
  - (a) 内联树守卫探针（零 fixture 依赖，现行为按设计通过）：测试自建 N=14 文件树（每文件一个 `os.system` 形态惰性模式）→ `RepositoryScanner(sast_mode="off").scan(RepositoryWorkspace(root))` → 断言 findings 数=预期 N（N>6 且 >12）全部保留、无"固定 6 条"式截断。
  - (b) fixture 物化探针（依赖 C3 交付）：物化 `archetype/signal-storm`（+`archetype/docs-content`+`archetype/test-heavy` 恶意惰性模式作 findings 原料）→ 同一扫描面 → 断言 findings 数=预期 N（从物化树派生；N>12）全部保留、taxonomy/复核计数无上限截断。
- **②runner triage 面**：N=15 python 文件树 → `_walk_python_files` 返回全部 N；`_select_candidate_texts` 恰取 `CANDIDATE_FILE_CAP=12` → 证明 12 是**请求构造参数非处理上限**；`CANDIDATE_FILE_CAP==12` 数值钉扎（不改值）。报告压缩链 raw_candidates 于 N>12 totals payload 无截断由既有冻结断言承载（test_report `test_realworld_projection_and_v2_anticonfusion` raw=20）。

### 8.2 探针二：holdout 身份无关性（三形态）

以 `RealWorldSecurityEvaluator`（deterministic 模式判定面；`SnapshotStore(root, opener=<内存 zip>)` 注入，零网络——CA #17 勘察：缓存命中路径零网络+opener 可注入）跑同一语义内容的三身份变体：①改名（dataset name 与 case id 变体）；②换路径（dataset 文件路径与 snapshot 缓存路径变体）；③非语义元数据（附加非语义键：顶层与 case 级两子面）。断言：逐 case 判定（vulnerable_hit/fixed_clean/verified_hit/paired_discrimination）与聚合 metrics 三变体恒等；身份面（`_dataset_identity`：dataset/dataset_sha256/manifest_sha256）如实不同（改名→三者皆变；顶层元数据→仅 manifest_sha256 变而 dataset_sha256 不变；case 级元数据→dataset_sha256 亦变——可判伪结构）；三变体均通过 `load_real_world_dataset` 校验面（identity 消费点限于校验/去重/获取键/呈报；spec↔manifest 绑定 fail-closed 是校验面非产品判断条件——矩阵 v2 如实登记该边界，K5）。

### 8.3 纪律符合性探针（同文件承载；R6.5）

A1/A2/A3 三 docs 在库+Dockerfile 三 COPY 行（a1 式）；零预算工件命名纪律机械扫描（R9.4①②——§7.4.4 判据 1/2 于 `REAL_RUN_ARTIFACT_FAMILY` 逐合成键机械断言）；工件族目录↔注册表一致性（合成描述子 commit_sha==派生式复算（PC3）且键集⊆注册表键集）；新源码 secret-token/网络 token 扫描（PC1：A4 自身源无网络 import roots、无 secret 形状）。

## 9. 测试矩阵（四文件面；R7 预算：M2 ≤38、M3 ≤42、M4 ≤76、A4 ≤12；合计 ≤168；基线 129）

### 9.1 M2：tests/test_v4_baseline_report.py v1→v2（29 演进保留+≤9 新增；定稿 38）

新增方法（9 个，逐个登记断言面；类=TestV5SchemaFaces 新类）：

| 方法 | 覆盖 | 断言面（冻结） |
| --- | --- | --- |
| `test_schema_v2_surface_and_v1_rejected` | FR-02/AC-1/R2.1/R2.2 | `set(report._REPORT_FIELDS)==19` 键（16+vep/rvr/stage_outcome 追加序）；`BASELINE_REPORT_SCHEMA_VERSION==2`；dataclass 字段序==19 键；schema_version=1 文档→`SCHEMA_VERSION_INVALID` @ `$.schema_version`（既有码 fail-closed）；`__all__` 十二符号与错误码族不变锚 |
| `test_vep_rvr_stage_outcome_null_discipline` | FR-02/AC-1/R2.1 | 无 domain 的三类 payload 构建报告：vep/rvr=={None,"unavailable"}；stage_outcome==三键映射全 {None,"unavailable"}；null-not-zero（value is None 且 ≠0）；from_mapping 对畸形新面（非 dict/缺键/词表外值/measured 配 null 值）逐例 typed 拒绝 |
| `test_realworld_domain_block_wires_measured_faces` | FR-02/AC-1/R2.3 | real-world v2 payload+合规 domain（signals=3/security_issues=2/hypotheses=1/vep=2/rvr=1/stage_outcome 三词/resources 三键）→ counts 三面 measured==域值、vep/rvr measured、stage_outcome 三键 measured==词表值、resources 三字段==domain.resources（形状不变）；sources/evidence_domain/其余投影不变 |
| `test_e2e_domain_block_wires_measured_faces` | FR-02/AC-1/R2.3 | e2e payload+同 domain → 同一接线（覆盖 real-world+e2e 路径；e2e 其余面 unavailable 保持） |
| `test_domain_absent_keeps_unavailable_everywhere` | FR-02/AC-1/R2.3 | 三类 payload 无 domain → vep/rvr/stage_outcome/resources 全 null+unavailable；counts 现状投影不变（诚实保持） |
| `test_domain_violations_fail_closed` | FR-02/AC-1/R2.3 | 违规矩阵（未知键/str 值/负值/缺 stage 键/词表外 stage 值/resources 缺键/非 int resources）逐例 `EVALUATOR_PAYLOAD_INVALID` @ `$.evaluator_payload`（既有码；零新增错误码锚） |
| `test_bundle_precedence_over_domain_counts` | FR-02/AC-1/R2.3（DR-PV-2） | bundle+domain 并存：signals/security_issues/hypotheses==bundle 派生；vep/rvr/stage_outcome/resources==domain 接线；evidence_domain=="v2" 不变 |
| `test_expert_package_example_sidecar_passes_frozen_validators` | FR-06/AC-3/R5.5 | 解析 `docs/LIMA_PR3e_Expert_Review_Package.md` 的 ```json 示例块 → `build_baseline_report(summary(digest=示例 run_spec_digest), scan payload, expert_sidecars=(doc,))` 成功（公共校验路径）；`_validate_sidecar_artifact` 通过（发现面）；示例==`ExpertTimingSession` 同事件序列的 `to_sidecar_document` 输出（协议 roundtrip）；包文档在库 |
| `test_v2_canonical_roundtrip_and_string_domain` | FR-02/AC-1/R2.1 | domain-wired 文档 canonical bytes 稳定+from_mapping roundtrip 无损；`_ALLOWED_DOC_STRINGS` 增词表四词后全字符串审计通过（无自由文本泄漏） |

(b) 类值更新（全部由 R2 驱动，无一处实现便利）：模块 docstring 追加 v2 演进段；测试常量 `_REPORT_FIELDS` 16→19、`_ALLOWED_DOC_STRINGS` +`completed`/`skipped`/`failed`/`inconclusive`；`test_report_surface_frozen` 版本断言 1→2；`test_schema_name_and_version_invalid_rejected` 非法版本探针值 2→1（v1 现为非法）。既有 29 断言零弱化。

### 9.2 M3：tests/test_v4_baseline_fixtures.py（34 演进保留+≤6 新增；定稿 40）

新增方法（6 个；类=TestSignalStormFixture 新类）：

| 方法 | 覆盖 | 断言面（冻结） |
| --- | --- | --- |
| `test_signal_storm_is_the_twelfth_synthetic_archetype` | FR-05/AC-3/R3.1 | `SYNTHETIC_FIXTURE_KEYS`==12 键（signal-storm 末位）；`FIXTURE_KEYS`==13；`EXTERNAL_IDENTITY_KEYS` 不变 |
| `test_signal_storm_materializes_deterministic_bounded_tree` | FR-05/AC-3/R3.2/R3.3 | 物化：N=.py 文件数（从树派生）>12；总字节 ≤262144；全 ASCII/LF；每 .py 文件 SYNTHETIC INERT 头+恰一 `os.system` 位点（常量参数）；两次物化逐字节恒等（纯索引确定性）；文件名/内容含模块索引 token（纯索引函数证明） |
| `test_signal_storm_registry_entry_and_fingerprints_agree` | FR-05/AC-3/R3.1/R3.6 | 注册表 13 条目中 signal-storm 条目：`_SYNTHETIC_FIELD_SET` 闭集、kind/origin/license 逐字同族、fingerprint hex64==物化 `compute_tree_fingerprint`==测试侧独立 oracle 复算（PC3）、file_count/declared_size_bytes==物化值 |
| `test_registry_regenerates_thirteen_entry_bytes` | FR-05/AC-3/R3.6/Done Command 10 | `write_registry(tempdir)` 两次字节恒等且==committed artifact 逐字节（13 条目） |
| `test_relationship_note_additive_and_notes_registered` | FR-05/AC-3/R3.5 | `relationship_to_support_matrix` 含新 additive 句（登记 `docs/LIMA_PR3e_Requirement_Matrix_v2.md`）且既有句全保留（零删除——逐 token 在场断言）；signal-storm notes 含 SYNTHETIC INERT/上限负例原料语义 |
| `test_signal_storm_no_url_no_real_identity` | FR-05/AC-3/R3.3 | 注册表 `https://` 计数==1（仅外部条目）；signal-storm 条目与物化字节无 `_REAL_IDENTITY_TOKENS`、无 http |

(b) 类值更新（全部由 R3 驱动）：`_EXPECTED_FILE_COUNTS` +`archetype/signal-storm`（值=定稿 N——由 Implementation 一次定稿后登记；测试以物化派生校验 file_count）；`test_materializes_all_eleven_synthetic_fixtures_with_declared_counts` 11→12（方法名与断言同步演进）；`test_registry_top_level_schema_fields` 12→13；`test_registry_keys_form_closed_set_matching_fixture_keys` 12→13 与 11→12；`test_fingerprints_distinct_across_keys_and_stable_across_runs` 11→12。既有 34 断言零弱化。

### 9.3 M4：tests/test_v4_baseline_real_run.py v5→v6（66 演进保留+≤10 新增；定稿 76）

新增方法（10 个；类=TestArtifactFamilyAndColdReset 新类）：

| 方法 | 覆盖 | 断言面（冻结） |
| --- | --- | --- |
| `test_entry_signature_gains_artifact_key_with_frozen_default` | FR-08/AC-4/R9.2 | 签名参数序==`_ENTRY_PARAM_ORDER`+artifact_key（末位 kw-only，默认 `external/llamafactory-replay`）；`__all__` 六符号不变；缺省调用→下载 URL==canonical tarball URL、destination 文件名==`llamafactory-7fcf5b3b….tar.gz`（默认路径逐字节兼容锚） |
| `test_artifact_family_catalog_frozen_ten_keys` | FR-08/AC-4/R9.1 | `REAL_RUN_ARTIFACT_FAMILY` 键集==10（九合成+external/llamafactory-replay）；每描述子七键闭集；llamafactory 描述子四钉+身份钉+filename 模板与现行逐字 |
| `test_synthetic_descriptors_derived_deterministically` | FR-08/AC-4/R9.1/DR-PV-4 | 每合成键：repository/requested_name==`lima-synth/<archetype>`；commit_sha==派生式复算（从注册表 fingerprint，PC3）；tarball_url==`.invalid` 模板；tarball_filename==`lima-synth-<archetype>-{commit_sha}.tar.gz`；approval_type==`PR3E-OFFLINE-PROOF-ZERO-BUDGET`；run_name 含 offline-proof |
| `test_unknown_artifact_key_rejected_structure_only` | FR-08/AC-4/R9.1 | 未知键（`external/ghost`/`archetype/ghost`）→`APPROVAL_ARTIFACT_INVALID` @ `$`；`RealRunErrorCode` 十成员不变锚（零新增错误码） |
| `test_synthetic_key_loader_pins_upstream_per_descriptor` | FR-08/AC-4/R9.1（S1） | 合成键+描述子一致文档→通过；upstream 四钉逐项漂移→逐路径 `APPROVAL_ARTIFACT_INVALID`；approval_type/run_name 漂移→同拒（逐工件钉扎非九份入口） |
| `test_zero_budget_synthetic_keys_refuse_before_invoke` | FR-08/AC-4/R9.3(a)/R9.4④ | 九合成键×零预算文档（全维 0）→首 reserve fail-closed（`RUN_BUDGET_EXCEEDED` @ `$.budget.per_run.calls`）；chat/download 零调用；ledger calls==0/cost==0 逐维；证据五件套文件名==冻结五键（无新 approval 族文件） |
| `test_offline_full_chain_synthetic_key_with_fake_transport` | FR-08/AC-4/R9.3(b)/R9.5 | 合成键（archetype/application）+正预算测试文档+fake transport→10 attempts 全成功+报告写出；门禁同构锚：canary 五键、身份钉行为（未知 form 拒绝）、七维预算门（g2 形态复用） |
| `test_cold_reset_entry_reextracts_rebuilds_and_observes` | FR-07/AC-4/R8.1/R8.2/R8.3 | 构造 evaluator（g3/g4 直接构造先例）→attempt-0 全成功→`reset_cold_state()`：返回五键闭集；state_reuse==(T,F,T)+process_identity 恒同；timings extract int≥0/download None/attempt_wall int≥0；`snapshot_tree_sha256`==首次物化树摘要；`request_body_sha256`==首次请求体摘要；materialization_count 1→2；transport download_calls 不变（零 GET）；`_materialized/snapshot-cold-2` 新目录在场 |
| `test_cold_reset_repeat_deterministic_and_full_state_sequence` | FR-07/AC-4/R8.3 | 二次重置：摘要与首次重置恒等、目录 `snapshot-cold-3` 区别于 `snapshot-cold-2`、materialization_count 1→2→3；全序列断言：默认 run 的 records state_reuse==(T,F,T)+(F,T,F)×9 与重置观测 (T,F,T) 并存（"每 attempt 状态"探针） |
| `test_default_batch_unchanged_and_no_per_cold_dirs` | FR-07/AC-4/R8.1 | 默认入口 run：`_materialized` 下无 `snapshot-cold-*` 目录；attempt 序列/mode 序列/cold-warm 5-5/manifest 键集与 v5 冻结面一致（默认批次行为不变锚） |

(b) 类值更新（全部由 R9.2 驱动）：`_ENTRY_PARAM_ORDER`+`artifact_key`、`_ENTRY_KEYWORD_ONLY`+`artifact_key`；模块 docstring 追加 v6 演进段；新常量（`_ARTIFACT_FAMILY_KEYS`/`_SYNTHETIC_FAMILY_KEYS`/`_ZERO_BUDGET_FAMILY_VALUE`/`_COLD_RESET_KEYS`/`_PER_COLD_DIR_PATTERN`/派生复算辅助）纯增量。既有 66 断言零弱化。

### 9.4 A4：tests/test_v4_baseline_v5_negatives.py（新文件；≤12；定稿 9）

组织：四个类（TestHiddenCapProbes/TestHoldoutIdentityProbes/TestDisciplineProbes+共享 arrange 基类）。全离线、fake opener/内联树、零真实 sleep、不触网。逐方法：

| # | 方法 | 覆盖 | 断言面（冻结） |
| --- | --- | --- | --- |
| 1 | `test_scanner_face_inline_tree_no_fixed_finding_cap` | FR-03/AC-2/R6.2-①(a) | 内联 N=14 文件树（每文件一 `os.system` 惰性模式）→`RepositoryScanner(sast_mode="off").scan(RepositoryWorkspace(root))`→findings==N（N>6 且 >12）全保留、无 6/12 截断；findings 路径覆盖全部 14 文件 |
| 2 | `test_scanner_face_signal_storm_materialization_not_truncated` | FR-03/AC-2/R6.2-①(b) | 物化 signal-storm+docs-content+test-heavy→同一扫描面→findings==N（从物化树派生，N>12）全保留；taxonomy/复核计数无上限截断 |
| 3 | `test_runner_face_cap_is_request_construction_parameter` | FR-03/AC-2/R6.2-② | N=15 python 文件树→`_walk_python_files` 返回全部 15；`_select_candidate_texts` 恰取 12；`CANDIDATE_FILE_CAP==12` 数值钉扎（请求构造参数语义证明） |
| 4 | `test_holdout_identity_variants_keep_verdicts_and_metrics` | FR-04/AC-2/R6.3 | 三变体（改名/换路径/非语义元数据）经 `RealWorldSecurityEvaluator(SnapshotStore(root, opener=内存 zip))` deterministic run→逐 case 判定四元组与聚合 metrics 恒等；三变体均过 `load_real_world_dataset` 校验面；opener 仅内存 zip（零真实主机） |
| 5 | `test_holdout_identity_faces_differ_honestly` | FR-04/AC-2/R6.3 | 身份面可判伪结构：改名→dataset/dataset_sha256/manifest_sha256 皆变；顶层元数据→仅 manifest_sha256 变；case 级元数据→dataset_sha256 亦变；判定恒等（身份面如实不同、判定不受身份影响） |
| 6 | `test_pr3e_docs_in_repo_with_container_copy_lines` | FR-01/AC-5/R6.5 | A1/A2/A3 三 docs 在库；Dockerfile 含三条 COPY 行（a1 式）；Packet 承载 R1-R12 抽查 token |
| 7 | `test_zero_budget_artifact_naming_discipline_scan` | FR-08/AC-4/R9.4①②/R6.5 | `REAL_RUN_ARTIFACT_FAMILY` 每合成键：approval_type==`PR3E-OFFLINE-PROOF-ZERO-BUDGET` 且不含 "approval"（大小写不敏感）；run_name 含 offline-proof；族判别值无 api_key 通道（键集闭集断言） |
| 8 | `test_artifact_family_matches_fixture_registry` | FR-08/AC-4/R6.5 | 目录合成键集⊆注册表 13 键；每合成键 commit_sha==派生式复算（注册表 fingerprint，PC3） |
| 9 | `test_new_test_sources_offline_and_secretless` | NFR-02/R6.5/PC1 | 本文件源码：网络 import roots 零命中（socket/urllib/requests/http）、secret 形状零命中（sk-/AKIA/Bearer 形状探针+正例对照）；fake opener URL 断言=合成 codeload URL 形态 |

### 9.5 RED 形态（Modify 型 IP；产品已存在；逐文件独立归因）

对**未修改产品（1046501d 版）**运行四测试文件（C1 已落库后、C2 冻结前）：

- **M2**：新面缺席——schema v1（版本断言红）、三键不在（`_REPORT_FIELDS` 19≠16 红/KeyError）、from_mapping 不拒 v1（v1 探针红）、domain 块不被接线（measured 断言红/域块被当 unknown?——注意：现行 `_recognize_evaluator_payload` 对带 domain 的 payload 仍按形状识别（e2e/real-world 判定不看多余键），故识别通过而接线断言红）、专家包示例校验经现行校验器**通过**（R5.5 面向现行形状——按设计通过）。
- **M3**：signal-storm 键缺席（`SYNTHETIC_FIXTURE_KEYS` 11≠12 红；物化 UNKNOWN_FIXTURE_KEY 红）；注册表 12≠13 红。
- **M4**：工件参数/目录/cold 重置缺席（签名 8≠9 参数红；`REAL_RUN_ARTIFACT_FAMILY` getattr None 红；`reset_cold_state` 缺席红；零预算合成键路径红——现行 loader 拒合成文档于身份钉）。
- **A4 混合态**：扫描面内联探针/runner 面探针/holdout 两探针/自扫=**按设计通过**（守卫性断言，现行为即目标行为——如实归因）；docs 探针=C1 先落后通过；signal-storm 物化探针=RED（缺失 C3 交付物，UNKNOWN_FIXTURE_KEY）；工件族两探针=RED（缺失 C5 交付物，目录缺席）。
- 逐方法"RED 失败/按设计通过"归因表强制（归档于 `.pv_tmp/RED_IP-0036_2026-09-28/`）；基线态证明=C0（129/298/2650/24 全绿，Design Input #18）。

## 10. 冻结测试面演进程序（三个演进文件各自适用；CA R7 六条件全文；正式 Packet 级一次性授权）

**冲突裁定**：IP-0036 的产品语义变更（schema v2/fixture 第 12 键/工件族与 cold 重置）必然触碰 IP-0029/IP-0030/IP-0032..0035 冻结测试面 `tests/test_v4_baseline_report.py`、`tests/test_v4_baseline_fixtures.py`、`tests/test_v4_baseline_real_run.py`。**裁定：允许该三文件以受控方式分别演进至冻结版本 v2/演进版/v6**（先例=IP-0033/0034/0035 Packet §10）。演进是产品语义驱动（非机械缺陷），ALLOWED_ONCE 不适用、不得以其消化——授权依据=CA-IP-0036-v1.0 R7+本节。**演进依据=2026-09-28 第三轮 Maintainer 授权（#237 Scope 2/5/7/8）+DR-IP-0035-01 义务（§5.6 登记）。**

**演进六条件（每个演进文件独立适用；任一不满足=Stop Condition 7）**：

1. **对象唯一**：仅 M2/M3/M4 三文件各自一次+A4 新增一次；其余七个 v4 冻结测试文件（298 方法）与全部产品禁区模块 blob 逐字不变（Done Command 7 守护）。IP-0024..0031 冻结面=禁止。
2. **逐 hunk 归因**：每个 hunk 必须映射到 #237 FR-01..08/AC-1..5 之一或 CA 裁定编号（R2/R3/R7/R8/R9）并在 Packet 登记（§9 各表已登记：M2 新增→FR-02/FR-06/R2/R5.5；(b) 更新→R2.1/R2.2；M3 新增→FR-05/R3；(b) 更新→R3；M4 新增→FR-07/FR-08/R8/R9；(b) 更新→R9.2；A4→FR-01/FR-03/FR-04/FR-08/R6/R9.4）。
3. **禁止弱化**：既有断言不得删除或放松（fail-closed 门禁、泄露探针、hygiene、`__all__`/签名/数值守卫全部保留）；只允许 (a) 新增断言/方法、(b) 因显式登记的语义变更而更新的期望值。**本轮 (b) 类值更新清单（全部由 R2/R3/R9 裁定驱动，无一处为实现便利）**：M2——`_REPORT_FIELDS` 16→19、`_ALLOWED_DOC_STRINGS`+四词、`BASELINE_REPORT_SCHEMA_VERSION` 1→2、v1 拒绝探针 2→1；M3——`_EXPECTED_FILE_COUNTS`+signal-storm、11→12×2、12→13×2；M4——`_ENTRY_PARAM_ORDER`/`_ENTRY_KEYWORD_ONLY`+artifact_key。弱化判定争议 → Decision Request。
4. **版本链保留**：v1/v5 基线 blob（`b53176f5`/`34b397b7`/`d982bdd8`）与历史提交永久在链；Packet 记录基线与演进 blob（演进 blob 由 C2 冻结时登记于提交与验证记录）。
5. **RED 先于冻结**：C2 冻结前，四文件对未修改产品（1046501d 版）运行并留档 RED 证据（独立日志文件归档于 `.pv_tmp/RED_IP-0036_2026-09-28/`，每方法 traceback 可定位），逐方法登记"RED 失败/按设计通过"归因（§9.5）。
6. **角色纪律**：演进只在 C2 由 P&V 执行；Implementation 结构性零参与测试修改；C2 冻结提交后本 Assignment 的 ALLOWED_ONCE（§11）仅覆盖四文件面的机械缺陷（合计一次）。

**Pre-Freeze Harness Gate（冻结前必须全部通过；本 Packet 级强制）**：①四测试文件可完整 import 与 collect（零加载期错误）；②fixture/helper/参数组合经最小桩或现行产品执行到行为断言处（区分 fixture 缺陷与行为缺失——A4 的 UNKNOWN_FIXTURE_KEY/getattr-None 即行为缺失锚）；③Ruff `--no-cache` 在产品模块在场态运行通过（本叶产品模块已在库，A4 新 import 的 first-party 分类以在场态为准）；④临时桩（如有）位于临时目录且不入冻结提交；⑤RED 逐项归因于缺失产品行为。

**ER 复核面**：ER 将逐 hunk 复核三文件演进正当性（条件 2/3）、独立复跑 RED 归因、复核 §9 矩阵断言与 AC 映射。

## 11. ALLOWED_ONCE（一次性机械测试修正授权；CA §Mechanical Test Correction Allowance）

C2 冻结后，P&V 可在不新增 Coordinator 调用的情况下自行纠正**一次**纯测试机械缺陷并重新冻结（受影响冻结文件 v→v'），条件全部满足：①不改产品语义、公共接口、稳定错误码或文件范围（含 Dockerfile 行数）；②仅限 fixture/arrange/import/lint/测试基础设施缺陷；③旧 Frozen Commit 保留；④修正前缺陷证据（原始 traceback 独立日志）、修正后有效 RED、新 Frozen Commit 完整记录；⑤Implementation 未参与测试修改。涉及产品行为、验收语义或文件范围 → Decision Request；本授权与 §10 演进授权互不折抵、各仅一次（本叶 M2/M3/M4/A4 四文件面合计适用一次机械修正事件）。

## 12. Stop Conditions（触发即停并提交 Decision Request；CA R11 全文）

0. 派发前再核验失败：#237 正文/标签/远程状态与本地捕获不一致，或 Base SHA 上 main 出现冲突性实现（含 IP-0036 编号被占用）。
1. **任何真实网络/下载/付费调用（含分支上/CI 内/pre-merge"顺手验证"）——绝对禁令。**
2. 需要修改 budget.py/orchestrate.py/run.py/collect.py/expert_timing.py/offline_flow.py/`__init__.py`/七个冻结测试文件/`baseline_manifest.json`/`python_mvp_support_matrix.json`/`lima/**` 任何字节才能交付。
3. 需要放松任何 fail-closed 门禁/钉扎/既有断言/canary 五项/预算语义；需要 transport 注入契约偏离 4 参；需要新增 `RealRunErrorCode`/`BaselineReportErrorCode`/`BaselineFixtureErrorCode` 成员。
4. 需要通配仓库（非闭集工件目录）、默认联网、或任何"因测试方便"的门禁绕行（M5 明文）。
5. 需要触碰 Do Not Touch 路径、第 13 个变更文件、或 Dockerfile 超 3 行。
6. 方法数超预算（38/42/76/12）；298 回归/全量 discover 出现非预期失败；注册表再生字节不一致。
7. 六条件演进程序任一不满足，或出现"弱化既有断言才能通过"的 hunk；弱化判定争议→DR。
8. 授权文本与实现需求冲突（含本 Assignment 裁定与 Maintainer 授权原文语义矛盾、或裁定间互斥）——不得自行改写授权或裁定。
9. 需要新第三方依赖，或新 import 超出 Packet 登记白名单（§6：real_run+benchmarks.v4.baseline.fixtures；A4+lima 评估面与预登记项；新测试文件 import lima 评估面=已预登记），或非注入式外部输入/真实 sleep 驱动的测试。
10. 固定上限普查发现新的疑似隐藏处理上限，或证据/代码间新矛盾影响验收语义——记录并提交，不得静默。
11. 需要消耗 Maintainer 决策的任何事项（预算 ≤1，预期 0）。
12. **任何形态需要携带可用请求能力或 api_key 通道的零预算证明工件（I-2 硬边界），或任何具付费调用效力的新工件。**
13. cold 重置实现需要改 state_reuse/provider_cache/timings 键集、RunSpec、或结算/预算策略（G5 键集不变路径不成立）→ M9 DR。
14. V5 schema 演进需要触碰 counts 7 键/sidecar 5 键/错误码族，或 schema v2 需要 v1/v2 双解析宽容（破坏 fail-closed 版本化）。
15. R1 单叶边界被证明不可行（如 real_run 演进引发跨文件连锁回归超出预算）→ 拆分决策归 Maintainer，不得自行拆叶。
16. 需要吞噬/转换/延迟重抛 BaseException（IP-0035 R4.3 延续）或丢弃证据。

## 13. Done Commands（worktree 根执行；Windows 设 `PYTHONUTF8=1`；成功判据=全绿/为空/恰 4 Add+8 Modify/blob 不变/ancestry exit 0）

```bash
# 0. 预冻结基线（C2 之前登记；本轮已执行并归档 .pv_tmp/RED_IP-0036_2026-09-28/baseline.txt）：
#    三冻结测试文件 129/129 绿；九冻结文件 298/298 绿；全量 discover 2650 OK (skipped=24)
#    （与 CA 参照值逐项一致，@1046501d 本 P&V 会话亲跑）
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_report tests.test_v4_baseline_fixtures tests.test_v4_baseline_real_run -v
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline tests.test_v4_baseline_budget tests.test_v4_baseline_cli tests.test_v4_baseline_collection tests.test_v4_baseline_manifest tests.test_v4_baseline_offline_flow tests.test_v4_baseline_result
PYTHONUTF8=1 python -m unittest discover -s tests
# 0b. RED 证据（C2 冻结前，对未修改产品 @1046501d）：独立日志归档
#     （.pv_tmp/RED_IP-0036_2026-09-28/）+ 逐文件逐方法归因表（R7；M2/M3/M4 分别 RED 归因；
#     A4 混合态逐方法"RED 失败/按设计通过"）
# 1. 定向四文件（C2 冻结时按设计 RED 且逐方法归因；C-final 后全绿；≤38/≤42/≤76/≤12 方法）
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_report tests.test_v4_baseline_fixtures tests.test_v4_baseline_real_run tests.test_v4_baseline_v5_negatives -v
# 2. 七冻结文件回归（298 必须全绿）
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline tests.test_v4_baseline_budget tests.test_v4_baseline_cli tests.test_v4_baseline_collection tests.test_v4_baseline_manifest tests.test_v4_baseline_offline_flow tests.test_v4_baseline_result
# 3. 全量 discover 回归（绿；skipped 集与基线 2650/24 一致；CI 零付费断言延续）
PYTHONUTF8=1 python -m unittest discover -s tests
# 4. 字节编译；5. ruff（--no-cache；bandit 选做，如实登记）
PYTHONUTF8=1 python -m compileall -q benchmarks tests
PYTHONUTF8=1 python -m ruff check --no-cache benchmarks/v4/baseline/fixtures.py benchmarks/v4/baseline/report.py benchmarks/v4/baseline/real_run.py tests/test_v4_baseline_report.py tests/test_v4_baseline_fixtures.py tests/test_v4_baseline_real_run.py tests/test_v4_baseline_v5_negatives.py
# 6. diff 守护：恰 4 Add（Packet/矩阵 v2/专家包/新测试文件）+ 8 Modify（Dockerfile/fixtures/
#    fixture_registry.json/report/real_run/三测试文件）；Dockerfile diff 恰 +3 行
git diff --name-status 10465010de05a759c339a491531707ff6e6619dc...HEAD
git diff 10465010de05a759c339a491531707ff6e6619dc...HEAD -- Dockerfile   # 恰 +3 行
# 7. blob 守护：budget(6c783848)/orchestrate(8655067e)/collect(063ecb41)/run(d29928e5)/
#    expert_timing(dd7aa365)/offline_flow(0f2916c8)/__init__(1c478346) + 七冻结测试文件
#    (4cde7bdf/edd4c62b/edb2391b/35e6ec6a/8e8ab0dc/539d2fb3/0a44cf7d)
#    + baseline_manifest.json(7ecb39f8)/python_mvp_support_matrix.json(3ea94fcf) + lima/** 与基线一致；
#    report(3615a75d)/fixtures(0e4fb11f)/real_run(0d6db453)/registry(493f3da5)/
#    test_report(b53176f5)/test_fixtures(34b397b7)/test_real_run(d982bdd8)/Dockerfile(fcade9c9)
#    登记为"演进文件"（从 blob 记录在案，至 blob 由 C2/C3/C4/C5 登记）
git ls-tree 10465010de05a759c339a491531707ff6e6619dc -- <守护清单> 与 HEAD 对比
# 8. ancestry：1046501d → C1 → C2(冻结) → C3 → C4 → C5 各段 merge-base --is-ancestor exit 0
# 9. 零预算证明留痕：各合成工件键的拒付证据摘要（calls=0/cost=0/零传输调用）+
#    cold 重置探针产物摘要（state_reuse 序列/树摘要恒等/请求体恒等/extract 实测/download None）
#    + holdout 三变体判定恒等对照，登记于 Completion Summary
# 10. 注册表再生守护：python -c 调 write_registry(tempdir) 与
#     evaluation_data/v4/fixture_registry.json 逐字节一致（13 条目）
git status --porcelain evaluation_data/   # 除 fixture_registry.json 外零改动
```

PC1-PC3 标配（IP-0033/0034/0035 同款）：PC1 测试源 secret-token/网络-token 拼接扫描（A4 fake opener 零真实主机；A4 方法 9 承载）；PC2 arrange 经冻结校验器（探针 dataset/payload/spec 经 `load_real_world_dataset`/`spec_from_mapping`/`validate_baseline_manifest` 等同源构造——A4 方法 4 与 M4 既有 arrange 复用）；PC3 派生数值断言（signal-storm 期望 N 从物化树派生、合成 commit_sha 按冻结派生式复算、cold 重置摘要以关系断言复算、holdout 身份面以 canonical 复算——不硬抄实现值）。

## 14. PR 与 Completion Summary 契约（CA §Handoff）

- PR：单 PR `codex/ip-0036-pr3e-offline` → main；标题禁 close 族关键词与编号组合（含否定句）；正文含 Final SHA、变更文件清单（恰 4 Add+8 Modify）、Done Commands 实际输出摘要（0/0b+1-10）、满足/不满足/未验证逐条、下一责任人（P&V C-final → ER → Coordinator 合并判定）；合并/推送/评论由主会话按 Maintainer 授权执行，P&V/IMPL 零远端写；PR 必须写明 "This PR does not auto-close the Source Issue." 与 "Related to #237."（仅此关联形式；不得关联关闭 #57）。提交前缀 `[IP-0036][PV]`/`[IP-0036][IMPL]`/`[IP-0036][CI]`；C-final 后修复提交必须引用 Stop/DR/ALLOWED_ONCE 编号；实现提交以 C2 冻结提交为祖先（Done Command 8）。
- Completion Summary 必含：FR-01..08 逐条证据索引（测试 ID）、AC-1..5 判定、四文件 blob 演进记录与 C1/C2/C3/C4/C5 提交 SHA、RED 归档路径与逐方法归因计数、C0 基线实际值（129/298/2650/24）、零真实调用声明、Dockerfile 恰 +3 行证明、零预算拒付面证据摘要（九键 calls=0/cost=0/零传输）、cold 重置探针产物摘要（state_reuse 序列/树摘要恒等/请求体恒等/extract 实测/download None/materialization_count）、holdout 三变体判定恒等对照、K1-K6 已知缺口状态。

## 15. 范围裁定 R1-R12 转录（CA-IP-0036-v1.0 决定性内容）

- **R1（文件拓扑终形）**：单叶单 PR，不拆 0036a/0036b。Allowed Files 终形=恰 4 Add+8 Modify（§5 表）；零 Delete。裁定依据：#237 是一个集成切片（Scope 1-8 互为门禁面：AC-5 矩阵 v2 必须引用全部面的最终状态）；两半文件集零重叠；Maintainer 第三轮授权与 Intent Record 均以单载体框定；拆叶使治理周期翻倍而不降低冻结面风险。被否决替代方案（不得重试）：IP-0036a/IP-0036b 双叶；若 R1 边界被证明不可行 → Stop 15 提 DR 由 Maintainer 决定拆分。历史文档冲突处置沿用 IP-0033 §5.6 先例（§5.6）。
- **R2（V5 报告 schema 终形）**：①`vep`/`rvr`/`stage_outcome` 为三个 additive 顶层字段（非 counts 内新键——counts 是 7 键闭集）；vep/rvr 沿用 `{value, projection}` 三值形态；stage_outcome 为冻结三键映射，值域闭集词表（Packet 定稿=§7.1.1 词表；无来源 None+unavailable）；`_REPORT_FIELDS` 16→19；`to_canonical_value`/`from_mapping`/严格校验同步演进。②`BASELINE_REPORT_SCHEMA_VERSION` 1→2；v1 fail-closed（既有码，零新增）；两批真实运行报告为终态产物无重读路径（K1）；`BASELINE_REPORT_DECLARATIONS` 与错误码族逐字不动。③来源接线（规则冻结）：real-world v2 payload 可选 `domain` 子块（冻结键集 signals/security_issues/hypotheses/vep/rvr 各 exact int ≥0、stage_outcome 三键闭集词表、可选 resources 三键 exact int ≥0）；在场必须合规（违规=`EVALUATOR_PAYLOAD_INVALID` fail-closed）；合规→measured（覆盖 real-world+e2e 路径当前 unavailable；resources 三字段由 domain.resources 接线，形状不变）；缺席→null+unavailable；scanner 派生面与其余投影不变；coverage_gap_reasons 语义保持文件级 skip 专用（§7.1.1-3 映射登记）。④collect.py 零字节（I-8 事实校正采纳）。⑤测试面：v1→v2 演进（R7 六条件；≤38=29+≤9）；新增必含清单（§9.1 全落位）。
- **R3（signal-storm fixture 终形）**：第 12 合成 archetype（注册表第 13 条目）：①确定性生成器（纯索引函数，无随机/时钟/网络）；②形态=大量低价值 signal（N>12 且模式位点数 >12，为 R6 上限负例提供原料；每文件 SYNTHETIC INERT 头，先例=malicious-layout）；③全 ASCII/LF、字节 ≤262144、无 URL、无真实身份 token；④`SYNTHETIC_FIXTURE_KEYS` 11→12、`_SYNTHETIC_NOTES`+1、`_build_shapes`+1；⑤`_RELATIONSHIP_TO_SUPPORT_MATRIX` 只允许 additive 一句（既有句零删除）；⑥注册表恰由 `write_registry()` 再生成（schema_version=1 不变；Done Command 10 守护）。测试面 34→≤42（§9.2 落位）。
- **R4（矩阵 v2 终形）**：载体=`docs/LIMA_PR3e_Requirement_Matrix_v2.md`+Dockerfile COPY。六列（冻结）：`要求 | 状态(已证实/部分/未证实) | 证据指针 | 完成门禁（可机械检查判据） | 未闭环缺口与真实运行/人工依赖 | 承接（IP/PR/工件）`。五类目标行：#57 原生 FR/NFR/AC、V5-FR-01..05、V5-AC/T-01..03。行集以 issuecomment-5867392527 两表为基线逐行移植并更新（IP-0036 交付使 V5-FR-03/04、V5-AC/T-01(schema 面)/02/03 的离线可验证部分转为已证实；真实运行/人工依赖列如实保留未闭环项）。锚行必含：空仓/最小仓/LlamaFactory 固定 SHA/repository-disjoint 标注样本（popular external holdout v2）/九类 archetype/signal-storm。完成门禁列=可机械检查判据（N5）；R6.3 普查表结论入矩阵（披露有界参数行）；矩阵不得宣称未验证状态（AC-5"与实现一致"）。
- **R5（来源接线+专家复核包）**：①来源接线规则见 R2.3（唯一权威表述处；Packet §7.1.1-3 全文转录）。原始候选/压缩队列：现状已接线（real-world total_findings→raw_candidates；压缩链比率），v2 测试加断言钉扎即可，无产品变更。②专家复核包（docs，P&V C1）：真人流程（开始/暂停/恢复/结束，ns 时间戳→ExpertTimingSession）→sidecar（5 键；reviewer 身份只以 SHA-256 摘要出现）；逐字段表；示例 sidecar（完整 JSON）必须字面通过 report 现行 `_gate_sidecar`/`_validate_sidecar_artifact` 冻结形状校验——验收面=M2 新增测试解析包内示例并断言通过（双承载）；与 report.py 冻结形状校验兼容性说明（本叶不触碰 `_SIDECAR_FIELDS`——sidecar schema 零变更）；缺席纪律（无真人事件→sessions=0/active_time_ms_total=None；不得以模型调用或合成事件填充）；包不含 api_key/付费通道；本叶零真人事件（K4）。
- **R6（负例双探针终形）**：①载体=新测试文件（≤12 方法；全离线；fake opener/注入源；零真实 sleep；不触网）。②探针一（固定上限不存在）双面：审查/扫描面（生产纯函数判定路径）物化 signal-storm+docs-content+test-heavy→`RepositoryScanner.scan(RepositoryWorkspace(root))`→断言 findings=预期 N（N>6 且 >12）全保留、无"固定 6 条"式截断、taxonomy/复核计数无上限截断；runner triage 面：`_walk_python_files` 于 N>12 树返回全部 N；`_select_candidate_texts` 恰取 12→证明 12 是请求构造参数非处理上限；报告压缩链 raw_candidates 于 N>12 totals 无截断。③探针二（holdout 身份无关性）三形态：`RealWorldSecurityEvaluator`（deterministic；`SnapshotStore(root, opener=fake)` 注入内存 zip/预置缓存，零网络）跑同一语义内容三身份变体（改名/换路径/非语义元数据）→逐 case 判定与聚合 metrics 恒等，身份面如实不同；identity 消费点限于校验/去重/获取键/呈报（load 校验面与 spec↔manifest 绑定 fail-closed 是校验面非产品判断条件——矩阵如实登记）。④固定上限普查与如实登记（Packet 必载=§7.6，矩阵承接）：披露有界参数 vs 隐藏上限（普查结论=不存在"固定 6 条"式未披露上限；新疑似→Stop 10）。⑤纪律符合性探针（同文件承载）：三 docs 在库+Dockerfile 三 COPY 行；零预算工件命名纪律机械扫描；工件族目录↔注册表一致性；新源码 secret/网络 token 扫描（PC1）。
- **R7（测试面演进程序）**：三冻结文件+1 新文件，全部沿用六条件程序（对象唯一【恰四文件面】/逐 hunk 归因/禁弱化【(b) 类值更新全部由 R2-R9 驱动】/版本链保留/RED 先于冻结且逐文件独立归因/角色纪律——演进只在 C2 由 P&V 执行）。方法预算：≤38/≤42/≤76/≤12（合计 ≤168；基线 129）。RED 形态逐文件归因（M2=新面缺席；M3=键缺席/12≠13；M4=工件参数/目录/cold 缺席；A4=混合态——逐方法归因表强制）。
- **R8（cold 重置/warm 复用程序终形）**：①语义（冻结）：cold=从已缓存 tarball 重新解包（新 per-cold snapshot 目录或等价可验证重置物化）+重建请求体；download 仅首次（重置零 GET 零下载字节）；warm=现状明确复用。产品默认批次行为不变——重置以可独立调用入口交付（Packet 冻结符号名与签名=§7.5.2）；未来真实批按 DR-IP-0035-01 结构调用。否决"改为默认批次行为"。②观测面（G5 键集不变路径）：重置 attempt state_reuse=(T,F,T)——四键集零变化；timings 如实（extract int≥0、download_ms=None、attempt_wall 实测）；不新增任何键。真实 cold 计数=物化重置次数——计数规则由 Packet 冻结为规范性契约（§7.5.2）。③离线探针（M4 承载=§9.3）。④键集边界：本路径无需 Maintainer 决策；改键集/RunSpec/结算 → Stop 13+M9 DR。
- **R9（入口泛化与工件族终形）**：①参数化工件描述：冻结工件族目录（closed dict，10 键=九合成+external/llamafactory-replay）。llamafactory 描述子=现行四钉+文档身份钉逐字；合成描述子一次性定稿冻结（repository slug lima-synth/<archetype> ASCII、requested_name 同、commit_sha=由 fixture 树指纹确定性派生的 40-hex（Packet 冻结派生式=§7.4.1 并明示"非 git commit"）、tarball_url=RFC 2606 .invalid URL（永不 fetchable，披露）、tarball 目标文件名模板（llamafactory 键与现状逐字节一致））。逐工件钉扎校验（loader 按所选描述子校验 upstream 四钉与文档身份钉——S1 非复制九份入口）；共享钉不变。未知 key→既有 `APPROVAL_ARTIFACT_INVALID`+structure-only field_path（零新增错误码）。②入口参数化：`run_real_baseline_suite` 新增恰一个 kw-only 参数（工件键；默认=external/llamafactory-replay——默认路径全部现行行为逐字节保持；签名演进登记于 Packet §5.6 同构节）。③零预算离线证明（AC-4 验收分解）：(a) 零预算工件拒付面（每合成键零预算文档→首 reserve fail-closed→calls=0/cost=0、零传输；如实部分链不作全链宣称）；(b) 离线全链面（fake transport+测试构造预算工件证明物化→重置→观测面全链）。④零预算工件命名纪律（S2；机械判据清单入 Packet=§7.4.4 五条）：①禁 Approval 字样（族判别值 PR3E-OFFLINE-PROOF-ZERO-BUDGET 形态；冻结证据五件套文件名不改——approval.json 承载被加载输入文档逐字记录，其族判别值即为区隔，Packet 如实登记）；②offline-proof 显式标记；③文档内无 api_key 通道（入口 api_key 参数为冻结签名，零预算运行中永不被使用——注入面证明零传输调用）；④calls=0/cost=0 逐维断言；⑤CI 断言零付费模型请求（NFR-02 延续+新探针）。任何形态需携带可用请求能力或 api_key 通道→Stop 12（I-2 硬边界）。⑤门禁零放松逐项断言（M4/A4 承载）。
- **R10（Done Commands）**：§13（0/0b+1-10）。
- **R11（Stop Conditions 与 ALLOWED_ONCE）**：§12（0-16）/§11。
- **R12（升级条款）**：Implementation 出现跨冻结模块语义约束、同一根因两轮有新证据修复仍失败、疑似规格矛盾 → 停止并提交 DR；如裁定升级目标档位 `glm-5.3 / max`，实际切换须新建/重新配置会话并取得 SESSION-RUNTIME-VERIFIED（派发文本声明不构成运行切换），文件边界/测试冻结/验收标准不变。

## 16. Decision Record（P&V 定稿决策；CA 授权范围内的冻结裁量）

| # | 决策 | 时间 | 依据 |
| --- | --- | --- | --- |
| DR-IP-0036-PV-1 | `stage_outcome` 值域闭集词表定稿为 `("completed", "skipped", "failed", "inconclusive")`（三阶段共用；completed=运行至终态/skipped=显式未配置未执行/failed=运行且失败终态/inconclusive=运行但无可判定终态）；域块在场时三键必须全为词表串，缺席承载由报告层 None+unavailable 表达 | 2026-09-28 | R2.1"值域为 Packet 定稿冻结的闭集词表"；最小可判定 ASCII snake_case 词表；M2 词表校验断言可机械执行 |
| DR-IP-0036-PV-2 | domain 块接线优先级：`EvidenceDomainBundle` 在场时 signals/security_issues/hypotheses 保持 bundle 派生（更完整证据域源）；vep/rvr/stage_outcome/resources 恒以 domain 为唯一来源；domain 块在 e2e v1 与 real-world v2 两种 recognized dict payload 上同等接线（R2.3"覆盖 real-world+e2e 路径"的字面承载） | 2026-09-28 | R2.3；确定性优先级防多解；scanner 路径不受影响（对象形态 payload 无 domain） |
| DR-IP-0036-PV-3 | 工件族目录符号=模块级公开常量 `REAL_RUN_ARTIFACT_FAMILY`（closed dict，10 键）；描述子七键闭集（repository/requested_name/commit_sha/tarball_url/tarball_filename/approval_type/run_name）；**不入 `__all__`**（六符号逐字冻结；测试经模块属性访问） | 2026-09-28 | R9.1"closed dict，10 键"+"新入口符号是否入 __all__ 由 Packet 定稿并登记"；最小公共面扩张 |
| DR-IP-0036-PV-4 | 合成描述子 commit_sha 派生式冻结：`sha256(("lima-synth-artifact:"+key+":"+registry_fingerprint).encode())[:40]`（key=fixture 键；registry_fingerprint=注册表条目 64-hex fingerprint；文档明示非 git commit） | 2026-09-28 | R9.1"由 fixture 树指纹确定性派生的 40-hex（Packet 冻结派生式）"；PC3 可复算 |
| DR-IP-0036-PV-5 | 入口参数名冻结 `artifact_key: str = "external/llamafactory-replay"`（kw-only，追加于签名末位） | 2026-09-28 | R9.2"恰一个 kw-only 参数（工件键；默认=external/llamafactory-replay）"；末位追加使既有参数序零变化 |
| DR-IP-0036-PV-6 | cold 重置入口冻结为 `_GuardedRealEvaluator.reset_cold_state(self) -> dict[str, object]`（公开方法形态；类名不重命名）；返回观测文档恰五键（state_reuse 四键/timings 三键/snapshot_tree_sha256/request_body_sha256/materialization_count）；per-cold 目录命名 `_materialized/snapshot-cold-{n}`（n=重置后 materialization_count；初始物化=现行 `_materialized/snapshot` 逐字保持）；真实 cold 计数=materialization_count（初始 1+重置次数） | 2026-09-28 | R8.1"可独立调用入口（建议模块级函数或 evaluator 公开方法形态）"+R8.2 计数规则"由 Packet 冻结为规范性契约"；evaluator 持有全部重置所需状态（tarball/snapshot/body/clock）；G5 键集不变路径 |
| DR-IP-0036-PV-7 | signal-storm 形状语义冻结：N 个 .py 模式文件（N>12，具体值由 Implementation 一次定稿；测试从物化树派生期望），每文件恰一个 `os.system(...)` 形态惰性命令注入位点（常量良性参数、CWE-78 可判定）+SYNTHETIC INERT 头；纯索引生成；总字节 ≤262144 | 2026-09-28 | R3.2"大量低价值 signal（N 个惰性模式文件，N>12 且模式位点数 >12…每文件带 SYNTHETIC INERT 头）"；常量参数排除数据流次级发现，使 findings==N 可判定（R6.2 探针可机械断言） |
| DR-IP-0036-PV-8 | A4 扫描面探针拆双方法：内联树守卫探针（零 fixture 依赖——现行为按设计通过，证明当前产品无隐藏上限）+signal-storm 物化探针（依赖 C3 交付——RED 归因"缺失交付物"）；runner 面与 holdout 探针为守卫性断言（按设计通过） | 2026-09-28 | R7"A4=混合态（扫描面/holdout 现行为按设计通过）"+R6.2 物化 signal-storm 要求；本拆分使"现行为守卫"与"交付物验收"两个断言面各自可归因 |
| DR-IP-0036-PV-9 | real_run.py 获准唯一新 import=`benchmarks.v4.baseline.fixtures`（公共符号 `load_registry`/`compute_tree_fingerprint`；用途=工件族 commit_sha 派生与 cold 重置观测树摘要）；`reset_cold_state` 观测的树摘要复用冻结算法 `compute_tree_fingerprint`（不另行实现避免算法漂移） | 2026-09-28 | R9.1 派生式需注册表指纹；R8.3"树摘要与原物化一致"需同一冻结算法；§6 import 白名单登记 |
| DR-IP-0036-PV-10 | 矩阵 v2 六列采用 CA R4 冻结列序（要求/状态/证据指针/完成门禁/未闭环缺口与真实运行人工依赖/承接）；状态列以本叶 Done Commands 全绿（合并门）为"已证实"的时点口径，依赖真实运行/人工专家的行保持 部分/未证实（K6） | 2026-09-28 | R4 六列冻结原文；AC-5"与实现一致（无未验证宣称）"；K6 |

（无未决 DR。）

## 17. 已知缺口（不阻塞本 Packet；CA K1-K6 同构登记）

- **K1** 两批真实运行的 v1 报告文件在 schema v2 严格解析下 fail-closed（诚实版本化；报告为终态产物，无重读消费方——Coordinator 亲验 grep 零重读路径）；不迁移不改写。
- **K2** 披露有界参数（semantic_retrieval 证据包 `[:5]`、`MAX_UAF_TRANSLATION_UNITS=16`、全部 runner cap 常量）保持零改动，矩阵 v2 登记边界行（§7.6 表 A）；修改其语义=另行决策。
- **K3** 真实批次的 cold attempt 结算策略（重置 attempt 的估计/结算差异）归决策包 v4/未来真实批 DR；本叶重置入口不触结算。
- **K4** 本叶零真人专家事件（专家分钟缺席纪律保持）；专家包交付=流程可用性而非执行证据。
- **K5** holdout 探针覆盖 deterministic 模式判定面；llm/llm-retrieval 模式的身份无关性由"判定面共享同一 scan/matching 路径"论证承载（本 Packet §8.2 记载），不逐模式注入。
- **K6** 矩阵 v2 中依赖真实运行/人工专家的行保持 部分/未证实（不因离线叶闭合计为完成）。
