# LIMA PR3-e Requirement Matrix v2（#57 × V5 × #237 离线集成逐行矩阵）

- 文档类型：需求级逐行矩阵（Requirement Matrix v2）。
- 版本：v2.0（2026-09-28；取代 #57 issuecomment-5867392527 的两表口径——该评论保留为历史证据，本文为其 v2 升级载体）。
- 承接：#237 / IP-0036（Packet：`docs/LIMA_Implementation_Packet_IP-0036_PR3e_Offline_Integration.md`）；parent #57 保持 open，PR3 不勾选。
- 行集基线：issuecomment-5867392527 两表（#57 原生 FR/NFR/AC + V5-FR-01..05/V5-AC/T-01..03）逐行移植并按 IP-0036 交付更新。
- 状态口径：已证实=有测试/实测证据；部分=有结构无完整证据；未证实=无证据或能力缺席。**状态时点=本叶 Done Commands 全绿（合并门；DR-IP-0036-PV-10）**；依赖真实运行/人工专家的行保持部分/未证实，不因离线叶闭合计为完成（K6）。
- 完成门禁列=可机械检查判据（N5）：每格给出可由命令复现的判据（测试模块/命令/blob 守护），不含人工裁量。
- 全部证据均零真实调用取得（离线注入式：fake transport/fake opener/预置缓存/注入 clock）；CI 永远零付费模型请求（NFR-02）。

## 1. #57 原生要求（FR/NFR/AC）

| 要求 | 状态 | 证据指针 | 完成门禁（可机械检查判据） | 未闭环缺口与真实运行/人工依赖 | 承接（IP/PR/工件） |
|---|---|---|---|---|---|
| FR-01 RunSpec 冻结/校验/canonical | 已证实 | T-01+298 面 | `tests.test_v4_baseline_manifest` 全绿（298 回归 Done Command 2） | — | IP-0026/#210 |
| FR-02 独立 CLI/失败 taxonomy | 部分（CLI 接线已证；真实失败样本仅 2 批各 1 形态） | IP-0031 离线+IP-0032/0034 两批终局样本 | `tests.test_v4_baseline_cli` 全绿；taxonomy 断言面（test_real_run 检查点族）全绿 | 真实失败多样性（真实批次） | IP-0031/#221；批次证据两目录 |
| FR-03 ≥3c/≥5w+nearest-rank+insufficient_sample | 部分（12 候选文件负载上 5c+5w success 达标；cold 语义政策=DR-IP-0035-01 已裁定带硬条件） | 2026-09-28 批（cold p50 1640/p95 2094ms；warm 1328/1406）；DR-IP-0035-01 裁定记录 | `tests.test_v4_baseline_real_run`（v6）ho1/tg 族全绿；cold 计数规则=materialization_count（Packet §7.5.2） | 各评测路径样本；未来真实批"每类 3 次可验证 cold+5 warm"（决策包 v4 批结构，主会话） | IP-0034/#232；IP-0036（cold 重置程序）；EXECUTION_CREDENTIALS 文件 |
| FR-04 计数/压缩率/legacy projection | 部分（压缩链 raw_candidates 已载；Signal/Issue/Hypothesis 来源接线=IP-0036 domain 域块离线已证；真实检测计数未取得） | IP-0029 报告面；IP-0036 M2 新增（domain 接线三态） | `tests.test_v4_baseline_report`（v2）全绿（domain measured/unavailable/fail-closed 三态断言） | 真实检测计数（真实批次；domain 域块真实值） | IP-0029/#217；IP-0036/#237 |
| FR-05 专家计时协议 | 部分（sidecar 协议+ExpertFace 聚合已实现；真实 sessions=0 缺席如实；专家复核包=IP-0036 交付） | IP-0027/#212；IP-0036 专家包文档+M2 示例校验 | `docs/LIMA_PR3e_Expert_Review_Package.md` 在库；M2 `test_expert_package_example_sidecar_passes_frozen_validators` 全绿；`tests.test_v4_baseline_collection`（IP-0027 面）全绿 | 真实评审事件（**人工专家必需**：开始/暂停/结束+reviewer 摘要） | IP-0027/#212；IP-0036/#237 |
| FR-06 四类仓库+manifest 许可/来源/角色/digest | 部分（空/最小/外部 holdout+LlamaFactory 物化已证；repository-disjoint 已标注样本集=popular external holdout v2；身份无关性负例=IP-0036 A4 离线已证） | IP-0026/0030；IP-0036 A4 探针二 | `tests.test_v4_baseline_manifest` 全绿；`tests.test_v4_baseline_v5_negatives` holdout 两探针全绿 | popular external holdout v2 真实评测运行 | IP-0026/#210、IP-0030/#219、IP-0036/#237 |
| NFR-01 canonical 字节一致 | 已证实 | T-01 | `tests.test_v4_baseline`（canonical 稳定断言）全绿 | — | 同 FR-01 |
| NFR-02 CI 离线无 Secret 零付费 | 已证实 | 全链 CI 绿+探针；IP-0036 A4 方法 9（新源离线/无 secret 自扫） | `python -m unittest discover -s tests` 全绿（skipped=24 基线集）；A4 自扫探针全绿 | 手动真实批次=有预算门（另行授权） | IP-0031/0032/0034；IP-0036/#237 |
| AC-01 两次执行 identity/digest 一致 | 已证实 | T-01 | `tests.test_v4_baseline`（两次执行一致性断言）全绿 | — | 同上 |
| AC-02 manifest 负例 fail-closed | 已证实 | T-02 矩阵 | `tests.test_v4_baseline_manifest` 负例矩阵全绿 | — | IP-0026 |
| AC-03 全要素报告回指 RunResult digest | 部分（报告模板/schema 面=IP-0036 v2 已证：VEP/RVR/stage_outcome/专家/资源面全部在场且 null 纪律正确；12 文件 bounded-triage 数字不冒充——raw_candidates 语义钉扎） | 2026-09-28 批 run 级证据；IP-0036 M2（schema v2 全文件） | `tests.test_v4_baseline_report`（v2）全绿（三新面+null 纪律+roundtrip）；`tests.test_v4_baseline_result` 全绿 | 真实批+真实评审（原始候选 vs 压缩队列对照、专家分钟、资源成本完整模板的真实值） | PR3-e 真实叶（后续授权）；IP-0036/#237 |

## 2. V5 规范性覆盖层

| 要求 | 状态 | 证据指针 | 完成门禁（可机械检查判据） | 未闭环缺口与真实运行/人工依赖 | 承接 |
|---|---|---|---|---|---|
| V5-FR-01 九类 archetype fixture | 部分（11→12 fixture 全部在库：九类+empty/minimal+signal-storm（IP-0036）；物化/结构/报告接线离线已证；九类离线全链=IP-0036 M4 工件族+fake transport 已证） | fixture_registry（13 条目）+IP-0030 298 面+IP-0036 M3/A4/M4 | `tests.test_v4_baseline_fixtures` 全绿（13 键闭集/字节一致）；`tests.test_v4_baseline_v5_negatives` 探针全绿；`tests.test_v4_baseline_real_run`（v6）合成键全链探针全绿；Done Command 10（write_registry 字节一致） | 九类真实验收（真实批次，另行授权） | IP-0030/#219；IP-0036/#237 |
| V5-FR-02 外部公开仓库只作 holdout | 部分（popular external holdout v2 数据角色冻结；**产品行为身份无关性=IP-0036 A4 探针二离线已证**：改名/换路径/非语义元数据三形态判定与聚合恒等、身份面如实不同） | manifest 角色；IP-0036 A4 holdout 两探针 | `tests.test_v4_baseline_v5_negatives` holdout 两探针全绿（三变体判定恒等+身份面差异断言） | popular holdout v2 真实评测运行 | IP-0026（角色）；IP-0036/#237（负例） |
| V5-FR-03 指标分 Signal/Issue/Hypothesis/VEP/RVR/terminal outcome | 部分（**离线可验证部分已证实**：schema v2 vep/rvr/stage_outcome 三 additive 顶层字段+schema_version 2+domain 域块来源接线（measured/unavailable/fail-closed 三态）——M2 全文件证据；真实值未取得） | IP-0036 M2（v2 演进+9 新增方法）；#237 Scope 2 | `tests.test_v4_baseline_report`（v2）全绿：三新面在场/null 纪律/domain 三态/resources 接线/v1 fail-closed/词表闭集 | 真实指标值（真实批次 domain 域块真实内容） | IP-0036/#237 |
| V5-FR-04 needs-review 按 root-cause 统计；固定 6 条=失败 | 部分（**离线可验证部分已证实**：固定上限不存在双探针——扫描面 N>6/>12 全保留（内联守卫+signal-storm 物化）+runner 面 CANDIDATE_FILE_CAP=12 证明为请求构造参数+普查表零隐藏上限；生产 audit 队列真实行为未验证） | IP-0036 A4 探针一（三方法）+Packet §7.6 普查表 | `tests.test_v4_baseline_v5_negatives` 探针一三方法全绿（findings==N 无截断/walk 全量/select 恰 12/数值钉扎） | 队列真实行为（真实批次 needs-review root-cause 统计） | IP-0036/#237 |
| V5-FR-05 immutable before baseline | 部分（2026-09-27 失败批+2026-09-28 成功批证据已不可变封存+凭据（sha256 d10d04b0）；"作为对比基线的正式封存声明"未做） | 两批目录+EXECUTION_CREDENTIALS | 封存声明可离线（后续叶）；本轮无代码门禁 | — | PR3-e 收口（后续） |
| V5-AC-01/T-01 九类 cold/warm 全指标输出 | 部分（**schema 面已证实**：v2 报告三新面+timings/state_reuse 观测面+工件族 10 键离线全链（M4）；九类真实 cold/warm 未运行） | IP-0036 M2/M4；IP-0035 ho 族 | `tests.test_v4_baseline_report`（v2）+`tests.test_v4_baseline_real_run`（v6）全绿；cold 重置探针（reset/state_reuse 全序列/零 GET）全绿 | 九类真实（真实批次）；**人工专家（分钟数）** | IP-0036/#237；PR3-e 真实叶 |
| V5-AC-02/T-02 文档型/test-heavy/signal-storm 无固定复核上限 | **已证实**（负例探针交付且全绿：内联树 N=14 守卫+signal-storm 物化（N>12）扫描面全保留+runner 面 cap 语义证明；该要求离线可验证部分=全部） | IP-0036 A4 探针一（方法 1/2/3） | `tests.test_v4_baseline_v5_negatives` 探针一三方法全绿（findings==预期 N、>6、>12、无 6/12 截断） | — | IP-0036/#237 |
| V5-AC-03/T-03 holdout 改名/换路径/非语义元数据身份无关 | **已证实**（负例探针交付且全绿：三变体判定四元组与聚合 metrics 恒等；身份面（dataset/dataset_sha256/manifest_sha256）如实不同且可判伪；identity 消费点限于校验/去重/获取键/呈报——spec↔manifest 绑定 fail-closed 是校验面非产品判断条件【K5 边界如实登记】；该要求离线可验证部分=全部——deterministic 判定面；llm/llm-retrieval 模式由"判定面共享同一 scan/matching 路径"论证承载） | IP-0036 A4 探针二（方法 4/5） | `tests.test_v4_baseline_v5_negatives` holdout 两探针全绿（三变体恒等+身份面差异+load 校验面通过） | llm/llm-retrieval 模式逐模式注入（K5：不逐模式，判定面共享论证承载） | IP-0036/#237 |

## 3. 锚行（四类仓库/九类/固定 SHA/标注样本/signal-storm）

| 锚目标 | 状态 | 证据指针 | 完成门禁（可机械检查判据） | 未闭环缺口与真实运行/人工依赖 | 承接 |
|---|---|---|---|---|---|
| 空仓（archetype/empty-repository） | 已证实 | IP-0030 fixture（零文件物化+sentinel 摘要） | `tests.test_v4_baseline_fixtures` 空仓断言全绿（file_count==0/`e3b0c442…` sentinel） | — | IP-0030/#219 |
| 最小仓（archetype/minimal-python-repository） | 已证实 | IP-0030 fixture（3 文件精确结构） | `tests.test_v4_baseline_fixtures` 最小仓断言全绿 | — | IP-0030/#219 |
| LlamaFactory 固定 SHA（7fcf5b3b130e5713b52415bb7404c476fada9c8c） | 已证实 | 两批真实运行证据（物化+digest 链）；工件族 llamafactory 描述子四钉逐字（IP-0036） | `tests.test_v4_baseline_real_run`（v6）工件族目录断言全绿（llamafactory 描述子==现行钉逐字）；`_materialize` destination 文件名逐字节一致断言 | — | IP-0032/0034 两批；IP-0036/#237 |
| repository-disjoint 标注样本（popular external holdout v2） | 部分（数据角色冻结+身份无关性负例离线已证；真实评测运行未做） | manifest 角色+IP-0036 A4 探针二 | `tests.test_v4_baseline_v5_negatives` holdout 探针全绿 | popular holdout v2 真实评测运行 | IP-0026（角色）；IP-0036/#237 |
| 九类 archetype（application/library/cli/docs-content/test-heavy/monorepo/large-repo/malicious-layout/dependency-blocked） | 部分（fixture 全部在库且离线接线探针跑通；工件族离线全链（fake transport 物化→chat→报告）=IP-0036 M4 已证；九类真实验收未做） | fixture_registry+IP-0030+IP-0036 M4（合成键全链探针+零预算拒付面九键） | `tests.test_v4_baseline_real_run`（v6）合成键探针全绿（描述子钉扎/零预算拒付/全链/门禁同构）；A4 目录↔注册表一致性全绿 | 九类真实验收（真实批次，另行授权） | IP-0030/#219；IP-0036/#237 |
| signal-storm（第 12 合成 archetype） | 已证实（离线交付即全部：确定性生成器+注册表第 13 条目+digest+幂等+边界（N>12/≤262144/ASCII-LF/无 URL/无真实身份/inert 头）+上限负例原料） | IP-0036 M3（6 新增方法）+A4 探针一（方法 2） | `tests.test_v4_baseline_fixtures` signal-storm 六方法全绿；Done Command 10（13 条目字节一致）；A4 物化扫描探针全绿 | — | IP-0036/#237 |

## 4. 固定上限普查表（R6.3；Packet §7.6 结论入矩阵；披露有界参数行）

普查口径：离线可判定路径（`benchmarks/v4/baseline/*` 与 `lima/` 评估面）全部固定数值选择/上限常量。普查结论（本 P&V 会话 grep 亲验）：**不存在"固定 6 条"式未披露复核/处理上限**；下列均为具名披露的有界参数（修改任何一项的语义=另行决策，本叶零改动）。

| 披露参数 | 位置 | 语义（披露） | 门禁（可机械检查判据） |
|---|---|---|---|
| `CANDIDATE_FILE_CAP=12` | benchmarks/v4/baseline/real_run.py L129 | 请求构造参数（每请求候选文件数）；非处理/复核上限 | A4 探针一方法 3（walk 全量 N=15+select 恰 12+数值钉扎） |
| `CANDIDATE_CHAR_CAP=6000` | real_run.py L130 | 每候选文件读入字符上限（请求构造） | `tests.test_v4_baseline_real_run`（v6）既有 cap 断言（b 族）全绿 |
| `MAX_CONTEXT_CHARS=36000` | real_run.py L128 | 每请求上下文总字符上限 | 同上（cjk 截断负例） |
| `WALK_ENTRY_CAP=5000` | real_run.py L131 | 目录遍历访问条目上限（防失控遍历；非 findings 上限） | 同上（walk 契约断言） |
| `MEMBER_COUNT_CAP=30000` | real_run.py L135 | 归档成员数上限（安全解包） | `tests.test_v4_baseline_real_run`（v6）archive cap 负例全绿 |
| `MEMBER_BYTE_CAP=50000000` | real_run.py L136 | 单成员字节上限（安全解包） | 同上 |
| 下载字节上限（250,000,000） | 预算维度 per_run.download_bytes（工件声明） | 每 attempt 下载字节上限（流式逐块执行中检查） | 同上（download exceeded 负例） |
| 证据包候选 `[:5]` | lima/semantic_retrieval.py L666 | 语义检索证据包候选数（具名披露有界选择） | 既有 `tests.test_semantic_retrieval` 面（禁区，blob 守护） |
| `MAX_UAF_TRANSLATION_UNITS=16` | lima/cxx_memory.py L158 | UAF 分析翻译单元上限（具名披露） | 既有 `tests.test_cxx_*` 面（禁区，blob 守护） |

## 5. 本叶（IP-0036）需求覆盖汇总（#237 FR-01..08 / AC-1..5 → 证据）

| #237 需求 | 状态 | 证据（测试 ID/命令） |
|---|---|---|
| FR-01 矩阵 v2 | 已证实（本文档入库即交付；与实现一致口径=DR-IP-0036-PV-10） | A4 方法 6（docs 在库+3 COPY 行）；Done Command 6（diff 守护恰 4 Add+8 Modify） |
| FR-02 V5 schema | 已证实（离线面全部：三新面/null 纪律/domain 三态/resources/collect 零字节） | M2 全文件（29 演进+9 新增）；Done Command 1 |
| FR-03 隐藏上限负例 | 已证实 | A4 探针一方法 1/2/3；Packet §7.6 普查表（本文 §4） |
| FR-04 holdout 身份无关 | 已证实 | A4 探针二方法 4/5 |
| FR-05 signal-storm | 已证实 | M3 六新增方法；Done Command 10 |
| FR-06 专家复核包 | 已证实（流程可用性交付；本叶零真人事件=K4 如实登记） | M2 示例 sidecar 校验方法；A4 方法 6 |
| FR-07 cold 重置程序 | 已证实（离线探针全部：重置/确定性/全序列/默认不变） | M4 方法 8/9/10 |
| FR-08 入口泛化 | 已证实（工件族 10 键/逐工件钉扎/未知键 fail-closed/零预算拒付面+离线全链面/命名纪律/门禁零放松） | M4 方法 1-7；A4 方法 7/8 |
| AC-1 | 已证实 | M2 全文件（零弱化=Done Command 7 blob 守护+六条件程序） |
| AC-2 | 已证实 | A4 探针一/二全绿 |
| AC-3 | 已证实 | M3+M2 示例校验；缺席纪律保持（M2 既有 zero-sidecar 断言零弱化） |
| AC-4 | 已证实 | M4 全部新增+Done Commands 2/3（298 回归+discover 绿=CI 离线） |
| AC-5 | 已证实 | 本文档+A4 方法 6；无未验证宣称（K6 行保持部分/未证实） |

（矩阵完；勘误按新版本发布，不原地覆盖语义。）
