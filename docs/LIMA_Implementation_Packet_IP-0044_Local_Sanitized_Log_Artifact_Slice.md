# LIMA Implementation Packet — IP-0044 本机脱敏日志 Artifact 存取（首片）

- Packet 版本：`2.2`（2026-10-12；状态 `RC-REVISION / PENDING-MERGE`，docs-only PR #283 呈审
  对象=本版新精确 head）
- 修订批次：D1R——v1.0（@`1e6a68743b38795089c56a6edd80d49d0c770e08`）被 Maintainer 否决合并
  （"仅余 P3 文字级"结论被 `MR-66-PR283-D1-REPAIR-AND-IMPLEMENTATION-20261011/v1` 替代）；
  v2.0（@`8377a6eb4ee9dae43fc0e8fa246082de1458ee48`，内容 SHA-256
  `08aa375394a12e573be2e8b6c2564a313065d602d16c49cd25e28015fdd1f779`，862 行——尾部空元素
  计数口径不计，哈希为准）按六项 R66 修正整体修订并取代 v1.0，v1.0/v2.0 均保留为历史证据
- D1F 修订（2026-10-11）：v2.0 head `8377a6eb` 经新审核承认其已成立修正与真实证据、
  但暂不批准合并（说明书 `MR-66-PR283-D1F-AND-CODE-DELIVERY-20261011/v1`）；该版按
  R66F-01（seal expected 参数贯通）/R66F-02（持久预留-结算协议）/R66F-03（真实入口错误归属）
  在同一文件修订，新 commit 落在 `8377a6eb` 之上（不 amend/force，历史保留）；
  行数口径=各版 `wc -l` 实际计数（哈希为准）
- **RC 修订（本版 v2.2，2026-10-12）**：v2.1 head `1e223326` 经第三轮审核+实测承认其已
  成立修正与真实证据、**暂不批准合并**（说明书
  `MR-66-PR283-RESOURCE-CORRECTION-AND-CODE-20261012/v1`，SHA-256
  `b558b020f6021837aea6657e9100c33d4c862b1e58e011380a16711c78a3845a`）；本版按
  R66S-01（SQLite 物理预算规约——机制①单选：`PRAGMA max_page_count=M` 页数硬限+受限事务
  页级 journal 上界+每步预留，口径换页 denomination）/R66S-02（共享 blob 唯一物理键结算
  五条规则+零新表方案）同步修订全部受影响协议步骤、限额表、预留/结算、故障矩阵、错误
  副作用、验收映射与测试计划，并把 D2 接续义务预告写入正文（§10.1）；§7.4 十七行替换
  清单逐项核销（§1.3 登记）；新 commit 落在 `1e223326` 之上（不 amend/force，六 commit
  历史保留）。**Coordinator 单值裁定引用**：资源机制单选=§11.1（①：max_page_count+
  页级上界+每步预留，不带②入 D2）；共享 blob exact 私有表示=§11.4（复用
  `seal_attempts.blob_id` 在途登记，零新表/零新列/零新公共接口）；例值处置=按新规约全部
  重算重写（一次选定、全文一致，§11.7）；公共限额面零变更=§11.2
- Assignment：`ASN-D1R-IP-0044-66-LOCAL-LOG/v1`（2026-10-11；授权指针
  `MR-66-PR283-D1-REPAIR-AND-IMPLEMENTATION-20261011/v1`）；D1F 增量：
  `ASN-D1F-IP-0044-66-LOCAL-LOG/v1`（2026-10-11；授权指针
  `MR-66-PR283-D1F-AND-CODE-DELIVERY-20261011/v1`）；**RC 增量：
  `ASN-RC-IP-0044-66-LOCAL-LOG/v1`（2026-10-12；授权指针
  `MR-66-PR283-RESOURCE-CORRECTION-AND-CODE-20261012/v1`；Assignment SHA-256
  `a555f9afe27bd0fc48348bff806e5ead4c509ccba3ff9116d9d61aa072392030`）**
- 编制角色：Packet & Verification Agent（运行模型：无法核验——未取得可独立核验的运行元数据，
  TELEMETRY-MISSING / RUNTIME-UNVERIFIED，不伪造）
- 设计探针：`.pv_tmp/issue66-local-log-2026-10-10/probes/`（P1–P4 为 D1 记录；P5–P8 为 D1R
  新增实测/模型记录；P9–P11 为 D1F 新增实测/模型记录；**RC-P1–RC-P4 为 RC 新增实测/模型
  记录（真实 DDL/九事务形状/页级上界推翻尝试/max_page_count/整 root Oracle/共享 blob
  六场景）**，均可复现；下文标注「设计探针实测（probe Px，可复现）」处均以该记录为据）
- 审核探针证据（引用，只读）：`output/issue66-pr283-review-2026-10-11/probe_results.json`、
  `output/issue66-pr283-v2-review-2026-10-11/review_v2_probe_results.json`、
  **`output/issue66-pr283-v21-review-2026-10-12/capacity_probe_results.json`（第三轮实测
  反例：journal 行数公式被真实 SQLite 推翻〔8 行 66,176 B>J(8)=57,344、12 行 99,008 B>
  73,728〕、初始 DB 28,672 B 未入账、共享 blob 结算对象账 1→2——R66S-01/02 反例依据；
  引用不越类：journal 反例=对一般行数公式的反例、非已实现事务超限；blob 反例=原协议
  模型实测、非产品缺陷）**

## 1. Header

```text
Source Issue：#66（Artifact Registry 与不可变对象存储；OPEN；labels feature/security/area:storage/priority:high/status:blocked，本片不动 labels）
Issue specification revision：正文 updated_at 2026-09-11T17:39:36Z（V4 FR/NFR/AC/T + V5 覆盖层；V5 节与前文冲突时以 V5 为准）
Delivery role：vertical-slice（#66 首片）
Issue closure impact：PARTIAL（首片完成 ≠ #66 关闭；说明书 §5 清单仍是 mandatory 缺口）
Covered requirements（本片贡献，均为部分/设计层，零 SATISFIED）：FR-01/02/03/04、NFR-01/02、AC-01..03（本机 SQLite/日志子集）、V5-FR-01/02/03/04、V5-AC-01..03（逐条见 §9 映射表）
Not covered requirements：FR-05（migration registry）、FR-06（retention/pin/删除）及 PostgreSQL/report_json 迁移/TTL/GC/tombstone/lineage DAG/多领域 dispatch/S3/生产接线（说明书 §5 全清单）
Upstream IP/PR/merge commits：#58 契约基线与 #94 隐私核心已并入 main `fbbbd619fb0b96efbbb903916ab46dc0daed2214`（本 Packet exact base；详见 §2 DI-007/DI-008）
```

用户可观察结果（首片完成后的真实行为）：调用者提交一份有界 UTF-8 日志及真实租户/任务上下文 →
经真实 #94 storage policy 净化 → 只保存获准内容（净化后字节）并返回既有 `ArtifactReference` →
另一进程重启后仅凭引用与访问上下文读回同一已封存字节并核验身份/权限/大小/摘要。失败不返回未校验
内容、不退回保存原文、不以内联巨型 JSON 降级。

D1R 交付性质声明：本文是**设计冻结（修订版）**——零产品实现、零冻结测试、零 CI 产品证据。六项
R66 修正（R66-01..06）已收敛为唯一合同（§1.2），全部旧相反条款已替换核销（§1.3）。D2 才冻结
验收测试与有效 RED；Implementation 只能在修订 Packet 合并 + 测试冻结 + 有效 RED + Coordinator
IMPL Assignment + 主会话真实派发五条件齐备后启动。

### 1.1 修订说明（D1R）

- 否决与取代：旧 head `1e6a6874`（Packet v1.0）不批准合并；本 v2.0 在同一文件、同一 PR #283、
  同一 IP-0044 上以新 commit 修订，保留 `de7181b3`/`1e6a6874` 历史（不 amend/force）。
- 修订依据：说明书 §4（`e27009ae…93b7`）采纳的六项修正 + D1R Assignment §7 规约与 §11 单值
  裁定 + 审核报告（`da11ba2f…4d0`）与审核探针证据。旧 ER（ERR-IP-0044-D1-v1/v2）与旧 Brief
  结论只适用旧 head（DI-018）；其 SF-01（schema name 计数）复核事实仍有效，SF-04/SF-05/
  SF-07/SF-08 相关表述被本版取代或核销。
- 修订面：协议步骤与签名、错误副作用、预算与限额、故障矩阵、验收映射全部同步；不只追加六段
  声明——§1.3 十六行替换清单逐项核销，全文（含示例、恢复规则、测试计划）无并存反义表述。
- 新增探针：P5（R66-01 字段贯通，真实 API）、P6（R66-03 hash 物理键，win32 文件系统实验）、
  P7（R66-04 预算前置，真实净化复现+协议顺序模型）、P8（R66-02 复用核验，协议模型——非产品
  实测，明确标注）。
- 唯一新错误码：`STORE_CONFIG_CONFLICT`（R66-05，open 时同 root limits 不一致拒绝）；其余错误
  语义复用既有码扩展触发面（R66-02 映射）。
- journal 模式单值选定：**rollback journal（DELETE）**（Assignment §7.5 第 7 条唯一下放项；
  理由与验证边界见 §7.3）。
- 同范围最小修订（2026-10-11，ER Record v3 四项 Shadow Findings SF-D1R-01..04）：按 Coordinator
  裁定 CR-D1R-01（seal_log 状态判定全函数/方向性单值——§4.4/§5.3/§6.1）、CR-D1R-02（落点
  规约：四项一次 commit、版本维持 2.0、§1.2/§1.3 登记指针）、CR-D1R-03（SF-D1R-02/03/04
  句级单值：P1 非常规文件映射、契约层 schema-major 拒绝入口归属、限额计账单值与 DDL 排序
  规则纪律）执行；本行即该 delta 的修订说明登记。
- **D1F 修订（本版 v2.1，2026-10-11）**：v2.0 @`8377a6eb` 暂不批准合并；按新审核
  （DI-020）与 D1F Assignment（DI-023）§7.1–7.4 修订三项：R66F-01 seal 六段冻结次序+两分支
  expected 核验+fresh staging 四态映射（§4.2/§4.3/§4.4/§5.3/§6.1/§8）；R66F-02 预留-结算
  协议（seal_attempts 行承载 RESERVED、R1/R2 独立提交事务、逐段峰值预留、失败/崩溃锁内
  结算、journal 保守公式、诊断行取消——§4.2/§4.3/§7.1/§7.3）；R66F-03 真实入口错误归属
  （删「get 映射构造期异常」承诺——§4.2 G2/§6.1/§8）。§7.4 十五行替换清单逐项核销
  （§1.3 登记表）；§7.5 继续有效条款不动（R66-01..06 与 CR-D1R-01..03 不重开）。新增探针
  P9–P11（SQLite 实测+协议模型+真实 foundation API，如实分类）。
- **D1F 同范围最小勘误（2026-10-11 第二批；版本维持 `2.1`——同版本勘误登记，新 commit 于
  v2.1 首 commit `70906428` 之上；ASN-D1F-IP-0044-66-LOCAL-LOG/v1 延续，依据=ER Record v5
  〔`er/ERR_IP-0044_D1_v5.md`，SHA-256
  `ec5ce8d55c4ca76a4f89ba64b6b789e5be95f89e0f0362d6d38b59ceb0191592`，READY-FOR-SUBMISSION@
  `70906428`：15 一致/2 不一致/1 无法核验〔新 head CI 归主会话〕〕+ Coordinator 裁定
  CR-D1F-01）**：①SF-D1F-01——§7.1f 例⑥数值修正：Σ实际+Σ有效预留=**269,536**（原 271,536
  系把已含于 A 预留 134,768 的 DB 行 2,000 重复相加；与 P10 例⑥〔b_sees_lhs=134,768+
  b_need=134,768〕及 PROBE_LOG 一致）；②SF-D1F-02——CR-D1F-01 补裁落位 §4.4（权威行
  RESERVED 的 seal 判定唯一归属 `STAGING_STATE_INVALID`，补裁原文见 §4.4；§4.2 ①–⑤ 枚举行/
  §4.4 末句/§5.3 handle 字段表/§6.1 (b) 触发面/§8 谓词组合连带同步）；§1.2 指针与 §1.3
  D16/D17 勘误行登记。**〔v2.2 注：本批勘误的 269,536/134,768 等数值面属旧行数/行字节
  口径的历史登记，已被 RC 页级规约全量重算重写（§7.1f），保留不改写以存证据链〕**
- **RC 修订（2026-10-12，版本升至 `2.2`）**：v2.1 head `1e223326` 被第三轮审核
  （DI-025）+实测反例（DI-026）认定：journal 行数公式无上界证明（真实 SQLite 反例）、
  P10 root 计账漏 DB 文件、共享 blob 被 per-attempt 结算重复计数——三项均为资源计账
  证明缺口，不重开总体架构。本版按 RC Assignment（DI-028）§7.1/§7.2/§7.4 修订：
  R66S-01 落位=撤销旧公式上界地位（例值按新规约全部重算重写——§11.7 二选一选定
  「重算重写」）、建立拟用真实 DDL/索引与九事务形状目录+K_T 派生（§7.3）、冻结支持
  的 SQLite 配置面并绑定 root metadata（§7.3）、页级 journal 上界公式+五条适用前提+
  推翻义务（§7.3）、`reserved_metadata_bytes` 语义改 DB 物理页增长预留 Δpages×P
  （显式取代 D1F Assignment §11.6 行字节合计口径——§7.4 R6）、`max_page_count=M` 派生
  硬限与到限内容 IO 前稳定拒绝（§7.3/§7.1a 行 12）、限额表行 4/5/10/12 语义列重写；
  R66S-02 落位=五条唯一结算规则+零新表方案（seal_attempts.blob_id 在途登记+唯一物理键
  集合 U 对账+账本单调≥|U|+首次差额入账+重复 no-op+判定与对账不一致 fail-closed，
  §7.2/§7.1d/§7.1f）；D2 接续义务预告三条写入 §10.1。**三不变**：18-ID 映射分布
  不变（14/2/2/0）、44 方法最低数不变（新场景参数 case 接入既有族）、公共签名逐字
  不变；23 错误码零新增。新增探针 RC-P1–RC-P4（真实 SQLite/真实文件树，如实分类）。
  ER v5/v6 与 D1F Brief 结论限定登记见 DI-029（算术/RESERVED 修正事实保留；其
  root/journal/共享 blob 保证被本轮反例限定）。
- **RC 同范围最小勘误（2026-10-12 第二批；版本维持 `2.2`——同版本勘误登记，新 commit 于
  v2.2 首 commit `4ccf46ba` 之上，不 amend/force；ASN-RC-IP-0044-66-LOCAL-LOG/v1 延续；
  依据=ER Record v7〔`er/ERR_IP-0044_D1_v7.md`，SHA-256
  `a29897460e826b84cb06c7a47921121b5e7fb2fc134421ff2b113d3baf2c9af4`，
  READY-FOR-SUBMISSION@`4ccf46ba`：27 一致/5 非承重/1 无法核验〕+ Coordinator 裁定
  CR-RC-01 勘误路径）**：SF-01——恢复 v2.2 首 commit 误删的 `PRAGMA foreign_keys=ON`
  与连接纪律句（§7.3-a；§1.3 E1 勘误登记行；语义无变化：DDL 无外键约束、连接纪律连续性
  而非语义依赖）；SF-02——§1.2 R66S-02 行「本版落点」首项改为实际章节列举
  （§7.1a 行 4/§7.1b/§7.1d/§7.1f〔五条规则落位〕、§7.3-b〔blob_id 列语义〕、§7.2〔物理键
  路径〕）；SF-03——§7.1f 增口径注（RC-P3 驱动器 R2 段 2 页演示预留＜冻结声明口径 10 页=
  T-R2+T-P2；T-P2 Δpages=8 为保守推导值、RC-P1 实测增长 2 页、P2 实际 0 增长未构成漏计、
  max_page_count 硬限兜底、D2 按声明口径断言；init 9/8 页为驱动器样本差异）——**标注不改
  数值**；SF-04——publish 临时文件命名冻结（`publish-<uuid4hex(32)>.tmp`，Coordinator
  单值；U 枚举分类据此确定；§7.1d 单源）；SF-05——§7.3-d 提交点措辞按 atomiccommit 修正
  （journal 头 nPage 由 0 改真实值使其后失效〔不可回滚点〕；DELETE 模式提交点=journal
  删除〔头失效〕）；SF-07——§8 增记录上限水位（行 10 域值）下 btree 深度/脏页数边界参数
  case 义务。六项均为非承重文字/指针/命名单值化（ER v7 定性 5 非承重），零语义变更——
  三不变、23 错误码、44 方法、公共签名、公共限额面均不动。

### 1.2 六项 R66 + 三项 R66F（D1F）+ 两项 R66S（RC）↔ 受影响章节/被替换旧条款对照表

| 修正 | 规则摘要（单值） | 本版落点 | 被替换旧条款（@锚点） | 证据/探针 |
|---|---|---|---|---|
| R66-01 | S2 租户绑定检查 `SanitizedPayload.tenant_id`（真实字段层级）；manifest 分项核验（policy_digest 实算比对、classification/retention 接受面） | §4.2 S2、§2.2、§6.1 表述、§8 隐私组 | §4.2 S2 `manifest.tenant_id == store tenant`（约 L121–123） | P5（真实 API 实测）；审核 `probe_results.json`（manifest_has_tenant_id=false） |
| R66-02 | P1 三分支（无目标→发布 / 已存在→受控核验后复用 / 竞态→同等核验）；核验失败稳定失败零副作用；幂等成功同样核验实物；发布+commit 同临界区；错误码复用映射 | §4.2 P1、§4.3、§4.4、§6.1、§7.1d | §4.2 P1「已存在同 digest 文件则复用」+无条件 `os.replace`（约 L131–134）；§4.4 幂等段只看 DB 行（约 L190–194） | P8（协议模型，`is_product_implementation_test=false`）；审核 `existing_blob_protocol_model` |
| R66-03 | `tenant_storage_key=SHA256(tenant_id 精确 UTF-8 字节).hexdigest()`（小写 64-hex，仅物理目录）；逻辑身份精确比较不变；映射版本绑定 fail-closed（`METADATA_CORRUPT`） | §4.4、§7.2、§8 路径组 | §4.4 blob 键 `blobs/<tenant_id>/...`（约 L187–189）；§7.2 路径表与「尾随 `.`/空格…混叠」表述（约 L334–344） | P6（win32 实测；Linux 未验证→D2）；审核 `synthetic_fs` |
| R66-04 | 输出校验（类型/字节/上限交集）先于任何 content staging 写入；输入/输出两步分开；超限零内容写入；S4 只做重读复核；写入原语有上限 | §4.2 S2/S3/S4、§6.1、§7.1、§9.1 NFR-01、§8 | §4.2 S3→S4 时序（约 L124–129）；§6.1「staging 可留诊断行」（约 L281）；§7.1 两层说明（约 L325–327）；§9.1 NFR-01 行（约 L411） | P7（真实净化复现 262,119→365,378 + 顺序模型）；审核实测 |
| R66-05 | 统一限额表（作用域/默认/合法域/硬上限/计数单位/预留-提交-失败-崩溃/稳定错误逐行单值）；计数语义与跨进程额度冻结；单 root 串行临界区+有限等待+SQLite 小记录；同 root limits 不一致→`STORE_CONFIG_CONFLICT`；journal 单值 DELETE | §7.1、§7.3、§7.1d、§8 | §7.1 零散限额行（约 L319–323）；§7.3 无条件 `PRAGMA journal_mode=WAL`（约 L350） | 合同分析级冻结（无实现实测；多进程/crash 兑现归 D2，如实标注）；说明书 §4 R66-05 |
| R66-06 | 公共合同一次冻结：open 签名 policy 必填注入；get 六字段六步校验顺序；持久 handle 与 close 语义；lineage 最小面+`STAGING_STATE_INVALID`「已 abort」触发删除；`SealedLogReceipt`/`RetrievedLogArtifact` 分型（旧单类型删除） | §4.2 get G1–G6、§4.5、§5.1–5.3（含字段表）、§6.1、§10.1 | §4.5 open 只绑 tenant（约 L202–205）；§5.3 签名无 policy（约 L250–268）；§4.2 get G1–G4（约 L139–145）；§6.1「非本 store、已 abort」（约 L284–286）；§10.1 SF-05/SF-08 | Assignment §7.6 逐字裁定 + §11 单值；**CR-D1R-01 补裁（seal_log 状态判定全函数/方向性，§4.4）**；源码复核（`ArtifactReference` 六字段，§2.2） |
| **R66F-01**（D1F） | seal 入口六段冻结次序：⓪ 参数形状（expected ∈ {None}∪{64 小写 hex fullmatch}+handle 形状；违反 → INVALID_ARGUMENT 零副作用）→ ①–⑤ 权威状态判定（CR-D1R-01 不变）→ 实物完整性核验（正常分支临界区内重核 staging〔四态映射 lstat→存在→size→digest〕/幂等分支核验已有 blob）→ expected 比较（正常=任何 publish IO 之前对重核 staging digest；幂等=blob 核验后返回前对已核验 blob digest；不符 → SEAL_DIGEST_MISMATCH 两分支）→ R2 预留事务 → 新发布/P2 commit 或幂等返回；S4 删除 expected 提及（只复核 staged 字节/记录）；「正确 blob+错 expected」→ SEAL_DIGEST_MISMATCH 且原状态不动 | §4.2（S4/seal 六段）、§4.3（新增两矩阵行）、§4.4 ③⑤、§5.3 签名说明、§6.1（错误表 6 行触发面）、§8（参数 case 接入） | §4.2 S4 末行 expected 句（@8377a6e 约 L231）；seal 伪代码无参数形状/核验/expected 次序（约 L232）；§4.4 ③⑤ 幂等不核 expected（约 L323–342）；§6.1 SEAL_DIGEST_MISMATCH 触发「S4」（约 L504） | 审核 `expected_digest_contract_static` 静态四事实（DI-021）；**P9（SQLite 实测：预留事务独立提交/P2 回滚不吞预留行；⓪ 形状谓词+次序）**；16 状态谓词模型只覆盖 ①–⑤ 状态分类、不覆盖 expected/实物变化（新 ER/Brief 标注）；**CR-D1F-01 补裁（SF-D1F-02，D1F 勘误第二批）：权威行 RESERVED 的 seal 判定唯一归属——§4.4** |
| **R66F-02**（D1F） | 预留-结算协议（唯一形态）：seal_attempts 行承载 RESERVED（预留字段列；artifacts 状态机不扩）+R1（S3 前独立提交）/R2（P1 前独立提交）逐段新增峰值预留+P2 转实际+失败释放未用/已写实物继续占额+锁内有界结算（先结算后写；范围外/未知实物 fail-closed）+「Σ实际+Σ有效预留 ≤ cap」不变量（行 5 双口径）+journal 余量入账（**v2.1 的行数公式已撤销上界地位并被 v2.2 R66S-01 页级规约取代——本行历史登记保留，现行口径见 §7.3**）+诊断行取消（S2 失败零持久行）+行 7 计数单位含 RESERVED+524,288B 双副本分别预留 | §4.2（S0/S2d/R1/R2/P2）、§4.3（矩阵行 1/orphan 行）、§7.1（行 2/4–12 重写+计账细则+7.1d 扩+新增 7.1f 状态/动作表与七例数值反例集）、§7.3（journal 余量/**v2.2：DDL/形状目录/页级公式**）、§8、§9/§10/§12 同步 | §4.2 S0 额度检查（约 L205–206）；S2d 诊断记录（约 L222–223）；S3「单事务+账本预留」（约 L224–227）；§7.1 行 4–12 预留/失败列（约 L542–550）与行 2/行 10 诊断条款；§7.1d（约 L582–589）；§7.3 journal 推导（约 L644–647） | 审核 orphan 反例（ledger=0/physical=1）与 524,288B 峰值反例（DI-021，协议模型）；P10（SQLite+文件系统模型：orphan 消解、双副本分别预留、二进程争额、小 aux cap、fail-closed；**其 journal 行字节示意与「公式数值核对」证据面被 R66S-01 限定——DI-029/§7.4 R8**）；多进程/crash 兑现仍标设计（D2）；**v2.2 数值面按页级规约全部重算重写（§7.1f），RC-P1/RC-P3 为现行证据** |
| **R66F-03**（D1F） | 真实入口错误归属：构造期错误（含 `SchemaVersion(3,0)` 的 SCHEMA_UNKNOWN_MAJOR）归 foundation/caller——get 未被进入、不映射；实际可传入的错误 schema_name/合法 4.x 非本片 minor（如 4.1）→ G2 UNSUPPORTED_SCHEMA；非 Reference 形状 → G1 INVALID_ARGUMENT；G4/G5 内部实际执行 decode/validation 的契约错误按既有映射；不新增 raw/dict 解析 API、不改 #58 | §4.2 G2、§6.1（UNSUPPORTED_SCHEMA 行+映射注重写）、§8（真实触发面） | §4.2 G2 括注「含契约层 SCHEMA_UNKNOWN_MAJOR 及构造期同族…映射」（@8377a6e 约 L256–258）；§6.1 映射注同名句（约 L518–522）——两句都删，不留变体 | 审核 `real_contract_constructor_call_order` 实测（DI-021：3.0 构造即抛且被调函数未进入；4.0/4.1 构造成功可传入）；**P11（git 对象抽取 cc4c1d31 复测+异名/非 Reference 可达性，协议层标注）**；SF-D1R-03 的入口映射部分被推翻（入口勘误，非新接口） |
| **R66S-01**（RC） | SQLite 物理预算规约（**机制①单选**，Assignment §11.1）：①撤销旧行数公式 `4096×(N+2)+16384` 的安全上界地位，其例值全部按新规约重算重写（一次选定、全文一致）；②建立拟用真实 DDL/索引与**九事务形状目录**（init/R1/S3/S4/R2/P1 后登记=不使用/P2/失败结算/重开结算，逐类 K_T 派生：每 btree 写入行数+分裂余量+内部路径页，深度由 M 上界扇出推导）；③冻结支持的 SQLite 配置面（page_size=4096 实读验证/journal_mode=DELETE/auto_vacuum=NONE/synchronous 不降级/busy_timeout=10000/**max_page_count=M**/cache 与 spill 边界/临时文件声明）并绑定 `artifact_store_meta`，不依赖本机默认；④**页级 journal 上界** `journal_headroom(T)=(K_T+2)×(P+S)+2×S`（P=4096 实读；S=512 B/页探针冻结——实测本机 journal=512+K×4,104，每页开销 8 B，冻结值含扇区对齐与平台余量）+五条适用前提+推翻义务；⑤`max_page_count=M=floor(行5默认域值÷P)` 派生硬限（行 5 派生执行参数、非第 14 个公共限额；SQLITE_FULL→CAPACITY_EXCEEDED 稳定拒绝、到限内容 IO 前拒绝、不先越限再回滚）；⑥计费口径=root 下常规文件 st_size+有效预留（DB 按页计入行 5；`reserved_metadata_bytes`=Δpages×P 取代行字节合计；row bytes 行 9 逻辑界与 DB bytes 不双计；整区保守预留单列 reservation） | §7.3（DDL/形状目录/配置面/页级公式与前提/推翻义务/M 派定）、§7.1a（行 4/5/9/10/12 语义列）、§7.1d（journal/预留口径）、§7.1f（数值反例集全量重算重写）、§4.2（R1/R2 段）、§8（资源组+Oracle）、§10/§12 同步 | §7.1a 行 12 journal 公式 `journal_headroom(T)=4096×(T 计划脏行数+2)+16,384`（@1e223326 约 L717）；§7.1f `J(2)=32,768、J(3)=36,864、69,632` 与例①③⑤⑥⑦分量（约 L823–835，含 333,776/134,768/269,536）与 `J(1)=28,672…J(5)=45,056` 数值表（约 L837–839）；§7.3 验证边界段同名公式（约 L887–892）；§8 资源组 journal 数值核对与 333,776 例值（约 L954）；`reserved_metadata_bytes（按计划写入行字节合计）`（§4.2 R1/R2 段、§7.1a 行 5、行 9——**本行即对 D1F §11.6 的显式取代声明**）；§1.2/§12.3 P10 引用无限度标注（R8） | **RC-P1（真实 DDL 九形状实测：全部样本高水位≤页级上界；S 校准 slope=4,104/intercept=512；八项推翻尝试均未推翻）**；**RC-P2（max_page_count 实测：SQLITE_FULL 稳定拒绝×3、page_count=M、st_size=M×P、拒绝在 execute 步、大事务无越限增长）**；**RC-P3（整 root 独立 Oracle：终态账本==盘点两序列、init DB 即计额）**；审核 capacity_probe_results.json（行数公式反例，引用不越类）；官方依据=sqlite.org/atomiccommit.html（journal 按页存原始内容、页号随页存储、整扇区写入、头独立扇区、提交=删除） |
| **R66S-02**（RC） | 共享 blob 唯一结算（五条规则 Maintainer 冻结原文+**exact 私有表示=Assignment §11.4 单值**）：物理身份键=`(tenant_storage_key, content_digest)`（同键只计一个 blob/一份内容字节；逻辑身份/staging 各自计）；orphan 判定查询物理键是否被**任何 SEALED Artifact 或已登记在途 owner**引用（在途登记=复用 `seal_attempts.blob_id`，R2 提交时写入——零新表/零新列/零新公共接口；行 10 组成不变）；结算幂等=唯一物理键集合 U 对账（内容寻址布局天然一键一文件；同键第二文件/布局外实物→fail-closed METADATA_CORRUPT；账本 hold<\|U\| 差额=真正新 orphan 首次按唯一键入账、hold≥\|U\| 保守 no-op 不减、重复结算/多同 digest 行 no-op；恢复先结算后写、多次 open/settle 不创造容量；判定与对账不一致 fail-closed）；P1 复用不预留新物理额度（键已引用→reserved_objects=0；对象数满不误拒同租户有效复用）；崩溃 orphan 重试 seal 复用已登记实物不重复加账（P2 只增逻辑身份与记录）；**原 per-attempt 负例（A SEALED+B idle STAGING 同 digest→对象账 1→2）保留为回归反例并标注「原协议模型反例，非产品实测」** | §7.1a 行 4 预留/结算语义列/§7.1b 计数语义物理键/§7.1d 重开结算对账协议/§7.1f 状态动作表行 5/行 10+六场景四维度+原负例回归反例（五条规则落位）、§7.3-b（blob_id 列语义）、§7.2（物理键路径）、§4.2 R2（blob_id 在途登记）、§4.3（P1 后 P2 前矩阵行）、§8（六场景参数 case+四维度断言） | §7.1d「orphan blob（blob 在、无 artifacts 行）→ 按实际字节转实际占用」（@1e223326 约 L779–780，per-attempt 判定）；§7.1a 行 4 预留列「R2 预留事务对计划新增物理对象预留（复用分支不新增）」（约 L709）；§7.1b「唯一物理 blob（内容寻址去重后）」（约 L736）；§7.1f 状态/动作表行 5/行 10 对象计数（约 L812/L817）；§4.3 矩阵「P1 发布后、P2 前」orphan 行（约 L427）与 §4.2 DR-PACKET-1 段 orphan 计额句（约 L406–408） | **RC-P4（真实 SQLite+真实文件六场景×四维度：A/B/C1/C2/D/E/F 全过；同键第二文件与布局外实物 fail-closed 实测；旧 per-attempt 规则对照复现对象账 1→2——标注「原协议模型反例，非产品实测」）**；审核 capacity_probe_results.json 共享反例（is_product_test=false，引用不越类）；DI-021 orphan 反例（协议模型） |

### 1.3 旧条款替换核销清单（D1R 十六行 + D1F 十五行，逐项核销登记）

| # | 旧条款（v1.0 锚点） | 处置与落点 | 核销 |
|---|---|---|---|
| 1 | §4.2 S2 `manifest.tenant_id == store tenant`（约 L123） | 删除；替换为 `SanitizedPayload.tenant_id` 精确比较 + manifest 分项核验（§4.2 S2b/S2c） | 已核销 |
| 2 | §4.2 P1 见在即复用 + 无条件 `os.replace`（约 L131–134） | 替换为三分支核验/发布 + 临界区（§4.2 P1、§7.1d） | 已核销 |
| 3 | §4.4 blob 键 `blobs/<tenant_id>/...`（约 L187–189） | 替换为 `tenant_storage_key` 物理键（§4.4、§7.2） | 已核销 |
| 4 | §7.2 `<tenant_id>` 直作路径 + 「尾随 `.`/空格…混叠」（约 L334–344） | hash 键示例；删除「空格」表述（identifier 域不含空格，P6-e）（§7.2） | 已核销 |
| 5 | §4.2 S3→S4 先写 content.bin 再查 `max_sealed_bytes`（约 L124–129） | 输出校验先于任何 staging 写入（§4.2 S2d/S3） | 已核销 |
| 6 | §6.1 `SEALED_BUDGET_EXCEEDED`「staging 可留诊断行」（约 L281） | 零内容写入 + 事先声明有界诊断（§6.1、§7.1 行 2） | 已核销 |
| 7 | §7.1「净化后字节预算（S4，对 staged 净化字节）」（约 L325–327） | 同步为新时序（S2 写前校验；§7.1 末段） | 已核销 |
| 8 | §9.1 NFR-01 行与旧时序矛盾（约 L411） | 与新协议对齐（§9.1 NFR-01） | 已核销 |
| 9 | §7.1 零散限额行（约 L319–323） | 并入统一限额表（§7.1，默认值全保留） | 已核销 |
| 10 | §7.3 无条件 `PRAGMA journal_mode=WAL`（约 L350） | 替换为 DELETE 单值 + 验证边界（§7.3） | 已核销 |
| 11 | §4.5 open 只绑 tenant + §5.3 签名无 policy（约 L202–205、L250–268） | 替换为 §5.3 逐字冻结签名（policy 必填） | 已核销 |
| 12 | §4.2 get G1–G4 未冻结六字段逐项校验（约 L139–145） | 替换为 §4.2 G1–G6 六步顺序表 | 已核销 |
| 13 | §6.1 `STAGING_NOT_FOUND`/`STAGING_STATE_INVALID`「非本 store、已 abort」（约 L284–286） | 「非本 store」删除（同 root 同租户跨实例可重开）；「已 abort」删除（§5.3 handle 触发面、§6.1）；2026-10-11 CR-D1R-01 补裁：(b) 收窄为方向性矛盾（仅 declared=`sealed` 而权威行 STAGING；缺行唯一归属 `STAGING_NOT_FOUND`；全函数见 §4.4） | 已核销 |
| 14 | §5.1/5.2/5.3 `SealedLogArtifact` 单类型与 content 双语义、§10.1 SF-08 | 替换为 `SealedLogReceipt`/`RetrievedLogArtifact`；SF-08 核销（§5.1–5.3、§10.1） | 已核销 |
| 15 | §10.1 SF-05（abort 载体 D2 二选一） | 核销（裁定=删除触发条件）；§10.1 仅保留仍真实义务 | 已核销 |
| 16 | §4.3 故障矩阵、§6.1 错误表、§8 测试计划不一致表述 | 同步改写（新增「SEALED 后实物损坏重复 seal」行、限额/计额用例、两平台租户键用例、膨胀反例用例） | 已核销 |

**D1F 十五行替换核销登记（Assignment `ASN-D1F-IP-0044-66-LOCAL-LOG/v1` §7.4，对 v2.0 @8377a6e；无新旧并存，逐项核销；下表为对 v2.0 的历史登记——其 D9 行引入的 journal 行数公式与 D15/D16 行的数值面已被 v2.2 RC R1–R3/R16 显式取代并重算重写，历史登记保留以存证据链）**：

| # | 旧条款（v2.0 @8377a6e 锚点） | 处置与落点 | 核销 |
|---|---|---|---|
| D1 | §4.2 S4 末行「expected_content_digest（如给）必须等于实测（SEAL_DIGEST_MISMATCH）」（约 L231） | 删除；S4 回归 staged 字节/记录复核职责，expected 移入 seal 六段次序（§4.2 seal ⓪/expected 段） | 已核销 |
| D2 | §4.2 seal 伪代码 `seal_log(handle)` 无参数形状/核验/expected 次序（约 L232） | 重写为 ⓪–⑤+实物核验+expected+R2 六段次序（§4.2） | 已核销 |
| D3 | §4.4 ③/⑤ 幂等不核 expected、正常不重核 staging（约 L323–342） | ③补「blob 核验→expected→才返回」；⑤补「临界区内重核 staging→expected→才发布」（§4.4） | 已核销 |
| D4 | §6.1 `SEAL_DIGEST_MISMATCH` 触发「expected_content_digest ≠ 实测（S4）」（约 L504） | 触发改 seal 两分支（发布前/返回前）+副作用扩「不改动既有 SEALED、不覆盖 blob」（§6.1） | 已核销 |
| D5 | §4.2 S0「store 已用尽 live-staging/逻辑对象/记录/容量额度则拒绝（CAPACITY_EXCEEDED，临界区内原子检查+预留）」（约 L205–206） | S0 收敛纯输入/上下文预检；额度检查+预留移至 S2 后 R1 预留事务（§4.2/§7.1d/§7.1f） | 已核销 |
| D6 | §4.2 S2d「仅允许 §7.1 行 2 事先声明的有界诊断记录」+ §7.1 行 2 诊断条款 + 计账细则 (i) 诊断行（约 L222–223、L540、L558–562） | 取消持久诊断行（S2 失败=有界错误输出、零持久行）；(i) 替换为「无持久诊断行」单句；(ii)(iii) 保留但删诊断行交叉引用（§4.2 S2d/§7.1a 行 2/§7.1 计账细则） | 已核销 |
| D7 | §7.1 行 4–12 预留/提交/失败/崩溃列（「失败=释放预留」「预留按实测字节数入账」等，约 L542–550） | 按预留-结算协议逐行重写（逐段峰值预留、失败只释放未用预留、orphan/已写实物继续占额、行 7 计数单位含 RESERVED、行 5 双口径）（§7.1a） | 已核销 |
| D8 | §7.1d「写入前原子检查/预留——账本行与业务行同库同事务…失败释放哪些预留…=每行单值」（约 L582–589） | 扩为预留载体/R1/R2 事务提交点/P2 转占用/失败释放/锁内结算与 fail-closed 恢复协议（§7.1d） | 已核销 |
| D9 | §7.3「journal 峰值 ≤ 单事务脏页上界（本片每事务仅写有界小记录，行 9/12 计账）」（约 L644–645） | 替换为保守公式 4096×(计划脏行数+2)+16,384（8 KiB 单记录≠脏页上界）（§7.3/§7.1a 行 12） | 已核销 |
| D10 | §4.2 G2 括注「含契约层 SCHEMA_UNKNOWN_MAJOR 及构造期同族 schema 版本拒绝在本入口的映射」（约 L256–258） | 删除；真实归属表替换（§4.2 G2、§6.1 映射注） | 已核销 |
| D11 | §6.1 映射注「get 入口（G1/G2 边界）的契约层 SCHEMA_UNKNOWN_MAJOR 及构造期同族…→ UNSUPPORTED_SCHEMA」（约 L518–522） | 删除该句；G1/G2/G4/G5 按真实调用边界映射（§6.1 映射注重写） | 已核销 |
| D12 | §4.3 矩阵行 1「S2 失败至多留 §7.1 行 2 有界诊断记录」（约 L295） | 改「无行」（诊断行取消连带）（§4.3） | 已核销 |
| D13 | §6.1 `SEALED_BUDGET_EXCEEDED` 副作用「仅允许 §7.1 行 2 事先声明的有界诊断记录」+ 行 10 计数单位「artifacts+seal_attempts+诊断行」 | 改「零内容写入、零持久诊断行」；行 10 单位改「artifacts+seal_attempts」（§6.1/§7.1a 行 10） | 已核销 |
| D14 | §8 测试计划 expected/资源/构造器触发面（约 L690–698） | 增补 R66F-01 验收面（None/匹配/合法错值/非法格式 × 正常/SEALED/重开重试 + staging 改坏）与 R66F-02 七例、R66F-03 真实触发面；**44 方法最低数不变，新分支参数 case 接入既有方法族，不刷数**（§8） | 已核销 |
| D15 | §4.3 矩阵、§7.1 新增小节、§9/§10/§12 中与上述不一致的全部表述 | 同步改写（新增「stage 后 staging 改坏」「SEALED+错 expected 重试」矩阵行；§7.1f 新增小节；§7.4 kill 点增 R1 后+结算断言；§10.1/§11/§12 D2 义务与 diff 基线 `8377a6eb..HEAD` 同步） | 已核销 |
| D16 | §7.1f 例⑥「Σ实际+Σ有效预留=271,536」（v2.1 首 commit @70906428 笔误：把已含于 A 预留 134,768 的 DB 行 2,000 重复相加；ER v5 SF-D1F-01） | 修正为 **Σ=269,536**（A 预留 134,768 已含其 DB 行 2,000，不再另计；等价拆分=预留 132,768+实际 DB 2,000+B 需 134,768；与 P10 例⑥及 PROBE_LOG 一致）（§7.1f） | 已核销 |
| D17 | §4.2 ①–⑤/§4.4 末句/§5.3 handle 字段表/§6.1 (b)/§8：权威行 **RESERVED** 时 seal 判定未定义（v2.1 首 commit 的 ①–⑤ 五步未覆盖 RESERVED 行——ER v5 SF-D1F-02） | **CR-D1F-01 补裁**（原文逐字落位 §4.4）：declared_state 无论 "staged"/"sealed" 均唯一归属 `STAGING_STATE_INVALID`（触发 (b) 扩展形态，②′）；不按 ⑤ 正常路径处理（不重核、不发布）；RESERVED 行唯一处理通道=其所属 stage 操作自身与锁内结算（§7.1f 行 1–3）；§4.4 末句/§6.1 (b) 扩为「权威行为 STAGING **或 RESERVED**」；§8 标注两组合 | 已核销 |

**RC 十七行替换核销登记（Assignment `ASN-RC-IP-0044-66-LOCAL-LOG/v1` §7.4，对 v2.1 @1e223326；无新旧并存，逐项核销；「现状锚点」行号按 @1e223326，修订后行号已移动、以章节/步骤锚为准）**：

| # | 旧条款（v2.1 @1e223326 锚点） | 处置与落点 | 核销 |
|---|---|---|---|
| R1 | §7.1a 行 12 journal 公式 `journal_headroom(T)=4096×(T 计划脏行数+2)+16,384`（约 L717） | 撤销上界地位；替换为 §7.3 页级公式（K_T/P/S）+五条适用前提+官方机制依据+推翻义务 | 已核销 |
| R2 | §7.1f 数值反例集参数 `J(2)=32,768、J(3)=36,864、69,632` 与例①③⑤⑥⑦ journal/metadata 分量（约 L823–835，含 333,776/134,768/269,536） | **按新页级规约全部重算重写**（§11.7 二选一选定「重算重写」，全文一致；旧值不保留任何一处未标注出现——§1.2 R66F-02 行的历史登记处已标「被取代」） | 已核销 |
| R3 | journal 公式数值表 `J(1)=28,672…J(5)=45,056`（约 L837–839） | 同 R2 处置：替换为按真实 DDL 各形状 K_T 的页级上界数值表（§7.1f） | 已核销 |
| R4 | §7.3 验证边界段 journal 公式（约 L887–892） | 替换为页级上界推导+官方依据+前提+探针推翻义务；补配置面声明与 max_page_count=M（§7.3） | 已核销 |
| R5 | §8 资源组 `journal 公式数值核对（J(2)=32,768/J(3)=36,864）` 与 `333,776` 例值（约 L954） | 同步新公式/新例值；新增页级上界与事务内高水位断言用例（§8） | 已核销 |
| R6 | `reserved_metadata_bytes（按计划写入行字节合计）` 口径（§4.2 R1 段约 L293–294、R2 段约 L340、§7.1a 行 5 约 L710、行 9 约 L714；D1F Assignment §11.6 同口径） | 语义改为 **DB 物理页增长预留 Δpages×P**（行 9 仍为单条记录逻辑校验上界、非计费单位）；**本行即对 D1F §11.6 的显式取代声明**（§4.2/§7.1a/§7.1f/§7.3） | 已核销 |
| R7 | §7.3 及全文无 DDL/事务形状目录与配置面声明的空位 | 新增「拟用真实 DDL/索引与全部写事务形状目录」（九形状逐项，含「P1 后登记=不使用」表态）+ 支持的 SQLite 配置面（§7.3） | 已核销 |
| R8 | P10 作为 journal 公式/root 计账证据的引用（§1.2 约 L101、§8 约 L954、§12.3 约 L1125 等） | 引用保留但**证据限度标注**：P10 计量口径漏 DB 文件（lhs=0 vs 实际 28,672 B 实测）、其 journal 行字节为示意；新计账口径由本轮 RC-P1..RC-P4 探针建立（§1.2 R66F-02 行/DI-029/§8/§12.3） | 已核销 |
| R9 | §7.1d 重开结算「orphan blob（blob 在、无 artifacts 行）→ 按实际字节转实际占用」（约 L779–780） | 改为物理键引用判定+唯一物理键集合 U 对账（§7.1d/§7.2）；原负例保留为回归反例并标注「原协议模型反例，非产品实测」（§7.1f/§8） | 已核销 |
| R10 | §7.1a 行 4 预留列「R2 预留事务对计划新增物理对象预留（复用分支不新增）」（约 L709） | 扩写：物理键已引用（SEALED/在途两类）→ reserved_objects=0；对象数满不误拒同租户有效复用（§7.1a 行 4/§7.2 规则 4） | 已核销 |
| R11 | §7.1f 状态/动作表行 5/行 10 对象计数（约 L812/L817） | 按唯一物理键口径改写（同键共享不重复 +1；true orphan 首次 +1、重复结算 no-op）（§7.1f） | 已核销 |
| R12 | §7.1b 计数语义「唯一物理 blob（内容寻址去重后）」（约 L736） | 明确物理身份键=(tenant_storage_key, content_digest)；逻辑身份/attempt/staging 分开计（行 4/6/7/10 各归其位）（§7.1b） | 已核销 |
| R13 | §4.3 矩阵「P1 发布后、P2 前」orphan 行（约 L427）与 §4.2 DR-PACKET-1 段 orphan 计额句（约 L406–408） | orphan 判定与计额按物理键规则改写（R2 已在途登记→非误判 orphan；账上由 R2 预留覆盖）；DR-PACKET-1 段时态更新（本轮剩余=R66S-01/02 收口）（§4.2/§4.3） | 已核销 |
| R14 | §7.3 `seal_attempts` 列说明（约 L908–912） | blob_id 列语义扩写（R2 提交写入=物理键在途登记）；D2 接续私有列（producer 上下文+stage_policy_digest+size_bytes）落位说明；行 10 组成不变声明（§7.3） | 已核销 |
| R15 | §8 资源/恢复组用例（约 L953–954） | 新增六场景参数 case+四对比维度断言+独立 Oracle 整 root 盘点；44 最低数不变（§8） | 已核销 |
| R16 | §12 完成定义第 4 条 diff 基线 `8377a6eb..HEAD` 与「四 commit 历史」（约 L1128–1130） | 改 `1e223326..HEAD`；六 commit 历史保留声明（§12.4） | 已核销 |
| R17 | §4.2/§5.3/§10.1/§12 中与上述不一致的全部表述、§1.2 对照表、Packet header 版本/修订说明 | 同步改写（§1.2 扩 R66S-01/02 两行；header 版本 2.2、RC 批次与授权指针登记；D2 接续义务预告落位 §10.1；§2.1 DI-024..029）（本表 R17 与上述各行一并落地） | 已核销 |
| E1 | **（勘误登记行，非替换清单项——CR-RC-01/SF-01）** v2.2 首 commit（@4ccf46ba）在重写 §7.3 时误删 v2.1 §7.3 的 `PRAGMA foreign_keys=ON` 与连接纪律句（每操作一连接、异常回滚、finally close，参考 `TaskStore`，只读借鉴）——**非授权删除**（ER v7 SF-01 复核发现） | **本批（v2.2 勘误第二批）恢复**至 §7.3-a 配置面列表；**语义无变化**：本 DDL 无外键约束，本项为连接纪律连续性而非语义依赖 | 已核销（恢复完成） |

## 2. Design Input Manifest 与 Explicitly Rejected Inputs

### 2.1 Design Input Manifest

| ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001 | Standard | `docs/ZCODE_LONG_TASK_ISSUE66_LOCAL_LOG_ARTIFACT_AND_DELIVERY_2026-10-10.md` | SHA-256 `947fa9fb…a3b`（编制时亲算一致） | §4 最小行为、§5 边界、§6 顺序、§7 审阅面、§9 反过度设计 | normative（原交接正文） | 与 DI-013 冲突处以 DI-013 为准 |
| DI-002 | Architecture | `docs/LIMA_Issue66_Minimal_Local_Artifact_and_Parallel_Plan_2026-10-10.md` | SHA-256 `0b9facf8…4ef4` | 首片功能边界、协议雏形、验收组 | 设计输入（已确认方向） | 从 DI-001/DI-013 |
| DI-003 | Decision | `.pv_tmp/issue66-local-log-2026-10-10/intent/Maintainer_Intent_MR-66-LOCAL-LOG-FIRST-20261010_v1.md` | SHA-256 `e1de6fff…3c84` | 三项既定选择、授权边界 | evidence | 从 DI-013 |
| DI-004 | Finding | `.pv_tmp/issue66-local-log-2026-10-10/INDEX.md`（任务索引） | 2026-10-10 快照（`eead37ac…d845`） | 恢复事实、开放 PR 零交集 | evidence | 过时时以远端实时刷新为准 |
| DI-005 | Issue | #66 正文（V4+V5）与评论 5559178921/5559627362/5638380471 | spec revision 2026-09-11T17:39:36Z（快存 `recovery/issue66_body.txt`） | 18 个 requirement ID、Add/Modify/Read-only 文件面 | normative（需求真值；V5 优先） | 从 DI-013 |
| DI-006 | Standard | 治理文档三份 + 三角色责任书 | main `fbbbd619` | Packet 结构、PR 契约、角色边界 | normative | 无冲突 |
| DI-007 | Code | `lima/contracts/{common,codec,errors}.py` @ `fbbbd619` | git blob 亲验（§2.2） | Envelope/Reference/BlobReference/codec/limits 复用契约 | current-behavior + normative（冻结 wire 面） | 只读复用，不改 |
| DI-008 | Code | `lima/evidence_privacy/{port,models,policy,classifier,content_scan,fingerprint,errors}.py` @ `fbbbd619` | git blob 亲验（§2.2） | sanitize_for_sink 语义、SanitizedPayload/ClassificationManifest 字段、PrivacyLimits、policy_digest | current-behavior + normative | 只读复用，不改 |
| DI-009 | Code | `lima/store.py`、`lima/repository_cache.py` @ `fbbbd619` | git blob 亲验 | 只读参考：单事务建表、reserve/publish/abort、原子写+fsync 模式 | background-only | 不混用 repository snapshot 生命周期 |
| DI-010 | Code | `lima/contracts/profile.py:1183`、`lima/audit/inventory.py` @ `fbbbd619` | git blob 亲验 | 下一片边界登记 | background-only | 本片不展开 |
| DI-011 | Decision | Coordinator Assignment `ASN-D1-IP-0044-66-LOCAL-LOG/v1` 及附录 A/B/C | SHA-256 `d7c91f05…b976` | 20 条冻结清单（§7.8 继续有效）、18-ID 映射基线、文件边界 | normative（Assignment） | 被 DI-017 增量取代者以 DI-017 为准 |
| DI-012 | Finding | 设计探针 P1–P4 记录（probes/PROBE_LOG.md + 3 脚本） | 2026-10-10 实测（38 PASS / EXIT=0） | 形态判定、digest 实测、绑定实测、双预算、fail-closed | evidence（PASS ≠ 产品正确） | 与源码矛盾时停并上报（本轮无） |
| DI-013 | Standard | `docs/ZCODE_LONG_TASK_ISSUE66_PR283_D1_REPAIR_TO_IMPLEMENTATION_2026-10-11.md` | SHA-256 `e27009ae6576c218f8d27aaf47a113ad357d42fe272a32589367d16f75cc93b7`（本轮复算一致） | 六项修正规则原文（§4）、三段授权、记录修正、D2 覆盖组 | normative（Maintainer 指令正文；最高优先级） | 与其他输入冲突时以本文为准 |
| DI-014 | Decision | `docs/LIMA_Issue66_PR283_D1_Review_and_Ruling_2026-10-11.md` | SHA-256 `da11ba2f4f3f4df9de921f1564e5b75bd8717f4cfdcb2379f39a86da5bdf64d0`（本轮复算一致） | 六项定义与 v1.0 锚点（经 DI-013 采纳升格为修订方向） | normative（经 DI-013 采纳） | 从 DI-013 |
| DI-015 | Finding | `output/issue66-pr283-review-2026-10-11/probe_results.json`（同目录 review_probes.py、remote_snapshot.json、synthetic_fs、复跑结果） | 审核快照（本轮复读一致） | manifest 无 tenant_id/SanitizedPayload 有；262,119→365,378；case/dot alias 实测；坏 blob 复用协议模型 | evidence | 与 P5–P8 探针互证 |
| DI-016 | Decision | `.pv_tmp/issue66-local-log-2026-10-10/intent/Maintainer_Intent_MR-66-PR283-D1-REPAIR-20261011_v1.md` | SHA-256 `076fd1d79ebf4a87651fa61a3e61aa85845339898834955741a456b754aad7d7`（本轮复算一致） | 增量变化集、三段授权触发条件、技术偏好 | evidence | 从 DI-013 |
| DI-017 | Decision | Coordinator Assignment `ASN-D1R-IP-0044-66-LOCAL-LOG/v1`（assignment/D1R_ASSIGNMENT.md） | SHA-256 `de984a61956d2d7d39cfb80461a6243bd94bd8ddf6cae81e42e815f172e122af` | §7 六项修正规约、§7.7 十六行替换清单、§8 验收判据、§11 单值裁定 | normative（Assignment） | 与本派发矛盾时以 Assignment 为准并上报 |
| DI-018 | Finding | 旧 ER 记录（ERR-IP-0044-D1-v1/v2 及勘误链 71f81a08…731）与旧 Brief | **适用旧 head `1e6a6874`**（其「仅 P3」结论被 DI-013 否决） | SF-01（schema name 计数=18）复核事实仍有效；SF-04/SF-05/SF-07/SF-08 相关表述被 R66-03/04/06 取代或核销。**D1R 之 ER v4（`f2733c38…91f`）与 D1R Brief（`539361c0…d3a1`）适用旧 head `8377a6eb`，其「全部公共合同闭合」结论被 D1F 限定：16 组合只覆盖绑定/行存在/权威状态/声明状态，不含 expected digest、实际文件变化或资源结算** | background-only（历史证据） | 从 DI-013/DI-019 |
| DI-019 | Standard | `docs/ZCODE_LONG_TASK_ISSUE66_PR283_D1_FINALIZE_AND_CODE_DELIVERY_2026-10-11.md` | SHA-256 `d5f25d7b97966e405a5442cf3f578181268b5767c476cc3de9d4662e5a6147e5`（D1F 编制时复算一致） | §3=三项合同原文（R66F-01/02/03 修正方向）、§4=D1F 批次六步与首批退出条件、§5=获批后条件链 | normative（Maintainer 指令正文） | 与其他输入冲突时以本文为准（经 DI-023） |
| DI-020 | Decision | `docs/LIMA_Issue66_PR283_V2_Review_and_Next_Ruling_2026-10-11.md` | SHA-256 `1e3e4cfc86f9239baf0a83cf22e0ffd33c88e22637e1852bcfa908cb69f04f24`（D1F 编制时复算一致） | R66F-01/02/03 定义/锚点/反例；ER v4 扩展结论的限定（§4）；七例验收面（§5 R66F-02） | normative（经 DI-019/023 采纳为修订方向） | 从 DI-019/DI-023 |
| DI-021 | Finding | `output/issue66-pr283-v2-review-2026-10-11/review_v2_probe_results.json`（同目录 review_v2_probes.py/remote_snapshot.json/Packet_8377a6eb.md/复跑结果） | SHA-256 `df4bd895435eecb69c10713ecae864bf3e10e2d641a8143f1dd1e85bc0a4bb77`（D1F 编制时复算一致） | ①构造时序三例（3.0 拒且未进入/4.0、4.1 入）；②expected_digest 契约静态四事实；③orphan 反例（ledger=0/physical=1）；④524,288B 峰值反例；⑤两类证据分类（API 实测 vs 协议模型） | evidence（引用时不得越类：①为 API 实测、③④为协议模型、`is_product_test=false`） | 与 D1F 探针 P9–P11 互证（DI-024 性质，登记于 PROBE_LOG） |
| DI-022 | Decision | `.pv_tmp/issue66-local-log-2026-10-10/intent/Maintainer_Intent_MR-66-PR283-D1F-20261011_v1.md` | SHA-256 `6f8a2eecd20f1c6d9fdfee7c1396fe5451f5475e9d2c61c0c8cad16af0a96bf5`（D1F 编制时复算一致） | D1F 增量变化集、技术偏好、未确定事项下移清单 | evidence | 从 DI-019/DI-023 |
| DI-023 | Decision | Coordinator Assignment `ASN-D1F-IP-0044-66-LOCAL-LOG/v1`（assignment/D1F_ASSIGNMENT.md） | SHA-256 `c078ae92e4b46f3297f08647924f6bc2b9219b8ad78a82a2a6117f8fa6c01150`（D1F 编制时复算一致） | §7.1–7.3 三项规约、§7.4 十五行替换清单、§8 验收判据、§11 十五条单值裁定（含 ⓪形状/比较次序、RESERVED 载体、诊断行取消、四态映射、journal 公式、行 5 双口径、行 7 单位、524,288B 分别预留、fail-closed 范围、R66F-03 归属、44/18-ID/签名三不变）——**其中 §11.6（journal 行数公式）与「metadata 增量=计划写入行字节合计」口径被 DI-028 §11 显式取代，其余继续有效** | normative（Assignment） | 与本派发矛盾时以 Assignment 为准并上报 |
| DI-024 | Standard | `docs/ZCODE_LONG_TASK_ISSUE66_SQLITE_RESOURCE_CORRECTION_AND_CODE_2026-10-12.md`（RC 说明书） | SHA-256 `b558b020f6021837aea6657e9100c33d4c862b1e58e011380a16711c78a3845a`（RC 编制时复算一致） | §3=物理预算纠正、§3.1=机制选择与要固定什么、§3.2=计费口径、§4=共享 blob 唯一结算五条规则原文、§5=批次六步与退出条件、§6.2=D2 接续义务 | normative（Maintainer 指令正文） | 与其他输入冲突时以本文为准（经 DI-028） |
| DI-025 | Decision | `docs/LIMA_Issue66_PR283_V21_Full_Review_and_Ruling_2026-10-12.md`（第三轮审核） | SHA-256 `0db42724343aa65a38c39ff4ba08c141e709d0156de9992de29c3eb77d675090`（RC 编制时复算一致） | R66S-01 定义/锚点/反例（§4）；R66S-02（§5）；D2 接续义务（§6）；轻量勘误（§7） | normative（经 DI-024/028 采纳为修订方向） | 从 DI-024/DI-028 |
| DI-026 | Finding | `output/issue66-pr283-v21-review-2026-10-12/capacity_probe_results.json`（同目录 sqlite_capacity_probe.py/原 Packet 快照/remote_snapshot/复跑日志，只读） | SHA-256 `4336a9cf5a3b700a68fce7ec8683d416084b4144d2762f1ee618a5d6b9a52fcd`（RC 编制时复算一致） | ①真实 SQLite 3.45.3/page 4096/每行<8,192 B：1–5 行公式成立（样本）、8 行 66,176>57,344、12 行 99,008>73,728 被推翻（**对一般行数公式的反例，非已实现 LIMA 事务超限**）；②P10 初始 lhs=0 vs 实际 `metadata.sqlite3`=28,672 B（`model_includes_existing_db_file_bytes=false`）；③共享 blob 结算反例 objects 1→2、actual_unique_blob_files=1、is_product_test=false（**原协议模型反例，非产品缺陷**） | evidence（引用不得越类） | 与 RC-P1..RC-P4 探针互证 |
| DI-027 | Decision | `.pv_tmp/issue66-local-log-2026-10-10/intent/Maintainer_Intent_MR-66-PR283-RC-20261012_v1.md`（RC Intent） | SHA-256 `3feaae96f54d989805784eaf54ff2046cef66c6cc2733da7f08aa448578e10ff`（RC 编制时复算一致） | RC 增量变化集、技术偏好、已授权下移清单 | evidence | 从 DI-024/DI-028 |
| DI-028 | Decision | Coordinator Assignment `ASN-RC-IP-0044-66-LOCAL-LOG/v1`（assignment/RC_ASSIGNMENT.md） | SHA-256 `a555f9afe27bd0fc48348bff806e5ead4c509ccba3ff9116d9d61aa072392030`（RC 编制时复算一致） | §7.1 R66S-01 规约（九形状目录/页级公式与五前提/推翻义务/计费口径/独立 Oracle）、§7.2 R66S-02 五条规则+零新表方案+六场景四维度、§7.3 D2 接续义务、§7.4 R1–R17 替换清单、§8 验收判据、§11 单值裁定（机制①单选、零公共限额变更、页级公式、exact 表示=seal_attempts.blob_id、计费细则、D2 policy 规则、例值处置=重算重写、三不变） | normative（Assignment） | 与本派发矛盾时以 Assignment 为准并上报 |
| DI-029 | Finding | ER Record v5（`ec5ce8d55c5ca76a4f89ba64b6b789e5be95f89e0f0362d6d38b59ceb0191592`）、ER v6（`a55b3e6995ce5c12cd2949004eee9edd039e3dfb1bde884833d0cf9e594a52d6`）、D1F Brief（`c0438620521b7aeed5dc8549d120a492cc2c574bd690a6a1a0890eabac9e7ff4`） | **适用旧 head `1e223326`**（DI-028 §3.5/§7.5 裁定） | 其算术/RESERVED 修正闭合结论仍成立（例⑥ 269,536 等事实保留）；**其 root/journal/共享 blob 保证被 R66S-01/02 反例限定**——ER v5 的 journal 核验只复算 J(1..5) 与页大小、未测事务内高水位；ER v6 增量结论不补物理层证明；Brief 的 READY 只适用旧 head。本轮修订后须锚定新 head 的独立 ER 增量（Assignment §1 后续角色链②） | background-only（历史证据，结论限定登记；不改旧文件） | 从 DI-024/DI-025/DI-026/DI-028 |

### 2.2 关键源码复核（@fbbbd619 git 对象，本 Packet 编制时亲验）

`sanitize_for_sink(EvidencePayload, SinkContext, TenantPolicy)`（port.py，fail-closed）；sink allowlist
`{"storage","log","prompt","api","export"}`（policy.py:17-19）；**`SanitizedPayload`（models.py:215-221）
字段=`sink_kind`/`tenant_id`/`manifest`/`redacted_value`——`tenant_id` 在 SanitizedPayload 上；
`ClassificationManifest`（models.py:203-211）字段恰为 `classification`/`retention_class`/
`policy_version`/`policy_digest`/`entries`/`created_at` 六项，无 `tenant_id`**（P5 真实 API 实测与
DI-015 一致）；**`policy_digest(policy)`（policy.py:28-30）=`compute_content_digest(policy.digest_source())`**；
text 输出形态（classifier.py：PEM/URL 凭据→RESTRICTED 或敏感关键词→SENSITIVE 均返回
`FingerprintRecord`；bare-Base64 span→占位符替换 str；其余→NFC str）；`PrivacyLimits`（models.py:83-87：
32/1 MiB/256 KiB/10k/1000ms）；`ContractLimits`（codec.py:38-43：1 MiB/32/10k/1k/256 KiB）；
`compute_content_digest(bytes)=raw SHA-256 hex`（codec.py:187-196）；Envelope/Reference 规则
（common.py：schema name pattern/≤128B、identifier pattern `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`、
64-hex digest、payload XOR blob_ref、`content_digest==blob_ref.content_digest` hmac 比较、lineage
同租户/同快照/禁自环、4.0 禁 extensions；**`ArtifactReference`（common.py:328-349）六字段=
`schema_name`/`schema_version`/`artifact_id`/`tenant_id`/`repository_snapshot_digest`/
`content_digest`**——get 六字段绑定对象，§4.2 G3）；`TaskStore._init` 单事务建表；
`RepositoryCache` reserve/publish/abort + 原子写 + 目录 fsync。

### 2.3 Explicitly Rejected Inputs

| 被否决项 | 理由 | 出处 |
|---|---|---|
| 单 IP 全承载 #66 全范围 | 显著扩大实现与验收面 | DI-002 §3；DI-001 §5；DI-017 §2 Not-covered |
| prompt/展示/wire 层掩码替代存储前净化 | 净化点必须前置于任何持久化 | DI-001 §4.2、§7 |
| 机械沿用原 Issue「事务写 SEALED metadata→原子 rename」顺序 | 读者见 SEALED 而 blob 未就位的可见窗口 | DI-001 §4.4（DR-PACKET-1） |
| 先实现 S3 SDK / 多后端配置框架 / 插件注册器 / 动态 schema 平台 | 过度设计 | DI-001 §4.1、§9 |
| 全局跨租户 blob 去重或经错误信息泄露他租户对象 | 跨租户必须隔离 + 拒绝不可区分 | DI-001 §4.3 |
| Artifact store 不可用时回退 inline 巨型 JSON / 旧 task report_json | V5-FR-04 禁止静默降级 | DI-005 V5 节 |
| 修改共享契约或既有 schema 版本/公共字段/默认预算以适配本片 | 文件边界禁改；新类型走新增文件 | DI-001 §3；DI-017 §6 |
| 根检出 HEAD 作为源码依据 | 根检出落后；以 `fbbbd619` git 对象读取 | DI-001 §2；DI-004 |
| 用 canonical JSON 摘要或 metadata 整体身份充当封存字节摘要 | digest 必须来自实际净化后封存字节 | DI-001 §4.1；probe P2 |
| **`manifest.tenant_id` 检查层级（v1.0 S2 旧文）** | ClassificationManifest 无该字段（真实 API 实测）；检查 SanitizedPayload.tenant_id | R66-01；P5；DI-015 |
| **blob 复用「见在即用」+ 无条件 `os.replace` 覆盖发布** | seal 成功条件必须含既有实物受控核验；覆盖不是不可变保证 | R66-02；P8 模型；DI-015 |
| **原始 `<tenant_id>` 直作路径组件** | Windows 大小写/尾点目录混叠实测（P6 对照组） | R66-03；P6；DI-015 synthetic_fs |
| **先写 content.bin 再查净化输出预算（v1.0 S3→S4 时序）** | 超限内容已完整落盘，与 NFR-01 矛盾；膨胀反例 262,119→365,378 | R66-04；P7；DI-015 |
| **WAL/DELETE 双轨可选带入 D2** | Assignment §7.5 第 7 条要求单值选定 | R66-05；DI-017 |
| **「尾随空格已被 identifier 接受」表述** | identifier 字符类不含空格 | R66-03；P6-e；DI-015（trailing_space_contract_valid=false） |
| **零散限额行（无作用域/计额/预留语义）** | 统一限额表（R66-05 列规范）取代 | R66-05；DI-013 |
| **journal 行数公式 `4096×(N+2)+16384` 作为安全上界（含乘二/换例值变体）** | 真实 SQLite 反例推翻（8 行 66,176 B、12 行 99,008 B）；页级公式+前提+推翻义务取代 | R66S-01；DI-026；RC-P1 |
| **机制②固定有界预留区（替代 max_page_count 的资源机制）** | Coordinator 单选裁定机制①（Assignment §11.1）：②同样须给 sizing 依据且运行时强制更弱、永久占额降利用率；不带②入 D2 | RC Assignment §11.1 |
| **共享 blob per-attempt orphan 判定（「当前 attempt 无 artifacts 行即 orphan」）** | 被同租户同 digest 共享场景推翻（对象账 1→2 而唯一物理文件恒 1——原协议模型反例保留为回归反例）；物理键引用判定+U 对账取代 | R66S-02；DI-026；RC-P4 |
| **为在途登记新建表/新列/公共接口** | Coordinator exact 表示单选=复用 `seal_attempts.blob_id`（零新表/零新列/零新公共接口；行 10 组成不变） | RC Assignment §11.4 |
| **seal 返回 `content=b""` 双语义** | 「未读取」与「真实空日志」歧义；分型消除 | R66-06⑤；DI-017 §11.10 |

## 3. Goal / Non-goals

**Goal**（对齐 Assignment §2 与说明书 §1）：在 `fbbbd619` 之上新增 `lima/artifacts/`，交付
「脱敏 UTF-8 日志 Artifact 存取」的本机可运行闭环：真实净化前置（可信 policy 显式注入）、
输出校验先于落盘、blob/metadata 双介质明确提交点（发布前实物核验+跨进程临界区）、跨进程重启
读回并独立核验（六字段绑定）、租户隔离（逻辑精确+hash 物理键）、幂等/并发语义、有限资源与
路径防护、故障点可诊断；配 `tests/artifacts/` 行为验收（D2 冻结）与 `python -m
lima.artifacts.demo` 本机示例。

**Non-goals（本片不做，均为顺序安排而非删除 mandatory）**：PostgreSQL；历史 report_json 迁移；
TTL/GC/pin/tombstone/删除接口；lineage DAG 与多领域 dispatch；S3 后端与 SDK；service/API/UI/queue
接线；真实模型客户端；migration registry（FR-05）；retention 规则执行（FR-06）；真实 Profile
hydration/provenance（下一片，DI-010 边界登记）；多用户身份体系（触发即 DR）；跨租户共享。

## 4. 协议：类型契约、提交点与状态机（D1 §7 条款 1–5、12–16，经 R66 修正）

### 4.1 冻结的类型身份（条款 1、2、3、4、5、6、9）

| 冻结项 | 值 | 依据/复核 |
|---|---|---|
| schema name | `lima.sanitized-log` | 匹配 `_SCHEMA_NAME_PATTERN`，18 字节 ≤128B；与 main `fbbbd619` 既有 18 个 `lima.*` schema name（`*_SCHEMA_NAME` 常量口径亲验，经 ER 独立复核一致——ERR-IP-0044-D1-v1 第 25 项/SF-01，DI-018）零冲突；设计探针实测（probe P3）通过契约校验 |
| schema version | `4.0`（`SchemaVersion(4,0)`；仅此一个值，4.1+ 在本片 get/stage 均拒绝） | 4.0 是禁 extensions 的当前次版本 |
| 编码 | UTF-8（封存字节 = 净化后 str 的 `encode("utf-8")`） | 条款 10；probe P2 |
| media type（blob_ref.media_type） | `text/plain` | 契约 `_MEDIA_TYPE_PATTERN` 不接受 `; charset=` 参数（common.py:60-62 亲验）；UTF-8 编码作为本片不变量单列 |
| digest | `compute_content_digest(sealed_bytes)`（raw SHA-256 hex，bytes 入口） | 条款 3；probe P2 实测；同字节稳定 |
| wire 容器 | 复用 `ArtifactEnvelope`/`ArtifactReference`/`ArtifactBlobReference` + `encode_envelope`/`decode_envelope`；payload XOR blob_ref（本片恒 blob-only）；**wire 格式不改（R66-06⑤）** | 条款 2；probe P3 往返全等 |
| lineage/supersedes | 仅空 `lineage=()`、`supersedes=None`；公共 stage 不开放 lineage/supersedes 参数；envelope helper 强制空 lineage/无 supersedes——构造器实际接收对应字段时对非空**明确拒绝**（`UNSUPPORTED_LINEAGE`） | 条款 5；R66-06④；probe P3-C（契约层接受合法非空 lineage ⇒ 拒绝必须落产品层） |
| classification/retention 接受面 | 接受 = `redacted_value` 为 **str** 且 `classification ∈ {internal, sensitive}` 且 `retention_class == standard`；三条件任一不满足（RESTRICTED、整值 SENSITIVE/RESTRICTED 的 FingerprintRecord 形态、bytes/JSON 形态、非 standard retention）→ `UNSUPPORTED_REDACTED_FORM`，零内容落盘 | 条款 6、9；probe P1/P5（P5-g：clean=internal/str、span=sensitive/str、pem=restricted/FingerprintRecord） |
| 上下文 | tenant/task/workflow/attempt/snapshot/producer/toolchain 全部必填真实值（identifier/digest 校验）；**policy 必填显式注入（open 时绑定，§5.3）**；禁止全零或占位 | 条款 4；R66-06①；probe P3 |

补充：`repository_snapshot_digest`/`toolchain_digest` 为 64-hex（调用方按真实快照/工具链身份
计算）；`policy_digest` 必须等于实测 `lima.evidence_privacy.policy.policy_digest(policy)`（注入
policy 实算，不信 producer 自报——本片 ProducerContext 不含 policy 字段；probe P1/P3/P5 一致性
实测）；`created_at` 由 store 在 seal 时生成 UTC RFC3339（契约归一化 `.ffffffZ`）。

### 4.2 提交点协议与对原 Issue 文字的处置（条款 15——呈批项 DR-PACKET-1；R66-01/02/04/06 + D1F R66F-01/02 修订）

**本片冻结协议**（stage/seal/get；任一步失败即中止且不返回成功引用；协议顺序单值，
R66F-02 改写：S0 输入预检 → S1 净化 → S2 输出校验 → R1 预留事务 → S3 有界写入 →
S4 重读复核 → seal〔⓪ 参数形状 → ①–⑤ 权威状态判定 → 实物完整性核验 → expected 比较
→ R2 预留事务 → P1 发布 → P2 commit → P3 回执；SEALED 幂等分支：③ blob 核验 →
expected 比较 → 返回同一回执〕→ get G1–G6）：

```text
stage_log(text, producer)
  S0  入口预检【纯输入/上下文预检——R66F-02：零写入、无预留、无账本交互；额度检查+
      预留已移至 S2 全部通过之后的 R1 预留事务；输入检查与输出检查分开的两步之一，
      R66-04】：
      text 为 str 且 UTF-8 可编码（lone surrogate → INVALID_TEXT_ENCODING，零写入）；
      输入 UTF-8 字节数 ≤ 有效输入上限=交集（max_input_bytes ∩ 注入 policy.limits.
      max_string_bytes ∩ codec 上限）（INPUT_BUDGET_EXCEEDED，零写入）；
      producer 各字段 identifier/digest 校验（INVALID_ARGUMENT，零写入）
  S1  真实净化：sanitize_for_sink(EvidencePayload("text", text, "text/plain"),
      SinkContext("storage", tenant_id=store 绑定可信租户, tenant_key), policy)
      ← policy=open 时必填显式注入；原文只在有界内存
  S2  输出校验【在任何 content staging 写入之前，R66-04；写前四查，单值次序】：
      a. 输出类型：redacted_value 必须 str（FingerprintRecord/bytes/JSON →
         UNSUPPORTED_REDACTED_FORM，零内容落盘）
      b. 租户绑定：SanitizedPayload.tenant_id 必须 == store 绑定可信 tenant（精确比较，
         不归一化；真实字段层级——ClassificationManifest 无 tenant_id 字段，R66-01；
         不符 → SANITIZATION_FAILED 绑定类，零内容落盘）
      c. manifest 分项核验：manifest.policy_digest == 实算
         lima.evidence_privacy.policy.policy_digest(policy)（不符 → SANITIZATION_FAILED
         策略类，零内容落盘）；manifest.classification ∈ {internal, sensitive} 且
         manifest.retention_class == standard（§4.1 接受面）
      d. 净化输出 UTF-8 字节数 ≤ 有效封存上限=交集（max_sealed_bytes ∩ 注入
         policy.limits.max_string_bytes ∩ codec 上限；不得回填更宽默认）
         （SEALED_BUDGET_EXCEEDED：零内容文件、零正文入库、**零持久诊断行**——
         R66F-02 取消净化失败持久诊断行，失败信息走有界错误输出〔bounded 元数据，
         §6.1〕，不含内容/凭据）
  R1  预留事务【S2 全部通过之后、任何文件 IO 之前；R66F-02 唯一形态：seal_attempts
      行承载预留，不建独立 reservations 表】：
      临界区内独立提交事务 INSERT seal_attempts 行 state=RESERVED（attempt 生命周期
      内部状态；**artifacts 表状态仍只有 STAGING/SEALED——RESERVED 不入 artifact
      状态机**），携带预留字段（**v2.2 页 denomination，R66S-01**）：reserved_staging_bytes
      （=净化输出字节数，S3 段内容峰值）、reserved_metadata_bytes（=本段 DB 物理页
      增长预留 Δpages×P，按 §7.3 形状目录 T-R1 的派生页数——**取代 D1F「计划写入
      行字节合计」口径；行 9 的行字节上界只是单条记录逻辑校验界、非计费单位，row
      bytes 与 DB bytes 不双计**）、reserved_journal_bytes（=§7.3 页级公式
      journal_headroom(T-R1)）；13 维账本行同事务 +N；行 7 live-staging 名额即占
      （RESERVED 也占——新 stage 不是免费重试）；保守预留超过剩余额度 →
      CAPACITY_EXCEEDED 先拒绝（零提交）；**预留事务提交点=该事务 commit；此后才
      允许 staging 文件 IO**（进程死亡不丢账——预留先于文件 IO 已持久化；P9 SQLite
      实测：预留事务独立提交，后续事务回滚不吞预留行）
  S3  有界 staging 写入：staging_id/artifact_id 系统生成；净化后字节按上限有界写入
      root/staging/<staging_id>/content.bin（O_CREAT|O_EXCL + fsync；写入原语达到上限
      即停止并失败——不允许「先完整写盘再拒绝」）
  S4  staging 完整性复核【职责：只防写入损坏，不再承担首次预算判定（R66-04）、
      **不涉及 expected_content_digest**（R66F-01：expected 是 seal 调用参数，
      stage 的 S4 不检查稍后 seal 才传入的值）】：
      从 staged 字节重读并计算 len(bytes) 与 compute_content_digest(bytes)，与 S2 判定值
      一致（不一致 → 稳定失败 INTERNAL_STORAGE_ERROR 类，残留计额）；
      S4 通过后同事务 UPDATE seal_attempts RESERVED→STAGING：预留字段清零、按实际
      写入字节转实际占用账目（§7.1d/§7.1f）
seal_log(handle, *, expected_content_digest=None)
  【六段冻结次序，R66F-01：⓪ 参数形状 → ①–⑤ 权威状态判定 → 实物完整性核验 →
   expected 比较 → R2 预留事务（仅正常分支）→ 新发布/P2 commit 或幂等返回。
   「形状在入口、值比较在实物核验后」两句并立，不合并为一步（Assignment §11.1）】
  ⓪  参数形状校验（入口段；违反 → INVALID_ARGUMENT，零副作用——不触碰权威行/
      实物/账本；先于 ①–⑤，非法 expected + 缺行也判 INVALID_ARGUMENT 而非
      STAGING_NOT_FOUND，P9 次序演示）：
      expected_content_digest ∈ {None} ∪ {64 位小写 hex fullmatch}；handle 为
      StagedLogHandle 实例且字段形状合法（staging_id/root_id/tenant_id/created_at
      形状、declared_state ∈ {"staged","sealed"}）
  ①–⑤ 权威状态判定（CR-D1R-01 五步原样保留+CR-D1F-01 补裁 ②′，全函数见 §4.4）：①绑定
      不符/②缺行/②′权威行 RESERVED → STAGING_STATE_INVALID（CR-D1F-01，任何 declared_state）/
      ③SEALED 幂等可达/④方向性矛盾/⑤STAGING 正常路径
  实物完整性核验（root 临界区内**重新受控核验**——重读实际字节重算，不能依靠更早
      stage 的 S4 证明稍后复制/发布结果，R66F-01）：
      · ⑤ 正常 STAGING 分支：重核 staging 实际 size/digest 与权威记录值——fresh
        staging 四态映射（检查次序冻结：lstat〔含存在性〕→ size → digest）：非常规
        文件（目录/FIFO）/symlink/junction/reparse/路径越界 → PATH_POLICY_VIOLATION；
        缺失 → BLOB_MISSING；实际 size ≠ 记录 size → BLOB_SIZE_MISMATCH；实际
        digest ≠ 记录 digest → BLOB_CORRUPT（复用既有码，不新增专用码；与 P1 ②/③
        与 get G5 同一套映射）
      · ③ SEALED 幂等分支：核验已有实际 blob（既有 P1 ② 受控核验规则不变：
        lstat→size→digest）
  expected 比较【位于实物核验之后——不先于、不掩盖实物错误；错 expected 不掩盖、
      不替代实物错误码；比较不过 → SEAL_DIGEST_MISMATCH，不发布/不提交/不返回回执】：
      · 正常分支：在 P1 任何 publish 文件 IO 之前，与重核出的 staging 实际 digest 比对
      · 幂等分支：在 blob 核验通过之后、返回回执之前，与已核验 blob 的实际 digest
        （=权威记录 content_digest）比对——**正确 blob + 错 expected →
        SEAL_DIGEST_MISMATCH，不返回「因为已 seal 所以成功」**；不新增 SEALED、
        不覆盖原 blob/metadata，原状态不动
  R2  预留事务（仅正常分支；P1 之前；R66F-02+R66S-02）：UPDATE 同行写入发布段**新增峰值**
      预留（publish 副本字节 + DB 物理页增长预留 Δpages×P〔T-R2 与其预留的 T-P2 形状
      派生页数，§7.3；行 9 逻辑界不参与计费〕+ journal 余量〔§7.3 页级公式
      journal_headroom(T-R2)+journal_headroom(T-P2)——R2 段含其预留的 P2 事务〕）与
      **blob_id=staged 内容 digest（R2 提交即该物理键 `(tenant_storage_key, content_digest)`
      的在途登记，R66S-02 规则 2——零新表/零新列/零新公共接口；P1 后登记事务=不使用，
      §7.3 形状目录 T-P1reg）**，独立提交；**此后才允许 publish 临时文件 IO**；staging
      实际占用不重复扣、**publish 副本必须另扣**（524,288B 规则：262,144 B staging+
      同大小发布副本是至少 524,288 B 内容占用，同内容两份物理存在即两份占用，不可只扣
      一次内容字节）；**对象预留按物理键引用判定（R66S-02 规则 4）：物理键已被任何
      SEALED Artifact 或已登记在途 owner 引用 → reserved_objects=0，否则 1——对象数
      （行 4）已满不因此误拒同租户有效复用**；保守预留超过剩余额度 → CAPACITY_EXCEEDED
      先拒绝（零提交、零 publish IO）
  P1  临界区内三分支 blob 发布（R66-02；与 P2 同置于单 root 跨进程串行临界区，§7.1d）。
      目标路径 = root/blobs/<tenant_storage_key>/<d[:2]>/<d>/blob.bin（d=staged 内容
      digest；物理键见 §4.4/§7.2）：
      ① 无目标对象 → 同目录临时文件 + fsync + 原子 rename 发布（rename 仅在目标不存在
         的核验之后作为发布原语，不无条件覆盖已存在对象）；rename 后目录 fsync（Linux）/
         平台声明（Windows，§7.4）
      ② 目标已存在 → 受控、有界核验既有实物后方可复用（租户内内容寻址去重，仅 blob
         层）：常规文件（非 symlink/junction/reparse，lstat 判定）→ 实际 size == 记录
         size → 实际 SHA-256 == 目标 digest（此核验次序冻结）
      ③ 竞态分支（核验与发布之间目标出现，含不合规范外部写入者）→ 按 ② 同等核验：
         通过 → 复用；失败 → 按下行失败语义
      核验失败（任何分支）→ 本次 seal 稳定失败：不新增 SEALED metadata、不覆盖/修复/
      改动原内容与原 SEALED 记录；错误映射（复用既有码，不新增专用码）：链接/reparse
      异常、非常规文件（目录/FIFO 等）→ PATH_POLICY_VIOLATION；实际 digest 不符 →
      BLOB_CORRUPT；size 不符 → BLOB_SIZE_MISMATCH；幂等重试发现实物缺失 →
      BLOB_MISSING。失败残留（staging 文件与 attempt 行）按 §7.1 统一限额表计额；
      失败结算=释放**未实际使用**的预留（独立事务清零预留字段），已写出的 staging/
      publish 临时文件/orphan 继续按实际占额（R66F-02，§7.1f）
  P2  同一临界区内 SQLite 单事务（BEGIN IMMEDIATE）提交可见 SEALED metadata：insert
      artifacts 行、seal_attempts STAGING→SEALED、**预留转实际占用（按实际字节数
      落账）、预留字段清零、行 7 live 名额释放**（attempt 行仍占行 10 记录额度、
      staging 文件目录标记可清理但不自动删——残留仍占行 5，R66F-02）
  P3  返回 SealedLogReceipt(reference, envelope)   ← 成功可见点 = P2 commit；
      回执无 content 字段（R66-06⑤：结构上消除「未读取」歧义）
  幂等分支（③）：blob 核验 + expected 两关都过 → 直接返回**同一** SealedLogReceipt
      （无 R2/P1/P2；不新增 SEALED、不覆盖原 blob/metadata）
get_log(reference)   【六步校验顺序冻结，R66-06②；错误映射单值】
  G1  Reference 结构/格式校验（六字段形状：schema_name pattern、identifier、64-hex、
      SchemaVersion）→ INVALID_ARGUMENT
  G2  schema 接受面（`lima.sanitized-log`/`4.0` 之外）→ UNSUPPORTED_SCHEMA——仅指
      **实际可传入本入口的对象**：错误 schema_name 的合法 Reference、合法 4.x 非本片
      minor（如 `4.1`，构造成功可传入，P11 实测进入被调函数）；**调用者构造 Reference
      失败（含 `SchemaVersion(3,0)` 构造期 SCHEMA_UNKNOWN_MAJOR 及同族）归
      foundation/caller——get 未被进入、不映射为任何存储错误**（R66F-03 真实归属，
      §6.1 映射注；不新增 raw/dict Reference 解析 API、不改 #58 构造器）
  G3  租户绑定 + 权威记录查询：store 绑定受信租户 vs reference.tenant_id；仅 SEALED 行
      可读；租户不符、未知 artifact_id、未封存、**或六字段（schema_name/schema_version/
      artifact_id/tenant_id/repository_snapshot_digest/content_digest）任一与权威记录
      不一致（含合法格式但错误的 repository_snapshot_digest/content_digest）**→
      ARTIFACT_NOT_FOUND（租户不符与对象不存在不可区分；不得验证内部三方一致后忽略
      传入错误引用）
  G4  envelope/blob 校验：envelope_wire 解码与 blob_ref 绑定（契约错误映射
      METADATA_CORRUPT/BLOB_CORRUPT，不透传原始异常文本）
  G5  实际字节核验：读取实际 blob 字节（有界，读放大上限 §7.1），重算 size 与
      compute_content_digest 与 metadata/envelope/blob_ref 三方比对 →
      BLOB_MISSING/BLOB_CORRUPT/BLOB_SIZE_MISMATCH
  G6  返回 RetrievedLogArtifact(reference, envelope, content)——content 恒为已验证封存
      字节；合法空日志 b"" 仅在该对象出现且语义唯一；绝不返回未核验字节
```

**对 #66 原文「先写临时 blob→fsync/verify→事务写 SEALED metadata→原子 rename」的处置声明
（呈批项 DR-PACKET-1；v2.2 更新：R66-02 两前提〔既有 blob 有效复用与并发发布不覆盖〕已由 v2.0
落地为三分支核验+临界区规则、R66F-01/02/03 已由 v2.1 收口；**本轮剩余=R66S-01/02 收口**，
处置随 v2.2 新 head 一并呈批，未获批前不视为已批准）**：
本片**保留原文全部四个元素**（临时写、fsync/verify、事务化 SEALED metadata、原子 rename），但把
**原子 rename 移到 metadata 事务之前**（P1→P2）。理由与证明：成功可见点唯一化为「SQLite 提交
可见 SEALED metadata」（P2）；由于 rename（P1）先于该点完成，**且 P1 三分支核验保证「已存在即
有效、否则本次 seal 稳定失败」、发布与 P2 同置于单 root 跨进程串行临界区保证并发发布不覆盖已
存在有效对象（R66-02）**，任何读者在看到 SEALED 引用之时 blob 必已完整发布且可验证——读者无
不完整可见窗口；幂等重试同样核验实物+核对本次 expected（R66F-01），不因 DB 行返回假成功。崩溃
残留对照：本协议在 P1 后 P2 前崩溃留下**可诊断的已发布 blob**（无 artifacts 行，读者不可见）；
**该 blob 的物理键已由 R2 提交在 `seal_attempts.blob_id` 在途登记（R66S-02 规则 2），重开结算
按物理键引用判定其被在途 owner 引用——不按「当前 attempt 是否有自己的 artifacts 行」误判
orphan、不搬走、不重复收费；其占用由 R2 预留覆盖并按 §7.1f 状态表转实际（预留转实际、对象按
唯一物理键首计），不因释放预留漏账（§7.1f 例③/③b）；真正未被任何引用的 true orphan 才按唯一
物理键首次入账（§7.1d 对账协议）**；reconcile 分类覆盖原文要求的 orphan/metadata-only 集合。
**覆盖范围**：本处置针对本片本机 SQLite+文件后端；未来 PostgreSQL/S3 适配器必须在同一不变量
（读者永不见「SEALED 而内容未完整发布」）下重新推导，不继承本结论。

### 4.3 状态机与故障点状态矩阵（条款 12、16；R66-02/04/05 + D1F R66F-01/02 同步）

Artifact metadata 状态本片仅使用 `STAGING`、`SEALED`（FR-02 允许集的子集；`QUARANTINED/
EXPIRED/DELETING` 不出现：corruption 不改状态、在 G5 读时 fail closed，recovery 只诊断/隔离
（可将损坏 blob 文件移入 `root/quarantine/`，不动 metadata、不虚造 SEALED、满额时拒绝移动而
诊断照常，§7.1 行 11）、不自动删除）。**`RESERVED` 仅是 `seal_attempts` 行的 attempt 生命周期
内部状态（R66F-02），不入 artifact 状态机。**

| 故障点 | blob 实物 | metadata（SQLite） | 重启后分类 | get 行为 |
|---|---|---|---|---|
| S0–S2 崩溃（含 S2 输出校验失败：超限/形态/绑定/digest 不符） | 无任何写入 | 无行（S2 失败零持久行——诊断行已取消，R66F-02） | 干净 | 无引用存在 |
| R1 预留事务后、S3 前 kill（**R66F-02 新增**） | 无内容文件 | seal_attempts RESERVED 行（预留字段非空） | 预留行（结算→空预留解除，行保留为记录，§7.1f 例①） | 无引用存在 |
| S3 有界写入中崩溃（或达到上限即停） | 部分 staging 文件（≤上限） | RESERVED 行（写中；S3 完成事务未提交） | `staging`（未完成；结算→staging 按实际字节转实际占用，§7.1f 状态表行 2） | 该 staging 无引用可 get |
| S3/S4 完成后、seal 前 | staging 完整 | STAGING 行（预留字段空、实际占用已计） | `staging`（结算 no-op） | 同上 |
| P1 临界区内临时文件写/fsync 中 | publish 临时文件 | STAGING 行（R2 预留字段非空） | `orphan`（临时；结算按实际占额） | 无 SEALED 行 |
| P1 发布后、P2 前 | 最终 blob 就位 | STAGING 行、无 artifacts 行、**blob_id 已在途登记（R2 提交，R66S-02）** | `orphan`（按物理键引用判定=被在途 owner 引用——不搬走、不重复收费；占用由 R2 预留转实际；**对象按唯一物理键首计，per-attempt 误判〔对象 1→2〕不可达——R66S-02 回归反例见 §7.1f**；§7.1f 例③/③b） | 调用者从未获得引用；伪造 id → ARTIFACT_NOT_FOUND |
| P1 ②/③ 核验既有实物失败（坏/链接异常/缺失） | 原实物保持原样（不覆盖/修复/改动） | STAGING 行（**无新增 SEALED**） | `staging`/`corrupt` 诊断 | 无新增引用；残留计额（§7.1） |
| **stage 后 staging 被改坏（截断/篡改/删除/替换为链接或目录），seal 重核（R66F-01 新增）** | staging 损坏/缺失/异常 | STAGING 行（无新增 SEALED） | `staging`/`corrupt` 诊断 | **seal：按 fresh staging 四态映射拒绝（PATH_POLICY_VIOLATION/BLOB_MISSING/BLOB_SIZE_MISMATCH/BLOB_CORRUPT，次序 lstat→size→digest），零发布、零新增 SEALED、预期比较不掩盖实物错误**；该 staging 无引用可 get |
| P2 事务中崩溃 | 最终 blob 就位 | DELETE hot journal → 重启自动回滚：有 artifacts(SEALED) 行或无 | 有行=完全成功；无行=上一种 orphan | 有行则 get 正常且 G5 全过 |
| P2 后、P3 返回前 | 就位 | SEALED（预留全转实际、live 名额已释放） | 完全成功 | 同 handle 幂等重试返回同一 artifact（且核验实物+核对本次 expected，R66F-01） |
| SEALED 后 blob 被外部删除/篡改/截断 | 缺失/异字节 | SEALED | `metadata-only` / `corrupt` | get：BLOB_MISSING/BLOB_CORRUPT（fail closed，metadata 不丢） |
| **SEALED 后实物损坏时重复 seal（同 handle 幂等重试）** | 损坏/缺失 | SEALED | `corrupt` | **seal 稳定失败（BLOB_CORRUPT/BLOB_SIZE_MISMATCH/PATH_POLICY_VIOLATION/BLOB_MISSING 按核验项映射），非假幂等；原 metadata 不改动** |
| **SEALED 后以错 expected 幂等重试 seal（R66F-01 新增）** | 完好 | SEALED（原状态不动） | 完全成功（既有 SEALED 不变） | **seal：SEAL_DIGEST_MISMATCH——正确 blob+错 expected 不返回回执、不新增 SEALED、不覆盖 blob/metadata；get 行为不受影响** |

get 永远执行 G5 实物核验，绝不只信 SEALED 字符串（条款 16；另据**设计探针实测（probe P3-A）**：
wire 上保持内部一致的 digest 篡改能通过契约层——契约层看不到字节，故 G5 的字节级重算比对是
mandatory 不可省略）。`inspect()`（recovery 入口）输出 staging/orphan/metadata-only/corrupt 四类
分类 + 计数（扫描有界，§7.1 行 10/11），不删除、不重构、不虚造。

### 4.4 身份键、幂等与并发（条款 14；R66-02/03 修订）

- **Artifact 身份键** = `(tenant_id, artifact_id)`；`artifact_id = "art-" + uuid4hex(32)`（系统
  生成，identifier 合法）。**同字节 ≠ 同身份**：不同 stage 调用各自生成 artifact_id；metadata
  身份、上下文、身份绑定不因 blob 去重合并。
- **blob 物理键** = `blobs/<tenant_storage_key>/<digest[:2]>/<digest>/blob.bin`，其中
  **`tenant_storage_key = SHA256(tenant_id 的精确 UTF-8 字节).hexdigest()`（小写 64-hex；版本化
  内部规则 v1，与 root 元数据绑定，§7.2）**；`blob_id == content_digest`（64-hex）。blob 复用仅
  发生在**同租户同字节**（内容寻址 + 租户物理目录隔离），且复用前必须通过 P1 ② 受控核验
  （R66-02）；跨租户同字节各自独立 blob 文件，无全局去重。**逻辑身份不变**：SQL、
  ArtifactReference、ACL/权限比较仍按逻辑 `tenant_id` 精确比较（不 lowercase、不剥尾点、不合并
  租户）。
- **seal_log 状态判定（全函数，按以下次序唯一归属；CR-D1R-01 单值+CR-D1F-01 补裁 ②′。
  declared_state 为 handle 声明，权威=`seal_attempts` 行）**：
  ① handle 绑定 root/tenant 与当前 store 不符 → `STAGING_STATE_INVALID`（触发 (a)，不变）；
  ② 按 staging_id 查权威行：行不存在（无论 declared_state）→ `STAGING_NOT_FOUND`（**唯一
  归属**——无行即无可幂等返回的已 seal 身份；缺行是无法解析的身份，不是可矛盾的记录，两码
  触发面保持不相交）；
  ③ 行存在且 state=SEALED（declared_state 无论 "staged" 或 "sealed"）→ 幂等成功路径：
      **root 临界区内核验已有实际 blob（既有 P1 ② 受控核验规则：lstat→size→digest）→
      blob 核验通过后核对本次 expected_content_digest（与已核验 blob 的实际 digest=权威
      content_digest 比较；不符 → SEAL_DIGEST_MISMATCH——正确 blob+错 expected 不返回
      「因为已 seal 所以成功」，原状态不动）→ 两关都过才返回同一 SealedLogReceipt**
      （R66F-01）；blob 核验不通过 → 按 §6.1 seal 路径映射稳定失败。**「handle 声明
      staged + 权威行 SEALED」= 幂等重试的正常可达状态**（handle 为 stage 时签发的
      frozen 对象，seal 不重签发；含 P2 已提交未返回即崩溃后的重试），非矛盾；
  ④ 行存在且 state=STAGING、declared_state="sealed" → `STAGING_STATE_INVALID`（触发 (b) 的
      **STAGING 形态**：handle 声明强于权威行——过度声明，CR-D1R-01④；(b) 的 RESERVED
      扩展形态见 ②′〔CR-D1F-01〕）；
  ⑤ 行存在且 state=STAGING、declared_state="staged" → 正常 seal 路径：**临界区内重核
      staging 实物（重读实际字节重算 size/digest 与权威记录值——fresh staging 四态映射，
      §4.2 实物核验段）→ expected 比较（P1 任何 publish 文件 IO 之前，与重核出的 staging
      实际 digest；不符 → SEAL_DIGEST_MISMATCH）→ R2 预留事务 → P1→P2**（R66F-01/02）；
  ②′ 行存在且 state=RESERVED（任何 declared_state）→ `STAGING_STATE_INVALID`（CR-D1F-01
      补裁，判定位置=② 缺行检查之后、③ SEALED 分支之前——见下补裁原文）。
  即：§6.1 (b) 的「矛盾」按**方向性**定义——「handle 声明 sealed 而权威行为 STAGING」与
  「权威行为 RESERVED（handle 尚未签发，任何携带该 staging_id 的 handle 均为过度声明）」
  均构成矛盾（CR-D1R-01④+CR-D1F-01）。

  **CR-D1F-01 补裁（SF-D1F-02）**：权威行 state=RESERVED（预留已持久化、staging 身份未完成，handle 尚未签发）时，declared_state 无论 "staged" 或 "sealed" **均唯一归属 `STAGING_STATE_INVALID`**——任何携带该 staging_id 的 handle 都是对权威行的过度声明（CR-D1R-01 方向性矛盾原则的扩展形态，触发 (b)），只读失败、零副作用；**不按 ⑤ 正常路径处理**（不重核、不发布——伪造/竞态句柄不得推动在途预留进入验证/发布，不为其扩大并发面）；RESERVED 行的唯一处理通道是其所属 stage 操作自身与锁内结算（§7.1f 状态/动作表行 1–3）。
- **同请求幂等（强化，R66-02④+R66F-01）**：同一 staging handle 的 seal 重复/并发调用（含同 root 同可信
  租户跨实例/跨进程重开 handle 后、含 P2 已提交未返回即崩溃后的重试）按上列 ③ 返回**同一**
  SealedLogReceipt——由 P2 的单事务 + `seal_attempts.staging_id` 唯一约束裁决，后到者在事务内
  读到胜者已写的 artifact_id 并原样返回；**幂等成功同样执行实物完整性核验（核验已有 blob）
  并核对本次 expected_content_digest**（不只看 DB 行；任一关不过 → 按 §6.1 映射稳定失败
  〔实物错误按实物错误码、expected 不符 → SEAL_DIGEST_MISMATCH〕，不返回假成功）；不产生
  第二个 artifact。
- **并发重复 seal（不同 staging、同字节/不同字节）**：各自独立 artifact；先到者发布、后到者走
  P1 ② 核验复用；并发发布在临界区内**不覆盖已存在有效对象**；无 ACL 放宽面（本片 ACL 即租户
  绑定，无运行时放宽接口）。
- **跨进程协调**：R1/S3/S4 的预留与转换事务、R2 预留事务、seal 的 P1+P2 复合段、以及**重开
  结算（同 root 锁内先结算后写，§7.1d/§7.1f）**都在单 root 跨进程串行临界区内执行
  （有限等待；超时 → CONCURRENCY_LIMIT_EXCEEDED 零提交；崩溃 OS 锁自动释放，§7.1d）。
- **metadata 冲突**：同 `(tenant_id, artifact_id)` 已存在且字段值不一致 → `METADATA_CONFLICT`
  拒绝，绝不覆盖（UUID 下实际不可达，仍冻结为唯一约束违反路径的稳定语义）。
- **首片无公共 delete/update**（条款 14 末句）；SEALED 内容及其租户/身份绑定不可修改（无任何
  UPDATE 路径）。

### 4.5 权限与信任边界（条款 13；R66-06①/③ 修订）

- 信任边界 = 受控本机进程：`LocalArtifactStore.open(root, *, tenant, policy, limits=None)`
  （§5.3 逐字签名）在打开时绑定**受信租户身份**（tenant_id + tenant_key；key 仅驻内存，绝不
  持久化、绝不入错误信息）与**可信 TenantPolicy**（必填显式注入：不信 producer 自报摘要、不默
  用 DEFAULT_POLICY；policy_digest 一律用注入 policy 实算）。
- 调用者**不能**逐调用传入租户字符串充当身份；`reference.tenant_id` 只是声明，G3 以 store 绑定
  的受信租户比对，不符即 `ARTIFACT_NOT_FOUND`（与不存在同错误，杜绝存在性泄露）。
- **open 时 root 一致性核验**（R66-03/05）：`artifact_store_meta` 的 tenant-storage-key 映射
  版本不一致或可检测冲突 → `METADATA_CORRUPT` fail-closed（绝不落入另一租户目录）；limits
  指纹与既有绑定不一致 → `STORE_CONFIG_CONFLICT` 拒绝（零写入；不允许后开实例以更宽配置绕过，
  也不能借不同租户实例跳过 root 总上限，§7.1c）。
- 权限执行点 = metadata 查询（G3，租户等值过滤在 SQL 谓词中）与读取入口（G5 实物核验），双层；
  无跨租户共享、无运行时 ACL 放宽。
- 需要多用户身份体系、真实认证来源时必须提 DR（六类升 Maintainer 之一）；本片不声称防御拥有
  同等 OS 权限的恶意本机用户（§7.2 平台声明）。

## 5. 精确文件与符号（exact files 由 D2/IMPL Assignment 最终冻结，本节为 Packet 冻结的允许面、符号与公共合同）

### 5.1 Files

| 类别 | 路径 | 说明 |
|---|---|---|
| Add（产品） | `lima/artifacts/__init__.py` | 公共导出：`LocalArtifactStore`、`TrustedTenantContext`、`ProducerContext`、`ArtifactStoreLimits`、`StagedLogHandle`、`SealedLogReceipt`、`RetrievedLogArtifact`、`ArtifactStoreError`、`ArtifactStoreErrorCode`、`SANITIZED_LOG_SCHEMA_NAME` 等 schema 常量（**导出清单本轮冻结，R66-06⑤；旧 `SealedLogArtifact` 删除，不导出**） |
| Add（产品） | `lima/artifacts/schema.py` | 冻结类型身份常量 + `build_sanitized_log_envelope(...)`（校验型构造器；实际接收 lineage/supersedes 字段时对非空明确拒绝）+ `decode_sanitized_log_envelope(bytes)` |
| Add（产品） | `lima/artifacts/context.py` | `TrustedTenantContext`、`ProducerContext`（frozen dataclass；字段表见 §5.3；fail-closed 校验） |
| Add（产品） | `lima/artifacts/limits.py` | `ArtifactStoreLimits`（frozen dataclass；字段/默认/合法域=§7.1 统一限额表；域校验 fail-closed；提供 root 绑定用 canonical 指纹） |
| Add（产品） | `lima/artifacts/errors.py` | `ArtifactStoreError`/`ArtifactStoreErrorCode`（§6.1 稳定错误面 23 码，含新增 `STORE_CONFIG_CONFLICT`；错误串永不包含日志正文/凭据/绝对路径） |
| Add（产品） | `lima/artifacts/staging.py` | `StagedLogHandle`（§5.3 字段表）+ staging 写入/校验原语（S0–S4；有界写入原语） |
| Add（产品） | `lima/artifacts/metadata.py` | SQLite 层：`_init` 单事务建表（`PRAGMA user_version=1`、DELETE journal、幂等可重开）、seal 事务、限额账本（§7.1d）、租户作用域查询、`artifact_store_meta`（root_id/映射版本/limits 指纹） |
| Add（产品） | `lima/artifacts/local_store.py` | `LocalArtifactStore`（open/stage_log/seal_log/get_log/inspect/close；临界区；blob IO 与 metadata 分离） |
| Add（产品） | `lima/artifacts/recovery.py` | `inspect` 诊断（四类分类+计数；有界扫描）与隔离移动（不删不重构；满额拒绝移动、诊断照常） |
| Add（产品） | `lima/artifacts/demo.py` | `python -m lima.artifacts.demo --root <dir>`：本机可运行示例（进程内 stage→seal→get 回执→get 读结果 + 子进程重开读回 + 独立 digest 复算；合成上下文显式标明） |
| Add（测试，D2 冻结名称/符号/计数） | `tests/artifacts/__init__.py` + `tests/artifacts/test_*.py` | 方法族与最小覆盖数见 §8；exact 文件/符号 D2 冻结 |
| Modify | 无（本片零修改既有文件） | 首片不改 `lima/store.py` 等；V5-FR-01 迁移义务留在 #66 后续 |
| Read-only | `lima/contracts/`、`lima/evidence_privacy/`、`lima/audit/`、workspace、cache、`lima/store.py`/`postgres_store.py`/`repository_cache.py`、service/auth、Docker/compose、#60 全部工作面、其余一切 | 只读复用/参考 |
| Forbidden | 共享契约任何修改；既有 schema 版本/公共字段/默认预算/全局 registry；`lima/persistence/migrations.py`（FR-05 后续片）；除上述 Add 面外的任何新增仓库文件 | Assignment §6（DI-017） |

实现期文件面按 #66 Add 面收敛到 `lima/artifacts/` + `tests/artifacts/`；不新增 `ports.py`/
`retention.py` 框架性文件（防过度设计）。依赖约束：仅 Python 标准库（sqlite3/uuid/pathlib/
hmac/hashlib 等）+ 既有 `lima.contracts`/`lima.evidence_privacy`；禁网络、禁新第三方依赖、禁
容器、禁远端写。

### 5.2 Symbol-to-File Map（公共符号）

| Symbol | File |
|---|---|
| `SANITIZED_LOG_SCHEMA_NAME`/`SANITIZED_LOG_SCHEMA_VERSION`/`SANITIZED_LOG_MEDIA_TYPE`/`SANITIZED_LOG_ENCODING`/`build_sanitized_log_envelope`/`decode_sanitized_log_envelope` | `lima/artifacts/schema.py` |
| `TrustedTenantContext`/`ProducerContext` | `lima/artifacts/context.py` |
| `ArtifactStoreLimits` | `lima/artifacts/limits.py` |
| `ArtifactStoreError`/`ArtifactStoreErrorCode` | `lima/artifacts/errors.py` |
| `StagedLogHandle` | `lima/artifacts/staging.py` |
| `LocalArtifactStore`（`open`/`stage_log`/`seal_log`/`get_log`/`inspect`/`close`） | `lima/artifacts/local_store.py` |
| `SealedLogReceipt`/`RetrievedLogArtifact` | `lima/artifacts/local_store.py`（或 schema.py——模块落点为 SF-09 D2 收敛义务，§10.1；**字段与语义本轮已冻结，§5.3**） |
| `StoreHealthReport`（inspect 返回） | `lima/artifacts/recovery.py` |
| `main`（demo 入口） | `lima/artifacts/demo.py` |

### 5.3 冻结公共合同（R66-06；Assignment §7.6① 逐字）

```python
class LocalArtifactStore:
    @classmethod
    def open(cls, root: Path, *, tenant: TrustedTenantContext,
             policy: TenantPolicy, limits: ArtifactStoreLimits | None = None) -> LocalArtifactStore
    def stage_log(self, *, text: str, producer: ProducerContext) -> StagedLogHandle
    def seal_log(self, handle: StagedLogHandle, *,
                 expected_content_digest: str | None = None) -> SealedLogReceipt
    def get_log(self, reference: ArtifactReference) -> RetrievedLogArtifact
    def inspect(self) -> StoreHealthReport
    def close(self) -> None
```

- 全部关键字参数（store 打开参数与 stage 入参）；`TenantPolicy` 自 `lima.evidence_privacy.models`
  复用（不重定义、不改 #94）；测试/demo 可显式注入**已标明合成**的 policy（不冒充生产来源）。
- **open 语义**：首次打开创建目录骨架（`root/blobs`、`root/staging`、`root/quarantine`）与
  `metadata.sqlite3`（user_version=1、DELETE journal、`artifact_store_meta` 写入 root_id、
  `tenant_storage_key_map_version=1`、limits 指纹、账本清零行）；再次打开校验版本/指纹（§4.5）。
  policy 不进 root 绑定（每次注入、只收紧）。
- **handle 一次性身份语义**：seal 后 handle 不可再用于新 seal 的身份变更，仅幂等重读；业务不
  接触绝对路径（路径仅存在于 store 内部与 bounded 诊断计数中）。
- **seal_log 入口六段冻结次序（R66F-01，本节为签名说明；行为规约见 §4.2/§4.4）**：
  ⓪ 参数形状（`expected_content_digest ∈ {None} ∪ {64 位小写 hex fullmatch}`；handle 类型/
  字段形状/`declared_state` 域——违反 → `INVALID_ARGUMENT` 零副作用）→ ①–⑤ 权威状态判定
  （§4.4 全函数）→ 实物完整性核验（正常分支临界区内重核 staging〔四态映射 lstat→存在→
  size→digest〕；幂等分支核验已有 blob）→ expected 比较（正常=P1 任何 publish IO 之前对
  重核 staging digest；幂等=blob 核验通过后返回回执前对已核验 blob digest；不符 →
  `SEAL_DIGEST_MISMATCH` 且原状态不动）→ R2 预留事务 → 新发布/P2 commit 或幂等返回。
  **签名本身逐字不变（本节代码块）；不增加通用输入、新参数、新 wire。**
- **get 六步校验顺序**：冻结于 §4.2 G1–G6（含每步错误映射）；本节不重复展开以避免双源。

**TrustedTenantContext 字段表（frozen dataclass；fail-closed，本轮冻结不留 D2）**

| 字段 | 类型 | 合法域（冻结） | fail-closed 行为 |
|---|---|---|---|
| `tenant_id` | str | 契约 identifier pattern `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}` fullmatch；逻辑身份精确值（大小写/尾点差异=不同租户，不归一化） | 违反 → `INVALID_ARGUMENT`（open 拒绝，零写入） |
| `tenant_key` | bytes | 非空且 1..64 字节；仅驻内存 | 违反 → `INVALID_ARGUMENT`；绝不持久化/入错误信息/日志 |

**ProducerContext 字段表（frozen dataclass；fail-closed，本轮冻结；无 policy 相关字段——R66-06①：
不保留 producer 自报 policy 声明，store 只信注入 policy 的实算 digest）**

| 字段 | 类型 | 合法域（冻结） | fail-closed 行为 |
|---|---|---|---|
| `producer` | str | identifier pattern | 违反 → `INVALID_ARGUMENT`（stage 入口，零写入） |
| `task_id` | str | identifier pattern | 同上 |
| `workflow_id` | str | identifier pattern | 同上 |
| `stage_attempt_id` | str | identifier pattern | 同上 |
| `repository_snapshot_digest` | str | 64-hex 小写 | 同上 |
| `toolchain_digest` | str | 64-hex 小写 | 同上 |

**StagedLogHandle 字段表（frozen dataclass；有界表示——不含主机路径、不含 tenant key/任何密钥；
可序列化 canonical JSON ≤1 KiB；本轮冻结，内部表示细节可在文件边界内收敛）**

| 字段 | 类型 | 合法域（冻结） | 语义/失败行为 |
|---|---|---|---|
| `staging_id` | str | identifier；系统生成 `"stg-"+uuid4hex(32)` | staging 身份（`seal_attempts` PK）；查无此行且无可幂等返回的已 seal 身份 → `STAGING_NOT_FOUND` |
| `root_id` | str | 64-hex；root 初始化时生成并记录于 `artifact_store_meta`（**不是主机路径**） | 与当前 store 的 root_id 不符 → `STAGING_STATE_INVALID`（外来 root handle） |
| `tenant_id` | str | identifier；逻辑租户绑定（非 tenant_key） | 与当前 store 可信租户不符 → `STAGING_STATE_INVALID`（外来租户 handle） |
| `declared_state` | str | `{"staged","sealed"}`（权威=`seal_attempts` 行） | 方向性矛盾（CR-D1R-01+CR-D1F-01）：declared=`sealed` 而权威行=STAGING → `STAGING_STATE_INVALID`（过度声明，触发 (b)；CR-D1R-01④）；**权威行=RESERVED 时无论 declared=`staged`/`sealed` 同归 `STAGING_STATE_INVALID`（handle 尚未签发，任何携带该 staging_id 的 handle 均为过度声明——触发 (b) 扩展形态，CR-D1F-01；不按 ⑤ 处理）**；declared=`staged`+权威行 SEALED = 幂等重试正常可达态（§4.4 ③）；缺行 → `STAGING_NOT_FOUND`（§4.4 ②，唯一归属）；全函数判定见 §4.4 |
| `created_at` | str | UTC RFC3339 | 仅诊断 |

- **重开与重试（R66-06③）**：同 root、同可信租户重开（含跨实例/跨进程新 `open`）后**可重试原
  staging**（含 close 后再重开的场景）；外来 root/tenant handle 拒绝（`STAGING_STATE_INVALID`）；
  P2 已提交未返回即崩溃后，原 handle 幂等取得同一身份（且按 R66-02 核验实物）。
- **close() 只释放本实例资源**：不批量 abort、不删除/移动持久 staging；关闭后 inspect/重开/重复
  seal 行为明确（重开后原 handle 仍可用）。「非本 store」不再是 handle 拒绝理由（§6.1）。

**SealedLogReceipt 字段表（frozen dataclass；本轮冻结类型名与公共导出）**

| 字段 | 类型 | 语义 |
|---|---|---|
| `reference` | `ArtifactReference` | 既有契约 wire（不改） |
| `envelope` | `ArtifactEnvelope` | 既有契约 wire（不改） |

（**无 content 字段**——结构上消除「未读取」歧义；不用 `content=b""`/`None` 编码未读取语义。）

**RetrievedLogArtifact 字段表（frozen dataclass；本轮冻结类型名与公共导出）**

| 字段 | 类型 | 语义 |
|---|---|---|
| `reference` | `ArtifactReference` | 既有契约 wire（不改） |
| `envelope` | `ArtifactEnvelope` | 既有契约 wire（不改） |
| `content` | `bytes` | **恒为已验证封存字节**（G1–G6 全过后返回）；合法空日志 `b""` 只在该对象出现且语义唯一 |

## 6. 状态/错误/权限语义（条款 8、11、13、16；R66-02/04/06 同步）

### 6.1 稳定错误码表（`ArtifactStoreErrorCode`，wire 值冻结；23 码，**唯一新增=`STORE_CONFIG_CONFLICT`**）

| code | 触发条件 | 副作用保证 |
|---|---|---|
| `INVALID_ARGUMENT` | 参数类型/形状错误（非 str text、非法 context 字段、非 ArtifactReference、G1 六字段形状不符；**seal ⓪ 参数形状：expected_content_digest 非 None 且非 64 位小写 hex fullmatch、handle 非 StagedLogHandle 实例或字段形状/declared_state 域违反——R66F-01，先于 ①–⑤**） | 零写入（seal ⓪ 零副作用：不触碰权威行/实物/账本） |
| `INVALID_TEXT_ENCODING` | text 非 UTF-8 可编码（lone surrogate 等） | 零写入（S0 预检；probe P4.2e：裸 UnicodeEncodeError 会逃出隐私端口，必须前置） |
| `INPUT_BUDGET_EXCEEDED` | 输入 UTF-8 字节数 > 有效输入上限交集（S0） | 零写入 |
| `SEALED_BUDGET_EXCEEDED` | 净化输出 UTF-8 字节数 > 有效封存上限交集（**S2 输出校验，先于任何 content staging 写入**，R66-04） | **零内容文件、零正文入库、零持久诊断行**（R66F-02 取消；失败信息走有界错误输出 bounded 元数据，无内容/凭据） |
| `SANITIZATION_FAILED` | 隐私端口 PrivacyError（含 MISSING_TENANT_KEY/UNKNOWN_SINK/MAX_STRING_LENGTH_EXCEEDED 等，bounded context 携带 privacy_code）；**或 S2b 租户绑定不符 / S2c policy_digest 不符（R66-01）** | 零内容落盘、无 staging 内容文件 |
| `UNSUPPORTED_REDACTED_FORM` | redacted_value 非 str（FingerprintRecord/bytes/JSON）或 classification/retention 不在接受面（S2a/S2c） | 零内容落盘、不取回原文、不声称已保存全文 |
| `UNSUPPORTED_LINEAGE` | 非空 lineage/supersedes 进入 stage 或 envelope helper 构造器 | 零写入 |
| `UNSUPPORTED_SCHEMA` | get 的 schema name/version 非 `lima.sanitized-log`/`4.0`（G2；**仅实际可传入对象**——错误 schema_name 的合法 Reference、合法 4.x 非本片 minor 如 4.1；构造期错误归 foundation/caller 不经本入口，R66F-03 映射注） | 只读失败 |
| `STAGING_NOT_FOUND` | handle 的 staging 身份在权威 `seal_attempts` 中不存在（**唯一归属**：无行即无可幂等返回的已 seal 身份，declared_state 不影响归属，缺行不落 (b)——CR-D1R-01②；R66-06③改写：「非本 store」不再是触发） | 只读失败 |
| `STAGING_STATE_INVALID` | (a) handle 绑定 root/tenant 与当前 store 不符（外来 handle）；(b) **方向性矛盾**——handle 声明 `sealed` 而权威 `seal_attempts` 行为 **STAGING**（过度声明；CR-D1R-01④）；**或权威行为 RESERVED**（预留已持久化、staging 身份未完成、handle 尚未签发——任何携带该 staging_id 的 handle 均为过度声明，declared_state 无论 `staged`/`sealed` 均归本码，触发 (b) 的扩展形态，CR-D1F-01 补裁：不按 ⑤ 正常路径处理〔不重核、不发布〕，只读失败零副作用，RESERVED 行唯一处理通道=其所属 stage 操作自身与锁内结算）；declared=`staged`+权威行 SEALED 为幂等重试正常可达态、缺行归 `STAGING_NOT_FOUND`（**「已 abort」触发已删除——本片无公共 abort 入口、close 不批量 abort，该状态不可达，R66-06④裁定**） | 只读失败 |
| `SEAL_DIGEST_MISMATCH` | **seal 两分支 expected 比较（R66F-01，均在实物核验之后——不掩盖/不替代实物错误码）**：正常分支=P1 任何 publish 文件 IO 之前，expected ≠ 临界区内重核出的 staging 实际 digest；幂等分支=blob 核验通过后、返回回执之前，expected ≠ 已核验 blob 实际 digest（=权威 content_digest；正确 blob+错 expected 仍拒绝） | 不发布、不提交、不返回回执；**不改动既有 SEALED 记录、不覆盖 blob（幂等分支原状态不动）**；零新增 SEALED |
| `ARTIFACT_NOT_FOUND` | G3：租户不符、未知 artifact_id、未封存、**或六字段任一与权威记录不一致（含合法格式但错误的 repository_snapshot_digest/content_digest，R66-06②）** | 只读失败；绝不泄露他租户对象存在性 |
| `BLOB_MISSING` | G5 实物缺失（metadata-only）；**或 seal/幂等重试路径核验发现实物缺失（P1，R66-02 扩展触发面）；或 seal 实物核验段 fresh staging 缺失（正常分支重核路径，R66F-01）** | metadata 不丢；不返回内容；seal 路径零新增 SEALED |
| `BLOB_CORRUPT` | 实际字节 digest 不匹配（G5）；**或 P1 ②/③ 核验既有实物 digest 不符；或 seal 实物核验段 digest 不符（staging 重核〔R66F-01〕/blob 重核）** | fail closed；可隔离不改状态；seal 路径不覆盖/不修复原内容与原 SEALED 记录 |
| `BLOB_SIZE_MISMATCH` | 实际 size ≠ 记录 size（G5）；**或 P1 ②/③ 核验 size 不符；或 seal 实物核验段 size 不符（staging 重核路径，R66F-01）** | 同上 |
| `METADATA_CORRUPT` | metadata 行/envelope 无法解码或互相矛盾；**或 open 时 root 元数据/tenant-storage-key 映射版本绑定不一致（R66-03）** | fail closed；报告分类 |
| `METADATA_CONFLICT` | 身份键冲突且字段不一致 | 拒绝，不覆盖 |
| `CAPACITY_EXCEEDED` | §7.1 统一限额表任一容量/对象/记录/残留类限额超限；**或 R1/R2 保守预留超过剩余额度（Σ实际+Σ有效预留 > cap，先拒绝——R66F-02；含辅助文件/journal 余量不足）** | 拒绝新写（预留事务零提交、零文件 IO）；不自动清理活对象；不 fallback；不提高 cap 使演示通过 |
| `CONCURRENCY_LIMIT_EXCEEDED` | 并发 seal 超 max_concurrent_seals；**或临界区/锁有限等待超时（R66-05；含 DELETE 模式写事务期间读者 busy_timeout 超时）** | 拒绝/稳定失败（零提交） |
| `STORE_CONFIG_CONFLICT` | **新增（唯一新码，R66-05）**：open 发现同 root 已绑定的 limits 指纹与本次 open 传入（或默认）limits 不一致 | 拒绝 open，零写入（不允许后开实例以更宽配置绕过 root 上限） |
| `PATH_POLICY_VIOLATION` | 解析路径越出私有 root、symlink/junction 命中发布/读取路径；**或 P1 ②/③ 核验链接/reparse 异常、非常规文件（目录/FIFO 等）（R66-02；SF-D1R-02）；或 seal 实物核验段 lstat 判定非常规文件/链接/越界（staging 重核路径，R66F-01）** | 拒绝该 IO；零越界访问 |
| `IO_ERROR` | 磁盘满/权限拒绝/IO 异常（bounded：仅异常类型与 errno 级元数据） | 稳定失败；不回显日志原文 |
| `INTERNAL_STORAGE_ERROR` | 不可预期异常兜底（bounded：仅异常类型；含契约层 encode 资源上限映射——正常不可达） | 稳定失败；不回显内容 |

契约层 `ContractError` 在 get 路径被映射为上表对应存储错误，不把原始异常文本透传给业务：G4/G5
阶段（store **实际执行** decode/validation 的真实调用边界）的契约 digest 失败（如 decode 时的
DIGEST_MISMATCH）→ `BLOB_CORRUPT`/`METADATA_CORRUPT`（既有映射不变）。

**真实入口错误归属表（R66F-03，替换 D1R 的「构造期同族映射」句——该 SF-D1R-03 入口映射部分被
真实 API 实测推翻：`SchemaVersion(3,0)` 构造即抛 `SCHEMA_UNKNOWN_MAJOR` 且被调函数未进入、
`SchemaVersion(4,0)`/`(4,1)` 构造成功可传入〔审核探针+P11 复测，Python 先求值参数〕——只接
`ArtifactReference` 的 get 不可能把调用者构造时、进入 get 之前的异常映射成存储错误）**：

| 真实调用序情形 | 归属/映射 | 证据 |
|---|---|---|
| 调用者构造 Reference 失败（含 `SchemaVersion(3,0)` 构造期 `SCHEMA_UNKNOWN_MAJOR` 及同族） | foundation/caller——**get 未被进入、不映射为任何存储错误** | P11 实测（构造即抛、被调函数未进入） |
| 实际可传入的错误 schema_name（合法构造的 Reference，如 `lima.other-slice`） | G2 → `UNSUPPORTED_SCHEMA` | P11 实测（构造成功、被调函数进入） |
| 实际可传入的合法 4.x 非本片 minor（如 `4.1` Reference） | G2 → `UNSUPPORTED_SCHEMA` | P11 实测（4.1 构造成功、被调函数进入） |
| 非 `ArtifactReference` 形状（如 dict） | G1 → `INVALID_ARGUMENT` | P11 实测（被调函数进入——形状检查是真实产品义务） |
| store 内部实际执行 decode/validation 的契约错误（G4/G5 真实调用边界） | 既有映射（`METADATA_CORRUPT`/`BLOB_CORRUPT` 等，不变） | §4.2 G4/G5 |

不新增 raw/dict Reference 解析 API、不改 #58 构造器。所有错误信息
只含：code、field 级定位、`{"limit","actual","privacy_code","exception_type"}` 式 bounded 元数据
——**无日志正文、无 tenant_key/token/Secret、无主机绝对路径**（条款 11）。

### 6.2 权限校验入口

两处强制：metadata 查询（G3，租户等值过滤在 SQL 谓词中）与读取入口（G5 实物核验）。ref 自带
tenant 与调用者传入字符串均不作为身份认证依据（§4.5）。

## 7. 预算与资源（条款 10、17、18、19、20；R66-04/05 修订）

### 7.1 统一限额表与跨进程额度（R66-05 列规范；替换 v1.0 零散限额行——Assignment §7.7 第 9 行，本 Packet §1.3 已核销）

#### 7.1a 统一限额表

| # | 限额 | 作用域 | 默认值 | 合法域（open 可调） | 硬上限 | 计数单位 | 预留/提交/失败/崩溃（每行单值） | 稳定错误 |
|---|---|---|---|---|---|---|---|---|
| 1 | `max_input_bytes` 单条日志输入 UTF-8 字节 | 每次调用（叠加注入 policy 更严值） | 262,144 | [1, 262,144] | 262,144（=PrivacyLimits∩ContractLimits string 上限，**不可扩**） | 输入字节 | 无预留（S0 纯校验）；失败=零写入；崩溃=无副作用（任何写入前） | `INPUT_BUDGET_EXCEEDED` |
| 2 | `max_sealed_bytes` 净化输出封存字节 | 每次调用（同上） | 262,144 | [0, 262,144] | 262,144（同上交集；更严 policy 收紧，不回填宽默认） | 净化输出字节 | 无预留（S2 写前校验，先于 R1 预留事务）；失败=零内容文件、零正文入库、**零持久诊断行**（R66F-02 取消——失败信息走有界错误输出）；崩溃=写前失败无内容 | `SEALED_BUDGET_EXCEEDED` |
| 3 | `max_envelope_bytes` envelope wire | 进程内 | 1,048,576 | 固定（契约 `ContractLimits.max_input_bytes`） | 1,048,576 | wire 字节 | encode 时校验；失败=拒绝封存（本片 envelope 字段全有界，正常不可达） | `INTERNAL_STORAGE_ERROR`（契约资源上限映射） |
| 4 | `max_blob_objects` root 持久对象总数 | root 跨进程 | 10,000 | [1, 1,000,000] | 1,000,000 | 唯一物理 blob（**物理键去重——`(tenant_storage_key, content_digest)` 跨 attempt 共享只计一次**，R66S-02 规则 1） | R2 预留事务按**物理键引用判定**预留（规则 4：键已被任何 SEALED Artifact〔artifacts 行 state=SEALED ∧ content_digest=d〕或已登记在途 owner〔seal_attempts 非终态行 ∧ blob_id 非空〕引用 → reserved_objects=0；否则 1）；P2 提交=占用；**对象数已满不误拒同租户有效复用（规则 4）**；失败=已发布 orphan **继续按实际占额**（不因释放预留漏账）、未发布释放预留；崩溃=锁内按唯一物理键集合 U 对账结算（首次差额入账、重复 no-op、保守不减，§7.1d/§7.1f）；同 digest 多行/重复结算不重复 +1 | `CAPACITY_EXCEEDED` |
| 5 | `max_total_root_bytes` root 磁盘总字节（原 `max_total_blob_bytes` 更名扩域：blob+staging+orphan+quarantine+envelope/metadata+SQLite 数据与 journal+锁文件） | root 跨进程 | 512 MiB | [1 MiB, 64 GiB] | 64 GiB | **root 下常规文件 `st_size`+有效 reservation（R66S-01 计费口径；不冒称整个卷分配块/目录开销；DB 文件按 st_size=提交后 page_count×P 计入；行 9 逻辑行字节不入账——row bytes 与 DB bytes 不双计；双口径盘点：实际字节与未结算有效预留分开列报，不把保守 charge 冒称物理实物；整区保守预留单列 reservation、不称实际实物）** | R1 预留（staging 内容+R1 段 DB 页增长 Δpages×P+journal_headroom(T-R1)）→S3/S4 转实际→R2 追加（**publish 副本另扣**+R2/P2 段 Δpages×P+journal_headroom(T-R2)+journal_headroom(T-P2)）→P2 转实际；失败=释放未实际使用的预留、已写实物继续按实际占额；崩溃=锁内结算（实物在→转实际；无实物→空预留解除；已发布 blob→占用按唯一物理键结算）；**不变量 Σ(实际占用)+Σ(未结算有效预留) ≤ cap，每段入口检查**（盘点面=metadata.sqlite3/journal 与热 journal/锁/staging/publish 临时/最终 blob/quarantine/声明辅助文件——§7.3 配置面；**DB 物理页数硬限 M=floor(本行值÷P) 由 max_page_count 施加**，SQLITE_FULL→CAPACITY_EXCEEDED 稳定拒绝） | `CAPACITY_EXCEEDED` |
| 6 | `max_logical_artifacts` 逻辑 Artifact 总数（**新增**） | root 跨进程 | 10,000 | [1, 1,000,000] | 1,000,000 | 身份键 `(tenant_id, artifact_id)` 计 | R2 预留事务预留（P2 将 insert artifacts 行）；P2 提交=占用；失败/崩溃=无 artifacts 行即不占用（预留释放）；同 handle 幂等重试不重复计数；新 stage 不是免费重试 | `CAPACITY_EXCEEDED` |
| 7 | `max_live_staging` live staging/seal attempt 数 | root 跨进程 | 256 | [1, 10,000] | 10,000 | **`seal_attempts` 行 state ∈ {RESERVED, STAGING}（R66F-02 扩：RESERVED 也占 live 名额——新 stage 不是免费重试）** | R1 预留事务 INSERT RESERVED 行即占 live 名额；P2 提交 state→SEALED **释放 live 名额**（attempt 行仍占行 10 记录额度、留存 staging/blob 文件仍占行 4/5——live 名额与磁盘/记录占用不混算）；失败=预留字段清零（未用部分）但**行保留**（state ∈ {RESERVED, STAGING} 继续占 live 名额，无删除授权不释放）；崩溃=锁内结算（空预留解除只清预留字段，不释放 live 名额、不删行） | `CAPACITY_EXCEEDED` |
| 8 | `max_concurrent_seals` 并发 seal 数 | root 跨进程 | 8 | [1, 64] | 64 | 临界区并发持有者 | 获取临界区时检查；等待超时=稳定失败零提交；崩溃=OS 文件锁随进程终止自动释放（不悬挂） | `CONCURRENCY_LIMIT_EXCEEDED` |
| 9 | `max_metadata_record_bytes` metadata 单条记录上界（**新增**） | 进程内不变量 | 8 KiB | 固定 | 8 KiB | 单行+envelope_wire 合计（**逻辑校验界，非计费单位——R66S-01：DB 物理增长按页计行 5，row bytes 不入物理账**） | 构造时校验；超限拒绝封存（字段全有界，正常不可达）；每行溢出页 ≤2（page_size 4096 下 8 KiB 记录叶页+≤2 溢出页，RC-P1 实测单 8 KiB INSERT 增长 2 页复核） | `INTERNAL_STORAGE_ERROR` |
| 10 | `max_metadata_records` metadata 记录总数上界（**新增**：**artifacts+seal_attempts**——R66F-02 诊断行取消；**R66S-02：组成不变——零新表/零新记录载体，在途登记复用 seal_attempts.blob_id 列，无新增私有记录可藏账**） | root 跨进程 | 100,000 | [10,000, 1,000,000] | 1,000,000 | metadata 行（artifacts+seal_attempts） | R1 预留事务 +1（seal_attempts RESERVED 行）+账本行增长；P2 提交 +1（artifacts 行）；幂等重试不新增行；失败/崩溃残留行计额（结算不删行——行保留为记录） | `CAPACITY_EXCEEDED` |
| 11 | `max_quarantine_items` 诊断与隔离残留计数（**新增**） | root 跨进程 | 1,000 | [1, 100,000] | 100,000 | quarantine 目录下的文件系统条目 | 残留恒计额（无删除授权仍占额）；inspect 隔离移动满额时拒绝执行、诊断报告照常输出 | `CAPACITY_EXCEEDED` |
| 12 | `max_auxiliary_bytes` 辅助文件预算（**新增**：DELETE journal 峰值+锁文件） | root 跨进程 | 4 MiB | [64 KiB, 64 MiB] | 64 MiB | journal+锁文件字节 | **journal 余量按 §7.3 页级公式预留（R66S-01 取代行数公式）：`journal_headroom(T)=(K_T+2)×(P+S)+2×S` 字节（P=page_size 实读〔初始化固定 4096、open 实读验证〕；S=512 B/页〔RC-P1 探针冻结：本机实测 journal=512+K×4,104、每页开销 8 B，冻结值含扇区对齐与平台余量〕；K_T=§7.3 九形状目录派生单值——T-R1/T-S4/T-R2/T-fail/T-reopen=25、T-P2=45、T-init=69；五条适用前提与推翻义务见 §7.3）——R1/R2 段分别按各自形状入账（R2 段含其预留的 P2 事务：headroom(T-R2)+headroom(T-P2)）；事务结束 journal 文件即删（DELETE 模式），余量属未用预留即时释放；**hot journal 残留计额至回滚（RC-P1 实测：重开读路径已回滚数据，journal 文件迟至下一次写事务才被删除——存在期按实际字节计入本行与行 5）**；锁文件恒 0 字节；计入行 5；辅助文件余量不足 → CAPACITY_EXCEEDED 先拒绝（合法较小 auxiliary cap 场景按同一公式判定，不为通过演示放大公式或 cap——cap 64 KiB 时 R1 即拒，§7.1f 例⑦）** | `CAPACITY_EXCEEDED` |
| 13 | `max_read_bytes_per_get` 单次 get 读放大 | 进程内 | = `max_sealed_bytes`+`max_envelope_bytes` | 随前两者 | 同左 | 单次 get 读取字节 | 读取硬限：实际 size 超界先由 G5 size 校验拒绝，**永不读入超界字节** | `BLOB_SIZE_MISMATCH`（size 前置拒绝） |

新增限额理由（有限、不为演示提高额度）：行 6（逻辑计数与物理计数分开是 R66-05 要求——同内容
dedup 与空日志照样消耗逻辑额度）；行 9/10（metadata 每条/总数上界是 R66-05 要求的运维占用有界）；
行 11（隔离/诊断残留占额）；行 12（journal/锁文件预算）。原适用限额默认值全部保留（行 1–5、8、
13 与 v1.0 一致）。

**计账单值细则（SF-D1R-04，Coordinator 裁定；D1F 按 R66F-02 诊断行取消改写）**：
(i) **无持久诊断行**：S2 各失败（超限/形态/绑定/策略）零持久行（R66F-02 取消 D1R 的诊断行
条款）——失败信息走有界错误输出（§6.1 bounded 元数据）；重试 stage 另 mint 新 staging_id
（新 stage 不是免费重试，7.1b）。
(ii) inspect 隔离移动后，行 4 物理对象计数**不释放**（对象仍在 root 下；释放仅存在于有删除授权
的未来片）；行 5 字节不变，行 11 +1。
(iii) 计数不相交规则——同一物理计入在同一维度只落一个限额行：行 5 双口径的「实际字节」与
「未结算有效预留」分开列报（同一字节先以预留计、转实际后以实际计，不叠加双扣，不属双计）；
行 11 计数单位为 quarantine 目录下的文件系统条目；跨维度（如行 4 对象数与行 5 字节、
行 6 逻辑身份与行 4 物理对象）按各自单位独立计，不属双计。

**计数语义（7.1b，冻结；D1F 增 RESERVED 说明；v2.2 增 R66S-02 物理键口径）**：唯一物理 blob
（行 4——**物理身份键 `(tenant_storage_key, content_digest)` 去重：跨 attempt/Artifact 共享同一
物理键只计一个 blob，内容字节同样只计一次**）/ 逻辑 Artifact（行 6，身份键 `(tenant_id,
artifact_id)` 计——同字节 ≠ 同身份，dedup 不合并逻辑身份）/ staging-seal attempt（行 7/10；
attempt 生命周期 RESERVED→STAGING→SEALED，行 7 live 名额只看前两态）/ 各自 staging 文件（行 5，
按文件计——不经 dedup 合并）/ 诊断隔离残留（行 11）**分开计数**；同内容 dedup 与 0 字节日志
照样消耗逻辑对象/记录额度；同 handle 幂等重试不重复生成 Artifact、不新增 attempt 行；**新 stage
不是免费重试**（消耗 attempt/逻辑额度——R1 预留事务 INSERT RESERVED 即占行 7 live 名额）。更严
policy 只收紧行 1/2 的每次调用上限，不构成另一个 root 配额。

**作用域与配置绑定（7.1c，冻结）**：行 4–8、10–12（root 跨进程作用域）跨实例/跨进程共享同一账本；
**同 root 存储限制配置绑定一致**——`artifact_store_meta` 记录 `ArtifactStoreLimits` 全字段的
canonical 指纹（`compute_content_digest` 规则实算），`open()` 发现与既有绑定不一致 →
`STORE_CONFIG_CONFLICT` 拒绝（零写入）；不允许后开实例以更宽配置绕过，也不能借不同租户实例
跳过 root 总上限；TenantPolicy 不进 root 绑定。无删除授权的残留仍占额度；达上限拒绝新写（稳定
错误），不自动 GC、不删除活对象、不 fallback。

**原子性与协调规则（7.1d，冻结，单值实现形态；D1F 按 R66F-02 扩为预留-结算协议）**：**单 root
跨进程串行临界区 + 有限等待 + SQLite 小记录 + seal_attempts 行承载持久预留**。临界区 = root
锁文件（OS 独占文件锁：win32 `LockFileEx` / POSIX `flock` 等价语义）+ 有限等待（默认
10,000 ms，与 busy_timeout 一致）；R1/S3/S4 的预留与转换事务、R2 预留事务、seal 的「blob 发布
+ metadata commit」复合段（P1+P2）、以及重开结算都在临界区内执行（R66-02 第 3 条联动）。

- **预留载体（唯一形态，Assignment §11.2）**：既有 `seal_attempts` 行承载——state 增
  `RESERVED` + 预留字段列（`reserved_staging_bytes`/`reserved_publish_bytes`/
  `reserved_metadata_bytes`/`reserved_journal_bytes`，§7.3——R1 写 staging 段三项、R2 追加
  publish 副本与发布段余量）；**不建独立 reservations 表/预留
  服务**（相对独立表为更小等价：不新增表、恢复枚举复用既有权威行、不变量相同——证明义务=
  §7.1f 七例数值反例逐例「不丢账/不漏账/不永久占锁」；不把选择权带入 D2）。
- **预留事务提交点**：R1 预留事务（S3 前）与 R2 预留事务（P1 前）各自**独立提交**——预留
  commit 之后才允许对应段文件 IO（staging IO 在 R1 commit 后、publish IO 在 R2 commit 后）；
  后续事务（含 P2）失败回滚不吞已提交预留行（P9 SQLite 实测）；账本行（计数）与业务行同库
  同事务（BEGIN IMMEDIATE）更新。
- **转换与结算**：S3/S4 完成同事务 RESERVED→STAGING、预留转实际；P2 commit 同事务转实际、
  清零预留、state→SEALED、行 7 live 名额释放；**失败=释放未实际使用的预留（独立事务清零
  预留字段），已写出的 staging/publish 临时文件/orphan/隔离内容继续按实际占额**（P1 成功
  P2 失败的已发布 orphan 不得因释放预留而漏账——结算后账本 ≥ 实际盘点，
  ledger=0/physical=1 不再可达，§7.1f 例③）；**每段入口不变量 Σ(实际占用)+Σ(未结算有效
  预留) ≤ cap**（行 5 双口径盘点）；保守预留超过剩余额度 → 先拒绝（`CAPACITY_EXCEEDED`，
  零提交），不追求完全利用率、不提高 cap 使演示通过。
- **崩溃/重开结算（有界恢复，锁内先结算后写；v2.2 按 R66S-02 唯一物理键对账改写）**：
  open/下一写在同 root 锁内**先结算后写**——枚举 `seal_attempts` 非终态行（state ∈
  {RESERVED, STAGING} 或预留字段非空；枚举有界=既有行 7/10 记录限定，不做全目录无限扫描），
  逐行在授权物理范围（`staging/<staging_id>/`、`blobs/<tenant_storage_key>/`〔按行记录 digest
  派生路径〕、blob 同目录 publish 临时文件、`quarantine/`）内核对实物：staging 文件在 →
  按实际字节转实际占用；无任何实物 → 空预留解除（预留清零；行保留为记录，不得借此删掉仍有
  实物的占用）；**对象/字节账按唯一物理键集合 U 对账（R66S-02 规则 3）：对授权 blob 物理范围
  枚举 U（内容寻址布局天然一键一文件；**同键第二文件或布局外实物 → fail-closed
  `METADATA_CORRUPT`，不跳过不计**）；orphan 判定查询该物理键是否被**任何有效 SEALED Artifact
  （artifacts 行 state=SEALED ∧ content_digest=d）或已登记在途 owner（seal_attempts 非终态行 ∧
  blob_id 非空——R2 提交时写入）引用**，不按「当前 attempt 是否有自己的 artifacts 行」判定
  〔原 per-attempt 规则的反例——A SEALED+B idle STAGING 同 digest → 对象账 1→2——保留为回归
  反例并标注「原协议模型反例，非产品实测」，§7.1f〕；已登记共享 blob 不改状态、不搬走、不重复
  收费；账本 hold（actual+reserved）< |U| 的差额=真正新 orphan **首次按唯一物理键入账**（每键
  +1 对象+其实际字节）；hold ≥ |U| → no-op（**保守不减**——已入账 orphan/被外部删除残留继续
  占额）；后续多个同 digest 行与重复结算 no-op；**引用判定与对账结论必须一致，不一致
  fail-closed**；恢复先结算后写，多次 open/settle 不能创造容量占用**；结算完成后才允许继续写。
  **publish 临时文件命名冻结（v2.2 勘误第二批，CR-RC-01/SF-04，Coordinator 单值；本节为该
  规则单源）**：`publish-<uuid4hex(32)>.tmp`——小写 32 位 hex（系统生成），位于目标 blob 同
  目录（`root/blobs/<tenant_storage_key>/<d[:2]>/<d>/`）；每 attempt 每 P1 ① 分支至多一个、
  `O_CREAT|O_EXCL`、发布后原子 rename 为 `blob.bin`；失败/崩溃残留按实际字节占额。**U 枚举
  分类据此确定**：授权范围内 `blob.bin`=该键唯一物理文件；fullmatch `publish-[0-9a-f]{32}\.tmp`
  =授权 publish 临时文件（计额、结算转实际占用）；其他文件名或同键第二实体 → fail-closed
  `METADATA_CORRUPT`。
  **超出授权扫描范围或发现未知实物 → fail-closed**（`METADATA_CORRUPT` 语义面，拒绝继续写；
  不跳过不计——P10/RC-P4 观察）。
- 进程崩溃后不丢账（预留先于文件 IO 已持久化）、不永久占锁（OS 文件锁随进程终止自动释放，
  §7.1d 原句不变）；DELETE hot journal 回滚（§7.3）先于结算、同在临界区内；初始建表/open
  在既有声明边界内；临界区有限等待超时 → `CONCURRENCY_LIMIT_EXCEEDED` 稳定失败（零提交）。
  **不建**配额服务、多池调度、分布式锁、WAL 管理池。

预算两层说明（7.1e；条款 10，R66-04 同步）：**输入预算**（S0，对原始 text 的 UTF-8 字节数）与**净化
输出预算**（S2，对净化后字节数——**在任何 content staging 写入之前**）分别执行，大小一律按
UTF-8 字节数（设计探针实测 probe P4.2：1 emoji=1 字符/4 字节、6 CJK 字符=18 字节、100 emoji=
100 字符/400 字节——字符计数与字节计数必须分离）。**预算内输入可能因净化占位符膨胀触发输出
预算**——实测反例 262,119 B 输入膨胀至 365,378 B（cap 262,144 B）→ 新时序下 S2 写前拒绝：
`SEALED_BUDGET_EXCEEDED`（稳定失败、零内容写入、无数据丢失、无降级；P7 复现+审核实测；
ERR-IP-0044-D1-v1 SF-07 事实保留，其「S4 检查」时序表述已被本表取代）。默认限额触发实例实测：
262,145 字节 → `MAX_STRING_LENGTH_EXCEEDED {limit:262144,actual:262145}`（probe P4.1）。容量
不足拒绝新写（`CAPACITY_EXCEEDED`）：不无限积累、不自动清理活对象、不 fallback 到旧 task
report_json、不回退 inline。既有 privacy/codec 限制零扩大；**不改 privacy foundation**（#94 只读
复用）。

#### 7.1f 预留-结算协议：状态/动作表与数值反例集（R66F-02 新增小节；Assignment §7.2 第 6 条）

**状态/动作表**（重开结算视角：`seal_attempts` 行 state × 预留字段空/非空 × 该 attempt 的授权
实物在/不在——实物指 staging 文件/publish 临时文件/orphan 或最终 blob 任一；不可达组合标注
原因；结算动作只调整账目〔预留字段清零/实际占用入账〕，不改写 attempt 行 state 标签——state
转换只发生在正常协议事务〔S3 完成事务/R2 事务/P2 事务〕）：

| # | state | 预留字段 | 实物 | 重开结算动作（锁内，先结算后写） | 结算后占额 |
|---|---|---|---|---|---|
| 1 | RESERVED | 非空 | 无任何实物（R1 后、S3 前 kill） | 空预留解除：预留字段清零（独立事务）；行保留为记录 | 行 7 +1、行 10 +1（DB 行字节计行 5）；内容/对象额度零 |
| 2 | RESERVED | 非空 | staging 在（S3 写中 kill，可能部分） | 按实际字节转实际占用（预留清零）；staging 文件保留不删 | 行 5 +staging 实际字节；行 7 +1、行 10 +1 |
| 3 | RESERVED | 非空 | orphan blob 在 | **不可达**（blob 发布仅在 R2 之后，而 R2 前 state 已转 STAGING） | — |
| 4 | STAGING | 非空 | staging 在（R2 提交后 P1 前 kill，或 publish 临时文件写中） | staging 实际占用已计（S3 转换）；publish 临时文件按实际占额；未用预留清零 | 行 5 实际字节合计；行 7 +1、行 10 +1 |
| 5 | STAGING | 非空 | staging+已发布 blob 在（P1 后 P2 失败/kill） | **物理键已被本行 blob_id 在途登记（R2）→ 按引用判定非误判 orphan：不搬走、不重复收费；R2 预留按实际转占用（对象按唯一物理键首计、字节=实际——不释放，消解 ledger=0/physical=1 反例；per-attempt 误判〔对象 1→2〕不可达——原负例保留为回归反例）**；未用预留清零 | 行 4 +1（唯一物理键首计）、行 5 实际字节合计；行 7 +1、行 10 +1 |
| 6 | STAGING | 非空 | 无任何实物（外部删除 staging 后 kill 于 R2–P2 窗口） | 空预留解除（预留清零）；行保留 | 行 7 +1、行 10 +1；后续 seal 重核 → BLOB_MISSING（四态映射） |
| 7 | STAGING | 空 | staging 在（idle staging：stage 完成未 seal） | 实际占用已计、无预留——结算 no-op | 不变（行 4/5/7/10 按实际） |
| 8 | STAGING | 空 | 无（外部删除） | 无预留可解除；行保留 | 行 7 +1、行 10 +1；seal 重核 → BLOB_MISSING |
| 9 | SEALED | 非空 | 任意 | **不可达**（P2 commit 同事务清零预留+转占用+state→SEALED） | — |
| 10 | SEALED | 空 | blob 在（±staging 残留——标记可清理不自动删，残留仍计行 5） | 无未结算预留——正常终态，结算 no-op（同物理键被 SEALED 引用：U 对账 no-op） | 行 4 +1（唯一物理键；同键其他 SEALED/在途共享不重复 +1）、行 5 实际字节（含 staging 残留）；**行 7 释放（live=0）**；行 10 +2 |
| 11 | SEALED | 空 | blob 缺失/损坏（外部） | 无预留；不改状态、不修复（fail-closed 语义归 get/幂等核验） | 同上占额；get → BLOB_MISSING/BLOB_CORRUPT |
| 12 | 任意 | 任意 | 授权范围外/未知实物（如 root 下非授权布局文件） | **fail-closed**：`METADATA_CORRUPT` 语义面，拒绝继续写（不跳过不计） | 拒绝写直至人工处置 |

**数值反例集（七例全列；三列=预留/实际/账本；v2.2 全量按页级规约重算重写——示例参数：
净化输出 payload=100,000 B〔⑤ 用 262,144 B〕；P=4096、S=512、K_T 与 headroom 按 §7.3 目录：
journal_headroom(T-R1)=journal_headroom(T-S4)=journal_headroom(T-R2)=journal_headroom(T-fail)=
journal_headroom(T-reopen)=125,440 B、journal_headroom(T-P2)=217,600 B、R2 段 journal=
125,440+217,600=343,040 B〔含其预留的 P2 事务〕；DB 页增长预留 Δpages×P：R1 段 4 页=16,384 B、
R2 段〔T-R2+T-P2〕2+8=10 页=40,960 B；初始 DB 文件实测 32,768 B=8 页〔RC-P3 本 DDL；P10 模型的
28,672 B=7 页系其简化 DDL，引用不越类〕；证据=**RC-P1/RC-P3 真实 SQLite+文件系统实测**，协议
模型非产品实测）**：

**口径注（CR-RC-01/SF-03，标注不改数值）**：RC-P3 驱动器的 R2 段按 2 页演示预留——协议模型
驱动器取值＜冻结声明口径 10 页=T-R2+T-P2（Δpages 冻结值：T-R2=2、T-P2=8）；T-P2 Δpages=8
为保守推导值（RC-P1 实测 T-P2 增长 2 页），P2 实际 0 增长时未构成漏计、max_page_count=M
硬限兜底；**D2 冻结测试一律按冻结声明口径（10 页）断言预留与转实际**。RC-P1 init=9 页与
RC-P3 init=8 页系不同驱动器/时点的样本差异，均 ≤T-init 预算 69 页——不影响任何冻结值。

| 例 | 场景 | 预留（有效未结算） | 实际（已落账/盘点） | 账本与结算后状态 |
|---|---|---|---|---|
| ① | R1 提交后未写即 kill | 241,824（内容 100,000+DB 页 16,384+journal 125,440） | 内容 0（DB 文件按 st_size 实际盘点） | 结算=空预留解除（预留清零，行保留 RESERVED 占行 7/10）；内容/对象额度归零；账本=实际盘点（不丢账） |
| ② | staging 后 kill（S3/S4 完成事务已提交） | 0 | staging 100,000+DB st_size | 结算 no-op（S3 完成事务已转实际）；行 7 +1 |
| ③ | P1 后 P2 失败/kill | 未用部分（DB 页余量+journal 343,040）→ 失败释放 | staging 100,000+blob 100,000=200,000；对象 1 | **已发布 blob 物理键由 R2 在途登记（blob_id）→ 结算按引用判定非误判 orphan：继续按实际占额且只计一次——对象账 1=唯一物理文件 1、字节账 200,000=实物 200,000（ledger=0/physical=1 旧规则反例与 per-attempt 误判 1→2 均不可达）**；行 7 +1 |
| ③b | P1 rename 后、记账事务前 kill（补充态） | publish 预留 100,000+DB 页+journal | blob 100,000 未入账 | 锁内结算转实际：对象 +1（唯一物理键首计）、字节账=实物；不漏账（状态表行 5 同构） |
| ④ | P2 commit 后、返回前 kill | 0 | staging 100,000+blob 100,000+DB st_size | 终态 SEALED：**行 7 live 名额释放（live=0）、记录 +2、对象 1**；行 4/5/10 占额保留；get/幂等 seal 正常（幂等需过 blob 核验+expected 两关） |
| ⑤ | 临时副本余量不足（payload 262,144 B，cap 剩余 300,000） | R2 需 646,144（publish 副本 262,144+DB 页 40,960+journal 343,040）> 300,000 | staging 262,144（实际已计） | R2 **先拒绝**（CAPACITY_EXCEEDED 零提交、零 publish IO）；**仅按 payload 预留 262,144 会错误放行**（同内容两份物理存在=至少 524,288 B 内容占用——双副本分别预留消解该反例） |
| ⑥ | 重开后二进程争最后额度（cap 300,000） | A 已提交 R1 预留 241,824（**已含其 DB 行页增长**——不再另计） | 0 内容（A 的 DB 增长在预留内实现） | B 需 241,824：**Σ实际+Σ有效预留=483,648**>cap → B CAPACITY_EXCEEDED 零提交（第二连接实测可见 A 已提交预留——不因 A 尚未写文件而漏计） |
| ⑦ | 合法较小 auxiliary cap=65,536 B（合法域 [64 KiB,…] 内取小值） | R1 journal headroom 125,440 > 65,536 | — | **R1 处 CAPACITY_EXCEEDED**（比旧行数口径更早拒绝——页级预算更保守）；零提交零文件 IO；**同一公式判定，不为通过演示放大公式或 cap** |

**页级 journal 上界数值表（§7.3 公式；K_T=目录冻结值，实测高水位=RC-P1 真实 SQLite 事务存续期
`metadata.sqlite3-journal` stat 采样最大值）**：

| 形状 | K_T | journal_headroom 上界（B） | 实测高水位（B） | 备注 |
|---|---|---|---|---|
| T-init | 69 | 328,192 | 512 | 新库首事务引擎免 journal 页记录（保守并集仍计页，上界不依赖该细节） |
| T-R1 | 25 | 125,440 | 16,928 | 4 实脏页（attempt 叶+PK autoindex+state 索引+账本行页） |
| T-S3 | 0 | 0（无 DB 事务） | — | 纯文件 IO |
| T-S4 | 25 | 125,440 | 12,824 | 3 实脏页 |
| T-R2 | 25 | 125,440 | 8,720 | 2 实脏页（含 blob_id 在途登记） |
| T-P1reg | — | —（**不使用**） | — | 登记并入 R2；零新表/零新列/零新公共接口 |
| T-P2 | 45 | 217,600 | 29,240 | 7 实脏页（artifacts 叶+溢出+两索引+attempt+state 索引+账本）；DB 增长 2 页=8,192 B |
| T-fail | 25 | 125,440 | 8,720 | 同 T-R2 形状 |
| T-reopen | 25 | 125,440 | 8,720 | hot-journal 回滚后逐行独立结算事务 |

**共享 blob 六场景×四维度验收面（R66S-02 第 6 条；§8 参数 case 接入既有资源/恢复族）**：
A 已 SEALED+B 未 seal（同租户同 digest）/ 两在途行同 digest / true orphan→恢复→重试 /
成功复用 / 重复 open·settle / 物理对象上限已满仍合法复用——每场景对**唯一物理文件数 /
物理字节 / 逻辑身份数 / 记录数**四维度分别断言（禁止只断言「没有漏计」而容忍重复计）；
**原负例回归反例（标注「原协议模型反例，非产品实测」，is_product_test=false）**：A 已
SEALED、B 同租户同 digest idle STAGING，原 per-attempt 结算把被 A 引用的唯一物理 blob 误判
orphan → 对象账 **1→2**（实际唯一物理文件恒 1、内容字节重复计）——RC-P4 以旧规则对照复现
（fail_closed=false），新规则下不可达（回归断言必含）。

**更小等价实现裁定（Assignment §7.2 第 8 条）**：本规约（seal_attempts 行承载预留+逐段新增
峰值预留+锁内有界结算+**v2.2 页级 journal 上界与唯一物理键对账**）即选定**唯一**形态，不把
选择权带入 D2；不建配额平台、WAL 管理池、分布式锁。**多进程/crash 兑现仍标设计**（D2/产品
验收——RC-P1..P4 为真实 SQLite/文件系统模型实测，非产品实测）。

### 7.2 路径与键（条款 18；R66-03 修订）

- 存储键全部系统生成：`blobs/<tenant_storage_key>/<d[:2]>/<d>/blob.bin`、
  `staging/<staging_id>/content.bin`、`quarantine/…`、`metadata.sqlite3`、锁文件；API 面无任何
  调用者路径参数（系统生成 staging key 同样不接受调用者路径）。
- **tenant_storage_key（冻结版本化内部规则 v1）= `SHA256(tenant_id 的精确 UTF-8 字节)
  .hexdigest()`（小写 64-hex）**；**仅用于本地物理目录命名**（blob 分桶、quarantine 等 root
  物理布局）。hash 物理键使租户目录名不再包含冒号/尾点/大小写敏感情形——该类混叠（Windows
  `Tenant-A`/`tenant-a`、`tenant-end`/`tenant-end.` 目录混叠）在物理键层面消除（**设计探针实测
  probe P6，win32**：四租户 hash 键互不相同、目录互不混叠，对照组直接命名混叠复现；**Linux 未
  验证，D2 双平台覆盖**；审核 synthetic_fs 实测互证）。原「冒号在 Win32 触发 OSError
  fail-closed」保留为**纵深防御姿态**（P6-d 实测 `NotADirectoryError`），非主消除手段。
  v1.0「尾随 `.`/空格的名称规范化混叠」表述已删——identifier 字符类不含空格（P6-e；审核
  `trailing_space_contract_valid=false`）。
- **逻辑身份不变**：SQL、ArtifactReference、ACL/权限比较仍按逻辑 `tenant_id` 精确比较——不
  lowercase、不剥尾点、不把两个逻辑租户合并。
- **版本绑定 fail-closed**：内部映射规则版本（`tenant_storage_key_map_version=1`）与 root 元数据
  （`artifact_store_meta`）绑定；打开时发现不一致或可检测冲突 → `METADATA_CORRUPT`
  fail-closed，绝不落入另一租户目录。
- 终点 containment 与链接防护**保留且不被物理键替代**：每次 IO 前 `Path.resolve()` 结果必须
  `is_relative_to(root.resolve())`，否则 `PATH_POLICY_VIOLATION`；tenant_id 虽受契约 identifier
  pattern 约束（首字符必为字母数字，`/`、纯 `..` 不可构造），仍执行该防御性终点校验；
  symlink/junction/reparse/hardlink：发布/读取路径上的符号链接与 junction 拒绝（Linux
  `O_NOFOLLOW` 等价语义；Windows 显式 reparse-point 检查）；发布使用同目录临时文件 + 核验后
  原子改名（同卷原子，不无条件覆盖已存在对象）；blob 发布后只读打开；hardlink 到同内容 blob
  文件无害（内容寻址），威胁是替换，由独占创建/只读打开缓解。
- 受控 root：`root/` 与子目录以最小权限创建（POSIX 0o700；Windows 继承 ACL 并声明限制）。
  **不声称防御同等 OS 权限的恶意本机用户**（条款 18 末句）。#58 identifier 合法域零改动、
  不新增租户注册服务。

### 7.3 SQLite schema、配置面与物理预算规约（条款 19；R66-05 单值 + R66S-01 机制① 单选）

#### 7.3-a 支持的 SQLite 配置面（冻结并绑定 root metadata，不依赖本机默认）

- 文件：`root/metadata.sqlite3`；**`PRAGMA page_size=4096`（P；初始化前固定，之后不可变；
  每次 open `PRAGMA page_size` 实读验证——不符 fail-closed `METADATA_CORRUPT`）**；
  **`PRAGMA journal_mode=DELETE`（P&V 选定单值，2026-10-11；替换 v1.0 无条件 WAL——
  Assignment §7.7 第 10 行已核销；不得两套可选实现并存带入 D2）**；
  **`PRAGMA auto_vacuum=NONE`（v2.2 冻结——避免 ptrmap 页进入脏页集，K_T 派生前提）**；
  `synchronous` 不停用/不降级（**支持值=FULL**；杀进程/OS 活层面保证 journal 先于 DB 页
  落盘——不停用 journal/synchronous 来降低占用）；`busy_timeout=10000`（既有）；
  `PRAGMA foreign_keys=ON`（**v2.2 勘误第二批恢复〔CR-RC-01/SF-01：v2.2 首 commit 误删、
  非授权删除、语义无变化——本 DDL 无外键约束，本项为连接纪律连续性而非语义依赖〕；
  连接纪律：每操作一连接、异常回滚、finally close，参考 `TaskStore`，只读借鉴**）；
  **`PRAGMA max_page_count=M`（v2.2 新增绑定：open 时设置、记录于 `artifact_store_meta`、
  重开验证；M=floor(max_total_root_bytes ÷ P)——由公共行 5 派生的**内部执行参数，不是
  第 14 个公共限额**；默认 512 MiB→131,072 页、合法域上限 64 GiB→16,777,216 页；超限
  SQLITE_FULL → `CAPACITY_EXCEEDED` 稳定拒绝〔错误串不透传〕；RC-P2 实测：到限后重复
  写入三次同错、他表需新页写同样拒绝、page_count 恒=M、DB st_size==M×P、拒绝发生在
  execute 步〔协议顺序中先于任何依赖性内容文件 IO〕、读路径可用、无 journal 残留、
  抬高 M 后写入恢复、把 M 压到当前页数以下被引擎拒绝、需超 M 页的大事务被拒且 DB
  不增长过 M——**不存在「先越限再回滚」的空间泄漏**；页级语义如实声明：已分配页内
  剩余空间可容纳的行仍可写〔限页不限行〕〕**。
- **缓存/溢出边界**：`cache_size` 声明支持范围 [-65536, -2000]（KB 计）∪ [2000, 65536]
  （页计），默认 -2000（2 MiB）；**缓存 spill 不改变 K_T**——journal 对每个不同脏页恰好
  一条原始内容记录，spill 只影响写 DB 文件时机（RC-P1 实测 cache_size=2 强制 spill 下
  R1 17,928/P2 30,232，均不超各自上界）。
- **临时文件面**：本片冻结查询形状（等值/主键查找、有界枚举）不产生 sorter/temp 文件；
  若实现引入产生临时文件的查询形状，须先修订本节给出有限上界并计入行 5 盘点面。
- **journal 与锁文件路径及上界**：`metadata.sqlite3-journal` 仅事务存续期存在（DELETE
  模式提交即删）；其大小上界=§7.3-c 页级公式；**不以 `journal_size_limit` 名称声称瞬时
  硬限**——它只限事务/检查点后留存大小（可以设置但不得作为上界依据）；hot journal 残留
  计额至回滚（RC-P1 实测：崩溃后 journal 在〔8,720 B 级〕、重开读路径已回滚数据、
  **journal 文件迟至下一次写事务才被删除——存在期按实际字节计入行 5/12**）；锁文件
  恒 0 字节。
- **配置绑定（不依赖「刚好本机默认值」）**：P、M、journal 模式、auto_vacuum、
  `tenant_storage_key_map_version`、limits 指纹全部写入 `artifact_store_meta`
  （`cfg_page_size`/`cfg_max_page_count`/`cfg_journal_mode`/`cfg_auto_vacuum`/
  `cfg_kv_mapping_version` 键），open 校验不一致按既有语义面拒绝
  （`METADATA_CORRUPT`/`STORE_CONFIG_CONFLICT`）；13 维限额账本以单行
  `quota_ledger`（canonical JSON ≤1 KiB）承载于同表（每事务账本更新恒 1 行——K_T
  派生单值前提）。
- 版本化：`PRAGMA user_version=1`（本片唯一版本）；初始建表在**单事务**内执行
  `CREATE TABLE IF NOT EXISTS …`（幂等、可重开；模式参考 `TaskStore._init`，只读借鉴）。
  不建跨数据库迁移框架（FR-05 归后续片）。

#### 7.3-b 拟用真实 DDL/索引（冻结；实现可在语义列不变下微调列组织，SF-09）

```sql
CREATE TABLE artifacts(
  artifact_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, task_id TEXT NOT NULL,
  workflow_id TEXT NOT NULL, stage_attempt_id TEXT NOT NULL,
  repository_snapshot_digest TEXT NOT NULL, schema_name TEXT NOT NULL,
  schema_version TEXT NOT NULL, producer TEXT NOT NULL, policy_digest TEXT NOT NULL,
  toolchain_digest TEXT NOT NULL, content_digest TEXT NOT NULL, blob_id TEXT NOT NULL,
  size_bytes INTEGER NOT NULL, media_type TEXT NOT NULL, classification TEXT NOT NULL,
  retention_class TEXT NOT NULL, created_at TEXT NOT NULL, sealed_at TEXT NOT NULL,
  state TEXT NOT NULL, envelope_wire TEXT NOT NULL);
CREATE UNIQUE INDEX idx_artifacts_tenant_artifact ON artifacts(tenant_id, artifact_id);
CREATE TABLE seal_attempts(
  staging_id TEXT PRIMARY KEY, artifact_id TEXT, tenant_id TEXT NOT NULL,
  producer TEXT NOT NULL, task_id TEXT NOT NULL, workflow_id TEXT NOT NULL,
  stage_attempt_id TEXT NOT NULL, repository_snapshot_digest TEXT NOT NULL,
  toolchain_digest TEXT NOT NULL, stage_policy_digest TEXT NOT NULL,
  classification TEXT NOT NULL, retention_class TEXT NOT NULL, state TEXT NOT NULL,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, blob_id TEXT,
  content_digest TEXT, size_bytes INTEGER,
  reserved_staging_bytes INTEGER NOT NULL DEFAULT 0,
  reserved_publish_bytes INTEGER NOT NULL DEFAULT 0,
  reserved_metadata_bytes INTEGER NOT NULL DEFAULT 0,
  reserved_journal_bytes INTEGER NOT NULL DEFAULT 0);
CREATE INDEX idx_seal_attempts_state ON seal_attempts(state);
CREATE TABLE artifact_store_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
```

- 8 个 schema 对象（3 表+2 显式索引+3 隐式 PK autoindex）；**建表列禁止 `COLLATE NOCASE`
  及任何大小写归一排序规则——一切字符串键（tenant_id/artifact_id/staging_id/blob_id 等）
  按 BINARY 精确字节比较**（SQLite 默认即 BINARY；SF-D1R-04 附注）。
- **`seal_attempts.blob_id` 列语义（v2.2 扩写，R66S-02）**：R2 预留事务提交时写入
  （=staged 内容 digest）——**该值非空即物理键 `(tenant_storage_key, content_digest)`
  的在途登记**；重开结算/对象预留判定/R66S-02 规则 2/5 均以本列+artifacts 行为据；
  **零新表/零新列/零新公共接口；行 10 组成不变（artifacts+seal_attempts，无新增私有
  记录可藏账）**。
- **D2 接续私有列（v2.2 落位，Assignment §7.3-1/§11.6）**：`producer`/`task_id`/
  `workflow_id`/`repository_snapshot_digest`/`toolchain_digest`（ProducerContext 持久
  绑定）+`stage_policy_digest`（stage 时实际 policy_digest）+`classification`/
  `retention_class`（manifest 分项）——R1 插入时写入，seal（含跨进程重开再 seal）一律
  以本行持久值为准，不靠内存缓存、不回填新 producer/默认 policy（§10.1）。
  **exact 列集以此为准（P&V 冻结，不留 D2 选择）**。
- `envelope_wire` 存 `encode_envelope` 的 canonical JSON 文本（envelope 本身无日志正文；
  每条记录上界=行 9——逻辑校验界，非计费单位）。

#### 7.3-c 全部写事务形状目录与 K_T 派生（九形状逐项；R66S-01 B 项）

**K_T 派生规则（单值）**：对事务触及的每个 btree，K_T 分量=写入行数（叶页）+写入行数
（分裂余量——每次叶写最多引发一次分裂=1 旧页改写+1 新页）+内部路径页（深度−1，由 M
上界最小扇出推导：M ≤ floor(64 GiB ÷ 4096)=16,777,216 页；rowid 表内部 cell ≈ 4 B 子指针
+行号 varint ⇒ 扇出 ≥ 约 400 ⇒ 深度 ≤ 4 ⇒ 余量 3；短键索引（键 ≤64 B）同 3；复合索引
`idx_artifacts_tenant_artifact`（键 ≈ tenant_id 128+artifact_id 36+开销 ≈ 170 B）⇒ 扇出
≥ 约 22 ⇒ 深度 ≤ 7 ⇒ 余量 6；sqlite_master 余量 3）；溢出页=每 8 KiB 记录 ≤2（RC-P1 实测
单 8 KiB artifacts INSERT 增长 2 页复核）；**新增页并入保守并集（不依赖「新页免 journal
记录」的引擎优化——RC-P1 实测 T-init 高水位仅 512 B 即因该优化，上界仍按含新增页计）**；
auto_vacuum=NONE ⇒ 无 ptrmap 页；本片无 DELETE 语句 ⇒ 无 freelist 释放路径（保守不设
freelist 余量、亦不依赖「leaf freelist 页省略」的缩小方向优化）。

| # | 形状 | 写哪些表/行/索引 | 数据上限 | K_T | journal 上界（B） |
|---|---|---|---|---|---|
| 1 | T-init 初始化事务（单事务） | sqlite_master 8 对象（3 表+5 索引根）+8 新根页+page 1；artifact_store_meta 9 行（root_id/映射版本/limits 指纹/5 配置键/quota_ledger） | meta 值 ≤1 KiB/行（quota_ledger canonical JSON） | 69（master 8+8+3、新根 8、meta 9+9+3、meta PK 9+9+3） | 328,192 |
| 2 | T-R1 R1 预留事务 | INSERT 1 seal_attempts 行（含 D2 接续列+预留字段）+UPDATE quota_ledger 1 行 | attempt 行全列 ≤约 1,150 B（无溢出） | 25（seal 1+1+3、seal PK autoindex 1+1+3、state 索引 1+1+3、meta 1+1+3、meta PK 1+1+3） | 125,440 |
| 3 | T-S3 S3 有界写入段 | **零 DB 写**（纯 staging 文件 IO：O_CREAT\|O_EXCL+fsync+上限即停） | 净化输出 ≤行 2 上限 | 0（无事务、无 journal） | 0 |
| 4 | T-S4 S3/S4 转换事务 | UPDATE 同 seal_attempts 行（RESERVED→STAGING、预留字段清零/转实际）+UPDATE quota_ledger | 同上 | 25 | 125,440 |
| 5 | T-R2 R2 预留事务（含 blob_id 在途登记） | UPDATE 同行（发布段预留字段+blob_id+content_digest）+UPDATE quota_ledger | 同上 | 25 | 125,440 |
| 6 | T-P1reg P1 后登记 | **不使用**（显式声明：发布后登记无独立事务——物理键在途登记已由 T-R2 提交写入；零新表/零新列/零新公共接口；说明书列出的形状逐项表态，无缺项） | — | 0（无此事务） | 0 |
| 7 | T-P2 P2 commit 事务 | INSERT 1 artifacts 行（≤8 KiB 含 envelope_wire→叶+≤2 溢出）+其 PK autoindex+复合索引各 1 条目；UPDATE 同 seal_attempts 行（SEALED/清零）+state 索引；UPDATE quota_ledger | 行 9 ≤8 KiB | 45（artifacts 1+1+2+3、artifacts PK 1+1+3、复合索引 1+1+6、seal 5、seal PK 5、state 5、meta 5、meta PK 5） | 217,600 |
| 8 | T-fail 失败结算事务 | UPDATE 同行（释放未用预留）+UPDATE quota_ledger | 同上 | 25 | 125,440 |
| 9 | T-reopen 重开结算事务（hot-journal 回滚后） | **逐行独立事务**（每非终态行一个 T-fail 形状事务；枚举用只读查询、盘点用独立文件遍历——均不写） | 同上；行数 ≤行 7 上限 | 25（每事务） | 125,440（每事务） |

R1 段 journal 预留=headroom(T-R1)；R2 段=headroom(T-R2)+headroom(T-P2)=343,040 B（含其
预留的 P2 事务）；段末事务 journal 删除（DELETE 模式），余量属未用预留即时释放。

#### 7.3-d 页级 journal 上界公式、适用前提与推翻义务（替换旧行数公式的唯一公式；R66S-01 D 项）

```
journal_headroom(T) = (K_T + 2) × (P + S) + 2 × S   字节
```

- **K_T** = 事务 T 计划改写的不同 DB 页数上界（含计划新增页保守并集）；由 §7.3-b 真实
  DDL 按 §7.3-c 规则派生，逐形状单值（九形状表）。
- **P** = page_size（初始化固定 4096、open 实读验证——§7.3-a）。
- **S** = 每页 journal 记录开销与扇区对齐余量（页号 4 B/页+每页校验和+整扇区整组写入
  对齐+journal 头独立扇区）——**冻结 S=512 B/页**。定值依据（RC-P1 探针，真实 SQLite
  3.45.3/win32）：单页行校准表事务更新 k∈{1,2,4,8,16,32} 页，线性拟合 slope=4,104.0、
  intercept=512.0（即 journal=512+K×4,104，每页开销 8 B——与第三轮审核反例同式吻合：
  66,176=512+16×4,104、99,008=512+24×4,104）；冻结取 Assignment 预期 ≤512 量级上限以
  覆盖扇区对齐批写与平台差异（一次小库观测只是样本；Linux D2 复测义务保留）。
- **+2 页/+2S** = journal 头（独立扇区）与 commit 记录/对齐余量。
- **官方机制依据**（sqlite.org/atomiccommit.html，Packet 内引用）：journal 在修改任何
  DB 页之前写入该页**原始内容**；页号随每页记录存储；同扇区页整组写入；journal 头独立
  扇区；**journal 头 nPage 字段由 0 改为真实值使其后 journal 失效（不可回滚点）；DELETE
  模式提交点=journal 删除（头失效）**（v2.2 勘误第二批措辞修正，CR-RC-01/SF-05）；leaf
  freelist 页省略是**缩小**方向不影响上界 ⇒ journal 大小 ∝ 事务改写的**不同页数**而非
  行数——这正是实测反例的机理（8 行→16 页+640 B、12 行→24 页+704 B，与页记录机制一致；
  该实测构成对行数公式的反例、同时与页级机制相容）。
- **适用前提（五条，全部满足才可用本公式）**：① 事务形状限定于 §7.3-c 目录冻结形状
  （每类脏行/行字节/索引/btree 深度有界；**同事务多表混写等非冻结形状不在此上界内——
  RC-P1 记录其对照测量 33,344 B ≤ ΣK=70 上界，产品不得采用**）；② 配置面 §7.3-a 全部
  绑定验证（P/模式/auto_vacuum/M/synchronous）；③ 单写临界区序列化（§7.1d 既有），无
  并发写事务 journal 叠加；④ K_T 派生含溢出/分裂/新增页保守并集；⑤ P/S 实读或探针
  冻结值。
- **可反驳性（强制）**：P&V 已用真实 DDL 压力探针**尝试推翻**该上界（RC-P1 八项：边界
  行字节 8 KiB/最大 K_T 形状/分裂风暴 3,000 随机键/小 cache spill/DB 近 M 页/小 cap/
  写后回滚/真崩溃热 journal——全部未推翻，实测高水位均 ≤ 上界）；**任一实测 > 派生上界
  ⇒ 前提失效，触发 Assignment §12 停点（回 Coordinator 重裁定，不得自行放大系数或换
  公式再 READY）**。ER 将独立重复推翻尝试（Assignment §1 后续角色链②）。
- R1/R2 段按各自事务形状的 K_T 分别入账（R2 段含其预留的 P2 事务）；事务结束 journal
  删除（DELETE 模式），余量属未用预留即时释放；hot journal 残留计额至回滚（含「文件
  迟至下一次写事务才删除」的存在期，RC-P1 实测）；锁文件恒 0 字节；计入行 5/12；辅助
  文件余量不足 → `CAPACITY_EXCEEDED` 先拒绝（合法较小 auxiliary cap 同一公式判定，不为
  通过演示放大公式或 cap——§7.1f 例⑦）。
- **旧公式撤销声明**：`4096×(计划脏行数+2)+16384` 及其一切行数口径变体不再作为 journal
  上界；其示例值（`J(1)=28,672…J(5)=45,056`、`69,632`、`333,776`、`269,536`、`134,768`）
  已按 RC Assignment §11.7 例值处置裁定选定「重算重写」全文替换（历史登记处标注「被取代」）——不是乘二、不是
  换一组示例、不是只验证算术。

#### 7.3-e 验证边界（如实声明；D2/产品义务）

真实多进程/kill/双平台验证归 D2/产品阶段（本版不报产品已通过）；P6 Linux 存储路径
缺口保持；RC-P1..P4 为 win32 单机样本（真实 SQLite 引擎+真实文件系统，协议模型驱动），
PASS ≠ 产品正确；页级上界只在 §7.3-d 五条前提下成立；DELETE 模式下写事务期间读者阻塞、
busy_timeout 超时映射 `CONCURRENCY_LIMIT_EXCEEDED` 语义面；Windows 无目录 fsync
（§7.4 声明，文件级尽力）；回滚自身 IO 失败 → fail-closed（`IO_ERROR`/`METADATA_CORRUPT`
路径），不虚造状态；重启后仅见「已提交」或「净回滚」两态（无第三态，D2 kill 验证义务）。

### 7.4 崩溃/重启验证与平台分层声明（条款 20）

- 验证方式：**真实子进程 + 真 kill**（非模拟）：测试在子进程内于各协议步（**R1 后**〔R66F-02
  新增点：预留已提交、未写任何内容文件〕/S3 后/P1 前/P1 后/P2 前/P2 后——六点）设置标记文件，
  父进程观测标记后调用 `subprocess.Popen.kill()`（Windows=TerminateProcess；Linux=SIGKILL）
  终止，再以**新进程**重开 root/SQLite 断言 §4.3 矩阵与 §7.1f 状态/动作表（**重开结算断言：
  先结算后写；结算后账本 ≥ 实际盘点——orphan 不漏账、空预留解除、未知实物 fail-closed、
  live 名额/记录/字节三口径与 §7.1 限额表一致**）；P2 中崩溃必须断言 DELETE hot journal 回滚
  两态（已提交/净回滚，无第三态）；临界区内崩溃必须断言 OS 锁自动释放、账本不丢不重
  （§7.1d）。
- 持久化分层声明：本片验证与保证**进程崩溃**层面（进程死、OS 活）；API 边界 fsync（文件级
  `os.fsync`；Linux 目录 fsync；Windows 无目录 fsync API，仅文件级）尽力缩小 OS 缓存窗口；
  **不声称**文件系统/物理断电层面的跨平台原子性或持久性证明。Windows 与 Linux 都必须实际运行
  kill/重启验收（缺平台保留实际缺口，不以 skip 冒充通过）。

## 8. 测试方法与最小覆盖数 + 独立 Oracle（对齐说明书 §7 七组与 §7.2 D2 覆盖组）

**D2 才冻结实际测试文件名/符号/计数**；本节冻结方法族与最小覆盖数（合计 44 个测试方法——超出
P&V 默认预算 35 的理由：D1R 六项修正各自新增行为面（输出校验前置、复用核验、hash 物理键隔离、
限额计额与配置冲突、六字段绑定、回执/读结果分型）需要对应反例；按行为覆盖收敛，未删减任何
安全断言，不靠重复方法刷计数；D2 冻结时各组最小数不得降低。**D1F（R66F-01/02/03）：44 最低数
不变——新分支（expected 全组合、四态映射重核、预留-结算七例、真实构造触发面）一律以参数 case
接入既有方法族，不刷数、不降数（Assignment §11.13）**）。**RC（R66S-01/02）：44 最低数不变——页级上界/整 root 盘点/共享
blob 六场景四维度一律以参数 case 接入既有资源/恢复族，不刷数、不降数（RC Assignment
§11.8）**）。**D2 冻结测试须含记录上限水位（行 10 域值）下的 btree 深度/脏页数边界参数
case，断言冻结形状 journal 高水位 ≤ 页级上界（CR-RC-01/SF-07）**。探针/本表 PASS 均不构成产品实现证据。

| 组（说明书 §7/D2 覆盖组） | 方法族 | 最小数 | 必含反例 |
|---|---|---|---|
| 隐私 | 真实 storage policy 净化；磁盘/DB/错误信息中无 raw Secret（含 SQLite 全文扫描）；缺 key/policy、净化失败、UNSUPPORTED_REDACTED_FORM 时零内容写入（目录快照对比）；**错 tenant 注入 → SanitizedPayload.tenant_id 不符 → S2b 拒绝零落盘（R66-01）；manifest 携错误 policy_digest → S2c 拒绝零落盘** | 6 | FingerprintRecord 形态拒绝且零落盘；绑定/策略反例经真实净化输出 |
| 真实闭环 | 同进程 stage→seal（回执）→get（读结果）；**seal expected_content_digest=None 与正确匹配值两参数 case（正常分支，R66F-01）**；**新进程**重开 root/SQLite（同 root+同可信租户+policy）读回同字节；独立 digest 复算；envelope/blob_ref/reference 三方绑定校验；**回执无 content 字段 / 读结果 content=已验证字节（含合法空日志 b"" 唯一语义）** | 5 | 字节级全等断言（非仅 digest 相等） |
| 权限与输入 | 错租户（== NOT_FOUND 不可区分）；**六字段 ref 逐项校验（合法格式但错误 repository_snapshot_digest/content_digest → ARTIFACT_NOT_FOUND，R66-06②）**；**错 schema 触发面=实际可传入对象（R66F-03）：错误 schema_name 的合法 Reference、4.1 的合法 Reference → UNSUPPORTED_SCHEMA；非 Reference 对象（dict 等）→ INVALID_ARGUMENT——不期待未调用的函数捕获构造期异常（P11 真实触发面）**；**seal ⓪ 参数形状：非法 expected 格式（大写/短/非 hex/int）与非 StagedLogHandle/非法 declared_state → INVALID_ARGUMENT 零副作用、先于 ①–⑤（R66F-01，参数 case）**；非空 lineage/supersedes（stage 与 envelope helper 双入口）；未封送 id；缺失/损坏 blob 拒绝；**外来 root/tenant handle 拒绝（STAGING_STATE_INVALID）**；**handle 状态判定反例：declared=sealed + 权威行 STAGING → STAGING_STATE_INVALID（CR-D1R-01④）；权威行 RESERVED × declared=staged / declared=sealed 两组合 → 同归 STAGING_STATE_INVALID（CR-D1F-01 补裁，参数 case 接入；16 状态谓词模型原 ①–⑤ 枚举不含 RESERVED 组合，本两组合为其扩展）**；拒绝不泄露他租户 | 7 | 伪造 ref / 篡改 wire digest / 合法格式错误 digest |
| 不可变与重试 | 同 handle 重复 seal 幂等（**含跨进程重开 handle、P2 后崩溃重试**）；**expected 参数 case 全组合 × 幂等/重开（R66F-01，参数 case 接入）：None/匹配/合法错值〔64-hex 但非本内容〕/非法格式 × 正常分支/SEALED 幂等分支/新进程重开重试——SEALED+错 expected → SEAL_DIGEST_MISMATCH 且原状态不动（不返回回执、不覆盖 blob/metadata）**；**declared=staged + 权威行 SEALED 重试 → 同一回执（blob 核验+expected 两关通过后，CR-D1R-01③）**；**幂等成功仍核验实物：SEALED 后实物损坏 → 重复 seal 稳定失败非假幂等（R66-02）**；**同长度坏旧 blob + 合法新 staging → 复用前核验拒绝（零覆盖、零新增 SEALED、原字节不动）**；**竞态分支核验（目标在核验与发布间出现）**；并发 seal（线程/进程）单胜者且不覆盖已存在有效对象；同字节不同 staging → 不同 artifact_id 同 blob；METADATA_CONFLICT 不覆盖 | 7 | 并发窗口内无双重提交；坏复用零副作用 |
| 故障与恢复 | 真子进程 kill 于 **R1 后〔R66F-02 新增〕**/S3 后/P1 前/P1 后/P2 前/P2 后六点（两平台）；**重开结算断言（R66F-02）：先结算后写、结算后账本 ≥ 实际盘点（orphan 转实际占用不漏账、空预留解除、行保留占行 7/10、未知实物 fail-closed）**；**stage 后 staging 被改坏（截断/篡改/删除/替换为链接或目录）→ seal 重核按四态映射拒绝（PATH_POLICY_VIOLATION/BLOB_MISSING/BLOB_SIZE_MISMATCH/BLOB_CORRUPT，次序 lstat→size→digest）、零发布零新增 SEALED、expected 比较不掩盖实物错误（R66F-01）**；重启诊断分类正确；**P2 中 kill → DELETE hot journal 回滚两态**；部分/缺失内容不作为成功返回；**close 不破坏重试（close 后重开+原 handle 幂等）** | 6 | 无假 SEALED 断言 |
| 资源与路径 | 0-byte、Unicode 字节边界（单 emoji/多字节）、输入超限、**净化输出超限（膨胀反例 262,119 B 输入→365,378 B 输出 → SEALED_BUDGET_EXCEEDED、零内容写入、零持久诊断行、staging 目录为空、稳定失败无降级，R66-04/02）**、**更严格 policy 交集收紧（注入更严 policy 触发失败）**、**限额计额（重复同内容/空内容仍消耗逻辑额度；失败/崩溃残留计额；两真实进程争最后一个额度不超限〔按「实际+有效预留」双口径，预留提交即计——RC-P3 序列复现〕；同 root limits 不一致 → STORE_CONFIG_CONFLICT；**预留-结算参数 case（接入本族）：R1/R2 保守预留先拒绝 CAPACITY_EXCEEDED 零提交零文件 IO、publish 副本另扣（262,144 B 内容剩余 300,000 B 时 R2 需 646,144 B 先拒绝——524,288B 双副本反例消解）、合法较小 auxiliary cap 64 KiB 同公式拒绝（R1 即拒）、行 7 RESERVED 占 live 名额、P2 后 live 释放而行 4/5/10 保留；**R66S-01 参数 case（接入本族）：页级上界数值核对（各形状实测事务内 journal 高水位 ≤ (K_T+2)×(P+S)+2×S——K_T/S/P 按 §7.3 冻结值）、`PRAGMA page_size`/`max_page_count` open 实读与绑定校验、M 派生=floor(行5÷P)、到限（SQLITE_FULL→CAPACITY_EXCEEDED）稳定拒绝且先于依赖性内容 IO、DB st_size==page_count×P、初始化即计入 DB 文件字节（≠行字节示意）、预留事务自身/失败/恢复/hot-journal 回滚均在声明预算内、非法配置（page_size/auto_vacuum/journal 模式漂移）open 拒绝；R66S-02 六场景四维度参数 case（接入本族）：A 已 SEALED+B 未 seal/两在途行同 digest/true orphan→恢复→重试/成功复用/重复 open·settle/对象上限满仍合法复用——对唯一物理文件数/物理字节/逻辑身份数/记录数四维度分别断言（禁止只断「无漏计」），原 per-attempt 负例（对象账 1→2）作为回归反例断言不可达（标注「原协议模型反例，非产品实测」）**；inspect 扫描有界）**、**两平台租户键（Windows `Tenant-A`/`tenant-a`、`tenant-end`/`tenant-end.` 独立物理目录互不混叠；合法标识含冒号/保留名租户正常封存；Linux 不同逻辑租户同内容独立存放；逻辑层 SQL/Reference/ACL 仍区分大小写与尾点，R66-03）**、路径穿越/symlink/junction/reparse 拒绝、满盘/权限（模拟注入） | 9 | 空对象不绕对象数；失败不变空成功 |
| 持久化边界 | SQLite 无日志正文/凭据（全库扫描）；metadata/ref 有界（行 9）；store 不可用无 inline/旧 report_json 降级；contracts/privacy 既有测试回归 + #60 面零触碰 | 4 | 契约兼容（import 面/wire 面） |

**独立 Oracle 要求**（D2 交付，禁止复用被测实现路径）：
1. digest 复算：`hashlib.sha256(sealed_bytes).hexdigest()` 直接计算，不经 `lima` codec；
2. 绑定校验：独立 JSON 遍历 envelope wire dict，验证 `content_digest==blob_ref.content_digest`、
   size、media type、schema 身份（不经 `decode_envelope`）；
3. 重启复读：独立子进程读文件字节做全等比较（不经 `get_log`）；
4. kill 时序：父进程独立观测标记文件（不在子进程内自证）；
5. **限额独立盘点（R66-05）**：独立文件系统遍历 + SQLite 只读查询重算对象数/字节数，与账本行
   比对（不经 store 计数接口）；
6. **物理键独立性（R66-03）**：独立计算 `SHA256(tenant_id)` 键并断言目录互不混叠（不经 store）；
7. **预留-结算独立盘点（R66F-02，D1F 新增；v2.2 扩 R66S-01/02 口径）**：独立遍历授权物理范围
   （staging//blobs//publish 临时/quarantine/）+ 只读查询 seal_attempts 非终态行与预留字段，
   重算「Σ实际+Σ有效预留」双口径并与账本比对（不经 store 计数/结算接口）；kill 后断言
   **结算后账本 ≥ 实际盘点**（orphan 不漏账——审核反例 ledger=0/physical=1 不再可达的
   负例断言）。
8. **整 root 独立盘点 Oracle（R66S-01，RC 新增）**：独立 os.walk 整个 root（常规文件、
   含 metadata.sqlite3/journal 与热 journal/锁/staging/publish 临时/最终 blob/quarantine
   及声明辅助文件）按 st_size 求和，分类+合计分别与账本比对（初始化后即含 DB 文件
   字节——P10 的 lhs=0 缺陷为负例断言）；断言 row bytes（行 9 逻辑界）与 DB bytes
   （行 5 物理计）无双计；断言到限在内容 IO 前稳定拒绝、事务内 journal 高水位 ≤
   §7.3-d 上界（不经 store 计数函数自证——RC-P3 方法）。
9. **共享 blob 唯一物理键独立断言（R66S-02，RC 新增）**：独立枚举 blobs 布局的唯一物理
   键集合 U 与独立文件计数，对六场景分别断言四维度（唯一物理文件数/物理字节/逻辑身份
   数/记录数）无重复计、无漏计（RC-P4 方法；含「同键第二文件/布局外实物 fail-closed」
   负例）。

## 9. Traceability

### 9.1 #66 requirement ID 逐行映射（18 ID；**无一条 SATISFIED**——D1R 零产品证据；状态语义：
PARTIAL=本片冻结其中本机 SQLite/日志子集行为、余下归后续片与 D2+ 证据；DESIGN-ONLY=本片仅设计
层冻结、实现证据归后续；NOT-COVERED=本片不做；**分布与 v1.0 不变：PARTIAL 14 / NOT-COVERED 2 /
DESIGN-ONLY 2 / SATISFIED 0——首片边界未扩大**）

| ID | 状态 | 本片贡献与理由 | 下一 Owner |
|---|---|---|---|
| FR-01 | PARTIAL | stage 仅建 attempt-scoped handle（净化已完成、输出校验先于任何写入、staging 只含净化内容）；seal 在类型/绑定/schema/digest/预算全过后返回 immutable ref 回执 | 后续片扩展非日志类型 |
| FR-02 | PARTIAL | 状态机实现 STAGING→SEALED 子集（QUARANTINED/EXPIRED/DELETING 不出现、corruption 不改状态）；**seal_attempts 生命周期含 RESERVED（R66F-02 预留载体；不入 artifact 状态机）**；SEALED 内容/身份绑定无任何覆盖路径（P1 三分支核验+临界区发布不覆盖既有有效对象，R66-02） | 后续片补 QUARANTINED/EXPIRED 转移与 ACL 面 |
| FR-03 | PARTIAL | 提交点协议（§4.2）明确 crash points；`inspect` 输出 staging/orphan/metadata-only/corrupt 四类；不静默伪造内容 | 后续片补 expired-with-reference 分类与自动 reconcile |
| FR-04 | PARTIAL | get 六字段绑定（G1–G6，R66-06②）；租户不符不可区分拒绝；本片无 lineage 查询（空 lineage only，非空双入口拒绝） | 后续片补 list_lineage/DAG/自环跨租户边 |
| FR-05 | NOT-COVERED | 本片仅版本化幂等建表（PRAGMA user_version+单事务 IF NOT EXISTS），非 migration registry；#67/#65 入口不存在 | 后续片（migration registry slice） |
| FR-06 | NOT-COVERED | 无 retention/pin/删除接口（首片无公共 delete/update）；容量满拒绝新写而非清理 | 后续片（retention slice） |
| NFR-01 | PARTIAL | 0-byte 到上限可验证（探针 P4.2a 实测 0-byte 路径）；**输入与净化输出双预算均在任何内容写入之前判定（S0/S2；膨胀反例 262,119→365,378 已纳入 §8，R66-04）**；路径/symlink/junction/reparse 防护（§7.2）；**hash 物理键消除大小写/尾点目录混叠（P6 win32 实测；Linux D2）** | 后续片补满盘演练平台面 |
| NFR-02 | PARTIAL | Blob IO 与 SQLite metadata 分离、业务仅 ref/字节/错误；本片仅本地 backend、不写 S3 SDK/配置框架；S3-compatible Port 语义由行为契约保证 | 后续片（S3 adapter） |
| AC-01/T-01 | PARTIAL | §4.3 矩阵 + §8 故障组（六 kill 点〔含 R1 后，R66F-02〕、两平台、真子进程、DELETE hot journal 两态、重开结算断言〔orphan 不漏账/空预留解除/未知实物 fail-closed〕）；无假 SEALED 断言 | D2+ 实证 |
| AC-02/T-02 | PARTIAL | 同 handle 幂等（含重开/崩溃重试且核验实物）、并发 seal 单胜者不覆盖、租户隔离（逻辑精确比较+hash 物理键双层）、无 ACL 放宽面（§4.4）；同字节≠同身份 | D2+ 实证 |
| AC-03/T-03 | PARTIAL | corrupt/missing blob、路径逃逸 fail closed 且 metadata 不丢（§6.1）；**坏旧 blob 复用在 seal 侧拒绝（R66-02，非仅 get 兜底）**；lineage 自环由契约层拒绝（源码复核：common.py `LINEAGE_SELF_REFERENCE`）、跨租户由契约层拒绝（探针 P3-B）+ 本片空 lineage only；Redis 不在链路 | D2+ 实证 |
| V5-FR-01 | PARTIAL | 新增 artifact 路径只存 metadata+blob ref（envelope_wire 无正文，§7.3）；**历史 report_json 迁移不在本片**（#66 仍是唯一迁移 Owner） | 后续片（迁移 slice） |
| V5-FR-02 | DESIGN-ONLY | seal 前强制 #94 policy 冻结于协议 S1（前置任何持久化；探针 P1 实测真实调用面；**policy 必填显式注入冻结于 §5.3 签名，R66-06①**）；实现证据归 D2+/IMPL | IMPL |
| V5-FR-03 | PARTIAL | digest verification 冻结为 G5 必检（探针 P3-A 证明不可省略）+ **六字段逐项绑定（G3）**；retention class 校验接受面；lineage query/tombstone 未实现（明确拒绝非空 lineage） | 后续片 |
| V5-FR-04 | DESIGN-ONLY | 无 inline 降级路径冻结于错误语义（CAPACITY_EXCEEDED/IO_ERROR 均拒绝，绝不回退 inline 巨型 JSON/旧 report_json）；实现证据归后续 | IMPL |
| V5-AC-01/V5-T-01 | PARTIAL | DB 只存 metadata/blob ref + seal 前强制 #94 + 不内联（§4.2/§7.3/§8 持久化边界组） | D2+ 实证 |
| V5-AC-02/V5-T-02 | PARTIAL | digest verify、跨 tenant/type mismatch 按契约工作（§6.1）；retention/tombstone/lineage query 未覆盖 | 后续片 |
| V5-AC-03/V5-T-03 | PARTIAL | blob/store 中断、partial write、重复 seal 可恢复且不返回未封存 Artifact（§4.3 矩阵 + §8） | D2+ 实证 |

分布统计：PARTIAL 14；NOT-COVERED 2（FR-05/06）；DESIGN-ONLY 2（V5-FR-02/04）；SATISFIED 0。

### 9.2 Assignment §7 条款 1–20 覆盖索引（D1 二十条；R66 改变者已更新落点）

| 条款 | 冻结位置 | 条款 | 冻结位置 |
|---|---|---|---|
| 1（类型身份） | §4.1 表 | 11（不持久化敏感物） | §6.1 错误面 + §7.3 |
| 2（复用契约） | §4.1 wire 行 | 12（stage/seal/get+入口） | §4.2、§5.3、`demo.py` |
| 3（digest 来源） | §4.1 digest 行（探针 P2） | 13（信任边界） | §4.5、§6.2 |
| 4（真实上下文） | §4.1 上下文行 + §5.3 字段表 | 14（身份/幂等/并发） | §4.4 |
| 5（lineage 空集） | §4.1 lineage 行 + §5.1 schema.py（探针 P3-C） | 15（提交点协议+处置） | §4.2（DR-PACKET-1） |
| 6（classification 相容） | §4.1 接受面行（探针 P1/P5） | 16（故障点矩阵） | §4.3 |
| 7（真实净化调用） | §4.2 S1（探针 P1/P5） | 17（资源上限） | §7.1 统一限额表 |
| 8（失败零落盘） | §4.2 S2、§6.1 | 18（路径与键） | §7.2 |
| 9（str-only 接受面） | §4.1/§6.1（探针 P1/P5） | 19（SQLite schema） | §7.3 |
| 10（双预算） | §7.1 + §4.2 S0/S2（探针 P4/P7） | 20（崩溃/重启验证） | §7.4 |

## 10. 平台命令骨架（实际命令面 D2 冻结；此处冻结骨架与平台义务）

**基线（合并前基线健康，两平台同）**

```bash
git fetch origin && git rev-parse origin/main        # 基线 SHA 声明
python -m compileall -q lima tests
python -m unittest discover -s tests -v              # 既有套件全绿（contracts/privacy/audit/#60 面零回归）
```

**slice（本片验收面）**

```bash
python -m unittest discover -s tests/artifacts -v   # D2 冻结的测试集
python -m ruff check lima/artifacts tests/artifacts
python -m bandit -q lima/artifacts
```

**integration（真实闭环示例）**

```bash
python -m lima.artifacts.demo --root "$TMP/ip0044-demo"   # 进程内闭环 + 子进程重开 + 独立 digest 复算
```

**boundary（文件边界 gate）**

```bash
git diff --name-only <base>..HEAD                    # 只允许 lima/artifacts/** 与 tests/artifacts/**（实现期）
git diff --check
```

**compatibility（契约兼容）**

```bash
python -m unittest discover -s tests -v              # 含既有 contracts/privacy 测试
python - <<'PY'
import lima.contracts.common, lima.evidence_privacy.port  # import 面未变
PY
```

**kill/重启（真子进程；两平台各自运行，缺平台记实际缺口）**

```text
Windows（PowerShell/Git Bash）：
  python -m tests.artifacts.crash_harness --point post_publish --root <tmp>
    （父进程：subprocess.Popen(...); 观测标记文件; child.kill()/taskkill /PID <pid> /T /F;
      新进程重开 root/SQLite 断言 §4.3 矩阵；P2 点含 DELETE hot journal 两态断言）
Linux：同 harness，父进程 os.kill(pid, SIGKILL)；其余一致
```

**post-merge（合并后在最新 main）**

```bash
python -m unittest discover -s tests/artifacts -v && python -m unittest discover -s tests -v
python -m lima.artifacts.demo --root <fresh tmp>
```

### 10.1 D2 收敛义务（v2.0：仅保留仍真实的义务；SF-05/SF-08 已核销）

**已核销登记**：

- **SF-05（abort 载体 D2 二选一）：核销**——R66-06④ 裁定删除 `STAGING_STATE_INVALID` 的「已
  abort」触发条件（本片无公共 abort 入口、`close()` 不批量 abort，该状态不可达；Assignment
  §11.9）。触发面收窄见 §6.1。
- **SF-08（content 双语义判空提示）：核销**——R66-06⑤ 裁定分型（`SealedLogReceipt` 无 content
  字段 / `RetrievedLogArtifact.content` 恒为已验证字节，合法空日志 `b""` 语义唯一；Assignment
  §11.10）；旧 `SealedLogArtifact` 类型删除（§5.1/§5.2/§5.3）。

**仍保留的 D2 收敛义务**：

1. **SF-06（crash harness 命名统一）**：§10 kill 骨架的 `tests.artifacts.crash_harness` 模块名
   与 §5.1 测试命名面（`tests/artifacts/test_*.py`）须在 D2 冻结时统一（harness 可为测试辅助
   模块，但命名归属须单值）。
2. **SF-09（内部模块落点/表列组织）**：`SealedLogReceipt`/`RetrievedLogArtifact`/
   `StoreHealthReport` 的模块归属（local_store.py vs schema.py vs recovery.py）与 SQLite 列
   组织可在 §5.1 文件边界内由 D2/IMPL 收敛——公共签名、字段与语义本轮已冻结（§5.3），仅物理
   落点可调（R66-06 收尾要求）；**seal_attempts 预留字段列（R66F-02）属语义列冻结面，落点调整
   不得改变其承载与结算语义**。

**D1F 附注（R66F-02）**：§10 kill/重启与 §7.4 的验收义务**已含预留-结算兑现**——六 kill 点
（含 R1 后）+ 重开结算断言（先结算后写、结算后账本 ≥ 实际盘点、未知实物 fail-closed）是
D2 冻结测试的 mandatory 组成，不是可选项；P10 协议模型 PASS 不解除该义务。

**D2 接续义务预告（RC v2.2 新增，落位正文不藏在测试里；RC Assignment §7.3/说明书 §6.2）**：

1. **stage 接续**：未 seal 就 `close()` / 新进程重开后再 `seal_log` 原 handle——原
   ProducerContext（producer/task_id/workflow_id/stage_attempt_id）、
   repository_snapshot_digest/toolchain_digest、classification/retention、**stage 时实际
   policy_digest** 必须持久绑定并原样用于 seal。载体已冻结：`seal_attempts` 私有列
   （§7.3-b D2 接续列集——producer 上下文 8 列+stage_policy_digest，R1 插入时写入）；
   不靠内存缓存、不回填新 producer/默认 policy。**D2 冻结测试必须比较全部
   Envelope/reference 绑定字段，不得只测试「先 seal 再重开 get」**。
2. **policy 变化规则（Coordinator 依既有合同明示，本条即裁定——RC Assignment §11.6）**：
   stage 所用 policy_digest 持久保存（同上列）；**本首片默认未封存 handle 只能在相同
   policy_digest 下 seal**——seal 时 open 注入 policy 的实算 digest ≠ stage 持久化 digest →
   稳定 `SANITIZATION_FAILED`（策略类，复用既有码零新增）、零新增 SEALED、不把当前
   policy 重新冒充 stage 策略、不动 staging 实物；与 S2c 既有 policy_digest 实算比对语义
   同族。SEALED 读取保留原 Envelope 事实与既有租户权限，不重写历史。
3. **定性声明**：上述属既有持久 handle/真实上下文合同的实现与 D2 细化义务，不新增认证
   产品；若与更高权威冻结 contract 冲突，提交集中 DR 而非擅改（当前无冲突）。

## 11. Decision Request 区（随 Packet 呈批）

1. **DR-PACKET-1（既有呈批项，v2.2 更新表述——RC Assignment §9.6）**：提交点协议对 #66 原文
   「先写临时 blob→fsync/verify→事务写 SEALED metadata→原子 rename」的处置——**R66-02 两
   前提（既有 blob 有效复用与并发发布不覆盖）已由 v2.0 落地为三分支核验+临界区规则；
   R66F-01/02/03 已由 v2.1 收口；本轮剩余=R66S-01/02 收口（v2.2：物理预算规约+共享 blob
   唯一结算），处置随新 head 一并呈批，未获批前不视为已批准**。本 Packet
   采用保留全部元素、把原子 rename 前移到 metadata 事务之前的等价重排，并给出读者无
   不完整可见窗口的证明与覆盖范围声明（§4.2；已发布 blob 的崩溃残留按 §7.1f 物理键在途
   登记与 U 对账结算计额）。请 Maintainer 在本 Packet v2.2 新 head 批准时一并裁定该处置
   （与首片范围批准为同一个合并决定）。
2. 其余：无新增 DR。六类升 Maintainer 事项（跨租户共享/真实身份来源/删除合规/默认部署/公共
   Contract/Profile 来源身份）本轮均未触发；SQLite 内部表结构、文件组织、实现手段按 Assignment
   §11 由责任角色在批准范围内自决（R66-06 公共合同已本轮冻结，不留给 D2/Implementation）。

## 12. 完成定义（Packet 完成本身，非产品完成）

本 Packet 视为完成，当且仅当：
1. 12 节齐备、20 条冻结项全部落地为可验证契约（§9.2 索引无空洞）、18-ID 映射表无 SATISFIED 且
   分布不变（PARTIAL 14 / NOT-COVERED 2 / DESIGN-ONLY 2 / SATISFIED 0——**v2.1/v2.2 不变，
   Assignment §11.14/RC §11.8**）；
2. 六项 R66 + 三项 R66F + 两项 R66S 各有唯一合同与可复核依据（§1.2 对照表）、§1.3 十六行
   （D1R）+十五行（D1F）+**十七行（RC，R1–R17）**替换核销完成、全文无新旧并存反义表述
   （含 S4+expected、诊断行、S0 额度、构造期映射、行 4「失败=释放预留」旧句式——特别检索
   通过；**v2.2 追加检索：`4096×`、`J(N)`、`(计划脏行数+2)`、`333,776`、`269,536`、
   `134,768`、`J(2)=`、「blob 在、无 artifacts 行」、「计划写入行字节合计」——命中处必须
   已是历史标注〔「被取代/原协议模型反例」〕或新规约**）、关键接口无 TBD（open/stage/seal/get
   签名、错误码表 23 码、handle 字段表、回执/读结果类型、统一限额表、journal 模式单值
   DELETE、seal 六段次序、预留-结算协议、**页级 journal 公式+DDL/九形状目录+K_T/S/P 冻结值+
   配置面+M 派生**）；冻结值均有源码复核或设计探针实测支撑并标注出处；**公共签名块（§5.3
   代码块）逐字不变、§8 方法最低数 44 不变（Assignment §11.13/15/RC §11.8）、零公共限额
   合法域/默认/硬上限变更（RC §11.2——M 为行 5 派生执行参数非第 14 个公共限额）**；
3. 设计探针 P1–P11 与 **RC-P1–RC-P4** 在 `.pv_tmp/issue66-local-log-2026-10-10/probes/`
   留有输入/命令/输出/脚本，可复现；R66-02/R66-05/R66F-02/R66S-01/02 的多进程与 crash
   兑现如实标注协议推导/设计（D2/产品验收；P9–P11 区分 SQLite 实测/协议模型/真实
   foundation API，RC-P1..P4 区分真实引擎实测/协议模型，不越类引用）；**P10 作为 journal
   公式/root 计账证据的引用处已标注证据限度（lhs=0 vs 实际 28,672 B；行字节示意≠DB 物理
   增长——§7.4 R8/DI-029），现行口径以 RC-P1..RC-P4 为据**；
4. docs-only 新 commit 落在 `codex/issue66-local-log-packet` 的 `1e223326` 之上（**保留
   `de7181b3`/`1e6a6874`/`f1f3aab`/`8377a6e`/`70906428`/`1e223326` 六 commit 历史**，不
   amend/force），`git diff --name-only 1e223326..HEAD` 与 `git diff --name-only
   fbbbd619..HEAD` 均仅本文一份 md，工作树 clean，`git diff --check` 干净；
5. PR 呈审以新精确 head 为准（`Related to #66`、无任何自动关闭关键字），停在审批点。

产品完成定义不在本文：需 D2 冻结测试 + 有效 RED + IMPL + 独立验证 + post-merge，且 #66 整体关闭
仍需完整 Closure Audit 与明确授权（首片完成 ≠ #66 DONE）。
