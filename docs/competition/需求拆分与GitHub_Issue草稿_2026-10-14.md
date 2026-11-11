# OpenHarmony 赛题需求拆分与 GitHub Issue 草稿

日期：2026-10-14。用途：需求拆分与实施草稿。首批六项已发布为 GitHub #288–#293，并已分配给 wenxinliu52；其余任务仍为候选。

已发布任务：E02→[#288](https://github.com/agent-sec-labs/LIMA/issues/288)、E12→[#289](https://github.com/agent-sec-labs/LIMA/issues/289)、E13→[#290](https://github.com/agent-sec-labs/LIMA/issues/290)、E09→[#291](https://github.com/agent-sec-labs/LIMA/issues/291)、E03→[#292](https://github.com/agent-sec-labs/LIMA/issues/292)、E04→[#293](https://github.com/agent-sec-labs/LIMA/issues/293)。远端正文已按“Codex 实施步骤 + wenxinliu52 人工验收”扩写；本地正文备份见 `issue-drafts/E*.md`，发布记录见 `issue-drafts/published.json`。

## 1. 分工与基线

建议把任务分为三类：

- **E：工程任务**，建议 wenxinliu52 负责。需要 Python、PowerShell、JSON、测试或文档能力，不要求判断漏洞是否成立。
- **C：需要先冻结专业判据的工程任务**，你先给输入与期望输出，wenxinliu52 再实现数据接线、统计或展示。
- **V：漏洞专业任务**，你负责机理、样本资格、CWE、PoC、安全影响、修复正确性和最终漏洞判定。

低漏洞知识要求不等于低工程难度。E 类不能修改漏洞裁决、ASan 命中判据、快照身份、沙箱策略或修复 Oracle。需要改这些边界时，拆出 V 类设计任务。

核对基线：当前本地 `feat/patch-regression-replay`，HEAD `fb4af49`。本地分支能力不能直接当作 `main` 已交付能力。2026-10-14 查询的待合并 PR 为 #285（DEMO 文档）、#286（影响分析接线）、#287（补丁回归）；按堆叠关系处理依赖，不能重复开发。每项开工前重查 main、Issue、PR 和已有脚本。

已存在的需求容器：#267 pilot Epic；#268 样本合同；#269 checkout 校验；#270 双版本与 3+3 回放；#271 bundle/报告；#272 CLI/文档；#273 真实运行验收；#246 前端结果展示；#185/#188–197 CWE 扩展；#181 构建依赖；#182 compdb 预算；#165 全量验收。Issue 仍 open 不代表其中所有代码都未实现，需核对评论、合并记录与验收证据。

本文件是需求草稿，不代替实施 Packet。引用现有 Issue 时增加子任务或关联新 Issue，避免复制整个父需求。E/C/V 是本文件编号，不是 GitHub 号码或 IP 号码。

## 2. 建议先分配的工程任务

| 编号 | 可作为 Issue 的标题 | 优先级 | 建议负责人 | 前置 |
|---|---|---|---|---|
| E01 | [Competition] 增加真实验证前的只读环境预检查 | P0 | wenxinliu52 | 复用 #269/#272 |
| E02 | [Competition] 增加 evidence bundle 离线完整性校验命令 | P0 | wenxinliu52 | 复用 #271 |
| E03 | [Competition] 采集验证进程与 Sidecar 的性能数据 | P0 | wenxinliu52 | 冻结性能字段 |
| E04 | [Competition] 从现有 evidence bundle 生成扫描覆盖摘要 | P0 | wenxinliu52 | 冻结分母说明 |
| E05 | [Competition] 增加多案例串行运行与逐案例结果清单 | P1 | wenxinliu52 | E01；案例由你提供 |
| E06 | [Competition] 汇总多次验证结果并保留证据等级和失败原因 | P0 | wenxinliu52 | E02、E03、E04 |
| E07 | [Competition] 导出可复现运行的非敏感环境清单 | P0 | wenxinliu52 | E01；明确字段白名单 |
| E08 | [Competition] 验证干净部署的启动与健康检查流程 | P0 | wenxinliu52 | 固定发布 commit/image |
| E09 | [Competition] 更新参赛文档的实现状态与验证证据引用 | P0 | wenxinliu52 | #285；你审核事实 |
| E10 | [Competition] 按白名单生成参赛提交包与缺件清单 | P0 | wenxinliu52 | E02、E07、E09 |
| E11 | [Competition] 按冻结脚本完成 DEMO 彩排和演示视频 | P0 | wenxinliu52 | E08、E09；你审核讲解 |
| E12 | [Frontend] 任务详情支持下载 Markdown 与 JSON 报告 | P1 | wenxinliu52 | 复用现有报告 API |
| E13 | [Deployment] 补齐参赛环境示例与配置一致性检查 | P0 | wenxinliu52 | 维护者确认现有建议值 |

推荐首批 **E02、E12、E13、E09**：范围清楚、无需判漏洞、可独立产生交付物。E03/E04 紧接着推进。E01/E08 要求 Docker 与部署经验；E05 涉及成本和中断管理，放到第二批。E10/E11 在证据与脚本稳定后收尾。

### E01：真实验证前的只读环境预检查

**问题**：当前 CLI 直接组织真实运行；缺少独立、不调用模型的预检查结果，容易在昂贵运行开始后才暴露环境问题。

**最小范围**：新增独立 preflight 脚本或子命令。复用 `load_openharmony_case`、现有 checkout/compdb 校验和 analyzer `health()`，检查配置是否存在、输入和输出路径、Sidecar 连接与所需能力；不另写一套校验规则。

**验收**：

- AC-01：缺配置、错误 manifest、checkout 漂移、Sidecar 不可用各输出具名检查项和可操作提示。
- AC-02：输出 JSON + 简短文本；密钥只记录是否配置，URL 不包含认证信息；配置检查不声称凭证已通过供应商认证。
- AC-03：预检查不调用 LLM、不运行目标代码、不改变 checkout；结果只说明运行前提，不代表漏洞验收通过。

**入口/范围**：`scripts/run_openharmony_validation.py`、`lima/openharmony_validation.py`、`lima/cxx_memory.py`。建议以新增脚本及测试为主。关联 #269/#272。

### E02：evidence bundle 离线完整性校验命令

**问题**：bundle 已生成 `SHA256SUMS.json`，但交付接收方缺少统一的离线验证入口。

**最小范围**：读取已有 bundle，逐文件校验摘要、缺失文件和未列入清单的额外文件，输出验证结果与错误路径；只读，不执行 PoC。

**验收**：

- AC-01：原始合法包完整性通过；修改任意文件、删除列入文件、加入未列入文件均有明确失败结果。摘要清单自身按现有格式单独处理。
- AC-02：拒绝绝对路径、`..`、符号链接或目录联接逃逸；异常 JSON/摘要、重复路径不会静默通过。
- AC-03：区分 `integrity_valid` 和包内 `validation_status`：失败实验的包可以完整，完整包不代表漏洞成立；旧包兼容范围明确。

**入口/范围**：`lima/openharmony_validation.py:write_validation_bundle`；建议新建只读校验脚本，复用 writer 格式。关联 #271。需明确：SHA-256 清单提供内部一致性检查，不提供发布者身份认证或数字签名。

### E03：性能采集

**问题**：现有记录有总耗时与调用预算，但缺可复用的宿主/Sidecar 峰值内存采集，无法交付完整性能数据。

**最小范围**：包装现有运行命令，采集墙钟时间、验证进程树峰值内存、Sidecar 内存和 CPU 采样，保存独立 `performance.json`；不改已封存 bundle。

**验收**：

- AC-01：每个数值携带单位、采集来源和采样方式；记录宿主与容器资源限额、案例与运行标识。
- AC-02：权限或平台不支持时输出 `null` 和原因；容器生命周期峰值与本次采样峰值分别命名，不能混用；不重建用户现有容器来清零峰值。
- AC-03：成功、失败、超时均尽量保留已采集记录；用无网络测试进程验证采集，不在普通 CI 调用真实模型。

**入口/范围**：现有 CLI 外围新增包装脚本与测试。关联 #273/#165。性能 wrapper 的启动、停止与中断语义需单独测试，不自动重试真实模型请求。

### E04：扫描覆盖摘要

**问题**：bundle 已有 `file_coverage`、`byte_coverage`、`unreviewed_units` 等字段，但不能直接用快照读取覆盖率代表漏洞审阅覆盖率。

**最小范围**：读取现有 summary/platform/AEP，生成 `coverage-summary.json` 和表格；分别展示快照文件/字节覆盖、TU 提取可用情况、未审阅 TU 与 coverage gap。

**验收**：

- AC-01：字段来自原始证据，并标出来源；没有总 TU 分母时只给数量和“比例不可计算”，不推算 100%。
- AC-02：有未审阅单元、截断或提取失败时显式显示；零 finding 不写“全部代码安全”。
- AC-03：用完整、部分、空结果、旧格式和损坏输入测试；不修改检测器或裁决状态。

**入口/范围**：`lima/openharmony_validation.py:_platform_document`、`lima/agent_orchestrator.py:PlatformReviewOutcome`；新增投影脚本。分母与术语由你先确认。关联 #273/#165。

### E05：多案例串行运行

**问题**：现有 CLI 一次处理一个 case；多案例运行与结果登记依赖手工执行。

**最小范围**：新增 batch wrapper，按案例列表调用现有 CLI。第一版固定串行，为每案例分配独立输出目录，记录退出码、运行时间、输出位置和剩余未执行案例。

**验收**：

- AC-01：一个案例失败后按配置停止或继续，保留结果；`passed/failed/inconclusive/not-run` 不混淆。
- AC-02：启动前展示案例数和预计调用上限；配置批次案例数/总墙钟上限，不宣称能精确限制底层实际费用；不修改单案例判据或不可变预算。
- AC-03：已完成案例不重跑；不完整目录、已有路径和中断案例显式处理，禁止自动重复可能已计费的模型调用。

**入口/范围**：新增脚本，复用现有 CLI。案例列表由你提供，测试用假子进程。关联 #272/#273。此任务不包含全量 OpenHarmony 的选样或构建方案。

### E06：多次结果汇总

**问题**：真实运行证据分散，难以快速查看哪一轮失败、为何失败以及耗费多少资源。

**最小范围**：从指定 bundle 与外围性能/覆盖摘要生成 CSV + Markdown。每行标记案例、运行、双 commit、最终状态、各证据等级数量、回放结果、失败原因、耗时与证据路径。

**验收**：

- AC-01：保留每一次历史运行；按运行标识与证据摘要去重，不能因 case_id 相同覆盖旧轮次。
- AC-02：不同模型、预算、commit、Fake/真实模式明确区分；输出计数，不在缺 ground truth 时计算 precision/recall。
- AC-03：异常包列入错误清单；不能把语义 finding 升级为 runtime-confirmed，不能把缺失回放记为通过。

**入口/范围**：新建只读汇总脚本，依赖 E02–E04。关联 #273。证据等级词汇复用现有合同。

### E07：非敏感环境清单

**问题**：复现实验依赖的版本与环境分散在文档、容器和本机中。

**最小范围**：导出源码 commit/dirty 状态、Python/工具版本、已使用容器的 image digest、操作系统、CPU/内存、模型名、允许公开的预算配置与案例摘要。

**验收**：

- AC-01：环境字段使用明确白名单；不转储 `.env`、完整环境变量、认证头或完整命令行；供应商 URL 去除认证参数。
- AC-02：拿不到镜像 digest 或工具版本时保留 unknown；模型名记录为供应商声明，不能保证远程后端版本固定。
- AC-03：输出绑定运行 ID 与采集时间；dirty 工作区明确标记，不能声称只靠 commit 可还原。

**入口/范围**：新增环境采集脚本，复用现有部署信息。依赖 E01。关联 #273。

### E08：干净部署 smoke test

**问题**：README 和已有测试不等于参赛者能在干净环境按手册成功启动。

**最小范围**：在专用 Compose project 和测试数据目录中，验证镜像启动、服务健康、Sidecar 能力及退出清理，形成操作记录。不更改沙箱、不构建真实漏洞靶场。

**验收**：

- AC-01：固定 commit/image，在干净测试环境按手册跑通；端口冲突和依赖缺失有诊断。
- AC-02：不使用用户现有数据库、卷或管理员账号；清理只针对本任务创建的资源；不调用真实模型。
- AC-03：记录环境、命令、日志、退出码；本地通过与 CI 通过分别标记，未测试平台不宣称支持。

**入口/范围**：`docker-compose.yml`、`scripts/lima.ps1`、`deploy/competition/README.md`；建议新增 smoke-test wrapper，配置变更另评审。关联 #273。

### E09：参赛文档状态与证据更新

**问题**：文档包含历史基线与后续补充，既有能力、待合并能力、未验证项容易混读。

**最小范围**：更新技术说明书、使用说明书、性能数据和验证台账中的状态导航；统一引用当前 release/commit、实际 artifact 和已知限制。DEMO 脚本先复用 #285。

**验收**：

- AC-01：每个“已验证”结论附日期、代码基线、命令和证据位置；待合并与已合入 main 明确区分。
- AC-02：保留历史记录；消除“正文未验证、附录已执行”却没有解释的冲突；将 Fake 与真实结果分开。
- AC-03：你审核 CWE、漏洞危害、结果解读及修复结论；wenxinliu52 不自行改写结论为成功。

**入口/范围**：`docs/competition/`、`docs/COMPETITION_VALIDATION.md`、`deploy/competition/README.md`。关联 #272/#273/#285。属编辑任务，不要求为文字改动新增镜像实现的测试。

### E10：参赛提交包与缺件检查

**问题**：目前没有可核对的最终提交清单与按官方命名生成的完整交付包。

**最小范围**：从显式 allowlist 打包源码、依赖/运行说明、你批准的正式漏洞报告、PoC/补丁/证据、技术与使用文档 PDF、性能说明、视频、作品声明和程序交付形式；交付项缺失时生成清单。

**验收**：

- AC-01：按官方模板与命名检查，文档 PDF 不超过 10 MB；报名字段通过配置提供，不写死进仓库。
- AC-02：拒绝含密钥、`.env`、本地数据库、缓存、未批准报告、`.git` 和完整导入仓库的打包项；固定清单，不能递归打包整个 cwd。
- AC-03：输出最终 SHA-256 清单，关联 E02 离线验包；从解压目录核对运行说明，不自动发布或提交比赛平台。

**入口/范围**：新增打包脚本、交付清单模板；依赖 E02/E07/E09。你确认官方模板、程序形式和允许公开内容。已有文件引用，不重新生成漏洞结论。

### E11：DEMO 彩排与视频

**问题**：已有 DEMO 脚本，缺成品视频以及面向参赛版本的可重复彩排记录。

**最小范围**：按冻结脚本录制环境检查、任务提交、进度、证据等级、真实 PoC 记录、修复对照、影响报告和导出操作；允许用已封存真实记录讲解长耗时步骤，并明确注明历史回放。

**验收**：

- AC-01：视频标明真实运行、历史记录回放与 Fake 演示；不把 Fake 当真实性能或漏洞成果。
- AC-02：画面无密钥、私人路径/信息或未经批准漏洞材料；正文/展示材料符合官方匿名要求。
- AC-03：你批准讲解中的漏洞与评分主张；视频、脚本、实际 release 功能一致；长时间现场任务提供已验证的展示方案。

**入口/范围**：`docs/competition/DEMO脚本.md`、视频文件及彩排记录。依赖 E08/E09，复用 #285。录制工具由实施者选，不包含新的检测代码。

### E12：任务报告 Markdown 与 JSON 下载

**问题**：后端已有认证的 `GET /v1/tasks/{id}/report`，前端已展示报告，但任务详情没有下载入口，API client 也没有对应文本读取方法。

**最小范围**：报告卡片增加两个下载动作。Markdown 复用后端同源报告端点；JSON 导出已加载的 report 对象，明确这是 API 脱敏/有界投影，不是完整 evidence bundle。不重新计算漏洞结论。

**验收**：

- AC-01：有报告时按当前访问权限下载，task_id 正确 URL 编码；文件名、UTF-8 与 MIME 正确；无报告时入口不可用。
- AC-02：403/404/网络错误可见；请求带现有认证，下载内容不包含 token；复用现有按 Content-Type 解析文本/JSON 的客户端，不另写认证流程。
- AC-03：测试当前平台报告、旧报告、空报告和下载失败；前端 `typecheck`、相应用例及构建通过；下载内容保持后端状态，不把文本 PoC 自动执行。

**入口/范围**：`frontend/src/shared/api/client.ts`、`frontend/src/features/tasks/TaskDetailPage.tsx`、相应前端测试。关联 #246 的后续小任务。基础页面不重做，后端报告模型不改。

### E13：参赛环境示例与配置一致性

**问题**：`deploy/competition/README.md` 引用了 `.env.competition.example`，但实查目录（包括隐藏项）只有 README，参赛 profile 缺少可直接使用的示例。

**最小范围**：补齐无真实凭证的示例，整理 README 中已声明的快照/AST/Sidecar/Agent 限额与模型参数。先逐项核对现有配置解析器，再由维护者确认建议值。

**验收**：

- AC-01：README 引用文件存在；变量名称与真实解析器一致；每项说明单位、用途、默认值与参赛建议值，未知值不自行发明。
- AC-02：凭证留空；不会因复制模板而默认打开受信构建执行或调用模型；需要显式启用的能力有对应注释。
- AC-03：静态检查覆盖文档引用、配置名称和敏感值；不改变全局默认配置、Compose 安全权限或预算规则；与现有 CLI 实际使用的凭证变量一致。

**入口/范围**：`deploy/competition/.env.competition.example`（新增）、`deploy/competition/README.md`、小范围配置文档一致性测试。关联 #272/#273，作为缺件修复而非重新设计部署架构。

## 3. 你先定义判据，再交给 wenxinliu52 的任务

### C01：[Evaluation] 增加语义检测补充指标并标注工作台模式

- **你提供**：哪些状态算正向语义 finding、正负样本分母、重复 finding 的计数方式、无分母行为及手算期望表。
- **wenxinliu52 实现**：在 `scripts/run_platform_evaluation.py` 中增加补充统计；保留原 runtime 指标；LLM 模式与 workbench 模式独立标注。
- **验收**：冻结例表逐项吻合；空分母为 null+诊断；真实 provider + scripted workbench 不标为真实 ASan；历史 Fake 指标不被悄悄改变。
- **优先级/依赖**：P0；V03。关联 #273/#165。无需贡献者判断源码漏洞。

### C02：[Report] 生成你确认过的分支/版本影响矩阵

- **你提供**：待核对分支/版本、固定 SHA、构建开关、受影响/已修复/未知判据与最终审核结论。
- **wenxinliu52 实现**：收集固定 Git 元数据和逐版本测试记录，生成矩阵，区分 historical contains 与 validated affected；不自动按 `branch contains` 推导受影响。
- **验收**：每行有 SHA、来源、构建配置和结论状态；缺复现证据显示未知；修复 cherry-pick 与原修复 SHA 不同的案例按你给的规则处理。
- **优先级/依赖**：P0；V05；#286 合入或确定整合基线。复用影响挖掘，不重写。

### C03：[Evaluation] 增加真实工作台的已审核样本运行入口

- **你提供**：合法正负样本、编译上下文、允许执行的源文件、命中/不命中/环境失败判据和重复次数。
- **wenxinliu52 实现**：增加独立真实评测入口，注入现有 analyzer/ReproWorkbench，记录原始观察并汇总你冻结的判据；保留离线测试入口。
- **验收**：真实执行与 scripted 执行分别标记；编译失败/超时不记为安全负例；普通 CI 无模型密钥或付费调用；原始证据可定位。
- **优先级/依赖**：P0；V02/V03；E01/E07。此项需要较强工程经验，你负责执行边界评审。

## 4. 应由你负责的漏洞专业任务

| 编号与建议 Issue 标题 | 必须形成的输入或交付物 | 工程协作接口 | 已有需求关联 |
|---|---|---|---|
| V01 [Detection] 确认首个符合赛题范围的真实 OpenHarmony 案例 | OH 来源、固定 commit、实际构建配置、触发面与安全危害；已公开 CVE 与新发现分开 | 交 E01/E05/C03 执行清单 | #268/#267 |
| V02 [Detection] 打通专家假设到真实 PoC 的自动转换 | 编译/依赖策略、触发输入、目标绑定、修正反馈；冻结 3+3 验收；保留失败证据 | C03 只负责运行和存证 | #270/#273 |
| V03 [Detection] 非安全问题过滤与误报评测判据 | 整数运算异常如何证明安全危害；危险/安全近邻/不确定例；状态与指标定义 | C01 实现统计；E06 汇总 | #185/#273 |
| V04 [Detection] 校验 CWE/CVE 分类与运行时证据一致性 | ASan 类型、读写方向、目标归因、CWE 边界及 CVE 来源，处理短 marker 误匹配 | 你确认后再实施接线，不作为初学者独立任务 | #188/#190 |
| V05 [Detection] 验证受支持分支、版本与模块的影响和严重度 | 实际可达性、配置差异、修复/backport、风险依据；不能只用 blame/contains | C02 制作矩阵 | #286/#267 |
| V06 [Remediation] 确认补丁安全性与功能保持 | 最小补丁、不变量、旧 PoC 回归、正常功能对照；PoC 不触发不等于所有功能正确 | E06 展示记录；复用 #287 | #287/#273 |
| V07 [Detection] 冻结大型 OH 扫描范围与构建方案 | 目标组件/TU、依赖来源、预算分层、失败/未审阅解释；限制漏报主张 | E03/E04/E05 采集与运行 | #181/#182/#165 |
| V08 [Detection] 选择一个可确认的新漏洞类型并完成真实正负对照 | 优先选择触发和确认可实施的类型；UBSan/LSan/行为哨兵的判据与安全设计 | 样本冻结后贡献者补数据与统计 | #185/#189/#191–197 |
| V09 [Disclosure] 整理正式漏洞报告并按赛题要求提交评审 | 安全价值、复现边界、报告内容、公开范围、社区反馈/受理状态；授权后提交 | E09/E10/E11 仅用你批准的版本 | #267/#273 |

**不能直接交给低专业知识贡献者的工作**：根据 LLM 猜测确定漏洞、修改运行时命中条件、设计行为哨兵/改变 Landlock、评估补丁是否消除根因、把包含提交的标签判成受影响版本、把无 finding 判成零漏报，以及设计跨仓依赖桩是否保留真实语义。

## 5. 提 Issue 与执行建议

首批已提六个小 Issue：E02、E12、E13、E09、E03、E04，均已实际设置 assignee `wenxinliu52` 并回读核对。其余标题与验收可在后续选择后按 `.github/ISSUE_TEMPLATE/feature.yml` 提交，避免一次激活所有候选。

你可以同时推进 V01/V02/V03/V05，并为 C01–C03提供冻结输入。E 类每个 Issue 限定一个结果、一个主要实现范围；优先新增外围脚本，减少多人同时改 `openharmony_validation.py`、`agent_orchestrator.py` 和 `TaskDetailPage.tsx`。

建议依赖顺序：

1. E02/E03/E04/E07：完整性、性能、覆盖和环境记录可并行开发，真实运行由你发起。
2. V01/V02/V03 → C01/C03；V05 → C02：你先冻结专业规则，贡献者负责工程实现。
3. E01/E08 → E05 → E06：预检查与部署可用后再跑多案例，最后汇总结果。
4. 已审核证据 + 已确定 release → E09 → E10/E11：更新文档、生成包、录制视频。

共享交付约束：日志不含密钥；不改已封存证据包；真实模型运行由你发起并控制预算；单元测试不调用付费服务；任务完成需说明本地/CI/真实运行分别验证了什么。不要把“脚本完成”当作“赛题完成”。

发布前还需核对 #285/#286/#287 的合并和 post-merge 证据。首次真实运行失败的修复应按具体问题切小 Issue，不重新开一个“完成所有 OpenHarmony 检测”的大任务。

## 6. 证据入口

- 官方赛题附件：<https://cpipc.acge.org.cn/sysFile/downFile.do?fileId=404b13ab51f64f52adb72bbcef926cfc>
- 官方邀请函与交付要求：<https://cpipc.acge.org.cn/cw/contestNews/detail/2c90800c8093eef401809d33b36f0652/2c9080199ed8b78d019ed96ceea21560?page=1>
- 项目验证记录：`docs/COMPETITION_VALIDATION.md`。
- 已封存 pilot：`output/openharmony/pilot/summary.json`（failed）。
- 蓝牙沙箱旁证：`.zcode/reports/bt-avrcp-cwe476-verification/VERIFICATION.md`；支持分支与真实设备/模拟器验证仍需按正式报告边界核对。
- 已有实现：`scripts/run_openharmony_validation.py`、`lima/openharmony_validation.py`、`lima/agent_repro_tools.py`、`lima/impact_mining.py`、`lima/agent_report.py`、`frontend/src/features/tasks/TaskDetailPage.tsx`。
- 工程协作约束：`docs/GITHUB_COLLABORATION.md`。
