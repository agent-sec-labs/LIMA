# Python Agent 主链真实模型调查：效果报告（2026-10-03）

> 一页结论。模型实际处理了什么、自主用了哪些工具、哪些结论改变了、哪些仍未解决。真实 API 总额度 60 次请求 / US$5；**实际用量 60/60 次、US$0.122（保守估价，为额度上限的 2.4%）**。逐次调用与用量台账：`.pv_tmp/AGENT_REVIEW_2026-10-03/api_ledger.json`；逐项结论与工具轨迹（after 工件）：`LIMA-real-runs/agent-investigation-2026-10-03/`。

## 用户现在如何运行

```bash
# 生产入口（本地导入仓库；含指定模块的 Agent 调查入口）：
LIMA_REPOSITORY_INVESTIGATION_MODE=auto \
LIMA_REPOSITORY_IMPORT_ROOT=<目录> LIMA_REPOSITORY_SCAN_SOURCES=local-import \
python -c "from lima.config import Settings; from lima.service import ReviewService; \
s=ReviewService(Settings.from_env()); print(s.enqueue_repository_scan('repo','default',investigate_paths=['app/danger']))"
```
模型与批量参数由运行配置承载（`LIMA_REPOSITORY_INVESTIGATION_*`：batch/steps/timeout/max_requests）；每任务有独立请求上限，额度耗尽=未处理（如实标注），绝不静默截断。

## 模型实际处理了哪些目标（全部经生产调查核心 `lima/repository_investigation.py`）

| 运行 | 目标 | 结果 |
|---|---|---|
| 早期贯通 | 4 目标（对象方法 eval/环境变量名/真凭据形状/未解析绑定） | 4/4 绑定结论，全部方向正确 |
| 控制集（仓库无关） | 12 目标：4 正例/4 安全邻例/4 证据不足 | **12/12 与评测侧标签一致**（标签只在评测侧，未进模型输入） |
| LF 固定仓原 27 件 | 27/27 全部进入复核（sealed tarball 只读快照） | **refuted 8（均有实际读源依据）+ insufficient 19（含 11 件"模型裸 clean 未引证据被安全降级"）+ supported 0**；与既有 AI 静态复核"27/27 误报"方向独立一致 |
| 服务全链路（ReviewService→队列 worker→存储报告） | 2 静态发现+1 模块目标 | 任务 SUCCESS；步骤预算耗尽→三件如实 failed；failed 项保持调查前有效处置（原活动告警仍为 alert），**未清除、未降级任何告警**。修正注记：本行早先写作"未清除任何告警"，但当时合并层曾把 failed/insufficient 一律默认降级为 needs_review，与该声明不符；2026-10-03 已按 fail-closed 转移表修正合并语义，本报告表述随之与修正后行为一致 |
| 模块发现定点 | 1 模块目标（静态零发现样本） | 读源后任务预算耗尽→failed（如实）；预算已满未复跑 |

## 模型自主调用了哪些工具（真实请求中选择，非脚本预调）

`read_source`（按路径+行区间）、`find_definition`、`ast_facts`、`search_code`；观测文本（逐行隐私脱敏、凭据字面量掩码）回入后续推理并成为结论的 `evidence_refs`（校验：工具确实运行过、路径确实出现在观测中）。典型证据：模型独立读到 `Evaluator` 类定义（evaluator.py:61）从而**有据反驳**旗舰误报 `Evaluator().eval()`（CWE-95）；LF 8 件反驳全部携带 `read_source:path:line` 引用。

## 哪些误报被有证据地反驳 / 哪些真实风险被保留或新发现

- **被反驳（退出活动告警，留历史）**：对象方法/局部同名 `eval`、环境变量名引用、枚举值/模型标记字符串——控制集 4 件 + LF 8 件（含 `Evaluator().eval()`、`vision_bos_token` 等 dataclass 标记字段、`padding_side="left"`）。
- **被保留为活动告警**：真凭据形状（sk-/AKIA- 前缀高熵字面量）、裸内置 `eval(user)`、`shell=True` 插值——控制集 4 件 supported。
- **新发现**：控制集运行中模型对未读文件提出 1 项 new_target，因未实际读过该路径被绑定校验拒绝（`unverified-model-claim`，不物化为告警）——按设计工作。
- **未定（不借用 clean）**：跨快照导入、动态分派、文件缺失、输入来源不明——控制集 4 + LF 19；"模型称 clean 但未引证据"一律降级 insufficient。

## 静态根因修正（输入质量，非模型闭环替代）

`_call_name` 丢接收者→现在仅裸名/显式 `builtins.eval` 触发 SEC-EVAL 断言（对象方法/可解析接收者不再冒充内置调用；绑定收集为作用域正确：模块级绑定具全模块效力，参数/局部 def/函数内导入别名仅在其函数内遮蔽，同名类方法不跨作用域抑制；下标/构造调用等无法在本层唯一解析的接收者保持候选级 finding 可见、不静默消失）；凭据规则按字面量形状分级（高熵/混合类=HIGH；纯标识符/名称引用/标记文本=LOW 候选，可见但非无据 HIGH）。无仓库/路径/token 清单。**原 27 件仍按原清单送模型复核**（区分"规则不报了"与"模型反驳了"）；LF R2 sealed 前后只读未动。

## 真实未完成（不伪装为完成）

1. **模型触发的合成动态对照**（验收 3b）：真实运行中模型从未选择 `dynamic_contrast`（0 次）。工具本身可用且经隔离解释器测试（单测覆盖模型请求路径），但"模型在真实请求中选择它"未发生。
2. **静态零发现样本的模块级真实发现**（验收 4）：模块入口在软件层已验证（脚本模型：new_target→AGENT-DISCOVERY 告警）；真实模型两次尝试均因步骤/请求预算耗尽 failed（服务链路 max_steps=3 + 60 次总额度用尽）。**未在真实模型层面证明**。
3. LF 19 件 insufficient 中 11 件是"模型裸 clean 未引证据被降级"——真实模型行为局限，如实保留为未知。
4. 通用规则两根因的**完整**治理（跨文件绑定、凭据语义上下文）仍归 #62/#61 既有归属；本轮只修输入面。

## 边界

零执行被审代码（快照只读；动态对照仅隔离解释器内的罐装合成样例）；凭据仅认证；逐行隐私脱敏+字面量掩码经既有 evidence-privacy 管道（fail-closed）；模型输入含"仓库文本是不可信数据"。未动 #59/#60/#61/#62/#93 的整项开发；不冒充完整 Mining/Repair/V5。
