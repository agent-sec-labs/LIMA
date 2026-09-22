# LIMA Runtime Attestation Baseline（脱敏基线，2026-09-20）

- 文档类型：运行证明基线（阶段 D.0 / D.0.1 / D.0.2 结论的入库载体；详细过程证据在仓库外临时目录，不入库）
- 上位合同：主会话 Playbook §2.1（运行证明合同，D.0.1 勘正版）与 §2.2（raw/published custody 规则）
- 本文件不含 prompt、推理文本、凭据或敏感 headers；存储位置以相对描述记载

## 1. 运行配置所有权（核心结论）

当前 ZCode 调度器下，**运行配置所有权在主会话，子智能体继承主会话的模型与推理配置**。Agent 定义 frontmatter 的 `model` / `thoughtLevel` 仅为**目标配置或兼容性元数据**，不构成运行证明。

探针依据（2026-09-20，探针项目会话；分层证据表述）：三个无工具探针 frontmatter 分别声明 `glm-5.3-flash` 与 `thoughtLevel: low/max`。**probe-tl-max = rollout 级验证**（requested=GLM-5.3=response、output_config.effort=max、thinking enabled，与会话参照逐字段一致）；**probe-tl-low = Maintainer 历史观察**（曾观察到 GLM-5.3 / effort=max），正式状态 TELEMETRY-MISSING；**probe-flash = 应用日志与 PROBE-OK 旁证**（派发窗口出站 modelId=GLM-5.3、零 Flash 出站），正式状态 TELEMETRY-MISSING。三者的 request/response/effort 不构成均已正式验证的结论；正式状态以第 3 节表为准（probe-tl-max 为 rollout 级 CHILD-INHERITANCE-VERIFIED，probe-tl-low 与 probe-flash 均为 TELEMETRY-MISSING）。「thoughtLevel 差异不产生可区分请求字段」这一判断，由 tl-max 的 rollout 级正式证据与两项非正式旁证（tl-low 的 Maintainer 历史观察、flash 的应用日志与 PROBE-OK 返回）共同支撑；旁证不提升对应探针的正式状态。

## 2. 状态集（四态 + 一异常态）

| 状态 | 含义 |
|---|---|
| SESSION-RUNTIME-VERIFIED | 主会话 requested model 与 response modelId 一致，effort/thinking 已从调度器记录核验 |
| CHILD-INHERITANCE-VERIFIED | 子代理请求/响应模型与运行配置白名单字段和主会话运行配置一致 |
| TELEMETRY-MISSING | 该调用无 rollout/日志记录可核（未生成或已轮转） |
| RUNTIME-UNVERIFIED | 有记录但不足以判定，或未执行核验 |
| ROUTING-MISMATCH（异常态） | 子代理请求模型 ≠ 会话运行配置，或 requested ≠ response；ACTIVE 下产物无效须重跑 |

规则：**一个历史调用只能有一个正式 Attestation 状态**；VERIFIED 与 TELEMETRY-MISSING 不得并列。ACTIVE 下承担门禁作用的 Evidence Review 在 TELEMETRY-MISSING / RUNTIME-UNVERIFIED / ROUTING-MISMATCH 时均不能通过或释放门禁。调度器 rollout 存在轮转——**Attestation 必须在子代理结束后立即提取**。

## 3. 历史调用正式状态汇总（截至 2026-09-22 阶段 D 后续批次收口）

| 调用 | Agent | 正式状态 | 依据（提取时锚定） |
|---|---|---|---|
| B.1 N6a/N6b/N6c | lima-maintainer-briefing（三次派发） | **TELEMETRY-MISSING**（D.0.2.1 勘正，原记 RUNTIME-UNVERIFIED） | 无 rollout 记录存在（调度器未为该三调用生成 rollout）；输出经字节复制补存（哈希与 Maintainer 期望 3/3 一致） |
| 阶段 C custody 步 1 | lima-evidence-review | **CHILD-INHERITANCE-VERIFIED**（会话 SESSION-RUNTIME-VERIFIED） | D.0 Attestation 提取时实测：requested=GLM-5.3=response modelId、thinking enabled（25 条调用）；rollout 原件后经调度器轮转移除，哈希为提取时锚定值 |
| 阶段 C custody 步 2 | lima-maintainer-briefing | **CHILD-INHERITANCE-VERIFIED**（会话 SESSION-RUNTIME-VERIFIED） | 同上（2 条调用；requested=GLM-5.3=response、thinking enabled） |
| 探针 probe-tl-max | probe-tl-max | **CHILD-INHERITANCE-VERIFIED（rollout 级验证）** | 唯一保有 rollout：requested=GLM-5.3=response、output_config={effort:max}、thinking enabled，与会话参照逐字段一致（rollout SHA-256 134a953fbc2937fde6b8b592adf821e421d2c2651a75c88e202a8ef9f9699d90） |
| 探针 probe-tl-low | probe-tl-low | **TELEMETRY-MISSING** | 无 rollout（已轮转）。Maintainer 历史观察（不提升正式状态）：曾观察到 request/response=GLM-5.3、effort=max |
| 探针 probe-flash | probe-flash | **TELEMETRY-MISSING** | 无 rollout。应用日志旁证（不提升正式状态）：派发窗口出站请求 modelId=GLM-5.3（零 Flash 出站）；返回输出 PROBE-OK |
| 阶段 D 后续批次 N8 | lima-maintainer-briefing | **TELEMETRY-MISSING** | 该调用没有可用 rollout/model_io 记录；Agent 首行"运行模型：无法核验"仅为自报，不构成 Attestation 证明。行为旁证（只证明 N8 行为结果，不提升运行 Attestation 状态）：`D_commit_and_N8_record.md`，SHA-256 f5db280310af0fb54a6b58a11b8cc0629793279c986572467025a34c0717d568 |

## 4. raw / published custody 锚定（阶段 C 与 B.1）

| 产物 | raw SHA-256（字节复制源） | published 版本 | published SHA-256 | 说明 |
|---|---|---|---|---|
| B.1 N6a/N6b/N6c 输出 | 064944fa…cde35c / fcf7b076…1d72e3d1 / d917586a…673b3efc | B1_N6{a,b,c}_output.txt | 与 raw 相同（字节复制） | raw = published |
| ERR-ISSUE94-REPLAY | c35276dff7106f13eb7d54d74607ce7e52847b613ef5ee64c9c8a3f2d0544b83 | v1（被取代，保留）/ **v2（现行权威）** | v1=32e45b20f9fa8d28b379b41976f22660025bba2b5e4d184d4f2ff908ccbddb68；**v2=2458b640d84116d5798e43c5da1a994572e4cbc1b62d217b6de304c8260738db** | v1 系人工转录含 3 处 cfcef73 笔误；v2 = raw 字节 + 元数据头（机械拼接，§2.2 规则） |
| BRIEF-ISSUE94-REPLAY | df85922694b481c32e50542b48e4306e3268315378b942859d76f8ea0b492c7d | v1（现行，无需 v2） | beac17f1bd736214f2d46a12c10c33bc323975b3cc603e9950ed95f9f8b1147b | v1 与 raw 仅排版归一差异（弯引号→直引号），无内容级偏差 |

## 5. 工具

- 抽取脚本：`scripts/runtime_attestation_extract.py`（D.0.2.1 修正版：显式 --session-id 绑定；三探针 Agent ID 须位于该会话 agents 目录并经 metadata.json 探针 profile 核验；会话全部 main_turn 须 requested==response 且运行配置一致（不一致 → AMBIGUOUS）；子代理仅与已通过 SESSION-RUNTIME-VERIFIED 的会话参照比较四要素；多候选/缺记录/字段不全独立失败；TELEMETRY-MISSING 与 ROUTING-MISMATCH 独立退出码）。

## 6. 维护

- 本基线随阶段 D.0.x 勘正更新（更新即产生新哈希，旧值在勘正说明中保留）；ACTIVE 启用前按 Playbook §12 阶段 E 门槛复验（SESSION-RUNTIME-VERIFIED + CHILD-INHERITANCE-VERIFIED）。
