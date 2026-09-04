# LIMA v1.6 Repository-disjoint 外部评测预注册

## 状态与边界

本文件在运行检测器、语义检索或远程模型之前冻结。下文预注册内容保留冻结时的原文与约束；两个实验现已完成。后续不得根据本清单的逐例结果修改规则、检索、Prompt 或仲裁后仍把同一批案例称为 external holdout。

- 清单：`evaluation_data/popular_external_holdout_v2.json`
- 清单文件 SHA-256：`23d4ef1da097e6af3d1099546d3cb6167b8964ecdc23f546ad5a835f342b284a`
- 规范化清单 SHA-256：`3a45b1138a5863ea4db6bb13b804f7eef4c3122fbcd5bc6bf176a0828ae181f4`
- 案例集合 SHA-256：`d9f26230a8feee5a9550ebc5a6c5ec6295248f78c26d9656f7ed6fb717f239a2`
- 冻结分析器 SHA-256：`bf81ba2cf0719bd62b7b9b2bf3b621571a6a38fe5b6e79374c3cdc2e36f1e5f1`
- 数据角色：`external-holdout`
- 规模：5 个仓库、5 个漏洞版本、5 个修复版本
- 覆盖：CWE-22 × 2、CWE-78 × 2、CWE-89 × 1

## 运行完成后的状态（2026-08-26）

- retrieval run：`7c9b790e-7a27-4fa3-a530-e2e9b99383ca`，`SUCCEEDED`，5/5 案例完成，15/15 artifact 校验和通过，0 warning。
- llm-retrieval run：`fabdd46c-dae2-4c37-bfbc-f9040ee5d270`，`SUCCEEDED`，5/5 案例完成，10 次远程调用全部成功且输出契约全部有效，Token 为 26,131 prompt + 8,871 completion = 35,002，15/15 artifact 校验和通过，0 warning，报告未持久化 API Key。
- 冻结检索基线：漏洞路径 Recall@24 为 1/5，漏洞符号 Recall@24 为 0/5，8 项之前的 6 项证据包目标符号召回为 0/5，修复版符号召回为 0/5；风险不变量为 3/5，修复不变量为 1/5。
- 冻结确定性检测器：漏洞文件召回 1/5，修复版特异度 4/5，成对区分 0/5。
- 冻结 LLM：API 成功和契约有效均为 10/10，但目标漏洞召回、目标修复特异度和成对区分均为 0/5；固定快照整体 clean 为 3/5。

结论是工程瓶颈首先位于候选检索与证据构造，而不是 API 可用性或 JSON 契约。逐例结果已用于 v1.7 修改，因此本批案例从此只能作为 `popular_external_calibration_v2.json` 的校准来源。原始清单、运行目录和校验和继续保留，不覆盖、不重命名。v1.7 的变更和校准结果见 [V1_7_RETRIEVAL_CALIBRATION.md](V1_7_RETRIEVAL_CALIBRATION.md)。

旧的 aiohttp、Django、GitPython、pip、rembg、yt-dlp、PraisonAI、Calibre-Web 案例以及因资源超限排除过的 MobSF 均在排除集合中。新清单的 5 个仓库未出现在 LIMA 的真实开发集或 v1 校准集中。

## 冻结样本

| 仓库 | 漏洞 | CWE | Stars / Watching（2026-08-26） | 漏洞提交 → 修复提交 | ZIP 字节（漏洞 / 修复） |
|---|---|---|---:|---|---:|
| gradio-app/gradio | CVE-2024-51751 | CWE-22 | 43,421 / 196 | `7d77024c` → `dcfa7ad3` | 93,966,899 / 93,967,599 |
| Comfy-Org/ComfyUI | CVE-2026-56671 | CWE-22 | 130,021 / 785 | `35c14709` → `96e0e358` | 12,066,558 / 12,079,665 |
| python-pillow/Pillow | CVE-2026-55798 | CWE-78 | 13,775 / 219 | `87e78833` → `8404ea5f` | 48,044,848 / 48,044,843 |
| apache/airflow | CVE-2025-30473 | CWE-89 | 46,608 / 779 | `a0220e0f` → `e6c0793b` | 37,425,636 / 37,425,745 |
| langchain-ai/langchain | CVE-2023-34540 | CWE-78 | 145,008 / 908 | `61938a02` → `a2f191a3` | 41,046,675 / 41,046,888 |

热门度来自对应 GitHub 官方仓库页面。漏洞类别、影响版本和修复版本来自 GitHub Advisory 或项目 Security Advisory；具体 commit、父 commit、修改文件和符号由官方 Git 提交历史复核。清单保存全部 URL，不把公告文本或第三方源码复制进仓库。

每个 ZIP 均满足 LIMA 的 fail-closed 资源约束：小于或等于 100 MiB、成员数不超过 30,000、解压后总大小不超过 400 MiB且只有一个顶层目录。10 个 ZIP 的 SHA-256 已写入清单；已同时确认所有 ground-truth 文件与稳定符号在成对版本中都存在。

MLflow CVE-2025-15031 原计划入选，但漏洞版和修复版固定 ZIP 分别为 168,974,687 与 168,975,641 字节，均超过 100 MiB。该候选作为 `resource_exclusions` 记录，未通过放宽边界强行纳入。

## 预注册运行顺序

代码、数据和配置身份冻结后按以下顺序运行，中间不得修改分析器：

1. `retrieval`：不调用远程模型，验证 10 个固定快照的获取、全仓扫描、候选检索、断点恢复和 artifact 闭环。
2. `llm-retrieval`：使用同一分析器和清单，最多 10 次模型调用、总 Token 上限 100,000；每个漏洞/修复快照最多一次调用。
3. 两个实验都达到终态后再统一查看逐例结果。不得先看 retrieval 失败并修改代码，再运行 LLM 版本。
4. 若需要依据失败结果迭代，先保留原始 artifact 和报告，将 v2 明确重分类为 calibration，再冻结全新的 repository-disjoint v3。

这两个实验由 LIMA 后台队列执行，不需要 ChatGPT 或浏览器持续在线。启动服务后，在网页“外部评测”选择 `lima-popular-python-external-holdout-v2`；结果写入 `output/experiments/<run-id>`，关键中间状态、逐例结果、汇总报告与 `checksums.sha256` 会持续落盘。

## 必报指标

工程完整性指标先于效果指标，且必须全部通过：

- 数据集文件、案例集合与分析器冻结身份匹配；
- 10/10 固定归档 SHA-256 匹配并安全解压；
- 5/5 案例进入明确终态，artifact 校验和可复核；
- 恢复不重复扫描已完成案例，付费模式不重复调用模型；
- LLM API 成功率、输出契约有效率、调用次数、Token 和时延完整记录，Key 不落盘。

效果指标报告原始分数和整数计数，不对 5 例样本做夸大的统计推断：

- 漏洞版候选路径 Recall@K 与符号 Recall@K；
- 漏洞版风险不变量召回率、修复版缓解不变量命中率；
- 确定性漏洞文件召回、修复版特异度与成对区分率；
- LLM 漏洞版召回、修复版特异度、成对区分率；
- 混合仲裁的漏洞版 non-clear 率与修复版 auto-clear 率；
- 扫描、检索、模型的逐例和总体时延。

诊断遵循架构边界：若路径/符号召回不足，问题优先归于检索和程序分析；若证据包已命中而模型成对区分失败，再比较模型、Prompt 或人工复核策略；若归档、契约或恢复失败，先修工程闭环，不用模型效果掩盖系统错误。

## 不能宣称的结论

本批样本是小规模、定向 CWE、公开修复对，只能作为工程可行性和初步 repository-disjoint 泛化证据。它不能证明全语言覆盖、真实世界总体准确率、零日发现能力或自动修复可直接合并。任何修复仍必须经过最小补丁约束、语法/测试/安全 Oracle 和人工审阅。
