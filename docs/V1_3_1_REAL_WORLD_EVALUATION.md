# LIMA v1.3.1 真实项目评测与消融

## 结论

v1.3.1 在 3 个固定公开漏洞/修复对上完成了仓库级 label-blind 检索、跨函数证据组装和真实 DeepSeek 判定。最终一次运行的漏洞召回率、修复版特异度、严格成对区分率、API 成功率和输出契约有效率均为 100%。

这个结果只证明当前工程链路能区分这 3 个已研究案例，不代表通用漏洞检测准确率。三个根因规则是在早期真实失败上形成的，尚未通过独立外部 holdout。

## 固定数据集

数据清单：`evaluation_data/real_world_security_cases.json`

数据指纹：`064486f0a7fba119f2f1c2a52f856462e7299bd82e191ea97501acd8b1109abb`

| 项目 | 漏洞 | CWE | 漏洞提交 | 修复提交 |
|---|---|---|---|---|
| aiohttp | CVE-2024-23334 | CWE-22 | `33ccdfb0...` | `1c335944...` |
| Django | CVE-2020-7471 | CWE-89 | `6b178a3e...` | `eb31d845...` |
| GitPython | CVE-2026-42215 | CWE-78 | `da545232...` | `0f68db07...` |

每个提交使用完整 SHA 固定，GitHub codeload 归档另有 SHA-256 校验。快照获取拒绝路径穿越、符号链接和超限压缩包。

## 评测协议

1. 检索器扫描完整的受限仓库，不接收 CVE、CWE、修复文件或目标符号标签。
2. 排名器在 path、command、SQL 三类信号之间保留平衡候选，并降低测试目录优先级。
3. 确定性不变量提取器标注风险或缓解证据，但不直接把假设当作漏洞结论。
4. 最小证据包只保留不变量锚点，以及父类模板渲染、验证调用点、规范化和执行点。
5. LLM 只能返回上下文中真实存在的 `path + symbol`；格式、CWE 或身份不一致均严格判错。
6. 漏洞提交应判为对应 CWE，配对修复提交应判为安全，二者同时正确才计一次 paired success。

真实 Provider 为 `deepseek`，模型为 `deepseek-v4-flash`。评测不记录 API key；异常只保留脱敏错误、`finish_reason`、Token 和时延。

## 消融结果

| 版本 | 上下文/推理策略 | 漏洞召回 | 修复版特异度 | 成对区分 | 总 Token | LLM 平均时延 |
|---|---|---:|---:|---:|---:|---:|
| v1.2 | 已知修复文件 + 默认思考 | 33.33% | 66.67% | 33.33% | 50,794 | 20,951 ms |
| v1.3 | 全仓语义候选 + 默认思考 | 0% | 100% | 0% | 54,312 | 40,629 ms |
| v1.3.1-a | 宽候选 + 关闭思考 | 0% | 100% | 0% | 28,796 | 2,151 ms |
| v1.3.1-b | 最小不变量证据包 | 33.33% | 100% | 33.33% | 6,678 | 2,226 ms |
| v1.3.1-final | 跨函数/父类数据流证据包 | 100% | 100% | 100% | 12,688 | 1,778 ms |

最终版本相对 v1.3 宽候选思考模式减少 76.6% Token，平均 LLM 时延减少 95.6%。v1.3.1-b 虽然成本最低，但只识别 aiohttp；加入 Django 父类 SQL 模板渲染链和 GitPython kwargs 检查到转换的顺序证据后，另外两例才正确。这个消融说明收益来自可验证上下文，而不是单纯增加 Prompt 长度。

## 最终逐例结果

| 案例 | 漏洞版根因定位 | 修复版缓解定位 | 成对正确 |
|---|---|---|---:|
| aiohttp | `StaticResource._handle` 在 follow-symlinks 分支缺少目录包含检查 | 两个分支均在文件使用前进行规范化/包含检查 | 是 |
| Django | `StringAgg.__init__` 把 delimiter 放入 `**extra`，`Func.as_sql` 通过 `template % data` 拼入 SQL | delimiter 变为 `Value` 表达式并进入数据库参数通道 | 是 |
| GitPython | guard 检查原始 kwargs 名称，执行前才把下划线 dash-normalize | guard 与执行端使用同一 canonical form | 是 |

最终运行还得到：

- 漏洞路径 Recall@K：100%；
- 漏洞符号 Recall@K：100%；
- 修复符号 Recall@K：100%；
- 漏洞版 risk 不变量召回：100%；
- 修复版 mitigation 不变量命中：100%；
- 平均完整检索候选数：11.5；
- 平均检索耗时：958 ms；
- P95 LLM 时延：2,289 ms；
- 6 次 LLM 调用总 Token：12,688。

## 可复现命令

```powershell
Set-Location D:\BaseAIProject\LIMA

# 单次 Provider/JSON 契约探针。
powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 llm-probe

# 固定快照、确定性基线、检索和隔离 Oracle。
powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 real-eval

# 3 个漏洞版本 + 3 个修复版本的真实 LLM 成对评测。
powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 llm-eval `
  -Output output\v1.3.1-reproduction

# 项目回归。
python -m pytest -q
powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 test
```

最终原始 JSON：`output/v1.3.1-dataflow-llm-eval/real-world-llm-retrieval-ab.json`

## 有效性边界

- 样本只有 3 个，且每个 CWE 只有 1 个案例，不能计算稳定置信区间或代表总体分布。
- 根因不变量受这些案例启发，最终结果属于开发集表现；下一阶段必须冻结规则后再测试新的 repository-disjoint holdout。
- 传统 AST/数据流扫描器在这三个已知文件上的漏洞召回仍为 0%；最终 100% 来自语义检索 + 不变量 + LLM 链路，报告保留了这一失败基线。
- 自动真实项目 Oracle 当前覆盖 1/3。aiohttp 完整源码构建测试和 Django PostgreSQL 测试矩阵尚未在隔离容器自动执行。
- 数据集策略要求三个真实框架级案例 `abstain`，因此没有把 LLM 分类直接变成补丁。任何自动修复仍需经过确定性安全 Oracle、仓库测试和人工审批。
- 当前表格是每个配置的一次真实运行。模型服务可能有非确定性，后续应增加重复运行、失败重试统计和成本分布。

