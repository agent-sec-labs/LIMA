# 离线 CVE 索引（evaluation_data/cve_index/）

本目录是 LIMA 报告智能体（`lima/agent_report.py`）使用的**本地离线 CVE 索引**。
本任务（平台计划 Task 6）**不下载、不抓取任何数据**：生产用索引由运维离线
准备（见下文"数据获取"），报告智能体只读取本地文件，全程无网络。

## 目录内容

- `README.md`：本说明。
- `cve_index.schema.json`：索引条目的 JSON Schema（draft-07 形式，供人读与
  外部工具校验；`load_cve_index` 内置等价的严格校验，不依赖 jsonschema 库）。
- `sample_index.json`：**仅 2 条样例条目，summary 中均带 `SAMPLE ONLY` 标注，
  供单元测试与格式演示使用，不是真实通告**。生产部署请替换为真实索引文件
  （或删除本文件——装载器只读 `*.json` 且跳过 `*.schema.json`）。

## 条目格式（固化于 `cve_index.schema.json` 与 `CVE_ENTRY_FIELDS`）

每个索引文件是一个 JSON 数组，元素为恰好包含以下六个字段的对象
（缺字段、多字段、类型错误、坏 CVE id 均在装载时抛 `ValueError`）：

```json
{
  "cve_id": "CVE-2024-25062",
  "component": "third_party/libexpat",
  "affected_paths": ["third_party/libexpat/expat/lib/*.c"],
  "introduced_commit": "",
  "fixed_commit": "a6b52f4b1908266c74f99bee845b5b0a038d4f30",
  "summary": "libexpat ... entity use-after-free (CWE-416)."
}
```

- `cve_id`：`CVE-YYYY-NNNN+`（4 位年份、至少 4 位序号）。
- `component`：非空组件路径；匹配时与发现组件做**互为前缀**比较。
- `affected_paths`：非空的 glob 列表；用 `fnmatch.fnmatchcase` 对发现的
  规范化仓库相对路径做**大小写精确**匹配（跨平台确定性）。
- `introduced_commit` / `fixed_commit`：引入/修复提交哈希；未知时留空串
  （空串表示"该通告时间线未知"，提交窗键无法据此排除该条目）。
- `summary`：非空的一句话描述。

## 三键匹配语义（`match_cve`）

发现的 `(component, path, 提交窗)` 与索引条目必须同时满足：

1. **组件键**：条目 component 与发现 component 互为非空前缀；
2. **路径键**：发现 path 命中 `affected_paths` 中任一 glob（`fnmatchcase`）；
3. **提交键**：调用方提供提交窗（`introduced_range`，即漏洞窗口内已知提交
   哈希集合，后续由 Task 7 git 影响挖掘产出）时，条目的
   `introduced_commit`/`fixed_commit` 至少一个落在窗口内；未提供提交窗则
   跳过该键。条目双哈希皆空 → 提交键不排除；条目有哈希且都不在窗口内 →
   排除。

**无匹配返回空 tuple，报告写"暂无对应公开 CVE（待评审）"——不臆测。**

## 数据获取（离线，由运维执行）

1. 从 NVD 官方源获取全量 CVE 数据：`https://nvd.nist.gov/vuln/data-feeds`
   （JSON 1.1/2.0 feeds）或 GitHub `github.com/cve-project/cvelistV5`
   （CVE List v5 每日快照）；亦可用 OSV.dev 离线导出。
2. 按赛题目标仓库（OpenHarmony / 油气仓库）的第三方组件清单过滤出
   `component` + `affected_paths` + 引入/修复提交（NVD `cwe`、CPE、参考
   链接中的 commit 链接是引入/修复提交的主要来源）。
3. 转换为本目录条目格式，存为若干 `*.json` 数组文件放入本目录
   （文件名避开 `*.schema.json` 即可，装载按文件名排序聚合、CVE id 全局去重）。
4. 用 `lima.agent_report.load_cve_index("<本目录>")` 校验通过后方可投产。

## 装载与使用

```python
from lima.agent_report import generate_all_dossiers, load_cve_index

index = load_cve_index("evaluation_data/cve_index")
results = generate_all_dossiers(findings, context, index)
```
