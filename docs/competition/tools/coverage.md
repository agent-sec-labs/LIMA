# 离线覆盖记录摘要（E04 / #293）

`scripts/summarize_competition_coverage.py` 只读一个 competition-validation
bundle，将已有覆盖记录输出为 JSON 或 Markdown。仅用 Python 3.11+ 标准库，
不联网、不加载模型、不执行目标代码、不修改输入包。

```powershell
python scripts/summarize_competition_coverage.py --bundle <bundle目录> --format json
python scripts/summarize_competition_coverage.py --bundle <bundle目录> --format markdown
```

默认格式为 JSON。stdout 为完整结果；输入错误写入 stderr，stdout 为空，退出码 2。
成功解析的退出码为 0，即使包内 `status` 是 `failed` 或 `inconclusive`。
此退出码仅表示摘要生成成功，不改变原验证状态。

也支持 `python -m lima.competition_coverage --bundle <目录> --format json`。
脚本与模块使用同一个 `main`；常规单测通过模块入口运行，兼容仅打包 `lima/`
而未复制新增脚本的既有 Docker 测试镜像。专用 Docker 验收另以脚本入口执行 18 次 CLI。

## 输入与一致性

- `summary.json` 必须存在且为 UTF-8 JSON 对象。根 `case_id`、`status` 缺失或为
  `null` 时保持未知，非字符串的已知值失败；未知状态字符串原样保留。
- 两侧 `vulnerable` / `fixed` 独立处理。缺侧对象允许；侧对象存在时必须为对象。
- `vulnerable/platform.json`、`fixed/platform.json` 可缺失；文件存在但损坏则失败。
  不读取 `case.json`、finding 附件、AEP 或其他文件。
- summary 侧对象与对应 platform 对象中的**所有重叠字段**必须相同，包括未投影的
  字段。对象键顺序不影响一致性，数组顺序影响；数值 `1` 和 `1.0` 相同，布尔值
  不视为数值。所有发现的冲突列出双方文件及 JSON Pointer，拒绝静默覆盖。
- 两处都存在同一字段时记录两个来源；仅一处存在则使用该处。显式 `null` 是未知值，
  与另一处非空值冲突；缺字段不会与另一处的已知值冲突。
- 拒绝重复 JSON 键、损坏编码、错误字段类型及非有限数（包括 NaN、Infinity、
  `1e400`）。比例为数值且在闭区间 `[0, 1]`，不接受布尔值或数字字符串。
  `unreviewed_units` / `diagnostics` 为字符串数组或 `null`。
- 该工具不校验哈希、文件清单完整性或证据真实性，也不实现 #288 的校验器。
  输入应来自已经批准的 bundle；摘要成功不能代替验包。

## 输出合同（schema_version = 1）

根字段：`schema_version` 为本工具输出版本 1；`case_id` 直取根 `case_id`；
`validation_status` 直取根 `status`；`vulnerable` / `fixed` 各含下表字段。
根 `field_sources` 记录元数据来源，工具生成的 schema_version 来源为空数组。

| 每侧字段 | 含义、来源与未知值 |
| --- | --- |
| `snapshot_file_coverage` | 输入 `file_coverage` 原比例；缺失/null 输出 null |
| `snapshot_byte_coverage` | 输入 `byte_coverage` 原比例；缺失/null 输出 null |
| `unreviewed_units` | 原字符串数组，保持顺序和重复记录；缺失/null 输出 null |
| `unreviewed_count` | 上述数组长度；缺失/null 输出 null；明确的 `[]` 输出 0 |
| `expected_tu_count` | 始终 null；当前格式没有可依赖的完整 TU 总数 |
| `reviewed_tu_count` | 始终 null；当前格式没有可依赖的已审阅 TU 数 |
| `semantic_review_coverage` | 始终 null；不能计算可靠的语义审阅覆盖率 |
| `coverage_gaps` | 从 diagnostics 中精确匹配 `coverage gap: ` 开头，去掉该前缀，保留剩余原始 code 字符串，按侧去重并按字符串升序排序；diagnostics 未知则 null |
| `coverage_gap_count` | 上述去重 code 数，表示“记录的 gap 种类数”；诊断未知为 null；显式空诊断为 0 |
| `diagnostics` | 其余诊断字符串，保持原顺序和重复记录，不重新分类；缺失/null 为 null |
| `field_sources` | 每个数据字段对应 JSON Pointer 字符串数组；计算字段指向原始输入字段，无依据为空数组 |
| `field_notes` | 对未知字段说明原因；说明文字不混入输入 diagnostics |

例如来源 `summary.json#/vulnerable/file_coverage` 与
`vulnerable/platform.json#/file_coverage` 可同时出现。
`unreviewed_count` 来源是 `unreviewed_units`，gap 及其数量来源是 `diagnostics`。
来源表示字段或计算输入的位置，不代表数据已被独立验证。

JSON 始终保存原比例；Markdown 才转为百分比（最多六位小数）。
Markdown 包含双侧比较、未审阅原始条目、gap code、其他诊断、字段来源及未知原因，
并对输入文本中的 HTML/Markdown 字符转义。

不得从 `case.translation_units`、finding 数量或空未审阅列表推算扫描范围；即使输入
出现同名 TU 数字段，本版本也不采用它们。无 finding 不证明零漏报，快照比例 100%
不证明完整语义审阅。两侧分母不合并。未审阅记录数也不作为 TU 总数。

## 两份可复现合成演示

在仓库根目录执行，生成器只新建目录，不覆盖已有演示。重复执行时请换一个新目录名。
以下全部是合成数据，用于字段解析验收，不是实战检测效果。

```powershell
python -c "from pathlib import Path; from tests.test_competition_coverage import write_demo_bundles; write_demo_bundles(Path('output/coverage-demo'))"
python scripts/summarize_competition_coverage.py --bundle output/coverage-demo/current --format json
python scripts/summarize_competition_coverage.py --bundle output/coverage-demo/current --format markdown
python scripts/summarize_competition_coverage.py --bundle output/coverage-demo/legacy --format json
python scripts/summarize_competition_coverage.py --bundle output/coverage-demo/legacy --format markdown
```

### 演示一：部分未审阅，状态 failed

`current/summary.json`（完整输入）：

```json
{
  "case_id": "synthetic-current",
  "status": "failed",
  "vulnerable": {
    "file_coverage": 0.5,
    "byte_coverage": 0.25,
    "unreviewed_units": ["src/b.c"],
    "diagnostics": ["coverage gap: BUDGET", "coverage gap: BUDGET", "provider-unavailable"],
    "findings": []
  },
  "fixed": {
    "file_coverage": 1.0,
    "byte_coverage": 1.0,
    "unreviewed_units": [],
    "diagnostics": [],
    "findings": []
  }
}
```

另有 `current/vulnerable/platform.json`，内容与上述 vulnerable 对象一致；fixed 无
platform 文件。两个输入来源一致后才采用 vulnerable 字段。

实际 JSON 输出节选（省略 fixed 和其余字段来源/说明）：

```json
{
  "schema_version": 1,
  "case_id": "synthetic-current",
  "validation_status": "failed",
  "vulnerable": {
    "snapshot_file_coverage": 0.5,
    "snapshot_byte_coverage": 0.25,
    "unreviewed_units": ["src/b.c"],
    "unreviewed_count": 1,
    "expected_tu_count": null,
    "reviewed_tu_count": null,
    "semantic_review_coverage": null,
    "coverage_gaps": ["BUDGET"],
    "coverage_gap_count": 1,
    "diagnostics": ["provider-unavailable"],
    "field_sources": {
      "snapshot_file_coverage": [
        "summary.json#/vulnerable/file_coverage",
        "vulnerable/platform.json#/file_coverage"
      ]
    }
  }
}
```

实际 Markdown 比较表（stdout 还包含来源、原始条目与未知原因）：

| 字段 | vulnerable | fixed |
| --- | --- | --- |
| 快照文件覆盖率 | 50% | 100% |
| 快照字节覆盖率 | 25% | 100% |
| 未审阅条目数 | 1 | 0 |
| 预期 TU 数 | 未记录 | 未记录 |
| 已审阅 TU 数 | 未记录 | 未记录 |
| 语义审阅覆盖率 | 不可计算（未记录可靠 TU 分母） | 不可计算（未记录可靠 TU 分母） |
| 记录的 gap 种类数 | 1 | 0 |

根 `validation_status` 仍为 `failed`；fixed 明确空列表也没有变成 100% 语义覆盖。

### 演示二：旧包未记录未审阅字段

`legacy/summary.json`（完整输入，无 platform 文件）：

```json
{
  "case_id": "synthetic-legacy",
  "status": "inconclusive",
  "vulnerable": {"file_coverage": 1.0, "byte_coverage": 1.0, "findings": []},
  "fixed": {}
}
```

实际 vulnerable JSON 输出节选：

```json
{
  "snapshot_file_coverage": 1.0,
  "snapshot_byte_coverage": 1.0,
  "unreviewed_units": null,
  "unreviewed_count": null,
  "expected_tu_count": null,
  "reviewed_tu_count": null,
  "semantic_review_coverage": null,
  "coverage_gaps": null,
  "coverage_gap_count": null,
  "diagnostics": null
}
```

实际 Markdown 比较表：

| 字段 | vulnerable | fixed |
| --- | --- | --- |
| 快照文件覆盖率 | 100% | 未记录 |
| 快照字节覆盖率 | 100% | 未记录 |
| 未审阅条目数 | 未记录 | 未记录 |
| 预期 TU 数 | 未记录 | 未记录 |
| 已审阅 TU 数 | 未记录 | 未记录 |
| 语义审阅覆盖率 | 不可计算（未记录可靠 TU 分母） | 不可计算（未记录可靠 TU 分母） |
| 记录的 gap 种类数 | 未记录 | 未记录 |

### 错误演示

仅修改演示副本 `current/vulnerable/platform.json` 的 `file_coverage` 为 0.75，
再次运行任一格式会退出 2，stdout 为空，stderr 包含：

```text
coverage_input_error:
conflicting field: summary.json#/vulnerable/file_coverage != vulnerable/platform.json#/file_coverage
```

## 自动与人工验收

```powershell
python -m unittest tests.test_competition_coverage -v
python -m unittest tests.test_openharmony_validation tests.test_ci_contract -v
```

专项测试覆盖：完整字段与来源、旧包缺字段、空列表、部分未审阅、无 finding、
缺失 TU 分母、比例越界/NaN/无穷/错误类型、双来源多字段冲突、platform 单独字段、
gap 精确前缀/同码去重/双侧隔离、损坏输入、JSON 与 Markdown 同源、退出码与输入不变。

人工复核 Issue 清单：

- [ ] 演示一 vulnerable 的 JSON 是 0.5，Markdown 是 50%。
- [ ] 演示二未审阅字段为 null / 未记录。
- [ ] 演示一 fixed 的 [] 和 0 不改变语义覆盖率 null / 不可计算。
- [ ] 演示一两个相同 gap 计一种，两侧不混合。
- [ ] 演示一验证状态保持 failed，即使 fixed 快照覆盖率为 100%。

测试和演示不调用真实模型、Sidecar 或目标项目代码；没有验证漏洞真假、CWE、
修复有效性、检测率或 bundle 哈希真实性。这些结论不能由本工具给出。

2026-10-18 本机执行记录：Windows / Python 3.12.14，基线 `bd8ba34`。
专项命令原始结果末尾为：

```text
Ran 21 tests in 1.645s

OK
```

现有 bundle 与 CI 合同回归命令原始结果末尾为：

```text
Ran 70 tests in 154.122s

OK
```

此外，以现有 `BundleWriterTests` 的合成 fixture 调用真实 `write_validation_bundle`
后读取摘要，双来源一致、验证状态保持 `passed`、语义覆盖率为 null，包文件哈希不变。
两份文中演示已实际运行 JSON/Markdown；另建冲突副本，确认退出 2、stdout 为空，
三份输入文件哈希均不变。新增 Python 文件编译和 `git diff --check` 通过。

本机完整专项原始日志和实际演示材料保存在忽略目录
`output/competition-coverage-293/`：`unit-tests.log`、`current/`、`legacy/`、
`current.json`、`current.md`、`legacy.json`、`legacy.md`、`conflict.stderr.txt`、
`demo-verification.json` 和 `writer-round-trip.json`。这些生成材料不加入提交。
Windows 沙箱的临时目录 ACL 阻止测试创建子目录，本机测试在沙箱外完成。
上述本机阶段未运行全量套件、容器测试或真实模型评测；后续 Docker 验收单独记录如下。
自动测试不代替人工验收或合并后复验。

## Docker 验收流程（先冻结脚本，再执行）

容器验收入口放在本次新增的测试文件中，避免增加 Issue 白名单以外的项目文件：

```text
python -m tests.test_competition_coverage --docker-acceptance --output /evidence/results
```

`--output` 必须是不存在的新目录。失败返回 1，成功返回 0；完整结果保存到
`report.json`，保留各步骤日志及实际 CLI 输出。正常 `python -m unittest` 用法不变。

预先固定以下流程；不得因为失败而跳过测试、减小预期测试数量或放宽通过条件：

1. 使用项目 Dockerfile 中同一个 digest 固定的 Python 3.11 slim 基镜像，安装 Git
   仅用于已有合成 checkout fixture。不安装 pip 依赖，以验证该工具的标准库独立性。
2. 构建上下文只复制 tracked `lima/` 和显式列出的三份测试、三个脚本、pilot/schema、
   CI/前端合同文本；不复制 `.env`、导入仓库或历史证据包。记录源文件 SHA-256。
3. 运行 non-root UID 10001、只读根文件系统、`--network none`，丢弃 capabilities，
   禁止提权；限制 512 MiB 内存、2 CPU、128 个进程。仅 `/tmp` tmpfs 和专用证据目录
   可写，不向容器挂载 Docker socket。
4. 专项 21 项与已有 bundle/CI 合同回归 70 项分别执行；任意失败、错误、跳过或测试
   数量偏离都判定失败。保存 `unit-tests.log` 和 `regression-tests.log`。
5. 通过真实 writer 生成合成 bundle 并摘要，核对验证状态、双来源一致、语义覆盖率未知，
   对比输入文件哈希；输出 `writer-summary.json`。
6. 创建 9 种 CLI 输入：部分未审阅新包、缺字段旧包、明确空列表、双侧不同重复 gap、
   summary/platform 冲突、越界比例、NaN、损坏 JSON、缺 summary。输入在 Linux tmpfs
   中设为只读，并通过写入探针确认不可写。
7. 对 9 种输入分别运行 JSON/Markdown，共 18 次 CLI。正常输入退出 0；坏输入退出 2、
   stdout 为空、stderr 包含文件及字段。每次测试后比较输入文件清单与哈希。
8. 自动核对 Issue 的五项人工清单对应字段：0.5 → 50%、缺字段 → 未记录、空列表
   不产生语义 100%、gap 按侧去重、failed 状态不变。保存原始输入和输出便于人工复核。
9. 保存 Docker 引擎/镜像身份、实际容器配置和退出状态，确认断网、只读、无 OOM。
   仅移除本次测试容器，保留镜像与证据；不操作其他容器或卷。

本机便捷编排脚本位于忽略目录
`output/competition-coverage-293/docker/run_docker_tests.py`。它先创建独立构建上下文，
再 build/create/start/inspect 本次容器，每次运行写入新时间戳目录：

```powershell
cd E:\githubproject\LIMA
python output/competition-coverage-293/docker/run_docker_tests.py
```

等价容器运行参数（`$evidencePath` 为已创建的专用证据目录；镜像由上述脚本构建）：

```powershell
docker run --rm --read-only --network none --cap-drop ALL --security-opt no-new-privileges `
  --pids-limit 128 --memory 512m --cpus 2 `
  --tmpfs /tmp:rw,nosuid,nodev,size=256m,mode=1777 `
  --mount "type=bind,source=$evidencePath,target=/evidence" `
  lima-coverage-293:test --output /evidence/results
```

本流程验证 E04 离线字段投影及当前 writer/CLI 合同；不是 LIMA 全量容器套件，
也不产生真实漏洞检测、Sidecar 或模型效果结论。

### Docker 实际执行结果（2026-10-18）

北京时间 17:16:56–17:17:02，在 Docker Desktop 4.65.0 / Engine 29.2.1 的
Linux amd64 容器中完成；Python 3.11.16，UID 10001，未安装 pip 依赖。
源基线仍为 `bd8ba34` 加本分支新增文件，所有实际输入源码哈希见 source manifest。

| 验收项 | 实际结果 |
| --- | --- |
| 专项 unittest | 21 通过，0 失败/错误/跳过；0.713 秒 |
| 相关回归 unittest | 70 通过，0 失败/错误/跳过；2.348 秒 |
| CLI 实际运行 | 9 类输入 × 2 种格式 = 18 次，全部符合预期 |
| 过程及最终效果检查 | 43 项通过（与 unittest/CLI 次数不同，不合并计数） |
| 真实 writer | 双来源一致、原状态保留、语义覆盖率 null、输入不变 |
| 只读输入 | 每份输入写入探针被拒绝，运行前后清单/哈希相同 |
| 运行配置 | network none、只读根文件系统、non-root、cap-drop ALL，实际 inspect 已核对 |
| 容器退出 | 0，OOMKilled=false；本次容器已清理，镜像保留 |

实际证据目录：
`output/competition-coverage-293/docker/run-20261018T091529939680Z/`。
其中 `results/report.json` 为结构化验收记录，`results/unit-tests.log` 和
`results/regression-tests.log` 为完整原始日志；`results/inputs/` 与 `results/cli/`
为完整输入输出；`container-inspect.json` 为实际隔离配置与退出状态，`build.log`
为镜像构建日志。便捷阅读报告位于 `output/competition-coverage-293/docker/REPORT.md`。

提交 PR 前将 CLI 逻辑集中到模块 `main`，常规单测改从模块入口运行，以兼容既有
Dockerfile 未复制新增脚本的打包范围。2026-10-18 北京时间 18:12 再次完整运行专用容器：
专项 21 项（0.723 秒）、相关回归 70 项（2.397 秒），均零失败/错误/跳过；脚本入口
18 次 CLI 与 43 项检查全部通过。该次最新源码与证据位于
`output/competition-coverage-293/docker/run-20261018T101224405841Z/`。

## 本次文件范围

E04 功能新增以下四个文件，无需改依赖、writer、检测器、gap taxonomy 或历史 bundle：

- `scripts/summarize_competition_coverage.py`
- `lima/competition_coverage.py`
- `tests/test_competition_coverage.py`
- `docs/competition/tools/coverage.md`

### 用户授权的 CI 镜像源修复

PR #316 的 `container-read-only` 在拉取 ECR Python 基镜像时遇到
`429 Too Many Requests / Data limit exceeded`，尚未进入容器测试。
用户随后明确授权考虑更换镜像源，因此本次在原四个新文件之外，仅额外修改主
`Dockerfile` 两个 ARG 的默认拉取地址：

- `public.ecr.aws/docker/library/python` → `docker.io/library/python`
- `public.ecr.aws/docker/library/node` → `docker.io/library/node`

Python 的 `9c900dea…d5bfc7` 和 Node 的 `c610fcdf…3aa32` 完整固定 digest 保持原值。
实测读取 Docker Hub 官方仓库的原始 OCI manifest，计算 SHA-256 与各固定 digest
相同；没有升级基础镜像。Sidecar、数据库、Redis 的来源与其合同不变。
原 `PYTHON_BASE_IMAGE` / `NODE_BASE_IMAGE` build arg 覆盖方式继续可用。

换源后实际执行主 Dockerfile 的 `docker build --pull --target test` 构建成功，再以
非 root、只读根文件系统、断网容器执行默认全量 unittest：

```text
Ran 3221 tests in 64.130s

OK (skipped=80)
```

即执行 3141 项、按既有条件跳过 80 项，零失败/错误；跳过原因包括镜像未装 Git、
Clang/CMake/Semgrep、宿主 Landlock ABI 不足和平台限定。没有为了通过而修改测试
或跳过条件。容器退出 0，OOMKilled=false。
构建日志、完整测试日志、manifest 和校验记录保存在本机忽略目录
`output/competition-coverage-293/registry-switch/run-20261018T103327820981Z/`。

Docker Hub 官方源也有拉取限额；这次变更绕开已确认的 ECR 限流，不承诺任何镜像仓库
永久无限制。说明见 [Docker Official Images](https://docs.docker.com/docker-hub/image-library/trusted-content/)
和 [Docker Hub 拉取限额](https://docs.docker.com/docker-hub/usage/pulls/)。

参考：[Issue #293](https://github.com/agent-sec-labs/LIMA/issues/293)。
