# 正式报告材料缺件检查（Issue #314）

## 实施计划与测试流程（先于实现冻结）

初始基线：`origin/main` 的 `15c8835112ada5d241584926b275693ff582bf44`。
从该基线新建 `codex/issue-314-report-materials`，开始时 tracked diff 为空。
冻结测试时远端 #316、#317 已合并，#318 仍独立审阅，本工具不依赖这些工具。
提交 PR 前 #318 已合并，分支快进到最新 main
`dda3b7f2f33f9fb60c10bcfea924d1a5c434ca7c`，产品改动仍只有本工具五个新增文件。

本次只新增 Issue 约定的五个文件。不改 writer、V4 schema、case 合同、
已有 bundle、打包工具、依赖、CI、Compose 或共享文档。
参考现有 `agent_report` / `openharmony_validation` 输出与赛题材料，但不导入服务。

1. 先新增 unittest 与本流程，运行 Docker 专项取得缺少实现模块的 RED。
2. 实现独立、标准库索引校验与只读附件元数据检查；不读取附件正文。
3. 专项验证八项逐项缺字段、CVE 三态与 known 缺证据、重复 ID/key、空附件、
   路径越界、symlink/junction/reparse、预算、异常脱敏与新输出不覆盖。
4. 使用合成数据运行完整与缺 PoC 两个 CLI 案例，保存两份 JSON、退出码，
   对照执行前后索引/附件 SHA-256，确认只读。
5. 运行相关回归与完整 unittest；检查 diff 仅含五个新增文件。

## 合同

```text
python scripts/check_competition_report_materials.py --index materials.json --root approved-materials --output new-check.json
python -m lima.competition_report_materials --index materials.json --root approved-materials --output new-check.json
```

`--output` 必须显式指定 root 外的新文件，父目录必须已存在；不创建父目录，
不覆盖文件、链接或索引，不向材料目录/已有 sealed bundle 写入。
Windows 输出在规范化前逐组件拒绝盘符之外的冒号/ADS、DOS 保留设备名
（含扩展名、大小写变体和适用的 COM/LPT 上标数字）、CONIN$/CONOUT$、
尾随点/空格及开头 ASCII 空格别名，包含稍后会被 `..` 折叠掉的组件。
合法盘符保留；创建前复核同样规则，保留目录句柄与 O_EXCL，写入前还要求
打开的描述符是普通文件。相关平台语义见
[Windows 命名规则](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)
和 [NTFS 文件流](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)。
退出码：0=结构与必需引用齐备，2=缺件/无效输入，3=用法/输出错误。
输入错误也生成结构化报告；输出错误只打印固定原因码，无原始异常或绝对路径。

独立 JSON 索引：`schema_version` 必须是整数 1；`scope` 必须是
`report-materials-check`；`case_label` 与唯一 `finding_id` 为 1–128 字符
ASCII 标识符（首字符字母/数字，其余字母/数字/点/下划线/连字符）。
`findings` 至少一项。未知字段、重复 JSON key、非有限数字和无效 UTF-8 拒绝。

每项 `field_refs` 必须有八项规范相对路径：
`source_excerpt`、`description_and_cwe`、`trigger_and_path`、`poc_source`、
`reproduction_instructions`、`impact_modules_and_versions`、`remediation`、
`maintainer_review`。一个文件可重复承载多项；仅声明普通文件存在且字节数大于零，
不判断空白正文、段落内容、CWE、复现结果或维护者签名真实性。

`cve_status` 必须显式为 `known`、`no-match-recorded`、`not-assessed`。
`known` 必须提供非空、不重复、格式为 `CVE-YYYY-NNNN...` 的 `cve_ids` 和
非空文件 `evidence_ref`。其余状态允许省略/空 `cve_ids`，禁止附带编号声明。
可选 `evidence_ref` 一旦提供也检查附件，不联网检索 CVE、不推断新漏洞。

可选 `severity` 是维护者提供的非空文本（最多 128 字符、无控制字符）；只记录
provided/pending，不计算严重度、不转述文本为机器判定。
可选 `execution_record_ref` 一旦提供就检查引用；省略 severity 或执行记录时
diagnostics 标记 pending，但不阻止八项必需材料齐备。已提供却无效的可选项返回 2。

路径逐段检查，拒绝绝对路径、盘符、冒号、反斜杠、空/点/点点组件、控制字符、
Windows 保留名/尾随点或空格，以及 root/祖先/附件路径上的链接和 reparse point。
仅检查显式引用，不递归枚举 root，不验清单哈希、不执行附件、不联网、不生成 zip。
POSIX 目录用 dir_fd + O_NOFOLLOW 锚定；Windows 以 OPEN_REPARSE_POINT 句柄检查目录
并持有祖先句柄、拒绝共享写/删除。CLI 也拒绝 Windows UNC/设备路径。
检查只反映观察时的元数据，不是内容快照；检查后材料仍可变化，不能据此声称已封存。
维护者仍需确保所选输出位置不在其他已有 sealed bundle 内。

威胁/失败模型：不可信索引可能尝试越界引用、通过链接访问 root 外文件、
重复 key 覆盖审核信息、提供巨大文件耗尽资源、利用输出竞争覆盖已有结果。
不变量分别是规范相对路径与逐段不跟随检查、有界索引读取与元数据预算、
重复 key 拒绝和新文件 O_EXCL 创建；测试同时覆盖允许的普通文件与这些拒绝路径。

预算：索引 1 MiB，最多 256 个 finding，最多 4096 次引用，路径最多 1024 字符/
32 段，单附件 64 MiB、全部不同引用路径累计 256 MiB；附件只用 stat 检查大小。
超过预算明确报错，不截断成“齐备”。索引以有界读取加载。

输出固定含 `schema_version`、`scope`、`case_label`、`fields_complete`、
`per_finding_missing`、`input_errors`、`diagnostics`。
每个 finding 的 `missing` 列出 field/reason；诊断用固定 schema JSON pointer 定位，
不回显无效输入、附件内容、绝对路径、凭证或原始异常。
始终有 `semantic_verification=not-performed`、`disclosure_approval=not-checked`。
`fields_complete=true` 只代表字段/附件齐备，不代表漏洞成立、批准公开或允许提交比赛。
不替代 #288 的完整性校验、#299 的打包流程或维护者终审。

## 纯合成示例与可复制演示

`report-materials.example.json` 不附带附件，直接检查会返回 2 并如实列缺件。

```powershell
python -m unittest tests.test_competition_report_materials -v
python -m tests.test_competition_report_materials --demo output/report-materials-demo-new
```

先创建 `output`（若不存在）；demo 目录必须是新目录。
demo 首先产生完整结果，随后仅为人工删除 PoC 的模拟删除合成 `poc.txt`，再检查。
其中 body 为合成哨兵，PoC 文件为不可执行文本，未使用真实漏洞或模型。
交付 `complete.json`、`missing-poc.json` 与 `exit-codes.json`；后者应分别为 0、2，
并记录两次检查均未修改各自输入。

Docker 可复用已有含 Python 3.11+ 的 LIMA 镜像，把仓库只读挂到 `/src`，
使用 `--network none --read-only --cap-drop ALL --security-opt no-new-privileges`
与临时 `/tmp`，在 `/src` 执行相同 unittest 命令；演示输出放独立可写目录。
不启动 LIMA 服务，不执行 PoC，不扫描真实仓库。

## 验证记录（2026-10-19）

Docker Desktop 4.65.0 / Engine 29.2.1，复用本机已有 `lima:issue317-review`，
镜像 ID `sha256:a0e1469cb514ce1a36826fa362670a4d1ccd48a4f019435695eea5507b3ed54d`。
使用该镜像既有 Python 3.11 及依赖，未拉取镜像、安装依赖或启动服务。

首次 Docker RED：`python -m unittest tests.test_competition_report_materials -v`
退出 1，只有 loader 的 1 项错误，原因是尚无 `lima.competition_report_materials`。
随后修正两处测试夹具：无效 UTF-8 用例不再被辅助函数重写，输出竞争 Mock 同时
匹配 dir_fd 模式下的文件名；未降低验收断言。
另先写回归再复现并修复了孤立 Unicode surrogate 未处理异常、Windows 大小写
绕过 output/root 比较的问题，保留 RED 日志。新增执行/网络调用禁用测试。

| 环境与范围 | Ran（含跳过） | 实际通过 | 跳过 | 失败/错误 |
| --- | ---: | ---: | ---: | ---: |
| Windows Python 3.12.14 专项 | 42 | 35 | 7 | 0 |
| Docker Linux 专项及相关六模块 | 171 | 169 | 2 | 0 |
| Docker Linux 初始基线全量（修正容器 Git 信任后） | 3290 | 3266 | 24 | 0 |
| Docker Linux PR 基线 dda3b7f 全量 | 3327 | 3303 | 24 | 0 |

Windows 跳过 6 项缺少创建权限的 symlink 测试及 1 项 POSIX FIFO 测试；
真实 Windows junction 与输出大小写边界均通过。Linux 的 2 项跳过分别为这两个
Windows 专用测试，Linux symlink/FIFO 实际通过。

首轮全量发现 3290 项，耗时 192.035 s，跳过 24 项、1 项错误：既有
`test_impact_mining.RealWorktreeIntegrationTests.test_introducing_commit_on_real_worktree`
对非 root 的 `/src` 挂载执行 Git blame，因 dubious ownership 被 Git 拒绝。
单独复现原命令确认原因后，仅在测试容器增加以下环境（无持久配置修改），
该用例已单独复验通过：

```text
--env GIT_CONFIG_COUNT=1 --env GIT_CONFIG_KEY_0=safe.directory --env GIT_CONFIG_VALUE_0=/src
```

全量使用相同配置、2 GiB 内存、2 CPU、PID 512、512 MiB 临时目录，命令为
`python -m unittest discover -s tests -v`。最终实际结果，退出 0：

```text
Ran 3290 tests in 192.791s
OK (skipped=24)
```

24 项跳过包含本工具的 2 项 Windows 用例及既有 22 项环境条件用例
（如 Windows Job Object、Landlock 能力、CMake/clang/ASan/Semgrep 工具条件）。
不把跳过算作通过；本机未运行 Windows 全量。

提交 PR 前同步 #318 后再次运行同一 Docker 全量命令，实际退出 0：

```text
Ran 3327 tests in 182.573s
OK (skipped=24)
```

即实际执行并通过 3303 项，零失败/错误。Windows 在新基线上再次运行专项，
42 项、跳过 7 项，实际通过 35 项，耗时 3.311 s，退出 0。

相关六模块的实际命令：

```text
python -m unittest tests.test_competition_report_materials tests.test_competition_run_summary tests.test_competition_coverage tests.test_agent_report tests.test_openharmony_validation tests.test_ci_contract -v
```

在仓库根目录 PowerShell 可复制以下容器配置，末尾可替换为上述六模块命令：

```powershell
docker run --rm --init --network none --read-only --cap-drop ALL --security-opt no-new-privileges `
  --user 65534:65534 --memory 1g --cpus 2 --pids-limit 128 `
  --tmpfs /tmp:rw,nosuid,nodev,size=256m `
  --mount "type=bind,source=${PWD},target=/src,readonly" `
  --env PYTHONDONTWRITEBYTECODE=1 --env PYTHONPATH=/src --workdir /src `
  --entrypoint python lima:issue317-review -m unittest tests.test_competition_report_materials -v
```

实际 Docker CLI 演示在同样配置下另挂一个独立可写目录为 `/evidence`，运行：

```text
python -m tests.test_competition_report_materials --demo /evidence/docker-demo
```

生成的两份 JSON 如下（仅排版压缩，字段和值与实际文件一致）。
`complete.json`，退出 0：

```json
{
  "schema_version": 1,
  "scope": "report-materials-check",
  "case_label": "synthetic-314",
  "fields_complete": true,
  "per_finding_missing": [{
    "finding_id": "synthetic-001", "finding_index": 0,
    "cve_status": "not-assessed", "missing": [],
    "severity_status": "pending", "execution_record_status": "pending"
  }],
  "input_errors": [],
  "diagnostics": [
    {"location": "#/findings/0/severity", "code": "severity_pending"},
    {"location": "#/findings/0/execution_record_ref", "code": "execution_record_pending"}
  ],
  "semantic_verification": "not-performed",
  "disclosure_approval": "not-checked"
}
```

删除合成 PoC 后的 `missing-poc.json`，退出 2：

```json
{
  "schema_version": 1,
  "scope": "report-materials-check",
  "case_label": "synthetic-314",
  "fields_complete": false,
  "per_finding_missing": [{
    "finding_id": "synthetic-001", "finding_index": 0,
    "cve_status": "not-assessed",
    "missing": [{"field": "poc_source", "reason": "missing_file"}],
    "severity_status": "pending", "execution_record_status": "pending"
  }],
  "input_errors": [],
  "diagnostics": [
    {"location": "#/findings/0/field_refs/poc_source", "code": "missing_file"},
    {"location": "#/findings/0/severity", "code": "severity_pending"},
    {"location": "#/findings/0/execution_record_ref", "code": "execution_record_pending"}
  ],
  "semantic_verification": "not-performed",
  "disclosure_approval": "not-checked"
}
```

`exit-codes.json` 实际记录：

```json
{
  "complete": {"exit_code": 0, "inputs_unchanged": true},
  "missing-poc": {"exit_code": 2, "inputs_unchanged": true}
}
```

文档 example 针对空材料 root 实际退出 2，八项附件逐条报缺件。
演示使用合成 body 哨兵与不可执行 PoC 文本，不验证真实漏洞、CWE、危害、修复、
稳定性、CVE 记录真实性、签名/公开批准或 OpenHarmony 能力；不代表比赛提交验收。
原始日志和合成输入/输出位于本地忽略的 `output/issue-314/`，不进入产品五文件清单。
最终 AST、示例 JSON、空白/末尾换行和文档 JSON 对照实际 Docker 输出检查通过。
结束时 tracked diff 仍为空，未跟踪交付恰为本 Issue 五个允许新增文件；
未修改其他任务、共享文件或既有结果。

## PR #320 的 CI 修复（2026-10-19）

首轮 CI `39230023198` 的两个独立失败：

1. `container-read-only` 构建成功，但测试镜像只复制模块、没有安装包或复制本工具
   脚本。临时工作目录下的 `python -m lima.competition_report_materials` 因找不到
   包而失败。此前源码挂载和 PYTHONPATH 掩盖了这项测试启动错误。
2. `cxx-sidecar-integration` 尚未执行测试，ECR 获取已固定的基础镜像 manifest
   返回 `429 Too Many Requests: Data limit exceeded`，导致 merge-gate 同时失败。

先新增不含脚本、不继承 PYTHONPATH 的最小打包布局用例，实际复现同一错误。
测试/合成 demo 的 fallback 改为通过固定 Python bootstrap 把已知包根目录加入
子进程 sys.path，再用 runpy 启动模块；仍保留临时 cwd 和原有输出/退出码断言。
不改产品 CLI、生产入口、主应用 Dockerfile、环境默认值或 CI。

用户在本轮明确授权排查镜像问题和更改镜像源，因此另外修改
`cxx_analyzer/Dockerfile` 和其既有 `tests/test_cxx_analyzer.py` 固定镜像合同。
仅将 ECR 换成官方 Docker Hub `docker.io/library/python`，digest 仍为
`sha256:b1add8a6f2aca6bcfcf0b9c9b522352f7ce0d62a3d556a2f2f32511aa0cca250`；
实际 `docker pull` 成功，digest 完全一致。未升级基础镜像、改变 Clang/CMake/
Semgrep 版本或弱化非 root、COPY 边界、只读及安全合同。
本轮 PR 的最终范围为最初五个新增文件，加上述两个既有文件的来源/合同调整。

从 Git tracked-source 快照叠加本轮改动构建真实 test 镜像，避免携带本地 worktree/
输出。以下命令直接运行镜像自带测试，不挂载源码、不设置 PYTHONPATH：

```text
docker build --target test --tag lima:issue314-ci-fixed <tracked-source-context>
docker run --rm --network none --read-only --tmpfs /tmp:rw,size=256m lima:issue314-ci-fixed
Ran 3328 tests in 68.655s
OK (skipped=87)
```

即实际执行并通过 3241 项；87 项为该镜像的平台/工具条件跳过，不算作通过。
Windows 本轮材料检查专项与 Sidecar 安全合同合计 48 项，实际通过 41 项，
跳过 7 项，耗时 3.951 s。以上均退出 0、零失败/错误。
新增布局 RED 和两份构建/测试日志保留在本地忽略目录；远端完整 Sidecar 集成
与合并门禁状态以本轮 PR 对应 GitHub Actions 检查为准，不用镜像拉取成功冒充
Sidecar 测试通过。

## 审阅 P2/P3 修复（2026-10-20）

对应 [审阅意见](https://github.com/agent-sec-labs/LIMA/pull/320#issuecomment-6269252266)，
不改字段完整性语义、CVE 状态或报告 writer。

P2：此前 Windows 输出只检查文本路径和 O_EXCL，ADS 能向既有文件/输入索引
增加数据流，设备名也可能不生成普通文件。先新增原生 Windows 回归，实际观察到
`existing.txt` 和 `index.json` 均出现新数据流；设备测试拦截 O_CREAT，不实际写入
控制台、打印机或串口。另复现规范化用 `..` 隐藏不安全组件的情形。

现在在原始输出参数规范化前检查所有 Windows 组件；创建前复核、保留目录句柄/
O_EXCL，并在写入前校验描述符为普通文件。测试通过 FindFirstStreamW/
FindNextStreamW 枚举所有 NTFS 数据流，比较前后名称/大小、默认流字节和既有
合成 ADS 哨兵内容；既有文件和输入索引均不新增或修改数据流，非法输出退出 3。
成功用例必须生成仅有默认数据流的新普通 JSON 文件。

P3：同步 README 的镜像来源说明，主应用及 Sidecar 都使用官方 Docker Hub；
Compose PostgreSQL/Redis 仍用 ECR，digest 固定及主应用 build-arg 范围不变。
审阅修正经本轮用户指示包含 README；最终 PR 为原七文件加 README，共八文件。

原生 Windows Python 3.12.14 专项实际结果：

```text
python -m unittest tests.test_competition_report_materials -v
Ran 48 tests in 3.955s
OK (skipped=7)
```

实际通过 41 项，新增 5 项全部执行（四项原生 Windows 回归及一项跨平台语法测试）。
7 项仍为六项无权限创建 symlink 及 POSIX FIFO；真实 junction 继续通过。
不再用默认数据流的 SHA-256 不变代替 NTFS 数据流完整性检查。

本轮真实 Docker test 镜像构建成功；不挂源码、不设置 PYTHONPATH 的只读全量结果：

```text
docker run --rm --network none --read-only --tmpfs /tmp:rw,size=256m lima:issue314-review
Ran 3333 tests in 67.393s
OK (skipped=91)
```

实际通过 3242 项，零失败/错误。较前次 87 项环境跳过新增四项 Windows 原生测试；
跨平台 Windows 语法校验在 Linux 实际执行。未执行真实漏洞 PoC、OH 扫描或模型调用。
AST 与 diff 空白检查通过；本轮仅修改实现、专项测试、本文和 README 四个文件。
