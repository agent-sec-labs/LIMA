# C/C++ 内存安全分析

LIMA 第一阶段只检测 CWE-787（越界写）、CWE-125（越界读）、CWE-416（释放后使用）和
CWE-415（重复释放）。它分析管理员已导入、受文件数和字节数预算约束的完整仓库快照，
不分析 C/C++ PR diff，也**不自动修复** C/C++ Finding。报告、修复预览、SafeFixer 和
Web 修复按钮都排除这类结果；开发者必须人工复核并在上游项目自己的环境中修复。

## 三层证据

| 层 | 模式 / 状态 | 能说明什么 | 局限 |
|---|---|---|---|
| Semgrep 窄规则 | `source-only` / `candidate` | 从文本快照识别固定缓冲区、明显常量越界、直接释放后使用或重复释放候选 | 没有编译、宏展开、模板、链接或运行路径证据 |
| Clang Static Analyzer | `build-backed` / `build-verified` | 构建成功并得到可信 `compile_commands.json` 后产生结构化路径证据 | 未执行程序，未覆盖编译单元和条件编译仍是盲区 |
| AddressSanitizer | `sanitizer-confirmed` / `confirmed` | 管理员授权测试中解析到完整 ASan 报告并映射访问类型 | 只覆盖真实执行的测试路径 |

`source-only` 是**纯源码分析**。纯源码分析无法可靠理解宏、别名、所有权协议、跨模块
控制流和构建选项，因此永远不高于 `candidate`。任何一层未运行、失败或超时，都必须展示
工具状态和诊断，不能写成“没有漏洞”。测试未触发 ASan 也不能证明安全。

## 管理员 argv JSON 与预算

Compose 默认使用 `auto`：Sidecar 基础设施不可用时继续其他扫描并记录降级；`required`
会让 Sidecar/协议错误导致任务失败。目标项目构建失败属于分析结果，仍保留纯源码候选。
构建和测试只能由管理员在 Sidecar 启动时配置为 JSON argv 数组，分析请求不能提交命令、
Shell 字符串或环境变量：

```dotenv
LIMA_CXX_MEMORY_MODE=auto
LIMA_CXX_ANALYZER_URL=http://cxx-analyzer:8090
LIMA_CXX_AUTO_CMAKE=false
LIMA_CXX_BUILD_STEPS_JSON=[["cmake","-S",".","-B","build","-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"],["cmake","--build","build","--parallel","2"]]
LIMA_CXX_TEST_STEPS_JSON=[["ctest","--test-dir","build","--output-on-failure"]]
```

不要写 `"cmake ... && ctest ..."`、`["sh","-c","..."]` 或 `cmd /c`。每个参数都是
独立字符串，执行器使用 `shell=False`。Sidecar 使用清理后的固定环境；ASan 变量由分析器
拥有，仓库和请求不能覆盖。

| 配置 | 默认值 | 作用 |
|---|---:|---|
| `LIMA_REPOSITORY_SCAN_MAX_FILES` | 5000 | 快照普通文件上限 |
| `LIMA_REPOSITORY_SCAN_MAX_FILE_BYTES` | 524288 | 单文件字节上限 |
| `LIMA_REPOSITORY_SCAN_MAX_TOTAL_BYTES` | 20971520 | 快照总字节上限 |
| `LIMA_CXX_ANALYSIS_TIMEOUT_SECONDS` | 300 | LIMA 等待 Sidecar 的总超时 |
| `LIMA_CXX_MAX_RESPONSE_BYTES` | 2097152 | 响应读取上限 |
| `LIMA_CXX_MAX_MEMORY_MB` | 2048 | Sidecar 内存预算 |
| `LIMA_CXX_MAX_PROCESSES` | 128 | Sidecar PID 预算 |
| `LIMA_CXX_MAX_OUTPUT_BYTES` | 1048576 | 单次工具输出保留上限 |

输出超限时只保留有界前缀、摘要和截断诊断；摘要不完整时不会提升 Finding。

## Compose 部署与健康检查

```powershell
powershell -ExecutionPolicy Bypass -File scripts/lima.ps1 bootstrap
docker compose build cxx-analyzer lima
docker compose up -d
docker compose ps
```

主服务健康入口是 `http://127.0.0.1:18080/health`。管理员登录后访问
`GET /api/repository-scans/capabilities`，核对 C/C++ 模式、Sidecar URL、支持扩展名、四类
CWE、构建/测试配置和 `automatic_repair=false`。Sidecar `/health` 只在内部网络 `8090`
可用，可在主容器内诊断：

```powershell
docker compose exec lima python -c "import urllib.request; print(urllib.request.urlopen('http://cxx-analyzer:8090/health', timeout=2).read().decode())"
```

`cxx-analyzer` 使用非 root UID、只读根文件系统、`/tmp` 与 `/work` tmpfs、全部 capabilities
丢弃、`no-new-privileges`、CPU/内存/PID 限制和只读仓库挂载。它只连接
`internal: true` 的 `cxx_analysis`，不映射宿主端口，也不挂载 Docker Socket。修改 Compose
后必须运行 `docker compose config` 并保留自动化安全契约测试。

## 失败诊断

- `unavailable`/连接超时：检查两个服务的内部网络、Sidecar `/health`、URL 和响应预算。
- `snapshot_rejected`：仓库键、快照 SHA-256、文件预算或符号链接边界不一致；重新导入，
  不要放宽路径检查。
- Semgrep 失败/输出截断：只能记工具失败，空 findings 不能表述为安全。
- `build-not-configured`、`build_failed`、`compile-commands-*`：检查管理员 argv、依赖和
  `compile_commands.json`。请求不能临时补命令或联网装依赖。
- Clang 超时或 plist 被拒绝：保留 source-only，不提升候选。
- `sanitizer-not-configured` 或测试失败但没有完整 ASan：只记诊断；普通断言失败不是漏洞证据。
- `needs-human-review`：ASan 不完整、类型不支持或身份无法安全绑定；查看有界日志摘要，
  不猜测 CWE。

## fixture 协作

`tests/fixtures/cxx_memory/manifest.json` 固定 24 个 LIMA 自有 fixture：每个 CWE 3 个脆弱、
3 个安全场景。新增或修改时：

1. 写一个只表达单一内存语义的 `.c/.cpp`，使用稳定 symbol。
2. 在 manifest 记录唯一 `id`、`cwe`、相对 `path`、`symbol`、`vulnerable`、允许层及
   Clang/ASan 预期。
3. 每个 CWE 始终保留至少 3 脆弱 + 3 安全身份；安全样本针对误报边界，不用空程序凑数。
4. 运行 source、build-backed 和 ASan 容器测试；真实工具没运行时只记录跳过原因。
5. 不复制外部项目源码作为 fixture；外部证据只进入固定版本对清单。

## 固定公开版本对与评测

`evaluation_data/cxx_memory_cases.json` 为每个 CWE 固定一个公开漏洞/修复对。每项必须包含
两个不同的 40 位提交、两个提交归档 HTTPS URL 和实际 SHA-256、CVE/GHSA、上游修复 URL、
affected path/symbol、build/test argv、选样理由和固定许可证 URL。归档先校验 SHA-256 再
解压；解压器拒绝绝对路径、`..`、Windows 路径、符号链接、硬链接、设备/FIFO 和重复路径。
第三方源码只存在于 cache/临时目录，不提交到 Git。

评测器固定只有五个参数：

```powershell
python scripts/run_cxx_memory_evaluation.py `
  --cases evaluation_data/cxx_memory_cases.json `
  --cache-dir .cache/cxx-memory `
  --output output/cxx-memory-evaluation.json `
  --analyzer-url http://cxx-analyzer:8090 `
  --fail-under-precision 0.80
```

缓存的 `repositories` 必须与 Sidecar `/repositories` 使用同一共享挂载，并保留完全相同的
相对 repository key。定时/手动 CI 先校验完整 manifest，再用固定 case ID 选择一项，将其
build/test argv 作为管理员进程环境启动一个专用 Sidecar，并在同一 Sidecar 上依次评测该项
的 vulnerable/fixed revision。argv JSON 通过环境变量原样转发给 `docker --env NAME`，不会
拼接或求值为 Shell 文本。评测请求仍严格只有 `request_id`、`repository_key`、
`snapshot_sha256`、`requested_layers` 四个字段，不携带命令或环境。

报告包含 TP/FP/FN/TN、precision、recall、F1、成对准确率、修复端每 KLoC 目标误报、
各层 Finding 数/完成覆盖率、构建成功率、耗时和超时率。只对清单中的 CWE + path + symbol
打标签，其他 Finding 不计分。层完成要求该 revision 至少有相应工具记录且所有必要记录均
为 `completed`：build-backed 同时要求全部 `build-step` 和全部 `clang` 完成；混合成功/失败
或超时不计覆盖，构建成功也要求全部 build step 完成。分母为零时写 JSON `null` 和
diagnostic，绝不伪造 100%。

每个 revision 还保存 `snapshot_sha256`、源码行数、目标身份/预测、各层 Finding 数与完成
布尔值、构建尝试/完成、超时、耗时、严格有界的 tool-run/coverage/diagnostics。聚合混淆
矩阵、FP/KLoC、层计数/覆盖率、构建率、超时率和总耗时都可仅从 `cases[].revisions` 独立
重算。报告另记录 case-data SHA-256、Sidecar 报告的镜像 digest 和有效性边界；当前
Sidecar 未提供镜像 digest 时字段为 `null` 并明确列为缺口，不能伪造身份。

CWE-415 使用 curl/curl 的 CVE-2026-8925：固定构建显式启用 `CURL_USE_GSASL`，使
`lib/vauth/gsasl.c::Curl_auth_gsasl_is_supported` 进入构建身份，测试以固定构建产物的
`curl --version` 核对该 feature。上游补丁没有确定性的分配失败回归测试，因此这只能证明
受影响 feature 可构建/可执行，不能证明 vulnerable revision 必然在每次评测中触发 double
free；该限制必须保留在评测解释中。

CWE-416 使用 PoDoFo 的 CVE-2025-9394。上游 GitHub 归档不含 `test/resources`
submodule，而默认有界 snapshot 不接纳超过单文件预算的生成式 `utf8proc_data.c`；因此固定
步骤只通过 CMake 生成的 `build.make` 强制编译
`src/podofo/main/PdfTokenizer.cpp`，不会把“没有测试”记为通过，也不声称完整库已链接或漏洞
已确定触发。该 build-verification 在 vulnerable/fixed 两端都验证受影响翻译单元进入真实
Linux/Clang 编译边界。

**合成和固定样本结果不代表真实项目完整检测能力**。这些样本参与规则和流程验证，不能用来
宣称外部泛化、零日能力或生产召回率。

新增版本对前应从 CVE/GHSA 与上游 commit 双重核验：确认修复提交父提交，下载两端归档并
重算哈希，从 diff 记录真实 path/symbol，从固定提交读取许可证，并把命令与结果写进报告。
不得用分支、短 SHA、网页摘要猜测值或不可下载样本补齐行数。
