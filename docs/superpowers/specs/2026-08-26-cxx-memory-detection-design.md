# LIMA C/C++ 内存漏洞检测设计

日期：2026-08-26

## 1. 目标

在保持 LIMA“证据优先、失败时保守关闭”原则的前提下，为有界整仓扫描增加分层的 C/C++ 内存安全检测能力。

第一阶段只检测、不自动修复以下漏洞：

- CWE-787：越界写；
- CWE-125：越界读；
- CWE-416：释放后使用（Use-After-Free）；
- CWE-415：重复释放（Double Free）。

第一阶段只接入配置好的 `repositories/` 导入根目录下的受控整仓扫描。C/C++ PR Diff 分析留作后续扩展。

## 2. 范围与非目标

### 2.1 本阶段范围

- 识别 `.c`、`.cc`、`.cpp`、`.cxx`、`.h`、`.hh`、`.hpp`、`.hxx` 源文件和头文件。
- 使用 Semgrep 实现纯源码候选检测层。
- 使用 Clang Static Analyzer 实现基于构建的静态验证层。
- 使用 AddressSanitizer 实现可选的动态确认层。
- 在 Linux 容器中运行，默认支持自动识别 CMake，并允许管理员配置构建和测试步骤。
- 在报告中明确展示分析模式、工具状态、降级原因和扫描覆盖范围。
- 建立合成测试夹具以及固定的公开漏洞版本/修复版本对。

### 2.2 非目标

- 不自动修复 C/C++ 内存漏洞。
- 不在第一阶段支持 C/C++ PR Diff 内存检测。
- 不自动适配 Windows/MSVC、Bazel、Meson 等构建系统。
- 不加入 Fuzzing、利用代码生成或武器化 PoC。
- 不宣称检测完整、零误报或具备通用零日发现能力。
- 不从头实现指针分析、别名分析、所有权分析或跨过程 CPG 引擎。

## 3. 证据模型

LIMA 必须把“证据是如何产生的”和“结论有多强”分开表示。`Finding` 与 `EvidenceRecord` 增加以下带安全默认值、向后兼容的字段：

```python
language: str = ""
symbol: str = ""
analysis_mode: str = ""
```

`Finding` 额外增加三态修复策略字段：

```python
automatic_repair: Optional[bool] = None
```

字段含义：

- `None`：保持现有 Python 规则驱动的修复资格判断。
- `False`：明确禁止自动修复；所有 C/C++ 内存 Finding 都使用该值。
- 未来即使出现 `True`，也只能表示工具能力，不能绕过 `SafeFixer` 的规则、验证状态、仓库授权、Oracle 和测试门禁。

C/C++ 分析模式限定为：

| 分析模式 | 含义 |
|---|---|
| `source-only` | 未使用成功的目标项目构建，只能视为纯源码候选。 |
| `build-backed` | 在有效编译配置下获得了 Clang 静态分析证据。 |
| `sanitizer-confirmed` | 在授权测试中解析到了 ASan 失败证据。 |

证据与验证状态的映射：

| 证据 | `analysis_mode` | `verification_state` |
|---|---|---|
| 只有 Semgrep | `source-only` | `candidate` |
| Clang 在有效编译上下文中报告 | `build-backed` | `build-verified` |
| Semgrep 与 Clang 对同一保守身份达成一致 | `build-backed` | `build-verified` |
| ASan 动态复现 | `sanitizer-confirmed` | `confirmed` |

`RepositoryScanner.VERIFICATION_RANK` 将 `build-verified` 与 `dataflow-verified` 设为同等级，但不改变现有 Python 验证状态的含义。报告必须单独展示 `analysis_mode`。

所有 C/C++ 内存 Finding 必须设置 `automatic_repair=false`。`SafeFixer` 和修复预览必须在匹配规则前直接拒绝这类结果，即使未来规则 ID 意外与现有可修复规则重名，也不能进入修复流程。

## 4. 总体架构

LIMA 主容器不得挂载 Docker Socket，也不得拥有创建兄弟容器的权限。原生代码分析由独立的 Compose Sidecar 完成：

```text
Repository Scan API
        │
        ▼
ReviewService → RepositoryScanner
                       │
                       ▼
              CxxMemoryAnalyzerAdapter
                       │
                  内部 HTTP
                       │
                       ▼
               lima-cxx-analyzer
                 │       │      │
              Semgrep  Clang   ASan
```

LIMA 与分析器同时以只读方式挂载仓库导入目录。分析器只能解析经过验证的 `repository_key`，并将目标快照复制到自己的隔离临时工作区；它永远不能写入导入仓库。

分析器只连接到与 LIMA 共享的 Compose 内部网络，不发布宿主机端口，也不具备外网出口。LIMA 可以继续连接正常应用网络，以支持已配置的 GitHub 或 LLM 服务。

## 5. 组件与文件

### 5.1 LIMA 主应用

- `lima/cxx_memory.py`
  - 实现版本化 Sidecar 客户端；
  - 校验请求和响应；
  - 作为工具输出规范化边界；
  - 映射 CWE 和 ASan 错误类型；
  - 转换为 `Finding` 与 `EvidenceRecord`。
- `lima/repository_scanner.py`
  - 判断清单是否包含 C/C++ 文件；
  - 按配置模式调用 Adapter；
  - 保守融合规范化后的 C/C++ Finding；
  - 在报告协作元数据中保存工具状态与覆盖范围。
- `lima/models.py`
  - 增加向后兼容的证据字段。
- `lima/config.py`
  - 解析并校验分析器模式、URL、预算和可信构建步骤。
- `lima/service.py`
  - 暴露 C/C++ 扫描能力及各分析层的可用状态。
- `lima/report.py` 与 `web/app.js`
  - 展示语言、分析模式、验证状态、工具证据和降级原因。

### 5.2 分析器 Sidecar

- `cxx_analyzer/server.py`：内部 HTTP 服务和请求校验。
- `cxx_analyzer/source_scan.py`：Semgrep 编排。
- `cxx_analyzer/build_scan.py`：CMake 和 Clang Static Analyzer 编排。
- `cxx_analyzer/sanitizer_scan.py`：ASan 构建、测试执行和日志解析。
- `cxx_analyzer/normalizers.py`：版本化的规范 Finding Schema。
- `cxx_analyzer/rules/cxx-memory.yml`：窄范围纯源码候选规则。
- `cxx_analyzer/Dockerfile`：固定版本的 Semgrep 与 LLVM/Clang 工具链。

### 5.3 测试与数据

- `tests/test_cxx_memory.py`：客户端、Schema、规范化、融合和失败行为测试。
- `tests/fixtures/cxx_memory/`：合成的脆弱与安全 C/C++ 程序。
- `evaluation_data/cxx_memory_cases.json`：固定的公开漏洞/修复版本对。
- `scripts/run_cxx_memory_evaluation.py`：可复现评测入口。

## 6. Sidecar 协议

Sidecar 只提供内部接口：

```http
POST /v1/analyze
```

请求 Schema：

```json
{
  "request_id": "uuid",
  "repository_key": "team/project",
  "snapshot_sha256": "hex-sha256",
  "requested_layers": [
    "source-only",
    "build-backed",
    "sanitizer-confirmed"
  ]
}
```

接口不得接受绝对路径、Shell 片段、环境变量集合或任意命令。`repository_key` 使用与 `RepositoryImportPolicy` 相同的规范化规则，并由 Sidecar 独立再次校验。

响应 Schema：

```json
{
  "schema_version": 1,
  "request_id": "uuid",
  "status": "completed",
  "snapshot_sha256": "hex-sha256",
  "tool_runs": [],
  "findings": [],
  "coverage": {},
  "diagnostics": []
}
```

每个规范化 Finding 必须包含：CWE、规则 ID、严重程度、语言、路径、主行号、符号、解释、有界证据、分析模式、工具名称和可选 Trace Frame。

Schema 版本 1 不接受未知字段。遇到未知 Schema 版本、未知 CWE、快照哈希不一致、不安全路径或错误的 `request_id` 时，必须拒绝整份响应，而不是只丢弃其中一部分。

## 7. 配置

LIMA 主服务接受：

```text
LIMA_CXX_MEMORY_MODE=auto|off|required
LIMA_CXX_ANALYZER_URL=http://cxx-analyzer:8090
LIMA_CXX_ANALYSIS_TIMEOUT_SECONDS=300
LIMA_CXX_MAX_RESPONSE_BYTES=2097152
```

Sidecar 接受由管理员控制的配置：

```text
LIMA_CXX_AUTO_CMAKE=true
LIMA_CXX_BUILD_STEPS_JSON=[]
LIMA_CXX_TEST_STEPS_JSON=[]
LIMA_CXX_MAX_MEMORY_MB=2048
LIMA_CXX_MAX_PROCESSES=128
LIMA_CXX_MAX_OUTPUT_BYTES=1048576
```

构建和测试步骤采用“参数数组的数组”，例如：

```json
[
  ["cmake", "-S", ".", "-B", "build", "-DCMAKE_BUILD_TYPE=Debug"],
  ["cmake", "--build", "build", "--parallel", "2"]
]
```

每个步骤都必须满足：

- 使用 `shell=false`；
- 使用清理后的环境变量；
- 工作目录固定在临时快照内部；
- 有独立超时限制；
- 不支持请求时覆盖命令。

模式行为：

- `off`：跳过 C/C++ 内存分析。
- `auto`：Sidecar 不可用时继续其他仓库扫描；构建或动态层失败时保留纯源码结果。
- `required`：Sidecar 或协议不可用时让扫描任务失败。目标仓库构建失败属于分析结果，不属于基础设施不可用，因此仍应返回纯源码结果及构建失败诊断。

## 8. 分析流程

1. `RepositoryWorkspace` 生成有界文件清单和快照哈希。
2. 如果没有支持的 C/C++ 文件，`RepositoryScanner` 不调用 Sidecar。
3. LIMA 发送经过验证的仓库键、快照哈希、请求层和请求 ID。
4. Sidecar 解析仓库键、拒绝符号链接逃逸、独立计算快照哈希，并将普通文件复制到临时工作区。
5. 请求纯源码层时，首先运行 Semgrep。
6. 如果存在 `CMakeLists.txt` 且启用了自动 CMake，则使用固定的 CMake 参数数组；否则使用管理员配置的步骤。
7. 获得成功构建上下文后，才允许运行 Clang Static Analyzer。
8. 只有配置了可信测试步骤时才启用 ASan。测试失败但没有可识别的 Sanitizer 报告时，只能记录诊断，不能判定存在内存漏洞。
9. Sidecar 规范化并限制输出、重新确认快照身份，然后返回响应。
10. LIMA 必须先完整校验响应，再接受任何 Finding。
11. 只有 CWE、规范化路径、符号和主位置一致时才融合证据；有歧义的结果保持独立。
12. 现有报告和 Store 持久化接受的 Finding 与分析元数据。

## 9. 纯源码规则

纯源码规则必须保持窄范围，且永远不能声明已确认漏洞。第一批候选形态包括：

- 固定大小缓冲区传入无界复制或格式化 API；
- `memcpy`/`memmove` 长度表达式与目标缓冲区大小存在明显不一致；
- 同一函数中指针被无条件 `free` 后，在没有重新赋值的情况下继续使用；
- 同一函数中同一指针在没有重新赋值的情况下重复 `free`；
- 对静态已知长度数组使用明显越界的常量索引。

禁止使用“报告所有 `memcpy`、指针解引用、数组索引或 `free`”之类的宽泛规则，否则纯源码层会因误报过多而失去使用价值。

## 10. ASan 映射

可识别的动态证据按下表映射：

| ASan 类型 | 附加信号 | CWE |
|---|---|---|
| `heap-buffer-overflow` / `stack-buffer-overflow` / `global-buffer-overflow` | 写访问 | CWE-787 |
| 上述 Overflow 类型 | 读访问 | CWE-125 |
| `heap-use-after-free` | 任意访问 | CWE-416 |
| `attempting double-free` | 释放操作 | CWE-415 |

无法识别的 Sanitizer 失败只能形成有界诊断，并标记 `needs-human-review`，不得强行映射到这四类 CWE。

## 11. 安全控制

分析器会执行已授权但仍可能恶意的构建逻辑，因此容器必须具备以下限制：

- 使用非 root 用户；
- 根文件系统只读；
- 仅为工作目录和临时文件提供有大小限制的 tmpfs；
- 不挂载 Docker Socket；
- 不发布宿主机端口；
- 只连接无外网出口的 Compose 内部网络；
- 丢弃全部 Linux capabilities；
- 设置 `no-new-privileges`；
- 限制内存、CPU、进程数、文件大小、输出大小和执行时间；
- 使用清理后的环境，不提供 LIMA、GitHub、LLM、数据库、代理或用户密钥；
- 不跟随导入仓库中的符号链接；
- 在每个复制边界执行路径包含校验。

LIMA 主服务必须把 Sidecar 输出视为不可信输入。在持久化前校验：响应大小、JSON 结构、Schema 版本、标识符、路径、行号、枚举值、快照身份和请求关联关系。

## 12. 失败语义

- `auto` 模式下 Sidecar 不可用：继续 Python 和其他扫描，并记录 `cxx_memory.status=unavailable`。
- `required` 模式下 Sidecar 不可用：任务失败。
- Semgrep 失败：记录工具失败，不能将其表述为“扫描无漏洞”。
- 构建失败：保留纯源码候选并记录 `build_failed`。
- Clang 超时或输出格式错误：不得提升任何候选的验证状态。
- 测试失败但没有 ASan 证据：只记录测试失败。
- ASan 崩溃无法解析：只记录 `needs-human-review`。
- 输出达到上限：保留结构化摘要与哈希，并标记原始日志已截断。
- 快照不一致、不安全路径、未知 Schema/CWE 或响应超限：拒绝完整 Sidecar 响应。

## 13. 报告与 API 行为

仓库扫描能力接口需要报告：

- Sidecar 是否已配置且可访问；
- 当前选择的 C/C++ 模式；
- 支持的扩展名和 CWE；
- 纯源码、构建和 Sanitizer 层是否可用；
- 是否配置了构建与测试步骤；
- `automatic_repair=false`。

Markdown 和 Web 报告需要为每条 C/C++ Finding 展示：

- 语言与符号；
- CWE 与主位置；
- 用户可读的分析模式；
- 验证状态；
- 提供证据的工具；
- 有界 Trace/证据；
- 纯源码候选的明确警告；
- 构建或 Sanitizer 降级原因；
- 不支持自动修复的说明。

## 14. 测试与评测

### 14.1 单元测试

覆盖 Semgrep、Clang、ASan 规范化，响应校验，CWE 映射，证据融合，验证等级，纯源码标签，超时和不可用处理，输出限制，快照不一致，不安全路径，以及修复流程排除。

### 14.2 合成测试夹具

每个 CWE 至少准备 3 个脆弱场景和 3 个安全/修复场景，总计不少于 24 个。每个夹具记录预期 CWE、路径、符号、允许的检测层以及是否预期由 ASan 确认。

### 14.3 公开漏洞/修复版本对

每个 CWE 至少选择一个公开版本对，并固定：项目、脆弱 Commit、修复 Commit、归档 SHA-256、上游公告/CVE、受影响路径和符号、构建步骤、测试/复现入口以及选样理由。每个版本对的两端都必须参与评测。

### 14.4 CI

Windows/Linux Python CI 使用模拟 Sidecar 响应，不要求安装 LLVM。Ubuntu 容器 CI 构建分析器镜像、运行合成夹具，并在网络和资源限制下执行 LIMA 与 Sidecar 集成测试。

### 14.5 指标

记录以下指标：

- Precision、Recall、F1；
- 脆弱/修复版本对准确率；
- 每 KLoC 误报数；
- 各分析层候选数量；
- build-backed 覆盖率；
- sanitizer-confirmed 覆盖率；
- 构建成功率；
- 分析耗时；
- 超时率。

## 15. 验收标准

- 每条被接受的 C/C++ Finding 都显示明确的分析模式。
- 纯源码结果的验证状态不得超过 `candidate`。
- 四类已识别的 ASan 错误能正确映射到对应 CWE。
- 构建失败时保留纯源码候选并展示降级原因。
- 修复版本不得继承漏洞版本的 `confirmed` Finding。
- 快照不一致和不安全路径会导致响应被拒绝。
- 请求载荷不能引入命令或环境变量。
- C/C++ 内存 Finding 不能进入自动修复或修复预览。
- Sidecar 不得拥有 Docker Socket、宿主机端口、外网出口、root 用户或额外 Linux capabilities。
- 现有 Python 扫描行为和当前 165 个测试不得回归。
- 评测输出必须说明有效性边界，不得把合成夹具成功率等同于真实项目完整检测能力。

## 16. 实施顺序

1. 增加向后兼容的数据模型、协议类型和模拟客户端测试。
2. 实现纯源码 Sidecar 分析层与合成 CWE 夹具。
3. 接入 Compose、安全限制和仓库扫描 Adapter。
4. 实现 CMake/Clang build-backed 分析层。
5. 实现 ASan 测试层和日志解析器。
6. 完善 Markdown/Web 报告和能力接口。
7. 加入固定的公开漏洞/修复版本对和可复现评测报告。
8. 首先以可选 `auto` 模式发布；只有测得足够的运行可靠性后才考虑启用 `required`。
