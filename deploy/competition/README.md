# 参赛部署 profile（性能调优部署）

本目录是 LIMA 智能体漏洞挖掘平台在**比赛/性能评分场景**下的部署指引。与默认
部署的差异只有一类：**房间大小**（快照限额、内存、CPU、tmpfs）与**预处理
深度**。沙箱五层锁不放宽；受信构建门禁按其自身的 fail-closed 探针清单开启，
不构成沙箱放宽。设计依据：`docs/superpowers/specs/2026-09-12-agent-vuln-platform-design.md`
§8（规模化）、`docs/CXX_MEMORY_ANALYSIS.md`（受信构建生成门禁）。

环境变量样例见同目录 `.env.competition.example`（每项有注释）。

## 1. 快照限额参数组（放开默认限额）

默认限额面向普通 Web 仓库；参赛场景是大型 C/C++ 仓库（如 OpenHarmony 子系统、
油气仓库），需按组放开：

| 变量 | 默认 | 参赛建议 | 说明 |
|---|---:|---:|---|
| `LIMA_REPOSITORY_SCAN_MAX_FILES` | 5000 | 50000 | 快照普通文件上限 |
| `LIMA_REPOSITORY_SCAN_MAX_FILE_BYTES` | 524288 | 4194304 (4MB) | 单文件字节上限（大型生成代码/数据表需要） |
| `LIMA_REPOSITORY_SCAN_MAX_TOTAL_BYTES` | 20971520 | 2147483648 (2GB) | 快照总字节上限 |

配套必须同步放大的 Sidecar/分析侧限额（否则快照进得去、分析出不来）：

| 变量 | 默认 | 参赛建议 |
|---|---:|---:|
| `LIMA_CXX_ANALYSIS_TIMEOUT_SECONDS` | 300 | 900 |
| `LIMA_CXX_MAX_RESPONSE_BYTES` | 2097152 | 16777216 |
| `LIMA_CXX_MAX_MEMORY_MB`（Sidecar 容器 `mem_limit`） | 2048 | 8192 |
| `LIMA_CXX_MAX_PROCESSES`（Sidecar 容器 `pids_limit`） | 128 | 512 |
| `LIMA_CXX_STEP_TIMEOUT_SECONDS` / `LIMA_CXX_TOTAL_TIMEOUT_SECONDS`（受信构建步骤） | 120 / 300 | 600 / 1800 |

智能体侧（按核数与预算调整，逐项含义见 `.env.competition.example`）：
`LIMA_CXX_AGENT_PARALLELISM`（独立沙箱实例并行目标数）、
`LIMA_CXX_AGENT_DIALOGUE_ROUNDS`、`LIMA_CXX_AGENT_MAX_CALLS`、
`LIMA_CXX_AGENT_TIMEOUT_SECONDS`、`LIMA_CXX_AGENT_MAX_OUTPUT_BYTES`。

## 2. tmpfs / 内存 / CPU 建议

- Sidecar（cxx-analyzer）容器：`mem_limit` ≥ 8GB、`pids_limit` ≥ 512；CPU
  按并行度给满（每个并行目标一个 clang/ASan 编译运行）。
- WORK_ROOT / scratch/build 目录保持 **ephemeral tmpfs**（compose 已有
  `tmpfs` 挂载）；容量按最大单次实验（编译产物 + PoC 运行）估算，建议 ≥ 4GB。
- 仓库缓存（`LIMA_REPOSITORY_CACHE_ROOT` 所在卷）≥ 3× 最大仓库裸大小，
  `LIMA_REPOSITORY_CACHE_QUOTA_BYTES` 相应放大（默认 2GB，建议 10GB+），
  `LIMA_REPOSITORY_CACHE_MIN_FREE_BYTES` 保持 512MB 以上。
- 复现工作台的 ASan 运行是串行资源大头：`LIMA_CXX_AGENT_PARALLELISM` 的
  上限 = 独立沙箱实例数，不要超过 CPU 核数与 Sidecar 内存预算的比值。

## 3. 受信构建门禁开启步骤

默认部署**永不执行**仓库里的构建系统（`CMakeLists.txt` 可通过
`execute_process()` 产生任意副作用）。需要 compile_commands.json 的仓库走
受信构建生成门禁，开启步骤：

1. 部署环境先满足机器可探测探针（`cxx_analyzer/trust.py` 执行时 fail-closed
   探测，缺一即不执行）：Landlock ABI ≥ 3、seccomp 进程隔离可用、非 root
   uid、network namespace 仅 loopback、WORK_ROOT 所在挂载只读、snapshot 与
   import 目录只读挂载、无 Docker socket / host path / credential 挂载、
   scratch/build 为请求后销毁的 ephemeral tmpfs、CPU/memory/PID/输出/文件
   大小/绝对时间限额配置存在。
2. 设置管理员级总门禁 `LIMA_CXX_TRUSTED_BUILD_CONTEXT_GENERATION=true`
   （部署环境变量；分析请求、仓库内容与模型输出都无法设置或影响它）。
3. 如需自动选择 CMake adapter，设 `LIMA_CXX_AUTO_CMAKE=true`（仅是 adapter
   选择器，本身不构成执行授权）；否则用管理员显式 argv
   `LIMA_CXX_BUILD_STEPS_JSON` / `LIMA_CXX_TEST_STEPS_JSON`。
4. 验证：`/health` 的 `trusted_build_context_generation_available` 为 true
   才表示门禁可用；默认 Compose 部署不会全部通过探针，需要专门加固部署。

注意：总门禁只影响"为快照生成构建上下文"这一步，沙箱五层锁不变；模型生成
的 PoC 与仓库代码同狱。

## 4. 离线依赖预处理流程（沙箱不开外网）

沙箱内无网络是设计约束（设计 §10.1）。依赖一律在沙箱外预处理：

1. **沙箱外 clone**：在宿主/构建机完成 `git clone`（含子模块
   `--recurse-submodules`）。
2. **拉依赖**：包管理器（vcpkg/conan/tpf/hpm 等）在宿主解析并下载全部三方
   依赖到仓库内的 vendor/依赖目录；交叉编译工具链按目标架构就位。
3. **打包导入目录**：把"源码 + 依赖闭包"整理为一棵只读导入树，放到
   `LIMA_REPOSITORY_IMPORT_ROOT` 下；剔除与检测无关的巨型目录（见 §5 的
   OpenHarmony 注意事项）。
4. **固定指纹灌入**：扫描引用 `local-import` 源类型；快照身份由内容哈希
   派生（`snapshot_hash`），同一棵导入树灌入得到同一指纹——分诊、事实、
   实验、报告与结果缓存（Task 9 的 `ResultCache`）都锚定这一指纹，重复
   运行命中缓存即跳过已完成的智能体/实验工作。
5. 之后平台的所有下载类来源（github 等）保持关闭，
   `LIMA_REPOSITORY_SCAN_SOURCES=local-import`。

## 5. OpenHarmony 专用注意事项

- **`*.inl` 已在白名单**：`.inl/.ipp/.tpp` 内联实现头在
  `lima/workspace.py` 与 `cxx_analyzer/snapshot.py` 两处镜像的白名单里
  （缺失会让 OH 的 cvfObject.inl 这类 TU 准备失败），无需部署侧处理。
- **Qt 依赖目录剔除**：OH 图形栈周边常带 Qt/第三方 SDK 目录，体积大且不进
  编译闭包；导入前从导入树剔除（或移到快照配额外的目录），否则会吃掉
  `LIMA_REPOSITORY_SCAN_MAX_FILES/MAX_TOTAL_BYTES` 配额并给事实提取带来
  噪声。
- OH 仓库通常整仓无法构建：按设计走依赖闭包抽取，不承诺整仓构建；对参与
  检测的子系统目录保持相对完整的 compile_commands.json（或开启 §3 门禁）。

## 6. 规模化设施（平台内置）

- **并行**：`run_platform_review(parallelism=N)` 让独立目标在受控线程内并
  行实验；结果恒按确定性 Scout 序聚合（并行只影响墙钟，不改输出序）。
  平台服务侧由 `LIMA_CXX_AGENT_PARALLELISM` 注入。
- **缓存**：`run_platform_review(cache=ResultCache(dir, ns))` 按快照指纹 +
  目标全字段 + 模式 + 对话轮数复用每目标完整结果；命中即零 LLM 调用、零
  沙箱实验。缓存损坏自愈（坏条目按未命中处理并删除）。
- **增量**：`lima.agent_scale.detect_changed_files` 提供两份
  `{path: sha256}` 清单的三方差异（新增/修改/删除），是"仅变更文件重跑"的
  数据基础；按文件粒度的自动增量重跑为接口预留（当前缓存键以整快照指纹为
  锚，任何文件变更都会换指纹全量重算——这是快照身份贯穿不变量的直接后果）。
