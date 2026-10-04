# OpenHarmony pilot 案例目录

本目录存放 OpenHarmony 双版本验证 pilot 的冻结案例合同（`schema.json`）、
唯一真实案例（`pilot_case.json`，经资格审查后冻结）与准入规则。

## 候选准入门槛（全部满足才可冻结为 pilot）

1. 官方或项目维护者公开通告（OpenHarmony 安全公告、上游项目 GHSA/CVE 记录），
   有可引用 URL。
2. CWE 精确为 CWE-416（释放后使用）。
3. 目标为 C/C++ 原生代码，位于公开 OpenHarmony 仓库（自研子系统或
   third_party 组件均可；上游通告 + OH 镜像内修复 commit 也满足）。
4. 修复 commit 可定位（40 位 SHA 经 GitHub 镜像 API 或 gitee patch 核实）；
   脆弱版本 = 修复 commit 的 parent。
5. 不需要设备/内核/硬件，进程内 harness 可触发。
6. **编译可行性（容器实测标准）**：目标 TU 的 `#include` 闭包落在组件单仓内，
   或差一两个薄依赖头（可由 `_overlay/` 降级头替代：日志类 no-op 宏化、
   工具库类上游原版头）；构建宏（如 `-DENABLE_USER_LOG`）允许写进 compdb。
7. **链接自包含（容器实测标准，dsoftbus 教训）**：目标 TU 编译产物
   （`clang++-14 -fsanitize=address`）的未定义符号 ⊆ libc/libc++ 标准库；
   平台实验的链接集固定为"目标文件 + PoC 驱动"，不允许依赖兄弟源文件。
8. **C++ 模式可编译**：Sidecar 的 repro 用 `clang++-14` 把 `.c` 当 C++ 编，
   含 void* 隐式转换等 C 习惯写法的目标直接出局。
9. 非普通功能 bug、非无安全价值 DoS。
10. 许可证可记录。

任何一条不满足的候选记入下方 rejection ledger，禁止用合成样本顶替。

## Rejection ledger（按时间追加，不删改）

| 日期 | 候选 | 拒绝原因 |
|---|---|---|
| 2026-10-04 | storage_service CVE-2026-28733 | TU 闭包 4 个跨仓头，含 IPC 基类 `iremote_stub.h`（结构性无解） |
| 2026-10-04 | dsoftbus CVE-2025-23409/20081/20091 | 编译可过（overlay 三件头+`-DENABLE_USER_LOG`），但 `nm -u` 30+ 非 libc 未定义符号（NSTACKX_*/DiscCoap_*/SoftBus_*/cJSON_*/securec），需 20+ 兄弟源文件，链接非自包含 |
| 2026-10-04 | msdp_device_status CVE-2024-27217 | TU 闭包 25+ 跨仓框架头（iremote_*/refbase/singleton/event_handler/pixel_map 等） |
| 2026-10-02 | 内核系 7 个 CVE | 内核目标，门槛 5 |
| 2026-10-02 | multimedia_*/bluetooth 共 5 个 CVE | 纯崩溃 DoS，无安全价值叙述 |
| 2026-10-02 | jerryscript CVE-2024-23808/28951 | OH 仓库无可定位修复 commit |

完整调研记录（含每个候选的证据链接）见
`D:\Projects\LIMA\.zcode\reports\2026-10-02-openharmony-cwe416-candidates.md`
（本地工作档案）。

## 源码预置方法（管理员，沙箱外）

1. vulnerable checkout：组件仓库**完整克隆**（必须能同时解析 manifest 的
   vulnerable/fixed 两个 commit；禁止 shallow clone），`git checkout --detach
   <vulnerable_sha>`。
2. fixed checkout：同一对象库再出一份工作树（或再次克隆），
   `git checkout --detach <fixed_sha>`。
3. 案例声明 `dependency_overlay` 时：两个 checkout 根下放置**字节一致**的
   `_overlay/`，文件清单与 SHA-256 与 manifest 逐一对应，不多不少。
4. 两个 checkout 根各生成一份可信 `compile_commands.json`（构建上下文的
   编译命令来自组件真实 GN/CMake 构建，`-I` 只允许仓内目录与 `_overlay/`）。
5. 通过 repository import root（如 `D:\OpenHarmonyPilot`）暴露给宿主与
   Sidecar，挂载路径两端一致。

## 披露边界

- 案例经过"facts 链可达 + 链接自包含"筛选，**不能**从 pilot 结果推导全仓
  检测率、漏报率或无偏基准。
- pilot 不把已公开 CVE 计为新发现；报告的"影响版本"分"本地实际验证的
  commit"与"公开通告声称的版本"两类陈述。
- `dependency_overlay` 是环境依赖的降级替身（digest 钉扎、双 checkout 字节
  一致、零仓外链接符号），不是目标代码的一部分；任何越界即判 inconclusive。

## 当前状态

- 合同：`openharmony-validation-v1` 已冻结（`schema.json` +
  `lima/openharmony_validation.py`，二者字段/枚举由
  `tests/test_openharmony_validation.py` 强制一致）。
- pilot 案例：自研组件方向已全部淘汰（见 ledger），third_party 自包含组件
  方向资格审查进行中，冻结后回填本节。
