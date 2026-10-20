# opm-common 通过 LIMA 自动化构建验收

现行推荐命令使用 `python -m lima.container_build --project opm-common`。本页的 `--recipe` 命令继续兼容；统一流程及所需文件见 [容器完整构建指南](CONTAINER_BUILD_GUIDE.md)。

## 结果

已通过 LIMA 命令行入口完成真实 Docker 配置、编译、链接、测试、安装和产物导出；随后用补强后的同一入口增量复跑通过。
这次未调用模型服务，也未推送 GitHub 或镜像仓库。

| 检查 | 实际结果 |
| --- | --- |
| 原始仓库 | `D:\paper\油气数据\油气工业软件源码\opm-common` |
| 固定源码提交 | `27c82ec9e30cc264038996c57e3bb0f9ddd43716` |
| 源码版本 | `2026.04-pre`，来自 `dune.module` |
| 环境 | Debian 13 / GCC 14.2.0 / CMake 3.31.6 / Ninja / Release / C++17 |
| 构建镜像 | `lima-builder-opm-common:local` |
| 实际镜像 ID | `sha256:a67c8ea7d87da534c8f4069a1656248da539c8ad1d418d9a782c5824283a0e21` |
| 首次完整构建 | 1116 个 Ninja 步骤，编译阶段约 342 秒，退出码 0 |
| 实际 CTest | 213 项全部通过；JUnit 中 failures=0、errors=0、skipped=0 |
| 安装校验 | 922 个清单文件均存在且处于安装前缀内 |
| 归档清单复核 | 规范化路径并去重后 919 个文件，与归档文件集合完全一致，无额外或缺失文件 |
| 关键产物 | `lib/libopmcommon.a`、OPM 头文件、CMake package metadata、compareECL 等工具 |
| 编译数据库 | 747 条记录 |
| 安装工具冒烟 | 在无网络容器中运行 `compareECL -h`，退出码 0 |
| LIMA 执行器测试 | 新执行器与既有 configure-only 配方测试共 19 项通过；Ruff 检查通过 |
| 原仓库保护 | 容器只读挂载 `/input`，在专用卷中 clone 固定提交；构建后原仓库 `git status --short` 为空 |

## LIMA 入口与复跑命令

入口：`lima/container_build.py`，使用配方 `deploy/build-recipes/opm-common/full-build.json`。
配方目录 Dockerfile 会由 LIMA 自动构建，不需要人工在容器中逐条执行编译命令。
从 `D:\Projects\LIMA` 执行，输出目录必须不存在或为空：

```powershell
python -m lima.container_build --source 'D:\paper\油气数据\油气工业软件源码\opm-common' --recipe deploy/build-recipes/opm-common/full-build.json --output output/opm-common-build-next --jobs 6
```

本次专用卷为 `lima-build-0abc1b45bdbd`。固定提交、配方哈希和镜像 ID 都一致时，可复用增量构建目录：

```powershell
python -m lima.container_build --source 'D:\paper\油气数据\油气工业软件源码\opm-common' --recipe deploy/build-recipes/opm-common/full-build.json --output output/opm-common-build-next --jobs 6 --volume lima-build-0abc1b45bdbd --skip-image-build
```

源码副本一旦出现 tracked、untracked、ignored 或子模块改动，入口会拒绝复用，要求使用新卷；不会静默删除这些内容。
任一步骤失败都会中止后续步骤，状态文件记录退出码；中断或外部容器失败也会写入终态。
导出完成前状态保持 `exporting`，最终只有在安装清单和测试报告校验通过后写入 `completed`。

## 证据与产物

首次完整构建证据：`output/opm-common-build-2026-10-19/`。
最终新版入口验收：`output/opm-common-build-2026-10-19-verified/`。

- `invocation.json`：原始目录、提交、镜像 ID、配方内容/哈希、执行器哈希、容器和卷身份。
- `build-result.json`：每阶段 argv、耗时、退出码、测试统计、安装数量和产物 SHA256。
- `logs/`：各阶段完整日志。
- `ctest-results.xml` / `Testing/Temporary/LastTest.log`：实际运行的测试证据。
- `install_manifest.txt`：安装清单。
- `compile_commands.json`：容器中真实构建产生的原始编译数据库。
- `install-linux-x64.tar.gz`：Linux x86_64 安装目录压缩包，顶层目录为 `install/`。

最终安装包 SHA256：`9f4cc386895819bfee03f4a0f0256acf08b4f4119b93e5f6bddd7777f4581a88`。
产物需要兼容的 Linux 运行环境，不能直接作为 Windows 可执行程序使用。

## 验收边界

本次保留 Eclipse 输入、输出和 mocksim；关闭可选 MPI、DUNE 和 Python 绑定/安装。
没有引入外部 `opm-tests` 仓库，因此依赖外部 Norne、SPE 等数据的集成测试未被注册，不计入 213 项通过结果。
这不代表那些可选配置和外部数据场景已经验收。

本次新增的是 LIMA 的 CMake/CTest 完整构建命令行入口；原有 `lima.build_recipe` 的 configure-only 分析上下文协议保持原样。
当前入口需要仓库专用依赖镜像和配方，不会自动推断任意 C/C++ 仓库的依赖。
尚未增加前端“一键构建”按钮，也未把原始编译数据库自动转换、附加到前端分析任务。
