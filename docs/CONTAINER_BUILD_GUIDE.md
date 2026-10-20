# LIMA 容器完整构建指南

LIMA 用项目专用的 Dockerfile 与 `full-build.json` 在 Linux 容器中完成 C/C++ 仓库的
配置、编译、测试、安装和产物导出，并记录版本与结果以供追溯。它不负责
自动识别任意仓库的依赖；新项目需要先由人或 Codex 编写和审阅配方。

配方主入口在 [`deploy/build-recipes/README.md`](../deploy/build-recipes/README.md)。

## 开始前

在 Windows/PowerShell 上运行前，请确认：

- Docker Desktop 的 Linux 容器引擎可用；
- Python 版本为 3.11 或更高，且当前目录可导入 LIMA；
- Git 可用，目标源码是带 `.git` 元数据的干净工作树；
- 第一次构建可以访问网络，以拉取基础镜像、系统包和项目声明的依赖；
- `--source` 使用绝对路径，`--output` 指向全新的空目录，且两者没有包含关系。

构建过程不会把编译产物写回 `--source`。源码有未提交变更时，入口会拒绝执行，以免
固定提交的构建与用户工作树混淆。

## 使用受维护的项目配方

先查看可用项目：

```powershell
python -m lima.container_build --list
```

示例中的源路径和输出路径应替换为本机实际绝对路径：

```powershell
python -m lima.container_build --project resinsight --source 'D:\paper\油气数据\油气工业软件源码\ResInsight' --output 'D:\build-output\resinsight' --jobs 6

python -m lima.container_build --project opm-common --source 'D:\paper\油气数据\油气工业软件源码\opm-common' --output 'D:\build-output\opm-common' --jobs 6
```

`--project` 会选择 `deploy/build-recipes/<project>/` 下的 Dockerfile 和完整构建配方。
`--jobs` 控制并行度，配方中的 `{jobs}` 会替换为该数值。

也可为兼容已有自动化直接指定经审阅的自定义配方：

```powershell
python -m lima.container_build --recipe 'D:\recipes\my-project\full-build.json' --source 'D:\src\my-project' --output 'D:\build-output\my-project' --jobs 6
```

## 容器中的执行流程

LIMA 只读挂载原始 Git 仓库为 `/input`，在 Docker 卷内创建工作副本并固定调用开始时的
Git 提交。容器路径如下：

| 路径 | 用途 |
| --- | --- |
| `/input` | 原始仓库，只读 |
| `/work/src` | 工作副本与子模块 |
| `/work/build` | 构建目录 |
| `/work/install` | 安装前缀 |
| `/output` | 宿主机可见的日志与导出结果 |

```text
prepare → setup → configure → build → test → install → verify → 核验并导出
```

`prepare` 检出固定提交并递归初始化子模块；`setup` 是配置前可选的依赖初始化阶段。
任何阶段或命令失败都会停止后续工作，已有结果与日志保留在输出目录供诊断。旧专用脚本
和 `Dockerfile.full-build` 仅为历史兼容；标准完整构建使用项目目录里的 Dockerfile。

## 配方和验收

`full-build.json` 的必填字段为：

```text
schema_version, name, image, configure, build, test, install
```

命令均写成 argv 数组，不经过 shell 拼接。可选 `setup`、`verify` 同样为 argv 数组列表；
`environment` 是环境变量映射（值可含 `{jobs}`）；`test_reports` 是相对于 `/output` 的
JUnit XML 路径列表，省略时默认 `ctest-results.xml`。

对于 CMake/CTest/GoogleTest 项目，完整构建应产生非空安装清单、有效的
`compile_commands.json` 和 JUnit 测试报告。报告汇总分别记录通过、失败、错误、跳过与
disabled；disabled 是上游未启用项，不能混同为失败或已执行通过。

输出目录通常包含：

- `invocation.json`：源码提交、镜像身份、配方摘要、作业数和运行身份；
- `build-result.json`：阶段、命令、耗时、退出状态、测试汇总及导出核验；
- `logs/`：每个命令的标准输出和错误输出；
- `compile_commands.json`、`install_manifest.txt`、安装归档和 JUnit 测试报告。

`compile_commands.json` 是构建自动生成的原始编译数据库，不是输入文件，路径通常指向
容器内目录。完整构建不会自动向 LIMA 前端创建分析任务。运行时验收应检查
`build-result.json`、阶段日志、测试报告和安装结果；自动化单元或契约测试不能替代指定
提交、镜像和配方的真实 Docker 构建验收。

## 缓存工作区

默认每次使用新 Docker 卷。仅在需要重用工作区时，同时给出已记录的卷名和
`--skip-image-build`：

```powershell
python -m lima.container_build --project opm-common --source 'D:\paper\油气数据\油气工业软件源码\opm-common' --output 'D:\build-output\opm-common-retry' --jobs 6 --volume lima-build-example --skip-image-build
```

缓存复用要求源码提交、配方哈希和镜像 ID 一致，且卷内源码及子模块保持干净。校验不
通过时使用新卷，不要绕过记录。ResInsight 的测试会生成 ignored 文件，因此不保证其
缓存工作区可安全复用。

## 范围

入口当前面向 CMake/CTest/GoogleTest 与安装清单的通用模式；每个项目仍需要自己的
Dockerfile 和配方。它不承诺自动解决任意 C++ 项目的依赖、不提供前端构建按钮，也不把
构建导出自动转换成分析上下文包。

旧 `recipe.yaml` 是独立的 configure-only 分析上下文协议，字段约束与 include-root
导出细节见 [`deploy/build-recipes/README.md`](../deploy/build-recipes/README.md) 的
“历史：configure-only 分析上下文协议”。
