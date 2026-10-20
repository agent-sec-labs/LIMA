# LIMA 容器完整构建配方

本目录是 LIMA 的 C/C++ **完整容器构建**配方入口。每个项目目录包含独立
`Dockerfile` 和 `full-build.json`：前者固化 Linux 工具链与依赖，后者声明从配置到
安装验证的命令。LIMA 执行已适配的配方，不自动猜测任意 C/C++ 仓库的依赖或构建系统。
完整使用说明见 [`docs/CONTAINER_BUILD_GUIDE.md`](../../docs/CONTAINER_BUILD_GUIDE.md)。

## 先决条件和项目入口

首次运行需要 Docker 的 Linux 容器引擎、Python 3.11 或更高版本、Git、网络访问和干净
的 Git 工作树。`--source` 必须为绝对路径，`--output` 必须是全新的空目录，且二者不能
互为父目录。

列出内置项目：

```powershell
python -m lima.container_build --list
```

构建 ResInsight：

```powershell
python -m lima.container_build --project resinsight --source 'D:\paper\油气数据\油气工业软件源码\ResInsight' --output 'D:\build-output\resinsight' --jobs 6
```

构建 opm-common：

```powershell
python -m lima.container_build --project opm-common --source 'D:\paper\油气数据\油气工业软件源码\opm-common' --output 'D:\build-output\opm-common' --jobs 6
```

`--project` 解析本目录中受维护的项目配方。为兼容已有自动化，`--recipe` 仍接受经审阅
的自定义 `full-build.json`，但它不是新项目的推荐导航方式：

```powershell
python -m lima.container_build --recipe 'D:\recipes\my-project\full-build.json' --source 'D:\src\my-project' --output 'D:\build-output\my-project' --jobs 6
```

旧专用脚本和 `Dockerfile.full-build` 仅为历史兼容保留。新的完整构建使用项目目录中的
`Dockerfile`。

## 执行边界、阶段和结果

原始源码仅以只读方式挂载为 `/input`。执行器把固定 Git 提交复制到 `/work/src`，在
`/work/build` 配置和编译、在 `/work/install` 安装；`/output` 保存宿主可见日志与结果。
它不会在原始仓库内生成构建文件。

```text
prepare → setup → configure → build → test → install → verify → 核验并导出
```

`prepare` 固定提交并递归初始化子模块；可选 `setup` 在配置前运行项目所需的初始化。
任一命令失败都会停止后续阶段。导出前，执行器核验安装清单、编译数据库与测试报告。
典型输出为 `invocation.json`、`build-result.json`、`logs/`、`compile_commands.json`、
`install_manifest.txt`、JUnit 报告和安装归档。

`compile_commands.json` 是完整构建自动导出的产物，不是用户要手写的输入。它保留容器
路径；构建成功也不会自动附加到 LIMA 前端分析任务。

测试报告默认写到 `/output/ctest-results.xml`。有多个测试命令或报告时，配方以
`test_reports` 列出相对 `/output` 的 JUnit XML 路径；执行器汇总各报告，并把上游
disabled 测试与实际失败、错误分开记录。空测试集、失败或错误不能作为成功。

## `full-build.json` 协议

必填字段为 `schema_version`、`name`、`image`、`configure`、`build`、`test`、`install`。
所有命令字段都是非空 argv 列表的非空列表，不经 shell 拼接；`{jobs}` 替换为 `--jobs`
的值。

可选字段为：

| 字段 | 含义 |
| --- | --- |
| `setup` | `prepare` 后、`configure` 前执行的 argv，可用于依赖初始化 |
| `environment` | 环境变量映射；值可包含 `{jobs}` |
| `verify` | 安装后的冒烟验证 argv |
| `test_reports` | 相对 `/output` 的 JUnit 报告路径列表；默认 `ctest-results.xml` |

```json
{
  "schema_version": 1,
  "name": "example-full-build-v1",
  "image": "lima-builder-example:local",
  "setup": [["git", "-C", "/work/src", "submodule", "update", "--init"]],
  "environment": {"CMAKE_BUILD_PARALLEL_LEVEL": "{jobs}"},
  "configure": [["cmake", "-S", "/work/src", "-B", "/work/build", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", "-DCMAKE_INSTALL_PREFIX=/work/install"]],
  "build": [["cmake", "--build", "/work/build", "--parallel", "{jobs}"]],
  "test": [["ctest", "--test-dir", "/work/build", "--output-junit", "/output/ctest-results.xml"]],
  "install": [["cmake", "--install", "/work/build"]],
  "verify": [["/work/install/bin/example", "--version"]]
}
```

配方与 Dockerfile 是受信任的本地构建指令，运行前应审阅。通用入口面向
CMake/CTest/GoogleTest 加安装清单；其他构建系统或外部依赖需由人或 Codex 写出项目
配方，再由 LIMA 运行。

## 缓存复用

默认使用新 Docker 卷。只有同时给出保存下来的 `--volume <name>` 和
`--skip-image-build` 时才尝试复用：

```powershell
python -m lima.container_build --project opm-common --source 'D:\paper\油气数据\油气工业软件源码\opm-common' --output 'D:\build-output\opm-common-retry' --jobs 6 --volume lima-build-example --skip-image-build
```

复用要求源码提交、配方哈希、镜像 ID 完全一致，且卷内检出必须干净；不满足时请新建卷。
不要承诺 ResInsight 的缓存可安全复用：其测试会生成 ignored 文件，可能导致复用校验拒绝
该工作区。

## 历史：configure-only 分析上下文协议

`recipe.yaml` 是另一个冻结的 configure-only 分析上下文导出协议。它只声明如何生成
一次编译上下文包，不执行完整的 build、test、install，因此不是本页完整构建入口。其
目录形式为：

```text
deploy/build-recipes/<name>/
    Dockerfile
    recipe.yaml
```

schema v1 字段如下：

| 字段 | 含义与约束 |
| --- | --- |
| `schema_version` | 必须为 `1` |
| `name` | 非空配方身份；写入清单 `created_by` |
| `image` | 非空构建镜像引用 |
| `repository` | 非空仓库标识；写入清单 `repository` |
| `source_mount` | 源码挂载点，必须是绝对容器路径 |
| `configure` | 在 `source_mount` 运行的非空 argv 列表 |
| `compdb_path` | 相对源码根的安全路径，不能绝对或含 `..` |
| `generated_globs` | 可选相对生成头文件 glob |
| `include_roots` | 可选 `{container: <绝对路径>, package: <名称>}` 列表 |

解析会拒绝未知键、重复 YAML 键、不安全路径、保留的 `package` 名称
（`generated`、`compile_commands.json`、`context_manifest.json`）、嵌套或重复包根，
以及位于 `source_mount` 内的 include root。configure-only 命令通过
`-DCMAKE_EXPORT_COMPILE_COMMANDS=ON` 导出编译数据库，协议中没有 `--build`。

`include_roots.container` 是镜像内绝对 include 根，例如 Debian amd64 的
`/usr/include/x86_64-linux-gnu/qt5`；`package` 是导出包中的相对根，通常为
`headers/<library>`。收集器按实际引用的 include 目录复制整个子树并改写编译参数，
避免遗漏传递头文件；请勿使用 `/usr/include` 这类过宽根。未覆盖的绝对 include 路径会
保留原样，分析端会将相关翻译单元标记为 unresolved。
