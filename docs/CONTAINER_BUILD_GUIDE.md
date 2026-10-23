# LIMA 容器完整构建指南

`python -m lima.container_build` 在 Linux Docker 容器中按配方执行配置、编译、测试、安装和产物核验。**仓库专用的 Dockerfile 与 `full-build.json` 由使用者在本机维护，不随 LIMA 源码发布。** 入口不会自动推断依赖、生成配方或向前端创建分析任务。

## 准备本地配方

在 LIMA 仓库之外创建一个目录，例如 `D:\local-build-recipes\target-a\`：

```text
D:\local-build-recipes\target-a\
  Dockerfile
  full-build.json
```

Dockerfile 应提供 Linux 上的 Git、Python 3、编译器、构建工具和目标仓库需要的依赖。LIMA 从该目录构建镜像；构建脚本与测试来自目标仓库，执行前应审阅其权限和依赖来源。

`full-build.json` 的必填字段是 `schema_version`（当前为 `1`）、`name`、`image`、`configure`、`build`、`test` 和 `install`。各阶段是 argv 数组列表；可选 `setup`、`verify`、`environment` 和相对于输出目录的 `test_reports`。以下仅展示结构，具体命令和依赖须按目标仓库填写：

```json
{
  "schema_version": 1,
  "name": "local-target-a",
  "image": "local-target-a-builder:latest",
  "configure": [["cmake", "-S", "/work/src", "-B", "/work/build", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", "-DCMAKE_INSTALL_PREFIX=/work/install"]],
  "build": [["cmake", "--build", "/work/build", "--parallel", "{jobs}"]],
  "test": [["ctest", "--test-dir", "/work/build", "--no-tests=error", "--output-junit", "/output/ctest-results.xml"]],
  "install": [["cmake", "--install", "/work/build"]]
}
```

该示例只适用于确实支持这些 CMake/CTest 命令、会生成安装清单和非空测试报告的项目。配方里的命令由本机 Docker 执行；argv 格式避免 shell 拼接，但不等于命令已经安全，须先审阅本地配方。

## 执行

使用带 `.git` 元数据且没有未提交变更的目标源码。`--source`、`--recipe` 和 `--output` 都使用绝对路径，输出目录须为空且不能包含源码目录：

```powershell
python -m lima.container_build --source 'D:\src\target-a' --recipe 'D:\local-build-recipes\target-a\full-build.json' --output 'D:\build-output\target-a-run-1' --jobs 6
```

入口固定源码提交，只读挂载原仓库为 `/input`，在 Docker 卷的 `/work/src` 创建工作副本。阶段按 `prepare → setup → configure → build → test → install → verify` 执行；任一阶段失败即停止。运行日志和 `build-result.json` 写入宿主输出目录。容器结束后删除，构建卷保留，卷名记在 `invocation.json`。

成功还要求非空 `compile_commands.json`、安装清单及通过的 JUnit 报告。报告中出现 `<failure>`、`<error>` 或父套件的失败计数都会使构建失败。`test_reports` 路径不能占用 `compile_commands.json`、`build-result.json` 等构建产物名称，也不能放在 `logs/` 或 `Testing/` 下。输出包含原始编译数据库、安装归档、测试报告和文件哈希。`build-result.json` 的 `status=completed` 才表示此构建任务完成；它不证明漏洞存在，也不表示编译数据库已接入 LIMA 的审计任务。

需要复用卷时，使用上次 `invocation.json` 的卷名，并保持源码提交、配方内容和镜像完全一致：

```powershell
python -m lima.container_build --source 'D:\src\target-a' --recipe 'D:\local-build-recipes\target-a\full-build.json' --output 'D:\build-output\target-a-run-2' --jobs 6 --volume lima-build-example --skip-image-build
```

复用前会检查卷中的源码是否干净，包括 Git `skip-worktree`、`assume-unchanged` 标志；失败时改用新卷。按 Ctrl+C 中断时，入口会停止容器并记录 `interrupted`；若停止和强制终止都无法确认，则记录失败及取消标记，不能把之后的 worker 结果视为完成。`--skip-image-build` 只适用于已经审阅并确认标识的本地镜像。容器构建可能需要拉取镜像或安装依赖，配方的网络和资源使用须按部署环境控制。

现有 `recipe.yaml` 是另一种只导出分析上下文的 configure-only 协议，见 [配方协议说明](../deploy/build-recipes/README.md)。完整构建的 `full-build.json` 与它不共用 schema，也不会自动转换成下游分析上下文包。
