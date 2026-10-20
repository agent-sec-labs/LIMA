# ResInsight Docker 实际构建记录

本页记录早期专用脚本构建。现行入口已统一为 `python -m lima.container_build --project resinsight`；请优先阅读 [统一构建指南](CONTAINER_BUILD_GUIDE.md)。旧脚本及下文命令仅用于历史追溯。

## 范围与当前状态

目标仓库：`D:\paper\油气数据\油气工业软件源码\ResInsight`。
源码提交：`78672054687a538a89f9453d8382f33023ea98f6`。

状态：完整 configure → compile → link → install 通过，已安装程序的版本启动、动态库检查和已启用测试通过。

产物：`output/resinsight-build-2026-10-19/resinsight-linux-x64.tar.gz`，为 Linux x86_64 安装目录压缩包，不能直接作为 Windows 程序运行；需使用本次容器镜像或提供兼容的 Qt6/Linux 运行环境。
编译数据库：`output/resinsight-build-2026-10-19/compile_commands.json`，内部路径指向本次容器的 `/work/src`、`/work/build`。

本次证明了该固定提交在指定容器配置下可以实际构建。尚未验收完整 GUI 操作、真实油藏项目导入、3D 渲染、LIMA 前端任务触发构建，以及下列关闭的可选功能。

原目录以只读方式挂载到 `/input`。独立副本、构建目录、安装目录和依赖缓存位于专用 Docker 卷中，不写入原仓库。

## 执行环境

- 镜像：`lima-builder-resinsight:full-build`
- 镜像 ID：`sha256:c4bcc394941d9d5569892426c6eb3b3a6ec3b1bf65dc3068f1f3b115fe642221`
- Debian 13 / GCC 14.2 / CMake 3.31.6 / Ninja 1.12.1 / Qt 6.8.2。
- 容器：`lima-resinsight-full-build`，内存上限 10 GiB，CPU 上限 6，构建并行度先 4 后 6；切换时复用 Ninja 已完成产物。
- 持久卷：`lima-resinsight-full-build-20261019`，挂载 `/work`。
- 入口脚本：`scripts/build_resinsight_in_container.py`。
- 依赖子模块按目标提交固定版本递归初始化；版本记录见 `output/resinsight-build-2026-10-19/submodule-revisions.log`。

## 构建配置

Release / Ninja / C++23 / vcpkg `x64-linux-release`。
关闭可选 OpenVDS、ODB 下载、应用 gRPC、HDF5、Octave 插件和文档生成。
关闭 unity build、预编译头及 warnings-as-errors，启用应用单元测试。
这次构建不能代表上述关闭的可选功能已经验收。

## 观察与重跑

```powershell
docker logs --tail 10 lima-resinsight-full-build
docker exec lima-resinsight-full-build cat /work/build-result.json
docker exec lima-resinsight-full-build tail -n 20 /work/logs/configure.log
docker exec lima-resinsight-full-build tail -n 20 /work/logs/build.log
```

容器退出后可用 `docker start lima-resinsight-full-build` 重跑入口；缓存和构建目录保留。
重跑会覆盖同名步骤日志，诊断前应先导出日志。
构建入口执行 configure、build、install、应用与依赖测试、版本启动、动态库检查；失败时记录错误和退出码。

首次创建容器的完整命令（在 `D:\Projects\LIMA` 执行；同名容器已存在时用上面的重跑命令）：

```powershell
docker build -t lima-builder-resinsight:latest deploy/build-recipes/resinsight
docker build -f deploy/build-recipes/resinsight/Dockerfile.full-build -t lima-builder-resinsight:full-build deploy/build-recipes/resinsight
docker run -d --name lima-resinsight-full-build --init --cap-drop ALL --security-opt no-new-privileges:true --memory 10g --cpus 6 --pids-limit 1024 --mount 'type=bind,source=D:\paper\油气数据\油气工业软件源码\ResInsight,target=/input,readonly' --mount 'type=volume,source=lima-resinsight-full-build-20261019,target=/work' --mount 'type=bind,source=D:\Projects\LIMA\scripts\build_resinsight_in_container.py,target=/control/build.py,readonly' lima-builder-resinsight:full-build python3 /control/build.py --revision 78672054687a538a89f9453d8382f33023ea98f6 --jobs 6
```

首次依赖下载需要访问公开源码站点。构建完成后的独立验证已在 `--network none` 容器中执行。

## 验证结果

| 检查 | 结果 |
| --- | --- |
| 配置、编译、链接、安装 | 各步骤退出码 0 |
| `ResInsight --console --version` | `2026.09.1-dev.01` / `SHA 786720546`，退出码 0 |
| `ldd` | 无 `not found` |
| 应用单元测试 | 1060 项通过，35 项上游禁用测试未运行 |
| ROFF 测试 | 45 项通过 |
| 回归分析测试 | 8 项通过 |
| OPM 解析测试 | 2 项通过 |
| OpenZGY 测试 | 24 项通过 |
| 原始目标仓库状态 | `git status --short` 输出为空 |

共 1139 项已启用测试通过。顶层 `ctest --test-dir /work/build` 枚举为 0；应用测试实际注册在 `ApplicationLibCode/UnitTests`，入口已改为在该目录运行 CTest，未将顶层空测试视作通过证据。

详细日志：`output/resinsight-build-2026-10-19/logs/`；独立验证结果：`output/resinsight-build-2026-10-19/verification/results.json` 和 `ResInsight-tests-full.log`。

已安装二进制 SHA256：`bb2e283bd44df93f8f9043d2047cb0f377e9e48ddf502b073d3516cebfae0b77`。
安装包 SHA256：`517e4a8dc34bac9ee9886b1375a8321f146e289dc86491d2b6ddf558794be0fc`。

运行环境需设置 `QT_PLUGIN_PATH=/usr/lib/x86_64-linux-gnu/qt6/plugins`；无界面测试使用 `QT_QPA_PLATFORM=offscreen`，并设置 `LANG=C.UTF-8`。原因是安装产物的 `qt.conf` 将 Qt 前缀设到安装目录，默认未发现系统 TLS 插件。插件实际已安装，无需修改源码；设置搜索路径后版本启动日志无 TLS 提示。已将这些设置写入构建入口。

最初的失败是 vcpkg 下载目录尚未创建，已在入口中补齐目录创建后重跑。
首次配置在 Advanced Docking 的 `Qt6::GuiPrivate` 头文件目录检查失败，已在完整构建镜像中补装 `qt6-base-private-dev`，重跑配置通过。
首次配置日志保留在 `output/resinsight-build-2026-10-19/configure-attempt-1.log`。
旧构建镜像配方已同步到 Qt6；分析上下文 `recipe.yaml` 仍仅负责 configure，不等同于完整构建工作流。
