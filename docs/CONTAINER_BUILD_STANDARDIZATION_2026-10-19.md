# 容器构建入口统一验收记录

本次将 ResInsight 和 opm-common 统一到 `python -m lima.container_build`。日常操作入口见 [构建指南](CONTAINER_BUILD_GUIDE.md)，配方目录见 `deploy/build-recipes/`。

## 变更

- 每个项目的完整构建固定使用 `Dockerfile + full-build.json`。
- `--list` 列出内置项目；`--project resinsight/opm-common` 选择配方，`--recipe` 保留自定义兼容。
- 统一执行 prepare → setup → configure → build → test → install → verify → 核验导出。
- 依赖初始化、环境变量、JUnit 报告位置和安装后检查均可由配方声明；不再向 ResInsight 专用脚本添加功能。
- ResInsight 的 canonical Dockerfile 现在包含完整构建依赖，不要求先另外构建基础镜像。
- 镜像构建失败、容器失败和中断均记录终态；测试报告分别汇总 passed、skipped、disabled，导出成功后才写 completed。
- `compile_commands.json` 是输出；旧 `recipe.yaml` 是独立的分析上下文导出协议，不承担完整构建。

## 实际复跑

两次运行均使用既有专用卷中的固定源码和编译产物做增量复跑。首次完整编译证据保留在先前项目验收记录中。
本轮重新构建了 ResInsight 的统一 Dockerfile，两个项目均通过新 `--project` 入口执行了完整阶段并重新生成测试报告和安装包。

| 项目 | ResInsight | opm-common |
| --- | --- | --- |
| 源码提交 | `78672054687a538a89f9453d8382f33023ea98f6` | `27c82ec9e30cc264038996c57e3bb0f9ddd43716` |
| 实际通过测试 | 1139 项 GoogleTest | 213 项 CTest |
| 失败 / 错误 | 0 / 0 | 0 / 0 |
| 上游 disabled | 35 项，未计为通过 | 0 |
| 安装清单核验 | 58 条 | 922 条 |
| 编译数据库 | 3349 条记录 | 747 条记录 |
| 额外验证 | 已安装程序版本启动、ldd 无缺失 | 安装及 JUnit 核验 |
| 最终输出目录 | `output/builds/resinsight-standard-resume-2026-10-19` | `output/builds/opm-common-standard-resume-2026-10-19` |

每个输出目录都有 `invocation.json`、`build-result.json`、阶段日志、安装清单、原始编译数据库、JUnit 报告和安装归档。
完整构建结果应以 status=completed、步骤退出码 0、实际测试统计和产物 SHA256 为准。

## 本轮异常及边界

此前 C 盘满导致 Docker 存储层 input/output error，相关失败输出保留在 `output/builds/*-standard-2026-10-19/`，未计为成功。用户释放空间后，本轮使用新的 `*-standard-resume-*` 输出目录复跑。

opm-common 的 `EclipseIO_LGR` 在本轮耗时约 185 秒后通过，显著慢于此前运行；两个子测试独立执行均较快。未修改源码、未跳过测试或缩短测试范围，原配方的 300 秒超时仍生效。

只读排查发现上游代码存在可解释该波动的未初始化读取：`tests/test_EclipseIO_LGR.cpp:940-944` 用 `EGrid` 打开 `.INIT`；`opm/io/eclipse/EGrid.hpp:89` 的 `nijk` 没有默认初始化，构造器只在读到 `GRIDHEAD` 时赋值，却在 `EGrid.cpp:146-148` 无条件使用 `nijk[2]` 循环。慢跑现场还观察到较大内存占用和换页。此处未实施补丁或做补丁前后对照，因此保留为上游风险，不能据此宣称测试运行稳定，也不能归因为 LIMA 执行器故障。

两个原始仓库仍只读使用；ResInsight 专用卷中由历史测试生成的一份 ignored 输出在复跑前备份移至 `/work/legacy-generated-test-output.GRDECL`，没有改动原始仓库。
本轮不覆盖 MPI、DUNE、Python 绑定、OpenVDS、ODB、HDF5、gRPC 等关闭的可选配置，也不覆盖外部油藏数据集与完整 GUI 操作。

当前为命令行构建能力，尚未加入前端按钮；新仓库仍需人工或 Codex 适配配方，LIMA 不自动推断依赖。
