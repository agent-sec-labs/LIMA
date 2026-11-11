# Build Agent 宿主部署指南

Build Agent 从运行 LIMA 的进程调用 Docker，创建禁网、资源受限的临时构建容器。它是 C/C++ 编译上下文的显式 opt-in 功能，默认关闭。

标准 `docker compose up` 的 `lima` 服务使用只读根文件系统，未安装 Docker CLI，也没有 Docker daemon 通道。因此它可以运行普通 LIMA 服务，但**不能启用 Build Agent**。不要为此向 Web 应用容器挂载宿主 Docker socket；这会把宿主 Docker 控制权交给处理审计任务的应用进程。

## 1. 准备运行 Build Agent 的宿主

在专用 Windows 主机、Linux worker 或受隔离的执行节点安装并启动 Docker Desktop / Docker Engine。运行 LIMA 的账户必须能执行 Docker 命令：

```powershell
docker info --format '{{.ServerVersion}}'
```

该命令必须在启动 LIMA **同一账户、同一执行环境**下成功。服务会在每次构建前以最多 5 秒的 `docker info` 预检确认 daemon；失败会记录 `docker-cli-unavailable` 或 `docker-daemon-unavailable`，不会尝试构建。

## 2. 构建并批准 CMake 构建镜像

Build Agent 当前只支持受限的 `cmake-linux` configure 路径。镜像应由管理员在受控位置维护，至少提供 Linux C/C++ 编译器、CMake 和 `python3`；目标仓库需要的依赖必须在镜像内经审阅安装。LIMA 仓库不发布通用构建镜像，也不会替任务动态构建镜像。

在镜像目录创建并审阅 Dockerfile 后，构建固定标签的本地镜像，例如：

```powershell
docker build -t lima-builder-cmake:local D:\lima-build-images\cmake
docker image inspect lima-builder-cmake:local
```

将确认后的镜像名写入 `LIMA_BUILD_AGENT_IMAGE`。生产环境建议使用受信镜像仓库和不可变 digest，而不是可变标签。

## 3. 启动 LIMA 的宿主进程并配置路径

为运行 LIMA 的宿主进程设置配置。产物目录必须是该账户实际可创建临时文件的本地或受控挂载目录；服务不会仅凭权限位猜测可写性。

```powershell
$env:LIMA_BUILD_AGENT_MODE = 'auto'
$env:LIMA_BUILD_AGENT_IMAGE = 'lima-builder-cmake:local'
$env:LIMA_BUILD_ARTIFACTS_ROOT = 'D:\lima-data\build-artifacts'
$env:LIMA_BUILD_CONCURRENCY = '1'
```

先完成第 4 节的 Sidecar、路径和模型配置，再在仓库根目录用同一账户安装依赖并启动宿主进程。环境变量必须在启动前设置；`python -m lima` 是实际服务入口：

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m lima
```

若需要从源码显示管理台，还需预先构建前端：`npm --prefix frontend ci`，再运行 `npm --prefix frontend run build`。若使用 `scripts\lima.ps1 up`，那是标准 Compose 启动路径，不应用于启用了 Build Agent 的服务进程。`LIMA_BUILD_ARTIFACTS_ROOT` 预检失败会报告 `build-artifacts-unwritable`。

`LIMA_BUILD_ARTIFACTS_RETENTION_DAYS` 由离线维护命令使用，不会在服务运行期间自动删除。

## 4. 启用分析 Sidecar

构建包要被 C/C++ 分析链实际消费，还需启动 Sidecar 并显式开启分析模式：

```powershell
docker compose --profile cxx up -d --build cxx-analyzer
$env:LIMA_CXX_MEMORY_MODE = 'required'
$env:LIMA_CXX_AGENT_MODE = 'auto'
```

Compose 内服务默认使用 `http://cxx-analyzer:8090`。该 Compose Sidecar 没有向宿主发布端口；若 LIMA 在宿主进程运行，应将 Sidecar 部署为宿主可访问的独立服务，或通过受控的部署覆盖显式发布端口，再把 `LIMA_CXX_ANALYZER_URL` 配置为实际可达地址。不要把容器内部服务名直接当作宿主 DNS 名称。

例如，在本机维护 `compose.host-sidecar.yml`，只向回环地址开放分析端口：

```yaml
services:
  cxx-analyzer:
    ports:
      - "127.0.0.1:18090:8090"
```

用 `docker compose -f docker-compose.yml -f compose.host-sidecar.yml --profile cxx up -d --build cxx-analyzer` 代替本节上面的默认启动命令，并在启动宿主 LIMA 前设置 `$env:LIMA_CXX_ANALYZER_URL = 'http://127.0.0.1:18090'`。宿主的 `LIMA_REPOSITORY_IMPORT_ROOT` 与 Compose 的 `LIMA_REPOSITORY_IMPORT_PATH` 必须指向同一份导入仓库内容；构建包按摘要注册，不能代替 Sidecar 对源快照的访问。其他来源的任务也必须先验证其快照在 Sidecar 中可达且指纹一致。

平台分析还需要可用模型配置：按部署实际设置 `LIMA_LLM_PROVIDER`、`LIMA_LLM_BASE_URL`、`LIMA_LLM_MODEL` 和 `LIMA_LLM_API_KEY`，或使用服务的模型配置入口。未配置模型、平台模式为 off 或上下文不可用时，不会显示“已消费”；required 构建模式会明确显示消费阻断。

## 5. 上线前验收

用一个正常 CMake 仓库和一个故意缺失目标的仓库分别运行 auto/required。确认任务记录中有镜像、包和相对证据引用；确认请求 TU 缺失不会显示构建成功；确认 facts 的 TU 消费回执，以及实际执行的 Specialist 计划和 repro 证据绑定同一制品摘要。未执行实验时不能声称已经复现。再覆盖 Docker daemon 停止、产物目录只读、Sidecar 重启和容量已满等故障场景。

Build Agent 的成功只证明受限范围内的构建上下文已验证。它不证明仓库没有漏洞，也不代表完整 Audit → Mining → Repair 平台闭环已经完成。

## 6. 离线清理构建产物

停止所有 LIMA worker 后，先执行 dry-run：

```powershell
python -m lima.build_artifact_cleanup
```

确认候选目录后，才执行删除：

```powershell
python -m lima.build_artifact_cleanup --apply --workers-stopped
```

`--workers-stopped` 是维护契约的显式确认；命令不会假装能够探测所有本机或分布式 worker。可用 `--root`、`--retention-days` 覆盖环境配置；`--db-path` 明确选择一个 SQLite 任务库，例如：

```powershell
python -m lima.build_artifact_cleanup --root 'D:\lima-data\build-artifacts' --db-path 'D:\lima-data\lima.db' --retention-days 30
```

只有直属任务目录同时满足以下条件才会成为候选：任务库明确记录终态 `SUCCESS`、`FAILED` 或 `CANCELLED`；任务 `updated_at` 与目录树（含嵌套文件）最新修改时间均已超过保留期；目录及其树中不存在符号链接或 Windows junction；解析后的路径仍直接位于产物根目录。活动、未知、已恢复、无法解析或带链接的目录只会在 dry-run 输出中标为跳过。命令在删除前重复检查路径边界和链接状态。
