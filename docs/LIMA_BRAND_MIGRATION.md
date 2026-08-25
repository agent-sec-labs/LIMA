# 砺码 · LIMA 品牌与配置迁移

从 v1.6.0 开始，项目统一使用以下公开命名：

- 产品：砺码 · LIMA
- Python 包：`lima`
- Python 分发包：`lima-security-agent`
- Docker Compose 项目与服务：`lima`
- 镜像：`lima:local`
- PowerShell 入口：`scripts/lima.ps1`
- 环境变量：`LIMA_*`

## 旧配置兼容

已有 `.env` 不需要立即改写。运行时会把旧 `EVOAGENT_*` 变量映射到对应的
`LIMA_*` 配置；如果两个名称同时存在，以 `LIMA_*` 为准。兼容过程不会打印、
复制到日志或通过网页发送密钥值。

新配置和文档只使用 `LIMA_*`。建议在下一次主动轮换密钥时一并迁移变量名，
而不是为了改名覆盖当前可用的生产凭据。

## 数据与容器

Compose 服务、容器和镜像已改为 LIMA。PostgreSQL 与 Redis 继续挂载原有的
Docker 卷，数据库内部角色和数据库名暂时保持不变，从而避免破坏账号、任务、
反馈和评测历史。存储内部标识不属于公开 API，后续如需彻底迁移，应单独执行有
备份、可回滚的数据迁移，而不应在品牌替换时隐式完成。Compose 将它们显式视为
外部兼容卷，`scripts/lima.ps1 up` 会在全新环境自动创建，因此不会产生旧项目归属警告。
