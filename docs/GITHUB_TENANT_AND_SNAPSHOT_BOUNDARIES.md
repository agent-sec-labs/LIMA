# GitHub 租户凭据与扫描快照边界

GitHub App installation 的租户归属由部署人员配置，不由浏览器回调或租户管理员提交的数字 ID 决定。

## GitHub App 部署

在服务环境中配置 JSON 对象，例如：

```dotenv
LIMA_GITHUB_APP_ID=12345
LIMA_GITHUB_PRIVATE_KEY_PATH=/run/secrets/github-app.pem
LIMA_GITHUB_INSTALLATION_TENANTS={"111":"tenant-a","222":"tenant-b"}
```

映射应由有权管理部署与 GitHub App 的人员根据安装事实维护，不应开放给租户 API 修改。ID 必须是规范的正整数键；租户值必须与服务中的 tenant ID 一致。重复键、空租户和非法 ID 会导致配置校验失败。修改配置后重启服务，使所有 worker 使用相同映射。

各租户管理员随后通过 `POST /v1/github/installations` 登记自己的已批准 installation。相同租户重复登记可更新展示名；数据库原子拒绝将其他租户的已有安装改到当前租户。`account` 只是展示文本，不是所有权证明。迁移归属须由部署管理流程协调配置及数据库，不提供租户自行转移接口。

App 模式下，未知、未登记、缺失 installation 或显式租户不匹配的 webhook 会被拒绝，不再放入默认租户。任务准入时保存 `github_auth` 身份，取件、评论和修复使用该身份并重新核对当前配置与登记；fix 请求中的 installation 只能与任务身份一致，不能切换凭据。省略参数时仍使用任务的安装。

未配置 App 凭据时，原 PAT 模式只供默认租户使用；PAT 任务同样保存身份，不能通过省略参数将 App 任务改用全局 PAT。没有可信身份记录的历史任务不能直接发布修复，需要重新审计。已有 installation 数据库记录也不能替代部署映射的批准。

## 扫描快照

workspace 对实际读取字节执行文件上限检查；读取与盘点大小不一致、或后续读取与盘点 SHA-256 不一致时，抛出 `workspace snapshot drift`，不生成属于旧指纹的新结果。

scanner 在校验后把选定的有界内容物化为本次扫描专用临时副本。AST、SAST 及平台的本地文件读取使用同一份内容。原始 inventory、跳过原因、覆盖分母、指纹和报告仓库标识继续保留；这不会把有界扫描表示成全仓覆盖。CRLF 等原始字节不经过换行规范化。

本轮验证使用临时 SQLite、真实本机 HTTP/RBAC 和子进程/适配器测试，不需要真实 GitHub 令牌或远端写入。PostgreSQL 所有权写入使用同样的条件 UPSERT；其测试验证语句的冲突语义，不代表完成真实 PostgreSQL 故障切换验收。
