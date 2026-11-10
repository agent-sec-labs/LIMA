# PR #354：以实际 facts 回执证明上下文消费

本次修改针对 `fcd098562001d1d610134c86e3a92e15cde1ea72`：注册 ACK 只证明视图已交付，不能证明后续 facts 请求成功使用了它。此前 Sidecar 在 ACK 后丢失注册时，报告仍可能仅凭 `completed` 和 `verified-package` 模式将 `consumed_by_analysis` 标为 true。

现在平台在 verified-package 模式先取得 facts，逐 TU 检查上下文来源为 verified-package、状态 resolved、context hash 非空且 AST 完整，再记录 `verified_context_units`。缺失的 TU 保留在未审阅清单与 AEP 覆盖缺口中；required 模式在上下文不可用时停止依赖它的分析。服务只在请求集合非空且全部具有回执时标记“已消费”，缺失时记录 `verified-context-unavailable`，required 同时标记 blocking。未消费或阻断会进入任务总警告。

回归覆盖真实子进程 Sidecar 在注册成功后、facts 前失去注册：auto 明确不完整；required 不调用后续模型，不声称消费成功。此外覆盖正常回执、无回执、部分回执、空请求范围和平台被禁用的情况。

本次仅修改消费判定、回执传递与相应测试，不包含工作区中其他构建输入、租约、Webhook、修复发布或跨租户授权改动。验证使用隔离导出的待提交 Git tree，详细结果记录于 `output/pr354-consumption-fix-2026-11-10/`。本说明不代表真实 Docker 构建、真实模型推理或 OpenHarmony 漏洞验收已经完成。
