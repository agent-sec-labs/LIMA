import React, { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { Alert, App as AntApp, Card, Col, Row, Typography } from "antd";
import { api } from "@/shared/api/client";
import { useAuth } from "@/shared/auth/AuthContext";

interface RuntimePayload {
  llm: {
    enabled?: boolean;
    provider?: string;
    model?: string;
    error?: boolean;
  };
}

/** 模型设置：只读运行时状态 + 密钥配置指引（密钥只进服务端 .env，网页不采集）。 */

const PROVIDER_KEYS = [
  { label: "DeepSeek", env: "LIMA_DEEPSEEK_API_KEY" },
  { label: "OpenRouter", env: "LIMA_OPENROUTER_API_KEY" },
  { label: "其他 OpenAI 兼容接口", env: "LIMA_LLM_API_KEY" },
];

/**
 * GitHub App 安装登记（legacy #github-install 对等）：
 * /github/setup 回跳到 /app/#/settings?github_installation=<id>&account=<name>，
 * 已登录则自动 POST 登记并提示；未登录先提示，登录后（token 出现）自动完成。
 */
function GithubInstallRegistration(): React.JSX.Element | null {
  const { message } = AntApp.useApp();
  const { token } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const [status, setStatus] = useState<"idle" | "waiting-login" | "done">("idle");

  const raw = searchParams.get("github_installation") ?? "";
  const account = (searchParams.get("account") || "github-app").slice(0, 100);
  const installationId = Number.parseInt(raw, 10);

  // status=done 守卫防止 effect 重入（token 到达、参数清理都会触发重跑）。
  useEffect(() => {
    if (!raw || status === "done") return;
    if (!Number.isInteger(installationId) || installationId <= 0) {
      setStatus("done");
      void message.error("GitHub 安装登记失败：回跳链接缺少有效的 installation_id。");
      setSearchParams({}, { replace: true });
      return;
    }
    if (!token) {
      setStatus("waiting-login");
      return;
    }
    setStatus("done");
    void api
      .registerGithubInstallation(installationId, account)
      .then(() => {
        void message.success(
          `GitHub 安装已登记：installation ${installationId} 已绑定到当前租户。`,
        );
      })
      .catch((error: Error) => {
        void message.error(`GitHub 安装登记失败：${error.message}`);
      })
      .finally(() => {
        setSearchParams({}, { replace: true });
      });
  }, [raw, installationId, account, token, status, message, setSearchParams]);

  if (status !== "waiting-login") return null;
  return (
    <Alert
      type="warning"
      showIcon
      style={{ marginBottom: 16 }}
      message="请先登录"
      description="使用管理员账号登录后将自动完成 GitHub 安装登记。"
    />
  );
}

export function SettingsPage(): React.JSX.Element {
  const query = useQuery({
    queryKey: ["skills"],
    queryFn: () => api.get<RuntimePayload>("/api/skills"),
  });
  const llm = query.data?.llm ?? {};

  return (
    <div style={{ padding: 24, maxWidth: 900 }}>
      <Typography.Title level={3}>模型设置</Typography.Title>
      <GithubInstallRegistration />
      <Row gutter={[16, 16]}>
        <Col xs={24} md={8}>
          <Card size="small">
            <Typography.Text type="secondary">分析模式</Typography.Text>
            <Typography.Paragraph style={{ marginBottom: 0 }}>
              <Typography.Text strong>
                {llm.error ? "状态未知" : llm.enabled ? "规则 + LLM 证据融合" : "确定性本地规则"}
              </Typography.Text>
            </Typography.Paragraph>
          </Card>
        </Col>
        <Col xs={24} md={8}>
          <Card size="small">
            <Typography.Text type="secondary">Provider / Model</Typography.Text>
            <Typography.Paragraph style={{ marginBottom: 0 }}>
              <Typography.Text strong>
                {(llm.enabled ? llm.provider || "已配置" : "local") + " / " + (llm.model || "local-rules")}
              </Typography.Text>
            </Typography.Paragraph>
          </Card>
        </Col>
        <Col xs={24} md={8}>
          <Card size="small">
            <Typography.Text type="secondary">密钥来源</Typography.Text>
            <Typography.Paragraph style={{ marginBottom: 0 }}>
              <Typography.Text strong>服务端 .env（网页不可读取）</Typography.Text>
            </Typography.Paragraph>
          </Card>
        </Col>
      </Row>
      <Card size="small" title="为服务端配置模型密钥" style={{ marginTop: 16 }}>
        <Typography.Paragraph>
          模型密钥只写入服务端 <Typography.Text code>.env</Typography.Text>，浏览器永不采集、存储或提交密钥。
          未配置时系统使用确定性本地规则完成基础审计。
        </Typography.Paragraph>
        <ul style={{ margin: 0, paddingLeft: 20 }}>
          {PROVIDER_KEYS.map((item) => (
            <li key={item.env}>
              {item.label}：<Typography.Text code>{item.env}</Typography.Text>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
