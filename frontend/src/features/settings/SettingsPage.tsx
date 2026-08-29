import React from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, Col, Row, Typography } from "antd";
import { api } from "@/shared/api/client";

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

export function SettingsPage(): React.JSX.Element {
  const query = useQuery({
    queryKey: ["skills"],
    queryFn: () => api.get<RuntimePayload>("/api/skills"),
  });
  const llm = query.data?.llm ?? {};

  return (
    <div style={{ padding: 24, maxWidth: 900 }}>
      <Typography.Title level={3}>模型设置</Typography.Title>
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
