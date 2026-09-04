import React from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, Col, Row, Space, Tag, Typography } from "antd";
import { api } from "@/shared/api/client";

interface SkillsPayload {
  llm: {
    enabled?: boolean;
    provider?: string;
    model?: string;
    error?: boolean;
  };
  skills: Array<{
    name: string;
    version?: string;
    source?: string;
    sandboxed?: boolean;
    description?: string;
  }>;
}

/** 系统能力：内置 Skill 清单 + 模型运行时一角（数据同源于 /api/skills）。 */

export function SkillsPage(): React.JSX.Element {
  const query = useQuery({
    queryKey: ["skills"],
    queryFn: () => api.get<SkillsPayload>("/api/skills"),
  });

  const llm = query.data?.llm ?? {};
  const skills = (query.data?.skills ?? []).filter((item) => item.name !== "llm-review");

  return (
    <div style={{ padding: 24 }}>
      <Typography.Title level={3}>系统能力</Typography.Title>
      <Typography.Paragraph type="secondary">
        内置能力在隔离环境运行，不执行被审计仓库的代码；语义复核为可选项。
      </Typography.Paragraph>
      <Card size="small" style={{ marginBottom: 16 }}>
        <Space size="large">
          <span>
            分析模式：
            <Typography.Text strong>
              {llm.error ? "状态未知" : llm.enabled ? "规则 + LLM 证据融合" : "确定性本地规则"}
            </Typography.Text>
          </span>
          <span>
            Provider / Model：
            <Typography.Text strong>
              {llm.provider || "local"} / {llm.model || "local-rules"}
            </Typography.Text>
          </span>
          <span>
            密钥来源：<Typography.Text strong>服务端 .env（网页不可读取）</Typography.Text>
          </span>
        </Space>
      </Card>
      <Row gutter={[16, 16]}>
        {skills.map((skill) => (
          <Col key={skill.name} xs={24} md={12} xl={8}>
            <Card
              title={skill.name}
              extra={<Tag color={skill.sandboxed ? "green" : "default"}>{skill.sandboxed ? "隔离运行" : "标准运行"}</Tag>}
            >
              <Typography.Paragraph style={{ minHeight: 44 }}>
                {skill.description || "暂无能力描述"}
              </Typography.Paragraph>
              <Typography.Text type="secondary">
                v{skill.version || "1.0"} · {skill.source || "built-in"}
              </Typography.Text>
            </Card>
          </Col>
        ))}
      </Row>
      {query.isError && (
        <Typography.Text type="danger">能力清单加载失败：{String((query.error as Error)?.message ?? "")}</Typography.Text>
      )}
    </div>
  );
}
