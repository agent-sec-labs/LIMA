import React from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, Col, Descriptions, List, Row, Tag, Typography } from "antd";
import { api } from "@/shared/api/client";

/** 高级实验：进化状态、门禁记录与未解决失败案例（只读视图）。 */

interface EvolutionStatus {
  validation_cases?: number;
  holdout_cases?: number;
  unresolved_cases?: number;
  active_version?: string;
  ready?: boolean;
}

interface EvolutionRunsPayload {
  runs: Array<{
    candidate_version?: number | string;
    decision?: string;
    candidate_score?: number;
    baseline_score?: number;
  }>;
}

interface FailureCasesPayload {
  cases: Array<{
    id?: string | number;
    category?: string;
    resolved?: boolean;
    payload?: { note?: string };
  }>;
}

export function EvolutionPage(): React.JSX.Element {
  const status = useQuery({
    queryKey: ["evolution-status"],
    queryFn: () => api.get<EvolutionStatus>("/v1/evolution/status"),
  });
  const runs = useQuery({
    queryKey: ["evolution-runs"],
    queryFn: () => api.get<EvolutionRunsPayload>("/v1/evolution/runs"),
  });
  const failures = useQuery({
    queryKey: ["failures"],
    queryFn: () => api.get<FailureCasesPayload>("/api/failures"),
  });

  return (
    <div style={{ padding: 24 }}>
      <Typography.Title level={3}>高级实验</Typography.Title>
      <Row gutter={[16, 16]}>
        <Col xs={12} md={6}>
          <Card size="small">
            <Typography.Text type="secondary">校验案例</Typography.Text>
            <Typography.Paragraph style={{ marginBottom: 0, fontSize: 20 }}>
              {status.data?.validation_cases ?? "—"}
            </Typography.Paragraph>
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card size="small">
            <Typography.Text type="secondary">冻结 holdout</Typography.Text>
            <Typography.Paragraph style={{ marginBottom: 0, fontSize: 20 }}>
              {status.data?.holdout_cases ?? "—"}
            </Typography.Paragraph>
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card size="small">
            <Typography.Text type="secondary">未解决失败案例</Typography.Text>
            <Typography.Paragraph style={{ marginBottom: 0, fontSize: 20 }}>
              {status.data?.unresolved_cases ?? "—"}
            </Typography.Paragraph>
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card size="small">
            <Typography.Text type="secondary">激活版本</Typography.Text>
            <Typography.Paragraph style={{ marginBottom: 0, fontSize: 20 }}>
              {status.data?.active_version ?? "—"}
              {status.data?.ready ? <Tag color="green" style={{ marginLeft: 8 }}>门禁就绪</Tag> : null}
            </Typography.Paragraph>
          </Card>
        </Col>
      </Row>
      <Card size="small" title="门禁记录" style={{ marginTop: 16 }}>
        <List
          size="small"
          dataSource={runs.data?.runs ?? []}
          locale={{ emptyText: "暂无进化门禁记录" }}
          renderItem={(item) => (
            <List.Item>
              <Descriptions size="small" column={4} style={{ width: "100%" }}>
                <Descriptions.Item label="候选版本">{String(item.candidate_version ?? "—")}</Descriptions.Item>
                <Descriptions.Item label="决策">{item.decision ?? "—"}</Descriptions.Item>
                <Descriptions.Item label="候选得分">{item.candidate_score ?? "—"}</Descriptions.Item>
                <Descriptions.Item label="基线得分">{item.baseline_score ?? "—"}</Descriptions.Item>
              </Descriptions>
            </List.Item>
          )}
        />
      </Card>
      <Card size="small" title="失败案例集（进入回放评测）" style={{ marginTop: 16 }}>
        <List
          size="small"
          dataSource={failures.data?.cases ?? []}
          locale={{ emptyText: "暂无失败案例" }}
          renderItem={(item) => (
            <List.Item>
              <span>{item.payload?.note || "未填写说明"}</span>
              <Tag color={item.category === "missed_issue" ? "red" : "orange"}>{item.category ?? "feedback"}</Tag>
              <Tag color={item.resolved ? "green" : "default"}>{item.resolved ? "已解决" : "待评测"}</Tag>
            </List.Item>
          )}
        />
      </Card>
    </div>
  );
}
