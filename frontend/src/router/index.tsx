import React from "react";
import { Navigate, Outlet, RouterProvider, createHashRouter, createMemoryRouter } from "react-router-dom";

export type AppRouterInstance = ReturnType<typeof createHashRouter>;
import { Layout, Menu, Typography } from "antd";
import {
  ExperimentOutlined,
  FileProtectOutlined,
  RadarChartOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
  ThunderboltOutlined,
} from "@ant-design/icons";
import { Link, useLocation } from "react-router-dom";
import { AuditCreatePage } from "@/features/audit-create/AuditCreatePage";

/**
 * T5 只交付地基：所有业务路由渲染同一个占位页。
 * T6/T7/T8 按 feature 目录逐页替换，不再修改本骨架。
 */
function FeaturePlaceholder({ title }: { title: string }): React.JSX.Element {
  return (
    <div style={{ padding: 24 }}>
      <Typography.Title level={3}>{title}</Typography.Title>
      <Typography.Paragraph type="secondary">
        该页面属于 React 迁移的后续任务，当前由前端地基占位。旧版界面仍在根路径可用。
      </Typography.Paragraph>
    </div>
  );
}

const NAV_ITEMS = [
  { key: "/audit/new", icon: <RadarChartOutlined />, label: "发起审计" },
  { key: "/tasks", icon: <FileProtectOutlined />, label: "审计结果" },
  { key: "/experiments", icon: <ExperimentOutlined />, label: "外部评测" },
  { key: "/skills", icon: <SafetyCertificateOutlined />, label: "系统能力" },
  { key: "/settings", icon: <SettingOutlined />, label: "模型设置" },
  { key: "/evolution", icon: <ThunderboltOutlined />, label: "高级实验" },
] as const;

function Shell(): React.JSX.Element {
  const location = useLocation();
  const selected = NAV_ITEMS.find(
    (item) => location.pathname === item.key || location.pathname.startsWith(`${item.key}/`),
  );
  return (
    <Layout style={{ minHeight: "100vh" }}>
      <Layout.Sider theme="light" width={208}>
        <div style={{ padding: "18px 16px 10px", fontWeight: 700, fontSize: 18 }}>
          砺码 · LIMA
        </div>
        <Menu
          mode="inline"
          selectedKeys={selected ? [selected.key] : []}
          items={NAV_ITEMS.map((item) => ({
            key: item.key,
            icon: item.icon,
            label: <Link to={item.key}>{item.label}</Link>,
          }))}
        />
      </Layout.Sider>
      <Layout>
        <Layout.Content style={{ background: "#f4f7fb" }}>
          <Outlet />
        </Layout.Content>
      </Layout>
    </Layout>
  );
}

function routeTree() {
  return [
    {
      path: "/",
      element: <Shell />,
      children: [
        { index: true, element: <Navigate to="/audit/new" replace /> },
        { path: "audit/new", element: <AuditCreatePage /> },
        { path: "tasks", element: <FeaturePlaceholder title="审计结果（T7）" /> },
        { path: "tasks/:taskId", element: <FeaturePlaceholder title="任务详情（T7）" /> },
        { path: "experiments", element: <FeaturePlaceholder title="外部评测（T8）" /> },
        { path: "skills", element: <FeaturePlaceholder title="系统能力（T8）" /> },
        { path: "settings", element: <FeaturePlaceholder title="模型设置（T8）" /> },
        { path: "evolution", element: <FeaturePlaceholder title="高级实验（T8）" /> },
        { path: "*", element: <Navigate to="/audit/new" replace /> },
      ],
    },
  ];
}

/** 生产使用 hash 路由；测试注入 memory 路由避免 jsdom 导航差异。 */
export function createAppRouter(kind: "hash" | "memory" = "hash", initialPath = "/audit/new"): AppRouterInstance {
  if (kind === "memory") {
    return createMemoryRouter(routeTree(), { initialEntries: [initialPath] });
  }
  return createHashRouter(routeTree());
}

export function AppRouter({ router }: { router: AppRouterInstance }): React.JSX.Element {
  return <RouterProvider router={router} />;
}
