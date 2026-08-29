import React from "react";
import { Navigate, Outlet, RouterProvider, createHashRouter, createMemoryRouter } from "react-router-dom";

export type AppRouterInstance = ReturnType<typeof createHashRouter>;
import { Layout, Menu } from "antd";
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
import { TaskDetailPage } from "@/features/tasks/TaskDetailPage";
import { TaskListPage } from "@/features/tasks/TaskListPage";
import { AuthBar } from "@/features/auth/AuthBar";
import { ExperimentsPage } from "@/features/experiments/ExperimentsPage";
import { EvolutionPage } from "@/features/evolution/EvolutionPage";
import { SettingsPage } from "@/features/settings/SettingsPage";
import { SkillsPage } from "@/features/skills/SkillsPage";

/**
 * 业务路由由各 feature 目录提供（T6 audit-create / T7 tasks / T8 其余页面）。
 */
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
        <Layout.Header
          style={{
            background: "#fff",
            padding: "0 24px",
            display: "flex",
            justifyContent: "flex-end",
            alignItems: "center",
          }}
        >
          <AuthBar />
        </Layout.Header>
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
        { path: "tasks", element: <TaskListPage /> },
        { path: "tasks/:taskId", element: <TaskDetailPage /> },
        { path: "experiments", element: <ExperimentsPage /> },
        { path: "skills", element: <SkillsPage /> },
        { path: "settings", element: <SettingsPage /> },
        { path: "evolution", element: <EvolutionPage /> },
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
