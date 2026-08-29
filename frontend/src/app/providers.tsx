import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ConfigProvider, App as AntApp } from "antd";
import zhCN from "antd/locale/zh_CN";
import { AuthProvider } from "@/shared/auth/AuthContext";
import { limaTheme } from "@/theme";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 5_000,
    },
    mutations: {
      // 变更不做全局自动重试：重试语义由调用方按业务决定。
      retry: false,
    },
  },
});

export function AppProviders({ children }: { children: React.ReactNode }): React.JSX.Element {
  return (
    <ConfigProvider locale={zhCN} theme={limaTheme}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <AuthProvider>{children}</AuthProvider>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>
  );
}
