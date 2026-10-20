import React, { createContext, useCallback, useContext, useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api, clearStoredToken, getStoredToken, storeToken } from "@/shared/api/client";

interface AuthState {
  token: string;
  signIn: (username: string, password: string, tenantId?: string) => Promise<void>;
  signOut: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }): React.JSX.Element {
  const [token, setToken] = useState<string>(() => getStoredToken());
  const queryClient = useQueryClient();

  const signIn = useCallback(async (username: string, password: string, tenantId = "") => {
    const session = await api.login(username, password, tenantId);

    // 先取消使用旧凭据的读取，避免旧响应在新会话中写回缓存。
    await queryClient.cancelQueries();
    storeToken(session.access_token);
    setToken(session.access_token);
    // 只在成功建立会话后重置并重取当前活跃查询；不改变 401 的重试策略。
    await queryClient.resetQueries();
  }, [queryClient]);

  const signOut = useCallback(() => {
    clearStoredToken();
    setToken("");
    // 退出后不保留任何可能属于前一账号的查询结果。
    void queryClient.cancelQueries();
    // 逐个重置观察者数据，避免 resetQueries 为活跃查询发起新请求。
    queryClient.getQueryCache().getAll().forEach((query) => query.reset());
  }, [queryClient]);

  const value = useMemo<AuthState>(() => ({ token, signIn, signOut }), [token, signIn, signOut]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used inside AuthProvider");
  }
  return context;
}

/** Provider 之外返回 null：让 Shell 级可选 UI（登录入口）不强制依赖 Provider。 */
export function useOptionalAuth(): AuthState | null {
  return useContext(AuthContext);
}
