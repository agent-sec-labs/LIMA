import React, { createContext, useCallback, useContext, useMemo, useState } from "react";
import { api, clearStoredToken, getStoredToken, storeToken } from "@/shared/api/client";

interface AuthState {
  token: string;
  signIn: (username: string, password: string, tenantId?: string) => Promise<void>;
  signOut: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }): React.JSX.Element {
  const [token, setToken] = useState<string>(() => getStoredToken());

  const signIn = useCallback(async (username: string, password: string, tenantId = "") => {
    const session = await api.login(username, password, tenantId);
    storeToken(session.access_token);
    setToken(session.access_token);
  }, []);

  const signOut = useCallback(() => {
    clearStoredToken();
    setToken("");
  }, []);

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
