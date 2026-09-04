import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { App as AntApp, ConfigProvider } from "antd";
import { RouterProvider } from "react-router-dom";
import { AuthProvider } from "@/shared/auth/AuthContext";
import { clearStoredToken } from "@/shared/api/client";
import { createAppRouter, type AppRouterInstance } from "@/router";

/** T8 登录入口：Modal 表单 → /v1/auth/login → JWT 仅入 localStorage。 */

function renderShell(path: string): AppRouterInstance {
  const router = createAppRouter("memory", path);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <ConfigProvider>
      <AntApp>
        <QueryClientProvider client={client}>
          <AuthProvider>
            <RouterProvider router={router} />
          </AuthProvider>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  );
  return router;
}

afterEach(() => {
  vi.unstubAllGlobals();
  clearStoredToken();
  window.localStorage.clear();
});

describe("AuthBar", () => {
  it("signs in through the modal and flips to signed-out control", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            access_token: "jwt-token",
            token_type: "bearer",
            expires_in: 3600,
            tenant_id: "default",
            role: "admin",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
      ),
    );
    renderShell("/skills");

    fireEvent.click(await screen.findByRole("button", { name: "登 录" }));
    fireEvent.change(await screen.findByLabelText("用户名"), { target: { value: "admin" } });
    fireEvent.change(await screen.findByLabelText("密码"), { target: { value: "secret" } });
    fireEvent.click(await screen.findByRole("button", { name: "确认登录" }));

    await waitFor(() => {
      expect(window.localStorage.getItem("lima_token")).toBe("jwt-token");
    });
    expect(await screen.findByRole("button", { name: "退 出" })).toBeInTheDocument();
  });

  it("stays signed out and shows the failure when credentials are rejected", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(JSON.stringify({ error: "invalid credentials" }), {
          status: 401,
          headers: { "content-type": "application/json" },
        }),
      ),
    );
    renderShell("/skills");

    fireEvent.click(await screen.findByRole("button", { name: "登 录" }));
    fireEvent.change(await screen.findByLabelText("用户名"), { target: { value: "admin" } });
    fireEvent.change(await screen.findByLabelText("密码"), { target: { value: "wrong" } });
    fireEvent.click(await screen.findByRole("button", { name: "确认登录" }));

    expect(await screen.findByText("用户名或密码不正确。")).toBeInTheDocument();
    expect(window.localStorage.getItem("lima_token")).toBeNull();
  });
});
