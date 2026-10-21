import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { AuthProvider, useAuth } from "@/shared/auth/AuthContext";
import { api, clearStoredToken, storeToken } from "@/shared/api/client";

interface ProtectedPayload {
  owner: string;
}

function ProtectedQuery(): React.JSX.Element {
  const query = useQuery({
    queryKey: ["protected-profile"],
    queryFn: ({ signal }) => api.get<ProtectedPayload>("/protected-profile", signal),
    retry: false,
  });

  return <output>{query.data?.owner ?? "none"}</output>;
}

function AuthControls(): React.JSX.Element {
  const { signIn, signOut } = useAuth();

  return (
    <>
      <button type="button" onClick={() => void signIn("admin", "secret")}>登录</button>
      <button type="button" onClick={signOut}>退出</button>
    </>
  );
}

function renderAuthTree(client = new QueryClient({ defaultOptions: { queries: { retry: false } } })): QueryClient {
  render(
    <QueryClientProvider client={client}>
      <AuthProvider>
        <AuthControls />
        <ProtectedQuery />
      </AuthProvider>
    </QueryClientProvider>,
  );
  return client;
}

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  clearStoredToken();
  window.localStorage.clear();
});

describe("AuthProvider query boundary", () => {
  it("refetches an active query after login when its anonymous request was rejected", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === "/v1/auth/login") {
        return jsonResponse({ access_token: "new-token" });
      }
      return init?.headers && (init.headers as Record<string, string>).Authorization === "Bearer new-token"
        ? jsonResponse({ owner: "admin" })
        : jsonResponse({ error: "unauthorized" }, 401);
    });
    vi.stubGlobal("fetch", fetchMock);

    renderAuthTree();

    await waitFor(() => expect(screen.getByText("none")).toBeInTheDocument());
    expect(fetchMock).toHaveBeenCalledWith("/protected-profile", expect.objectContaining({ headers: {} }));

    fireEvent.click(screen.getByRole("button", { name: "登录" }));

    expect(await screen.findByText("admin")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      "/protected-profile",
      expect.objectContaining({ headers: { Authorization: "Bearer new-token" } }),
    );
  });

  it("removes the previous account's protected data on logout", async () => {
    storeToken("first-account");
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) =>
        String(input) === "/protected-profile" ? jsonResponse({ owner: "first-account" }) : jsonResponse({}),
      ),
    );

    renderAuthTree();

    expect(await screen.findByText("first-account")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "退出" }));

    await waitFor(() => expect(screen.getByText("none")).toBeInTheDocument());
  });

  it("does not accept an in-flight response after logout", async () => {
    storeToken("first-account");
    let resolveRequest: ((response: Response) => void) | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn(
        () =>
          new Promise<Response>((resolve) => {
            resolveRequest = resolve;
          }),
      ),
    );

    const client = renderAuthTree();
    await waitFor(() => expect(resolveRequest).toBeTypeOf("function"));
    fireEvent.click(screen.getByRole("button", { name: "退出" }));
    await act(async () => {
      resolveRequest?.(jsonResponse({ owner: "first-account" }));
      await Promise.resolve();
    });

    await waitFor(() => expect(screen.getByText("none")).toBeInTheDocument());
    expect(client.getQueryData(["protected-profile"])).toBeUndefined();
  });

  it("does not dispatch another protected request while logging out", async () => {
    storeToken("first-account");
    const fetchMock = vi.fn(async () => jsonResponse({ owner: "first-account" }));
    vi.stubGlobal("fetch", fetchMock);
    renderAuthTree();
    expect(await screen.findByText("first-account")).toBeInTheDocument();
    const requestsBeforeLogout = fetchMock.mock.calls.length;
    fireEvent.click(screen.getByRole("button", { name: "退出" }));
    await waitFor(() => expect(screen.getByText("none")).toBeInTheDocument());
    expect(fetchMock).toHaveBeenCalledTimes(requestsBeforeLogout);
  });
});
