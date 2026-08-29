import type { HealthPayload, LoginResponse } from "@/shared/api/types";

/** 集中式 API 客户端：组件不得散落直接 fetch。 */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export class UnauthorizedError extends ApiError {
  constructor() {
    super(401, "未授权或登录已过期");
    this.name = "UnauthorizedError";
  }
}

const TOKEN_STORAGE_KEY = "lima_token";

export function getStoredToken(): string {
  return window.localStorage.getItem(TOKEN_STORAGE_KEY) ?? "";
}

export function storeToken(token: string): void {
  window.localStorage.setItem(TOKEN_STORAGE_KEY, token);
}

export function clearStoredToken(): void {
  window.localStorage.removeItem(TOKEN_STORAGE_KEY);
}

export interface RequestOptions {
  method?: string;
  body?: unknown;
  /** 跳过 Authorization 头（登录接口自身）。 */
  anonymous?: boolean | undefined;
  signal?: AbortSignal | undefined;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = {};
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  const token = getStoredToken();
  if (!options.anonymous && token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const init: RequestInit = {
    method: options.method ?? "GET",
    headers,
  };
  if (options.body !== undefined) {
    init.body = JSON.stringify(options.body);
  }
  if (options.signal !== undefined) {
    init.signal = options.signal;
  }
  const response = await fetch(path, init);
  if (response.status === 401) {
    throw new UnauthorizedError();
  }
  const contentType = response.headers.get("content-type") ?? "";
  const payload: unknown = contentType.includes("json")
    ? await response.json()
    : await response.text();
  if (!response.ok) {
    const message =
      typeof payload === "object" && payload !== null && "error" in payload
        ? String((payload as { error: unknown }).error)
        : `请求失败 (${response.status})`;
    throw new ApiError(response.status, message);
  }
  return payload as T;
}

export const api = {
  get: <T>(path: string, signal?: AbortSignal | undefined) =>
    request<T>(path, { method: "GET", signal }),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "POST", body }),
  health: () => request<HealthPayload>("/health", { anonymous: true }),
  login: (username: string, password: string, tenantId = "") =>
    request<LoginResponse>("/v1/auth/login", {
      method: "POST",
      anonymous: true,
      body: { username, password, tenant_id: tenantId },
    }),
};
