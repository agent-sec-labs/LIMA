import { describe, expect, it, vi } from "vitest";
import { ApiError, UnauthorizedError, api } from "@/shared/api/client";
import type { TaskProgressSummary } from "@/shared/api/types";

function mockFetchOnce(payload: unknown, status = 200, contentType = "application/json") {
  const fake = vi.fn().mockResolvedValue({
    ok: status < 400,
    status,
    headers: new Headers({ "content-type": contentType }),
    json: () => Promise.resolve(payload),
    text: () => Promise.resolve(String(payload)),
  });
  vi.stubGlobal("fetch", fake);
  return fake;
}

describe("typed api client", () => {
  it("attaches bearer tokens from storage", async () => {
    window.localStorage.setItem("lima_token", "test-token");
    const fake = mockFetchOnce({ id: "t", state: "PENDING" });
    await api.get("/v1/tasks/t");
    const [, init] = fake.mock.calls[0] as [string, RequestInit];
    expect(init.headers).toMatchObject({ Authorization: "Bearer test-token" });
    window.localStorage.removeItem("lima_token");
  });

  it("maps 401 to UnauthorizedError", async () => {
    mockFetchOnce({ error: "unauthorized" }, 401);
    await expect(api.get("/v1/tasks/x")).rejects.toBeInstanceOf(UnauthorizedError);
  });

  it("surfaces error payloads as ApiError messages", async () => {
    mockFetchOnce({ error: "task not found" }, 404);
    const failure = await api.get("/v1/tasks/missing").catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ApiError);
    expect((failure as ApiError).message).toContain("task not found");
  });
});

describe("progress summary contract", () => {
  it("accepts backend-shaped summaries", () => {
    const summary: TaskProgressSummary = {
      stage: "DOWNLOADING_ARCHIVE",
      stage_index: 4,
      stage_total: 13,
      message: "正在下载仓库快照",
      attempt: 1,
      max_attempts: 3,
      current: 36700160,
      total: null,
      unit: "bytes",
    };
    expect(summary.stage).toBe("DOWNLOADING_ARCHIVE");
    expect(summary.stage_total).toBe(13);
  });
});
