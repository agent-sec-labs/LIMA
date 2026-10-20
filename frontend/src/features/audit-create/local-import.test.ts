import { describe, expect, it } from "vitest";
import { auditDraftSchema, buildSubmitPayload, EMPTY_DRAFT } from "./model";

describe("local repository import keys", () => {
  it.each(["ResInsight", "team/ResInsight", "油气工业软件源码/ResInsight"])(
    "accepts the backend relative key %s without rewriting it",
    (repository) => {
      const draft = { ...EMPTY_DRAFT, repository };
      expect(auditDraftSchema.safeParse(draft).success).toBe(true);
      expect(buildSubmitPayload(draft).body).toMatchObject({ repository_key: repository });
    },
  );

  it.each(["../ResInsight", "D:\\paper\\ResInsight", "/ResInsight", "team//repo", ".git", "https://github.com/owner/repo"])(
    "rejects an unsafe or non-local key %s",
    (repository) => {
      expect(auditDraftSchema.safeParse({ ...EMPTY_DRAFT, repository }).success).toBe(false);
    },
  );

  it("retains the GitHub owner/project requirement", () => {
    expect(auditDraftSchema.safeParse({ ...EMPTY_DRAFT, sourceMode: "github", repository: "ResInsight" }).success).toBe(false);
  });
});
