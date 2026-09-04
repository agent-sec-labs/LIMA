# PROGRESS.md — Local Execution Cache Template

> Copy this file to `PROGRESS.md` when a local Coordinator needs a disposable
> execution cache. `PROGRESS.md` is ignored by Git and must never be treated as
> the cross-agent source of truth.

## Remote truth references

| Field | Value |
|---|---|
| Source Issue | `<url>` |
| Delivery Ledger revision | `<issue edit/comment id and timestamp>` |
| Coordinator Assignment | `<task/artifact reference>` |
| Active Packet | `<path and merged commit>` |
| Frozen Test Commit | `<sha or not-created>` |
| Implementation PR | `<url or not-created>` |
| Verified `origin/main` | `<sha>` |

## Local workspace cache

| Field | Value |
|---|---|
| Snapshot time | `<ISO-8601>` |
| Local branch | `<branch>` |
| Local HEAD | `<sha>` |
| Worktree | `<absolute local path>` |
| Dirty tracked files | `none` or `<list>` |
| Untracked files | `none` or `<list; never include secrets>` |
| Local owner/session | `<identity>` |

## Local verification cache

| Command | Environment | Result | Log/artifact |
|---|---|---|---|
| `<exact command>` | `<versions>` | `<pass/fail/skip/exit>` | `<local path>` |

## Recovery note

- Last verified remote state: `<fact>`
- Local-only observation: `<fact>`
- Exact safe next action: `<one action>`
- Stop condition / decision request: `none | <reference>`
- Forbidden cleanup/action: `<if applicable>`

If this cache conflicts with the Source Issue Delivery Ledger, Coordinator
Assignment, merged Packet, PR, or Git state, discard or rebuild this cache. It
must not activate an IP, authorize file ownership, or close an Issue.
