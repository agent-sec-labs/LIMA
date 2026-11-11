"""Durable, content-bound publication with read-after-write recovery."""

import hashlib
import json


def publish_repair(
    client,
    store,
    scope,
    *,
    repository,
    pull_request,
    source_sha,
    files,
    verification,
    repairs,
    response,
    test_command,
    body,
):
    identity = {
        "version": 1,
        "scope": scope,
        "repository": repository,
        "pull_request": pull_request,
        "source_sha": source_sha,
        "files": files,
        "repairs": repairs,
        "test_command": test_command,
        "image_id": verification["sandbox"]["image_id"],
        "verified_checks": sorted(str(check["name"]) for check in verification["checks"]),
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    operation_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    branch = f"lima/fix-pr-{pull_request}-{operation_id}"
    message = (
        f"fix: apply verified LIMA repairs for PR #{pull_request} at {source_sha} "
        f"[lima-repair:{operation_id}]"
    )
    intent = {
        **identity,
        "branch": branch,
        "message": message,
        "base": response.pop("_base"),
        "body": body,
        "title": f"fix: verified LIMA repairs for #{pull_request} at {source_sha}",
        "verified_checks": sorted(str(check["name"]) for check in verification["checks"]),
    }
    try:
        # Reserve room for remote identifiers before any remote write.
        if (
            len(json.dumps(intent, ensure_ascii=False).encode()) > 32 * 1024 * 1024
            or len(json.dumps(response, ensure_ascii=False).encode()) > 32 * 1024 * 1024 - 4096
        ):
            return {
                "branch": None,
                "source_sha": source_sha,
                "commits": [],
                "failure_code": "repair-input-too-large",
                "note": "Publication evidence exceeded its byte budget.",
            }
        record = store.prepare_repair_publication(operation_id, intent)
        intent = record["intent"]
        commit = client.ensure_repair_commit(
            repository,
            branch,
            source_sha,
            files,
            message,
            allow_create=record.get("result") is None and not record["stages"].get("commit"),
        )
        store.record_repair_publication_stage(operation_id, "commit", {"sha": commit["sha"]})
        draft = client.ensure_repair_pull(
            repository,
            intent["title"],
            branch,
            intent["base"],
            intent["body"],
            commit["sha"],
            operation_id,
            allow_create=record.get("result") is None and not record["stages"].get("draft"),
        )
        store.record_repair_publication_stage(
            operation_id,
            "draft",
            {
                "number": draft["number"],
                "url": draft["html_url"],
            },
        )
        response.update(
            {
                "branch": branch,
                "publication_operation_id": operation_id,
                "draft_pull_request": {"number": draft["number"], "url": draft["html_url"]},
            }
        )
        response["commits"][0]["sha"] = commit["sha"]
        return store.complete_repair_publication(operation_id, response)["result"]
    except Exception as exc:
        conflict = isinstance(exc, ValueError)
        return {
            "branch": None,
            "source_sha": source_sha,
            "commits": [],
            "publication_operation_id": operation_id,
            "failure_code": "repair-publication-conflict"
            if conflict
            else "repair-publication-pending",
            "note": (
                "Publication conflicts with the recorded intent; no further writes were requested."
                if conflict
                else "Publication outcome is pending. "
                "Retry this task to reconcile the same operation."
            ),
        }
