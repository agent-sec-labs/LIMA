"""Producer-side constructors for the strict Sidecar v1 tool-run state machine."""

from __future__ import annotations

from typing import Final

PROTOCOL_TOOL_STATUSES: Final = {
    "semgrep": frozenset({"completed", "failed", "timed-out"}),
    "build-step": frozenset({"completed", "build_failed", "timed-out"}),
    "clang": frozenset({"completed", "failed", "timed-out"}),
    "asan-test": frozenset({"completed", "failed", "timed-out"}),
}


def tool_run_from_execution(
    tool: str,
    execution: object,
    *,
    build_step: bool = False,
    semantic_failure: bool = False,
) -> dict[str, object]:
    """Map internal execution states to one semantically closed v1 record."""

    if tool not in PROTOCOL_TOOL_STATUSES:
        raise ValueError("tool is outside the v1 protocol")
    internal_status = getattr(execution, "status", None)
    returncode = getattr(execution, "returncode", None)
    complete = getattr(execution, "digests_complete", None)
    output_sha256 = getattr(execution, "output_sha256", None)
    truncated = getattr(execution, "output_truncated", None)
    if (
        not isinstance(internal_status, str)
        or (returncode is not None and type(returncode) is not int)
        or type(complete) is not bool
        or not isinstance(output_sha256, str)
        or type(truncated) is not bool
    ):
        raise ValueError("execution does not satisfy the tool-run source contract")

    if semantic_failure:
        status = "build_failed" if build_step else "failed"
        returncode = None
    elif internal_status == "completed" and returncode == 0:
        status = "completed"
    elif internal_status == "timed-out":
        status = "timed-out"
        returncode = None
    else:
        status = "build_failed" if build_step else "failed"
        if returncode == 0:
            returncode = None

    if status == "completed" and not complete:
        status = "build_failed" if build_step else "failed"
        returncode = None
    digest = output_sha256 if complete else ""
    return {
        "tool": tool,
        "status": status,
        "returncode": returncode,
        "output_sha256": digest,
        "output_truncated": truncated or not complete,
        "digests_complete": complete,
    }


def timed_out_tool_run(tool: str) -> dict[str, object]:
    """Return a synthetic no-launch record without claiming an output digest."""

    if tool not in PROTOCOL_TOOL_STATUSES:
        raise ValueError("tool is outside the v1 protocol")
    return {
        "tool": tool,
        "status": "timed-out",
        "returncode": None,
        "output_sha256": "",
        "output_truncated": True,
        "digests_complete": False,
    }
