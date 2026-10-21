"""Bounded, allowlisted environment identity exporter (Issue #313).

No settings, credentials, environment enumeration, or application services are loaded.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

COMMAND_TIMEOUT = 5.0
OUTPUT_LIMIT = 16 * 1024
TOOL_PATTERNS = {
    "git": r"git version (\d+(?:\.\d+){1,3})(?=[.\s-]|$)",
    "clang": r"(?:Debian |Ubuntu |Apple )?clang version (\d+(?:\.\d+){1,3})(?=[\s-]|$)",
    "clang-14": r"(?:Debian |Ubuntu |Apple )?clang version (\d+(?:\.\d+){1,3})(?=[\s-]|$)",
    "cmake": r"cmake version (\d+(?:\.\d+){1,3})(?=[\s-]|$)",
}
GIT_PREFIX = ["git", "--no-optional-locks", "-c", "core.fsmonitor=false",
              "-c", "core.untrackedCache=false"]
LIMIT_FIELDS = ("nano_cpus", "cpu_period", "cpu_quota", "cpuset_cpus",
                "memory_bytes", "memory_swap_bytes", "pids_limit")
# The daemon returns only this projection. Never request full inspect, Env or Mounts.
INSPECT_FORMAT = (
    '{"image_id":{{json .Image}},"image_reference":{{json .Config.Image}},'
    '"limits":{"nano_cpus":{{json .HostConfig.NanoCpus}},'
    '"cpu_period":{{json .HostConfig.CpuPeriod}},'
    '"cpu_quota":{{json .HostConfig.CpuQuota}},'
    '"cpuset_cpus":{{json .HostConfig.CpusetCpus}},'
    '"memory_bytes":{{json .HostConfig.Memory}},'
    '"memory_swap_bytes":{{json .HostConfig.MemorySwap}},'
    '"pids_limit":{{json .HostConfig.PidsLimit}}}}'
)
SENSITIVE_TOKEN = re.compile(
    r"(?:sk[-_]|gh[pousr]_|github_pat_|bearer|password|credential|api[_-]?key|"
    r"token[_.-]|secret[_.-]|(?:AKIA|ASIA)[0-9A-Z]{16})", re.I
)


class ExportError(ValueError):
    """Only constant reason codes may cross the CLI boundary."""

    def __init__(self, code, exit_code=3):
        super().__init__(code)
        self.code = code
        self.exit_code = exit_code


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ExportError("invalid_arguments")


def _command(argv, *, cwd=None):
    """Run argv without a shell, discard stderr, bound time and retained stdout.

    The reader retains at most OUTPUT_LIMIT+1 bytes, then kills the child. A daemon
    reader also lets the caller return on timeout if a descendant holds the pipe.
    Nothing from a command's stderr or an exception is returned to the manifest.
    """
    child_env = None
    if argv[0] == "git":
        # Build a minimal launch environment instead of enumerating the parent's.
        # Inherited GIT_DIR/WORK_TREE/COMMON_DIR/INDEX_FILE/config/object overrides
        # must not redirect identity away from the selected checkout. Let Git
        # discover its own metadata, including a linked worktree's .git file.
        child_env = {}
        # User config locations preserve normal Git config and ignore rules
        # without accepting GIT_CONFIG_* overrides from the parent process.
        for key in ("PATH", "SystemRoot", "TEMP", "TMP", "HOME", "USERPROFILE",
                    "XDG_CONFIG_HOME"):
            value = os.environ.get(key)
            if value is not None:
                child_env[key] = value
    try:
        process = subprocess.Popen(  # noqa: S603 -- callers use fixed command allowlist
            argv, cwd=cwd, shell=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=child_env,
        )
    except FileNotFoundError:
        return None, "not_found"
    except PermissionError:
        return None, "permission_denied"
    except OSError:
        return None, "os_error"

    completed = threading.Event()
    result = {"raw": None, "reason": None}

    def stop():
        try:
            process.kill()
        except OSError:
            pass

    def read():
        try:
            raw = process.stdout.read(OUTPUT_LIMIT + 1)
            if len(raw) > OUTPUT_LIMIT:
                result["reason"] = "output_limit"
                stop()
            else:
                result["raw"] = raw
        except OSError:
            result["reason"] = "os_error"
            stop()
        finally:
            process.stdout.close()
            completed.set()

    deadline = time.monotonic() + COMMAND_TIMEOUT
    threading.Thread(target=read, daemon=True).start()
    try:
        process.wait(timeout=COMMAND_TIMEOUT)
        if not completed.wait(max(0, deadline - time.monotonic())):
            stop()
            return None, "timeout"
    except subprocess.TimeoutExpired:
        stop()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        return None, "timeout"
    if result["reason"]:
        return None, result["reason"]
    if process.returncode:
        return None, "nonzero_exit"
    return result["raw"], None


def _label(value):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value, flags=re.ASCII):
        raise ExportError("invalid_label")
    if SENSITIVE_TOKEN.search(value):
        raise ExportError("invalid_label")
    return value


def _source(repository):
    source = {"commit": None, "dirty": None, "unknown_reasons": {}}
    raw, reason = _command([*GIT_PREFIX, "rev-parse", "--is-inside-work-tree"],
                           cwd=repository)
    if reason == "nonzero_exit" or (reason is None and raw.strip() != b"true"):
        raise ExportError("repository_identity_unavailable", 2)
    if reason:
        source["unknown_reasons"] = {"commit": reason, "dirty": reason}
        return source
    raw, reason = _command([*GIT_PREFIX, "rev-parse", "--show-toplevel"], cwd=repository)
    if reason:
        raise ExportError("repository_identity_unavailable", 2)
    try:
        root = Path(raw.decode("utf-8").rstrip("\r\n")).resolve(strict=True)
        if root != repository:
            raise ExportError("repository_root_required", 2)
    except (OSError, UnicodeError, ValueError, RuntimeError) as error:
        if isinstance(error, ExportError):
            raise
        raise ExportError("repository_identity_unavailable", 2) from None
    raw, reason = _command([*GIT_PREFIX, "rev-parse", "--verify", "HEAD"], cwd=repository)
    if reason is None and not re.fullmatch(rb"(?:[0-9a-f]{40}|[0-9a-f]{64})\s*", raw):
        reason = "invalid_commit"
    if reason:
        source["unknown_reasons"]["commit"] = reason
    else:
        source["commit"] = raw.decode("ascii").strip()
    raw, reason = _command([*GIT_PREFIX, "status", "--porcelain=v1", "--untracked-files=all"],
                           cwd=repository)
    if reason:
        source["unknown_reasons"]["dirty"] = reason
    else:
        # Retain no filenames, even when Git prints paths containing secrets.
        source["dirty"] = bool(raw)
    return source


def _tools():
    tools = {}
    for name, pattern in TOOL_PATTERNS.items():
        raw, reason = _command([name, "--version"])
        version = None
        if reason is None:
            try:
                # Only a numeric version at the start of a recognized first line.
                match = re.match(pattern, raw.decode("utf-8"), flags=re.ASCII)
            except UnicodeError:
                match = None
            if match is None:
                reason = "unrecognized_version"
            else:
                version = match.group(1)
        tools[name] = {"version": version, "source": "host", "reason": reason}
    return tools


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("non_finite")


def _image_reference(value):
    if not isinstance(value, str) or len(value) > 256 or SENSITIVE_TOKEN.search(value):
        return False
    # @ is allowed only for an exact sha256 digest, never URL userinfo.
    parts = value.split("@")
    if len(parts) > 2 or (len(parts) == 2 and not re.fullmatch(r"sha256:[0-9a-f]{64}", parts[1])):
        return False
    # distribution/reference permits '.', '_', '__', or one or more '-' between
    # alphanumeric runs. Preserve the separate credential and digest guards.
    component = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
    return re.fullmatch(
        component + r"(?::[0-9]+)?(?:/" + component + r")*"
        r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?", parts[0], flags=re.ASCII,
    ) is not None


def _container(container):
    result = {"image_id": None, "image_reference": None, "limits": None,
              "source": "docker-inspect", "reason": "not_selected",
              "tool_versions": "unknown", "tool_versions_reason": "not_collected"}
    if container is None:
        return result
    raw, reason = _command(["docker", "inspect", "--type=container", "--format",
                            INSPECT_FORMAT, "--", container])
    if reason:
        result["reason"] = reason
        return result
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=_invalid_constant)
        if not isinstance(data, dict):
            raise ValueError("object_required")
        image_id, reference, limits = data["image_id"], data["image_reference"], data["limits"]
        if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise ValueError("invalid_image_id")
        if not _image_reference(reference) or not isinstance(limits, dict):
            raise ValueError("invalid_image_or_limits")
        projected = {field: limits[field] for field in LIMIT_FIELDS}
        for field, value in projected.items():
            if field == "cpuset_cpus":
                if not isinstance(value, str) or not re.fullmatch(r"[0-9,-]{0,128}", value):
                    raise ValueError("invalid_cpuset")
            elif field == "pids_limit" and value is None:
                continue
            elif type(value) is not int or not -1 <= value <= 2**63 - 1:
                raise ValueError("invalid_limit")
            elif value < 0 and field not in ("pids_limit", "memory_swap_bytes", "cpu_quota"):
                raise ValueError("invalid_negative_limit")
        result.update(image_id=image_id, image_reference=reference, limits=projected, reason=None)
    except (UnicodeError, ValueError, TypeError, KeyError, RecursionError):
        result["reason"] = "invalid_projection"
    return result


def _host():
    # Do not use platform.platform()/uname()/sys.version, which include extra identity.
    result = {"memory_total_bytes": None,
              "memory_reason": "not_collected_without_additional_dependencies"}
    reasons = {}
    for field, getter in (("os_type", platform.system), ("os_version", platform.release),
                          ("architecture", platform.machine), ("logical_cpu_count", os.cpu_count),
                          ("python_version", platform.python_version)):
        try:
            value = getter()
            if field == "logical_cpu_count":
                valid = type(value) is int and value > 0
            else:
                valid = (isinstance(value, str)
                         and re.fullmatch(r"[A-Za-z0-9_.+-]{1,128}", value))
            if not valid:
                value = None
                reasons[field] = "unavailable_or_unrecognized"
        except (OSError, ValueError, RuntimeError):
            value = None
            reasons[field] = "unavailable"
        result[field] = value
    result["unknown_reasons"] = reasons
    return result


def _paths(repository, output):
    try:
        repository = Path(repository).resolve(strict=True)
        if not repository.is_dir():
            raise OSError()
    except (OSError, ValueError, RuntimeError):
        raise ExportError("repository_unavailable", 2) from None
    try:
        output = Path(output).absolute()
        # Reject dangling symlinks and existing files too. Never create directories.
        if os.path.lexists(output) or not output.parent.is_dir():
            raise ExportError("output_unavailable")
        output = output.resolve()
        # Avoid modifying the inspected checkout or contaminating its dirty status.
        if output.is_relative_to(repository):
            raise ExportError("output_inside_repository")
    except (OSError, ValueError, RuntimeError) as error:
        if isinstance(error, ExportError):
            raise
        raise ExportError("output_unavailable") from None
    return repository, output


def main(argv=None):
    parser = Parser(description="Export allowlisted identity; not a dependency lock or health check.",
                    allow_abbrev=False)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-label", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--container", help="Exact container ID/name; optional read-only inspect")
    parser.add_argument("--model-label", help="Operator-declared label; backend remains unknown")
    created = False
    output = None
    try:
        args = parser.parse_args(argv)
        _label(args.run_label)
        if args.container is not None:
            _label(args.container)
        if args.model_label is not None:
            _label(args.model_label)
        repository, output = _paths(args.repository, args.output)
        source = _source(repository)
        document = {
            "schema_version": 1, "run_label": args.run_label,
            "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "host": _host(), "source": source, "host_tools": _tools(),
            "container": _container(args.container),
            "model": {"label": args.model_label, "source": "operator-declared",
                      "backend_version": "unknown"},
            "limitations": ["not_a_dependency_lock_or_health_check",
                            "host_is_the_exporter_execution_environment",
                            "container_tool_versions_not_collected",
                            "model_backend_not_verified"],
        }
        serialized = json.dumps(document, ensure_ascii=True, allow_nan=False, indent=2) + "\n"
        with output.open("x", encoding="utf-8", newline="\n") as stream:
            created = True
            stream.write(serialized)
        return 0
    except ExportError as error:
        print(error.code, file=sys.stderr)
        return error.exit_code
    except SystemExit as error:
        return error.code  # --help
    except (OSError, ValueError, RuntimeError):
        if created:
            try:
                output.unlink()
            except OSError:
                pass
        print("output_or_collection_error", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
