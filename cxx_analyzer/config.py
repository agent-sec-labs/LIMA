"""Administrator-only configuration for the isolated analyzer Sidecar."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

MAX_STEPS = 64
MAX_ARGUMENTS_PER_STEP = 128
MAX_ARGUMENT_BYTES = 4096


def parse_steps_json(name: str, raw: str) -> tuple[tuple[str, ...], ...]:
    """Parse a bounded JSON array of argv arrays without accepting shell text."""

    try:
        payload = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{name} must be a JSON array of argv arrays") from exc
    if not isinstance(payload, list):
        raise ValueError(f"{name} must be a JSON array of argv arrays")
    if len(payload) > MAX_STEPS:
        raise ValueError(f"{name} must contain at most {MAX_STEPS} steps")

    parsed: list[tuple[str, ...]] = []
    for step in payload:
        if not isinstance(step, list) or not step:
            raise ValueError(f"{name} steps must be non-empty argv arrays")
        if len(step) > MAX_ARGUMENTS_PER_STEP:
            raise ValueError(
                f"{name} steps must contain at most {MAX_ARGUMENTS_PER_STEP} arguments"
            )
        arguments: list[str] = []
        for argument in step:
            if not isinstance(argument, str):
                raise ValueError(f"{name} argv values must be strings")
            if "\0" in argument:
                raise ValueError(f"{name} argv values must not contain NUL")
            if len(argument.encode("utf-8")) > MAX_ARGUMENT_BYTES:
                raise ValueError(
                    f"{name} argv values must be at most {MAX_ARGUMENT_BYTES} bytes"
                )
            arguments.append(argument)
        if not arguments[0]:
            raise ValueError(f"{name} executable must not be empty")
        parsed.append(tuple(arguments))
    return tuple(parsed)


def _positive_int(name: str, default: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _strict_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name, "true" if default else "false").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


@dataclass(frozen=True)
class AnalyzerSettings:
    """Immutable settings read exclusively from the Sidecar process environment."""

    auto_cmake: bool
    build_steps: tuple[tuple[str, ...], ...]
    test_steps: tuple[tuple[str, ...], ...]
    max_memory_mb: int
    max_processes: int
    max_output_bytes: int
    step_timeout_seconds: int
    total_timeout_seconds: int
    repository_scan_max_files: int
    repository_scan_max_file_bytes: int
    repository_scan_max_total_bytes: int

    @classmethod
    def from_env(cls) -> AnalyzerSettings:
        return cls(
            auto_cmake=_strict_bool("LIMA_CXX_AUTO_CMAKE", True),
            build_steps=parse_steps_json(
                "LIMA_CXX_BUILD_STEPS_JSON",
                os.getenv("LIMA_CXX_BUILD_STEPS_JSON", "[]"),
            ),
            test_steps=parse_steps_json(
                "LIMA_CXX_TEST_STEPS_JSON",
                os.getenv("LIMA_CXX_TEST_STEPS_JSON", "[]"),
            ),
            max_memory_mb=_positive_int("LIMA_CXX_MAX_MEMORY_MB", 2048),
            max_processes=_positive_int("LIMA_CXX_MAX_PROCESSES", 128),
            max_output_bytes=_positive_int("LIMA_CXX_MAX_OUTPUT_BYTES", 1_048_576),
            step_timeout_seconds=_positive_int("LIMA_CXX_STEP_TIMEOUT_SECONDS", 120),
            total_timeout_seconds=_positive_int("LIMA_CXX_TOTAL_TIMEOUT_SECONDS", 300),
            repository_scan_max_files=_positive_int(
                "LIMA_REPOSITORY_SCAN_MAX_FILES", 5_000
            ),
            repository_scan_max_file_bytes=_positive_int(
                "LIMA_REPOSITORY_SCAN_MAX_FILE_BYTES", 512 * 1024
            ),
            repository_scan_max_total_bytes=_positive_int(
                "LIMA_REPOSITORY_SCAN_MAX_TOTAL_BYTES", 20 * 1024 * 1024
            ),
        )
