"""Read-only projection of competition-validation coverage records (E04).

This module uses only the standard library. It neither validates bundle hashes
nor derives a scan denominator, a vulnerability verdict, or a detection rate.
"""

from __future__ import annotations

import argparse
import html
import json
import math
import sys
from pathlib import Path
from typing import Any

_GAP_PREFIX = "coverage gap: "
_PROJECTED = ("file_coverage", "byte_coverage", "unreviewed_units", "diagnostics")
_SEMANTIC_NOTE = (
    "当前 bundle 未记录可靠的 TU 总数和已审阅 TU 数，无法计算；"
    "不从 case.translation_units、finding 数或空未审阅列表推断。"
)


class CoverageInputError(ValueError):
    """Invalid input, with file names and JSON pointers for manual inspection."""


def _pointer(key: str) -> str:
    return key.replace("~", "~0").replace("/", "~1")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON field: {key!r}")
        document[key] = value
    return document


def _check_finite(value: Any, source: str, errors: list[str]) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        errors.append(f"{source}: expected a finite JSON number")
    elif isinstance(value, dict):
        for key, child in value.items():
            _check_finite(child, f"{source}/{_pointer(key)}", errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_finite(child, f"{source}/{index}", errors)


def _read_document(
    bundle: Path, relative: str, errors: list[str], *, required: bool = False,
) -> dict[str, Any] | None:
    source = f"{relative}#"
    try:
        text = (bundle / relative).read_text(encoding="utf-8")
    except FileNotFoundError:
        if required:
            errors.append(f"{source}: required file is missing")
        return None
    except (OSError, UnicodeError) as exc:
        errors.append(f"{source}: cannot read UTF-8 JSON ({type(exc).__name__})")
        return None
    try:
        document = json.loads(text, object_pairs_hook=_unique_object)
    except (ValueError, RecursionError) as exc:
        errors.append(f"{source}: invalid JSON ({exc})")
        return None
    if not isinstance(document, dict):
        errors.append(f"{source}: expected a JSON object")
        return None
    _check_finite(document, source, errors)
    return document


def _validate_fields(document: dict[str, Any], source: str, errors: list[str]) -> None:
    for key in _PROJECTED:
        value = document.get(key)
        if value is None:
            continue
        location = f"{source}/{key}"
        if key in ("file_coverage", "byte_coverage"):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not 0 <= value <= 1
            ):
                errors.append(f"{location}: expected a finite ratio between 0 and 1 or null")
        elif not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            errors.append(f"{location}: expected an array of strings or null")


def _same_json(left: Any, right: Any) -> bool:
    # JSON true must not compare equal to 1; numeric 1 and 1.0 do agree.
    if type(left) is not type(right):
        return (
            type(left) in (int, float) and type(right) in (int, float) and left == right
        )
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _same_json(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _same_json(a, b) for a, b in zip(left, right, strict=True)
        )
    return left == right


def _side_summary(
    side: str, summary: dict[str, Any], platform: dict[str, Any] | None, errors: list[str],
) -> dict[str, Any]:
    embedded = summary.get(side, {})
    summary_source = f"summary.json#/{side}"
    platform_source = f"{side}/platform.json#"
    if not isinstance(embedded, dict):
        errors.append(f"{summary_source}: expected a JSON object")
        embedded = {}
    _validate_fields(embedded, summary_source, errors)
    if platform is not None:
        _validate_fields(platform, platform_source, errors)
        for key in sorted(embedded.keys() & platform.keys()):
            if not _same_json(embedded[key], platform[key]):
                escaped = _pointer(key)
                errors.append(
                    f"conflicting field: {summary_source}/{escaped} != "
                    f"{platform_source}/{escaped}"
                )

    values: dict[str, Any] = {}
    input_sources: dict[str, list[str]] = {}
    for key in _PROJECTED:
        candidates = [
            (document[key], f"{source}/{key}")
            for document, source in ((embedded, summary_source), (platform, platform_source))
            if document is not None and key in document
        ]
        values[key] = candidates[0][0] if candidates else None
        input_sources[key] = [source for _value, source in candidates]

    units = values["unreviewed_units"]
    diagnostics = values["diagnostics"]
    # Avoid deriving from malformed values while collecting all input errors.
    valid_units = isinstance(units, list) and all(isinstance(unit, str) for unit in units)
    valid_diagnostics = isinstance(diagnostics, list) and all(
        isinstance(item, str) for item in diagnostics
    )
    gaps = sorted({
        item[len(_GAP_PREFIX):] for item in diagnostics if item.startswith(_GAP_PREFIX)
    }) if valid_diagnostics else None
    result = {
        "snapshot_file_coverage": values["file_coverage"],
        "snapshot_byte_coverage": values["byte_coverage"],
        "unreviewed_units": units,
        "unreviewed_count": len(units) if valid_units else None,
        "expected_tu_count": None,
        "reviewed_tu_count": None,
        "semantic_review_coverage": None,
        "coverage_gaps": gaps,
        "coverage_gap_count": len(gaps) if gaps is not None else None,
        "diagnostics": [
            item for item in diagnostics if not item.startswith(_GAP_PREFIX)
        ] if valid_diagnostics else None,
    }
    mapping = {
        "snapshot_file_coverage": "file_coverage",
        "snapshot_byte_coverage": "byte_coverage",
        "unreviewed_units": "unreviewed_units",
        "unreviewed_count": "unreviewed_units",
        "coverage_gaps": "diagnostics",
        "coverage_gap_count": "diagnostics",
        "diagnostics": "diagnostics",
    }
    result["field_sources"] = {
        key: list(input_sources[mapping[key]]) if key in mapping else [] for key in result
    }
    result["field_notes"] = {
        key: _SEMANTIC_NOTE if key in (
            "expected_tu_count", "reviewed_tu_count", "semantic_review_coverage",
        ) else "未记录（字段缺失或明确为 null）。"
        for key, value in result.items() if value is None
    }
    return result


def summarize_bundle(bundle: str | Path) -> dict[str, Any]:
    """Project summary and optional platform files; reject corruption/conflicts.

    Missing coverage fields remain null; the summary file itself is required.
    Unknown input fields are ignored after comparing any duplicated side fields.
    No other file (including case.json or executable artifacts) is read.
    """
    root = Path(bundle)
    errors: list[str] = []
    summary = _read_document(root, "summary.json", errors, required=True)
    summary = summary if summary is not None else {}
    for key in ("case_id", "status"):
        if summary.get(key) is not None and not isinstance(summary[key], str):
            errors.append(f"summary.json#/{key}: expected a string or null")
    report: dict[str, Any] = {
        "schema_version": 1,
        "case_id": summary.get("case_id"),
        "validation_status": summary.get("status"),
        "field_sources": {
            "schema_version": [],
            "case_id": ["summary.json#/case_id"] if "case_id" in summary else [],
            "validation_status": ["summary.json#/status"] if "status" in summary else [],
        },
    }
    for side in ("vulnerable", "fixed"):
        platform = _read_document(root, f"{side}/platform.json", errors)
        report[side] = _side_summary(side, summary, platform, errors)
    if errors:
        raise CoverageInputError("\n".join(errors))
    return report


def _markdown_text(value: Any) -> str:
    text = "未记录" if value is None else str(value)
    text = html.escape(text, quote=True).replace("\r", "&#13;").replace("\n", "&#10;")
    # Bundle strings must not create HTML, table columns, links, or formatting.
    for character in "\\`*_{}[]()#+-.!|>":
        text = text.replace(character, f"&#{ord(character)};")
    return text


def _percent(value: Any) -> str:
    return "未记录" if value is None else f"{value * 100:.6f}".rstrip("0").rstrip(".") + "%"


def render_markdown(report: dict[str, Any]) -> str:
    """Render the same projection used by JSON; percentages are presentation only."""
    lines = [
        "# 覆盖记录摘要",
        "",
        f"case_id：{_markdown_text(report['case_id'])}",
        f"validation_status：{_markdown_text(report['validation_status'])}",
        f"schema_version：{report['schema_version']}（本工具输出版本）",
        "",
        "仅描述覆盖记录并保留原验证状态。快照读取比例不代表语义审阅覆盖率，"
        "也不能证明零漏报。gap 数量表示记录的 gap 种类数，不是受影响 TU 数。",
        "",
        "| 字段 | vulnerable | fixed |",
        "| --- | --- | --- |",
    ]
    for label, key, percentage in (
        ("快照文件覆盖率", "snapshot_file_coverage", True),
        ("快照字节覆盖率", "snapshot_byte_coverage", True),
        ("未审阅条目数", "unreviewed_count", False),
        ("预期 TU 数", "expected_tu_count", False),
        ("已审阅 TU 数", "reviewed_tu_count", False),
        ("语义审阅覆盖率", "semantic_review_coverage", False),
        ("记录的 gap 种类数", "coverage_gap_count", False),
    ):
        rendered = []
        for side in ("vulnerable", "fixed"):
            value = report[side][key]
            rendered.append(
                "不可计算（未记录可靠 TU 分母）" if key == "semantic_review_coverage"
                else _percent(value) if percentage else _markdown_text(value)
            )
        lines.append(f"| {label} | {rendered[0]} | {rendered[1]} |")
    lines.extend(["", "根字段来源："])
    for key, sources in report["field_sources"].items():
        if key != "schema_version":
            lines.append(f"- {key}：{', '.join(sources) or '未记录'}")
    for side in ("vulnerable", "fixed"):
        data = report[side]
        lines.extend(["", f"## {side}", ""])
        for label, key in (("未审阅条目", "unreviewed_units"),
                           ("gap 原始 code", "coverage_gaps"), ("其他诊断", "diagnostics")):
            value = data[key]
            lines.append(f"{label}：" + (
                "未记录" if value is None
                else _markdown_text(json.dumps(value, ensure_ascii=False))
            ))
        lines.extend(["", "| 字段 | 来源（JSON Pointer） |", "| --- | --- |"])
        for key, sources in data["field_sources"].items():
            lines.append(f"| {key} | {', '.join(sources) or '无可用来源'} |")
        lines.append("")
        for key, note in data["field_notes"].items():
            lines.append(f"- {key}：{note}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    """Shared CLI for the standalone script and package-only test images."""
    parser = argparse.ArgumentParser(description="Summarize one evidence bundle offline.")
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    args = parser.parse_args(argv)
    try:
        report = summarize_bundle(args.bundle)
    except CoverageInputError as exc:
        print(f"coverage_input_error:\n{exc}", file=sys.stderr)
        return 2
    output = (
        json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.format == "json" else render_markdown(report)
    )
    sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    raise SystemExit(main())
