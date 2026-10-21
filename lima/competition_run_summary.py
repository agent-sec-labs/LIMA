"""Read-only projection of explicitly selected competition runs (Issue #312).

No writer, detector, model, performance collector, or integrity verifier is imported.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import io
import json
import math
import os
import sys
from collections import Counter
from pathlib import Path

SIDES = ("vulnerable", "fixed")
MISSING = object()
MAX_BYTES = 16 * 1024 * 1024
PERFORMANCE_FIELDS = {
    "performance_wall_time_seconds": ("wall_time_seconds",),
    "host_sampled_peak_rss_bytes": ("host", "sampled_peak_rss_bytes"),
    "host_measurement_source": ("host", "measurement_source"),
    "host_sampling_complete": ("host", "complete"),
    "container_sampled_peak_memory_bytes": ("container", "sampled_peak_memory_bytes"),
    "container_sampled_peak_cpu_percent": ("container", "sampled_peak_cpu_percent"),
    "container_measurement_source": ("container", "measurement_source"),
    "container_sampling_complete": ("container", "complete"),
    "performance_partial": ("partial",),
}
FIELDS = (
    "run_label", "row_status", "case_id", "vulnerable_commit", "fixed_commit",
    "validation_status", "vulnerable_validation_status", "fixed_validation_status",
    "vulnerable_findings_by_state", "fixed_findings_by_state", "reason_codes",
    "vulnerable_diagnostics", "fixed_diagnostics", "total_elapsed_seconds",
    "execution_label", "execution_mode", "model_identity", *PERFORMANCE_FIELDS,
    "summary_ref", "summary_sha256", "performance_ref", "field_sources", "unknown_reasons",
)
SIDE_FIELDS = (
    "commit", "status", "findings", "diagnostics", "reason_codes", "snapshot_hash",
    "file_coverage", "byte_coverage", "budget_usage", "elapsed_seconds", "unreviewed_units",
    "execution_mode", "model_identity",
)


class InputError(ValueError):
    """Only controlled codes and logical references cross the CLI boundary."""

    def __init__(self, code, ref, field=None):
        super().__init__(code)
        self.code, self.ref, self.field = code, ref, field

    def record(self, label):
        return {"run_label": label, "code": self.code, "ref": self.ref, "field": self.field}


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def _finite(value):
    if isinstance(value, str):
        value.encode("utf-8")  # Reject escaped lone surrogates before rendering UTF-8.
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non_finite_number")
    if isinstance(value, dict):
        for key, item in value.items():
            key.encode("utf-8")
            _finite(item)
    elif isinstance(value, list):
        for item in value:
            _finite(item)


def _decode(raw, ref):
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
        _finite(value)
    except (UnicodeError, ValueError, RecursionError):
        raise InputError("invalid_json_or_duplicate_key", ref) from None
    if not isinstance(value, dict):
        raise InputError("object_required", ref)
    return value


def _read(path, ref, *, optional=False, bundle_root=None):
    if optional and not os.path.lexists(path):
        return None
    if bundle_root is not None and not path.resolve().is_relative_to(bundle_root):
        raise InputError("evidence_path_escape", ref)
    try:
        if not path.is_file():
            raise OSError("regular file required")
        with path.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
    except OSError:
        raise InputError("file_unavailable", ref) from None
    if len(raw) > MAX_BYTES:
        raise InputError("file_too_large", ref)
    return raw


def _document(path, ref, **kwargs):
    raw = _read(path, ref, **kwargs)
    return {} if raw is None else _decode(raw, ref)


def _text(value, ref, field):
    if value is not None and (not isinstance(value, str) or not value.strip()):
        raise InputError("nonempty_text_required", ref, field)
    return value


def _number(value, ref, field):
    if value is not None and (
        isinstance(value, bool) or not isinstance(value, (int, float))
        or (isinstance(value, float) and not math.isfinite(value)) or value < 0
    ):
        raise InputError("nonnegative_finite_number_required", ref, field)
    return value


def _strings(value, ref, field):
    if value is not None and (
        not isinstance(value, list) or any(not isinstance(v, str) for v in value)
    ):
        raise InputError("text_array_required", ref, field)
    return value


def _object(parent, key, ref):
    value = parent.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise InputError("object_required", ref, key)
    return value


def _json_equal(left, right):
    """Compare JSON values, retaining types except equivalent numeric spellings."""
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _json_equal(value, right[key]) for key, value in left.items())
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _json_equal(a, b) for a, b in zip(left, right, strict=True))
    return left == right


def _agree(candidates, field):
    present = [(value, ref) for value, ref in candidates if value is not MISSING]
    if not present:
        return None, []
    first = present[0][0]
    for value, ref in present[1:]:
        if not _json_equal(value, first):
            raise InputError("field_conflict", ref, field)
    return present[0][0], [ref for _, ref in present]


def _empty_row(label):
    row = dict.fromkeys(FIELDS)
    row.update(run_label=label, row_status="parsed", execution_mode="unknown",
               model_identity="unknown", field_sources={}, unknown_reasons={})
    return row


def _set(row, field, value, sources, reason="not_recorded"):
    row[field] = value
    row["field_sources"][field] = sources
    if value is None:
        row["unknown_reasons"][field] = reason


def _project_bundle(row, root):
    ref = f"bundle:{row['run_label']}/"
    row["summary_ref"] = ref + "summary.json"
    raw = _read(root / "summary.json", ref + "summary.json", bundle_root=root)
    row["summary_sha256"] = hashlib.sha256(raw).hexdigest()
    summary = _decode(raw, ref + "summary.json")
    case = _document(root / "case.json", ref + "case.json", optional=True, bundle_root=root)
    identity, sources = _agree([
        (doc.get("case_id", MISSING), ref + file + "#/case_id")
        for doc, file in ((summary, "summary.json"), (case, "case.json"))], "case_id")
    _set(row, "case_id", _text(identity, ref + "case.json", "case_id"), sources)
    status, sources = _agree([
        (summary.get(field, MISSING), ref + "summary.json#/" + field)
        for field in ("status", "validation_status")], "validation_status")
    _set(row, "validation_status", _text(status, ref + "summary.json", "status"), sources)
    for field, validate in (("reason_codes", _strings), ("total_elapsed_seconds", _number),
                            ("execution_mode", _text), ("model_identity", _text)):
        value = validate(summary.get(field), ref + "summary.json", field)
        _set(row, field, value, [ref + "summary.json#/" + field] if field in summary else [])
        if value is None and field in ("execution_mode", "model_identity"):
            row[field] = "unknown"
    for side in SIDES:
        summary_side = _object(summary, side, ref + "summary.json")
        case_side = _object(case, side, ref + "case.json")
        platform = _document(root / side / "platform.json", ref + side + "/platform.json",
                             optional=True, bundle_root=root)
        merged, origins = {}, {}
        for field in SIDE_FIELDS:
            candidates = [
                (summary_side.get(field, MISSING), ref + f"summary.json#/{side}/{field}"),
                (platform.get(field, MISSING), ref + f"{side}/platform.json#/{field}"),
            ]
            if field == "commit":
                candidates.append((case_side.get("commit", MISSING),
                                   ref + f"case.json#/{side}/commit"))
            merged[field], origins[field] = _agree(candidates, f"{side}/{field}")
        for field, source, validate in (
            (f"{side}_commit", "commit", _text),
            (f"{side}_validation_status", "status", _text),
            (f"{side}_diagnostics", "diagnostics", _strings),
        ):
            _set(row, field, validate(merged[source], ref + side + "/platform.json", source),
                 origins[source])
        findings = merged["findings"]
        counts = None
        if findings is not None:
            if not isinstance(findings, list):
                raise InputError("findings_array_required", ref + side + "/platform.json", "findings")
            counts = Counter()
            for finding in findings:
                if not isinstance(finding, dict):
                    raise InputError("finding_object_required", ref + side + "/platform.json", "findings")
                state = _text(finding.get("state"), ref + side + "/platform.json", "findings/state")
                if state is None:
                    raise InputError("finding_state_required", ref + side + "/platform.json", "findings/state")
                counts[state] += 1
            counts = dict(sorted(counts.items()))
        _set(row, f"{side}_findings_by_state", counts, origins["findings"])


def _project_performance(row, path):
    ref = "performance:" + row["run_label"]
    reason = "performance_not_provided"
    data = {}
    _set(row, "performance_ref", ref if path is not None else None,
         ["inputs#performance_file"] if path is not None else [], "performance_not_provided")
    if path is not None:
        try:
            data = _decode(_read(path, ref), ref)
        except InputError as exc:
            if exc.code != "file_unavailable":
                raise
            reason = "performance_unavailable"
        else:
            version = data.get("schema_version")
            if type(version) is not int or version != 1:
                data, reason = {}, "performance_schema_unsupported"
            else:
                reason = "not_recorded"
    for field, parts in PERFORMANCE_FIELDS.items():
        value = data
        for part in parts:
            if value is None:
                break
            if not isinstance(value, dict):
                raise InputError("object_required", ref, "/".join(parts))
            value = value.get(part)
        source = [ref + "#/" + "/".join(parts)] if value is not None else []
        if field.endswith(("_source",)):
            _text(value, ref, "/".join(parts))
        elif field.endswith(("_complete", "_partial")):
            if value is not None and not isinstance(value, bool):
                raise InputError("boolean_required", ref, "/".join(parts))
        else:
            _number(value, ref, "/".join(parts))
        _set(row, field, value, source, reason)


def _manifest(path, output):
    data = _document(path, "inputs")
    if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        raise InputError("manifest_schema_unsupported", "inputs", "schema_version")
    runs = data.get("runs")
    if not isinstance(runs, list) or not runs:
        raise InputError("nonempty_runs_array_required", "inputs", "runs")
    entries, labels, roots, performance_paths = [], set(), {}, {}
    for index, run in enumerate(runs):
        if not isinstance(run, dict):
            raise InputError("run_object_required", "inputs", f"runs/{index}")
        label = _text(run.get("run_label"), "inputs", "run_label")
        location = _text(run.get("bundle_dir"), "inputs", "bundle_dir")
        if label is None or location is None:
            raise InputError("run_label_and_bundle_dir_required", "inputs", f"runs/{index}")
        if label in labels:
            raise InputError("duplicate_run_label", "run:" + label)
        labels.add(label)
        root = (path.parent / location).resolve()
        if root in roots:
            raise InputError("duplicate_bundle_path", "runs:" + roots[root] + "," + label)
        roots[root] = label
        performance = run.get("performance_file")
        if performance is not None:
            _text(performance, "run:" + label, "performance_file")
            performance = (path.parent / performance).resolve()
            if performance in performance_paths:
                raise InputError("duplicate_performance_path",
                                 "runs:" + performance_paths[performance] + "," + label)
            performance_paths[performance] = label
        execution = _text(run.get("execution_label"), "run:" + label, "execution_label")
        if (output.is_relative_to(root) or root.is_relative_to(output)
            or path.is_relative_to(output)
            or (performance is not None and performance.is_relative_to(output))):
            raise InputError("output_overlaps_input", "run:" + label)
        entries.append((label, root, performance, execution))
    return sorted(entries, key=lambda entry: entry[0])


def _cell(value):
    if value is None or isinstance(value, (dict, list, bool)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return str(value)


def _csv_cell(value):
    cell = _cell(value)
    return "'" + cell if isinstance(value, str) and cell.startswith(("=", "+", "-", "@", "\t")) else cell


def _md_cell(value):
    return (html.escape(_cell(value)).replace("\\", "&#92;").replace("|", "\\|")
            .replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br>"))


def _publish(output, rows, errors):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(FIELDS)
    writer.writerows([_csv_cell(row[field]) for field in FIELDS] for row in rows)
    markdown = (
        "# Competition run summary\n\n"
        "One row per explicitly selected run; original statuses and finding states are retained. "
        "The complete bundle is not verified. summary_sha256 identifies only the raw summary.json "
        "bytes read for this table. Unknown values have reasons; sampling is optional.\n\n"
        + "| " + " | ".join(FIELDS) + " |\n| " + " | ".join("---" for _ in FIELDS) + " |\n"
        + "".join("| " + " | ".join(_md_cell(row[field]) for field in FIELDS) + " |\n" for row in rows)
    )
    documents = {"summary.csv": stream.getvalue(), "summary.md": markdown,
                 "errors.json": json.dumps({"schema_version": 1, "errors": errors},
                                            ensure_ascii=False, sort_keys=True, indent=2) + "\n"}
    created = []
    try:
        output.mkdir(parents=True, exist_ok=False)
        for name, content in documents.items():
            path = output / name
            with path.open("x", encoding="utf-8", newline="") as handle:
                created.append(path)
                handle.write(content)
    except OSError:
        # Only clean files created by this invocation; never unlink an existing output.
        for path in created:
            path.unlink(missing_ok=True)
        if created:
            output.rmdir()
        raise InputError("output_unavailable_or_exists", "output") from None


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise InputError("invalid_arguments", "usage")


def main(argv=None):
    parser = _Parser(description=__doc__)
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    try:
        options = parser.parse_args(argv)
        path, output = options.inputs.resolve(), options.output_dir.resolve()
        if os.path.lexists(options.output_dir):
            raise InputError("output_exists", "output")
        entries = _manifest(path, output)
    except (InputError, OSError, RuntimeError, ValueError) as exc:
        error = exc if isinstance(exc, InputError) else InputError("invalid_path", "inputs")
        print(json.dumps(error.record(None), ensure_ascii=True), file=sys.stderr)
        return 3
    rows, errors = [], []
    for label, root, performance, execution in entries:
        row = _empty_row(label)
        _set(row, "execution_label", execution, ["inputs#execution_label"] if execution else [])
        try:
            _project_bundle(row, root)
            _project_performance(row, performance)
        except (InputError, OSError, RuntimeError, ValueError) as exc:
            error = exc if isinstance(exc, InputError) else InputError("input_unavailable", "bundle:" + label)
            row["row_status"] = "error"
            errors.append(error.record(label))
            # Preserve fields already projected, and explain every remaining unknown.
            for field in FIELDS:
                if row[field] is None or (field in ("execution_mode", "model_identity")
                                          and row[field] == "unknown"):
                    row["unknown_reasons"].setdefault(field, "run_input_error")
        rows.append(row)
    try:
        _publish(output, rows, errors)
    except (InputError, OSError) as exc:
        error = exc if isinstance(exc, InputError) else InputError("output_write_failed", "output")
        print(json.dumps(error.record(None), ensure_ascii=True), file=sys.stderr)
        return 3
    return 2 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
