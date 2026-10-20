"""Bounded, read-only report-material references; no semantic or disclosure verdict.

Only the index is read. Attachments are inspected with non-following metadata calls.
No application settings, network clients, report writers or executors are imported.
"""

from __future__ import annotations

import argparse
import json
import ntpath
import os
import re
import stat
import sys
import unicodedata
from contextlib import contextmanager
from pathlib import Path

MAX_INDEX_BYTES = 1024 * 1024
MAX_FINDINGS = 256
MAX_REFERENCES = 4096
MAX_ATTACHMENT_BYTES = 64 * 1024 * 1024
MAX_TOTAL_ATTACHMENT_BYTES = 256 * 1024 * 1024
SCOPE = "report-materials-check"
REQUIRED_FIELDS = (
    "source_excerpt", "description_and_cwe", "trigger_and_path", "poc_source",
    "reproduction_instructions", "impact_modules_and_versions", "remediation",
    "maintainer_review",
)
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")
_DEVICE = re.compile(r"(?:CON|PRN|AUX|NUL|COM[0-9¹²³]|LPT[0-9¹²³])(?:\..*)?\Z", re.I)
_STATES = ("known", "no-match-recorded", "not-assessed")


class CheckError(ValueError):
    """Only constant codes, never raw input or exception text, cross the boundary."""


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise CheckError("invalid_arguments")


def _is_link(metadata):
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & 0x400)


def _absolute(path):
    # Do not resolve links away before checking them.
    value = os.fspath(path)
    if any(unicodedata.category(c) in ("Cc", "Cf", "Cs") for c in value):
        raise CheckError("invalid_path")
    if os.name == "nt" and value.startswith(("\\\\", "//")):
        raise CheckError("network_or_device_path")
    return Path(os.path.abspath(path))


def _validate_windows_output_path(path):
    """Reject device/stream aliases before Win32 normalization can hide them."""
    drive, tail = ntpath.splitdrive(os.fspath(path))
    if drive and re.fullmatch(r"[A-Za-z]:", drive) is None:
        raise CheckError("invalid_output_path")
    for component in re.split(r"[\\/]", tail):
        if component in ("", ".", ".."):
            continue
        stem = component.split(".", 1)[0].strip(" ")
        if (any(c in ':<>"|?*' or unicodedata.category(c) in ("Cc", "Cf", "Cs")
                for c in component)
                or component[-1] in " ." or component.startswith(" ")
                or _DEVICE.fullmatch(stem) or stem.upper() in ("CONIN$", "CONOUT$")):
            raise CheckError("invalid_output_path")


def _output_absolute(path):
    if os.name == "nt":
        _validate_windows_output_path(path)
    return _absolute(path)


@contextmanager
def _windows_handle(path, *, directory=False):
    """Open the reparse point itself; hold ancestors against writes/deletion.

    CreateFile + OPEN_REPARSE_POINT is needed because Python's O_NOFOLLOW is
    unavailable on Windows. No attachment data handle is ever requested.
    """
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                       wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = (wintypes.HANDLE,)
    close.restype = wintypes.BOOL
    info = kernel.GetFileInformationByHandleEx
    info.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
    info.restype = wintypes.BOOL

    class Attributes(ctypes.Structure):
        _fields_ = [("attributes", wintypes.DWORD), ("tag", wintypes.DWORD)]

    access = 0x80 if directory else 0x80000000  # metadata / index GENERIC_READ
    handle = create(str(path), access, 1, None, 3, 0x02200000, None)
    if handle == wintypes.HANDLE(-1).value:
        raise OSError("file_access_error")
    try:
        attrs = Attributes()
        if not info(handle, 9, ctypes.byref(attrs), ctypes.sizeof(attrs)):
            raise OSError("file_access_error")
        if attrs.attributes & 0x400:
            raise CheckError("link_or_reparse_point")
        if bool(attrs.attributes & 0x10) != directory:
            raise CheckError("not_directory" if directory else "not_regular_file")
        yield handle
    finally:
        close(handle)


@contextmanager
def _directory_handle(path):
    """Anchor each directory traversal; reject links in all absolute ancestors."""
    path = _absolute(path)
    if os.name == "nt":
        from contextlib import ExitStack

        with ExitStack() as stack:
            current = Path(path.anchor)
            stack.enter_context(_windows_handle(current, directory=True))
            for part in path.parts[1:]:
                current = current / part
                stack.enter_context(_windows_handle(current, directory=True))
            yield None
        return

    descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            metadata = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            if _is_link(metadata):
                raise CheckError("link_or_reparse_point")
            if not stat.S_ISDIR(metadata.st_mode):
                raise CheckError("not_directory")
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor
    finally:
        os.close(descriptor)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CheckError("duplicate_json_key")
        result[key] = value
    return result


def _nonfinite(value):
    raise CheckError("invalid_json_number")


def _load_index(path):
    path = _absolute(path)
    with _directory_handle(path.parent) as parent:
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            with _windows_handle(path) as handle:
                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                read = kernel.ReadFile
                read.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                                 ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID)
                read.restype = wintypes.BOOL
                buffer = ctypes.create_string_buffer(MAX_INDEX_BYTES + 1)
                count = wintypes.DWORD()
                if not read(handle, buffer, MAX_INDEX_BYTES + 1, ctypes.byref(count), None):
                    raise OSError("index_read_error")
                raw = buffer.raw[:count.value]
        else:
            metadata = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if _is_link(metadata):
                raise CheckError("link_or_reparse_point")
            if not stat.S_ISREG(metadata.st_mode):
                raise CheckError("not_regular_file")
            descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 dir_fd=parent)
            with os.fdopen(descriptor, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise CheckError("not_regular_file")
                raw = stream.read(MAX_INDEX_BYTES + 1)
    if len(raw) > MAX_INDEX_BYTES:
        raise CheckError("index_size_budget")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                          parse_constant=_nonfinite)
    except CheckError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise CheckError("invalid_json") from None


def _relative(value):
    if not isinstance(value, str) or not value or len(value) > 1024:
        return False
    if any(unicodedata.category(c) in ("Cc", "Cf", "Cs") or c in '\\:<>"|?*'
           for c in value):
        return False
    parts = value.split("/")
    return len(parts) <= 32 and all(
        part not in ("", ".", "..") and part[-1] not in " ."
        and not _DEVICE.fullmatch(part) for part in parts)


def _reference_metadata(root, relative):
    path = root.joinpath(*relative.split("/"))
    with _directory_handle(path.parent) as parent:
        metadata = (path.lstat() if parent is None else
                    os.stat(path.name, dir_fd=parent, follow_symlinks=False))
        if _is_link(metadata):
            raise CheckError("link_or_reparse_point")
        if not stat.S_ISREG(metadata.st_mode):
            raise CheckError("not_regular_file")
        if metadata.st_size == 0:
            raise CheckError("empty_file")
        if metadata.st_size > MAX_ATTACHMENT_BYTES:
            raise CheckError("attachment_size_budget")
        return metadata.st_size


def _new_report():
    return {"schema_version": 1, "scope": SCOPE, "case_label": None,
            "fields_complete": False, "per_finding_missing": [], "input_errors": [],
            "diagnostics": [], "semantic_verification": "not-performed",
            "disclosure_approval": "not-checked"}


def _error(report, location, code):
    report["input_errors"].append({"location": location, "code": code})


def _identifier(value):
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _validate(document, root, report, root_valid):
    if not isinstance(document, dict):
        _error(report, "#", "expected_object")
        return
    top_fields = {"schema_version", "scope", "case_label", "findings"}
    if set(document) - top_fields:
        _error(report, "#", "unknown_fields")
    if type(document.get("schema_version")) is not int or document["schema_version"] != 1:
        _error(report, "#/schema_version", "expected_schema_version_1")
    if document.get("scope") != SCOPE:
        _error(report, "#/scope", "invalid_scope")
    if _identifier(document.get("case_label")):
        report["case_label"] = document["case_label"]
    else:
        _error(report, "#/case_label", "invalid_identifier")
    findings = document.get("findings")
    if not isinstance(findings, list) or not findings:
        _error(report, "#/findings", "expected_nonempty_array")
        return
    if len(findings) > MAX_FINDINGS:
        _error(report, "#/findings", "finding_count_budget")
        return

    seen = set()
    cached = {}
    reference_count = 0
    total_size = 0
    for number, finding in enumerate(findings):
        location = f"#/findings/{number}"
        if not isinstance(finding, dict):
            _error(report, location, "expected_object")
            continue
        allowed = {"finding_id", "field_refs", "cve_status", "cve_ids", "evidence_ref",
                   "severity", "execution_record_ref"}
        if set(finding) - allowed:
            _error(report, location, "unknown_fields")
        identity = finding.get("finding_id")
        if not _identifier(identity):
            _error(report, location + "/finding_id", "invalid_identifier")
            identity = None
        elif identity in seen:
            _error(report, location + "/finding_id", "duplicate_finding_id")
        else:
            seen.add(identity)
        status = finding.get("cve_status")
        if status not in _STATES:
            _error(report, location + "/cve_status", "invalid_cve_status")
            status = None
        row = {"finding_id": identity, "finding_index": number, "cve_status": status,
               "missing": [], "severity_status": "pending", "execution_record_status": "pending"}
        report["per_finding_missing"].append(row)

        def missing(field, reason):
            row["missing"].append({"field": field, "reason": reason})

        def reference(field, value, pointer):
            nonlocal reference_count, total_size
            reference_count += 1
            if reference_count > MAX_REFERENCES:
                reason = "reference_budget"
            elif not _relative(value):
                reason = "invalid_relative_path"
            elif not root_valid:
                reason = "invalid_root"
            elif value in cached:
                reason = cached[value]
            else:
                try:
                    size = _reference_metadata(root, value)
                    if total_size + size > MAX_TOTAL_ATTACHMENT_BYTES:
                        reason = "total_size_budget"
                    else:
                        total_size += size
                        reason = None
                except CheckError as exc:
                    reason = str(exc)
                except FileNotFoundError:
                    reason = "missing_file"
                except PermissionError:
                    reason = "file_access_denied"
                except OSError:
                    reason = "file_access_error"
                cached[value] = reason
            if reason:
                missing(field, reason)
                report["diagnostics"].append({"location": pointer, "code": reason})
            return reason is None

        refs = finding.get("field_refs")
        if not isinstance(refs, dict):
            _error(report, location + "/field_refs", "expected_object")
            refs = {}
        elif set(refs) - set(REQUIRED_FIELDS):
            _error(report, location + "/field_refs", "unknown_fields")
        for field in REQUIRED_FIELDS:
            if field not in refs:
                missing(field, "missing_field")
            else:
                reference(field, refs[field], location + "/field_refs/" + field)
        ids = finding.get("cve_ids", [])
        valid_ids = (isinstance(ids, list) and len(ids) <= 128
                     and all(isinstance(item, str) and len(item) <= 128
                             and _CVE.fullmatch(item) for item in ids))
        if valid_ids and len(set(ids)) != len(ids):
            valid_ids = False
        if not valid_ids or (status == "known" and not ids):
            missing("cve_ids", "invalid_cve_ids")
        elif status != "known" and ids:
            _error(report, location + "/cve_ids", "ids_require_known_status")
        if "evidence_ref" in finding:
            reference("evidence_ref", finding["evidence_ref"], location + "/evidence_ref")
        elif status == "known":
            missing("evidence_ref", "missing_field")
        if "severity" in finding:
            severity = finding["severity"]
            if (isinstance(severity, str) and severity.strip() and len(severity) <= 128
                    and all(ord(c) >= 32 and ord(c) != 127 for c in severity)):
                row["severity_status"] = "provided"
            else:
                _error(report, location + "/severity", "invalid_severity_text")
        else:
            report["diagnostics"].append({"location": location + "/severity",
                                          "code": "severity_pending"})
        if "execution_record_ref" in finding:
            if reference("execution_record_ref", finding["execution_record_ref"],
                         location + "/execution_record_ref"):
                row["execution_record_status"] = "provided"
        else:
            report["diagnostics"].append({"location": location + "/execution_record_ref",
                                          "code": "execution_record_pending"})
    report["fields_complete"] = (not report["input_errors"] and root_valid
                                 and not any(row["missing"] for row in report["per_finding_missing"]))


def _validate_output(output, root, index):
    if os.name == "nt":
        _validate_windows_output_path(output)
    if output == index:
        raise CheckError("output_is_input")
    try:
        common = os.path.commonpath([output, root])
    except ValueError:
        # Different Windows drives cannot overlap.
        common = None
    if common is not None and os.path.normcase(common) == os.path.normcase(str(root)):
        raise CheckError("output_inside_material_root")
    with _directory_handle(output.parent):
        if os.path.lexists(output):
            raise CheckError("output_already_exists")


def _write_report(output, report):
    output = _output_absolute(output)
    payload = (json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode()
    with _directory_handle(output.parent) as parent:
        kwargs = {} if parent is None else {"dir_fd": parent}
        target = output if parent is None else output.name
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | getattr(os, "O_BINARY", 0), 0o600, **kwargs)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise CheckError("output_not_regular_file")
                stream.write(payload)
        except (CheckError, OSError):
            # Only a file created by this call is eligible for cleanup.
            try:
                os.unlink(target, **kwargs)
            except OSError:
                pass
            raise


def main(argv=None):
    parser = Parser(description="Check report fields and attachment metadata only.")
    parser.add_argument("--index", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--output", required=True)
    try:
        args = parser.parse_args(argv)
        index, root = map(_absolute, (args.index, args.root))
        output = _output_absolute(args.output)
        _validate_output(output, root, index)
    except (CheckError, OSError, ValueError):
        print("report-materials-check: usage_or_output_error", file=sys.stderr)
        return 3
    report = _new_report()
    root_valid = True
    try:
        with _directory_handle(root):
            pass
    except CheckError as exc:
        root_valid = False
        _error(report, "root", str(exc))
    except OSError:
        root_valid = False
        _error(report, "root", "root_access_error")
    try:
        document = _load_index(index)
        _validate(document, root, report, root_valid)
    except CheckError as exc:
        _error(report, "#", str(exc))
    except OSError:
        _error(report, "#", "index_access_error")
    try:
        _write_report(output, report)
    except (CheckError, OSError, ValueError):
        print("report-materials-check: output_error", file=sys.stderr)
        return 3
    print("report-materials-check: fields_complete=" + str(report["fields_complete"]).lower()
          + "; semantic_verification=not-performed; disclosure_approval=not-checked")
    return 0 if report["fields_complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
