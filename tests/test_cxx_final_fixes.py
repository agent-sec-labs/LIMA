"""Final whole-branch security and contract regressions for C/C++ analysis."""

from __future__ import annotations

import copy
import errno
import hashlib
import importlib
import io
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

try:
    import resource
except ImportError:  # Windows hosts have no resource module.
    resource = None

from cxx_analyzer import sandbox
from cxx_analyzer.config import AnalyzerSettings
from cxx_analyzer.execution import ToolExecution, run_step
from cxx_analyzer.normalizers import NormalizedFinding, fuse_findings
from cxx_analyzer.snapshot import prepare_snapshot
from cxx_analyzer.source_scan import LayerResult, parse_semgrep_json, run_source_scan
from lima.cxx_memory import (
    CxxAnalyzerProtocolError,
    CxxMemoryAnalyzerClient,
    validate_response_metadata,
)
from lima.report import to_markdown
from lima.workspace import RepositoryWorkspace

REQUEST_ID = "00000000-0000-0000-0000-000000000001"


def prepared_snapshot(temporary: str):
    """Prepare one bounded snapshot for sandbox-exercising tests."""

    base = Path(temporary)
    repository = base / "imports" / "team" / "project"
    repository.mkdir(parents=True)
    (repository / "src").mkdir()
    (repository / "src" / "main.cpp").write_text(
        "int main() { return 0; }\n", encoding="utf-8"
    )
    work = base / "work"
    work.mkdir()
    fingerprint = RepositoryWorkspace(repository).inventory().fingerprint()
    return prepare_snapshot(base / "imports", "team/project", fingerprint, work)


def analyzer_settings(**changes: object) -> AnalyzerSettings:
    values: dict[str, object] = {
        "auto_cmake": True,
        "build_steps": (),
        "test_steps": (),
        "max_memory_mb": 1024,
        "max_processes": 32,
        "max_output_bytes": 8192,
        "step_timeout_seconds": 10,
        "total_timeout_seconds": 30,
        "repository_scan_max_files": 100,
        "repository_scan_max_file_bytes": 4096,
        "repository_scan_max_total_bytes": 16384,
    }
    values.update(changes)
    return AnalyzerSettings(**values)  # type: ignore[arg-type]


def tool_execution(
    status: str = "completed",
    *,
    returncode: int | None = 0,
    stdout: str = "",
    stderr: str = "",
    truncated: bool = False,
    complete: bool = True,
) -> ToolExecution:
    return ToolExecution(
        status=status,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        stdout_sha256="a" * 64 if complete else "",
        stderr_sha256="b" * 64 if complete else "",
        output_sha256="c" * 64 if complete else "",
        output_truncated=truncated,
        digests_complete=complete,
        diagnostic="",
    )


def normalized_finding(
    mode: str,
    *,
    path: str = "src/main.cpp",
    line: int = 1,
    symbol: str = "release",
) -> NormalizedFinding:
    contract = {
        "source-only": ("candidate", "semgrep"),
        "build-backed": ("build-verified", "clang"),
        "sanitizer-confirmed": ("confirmed", "asan"),
    }
    state, tool = contract[mode]
    return NormalizedFinding.create(
        rule_id=f"cxx.{tool}.double-free",
        severity="high",
        title="Potential double free",
        explanation="free called twice",
        path=path,
        line=line,
        evidence="free(p)",
        fix="",
        test="Exercise the path under AddressSanitizer.",
        confidence=0.8,
        cwe="CWE-415",
        tool=tool,
        evidence_kind="line",
        verification_state=state,
        language="c++",
        symbol=symbol,
        analysis_mode=mode,
        diagnostics=[],
    )


def valid_tool_run(tool: str = "semgrep", status: str = "completed") -> dict[str, object]:
    return {
        "tool": tool,
        "status": status,
        "returncode": 0,
        "output_sha256": "b" * 64,
        "output_truncated": False,
        "digests_complete": True,
    }


class FakeResponse(io.BytesIO):
    def __init__(self, payload: dict[str, object]):
        super().__init__(json.dumps(payload).encode("utf-8"))
        self.headers: dict[str, str] = {}

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> bool:
        return False


class FinalSnapshotSecurityTests(unittest.TestCase):
    def _snapshot(self, temporary: str):
        return prepared_snapshot(temporary)

    def test_verified_source_is_read_only_and_only_request_owned_roots_are_writable(self):
        """C1: mutating declared source must not be authorized by the OS policy."""

        with tempfile.TemporaryDirectory() as temporary:
            with self._snapshot(temporary) as snapshot:
                policy = sandbox.build_policy(snapshot.root, snapshot.writable_roots)
                source_rule = next(rule for rule in policy.rules if rule.path == snapshot.root)
                self.assertEqual(sandbox.READ_ONLY, source_rule.access)
                self.assertNotEqual(sandbox.READ_WRITE_TREE, source_rule.access)
                for rule in policy.rules:
                    if rule.access == sandbox.READ_WRITE_TREE:
                        self.assertTrue(
                            any(
                                rule.path == root or rule.path.is_relative_to(root)
                                for root in snapshot.writable_roots
                            ),
                            rule.path,
                        )
                snapshot.verify_inventory()

    @unittest.skipUnless(sys.platform == "linux", "real sandbox mutation test requires Linux")
    def test_tool_cannot_mutate_inventory_but_can_write_analyzer_build_output(self):
        """C1: the real child can write build output but inventory bytes stay immutable."""

        if sandbox.landlock_abi() < sandbox.MIN_LANDLOCK_ABI:
            self.skipTest("required Landlock ABI is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            with self._snapshot(temporary) as snapshot:
                code = (
                    "from pathlib import Path; "
                    "denied=False; "
                    "\ntry: Path('src/main.cpp').write_text('tampered')"
                    "\nexcept PermissionError: denied=True"
                    "\nPath('build/result.txt').write_text('ok')"
                    "\nraise SystemExit(0 if denied else 9)"
                )
                result = run_step(
                    [sys.executable, "-c", code], snapshot, ".", 10, 1024, {}
                )
                self.assertEqual("completed", result.status, result.stderr)
                self.assertIn("return 0", (snapshot.root / "src/main.cpp").read_text())
                self.assertEqual("ok", (snapshot.root / "build/result.txt").read_text())
                snapshot.verify_inventory()

    def test_each_snapshot_owns_distinct_private_scratch_and_environment(self):
        """C2: concurrent requests cannot share HOME, TMPDIR, rules, or tool output."""

        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            with self._snapshot(first) as left, self._snapshot(second) as right:
                self.assertNotEqual(left.scratch_root, right.scratch_root)
                execution = importlib.import_module("cxx_analyzer.execution")
                left_env = execution.clean_environment(left)
                right_env = execution.clean_environment(right)
                self.assertNotEqual(left_env["HOME"], right_env["HOME"])
                self.assertNotEqual(left_env["TMPDIR"], right_env["TMPDIR"])
                self.assertTrue(Path(left_env["HOME"]).is_relative_to(left.scratch_root))
                self.assertTrue(Path(left_env["TMPDIR"]).is_relative_to(left.scratch_root))
                self.assertNotIn("/work/tmp", left_env.values())

    @unittest.skipUnless(sys.platform == "linux", "descendant lifecycle test requires Linux")
    def test_success_failure_and_timeout_reap_all_descendants_even_after_setsid_attempt(self):
        """C2: no exit path leaves a delayed descendant alive."""

        if sandbox.landlock_abi() < sandbox.MIN_LANDLOCK_ABI:
            self.skipTest("required Landlock ABI is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            with self._snapshot(temporary) as snapshot:
                for name, leader_status, timeout in (
                    ("success", 0, 5),
                    ("failure", 7, 5),
                    ("timeout", None, 1),
                ):
                    marker = snapshot.scratch_root / f"{name}.txt"
                    code = (
                        "import os,time; "
                        "p=os.fork(); "
                        f"marker={str(marker)!r}; "
                        "\nif p==0:"
                        "\n try: os.setsid()"
                        "\n except PermissionError: pass"
                        "\n os.close(1); os.close(2); time.sleep(1.5); "
                        "open(marker,'w').write('survived'); os._exit(0)"
                        "\n"
                        + (
                            "time.sleep(5)"
                            if leader_status is None
                            else f"os._exit({leader_status})"
                        )
                    )
                    result = run_step(
                        [sys.executable, "-c", code], snapshot, ".", timeout, 1024, {}
                    )
                    if leader_status == 0:
                        self.assertEqual("completed", result.status)
                    elif leader_status is None:
                        self.assertEqual("timed-out", result.status)
                    else:
                        self.assertEqual("failed", result.status)
                    time.sleep(1.8)
                    self.assertFalse(marker.exists(), name)


def _proc_state(pid: int) -> str | None:
    """Return the scheduler state of a live pid, or None once it is gone."""

    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError:
        return None
    tail = stat.rsplit(")", 1)
    if len(tail) != 2:
        return None
    fields = tail[1].split()
    return fields[0] if fields else None


@unittest.skipUnless(sys.platform == "linux", "process isolation boundary requires Linux")
class ProcessIsolationTests(unittest.TestCase):
    """Residual 1: same-UID process control and orphan/zombie reaping."""

    _ESCAPE_TOOL = '''
import ctypes, os, resource, sys, time
from pathlib import Path

mode = sys.argv[1]
grand_marker = Path(sys.argv[2])
result_marker = Path(sys.argv[3])

pid = os.fork()
if pid == 0:
    staged = grand_marker.with_suffix(".staged")
    staged.write_text(str(os.getpid()), encoding="utf-8")
    staged.rename(grand_marker)
    for descriptor in (0, 1, 2):
        try:
            os.close(descriptor)
        except OSError:
            pass
    time.sleep(30)
    os._exit(0)

while not grand_marker.exists():
    time.sleep(0.05)

escape = {}
try:
    os.setsid()
    escape["setsid"] = "granted"
except OSError as exc:
    escape["setsid"] = "errno:%d" % (exc.errno or -1)

class RLimit(ctypes.Structure):
    _fields_ = [("cur", ctypes.c_long), ("max", ctypes.c_long)]

libc = ctypes.CDLL(None, use_errno=True)
old = RLimit()
ctypes.set_errno(0)
prc = libc.prlimit64(os.getppid(), 7, None, ctypes.byref(old))
if prc == 0:
    target = 64 if (old.cur == -1 or old.cur > 64) else 1
    new = RLimit(target, old.max)
    ctypes.set_errno(0)
    prc = libc.prlimit64(os.getppid(), 7, ctypes.byref(new), None)
    escape["prlimit64"] = "granted" if prc == 0 else "errno:%d" % ctypes.get_errno()
else:
    escape["prlimit64"] = "errno:%d" % ctypes.get_errno()

# Self-targeted limits must stay usable: CPython setrlimit uses prlimit64(0).
try:
    current = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, current)
    escape["self_prlimit64"] = "granted"
except OSError as exc:
    escape["self_prlimit64"] = "errno:%d" % (exc.errno or -1)

# clone3 must fail with ENOSYS so glibc falls back to plain clone.
ctypes.set_errno(0)
crc = libc.syscall(435, 0, 0)
escape["clone3"] = "errno:%d" % (ctypes.get_errno() if crc == -1 else 0)

result_marker.write_text(repr(escape), encoding="utf-8")
if mode == "timeout":
    time.sleep(30)
os._exit({"success": 0, "failure": 7}[mode])
'''

    def _run_untrusted_process_tree(self, mode: str) -> SimpleNamespace:
        if sandbox.landlock_abi() < sandbox.MIN_LANDLOCK_ABI:
            self.skipTest("required Landlock ABI is unavailable")
        before = resource.getrlimit(resource.RLIMIT_NOFILE)
        try:
            with tempfile.TemporaryDirectory() as temporary:
                with prepared_snapshot(temporary) as snapshot:
                    grand_marker = snapshot.scratch_root / f"grandchild-{mode}.txt"
                    result_marker = snapshot.scratch_root / f"escape-{mode}.txt"
                    result = run_step(
                        [
                            sys.executable, "-c", self._ESCAPE_TOOL,
                            mode, str(grand_marker), str(result_marker),
                        ],
                        snapshot,
                        ".",
                        3 if mode == "timeout" else 10,
                        1024,
                        {},
                    )
                    expected = {
                        "success": "completed",
                        "failure": "failed",
                        "timeout": "timed-out",
                    }[mode]
                    self.assertEqual(expected, result.status)
                    grandchild_pid = int(grand_marker.read_text(encoding="utf-8"))
                    settle = time.monotonic() + 5.0
                    state = _proc_state(grandchild_pid)
                    while time.monotonic() < settle and state not in (None, "Z"):
                        time.sleep(0.1)
                        state = _proc_state(grandchild_pid)
                    after = resource.getrlimit(resource.RLIMIT_NOFILE)
                    return SimpleNamespace(
                        parent_limits_unchanged=before == after,
                        live_descendants=(
                            [] if state in (None, "Z") else [grandchild_pid]
                        ),
                        zombie_descendants=[grandchild_pid] if state == "Z" else [],
                        escape_report=(
                            result_marker.read_text(encoding="utf-8")
                            if result_marker.exists()
                            else ""
                        ),
                    )
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, before)

    def test_success_failure_timeout_cannot_escape_or_leave_zombies(self):
        for mode in ("success", "failure", "timeout"):
            with self.subTest(mode=mode):
                result = self._run_untrusted_process_tree(mode)
                self.assertTrue(result.parent_limits_unchanged)
                self.assertEqual([], result.live_descendants)
                self.assertEqual([], result.zombie_descendants)
                if mode != "timeout":
                    self.assertIn("'setsid': 'errno:", result.escape_report)
                    self.assertIn("'prlimit64': 'errno:", result.escape_report)
                    self.assertIn("'self_prlimit64': 'granted'", result.escape_report)
                    self.assertIn(
                        f"'clone3': 'errno:{errno.ENOSYS}'", result.escape_report
                    )


class FinalDeadlineAndLanguageTests(unittest.TestCase):
    def test_one_entry_deadline_is_passed_to_snapshot_and_every_requested_layer(self):
        """I1: source/build/ASan cannot each renew the total request budget."""

        server = importlib.import_module("cxx_analyzer.server")
        deadline_module = importlib.import_module("cxx_analyzer.deadline")
        deadline = deadline_module.AnalysisDeadline(123.0)
        payload = {
            "request_id": REQUEST_ID,
            "repository_key": "team/project",
            "snapshot_sha256": "a" * 64,
            "requested_layers": ["source-only", "build-backed", "sanitizer-confirmed"],
        }
        prepared = mock.MagicMock()
        snapshot = prepared.__enter__.return_value
        snapshot.files = ("src/main.cpp",)
        snapshot.verify_inventory.return_value = None
        empty = LayerResult((), (), ())
        build = LayerResult((), (), (), object())
        with (
            mock.patch.object(deadline_module.AnalysisDeadline, "start", return_value=deadline),
            mock.patch.object(server, "prepare_snapshot", return_value=prepared) as prepare,
            mock.patch.object(server, "run_source_scan", return_value=empty) as source,
            mock.patch.object(server, "run_build_scan", return_value=build) as build_scan,
            mock.patch.object(server, "run_sanitizer_scan", return_value=empty) as sanitizer,
        ):
            server.analyze_request(payload, analyzer_settings())

        self.assertIs(deadline, prepare.call_args.kwargs["deadline"])
        self.assertIs(deadline, source.call_args.kwargs["deadline"])
        self.assertIs(deadline, build_scan.call_args.kwargs["deadline"])
        self.assertIs(deadline, sanitizer.call_args.kwargs["deadline"])
        self.assertIs(deadline, prepared.cleanup.call_args.kwargs["deadline"])

    def test_expired_deadline_prevents_semgrep_launch(self):
        """I1: source-only uses the request deadline rather than a fresh step timeout."""

        deadline_module = importlib.import_module("cxx_analyzer.deadline")
        deadline = deadline_module.AnalysisDeadline(1.0)
        snapshot = mock.MagicMock()
        snapshot.files = ("src/main.cpp",)
        snapshot.scratch_root = Path(tempfile.gettempdir())
        with (
            mock.patch.object(deadline_module.time, "monotonic", return_value=2.0),
            mock.patch("cxx_analyzer.source_scan.run_step") as run_tool,
        ):
            result = run_source_scan(snapshot, analyzer_settings(), deadline=deadline)
        run_tool.assert_not_called()
        self.assertEqual(("timed-out",), result.diagnostics)

    def test_one_language_map_covers_sources_and_all_header_suffixes(self):
        """I2: headers are scanned and C++ headers never fall back to C."""

        languages = importlib.import_module("cxx_analyzer.languages")
        expected = {
            ".c": "c",
            ".h": "c",
            ".cc": "c++",
            ".cpp": "c++",
            ".cxx": "c++",
            ".hh": "c++",
            ".hpp": "c++",
            ".hxx": "c++",
        }
        self.assertEqual(expected, dict(languages.CXX_LANGUAGE_BY_SUFFIX))
        for path, language in (("include/a.h", "c"), ("include/a.hpp", "c++")):
            self.assertEqual(language, languages.language_for_path(path))

        semgrep_document = {
            "results": [
                {
                    "check_id": "cxx.source.double-free.same-pointer",
                    "path": "include/a.hpp",
                    "start": {"line": 1},
                    "extra": {
                        "lines": "free(p); free(p);",
                        "message": "double free",
                        "metadata": {"cwe": "CWE-415", "candidate": True},
                        "metavars": {"$FUNC": {"abstract_content": "release"}},
                    },
                }
            ],
            "errors": [],
        }
        findings, _ = parse_semgrep_json(
            json.dumps(semgrep_document), {"include/a.hpp"}
        )
        self.assertEqual("c++", findings[0].language)


class FinalProtocolAndEvidenceTests(unittest.TestCase):
    @staticmethod
    def _payload(snapshot_sha256: str, **changes: object) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": 1,
            "request_id": REQUEST_ID,
            "status": "completed",
            "snapshot_sha256": snapshot_sha256,
            "tool_runs": [valid_tool_run()],
            "findings": [normalized_finding("source-only").to_dict()],
            "coverage": {"source_files": 1, "snapshot_files": 1},
            "diagnostics": [],
        }
        payload.update(changes)
        return payload

    @mock.patch("lima.cxx_memory.uuid.uuid4", return_value=REQUEST_ID)
    def test_client_rejects_path_line_language_and_coverage_not_bound_to_local_inventory(
        self, _uuid: mock.Mock
    ):
        """I3: response acceptance is all-or-nothing against the caller inventory."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src" / "main.cpp").write_text("int main() {}\n", encoding="utf-8")
            workspace = RepositoryWorkspace(root)
            inventory = workspace.inventory()
            fingerprint = inventory.fingerprint()
            mutations = {
                "unknown-path": {"path": "src/missing.cpp"},
                "line-out-of-range": {"line": 2},
                "wrong-language": {"language": "c"},
            }
            for name, finding_change in mutations.items():
                payload = self._payload(fingerprint)
                payload["findings"][0].update(finding_change)  # type: ignore[index,union-attr]
                opener = mock.Mock(return_value=FakeResponse(payload))
                client = CxxMemoryAnalyzerClient("http://analyzer", 3, 1_000_000, opener)
                with self.subTest(name=name), self.assertRaises(CxxAnalyzerProtocolError):
                    client.analyze(
                        "team/project", fingerprint, ("source-only",), inventory=inventory
                    )

            for coverage in (
                {"source_files": 0, "snapshot_files": 1},
                {"source_files": 1, "snapshot_files": 2},
            ):
                payload = self._payload(fingerprint, coverage=coverage)
                client = CxxMemoryAnalyzerClient(
                    "http://analyzer",
                    3,
                    1_000_000,
                    mock.Mock(return_value=FakeResponse(payload)),
                )
                with self.subTest(coverage=coverage), self.assertRaises(
                    CxxAnalyzerProtocolError
                ):
                    client.analyze(
                        "team/project", fingerprint, ("source-only",), inventory=inventory
                    )

    def test_tool_run_state_machine_rejects_cross_field_contradictions(self):
        """I4: status, return code, digest completeness, and truncation form one contract."""

        contradictions = (
            {**valid_tool_run(), "returncode": 1},
            {**valid_tool_run(status="failed"), "returncode": 0},
            {**valid_tool_run(status="timed-out"), "returncode": 9},
            {
                **valid_tool_run(),
                "digests_complete": False,
                "output_sha256": "",
                "output_truncated": False,
            },
        )
        for run in contradictions:
            with self.subTest(run=run), self.assertRaises(CxxAnalyzerProtocolError):
                validate_response_metadata(
                    [run], {"source_files": 0, "snapshot_files": 0}, []
                )

    def test_internal_sandbox_states_are_mapped_to_protocol_failures(self):
        """I4: producer never emits internal-only sandbox status strings."""

        source_scan = importlib.import_module("cxx_analyzer.source_scan")
        for internal_status in ("sandbox-unavailable", "sandbox-failed"):
            run = source_scan._tool_run(
                tool_execution(internal_status, returncode=None)
            )
            self.assertEqual("failed", run["status"])
            validate_response_metadata(
                [run], {"source_files": 0, "snapshot_files": 0}, []
            )

    def test_sidecar_keeps_all_same_identity_layers_for_main_boundary_fusion(self):
        """I5: Semgrep, Clang, and ASan evidence all cross the process boundary."""

        source = normalized_finding("source-only")
        build = normalized_finding("build-backed")
        sanitizer = normalized_finding("sanitizer-confirmed")
        fused = fuse_findings((source,), (build,), (sanitizer,))
        self.assertEqual(3, len(fused))
        self.assertEqual({"semgrep", "clang", "asan"}, {item.tool for item in fused})

    def test_response_budget_keeps_tool_evidence_for_every_retained_finding(self):
        """I6: a retained ASan finding cannot outlive its asan-test run record."""

        server = importlib.import_module("cxx_analyzer.server")
        asan = normalized_finding("sanitizer-confirmed")
        runs = [valid_tool_run() for _ in range(server.MAX_TOOL_RUNS + 3)]
        runs.append({**valid_tool_run("asan-test", "failed"), "returncode": 1})
        findings, diagnostics, bounded_runs = server._bound_response_lists(
            (asan,), [], runs
        )
        self.assertEqual((asan,), findings)
        self.assertTrue(any(run["tool"] == "asan-test" for run in bounded_runs))
        self.assertLessEqual(len(bounded_runs), server.MAX_TOOL_RUNS)
        self.assertIn("analysis-budget-exhausted", diagnostics)

        findings, diagnostics, _ = server._bound_response_lists((asan,), [], [])
        self.assertEqual((), findings)
        self.assertIn("finding-without-tool-evidence", diagnostics)

    def test_health_requires_exact_clang_driver_pair_and_reports_safe_configuration(self):
        """I7: availability and administrator configuration are explicit and versioned."""

        server = importlib.import_module("cxx_analyzer.server")
        settings = analyzer_settings(
            auto_cmake=False,
            build_steps=(("cmake", "-S", ".", "-B", "build"),),
            test_steps=(),
        )
        paths = {
            "semgrep": "/usr/bin/semgrep",
            "cmake": "/usr/bin/cmake",
            "clang-14": "/usr/bin/clang-14",
            "clang++-14": None,
        }
        with mock.patch.object(server.shutil, "which", side_effect=paths.get):
            payload = server.health_payload(settings)
        self.assertEqual(1, payload["schema_version"])
        self.assertFalse(payload["tools"]["clang"])
        self.assertEqual(
            {"source": True, "build": True, "test": False},
            payload["configuration"],
        )

    def test_semgrep_errors_are_bounded_and_make_the_source_layer_incomplete(self):
        """I8: JSON errors cannot coexist with accepted findings."""

        document = {
            "results": [
                {
                    "check_id": "cxx.source.double-free.same-pointer",
                    "path": "src/main.cpp",
                    "start": {"line": 1},
                    "extra": {
                        "lines": "free(p); free(p);",
                        "message": "double free",
                        "metadata": {"cwe": "CWE-415", "candidate": True},
                        "metavars": {"$FUNC": {"abstract_content": "release"}},
                    },
                }
            ],
            "errors": [{"type": "Parse error", "message": "incomplete scan"}],
        }
        findings, diagnostics = parse_semgrep_json(
            json.dumps(document), {"src/main.cpp"}
        )
        self.assertEqual((), findings)
        self.assertEqual(["semgrep-reported-errors"], diagnostics)

        invalid = copy.deepcopy(document)
        invalid["errors"][0]["message"] = "x" * 4097
        with self.assertRaises(ValueError):
            parse_semgrep_json(json.dumps(invalid), {"src/main.cpp"})

    def test_only_exact_windows_x509_semgrep_startup_failure_is_skippable(self):
        """I8: generic Semgrep engine/rule failures can never become capability skips."""

        source_scan = importlib.import_module("cxx_analyzer.source_scan")
        exact = "Fatal error: Failed to create system store X509 authenticator"
        self.assertTrue(
            source_scan.recognized_host_semgrep_unavailability(
                2, exact, platform_name="win32"
            )
        )
        for returncode, stderr, platform_name in (
            (2, "Fatal error: invalid rule", "win32"),
            (2, exact, "linux"),
            (1, exact, "win32"),
        ):
            with self.subTest(
                returncode=returncode, stderr=stderr, platform_name=platform_name
            ):
                self.assertFalse(
                    source_scan.recognized_host_semgrep_unavailability(
                        returncode, stderr, platform_name=platform_name
                    )
                )

    def test_main_health_probe_is_strict_cached_and_capabilities_are_authoritative(self):
        """I7: main reports the probed v1 health contract, not URL presence as availability."""

        payload = {
            "schema_version": 1,
            "tools": {"semgrep": True, "cmake": False, "clang": True},
            "configuration": {"source": True, "build": True, "test": False},
        }
        opener = mock.Mock(return_value=FakeResponse(payload))
        client = CxxMemoryAnalyzerClient("http://analyzer", 30, 1_000_000, opener)
        first = client.health()
        second = client.health()
        self.assertIs(first, second)
        self.assertEqual(payload["tools"], first.tools)
        self.assertEqual(payload["configuration"], first.configuration)
        self.assertEqual(1, opener.call_count)
        request = opener.call_args.args[0]
        self.assertEqual("GET", request.method)
        self.assertEqual("http://analyzer/health", request.full_url)
        self.assertLessEqual(opener.call_args.kwargs["timeout"], 2.0)

        invalid = {**payload, "unexpected": True}
        with self.assertRaises(CxxAnalyzerProtocolError):
            CxxMemoryAnalyzerClient(
                "http://analyzer",
                30,
                1_000_000,
                mock.Mock(return_value=FakeResponse(invalid)),
            ).health()

        service_module = importlib.import_module("lima.service")
        service = object.__new__(service_module.ReviewService)
        service.repository_import = SimpleNamespace(capabilities=lambda: {})
        service.settings = SimpleNamespace(
            repository_scan_sast_mode="off",
            repair_test_command=(),
            cxx_memory_mode="auto",
            cxx_analyzer_url="http://analyzer",
            repository_scan_max_files=100,
            repository_scan_max_file_bytes=4096,
            repository_scan_max_total_bytes=16384,
        )
        service.repository_scanner = SimpleNamespace(
            python_dataflow=SimpleNamespace(max_call_depth=4),
            cxx_memory_adapter=client,
        )
        cxx = service.repository_scan_capabilities()["cxx_memory"]
        self.assertEqual("available", cxx["health_status"])
        self.assertEqual(payload["tools"], cxx["tool_availability"])
        self.assertEqual(payload["configuration"], cxx["configuration"])
        self.assertTrue(cxx["source_layer_available"])
        self.assertTrue(cxx["build_layer_available"])
        self.assertFalse(cxx["sanitizer_layer_available"])

    def test_sanitizer_capability_requires_build_and_test_configuration(self):
        """I7: sanitizer availability cannot outlive its required build context."""

        payload = {
            "schema_version": 1,
            "tools": {"semgrep": True, "cmake": True, "clang": True},
            "configuration": {"source": True, "build": False, "test": True},
        }
        client = CxxMemoryAnalyzerClient(
            "http://analyzer",
            30,
            1_000_000,
            mock.Mock(return_value=FakeResponse(payload)),
        )
        service_module = importlib.import_module("lima.service")
        service = object.__new__(service_module.ReviewService)
        service.repository_import = SimpleNamespace(capabilities=lambda: {})
        service.settings = SimpleNamespace(
            repository_scan_sast_mode="off",
            repair_test_command=(),
            cxx_memory_mode="auto",
            cxx_analyzer_url="http://analyzer",
            repository_scan_max_files=100,
            repository_scan_max_file_bytes=4096,
            repository_scan_max_total_bytes=16384,
        )
        service.repository_scanner = SimpleNamespace(
            python_dataflow=SimpleNamespace(max_call_depth=4),
            cxx_memory_adapter=client,
        )

        cxx = service.repository_scan_capabilities()["cxx_memory"]

        self.assertFalse(cxx["build_layer_available"])
        self.assertFalse(cxx["sanitizer_layer_available"])


class FinalRenderingDownloadAndIdentityTests(unittest.TestCase):
    def test_markdown_contexts_cannot_be_closed_or_injected_by_tool_text(self):
        """I9: heading, prose, inline code, and evidence block use context encoding."""

        report = {
            "repository": "org/repo",
            "pull_request": None,
            "summary": "summary",
            "risk": "high",
            "reviewer": "test",
            "collaboration": {},
            "findings": [
                {
                    "rule_id": "cxx.source.double-free`\n## injected",
                    "severity": "high",
                    "title": "title\n# injected <script>alert(1)</script>",
                    "explanation": "# injected <img src=x onerror=alert(1)>\nexplain",
                    "path": "src/a`b.cpp",
                    "line": 1,
                    "evidence": "before\n```\n# injected\n<script>x</script>\nafter",
                    "fix": "",
                    "test": "test",
                    "confidence": 0.5,
                    "cwe": "CWE-415",
                    "source": "semgrep",
                    "evidence_kind": "line",
                    "verification_state": "candidate",
                    "language": "c++",
                    "symbol": "release`\n# injected",
                    "analysis_mode": "source-only",
                    "automatic_repair": False,
                }
            ],
        }
        rendered = to_markdown(report)
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("<img", rendered)
        self.assertNotIn("\n# injected", rendered)
        self.assertNotIn("\n## injected", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        fence_lines = [line for line in rendered.splitlines() if line.startswith("```")]
        self.assertEqual(2, len(fence_lines))
        self.assertEqual(fence_lines[0].split("text", 1)[0], fence_lines[1])

    def test_each_download_read_rebinds_socket_timeout_to_remaining_deadline(self):
        """I10: a near-deadline blocking read cannot reuse the original socket timeout."""

        module = importlib.import_module("scripts.run_cxx_memory_evaluation")

        class Socket:
            def __init__(self):
                self.timeouts: list[float] = []

            def settimeout(self, value: float) -> None:
                self.timeouts.append(value)

        class Raw:
            def __init__(self, socket: Socket):
                self._sock = socket

        class Fp:
            def __init__(self, socket: Socket):
                self.raw = Raw(socket)

        class Response(io.BytesIO):
            def __init__(self, raw: bytes, socket: Socket):
                super().__init__(raw)
                self.fp = Fp(socket)

            def geturl(self) -> str:
                return "https://example.test/archive.tar.gz"

        class Opener:
            def __init__(self, response: Response):
                self.response = response

            def open(self, request: object, timeout: float) -> Response:
                return self.response

        raw = b"archive"
        socket = Socket()
        response = Response(raw, socket)
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "archive.tar.gz"
            with (
                mock.patch.object(
                    module.urllib.request,
                    "build_opener",
                    return_value=Opener(response),
                ),
                mock.patch.object(
                    module.time,
                    "monotonic",
                    side_effect=(0.0, 0.0, 4.0, 4.5, 4.5, 4.5, 4.5),
                ),
                mock.patch.object(module, "_DOWNLOAD_DEADLINE_SECONDS", 5.0),
                mock.patch.object(module, "_DOWNLOAD_SOCKET_TIMEOUT_SECONDS", 10.0),
            ):
                module.download_verified_archive(
                    "https://example.test/archive.tar.gz",
                    hashlib.sha256(raw).hexdigest(),
                    destination,
                )
        self.assertTrue(socket.timeouts)
        self.assertLessEqual(socket.timeouts[-1], 1.0)

    def test_evaluator_requires_explicit_ci_obtained_image_identity(self):
        """I11: health cannot invent image identity; the evaluator requires it as input."""

        module = importlib.import_module("scripts.run_cxx_memory_evaluation")
        parser = module.build_parser()
        options = {
            option
            for action in parser._actions
            for option in action.option_strings
        }
        self.assertIn("--analyzer-image-digest", options)
        digest = "sha256:" + "a" * 64
        report = module.add_report_metadata(
            {"precision": None},
            b'{}',
            analyzer_image_digest=digest,
        )
        self.assertEqual(digest, report["analyzer_image_digest"])
        with self.assertRaises(ValueError):
            module.add_report_metadata(
                {"precision": None}, b'{}', analyzer_image_digest=None
            )

        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("docker image inspect", workflow)
        self.assertIn("--analyzer-image-digest", workflow)

        dockerfile = Path("cxx_analyzer/Dockerfile").read_text(encoding="utf-8")
        self.assertIn("dpkg-query", dockerfile)
        self.assertIn("analyzer-toolchain-packages", dockerfile)


if __name__ == "__main__":
    unittest.main()
