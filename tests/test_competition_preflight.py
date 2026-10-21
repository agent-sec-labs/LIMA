"""Contract tests for the read-only competition run preflight (#311)."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI_PATH = REPO_ROOT / "scripts" / "preflight_competition_run.py"

try:  # preflight contract (RED until lima.competition_preflight lands)
    from lima.competition_preflight import (
        DISCLAIMER_TEXT,
        PREFLIGHT_SCHEMA_VERSION,
        PreflightRequest,
        preflight_exit_code,
        run_competition_preflight,
        validate_analyzer_url,
        validate_output_placement,
    )
except ImportError:  # pragma: no cover - RED phase
    run_competition_preflight = None

from lima.cxx_memory import (  # noqa: E402
    CxxAnalyzerHealth,
    CxxAnalyzerProtocolError,
    CxxAnalyzerUnavailable,
)
from lima.openharmony_validation import (  # noqa: E402
    CheckoutPreflightError,
    WorkspaceLimits,
)
from lima.repository_import import RepositoryImportPolicy  # noqa: E402

REPO = "https://gitee.com/openharmony/third_party_sample"
MODEL_ENV = {
    "LIMA_LLM_BASE_URL": "https://example.invalid/v1",
    "LIMA_CXX_AGENT_MODEL": "test-model",
    "LIMA_LLM_API_KEY": "sk-leakcanary987654321",
}

CHECK_ORDER = [
    "case-manifest",
    "repository-import-root",
    "checkouts",
    "model-config",
    "sidecar-health",
]

_GIT_BASE = [
    "-c", "safe.directory=*", "-c", "core.autocrlf=false",
    "-c", "core.filemode=false",
]
_GIT_IDENTITY = [
    "-c", "user.name=preflight-test",
    "-c", "user.email=preflight@example.com",
]


def _git(path: Path, *args: str) -> str:
    result = subprocess.run(  # noqa: S603
        ["git", "-C", str(path), *_GIT_BASE, *args],  # noqa: S607
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def run_cli(arguments, env_extra=None, cwd=REPO_ROOT):
    env = {
        name: value for name, value in os.environ.items()
        if not name.startswith("LIMA_")
    }
    if env_extra:
        env.update(env_extra)
    return subprocess.run(  # noqa: S603
        [sys.executable, str(CLI_PATH), *arguments],  # noqa: S607
        capture_output=True, text=True, env=env, cwd=str(cwd),
    )


def _check(payload: dict, name: str) -> dict:
    return next(item for item in payload["checks"] if item["name"] == name)


def _case_payload(
    vulnerable_commit: str, fixed_commit: str, overlay_bytes: bytes,
) -> dict:
    return {
        "schema_version": "openharmony-validation-v1",
        "case_id": "sample-pilot-uaf-001",
        "repository": REPO,
        "component": "third_party_sample",
        "cve_id": "CVE-2026-9001",
        "cwe": "CWE-416",
        "vulnerable": {
            "repository_key": "sample-vuln",
            "commit": vulnerable_commit,
            "version": "v1.0.0",
        },
        "fixed": {
            "repository_key": "sample-fixed",
            "commit": fixed_commit,
            "version": "v1.0.1",
        },
        "translation_units": ["src/parser.c"],
        "target_paths": ["src/parser.c"],
        "build_context_mode": "snapshot-compdb",
        "advisory_urls": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-9001",
        ],
        "patch_paths": ["src/parser.c"],
        "remediation": "Upgrade to the fixed release.",
        "license": "MIT",
        "dependency_overlay": [{
            "path": "_overlay/log.h",
            "sha256": hashlib.sha256(overlay_bytes).hexdigest(),
            "role": "dependency-header",
            "upstream_repo": REPO,
            "upstream_commit": "d" * 40,
            "license": "Apache-2.0",
            "note": "reduced no-op logging header",
        }],
    }


class PreflightFixture:
    """Two pinned, clean checkouts plus a case manifest under one temp root."""

    overlay_bytes = b"/* reduced overlay header */\n"

    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(suffix="-preflight"))
        self.import_root = self.root / "imports"
        self.import_root.mkdir()
        repo = self.import_root / "sample-vuln"
        (repo / "src").mkdir(parents=True)
        _git(repo, "init", "-q")
        (repo / "src" / "parser.c").write_text(
            "int parse(void) { return 1; }\n", encoding="utf-8",
        )
        (repo / "src" / "util.c").write_text(
            "int util(void) { return 2; }\n", encoding="utf-8",
        )
        _git(repo, "add", "-A")
        _git(repo, *_GIT_IDENTITY, "commit", "-q", "-m", "vulnerable")
        self.vulnerable_commit = _git(repo, "rev-parse", "HEAD")
        (repo / "src" / "parser.c").write_text(
            "int parse(void) { return 2; }\n", encoding="utf-8",
        )
        _git(repo, "add", "-A")
        _git(repo, *_GIT_IDENTITY, "commit", "-q", "-m", "fixed")
        self.fixed_commit = _git(repo, "rev-parse", "HEAD")
        fixed = self.import_root / "sample-fixed"
        subprocess.run(  # noqa: S603
            ["git", "clone", "-q", "--no-hardlinks", str(repo), str(fixed)],  # noqa: S607
            check=True, capture_output=True,
        )
        _git(fixed, "checkout", "-q", "--detach", self.fixed_commit)
        _git(repo, "checkout", "-q", "--detach", self.vulnerable_commit)
        self.vulnerable_repo = repo
        self.fixed_repo = fixed
        self._stage_case_files()

    def _stage_case_files(self) -> None:
        document = [{
            "directory": ".",
            "file": "src/parser.c",
            "arguments": [
                "clang-14", "-c", "-I_overlay", "-Isrc", "src/parser.c",
                "-o", "build/parser.o",
            ],
        }]
        for repo in (self.vulnerable_repo, self.fixed_repo):
            overlay = repo / "_overlay"
            overlay.mkdir(exist_ok=True)
            (overlay / "log.h").write_bytes(self.overlay_bytes)
            (repo / "compile_commands.json").write_text(
                json.dumps(document), encoding="utf-8",
            )

    def case_payload(self) -> dict:
        return _case_payload(
            self.vulnerable_commit, self.fixed_commit, self.overlay_bytes,
        )

    def write_case(self, payload: dict | None = None) -> Path:
        target = self.root / "case.json"
        target.write_text(
            json.dumps(payload if payload is not None else self.case_payload()),
            encoding="utf-8",
        )
        return target

    def request(self, **overrides) -> "PreflightRequest":
        defaults = {
            "case_path": str(self.write_case()),
            "repository_import_root": str(self.import_root),
            "check_sidecar": False,
            "analyzer_url": "",
        }
        defaults.update(overrides)
        return PreflightRequest(**defaults)

    def input_snapshot(self) -> dict:
        """Content digests of every tested file, git metadata excluded."""
        entries = {}
        for path in sorted(self.import_root.rglob("*")):
            if path.is_file() and ".git" not in path.parts:
                entries[str(path.relative_to(self.root))] = (
                    hashlib.sha256(path.read_bytes()).hexdigest()
                )
        return entries


def _healthy_snapshot() -> CxxAnalyzerHealth:
    return CxxAnalyzerHealth(
        schema_version=1,
        source_available=True,
        build_available=True,
        test_configured=True,
        clang_c_available=True,
        clang_cxx_available=True,
        cmake_available=True,
        landlock_available=False,
        process_isolation_available=True,
        trusted_build_context_generation_available=False,
    )


class _StubClient:
    def __init__(self, health=None, error=None) -> None:
        self._health = health
        self._error = error
        self.calls = 0

    def health(self):
        self.calls += 1
        if self._error is not None:
            raise self._error
        return self._health


def _factory_spy(client, log):
    def factory(base_url, timeout_seconds, max_response_bytes):
        log.append((base_url, timeout_seconds, max_response_bytes))
        return client
    return factory


class AnalyzerUrlTests(unittest.TestCase):
    def setUp(self):
        if run_competition_preflight is None:
            self.fail("lima.competition_preflight not implemented yet")

    def test_plain_http_and_https_accepted(self):
        self.assertEqual(
            validate_analyzer_url("http://127.0.0.1:8090"),
            "http://127.0.0.1:8090",
        )
        self.assertEqual(
            validate_analyzer_url("https://sidecar.internal:9443/"),
            "https://sidecar.internal:9443",
        )

    def test_rejected_forms(self):
        rejected = [
            "http://user:pass@127.0.0.1:8090",
            "http://127.0.0.1:8090/?x=1",
            "http://127.0.0.1:8090/#fragment",
            "file:///tmp/sidecar",
            "ftp://127.0.0.1:8090",
            "http://127.0.0.1:not-a-port",
            "http://",
            "http:///no-host",
            "   ",
        ]
        for candidate in rejected:
            with self.assertRaises(ValueError, msg=candidate):
                validate_analyzer_url(candidate)


@unittest.skipUnless(
    shutil.which("git") is not None,
    "git is required for the checkout fixtures",
)
class PreflightCheckoutTests(unittest.TestCase):
    def setUp(self):
        self.fixture = PreflightFixture()
        self.addCleanup(shutil.rmtree, self.fixture.root, ignore_errors=True)

    def _run(self, request=None, environ=None, **overrides):
        return run_competition_preflight(
            request or self.fixture.request(**overrides),
            environ=dict(MODEL_ENV) if environ is None else dict(environ),
        )

    def test_all_prerequisites_pass(self):
        payload = self._run()
        self.assertEqual(
            [item["name"] for item in payload["checks"]], CHECK_ORDER,
        )
        self.assertTrue(payload["prerequisites_passed"])
        self.assertFalse(payload["sidecar_requested"])
        self.assertEqual(payload["schema_version"], PREFLIGHT_SCHEMA_VERSION)
        self.assertEqual(payload["case_id"], "sample-pilot-uaf-001")
        self.assertEqual(_check(payload, "case-manifest")["status"], "pass")
        self.assertEqual(_check(payload, "repository-import-root")["status"], "pass")
        self.assertEqual(_check(payload, "checkouts")["status"], "pass")
        self.assertEqual(_check(payload, "model-config")["status"], "pass")
        sidecar = _check(payload, "sidecar-health")
        self.assertEqual(sidecar["status"], "not-requested")
        self.assertEqual(sidecar["reason_code"], "not-selected")
        self.assertEqual(preflight_exit_code(payload), 0)
        self.assertIn(DISCLAIMER_TEXT, json.dumps(payload, ensure_ascii=False))

    def test_head_mismatch_reason(self):
        _git(
            self.fixture.vulnerable_repo, "checkout", "-q", "--detach",
            self.fixture.fixed_commit,
        )
        payload = self._run()
        record = _check(payload, "checkouts")
        self.assertEqual(record["status"], "fail")
        self.assertEqual(record["reason_code"], "head-mismatch")
        self.assertFalse(payload["prerequisites_passed"])
        self.assertEqual(preflight_exit_code(payload), 2)

    def test_dirty_tree_reason(self):
        target = self.fixture.vulnerable_repo / "src" / "parser.c"
        target.write_text(
            target.read_text(encoding="utf-8") + "/* dirty */\n",
            encoding="utf-8",
        )
        payload = self._run()
        self.assertEqual(
            _check(payload, "checkouts")["reason_code"], "tracked-files-dirty",
        )

    def test_missing_compdb_reason(self):
        (self.fixture.vulnerable_repo / "compile_commands.json").unlink()
        payload = self._run()
        self.assertEqual(
            _check(payload, "checkouts")["reason_code"], "missing-compdb",
        )

    def test_overlay_digest_mismatch_reason(self):
        (self.fixture.vulnerable_repo / "_overlay" / "log.h").write_bytes(
            b"tampered",
        )
        payload = self._run()
        self.assertEqual(
            _check(payload, "checkouts")["reason_code"],
            "overlay-digest-mismatch",
        )

    def test_budget_exceeded_reason(self):
        payload = self._run(
            environ={**MODEL_ENV, "LIMA_REPOSITORY_SCAN_MAX_FILES": "1"},
        )
        self.assertEqual(
            _check(payload, "checkouts")["reason_code"], "inventory-truncated",
        )

    def test_bad_manifest_records_error_and_stops_dependents(self):
        broken = self.fixture.root / "broken-case.json"
        broken.write_text("{'not json", encoding="utf-8")
        payload = self._run(
            case_path=str(broken), environ=dict(MODEL_ENV),
        )
        manifest = _check(payload, "case-manifest")
        self.assertEqual(manifest["status"], "fail")
        self.assertEqual(manifest["reason_code"], "manifest-invalid")
        self.assertEqual(
            manifest["detail"], "case manifest is not valid JSON",
        )
        checkouts = _check(payload, "checkouts")
        self.assertEqual(checkouts["status"], "not-requested")
        self.assertEqual(checkouts["reason_code"], "skipped-upstream-failed")
        self.assertEqual(payload["case_id"], "")
        self.assertEqual(preflight_exit_code(payload), 2)

    def test_missing_case_file_fails_manifest_check(self):
        payload = self._run(
            case_path=str(self.fixture.root / "absent.json"),
            environ=dict(MODEL_ENV),
        )
        record = _check(payload, "case-manifest")
        self.assertEqual(record["reason_code"], "manifest-invalid")
        self.assertEqual(record["detail"], "case manifest unreadable")
        self.assertEqual(preflight_exit_code(payload), 2)

    def test_import_root_unavailable_stops_checkouts(self):
        payload = self._run(
            repository_import_root=str(self.fixture.root / "absent"),
            environ=dict(MODEL_ENV),
        )
        root_record = _check(payload, "repository-import-root")
        self.assertEqual(root_record["status"], "fail")
        self.assertEqual(root_record["reason_code"], "import-root-unavailable")
        self.assertEqual(
            _check(payload, "checkouts")["reason_code"],
            "skipped-upstream-failed",
        )
        self.assertEqual(preflight_exit_code(payload), 2)

    def test_model_config_missing_does_not_claim_provider_down(self):
        payload = self._run(environ={})
        record = _check(payload, "model-config")
        self.assertEqual(record["status"], "fail")
        self.assertEqual(record["reason_code"], "model-config-missing")
        self.assertEqual(
            record["detail"], "missing required items: model, provider_url",
        )
        self.assertNotIn("unavailable", record["reason_code"])
        self.assertNotIn("unavailable", record["detail"])
        self.assertEqual(preflight_exit_code(payload), 2)

    def test_no_key_local_service_config_passes(self):
        # Review #328 (P2-3): the run entry accepts an empty API key
        # for local endpoints, so the key is recorded but not required.
        local_env = {
            "LIMA_LLM_BASE_URL": "http://127.0.0.1:8000/v1",
            "LIMA_CXX_AGENT_MODEL": "local-model",
        }
        payload = self._run(environ=local_env)
        record = _check(payload, "model-config")
        self.assertEqual(record["status"], "pass")
        self.assertIn("api_key=absent", record["detail"])
        self.assertIn(
            "api_key=absent", " ".join(payload["diagnostics"]),
        )
        self.assertTrue(payload["prerequisites_passed"])
        self.assertEqual(preflight_exit_code(payload), 0)

    def test_model_config_present_does_not_claim_auth_valid(self):
        payload = self._run(environ=dict(MODEL_ENV))
        record = _check(payload, "model-config")
        self.assertEqual(record["status"], "pass")
        self.assertIn("not verified", record["detail"])

    def test_api_key_value_never_appears_in_payload(self):
        payload = self._run(environ=dict(MODEL_ENV))
        self.assertNotIn(
            MODEL_ENV["LIMA_LLM_API_KEY"],
            json.dumps(payload, ensure_ascii=False),
        )

    def test_sensitive_input_never_reaches_the_report(self):
        # Review #328 (P2-2): the loader echoes raw manifest values in
        # its exception text (here the repr of an unsafe path), and a
        # mocked loader may raise arbitrary text; neither may reach the
        # report -- failure location is a fixed triage string instead.
        secret = "topsecret-token-998877"  # noqa: S105 - synthetic token
        payload = json.loads(json.dumps(self.fixture.case_payload()))
        payload["translation_units"] = [f"C:\\{secret}"]
        poisoned = self.fixture.root / "poisoned.json"
        poisoned.write_text(json.dumps(payload), encoding="utf-8")
        result = run_competition_preflight(
            self.fixture.request(case_path=str(poisoned)),
            environ=dict(MODEL_ENV),
        )
        record = _check(result, "case-manifest")
        self.assertEqual(record["status"], "fail")
        self.assertEqual(record["reason_code"], "manifest-invalid")
        self.assertEqual(
            record["detail"], "case manifest violates the frozen schema",
        )
        self.assertNotIn(secret, json.dumps(result, ensure_ascii=False))

        api_secret = "sk-supersecret112233"  # noqa: S105 - synthetic token
        with patch(
            "lima.openharmony_validation.load_openharmony_case",
            Mock(side_effect=ValueError(f"boom {api_secret}")),
        ):
            mocked = self._run()
        self.assertNotIn(
            api_secret, json.dumps(mocked, ensure_ascii=False),
        )
        self.assertNotIn("boom", json.dumps(mocked, ensure_ascii=False))

    def test_existing_validators_are_reused_with_their_interfaces(self):
        captured = {}

        def fake_validate(case, policy, limits):
            captured["case"] = case
            captured["policy"] = policy
            captured["limits"] = limits
            return Mock(), Mock()

        with patch(
            "lima.openharmony_validation.validate_case_checkouts",
            side_effect=fake_validate,
        ):
            payload = self._run()
        self.assertIsInstance(captured["policy"], RepositoryImportPolicy)
        self.assertEqual(
            captured["policy"].configured_root, str(self.fixture.import_root),
        )
        self.assertIsInstance(captured["limits"], WorkspaceLimits)
        self.assertEqual(captured["limits"].max_files, 5000)
        self.assertEqual(captured["limits"].max_file_bytes, 512 * 1024)
        self.assertEqual(captured["limits"].max_total_bytes, 20 * 1024 * 1024)
        self.assertEqual(captured["case"].case_id, "sample-pilot-uaf-001")
        self.assertEqual(_check(payload, "checkouts")["status"], "pass")

    def test_mocked_preflight_error_reason_is_projected(self):
        with patch(
            "lima.openharmony_validation.validate_case_checkouts",
            Mock(side_effect=CheckoutPreflightError("head-mismatch", "drift")),
        ):
            payload = self._run()
        record = _check(payload, "checkouts")
        self.assertEqual(record["status"], "fail")
        self.assertEqual(record["reason_code"], "head-mismatch")
        # The validator's detail text can embed input values; only the
        # stable reason category is projected, never the detail.
        self.assertEqual(record["detail"], "")

    def test_no_model_or_platform_run_calls(self):
        with patch(
            "lima.openharmony_validation.run_openharmony_case",
        ) as run_case, patch(
            "lima.agent_orchestrator.run_platform_review",
        ) as review, patch(
            "lima.openharmony_validation.validate_case_checkouts",
            Mock(return_value=(Mock(), Mock())),
        ):
            payload = self._run()
        run_case.assert_not_called()
        review.assert_not_called()
        self.assertTrue(payload["prerequisites_passed"])

    def test_default_mode_never_touches_network_or_analyzer_client(self):
        with patch(
            "urllib.request.urlopen",
            Mock(side_effect=AssertionError("network call")),
        ), patch(
            "lima.cxx_memory.CxxMemoryAnalyzerClient",
        ) as client_class:
            payload = self._run()
        client_class.assert_not_called()
        self.assertEqual(preflight_exit_code(payload), 0)

    def test_inputs_are_read_only(self):
        before = self.fixture.input_snapshot()
        case_path = self.fixture.write_case()
        case_digest = hashlib.sha256(case_path.read_bytes()).hexdigest()
        request = PreflightRequest(
            case_path=str(case_path),
            repository_import_root=str(self.fixture.import_root),
        )
        run_competition_preflight(request, environ=dict(MODEL_ENV))
        self.assertEqual(self.fixture.input_snapshot(), before)
        self.assertEqual(
            hashlib.sha256(case_path.read_bytes()).hexdigest(), case_digest,
        )

    def test_output_inside_import_root_is_rejected_before_checks(self):
        # Review #328 (P2-1): a report written below the import root
        # would become an untracked file and fail the next preflight of
        # the same checkout; the guard fires before anything runs.
        case_path = self.fixture.write_case()
        for bad in (
            self.fixture.import_root / "report.json",
            self.fixture.import_root / "sample-vuln" / "report.json",
            case_path,
        ):
            request = PreflightRequest(
                case_path=str(case_path),
                repository_import_root=str(self.fixture.import_root),
                output_path=str(bad),
            )
            with self.assertRaises(ValueError, msg=str(bad)):
                run_competition_preflight(request, environ=dict(MODEL_ENV))
        distinct = PreflightRequest(
            case_path=str(case_path),
            repository_import_root=str(self.fixture.import_root),
            output_path=str(self.fixture.root / "reports" / "report.json"),
        )
        payload = run_competition_preflight(distinct, environ=dict(MODEL_ENV))
        self.assertEqual(preflight_exit_code(payload), 0)


class SidecarProbeTests(unittest.TestCase):
    """Sidecar behavior with mocked validators: no git, no real network."""

    def setUp(self):
        if run_competition_preflight is None:
            self.fail("lima.competition_preflight not implemented yet")

        self.directory = Path(tempfile.mkdtemp(suffix="-sidecar"))
        self.addCleanup(shutil.rmtree, self.directory, ignore_errors=True)
        payload = _case_payload("a" * 40, "b" * 40, PreflightFixture.overlay_bytes)
        self.case_path = self.directory / "case.json"
        self.case_path.write_text(json.dumps(payload), encoding="utf-8")

    def _run(self, factory, **overrides):
        request = PreflightRequest(
            case_path=str(self.case_path),
            repository_import_root=str(self.directory),
            **overrides,
        )
        with patch(
            "lima.openharmony_validation.validate_case_checkouts",
            Mock(return_value=(Mock(), Mock())),
        ):
            return run_competition_preflight(
                request, environ=dict(MODEL_ENV),
                analyzer_client_factory=factory,
            )

    def test_healthy_sidecar_passes_without_echoing_the_url(self):
        log = []
        payload = self._run(
            _factory_spy(_StubClient(health=_healthy_snapshot()), log),
            check_sidecar=True, analyzer_url="http://127.0.0.1:8901",
        )
        record = _check(payload, "sidecar-health")
        self.assertEqual(record["status"], "pass")
        self.assertTrue(payload["prerequisites_passed"])
        self.assertTrue(payload["sidecar_requested"])
        self.assertEqual(preflight_exit_code(payload), 0)
        self.assertIn(
            "clang_c_available=true", " ".join(payload["diagnostics"]),
        )
        self.assertNotIn(
            "127.0.0.1:8901", json.dumps(payload, ensure_ascii=False),
        )
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0][0], "http://127.0.0.1:8901")

    def test_unavailable_sidecar_fails_while_prerequisites_hold(self):
        payload = self._run(
            _factory_spy(
                _StubClient(error=CxxAnalyzerUnavailable("down")), [],
            ),
            check_sidecar=True, analyzer_url="http://127.0.0.1:8901",
        )
        record = _check(payload, "sidecar-health")
        self.assertEqual(record["status"], "fail")
        self.assertEqual(record["reason_code"], "sidecar-unavailable")
        self.assertTrue(payload["prerequisites_passed"])
        self.assertEqual(preflight_exit_code(payload), 2)

    def test_protocol_error_reason(self):
        payload = self._run(
            _factory_spy(
                _StubClient(error=CxxAnalyzerProtocolError("bad json")), [],
            ),
            check_sidecar=True, analyzer_url="http://127.0.0.1:8901",
        )
        self.assertEqual(
            _check(payload, "sidecar-health")["reason_code"],
            "sidecar-protocol-error",
        )

    def test_probe_timeout_fails_without_retry(self):
        log = []
        client = _StubClient(error=TimeoutError("timed out"))
        payload = self._run(
            _factory_spy(client, log), check_sidecar=True,
            analyzer_url="http://127.0.0.1:8901",
        )
        self.assertEqual(
            _check(payload, "sidecar-health")["reason_code"],
            "sidecar-unavailable",
        )
        self.assertEqual(client.calls, 1)
        self.assertEqual(len(log), 1)
        self.assertLessEqual(log[0][1], 5)
        self.assertGreaterEqual(log[0][1], 1)

    def test_analyzer_url_falls_back_to_env_then_default(self):
        for environ_url, expected in (
            ("http://10.0.0.5:9000", "http://10.0.0.5:9000"),
            ("", "http://127.0.0.1:8090"),
        ):
            log = []
            with patch(
                "lima.openharmony_validation.validate_case_checkouts",
                Mock(return_value=(Mock(), Mock())),
            ):
                payload = run_competition_preflight(
                    PreflightRequest(
                        case_path=str(self.case_path),
                        repository_import_root=str(self.directory),
                        check_sidecar=True,
                    ),
                    environ={**MODEL_ENV, "LIMA_CXX_ANALYZER_URL": environ_url},
                    analyzer_client_factory=_factory_spy(
                        _StubClient(health=_healthy_snapshot()), log,
                    ),
                )
            self.assertEqual(log[0][0], expected)
            self.assertEqual(
                _check(payload, "sidecar-health")["status"], "pass",
            )

    def test_bad_sidecar_url_fails_before_any_probe(self):
        log = []
        factory = _factory_spy(_StubClient(health=_healthy_snapshot()), log)
        with self.assertRaises(ValueError):
            self._run(
                factory, check_sidecar=True,
                analyzer_url="http://user:pass@127.0.0.1:8901/",
            )
        self.assertEqual(log, [])


@unittest.skipUnless(
    shutil.which("git") is not None,
    "git is required for the checkout fixtures",
)
class PreflightCliTests(unittest.TestCase):
    def setUp(self):
        self.fixture = PreflightFixture()
        self.addCleanup(shutil.rmtree, self.fixture.root, ignore_errors=True)
        self.case_path = self.fixture.write_case()
        self.output_path = self.fixture.root / "preflight.json"

    def test_happy_path_exits_zero_with_disclaimer(self):
        completed = run_cli([
            "--case", str(self.case_path),
            "--repository-import-root", str(self.fixture.import_root),
            "--output", str(self.output_path),
        ], env_extra=MODEL_ENV)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(DISCLAIMER_TEXT, completed.stdout)
        self.assertNotIn(MODEL_ENV["LIMA_LLM_API_KEY"], completed.stdout)
        payload = json.loads(
            self.output_path.read_text(encoding="utf-8"),
        )
        self.assertEqual(
            payload["schema_version"], PREFLIGHT_SCHEMA_VERSION,
        )
        self.assertTrue(payload["prerequisites_passed"])
        self.assertNotIn(
            MODEL_ENV["LIMA_LLM_API_KEY"],
            self.output_path.read_text(encoding="utf-8"),
        )

    def test_prerequisite_failure_exits_two_with_report(self):
        target = self.fixture.vulnerable_repo / "src" / "parser.c"
        target.write_text(
            target.read_text(encoding="utf-8") + "/* dirty */\n",
            encoding="utf-8",
        )
        completed = run_cli([
            "--case", str(self.case_path),
            "--repository-import-root", str(self.fixture.import_root),
            "--output", str(self.output_path),
        ], env_extra=MODEL_ENV)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        payload = json.loads(
            self.output_path.read_text(encoding="utf-8"),
        )
        self.assertEqual(
            _check(payload, "checkouts")["reason_code"], "tracked-files-dirty",
        )

    def test_missing_required_arguments_exit_three(self):
        completed = run_cli([])
        self.assertEqual(completed.returncode, 3)

    def test_existing_output_is_never_overwritten(self):
        self.output_path.write_text("sentinel", encoding="utf-8")
        completed = run_cli([
            "--case", str(self.case_path),
            "--repository-import-root", str(self.fixture.import_root),
            "--output", str(self.output_path),
        ], env_extra=MODEL_ENV)
        self.assertEqual(completed.returncode, 3, completed.stderr)
        self.assertEqual(
            self.output_path.read_text(encoding="utf-8"), "sentinel",
        )

    def test_bad_analyzer_url_exits_three_without_report(self):
        completed = run_cli([
            "--case", str(self.case_path),
            "--repository-import-root", str(self.fixture.import_root),
            "--output", str(self.output_path),
            "--check-sidecar",
            "--analyzer-url", "http://127.0.0.1:8901/?token=1",
        ], env_extra=MODEL_ENV)
        self.assertEqual(completed.returncode, 3, completed.stderr)
        self.assertFalse(self.output_path.exists())

    def test_output_inside_import_root_rejected_and_inputs_stay_clean(self):
        # Review #328 (P2-1) repro: the rejected run must leave the
        # checkout pristine, so a follow-up with a proper output path
        # still passes instead of failing on an untracked report.
        inside = self.fixture.import_root / "sample-vuln" / "report.json"
        rejected = run_cli([
            "--case", str(self.case_path),
            "--repository-import-root", str(self.fixture.import_root),
            "--output", str(inside),
        ], env_extra=MODEL_ENV)
        self.assertEqual(rejected.returncode, 3, rejected.stderr)
        self.assertFalse(inside.exists())
        clean_run = run_cli([
            "--case", str(self.case_path),
            "--repository-import-root", str(self.fixture.import_root),
            "--output", str(self.output_path),
        ], env_extra=MODEL_ENV)
        self.assertEqual(clean_run.returncode, 0, clean_run.stderr)
        self.assertTrue(self.output_path.exists())

    def test_tilde_output_uses_the_validated_home_path(self):
        checkout = self.fixture.vulnerable_repo
        literal_tilde = checkout / "~"
        literal_tilde.mkdir()
        home = self.fixture.root / "external-home"
        home.mkdir()
        output = home / "preflight-report.json"
        checkout_status = _git(checkout, "status", "--porcelain")
        completed = run_cli([
            "--case", str(self.case_path),
            "--repository-import-root", str(self.fixture.import_root),
            "--output", "~/preflight-report.json",
        ], env_extra={**MODEL_ENV, "HOME": str(home), "USERPROFILE": str(home)},
            cwd=checkout)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertTrue(output.is_file())
        self.assertFalse((literal_tilde / "preflight-report.json").exists())
        self.assertEqual(_git(checkout, "status", "--porcelain"), checkout_status)

        next_output = self.fixture.root / "second-report.json"
        second = run_cli([
            "--case", str(self.case_path),
            "--repository-import-root", str(self.fixture.import_root),
            "--output", str(next_output),
        ], env_extra=MODEL_ENV, cwd=checkout)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertTrue(next_output.is_file())

    def test_unknown_argument_value_is_never_echoed(self):
        # Review #328 (P2-2): argparse echoes unrecognized arguments
        # (including a mistyped secret) to stderr; the echo is
        # suppressed and replaced by a fixed message.
        secret = "sk-toppsecret424242"  # noqa: S105 - synthetic token
        completed = run_cli([
            "--case", str(self.case_path),
            "--repository-import-root", str(self.fixture.import_root),
            "--output", str(self.output_path),
            f"--api-key={secret}",
        ], env_extra=MODEL_ENV)
        self.assertEqual(completed.returncode, 3)
        self.assertNotIn(secret, completed.stdout)
        self.assertNotIn(secret, completed.stderr)
        self.assertFalse(self.output_path.exists())


@unittest.skipUnless(run_competition_preflight, "module not implemented yet")
@unittest.skipIf(
    sys.platform != "win32",
    "Windows ADS streams and device aliases",
)
class WindowsOutputPlacementTests(unittest.TestCase):
    """Review #328 (P2-1): ADS and device-alias outputs on Windows."""

    def setUp(self):
        if run_competition_preflight is None:
            self.fail("lima.competition_preflight not implemented yet")
        self.fixture = PreflightFixture()
        self.addCleanup(shutil.rmtree, self.fixture.root, ignore_errors=True)
        self.case_path = self.fixture.write_case()

    def test_ads_onto_manifest_rejected_without_touching_it(self):
        before = self.case_path.read_bytes()
        ads_output = f"{self.case_path}:report.json"
        completed = run_cli([
            "--case", str(self.case_path),
            "--repository-import-root", str(self.fixture.import_root),
            "--output", ads_output,
        ], env_extra=MODEL_ENV)
        self.assertEqual(completed.returncode, 3, completed.stderr)
        self.assertFalse(Path(ads_output).exists())
        self.assertEqual(self.case_path.read_bytes(), before)

    def test_device_and_alias_component_names_rejected(self):
        reports = self.fixture.root / "reports"
        reports.mkdir()
        rejected = [
            "NUL", "CON", "com3.txt", "report.json.", " report.json",
            "CONIN$", "report.json:$DATA",
        ]
        for name in rejected:
            with self.assertRaises(ValueError, msg=name):
                validate_output_placement(
                    reports / name,
                    repository_import_root=str(self.fixture.import_root),
                    case_path=str(self.case_path),
                )


if __name__ == "__main__":
    unittest.main()
