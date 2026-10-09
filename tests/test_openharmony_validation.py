"""Contract tests for the frozen OpenHarmony pilot case manifest."""

import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

try:  # pilot case contract (RED until Task 2 lands)
    from lima.openharmony_validation import (
        DependencyOverlayEntry,
        OpenHarmonyCase,
        load_openharmony_case,
    )
except ImportError:  # pragma: no cover - RED phase
    load_openharmony_case = None

REPO = "https://gitee.com/openharmony/third_party_sample"
ADVISORY = "https://nvd.nist.gov/vuln/detail/CVE-2026-9001"

VALID_CASE = {
    "schema_version": "openharmony-validation-v1",
    "case_id": "sample-pilot-uaf-001",
    "repository": REPO,
    "component": "third_party_sample",
    "cve_id": "CVE-2026-9001",
    "cwe": "CWE-416",
    "vulnerable": {
        "repository_key": "sample-vuln",
        "commit": "a" * 40,
        "version": "v1.0.0",
    },
    "fixed": {
        "repository_key": "sample-fixed",
        "commit": "b" * 40,
        "version": "v1.0.1",
    },
    "translation_units": ["src/parser.c"],
    "target_paths": ["src/parser.c"],
    "build_context_mode": "snapshot-compdb",
    "advisory_urls": [ADVISORY],
    "patch_paths": ["src/parser.c"],
    "remediation": "Upgrade to the fixed release; the fix adds a free-order guard.",
    "license": "MIT",
    "dependency_overlay": [
        {
            "path": "_overlay/log.h",
            "sha256": "c" * 64,
            "role": "dependency-header",
            "upstream_repo": "https://gitee.com/openharmony/third_party_sample",
            "upstream_commit": "d" * 40,
            "license": "Apache-2.0",
            "note": "reduced no-op logging header",
        }
    ],
}


def write_case(payload) -> Path:
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False, encoding="utf-8"
    )
    json.dump(payload, handle, ensure_ascii=False)
    handle.close()
    return Path(handle.name)


def load_or_skip(test):
    if load_openharmony_case is None:
        test.fail("lima.openharmony_validation not implemented yet")
    return None


class OpenHarmonyCaseContractTests(unittest.TestCase):
    def test_valid_case_decodes_with_sorted_deduped_tuples(self):
        load_or_skip(self)
        shuffled = dict(VALID_CASE)
        shuffled["translation_units"] = ["src/extra.c", "src/parser.c", "src/extra.c"]
        shuffled["target_paths"] = ["src/parser.c", "src/a.c", "src/a.c"]
        shuffled["advisory_urls"] = ["https://example.org/a", ADVISORY]
        case = load_openharmony_case(write_case(shuffled))
        self.assertIsInstance(case, OpenHarmonyCase)
        self.assertEqual(case.translation_units, ("src/extra.c", "src/parser.c"))
        self.assertEqual(case.target_paths, ("src/a.c", "src/parser.c"))
        self.assertEqual(
            case.advisory_urls, ("https://example.org/a", ADVISORY)
        )
        self.assertEqual(case.cwe, "CWE-416")
        self.assertEqual(case.vulnerable.commit, "a" * 40)
        self.assertEqual(case.vulnerable.repository_key, "sample-vuln")
        self.assertEqual(
            case.dependency_overlay,
            (DependencyOverlayEntry(
                path="_overlay/log.h",
                sha256="c" * 64,
                role="dependency-header",
                upstream_repo=REPO,
                upstream_commit="d" * 40,
                license="Apache-2.0",
                note="reduced no-op logging header",
            ),),
        )
        # Input order never leaks into the decoded case.
        again = load_openharmony_case(write_case(VALID_CASE))
        self.assertEqual(again.dependency_overlay, case.dependency_overlay)

    def test_overlay_field_is_optional(self):
        load_or_skip(self)
        payload = {k: v for k, v in VALID_CASE.items() if k != "dependency_overlay"}
        case = load_openharmony_case(write_case(payload))
        self.assertEqual(case.dependency_overlay, ())

    def test_overlay_less_case_survives_export_reload(self):
        # Review finding 7: the loader allowed an omitted overlay but
        # rejected the exporter's explicit empty list, so a bundle's
        # case.json could not be fed back as a replay input.  Both
        # spellings of "no overlay" must decode identically.
        load_or_skip(self)
        from lima.openharmony_validation import _case_document

        payload = {k: v for k, v in VALID_CASE.items() if k != "dependency_overlay"}
        case = load_openharmony_case(write_case(payload))
        document = _case_document(case)
        self.assertEqual([], document["dependency_overlay"])
        reloaded = load_openharmony_case(write_case(document))
        self.assertEqual((), reloaded.dependency_overlay)
        # The explicit empty list also decodes on its own.
        self.assertEqual(
            (),
            load_openharmony_case(write_case(
                dict(payload, dependency_overlay=[])
            )).dependency_overlay,
        )

    def test_unknown_and_missing_fields_rejected(self):
        load_or_skip(self)
        extra = dict(VALID_CASE)
        extra["surprise"] = 1
        with self.assertRaises(ValueError):
            load_openharmony_case(write_case(extra))
        for field in VALID_CASE:
            payload = {k: v for k, v in VALID_CASE.items() if k != field}
            if field == "dependency_overlay":
                continue  # optional
            with self.assertRaises(ValueError, msg=f"missing {field}"):
                load_openharmony_case(write_case(payload))

    def test_duplicate_json_keys_rejected(self):
        load_or_skip(self)
        text = json.dumps(VALID_CASE)[:-1] + ', "case_id": "other"}'
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        )
        handle.write(text)
        handle.close()
        with self.assertRaises(ValueError):
            load_openharmony_case(Path(handle.name))

    def test_nan_and_infinity_rejected(self):
        load_or_skip(self)
        text = json.dumps(VALID_CASE).replace('"MIT"', "NaN")
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        )
        handle.write(text)
        handle.close()
        with self.assertRaises(ValueError):
            load_openharmony_case(Path(handle.name))

    def test_closed_enums_rejected(self):
        load_or_skip(self)
        for field, bad in (
            ("schema_version", "openharmony-validation-v2"),
            ("cwe", "CWE-415"),
            ("cwe", "cwe-416"),
            ("build_context_mode", "heuristic"),
            ("cve_id", "CVE-26-1"),
            ("cve_id", "GHSA-xxxx"),
        ):
            payload = dict(VALID_CASE)
            payload[field] = bad
            with self.assertRaises(ValueError, msg=f"{field}={bad!r}"):
                load_openharmony_case(write_case(payload))

    def test_commits_must_be_40_lowercase_hex(self):
        load_or_skip(self)
        for bad in ("a" * 39, "A" * 40, "g" * 40, "a" * 41, "short"):
            payload = json.loads(json.dumps(VALID_CASE))
            payload["vulnerable"]["commit"] = bad
            with self.assertRaises(ValueError, msg=bad):
                load_openharmony_case(write_case(payload))

    def test_unsafe_paths_rejected(self):
        load_or_skip(self)
        for field in ("translation_units", "target_paths", "patch_paths"):
            for bad in ("/abs/path.c", "src\\win.c", "../escape.c", "", "src/../x.c"):
                payload = json.loads(json.dumps(VALID_CASE))
                payload[field] = [bad]
                with self.assertRaises(ValueError, msg=f"{field}={bad!r}"):
                    load_openharmony_case(write_case(payload))

    def test_translation_units_must_be_c_family(self):
        load_or_skip(self)
        payload = json.loads(json.dumps(VALID_CASE))
        payload["translation_units"] = ["src/parser.py"]
        with self.assertRaises(ValueError):
            load_openharmony_case(write_case(payload))

    def test_empty_path_lists_rejected(self):
        load_or_skip(self)
        for field in ("translation_units", "target_paths", "patch_paths",
                      "advisory_urls"):
            payload = json.loads(json.dumps(VALID_CASE))
            payload[field] = []
            with self.assertRaises(ValueError, msg=field):
                load_openharmony_case(write_case(payload))

    def test_advisory_urls_must_be_https(self):
        load_or_skip(self)
        payload = json.loads(json.dumps(VALID_CASE))
        payload["advisory_urls"] = ["http://example.org/advisory"]
        with self.assertRaises(ValueError):
            load_openharmony_case(write_case(payload))

    def test_revision_keys_must_differ(self):
        load_or_skip(self)
        payload = json.loads(json.dumps(VALID_CASE))
        payload["fixed"]["repository_key"] = payload["vulnerable"]["repository_key"]
        with self.assertRaises(ValueError):
            load_openharmony_case(write_case(payload))

    def test_overlay_entries_validated(self):
        load_or_skip(self)
        base_entry = dict(VALID_CASE["dependency_overlay"][0])
        for field, bad in (
            ("path", "overlay/log.h"),
            ("path", "_overlay/../log.h"),
            ("path", "_overlay/sub/../../log.h"),
            ("sha256", "c" * 63),
            ("sha256", "C" * 64),
            ("role", "dependency-source"),
            ("upstream_commit", "not-a-sha"),
            ("upstream_repo", "http://example.org/x"),
            ("license", ""),
        ):
            payload = json.loads(json.dumps(VALID_CASE))
            entry = dict(base_entry)
            entry[field] = bad
            payload["dependency_overlay"] = [entry]
            with self.assertRaises(ValueError, msg=f"{field}={bad!r}"):
                load_openharmony_case(write_case(payload))
        # An explicitly empty overlay list means the same as an omitted
        # field; the exporter emits it, so it must reload (review 7).
        payload = json.loads(json.dumps(VALID_CASE))
        payload["dependency_overlay"] = []
        self.assertEqual(
            (),
            load_openharmony_case(write_case(payload)).dependency_overlay,
        )
        # Duplicate overlay paths are rejected.
        payload = json.loads(json.dumps(VALID_CASE))
        payload["dependency_overlay"] = [base_entry, dict(base_entry)]
        with self.assertRaises(ValueError):
            load_openharmony_case(write_case(payload))

    def test_bounded_text_rejected(self):
        load_or_skip(self)
        payload = json.loads(json.dumps(VALID_CASE))
        payload["remediation"] = "x" * 100_000
        with self.assertRaises(ValueError):
            load_openharmony_case(write_case(payload))


class CaseSchemaParityTests(unittest.TestCase):
    """evaluation_data/openharmony/schema.json mirrors the Python parser."""

    SCHEMA = (
        Path(__file__).resolve().parents[1]
        / "evaluation_data" / "openharmony" / "schema.json"
    )

    def test_schema_fields_match_parser_contract(self):
        from lima.openharmony_validation import (
            CASE_BUILD_CONTEXT_MODE,
            CASE_CWE,
            CASE_FIELDS,
            OPTIONAL_FIELDS,
            OVERLAY_FIELDS,
            OVERLAY_ROLES,
            SCHEMA_VERSION,
        )

        schema = json.loads(self.SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(
            set(schema["properties"]),
            CASE_FIELDS,
            "schema.json properties must equal the parser's closed field set",
        )
        self.assertEqual(
            set(schema["required"]),
            CASE_FIELDS - OPTIONAL_FIELDS,
        )
        self.assertEqual(
            schema["properties"]["schema_version"]["const"], SCHEMA_VERSION
        )
        self.assertEqual(schema["properties"]["cwe"]["const"], CASE_CWE)
        self.assertEqual(
            schema["properties"]["build_context_mode"]["const"],
            CASE_BUILD_CONTEXT_MODE,
        )
        overlay = schema["properties"]["dependency_overlay"]["items"]
        self.assertEqual(set(overlay["properties"]), OVERLAY_FIELDS)
        self.assertEqual(
            set(overlay["properties"]["role"]["enum"]), OVERLAY_ROLES
        )
        # An empty overlay array is the same as an omitted field, so the
        # schema must not carry a minItems bound the Python loader no
        # longer enforces (review finding 7).
        self.assertNotIn(
            "minItems", schema["properties"]["dependency_overlay"],
        )


# ------------------------------------------------------------ git fixtures


_GIT_BASE = [
    "-c", "user.name=pilot", "-c", "user.email=pilot@example.invalid",
    "-c", "safe.directory=*",
    "-c", "core.autocrlf=false", "-c", "core.filemode=false",
]


def _git(path: Path, *args: str) -> str:
    result = subprocess.run(  # noqa: S603
        ["git", "-C", str(path), *_GIT_BASE, *args],  # noqa: S607
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


class CheckoutFixture:
    """Two pinned git checkouts below one import root."""

    def __init__(
        self, overlay: bytes | None = None,
        parser_source: str | None = None,
    ) -> None:
        self.root = Path(tempfile.mkdtemp(suffix="-oh-checkout"))
        self.import_root = self.root / "imports"
        self.import_root.mkdir()
        repo = self.import_root / "sample-vuln"
        repo.mkdir(parents=True)
        _git(repo, "init", "-q")
        (repo / "src").mkdir()
        (repo / "src" / "parser.c").write_text(
            parser_source
            if parser_source is not None
            else "int parse(void) { return 1; }\n",
            encoding="utf-8",
        )
        (repo / "src" / "util.c").write_text(
            "int util(void) { return 2; }\n", encoding="utf-8"
        )
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "vulnerable")
        self.vulnerable_commit = _git(repo, "rev-parse", "HEAD")
        (repo / "src" / "parser.c").write_text(
            parser_source + "\n/* fixed revision */\n"
            if parser_source is not None
            else "int parse(void) { return 2; }\n",
            encoding="utf-8",
        )
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "fixed")
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
        self.overlay_bytes = overlay

    def stage_case_files(self, compdb: dict | None = None) -> dict:
        """Write compdb and overlay into both checkouts; return overlay entry."""
        entry = None
        if self.overlay_bytes is not None:
            for repo in (self.vulnerable_repo, self.fixed_repo):
                overlay_dir = repo / "_overlay"
                overlay_dir.mkdir(exist_ok=True)
                (overlay_dir / "log.h").write_bytes(self.overlay_bytes)
            entry = {
                "path": "_overlay/log.h",
                "sha256": hashlib.sha256(self.overlay_bytes).hexdigest(),
                "role": "dependency-header",
                "upstream_repo": REPO,
                "upstream_commit": "d" * 40,
                "license": "Apache-2.0",
                "note": "reduced no-op logging header",
            }
        document = [{
            "directory": ".",
            "file": "src/parser.c",
            "arguments": [
                "clang-14", "-c", "-I_overlay", "-Isrc", "src/parser.c",
                "-o", "build/parser.o",
            ],
        }] if compdb is None else compdb
        for repo in (self.vulnerable_repo, self.fixed_repo):
            (repo / "compile_commands.json").write_text(
                json.dumps(document), encoding="utf-8"
            )
        return entry

    def case(self, entry: dict | None) -> OpenHarmonyCase:
        payload = json.loads(json.dumps(VALID_CASE))
        payload["vulnerable"]["commit"] = self.vulnerable_commit
        payload["fixed"]["commit"] = self.fixed_commit
        payload["translation_units"] = ["src/parser.c"]
        payload["target_paths"] = ["src/parser.c"]
        payload["patch_paths"] = ["src/parser.c", "src/util.c"]
        if entry is None:
            payload.pop("dependency_overlay", None)
        else:
            payload["dependency_overlay"] = [entry]
        return load_openharmony_case(write_case(payload))


@unittest.skipUnless(
    shutil.which("git") is not None,
    "git is required for the checkout fixtures",
)
class CheckoutValidationTests(unittest.TestCase):
    def setUp(self):
        if load_openharmony_case is None:
            self.fail("lima.openharmony_validation not implemented yet")
        from lima.openharmony_validation import (
            CheckoutPreflightError,
            WorkspaceLimits,
            validate_case_checkouts,
        )
        from lima.repository_import import RepositoryImportPolicy
        self.error = CheckoutPreflightError
        self.limits = WorkspaceLimits
        self.validate = validate_case_checkouts
        self.policy = RepositoryImportPolicy

    def test_happy_path_returns_both_workspaces(self):
        fixture = CheckoutFixture(overlay=b"/* overlay */\n")
        entry = fixture.stage_case_files()
        case = fixture.case(entry)
        vulnerable, fixed = self.validate(
            case, self.policy(str(fixture.import_root)),
            self.limits(max_files=500, max_file_bytes=65536, max_total_bytes=1 << 20),
        )
        self.assertEqual(
            {path.path for path in vulnerable.inventory().files},
            {"src/parser.c", "src/util.c", "compile_commands.json",
             "_overlay/log.h"},
        )

    def test_wrong_head_and_dirty_tree_rejected(self):
        fixture = CheckoutFixture()
        entry = fixture.stage_case_files()
        case = fixture.case(entry)
        policy = self.policy(str(fixture.import_root))
        limits = self.limits(max_files=500, max_file_bytes=65536,
                             max_total_bytes=1 << 20)
        _git(fixture.vulnerable_repo, "checkout", "-q", "--detach",
             fixture.fixed_commit)
        with self.assertRaises(self.error) as caught:
            self.validate(case, policy, limits)
        self.assertEqual("head-mismatch", caught.exception.reason)
        _git(fixture.vulnerable_repo, "checkout", "-q", "--detach",
             fixture.vulnerable_commit)
        (fixture.vulnerable_repo / "src" / "parser.c").write_text(
            "dirty\n", encoding="utf-8"
        )
        with self.assertRaises(self.error) as caught:
            self.validate(case, policy, limits)
        self.assertEqual("tracked-files-dirty", caught.exception.reason)

    def test_staged_changes_rejected_like_dirty_trees(self):
        # Review finding 2: a bare ``git diff --quiet`` compares the
        # worktree to the index only, so staged modifications, additions
        # and deletions passed the preflight while HEAD still matched the
        # pinned commit -- the run then fingerprinted attacker-controlled
        # content as the pinned snapshot.
        policy_maker = self.policy
        limits = self.limits(max_files=500, max_file_bytes=65536,
                             max_total_bytes=1 << 20)

        def _expect_rejected(fixture, case):
            with self.assertRaises(self.error) as caught:
                self.validate(
                    case, policy_maker(str(fixture.import_root)), limits,
                )
            self.assertEqual("tracked-files-dirty", caught.exception.reason)

        # Staged modification of a tracked file.
        fixture = CheckoutFixture()
        entry = fixture.stage_case_files()
        (fixture.vulnerable_repo / "src" / "parser.c").write_text(
            "tampered\n", encoding="utf-8"
        )
        _git(fixture.vulnerable_repo, "add", "src/parser.c")
        _expect_rejected(fixture, fixture.case(entry))

        # Staged addition of a new file.
        fixture = CheckoutFixture()
        entry = fixture.stage_case_files()
        (fixture.vulnerable_repo / "src" / "evil.c").write_text(
            "int evil(void);\n", encoding="utf-8"
        )
        _git(fixture.vulnerable_repo, "add", "src/evil.c")
        _expect_rejected(fixture, fixture.case(entry))

        # Staged deletion of a tracked file (index-only, worktree intact).
        fixture = CheckoutFixture()
        entry = fixture.stage_case_files()
        _git(fixture.vulnerable_repo, "rm", "-q", "--cached", "src/util.c")
        _expect_rejected(fixture, fixture.case(entry))

    def test_missing_files_and_stray_untracked_rejected(self):
        fixture = CheckoutFixture()
        entry = fixture.stage_case_files()
        _git(fixture.vulnerable_repo, "rm", "-q", "src/util.c")
        _git(fixture.vulnerable_repo, "commit", "-q", "-m", "drop util")
        fixture.vulnerable_commit = _git(
            fixture.vulnerable_repo, "rev-parse", "HEAD",
        )
        case = fixture.case(entry)
        policy = self.policy(str(fixture.import_root))
        limits = self.limits(max_files=500, max_file_bytes=65536,
                             max_total_bytes=1 << 20)
        with self.assertRaises(self.error) as caught:
            self.validate(case, policy, limits)
        self.assertEqual("missing-manifest-path", caught.exception.reason)
        fixture2 = CheckoutFixture()
        entry2 = fixture2.stage_case_files()
        case2 = fixture2.case(entry2)
        (fixture2.vulnerable_repo / "generated.h").write_text(
            "x", encoding="utf-8"
        )
        with self.assertRaises(self.error) as caught:
            self.validate(
                case2, self.policy(str(fixture2.import_root)), limits,
            )
        self.assertEqual("untracked-not-allowed", caught.exception.reason)

    def test_overlay_digest_and_cross_checkout_drift_rejected(self):
        fixture = CheckoutFixture(overlay=b"/* overlay */\n")
        entry = fixture.stage_case_files()
        broken = dict(entry, sha256="e" * 64)
        case = fixture.case(broken)
        limits = self.limits(max_files=500, max_file_bytes=65536,
                             max_total_bytes=1 << 20)
        with self.assertRaises(self.error) as caught:
            self.validate(case, self.policy(str(fixture.import_root)), limits)
        self.assertEqual("overlay-digest-mismatch", caught.exception.reason)
        case_good = fixture.case(entry)
        (fixture.fixed_repo / "_overlay" / "log.h").write_bytes(
            b"/* drifted */\n"
        )
        with self.assertRaises(self.error) as caught:
            self.validate(
                case_good, self.policy(str(fixture.import_root)), limits,
            )
        self.assertEqual("overlay-digest-mismatch", caught.exception.reason)

    def test_limits_validated_before_any_work(self):
        fixture = CheckoutFixture()
        entry = fixture.stage_case_files()
        case = fixture.case(entry)
        for kwargs in (
            {"max_files": True, "max_file_bytes": 1, "max_total_bytes": 1},
            {"max_files": 0, "max_file_bytes": 1, "max_total_bytes": 1},
            {"max_files": 1, "max_file_bytes": -1, "max_total_bytes": 1},
            {"max_files": 1, "max_file_bytes": 1, "max_total_bytes": 0},
        ):
            with self.subTest(limits=kwargs):
                with self.assertRaises(ValueError):
                    self.validate(
                        case,
                        self.policy(str(fixture.import_root)),
                        self.limits(**kwargs),
                    )

    def test_duplicate_keys_rejected_at_manifest_load(self):
        # The parser freezes distinct keys, so a duplicate-checkout preflight
        # can never be reached through a decoded manifest.
        payload = json.loads(json.dumps(VALID_CASE))
        payload["fixed"]["repository_key"] = (
            payload["vulnerable"]["repository_key"]
        )
        with self.assertRaises(ValueError):
            load_openharmony_case(write_case(payload))

    def test_unresolvable_root_rejected(self):
        fixture = CheckoutFixture()
        entry = fixture.stage_case_files()
        case = fixture.case(entry)
        limits = self.limits(max_files=500, max_file_bytes=65536,
                             max_total_bytes=1 << 20)
        with self.assertRaises(self.error) as caught:
            self.validate(
                case, self.policy(str(fixture.root / "empty")), limits,
            )
        self.assertEqual("repository-key-unresolvable", caught.exception.reason)


# --------------------------------------------------------- paired-run tests


def _observation(*, ok=False, stage="run", error_type=None,
                 faulting_file=None, exit_code=None):
    from lima.agent_repro_tools import ExperimentObservation
    return ExperimentObservation(
        ok=ok, stage=stage, exit_code=exit_code, error_type=error_type,
        faulting_line=30 if error_type else None,
        freed_line=20 if error_type else None,
        allocated_line=10 if error_type else None,
        diagnostics=(), raw_tail="",
        faulting_file=faulting_file,
    )


def _finding(path="src/parser.c", cwe="CWE-416", state="runtime-confirmed",
             driver="int main() { return 0; }"):
    from lima.agent_orchestrator import PlatformFinding
    from lima.models import EvidenceRecord
    runtime_evidence = (
        EvidenceRecord(
            source="asan", kind="runtime", path=path, line=30,
            snippet="==1==ERROR: AddressSanitizer: heap-use-after-free",
            rule_id="asan.repro", cwe=cwe, symbol="parse",
            tool_run_id="run-uaf-1",
        ),
    ) if state == "runtime-confirmed" else ()
    experiment_log = (
        {
            "round": 1, "driver_sha256": "0123456789abcdef", "stage": "run",
            "ok": False, "exit_code": 1,
            "error_type": "heap-use-after-free", "faulting_line": 30,
            "faulting_file": path, "hit": True,
        },
    ) if state == "runtime-confirmed" else ()
    return PlatformFinding(
        target_id="discovery-1", path=path, line=30, symbol="parse",
        cwe=cwe, state=state, hypothesis_reason="hypothesis",
        poc_driver_code=driver, experiment_log=experiment_log,
        identity=None, evidence_records=runtime_evidence,
    )


def _outcome(findings, diagnostics=(), unreviewed_units=()):
    from lima.agent_orchestrator import (
        PlatformReviewOutcome,
        PlatformReviewStats,
    )
    return PlatformReviewOutcome(
        findings=tuple(findings), targets=tuple(findings),
        stats=PlatformReviewStats(1, 1, len(findings), 0, 0, 0, 0),
        diagnostics=tuple(diagnostics),
        unreviewed_units=tuple(unreviewed_units),
    )


class FakeWorkbench:
    """Scripted run_experiment responses keyed by call order."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def run_experiment(self, repository_key, snapshot_hash, sources, driver,
                       **kwargs):
        self.calls.append((repository_key, tuple(sources), driver))
        if not self.responses:
            raise AssertionError("workbench exhausted")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


@unittest.skipUnless(
    shutil.which("git") is not None,
    "git is required for the checkout fixtures",
)
class PairedRunTests(unittest.TestCase):
    def setUp(self):
        if load_openharmony_case is None:
            self.fail("lima.openharmony_validation not implemented yet")
        from lima import openharmony_validation as module
        from lima.cxx_agent_tools import CxxAgentBudget
        from lima.repository_import import RepositoryImportPolicy
        self.module = module
        self.budget_factory = lambda: CxxAgentBudget(
            max_calls=64, max_output_bytes=1 << 20,
        )
        self.policy = RepositoryImportPolicy
        self.fixture = CheckoutFixture(overlay=b"/* overlay */\n")
        self.entry = self.fixture.stage_case_files()
        self.case = self.fixture.case(self.entry)
        self.limits = module.WorkspaceLimits(
            max_files=500, max_file_bytes=65536, max_total_bytes=1 << 20,
        )

    def _run(self, *, vulnerable_outcome, fixed_outcome=None,
             vulnerable_replay=(), fixed_replay=(), review_error=None):
        """Patch the review boundary and workbench; run the paired case."""
        from unittest.mock import patch

        module = self.module
        outcomes = {
            self.case.vulnerable.repository_key: vulnerable_outcome,
            self.case.fixed.repository_key: fixed_outcome,
        }
        scripted = {"vulnerable": list(vulnerable_replay),
                    "fixed": list(fixed_replay)}
        current = {"key": None}

        def fake_review(analyzer, workspace, *, repository_key, **kwargs):
            current["key"] = repository_key
            if review_error is not None:
                raise review_error
            return outcomes[repository_key]

        workbenches = []
        construction = {"index": 0}

        def fake_workbench(client, budget, default_timeout=60):
            # Construction order is deterministic: the vulnerable revision
            # runs first, so its workbench is built first.
            side = "vulnerable" if construction["index"] == 0 else "fixed"
            construction["index"] += 1
            bench = FakeWorkbench(scripted[side])
            workbenches.append((side, bench))
            return bench

        with patch.object(module, "run_platform_review", fake_review), \
                patch.object(module, "ReproWorkbench", fake_workbench):
            return module.run_openharmony_case(
                self.case,
                import_policy=self.policy(str(self.fixture.import_root)),
                workspace_limits=self.limits,
                analyzer_client=object(),
                llm_config={"provider": "custom", "base_url": "x",
                            "api_key": "k", "model": "m"},
                budget_factory=self.budget_factory,
                timeout=60, deadline_seconds=600.0,
                parallelism=1, dialogue_rounds=1,
            ), workbenches

    def test_vulnerable_hits_and_fixed_clean_passes(self):
        target_hit = _observation(
            ok=False, stage="run", error_type="'heap-use-after-free'",
            faulting_file="'src/parser.c'", exit_code=1,
        )
        clean = _observation(ok=True, stage="run", exit_code=0)
        result, workbenches = self._run(
            vulnerable_outcome=_outcome([_finding()]),
            vulnerable_replay=[target_hit] * 3,
            fixed_outcome=_outcome([]),
            fixed_replay=[clean] * 3,
        )
        self.assertEqual("passed", result.status.value)
        self.assertEqual(3, len(result.vulnerable.replay_observations))
        self.assertEqual(3, len(result.fixed.replay_observations))
        self.assertEqual((), result.reason_codes)
        # The vulnerable driver replays on the fixed snapshot unchanged.
        vulnerable_calls = workbenches[0][1].calls
        fixed_calls = workbenches[1][1].calls
        self.assertEqual(3, len(vulnerable_calls))
        self.assertEqual(3, len(fixed_calls))
        self.assertEqual(vulnerable_calls[0][2], fixed_calls[0][2])

    def test_unstable_vulnerable_replay_fails(self):
        target_hit = _observation(
            ok=False, stage="run", error_type="'heap-use-after-free'",
            faulting_file="'src/parser.c'", exit_code=1,
        )
        clean = _observation(ok=True, stage="run", exit_code=0)
        result, _ = self._run(
            vulnerable_outcome=_outcome([_finding()]),
            vulnerable_replay=[target_hit, target_hit, clean],
            fixed_outcome=_outcome([]),
            fixed_replay=[clean] * 3,
        )
        self.assertEqual("failed", result.status.value)
        self.assertIn("vulnerable-replay-unstable", result.reason_codes)

    def test_fixed_replay_hit_fails(self):
        target_hit = _observation(
            ok=False, stage="run", error_type="'heap-use-after-free'",
            faulting_file="'src/parser.c'", exit_code=1,
        )
        clean = _observation(ok=True, stage="run", exit_code=0)
        result, _ = self._run(
            vulnerable_outcome=_outcome([_finding()]),
            vulnerable_replay=[target_hit] * 3,
            fixed_outcome=_outcome([]),
            fixed_replay=[clean, clean, target_hit],
        )
        self.assertEqual("failed", result.status.value)
        self.assertIn("fixed-replay-hit", result.reason_codes)

    def test_fixed_compile_failure_is_inconclusive(self):
        target_hit = _observation(
            ok=False, stage="run", error_type="'heap-use-after-free'",
            faulting_file="'src/parser.c'", exit_code=1,
        )
        compile_fail = _observation(
            ok=False, stage="compile", exit_code=1,
        )
        result, _ = self._run(
            vulnerable_outcome=_outcome([_finding()]),
            vulnerable_replay=[target_hit] * 3,
            fixed_outcome=_outcome([]),
            fixed_replay=[compile_fail, compile_fail, compile_fail],
        )
        self.assertEqual("inconclusive", result.status.value)
        self.assertIn("fixed-replay-compile-failure", result.reason_codes)

    def test_no_matching_vulnerable_finding_fails(self):
        clean = _observation(ok=True, stage="run", exit_code=0)
        result, _ = self._run(
            vulnerable_outcome=_outcome([]),
            fixed_outcome=_outcome([]),
            fixed_replay=[clean] * 3,
        )
        self.assertEqual("failed", result.status.value)
        self.assertIn("vulnerable-no-matching-finding", result.reason_codes)

    def test_provider_failure_is_inconclusive(self):
        from lima.reviewer import LLMTransportError
        result, _ = self._run(
            vulnerable_outcome=None,
            review_error=LLMTransportError("provider unreachable"),
        )
        self.assertEqual("inconclusive", result.status.value)
        self.assertTrue(
            any(code.startswith("vulnerable-review-failed")
                for code in result.reason_codes),
            result.reason_codes,
        )

    def test_discovery_degradation_is_inconclusive_not_passed(self):
        # Review finding 1, on the real orchestrator path (the review
        # boundary itself is NOT patched): the provider refuses every
        # required Discovery window, so the review returns normally with
        # zero findings and the revision must land on inconclusive
        # instead of laundering an unaudited snapshot into a pass.
        from unittest.mock import patch
        from lima.reviewer import LLMTransportError

        def dead_provider(*args, **kwargs):
            raise LLMTransportError("provider down")

        with patch(
            "lima.agent_orchestrator.send_semantic_request", dead_provider,
        ), patch.object(
            self.module, "ReproWorkbench",
            lambda client, budget, default_timeout=60: FakeWorkbench([]),
        ):
            result = self.module.run_openharmony_case(
                self.case,
                import_policy=self.policy(str(self.fixture.import_root)),
                workspace_limits=self.limits,
                analyzer_client=None,
                llm_config={"provider": "custom", "base_url": "x",
                            "api_key": "k", "model": "m"},
                budget_factory=self.budget_factory,
                timeout=60, deadline_seconds=600.0,
                parallelism=1, dialogue_rounds=1,
            )
        self.assertEqual("inconclusive", result.status.value)
        self.assertEqual(
            ("src/parser.c",),
            result.vulnerable.platform_outcome.unreviewed_units,
        )
        self.assertTrue(any(
            code.startswith("required-review-unreviewed-units")
            for code in result.reason_codes
        ), result.reason_codes)
        self.assertIn("fixed-not-run", result.reason_codes)

    def test_discovery_partial_window_degradation_is_inconclusive(self):
        # Round 2 review, the reviewer's own probe on the real
        # orchestrator path: one translation unit spanning several
        # windows.  The first window completes, a later one fails
        # transport.  The completed window keeps its (empty) reply and
        # the loop kept going, but the unit's coverage is partial -- the
        # paired validation must land on inconclusive, not passed.
        from unittest.mock import patch
        from lima.reviewer import LLMTransportError

        two_window_source = "\n".join(
            f"int filler_{index}(void) {{ return {index}; }}"
            for index in range(4000)
        )
        self.fixture = CheckoutFixture(parser_source=two_window_source)
        self.entry = self.fixture.stage_case_files()
        self.case = self.fixture.case(self.entry)
        # The multi-window source is ~145 KB, past the default 64 KB
        # per-file bound; widen the limits so the preflight accepts it.
        self.limits = self.module.WorkspaceLimits(
            max_files=500, max_file_bytes=262144,
            max_total_bytes=1 << 22,
        )

        sends = []

        def partially_dead_provider(*args, **kwargs):
            sends.append(args)
            if len(sends) == 1:
                return json.dumps({"leads": []})
            raise LLMTransportError("gateway down")

        with patch(
            "lima.agent_orchestrator.send_semantic_request",
            partially_dead_provider,
        ), patch.object(
            self.module, "ReproWorkbench",
            lambda client, budget, default_timeout=60: FakeWorkbench([]),
        ):
            result = self.module.run_openharmony_case(
                self.case,
                import_policy=self.policy(str(self.fixture.import_root)),
                workspace_limits=self.limits,
                analyzer_client=None,
                llm_config={"provider": "custom", "base_url": "x",
                            "api_key": "k", "model": "m"},
                budget_factory=self.budget_factory,
                timeout=60, deadline_seconds=600.0,
                parallelism=1, dialogue_rounds=1,
            )
        self.assertGreaterEqual(len(sends), 2)
        self.assertEqual("inconclusive", result.status.value)
        self.assertEqual(
            ("src/parser.c",),
            result.vulnerable.platform_outcome.unreviewed_units,
        )
        self.assertTrue(any(
            code.startswith("required-review-unreviewed-units")
            for code in result.reason_codes
        ), result.reason_codes)

    def test_fixed_partial_unreviewed_blocks_pass(self):
        # The reviewer's end-to-end shape: the vulnerable side confirms
        # 3/3 and the fixed side replays clean, but the fixed review has
        # partially unaudited units -- the pair is inconclusive, never a
        # pass.
        target_hit = _observation(
            ok=False, stage="run", error_type="'heap-use-after-free'",
            faulting_file="'src/parser.c'", exit_code=1,
        )
        clean = _observation(ok=True, stage="run", exit_code=0)
        result, _ = self._run(
            vulnerable_outcome=_outcome([_finding()]),
            vulnerable_replay=[target_hit] * 3,
            fixed_outcome=_outcome(
                [], unreviewed_units=("src/parser.c",),
            ),
            fixed_replay=[clean] * 3,
        )
        from lima.openharmony_validation import ValidationStatus

        self.assertEqual("inconclusive", result.status.value)
        self.assertEqual(
            ValidationStatus.INCONCLUSIVE, result.fixed.status,
        )
        self.assertTrue(any(
            code.startswith("required-review-unreviewed-units")
            for code in result.reason_codes
        ), result.reason_codes)

    def test_unrelated_fixed_findings_are_recorded_not_decisive(self):
        target_hit = _observation(
            ok=False, stage="run", error_type="'heap-use-after-free'",
            faulting_file="'src/parser.c'", exit_code=1,
        )
        clean = _observation(ok=True, stage="run", exit_code=0)
        unrelated = _finding(path="src/util.c", cwe="CWE-476",
                             state="semantic-supported")
        result, _ = self._run(
            vulnerable_outcome=_outcome([_finding()]),
            vulnerable_replay=[target_hit] * 3,
            fixed_outcome=_outcome([unrelated]),
            fixed_replay=[clean] * 3,
        )
        self.assertEqual("passed", result.status.value)
        self.assertEqual(
            (unrelated.path, unrelated.cwe),
            (result.fixed.platform_outcome.findings[0].path,
             result.fixed.platform_outcome.findings[0].cwe),
        )


# --------------------------------------------------------- bundle writer


@unittest.skipUnless(
    shutil.which("git") is not None,
    "git is required for the checkout fixtures",
)
class BundleWriterTests(unittest.TestCase):
    def setUp(self):
        if load_openharmony_case is None:
            self.fail("lima.openharmony_validation not implemented yet")
        import shutil

        from lima import openharmony_validation as module
        self.module = module
        self.root = Path(tempfile.mkdtemp(suffix="-oh-bundle"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        paired = PairedRunTests("test_vulnerable_hits_and_fixed_clean_passes")
        paired.setUp()
        self.addCleanup(shutil.rmtree, str(paired.fixture.root), True)
        result, _ = paired._run(
            vulnerable_outcome=_outcome([_finding()]),
            vulnerable_replay=[
                _observation(
                    ok=False, stage="run",
                    error_type="'heap-use-after-free'",
                    faulting_file="'src/parser.c'", exit_code=1,
                )] * 3,
            fixed_outcome=_outcome([]),
            fixed_replay=[
                _observation(ok=True, stage="run", exit_code=0)] * 3,
        )
        self.result = result
        self.fixture = paired.fixture
        self.case = paired.case

    def _write(self, target=None):
        output = target or (self.root / "bundle")
        return self.module.write_validation_bundle(
            self.result, output,
            git_root=self.fixture.vulnerable_repo,
        )

    def test_bundle_layout_digests_and_summary(self):
        output = self._write()
        names = sorted(
            str(item.relative_to(output)).replace("\\", "/")
            for item in output.rglob("*") if item.is_file()
        )
        self.assertIn("case.json", names)
        self.assertIn("summary.json", names)
        self.assertIn("vulnerable/platform.json", names)
        self.assertIn("vulnerable/aep.json", names)
        self.assertIn("vulnerable/poc_driver.cpp", names)
        self.assertIn("vulnerable/replay-01.json", names)
        self.assertIn("vulnerable/replay-03.json", names)
        self.assertIn("fixed/replay-01.json", names)
        self.assertIn("patch.diff", names)
        self.assertIn("report.md", names)
        self.assertIn("SHA256SUMS.json", names)
        self.assertTrue(
            any(name.startswith("vulnerable/vep-") for name in names), names,
        )
        sums = json.loads(
            (output / "SHA256SUMS.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            sorted(set(names) - {"SHA256SUMS.json"}),
            sorted(sums),
        )
        self.assertEqual(list(sums), sorted(sums))
        for relative, digest in sums.items():
            data = (output / relative).read_bytes()
            self.assertEqual(
                digest, hashlib.sha256(data).hexdigest(), relative,
            )
        summary = json.loads(
            (output / "summary.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            "competition-validation", summary["artifact_scope"],
        )
        self.assertEqual("passed", summary["status"])
        self.assertEqual(self.case.case_id, summary["case_id"])
        case = json.loads(
            (output / "case.json").read_text(encoding="utf-8")
        )
        self.assertEqual(self.case.cve_id, case["cve_id"])
        patch = (output / "patch.diff").read_text(encoding="utf-8")
        self.assertIn("src/parser.c", patch)
        report = (output / "report.md").read_text(encoding="utf-8")
        self.assertIn(self.case.remediation[:30], report)
        self.assertIn("3+3", report)
        self.assertIn(self.case.vulnerable.commit[:12], report)
        self.assertIn(self.case.advisory_urls[0], report)

    def test_existing_output_rejected_and_atomic_publish(self):
        existing = self.root / "bundle"
        existing.mkdir()
        with self.assertRaises(ValueError):
            self._write()
        existing.rmdir()
        from unittest.mock import patch
        with patch(
            "os.rename", side_effect=OSError("disk vanished"),
        ) as fake:
            with self.assertRaises(OSError):
                self._write()
            fake.assert_called_once()
        self.assertFalse((self.root / "bundle").exists())
        leftovers = [
            item for item in self.root.iterdir()
            if item.name != "bundle"
        ]
        self.assertEqual([], leftovers, leftovers)

    def test_secrets_never_reach_the_bundle(self):
        import shutil

        from lima.reviewer import LLMTransportError
        paired = PairedRunTests("test_provider_failure_is_inconclusive")
        paired.setUp()
        self.addCleanup(shutil.rmtree, str(paired.fixture.root), True)
        marker = "sk-SECRETMARKER123"
        result, _ = paired._run(
            vulnerable_outcome=None,
            review_error=LLMTransportError(f"key {marker} rejected"),
        )
        output = self.root / "secret-bundle"
        self.module.write_validation_bundle(
            result, output, git_root=paired.fixture.vulnerable_repo,
        )
        for item in output.rglob("*"):
            if item.is_file():
                self.assertNotIn(
                    marker, item.read_text(encoding="utf-8", errors="replace"),
                    item.name,
                )

    def test_large_report_keeps_the_verification_appendix(self):
        # A real dossier body alone runs past the diagnostic text budget;
        # the report must keep its larger bound so the 3+3 appendix and
        # honesty sections never truncate away.
        import dataclasses

        padded_case = dataclasses.replace(
            self.case, remediation=self.case.remediation + "填充" * 3000,
        )
        padded = dataclasses.replace(self.result, case=padded_case)
        output = self.root / "big-report-bundle"
        self.module.write_validation_bundle(
            padded, output, git_root=self.fixture.vulnerable_repo,
        )
        report = (output / "report.md").read_text(encoding="utf-8")
        self.assertGreater(len(report), 4096)
        for marker in ("3+3", "真实性边界", padded_case.vulnerable.commit[:12]):
            self.assertIn(marker, report)

    def test_oversized_diagnostics_are_omitted_not_corrupt(self):
        record = self.result.vulnerable
        from dataclasses import replace as _replace
        inflated = _replace(
            self.result,
            vulnerable=_replace(
                record,
                diagnostics=record.diagnostics + ("x" * 100_000,),
            ),
        )
        output = self.root / "big-bundle"
        self.module.write_validation_bundle(
            inflated, output, git_root=self.fixture.vulnerable_repo,
        )
        summary = json.loads(
            (output / "summary.json").read_text(encoding="utf-8")
        )
        self.assertIn("(omitted", json.dumps(summary))


class PilotCaseConsistencyTests(unittest.TestCase):
    """The frozen pilot case and its offline CVE index entry agree."""

    ROOT = Path(__file__).resolve().parents[1]
    CASE = ROOT / "evaluation_data" / "openharmony" / "pilot_case.json"
    INDEX = ROOT / "evaluation_data" / "cve_index" / "openharmony_pilot.json"

    def test_pilot_case_loads_and_matches_cve_index(self):
        from lima.agent_report import load_cve_index, match_cve

        case = load_openharmony_case(self.CASE)
        entries = load_cve_index(self.INDEX)
        self.assertEqual(1, len(entries))
        entry = entries[0]
        # The three shared keys must agree with the frozen manifest.
        self.assertEqual(case.cve_id, entry["cve_id"])
        self.assertEqual(case.component, entry["component"])
        self.assertEqual(case.fixed.commit, entry["fixed_commit"])
        self.assertTrue(
            all(
                path in case.target_paths
                for path in entry["affected_paths"]
            ),
            "index affected_paths must be pinned to the manifest targets",
        )
        # Introduced commit stays empty unless publicly evidenced.
        self.assertEqual("", entry["introduced_commit"])
        # The exact three-key lookup matches, and any valued-key drift
        # breaks it.
        target = case.target_paths[0]
        self.assertEqual(
            (case.cve_id,),
            match_cve(case.component, target, None, entries),
        )
        self.assertEqual(
            (), match_cve("other-component", target, None, entries)
        )
        self.assertEqual(
            (), match_cve(case.component, "other/file.c", None, entries)
        )


# ------------------------------------------------------------- CLI tests


class CliTests(unittest.TestCase):
    """Argument validation, exit codes, secret redaction; no network."""

    ROOT = Path(__file__).resolve().parents[1]
    CASE = ROOT / "evaluation_data" / "openharmony" / "pilot_case.json"

    ENV = {
        "LIMA_LLM_BASE_URL": "http://llm.example.invalid/v1",
        "LIMA_LLM_API_KEY": "sk-CLIKEY123",
        "LIMA_CXX_AGENT_MODEL": "test-model",
    }

    def setUp(self):
        if load_openharmony_case is None:
            self.fail("lima.openharmony_validation not implemented yet")
        import importlib

        self.cli = importlib.import_module(
            "scripts.run_openharmony_validation"
        )

    def _argv(self, *extra):
        return [
            "--case", str(self.CASE),
            "--repository-import-root", "D:/nowhere",
            "--output", "unused",
            *extra,
        ]

    def _run(self, argv, env=None):
        stdout = io.StringIO()
        environment = dict(os.environ)
        environment.update(self.ENV if env is None else env)
        with patch.dict(
            os.environ, environment, clear=False,
        ), contextlib.redirect_stdout(stdout):
            code = self.cli.main(argv)
        return code, stdout.getvalue()

    def test_missing_required_argument_exits_three(self):
        for argv in (
            [],
            ["--case", str(self.CASE)],
            ["--case", str(self.CASE), "--repository-import-root", "D:/x"],
            ["--output", "o"],
        ):
            with self.subTest(argv=argv):
                self.assertEqual(3, self._run(argv)[0])

    def test_invalid_numbers_exit_three(self):
        for bad in (
            ["--timeout", "0"],
            ["--timeout", "abc"],
            ["--deadline-seconds", "-1"],
            ["--parallelism", "0"],
            ["--dialogue-rounds", "0"],
            ["--max-files", "-5"],
        ):
            with self.subTest(flag=bad):
                self.assertEqual(3, self._run(self._argv(*bad))[0])

    def test_missing_provider_exits_three(self):
        code, text = self._run(
            self._argv(), env={"LIMA_LLM_BASE_URL": ""},
        )
        self.assertEqual(3, code)
        self.assertIn("provider", text.lower())

    def _fixture_result(self, status):
        from lima.openharmony_validation import (
            OpenHarmonyValidationResult,
            RevisionValidation,
            WorkspaceLimits,
        )

        case = load_openharmony_case(self.CASE)
        empty = RevisionValidation(
            revision=case.vulnerable, status=status, snapshot_hash="",
            platform_outcome=None, replay_observations=(),
            replay_elapsed_seconds=(), elapsed_seconds=0.0,
            file_coverage=0.0, byte_coverage=0.0, budget_usage={},
            diagnostics=(),
        )
        return OpenHarmonyValidationResult(
            case=case,
            workspace_limits=WorkspaceLimits(
                max_files=1, max_file_bytes=1, max_total_bytes=1,
            ),
            status=status, reason_codes=(), vulnerable=empty, fixed=empty,
            total_elapsed_seconds=0.0,
        )

    def test_business_exit_codes(self):
        from lima.openharmony_validation import ValidationStatus

        for status, expected in (
            (ValidationStatus.PASSED, 0),
            (ValidationStatus.FAILED, 2),
            (ValidationStatus.INCONCLUSIVE, 3),
        ):
            with self.subTest(status=status):
                with patch.object(
                    self.cli, "run_openharmony_case",
                    return_value=self._fixture_result(status),
                ), patch.object(
                    self.cli, "write_validation_bundle",
                    return_value=Path("bundle"),
                ):
                    code, _ = self._run(self._argv())
                self.assertEqual(expected, code)

    def test_output_conflict_and_secret_redaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "bundle"
            output.mkdir()
            code, text = self._run(self._argv("--output", str(output)))
            self.assertEqual(3, code)
            self.assertIn("already exists", text)
            self.assertNotIn("sk-CLIKEY123", text)


if __name__ == "__main__":
    unittest.main()
