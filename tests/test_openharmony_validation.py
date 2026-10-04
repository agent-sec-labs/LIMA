"""Contract tests for the frozen OpenHarmony pilot case manifest."""

import json
import tempfile
import unittest
from pathlib import Path

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
        # Empty overlay list is rejected; drop the field entirely instead.
        payload = json.loads(json.dumps(VALID_CASE))
        payload["dependency_overlay"] = []
        with self.assertRaises(ValueError):
            load_openharmony_case(write_case(payload))
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


if __name__ == "__main__":
    unittest.main()
