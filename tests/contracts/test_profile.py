"""Deterministic repository profile domain tests (IP-0003 packet sections 9-14, 17)."""

import unittest
from pathlib import Path

from lima.contracts.codec import (
    canonical_decode,
    canonical_encode,
    compute_content_digest,
)
from lima.contracts.common import SchemaVersion
from lima.contracts.errors import ContractError, ContractErrorCode
from lima.contracts.profile import (
    AttackSurfaceEntry,
    CodeRole,
    CodeRoleAssignment,
    DetectionMethod,
    ExecutionCapability,
    ProfileCoverageGap,
    RepositoryKind,
    RepositoryProfile,
    SupportLevel,
    TechnologyDeclaration,
    decode_profile_payload,
    encode_profile_payload,
)

VERSION_4_0 = SchemaVersion(4, 0)
VERSION_4_2 = SchemaVersion(4, 2)
FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "repository_profile_v4_golden.json"
)
GOLDEN_PAYLOAD_DIGEST = (
    "ad7d53a0ed22412dbbfc60d0ed9183d7e939e2d14e4eee2d9399944cb5c4dccc"
)
FORBIDDEN_VERDICT_KEYS = frozenset(
    {"confidence", "severity", "trust_score", "is_secure", "is_safe"}
)


def _capability(**overrides):
    kwargs = {
        "buildable": True,
        "testable": True,
        "requires_network": False,
        "requires_services": False,
        "requires_gpu": False,
        "requires_external_credentials": False,
    }
    kwargs.update(overrides)
    return ExecutionCapability(**kwargs)


def _capability_dict(**overrides):
    wire = {
        "buildable": False,
        "testable": False,
        "requires_network": False,
        "requires_services": False,
        "requires_gpu": False,
        "requires_external_credentials": False,
    }
    wire.update(overrides)
    return wire


def _tech(name="python", detection=DetectionMethod.DECLARED, artifacts=("tool-run-0001",)):
    return TechnologyDeclaration(
        name=name, detection=detection, source_artifact_ids=artifacts
    )


def _tech_dict(name="python", detection="declared"):
    return {
        "name": name,
        "detection": detection,
        "source_artifact_ids": ["tool-run-0001"],
    }


def _role(
    role=CodeRole.PRODUCTION,
    path="src/cli.py",
    reasons=("PATH_PATTERN_SRC",),
    artifacts=("tool-run-0001",),
):
    return CodeRoleAssignment(
        role=role, path=path, reason_codes=reasons, source_artifact_ids=artifacts
    )


def _role_dict(role="production", path="src/cli.py"):
    return {
        "role": role,
        "path": path,
        "reason_codes": ["PATH_PATTERN_SRC"],
        "source_artifact_ids": ["tool-run-0001"],
    }


def _entry(
    path="src/cli.py",
    symbol="main",
    reasons=("CLI_ENTRY_SCRIPT",),
    artifacts=("tool-run-0001",),
):
    return AttackSurfaceEntry(
        path=path, reason_codes=reasons, source_artifact_ids=artifacts, symbol=symbol
    )


def _entry_dict(path="src/cli.py", symbol="main"):
    return {
        "path": path,
        "reason_codes": ["CLI_ENTRY_SCRIPT"],
        "source_artifact_ids": ["tool-run-0001"],
        "symbol": symbol,
    }


def _gap(gap_code="FRAMEWORK_DETECTION_PARTIAL", detail="Dynamic imports unresolved."):
    return ProfileCoverageGap(gap_code=gap_code, detail=detail)


def _minimal_payload(**overrides):
    payload = {
        "repository_kinds": ["docs_content"],
        "languages": [],
        "frameworks": [],
        "package_managers": [],
        "build_systems": [],
        "code_roles": [],
        "entrypoints": [],
        "external_inputs": [],
        "trust_boundaries": [],
        "sensitive_operations": [],
        "deployment_surface": [],
        "execution_capability": _capability_dict(),
        "support_level": "partial",
        "component_path": None,
        "file_count": 0,
        "total_bytes": 0,
        "max_file_bytes": 0,
        "code_density_bp": 0,
        "binary_ratio_bp": 0,
        "generated_ratio_bp": 0,
        "coverage_gaps": [],
    }
    payload.update(overrides)
    return payload


class ProfileContractTestCase(unittest.TestCase):
    def assert_rejected(self, invoke, code, field_path=None):
        with self.assertRaises(ContractError) as ctx:
            invoke()
        self.assertIs(ctx.exception.code, code)
        if field_path is not None:
            self.assertEqual(ctx.exception.field_path, field_path)
        return ctx.exception


class ProfileEnumTests(ProfileContractTestCase):
    def test_wire_values_are_exact(self):
        self.assertEqual(
            sorted(member.value for member in RepositoryKind),
            [
                "application",
                "cli",
                "dataset_asset",
                "docs_content",
                "library",
                "monorepo",
                "unknown",
            ],
        )
        self.assertEqual(len(RepositoryKind), 7)
        self.assertEqual(
            sorted(member.value for member in CodeRole),
            [
                "config",
                "dev_tool",
                "documentation",
                "example",
                "generated",
                "production",
                "test",
                "vendored",
            ],
        )
        self.assertEqual(len(CodeRole), 8)
        self.assertEqual(
            sorted(member.value for member in SupportLevel),
            ["partial", "supported", "unsupported"],
        )
        self.assertEqual(len(SupportLevel), 3)
        self.assertEqual(
            sorted(member.value for member in DetectionMethod),
            ["declared", "inferred"],
        )
        self.assertEqual(len(DetectionMethod), 2)


class TechnologyDeclarationTests(ProfileContractTestCase):
    def test_round_trip_has_exact_wire_shape(self):
        declaration = _tech(name="python", detection=DetectionMethod.DECLARED)
        wire = {
            "name": "python",
            "detection": "declared",
            "source_artifact_ids": ["tool-run-0001"],
        }
        self.assertEqual(declaration.to_dict(), wire)
        decoded = TechnologyDeclaration.from_dict(wire, schema_version=VERSION_4_0)
        self.assertEqual(decoded, declaration)
        self.assertEqual(decoded.to_dict(), wire)

    def test_rejects_missing_required_fields(self):
        base = _tech_dict()
        for missing, path in (
            ("name", "$.name"),
            ("detection", "$.detection"),
            ("source_artifact_ids", "$.source_artifact_ids"),
        ):
            data = dict(base)
            del data[missing]
            self.assert_rejected(
                lambda d=data: TechnologyDeclaration.from_dict(
                    d, schema_version=VERSION_4_0
                ),
                ContractErrorCode.REQUIRED_FIELD_MISSING,
                path,
            )

    def test_rejects_unknown_enum_and_wrong_field_type(self):
        self.assert_rejected(
            lambda: TechnologyDeclaration.from_dict(
                _tech_dict(detection="guessed"), schema_version=VERSION_4_0
            ),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            "$.detection",
        )
        wrong_name = _tech_dict()
        wrong_name["name"] = 7
        self.assert_rejected(
            lambda: TechnologyDeclaration.from_dict(wrong_name, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.name",
        )
        wrong_artifacts = _tech_dict()
        wrong_artifacts["source_artifact_ids"] = "tool-run-0001"
        self.assert_rejected(
            lambda: TechnologyDeclaration.from_dict(
                wrong_artifacts, schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.source_artifact_ids",
        )

    def test_rejects_invalid_name_and_unsorted_duplicate_arrays(self):
        for bad_name in ("", "python!", "python ", "питон", "python/2"):
            self.assert_rejected(
                lambda n=bad_name: _tech(name=n),
                ContractErrorCode.INVALID_FIELD_VALUE,
                "$.name",
            )
        unsorted_languages = _minimal_payload(
            repository_kinds=["library"],
            languages=[_tech_dict(name="python"), _tech_dict(name="bash")],
        )
        self.assert_rejected(
            lambda: decode_profile_payload(unsorted_languages, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        duplicate_languages = _minimal_payload(
            repository_kinds=["library"],
            languages=[_tech_dict(name="python"), _tech_dict(name="python")],
        )
        self.assert_rejected(
            lambda: decode_profile_payload(
                duplicate_languages, schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )

    def test_rejects_empty_source_provenance(self):
        empty_wire = _tech_dict()
        empty_wire["source_artifact_ids"] = []
        self.assert_rejected(
            lambda: TechnologyDeclaration.from_dict(empty_wire, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.source_artifact_ids",
        )
        self.assert_rejected(
            lambda: _tech(artifacts=()),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.source_artifact_ids",
        )


class CodeRoleAssignmentTests(ProfileContractTestCase):
    def test_round_trip_has_exact_wire_shape(self):
        assignment = _role(role=CodeRole.TEST, path="tests")
        wire = {
            "role": "test",
            "path": "tests",
            "reason_codes": ["PATH_PATTERN_SRC"],
            "source_artifact_ids": ["tool-run-0001"],
        }
        self.assertEqual(assignment.to_dict(), wire)
        decoded = CodeRoleAssignment.from_dict(wire, schema_version=VERSION_4_0)
        self.assertEqual(decoded, assignment)
        self.assertEqual(decoded.to_dict(), wire)

    def test_rejects_missing_and_unknown_fields(self):
        base = {
            "role": "test",
            "path": "tests",
            "reason_codes": ["TEST_CONFIG_DISCOVERY"],
            "source_artifact_ids": ["tool-run-0001"],
        }
        for missing, path in (
            ("role", "$.role"),
            ("path", "$.path"),
            ("reason_codes", "$.reason_codes"),
            ("source_artifact_ids", "$.source_artifact_ids"),
        ):
            data = dict(base)
            del data[missing]
            self.assert_rejected(
                lambda d=data: CodeRoleAssignment.from_dict(d, schema_version=VERSION_4_0),
                ContractErrorCode.REQUIRED_FIELD_MISSING,
                path,
            )
        unknown_role = dict(base)
        unknown_role["role"] = "staging"
        self.assert_rejected(
            lambda: CodeRoleAssignment.from_dict(unknown_role, schema_version=VERSION_4_0),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            "$.role",
        )
        unknown_field = dict(base)
        unknown_field["confidence"] = 1
        self.assert_rejected(
            lambda: CodeRoleAssignment.from_dict(
                unknown_field, schema_version=VERSION_4_0
            ),
            ContractErrorCode.UNKNOWN_FIELD,
        )

    def test_rejects_unsorted_duplicate_and_oversize_pairs(self):
        unsorted_roles = _minimal_payload(
            repository_kinds=["library"],
            languages=[_tech_dict()],
            code_roles=[_role_dict(path="src/b.py"), _role_dict(path="src/a.py")],
        )
        self.assert_rejected(
            lambda: decode_profile_payload(unsorted_roles, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        duplicate_roles = _minimal_payload(
            repository_kinds=["library"],
            languages=[_tech_dict()],
            code_roles=[_role_dict(path="src/a.py"), _role_dict(path="src/a.py")],
        )
        self.assert_rejected(
            lambda: decode_profile_payload(duplicate_roles, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        oversize = _minimal_payload(
            repository_kinds=["library"],
            languages=[_tech_dict()],
            code_roles=[_role_dict(path=f"src/f{index:04d}.py") for index in range(2049)],
        )
        self.assert_rejected(
            lambda: decode_profile_payload(oversize, schema_version=VERSION_4_0),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
        )

    def test_allows_directory_prefix_paths(self):
        for path in ("tests", "src/lib", "a/b/c"):
            assignment = _role(role=CodeRole.TEST, path=path)
            self.assertEqual(assignment.path, path)
            decoded = CodeRoleAssignment.from_dict(
                assignment.to_dict(), schema_version=VERSION_4_0
            )
            self.assertEqual(decoded.path, path)


class AttackSurfaceEntryTests(ProfileContractTestCase):
    def test_round_trip_with_null_and_present_symbol(self):
        with_symbol = _entry(path="src/cli.py", symbol="main")
        self.assertEqual(
            with_symbol.to_dict(),
            {
                "path": "src/cli.py",
                "reason_codes": ["CLI_ENTRY_SCRIPT"],
                "source_artifact_ids": ["tool-run-0001"],
                "symbol": "main",
            },
        )
        without_symbol = _entry(path="Dockerfile", symbol=None)
        wire = without_symbol.to_dict()
        self.assertIsNone(wire["symbol"])
        decoded = AttackSurfaceEntry.from_dict(wire, schema_version=VERSION_4_0)
        self.assertEqual(decoded, without_symbol)
        self.assertIsNone(decoded.symbol)

    def test_rejects_invalid_paths_symbols_and_reason_codes(self):
        for bad_path in ("src/", "/abs", "../up", "a//b", "C:\\x", ""):
            self.assert_rejected(
                lambda p=bad_path: _entry(path=p),
                ContractErrorCode.INVALID_FIELD_VALUE,
                "$.path",
            )
        self.assert_rejected(
            lambda: _entry(symbol=""),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.symbol",
        )
        self.assert_rejected(
            lambda: _entry(symbol=" leading"),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.symbol",
        )
        self.assert_rejected(
            lambda: _entry(reasons=()),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.reason_codes",
        )
        self.assert_rejected(
            lambda: _entry(reasons=("lower_case",)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.reason_codes[0]",
        )

    def test_rejects_unsorted_duplicate_pairs(self):
        unsorted_entries = _minimal_payload(
            repository_kinds=["library"],
            languages=[_tech_dict()],
            entrypoints=[
                _entry_dict(path="src/z.py", symbol="run"),
                _entry_dict(path="src/a.py", symbol="main"),
            ],
        )
        self.assert_rejected(
            lambda: decode_profile_payload(unsorted_entries, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        duplicate_entries = _minimal_payload(
            repository_kinds=["library"],
            languages=[_tech_dict()],
            entrypoints=[
                _entry_dict(path="src/z.py", symbol="run"),
                _entry_dict(path="src/z.py", symbol="run"),
            ],
        )
        self.assert_rejected(
            lambda: decode_profile_payload(
                duplicate_entries, schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )


class ExecutionCapabilityTests(ProfileContractTestCase):
    def test_round_trip_has_exact_six_bool_wire_shape(self):
        capability = _capability(buildable=True, requires_gpu=True)
        wire = {
            "buildable": True,
            "testable": True,
            "requires_network": False,
            "requires_services": False,
            "requires_gpu": True,
            "requires_external_credentials": False,
        }
        self.assertEqual(capability.to_dict(), wire)
        decoded = ExecutionCapability.from_dict(wire, schema_version=VERSION_4_0)
        self.assertEqual(decoded, capability)
        self.assertEqual(decoded.to_dict(), wire)

    def test_rejects_missing_bool_and_non_bool_values(self):
        missing_gpu = _capability_dict()
        del missing_gpu["requires_gpu"]
        self.assert_rejected(
            lambda: ExecutionCapability.from_dict(missing_gpu, schema_version=VERSION_4_0),
            ContractErrorCode.REQUIRED_FIELD_MISSING,
            "$.requires_gpu",
        )
        int_bool = _capability_dict(buildable=1)
        self.assert_rejected(
            lambda: ExecutionCapability.from_dict(int_bool, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.buildable",
        )
        none_bool = _capability_dict(testable=None)
        self.assert_rejected(
            lambda: ExecutionCapability.from_dict(none_bool, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.testable",
        )


class ProfileCoverageGapTests(ProfileContractTestCase):
    def test_round_trip_has_exact_wire_shape(self):
        gap = _gap()
        wire = {
            "gap_code": "FRAMEWORK_DETECTION_PARTIAL",
            "detail": "Dynamic imports unresolved.",
        }
        self.assertEqual(gap.to_dict(), wire)
        decoded = ProfileCoverageGap.from_dict(wire, schema_version=VERSION_4_0)
        self.assertEqual(decoded, gap)
        self.assertEqual(decoded.to_dict(), wire)

    def test_rejects_invalid_code_detail_and_duplicates(self):
        self.assert_rejected(
            lambda: _gap(gap_code="framework"),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.gap_code",
        )
        self.assert_rejected(
            lambda: _gap(detail=""),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.detail",
        )
        self.assert_rejected(
            lambda: _gap(detail="line\nbreak"),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.detail",
        )
        self.assert_rejected(
            lambda: _gap(detail="x" * 4097),
            ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED,
            "$.detail",
        )
        duplicate_gaps = _minimal_payload(
            coverage_gaps=[
                {"gap_code": "A", "detail": "d"},
                {"gap_code": "A", "detail": "d"},
            ]
        )
        self.assert_rejected(
            lambda: decode_profile_payload(duplicate_gaps, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )


class RepositoryProfileTests(ProfileContractTestCase):
    def test_minimal_profile_round_trip_is_valid(self):
        payload = _minimal_payload()
        profile = decode_profile_payload(payload, schema_version=VERSION_4_0)
        self.assertEqual(profile.to_dict(), payload)
        self.assertEqual(encode_profile_payload(profile), payload)
        rebuilt = RepositoryProfile(
            schema_version=VERSION_4_0,
            repository_kinds=(RepositoryKind.DOCS_CONTENT,),
            execution_capability=_capability(buildable=False, testable=False),
            support_level=SupportLevel.PARTIAL,
            component_path=None,
            file_count=0,
            total_bytes=0,
            max_file_bytes=0,
            code_density_bp=0,
            binary_ratio_bp=0,
            generated_ratio_bp=0,
        )
        self.assertEqual(rebuilt.to_dict(), payload)

    def test_golden_profile_round_trip_and_digest(self):
        raw = FIXTURE.read_bytes()
        self.assertEqual(len(raw), 2152)
        payload = canonical_decode(raw)
        profile = decode_profile_payload(payload, schema_version=VERSION_4_0)
        self.assertEqual(profile.to_dict(), payload)
        self.assertEqual(compute_content_digest(payload), GOLDEN_PAYLOAD_DIGEST)
        self.assertEqual(canonical_encode(encode_profile_payload(profile)), raw)

    def test_rejects_empty_unknown_mixed_and_unsorted_repository_kinds(self):
        self.assert_rejected(
            lambda: decode_profile_payload(
                _minimal_payload(repository_kinds=[]), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.repository_kinds",
        )
        mixed = self.assert_rejected(
            lambda: decode_profile_payload(
                _minimal_payload(repository_kinds=["unknown", "library"]),
                schema_version=VERSION_4_0,
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(mixed.field_path.startswith("$.repository_kinds"), mixed.field_path)
        self.assert_rejected(
            lambda: decode_profile_payload(
                _minimal_payload(repository_kinds=["library", "application"]),
                schema_version=VERSION_4_0,
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assert_rejected(
            lambda: decode_profile_payload(
                _minimal_payload(repository_kinds=["library", "library"]),
                schema_version=VERSION_4_0,
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assert_rejected(
            lambda: decode_profile_payload(
                _minimal_payload(repository_kinds=["application", "staging"]),
                schema_version=VERSION_4_0,
            ),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            "$.repository_kinds[1]",
        )

    def test_rejects_code_kind_without_languages(self):
        for kind in ("application", "library", "cli", "monorepo"):
            payload = _minimal_payload(repository_kinds=[kind])
            self.assert_rejected(
                lambda p=payload: decode_profile_payload(p, schema_version=VERSION_4_0),
                ContractErrorCode.INVALID_FIELD_VALUE,
                "$.languages",
            )
        for kind in ("docs_content", "dataset_asset", "unknown"):
            profile = decode_profile_payload(
                _minimal_payload(repository_kinds=[kind]), schema_version=VERSION_4_0
            )
            self.assertEqual(profile.languages, ())

    def test_rejects_invalid_metrics_ranges_and_impossible_totals(self):
        self.assert_rejected(
            lambda: decode_profile_payload(
                _minimal_payload(code_density_bp=10001), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.code_density_bp",
        )
        self.assert_rejected(
            lambda: decode_profile_payload(
                _minimal_payload(binary_ratio_bp=-1), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.binary_ratio_bp",
        )
        self.assert_rejected(
            lambda: decode_profile_payload(
                _minimal_payload(file_count=True), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.file_count",
        )
        self.assert_rejected(
            lambda: decode_profile_payload(
                _minimal_payload(total_bytes=2**63), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.total_bytes",
        )
        self.assert_rejected(
            lambda: decode_profile_payload(
                _minimal_payload(total_bytes=5, max_file_bytes=9),
                schema_version=VERSION_4_0,
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.max_file_bytes",
        )

    def test_rejects_file_count_zero_with_nonzero_bytes(self):
        self.assert_rejected(
            lambda: decode_profile_payload(
                _minimal_payload(total_bytes=5), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.total_bytes",
        )
        self.assert_rejected(
            lambda: decode_profile_payload(
                _minimal_payload(max_file_bytes=5), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.max_file_bytes",
        )

    def test_rejects_wrong_container_and_missing_required_fields(self):
        self.assert_rejected(
            lambda: decode_profile_payload(
                ["not", "an", "object"], schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$",
        )
        for missing, path in (
            ("repository_kinds", "$.repository_kinds"),
            ("execution_capability", "$.execution_capability"),
            ("support_level", "$.support_level"),
            ("component_path", "$.component_path"),
            ("file_count", "$.file_count"),
            ("code_density_bp", "$.code_density_bp"),
        ):
            data = _minimal_payload()
            del data[missing]
            self.assert_rejected(
                lambda d=data: decode_profile_payload(d, schema_version=VERSION_4_0),
                ContractErrorCode.REQUIRED_FIELD_MISSING,
                path,
            )

    def test_component_path_scoping_round_trip(self):
        for value in (None, "services/api", "pkg"):
            payload = _minimal_payload(component_path=value)
            profile = decode_profile_payload(payload, schema_version=VERSION_4_0)
            self.assertEqual(profile.component_path, value)
            self.assertEqual(profile.to_dict()["component_path"], value)

    def test_rejects_absolute_and_parent_component_paths(self):
        for bad in ("/srv/app", "a/../b", "src/", "", "src\\api"):
            payload = _minimal_payload(component_path=bad)
            self.assert_rejected(
                lambda p=payload: decode_profile_payload(p, schema_version=VERSION_4_0),
                ContractErrorCode.INVALID_FIELD_VALUE,
                "$.component_path",
            )

    def test_empty_surface_arrays_are_valid_and_distinct_from_safety_verdicts(self):
        profile = decode_profile_payload(_minimal_payload(), schema_version=VERSION_4_0)
        for array in (
            "languages",
            "frameworks",
            "package_managers",
            "build_systems",
            "code_roles",
            "entrypoints",
            "external_inputs",
            "trust_boundaries",
            "sensitive_operations",
            "deployment_surface",
            "coverage_gaps",
        ):
            self.assertEqual(getattr(profile, array), ())
        supported = decode_profile_payload(
            _minimal_payload(repository_kinds=["docs_content"], support_level="supported"),
            schema_version=VERSION_4_0,
        )
        self.assertIs(supported.support_level, SupportLevel.SUPPORTED)
        self.assertEqual(supported.entrypoints, ())

    def test_rejects_oversize_arrays_with_max_array_length_exceeded(self):
        entries = [_entry_dict(path=f"src/e{index:04d}.py") for index in range(257)]
        oversize = _minimal_payload(
            repository_kinds=["library"],
            languages=[_tech_dict()],
            entrypoints=entries,
        )
        self.assert_rejected(
            lambda: decode_profile_payload(oversize, schema_version=VERSION_4_0),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
        )
        boundary = _minimal_payload(
            repository_kinds=["library"],
            languages=[_tech_dict()],
            entrypoints=entries[:256],
        )
        profile = decode_profile_payload(boundary, schema_version=VERSION_4_0)
        self.assertEqual(len(profile.entrypoints), 256)

    def test_future_minor_round_trips_unknown_fields_at_every_level(self):
        payload = _minimal_payload()
        payload["future_top"] = 1
        payload["execution_capability"]["future_cap"] = True
        payload["languages"] = [dict(_tech_dict(), future_lang="x")]
        payload["code_roles"] = [dict(_role_dict(), future_role=2)]
        payload["entrypoints"] = [dict(_entry_dict(), future_entry=None)]
        payload["coverage_gaps"] = [
            {"gap_code": "A", "detail": "d", "future_gap": 3}
        ]
        profile = decode_profile_payload(payload, schema_version=VERSION_4_2)
        wire = profile.to_dict()
        self.assertEqual(wire["future_top"], 1)
        self.assertEqual(wire["execution_capability"]["future_cap"], True)
        self.assertEqual(wire["languages"][0]["future_lang"], "x")
        self.assertEqual(wire["code_roles"][0]["future_role"], 2)
        self.assertEqual(wire["entrypoints"][0]["future_entry"], None)
        self.assertEqual(wire["coverage_gaps"][0]["future_gap"], 3)
        again = decode_profile_payload(wire, schema_version=VERSION_4_2)
        self.assertEqual(again.to_dict(), wire)

    def test_current_minor_rejects_unknown_fields_at_every_level(self):
        def inject_top(data):
            data["future_top"] = 1

        def inject_capability(data):
            data["execution_capability"]["future_cap"] = True

        def inject_language(data):
            data["languages"] = [dict(_tech_dict(), future_lang="x")]

        def inject_code_role(data):
            data["code_roles"] = [dict(_role_dict(), future_role=2)]

        def inject_entry(data):
            data["entrypoints"] = [dict(_entry_dict(), future_entry=None)]

        def inject_gap(data):
            data["coverage_gaps"] = [{"gap_code": "A", "detail": "d", "future_gap": 3}]

        for inject in (
            inject_top,
            inject_capability,
            inject_language,
            inject_code_role,
            inject_entry,
            inject_gap,
        ):
            payload = _minimal_payload()
            inject(payload)
            self.assert_rejected(
                lambda p=payload: decode_profile_payload(p, schema_version=VERSION_4_0),
                ContractErrorCode.UNKNOWN_FIELD,
            )

    def test_defensive_copy_prevents_post_construction_mutation(self):
        languages = [_tech()]
        entrypoints = [_entry()]
        extensions = {"future_key": "v"}
        profile = RepositoryProfile(
            schema_version=VERSION_4_2,
            repository_kinds=[RepositoryKind.LIBRARY],
            execution_capability=_capability(),
            support_level=SupportLevel.SUPPORTED,
            component_path=None,
            file_count=1,
            total_bytes=10,
            max_file_bytes=10,
            code_density_bp=0,
            binary_ratio_bp=0,
            generated_ratio_bp=0,
            languages=languages,
            entrypoints=entrypoints,
            extensions=extensions,
        )
        languages.append(_tech(name="zzz"))
        entrypoints.append(_entry(path="src/zzz.py"))
        extensions["future_key2"] = "v2"
        self.assertEqual(len(profile.languages), 1)
        self.assertEqual(len(profile.entrypoints), 1)
        self.assertEqual(profile.extensions, {"future_key": "v"})
        wire = profile.to_dict()
        wire["injected"] = True
        self.assertNotIn("injected", profile.to_dict())

    def test_payload_has_no_confidence_severity_or_safety_verdict_fields(self):
        def scan(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    self.assertNotIn(key, FORBIDDEN_VERDICT_KEYS)
                    scan(value)
            elif isinstance(node, list):
                for item in node:
                    scan(item)

        scan(canonical_decode(FIXTURE.read_bytes()))
        scan(_minimal_payload())
        self.assertEqual(
            FORBIDDEN_VERDICT_KEYS,
            frozenset({"confidence", "severity", "trust_score", "is_secure", "is_safe"}),
        )

    def test_rejects_unknown_support_level_and_capability_container(self):
        self.assert_rejected(
            lambda: decode_profile_payload(
                _minimal_payload(support_level="full"), schema_version=VERSION_4_0
            ),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            "$.support_level",
        )
        self.assert_rejected(
            lambda: decode_profile_payload(
                _minimal_payload(execution_capability=["nope"]),
                schema_version=VERSION_4_0,
            ),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.execution_capability",
        )


if __name__ == "__main__":
    unittest.main()
