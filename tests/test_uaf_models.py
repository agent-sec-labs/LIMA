"""Contracts for UAF v2 identity, fact, proof and completeness types."""

import dataclasses
import unittest

from lima.contracts.evidence import EvidenceLevel, EvidencePolarity
from lima.uaf_models import (
    PROOF_OBLIGATIONS,
    UAF_SCHEMA_VERSION,
    BuildContextResolution,
    CandidateIdentity,
    ExtractionCoverage,
    FactBundleExpectation,
    FactBundleMeta,
    ObligationVerdict,
    P5Detail,
    ProofObligation,
    ProofReadiness,
    ProofResult,
    UafCandidate,
    UafFact,
    UafFactKind,
    derive_candidate_id,
    derive_object_id,
    proof_readiness,
)

_A = "a" * 64
_B = "b" * 64
_C = "c" * 64
_D = "d" * 64
_E = "e" * 64


def _candidate(**overrides):
    base = {
        "candidate_id": _A,
        "object_id": _B,
        "allocation_fact_id": _C,
        "release_fact_id": _D,
        "use_fact_id": _E,
        "canonical_path": "src/session.cpp",
        "function_usr": "c:@F@Session#close#",
        "release_range": (10, 12),
        "use_range": (20, 24),
    }
    base.update(overrides)
    return UafCandidate(**base)


def _fact(**overrides):
    base = {
        "fact_id": "1" * 64,
        "kind": UafFactKind.ALLOCATION,
        "snapshot_hash": "2" * 64,
        "build_context_hash": "3" * 64,
        "translation_unit": "src/session.cpp",
        "canonical_path": "src/session.cpp",
        "function_usr": "c:@F@Session#close#",
        "source_range": (40, 40),
        "cfg_block": 0,
    }
    base.update(overrides)
    return UafFact(**base)


def _satisfied_verdicts():
    return tuple(
        ObligationVerdict(
            obligation=obligation,
            verdict="satisfied",
            fact_ids=(_A,),
            reason="supported by facts",
            witness_cfg_blocks=(0, 1),
        )
        for obligation in PROOF_OBLIGATIONS
    )


class IdentityDerivationTests(unittest.TestCase):
    def test_object_id_stable_when_unrelated_allocation_inserted(self):
        # object_id 由 allocation 的 AST source range 派生，不含任何
        # ordinal/顺序信息：同一对象在事实集里前后插入无关 allocation，
        # 身份材料逐字节不变，id 恒定。
        material = {
            "schema_version": UAF_SCHEMA_VERSION,
            "canonical_path": "src/session.cpp",
            "function_usr": "c:@F@Session#close#",
            "alloc_begin_line": 40,
            "alloc_end_line": 40,
            "alloc_kind": "new",
        }
        before = derive_object_id(**material)
        after = derive_object_id(**material)
        self.assertEqual(before, after)

        shifted = derive_object_id(**{**material, "alloc_begin_line": 41, "alloc_end_line": 41})
        self.assertNotEqual(before, shifted)
        other_kind = derive_object_id(**{**material, "alloc_kind": "malloc"})
        self.assertNotEqual(before, other_kind)
        other_usr = derive_object_id(**{**material, "function_usr": "c:@F@Session#read#"})
        self.assertNotEqual(before, other_usr)

    def test_distinct_release_use_pairs_yield_distinct_candidate_ids(self):
        object_id = _A
        first = derive_candidate_id(UAF_SCHEMA_VERSION, object_id, _B, _C)
        second = derive_candidate_id(UAF_SCHEMA_VERSION, object_id, _D, _E)
        self.assertNotEqual(first, second)
        self.assertEqual(first, derive_candidate_id(UAF_SCHEMA_VERSION, object_id, _B, _C))
        # 同一 release/use 对在不同对象上也不合并。
        self.assertNotEqual(
            first, derive_candidate_id(UAF_SCHEMA_VERSION, "f" * 64, _B, _C)
        )
        # 候选 id 是 64 位小写 hex（CWE-416 已混入派生材料）。
        self.assertRegex(first, r"^[0-9a-f]{64}$")
        # 非法哈希输入被拒绝。
        with self.assertRaises(ValueError):
            derive_candidate_id(UAF_SCHEMA_VERSION, object_id, "short", _C)


class CandidateIdentityTests(unittest.TestCase):
    def test_same_candidate_id_across_snapshots_are_distinct_identities(self):
        first = CandidateIdentity(snapshot_hash=_A, candidate_id=_C)
        second = CandidateIdentity(snapshot_hash=_B, candidate_id=_C)
        # 同一 candidate_id 跨 snapshot 是两个不等身份：candidate_id 跨
        # snapshot 可复现，但不是全局运行身份。
        self.assertNotEqual(first, second)
        self.assertNotEqual(first.as_key(), second.as_key())
        self.assertEqual((_A, _C), first.as_key())
        self.assertEqual((_B, _C), second.as_key())
        # 相同取值相等且同哈希，复合键可直接用作 dict/set 键。
        self.assertEqual(first, CandidateIdentity(snapshot_hash=_A, candidate_id=_C))
        self.assertEqual(
            hash(first), hash(CandidateIdentity(snapshot_hash=_A, candidate_id=_C))
        )
        registry = {first.as_key(): "one", second.as_key(): "two"}
        self.assertEqual({"one", "two"}, set(registry.values()))

    def test_short_hash_and_non_hex_rejected(self):
        cases = (
            ("short snapshot hash", {"snapshot_hash": _A[:63], "candidate_id": _C}),
            ("long snapshot hash", {"snapshot_hash": _A + "a", "candidate_id": _C}),
            ("uppercase snapshot hash", {"snapshot_hash": _A.upper(), "candidate_id": _C}),
            ("non-hex snapshot hash", {"snapshot_hash": "z" * 64, "candidate_id": _C}),
            ("short candidate id", {"snapshot_hash": _A, "candidate_id": _C[:63]}),
            ("uppercase candidate id", {"snapshot_hash": _A, "candidate_id": _C.upper()}),
            ("non-hex candidate id", {"snapshot_hash": _A, "candidate_id": "g" * 64}),
            ("non-string candidate id", {"snapshot_hash": _A, "candidate_id": 123}),
        )
        for name, kwargs in cases:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    CandidateIdentity(**kwargs)


class UafCandidateContractTests(unittest.TestCase):
    def test_missing_usr_records_coverage_gap_and_forbids_pass_hint(self):
        # 子断言一：candidate 身份仍可携带（空 USR 可构造），但
        # derive_object_id 拒绝空 USR——缺失 USR 记 coverage gap，不造替代身份。
        candidate = _candidate(function_usr="")
        self.assertEqual("", candidate.function_usr)
        with self.assertRaises(ValueError):
            derive_object_id(
                UAF_SCHEMA_VERSION,
                candidate.canonical_path,
                "",
                40,
                40,
                "new",
            )
        # 子断言二：coverage-gap 事实存在时 readiness 不 complete——
        # 关键 gap 封死 fact-verified 方向（禁止 PASS 提示）。
        gap = _fact(kind=UafFactKind.COVERAGE_GAP, fact_id="9" * 64)
        self.assertIs(UafFactKind.COVERAGE_GAP, gap.kind)
        resolved = BuildContextResolution(
            status="resolved",
            source_kind="repository-compdb",
            context_hash="3" * 64,
        )
        complete = ExtractionCoverage(ast_complete=True, cfg_complete=True)
        self.assertTrue(proof_readiness(resolved, complete, critical=False).complete)
        self.assertFalse(proof_readiness(resolved, complete, critical=True).complete)

    def test_candidate_rejects_invalid_hashes_paths_ranges_and_duplicate_fact_ids(self):
        cases = (
            ("bad candidate id", {"candidate_id": "Z" * 64}),
            ("short object id", {"object_id": _B[:63]}),
            ("non-hex release fact", {"release_fact_id": "g" * 64}),
            ("absolute path", {"canonical_path": "/src/session.cpp"}),
            ("parent path", {"canonical_path": "../src/session.cpp"}),
            ("backslash path", {"canonical_path": "src\\session.cpp"}),
            ("reversed release range", {"release_range": (12, 10)}),
            ("zero use start", {"use_range": (0, 4)}),
            ("bool range value", {"use_range": (True, 4)}),
            ("non-int range value", {"use_range": ("20", 24)}),
            ("range not a tuple", {"release_range": [10, 12]}),
            ("duplicate release and allocation", {"release_fact_id": _C}),
            ("duplicate use and allocation", {"use_fact_id": _C}),
        )
        for name, mutation in cases:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    _candidate(**mutation)

    def test_candidate_fields_round_trip(self):
        candidate = _candidate()
        self.assertEqual((10, 12), candidate.release_range)
        self.assertEqual((20, 24), candidate.use_range)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            candidate.canonical_path = "src/other.cpp"


class FactModelTests(unittest.TestCase):
    def test_unknown_fields_duplicate_ids_dangling_refs_rejected(self):
        # dataclass 构造器没有"未知字段"概念：未知字段、重复 fact_id 与
        # 悬空 related_fact_ids 引用由 Task 5 的 bundle 级校验器
        # （load_fact_bundle, expectation 驱动）负责；构造器层校验每个
        # 字段自身的值域，以下逐项拒绝。
        with self.assertRaises(ValueError):
            _fact(kind="mystery-kind")
        cases = (
            ("non-hex fact id", {"fact_id": "z" * 64}),
            ("short snapshot hash", {"snapshot_hash": "2" * 63}),
            ("uppercase build context hash", {"build_context_hash": (_A).upper()}),
            ("absolute translation unit", {"translation_unit": "/repo/session.cpp"}),
            ("escaping canonical path", {"canonical_path": "../session.cpp"}),
            ("backslash path", {"translation_unit": "src\\session.cpp"}),
            ("reversed source range", {"source_range": (44, 40)}),
            ("zero source line", {"source_range": (0, 5)}),
            ("negative cfg block", {"cfg_block": -1}),
            ("bool cfg block", {"cfg_block": True}),
            ("non-int cfg block", {"cfg_block": "0"}),
            ("non-hex related fact", {"related_fact_ids": ("f" * 63,)}),
            ("related not a tuple", {"related_fact_ids": ["f" * 64]}),
            ("non-hex object id", {"object_id": "nope"}),
        )
        for name, mutation in cases:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    _fact(**mutation)

    def test_fact_defaults_carry_optional_identity_fields(self):
        fact = _fact()
        self.assertEqual("", fact.object_id)
        self.assertEqual("", fact.pointer_id)
        self.assertEqual((), fact.related_fact_ids)
        linked = _fact(
            object_id=_B,
            pointer_id="p-local-x",
            related_fact_ids=(_C, _D),
        )
        self.assertEqual((_C, _D), linked.related_fact_ids)
        self.assertEqual("p-local-x", linked.pointer_id)


class FactBundleExpectationTests(unittest.TestCase):
    def test_expectation_validates_hashes_root_and_tool_runs(self):
        expectation = FactBundleExpectation(
            snapshot_hash=_A,
            build_context_hash=_B,
            repository_root="",
            allowed_tool_runs=frozenset({"clang-14-uaf"}),
        )
        self.assertEqual(frozenset({"clang-14-uaf"}), expectation.allowed_tool_runs)
        rooted = FactBundleExpectation(
            snapshot_hash=_A,
            build_context_hash=_B,
            repository_root="snapshots/repo",
            allowed_tool_runs=frozenset(),
        )
        self.assertEqual("snapshots/repo", rooted.repository_root)
        base = {
            "snapshot_hash": _A,
            "build_context_hash": _B,
            "repository_root": "repo",
            "allowed_tool_runs": frozenset({"run"}),
        }
        cases = (
            ("bad snapshot hash", {"snapshot_hash": _A[:62]}),
            ("uppercase build context hash", {"build_context_hash": _B.upper()}),
            ("absolute repository root", {"repository_root": "/repo"}),
            ("parent repository root", {"repository_root": "../repo"}),
            ("backslash repository root", {"repository_root": "repo\\sub"}),
            ("dot repository root", {"repository_root": "."}),
            ("non-string tool run", {"allowed_tool_runs": frozenset({7})}),
            ("empty tool run name", {"allowed_tool_runs": frozenset({""})}),
            ("tool runs not a set", {"allowed_tool_runs": ["run"]}),
        )
        for name, mutation in cases:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    FactBundleExpectation(**{**base, **mutation})

    def test_bundle_meta_validates_producer_and_optional_hash(self):
        meta = FactBundleMeta(
            snapshot_hash=_A,
            build_context_hash=_B,
            producer_name="cxx-analyzer",
            producer_version="1.0",
            tool_run_id="run-1",
        )
        self.assertEqual("", meta.bundle_sha256)
        sealed = FactBundleMeta(
            snapshot_hash=_A,
            build_context_hash=_B,
            producer_name="cxx-analyzer",
            producer_version="1.0",
            tool_run_id="run-1",
            bundle_sha256=_C,
        )
        self.assertEqual(_C, sealed.bundle_sha256)
        meta_base = {
            "snapshot_hash": _A,
            "build_context_hash": _B,
            "producer_name": "cxx-analyzer",
            "producer_version": "1.0",
            "tool_run_id": "run-1",
        }
        for name, mutation in (
            ("short snapshot hash", {"snapshot_hash": _A[:63]}),
            ("empty producer name", {"producer_name": ""}),
            ("empty tool run id", {"tool_run_id": ""}),
            ("bad bundle hash", {"bundle_sha256": "z" * 64}),
        ):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    FactBundleMeta(**{**meta_base, **mutation})


class ReadinessTests(unittest.TestCase):
    def _resolution(self, **overrides):
        base = {
            "status": "resolved",
            "source_kind": "repository-compdb",
            "context_hash": "3" * 64,
        }
        base.update(overrides)
        return BuildContextResolution(**base)

    def _coverage(self, **overrides):
        base = {"ast_complete": True, "cfg_complete": True}
        base.update(overrides)
        return ExtractionCoverage(**base)

    def test_heuristic_or_unresolved_context_never_ready(self):
        heuristic = self._resolution(status="incomplete", source_kind="heuristic")
        self.assertFalse(
            proof_readiness(heuristic, self._coverage(), critical=False).complete
        )
        self.assertFalse(
            proof_readiness(
                self._resolution(status="incomplete"), self._coverage(), critical=False
            ).complete
        )
        self.assertFalse(
            proof_readiness(
                self._resolution(status="unavailable"), self._coverage(), critical=False
            ).complete
        )
        # 正向对照：resolved + 双 complete + 无关键 gap 才 complete。
        self.assertTrue(
            proof_readiness(self._resolution(), self._coverage(), critical=False).complete
        )
        # 直接构造 ProofReadiness 时，非 resolved 状态永不 complete。
        self.assertFalse(
            ProofReadiness(
                resolution_status="incomplete",
                ast_complete=True,
                cfg_complete=True,
                critical_gaps=False,
            ).complete
        )
        self.assertFalse(
            ProofReadiness(
                resolution_status="unavailable",
                ast_complete=True,
                cfg_complete=True,
                critical_gaps=False,
            ).complete
        )

    def test_cfg_incomplete_never_ready(self):
        resolved = self._resolution()
        self.assertFalse(
            proof_readiness(resolved, self._coverage(cfg_complete=False), critical=False).complete
        )
        self.assertFalse(
            proof_readiness(resolved, self._coverage(ast_complete=False), critical=False).complete
        )
        self.assertFalse(
            proof_readiness(resolved, self._coverage(), critical=True).complete
        )

    def test_strict_types_in_resolution_coverage_and_readiness(self):
        # 词表/类型拒绝发生在严格构造器里；用 lambda 延迟到 assertRaises 内调用。
        cases = (
            (
                "unknown status",
                lambda: proof_readiness(
                    self._resolution(status="complete"), self._coverage(), critical=False
                ),
            ),
            (
                "unknown source kind",
                lambda: proof_readiness(
                    self._resolution(source_kind="guess"), self._coverage(), critical=False
                ),
            ),
            (
                "bad context hash",
                lambda: proof_readiness(
                    self._resolution(context_hash="z" * 64), self._coverage(), critical=False
                ),
            ),
            (
                "non-string diagnostic",
                lambda: proof_readiness(
                    self._resolution(diagnostics=(7,)), self._coverage(), critical=False
                ),
            ),
            (
                "non-string gap",
                lambda: proof_readiness(
                    self._resolution(), self._coverage(semantic_gaps=(None,)), critical=False
                ),
            ),
            (
                "non-bool flag",
                lambda: proof_readiness(
                    self._resolution(), self._coverage(ast_complete="yes"), critical=False
                ),
            ),
            (
                "non-bool critical",
                lambda: proof_readiness(self._resolution(), self._coverage(), critical="no"),
            ),
        )
        for name, call in cases:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    call()
        with self.subTest(name="bad readiness status"):
            with self.assertRaises(ValueError):
                ProofReadiness(
                    resolution_status="complete",
                    ast_complete=True,
                    cfg_complete=True,
                    critical_gaps=False,
                )


class ProofResultTests(unittest.TestCase):
    def test_evidence_hint_mapping(self):
        passing = ProofResult(verdict="PASS", obligations=_satisfied_verdicts())
        self.assertEqual(
            (EvidenceLevel.D2, EvidencePolarity.SUPPORTS), passing.evidence_hint()
        )
        refuted = ProofResult(
            verdict="REFUTED",
            obligations=tuple(
                dataclasses.replace(verdict, verdict="refuted")
                if verdict.obligation is ProofObligation.P6
                else verdict
                for verdict in _satisfied_verdicts()
            ),
            p5_detail=P5Detail(
                structural_reachability="satisfied",
                path_feasibility="satisfied",
                witness_cfg_blocks=(1, 2, 3),
                guard_facts=(_B,),
                unresolved_constraints=(),
            ),
        )
        self.assertEqual(
            (EvidenceLevel.D2, EvidencePolarity.REFUTES), refuted.evidence_hint()
        )
        unknown = ProofResult(
            verdict="UNKNOWN",
            obligations=tuple(
                dataclasses.replace(verdict, verdict="unknown", fact_ids=(), reason="gap")
                if verdict.obligation is ProofObligation.P5
                else verdict
                for verdict in _satisfied_verdicts()
            ),
        )
        # UNKNOWN 不可证据化：任何证据等级/方向都不成立。
        with self.assertRaises(ValueError):
            unknown.evidence_hint()

    def test_proof_result_requires_exactly_the_seven_obligations(self):
        with self.assertRaises(ValueError):
            ProofResult(verdict="PASS", obligations=_satisfied_verdicts()[:6])
        duplicated = _satisfied_verdicts()[:6] + (_satisfied_verdicts()[0],)
        with self.assertRaises(ValueError):
            ProofResult(verdict="PASS", obligations=duplicated)
        with self.assertRaises(ValueError):
            ObligationVerdict(
                obligation="P8",
                verdict="satisfied",
                fact_ids=(),
                reason="r",
                witness_cfg_blocks=(),
            )
        with self.assertRaises(ValueError):
            ObligationVerdict(
                obligation=ProofObligation.P1,
                verdict="maybe",
                fact_ids=(),
                reason="r",
                witness_cfg_blocks=(),
            )


if __name__ == "__main__":
    unittest.main()
