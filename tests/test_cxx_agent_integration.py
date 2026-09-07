"""Whole-repository scan integration of the C/C++ LLM agent pipeline.

All tests run offline: the LLM is a scripted fake client (zero network), the
C/C++ Sidecar is a fake adapter, and GitHub materialization uses the fake
opener pattern from the existing repository-scan integration tests.
"""

import io
import tempfile
import time
import unittest
import urllib.error
import zipfile
from pathlib import Path

from lima.config import Settings
from lima.cxx_agent_models import CxxAgentCandidate
from lima.cxx_agents import (
    ROLE_ARBITER,
    ROLE_BOUNDS,
    ROLE_CRITIC,
    ROLE_EVIDENCE,
    ROLE_INTERPROCEDURAL,
    ROLE_MEMORY_LIFETIME,
    ROLE_PLANNER,
    ROLE_VERIFIER,
)
from lima.cxx_llm import AgentStep
from lima.cxx_memory import CxxAnalysisResult
from lima.models import EvidenceRecord, Finding, Severity
from lima.repository_materializer import GitHubMaterializer
from lima.repository_scanner import RepositoryScanner
from lima.service import ReviewService
from lima.workspace import RepositoryWorkspace

SHA = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

VULN_C = """#include <stdlib.h>

static char *g_buf = 0;

void leak(void) {
    char *buf = malloc(64);
    free(buf);
    buf[0] = 'a';
}
"""

SAFE_C = """#include <stdlib.h>

int iden(int value) {
    return value;
}
"""

PLAIN_C = """int add(int left, int right) {
    return left + right;
}
"""

EVAL_PY = "def evaluate(code):\n    return eval(code)\n"

UAF_CANDIDATE = CxxAgentCandidate.from_untrusted_json({
    "cwe": "CWE-416",
    "path": "vuln.c",
    "line": 8,
    "symbol": "leak",
    "title": "buf is used after free",
    "mechanism": "free(buf) releases the buffer before buf[0] is written",
    "trigger_path": ["leak", "free", "buf[0]"],
    "confidence": 0.9,
})

UAF_AGENT_FINDING_PAYLOAD = {
    "rule_id": "cxx.llm.cwe-416",
    "source": "cxx-agent",
    "cwe": "CWE-416",
    "path": "vuln.c",
    "line": 8,
    "symbol": "leak",
}


def agent_step_final(candidate):
    return AgentStep(action="final", candidates=(candidate,))


def planner_step():
    return agent_step_final(CxxAgentCandidate.from_untrusted_json({
        "cwe": "CWE-416",
        "path": "vuln.c",
        "line": 5,
        "symbol": "leak",
        "title": "anchor selection",
        "mechanism": "anchor selection only; rebuilt deterministically",
        "trigger_path": ["leak"],
        "confidence": 0.5,
    }))


def snippet_step(path, start_line, end_line):
    return AgentStep(
        action="tool",
        tool="read_code_snippet",
        arguments=(
            ("path", path), ("start_line", start_line), ("end_line", end_line),
        ),
        reason="read the assigned function body",
    )


class ScriptedAgentClient:
    """Offline stand-in for ``CxxLLMClient`` with a per-role step script.

    Every ``step`` call records the role, the tool catalog it was given, the
    managed context and the tool it requested, so tests can assert what the
    model really saw and which tools each role could reach.
    """

    def __init__(self, scripts=None, model="fake-cxx-model"):
        self.scripts = dict(scripts or {})
        self.model = model
        self.calls = []

    def step(self, role, managed_context, tools, budget, read_paths=None):
        catalog = sorted(entry["name"] for entry in tools.catalog())
        self.calls.append({
            "role": role,
            "tools": catalog,
            "context": managed_context,
        })
        script = self.scripts.get(role) or []
        if not script:
            raise AssertionError(f"unexpected LLM call for role {role!r}")
        return script.pop(0)


class ExplodingAgentClient:
    """Client whose provider transport always fails (RuntimeError family)."""

    model = "exploding-cxx-model"

    def step(self, role, managed_context, tools, budget, read_paths=None):
        raise RuntimeError("provider transport down")


class FakeCxxSidecar:
    """Offline stand-in for the C/C++ memory analyzer Sidecar adapter."""

    def __init__(self, finding=None):
        self._finding = finding

    def analyze(
        self, repository_key, snapshot_sha256, requested_layers, inventory=None,
    ):
        findings = [self._finding] if self._finding is not None else []
        return CxxAnalysisResult(
            status="completed",
            tool_runs=[
                {"run_id": "run-1", "tool": "semgrep", "status": "completed"},
            ] if self._finding is not None else [],
            findings=findings,
            coverage={"files": 0},
            diagnostics=[],
        )


def semgrep_uaf_finding():
    return Finding(
        rule_id="mem.uaf", severity=Severity.HIGH,
        title="use after free", explanation="buffer used after free",
        path="vuln.c", line=8, evidence="buf[0] = 'a';", fix="", test="",
        cwe="CWE-416", source="semgrep", symbol="leak",
        evidence_records=[EvidenceRecord(
            source="semgrep", kind="tool", path="vuln.c", line=8,
            snippet="buf[0] = 'a';", rule_id="mem.uaf", cwe="CWE-416",
            symbol="leak", tool_run_id="run-1",
        )],
    )


def vuln_scripts():
    """Honest-model script: read the code, then report only the real UAF."""
    return {
        ROLE_PLANNER: [planner_step()],
        ROLE_MEMORY_LIFETIME: [
            snippet_step("vuln.c", 5, 9),
            agent_step_final(UAF_CANDIDATE),
        ],
        ROLE_CRITIC: [agent_step_final(UAF_CANDIDATE)],
        ROLE_EVIDENCE: [
            AgentStep(
                action="tool",
                tool="get_tool_evidence",
                arguments=(("candidate_id", UAF_CANDIDATE.candidate_id),),
                reason="check Sidecar tool evidence",
            ),
            agent_step_final(UAF_CANDIDATE),
        ],
        ROLE_VERIFIER: [agent_step_final(UAF_CANDIDATE)],
    }


def write_repo(root, files):
    for name, content in files.items():
        path = Path(root, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        # LF 字节：inventory 对原始字节哈希，read_text 走 universal newlines，
        # Windows 默认 write_text 会产生 CRLF 导致 snapshot-drift。
        path.write_bytes(content.encode("utf-8"))


def vuln_scanner(client_factory, sidecar=None, **kwargs):
    return RepositoryScanner(
        sast_mode="off",
        dataflow_enabled=False,
        cxx_memory_mode="auto",
        cxx_memory_adapter=sidecar,
        cxx_agent_mode=kwargs.pop("cxx_agent_mode", "auto"),
        cxx_agent_client_factory=client_factory,
        should_cancel=kwargs.pop("should_cancel", None),
    )


class RepositoryAgentTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(suffix="-cxx-agent"))
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        import shutil

        shutil.rmtree(self.root, ignore_errors=True)

    # ------------------------------------------------------------- scanner

    def test_uaf_repository_full_agent_pipeline(self):
        write_repo(self.root, {"vuln.c": VULN_C, "safe.c": SAFE_C})
        client = ScriptedAgentClient(vuln_scripts())
        scanner = vuln_scanner(
            lambda: client, sidecar=FakeCxxSidecar(semgrep_uaf_finding()),
        )

        workspace = RepositoryWorkspace(self.root)
        result = scanner.scan(workspace, repository_key="team/project")
        report = result.report
        collaboration = report.collaboration["cxx_agent"]

        # 真实代码片段进入模型：specialist 通过工具读到 vuln.c 真实行。
        reads = [call for call in client.calls if call["role"] == "memory-lifetime"]
        self.assertTrue(reads)
        self.assertIn(
            "char *buf = malloc(64);", reads[1]["context"],
        )
        self.assertIn("buf[0] = 'a';", reads[1]["context"])
        planner = [call for call in client.calls if call["role"] == "planner"]
        self.assertIn("vuln.c", planner[0]["context"])

        # 工具证据只在 Evidence 阶段：get_tool_evidence 不进入其他角色的目录。
        for call in client.calls:
            evidence_tool = "get_tool_evidence" in call["tools"]
            self.assertEqual(
                call["role"] == ROLE_EVIDENCE, evidence_tool,
                "get_tool_evidence must only be in the evidence catalog",
            )
        evidence_calls = [
            call for call in client.calls if call["role"] == ROLE_EVIDENCE
        ]
        self.assertIn("get_tool_evidence", evidence_calls[0]["tools"])

        # Agent Finding：绑定候选身份与快照，automatic_repair 恒为 False。
        agent_findings = [
            item for item in report.findings if item.source == "cxx-agent"
        ]
        self.assertEqual(1, len(agent_findings))
        finding = agent_findings[0]
        self.assertEqual("cxx.llm.cwe-416", finding.rule_id)
        self.assertEqual("vuln.c", finding.path)
        self.assertEqual(8, finding.line)
        self.assertEqual("leak", finding.symbol)
        self.assertEqual(UAF_CANDIDATE.candidate_id, finding.candidate_id)
        self.assertIn(ROLE_MEMORY_LIFETIME, finding.agent_role)
        self.assertEqual(["leak", "free", "buf[0]"], finding.trigger_path)
        self.assertIs(False, finding.automatic_repair)
        self.assertEqual("tool-corroborated", finding.verification_state)

        # Sidecar finding 与 agent finding 两来源并存，不互相吞并。
        self.assertIn(
            "semgrep", [item.source for item in report.findings],
        )

        # collaboration.cxx_agent 审计载荷。
        self.assertEqual("auto", collaboration["mode"])
        self.assertEqual("completed", collaboration["status"])
        self.assertEqual("fake-cxx-model", collaboration["model"])
        self.assertEqual(
            result.inventory.fingerprint(), collaboration["snapshot_sha256"],
        )
        self.assertEqual(1, collaboration["retrieval"]["candidates"])
        self.assertEqual(1, collaboration["retrieval"]["context_files"])
        self.assertGreater(collaboration["retrieval"]["context_lines"], 0)
        self.assertEqual(1, collaboration["verification"]["tool-corroborated"])
        self.assertEqual(1, collaboration["verification"]["verified_only"])
        self.assertTrue(collaboration["tool_evidence_bound"])
        roles = {item["role"]: item["status"] for item in collaboration["roles"]}
        self.assertEqual("ok", roles[ROLE_PLANNER])
        self.assertEqual("ok", roles[ROLE_MEMORY_LIFETIME])
        self.assertEqual("ok", roles[ROLE_ARBITER])
        self.assertIn("max_calls", collaboration["budget"])
        self.assertIn("remaining", collaboration["budget"])

        # 安全版本不被强行判漏洞：safe.c 零 finding。
        self.assertEqual(
            [], [item for item in report.findings if item.path == "safe.c"],
        )

    def test_safe_only_repository_produces_zero_llm_calls(self):
        write_repo(self.root, {"safe.c": SAFE_C})
        client = ScriptedAgentClient()
        factory_calls = []
        scanner = vuln_scanner(
            lambda: (factory_calls.append(1), client)[1],
            sidecar=FakeCxxSidecar(),
        )

        result = scanner.scan(
            RepositoryWorkspace(self.root), repository_key="team/project",
        )
        collaboration = result.report.collaboration["cxx_agent"]

        self.assertEqual([], client.calls)
        self.assertEqual(1, len(factory_calls))
        self.assertEqual("completed", collaboration["status"])
        self.assertEqual(0, collaboration["retrieval"]["candidates"])
        self.assertEqual(
            [], [item for item in result.report.findings
                 if item.source == "cxx-agent"],
        )

    def test_repository_without_cxx_sources_skips_agent(self):
        write_repo(self.root, {"app.py": EVAL_PY})
        client = ScriptedAgentClient()
        scanner = vuln_scanner(lambda: client, sidecar=FakeCxxSidecar())

        result = scanner.scan(
            RepositoryWorkspace(self.root), repository_key="team/project",
        )
        collaboration = result.report.collaboration["cxx_agent"]

        self.assertEqual([], client.calls)
        self.assertEqual("no-cxx-sources", collaboration["status"])

    def test_cancelled_task_stops_all_model_calls(self):
        write_repo(self.root, {"vuln.c": VULN_C})
        client = ScriptedAgentClient(vuln_scripts())
        scanner = vuln_scanner(
            lambda: client, sidecar=FakeCxxSidecar(),
            should_cancel=lambda: True,
        )

        result = scanner.scan(
            RepositoryWorkspace(self.root), repository_key="team/project",
        )
        collaboration = result.report.collaboration["cxx_agent"]

        self.assertEqual([], client.calls)
        self.assertEqual("cancelled", collaboration["status"])
        roles = {
            item["role"]: item for item in collaboration["roles"]
        }
        for role in (
            ROLE_PLANNER, ROLE_MEMORY_LIFETIME, ROLE_BOUNDS,
            ROLE_INTERPROCEDURAL, ROLE_CRITIC, ROLE_EVIDENCE, ROLE_VERIFIER,
        ):
            self.assertEqual("failed-replaced", roles[role]["status"])
            self.assertIn("cancelled", roles[role]["error"])
        self.assertEqual("ok", roles[ROLE_ARBITER]["status"])
        self.assertEqual(
            [], [item for item in result.report.findings
                 if item.source == "cxx-agent"],
        )

    def test_auto_mode_llm_failure_degrades_and_keeps_tool_results(self):
        write_repo(self.root, {"vuln.c": VULN_C, "safe.c": SAFE_C})
        sidecar = FakeCxxSidecar(semgrep_uaf_finding())
        scanner = vuln_scanner(lambda: ExplodingAgentClient(), sidecar=sidecar)

        result = scanner.scan(
            RepositoryWorkspace(self.root), repository_key="team/project",
        )
        report = result.report
        collaboration = report.collaboration["cxx_agent"]

        self.assertEqual("llm-unavailable", collaboration["status"])
        # 工具结果保留：Sidecar finding 仍在报告中。
        self.assertIn("semgrep", [item.source for item in report.findings])
        self.assertEqual(
            [], [item for item in report.findings
                 if item.source == "cxx-agent"],
        )
        roles = {item["role"]: item["status"] for item in collaboration["roles"]}
        self.assertEqual("failed-replaced", roles[ROLE_PLANNER])
        self.assertEqual("failed-replaced", roles[ROLE_MEMORY_LIFETIME])

    def test_required_mode_llm_failure_fails_scan(self):
        write_repo(self.root, {"vuln.c": VULN_C})
        scanner = vuln_scanner(
            lambda: ExplodingAgentClient(),
            sidecar=FakeCxxSidecar(),
            cxx_agent_mode="required",
        )

        with self.assertRaisesRegex(RuntimeError, "required"):
            scanner.scan(
                RepositoryWorkspace(self.root), repository_key="team/project",
            )

    def test_off_mode_matches_baseline_pipeline(self):
        write_repo(self.root, {"vuln.c": VULN_C, "safe.c": SAFE_C})
        sidecar = FakeCxxSidecar(semgrep_uaf_finding())
        factory_calls = []

        def factory():
            factory_calls.append(1)
            return ExplodingAgentClient()

        baseline = RepositoryScanner(
            sast_mode="off", dataflow_enabled=False, cxx_memory_adapter=sidecar,
        )
        disabled = RepositoryScanner(
            sast_mode="off", dataflow_enabled=False, cxx_memory_adapter=sidecar,
            cxx_agent_mode="off",
            cxx_agent_client_factory=factory,
        )

        baseline_result = baseline.scan(
            RepositoryWorkspace(self.root), repository_key="team/project",
        )
        disabled_result = disabled.scan(
            RepositoryWorkspace(self.root), repository_key="team/project",
        )

        self.assertEqual([], factory_calls)
        self.assertEqual(
            [item.to_dict() for item in baseline_result.report.findings],
            [item.to_dict() for item in disabled_result.report.findings],
        )
        self.assertEqual(
            "disabled",
            disabled_result.report.collaboration["cxx_agent"]["status"],
        )
        self.assertEqual(
            "off", disabled_result.report.collaboration["cxx_agent"]["mode"],
        )

    def test_invalid_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            RepositoryScanner(cxx_agent_mode="aggressive")

    # ------------------------------------------------------------- service

    def make_service(self, mode, llm_model=""):
        settings = Settings(
            host="127.0.0.1", port=8080,
            db_path=str(Path(self.root, "state.db")),
            max_diff_bytes=10000, max_steps=8, timeout_seconds=120,
            llm_base_url="http://127.0.0.1:9" if llm_model else "",
            llm_api_key="stub-key" if llm_model else "",
            llm_model=llm_model,
            github_webhook_secret="", github_token="",
            auto_post_review=False,
            repository_scan_sources="github",
            repository_scan_sast_mode="off",
            repository_cache_root=str(Path(self.root, "cache")),
            repository_cache_min_free_bytes=1,
            cxx_memory_mode="off",
            cxx_agent_mode=mode,
        )
        service = ReviewService(settings)
        self.addCleanup(service.queue.close)
        return service

    def _enqueue_vuln_repo(self, service):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
            bundle.writestr("repo-main/vuln.c", VULN_C)
            bundle.writestr("repo-main/safe.c", SAFE_C)
        opener = self._FakeOpener(buffer.getvalue())
        service.repository_materializer = GitHubMaterializer(
            service._ensure_repository_cache(), opener=opener,
        )
        return service.enqueue_repository_scan_source(
            {
                "type": "github",
                "url": "https://github.com/agent-sec-labs/LIMA",
                "ref": SHA,
            },
            "tenant-a",
        )

    class _FakeResponse:
        def __init__(self, payload):
            self._payload = payload

        def read(self, size=-1):
            chunk, self._payload = self._payload, b""
            return chunk

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    class _FakeOpener:
        def __init__(self, archive):
            self.archive = archive

        def __call__(self, request, timeout=None):
            url = request.full_url
            if url.startswith("https://api.github.com/repos/"):
                body = f'{{"sha": "{SHA}"}}'.encode()
                return RepositoryAgentTests._FakeResponse(body)
            if url.startswith("https://codeload.github.com/"):
                return RepositoryAgentTests._FakeResponse(self.archive)
            raise urllib.error.URLError(f"unexpected url {url}")

    def _wait_terminal(self, service, task_id):
        task = None
        for _ in range(400):
            task = service.store.get(task_id, "tenant-a")
            if task and task["state"] in {"SUCCESS", "FAILED"}:
                return task
            time.sleep(0.01)
        self.fail("task did not reach a terminal state")

    def test_service_repository_scan_persists_agent_report(self):
        service = self.make_service("auto")
        client = ScriptedAgentClient(vuln_scripts())
        service.repository_scanner.cxx_agent_client_factory = lambda: client
        created = self._enqueue_vuln_repo(service)

        task = self._wait_terminal(service, created["task_id"])

        self.assertEqual("SUCCESS", task["state"])
        collaboration = task["report"]["collaboration"]["cxx_agent"]
        self.assertEqual("completed", collaboration["status"])
        self.assertEqual("fake-cxx-model", collaboration["model"])
        agent_findings = [
            item for item in task["report"]["findings"]
            if item["source"] == "cxx-agent"
        ]
        self.assertEqual(1, len(agent_findings))
        self.assertEqual("vuln.c", agent_findings[0]["path"])
        self.assertEqual(8, agent_findings[0]["line"])
        self.assertIs(False, agent_findings[0]["automatic_repair"])
        self.assertEqual(
            task["report"]["collaboration"]["import_policy"]["snapshot_sha256"],
            collaboration["snapshot_sha256"],
        )

    def test_service_auto_mode_llm_failure_keeps_task_successful(self):
        service = self.make_service("auto")
        service.repository_scanner.cxx_agent_client_factory = (
            lambda: ExplodingAgentClient()
        )
        created = self._enqueue_vuln_repo(service)

        task = self._wait_terminal(service, created["task_id"])

        self.assertEqual("SUCCESS", task["state"])
        collaboration = task["report"]["collaboration"]["cxx_agent"]
        self.assertEqual("llm-unavailable", collaboration["status"])
        self.assertEqual(
            [], [item for item in task["report"]["findings"]
                 if item["source"] == "cxx-agent"],
        )

    def test_service_required_mode_llm_failure_fails_task(self):
        # required 模式在 Settings 校验就强制要求模型名；这里给一个满足校验的
        # 模型名，再用失败的 fake client 覆盖工厂，验证任务失败语义。
        service = self.make_service("required", llm_model="stub-model")
        service.repository_scanner.cxx_agent_client_factory = (
            lambda: ExplodingAgentClient()
        )
        created = self._enqueue_vuln_repo(service)

        task = self._wait_terminal(service, created["task_id"])

        self.assertEqual("FAILED", task["state"])
        self.assertIn("required", str(task.get("failure") or ""))
