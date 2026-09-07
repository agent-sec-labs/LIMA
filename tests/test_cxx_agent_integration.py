"""Whole-repository scan integration of the C/C++ LLM agent pipeline.

All tests run offline: the LLM is a scripted fake client (zero network), the
C/C++ Sidecar is a fake adapter, and GitHub materialization uses the fake
opener pattern from the existing repository-scan integration tests.
"""

import base64
import hashlib
import io
import json
import re
import shutil
import tempfile
import time
import unittest
import urllib.error
import uuid
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
BASE_SHA = "f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1"

# PR diff：把 VULN_C 作为一个新文件的全部新增行引入，使 changed lines 覆盖
# leak 符号（5-9 行），与 vuln_scripts() 的 read_code_snippet("vuln.c", 5, 9)
# 保持行号一致。
PR_DIFF = (
    "diff --git a/vuln.c b/vuln.c\n"
    "new file mode 100644\n"
    "index 0000000..1111111\n"
    "--- /dev/null\n"
    "+++ b/vuln.c\n"
    "@@ -0,0 +1,9 @@\n"
    "+#include <stdlib.h>\n"
    "+\n"
    "+static char *g_buf = 0;\n"
    "+\n"
    "+void leak(void) {\n"
    "+    char *buf = malloc(64);\n"
    "+    free(buf);\n"
    "+    buf[0] = 'a';\n"
    "+}\n"
)

PY_DIFF = (
    "diff --git a/app.py b/app.py\n"
    "new file mode 100644\n"
    "index 0000000..2222222\n"
    "--- /dev/null\n"
    "+++ b/app.py\n"
    "@@ -0,0 +1,2 @@\n"
    "+def evaluate(code):\n"
    "+    return eval(code)\n"
)

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


def pr_scripts():
    """PR 场景的诚实模型脚本。

    pr-changed 锚的 seed_reason 是 pr-changed-symbol，按 SEED_DOMAINS 路由到
    interprocedural specialist（设计第 5.3 节：PR 从修改行定位所在符号再扩
    展），因此工具读取与候选产出发生在该角色。
    """
    scripts = vuln_scripts()
    scripts.pop(ROLE_MEMORY_LIFETIME)
    scripts[ROLE_INTERPROCEDURAL] = [
        snippet_step("vuln.c", 5, 9),
        agent_step_final(UAF_CANDIDATE),
    ]
    return scripts


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


class FakePRGitHubClient:
    """Offline GitHub client: diff fetch plus pinned Contents-API reads.

    ``file_calls`` 记录每次 get_file_at_commit 的 (repository, path, sha)，
    用于断言抓取绑定的是完整 40 位 head SHA 而非分支名或 PR ref。
    """

    def __init__(self, files=None, fail_fetch=False):
        self.files = dict(files or {})
        self.fail_fetch = fail_fetch
        self.diff = ""
        self.diff_calls = []
        self.file_calls = []

    def ensure_repository_access(self, repository):
        return None

    def get_repository(self, repository):
        return {"full_name": repository}

    def fetch_diff(self, url):
        self.diff_calls.append(url)
        return self.diff

    def get_file_at_commit(
        self, repository, path, commit_sha, max_response_bytes=None,
    ):
        self.file_calls.append((repository, path, commit_sha))
        if self.fail_fetch:
            raise RuntimeError("github contents api down")
        content = self.files[path]
        encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
        return {
            "type": "file",
            "size": len(content.encode("utf-8")),
            "content": encoded,
        }


class FakeLocalSource:
    """Offline LocalCommitSource: exact (repository, commit_sha) tree lookup."""

    def __init__(self, trees=None):
        self.trees = dict(trees or {})
        self.calls = []

    def snapshot(self, repository, commit_sha):
        self.calls.append((repository, commit_sha))
        return self.trees.get((repository, commit_sha))


def pr_payload(action="opened", number=11, head=SHA, base=BASE_SHA,
               repository="team/project"):
    return {
        "action": action,
        "number": number,
        "pull_request": {
            "diff_url": f"https://github.com/{repository}/pull/{number}.diff",
            "issue_url": f"https://api.github.com/repos/{repository}/issues/{number}",
            # 分支名照常出现在 payload 里，但下游抓取只允许绑定 sha。
            "head": {"ref": "feature/uaf", "sha": head},
            "base": {"ref": "main", "sha": base},
        },
        "repository": {"full_name": repository},
    }


class PullRequestAgentTests(unittest.TestCase):
    """GitHub PR 任务的三级上下文链（repository / pr-context / diff-only）。

    head SHA 来自已验签 webhook payload 并绑定任务；所有网络访问都由 fake
    client 记账，本地档由注入的 fake LocalCommitSource 提供零网络快照。
    """

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(suffix="-cxx-pr-agent"))
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)

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

    def _wait_terminal(self, service, task_id):
        task = None
        for _ in range(400):
            task = service.store.get(task_id, "tenant-a")
            if task and task["state"] in {"SUCCESS", "FAILED"}:
                return task
            time.sleep(0.01)
        self.fail("task did not reach a terminal state")

    def _open_pr(self, service, github, local_source=None, diff=PR_DIFF,
                 head=SHA, base=BASE_SHA):
        github.diff = diff
        service.github = github
        if local_source is not None:
            service.cxx_pr_local_source = local_source
        payload = pr_payload(head=head, base=base)
        digest = hashlib.sha256(json.dumps(payload).encode("utf-8")).hexdigest()
        return service.handle_github_pull_request(
            payload, "delivery-" + uuid.uuid4().hex, digest, "tenant-a",
        )

    def _agent_findings(self, task):
        return [
            item for item in task["report"]["findings"]
            if item["source"] == "cxx-agent"
        ]

    def test_local_head_match_uses_repository_scope_without_github(self):
        service = self.make_service("auto")
        client = ScriptedAgentClient(pr_scripts())
        service.repository_scanner.cxx_agent_client_factory = lambda: client
        github = FakePRGitHubClient()
        local = FakeLocalSource({("team/project", SHA): {"vuln.c": VULN_C}})

        created = self._open_pr(service, github, local_source=local)
        task = self._wait_terminal(service, created["task_id"])

        self.assertEqual("SUCCESS", task["state"])
        collaboration = task["report"]["collaboration"]["cxx_agent"]
        self.assertEqual("auto", collaboration["mode"])
        self.assertEqual("completed", collaboration["status"])
        self.assertEqual("repository", collaboration["scope"])
        self.assertEqual("wired", collaboration["local-source"])
        self.assertEqual(SHA, collaboration["head_sha"])
        self.assertEqual(BASE_SHA, collaboration["base_sha"])
        self.assertEqual("fake-cxx-model", collaboration["model"])
        self.assertIn("budget", collaboration)
        self.assertIn("retrieval", collaboration)
        self.assertIn("roles", collaboration)
        # 本地精确命中：GitHub 零调用，本地档只被查询一次且绑定完整 head SHA。
        self.assertEqual([], github.file_calls)
        self.assertEqual([("team/project", SHA)], local.calls)
        # 任务输入保存 base/head SHA 与 source manifest hash。
        self.assertEqual(SHA, task["input"]["head_sha"])
        self.assertEqual(BASE_SHA, task["input"]["base_sha"])
        manifest = task["input"]["source_manifest_sha256"]
        self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", manifest))
        self.assertEqual(manifest, collaboration["source_manifest_sha256"])
        # Agent Finding 走完整管线，绑定修改行符号与触发路径。
        agent_findings = self._agent_findings(task)
        self.assertEqual(1, len(agent_findings))
        self.assertEqual("vuln.c", agent_findings[0]["path"])
        self.assertEqual(8, agent_findings[0]["line"])
        self.assertEqual("leak", agent_findings[0]["symbol"])
        self.assertIs(False, agent_findings[0]["automatic_repair"])
        self.assertEqual(["leak", "free", "buf[0]"], agent_findings[0]["trigger_path"])
        # 模型读到的是固定快照里的真实代码。
        reads = [call for call in client.calls if call["role"] == ROLE_INTERPROCEDURAL]
        self.assertTrue(reads)
        self.assertIn("malloc(64)", reads[-1]["context"])
        self.assertIn("buf[0] = 'a';", reads[-1]["context"])

    def test_head_mismatch_fetches_github_snapshot_pinned_to_head_sha(self):
        service = self.make_service("auto")
        client = ScriptedAgentClient(pr_scripts())
        service.repository_scanner.cxx_agent_client_factory = lambda: client
        # 本地档存在但 commit 不等于 head SHA：精确匹配语义下视为 miss。
        github = FakePRGitHubClient(files={"vuln.c": VULN_C})
        local = FakeLocalSource({("team/project", BASE_SHA): {"vuln.c": VULN_C}})

        created = self._open_pr(service, github, local_source=local)
        task = self._wait_terminal(service, created["task_id"])

        self.assertEqual("SUCCESS", task["state"])
        collaboration = task["report"]["collaboration"]["cxx_agent"]
        self.assertEqual("pr-context", collaboration["scope"])
        self.assertEqual("completed", collaboration["status"])
        # 抓取必须绑定 40 位 head SHA：既不是分支名，也不是 base SHA。
        self.assertEqual([("team/project", "vuln.c", SHA)], github.file_calls)
        self.assertEqual([("team/project", SHA)], local.calls)
        self.assertEqual(1, len(self._agent_findings(task)))
        self.assertTrue(re.fullmatch(
            r"[0-9a-f]{64}", task["input"]["source_manifest_sha256"],
        ))

    def test_github_failure_degrades_to_diff_only_without_agent(self):
        service = self.make_service("auto")
        # 脚本故意可用：diff-only 下管线绝不运行，任何调用都是失败。
        client = ScriptedAgentClient(pr_scripts())
        service.repository_scanner.cxx_agent_client_factory = lambda: client
        github = FakePRGitHubClient(files={"vuln.c": VULN_C}, fail_fetch=True)
        local = FakeLocalSource()

        created = self._open_pr(service, github, local_source=local)
        task = self._wait_terminal(service, created["task_id"])

        self.assertEqual("SUCCESS", task["state"])
        collaboration = task["report"]["collaboration"]["cxx_agent"]
        self.assertEqual("diff-only", collaboration["scope"])
        self.assertEqual("diff-only", collaboration["status"])
        self.assertEqual(
            "local-miss+github-unavailable", collaboration["reason"],
        )
        self.assertEqual(SHA, collaboration["head_sha"])
        # Diff-only 不得升级：零 cxx-agent Finding、零模型调用。
        self.assertEqual([], self._agent_findings(task))
        self.assertEqual([], client.calls)
        # 固定 SHA 的抓取尝试确实发生过（降级不是静默跳过）。
        self.assertEqual([("team/project", "vuln.c", SHA)], github.file_calls)
        self.assertNotIn("source_manifest_sha256", task["input"])

    def test_diff_only_does_not_escalate_even_in_required_mode(self):
        service = self.make_service("required", llm_model="stub-model")
        client = ScriptedAgentClient(pr_scripts())
        service.repository_scanner.cxx_agent_client_factory = lambda: client
        github = FakePRGitHubClient(files={"vuln.c": VULN_C}, fail_fetch=True)

        created = self._open_pr(service, github)
        task = self._wait_terminal(service, created["task_id"])

        # 源头降级不是 agent 失败：任务保持成功，如实记录 diff-only，
        # 绝不为满足 required 而用 diff-only 证据运行管线。
        self.assertEqual("SUCCESS", task["state"])
        collaboration = task["report"]["collaboration"]["cxx_agent"]
        self.assertEqual("diff-only", collaboration["status"])
        self.assertEqual([], self._agent_findings(task))
        self.assertEqual([], client.calls)

    def test_non_cxx_pull_request_skips_agent_and_fetch(self):
        service = self.make_service("auto")
        client = ScriptedAgentClient(pr_scripts())
        service.repository_scanner.cxx_agent_client_factory = lambda: client
        github = FakePRGitHubClient()
        local = FakeLocalSource({("team/project", SHA): {"vuln.c": VULN_C}})

        created = self._open_pr(
            service, github, local_source=local, diff=PY_DIFF,
        )
        task = self._wait_terminal(service, created["task_id"])

        self.assertEqual("SUCCESS", task["state"])
        collaboration = task["report"]["collaboration"]["cxx_agent"]
        self.assertEqual("no-cxx-sources", collaboration["status"])
        # 零 LLM、零 fetch、零本地查询。
        self.assertEqual([], client.calls)
        self.assertEqual([], github.file_calls)
        self.assertEqual([], local.calls)
        self.assertNotIn("source_manifest_sha256", task["input"])

    def test_api_pull_request_without_head_sha_keeps_existing_report(self):
        service = self.make_service("auto")
        client = ScriptedAgentClient(pr_scripts())
        service.repository_scanner.cxx_agent_client_factory = lambda: client

        created = service.enqueue_review(
            "team/project", PR_DIFF, 11, tenant_id="tenant-a",
        )
        task = self._wait_terminal(service, created["task_id"])

        # API 提交的 PR 任务没有已验签 head SHA：行为与既有流程逐字节等价，
        # 不出现 collaboration.cxx_agent。
        self.assertEqual("SUCCESS", task["state"])
        self.assertNotIn("cxx_agent", task["report"]["collaboration"])
        self.assertEqual([], client.calls)

    def test_required_mode_llm_failure_fails_pr_task(self):
        service = self.make_service("required", llm_model="stub-model")
        service.repository_scanner.cxx_agent_client_factory = (
            lambda: ExplodingAgentClient()
        )
        github = FakePRGitHubClient(files={"vuln.c": VULN_C})

        created = self._open_pr(service, github)
        task = self._wait_terminal(service, created["task_id"])

        # 评审类任务的失败走队列 dead-letter 路径，error 而非 typed failure。
        self.assertEqual("FAILED", task["state"])
        self.assertIn("required", str(task.get("error") or ""))
        self.assertEqual([("team/project", "vuln.c", SHA)], github.file_calls)


if __name__ == "__main__":
    unittest.main()
