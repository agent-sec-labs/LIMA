"""Adapters for deterministic static-analysis tools and normalized evidence."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from .models import Finding, Severity
from .workspace import RepositoryWorkspace, WorkspaceInventory


BANDIT_CWE_OVERRIDES = {
    # Bandit 1.9 reports B307/eval as CWE-78. LIMA uses the more
    # specific CWE-95 so deterministic AST and SAST evidence can be fused.
    "B307": "CWE-95",
}


@dataclass
class SastRunResult:
    engine: str
    status: str
    findings: list[Finding] = field(default_factory=list)
    duration_ms: int = 0
    diagnostic: str = ""

    def summary(self) -> dict:
        return {
            "status": self.status,
            "findings": len(self.findings),
            "duration_ms": self.duration_ms,
            "diagnostic": self.diagnostic[:500],
        }


class SastAdapter(Protocol):
    name: str

    def available(self) -> bool:
        ...

    def scan(
        self, workspace: RepositoryWorkspace, inventory: WorkspaceInventory
    ) -> SastRunResult:
        ...


class BanditAdapter:
    """Run Bandit in bounded batches and normalize its JSON report."""

    name = "bandit"

    def __init__(self, timeout_seconds: int = 120, batch_size: int = 100) -> None:
        if timeout_seconds < 1 or batch_size < 1:
            raise ValueError("Bandit adapter limits must be positive")
        self.timeout_seconds = timeout_seconds
        self.batch_size = batch_size

    def available(self) -> bool:
        return importlib.util.find_spec("bandit") is not None

    def scan(
        self, workspace: RepositoryWorkspace, inventory: WorkspaceInventory
    ) -> SastRunResult:
        started = time.monotonic()
        if not self.available():
            return SastRunResult(
                self.name, "unavailable", duration_ms=self._elapsed(started),
                diagnostic="Bandit is not installed",
            )

        python_files = [
            str(workspace.absolute_file(item.path))
            for item in inventory.files if item.path.endswith(".py")
        ]
        if not python_files:
            return SastRunResult(
                self.name, "completed", duration_ms=self._elapsed(started)
            )

        findings: list[Finding] = []
        try:
            for offset in range(0, len(python_files), self.batch_size):
                batch = python_files[offset:offset + self.batch_size]
                command = [
                    sys.executable, "-m", "bandit", "-q", "-f", "json", *batch,
                ]
                completed = subprocess.run(
                    command,
                    cwd=workspace.root,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=self.timeout_seconds,
                    check=False,
                )
                if completed.returncode not in {0, 1}:
                    return SastRunResult(
                        self.name, "failed", findings=findings,
                        duration_ms=self._elapsed(started),
                        diagnostic=(completed.stderr or completed.stdout or "Bandit failed")[:500],
                    )
                findings.extend(self.parse_report(completed.stdout, workspace.root))
        except subprocess.TimeoutExpired:
            return SastRunResult(
                self.name, "failed", findings=findings,
                duration_ms=self._elapsed(started), diagnostic="Bandit timed out",
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return SastRunResult(
                self.name, "failed", findings=findings,
                duration_ms=self._elapsed(started), diagnostic=str(exc)[:500],
            )
        return SastRunResult(
            self.name, "completed", findings=findings,
            duration_ms=self._elapsed(started),
        )

    @staticmethod
    def _elapsed(started: float) -> int:
        return int((time.monotonic() - started) * 1000)

    @classmethod
    def parse_report(cls, payload: str, root: Path) -> list[Finding]:
        report = json.loads(payload or "{}")
        findings: list[Finding] = []
        for item in report.get("results") or []:
            raw_path = Path(str(item.get("filename") or ""))
            candidate = raw_path if raw_path.is_absolute() else root / raw_path
            resolved = candidate.resolve(strict=False)
            try:
                path = resolved.relative_to(root).as_posix()
            except ValueError:
                continue

            raw_severity = str(item.get("issue_severity") or "MEDIUM").upper()
            severity = {
                "LOW": Severity.LOW,
                "MEDIUM": Severity.MEDIUM,
                "HIGH": Severity.HIGH,
            }.get(raw_severity, Severity.MEDIUM)
            raw_confidence = str(item.get("issue_confidence") or "MEDIUM").upper()
            confidence = {
                "LOW": 0.62,
                "MEDIUM": 0.78,
                "HIGH": 0.9,
            }.get(raw_confidence, 0.72)
            test_id = str(item.get("test_id") or "UNKNOWN")
            cwe_value = (item.get("issue_cwe") or {}).get("id")
            cwe = BANDIT_CWE_OVERRIDES.get(
                test_id, "CWE-%s" % cwe_value if cwe_value else ""
            )
            more_info = str(item.get("more_info") or "")
            issue = str(item.get("issue_text") or "Bandit security finding")
            code = " ".join(str(item.get("code") or "").strip().split())[:240]
            findings.append(
                Finding(
                    rule_id="BANDIT-" + test_id,
                    severity=severity,
                    title=issue[:160],
                    explanation=(
                        "%s Bandit confidence: %s.%s"
                        % (issue, raw_confidence, (" Reference: " + more_info) if more_info else "")
                    )[:1000],
                    path=path,
                    line=max(1, int(item.get("line_number") or 1)),
                    evidence=code,
                    fix="Follow the rule-specific remediation and keep untrusted data out of the flagged operation.",
                    test="Add a regression test that exercises a malicious and a valid input.",
                    confidence=confidence,
                    cwe=cwe,
                    source="bandit",
                    evidence_kind="sast",
                )
            )
        return findings
