"""Multi-agent review with planning, dialogue, verification and arbitration.

The coordinator implements a bounded collaboration protocol:
plan -> specialist review -> peer challenge -> evidence revision -> independent
verification -> arbitration.  Every hand-off is persisted as an agent message
when a task store is available.  Failed specialists are retried and then
replanned to a substitute reviewer.
"""
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, TypedDict

from .context_manager import ContextManager
from .diff_parser import ParsedDiff
from .memory import MemoryManager
from .models import Finding, Severity
from .reviewer import LocalRuleReviewer, Reviewer
from .runtime import AgentLoop, AgentRuntime, AgentTool, RuntimeNode, ToolRegistry


@dataclass
class AgentMessage:
    sender: str
    recipient: str
    kind: str
    content: Dict[str, Any]
    correlation_id: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class CollaborationBus:
    """Task-scoped mailbox plus durable transcript."""

    def __init__(self, task_id: str = "", store=None):
        self.task_id = task_id
        self.store = store
        self.messages: List[AgentMessage] = []
        self._lock = threading.Lock()

    def send(
        self, sender: str, recipient: str, kind: str,
        content: Dict[str, Any], correlation_id: str = "",
    ) -> AgentMessage:
        message = AgentMessage(sender, recipient, kind, content, correlation_id)
        with self._lock:
            self.messages.append(message)
            if self.store is not None and self.task_id:
                self.store.record_agent_message(self.task_id, message.to_dict())
        return message

    def inbox(self, recipient: str, correlation_id: str = "") -> List[dict]:
        with self._lock:
            values = [
                message.to_dict() for message in self.messages
                if message.recipient in {recipient, "specialists", "all"}
                and (not correlation_id or message.correlation_id == correlation_id)
            ]
        return values

    def count(self, kind: str = "") -> int:
        with self._lock:
            return sum(1 for item in self.messages if not kind or item.kind == kind)


@dataclass
class ReviewAssignment:
    agent: str
    objective: str
    files: List[str]
    risk_domains: List[str]
    assignment_id: str = ""
    round: int = 1
    reason: str = "initial-plan"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ReviewPlan:
    languages: List[str]
    changed_files: List[str]
    risk_level: str
    assignments: List[ReviewAssignment]

    def to_dict(self) -> dict:
        return {
            "languages": self.languages,
            "changed_files": self.changed_files,
            "risk_level": self.risk_level,
            "assignments": [item.to_dict() for item in self.assignments],
        }


@dataclass
class Critique:
    finding_key: str
    accepted: bool
    objections: List[str]
    confidence_adjustment: float
    questions: List[str]
    requires_revision: bool
    round: int = 1


@dataclass
class Reflection:
    finding_key: str
    revision_needed: bool
    guidance: List[str]
    round: int


@dataclass
class Reproduction:
    finding_key: str
    reproducible: bool
    method: str
    evidence: str


@dataclass
class VerificationDecision:
    finding_key: str
    approved: bool
    reasons: List[str]
    confidence: float


class CollaborationState(TypedDict, total=False):
    diff: str
    parsed: ParsedDiff
    task_id: str
    repository: str
    tenant_id: str
    bus: CollaborationBus
    plan: ReviewPlan
    specialist_findings: List[Finding]
    finding_sources: Dict[str, List[str]]
    assignments_by_agent: Dict[str, ReviewAssignment]
    critiques: Dict[str, Critique]
    reproductions: Dict[str, Reproduction]
    fix_ready: Dict[str, bool]
    decisions: Dict[str, VerificationDecision]
    verified: List[Finding]
    agent_outcomes: List[dict]
    rounds_completed: int


def finding_key(finding: Finding) -> str:
    raw = "%s:%s:%s" % (finding.path, finding.line, finding.rule_id)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class FilteredAgent(Reviewer):
    """Compatibility adapter for third-party reviewers; built-ins do not use it."""

    def __init__(self, name: str, reviewer: Reviewer, prefixes: tuple):
        self.name = name
        self.reviewer = reviewer
        self.prefixes = prefixes
        self.domains = tuple(
            "security" if item.startswith("SEC") else "reliability"
            for item in prefixes
        )

    def review(self, diff: str, parsed: ParsedDiff) -> List[Finding]:
        return [
            item for item in self.reviewer.review(diff, parsed)
            if item.rule_id.startswith(self.prefixes)
        ]


class PlannerAgent:
    name = "planner-agent"

    DOMAIN_OBJECTIVES = {
        "security": "Trace attacker-controlled data and find exploitable security defects.",
        "reliability": "Find failure handling, observability and runtime reliability regressions.",
        "correctness": "Find behavior and data-flow defects introduced by the change.",
        "regression": "Identify compatibility and test gaps caused by the change.",
    }

    def plan(self, parsed: ParsedDiff, specialists: List[Reviewer]) -> ReviewPlan:
        extensions = {path.rsplit(".", 1)[-1].lower() for path in parsed.files if "." in path}
        languages = sorted({
            "python" if ext == "py" else
            "javascript" if ext in {"js", "jsx", "ts", "tsx"} else
            "configuration" if ext in {"yml", "yaml", "json", "toml"} else ext
            for ext in extensions
        })
        sensitive = any(
            token in path.lower()
            for path in parsed.files
            for token in ("auth", "security", "payment", "permission", "token", "migration")
        )
        default_domains = ["security", "reliability", "correctness", "regression"]
        assignments = []
        for index, agent in enumerate(specialists, 1):
            declared = list(getattr(agent, "domains", ()) or default_domains)
            objectives = [
                self.DOMAIN_OBJECTIVES[item]
                for item in declared if item in self.DOMAIN_OBJECTIVES
            ]
            assignments.append(ReviewAssignment(
                agent=agent.name,
                objective=" ".join(objectives) or "Find actionable defects and cite changed-line evidence.",
                files=list(parsed.files),
                risk_domains=declared,
                assignment_id="A%02d" % index,
            ))
        return ReviewPlan(
            languages=languages or ["unknown"],
            changed_files=list(parsed.files),
            risk_level="high" if sensitive or len(parsed.files) > 10 else "normal",
            assignments=assignments,
        )

    def replan(
        self, failed: ReviewAssignment, substitutes: List[Reviewer], error: str,
    ) -> Optional[ReviewAssignment]:
        if not substitutes:
            return None
        target = max(
            substitutes,
            key=lambda item: len(
                set(getattr(item, "domains", ()) or failed.risk_domains)
                .intersection(failed.risk_domains)
            ),
        )
        return ReviewAssignment(
            agent=target.name,
            objective=(
                failed.objective
                + " Take over a failed assignment and independently reconstruct its evidence."
            ),
            files=list(failed.files), risk_domains=list(failed.risk_domains),
            assignment_id=failed.assignment_id, round=failed.round + 1,
            reason="replacement-after-failure: %s" % error[:160],
        )


class CriticAgent:
    name = "critic-agent"

    def challenge(
        self, finding: Finding, parsed: ParsedDiff,
        peer_sources: Optional[List[str]] = None, round_number: int = 1,
    ) -> Critique:
        objections = []
        questions = []
        valid_locations = {(line.path, line.line) for line in parsed.added_lines}
        if (finding.path, finding.line) not in valid_locations:
            objections.append("location is not an added line")
        source_line = next(
            (line.content for line in parsed.added_lines
             if line.path == finding.path and line.line == finding.line), ""
        )
        if not finding.evidence or finding.evidence.strip() not in source_line.strip():
            objections.append("quoted evidence does not match the changed line")
        if len(finding.explanation.strip()) < 12:
            objections.append("explanation is not specific enough")
        if len(finding.fix.strip()) < 8:
            objections.append("remediation is not actionable")
        if len(finding.test.strip()) < 8:
            objections.append("test strategy is not actionable")
        if len(peer_sources or []) < 2 and finding.severity in {Severity.CRITICAL, Severity.HIGH}:
            questions.append("High-impact claim needs independent verifier evidence.")
        adjustment = -.35 if objections else (.08 if len(peer_sources or []) > 1 else .03)
        return Critique(
            finding_key(finding), not objections, objections, adjustment,
            questions, bool(objections), round_number,
        )


class EvidenceAgent:
    name = "evidence-agent"

    def reproduce(self, finding: Finding, parsed: ParsedDiff) -> Reproduction:
        line = next(
            (item.content for item in parsed.added_lines
             if item.path == finding.path and item.line == finding.line), ""
        )
        normalized = line.replace(" ", "")
        signatures = {
            "SEC-EVAL": ("eval(" in line or "exec(" in line),
            "SEC-SUBPROCESS-SHELL": "shell=True" in normalized,
            "SEC-HARDCODED-SECRET": any(
                token in line.lower() for token in ("password", "secret", "token", "api_key")
            ),
            "SEC-SQL-CONCAT": any(token in line for token in ("execute(", "query(")),
            "REL-DEBUG-PRINT": "print(" in line or "console.log(" in line,
            "REL-EMPTY-EXCEPT": "except" in line,
        }
        exact_evidence = bool(line and finding.evidence and finding.evidence.strip() in line.strip())
        reproducible = signatures.get(finding.rule_id, exact_evidence)
        return Reproduction(
            finding_key(finding), reproducible,
            "independent changed-line evidence check",
            line.strip()[:240] if reproducible else "No independently matching changed-line evidence.",
        )


class ReflectionAgent:
    name = "reflection-agent"

    def reflect(self, critique: Critique) -> Reflection:
        guidance = list(critique.objections)
        guidance.extend(critique.questions)
        if critique.requires_revision:
            guidance.append(
                "Re-read the changed line, discard unsupported assumptions, and return a corrected claim."
            )
        return Reflection(
            critique.finding_key, critique.requires_revision, guidance, critique.round
        )


class TestAgent(EvidenceAgent):
    """Backward-compatible name for integrations importing TestAgent."""

    name = "test-agent"


class FixAgent:
    name = "fix-agent"

    def assess(self, finding: Finding) -> bool:
        dangerous = ("disable validation", "ignore error", "catch all")
        text = finding.fix.lower()
        return bool(finding.fix and not any(item in text for item in dangerous))


class VerifierAgent:
    name = "verifier-agent"

    def verify(
        self, finding: Finding, critique: Critique,
        reproduction: Reproduction, fix_ready: bool,
    ) -> VerificationDecision:
        reasons = []
        confidence = max(0.0, min(1.0, finding.confidence + critique.confidence_adjustment))
        if not critique.accepted:
            reasons.extend(critique.objections)
        if not reproduction.reproducible:
            reasons.append("independent evidence could not reproduce the claim")
        if not fix_ready:
            reasons.append("proposed remediation failed the safety/actionability gate")
        if confidence < .55:
            reasons.append("confidence is below the verification threshold")
        approved = not reasons
        return VerificationDecision(finding_key(finding), approved, reasons, confidence)


class ArbiterAgent:
    name = "arbiter-agent"

    def decide(
        self, findings: List[Finding], decisions: Dict[str, VerificationDecision],
    ) -> List[Finding]:
        merged: Dict[tuple, Finding] = {}
        for finding in findings:
            decision = decisions[finding_key(finding)]
            if not decision.approved:
                continue
            finding.confidence = decision.confidence
            identity = (finding.path, finding.line, finding.rule_id)
            current = merged.get(identity)
            if current is None or finding.confidence > current.confidence:
                merged[identity] = finding
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        return sorted(merged.values(), key=lambda item: (order[item.severity], item.path, item.line))


class SynthesizerAgent(ArbiterAgent):
    """Compatibility alias; arbitration is now an explicit final role."""

    name = "synthesizer-agent"


class MultiAgentCoordinator(Reviewer):
    """Bounded collaborative review with dialogue and failure recovery."""

    name = "multi-agent-collaboration"

    def __init__(
        self, agents: List[Reviewer], max_workers: int = 4, store=None,
        agent_retries: int = 1, collaboration_rounds: int = 2,
        fallback_agent: Optional[Reviewer] = None,
        context_manager: Optional[ContextManager] = None,
        memory_manager: Optional[MemoryManager] = None,
        agent_loop_max_steps: int = 4, agent_loop_timeout_seconds: int = 45,
    ):
        self.agents = agents
        self.max_workers = max_workers
        self.store = store
        self.agent_retries = max(0, agent_retries)
        self.collaboration_rounds = max(1, collaboration_rounds)
        self.fallback_agent = fallback_agent or LocalRuleReviewer()
        self.context_manager = context_manager or ContextManager()
        self.memory_manager = memory_manager
        self.agent_loop = AgentLoop(agent_loop_max_steps, agent_loop_timeout_seconds)
        self.runtime = AgentRuntime(max_steps=8, timeout_seconds=120)
        self.planner = PlannerAgent()
        self.critic = CriticAgent()
        self.reflection_agent = ReflectionAgent()
        self.evidence_agent = EvidenceAgent()
        self.test_agent = self.evidence_agent
        self.fix_agent = FixAgent()
        self.verifier = VerifierAgent()
        self.arbiter = ArbiterAgent()
        self.synthesizer = self.arbiter
        self._summaries: Dict[str, dict] = {}
        self._summary_lock = threading.Lock()

    def review(self, diff: str, parsed: ParsedDiff) -> List[Finding]:
        return self.review_with_context("", diff, parsed)

    def review_with_context(
        self, task_id: str, diff: str, parsed: ParsedDiff,
        repository: str = "", tenant_id: str = "default",
    ) -> List[Finding]:
        state: CollaborationState = {
            "task_id": task_id, "diff": diff, "parsed": parsed,
            "repository": repository, "tenant_id": tenant_id,
            "bus": CollaborationBus(task_id, self.store),
        }
        result = self.runtime.execute(
            state,
            [
                RuntimeNode("planner", self._plan_node, checkpoint=False),
                RuntimeNode("specialists", self._specialist_node, checkpoint=False),
                RuntimeNode("deliberation", self._deliberation_node, checkpoint=False),
                RuntimeNode("evidence", self._evidence_node, checkpoint=False),
                RuntimeNode("verifier", self._verify_node, checkpoint=False),
                RuntimeNode("arbiter", self._arbitrate_node, checkpoint=False),
            ],
            task_id=task_id,
        )
        summary = self._make_summary(result)
        if task_id:
            with self._summary_lock:
                self._summaries[task_id] = summary
        return result["verified"]

    def collaboration_summary(self, task_id: str) -> dict:
        with self._summary_lock:
            return dict(self._summaries.get(task_id, {}))

    @staticmethod
    def _bus(state: CollaborationState) -> CollaborationBus:
        return state["bus"]

    def _emit(
        self, state: CollaborationState, sender: str, recipient: str,
        kind: str, content: Dict[str, Any], correlation_id: str = "",
    ) -> None:
        self._bus(state).send(sender, recipient, kind, content, correlation_id)

    def _plan_node(self, state: CollaborationState) -> Dict[str, Any]:
        plan = self.planner.plan(state["parsed"], self.agents)
        for assignment in plan.assignments:
            self._emit(
                state, self.planner.name, assignment.agent, "assignment",
                assignment.to_dict(), assignment.assignment_id,
            )
        return {
            "plan": plan,
            "assignments_by_agent": {item.agent: item for item in plan.assignments},
        }

    def _recall_memories(
        self, state: CollaborationState, assignment: ReviewAssignment,
    ) -> List[dict]:
        if not self.memory_manager or not state.get("repository"):
            return []
        query = " ".join([
            assignment.objective, " ".join(assignment.files),
            " ".join(assignment.risk_domains),
        ])
        memories = self.memory_manager.recall(
            state.get("tenant_id", "default"), state.get("repository", ""), query
        )
        if memories:
            self._emit(
                state, "memory-manager", assignment.agent, "memory_recalled",
                {
                    "count": len(memories),
                    "memory_ids": [item["id"] for item in memories],
                    "scopes": sorted({item["scope"] for item in memories}),
                }, assignment.assignment_id,
            )
        return memories

    def _agent_tools(
        self, state: CollaborationState, assignment: ReviewAssignment,
    ) -> ToolRegistry:
        def search_diff(query: str, limit: int = 20):
            value = str(query).strip().lower()
            if not value:
                raise ValueError("search_diff query is required")
            hits = []
            for index, line in enumerate(state["diff"].splitlines(), 1):
                if value in line.lower():
                    hits.append({"diff_line": index, "content": line[:500]})
                if len(hits) >= max(1, min(int(limit), 50)):
                    break
            return hits

        def changed_line(path: str, line: int):
            match = next((
                item for item in state["parsed"].added_lines
                if item.path == str(path) and item.line == int(line)
            ), None)
            if match is None:
                return {"found": False, "path": path, "line": line}
            return {
                "found": True, "path": match.path, "line": match.line,
                "content": match.content,
            }

        def list_changed_files():
            return list(state["parsed"].files)

        def recall_memory(query: str, limit: int = 5):
            if not self.memory_manager or not state.get("repository"):
                return []
            return self.memory_manager.recall(
                state.get("tenant_id", "default"), state["repository"], str(query),
                limit=max(1, min(int(limit), 10)),
            )

        return ToolRegistry([
            AgentTool(
                "search_diff",
                "Search the PR diff for an exact case-insensitive text fragment.",
                {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 50},
                    },
                    "required": ["query"], "additionalProperties": False,
                },
                search_diff,
            ),
            AgentTool(
                "changed_line",
                "Read one added line by new-file path and line number.",
                {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "line": {"type": "integer", "minimum": 1},
                    },
                    "required": ["path", "line"], "additionalProperties": False,
                },
                changed_line,
            ),
            AgentTool(
                "list_changed_files",
                "List files changed by this PR.",
                {
                    "type": "object", "properties": {},
                    "additionalProperties": False,
                },
                list_changed_files,
            ),
            AgentTool(
                "recall_memory",
                "Recall repository-scoped review experience relevant to a query.",
                {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 10},
                    },
                    "required": ["query"], "additionalProperties": False,
                },
                recall_memory,
            ),
        ])

    def _run_agent_loop(
        self, state: CollaborationState, agent: Reviewer,
        assignment: ReviewAssignment, feedback: Optional[List[str]],
    ) -> tuple:
        memories = self._recall_memories(state, assignment)
        bundle = self.context_manager.build(state["diff"], assignment.to_dict(), memories)
        self._emit(
            state, "context-manager", agent.name, "context_prepared",
            bundle.metadata(), assignment.assignment_id,
        )
        tools = self._agent_tools(state, assignment)

        def on_event(kind: str, detail: Dict[str, Any]) -> None:
            self._emit(
                state, "agent-runtime", agent.name, kind, detail,
                assignment.assignment_id,
            )
            if self.memory_manager and state.get("task_id") and state.get("repository"):
                self.memory_manager.remember(
                    state.get("tenant_id", "default"), state["repository"],
                    "working", kind, str(detail), task_id=state["task_id"],
                    agent=agent.name, importance=0.3,
                )

        loop_state = {
            "diff": state["diff"], "context": bundle.text,
            "context_metadata": bundle.metadata(), "parsed": state["parsed"],
            "assignment": assignment.to_dict(), "feedback": list(feedback or []),
            "inbox": self._bus(state).inbox(agent.name, assignment.assignment_id),
            "memories": memories, "available_tools": tools.catalog(),
        }
        last_context = {"metadata": bundle.metadata()}

        def managed_step(loop_iteration: Dict[str, Any]) -> Dict[str, Any]:
            managed = self.context_manager.compose(
                bundle, assignment.to_dict(), feedback=list(feedback or []),
                inbox=loop_iteration.get("inbox") or [], memories=memories,
                observations=loop_iteration.get("observations") or [],
                tools=tools.catalog(),
            )
            metadata = managed.metadata()
            last_context["metadata"] = metadata
            self._emit(
                state, "context-manager", agent.name, "context_window_prepared",
                metadata, assignment.assignment_id,
            )
            prepared = dict(loop_iteration)
            prepared["context"] = managed.text
            prepared["managed_context"] = managed.text
            prepared["context_metadata"] = metadata
            return getattr(agent, "agent_step")(prepared)

        result = self.agent_loop.run(
            managed_step, tools, loop_state, on_event,
        )
        findings = list(result.output or [])
        if not all(isinstance(item, Finding) for item in findings):
            raise TypeError("agent loop final output must contain Finding objects")
        return findings, {
            "loop_steps": result.steps, "loop_stop_reason": result.stop_reason,
            "context": last_context["metadata"], "memories_recalled": len(memories),
            "tools_available": len(tools.names()),
            "tool_calls": len(result.observations),
        }

    def _invoke_agent(
        self, state: CollaborationState, agent: Reviewer,
        assignment: ReviewAssignment, feedback: Optional[List[str]] = None,
    ) -> tuple:
        last_error = None
        for attempt in range(1, self.agent_retries + 2):
            self._emit(
                state, "coordinator", agent.name, "attempt_started",
                {"attempt": attempt, "round": assignment.round}, assignment.assignment_id,
            )
            try:
                loop_stepper = getattr(agent, "agent_step", None)
                execution = {"loop_steps": 0, "loop_stop_reason": "one-shot"}
                if loop_stepper:
                    findings, execution = self._run_agent_loop(
                        state, agent, assignment, feedback
                    )
                else:
                    collaborative = getattr(agent, "review_assignment", None)
                    if collaborative:
                        findings = collaborative(
                            state["diff"], state["parsed"], assignment.to_dict(),
                            list(feedback or []),
                            self._bus(state).inbox(agent.name, assignment.assignment_id),
                        )
                    else:
                        findings = agent.review(state["diff"], state["parsed"])
                self._emit(
                    state, agent.name, self.critic.name, "specialist_evidence",
                    {
                        "attempt": attempt, "round": assignment.round,
                        "findings": [item.to_dict() for item in findings],
                        "execution": execution,
                    }, assignment.assignment_id,
                )
                return findings, attempt, "", execution
            except Exception as exc:
                last_error = str(exc)
                self._emit(
                    state, agent.name, self.planner.name, "agent_failure",
                    {"attempt": attempt, "error": last_error[:1000]},
                    assignment.assignment_id,
                )
                if attempt <= self.agent_retries:
                    self._emit(
                        state, self.planner.name, agent.name, "retry_request",
                        {"next_attempt": attempt + 1, "reason": last_error[:500]},
                        assignment.assignment_id,
                    )
        return (
            [], self.agent_retries + 1, last_error or "unknown agent failure",
            {"loop_steps": 0, "loop_stop_reason": "failed"},
        )

    def _replacement_candidates(self, failed_agent: Reviewer) -> List[Reviewer]:
        values = [item for item in self.agents if item is not failed_agent]
        if all(item.name != self.fallback_agent.name for item in values):
            values.append(self.fallback_agent)
        return values

    def _run_assignment(
        self, state: CollaborationState, assignment: ReviewAssignment,
        agent: Reviewer,
    ) -> dict:
        findings, attempts, error, execution = self._invoke_agent(
            state, agent, assignment
        )
        result = {
            "agent": agent.name, "assignment_id": assignment.assignment_id,
            "attempts": attempts, "status": "completed" if not error else "failed",
            "findings": findings, "error": error, "substituted_for": "",
            "assignment": assignment, "execution": execution,
        }
        if not error:
            return result
        replacement = self.planner.replan(
            assignment, self._replacement_candidates(agent), error
        )
        if replacement is None:
            return result
        substitute = next(
            item for item in self._replacement_candidates(agent)
            if item.name == replacement.agent
        )
        self._emit(
            state, self.planner.name, substitute.name, "assignment_handoff",
            {
                "from": agent.name, "reason": error[:500],
                "assignment": replacement.to_dict(),
            }, assignment.assignment_id,
        )
        findings, replacement_attempts, replacement_error, replacement_execution = self._invoke_agent(
            state, substitute, replacement, ["Take over after %s failed: %s" % (agent.name, error)]
        )
        return {
            "agent": substitute.name, "assignment_id": assignment.assignment_id,
            "attempts": attempts + replacement_attempts,
            "status": "completed" if not replacement_error else "failed",
            "findings": findings, "error": replacement_error,
            "substituted_for": agent.name,
            "assignment": replacement, "execution": replacement_execution,
        }

    def _specialist_node(self, state: CollaborationState) -> Dict[str, Any]:
        outcomes = []
        by_name = {item.name: item for item in self.agents}
        assignments = state["plan"].assignments
        with ThreadPoolExecutor(
            max_workers=min(self.max_workers, max(1, len(assignments)))
        ) as pool:
            futures = {
                pool.submit(self._run_assignment, state, assignment, by_name[assignment.agent]): assignment
                for assignment in assignments
            }
            for future in as_completed(futures):
                outcomes.append(future.result())
        findings = []
        sources: Dict[str, List[str]] = {}
        assignment_map = dict(state["assignments_by_agent"])
        for outcome in outcomes:
            assignment_map[outcome["agent"]] = outcome["assignment"]
            for finding in outcome["findings"]:
                key = finding_key(finding)
                sources.setdefault(key, []).append(outcome["agent"])
                findings.append(finding)
        if outcomes and all(item["status"] == "failed" for item in outcomes):
            raise RuntimeError(
                "all review assignments failed after retry/replanning: "
                + "; ".join(item["error"] for item in outcomes)
            )
        return {
            "specialist_findings": findings,
            "finding_sources": sources,
            "agent_outcomes": outcomes,
            "assignments_by_agent": assignment_map,
        }

    def _deliberation_node(self, state: CollaborationState) -> Dict[str, Any]:
        findings = list(state["specialist_findings"])
        critiques: Dict[str, Critique] = {}
        rounds_completed = 0
        agents = {item.name: item for item in self.agents}
        agents.setdefault(self.fallback_agent.name, self.fallback_agent)
        assignments = state["assignments_by_agent"]
        for round_number in range(1, self.collaboration_rounds + 1):
            rounds_completed = round_number
            revisions = []
            for finding in findings:
                key = finding_key(finding)
                critique = self.critic.challenge(
                    finding, state["parsed"], state["finding_sources"].get(key, []),
                    round_number,
                )
                critiques[key] = critique
                reflection = self.reflection_agent.reflect(critique)
                self._emit(
                    state, self.critic.name, self.reflection_agent.name,
                    "critique_for_reflection", asdict(critique), key,
                )
                recipients = state["finding_sources"].get(key, []) or ["specialists"]
                for recipient in recipients:
                    self._emit(
                        state, self.critic.name, recipient, "peer_challenge",
                        asdict(critique), key,
                    )
                    self._emit(
                        state, self.reflection_agent.name, recipient,
                        "reflection_guidance", asdict(reflection), key,
                    )
                if reflection.revision_needed:
                    revisions.append((finding, critique, reflection, recipients[0]))
            if not revisions or round_number >= self.collaboration_rounds:
                break
            revised_by_key = {}
            for original, critique, reflection, source in revisions:
                assignment = assignments.get(source)
                agent = agents.get(source)
                if not assignment or not agent:
                    continue
                revised_assignment = ReviewAssignment(
                    agent=source, objective=assignment.objective,
                    files=list(assignment.files), risk_domains=list(assignment.risk_domains),
                    assignment_id=assignment.assignment_id, round=round_number + 1,
                    reason="critic-requested-revision",
                )
                self._emit(
                    state, self.critic.name, source, "revision_request",
                    {"objections": critique.objections, "guidance": reflection.guidance},
                    finding_key(original),
                )
                revised, _attempts, error, _execution = self._invoke_agent(
                    state, agent, revised_assignment,
                    reflection.guidance,
                )
                match = next(
                    (item for item in revised if finding_key(item) == finding_key(original)), None
                )
                if match is not None:
                    revised_by_key[finding_key(original)] = match
                    self._emit(
                        state, source, self.critic.name, "revision_response",
                        {"finding": match.to_dict(), "resolved": True}, finding_key(original),
                    )
                elif error:
                    self._emit(
                        state, source, self.critic.name, "revision_response",
                        {"resolved": False, "error": error[:500]}, finding_key(original),
                    )
            findings = [revised_by_key.get(finding_key(item), item) for item in findings]
        return {
            "specialist_findings": findings,
            "critiques": critiques,
            "rounds_completed": rounds_completed,
        }

    def _evidence_node(self, state: CollaborationState) -> Dict[str, Any]:
        reproductions = {}
        for finding in state["specialist_findings"]:
            reproduction = self.evidence_agent.reproduce(finding, state["parsed"])
            reproductions[reproduction.finding_key] = reproduction
            self._emit(
                state, self.evidence_agent.name, self.verifier.name, "evidence_report",
                asdict(reproduction), reproduction.finding_key,
            )
        return {"reproductions": reproductions}

    def _verify_node(self, state: CollaborationState) -> Dict[str, Any]:
        fix_ready = {}
        decisions = {}
        for finding in state["specialist_findings"]:
            key = finding_key(finding)
            ready = self.fix_agent.assess(finding)
            fix_ready[key] = ready
            decision = self.verifier.verify(
                finding, state["critiques"][key], state["reproductions"][key], ready,
            )
            decisions[key] = decision
            self._emit(
                state, self.verifier.name, self.arbiter.name, "verification_decision",
                asdict(decision), key,
            )
        return {"fix_ready": fix_ready, "decisions": decisions}

    def _arbitrate_node(self, state: CollaborationState) -> Dict[str, Any]:
        verified = self.arbiter.decide(
            state["specialist_findings"], state["decisions"]
        )
        rejected = [
            {"finding_key": key, "reasons": decision.reasons}
            for key, decision in state["decisions"].items() if not decision.approved
        ]
        self._emit(
            state, self.arbiter.name, "review-report", "arbitration_decision",
            {
                "approved_findings": [item.to_dict() for item in verified],
                "rejected_findings": rejected,
            },
        )
        if self.memory_manager and state.get("repository"):
            approved_keys = {finding_key(item) for item in verified}
            for finding in state["specialist_findings"]:
                key = finding_key(finding)
                decision = state["decisions"][key]
                self.memory_manager.remember_finding(
                    state.get("tenant_id", "default"), state["repository"],
                    state.get("task_id", ""), finding.to_dict(),
                    key in approved_keys, decision.reasons,
                )
            if state.get("task_id"):
                outcomes = state.get("agent_outcomes", [])
                memory_summary = {
                    "proposed_findings": len(state.get("specialist_findings", [])),
                    "approved_findings": len(verified),
                    "rejected_findings": len(rejected),
                    "dialogue_rounds": state.get("rounds_completed", 0),
                    "agent_loop_steps": sum(
                        int((item.get("execution") or {}).get("loop_steps", 0))
                        for item in outcomes
                    ),
                    "tool_calls": sum(
                        int((item.get("execution") or {}).get("tool_calls", 0))
                        for item in outcomes
                    ),
                }
                archived = self.memory_manager.consolidate_task(
                    state.get("tenant_id", "default"), state["repository"],
                    state["task_id"], memory_summary,
                )
                self._emit(
                    state, "memory-manager", "agent-runtime", "memory_consolidated",
                    {
                        "task_id": state["task_id"],
                        "summary_memory_id": (archived or {}).get("id", ""),
                        "working_memory_released": True,
                    },
                )
        return {"verified": verified}

    def _make_summary(self, state: CollaborationState) -> dict:
        outcomes = state.get("agent_outcomes", [])
        decisions = state.get("decisions", {})
        return {
            "protocol": "plan-challenge-revise-evidence-verify-arbitrate",
            "roles": [
                self.planner.name, "specialists", self.critic.name,
                self.reflection_agent.name,
                self.evidence_agent.name, self.verifier.name, self.arbiter.name,
            ],
            "planned_assignments": len(state.get("plan").assignments) if state.get("plan") else 0,
            "dialogue_rounds": state.get("rounds_completed", 0),
            "messages": self._bus(state).count(),
            "retries": self._bus(state).count("retry_request"),
            "handoffs": self._bus(state).count("assignment_handoff"),
            "agents": [
                {
                    "agent": item["agent"], "status": item["status"],
                    "attempts": item["attempts"],
                    "substituted_for": item.get("substituted_for", ""),
                    "loop_steps": (item.get("execution") or {}).get("loop_steps", 0),
                    "loop_stop_reason": (
                        item.get("execution") or {}
                    ).get("loop_stop_reason", "one-shot"),
                    "context_compressed": bool(
                        ((item.get("execution") or {}).get("context") or {}).get("compressed")
                    ),
                    "memories_recalled": (
                        item.get("execution") or {}
                    ).get("memories_recalled", 0),
                }
                for item in outcomes
            ],
            "agent_loop_steps": sum(
                int((item.get("execution") or {}).get("loop_steps", 0))
                for item in outcomes
            ),
            "context_compressions": sum(
                bool(((item.get("execution") or {}).get("context") or {}).get("compressed"))
                for item in outcomes
            ),
            "memories_recalled": sum(
                int((item.get("execution") or {}).get("memories_recalled", 0))
                for item in outcomes
            ),
            "proposed_findings": len(state.get("specialist_findings", [])),
            "approved_findings": sum(1 for item in decisions.values() if item.approved),
            "rejected_findings": sum(1 for item in decisions.values() if not item.approved),
        }
