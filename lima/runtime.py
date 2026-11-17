"""LIMA's dependency-free durable runtime and bounded agent loop.

The runtime deliberately separates orchestration from agent behaviour:

* ``AgentRuntime`` executes named nodes with budgets, retry policy, cancellation
  checks and application-owned checkpoints.
* ``AgentLoop`` executes model-selected tool actions until the agent returns a
  final result or its step/time budget is exhausted.

Both components are deterministic around side effects.  Persistence remains in
the application store so a worker restart does not depend on a framework-owned
checkpoint format.
"""
from contextlib import nullcontext
from dataclasses import dataclass, field
import json
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


class RuntimeBudgetExceeded(RuntimeError):
    """The configured step or wall-clock budget was exhausted."""


class RuntimeCancelled(RuntimeError):
    """The owning task requested cancellation."""


class AgentLoopProtocolError(RuntimeError):
    """An agent returned an invalid loop action."""


@dataclass(frozen=True)
class AgentTool:
    name: str
    description: str
    parameters: Dict[str, Any]
    handler: Callable[..., Any]

    def catalog_entry(self) -> Dict[str, Any]:
        return {
            "name": self.name, "description": self.description,
            "parameters": self.parameters,
        }


class ToolRegistry:
    """Explicit tool catalog with JSON-schema-like argument validation."""

    def __init__(self, tools: Iterable[AgentTool] = ()):
        self._tools: Dict[str, AgentTool] = {}
        for tool in tools:
            self.register(tool)

    def register(self, tool: AgentTool) -> None:
        if not tool.name or tool.name in self._tools:
            raise ValueError("tool names must be non-empty and unique")
        self._tools[tool.name] = tool

    def names(self) -> List[str]:
        return sorted(self._tools)

    def catalog(self) -> List[Dict[str, Any]]:
        return [self._tools[name].catalog_entry() for name in self.names()]

    def invoke(self, name: str, arguments: Dict[str, Any]) -> Any:
        tool = self._tools.get(name)
        if tool is None:
            raise AgentLoopProtocolError("unknown agent tool: %s" % name)
        self._validate(tool.parameters, arguments)
        return tool.handler(**arguments)

    @staticmethod
    def _validate(schema: Dict[str, Any], arguments: Dict[str, Any]) -> None:
        if not isinstance(arguments, dict):
            raise AgentLoopProtocolError("tool arguments must be an object")
        properties = dict(schema.get("properties") or {})
        required = set(schema.get("required") or [])
        missing = required.difference(arguments)
        if missing:
            raise AgentLoopProtocolError(
                "missing required tool arguments: %s" % ", ".join(sorted(missing))
            )
        if schema.get("additionalProperties", False) is False:
            unknown = set(arguments).difference(properties)
            if unknown:
                raise AgentLoopProtocolError(
                    "unknown tool arguments: %s" % ", ".join(sorted(unknown))
                )
        expected_types = {
            "string": str, "integer": int, "number": (int, float),
            "boolean": bool, "object": dict, "array": list,
        }
        for key, value in arguments.items():
            spec = properties.get(key) or {}
            expected = expected_types.get(spec.get("type"))
            if expected and (not isinstance(value, expected) or (
                spec.get("type") in {"integer", "number"} and isinstance(value, bool)
            )):
                raise AgentLoopProtocolError(
                    "tool argument %s must be %s" % (key, spec.get("type"))
                )
            if isinstance(value, (int, float)):
                if "minimum" in spec and value < spec["minimum"]:
                    raise AgentLoopProtocolError("tool argument %s is below minimum" % key)
                if "maximum" in spec and value > spec["maximum"]:
                    raise AgentLoopProtocolError("tool argument %s exceeds maximum" % key)


@dataclass(frozen=True)
class RuntimeNode:
    name: str
    handler: Callable[[Dict[str, Any]], Dict[str, Any]]
    retries: Optional[int] = None
    checkpoint: bool = True


@dataclass(frozen=True)
class RuntimeEvent:
    kind: str
    node: str
    step: int
    attempt: int = 0
    detail: Dict[str, Any] = field(default_factory=dict)


class AgentRuntime:
    """Execute a bounded node graph without a third-party orchestration engine."""

    def __init__(
        self, max_steps: int = 8, timeout_seconds: int = 120,
        node_retries: int = 0,
    ):
        if max_steps < 1:
            raise ValueError("runtime max_steps must be at least 1")
        if timeout_seconds < 1:
            raise ValueError("runtime timeout_seconds must be at least 1")
        if node_retries < 0:
            raise ValueError("runtime node_retries cannot be negative")
        self.max_steps = max_steps
        self.timeout_seconds = timeout_seconds
        self.node_retries = node_retries

    def execute(
        self, initial_state: Dict[str, Any], nodes: Iterable[RuntimeNode],
        task_id: str = "", checkpoint_store=None,
        cancel_check: Optional[Callable[[], bool]] = None,
        event_sink: Optional[Callable[[RuntimeEvent], None]] = None,
        span_factory: Optional[Callable[[str, Dict[str, Any]], Any]] = None,
        non_retryable: Tuple[type, ...] = (ValueError, RuntimeCancelled, RuntimeBudgetExceeded),
    ) -> Dict[str, Any]:
        state = dict(initial_state)
        started = time.monotonic()
        steps = 0
        checkpoints = (
            checkpoint_store.load_checkpoints(task_id)
            if checkpoint_store is not None and task_id else {}
        )

        def emit(kind: str, node: str, attempt: int = 0, **detail) -> None:
            if event_sink:
                event_sink(RuntimeEvent(kind, node, steps, attempt, detail))

        def guard(node: str) -> None:
            if cancel_check and cancel_check():
                emit("cancelled", node)
                raise RuntimeCancelled("Task was cancelled")
            if steps >= self.max_steps or time.monotonic() - started > self.timeout_seconds:
                emit("budget_exhausted", node)
                raise RuntimeBudgetExceeded("task execution budget exceeded")

        for node in nodes:
            cached = checkpoints.get(node.name) if node.checkpoint else None
            if cached and cached.get("status") == "completed":
                output = dict(cached.get("state") or {})
                state.update(output)
                emit("checkpoint_restored", node.name, int(cached.get("attempt", 0)))
                continue

            retries = self.node_retries if node.retries is None else node.retries
            previous_attempt = int((cached or {}).get("attempt", 0))
            last_error: Optional[Exception] = None
            for offset in range(1, retries + 2):
                guard(node.name)
                steps += 1
                attempt = previous_attempt + offset
                emit("node_started", node.name, attempt)
                try:
                    attrs = {
                        "task_id": task_id, "node": node.name,
                        "attempt": attempt, "runtime_step": steps,
                    }
                    context = (
                        span_factory("runtime.%s" % node.name, attrs)
                        if span_factory else nullcontext()
                    )
                    with context:
                        output = node.handler(state) or {}
                    if not isinstance(output, dict):
                        raise TypeError("runtime node %s must return a dict" % node.name)
                    state.update(output)
                    if checkpoint_store is not None and task_id and node.checkpoint:
                        checkpoint_store.save_checkpoint(
                            task_id, node.name, output, "completed", attempt
                        )
                    emit("node_completed", node.name, attempt, output_keys=sorted(output))
                    last_error = None
                    break
                except non_retryable:
                    raise
                except Exception as exc:
                    last_error = exc
                    if checkpoint_store is not None and task_id and node.checkpoint:
                        checkpoint_store.save_checkpoint(
                            task_id, node.name, {}, "failed", attempt, str(exc)
                        )
                    emit(
                        "node_failed", node.name, attempt,
                        error=str(exc)[:1000], will_retry=offset <= retries,
                    )
            if last_error is not None:
                raise last_error
        return state


@dataclass
class AgentLoopResult:
    output: Any
    steps: int
    observations: List[Dict[str, Any]]
    stop_reason: str
    # Raw values stay available to the application even when the model-facing
    # observation is projected or truncated.
    tool_results: List[Any] = field(default_factory=list)


class AgentLoop:
    """Run a model/tool loop with strict action, time and observation budgets."""

    def __init__(
        self, max_steps: int = 4, timeout_seconds: int = 45,
        max_observation_chars: int = 4000,
    ):
        if max_steps < 1:
            raise ValueError("agent loop max_steps must be at least 1")
        if timeout_seconds < 1:
            raise ValueError("agent loop timeout_seconds must be at least 1")
        self.max_steps = max_steps
        self.timeout_seconds = timeout_seconds
        self.max_observation_chars = max(256, max_observation_chars)

    def run(
        self, stepper: Callable[[Dict[str, Any]], Dict[str, Any]],
        tools: Any, initial_state: Dict[str, Any],
        event_sink: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        *,
        cancel_check: Optional[Callable[[], bool]] = None,
        fatal_exceptions: Tuple[type, ...] = (),
        result_projector: Optional[Callable[[Any], Any]] = None,
    ) -> AgentLoopResult:
        if not isinstance(fatal_exceptions, tuple) or any(
            not isinstance(exc_type, type) or not issubclass(exc_type, BaseException)
            for exc_type in fatal_exceptions
        ):
            raise ValueError("fatal_exceptions must be a tuple of exception types")
        state = dict(initial_state)
        observations = list(state.get("observations") or [])
        tool_results: List[Any] = []
        started = time.monotonic()

        def emit(kind: str, **detail) -> None:
            if event_sink:
                event_sink(kind, detail)

        def guard(step: int, phase: str) -> None:
            if cancel_check and cancel_check():
                emit("agent_loop_cancelled", step=step, phase=phase)
                raise RuntimeCancelled("agent loop was cancelled")
            if time.monotonic() - started > self.timeout_seconds:
                emit("agent_loop_budget_exhausted", step=step, budget="time")
                raise RuntimeBudgetExceeded("agent loop time budget exceeded")

        # Cancellation is opt-in to preserve the historic treatment of tool
        # exceptions.  Once enabled, RuntimeCancelled is never converted into
        # an ordinary tool observation.
        fatal_types = fatal_exceptions + ((RuntimeCancelled,) if cancel_check else ())

        for step in range(1, self.max_steps + 1):
            guard(step, "before_stepper")
            state["loop_step"] = step
            state["observations"] = list(observations)
            action = stepper(state)
            # A slow model response cannot authorize a subsequent tool side
            # effect after the loop deadline has elapsed.
            guard(step, "after_stepper")
            if not isinstance(action, dict):
                raise AgentLoopProtocolError("agent loop action must be an object")
            kind = str(action.get("action", "")).strip().lower()
            emit("agent_loop_action", step=step, action=kind)
            if kind == "final":
                return AgentLoopResult(
                    action.get("findings", action.get("output")), step,
                    observations, "final", tool_results,
                )
            if kind != "tool":
                raise AgentLoopProtocolError("unsupported agent loop action: %s" % kind)
            tool_name = str(action.get("tool", "")).strip()
            arguments = action.get("arguments") or {}
            if not isinstance(arguments, dict):
                raise AgentLoopProtocolError("tool arguments must be an object")
            try:
                guard(step, "before_tool")
                if isinstance(tools, ToolRegistry):
                    value = tools.invoke(tool_name, arguments)
                else:
                    tool = tools.get(tool_name)
                    if tool is None:
                        raise AgentLoopProtocolError("unknown agent tool: %s" % tool_name)
                    value = tool(**arguments)
                tool_results.append(value)
                guard(step, "after_tool")
                projected = result_projector(value) if result_projector else value
                rendered = (
                    json.dumps(projected, ensure_ascii=False, sort_keys=True)
                    if isinstance(projected, (dict, list, tuple)) else str(projected)
                )
                observation = {
                    "step": step, "tool": tool_name, "ok": True,
                    "result": rendered[:self.max_observation_chars],
                    "truncated": len(rendered) > self.max_observation_chars,
                }
            except fatal_types:
                raise
            except Exception as exc:
                error = str(exc)
                observation = {
                    "step": step, "tool": tool_name, "ok": False,
                    "error": error[:1000],
                    "truncated": len(error) > 1000,
                }
            observations.append(observation)
            emit("agent_loop_observation", **observation)
        emit("agent_loop_budget_exhausted", step=self.max_steps, budget="steps")
        raise RuntimeBudgetExceeded("agent loop step budget exceeded")
