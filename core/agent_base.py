"""BaseAgent abstraction with least-privilege enforcement, structured contracts, and bounded async execution."""

from abc import ABC, abstractmethod
import asyncio
import json
import logging
from typing import Any, Callable, Dict, List, Optional, Set

from core.context import InvestigationContext
from core.llm_provider import BaseLLMProvider, ModelConfig, ModelRegistry
from core.schemas import (
    AgentFinding,
    AgentResult,
    AgentRole,
    ConfidenceLevel,
    FindingSeverity,
    FindingStatus,
    InvestigationTask,
    utc_now_iso,
)
from tools.registry import ToolCapability, ToolCatalog

logger = logging.getLogger("FortiGateCore.BaseAgent")


class BaseAgent(ABC):
    """
    Abstract base class for all specialist agents and the orchestrator.
    Enforces:
    - Least-privilege capability scoping (diagnostic agents and orchestrator cannot hold write tools).
    - Structured AgentResult JSON output with explicit unknown/error fallbacks.
    - Correlation-ID trace logging and bounded async execution with timeouts.
    """

    role: AgentRole
    name: str
    allowed_capabilities: Set[ToolCapability]

    def __init__(
        self,
        provider: BaseLLMProvider,
        model_config: Optional[ModelConfig] = None,
        model_registry: Optional[ModelRegistry] = None,
        tool_catalog: Optional[ToolCatalog] = None,
    ):
        # Hard least-privilege invariant: only REMEDIATION role may request write capabilities
        if self.role != AgentRole.REMEDIATION and ToolCapability.REMEDIATION_WRITE in self.allowed_capabilities:
            raise PermissionError(
                f"Least-privilege violation: agent '{self.name}' (role={self.role.value}) "
                "cannot be granted REMEDIATION_WRITE capability."
            )

        self.provider = provider
        registry = model_registry or ModelRegistry()
        self.model_config = model_config or registry.get_model_config(self.role)
        self.tool_catalog = tool_catalog or ToolCatalog.default()

    @abstractmethod
    def build_system_instruction(self, context: InvestigationContext) -> str:
        """Returns the role-specific system instruction including prompt-injection guardrails."""

    def get_bound_tools(self, context: InvestigationContext) -> List[Callable[..., Any]]:
        """Binds only the tools permitted for this agent's role and allowed capabilities."""
        return self.tool_catalog.bind_for_role(
            role=self.role,
            capabilities=self.allowed_capabilities,
            context=context,
        )

    def _build_structured_prompt(self, task: InvestigationTask) -> str:
        schema_json = json.dumps(AgentResult.model_json_schema(), indent=2)
        return (
            f"TASK ID: {task.task_id}\n"
            f"CORRELATION ID: {task.correlation_id}\n"
            f"OBJECTIVE: {task.objective}\n"
            f"CONTEXT HINTS: {json.dumps(task.context_hints, default=str)}\n\n"
            "REQUIRED OUTPUT FORMAT:\n"
            "Return ONLY valid JSON matching the AgentResult schema below. "
            "Preserve evidence provenance and explicitly report unknown or unavailable data:\n"
            f"{schema_json}"
        )

    @staticmethod
    def _strip_json_fences(raw_text: str) -> str:
        text = (raw_text or "").strip()
        if text.startswith("```json"):
            return text.split("```json", 1)[1].rsplit("```", 1)[0].strip()
        if text.startswith("```"):
            return text.split("```", 1)[1].rsplit("```", 1)[0].strip()
        return text

    def run(self, task: InvestigationTask, context: InvestigationContext) -> AgentResult:
        """Executes the agent synchronously and returns a validated AgentResult."""
        started_at = utc_now_iso()
        context.record_trace(
            "agent_start",
            {
                "agent": self.name,
                "role": self.role.value,
                "task_id": task.task_id,
                "model": self.model_config.model_id,
                "provider": self.model_config.provider,
            },
        )

        tools = self.get_bound_tools(context)
        system_instruction = self.build_system_instruction(context)
        prompt = self._build_structured_prompt(task)

        try:
            resp = self.provider.generate_with_tools(
                prompt=prompt,
                system_instruction=system_instruction,
                tools=tools,
                model_config=self.model_config,
                role=self.role,
            )
        except Exception as exc:
            logger.error("Agent '%s' provider error: %s", self.name, exc)
            context.record_trace("agent_error", {"agent": self.name, "task_id": task.task_id, "error": str(exc)})
            return AgentResult(
                agent_name=self.name,
                agent_role=self.role,
                task_id=task.task_id,
                correlation_id=task.correlation_id,
                device=context.device,
                vdom=context.vdom,
                status="error",
                summary=f"Provider execution failed for {self.name}.",
                unknowns=[f"Agent '{self.name}' could not complete due to provider error."],
                errors=[str(exc)],
                started_at=started_at,
                completed_at=utc_now_iso(),
            )

        cleaned = self._strip_json_fences(resp.text)
        try:
            result = AgentResult.model_validate_json(cleaned)
            # Authoritative runtime identity fields cannot be spoofed by model output
            result.agent_name = self.name
            result.agent_role = self.role
            result.task_id = task.task_id
            result.correlation_id = task.correlation_id
            result.device = context.device
            result.vdom = context.vdom
            result.tools_executed = result.tools_executed or resp.tools_executed
            result.model_provenance = resp.model_provenance
            result.started_at = started_at
            result.completed_at = utc_now_iso()
        except Exception as parse_exc:
            logger.warning("Agent '%s' returned non-conforming JSON: %s", self.name, parse_exc)
            result = AgentResult(
                agent_name=self.name,
                agent_role=self.role,
                task_id=task.task_id,
                correlation_id=task.correlation_id,
                device=context.device,
                vdom=context.vdom,
                status="partial",
                summary=f"Unstructured output received from {self.name}.",
                findings=[
                    AgentFinding(
                        category=self.role.value,
                        severity=FindingSeverity.INFO,
                        status=FindingStatus.UNKNOWN,
                        confidence=ConfidenceLevel.LOW,
                        summary="Structured schema validation fallback",
                        details=cleaned[:500],
                    )
                ],
                unknowns=["Model output did not strictly conform to AgentResult JSON schema."],
                errors=[f"Schema validation error: {parse_exc}"],
                tools_executed=resp.tools_executed,
                model_provenance=resp.model_provenance,
                started_at=started_at,
                completed_at=utc_now_iso(),
            )

        context.record_trace(
            "agent_complete",
            {
                "agent": self.name,
                "task_id": task.task_id,
                "status": result.status,
                "findings_count": len(result.findings),
            },
        )
        return result

    async def arun(self, task: InvestigationTask, context: InvestigationContext) -> AgentResult:
        """Executes the agent asynchronously with bounded timeout enforcement."""
        started_at = utc_now_iso()
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self.run, task, context),
                timeout=task.timeout_seconds,
            )
        except asyncio.TimeoutError:
            context.record_trace(
                "agent_timeout",
                {"agent": self.name, "task_id": task.task_id, "timeout_seconds": task.timeout_seconds},
            )
            return AgentResult(
                agent_name=self.name,
                agent_role=self.role,
                task_id=task.task_id,
                correlation_id=task.correlation_id,
                device=context.device,
                vdom=context.vdom,
                status="timeout",
                summary=f"Agent '{self.name}' timed out after {task.timeout_seconds}s.",
                unknowns=[f"Timed out after {task.timeout_seconds}s before completing objective."],
                errors=[f"TimeoutError: exceeded {task.timeout_seconds}s"],
                started_at=started_at,
                completed_at=utc_now_iso(),
            )
