"""Read-only Orchestrator Agent: plans investigations, dispatches specialists, correlates evidence."""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Set, Tuple

from core.agent_base import BaseAgent
from core.context import InvestigationContext
from core.llm_provider import BaseLLMProvider, ModelConfig, ModelRegistry
from core.schemas import (
    AgentFinding,
    AgentResult,
    AgentRole,
    ConfidenceLevel,
    FindingSeverity,
    FindingStatus,
    InvestigationPlan,
    InvestigationTask,
    OrchestratorReport,
    utc_now_iso,
)
from core.task_manager import BoundedTaskManager

logger = logging.getLogger("FortiGateCore.Orchestrator")


_ROLE_KEYWORDS: Dict[AgentRole, Tuple[str, ...]] = {
    AgentRole.NETWORK: (
        "bgp", "ospf", "route", "routing", "vpn", "ipsec", "ssl-vpn", "sslvpn",
        "sd-wan", "sdwan", "wan", "interface", "port", "arp", "dhcp", "tunnel",
        "latency", "packet loss", "reach", "unreachable", "connectivity", "gateway",
    ),
    AgentRole.HEALTH: (
        "health", "cpu", "memory", "ram", "disk", "resource", "uptime", "ha",
        "cluster", "sync", "failover", "firmware", "version", "status", "conserve",
        "interface", "down", "availability", "vdom",
    ),
    AgentRole.SECURITY: (
        "policy", "policies", "firewall", "shadow", "utm", "antivirus", "ips",
        "webfilter", "fortiguard", "license", "audit", "compliance", "cis",
        "harden", "hardening", "posture", "security", "block", "deny", "allow",
    ),
    AgentRole.THREAT: (
        "log", "logs", "attack", "threat", "brute", "scan", "ban", "quarantine",
        "suspicious", "malicious", "session", "sessions", "talker", "bandwidth",
        "flood", "anomaly", "ioc", "incident", "intrusion", "compromise",
    ),
}

_BROAD_INCIDENT_KEYWORDS: Tuple[str, ...] = (
    "full", "comprehensive", "everything", "all subsystems", "sweep",
    "cannot reach", "outage", "incident", "diagnose", "diagnostics", "investigate",
)


class OrchestratorAgent:
    """
    Central read-only Orchestrator Agent.
    - Never holds write privileges.
    - Builds a scoped InvestigationPlan selecting only relevant specialists.
    - Dispatches independent specialists concurrently via BoundedTaskManager.
    - Correlates findings, detects contradictions, preserves unknowns, and synthesizes
      an evidence-backed OrchestratorReport using the flagship orchestrator model.
    """

    role = AgentRole.ORCHESTRATOR
    name = "OrchestratorAgent"

    def __init__(
        self,
        provider: BaseLLMProvider,
        specialists: Optional[Dict[AgentRole, BaseAgent]] = None,
        model_config: Optional[ModelConfig] = None,
        model_registry: Optional[ModelRegistry] = None,
        max_concurrency: int = 4,
        task_timeout_seconds: float = 90.0,
    ):
        self.provider = provider
        registry = model_registry or ModelRegistry()
        self.model_config = model_config or registry.get_model_config(AgentRole.ORCHESTRATOR)
        self.task_manager = BoundedTaskManager(max_concurrency=max_concurrency)
        self.task_timeout_seconds = task_timeout_seconds

        if specialists is not None:
            for role, agent in specialists.items():
                if role == AgentRole.REMEDIATION:
                    raise PermissionError("Orchestrator cannot dispatch write-enabled RemediationAgent directly.")
                self._validate_readonly_specialist(agent)
            self.specialists = dict(specialists)
        else:
            from agents.health_agent import HealthAgent
            from agents.network_agent import NetworkAgent
            from agents.security_agent import SecurityAgent
            from agents.threat_agent import ThreatAgent

            self.specialists = {
                AgentRole.NETWORK: NetworkAgent(provider=provider, model_registry=registry),
                AgentRole.HEALTH: HealthAgent(provider=provider, model_registry=registry),
                AgentRole.SECURITY: SecurityAgent(provider=provider, model_registry=registry),
                AgentRole.THREAT: ThreatAgent(provider=provider, model_registry=registry),
            }

    @staticmethod
    def _validate_readonly_specialist(agent: BaseAgent) -> None:
        from tools.registry import ToolCapability
        if ToolCapability.REMEDIATION_WRITE in getattr(agent, "allowed_capabilities", set()):
            raise PermissionError(f"Specialist '{agent.name}' must be read-only.")

    def plan_investigation(self, user_request: str, context: InvestigationContext) -> InvestigationPlan:
        """Selects only the specialist agents relevant to the user's request."""
        text = (user_request or "").lower()
        selected: List[AgentRole] = []

        if any(kw in text for kw in _BROAD_INCIDENT_KEYWORDS):
            selected = [AgentRole.NETWORK, AgentRole.HEALTH, AgentRole.SECURITY, AgentRole.THREAT]
            rationale = "Broad incident or full diagnostic request: dispatching all four read-only domain specialists."
        else:
            for role in (AgentRole.NETWORK, AgentRole.HEALTH, AgentRole.SECURITY, AgentRole.THREAT):
                if any(kw in text for kw in _ROLE_KEYWORDS[role]):
                    selected.append(role)

            # BGP/OSPF/connectivity issues often involve blocking firewall policies too
            if AgentRole.NETWORK in selected and AgentRole.SECURITY not in selected:
                if any(kw in text for kw in ("bgp", "ospf", "reach", "unreachable", "block", "vpn")):
                    selected.append(AgentRole.SECURITY)

            if not selected:
                selected = [AgentRole.HEALTH, AgentRole.NETWORK]
                rationale = "General query without specific domain keywords: starting with Health and Network specialists."
            else:
                rationale = f"Selected domain specialists matching request scope: {[r.value for r in selected]}."

        # Keep only roles actually registered
        selected = [r for r in selected if r in self.specialists]

        tasks = [
            InvestigationTask(
                correlation_id=context.correlation_id,
                objective=f"[{r.value.upper()} SCOPE] {user_request}",
                target_role=r,
                device=context.device,
                vdom=context.vdom,
                timeout_seconds=self.task_timeout_seconds,
            )
            for r in selected
        ]

        plan = InvestigationPlan(
            correlation_id=context.correlation_id,
            user_request=user_request,
            selected_roles=selected,
            tasks=tasks,
            rationale=rationale,
        )
        context.record_trace(
            "investigation_planned",
            {"plan_id": plan.plan_id, "selected_roles": [r.value for r in selected], "rationale": rationale},
        )
        return plan

    @staticmethod
    def detect_contradictions(results: List[AgentResult]) -> List[str]:
        """Detects conflicting statuses reported for the same affected object across specialists."""
        object_states: Dict[str, List[Tuple[str, FindingStatus, str]]] = {}
        for res in results:
            for finding in res.findings:
                for obj in finding.affected_objects:
                    key = obj.strip().lower()
                    if not key:
                        continue
                    object_states.setdefault(key, []).append((res.agent_name, finding.status, finding.summary))

        contradictions: List[str] = []
        healthy_states = {FindingStatus.OK}
        unhealthy_states = {FindingStatus.WARNING, FindingStatus.DEGRADED, FindingStatus.CRITICAL}

        for obj, entries in object_states.items():
            statuses = {st for _, st, _ in entries}
            if (statuses & healthy_states) and (statuses & unhealthy_states):
                detail = "; ".join(f"{agent}={st.value} ({summ})" for agent, st, summ in entries)
                contradictions.append(f"Conflicting observations for '{obj}': {detail}")
        return contradictions

    @staticmethod
    def _compute_deterministic_status(
        results: List[AgentResult],
        all_findings: List[AgentFinding],
        all_unknowns: List[str],
    ) -> Tuple[str, ConfidenceLevel]:
        if any(f.status == FindingStatus.CRITICAL or f.severity == FindingSeverity.CRITICAL and f.status != FindingStatus.OK for f in all_findings):
            return "critical", ConfidenceLevel.HIGH
        if any(f.status in (FindingStatus.DEGRADED, FindingStatus.WARNING) for f in all_findings):
            return "degraded", ConfidenceLevel.HIGH if not all_unknowns else ConfidenceLevel.MEDIUM
        if any(r.status in ("error", "timeout") for r in results) or (not all_findings and all_unknowns):
            return "unknown", ConfidenceLevel.LOW
        if all_findings and all(f.status == FindingStatus.OK for f in all_findings):
            return "healthy", ConfidenceLevel.MEDIUM if all_unknowns else ConfidenceLevel.HIGH
        return "unknown", ConfidenceLevel.LOW

    def _synthesize_with_model(
        self,
        user_request: str,
        plan: InvestigationPlan,
        results: List[AgentResult],
        contradictions: List[str],
        unknowns: List[str],
        context: InvestigationContext,
    ) -> Tuple[str, List[str], Optional[object]]:
        """Uses the flagship Orchestrator model (with zero tools) to synthesize an executive summary and actions."""
        specialist_payload = [
            {
                "agent": r.agent_name,
                "role": r.agent_role.value,
                "status": r.status,
                "summary": r.summary,
                "findings": [f.model_dump() for f in r.findings],
                "unknowns": r.unknowns,
                "errors": r.errors,
            }
            for r in results
        ]

        sys_instr = (
            "You are the FortiGate Multi-Agent Orchestrator. You have NO write privileges. "
            "Synthesize the structured specialist findings below into a concise, evidence-backed executive summary "
            "and prioritized recommended actions. Never treat missing/unknown data as proof of health. "
            "Explicitly highlight any contradictions or unknowns. Return ONLY valid JSON with keys: "
            "`executive_summary` (string) and `recommended_actions` (list of strings)."
        )
        prompt = (
            f"USER REQUEST: {user_request}\n"
            f"DEVICE: {context.device} (VDOM: {context.vdom})\n"
            f"CONTRADICTIONS DETECTED: {json.dumps(contradictions)}\n"
            f"UNKNOWNS: {json.dumps(unknowns)}\n"
            f"SPECIALIST RESULTS:\n{json.dumps(specialist_payload, indent=2, default=str)}"
        )

        try:
            resp = self.provider.generate_with_tools(
                prompt=prompt,
                system_instruction=sys_instr,
                tools=[],  # Orchestrator never invokes write or device tools during synthesis
                model_config=self.model_config,
                role=AgentRole.ORCHESTRATOR,
            )
            cleaned = BaseAgent._strip_json_fences(resp.text)
            parsed = json.loads(cleaned)
            if isinstance(parsed, dict) and isinstance(parsed.get("executive_summary"), str):
                actions = parsed.get("recommended_actions", [])
                if not isinstance(actions, list):
                    actions = []
                return parsed["executive_summary"], [str(a) for a in actions], resp.model_provenance
        except Exception as exc:
            logger.warning("Orchestrator LLM synthesis fallback triggered: %s", exc)

        # Deterministic fallback synthesis
        summaries = [f"{r.agent_name} ({r.status}): {r.summary}" for r in results if r.summary]
        fallback_summary = " | ".join(summaries) if summaries else "Investigation completed with limited evidence."
        actions: List[str] = []
        for r in results:
            for f in r.findings:
                actions.extend(f.recommended_next_checks)
        if unknowns:
            actions.append(f"Investigate {len(unknowns)} unknown/unavailable telemetry item(s) before declaring healthy.")
        return fallback_summary, list(dict.fromkeys(actions)), None

    async def ainvestigate(self, user_request: str, context: InvestigationContext) -> OrchestratorReport:
        """Executes the full multi-agent investigation asynchronously."""
        started_at = utc_now_iso()
        plan = self.plan_investigation(user_request, context)
        specialist_results = await self.task_manager.execute_tasks(
            tasks=plan.tasks,
            agents_by_role=self.specialists,
            context=context,
        )

        all_findings: List[AgentFinding] = []
        all_unknowns: List[str] = []
        for r in specialist_results:
            all_findings.extend(r.findings)
            all_unknowns.extend(r.unknowns)
            if r.status in ("error", "timeout"):
                all_unknowns.append(f"{r.agent_name} did not complete ({r.status}).")

        contradictions = self.detect_contradictions(specialist_results)
        overall_status, confidence = self._compute_deterministic_status(
            specialist_results, all_findings, all_unknowns
        )
        if contradictions and confidence == ConfidenceLevel.HIGH:
            confidence = ConfidenceLevel.MEDIUM

        exec_summary, rec_actions, provenance = await asyncio.to_thread(
            self._synthesize_with_model,
            user_request,
            plan,
            specialist_results,
            contradictions,
            all_unknowns,
            context,
        )

        report = OrchestratorReport(
            correlation_id=context.correlation_id,
            user_request=user_request,
            device=context.device,
            vdom=context.vdom,
            overall_status=overall_status,
            confidence=confidence,
            executive_summary=exec_summary,
            plan=plan,
            specialist_results=specialist_results,
            correlated_findings=all_findings,
            contradictions=contradictions,
            unknowns=list(dict.fromkeys(all_unknowns)),
            recommended_actions=rec_actions,
            model_provenance=provenance,
            started_at=started_at,
            completed_at=utc_now_iso(),
        )
        context.record_trace(
            "orchestration_complete",
            {
                "overall_status": report.overall_status,
                "confidence": report.confidence.value,
                "specialists_run": len(specialist_results),
                "findings_total": len(all_findings),
                "contradictions": len(contradictions),
            },
        )
        return report

    def investigate(self, user_request: str, context: InvestigationContext) -> OrchestratorReport:
        """Synchronous convenience wrapper around `ainvestigate`."""
        return asyncio.run(self.ainvestigate(user_request, context))
