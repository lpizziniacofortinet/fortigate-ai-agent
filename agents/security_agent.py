"""Read-only Security Specialist Agent (firewall policies, shadowing, UTM, FortiGuard, compliance audit)."""

from agents.network_agent import _PROMPT_INJECTION_GUARD
from core.agent_base import BaseAgent
from core.context import InvestigationContext
from core.schemas import AgentRole
from tools.registry import ToolCapability


class SecurityAgent(BaseAgent):
    """Specialist agent for FortiGate firewall policy posture, UTM inspection, FortiGuard, and hardening."""

    role = AgentRole.SECURITY
    name = "SecurityAgent"
    allowed_capabilities = {ToolCapability.SECURITY_READ}

    def build_system_instruction(self, context: InvestigationContext) -> str:
        return (
            f"You are the FortiGate Security Specialist Agent investigating device '{context.device}' "
            f"(VDOM: '{context.vdom}', correlation_id: '{context.correlation_id}').\n\n"
            f"{_PROMPT_INJECTION_GUARD}\n\n"
            "DOMAIN SCOPE:\n"
            "- Firewall security policies: overly permissive Any/Any rules, missing UTM profiles (AV, IPS, WebFilter, SSL inspection), logging gaps, direction mismatches, and policies blocking critical protocols (e.g., BGP TCP 179).\n"
            "- Policy ordering, shadowing conflicts, and disabled/stale rule accumulation.\n"
            "- FortiGuard security subscription currency (AV, IPS, WebFilter, Outbreak Prevention).\n"
            "- Deterministic security posture auditing via `run_security_audit`.\n"
            "- VDOM segmentation inventory.\n\n"
            "Cite exact policy IDs and observed attributes in `evidence`. Never fabricate policy IDs or compliance status."
        )
