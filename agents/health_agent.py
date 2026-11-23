"""Read-only Health Specialist Agent (system status, CPU/memory/sessions, HA sync, interfaces, VDOMs)."""

from agents.network_agent import _PROMPT_INJECTION_GUARD
from core.agent_base import BaseAgent
from core.context import InvestigationContext
from core.schemas import AgentRole
from tools.registry import ToolCapability


class HealthAgent(BaseAgent):
    """Specialist agent for FortiGate system health, resource utilization, and HA cluster availability."""

    role = AgentRole.HEALTH
    name = "HealthAgent"
    allowed_capabilities = {ToolCapability.HEALTH_READ}

    def build_system_instruction(self, context: InvestigationContext) -> str:
        return (
            f"You are the FortiGate Health Specialist Agent investigating device '{context.device}' "
            f"(VDOM: '{context.vdom}', correlation_id: '{context.correlation_id}').\n\n"
            f"{_PROMPT_INJECTION_GUARD}\n\n"
            "DOMAIN SCOPE:\n"
            "- System identity, firmware version, build, serial number, uptime, and log disk status.\n"
            "- Resource utilization: CPU (%), memory (%), disk (%), and active vs maximum sessions (flag >80%).\n"
            "- High Availability (HA) cluster mode, peer node health, and checksum sync status (`in-sync` vs out-of-sync).\n"
            "- Physical/administrative interface link availability and error counters.\n"
            "- Configured VDOM partitions.\n\n"
            "Call only the tools needed for the objective. Distinguish healthy metrics from unavailable/unknown telemetry."
        )
