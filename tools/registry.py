"""Tool capability registry enforcing least-privilege access across specialist agents."""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Set

from core.context import InvestigationContext
from core.schemas import AgentRole


class ToolCapability(str, Enum):
    NETWORK_READ = "network_read"
    SECURITY_READ = "security_read"
    THREAT_READ = "threat_read"
    HEALTH_READ = "health_read"
    BACKUP_READ = "backup_read"
    REMEDIATION_WRITE = "remediation_write"


@dataclass(frozen=True)
class ToolSpec:
    """Declarative specification for a bindable FortiGate tool."""
    name: str
    capability: ToolCapability
    is_write: bool
    description: str
    builder: Callable[[InvestigationContext], Callable[..., Any]]


class ToolCatalog:
    """
    Central capability-based registry of FortiGate tools.
    Reuses existing FortiGateClient methods while enforcing strict least-privilege
    binding per AgentRole and per-investigation context isolation (no global client).
    """

    def __init__(self, specs: List[ToolSpec]):
        self._specs: List[ToolSpec] = list(specs)

    @classmethod
    def default(cls) -> "ToolCatalog":
        from tools.network_tools import get_network_tool_specs
        from tools.security_tools import get_security_tool_specs
        from tools.threat_tools import get_threat_tool_specs
        from tools.health_tools import get_health_tool_specs
        from tools.remediation_tools import get_remediation_tool_specs

        specs: List[ToolSpec] = []
        specs.extend(get_network_tool_specs())
        specs.extend(get_security_tool_specs())
        specs.extend(get_threat_tool_specs())
        specs.extend(get_health_tool_specs())
        specs.extend(get_remediation_tool_specs())
        return cls(specs)

    def list_specs(self, capabilities: Set[ToolCapability]) -> List[ToolSpec]:
        seen = set()
        matched: List[ToolSpec] = []
        for spec in self._specs:
            if spec.capability in capabilities and spec.name not in seen:
                seen.add(spec.name)
                matched.append(spec)
        return matched

    def bind_for_role(
        self,
        role: AgentRole,
        capabilities: Set[ToolCapability],
        context: InvestigationContext,
    ) -> List[Callable[..., Any]]:
        """
        Binds and returns callables permitted for `role` and `capabilities`.
        Raises PermissionError if any non-remediation role requests write tools.
        """
        if role != AgentRole.REMEDIATION and ToolCapability.REMEDIATION_WRITE in capabilities:
            raise PermissionError(
                f"Least-privilege violation: role '{role.value}' is not permitted to bind REMEDIATION_WRITE tools."
            )

        bound: List[Callable[..., Any]] = []
        seen_names: Set[str] = set()
        for spec in self._specs:
            if spec.capability not in capabilities:
                continue
            if spec.is_write and role != AgentRole.REMEDIATION:
                continue
            if spec.name in seen_names:
                continue
            seen_names.add(spec.name)
            bound.append(spec.builder(context))
        return bound
