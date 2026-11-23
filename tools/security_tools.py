"""Read-only Security domain tools (firewall policies, FortiGuard, VDOMs, deterministic security audit)."""

from typing import Any, Callable, Dict, List

from agent import wrap_untrusted_tool_output
from core.context import InvestigationContext
from security_audit import FortiGateSecurityAuditor
from tools.network_tools import _build_cached_read_tool
from tools.registry import ToolCapability, ToolSpec


def _build_run_security_audit(context: InvestigationContext) -> Callable[[], Dict[str, Any]]:
    def run_security_audit() -> Dict[str, Any]:
        """Run a comprehensive FortiOS Security Posture & CIS Hardening Benchmark Audit."""
        raw = context.get_or_fetch(
            cache_key="run_security_audit",
            fetcher=lambda: FortiGateSecurityAuditor(context.fg_client).run_audit().to_dict(),
        )
        return wrap_untrusted_tool_output("run_security_audit", raw)

    return run_security_audit


def get_security_tool_specs() -> List[ToolSpec]:
    return [
        ToolSpec(
            name="get_firewall_policies",
            capability=ToolCapability.SECURITY_READ,
            is_write=False,
            description="Get configured firewall security policies.",
            builder=lambda ctx: _build_cached_read_tool(
                ctx, "get_firewall_policies", "Get configured firewall security policies.", "get_firewall_policies"
            ),
        ),
        ToolSpec(
            name="get_fortiguard_status",
            capability=ToolCapability.SECURITY_READ,
            is_write=False,
            description="Get FortiGuard security subscription licenses and engine versions.",
            builder=lambda ctx: _build_cached_read_tool(
                ctx, "get_fortiguard_status", "Get FortiGuard subscription licenses and engine status.", "get_fortiguard_status"
            ),
        ),
        ToolSpec(
            name="get_vdom_list",
            capability=ToolCapability.SECURITY_READ,
            is_write=False,
            description="Get configured Virtual Domains (VDOMs).",
            builder=lambda ctx: _build_cached_read_tool(
                ctx, "get_vdom_list", "Get configured Virtual Domains (VDOMs).", "get_vdom_list"
            ),
        ),
        ToolSpec(
            name="run_security_audit",
            capability=ToolCapability.SECURITY_READ,
            is_write=False,
            description="Run deterministic FortiOS security posture and policy shadowing audit.",
            builder=_build_run_security_audit,
        ),
    ]
