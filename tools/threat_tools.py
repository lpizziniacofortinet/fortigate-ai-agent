"""Read-only Threat domain tools (logs, top sessions, quarantined IPs)."""

from typing import Any, Callable, Dict, List

from agent import wrap_untrusted_tool_output
from core.context import InvestigationContext
from tools.network_tools import _build_cached_read_tool
from tools.registry import ToolCapability, ToolSpec


def _build_get_system_logs(context: InvestigationContext) -> Callable[..., Dict[str, Any]]:
    def get_system_logs(log_type: str = "event", limit: int = 15) -> Dict[str, Any]:
        """Get recent system/event/traffic/security logs from the FortiGate."""
        raw = context.get_or_fetch(
            cache_key="get_system_logs",
            cache_scope=f"{log_type}:{limit}",
            fetcher=lambda: context.fg_client.get_system_logs(log_type=log_type, limit=limit),
        )
        return wrap_untrusted_tool_output("get_system_logs", raw)

    return get_system_logs


def _build_get_top_sessions(context: InvestigationContext) -> Callable[..., Dict[str, Any]]:
    def get_top_sessions(limit: int = 10, sort_by: str = "bytes") -> Dict[str, Any]:
        """Get active firewall sessions sorted by bytes, packets, or duration."""
        raw = context.get_or_fetch(
            cache_key="get_top_sessions",
            cache_scope=f"{limit}:{sort_by}",
            fetcher=lambda: context.fg_client.get_top_sessions(limit=limit, sort_by=sort_by),
        )
        return wrap_untrusted_tool_output("get_top_sessions", raw)

    return get_top_sessions


def get_threat_tool_specs() -> List[ToolSpec]:
    return [
        ToolSpec(
            name="get_system_logs",
            capability=ToolCapability.THREAT_READ,
            is_write=False,
            description="Get recent system, event, traffic, or security logs.",
            builder=_build_get_system_logs,
        ),
        ToolSpec(
            name="get_top_sessions",
            capability=ToolCapability.THREAT_READ,
            is_write=False,
            description="Get active network sessions sorted by bandwidth, packets, or duration.",
            builder=_build_get_top_sessions,
        ),
        ToolSpec(
            name="get_quarantined_ips",
            capability=ToolCapability.THREAT_READ,
            is_write=False,
            description="Get currently quarantined/banned IP addresses.",
            builder=lambda ctx: _build_cached_read_tool(
                ctx, "get_quarantined_ips", "Get currently banned/quarantined IP addresses.", "get_quarantined_ips"
            ),
        ),
    ]
