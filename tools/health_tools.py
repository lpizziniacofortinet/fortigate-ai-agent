"""Read-only Health domain tools (system status, resources, HA state, interfaces, VDOMs)."""

from typing import List

from tools.network_tools import _build_cached_read_tool
from tools.registry import ToolCapability, ToolSpec


def get_health_tool_specs() -> List[ToolSpec]:
    return [
        ToolSpec(
            name="get_system_status",
            capability=ToolCapability.HEALTH_READ,
            is_write=False,
            description="Get basic FortiGate system status (hostname, firmware, serial, uptime).",
            builder=lambda ctx: _build_cached_read_tool(
                ctx, "get_system_status", "Get basic FortiGate system status.", "get_system_status"
            ),
        ),
        ToolSpec(
            name="get_system_resources",
            capability=ToolCapability.HEALTH_READ,
            is_write=False,
            description="Get CPU, memory, disk, and session resource utilization metrics.",
            builder=lambda ctx: _build_cached_read_tool(
                ctx, "get_system_resources", "Get CPU, memory, disk, and session utilization.", "get_system_resources"
            ),
        ),
        ToolSpec(
            name="get_ha_status",
            capability=ToolCapability.HEALTH_READ,
            is_write=False,
            description="Get High Availability (HA) cluster sync status and member health.",
            builder=lambda ctx: _build_cached_read_tool(
                ctx, "get_ha_status", "Get High Availability cluster status and checksum sync.", "get_ha_status"
            ),
        ),
        ToolSpec(
            name="get_interfaces",
            capability=ToolCapability.HEALTH_READ,
            is_write=False,
            description="Get status, IP configurations, and traffic statistics for all network interfaces.",
            builder=lambda ctx: _build_cached_read_tool(
                ctx, "get_interfaces", "Get status, IP configs, and traffic stats for all interfaces.", "get_interfaces"
            ),
        ),
        ToolSpec(
            name="get_vdom_list",
            capability=ToolCapability.HEALTH_READ,
            is_write=False,
            description="Get configured Virtual Domains (VDOMs).",
            builder=lambda ctx: _build_cached_read_tool(
                ctx, "get_vdom_list", "Get configured Virtual Domains (VDOMs).", "get_vdom_list"
            ),
        ),
    ]
