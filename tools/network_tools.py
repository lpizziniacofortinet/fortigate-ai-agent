"""Read-only Network domain tools (interfaces, routing, BGP, OSPF, VPN, SD-WAN, ARP, DHCP)."""

from typing import Any, Callable, Dict, List

from agent import wrap_untrusted_tool_output
from core.context import InvestigationContext
from tools.registry import ToolCapability, ToolSpec


def _build_cached_read_tool(
    context: InvestigationContext,
    tool_name: str,
    doc: str,
    client_method_name: str,
) -> Callable[[], Dict[str, Any]]:
    def _tool() -> Dict[str, Any]:
        raw = context.get_or_fetch(
            cache_key=client_method_name,
            fetcher=getattr(context.fg_client, client_method_name),
        )
        return wrap_untrusted_tool_output(tool_name, raw)

    _tool.__name__ = tool_name
    _tool.__doc__ = doc
    return _tool


def get_network_tool_specs() -> List[ToolSpec]:
    return [
        ToolSpec(
            name="get_interfaces",
            capability=ToolCapability.NETWORK_READ,
            is_write=False,
            description="Get status, IP configurations, and traffic statistics for all network interfaces.",
            builder=lambda ctx: _build_cached_read_tool(
                ctx, "get_interfaces", "Get status, IP configs, and traffic stats for all interfaces.", "get_interfaces"
            ),
        ),
        ToolSpec(
            name="get_routing_table",
            capability=ToolCapability.NETWORK_READ,
            is_write=False,
            description="Get the active IPv4 routing table from the FortiGate.",
            builder=lambda ctx: _build_cached_read_tool(
                ctx, "get_routing_table", "Get the active IPv4 routing table.", "get_routing_table"
            ),
        ),
        ToolSpec(
            name="get_bgp_neighbors",
            capability=ToolCapability.NETWORK_READ,
            is_write=False,
            description="Get BGP dynamic routing neighbor peer states and stats.",
            builder=lambda ctx: _build_cached_read_tool(
                ctx, "get_bgp_neighbors", "Get BGP dynamic routing neighbor peer states.", "get_bgp_neighbors"
            ),
        ),
        ToolSpec(
            name="get_ospf_neighbors",
            capability=ToolCapability.NETWORK_READ,
            is_write=False,
            description="Get OSPF dynamic routing neighbor adjacencies.",
            builder=lambda ctx: _build_cached_read_tool(
                ctx, "get_ospf_neighbors", "Get OSPF dynamic routing neighbor adjacencies.", "get_ospf_neighbors"
            ),
        ),
        ToolSpec(
            name="get_vpn_status",
            capability=ToolCapability.NETWORK_READ,
            is_write=False,
            description="Get IPsec tunnel and SSL-VPN monitoring status.",
            builder=lambda ctx: _build_cached_read_tool(
                ctx, "get_vpn_status", "Get IPsec tunnel and SSL-VPN status.", "get_vpn_status"
            ),
        ),
        ToolSpec(
            name="get_sdwan_status",
            capability=ToolCapability.NETWORK_READ,
            is_write=False,
            description="Get SD-WAN member states and SLA health metrics.",
            builder=lambda ctx: _build_cached_read_tool(
                ctx, "get_sdwan_status", "Get SD-WAN member states and SLA metrics.", "get_sdwan_status"
            ),
        ),
        ToolSpec(
            name="get_arp_table",
            capability=ToolCapability.NETWORK_READ,
            is_write=False,
            description="Get active IPv4 ARP table mappings.",
            builder=lambda ctx: _build_cached_read_tool(
                ctx, "get_arp_table", "Get active IPv4 ARP table mappings.", "get_arp_table"
            ),
        ),
        ToolSpec(
            name="get_dhcp_leases",
            capability=ToolCapability.NETWORK_READ,
            is_write=False,
            description="Get active DHCP client lease assignments.",
            builder=lambda ctx: _build_cached_read_tool(
                ctx, "get_dhcp_leases", "Get active DHCP client lease assignments.", "get_dhcp_leases"
            ),
        ),
    ]
