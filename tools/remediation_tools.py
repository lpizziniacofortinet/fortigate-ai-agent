"""Gated Remediation tools (strictly bound to REMEDIATION role and WriteAuthorizationController)."""

from typing import Any, Callable, Dict, List

from agent import wrap_untrusted_tool_output
from core.context import InvestigationContext
from tools.registry import ToolCapability, ToolSpec


def _authorize(
    context: InvestigationContext,
    action: str,
    target: str,
    parameters: Dict[str, Any],
    proposed_state: Dict[str, Any],
    risk: str = "high",
) -> None:
    if not context.fg_client.enable_write_actions:
        raise PermissionError(
            "Write/Mitigation actions are currently disabled. Set ENABLE_WRITE_ACTIONS=True "
            "or use --enable-write."
        )
    proposal = context.auth_controller.create_proposal(
        action=action,
        target=target,
        vdom=context.vdom,
        parameters=parameters,
        proposed_state=proposed_state,
        risk=risk,
    )
    context.auth_controller.authorize(proposal)


def _build_backup_configuration(context: InvestigationContext) -> Callable[..., Dict[str, Any]]:
    def backup_configuration(destination_dir: str = ".backups") -> Dict[str, Any]:
        """Take a verified configuration backup snapshot of the FortiGate."""
        raw = context.fg_client.backup_configuration(destination_dir=destination_dir)
        return wrap_untrusted_tool_output("backup_configuration", raw)

    return backup_configuration


def _build_toggle_interface(context: InvestigationContext) -> Callable[..., Dict[str, Any]]:
    def toggle_interface(interface_name: str, status: str) -> Dict[str, Any]:
        """Toggle administrative state of a network interface ('up' or 'down')."""
        _authorize(
            context,
            action="toggle_interface",
            target=interface_name,
            parameters={"interface_name": interface_name, "status": status},
            proposed_state={"interface": interface_name, "status": status},
            risk="high",
        )
        res = context.fg_client.toggle_interface(interface_name=interface_name, status=status)
        context.invalidate_cache()
        return res

    return toggle_interface


def _build_reset_vpn_tunnel(context: InvestigationContext) -> Callable[..., Dict[str, Any]]:
    def reset_vpn_tunnel(p1_name: str) -> Dict[str, Any]:
        """Reset an IPsec VPN Phase 1 tunnel."""
        _authorize(
            context,
            action="reset_vpn_tunnel",
            target=p1_name,
            parameters={"p1_name": p1_name},
            proposed_state={"tunnel": p1_name, "operation": "reset_phase1"},
            risk="high",
        )
        res = context.fg_client.reset_vpn_tunnel(p1_name=p1_name)
        context.invalidate_cache()
        return res

    return reset_vpn_tunnel


def _build_add_static_route(context: InvestigationContext) -> Callable[..., Dict[str, Any]]:
    def add_static_route(destination: str, gateway: str, interface: str) -> Dict[str, Any]:
        """Configure a new static IPv4 route on the FortiGate."""
        _authorize(
            context,
            action="add_static_route",
            target=destination,
            parameters={"destination": destination, "gateway": gateway, "interface": interface},
            proposed_state={"destination": destination, "gateway": gateway, "interface": interface},
            risk="high",
        )
        res = context.fg_client.add_static_route(destination=destination, gateway=gateway, interface=interface)
        context.invalidate_cache()
        return res

    return add_static_route


def _build_toggle_firewall_policy(context: InvestigationContext) -> Callable[..., Dict[str, Any]]:
    def toggle_firewall_policy(policy_id: int, status: str) -> Dict[str, Any]:
        """Enable or disable a firewall policy by ID."""
        _authorize(
            context,
            action="toggle_firewall_policy",
            target=f"policy:{policy_id}",
            parameters={"policy_id": policy_id, "status": status},
            proposed_state={"policy_id": policy_id, "status": status},
            risk="high",
        )
        res = context.fg_client.toggle_firewall_policy(policy_id=policy_id, status=status)
        context.invalidate_cache()
        return res

    return toggle_firewall_policy


def _build_apply_policy_hardening(context: InvestigationContext) -> Callable[..., Dict[str, Any]]:
    def apply_policy_hardening(policy_id: int) -> Dict[str, Any]:
        """Apply UTM profiles and full logging to a firewall policy."""
        _authorize(
            context,
            action="apply_policy_hardening",
            target=f"policy:{policy_id}",
            parameters={"policy_id": policy_id},
            proposed_state={"policy_id": policy_id, "utm_status": "enable", "logtraffic": "all"},
            risk="high",
        )
        res = context.fg_client.apply_policy_hardening(policy_id=policy_id)
        context.invalidate_cache()
        return res

    return apply_policy_hardening


def _build_disconnect_ssl_vpn_user(context: InvestigationContext) -> Callable[..., Dict[str, Any]]:
    def disconnect_ssl_vpn_user(username: str) -> Dict[str, Any]:
        """Forcefully disconnect an active SSL-VPN user session."""
        _authorize(
            context,
            action="disconnect_ssl_vpn_user",
            target=username,
            parameters={"username": username},
            proposed_state={"ssl_vpn_user": username, "connected": False},
            risk="medium",
        )
        res = context.fg_client.disconnect_ssl_vpn_user(username=username)
        context.invalidate_cache()
        return res

    return disconnect_ssl_vpn_user


def _build_quarantine_ip_address(context: InvestigationContext) -> Callable[..., Dict[str, Any]]:
    def quarantine_ip_address(ip_address: str, duration_seconds: int = 3600, reason: str = "") -> Dict[str, Any]:
        """Ban and quarantine a malicious IP address."""
        _authorize(
            context,
            action="quarantine_ip_address",
            target=ip_address,
            parameters={"ip_address": ip_address, "duration_seconds": duration_seconds, "reason": reason},
            proposed_state={"ip_address": ip_address, "quarantined": True, "duration_seconds": duration_seconds},
            risk="critical",
        )
        res = context.fg_client.quarantine_ip_address(
            ip_address=ip_address, duration_seconds=duration_seconds, reason=reason
        )
        context.invalidate_cache()
        return res

    return quarantine_ip_address


def get_remediation_tool_specs() -> List[ToolSpec]:
    return [
        ToolSpec(
            name="backup_configuration",
            capability=ToolCapability.BACKUP_READ,
            is_write=False,
            description="Create a verified FortiGate configuration snapshot backup.",
            builder=_build_backup_configuration,
        ),
        ToolSpec(
            name="toggle_interface",
            capability=ToolCapability.REMEDIATION_WRITE,
            is_write=True,
            description="Toggle administrative state of a network interface.",
            builder=_build_toggle_interface,
        ),
        ToolSpec(
            name="reset_vpn_tunnel",
            capability=ToolCapability.REMEDIATION_WRITE,
            is_write=True,
            description="Reset an IPsec VPN Phase 1 tunnel.",
            builder=_build_reset_vpn_tunnel,
        ),
        ToolSpec(
            name="add_static_route",
            capability=ToolCapability.REMEDIATION_WRITE,
            is_write=True,
            description="Add a static IPv4 route.",
            builder=_build_add_static_route,
        ),
        ToolSpec(
            name="toggle_firewall_policy",
            capability=ToolCapability.REMEDIATION_WRITE,
            is_write=True,
            description="Enable or disable a firewall security policy.",
            builder=_build_toggle_firewall_policy,
        ),
        ToolSpec(
            name="apply_policy_hardening",
            capability=ToolCapability.REMEDIATION_WRITE,
            is_write=True,
            description="Apply UTM profiles and full logging to a firewall policy.",
            builder=_build_apply_policy_hardening,
        ),
        ToolSpec(
            name="disconnect_ssl_vpn_user",
            capability=ToolCapability.REMEDIATION_WRITE,
            is_write=True,
            description="Disconnect an active SSL-VPN user session.",
            builder=_build_disconnect_ssl_vpn_user,
        ),
        ToolSpec(
            name="quarantine_ip_address",
            capability=ToolCapability.REMEDIATION_WRITE,
            is_write=True,
            description="Quarantine/ban a malicious IP address.",
            builder=_build_quarantine_ip_address,
        ),
    ]
