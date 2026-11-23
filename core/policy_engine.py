"""Deterministic Policy Engine validating write proposals strictly outside the LLM (Issue #16 Phase 4)."""

import ipaddress
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set


SUPPORTED_WRITE_ACTIONS: Set[str] = {
    "toggle_interface",
    "reset_vpn_tunnel",
    "add_static_route",
    "toggle_firewall_policy",
    "apply_policy_hardening",
    "disconnect_ssl_vpn_user",
    "quarantine_ip_address",
}

DEFAULT_PROTECTED_INTERFACES: Set[str] = {"mgmt", "mgmt1", "mgmt2", "ha", "ha1", "ha2", "lo", "loopback"}


@dataclass(frozen=True)
class PolicyDecision:
    """Deterministic allow/deny decision produced by DeterministicPolicyEngine."""
    allowed: bool
    reason: str
    risk: str = "high"
    violations: List[str] = field(default_factory=list)
    preconditions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PolicyViolationError(PermissionError):
    """Raised when a proposed remediation violates deterministic policy rules."""

    def __init__(self, decision: PolicyDecision):
        self.decision = decision
        super().__init__(f"Policy Engine denied write action: {decision.reason}")


class DeterministicPolicyEngine:
    """
    Deterministic validation layer guarding all FortiGate write operations.
    Validates device, VDOM allowlist, supported action, target syntax, protected objects,
    and parameter invariants independently of LLM reasoning.
    """

    def __init__(
        self,
        allowed_vdoms: Optional[Set[str]] = None,
        protected_interfaces: Optional[Set[str]] = None,
        allow_permanent_quarantine: bool = False,
    ):
        self.allowed_vdoms = {v.strip() for v in allowed_vdoms} if allowed_vdoms else None
        self.protected_interfaces = (
            {i.strip().lower() for i in protected_interfaces}
            if protected_interfaces is not None
            else set(DEFAULT_PROTECTED_INTERFACES)
        )
        self.allow_permanent_quarantine = allow_permanent_quarantine

    def evaluate(
        self,
        action: str,
        target: str,
        vdom: str,
        parameters: Dict[str, Any],
        device: str = "",
    ) -> PolicyDecision:
        violations: List[str] = []
        preconditions: List[str] = []
        risk = "high"

        if action not in SUPPORTED_WRITE_ACTIONS:
            violations.append(f"Unsupported write action '{action}'.")

        if not vdom or not str(vdom).strip():
            violations.append("Target VDOM must be specified.")
        elif self.allowed_vdoms is not None and vdom.strip() not in self.allowed_vdoms:
            violations.append(f"VDOM '{vdom}' is not in the permitted VDOM allowlist.")

        if not target or not str(target).strip():
            violations.append("Target object identifier must not be empty.")

        # Action-specific deterministic safety checks
        if action == "toggle_interface":
            intf = str(parameters.get("interface_name", target)).strip()
            status = str(parameters.get("status", "")).strip().lower()
            if status not in ("up", "down"):
                violations.append("toggle_interface status must be 'up' or 'down'.")
            if any(ch in intf for ch in ("/", "\\", "..", "?", "#")):
                violations.append(f"Illegal path characters in interface name '{intf}'.")
            if status == "down" and intf.lower() in self.protected_interfaces:
                violations.append(
                    f"Refusing to bring down protected management/HA interface '{intf}'."
                )
            preconditions.append(f"Verify interface '{intf}' exists in VDOM '{vdom}'.")

        elif action in ("toggle_firewall_policy", "apply_policy_hardening"):
            pid = parameters.get("policy_id")
            if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
                violations.append(f"policy_id must be a positive integer (got {pid!r}).")
            if action == "toggle_firewall_policy":
                status = str(parameters.get("status", "")).strip().lower()
                if status not in ("enable", "disable"):
                    violations.append("toggle_firewall_policy status must be 'enable' or 'disable'.")
            preconditions.append(f"Verify firewall policy ID {pid} exists in VDOM '{vdom}'.")

        elif action == "add_static_route":
            dst = str(parameters.get("destination", "")).strip()
            gw = str(parameters.get("gateway", "")).strip()
            intf = str(parameters.get("interface", "")).strip()
            try:
                ipaddress.ip_network(dst, strict=False)
            except ValueError:
                violations.append(f"Invalid destination CIDR/subnet '{dst}'.")
            try:
                ipaddress.ip_address(gw)
            except ValueError:
                violations.append(f"Invalid next-hop gateway IP '{gw}'.")
            if not intf:
                violations.append("Output interface must be non-empty.")
            if dst == "0.0.0.0/0":
                risk = "critical"
            preconditions.append(f"Verify output interface '{intf}' exists and route does not duplicate an active entry.")

        elif action == "quarantine_ip_address":
            risk = "critical"
            ip_str = str(parameters.get("ip_address", target)).strip()
            dur = parameters.get("duration_seconds", 3600)
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj.is_loopback or ip_obj.is_unspecified:
                    violations.append(f"Refusing to quarantine loopback/unspecified IP '{ip_str}'.")
            except ValueError:
                violations.append(f"Invalid IP address '{ip_str}'.")
            if isinstance(dur, bool) or not isinstance(dur, int) or dur < 0:
                violations.append("duration_seconds must be a non-negative integer.")
            elif dur == 0 and not self.allow_permanent_quarantine:
                violations.append("Permanent IP quarantine (duration_seconds=0) is disabled by policy.")
            preconditions.append(f"Confirm '{ip_str}' is not the active management workstation or FortiGate interface IP.")

        elif action == "reset_vpn_tunnel":
            p1 = str(parameters.get("p1_name", target)).strip()
            if not p1:
                violations.append("VPN Phase 1 tunnel name must not be empty.")
            preconditions.append(f"Confirm IPsec Phase 1 tunnel '{p1}' is configured in VDOM '{vdom}'.")

        elif action == "disconnect_ssl_vpn_user":
            risk = "medium"
            user = str(parameters.get("username", target)).strip()
            if not user:
                violations.append("SSL-VPN username must not be empty.")
            preconditions.append(f"Verify SSL-VPN user '{user}' has an active session.")

        if violations:
            return PolicyDecision(
                allowed=False,
                reason="; ".join(violations),
                risk=risk,
                violations=violations,
                preconditions=preconditions,
            )

        return PolicyDecision(
            allowed=True,
            reason=f"Action '{action}' on '{target}' (device={device or 'target'}, vdom={vdom}) passed deterministic policy validation.",
            risk=risk,
            violations=[],
            preconditions=preconditions,
        )
