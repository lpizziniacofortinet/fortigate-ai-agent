"""Action-specific post-change state verification for FortiGate remediation (Issue #18)."""

from dataclasses import dataclass, field, asdict
from enum import Enum
import ipaddress
from typing import Any, Dict, List, Optional

from core.context import InvestigationContext
from write_authorization import ChangeProposal


class VerificationStatus(str, Enum):
    VERIFIED = "verified"
    FAILED = "failed"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class VerificationResult:
    """Tri-state post-change verification result with full target/desired/observed evidence."""
    status: VerificationStatus
    target: str
    vdom: str
    desired_state: Dict[str, Any]
    observed_state: Dict[str, Any]
    evidence_source: str
    reason: str

    @property
    def verified(self) -> bool:
        return self.status == VerificationStatus.VERIFIED

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["verified"] = self.verified
        return data


def _extract_list_results(resp: Any) -> Optional[List[Dict[str, Any]]]:
    """Safely extracts a list of dict objects from FortiOS API responses; returns None if unparseable."""
    if not isinstance(resp, dict):
        return None
    if resp.get("status") not in (None, "success"):
        return None
    raw = resp.get("results")
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if isinstance(raw, dict):
        # Some FortiOS monitor endpoints (e.g. /monitor/system/interface) return a dict keyed by object name
        values = list(raw.values())
        if all(isinstance(v, dict) for v in values):
            return values
    return None


def _normalize_cidr(value: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_network(str(value).strip(), strict=False))
    except ValueError:
        return None


def _normalize_ip(value: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


class PostChangeVerifier:
    """
    Verifies that a FortiGate object actually reached the requested desired state
    after a write operation, returning an explicit tri-state VerificationResult
    (`verified`, `failed`, or `unknown`). Never treats mere API reachability as success.
    """

    def verify(self, proposal: ChangeProposal, context: InvestigationContext) -> VerificationResult:
        client = context.fg_client
        vdom = proposal.vdom

        if str(client.vdom).strip() != str(vdom).strip():
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                target=proposal.target,
                vdom=vdom,
                desired_state=dict(proposal.proposed_state),
                observed_state={"client_vdom": client.vdom},
                evidence_source="vdom_check",
                reason=f"Cannot verify target in VDOM '{vdom}': client is bound to VDOM '{client.vdom}'.",
            )

        handlers = {
            "toggle_interface": self._verify_toggle_interface,
            "toggle_firewall_policy": self._verify_toggle_firewall_policy,
            "apply_policy_hardening": self._verify_apply_policy_hardening,
            "add_static_route": self._verify_add_static_route,
            "quarantine_ip_address": self._verify_quarantine_ip_address,
            "disconnect_ssl_vpn_user": self._verify_disconnect_ssl_vpn_user,
            "reset_vpn_tunnel": self._verify_reset_vpn_tunnel,
        }
        handler = handlers.get(proposal.action)
        if handler is None:
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                target=proposal.target,
                vdom=vdom,
                desired_state=dict(proposal.proposed_state),
                observed_state={},
                evidence_source="none",
                reason=f"No action-specific verifier implemented for '{proposal.action}'.",
            )

        try:
            return handler(proposal, context)
        except Exception as exc:
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                target=proposal.target,
                vdom=vdom,
                desired_state=dict(proposal.proposed_state),
                observed_state={"error": str(exc)},
                evidence_source=proposal.action,
                reason=f"Verification read failed: {exc}",
            )

    def _verify_toggle_interface(self, proposal: ChangeProposal, context: InvestigationContext) -> VerificationResult:
        intf_name = str(proposal.parameters.get("interface_name", proposal.target)).strip()
        desired_status = str(proposal.parameters.get("status", "")).strip().lower()
        desired = {"interface_name": intf_name, "status": desired_status}
        source = "get_interfaces (/monitor/system/interface)"

        resp = context.fg_client.get_interfaces()
        items = _extract_list_results(resp)
        if items is None:
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                target=intf_name,
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"raw_type": type(resp).__name__},
                evidence_source=source,
                reason="Interface response shape is unsupported or unparseable.",
            )

        matches = [
            i for i in items
            if str(i.get("name") or i.get("id") or "").strip().lower() == intf_name.lower()
        ]
        if len(matches) == 0:
            return VerificationResult(
                status=VerificationStatus.FAILED,
                target=intf_name,
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"found": False},
                evidence_source=source,
                reason=f"Target interface '{intf_name}' not found in VDOM '{proposal.vdom}'.",
            )
        if len(matches) > 1:
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                target=intf_name,
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"match_count": len(matches)},
                evidence_source=source,
                reason=f"Ambiguous interface match: found {len(matches)} entries for '{intf_name}'.",
            )

        obj = matches[0]
        raw_status = obj.get("status")
        link = obj.get("link")
        link_status = obj.get("link_status")
        observed_status: Optional[str] = None
        if isinstance(raw_status, str) and raw_status.strip().lower() in ("up", "down"):
            observed_status = raw_status.strip().lower()
        elif isinstance(link, bool):
            observed_status = "up" if link else "down"
        elif link_status in (0, 1):
            observed_status = "up" if link_status == 1 else "down"

        observed = {"name": intf_name, "status": observed_status, "link": link, "link_status": link_status}
        if observed_status is None:
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                target=intf_name,
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state=observed,
                evidence_source=source,
                reason=f"Interface '{intf_name}' returned incomplete state fields.",
            )
        if observed_status == desired_status:
            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                target=intf_name,
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state=observed,
                evidence_source=source,
                reason=f"Interface '{intf_name}' confirmed in desired state '{desired_status}'.",
            )
        return VerificationResult(
            status=VerificationStatus.FAILED,
            target=intf_name,
            vdom=proposal.vdom,
            desired_state=desired,
            observed_state=observed,
            evidence_source=source,
            reason=f"Interface '{intf_name}' is '{observed_status}', expected '{desired_status}'.",
        )

    def _verify_toggle_firewall_policy(self, proposal: ChangeProposal, context: InvestigationContext) -> VerificationResult:
        policy_id = proposal.parameters.get("policy_id")
        desired_status = str(proposal.parameters.get("status", "")).strip().lower()
        desired = {"policy_id": policy_id, "status": desired_status}
        source = "get_firewall_policies (/cmdb/firewall/policy)"

        resp = context.fg_client.get_firewall_policies()
        items = _extract_list_results(resp)
        if items is None:
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                target=f"policy:{policy_id}",
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"raw_type": type(resp).__name__},
                evidence_source=source,
                reason="Firewall policy response shape is unsupported or unparseable.",
            )

        matches = [p for p in items if p.get("policyid") == policy_id]
        if len(matches) == 0:
            return VerificationResult(
                status=VerificationStatus.FAILED,
                target=f"policy:{policy_id}",
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"found": False},
                evidence_source=source,
                reason=f"Firewall policy ID {policy_id} not found in VDOM '{proposal.vdom}'.",
            )
        if len(matches) > 1:
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                target=f"policy:{policy_id}",
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"match_count": len(matches)},
                evidence_source=source,
                reason=f"Ambiguous policy match: found {len(matches)} entries for policy ID {policy_id}.",
            )

        obj = matches[0]
        obs_status = str(obj.get("status", "")).strip().lower()
        observed = {"policy_id": policy_id, "name": obj.get("name"), "status": obs_status or None}
        if not obs_status:
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                target=f"policy:{policy_id}",
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state=observed,
                evidence_source=source,
                reason=f"Policy ID {policy_id} is missing a 'status' field.",
            )
        if obs_status == desired_status:
            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                target=f"policy:{policy_id}",
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state=observed,
                evidence_source=source,
                reason=f"Firewall policy ID {policy_id} confirmed '{desired_status}'.",
            )
        return VerificationResult(
            status=VerificationStatus.FAILED,
            target=f"policy:{policy_id}",
            vdom=proposal.vdom,
            desired_state=desired,
            observed_state=observed,
            evidence_source=source,
            reason=f"Firewall policy ID {policy_id} is '{obs_status}', expected '{desired_status}'.",
        )

    def _verify_apply_policy_hardening(self, proposal: ChangeProposal, context: InvestigationContext) -> VerificationResult:
        policy_id = proposal.parameters.get("policy_id")
        desired = {"policy_id": policy_id, "utm_status": "enable", "logtraffic": "all", "utm_profile_present": True}
        source = "get_firewall_policies (/cmdb/firewall/policy)"

        resp = context.fg_client.get_firewall_policies()
        items = _extract_list_results(resp)
        if items is None:
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                target=f"policy:{policy_id}",
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"raw_type": type(resp).__name__},
                evidence_source=source,
                reason="Firewall policy response shape is unsupported or unparseable.",
            )

        matches = [p for p in items if p.get("policyid") == policy_id]
        if len(matches) == 0:
            return VerificationResult(
                status=VerificationStatus.FAILED,
                target=f"policy:{policy_id}",
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"found": False},
                evidence_source=source,
                reason=f"Firewall policy ID {policy_id} not found in VDOM '{proposal.vdom}'.",
            )
        if len(matches) > 1:
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                target=f"policy:{policy_id}",
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"match_count": len(matches)},
                evidence_source=source,
                reason=f"Ambiguous policy match: found {len(matches)} entries for policy ID {policy_id}.",
            )

        obj = matches[0]
        utm_status = str(obj.get("utm-status") or obj.get("utm_status") or "").strip().lower()
        logtraffic = str(obj.get("logtraffic") or "").strip().lower()
        profiles = {
            k: obj.get(k) or obj.get(k.replace("-", "_"))
            for k in ("av-profile", "ips-sensor", "webfilter-profile", "ssl-ssh-profile")
            if obj.get(k) or obj.get(k.replace("-", "_"))
        }
        observed = {
            "policy_id": policy_id,
            "utm_status": utm_status or None,
            "logtraffic": logtraffic or None,
            "profiles": profiles,
        }

        if utm_status == "enable" and logtraffic == "all" and len(profiles) > 0:
            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                target=f"policy:{policy_id}",
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state=observed,
                evidence_source=source,
                reason=f"Policy ID {policy_id} confirmed hardened (utm-status=enable, logtraffic=all, profiles={list(profiles.keys())}).",
            )
        return VerificationResult(
            status=VerificationStatus.FAILED,
            target=f"policy:{policy_id}",
            vdom=proposal.vdom,
            desired_state=desired,
            observed_state=observed,
            evidence_source=source,
            reason=f"Policy ID {policy_id} does not meet hardened state (utm={utm_status!r}, logtraffic={logtraffic!r}, profiles={list(profiles.keys())}).",
        )

    def _verify_add_static_route(self, proposal: ChangeProposal, context: InvestigationContext) -> VerificationResult:
        dst = _normalize_cidr(proposal.parameters.get("destination", ""))
        gw = _normalize_ip(proposal.parameters.get("gateway", ""))
        intf = str(proposal.parameters.get("interface", "")).strip().lower()
        desired = {"destination": dst, "gateway": gw, "interface": intf}
        source = "get_routing_table (/monitor/router/ipv4)"

        resp = context.fg_client.get_routing_table()
        items = _extract_list_results(resp)
        if items is None:
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                target=str(proposal.target),
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"raw_type": type(resp).__name__},
                evidence_source=source,
                reason="Routing table response shape is unsupported or unparseable.",
            )

        matches = []
        for r in items:
            r_dst = _normalize_cidr(r.get("destination") or r.get("ip_mask") or "")
            r_gw = _normalize_ip(r.get("gateway") or "")
            r_intf = str(r.get("interface") or "").strip().lower()
            if r_dst == dst and r_gw == gw and r_intf == intf:
                matches.append(r)

        if len(matches) >= 1:
            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                target=str(proposal.target),
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"matched_route": matches[0]},
                evidence_source=source,
                reason=f"Static route {dst} via {gw} dev {intf} confirmed present in active routing table.",
            )
        return VerificationResult(
            status=VerificationStatus.FAILED,
            target=str(proposal.target),
            vdom=proposal.vdom,
            desired_state=desired,
            observed_state={"route_count": len(items), "matched": False},
            evidence_source=source,
            reason=f"Static route {dst} via {gw} dev {intf} not found in active routing table.",
        )

    def _verify_quarantine_ip_address(self, proposal: ChangeProposal, context: InvestigationContext) -> VerificationResult:
        target_ip = _normalize_ip(proposal.parameters.get("ip_address", proposal.target))
        desired = {"ip_address": target_ip, "quarantined": True}
        source = "get_quarantined_ips (/monitor/user/banned)"

        resp = context.fg_client.get_quarantined_ips()
        items = _extract_list_results(resp)
        if items is None:
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                target=str(target_ip or proposal.target),
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"raw_type": type(resp).__name__},
                evidence_source=source,
                reason="Quarantined IP response shape is unsupported or unparseable.",
            )

        matches = [
            entry for entry in items
            if _normalize_ip(entry.get("ip") or entry.get("ip_address") or "") == target_ip
        ]
        if matches:
            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                target=str(target_ip),
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"banned_entry": matches[0]},
                evidence_source=source,
                reason=f"IP '{target_ip}' confirmed present in FortiGate active ban/quarantine table.",
            )
        return VerificationResult(
            status=VerificationStatus.FAILED,
            target=str(target_ip),
            vdom=proposal.vdom,
            desired_state=desired,
            observed_state={"banned_count": len(items), "found": False},
            evidence_source=source,
            reason=f"IP '{target_ip}' was NOT found in FortiGate active ban/quarantine table.",
        )

    def _verify_disconnect_ssl_vpn_user(self, proposal: ChangeProposal, context: InvestigationContext) -> VerificationResult:
        username = str(proposal.parameters.get("username", proposal.target)).strip()
        desired = {"username": username, "connected": False}
        source = "get_vpn_status (/monitor/vpn/ssl)"

        resp = context.fg_client.get_vpn_status()
        if not isinstance(resp, dict) or not isinstance(resp.get("results"), dict):
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                target=username,
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"raw_type": type(resp).__name__},
                evidence_source=source,
                reason="VPN status response shape is unsupported or unparseable.",
            )

        ssl_vpn = resp["results"].get("ssl_vpn")
        if not isinstance(ssl_vpn, dict) or "sessions" not in ssl_vpn or not isinstance(ssl_vpn.get("sessions"), list):
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                target=username,
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"ssl_vpn": ssl_vpn},
                evidence_source=source,
                reason="SSL-VPN session list is missing or unavailable in VPN status response.",
            )

        active = [
            s for s in ssl_vpn["sessions"]
            if isinstance(s, dict) and str(s.get("user") or s.get("user_name") or "").strip().lower() == username.lower()
        ]
        if not active:
            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                target=username,
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"active_sessions_for_user": 0},
                evidence_source=source,
                reason=f"SSL-VPN user '{username}' is no longer present in active sessions.",
            )
        return VerificationResult(
            status=VerificationStatus.FAILED,
            target=username,
            vdom=proposal.vdom,
            desired_state=desired,
            observed_state={"active_sessions_for_user": len(active)},
            evidence_source=source,
            reason=f"SSL-VPN user '{username}' still has {len(active)} active session(s).",
        )

    def _verify_reset_vpn_tunnel(self, proposal: ChangeProposal, context: InvestigationContext) -> VerificationResult:
        p1_name = str(proposal.parameters.get("p1_name", proposal.target)).strip()
        desired = {"p1_name": p1_name, "status": "up"}
        source = "get_vpn_status (/monitor/vpn/ipsec)"

        resp = context.fg_client.get_vpn_status()
        if not isinstance(resp, dict) or not isinstance(resp.get("results"), dict):
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                target=p1_name,
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"raw_type": type(resp).__name__},
                evidence_source=source,
                reason="VPN status response shape is unsupported or unparseable.",
            )

        raw_ipsec = resp["results"].get("ipsec")
        if isinstance(raw_ipsec, dict):
            tunnels = [v for v in raw_ipsec.values() if isinstance(v, dict)]
        elif isinstance(raw_ipsec, list):
            tunnels = [t for t in raw_ipsec if isinstance(t, dict)]
        else:
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                target=p1_name,
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"ipsec": raw_ipsec},
                evidence_source=source,
                reason="IPsec tunnel list is missing or unparseable.",
            )

        matches = [t for t in tunnels if str(t.get("name", "")).strip() == p1_name]
        if len(matches) == 0:
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                target=p1_name,
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"found": False},
                evidence_source=source,
                reason=f"IPsec tunnel '{p1_name}' not found in /monitor/vpn/ipsec output.",
            )
        if len(matches) > 1:
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                target=p1_name,
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"match_count": len(matches)},
                evidence_source=source,
                reason=f"Ambiguous IPsec tunnel match: found {len(matches)} entries for '{p1_name}'.",
            )

        t = matches[0]
        proxyid = t.get("proxyid", [])
        proxy_up = isinstance(proxyid, list) and any(isinstance(p, dict) and p.get("status") == "up" for p in proxyid)
        is_up = (
            str(t.get("status", "")).lower() == "up"
            or str(t.get("phase1", "")).lower() == "up"
            or proxy_up
        )
        observed = {"name": p1_name, "status": t.get("status"), "phase1": t.get("phase1"), "phase2": t.get("phase2")}
        if is_up:
            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                target=p1_name,
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state=observed,
                evidence_source=source,
                reason=f"IPsec tunnel '{p1_name}' confirmed UP after reset.",
            )
        return VerificationResult(
            status=VerificationStatus.FAILED,
            target=p1_name,
            vdom=proposal.vdom,
            desired_state=desired,
            observed_state=observed,
            evidence_source=source,
            reason=f"IPsec tunnel '{p1_name}' is still DOWN after reset.",
        )
