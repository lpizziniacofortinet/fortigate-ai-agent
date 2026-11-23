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
    """Normalizes both CIDR ('10.50.0.0/16') and FortiOS CMDB ('10.50.0.0 255.255.0.0') strings."""
    raw = str(value or "").strip()
    if not raw:
        return None
    parts = raw.split()
    if len(parts) == 2:
        raw = f"{parts[0]}/{parts[1]}"
    try:
        return str(ipaddress.ip_network(raw, strict=False))
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
        desired = {"interface_name": intf_name, "admin_status": desired_status}
        source = f"get_interface_config (/cmdb/system/interface/{intf_name})"

        resp = context.fg_client.get_interface_config(intf_name)
        items = _extract_list_results(resp)
        if items is None:
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                target=intf_name,
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"raw_type": type(resp).__name__, "response_status": resp.get("status") if isinstance(resp, dict) else None},
                evidence_source=source,
                reason="CMDB interface response shape is unsupported or unparseable.",
            )

        matches = [
            i for i in items
            if str(i.get("name") or i.get("q_origin_key") or "").strip().lower() == intf_name.lower()
        ]
        if len(matches) == 0:
            return VerificationResult(
                status=VerificationStatus.FAILED,
                target=intf_name,
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"found": False},
                evidence_source=source,
                reason=f"Target interface '{intf_name}' not found in CMDB for VDOM '{proposal.vdom}'.",
            )
        if len(matches) > 1:
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                target=intf_name,
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"match_count": len(matches)},
                evidence_source=source,
                reason=f"Ambiguous CMDB interface match: found {len(matches)} entries for '{intf_name}'.",
            )

        obj = matches[0]
        raw_admin = obj.get("status")
        admin_status = raw_admin.strip().lower() if isinstance(raw_admin, str) and raw_admin.strip().lower() in ("up", "down") else None

        # Separately observe operational link state from monitor endpoint (informational only; never substitutes for admin state)
        operational_link: Optional[str] = None
        try:
            mon_items = _extract_list_results(context.fg_client.get_interfaces()) or []
            mon_matches = [
                m for m in mon_items
                if str(m.get("name") or m.get("id") or "").strip().lower() == intf_name.lower()
            ]
            if len(mon_matches) == 1:
                m = mon_matches[0]
                if isinstance(m.get("link"), bool):
                    operational_link = "up" if m["link"] else "down"
                elif m.get("link_status") in (0, 1):
                    operational_link = "up" if m["link_status"] == 1 else "down"
                elif isinstance(m.get("status"), str) and m["status"].lower() in ("up", "down"):
                    operational_link = m["status"].lower()
        except Exception:
            operational_link = None

        observed = {
            "name": intf_name,
            "admin_status": admin_status,
            "operational_link_status": operational_link,
            "vdom": obj.get("vdom", proposal.vdom),
        }
        if admin_status is None:
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                target=intf_name,
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state=observed,
                evidence_source=source,
                reason=f"CMDB interface '{intf_name}' is missing a valid administrative 'status' field.",
            )
        if admin_status == desired_status:
            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                target=intf_name,
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state=observed,
                evidence_source=source,
                reason=(
                    f"Interface '{intf_name}' CMDB administrative status confirmed '{desired_status}' "
                    f"(operational link: {operational_link or 'unknown'})."
                ),
            )
        return VerificationResult(
            status=VerificationStatus.FAILED,
            target=intf_name,
            vdom=proposal.vdom,
            desired_state=desired,
            observed_state=observed,
            evidence_source=source,
            reason=f"Interface '{intf_name}' CMDB administrative status is '{admin_status}', expected '{desired_status}'.",
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
        desired = {"destination": dst, "gateway": gw, "interface": intf, "cmdb_configured": True, "operational_active": True}
        source = "get_static_routes (/cmdb/router/static) + get_routing_table (/monitor/router/ipv4)"

        # 1. Verify exact CMDB static route configuration
        cmdb_resp = context.fg_client.get_static_routes()
        cmdb_items = _extract_list_results(cmdb_resp)
        if cmdb_items is None:
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                target=str(proposal.target),
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"cmdb_error": cmdb_resp.get("error") if isinstance(cmdb_resp, dict) else type(cmdb_resp).__name__},
                evidence_source=source,
                reason="CMDB static route response is unavailable or unparseable.",
            )

        cmdb_matches = []
        for r in cmdb_items:
            r_dst = _normalize_cidr(r.get("dst") or r.get("destination") or "")
            r_gw = _normalize_ip(r.get("gateway") or "")
            r_dev = str(r.get("device") or r.get("interface") or "").strip().lower()
            r_enabled = str(r.get("status", "enable")).strip().lower() == "enable"
            if r_dst == dst and r_gw == gw and r_dev == intf and r_enabled:
                cmdb_matches.append(r)

        cmdb_configured = len(cmdb_matches) >= 1

        # 2. Separately check operational installation in active IPv4 routing table
        operational_active: Optional[bool] = None
        op_match = None
        op_error: Optional[str] = None
        try:
            rt_resp = context.fg_client.get_routing_table()
            rt_items = _extract_list_results(rt_resp)
            if rt_items is not None:
                rt_matches = [
                    r for r in rt_items
                    if _normalize_cidr(r.get("destination") or r.get("ip_mask") or "") == dst
                    and _normalize_ip(r.get("gateway") or "") == gw
                    and str(r.get("interface") or "").strip().lower() == intf
                ]
                operational_active = len(rt_matches) >= 1
                op_match = rt_matches[0] if rt_matches else None
            else:
                op_error = "Routing table response shape unparseable or unavailable"
        except Exception as exc:
            op_error = str(exc)

        observed = {
            "cmdb_configured": cmdb_configured,
            "cmdb_match": cmdb_matches[0] if cmdb_matches else None,
            "operational_active": operational_active,
            "operational_match": op_match,
            "operational_error": op_error,
        }

        if not cmdb_configured:
            return VerificationResult(
                status=VerificationStatus.FAILED,
                target=str(proposal.target),
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state=observed,
                evidence_source=source,
                reason=f"Static route {dst} via {gw} dev {intf} is NOT configured in CMDB (/cmdb/router/static).",
            )
        if operational_active is True:
            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                target=str(proposal.target),
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state=observed,
                evidence_source=source,
                reason=f"Static route {dst} via {gw} dev {intf} confirmed in CMDB and installed in active routing table.",
            )
        if operational_active is False:
            return VerificationResult(
                status=VerificationStatus.FAILED,
                target=str(proposal.target),
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state=observed,
                evidence_source=source,
                reason=(
                    f"Static route {dst} via {gw} dev {intf} IS configured in CMDB, "
                    "but is NOT installed in the active operational routing table."
                ),
            )
        return VerificationResult(
            status=VerificationStatus.UNKNOWN,
            target=str(proposal.target),
            vdom=proposal.vdom,
            desired_state=desired,
            observed_state=observed,
            evidence_source=source,
            reason=(
                f"Static route {dst} via {gw} dev {intf} is configured in CMDB, "
                f"but active routing table verification is unavailable ({op_error})."
            ),
        )

    def _verify_quarantine_ip_address(self, proposal: ChangeProposal, context: InvestigationContext) -> VerificationResult:
        target_ip = _normalize_ip(proposal.parameters.get("ip_address", proposal.target))
        desired = {"ip_address": target_ip, "quarantined": True}
        source = "get_quarantined_ips (/monitor/user/banned)"

        resp = context.fg_client.get_quarantined_ips()
        if isinstance(resp, dict) and resp.get("status") in ("error", "warning"):
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                target=str(target_ip or proposal.target),
                vdom=proposal.vdom,
                desired_state=desired,
                observed_state={"response_status": resp.get("status"), "error": resp.get("error") or resp.get("message")},
                evidence_source=source,
                reason=f"Quarantine table read failed: {resp.get('error') or resp.get('message') or 'unavailable'}",
            )

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
        phase1_raw = t.get("phase1")
        phase2_raw = t.get("phase2")
        status_raw = t.get("status")
        proxyid = t.get("proxyid")
        expected_selectors = proposal.parameters.get("expected_selectors")

        phase1_state = str(phase1_raw).strip().lower() if isinstance(phase1_raw, str) else None
        phase2_state = str(phase2_raw).strip().lower() if isinstance(phase2_raw, str) else None
        tunnel_status = str(status_raw).strip().lower() if isinstance(status_raw, str) else None

        # Evaluate Phase 1 state
        if phase1_state in ("up", "down"):
            p1_up: Optional[bool] = phase1_state == "up"
        elif tunnel_status in ("up", "down") and isinstance(proxyid, list) and len(proxyid) > 0:
            p1_up = tunnel_status == "up"
        else:
            p1_up = None

        # Evaluate Phase 2 / Proxy-ID selectors (ALL required selectors must be up)
        selector_states: Dict[str, str] = {}
        p2_up: Optional[bool] = None
        if isinstance(proxyid, list) and len(proxyid) > 0:
            valid_proxies = [p for p in proxyid if isinstance(p, dict)]
            for idx, p in enumerate(valid_proxies):
                sname = str(p.get("p2name") or p.get("name") or f"selector_{idx}")
                sstat = str(p.get("status", "")).strip().lower()
                selector_states[sname] = sstat or "unknown"

            if isinstance(expected_selectors, list) and expected_selectors:
                missing_expected = [s for s in expected_selectors if s not in selector_states]
                if missing_expected:
                    p2_up = False
                else:
                    target_states = [selector_states[s] for s in expected_selectors]
                    if any(s == "unknown" for s in target_states):
                        p2_up = None
                    else:
                        p2_up = all(s == "up" for s in target_states)
            else:
                if any(s == "unknown" for s in selector_states.values()):
                    p2_up = None
                else:
                    p2_up = all(s == "up" for s in selector_states.values())
        elif phase2_state in ("up", "down"):
            p2_up = phase2_state == "up"

        observed = {
            "name": p1_name,
            "status": tunnel_status,
            "phase1": phase1_state,
            "phase2": phase2_state,
            "selectors": selector_states,
        }

        if p1_up is False or p2_up is False:
            return VerificationResult(
                status=VerificationStatus.FAILED,
                target=p1_name,
                vdom=proposal.vdom,
                desired_state={"p1_name": p1_name, "phase1": "up", "phase2_all_selectors": "up"},
                observed_state=observed,
                evidence_source=source,
                reason=f"IPsec tunnel '{p1_name}' failed verification (phase1_up={p1_up}, phase2_all_up={p2_up}, selectors={selector_states}).",
            )
        if p1_up is True and p2_up is True:
            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                target=p1_name,
                vdom=proposal.vdom,
                desired_state={"p1_name": p1_name, "phase1": "up", "phase2_all_selectors": "up"},
                observed_state=observed,
                evidence_source=source,
                reason=f"IPsec tunnel '{p1_name}' confirmed Phase 1 and all required Phase 2 selectors UP.",
            )
        return VerificationResult(
            status=VerificationStatus.UNKNOWN,
            target=p1_name,
            vdom=proposal.vdom,
            desired_state={"p1_name": p1_name, "phase1": "up", "phase2_all_selectors": "up"},
            observed_state=observed,
            evidence_source=source,
            reason=f"IPsec tunnel '{p1_name}' response lacks sufficient Phase 1/Phase 2 selector fields to prove operational state.",
        )
