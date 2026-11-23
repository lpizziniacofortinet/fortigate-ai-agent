import unittest
from unittest.mock import MagicMock, patch

from core.context import InvestigationContext
from core.verification import PostChangeVerifier, VerificationStatus
from fortigate_client import FortiGateClient
from write_authorization import WriteAuthorizationController


class TestPostChangeVerification(unittest.TestCase):
    """Positive & negative tri-state verification tests for all 7 write actions (Issues #18 & #23)."""

    def _ctx(self, client=None):
        c = client or FortiGateClient(host="10.0.0.1", token="tok", vdom="root", mock=True)
        return InvestigationContext(fg_client=c, auth_controller=WriteAuthorizationController(isatty_fn=lambda: False))

    def _proposal(self, ctx, action, target, params, vdom="root"):
        return ctx.auth_controller.create_proposal(
            action=action, target=target, vdom=vdom, parameters=params, proposed_state=params
        )

    def test_toggle_interface_admin_up_with_physical_link_down_verifies_cmdb(self):
        verifier = PostChangeVerifier()
        client = MagicMock(spec=FortiGateClient)
        client.host = "10.0.0.1"
        client.vdom = "root"
        # CMDB admin status is UP, while physical monitor link is DOWN (e.g., unplugged cable)
        client.get_interface_config.return_value = {
            "status": "success",
            "results": [{"name": "port2", "vdom": "root", "status": "up"}],
        }
        client.get_interfaces.return_value = {
            "status": "success",
            "results": [{"name": "port2", "status": "down", "link": False}],
        }
        ctx = self._ctx(client)
        p = self._proposal(ctx, "toggle_interface", "port2", {"interface_name": "port2", "status": "up"})
        res = verifier.verify(p, ctx)

        self.assertEqual(res.status, VerificationStatus.VERIFIED)
        self.assertEqual(res.observed_state["admin_status"], "up")
        self.assertEqual(res.observed_state["operational_link_status"], "down")

    def test_toggle_interface_old_state_missing_and_unparseable(self):
        verifier = PostChangeVerifier()
        ctx = self._ctx()

        # Negative (old state): port1 CMDB admin status is 'up', requested 'down' -> FAILED
        p_old = self._proposal(ctx, "toggle_interface", "port1", {"interface_name": "port1", "status": "down"})
        self.assertEqual(verifier.verify(p_old, ctx).status, VerificationStatus.FAILED)

        # Missing target -> FAILED
        p_missing = self._proposal(ctx, "toggle_interface", "port99", {"interface_name": "port99", "status": "up"})
        self.assertEqual(verifier.verify(p_missing, ctx).status, VerificationStatus.FAILED)

        # Unparseable CMDB response -> UNKNOWN
        bad_client = MagicMock(spec=FortiGateClient)
        bad_client.host = "10.0.0.1"
        bad_client.vdom = "root"
        bad_client.get_interface_config.return_value = {"status": "success", "results": "corrupt"}
        r_bad = verifier.verify(p_old, self._ctx(bad_client))
        self.assertEqual(r_bad.status, VerificationStatus.UNKNOWN)
        self.assertFalse(r_bad.verified)

    def test_toggle_firewall_policy_positive_and_negative(self):
        verifier = PostChangeVerifier()
        ctx = self._ctx()

        p_ok = self._proposal(ctx, "toggle_firewall_policy", "policy:5", {"policy_id": 5, "status": "enable"})
        self.assertEqual(verifier.verify(p_ok, ctx).status, VerificationStatus.VERIFIED)

        p_old = self._proposal(ctx, "toggle_firewall_policy", "policy:5", {"policy_id": 5, "status": "disable"})
        self.assertEqual(verifier.verify(p_old, ctx).status, VerificationStatus.FAILED)

        p_miss = self._proposal(ctx, "toggle_firewall_policy", "policy:999", {"policy_id": 999, "status": "enable"})
        self.assertEqual(verifier.verify(p_miss, ctx).status, VerificationStatus.FAILED)

    def test_apply_policy_hardening_positive_and_negative(self):
        verifier = PostChangeVerifier()
        ctx_mock = self._ctx()
        p_fail = self._proposal(ctx_mock, "apply_policy_hardening", "policy:1", {"policy_id": 1})
        self.assertEqual(verifier.verify(p_fail, ctx_mock).status, VerificationStatus.FAILED)

        hardened_client = MagicMock(spec=FortiGateClient)
        hardened_client.host = "10.0.0.1"
        hardened_client.vdom = "root"
        hardened_client.get_firewall_policies.return_value = {
            "status": "success",
            "results": [{
                "policyid": 1,
                "utm-status": "enable",
                "logtraffic": "all",
                "av-profile": "default",
                "ips-sensor": "all_default",
            }],
        }
        self.assertEqual(verifier.verify(p_fail, self._ctx(hardened_client)).status, VerificationStatus.VERIFIED)

    def test_add_static_route_cmdb_vs_operational_states(self):
        verifier = PostChangeVerifier()
        params = {"destination": "10.50.0.0/16", "gateway": "198.51.100.254", "interface": "port1"}

        # 1. Configured in CMDB AND active in routing table -> VERIFIED
        ctx_mock = self._ctx()
        p = self._proposal(ctx_mock, "add_static_route", "10.50.0.0/16", params)
        r_ok = verifier.verify(p, ctx_mock)
        self.assertEqual(r_ok.status, VerificationStatus.VERIFIED)
        self.assertTrue(r_ok.observed_state["cmdb_configured"])
        self.assertTrue(r_ok.observed_state["operational_active"])

        # 2. Configured in CMDB BUT NOT active in routing table -> FAILED (distinguishes config vs operational)
        c_inactive = MagicMock(spec=FortiGateClient)
        c_inactive.host = "10.0.0.1"
        c_inactive.vdom = "root"
        c_inactive.get_static_routes.return_value = {
            "status": "success",
            "results": [{"seq-num": 2, "status": "enable", "dst": "10.50.0.0 255.255.0.0", "gateway": "198.51.100.254", "device": "port1"}],
        }
        c_inactive.get_routing_table.return_value = {"status": "success", "results": []}
        r_inact = verifier.verify(p, self._ctx(c_inactive))
        self.assertEqual(r_inact.status, VerificationStatus.FAILED)
        self.assertTrue(r_inact.observed_state["cmdb_configured"])
        self.assertFalse(r_inact.observed_state["operational_active"])

        # 3. Missing from CMDB -> FAILED
        c_missing = MagicMock(spec=FortiGateClient)
        c_missing.host = "10.0.0.1"
        c_missing.vdom = "root"
        c_missing.get_static_routes.return_value = {"status": "success", "results": []}
        c_missing.get_routing_table.return_value = {"status": "success", "results": []}
        r_miss = verifier.verify(p, self._ctx(c_missing))
        self.assertEqual(r_miss.status, VerificationStatus.FAILED)
        self.assertFalse(r_miss.observed_state["cmdb_configured"])

        # 4. Configured in CMDB, routing table unavailable -> UNKNOWN
        c_unavail = MagicMock(spec=FortiGateClient)
        c_unavail.host = "10.0.0.1"
        c_unavail.vdom = "root"
        c_unavail.get_static_routes.return_value = c_inactive.get_static_routes.return_value
        c_unavail.get_routing_table.side_effect = ConnectionError("routing table timeout")
        r_unk = verifier.verify(p, self._ctx(c_unavail))
        self.assertEqual(r_unk.status, VerificationStatus.UNKNOWN)
        self.assertTrue(r_unk.observed_state["cmdb_configured"])
        self.assertIsNone(r_unk.observed_state["operational_active"])

    def test_quarantine_ip_preserves_read_failure_as_unknown(self):
        verifier = PostChangeVerifier()
        ctx = self._ctx()

        # Positive: 198.51.100.99 present in mock
        p_ok = self._proposal(ctx, "quarantine_ip_address", "198.51.100.99", {"ip_address": "198.51.100.99"})
        self.assertEqual(verifier.verify(p_ok, ctx).status, VerificationStatus.VERIFIED)

        # Negative: absent from valid ban table -> FAILED
        p_miss = self._proposal(ctx, "quarantine_ip_address", "203.0.113.77", {"ip_address": "203.0.113.77"})
        self.assertEqual(verifier.verify(p_miss, ctx).status, VerificationStatus.FAILED)

        # Read exception on live client -> get_quarantined_ips returns status='error', verifier returns UNKNOWN
        live_client = FortiGateClient(host="10.0.0.1", token="secret_tok", verify_ssl=True, mock=False)
        with patch.object(live_client, "_get", side_effect=ConnectionError("500 error with secret_tok")):
            raw = live_client.get_quarantined_ips()
            self.assertEqual(raw["status"], "error")
            self.assertIsNone(raw["results"])
            self.assertNotIn("secret_tok", raw["error"])
            res = verifier.verify(p_ok, self._ctx(live_client))
            self.assertEqual(res.status, VerificationStatus.UNKNOWN)
            self.assertFalse(res.verified)

    def test_disconnect_ssl_vpn_user_positive_and_negative(self):
        verifier = PostChangeVerifier()
        ctx = self._ctx()

        p_still = self._proposal(ctx, "disconnect_ssl_vpn_user", "jdoe", {"username": "jdoe"})
        self.assertEqual(verifier.verify(p_still, ctx).status, VerificationStatus.FAILED)

        p_gone = self._proposal(ctx, "disconnect_ssl_vpn_user", "disconnected_user", {"username": "disconnected_user"})
        self.assertEqual(verifier.verify(p_gone, ctx).status, VerificationStatus.VERIFIED)

    def test_reset_vpn_tunnel_strict_phase1_and_phase2_selector_fixtures(self):
        verifier = PostChangeVerifier()

        def _check(tunnel_dict, extra_params=None):
            c = MagicMock(spec=FortiGateClient)
            c.host = "10.0.0.1"
            c.vdom = "root"
            c.get_vpn_status.return_value = {"status": "success", "results": {"ipsec": [tunnel_dict]}}
            ctx = self._ctx(c)
            params = {"p1_name": "VPN-DC"}
            if extra_params:
                params.update(extra_params)
            p = self._proposal(ctx, "reset_vpn_tunnel", "VPN-DC", params)
            return verifier.verify(p, ctx)

        # 1. Phase 1 up, Phase 2 down -> FAILED
        self.assertEqual(
            _check({"name": "VPN-DC", "phase1": "up", "phase2": "down"}).status,
            VerificationStatus.FAILED,
        )
        # 2. Partial selector establishment (1 up, 1 down) -> FAILED
        self.assertEqual(
            _check({
                "name": "VPN-DC",
                "status": "up",
                "proxyid": [{"p2name": "p2-lan", "status": "up"}, {"p2name": "p2-dmz", "status": "down"}],
            }).status,
            VerificationStatus.FAILED,
        )
        # 3. All selectors up -> VERIFIED
        self.assertEqual(
            _check({
                "name": "VPN-DC",
                "status": "up",
                "proxyid": [{"p2name": "p2-lan", "status": "up"}, {"p2name": "p2-dmz", "status": "up"}],
            }).status,
            VerificationStatus.VERIFIED,
        )
        # 4. Missing phase/selector fields -> UNKNOWN (never verified)
        self.assertEqual(
            _check({"name": "VPN-DC", "status": "up"}).status,
            VerificationStatus.UNKNOWN,
        )

    def test_vdom_mismatch_returns_unknown(self):
        verifier = PostChangeVerifier()
        ctx = self._ctx()
        p_other = self._proposal(ctx, "toggle_interface", "port1", {"interface_name": "port1", "status": "up"}, vdom="other")
        res = verifier.verify(p_other, ctx)
        self.assertEqual(res.status, VerificationStatus.UNKNOWN)
        self.assertFalse(res.verified)


if __name__ == "__main__":
    unittest.main()
