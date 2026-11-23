import unittest
from unittest.mock import MagicMock

from core.context import InvestigationContext
from core.verification import PostChangeVerifier, VerificationStatus
from fortigate_client import FortiGateClient
from write_authorization import WriteAuthorizationController


class TestPostChangeVerification(unittest.TestCase):
    """Positive & negative tri-state verification tests for all 7 write actions (Issue #18)."""

    def _ctx(self, client=None):
        c = client or FortiGateClient(host="10.0.0.1", token="tok", vdom="root", mock=True)
        return InvestigationContext(fg_client=c, auth_controller=WriteAuthorizationController(isatty_fn=lambda: False))

    def _proposal(self, ctx, action, target, params, vdom="root"):
        return ctx.auth_controller.create_proposal(
            action=action, target=target, vdom=vdom, parameters=params, proposed_state=params
        )

    def test_toggle_interface_positive_negative_missing_and_unparseable(self):
        verifier = PostChangeVerifier()
        ctx = self._ctx()

        # Positive: port1 is 'up' in mock
        p_ok = self._proposal(ctx, "toggle_interface", "port1", {"interface_name": "port1", "status": "up"})
        r_ok = verifier.verify(p_ok, ctx)
        self.assertEqual(r_ok.status, VerificationStatus.VERIFIED)
        self.assertTrue(r_ok.verified)
        self.assertEqual(r_ok.observed_state["status"], "up")

        # Negative (old state): port1 is 'up', but we requested 'down' -> MUST FAIL even though API succeeded
        p_old = self._proposal(ctx, "toggle_interface", "port1", {"interface_name": "port1", "status": "down"})
        r_old = verifier.verify(p_old, ctx)
        self.assertEqual(r_old.status, VerificationStatus.FAILED)
        self.assertFalse(r_old.verified)

        # Missing target -> FAILED
        p_missing = self._proposal(ctx, "toggle_interface", "port99", {"interface_name": "port99", "status": "up"})
        r_missing = verifier.verify(p_missing, ctx)
        self.assertEqual(r_missing.status, VerificationStatus.FAILED)

        # Unparseable response -> UNKNOWN (never verified=True)
        bad_client = MagicMock(spec=FortiGateClient)
        bad_client.host = "10.0.0.1"
        bad_client.vdom = "root"
        bad_client.get_interfaces.return_value = {"status": "success", "results": "corrupt"}
        r_bad = verifier.verify(p_ok, self._ctx(bad_client))
        self.assertEqual(r_bad.status, VerificationStatus.UNKNOWN)
        self.assertFalse(r_bad.verified)

    def test_toggle_firewall_policy_positive_and_negative(self):
        verifier = PostChangeVerifier()
        ctx = self._ctx()

        # Policy 5 is 'enable' in mock
        p_ok = self._proposal(ctx, "toggle_firewall_policy", "policy:5", {"policy_id": 5, "status": "enable"})
        self.assertEqual(verifier.verify(p_ok, ctx).status, VerificationStatus.VERIFIED)

        # Requested 'disable' while still 'enable' -> FAILED
        p_old = self._proposal(ctx, "toggle_firewall_policy", "policy:5", {"policy_id": 5, "status": "disable"})
        self.assertEqual(verifier.verify(p_old, ctx).status, VerificationStatus.FAILED)

        # Missing policy 999 -> FAILED
        p_miss = self._proposal(ctx, "toggle_firewall_policy", "policy:999", {"policy_id": 999, "status": "enable"})
        self.assertEqual(verifier.verify(p_miss, ctx).status, VerificationStatus.FAILED)

    def test_apply_policy_hardening_positive_and_negative(self):
        verifier = PostChangeVerifier()
        # Mock policy 1 has NO utm-status / profiles -> FAILED
        ctx_mock = self._ctx()
        p_fail = self._proposal(ctx_mock, "apply_policy_hardening", "policy:1", {"policy_id": 1})
        self.assertEqual(verifier.verify(p_fail, ctx_mock).status, VerificationStatus.FAILED)

        # Hardened policy -> VERIFIED
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
        res = verifier.verify(p_fail, self._ctx(hardened_client))
        self.assertEqual(res.status, VerificationStatus.VERIFIED)

    def test_add_static_route_positive_and_negative(self):
        verifier = PostChangeVerifier()
        ctx = self._ctx()

        # Mock already has 10.50.0.0/16 via 198.51.100.254 on port1
        p_ok = self._proposal(
            ctx, "add_static_route", "10.50.0.0/16",
            {"destination": "10.50.0.0/16", "gateway": "198.51.100.254", "interface": "port1"},
        )
        self.assertEqual(verifier.verify(p_ok, ctx).status, VerificationStatus.VERIFIED)

        # Missing route -> FAILED
        p_miss = self._proposal(
            ctx, "add_static_route", "10.99.0.0/16",
            {"destination": "10.99.0.0/16", "gateway": "198.51.100.254", "interface": "port1"},
        )
        self.assertEqual(verifier.verify(p_miss, ctx).status, VerificationStatus.FAILED)

    def test_quarantine_ip_positive_and_negative(self):
        verifier = PostChangeVerifier()
        ctx = self._ctx()

        # Mock has 198.51.100.99 banned
        p_ok = self._proposal(ctx, "quarantine_ip_address", "198.51.100.99", {"ip_address": "198.51.100.99"})
        self.assertEqual(verifier.verify(p_ok, ctx).status, VerificationStatus.VERIFIED)

        # Unbanned IP -> FAILED
        p_miss = self._proposal(ctx, "quarantine_ip_address", "203.0.113.77", {"ip_address": "203.0.113.77"})
        self.assertEqual(verifier.verify(p_miss, ctx).status, VerificationStatus.FAILED)

    def test_disconnect_ssl_vpn_user_positive_and_negative(self):
        verifier = PostChangeVerifier()
        ctx = self._ctx()

        # User 'jdoe' is STILL connected in mock -> FAILED
        p_still = self._proposal(ctx, "disconnect_ssl_vpn_user", "jdoe", {"username": "jdoe"})
        self.assertEqual(verifier.verify(p_still, ctx).status, VerificationStatus.FAILED)

        # User 'disconnected_user' is absent -> VERIFIED
        p_gone = self._proposal(ctx, "disconnect_ssl_vpn_user", "disconnected_user", {"username": "disconnected_user"})
        self.assertEqual(verifier.verify(p_gone, ctx).status, VerificationStatus.VERIFIED)

    def test_reset_vpn_tunnel_positive_negative_and_missing(self):
        verifier = PostChangeVerifier()
        ctx = self._ctx()

        # AWS-Transit is 'up' -> VERIFIED
        p_up = self._proposal(ctx, "reset_vpn_tunnel", "AWS-Transit", {"p1_name": "AWS-Transit"})
        self.assertEqual(verifier.verify(p_up, ctx).status, VerificationStatus.VERIFIED)

        # Branch-2-VPN is still 'down' -> FAILED
        p_down = self._proposal(ctx, "reset_vpn_tunnel", "Branch-2-VPN", {"p1_name": "Branch-2-VPN"})
        self.assertEqual(verifier.verify(p_down, ctx).status, VerificationStatus.FAILED)

        # Unknown tunnel -> UNKNOWN
        p_unk = self._proposal(ctx, "reset_vpn_tunnel", "NoSuchTunnel", {"p1_name": "NoSuchTunnel"})
        self.assertEqual(verifier.verify(p_unk, ctx).status, VerificationStatus.UNKNOWN)

    def test_vdom_mismatch_returns_unknown(self):
        verifier = PostChangeVerifier()
        ctx = self._ctx()
        p_other = self._proposal(ctx, "toggle_interface", "port1", {"interface_name": "port1", "status": "up"}, vdom="other")
        res = verifier.verify(p_other, ctx)
        self.assertEqual(res.status, VerificationStatus.UNKNOWN)
        self.assertFalse(res.verified)


if __name__ == "__main__":
    unittest.main()
