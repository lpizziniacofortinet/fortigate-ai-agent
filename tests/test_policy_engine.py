import unittest

from core.policy_engine import DeterministicPolicyEngine


class TestDeterministicPolicyEngine(unittest.TestCase):
    """Tests for DeterministicPolicyEngine safety rules (Issue #16 Phase 4)."""

    def setUp(self):
        self.engine = DeterministicPolicyEngine(allowed_vdoms={"root", "DMZ-VDOM"})

    def test_blocks_shutting_down_protected_management_interface(self):
        d = self.engine.evaluate("toggle_interface", "mgmt1", "root", {"interface_name": "mgmt1", "status": "down"})
        self.assertFalse(d.allowed)
        self.assertIn("protected", d.reason.lower())

    def test_blocks_unlisted_vdom_and_unsupported_action(self):
        d1 = self.engine.evaluate("toggle_interface", "port1", "Prod-VDOM", {"interface_name": "port1", "status": "up"})
        self.assertFalse(d1.allowed)
        self.assertIn("allowlist", d1.reason.lower())

        d2 = self.engine.evaluate("wipe_firewall", "all", "root", {})
        self.assertFalse(d2.allowed)
        self.assertIn("Unsupported", d2.reason)

    def test_validates_static_route_and_quarantine_ip_rules(self):
        bad_route = self.engine.evaluate(
            "add_static_route", "not-a-cidr", "root",
            {"destination": "not-a-cidr", "gateway": "999.1.1.1", "interface": "port1"},
        )
        self.assertFalse(bad_route.allowed)
        self.assertEqual(len(bad_route.violations), 2)

        bad_ban = self.engine.evaluate(
            "quarantine_ip_address", "127.0.0.1", "root",
            {"ip_address": "127.0.0.1", "duration_seconds": 0},
        )
        self.assertFalse(bad_ban.allowed)
        self.assertEqual(len(bad_ban.violations), 2)

        good_ban = self.engine.evaluate(
            "quarantine_ip_address", "198.51.100.99", "root",
            {"ip_address": "198.51.100.99", "duration_seconds": 3600},
        )
        self.assertTrue(good_ban.allowed)
        self.assertEqual(good_ban.risk, "critical")


if __name__ == "__main__":
    unittest.main()
