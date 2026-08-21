import unittest
from unittest.mock import MagicMock
from fortigate_client import FortiGateClient
from security_audit import (
    FortiGateSecurityAuditor,
    SecurityAuditReport,
    AuditSeverity,
    AuditStatus
)

class TestSecurityAudit(unittest.TestCase):
    """Unit tests for the FortiOS Security Posture & CIS Hardening Benchmark Engine."""

    def setUp(self):
        self.mock_client = FortiGateClient(
            host="10.0.0.1",
            token="token123",
            enable_write_actions=False,
            mock=True
        )
        self.auditor = FortiGateSecurityAuditor(self.mock_client)

    def test_run_audit_structure(self):
        """Asserts that running audit returns a well-formed report with findings."""
        report = self.auditor.run_audit()
        self.assertIsInstance(report, SecurityAuditReport)
        self.assertIsInstance(report.overall_score, (int, float))
        self.assertIn(report.letter_grade, ["A+", "A", "B", "C", "D", "F"])
        self.assertGreater(len(report.findings), 5)
        self.assertGreater(report.total_checks if hasattr(report, "total_checks") else len(report.findings), 0)

    def test_detect_policy_shadowing(self):
        """Asserts that detect_policy_shadowing accurately identifies order inversions."""
        policies = [
            {
                "policyid": 1,
                "name": "Catch-All-Permit",
                "srcintf": [{"name": "port3"}],
                "dstintf": [{"name": "port1"}],
                "srcaddr": [{"name": "all"}],
                "dstaddr": [{"name": "all"}],
                "action": "accept",
                "service": [{"name": "ALL"}],
                "status": "enable"
            },
            {
                "policyid": 5,
                "name": "Block-Specific-Port",
                "srcintf": [{"name": "port3"}],
                "dstintf": [{"name": "port1"}],
                "srcaddr": [{"name": "all"}],
                "dstaddr": [{"name": "all"}],
                "action": "deny",
                "service": [{"name": "BGP"}],
                "status": "enable"
            }
        ]

        shadows = self.auditor.detect_policy_shadowing(policies)
        self.assertEqual(len(shadows), 1)
        self.assertEqual(shadows[0].shadowed_policy_id, 5)
        self.assertEqual(shadows[0].shadowing_policy_id, 1)
        self.assertIn("move 5 before 1", shadows[0].cli_reorder_command)

    def test_detect_no_shadowing_when_distinct_interfaces(self):
        """Asserts that distinct interfaces do not trigger false positive shadowing."""
        policies = [
            {
                "policyid": 1,
                "name": "LAN-to-WAN",
                "srcintf": [{"name": "port3"}],
                "dstintf": [{"name": "port1"}],
                "srcaddr": [{"name": "all"}],
                "dstaddr": [{"name": "all"}],
                "action": "accept",
                "service": [{"name": "ALL"}],
                "status": "enable"
            },
            {
                "policyid": 2,
                "name": "DMZ-to-WAN",
                "srcintf": [{"name": "dmz"}],
                "dstintf": [{"name": "port1"}],
                "srcaddr": [{"name": "all"}],
                "dstaddr": [{"name": "all"}],
                "action": "deny",
                "service": [{"name": "ALL"}],
                "status": "enable"
            }
        ]

        shadows = self.auditor.detect_policy_shadowing(policies)
        self.assertEqual(len(shadows), 0)

    def test_hardening_playbook_generation(self):
        """Asserts that the hardening playbook includes FortiOS CLI configuration commands."""
        report = self.auditor.run_audit()
        playbook = report.generate_hardening_playbook()
        self.assertIn("config firewall policy", playbook)
        self.assertIn("set utm-status enable", playbook)

    def test_to_dict_and_markdown(self):
        """Asserts that report serializes to dict and markdown correctly."""
        report = self.auditor.run_audit()
        data = report.to_dict()
        self.assertIn("overall_score", data)
        self.assertIn("letter_grade", data)
        self.assertIn("findings", data)
        self.assertIn("summary", data)

        md = report.to_markdown()
        self.assertIn("# 🛡️ FortiOS Security Posture & CIS Hardening Benchmark Report", md)
        self.assertIn("Executive Scorecard", md)

    def test_apply_policy_hardening_mock(self):
        """Asserts that apply_policy_hardening executes safely in mock mode."""
        mock_write_client = FortiGateClient(
            host="10.0.0.1",
            token="token123",
            enable_write_actions=True,
            mock=True
        )
        res = mock_write_client.apply_policy_hardening(policy_id=2)
        self.assertEqual(res["status"], "success")
        self.assertIn("Successfully applied UTM hardening", res["message"])

if __name__ == "__main__":
    unittest.main()
