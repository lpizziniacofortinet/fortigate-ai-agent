import os
import unittest
from unittest.mock import patch, MagicMock
import requests
from tenacity import RetryError

from config import Config
from fortigate_client import FortiGateClient
from agent import FortiGateAgent, DiagnosticReport

class TestFortiGateClient(unittest.TestCase):
    """Unit tests for the FortiGateClient connection and request methods."""

    def setUp(self):
        self.client = FortiGateClient(
            host="192.168.1.1",
            token="testtoken",
            port=443,
            use_ssl=True,
            verify_ssl=False,
            vdom="root",
            enable_write_actions=False,
            mock=False
        )

    def test_constructor_parameters(self):
        """Asserts that client properties are correctly initialized."""
        self.assertEqual(self.client.host, "192.168.1.1")
        self.assertEqual(self.client.token, "testtoken")
        self.assertEqual(self.client.base_url, "https://192.168.1.1:443/api/v2")
        self.assertEqual(self.client.vdom, "root")
        self.assertFalse(self.client.enable_write_actions)

    @patch("requests.get")
    def test_get_vdom_injection(self, mock_get):
        """Asserts that _get automatically appends the target vdom query parameter."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "success", "results": []}
        mock_get.return_value = mock_response

        self.client._get("/monitor/system/status")
        
        # Verify requests.get was called and included vdom in params
        mock_get.assert_called_once()
        args, kwargs = mock_get.call_args
        self.assertIn("vdom", kwargs["params"])
        self.assertEqual(kwargs["params"]["vdom"], "root")

    @patch("requests.get")
    def test_get_rate_limit_retry(self, mock_get):
        """Asserts that requests.get retries on rate limits (HTTP 429)."""
        mock_response_429 = MagicMock()
        mock_response_429.status_code = 429
        mock_response_429.raise_for_status.side_effect = requests.exceptions.HTTPError("Rate Limit")

        mock_response_200 = MagicMock()
        mock_response_200.status_code = 200
        mock_response_200.json.return_value = {"status": "success"}

        # Simulate two 429 failures followed by a 200 success
        mock_get.side_effect = [mock_response_429, mock_response_429, mock_response_200]

        result = self.client._get("/monitor/system/status")
        
        # Assert retries completed successfully
        self.assertEqual(mock_get.call_count, 3)
        self.assertEqual(result["status"], "success")

    def test_write_action_permission_denial(self):
        """Asserts that write methods throw PermissionError when write actions are disabled."""
        self.client.enable_write_actions = False
        
        with self.assertRaises(PermissionError):
            self.client.toggle_interface("port1", "down")
            
        with self.assertRaises(PermissionError):
            self.client.add_static_route("10.0.0.0/24", "192.168.1.254", "port1")

        with self.assertRaises(PermissionError):
            self.client.toggle_firewall_policy(5, "disable")

        with self.assertRaises(PermissionError):
            self.client.disconnect_ssl_vpn_user("jdoe")

    def test_new_core_capabilities_mock(self):
        """Asserts that new FortiGate core client methods return valid mock structures."""
        mock_client = FortiGateClient(
            host="10.0.0.1",
            token="token123",
            enable_write_actions=True,
            mock=True
        )

        sdwan = mock_client.get_sdwan_status()
        self.assertEqual(sdwan["status"], "success")
        self.assertGreaterEqual(len(sdwan["results"]), 1)

        ha = mock_client.get_ha_status()
        self.assertEqual(ha["status"], "success")
        self.assertEqual(ha["results"]["sync_status"], "in-sync")

        vdoms = mock_client.get_vdom_list()
        self.assertEqual(vdoms["status"], "success")
        self.assertTrue(any(v["name"] == "root" for v in vdoms["results"]))

        toggle_res = mock_client.toggle_firewall_policy(5, "enable")
        self.assertEqual(toggle_res["status"], "success")

        disc_res = mock_client.disconnect_ssl_vpn_user("jdoe")
        self.assertEqual(disc_res["status"], "success")

        arp_res = mock_client.get_arp_table()
        self.assertEqual(arp_res["status"], "success")
        self.assertGreaterEqual(len(arp_res["results"]), 1)

        dhcp_res = mock_client.get_dhcp_leases()
        self.assertEqual(dhcp_res["status"], "success")
        self.assertGreaterEqual(len(dhcp_res["results"]), 1)

    def test_dry_run_mode(self):
        """Asserts that dry run mode intercepts write actions safely without execution."""
        dry_run_client = FortiGateClient(
            host="10.0.0.1",
            token="token123",
            enable_write_actions=True,
            dry_run=True,
            mock=True
        )

        res = dry_run_client.toggle_interface("port1", "down")
        self.assertEqual(res["status"], "dry_run")
        self.assertIn("DRY RUN", res["message"])

        route_res = dry_run_client.add_static_route("10.10.0.0/16", "192.168.1.254", "port1")
        self.assertEqual(route_res["status"], "dry_run")

    def test_backup_configuration(self):
        """Asserts that backup_configuration creates a valid backup snapshot file."""
        mock_client = FortiGateClient(
            host="10.0.0.1",
            token="token123",
            enable_write_actions=True,
            mock=True
        )
        backup_res = mock_client.backup_configuration(destination_dir=".test_backups")
        self.assertEqual(backup_res["status"], "success")
        self.assertTrue(os.path.exists(backup_res["file_path"]))
        # Clean up test file
        if os.path.exists(backup_res["file_path"]):
            os.remove(backup_res["file_path"])
        if os.path.exists(".test_backups"):
            os.rmdir(".test_backups")


class TestAgentRoutingReasoning(unittest.TestCase):
    """Integration test checking AI Agent reasoning capabilities under a dynamic routing failure."""

    @unittest.skipIf(not os.getenv("GEMINI_API_KEY") and not Config.GEMINI_API_KEY, "Gemini API Key is missing. Skipping integration test.")
    def test_bgp_blocking_policy_correlation(self):
        """
        Integration test verifying that the AI Agent correctly correlates BGP neighbor down states
        with firewall policies blocking TCP port 179.
        """
        # Set up client in Mock Mode to return the designed routing issue scenario
        client = FortiGateClient(
            host="10.0.0.1",
            token="token123",
            enable_write_actions=False,
            mock=True
        )
        
        # Verify mock responses are configured as expected
        bgp_status = client.get_bgp_neighbors()
        self.assertEqual(bgp_status["results"][1]["neighbor"], "10.255.0.2")
        self.assertEqual(bgp_status["results"][1]["state"], "Active") # Peer state is Active/Down

        ospf_status = client.get_ospf_neighbors()
        self.assertEqual(ospf_status["results"][1]["neighbor_id"], "172.16.100.2")
        self.assertEqual(ospf_status["results"][1]["state"], "Init") # Peer state is Init/Down

        policies = client.get_firewall_policies()
        self.assertEqual(policies["results"][1]["policyid"], 5)
        self.assertEqual(policies["results"][1]["action"], "deny")
        self.assertEqual(policies["results"][1]["service"][0]["name"], "BGP") # Blocking BGP policy is active

        agent = FortiGateAgent(fg_client=client)
        
        prompt = (
            "Analyze why BGP dynamic routing is down with peer 10.255.0.2. "
            "Check both BGP neighbor status and firewall security policies, and identify the root cause."
        )
        
        # Query the agent with a structured report schema expectation
        report = agent.run_structured_query(prompt)
        
        # Validate that the AI reasoning engine successfully diagnosed the routing issue
        self.assertIsInstance(report, DiagnosticReport)
        self.assertIn(report.overall_health.lower(), ["degraded", "critical"])
        
        # Check if BGP/Policy details exist in findings
        findings_summary = " ".join([f.summary.lower() for f in report.findings] + [f.details.lower() for f in report.findings])
        self.assertIn("bgp", findings_summary)
        self.assertIn("policy", findings_summary)
        self.assertTrue(any(x in findings_summary for x in ["179", "tcp", "block", "deny", "service"]))

        # Check troubleshooting steps
        troubleshooting = " ".join(report.troubleshooting_steps).lower()
        self.assertTrue(any(x in troubleshooting for x in ["policy 5", "policy id 5", "allow", "enable"]))

if __name__ == "__main__":
    unittest.main()
