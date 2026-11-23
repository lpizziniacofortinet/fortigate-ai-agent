import unittest
from unittest.mock import patch, MagicMock

from fortigate_client import FortiGateClient


class TestURLPathEscaping(unittest.TestCase):
    """Tests for URL path parameter validation and encoding (Issue #13)."""

    def setUp(self):
        self.client = FortiGateClient(
            host="10.0.0.1",
            token="testtoken",
            verify_ssl=True,
            enable_write_actions=True,
            backup_before_write=False,
            mock=False,
        )

    @patch("requests.put")
    def test_interface_path_traversal_rejected(self, mock_put):
        for bad_name in ["../global", "port1/../../global", "port1\\admin", "..", "."]:
            with self.assertRaises(ValueError):
                self.client.toggle_interface(bad_name, "down")
        mock_put.assert_not_called()

    @patch("requests.put")
    def test_interface_query_and_fragment_injection_rejected(self, mock_put):
        for bad_name in ["port1?vdom=other", "port1#frag", "port1%2fadmin", "port1\nX-Injected: 1", ""]:
            with self.assertRaises(ValueError):
                self.client.toggle_interface(bad_name, "down")
        mock_put.assert_not_called()

    @patch("requests.put")
    def test_interface_special_chars_url_encoded(self, mock_put):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "success"}
        mock_put.return_value = mock_resp

        self.client.toggle_interface("wan 1", "up")
        args, _ = mock_put.call_args
        self.assertTrue(args[0].endswith("/cmdb/system/interface/wan%201"))

    @patch("requests.put")
    def test_policy_id_strict_positive_int_validation(self, mock_put):
        for bad_id in [0, -5, "1/../../global", True, False, None, 1.5]:
            with self.assertRaises(ValueError):
                self.client.toggle_firewall_policy(bad_id, "disable")
            with self.assertRaises(ValueError):
                self.client.apply_policy_hardening(bad_id)
        mock_put.assert_not_called()


if __name__ == "__main__":
    unittest.main()
