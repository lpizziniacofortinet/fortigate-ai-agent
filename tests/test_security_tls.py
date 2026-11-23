import os
import tempfile
import unittest
import warnings
from unittest.mock import patch, MagicMock
import requests

from config import Config
from fortigate_client import FortiGateClient, TLSVerificationError


class TestTLSVerificationDefaults(unittest.TestCase):
    """Tests for secure-by-default TLS certificate verification (Issue #3)."""

    def test_config_default_verify_ssl_enabled(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("VERIFY_SSL", None)
            default_val = os.getenv("VERIFY_SSL", "True").lower() in ("true", "1", "yes")
            self.assertTrue(default_val)

    def test_client_defaults_to_verify_ssl_true(self):
        client = FortiGateClient(host="10.0.0.1", token="tok", mock=False)
        self.assertTrue(client.verify_ssl)
        self.assertTrue(client._resolve_ssl_verify())

    def test_insecure_opt_out_emits_prominent_warning(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            client = FortiGateClient(host="10.0.0.1", token="tok", verify_ssl=False, mock=False)
            self.assertFalse(client.verify_ssl)
            self.assertTrue(
                any("INSECURE TLS WARNING" in str(w.message) for w in caught),
                "Expected prominent UserWarning when verify_ssl=False"
            )

    @patch("requests.get")
    def test_ssl_error_fails_clearly_without_retry(self, mock_get):
        mock_get.side_effect = requests.exceptions.SSLError("certificate verify failed: self-signed certificate")
        client = FortiGateClient(host="10.0.0.1", token="tok", mock=False)

        with self.assertRaises(TLSVerificationError) as ctx:
            client._get("/monitor/system/status")

        self.assertEqual(mock_get.call_count, 1)
        self.assertIn("TLS certificate verification failed", str(ctx.exception))
        self.assertIn("--ca-bundle", str(ctx.exception))

    @patch("requests.get")
    def test_custom_ca_bundle_passed_to_requests(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "success", "results": {}}
        mock_get.return_value = mock_resp

        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as tf:
            tf.write("-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n")
            ca_path = tf.name

        try:
            client = FortiGateClient(host="10.0.0.1", token="tok", ca_bundle=ca_path, mock=False)
            client._get("/monitor/system/status")
            _, kwargs = mock_get.call_args
            self.assertEqual(kwargs["verify"], ca_path)
        finally:
            os.unlink(ca_path)

    def test_missing_ca_bundle_fails_clearly(self):
        client = FortiGateClient(host="10.0.0.1", token="tok", ca_bundle="/nonexistent/ca.pem", mock=False)
        with self.assertRaises(TLSVerificationError):
            client._resolve_ssl_verify()


if __name__ == "__main__":
    unittest.main()
