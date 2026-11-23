import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from fortigate_client import FortiGateClient, BackupRequiredError


class TestFailClosedPreChangeBackup(unittest.TestCase):
    """Tests for fail-closed pre-change backup enforcement (Issue #1 & #9)."""

    def _make_client(self, **kwargs):
        defaults = dict(
            host="10.0.0.1",
            token="super_secret_token_12345",
            verify_ssl=True,
            enable_write_actions=True,
            backup_before_write=True,
            mock=False,
        )
        defaults.update(kwargs)
        return FortiGateClient(**defaults)

    @patch("requests.put")
    @patch("requests.get")
    def test_backup_api_failure_aborts_write_and_redacts_secret(self, mock_get, mock_put):
        mock_get.side_effect = RuntimeError("API failure with token super_secret_token_12345")
        client = self._make_client()

        with self.assertRaises(BackupRequiredError) as ctx:
            client.toggle_interface("port1", "up")

        mock_put.assert_not_called()
        err_dict = ctx.exception.to_dict()
        self.assertEqual(err_dict["status"], "blocked")
        self.assertEqual(err_dict["error"], "backup_required")
        self.assertEqual(err_dict["blocked_action"], "toggle_interface")
        self.assertNotIn("super_secret_token_12345", str(ctx.exception))
        self.assertNotIn("super_secret_token_12345", err_dict["reason"])

    @patch("requests.put")
    def test_filesystem_failure_aborts_write(self, mock_put):
        client = self._make_client(mock=True)
        with patch("os.makedirs", side_effect=OSError("Read-only file system")):
            with self.assertRaises(BackupRequiredError) as ctx:
                client.toggle_interface("port1", "up")

        mock_put.assert_not_called()
        self.assertEqual(ctx.exception.blocked_action, "toggle_interface")

    @patch("requests.put")
    def test_empty_backup_artifact_aborts_write(self, mock_put):
        client = self._make_client()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as tf:
            empty_path = tf.name

        try:
            with patch.object(client, "backup_configuration", return_value={"status": "success", "file_path": empty_path}):
                with self.assertRaises(BackupRequiredError) as ctx:
                    client.toggle_interface("port1", "up")
            mock_put.assert_not_called()
            self.assertIn("empty", ctx.exception.reason.lower())
        finally:
            if os.path.exists(empty_path):
                os.unlink(empty_path)

    @patch("requests.put")
    def test_corrupt_json_error_backup_aborts_write(self, mock_put):
        client = self._make_client()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as tf:
            tf.write('{"status": "error", "http_status": 403}')
            bad_path = tf.name

        try:
            with patch.object(client, "backup_configuration", return_value={"status": "success", "file_path": bad_path}):
                with self.assertRaises(BackupRequiredError) as ctx:
                    client.toggle_interface("port1", "up")
            mock_put.assert_not_called()
            self.assertIn("error payload", ctx.exception.reason.lower())
        finally:
            if os.path.exists(bad_path):
                os.unlink(bad_path)

    @patch("requests.put")
    @patch("requests.get")
    def test_live_plain_text_backup_succeeds_and_allows_write(self, mock_get, mock_put):
        mock_backup_resp = MagicMock()
        mock_backup_resp.status_code = 200
        mock_backup_resp.text = "#config-version=FGVMK6-7.4.13\nconfig system global\n    set hostname \"test\"\nend\n"
        mock_backup_resp.json.side_effect = ValueError("Not JSON")
        mock_get.return_value = mock_backup_resp

        mock_put_resp = MagicMock()
        mock_put_resp.status_code = 200
        mock_put_resp.json.return_value = {"status": "success"}
        mock_put.return_value = mock_put_resp

        client = self._make_client()
        with tempfile.TemporaryDirectory() as tmpdir:
            orig_backup = client.backup_configuration
            with patch.object(client, "backup_configuration", side_effect=lambda: orig_backup(destination_dir=tmpdir)):
                res = client.toggle_interface("port1", "up")

        self.assertEqual(res["status"], "success")
        mock_get.assert_called_once()
        mock_put.assert_called_once()

    @patch("requests.put")
    def test_explicit_backup_override_allows_write_without_backup(self, mock_put):
        mock_put_resp = MagicMock()
        mock_put_resp.status_code = 200
        mock_put_resp.json.return_value = {"status": "success"}
        mock_put.return_value = mock_put_resp

        client = self._make_client(backup_before_write=False)
        with patch.object(client, "backup_configuration") as mock_backup:
            res = client.toggle_interface("port1", "up")

        self.assertEqual(res["status"], "success")
        mock_backup.assert_not_called()
        mock_put.assert_called_once()


if __name__ == "__main__":
    unittest.main()
