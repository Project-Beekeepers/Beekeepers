import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "Beekeeper scripts" / "Slack bot" / "Slack_alerter.py"


class AlerterEventTitleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        test_dir = Path(cls.temp.name)
        shutil.copy2(SCRIPT, test_dir / "Slack_alerter.py")
        (test_dir / ".env").write_text(
            "WEBHOOK_TYPE=discord\nWEBHOOK_URL=http://127.0.0.1:9/not-real\n",
            encoding="utf-8",
        )
        spec = importlib.util.spec_from_file_location(
            "beekeepers_alerter_event_title_test", test_dir / "Slack_alerter.py"
        )
        cls.alerter = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {"WEBHOOK_TYPE": "discord", "WEBHOOK_URL": "http://127.0.0.1:9/not-real"}):
            spec.loader.exec_module(cls.alerter)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_ssh_login_attempt_title(self):
        self.assertEqual(
            self.alerter.alert_title({"Protocol": "SSH", "Msg": "New SSH Login Attempt"}),
            "New SSH login attempt",
        )

    def test_ssh_terminal_started_title(self):
        self.assertEqual(
            self.alerter.alert_title({"Protocol": "SSH", "Msg": "New SSH Terminal Session"}),
            "New SSH terminal session",
        )

    def test_ssh_interactive_command_title(self):
        self.assertEqual(
            self.alerter.alert_title({"Protocol": "SSH", "Msg": "SSH Terminal Session Interaction", "Command": "whoami"}),
            "SSH command received",
        )

    def test_ssh_raw_command_title(self):
        self.assertEqual(
            self.alerter.alert_title({"Protocol": "SSH", "Msg": "SSH Raw Command"}),
            "SSH command received",
        )

    def test_ssh_session_end_title(self):
        self.assertEqual(
            self.alerter.alert_title({"Protocol": "SSH", "Msg": "End SSH Session"}),
            "SSH session ended",
        )

    def test_ssh_command_fallback_when_event_message_missing(self):
        self.assertEqual(
            self.alerter.alert_title({"Protocol": "SSH", "Command": "ls"}),
            "SSH command received",
        )

    def test_unrecognised_ssh_event_is_not_called_login(self):
        self.assertEqual(
            self.alerter.alert_title({"Protocol": " SSH ", "Msg": "something else"}),
            "New SSH activity detected",
        )

    def test_http_request_title(self):
        self.assertEqual(
            self.alerter.alert_title({"Protocol": "http", "Msg": "HTTP New request"}),
            "New HTTP request",
        )

    def test_other_known_protocols_get_generic_titles(self):
        for protocol in ("TCP", "TELNET", "MCP"):
            with self.subTest(protocol=protocol):
                self.assertEqual(
                    self.alerter.alert_title({"Protocol": protocol}),
                    f"New {protocol} activity detected",
                )

    def test_unknown_or_malformed_protocol_has_safe_generic_title(self):
        for details in ({}, {"Protocol": None}, {"Protocol": "ATTACK\n@everyone"}):
            with self.subTest(details=details):
                self.assertEqual(
                    self.alerter.alert_title(details),
                    "New honeypot activity detected",
                )

    def test_complete_alert_uses_classified_title(self):
        details = {
            "Msg": "New SSH Login Attempt",
            "Protocol": "SSH",
            "SourceIp": "192.0.2.10",
            "CommandOutput": "",
            "DateTime": "2026-11-03T06:15:03Z",
        }
        message = self.alerter.format_message(details, 1)
        self.assertTrue(message.startswith("New SSH login attempt\n"))
        self.assertIn("Source IP:**\n```\n192.0.2.10\n```", message)
        self.assertNotIn("Active probing found", message)

    def test_handle_line_sends_title_without_network_calls(self):
        entry = {
            "msg": "New Event",
            "event": {
                "Msg": "HTTP New request",
                "Protocol": "HTTP",
                "SourceIp": "192.0.2.11",
                "RequestURI": "/admin",
                "HTTPMethod": "GET",
                "CommandOutput": "",
            },
        }
        self.alerter.last_alerted.clear()
        self.alerter.request_times.clear()
        with patch.object(self.alerter, "send_alert") as mock_send:
            self.alerter.handle_line(json.dumps(entry))
        mock_send.assert_called_once()
        self.assertTrue(mock_send.call_args.args[0].startswith("New HTTP request\n"))


if __name__ == "__main__":
    unittest.main()
