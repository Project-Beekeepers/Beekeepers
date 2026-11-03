"""Regression tests for per-IP, per-protocol alert cooldowns."""

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


class AlerterProtocolCooldownTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        work = Path(cls.temp.name)
        shutil.copy2(SCRIPT, work / "Slack_alerter.py")
        (work / ".env").write_text(
            "WEBHOOK_TYPE=discord\nWEBHOOK_URL=http://127.0.0.1:9/not-real\n",
            encoding="utf-8",
        )
        spec = importlib.util.spec_from_file_location(
            "beekeepers_alerter_protocol_test", work / "Slack_alerter.py"
        )
        cls.alerter = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {
            "WEBHOOK_TYPE": "discord",
            "WEBHOOK_URL": "http://127.0.0.1:9/not-real",
        }):
            spec.loader.exec_module(cls.alerter)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.alerter.last_alerted.clear()
        self.alerter.request_times.clear()
        self.alerter.PROBE_THRESHOLD = 1
        self.alerter.PROBE_WINDOW_SECONDS = 60
        self.alerter.COOLDOWN_SECONDS = 300

    def event(self, protocol, ip="192.0.2.10"):
        return json.dumps({
            "msg": "New Event",
            "event": {
                "Protocol": protocol,
                "SourceIp": ip,
                "RequestURI": "/admin" if protocol == "HTTP" else "",
                "Command": "whoami" if protocol == "SSH" else "",
                "CommandOutput": "",
                "DateTime": "2026-11-03T06:15:03Z",
            },
        })

    def test_ssh_does_not_suppress_http_from_same_ip(self):
        with patch.object(self.alerter.time, "time", return_value=1000):
            self.assertTrue(self.alerter.should_alert("192.0.2.10", "", "SSH"))
            self.assertTrue(self.alerter.should_alert("192.0.2.10", "/admin", "HTTP"))
            self.assertFalse(self.alerter.should_alert("192.0.2.10", "", "SSH"))
            self.assertFalse(self.alerter.should_alert("192.0.2.10", "/admin", "HTTP"))
        self.assertEqual(len(self.alerter.last_alerted), 2)

    def test_same_protocol_remains_on_cooldown_then_expires(self):
        with patch.object(self.alerter.time, "time", return_value=1000):
            self.assertTrue(self.alerter.should_alert("192.0.2.10", "", "SSH"))
        with patch.object(self.alerter.time, "time", return_value=1299):
            self.assertFalse(self.alerter.should_alert("192.0.2.10", "", "SSH"))
        with patch.object(self.alerter.time, "time", return_value=1300):
            self.assertTrue(self.alerter.should_alert("192.0.2.10", "", "SSH"))

    def test_different_ips_remain_independent(self):
        with patch.object(self.alerter.time, "time", return_value=1000):
            self.assertTrue(self.alerter.should_alert("192.0.2.10", "", "SSH"))
            self.assertTrue(self.alerter.should_alert("192.0.2.11", "", "SSH"))

    def test_protocol_case_and_whitespace_are_normalized(self):
        with patch.object(self.alerter.time, "time", return_value=1000):
            self.assertTrue(self.alerter.should_alert("192.0.2.10", "", "ssh"))
            self.assertFalse(self.alerter.should_alert("192.0.2.10", "", " SSH "))
            self.assertTrue(self.alerter.should_alert("192.0.2.10", "/admin", "http"))
        self.assertIn(("192.0.2.10", "SSH"), self.alerter.last_alerted)

    def test_probe_threshold_counts_per_protocol(self):
        self.alerter.PROBE_THRESHOLD = 2
        with patch.object(self.alerter.time, "time", return_value=1000):
            self.assertFalse(self.alerter.should_alert("192.0.2.10", "", "SSH"))
            self.assertFalse(self.alerter.should_alert("192.0.2.10", "/", "HTTP"))
            self.assertTrue(self.alerter.should_alert("192.0.2.10", "", "SSH"))
            self.assertTrue(self.alerter.should_alert("192.0.2.10", "/", "HTTP"))
        self.assertEqual(len(self.alerter.request_times[("192.0.2.10", "SSH")]), 2)
        self.assertEqual(len(self.alerter.request_times[("192.0.2.10", "HTTP")]), 2)

    def test_handle_line_sends_both_protocol_alerts_from_same_ip(self):
        with patch.object(self.alerter.time, "time", return_value=1000), \
             patch.object(self.alerter, "send_alert") as send, \
             patch("builtins.print"):
            self.alerter.handle_line(self.event("SSH"))
            self.alerter.handle_line(self.event("HTTP"))
            self.alerter.handle_line(self.event("SSH"))
        self.assertEqual(send.call_count, 2)
        self.assertIn("Protocol:** SSH", send.call_args_list[0].args[0])
        self.assertIn("Protocol:** HTTP", send.call_args_list[1].args[0])

    def test_handle_line_probe_count_uses_correct_protocol(self):
        self.alerter.PROBE_THRESHOLD = 2
        with patch.object(self.alerter.time, "time", return_value=1000), \
             patch.object(self.alerter, "send_alert") as send, \
             patch("builtins.print"):
            self.alerter.handle_line(self.event("SSH"))
            self.alerter.handle_line(self.event("HTTP"))
            self.alerter.handle_line(self.event("SSH"))
            self.alerter.handle_line(self.event("HTTP"))
        self.assertEqual(send.call_count, 2)
        for call in send.call_args_list:
            self.assertIn("Probes in last 60s:** 2", call.args[0])

    def test_missing_protocol_uses_unknown_key_and_old_call_style(self):
        with patch.object(self.alerter.time, "time", return_value=1000):
            self.assertTrue(self.alerter.should_alert("192.0.2.10", ""))
            self.assertFalse(self.alerter.should_alert("192.0.2.10", "", None))
            self.assertTrue(self.alerter.should_alert("192.0.2.10", "", "HTTP"))
        self.assertIn(("192.0.2.10", "UNKNOWN"), self.alerter.last_alerted)

    def test_ignored_http_path_does_not_affect_other_protocol(self):
        with patch.object(self.alerter.time, "time", return_value=1000):
            self.assertFalse(self.alerter.should_alert("192.0.2.10", "/example.ico", "HTTP"))
            self.assertTrue(self.alerter.should_alert("192.0.2.10", "", "SSH"))
            self.assertTrue(self.alerter.should_alert("192.0.2.10", "/admin", "HTTP"))


if __name__ == "__main__":
    unittest.main()
