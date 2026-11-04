"""Tests for PR #6: reporting events suppressed by the ordinary alert cooldown."""

import importlib.util
import json
import os
import unittest
from pathlib import Path
from unittest.mock import mock_open, patch


ROOT = Path(__file__).resolve().parents[1]
ALERTER_PATH = ROOT / "Beekeeper scripts" / "Slack bot" / "Slack_alerter.py"


class SuppressedEventCountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("pr6_suppressed_event_alerter", ALERTER_PATH)
        cls.alerter = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {"WEBHOOK_TYPE": "discord", "WEBHOOK_URL": "https://example.invalid/testing"}):
            with patch("builtins.open", mock_open(read_data="")):
                spec.loader.exec_module(cls.alerter)

    def setUp(self):
        m = self.alerter
        m.WEBHOOK_TYPE = "discord"
        m.COOLDOWN_SECONDS = 300
        m.PROBE_THRESHOLD = 1
        m.PROBE_WINDOW_SECONDS = 60
        m.IGNORE_PATHS = {"/example.ico"}
        m.last_alerted.clear()
        m.request_times.clear()
        m.cooldown_suppressed.clear()
        self.now = [1000.0]
        clock = patch.object(m.time, "time", side_effect=lambda: self.now[0])
        self.addCleanup(clock.stop)
        clock.start()
        self.sender = patch.object(m, "send_alert")
        self.send = self.sender.start()
        self.addCleanup(self.sender.stop)

    def event(self, ip="192.0.2.10", path="/login", protocol="HTTP"):
        return json.dumps({"msg": "New Event", "event": {
            "SourceIp": ip,
            "RequestURI": path,
            "Protocol": protocol,
            "HTTPMethod": "GET",
            "DateTime": "2026-11-03T10:00:00Z",
            "Description": "Test honeypot",
        }})

    def sent_messages(self):
        return [call.args[0] for call in self.send.call_args_list]

    def test_first_alert_has_zero_suppressed(self):
        self.alerter.handle_line(self.event())
        self.assertEqual(len(self.sent_messages()), 1)
        self.assertIn("Events suppressed by cooldown since last alert:** 0", self.sent_messages()[0])
        self.assertEqual(dict(self.alerter.cooldown_suppressed), {})

    def test_repeated_events_are_counted_during_cooldown(self):
        self.alerter.handle_line(self.event())
        for second in (1, 2, 3):
            self.now[0] = 1000 + second
            self.alerter.handle_line(self.event(path=f"/test{second}"))
        self.assertEqual(self.alerter.cooldown_suppressed[("192.0.2.10", "HTTP")], 3)
        self.assertEqual(len(self.sent_messages()), 1)

    def test_next_alert_reports_count_and_resets(self):
        self.alerter.handle_line(self.event())
        for second in (10, 20):
            self.now[0] = 1000 + second
            self.alerter.handle_line(self.event())
        self.now[0] = 1300.0
        self.alerter.handle_line(self.event())
        self.assertEqual(len(self.sent_messages()), 2)
        self.assertIn("Events suppressed by cooldown since last alert:** 2", self.sent_messages()[1])
        self.assertNotIn(("192.0.2.10", "HTTP"), self.alerter.cooldown_suppressed)
    def test_suppression_count_is_independent_per_ip(self):
        self.alerter.handle_line(self.event(ip="192.0.2.10"))
        self.alerter.handle_line(self.event(ip="192.0.2.11"))
        self.now[0] += 1
        self.alerter.handle_line(self.event(ip="192.0.2.10"))
        self.alerter.handle_line(self.event(ip="192.0.2.10"))
        self.alerter.handle_line(self.event(ip="192.0.2.11"))
        self.now[0] += 300
        self.alerter.handle_line(self.event(ip="192.0.2.11"))
        self.alerter.handle_line(self.event(ip="192.0.2.10"))
        self.assertIn("last alert:** 1", self.sent_messages()[-2])
        self.assertIn("last alert:** 2", self.sent_messages()[-1])

    def test_ignored_path_is_not_counted(self):
        self.alerter.handle_line(self.event())
        self.now[0] += 1
        self.alerter.handle_line(self.event(path="/example.ico"))
        self.assertEqual(dict(self.alerter.cooldown_suppressed), {})
        self.now[0] = 1300
        self.alerter.handle_line(self.event())
        self.assertIn("last alert:** 0", self.sent_messages()[-1])

    def test_below_threshold_is_not_counted(self):
        self.alerter.PROBE_THRESHOLD = 3
        self.alerter.handle_line(self.event())
        self.alerter.handle_line(self.event())
        self.assertEqual(dict(self.alerter.cooldown_suppressed), {})
        self.alerter.handle_line(self.event())
        self.assertEqual(len(self.sent_messages()), 1)
        self.alerter.handle_line(self.event())
        self.assertEqual(self.alerter.cooldown_suppressed[("192.0.2.10", "HTTP")], 1)

    def test_cooldown_boundary_allows_next_alert(self):
        self.assertTrue(self.alerter.should_alert("192.0.2.10", "/"))
        self.now[0] += 299.999
        self.assertFalse(self.alerter.should_alert("192.0.2.10", "/"))
        self.assertEqual(self.alerter.cooldown_suppressed[("192.0.2.10", "UNKNOWN")], 1)
        self.now[0] += 0.001
        self.assertTrue(self.alerter.should_alert("192.0.2.10", "/"))

    def test_count_survives_long_gap_until_next_alert(self):
        self.alerter.handle_line(self.event())
        self.now[0] = 1001
        self.alerter.handle_line(self.event())
        self.now[0] = 2000
        self.alerter.handle_line(self.event())
        self.assertIn("last alert:** 1", self.sent_messages()[-1])

    def test_second_cycle_reports_only_new_suppressions(self):
        self.alerter.handle_line(self.event())
        self.now[0] = 1010
        self.alerter.handle_line(self.event())
        self.now[0] = 1300
        self.alerter.handle_line(self.event())
        self.now[0] = 1600
        self.alerter.handle_line(self.event())
        self.assertIn("last alert:** 1", self.sent_messages()[1])
        self.assertIn("last alert:** 0", self.sent_messages()[2])

    def test_format_message_accepts_old_two_argument_style(self):
        message = self.alerter.format_message({"Protocol": "HTTP", "SourceIp": "192.0.2.10"}, 1)
        self.assertIn("Events suppressed by cooldown since last alert:** 0", message)
        self.assertIn("Probes in last 60s:** 1", message)

    def test_slack_uses_single_asterisks(self):
        self.alerter.WEBHOOK_TYPE = "slack"
        message = self.alerter.format_message({}, 3, 12)
        self.assertIn("*Events suppressed by cooldown since last alert:* 12", message)

    def test_unrelated_log_and_invalid_json_are_not_counted(self):
        self.alerter.handle_line(self.event())
        self.alerter.handle_line("not json")
        self.alerter.handle_line(json.dumps({"msg": "Starting service", "event": {
            "SourceIp": "192.0.2.10", "RequestURI": "/"
        }}))
        self.assertEqual(dict(self.alerter.cooldown_suppressed), {})
        self.assertEqual(len(self.sent_messages()), 1)

    def test_uses_existing_webhook_transport(self):
        self.alerter.handle_line(self.event())
        self.send.assert_called_once()
        self.assertIn("New HTTP request", self.send.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
