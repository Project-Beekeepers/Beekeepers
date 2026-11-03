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


class SSHSessionAlertTests(unittest.TestCase):
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
            "pr5_ssh_session_alerter", work / "Slack_alerter.py"
        )
        cls.mod = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {"WEBHOOK_TYPE": "discord", "WEBHOOK_URL": "http://127.0.0.1:9/not-real"}):
            spec.loader.exec_module(cls.mod)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.mod.last_alerted.clear()
        self.mod.request_times.clear()
        self.mod.ssh_command_state.clear()
        self.mod.SSH_COMMANDS_PER_ALERT = 1
        self.mod.SSH_COMMAND_COOLDOWN_SECONDS = 0
        self.mod.SSH_SESSION_STATE_TTL_SECONDS = 3600
        self.mod.ALERT_ON_SSH_SESSION_END = False
        self.messages = []
        self.sender = patch.object(self.mod, "send_alert", side_effect=self.messages.append)
        self.sender.start()
        self.addCleanup(self.sender.stop)

    def event(self, msg, *, ip="192.0.2.10", session="session-a", command="", protocol="SSH", **extras):
        event = {
            "Protocol": protocol, "Msg": msg, "SourceIp": ip,
            "ID": session, "Command": command, "CommandOutput": "ok",
            "RequestURI": "", "DateTime": "2026-11-03T00:00:00Z",
        }
        event.update(extras)
        self.mod.handle_line(json.dumps({"msg": "New Event", "event": event}))

    def test_login_then_command_both_alert_within_five_minutes(self):
        with patch.object(self.mod.time, "time", return_value=1000):
            self.event("New SSH Login Attempt", command="")
            self.event("SSH Terminal Session Interaction", command="whoami")
        self.assertEqual(len(self.messages), 2)
        self.assertIn("whoami", self.messages[1])

    def test_multiple_commands_are_not_suppressed_by_default(self):
        with patch.object(self.mod.time, "time", return_value=1000):
            self.event("SSH Terminal Session Interaction", command="pwd")
            self.event("SSH Terminal Session Interaction", command="ls")
        self.assertEqual(len(self.messages), 2)
        self.assertIn("pwd", self.messages[0])
        self.assertIn("ls", self.messages[1])
        self.assertEqual(self.mod.ssh_command_state, {})

    def test_raw_ssh_command_is_classified_as_command(self):
        self.event("SSH Raw Command", command="id")
        self.assertEqual(len(self.messages), 1)
        self.assertIn("id", self.messages[0])

    def test_end_event_suppressed_even_without_source_ip(self):
        self.event("End SSH Session", ip="", command="", CommandOutput="")
        self.assertEqual(self.messages, [])

    def test_end_event_can_be_enabled(self):
        self.mod.ALERT_ON_SSH_SESSION_END = True
        self.event("End SSH Session", ip="", command="", CommandOutput="")
        self.assertEqual(len(self.messages), 1)

    def test_non_ssh_end_is_not_filtered(self):
        self.event("End SSH Session", protocol="TELNET")
        self.assertEqual(len(self.messages), 1)

    def test_configurable_command_threshold_per_session(self):
        self.mod.SSH_COMMANDS_PER_ALERT = 2
        self.event("SSH Terminal Session Interaction", session="A", command="first")
        self.event("SSH Terminal Session Interaction", session="B", command="first")
        self.assertEqual(len(self.messages), 0)
        self.event("SSH Terminal Session Interaction", session="A", command="second")
        self.assertEqual(len(self.messages), 1)
        self.event("SSH Terminal Session Interaction", session="B", command="second")
        self.assertEqual(len(self.messages), 2)

    def test_command_cooldown_independent_of_login_and_other_session(self):
        self.mod.SSH_COMMAND_COOLDOWN_SECONDS = 60
        with patch.object(self.mod.time, "time", return_value=1000):
            self.event("New SSH Login Attempt", session="login")
            self.event("SSH Terminal Session Interaction", session="A", command="pwd")
            self.event("SSH Terminal Session Interaction", session="A", command="ls")
            self.event("SSH Terminal Session Interaction", session="B", command="whoami")
        self.assertEqual(len(self.messages), 3)
        with patch.object(self.mod.time, "time", return_value=1061):
            self.event("SSH Terminal Session Interaction", session="A", command="id")
        self.assertEqual(len(self.messages), 4)

    def test_session_end_clears_command_state(self):
        self.mod.SSH_COMMANDS_PER_ALERT = 2
        self.event("SSH Terminal Session Interaction", session="A", command="pwd")
        self.assertEqual(len(self.mod.ssh_command_state), 1)
        self.event("End SSH Session", session="A", ip="", CommandOutput="")
        self.assertEqual(len(self.mod.ssh_command_state), 0)

    def test_expired_session_state_is_pruned(self):
        self.mod.SSH_COMMANDS_PER_ALERT = 2
        self.mod.SSH_SESSION_STATE_TTL_SECONDS = 60
        with patch.object(self.mod.time, "time", return_value=1000):
            self.event("SSH Terminal Session Interaction", session="A", command="pwd")
        with patch.object(self.mod.time, "time", return_value=1061):
            self.event("SSH Terminal Session Interaction", session="B", command="pwd")
        self.assertEqual(len(self.mod.ssh_command_state), 1)

    def test_http_and_login_use_existing_filter(self):
        with patch.object(self.mod.time, "time", return_value=1000):
            self.event("HTTP New request", protocol="HTTP", command="", RequestURI="/admin", HTTPMethod="GET")
            self.event("HTTP New request", protocol="HTTP", command="", RequestURI="/login", HTTPMethod="GET")
        self.assertEqual(len(self.messages), 1)

    def test_ssh_unrecognised_event_retains_original_filter(self):
        with patch.object(self.mod.time, "time", return_value=1000):
            self.event("New SSH Terminal Session", session="A")
            self.event("New SSH Terminal Session", session="B")
        self.assertEqual(len(self.messages), 1)

    def test_protocol_and_event_message_case_insensitive(self):
        self.event(" sSh terminal session interaction ", protocol=" ssh ", command="hostname")
        self.assertEqual(len(self.messages), 1)

    def test_unrelated_outer_message_is_ignored(self):
        self.mod.handle_line(json.dumps({"msg": "Startup", "event": {"Protocol":"SSH","Msg":"SSH Raw Command"}}))
        self.assertEqual(len(self.messages), 0)


if __name__ == "__main__":
    unittest.main()
