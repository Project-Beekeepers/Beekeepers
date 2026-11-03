"""MITRE ATT&CK candidate tagging regression tests (no webhook network calls)."""

import importlib.util
import os
import unittest
from pathlib import Path
from unittest.mock import mock_open, patch

ROOT = Path(__file__).resolve().parents[1]
ALERTER_PATH = ROOT / "Beekeeper scripts" / "Slack bot" / "Slack_alerter.py"


class MitreAttackMappingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("mitre_alerter", ALERTER_PATH)
        cls.alerter = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {
            "WEBHOOK_TYPE": "discord",
            "WEBHOOK_URL": "https://example.invalid/testing",
        }):
            with patch("builtins.open", mock_open(read_data="")):
                spec.loader.exec_module(cls.alerter)

    def test_http_env_probe_maps_to_vulnerability_scanning(self):
        details = {"Protocol": "HTTP", "RequestURI": "/.env?x=1"}
        match = self.alerter.mitre_attack_candidate(details)
        self.assertEqual(match[:3], ("T1595.002", "Vulnerability Scanning", "Reconnaissance"))

    def test_http_git_config_probe_supports_absolute_url(self):
        details = {"Protocol": "http", "RequestURI": "https://honeypot.invalid/.GIT/CONFIG"}
        self.assertEqual(self.alerter.mitre_attack_candidate(details)[0], "T1595.002")

    def test_normal_http_request_does_not_get_mitre_label(self):
        self.assertIsNone(self.alerter.mitre_attack_candidate(
            {"Protocol": "HTTP", "RequestURI": "/about"}, 1))

    def test_repeated_http_activity_maps_to_possible_scanning(self):
        details = {"Protocol": "HTTP", "RequestURI": "/random"}
        self.assertEqual(self.alerter.mitre_attack_candidate(details, 5)[0], "T1595")

    def test_http_repeated_threshold_not_reached(self):
        details = {"Protocol": "HTTP", "RequestURI": "/random"}
        self.assertIsNone(self.alerter.mitre_attack_candidate(details, 4))

    def test_explicit_ssh_shell_command_maps_to_unix_shell(self):
        details = {"Protocol": "SSH", "Msg": "SSH raw command", "Command": "/bin/bash -c id"}
        self.assertEqual(self.alerter.mitre_attack_candidate(details)[0], "T1059.004")

    def test_other_ssh_commands_not_automatically_mapped(self):
        details = {"Protocol": "SSH", "Msg": "SSH raw command", "Command": "uname -a"}
        self.assertIsNone(self.alerter.mitre_attack_candidate(details))

    def test_repeated_ssh_login_attempt_is_only_possible_bruteforce(self):
        details = {"Protocol": "SSH", "Msg": "New SSH login attempt"}
        self.assertIsNone(self.alerter.mitre_attack_candidate(details, 1))
        self.assertEqual(self.alerter.mitre_attack_candidate(details, 5)[0], "T1110")

    def test_unsupported_and_malformed_events_remain_unmapped(self):
        self.assertIsNone(self.alerter.mitre_attack_candidate("not an event"))
        self.assertIsNone(self.alerter.mitre_attack_candidate({"Protocol": "TCP"}, 100))
        self.assertIsNone(self.alerter.mitre_attack_candidate({"Protocol": "HTTP", "RequestURI": 42}, 100))
        self.assertIsNone(self.alerter.mitre_attack_candidate({"Protocol": "HTTP", "RequestURI": "/foo"}, "5"))

    def test_formatted_alert_includes_tentative_label_without_leaking_secret(self):
        details = {"Protocol": "HTTP", "RequestURI": "/.env?token=hunter2"}
        message = self.alerter.format_message(details, 1)
        self.assertIn("Possible MITRE ATT&CK", message)
        self.assertIn("T1595.002", message)
        self.assertNotIn("hunter2", message)
        normal = self.alerter.format_message({"Protocol": "HTTP", "RequestURI": "/"}, 1)
        self.assertNotIn("Possible MITRE ATT&CK", normal)


if __name__ == "__main__":
    unittest.main()
