import importlib.util
import os
import unittest
from pathlib import Path
from unittest.mock import mock_open, patch


ROOT = Path(__file__).resolve().parents[1]
ALERTER_PATH = ROOT / "Beekeeper scripts" / "Slack bot" / "Slack_alerter.py"


class AdditionalFieldsTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "additional_fields_alerter", ALERTER_PATH
        )
        cls.alerter = importlib.util.module_from_spec(spec)

        with patch.dict(os.environ, {
            "WEBHOOK_TYPE": "discord",
            "WEBHOOK_URL": "https://example.invalid/testing",
        }):
            with patch("builtins.open", mock_open(read_data="")):
                spec.loader.exec_module(cls.alerter)

    def test_additional_fields_are_displayed(self):
        details = {
            "Protocol": "HTTP",
            "SourceIp": "192.0.2.10",
            "SourcePort": 54321,
            "UserAgent": "curl/8.5.0",
            "Status": 401,
            "ID": "session-123",
        }

        message = self.alerter.format_message(details, 3, 2)

        self.assertIn("Source Port:** 54321", message)
        self.assertIn("User Agent:** curl/8.5.0", message)
        self.assertIn("Status:** 401", message)
        self.assertIn("Session ID:** session-123", message)
        self.assertIn("last alert:** 2", message)

    def test_missing_fields_are_hidden(self):
        details = {
            "Protocol": "SSH",
            "SourceIp": "192.0.2.11",
        }

        message = self.alerter.format_message(details, 1)

        self.assertNotIn("Source Port:", message)
        self.assertNotIn("User Agent:", message)
        self.assertNotIn("Session ID:", message)

    def test_extra_fields_are_truncated_and_newlines_escaped(self):
        details = {
            "Protocol": "HTTP",
            "UserAgent": "A" * 200,
            "Client": "test\ninjected",
        }

        message = self.alerter.format_message(details, 1)

        self.assertIn("A" * 150, message)
        self.assertNotIn("A" * 151, message)
        self.assertIn("test\\ninjected", message)


if __name__ == "__main__":
    unittest.main()