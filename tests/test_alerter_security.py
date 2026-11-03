"""Security regression tests for user-controlled honeypot alert fields."""

import importlib.util
import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import mock_open, patch

ROOT = Path(__file__).resolve().parents[1]
ALERTER_PATH = ROOT / "Beekeeper scripts" / "Slack bot" / "Slack_alerter.py"


class AlertSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("security_alerter", ALERTER_PATH)
        cls.alerter = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {
            "WEBHOOK_TYPE": "discord",
            "WEBHOOK_URL": "https://example.invalid/testing",
        }):
            with patch("builtins.open", mock_open(read_data="")):
                spec.loader.exec_module(cls.alerter)

    def setUp(self):
        self.alerter.WEBHOOK_TYPE = "discord"

    def test_malicious_mentions_and_slack_markup_are_defused(self):
        details = {
            "Protocol": "HTTP",
            "SourceIp": "203.0.113.7",
            "RequestURI": "/admin\n@everyone <@123456> <!here>",
            "UserAgent": "curl\r\n@here",
            "CommandOutput": "<@123456> @everyone",
        }
        for platform in ("discord", "slack"):
            self.alerter.WEBHOOK_TYPE = platform
            message = self.alerter.format_message(details, 2)
            self.assertNotIn("\n@everyone", message)
            self.assertNotIn("@everyone", message)
            self.assertNotIn("@here", message)
            self.assertNotIn("<@", message)
            self.assertNotIn("<!here>", message)
            self.assertIn("Probes in last 60s", message)

    def test_request_and_response_secrets_are_redacted(self):
        details = {
            "Protocol": "HTTP",
            "RequestURI": "/login?password=hunter2&api_key=verysecret",
            "CommandOutput": "Authorization: Bearer PRIVATE_TOKEN",
        }
        message = self.alerter.format_message(details, 1)
        for secret in ("hunter2", "verysecret", "PRIVATE_TOKEN"):
            self.assertNotIn(secret, message)
        self.assertIn("[REDACTED]", message)
        self.assertIn("/login?password=[REDACTED]", message)

    def test_raw_body_headers_and_cookies_are_not_forwarded(self):
        details = {
            "Protocol": "HTTP",
            "Body": "BODY-SENSITIVE-VALUE",
            "Headers": "HEADERS-SENSITIVE-VALUE",
            "HeadersMap": {"Authorization": "MAP-SENSITIVE-VALUE"},
            "Cookies": "COOKIE-SENSITIVE-VALUE",
        }
        message = self.alerter.format_message(details, 1)
        for forbidden in ("BODY-SENSITIVE-VALUE", "HEADERS-SENSITIVE-VALUE",
                          "MAP-SENSITIVE-VALUE", "COOKIE-SENSITIVE-VALUE"):
            self.assertNotIn(forbidden, message)

    def test_optional_field_is_bounded_and_escaped(self):
        details = {"Protocol": "HTTP", "Client": "A" * 300, "Handler": "line1\nline2"}
        message = self.alerter.format_message(details, 1)
        self.assertIn("A" * 150, message)
        self.assertNotIn("A" * 151, message)
        self.assertIn("line1\\nline2", message)

    def test_discord_payload_disables_mentions(self):
        response = SimpleNamespace(status_code=204, headers={})
        with patch.object(self.alerter.requests, "post", return_value=response) as post:
            self.assertTrue(self.alerter._deliver_webhook("hello @everyone"))
        self.assertEqual(post.call_args.kwargs["json"]["allowed_mentions"], {"parse": []})

    def test_webhook_exception_does_not_log_credential_url(self):
        secret_url = "https://example.invalid/webhook/SENSITIVE-WEBHOOK-TOKEN"
        with patch.object(self.alerter, "WEBHOOK_URL", secret_url):
            with patch.object(self.alerter.requests, "post", side_effect=self.alerter.requests.Timeout(secret_url)):
                with patch.object(self.alerter.time, "sleep"):
                    with self.assertLogs(level="ERROR") as captured:
                        self.assertFalse(self.alerter._deliver_webhook("hello"))
        self.assertNotIn(secret_url, "\n".join(captured.output))


if __name__ == "__main__":
    unittest.main()
