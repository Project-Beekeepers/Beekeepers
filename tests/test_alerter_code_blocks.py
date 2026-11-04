"""Security regression tests for rendering attacker-controlled values as code."""

import importlib.util
import os
import re
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import mock_open, patch

ROOT = Path(__file__).resolve().parents[1]
ALERTER_PATH = ROOT / "Beekeeper scripts" / "Slack bot" / "Slack_alerter.py"


class CodeBlockSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("codeblock_alerter", ALERTER_PATH)
        cls.alerter = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {
            "WEBHOOK_TYPE": "discord",
            "WEBHOOK_URL": "https://example.invalid/testing",
        }):
            with patch("builtins.open", mock_open(read_data="")):
                spec.loader.exec_module(cls.alerter)

    def setUp(self):
        self.alerter.WEBHOOK_TYPE = "discord"

    @staticmethod
    def blocks(message):
        return re.findall(r"(?m)^```\n([^\n]*)\n```$", message)

    def test_attacker_content_is_fenced_and_backticks_are_neutralized(self):
        details = {
            "Protocol": "HTTP",
            "HTTPMethod": "GET",
            "RequestURI": "/admin```\nFAKE ADMIN ALERT\n```",
            "Description": "a`b``c```d",
            "CommandOutput": "response ``` @everyone <@123>",
            "SourceIp": "192.0.2.10",
            "UserAgent": "curl```\nFAKE SECURITY WARNING",
        }
        for platform in ("discord", "slack"):
            with self.subTest(platform=platform):
                self.alerter.WEBHOOK_TYPE = platform
                message = self.alerter.format_message(details, 1)
                blocks = self.blocks(message)
                self.assertEqual(len(blocks), 7)
                self.assertTrue(any("FAKE ADMIN ALERT" in value for value in blocks))
                self.assertTrue(any("FAKE SECURITY WARNING" in value for value in blocks))
                self.assertIn("\\nFAKE ADMIN ALERT", message)
                self.assertNotIn("\nFAKE ADMIN ALERT", message)
                self.assertNotIn("@everyone", message)
                self.assertNotIn("<@123>", message)
                self.assertNotIn("`", message.replace("```", ""))
                self.assertIn("\u02cb\u02cb\u02cb", message)

    def test_untrusted_fields_are_inside_individual_code_blocks(self):
        details = {
            "DateTime": "2026-11-04T00:00:00Z",
            "Protocol": "HTTP", "SourceIp": "203.0.113.4",
            "RequestURI": "/login", "Description": "Test service",
            "CommandOutput": "Unauthorized",
            "SourcePort": 4232, "Status": "Stateless", "ID": "session-123",
            "Handler": "static", "Client": {"name": "browser"},
        }
        message = self.alerter.format_message(details, 1)
        blocks = self.blocks(message)
        self.assertEqual(len(blocks), 11)
        for expected in ("203.0.113.4", "/login", "Unauthorized", "4232", "session-123", "static"):
            self.assertTrue(any(expected in block for block in blocks), expected)
        self.assertIn("**Probes in last 60s:** 1", message)

    def test_raw_newlines_and_secrets_are_still_sanitized(self):
        message = self.alerter.format_message({
            "Protocol": "SSH", "Command": "echo test\nAuthorization: Bearer MYSUPERSECRET",
            "CommandOutput": "password=hunter2\r\n@here",
        }, 1)
        self.assertNotIn("hunter2", message)
        self.assertNotIn("MYSUPERSECRET", message)
        self.assertNotIn("@here", message)
        self.assertIn("[REDACTED]", message)
        self.assertIn("\\n", message)
        self.assertEqual(message.count("```"), 12)

    def test_optional_empty_fields_stay_hidden(self):
        message = self.alerter.format_message({"Protocol": "HTTP", "UserAgent": "", "Client": None}, 1)
        self.assertNotIn("User Agent:", message)
        self.assertNotIn("Client:", message)
        self.assertEqual(len(self.blocks(message)), 6)

    def test_discord_limit_does_not_leave_open_code_fence(self):
        details = {
            "Protocol": "HTTP", "SourceIp": "203.0.113.4",
            "RequestURI": "/" + "r" * 550,
            "Description": "d" * 240,
            "CommandOutput": "o" * 550,
        }
        for key in ("UserAgent", "Client", "Handler", "ID", "HostHTTPRequest", "TLSServerName"):
            details[key] = "z" * 180
        long_message = self.alerter.format_message(details, 1)
        self.assertGreater(len(long_message), 2000)
        clipped = self.alerter._discord_content(long_message)
        self.assertLessEqual(len(clipped), 2000)
        self.assertTrue(clipped.endswith("[alert truncated]"))
        self.assertEqual(clipped.count("```") % 2, 0)
        # Every included code block must have a matching closing fence.
        self.assertEqual(clipped.count("```"), len(self.blocks(clipped)) * 2)

    def test_worker_payload_preserves_safe_fences(self):
        details = {"Protocol": "HTTP", "RequestURI": "/``````"}
        message = self.alerter.format_message(details, 1)
        response = SimpleNamespace(status_code=204, headers={})
        with patch.object(self.alerter.requests, "post", return_value=response) as post:
            self.assertTrue(self.alerter._deliver_webhook(message))
        sent = post.call_args.kwargs["json"]
        self.assertEqual(sent["content"], message)
        self.assertEqual(sent["allowed_mentions"], {"parse": []})
        self.assertNotIn("`", message.replace("```", ""))

    def test_plain_text_discord_truncation_is_backward_compatible(self):
        self.assertEqual(self.alerter._discord_content("x" * 2100), "x" * 2000)


if __name__ == "__main__":
    unittest.main()
