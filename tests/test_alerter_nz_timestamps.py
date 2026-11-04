"""Verify New Zealand timestamp formatting without sending webhook requests."""

import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "Beekeeper scripts" / "Slack bot" / "Slack_alerter.py"


class AlerterNZTimestampTests(unittest.TestCase):
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
            "beekeepers_alerter_nz_test", test_dir / "Slack_alerter.py"
        )
        cls.alerter = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {"WEBHOOK_TYPE": "discord", "WEBHOOK_URL": "http://127.0.0.1:9/not-real"}):
            spec.loader.exec_module(cls.alerter)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_summer_uses_nzdt_utc_plus_13(self):
        self.assertEqual(
            self.alerter.format_nz_timestamp("2026-01-15T12:00:00Z"),
            "16 Jan 2026 01:00:00 NZDT",
        )

    def test_winter_uses_nzst_utc_plus_12(self):
        self.assertEqual(
            self.alerter.format_nz_timestamp("2026-07-15T12:00:00Z"),
            "16 Jul 2026 00:00:00 NZST",
        )

    def test_existing_offset_is_respected(self):
        self.assertEqual(
            self.alerter.format_nz_timestamp("2026-01-15T14:00:00+02:00"),
            "16 Jan 2026 01:00:00 NZDT",
        )

    def test_missing_and_invalid_timestamps_are_safe(self):
        self.assertEqual(self.alerter.format_nz_timestamp(None), "Unknown")
        self.assertEqual(self.alerter.format_nz_timestamp(""), "Unknown")
        self.assertEqual(self.alerter.format_nz_timestamp("not-a-time"), "not-a-time")
        self.assertEqual(
            self.alerter.format_nz_timestamp("2026-01-15T12:00:00"),
            "2026-01-15T12:00:00",
        )

    def test_formatted_alert_contains_new_zealand_time(self):
        result = self.alerter.format_message(
            {
                "DateTime": "2026-11-03T06:15:03Z",
                "Protocol": "HTTP",
                "SourceIp": "192.0.2.10",
                "HTTPMethod": "GET",
                "RequestURI": "/",
                "CommandOutput": "",
            },
            1,
        )
        self.assertIn("Time (NZ):**\n```\n03 Nov 2026 19:15:03 NZDT\n```", result)
        self.assertIn("Source IP:**\n```\n192.0.2.10\n```", result)


if __name__ == "__main__":
    unittest.main()
