"""Regression tests for the bounded webhook queue and asynchronous delivery."""

import importlib.util
import os
import unittest
from pathlib import Path
from queue import Queue
from types import SimpleNamespace
from unittest.mock import mock_open, patch


ROOT = Path(__file__).resolve().parents[1]
ALERTER_PATH = ROOT / "Beekeeper scripts" / "Slack bot" / "Slack_alerter.py"


class WebhookQueueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("webhook_queue_alerter", ALERTER_PATH)
        cls.alerter = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {
            "WEBHOOK_TYPE": "discord",
            "WEBHOOK_URL": "https://example.invalid/testing",
        }):
            with patch("builtins.open", mock_open(read_data="")):
                spec.loader.exec_module(cls.alerter)

    def setUp(self):
        self.alerter.WEBHOOK_TYPE = "discord"

    def test_queue_is_bounded_and_never_blocks_producer(self):
        m = self.alerter
        with patch.object(m, "webhook_queue", Queue(maxsize=1)):
            with patch.object(m, "_ensure_webhook_worker") as start_worker:
                self.assertTrue(m.send_alert("one"))
                self.assertFalse(m.send_alert("two"))
                start_worker.assert_called_once()

    def test_worker_posts_queued_messages(self):
        m = self.alerter
        response = SimpleNamespace(status_code=204, headers={})
        with patch.object(m, "webhook_queue", Queue(maxsize=4)):
            with patch.object(m, "webhook_worker_thread", None):
                with patch.object(m.requests, "post", return_value=response) as post:
                    self.assertTrue(m.send_alert("hello"))
                    m.webhook_queue.join()
                    m.stop_webhook_worker()
                    post.assert_called_once_with(
                        "https://example.invalid/testing",
                        json={"content": "hello", "allowed_mentions": {"parse": []}}, timeout=10
                    )

    def test_http_429_retry_after_then_success(self):
        m = self.alerter
        limited = SimpleNamespace(status_code=429, headers={"Retry-After": "4"})
        ok = SimpleNamespace(status_code=200, headers={})
        with patch.object(m.requests, "post", side_effect=[limited, ok]) as post:
            with patch.object(m.time, "sleep") as sleep:
                self.assertTrue(m._deliver_webhook("test"))
                self.assertEqual(post.call_count, 2)
                sleep.assert_called_once_with(4)

    def test_http_400_is_not_retried(self):
        m = self.alerter
        bad = SimpleNamespace(status_code=400, headers={})
        with patch.object(m.requests, "post", return_value=bad) as post:
            with patch.object(m.time, "sleep") as sleep:
                self.assertFalse(m._deliver_webhook("test"))
                post.assert_called_once()
                sleep.assert_not_called()

    def test_http_503_retries_with_bounded_attempts(self):
        m = self.alerter
        unavailable = SimpleNamespace(status_code=503, headers={})
        with patch.object(m.requests, "post", return_value=unavailable) as post:
            with patch.object(m.time, "sleep") as sleep:
                self.assertFalse(m._deliver_webhook("test"))
                self.assertEqual(post.call_count, m.WEBHOOK_MAX_ATTEMPTS)
                self.assertEqual(sleep.call_count, m.WEBHOOK_MAX_ATTEMPTS - 1)

    def test_network_timeout_retries_then_succeeds(self):
        m = self.alerter
        ok = SimpleNamespace(status_code=200, headers={})
        with patch.object(m.requests, "post", side_effect=[m.requests.Timeout("timeout"), ok]) as post:
            with patch.object(m.time, "sleep") as sleep:
                self.assertTrue(m._deliver_webhook("test"))
                self.assertEqual(post.call_count, 2)
                sleep.assert_called_once_with(1)

    def test_shutdown_drains_queued_alerts(self):
        m = self.alerter
        ok = SimpleNamespace(status_code=200, headers={})
        with patch.object(m, "webhook_queue", Queue(maxsize=4)):
            with patch.object(m, "webhook_worker_thread", None):
                with patch.object(m.requests, "post", return_value=ok) as post:
                    self.assertTrue(m.send_alert("first"))
                    self.assertTrue(m.send_alert("second"))
                    m.stop_webhook_worker()
                    self.assertEqual(post.call_count, 2)
                    self.assertFalse(m.webhook_worker_thread.is_alive())

    def test_slack_format_and_discord_limit(self):
        m = self.alerter
        ok = SimpleNamespace(status_code=200, headers={})
        with patch.object(m.requests, "post", return_value=ok) as post:
            m.WEBHOOK_TYPE = "discord"
            self.assertTrue(m._deliver_webhook("X" * 2100))
            self.assertEqual(len(post.call_args.kwargs["json"]["content"]), 2000)
            m.WEBHOOK_TYPE = "slack"
            self.assertTrue(m._deliver_webhook("hello"))
            self.assertEqual(post.call_args.kwargs["json"], {"text": "hello"})


if __name__ == "__main__":
    unittest.main()
