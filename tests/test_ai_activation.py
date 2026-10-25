"""Backend contract for the persisted IA activation flag."""

from __future__ import annotations

import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from sniff4hound.store import SniffStore


class AiStoreConfigTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = SniffStore(str(Path(self._tmp.name) / "ai.db"))
        self.addCleanup(self.store.close)

    def test_defaults_off_and_persists_across_connections(self):
        self.assertFalse(self.store.get_ai_enabled())
        self.assertTrue(self.store.set_ai_enabled(True))
        self.store.close()
        reopened = SniffStore(str(Path(self._tmp.name) / "ai.db"))
        self.addCleanup(reopened.close)
        self.assertTrue(reopened.get_ai_enabled())

    def test_rejects_non_boolean_without_writing(self):
        for value in ("true", 1, 0, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.store.set_ai_enabled(value)
        self.assertFalse(self.store.get_ai_enabled())


class AiConfigApiTests(unittest.TestCase):
    class Request:
        def __init__(self, method, payload=None):
            self.method = method
            self.query = {}
            self._payload = "" if payload is None else json.dumps(payload)

        def text(self):
            return self._payload

    def setUp(self):
        import sniff4hound.app as app

        self.app = app
        self.previous = app.store.get_runtime_config("ai_enabled", "")
        self.addCleanup(self._restore)
        app.store.set_runtime_config("ai_enabled", "")

    def _restore(self):
        if self.previous == "":
            self.app.store._execute("DELETE FROM runtime_config WHERE key = ?", ("ai_enabled",), commit=True)
        else:
            self.app.store.set_runtime_config("ai_enabled", self.previous)

    def test_get_post_and_get_round_trip(self):
        initial = self.app.ai_config(self.Request("GET"))
        self.assertFalse(initial["enabled"])
        self.assertEqual(initial["model_status"], "ready")
        self.assertEqual(initial["provider"], "Local aggregate engine")
        saved = self.app.ai_config(self.Request("POST", {"enabled": True}))
        self.assertTrue(saved["enabled"])
        self.assertEqual(saved["model"], "sniff4hound-aggregate-risk-v1")
        self.assertEqual(self.app.ai_config(self.Request("GET"))["enabled"], True)

    def test_invalid_payload_is_rejected_and_does_not_change_state(self):
        for payload in ({}, {"enabled": "true"}, {"enabled": True, "extra": 1}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.app.ai_config(self.Request("POST", payload))
        self.assertFalse(self.app.ai_config(self.Request("GET"))["enabled"])

    def test_analysis_runs_only_when_enabled_and_returns_explainable_metrics(self):
        disabled = self.app.ai_analysis(self.Request("POST", {}))
        self.assertEqual(disabled["status"], "disabled")
        self.app.store.set_runtime_config("ai_enabled", "1")
        with patch.object(
            self.app.store,
            "analytics_snapshot",
            return_value={
                "summary": {"targets": 2, "ports": 40, "open_ports": 6, "banners": 3, "tags": 1, "unique_hosts": 4},
                "ports_by_proto": [{"label": "TCP", "value": 2}] * 4,
                "risk_ports": [{"port": 22}] * 2,
            },
        ):
            result = self.app.ai_analysis(self.Request("POST", {}))
        self.assertEqual(result["status"], "completed")
        self.assertIn(result["result"]["label"], {"bajo", "medio", "alto"})
        self.assertEqual(result["result"]["source"], "aggregate_metrics")
        self.assertEqual(result["result"]["features"]["open_ports"], 6)
        self.assertGreaterEqual(result["total_runs"], 1)
