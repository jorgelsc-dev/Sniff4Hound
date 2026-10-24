"""Backend contract for the persisted IA activation flag."""

from __future__ import annotations

import json
import tempfile
import unittest
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
        self.assertEqual(self.app.ai_config(self.Request("GET")), {"enabled": False, "model_status": "not_configured"})
        self.assertEqual(self.app.ai_config(self.Request("POST", {"enabled": True})), {"enabled": True, "model_status": "not_configured"})
        self.assertEqual(self.app.ai_config(self.Request("GET")), {"enabled": True, "model_status": "not_configured"})

    def test_invalid_payload_is_rejected_and_does_not_change_state(self):
        for payload in ({}, {"enabled": "true"}, {"enabled": True, "extra": 1}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.app.ai_config(self.Request("POST", payload))
        self.assertEqual(self.app.ai_config(self.Request("GET")), {"enabled": False, "model_status": "not_configured"})
