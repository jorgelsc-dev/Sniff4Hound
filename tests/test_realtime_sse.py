"""The SSE realtime channel: streamed events down, POSTed actions up.

Drives the real app through dispatch(), the same entry point the HTTP/1.1,
HTTP/2 and HTTP/3 listeners use, so the auth guards and routing apply.
"""

import importlib
import json
import os
import sys
import unittest

from wsbuilder import Request


def _close_app_store(module):
    store = getattr(module, "store", None)
    if store is None:
        return
    try:
        store.close()
    except Exception:
        pass


def _reload_app_stack(test_case, require_auth: str = "1"):
    """Reload sniff4hound.app/.auth with SNIFF4HOUND_REQUIRE_AUTH pinned for the
    test, and restore the previous environment and modules afterwards."""
    previous = os.environ.get("SNIFF4HOUND_REQUIRE_AUTH")

    def _restore():
        if previous is None:
            os.environ.pop("SNIFF4HOUND_REQUIRE_AUTH", None)
        else:
            os.environ["SNIFF4HOUND_REQUIRE_AUTH"] = previous
        import sniff4hound.app as app_module
        import sniff4hound.auth as auth_module

        _close_app_store(sys.modules.get("sniff4hound.app"))
        importlib.reload(auth_module)
        importlib.reload(app_module)

    test_case.addCleanup(_restore)

    os.environ["SNIFF4HOUND_REQUIRE_AUTH"] = require_auth
    import sniff4hound.app as app_module
    import sniff4hound.auth as auth_module

    _close_app_store(sys.modules.get("sniff4hound.app"))
    auth_module = importlib.reload(auth_module)
    app_module = importlib.reload(app_module)
    return auth_module, app_module


def _request(path, *, query="", headers=None, client=("203.0.113.10", 4444), method="GET", body=b""):
    if isinstance(body, str):
        body = body.encode("utf-8")
    return Request(method, path, query, dict(headers or {}), body, client)


class RealtimeSseTests(unittest.TestCase):
    def setUp(self):
        self.auth, self.app = _reload_app_stack(self, "1")
        self.auth._SESSION_TOKEN = "Ab12Cd34"
        self.auth.RATE_LIMITER.reset()
        self.addCleanup(self.auth.RATE_LIMITER.reset)

    def _session_for(self, request):
        session = self.app.RealtimeSession(self.app._client_address(request))
        with self.app._REALTIME_LOCK:
            self.app._REALTIME_SESSIONS[session.id] = session
        self.addCleanup(self.app._REALTIME_SESSIONS.pop, session.id, None)
        return session

    def test_stream_without_a_ticket_answers_auth_required_and_closes_4401(self):
        response = self.app.app.dispatch(_request("/realtime/stream"))
        self.assertEqual(response.status, 200)
        self.assertEqual(response.headers.get("content-type"), "text/event-stream")
        body = response.body.decode("utf-8")
        self.assertIn('"type": "auth_required"', body)
        self.assertIn("event: close", body)
        self.assertIn('"code": 4401', body)

    def test_command_for_an_unknown_session_is_gone(self):
        response = self.app.app.dispatch(
            _request(
                "/api/realtime/command",
                query="session=not-a-session",
                method="POST",
                headers={
                    "x-security-code": "Ab12Cd34",
                    "host": "127.0.0.1:45678",
                    "origin": "https://127.0.0.1:45678",
                },
                body='{"action": "ping"}',
            )
        )
        self.assertEqual(response.status, 410)

    def test_a_command_is_answered_on_the_session_stream(self):
        request = _request(
            "/api/realtime/command",
            method="POST",
            headers={
                "x-security-code": "Ab12Cd34",
                "host": "127.0.0.1:45678",
                "origin": "https://127.0.0.1:45678",
            },
            body='{"action": "ping"}',
        )
        session = self._session_for(request)
        request.query = {"session": session.id}
        response = self.app.app.dispatch(request)
        self.assertEqual(response.status, 202)

        kind, value = session.next_event(1.0)
        self.assertEqual(kind, "data")
        self.assertEqual(json.loads(value)["type"], "pong")

    def test_a_command_body_must_be_a_json_object(self):
        request = _request(
            "/api/realtime/command",
            method="POST",
            headers={
                "x-security-code": "Ab12Cd34",
                "host": "127.0.0.1:45678",
                "origin": "https://127.0.0.1:45678",
            },
            body="[1, 2]",
        )
        session = self._session_for(request)
        request.query = {"session": session.id}
        self.assertEqual(self.app.app.dispatch(request).status, 400)

    def test_a_session_is_dropped_when_its_client_stops_reading(self):
        session = self.app.RealtimeSession("203.0.113.10")
        for _ in range(self.app.REALTIME_QUEUE_LIMIT):
            session.send_text("{}")
        with self.assertRaises(ConnectionError):
            session.send_text("{}")

    def test_a_closed_session_refuses_further_messages(self):
        session = self.app.RealtimeSession("203.0.113.10")
        session.close(1000, "bye")
        with self.assertRaises(ConnectionError):
            session.send_text("{}")
        kind, value = session.next_event(1.0)
        self.assertEqual(kind, "close")
        self.assertEqual(value["code"], 1000)


if __name__ == "__main__":
    unittest.main()
