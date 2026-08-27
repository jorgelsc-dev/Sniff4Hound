"""Regression tests for the authentication hardening work.

Covers, in order:

- C-01: no fixed default JWT signing secret. Two installations that never
  set SNIFF4HOUND_JWT_SECRET must not accept each other's tokens, and a token
  signed with the literal that used to be hard-coded must be rejected.
- M-04: issuer/audience/key-id/nbf validation, a bounded `expires_in`, a
  `jti` that can be revoked, and secret rotation invalidating everything.
- M-01: the per-source failed-authentication limiter and its backoff.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import sniff4hound.auth as auth
import sniff4hound.settings as settings


# The literal that shipped in sniff4hound/auth.py as the default signing key.
# It must never authenticate anything again.
LEAKED_DEFAULT_SECRET = "sniff4hound-local-signing-key"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _forge(secret: str, payload: dict, header: dict | None = None) -> str:
    head = _b64(json.dumps(header or {"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    signature = _b64(hmac.new(secret.encode("utf-8"), f"{head}.{body}".encode(), hashlib.sha256).digest())
    return f"{head}.{body}.{signature}"


def _reload_auth_with(env: dict[str, str]):
    """Reload settings+auth under a specific environment, the way a fresh
    process would resolve them."""
    with patch.dict(os.environ, env, clear=False):
        for key, value in list(env.items()):
            if value is None:
                os.environ.pop(key, None)
        importlib.reload(settings)
        return importlib.reload(auth)


class JwtSecretTests(unittest.TestCase):
    """C-01: the signing secret is per-installation, never a constant."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        # Always put the modules back the way the rest of the suite expects.
        self.addCleanup(lambda: importlib.reload(auth))
        self.addCleanup(lambda: importlib.reload(settings))

    def _instance_secret(self, data_dir: str) -> str:
        env = {"SNIFF4HOUND_DATA_DIR": data_dir}
        with patch.dict(os.environ, env, clear=False):
            os.environ.pop("SNIFF4HOUND_JWT_SECRET", None)
            os.environ.pop("SNIFF4HOUND_JWT_SECRET_FILE", None)
            reloaded = importlib.reload(settings)
            return reloaded.resolve_jwt_secret()

    def test_no_hardcoded_default_secret_in_the_source(self):
        source = Path(auth.__file__).read_text(encoding="utf-8")
        self.assertNotIn(LEAKED_DEFAULT_SECRET, source)

    def test_two_installations_get_different_secrets(self):
        first = self._instance_secret(str(Path(self._tmp.name) / "a"))
        second = self._instance_secret(str(Path(self._tmp.name) / "b"))
        self.assertNotEqual(first, second)
        self.assertGreaterEqual(len(first), 32)
        self.assertGreaterEqual(len(second), 32)

    def test_the_secret_is_stable_for_one_installation(self):
        data_dir = str(Path(self._tmp.name) / "stable")
        self.assertEqual(self._instance_secret(data_dir), self._instance_secret(data_dir))

    def test_the_persisted_secret_file_is_private(self):
        data_dir = Path(self._tmp.name) / "perms"
        self._instance_secret(str(data_dir))
        secret_file = data_dir / "jwt_secret"
        self.assertTrue(secret_file.exists())
        self.assertEqual(secret_file.stat().st_mode & 0o777, 0o600)

    def test_an_unwritable_data_dir_falls_back_to_an_ephemeral_secret(self):
        # Never a constant: an install that cannot persist the secret gets a
        # different one on every start rather than a guessable default.
        with patch.object(settings, "_persist_jwt_secret", return_value=False), patch.object(
            settings, "_load_persisted_jwt_secret", return_value=""
        ), patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SNIFF4HOUND_JWT_SECRET", None)
            first = settings.resolve_jwt_secret()
            second = settings.resolve_jwt_secret()
        self.assertNotEqual(first, second)
        self.assertNotEqual(first, LEAKED_DEFAULT_SECRET)

    def test_two_instances_reject_each_others_tokens(self):
        data_a = str(Path(self._tmp.name) / "inst-a")
        data_b = str(Path(self._tmp.name) / "inst-b")

        module_a = _reload_auth_with({"SNIFF4HOUND_DATA_DIR": data_a})
        token_a = module_a.generate_token(user="a")
        self.assertTrue(module_a.decode_jwt(token_a)[0])

        module_b = _reload_auth_with({"SNIFF4HOUND_DATA_DIR": data_b})
        self.assertFalse(module_b.decode_jwt(token_a)[0])
        self.assertFalse(module_b.authenticate_request(token_a)[0])

    def test_a_token_signed_with_the_old_default_is_rejected(self):
        now = int(time.time())
        forged = _forge(
            LEAKED_DEFAULT_SECRET,
            {
                "user": "attacker",
                "scope": "session",
                "iss": auth.JWT_ISSUER,
                "aud": auth.JWT_AUDIENCE,
                "iat": now,
                "exp": now + 3600,
            },
            header={"alg": "HS256", "typ": "JWT", "kid": auth.JWT_KEY_ID},
        )
        self.assertFalse(auth.decode_jwt(forged)[0])
        self.assertFalse(auth.authenticate_request(forged)[0])


class JwtClaimTests(unittest.TestCase):
    """M-04: the token carries and enforces more than a signature."""

    def tearDown(self):
        auth.clear_revoked_jwt_ids()

    def test_generated_tokens_carry_the_expected_claims(self):
        valid, payload = auth.decode_jwt(auth.generate_token(user="soc", scope="read"))
        self.assertTrue(valid)
        self.assertEqual(payload["iss"], auth.JWT_ISSUER)
        self.assertEqual(payload["aud"], auth.JWT_AUDIENCE)
        self.assertEqual(payload["user"], "soc")
        self.assertEqual(payload["scope"], "read")
        self.assertTrue(payload["jti"])
        self.assertLessEqual(payload["nbf"], payload["exp"])

    def test_a_wrong_issuer_is_rejected(self):
        token = auth.encode_jwt({"user": "x", "iss": "somebody-else", "exp": int(time.time()) + 60})
        self.assertFalse(auth.decode_jwt(token)[0])

    def test_a_wrong_audience_is_rejected(self):
        token = auth.encode_jwt({"user": "x", "aud": "another-service", "exp": int(time.time()) + 60})
        self.assertFalse(auth.decode_jwt(token)[0])

    def test_a_foreign_key_id_is_rejected_before_the_signature(self):
        token = auth.generate_token()
        head, body, signature = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))
        header["kid"] = "deadbeefdeadbeef"
        tampered = f"{_b64(json.dumps(header, separators=(',', ':')).encode())}.{body}.{signature}"
        self.assertFalse(auth.decode_jwt(tampered)[0])

    def test_a_token_not_yet_valid_is_rejected(self):
        future = int(time.time()) + 3600
        token = auth.encode_jwt({"user": "x", "nbf": future, "exp": future + 60})
        self.assertFalse(auth.decode_jwt(token)[0])

    def test_expires_in_is_capped(self):
        _valid, payload = auth.decode_jwt(auth.generate_token(expires_in=10 * 365 * 24 * 3600))
        self.assertLessEqual(payload["exp"] - payload["iat"], settings.JWT_MAX_TTL_SECONDS)

    def test_a_revoked_jti_stops_decoding(self):
        token = auth.generate_token()
        _valid, payload = auth.decode_jwt(token)
        auth.revoke_jwt_id(payload["jti"])
        self.assertFalse(auth.decode_jwt(token)[0])
        self.assertFalse(auth.authenticate_request(token)[0])

    def test_bumping_the_key_version_invalidates_every_token(self):
        token = auth.generate_token()
        self.assertTrue(auth.decode_jwt(token)[0])
        rotated = auth._derive_signing_key(auth.JWT_SECRET, auth.JWT_KEY_VERSION + 1)
        with patch.object(auth, "_SIGNING_KEY", rotated), patch.object(
            auth, "JWT_KEY_ID", hashlib.sha256(rotated).hexdigest()[:16]
        ):
            self.assertFalse(auth.decode_jwt(token)[0])


class AuthRateLimiterTests(unittest.TestCase):
    """M-01: repeated failures cost the source something."""

    def _limiter(self, **kwargs):
        params = {
            "window_seconds": 60,
            "threshold": 3,
            "base_lockout": 4,
            "max_lockout": 16,
            "max_clients": 8,
        }
        params.update(kwargs)
        return auth.AuthRateLimiter(**params)

    def test_failures_under_the_threshold_do_not_lock_out(self):
        limiter = self._limiter()
        for _ in range(2):
            self.assertEqual(limiter.register_failure("10.0.0.1"), 0.0)
        allowed, retry_after = limiter.check("10.0.0.1")
        self.assertTrue(allowed)
        self.assertEqual(retry_after, 0.0)

    def test_crossing_the_threshold_locks_the_source_out(self):
        limiter = self._limiter()
        lockouts = [limiter.register_failure("10.0.0.2") for _ in range(3)]
        self.assertEqual(lockouts[-1], 4.0)
        allowed, retry_after = limiter.check("10.0.0.2")
        self.assertFalse(allowed)
        self.assertGreater(retry_after, 0.0)

    def test_the_lockout_backs_off_and_is_capped(self):
        limiter = self._limiter()
        applied = []
        for _round in range(4):
            for _ in range(3):
                lockout = limiter.register_failure("10.0.0.3")
            applied.append(lockout)
            # Serve the sentence so the next round can accumulate again.
            limiter._clients["10.0.0.3"]["blocked_until"] = 0.0
        self.assertEqual(applied, [4.0, 8.0, 16.0, 16.0])

    def test_other_sources_are_unaffected(self):
        limiter = self._limiter()
        for _ in range(3):
            limiter.register_failure("10.0.0.4")
        self.assertFalse(limiter.check("10.0.0.4")[0])
        self.assertTrue(limiter.check("10.0.0.5")[0])

    def test_a_successful_authentication_clears_the_history(self):
        limiter = self._limiter()
        limiter.register_failure("10.0.0.6")
        limiter.register_failure("10.0.0.6")
        limiter.register_success("10.0.0.6")
        self.assertEqual(limiter.register_failure("10.0.0.6"), 0.0)

    def test_the_client_table_is_bounded(self):
        limiter = self._limiter(max_clients=4)
        for index in range(50):
            limiter.register_failure(f"198.51.100.{index}")
        self.assertLessEqual(len(limiter._clients), 4)

    def test_the_limiter_can_be_disabled(self):
        limiter = self._limiter()
        with patch.object(auth, "AUTH_RATE_LIMIT_ENABLED", False):
            for _ in range(20):
                self.assertEqual(limiter.register_failure("10.0.0.7"), 0.0)
            self.assertTrue(limiter.check("10.0.0.7")[0])


if __name__ == "__main__":
    unittest.main()
