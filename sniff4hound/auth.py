"""
Simple security-code authentication for Sniff4Hound.

Sniff4Hound generates an 8-character code at startup and shows it in the
terminal. The frontend must present the same code to unlock HTTP and WebSocket
communication with the backend.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import string
import threading
import time
from collections import deque
from typing import Any

from .settings import (
    AUTH_FAILURE_THRESHOLD,
    AUTH_FAILURE_WINDOW_SECONDS,
    AUTH_LOCKOUT_BASE_SECONDS,
    AUTH_LOCKOUT_MAX_SECONDS,
    AUTH_RATE_LIMIT_ENABLED,
    AUTH_RATE_LIMIT_MAX_CLIENTS,
    JWT_MAX_TTL_SECONDS,
    JWT_TTL_SECONDS,
    resolve_jwt_secret,
)


SESSION_TOKEN_LENGTH = 8
SESSION_TOKEN_ALPHABET = string.ascii_letters + string.digits
SECURITY_CODE_LENGTH = SESSION_TOKEN_LENGTH
JWT_ALGORITHM = "HS256"
# Fixed audience/issuer, validated on every decode: a token minted by some
# other HS256 service that happens to share a secret (or by an older
# Sniff4Hound key generation) is not a Sniff4Hound API token.
JWT_ISSUER = "sniff4hound"
JWT_AUDIENCE = "sniff4hound-api"
# Bump to invalidate every token this installation has ever issued without
# touching the stored secret - the signing key is derived from the pair, so
# a new version (or a rotated secret) changes `kid` and the signature at
# once, and every outstanding token stops decoding.
JWT_KEY_VERSION = 1
# Tolerance for a client/server clock offset when checking `nbf`.
JWT_CLOCK_SKEW_SECONDS = 60

# No default literal here: see settings.resolve_jwt_secret().
JWT_SECRET = resolve_jwt_secret()
JWT_DEFAULT_TTL_SECONDS = int(JWT_TTL_SECONDS)


def _derive_signing_key(secret: str, version: int) -> bytes:
    """Sign with a key *derived* from the secret rather than the secret
    itself, so the key version participates in the signature."""
    return hmac.new(
        str(secret or "").encode("utf-8"),
        f"sniff4hound-jwt-key-v{int(version)}".encode("ascii"),
        hashlib.sha256,
    ).digest()


_SIGNING_KEY = _derive_signing_key(JWT_SECRET, JWT_KEY_VERSION)
# Public, non-reversible identifier of the active signing key. Published in
# the JWT header so a token from a previous secret/version is rejected
# before its signature is even computed.
JWT_KEY_ID = hashlib.sha256(_SIGNING_KEY).hexdigest()[:16]

# In-memory revocation list keyed by `jti`. Cleared on restart, which is
# harmless: a restart rotates nothing but every token still has an `exp`,
# and rotating the secret revokes the whole generation at once.
_REVOKED_JWT_IDS: set[str] = set()
_REVOKED_JWT_LOCK = threading.Lock()


def revoke_jwt_id(jti: str) -> bool:
    value = str(jti or "").strip()
    if not value:
        return False
    with _REVOKED_JWT_LOCK:
        _REVOKED_JWT_IDS.add(value)
    return True


def is_jwt_revoked(jti: str) -> bool:
    value = str(jti or "").strip()
    if not value:
        return False
    with _REVOKED_JWT_LOCK:
        return value in _REVOKED_JWT_IDS


def clear_revoked_jwt_ids() -> None:
    with _REVOKED_JWT_LOCK:
        _REVOKED_JWT_IDS.clear()


def _generate_random_token(length: int = SESSION_TOKEN_LENGTH) -> str:
    """Generate a session token with uppercase, lowercase, and digits."""
    return "".join(secrets.choice(SESSION_TOKEN_ALPHABET) for _ in range(length))


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(f"{value}{padding}".encode("ascii"))


def _jwt_sign(signing_input: str) -> str:
    digest = hmac.new(
        _SIGNING_KEY,
        signing_input.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return _b64url_encode(digest)


def _audience_matches(value: Any) -> bool:
    """RFC 7519 allows `aud` to be a string or a list of strings."""
    if isinstance(value, str):
        return value == JWT_AUDIENCE
    if isinstance(value, (list, tuple)):
        return any(isinstance(item, str) and item == JWT_AUDIENCE for item in value)
    return False


def encode_jwt(payload: dict[str, Any]) -> str:
    """Encode a compact JWT using HS256.

    `iss`/`aud` are stamped in when the caller did not supply them, so every
    token this module emits carries the claims `decode_jwt()` insists on.
    """
    header = {"alg": JWT_ALGORITHM, "typ": "JWT", "kid": JWT_KEY_ID}
    claims = dict(payload or {})
    claims.setdefault("iss", JWT_ISSUER)
    claims.setdefault("aud", JWT_AUDIENCE)
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}"
    signature_b64 = _jwt_sign(signing_input)
    return f"{signing_input}.{signature_b64}"


def decode_jwt(token: str | None) -> tuple[bool, dict[str, Any] | None]:
    """Decode and verify a HS256 JWT.

    Checked, in order: the key id in the header (so a token from a rotated
    secret or an older key version dies immediately), the algorithm, the
    signature, the issuer/audience pair, `nbf`, `exp`, and the `jti`
    revocation list.
    """
    if not token:
        return False, None
    try:
        header_b64, payload_b64, signature_b64 = str(token).split(".", 2)

        header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
        if str(header.get("alg") or "") != JWT_ALGORITHM:
            return False, None
        key_id = str(header.get("kid") or "")
        if not key_id or not secrets.compare_digest(key_id, JWT_KEY_ID):
            return False, None

        signing_input = f"{header_b64}.{payload_b64}"
        expected_signature = _jwt_sign(signing_input)
        if not secrets.compare_digest(signature_b64, expected_signature):
            return False, None

        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        if str(payload.get("iss") or "") != JWT_ISSUER:
            return False, None
        if not _audience_matches(payload.get("aud")):
            return False, None

        now = int(time.time())
        exp = payload.get("exp")
        if exp is not None and int(exp) < now:
            return False, None
        nbf = payload.get("nbf")
        if nbf is not None and int(nbf) > now + JWT_CLOCK_SKEW_SECONDS:
            return False, None
        if is_jwt_revoked(payload.get("jti")):
            return False, None
        return True, payload
    except Exception:
        return False, None


def generate_token(
    *,
    user: str = "operator",
    scope: str = "session",
    expires_in: int = JWT_DEFAULT_TTL_SECONDS,
    extra: dict[str, Any] | None = None,
) -> str:
    """Generate a signed JWT for API-oriented authentication tests and integrations."""
    now = int(time.time())
    # These tokens are stateless and bearer-only; an unbounded `expires_in`
    # would hand out a credential nothing can take back.
    ttl = min(max(1, int(expires_in)), int(JWT_MAX_TTL_SECONDS))
    payload = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "user": str(user or "operator"),
        "scope": str(scope or "session"),
        "jti": secrets.token_hex(16),
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
    }
    if extra:
        payload.update(dict(extra))
    return encode_jwt(payload)


# Session token (generated at startup, displayed in terminal)
_SESSION_TOKEN: str | None = None
REQUIRE_AUTH = os.getenv("SNIFF4HOUND_REQUIRE_AUTH", "1").lower() in {"1", "true", "yes", "on"}


def initialize_session_token() -> str:
    """Initialize the startup security code once per process."""
    global _SESSION_TOKEN
    if _SESSION_TOKEN is None:
        _SESSION_TOKEN = _generate_random_token(SESSION_TOKEN_LENGTH)
    return _SESSION_TOKEN


def get_session_token() -> str:
    """Get the current startup security code."""
    if _SESSION_TOKEN is None:
        return initialize_session_token()
    return _SESSION_TOKEN


def verify_token(token: str | None) -> bool:
    """Verify whether the provided value matches the active security code."""
    if not token:
        return not REQUIRE_AUTH

    if _SESSION_TOKEN is None:
        initialize_session_token()

    candidate = token.strip()
    if secrets.compare_digest(candidate, _SESSION_TOKEN):
        return True

    jwt_valid, _jwt_payload = decode_jwt(candidate)
    return jwt_valid


def extract_token_from_header(auth_header: str | None) -> str | None:
    """
    Extract token from Authorization header or x-access-token.

    Args:
        auth_header: Authorization header value (e.g., "Bearer <token>")

    Returns:
        Token string or None
    """
    if not auth_header:
        return None
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    return auth_header.strip()


def authenticate_request(token: str | None) -> tuple[bool, dict[str, Any] | None]:
    """
    Authenticate a request using session token.

    Args:
        token: Token from request

    Returns:
        Tuple of (is_authenticated, user_info)
    """
    if not token:
        if not REQUIRE_AUTH:
            return True, {"authenticated": True, "auth_type": "anonymous"}
        return False, None

    jwt_valid, jwt_payload = decode_jwt(token)
    if jwt_valid and jwt_payload is not None:
        payload = dict(jwt_payload)
        payload["authenticated"] = True
        payload["auth_type"] = "jwt"
        return True, payload

    if not verify_token(token):
        return False, None

    return True, {
        "authenticated": True,
        "auth_type": "session",
    }


class AuthRateLimiter:
    """Sliding-window failed-authentication limiter with incremental backoff.

    `secrets.compare_digest` already keeps the security-code check itself
    constant-time, but nothing bounded how *often* a client could try: an
    8-character alphanumeric code was guessable at whatever rate the HTTP
    server would answer, with no counter, no lockout and no record of the
    attempt anywhere. Failures are counted per source address over
    AUTH_FAILURE_WINDOW_SECONDS; crossing AUTH_FAILURE_THRESHOLD locks that
    source out, doubling the lockout on each further strike up to
    AUTH_LOCKOUT_MAX_SECONDS.

    In-memory and per-process on purpose - this is one local sensor, not a
    cluster, and a restart clearing the table is acceptable. The table is
    capped (AUTH_RATE_LIMIT_MAX_CLIENTS) so a spoofed-source flood cannot
    grow it without bound.
    """

    __slots__ = ("_window", "_threshold", "_base_lockout", "_max_lockout", "_max_clients", "_clients", "_lock")

    def __init__(
        self,
        *,
        window_seconds: float = AUTH_FAILURE_WINDOW_SECONDS,
        threshold: int = AUTH_FAILURE_THRESHOLD,
        base_lockout: float = AUTH_LOCKOUT_BASE_SECONDS,
        max_lockout: float = AUTH_LOCKOUT_MAX_SECONDS,
        max_clients: int = AUTH_RATE_LIMIT_MAX_CLIENTS,
    ):
        self._window = max(1.0, float(window_seconds))
        self._threshold = max(1, int(threshold))
        self._base_lockout = max(1.0, float(base_lockout))
        self._max_lockout = max(self._base_lockout, float(max_lockout))
        self._max_clients = max(1, int(max_clients))
        self._clients: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(client: str | None) -> str:
        return str(client or "").strip() or "unknown"

    def _entry(self, key: str, now: float) -> dict[str, Any]:
        entry = self._clients.get(key)
        if entry is None:
            self._evict(now)
            entry = {"failures": deque(), "blocked_until": 0.0, "strikes": 0, "seen_at": now}
            self._clients[key] = entry
        entry["seen_at"] = now
        return entry

    def _evict(self, now: float) -> None:
        if len(self._clients) < self._max_clients:
            return
        stale = [
            key
            for key, entry in self._clients.items()
            if entry["blocked_until"] <= now and (not entry["failures"] or entry["failures"][-1] <= now - self._window)
        ]
        for key in stale:
            self._clients.pop(key, None)
        while len(self._clients) >= self._max_clients:
            oldest = min(self._clients, key=lambda item: self._clients[item]["seen_at"])
            self._clients.pop(oldest, None)

    def check(self, client: str | None) -> tuple[bool, float]:
        """(allowed, retry_after_seconds) for a source about to be
        authenticated."""
        if not AUTH_RATE_LIMIT_ENABLED:
            return True, 0.0
        key = self._key(client)
        now = time.monotonic()
        with self._lock:
            entry = self._clients.get(key)
            if entry is None:
                return True, 0.0
            entry["seen_at"] = now
            remaining = float(entry["blocked_until"]) - now
            if remaining > 0:
                return False, remaining
            return True, 0.0

    def register_failure(self, client: str | None) -> float:
        """Record one rejected attempt. Returns the lockout just applied, or
        0.0 while the source is still under the threshold."""
        if not AUTH_RATE_LIMIT_ENABLED:
            return 0.0
        key = self._key(client)
        now = time.monotonic()
        with self._lock:
            entry = self._entry(key, now)
            failures: deque = entry["failures"]
            failures.append(now)
            cutoff = now - self._window
            while failures and failures[0] <= cutoff:
                failures.popleft()
            if len(failures) < self._threshold:
                return 0.0
            entry["strikes"] = int(entry["strikes"]) + 1
            lockout = min(self._base_lockout * (2 ** (int(entry["strikes"]) - 1)), self._max_lockout)
            entry["blocked_until"] = now + lockout
            failures.clear()
            return float(lockout)

    def register_success(self, client: str | None) -> None:
        """A successful authentication clears the source's failure history -
        an operator who mistyped the code a few times is not a threat."""
        if not AUTH_RATE_LIMIT_ENABLED:
            return
        key = self._key(client)
        with self._lock:
            self._clients.pop(key, None)

    def blocked_for(self, client: str | None) -> float:
        allowed, retry_after = self.check(client)
        return 0.0 if allowed else retry_after

    def reset(self) -> None:
        with self._lock:
            self._clients.clear()

    def snapshot(self) -> dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            return {
                "enabled": bool(AUTH_RATE_LIMIT_ENABLED),
                "window_seconds": self._window,
                "threshold": self._threshold,
                "tracked_clients": len(self._clients),
                "blocked_clients": sum(1 for entry in self._clients.values() if entry["blocked_until"] > now),
            }


# Process-wide limiter shared by the API guard and the WebSocket handshake,
# so a client cannot dodge the backoff by switching transports.
RATE_LIMITER = AuthRateLimiter()


def initialize_security_code() -> str:
    return initialize_session_token()


def get_security_code() -> str:
    return get_session_token()


def verify_security_code(token: str | None) -> bool:
    return verify_token(token)
