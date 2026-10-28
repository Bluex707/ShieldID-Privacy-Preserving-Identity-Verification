"""Mock University Portal: user store + OAuth 2.0 authorization server.

It is the ONLY component that ever sees a student's password. Downstream
components (wallet backend, issuer) deal exclusively in short-lived, single-use
authorization codes and scoped access tokens.
"""
import hashlib
import hmac
import os
import secrets
import threading
import time

import config

_PBKDF2_ITERATIONS = 600_000


def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERATIONS)


_DUMMY_SALT = os.urandom(16)
_DUMMY_HASH = _hash_password(secrets.token_urlsafe(16), _DUMMY_SALT)

AUTH_CODE_TTL_SECONDS = 60       
ACCESS_TOKEN_TTL_SECONDS = 300   


def _safe_equal(a, b) -> bool:
    """Constant-time equality that never raises on non-str / non-ASCII input."""
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return hmac.compare_digest(a.encode(), b.encode())


class UniversityPortal:
    def __init__(self):
        self._users = {}
        self._auth_codes = {}      
        self._access_tokens = {}   
        self._lock = threading.Lock()
        
        self._clients = {config.WALLET_CLIENT_ID: config.WALLET_CLIENT_SECRET}

    
    def register_student(self, username, password, student_record):
        salt = os.urandom(16)
        self._users[username] = {
            "salt": salt,
            "password_hash": _hash_password(password, salt),
            "record": dict(student_record),
        }

    def authenticate(self, username, password):
        if not isinstance(username, str) or not isinstance(password, str) or len(password) > 1024:
            return None
        user = self._users.get(username)
        salt = user["salt"] if user else _DUMMY_SALT
        expected = user["password_hash"] if user else _DUMMY_HASH
        candidate = _hash_password(password, salt)
        if hmac.compare_digest(candidate, expected) and user is not None:
            return dict(user["record"])
        return None

    
    def _purge_expired(self, now):
        """Caller holds the lock. Keeps the in-memory stores bounded."""
        for store in (self._auth_codes, self._access_tokens):
            for k in [k for k, v in store.items() if v["expiry"] < now]:
                del store[k]

    def mint_authorization_code(self, username, scope, client_id):
        if client_id not in self._clients:
            raise ValueError("unknown OAuth client_id")
        code = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._purge_expired(now)
            self._auth_codes[code] = {
                "username": username,
                "scope": scope,
                "client_id": client_id,
                "expiry": now + AUTH_CODE_TTL_SECONDS,
            }
        return code

    def exchange_code_for_token(self, code, client_id, client_secret):
        """RFC 6749 4.1.3. Returns the token response or raises ValueError.
        The code is consumed atomically (pop under a lock) the moment it is
        presented with valid client credentials, so it can never be redeemed
        twice -- even by two racing requests."""
        if not all(isinstance(v, str) for v in (code, client_id, client_secret)):
            raise ValueError("invalid request")
        expected_secret = self._clients.get(client_id)
        if expected_secret is None or not _safe_equal(client_secret, expected_secret):
            raise ValueError("invalid client credentials")

        now = time.time()
        with self._lock:
            entry = self._auth_codes.pop(code, None)
            if entry is None:
                raise ValueError("invalid or expired authorization code")
            if now > entry["expiry"]:
                raise ValueError("authorization code expired")
            if entry["client_id"] != client_id:
                raise ValueError("authorization code was not issued to this client")
            access_token = secrets.token_urlsafe(48)
            self._access_tokens[access_token] = {
                "username": entry["username"],
                "scope": entry["scope"],
                "client_id": client_id,
                "expiry": now + ACCESS_TOKEN_TTL_SECONDS,
                "revoked": False,
            }
        return {
            "access_token": access_token,
            "token_type": "bearer",  
            "expires_in": ACCESS_TOKEN_TTL_SECONDS,
            "scope": entry["scope"],
        }

    def introspect_token(self, access_token):
        """RFC 7662 token introspection (called by the Issuer service)."""
        if not isinstance(access_token, str):
            return {"active": False}
        with self._lock:
            entry = self._access_tokens.get(access_token)
        if entry is None or entry["revoked"] or time.time() > entry["expiry"]:
            return {"active": False}
        user = self._users.get(entry["username"])
        if user is None:
            return {"active": False}
        return {
            "active": True,
            "username": entry["username"],
            "scope": entry["scope"],
            "client_id": entry["client_id"],
            "student_record": dict(user["record"]),
        }

    def revoke_token(self, access_token):
        with self._lock:
            entry = self._access_tokens.get(access_token)
            if entry is not None:
                entry["revoked"] = True
