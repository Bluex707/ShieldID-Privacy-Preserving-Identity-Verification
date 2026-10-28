"""Online-attack mitigations: rate limiting, account lockout, progressive delay,
and outbound-URL allow-listing (SSRF guard).

The tracker is an in-memory, single-process implementation suitable for a
demo. In production this state belongs in a shared store (e.g. Redis) so it
survives restarts and works across instances.
"""
import re
import threading
import time
from collections import defaultdict

import config


# ---------------------------------------------------------------------------
# SSRF guards: exact-match allow-lists, never prefix/hostname checks
# ---------------------------------------------------------------------------
class UntrustedCallbackURLError(Exception):
    """A QR-supplied callback_url is not on the verifier allow-list."""


def validate_callback_url(callback_url: str) -> str:
    """The wallet's 'present VC' flow receives `callback_url` from a QR code the
    student scans -- attacker-controlled input. Passing it straight to an HTTP
    client would let anyone who can show a bad QR code make the wallet server
    contact an arbitrary destination (internal services, cloud metadata) with
    the student's presentation as the POST body.

    Mitigation: require an EXACT match against a server-side allow-list; reject
    before any network call is made.
    """
    if not isinstance(callback_url, str) or callback_url not in config.ALLOWED_VERIFIER_CALLBACKS:
        raise UntrustedCallbackURLError(
            "This QR code points to a callback URL that isn't on the wallet's "
            "list of trusted verifiers. Refusing to send your credential there."
        )
    return callback_url


class UntrustedIssuerEndpointError(Exception):
    """The configured Issuer endpoint isn't on the wallet's allow-list."""


def validate_issuer_endpoint(issuer_url: str) -> str:
    """Same exact-match discipline for the Wallet -> Issuer call. The value comes
    from server config, but is checked anyway so a future change that threads a
    request-supplied URL through here fails safe instead of becoming SSRF."""
    if not isinstance(issuer_url, str) or issuer_url not in config.ALLOWED_ISSUER_ENDPOINTS:
        raise UntrustedIssuerEndpointError(
            "The configured issuer-service endpoint isn't on the wallet's "
            "list of trusted issuers. Refusing to send the request there."
        )
    return issuer_url


# ---------------------------------------------------------------------------
# Log hygiene
# ---------------------------------------------------------------------------
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def sanitize_log_value(value, max_len: int = 200) -> str:
    """Strip control characters (CR/LF would allow forged log lines) and bound
    the length of any value that may contain user- or network-supplied text."""
    return _CONTROL.sub(" ", str(value))[:max_len]


# ---------------------------------------------------------------------------
# Attempt tracking
# ---------------------------------------------------------------------------
MAX_ATTEMPTS = 5          # failed attempts allowed inside the rolling window
WINDOW_SECONDS = 60       # rolling window used to count failures
LOCKOUT_SECONDS = 300     # cooldown once the cap is hit
MAX_DELAY_SECONDS = 3     # ceiling for the progressive-delay backoff
MAX_TRACKED_KEYS = 10_000  # memory bound: attackers can invent unlimited keys


class AttemptTracker:
    """Tracks failed attempts per key (e.g. 'login:<username>') and enforces
    rate limiting + temporary lockout. Thread-safe."""

    def __init__(self, max_attempts=MAX_ATTEMPTS, window_seconds=WINDOW_SECONDS,
                 lockout_seconds=LOCKOUT_SECONDS, max_keys=MAX_TRACKED_KEYS):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self.max_keys = max_keys
        self._attempts = defaultdict(list)   # key -> [timestamps of recent failures]
        self._locked_until = {}              # key -> unix timestamp the lock expires
        self._lock = threading.Lock()

    def is_locked(self, key: str) -> tuple[bool, int]:
        """Returns (locked, seconds_remaining)."""
        with self._lock:
            locked_until = self._locked_until.get(key)
            now = time.time()
            if locked_until and now < locked_until:
                return True, int(locked_until - now) + 1
            return False, 0

    def progressive_delay(self, key: str):
        """Sleep briefly, longer per recent failure, to slow scripted guessing
        before the hard lockout kicks in. Sleeps OUTSIDE the lock."""
        with self._lock:
            recent = len(self._attempts.get(key, ()))
        if recent:
            time.sleep(min(recent * 0.6, MAX_DELAY_SECONDS))

    def record_failure(self, key: str):
        now = time.time()
        with self._lock:
            self._prune(now)
            attempts = self._attempts[key]
            attempts.append(now)
            attempts[:] = [t for t in attempts if now - t <= self.window_seconds]
            if len(attempts) >= self.max_attempts:
                self._locked_until[key] = now + self.lockout_seconds
                attempts.clear()

    def record_success(self, key: str):
        with self._lock:
            self._attempts.pop(key, None)
            self._locked_until.pop(key, None)

    def _prune(self, now: float):
        """Drop expired state; if still over budget, evict the oldest keys.
        Caller holds the lock."""
        if len(self._attempts) + len(self._locked_until) < self.max_keys:
            return
        for k in [k for k, ts in self._attempts.items() if not ts or now - ts[-1] > self.window_seconds]:
            del self._attempts[k]
        for k in [k for k, until in self._locked_until.items() if until <= now]:
            del self._locked_until[k]
        overflow = len(self._attempts) - self.max_keys // 2
        if overflow > 0:
            oldest = sorted(self._attempts, key=lambda k: self._attempts[k][-1] if self._attempts[k] else 0)
            for k in oldest[:overflow]:
                del self._attempts[k]


# Separate trackers so, e.g., too many bad PINs doesn't lock out login attempts.
login_tracker = AttemptTracker()
pin_tracker = AttemptTracker()
portal_tracker = AttemptTracker()
issue_tracker = AttemptTracker()   # used by issuer_app.py, per caller IP
