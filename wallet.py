"""Holder wallet: key custody, credential storage, presentation building.

Every use of the wallet's private key (credential request, presentation) must
be authorised by the holder's PIN. An unlock is short-lived and single-use.
"""
import hashlib
import hmac
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone

import pyotp
import requests

import config
import crypto_utils
from issuer import CredentialRequestError
from security_utils import (
    UntrustedIssuerEndpointError, sanitize_log_value, validate_issuer_endpoint,
)

# ---------------------------------------------------------------------------
# Persistent security audit log (separate from the in-memory list shown in the UI)
# ---------------------------------------------------------------------------
security_logger = logging.getLogger("shieldid.security")
security_logger.setLevel(logging.INFO)

if not security_logger.handlers:  # avoid duplicate handlers on module reload
    os.makedirs(os.path.dirname(config.SECURITY_LOG_PATH), mode=0o700, exist_ok=True)
    _file_handler = logging.FileHandler(config.SECURITY_LOG_PATH, encoding="utf-8")
    _file_handler.setFormatter(logging.Formatter("%(asctime)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    security_logger.addHandler(_file_handler)
    security_logger.propagate = False
    try:
        os.chmod(config.SECURITY_LOG_PATH, 0o600)
    except OSError:
        pass


class WalletLockedError(Exception):
    """A key operation was attempted without valid, unexpired PIN authorization."""


_PBKDF2_ITERATIONS = 600_000


def _hash_secret(secret: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256, 600k iterations (OWASP guidance)."""
    return hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, _PBKDF2_ITERATIONS)


_DUMMY_SALT = os.urandom(16)


def burn_password_check(attempt: str) -> None:
    """Do the same expensive work as a real password check. Called when the
    username doesn't exist so response time can't reveal which usernames are
    registered."""
    _hash_secret(attempt if isinstance(attempt, str) else "", _DUMMY_SALT)


_AUTH_LOG_MAX_ENTRIES = 200
UNLOCK_TTL_SECONDS = 120          # a PIN entry authorises key use for at most this long
_CHALLENGE_RE = re.compile(r"[0-9a-fA-F]{32,128}")
_MAX_VALUE_LEN = 64
_MAX_ISSUER_RESPONSE_BYTES = 64 * 1024


class Wallet:
    def __init__(self, username: str, password: str, pin: str):
        self.username = username
        self._private_key, self.public_key = crypto_utils.generate_ec_keypair()
        self.public_key_hex = crypto_utils.ec_point_to_hex(self.public_key)

        # Separate salted hashes: password (login) and PIN (key authorization).
        self._password_salt = os.urandom(16)
        self._password_hash = _hash_secret(password, self._password_salt)
        self._pin_salt = os.urandom(16)
        self._pin_hash = _hash_secret(pin, self._pin_salt)

        # Second factor: TOTP is "something you have", a different category
        # than password/PIN ("something you know").
        self.totp_secret = pyotp.random_base32()
        self.mfa_enabled = False
        self._last_totp_counter = -1   # rejects replay of an already-used code
        self._totp_lock = threading.Lock()

        self._unlocked_until = 0.0
        self.credential = None
        self.attribute_disclosures = None

        # Never stores the password/PIN, only the outcome of each attempt.
        self._auth_log = []
        self._log_event("wallet_created", success=True)

    # ---- audit log ---------------------------------------------------------
    def _log_event(self, event: str, success: bool, detail: str = "", ip: str = None):
        detail = sanitize_log_value(detail)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "success": success,
            "detail": detail,
            "ip": ip or "unknown",
        }
        self._auth_log.append(entry)
        if len(self._auth_log) > _AUTH_LOG_MAX_ENTRIES:
            self._auth_log.pop(0)
        security_logger.info(
            "user=%s event=%s status=%s ip=%s detail=%s",
            sanitize_log_value(self.username, 40), event,
            "SUCCESS" if success else "FAILED", sanitize_log_value(ip or "unknown", 45), detail,
        )

    def get_auth_log(self):
        """Most-recent-first copy of the authentication log for display."""
        return list(reversed(self._auth_log))

    # ---- authentication factors ---------------------------------------------
    def get_totp_uri(self, issuer_name: str = "ShieldID Wallet") -> str:
        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(name=self.username, issuer_name=issuer_name)

    def verify_totp(self, code) -> bool:
        """Accepts a code from the current or adjacent 30s window, but each
        time-step can be used only ONCE (replay protection, RFC 6238 5.2)."""
        if not (isinstance(code, str) and len(code) == 6 and code.isascii() and code.isdigit()):
            return False
        totp = pyotp.totp.TOTP(self.totp_secret)
        now = int(time.time())
        with self._totp_lock:
            for offset in (-1, 0, 1):
                t = now + offset * totp.interval
                counter = t // totp.interval
                if counter <= self._last_totp_counter:
                    continue
                if hmac.compare_digest(totp.at(t), code):
                    self._last_totp_counter = counter
                    return True
        return False

    def verify_password(self, password_attempt: str, ip: str = None) -> bool:
        ok = hmac.compare_digest(_hash_secret(password_attempt, self._password_salt), self._password_hash)
        self._log_event("login", success=ok, ip=ip)
        return ok

    def unlock_with_pin(self, pin_attempt: str, ip: str = None) -> bool:
        ok = hmac.compare_digest(_hash_secret(pin_attempt, self._pin_salt), self._pin_hash)
        self._log_event("pin_unlock", success=ok, ip=ip)
        if ok:
            self._unlocked_until = time.time() + UNLOCK_TTL_SECONDS
        return ok

    @property
    def _unlocked(self) -> bool:
        return time.time() < self._unlocked_until

    def lock(self):
        self._unlocked_until = 0.0

    def _require_unlocked(self):
        if not self._unlocked:
            raise WalletLockedError("Wallet key is locked. Provide your security PIN first.")

    # ---- credential lifecycle -------------------------------------------------
    def has_credential_from_issuer(self, issuer_id: str) -> bool:
        return bool(self.credential and self.credential.get("issuer_id") == issuer_id)

    def clear_revoked_credential(self):
        self._log_event("credential_revoked", success=True)
        self.credential = None
        self.attribute_disclosures = None

    def request_credential(self, access_token: str):
        """Exchanges a scoped OAuth access token -- never a password -- for a
        signed credential by calling the standalone Issuer service over HTTPS
        (certificate verified, destination allow-listed, redirects refused)."""
        self._require_unlocked()
        try:
            try:
                issuer_endpoint = validate_issuer_endpoint(config.ISSUER_ISSUE_CREDENTIAL_URL)
            except UntrustedIssuerEndpointError as e:
                self._log_event("credential_issued", success=False, detail=str(e))
                raise CredentialRequestError(str(e)) from e

            try:
                response = requests.post(
                    issuer_endpoint,
                    json={"access_token": access_token, "holder_public_key_hex": self.public_key_hex},
                    timeout=10,
                    verify=config.TLS_CA_BUNDLE,
                    allow_redirects=False,
                )
            except requests.RequestException as e:
                self._log_event("credential_issued", success=False, detail=f"issuer unreachable: {type(e).__name__}")
                raise CredentialRequestError("Could not reach the issuer service.") from e

            if response.status_code != 200:
                detail = None
                try:
                    body = response.json()
                    detail = body.get("error_description") or body.get("error")
                except ValueError:
                    pass
                detail = sanitize_log_value(detail or f"issuer returned HTTP {response.status_code}")
                self._log_event("credential_issued", success=False, detail=detail)
                raise CredentialRequestError(detail)

            try:
                if len(response.content) > _MAX_ISSUER_RESPONSE_BYTES:
                    raise ValueError("response too large")
                result = response.json()
                credential = result["credential"]
                disclosures = result["attribute_disclosures"]
                if not isinstance(credential, dict) or not isinstance(disclosures, dict):
                    raise ValueError("unexpected shape")
                credential["credential_id"], credential["issuer_id"], credential["attribute_commitments"]
            except (ValueError, KeyError, TypeError) as e:
                self._log_event("credential_issued", success=False, detail="malformed issuer response")
                raise CredentialRequestError("The issuer returned an unexpected response.") from e

            self.credential = credential
            self.attribute_disclosures = disclosures
            self._log_event("credential_issued", success=True, detail=f"issuer={credential['issuer_id']}")
            return self.credential
        finally:
            self.lock()   # single-use authorization

    def available_attributes(self):
        if not self.attribute_disclosures:
            return []
        return list(self.attribute_disclosures.keys())

    # ---- presentation -----------------------------------------------------------
    def create_presentation(self, verifier_challenge_hex: str, required_attribute: str,
                            required_value, extra_attributes=None) -> dict:
        """Builds a presentation for a verifier challenge. Requires a fresh PIN
        unlock, which is consumed by this call.

        The required attribute is proven in zero knowledge (Pedersen equality
        proof): its value and blinding factor never leave the wallet.
        `extra_attributes` is an explicit, student-chosen opt-in list of
        attributes to reveal in full; everything else stays sealed.
        """
        self._require_unlocked()
        try:
            if not self.credential or not self.attribute_disclosures:
                raise ValueError("No credential available in wallet to generate presentation.")
            if not isinstance(verifier_challenge_hex, str) or not _CHALLENGE_RE.fullmatch(verifier_challenge_hex):
                raise ValueError("Malformed verifier challenge.")
            if not isinstance(required_value, str) or len(required_value) > _MAX_VALUE_LEN:
                raise ValueError("Malformed required value.")
            if required_attribute not in self.attribute_disclosures:
                raise ValueError("Wallet holds no such attribute to prove.")

            context = bytes.fromhex(verifier_challenge_hex) + self.credential["credential_id"].encode()
            proof_of_possession = crypto_utils.schnorr_prove(self._private_key, self.public_key, context)

            commitment = crypto_utils.ec_point_from_hex(self.credential["attribute_commitments"][required_attribute])
            blinding = int(self.attribute_disclosures[required_attribute]["blinding"])
            # Domain-separate per attribute so a proof can't be replayed against
            # a different attribute or challenge.
            attr_context = hashlib.sha256(context + b"|" + required_attribute.encode()).digest()
            equality_proof = crypto_utils.prove_attribute_equals(blinding, commitment, required_value, attr_context)

            disclosed_attributes = {required_attribute: {"proof": equality_proof}}
            chosen_extra = []
            for name in (extra_attributes or [])[: len(self.attribute_disclosures)]:
                if name == required_attribute or name in disclosed_attributes:
                    continue
                if name in self.attribute_disclosures:
                    entry = self.attribute_disclosures[name]
                    disclosed_attributes[name] = {"value": entry["value"], "blinding": entry["blinding"]}
                    chosen_extra.append(name)

            self._log_event("presentation_created", success=True,
                            detail=f"zk_proved={required_attribute}, disclosed={chosen_extra}")
            return {
                "credential_id": self.credential["credential_id"],
                "issuer_id": self.credential["issuer_id"],
                "subject_public_key": self.credential["subject_public_key"],
                "attribute_commitments": self.credential["attribute_commitments"],
                "revocation_index": self.credential["revocation_index"],
                "issued_at": self.credential["issued_at"],
                "expires_at": self.credential["expires_at"],
                "issuer_signature": self.credential["signature"],
                "disclosed_attributes": disclosed_attributes,
                "challenge": verifier_challenge_hex,
                "proof_of_possession": proof_of_possession,
            }
        finally:
            self.lock()   # single-use authorization
