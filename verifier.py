"""Presentation verifier. Fails CLOSED: any malformed, unexpected or
unverifiable input yields (False, reason) -- never an exception, never True."""
import hashlib
import logging
import os
import re
from datetime import datetime, timedelta, timezone

import crypto_utils

log = logging.getLogger("shieldid.verifier")

MAX_ATTRIBUTES = 32
MAX_FIELD_LEN = 4096
MAX_CLOCK_SKEW = timedelta(minutes=5)
_CHALLENGE_RE = re.compile(r"[0-9a-fA-F]{32,128}")


def issue_challenge(nbytes=16) -> bytes:
    """Fresh, unpredictable, single-use challenge nonce."""
    return os.urandom(nbytes)


def _is_str(v, max_len=MAX_FIELD_LEN):
    return isinstance(v, str) and 0 < len(v) <= max_len


def _parse_time(value):
    """Timezone-aware ISO-8601 -> datetime, else None."""
    try:
        dt = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo is not None else None


class Verifier:
    def __init__(self, registry, status_cache, policy, trusted_issuers):
        """`trusted_issuers`: issuer ids this verifier accepts. Being present in
        the registry is NOT sufficient -- the verifier decides whom to trust."""
        self.registry = registry
        self.status_cache = status_cache
        self.policy = policy
        self.trusted_issuers = frozenset(trusted_issuers)

    def decide(self, presentation) -> bool:
        return self.verify_presentation(presentation)[0]

    def verify_presentation(self, presentation):
        try:
            return self._verify(presentation)
        except Exception as e:   # fail closed; log only the type (message may echo attacker input)
            log.error("unexpected %s while verifying a presentation", type(e).__name__)
            return False, "internal verification error"

    
    def _verify(self, p):
        if not isinstance(p, dict):
            return False, "malformed presentation"

        
        issuer_id = p.get("issuer_id")
        if not _is_str(issuer_id, 128):
            return False, "malformed issuer id"
        if issuer_id not in self.trusted_issuers:
            return False, "issuer not trusted by this verifier"

        credential_id = p.get("credential_id")
        commitments = p.get("attribute_commitments")
        index = p.get("revocation_index")
        disclosed = p.get("disclosed_attributes")
        if not (_is_str(credential_id, 100) and _is_str(p.get("subject_public_key"), 200)
                and _is_str(p.get("issued_at"), 64) and _is_str(p.get("expires_at"), 64)
                and _is_str(p.get("issuer_signature"))):
            return False, "malformed credential fields"
        if not isinstance(commitments, dict) or not 0 < len(commitments) <= MAX_ATTRIBUTES:
            return False, "malformed attribute commitments"
        if isinstance(index, bool) or not isinstance(index, int) or index < 0:
            return False, "malformed revocation index"
        if not isinstance(disclosed, dict) or len(disclosed) > MAX_ATTRIBUTES:
            return False, "malformed disclosures"
        challenge = p.get("challenge")
        if not isinstance(challenge, str) or not _CHALLENGE_RE.fullmatch(challenge):
            return False, "malformed proof context"

        raw_key = self.registry.get_issuer_key(issuer_id)
        if raw_key is None:
            return False, "issuer unknown to registry"
        if isinstance(raw_key, (bytes, bytearray)):
            raw_key = raw_key.decode()
        try:
            issuer_public_key = crypto_utils.public_key_from_pem(raw_key)
        except ValueError:
            return False, "malformed issuer key"

        signed_part = {
            "credential_id": credential_id,
            "issuer_id": issuer_id,
            "subject_public_key": p["subject_public_key"],
            "attribute_commitments": commitments,
            "revocation_index": index,
            "issued_at": p["issued_at"],
            "expires_at": p["expires_at"],
        }
        if not crypto_utils.verify_signature(issuer_public_key, signed_part, p["issuer_signature"]):
            return False, "invalid issuer signature"

        
        now = datetime.now(timezone.utc)
        expires_at, issued_at = _parse_time(p["expires_at"]), _parse_time(p["issued_at"])
        if expires_at is None or issued_at is None:
            return False, "malformed validity period"
        if now > expires_at:
            return False, "credential expired"
        if issued_at > now + MAX_CLOCK_SKEW:
            return False, "credential issued in the future"

        
        context = bytes.fromhex(challenge) + credential_id.encode()
        try:
            subject_point = crypto_utils.ec_point_from_hex(p["subject_public_key"])
        except ValueError:
            return False, "malformed subject key"
        if not crypto_utils.schnorr_verify(subject_point, p.get("proof_of_possession"), context):
            return False, "invalid proof of possession"

        
        
        required_attr = self.policy["required_attribute"]
        required_value = self.policy["required_value"]
        required_entry = disclosed.get(required_attr)
        if not isinstance(required_entry, dict):
            return False, "required attribute not disclosed"
        if not _is_str(commitments.get(required_attr), 200):
            return False, "no commitment for required attribute"
        try:
            required_point = crypto_utils.ec_point_from_hex(commitments[required_attr])
        except ValueError:
            return False, "malformed attribute commitment"
        attr_context = hashlib.sha256(context + b"|" + required_attr.encode()).digest()
        if not crypto_utils.verify_attribute_equals(
                required_point, required_value, required_entry.get("proof"), attr_context):
            return False, "disclosed attribute does not satisfy policy"

        
        for name, entry in disclosed.items():
            if name == required_attr:
                continue
            if not isinstance(entry, dict) or not _is_str(commitments.get(name), 200):
                return False, f"malformed disclosure for an attribute"
            value = entry.get("value")
            if not (isinstance(value, (str, int, float, bool)) and len(str(value)) <= 256):
                return False, "malformed disclosure for an attribute"
            try:
                point = crypto_utils.ec_point_from_hex(commitments[name])
                blinding_raw = entry.get("blinding")
                if not isinstance(blinding_raw, (str, int)) or len(str(blinding_raw)) > 80:
                    raise ValueError
                blinding = int(blinding_raw)
            except ValueError:
                return False, "malformed disclosure for an attribute"
            if not crypto_utils.pedersen_open_verify(point, value, blinding):
                return False, "attribute commitment mismatch"

        
        status_list = self.status_cache.get(issuer_id)
        if status_list is None or index >= len(status_list):
            return False, "status list unavailable for this credential index"
        if status_list[index]:
            return False, "credential revoked"

        return True, "all checks passed"
