"""Credential issuer: signs credentials and maintains the revocation status list."""
import threading
import uuid
from datetime import datetime, timedelta, timezone

import crypto_utils

MAX_CREDENTIALS = 100_000   


class CredentialRequestError(Exception):
    """A holder's credential request cannot be honored."""


class Issuer:
    def __init__(self, issuer_id, registry, status_cache=None):
        self.issuer_id = issuer_id
        self.registry = registry
        self.status_cache = status_cache
        self.private_key, self.public_key = crypto_utils.generate_keypair()
        self._published = False
        self.status_list = []          
        self._active_by_subject = {}   
        self._lock = threading.Lock()

    
    def publish_key(self):
        pem = crypto_utils.public_key_to_pem(self.public_key)
        result = self.registry.publish_issuer_key(self.issuer_id, pem)
        self._published = True
        return result

    def _publish_status_list(self):
        if self.status_cache is not None:
            self.status_cache.publish(self.issuer_id, self.status_list)

   
    def issue_credential(self, student_record, holder_public_key_hex, validity_days=180):
        """`student_record` is the claims dict the caller (issuer_app.py) already
        obtained by validating an OAuth access token against the Portal. This
        method never sees a username, password, or token."""
        if not self._published:
            raise RuntimeError("issuer has not published its key to the registry yet")
        if not student_record or not isinstance(student_record, dict):
            raise CredentialRequestError("no student record supplied")
        if student_record.get("enrollment_status") != "active":
            raise CredentialRequestError("cannot issue credential: enrollment_status is not 'active'")

        subject_id = student_record.get("student_id")
        if not isinstance(subject_id, str) or not subject_id:
            raise CredentialRequestError("student record has no student_id")

        
        try:
            crypto_utils.ec_point_from_hex(holder_public_key_hex)
        except ValueError as e:
            raise CredentialRequestError("holder_public_key_hex is not a valid secp256k1 public key") from e

        attribute_commitments = {}
        attribute_disclosures = {}
        for name, value in student_record.items():
            blinding, commitment_point = crypto_utils.pedersen_commit(value)
            attribute_commitments[name] = crypto_utils.ec_point_to_hex(commitment_point)
            attribute_disclosures[name] = {"value": value, "blinding": str(blinding)}

        with self._lock:
            existing = self._active_by_subject.get(subject_id)
            if existing is not None and not self.status_list[existing]:
                raise CredentialRequestError(
                    "an active credential already exists for this student; revoke it before requesting a new one"
                )
            if len(self.status_list) >= MAX_CREDENTIALS:
                raise CredentialRequestError("issuer capacity reached")

            revocation_index = len(self.status_list)
            self.status_list.append(False)
            self._active_by_subject[subject_id] = revocation_index
            self._publish_status_list()

        now = datetime.now(timezone.utc)
        credential = {
            "credential_id": str(uuid.uuid4()),
            "issuer_id": self.issuer_id,
            "subject_public_key": holder_public_key_hex,
            "attribute_commitments": attribute_commitments,
            "revocation_index": revocation_index,
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(days=validity_days)).isoformat(),
        }
        credential["signature"] = crypto_utils.sign_payload(self.private_key, credential)
        return {"credential": credential, "attribute_disclosures": attribute_disclosures}

    # ---- revocation ------------------------------------------------------------
    def revoke_credential(self, revocation_index):
        """Raises ValueError for anything but an existing, non-negative index.
        (A negative index would silently revoke from the END of the list.)"""
        if isinstance(revocation_index, bool) or not isinstance(revocation_index, int):
            raise ValueError("revocation_index must be an integer")
        with self._lock:
            if not 0 <= revocation_index < len(self.status_list):
                raise ValueError("revocation_index out of range")
            self.status_list[revocation_index] = True
            self._publish_status_list()

    def get_status_list(self):
        with self._lock:
            return list(self.status_list)
