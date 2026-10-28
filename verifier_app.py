
import logging
import os
import re
import secrets
import threading
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import config
from verifier import Verifier, issue_challenge
from verifier_state import registry, status_cache  
from web_security import init_security_headers

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024     
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
limiter = Limiter(key_func=get_remote_address, app=app, storage_uri="memory://")
init_security_headers(app)
log = logging.getLogger("shieldid.verifier")


_SAFE_EXTERNAL_REASONS = {
    "unknown challenge nonce",
    "challenge expired -- please rescan a fresh QR code",
    "challenge already used",
}


def _external_reason(internal_reason: str) -> str:
    """Collapse every crypto/credential failure into one message so the response
    can't be used as an oracle for which part of a forged proof failed. The
    precise reason is logged server-side."""
    return internal_reason if internal_reason in _SAFE_EXTERNAL_REASONS else "verification failed"


policy = {"required_attribute": "enrollment_status", "required_value": "active"}
verifier = Verifier(registry=registry, status_cache=status_cache, policy=policy,
                    trusted_issuers=config.TRUSTED_ISSUER_IDS)

CHALLENGE_TTL = timedelta(minutes=5)
MAX_PENDING_CHALLENGES = 5_000
_CHALLENGE_RE = re.compile(r"[0-9a-f]{32}")


verification_results = {}
_results_lock = threading.Lock()


def _is_expired(entry) -> bool:
    return datetime.now(timezone.utc) - entry["issued_at"] > CHALLENGE_TTL


def _purge_expired_locked():
    cutoff = datetime.now(timezone.utc) - 2 * CHALLENGE_TTL
    for k in [k for k, v in verification_results.items() if v["issued_at"] < cutoff]:
        del verification_results[k]


@app.route("/", methods=["GET"])
@limiter.limit("30 per minute")
def index():
    """Renders the verifier page and registers a new challenge nonce."""
    challenge_hex = issue_challenge().hex()
    with _results_lock:
        _purge_expired_locked()
        if len(verification_results) >= MAX_PENDING_CHALLENGES:
            return "Too many pending verification requests. Please retry shortly.", 503
        verification_results[challenge_hex] = {
            "status": "pending",
            "reason": "Awaiting ZK proof presentation...",
            "issued_at": datetime.now(timezone.utc),
            "consumed": False,
        }
    return render_template(
        "verifier.html", challenge=challenge_hex,
        callback_url=config.VERIFIER_PUBLIC_CALLBACK_URL,
        required_attribute=policy["required_attribute"], required_value=policy["required_value"],
    )


@app.route("/api/verify", methods=["POST"])
@limiter.limit("20 per minute")
def verify_presentation_api():
    """Called directly by the wallet backend (JSON only)."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"success": False, "reason": "verification failed"}), 400
    challenge = payload.get("challenge")
    if not isinstance(challenge, str) or not _CHALLENGE_RE.fullmatch(challenge):
        return jsonify({"success": False, "reason": "unknown challenge nonce"})

    with _results_lock:
        entry = verification_results.get(challenge)
        if entry is None:
            return jsonify({"success": False, "reason": "unknown challenge nonce"})
        if _is_expired(entry):
            entry["status"], entry["reason"] = "expired", "challenge expired -- please rescan a fresh QR code"
            return jsonify({"success": False, "reason": entry["reason"]})
        
        
        if entry["consumed"]:
            return jsonify({"success": False, "reason": "challenge already used"})
        entry["consumed"] = True

    decision, reason = verifier.verify_presentation(payload)

    with _results_lock:
        entry["status"] = "passed" if decision else "failed"
        entry["reason"] = _external_reason(reason) if not decision else "verified"
        if not decision:
            entry["consumed"] = False   # a failed attempt doesn't burn the QR code
    if not decision:
        log.info("presentation rejected: %s", reason)
    return jsonify({"success": decision, "reason": entry["reason"]})


@app.route("/api/status/<challenge>", methods=["GET"])
@limiter.limit("120 per minute")
def check_status(challenge):
    """Polled by verifier.html every 2 seconds."""
    if not _CHALLENGE_RE.fullmatch(challenge):
        return jsonify({"status": "unknown", "reason": "Invalid challenge nonce"})
    with _results_lock:
        entry = verification_results.get(challenge)
        if entry is None:
            return jsonify({"status": "unknown", "reason": "Invalid challenge nonce"})
        if entry["status"] == "pending" and _is_expired(entry):
            entry["status"] = "expired"
            entry["reason"] = "Challenge expired -- please refresh the page for a new QR code."
        return jsonify({"status": entry["status"], "reason": entry["reason"]})


@app.errorhandler(413)
def too_large(_e):
    return jsonify({"success": False, "reason": "verification failed"}), 413


if __name__ == "__main__":
    app.run(host=config.BIND_HOST, port=5001, debug=False, ssl_context=config.tls_context())
