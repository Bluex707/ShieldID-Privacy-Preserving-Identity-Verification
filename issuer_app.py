"""Standalone Issuer service. Issues credentials against OAuth access tokens and
revokes them on behalf of the wallet backend."""
import hmac
import logging
import os
import secrets

import requests
from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import config
from issuer import CredentialRequestError
from issuer_state import issuer  
from security_utils import issue_tracker
from web_security import init_security_headers

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
limiter = Limiter(key_func=get_remote_address, app=app, storage_uri="memory://")
init_security_headers(app)
log = logging.getLogger("shieldid.issuer")


def _safe_equal(a, b) -> bool:
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return hmac.compare_digest(a.encode(), b.encode())


def _wallet_service_authenticated() -> bool:
    """Is the caller the wallet backend? Without this, /issuer/revoke-credential
    would be an unauthenticated 'revoke anyone by index' endpoint."""
    return (
        _safe_equal(request.headers.get("X-Resource-Client-Id"), config.WALLET_SERVICE_CLIENT_ID)
        and _safe_equal(request.headers.get("X-Resource-Client-Secret"), config.WALLET_SERVICE_CLIENT_SECRET)
    )


@app.route("/issuer/issue-credential", methods=["POST"])
@limiter.limit("20 per minute")
def issue_credential_endpoint():
    """Called by the wallet backend with {access_token, holder_public_key_hex}.
    The token is validated via the Portal's /oauth/introspect endpoint; no
    password ever reaches this process."""
    rate_key = f"issue:{request.remote_addr}"
    locked, retry_after = issue_tracker.is_locked(rate_key)
    if locked:
        return jsonify({"error": "rate_limited", "retry_after": retry_after}), 429
    issue_tracker.progressive_delay(rate_key)

    data = request.get_json(silent=True)
    data = data if isinstance(data, dict) else {}
    access_token = data.get("access_token")
    holder_public_key_hex = data.get("holder_public_key_hex")

    if not isinstance(access_token, str) or not access_token or not isinstance(holder_public_key_hex, str):
        issue_tracker.record_failure(rate_key)
        return jsonify({
            "error": "invalid_request",
            "error_description": "access_token and holder_public_key_hex are required",
        }), 400

    try:
        introspect_res = requests.post(
            f"{config.PORTAL_BASE_URL}/oauth/introspect",
            json={"access_token": access_token},
            headers={
                "X-Resource-Client-Id": config.ISSUER_SERVICE_CLIENT_ID,
                "X-Resource-Client-Secret": config.ISSUER_SERVICE_CLIENT_SECRET,
            },
            timeout=5,
            verify=config.TLS_CA_BUNDLE,
            allow_redirects=False,
        )
        introspection = introspect_res.json()
        if not isinstance(introspection, dict):
            raise ValueError("unexpected introspection response")
    except (requests.RequestException, ValueError) as e:
        log.error("portal introspection failed: %s", type(e).__name__)
        return jsonify({"error": "portal_unreachable",
                        "error_description": "could not validate the access token"}), 502

    if not introspection.get("active"):
        issue_tracker.record_failure(rate_key)
        return jsonify({"error": "invalid_token"}), 401

    scope = introspection.get("scope", "")
    if not isinstance(scope, str) or config.OAUTH_SCOPE not in scope.split():
        issue_tracker.record_failure(rate_key)
        return jsonify({"error": "insufficient_scope",
                        "error_description": f"token is missing required scope '{config.OAUTH_SCOPE}'"}), 403

   
    if introspection.get("client_id") != config.WALLET_CLIENT_ID:
        issue_tracker.record_failure(rate_key)
        return jsonify({"error": "invalid_token"}), 401

    try:
        result = issuer.issue_credential(
            student_record=introspection.get("student_record"),
            holder_public_key_hex=holder_public_key_hex,
        )
    except CredentialRequestError as e:
        issue_tracker.record_failure(rate_key)
        return jsonify({"error": "issuance_failed", "error_description": str(e)}), 400

    issue_tracker.record_success(rate_key)
    return jsonify(result), 200


@app.route("/issuer/revoke-credential", methods=["POST"])
@limiter.limit("30 per minute")
def revoke_credential_endpoint():
    """Internal service-to-service endpoint, called by the wallet backend after
    the student authorised revocation with their PIN."""
    if not _wallet_service_authenticated():
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(silent=True)
    data = data if isinstance(data, dict) else {}
    try:
        issuer.revoke_credential(data.get("revocation_index"))
    except ValueError:
        return jsonify({"error": "invalid_revocation_index"}), 400
    return jsonify({"revoked": True}), 200


@app.errorhandler(413)
def too_large(_e):
    return jsonify({"error": "request_too_large"}), 413


if __name__ == "__main__":
    app.run(host=config.BIND_HOST, port=5002, debug=False, ssl_context=config.tls_context())
