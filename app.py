import logging
import os
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone

import requests
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import config
from security_utils import (
    UntrustedCallbackURLError, login_tracker, pin_tracker, portal_tracker,
    sanitize_log_value, validate_callback_url,
)
from shared_state import portal
from wallet import Wallet, WalletLockedError, burn_password_check
from web_security import init_security_headers

log = logging.getLogger("shieldid.wallet_app")

app = Flask(__name__)


app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=15)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

limiter = Limiter(key_func=get_remote_address, app=app, storage_uri="memory://")
init_security_headers(app)

MAX_SESSION_HOURS = 2
PENDING_STEP_SECONDS = 300      # time allowed between password step and MFA step
OAUTH_STATE_TTL_SECONDS = 300


# --- Demo data ---------------------------------------------------------------
def _seed_demo_student():
    """Creates the single demo University Portal account. The password is NEVER
    hardcoded: it comes from DEMO_STUDENT_PASSWORD (written to .env by
    setup_dev.py) or is generated for this run and printed once."""
    username = os.environ.get("DEMO_STUDENT_USERNAME", "sara222")
    password = os.environ.get("DEMO_STUDENT_PASSWORD")
    generated = not password
    if generated:
        password = secrets.token_urlsafe(14)
    portal.register_student(
        username=username,
        password=password,
        student_record={
            "student_id": "S1029384",
            "name": "Sara Ahmad",
            "program": "B.Sc. Computer Science",
            "enrollment_status": "active",
        },
    )
    if generated:
        print(f"[demo] University Portal login -> username: {username}  password: {password}")


_seed_demo_student()




COMMON_PASSWORDS = {
    "password", "password123", "password1234", "12345678", "123456789", "1234567890",
    "qwerty123", "qwertyuiop", "letmein123", "welcome123", "admin1234", "changeme123",
    "iloveyou1", "abc123456", "football1", "trustno1", "monkey123", "dragon123",
    "sunshine1", "princess1", "1q2w3e4r5t", "jordan1234", "student123", "university1",
}

PASSWORD_MIN_LENGTH = 12  
PASSWORD_MAX_LENGTH = 128 


def validate_pin(pin: str) -> tuple[bool, str]:
    if not pin or not pin.isdigit() or len(pin) < 4 or len(pin) > 8:
        return False, "PIN must be between 4 and 8 numerical digits."
    return True, ""


def validate_password_nist(password: str, username: str = "") -> tuple[bool, str]:
    """
    Password policy informed by NIST SP 800-63B and OWASP ASVS:
      - Minimum length (OWASP ASVS L1 baseline of 12; NIST's own hard floor is 8,
        current NIST Rev.4 guidance actually recommends >=15 chars for password-only
        auth and explicitly does NOT require character-class composition rules -
        we still enforce classes below for user education purposes, as requested).
      - Enforces presence of lowercase, uppercase, digit, and special character.
      - Rejects passwords found in a known-common/breached password blocklist.
      - Rejects passwords that simply contain the username.
    Returns (is_valid, message) where message lists ALL unmet requirements at once
    so the user isn't stuck fixing one issue per submit.
    """
    errors = []

    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(f"be at least {PASSWORD_MIN_LENGTH} characters long")
    if len(password) > PASSWORD_MAX_LENGTH:
        errors.append(f"be no more than {PASSWORD_MAX_LENGTH} characters long")
    if not re.search(r"[a-z]", password):
        errors.append("include a lowercase letter (a-z)")
    if not re.search(r"[A-Z]", password):
        errors.append("include an uppercase letter (A-Z)")
    if not re.search(r"\d", password):
        errors.append("include a number (0-9)")
    if not re.search(r"[^\w\s]", password):
        errors.append("include a special character (e.g. ! @ # $ % ^ & *)")

    if errors:
        return False, "Password must " + "; ".join(errors) + "."

    if password.lower() in COMMON_PASSWORDS:
        return False, "This password is too common or has appeared in known data breaches. Please choose a stronger one."

    if username and username.lower() in password.lower():
        return False, "Password must not contain your username."

    return True, ""

def validate_username(username: str) -> tuple[bool, str]:
    if not username or len(username) < 3 or len(username) > 30:
        return False, "Username must be between 3 and 30 characters."
    if not re.fullmatch(r"[a-zA-Z0-9_.-]+", username):
        return False, "Username contains invalid characters. Use alphanumeric, dots, underscores, or hyphens."
    return True, ""


def get_csrf_token() -> str:
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(16)
    return session["_csrf_token"]


def _safe_equal(a, b) -> bool:
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return secrets.compare_digest(a.encode(), b.encode())


def require_csrf():
    expected = session.get("_csrf_token", "")
    if not expected or not _safe_equal(request.form.get("csrf_token", ""), expected):
        abort(403, description="Invalid or missing CSRF token. Please refresh the page and try again.")


wallets = {}
_wallets_lock = threading.Lock()


def get_current_wallet():
    username = session.get("wallet_username")
    return wallets.get(username) if username else None


def _auth_page():
    return render_template("wallet.html", wallet=None, card=None, mode="auth", csrf_token=get_csrf_token())


def _pending(key):
    """Username stored by an unfinished login/registration step, if it is still fresh."""
    if time.time() > session.get("pending_exp", 0):
        return None
    return session.get(key)


@app.before_request
def check_session_timeouts():
    session.modified = True   
    if "wallet_username" in session:
        auth_time_iso = session.get("auth_time")
        if auth_time_iso:
            auth_time = datetime.fromisoformat(auth_time_iso)
            if datetime.now(timezone.utc) - auth_time > timedelta(hours=MAX_SESSION_HOURS):
                session.clear()
                flash("Your session has reached its maximum lifetime (2 hours). Please log in again.", "warning")
                return redirect(url_for("auth_wallet"))


@app.route("/")
def index():
    wallet = get_current_wallet()
    if not wallet:
        return redirect(url_for("auth_wallet"))

    card_data = None
    if wallet.credential and wallet.attribute_disclosures:
        card_data = {
            "credential_id": wallet.credential["credential_id"],
            "issuer_id": wallet.credential["issuer_id"],
            "issued_at": wallet.credential["issued_at"][:10],
            "expires_at": wallet.credential["expires_at"][:10],
            "attributes": {k: v["value"] for k, v in wallet.attribute_disclosures.items()},
        }
    return render_template("wallet.html", wallet=wallet, card=card_data, csrf_token=get_csrf_token())


@app.route("/wallet/auth", methods=["GET", "POST"])
@limiter.limit("15 per minute", methods=["POST"])
def auth_wallet():
    if request.method == "POST":
        require_csrf()
        action = request.form.get("action")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        is_valid_user, user_err = validate_username(username)
        if not is_valid_user:
            flash(user_err, "danger")
            return _auth_page()

        if action == "register":
            pin = request.form.get("pin", "")
            confirm_password = request.form.get("confirm_password", "")

            if password != confirm_password:
                flash("Passwords do not match. Please re-type your password.", "danger")
                return _auth_page()
            is_valid_pw, pw_err = validate_password_nist(password, username=username)
            if not is_valid_pw:
                flash(pw_err, "danger")
                return _auth_page()
            is_valid_pin, pin_err = validate_pin(pin)
            if not is_valid_pin:
                flash(pin_err, "danger")
                return _auth_page()

            new_wallet = Wallet(username=username, password=password, pin=pin)
            with _wallets_lock:
                if username in wallets:
                    taken = True
                else:
                    taken = False
                    wallets[username] = new_wallet
            if taken:
                flash("That username is already taken.", "danger")
                return _auth_page()

           
            session.clear()
            session["pending_mfa_setup_username"] = username
            session["pending_exp"] = time.time() + PENDING_STEP_SECONDS
            flash("Wallet created! Now set up your authenticator app to finish registration.", "success")
            return redirect(url_for("setup_mfa"))

        elif action == "login":
            rate_key = f"login:{username}"
            locked, retry_after = login_tracker.is_locked(rate_key)
            if locked:
                flash(f"Too many failed attempts. Please try again in {retry_after} seconds.", "danger")
                return _auth_page()

            login_tracker.progressive_delay(rate_key)
            wallet = wallets.get(username)
            if wallet is None:
                burn_password_check(password)   # same cost as a real check: no username enumeration by timing
                ok = False
            else:
                ok = wallet.verify_password(password, ip=request.remote_addr)
            if ok:
                login_tracker.record_success(rate_key)
                session.clear()
                session["pending_mfa_username"] = username
                session["pending_exp"] = time.time() + PENDING_STEP_SECONDS
                return redirect(url_for("verify_mfa"))
            login_tracker.record_failure(rate_key)
            flash("Invalid username or password.", "danger")

    return render_template("wallet.html", wallet=get_current_wallet(), card=None, mode="auth", csrf_token=get_csrf_token())


def _finish_login(username: str):
    """Called once password + TOTP have both been verified."""
    session.clear()  
    session.permanent = True
    session["wallet_username"] = username
    session["auth_time"] = datetime.now(timezone.utc).isoformat()  
    session["_csrf_token"] = secrets.token_hex(16)


@app.route("/wallet/setup-mfa", methods=["GET", "POST"])
@limiter.limit("20 per minute", methods=["POST"])
def setup_mfa():
    """Shown once after registration: scan a QR code with an authenticator app
    and confirm with a live code."""
    username = _pending("pending_mfa_setup_username")
    if not username or username not in wallets:
        flash("Please register or log in first.", "danger")
        return redirect(url_for("auth_wallet"))
    wallet = wallets[username]

    if request.method == "POST":
        require_csrf()
        rate_key = f"mfa-setup:{username}"
        locked, retry_after = login_tracker.is_locked(rate_key)
        if locked:
            flash(f"Too many failed codes. Please try again in {retry_after} seconds.", "danger")
        elif wallet.verify_totp(request.form.get("totp_code", "").strip()):
            login_tracker.record_success(rate_key)
            wallet.mfa_enabled = True
            _finish_login(username)
            flash("Authenticator app linked! Your wallet now requires two factors to log in.", "success")
            return redirect(url_for("index"))
        else:
            login_tracker.record_failure(rate_key)
            flash("That code didn't match. Check the time on your phone and try again.", "danger")

    return render_template(
        "mfa.html", mode="setup", username=username,
        totp_uri=wallet.get_totp_uri(), totp_secret=wallet.totp_secret, csrf_token=get_csrf_token(),
    )


@app.route("/wallet/verify-mfa", methods=["GET", "POST"])
@limiter.limit("20 per minute", methods=["POST"])
def verify_mfa():
    """Second step of login: a live TOTP code from the enrolled device."""
    username = _pending("pending_mfa_username")
    if not username or username not in wallets:
        flash("Please log in again.", "danger")
        return redirect(url_for("auth_wallet"))
    wallet = wallets[username]

    if request.method == "POST":
        require_csrf()
        rate_key = f"mfa:{username}"
        locked, retry_after = login_tracker.is_locked(rate_key)
        if locked:
            flash(f"Too many failed codes. Please try again in {retry_after} seconds.", "danger")
            return render_template("mfa.html", mode="verify", username=username, csrf_token=get_csrf_token())

        login_tracker.progressive_delay(rate_key)
        if wallet.verify_totp(request.form.get("totp_code", "").strip()):
            login_tracker.record_success(rate_key)
            _finish_login(username)
            flash("Wallet unlocked!", "success")
            return redirect(url_for("index"))
        login_tracker.record_failure(rate_key)
        flash("Incorrect authenticator code.", "danger")

    return render_template("mfa.html", mode="verify", username=username, csrf_token=get_csrf_token())


def _pin_gate(wallet, failure_message):
    """Checks the PIN in the request with lockout + progressive delay.
    Returns None on success, or a redirect response to return immediately."""
    rate_key = f"pin:{wallet.username}"
    locked, retry_after = pin_tracker.is_locked(rate_key)
    if locked:
        flash(f"Too many incorrect PIN attempts. Please try again in {retry_after} seconds.", "danger")
        return redirect(url_for("index"))
    pin_tracker.progressive_delay(rate_key)
    if not wallet.unlock_with_pin(request.form.get("pin", ""), ip=request.remote_addr):
        pin_tracker.record_failure(rate_key)
        flash(failure_message, "danger")
        return redirect(url_for("index"))
    pin_tracker.record_success(rate_key)
    return None


@app.route("/wallet/issue-vc", methods=["POST"])
def trigger_issue_vc():
    """PIN-authorised start of the OAuth issuance flow."""
    require_csrf()
    wallet = get_current_wallet()
    if not wallet:
        flash("You must be logged in to request credentials.", "danger")
        return redirect(url_for("auth_wallet"))

    if wallet.has_credential_from_issuer(config.ISSUER_ID):
        flash(f"You already hold an active Verifiable Credential from {config.ISSUER_ID}.", "warning")
        return redirect(url_for("index"))

    denied = _pin_gate(wallet, "Incorrect PIN! Unable to authorize credential issuance.")
    if denied:
        return denied

   
    
    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state
    session["oauth_state_exp"] = time.time() + OAUTH_STATE_TTL_SECONDS
    return redirect(url_for("oauth_authorize", client_id=config.WALLET_CLIENT_ID,
                            response_type="code", state=state))


@app.route("/wallet/revoke-vc", methods=["POST"])
def revoke_vc():
    require_csrf()
    wallet = get_current_wallet()
    if not wallet:
        flash("You must be logged in to revoke a credential.", "danger")
        return redirect(url_for("auth_wallet"))
    if not wallet.credential:
        flash("No active credential to revoke.", "warning")
        return redirect(url_for("index"))

    denied = _pin_gate(wallet, "Incorrect PIN! Unable to authorize revocation.")
    if denied:
        return denied

   
   
    try:
        revoke_res = requests.post(
            config.ISSUER_REVOKE_CREDENTIAL_URL,
            json={"revocation_index": wallet.credential["revocation_index"]},
            headers={
                "X-Resource-Client-Id": config.WALLET_SERVICE_CLIENT_ID,
                "X-Resource-Client-Secret": config.WALLET_SERVICE_CLIENT_SECRET,
            },
            timeout=5,
            verify=config.TLS_CA_BUNDLE,
            allow_redirects=False,
        )
    except requests.RequestException as e:
        log.error("revocation call failed: %s", type(e).__name__)
        wallet.lock()
        flash("Revocation failed: could not reach the issuer service.", "danger")
        return redirect(url_for("index"))
    finally:
        wallet.lock()

    if revoke_res.status_code != 200:
        log.error("issuer rejected revocation: HTTP %s", revoke_res.status_code)
        flash("Revocation failed: the issuer rejected the request.", "danger")
        return redirect(url_for("index"))

    wallet.clear_revoked_credential()
    flash("Your credential has been revoked. You may request a new one whenever you're ready.", "success")
    return redirect(url_for("index"))


@app.route("/wallet/logs")
def wallet_auth_logs():
    wallet = get_current_wallet()
    if not wallet:
        flash("You must be logged in to view your security log.", "danger")
        return redirect(url_for("auth_wallet"))
    return render_template("wallet_logs.html", wallet=wallet, logs=wallet.get_auth_log())


@app.route("/wallet/logout", methods=["POST"])
def logout_wallet():
    """POST + CSRF so a third-party page can't log the user out."""
    require_csrf()
    wallet = get_current_wallet()
    if wallet:
        wallet.lock()
    session.clear()
    flash("Logged out of wallet.", "success")
    return redirect(url_for("auth_wallet"))


def _validated_oauth_request():
    """Rejects authorization requests that didn't originate from this wallet
    session (unknown client, wrong response_type, missing/forged state)."""
    state = request.args.get("state", "")
    expected = session.get("oauth_state")
    if (request.args.get("client_id") != config.WALLET_CLIENT_ID
            or request.args.get("response_type") != "code"
            or not expected or not _safe_equal(state, expected)
            or time.time() > session.get("oauth_state_exp", 0)):
        abort(400, description="Invalid authorization request. Start again from your wallet.")
    return state


@app.route("/oauth/authorize", methods=["GET", "POST"])
@limiter.limit("20 per minute", methods=["POST"])
def oauth_authorize():
    """The Portal's own login page (RFC 6749 authorization endpoint). The only
    place a student's password is entered; the wallet only ever gets a code."""
    state = _validated_oauth_request()
    if request.method == "POST":
        require_csrf()
        username = request.form.get("username")
        password = request.form.get("password")
        username = username if isinstance(username, str) else ""

        rate_key = f"portal:{username[:64]}"
        locked, retry_after = portal_tracker.is_locked(rate_key)
        if locked:
            flash(f"Too many failed attempts. Please try again in {retry_after} seconds.", "danger")
            return render_template("portal_login.html", csrf_token=get_csrf_token())

        portal_tracker.progressive_delay(rate_key)
        if portal.authenticate(username, password):
            portal_tracker.record_success(rate_key)
            code = portal.mint_authorization_code(
                username=username, scope=config.OAUTH_SCOPE, client_id=config.WALLET_CLIENT_ID)
            return redirect(url_for("oauth_callback", code=code, state=state))
        portal_tracker.record_failure(rate_key)
        flash("Invalid University Portal Credentials!", "danger")

    return render_template("portal_login.html", csrf_token=get_csrf_token())


@app.route("/oauth/token", methods=["POST"])
@limiter.limit("30 per minute")
def oauth_token():
    """RFC 6749 4.1.3 token endpoint -- server-to-server; the caller must
    present client_id/client_secret alongside the code."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = request.form
    code, client_id, client_secret = data.get("code"), data.get("client_id"), data.get("client_secret")

    if not all(isinstance(v, str) and v for v in (code, client_id, client_secret)):
        return jsonify({"error": "invalid_request"}), 400
    try:
        token_response = portal.exchange_code_for_token(code, client_id, client_secret)
    except ValueError as e:
        return jsonify({"error": "invalid_grant", "error_description": str(e)}), 400
    return jsonify(token_response), 200


@app.route("/oauth/introspect", methods=["POST"])
@limiter.limit("60 per minute")
def oauth_introspect():
    """RFC 7662 introspection. Called by the Issuer service; gated by its own
    resource-server credentials so it isn't a public token oracle."""
    if not (_safe_equal(request.headers.get("X-Resource-Client-Id"), config.ISSUER_SERVICE_CLIENT_ID)
            and _safe_equal(request.headers.get("X-Resource-Client-Secret"), config.ISSUER_SERVICE_CLIENT_SECRET)):
        return jsonify({"active": False}), 401
    data = request.get_json(silent=True)
    token = data.get("access_token", "") if isinstance(data, dict) else ""
    return jsonify(portal.introspect_token(token)), 200


@app.route("/wallet/callback")
def oauth_callback():
    """Wallet backend exchanges the authorization code for an access token, then
    hands that token (never a password) to the Issuer for a credential."""
    code = request.args.get("code")
    wallet = get_current_wallet()

    
    expected = session.pop("oauth_state", None)
    expiry = session.pop("oauth_state_exp", 0)
    if (not wallet or not isinstance(code, str) or not code or not expected
            or not _safe_equal(request.args.get("state", ""), expected) or time.time() > expiry):
        flash("OAuth authorization failed.", "danger")
        return redirect(url_for("index"))

    try:
        token_res = requests.post(
            f"{config.PORTAL_BASE_URL}/oauth/token",
            json={"code": code, "client_id": config.WALLET_CLIENT_ID,
                  "client_secret": config.WALLET_CLIENT_SECRET},
            timeout=5,
            verify=config.TLS_CA_BUNDLE,
            allow_redirects=False,
        )
        if token_res.status_code != 200:
            raise RuntimeError("token exchange failed")
        access_token = token_res.json()["access_token"]
        wallet.request_credential(access_token)
        flash("Verifiable Credential successfully issued and saved to wallet!", "success")
    except WalletLockedError:
        flash("Your PIN authorization expired. Please start again.", "warning")
    except Exception as e:   # noqa: BLE001 - show a safe message, log the detail
        log.error("issuance failed: %s", sanitize_log_value(f"{type(e).__name__}: {e}"))
        # CredentialRequestError messages are already sanitised, user-facing text.
        user_msg = str(e) if type(e).__name__ == "CredentialRequestError" else "Credential issuance failed."
        flash(f"Issuance Error: {user_msg}", "danger")
    return redirect(url_for("index"))


@app.route("/wallet/present-vc", methods=["POST"])
def present_vc():
    require_csrf()
    wallet = get_current_wallet()
    if not wallet or not wallet.credential:
        flash("No active credential found in wallet.", "warning")
        return redirect(url_for("index"))

    verifier_challenge = request.form.get("challenge")
  
   
    raw_callback_url = request.form.get("callback_url", "https://localhost:5001/api/verify")
    
    required_attribute = request.form.get("required_attribute", "enrollment_status")
    required_value = request.form.get("required_value", "active")
    extra_attributes = request.form.getlist("extra_attributes")

    if not verifier_challenge:
        flash("Invalid QR Code: Missing challenge nonce.", "danger")
        return redirect(url_for("index"))

    try:
        callback_url = validate_callback_url(raw_callback_url)
    except UntrustedCallbackURLError as e:
        flash(f"⚠️ {e}", "danger")
        return redirect(url_for("index"))

   
    denied = _pin_gate(wallet, "Incorrect PIN! Unable to authorize this presentation.")
    if denied:
        return denied

    try:
        presentation = wallet.create_presentation(
            verifier_challenge, required_attribute, required_value, extra_attributes=extra_attributes)
        res = requests.post(callback_url, json=presentation, timeout=5,
                            verify=config.TLS_CA_BUNDLE, allow_redirects=False)
        accepted = False
        if res.status_code == 200:
            try:
                accepted = res.json().get("success") is True
            except ValueError:
                accepted = False
        if accepted:
            flash("✅ Proof generated and accepted by the verifier.", "success")
        else:
            flash("⚠️ The verifier did not accept the proof.", "warning")
    except (ValueError, WalletLockedError) as e:
        flash(f"Presentation Error: {sanitize_log_value(e, 120)}", "danger")
    except requests.RequestException as e:
        log.error("presentation delivery failed: %s", type(e).__name__)
        flash("Presentation Error: could not reach the verifier.", "danger")
    except Exception as e:   # noqa: BLE001
        log.error("presentation failed: %s", type(e).__name__)
        flash("Presentation Error: something went wrong.", "danger")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host=config.BIND_HOST, port=5000, debug=False, use_reloader=False,
            ssl_context=config.tls_context(), threaded=True)
