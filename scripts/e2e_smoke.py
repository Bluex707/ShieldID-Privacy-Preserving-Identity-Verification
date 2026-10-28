"""End-to-end smoke test against RUNNING services (anvil + issuer_app + app +
verifier_app). Drives the real HTTP flows like a browser would:
register -> MFA -> OAuth issuance -> present -> revoke -> present again,
plus a handful of attack scenarios.

    python scripts/e2e_smoke.py
"""
import os
import re
import sys
import time

import pyotp
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config  # noqa: E402

WALLET, VERIFIER = "https://localhost:5000", "https://localhost:5001"
VERIFY = config.TLS_CA_BUNDLE
PASSWORD, PIN = "Corr3ct-Horse-Battery-Staple", "4821"
USER = f"e2e_{int(time.time())}"
passed = failed = 0


def check(name, cond):
    global passed, failed
    print(("  PASS  " if cond else "  FAIL  ") + name)
    passed, failed = passed + bool(cond), failed + (not cond)


def csrf(html):
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def next_totp(totp):
    """A code from the NEXT 30s step: valid via the +-1 window and never equal to a code already used."""
    return totp.at(int(time.time()) + 30)


def _session():
    sess = requests.Session()
    sess.trust_env = False      # ignore REQUESTS_CA_BUNDLE / proxy env vars: always trust only our dev cert
    sess.verify = VERIFY
    return sess


s = _session()          # the "browser" (keeps cookies)
anon = _session()       # a cookie-less caller

print("== Registration + MFA")
page = s.get(f"{WALLET}/wallet/auth").text
r = s.post(f"{WALLET}/wallet/auth", data={"action": "register", "username": USER, "password": PASSWORD,
           "confirm_password": PASSWORD, "pin": PIN, "csrf_token": csrf(page)})
secret = re.search(r"\b([A-Z2-7]{32})\b", r.text).group(1)
totp = pyotp.TOTP(secret)
r = s.post(f"{WALLET}/wallet/setup-mfa", data={"totp_code": totp.now(), "csrf_token": csrf(r.text)})
check("registered and logged in after MFA setup", "Request New Credential" in r.text or "Wallet" in r.text and "Log Out" in r.text)

print("== Security headers & CSRF")
h = r.headers
check("CSP present with nonce, no unsafe-inline scripts", "script-src 'self' 'nonce-" in h.get("Content-Security-Policy", "") and "unsafe-inline" not in h["Content-Security-Policy"].split("style-src")[0])
check("X-Frame-Options DENY + nosniff + no-store", h.get("X-Frame-Options") == "DENY" and h.get("X-Content-Type-Options") == "nosniff" and h.get("Cache-Control") == "no-store")
check("inline <script> tags carry the nonce", "<script>" not in r.text)
check("POST without CSRF token is rejected (403)", s.post(f"{WALLET}/wallet/revoke-vc", data={"pin": PIN}).status_code == 403)
check("logout via GET no longer works (405)", s.get(f"{WALLET}/wallet/logout").status_code == 405)
dash = s.get(f"{WALLET}/").text
tok = csrf(dash)

print("== Issuance (OAuth with state)")
check("callback with forged code and no state is refused", "OAuth authorization failed" in s.get(f"{WALLET}/wallet/callback?code=forged&state=x", allow_redirects=True).text)
r = s.post(f"{WALLET}/wallet/issue-vc", data={"pin": "0000", "csrf_token": tok}, allow_redirects=True)
check("wrong PIN refuses issuance", "Incorrect PIN" in r.text)
r = s.post(f"{WALLET}/wallet/issue-vc", data={"pin": PIN, "csrf_token": tok}, allow_redirects=False)
authorize_url = r.headers["Location"]
check("authorize redirect carries a state parameter", "state=" in authorize_url)
check("authorize with tampered state is rejected (400)", s.get(WALLET + re.sub(r"state=[^&]+", "state=evil", authorize_url)).status_code == 400)
login = s.get(WALLET + authorize_url)
check("portal login page has NO prefilled credentials", 'value="sara222"' not in login.text and "password123" not in login.text)
bad = s.post(WALLET + authorize_url, data={"username": "sara222", "password": "wrong", "csrf_token": csrf(login.text)})
check("wrong portal password is refused", "Invalid University Portal Credentials" in bad.text)
r = s.post(WALLET + authorize_url, data={"username": "sara222", "password": os.environ["DEMO_STUDENT_PASSWORD"],
           "csrf_token": csrf(login.text)}, allow_redirects=True)
check("credential issued after portal login", "successfully issued" in r.text)
check("student record shown in the wallet", "S1029384" in r.text)

print("== Presentation")
def new_challenge():
    return re.search(r'const challengeNonce = "([0-9a-f]+)"', anon.get(VERIFIER).text).group(1)

def present(challenge, pin, tok, callback=f"{VERIFIER}/api/verify"):
    return s.post(f"{WALLET}/wallet/present-vc", data={"challenge": challenge, "callback_url": callback,
                  "pin": pin, "csrf_token": tok, "required_attribute": "enrollment_status",
                  "required_value": "active"}, allow_redirects=True)

def status(ch):
    return anon.get(f"{VERIFIER}/api/status/{ch}").json()["status"]

ch = new_challenge()
r = present(ch, "0000", tok)
check("presentation WITHOUT correct PIN is refused", "Incorrect PIN" in r.text and status(ch) == "pending")
r = present(ch, PIN, tok, callback="https://169.254.169.254/latest/meta-data")
check("SSRF: non-allow-listed callback_url is refused", "trusted verifiers" in r.text)
r = present(ch, PIN, tok)
check("valid presentation accepted by verifier", "accepted by the verifier" in r.text and status(ch) == "passed")
r = present(ch, PIN, tok)
check("replaying the same challenge is not accepted again", "did not accept" in r.text)
r = anon.post(f"{VERIFIER}/api/verify", data="not json")
check("verifier answers malformed body with 400 (not 500)", r.status_code == 400)
r = anon.post(f"{VERIFIER}/api/verify", json=["x"])
check("verifier answers non-object JSON with 400", r.status_code == 400)
r = anon.post(f"{VERIFIER}/api/verify", json={"challenge": new_challenge(), "issuer_id": {"a": 1}})
check("garbage presentation -> clean refusal, no stack trace", r.status_code == 200 and r.json()["success"] is False and r.json()["reason"] == "verification failed")

print("== Revocation")
r = s.post(f"{WALLET}/wallet/revoke-vc", data={"pin": PIN, "csrf_token": tok}, allow_redirects=True)
check("credential revoked via PIN-authorised call", "has been revoked" in r.text)
r = anon.post(f"https://localhost:5002/issuer/revoke-credential", json={"revocation_index": 0})
check("issuer revoke endpoint refuses unauthenticated callers (401)", r.status_code == 401)
r = anon.post(f"{WALLET}/oauth/introspect", json={"access_token": "x"})
check("introspection endpoint refuses unauthenticated callers (401)", r.status_code == 401)
r = anon.post(f"{WALLET}/oauth/token", json={"code": "x", "client_id": "wallet_app_01", "client_secret": 12345})
check("token endpoint: non-string secret -> 400, not 500", r.status_code == 400)

print("== Logout")
r = s.post(f"{WALLET}/wallet/logout", data={"csrf_token": tok}, allow_redirects=True)
check("logout via POST works", "Logged out" in r.text)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
