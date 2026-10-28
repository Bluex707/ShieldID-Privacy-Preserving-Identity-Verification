# Security review

A review of the original project (`Code version 5`) followed by fixes. Each finding was either
**reproduced against the original code** (✔ PoC) or confirmed by reading the code and fixed with a
regression test. Severity is my assessment for the project's stated use (a demo that may be run
on a laptop and shown publicly), not a CVSS score.

Tooling: `bandit` went from **5 High / 2 Medium / 2 Low → 0**; `pip-audit` reports one accepted
advisory (see F-18). Verification: 95 unit tests + a 26-step end-to-end run (real Anvil chain,
three HTTPS services).

## Findings and fixes

| ID | Severity | Finding | Fix | Evidence |
|---|---|---|---|---|
| F-01 | **High** | **TLS certificate verification disabled** (`verify=False`) on all 5 outbound calls (token exchange, introspection, issuance, revocation, presentation). Anyone on the network path could read access tokens/credentials or tamper with them. | Services use a locally generated certificate; every client call verifies against it (`config.TLS_CA_BUNDLE`); verification can't be switched off; redirects refused. | bandit B501 ×5 → 0; e2e runs over verified TLS |
| F-02 | **High** | **Hard-coded credentials**: demo portal login `sara222` / `password123` in source *and pre-filled in the login page HTML*; default service-to-service secrets (`dev-only-…-change-me`) in `config.py`. | No secret has a default. `setup_dev.py` generates random ones into a git-ignored `.env`; the app refuses to start without them (≥32 chars). Login form is empty. | `test_unconfigured_secret_fails_loudly`, e2e "no prefilled credentials" |
| F-03 | **High** | **Open issuer registration on the smart contract** — anyone could register `University_of_Jordan.edu.jo` first and publish their own key; the verifier trusted any registered issuer. | Contract: `registerIssuer` is admin-only, key publishing owner-only, events added. Verifier: explicit `TRUSTED_ISSUER_IDS` allow-list. | Tested on live chain: squatting, overwrite, revoke by attacker all revert |
| F-04 | Medium | **OAuth login-CSRF / code injection**: no `state` parameter; `/oauth/authorize` ignored `client_id`/`response_type`. An attacker could make a victim's wallet redeem the attacker's code and store the attacker's credential. | Per-session `state` (single-use, 5 min), validated on authorize and callback; client/response type checked. | e2e: forged and tampered state rejected ✔ |
| F-05 | Medium | **PIN not required to present a credential** though `request_credential` required it and the wallet's own messages say the key is PIN-locked. A hijacked session could present without the PIN. | PIN required for every presentation; authorization is single-use and expires after 120 s. UI has a PIN field. | ✔ PoC; `test_presentation_requires_pin` |
| F-06 | Medium | **TOTP replay**: the same 6-digit code could be reused within its window. | Each time-step accepted once. | ✔ PoC; `test_totp_code_cannot_be_replayed` |
| F-07 | Medium | **Username enumeration by timing**: login took 0.343 s for existing users vs 0.001 s for unknown ones (the password hash was skipped). | Dummy PBKDF2 for unknown users (portal and wallet): 0.350 s vs 0.371 s. | ✔ PoC |
| F-08 | Medium | **Negative revocation index** revoked the *last* credential (`status_list[-1] = True`). | Strict type/range check. | ✔ PoC; `test_negative_revocation_index_is_rejected` |
| F-09 | Medium | **Unlimited credential minting & index race**: one token could mint many credentials per student; concurrent requests could receive the same revocation index. | One active credential per student; index allocation under a lock; capacity cap. | `test_one_active_credential_per_student`, concurrency test |
| F-10 | Medium | **Crashes (HTTP 500) on malformed input** — non-string `client_secret`, off-curve EC points (`assert`-based check, disabled under `python -O`), non-object JSON, bad base64 in signatures. | Explicit on-curve validation, scalar range checks, type checks everywhere; verifier fails closed and never raises. | ✔ PoCs; fuzz test over every presentation field |
| F-11 | Medium | **Unbounded memory growth** (unauthenticated `GET /` created a permanent entry; rate-limit trackers and token stores grew without limit). | Caps + expiry purge; rate limits on all endpoints (Flask-Limiter). | `test_tracker_memory_is_bounded` |
| F-12 | Medium | **Front-end supply chain & XSS hardening**: Bootstrap/jsQR/fonts loaded from CDNs without integrity hashes; server text written with `innerHTML`; no CSP or security headers. | Libraries vendored locally (Google Fonts removed); `textContent`/DOM APIs; strict CSP with per-request nonce, `frame-ancestors 'none'`, nosniff, no-store, referrer policy. | e2e header checks |
| F-13 | Low | Logout via `GET` (CSRF-able) and only popped one session key. | `POST` + CSRF token, `session.clear()`. | e2e |
| F-14 | Low | Exception text echoed to users (`Issuance Error: {e}`); log injection possible via CR/LF in logged values. | Generic user messages, details logged server-side; control characters stripped from logs. | `test_log_injection_is_neutralised` |
| F-15 | Low | **Wallet said "✅ transmitted successfully" even when the verifier rejected the proof** (checked only HTTP 200). | Parses the verifier's `success` flag. | e2e |
| F-16 | Low | **Sensitive/unwanted files in the repo**: `.env`, `security.log` (a real username + IPs), `__pycache__`, status cache, the university's official logo. | Removed; `.gitignore`; runtime data moved to git-ignored `data/`, `logs/`, `certs/`. Logo replaced with a generic icon. | — |
| F-17 | Low | **Reliability bugs with security impact**: issuer restart reverted ("already registered"); stale contract address after chain restart gave cryptic errors; `solc` binary downloaded at *import time* (even for the read-only verifier). | Restart-safe publish; contract-code existence check with clear message; ABI committed, compiler only needed for deployment. | Live-chain tests |
| F-18 | Low (accepted) | **`ecdsa` is not constant-time** (CVE-2024-23342 / PYSEC-2026-1325, no upstream fix). | Not fixed: replacement (`coincurve`) has no wheels for newer Python versions and would complicate installation. Documented; CI ignores this one ID explicitly. | README → Known limitations |
| F-19 | Low | Token scope `read:enrollment_status` but introspection returned the whole student record. | Scope renamed to `read:student_record`; token must be issued to the wallet client. | — |

## Reviewed and found sound

- **ZK/commitment construction**: Pedersen with a nothing-up-my-sleeve `H`; equality proof is sound (tested that a false statement cannot be proven); proofs are domain-separated by challenge, credential and attribute.
- **SSRF guard** on the QR-supplied `callback_url` (exact-match allow-list *before* any request) was already correct and is now also enforced for the issuer endpoint.
- **`status_cache` path handling** looked like path traversal but replaced `/` and `\`; it is now an explicit allow-list regex as defence in depth (not a vulnerability).
- **Password hashing** (PBKDF2-HMAC-SHA256, 600k, per-user salt), constant-time comparisons, CSRF on every state-changing form, session cookie flags (`Secure`, `HttpOnly`, `SameSite=Strict`), debug mode off.

## Not addressed (by design — see README "Known limitations")

In-memory state, server-side custody of keys, unsigned status list, linkable presentations,
dev-chain unlocked accounts, shared-secret service auth, Flask dev server.
