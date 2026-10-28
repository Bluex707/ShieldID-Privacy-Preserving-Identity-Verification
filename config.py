
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_ENV_FILE = os.path.join(BASE_DIR, ".env")


class ConfigError(RuntimeError):
    """Raised when a required setting is missing or unsafe."""


def _load_dotenv(path):
    """Minimal .env loader. Real environment variables always win."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


_load_dotenv(_ENV_FILE)


BIND_HOST = os.environ.get("BIND_HOST", "127.0.0.1")


RPC_URL = os.environ.get("ETH_RPC_URL", "http://127.0.0.1:8545")
ISSUER_REGISTRY_ADDRESS = os.environ.get("ISSUER_REGISTRY_ADDRESS")  # None if unset
ISSUER_ID = os.environ.get("ISSUER_ID", "University_of_Jordan.edu.jo")


TRUSTED_ISSUER_IDS = frozenset(
    i.strip() for i in os.environ.get("TRUSTED_ISSUER_IDS", ISSUER_ID).split(",") if i.strip()
)


STATUS_CACHE_DIR = os.environ.get("STATUS_CACHE_DIR", os.path.join(BASE_DIR, "data", "status_cache"))
SECURITY_LOG_PATH = os.environ.get("SECURITY_LOG_PATH", os.path.join(BASE_DIR, "logs", "security.log"))


CERT_DIR = os.environ.get("TLS_CERT_DIR", os.path.join(BASE_DIR, "certs"))
TLS_CERT_FILE = os.path.join(CERT_DIR, "dev-cert.pem")
TLS_KEY_FILE = os.path.join(CERT_DIR, "dev-key.pem")
TLS_CA_BUNDLE = os.environ.get("TLS_CA_BUNDLE", TLS_CERT_FILE)


def tls_context():
    """(cert, key) tuple for ``app.run(ssl_context=...)``. Refuses to fall back
    to an ad-hoc certificate that clients could not verify."""
    if not (os.path.exists(TLS_CERT_FILE) and os.path.exists(TLS_KEY_FILE)):
        raise ConfigError(
            f"TLS certificate not found in {CERT_DIR}. Run `python setup_dev.py` first."
        )
    return TLS_CERT_FILE, TLS_KEY_FILE



# SSRF hardening for the wallet's "present VC" flow: `callback_url` is read
# from a QR code (attacker-controllable). Only EXACT matches against this
# allow-list are ever contacted (see security_utils.validate_callback_url).
_default_callbacks = "https://localhost:5001/api/verify"
ALLOWED_VERIFIER_CALLBACKS = frozenset(
    url.strip()
    for url in os.environ.get("ALLOWED_VERIFIER_CALLBACKS", _default_callbacks).split(",")
    if url.strip()
)

VERIFIER_PUBLIC_CALLBACK_URL = os.environ.get("VERIFIER_PUBLIC_CALLBACK_URL", _default_callbacks)

PORTAL_BASE_URL = os.environ.get("PORTAL_BASE_URL", "https://localhost:5000")
ISSUER_SERVICE_BASE_URL = os.environ.get("ISSUER_SERVICE_BASE_URL", "https://localhost:5002")
ISSUER_ISSUE_CREDENTIAL_URL = f"{ISSUER_SERVICE_BASE_URL}/issuer/issue-credential"
ISSUER_REVOKE_CREDENTIAL_URL = f"{ISSUER_SERVICE_BASE_URL}/issuer/revoke-credential"

ALLOWED_ISSUER_ENDPOINTS = frozenset(
    url.strip()
    for url in os.environ.get("ALLOWED_ISSUER_ENDPOINTS", ISSUER_ISSUE_CREDENTIAL_URL).split(",")
    if url.strip()
)


OAUTH_SCOPE = "read:student_record"
WALLET_CLIENT_ID = os.environ.get("WALLET_CLIENT_ID", "wallet_app_01")
ISSUER_SERVICE_CLIENT_ID = os.environ.get("ISSUER_SERVICE_CLIENT_ID", "issuer_service_01")
WALLET_SERVICE_CLIENT_ID = os.environ.get("WALLET_SERVICE_CLIENT_ID", "wallet_service_01")


_SECRET_NAMES = (
    "WALLET_CLIENT_SECRET",           
    "ISSUER_SERVICE_CLIENT_SECRET",   
    "WALLET_SERVICE_CLIENT_SECRET",   
)
_MIN_SECRET_LEN = 32


def __getattr__(name):
    if name in _SECRET_NAMES:
        value = os.environ.get(name, "")
        if len(value) < _MIN_SECRET_LEN:
            raise ConfigError(
                f"{name} is missing or shorter than {_MIN_SECRET_LEN} characters. "
                "Run `python setup_dev.py` to generate random development secrets."
            )
        return value
    raise AttributeError(f"module 'config' has no attribute {name!r}")
