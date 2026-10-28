"""One-time local development setup (idempotent -- safe to re-run).

  * writes random secrets into a git-ignored ``.env`` (never overwrites values
    that already exist),
  * generates a self-signed TLS certificate for localhost in ``certs/`` so the
    three services can talk HTTPS *with certificate verification enabled*.

Usage:  python setup_dev.py
"""
import datetime
import ipaddress
import os
import secrets
import stat

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import config

GENERATED_SECRETS = (
    "WALLET_CLIENT_SECRET",
    "ISSUER_SERVICE_CLIENT_SECRET",
    "WALLET_SERVICE_CLIENT_SECRET",
)


def _read_env_lines():
    if not os.path.exists(config._ENV_FILE):
        return []
    with open(config._ENV_FILE, encoding="utf-8") as f:
        return f.readlines()


def _existing_keys(lines):
    return {ln.split("=", 1)[0].strip() for ln in lines if "=" in ln and not ln.lstrip().startswith("#")}


def write_env():
    lines = _read_env_lines()
    have = _existing_keys(lines)
    new_values = {}
    for name in GENERATED_SECRETS:
        if name not in have:
            new_values[name] = secrets.token_urlsafe(48)
    if "DEMO_STUDENT_PASSWORD" not in have:
        new_values["DEMO_STUDENT_PASSWORD"] = secrets.token_urlsafe(14)

    if new_values:
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        for k, v in new_values.items():
            lines.append(f"{k}={v}\n")
        # create with owner-only permissions
        fd = os.open(config._ENV_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.writelines(lines)
        print(f"[ok] wrote {len(new_values)} new value(s) to .env (owner-only permissions)")
    else:
        print("[ok] .env already has all generated values -- left untouched")
    return new_values


def write_cert():
    if os.path.exists(config.TLS_CERT_FILE) and os.path.exists(config.TLS_KEY_FILE):
        print("[ok] TLS certificate already exists -- left untouched")
        return
    os.makedirs(config.CERT_DIR, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ShieldID local development")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                x509.IPAddress(ipaddress.ip_address("::1")),
            ]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    fd = os.open(config.TLS_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    with open(config.TLS_CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(config.TLS_CERT_FILE, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    print(f"[ok] generated self-signed certificate for localhost in {config.CERT_DIR} (valid 365 days)")


def main():
    new_values = write_env()
    write_cert()
    print()
    print("Next: start a local Ethereum node (anvil), then `python deploy_contract.py`.")
    if "DEMO_STUDENT_PASSWORD" in new_values:
        print()
        print("Demo University Portal login (used only on the SSO page when issuing a credential):")
        print("  username: sara222")
        print(f"  password: {new_values['DEMO_STUDENT_PASSWORD']}")
        print("  (also stored in .env as DEMO_STUDENT_PASSWORD)")


if __name__ == "__main__":
    main()
