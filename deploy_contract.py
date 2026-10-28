
import os

import config
from eth_registry import EthIssuerRegistry, RegistryNotDeployedError

ENV_FILE = config._ENV_FILE


def _write_env_var(key, value):
    
    lines = []
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, encoding="utf-8") as f:
            lines = f.readlines()
    for i, line in enumerate(lines):
        if line.strip().startswith(f"{key}="):
            lines[i] = f"{key}={value}\n"
            break
    else:
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        lines.append(f"{key}={value}\n")
    fd = os.open(ENV_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.writelines(lines)


def main():
    if config.ISSUER_REGISTRY_ADDRESS:
        try:
            EthIssuerRegistry(contract_address=config.ISSUER_REGISTRY_ADDRESS, rpc_url=config.RPC_URL)
            print(f"IssuerRegistry already deployed at {config.ISSUER_REGISTRY_ADDRESS}; nothing to do.")
            return
        except RegistryNotDeployedError:
            print("The recorded contract address has no code on this chain (chain restarted?). Redeploying...")

    print(f"Deploying IssuerRegistry to {config.RPC_URL} ...")
    registry = EthIssuerRegistry(rpc_url=config.RPC_URL)
    print(f"Deployed at {registry.contract_address} (admin: {registry.admin_account})")
    _write_env_var("ISSUER_REGISTRY_ADDRESS", registry.contract_address)
    print("Wrote ISSUER_REGISTRY_ADDRESS to .env")
    print("Next: start issuer_app.py, app.py and verifier_app.py (see README).")


if __name__ == "__main__":
    main()
