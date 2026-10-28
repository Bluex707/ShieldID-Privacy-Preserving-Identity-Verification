"""Process-wide read-only registry/status-cache handles for verifier_app.py."""
import config
from eth_registry import EthIssuerRegistry
from status_cache import StatusListCache

if not config.ISSUER_REGISTRY_ADDRESS:
    raise config.ConfigError(
        "ISSUER_REGISTRY_ADDRESS is not set. Run `python deploy_contract.py` first; "
        "the verifier has nothing to read until the issuer has published its key."
    )

registry = EthIssuerRegistry(contract_address=config.ISSUER_REGISTRY_ADDRESS, rpc_url=config.RPC_URL)
status_cache = StatusListCache(cache_dir=config.STATUS_CACHE_DIR)

print(f"Verifier attached to IssuerRegistry contract at {config.ISSUER_REGISTRY_ADDRESS}")
