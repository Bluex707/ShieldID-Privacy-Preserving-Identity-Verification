"""Process-wide Issuer instance for issuer_app.py. Importing this module
publishes the issuer's public key to the on-chain registry."""
import logging

import config
from eth_registry import EthIssuerRegistry
from issuer import Issuer
from status_cache import StatusListCache

log = logging.getLogger("shieldid.issuer")

if not config.ISSUER_REGISTRY_ADDRESS:
    raise config.ConfigError(
        "ISSUER_REGISTRY_ADDRESS is not set. Run `python deploy_contract.py` first."
    )

registry = EthIssuerRegistry(contract_address=config.ISSUER_REGISTRY_ADDRESS, rpc_url=config.RPC_URL)
status_cache = StatusListCache(cache_dir=config.STATUS_CACHE_DIR)

issuer = Issuer(issuer_id=config.ISSUER_ID, registry=registry, status_cache=status_cache)
issuer.publish_key()


issuer._publish_status_list()

print(f"Published issuer '{config.ISSUER_ID}' key to contract {config.ISSUER_REGISTRY_ADDRESS}")
