import json
import os

from web3 import Web3

_CONTRACT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "contracts")
SOURCE_PATH = os.path.join(_CONTRACT_DIR, "IssuerRegistry.sol")
ABI_PATH = os.path.join(_CONTRACT_DIR, "IssuerRegistry.abi.json")
SOLC_VERSION = "0.8.20"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


def load_abi():
    with open(ABI_PATH, encoding="utf-8") as f:
        return json.load(f)


def compile_contract():
    """Compile the contract (deploy-time only). Downloads solc on first use."""
    import solcx  

    if SOLC_VERSION not in {str(v) for v in solcx.get_installed_solc_versions()}:
        solcx.install_solc(SOLC_VERSION)
    with open(SOURCE_PATH, encoding="utf-8") as f:
        source = f.read()
    
    compiled = solcx.compile_source(
        source, output_values=["abi", "bin"], solc_version=SOLC_VERSION, evm_version="london"
    )
    (_, interface), = compiled.items()
    return interface["abi"], interface["bin"]


class RegistryNotDeployedError(RuntimeError):
    """No contract code exists at the configured address (e.g. the dev chain was restarted)."""


class EthIssuerRegistry:
    def __init__(self, contract_address=None, rpc_url="http://127.0.0.1:8545",
                 admin_index=0, issuer_index=1):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 15}))
        if not self.w3.is_connected():
            raise ConnectionError(f"Could not connect to an Ethereum node at {rpc_url}. Is Anvil/Ganache running?")

        accounts = self.w3.eth.accounts
        if not accounts:
            raise RuntimeError("The node exposes no accounts; use a dev node such as Anvil or Ganache.")
        # Demo role separation: the admin (deployer / accreditation authority)
        # registers the issuer; the issuer's own account publishes its key.
        self.admin_account = accounts[min(admin_index, len(accounts) - 1)]
        self.issuer_account = accounts[min(issuer_index, len(accounts) - 1)]

        if contract_address:
            if not Web3.is_address(contract_address):
                raise ValueError("ISSUER_REGISTRY_ADDRESS is not a valid Ethereum address")
            address = Web3.to_checksum_address(contract_address)
            if not self.w3.eth.get_code(address):
                raise RegistryNotDeployedError(
                    f"No contract found at {address}. If you restarted the local chain, "
                    "re-run `python deploy_contract.py`."
                )
            self.contract_address = address
            self.contract = self.w3.eth.contract(address=address, abi=load_abi())
        else:
            abi, bytecode = compile_contract()
            factory = self.w3.eth.contract(abi=abi, bytecode=bytecode)
            tx_hash = factory.constructor().transact({"from": self.admin_account})
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            self.contract_address = receipt.contractAddress
            self.contract = self.w3.eth.contract(address=self.contract_address, abi=abi)

    # ---- reads ---------------------------------------------------------------
    def get_issuer_key(self, issuer_id):
        key = self.contract.functions.getIssuerKey(issuer_id).call()
        return key if key else None

    def get_issuer_owner(self, issuer_id):
        owner = self.contract.functions.getIssuerOwner(issuer_id).call()
        return None if owner == ZERO_ADDRESS else owner

    # ---- writes ----------------------------------------------------------------
    def _send(self, fn, account):
        tx_hash = fn.transact({"from": account})
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt.status != 1:
            raise RuntimeError("transaction reverted")
        return receipt

    def publish_issuer_key(self, issuer_id, public_key_pem):
        """Register the issuer id if it is new (admin-only on-chain), then
        publish/rotate its key (owner-only on-chain). Safe to call on every
        issuer start-up."""
        if isinstance(public_key_pem, bytes):
            public_key_pem = public_key_pem.decode("utf-8")
        owner = self.get_issuer_owner(issuer_id)
        if owner is None:
            self._send(self.contract.functions.registerIssuer(issuer_id, self.issuer_account), self.admin_account)
        elif owner != self.issuer_account:
            raise PermissionError(f"issuer id '{issuer_id}' is registered to a different account ({owner})")
        return self._send(self.contract.functions.publishIssuerKey(issuer_id, public_key_pem), self.issuer_account)
