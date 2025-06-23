import argparse
import secrets
import time
from typing import Tuple

import requests
import tomllib
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_typing import HexStr
from eth_utils import to_checksum_address
from web3 import HTTPProvider, Web3


# ──────────────────────────── constants ────────────────────────────
CONFIG_FILE = "config.toml"
API_ENDPOINT = "http://localhost:8459/relay3009"  # adjust if the relayer runs elsewhere


# ──────────────────────────── helpers ──────────────────────────────

def load_config() -> dict:
    """Load TOML config used by the relayer to reuse RPC URLs."""
    with open(CONFIG_FILE, "rb") as f:
        return tomllib.load(f)


def get_chain_cfg(cfg: dict, chain_id: int) -> dict:
    for c in cfg["chains"]:
        if c["chain_id"] == chain_id:
            return c
    raise ValueError(f"Chain {chain_id} not present in {CONFIG_FILE}")


def get_token_metadata(w3: Web3, token_addr: str) -> Tuple[str, str]:
    """Return (name, version) for the ERC-20 token.

    Falls back to sensible defaults if the contract does not implement
    either function so that we can still produce a signature.
    """

    # Minimal ERC-20 ABI snippets
    minimal_abi = [
        {
            "name": "name",
            "type": "function",
            "stateMutability": "view",
            "inputs": [],
            "outputs": [{"type": "string"}],
        },
        {
            "name": "version",
            "type": "function",
            "stateMutability": "view",
            "inputs": [],
            "outputs": [{"type": "string"}],
        },
    ]

    contract = w3.eth.contract(to_checksum_address(token_addr), abi=minimal_abi)

    name = contract.functions.name().call()
    version = contract.functions.version().call()

    return name, version


def build_typed_data(
    chain_id: int,
    verifying_contract: str,
    token_name: str,
    token_version: str,
    from_addr: str,
    to_addr: str,
    value: int,
    valid_after: int,
    valid_before: int,
    nonce: bytes,
) -> dict:
    """Construct EIP-712 typed data for TransferWithAuthorization."""

    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "TransferWithAuthorization": [
                {"name": "from", "type": "address"},
                {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "validAfter", "type": "uint256"},
                {"name": "validBefore", "type": "uint256"},
                {"name": "nonce", "type": "bytes32"},
            ],
        },
        "primaryType": "TransferWithAuthorization",
        "domain": {
            "name": token_name,
            "version": token_version,
            "chainId": chain_id,
            "verifyingContract": verifying_contract,
        },
        "message": {
            "from": from_addr,
            "to": to_addr,
            "value": value,
            "validAfter": valid_after,
            "validBefore": valid_before,
            "nonce": nonce,
        },
    }


# ──────────────────────────── main logic ───────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate an ERC-3009 authorization and submit it to the relayer"
    )
    parser.add_argument("private_key", help="Sender's private key as 0x… hex string")
    parser.add_argument("chain_id", type=int, help="EVM chain ID (e.g. 10 for Optimism)")
    parser.add_argument("token", help="ERC-20 token contract address")
    parser.add_argument("amount", type=int, help="Amount in the token's smallest decimals")
    parser.add_argument("recipient", help="Recipient address")
    args = parser.parse_args()

    # Normalise / derive additional values
    pk: HexStr = HexStr(args.private_key)
    chain_id = args.chain_id
    token_addr = to_checksum_address(args.token)
    recipient = to_checksum_address(args.recipient)

    account = Account.from_key(pk)
    sender = to_checksum_address(account.address)

    # Load chain configuration → RPC URL
    cfg = load_config()
    chain_cfg = get_chain_cfg(cfg, chain_id)
    w3 = Web3(HTTPProvider(chain_cfg["rpc_url"]))

    # Fetch token name & version for EIP-712 domain
    token_name, token_version = get_token_metadata(w3, token_addr)

    # Build EIP-712 typed data structure
    now = int(time.time())
    valid_after = 0  # valid immediately
    valid_before = now + 3600  # 1 hour validity window
    nonce = secrets.token_bytes(32)

    typed_data = build_typed_data(
        chain_id,
        token_addr,
        token_name,
        token_version,
        sender,
        recipient,
        args.amount,
        valid_after,
        valid_before,
        nonce,
    )

    # Sign the typed data using the newer eth-account helper
    message = encode_typed_data(full_message=typed_data)
    signed = Account.sign_message(message, pk)

    body = {
        "chainId": chain_id,
        "token": token_addr,
        "from": sender,
        "to": recipient,
        "value": args.amount,
        "validAfter": valid_after,
        "validBefore": valid_before,
        "nonce": HexStr("0x" + nonce.hex()),
        "v": signed.v,
        "r": hex(signed.r),
        "s": hex(signed.s),
    }

    # Submit to relayer API
    print("Submitting authorization to relayer…")
    resp = requests.post(API_ENDPOINT, json=body, timeout=30)
    if resp.status_code == 200:
        print("Success → tx hash:", resp.json()["txHash"])
    else:
        print("Relayer returned an error:")
        print(resp.status_code, resp.text)


if __name__ == "__main__":
    main() 