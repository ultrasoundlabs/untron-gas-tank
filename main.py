import json
import tomllib
import math
import logging
from typing import Dict, Optional
import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from eth_account import Account
from eth_typing import HexStr
from eth_utils import to_checksum_address
import uvicorn
from web3 import AsyncHTTPProvider, AsyncWeb3
from web3.middleware import ExtraDataToPOAMiddleware
from fastapi.middleware.cors import CORSMiddleware

# ────────────────────────────── logging setup ─
# We set up logging to write logs to gastank.log file.
# This helps us keep track of important events and errors for debugging and monitoring.
logging.basicConfig(
    filename="gastank.log",
    filemode="a",  # append to the log file
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# ────────────────────────────── load config ──
with open("config.toml", "rb") as f:
    cfg = tomllib.load(f)

RELAYER_PK = HexStr(cfg["relayer"]["private_key"])
RELAYER_ADDR = Account.from_key(RELAYER_PK).address

CHAIN_MAP: Dict[int, Dict] = {c["chain_id"]: c for c in cfg["chains"]}


# ────────────────────────────── helpers ──────
def allowed_token(chain_id: int, token: str) -> bool:
    """Return True if *token* is present in the allow-list for *chain_id*."""
    return get_token_cfg(chain_id, token) is not None


def get_token_cfg(chain_id: int, token: str) -> Optional[Dict]:
    """Return the configuration object for *token* on *chain_id* or *None* if the
    token is not allow-listed. Token comparison is case-insensitive.
    The returned dict is expected to contain the keys:

    • address – the checksum (or lower-case) address of the ERC-20 token
    • min_transfer – the minimum transfer amount that will be accepted by the relayer
    """
    token_lower = token.lower()
    for t in CHAIN_MAP[chain_id]["allowed_tokens"]:
        if t["address"].lower() == token_lower:
            return t
    return None


async def verify_recipient_is_allowed(recipient: str) -> bool:
    """
    TODO: call your own API here.
    For now we always return True.
    """
    return True


def make_w3(chain_cfg: Dict) -> AsyncWeb3:
    w3 = AsyncWeb3(AsyncHTTPProvider(chain_cfg["rpc_url"]))
    # Polygon and *some* side-chains are PoA → add middleware
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    return w3


# ────────────────────────────── ABI ──────────
ERC3009_ABI = json.loads(
    """[
        {"name":"transferWithAuthorization",
         "type":"function",
         "stateMutability":"nonpayable",
         "inputs":[
            {"name":"from","type":"address"},
            {"name":"to","type":"address"},
            {"name":"value","type":"uint256"},
            {"name":"validAfter","type":"uint256"},
            {"name":"validBefore","type":"uint256"},
            {"name":"nonce","type":"bytes32"},
            {"name":"v","type":"uint8"},
            {"name":"r","type":"bytes32"},
            {"name":"s","type":"bytes32"}
         ],
         "outputs":[]}
    ]"""
)


# ────────────────────────────── request body ─
class EIP3009Body(BaseModel):
    chain_id: int = Field(..., alias="chainId")
    token_address: str = Field(..., alias="token")
    from_addr: str = Field(..., alias="from")
    to_addr: str = Field(..., alias="to")
    value: int = Field(
        ...,
        description="Amount of tokens to transfer (must be greater than or equal to the token-specific minimum; normally 2(000_000) for USDC and USDT).",
    )
    valid_after: int = Field(..., alias="validAfter")
    valid_before: int = Field(..., alias="validBefore")
    nonce: str
    v: int
    r: HexStr
    s: HexStr


class RelayResponse(BaseModel):
    tx_hash: HexStr = Field(..., alias="txHash")


# ────────────────────────────── FastAPI app ──
ROOT_PATH = os.getenv("ROOT_PATH", "")  # e.g. set to "/api/gasless" in production
app = FastAPI(title="EIP-3009 Relayer", root_path=ROOT_PATH)

# ──────────────────────── CORS setup ────
# We enable highly permissive CORS so that any web client can interact with this
# relayer API without being blocked by the browser's same-origin policy.  In a
# production environment you would typically restrict *allow_origins* (and
# potentially methods/headers) to a specific list of trusted web front-ends,
# but for ease of integration during development we open it up completely.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Accept requests from any origin
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods (GET, POST, etc.)
    allow_headers=["*"],  # Allow all headers including Authorization
)


@app.post("/relay3009", response_model=RelayResponse)
async def relay(body: EIP3009Body):
    # Log the incoming request
    logger.info(
        f"Received relay request: chain_id={body.chain_id}, token={body.token_address}, "
        f"from={body.from_addr}, to={body.to_addr}, value={body.value}"
    )

    # ---------- basic allow-list checks ----------
    chain_cfg = CHAIN_MAP.get(body.chain_id)
    if not chain_cfg:
        logger.warning(f"Unsupported chain {body.chain_id}")
        raise HTTPException(400, f"Unsupported chain {body.chain_id}")

    token = to_checksum_address(body.token_address)

    # Retrieve the token configuration in one go (includes min_transfer)
    token_cfg = get_token_cfg(body.chain_id, token)
    if token_cfg is None:
        logger.warning(f"Token {token} not allowed on chain {body.chain_id}")
        raise HTTPException(400, "Token not allowed on this chain")

    min_transfer = int(token_cfg.get("min_transfer", 0))
    if body.value < min_transfer:
        logger.warning(
            f"Transfer value {body.value} below minimum {min_transfer} for token {token} on chain {body.chain_id}"
        )
        raise HTTPException(
            400,
            f"Transfer value below minimum allowed: must be at least {min_transfer}",
        )

    if not await verify_recipient_is_allowed(body.to_addr):
        logger.warning(f"Recipient {body.to_addr} not allowed")
        raise HTTPException(400, "Recipient not allowed")

    # ---------- create Web3 & contract ----------
    w3 = make_w3(chain_cfg)
    contract = w3.eth.contract(token, abi=ERC3009_ABI)

    # ---------- emulation (eth_call) ------------
    try:
        await contract.functions.transferWithAuthorization(
            body.from_addr,
            body.to_addr,
            body.value,
            body.valid_after,
            body.valid_before,
            HexStr(body.nonce),
            body.v,
            HexStr(body.r),
            HexStr(body.s),
        ).call()
    except Exception as e:
        logger.error(f"Off-chain simulation failed: {e}")
        raise HTTPException(400, f"Off-chain simulation failed: {e}")

    # ---------- build transaction ---------------
    try:
        tx = await contract.functions.transferWithAuthorization(
            body.from_addr,
            body.to_addr,
            body.value,
            body.valid_after,
            body.valid_before,
            HexStr(body.nonce),
            body.v,
            HexStr(body.r),
            HexStr(body.s),
        ).build_transaction(
            {
                "from": RELAYER_ADDR,
                "nonce": await w3.eth.get_transaction_count(RELAYER_ADDR),
            }
        )
    except Exception as e:
        logger.error(f"Transaction build failed: {e}")
        raise HTTPException(400, f"Transaction build failed: {e}")

    # ---------- gas & fee handling -------------
    try:
        base_gas = await w3.eth.estimate_gas(tx)
    except Exception as e:
        logger.error(f"Gas estimation failed: {e}")
        raise HTTPException(400, f"Gas estimation failed: {e}")

    # Arbitrum has its own gas estimator, OP-stack chains need padding
    if body.chain_id == 10:  # Optimism
        tx["gas"] = math.ceil(base_gas * 1.10)  # +10 %
    else:
        tx["gas"] = base_gas

    try:
        latest = await w3.eth.gas_price  # falls back to gasPrice on pre-1559 chains
        latest_block = await w3.eth.get_block("latest")
        is_eip1559 = "baseFeePerGas" in latest_block

        if is_eip1559:
            tx["maxFeePerGas"] = latest * 2
            tx["maxPriorityFeePerGas"] = latest
        else:
            tx["gasPrice"] = latest

        tx["chainId"] = body.chain_id
    except Exception as e:
        logger.error(f"Gas price or block info fetch failed: {e}")
        raise HTTPException(400, f"Gas price or block info fetch failed: {e}")

    # ---------- sign & send ---------------------
    try:
        signed = Account.sign_transaction(tx, RELAYER_PK)
        tx_hash = await w3.eth.send_raw_transaction(signed.raw_transaction)
        logger.info(
            f"Relayed tx: chain_id={body.chain_id}, token={body.token_address}, "
            f"from={body.from_addr}, to={body.to_addr}, value={body.value}, tx_hash={tx_hash.hex()}"
        )
        return {"txHash": tx_hash.hex()}
    except Exception as e:
        logger.error(f"Transaction signing or sending failed: {e}")
        raise HTTPException(400, f"Transaction signing or sending failed: {e}")


if __name__ == "__main__":
    logger.info("Starting EIP-3009 Relayer FastAPI server")
    uvicorn.run("main:app", host="0.0.0.0", port=8459, root_path=ROOT_PATH)
