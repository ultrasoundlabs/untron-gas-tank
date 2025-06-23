# untron-gas-tank

A lightweight FastAPI service that relays pre-signed ERC-3009 `transferWithAuthorization` transactions, letting users move ERC-20 tokens without spending their own gas.

## Quick start

```bash
# 1. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Launch the relayer API (http://localhost:8459 by default)
python3 main.py
```

## Send a gasless transfer

`example.py` builds the EIP-712 signature and submits it to the relayer:

```bash
python3 example.py <sender-private-key> <chain-id> <token-address> <amount> <recipient>
```

Upon success it prints the transaction hash returned by the relayer.