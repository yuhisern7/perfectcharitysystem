"""Simple wallet utilities for the PCS charity system.

For now, a wallet is just an internal ID string that can hold PCS
balances on the PCS blockchain defined in pcs-crypto.py.

Later, this module can be expanded to store balances in a database,
handle authentication, etc.
"""

from __future__ import annotations

import uuid
from typing import Dict, Any
import importlib.util
import pathlib
import sys


def create_wallet_id() -> str:
	"""Create a new unique internal wallet ID.

	Example: "wallet_3f8e...". This ID is what pcs-crypto.py uses
	as sender/receiver in transactions.
	"""

	return f"wallet_{uuid.uuid4().hex}"


def calculate_balance_for_wallet(wallet_id: str) -> float:
	"""Compute the PCS balance for a wallet from the blockchain.

	NOTE: We load pcs-crypto.py by file path (because the filename
	contains a hyphen and cannot be imported as a normal module).
	"""

	here = pathlib.Path(__file__).resolve().parent
	pcs_crypto_path = here / "pcs-crypto.py"

	spec = importlib.util.spec_from_file_location("pcs_crypto_module", pcs_crypto_path)
	if spec is None or spec.loader is None:
		raise RuntimeError("Unable to load pcs-crypto.py module")

	pcs_crypto = importlib.util.module_from_spec(spec)
	sys.modules["pcs_crypto_module"] = pcs_crypto
	spec.loader.exec_module(pcs_crypto)  # type: ignore[arg-type]

	blockchain = pcs_crypto.blockchain

	balance: float = 0.0
	for tx in blockchain.get_transactions_for_wallet(wallet_id):
		if tx.sender == wallet_id:
			balance -= tx.amount
		if tx.receiver == wallet_id:
			balance += tx.amount
	return balance


def wallet_summary(wallet_id: str) -> Dict[str, Any]:
	"""Return a simple summary that can be sent to the frontend."""

	return {
		"wallet_id": wallet_id,
		"balance_pcs": calculate_balance_for_wallet(wallet_id),
	}

