"""PCS Charity Blockchain

This module defines a very simple private blockchain for the PCS coin.

Goals:
- PCS is an internal charity coin ("dead" coin):
  - Cannot be withdrawn to external exchanges.
  - Used only inside this system for recording donations.
- Zero transaction fees: the full amount is recorded as sent to the receiver.
- Transparent history: every transaction is stored in a block so anyone can
  inspect the chain to see where PCS moved.

This is NOT a real-world secure blockchain implementation. It is a
transparent ledger for educational / prototype purposes.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime
from hashlib import sha256
from typing import List, Optional, Dict, Any


PCS_COIN_NAME = "PCS"


@dataclass
class Transaction:
	"""A single PCS transfer on the charity chain.

	- sender:    wallet address of the donor (or "SYSTEM" for initial mint).
	- receiver:  wallet address of the receiver (usually a charity wallet).
	- amount:    PCS amount transferred.
	- metadata:  optional info (e.g. profile id, message).
	"""

	sender: str
	receiver: str
	amount: float
	metadata: Optional[Dict[str, Any]] = None

	def to_dict(self) -> Dict[str, Any]:
		return asdict(self)


@dataclass
class Block:
	"""A block in the PCS charity blockchain."""

	index: int
	timestamp: str
	transactions: List[Transaction]
	previous_hash: str
	hash: str


class PCSBlockchain:
	"""Very small, private blockchain to track PCS transactions.

	This runs in memory only. Later we can persist it to a database
	or expose it via an API for the website / apps.
	"""

	def __init__(self) -> None:
		self.chain: List[Block] = []
		# Create the genesis block (first block in the chain)
		self._create_genesis_block()

	# ------------------------------------------------------------------
	# Internal helpers
	# ------------------------------------------------------------------

	def _create_genesis_block(self) -> None:
		if self.chain:
			return

		genesis_tx = Transaction(
			sender="SYSTEM",
			receiver="SYSTEM",
			amount=0.0,
			metadata={"note": "Genesis block for PCS charity chain"},
		)
		block = self._create_block(transactions=[genesis_tx], previous_hash="0")
		self.chain.append(block)

	def _calculate_hash(
		self, index: int, timestamp: str, transactions: List[Transaction], previous_hash: str
	) -> str:
		tx_payload = [tx.to_dict() for tx in transactions]
		block_string = f"{index}{timestamp}{tx_payload}{previous_hash}".encode("utf-8")
		return sha256(block_string).hexdigest()

	def _create_block(self, transactions: List[Transaction], previous_hash: str) -> Block:
		index = len(self.chain)
		timestamp = datetime.utcnow().isoformat()
		block_hash = self._calculate_hash(index, timestamp, transactions, previous_hash)
		return Block(
			index=index,
			timestamp=timestamp,
			transactions=transactions,
			previous_hash=previous_hash,
			hash=block_hash,
		)

	# ------------------------------------------------------------------
	# Public API
	# ------------------------------------------------------------------

	def get_last_block(self) -> Block:
		return self.chain[-1]

	def add_transactions_block(self, transactions: List[Transaction]) -> Block:
		"""Append a new block with one or more PCS transactions.

		No fees are taken. The full amount stays in the system.
		"""

		previous_hash = self.get_last_block().hash
		block = self._create_block(transactions=transactions, previous_hash=previous_hash)
		self.chain.append(block)
		return block

	def create_donation(
		self,
		from_wallet: str,
		to_wallet: str,
		amount: float,
		profile_id: Optional[str] = None,
		message: Optional[str] = None,
		extra_metadata: Optional[Dict[str, Any]] = None,
	) -> Block:
		"""Record a single PCS donation as a new block.

		- from_wallet: donor's wallet address (internal only).
		- to_wallet:   receiver's wallet (typically a charity profile wallet).
		- amount:      PCS to send (no fee is taken).
		- profile_id:  optional ID of the profile being supported.
		- message:     optional note for transparency.
		"""

		metadata: Dict[str, Any] = {}
		if profile_id is not None:
			metadata["profile_id"] = profile_id
		if message is not None:
			metadata["message"] = message
		if extra_metadata:
			metadata.update(extra_metadata)

		tx = Transaction(
			sender=from_wallet,
			receiver=to_wallet,
			amount=amount,
			metadata=metadata or None,
		)
		block = self.add_transactions_block([tx])
		
		# Save blockchain to disk after each donation
		try:
			from . import pcs_persistence
			pcs_persistence.save_blockchain(self.to_dict())
		except Exception as e:
			print(f"Warning: Failed to save blockchain: {e}")
		
		return block

	def get_all_transactions(self) -> List[Transaction]:
		"""Return a flat list of all PCS transactions on the chain."""

		txs: List[Transaction] = []
		for block in self.chain:
			txs.extend(block.transactions)
		return txs

	def get_transactions_for_wallet(self, wallet_address: str) -> List[Transaction]:
		"""Return all transactions where this wallet is sender or receiver."""

		return [
			tx
			for tx in self.get_all_transactions()
			if tx.sender == wallet_address or tx.receiver == wallet_address
		]

	def to_dict(self) -> List[Dict[str, Any]]:
		"""Serialize the entire chain to basic Python types (for JSON / APIs)."""

		result: List[Dict[str, Any]] = []
		for block in self.chain:
			result.append(
				{
					"index": block.index,
					"timestamp": block.timestamp,
					"previous_hash": block.previous_hash,
					"hash": block.hash,
					"transactions": [tx.to_dict() for tx in block.transactions],
				}
			)
		return result

	def from_dict(self, chain_data: List[Dict[str, Any]]) -> None:
		"""Load blockchain from serialized data."""
		self.chain = []
		for block_dict in chain_data:
			transactions = [
				Transaction(
					sender=tx["sender"],
					receiver=tx["receiver"],
					amount=tx["amount"],
					metadata=tx.get("metadata"),
				)
				for tx in block_dict["transactions"]
			]
			block = Block(
				index=block_dict["index"],
				timestamp=block_dict["timestamp"],
				transactions=transactions,
				previous_hash=block_dict["previous_hash"],
				hash=block_dict["hash"],
			)
			self.chain.append(block)


# A single global instance for now. In a real application this would
# live behind an API and / or be persisted to a database.
blockchain = PCSBlockchain()

# Load blockchain from disk if available
try:
	from . import pcs_persistence
	chain_data = pcs_persistence.load_blockchain()
	if chain_data:
		blockchain.from_dict(chain_data)
except Exception:
	pass  # If loading fails, start with genesis block


if __name__ == "__main__":
	# Simple demo when you run: python pcs-crypto.py
	print(f"PCS coin name: {PCS_COIN_NAME}")
	print("Current chain length:", len(blockchain.chain))

	# Example donation from one wallet to another
	example_donor = "wallet_donor_123"
	example_charity = "wallet_charity_abc"
	blockchain.create_donation(
		from_wallet=example_donor,
		to_wallet=example_charity,
		amount=100.0,
		profile_id="example_profile",
		message="Demo donation",
	)

	print("New chain length:", len(blockchain.chain))
	print("All transactions:")
	for tx in blockchain.get_all_transactions():
		print(" -", tx)

