"""Perfect Charity System (PCS)

Main web API that connects:
- pcs-crypto.py  : PCS private charity blockchain (ledger of donations)
- pcs-wallet.py  : internal wallet helpers
- pcs-profiles.py: donation profiles with wallets

Security notes (prototype level):
- No external withdrawals or exchange integration.
- All wallet IDs are internal, random, and not guessable (UUID based).
- Inputs are validated via Pydantic models.
- No secrets are hard-coded here; later you can add authentication,
  HTTPS (via a reverse proxy), rate limiting, and a database.

This file exposes a HTTP API that your website, iOS app, and
Android app can all call.
"""

from __future__ import annotations

import importlib.util
import pathlib
from typing import List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, constr, validator
import sys


BASE_DIR = pathlib.Path(__file__).resolve().parent


def _load_module_from_file(name: str, filename: str):
	"""Securely load a Python file in this folder as a module.

	This is needed because the filenames contain hyphens, which
	cannot be imported with the normal `import` statement.
	"""

	path = BASE_DIR / filename
	spec = importlib.util.spec_from_file_location(name, path)
	if spec is None or spec.loader is None:
		raise RuntimeError(f"Unable to load module from {filename}")
	module = importlib.util.module_from_spec(spec)
	# Register in sys.modules so features like dataclasses that
	# rely on sys.modules[cls.__module__] work correctly.
	sys.modules[name] = module
	spec.loader.exec_module(module)  # type: ignore[arg-type]
	return module


# Load our core modules
pcs_crypto = _load_module_from_file("pcs_crypto", "pcs-crypto.py")
pcs_profiles = _load_module_from_file("pcs_profiles", "pcs-profiles.py")
pcs_wallet = _load_module_from_file("pcs_wallet", "pcs-wallet.py")
pcs_ai = _load_module_from_file("pcs_ai", "pcs_ai.py")

blockchain = pcs_crypto.blockchain
profiles_store = pcs_profiles.profiles


app = FastAPI(title="Perfect Charity System (PCS)")


# ---------------------------------------------------------------------------
# Pydantic models (input/output schemas)
# ---------------------------------------------------------------------------


ProfileCreate = BaseModel


class ProfileCreate(BaseModel):
	name: constr(strip_whitespace=True, min_length=1, max_length=100)
	description: constr(strip_whitespace=True, min_length=1, max_length=500)


class ProfileOut(BaseModel):
	profile_id: str
	name: str
	description: str
	wallet_id: str


class DonationCreate(BaseModel):
	from_wallet: str = Field(..., description="Donor's internal wallet ID")
	profile_id: str = Field(..., description="Profile that will receive the donation")
	amount: float = Field(..., gt=0, description="Amount of PCS to donate (must be > 0)")
	message: str | None = Field(None, max_length=300)

	@validator("from_wallet", "profile_id")
	def _strip_spaces(cls, v: str) -> str:  # type: ignore[override]
		return v.strip()


class DonationOut(BaseModel):
	block_index: int
	tx_hash: str
	from_wallet: str
	to_wallet: str
	amount: float
	profile_id: str | None = None
	message: str | None = None
	ai_risk_level: str | None = None
	ai_reasons: list[str] | None = None


class WalletSummaryOut(BaseModel):
	wallet_id: str
	balance_pcs: float


class ChainBlockOut(BaseModel):
	index: int
	timestamp: str
	previous_hash: str
	hash: str
	transactions: list


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health")
def health_check() -> dict:
	return {"status": "ok", "coin": pcs_crypto.PCS_COIN_NAME}


@app.post("/profiles", response_model=ProfileOut)
def create_profile(data: ProfileCreate):
	profile = profiles_store.create_profile(data.name, data.description)
	return profile.to_dict()


@app.get("/profiles", response_model=list[ProfileOut])
def list_profiles() -> list[ProfileOut]:
	return [p.to_dict() for p in profiles_store.list_profiles()]


@app.get("/profiles/{profile_id}", response_model=ProfileOut)
def get_profile(profile_id: str):
	profile = profiles_store.get_profile(profile_id)
	if profile is None:
		raise HTTPException(status_code=404, detail="Profile not found")
	return profile.to_dict()


@app.post("/donate", response_model=DonationOut)
def donate(data: DonationCreate):
	profile = profiles_store.get_profile(data.profile_id)
	if profile is None:
		raise HTTPException(status_code=404, detail="Profile not found")

	# Optional: you could enforce that the donor wallet must already exist
	# and/or have enough balance. For now, the blockchain is trust-based.

	# --- Internal AI assessment (no direct user interaction) ---
	# Build a simple history view for this wallet for the AI engine.
	wallet_history: list[dict] = []
	for block_dict in blockchain.to_dict():
		for tx in block_dict["transactions"]:
			if tx["sender"] == data.from_wallet:
				wallet_history.append(
					{
						"timestamp": block_dict["timestamp"],
						"sender": tx["sender"],
						"receiver": tx["receiver"],
						"amount": tx["amount"],
						"profile_id": (tx.get("metadata") or {}).get("profile_id"),
					}
				)

	assessment = pcs_ai.assess_donation(
		from_wallet=data.from_wallet,
		profile_id=profile.profile_id,
		amount=data.amount,
		wallet_history=wallet_history,
	)

	extra_metadata = {
		"ai_risk_level": assessment.level.value,
		"ai_reasons": assessment.reasons,
	}

	block = blockchain.create_donation(
		from_wallet=data.from_wallet,
		to_wallet=profile.wallet_id,
		amount=data.amount,
		profile_id=profile.profile_id,
		message=data.message,
		extra_metadata=extra_metadata,
	)

	# Save blockchain to disk after each donation
	try:
		import pcs_persistence
		pcs_persistence.save_blockchain(blockchain.to_dict())
	except Exception:
		pass  # Silently fail for now

	tx = block.transactions[0]
	return DonationOut(
		block_index=block.index,
		tx_hash=block.hash,
		from_wallet=tx.sender,
		to_wallet=tx.receiver,
		amount=tx.amount,
		profile_id=tx.metadata.get("profile_id") if tx.metadata else None,
		message=tx.metadata.get("message") if tx.metadata else None,
		ai_risk_level=(tx.metadata or {}).get("ai_risk_level") if tx.metadata else None,
		ai_reasons=(tx.metadata or {}).get("ai_reasons") if tx.metadata else None,
	)


@app.get("/wallets/{wallet_id}", response_model=WalletSummaryOut)
def wallet_summary(wallet_id: str):
	summary = pcs_wallet.wallet_summary(wallet_id)
	return WalletSummaryOut(**summary)


@app.get("/chain", response_model=list[ChainBlockOut])
def get_chain() -> List[ChainBlockOut]:
	return [ChainBlockOut(**b) for b in blockchain.to_dict()]


if __name__ == "main__":  # pragma: no cover
	# This block is here as a reminder; normally you would run this
	# with:  uvicorn perfectcharitysystem:app --reload
	import uvicorn

	uvicorn.run("perfectcharitysystem:app", host="127.0.0.1", port=8000, reload=True)

