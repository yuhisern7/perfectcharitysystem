"""Profiles for the PCS charity system.

Each profile represents a person, project, or organization that can
receive PCS donations. Profiles are linked to an internal wallet ID
from pcs-wallet.py.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, List

import importlib.util
import pathlib


def _load_pcs_wallet_module():
	"""Load pcs-wallet.py by file path (hyphen in name blocks normal import)."""

	here = pathlib.Path(__file__).resolve().parent
	pcs_wallet_path = here / "pcs-wallet.py"

	spec = importlib.util.spec_from_file_location("pcs_wallet_module", pcs_wallet_path)
	if spec is None or spec.loader is None:
		raise RuntimeError("Unable to load pcs-wallet.py module")

	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)  # type: ignore[arg-type]
	return module


@dataclass
class Profile:
	profile_id: str
	name: str
	description: str
	wallet_id: str

	def to_dict(self) -> Dict[str, str]:
		return asdict(self)


class ProfileStore:
	"""In-memory store for profiles.

	Later this can be replaced with a real database.
	"""

	def __init__(self) -> None:
		self._profiles: Dict[str, Profile] = {}
		self._load_from_disk()

	def _load_from_disk(self) -> None:
		"""Load profiles from disk on startup."""
		try:
			import pcs_persistence
			profiles_data = pcs_persistence.load_profiles()
			for profile_id, data in profiles_data.items():
				self._profiles[profile_id] = Profile(**data)
		except Exception:
			pass  # If loading fails, start with empty profiles

	def _save_to_disk(self) -> None:
		"""Save profiles to disk."""
		try:
			import pcs_persistence
			profiles_data = {pid: p.to_dict() for pid, p in self._profiles.items()}
			pcs_persistence.save_profiles(profiles_data)
		except Exception:
			pass  # Silently fail for now

	def create_profile(self, name: str, description: str) -> Profile:
		profile_id = f"profile_{len(self._profiles) + 1}"

		pcs_wallet = _load_pcs_wallet_module()
		create_wallet_id = pcs_wallet.create_wallet_id
		wallet_id = create_wallet_id()
		profile = Profile(
			profile_id=profile_id,
			name=name,
			description=description,
			wallet_id=wallet_id,
		)
		self._profiles[profile_id] = profile
		self._save_to_disk()
		return profile

	def get_profile(self, profile_id: str) -> Profile | None:
		return self._profiles.get(profile_id)

	def list_profiles(self) -> List[Profile]:
		return list(self._profiles.values())


profiles = ProfileStore()


if __name__ == "__main__":
	# Small demo when running: python pcs-profiles.py
	p = profiles.create_profile("Example Charity", "Demo profile")
	print("Created profile:", p.to_dict())

