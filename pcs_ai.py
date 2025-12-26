"""Internal AI-like helper for PCS transactions.

This module does NOT talk to users. It is only used by the
backend to help evaluate donations before they are written
to the blockchain.

For now this is a rule-based engine that *simulates* AI:
- Scores each donation as LOW / MEDIUM / HIGH risk.
- Uses simple heuristics based on amount and past behaviour.

Later you can replace this with a real ML model without
changing the public API of this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import List


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class DonationAssessment:
    level: RiskLevel
    reasons: list[str]


def _parse_iso_ts(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def assess_donation(
    *,
    from_wallet: str,
    profile_id: str,
    amount: float,
    wallet_history: List[dict],
) -> DonationAssessment:
    """Assess a donation using simple heuristics.

    Parameters
    ----------
    from_wallet: internal wallet id of the donor.
    profile_id: target profile id.
    amount: PCS amount.
    wallet_history: list of past transactions for this wallet as
        dictionaries, e.g. blockchain.to_dict() flattened.

    Returns
    -------
    DonationAssessment with a risk level and reasons.
    """

    reasons: list[str] = []

    # 1) Amount-based heuristic
    if amount <= 0:
        return DonationAssessment(
            level=RiskLevel.HIGH,
            reasons=["Amount must be positive"],
        )
    elif amount <= 1000:
        level = RiskLevel.LOW
    elif amount <= 10000:
        level = RiskLevel.MEDIUM
        reasons.append("Amount is relatively large (MEDIUM risk threshold)")
    else:
        level = RiskLevel.HIGH
        reasons.append("Amount is very large (HIGH risk threshold)")

    # 2) Behaviour-based heuristic: many donations in a short time window
    #    Here we roughly check how many donations this wallet made today.
    today_count = 0
    now = datetime.utcnow().date()
    for tx_info in wallet_history:
        ts_str = tx_info.get("timestamp")
        ts = _parse_iso_ts(ts_str) if isinstance(ts_str, str) else None
        if ts is None:
            continue
        if ts.date() != now:
            continue
        if tx_info.get("sender") == from_wallet and tx_info.get("profile_id") == profile_id:
            today_count += 1

    if today_count >= 20:
        level = RiskLevel.HIGH
        reasons.append("Many donations from this wallet to the same profile today")
    elif today_count >= 5 and level is RiskLevel.LOW:
        # bump to MEDIUM at least
        level = RiskLevel.MEDIUM
        reasons.append("Several donations from this wallet to the same profile today")

    if not reasons:
        reasons.append("No suspicious patterns detected")

    return DonationAssessment(level=level, reasons=reasons)
