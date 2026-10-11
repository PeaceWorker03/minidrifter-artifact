# -*- coding: utf-8 -*-
"""Universal N-tier scheduling policy — priority, skip, early-ticket."""
from __future__ import annotations

from typing import Any, Dict, Optional, Set

from minidrifter.ir.constants import N_TIERS

TIER_PRIORITY: Dict[str, float] = {
    'N0': 2.5,
    'N1-auth': 2.0,
    'N1-object': 1.5,
    'N1-capability': 0.5,
    'N1-state': -1.0,
    'N2-cross-subject': -0.5,
    'N3-audit-only': -10.0,
}

SKIP_TIERS = frozenset({'N3-audit-only'})
EARLY_TICKET_TIERS = frozenset({'N1-state'})


def runtime_tier_for_api(ir_session: Any, api_id: str) -> str:
    if ir_session is None:
        return 'N1-auth'
    card = ir_session.get_api(api_id) if hasattr(ir_session, 'get_api') else None
    if not card:
        return 'N1-auth'
    return (card.get('runtime_tier') or {}).get('tier') or 'N1-auth'


def tier_priority_delta(tier: str) -> float:
    return TIER_PRIORITY.get(tier, 0.0)


def should_skip_tier(tier: str) -> bool:
    return tier in SKIP_TIERS


def should_early_ticket(tier: str, *, confirmed_fields: Optional[Set[str]] = None) -> bool:
    """N1-state without prerequisite objects → ticket instead of burning HTTP."""
    if tier not in EARLY_TICKET_TIERS:
        return False
    return True


def schedule_boost(
    api_id: str,
    *,
    ir_session: Any = None,
    confirmed_fields: Optional[Set[str]] = None,
) -> float:
    """Priority delta from universal N-tier policy."""
    tier = runtime_tier_for_api(ir_session, api_id)
    boost = tier_priority_delta(tier)
    fields = confirmed_fields or set()
    if tier == 'N1-object':
        card = ir_session.get_api(api_id) if ir_session else None
        if card and card.get('api_role') == 'producer':
            boost += 1.0
    if tier == 'N1-capability' and not fields:
        boost -= 2.0
    return round(boost, 4)
