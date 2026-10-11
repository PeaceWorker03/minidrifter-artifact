# -*- coding: utf-8
"""Map legacy N0/N1 + skeleton sublevels → Universal N-tier."""
from __future__ import annotations

from typing import Any, Dict, List, Set

from minidrifter.core.runtime_taxonomy import classify_side_effect, side_effect_short
from minidrifter.ir.constants import LEGACY_N0, LEGACY_N1, N_TIERS

OBJECT_ROLES = frozenset({
    'object_identifier_candidate', 'object_id', 'object_identifier_replaceable_candidate',
})
STATE_OBTAINABILITY = frozenset({'O4_workflow_object', 'O5_sensitive_capability'})
CAPABILITY_HINTS = frozenset({
    'paycode', 'verifycode', 'ticket', 'qrtoken', 'qrcode', 'smscode', 'captcha',
    'authorizationcode', 'nonce', 'signature',
})


def classify_universal_n_tier(card: Dict[str, Any], erd_item: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Return universal runtime tier + blocking reasons for one API."""
    erd_item = erd_item or {}
    legacy_level = (erd_item.get('runtime_requirement') or {}).get('level') or LEGACY_N1
    skeleton = erd_item.get('runtime_requirement_skeleton') or {}
    sublevel = skeleton.get('runtime_sublevel') or ''
    blocking = list(skeleton.get('blocking_missing') or erd_item.get('blocking_requirements') or [])

    side = side_effect_short(classify_side_effect(card))
    if side == 'S4':
        tier = 'N3-audit-only'
        reasons = ['high_risk_side_effect']
    elif legacy_level == LEGACY_N0:
        tier = 'N0'
        reasons = []
    else:
        needs_auth = _needs_auth(card, skeleton, blocking)
        needs_object = _needs_object(card, skeleton, blocking)
        needs_state = _needs_state(card, skeleton, blocking)
        needs_capability = _needs_capability(card, skeleton, blocking)
        needs_cross = _needs_cross_subject(card, skeleton)

        if needs_cross:
            tier = 'N2-cross-subject'
            reasons = ['cross_subject_binding_required']
        elif needs_capability:
            tier = 'N1-capability'
            reasons = ['capability_credential_required']
        elif needs_state:
            tier = 'N1-state'
            reasons = ['account_state_required']
        elif needs_object:
            tier = 'N1-object'
            reasons = ['business_object_required']
        elif needs_auth or sublevel in {'N1-A', 'N1-H', 'N1-B'}:
            tier = 'N1-auth'
            reasons = ['session_credential_required']
        elif sublevel == 'N1-C':
            tier = 'N1-state'
            reasons = ['context_state_required']
        else:
            tier = 'N1-auth'
            reasons = ['baseline_runtime_template']

    return {
        'tier': tier if tier in N_TIERS else 'N1-auth',
        'legacy_level': legacy_level,
        'legacy_sublevel': sublevel,
        'side_effect': side,
        'blocking_reasons': reasons,
        'replay_ready': bool((card.get('replay') or {}).get('readiness') == 'ready'),
    }


def summarize_n_tier_distribution(cards: List[Dict[str, Any]], erd_items: List[Dict[str, Any]]) -> Dict[str, int]:
    by_id = {i.get('card_id'): i for i in erd_items if i.get('card_id')}
    hist: Dict[str, int] = {t: 0 for t in sorted(N_TIERS)}
    for card in cards:
        cid = card.get('card_id')
        tier = classify_universal_n_tier(card, by_id.get(cid)).get('tier', 'N1-auth')
        hist[tier] = hist.get(tier, 0) + 1
    return {k: v for k, v in hist.items() if v}


def _binding_roles(card: Dict[str, Any]) -> Set[str]:
    return {
        p.get('static_role') for p in ((card.get('bindings') or {}).get('params') or [])
        if p.get('static_role')
    }


def _needs_auth(card: Dict[str, Any], skeleton: Dict[str, Any], blocking: List[str]) -> bool:
    if any('auth' in str(b).lower() or 'token' in str(b).lower() for b in blocking):
        return True
    roles = _binding_roles(card)
    return bool(roles & {'auth_credential_candidate', 'crypto_material'})


def _needs_object(card: Dict[str, Any], skeleton: Dict[str, Any], blocking: List[str]) -> bool:
    if any('object' in str(b).lower() for b in blocking):
        return True
    roles = _binding_roles(card)
    if roles & OBJECT_ROLES:
        return True
    for req in skeleton.get('field_requirements') or []:
        if req.get('field_role') == 'object_id':
            return True
        if req.get('obtainability') in {'O3_first_hop_object', 'O4_workflow_object'}:
            return True
    return False


def _needs_state(card: Dict[str, Any], skeleton: Dict[str, Any], blocking: List[str]) -> bool:
    if any('state' in str(b).lower() or 'baseline_response' in str(b).lower() for b in blocking):
        return True
    for req in skeleton.get('field_requirements') or []:
        if req.get('obtainability') in STATE_OBTAINABILITY:
            return True
    return False


def _needs_cross_subject(card: Dict[str, Any], skeleton: Dict[str, Any]) -> bool:
    path = ((card.get('static') or {}).get('endpoint') or {}).get('path') or ''
    if skeleton.get('binding_check') == 'cross_subject':
        return True
    return 'mismatch' in path.lower() and 'other' in path.lower()


def _needs_capability(card: Dict[str, Any], skeleton: Dict[str, Any], blocking: List[str]) -> bool:
    if any('capability' in str(b).lower() or 'verify' in str(b).lower() for b in blocking):
        return True
    roles = _binding_roles(card)
    if roles & {'capability_token', 'crypto_material'}:
        params = ((card.get('bindings') or {}).get('params') or [])
        for p in params:
            name = str(p.get('name') or '').lower()
            if any(h in name for h in CAPABILITY_HINTS):
                return True
    for req in skeleton.get('field_requirements') or []:
        if req.get('obtainability') == 'O5_sensitive_capability':
            return True
        fname = str(req.get('field') or req.get('name') or '').lower()
        if any(h in fname for h in CAPABILITY_HINTS):
            return True
    return False
