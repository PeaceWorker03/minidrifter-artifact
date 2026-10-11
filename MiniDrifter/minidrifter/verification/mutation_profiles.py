# -*- coding: utf-8
"""M7 mutation profiles — invalid / sibling / environment probes (profile-driven)."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from minidrifter.orchestration.frontier_scheduler import ENVIRONMENT_ANCHORS, primary_object_anchor

PROFILE_INVALID = 'invalid_anchor'
PROFILE_SIBLING = 'sibling_anchor'
PROFILE_ENVIRONMENT = 'environment_probe'

EXPECTED_INVALID = 'should_block_or_reject'
EXPECTED_SIBLING = 'same_owner_may_accept'
EXPECTED_ENVIRONMENT = 'environment_consistency_only'


def _synthetic_invalid(value: str) -> str:
    if str(value).isdigit():
        return str(int(value) + 1) if len(str(value)) < 12 else '9999999999'
    return f'{value}_alt'


def _sibling_candidates(
    object_pool: Optional[Dict[str, Any]],
    field: str,
    current: str,
) -> List[str]:
    out: List[str] = []
    pools = (object_pool or {}).get('pools') or {}
    for pool_name, objs in pools.items():
        if pool_name == 'negative_pool':
            continue
        if not isinstance(objs, dict):
            continue
        for obj in objs.values():
            if not isinstance(obj, dict):
                continue
            if str(obj.get('field', '')).lower() != field.lower():
                continue
            val = str(obj.get('value') or '')
            if val and val != str(current):
                out.append(val)
    return out


def build_mutation_profiles_for_chain(
    chain: Dict[str, Any],
    *,
    baseline_context: Optional[Dict[str, Any]] = None,
    object_pool: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return mutation profile doc for one chain (invalid + optional sibling + env)."""
    anchor = primary_object_anchor(chain)
    resolved = (baseline_context or {}).get('resolved_fields') or {}
    base_val = None
    ent = resolved.get(anchor) or resolved.get(anchor.lower())
    if isinstance(ent, dict):
        base_val = ent.get('value')
    elif ent is not None:
        base_val = ent
    of = chain.get('object_flow') or {}
    if base_val is None and of.get('object_value') not in (None, ''):
        base_val = str(of['object_value'])

    profiles: List[Dict[str, Any]] = []
    if base_val is not None and str(anchor).lower() not in ENVIRONMENT_ANCHORS:
        invalid_to = _synthetic_invalid(str(base_val))
        if invalid_to != str(base_val):
            profiles.append({
                'profile': PROFILE_INVALID,
                'field': anchor,
                'from': str(base_val),
                'to': invalid_to,
                'expected_semantics': EXPECTED_INVALID,
                'priority': 1,
            })
        for sib in _sibling_candidates(object_pool, anchor, str(base_val))[:2]:
            profiles.append({
                'profile': PROFILE_SIBLING,
                'field': anchor,
                'from': str(base_val),
                'to': sib,
                'expected_semantics': EXPECTED_SIBLING,
                'priority': 2,
            })

    for env_field in chain.get('binding_fields') or []:
        if str(env_field).lower() not in ENVIRONMENT_ANCHORS:
            continue
        ev = resolved.get(env_field)
        if isinstance(ev, dict):
            ev = ev.get('value')
        if ev is None:
            continue
        alt = _synthetic_invalid(str(ev))
        profiles.append({
            'profile': PROFILE_ENVIRONMENT,
            'field': env_field,
            'from': str(ev),
            'to': alt,
            'expected_semantics': EXPECTED_ENVIRONMENT,
            'priority': 10,
        })

    profiles.sort(key=lambda p: p.get('priority') or 99)
    return {
        'chain_id': chain.get('chain_id'),
        'object_anchor': anchor,
        'profiles': profiles,
        'primary_profile': profiles[0]['profile'] if profiles else None,
    }


def is_environment_mutation_field(field: Optional[str]) -> bool:
    return str(field or '').lower().replace('_', '') in ENVIRONMENT_ANCHORS


def profile_for_m7_step(
    chain: Dict[str, Any],
    *,
    baseline_context: Optional[Dict[str, Any]] = None,
    object_pool: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    doc = build_mutation_profiles_for_chain(
        chain, baseline_context=baseline_context, object_pool=object_pool,
    )
    for p in doc.get('profiles') or []:
        if p.get('profile') in {PROFILE_INVALID, PROFILE_SIBLING}:
            return p
    return (doc.get('profiles') or [None])[0]
