# -*- coding: utf-8
"""Universal chain hypothesis builder — consumes IR only, no app-specific rules."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from minidrifter.adapters.registry import load_chain_template
from minidrifter.ir.converters import to_universal_chain_hypothesis


def match_chain_template(api_card: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Pick best universal chain template for an API card."""
    path = (api_card.get('path') or '').lower()
    domain = api_card.get('business_domain') or 'general'
    role = api_card.get('api_role') or 'unknown'

    if 'list' in path and role == 'producer':
        return load_chain_template('list_to_detail') or _inline_list_to_detail()
    if role == 'consumer' and any(x in path for x in ('detail', 'info')):
        return load_chain_template('list_to_detail') or _inline_list_to_detail()
    if any(x in path for x in ('pay', 'qrcode', 'verify')):
        return load_chain_template('state_check_to_capability') or {}
    if domain in {'order', 'invoice'} and any(x in path for x in ('create', 'submit', 'confirm')):
        return load_chain_template('create_preview_confirm') or {}
    return None


def build_hypothesis_from_seed(
    seed_api: Dict[str, Any],
    *,
    chain_id: str = '',
    missing_materials: Optional[List[str]] = None,
) -> Dict[str, Any]:
    template = match_chain_template(seed_api) or {}
    chain_type = template.get('chain_type') or 'producer_consumer_binding'
    domain = seed_api.get('business_domain') or 'general'
    chain = {
        'chain_id': chain_id or f"hyp_{seed_api.get('api_id', 'seed')}",
        'chain_type': chain_type,
        'business_domain': domain,
        'nodes': [{'path': seed_api.get('path'), 'api_id': seed_api.get('api_id'), 'role': seed_api.get('api_role')}],
        'missing_materials': missing_materials or [],
        'next_action': 'PROBE_PRODUCER',
        'confidence': seed_api.get('confidence') or 0.5,
    }
    return to_universal_chain_hypothesis(chain, domain=domain)


def _inline_list_to_detail() -> Dict[str, Any]:
    return {
        'template_id': 'list_to_detail',
        'chain_type': 'list_to_detail',
        'pattern': ['list', 'detail'],
    }
