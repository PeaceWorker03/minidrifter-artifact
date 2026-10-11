# -*- coding: utf-8
"""Field binding risk tiers and chain semantic scoring penalties."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from minidrifter.graph.semantic_workflow_graph import infer_domain_from_path, list_detail_score
from minidrifter.quality.resolvers.url_role import is_third_party_sdk_url

_HIGH_RISK = re.compile(
    r'(order_?id|invoice_?id|coupon_?id|pay_?id|ticket_?id|device_?id|'
    r'id_?card_?no|id_?no|license_?no|passport_?no|cert_?no|bank_?card_?no)',
    re.I,
)
_SUBJECT_RISK = re.compile(r'^(user_?id|customer_?id|member_?id|open_?id|uid|target_?user_?id)$', re.I)
_MED_RISK = re.compile(r'(dept_?id|city_?id|store_?id|shop_?id|poi_?id)', re.I)
_LOW_RISK = re.compile(r'^(type|page|keyword|lat|lng|limit|offset|status)$', re.I)

_MODULE_TOKENS = {
    'order': {'order', 'orders', 'orderdata', 'invoice', 'refund'},
    'hicar': {'hicar', 'digitalkey', 'bluetooth', 'dropoff', 'pickup'},
    'device': {'device', 'digitalkey'},
    'dept': {'dept', 'city', 'store', 'poi'},
    'member': {'member', 'user', 'profile'},
}


def field_binding_risk_tier(field_name: str) -> str:
    nl = str(field_name or '').strip()
    if _HIGH_RISK.search(nl):
        return 'high'
    if _SUBJECT_RISK.match(nl):
        return 'low'
    if _MED_RISK.search(nl):
        return 'medium'
    if _LOW_RISK.match(nl):
        return 'low'
    return 'medium'


def is_subject_bridge_field(field_name: str) -> bool:
    return bool(_SUBJECT_RISK.match(str(field_name or '').strip()))


def chain_binding_risk_summary(binding_fields: List[str]) -> Dict[str, Any]:
    tiers = [field_binding_risk_tier(f) for f in (binding_fields or [])]
    high = sum(1 for t in tiers if t == 'high')
    med = sum(1 for t in tiers if t == 'medium')
    low = sum(1 for t in tiers if t == 'low')
    overall = 'high' if high else ('medium' if med else ('low' if low else 'unknown'))
    return {
        'binding_risk_tier': overall,
        'high_risk_field_count': high,
        'medium_risk_field_count': med,
        'low_risk_field_count': low,
    }


def _path_module(path: str) -> str:
    low = (path or '').lower()
    for mod, tokens in _MODULE_TOKENS.items():
        if any(t in low for t in tokens):
            return mod
    return infer_domain_from_path(path)


def chain_semantic_penalties(
    chain: Dict[str, Any],
    *,
    entry_counts: Dict[str, int],
    total_chains: int,
) -> Tuple[float, List[str]]:
    """Penalize over-converged entries, cross-module bridges, long weak chains."""
    why: List[str] = []
    delta = 0.0
    entry = chain.get('entry_api') or ''
    entry_path = chain.get('entry_path') or entry
    if entry_path and is_third_party_sdk_url(entry_path):
        delta -= 0.35
        why.append('third_party_entry_penalty')

    entry_n = entry_counts.get(entry, 0)
    if total_chains and entry_n / total_chains > 0.5:
        delta -= 0.14
        why.append(f'same_entry_overuse:{entry_n}/{total_chains}')

    hops = chain.get('hops') or []
    modules = [_path_module(h.get('path') or '') for h in hops]
    uniq = set(modules)
    if len(uniq) > 2 and chain.get('chain_type') != 'LIST_DETAIL':
        delta -= 0.10
        why.append(f'semantic_domain_mismatch:{sorted(uniq)}')

    if len(hops) >= 4:
        ld = 0.0
        for i in range(len(hops) - 1):
            ld = max(ld, list_detail_score(hops[i].get('path') or '', hops[i + 1].get('path') or ''))
        if ld < 0.45:
            delta -= 0.06
            why.append('long_bridge_penalty')

    risk = chain_binding_risk_summary(chain.get('binding_fields') or [])
    if risk['binding_risk_tier'] == 'low' and chain.get('binding_fields'):
        delta -= 0.12
        why.append('low_binding_risk_fields')
    elif risk['binding_risk_tier'] == 'medium' and not risk['high_risk_field_count']:
        delta -= 0.05
        why.append('medium_binding_risk_only')

    binding = chain.get('binding_fields') or []
    high_n = sum(1 for f in binding if field_binding_risk_tier(f) == 'high')
    subject_n = sum(1 for f in binding if is_subject_bridge_field(f))
    if binding and subject_n >= high_n and high_n == 0:
        delta -= 0.12
        why.append('broad_subject_bridge_penalty')
    elif binding and subject_n > high_n:
        delta -= 0.08
        why.append('subject_field_dominant')

    return round(delta, 3), why


def count_entries(chains: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for c in chains:
        e = c.get('entry_api') or ''
        if e:
            counts[e] = counts.get(e, 0) + 1
    return counts
