# -*- coding: utf-8
"""Rank object-flow and high-risk chains by field/domain priority — profile-driven."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.graph.semantic_workflow_graph import infer_domain_from_path
from minidrifter.materials.intake_param_hints import normalize_api_path

_ONTOLOGY_PATHS = (
    Path(__file__).resolve().parents[2] / 'packs' / 'object_field_ontology.json',
    Path(__file__).resolve().parents[2] / 'packs' / 'domain_ontology.json',
)


@lru_cache(maxsize=1)
def _load_field_ontology() -> Dict[str, Any]:
    path = _ONTOLOGY_PATHS[0]
    if path.exists():
        return json.loads(path.read_text(encoding='utf-8'))
    return {}


@lru_cache(maxsize=1)
def _load_domain_ontology() -> Dict[str, Any]:
    path = _ONTOLOGY_PATHS[1]
    if path.exists():
        return json.loads(path.read_text(encoding='utf-8'))
    return {}


def field_priority_score(field: str) -> float:
    ont = _load_field_ontology()
    pri = (ont.get('field_priority') or {}).get(field)
    if pri is not None:
        return float(pri) / 100.0
    fl = (field or '').lower()
    for k, v in (ont.get('field_priority') or {}).items():
        if k.lower() == fl:
            return float(v) / 100.0
    return 0.35 if fl.endswith('id') else 0.15


def domain_priority_score(domain: str) -> float:
    ont = _load_domain_ontology()
    pri = (ont.get('domain_priority') or _load_field_ontology().get('domain_priority') or {}).get(domain)
    if pri is not None:
        return float(pri) / 100.0
    if domain in (ont.get('low_priority_domains') or []):
        return 0.15
    return 0.35


def is_low_value_path(path: str) -> bool:
    low = normalize_api_path(path).lower()
    hints = _load_field_ontology().get('low_value_path_hints') or []
    return any(h in low for h in hints)


def is_identity_relevant_path(path: str) -> bool:
    low = normalize_api_path(path).lower()
    hints = _load_field_ontology().get('identity_relevant_path_hints') or []
    return any(h in low for h in hints)


def rank_object_flow_chain(
    chain: Dict[str, Any],
    *,
    risk_by_path: Optional[Dict[str, float]] = None,
) -> float:
    """Higher = run sooner. orderId consumer chains beat dept/city config chains."""
    target = normalize_api_path(chain.get('target_path') or '')
    domain = chain.get('domain') or infer_domain_from_path(target)
    of = chain.get('object_flow') or {}
    conf = float(of.get('confidence') or 0.0)
    fields = chain.get('binding_fields') or [of.get('object_field')] if of.get('object_field') else []
    field_pri = max((field_priority_score(f) for f in fields if f), default=0.2)
    dom_pri = domain_priority_score(domain)
    risk = float((risk_by_path or {}).get(target) or 0.0) / 100.0
    tier_bonus = {'high': 0.2, 'medium': 0.08}.get(chain.get('binding_risk_tier') or '', 0.0)
    source_bonus = 0.1 if chain.get('chain_source') == 'runtime_object_flow' else 0.0
    low_penalty = 0.25 if is_low_value_path(target) and field_pri < 0.5 else 0.0
    id_bonus = 0.12 if is_identity_relevant_path(target) else 0.0
    producer_bonus = 0.08 if _path_role(of.get('producer_api') or chain.get('entry_path') or '') == 'list' else 0.0
    return (
        field_pri * 0.35
        + dom_pri * 0.22
        + conf * 0.18
        + risk * 0.15
        + tier_bonus
        + source_bonus
        + id_bonus
        + producer_bonus
        - low_penalty
    )


def _path_role(path: str) -> str:
    low = normalize_api_path(path).lower()
    if any(h in low for h in ('list', 'query', 'search', 'orderlist')):
        return 'list'
    if any(h in low for h in ('detail', 'info', 'cardorder')):
        return 'detail'
    return 'other'


def rank_object_flow_chains(
    chains: List[Dict[str, Any]],
    *,
    risk_by_path: Optional[Dict[str, float]] = None,
) -> List[Dict[str, Any]]:
    """Return chains sorted by rank score descending; inject rank_score on each."""
    scored: List[tuple] = []
    for chain in chains:
        score = rank_object_flow_chain(chain, risk_by_path=risk_by_path)
        row = dict(chain)
        row['rank_score'] = round(score, 4)
        scored.append((score, row))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [row for _, row in scored]


def rank_high_risk_api_chains(
    chains: List[Dict[str, Any]],
    *,
    risk_by_path: Optional[Dict[str, float]] = None,
) -> List[Dict[str, Any]]:
    """Rank high_risk_api_chains.json entries."""
    wrapped = []
    for hr in chains:
        wrapped.append({
            'chain_id': hr.get('chain_id'),
            'chain_source': hr.get('chain_source'),
            'domain': hr.get('domain'),
            'entry_path': hr.get('producer_api'),
            'target_path': hr.get('consumer_api') or hr.get('risk_api'),
            'binding_fields': hr.get('binding_fields') or hr.get('object_anchor') or [],
            'binding_risk_tier': 'high',
            'object_flow': {
                'producer_api': hr.get('producer_api'),
                'consumer_api': hr.get('consumer_api'),
                'object_field': (hr.get('object_anchor') or [''])[0],
                'confidence': (hr.get('evidence') or {}).get('confidence', 0.85),
            },
        })
    ranked = rank_object_flow_chains(wrapped, risk_by_path=risk_by_path)
    by_id = {r['chain_id']: r.get('rank_score') for r in ranked if r.get('chain_id')}
    out = []
    for hr in chains:
        row = dict(hr)
        row['rank_score'] = by_id.get(hr.get('chain_id'), 0.0)
        out.append(row)
    out.sort(key=lambda x: -(x.get('rank_score') or 0))
    return out
