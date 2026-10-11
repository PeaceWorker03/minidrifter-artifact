# -*- coding: utf-8
"""API producer-consumer transitions from business chain graph."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.business_chain.field_role import binding_fields_from_list, infer_field_role
from minidrifter.quality.policies.edge_prune import evaluate_transition
from minidrifter.business_chain.schema import (
    EDGE_PRODUCES_CAPABILITY,
    EDGE_PRODUCES_OBJECT,
    EDGE_REQUIRES_CAPABILITY,
    EDGE_REQUIRES_OBJECT,
    SCHEMA_VERSION,
)
from minidrifter.graph.semantic_workflow_graph import infer_domain_from_path, list_detail_score

_LIST_RE = re.compile(r'(list|history|search|query|index)', re.I)
_DETAIL_RE = re.compile(r'(detail|info|get\b|query\b)', re.I)
_SAFE_SIDE = frozenset({'S0', 'S1', 'S0_read_only', 'S1_query_like_post', 'read_only', 'query_like'})


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _api_lookup(graph: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {n['id']: n for n in (graph.get('api_nodes') or []) if n.get('id')}


def _produces_by_api(edges: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {}
    for e in edges:
        if e.get('type') not in {EDGE_PRODUCES_OBJECT, EDGE_PRODUCES_CAPABILITY, 'produces_object', 'produces_capability'}:
            continue
        aid = e.get('from_api')
        field = e.get('to_field')
        if aid and field:
            out.setdefault(aid, set()).add(field)
    return out


def _requires_by_api(edges: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {}
    for e in edges:
        if e.get('type') not in {EDGE_REQUIRES_OBJECT, EDGE_REQUIRES_CAPABILITY, 'requires_object', 'requires_capability'}:
            continue
        aid = e.get('from_api')
        field = e.get('to_field')
        if aid and field:
            out.setdefault(aid, set()).add(field)
    return out


def _side_safe(api_node: Dict[str, Any]) -> bool:
    side = api_node.get('side_effect_level') or ''
    short = side.split('_')[0] if side else ''
    return short in {'S0', 'S1'} or side in _SAFE_SIDE


def _transition_score(
    *,
    field: str,
    from_api: Dict[str, Any],
    to_api: Dict[str, Any],
    template: Optional[Dict[str, Any]],
) -> Tuple[float, List[str]]:
    evidence: List[str] = ['field_bridge:' + field]
    score = 0.40

    dom_a = from_api.get('domain') or infer_domain_from_path(from_api.get('path') or '')
    dom_b = to_api.get('domain') or infer_domain_from_path(to_api.get('path') or '')
    if dom_a == dom_b and dom_a != 'general':
        score += 0.20
        evidence.append(f'same_domain:{dom_a}')

    ld = list_detail_score(from_api.get('path') or '', to_api.get('path') or '')
    if ld >= 0.55:
        score += 0.15 * ld
        evidence.append('list_detail_pattern')

    role = infer_field_role(field, {'path': to_api.get('path') or ''})
    if role.get('binding_relevance') == 'high':
        score += 0.10
        evidence.append('binding_relevance:high')

    if template and template.get('status') in {
        'materialized_plain', 'materialized_with_crypto_profile',
    }:
        score += 0.15
        evidence.append('replayability:materialized')

    return round(min(score, 1.0), 3), evidence


def build_api_transitions(
    business_graph: Dict[str, Any],
    templates_by_id: Dict[str, Dict[str, Any]],
    cards_by_id: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """Build API→API transitions via shared object/capability fields."""
    api_lookup = _api_lookup(business_graph)
    edges = business_graph.get('edges') or []
    produces = _produces_by_api(edges)
    requires = _requires_by_api(edges)

    transitions: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str, str]] = set()
    prune_stats = {'rejected_count': 0, 'rejected_by_code': {}, 'penalized_count': 0}

    for from_id, prod_fields in produces.items():
        from_api = api_lookup.get(from_id) or {}
        from_path = from_api.get('path') or ''
        for field in prod_fields:
            for to_id, req_fields in requires.items():
                if from_id == to_id:
                    continue
                if field not in req_fields:
                    continue
                key = (from_id, to_id, field)
                if key in seen:
                    continue
                seen.add(key)
                to_api = api_lookup.get(to_id) or {}
                allowed, reject_code, score_delta, prune_evidence = evaluate_transition(
                    from_path=from_path,
                    to_path=to_api.get('path') or '',
                    field=field,
                    from_api=from_api,
                    to_api=to_api,
                )
                if not allowed:
                    prune_stats['rejected_count'] += 1
                    prune_stats['rejected_by_code'][reject_code] = prune_stats['rejected_by_code'].get(reject_code, 0) + 1
                    continue
                tpl = templates_by_id.get(to_id)
                conf, evidence = _transition_score(
                    field=field,
                    from_api=from_api,
                    to_api=to_api,
                    template=tpl,
                )
                conf = round(max(0.0, min(1.0, conf + score_delta)), 3)
                evidence = list(evidence) + list(prune_evidence)
                if score_delta < 0:
                    prune_stats['penalized_count'] += 1
                if conf < 0.45:
                    continue
                domain = to_api.get('domain') or infer_domain_from_path(to_api.get('path') or '')
                transitions.append({
                    'from_api': from_id,
                    'from_path': from_path,
                    'to_api': to_id,
                    'to_path': to_api.get('path') or '',
                    'edge_type': 'PRODUCES_OBJECT_TO_CONSUMES_OBJECT',
                    'field_mapping': [{
                        'produced_field': field,
                        'consumed_field': field,
                        'object_type': infer_field_role(field).get('object_type') or field,
                    }],
                    'domain': domain,
                    'confidence': conf,
                    'evidence': evidence,
                    'single_account_relevance': 'high' if infer_field_role(field).get('binding_relevance') == 'high' else 'medium',
                })

    transitions.sort(key=lambda t: t.get('confidence', 0), reverse=True)
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'transition_count': len(transitions),
        'prune_stats': prune_stats,
        'transitions': transitions,
    }
