# -*- coding: utf-8 -*-
"""Generic transition edge pruning — maps symptoms to GRAPH_SEMANTICS class."""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from minidrifter.business_chain.chain_semantic_scorer import (
    field_binding_risk_tier,
    is_subject_bridge_field,
)
from minidrifter.graph.semantic_workflow_graph import infer_domain_from_path, list_detail_score
from minidrifter.quality.resolvers.url_role import is_third_party_sdk_url


def evaluate_transition(
    *,
    from_path: str,
    to_path: str,
    field: str,
    from_api: Dict[str, Any],
    to_api: Dict[str, Any],
) -> Tuple[bool, str, float, List[str]]:
    """Return (allowed, reject_code, score_delta, evidence)."""
    evidence: List[str] = []

    if is_third_party_sdk_url(from_path):
        return False, 'GRAPH_THIRD_PARTY_PRODUCER', -1.0, ['third_party_producer:' + from_path]

    dom_a = from_api.get('domain') or infer_domain_from_path(from_path)
    dom_b = to_api.get('domain') or infer_domain_from_path(to_path)
    ld = list_detail_score(from_path, to_path)
    tier = field_binding_risk_tier(field)

    if is_subject_bridge_field(field) and tier != 'high' and ld < 0.45:
        if dom_a != dom_b and dom_a != 'general' and dom_b != 'general':
            return False, 'GRAPH_SUBJECT_ONLY_BRIDGE', -0.25, [
                f'subject_bridge:{field}',
                f'cross_domain:{dom_a}->{dom_b}',
            ]
        return True, '', -0.15, [f'subject_bridge_weak:{field}']

    if dom_a != dom_b and dom_a != 'general' and dom_b != 'general' and ld < 0.35:
        evidence.append(f'cross_domain:{dom_a}->{dom_b}')
        return True, 'GRAPH_CROSS_DOMAIN_WEAK', -0.08, evidence

    if ld >= 0.55:
        evidence.append('list_detail_pattern')
    return True, '', 0.0, evidence
