# -*- coding: utf-8
"""LLM parameter source hypothesis — field → producer API path (executable repair)."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set


def infer_param_sources_rule(
    missing_field: str,
    *,
    graph: Dict[str, Any],
    templates_by_id: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Universal rule: which APIs produce this field (no LLM)."""
    field = missing_field
    candidates: List[Dict[str, Any]] = []
    tpl = templates_by_id or {}
    for edge in graph.get('edges') or []:
        et = edge.get('type') or ''
        if 'produce' not in et.lower():
            continue
        fld = edge.get('to_field') or edge.get('field') or ''
        if fld.lower() != field.lower():
            continue
        api_id = edge.get('from') or edge.get('from_api') or ''
        path = (tpl.get(api_id) or {}).get('path') or ''
        candidates.append({
            'field': field,
            'producer_api_id': api_id,
            'producer_path': path,
            'source': 'graph_producer_edge',
            'confidence': 0.7,
        })
    return candidates[:5]


def build_param_hypothesis_context(
    missing_fields: List[str],
    *,
    graph: Dict[str, Any],
    templates_by_id: Optional[Dict[str, Any]] = None,
    object_pool: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Context bundle for LLM param hypothesis — rule candidates first."""
    confirmed = set((object_pool or {}).get('confirmed_fields') or [])
    hypotheses: List[Dict[str, Any]] = []
    for field in missing_fields:
        if field in confirmed:
            continue
        rule_hits = infer_param_sources_rule(field, graph=graph, templates_by_id=templates_by_id)
        hypotheses.append({
            'field': field,
            'rule_producers': rule_hits,
            'llm_may_refine': not rule_hits,
        })
    return {'param_hypotheses': hypotheses}
