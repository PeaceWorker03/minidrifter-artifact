# -*- coding: utf-8 -*-
"""Object Acquisition Planner — reverse producer search for missing fields."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from minidrifter.graph.runtime_demand_graph import (
    LEGACY_PRODUCES,
    PRODUCES_BUSINESS_OBJECT,
    PRODUCES_CAPABILITY,
)
from minidrifter.verification.frontier_expander import (
    _field_set_satisfied,
    get_required_business_fields,
)
from minidrifter.verification.object_pool import GLOBAL_CONTEXT_FIELDS
from minidrifter.verification.pack_loader import is_high_value_produce, is_chain_bridge_field, chain_bridge_fields


def _producers_for_field(graph: Dict[str, Any], field: str) -> List[Dict[str, Any]]:
    produce_types = {PRODUCES_BUSINESS_OBJECT, PRODUCES_CAPABILITY, LEGACY_PRODUCES}
    out: List[Dict[str, Any]] = []
    field_lower = field.lower()
    for e in graph.get('edges') or []:
        if e.get('type') not in produce_types:
            continue
        to_f = e.get('to_field') or e.get('to') or ''
        if to_f != field and to_f.lower() != field_lower:
            continue
        api_id = e.get('from') or e.get('from_api')
        if not api_id:
            continue
        conf = float(e.get('confidence') or 0.5)
        out.append({
            'api_id': api_id,
            'field': field,
            'confidence': conf,
            'evidence_level': e.get('evidence_level') or 'static_candidate',
        })
    out.sort(key=lambda x: x['confidence'], reverse=True)
    return out


def _api_node(graph: Dict[str, Any], api_id: str) -> Optional[Dict[str, Any]]:
    for n in graph.get('api_nodes') or []:
        if n.get('id') == api_id:
            return n
    return None


def missing_high_value_objects(
    object_pool: Dict[str, Any],
    *,
    ontology_fields: Optional[Set[str]] = None,
) -> List[str]:
    available = set(object_pool.get('confirmed_fields') or [])
    available |= set(object_pool.get('frontier_unlocks') or [])
    available_lower = {a.lower() for a in available}
    missing: List[str] = []
    for f in sorted(ontology_fields or set()):
        if f in GLOBAL_CONTEXT_FIELDS:
            continue
        if f not in available and f.lower() not in available_lower:
            if is_high_value_produce(f):
                missing.append(f)
    return missing


def plan_acquire(
    target_field: str,
    *,
    pack_dir: Any,
    graph: Dict[str, Any],
    object_pool: Dict[str, Any],
    templates_by_id: Dict[str, Any],
    confidence_tracker: Any = None,
    limit: int = 5,
) -> List[Dict[str, Any]]:
    """Return ranked acquire plans for a missing field."""
    available = set(object_pool.get('confirmed_fields') or [])
    available |= set(object_pool.get('frontier_unlocks') or [])
    if target_field in available or target_field.lower() in {a.lower() for a in available}:
        return []

    plans: List[Dict[str, Any]] = []
    for prod in _producers_for_field(graph, target_field)[:limit * 2]:
        api_id = prod['api_id']
        tpl = templates_by_id.get(api_id)
        if not tpl or tpl.get('status') != 'materialized_with_crypto_profile':
            continue
        required = get_required_business_fields(graph, api_id)
        missing_req = [r for r in required if not _field_set_satisfied(available, {r})]
        node = _api_node(graph, api_id) or {}
        base_conf = prod['confidence']
        if confidence_tracker:
            base_conf = confidence_tracker.producer_confidence(api_id, target_field)
        expected = 0.5
        if confidence_tracker:
            domain = tpl.get('domain') or 'general'
            expected = confidence_tracker.expected_success(api_id, domain)
        score = base_conf * 0.5 + expected * 0.5 - len(missing_req) * 0.15
        plans.append({
            'target_field': target_field,
            'producer_api_id': api_id,
            'path': node.get('path') or tpl.get('path'),
            'template': tpl,
            'required_fields': sorted(required),
            'missing_prerequisites': sorted(missing_req),
            'score': round(score, 3),
            'action': 'atomic_probe' if not missing_req else 'acquire_prerequisite_first',
        })

    plans.sort(key=lambda x: x['score'], reverse=True)
    return plans[:limit]


def missing_chain_target_fields(
    object_pool: Dict[str, Any],
    *,
    include_bridge: bool = True,
) -> List[str]:
    """Fields needed for deep chains — high-value + bridge."""
    from minidrifter.verification.pack_loader import load_field_ontology

    available = set(object_pool.get('confirmed_fields') or [])
    available |= set(object_pool.get('frontier_unlocks') or [])
    avail_lower = {a.lower() for a in available}
    missing: List[str] = []
    ontology = load_field_ontology()
    targets = set(ontology.get('high_value_produces') or [])
    if include_bridge:
        targets |= set(ontology.get('chain_bridge_fields') or [])
    for f in sorted(targets):
        if f in GLOBAL_CONTEXT_FIELDS:
            continue
        if f not in available and f.lower() not in avail_lower:
            missing.append(f)
    return missing


def plan_acquire_all_missing(
    object_pool: Dict[str, Any],
    graph: Dict[str, Any],
    templates_by_id: Dict[str, Any],
    *,
    pack_dir: Any = None,
    confidence_tracker: Any = None,
    limit_per_field: int = 3,
    include_bridge_fields: bool = True,
) -> List[Dict[str, Any]]:
    from minidrifter.verification.pack_loader import load_field_ontology

    ontology = load_field_ontology()
    hvo = set(ontology.get('high_value_produces') or [])
    bridge = set(ontology.get('chain_bridge_fields') or []) if include_bridge_fields else set()
    missing = missing_high_value_objects(object_pool, ontology_fields=hvo | bridge)
    if include_bridge_fields:
        for f in missing_chain_target_fields(object_pool, include_bridge=True):
            if f not in missing:
                missing.append(f)
    all_plans: List[Dict[str, Any]] = []
    for field in missing[:8]:
        all_plans.extend(plan_acquire(
            field,
            pack_dir=pack_dir,
            graph=graph,
            object_pool=object_pool,
            templates_by_id=templates_by_id,
            confidence_tracker=confidence_tracker,
            limit=limit_per_field,
        ))
    all_plans.sort(key=lambda x: x['score'], reverse=True)
    return all_plans
