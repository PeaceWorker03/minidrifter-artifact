# -*- coding: utf-8
"""Build business_chain_graph from runtime workflow demand graph."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from minidrifter.business_chain.field_role import infer_field_role, is_runtime_context_field
from minidrifter.business_chain.schema import (
    EDGE_BINDING_CANDIDATE,
    EDGE_MUTATION_TARGET,
    EDGE_PRODUCES_CAPABILITY,
    EDGE_PRODUCES_OBJECT,
    EDGE_REQUIRES_CAPABILITY,
    EDGE_REQUIRES_OBJECT,
    NODE_API,
    NODE_CAPABILITY,
    NODE_FIELD,
    NODE_OBJECT,
    SCHEMA_VERSION,
)
from minidrifter.graph.runtime_demand_graph import (
    PRODUCES_BUSINESS_OBJECT,
    PRODUCES_CAPABILITY,
    REQUIRES_BUSINESS_OBJECT,
    REQUIRES_CAPABILITY,
    WORKFLOW_PRODUCE_TYPES,
    WORKFLOW_REQUIRE_TYPES,
    _field_name,
)

_EDGE_MAP = {
    REQUIRES_BUSINESS_OBJECT: EDGE_REQUIRES_OBJECT,
    REQUIRES_CAPABILITY: EDGE_REQUIRES_CAPABILITY,
    PRODUCES_BUSINESS_OBJECT: EDGE_PRODUCES_OBJECT,
    PRODUCES_CAPABILITY: EDGE_PRODUCES_CAPABILITY,
    'requires': EDGE_REQUIRES_OBJECT,
    'produces': EDGE_PRODUCES_OBJECT,
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def build_business_chain_graph(
    workflow_graph: Dict[str, Any],
    *,
    cards_by_id: Optional[Dict[str, Dict[str, Any]]] = None,
    domain_tree: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Convert workflow graph edges into business-chain graph with field roles."""
    cards_by_id = cards_by_id or {}
    domain_by_id = (domain_tree or {}).get('by_card_id') or {}

    api_nodes: List[Dict[str, Any]] = []
    field_nodes: Dict[str, Dict[str, Any]] = {}
    object_nodes: Dict[str, Dict[str, Any]] = {}
    capability_nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []

    for n in workflow_graph.get('api_nodes') or []:
        aid = n.get('id')
        if not aid:
            continue
        path = n.get('path') or ''
        dom = (domain_by_id.get(aid) or {}).get('domain') or 'general'
        api_nodes.append({
            'id': aid,
            'type': NODE_API,
            'path': path,
            'method': n.get('method'),
            'domain': dom,
            'side_effect_level': n.get('side_effect_level'),
        })

    for e in workflow_graph.get('edges') or []:
        etype = e.get('type') or ''
        if etype not in WORKFLOW_REQUIRE_TYPES | WORKFLOW_PRODUCE_TYPES:
            continue
        field = _field_name(e)
        if not field or is_runtime_context_field(field):
            continue
        mapped = _EDGE_MAP.get(etype)
        if not mapped:
            continue

        api_id = e.get('from_api') or e.get('from')
        path = ''
        for an in api_nodes:
            if an['id'] == api_id:
                path = an.get('path') or ''
                break

        role_info = infer_field_role(field, {'path': path})
        field_nodes[field] = {
            'id': field,
            'type': NODE_FIELD,
            'role': role_info.get('role'),
            'binding_relevance': role_info.get('binding_relevance'),
            'object_type': role_info.get('object_type'),
        }

        if mapped in {EDGE_REQUIRES_OBJECT, EDGE_PRODUCES_OBJECT}:
            obj_key = role_info.get('object_type') or field
            object_nodes[obj_key] = {
                'id': obj_key,
                'type': NODE_OBJECT,
                'fields': sorted(set((object_nodes.get(obj_key) or {}).get('fields') or []) | {field}),
            }
        if mapped in {EDGE_REQUIRES_CAPABILITY, EDGE_PRODUCES_CAPABILITY}:
            capability_nodes[field] = {'id': field, 'type': NODE_CAPABILITY}

        edges.append({
            'type': mapped,
            'from_api': api_id,
            'to_field': field,
            'confidence': e.get('confidence', 0.7),
            'legacy_type': etype,
        })

        if role_info.get('binding_relevance') == 'high':
            edges.append({
                'type': EDGE_BINDING_CANDIDATE,
                'from_api': api_id,
                'to_field': field,
                'confidence': role_info.get('confidence', 0.7),
            })
            if role_info.get('mutation_relevance') == 'high':
                edges.append({
                    'type': EDGE_MUTATION_TARGET,
                    'from_api': api_id,
                    'to_field': field,
                    'confidence': role_info.get('confidence', 0.7),
                })

    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'source': {
            'workflow_graph': 'runtime_demand_graph.workflow.json',
            'domain_tree': 'business_domain_tree.json',
        },
        'api_nodes': api_nodes,
        'field_nodes': list(field_nodes.values()),
        'object_nodes': list(object_nodes.values()),
        'capability_nodes': list(capability_nodes.values()),
        'edges': edges,
        'stats': {
            'api_count': len(api_nodes),
            'field_count': len(field_nodes),
            'edge_counts': dict(Counter(ed.get('type') for ed in edges)),
            'binding_candidates': sum(1 for ed in edges if ed.get('type') == EDGE_BINDING_CANDIDATE),
        },
    }
