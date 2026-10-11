# -*- coding: utf-8 -*-
"""Runtime demand graph: requires + produces, full and preview exports."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from typing import Any, Dict, List, Optional, Set

from minidrifter.reasoning.runtime_skeleton import build_runtime_requirement_skeleton

PREVIEW_LIMITS = {
    'api_nodes': 500,
    'field_nodes': 300,
    'edges': 2000,
}

# P5 dual-layer edge types
REQUIRES_RUNTIME_CONTEXT = 'requires_runtime_context'
REQUIRES_BUSINESS_OBJECT = 'requires_business_object'
REQUIRES_CAPABILITY = 'requires_capability'
PRODUCES_BUSINESS_OBJECT = 'produces_business_object'
PRODUCES_CAPABILITY = 'produces_capability'

LEGACY_REQUIRES = 'requires'
LEGACY_PRODUCES = 'produces'

RUNTIME_CONTEXT_FIELDS = frozenset({
    'Token', 'Authorization', 'AppIdentity', 'TimeSpan', 'Timestamp',
    'AppVersion', 'AppPlatform', 'Host', 'Version', 'Source', 'Company',
    'ModelVersion', 'Remark', 'Content-Type', 'channelId', 'ticket',
    'TIMESTAMP', 'timeStamp', 'timestamp', 'timespan', 'timespanMs',
})

CAPABILITY_FIELD_HINTS = frozenset({
    'PayNo', 'QRCode', 'TokenCode', 'PayCode', 'VerifyCode', 'AuthCode',
    'CaptchaCode', 'SmsCode', 'Nonce', 'Sign', 'Signature',
})

WORKFLOW_REQUIRE_TYPES = frozenset({
    REQUIRES_BUSINESS_OBJECT, REQUIRES_CAPABILITY, LEGACY_REQUIRES,
})

WORKFLOW_PRODUCE_TYPES = frozenset({
    PRODUCES_BUSINESS_OBJECT, PRODUCES_CAPABILITY, LEGACY_PRODUCES,
})


def _field_name(edge: Dict[str, Any]) -> str:
    return edge.get('to_field') or edge.get('to') or ''


def classify_require_edge_type(
    field: str,
    *,
    role: Optional[str] = None,
    obtainability: Optional[str] = None,
) -> str:
    if not field:
        return REQUIRES_RUNTIME_CONTEXT
    if field in RUNTIME_CONTEXT_FIELDS or field.lower() in {f.lower() for f in RUNTIME_CONTEXT_FIELDS}:
        return REQUIRES_RUNTIME_CONTEXT
    if field in CAPABILITY_FIELD_HINTS:
        return REQUIRES_CAPABILITY
    if role in {'capability_credential', 'payment_credential', 'session_credential'}:
        return REQUIRES_CAPABILITY
    if role in {'host_identity'} and obtainability in {'O2_host_local', 'O3_platform'}:
        return REQUIRES_RUNTIME_CONTEXT
    if role in {'subject_id', 'object_id', 'host_identity'}:
        return REQUIRES_BUSINESS_OBJECT
    if obtainability in {'O4_workflow_object', 'O1_login_bootstrap'}:
        return REQUIRES_BUSINESS_OBJECT
    return REQUIRES_BUSINESS_OBJECT


def classify_produce_edge_type(field: str, *, field_class: Optional[str] = None) -> str:
    if not field:
        return PRODUCES_BUSINESS_OBJECT
    if field in CAPABILITY_FIELD_HINTS or field_class == 'capability_credential':
        return PRODUCES_CAPABILITY
    return PRODUCES_BUSINESS_OBJECT


def enrich_edge_dual_layer(edge: Dict[str, Any]) -> Dict[str, Any]:
    """Upgrade legacy requires/produces to P5 dual-layer types."""
    out = dict(edge)
    etype = edge.get('type') or ''
    field = _field_name(edge)
    if etype in (LEGACY_REQUIRES, REQUIRES_RUNTIME_CONTEXT, REQUIRES_BUSINESS_OBJECT, REQUIRES_CAPABILITY):
        if etype == LEGACY_REQUIRES:
            out['legacy_type'] = LEGACY_REQUIRES
        new_type = classify_require_edge_type(
            field, role=edge.get('role'), obtainability=edge.get('obtainability'),
        )
        out['type'] = new_type
        out['edge_layer'] = 'runtime_context' if new_type == REQUIRES_RUNTIME_CONTEXT else 'business'
    elif etype in (LEGACY_PRODUCES, PRODUCES_BUSINESS_OBJECT, PRODUCES_CAPABILITY):
        if etype == LEGACY_PRODUCES:
            out['legacy_type'] = LEGACY_PRODUCES
        new_type = classify_produce_edge_type(field, field_class=edge.get('field_class'))
        out['type'] = new_type
        out['edge_layer'] = 'capability' if new_type == PRODUCES_CAPABILITY else 'business'
    return out


def enrich_graph_dual_layer(graph: Dict[str, Any]) -> Dict[str, Any]:
    """Apply P5 dual-layer typing to all edges; add workflow statistics."""
    out = deepcopy(graph)
    edges = [enrich_edge_dual_layer(e) for e in (graph.get('edges') or [])]
    out['edges'] = edges
    out['dual_layer'] = True
    out['edge_counts'] = dict(Counter(e.get('type') for e in edges))
    out['workflow_stats'] = compute_workflow_stats(out)
    return out


def compute_workflow_stats(graph: Dict[str, Any]) -> Dict[str, Any]:
    edges = graph.get('edges') or []
    api_ids = {n.get('id') for n in graph.get('api_nodes') or [] if n.get('id')}
    business_requires: Dict[str, int] = Counter()
    for e in edges:
        if e.get('type') not in {REQUIRES_BUSINESS_OBJECT, REQUIRES_CAPABILITY, LEGACY_REQUIRES}:
            continue
        if e.get('type') == LEGACY_REQUIRES:
            field = _field_name(e)
            if classify_require_edge_type(field, role=e.get('role'), obtainability=e.get('obtainability')) != REQUIRES_BUSINESS_OBJECT:
                continue
        api = e.get('from_api') or e.get('from')
        if api in api_ids:
            business_requires[api] += 1

    counts = [c for c in business_requires.values() if c > 0]
    workflow_apis = len(business_requires)
    avg_req = round(sum(counts) / len(counts), 2) if counts else 0.0

    return {
        'edge_counts': dict(Counter(e.get('type') for e in edges)),
        'workflow_candidate_apis': workflow_apis,
        'avg_business_requires_per_api': avg_req,
        'runtime_context_edges': sum(1 for e in edges if e.get('type') == REQUIRES_RUNTIME_CONTEXT),
        'business_object_edges': sum(1 for e in edges if e.get('type') == REQUIRES_BUSINESS_OBJECT),
        'capability_edges': sum(
            1 for e in edges if e.get('type') in {REQUIRES_CAPABILITY, PRODUCES_CAPABILITY}
        ),
    }


def extract_workflow_graph(graph: Dict[str, Any]) -> Dict[str, Any]:
    """Workflow-only view: business + capability edges (no runtime context requires)."""
    edges = [
        e for e in (graph.get('edges') or [])
        if e.get('type') in WORKFLOW_REQUIRE_TYPES | WORKFLOW_PRODUCE_TYPES
        and e.get('type') != REQUIRES_RUNTIME_CONTEXT
    ]
    # Filter legacy requires that classify as runtime
    filtered: List[Dict[str, Any]] = []
    for e in edges:
        if e.get('type') == LEGACY_REQUIRES:
            field = _field_name(e)
            if classify_require_edge_type(field, role=e.get('role'), obtainability=e.get('obtainability')) == REQUIRES_RUNTIME_CONTEXT:
                continue
        filtered.append(e)

    wf_fields: Set[str] = set()
    for e in filtered:
        fn = _field_name(e)
        if fn:
            wf_fields.add(fn)

    return {
        'schema_version': graph.get('schema_version', '1.0.0'),
        'variant': 'workflow',
        'phase': graph.get('phase'),
        'dual_layer': graph.get('dual_layer', True),
        'note': 'P5 workflow view — runtime context requires excluded from chain planning',
        'api_nodes': graph.get('api_nodes') or [],
        'field_nodes': sorted(wf_fields),
        'edges': filtered,
        'edge_counts': dict(Counter(e.get('type') for e in filtered)),
        'api_node_count': len(graph.get('api_nodes') or []),
        'workflow_stats': graph.get('workflow_stats') or compute_workflow_stats({**graph, 'edges': filtered}),
        'source_ref': 'runtime_demand_graph.full.json',
    }


def build_requires_edges(
    cards: List[Dict[str, Any]],
    items_by_id: Dict[str, Dict[str, Any]],
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]], Set[str]]:
    api_nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    field_nodes: Set[str] = set()

    for card in cards:
        if (card.get('provenance') or {}).get('card_kind') != 'operation':
            continue
        cid = card['card_id']
        item = items_by_id.get(cid) or {}
        sk = item.get('runtime_requirement_skeleton') or build_runtime_requirement_skeleton(
            card, (item.get('runtime_requirement') or {}).get('level', 'N1_BASELINE_RUNTIME_TEMPLATE')
        )
        path = sk.get('endpoint') or ''
        api_nodes.append({
            'id': cid,
            'path': path,
            'method': sk.get('method'),
            'runtime_sublevel': sk.get('runtime_sublevel'),
            'side_effect_level': sk.get('side_effect_level'),
        })

        for f in sk.get('required_fields') or []:
            fname = f.get('name')
            if not fname:
                continue
            field_nodes.add(fname)
            edges.append({
                'type': 'requires',
                'from': cid,
                'from_api': cid,
                'to': fname,
                'to_field': fname,
                'obtainability': f.get('obtainability'),
                'role': f.get('role'),
                'confidence': f.get('confidence', 0.85 if f.get('source_hint') != 'project_wrapper_default' else 0.6),
                'phase': 'pre_baseline_candidate',
            })

    return api_nodes, edges, field_nodes


def assemble_demand_graph(
    api_nodes: List[Dict[str, Any]],
    requires_edges: List[Dict[str, Any]],
    produces_edges: List[Dict[str, Any]],
    field_nodes: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    nodes_set = field_nodes or set()
    for e in requires_edges + produces_edges:
        fn = e.get('to_field') or e.get('to')
        if fn:
            nodes_set.add(fn)

    edges = requires_edges + produces_edges
    graph = {
        'phase': 'pre_baseline_candidate',
        'note': 'produces edges are heuristic until baseline response confirms fields',
        'api_nodes': api_nodes,
        'field_nodes': sorted(nodes_set),
        'edges': edges,
        'edge_counts': dict(Counter(e['type'] for e in edges)),
        'produces_count': sum(1 for e in edges if e.get('type') == 'produces'),
        'requires_count': sum(1 for e in edges if e.get('type') == 'requires'),
        'api_node_count': len(api_nodes),
        'truncated': False,
    }
    return enrich_graph_dual_layer(graph)


def truncate_graph_preview(graph: Dict[str, Any], limits: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    lim = limits or PREVIEW_LIMITS
    preview = deepcopy(graph)
    preview['variant'] = 'preview'
    preview['truncated'] = True
    preview['truncation_limits'] = lim
    preview['api_nodes'] = (graph.get('api_nodes') or [])[: lim['api_nodes']]
    preview['field_nodes'] = (graph.get('field_nodes') or [])[: lim['field_nodes']]
    preview['edges'] = (graph.get('edges') or [])[: lim['edges']]
    preview['edge_counts'] = dict(Counter(e['type'] for e in preview['edges']))
    preview['produces_count'] = sum(1 for e in preview['edges'] if e.get('type') == 'produces')
    preview['requires_count'] = sum(1 for e in preview['edges'] if e.get('type') == 'requires')
    preview['api_node_count'] = len(preview['api_nodes'])
    preview['full_api_node_count'] = graph.get('api_node_count')
    preview['full_edge_count'] = len(graph.get('edges') or [])
    return preview


def build_full_and_preview_graphs(
    cards: List[Dict[str, Any]],
    items_by_id: Dict[str, Dict[str, Any]],
    produces_edges: List[Dict[str, Any]],
) -> Dict[str, Any]:
    api_nodes, requires_edges, field_nodes = build_requires_edges(cards, items_by_id)
    full = assemble_demand_graph(api_nodes, requires_edges, produces_edges, field_nodes)
    full['variant'] = 'full'
    preview = truncate_graph_preview(full)
    return {'full': full, 'preview': preview}
