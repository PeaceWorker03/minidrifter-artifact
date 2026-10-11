# -*- coding: utf-8 -*-
"""Build paper §5.2.2 RPGraph → Cross-API Business Credential Dependency Graph Ĝ."""
from __future__ import annotations

from typing import Any, Dict, List

import networkx as nx

from minidrifter.rpgraph.edge_recovery import recover_edges
from minidrifter.rpgraph.identity_scope import assign_identity_scopes
from minidrifter.rpgraph.precedence import build_precedence
from minidrifter.rpgraph.schema import SCHEMA_VERSION, credential_set


def _materialize_networkx(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Store the recovered graph in NetworkX and export the same node/edge records."""
    graph = nx.MultiDiGraph()
    for node in nodes:
        nid = node.get('node_id')
        if not nid:
            continue
        graph.add_node(nid, **{k: v for k, v in node.items() if k != 'node_id'})
    exported: List[Dict[str, Any]] = []
    for edge in edges:
        src, dst = edge.get('src'), edge.get('dst')
        kind = edge.get('kind') or 'edge'
        if not src or not dst or graph.has_edge(src, dst, key=kind):
            continue
        graph.add_edge(src, dst, key=kind, **{k: v for k, v in edge.items() if k not in ('src', 'dst')})
        exported.append(edge)
    return {
        'nodes': nodes,
        'edges': exported,
        'graph_library': f'networkx-{nx.__version__}',
        'weakly_connected_components': nx.number_weakly_connected_components(graph) if graph.order() else 0,
    }


def build_rpgraph(ccrs: List[Dict[str, Any]]) -> Dict[str, Any]:
    scopes = assign_identity_scopes(ccrs)
    precedence = build_precedence(ccrs, scopes['operation_scope'])
    recovered = recover_edges(ccrs, scopes['operation_scope'], precedence)
    materialized = _materialize_networkx(recovered['nodes'], recovered['edges'])
    recovered = dict(recovered)
    recovered['edges'] = materialized['edges']
    recovered['edge_count'] = len(materialized['edges'])

    # Attach RCR coverage stats
    with_bind = sum(1 for c in ccrs if credential_set(c))
    node_ops = {n['operation_id'] for n in recovered['nodes']}
    return {
        'schema_version': SCHEMA_VERSION,
        'graph_type': 'rpgraph',
        'paper_name': 'Reference Propagation Graph (RPGraph)',
        'notation': 'RPGraph=(N,E)',
        'node_semantics': 'RCR',
        'edge_semantics': 'phi_i ~> phi_j',
        'identity_scopes': scopes,
        'precedence': {
            'precedence_count': precedence.get('precedence_count'),
            # keep pairs for workflows; full list can be large but needed
            'pairs': precedence.get('pairs') or [],
        },
        'nodes': recovered['nodes'],
        'edges': recovered['edges'],
        'summary': {
            'rcr_count': len(ccrs),
            'ccr_with_bind_fields': with_bind,
            'nodes_covering_ops': len(node_ops),
            'node_count': recovered['node_count'],
            'edge_count': recovered['edge_count'],
            'graph_library': materialized['graph_library'],
            'weakly_connected_components': materialized['weakly_connected_components'],
            'direct_prop_count': recovered['direct_prop_count'],
            'resp_handoff_count': recovered['resp_handoff_count'],
            'scope_count': scopes.get('scope_count'),
            'anchored_operation_count': scopes.get('anchored_operation_count'),
        },
    }
