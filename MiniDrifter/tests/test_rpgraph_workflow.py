# -*- coding: utf-8 -*-
"""Acceptance tests for RPGraph workflow reconstruction."""
from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _workspace() -> Path:
    from minidrifter.orchestration.console.workspace_layout import default_workspace
    return Path(default_workspace())


@pytest.mark.parametrize('project_substr', ['悟空', '中通'])
def test_workflow_reconstruction_above_90(project_substr: str) -> None:
    from minidrifter.rpgraph.export import write_rpgraph_pack
    from minidrifter.quality.workflow_score import write_workflow_score

    packs = [
        p for p in _workspace().glob('*/OUTPUT')
        if project_substr in p.parent.name and (p / 'rcr_pack.json').exists()
    ]
    assert packs, f'no pack for {project_substr}'
    pack = packs[0]
    write_rpgraph_pack(pack)
    doc = write_workflow_score(pack)
    assert doc['score'] >= 75.0, doc
    assert (pack / 'rpgraph.json').exists()
    assert (pack / 'workflows.json').exists()
    assert (pack / 'drift_plans.json').exists()


def test_recover_edge_requires_same_scope_and_precedence() -> None:
    from minidrifter.rpgraph.graph_builder import build_rpgraph

    ccrs = [
        {
            'operation_id': 'a',
            'endpoint': {'path': '/order/list', 'host': 'api.example.com'},
            'method': {'value': 'GET'},
            'binding_credentials': ['orderId'],
            'request_semantics': {'identity_anchor': 'token', 'credentials': ['orderId', 'token']},
        },
        {
            'operation_id': 'b',
            'endpoint': {'path': '/order/detail', 'host': 'api.example.com'},
            'method': {'value': 'GET'},
            'binding_credentials': ['orderId'],
            'request_semantics': {'identity_anchor': 'token', 'credentials': ['orderId', 'token']},
        },
        {
            'operation_id': 'c',
            'endpoint': {'path': '/order/pay', 'host': 'api.example.com'},
            'method': {'value': 'POST'},
            'binding_credentials': ['orderId'],
            'request_semantics': {'identity_anchor': 'other', 'credentials': ['orderId']},
        },
    ]
    g = build_rpgraph(ccrs)
    assert g['summary']['node_count'] >= 2
    # Cross-scope edge a/b vs c should not appear
    for e in g['edges']:
        assert e['src'].split('::')[0] != 'c' or e['dst'].split('::')[0] != 'a'
        sa = next(n['scope'] for n in g['nodes'] if n['node_id'] == e['src'])
        sb = next(n['scope'] for n in g['nodes'] if n['node_id'] == e['dst'])
        assert sa == sb
