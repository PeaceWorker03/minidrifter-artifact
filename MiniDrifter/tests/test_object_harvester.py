# -*- coding: utf-8 -*-
"""Tests for nested object harvest and unlock matrix propagation."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from minidrifter.materials.object_harvester import (
    harvest_objects_from_captures,
    merge_harvest_into_aggregate,
)
from minidrifter.materials.object_pool_writer import (
    build_baseline_unlock_matrix,
    enrich_intake_with_object_harvest,
    load_baseline_field_pool,
    write_baseline_object_artifacts,
)


def _order_list_capture(order_id: str = '411379426') -> dict:
    return {
        'capture_index': 0,
        'source_file': 'need_order_v10.http',
        'path': '/getOrderList/v10',
        'response_crypto_processing': {
            'body_json': {
                'data': {
                    'orderList': [
                        {
                            'orderId': order_id,
                            'orderNo': 'SZ20260101001',
                            'status': '1',
                            'amount': '299.00',
                        }
                    ]
                }
            }
        },
    }


def _records_capture(record_id: str = '998877') -> dict:
    return {
        'capture_index': 1,
        'source_file': 'task_list.http',
        'path': '/task/list',
        'response_crypto_processing': {
            'body_json': {
                'result': {
                    'records': [
                        {
                            'id': record_id,
                            'taskId': 'task-abc',
                            'memberId': 'mem-001',
                        }
                    ]
                }
            }
        },
    }


def test_harvest_order_id_from_nested_order_list():
    harvest = harvest_objects_from_captures([_order_list_capture()])
    assert harvest['fields'].get('orderId') == '411379426'
    objs = harvest['objects']
    order_objs = [o for o in objs if o.get('object_type') == 'order']
    assert order_objs
    assert order_objs[0]['field'] == 'orderId'
    assert order_objs[0]['value'] == '411379426'
    src = order_objs[0]['source']
    assert 'need_order_v10.http' in src['capture']
    assert 'orderList' in src['response_path']


def test_harvest_generic_list_id_with_siblings():
    harvest = harvest_objects_from_captures([_records_capture()])
    assert harvest['fields'].get('taskId') == 'task-abc'
    assert harvest['fields'].get('memberId') == 'mem-001'


def test_merge_harvest_into_aggregate():
    agg = {'fields': {'deptId': '123'}, 'sources': {'deptId': 'capture'}}
    harvest = harvest_objects_from_captures([_order_list_capture()])
    merged = merge_harvest_into_aggregate(agg, harvest)
    assert merged['fields']['deptId'] == '123'
    assert merged['fields']['orderId'] == '411379426'
    assert merged['field_count'] >= 2


def test_write_artifacts_and_unlock_matrix(tmp_path: Path):
    pack = tmp_path / 'pack'
    pack.mkdir()
    intake = {
        'captures': [_order_list_capture()],
        'decrypted_fields_aggregate': {'fields': {}, 'sources': {}},
    }
    intake = enrich_intake_with_object_harvest(intake, pack_dir=pack)
    ctx = {'resolved_fields': {}, 'field_count': 0}
    write_baseline_object_artifacts(pack, intake, ctx=ctx)

    pool = load_baseline_field_pool(pack)
    assert pool['fields'].get('orderId') == '411379426'

    obj_doc = json.loads((pack / 'object_pool.json').read_text(encoding='utf-8'))
    assert any(o.get('field') == 'orderId' for o in obj_doc.get('objects') or [])

    ctx_doc = json.loads((pack / 'baseline_runtime_context.json').read_text(encoding='utf-8'))
    assert ctx_doc['resolved_fields']['orderId']['value'] == '411379426'

    (pack / 'business_chains.json').write_text(json.dumps({
        'chains': [
            {
                'chain_id': 'order_list_to_detail',
                'domain': 'order',
                'entry_path': '/getOrderList/v10',
                'target_path': '/orderDetail/v36',
                'binding_fields': ['orderId'],
                'hops': [{}, {}],
            },
            {
                'chain_id': 'task_verify',
                'domain': 'task',
                'entry_path': '/task/list',
                'target_path': '/pickupTaskVerify/v2',
                'binding_fields': ['taskId'],
                'hops': [{}],
            },
        ],
    }), encoding='utf-8')
    (pack / 'chain_rank_plan.json').write_text(json.dumps({
        'top_chains': [
            {'chain_id': 'order_list_to_detail', 'rank': 1},
            {'chain_id': 'task_verify', 'rank': 2},
        ],
    }), encoding='utf-8')
    (pack / 'binding_risk_candidates.json').write_text(json.dumps({
        'candidates': [
            {
                'path': '/orderDetail/v36',
                'probe_eligible': True,
                'rule_score': 0.9,
                'risk_signals': ['identity_params:orderId'],
            },
            {
                'path': '/pickupTaskVerify/v2',
                'probe_eligible': True,
                'rule_score': 0.85,
                'risk_signals': ['identity_params:taskId'],
            },
        ],
    }), encoding='utf-8')
    (pack / 'universal_ir').mkdir()
    (pack / 'universal_ir' / 'universal_api_cards.json').write_text('{"items": []}', encoding='utf-8')

    matrix = build_baseline_unlock_matrix(pack)
    runnable = matrix.get('runnable_chains') or []
    assert any(r.get('domain') == 'order' and r.get('status') == 'runnable' for r in runnable)
    blocked = matrix.get('blocked_chains') or []
    assert any(r.get('domain') == 'task' for r in blocked)
    gaps = matrix.get('deferred_material_gaps') or []
    assert any(g.get('domain') == 'task' for g in gaps)
    assert not any(g.get('domain') == 'order' for g in gaps)
