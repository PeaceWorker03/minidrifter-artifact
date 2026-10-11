# -*- coding: utf-8 -*-
"""Tests for object-flow chain synthesis."""
from __future__ import annotations

import json
from pathlib import Path

from minidrifter.graph.object_flow_chain_synthesizer import (
    synthesize_object_flow_chains,
    write_object_flow_artifacts,
)
from minidrifter.materials.intake_param_hints import normalize_api_path


def _write_min_pack(tmp_path: Path) -> Path:
    pack = tmp_path / 'pack'
    pack.mkdir()
    (pack / 'universal_ir').mkdir()

    (pack / 'object_pool.json').write_text(json.dumps({
        'objects': [{
            'object_type': 'order',
            'field': 'orderId',
            'value': '411379426',
            'source': {
                'api': '/resource/carrctapi/account/getOrderList/v10',
                'response_path': '$.orderList[0].orderId',
                'capture': 'need_order_v10.http',
            },
            'confidence': 0.95,
        }],
    }), encoding='utf-8')

    (pack / 'baseline_runtime_context.json').write_text(json.dumps({
        'resolved_fields': {
            'orderId': {'value': '411379426', 'source': 'harvest'},
            'token': {'value': 'tok', 'source': 'login'},
        },
        'field_count': 2,
        'crypto_replay_ready': True,
    }), encoding='utf-8')

    (pack / 'baseline_intake_report.json').write_text(json.dumps({
        'decrypted_fields_aggregate': {'fields': {'orderId': '411379426'}},
    }), encoding='utf-8')

    (pack / 'materialized_api_templates.json').write_text(json.dumps({
        'ready_for_replay': [
            {
                'api_id': 'op_prod',
                'path': '/resource/carrctapi/account/getOrderList/v10',
                'status': 'materialized_with_crypto_profile',
            },
            {
                'api_id': 'op_cons',
                'path': '/resource/carrctapi/order/orderDetail/v36',
                'status': 'materialized_with_crypto_profile',
            },
            {
                'api_id': 'op_card',
                'path': '/resource/carrctapi/cardSku/cardOrderInfo/v1',
                'status': 'materialized_with_crypto_profile',
            },
        ],
        'templates': [
            {
                'api_id': 'op_prod',
                'path': '/resource/carrctapi/account/getOrderList/v10',
                'status': 'materialized_with_crypto_profile',
                'plain_template': {'body_params': {}},
            },
            {
                'api_id': 'op_cons',
                'path': '/resource/carrctapi/order/orderDetail/v36',
                'status': 'materialized_with_crypto_profile',
                'plain_template': {'body_params': {'orderId': '$orderId'}},
            },
            {
                'api_id': 'op_card',
                'path': '/resource/carrctapi/cardSku/cardOrderInfo/v1',
                'status': 'materialized_with_crypto_profile',
                'plain_template': {'body_params': {'orderId': '$orderId'}},
            },
        ],
    }), encoding='utf-8')

    (pack / 'universal_ir' / 'universal_api_cards.json').write_text(json.dumps({
        'items': [
            {'api_id': 'op_prod', 'path': '/resource/carrctapi/account/getOrderList/v10'},
            {'api_id': 'op_cons', 'path': '/resource/carrctapi/order/orderDetail/v36',
             'bindings': {'params': [{'name': 'orderId', 'static_role': 'object_id'}]}},
            {'api_id': 'op_card', 'path': '/resource/carrctapi/cardSku/cardOrderInfo/v1',
             'bindings': {'params': [{'name': 'orderId', 'static_role': 'object_id'}]}},
        ],
    }), encoding='utf-8')

    (pack / 'business_chains.json').write_text(json.dumps({'chains': []}), encoding='utf-8')
    (pack / 'binding_risk_candidates.json').write_text(json.dumps({
        'candidates': [{
            'api_id': 'op_cons',
            'path': '/resource/carrctapi/order/orderDetail/v36',
            'rule_score': 75.0,
            'probe_eligible': True,
        }],
    }), encoding='utf-8')
    return pack


def test_synthesize_order_object_flow_chains(tmp_path: Path):
    pack = _write_min_pack(tmp_path)
    doc = synthesize_object_flow_chains(pack)
    chains = doc.get('chains') or []
    assert chains
    targets = {normalize_api_path(c.get('target_path') or '') for c in chains}
    assert normalize_api_path('/resource/carrctapi/order/orderDetail/v36') in targets
    assert normalize_api_path('/resource/carrctapi/cardSku/cardOrderInfo/v1') in targets
    detail = next(
        c for c in chains
        if 'orderdetail' in normalize_api_path(c.get('target_path') or '')
    )
    assert detail.get('chain_source') == 'runtime_object_flow'
    assert normalize_api_path(detail.get('entry_path') or '') == normalize_api_path(
        '/resource/carrctapi/account/getOrderList/v10'
    )
    assert 'orderId' in (detail.get('binding_fields') or [])
    assert len(detail.get('hops') or []) == 2


def test_write_object_flow_artifacts(tmp_path: Path):
    pack = _write_min_pack(tmp_path)
    paths = write_object_flow_artifacts(pack)
    assert Path(paths['object_flow_chains']).exists()
    assert Path(paths['high_risk_api_chains']).exists()
    flow = json.loads((pack / 'object_flow_chains.json').read_text(encoding='utf-8'))
    assert flow.get('summary', {}).get('chain_count', 0) >= 1
