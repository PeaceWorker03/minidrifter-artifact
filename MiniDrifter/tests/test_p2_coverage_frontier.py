# -*- coding: utf-8
"""Tests for P2 coverage frontier and chain ranker."""
from __future__ import annotations

import json
from pathlib import Path

from minidrifter.business_chain.high_risk_api_chain_ranker import (
    field_priority_score,
    rank_object_flow_chain,
    rank_object_flow_chains,
)
from minidrifter.orchestration.coverage_frontier import build_coverage_frontier


def test_field_priority_order_beats_dept():
    assert field_priority_score('orderId') > field_priority_score('deptId')
    assert field_priority_score('orderId') > field_priority_score('cityId')


def test_rank_object_flow_chains_order_first():
    chains = [
        {
            'chain_id': 'a',
            'target_path': '/action/carrctapi/order/citylist/v1',
            'domain': 'dept',
            'binding_fields': ['cityId'],
            'chain_source': 'runtime_object_flow',
            'object_flow': {'confidence': 0.9, 'object_field': 'cityId'},
        },
        {
            'chain_id': 'b',
            'target_path': '/resource/carrctapi/order/orderDetail/v36',
            'domain': 'order',
            'binding_fields': ['orderId'],
            'chain_source': 'runtime_object_flow',
            'object_flow': {'confidence': 0.92, 'object_field': 'orderId'},
            'binding_risk_tier': 'high',
        },
    ]
    ranked = rank_object_flow_chains(chains)
    assert ranked[0]['chain_id'] == 'b'
    assert ranked[0]['rank_score'] >= ranked[1]['rank_score']


def test_coverage_frontier_tiers(tmp_path: Path):
    pack = tmp_path / 'pack'
    pack.mkdir()
    (pack / 'universal_ir').mkdir()
    (pack / 'universal_ir' / 'universal_api_cards.json').write_text(json.dumps({
        'items': [
            {'api_id': 'a1', 'path': '/resource/foo/order/detail/v1'},
            {'api_id': 'a2', 'path': '/resource/foo/config/version/v1'},
        ],
    }), encoding='utf-8')
    (pack / 'materialized_api_templates.json').write_text(json.dumps({
        'ready_for_replay': [
            {'api_id': 'a1', 'path': '/resource/foo/order/detail/v1', 'status': 'materialized_with_crypto_profile'},
        ],
        'templates': [{
            'api_id': 'a1',
            'path': '/resource/foo/order/detail/v1',
            'status': 'materialized_with_crypto_profile',
            'side_effect_level': 'S0_read_only',
            'plain_template': {'body_params': {'orderId': 'x'}},
        }],
    }), encoding='utf-8')
    (pack / 'baseline_runtime_context.json').write_text(json.dumps({
        'resolved_fields': {'orderId': {'value': '1'}, 'token': {'value': 't'}},
        'crypto_replay_ready': True,
    }), encoding='utf-8')
    (pack / 'baseline_intake_report.json').write_text('{"decrypted_fields_aggregate":{"fields":{"orderId":"1"}}}', encoding='utf-8')
    (pack / 'object_pool.json').write_text('{"objects":[],"fields":{"orderId":"1"}}', encoding='utf-8')
    (pack / 'binding_risk_candidates.json').write_text(json.dumps({
        'candidates': [{
            'path': '/resource/foo/order/detail/v1',
            'rule_score': 80,
            'probe_eligible': True,
            'risk_signals': ['identity_params:orderId'],
        }],
    }), encoding='utf-8')
    (pack / 'business_chains.json').write_text('{"chains":[]}', encoding='utf-8')
    (pack / 'chain_batch_report.json').write_text(json.dumps({
        'chain_results': [{
            'target_path': '/resource/foo/order/detail/v1',
            'reached_m7': True,
            'campaign_phase': 'A2',
            'covered_via': 'object_flow_chain',
            'verdict': 'chain_completed_no_drift',
            'http_calls': 3,
        }],
    }), encoding='utf-8')

    doc = build_coverage_frontier(pack)
    assert doc['summary']['L0_static_recovered'] == 2
    assert doc['summary']['L1_materialized'] >= 1
    assert doc['summary']['L4_reached_m7'] >= 1
    assert doc['frontier']['verified_apis']
