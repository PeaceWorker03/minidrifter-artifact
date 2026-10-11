# -*- coding: utf-8
from pathlib import Path

from minidrifter.materials.object_flow_anchor_materializer import (
    anchor_injection_allowed,
    inject_object_flow_anchors,
)
from minidrifter.verification.finding_adjudicator import adjudicate_findings
from minidrifter.verification.mutation_target_selector import (
    prioritize_mutation_fields,
    select_chain_strict_m7_fields,
)


def test_prioritize_object_anchor_over_cityid():
    chain = {
        'binding_fields': ['orderId'],
        'primary_mutation_targets': ['orderId'],
        'object_flow': {'object_field': 'orderId'},
    }
    ordered = prioritize_mutation_fields(['cityId', 'orderId', 'deptId'], chain_doc=chain)
    assert ordered[0].lower().replace('_', '') == 'orderid'


def test_chain_strict_selects_anchor_only():
    chain = {
        'primary_mutation_targets': ['orderId'],
        'object_flow': {'object_field': 'orderId'},
    }
    picked = select_chain_strict_m7_fields(
        ['cityId', 'orderId', 'lat'], chain_doc=chain, max_fields=2,
    )
    assert picked == ['orderId']


def test_anchor_injection_allowed_by_path_hint():
    tpl = {'plain_template': {'body_params': {'cityId': 1}}}
    chain = {
        'binding_fields': ['orderId'],
        'object_flow': {'object_field': 'orderId', 'consumer_location': 'params.orderId'},
    }
    ok, reason = anchor_injection_allowed(
        object_field='orderId',
        consumer_path='/resource/carrctapi/order/orderdetail/v36',
        template=tpl,
        chain_doc=chain,
    )
    assert ok
    assert 'path_hint' in reason or 'consumer_location' in reason


def test_inject_object_flow_anchors(tmp_path: Path):
    pack = tmp_path / 'pack'
    pack.mkdir()
    (pack / 'universal_ir').mkdir()
    (pack / 'universal_ir' / 'universal_api_cards.json').write_text('{"items": []}', encoding='utf-8')
    (pack / 'object_pool.json').write_text(
        '{"fields": {"orderId": "411379426"}, "field_sources": {"orderId": "capture::order"}}',
        encoding='utf-8',
    )
    (pack / 'object_flow_chains.json').write_text(
        '''{"chains": [{
            "chain_id": "of_chain_test",
            "target_path": "/resource/carrctapi/order/orderdetail/v36",
            "target_hop": "op_consumer",
            "binding_fields": ["orderId"],
            "object_flow": {
                "object_field": "orderId",
                "object_value": "411379426",
                "object_source": "capture::getorderlist",
                "consumer_location": "params.orderId"
            }
        }]}''',
        encoding='utf-8',
    )
    (pack / 'high_risk_api_chains.json').write_text('{"high_risk_chains": []}', encoding='utf-8')
    (pack / 'materialized_api_templates.json').write_text(
        '''{"templates": [{
            "api_id": "op_consumer",
            "path": "/resource/carrctapi/order/orderDetail/v36",
            "status": "materialized_with_crypto_profile",
            "plain_template": {"body_params": {"cityId": 17}}
        }]}''',
        encoding='utf-8',
    )
    report = inject_object_flow_anchors(pack)
    assert report['injected_count'] >= 1
    import json
    doc = json.loads((pack / 'materialized_api_templates.json').read_text(encoding='utf-8'))
    body = doc['templates'][0]['plain_template']['body_params']
    assert body.get('orderId') == '411379426'


def test_adjudicator_enriches_mutation_bypass_finding():
    analysis = {
        'test_id': 'tc_m7',
        'api_id': 'op_x',
        'path': '/order/detail',
        'call_outcome': 'business_success',
        'produced_fields': ['orderId'],
        'security_signals': ['data_returned'],
        'binding_observation': {'mutated_fields': ['orderId']},
    }
    m0_analysis = {
        'api_id': 'op_x',
        'call_outcome': 'business_success',
    }
    tc = {
        'test_id': 'tc_m7',
        'mutation_type': 'M7_subject_object_mismatch',
        'target_field': 'orderId',
        'body_params': {'orderId': '999'},
    }
    tc_by_id = {'tc_m7': tc, 'tc_m0': {'test_id': 'tc_m0', 'mutation_type': 'M0', 'api_id': 'op_x'}}
    analyses = [m0_analysis, analysis]
    findings = adjudicate_findings(
        analyses, tc_by_id,
        chain_id='of_chain_test',
        chain_doc={
            'chain_id': 'of_chain_test',
            'chain_source': 'runtime_object_flow',
            'campaign_phase': 'A2',
            'binding_fields': ['orderId'],
            'primary_mutation_targets': ['orderId'],
            'object_flow': {
                'object_field': 'orderId',
                'object_value': '411379426',
                'object_source': 'capture::order',
                'producer_api': '/resource/getorderlist/v10',
            },
            'hops': [{'api_id': 'op_x', 'role': 'consumer'}],
            'target_hop': 'op_x',
        },
    )
    assert findings
    assert findings[0].get('evidence_grade')
    assert findings[0].get('evidence_bundle')
