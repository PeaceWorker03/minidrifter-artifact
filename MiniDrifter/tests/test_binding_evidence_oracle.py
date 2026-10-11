# -*- coding: utf-8
"""Tests for evidence-grade binding oracle."""
from __future__ import annotations

from pathlib import Path

from minidrifter.verification.binding_evidence_oracle import enrich_binding_evidence


def test_enrich_binding_evidence_includes_provenance(tmp_path: Path):
    pack = tmp_path / 'pack'
    pack.mkdir()
    chain_doc = {
        'chain_id': 'of_test',
        'chain_source': 'runtime_object_flow',
        'campaign_phase': 'A2',
        'object_flow': {
            'object_field': 'orderId',
            'object_value': '411379426',
            'object_source': 'capture::getOrderList::$.orderList[0].orderId',
            'producer_api': '/getOrderList/v10',
        },
    }
    finding = {'chain_id': 'of_test', 'finding_type': 'subject_object_binding_mismatch'}
    analysis = {
        'path': '/order/detail',
        'api_id': 'op_x',
        'test_id': 't1',
        'call_outcome': 'business_success',
        'binding_observation': {'binding_status': 'subject_object_binding_mismatch', 'mutated_fields': ['orderId']},
        'security_signals': ['subject_object_binding_mismatch'],
    }
    tc = {'mutation_type': 'M7_object_id', 'target_field': 'orderId', 'params': {'orderId': '999'}}
    verdict = {'verdict': 'likely', 'reason_codes': ['explicit_binding_mismatch'], 'checks_passed': 3, 'checks_total': 5}
    out = enrich_binding_evidence(
        finding, analysis, tc,
        pack_dir=pack, chain_doc=chain_doc, binding_verdict=verdict,
    )
    assert out.get('evidence_grade') in {'B_likely', 'A_confirmed', 'C_hypothesis'}
    bundle = out.get('evidence_bundle') or {}
    assert bundle.get('object_provenance', {}).get('provenance_type') == 'runtime_object_flow'
    assert bundle.get('reason_codes')
