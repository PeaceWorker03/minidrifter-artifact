# -*- coding: utf-8
from minidrifter.verification.binding_diff_exporter import (
    build_binding_diff_document,
    classify_binding_status_from_diff,
)


def _finding():
    return {
        'finding_id': 'fd_test',
        'chain_id': 'of_chain_test',
        'api_path': '/order/detail',
        'evidence_bundle': {'target_field': 'orderId'},
    }


def _pair(m0_oid, m7_oid, m0_ret, m7_ret):
    m0_tc = {'test_id': 'tc_m0', 'api_id': 'op_x', 'mutation_type': 'M0', 'body_params': {'orderId': m0_oid}}
    m7_tc = {'test_id': 'tc_m7', 'api_id': 'op_x', 'mutation_type': 'M7_subject_object_mismatch', 'target_field': 'orderId', 'body_params': {'orderId': m7_oid}}
    m0_ex = {
        'test_id': 'tc_m0',
        'request_preview_redacted': {'params_resolved': {'orderId': m0_oid}, 'body_form': {'uid': 'same_uid'}, 'headers': {}},
        'body_json': {'orderId': m0_ret, 'orderNo': 'A'},
        'produces_fields_hint': {'orderId': m0_ret},
    }
    m7_ex = {
        'test_id': 'tc_m7',
        'request_preview_redacted': {'params_resolved': {'orderId': m7_oid}, 'body_form': {'uid': 'same_uid'}, 'headers': {}},
        'body_json': {'orderId': m7_ret, 'orderNo': 'B'},
        'produces_fields_hint': {'orderId': m7_ret},
    }
    m0_an = {'call_outcome': 'business_success', 'produced_fields': ['orderId', 'orderNo'], 'produced_values': {'orderId': m0_ret}}
    m7_an = {'call_outcome': 'business_success', 'produced_fields': ['orderId', 'orderNo'], 'produced_values': {'orderId': m7_ret}}
    return m0_tc, m7_tc, m0_ex, m7_ex, m0_an, m7_an


def test_case_a_anchor_mutation_ignored():
    m0_tc, m7_tc, m0_ex, m7_ex, m0_an, m7_an = _pair('411379426', '999999999', '411379426', '411379426')
    doc = build_binding_diff_document(
        _finding(),
        m0_test_case=m0_tc, m7_test_case=m7_tc,
        m0_execution=m0_ex, m7_execution=m7_ex,
        m0_analysis=m0_an, m7_analysis=m7_an,
    )
    assert doc['response_diff']['anchor_mutation_ignored'] is True
    assert classify_binding_status_from_diff(doc) == 'credential_bound_clean'


def test_case_b_mutated_object_returned():
    m0_tc, m7_tc, m0_ex, m7_ex, m0_an, m7_an = _pair('411379426', '999999999', '411379426', '999999999')
    doc = build_binding_diff_document(
        _finding(),
        m0_test_case=m0_tc, m7_test_case=m7_tc,
        m0_execution=m0_ex, m7_execution=m7_ex,
        m0_analysis=m0_an, m7_analysis=m7_an,
    )
    assert doc['response_diff']['mutated_object_returned'] is True
    assert classify_binding_status_from_diff(doc) == 'likely_binding_drift'


def test_case_d_mutation_on_wire_server_blocked():
    m0_tc = {
        'test_id': 'tc_m0', 'api_id': 'op_x', 'method': 'GET', 'mutation_type': 'M0',
        'params': {'orderId': '411379426'},
        'body_params': {'orderId': '411379426', 'cityId': '1'},
    }
    m7_tc = {
        'test_id': 'tc_m7', 'api_id': 'op_x', 'method': 'GET',
        'mutation_type': 'M7_subject_object_mismatch', 'target_field': 'orderId',
        'params': {'orderId': '411379427'},
        'body_params': {'orderId': '411379426', 'cityId': '1'},
    }
    m0_ex = {
        'test_id': 'tc_m0',
        'request_preview_redacted': {'params_resolved': {'orderId': '411379426'}, 'body_form': {'uid': 'same_uid'}, 'headers': {}},
        'body_json': {'orderId': '411379426'},
        'produces_fields_hint': {'orderId': '411379426'},
    }
    m7_ex = {
        'test_id': 'tc_m7',
        'request_preview_redacted': {'params_resolved': {'orderId': '411379427'}, 'body_form': {'uid': 'same_uid'}, 'headers': {}},
        'body_json': {'code': 1, 'msg': 'blocked'},
    }
    m0_an = {'call_outcome': 'business_success', 'produced_fields': ['orderId'], 'produced_values': {'orderId': '411379426'}}
    m7_an = {'call_outcome': 'business_state_blocked', 'produced_fields': [], 'produced_values': {}}
    doc = build_binding_diff_document(
        _finding(),
        m0_test_case=m0_tc, m7_test_case=m7_tc,
        m0_execution=m0_ex, m7_execution=m7_ex,
        m0_analysis=m0_an, m7_analysis=m7_an,
    )
    assert doc['request_diff']['changed_fields'] == ['orderId']
    assert classify_binding_status_from_diff(doc) == 'anchor_mutation_accepted'


def test_case_c_wrapper_only():
    m0_tc, m7_tc, m0_ex, m7_ex, m0_an, m7_an = _pair('1', '2', '1', '1')
    m7_an = {'call_outcome': 'business_success', 'produced_fields': [], 'produced_values': {}}
    m7_ex['body_json'] = {'code': 0, 'msg': 'success', 'data': None}
    doc = build_binding_diff_document(
        _finding(),
        m0_test_case=m0_tc, m7_test_case=m7_tc,
        m0_execution=m0_ex, m7_execution=m7_ex,
        m0_analysis=m0_an, m7_analysis=m7_an,
    )
    assert classify_binding_status_from_diff(doc) in {'inconclusive', 'credential_bound_clean', 'unknown'}
