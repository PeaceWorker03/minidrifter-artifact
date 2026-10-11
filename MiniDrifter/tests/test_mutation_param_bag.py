# -*- coding: utf-8 -*-
from minidrifter.verification.mutation_engine import _mutation_param_bag, materialize_mutation_proposal


def test_mutation_targets_params_when_get_has_both_bags():
    parent = {
        'method': 'GET',
        'transport_style': 'form_cid_q_sign',
        'params': {'orderId': '411379426'},
        'body_params': {'orderId': '411379426', 'cityId': '1'},
        'test_id': 'tc_parent',
        'api_id': 'op_x',
        'path': '/resource/test',
        'safety': {'side_effect': 'S0_read_only'},
    }
    bag, bag_key = _mutation_param_bag(parent)
    assert bag_key == 'params'
    assert bag['orderId'] == '411379426'

    proposal = {
        'proposal_id': 'p1',
        'mutation_type': 'M7_subject_object_mismatch',
        'mutation_operator': 'replace_with_same_type_different_value',
        'target_field': 'orderId',
        'selector': {'field': 'orderId', 'allow_synthetic': True, 'required_pool': 'negative_pool'},
    }
    result = materialize_mutation_proposal(
        proposal, parent, {'pools': {}}, {}, index=1,
    )
    assert result['status'] == 'materialized'
    tc = result['test_case']
    assert tc['params']['orderId'] == '411379427'
    assert tc['body_params']['orderId'] == '411379426'
