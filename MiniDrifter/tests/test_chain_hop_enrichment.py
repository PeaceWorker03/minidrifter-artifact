# -*- coding: utf-8 -*-
"""Tests for chain hop enrichment (mutation targets, materialization)."""
from __future__ import annotations

import unittest

from minidrifter.business_chain.chain_hop_enrichment import (
    build_semantic_user_action,
    compute_hop_mutation_targets,
    enrich_chain,
    infer_api_semantic,
    object_credential_fields_from_card,
)


class TestChainHopEnrichment(unittest.TestCase):
    def test_object_credential_from_card(self):
        card = {
            'replay': {
                'mutation_points': [{'field': 'deptId'}],
                'plain_request_shape': {'body': {'orderId': '<object_credential>'}},
            },
        }
        fields = object_credential_fields_from_card(card)
        self.assertIn('deptId', fields)
        self.assertIn('orderId', fields)

    def test_mutation_targets_bridge(self):
        consumer = {'consumes': ['deptId', 'cityId'], 'path': '/dept/detail'}
        producer = {'produces': ['deptId']}
        targets = compute_hop_mutation_targets(
            consumer,
            chain_objects={'deptId', 'cityId'},
            prev_hop=producer,
            object_credential_fields={'orderId'},
        )
        self.assertEqual(targets, ['deptId'])

    def test_enrich_chain_sets_binding(self):
        chain = {
            'chain_id': 'c1',
            'entry_api': 'a1',
            'objects': ['OrderId', 'orderId'],
            'hops': [
                {
                    'api_id': 'a1',
                    'path': '/OrderData/List/Refund',
                    'role': 'producer',
                    'produces': ['OrderId', 'orderId'],
                    'consumes': [],
                    'mutation_targets': [],
                    'materialized': False,
                },
                {
                    'api_id': 'a2',
                    'path': '/Orders/Detail/V2',
                    'role': 'consumer',
                    'produces': [],
                    'consumes': ['OrderId', 'orderId'],
                    'mutation_targets': [],
                    'materialized': False,
                },
            ],
        }
        cards = {
            'a1': {
                'replay': {
                    'readiness': {'status': 'ready'},
                    'contract_included_in_top_k': True,
                    'mutation_points': [{'field': 'OrderId'}],
                },
            },
            'a2': {
                'replay': {
                    'readiness': {'status': 'partial', 'blockers': ['param_schema_empty']},
                    'mutation_points': [{'field': 'OrderId'}, {'field': 'orderId'}],
                },
            },
        }
        out = enrich_chain(chain, cards_by_id=cards, templates_by_id={})
        self.assertTrue(out['entry_runtime_replay_ready'])
        self.assertTrue(out['entry_materialized'])
        self.assertTrue(out['entry_request_template_partial'] is False)
        self.assertFalse(out['consumer_runtime_replay_ready'])
        self.assertIn('OrderId', out['binding_fields'])
        self.assertGreater(out['mutation_target_count'], 0)

    def test_citylist_semantic_not_order_list(self):
        sem = infer_api_semantic('/action/carrctapi/order/cityList/v1')
        self.assertIn('城市', sem['page_label'])
        self.assertNotIn('订单列表', sem['page_label'])
        action = build_semantic_user_action(
            {'entry_path': '/action/carrctapi/order/cityList/v1', 'objects': ['deptId']},
            sem,
        )
        self.assertIn('citylist', action.lower())
        self.assertNotIn('订单列表', action)


if __name__ == '__main__':
    unittest.main()
