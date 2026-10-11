# -*- coding: utf-8
"""Tests for chain rank dedup and semantic scoring."""
from __future__ import annotations

import unittest

from minidrifter.business_chain.chain_ranker import _dedupe_ranked, rank_business_chains
from minidrifter.business_chain.chain_semantic_scorer import field_binding_risk_tier


class TestChainRankDedup(unittest.TestCase):
    def test_dedupe_top_chains(self):
        scored = [
            {'chain_id': 'a', 'score': 0.9},
            {'chain_id': 'a', 'score': 0.8},
            {'chain_id': 'b', 'score': 0.7},
        ]
        out = _dedupe_ranked(scored, 25)
        self.assertEqual([x['chain_id'] for x in out], ['a', 'b'])
        self.assertEqual(out[0]['rank'], 1)

    def test_rank_plan_unique_ids(self):
        chains_doc = {
            'chains': [
                {
                    'chain_id': f'chain_{i}',
                    'chain_type': 'LIST_DETAIL',
                    'entry_api': 'entry1',
                    'entry_path': '/list',
                    'target_hop': 't1',
                    'hops': [],
                    'binding_fields': ['deptId'],
                    'mutation_target_count': 1,
                    'entry_runtime_replay_ready': False,
                    'entry_request_template_partial': True,
                    'entry_static_constructible': True,
                    'consumer_constructible': True,
                    'confidence': 0.6,
                    'safe_to_execute': True,
                }
                for i in range(3)
            ] + [
                {
                    'chain_id': 'chain_x',
                    'chain_type': 'LIST_DETAIL',
                    'entry_api': 'entry2',
                    'entry_path': '/order/list',
                    'target_hop': 't2',
                    'hops': [],
                    'binding_fields': ['OrderId', 'orderId'],
                    'mutation_target_count': 2,
                    'entry_runtime_replay_ready': True,
                    'consumer_constructible': True,
                    'binding_risk_tier': 'high',
                    'confidence': 0.7,
                    'safe_to_execute': True,
                }
            ],
        }
        plan = rank_business_chains(chains_doc, {}, limit=25)
        ids = [x['chain_id'] for x in plan['top_chains']]
        self.assertEqual(len(ids), len(set(ids)))


class TestBindingRiskTier(unittest.TestCase):
    def test_dept_medium_order_high(self):
        self.assertEqual(field_binding_risk_tier('deptId'), 'medium')
        self.assertEqual(field_binding_risk_tier('OrderId'), 'high')
        self.assertEqual(field_binding_risk_tier('UserId'), 'low')


if __name__ == '__main__':
    unittest.main()
