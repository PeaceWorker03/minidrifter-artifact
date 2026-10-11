# -*- coding: utf-8
"""Tests for chain run_id and chain_id uniqueness."""
from __future__ import annotations

import unittest

from minidrifter.business_chain.chain_run_context import make_chain_id, validate_chain_pack_consistency
from minidrifter.business_chain.chain_semantic_scorer import field_binding_risk_tier


class TestChainId(unittest.TestCase):
    def test_unique_ids_for_different_paths(self):
        a = {
            'entry_api': 'e1',
            'target_hop': 't1',
            'binding_fields': ['OrderId'],
            'hops': [
                {'api_id': 'a', 'path': '/list', 'mutation_targets': []},
                {'api_id': 'b', 'path': '/detail', 'mutation_targets': ['OrderId']},
            ],
        }
        b = {
            'entry_api': 'e1',
            'target_hop': 't2',
            'binding_fields': ['OrderId'],
            'hops': [
                {'api_id': 'a', 'path': '/list', 'mutation_targets': []},
                {'api_id': 'c', 'path': '/other', 'mutation_targets': ['OrderId']},
            ],
        }
        self.assertNotEqual(make_chain_id(a), make_chain_id(b))


class TestFieldRisk(unittest.TestCase):
    def test_user_id_is_low_not_high(self):
        self.assertEqual(field_binding_risk_tier('UserId'), 'low')
        self.assertEqual(field_binding_risk_tier('OrderId'), 'high')


class TestPackConsistency(unittest.TestCase):
    PACK = __import__('pathlib').Path(__file__).resolve().parents[1] / 'sample_outputs' / 'ehai'

    def test_validate_after_refresh(self):
        if not (self.PACK / 'business_chains.json').exists():
            self.skipTest('ehai pack missing')
        from minidrifter.business_chain.export import refresh_business_chains_for_pack
        refresh_business_chains_for_pack(self.PACK)
        doc = validate_chain_pack_consistency(self.PACK)
        self.assertTrue(doc.get('valid'), doc.get('errors'))
        self.assertEqual(doc.get('unique_chain_ids'), doc.get('chain_count'))


if __name__ == '__main__':
    unittest.main()
