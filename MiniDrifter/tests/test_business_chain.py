# -*- coding: utf-8
"""Tests for business chain recovery layer."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from minidrifter.business_chain.field_role import infer_field_role, is_runtime_context_field
from minidrifter.business_chain.export import build_business_chain_pipeline, refresh_business_chains_for_pack
from minidrifter.business_chain.chain_ranker import load_chain_priority_index


class TestFieldRole(unittest.TestCase):
    def test_customer_id_ambiguous_subject(self):
        info = infer_field_role('loginCustomerId')
        self.assertEqual(info['binding_relevance'], 'high')
        self.assertIn('SUBJECT_ID', info['role'])

    def test_runtime_context_excluded(self):
        self.assertTrue(is_runtime_context_field('signature'))
        self.assertTrue(is_runtime_context_field('Token'))


class TestBusinessChainPipeline(unittest.TestCase):
    PACK = Path(__file__).resolve().parents[1] / 'sample_outputs' / 'ehai'

    def test_build_on_ehai(self):
        if not (self.PACK / 'runtime_demand_graph.full.json').exists():
            self.skipTest('ehai pack missing demand graph')
        from minidrifter.reasoning.pack_loader import load_pack
        full = json.loads((self.PACK / 'runtime_demand_graph.full.json').read_text(encoding='utf-8'))
        domain = json.loads((self.PACK / 'business_domain_tree.json').read_text(encoding='utf-8'))
        pack = load_pack(self.PACK)
        tpl_path = self.PACK / 'materialized_api_templates.json'
        tpl_doc = json.loads(tpl_path.read_text(encoding='utf-8')) if tpl_path.exists() else {}
        templates = {t['api_id']: t for t in (tpl_doc.get('templates') or []) if t.get('api_id')}
        result = build_business_chain_pipeline(
            cards=pack['cards'],
            manifest=pack['manifest'],
            runtime_graph_full=full,
            domain_tree=domain,
            templates_by_id=templates,
            pack_dir=self.PACK,
        )
        self.assertIn('business_chains', result)
        self.assertGreater(result['summary'].get('chains', 0), 0)
        self.assertGreater(len(result['chain_rank_plan'].get('top_chains') or []), 0)
        self.assertEqual(result['chain_rank_plan'].get('verification_scope'), 'single_account')

    def test_chain_priority_index(self):
        if not (self.PACK / 'chain_rank_plan.json').exists():
            refresh_business_chains_for_pack(self.PACK)
        idx = load_chain_priority_index(self.PACK)
        if not idx:
            self.skipTest('no chain rank plan')
        self.assertTrue(any(v.get('chain_count', 0) > 0 for v in idx.values()))


if __name__ == '__main__':
    unittest.main()
