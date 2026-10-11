# -*- coding: utf-8 -*-
"""Tests for chain intake, object pool, finding classifier, chain_strict dry-run."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from minidrifter.business_chain.chain_intake import (
    build_chain_intake_checklist,
    load_chain_material_plan,
    render_chain_intake_prompt,
    validate_uploaded_material_against_chain,
)
from minidrifter.verification.chain_object_pool import ChainObjectPool
from minidrifter.verification.finding_classifier import (
    FINDING_F1,
    FINDING_F2,
    FINDING_F3,
    classify_binding_finding,
)
from minidrifter.verification.chain_strict_runner import (
    run_chain_strict_verification,
    select_ranked_business_chain,
)

PACK = Path(__file__).resolve().parent.parent / 'sample_outputs' / 'ehai'


class ChainIntakeTests(unittest.TestCase):
    def test_load_chain_material_plan(self):
        plan = load_chain_material_plan(PACK)
        self.assertIn('requests', plan)
        self.assertGreater(plan.get('request_count', 0), 0)

    def test_render_chain_intake_prompt(self):
        md = render_chain_intake_prompt(PACK, use_llm=False)
        self.assertIn('抓包与验证指南', md)
        self.assertIn('待办清单', md)
        self.assertIn('login_baseline', md)
        self.assertIn('导入与跑 Campaign', md)
        self.assertTrue('附录' in md or '静态候选' in md)

    def test_build_chain_intake_checklist(self):
        doc = build_chain_intake_checklist(PACK)
        self.assertTrue(doc.get('steps'))
        self.assertEqual(doc.get('primary_source'), 'chain_material_request_plan.json')

    def test_validate_material(self):
        v = validate_uploaded_material_against_chain(PACK)
        self.assertIn('valid', v)
        self.assertIn('reason', v)


class ChainObjectPoolTests(unittest.TestCase):
    def test_harvest_and_consume(self):
        pool = ChainObjectPool('chain_test', static_hops=[
            {'api_id': 'a1', 'role': 'producer', 'produces': ['DeviceId'], 'consumes': []},
            {'api_id': 'a2', 'role': 'consumer', 'produces': [], 'consumes': ['DeviceId']},
        ])
        pool.harvest('a1', ['DeviceId'], {'DeviceId': 'dev-123'})
        hop = {'api_id': 'a2', 'consumes': ['DeviceId'], 'requires': []}
        self.assertEqual(pool.missing_for_hop(hop), [])
        tc = {'params': {'DeviceId': '$baseline.DeviceId'}}
        out = pool.apply_to_test_case(tc, hop)
        self.assertEqual(out['params']['DeviceId'], 'dev-123')


class FindingClassifierTests(unittest.TestCase):
    def test_f1_entry(self):
        doc = classify_binding_finding(
            test_case={'chain_hop_role': 'producer', 'path': '/device/list'},
            analysis={},
        )
        self.assertEqual(doc['finding_tier'], FINDING_F1)
        self.assertFalse(doc['is_primary_chain_finding'])

    def test_f2_consumer(self):
        doc = classify_binding_finding(
            test_case={'chain_hop_role': 'consumer', 'path': '/device/detail'},
            analysis={},
            chain_doc={'chain_type': 'LIST_DETAIL'},
        )
        self.assertEqual(doc['finding_tier'], FINDING_F2)
        self.assertTrue(doc['is_primary_chain_finding'])

    def test_f3_capability(self):
        doc = classify_binding_finding(
            test_case={'chain_hop_role': 'consumer', 'path': '/paycode/generate'},
            analysis={},
            chain_doc={'chain_type': 'CAPABILITY_CONSUME'},
        )
        self.assertEqual(doc['finding_tier'], FINDING_F3)


class ChainStrictTests(unittest.TestCase):
    @unittest.skipUnless(PACK.exists(), 'ehai sample pack missing')
    def test_select_chain(self):
        chain = select_ranked_business_chain(PACK)
        self.assertIsNotNone(chain)
        self.assertTrue(chain.get('hops'))

    @unittest.skipUnless(PACK.exists(), 'ehai sample pack missing')
    def test_dry_run(self):
        result = run_chain_strict_verification(PACK, mode='dry-run', skip_preflight=True, verbose=False)
        self.assertEqual(result.get('verify_mode'), 'chain_strict')
        report_path = PACK / 'chain_strict_report.json'
        self.assertTrue(report_path.exists())
        report = json.loads(report_path.read_text(encoding='utf-8'))
        self.assertTrue(report.get('no_bfs_fallback'))


if __name__ == '__main__':
    unittest.main()
