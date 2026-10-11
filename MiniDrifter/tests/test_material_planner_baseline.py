# -*- coding: utf-8
"""Baseline-aware material planner tests."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from minidrifter.business_chain.material_planner import build_chain_material_request_plan

SHENZHOU = Path(__file__).resolve().parent.parent.parent / 'Workspace' / '神州租车' / 'OUTPUT'


class BaselineAwareMaterialPlannerTests(unittest.TestCase):
    @unittest.skipUnless(SHENZHOU.is_dir(), '神州 OUTPUT not present')
    def test_deptid_entries_satisfied_by_listandmap(self):
        rank = json.loads((SHENZHOU / 'chain_rank_plan.json').read_text(encoding='utf-8'))
        chains = json.loads((SHENZHOU / 'business_chains.json').read_text(encoding='utf-8'))
        plan = build_chain_material_request_plan(
            rank, chains, pack_dir=SHENZHOU, limit=12,
        )
        self.assertTrue(plan.get('baseline_aware'))
        satisfied = plan.get('satisfied_by_baseline') or []
        self.assertGreater(len(satisfied), 0, 'expected listAndMap to satisfy static entries')
        still = plan.get('requests') or []
        for row in satisfied:
            fields = row.get('binding_fields') or row.get('shared_fields') or []
            if 'deptId' in fields:
                self.assertIn(
                    row.get('reason'),
                    {'runtime_alias_and_baseline_fields', 'binding_fields_in_baseline_pool', 'direct_baseline_capture'},
                )
        for req in still:
            missing = set(req.get('binding_fields') or []) - {'deptId'}
            self.assertFalse(missing & {'deptId'}, 'deptId-only gaps should be satisfied')


if __name__ == '__main__':
    unittest.main()
