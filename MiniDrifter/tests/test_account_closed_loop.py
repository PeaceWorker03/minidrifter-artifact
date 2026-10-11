# -*- coding: utf-8 -*-
"""Tests for chain-first materialization targets and closed-loop helpers."""
from __future__ import annotations

import unittest
from pathlib import Path

from minidrifter.business_chain.chain_targets import (
    collect_chain_materialization_targets,
    merge_materialization_targets,
)
from minidrifter.orchestration.account_closed_loop import (
    _pack_has_chains,
    _resolve_verify_mode,
)


class TestChainTargets(unittest.TestCase):
    PACK = Path(__file__).resolve().parents[1] / 'sample_outputs' / 'ehai_p12'

    def test_collect_chain_targets_from_ehai_p12(self):
        if not (self.PACK / 'chain_rank_plan.json').exists():
            self.skipTest('ehai_p12 chain_rank_plan missing')
        ids = collect_chain_materialization_targets(self.PACK, top_n=1, max_ids=20)
        self.assertGreater(len(ids), 0)
        rank = __import__('json').loads((self.PACK / 'chain_rank_plan.json').read_text(encoding='utf-8'))
        entry = rank['top_chains'][0]['entry_api']
        self.assertEqual(ids[0], entry)

    def test_merge_chain_first(self):
        merged = merge_materialization_targets(['a', 'b'], ['c', 'a'], limit=10)
        self.assertEqual(merged[:3], ['a', 'b', 'c'])

    def test_resolve_verify_mode_chain_strict(self):
        if not (self.PACK / 'business_chains.json').exists():
            self.skipTest('ehai_p12 business_chains missing')
        self.assertTrue(_pack_has_chains(self.PACK))
        self.assertEqual(_resolve_verify_mode(self.PACK), 'chain_strict')


if __name__ == '__main__':
    unittest.main()
