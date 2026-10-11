# -*- coding: utf-8 -*-
"""Tests for baseline capture strategy."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from minidrifter.business_chain.baseline_capture_strategy import (
    build_baseline_capture_strategy,
    deferred_gaps_from_strategy,
    render_baseline_strategy_section,
)

EHAI = Path(__file__).resolve().parent.parent / 'sample_outputs' / 'ehai'
SHENZHOU = Path(__file__).resolve().parents[2] / 'Workspace' / '神州租车' / 'OUTPUT'


class BaselineCaptureStrategyTests(unittest.TestCase):
    def test_build_strategy_ehai(self):
        if not (EHAI / 'business_chains.json').exists():
            self.skipTest('ehai pack missing')
        doc = build_baseline_capture_strategy(EHAI)
        self.assertIn('summary', doc)
        self.assertIn('unlock_matrix', doc)
        self.assertIn('capture_recommendations', doc)
        self.assertGreaterEqual(doc['summary'].get('static_chain_count', 0), 1)

    def test_render_section_has_max_yield_header(self):
        if not (EHAI / 'business_chains.json').exists():
            self.skipTest('ehai pack missing')
        lines = render_baseline_strategy_section(EHAI)
        text = '\n'.join(lines)
        self.assertIn('一次性 Baseline 抓包策略', text)
        self.assertIn('覆盖预估', text)

    def test_deferred_gaps_from_strategy(self):
        if not (EHAI / 'business_chains.json').exists():
            self.skipTest('ehai pack missing')
        gaps = deferred_gaps_from_strategy(EHAI)
        self.assertIsInstance(gaps, list)

    @unittest.skipUnless(SHENZHOU.exists(), 'shenzhou OUTPUT missing')
    def test_shenzhou_strategy_detects_pool_gaps(self):
        doc = build_baseline_capture_strategy(SHENZHOU)
        summary = doc.get('summary') or {}
        recs = doc.get('capture_recommendations') or []
        self.assertGreater(summary.get('static_chain_count', 0), 0)
        matrix_missing = [m for m in doc.get('unlock_matrix') or [] if m.get('status') == 'missing']
        if summary.get('blocked_chain_count', 0) > 0 or summary.get('probe_blocked_by_pool', 0) > 0:
            self.assertTrue(matrix_missing or recs)
        if recs:
            self.assertTrue(any(r.get('unlocks_chains_estimate') or r.get('unlocks_probe_eligible_estimate') for r in recs))


if __name__ == '__main__':
    unittest.main()
