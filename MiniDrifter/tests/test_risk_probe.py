# -*- coding: utf-8 -*-
from __future__ import annotations

import unittest
from pathlib import Path

from minidrifter.verification.risk_probe_runner import select_uncovered_risk_probes
from minidrifter.materials.intake_param_hints import normalize_api_path

PACK = Path(__file__).resolve().parent.parent / 'sample_outputs' / 'shenzhou_p12'


class RiskProbeSelectionTests(unittest.TestCase):
    def test_select_uncovered_excludes_covered(self):
        if not (PACK / 'binding_risk_candidates.json').exists():
            self.skipTest('no binding_risk_candidates in sample pack')
        covered = {normalize_api_path('/action/carrctapi/order/deptDetail/v4')}
        rows = select_uncovered_risk_probes(PACK, covered_paths=covered, max_probes=5)
        paths = {normalize_api_path(r.get('path') or '') for r in rows}
        self.assertNotIn(normalize_api_path('/action/carrctapi/order/deptDetail/v4'), paths)
        self.assertTrue(all(r.get('probe_eligible') for r in rows))


if __name__ == '__main__':
    unittest.main()
