# -*- coding: utf-8 -*-
"""Tests for dual-track UI capture surface assessment."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from minidrifter.business_chain.ui_capture_surface import (
    assess_capture_surface,
    build_capture_surface_plan,
    is_user_facing_page,
)

SHENZHOU = Path(__file__).resolve().parents[2] / 'Workspace' / '神州租车' / 'OUTPUT'


class TestUiCaptureSurface(unittest.TestCase):
    def test_rejects_sub_common_as_user_page(self):
        self.assertFalse(is_user_facing_page('package/order/sub-common/67956398d58307823ab6de5980ffa340'))
        self.assertTrue(is_user_facing_page('pages/index/index'))

    def test_shenzhou_deptlist_is_proxy_or_static(self):
        if not (SHENZHOU / 'chain_material_request_plan.json').exists():
            self.skipTest('shenzhou pack missing')
        plan = json.loads((SHENZHOU / 'chain_material_request_plan.json').read_text(encoding='utf-8'))
        req = next(
            r for r in plan['requests']
            if 'deptList' in (r.get('example_paths') or [''])[0]
        )
        chains = json.loads((SHENZHOU / 'business_chains.json').read_text(encoding='utf-8'))
        chain = next(c for c in chains['chains'] if c['chain_id'] == req['chain_id'])
        from minidrifter.business_chain.chain_hop_enrichment import resolve_entry_context
        ctx = resolve_entry_context(SHENZHOU, req['example_paths'][0], api_id=req.get('entry_api'))
        surf = assess_capture_surface(SHENZHOU, req, chain, ctx)
        self.assertIn(surf['capture_role'], {'ui_proxy', 'static_only', 'ui_direct', 'bundle_opaque'})
        if surf['capture_role'] == 'ui_proxy':
            self.assertTrue(surf.get('runtime_proxies'))
            self.assertIn('listandmap', surf['capture_paths'][0].lower())
        self.assertTrue(surf.get('chain_test_included'))

    def test_build_capture_surface_plan_dual_track(self):
        if not (SHENZHOU / 'chain_material_request_plan.json').exists():
            self.skipTest('shenzhou pack missing')
        doc = build_capture_surface_plan(SHENZHOU)
        self.assertGreater(doc.get('surface_count', 0), 0)
        self.assertIn('chain_test_entry_paths', doc)
        self.assertIn('ui_capture_request_ids', doc)


if __name__ == '__main__':
    unittest.main()
