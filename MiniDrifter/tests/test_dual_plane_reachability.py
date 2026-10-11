# -*- coding: utf-8 -*-
"""Tests for P4 dual-plane runtime reachability."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from minidrifter.business_chain.chain_hop_enrichment import resolve_entry_context
from minidrifter.quality.runtime_reachability.capture_anchor_planner import (
    build_dual_plane_plans,
)
from minidrifter.quality.runtime_reachability.navigation_graph import (
    is_user_facing_page,
    page_role,
)
from minidrifter.quality.runtime_reachability.runtime_alias_resolver import (
    alias_trusted_for_material,
)
from minidrifter.quality.runtime_reachability.ui_api_reachability import (
    STATIC_ONLY_NEEDS_MATERIAL,
    UI_REACHABLE_WEAK_FALLBACK,
    assess_api_reachability,
)

ROOT = Path(__file__).resolve().parents[2] / 'Workspace'
SHENZHOU = ROOT / '神州租车' / 'OUTPUT'
YIHAI = ROOT / '一嗨租车' / 'OUTPUT'
LIXIN = ROOT / '礼信易购小程序' / 'OUTPUT'
DEPT_LIST = '/action/carrctapi/order/deptList/v1'
LIST_AND_MAP_V1 = '/action/carrctapi/order/dept/listAndMap/v1'


class TestDualPlaneReachability(unittest.TestCase):
    def test_bundle_chunk_not_user_page(self):
        chunk = 'package/order/sub-common/67956398d58307823ab6de5980ffa340'
        self.assertEqual(page_role(chunk), 'bundle_chunk')
        self.assertFalse(is_user_facing_page(chunk))

    def test_deptlist_static_only_on_shenzhou(self):
        if not (SHENZHOU / 'api_call_sites.json').exists():
            self.skipTest('shenzhou pack missing')
        reach = assess_api_reachability(SHENZHOU, DEPT_LIST)
        self.assertIn(reach['ui_reachability'], {
            STATIC_ONLY_NEEDS_MATERIAL, 'STATIC_ONLY_REPLAYABLE', 'UNREACHABLE_UNKNOWN',
        })
        self.assertFalse(reach['usable_for_capture'])

    def test_listandmap_not_direct_ui_but_material_anchor(self):
        """v3 has no user-page callsite; v1 is runtime material anchor via alias."""
        if not (SHENZHOU / 'api_call_sites.json').exists():
            self.skipTest('shenzhou pack missing')
        reach_v3 = assess_api_reachability(SHENZHOU, '/action/carrctapi/order/dept/listAndMap/v3')
        self.assertFalse(reach_v3['usable_for_capture'])
        reach_v1 = assess_api_reachability(
            SHENZHOU, LIST_AND_MAP_V1, has_material_alias=True,
        )
        self.assertEqual(reach_v1['ui_reachability'], 'UI_REACHABLE_VIA_ALIAS')
        self.assertTrue(reach_v1['usable_for_capture'])

    def test_resolve_entry_context_has_candidates(self):
        if not (SHENZHOU / 'api_call_sites.json').exists():
            self.skipTest('shenzhou pack missing')
        ctx = resolve_entry_context(SHENZHOU, DEPT_LIST)
        self.assertIn('reachability_candidates', ctx)
        self.assertIn('ui_reachability', ctx)
        weak_only = all(
            not c.get('usable_for_capture')
            for c in ctx['reachability_candidates']
        )
        if weak_only:
            self.assertFalse(ctx['usable_for_capture'])

    def test_dual_plane_deptlist_uses_listandmap_anchor(self):
        if not (SHENZHOU / 'business_chains.json').exists():
            self.skipTest('shenzhou pack missing')
        plans = build_dual_plane_plans(SHENZHOU)
        ui = plans.get('ui_capture_plan') or {}
        captures = ui.get('captures') or []
        alias_map = plans.get('runtime_alias_map') or {}
        dept_aliases = [
            a for a in alias_map.get('aliases') or []
            if DEPT_LIST in (a.get('static_api') or '')
        ]
        listandmap_captures = [
            c for c in captures if 'listandmap' in (c.get('api') or '').lower()
        ]
        unlocks_dept = [
            c for c in captures
            if any(DEPT_LIST in (u or '') for u in (c.get('unlocks_static_candidates') or []))
        ]
        self.assertTrue(dept_aliases or listandmap_captures or unlocks_dept)

    def test_alias_rejects_host_prefixed_token_only(self):
        self.assertFalse(alias_trusted_for_material(
            '/https://appmini.1hai.cn/wechat/foo',
            {'object_field_overlap': 0, 'shared_fields': []},
        ))
        self.assertTrue(alias_trusted_for_material(
            '/wechat/foo/bar',
            {'object_field_overlap': 0.2, 'shared_fields': ['OrderId']},
        ))

    def test_yihai_material_plan_fallback_capture(self):
        if not (YIHAI / 'business_chains.json').exists():
            self.skipTest('yihai pack missing')
        plans = build_dual_plane_plans(YIHAI)
        captures = (plans.get('ui_capture_plan') or {}).get('captures') or []
        self.assertGreaterEqual(len(captures), 1)
        cap = captures[0]
        self.assertEqual(cap.get('ui_reachability'), UI_REACHABLE_WEAK_FALLBACK)
        self.assertTrue(cap.get('weak_evidence'))
        self.assertIn('description', (cap.get('api') or '').lower())
        aliases = (plans.get('runtime_alias_map') or {}).get('aliases') or []
        for entry in aliases:
            self.assertFalse((entry.get('runtime_material_api') or '').lower().startswith('/http'))

    def test_lixin_direct_captures_still_work(self):
        if not (LIXIN / 'business_chains.json').exists():
            self.skipTest('lixin pack missing')
        plans = build_dual_plane_plans(LIXIN)
        captures = (plans.get('ui_capture_plan') or {}).get('captures') or []
        self.assertGreaterEqual(len(captures), 1)


if __name__ == '__main__':
    unittest.main()
