# -*- coding: utf-8 -*-
"""Tests for generic chain UI capture guide."""
from __future__ import annotations

import unittest
from pathlib import Path

from minidrifter.business_chain.chain_ui_guide import (
    build_ui_capture_guide,
    render_global_capture_preamble,
)


PACK = Path(__file__).resolve().parents[1] / 'sample_outputs' / 'ehai'


class TestChainUiGuide(unittest.TestCase):
    def test_preamble_includes_login_step(self):
        lines = render_global_capture_preamble(PACK)
        text = '\n'.join(lines)
        self.assertIn('登录态基线', text)
        self.assertIn('login_baseline', text)

    def test_preamble_accepts_llm_login_steps(self):
        lines = render_global_capture_preamble(
            PACK, llm_login_steps=['打开礼信易购小程序', '完成微信授权登录'],
        )
        self.assertIn('LLM 细化', '\n'.join(lines))
        self.assertIn('礼信易购', '\n'.join(lines))

    def test_build_guide_has_ui_steps(self):
        if not (PACK / 'chain_material_request_plan.json').exists():
            self.skipTest('no chain plan')
        import json
        plan = json.loads((PACK / 'chain_material_request_plan.json').read_text(encoding='utf-8'))
        req = (plan.get('requests') or [{}])[0]
        chains = json.loads((PACK / 'business_chains.json').read_text(encoding='utf-8'))
        chain = next(
            (c for c in chains.get('chains') or [] if c.get('chain_id') == req.get('chain_id')),
            {},
        )
        from minidrifter.business_chain.chain_hop_enrichment import resolve_entry_context
        ctx = resolve_entry_context(PACK, req.get('example_paths', [''])[0])
        guide = build_ui_capture_guide(req, chain, ctx, PACK)
        self.assertGreaterEqual(len(guide.get('ui_steps') or []), 5)
        self.assertTrue(guide.get('save_as'))


if __name__ == '__main__':
    unittest.main()
