# -*- coding: utf-8 -*-
"""Tests for coverage-aware chain intake prompt."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from minidrifter.business_chain.chain_intake import render_chain_intake_prompt
from minidrifter.verification.reporting.coverage_aware_intake_prompt import (
    baseline_sufficient_paths,
    build_coverage_aware_intake_doc,
    render_coverage_aware_intake_section,
)


class CoverageAwareIntakePromptTests(unittest.TestCase):
    def _write_fixture(self, pack: Path) -> None:
        p1 = '/wechat/applet/user/personalCore.jhtml'
        p2 = '/wechat/applet/address/list.jhtml'
        (pack / 'api_plane_index.json').write_text(json.dumps({
            'entries': [],
            'path_index': {},
            'plane_summary': {},
        }), encoding='utf-8')
        (pack / 'business_chains.json').write_text('{"chains": [], "chain_count": 0}', encoding='utf-8')
        (pack / 'chain_material_request_plan.json').write_text(json.dumps({
            'requests': [],
            'satisfied_by_baseline': [],
            'request_count': 0,
        }), encoding='utf-8')
        (pack / 'baseline_runtime_context.json').write_text('{"field_count": 1}', encoding='utf-8')
        (pack / 'sensitive_binding_coverage_report.json').write_text(json.dumps({
            'records': [
                {
                    'target_rank': 'P1',
                    'static_path': p1,
                    'business_label': 'user_profile_personal_info',
                    'replay_coverage_status': 'live_m0_success',
                    'm0_status': 'live_m0_success',
                    'business_status': 'business_success',
                    'sensitive_response_observed': True,
                    'binding_testability_status': 'signature_bound_skip',
                    'security_conclusion': 'inconclusive',
                    'block_reason': 'signature_not_recomputable',
                    'capture_matched': True,
                    'subject_candidates': [
                        {'field': 'userId'}, {'field': 'loginCustomerId'},
                    ],
                },
                {
                    'target_rank': 'P2',
                    'static_path': p2,
                    'business_label': 'contact_address_invoice',
                    'replay_coverage_status': 'baseline_m0_success',
                    'm0_status': 'baseline_m0_success',
                    'business_status': 'business_success',
                    'sensitive_response_observed': True,
                    'binding_testability_status': 'signature_bound_skip',
                    'security_conclusion': 'inconclusive',
                    'block_reason': 'signature_not_recomputable',
                    'capture_matched': True,
                    'subject_candidates': [{'field': 'customerId'}],
                },
                {
                    'target_rank': 'P4',
                    'static_path': '/applet/wechat/submit/api/json.jhtml',
                    'business_label': 'action_operation',
                    'replay_coverage_status': 'capture_exact_matched',
                    'm0_status': None,
                    'sensitive_response_observed': False,
                    'binding_testability_status': 'safety_gate_skip',
                    'security_conclusion': 'not_tested',
                    'capture_matched': True,
                    'subject_candidates': [],
                },
            ],
        }), encoding='utf-8')

    def test_baseline_sufficient_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            self._write_fixture(pack)
            paths = baseline_sufficient_paths(pack)
            self.assertIn('/wechat/applet/user/personalcore.jhtml', paths)
            self.assertIn('/wechat/applet/address/list.jhtml', paths)

    def test_intake_doc_signature_unblock(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            self._write_fixture(pack)
            doc = build_coverage_aware_intake_doc(pack)
            p1 = next(i for i in doc['items'] if 'personalcore' in i['api'].lower())
            self.assertTrue(p1['baseline_sufficient'])
            self.assertEqual(p1['missing_material_type'], 'signature_recompute_material')
            self.assertIn('signature_generation_logic', p1['required_materials'])
            self.assertFalse(p1['m7_execute_allowed'])

    def test_render_section_zh(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            self._write_fixture(pack)
            lines = render_coverage_aware_intake_section(pack)
            text = '\n'.join(lines)
            self.assertIn('signature_not_recomputable', text)
            self.assertIn('请勿重复', text)
            self.assertIn('不会', text)
            self.assertIn('personalCore', text)

    def test_chain_intake_includes_coverage_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            self._write_fixture(pack)
            md = render_chain_intake_prompt(pack, use_llm=False)
            self.assertIn('Coverage-Aware', md)
            self.assertIn('signature_not_recomputable', md)
            self.assertNotIn('请提供 personalCore', md)


if __name__ == '__main__':
    unittest.main()
