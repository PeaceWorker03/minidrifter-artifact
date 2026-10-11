# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from minidrifter.materials.baseline_capture_requirements import (
    build_baseline_capture_requirements,
    build_project_operator_checklist,
    render_baseline_capture_requirements_md,
    write_baseline_capture_requirements,
)

YUNJIAOFEI = Path(__file__).resolve().parents[2] / 'Workspace' / '云缴费' / 'OUTPUT'


class BaselineCaptureRequirementsTests(unittest.TestCase):
    def test_generic_fallback_when_no_static(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            checklist = build_project_operator_checklist(pack)
            self.assertEqual(len(checklist), 1)
            self.assertEqual(checklist[0]['source'], 'generic_fallback')

    def test_project_checklist_uses_static_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            (pack / 'api_plane_index.json').write_text(json.dumps({
                'entries': [
                    {
                        'path': '/MiniPro',
                        'method': 'POST',
                        'primary_plane': 'action_operation',
                        'sensitivity_score': 0.8,
                        'sensitive_fields': ['token'],
                        'recommended_campaign_role': 'safety_gated_operation',
                    },
                    {
                        'path': '/uiap/mass/api/cloudpay-search/v1/search',
                        'method': 'POST',
                        'primary_plane': 'action_operation',
                        'sensitivity_score': 0.8,
                    },
                ],
            }), encoding='utf-8')
            (pack / 'acquisition_plan.json').write_text(json.dumps({
                'stage_1_target_apis': [
                    {'path': '/MiniPro', 'method': 'POST', 'stage1_score': 90, 'stage1_user_fields': ['token']},
                ],
                'stage_1_user_materials': [
                    {'material_id': 'authenticated_request_sample', 'covers_fields': ['Token', 'Authorization']},
                ],
            }), encoding='utf-8')
            (pack / 'material_requirements.json').write_text(json.dumps({
                'required': [{'purpose': '登录后缴费网关请求', 'example_paths': ['/MiniPro']}],
            }), encoding='utf-8')
            (pack / 'host_resolution.json').write_text(json.dumps({
                'host_pools': {'business_explicit': [{'host': 'https://yaoyao.cebbank.com'}]},
            }), encoding='utf-8')
            checklist = build_project_operator_checklist(pack)
            self.assertGreaterEqual(len(checklist), 2)
            self.assertEqual(checklist[0]['source'], 'static_material_plan')
            paths = [a['path'] for step in checklist for a in (step.get('example_apis') or [])]
            self.assertIn('/MiniPro', paths)
            md = render_baseline_capture_requirements_md(build_baseline_capture_requirements(pack))
            self.assertIn('/MiniPro', md)
            self.assertIn('本应用 API 示例', md)
            self.assertNotIn('打开设备列表 / 资产页（如有）', md)

    @unittest.skipUnless(YUNJIAOFEI.exists(), 'yunjiaofei OUTPUT missing')
    def test_yunjiaofei_md_is_project_specific(self):
        write_baseline_capture_requirements(YUNJIAOFEI)
        md = (YUNJIAOFEI / 'baseline_capture_requirements.md').read_text(encoding='utf-8')
        self.assertIn('云缴费', md)
        self.assertIn('/MiniPro', md)
        self.assertIn('yaoyao.cebbank.com', md)
        self.assertIn('cloudpay-search', md)
        self.assertNotIn('打开设备列表 / 资产页（如有）', md)


if __name__ == '__main__':
    unittest.main()
