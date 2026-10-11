# -*- coding: utf-8 -*-
"""Tests for P4-fix-2 / P4-fix-3 sensitive read metrics and runner."""
from __future__ import annotations

import unittest

from minidrifter.verification.sensitive_read_metrics import (
    attach_sensitive_read_metrics,
    m0_business_success,
)
from minidrifter.verification.sensitive_read_runner import select_sensitive_read_targets


class SensitiveReadMetricsTests(unittest.TestCase):
    def test_m0_success_with_sensitive_fields(self):
        row = attach_sensitive_read_metrics(
            {'m0_outcome': 'business_success', 'm7_count': 0, 'reached_m7': False},
            path='/resource/carrctapi/account/getUserInfo/v1',
            m0_analysis={'call_outcome': 'business_success'},
            m0_execution={
                'body_json': {
                    'phone': '166******32',
                    'idNo': '1***1',
                    'integral': 526,
                    'name': '**天',
                },
                'status_code': 200,
            },
        )
        self.assertTrue(row['sensitive_read_m0_success'])
        self.assertFalse(row['sensitive_read_m7_success'])
        self.assertFalse(row['sensitive_mutation_tested'])
        self.assertTrue(row['sensitive_read_success'])

    def test_m0_failed_no_sensitive_read(self):
        row = attach_sensitive_read_metrics(
            {'m0_outcome': 'auth_required', 'm7_count': 0},
            path='/x',
            m0_analysis={'call_outcome': 'auth_required'},
            m0_execution={'body_json': {'phone': '1'}, 'status_code': 403},
        )
        self.assertFalse(row['sensitive_read_m0_success'])

    def test_m7_mutation_flag(self):
        row = attach_sensitive_read_metrics(
            {'m0_outcome': 'business_success', 'm7_count': 2, 'reached_m7': True},
            path='/x',
            m0_analysis={'call_outcome': 'business_success'},
            m0_execution={'body_json': {'phone': '166******32'}, 'status_code': 200},
            m7_analyses=[{}, {}],
        )
        self.assertTrue(row['sensitive_mutation_tested'])
        self.assertTrue(row['sensitive_read_m7_success'])

    def test_m0_business_success_helper(self):
        self.assertTrue(m0_business_success({'m0_outcome': 'business_success'}))
        self.assertTrue(m0_business_success({'status': 'm7_skipped', 'm0_outcome': 'business_success'}))


class IntakeEnrichmentTests(unittest.TestCase):
    def test_baseline_intake_counts_m0_sensitive_read(self):
        import json
        import tempfile
        from pathlib import Path

        from minidrifter.classification.api_plane_classifier import build_plane_coverage_stats

        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            path = '/resource/carrctapi/account/getUserInfo/v1'
            (pack / 'api_plane_index.json').write_text(
                json.dumps({
                    'entries': [{
                        'path': path,
                        'api_id': 'op_test',
                        'planes': ['user_profile_personal_info'],
                        'primary_plane': 'user_profile_personal_info',
                        'recommended_campaign_role': 'read_sensitive_state',
                    }],
                    'path_index': {
                        path.lower(): {
                            'path': path,
                            'primary_plane': 'user_profile_personal_info',
                            'recommended_campaign_role': 'read_sensitive_state',
                        },
                    },
                    'plane_summary': {
                        'user_profile_personal_info': {
                            'label': 'User Profile',
                            'detected_count': 1,
                        },
                    },
                }),
                encoding='utf-8',
            )
            (pack / 'baseline_intake_report.json').write_text(
                json.dumps({
                    'captures': [{
                        'path': path,
                        'overall_status': 'acceptable_with_crypto',
                        'response_crypto_processing': {
                            'body_json': {
                                'phone': '166******32',
                                'name': '**天',
                                'idNo': '1***1',
                                'integral': 526,
                            },
                        },
                    }],
                }),
                encoding='utf-8',
            )
            for name in ('chain_batch_report.json', 'risk_probe_report.json', 'sensitive_read_report.json'):
                (pack / name).write_text('{}', encoding='utf-8')

            stats = build_plane_coverage_stats(pack)
            row = stats['plane_coverage']['user_profile_personal_info']
            self.assertEqual(row['sensitive_read_m0_success'], 1)
            self.assertEqual(row['sensitive_read_success'], 1)


class SensitiveReadRunnerTests(unittest.TestCase):
    @unittest.skipUnless(
        __import__('pathlib').Path(__file__).resolve().parents[1].joinpath(
            '../Workspace/神州租车/OUTPUT/api_plane_index.json'
        ).exists(),
        '神州 OUTPUT not present',
    )
    def test_select_getuserinfo_target(self):
        from pathlib import Path
        pack = Path(__file__).resolve().parents[1].parent / 'Workspace' / '神州租车' / 'OUTPUT'
        targets = select_sensitive_read_targets(pack, covered_paths=set(), max_reads=20)
        paths = {t['path'].lower() for t in targets}
        self.assertTrue(
            any('getuserinfo' in p for p in paths)
            or any('personal' in p for p in paths)
            or any('getauthstatus' in p for p in paths),
        )


if __name__ == '__main__':
    unittest.main()
