# -*- coding: utf-8 -*-
"""Tests for P4-fix-5.2 subject wire gap planner."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from minidrifter.classification.subject_wire_gap_planner import build_subject_wire_gap_plan


class SubjectWireGapPlannerTests(unittest.TestCase):
    def test_gap_for_static_memberid_not_in_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            identity_path = '/action/carrctapi/account/identitycardinfo/get/v1'
            read_path = '/resource/carrctapi/account/getuserinfo/v1'
            (pack / 'api_plane_index.json').write_text(json.dumps({
                'entries': [
                    {
                        'path': identity_path,
                        'api_id': 'op_id',
                        'planes': ['realname_verification'],
                        'primary_plane': 'realname_verification',
                        'recommended_campaign_role': 'verification_state_probe',
                        'sensitivity_score': 0.95,
                        'side_effect': 'S0_read_only',
                    },
                    {
                        'path': read_path,
                        'api_id': 'op_gu',
                        'planes': ['user_profile_personal_info'],
                        'primary_plane': 'user_profile_personal_info',
                        'recommended_campaign_role': 'read_sensitive_state',
                        'sensitivity_score': 0.9,
                    },
                ],
                'path_index': {
                    identity_path: {
                        'path': identity_path,
                        'primary_plane': 'realname_verification',
                        'planes': ['realname_verification'],
                        'sensitivity_score': 0.95,
                        'side_effect': 'S0_read_only',
                    },
                },
                'plane_summary': {
                    'realname_verification': {'label': 'Real-name', 'detected_count': 1},
                },
            }), encoding='utf-8')
            (pack / 'object_flow_chains.json').write_text(json.dumps({
                'edges': [{
                    'edge_type': 'object_flow',
                    'consumer_api': identity_path,
                    'object_field': 'memberId',
                    'consumer_location': 'params.memberId',
                }],
            }), encoding='utf-8')
            (pack / 'api_cards.json').write_text('[]', encoding='utf-8')
            (pack / 'baseline_intake_report.json').write_text(json.dumps({
                'captures': [{
                    'path': read_path,
                    'overall_status': 'acceptable_with_crypto',
                    'crypto_processing': {'resolved_fields': {'cityId': '1'}},
                }],
            }), encoding='utf-8')
            (pack / 'sensitive_read_report.json').write_text(json.dumps({
                'results': [{
                    'path': read_path,
                    'live_sensitive_read_m0_success': True,
                }],
            }), encoding='utf-8')
            (pack / 'subject_wire_candidates.json').write_text(json.dumps({
                'candidates': [],
                'summary': {'credential_bound_sensitive_reads': 1},
            }), encoding='utf-8')
            for name in (
                'materialized_api_templates.json', 'business_chains.json',
                'binding_coverage_report.json', 'chain_batch_report.json',
            ):
                (pack / name).write_text('{}', encoding='utf-8')

            doc = build_subject_wire_gap_plan(pack, write=True)
            self.assertGreaterEqual(doc['summary']['static_subject_like_sensitive_apis'], 1)
            paths = {g['path'] for g in doc['gaps']}
            self.assertIn(identity_path, paths)
            self.assertNotIn(read_path, paths)


if __name__ == '__main__':
    unittest.main()
