# -*- coding: utf-8 -*-
"""Tests for P4-fix-4.5 sensitive target enrollment."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from minidrifter.classification.api_plane_classifier import classify_path_to_plane_entry
from minidrifter.verification.sensitive_target_enrollment import (
    build_gap_plan_synthetic_template,
    discover_path_inferred_subject_read_paths,
    enroll_gap_plan_sensitive_targets,
    enroll_intake_sensitive_targets,
    enroll_path_inferred_sensitive_targets,
    is_path_inferred_subject_read_target,
)


class SensitiveTargetEnrollmentTests(unittest.TestCase):
    def test_membership_home_classified_as_account_wallet(self):
        entry = classify_path_to_plane_entry('/resource/carrctapi/account/membership/home/v5')
        self.assertEqual(entry['primary_plane'], 'account_state_wallet')
        self.assertEqual(entry['recommended_campaign_role'], 'account_state_probe')

    def test_enroll_membership_from_intake(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            path = '/resource/carrctapi/account/membership/home/v5'
            (pack / 'baseline_intake_report.json').write_text(json.dumps({
                'captures': [{
                    'path': path,
                    'method': 'POST',
                    'overall_status': 'acceptable_with_crypto',
                    'host': 'apiproxy.zuche.com',
                    'crypto_processing': {
                        'can_replay': True,
                        'profile_id': 'token_sign_aes_wrapper',
                        'decrypted': {'body_form': '{}'},
                        'resolved_fields': {'cid': '500553', 'uid': 'u1', 'Host': 'apiproxy.zuche.com'},
                    },
                }],
            }), encoding='utf-8')
            (pack / 'baseline_runtime_context.json').write_text(json.dumps({
                'transport_style': 'form_cid_q_sign',
                'crypto_profile': 'token_sign_aes_wrapper',
            }), encoding='utf-8')
            (pack / 'api_plane_index.json').write_text(json.dumps({
                'entries': [],
                'path_index': {},
                'plane_summary': {},
            }), encoding='utf-8')

            rows = enroll_intake_sensitive_targets(pack, covered_paths=set())
            self.assertEqual(len(rows), 1)
            self.assertTrue(rows[0].get('intake_enrolled'))
            self.assertEqual(rows[0]['primary_plane'], 'account_state_wallet')
            self.assertIn('synthetic_template', rows[0])

    def test_enroll_personaldata_path_inferred(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            path = '/action/carrctapi/account/personalData/get/v2'
            (pack / 'api_plane_index.json').write_text(json.dumps({
                'entries': [{
                    'path': path,
                    'api_id': 'op_f99c627d58bc',
                    'primary_plane': 'user_profile_personal_info',
                    'recommended_campaign_role': 'read_sensitive_state',
                    'sensitivity_score': 0.9,
                }],
                'path_index': {path.lower(): path},
                'plane_summary': {},
            }), encoding='utf-8')
            (pack / 'baseline_runtime_context.json').write_text(json.dumps({
                'transport_style': 'form_cid_q_sign',
                'crypto_profile': 'token_sign_aes_wrapper',
                'resolved_fields': {
                    'memberId': {'value': '19100025'},
                    'MemberId': {'value': '19100025'},
                },
            }), encoding='utf-8')
            (pack / 'materialized_api_templates.json').write_text(json.dumps({
                'templates': [],
            }), encoding='utf-8')
            (pack / 'baseline_intake_report.json').write_text(json.dumps({
                'captures': [],
            }), encoding='utf-8')
            (pack / 'subject_wire_gap_plan.json').write_text(json.dumps({
                'gaps': [],
            }), encoding='utf-8')

            self.assertTrue(is_path_inferred_subject_read_target(path))
            rows = enroll_path_inferred_sensitive_targets(pack, covered_paths=set())
            self.assertEqual(len(rows), 1)
            tpl = rows[0]['synthetic_template']
            self.assertEqual(tpl['method'], 'POST')
            self.assertEqual(tpl['plain_template']['body_params'], {'memberId': '19100025'})
            self.assertEqual(tpl['plain_template']['params'], {})
            self.assertEqual(rows[0]['verification_intent'], 'subject_binding_gap_plan')

    def test_gap_template_personaldata_ignores_replay_context(self):
        entry = classify_path_to_plane_entry('/action/carrctapi/account/personalData/get/v2')
        tpl = build_gap_plan_synthetic_template(
            {
                'path': '/action/carrctapi/account/personalData/get/v2',
                'static_subject_fields': ['memberId'],
            },
            baseline_context={
                'transport_style': 'form_cid_q_sign',
                'crypto_profile': 'token_sign_aes_wrapper',
                'resolved_fields': {'memberId': {'value': '19100025'}},
            },
            plane_entry=entry,
            pack_dir=None,
        )
        self.assertEqual(tpl['plain_template']['body_params'], {'memberId': '19100025'})
        self.assertNotIn('uid', tpl['plain_template']['body_params'])


if __name__ == '__main__':
    unittest.main()
