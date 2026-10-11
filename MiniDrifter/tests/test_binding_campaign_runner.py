# -*- coding: utf-8 -*-
"""Tests for mutation eligibility and binding campaign runner."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from minidrifter.verification.binding_campaign_runner import build_final_binding_records
from minidrifter.verification.mutation_eligibility import (
    ELIGIBILITY_MUTATION_ALLOWED,
    ELIGIBILITY_NO_SUBJECT,
    ELIGIBILITY_SIGNATURE_BOUND,
    evaluate_mutation_eligibility,
    security_conclusion_from_m7,
)


class MutationEligibilityTests(unittest.TestCase):
    def test_signature_bound_inconclusive(self):
        row = evaluate_mutation_eligibility(
            api='/wechat/applet/user/personalCore.jhtml',
            mutation_type='subject_override',
            replay_context={
                'replay_mode': 'plaintext_direct',
                'can_recompute_signature': False,
                'query_params': {'signature': 'abc', 'userId': '1'},
            },
            subject_wire_row={
                'wire_subject_fields': [{'field': 'userId', 'mutation_allowed': True}],
            },
            m0_result={'ok': True, 'status': 'live_m0_success'},
        )
        self.assertFalse(row['eligible'])
        self.assertEqual(row['eligibility_status'], ELIGIBILITY_SIGNATURE_BOUND)
        self.assertEqual(row['security_conclusion'], 'inconclusive')
        self.assertEqual(row['reason'], 'signature_not_recomputable')

    def test_mutation_allowed_without_signature(self):
        row = evaluate_mutation_eligibility(
            api='/resource/account/get/v1',
            mutation_type='subject_override',
            replay_context={'can_recompute_signature': False, 'query_params': {'userId': '1'}},
            subject_wire_row={
                'wire_subject_fields': [{'field': 'userId', 'mutation_allowed': True}],
            },
            m0_result={'ok': True},
        )
        self.assertTrue(row['eligible'])
        self.assertEqual(row['eligibility_status'], ELIGIBILITY_MUTATION_ALLOWED)

    def test_no_subject_candidate(self):
        row = evaluate_mutation_eligibility(
            api='/wallet/balance',
            mutation_type='subject_override',
            replay_context={},
            m0_result={'ok': True},
        )
        self.assertEqual(row['eligibility_status'], ELIGIBILITY_NO_SUBJECT)

    def test_m7_drift_conclusion(self):
        elig = {'security_conclusion': 'not_tested', 'eligibility_status': ELIGIBILITY_MUTATION_ALLOWED}
        con = security_conclusion_from_m7(
            eligibility=elig,
            m7_status='executed',
            oracle_result='cross_subject_sensitive_success',
        )
        self.assertEqual(con, 'drift')


class BindingCampaignRunnerTests(unittest.TestCase):
    def test_build_final_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            p1 = '/wechat/applet/user/personalCore.jhtml'
            (pack / 'api_plane_index.json').write_text(json.dumps({
                'entries': [{'path': p1, 'primary_plane': 'user_profile_personal_info',
                             'recommended_campaign_role': 'read_sensitive_state'}],
                'path_index': {}, 'plane_summary': {},
            }), encoding='utf-8')
            (pack / 'baseline_intake_report.json').write_text(json.dumps({
                'captures': [{
                    'capture_index': 1,
                    'method': 'GET',
                    'path': p1,
                    'overall_status': 'acceptable_plaintext',
                    'transport_assessment': {'transport_mode': 'plaintext_only', 'plaintext_usable': True},
                    'crypto_processing': {
                        'input_mode': 'plaintext_query',
                        'decrypted': {'query': {
                            'userId': '1', 'nonce': 'n', 'timestamp': 't', 'signature': 'sig',
                        }},
                    },
                }],
            }), encoding='utf-8')
            (pack / 'sensitive_replay_context.json').write_text(json.dumps({
                'entries': [{
                    'api': p1,
                    'replay_context': {
                        'replay_mode': 'plaintext_direct',
                        'can_recompute_signature': False,
                        'query_params': {'userId': '1', 'signature': 'sig'},
                    },
                }],
                'by_path': {},
            }), encoding='utf-8')
            (pack / 'subject_wire_candidates.json').write_text(json.dumps({
                'candidates': [{
                    'path': p1,
                    'wire_subject_fields': [{'field': 'userId', 'mutation_allowed': True}],
                }],
            }), encoding='utf-8')
            (pack / 'object_wire_candidates.json').write_text('{"candidates": []}', encoding='utf-8')
            (pack / 'sensitive_read_report.json').write_text(json.dumps({
                'results': [{'path': p1, 'ok': True, 'status': 'live_m0_success'}],
            }), encoding='utf-8')
            (pack / 'signature_profile.json').write_text(json.dumps({
                'can_recompute_signature': False,
                'signature_profile_id': 'method_path_sorted_brace_salt_md5',
                'reason': 'runtime_secret_unresolved',
            }), encoding='utf-8')
            (pack / 'materialized_api_templates.json').write_text('{"templates": []}', encoding='utf-8')

            records = build_final_binding_records(pack)
            by_api = {r['api']: r for r in records}
            self.assertIn(p1, by_api)
            row = by_api[p1]
            self.assertEqual(row['mutation_eligibility'], ELIGIBILITY_SIGNATURE_BOUND)
            self.assertEqual(row['security_conclusion'], 'inconclusive')
            self.assertIn('userId', row['subject_candidates'])


if __name__ == '__main__':
    unittest.main()
