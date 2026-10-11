# -*- coding: utf-8 -*-
"""Tests for sensitive binding coverage report."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from minidrifter.verification.reporting.sensitive_binding_coverage import (
    build_sensitive_api_coverage_records,
    summarize_sensitive_api_coverage,
)
from minidrifter.verification.sensitive_api_oracle import analyze_sensitive_response


class SensitiveBindingCoverageTests(unittest.TestCase):
    def test_oracle_address_list_body(self):
        body = {
            'cusAddresses': [{
                'address': '111',
                'name': '11',
                'telephone': '14433527456',
                'city': '北京市',
            }],
        }
        sens = analyze_sensitive_response(
            path='/wechat/applet/address/list.jhtml',
            body=body,
        )
        self.assertTrue(sens.get('has_sensitive'))
        self.assertIn('address', sens.get('sensitive_fields') or [])

    def test_oracle_remain_money_body(self):
        body = {'ret': 1, 'remainMoney': 0.0}
        sens = analyze_sensitive_response(
            path='/wechat/applet/remain/money.jhtml',
            body=body,
        )
        self.assertTrue(sens.get('has_sensitive'))

    def test_coverage_record_personalcore_inconclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            p = '/wechat/applet/user/personalCore.jhtml'
            (pack / 'api_plane_index.json').write_text(json.dumps({
                'entries': [{
                    'path': p,
                    'api_id': 'op_pc',
                    'primary_plane': 'user_profile_personal_info',
                    'recommended_campaign_role': 'read_sensitive_state',
                }],
                'path_index': {p.lower(): {'path': p, 'primary_plane': 'user_profile_personal_info'}},
                'plane_summary': {},
            }), encoding='utf-8')
            (pack / 'sensitive_replay_context.json').write_text(json.dumps({
                'entries': [{
                    'api': p,
                    'capture_path': p,
                    'capture_match_score': 1040,
                    'capture_index': 1,
                    'replay_mode': 'plaintext_direct',
                    'signature_mode': 'reuse_capture_signature',
                    'can_recompute_signature': False,
                    'mutation_policy': 'exact_replay_first',
                    'replay_context': {'http_method': 'GET', 'query': {'userId': '1'}},
                }],
                'by_path': {p.lower(): {
                    'api': p,
                    'capture_path': p,
                    'capture_match_score': 1040,
                    'capture_index': 1,
                    'replay_mode': 'plaintext_direct',
                    'can_recompute_signature': False,
                    'replay_context': {},
                }},
            }), encoding='utf-8')
            (pack / 'subject_wire_candidates.json').write_text(json.dumps({
                'candidates': [{
                    'path': p,
                    'wire_subject_fields': [
                        {'field': 'userId', 'location': 'query_params', 'mutation_allowed': True},
                    ],
                }],
            }), encoding='utf-8')
            (pack / 'sensitive_read_report.json').write_text(json.dumps({
                'results': [{
                    'path': p,
                    'status': 'live_m0_success',
                    'm0_outcome': 'business_success',
                    'live_sensitive_read_m0_success': True,
                    'replay_strategy': 'exact_capture_replay',
                }],
            }), encoding='utf-8')
            (pack / 'subject_override_report.json').write_text(json.dumps({
                'results': [{
                    'path': p,
                    'subject_override_status': 'dry_run_planned_signature_bound',
                    'status': 'dry_run_planned',
                    'subject_override_inconclusive': True,
                    'reason': 'mutation_not_safe_without_signature_recompute',
                }],
            }), encoding='utf-8')
            (pack / 'baseline_intake_report.json').write_text(json.dumps({'captures': []}), encoding='utf-8')
            (pack / 'materialized_api_templates.json').write_text('{"templates": []}', encoding='utf-8')

            records = build_sensitive_api_coverage_records(pack)
            pc_rows = [r for r in records if 'personalcore' in (r.get('static_path') or '').lower()]
            self.assertEqual(len(pc_rows), 1)
            row = pc_rows[0]
            self.assertEqual(row['target_rank'], 'P1')
            self.assertEqual(row['m0_status'], 'live_m0_success')
            self.assertEqual(row['m7_status'], 'signature_bound_skip')
            self.assertEqual(row['security_conclusion'], 'inconclusive')
            self.assertEqual(row['block_reason'], 'mutation_not_safe_without_signature_recompute')

            summary = summarize_sensitive_api_coverage(records)
            self.assertEqual(summary['live_m0_success'], 1)
            self.assertEqual(summary['signature_bound_skip'], 1)


if __name__ == '__main__':
    unittest.main()
