# -*- coding: utf-8 -*-
"""Tests for P4-fix-4 sensitive replay context builder."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.verification.sensitive_replay_context_builder import (
    build_sensitive_replay_context,
    score_capture_match,
    select_best_matching_capture,
)


class SensitiveReplayContextBuilderTests(unittest.TestCase):
    def test_exact_path_capture_wins(self):
        api_path = '/resource/carrctapi/account/getUserInfo/v1'
        entry = {'primary_plane': 'user_profile_personal_info', 'recommended_campaign_role': 'read_sensitive_state'}
        captures = [
            {
                'path': '/resource/carrctapi/other/v1',
                'overall_status': 'acceptable_with_crypto',
                'crypto_processing': {'can_replay': True, 'sign_check': True},
            },
            {
                'path': api_path,
                'overall_status': 'acceptable_with_crypto',
                'host': 'apiproxy.zuche.com',
                'crypto_processing': {
                    'can_replay': True,
                    'sign_check': True,
                    'profile_id': 'token_sign_aes_wrapper',
                    'decrypted': {'body_form': '{}'},
                    'resolved_fields': {'cid': '801553', 'Host': 'apiproxy.zuche.com'},
                },
                'response_crypto_processing': {'body_json': {'phone': '166******32'}},
            },
        ]
        best, score = select_best_matching_capture(api_path, entry, captures)
        self.assertEqual(best['path'], api_path)
        self.assertGreater(score, 1000)

    def test_domain_fallback_cannot_beat_exact_path(self):
        target = '/applet/wechat/customer/personalCore/api/json.jhtml'
        other = '/applet/wechat/shop/submit/api/json.jhtml'
        entry = {'primary_plane': 'user_profile_personal_info'}
        captures = [
            {
                'path': other,
                'overall_status': 'acceptable_plaintext',
                'host': 'lxnn.tuanshan365.net',
                'crypto_processing': {
                    'input_mode': 'plaintext_form',
                    'decrypted': {'body_form': json.dumps({'shopId': '130'})},
                    'resolved_fields': {'shopId': '130', 'signature': 'abc'},
                },
            },
            {
                'path': target,
                'overall_status': 'acceptable_plaintext',
                'host': 'lxnn.tuanshan365.net',
                'method': 'GET',
                'crypto_processing': {
                    'input_mode': 'plaintext_query',
                    'decrypted': {'query': {'customerId': '73052', 'userId': '99'}},
                    'resolved_fields': {'customerId': '73052', 'userId': '99'},
                },
            },
        ]
        best, _ = select_best_matching_capture(target, entry, captures)
        self.assertEqual(normalize_api_path(best['path']), normalize_api_path(target))

    def test_plaintext_direct_context_populates_query(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            path = '/applet/wechat/customer/personalCore/api/json.jhtml'
            (pack / 'api_plane_index.json').write_text(json.dumps({
                'entries': [{
                    'path': path,
                    'api_id': 'lx_personal',
                    'primary_plane': 'user_profile_personal_info',
                    'recommended_campaign_role': 'read_sensitive_state',
                    'planes': ['user_profile_personal_info'],
                }],
                'path_index': {
                    path.lower(): {
                        'path': path,
                        'api_id': 'lx_personal',
                        'primary_plane': 'user_profile_personal_info',
                        'recommended_campaign_role': 'read_sensitive_state',
                    },
                },
                'plane_summary': {},
            }), encoding='utf-8')
            (pack / 'baseline_intake_report.json').write_text(json.dumps({
                'captures': [{
                    'path': path,
                    'method': 'GET',
                    'overall_status': 'acceptable_plaintext',
                    'host': 'lxnn.tuanshan365.net',
                    'transport_assessment': {'transport_mode': 'plaintext_only', 'plaintext_usable': True},
                    'crypto_processing': {
                        'input_mode': 'plaintext_query',
                        'decrypted': {
                            'query': {
                                'customerId': '73052',
                                'userId': '99',
                                'apiToken': 'tok',
                                'signature': 'sig',
                            },
                        },
                        'resolved_fields': {
                            'customerId': '73052',
                            'userId': '99',
                            'apiToken': 'tok',
                            'signature': 'sig',
                        },
                    },
                }],
            }), encoding='utf-8')
            (pack / 'baseline_runtime_context.json').write_text(json.dumps({
                'resolved_fields': {'Host': {'value': 'lxnn.tuanshan365.net'}},
                'replay_mode': 'plaintext_direct',
            }), encoding='utf-8')
            (pack / 'aggregate_materials.json').write_text('{}', encoding='utf-8')
            (pack / 'chain_object_pool.json').write_text('{}', encoding='utf-8')
            (pack / 'materialized_api_templates.json').write_text(json.dumps({
                'templates': [{
                    'api_id': 'lx_personal',
                    'path': path,
                    'plain_template': {'method': 'GET', 'params': {}},
                    'http_template': {'headers': {}},
                }],
            }), encoding='utf-8')

            doc = build_sensitive_replay_context(pack)
            entry = doc['entries'][0]
            self.assertEqual(entry['replay_mode'], 'plaintext_direct')
            self.assertEqual(entry['replay_context']['query'].get('customerId'), '73052')
            self.assertEqual(entry['replay_context']['http_method'], 'GET')
            self.assertFalse(entry['can_recompute_signature'])

    def test_build_context_doc(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            path = '/resource/carrctapi/account/getUserInfo/v1'
            (pack / 'api_plane_index.json').write_text(json.dumps({
                'entries': [{
                    'path': path,
                    'api_id': 'op_test',
                    'primary_plane': 'user_profile_personal_info',
                    'recommended_campaign_role': 'read_sensitive_state',
                    'planes': ['user_profile_personal_info'],
                }],
                'path_index': {
                    path.lower(): {
                        'path': path,
                        'api_id': 'op_test',
                        'primary_plane': 'user_profile_personal_info',
                        'recommended_campaign_role': 'read_sensitive_state',
                    },
                },
                'plane_summary': {},
            }), encoding='utf-8')
            (pack / 'baseline_intake_report.json').write_text(json.dumps({
                'captures': [{
                    'path': path,
                    'overall_status': 'acceptable_with_crypto',
                    'host': 'apiproxy.zuche.com',
                    'crypto_processing': {
                        'can_replay': True,
                        'sign_check': True,
                        'profile_id': 'token_sign_aes_wrapper',
                        'decrypted': {'body_form': '{}'},
                        'resolved_fields': {'cid': '801553', 'uid': 'u1', 'Host': 'apiproxy.zuche.com'},
                    },
                }],
            }), encoding='utf-8')
            (pack / 'baseline_runtime_context.json').write_text(json.dumps({
                'resolved_fields': {'Host': {'value': 'apiproxy.zuche.com'}},
                'transport_style': 'form_cid_q_sign',
                'crypto_profile': 'token_sign_aes_wrapper',
            }), encoding='utf-8')
            (pack / 'aggregate_materials.json').write_text('{"fields": {"cityId": "17"}}', encoding='utf-8')
            (pack / 'chain_object_pool.json').write_text('{}', encoding='utf-8')
            (pack / 'materialized_api_templates.json').write_text(json.dumps({
                'templates': [{
                    'api_id': 'op_test',
                    'path': path,
                    'plain_template': {'method': 'POST', 'body_params': {}},
                    'crypto_profile': {'profile_id': 'token_sign_aes_wrapper', 'available': True},
                    'http_template': {'headers': {'appletEncrypt': 'appletEncrypt'}},
                }],
            }), encoding='utf-8')

            doc = build_sensitive_replay_context(pack)
            self.assertEqual(doc['api_count'], 1)
            entry = doc['entries'][0]
            self.assertEqual(entry['api'], path)
            self.assertEqual(entry['replay_context']['pool'].get('cid'), '801553')
            self.assertIn('cityId', entry['replay_context']['environment_fields'])


if __name__ == '__main__':
    unittest.main()
