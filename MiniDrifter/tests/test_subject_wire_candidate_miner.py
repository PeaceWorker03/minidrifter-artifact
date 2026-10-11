# -*- coding: utf-8 -*-
"""Tests for P4-fix-5.1 subject wire candidate miner."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from minidrifter.classification.subject_wire_candidate_miner import (
    _classify_wire_subject_field,
    _wire_fields_from_capture,
    mine_subject_wire_candidates,
)


class SubjectWireMinerTests(unittest.TestCase):
    def test_wire_fields_from_login_capture(self):
        cap = {
            'capture_index': 1,
            'path': '/action/carrctapi/account/login/v1',
            'crypto_processing': {
                'resolved_fields': {
                    'openId': 'oYjja5NfPr-P15zlLdmiywHmZdKo',
                    'unionId': 'oBRRZwmYrj9--GucwGI_mNEtqwtc',
                    'cid': '801553',
                    'uid': '218ce9b77aa0',
                },
                'decrypted': {
                    'body_form': json.dumps({
                        'openId': 'oYjja5NfPr-P15zlLdmiywHmZdKo',
                        'unionId': 'oBRRZwmYrj9--GucwGI_mNEtqwtc',
                        'loginType': 3,
                    }),
                },
            },
            'response_crypto_processing': {
                'body_json': {'memberId': '191918925', 'name': '**天', 'tel': '166******32'},
            },
        }
        rows = _wire_fields_from_capture(cap)
        fields = {r['field'] for r in rows}
        self.assertIn('openId', fields)
        self.assertIn('unionId', fields)
        self.assertNotIn('memberId', fields)

    def test_wire_fields_from_plaintext_query(self):
        cap = {
            'capture_index': 2,
            'path': '/applet/wechat/customer/personalCore/api/json.jhtml',
            'method': 'GET',
            'crypto_processing': {
                'input_mode': 'plaintext_query',
                'decrypted': {
                    'query': {'customerId': '73052', 'userId': '88', 'signature': 'sig'},
                },
                'resolved_fields': {'customerId': '73052', 'userId': '88'},
            },
        }
        rows = _wire_fields_from_capture(cap)
        fields = {r['field'] for r in rows}
        self.assertIn('customerId', fields)
        self.assertIn('userId', fields)

    def test_classify_login_openid_deferred(self):
        row = _classify_wire_subject_field(
            'openId', 'oYjja5xxx', location='decrypted_body',
            path='/action/carrctapi/account/login/v1',
        )
        self.assertIsNotNone(row)
        self.assertFalse(row['mutation_allowed'])

    def test_classify_member_detail_allowed(self):
        row = _classify_wire_subject_field(
            'memberId', '191918925', location='query',
            path='/resource/carrctapi/member/detail/v1',
        )
        self.assertIsNotNone(row)
        self.assertTrue(row['mutation_allowed'])

    def test_mine_pack_with_login_and_sensitive_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            login_path = '/action/carrctapi/account/login/v1'
            read_path = '/resource/carrctapi/account/getUserInfo/v1'
            (pack / 'baseline_intake_report.json').write_text(json.dumps({
                'captures': [
                    {
                        'capture_index': 1,
                        'path': login_path,
                        'overall_status': 'acceptable_with_crypto',
                        'crypto_processing': {
                            'resolved_fields': {
                                'openId': 'oABC',
                                'unionId': 'oUNI',
                            },
                            'decrypted': {'body_form': json.dumps({'openId': 'oABC', 'unionId': 'oUNI'})},
                        },
                        'response_crypto_processing': {
                            'body_json': {'memberId': '123', 'name': '**天'},
                        },
                    },
                    {
                        'capture_index': 2,
                        'path': read_path,
                        'overall_status': 'acceptable_with_crypto',
                        'crypto_processing': {
                            'resolved_fields': {'cityId': '1', 'bucketIdList': '[]'},
                            'decrypted': {'body_form': json.dumps({'cityId': '1'})},
                        },
                        'response_crypto_processing': {
                            'body_json': {'phone': '166******32', 'name': '**天', 'idNo': '1***1'},
                        },
                    },
                ],
            }), encoding='utf-8')
            (pack / 'api_plane_index.json').write_text(json.dumps({
                'entries': [
                    {
                        'path': login_path,
                        'api_id': 'op_login',
                        'planes': ['credential_session'],
                        'primary_plane': 'credential_session',
                        'recommended_campaign_role': 'bootstrap_auth',
                    },
                    {
                        'path': read_path,
                        'api_id': 'op_gu',
                        'planes': ['user_profile_personal_info'],
                        'primary_plane': 'user_profile_personal_info',
                        'recommended_campaign_role': 'read_sensitive_state',
                    },
                ],
                'path_index': {},
                'plane_summary': {
                    'user_profile_personal_info': {'label': 'User Profile', 'detected_count': 1},
                    'credential_session': {'label': 'Credential', 'detected_count': 1},
                },
            }), encoding='utf-8')
            (pack / 'sensitive_read_report.json').write_text(json.dumps({
                'results': [{
                    'path': read_path,
                    'api_id': 'op_gu',
                    'live_sensitive_read_m0_success': True,
                }],
            }), encoding='utf-8')
            for name in (
                'materialized_api_templates.json', 'sensitive_replay_context.json',
                'binding_coverage_report.json', 'chain_batch_report.json',
            ):
                (pack / name).write_text('{}', encoding='utf-8')
            (pack / 'materialized_api_templates.json').write_text(json.dumps({
                'templates': [
                    {'api_id': 'op_login', 'path': login_path},
                    {'api_id': 'op_gu', 'path': read_path},
                ],
            }), encoding='utf-8')

            doc = mine_subject_wire_candidates(pack, write=True)
            summary = doc['summary']
            self.assertGreaterEqual(summary['candidates_total'], 1)
            paths = {c['path'] for c in doc['candidates']}
            self.assertIn(login_path, paths)
            self.assertNotIn(read_path, paths)
            self.assertGreaterEqual(summary['credential_bound_sensitive_reads'], 1)


if __name__ == '__main__':
    unittest.main()
