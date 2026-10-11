# -*- coding: utf-8 -*-
"""Unit tests for generic coverage campaigns (v1.3)."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from minidrifter.runtime_trace.generic_coverage_campaigns import (
    PARTNER_PATH_RE,
    WALLET_PATH_RE,
    ZERO_AUTH_WRITE_PATH_RE,
    build_coverage_families,
    m0_ladder_eligible,
    select_generic_coverage_campaigns,
    select_order_lookup_targets,
    select_partner_tenant_targets,
    select_phone_enum_targets,
    select_plane_seed_targets,
    select_store_file_export_targets,
    select_wallet_by_userid_targets,
    select_zero_auth_write_targets,
    strip_auth_from_test_case,
    synthetic_phone_donors,
)
from minidrifter.runtime_trace.single_subject_probe import (
    HIGH_VALUE_PATH_RE,
    SENSITIVE_RE,
    WRITE_PATH_RE,
    _scan_sensitive_leak,
    adjudicate_pair,
    build_response_evidence,
)


def _har_doc(entries):
    return {
        'log': {
            'version': '1.2',
            'entries': entries,
        }
    }


def _entry(url, method='GET', query=None, headers=None, status=200, body=''):
    q = query or []
    return {
        'request': {
            'method': method,
            'url': url,
            'headers': [{'name': k, 'value': v} for k, v in (headers or {}).items()],
            'queryString': [{'name': k, 'value': str(v)} for k, v in q],
            'postData': {},
        },
        'response': {
            'status': status,
            'headers': [],
            'content': {'text': body, 'mimeType': 'application/json'},
        },
    }


class PathRegexTests(unittest.TestCase):
    def test_high_value_covers_vuln_families(self):
        samples = [
            '/demeter/api/h5/store/stock/partner-info',
            '/api/v1/Zhiyunorder/offConsultation',
            '/wallet/getBalance',
            '/order/findByOrderCode',
            '/cinema/retailStoreInfo/getCinemaRetailStoreInfoList',
            '/admin/m/customer/transactions',
            '/user/getUserInfoByUid',
        ]
        for p in samples:
            self.assertTrue(SENSITIVE_RE.search(p) or HIGH_VALUE_PATH_RE.search(p), p)

    def test_write_path_covers_consultation(self):
        self.assertTrue(WRITE_PATH_RE.search('/api/v1/Zhiyunorder/offConsultation'))
        self.assertTrue(ZERO_AUTH_WRITE_PATH_RE.search('/api/imagetex/message/add_patient'))


class LeakOracleTests(unittest.TestCase):
    def test_schema_and_private_ip(self):
        payload = {
            'error': "SQLSTATE[42S22]: Fatal error: Unknown column 'foo' in 'field list'",
            'vpn': '10.1.2.3',
            'licenseUrl': 'https://cdn.example.com/license/abc.pdf',
            'balance': 12.5,
        }
        leak = _scan_sensitive_leak(payload)
        self.assertTrue(leak['has_schema_leak'])
        self.assertTrue(leak['has_private_ip'])
        self.assertTrue(leak['has_license_url'])
        self.assertTrue(leak['has_balance'])

    def test_adjudicate_schema_leak(self):
        a0 = {'call_outcome': 'business_success', 'produced_fields': [], 'security_signals': []}
        a5 = {'call_outcome': 'business_success', 'produced_fields': ['err'], 'security_signals': []}
        evidence = {
            'response_delta': True,
            'donor_reflected': False,
            'strong_leak': True,
            'schema_leak_hit': True,
            'invoice_content_hit': False,
            'cred_pii_hit': False,
            'store_infra_hit': False,
            'leak_m5': {'has_schema_leak': True, 'has_pii': False, 'has_invoice_content': False},
            'leak_diff': {},
            'evidence_ok': True,
        }
        v = adjudicate_pair(
            m0={'path': '/x', 'headers': {}},
            m5={'path': '/x', 'headers': {}},
            a0=a0, a5=a5,
            donor_class='synthetic', field='id', primary='1', donor='2',
            evidence=evidence,
        )
        self.assertEqual(v['label'], 'LikelyCRBD-DataLeak')
        self.assertTrue(v['positive'])


class CampaignSelectTests(unittest.TestCase):
    def test_synthetic_phones(self):
        donors = synthetic_phone_donors('13800138000')
        self.assertTrue(donors)
        self.assertNotIn('13800138000', donors)
        self.assertTrue(all(d.startswith('1') and len(d) == 11 for d in donors))

    def test_select_from_har_families(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            har = pack / 'a.har'
            entries = [
                _entry(
                    'https://api.example.com/demeter/api/h5/store/stock/partner-info',
                    query=[('partnerId', '10'), ('storeId', '1')],
                    headers={'Authorization': 'Bearer t', 'Cookie': 's=1'},
                ),
                _entry(
                    'https://api.example.com/wallet/getBalance',
                    query=[('userid', '100')],
                ),
                _entry(
                    'https://api.example.com/order/findByOrderCode',
                    query=[('orderCode', 'ORD1')],
                ),
                _entry(
                    'https://api.example.com/user/lookupByPhone',
                    query=[('phoneNo', '13800138000')],
                ),
                _entry(
                    'https://api.example.com/cinema/retailStoreInfo/getCinemaRetailStoreInfoList',
                    query=[('storeId', '5')],
                ),
                _entry(
                    'https://api.example.com/api/v1/Zhiyunorder/offConsultation',
                    query=[('consultationId', '9')],
                ),
            ]
            har.write_text(json.dumps(_har_doc(entries)), encoding='utf-8')
            multiset = {
                'partnerId': ['10', '11'],
                'userid': ['100', '101'],
                'orderCode': ['ORD1', 'ORD2'],
                'phoneNo': ['13800138000'],
                'storeId': ['5'],
                'consultationId': ['9'],
            }
            rows = select_generic_coverage_campaigns(
                crypto=None, pack=pack, har_path=har, multiset=multiset, max_targets=20,
            )
            camps = {r['campaign'] for r in rows}
            self.assertIn('partner_tenant_read', camps)
            self.assertIn('wallet_by_userid', camps)
            self.assertIn('order_lookup', camps)
            self.assertIn('phone_enum', camps)
            self.assertIn('store_file_export', camps)
            self.assertIn('zero_auth_write', camps)

    def test_plane_seed_missing_har_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            har = pack / 'a.har'
            har.write_text(json.dumps(_har_doc([
                _entry(
                    'https://api.example.com/api/v1/user/profile?x=1',
                    query=[('x', '1')],
                    headers={'token': 'abc'},
                ),
            ])), encoding='utf-8')
            (pack / 'api_plane_index.json').write_text(json.dumps({
                'entries': [{
                    'path': '/wallet/getBalance',
                    'method': 'GET',
                    'primary_plane': 'account_state_wallet',
                    'sensitivity_score': 0.95,
                }],
                'path_index': {
                    '/wallet/getbalance': {
                        'path': '/wallet/getBalance',
                        'method': 'GET',
                        'primary_plane': 'account_state_wallet',
                        'sensitivity_score': 0.95,
                    }
                },
            }), encoding='utf-8')
            rows = select_plane_seed_targets(pack, har, multiset={'userid': ['1']}, max_targets=5)
            self.assertTrue(rows)
            self.assertEqual(rows[0]['campaign'], 'wallet_by_userid')
            self.assertTrue(rows[0]['item'].get('synthetic'))

    def test_strip_auth(self):
        tc = {
            'headers': {'Authorization': 'Bearer x', 'X-Token': 't', 'Accept': 'json'},
            'params': {'token': 'abc', 'id': '1'},
            'body_params': {},
        }
        out = strip_auth_from_test_case(tc)
        self.assertNotIn('Authorization', out['headers'])
        self.assertEqual(out['params'].get('token'), '')
        self.assertEqual(out['params'].get('id'), '1')
        self.assertTrue(m0_ladder_eligible({'campaign': 'phone_enum', 'path': '/x'}))


class CoverageFamilyTests(unittest.TestCase):
    def test_build_coverage_families(self):
        targets = [
            {'path': '/wallet/getBalance', 'campaign': 'wallet_by_userid'},
            {'path': '/order/findByOrderCode', 'campaign': 'order_lookup'},
        ]
        results = [
            {
                'path': '/wallet/getBalance',
                'campaign': 'wallet_by_userid',
                'status': 'ok',
                'positive': True,
                'label': 'LikelyCRBD-Candidate',
            },
            {
                'path': '/order/findByOrderCode',
                'campaign': 'order_lookup',
                'status': 'm0_failed',
                'positive': False,
            },
            {
                'path': '/api/err',
                'status': 'ok',
                'positive': True,
                'label': 'LikelyCRBD-DataLeak',
                'schema_leak_hit': True,
                'leak_summary': {'m5_schema': True},
            },
        ]
        fam = build_coverage_families(targets, results)
        self.assertEqual(fam['wallet_by_userid']['status'], 'hit')
        self.assertEqual(fam['order_lookup']['status'], 'blocked_m0')
        self.assertEqual(fam['schema_error_leak']['status'], 'hit')


class HarReplayCapabilityTests(unittest.TestCase):
    def test_keeps_content_type_and_coerces_json_int(self):
        from minidrifter.runtime_trace.single_subject_probe import har_item_to_test_case

        item = {
            'request': {
                'method': 'POST',
                'url': 'https://api.example.com/demeter/api/h5/store/stock/partner-info?stockId=43',
                'path': '/demeter/api/h5/store/stock/partner-info',
                'query': {'stockId': '43'},
                'headers': {
                    'content-type': 'application/json;charset=UTF-8',
                    'token': '',
                    'user-agent': 'ua',
                },
                'body_json': {'stockId': 43},
                'body_form': {},
            }
        }
        m0 = har_item_to_test_case(item, index=1)
        self.assertIn('content-type', {k.lower() for k in m0['headers']})
        m5 = har_item_to_test_case(item, index=2, mutation={'stockId': '40'})
        self.assertEqual(m5['body_params']['stockId'], 40)
        self.assertIsInstance(m5['body_params']['stockId'], int)

    def test_success_status_oracle(self):
        from minidrifter.verification.response_oracle import _business_status

        self.assertEqual(
            _business_status({'status': 'SUCCESS', 'content': {'userPhone': '13800138000'}}, {}),
            'business_success',
        )
        self.assertEqual(
            _business_status({'success': True, 'data': {}}, {}),
            'business_success',
        )

    def test_partner_pii_upgrades_to_dataleak(self):
        a0 = {'call_outcome': 'business_success', 'produced_fields': [], 'security_signals': []}
        a5 = {'call_outcome': 'business_success', 'produced_fields': ['userPhone'], 'security_signals': []}
        evidence = {
            'response_delta': True,
            'donor_reflected': True,
            'strong_leak': True,
            'partner_pii_hit': True,
            'invoice_content_hit': False,
            'cred_pii_hit': False,
            'schema_leak_hit': False,
            'store_infra_hit': False,
            'phone_enum_hit': False,
            'leak_m5': {'has_pii': True, 'phones': ['13831415343'], 'has_invoice_content': False},
            'leak_diff': {'new_phones': ['13831415343']},
            'evidence_ok': True,
        }
        v = adjudicate_pair(
            m0={'path': '/demeter/api/h5/store/stock/partner-info', 'headers': {}},
            m5={'path': '/demeter/api/h5/store/stock/partner-info', 'headers': {}},
            a0=a0, a5=a5,
            donor_class='synthetic', field='stockId', primary='43', donor='40',
            evidence=evidence,
        )
        self.assertEqual(v['label'], 'LikelyCRBD-DataLeak')
        self.assertTrue(v['positive'])


class OAuthCcCapabilityTests(unittest.TestCase):
    def test_discover_basic_from_js(self):
        from minidrifter.runtime_trace.oauth_client_material import (
            discover_basic_from_source,
            discover_oauth_client_material,
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            js = root / 'util'
            js.mkdir()
            (js / 'api.js').write_text(
                'h.Authorization = "Basic Y3VzdG9tZXJfd3hfd2lkZ2V0OmJydXRzX3dpZGdldA==";\n'
                'grant_type: "client_credentials"\n',
                encoding='utf-8',
            )
            hits = discover_basic_from_source(root)
            self.assertTrue(hits)
            self.assertEqual(hits[0]['client_id'], 'customer_wx_widget')
            pack = root / 'OUTPUT'
            pack.mkdir()
            har = pack / 'a.har'
            har.write_text(json.dumps(_har_doc([
                _entry(
                    'https://api.example.com/auth/oauth/token',
                    method='POST',
                    headers={
                        'Authorization': 'Basic Y3VzdG9tZXJfd3hfd2lkZ2V0OmJydXRzX3dpZGdldA==',
                    },
                ),
                _entry(
                    'https://api.example.com/card/cinemacardinfo/cardAmountFlowRecordPage',
                    method='POST',
                    headers={'Authorization': 'Bearer u'},
                ),
            ])), encoding='utf-8')
            mat = discover_oauth_client_material(
                project_dir=root, pack=pack, har_path=har,
            )
            self.assertTrue(mat['ok'])
            self.assertTrue(mat['token_urls'])

    def test_select_oauth_cc_targets(self):
        from minidrifter.runtime_trace.generic_coverage_campaigns import (
            select_generic_coverage_campaigns,
            select_oauth_cc_targets,
            OAUTH_CC_LEAK_PATH_RE,
        )
        self.assertTrue(OAUTH_CC_LEAK_PATH_RE.search(
            '/card/cinemacardinfo/cardAmountFlowRecordPage'
        ))
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            har = pack / 'a.har'
            entries = [
                _entry(
                    'https://api.example.com/auth/oauth/token',
                    method='POST',
                    headers={
                        'Authorization': 'Basic Y3VzdG9tZXJfd3hfd2lkZ2V0OmJydXRzX3dpZGdldA==',
                    },
                ),
                _entry(
                    'https://api.example.com/card/cinemacardinfo/getDefaultCardInfo',
                    query=[('customerId', '100')],
                    headers={'Authorization': 'Bearer t'},
                ),
                _entry(
                    'https://api.example.com/card/intentionletter/page',
                    method='POST',
                    headers={'Authorization': 'Bearer t'},
                ),
            ]
            har.write_text(json.dumps(_har_doc(entries)), encoding='utf-8')
            multiset = {'customerId': ['100', '101']}
            from minidrifter.runtime_trace.generic_coverage_campaigns import (
                _har_host_templates, _paths_from_sources,
            )
            paths = _paths_from_sources(None, har, {})
            host_templates = _har_host_templates(har)
            rows = select_oauth_cc_targets(paths, multiset, host_templates, max_targets=8)
            self.assertTrue(rows)
            self.assertTrue(all(r['campaign'] == 'oauth_cc_probe' for r in rows))
            self.assertTrue(all(r.get('attach_cc_bearer') for r in rows))
            mat = {'ok': True, 'basic_b64': 'x', 'token_urls': ['https://api.example.com/auth/oauth/token']}
            merged = select_generic_coverage_campaigns(
                crypto=None, pack=pack, har_path=har, multiset=multiset,
                max_targets=20, oauth_material=mat,
            )
            camps = {r['campaign'] for r in merged}
            self.assertIn('oauth_cc_probe', camps)

    def test_oauth_cc_dump_adjudicates_dataleak(self):
        a0 = {'call_outcome': 'business_success', 'produced_fields': [], 'security_signals': []}
        a5 = {'call_outcome': 'business_success', 'produced_fields': [], 'security_signals': []}
        evidence = {
            'campaign': 'oauth_cc_probe',
            'response_delta': False,
            'donor_reflected': False,
            'strong_leak': True,
            'partner_pii_hit': False,
            'invoice_content_hit': False,
            'cred_pii_hit': True,
            'schema_leak_hit': False,
            'store_infra_hit': False,
            'phone_enum_hit': False,
            'leak_m0': {'has_pii': True, 'phones': ['13800138000'], 'has_cred_pii': True},
            'leak_m5': {'has_pii': True, 'phones': ['13800138000'], 'has_cred_pii': True},
            'leak_diff': {},
            'evidence_ok': True,
        }
        v = adjudicate_pair(
            m0={'path': '/card/cinemacardinfo/cardAmountFlowRecordPage', 'headers': {}},
            m5={'path': '/card/cinemacardinfo/cardAmountFlowRecordPage', 'headers': {}},
            a0=a0, a5=a5,
            donor_class='synthetic', field='customerId', primary='1', donor='2',
            evidence=evidence,
        )
        self.assertEqual(v['label'], 'LikelyCRBD-DataLeak')
        self.assertTrue(v['positive'])

    def test_apply_cc_bearer(self):
        from minidrifter.runtime_trace.oauth_client_material import apply_cc_bearer
        tc = apply_cc_bearer(
            {'headers': {'Authorization': 'Bearer user', 'Cookie': 'a=1'}, 'path': '/x'},
            'cc-token-1',
            channel='3',
        )
        self.assertEqual(tc['headers']['Authorization'], 'Bearer cc-token-1')
        self.assertNotIn('Cookie', tc['headers'])
        self.assertEqual(tc['headers']['Channel'], '3')


if __name__ == '__main__':
    unittest.main()
