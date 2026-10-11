# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from minidrifter.runtime.crypto.sign_engines import compute_sign, hmac_sha256_base64url
from minidrifter.runtime.crypto.sign_payload_builders import build_relative_path_merge_params
from minidrifter.verification.sensitive_target_enrollment import build_intake_synthetic_template
from minidrifter.verification.subject_override_target_selector import select_subject_override_targets
from minidrifter.verification.template_registry import register_enrollment_templates, resolve_template


class TemplateRegistryTests(unittest.TestCase):
    def test_resolve_by_path_when_api_id_differs(self):
        tpl = {'api_id': 'intake_abc', 'path': '/admin/m/customer/getCustomerInfoWx'}
        index = {'by_id': {'intake_abc': tpl}, 'by_path': {'/admin/m/customer/getcustomerinfowx': tpl}}
        found, tid = resolve_template(index, api_id='op_287ed1f3c6c5', path='/admin/m/customer/getCustomerInfoWx')
        self.assertIsNotNone(found)
        self.assertEqual(tid, 'intake_abc')

    def test_intake_template_uses_plane_api_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            (pack / 'api_plane_index.json').write_text(json.dumps({
                'entries': [{
                    'path': '/admin/m/customer/getCustomerInfoWx',
                    'api_id': 'op_static123',
                }],
            }), encoding='utf-8')
            cap = {'path': '/admin/m/customer/getCustomerInfoWx', 'method': 'GET', 'query': {}}
            tpl = build_intake_synthetic_template(
                cap,
                baseline_context={'transport_style': 'header_hmac_sign'},
                plane_entry={'primary_plane': 'user_profile_personal_info'},
                pack_dir=pack,
            )
            self.assertEqual(tpl['api_id'], 'op_static123')


class HmacSignEngineTests(unittest.TestCase):
    def test_payload_builder_sorted(self):
        payload = build_relative_path_merge_params(
            'admin/m/customer/getCustomerInfoWx',
            query={'openId': 'a', 'id': '1'},
            body={},
        )
        self.assertIn('admin/m/customer/getCustomerInfoWx?', payload)
        self.assertIn('id=1', payload)
        self.assertIn('openId=a', payload)

    def test_hmac_base64url_deterministic(self):
        a = hmac_sha256_base64url('hello', secret='secret')
        b = compute_sign('hello', 'hmac_sha256_base64url', secret='secret')
        self.assertEqual(a, b)
        self.assertNotIn('+', a)
        self.assertNotIn('/', a)
        self.assertNotIn('=', a)


if __name__ == '__main__':
    unittest.main()
