# -*- coding: utf-8 -*-
"""Tests for capture-authoritative pool, envelope wire, and merge overlay."""
from __future__ import annotations

import json
import unittest

from minidrifter.materials.capture_authoritative_pool import resolve_capture_authoritative_pool
from minidrifter.materials.envelope_wire import (
    apply_envelope_preserving_mutation,
    build_counterfactual_wire_body,
)
from minidrifter.materials.form_body_merge import merge_form_body_params
from minidrifter.verification.crypto_parity_preflight import check_crypto_parity_preflight


class MergeOverlayTests(unittest.TestCase):
    def test_capture_locked_still_applies_binding_overlay(self):
        merged = merge_form_body_params(
            {'memberId': '171902050'},
            baseline_context={'resolved_fields': {}},
            intake_report=None,
            path_hint={
                'capture_locked': True,
                'body_params': {'bucketIdList': [1, 2, 3]},
            },
        )
        self.assertEqual(str(merged.get('memberId')), '171902050')
        self.assertEqual(merged.get('bucketIdList'), [1, 2, 3])


class EnvelopeWireTests(unittest.TestCase):
    def test_preserves_bucket_strips_noise(self):
        capture = {
            'memberId': '191918925',
            'bucketIdList': [2621, 3363],
            'cityId': '20',
            'pickupDeptId': '535',
        }
        wire = build_counterfactual_wire_body(
            capture_body=capture,
            binding_field='memberId',
            mutated_value='171902050',
        )
        self.assertEqual(wire['memberId'], '171902050')
        self.assertEqual(wire['bucketIdList'], [2621, 3363])
        self.assertNotIn('cityId', wire)
        self.assertNotIn('pickupDeptId', wire)

    def test_apply_mutation_uses_pool_bucket(self):
        tc = {
            'method': 'POST',
            'body_params': {'memberId': '191918925', 'cityId': '20'},
        }
        replay = {
            'replay_context': {
                'body': {'memberId': '191918925'},
                'pool': {
                    'bucketIdList': json.dumps([10, 20]),
                    'cid': '801553',
                },
            }
        }
        apply_envelope_preserving_mutation(
            tc, field='memberId', mutated_value='171902050', replay_entry=replay,
        )
        self.assertEqual(tc['body_params']['memberId'], '171902050')
        self.assertEqual(tc['body_params']['bucketIdList'], [10, 20])
        self.assertNotIn('cityId', tc['body_params'])


class CapturePoolTests(unittest.TestCase):
    def test_capture_overrides_baseline_cid(self):
        baseline = {'resolved_fields': {'cid': {'value': '500553'}}}
        replay = {'replay_context': {'pool': {'cid': '801553', 'uid': 'u1'}}}
        pool, _meta = resolve_capture_authoritative_pool(
            baseline, replay_entry=replay,
        )
        self.assertEqual(pool['cid'], '801553')


class CryptoPreflightTests(unittest.TestCase):
    def test_detects_missing_binding_in_plaintext(self):
        preview = {
            'build_status': 'ok',
            'query_plain': json.dumps({'bucketIdList': [1, 2]}),
            'body_form': {'cid': '801553', 'q': 'x', 'sign': 'y', 'uid': 'u1'},
        }
        result = check_crypto_parity_preflight(
            preview,
            binding_field='memberId',
            expected_binding_value='171902050',
        )
        self.assertFalse(result['ok'])
        self.assertIn('binding_field_missing_on_wire', result['reasons'])


class HeaderQueryPreflightTests(unittest.TestCase):
    def test_accepts_urlencoded_query_plain(self):
        preview = {
            'build_status': 'ok',
            'transport_style': 'header_query_encrypted',
            'params_resolved': {'userId': '2519481972'},
            'query_plain': 'userId=2519481972',
        }
        result = check_crypto_parity_preflight(
            preview, binding_field='userId', expected_binding_value='2519481972',
        )
        self.assertTrue(result['ok'])


if __name__ == '__main__':
    unittest.main()
