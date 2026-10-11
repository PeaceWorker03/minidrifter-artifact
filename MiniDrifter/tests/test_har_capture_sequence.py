# -*- coding: utf-8 -*-
"""Tests for HAR sequence ingestion and capture_sequence artifact."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from minidrifter.materials.capture_sequence import (
    build_capture_sequence,
    infer_business_domain,
    infer_stage,
)
from minidrifter.materials.har_sequence import (
    filter_har_entries,
    har_text_to_capture_inputs,
    looks_like_har,
    parse_har_sequence,
)


SAMPLE_HAR = {
    'log': {
        'entries': [
            {
                'startedDateTime': '2026-01-01T10:00:00Z',
                'request': {
                    'method': 'GET',
                    'url': 'https://cdn.example.com/app.js',
                    'headers': [],
                },
                'response': {'status': 200, 'content': {'text': ''}},
            },
            {
                'startedDateTime': '2026-01-01T10:00:01Z',
                'request': {
                    'method': 'POST',
                    'url': 'https://api.example.com/wechat/login',
                    'headers': [{'name': 'Token', 'value': 'abc'}],
                    'postData': {'mimeType': 'application/json', 'text': '{"userId":"1"}'},
                },
                'response': {
                    'status': 200,
                    'content': {'mimeType': 'application/json', 'text': '{"orderId":"99"}'},
                },
            },
            {
                'startedDateTime': '2026-01-01T10:00:02Z',
                'request': {
                    'method': 'POST',
                    'url': 'https://api.example.com/order/detail',
                    'headers': [{'name': 'Authorization', 'value': 'Bearer x'}],
                    'postData': {'mimeType': 'application/json', 'text': '{"orderId":"99"}'},
                },
                'response': {
                    'status': 200,
                    'content': {'mimeType': 'application/json', 'text': '{"payAmount":100}'},
                },
            },
        ],
    },
}


class HarSequenceTests(unittest.TestCase):
    def test_looks_like_har(self):
        self.assertTrue(looks_like_har(json.dumps(SAMPLE_HAR)))
        self.assertFalse(looks_like_har('GET /api/foo HTTP/1.1'))

    def test_filter_static_assets(self):
        entries = SAMPLE_HAR['log']['entries']
        filtered = filter_har_entries(entries)
        self.assertEqual(len(filtered), 2)
        paths = [e['request']['url'] for e in filtered]
        self.assertTrue(any('login' in u for u in paths))
        self.assertTrue(any('order/detail' in u for u in paths))

    def test_parse_har_sequence(self):
        seq = parse_har_sequence(SAMPLE_HAR)
        self.assertEqual(len(seq), 2)
        self.assertEqual(seq[0]['request']['method'], 'POST')
        self.assertEqual(seq[0]['response_body']['orderId'], '99')

    def test_har_text_to_capture_inputs(self):
        inputs = har_text_to_capture_inputs(json.dumps(SAMPLE_HAR))
        self.assertEqual(len(inputs), 2)
        self.assertIn('orderId', inputs[0]['response_body'])


class CaptureSequenceTests(unittest.TestCase):
    def test_infer_stage_and_domain(self):
        self.assertEqual(infer_stage('/wechat/login'), 'login_or_profile')
        self.assertEqual(infer_stage('/order/detail'), 'object_detail')
        self.assertEqual(infer_business_domain('/wallet/balance'), 'payment')

    def test_build_capture_sequence(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            captures = [
                {
                    'capture_index': 1,
                    'method': 'POST',
                    'path': '/wechat/login',
                    'transport_assessment': {'token_present': True},
                    'response_fields': ['userId'],
                    'overall_status': 'acceptable_plaintext',
                },
                {
                    'capture_index': 2,
                    'method': 'POST',
                    'path': '/order/detail',
                    'transport_assessment': {'token_present': True},
                    'response_fields': ['orderId'],
                    'overall_status': 'acceptable_plaintext',
                },
            ]
            doc = build_capture_sequence(pack, captures, source='har')
            self.assertEqual(doc['coverage']['capture_count'], 2)
            self.assertIn('userId', doc['coverage']['produced_fields'])
            self.assertEqual(doc['captures'][0]['stage'], 'login_or_profile')
            self.assertEqual(doc['captures'][1]['stage'], 'object_detail')


if __name__ == '__main__':
    unittest.main()
