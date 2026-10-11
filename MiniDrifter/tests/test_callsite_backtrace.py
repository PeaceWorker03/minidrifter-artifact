# -*- coding: utf-8 -*-
"""Tests for P3 obfuscation-tolerant callsite backtrace."""
from __future__ import annotations

import unittest

from minidrifter.quality.semantics.callsite_backtrace import (
    extract_callsite_signals,
    is_obfuscated_callsite_source,
    page_id_from_file_path,
    url_matches_api,
)


class CallsiteBacktraceTests(unittest.TestCase):
    def test_obfuscated_source_detection(self):
        self.assertTrue(is_obfuscated_callsite_source({
            'file': 'package/order/sub-common/67956398d58307823ab6de5980ffa340.js',
            'line': 1,
        }))
        self.assertFalse(is_obfuscated_callsite_source({
            'file': 'package/common/pages/cityList/index.js',
            'line': 10,
        }))

    def test_extract_chunk_signals(self):
        call = {
            'url_expr': 'push([[74149], { api: "/action/carrctapi/order/deptList/v1" }])',
            'source': {'file': 'package/order/sub-common/abc123def456789012345678901234.js', 'snippet': 'push'},
        }
        sig = extract_callsite_signals(call)
        self.assertTrue(sig['obfuscated'])
        self.assertEqual(sig['chunk_id'], '74149')
        self.assertEqual(sig['sub_common_hash'], 'abc123def456789012345678901234')

    def test_page_id_from_paths(self):
        self.assertEqual(
            page_id_from_file_path('package/common/pages/cityList/index.js'),
            'package/common/pages/cityList/index',
        )
        self.assertIsNone(page_id_from_file_path('vendors.js'))

    def test_url_matches_api(self):
        self.assertTrue(url_matches_api(
            '/action/carrctapi/order/deptList/v1',
            '/action/carrctapi/order/deptList/v1',
            {'deptlist', 'order'},
        ))


if __name__ == '__main__':
    unittest.main()
