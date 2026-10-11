# -*- coding: utf-8 -*-
"""Tests for generic P0 quality framework."""
from __future__ import annotations

import unittest

from minidrifter.materials.baseline_importer import merge_baseline_runtime_context
from minidrifter.quality.policies.edge_prune import evaluate_transition
from minidrifter.quality.resolvers.host_pool import resolve_host_pools
from minidrifter.quality.resolvers.url_role import (
    classify_url_role,
    is_third_party_sdk_host,
    is_third_party_sdk_url,
)
from minidrifter.quality.taxonomy import ISSUE_REGISTRY, ISSUE_CLASSES


class QualityFrameworkTests(unittest.TestCase):
    def test_third_party_sdk_detection(self):
        self.assertTrue(is_third_party_sdk_host('api.map.baidu.com'))
        self.assertTrue(is_third_party_sdk_url('https://api.map.baidu.com/place/v2/search'))
        self.assertTrue(is_third_party_sdk_url('/place/v2/search'))
        self.assertFalse(is_third_party_sdk_url('/wechat/applet/order/list.jhtml'))

    def test_url_role_business_relative(self):
        role = classify_url_role('/wechat/applet/order/list.jhtml')
        self.assertEqual(role['url_role'], 'business_relative')
        self.assertTrue(role['is_chain_eligible'])

    def test_url_role_third_party_explicit(self):
        role = classify_url_role('https://api.map.baidu.com/place/v2/search')
        self.assertEqual(role['url_role'], 'third_party_sdk')
        self.assertFalse(role['is_chain_eligible'])

    def test_host_pool_excludes_third_party_as_default(self):
        inv = [
            {'raw_url': 'https://api.map.baidu.com/place/v2/search'},
            {'raw_url': '/wechat/applet/order/list.jhtml'},
            {'raw_url': '/wx/custom/purchased/shop/list/data.jhtml'},
        ]
        pooled = resolve_host_pools(inv, request_wrapper_text='getServerUrl wx.getExtConfigSync')
        self.assertIsNone(pooled['default_business_host'])
        self.assertTrue(pooled['runtime_dynamic_host'])
        self.assertEqual(pooled['host_resolution_strategy'], 'runtime_extconfig_pending')

    def test_host_pool_baseline_override(self):
        inv = [{'raw_url': '/wechat/applet/order/list.jhtml'}]
        pooled = resolve_host_pools(inv, baseline_host='lxnn.tuanshan365.net')
        self.assertEqual(pooled['authoritative_business_host'], 'https://lxnn.tuanshan365.net')

    def test_edge_prune_rejects_third_party_producer(self):
        allowed, code, delta, _ = evaluate_transition(
            from_path='/place/v2/search',
            to_path='/wechat/applet/order/list.jhtml',
            field='orderId',
            from_api={'path': '/place/v2/search', 'domain': 'general'},
            to_api={'path': '/wechat/applet/order/list.jhtml', 'domain': 'order'},
        )
        self.assertFalse(allowed)
        self.assertEqual(code, 'GRAPH_THIRD_PARTY_PRODUCER')

    def test_baseline_merge_accumulates_fields(self):
        existing = {
            'materials_imported': ['mat_a'],
            'resolved_fields': {'customerId': {'value': '1', 'source': 'a'}},
            'field_count': 1,
            'capture_index': [{'material_id': 'mat_a', 'path': '/a.jhtml'}],
        }
        incoming = {
            'generated_at': '2026-01-01T00:00:00Z',
            'materials_imported': ['mat_b'],
            'material_status': {'mat_b': 'parsed'},
            'resolved_fields': {
                'shopId': {'value': '2', 'source': 'b'},
                'customerId': {'value': '1', 'source': 'b'},
            },
            'field_count': 2,
            'capture_index': [{'material_id': 'mat_b', 'path': '/b.jhtml'}],
        }
        merged = merge_baseline_runtime_context(existing, incoming)
        self.assertEqual(merged['materials_imported'], ['mat_a', 'mat_b'])
        self.assertEqual(merged['field_count'], 2)
        self.assertEqual(merged['merge_mode'], 'incremental')

    def test_issue_taxonomy_covers_p0_classes(self):
        classes = {meta['class'] for meta in ISSUE_REGISTRY.values()}
        self.assertIn('HOST_RESOLUTION', classes)
        self.assertIn('GRAPH_SEMANTICS', classes)
        self.assertGreaterEqual(len(ISSUE_CLASSES), 6)

    def test_path_semantic_retail_order(self):
        from minidrifter.quality.semantics.path_tokens import infer_path_semantic
        sem = infer_path_semantic('/wechat/applet/order/list.jhtml')
        self.assertIn('订单', sem['page_label'])
        self.assertIn('order', sem['page_tokens'])


if __name__ == '__main__':
    unittest.main()
