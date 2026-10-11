# -*- coding: utf-8 -*-
"""Tests for API plane classifier (P4)."""
from __future__ import annotations

import unittest
from pathlib import Path

from minidrifter.classification.api_plane_classifier import (
    classify_api_card,
    load_sensitive_field_ontology,
    plane_sensitivity_for_path,
)

ROOT = Path(__file__).resolve().parents[1]
SHENZHOU = ROOT.parent / 'Workspace' / '神州租车' / 'OUTPUT'


def _card(path: str, *, method: str = 'GET', params=None, side: str = 'S0_read_only') -> dict:
    return {
        'card_id': 'op_test',
        'static': {
            'endpoint': {'path': path},
            'http': {'method': method},
        },
        'bindings': {'params': [{'name': p} for p in (params or [])]},
        'replay': {'side_effect': {'category': side}},
    }


class ApiPlaneClassifierTests(unittest.TestCase):
    def test_ontology_loads(self):
        ont = load_sensitive_field_ontology()
        self.assertIn('planes', ont)
        self.assertIn('user_profile_personal_info', ont['planes'])

    def test_member_identity_plane(self):
        row = classify_api_card(_card('/resource/carrctapi/student/memberIdentityInfo/v1'))
        self.assertIn('realname_verification', row['planes'])

    def test_deposit_wallet_plane(self):
        row = classify_api_card(_card('/resource/carrctapi/account/depositInfo/v1'))
        planes = row['planes']
        self.assertTrue(
            'account_state_wallet' in planes or 'user_profile_personal_info' in planes,
        )

    def test_environment_plane(self):
        row = classify_api_card(_card('/action/carrctapi/order/cityList/v1'))
        self.assertIn('environment_public', row['planes'])

    def test_order_business_object(self):
        row = classify_api_card(_card('/resource/carrctapi/order/orderDetail/v10', params=['orderId']))
        self.assertIn('business_object', row['planes'])

    def test_plane_sensitivity_path_helper(self):
        sens, planes = plane_sensitivity_for_path('/resource/carrctapi/account/depositInfo/v1')
        self.assertGreaterEqual(sens, 0.5)
        self.assertTrue(planes)

    @unittest.skipUnless(SHENZHOU.exists(), '神州 OUTPUT not present')
    def test_build_index_on_shenzhou(self):
        from minidrifter.classification.api_plane_classifier import build_api_plane_index
        doc = build_api_plane_index(SHENZHOU)
        self.assertGreater(doc.get('api_count', 0), 50)
        summary = doc.get('plane_summary') or {}
        self.assertGreater(summary.get('business_object', {}).get('detected_count', 0), 0)


if __name__ == '__main__':
    unittest.main()
