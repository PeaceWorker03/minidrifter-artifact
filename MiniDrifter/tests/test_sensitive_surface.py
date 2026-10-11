# -*- coding: utf-8 -*-
"""Tests for generic PII/sensitive surface classification."""
from __future__ import annotations

import unittest

from minidrifter.quality.sensitive_surface import (
    INTENT_PII_SCOPE,
    INTENT_PII_SUBMIT,
    classify_sensitive_surface,
    classify_sensitive_surface_from_card,
    resolve_verification_intent,
)
from minidrifter.verification.binding_risk_planner import (
    probe_eligible_for_candidate,
    rule_binding_risk_score,
)


class SensitiveSurfaceTests(unittest.TestCase):
    def test_id_card_read_path(self):
        surf = classify_sensitive_surface(
            '/action/carrctapi/user/drivingLicenseCerQua/v1',
            method='GET',
            side_effect_category='read_only',
        )
        self.assertTrue(surf['pii_surface'])
        self.assertEqual(surf['flow_kind'], 'read')
        self.assertFalse(surf['probe_blocked'])
        self.assertEqual(surf['probe_style'], 'pii_scope_m7')

    def test_id_card_upload_write_path(self):
        surf = classify_sensitive_surface(
            '/action/carrctapi/memberInfo/credentialsUpload/v1',
            method='POST',
            side_effect_category='state_changing',
        )
        self.assertTrue(surf['pii_surface'])
        self.assertEqual(surf['flow_kind'], 'write')
        self.assertTrue(surf['probe_blocked'])

    def test_resolve_intent_pii_read(self):
        card = {
            'static': {
                'endpoint': {'path': '/resource/carrctapi/account/depositInfo/v1'},
                'http': {'method': 'GET'},
            },
            'bindings': {'params': []},
            'replay': {'side_effect': {'category': 'read_only'}},
            'ranking': {'validation_value': 'none'},
        }
        intent = resolve_verification_intent(
            card, runtime_level='N1_BASELINE_RUNTIME_TEMPLATE', validation_value='none',
        )
        self.assertEqual(intent, INTENT_PII_SCOPE)

    def test_resolve_intent_pii_write(self):
        card = {
            'static': {
                'endpoint': {'path': '/action/carrctapi/account/idCardCertify/v1'},
                'http': {'method': 'POST'},
            },
            'bindings': {'params': []},
            'replay': {'side_effect': {'category': 'state_changing'}},
            'ranking': {'validation_value': 'none'},
        }
        intent = resolve_verification_intent(
            card, runtime_level='N1_BASELINE_RUNTIME_TEMPLATE', validation_value='none',
        )
        self.assertEqual(intent, INTENT_PII_SUBMIT)

    def test_pii_read_scores_higher_than_write(self):
        read_card = {
            'provenance': {'card_kind': 'operation'},
            'static': {
                'endpoint': {'path': '/resource/carrctapi/user/drivingLicenseCerQua/v1'},
                'http': {'method': 'GET'},
            },
            'bindings': {'params': []},
            'replay': {'side_effect': {'category': 'read_only'}},
            'ranking': {'validation_value': 'none'},
        }
        write_card = {
            'provenance': {'card_kind': 'operation'},
            'static': {
                'endpoint': {'path': '/action/carrctapi/memberInfo/credentialsUpload/v1'},
                'http': {'method': 'POST'},
            },
            'bindings': {'params': []},
            'replay': {'side_effect': {'category': 'state_changing'}},
            'ranking': {'validation_value': 'none'},
        }
        read_score, read_sigs, _ = rule_binding_risk_score(
            read_card, {'verification_intent': INTENT_PII_SCOPE},
        )
        write_score, write_sigs, _ = rule_binding_risk_score(
            write_card, {'verification_intent': INTENT_PII_SUBMIT},
        )
        self.assertIn('pii_read_surface', read_sigs)
        self.assertIn('pii_write_surface', write_sigs)
        self.assertGreater(read_score, write_score)

    def test_probe_eligible_blocks_pii_write(self):
        card = classify_sensitive_surface_from_card({
            'static': {
                'endpoint': {'path': '/action/carrctapi/memberInfo/credentialsUpload/v1'},
                'http': {'method': 'POST'},
            },
            'bindings': {'params': []},
            'replay': {'side_effect': {'category': 'state_changing'}},
        })
        self.assertTrue(card['probe_blocked'])
        write_card = {
            'static': {
                'endpoint': {'path': '/action/carrctapi/memberInfo/credentialsUpload/v1'},
                'http': {'method': 'POST'},
            },
            'bindings': {'params': []},
            'replay': {'side_effect': {'category': 'state_changing'}},
        }
        self.assertFalse(probe_eligible_for_candidate(
            write_card,
            materialized={'status': 'materialized_plain'},
        ))


if __name__ == '__main__':
    unittest.main()
