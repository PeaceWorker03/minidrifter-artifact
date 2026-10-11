# -*- coding: utf-8 -*-
"""Tests for binding-risk planner and per-API guard beliefs."""
from __future__ import annotations

import unittest
from pathlib import Path

from minidrifter.verification.api_guard_beliefs import ApiGuardBeliefs, BINDING_ENFORCED
from minidrifter.verification.binding_risk_planner import (
    build_binding_risk_plan,
    is_external_sdk_path,
    rule_binding_risk_score,
    risk_boost_for_api,
)


class TestBindingRiskRules(unittest.TestCase):
    def test_external_sdk_excluded(self):
        self.assertTrue(is_external_sdk_path('/geocoding/v3'))
        self.assertFalse(is_external_sdk_path('/wechat/applet/user/personalCore.jhtml'))

    def test_business_api_scores_above_map(self):
        biz = {
            'provenance': {'card_kind': 'operation'},
            'static': {'endpoint': {'path': '/wechat/applet/user/personalCore.jhtml'}},
            'bindings': {'params': [
                {'name': 'userId'}, {'name': 'loginCustomerId'}, {'name': 'signature'},
            ]},
            'ranking': {'priority_tier': 'P1', 'validation_value': 'high'},
            'replay': {'side_effect': {'category': 'read_only'}},
        }
        map_card = {
            'provenance': {'card_kind': 'operation'},
            'static': {'endpoint': {'path': '/geocoding/v3'}},
            'bindings': {'params': []},
        }
        erd = {'verification_intent': 'subject_object_binding_check'}
        biz_score, _, _ = rule_binding_risk_score(biz, erd, intake_anchor=True)
        map_score, sigs, _ = rule_binding_risk_score(map_card, erd)
        self.assertGreater(biz_score, 40)
        self.assertEqual(map_score, 0.0)
        self.assertIn('external_sdk_excluded', sigs)

    def test_per_api_identity_skip_not_family(self):
        beliefs = ApiGuardBeliefs()
        beliefs.record_probe(
            api_id='op_money',
            path='/wechat/applet/remain/money.jhtml',
            mutation_type='M7_subject_object_mismatch',
            target_field='loginCustomerId',
            outcome='binding_rejected',
            guard_kind='identity',
        )
        self.assertTrue(beliefs.should_skip_identity_field(
            '/wechat/applet/remain/money.jhtml', 'loginCustomerId', api_id='op_money',
        ))
        self.assertFalse(beliefs.should_skip_identity_field(
            '/wechat/applet/user/personalCore.jhtml', 'loginCustomerId', api_id='op_personal',
        ))


class TestBindingRiskPlanIntegration(unittest.TestCase):
    PACK = Path(__file__).resolve().parents[1] / 'sample_outputs' / 'ehai'

    def test_build_plan_on_ehai_sample(self):
        if not self.PACK.exists():
            self.skipTest('sample pack missing')
        doc = build_binding_risk_plan(self.PACK, with_llm=False)
        self.assertIn('candidates', doc)
        self.assertGreater(doc['summary']['candidates_scored'], 0)
        top = doc['candidates'][0]
        self.assertNotIn('/geocoding', top.get('path', ''))
        boost = risk_boost_for_api(self.PACK, top['api_id'])
        self.assertGreater(boost, 0)


if __name__ == '__main__':
    unittest.main()
