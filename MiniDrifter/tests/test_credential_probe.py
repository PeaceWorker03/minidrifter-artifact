# -*- coding: utf-8 -*-
"""Tests for intelligent credential probe planner and binding oracle."""
from __future__ import annotations

import unittest

from minidrifter.verification.campaign_planner import build_test_case
from minidrifter.verification.api_guard_beliefs import ApiGuardBeliefs
from minidrifter.verification.credential_probe_planner import (
    plan_intelligent_binding_campaign,
    should_continue_probes,
)
from minidrifter.verification.response_oracle import analyze_response


class TestCredentialProbePlanner(unittest.TestCase):
    def _template_with_sig(self):
        return {
            'api_id': 'op_test',
            'path': '/wechat/applet/user/personalCore.jhtml',
            'plain_template': {
                'method': 'GET',
                'params': {
                    'userId': '$baseline.userId',
                    'loginCustomerId': '$baseline.loginCustomerId',
                    'loginCustomerToken': '$baseline.loginCustomerToken',
                    'signature': '$baseline.signature',
                    'nonce': '$baseline.nonce',
                    'timestamp': '$baseline.timestamp',
                },
            },
        }

    def _baseline(self):
        return {
            'resolved_fields': {
                'userId': {'value': '1'},
                'loginCustomerId': {'value': '73052'},
                'loginCustomerToken': {'value': 'tok'},
                'signature': {'value': 'abc'},
                'nonce': {'value': 'n1'},
                'timestamp': {'value': '123'},
            },
        }

    def test_m8_ladder_includes_corrupt_signature_first(self):
        seed = {'seed_id': 's1', 'api_id': 'op_test', 'path': '/wechat/applet/user/personalCore.jhtml', 'template': self._template_with_sig()}
        m0 = build_test_case(self._template_with_sig(), baseline_context=self._baseline(), index=0)
        m0['test_id'] = 'tc_m0'
        m0['params'] = {
            'userId': '1',
            'loginCustomerId': '73052',
            'loginCustomerToken': 'tok',
            'signature': 'abc',
            'nonce': 'n1',
            'timestamp': '123',
        }
        plan = plan_intelligent_binding_campaign(
            seed, m0, baseline_context=self._baseline(), object_pool={'negative_pool': []},
        )
        step_ids = [s.get('step_id') for s in plan.get('steps') or []]
        self.assertIn('corrupt_signature', step_ids)
        self.assertTrue(any(s.startswith('m7_') for s in step_ids))
        self.assertGreaterEqual(len(plan.get('test_cases') or []), 2)

    def test_skip_m8_when_signature_already_ignored(self):
        beliefs = ApiGuardBeliefs()
        beliefs.record_probe(
            api_id='op_test',
            path='/wechat/applet/user/personalCore.jhtml',
            mutation_type='M8_weaken_credential_guard',
            target_field='signature',
            outcome='business_success',
            guard_kind='signature',
        )
        seed = {'seed_id': 's1', 'api_id': 'op_test', 'path': '/wechat/applet/user/personalCore.jhtml', 'template': self._template_with_sig()}
        m0 = {'test_id': 'tc_m0', 'api_id': 'op_test', 'path': '/wechat/applet/user/personalCore.jhtml', 'params': {'signature': 'x', 'nonce': 'n', 'timestamp': 't', 'loginCustomerId': '1', 'userId': '1'}}
        plan = plan_intelligent_binding_campaign(
            seed, m0, baseline_context=self._baseline(), object_pool={}, beliefs=beliefs,
        )
        m8_steps = [s for s in plan.get('steps') or [] if s.get('mutation_type', '').startswith('M8')]
        self.assertEqual(m8_steps, [])

    def test_early_stop_m8_not_m7(self):
        beliefs = ApiGuardBeliefs()
        cont, scope = should_continue_probes(
            {'mutation_type': 'M8_weaken_credential_guard', 'stop_if_success': True},
            {'call_outcome': 'business_success'},
            beliefs,
            api_id='op_test',
            path='/wechat/applet/user/personalCore.jhtml',
        )
        self.assertTrue(cont)
        self.assertEqual(scope, 'm8')

    def test_early_stop_m7_on_binding_rejected(self):
        beliefs = ApiGuardBeliefs()
        cont, scope = should_continue_probes(
            {'mutation_type': 'M7_subject_object_mismatch', 'stop_if_rejected': True},
            {'call_outcome': 'binding_rejected', 'failure_class': 'binding_rejected'},
            beliefs,
            api_id='op_test',
            path='/wechat/applet/user/personalCore.jhtml',
        )
        self.assertFalse(cont)
        self.assertEqual(scope, 'm7')


class TestBindingOracle(unittest.TestCase):
    def test_m7_ret1001_classified_as_binding_rejected(self):
        tc = {
            'mutation_type': 'M7_subject_object_mismatch',
            'target_field': 'loginCustomerId',
            'params': {'loginCustomerId': '73053', 'userId': '1'},
        }
        baseline = {'resolved_fields': {'loginCustomerId': {'value': '73052'}, 'userId': {'value': '1'}}}
        ex = {
            'test_id': 'tc_x',
            'build_status': 'ok',
            'mode': 'execute',
            'transport_status': 200,
            'body_json': {'ret': 1001, 'msg': '用户信息校验失败，请确认'},
        }
        analysis = analyze_response(ex, tc, baseline_context=baseline)
        self.assertEqual(analysis.get('call_outcome'), 'binding_rejected')
        self.assertEqual(analysis.get('failure_class'), 'binding_rejected')

    def test_m8_success_marks_credential_guard_ignored(self):
        tc = {
            'mutation_type': 'M8_weaken_credential_guard',
            'target_field': 'signature',
            'params': {'signature': 'deadbeef', 'userId': '1', 'loginCustomerId': '73052'},
        }
        baseline = {'resolved_fields': {'signature': {'value': 'abc'}, 'userId': {'value': '1'}, 'loginCustomerId': {'value': '73052'}}}
        ex = {
            'test_id': 'tc_y',
            'build_status': 'ok',
            'mode': 'execute',
            'transport_status': 200,
            'body_json': {'customerId': 73052, 'nickName': 'shaw'},
        }
        analysis = analyze_response(ex, tc, baseline_context=baseline)
        self.assertEqual(analysis.get('call_outcome'), 'business_success')
        self.assertIn('credential_guard_bypass', analysis.get('security_signals') or [])


if __name__ == '__main__':
    unittest.main()
