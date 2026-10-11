# -*- coding: utf-8 -*-
"""Tests for P4-fix-5 subject override pilot."""
from __future__ import annotations

import unittest

from minidrifter.verification.chain_strict_runner import HOP_STATUS_OK
from minidrifter.verification.subject_override_mutation import (
    build_subject_mutation_plan,
    mutate_subject_value,
)
from minidrifter.verification.subject_override_oracle import (
    classify_subject_override,
    summarize_subject_override_batch,
)
from minidrifter.verification.subject_override_fields import (
    field_allowed as _field_allowed,
    infer_subject_fields_from_path,
    pool_value_for_subject_field,
)
from minidrifter.verification.subject_override_target_selector import (
    is_pilot_subject_override_path,
    select_subject_override_targets,
)


class SubjectPathInferenceTests(unittest.TestCase):
    def test_by_user_id_path(self):
        fields = infer_subject_fields_from_path('/Wechat/Invoice/InvoiceableList/CarRentalWaiting/ByUserId')
        self.assertIn('userId', fields)

    def test_personal_data_path(self):
        fields = infer_subject_fields_from_path('/action/carrctapi/account/personalData/get/v2')
        self.assertIn('memberId', fields)

    def test_pool_lookup(self):
        val = pool_value_for_subject_field('memberId', {'userId': '123', 'MemberId': '456'})
        self.assertEqual(val, '456')


class SubjectOverrideSelectorTests(unittest.TestCase):
    def test_pilot_paths(self):
        self.assertTrue(is_pilot_subject_override_path('/resource/carrctapi/account/getUserInfo/v1'))
        self.assertTrue(is_pilot_subject_override_path('/Wechat/Special/Mini/Device/List'))
        self.assertTrue(is_pilot_subject_override_path('/action/carrctapi/account/personalData/get/v2'))
        self.assertFalse(is_pilot_subject_override_path('/resource/carrctapi/membership/home'))

    def test_forbidden_fields(self):
        for field in ('name', 'idNo', 'idCard', 'realName'):
            allowed, reason = _field_allowed(field)
            self.assertFalse(allowed)
            self.assertEqual(reason, 'forbidden_pii_field')

    def test_allowed_member_id(self):
        allowed, reason = _field_allowed('memberId', value='12345')
        self.assertTrue(allowed)
        self.assertEqual(reason, 'subject_identifier')

    def test_select_live_m0_targets(self):
        sensitive_rows = [
            {
                'path': '/resource/carrctapi/account/getUserInfo/v1',
                'api_id': 'op_gu',
                'live_sensitive_read_m0_success': True,
                'primary_plane': 'user_profile_personal_info',
            },
            {
                'path': '/resource/carrctapi/membership/home',
                'api_id': 'op_mh',
                'live_sensitive_read_m0_success': True,
            },
        ]
        templates = {
            'op_gu': {
                'api_id': 'op_gu',
                'path': '/resource/carrctapi/account/getUserInfo/v1',
                'plain_template': {'body_params': {'memberId': '1001'}},
            },
            'op_mh': {'api_id': 'op_mh', 'path': '/x'},
        }
        targets = select_subject_override_targets(
            '.', sensitive_rows, templates_by_id=templates, max_targets=3,
        )
        self.assertEqual(len(targets), 1)
        self.assertIn('getUserInfo', targets[0]['api'])


class SubjectOverrideMutationTests(unittest.TestCase):
    def test_numeric_increment(self):
        val, strategy = mutate_subject_value('memberId', '801553', pool={})
        self.assertEqual(val, '801554')
        self.assertEqual(strategy, 'numeric_increment')

    def test_feedback_keeps_width_and_widens_step(self):
        from minidrifter.verification.subject_override_mutation import (
            refine_source_from_feedback,
        )
        first, strategy = refine_source_from_feedback('userId', '801553', distance=1)
        self.assertEqual(first, '801554')
        self.assertEqual(strategy, 'structure_preserving_digits')
        widened, _ = refine_source_from_feedback(
            'userId', '801553', category='business_error', body='参数格式错误', distance=2,
        )
        self.assertEqual(widened, '801563')
        self.assertEqual(len(widened), 6)
        wrapped, _ = refine_source_from_feedback('userId', '999', distance=1)
        self.assertEqual(wrapped, '000')

    def test_forbidden_mutation(self):
        val, reason = mutate_subject_value('idNo', '110101199001011234', pool={})
        self.assertIsNone(val)
        self.assertEqual(reason, 'forbidden_field')

    def test_build_plan(self):
        target = {'selected_field': 'memberId', 'selected_value': '801553'}
        m0_tc = {
            'api_id': 'op_gu',
            'body_params': {'memberId': '801553', 'cid': '500553'},
        }
        plan = build_subject_mutation_plan(
            target, m0_tc, baseline_context={'pool': {}}, pool={},
        )
        self.assertEqual(plan['status'], 'ready')
        self.assertEqual(plan['m7_test_case']['body_params']['memberId'], '801554')


class SubjectOverrideOracleTests(unittest.TestCase):
    def _base_cases(self):
        m0_tc = {'body_params': {'memberId': '801553'}, 'headers': {'token': 't1'}}
        m7_tc = {'body_params': {'memberId': '801554'}, 'headers': {'token': 't1'}}
        m0_ex = {
            'body_json': {'memberId': '801553', 'phone': '166******32', 'name': '**天'},
            'status_code': 200,
        }
        return m0_tc, m7_tc, m0_ex

    def test_blocked_after_mutation(self):
        m0_tc, m7_tc, m0_ex = self._base_cases()
        m7_ex = {'body_json': {'error': 'forbidden'}, 'status_code': 403}
        oracle = classify_subject_override(
            path='/resource/carrctapi/account/getUserInfo/v1',
            subject_field='memberId',
            m0_test_case=m0_tc,
            m7_test_case=m7_tc,
            m0_execution=m0_ex,
            m7_execution=m7_ex,
            m0_analysis={'call_outcome': HOP_STATUS_OK},
            m7_analysis={'call_outcome': 'auth_required'},
            mutation_plan={'strategy': 'numeric_increment'},
        )
        self.assertEqual(oracle['status'], 'subject_override_blocked')
        self.assertFalse(oracle['high_risk_candidate'])

    def test_ignored_sensitive_same_subject(self):
        m0_tc, m7_tc, m0_ex = self._base_cases()
        m7_ex = {
            'body_json': {'memberId': '801553', 'phone': '166******32', 'name': '**天'},
            'status_code': 200,
        }
        oracle = classify_subject_override(
            path='/resource/carrctapi/account/getUserInfo/v1',
            subject_field='memberId',
            m0_test_case=m0_tc,
            m7_test_case=m7_tc,
            m0_execution=m0_ex,
            m7_execution=m7_ex,
            m0_analysis={'call_outcome': HOP_STATUS_OK},
            m7_analysis={'call_outcome': HOP_STATUS_OK},
            mutation_plan={'strategy': 'numeric_increment'},
        )
        self.assertEqual(oracle['status'], 'subject_override_ignored')

    def test_invalid_when_wire_unchanged(self):
        m0_tc, m7_tc, m0_ex = self._base_cases()
        m7_tc = dict(m0_tc)
        oracle = classify_subject_override(
            path='/x',
            subject_field='memberId',
            m0_test_case=m0_tc,
            m7_test_case=m7_tc,
            m0_execution=m0_ex,
            m7_execution=m0_ex,
            m0_analysis={'call_outcome': HOP_STATUS_OK},
            m7_analysis={'call_outcome': HOP_STATUS_OK},
            mutation_plan={'strategy': 'noop'},
        )
        self.assertEqual(oracle['status'], 'subject_override_invalid_test')

    def test_inject_anchor_mutation(self):
        m0_tc = {'params': {}, 'headers': {'token': 't1'}}
        m7_tc = {'params': {'memberId': '801554'}, 'headers': {'token': 't1'}}
        m0_ex = {
            'body_json': {'memberId': '801553', 'phone': '166******32'},
            'status_code': 200,
            'request_preview_redacted': {'params_resolved': {}},
        }
        m7_ex = {
            'body_json': {'memberId': '801554', 'phone': '188******99'},
            'status_code': 200,
            'request_preview_redacted': {'params_resolved': {'memberId': '801554'}},
        }
        oracle = classify_subject_override(
            path='/action/carrctapi/account/personalData/get/v2',
            subject_field='memberId',
            m0_test_case=m0_tc,
            m7_test_case=m7_tc,
            m0_execution=m0_ex,
            m7_execution=m7_ex,
            m0_analysis={'call_outcome': HOP_STATUS_OK},
            m7_analysis={'call_outcome': HOP_STATUS_OK},
            mutation_plan={'strategy': 'numeric_increment'},
        )
        self.assertTrue(oracle['anchor_mutated_on_wire'])
        self.assertEqual(oracle['status'], 'subject_override_accepted_sensitive')

    def test_preliminary_drift_on_wire_mutation_and_success(self):
        m0_tc = {'body_params': {'memberId': '801553'}, 'headers': {'token': 't1'}}
        m7_tc = {'body_params': {'memberId': '801554'}, 'headers': {'token': 't1'}}
        m0_ex = {'body_json': {'status': 'ok'}, 'status_code': 200}
        m7_ex = {'body_json': {'status': 'ok'}, 'status_code': 200}
        oracle = classify_subject_override(
            path='/action/example/personaldata/get/v2',
            subject_field='memberId',
            m0_test_case=m0_tc,
            m7_test_case=m7_tc,
            m0_execution=m0_ex,
            m7_execution=m7_ex,
            m0_analysis={'call_outcome': HOP_STATUS_OK},
            m7_analysis={'call_outcome': HOP_STATUS_OK},
            mutation_plan={'strategy': 'numeric_increment'},
        )
        self.assertEqual(oracle['status'], 'subject_override_accepted_sensitive')
        self.assertEqual(oracle['evidence_grade'], 'A_preliminary')
        self.assertTrue(oracle['high_risk_candidate'])

    def test_summarize_batch(self):
        summary = summarize_subject_override_batch([
            {'subject_override_status': 'subject_override_blocked', 'wire_mutation_valid': True},
            {'subject_override_status': 'subject_override_ignored', 'wire_mutation_valid': True},
            {'subject_override_status': 'subject_override_invalid_test'},
        ])
        self.assertEqual(summary['attempted'], 3)
        self.assertEqual(summary['blocked'], 1)
        self.assertEqual(summary['ignored'], 1)
        self.assertEqual(summary['wire_mutation_valid'], 2)


if __name__ == '__main__':
    unittest.main()
