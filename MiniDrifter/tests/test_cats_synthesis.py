# -*- coding: utf-8 -*-
"""CATS — constraint-aware binding test synthesis and fingerprint oracle."""
from __future__ import annotations

import unittest
from typing import Any, Dict

from minidrifter.verification.cats.candidate_builder import materialize_test_cases, resolve_candidate
from minidrifter.verification.cats.content_fingerprint import (
    fingerprints_differ,
    m7_empty_but_m0_has_pii,
)
from minidrifter.verification.cats.verifier import verify_binding_test_plan
from minidrifter.verification.subject_override_oracle import classify_subject_override


M0_BODY = {
    'memberName': '肖闰天',
    'decodeNo': '320***',
    'identityInfo': {'decodeNo': '320***', 'realName': '肖闰天'},
    'drivingLicenceInfo': {'licenseType': 'C1', 'status': 1},
}

M7_BODY_FOREIGN = {
    'memberName': '武文',
    'decodeNo': '110***',
    'identityInfo': {'decodeNo': '110***', 'realName': '武文'},
    'drivingLicenceInfo': {'licenseType': 'C1', 'status': 1},
}


def _fake_execution(body: Any, outcome: str = 'business_success') -> Dict[str, Any]:
    return {'body_json': body, 'status_code': 200}


def _fake_analysis(outcome: str = 'business_success') -> Dict[str, Any]:
    return {'call_outcome': outcome, 'sensitive_read': True}


def _fake_tc(field: str, value: str) -> Dict[str, Any]:
    return {
        'api_id': 'api-test',
        'body_params': {field: value},
    }


class ContentFingerprintTests(unittest.TestCase):
    def test_different_pii_fingerprints(self):
        self.assertTrue(fingerprints_differ(M0_BODY, M7_BODY_FOREIGN))

    def test_same_pii_no_drift(self):
        self.assertFalse(fingerprints_differ(M0_BODY, dict(M0_BODY)))

    def test_empty_m7_with_m0_pii_is_invalid_mutant(self):
        self.assertTrue(m7_empty_but_m0_has_pii(M0_BODY, {}))


class CandidateBuilderTests(unittest.TestCase):
    def test_far_jump_down_produces_distinct_id(self):
        val, policy = resolve_candidate('memberId', '191918925', 'numeric_far_jump_down', pool={})
        self.assertEqual(policy, 'numeric_far_jump_down')
        self.assertNotEqual(val, '191918925')
        self.assertNotEqual(val, '191918926')

    def test_authorized_seed_from_pool(self):
        pool = {'authorized_member_id_seed': '171902050'}
        val, policy = resolve_candidate('memberId', '191918925', 'authorized_seed', pool=pool)
        self.assertEqual(val, '171902050')
        self.assertEqual(policy, 'authorized_seed')

    def test_materialize_ordered_cases(self):
        plan = {
            'plan_id': 'cats-test',
            'mutation_field': 'memberId',
            'candidate_policies': [
                'authorized_seed',
                'numeric_far_jump_down',
                'numeric_increment',
            ],
            'oracle': {'type': 'sensitive_content_fingerprint'},
        }
        pool = {'authorized_member_id_seed': '171902050'}
        cases = materialize_test_cases(plan, original='191918925', pool=pool)
        policies = [c['candidate_policy'] for c in cases]
        self.assertIn('authorized_seed', policies)
        self.assertIn('numeric_far_jump_down', policies)
        self.assertEqual(cases[0]['candidate_policy'], 'authorized_seed')


class PlanVerifierTests(unittest.TestCase):
    def test_rejects_crypto_field_mutation(self):
        plan = {
            'target_api': '/personalData/get/v2',
            'mutation_field': 'sign',
            'candidate_policies': ['numeric_increment'],
        }
        ok, errs = verify_binding_test_plan(
            plan,
            known_paths={'/personaldata/get/v2'},
            template={'plain_template': {'body_params': {'sign': 'x'}}},
            identity_invariants=['uid'],
        )
        self.assertFalse(ok)
        self.assertTrue(any('crypto' in e or 'forbidden' in e for e in errs))


class OracleFingerprintIntegrationTests(unittest.TestCase):
    def test_drift_without_memberid_echo(self):
        oracle = classify_subject_override(
            path='/personalData/get/v2',
            subject_field='memberId',
            m0_test_case=_fake_tc('memberId', '191918925'),
            m7_test_case=_fake_tc('memberId', '171902050'),
            m0_execution=_fake_execution(M0_BODY),
            m7_execution=_fake_execution(M7_BODY_FOREIGN),
            m0_analysis=_fake_analysis(),
            m7_analysis=_fake_analysis(),
            mutation_plan={'strategy': 'authorized_seed'},
            oracle_plan={
                'type': 'sensitive_content_fingerprint',
                'fields': ['identityInfo', 'memberName', 'decodeNo'],
                'empty_response_policy': 'invalid_mutant_no_evidence',
            },
        )
        self.assertEqual(oracle['status'], 'subject_override_accepted_sensitive')
        self.assertIn('drift_sensitive_content_changed_no_echo', oracle['reason_codes'])

    def test_empty_m7_not_clean_with_fingerprint_oracle(self):
        oracle = classify_subject_override(
            path='/personalData/get/v2',
            subject_field='memberId',
            m0_test_case=_fake_tc('memberId', '191918925'),
            m7_test_case=_fake_tc('memberId', '191918926'),
            m0_execution=_fake_execution(M0_BODY),
            m7_execution=_fake_execution({}),
            m0_analysis=_fake_analysis(),
            m7_analysis=_fake_analysis(),
            mutation_plan={'strategy': 'numeric_increment'},
            oracle_plan={
                'type': 'sensitive_content_fingerprint',
                'empty_response_policy': 'invalid_mutant_no_evidence',
            },
        )
        self.assertEqual(oracle['status'], 'subject_override_inconclusive')
        self.assertIn('invalid_mutant_no_evidence', oracle['reason_codes'])


class EnvelopeWireIntegrationTests(unittest.TestCase):
    def test_personaldata_m7_preserves_bucket_from_capture_pool(self):
        from minidrifter.materials.envelope_wire import apply_envelope_preserving_mutation

        m0 = {
            'api_id': 'op_test',
            'path': '/action/carrctapi/account/personalData/get/v2',
            'method': 'POST',
            'transport_style': 'form_encrypted_body',
            'body_params': {
                'memberId': '191918925',
                'pickupDeptId': '535',
                'bucketIdList': [1, 2, 3],
            },
        }
        replay = {
            'replay_context': {
                'body': {'memberId': '191918925'},
                'pool': {'bucketIdList': '[2621,3363]', 'cid': '801553'},
            }
        }
        tc = dict(m0)
        apply_envelope_preserving_mutation(
            tc, field='memberId', mutated_value='171902050', replay_entry=replay,
        )
        self.assertEqual(tc['body_params']['memberId'], '171902050')
        self.assertEqual(tc['body_params']['bucketIdList'], [2621, 3363])
        self.assertNotIn('pickupDeptId', tc['body_params'])


if __name__ == '__main__':
    unittest.main()
