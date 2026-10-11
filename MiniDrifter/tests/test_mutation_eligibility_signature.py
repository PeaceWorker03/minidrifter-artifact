# -*- coding: utf-8 -*-
"""Tests for crypto_static_profile → M7 eligibility fallback."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from minidrifter.verification.mutation_eligibility import (
    ELIGIBILITY_MUTATION_ALLOWED,
    ELIGIBILITY_SIGNATURE_BOUND,
    can_recompute_or_replay_signature,
    evaluate_mutation_eligibility,
)
from minidrifter.verification.sensitive_replay_context_builder import _replay_mode_meta


class MutationEligibilitySignatureTests(unittest.TestCase):
    def test_can_recompute_from_crypto_static_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            (pack / 'crypto_static_profile.json').write_text(json.dumps({
                'can_replay': True,
                'profile_id': 'aes_cfb_md5_header_query_wrapper',
            }), encoding='utf-8')
            self.assertTrue(can_recompute_or_replay_signature(
                {'can_recompute_signature': False, 'signature_mode': 'reuse_capture_signature'},
                {'can_recompute_signature': None, 'reason': 'not_mined'},
                pack_dir=pack,
            ))

    def test_plaintext_replay_meta_fallback_crypto_static(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            (pack / 'crypto_static_profile.json').write_text(json.dumps({'can_replay': True}), encoding='utf-8')
            capture = {
                'transport_assessment': {'transport_mode': 'plaintext_only', 'plaintext_usable': True},
                'crypto_processing': {'input_mode': 'plaintext_query'},
            }
            meta = _replay_mode_meta(capture, {}, pack_dir=pack)
            self.assertTrue(meta['can_recompute_signature'])
            self.assertEqual(meta['signature_mode'], 'recompute')

    def test_template_only_fallback_crypto_static(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            (pack / 'crypto_static_profile.json').write_text(json.dumps({'can_replay': True}), encoding='utf-8')
            meta = _replay_mode_meta(None, {}, pack_dir=pack)
            self.assertTrue(meta['can_recompute_signature'])
            self.assertEqual(meta['replay_mode'], 'crypto_materialize')

    def test_evaluate_eligibility_allows_when_crypto_can_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            (pack / 'crypto_static_profile.json').write_text(json.dumps({'can_replay': True}), encoding='utf-8')
            wire = {
                'wire_subject_fields': [
                    {'field': 'userId', 'mutation_allowed': True},
                ],
            }
            row = evaluate_mutation_eligibility(
                api='/Wechat/User/CardInfo/ByUserId',
                mutation_type='subject_override',
                replay_context={
                    'signature_mode': 'reuse_capture_signature',
                    'query_params': {'sign': 'abc'},
                    'can_recompute_signature': False,
                },
                signature_profile={'can_recompute_signature': None, 'reason': 'not_mined'},
                subject_wire_row=wire,
                m0_result={'ok': True, 'call_outcome': 'business_success'},
                pack_dir=pack,
            )
            self.assertEqual(row['eligibility_status'], ELIGIBILITY_MUTATION_ALLOWED)

    def test_evaluate_eligibility_blocks_without_any_replay_path(self):
        wire = {
            'wire_subject_fields': [
                {'field': 'userId', 'mutation_allowed': True},
            ],
        }
        row = evaluate_mutation_eligibility(
            api='/api/signed',
            mutation_type='subject_override',
            replay_context={
                'signature_mode': 'reuse_capture_signature',
                'query_params': {'sign': 'abc'},
                'can_recompute_signature': False,
            },
            signature_profile={'can_recompute_signature': False},
            subject_wire_row=wire,
            m0_result={'ok': True, 'call_outcome': 'business_success'},
        )
        self.assertEqual(row['eligibility_status'], ELIGIBILITY_SIGNATURE_BOUND)


if __name__ == '__main__':
    unittest.main()
