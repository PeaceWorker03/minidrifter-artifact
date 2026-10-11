# -*- coding: utf-8 -*-
"""Tests for P5 signature profile mining."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from minidrifter.runtime.crypto.signature_profile_miner import mine_signature_profile
from minidrifter.runtime.crypto.signature_recipes import (
    RECIPE_CATALOG,
    clone_recipe,
    verify_capture_against_recipe,
)
from minidrifter.runtime.crypto.signature_static_mine import mine_signature_static_evidence
from minidrifter.verification.sensitive_replay_context_builder import _replay_mode_meta


class SignatureRecipeTests(unittest.TestCase):
    def test_sorted_params_secret_append_md5(self):
        recipe = RECIPE_CATALOG['sorted_params_secret_append_md5']
        params = {'b': '2', 'a': '1', 'signature': 'skip'}
        ok = verify_capture_against_recipe(
            recipe,
            method='GET',
            path='/api/demo',
            params=params,
            expected_signature='28eb33f8d7b0200120f6099066f92f7b',
            secret='pepper',
        )
        self.assertTrue(ok)


class SignatureProfileMinerTests(unittest.TestCase):
    def test_mine_static_and_baseline_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            source = pack / 'src'
            source.mkdir()
            (source / 'sign.js').write_text(
                'function getBaseApiData(m,u,p){'
                'function saltDataToStr(W,c){return c.map(i=>W[i]).join("")}'
                'return {signature:"x",nonce:"n",timestamp:"t"};'
                '}\n'
                'saltDataToStr(secret,[8,19,20,34,46,53,49,31]);',
                encoding='utf-8',
            )
            (pack / 'request_wrappers.json').write_text(json.dumps([{
                'file': 'sign.js',
                'crypto_hints': ['sign', 'md5'],
                'exported_or_defined_methods': ['getBaseApiData'],
            }]), encoding='utf-8')
            (pack / 'baseline_intake_report.json').write_text(json.dumps({
                'captures': [{
                    'capture_index': 1,
                    'method': 'GET',
                    'path': '/wechat/applet/user/personalCore.jhtml',
                    'host': 'example.test',
                    'crypto_processing': {
                        'decrypted': {
                            'query': {
                                'userId': '1',
                                'nonce': 'abc',
                                'timestamp': '123',
                                'signature': 'deadbeef',
                            },
                        },
                        'resolved_fields': {},
                    },
                }],
            }), encoding='utf-8')

            static = mine_signature_static_evidence(pack_dir=pack, source_dir=source)
            functions = [h.get('function') for h in static.get('function_hits') or []]
            self.assertIn('getBaseApiData', functions)
            profile = mine_signature_profile(pack, source_dir=source)
            self.assertIn('nonce', profile.get('covered_fields', []))
            self.assertFalse(profile.get('can_recompute_signature'))
            self.assertEqual(profile.get('reason'), 'static_signature_logic_found_secret_unresolved')

    def test_replay_meta_reads_signature_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            (pack / 'signature_profile.json').write_text(json.dumps({
                'can_recompute_signature': True,
                'signature_profile_id': 'method_path_sorted_brace_salt_md5',
            }), encoding='utf-8')
            capture = {
                'transport_assessment': {'transport_mode': 'plaintext_only', 'plaintext_usable': True},
                'crypto_processing': {'input_mode': 'plaintext_query'},
            }
            meta = _replay_mode_meta(capture, {}, pack_dir=pack)
            self.assertTrue(meta['can_recompute_signature'])
            self.assertEqual(meta['signature_mode'], 'recompute')


if __name__ == '__main__':
    unittest.main()
