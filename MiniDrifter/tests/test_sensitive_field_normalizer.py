# -*- coding: utf-8 -*-
"""Tests for sensitive field alias normalization (P4-fix-1)."""
from __future__ import annotations

import unittest

from minidrifter.classification.sensitive_field_normalizer import (
    detect_normalized_sensitive_fields,
    expand_canonical_aliases,
    mask_sensitive_value,
    missing_canonical_for_plane,
    normalize_field_name,
    plane_baseline_satisfied,
    pool_has_canonical,
)
from minidrifter.classification.api_plane_classifier import build_plane_capture_gaps
from minidrifter.verification.sensitive_api_oracle import analyze_sensitive_response

ROOT = None


class SensitiveFieldNormalizerTests(unittest.TestCase):
    def test_phone_aliases(self):
        self.assertEqual(normalize_field_name('Phone'), 'phone')
        self.assertEqual(normalize_field_name('maskPhone'), 'phone')
        self.assertTrue(pool_has_canonical('phone', {'Phone'}, {'Phone': '166******32'}))

    def test_id_card_aliases(self):
        self.assertEqual(normalize_field_name('idNo'), 'id_card')
        self.assertTrue(pool_has_canonical('id_card', {'idNo'}, {'idNo': '1***1'}))

    def test_points_aliases(self):
        self.assertEqual(normalize_field_name('integral'), 'points')
        self.assertTrue(pool_has_canonical('points', set(), {'growthValue': 526}))

    def test_user_profile_satisfied_with_getuserinfo_shape(self):
        pool = {'Phone', 'name', 'idNo', 'integral'}
        values = {'Phone': '166******32', 'name': '**天', 'idNo': '1***1', 'integral': 526}
        self.assertTrue(plane_baseline_satisfied('user_profile_personal_info', pool, values))
        self.assertEqual(missing_canonical_for_plane(
            'user_profile_personal_info', pool, values,
        ), [])

    def test_oracle_normalized_reads(self):
        body = {
            'phone': '166******32',
            'idNo': '1****************1',
            'integral': 526,
            'name': '**天',
        }
        sens = analyze_sensitive_response(path='/resource/carrctapi/account/getUserInfo/v1', body=body)
        reads = sens['sensitive_field_reads']
        self.assertTrue(any(r['raw_field'] in {'phone', 'Phone'} for r in reads))
        canon = {r['normalized_field'] for r in reads}
        self.assertIn('phone', canon)
        self.assertIn('id_card', canon)
        self.assertIn('points', canon)

    def test_masking(self):
        self.assertIn('***', mask_sensitive_value('phone', '16612341932'))
        self.assertEqual(mask_sensitive_value('id_card', '1****************1'), '1****************1')

    def test_expand_canonical_aliases(self):
        expanded = expand_canonical_aliases({'Phone': '166******32', 'integral': 526})
        self.assertIn('phone', expanded)
        self.assertIn('points', expanded)

    @unittest.skipUnless(
        __import__('pathlib').Path(__file__).resolve().parents[1].joinpath(
            '../Workspace/神州租车/OUTPUT/baseline_intake_report.json'
        ).exists(),
        '神州 intake not present',
    )
    def test_shenzhou_plane_gaps_after_alias(self):
        from pathlib import Path
        pack = Path(__file__).resolve().parents[1].parent / 'Workspace' / '神州租车' / 'OUTPUT'
        gaps = build_plane_capture_gaps(pack)
        planes = {g['plane'] for g in gaps}
        self.assertNotIn('user_profile_personal_info', planes)


if __name__ == '__main__':
    unittest.main()
