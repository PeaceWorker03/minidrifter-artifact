# -*- coding: utf-8 -*-
"""Tests for finding lifecycle dedupe and tier transitions."""
from __future__ import annotations

from minidrifter.verification.finding_lifecycle import FindingRegistry


def test_reingest_same_finding_not_self_pruned():
    reg = FindingRegistry()
    f = {
        'finding_id': 'fd_cf7d03b59d0d',
        'finding_type': 'subject_object_binding_mismatch',
        'api_id': 'api_1',
        'chain_id': 'chain_1',
        'mutation_type': 'M7_userId',
        'status': 'hypothesis',
        'evidence_test_ids': ['tc_a'],
    }
    reg.ingest([f])
    f2 = dict(f)
    f2['evidence_test_ids'] = ['tc_a', 'tc_b']
    f2['status'] = 'hypothesis'
    reg.ingest([f2])
    doc = reg.to_document()
    assert doc['summary']['pruned'] == 0
    assert doc['summary']['hypothesis'] == 1
    stored = reg.all_findings()[0]
    assert 'tc_b' in stored.get('evidence_test_ids', [])


def test_dedupe_different_ids_prunes_duplicate():
    reg = FindingRegistry()
    base = {
        'finding_type': 'binding_anomaly_hypothesis',
        'api_id': 'api_1',
        'chain_id': 'chain_1',
        'mutation_type': 'M7_userId',
        'status': 'signal',
    }
    reg.ingest([{**base, 'finding_id': 'fd_aaa'}])
    reg.ingest([{**base, 'finding_id': 'fd_bbb'}])
    assert reg.summary()['pruned'] == 1
