# -*- coding: utf-8 -*-
"""Tests for hop policy — skip, inherit, material-backed."""
from __future__ import annotations

import unittest

from minidrifter.verification.chain_object_pool import ChainObjectPool
from minidrifter.verification.hop_policy import (
    HOP_SKIPPED,
    collect_baseline_business_fields,
    inherit_baseline_params,
    is_success_status,
    should_skip_hop,
    try_material_backed_hop,
)


class HopPolicyTests(unittest.TestCase):
    def test_inherit_entrance_from_baseline(self):
        ctx = {
            'resolved_fields': {
                'entrance': {'value': '1'},
                'deptId': {'value': '142166'},
            },
        }
        hop = {'consumes': ['deptId'], 'requires': []}
        tc = {'body_params': {'deptId': '$pool.deptId'}}
        out = inherit_baseline_params(tc, hop, baseline_context=ctx)
        self.assertEqual(out['body_params']['entrance'], '1')

    def test_skip_intermediate_when_pool_ready(self):
        pool = ChainObjectPool('c1', static_hops=[
            {'api_id': 'a1', 'role': 'producer', 'produces': ['deptId'], 'consumes': []},
            {'api_id': 'a2', 'role': 'hop', 'consumes': ['deptId']},
            {'api_id': 'a3', 'role': 'consumer', 'consumes': ['deptId']},
        ])
        pool.harvest('a1', ['deptId'], {'deptId': '99'})
        chain = {'target_hop': 'a3', 'chain_id': 'c1'}
        hop = {'api_id': 'a2', 'role': 'hop', 'consumes': ['deptId'], 'mutation_points': []}
        reason = should_skip_hop(hop, pool, chain, hop_index=1, total_hops=3)
        self.assertEqual(reason, 'pool_satisfied_intermediate_skip')

    def test_skip_producer_when_baseline_seeded(self):
        pool = ChainObjectPool('c1', static_hops=[
            {'api_id': 'a1', 'role': 'producer', 'produces': ['deptId'], 'consumes': []},
            {'api_id': 'a2', 'role': 'consumer', 'consumes': ['deptId']},
        ])
        pool.harvest('baseline_seed', ['deptId'], {'deptId': '42'})
        chain = {'target_hop': 'a2', 'binding_fields': ['deptId']}
        hop = {'api_id': 'a1', 'role': 'producer', 'produces': ['deptId'], 'consumes': []}
        reason = should_skip_hop(hop, pool, chain, hop_index=0, total_hops=2, templates_by_id={})
        self.assertEqual(reason, 'baseline_seed_satisfies_producer')

    def test_material_backed_passthrough(self):
        pool = ChainObjectPool('c1')
        pool.harvest('seed', ['deptId'], {'deptId': '42'})
        hop = {'role': 'hop', 'consumes': ['deptId'], 'produces': []}
        backed = try_material_backed_hop(
            hop,
            api_id='a2',
            chain_pool=pool,
            baseline_context={},
            intake_report=None,
            material_validation={'valid': True},
            execution={'call_outcome': 'business_state_blocked'},
            analysis={'call_outcome': 'business_state_blocked'},
        )
        self.assertIsNotNone(backed)
        self.assertEqual(backed.get('material_source'), 'pool_satisfied_passthrough')

    def test_is_success_status_includes_skipped(self):
        self.assertTrue(is_success_status('business_success'))
        self.assertTrue(is_success_status(HOP_SKIPPED))

    def test_collect_baseline_fields(self):
        ctx = {'resolved_fields': {'deptId': {'value': '1'}, 'token': {'value': 't'}}}
        fields = collect_baseline_business_fields(ctx)
        self.assertIn('deptId', fields)
        self.assertNotIn('token', fields)


if __name__ == '__main__':
    unittest.main()
