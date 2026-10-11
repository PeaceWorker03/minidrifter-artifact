# -*- coding: utf-8 -*-
"""Information-gain heuristic for prune-before-execute (Phase 3)."""
from __future__ import annotations

from typing import Any, Dict, Optional

MANDATORY_STAGES = frozenset({'seed_baseline'})

BINDING_MUTATIONS = frozenset({
    'M5_same_account_object_substitution',
    'M7_subject_object_mismatch',
    'M2_missing_binding_param',
})

HIGH_VALUE_FIELDS = frozenset({'userid', 'orderid', 'invoiceid', 'deviceid', 'openid'})


def estimate_information_gain(
    test_case: Dict[str, Any],
    *,
    object_pool: Optional[Dict[str, Any]] = None,
    pool_hash: str = '',
) -> float:
    """Heuristic IG in [0, 1] — higher = more likely to produce useful signals."""
    mut = test_case.get('mutation_type') or 'M0_baseline_replay'
    stage = test_case.get('test_stage') or ''

    if stage in MANDATORY_STAGES and mut == 'M0_baseline_replay':
        return 1.0

    score = 0.12

    if mut in BINDING_MUTATIONS or mut.startswith('M7') or mut.startswith('M5'):
        score += 0.38
    elif mut.startswith('M2'):
        score += 0.22
    elif mut == 'M0_baseline_replay':
        score += 0.18

    if stage == 'depth_chain':
        score += 0.28
    elif stage == 'frontier_wave':
        score += 0.15

    side = (test_case.get('safety') or {}).get('side_effect') or ''
    if side in {'S0_read_only', 'S1_query_like_post'}:
        score += 0.08

    params = test_case.get('params') or {}
    if any(str(k).lower() in HIGH_VALUE_FIELDS for k in params):
        score += 0.12

    if test_case.get('workflow_hypothesis') or test_case.get('unlocked_by_fields'):
        score += 0.1

    pool = object_pool or {}
    unlocks = set(pool.get('frontier_unlocks') or [])
    if unlocks and stage == 'depth_chain':
        score += min(0.1, len(unlocks) * 0.02)

    return min(round(score, 3), 1.0)


def is_mandatory_test(test_case: Dict[str, Any]) -> bool:
    stage = test_case.get('test_stage') or ''
    mut = test_case.get('mutation_type') or 'M0_baseline_replay'
    return stage in MANDATORY_STAGES and mut == 'M0_baseline_replay'
