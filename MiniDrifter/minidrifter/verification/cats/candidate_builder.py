# -*- coding: utf-8
"""Resolve mutation candidates from evidence-grounded policies."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from minidrifter.verification.subject_override_fields import norm_field as _norm_field
from minidrifter.verification.subject_override_mutation import (
    SIBLING_FIELD_HINTS,
    _is_digits,
    _sibling_value,
)

FAR_JUMP_OFFSETS = (20_000_000, 5_000_000, 1_000_000, 100_000)


def _pool_values_for_field(field: str, pool: Dict[str, Any]) -> List[str]:
    nf = _norm_field(field)
    vals: List[str] = []
    seen = set()
    for k, v in (pool or {}).items():
        if v in (None, ''):
            continue
        kn = _norm_field(k)
        if kn == nf or kn in SIBLING_FIELD_HINTS.get(nf, []):
            s = str(v)
            if s not in seen:
                seen.add(s)
                vals.append(s)
    return vals


def resolve_candidate(
    field: str,
    original: str,
    policy: str,
    *,
    pool: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[str], str]:
    pool = pool or {}
    orig = str(original or '')

    if policy == 'sibling_subject_value':
        sib = _sibling_value(field, orig, pool)
        if sib and sib != orig:
            return sib, policy

    if policy in ('pool_alternate', 'subject_pool', 'har_pool'):
        for val in _pool_values_for_field(field, pool):
            if val != orig:
                return val, policy

    if policy == 'authorized_seed':
        seed = pool.get('_cats_authorized_seed') or pool.get('authorized_member_id_seed')
        if seed and str(seed) != orig:
            return str(seed), policy

    if _is_digits(orig):
        n = int(orig)
        if policy == 'numeric_increment' or policy == 'numeric_increment_legacy':
            alt = str(n + 1)
            if alt != orig:
                return alt, policy
        if policy == 'numeric_decrement':
            alt = str(n - 1) if n > 0 else None
            if alt and alt != orig:
                return alt, policy
        if policy == 'numeric_far_jump_down':
            for off in FAR_JUMP_OFFSETS:
                alt = str(max(1, n - off))
                if alt != orig:
                    return alt, policy
        if policy == 'numeric_far_jump_up':
            for off in FAR_JUMP_OFFSETS:
                alt = str(n + off)
                if alt != orig:
                    return alt, policy

    return None, f'no_candidate_for_{policy}'


def materialize_test_cases(
    plan: Dict[str, Any],
    *,
    original: str,
    pool: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Expand one binding test plan into ordered executable mutation cases."""
    field = plan.get('mutation_field') or ''
    policies = list(plan.get('candidate_policies') or [])
    cases: List[Dict[str, Any]] = []
    seen_vals = set()
    for i, policy in enumerate(policies):
        val, strat = resolve_candidate(field, original, policy, pool=pool)
        if not val or val in seen_vals:
            continue
        seen_vals.add(val)
        cases.append({
            'case_id': f"{plan.get('plan_id') or 'tc'}-{i}-{strat}",
            'plan_id': plan.get('plan_id'),
            'mutation_field': field,
            'mutated_value': val,
            'candidate_policy': strat,
            'expected_validity': plan.get('expected_validity') or 'medium',
            'oracle': plan.get('oracle') or {},
            'invalid_mutant_policy': plan.get('invalid_mutant_policy'),
        })
    return cases
