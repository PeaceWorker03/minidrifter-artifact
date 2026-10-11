# -*- coding: utf-8 -*-
"""P4-fix-5 — safe subject identifier mutations (single-account pilot)."""
from __future__ import annotations

import copy
import re
from typing import Any, Dict, List, Optional, Tuple

from minidrifter.core.utils import stable_id
from minidrifter.verification.mutation_engine import _mutation_param_bag, is_noop_mutation
from minidrifter.verification.subject_override_fields import (
    FORBIDDEN_SUBJECT_FIELDS,
    field_allowed,
    norm_field as _norm_field,
)

SIBLING_FIELD_HINTS = {
    'memberid': ['userid', 'customerid', 'memberid'],
    'userid': ['memberid', 'customerid', 'userid'],
    'customerid': ['memberid', 'userid', 'customerid'],
    'openid': ['unionid', 'openid'],
    'unionid': ['openid', 'unionid'],
}


def _is_digits(val: str) -> bool:
    return bool(val) and str(val).isdigit()


def _sibling_value(
    field: str,
    original: str,
    pool: Dict[str, Any],
) -> Optional[str]:
    nf = _norm_field(field)
    for hint in SIBLING_FIELD_HINTS.get(nf, []):
        for pk, pv in pool.items():
            if _norm_field(pk) == hint and pv not in (None, '', original):
                return str(pv)
    return None


_FORMAT_HINT = re.compile(r'格式|format|pattern|invalid\s+param|参数错误', re.I)


def value_pattern(value: str) -> str:
    """Pattern of a source credential, taken from its baseline spelling."""
    text = str(value or '')
    if text.isdigit():
        return 'digits'
    if re.fullmatch(r'[A-Za-z]+[0-9]+', text):
        return 'prefixed_digits'
    if re.fullmatch(r'[0-9a-fA-F\-]{8,}', text):
        return 'hex'
    return 'text'


def _same_width_step(original: str, distance: int) -> str:
    """Keep width and charset. distance 1,2,3 steps by 1, 10, 100."""
    step = 10 ** max(int(distance) - 1, 0)
    width = len(original)
    if width == 0:
        return original
    nxt = (int(original) + step) % (10 ** width)
    return str(nxt).zfill(width)


def structure_preserving_value(original: str, distance: int) -> str:
    """Lightweight perturbation that does not change the baseline pattern."""
    text = str(original or '')
    kind = value_pattern(text)
    if kind == 'digits':
        return _same_width_step(text, distance)
    if kind == 'prefixed_digits':
        head, tail = re.fullmatch(r'([A-Za-z]+)([0-9]+)', text).groups()
        return head + _same_width_step(tail, distance)
    if kind == 'hex':
        alphabet = '0123456789abcdef'
        chars = list(text.lower())
        step = 10 ** max(int(distance) - 1, 0)
        for i in range(len(chars) - 1, -1, -1):
            if chars[i] in alphabet:
                chars[i] = alphabet[(alphabet.index(chars[i]) + (step % 16)) % 16]
                break
        return ''.join(chars)
    if not text:
        return text
    # Text keeps its length. A format error must not grow an ``_alt`` suffix.
    last = text[-1]
    if last.isalpha():
        base = 'a' if last.islower() else 'A'
        text = text[:-1] + chr(ord(base) + ((ord(last.lower()) - ord('a') + distance) % 26))
        return text
    return text[:-1] + str(distance % 10)


def refine_source_from_feedback(
    field: str,
    original: Any,
    *,
    category: str = '',
    body: str = '',
    distance: int = 1,
    pool: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[str], str]:
    """Improve ``mutate_subject_value`` with a structure constraint and a response step.

    The existing mutator still proposes the first distinct value. Digit, prefixed
    and hex credentials are then forced back onto that pattern, so a later
    format error widens the step (1, 10, 100) without a random substitution.
    """
    orig = str(original or '')
    if not orig:
        return None, 'empty_original'
    base, strategy = mutate_subject_value(field, orig, pool=pool)
    if base is None:
        return None, strategy
    kind = value_pattern(orig)
    format_hit = bool(_FORMAT_HINT.search(body or '')) or category in {
        'business_error', 'empty_data', 'unknown',
    }
    if kind == 'text' and not format_hit:
        return base, strategy
    refined = structure_preserving_value(orig, max(int(distance), 1))
    if refined == orig:
        return None, 'no_distinct_mutation'
    return refined, f'structure_preserving_{kind}'


def mutate_subject_value(
    field: str,
    original: Any,
    *,
    pool: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[str], str]:
    """Return (mutated_value, strategy) or (None, reason) if unsafe/no-op."""
    if _norm_field(field) in FORBIDDEN_SUBJECT_FIELDS:
        return None, 'forbidden_field'

    orig = str(original or '')
    pool = pool or {}
    if not orig:
        sibling = _sibling_value(field, '', pool)
        if sibling:
            orig = sibling
        else:
            return None, 'empty_original'
    sibling = _sibling_value(field, orig, pool)
    if sibling and sibling != orig:
        return sibling, 'sibling_subject_value'

    if _is_digits(orig):
        alt = str(int(orig) + 1) if len(orig) < 14 else '9999999999'
        if alt != orig:
            return alt, 'numeric_increment'

    if re.match(r'^[0-9a-f\-]{16,}$', orig, re.I):
        return f'{orig[:-1]}0' if len(orig) > 4 else f'{orig}_alt', 'hex_tail_mutate'

    alt = f'{orig}_alt'
    if alt != orig:
        return alt, 'string_suffix_mutate'

    return None, 'no_distinct_mutation'


SUBJECT_ONLY_PATH_MARKERS = ('personaldata', 'identitycard')


def apply_subject_mutation_to_test_case(
    m0_test_case: Dict[str, Any],
    *,
    field: str,
    mutated_value: str,
    baseline_context: Dict[str, Any],
    replay_entry: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Clone M0 test case with one subject field mutated on the wire bag."""
    from minidrifter.materials.envelope_wire import apply_envelope_preserving_mutation

    tc = copy.deepcopy(m0_test_case)
    apply_envelope_preserving_mutation(
        tc, field=field, mutated_value=mutated_value, replay_entry=replay_entry,
    )
    bag, _ = _mutation_param_bag(tc)
    key = field
    for k in bag:
        if _norm_field(k) == _norm_field(field):
            key = k
            break
    tc['test_id'] = stable_id('tc', tc.get('api_id'), 'subject_override_m7', field, mutated_value[:8])
    tc['test_stage'] = 'subject_override_m7'
    tc['mutation_type'] = 'M7_subject_override'
    tc['mutation_operator'] = 'replace_with_same_type_different_value'
    tc['target_field'] = key
    tc['subject_override'] = {
        'field': key,
        'original_value_redacted': '***',
        'mutated_value_redacted': '***',
        'strategy': tc.get('subject_override_strategy'),
    }
    if is_noop_mutation(
        _mutation_param_bag(m0_test_case)[0],
        _mutation_param_bag(tc)[0],
        baseline_context,
    ):
        tc['_noop_mutation'] = True
    return tc


def build_subject_mutation_plan(
    target: Dict[str, Any],
    m0_test_case: Dict[str, Any],
    *,
    baseline_context: Dict[str, Any],
    pool: Optional[Dict[str, Any]] = None,
    mutated_value: Optional[str] = None,
    strategy: Optional[str] = None,
    replay_entry: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Produce M7-subject test case or blocked reason."""
    field = target.get('selected_field') or ''
    original = target.get('selected_value')
    if original is None:
        bag, _ = _mutation_param_bag(m0_test_case)
        for k, v in bag.items():
            if _norm_field(k) == _norm_field(field):
                original = v
                break
    if original is None and pool:
        from minidrifter.verification.subject_override_fields import pool_value_for_subject_field
        original = pool_value_for_subject_field(field, pool)
    if mutated_value is not None:
        mutated, strat = mutated_value, strategy or 'cats_materialized'
    else:
        mutated, strat = mutate_subject_value(field, original, pool=pool)
    if not mutated:
        return {'status': 'blocked', 'reason': strat, 'field': field}

    m7 = apply_subject_mutation_to_test_case(
        m0_test_case, field=field, mutated_value=mutated, baseline_context=baseline_context,
        replay_entry=replay_entry,
    )
    m7['subject_override_strategy'] = strat
    if m7.get('_noop_mutation'):
        return {'status': 'blocked', 'reason': 'no_op_mutation', 'field': field}

    return {
        'status': 'ready',
        'field': field,
        'strategy': strat,
        'm7_test_case': m7,
        'original_value': original,
        'mutated_value': mutated,
    }


def build_subject_mutation_plans(
    target: Dict[str, Any],
    m0_test_case: Dict[str, Any],
    *,
    baseline_context: Dict[str, Any],
    pool: Optional[Dict[str, Any]] = None,
    binding_test_plan: Optional[Dict[str, Any]] = None,
    replay_entry: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """CATS: expand evidence-grounded plan into ordered mutation plans."""
    field = target.get('selected_field') or ''
    original = target.get('selected_value')
    if original is None:
        bag, _ = _mutation_param_bag(m0_test_case)
        for k, v in bag.items():
            if _norm_field(k) == _norm_field(field):
                original = v
                break
    if original is None and pool:
        from minidrifter.verification.subject_override_fields import pool_value_for_subject_field
        original = pool_value_for_subject_field(field, pool)

    if binding_test_plan:
        from minidrifter.verification.cats.candidate_builder import materialize_test_cases
        cases = materialize_test_cases(binding_test_plan, original=str(original or ''), pool=pool)
        plans: List[Dict[str, Any]] = []
        for case in cases:
            built = build_subject_mutation_plan(
                target, m0_test_case,
                baseline_context=baseline_context,
                pool=pool,
                mutated_value=case['mutated_value'],
                strategy=case['candidate_policy'],
                replay_entry=replay_entry,
            )
            if built.get('status') == 'ready':
                built['cats_case'] = case
                plans.append(built)
        if plans:
            return plans

    single = build_subject_mutation_plan(
        target, m0_test_case, baseline_context=baseline_context, pool=pool,
        replay_entry=replay_entry,
    )
    return [single] if single.get('status') == 'ready' else []
