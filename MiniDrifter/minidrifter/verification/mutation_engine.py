# -*- coding: utf-8 -*-
"""Materialize LLM mutation intents into executable test cases with no-op guards."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from minidrifter.core.utils import stable_id
from minidrifter.verification.object_pool import object_pool_select, resolve_baseline_ref
from minidrifter.verification.request_builder import baseline_pool, resolve_params
from minidrifter.verification.safety_policy import evaluate_test_safety

MUTATION_OPERATORS = frozenset({
    'replace_with_same_type_different_value',
    'remove_optional_param',
    'remove_binding_param',
    'corrupt_param',
    'remove_params',
    'baseline_replay',
})


def is_noop_mutation(
    parent_params: Dict[str, Any],
    mutated_params: Dict[str, Any],
    baseline_context: Dict[str, Any],
) -> bool:
    pool = baseline_pool(baseline_context)
    resolved_parent, _ = resolve_params(parent_params or {}, pool)
    resolved_mutated, _ = resolve_params(mutated_params or {}, pool)
    return resolved_parent == resolved_mutated


def _apply_operator(
    operator: str,
    target_field: str,
    parent_params: Dict[str, Any],
    *,
    selected_value: Optional[str] = None,
) -> Dict[str, Any]:
    params = dict(parent_params or {})
    key = target_field
    if key not in params:
        for k in params:
            if k.lower() == target_field.lower():
                key = k
                break

    if operator == 'remove_optional_param' or operator == 'remove_binding_param':
        params.pop(key, None)
        return params

    if operator == 'corrupt_param':
        corrupt = selected_value or 'deadbeefdeadbeefdeadbeefdeadbeef'
        if key in params:
            params[key] = corrupt
        else:
            params[target_field] = corrupt
        return params

    if operator == 'remove_params':
        for rf in (selected_value or []):
            params.pop(rf, None)
            for k in list(params):
                if k.lower() == str(rf).lower():
                    params.pop(k, None)
        return params

    if operator == 'replace_with_same_type_different_value':
        if selected_value is None:
            return params
        if key in params:
            params[key] = selected_value
        else:
            params[target_field] = selected_value
        return params

    return params


TYPE_TO_OPERATOR = {
    'M1_missing_optional_param': 'remove_optional_param',
    'M2_missing_binding_param': 'remove_binding_param',
    'M5_same_account_object_substitution': 'replace_with_same_type_different_value',
    'M7_subject_object_mismatch': 'replace_with_same_type_different_value',
    'M8_weaken_credential_guard': 'corrupt_param',
    'M0_baseline_replay': 'baseline_replay',
}


def _mutation_param_bag(test_case: Dict[str, Any]) -> tuple[Dict[str, Any], str]:
    """Return the param dict to mutate — must match request_builder wire source."""
    params = dict(test_case.get('params') or {})
    body = dict(test_case.get('body_params') or {})
    method = (test_case.get('method') or 'GET').upper()
    style = test_case.get('transport_style') or ''
    use_form_body = (
        bool(body)
        and method in {'POST', 'PUT', 'PATCH'}
        and (
            style in {'form_urlencoded', 'form_cid_q_sign', 'form_encrypted_body'}
            or test_case.get('body_params')
        )
    )
    if use_form_body:
        return body, 'body_params'
    if body and not params:
        return body, 'body_params'
    return params, 'params'


def materialize_mutation_proposal(
    proposal: Dict[str, Any],
    parent_test: Dict[str, Any],
    object_pool: Dict[str, Any],
    baseline_context: Dict[str, Any],
    *,
    index: int = 0,
) -> Dict[str, Any]:
    """Turn intent-level proposal into test case, blocked, or no-op."""
    param_bag, bag_key = _mutation_param_bag(parent_test)
    parent_params = dict(param_bag)
    mutation_type = proposal.get('mutation_type')
    operator = proposal.get('mutation_operator') or TYPE_TO_OPERATOR.get(mutation_type or '')

    if not operator and proposal.get('param_overrides'):
        mutated = dict(parent_params)
        mutated.update(proposal.get('param_overrides') or {})
        if is_noop_mutation(parent_params, mutated, baseline_context):
            return {'status': 'blocked', 'reason': 'no_op_mutation', 'proposal_id': proposal.get('proposal_id')}
        tc = _build_test_case(proposal, parent_test, mutated, baseline_context, index=index)
        return {'status': 'materialized', 'test_case': tc}

    if not operator:
        return {'status': 'blocked', 'reason': 'unsupported_operator', 'proposal_id': proposal.get('proposal_id')}

    target_field = proposal.get('target_field') or _infer_target_field(proposal, parent_params)
    selector = proposal.get('selector') or {}

    remove_fields = proposal.get('remove_fields') or []
    if remove_fields:
        mutated = _apply_operator('remove_params', target_field, parent_params, selected_value=remove_fields)
    elif operator == 'corrupt_param':
        corrupt = (
            proposal.get('corrupt_value')
            or (proposal.get('param_overrides') or {}).get(target_field)
            or 'deadbeefdeadbeefdeadbeefdeadbeef'
        )
        mutated = _apply_operator(operator, target_field, parent_params, selected_value=corrupt)
    elif operator in {'remove_optional_param', 'remove_binding_param'}:
        mutated = _apply_operator(operator, target_field, parent_params)
    elif operator == 'replace_with_same_type_different_value':
        selected = object_pool_select(object_pool, selector, baseline_context=baseline_context)
        if not selected and selector.get('allow_synthetic'):
            sel2 = dict(selector)
            sel2['required_pool'] = 'negative_pool'
            selected = object_pool_select(object_pool, sel2, baseline_context=baseline_context)
        if not selected:
            sel3 = dict(selector)
            sel3['required_pool'] = 'negative_pool'
            sel3.pop('field_class', None)
            selected = object_pool_select(object_pool, sel3, baseline_context=baseline_context)
        if not selected:
            blocked_if = proposal.get('blocked_if') or []
            base_val = None
            if baseline_context and target_field:
                base_val = resolve_baseline_ref(f'$baseline.{target_field}', baseline_context)
                if base_val is None:
                    from minidrifter.verification.object_pool import _baseline_value
                    base_val = _baseline_value(baseline_context, target_field)
            if base_val is None:
                raw = parent_params.get(target_field)
                if raw is not None and not str(raw).startswith('$'):
                    base_val = str(raw)
            if selector.get('allow_synthetic') and base_val:
                if str(base_val).isdigit():
                    synthetic = str(int(base_val) + 1) if len(str(base_val)) < 12 else '9999999999'
                else:
                    synthetic = f'{base_val}_alt'
                if synthetic != str(base_val):
                    mutated = _apply_operator(operator, target_field, parent_params, selected_value=synthetic)
                elif 'no_distinct_candidate' in blocked_if or not proposal.get('param_overrides'):
                    return {
                        'status': 'blocked',
                        'reason': 'no_distinct_candidate',
                        'proposal_id': proposal.get('proposal_id'),
                        'target_field': target_field,
                    }
                else:
                    mutated = dict(parent_params)
                    mutated.update(proposal.get('param_overrides') or {})
            elif 'no_distinct_candidate' in blocked_if or not proposal.get('param_overrides'):
                return {
                    'status': 'blocked',
                    'reason': 'no_distinct_candidate',
                    'proposal_id': proposal.get('proposal_id'),
                    'target_field': target_field,
                }
            else:
                mutated = dict(parent_params)
                mutated.update(proposal.get('param_overrides') or {})
        else:
            mutated = _apply_operator(operator, target_field, parent_params, selected_value=selected['value'])
    elif operator == 'baseline_replay':
        mutated = dict(parent_params)
    else:
        return {'status': 'blocked', 'reason': 'unsupported_operator', 'proposal_id': proposal.get('proposal_id')}

    if is_noop_mutation(parent_params, mutated, baseline_context):
        return {'status': 'blocked', 'reason': 'no_op_mutation', 'proposal_id': proposal.get('proposal_id')}

    verdict = evaluate_test_safety(
        {**parent_test, 'params': mutated},
        baseline_context=baseline_context,
        only_safe=True,
        mode='dry-run',
    )
    if not verdict.allowed:
        return {
            'status': 'blocked',
            'reason': 'unsafe_side_effect',
            'proposal_id': proposal.get('proposal_id'),
            'safety_reasons': verdict.reasons,
        }

    tc = _build_test_case(proposal, parent_test, mutated, baseline_context, index=index)
    tc[bag_key] = mutated
    if bag_key == 'body_params':
        tc['params'] = dict(parent_test.get('params') or {})
        for k in list(tc['params']):
            if k.lower() == target_field.lower():
                tc['params'].pop(k)
    tc['mutation_operator'] = operator
    tc['selector'] = selector
    if operator == 'replace_with_same_type_different_value' and selector:
        tc['mutation_note'] = f"replaced {target_field} with distinct pool candidate"
    return {'status': 'materialized', 'test_case': tc}


def materialize_proposals(
    proposals: List[Dict[str, Any]],
    test_cases_by_id: Dict[str, Dict[str, Any]],
    object_pool: Dict[str, Any],
    baseline_context: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    materialized: List[Dict[str, Any]] = []
    blocked: List[Dict[str, Any]] = []
    for i, prop in enumerate(proposals):
        parent = test_cases_by_id.get(prop.get('parent_test_id') or '')
        if not parent:
            blocked.append({'proposal_id': prop.get('proposal_id'), 'reason': 'missing_parent'})
            continue
        result = materialize_mutation_proposal(prop, parent, object_pool, baseline_context, index=i)
        if result.get('status') == 'materialized':
            materialized.append(result['test_case'])
        else:
            blocked.append(result)
    return materialized, blocked


def _infer_target_field(proposal: Dict[str, Any], parent_params: Dict[str, Any]) -> str:
    overrides = proposal.get('param_overrides') or {}
    if overrides:
        return next(iter(overrides.keys()))
    for k in parent_params:
        if k.lower() in {'userid', 'user_id', 'orderid', 'invoiceid', 'deviceid'}:
            return k
    return 'userId'


def _build_test_case(
    proposal: Dict[str, Any],
    parent: Dict[str, Any],
    params: Dict[str, Any],
    baseline_context: Dict[str, Any],
    *,
    index: int,
) -> Dict[str, Any]:
    return {
        **parent,
        'test_id': stable_id('tc', proposal.get('proposal_id'), parent.get('api_id'), index),
        'parent_test_id': parent.get('test_id'),
        'mutation_type': proposal.get('mutation_type'),
        'target_field': proposal.get('target_field'),
        'params': params,
        'test_stage': 'mutation',
        'llm_proposal_id': proposal.get('proposal_id'),
        'llm_rationale': proposal.get('rationale'),
        'proposal_type': proposal.get('proposal_type') or 'binding_test',
        'expected_secure_behavior': proposal.get('expected_secure_behavior') or [],
        'source': 'llm_test_agent',
    }
