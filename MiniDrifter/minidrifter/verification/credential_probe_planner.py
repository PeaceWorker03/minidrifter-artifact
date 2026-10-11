# -*- coding: utf-8
"""Intelligent credential weakening + identity binding probe planner."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from minidrifter.core.utils import stable_id
from minidrifter.verification.api_guard_beliefs import ApiGuardBeliefs, classify_guard_field
from minidrifter.verification.finding_escalation_planner import (
    MAX_IDENTITY_M7_PROBES,
    STABLE_CREDENTIAL_PARAM_RE,
    bindable_fields_for_api,
)
from minidrifter.verification.mutation_engine import materialize_mutation_proposal
from minidrifter.verification.mutation_target_selector import (
    prioritize_mutation_fields,
    select_chain_strict_m7_fields,
)

# Identity fields most indicative of horizontal drift (prefer over platform userId).
IDENTITY_PROBE_ORDER = (
    'loginCustomerId',
    'customerId',
    'CustomerId',
    'fromCustomerId',
    'userId',
    'UserId',
    'platformUserId',
    'memberId',
    'openId',
)

M8_CORRUPT_VALUE = 'deadbeefdeadbeefdeadbeefdeadbeef'


def _param_keys(template: Dict[str, Any], parent: Dict[str, Any]) -> Dict[str, str]:
    """Lowercase -> actual key name."""
    out: Dict[str, str] = {}
    plain = template.get('plain_template') or {}
    for bag in (parent.get('params'), parent.get('body_params'), plain.get('params'), plain.get('body_params')):
        if isinstance(bag, dict):
            for k in bag:
                out[str(k).lower()] = str(k)
    return out


def _find_param_key(keys: Dict[str, str], *candidates: str) -> Optional[str]:
    for c in candidates:
        if c.lower() in keys:
            return keys[c.lower()]
    for kl, actual in keys.items():
        gk = classify_guard_field(actual)
        if gk and gk in candidates:
            return actual
    return None


def _credential_weakening_steps(
    parent: Dict[str, Any],
    template: Dict[str, Any],
    beliefs: Optional[ApiGuardBeliefs] = None,
) -> List[Dict[str, Any]]:
    """Ordered M8 steps: corrupt signature → drop signature → drop sig+nonce+ts."""
    keys = _param_keys(template, parent)
    path = parent.get('path') or template.get('path') or ''
    api_id = parent.get('api_id') or template.get('api_id') or ''
    beliefs = beliefs or ApiGuardBeliefs()

    steps: List[Dict[str, Any]] = []
    sig_key = _find_param_key(keys, 'signature', 'sign')
    nonce_key = _find_param_key(keys, 'nonce')
    ts_key = _find_param_key(keys, 'timestamp', 'timespan')

    if sig_key and not beliefs.should_skip_credential_step(path, guard_kind='signature', api_id=api_id):
        steps.append({
            'step_id': 'corrupt_signature',
            'guard_kind': 'signature',
            'mutation_type': 'M8_weaken_credential_guard',
            'mutation_operator': 'corrupt_param',
            'target_field': sig_key,
            'param_overrides': {sig_key: M8_CORRUPT_VALUE},
            'rationale': 'Probe whether signature field is enforced (corrupt value, hold rest stable)',
            'stop_if_success': True,
        })
        steps.append({
            'step_id': 'drop_signature',
            'guard_kind': 'signature',
            'mutation_type': 'M8_weaken_credential_guard',
            'mutation_operator': 'remove_optional_param',
            'target_field': sig_key,
            'rationale': 'Probe whether signature param is required at all',
            'skip_if_prior': 'signature_ignored',
        })

    drop_batch: Dict[str, Any] = {}
    batch_fields: List[str] = []
    for gk, pkey in (('signature', sig_key), ('nonce', nonce_key), ('timestamp', ts_key)):
        if not pkey:
            continue
        if beliefs.should_skip_credential_step(path, guard_kind=gk, api_id=api_id):
            continue
        drop_batch[pkey] = None
        batch_fields.append(pkey)

    if len(batch_fields) >= 2:
        steps.append({
            'step_id': 'drop_sig_nonce_ts',
            'guard_kind': 'signature',
            'mutation_type': 'M8_weaken_credential_guard',
            'mutation_operator': 'remove_params',
            'target_field': batch_fields[0],
            'param_overrides': {k: None for k in batch_fields},
            'rationale': 'Probe whether anti-replay triplet (signature/nonce/timestamp) is enforced',
            'skip_if_prior': 'signature_ignored',
        })

    return steps


def _identity_probe_steps(
    parent: Dict[str, Any],
    template: Dict[str, Any],
    *,
    ir_card: Optional[Dict[str, Any]] = None,
    beliefs: Optional[ApiGuardBeliefs] = None,
    chain_doc: Optional[Dict[str, Any]] = None,
    chain_strict: bool = False,
) -> List[Dict[str, Any]]:
    """M7 identity mismatch probes in smart field order."""
    beliefs = beliefs or ApiGuardBeliefs()
    path = parent.get('path') or ''
    api_id = parent.get('api_id') or ''
    keys = _param_keys(template, parent)
    param_keys_lower = set(keys.keys())

    bindable = bindable_fields_for_api(template, ir_card)
    bindable_by_field = {b['field']: b for b in bindable}

    candidate_fields: List[str] = []
    for pref in IDENTITY_PROBE_ORDER:
        if pref.lower() in param_keys_lower:
            actual = keys[pref.lower()]
            if actual not in candidate_fields:
                candidate_fields.append(actual)
    for bf in bindable:
        f = bf['field']
        if f not in candidate_fields and not STABLE_CREDENTIAL_PARAM_RE.match(f):
            candidate_fields.append(f)
    for kl, actual in keys.items():
        if actual not in candidate_fields and not STABLE_CREDENTIAL_PARAM_RE.match(actual):
            candidate_fields.append(actual)

    if chain_strict and chain_doc:
        ordered_fields = select_chain_strict_m7_fields(
            candidate_fields, chain_doc=chain_doc, max_fields=MAX_IDENTITY_M7_PROBES,
        )
    else:
        ordered_fields = prioritize_mutation_fields(candidate_fields, chain_doc=chain_doc)

    steps: List[Dict[str, Any]] = []
    for field in ordered_fields:
        if len(steps) >= MAX_IDENTITY_M7_PROBES:
            break
        if beliefs.should_skip_identity_field(path, field, api_id=api_id):
            continue
        if STABLE_CREDENTIAL_PARAM_RE.match(field):
            continue
        bf = bindable_by_field.get(field, {'role': 'subject_id'})
        steps.append({
            'step_id': f'm7_{field}',
            'guard_kind': 'identity',
            'mutation_type': 'M7_subject_object_mismatch',
            'mutation_operator': 'replace_with_same_type_different_value',
            'target_field': field,
            'bindable_role': bf.get('role'),
            'selector': {
                'field': field,
                'different_from': f'$baseline.{field}',
                'required_pool': 'negative_pool',
                'allow_synthetic': True,
            },
            'rationale': (
                f"Identity binding drift probe on {bf.get('role', 'identity')} field {field}; "
                f"session/crypto params held stable"
            ),
            'stop_if_rejected': True,
        })
    return steps


def _materialize_step(
    step: Dict[str, Any],
    parent: Dict[str, Any],
    *,
    seed_id: str,
    api_id: str,
    object_pool: Dict[str, Any],
    baseline_context: Dict[str, Any],
    index: int,
) -> Dict[str, Any]:
    overrides = step.get('param_overrides') or {}
    remove_fields = [k for k, v in overrides.items() if v is None]
    corrupt_val = None
    if step.get('mutation_operator') == 'corrupt_param' and step.get('target_field'):
        corrupt_val = overrides.get(step['target_field']) or M8_CORRUPT_VALUE

    proposal = {
        'proposal_id': stable_id('cred', seed_id, step.get('step_id'), api_id),
        'parent_test_id': parent.get('test_id'),
        'api_id': api_id,
        'proposal_type': 'credential_probe',
        'mutation_type': step.get('mutation_type'),
        'mutation_operator': step.get('mutation_operator'),
        'target_field': step.get('target_field'),
        'target_fields': step.get('target_fields'),
        'selector': step.get('selector'),
        'param_overrides': {k: v for k, v in overrides.items() if v is not None} or None,
        'remove_fields': remove_fields or None,
        'corrupt_value': corrupt_val,
        'rationale': step.get('rationale'),
        'probe_step_id': step.get('step_id'),
        'guard_kind': step.get('guard_kind'),
        'blocked_if': ['unsafe_side_effect'],
    }
    result = materialize_mutation_proposal(
        proposal, parent, object_pool, baseline_context, index=index,
    )
    if result.get('status') == 'materialized':
        result['step'] = step
    return result


def plan_intelligent_binding_campaign(
    seed: Dict[str, Any],
    m0_test_case: Dict[str, Any],
    *,
    baseline_context: Dict[str, Any],
    object_pool: Dict[str, Any],
    beliefs: Optional[ApiGuardBeliefs] = None,
    ir_card: Optional[Dict[str, Any]] = None,
    chain_doc: Optional[Dict[str, Any]] = None,
    chain_strict: bool = False,
    include_m8: bool = True,
    include_m7: bool = True,
) -> Dict[str, Any]:
    """Build ordered probe plan: M8 credential ladder then M7 identity tests."""
    template = seed.get('template') or {}
    api_id = seed.get('api_id') or m0_test_case.get('api_id')
    path = seed.get('path') or m0_test_case.get('path') or ''
    seed_id = seed.get('seed_id') or api_id or 'seed'
    beliefs = beliefs or ApiGuardBeliefs()

    skip_reason = beliefs.should_skip_api_mutations(path, api_id=api_id)
    if skip_reason:
        return {
            'seed_id': seed_id,
            'api_id': api_id,
            'path': path,
            'skipped': True,
            'skip_reason': skip_reason,
            'steps': [],
            'test_cases': [],
        }

    steps: List[Dict[str, Any]] = []
    if include_m8:
        raw_m8 = _credential_weakening_steps(m0_test_case, template, beliefs)
        for step in raw_m8:
            prior = step.get('skip_if_prior')
            if prior == 'signature_ignored' and beliefs.signature_guard(path, api_id or '') == 'ignored':
                continue
            steps.append(step)
    if include_m7:
        steps.extend(_identity_probe_steps(
            m0_test_case, template,
            ir_card=ir_card, beliefs=beliefs,
            chain_doc=chain_doc, chain_strict=chain_strict,
        ))

    test_cases: List[Dict[str, Any]] = []
    blocked: List[Dict[str, Any]] = []
    for i, step in enumerate(steps):
        result = _materialize_step(
            step, m0_test_case,
            seed_id=seed_id, api_id=api_id or '',
            object_pool=object_pool,
            baseline_context=baseline_context,
            index=i + 1,
        )
        if result.get('status') == 'materialized':
            tc = result['test_case']
            tc['seed_id'] = seed_id
            tc['strategy_source'] = 'credential_probe_planner'
            tc['probe_step_id'] = step.get('step_id')
            tc['guard_kind'] = step.get('guard_kind')
            tc['stop_if_success'] = step.get('stop_if_success', False)
            tc['stop_if_rejected'] = step.get('stop_if_rejected', False)
            tc['skip_if_prior'] = step.get('skip_if_prior')
            if step.get('bindable_role'):
                tc['bindable_role'] = step['bindable_role']
            test_cases.append(tc)
        else:
            blocked.append({**result, 'step_id': step.get('step_id')})

    return {
        'seed_id': seed_id,
        'api_id': api_id,
        'path': path,
        'skipped': False,
        'm8_steps': sum(1 for s in steps if s.get('mutation_type', '').startswith('M8')),
        'm7_steps': sum(1 for s in steps if s.get('mutation_type', '').startswith('M7')),
        'steps': steps,
        'test_cases': test_cases,
        'blocked': blocked,
        'source': 'credential_probe_planner',
    }


def should_continue_probes(
    step: Dict[str, Any],
    analysis: Dict[str, Any],
    beliefs: ApiGuardBeliefs,
    *,
    api_id: str,
    path: str,
) -> tuple[bool, Optional[str]]:
    """Return (continue, stop_scope) — stop_scope is 'm8' | 'm7' | 'all' | None."""
    outcome = analysis.get('call_outcome') or ''
    fc = analysis.get('failure_class') or ''
    mut = step.get('mutation_type') or analysis.get('mutation_type') or ''

    if mut.startswith('M8') and step.get('stop_if_success') and outcome == 'business_success':
        return True, 'm8'
    if mut.startswith('M7') and step.get('stop_if_rejected'):
        if fc == 'binding_rejected' or (
            outcome != 'business_success'
            and fc in {'binding_rejected', 'validation_error', 'auth_expired'}
        ):
            return False, 'm7'
    if mut.startswith('M7') and outcome == 'business_success':
        return False, 'all'
    return True, None


def filter_remaining_probes(
    test_cases: List[Dict[str, Any]],
    stop_scope: Optional[str],
    after_step_id: Optional[str],
) -> List[Dict[str, Any]]:
    """Drop probes that should be skipped after an early-stop decision."""
    if not stop_scope:
        return test_cases
    out: List[Dict[str, Any]] = []
    past = after_step_id is None
    for tc in test_cases:
        sid = tc.get('probe_step_id') or ''
        if not past:
            if sid == after_step_id:
                past = True
            continue
        mut = tc.get('mutation_type') or ''
        if stop_scope == 'm8' and mut.startswith('M8'):
            continue
        if stop_scope in {'m7', 'all'} and mut.startswith('M7'):
            if stop_scope == 'all':
                continue
        if stop_scope == 'all':
            continue
        out.append(tc)
    return out
