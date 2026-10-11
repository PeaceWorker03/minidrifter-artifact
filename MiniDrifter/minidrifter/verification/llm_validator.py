# -*- coding: utf-8 -*-
"""Validate LLM verification outputs — LLM-advisory, rules-authoritative."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.core.schema import SCHEMA_VERSION

ALLOWED_ACTIONS = frozenset({
    'continue_campaign', 'diagnostic_mode', 'refresh_baseline', 'refresh_baseline_field',
    'schema_repair', 'expand_frontier', 'switch_entry_api', 'pause_host',
    'collect_first_hop_material', 'execute_when_ready', 'version_baseline_repair',
})

FORBIDDEN_SCRIPT_PATTERNS = re.compile(
    r'\b(os\.system|subprocess|exec\(|eval\(|__import__|rm\s+-rf|curl\s+.*\|\s*sh)\b',
    re.I,
)

ALLOWED_MUTATIONS = None  # loaded from pack


def _load_mutation_policy() -> Dict[str, Any]:
    path = Path(__file__).resolve().parent / 'packs' / 'mutation_policy.json'
    return json.loads(path.read_text(encoding='utf-8'))


def validate_test_proposals(
    payload: Dict[str, Any],
    *,
    pack_id: str,
    allowed_api_ids: Set[str],
    allowed_parent_test_ids: Set[str],
) -> Tuple[bool, List[str], List[Dict[str, Any]]]:
    errors: List[str] = []
    approved: List[Dict[str, Any]] = []
    if not isinstance(payload, dict):
        return False, ['payload must be object'], []

    if payload.get('pack_id') and payload.get('pack_id') != pack_id:
        errors.append('pack_id mismatch')

    policy = _load_mutation_policy()
    allowed_mut = set(policy.get('allowed_mutations') or [])
    param_re = re.compile(policy.get('allowed_param_ref_pattern') or r'^\$baseline\.')
    max_n = int(policy.get('max_llm_proposals_per_campaign') or 5)

    for i, prop in enumerate(payload.get('proposals') or []):
        if len(approved) >= max_n:
            break
        pid = prop.get('proposal_id') or f'prop_{i}'
        api_id = prop.get('api_id')
        parent = prop.get('parent_test_id')
        mut = prop.get('mutation_type')

        if api_id not in allowed_api_ids:
            errors.append(f'{pid}: api_id not in campaign allowlist')
            continue
        if parent and parent not in allowed_parent_test_ids:
            errors.append(f'{pid}: parent_test_id not in campaign')
            continue
        if mut not in allowed_mut:
            errors.append(f'{pid}: mutation_type not allowed: {mut}')
            continue

        has_intent = bool(prop.get('mutation_operator') and prop.get('target_field') and prop.get('selector'))
        overrides = prop.get('param_overrides') or {}

        if has_intent:
            op = prop.get('mutation_operator')
            if op and op not in set(policy.get('allowed_operators') or []):
                errors.append(f'{pid}: mutation_operator not allowed: {op}')
                continue
            selector = prop.get('selector') or {}
            if not selector.get('different_from') and op == 'replace_with_same_type_different_value':
                errors.append(f'{pid}: selector.different_from required for replace operator')
                continue
        elif overrides:
            bad_params = []
            for k, v in overrides.items():
                if not isinstance(v, str) or not param_re.match(v):
                    bad_params.append(k)
            if bad_params:
                errors.append(f'{pid}: legacy param_overrides must use $baseline.* refs: {bad_params}')
                continue
        else:
            errors.append(f'{pid}: proposal must include intent (operator+selector) or legacy param_overrides')
            continue

        script = prop.get('script_hint') or ''
        if script and FORBIDDEN_SCRIPT_PATTERNS.search(script):
            errors.append(f'{pid}: forbidden script pattern')
            continue

        approved.append({
            **prop,
            'proposal_id': pid,
            'validation_status': 'approved',
            'source': 'llm_test_agent',
        })

    ok = bool(approved) or not (payload.get('proposals') or [])
    return ok, errors, approved


def validate_feedback_plan(
    payload: Dict[str, Any],
    *,
    pack_id: str,
    allowed_api_ids: Set[str],
    rule_actions: List[Dict[str, Any]],
) -> Tuple[bool, List[str], Dict[str, Any]]:
    errors: List[str] = []
    if not isinstance(payload, dict):
        return False, ['payload must be object'], {}

    if payload.get('pack_id') and payload.get('pack_id') != pack_id:
        errors.append('pack_id mismatch')

    rule_action_names = {a.get('action') for a in rule_actions}
    validated_actions: List[Dict[str, Any]] = []

    for act in payload.get('recommended_actions') or []:
        name = act.get('action')
        if name not in ALLOWED_ACTIONS:
            errors.append(f'action not allowed: {name}')
            continue
        if name in {'switch_entry_api', 'schema_repair'}:
            targets = act.get('target_apis') or act.get('target_api_ids') or []
            if targets and not set(targets).issubset(allowed_api_ids):
                errors.append(f'target apis not in allowlist for {name}')
                continue
        validated_actions.append({
            **act,
            'source': 'llm_feedback_agent',
            'authority': 'advisory',
        })

    followups = []
    for fu in payload.get('followup_test_hints') or []:
        if fu.get('api_id') and fu['api_id'] not in allowed_api_ids:
            errors.append(f'followup api_id not allowed: {fu.get("api_id")}')
            continue
        followups.append({**fu, 'source': 'llm_feedback_agent'})

    conf = payload.get('confidence')
    if conf is not None and not (0 <= float(conf) <= 1):
        errors.append('confidence out of range')

    cleaned = {
        'pack_id': pack_id,
        'diagnosis': str(payload.get('diagnosis') or '')[:2000],
        'root_cause_hypothesis': str(payload.get('root_cause_hypothesis') or '')[:1000],
        'recommended_actions': validated_actions,
        'followup_test_hints': followups,
        'confidence': conf,
        'validation_errors': errors,
        'agrees_with_rule_plan': payload.get('agrees_with_rule_plan'),
    }
    ok = len(validated_actions) > 0 or bool(cleaned.get('diagnosis'))
    return ok, errors, cleaned


def validate_workflow_emit(
    emit: Dict[str, Any],
    *,
    allowed_api_ids: Set[str],
) -> tuple[bool, List[str], Optional[str]]:
    """Validate A2 workflow emit — LLM advisory, api_id must be in rule candidates."""
    errors: List[str] = []
    if not isinstance(emit, dict):
        return False, ['emit must be object'], None

    if emit.get('stop'):
        return True, [], None

    api_id = emit.get('next_api_id')
    if not api_id:
        errors.append('next_api_id required when stop=false')
        return False, errors, None
    if api_id not in allowed_api_ids:
        errors.append(f'next_api_id not in rule candidate allowlist: {api_id}')
        return False, errors, None

    return True, [], api_id


def parse_strace_payload(payload: Dict[str, Any], *, expected_stage: str) -> tuple[Dict[str, Any], List[str]]:
    """Extract S-TRACE from LLM payload; tolerate flat emit-only responses."""
    errors: List[str] = []
    if not isinstance(payload, dict):
        return {}, ['payload must be object']

    if payload.get('stage') == expected_stage and payload.get('steps'):
        trace = payload
    elif payload.get('emit'):
        trace = {
            'stage': expected_stage,
            'steps': payload.get('steps') or [
                {'step': 'observe', 'content': str(payload.get('rationale') or 'LLM response')[:500]},
                {'step': 'emit', 'content': 'see emit block'},
            ],
            'confidence': payload.get('confidence'),
            'disagreements': payload.get('disagreements') or [],
            'emit': payload.get('emit'),
        }
    else:
        trace = {
            'stage': expected_stage,
            'steps': [{'step': 'emit', 'content': 'legacy flat payload'}],
            'emit': payload,
        }

    from minidrifter.verification.llm_trace import validate_trace_shape
    errors.extend(validate_trace_shape(trace))
    return trace, errors


def merge_feedback_into_plan(
    rule_plan: Dict[str, Any],
    llm_feedback: Dict[str, Any],
    *,
    llm_record: Dict[str, Any],
) -> Dict[str, Any]:
    """Rule plan authoritative; LLM adds advisory layer."""
    merged = dict(rule_plan)
    merged['schema_version'] = SCHEMA_VERSION
    merged['llm_enriched'] = True
    merged['authority_model'] = {
        'rule_layer': 'authoritative for safety gates and action allowlist',
        'llm_layer': 'advisory for diagnosis, schema repair hints, follow-up tests',
        'merge_policy': 'LLM cannot override rule priorities or bypass safety',
    }
    merged['llm_feedback'] = {
        'generated_at': llm_record.get('generated_at'),
        'model': llm_record.get('model'),
        'status': llm_record.get('status'),
        'diagnosis': llm_feedback.get('diagnosis'),
        'root_cause_hypothesis': llm_feedback.get('root_cause_hypothesis'),
        'confidence': llm_feedback.get('confidence'),
        'agrees_with_rule_plan': llm_feedback.get('agrees_with_rule_plan'),
        'advisory_actions': llm_feedback.get('recommended_actions') or [],
        'followup_test_hints': llm_feedback.get('followup_test_hints') or [],
        'validation_errors': llm_feedback.get('validation_errors') or [],
    }

    # Promote specific LLM actions only when they don't conflict with safety
    rule_names = {a.get('action') for a in merged.get('recommended_actions') or []}
    for act in llm_feedback.get('recommended_actions') or []:
        name = act.get('action')
        if name in {'refresh_baseline_field', 'version_baseline_repair', 'schema_repair'}:
            if name not in rule_names:
                merged.setdefault('recommended_actions', []).insert(0, {
                    **act,
                    'merged_from': 'llm_advisory',
                    'priority': act.get('priority') or 'P1',
                })
                rule_names.add(name)

    return merged
