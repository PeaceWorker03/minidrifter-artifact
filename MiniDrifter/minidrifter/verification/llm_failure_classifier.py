# -*- coding: utf-8
"""LLM failure diagnosis — enum labels only, universal failure taxonomy."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

FAILURE_LABELS = frozenset({
    'AUTH_EXPIRED',
    'MISSING_OBJECT',
    'BUSINESS_STATE_BLOCKED',
    'APP_VERSION_BLOCKED',
    'REQUEST_SCHEMA_ERROR',
    'TRANSPORT_ERROR',
    'ORACLE_UNCERTAIN',
    'SAFETY_BLOCKED',
    'BINDING_DRIFT_SIGNAL',
    'NONE',
})


def map_rule_diagnosis_to_label(
    *,
    call_outcome: str = '',
    failure_class: str = '',
    missing_fields: Optional[List[str]] = None,
    binding_delta: str = '',
) -> str:
    """Deterministic failure label — LLM must pick from same enum when used."""
    fc = (failure_class or call_outcome or '').lower()
    if fc in {'auth_expired', 'auth_required'}:
        return 'AUTH_EXPIRED'
    if fc in {'validation_error', 'build_failed', 'param_schema_mismatch'}:
        return 'REQUEST_SCHEMA_ERROR'
    if fc in {'transport_error', 'transport_url_routing'}:
        return 'TRANSPORT_ERROR'
    if fc in {'business_state_blocked', 'business_empty'}:
        return 'BUSINESS_STATE_BLOCKED'
    if fc == 'app_version_blocked':
        return 'APP_VERSION_BLOCKED'
    if fc == 'safety_blocked':
        return 'SAFETY_BLOCKED'
    if missing_fields:
        return 'MISSING_OBJECT'
    if binding_delta in {
        'binding_mismatch_under_mutation', 'binding_drift_confirmed', 'mutation_accepted',
    }:
        return 'BINDING_DRIFT_SIGNAL'
    if fc in {'unknown_response', 'oracle_uncertain'}:
        return 'ORACLE_UNCERTAIN'
    return 'NONE'


def llm_failure_prompt_context(hop_verdict: Dict[str, Any]) -> Dict[str, Any]:
    """Compact context for LLM failure classifier — enum output enforced in prompt."""
    corr = hop_verdict.get('param_correlation') or {}
    return {
        'allowed_labels': sorted(FAILURE_LABELS),
        'rule_label': map_rule_diagnosis_to_label(
            call_outcome=hop_verdict.get('call_outcome') or '',
            failure_class=hop_verdict.get('failure_class') or '',
            missing_fields=[m.get('field') for m in hop_verdict.get('missing_materials') or []],
            binding_delta=corr.get('response_delta') or '',
        ),
        'path': hop_verdict.get('path'),
        'node_health': hop_verdict.get('node_health'),
    }
