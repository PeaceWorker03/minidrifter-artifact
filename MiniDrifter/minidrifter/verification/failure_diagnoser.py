# -*- coding: utf-8 -*-
"""Failure Diagnosis Engine — L0-L6 attribution and recovery actions."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

LAYER_ORDER = (
    'L0_build', 'L1_transport', 'L2_auth', 'L3_param',
    'L4_business_state', 'L5_binding', 'L6_planner',
)

FAILURE_TO_LAYER = {
    'build_failed': 'L0_build',
    'safety_blocked': 'L0_build',
    'transport_error': 'L1_transport',
    'transport_url_routing': 'L1_transport',
    'auth_expired': 'L2_auth',
    'app_version_blocked': 'L2_auth',
    'validation_error': 'L3_param',
    'param_schema_mismatch': 'L3_param',
    'business_state_blocked': 'L4_business_state',
    'unknown_response': 'L4_business_state',
    'param_ignored': 'L5_binding',
    'no_op_mutation': 'L5_binding',
    'subject_object_binding_mismatch': 'L5_binding',
    'chain_dead_end': 'L6_planner',
}

ACTION_TABLE = {
    'L0_build': {
        'build_failed': ('freeze_method_profile', 'downrank_api'),
        'default': ('fix_build_or_skip', 'diagnostic_mode'),
    },
    'L1_transport': {
        'transport_url_routing': ('transport_url_repair', 'downrank_path_family'),
        'transport_error': ('transport_url_repair', 'switch_domain'),
        'default': ('diagnostic_transport', 'downrank_api'),
    },
    'L2_auth': {
        'auth_expired': ('refresh_baseline', 'pause_execute_class'),
        'app_version_blocked': ('version_baseline_repair', 'refresh_baseline_field'),
        'default': ('refresh_baseline', 'quarantine_chain'),
    },
    'L3_param': {
        'validation_error': ('schema_repair', 'recheck_object_pool'),
        'default': ('intake_baseline', 'downrank_api'),
    },
    'L4_business_state': {
        'business_state_blocked': ('acquire_object', 'quarantine_chain', 'switch_domain'),
        'default': ('switch_domain', 'quarantine_chain'),
    },
    'L5_binding': {
        'param_ignored': ('skip_binding_report', 'test_object_level_field'),
        'no_op_mutation': ('reject_mutation', 'regenerate_mutation'),
        'default': ('continue_chain', 'generate_mutation'),
    },
    'L6_planner': {
        'chain_dead_end': ('revise_graph_hypothesis', 'switch_chain', 'acquire_object'),
        'default': ('downgrade_producer_confidence', 'switch_chain'),
    },
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_ladder() -> Dict[str, Any]:
    path = Path(__file__).resolve().parent / 'packs' / 'replay_diagnostic_ladder.json'
    if path.exists():
        return json.loads(path.read_text(encoding='utf-8'))
    return {}


def _infer_atomic_label(analysis: Dict[str, Any], signals: Optional[Dict[str, Any]] = None) -> str:
    outcome = analysis.get('call_outcome') or 'unknown'
    fc = analysis.get('failure_class') or outcome
    if outcome == 'business_success':
        harvested = analysis.get('produced_fields') or []
        if signals and signals.get('harvest'):
            harvested = list(set(harvested) | set(signals.get('harvest') or []))
        if harvested:
            return 'object_harvested'
        return 'business_success'
    if fc == 'param_ignored' or (signals or {}).get('param_ignored'):
        return 'param_ignored'
    return fc


def diagnose_failure(
    test_case: Dict[str, Any],
    execution: Dict[str, Any],
    analysis: Dict[str, Any],
    *,
    signals: Optional[Dict[str, Any]] = None,
    chain_context: Optional[Dict[str, Any]] = None,
    anchor_ok: bool = True,
    recent_same_fc_count: int = 0,
) -> Dict[str, Any]:
    """Return AttributionRecord with layer, diagnosis, actions, fallbacks."""
    fc = analysis.get('failure_class') or analysis.get('call_outcome') or 'unknown'
    layer = FAILURE_TO_LAYER.get(fc, 'L4_business_state')
    atomic_label = _infer_atomic_label(analysis, signals)

    if fc == 'auth_expired' and anchor_ok:
        diagnosis = 'scoped_auth_failure'
        confidence = 0.75
    elif fc == 'business_state_blocked':
        diagnosis = 'account_state_unsatisfied'
        confidence = 0.69
    elif fc == 'build_failed':
        diagnosis = execution.get('build_status') or 'request_build_failed'
        confidence = 0.9
    elif fc == 'chain_dead_end' or (chain_context or {}).get('no_consumer'):
        layer = 'L6_planner'
        diagnosis = 'planner_consumer_mismatch'
        confidence = 0.65
    else:
        diagnosis = fc
        confidence = 0.7

    if recent_same_fc_count >= 2:
        confidence = min(confidence + 0.1, 0.95)

    layer_actions = ACTION_TABLE.get(layer, {})
    primary, *fallbacks = layer_actions.get(fc, layer_actions.get('default', ('continue_chain',)))

    belief_updates: List[Dict[str, Any]] = []
    if layer == 'L6_planner':
        belief_updates.append({
            'target': f"producer:{test_case.get('api_id')}",
            'delta': -0.2,
            'reason': 'chain_dead_end_or_no_consumer',
        })

    return {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'test_id': test_case.get('test_id'),
        'api_id': test_case.get('api_id'),
        'path': test_case.get('path'),
        'chain_id': test_case.get('chain_id'),
        'layer': layer,
        'failure_class': fc,
        'atomic_label': atomic_label,
        'diagnosis': diagnosis,
        'confidence': round(confidence, 2),
        'primary_action': primary,
        'fallback_actions': fallbacks,
        'belief_updates': belief_updates,
        'chain_context': chain_context,
    }


def diagnose_failure_with_ir(
    test_case: Dict[str, Any],
    execution: Dict[str, Any],
    analysis: Dict[str, Any],
    **kwargs: Any,
) -> Dict[str, Any]:
    """diagnose_failure + universal_failure enrichment."""
    from minidrifter.ir.verification_bridge import enrich_attribution
    return enrich_attribution(diagnose_failure(test_case, execution, analysis, **kwargs))


def apply_diagnosis_action(
    record: Dict[str, Any],
    *,
    circuits: Any,
    beam: Any,
    confidence: Any,
    chain_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute generic recovery side-effects on schedulers (circuit counts in process_result)."""
    action = record.get('primary_action')
    applied: List[str] = [action] if action else []

    if action == 'quarantine_chain' and chain_id and beam:
        beam.quarantine(chain_id, reason=record.get('diagnosis', 'blocked'))
        applied.append('quarantine_chain')
    elif action == 'switch_chain' and chain_id and beam:
        beam.downrank(chain_id, penalty=2.0)
        applied.append('downrank_chain')
    elif action == 'downgrade_producer_confidence':
        for bu in record.get('belief_updates') or []:
            target = bu.get('target', '')
            if target.startswith('producer:') and confidence:
                api_id = target.split(':', 1)[1]
                confidence.downgrade_producer(api_id, '*')

    for fb in record.get('fallback_actions') or []:
        if fb not in applied:
            applied.append(fb)

    record['applied_actions'] = applied
    return record
