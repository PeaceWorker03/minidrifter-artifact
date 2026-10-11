# -*- coding: utf-8 -*-
"""LLM Policy Replanner — global strategy from compressed state (Layer 5)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.reasoning.llm_client import LLMClient, LLMClientError
from minidrifter.reasoning.validator import parse_json_from_llm
from minidrifter.verification.llm_trace import make_trace
from minidrifter.verification.object_acquisition_planner import missing_high_value_objects

ALLOWED_ACTIONS = frozenset({
    'continue_chain', 'acquire_object', 'switch_domain', 'refresh_baseline',
    'generate_mutation', 'stop_chain', 'atomic_probe', 'exploration_reset',
})

SYSTEM_PROMPT = """You are MiniDrifter Apex-PoC Policy Replanner.
Given compressed search state, choose the next strategic action for API PoC chain search.

Rules:
- Output JSON only
- action must be one of: continue_chain, acquire_object, switch_domain, refresh_baseline, generate_mutation, stop_chain, atomic_probe, exploration_reset
- Always include fallback action string
- Do NOT output executable code or raw HTTP
- Prefer acquire_object when high-value objects missing and chains quarantined
- Prefer refresh_baseline when auth_expired circuit is open

Output:
{
  "action": "...",
  "target_field": "optional",
  "candidate_domain": "optional",
  "reason": "...",
  "fallback": "...",
  "confidence": 0.0-1.0
}
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def build_policy_context(
    *,
    object_pool: Dict[str, Any],
    beam_summary: Dict[str, Any],
    atomic_summary: Dict[str, Any],
    circuits: Dict[str, Any],
    watchdog: Dict[str, Any],
    recent_failures: Dict[str, int],
    anchor_api_id: Optional[str] = None,
) -> Dict[str, Any]:
    from minidrifter.verification.pack_loader import load_field_ontology

    ontology = load_field_ontology()
    hvo = set(ontology.get('high_value_produces') or [])
    missing = missing_high_value_objects(object_pool, ontology_fields=hvo)
    available = sorted(set(object_pool.get('confirmed_fields') or []) | set(object_pool.get('frontier_unlocks') or []))

    return {
        'current_goal': 'walk_business_chains_and_binding_checks',
        'anchor_api_id': anchor_api_id,
        'available_objects': available[:30],
        'missing_high_value_objects': missing[:15],
        'active_chains': beam_summary.get('top_scores') or [],
        'atomic_probe': {
            'pending': atomic_summary.get('pending'),
            'passed': atomic_summary.get('atomic_passed'),
        },
        'recent_failures': recent_failures,
        'circuits': circuits,
        'watchdog': watchdog,
        'candidate_actions': _rule_candidate_actions(missing, recent_failures, circuits),
    }


def _rule_candidate_actions(
    missing: List[str],
    recent_failures: Dict[str, int],
    circuits: Dict[str, Any],
) -> List[str]:
    actions = ['atomic_probe', 'continue_chain']
    if missing:
        actions.insert(0, 'acquire_object')
    if recent_failures.get('auth_expired', 0) >= 2 or circuits.get('pause_execute'):
        actions.insert(0, 'refresh_baseline')
    if recent_failures.get('business_state_blocked', 0) >= 3:
        actions.append('switch_domain')
    return actions


def _rule_policy(context: Dict[str, Any]) -> Dict[str, Any]:
    missing = context.get('missing_high_value_objects') or []
    failures = context.get('recent_failures') or {}
    circuits = context.get('circuits') or {}

    if circuits.get('pause_execute') or failures.get('auth_expired', 0) >= 3:
        return {
            'action': 'refresh_baseline',
            'reason': 'auth circuit open or repeated auth_expired',
            'fallback': 'switch_domain',
            'confidence': 0.85,
            'source': 'rule_policy',
        }
    if missing:
        return {
            'action': 'acquire_object',
            'target_field': missing[0],
            'reason': f'missing high-value object {missing[0]}',
            'fallback': 'switch_domain',
            'confidence': 0.75,
            'source': 'rule_policy',
        }
    active = context.get('active_chains') or []
    if active:
        return {
            'action': 'continue_chain',
            'candidate_domain': active[0].get('domain'),
            'reason': 'extend highest-scoring active chain',
            'fallback': 'atomic_probe',
            'confidence': 0.7,
            'source': 'rule_policy',
        }
    return {
        'action': 'atomic_probe',
        'reason': 'no active chains — probe next API',
        'fallback': 'switch_domain',
        'confidence': 0.65,
        'source': 'rule_policy',
    }


def propose_policy(
    pack_dir: Path,
    context: Dict[str, Any],
    *,
    client: Optional[LLMClient] = None,
    dry_run: bool = False,
    llm_traces: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Rule-first policy; optional LLM override when with_llm."""
    rule = _rule_policy(context)
    record = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'agent': 'llm_policy_replanner',
        'status': 'rule_only',
    }

    if dry_run:
        trace = make_trace(
            'policy_replanner',
            [{'step': 'observe', 'content': 'rule policy'}, {'step': 'emit', 'content': rule.get('action', '')}],
            emit={'action': rule.get('action'), 'reason': rule.get('reason')},
            rule_fallback='rule_policy',
        )
        if llm_traces is not None:
            llm_traces.append(trace)
        return {'policy': rule, 'record': record, 'trace': trace, 'used_llm': False}

    try:
        client = client or LLMClient()
        user_msg = json.dumps(context, ensure_ascii=False, indent=2)
        raw = client.chat_json(SYSTEM_PROMPT, user_msg)
        parsed = parse_json_from_llm(raw)
        action = parsed.get('action') or rule.get('action')
        if action not in ALLOWED_ACTIONS:
            action = rule.get('action')
        policy = {
            'action': action,
            'target_field': parsed.get('target_field') or rule.get('target_field'),
            'candidate_domain': parsed.get('candidate_domain') or rule.get('candidate_domain'),
            'reason': parsed.get('reason') or rule.get('reason'),
            'fallback': parsed.get('fallback') or rule.get('fallback'),
            'confidence': float(parsed.get('confidence') or rule.get('confidence', 0.5)),
            'source': 'llm_policy',
        }
        record['status'] = 'ok'
        trace = make_trace(
            'policy_replanner',
            [
                {'step': 'observe', 'content': f"missing={len(context.get('missing_high_value_objects') or [])}"},
                {'step': 'plan', 'content': policy.get('reason', '')},
                {'step': 'emit', 'content': policy.get('action', '')},
            ],
            confidence=policy.get('confidence'),
        )
        if llm_traces is not None:
            llm_traces.append(trace)
        return {'policy': policy, 'record': record, 'trace': trace, 'used_llm': True}
    except (LLMClientError, json.JSONDecodeError, ValueError, TypeError):
        record['status'] = 'llm_fallback_rule'
        return {'policy': rule, 'record': record, 'used_llm': False}
