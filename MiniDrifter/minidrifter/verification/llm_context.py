# -*- coding: utf-8 -*-
"""Build evidence-constrained context bundles for verification LLM agents."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.pack_meta import resolve_pack_id
from minidrifter.reasoning.pack_loader import load_evidence_pack


def _redact_pool(context: Dict[str, Any]) -> Dict[str, str]:
    out = {}
    for k, v in (context.get('resolved_fields') or {}).items():
        if isinstance(v, dict) and v.get('value') is not None:
            out[k] = '***'
    return out


def slim_test_case(tc: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'test_id': tc.get('test_id'),
        'api_id': tc.get('api_id'),
        'path': tc.get('path'),
        'domain': tc.get('domain'),
        'method': tc.get('method'),
        'mutation_type': tc.get('mutation_type'),
        'params': tc.get('params'),
        'side_effect': (tc.get('safety') or {}).get('side_effect'),
        'planner_score': tc.get('planner_score'),
        'expected_bindings': tc.get('expected_bindings'),
    }


def slim_analysis(a: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'test_id': a.get('test_id'),
        'api_id': a.get('api_id'),
        'path': a.get('path'),
        'call_outcome': a.get('call_outcome'),
        'business_status': a.get('business_status'),
        'failure_class': a.get('failure_class'),
        'recommended_action': a.get('recommended_action'),
        'produced_fields': a.get('produced_fields'),
        'security_signals': a.get('security_signals'),
        'binding_observation': a.get('binding_observation'),
    }


def slim_execution(ex: Dict[str, Any]) -> Dict[str, Any]:
    body = ex.get('body_json')
    body_summary = None
    if isinstance(body, dict):
        body_summary = {
            k: ('***' if k.lower() in {'token', 'authorization'} else v)
            for k, v in body.items()
            if not isinstance(v, (dict, list))
        }
    return {
        'test_id': ex.get('test_id'),
        'path': ex.get('path'),
        'mode': ex.get('mode'),
        'build_status': ex.get('build_status'),
        'transport_status': ex.get('transport_status'),
        'call_outcome': ex.get('call_outcome'),
        'response_decrypt_mode': ex.get('response_decrypt_mode'),
        'body_summary': body_summary,
        'errors': ex.get('errors'),
    }


def build_test_generation_context(
    pack_dir: Path,
    test_cases: List[Dict[str, Any]],
    baseline_context: Dict[str, Any],
    *,
    max_cards: int = 8,
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    mutation_policy = json.loads(
        (Path(__file__).resolve().parent / 'packs' / 'mutation_policy.json').read_text(encoding='utf-8')
    )
    cards = []
    for tc in test_cases[:max_cards]:
        api_id = tc.get('api_id')
        card = None
        if api_id:
            ep = load_evidence_pack(pack_dir, api_id)
            if ep:
                card = {
                    'api_id': api_id,
                    'path': tc.get('path'),
                    'evidence_snippet': (ep.get('primary_evidence') or {}).get('snippet', '')[:400],
                }
        cards.append(card or {'api_id': api_id, 'path': tc.get('path')})

    return {
        'pack_id': resolve_pack_id(pack_dir),
        'crypto_profile': baseline_context.get('crypto_profile'),
        'crypto_replay_ready': baseline_context.get('crypto_replay_ready'),
        'baseline_fields_redacted': _redact_pool(baseline_context),
        'allowed_mutations': mutation_policy.get('allowed_mutations'),
        'blocked_mutations': mutation_policy.get('blocked_mutations'),
        'test_cases': [slim_test_case(t) for t in test_cases[:max_cards]],
        'api_evidence': cards,
    }


def build_feedback_context(
    pack_dir: Path,
    *,
    test_cases: List[Dict[str, Any]],
    executions: List[Dict[str, Any]],
    analyses: List[Dict[str, Any]],
    rule_plan: Dict[str, Any],
    baseline_context: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        'pack_id': resolve_pack_id(pack_dir),
        'baseline_fields_redacted': _redact_pool(baseline_context),
        'crypto_profile': baseline_context.get('crypto_profile'),
        'rule_next_action_plan': rule_plan,
        'test_cases': [slim_test_case(t) for t in test_cases],
        'executions': [slim_execution(e) for e in executions],
        'analyses': [slim_analysis(a) for a in analyses],
    }


def build_strategy_context(
    pack_dir: Path,
    seed: Dict[str, Any],
    baseline_context: Dict[str, Any],
    object_pool: Dict[str, Any],
    *,
    prior_feedback: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    mutation_policy = json.loads(
        (Path(__file__).resolve().parent / 'packs' / 'mutation_policy.json').read_text(encoding='utf-8')
    )
    template = seed.get('template') or {}
    api_id = seed.get('api_id')
    card = None
    if api_id:
        ep = load_evidence_pack(pack_dir, api_id)
        if ep:
            card = {
                'api_id': api_id,
                'path': seed.get('path'),
                'evidence_snippet': (ep.get('primary_evidence') or {}).get('snippet', '')[:500],
            }

    pool_summary = {
        'confirmed_fields': object_pool.get('confirmed_fields') or [],
        'frontier_unlocks': object_pool.get('frontier_unlocks') or [],
        'negative_pool_available': bool((object_pool.get('pools') or {}).get('negative_pool')),
    }

    return {
        'pack_id': resolve_pack_id(pack_dir),
        'seed': {
            'seed_id': seed.get('seed_id'),
            'api_id': api_id,
            'path': seed.get('path'),
            'score': seed.get('score'),
            'params': template.get('params'),
            'side_effect': (template.get('safety') or {}).get('side_effect'),
            'expected_bindings': template.get('expected_bindings'),
        },
        'api_evidence': card,
        'baseline_fields_redacted': _redact_pool(baseline_context),
        'object_pool_summary': pool_summary,
        'allowed_mutations': mutation_policy.get('allowed_mutations'),
        'blocked_mutations': mutation_policy.get('blocked_mutations'),
        'prior_feedback': prior_feedback or [],
    }


def build_workflow_context(
    pack_dir: Path,
    *,
    chain_nodes: List[Dict[str, Any]],
    object_pool: Dict[str, Any],
    last_signals: Dict[str, Any],
    rule_candidates: List[Dict[str, Any]],
    near_miss_candidates: Optional[List[Dict[str, Any]]] = None,
    baseline_context: Dict[str, Any],
    rule_pick: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    from minidrifter.verification.workflow_schema import slim_candidate, slim_near_miss

    return {
        'pack_id': resolve_pack_id(pack_dir),
        'baseline_fields_redacted': _redact_pool(baseline_context),
        'chain_nodes': [
            {'api_id': n.get('api_id'), 'path': n.get('path'), 'role': n.get('role'), 'depth': n.get('depth')}
            for n in chain_nodes
        ],
        'last_signals': {
            'suspicious': last_signals.get('suspicious'),
            'harvest': last_signals.get('harvest'),
            'depth_continue': last_signals.get('depth_continue'),
            'outcome': last_signals.get('outcome'),
            'binding_ready': last_signals.get('binding_ready'),
            'escalation_pending': last_signals.get('escalation_pending'),
            'active_findings': last_signals.get('active_findings') or [],
        },
        'confirmed_findings_hint': last_signals.get('confirmed_findings') or [],
        'object_pool_summary': {
            'confirmed_fields': object_pool.get('confirmed_fields') or [],
            'frontier_unlocks': object_pool.get('frontier_unlocks') or [],
        },
        'rule_candidates': [slim_candidate(c) for c in rule_candidates[:10]],
        'near_miss_candidates': [slim_near_miss(c) for c in (near_miss_candidates or [])[:6]],
        'rule_pick': slim_candidate(rule_pick) if rule_pick else None,
    }
