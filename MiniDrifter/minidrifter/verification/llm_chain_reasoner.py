# -*- coding: utf-8 -*-
"""Chain-level deep reasoning — S-TRACE for each business chain (Cursor-like deliberation)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.reasoning.llm_client import LLMClient, LLMClientError
from minidrifter.reasoning.validator import parse_json_from_llm
from minidrifter.verification.chain_reasoning import ChainReasoningJournal, CHAIN_VERDICTS
from minidrifter.verification.llm_trace import make_trace

SYSTEM_PROMPT = """You are MiniDrifter Chain Reasoner — think step-by-step about ONE business API chain.

Your job is like a senior security engineer reviewing a PoC path:
1. Observe: what succeeded, what failed, what objects are available
2. Hypothesize: is the chain blocked by baseline, missing object, wrong static graph edge, or account state?
3. Plan: what is the next meaningful probe (not blind retry)
4. Constraint check: respect safety (read-only), do not invent HTTP payloads
5. Emit: structured verdict and actions

Output JSON only:
{
  "trace_id": "tr_chain_...",
  "reasoning_steps": [
    {"step": "observe", "content": "..."},
    {"step": "hypothesize", "content": "..."},
    {"step": "plan", "content": "..."},
    {"step": "constraint_check", "content": "..."},
    {"step": "emit", "content": "..."}
  ],
  "verdict": "continuable|blocked_temporary|blocked_baseline|blocked_graph_hypothesis|need_object|completed|finding|dead",
  "root_cause_layer": "L0_build|L1_transport|L2_auth|L3_param|L4_business_state|L5_binding|L6_planner",
  "root_cause_summary": "plain language diagnosis",
  "confidence": 0.0-1.0,
  "recommended_actions": ["acquire_object:OrderId", "switch_domain:order", "refresh_baseline:Token"],
  "fallback_actions": ["..."],
  "revival_conditions": ["OrderId", "InvoiceId"],
  "planner_errors": ["optional: static graph may wrongly mark X as producer"],
  "blocker": {"layer": "...", "code": "...", "message": "..."}
}

Rules:
- Distinguish global baseline failure vs chain-specific blocker
- If auth_expired on some APIs but not seed, say scoped auth not global
- If business_state_blocked, prefer need_object / switch_domain over retry same API
- If same hop pruned repeatedly, verdict blocked_graph_hypothesis or dead
- Never recommend high side-effect APIs without noting human confirmation
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def build_chain_context(
    chain: Any,
    journal: ChainReasoningJournal,
    *,
    object_pool: Dict[str, Any],
    attribution: Optional[Dict[str, Any]] = None,
    link: Optional[Dict[str, Any]] = None,
    recent_outcomes: Optional[List[Dict[str, Any]]] = None,
    ir_session: Any = None,
) -> Dict[str, Any]:
    available = sorted(set(object_pool.get('confirmed_fields') or []) | set(object_pool.get('frontier_unlocks') or []))
    nodes = [{'api_id': n.get('api_id'), 'path': n.get('path'), 'role': n.get('role')} for n in (chain.nodes or [])]
    ctx = {
        'chain_id': chain.chain_id,
        'domain': chain.domain,
        'seed_path': chain.path,
        'status': chain.status,
        'depth': chain.depth,
        'last_outcome': chain.last_outcome,
        'blocked_reason': chain.blocked_reason,
        'skip_streak': getattr(chain, 'skip_streak', 0),
        'nodes': nodes,
        'available_objects': available[:25],
        'goal_hypothesis': journal.goal_hypothesis,
        'prior_verdict': journal.verdict,
        'recent_attribution': {
            'layer': (attribution or {}).get('layer'),
            'diagnosis': (attribution or {}).get('diagnosis'),
            'failure_class': (attribution or {}).get('failure_class'),
            'primary_action': (attribution or {}).get('primary_action'),
        } if attribution else None,
        'planned_link': {
            'stop': (link or {}).get('stop'),
            'reason': (link or {}).get('reason'),
            'next_path': ((link or {}).get('next_api') or {}).get('path'),
            'near_miss': [
                {'path': c.get('path'), 'missing': c.get('missing_fields')}
                for c in ((link or {}).get('near_miss_candidates') or [])[:5]
            ],
        } if link else None,
        'recent_outcomes': (recent_outcomes or [])[-8:],
        'active_findings': getattr(chain, 'active_findings', [])[-3:],
        'escalation_pending': getattr(chain, 'escalation_pending', False),
    }
    if ir_session is not None:
        from minidrifter.ir.verification_bridge import build_llm_chain_ir_context
        ctx.update(build_llm_chain_ir_context(
            ir_session,
            chain_id=chain.chain_id,
            seed_api_id=getattr(chain, 'seed_api_id', '') or '',
            domain=chain.domain,
        ))
    return ctx


def _rule_reason_chain(ctx: Dict[str, Any]) -> Dict[str, Any]:
    attr = ctx.get('recent_attribution') or {}
    fc = attr.get('failure_class') or ctx.get('last_outcome')
    layer = attr.get('layer') or 'L6_planner'
    skip = ctx.get('skip_streak') or 0

    if skip >= 2:
        return {
            'verdict': 'blocked_graph_hypothesis',
            'root_cause_layer': 'L6_planner',
            'root_cause_summary': 'Repeated prune/skip on same hop — static consumer/producer link may be wrong or params saturated',
            'confidence': 0.72,
            'recommended_actions': ['switch_domain', 'acquire_object'],
            'fallback_actions': ['mark_chain_dead'],
            'planner_errors': ['consumer_edge_low_confidence'],
            'reasoning_steps': [
                {'step': 'observe', 'content': f'skip_streak={skip}, chain depth={ctx.get("depth")}'},
                {'step': 'hypothesize', 'content': 'Planner keeps picking same blocked hop'},
                {'step': 'emit', 'content': 'blocked_graph_hypothesis'},
            ],
        }

    if fc == 'auth_expired':
        return {
            'verdict': 'blocked_baseline',
            'root_cause_layer': 'L2_auth',
            'root_cause_summary': 'Token/session expired for this API family — refresh baseline before deepening chain',
            'confidence': 0.85,
            'recommended_actions': ['refresh_baseline:Token', 'switch_domain'],
            'fallback_actions': ['pause_chain'],
            'reasoning_steps': [
                {'step': 'observe', 'content': 'auth_expired on chain hop'},
                {'step': 'emit', 'content': 'blocked_baseline'},
            ],
        }

    if fc == 'business_state_blocked':
        near = (ctx.get('planned_link') or {}).get('near_miss') or []
        missing = near[0].get('missing') if near else []
        return {
            'verdict': 'need_object',
            'root_cause_layer': 'L4_business_state',
            'root_cause_summary': 'Account lacks business precondition — acquire upstream objects before detail APIs',
            'confidence': 0.75,
            'recommended_actions': [f'acquire_object:{m}' for m in (missing or ['OrderId'])[:2]] or ['switch_domain'],
            'fallback_actions': ['quarantine_chain'],
            'revival_conditions': missing or ['OrderId'],
            'reasoning_steps': [
                {'step': 'observe', 'content': 'business_state_blocked'},
                {'step': 'plan', 'content': f'try acquire {missing}'},
                {'step': 'emit', 'content': 'need_object'},
            ],
        }

    if ctx.get('status') == 'quarantined':
        return {
            'verdict': 'blocked_temporary',
            'root_cause_layer': layer,
            'root_cause_summary': ctx.get('blocked_reason') or 'Chain quarantined pending objects or baseline repair',
            'confidence': 0.68,
            'recommended_actions': ['acquire_object', 'switch_domain'],
            'revival_conditions': ctx.get('available_objects') or [],
            'reasoning_steps': [
                {'step': 'observe', 'content': f'quarantined: {ctx.get("blocked_reason")}'},
                {'step': 'emit', 'content': 'blocked_temporary'},
            ],
        }

    return {
        'verdict': 'continuable',
        'root_cause_layer': layer,
        'root_cause_summary': 'Chain can proceed with next graph consumer or binding mutation',
        'confidence': 0.65,
        'recommended_actions': ['continue_chain'],
        'fallback_actions': ['acquire_object'],
        'reasoning_steps': [
            {'step': 'observe', 'content': f'last_outcome={ctx.get("last_outcome")}'},
            {'step': 'emit', 'content': 'continuable'},
        ],
    }


def reason_about_chain(
    pack_dir: Path,
    chain: Any,
    journal: ChainReasoningJournal,
    *,
    object_pool: Dict[str, Any],
    attribution: Optional[Dict[str, Any]] = None,
    link: Optional[Dict[str, Any]] = None,
    recent_outcomes: Optional[List[Dict[str, Any]]] = None,
    trigger: str = 'hop_failure',
    with_llm: bool = True,
    llm_dry_run: bool = False,
    llm_traces: Optional[List[Dict[str, Any]]] = None,
    ir_session: Any = None,
) -> Dict[str, Any]:
    """Deep think on one chain; LLM when enabled, rule fallback always available."""
    ctx = build_chain_context(
        chain, journal,
        object_pool=object_pool,
        attribution=attribution,
        link=link,
        recent_outcomes=recent_outcomes,
        ir_session=ir_session,
    )
    ctx['trigger'] = trigger

    rule = _rule_reason_chain(ctx)
    record = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'agent': 'chain_reasoner',
        'chain_id': chain.chain_id,
        'trigger': trigger,
        'status': 'rule_only',
    }

    if not with_llm or llm_dry_run:
        thought = rule
        trace = make_trace(
            'chain_reasoner',
            [{'step': s.get('step', 'observe'), 'content': s.get('content', '')} for s in rule.get('reasoning_steps', [])],
            emit={'verdict': rule.get('verdict'), 'recommended_actions': rule.get('recommended_actions')},
            confidence=rule.get('confidence'),
            rule_fallback='llm_skipped' if llm_dry_run else 'deep_think_disabled',
        )
        if llm_traces is not None:
            llm_traces.append(trace)
        journal.apply_thought(thought)
        return {'thought': thought, 'record': record, 'trace': trace, 'used_llm': False, 'context': ctx}

    try:
        client = LLMClient()
        raw = client.chat_json(SYSTEM_PROMPT, json.dumps(ctx, ensure_ascii=False, indent=2))
        parsed = parse_json_from_llm(raw)
        verdict = parsed.get('verdict') or rule.get('verdict')
        if verdict not in CHAIN_VERDICTS:
            verdict = rule.get('verdict')
        thought = {
            'verdict': verdict,
            'root_cause_layer': parsed.get('root_cause_layer') or rule.get('root_cause_layer'),
            'root_cause_summary': parsed.get('root_cause_summary') or rule.get('root_cause_summary'),
            'confidence': float(parsed.get('confidence') or rule.get('confidence', 0.5)),
            'recommended_actions': parsed.get('recommended_actions') or rule.get('recommended_actions'),
            'fallback_actions': parsed.get('fallback_actions') or rule.get('fallback_actions'),
            'revival_conditions': parsed.get('revival_conditions') or rule.get('revival_conditions'),
            'planner_errors': parsed.get('planner_errors') or [],
            'blocker': parsed.get('blocker'),
            'reasoning_steps': parsed.get('reasoning_steps') or rule.get('reasoning_steps'),
        }
        steps = parsed.get('reasoning_steps') or []
        trace = make_trace(
            'chain_reasoner',
            steps if steps else [{'step': 'emit', 'content': thought.get('root_cause_summary', '')}],
            emit={
                'verdict': thought.get('verdict'),
                'recommended_actions': thought.get('recommended_actions'),
                'root_cause_summary': thought.get('root_cause_summary'),
            },
            confidence=thought.get('confidence'),
        )
        record['status'] = 'ok'
        if llm_traces is not None:
            llm_traces.append(trace)
        journal.apply_thought(thought)
        write_path = Path(pack_dir) / 'chain_thoughts' / f'{chain.chain_id}.json'
        write_path.parent.mkdir(parents=True, exist_ok=True)
        write_path.write_text(json.dumps({'context': ctx, 'thought': thought, 'trace': trace}, ensure_ascii=False, indent=2), encoding='utf-8')
        return {'thought': thought, 'record': record, 'trace': trace, 'used_llm': True, 'context': ctx}
    except (LLMClientError, json.JSONDecodeError, ValueError, TypeError) as exc:
        record['status'] = f'llm_fallback:{type(exc).__name__}'
        record['error'] = str(exc)
        trace = make_trace(
            'chain_reasoner',
            [{'step': 'observe', 'content': f'LLM failed: {exc}'},
             {'step': 'emit', 'content': rule.get('root_cause_summary', '')}],
            emit={'verdict': rule.get('verdict'), 'recommended_actions': rule.get('recommended_actions')},
            confidence=rule.get('confidence'),
            rule_fallback='rule_after_llm_error',
            status='llm_error_fallback',
        )
        trace['llm_error'] = str(exc)
        if llm_traces is not None:
            llm_traces.append(trace)
        journal.apply_thought(rule)
        return {'thought': rule, 'record': record, 'trace': trace, 'used_llm': False, 'context': ctx, 'llm_error': str(exc)}


def deliberate_global(
    pack_dir: Path,
    registry: Any,
    *,
    object_pool: Dict[str, Any],
    circuits: Dict[str, Any],
    recent_failures: Dict[str, int],
    anchor_api_id: Optional[str] = None,
    with_llm: bool = True,
    llm_dry_run: bool = False,
    llm_traces: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Before stopping search, synthesize cross-chain thinking."""
    ctx = {
        'trigger': 'global_deliberation',
        'anchor_api_id': anchor_api_id,
        'chain_summaries': registry.summary_for_llm(12),
        'recent_failures': recent_failures,
        'circuits': circuits,
        'available_objects': sorted(set(object_pool.get('confirmed_fields') or []))[:30],
    }
    rule = {
        'verdict': 'exploration_reset',
        'root_cause_summary': 'Multiple chains quarantined — try acquire missing objects or switch domain',
        'recommended_actions': ['acquire_object', 'switch_domain', 'refresh_baseline'],
        'confidence': 0.7,
    }
    if not with_llm or llm_dry_run:
        return {'thought': rule, 'used_llm': False, 'context': ctx}

    try:
        client = LLMClient()
        prompt = SYSTEM_PROMPT + '\n\nNow synthesize ALL chains and recommend next exploration priorities (breadth over retry).'
        raw = client.chat_json(prompt, json.dumps(ctx, ensure_ascii=False, indent=2))
        parsed = parse_json_from_llm(raw)
        thought = {
            'verdict': parsed.get('verdict') or 'exploration_reset',
            'root_cause_summary': parsed.get('root_cause_summary') or rule['root_cause_summary'],
            'recommended_actions': parsed.get('recommended_actions') or rule['recommended_actions'],
            'fallback_actions': parsed.get('fallback_actions') or [],
            'confidence': float(parsed.get('confidence') or 0.7),
            'chain_priorities': parsed.get('chain_priorities') or [],
        }
        trace = make_trace('chain_reasoner', parsed.get('reasoning_steps') or [], emit=thought, confidence=thought.get('confidence'))
        if llm_traces is not None:
            llm_traces.append(trace)
        out_path = Path(pack_dir) / 'chain_thoughts' / '_global_deliberation.json'
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps({'context': ctx, 'thought': thought}, ensure_ascii=False, indent=2), encoding='utf-8')
        return {'thought': thought, 'used_llm': True, 'trace': trace, 'context': ctx}
    except (LLMClientError, json.JSONDecodeError, ValueError, TypeError):
        return {'thought': rule, 'used_llm': False, 'context': ctx}
