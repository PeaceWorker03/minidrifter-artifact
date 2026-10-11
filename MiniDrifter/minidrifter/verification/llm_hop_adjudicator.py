# -*- coding: utf-8
"""LLM per-hop deep adjudication — why, missing info, resolution (allowlisted actions)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.reasoning.llm_client import LLMClient, LLMClientError
from minidrifter.reasoning.validator import parse_json_from_llm
from minidrifter.verification.llm_failure_classifier import llm_failure_prompt_context
from minidrifter.verification.llm_trace import make_trace

ALLOWED_ACTIONS = frozenset({
    'acquire_object', 'refresh_baseline', 'switch_domain', 'quarantine_chain',
    'downrank_api', 'downrank_path_family', 'retry_after_acquire', 'finding_escalation',
    'continue_chain', 'provide_capture', 'schema_repair', 'graph_feedback',
})

SYSTEM_PROMPT = """You are MiniDrifter Hop Adjudicator — analyze ONE API hop in a verification chain.

Goals:
1. Explain WHY this hop failed or looks suspicious (root cause in plain language)
2. Correlate param changes with response (binding drift, missing state, transport, auth)
3. List what materials/objects are MISSING for deeper chain progress
4. Propose resolution: auto actions (engine can run) + user actions (captures needed)

Output JSON only:
{
  "reasoning_steps": [
    {"step": "observe", "content": "..."},
    {"step": "hypothesize", "content": "..."},
    {"step": "plan", "content": "..."},
    {"step": "constraint_check", "content": "..."},
    {"step": "emit", "content": "..."}
  ],
  "node_assessment": "healthy|degraded|blocked|finding_signal",
  "root_cause_summary": "one paragraph",
  "param_binding_analysis": "how params relate to response",
  "missing_for_deeper_chain": [
    {"field": "OrderId", "why": "...", "capture_strategy": "list/detail API response"}
  ],
  "auto_actions": [
    {"action": "acquire_object|switch_domain|...", "target_field": "optional", "rationale": "..."}
  ],
  "user_must_provide": [
    {"what": "OrderId via order list capture", "why": "...", "example_path": "/..."}
  ],
  "retry_recommended": true/false,
  "confidence": 0.0-1.0,
  "failure_label": "AUTH_EXPIRED|MISSING_OBJECT|BUSINESS_STATE_BLOCKED|APP_VERSION_BLOCKED|REQUEST_SCHEMA_ERROR|TRANSPORT_ERROR|ORACLE_UNCERTAIN|SAFETY_BLOCKED|BINDING_DRIFT_SIGNAL|NONE"
}

Rules:
- auto_actions.action MUST be from: acquire_object, refresh_baseline, switch_domain, quarantine_chain, downrank_api, retry_after_acquire, finding_escalation, continue_chain
- Do NOT invent api paths outside context suggested_capture_paths
- Universal: speak in subject/object/capability terms, not brand names
- Do NOT declare final vulnerability confirmed
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def deepen_hop_adjudication(
    pack_dir: Path,
    *,
    hop_verdict: Dict[str, Any],
    prior_hops: Optional[List[Dict[str, Any]]] = None,
    dry_run: bool = False,
    llm_traces: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """LLM enriches rule hop verdict; merges into resolution plan."""
    pack_dir = Path(pack_dir)
    record: Dict[str, Any] = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'agent': 'hop_adjudicator',
        'status': 'skipped',
    }
    health = hop_verdict.get('node_health')
    if health in {'healthy', 'unknown'} and not hop_verdict.get('missing_materials'):
        return {'record': record, 'used_llm': False, 'enriched': hop_verdict}

    if dry_run:
        record['status'] = 'dry_run'
        return {'record': record, 'used_llm': False, 'enriched': hop_verdict}

    ctx = {
        'failure_diagnosis': llm_failure_prompt_context(hop_verdict),
        'hop': {
            'path': hop_verdict.get('path'),
            'node_health': health,
            'attribution': hop_verdict.get('attribution'),
            'param_correlation': hop_verdict.get('param_correlation'),
            'missing_materials': hop_verdict.get('missing_materials'),
            'resolution_plan': hop_verdict.get('resolution_plan'),
        },
        'prior_hops': (prior_hops or [])[-4:],
    }
    user_msg = f'Adjudicate this hop:\n{json.dumps(ctx, ensure_ascii=False, indent=2)[:14000]}'

    try:
        client = LLMClient()
        raw = client.chat([
            {'role': 'system', 'content': SYSTEM_PROMPT},
            {'role': 'user', 'content': user_msg},
        ], json_mode=True)
        thought = parse_json_from_llm(raw)
        record['model'] = client.config.get('model')
        record['status'] = 'ok'
    except (LLMClientError, json.JSONDecodeError, ValueError) as e:
        record['status'] = 'fallback_rule'
        record['error'] = str(e)
        return {'record': record, 'used_llm': False, 'enriched': hop_verdict}

    enriched = dict(hop_verdict)
    if thought.get('root_cause_summary'):
        enriched['llm_root_cause'] = thought.get('root_cause_summary')
    if thought.get('param_binding_analysis'):
        enriched['param_correlation'] = {
            **(enriched.get('param_correlation') or {}),
            'llm_analysis': thought.get('param_binding_analysis'),
        }
    for mm in thought.get('missing_for_deeper_chain') or []:
        field = mm.get('field')
        if not field:
            continue
        existing = {m.get('field') for m in enriched.get('missing_materials') or []}
        if field not in existing:
            enriched.setdefault('missing_materials', []).append({
                'field': field,
                'why_needed': mm.get('why') or mm.get('capture_strategy'),
                'capture_hint': mm.get('capture_strategy'),
                'source': 'llm_hop_adjudicator',
            })

    plan = dict(enriched.get('resolution_plan') or {})
    auto = list(plan.get('auto_actions') or [])
    for aa in thought.get('auto_actions') or []:
        act = aa.get('action')
        if act in ALLOWED_ACTIONS:
            auto.append({
                'action': act,
                'target_field': aa.get('target_field'),
                'rationale': aa.get('rationale'),
                'source': 'llm',
            })
    plan['auto_actions'] = auto
    plan['retry_eligible'] = bool(thought.get('retry_recommended')) or plan.get('retry_eligible')
    plan['llm_user_must_provide'] = thought.get('user_must_provide') or []
    enriched['resolution_plan'] = plan
    if thought.get('node_assessment'):
        enriched['node_health'] = thought.get('node_assessment')

    trace = make_trace(
        'hop_adjudicator',
        thought.get('reasoning_steps') or [],
        {
            'root_cause_summary': thought.get('root_cause_summary'),
            'retry_recommended': thought.get('retry_recommended'),
        },
        confidence=thought.get('confidence'),
    )
    if llm_traces is not None:
        llm_traces.append(trace)

    return {'record': record, 'used_llm': True, 'enriched': enriched, 'trace': trace}
