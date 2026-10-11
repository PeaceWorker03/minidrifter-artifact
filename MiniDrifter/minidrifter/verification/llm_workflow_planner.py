# -*- coding: utf-8 -*-
"""A2 LLM Workflow Planner — next-hop API linkage with S-TRACE."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.reasoning.llm_client import LLMClient, LLMClientError
from minidrifter.reasoning.validator import parse_json_from_llm
from minidrifter.verification.campaign_planner import build_test_case
from minidrifter.verification.llm_context import build_workflow_context
from minidrifter.verification.llm_trace import make_trace
from minidrifter.verification.llm_validator import parse_strace_payload, validate_workflow_emit
from minidrifter.verification.workflow_schema import workflow_link_from_candidate

SYSTEM_PROMPT = """You are MiniDrifter A2 Workflow Linker.
Given a depth chain with suspicious signals, pick the next consumer API to test.

Rules:
- Output S-TRACE JSON (observe, hypothesize, plan, constraint_check, emit)
- emit.next_api_id MUST be one of rule_candidates[].api_id OR emit.stop=true
- Do NOT invent api_ids outside rule_candidates or near_miss_candidates
- near_miss_candidates need missing fields — use frontier_hypothesis if stop=true
- Do NOT declare vulnerabilities confirmed; only binding hypotheses
- Prefer APIs that test cross-endpoint binding when harvest includes UserId/OrderId
- If binding_anomaly or active_findings on chain, prioritize hops that confirm SCOPE (sibling APIs with same bindable fields) or DOWNSTREAM impact (consumers trusting poisoned subject/object)
- When active_findings include subject_object_binding_mismatch, next hop should deepen evidence — not unrelated domains
- Reason about subject/object/capability roles from context, not app-specific brand names

Output JSON:
{
  "trace_id": "tr_...",
  "stage": "workflow_planner",
  "steps": [
    {"step": "observe", "content": "..."},
    {"step": "hypothesize", "content": "..."},
    {"step": "plan", "content": "..."},
    {"step": "constraint_check", "content": "..."},
    {"step": "emit", "content": "..."}
  ],
  "confidence": 0.0-1.0,
  "disagreements": [{"topic": "...", "rule_pick": "op_...", "llm_pick": "op_...", "reason": "..."}],
  "emit": {
    "stop": false,
    "next_api_id": "op_...",
    "binding_hypothesis": "why this hop tests the chain",
    "link_role": "consumer",
    "rationale": "..."
  }
}

When no satisfiable hop exists but near_miss suggests path:
{
  "emit": {
    "stop": true,
    "frontier_hypothesis": "Need OrderId from order list API first",
    "suggested_apis_after_harvest": ["op_..."]
  }
}
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def propose_workflow_link(
    pack_dir: Path,
    *,
    chain_nodes: List[Dict[str, Any]],
    object_pool: Dict[str, Any],
    baseline_context: Dict[str, Any],
    last_signals: Dict[str, Any],
    rule_candidates: List[Dict[str, Any]],
    rule_pick: Dict[str, Any],
    near_miss_candidates: Optional[List[Dict[str, Any]]] = None,
    client: Optional[LLMClient] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    ctx = build_workflow_context(
        pack_dir,
        chain_nodes=chain_nodes,
        object_pool=object_pool,
        last_signals=last_signals,
        rule_candidates=rule_candidates,
        near_miss_candidates=near_miss_candidates,
        baseline_context=baseline_context,
        rule_pick=rule_pick,
    )

    record: Dict[str, Any] = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'agent': 'llm_workflow_planner',
        'status': 'pending',
        'chain_depth': len(chain_nodes),
    }

    allowed_api_ids = {
        c['api_id'] for c in (rule_candidates + (near_miss_candidates or []))
        if c.get('api_id')
    }

    if dry_run:
        record['status'] = 'dry_run_skipped'
        pick_id = rule_pick.get('api_id') if rule_candidates else None
        trace = make_trace(
            'workflow_planner',
            [{'step': 'observe', 'content': f'dry_run: rule pick {rule_pick.get("path")}'}],
            {'stop': not pick_id, 'next_api_id': pick_id, 'binding_hypothesis': 'rule fallback'},
            status='dry_run_skipped',
        )
        return {
            'record': record,
            'trace': trace,
            'link_plan': None,
            'validation_errors': [],
            'used_llm_pick': False,
        }

    if not rule_candidates and not near_miss_candidates:
        record['status'] = 'skipped_no_candidates'
        return {
            'record': record,
            'trace': None,
            'link_plan': None,
            'validation_errors': [],
            'used_llm_pick': False,
        }

    try:
        client = client or LLMClient()
        user_msg = (
            'Pick the best next consumer API for this depth chain.\n'
            f'Rule layer default pick: {rule_pick.get("api_id")} ({rule_pick.get("path")})\n'
            'You may agree or pick a different rule_candidates entry with rationale.\n'
            'If no candidate is appropriate, emit stop=true with frontier_hypothesis.\n\n'
            f'CONTEXT:\n{json.dumps(ctx, ensure_ascii=False, indent=2)}'
        )
        raw = client.chat([
            {'role': 'system', 'content': SYSTEM_PROMPT},
            {'role': 'user', 'content': user_msg},
        ], json_mode=True)
        payload = parse_json_from_llm(raw)
        record['model'] = client.config.get('model')
        record['status'] = 'ok'
    except LLMClientError as e:
        record['status'] = 'error'
        record['error'] = str(e)
        fallback_trace = make_trace(
            'workflow_planner',
            [{'step': 'observe', 'content': f'LLM error: {e}'},
             {'step': 'emit', 'content': f'rule fallback {rule_pick.get("path")}'}],
            {'stop': False, 'next_api_id': rule_pick.get('api_id'), 'binding_hypothesis': 'rule fallback after LLM error'},
            status='llm_error_fallback',
            rule_fallback=rule_pick.get('api_id'),
        )
        link_plan = None
        if rule_pick.get('template') and not rule_pick.get('missing_fields'):
            tc = build_test_case(
                rule_pick['template'], baseline_context=baseline_context, index=2000 + len(chain_nodes),
            )
            tc['test_stage'] = 'depth_chain'
            link_plan = workflow_link_from_candidate(
                rule_pick, test_cases=[tc], source='rule_after_llm_error',
                link_hypothesis=f"Rule fallback after LLM error: {rule_pick.get('path')}",
                trace_id=fallback_trace.get('trace_id'),
            )
        return {
            'record': record,
            'trace': fallback_trace,
            'link_plan': link_plan,
            'validation_errors': [str(e)],
            'used_llm_pick': False,
        }
    except Exception as e:
        record['status'] = 'error'
        record['error'] = str(e)
        return {
            'record': record,
            'trace': None,
            'link_plan': None,
            'validation_errors': [str(e)],
            'used_llm_pick': False,
        }

    trace, trace_errors = parse_strace_payload(payload, expected_stage='workflow_planner')
    emit = trace.get('emit') or {}
    ok, val_errors, picked_id = validate_workflow_emit(emit, allowed_api_ids=allowed_api_ids)
    all_errors = trace_errors + val_errors

    disagreements = list(trace.get('disagreements') or [])
    if picked_id and picked_id != rule_pick.get('api_id'):
        disagreements.append({
            'topic': 'next_api_selection',
            'rule_pick': rule_pick.get('api_id'),
            'llm_pick': picked_id,
            'reason': emit.get('rationale') or emit.get('binding_hypothesis'),
        })

    full_trace = make_trace(
        'workflow_planner',
        trace.get('steps') or [],
        emit,
        confidence=trace.get('confidence'),
        trace_id=trace.get('trace_id') or payload.get('trace_id'),
        disagreements=disagreements,
        status='ok' if ok or emit.get('stop') else 'partial',
        rule_fallback=rule_pick.get('api_id') if all_errors else None,
    )
    record['validation_errors'] = all_errors

    link_plan = None
    used_llm_pick = False

    if emit.get('stop'):
        link_plan = {
            'stop': True,
            'reason': emit.get('frontier_hypothesis') or 'llm_stop',
            'frontier_hypothesis': emit.get('frontier_hypothesis'),
            'suggested_apis_after_harvest': emit.get('suggested_apis_after_harvest') or [],
            'next_test_cases': [],
            'source': 'llm_workflow_planner',
            'trace_id': full_trace.get('trace_id'),
        }
    elif ok and picked_id:
        pick = next((c for c in rule_candidates if c.get('api_id') == picked_id), rule_pick)
        used_llm_pick = picked_id != rule_pick.get('api_id')
        tc = build_test_case(
            pick['template'], baseline_context=baseline_context, index=2000 + len(chain_nodes),
        )
        tc['test_stage'] = 'depth_chain'
        tc['chain_role'] = 'consumer'
        tc['unlocked_by_fields'] = pick.get('unlocked_by')
        tc['workflow_hypothesis'] = emit.get('binding_hypothesis')

        hypothesis = emit.get('binding_hypothesis') or f"Consumer {pick['path']} via LLM link"
        link_plan = workflow_link_from_candidate(
            pick,
            test_cases=[tc],
            source='llm_workflow_planner' if used_llm_pick else 'llm_agrees_with_rule',
            link_hypothesis=hypothesis,
            trace_id=full_trace.get('trace_id'),
        )
    else:
        record['status'] = 'fallback_rule'

    return {
        'record': record,
        'trace': full_trace,
        'link_plan': link_plan,
        'validation_errors': all_errors,
        'used_llm_pick': used_llm_pick,
        'raw': payload,
    }
