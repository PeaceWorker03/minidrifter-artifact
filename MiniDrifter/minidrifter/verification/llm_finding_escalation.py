# -*- coding: utf-8
"""LLM creative deepening after binding findings — plans within rule allowlist."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.reasoning.llm_client import LLMClient, LLMClientError
from minidrifter.reasoning.validator import parse_json_from_llm
from minidrifter.verification.llm_trace import make_trace

SYSTEM_PROMPT = """You are MiniDrifter Finding Escalation Planner.

A binding drift signal was observed (M0/M7 differential or subject-object mismatch).
Your job: propose the most valuable NEXT probes to deepen understanding — not repeat the same test.

Think like a senior appsec researcher:
1. **Scope confirmation** — does the same binding flaw exist on sibling APIs?
2. **Lateral propagation** — can the mismatched subject access other business objects?
3. **Downstream impact** — do consumer APIs trust the poisoned binding?
4. **Privilege escalation** — cross-subject or cross-object tier APIs (N2) that accept the same fields
5. **Evidence chain** — what hop sequence would prove exploitability vs isolated anomaly?

Input: finding summary, bindable fields, rule-ranked escalation targets (allowlist).

Output JSON only:
{
  "reasoning_steps": [
    {"step": "observe", "content": "..."},
    {"step": "hypothesize", "content": "..."},
    {"step": "plan", "content": "..."},
    {"step": "constraint_check", "content": "..."},
    {"step": "emit", "content": "..."}
  ],
  "escalation_hypothesis": "one sentence: what deeper vulnerability class we might confirm",
  "priority_targets": [
    {
      "api_id": "MUST be from rule_targets[].api_id",
      "strategy": "scope_confirmation|lateral_binding|downstream_propagation|cross_object_binding|privilege_escalation",
      "priority": 1,
      "rationale": "why this deepens the finding",
      "expected_signal": "what response would confirm scope"
    }
  ],
  "chain_extension_goal": "describe ideal 2-4 hop evidence chain from current finding",
  "stop_if": ["condition when escalation should halt"],
  "confidence": 0.0-1.0
}

Rules:
- priority_targets MUST use api_id from rule_targets allowlist only
- Prefer depth over breadth when finding is confirmed (not hypothesis)
- Do NOT invent paths or api_ids
- Universal: reason about subject/object/capability roles, not app brand names
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def propose_finding_escalation(
    pack_dir: Path,
    *,
    escalation_plan: Dict[str, Any],
    dry_run: bool = False,
    llm_traces: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """LLM reorder/prioritize rule escalation targets; never invent APIs."""
    pack_dir = Path(pack_dir)
    targets = escalation_plan.get('targets') or []
    allowed = {t.get('api_id') for t in targets if t.get('api_id')}
    record: Dict[str, Any] = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'agent': 'finding_escalation_planner',
        'status': 'skipped',
    }
    if not targets or not allowed:
        return {'record': record, 'used_llm': False, 'reordered_targets': targets}

    if dry_run:
        record['status'] = 'dry_run'
        return {'record': record, 'used_llm': False, 'reordered_targets': targets}

    ctx = {
        'finding_summary': escalation_plan.get('finding_summary'),
        'bindable_fields': escalation_plan.get('bindable_fields'),
        'rule_targets': [
            {
                'api_id': t.get('api_id'),
                'path': t.get('path'),
                'strategy': t.get('strategy'),
                'score': t.get('score'),
                'shared_fields': t.get('shared_fields'),
                'rationale': t.get('rationale'),
            }
            for t in targets[:15]
        ],
    }
    user_msg = (
        'Plan finding escalation deepening.\n\n'
        f'Context JSON:\n{json.dumps(ctx, ensure_ascii=False, indent=2)[:12000]}'
    )

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
        return {'record': record, 'used_llm': False, 'reordered_targets': targets}

    priority = thought.get('priority_targets') or []
    by_id = {t['api_id']: t for t in targets if t.get('api_id')}
    reordered: List[Dict[str, Any]] = []
    seen: set = set()
    for pt in sorted(priority, key=lambda x: x.get('priority') or 99):
        aid = pt.get('api_id')
        if aid not in allowed or aid in seen:
            continue
        base = dict(by_id[aid])
        base['llm_strategy'] = pt.get('strategy') or base.get('strategy')
        base['llm_rationale'] = pt.get('rationale')
        base['expected_signal'] = pt.get('expected_signal')
        base['llm_priority'] = pt.get('priority')
        reordered.append(base)
        seen.add(aid)
    for t in targets:
        if t.get('api_id') not in seen:
            reordered.append(t)

    trace = make_trace(
        'finding_escalation',
        thought.get('reasoning_steps') or [],
        {
            'escalation_hypothesis': thought.get('escalation_hypothesis'),
            'chain_extension_goal': thought.get('chain_extension_goal'),
            'priority_count': len(reordered),
        },
        confidence=thought.get('confidence'),
    )
    if llm_traces is not None:
        llm_traces.append(trace)

    return {
        'record': record,
        'used_llm': True,
        'reordered_targets': reordered,
        'trace': trace,
        'hypothesis': thought.get('escalation_hypothesis'),
        'chain_extension_goal': thought.get('chain_extension_goal'),
    }
