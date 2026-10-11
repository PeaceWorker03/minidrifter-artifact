# -*- coding: utf-8 -*-
"""LLM feedback planner — diagnosis and advisory next actions after campaign run."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.reasoning.llm_client import LLMClient, LLMClientError
from minidrifter.reasoning.validator import parse_json_from_llm
from minidrifter.verification.llm_context import build_feedback_context
from minidrifter.verification.llm_validator import merge_feedback_into_plan, validate_feedback_plan

SYSTEM_PROMPT = """You are MiniDrifter Verification Feedback Planner.
Analyze campaign execution results and propose ADVISORY next steps.

You must NOT:
- declare vulnerabilities confirmed
- recommend unsafe auto-execution (delete/submit/pay/freeze)
- suggest bypassing safety gates
- invent API ids not in context

You should:
- diagnose transport vs crypto vs auth vs business failures
- interpret ErrorCode/Message patterns (e.g. version mismatch)
- propose concrete baseline field repairs (AppVersion, Token refresh)
- suggest follow-up tests within allowed mutation types

Output JSON:
{
  "pack_id": "...",
  "diagnosis": "1-3 sentence summary",
  "root_cause_hypothesis": "most likely root cause",
  "agrees_with_rule_plan": true/false,
  "confidence": 0.0-1.0,
  "recommended_actions": [
    {
      "action": "refresh_baseline_field|version_baseline_repair|schema_repair|diagnostic_mode|expand_frontier|switch_entry_api|continue_campaign",
      "priority": "P0|P1|P2",
      "field": "optional field name",
      "target_apis": ["op_..."],
      "rationale": "..."
    }
  ],
  "followup_test_hints": [
    {"api_id": "op_...", "mutation_type": "M0_baseline_replay", "note": "after baseline repair"}
  ]
}
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def generate_llm_feedback(
    pack_dir: Path,
    *,
    test_cases: List[Dict[str, Any]],
    executions: List[Dict[str, Any]],
    analyses: List[Dict[str, Any]],
    rule_plan: Dict[str, Any],
    baseline_context: Dict[str, Any],
    client: Optional[LLMClient] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    ctx = build_feedback_context(
        pack_dir,
        test_cases=test_cases,
        executions=executions,
        analyses=analyses,
        rule_plan=rule_plan,
        baseline_context=baseline_context,
    )
    record: Dict[str, Any] = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'agent': 'llm_feedback_agent',
        'status': 'pending',
    }

    if dry_run:
        record['status'] = 'dry_run_skipped'
        return {
            'record': record,
            'feedback': {},
            'merged_plan': rule_plan,
            'validation_errors': [],
        }

    try:
        client = client or LLMClient()
        user_msg = (
            'Analyze this verification campaign batch and propose advisory next actions.\n'
            'The rule-based plan is in rule_next_action_plan — agree or refine with evidence.\n\n'
            f'CONTEXT:\n{__import__("json").dumps(ctx, ensure_ascii=False, indent=2)}'
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
        return {
            'record': record,
            'feedback': {},
            'merged_plan': rule_plan,
            'validation_errors': [str(e)],
        }
    except Exception as e:
        record['status'] = 'error'
        record['error'] = str(e)
        return {
            'record': record,
            'feedback': {},
            'merged_plan': rule_plan,
            'validation_errors': [str(e)],
        }

    allowed_apis = {t.get('api_id') for t in test_cases if t.get('api_id')}
    _, errors, cleaned = validate_feedback_plan(
        payload,
        pack_id=ctx['pack_id'],
        allowed_api_ids=allowed_apis,
        rule_actions=rule_plan.get('recommended_actions') or [],
    )
    record['validation_errors'] = errors
    merged = merge_feedback_into_plan(rule_plan, cleaned, llm_record=record)
    return {
        'record': record,
        'feedback': cleaned,
        'merged_plan': merged,
        'validation_errors': errors,
        'raw': payload,
    }
