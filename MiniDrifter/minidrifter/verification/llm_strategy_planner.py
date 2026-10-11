# -*- coding: utf-8 -*-
"""A1 LLM Strategy Planner — seed test strategy with S-TRACE."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.reasoning.llm_client import LLMClient, LLMClientError
from minidrifter.reasoning.validator import parse_json_from_llm
from minidrifter.verification.llm_context import build_strategy_context
from minidrifter.verification.llm_trace import make_trace
from minidrifter.verification.llm_validator import parse_strace_payload, validate_test_proposals
from minidrifter.verification.mutation_engine import materialize_proposals

SYSTEM_PROMPT = """You are MiniDrifter A1 Strategy Planner.
Plan safe binding-verification mutation INTENTS for a seed API probe.

Rules:
- Output S-TRACE JSON with steps: observe, hypothesize, plan, constraint_check, emit
- emit.proposals follow mutation intent schema (no param values, use selector)
- Only propose mutation_type from allowed_mutations in context
- parent_test_id must match the seed M0 test_id provided in context
- api_id must match seed api_id
- Do NOT declare vulnerabilities or output executable code
- Prefer M7/M5 binding tests when UserId or object identifiers appear in params
- If disagrees with rule-only M7, log in disagreements[] — do not override safety

Output JSON:
{
  "trace_id": "tr_...",
  "stage": "strategy_planner",
  "steps": [
    {"step": "observe", "content": "..."},
    {"step": "hypothesize", "content": "..."},
    {"step": "plan", "content": "..."},
    {"step": "constraint_check", "content": "..."},
    {"step": "emit", "content": "..."}
  ],
  "confidence": 0.0-1.0,
  "disagreements": [],
  "emit": {
    "proposals": [
      {
        "proposal_id": "sp_001",
        "parent_test_id": "tc_...",
        "api_id": "op_...",
        "mutation_type": "M7_subject_object_mismatch",
        "mutation_operator": "replace_with_same_type_different_value",
        "target_field": "userId",
        "selector": {
          "field": "UserId",
          "different_from": "$baseline.UserId",
          "required_pool": "negative_pool"
        },
        "rationale": "..."
      }
    ],
    "blocked_suggestions": [],
    "strategy_notes": "optional"
  }
}
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def propose_seed_strategy(
    pack_dir: Path,
    seed: Dict[str, Any],
    *,
    baseline_context: Dict[str, Any],
    object_pool: Dict[str, Any],
    m0_test_case: Dict[str, Any],
    prior_feedback: Optional[List[Dict[str, Any]]] = None,
    client: Optional[LLMClient] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    ctx = build_strategy_context(
        pack_dir, seed, baseline_context, object_pool, prior_feedback=prior_feedback,
    )
    ctx['seed_m0_test_id'] = m0_test_case.get('test_id')

    record: Dict[str, Any] = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'agent': 'llm_strategy_planner',
        'status': 'pending',
        'seed_id': seed.get('seed_id'),
        'api_id': seed.get('api_id'),
    }

    if dry_run:
        record['status'] = 'dry_run_skipped'
        trace = make_trace(
            'strategy_planner',
            [{'step': 'observe', 'content': 'dry_run: LLM strategy skipped'}],
            {'proposals': [], 'blocked_suggestions': []},
            status='dry_run_skipped',
        )
        return {
            'record': record,
            'trace': trace,
            'proposals': [],
            'validation_errors': [],
            'materialization_blocked': [],
        }

    try:
        client = client or LLMClient()
        user_msg = (
            'Plan up to 2 additional safe mutation intents for this seed API.\n'
            f'Seed M0 test_id={m0_test_case.get("test_id")} — use as parent_test_id.\n'
            'Rule layer may already plan M7; propose complementary binding tests if warranted.\n'
            'Do NOT output param_overrides.\n\n'
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
        return {
            'record': record,
            'trace': None,
            'proposals': [],
            'validation_errors': [str(e)],
            'materialization_blocked': [],
        }
    except Exception as e:
        record['status'] = 'error'
        record['error'] = str(e)
        return {
            'record': record,
            'trace': None,
            'proposals': [],
            'validation_errors': [str(e)],
            'materialization_blocked': [],
        }

    trace, trace_errors = parse_strace_payload(payload, expected_stage='strategy_planner')
    emit = trace.get('emit') or {}
    proposal_doc = {
        'pack_id': ctx['pack_id'],
        'proposals': emit.get('proposals') or [],
    }

    allowed_apis = {seed.get('api_id')} if seed.get('api_id') else set()
    allowed_parents = {m0_test_case.get('test_id')} if m0_test_case.get('test_id') else set()
    _, val_errors, approved = validate_test_proposals(
        proposal_doc,
        pack_id=ctx['pack_id'],
        allowed_api_ids=allowed_apis,
        allowed_parent_test_ids=allowed_parents,
    )
    all_errors = trace_errors + val_errors
    record['validation_errors'] = all_errors
    record['proposal_count'] = len(approved)

    full_trace = make_trace(
        'strategy_planner',
        trace.get('steps') or [],
        emit,
        confidence=trace.get('confidence'),
        trace_id=trace.get('trace_id') or payload.get('trace_id'),
        disagreements=trace.get('disagreements'),
        status='ok' if approved or not emit.get('proposals') else 'partial',
        rule_fallback='rule_strategy_planner' if all_errors else None,
    )

    return {
        'record': record,
        'trace': full_trace,
        'proposals': approved,
        'validation_errors': all_errors,
        'materialization_blocked': [],
        'raw': payload,
    }


def materialize_strategy_proposals(
    proposals: List[Dict[str, Any]],
    test_cases_by_id: Dict[str, Dict[str, Any]],
    object_pool: Dict[str, Any],
    baseline_context: Dict[str, Any],
    *,
    seed_id: Optional[str] = None,
    start_index: int = 10,
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    materialized, blocked = materialize_proposals(
        proposals, test_cases_by_id, object_pool, baseline_context,
    )
    for tc in materialized:
        tc['seed_id'] = seed_id
        tc['strategy_source'] = 'llm_strategy_planner'
    return materialized, blocked
