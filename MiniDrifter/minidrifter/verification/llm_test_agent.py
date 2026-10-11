# -*- coding: utf-8 -*-
"""LLM test / mutation proposal agent — intent-level proposals, rule-layer materialization."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.reasoning.llm_client import LLMClient, LLMClientError
from minidrifter.reasoning.validator import parse_json_from_llm
from minidrifter.verification.llm_context import build_test_generation_context
from minidrifter.verification.llm_validator import validate_test_proposals
from minidrifter.verification.mutation_engine import materialize_proposals

SYSTEM_PROMPT = """You are MiniDrifter Verification Test Agent.
Generate binding-aware test INTENTS — never final parameter values or vulnerability verdicts.

Constraints:
- Only use mutation_type from allowed_mutations in context
- Do NOT output param_overrides with $baseline refs (rule layer materializes params)
- Output mutation_operator + target_field + selector for binding tests
- selector.different_from MUST differ from the value you intend to test (e.g. "$baseline.UserId")
- Do NOT propose S3/S4 side-effect APIs or delete/submit/payment actions
- Do NOT output executable shell/python code with system calls
- Focus on subject-object binding checks for successful GET APIs

Output JSON schema:
{
  "pack_id": "...",
  "proposals": [
    {
      "proposal_id": "lp_001",
      "proposal_type": "binding_test",
      "binding_type": "subject_object",
      "parent_test_id": "tc_...",
      "api_id": "op_...",
      "mutation_type": "M7_subject_object_mismatch",
      "mutation_operator": "replace_with_same_type_different_value",
      "target_field": "userId",
      "required_pool": "subject_pool",
      "selector": {
        "field_class": "subject_credential",
        "field": "UserId",
        "different_from": "$baseline.UserId",
        "owner_account": "A"
      },
      "expected_secure_behavior": ["reject", "empty_result", "permission_denied"],
      "blocked_if": ["no_distinct_candidate", "unsafe_side_effect"],
      "rationale": "why this tests binding drift",
      "confidence": 0.0-1.0
    }
  ],
  "blocked_suggestions": [{"mutation_type": "...", "reason": "..."}]
}
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def propose_llm_tests(
    pack_dir: Path,
    test_cases: List[Dict[str, Any]],
    baseline_context: Dict[str, Any],
    *,
    object_pool: Optional[Dict[str, Any]] = None,
    client: Optional[LLMClient] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    ctx = build_test_generation_context(pack_dir, test_cases, baseline_context)
    record: Dict[str, Any] = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'agent': 'llm_test_agent',
        'status': 'pending',
        'context_summary': {
            'test_case_count': len(test_cases),
            'allowed_mutations': ctx.get('allowed_mutations'),
        },
    }

    if dry_run:
        record['status'] = 'dry_run_skipped'
        return {'record': record, 'proposals': [], 'validation_errors': [], 'materialization_blocked': []}

    try:
        client = client or LLMClient()
        user_msg = (
            'Generate up to 3 safe mutation INTENTS for the verification campaign.\n'
            'Prefer M7/M5 binding tests on APIs that returned business_success.\n'
            'Use selector.different_from to ensure the mutation is NOT a no-op.\n'
            'Do NOT output param_overrides.\n\n'
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
        return {'record': record, 'proposals': [], 'validation_errors': [str(e)], 'materialization_blocked': []}
    except Exception as e:
        record['status'] = 'error'
        record['error'] = str(e)
        return {'record': record, 'proposals': [], 'validation_errors': [str(e)], 'materialization_blocked': []}

    allowed_apis = {t.get('api_id') for t in test_cases if t.get('api_id')}
    allowed_parents = {t.get('test_id') for t in test_cases if t.get('test_id')}
    _, errors, approved = validate_test_proposals(
        payload,
        pack_id=ctx['pack_id'],
        allowed_api_ids=allowed_apis,
        allowed_parent_test_ids=allowed_parents,
    )
    record['validation_errors'] = errors
    record['proposal_count'] = len(approved)
    return {
        'record': record,
        'proposals': approved,
        'raw': payload,
        'validation_errors': errors,
        'materialization_blocked': [],
    }


def proposals_to_test_cases(
    proposals: List[Dict[str, Any]],
    test_cases_by_id: Dict[str, Dict[str, Any]],
    object_pool: Dict[str, Any],
    baseline_context: Dict[str, Any],
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    return materialize_proposals(proposals, test_cases_by_id, object_pool, baseline_context)
