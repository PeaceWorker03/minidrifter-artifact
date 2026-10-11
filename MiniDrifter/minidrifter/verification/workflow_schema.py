# -*- coding: utf-8 -*-
"""JSON emit schemas for workflow / strategy LLM agents."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

WORKFLOW_EMIT_KEYS = frozenset({
    'stop', 'next_api_id', 'binding_hypothesis', 'link_role', 'rationale',
    'frontier_hypothesis', 'suggested_apis_after_harvest',
})

STRATEGY_EMIT_KEYS = frozenset({'proposals', 'blocked_suggestions', 'strategy_notes'})


def slim_candidate(c: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'api_id': c.get('api_id'),
        'path': c.get('path'),
        'required': c.get('required'),
        'unlocked_by': c.get('unlocked_by'),
        'score': c.get('score'),
    }


def slim_near_miss(c: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'api_id': c.get('api_id'),
        'path': c.get('path'),
        'required': c.get('required'),
        'missing_fields': c.get('missing_fields'),
        'score': c.get('score'),
    }


def workflow_link_from_candidate(
    pick: Dict[str, Any],
    *,
    test_cases: List[Dict[str, Any]],
    source: str,
    link_hypothesis: str,
    trace_id: Optional[str] = None,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        'stop': False,
        'reason': None,
        'next_api': pick,
        'link_hypothesis': link_hypothesis,
        'next_test_cases': test_cases,
        'source': source,
    }
    if trace_id:
        out['trace_id'] = trace_id
    return out
