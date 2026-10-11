# -*- coding: utf-8 -*-
"""S-TRACE — structured multi-stage reasoning traces for verification LLM agents."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.schema import SCHEMA_VERSION
from minidrifter.core.utils import stable_id

STRACE_STAGES = frozenset({
    'strategy_planner', 'workflow_planner', 'mutation_intent', 'blocker_diagnostician',
    'chain_reasoner', 'policy_replanner', 'finding_escalation',
})
STRACE_STEP_NAMES = frozenset({'observe', 'hypothesize', 'plan', 'constraint_check', 'emit'})


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def make_trace(
    stage: str,
    steps: List[Dict[str, Any]],
    emit: Dict[str, Any],
    *,
    confidence: Optional[float] = None,
    trace_id: Optional[str] = None,
    disagreements: Optional[List[Dict[str, Any]]] = None,
    rule_fallback: Optional[str] = None,
    status: str = 'ok',
) -> Dict[str, Any]:
    return {
        'schema_version': SCHEMA_VERSION,
        'trace_id': trace_id or stable_id('tr', stage),
        'stage': stage,
        'generated_at': _utc_now(),
        'status': status,
        'steps': steps,
        'confidence': confidence,
        'disagreements': disagreements or [],
        'rule_fallback': rule_fallback,
        'emit': emit,
    }


def validate_trace_shape(trace: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if trace.get('stage') not in STRACE_STAGES:
        errors.append(f"invalid stage: {trace.get('stage')}")
    steps = trace.get('steps') or []
    if not steps:
        errors.append('steps required')
    for i, step in enumerate(steps):
        if step.get('step') not in STRACE_STEP_NAMES:
            errors.append(f'step[{i}] invalid step name: {step.get("step")}')
        if not str(step.get('content') or '').strip():
            errors.append(f'step[{i}] empty content')
    emit = trace.get('emit')
    if not isinstance(emit, dict):
        errors.append('emit must be object')
    conf = trace.get('confidence')
    if conf is not None and not (0 <= float(conf) <= 1):
        errors.append('confidence out of range')
    return errors


def append_trace_log(pack_dir: Path, traces: List[Dict[str, Any]]) -> Path:
    path = Path(pack_dir) / 'llm_trace.jsonl'
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text(encoding='utf-8') if path.exists() else ''
    lines = [json.dumps(t, ensure_ascii=False) for t in traces]
    path.write_text(existing + ('\n'.join(lines) + '\n' if lines else ''), encoding='utf-8')
    return path


def write_trace_session(pack_dir: Path, traces: List[Dict[str, Any]], summary: Dict[str, Any]) -> None:
    from minidrifter.core.utils import write_json

    write_json(Path(pack_dir) / 'llm_trace_session.json', {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'trace_count': len(traces),
        'summary': summary,
        'traces': [t.get('trace_id') for t in traces],
    })
