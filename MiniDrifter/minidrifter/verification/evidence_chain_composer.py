# -*- coding: utf-8
"""Compose ordered multi-hop evidence chains from finding escalation plans."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from minidrifter.core.utils import stable_id
from minidrifter.verification.campaign_planner import build_test_case
from minidrifter.verification.finding_escalation_planner import _materialize_m7_cases


def compose_evidence_chain(
    *,
    escalation_plan: Dict[str, Any],
    llm_out: Optional[Dict[str, Any]] = None,
    baseline_context: Dict[str, Any],
    object_pool: Dict[str, Any],
    ir_session: Any = None,
    chain_id: Optional[str] = None,
    max_hops: int = 4,
) -> Dict[str, Any]:
    """Turn prioritized escalation targets into an ordered evidence chain (M0 then M7 per hop)."""
    finding_id = escalation_plan.get('finding_id') or stable_id('evidence')
    summary = escalation_plan.get('finding_summary') or {}
    targets = (llm_out or {}).get('reordered_targets') or escalation_plan.get('targets') or []
    targets = targets[:max_hops]

    hops: List[Dict[str, Any]] = [{
        'order': 0,
        'role': 'finding_origin',
        'api_id': summary.get('api_id'),
        'path': summary.get('path'),
        'strategy': 'finding_confirmed',
    }]
    for i, t in enumerate(targets, start=1):
        hops.append({
            'order': i,
            'role': 'escalation_hop',
            'api_id': t.get('api_id'),
            'path': t.get('path'),
            'strategy': t.get('llm_strategy') or t.get('strategy'),
            'rationale': t.get('llm_rationale') or t.get('rationale'),
            'expected_signal': t.get('expected_signal'),
        })

    m7_cases = _materialize_m7_cases(
        targets,
        baseline_context=baseline_context,
        object_pool=object_pool,
        ir_session=ir_session,
        finding_id=finding_id,
        chain_id=chain_id,
        index_start=6000,
    )
    m0_cases: List[Dict[str, Any]] = []
    for i, t in enumerate(targets):
        tpl = t.get('template')
        if not tpl:
            continue
        m0 = build_test_case(tpl, baseline_context=baseline_context, index=6100 + i * 2)
        m0['test_stage'] = 'evidence_chain_m0'
        m0['evidence_hop_order'] = i + 1
        m0['evidence_chain_id'] = f'ev_{finding_id}'
        m0['escalation_from_finding'] = finding_id
        if chain_id:
            m0['chain_id'] = chain_id
        m0_cases.append(m0)

    ordered_tests: List[Dict[str, Any]] = []
    m7_by_api = {}
    for tc in m7_cases:
        m7_by_api[tc.get('api_id')] = tc
    for i, t in enumerate(targets):
        for m0 in m0_cases:
            if m0.get('api_id') == t.get('api_id'):
                ordered_tests.append(m0)
                break
        m7 = m7_by_api.get(t.get('api_id'))
        if m7:
            m7['evidence_hop_order'] = i + 1
            m7['evidence_chain_id'] = f'ev_{finding_id}'
            m7['test_stage'] = 'evidence_chain_m7'
            ordered_tests.append(m7)

    return {
        'evidence_chain_id': f'ev_{finding_id}',
        'finding_id': finding_id,
        'chain_extension_goal': (llm_out or {}).get('chain_extension_goal'),
        'escalation_hypothesis': (llm_out or {}).get('hypothesis'),
        'hops': hops,
        'ordered_test_cases': ordered_tests,
        'hop_count': len(hops),
    }
