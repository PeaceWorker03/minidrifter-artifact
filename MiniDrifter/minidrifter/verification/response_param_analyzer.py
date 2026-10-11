# -*- coding: utf-8
"""Response ↔ param deep analysis — M0/M7 pairs, harvest diff, binding drift score."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set


def _norm_fields(fields: Optional[List[str]]) -> Set[str]:
    return {str(f).lower() for f in (fields or []) if f}


def diff_harvest(before: List[str], after: List[str]) -> Dict[str, Any]:
    b, a = _norm_fields(before), _norm_fields(after)
    return {
        'gained': sorted(a - b),
        'lost': sorted(b - a),
        'unchanged': sorted(a & b),
    }


def compare_m0_m7_pair(
    m0_case: Dict[str, Any],
    m7_case: Dict[str, Any],
    m0_exec: Dict[str, Any],
    m7_exec: Dict[str, Any],
    m0_analysis: Dict[str, Any],
    m7_analysis: Dict[str, Any],
    *,
    baseline_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Compare baseline replay vs mutation on same API — universal binding drift lens."""
    baseline = (baseline_context or {}).get('resolved_fields') or {}
    m0_params = m0_case.get('params') or {}
    m7_params = m7_case.get('params') or {}

    mutated: List[Dict[str, Any]] = []
    for key, m7_val in m7_params.items():
        m0_val = m0_params.get(key)
        if m0_val is None:
            for bk, bv in baseline.items():
                if str(bk).lower() == str(key).lower():
                    m0_val = bv
                    break
        if m0_val is not None and str(m0_val) != str(m7_val):
            mutated.append({'field': key, 'm0': str(m0_val)[:32], 'm7': str(m7_val)[:32]})

    m0_out = m0_analysis.get('call_outcome') or 'unknown'
    m7_out = m7_analysis.get('call_outcome') or 'unknown'
    m0_sec = set(m0_analysis.get('security_signals') or [])
    m7_sec = set(m7_analysis.get('security_signals') or [])

    harvest_diff = diff_harvest(
        m0_analysis.get('produced_fields') or [],
        m7_analysis.get('produced_fields') or [],
    )

    drift_score = 0.0
    signals: List[str] = []

    if m0_out == 'business_success' and m7_out == 'business_success' and mutated:
        drift_score += 0.6
        signals.append('both_success_under_mutation')
    if 'subject_object_binding_mismatch' in m7_sec:
        drift_score += 0.9
        signals.append('binding_mismatch')
    if m0_out == 'business_success' and m7_out != 'business_success' and mutated:
        drift_score += 0.3
        signals.append('mutation_rejected')
    if m0_out != 'business_success' and m7_out == 'business_success':
        drift_score += 0.5
        signals.append('anomalous_m7_success')
    if harvest_diff.get('gained') or harvest_diff.get('lost'):
        drift_score += 0.2
        signals.append('harvest_delta')

    m0_snip = str(m0_exec.get('response_snippet') or '')[:200]
    m7_snip = str(m7_exec.get('response_snippet') or '')[:200]
    body_changed = m0_snip != m7_snip and bool(m7_snip)

    interpretation = _interpret_pair(m0_out, m7_out, mutated, signals, body_changed)

    return {
        'api_id': m7_case.get('api_id'),
        'path': m7_case.get('path'),
        'mutated_fields': mutated,
        'm0_outcome': m0_out,
        'm7_outcome': m7_out,
        'harvest_diff': harvest_diff,
        'body_changed_under_mutation': body_changed,
        'binding_drift_score': round(min(drift_score, 1.0), 2),
        'drift_signals': signals,
        'interpretation': interpretation,
    }


def _interpret_pair(
    m0_out: str,
    m7_out: str,
    mutated: List[Dict[str, Any]],
    signals: List[str],
    body_changed: bool,
) -> str:
    fields = ', '.join(m['field'] for m in mutated) or 'bindable fields'
    if 'binding_mismatch' in signals:
        return f"M7 on {fields} produced subject/object inconsistency — strong binding drift signal."
    if 'both_success_under_mutation' in signals and body_changed:
        return f"M0 and M7 both succeed with different {fields}; response body differs — verify scope enforcement."
    if 'both_success_under_mutation' in signals:
        return f"Server accepts mutated {fields} without rejection — potential weak binding."
    if 'mutation_rejected' in signals:
        return f"M7 rejected after M0 success — server may enforce binding on {fields}."
    if 'anomalous_m7_success' in signals:
        return f"M7 succeeded where M0 failed — check baseline freshness or param repair need."
    return "Insufficient M0/M7 contrast for binding assessment."


def enrich_correlation_with_pair(
    correlation: Dict[str, Any],
    pair: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    if not pair:
        return correlation
    out = dict(correlation)
    out['m0_m7_pair'] = pair
    if pair.get('binding_drift_score', 0) >= 0.6:
        out['response_delta'] = 'binding_drift_confirmed'
        out['interpretation'] = pair.get('interpretation') or out.get('interpretation')
    return out


def find_m0_pair(
    test_case: Dict[str, Any],
    *,
    test_cases_by_id: Dict[str, Dict[str, Any]],
    executions_by_id: Dict[str, Dict[str, Any]],
    analyses_by_id: Dict[str, Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Locate M0 baseline for same api_id in chain."""
    api_id = test_case.get('api_id')
    chain_id = test_case.get('chain_id')
    if not api_id:
        return None
    for tid, tc in test_cases_by_id.items():
        if tc.get('api_id') != api_id:
            continue
        if chain_id and tc.get('chain_id') != chain_id:
            continue
        if (tc.get('mutation_type') or '').startswith('M0'):
            ex = executions_by_id.get(tid)
            an = analyses_by_id.get(tid)
            if ex and an:
                return {'test_case': tc, 'execution': ex, 'analysis': an}
    return None
