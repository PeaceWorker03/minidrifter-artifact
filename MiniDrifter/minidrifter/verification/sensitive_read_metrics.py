# -*- coding: utf-8 -*-
"""P4 sensitive read metrics — M0/M7/mutation split (not M7-only)."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from minidrifter.verification.chain_strict_runner import HOP_STATUS_OK
from minidrifter.verification.sensitive_api_oracle import analyze_sensitive_response

M0_OK_OUTCOMES = frozenset({
    HOP_STATUS_OK,
    'business_success',
    'm7_reached',
    'm0_ok',
})


def m0_business_success(row: Dict[str, Any]) -> bool:
    outcome = row.get('m0_outcome') or row.get('call_outcome') or row.get('m7_outcome')
    if outcome in M0_OK_OUTCOMES:
        return True
    if row.get('business_success') is True:
        return True
    status = str(row.get('status') or '')
    if status in {'m7_reached', 'm7_skipped', 'dry_run_planned'}:
        return True
    if row.get('reached_m7'):
        return True
    if row.get('status') == 'm7_skipped' and row.get('m0_outcome') == HOP_STATUS_OK:
        return True
    return False


def attach_sensitive_read_metrics(
    row: Dict[str, Any],
    *,
    path: str,
    m0_analysis: Optional[Dict[str, Any]] = None,
    m0_execution: Optional[Dict[str, Any]] = None,
    m7_analyses: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Augment probe/chain row with sensitive_read_m0/m7/mutation flags."""
    m7_analyses = m7_analyses or []
    body = None
    status_code = None
    if m0_execution:
        body = m0_execution.get('body_json') or m0_execution.get('response_json')
        status_code = m0_execution.get('status_code')
    if body is None and m0_analysis:
        body = m0_analysis.get('body_json') or m0_analysis.get('response_body')

    sens = analyze_sensitive_response(
        path=path,
        body=body,
        status_code=status_code,
    )
    m0_ok = m0_business_success({**(m0_analysis or {}), **row})
    m0_sensitive = m0_ok and bool(sens.get('has_sensitive'))
    m7_sensitive = bool(row.get('reached_m7')) and m0_sensitive
    mutation_tested = bool(row.get('m7_count') or len(m7_analyses) > 0)

    row['sensitive_api'] = sens
    row['sensitive_field_reads'] = sens.get('sensitive_field_reads') or []
    row['sensitive_read_m0_success'] = m0_sensitive
    row['sensitive_read_m7_success'] = m7_sensitive
    row['sensitive_mutation_tested'] = mutation_tested
    row['sensitive_read_success'] = m0_sensitive or m7_sensitive

    source = row.get('evidence_source') or row.get('source')
    if m0_sensitive:
        if source == 'baseline_intake':
            row['baseline_sensitive_read_m0_success'] = True
        elif source in {'live_campaign', 'replay', None}:
            row['live_sensitive_read_m0_success'] = True
            if not source:
                row['evidence_source'] = 'live_campaign'
    return row


def aggregate_plane_sensitive_counts(
    plane_entries: List[Dict[str, Any]],
    executed_rows: Dict[str, Dict[str, Any]],
    *,
    normalize_path,
    extra_paths: Optional[Set[str]] = None,
) -> Dict[str, int]:
    """Sum m0/m7/mutation sensitive read counters for one plane."""
    from minidrifter.materials.intake_param_hints import normalize_api_path as _norm

    norm = normalize_path or _norm
    m0 = m7 = mut = legacy = live_m0 = baseline_m0 = replay_fb = 0
    so_attempted = so_sensitive = 0
    paths = {norm(e.get('path') or '') for e in plane_entries if e.get('path')}
    paths.update(extra_paths or [])
    for p in paths:
        row = executed_rows.get(p)
        if not row:
            continue
        if row.get('sensitive_read_m0_success'):
            m0 += 1
        if row.get('live_sensitive_read_m0_success'):
            live_m0 += 1
        if row.get('baseline_sensitive_read_m0_success'):
            baseline_m0 += 1
        if row.get('replay_failed_but_baseline_valid'):
            replay_fb += 1
        if row.get('sensitive_read_m7_success'):
            m7 += 1
        if row.get('sensitive_mutation_tested'):
            mut += 1
        if row.get('subject_override_attempted'):
            so_attempted += 1
        if row.get('subject_override_sensitive_success'):
            so_sensitive += 1
        if row.get('sensitive_read_success'):
            legacy += 1
    return {
        'sensitive_read_m0_success': m0,
        'live_sensitive_read_m0_success': live_m0,
        'baseline_sensitive_read_m0_success': baseline_m0,
        'replay_failed_but_baseline_valid': replay_fb,
        'sensitive_read_m7_success': m7,
        'sensitive_mutation_tested': mut,
        'subject_override_attempted': so_attempted,
        'subject_override_sensitive_success': so_sensitive,
        'sensitive_read_success': max(m0, m7, legacy),
    }
