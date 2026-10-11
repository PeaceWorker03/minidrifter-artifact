# -*- coding: utf-8
"""Evidence chain reports — full finding → chain → test → response trace."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from minidrifter.core.schema import SCHEMA_VERSION


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _response_summary(execution: Dict[str, Any], analysis: Dict[str, Any]) -> Dict[str, Any]:
    body = execution.get('body_json') or {}
    summary: Dict[str, Any] = {
        'call_outcome': analysis.get('call_outcome') or execution.get('call_outcome'),
        'failure_class': analysis.get('failure_class'),
        'transport_status': execution.get('transport_status'),
    }
    if isinstance(body, dict):
        summary['is_success'] = body.get('IsSuccess')
        summary['error_code'] = body.get('ErrorCode')
        summary['message'] = (body.get('Message') or '')[:200] if body.get('Message') else None
        result = body.get('Result')
        if isinstance(result, list):
            summary['result_count'] = len(result)
        elif result is not None:
            summary['result_type'] = type(result).__name__
    summary['produced_fields'] = analysis.get('produced_fields') or []
    summary['security_signals'] = analysis.get('security_signals') or []
    summary['binding_status'] = (analysis.get('binding_observation') or {}).get('binding_status')
    return summary


def _param_diff_redacted(
    baseline_tc: Optional[Dict[str, Any]],
    tc: Dict[str, Any],
) -> Dict[str, Any]:
    if not baseline_tc:
        return {'changed_fields': list((tc.get('params') or {}).keys())}
    base_params = baseline_tc.get('params') or {}
    mut_params = tc.get('params') or {}
    changed = []
    for k in set(base_params) | set(mut_params):
        if base_params.get(k) != mut_params.get(k):
            changed.append(k)
    return {'changed_fields': changed, 'mutation_type': tc.get('mutation_type')}


def build_chain_evidence_steps(
    *,
    chain: Dict[str, Any],
    executions: List[Dict[str, Any]],
    analyses: List[Dict[str, Any]],
    test_cases_by_id: Dict[str, Dict[str, Any]],
    finding_test_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    exec_by_id = {e.get('test_id'): e for e in executions if e.get('test_id')}
    ana_by_id = {a.get('test_id'): a for a in analyses if a.get('test_id')}

    chain_test_ids: List[str] = []
    for node in chain.get('nodes') or []:
        api_id = node.get('api_id')
        for tid, tc in test_cases_by_id.items():
            if tc.get('api_id') == api_id and tid not in chain_test_ids:
                chain_test_ids.append(tid)

    for tid in exec_by_id:
        if tid not in chain_test_ids and test_cases_by_id.get(tid, {}).get('chain_id') == chain.get('chain_id'):
            chain_test_ids.append(tid)

    steps: List[Dict[str, Any]] = []
    seed_m0: Optional[Dict[str, Any]] = None
    for i, tid in enumerate(chain_test_ids):
        tc = test_cases_by_id.get(tid) or {}
        ex = exec_by_id.get(tid) or {}
        an = ana_by_id.get(tid) or {}
        if tc.get('mutation_type') == 'M0_baseline_replay' and tc.get('test_stage') == 'seed_baseline':
            seed_m0 = tc

        steps.append({
            'step_index': i,
            'test_id': tid,
            'api_id': tc.get('api_id') or ex.get('api_id'),
            'path': tc.get('path') or ex.get('path'),
            'role': tc.get('chain_role') or ('seed' if i == 0 else 'consumer'),
            'mutation_type': tc.get('mutation_type'),
            'test_stage': tc.get('test_stage'),
            'param_diff': _param_diff_redacted(seed_m0 if tc.get('mutation_type', '').startswith('M7') else None, tc),
            'request_preview': ex.get('request_preview_redacted'),
            'response_summary': _response_summary(ex, an),
            'signals': an.get('signals') or {},
            'is_finding_step': tid == finding_test_id,
        })
    return steps


def build_finding_chain_report(
    finding: Dict[str, Any],
    *,
    chain: Optional[Dict[str, Any]],
    executions: List[Dict[str, Any]],
    analyses: List[Dict[str, Any]],
    test_cases_by_id: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    chain = chain or {}
    finding_tid = finding.get('test_id')
    steps = build_chain_evidence_steps(
        chain=chain,
        executions=executions,
        analyses=analyses,
        test_cases_by_id=test_cases_by_id,
        finding_test_id=finding_tid,
    )

    narrative = _binding_narrative(finding, steps)

    return {
        'schema_version': SCHEMA_VERSION,
        'finding_id': finding.get('finding_id'),
        'finding_type': finding.get('finding_type'),
        'status': finding.get('status'),
        'severity': finding.get('severity'),
        'confidence': finding.get('confidence'),
        'chain_id': finding.get('chain_id') or chain.get('chain_id'),
        'seed_api': chain.get('seed_api'),
        'chain_depth': chain.get('depth'),
        'chain_nodes': chain.get('nodes') or [],
        'chain_stop_reason': chain.get('stop_reason'),
        'evidence_steps': steps,
        'binding_narrative': narrative,
        'lifecycle': {
            'status_history': finding.get('status_history') or [],
            'lifecycle_reason': finding.get('lifecycle_reason'),
            'source': finding.get('source'),
            'adjudicated_at': finding.get('adjudicated_at'),
        },
        'generated_at': _utc_now(),
    }


def build_all_chain_reports(
    findings: List[Dict[str, Any]],
    *,
    depth_chains: List[Dict[str, Any]],
    executions: List[Dict[str, Any]],
    analyses: List[Dict[str, Any]],
    test_cases_by_id: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    chain_by_id = {c.get('chain_id'): c for c in depth_chains if c.get('chain_id')}
    reports: List[Dict[str, Any]] = []

    for finding in findings:
        if finding.get('status') == 'pruned':
            continue
        chain = chain_by_id.get(finding.get('chain_id') or '')
        reports.append(build_finding_chain_report(
            finding,
            chain=chain,
            executions=executions,
            analyses=analyses,
            test_cases_by_id=test_cases_by_id,
        ))

    confirmed = [r for r in reports if r.get('status') == 'confirmed']
    hypothesis = [r for r in reports if r.get('status') == 'hypothesis']
    rejected = [r for r in reports if r.get('status') == 'rejected']

    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'report_count': len(reports),
        'confirmed_count': len(confirmed),
        'hypothesis_count': len(hypothesis),
        'rejected_count': len(rejected),
        'reports': reports,
    }


def _binding_narrative(finding: Dict[str, Any], steps: List[Dict[str, Any]]) -> str:
    ftype = finding.get('finding_type') or 'finding'
    path = finding.get('api_path') or '?'
    status = finding.get('status') or 'unknown'

    parts = [f"[{status}] {ftype} at {path}."]
    finding_steps = [s for s in steps if s.get('is_finding_step')]
    if finding_steps:
        fs = finding_steps[0]
        binding = (fs.get('response_summary') or {}).get('binding_status')
        if binding:
            parts.append(f"Binding status: {binding}.")
        mut = fs.get('mutation_type')
        if mut:
            parts.append(f"Mutation: {mut}.")
        changed = (fs.get('param_diff') or {}).get('changed_fields') or []
        if changed:
            parts.append(f"Param changes: {', '.join(changed)}.")

    if len(steps) > 1:
        hop_paths = [s.get('path') for s in steps if s.get('path')]
        parts.append(f"Chain ({len(steps)} hops): {' → '.join(hop_paths[:5])}.")

    return ' '.join(parts)
