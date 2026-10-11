# -*- coding: utf-8 -*-
"""Aggregate verification outcomes into human-readable analysis report."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def _load_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def build_verification_analysis_report(
    pack_dir: Path,
    *,
    preflight: Optional[Dict[str, Any]] = None,
    campaign_rounds: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    coverage = _load_json(pack_dir / 'coverage_report.json') or {}
    preflight = preflight or _load_json(pack_dir / 'replay_preflight_report.json') or {}
    search_session = _load_json(pack_dir / 'search_session.json') or {}
    budget_panel = _load_json(pack_dir / 'budget_panel.json') or {}
    finding_registry = _load_json(pack_dir / 'finding_registry.json') or {}
    chain_reports_doc = _load_json(pack_dir / 'finding_chain_reports.json') or {}
    depth_chains = (_load_json(pack_dir / 'depth_chain_state.json') or {}).get('chains') or []

    analyses = _load_jsonl(pack_dir / 'response_analysis.jsonl')
    executions = _load_jsonl(pack_dir / 'execution_results.jsonl')
    findings = _load_jsonl(pack_dir / 'findings.jsonl')
    if not findings and finding_registry.get('findings'):
        findings = finding_registry['findings']

    next_plan = _load_json(pack_dir / 'next_action_plan.json') or {}
    llm_fb = _load_json(pack_dir / 'llm_feedback_plan.json') or {}

    by_outcome: Dict[str, int] = {}
    by_api: Dict[str, List[str]] = {}
    successes: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []

    for a in analyses:
        oc = a.get('call_outcome') or 'unknown'
        by_outcome[oc] = by_outcome.get(oc, 0) + 1
        api = a.get('path') or a.get('api_id') or '?'
        by_api.setdefault(api, []).append(oc)
        row = {
            'test_id': a.get('test_id'),
            'path': a.get('path'),
            'call_outcome': oc,
            'failure_class': a.get('failure_class'),
            'mutation': next((e.get('mutation_type') for e in executions if e.get('test_id') == a.get('test_id')), None),
        }
        if oc == 'business_success':
            successes.append(row)
        elif oc not in ('dry_run_ok',):
            failures.append(row)

    exec_by_id = {e.get('test_id'): e for e in executions}
    binding_notes: List[str] = []
    for a in analyses:
        if a.get('call_outcome') != 'business_success':
            continue
        ex = exec_by_id.get(a.get('test_id')) or {}
        body = ex.get('body_json') or {}
        if isinstance(body, dict) and body.get('Result') == []:
            binding_notes.append(
                f"{a.get('path')}: business success with empty Result (possible binding isolation)"
            )
        elif a.get('produced_fields'):
            binding_notes.append(
                f"{a.get('path')}: produced {', '.join(a.get('produced_fields') or [])}"
            )

    lifecycle = finding_registry.get('summary') or _lifecycle_summary(findings)
    chain_reports = chain_reports_doc.get('reports') or []

    llm_diag = (llm_fb.get('feedback') or {}).get('diagnosis')
    verdict = _compute_verdict(coverage, search_session, preflight, lifecycle, successes, failures)

    report = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'verdict': verdict,
        'executive_summary': _executive_summary(
            verdict, coverage, search_session, preflight, successes, failures, lifecycle,
        ),
        'preflight': {
            'ready': preflight.get('ready'),
            'blockers': preflight.get('blockers') or [],
            'warnings': preflight.get('warnings') or [],
        },
        'search_session': search_session,
        'budget_panel': budget_panel,
        'coverage': search_session.get('coverage') or coverage,
        'campaign_rounds': campaign_rounds or [],
        'outcome_histogram': by_outcome,
        'by_api': by_api,
        'business_successes': successes,
        'failures': failures[:20],
        'findings': findings,
        'finding_lifecycle': lifecycle,
        'finding_chain_reports': chain_reports,
        'depth_chains': depth_chains,
        'binding_notes': binding_notes,
        'llm_diagnosis': llm_diag,
        'recommended_actions': next_plan.get('recommended_actions') or [],
        'deep_dive_ready': (search_session.get('coverage') or coverage).get('business_success', 0) > 0
        or len(successes) > 0,
    }
    return report


def _lifecycle_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts: Dict[str, int] = {'confirmed': 0, 'hypothesis': 0, 'rejected': 0, 'pruned': 0}
    for f in findings:
        st = f.get('status') or 'hypothesis'
        counts[st] = counts.get(st, 0) + 1
    return {'total': len(findings), 'by_status': counts, **counts}


def _compute_verdict(coverage, search_session, preflight, lifecycle, successes, failures) -> str:
    if search_session.get('verdict'):
        base = search_session['verdict']
        if lifecycle.get('confirmed', 0) > 0:
            return 'finding_confirmed'
        if base == 'success' and failures:
            return 'partial_success'
        return base
    if lifecycle.get('confirmed', 0) > 0:
        return 'finding_confirmed'
    if coverage.get('business_success', 0) > 0:
        return 'partial_success' if failures else 'success'
    if preflight.get('ready') and coverage.get('tests_executed', 0) > 0:
        return 'live_reachable_no_business_success'
    return 'blocked'


def _executive_summary(verdict, coverage, search_session, preflight, successes, failures, lifecycle) -> str:
    cov = search_session.get('coverage') or coverage or {}
    parts = [f"Verdict: {verdict}."]
    if preflight:
        parts.append(
            f"Preflight {'passed' if preflight.get('ready') else 'blocked'} "
            f"({preflight.get('summary', {}).get('checks_passed', '?')}/"
            f"{preflight.get('summary', {}).get('checks_total', '?')} checks)."
        )
    bs = cov.get('business_success', 0)
    te = cov.get('http_calls') or cov.get('tests_executed', 0)
    parts.append(f"Executed: {bs}/{te} business successes.")
    fc = lifecycle.get('confirmed', 0)
    fh = lifecycle.get('hypothesis', 0)
    if fc or fh:
        parts.append(f"Findings: {fc} confirmed, {fh} hypothesis, {lifecycle.get('rejected', 0)} rejected.")
    if successes:
        paths = sorted({s.get('path') for s in successes if s.get('path')})
        parts.append(f"Live OK APIs: {', '.join(paths[:5])}.")
    if failures:
        mix: Dict[str, int] = {}
        for f in failures:
            k = f.get('failure_class') or f.get('call_outcome')
            mix[k] = mix.get(k, 0) + 1
        parts.append(f"Failure mix: {mix}.")
    return ' '.join(parts)


def write_analysis_report(pack_dir: Path, report: Dict[str, Any]) -> Dict[str, str]:
    pack_dir = Path(pack_dir)
    json_path = pack_dir / 'verification_analysis_report.json'
    md_path = pack_dir / 'verification_analysis_report.md'
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    md_path.write_text(render_analysis_markdown(report), encoding='utf-8')
    return {'json': str(json_path), 'markdown': str(md_path)}


def render_analysis_markdown(report: Dict[str, Any]) -> str:
    lines = [
        '# Verification Analysis Report',
        '',
        f"**Generated:** {report.get('generated_at')}",
        f"**Verdict:** `{report.get('verdict')}`",
        '',
        '## Executive Summary',
        '',
        report.get('executive_summary') or '',
        '',
    ]

    ss = report.get('search_session') or {}
    if ss:
        lines.extend(['## Search Session (PBWS)', ''])
        budget = ss.get('budget') or {}
        cov = ss.get('coverage') or {}
        lines.append(f"- Mode: **{ss.get('mode')}** | Status: **{ss.get('status')}**")
        lines.append(f"- HTTP budget: **{budget.get('used_http')}/{budget.get('max_http')}**")
        lines.append(f"- Seeds retired: **{cov.get('seeds_retired')}/{budget.get('max_seeds')}**")
        lines.append(f"- Depth chains: **{cov.get('depth_chains')}** | Pruned: **{cov.get('pruned')}**")
        wg = ss.get('workflow_graph_stats') or {}
        if wg:
            lines.append(
                f"- Workflow graph: **{wg.get('workflow_candidate_apis')}** candidate APIs, "
                f"avg business requires **{wg.get('avg_business_requires_per_api')}**"
            )
        lines.append('')

    bp = report.get('budget_panel') or {}
    if bp.get('efficiency'):
        eff = bp['efficiency']
        lines.extend(['## Efficiency', ''])
        lines.append(f"- Prune rate: **{eff.get('prune_rate')}** ({eff.get('pruned')} pruned / {eff.get('http_calls')} executed)")
        lines.append('')

    lines.extend(['## Preflight', ''])
    pf = report.get('preflight') or {}
    lines.append(f"- Ready: **{pf.get('ready')}**")
    for b in pf.get('blockers') or []:
        msg = b.get('message') if isinstance(b, dict) else str(b)
        layer = b.get('layer', '') if isinstance(b, dict) else ''
        lines.append(f"- BLOCKER [{layer}]: {msg}")
    for w in pf.get('warnings') or []:
        msg = w.get('message') if isinstance(w, dict) else str(w)
        lines.append(f"- WARN: {msg}")

    lines.extend(['', '## Outcomes', ''])
    for k, v in sorted((report.get('outcome_histogram') or {}).items()):
        lines.append(f"- {k}: {v}")

    lc = report.get('finding_lifecycle') or {}
    if lc.get('total'):
        lines.extend(['', '## Finding Lifecycle', ''])
        for st in ('confirmed', 'hypothesis', 'rejected', 'pruned'):
            if lc.get(st):
                lines.append(f"- **{st}**: {lc.get(st)}")

    chain_reports_raw = report.get('finding_chain_reports') or []
    if isinstance(chain_reports_raw, dict):
        chain_reports = chain_reports_raw.get('reports') or []
    else:
        chain_reports = chain_reports_raw
    confirmed_reports = [r for r in chain_reports if r.get('status') == 'confirmed']
    if confirmed_reports:
        lines.extend(['', '## Confirmed Findings (Evidence Chains)', ''])
        for r in confirmed_reports:
            lines.extend(_render_chain_report_section(r))

    hypothesis_reports = [r for r in chain_reports if r.get('status') == 'hypothesis']
    if hypothesis_reports:
        lines.extend(['', '## Hypothesis Findings', ''])
        for r in hypothesis_reports:
            lines.append(f"### {r.get('finding_type')} @ `{r.get('finding_id')}`")
            lines.append('')
            lines.append(r.get('binding_narrative') or '')
            lines.append('')

    if report.get('business_successes'):
        lines.extend(['', '## Business Successes', ''])
        for s in report['business_successes']:
            lines.append(f"- `{s.get('path')}` test={s.get('test_id')} mutation={s.get('mutation')}")

    if report.get('binding_notes'):
        lines.extend(['', '## Binding / Harvest Notes', ''])
        for n in report['binding_notes']:
            lines.append(f"- {n}")

    if report.get('llm_diagnosis'):
        lines.extend(['', '## LLM Diagnosis', '', report['llm_diagnosis'], ''])

    if report.get('recommended_actions'):
        lines.extend(['', '## Recommended Next Actions', ''])
        for a in report['recommended_actions'][:8]:
            lines.append(f"- [{a.get('priority')}] **{a.get('action')}** — {a.get('reason')}")

    lines.extend(['', '## Deep Dive Status', ''])
    lines.append(
        'Ready for mutation/binding deep-dive.' if report.get('deep_dive_ready')
        else 'Blocked — fix preflight/credential/params before expanding mutations.'
    )
    return '\n'.join(lines) + '\n'


def _render_chain_report_section(report: Dict[str, Any]) -> List[str]:
    tier = report.get('finding_tier_label') or report.get('finding_tier') or ''
    lines = [
        f"### {report.get('finding_type')} @ `{report.get('finding_id')}`",
        '',
        f"**Finding Type:** {tier or 'unclassified'}",
        f"**Severity:** {report.get('severity')} | **Status:** {report.get('status')}",
        '',
        report.get('binding_narrative') or '',
        '',
        '#### Evidence Chain',
        '',
    ]
    for step in report.get('evidence_steps') or []:
        marker = ' **[FINDING]**' if step.get('is_finding_step') else ''
        rs = step.get('response_summary') or {}
        lines.append(
            f"{step.get('step_index') + 1}. `{step.get('path')}` "
            f"({step.get('mutation_type') or 'M0'}) → **{rs.get('call_outcome')}**"
            f"{marker}"
        )
        if rs.get('binding_status'):
            lines.append(f"   - binding: {rs.get('binding_status')}")
        if rs.get('produced_fields'):
            lines.append(f"   - harvest: {', '.join(rs.get('produced_fields'))}")
        if step.get('param_diff', {}).get('changed_fields'):
            lines.append(f"   - param diff: {', '.join(step['param_diff']['changed_fields'])}")
    lines.append('')
    return lines
