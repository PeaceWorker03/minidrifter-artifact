# -*- coding: utf-8 -*-
"""Orchestrate verification campaign: plan → execute → analyze → expand → next wave."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import write_json
from minidrifter.verification.campaign_planner import plan_campaign
from minidrifter.verification.executor import execute_test_case
from minidrifter.verification.frontier_expander import expand_frontier
from minidrifter.verification.object_pool import init_object_pool, update_pool_from_analysis, write_object_pools
from minidrifter.verification.planner_state import (
    build_next_action_plan,
    init_planner_state,
    update_planner_state,
)
from minidrifter.verification.response_oracle import analyze_response
from minidrifter.verification.safety_policy import evaluate_test_safety


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _write_jsonl(path: Path, records: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        '\n'.join(json.dumps(r, ensure_ascii=False) for r in records) + ('\n' if records else ''),
        encoding='utf-8',
    )


def _load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding='utf-8'))


def _run_llm_test_enrichment(
    pack_dir: Path,
    test_cases: List[Dict[str, Any]],
    baseline_context: Dict[str, Any],
    object_pool: Dict[str, Any],
    *,
    llm_dry_run: bool = False,
    base_url: Optional[str] = None,
) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    from minidrifter.verification.llm_test_agent import propose_llm_tests, proposals_to_test_cases
    from minidrifter.verification.llm_script_export import write_proposal_scripts

    result = propose_llm_tests(
        pack_dir, test_cases, baseline_context, object_pool=object_pool, dry_run=llm_dry_run,
    )
    by_id = {t['test_id']: t for t in test_cases if t.get('test_id')}
    materialized, blocked = proposals_to_test_cases(
        result.get('proposals') or [], by_id, object_pool, baseline_context,
    )
    result['materialization_blocked'] = blocked
    result['materialized_count'] = len(materialized)

    write_json(pack_dir / 'llm_test_proposals.json', {
        'record': result.get('record'),
        'proposals': result.get('proposals'),
        'validation_errors': result.get('validation_errors'),
        'materialization_blocked': blocked,
        'materialized_count': len(materialized),
    })

    merged = list(test_cases) + materialized

    if result.get('proposals'):
        scripts = write_proposal_scripts(
            pack_dir, result['proposals'], by_id, base_url=base_url or 'https://HOST_FROM_BASELINE',
        )
        result['script_paths'] = scripts

    return merged, result


def _run_llm_feedback(
    pack_dir: Path,
    *,
    test_cases: List[Dict[str, Any]],
    executions: List[Dict[str, Any]],
    analyses: List[Dict[str, Any]],
    rule_plan: Dict[str, Any],
    baseline_context: Dict[str, Any],
    llm_dry_run: bool = False,
) -> Dict[str, Any]:
    from minidrifter.verification.llm_feedback_agent import generate_llm_feedback

    fb = generate_llm_feedback(
        pack_dir,
        test_cases=test_cases,
        executions=executions,
        analyses=analyses,
        rule_plan=rule_plan,
        baseline_context=baseline_context,
        dry_run=llm_dry_run,
    )
    write_json(pack_dir / 'llm_feedback_plan.json', {
        'record': fb.get('record'),
        'feedback': fb.get('feedback'),
        'validation_errors': fb.get('validation_errors'),
    })
    return fb


def _execute_test_batch(
    test_cases: List[Dict[str, Any]],
    *,
    pack_dir: Path,
    baseline_context: Dict[str, Any],
    object_pool: Dict[str, Any],
    state: Dict[str, Any],
    mode: str,
    only_safe: bool,
    source_dir: Optional[Path],
    base_url: Optional[str],
    responses_dir: Optional[Path],
    wave_label: str,
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any], List[Dict[str, Any]]]:
    executions: List[Dict[str, Any]] = []
    analyses: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []

    for tc in test_cases:
        tc = {**tc, 'campaign_wave': wave_label}
        verdict = evaluate_test_safety(
            tc, baseline_context=baseline_context, only_safe=only_safe, mode=mode,
        )
        if not verdict.allowed and mode == 'execute':
            executions.append({
                'test_id': tc.get('test_id'),
                'executed': False,
                'call_outcome': 'safety_blocked',
                'safety_reasons': verdict.reasons,
                'campaign_wave': wave_label,
            })
            continue

        ex = execute_test_case(
            tc, pack_dir=pack_dir, baseline_context=baseline_context,
            mode=mode, source_dir=source_dir, base_url=base_url,
            responses_dir=responses_dir if mode == 'execute' else None,
        )
        ex['campaign_wave'] = wave_label
        executions.append(ex)

        analysis = analyze_response(ex, tc, baseline_context=baseline_context, pack_dir=pack_dir)
        if tc.get('source') == 'llm_test_agent':
            analysis['llm_proposal_id'] = tc.get('llm_proposal_id')
        analysis['campaign_wave'] = wave_label
        analyses.append(analysis)

        object_pool = update_pool_from_analysis(object_pool, analysis, test_id=tc.get('test_id', ''))
        state = update_planner_state(state, tc, ex, analysis)

        if 'subject_object_binding_mismatch' in (analysis.get('security_signals') or []):
            findings.append({
                'finding_id': f"fd_{tc.get('test_id', 'x')}",
                'finding_type': 'subject_object_binding_mismatch',
                'api_id': tc.get('api_id'),
                'api_path': tc.get('path'),
                'evidence_tests': [tc.get('test_id')],
                'severity': 'medium',
                'confidence': 'medium',
                'evidence_summary': 'Response subject field does not match baseline subject',
                'source': 'rule_oracle',
                'campaign_wave': wave_label,
            })

    return executions, analyses, findings, object_pool, state


def run_verification_campaign(
    pack_dir: Path,
    *,
    mode: str = 'dry-run',
    only_safe: bool = True,
    max_tests: int = 10,
    plan_only: bool = False,
    source_dir: Optional[Path] = None,
    base_url: Optional[str] = None,
    baseline_context: Optional[Dict[str, Any]] = None,
    with_llm: bool = False,
    llm_dry_run: bool = False,
    expand_frontier_wave: bool = True,
    max_frontier_tests: int = 5,
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    baseline_context = baseline_context or _load_json(pack_dir / 'baseline_runtime_context.json') or {}

    planned = plan_campaign(
        pack_dir, max_tests=max_tests, only_safe=only_safe, baseline_context=baseline_context,
    )
    campaign = planned['campaign']
    test_cases = planned['test_cases']
    rule_selected = len(test_cases)

    object_pool = init_object_pool(baseline_context)
    llm_test_meta: Dict[str, Any] = {}

    if with_llm and not plan_only:
        test_cases, llm_test_meta = _run_llm_test_enrichment(
            pack_dir, test_cases, baseline_context, object_pool,
            llm_dry_run=llm_dry_run, base_url=base_url,
        )
        campaign['selected_count_before_llm'] = rule_selected
        campaign['selected_count'] = len(test_cases)
        campaign['llm_added_test_count'] = len(test_cases) - rule_selected
        campaign['llm_test_proposals'] = len(llm_test_meta.get('proposals') or [])
        campaign['llm_materialized_count'] = llm_test_meta.get('materialized_count', 0)
        campaign['llm_materialization_blocked'] = len(llm_test_meta.get('materialization_blocked') or [])
        campaign['test_case_ids'] = [t['test_id'] for t in test_cases]

    write_json(pack_dir / 'verification_campaign.json', campaign)
    _write_jsonl(pack_dir / 'test_cases.jsonl', test_cases)

    if plan_only:
        out = {
            'phase': 'plan_only',
            'campaign': campaign,
            'test_case_count': len(test_cases),
        }
        if with_llm:
            test_cases, llm_test_meta = _run_llm_test_enrichment(
                pack_dir, test_cases, baseline_context, object_pool,
                llm_dry_run=llm_dry_run, base_url=base_url,
            )
            out['llm_test'] = llm_test_meta
        return out

    responses_dir = pack_dir / 'verification_responses'
    state = init_planner_state(campaign, max_tests=max_tests)

    executions, analyses, findings, object_pool, state = _execute_test_batch(
        test_cases,
        pack_dir=pack_dir,
        baseline_context=baseline_context,
        object_pool=object_pool,
        state=state,
        mode=mode,
        only_safe=only_safe,
        source_dir=source_dir,
        base_url=base_url,
        responses_dir=responses_dir,
        wave_label='wave0',
    )

    frontier_meta: Dict[str, Any] = {}
    if expand_frontier_wave:
        frontier_meta = expand_frontier(
            pack_dir,
            object_pool=object_pool,
            planner_state=state,
            baseline_context=baseline_context,
            max_new_tests=max_frontier_tests,
            only_safe=only_safe,
        )
        write_json(pack_dir / 'frontier_candidates.json', frontier_meta)
        next_wave = frontier_meta.get('next_wave_test_cases') or []
        if next_wave:
            _write_jsonl(pack_dir / 'next_wave_test_cases.jsonl', next_wave)
            wave_exec, wave_analyses, wave_findings, object_pool, state = _execute_test_batch(
                next_wave,
                pack_dir=pack_dir,
                baseline_context=baseline_context,
                object_pool=object_pool,
                state=state,
                mode=mode,
                only_safe=only_safe,
                source_dir=source_dir,
                base_url=base_url,
                responses_dir=responses_dir,
                wave_label='wave1_frontier',
            )
            executions.extend(wave_exec)
            analyses.extend(wave_analyses)
            findings.extend(wave_findings)
            frontier_meta['executed_count'] = len(wave_exec)

    _write_jsonl(pack_dir / 'execution_results.jsonl', executions)
    _write_jsonl(pack_dir / 'response_analysis.jsonl', analyses)
    if findings:
        _write_jsonl(pack_dir / 'findings.jsonl', findings)

    write_object_pools(pack_dir, object_pool)
    write_json(pack_dir / 'planner_state.json', state)

    rule_plan = build_next_action_plan(state, analyses, object_pool=object_pool)
    next_plan = rule_plan
    llm_fb_meta: Dict[str, Any] = {}
    if with_llm:
        llm_fb_meta = _run_llm_feedback(
            pack_dir,
            test_cases=test_cases,
            executions=executions,
            analyses=analyses,
            rule_plan=rule_plan,
            baseline_context=baseline_context,
            llm_dry_run=llm_dry_run,
        )
        next_plan = llm_fb_meta.get('merged_plan') or rule_plan

    write_json(pack_dir / 'next_action_plan.json', next_plan)

    coverage = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'mode': mode,
        'with_llm': with_llm,
        'tests_planned': len(test_cases) + (frontier_meta.get('next_wave_count') or 0),
        'tests_executed': sum(1 for e in executions if e.get('executed')),
        'wave0_tests': sum(1 for e in executions if e.get('campaign_wave') == 'wave0'),
        'wave1_tests': sum(1 for e in executions if e.get('campaign_wave') == 'wave1_frontier'),
        'dry_run_ok': sum(1 for a in analyses if a.get('call_outcome') == 'dry_run_ok'),
        'business_success': sum(1 for a in analyses if a.get('call_outcome') == 'business_success'),
        'business_state_blocked': sum(1 for a in analyses if a.get('call_outcome') == 'business_state_blocked'),
        'app_version_blocked': sum(1 for a in analyses if a.get('failure_class') == 'app_version_blocked'),
        'auth_expired': sum(1 for a in analyses if a.get('call_outcome') == 'auth_expired'),
        'transport_url_routing': sum(1 for a in analyses if a.get('failure_class') == 'transport_url_routing'),
        'build_failed': sum(1 for e in executions if e.get('build_status') not in (None, 'ok')),
        'findings_count': len(findings),
        'llm_proposals': len(llm_test_meta.get('proposals') or []),
        'llm_materialized': llm_test_meta.get('materialized_count', 0),
        'llm_materialization_blocked': len(llm_test_meta.get('materialization_blocked') or []),
        'llm_feedback_status': (llm_fb_meta.get('record') or {}).get('status'),
        'frontier_candidates': frontier_meta.get('candidate_count', 0),
        'frontier_executed': frontier_meta.get('executed_count', 0),
        'confirmed_fields': object_pool.get('confirmed_fields') or [],
        'frontier_unlocks': object_pool.get('frontier_unlocks') or [],
        'planner_coverage': state.get('coverage'),
    }
    write_json(pack_dir / 'coverage_report.json', coverage)

    return {
        'phase': 'full',
        'mode': mode,
        'with_llm': with_llm,
        'campaign': campaign,
        'coverage': coverage,
        'next_action_plan': next_plan,
        'rule_next_action_plan': rule_plan,
        'llm_test': llm_test_meta,
        'llm_feedback': llm_fb_meta,
        'frontier': frontier_meta,
        'findings_count': len(findings),
    }
