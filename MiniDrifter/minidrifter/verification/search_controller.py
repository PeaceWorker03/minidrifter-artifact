# -*- coding: utf-8 -*-
"""PBWS Search Controller — breadth queue + depth chain + prune + feedback."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import write_json
from minidrifter.verification.breadth_scheduler import BreadthScheduler
from minidrifter.verification.depth_chain import DepthChain
from minidrifter.verification.finding_adjudicator import adjudicate_findings
from minidrifter.verification.finding_lifecycle import FindingRegistry
from minidrifter.verification.object_pool import (
    ensure_negative_synthetics,
    init_object_pool,
    pool_snapshot_hash,
    update_pool_from_analysis,
    write_object_pools,
)
from minidrifter.verification.planner_state import init_planner_state, update_planner_state
from minidrifter.verification.prune_registry import PruneRegistry
from minidrifter.verification.replay_preflight import run_replay_preflight
from minidrifter.verification.response_oracle import analyze_response, extract_signals
from minidrifter.verification.safety_policy import evaluate_test_safety
from minidrifter.verification.strategy_planner import plan_seed_strategy
from minidrifter.verification.test_feedback import build_test_feedback
from minidrifter.verification.workflow_planner import plan_next_link


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


from minidrifter.verification.search_budget import SearchBudget


def _execute_one(
    tc: Dict[str, Any],
    *,
    pack_dir: Path,
    baseline_context: Dict[str, Any],
    mode: str,
    only_safe: bool,
    source_dir: Optional[Path],
    base_url: Optional[str],
    responses_dir: Optional[Path],
) -> Dict[str, Any]:
    from minidrifter.verification.executor import execute_test_case

    verdict = evaluate_test_safety(
        tc, baseline_context=baseline_context, only_safe=only_safe, mode=mode,
    )
    if not verdict.allowed and mode == 'execute':
        return {
            'test_id': tc.get('test_id'),
            'executed': False,
            'call_outcome': 'safety_blocked',
            'safety_reasons': verdict.reasons,
        }
    return execute_test_case(
        tc, pack_dir=pack_dir, baseline_context=baseline_context,
        mode=mode, source_dir=source_dir, base_url=base_url,
        responses_dir=responses_dir if mode == 'execute' else None,
    )


def run_verification_search(
    pack_dir: Path,
    *,
    mode: str = 'dry-run',
    only_safe: bool = True,
    max_http: int = 50,
    max_seeds: int = 8,
    max_depth: int = 5,
    source_dir: Optional[Path] = None,
    base_url: Optional[str] = None,
    baseline_context: Optional[Dict[str, Any]] = None,
    skip_preflight: bool = False,
    with_mutations: bool = True,
    with_llm_strategy: bool = False,
    with_llm_workflow: bool = False,
    llm_dry_run: bool = False,
    max_llm: int = 50,
    ig_threshold: float = 0.25,
    ig_prune: bool = True,
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    baseline_context = baseline_context or _load_json(pack_dir / 'baseline_runtime_context.json') or {}

    from minidrifter.verification.graph_loader import load_workflow_graph
    workflow_graph = load_workflow_graph(pack_dir, write_sidecar=True)
    graph_stats = (workflow_graph or {}).get('workflow_stats') or {}

    from minidrifter.ir.loader import load_universal_ir
    ir_session = load_universal_ir(pack_dir, auto_export=True)

    preflight = None
    if not skip_preflight:
        preflight = run_replay_preflight(
            pack_dir, source_dir=source_dir, base_url=base_url, live_probe=False,
        )
        write_json(pack_dir / 'replay_preflight_report.json', preflight)
        if not preflight.get('ready') and mode == 'execute':
            return {
                'status': 'preflight_blocked',
                'preflight': preflight,
                'verdict': 'blocked',
            }

    budget = SearchBudget(max_http=max_http, max_seeds=max_seeds, max_depth=max_depth, max_llm=max_llm)
    scheduler = BreadthScheduler(
        pack_dir, baseline_context=baseline_context, only_safe=only_safe, max_seeds=max_seeds * 3,
    )
    object_pool = ensure_negative_synthetics(init_object_pool(baseline_context), baseline_context)
    prune = PruneRegistry(ig_threshold=ig_threshold, ig_prune_enabled=ig_prune)
    finding_registry = FindingRegistry()
    state = init_planner_state({'campaign_mode': 'search', 'test_case_ids': []}, max_tests=max_http)

    all_executions: List[Dict[str, Any]] = []
    all_analyses: List[Dict[str, Any]] = []
    all_feedback: List[Dict[str, Any]] = []
    all_findings: List[Dict[str, Any]] = []
    all_test_cases: Dict[str, Dict[str, Any]] = {}
    depth_chains: List[Dict[str, Any]] = []
    breadth_log: List[Dict[str, Any]] = []
    llm_traces: List[Dict[str, Any]] = []

    responses_dir = pack_dir / 'verification_responses' if mode == 'execute' else None
    pool_hash = pool_snapshot_hash(object_pool)

    while budget.can_seed():
        seed = scheduler.pop_next()
        if not seed:
            break
        budget.seeds_used += 1

        use_llm_strategy = with_llm_strategy and budget.consume_llm('policy')
        strategy = plan_seed_strategy(
            seed, baseline_context=baseline_context, object_pool=object_pool,
            with_mutations=with_mutations,
            pack_dir=pack_dir,
            with_llm=use_llm_strategy,
            llm_dry_run=llm_dry_run,
            prior_feedback=all_feedback[-5:] if all_feedback else None,
            llm_traces=llm_traces,
        )
        chain = DepthChain(seed['api_id'], max_depth=max_depth)
        seed_tests = strategy.get('test_cases') or []
        for tc in seed_tests:
            if tc.get('test_id'):
                all_test_cases[tc['test_id']] = tc
        seed_findings = 0
        seed_http = 0
        last_signals: Dict[str, Any] = {}
        last_link: Dict[str, Any] = {}

        for tc in seed_tests:
            skip, reason = prune.should_skip(
                tc, baseline_context=baseline_context, pool_hash=pool_hash,
                chain_fingerprint=chain.fingerprint(),
                object_pool=object_pool,
            )
            if skip:
                prune.record_pruned(tc, reason or 'pruned')
                continue
            if not budget.consume():
                break

            tc = {**tc, 'chain_id': chain.chain_id, 'search_seed': seed.get('api_id')}
            all_test_cases[tc.get('test_id', '')] = tc
            ex = _execute_one(
                tc, pack_dir=pack_dir, baseline_context=baseline_context, mode=mode,
                only_safe=only_safe, source_dir=source_dir, base_url=base_url,
                responses_dir=responses_dir,
            )
            seed_http += 1
            analysis = analyze_response(ex, tc, baseline_context=baseline_context, pack_dir=pack_dir)
            signals = extract_signals(analysis, tc)
            analysis['signals'] = signals
            fb = build_test_feedback(tc, ex, analysis, signals)

            object_pool = update_pool_from_analysis(object_pool, analysis, test_id=tc.get('test_id', ''))
            pool_hash = pool_snapshot_hash(object_pool)
            state = update_planner_state(state, tc, ex, analysis)
            prune.record(tc, analysis, baseline_context=baseline_context, pool_hash=pool_hash,
                         chain_fingerprint=chain.fingerprint())

            all_executions.append(ex)
            all_analyses.append(analysis)
            all_feedback.append(fb)
            last_signals = signals

            if not chain.nodes:
                chain.push({'api_id': seed['api_id'], 'path': seed.get('path'), 'role': 'seed'})
            if signals.get('suspicious'):
                chain.record_signal(signals['suspicious'][0])

        # Depth phase
        while not chain.should_stop() and budget.used_http < budget.max_http:
            use_llm_workflow = with_llm_workflow and budget.consume_llm('policy')
            link = plan_next_link(
                pack_dir, chain_nodes=chain.nodes, object_pool=object_pool,
                baseline_context=baseline_context, last_signals=last_signals,
                with_llm=use_llm_workflow,
                llm_dry_run=llm_dry_run,
                llm_traces=llm_traces,
                ir_session=ir_session,
            )
            last_link = link
            if link.get('stop'):
                chain.stop_reason = link.get('reason')
                break

            next_tests = link.get('next_test_cases') or []
            if not next_tests:
                chain.record_no_signal()
                break

            progressed = False
            for tc in next_tests:
                skip, reason = prune.should_skip(
                    tc, baseline_context=baseline_context, pool_hash=pool_hash,
                    chain_fingerprint=chain.fingerprint(),
                    object_pool=object_pool,
                )
                if skip:
                    prune.record_pruned(tc, reason or 'pruned')
                    continue
                if not budget.consume():
                    break

                pick = link.get('next_api') or {}
                chain.push({'api_id': pick.get('api_id'), 'path': pick.get('path'), 'role': 'consumer'})
                tc = {**tc, 'chain_id': chain.chain_id, 'search_seed': seed.get('api_id')}
                all_test_cases[tc.get('test_id', '')] = tc

                ex = _execute_one(
                    tc, pack_dir=pack_dir, baseline_context=baseline_context, mode=mode,
                    only_safe=only_safe, source_dir=source_dir, base_url=base_url,
                    responses_dir=responses_dir,
                )
                seed_http += 1
                analysis = analyze_response(ex, tc, baseline_context=baseline_context, pack_dir=pack_dir)
                signals = extract_signals(analysis, tc)
                analysis['signals'] = signals
                fb = build_test_feedback(tc, ex, analysis, signals)

                object_pool = update_pool_from_analysis(object_pool, analysis, test_id=tc.get('test_id', ''))
                pool_hash = pool_snapshot_hash(object_pool)
                state = update_planner_state(state, tc, ex, analysis)
                prune.record(tc, analysis, baseline_context=baseline_context, pool_hash=pool_hash,
                             chain_fingerprint=chain.fingerprint())

                all_executions.append(ex)
                all_analyses.append(analysis)
                all_feedback.append(fb)
                last_signals = signals
                progressed = True

                if signals.get('suspicious'):
                    chain.record_signal(signals['suspicious'][0])
                else:
                    chain.record_no_signal()

            if not progressed:
                chain.record_no_signal()

        seed_start_idx = len(all_executions) - seed_http
        seed_executions = all_executions[seed_start_idx:] if seed_http else []
        seed_analyses = all_analyses[seed_start_idx:] if seed_http else []
        tc_by_id: Dict[str, Dict[str, Any]] = {}
        for tc in seed_tests:
            tc_by_id[tc.get('test_id', '')] = tc
        for ex in seed_executions:
            tid = ex.get('test_id')
            if tid and tid not in tc_by_id:
                tc_by_id[tid] = {'test_id': tid, 'api_id': ex.get('api_id'), 'path': ex.get('path')}

        seed_findings_list = adjudicate_findings(
            seed_analyses, tc_by_id, chain_id=chain.chain_id, seed_api_id=seed.get('api_id'),
        )
        finding_registry.ingest(seed_findings_list)
        chain_findings = [
            f for f in finding_registry.all_findings()
            if f.get('chain_id') == chain.chain_id and f.get('status') != 'pruned'
        ]
        for f in chain_findings:
            chain.record_finding(f['finding_id'])
        seed_findings = sum(1 for f in chain_findings if f.get('status') in {'confirmed', 'hypothesis'})

        retire_reason = 'depth_exhausted_no_signal'
        if seed_findings:
            retire_reason = 'finding_in_chain'
        elif any(s.get('depth_continue') for s in [last_signals]):
            retire_reason = 'depth_stopped_budget_or_frontier'
        elif any(a.get('call_outcome') == 'business_success' for a in seed_analyses):
            retire_reason = 'no_suspicious_after_success'

        scheduler.retire(
            seed['api_id'], retire_reason,
            tests_consumed=seed_http, findings=seed_findings,
        )
        breadth_log.append({
            'seed_api': seed['api_id'],
            'path': seed.get('path'),
            'retire_reason': retire_reason,
            'tests_consumed': seed_http,
            'findings': seed_findings,
            'chain': chain.to_dict(),
        })
        depth_chains.append(chain.to_dict())

        if last_link.get('frontier_hypothesis') and not chain.stop_reason:
            chain.stop_reason = last_link.get('reason') or 'llm_frontier_hypothesis'

        if not budget.can_seed() or budget.used_http >= budget.max_http:
            break

    finding_registry.apply_lifecycle_rules(all_analyses, all_test_cases)
    all_findings = finding_registry.all_findings()

    from minidrifter.verification.chain_report import build_all_chain_reports
    chain_reports = build_all_chain_reports(
        all_findings,
        depth_chains=depth_chains,
        executions=all_executions,
        analyses=all_analyses,
        test_cases_by_id=all_test_cases,
    )
    write_json(pack_dir / 'finding_registry.json', finding_registry.to_document())
    write_json(pack_dir / 'finding_chain_reports.json', chain_reports)

    write_object_pools(pack_dir, object_pool)
    write_json(pack_dir / 'planner_state.json', state)
    _write_jsonl(pack_dir / 'execution_results.jsonl', all_executions)
    _write_jsonl(pack_dir / 'response_analysis.jsonl', all_analyses)
    _write_jsonl(pack_dir / 'test_feedback.jsonl', all_feedback)
    if all_findings:
        _write_jsonl(pack_dir / 'findings.jsonl', all_findings)
    if prune.pruned:
        _write_jsonl(pack_dir / 'pruned_tests.jsonl', prune.pruned)

    write_json(pack_dir / 'depth_chain_state.json', {'chains': depth_chains})
    write_json(pack_dir / 'breadth_frontier.json', {
        'generated_at': _utc_now(),
        'breadth_log': breadth_log,
        'scheduler': scheduler.summary(),
    })

    if llm_traces:
        from minidrifter.verification.llm_trace import append_trace_log, write_trace_session
        append_trace_log(pack_dir, llm_traces)
        write_trace_session(pack_dir, llm_traces, {
            'llm_calls': len(llm_traces),
            'budget_used_llm': budget.used_llm,
            'with_llm_strategy': with_llm_strategy,
            'with_llm_workflow': with_llm_workflow,
            'strategy_traces': sum(1 for t in llm_traces if t.get('stage') == 'strategy_planner'),
            'workflow_traces': sum(1 for t in llm_traces if t.get('stage') == 'workflow_planner'),
        })

    prune_summary = prune.summary()
    budget_panel = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'budget': budget.to_dict(),
        'prune': prune_summary,
        'workflow_graph': graph_stats,
        'efficiency': {
            'http_calls': len(all_executions),
            'pruned': len(prune.pruned),
            'prune_rate': round(len(prune.pruned) / max(1, len(all_executions) + len(prune.pruned)), 3),
            'ig_threshold': ig_threshold,
        },
    }
    write_json(pack_dir / 'budget_panel.json', budget_panel)

    business_success = sum(1 for a in all_analyses if a.get('call_outcome') == 'business_success')
    suspicious_count = sum(1 for a in all_analyses if (a.get('signals') or {}).get('suspicious'))

    session = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'mode': mode,
        'status': 'completed',
        'verdict': 'success' if business_success else ('partial' if all_executions else 'empty'),
        'budget': budget.to_dict(),
        'budget_panel_ref': 'budget_panel.json',
        'workflow_graph_stats': graph_stats,
        'universal_ir': ir_session.to_search_context(),
        'prune_summary': prune_summary,
        'finding_lifecycle': finding_registry.summary(),
        'finding_chain_reports_ref': 'finding_chain_reports.json',
        'coverage': {
            'http_calls': len(all_executions),
            'seeds_retired': len(breadth_log),
            'business_success': business_success,
            'suspicious_signals': suspicious_count,
            'findings_confirmed': finding_registry.summary().get('confirmed', 0),
            'findings_hypothesis': finding_registry.summary().get('hypothesis', 0),
            'findings_rejected': finding_registry.summary().get('rejected', 0),
            'pruned': len(prune.pruned),
            'pruned_by_reason': prune_summary.get('by_reason'),
            'depth_chains': len(depth_chains),
            'llm_traces': len(llm_traces),
        },
        'llm': {
            'with_strategy': with_llm_strategy,
            'with_workflow': with_llm_workflow,
            'dry_run': llm_dry_run,
            'calls': budget.used_llm,
            'trace_count': len(llm_traces),
            'max_llm': max_llm,
        },
        'prune': {
            'ig_enabled': ig_prune,
            'ig_threshold': ig_threshold,
            **prune_summary,
        },
        'preflight': preflight,
    }
    write_json(pack_dir / 'search_session.json', session)

    from minidrifter.verification.analysis_report import (
        build_verification_analysis_report,
        write_analysis_report,
    )
    report = build_verification_analysis_report(pack_dir, preflight=preflight or {})
    report['search_session'] = session
    report['finding_lifecycle'] = finding_registry.summary()
    report['finding_chain_reports'] = {
        'confirmed_count': chain_reports.get('confirmed_count'),
        'hypothesis_count': chain_reports.get('hypothesis_count'),
        'reports': chain_reports.get('reports') or [],
    }
    paths = write_analysis_report(pack_dir, report)
    session['analysis_report'] = paths

    return session
