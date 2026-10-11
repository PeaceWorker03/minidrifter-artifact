# -*- coding: utf-8 -*-
"""Apex-PoC: Atomic-first Multi-chain Adaptive Search controller."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.core.utils import write_json
from minidrifter.verification.atomic_probe_scheduler import AtomicProbeScheduler
from minidrifter.verification.campaign_planner import build_test_case
from minidrifter.verification.chain_state import CHAIN_ACTIVE
from minidrifter.verification.beam_chain_scheduler import BeamChainScheduler
from minidrifter.verification.confidence_tracker import ConfidenceTracker
from minidrifter.verification.failure_diagnoser import apply_diagnosis_action
from minidrifter.verification.hop_adjudicator import adjudicate_hop
from minidrifter.verification.llm_hop_adjudicator import deepen_hop_adjudication
from minidrifter.verification.resolution_executor import (
    execute_hop_resolution,
    persist_material_requests,
)
from minidrifter.verification.response_param_analyzer import compare_m0_m7_pair, find_m0_pair
from minidrifter.verification.transport_family_tracker import TransportFamilyTracker
from minidrifter.verification.finding_adjudicator import adjudicate_findings
from minidrifter.verification.finding_lifecycle import FindingRegistry
from minidrifter.verification.chain_reasoning import ChainReasoningRegistry
from minidrifter.verification.llm_chain_reasoner import deliberate_global, reason_about_chain
from minidrifter.verification.llm_policy_replanner import build_policy_context, propose_policy
from minidrifter.verification.object_acquisition_planner import plan_acquire_all_missing
from minidrifter.verification.object_pool import (
    ensure_negative_synthetics,
    init_object_pool,
    pool_snapshot_hash,
    update_pool_from_analysis,
    write_object_pools,
)
from minidrifter.verification.planner_state import init_planner_state, update_planner_state
from minidrifter.verification.progress_watchdog import FailureCircuitBreaker, ProgressWatchdog
from minidrifter.verification.prune_registry import PruneRegistry
from minidrifter.verification.replay_preflight import run_replay_preflight
from minidrifter.verification.response_oracle import analyze_response, extract_signals
from minidrifter.verification.safety_policy import evaluate_test_safety
from minidrifter.verification.policy_executor import execute_policy_action
from minidrifter.verification.search_budget import SearchBudget
from minidrifter.verification.search_controller import _execute_one
from minidrifter.verification.search_progress import SearchProgress
from minidrifter.verification.strategy_planner import plan_seed_strategy
from minidrifter.verification.api_guard_beliefs import ApiGuardBeliefs
from minidrifter.verification.credential_probe_planner import should_continue_probes
from minidrifter.verification.test_feedback import build_test_feedback
from minidrifter.verification.workflow_planner import (
    branch_candidates_from_rule_result,
    plan_next_link,
)


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


def _recent_failure_hist(analyses: List[Dict[str, Any]], n: int = 20) -> Dict[str, int]:
    hist: Dict[str, int] = {}
    for a in analyses[-n:]:
        fc = a.get('failure_class') or a.get('call_outcome') or 'unknown'
        hist[fc] = hist.get(fc, 0) + 1
    return hist


def _run_one_test(
    tc: Dict[str, Any],
    *,
    pack_dir: Path,
    baseline_context: Dict[str, Any],
    mode: str,
    only_safe: bool,
    source_dir: Optional[Path],
    base_url: Optional[str],
    responses_dir: Optional[Path],
    budget: SearchBudget,
    prune: PruneRegistry,
    pool_hash: str,
    object_pool: Dict[str, Any],
    chain_fingerprint: str = '',
) -> Optional[Dict[str, Any]]:
    skip, reason = prune.should_skip(
        tc, baseline_context=baseline_context, pool_hash=pool_hash,
        chain_fingerprint=chain_fingerprint, object_pool=object_pool,
    )
    if skip:
        prune.record_pruned(tc, reason or 'pruned')
        return None
    if not budget.consume():
        return None
    ex = _execute_one(
        tc, pack_dir=pack_dir, baseline_context=baseline_context, mode=mode,
        only_safe=only_safe, source_dir=source_dir, base_url=base_url,
        responses_dir=responses_dir,
    )
    return ex


def _apply_thought_actions(
    thought: Dict[str, Any],
    *,
    atomic: AtomicProbeScheduler,
    object_pool: Dict[str, Any],
    workflow_graph: Dict[str, Any],
    templates_by_id: Dict[str, Any],
    pack_dir: Path,
    confidence: ConfidenceTracker,
    progress: SearchProgress,
) -> int:
    """Turn chain reasoner recommendations into atomic queue injections."""
    injected = 0
    for action in thought.get('recommended_actions') or []:
        act = str(action)
        if act.startswith('acquire_object:'):
            field = act.split(':', 1)[1].strip()
            for plan in plan_acquire_all_missing(
                object_pool, workflow_graph, templates_by_id,
                pack_dir=pack_dir, confidence_tracker=confidence, limit_per_field=3,
            ):
                if plan.get('target_field') != field:
                    continue
                tpl = plan.get('template')
                if not tpl:
                    continue
                atomic.inject_front({
                    'seed_id': f'think_{field}_{plan.get("producer_api_id")}',
                    'api_id': plan.get('producer_api_id'),
                    'path': plan.get('path'),
                    'domain': tpl.get('domain', 'general'),
                    'priority': plan.get('score', 0) + 4,
                    'template': tpl,
                }, boost=plan.get('score', 0) + 2)
                progress.acquire(
                    target_field=field,
                    producer_path=plan.get('path') or '?',
                    score=plan.get('score') or 0,
                )
                injected += 1
                break
        elif act == 'switch_domain':
            progress.emit('THINK', 'reprioritize atomic queue for domain breadth')
            atomic.reprioritize()
            injected += 1
        elif act.startswith('refresh_baseline:'):
            progress.emit('THINK', 'baseline refresh recommended', field=act.split(':', 1)[1])
    return injected


def run_adaptive_poc_search(
    pack_dir: Path,
    *,
    mode: str = 'dry-run',
    only_safe: bool = True,
    max_http: int = 100,
    max_seeds: int = 30,
    max_depth: int = 5,
    beam_width: int = 5,
    source_dir: Optional[Path] = None,
    base_url: Optional[str] = None,
    baseline_context: Optional[Dict[str, Any]] = None,
    skip_preflight: bool = False,
    with_mutations: bool = True,
    with_llm_policy: bool = False,
    with_llm_chain: Optional[bool] = None,
    deep_think: bool = False,
    llm_dry_run: bool = False,
    max_llm: int = 50,
    ig_threshold: float = 0.25,
    ig_prune: bool = True,
    anchor_api_id: Optional[str] = None,
    policy_interval: int = 8,
    verbose: bool = True,
    resume_mode: bool = False,
    force_resume: bool = False,
) -> Dict[str, Any]:
    """Apex-PoC main loop: atomic → diagnose → acquire → beam → policy replan."""
    effective_chain_llm = (
        with_llm_chain if with_llm_chain is not None
        else (with_llm_policy or (deep_think and with_llm_policy))
    )
    if deep_think and policy_interval == 8:
        policy_interval = 5
    pack_dir = Path(pack_dir)
    progress = SearchProgress(pack_dir, engine='apex', enabled=verbose)
    baseline_context = baseline_context or _load_json(pack_dir / 'baseline_runtime_context.json') or {}

    progress.banner(
        'Apex-PoC search start',
        mode=mode,
        max_http=max_http,
        max_seeds=max_seeds,
        beam_width=beam_width,
        anchor=anchor_api_id,
        llm_policy=with_llm_policy,
        deep_think=deep_think,
        llm_chain=effective_chain_llm,
    )

    from minidrifter.verification.graph_loader import load_workflow_graph
    progress.emit('INIT', 'loading workflow graph')
    workflow_graph = load_workflow_graph(pack_dir, write_sidecar=True)
    graph_stats = (workflow_graph or {}).get('workflow_stats') or {}
    runtime_graph_meta: Dict[str, Any] = {}

    from minidrifter.ir.loader import load_universal_ir
    progress.emit('INIT', 'loading universal IR')
    ir_session = load_universal_ir(pack_dir, auto_export=True)
    progress.emit(
        'INIT', 'universal IR ready',
        profile=ir_session.profile_id,
        apis=len(ir_session.api_cards),
        n_tier=ir_session.n_tier_distribution,
    )

    tpl_doc = _load_json(pack_dir / 'materialized_api_templates.json') or {}
    templates_by_id = {
        t.get('api_id'): t for t in (tpl_doc.get('templates') or []) if t.get('api_id')
    }

    business_chains_doc = _load_json(pack_dir / 'business_chains.json') or {}
    chain_rank_plan = _load_json(pack_dir / 'chain_rank_plan.json') or {}
    chain_material_plan = _load_json(pack_dir / 'chain_material_request_plan.json') or {}

    preflight = None
    anchor_report = None
    from minidrifter.verification.anchor_replay import run_anchor_capture_replay
    progress.emit('ANCHOR', 'replaying user captures')
    anchor_report = run_anchor_capture_replay(
        pack_dir,
        baseline_context=baseline_context,
        mode=mode,
        source_dir=source_dir,
        base_url=base_url,
    )
    progress.emit(
        'ANCHOR',
        'ok' if anchor_report.get('baseline_usable') else 'failed',
        exact=anchor_report.get('exact_replay_ok'),
        sign_match=anchor_report.get('parametric_sign_match'),
    )
    if (
        mode == 'execute'
        and anchor_report.get('status') != 'skipped'
        and not anchor_report.get('baseline_usable')
    ):
        return {
            'status': 'anchor_blocked',
            'anchor_replay': anchor_report,
            'verdict': 'blocked',
            'reason': 'user_capture_anchor_replay_failed',
        }

    if not skip_preflight:
        progress.emit('PREFLIGHT', 'running replay preflight checks')
        preflight = run_replay_preflight(
            pack_dir, source_dir=source_dir, base_url=base_url, live_probe=False,
        )
        write_json(pack_dir / 'replay_preflight_report.json', preflight)
        progress.emit(
            'PREFLIGHT',
            'ready' if preflight.get('ready') else 'blocked',
            checks=f"{preflight.get('summary', {}).get('checks_passed')}/{preflight.get('summary', {}).get('checks_total')}",
            warnings=preflight.get('summary', {}).get('warning_count'),
        )
        if not preflight.get('ready') and mode == 'execute':
            return {'status': 'preflight_blocked', 'preflight': preflight, 'verdict': 'blocked'}

    budget = SearchBudget(
        max_http=max_http, max_seeds=max_seeds, max_depth=max_depth, max_llm=max_llm,
        deep_think=deep_think,
    )
    confidence = ConfidenceTracker()
    atomic = AtomicProbeScheduler(
        pack_dir, baseline_context=baseline_context, graph=workflow_graph or {},
        confidence=confidence, only_safe=only_safe, limit=max_seeds * 2,
        anchor_api_id=anchor_api_id,
        ir_session=ir_session,
    )
    transport_tracker = TransportFamilyTracker()
    atomic.set_transport_tracker(transport_tracker)
    beam = BeamChainScheduler(beam_width=beam_width, max_depth=max_depth)
    circuits = FailureCircuitBreaker()
    watchdog = ProgressWatchdog(window=10)
    prune = PruneRegistry(ig_threshold=ig_threshold, ig_prune_enabled=ig_prune)
    finding_registry = FindingRegistry()
    chain_reasoning = ChainReasoningRegistry()
    from minidrifter.orchestration.operator_session import OperatorSession
    from minidrifter.orchestration.intake_prompts import format_request_for_console
    from minidrifter.verification.user_ticket import TicketRegistry, build_user_ticket
    from minidrifter.verification.resume_manager import build_resume_plan
    operator = OperatorSession(pack_dir)
    ticket_registry = TicketRegistry(pack_dir)
    if resume_mode:
        from minidrifter.verification.resume_manager import prepare_verify_resume
        ckpt = prepare_verify_resume(
            pack_dir, dismiss_chain_tickets=True, force_clear_global=force_resume,
        )
        progress.emit('RESUME', 'checkpoint loaded', open_tickets=ckpt.get('open_tickets'), can_continue=ckpt.get('can_continue'))
    object_pool = ensure_negative_synthetics(init_object_pool(baseline_context), baseline_context)
    guard_beliefs = ApiGuardBeliefs()
    state = init_planner_state({'campaign_mode': 'apex_poc'}, max_tests=max_http)

    progress.emit(
        'INIT',
        'schedulers ready',
        atomic_queue=len(atomic.queue),
        beam_width=beam_width,
        graph_apis=graph_stats.get('workflow_candidate_apis'),
        business_chains=business_chains_doc.get('chain_count', 0),
        top_chains=len(chain_rank_plan.get('top_chains') or []),
        material_requests=chain_material_plan.get('request_count', 0),
    )

    all_executions: List[Dict[str, Any]] = []
    all_analyses: List[Dict[str, Any]] = []
    all_feedback: List[Dict[str, Any]] = []
    all_test_cases: Dict[str, Dict[str, Any]] = {}
    attributions: List[Dict[str, Any]] = []
    policy_log: List[Dict[str, Any]] = []
    chain_thought_log: List[Dict[str, Any]] = []
    llm_traces: List[Dict[str, Any]] = []
    apex_log: List[Dict[str, Any]] = []
    escalation_queue: List[Dict[str, Any]] = []
    escalation_log: List[Dict[str, Any]] = []
    escalated_finding_ids: Set[str] = set()
    hop_adjudication_log: List[Dict[str, Any]] = []
    material_requests: List[Dict[str, Any]] = []
    retry_queue: List[Dict[str, Any]] = []
    hop_retry_counts: Dict[str, int] = {}
    exec_by_id: Dict[str, Dict[str, Any]] = {}
    analysis_by_id: Dict[str, Dict[str, Any]] = {}
    chain_hop_memory: Dict[str, List[Dict[str, Any]]] = {}

    responses_dir = pack_dir / 'verification_responses' if mode == 'execute' else None
    pool_hash = pool_snapshot_hash(object_pool)
    anchor_passed = False
    steps_since_policy = 0
    test_index = 0
    loop_round = 0
    idle_rounds = 0
    max_idle_rounds = 300 if deep_think else 150
    global_deliberations = 0
    max_global_deliberations = 3 if deep_think else 1
    stop_reason = 'budget_exhausted'

    def _reload_workflow_graph() -> None:
        nonlocal workflow_graph, graph_stats
        workflow_graph = load_workflow_graph(pack_dir, write_sidecar=True, force_upgrade=True)
        graph_stats = (workflow_graph or {}).get('workflow_stats') or {}

    def _writeback_produces(tc: Dict[str, Any], analysis: Dict[str, Any]) -> None:
        nonlocal runtime_graph_meta
        harvested = analysis.get('produced_fields') or []
        if analysis.get('call_outcome') != 'business_success' or not harvested:
            return
        from minidrifter.graph.produces_runtime import (
            apply_verification_produces,
            merge_runtime_graph_stats,
        )
        rb = apply_verification_produces(
            pack_dir,
            api_id=tc.get('api_id') or '',
            path=tc.get('path') or '',
            produced_fields=harvested,
        )
        if rb.get('status') == 'ok':
            runtime_graph_meta = merge_runtime_graph_stats(runtime_graph_meta, rb)
            _reload_workflow_graph()
            progress.emit(
                'GRAPH',
                'runtime produces confirmed',
                api=tc.get('api_id'),
                confirmed=len(rb.get('confirmed') or []),
                added=len(rb.get('added') or []),
            )

    def _seed_beam_branches(tc: Dict[str, Any], harvested: List[str]) -> None:
        """Seed primary chain + fork alternate first-hop branches."""
        api_id = tc.get('api_id') or ''
        from minidrifter.business_chain.export import find_chain_for_entry
        static_chain = find_chain_for_entry(pack_dir, api_id)
        if static_chain and static_chain.get('hops'):
            beam.seed_from_business_chain(static_chain, harvested=harvested)
            return
        last_signals = {'depth_continue': True, 'harvest': harvested}
        link_preview = plan_next_link(
            pack_dir,
            chain_nodes=[{'api_id': api_id, 'path': tc.get('path'), 'role': 'seed'}],
            object_pool=object_pool,
            baseline_context=baseline_context,
            last_signals=last_signals,
            with_llm=False,
            ir_session=ir_session,
            include_planner_meta=True,
        )
        branches = branch_candidates_from_rule_result(
            link_preview,
            from_path=tc.get('path') or '',
            object_pool=object_pool,
            top_k=min(5, max(3, beam_width)),
        )
        primary_pick = None
        selected = link_preview.get('selected_pick') or {}
        planned = list(link_preview.get('planned_path') or [])
        if selected.get('api_id'):
            tpl = None
            for src in (
                link_preview.get('path_bfs_candidates') or [],
                link_preview.get('rule_candidates') or [],
            ):
                for c in src:
                    if c.get('api_id') == selected['api_id']:
                        tpl = c.get('template')
                        if c.get('planned_path'):
                            planned = list(c['planned_path'])
                        break
                if tpl:
                    break
            primary_pick = {
                'api_id': selected['api_id'],
                'path': selected.get('path'),
                'planned_path': planned,
                'template': tpl,
            }
        if not primary_pick and branches:
            primary_pick = branches[0]
        alt_ids = {primary_pick.get('api_id')} if primary_pick else set()
        alt_picks = [b for b in branches if b.get('api_id') not in alt_ids][:min(3, max(2, beam_width // 2))]
        beam.seed_with_branches(
            api_id,
            path=tc.get('path') or '',
            domain=tc.get('domain', 'general'),
            harvested=harvested,
            primary_pick=primary_pick,
            branch_picks=alt_picks,
            max_branches=min(3, beam.beam_width),
        )

    def _chain_has_bindable_params(template: Optional[Dict[str, Any]]) -> bool:
        if not template:
            return False
        params = (template.get('plain_template') or {}).get('params') or template.get('params') or {}
        keys = {str(k).lower() for k in params}
        return bool(keys & {
            'userid', 'user_id', 'orderid', 'deviceid', 'customerid',
            'logincustomerid', 'platformuserid',
        })

    def _run_intelligent_binding_probes(
        seed_item: Dict[str, Any],
        m0_tc: Dict[str, Any],
        *,
        chain_id: Optional[str] = None,
        test_stage: str = 'binding_mutation',
    ) -> bool:
        """Run M8 credential ladder + M7 identity probes with early stop."""
        if not with_mutations:
            return False
        strat = plan_seed_strategy(
            seed_item,
            baseline_context=baseline_context,
            object_pool=object_pool,
            with_mutations=True,
            pack_dir=pack_dir,
            with_llm=False,
            ir_card=ir_session.get_api(seed_item.get('api_id', '')) if ir_session else None,
            guard_beliefs=guard_beliefs,
            m0_test_case=m0_tc,
        )
        probe_plan = strat.get('probe_plan') or {}
        steps_by_id = {s.get('step_id'): s for s in (probe_plan.get('steps') or [])}
        pending = [t for t in (strat.get('test_cases') or []) if t.get('test_id') != m0_tc.get('test_id')]
        ran = False
        idx = 0
        while idx < len(pending):
            mtc = pending[idx]
            idx += 1
            mtc = {
                **mtc,
                'test_stage': test_stage,
                'chain_id': chain_id or mtc.get('chain_id'),
            }
            mut = mtc.get('mutation_type') or ''
            if mut.startswith('M8') and guard_beliefs.should_skip_credential_step(
                mtc.get('path') or '', guard_kind=mtc.get('guard_kind') or 'signature',
                api_id=mtc.get('api_id') or '',
            ):
                continue
            if mut.startswith('M7') and guard_beliefs.should_skip_identity_field(
                mtc.get('path') or '', mtc.get('target_field') or '',
                api_id=mtc.get('api_id') or '',
            ):
                continue
            all_test_cases[mtc.get('test_id', '')] = mtc
            mex = _execute_tracked(mtc, chain_fingerprint=chain_id or '')
            if not mex:
                continue
            analysis = process_result(mtc, mex, chain_id=chain_id)
            ran = True
            step = steps_by_id.get(mtc.get('probe_step_id') or '') or {
                'mutation_type': mtc.get('mutation_type'),
                'target_field': mtc.get('target_field'),
                'guard_kind': mtc.get('guard_kind'),
                'stop_if_success': mtc.get('stop_if_success'),
                'stop_if_rejected': mtc.get('stop_if_rejected'),
            }
            guard_beliefs.record_probe(
                api_id=mtc.get('api_id') or '',
                path=mtc.get('path') or '',
                mutation_type=mtc.get('mutation_type') or '',
                target_field=mtc.get('target_field'),
                outcome=analysis.get('call_outcome') or '',
                failure_class=analysis.get('failure_class'),
                guard_kind=mtc.get('guard_kind'),
            )
            cont, stop_scope = should_continue_probes(
                step, analysis, guard_beliefs,
                api_id=mtc.get('api_id') or '',
                path=mtc.get('path') or '',
            )
            if not cont:
                progress.emit(
                    'PROBE',
                    'early stop — decisive guard/binding signal',
                    path=mtc.get('path'),
                    step=mtc.get('probe_step_id'),
                    outcome=analysis.get('call_outcome'),
                    scope=stop_scope,
                )
                if stop_scope == 'm8':
                    pending = [t for t in pending[idx:] if not str(t.get('mutation_type', '')).startswith('M8')]
                    idx = 0
                else:
                    break
            elif stop_scope == 'm8':
                progress.emit(
                    'PROBE',
                    'signature guard ignored — skip redundant M8 steps',
                    path=mtc.get('path'),
                    step=mtc.get('probe_step_id'),
                )
                pending = [t for t in pending[idx:] if not str(t.get('mutation_type', '')).startswith('M8')]
                idx = 0
            if budget.used_http >= budget.max_http:
                break
        return ran

    def _run_binding_phase(
        chain: Any,
        pick: Dict[str, Any],
        *,
        chain_id: str,
    ) -> bool:
        """M8/M7 intelligent binding probes when chain reaches BINDING_READY."""
        if not with_mutations or chain.binding_tested or not chain.binding_ready:
            return False
        seed_item = {
            'seed_id': chain_id,
            'api_id': pick.get('api_id'),
            'path': pick.get('path'),
            'template': templates_by_id.get(pick.get('api_id')),
        }
        if not seed_item.get('template'):
            return False
        parent = build_test_case(
            seed_item['template'], baseline_context=baseline_context, index=0,
        )
        parent['seed_id'] = chain_id
        ran = _run_intelligent_binding_probes(
            seed_item, parent, chain_id=chain_id, test_stage='binding_mutation',
        )
        if ran:
            chain.mark_binding_tested()
        return ran

    def _try_frontier_wave(trigger: str) -> int:
        """Pool-driven breadth wave + acquisition inject."""
        from minidrifter.verification.frontier_expander import expand_frontier
        if budget.used_http >= budget.max_http:
            return 0
        meta = expand_frontier(
            pack_dir,
            object_pool=object_pool,
            planner_state=state,
            baseline_context=baseline_context,
            max_new_tests=3,
        )
        injected = 0
        for tc in (meta.get('next_wave_test_cases') or [])[:2]:
            tc = {**tc, 'test_stage': 'frontier_wave', 'campaign_wave': trigger}
            all_test_cases[tc.get('test_id', '')] = tc
            ex = _execute_tracked(tc)
            if ex:
                process_result(tc, ex)
                injected += 1
        if injected:
            progress.emit('FRONTIER', f'expand_frontier ({trigger})', count=injected)
        for plan in plan_acquire_all_missing(
            object_pool, workflow_graph or {}, templates_by_id,
            pack_dir=pack_dir, confidence_tracker=confidence, limit_per_field=2,
        )[:3]:
            tpl = plan.get('template')
            if tpl and plan.get('action') == 'atomic_probe':
                atomic.inject_front({
                    'seed_id': f"frontier_{plan.get('target_field')}",
                    'api_id': plan.get('producer_api_id'),
                    'path': plan.get('path'),
                    'domain': 'general',
                    'priority': plan.get('score', 0) + 3,
                    'template': tpl,
                }, boost=plan.get('score', 0) + 2)
                injected += 1
        return injected

    def _dispatch_finding_escalation(
        tc: Dict[str, Any],
        analysis: Dict[str, Any],
        *,
        chain_state: Any = None,
        chain_id: Optional[str] = None,
    ) -> None:
        """On binding signal: plan + queue deepening tests (rule + optional LLM)."""
        if str(tc.get('test_stage') or '').startswith('finding_escalation'):
            return
        if str(tc.get('test_stage') or '').startswith('evidence_chain'):
            return
        from minidrifter.verification.finding_adjudicator import adjudicate_findings
        from minidrifter.verification.finding_escalation_planner import (
            _materialize_m7_cases,
            plan_finding_escalation,
        )
        from minidrifter.verification.llm_finding_escalation import propose_finding_escalation

        inline = adjudicate_findings(
            [analysis], {tc.get('test_id', ''): tc},
            chain_id=chain_id, baseline_context=baseline_context,
        )
        finding_registry.ingest(inline)

        plan = plan_finding_escalation(
            analysis=analysis,
            test_case=tc,
            pack_dir=pack_dir,
            graph=workflow_graph or {},
            templates_by_id=templates_by_id,
            object_pool=object_pool,
            baseline_context=baseline_context,
            ir_session=ir_session,
            chain_nodes=chain_state.nodes if chain_state else None,
            chain_id=chain_id,
        )
        fid = plan.get('finding_id') or ''
        summary = plan.get('finding_summary') or {}
        esc_key = f"{summary.get('api_id')}:{chain_id or 'global'}"
        if esc_key in escalated_finding_ids:
            return
        escalated_finding_ids.add(esc_key)

        use_llm = effective_chain_llm and not llm_dry_run and budget.consume_llm('chain')
        if use_llm:
            progress.llm_wait(stage='finding_escalation', detail=plan.get('finding_summary', {}).get('path'))
        llm_out = propose_finding_escalation(
            pack_dir, escalation_plan=plan, dry_run=not use_llm, llm_traces=llm_traces,
        )
        targets = llm_out.get('reordered_targets') or plan.get('targets') or []
        if targets != plan.get('targets'):
            plan['targets'] = targets
            plan['test_cases'] = _materialize_m7_cases(
                targets,
                baseline_context=baseline_context,
                object_pool=object_pool,
                ir_session=ir_session,
                finding_id=fid,
                chain_id=chain_id,
            )

        if chain_state:
            chain_state.add_finding_context({
                'finding_id': fid,
                'summary': plan.get('finding_summary'),
                'hypothesis': llm_out.get('hypothesis'),
                'chain_extension_goal': llm_out.get('chain_extension_goal'),
                'target_count': plan.get('target_count'),
            })
            chain_state.mark_escalation_dispatched()

        from minidrifter.verification.evidence_chain_composer import compose_evidence_chain

        evidence = compose_evidence_chain(
            escalation_plan=plan,
            llm_out=llm_out,
            baseline_context=baseline_context,
            object_pool=object_pool,
            ir_session=ir_session,
            chain_id=chain_id,
        )
        queued_ids: Set[str] = set()
        for esc_tc in evidence.get('ordered_test_cases') or plan.get('test_cases') or []:
            tid = esc_tc.get('test_id')
            if tid and tid in queued_ids:
                continue
            if tid:
                queued_ids.add(tid)
            escalation_queue.insert(0, esc_tc)

        for fork in plan.get('fork_seeds') or []:
            if chain_state and fork.get('api_id'):
                child = beam.fork_chain(
                    chain_state,
                    preferred_next_api=fork.get('api_id'),
                    hypothesis_id=fork.get('hypothesis_id'),
                )
                if child:
                    child.add_finding_context({'parent_finding_id': fid, 'strategy': fork.get('strategy')})

        escalation_log.append({
            'finding_id': fid,
            'source_path': tc.get('path'),
            'target_count': plan.get('target_count'),
            'test_count': len(queued_ids),
            'evidence_chain_id': evidence.get('evidence_chain_id'),
            'evidence_hops': evidence.get('hop_count'),
            'llm': bool(llm_out.get('used_llm')),
            'hypothesis': llm_out.get('hypothesis'),
            'chain_extension_goal': llm_out.get('chain_extension_goal'),
        })
        progress.emit(
            'ESCALATE',
            'finding-driven deepening queued',
            finding=fid,
            targets=plan.get('target_count'),
            tests=len(queued_ids),
            llm='yes' if llm_out.get('used_llm') else 'rule',
        )

    def _try_frontier_rescue(trigger: str) -> bool:
        nonlocal global_deliberations
        if global_deliberations >= max_global_deliberations:
            return False
        global_deliberations += 1
        ctx = build_policy_context(
            object_pool=object_pool,
            beam_summary=beam.summary(),
            atomic_summary=atomic.summary(),
            circuits=circuits.to_dict(),
            watchdog=watchdog.to_dict(),
            recent_failures=_recent_failure_hist(all_analyses),
            anchor_api_id=anchor_api_id,
        )
        pol_out = propose_policy(pack_dir, ctx, dry_run=not (with_llm_policy and deep_think), llm_traces=llm_traces)
        pol = pol_out.get('policy') or {}
        n_inj = execute_policy_action(
            pol, atomic=atomic, object_pool=object_pool,
            workflow_graph=workflow_graph or {}, templates_by_id=templates_by_id,
            pack_dir=pack_dir, confidence=confidence, progress=progress, beam=beam,
        )
        if deep_think:
            use_llm = effective_chain_llm and not llm_dry_run and budget.consume_llm('global')
            if use_llm:
                progress.llm_wait(stage='global_deliberation')
            glob = deliberate_global(
                pack_dir, chain_reasoning,
                object_pool=object_pool,
                circuits=circuits.to_dict(),
                recent_failures=_recent_failure_hist(all_analyses),
                anchor_api_id=anchor_api_id,
                with_llm=use_llm,
                llm_dry_run=llm_dry_run,
                llm_traces=llm_traces,
            )
            thought = glob.get('thought') or {}
            progress.emit(
                'THINK',
                f'global deliberation ({trigger})',
                summary=(thought.get('root_cause_summary') or '')[:120],
                llm='yes' if glob.get('used_llm') else 'rule',
            )
            n_inj += _apply_thought_actions(
                thought, atomic=atomic, object_pool=object_pool,
                workflow_graph=workflow_graph or {}, templates_by_id=templates_by_id,
                pack_dir=pack_dir, confidence=confidence, progress=progress,
            )
            chain_thought_log.append({
                'chain_id': '_global',
                'trigger': trigger,
                'used_llm': glob.get('used_llm'),
                'verdict': thought.get('verdict'),
                'summary': thought.get('root_cause_summary'),
            })
        atomic.reprioritize()
        beam.try_revive_all(
            set(object_pool.get('confirmed_fields') or []) | set(object_pool.get('frontier_unlocks') or [])
        )
        # Deep chain replan when shallow chains exhausted
        if deep_think and effective_chain_llm and not beam.select_top_b():
            from minidrifter.verification.llm_deep_chain_planner import (
                build_deep_chain_context, plan_deep_chains,
            )
            atomic_seeds = [
                {'api_id': c.seed_api_id, 'path': c.path, 'domain': c.domain, 'harvested': list(c.available_objects)}
                for c in beam.chains.values() if c.last_outcome == 'business_success'
            ]
            dctx = build_deep_chain_context(
                pack_dir,
                workflow_graph=workflow_graph or {},
                templates_by_id=templates_by_id,
                object_pool=object_pool,
                shallow_chains=beam.all_chains(),
                atomic_passed=atomic_seeds,
            )
            use_llm_deep = not llm_dry_run and budget.consume_llm('chain')
            deep_out = plan_deep_chains(pack_dir, dctx, with_llm=use_llm_deep, llm_dry_run=llm_dry_run, llm_traces=llm_traces)
            for prop in (deep_out.get('chains') or {}).get('proposed_chains') or []:
                for hop in prop.get('hops') or []:
                    tpl = templates_by_id.get(hop.get('api_id'))
                    if tpl and hop.get('order') == 1:
                        atomic.inject_front({
                            'seed_id': prop.get('chain_id'),
                            'api_id': hop.get('api_id'),
                            'path': hop.get('path'),
                            'domain': prop.get('domain', 'general'),
                            'priority': 10,
                            'template': tpl,
                        }, boost=5)
            progress.emit('DEEP_CHAIN', 'replanned deep chains', count=len((deep_out.get('chains') or {}).get('proposed_chains') or []), llm='yes' if deep_out.get('used_llm') else 'rule')
        _try_frontier_wave(trigger)
        return n_inj > 0 or bool(atomic.queue) or bool(beam.select_top_b())

    def _drain_retry_queue() -> int:
        """Re-run hops once missing materials enter the object pool."""
        nonlocal retry_queue
        if not retry_queue or budget.used_http >= budget.max_http:
            return 0
        available = set(object_pool.get('confirmed_fields') or []) | set(object_pool.get('frontier_unlocks') or [])
        avail_lower = {str(a).lower() for a in available}
        ready: List[Dict[str, Any]] = []
        remaining: List[Dict[str, Any]] = []
        for item in retry_queue:
            needed = item.get('retry_after_fields') or []
            if not needed or all(str(n).lower() in avail_lower for n in needed):
                ready.append(item)
            else:
                remaining.append(item)
        retry_queue = remaining
        ran = 0
        for tc in ready[:2]:
            cid = tc.get('chain_id')
            cstate = beam.chains.get(cid) if cid else None
            ex = _execute_tracked(tc, chain_fingerprint=cid or '')
            if ex:
                process_result(tc, ex, chain_id=cid, chain_state=cstate)
                ran += 1
                progress.emit('RETRY', 'hop retry after acquire', path=tc.get('path'), chain=cid)
        return ran

    def _reason_chain(
        chain: Any,
        *,
        trigger: str,
        attribution: Optional[Dict[str, Any]] = None,
        link: Optional[Dict[str, Any]] = None,
        force_llm: bool = False,
    ) -> Optional[Dict[str, Any]]:
        if not deep_think and not attribution:
            return None
        journal = chain_reasoning.get_or_create(
            chain.chain_id,
            seed_api_id=chain.seed_api_id,
            seed_path=chain.path,
            domain=chain.domain,
        )
        use_llm = effective_chain_llm and not llm_dry_run and budget.consume_llm('chain')
        journal.record_event(trigger, detail=attribution.get('diagnosis') if attribution else '')
        if use_llm:
            progress.llm_wait(stage='chain_reasoner', detail=chain.domain)
        out = reason_about_chain(
            pack_dir, chain, journal,
            object_pool=object_pool,
            attribution=attribution,
            link=link,
            recent_outcomes=[
                {'path': a.get('path'), 'outcome': a.get('call_outcome'), 'fc': a.get('failure_class')}
                for a in all_analyses[-12:]
            ],
            trigger=trigger,
            with_llm=use_llm,
            llm_dry_run=llm_dry_run,
            llm_traces=llm_traces,
            ir_session=ir_session,
        )
        thought = out.get('thought') or {}
        chain_thought_log.append({
            'chain_id': chain.chain_id,
            'trigger': trigger,
            'used_llm': out.get('used_llm'),
            'verdict': thought.get('verdict'),
            'summary': thought.get('root_cause_summary'),
        })
        progress.chain_think(
            chain_id=chain.chain_id,
            trigger=trigger,
            verdict=thought.get('verdict') or '?',
            summary=thought.get('root_cause_summary') or '',
            layer=thought.get('root_cause_layer'),
            actions=','.join(thought.get('recommended_actions') or [])[:100],
            used_llm=bool(out.get('used_llm')),
        )
        _apply_thought_actions(
            thought,
            atomic=atomic,
            object_pool=object_pool,
            workflow_graph=workflow_graph or {},
            templates_by_id=templates_by_id,
            pack_dir=pack_dir,
            confidence=confidence,
            progress=progress,
        )
        verdict = thought.get('verdict')
        if verdict == 'dead':
            beam.mark_dead(chain.chain_id, thought.get('root_cause_summary') or 'reasoner_dead')
        elif verdict in ('blocked_graph_hypothesis', 'blocked_temporary', 'need_object', 'blocked_baseline'):
            revive = thought.get('revival_conditions') or []
            chain.quarantine(
                thought.get('root_cause_summary') or verdict,
                revive=revive[:3] if isinstance(revive, list) else [],
            )
        return out

    def _execute_tracked(tc: Dict[str, Any], **kwargs: Any) -> Optional[Dict[str, Any]]:
        nonlocal pool_hash
        skip, reason = prune.should_skip(
            tc, baseline_context=baseline_context, pool_hash=pool_hash,
            chain_fingerprint=kwargs.get('chain_fingerprint') or '',
            object_pool=object_pool,
        )
        if skip:
            prune.record_pruned(tc, reason or 'pruned')
            return None
        circuit_skip, circuit_reason = circuits.should_skip_test(
            tc, template=templates_by_id.get(tc.get('api_id', '')),
        )
        if circuit_skip:
            prune.record_pruned(tc, circuit_reason)
            progress.emit('CIRCUIT', 'skip test', path=tc.get('path'), reason=circuit_reason)
            return None
        if not budget.consume():
            return None
        progress.http_execute(
            n=budget.used_http,
            max_n=budget.max_http,
            path=tc.get('path') or '?',
            stage=tc.get('test_stage') or 'test',
            mutation=tc.get('mutation_type'),
            chain_id=tc.get('chain_id'),
        )
        return _execute_one(
            tc, pack_dir=pack_dir, baseline_context=baseline_context, mode=mode,
            only_safe=only_safe, source_dir=source_dir, base_url=base_url,
            responses_dir=responses_dir,
        )

    def _log_http_start(tc: Dict[str, Any]) -> None:
        pass  # logging moved to _execute_tracked

    def process_result(
        tc: Dict[str, Any],
        ex: Dict[str, Any],
        *,
        chain_id: Optional[str] = None,
        chain_state: Any = None,
    ) -> Dict[str, Any]:
        nonlocal pool_hash, object_pool, state, anchor_passed, steps_since_policy
        tid_reg = tc.get('test_id') or ''
        if tid_reg:
            all_test_cases[tid_reg] = tc
        analysis = analyze_response(ex, tc, baseline_context=baseline_context, pack_dir=pack_dir)
        signals = extract_signals(analysis, tc)
        analysis['signals'] = signals
        fb = build_test_feedback(tc, ex, analysis, signals)

        prev_fields = set(object_pool.get('confirmed_fields') or [])
        object_pool = update_pool_from_analysis(object_pool, analysis, test_id=tc.get('test_id', ''))
        new_fields = set(object_pool.get('confirmed_fields') or []) - prev_fields
        pool_hash = pool_snapshot_hash(object_pool)
        _writeback_produces(tc, analysis)
        state = update_planner_state(state, tc, ex, analysis)
        prune.record(tc, analysis, baseline_context=baseline_context, pool_hash=pool_hash,
                     chain_fingerprint=chain_id or '')

        all_executions.append(ex)
        all_analyses.append(analysis)
        all_feedback.append(fb)
        tid = tc.get('test_id') or ''
        if tid:
            exec_by_id[tid] = ex
            analysis_by_id[tid] = analysis
        steps_since_policy += 1

        api_id_done = tc.get('api_id') or analysis.get('api_id') or ''
        if api_id_done:
            finding_registry.apply_lifecycle_for_api(api_id_done, all_analyses, all_test_cases)

        outcome = analysis.get('call_outcome') or 'unknown'
        fc = analysis.get('failure_class')
        harvested = analysis.get('produced_fields') or []

        if tc.get('test_stage') == 'atomic_probe':
            atomic.mark_probed(
                tc.get('api_id', ''), outcome=outcome, failure_class=fc,
                harvested=harvested, path=tc.get('path', ''), domain=tc.get('domain', 'general'),
            )
            atomic.record_transport_outcome(
                path=tc.get('path', ''), domain=tc.get('domain', 'general'),
                outcome=outcome, failure_class=fc,
            )
            if outcome == 'business_success':
                if anchor_api_id and tc.get('api_id') == anchor_api_id:
                    anchor_passed = True
                _seed_beam_branches(tc, harvested)
                if deep_think:
                    for c in beam.chains.values():
                        if c.seed_api_id == tc.get('api_id') and c.status == CHAIN_ACTIVE:
                            j = chain_reasoning.get_or_create(
                                c.chain_id, seed_api_id=c.seed_api_id, seed_path=c.path, domain=c.domain,
                            )
                            j.record_event('atomic_seed', detail=f'harvested={harvested}', path=tc.get('path'))
                            break

        if chain_state:
            finding = bool(signals.get('suspicious'))
            chain_state.record_outcome(outcome, failure_class=fc, harvested=harvested, finding=finding)
            if outcome == 'business_success':
                tpl = templates_by_id.get(tc.get('api_id', ''))
                if _chain_has_bindable_params(tpl) and harvested:
                    chain_state.mark_binding_ready()
            if fc:
                circuits.record(fc)

        domain = tc.get('domain') or 'general'
        tx_rec = transport_tracker.record(
            path=tc.get('path') or '', domain=domain, outcome=outcome, failure_class=fc,
        )
        transport_ctx = {
            'family': tx_rec.get('family'),
            'family_blocked': tx_rec.get('family_blocked'),
            'domain_blocked': tx_rec.get('domain_blocked'),
            'failures': tx_rec.get('failures'),
        }

        m0_m7_pair = None
        mut = tc.get('mutation_type') or ''
        if mut.startswith('M7'):
            m0_ref = find_m0_pair(
                tc,
                test_cases_by_id=all_test_cases,
                executions_by_id=exec_by_id,
                analyses_by_id=analysis_by_id,
            )
            if m0_ref:
                m0_m7_pair = compare_m0_m7_pair(
                    m0_ref['test_case'], tc,
                    m0_ref['execution'], ex,
                    m0_ref['analysis'], analysis,
                    baseline_context=baseline_context,
                )

        prior_hops = list(chain_hop_memory.get(chain_id or '', [])) if chain_id else []

        hop = adjudicate_hop(
            tc, ex, analysis,
            signals=signals,
            baseline_context=baseline_context,
            graph=workflow_graph or {},
            templates_by_id=templates_by_id,
            object_pool=object_pool,
            chain_context={'chain_id': chain_id},
            anchor_ok=anchor_passed or not anchor_api_id,
            recent_same_fc_count=_recent_failure_hist(all_analyses).get(fc or '', 0),
            retry_count=hop_retry_counts.get(tid, 0),
            prior_hops=prior_hops,
            m0_m7_pair=m0_m7_pair,
            transport_context=transport_ctx,
        )
        needs_llm = (
            effective_chain_llm
            and deep_think
            and (
                outcome != 'business_success'
                or signals.get('suspicious')
                or hop.get('missing_materials')
            )
        )
        used_llm_hop = False
        if needs_llm and not llm_dry_run and budget.consume_llm('chain'):
            progress.llm_wait(stage='hop_adjudicator', detail=tc.get('path') or '?')
            prior = [
                {
                    'path': h.get('path'),
                    'health': h.get('node_health'),
                    'missing': [m.get('field') for m in h.get('missing_materials') or []],
                }
                for h in hop_adjudication_log[-4:]
                if h.get('chain_id') == chain_id
            ]
            llm_hop = deepen_hop_adjudication(
                pack_dir, hop_verdict=hop, prior_hops=prior, llm_traces=llm_traces,
            )
            hop = llm_hop.get('enriched') or hop
            used_llm_hop = bool(llm_hop.get('used_llm'))
        hop_adjudication_log.append(hop)
        if chain_id:
            chain_hop_memory.setdefault(chain_id, []).append(hop)
            if len(chain_hop_memory[chain_id]) > 12:
                chain_hop_memory[chain_id] = chain_hop_memory[chain_id][-12:]

        missing_names = ', '.join(
            m.get('field') or '?' for m in hop.get('missing_materials') or []
        )
        attr = hop.get('attribution') or {}
        root = hop.get('llm_root_cause') or attr.get('diagnosis') or outcome
        progress.hop_adjudicate(
            path=tc.get('path') or '?',
            health=hop.get('node_health') or 'unknown',
            root_cause=str(root),
            missing=missing_names or None,
            retry=bool((hop.get('resolution_plan') or {}).get('retry_eligible')),
            used_llm=used_llm_hop,
        )

        def _escalate_from_hop(hop_verdict: Dict[str, Any], *, test_case: Optional[Dict[str, Any]] = None) -> None:
            tc_esc = test_case or tc
            corr = hop_verdict.get('param_correlation') or {}
            if corr.get('response_delta') not in {
                'binding_mismatch_under_mutation', 'binding_drift_confirmed',
            } and not signals.get('suspicious'):
                return
            _dispatch_finding_escalation(
                tc_esc, analysis, chain_state=chain_state, chain_id=chain_id,
            )

        res_exec = execute_hop_resolution(
            hop,
            atomic=atomic,
            beam=beam,
            object_pool=object_pool,
            workflow_graph=workflow_graph or {},
            templates_by_id=templates_by_id,
            pack_dir=pack_dir,
            confidence=confidence,
            progress=progress,
            ticket_registry=ticket_registry,
            material_requests=material_requests,
            retry_queue=retry_queue,
            test_case=tc,
            transport_tracker=transport_tracker,
            finding_escalation_hook=_escalate_from_hop,
        )
        if 'schedule_retry' in (res_exec.get('applied') or []):
            hop_retry_counts[tid] = hop_retry_counts.get(tid, 0) + 1

        if outcome != 'business_success':
            attr = apply_diagnosis_action(
                attr, circuits=circuits, beam=beam, confidence=confidence, chain_id=chain_id,
            )
            attributions.append(attr)
            progress.diagnose(
                path=tc.get('path') or '?',
                layer=attr.get('layer') or '?',
                action=attr.get('primary_action') or '?',
                diagnosis=attr.get('diagnosis') or fc or outcome,
            )
            if fc and circuits.is_open(fc):
                progress.circuit(
                    failure_class=fc,
                    open_now=True,
                    pause=circuits.pause_execute,
                )
            if deep_think and fc and chain_state:
                _reason_chain(chain_state, trigger='hop_failure', attribution=attr)
            auto_handled = any(
                a.startswith('acquire_object') or a == 'schedule_retry'
                for a in (res_exec.get('applied') or [])
            )
            hard_pause = fc in {'auth_expired', 'build_failed', 'transport_url_routing'}
            if fc == 'auth_expired' and attr.get('diagnosis') == 'scoped_auth_failure':
                hard_pause = False
            if mode == 'execute' and operator.should_pause(attr) and hard_pause and not auto_handled:
                req = operator.emit_request(
                    trigger=fc or 'failure',
                    attribution=attr,
                    test_case=tc,
                )
                ticket = build_user_ticket(
                    attribution=attr,
                    test_case=tc,
                    execution=ex,
                    chain_id=chain_id,
                )
                ticket['missing_materials'] = hop.get('missing_materials') or []
                ticket['material_request'] = hop.get('material_request')
                ticket['why_deeper_blocked'] = (hop.get('material_request') or {}).get('why_deeper_blocked') or ''
                ticket_registry.emit(ticket)
                write_json(pack_dir / 'resume_plan.json', build_resume_plan(pack_dir, ticket))
                progress.emit('OPERATOR', 'user action required', request=req.get('request_type'))
                if verbose:
                    print(ticket_registry.format_console(ticket), flush=True)
                    print(format_request_for_console(req), flush=True)
            elif hop.get('material_request') and verbose:
                progress.emit(
                    'MATERIAL',
                    hop.get('material_request', {}).get('why_deeper_blocked') or 'missing fields for deeper chain',
                    fields=missing_names or None,
                )

        elif hop.get('node_health') == 'finding_signal':
            progress.emit(
                'HOP',
                'binding signal on success hop',
                path=tc.get('path'),
                correlation=(hop.get('param_correlation') or {}).get('response_delta'),
            )

        harvested_str = ','.join(harvested[:5]) if harvested else None
        progress.http_result(
            path=tc.get('path') or '?',
            outcome=outcome,
            failure_class=fc,
            harvested=harvested_str,
            suspicious=bool(signals.get('suspicious')),
        )

        if tc.get('test_stage') == 'atomic_probe' and outcome == 'business_success':
            progress.emit('ATOMIC', 'gate passed - seeding beam chain', api=tc.get('api_id'), path=tc.get('path'))
        if signals.get('suspicious'):
            progress.emit('FINDING', 'suspicious signal', path=tc.get('path'), mutation=tc.get('mutation_type'))
            _dispatch_finding_escalation(
                tc, analysis, chain_state=chain_state, chain_id=chain_id,
            )

        watchdog.record_step(
            new_objects=len(new_fields),
            new_depth=1 if chain_state and outcome == 'business_success' else 0,
            new_success_api=1 if outcome == 'business_success' else 0,
            finding_signal=1 if signals.get('suspicious') else 0,
        )
        return analysis

    # --- Main loop ---
    while budget.used_http < budget.max_http:
        progressed = False
        loop_round += 1
        http_at_round_start = budget.used_http
        if loop_round == 1 or loop_round % 10 == 0:
            progress.emit(
                'LOOP',
                f'round {loop_round}',
                http=f'{budget.used_http}/{budget.max_http}',
                atomic_passed=atomic.summary().get('atomic_passed'),
                beam_chains=beam.summary().get('total'),
                llm=f'{budget.used_llm}/{budget.max_llm}',
            )

        # Policy replanner (Layer 5 — rule always, LLM optional override)
        if steps_since_policy >= policy_interval or watchdog.is_stalled():
            if watchdog.is_stalled():
                progress.emit('WATCHDOG', 'stall detected - triggering policy replan')
            ctx = build_policy_context(
                object_pool=object_pool,
                beam_summary=beam.summary(),
                atomic_summary=atomic.summary(),
                circuits=circuits.to_dict(),
                watchdog=watchdog.to_dict(),
                recent_failures=_recent_failure_hist(all_analyses),
                anchor_api_id=anchor_api_id,
            )
            use_llm = with_llm_policy and not llm_dry_run and budget.consume_llm('policy')
            if use_llm:
                progress.llm_wait(stage='policy_replanner', detail='global state summary')
            pol_out = propose_policy(
                pack_dir, ctx, dry_run=not use_llm, llm_traces=llm_traces,
            )
            policy_log.append(pol_out.get('policy') or {})
            pol = pol_out.get('policy') or {}
            progress.policy(
                action=pol.get('action') or '?',
                reason=pol.get('reason') or '',
                used_llm=bool(pol_out.get('used_llm')),
            )
            execute_policy_action(
                pol, atomic=atomic, object_pool=object_pool,
                workflow_graph=workflow_graph or {}, templates_by_id=templates_by_id,
                pack_dir=pack_dir, confidence=confidence, progress=progress, beam=beam,
                ticket_registry=ticket_registry,
            )
            steps_since_policy = 0

        available = set(object_pool.get('confirmed_fields') or []) | set(object_pool.get('frontier_unlocks') or [])
        beam.try_revive_all(available)
        beam.prune_dead()
        if _drain_retry_queue():
            progressed = True
            continue

        # Layer 3: inject acquire plans when objects missing
        if len(all_executions) % 5 == 0:
            for plan in plan_acquire_all_missing(
                object_pool, workflow_graph or {}, templates_by_id,
                pack_dir=pack_dir, confidence_tracker=confidence, limit_per_field=2,
            )[:2]:
                tpl = plan.get('template')
                if tpl and plan.get('action') == 'atomic_probe':
                    atomic.inject_front({
                        'seed_id': f"acq_{plan.get('target_field')}",
                        'api_id': plan.get('producer_api_id'),
                        'path': plan.get('path'),
                        'domain': 'general',
                        'priority': plan.get('score', 0) + 2,
                        'template': tpl,
                    })

        # Layer 0: finding escalation queue (highest priority)
        while escalation_queue and budget.used_http < budget.max_http:
            esc_tc = escalation_queue.pop(0)
            test_index += 1
            all_test_cases[esc_tc.get('test_id', '')] = esc_tc
            ex = _execute_tracked(esc_tc, chain_fingerprint=esc_tc.get('chain_id') or '')
            if not ex:
                break
            esc_chain = None
            if esc_tc.get('chain_id'):
                esc_chain = beam.chains.get(esc_tc.get('chain_id'))
            process_result(esc_tc, ex, chain_id=esc_tc.get('chain_id'), chain_state=esc_chain)
            progressed = True

        # Layer 4: beam expansion (top-B chains)
        for chain in beam.select_top_b():
            if budget.used_http >= budget.max_http:
                break
            if chain.depth >= max_depth:
                continue
            confirmed_findings = [
                {'api_id': f.get('api_id'), 'path': f.get('path'), 'type': f.get('finding_type'), 'status': f.get('status')}
                for f in finding_registry.active_findings()
                if f.get('status') == 'confirmed'
            ][:5]
            last_signals: Dict[str, Any] = {}
            if chain.last_outcome == 'business_success' or chain.binding_ready:
                last_signals = {
                    'depth_continue': True,
                    'harvest': list(chain.available_objects),
                    'binding_ready': chain.binding_ready,
                    'suspicious': bool(getattr(chain, 'active_findings', None)),
                    'active_findings': getattr(chain, 'active_findings', [])[-2:],
                    'escalation_pending': getattr(chain, 'escalation_pending', False),
                    'confirmed_findings': confirmed_findings,
                }

            pref = chain.preferred_next_api if chain.depth <= 1 else None
            planned = list(chain.planned_path) if getattr(chain, 'planned_path', None) else None
            use_workflow_llm = effective_chain_llm and not llm_dry_run and budget.consume_llm('chain')
            link = plan_next_link(
                pack_dir, chain_nodes=chain.nodes, object_pool=object_pool,
                baseline_context=baseline_context, last_signals=last_signals,
                with_llm=use_workflow_llm,
                llm_dry_run=llm_dry_run, llm_traces=llm_traces,
                ir_session=ir_session,
                preferred_next_api=pref,
                planned_path=planned,
                static_hops=getattr(chain, 'static_hops', None) or None,
            )
            if link.get('stop'):
                missing = link.get('missing_materials') or []
                if missing:
                    for plan in plan_acquire_all_missing(
                        object_pool, workflow_graph or {}, templates_by_id,
                        pack_dir=pack_dir, confidence_tracker=confidence, limit_per_field=2,
                    ):
                        if plan.get('target_field') not in missing:
                            continue
                        tpl = plan.get('template')
                        if tpl:
                            atomic.inject_front({
                                'seed_id': f"acq_{plan.get('target_field')}_{chain.chain_id[:8]}",
                                'api_id': plan.get('producer_api_id'),
                                'path': plan.get('path'),
                                'domain': chain.domain,
                                'priority': plan.get('score', 0) + 3,
                                'template': tpl,
                            }, boost=2)
                    chain.quarantine(
                        link.get('reason') or 'no_linked_consumer',
                        revive=list(missing)[:3],
                    )
                elif link.get('reason') == 'no_linked_consumer':
                    chain.quarantine(
                        'no_linked_consumer',
                        revive=[f for f in (link.get('near_miss_candidates') or [{}])[0].get('missing_fields') or []][:1],
                    )
                if deep_think or link.get('reason') == 'no_linked_consumer':
                    _reason_chain(chain, trigger='planner_stop', link=link)
                progress.beam(
                    event='quarantine' if chain.status != CHAIN_ACTIVE else 'planner_stop',
                    chain_id=chain.chain_id,
                    domain=chain.domain,
                    detail=link.get('reason') or 'no consumer',
                )
                continue

            if deep_think and link.get('near_miss_candidates'):
                _reason_chain(chain, trigger='pre_hop', link=link, force_llm=False)

            for tc in link.get('next_test_cases') or []:
                tc = {
                    **tc,
                    'chain_id': chain.chain_id,
                    'test_stage': 'beam_expand',
                }
                test_index += 1
                all_test_cases[tc.get('test_id', '')] = tc
                ex = _execute_tracked(tc, chain_fingerprint=chain.chain_id)
                if not ex:
                    chain.record_skip()
                    if chain.skip_streak >= 2:
                        _reason_chain(chain, trigger='beam_skip_exhausted', link=link)
                        if chain.status == CHAIN_ACTIVE:
                            chain.quarantine('beam_skip_exhausted', revive=[])
                        progress.beam(
                            event='quarantine',
                            chain_id=chain.chain_id,
                            domain=chain.domain,
                            detail='pruned_or_blocked_repeatedly',
                        )
                    break
                chain.clear_skip_streak()
                pick = link.get('next_api') or {}
                chain.push_node(pick.get('api_id', ''), pick.get('path', ''), role='consumer')
                if chain.preferred_next_api:
                    chain.preferred_next_api = None
                process_result(tc, ex, chain_id=chain.chain_id, chain_state=chain)
                progressed = True

                _run_binding_phase(chain, pick, chain_id=chain.chain_id)

                if with_mutations and ex.get('call_outcome') != 'business_success':
                    break
                if chain.binding_ready and not chain.binding_tested:
                    _run_binding_phase(chain, pick, chain_id=chain.chain_id)
                break

        # Layer 1: atomic probe
        if budget.used_http < budget.max_http:
            item = atomic.pop_next()
            if item:
                tc = atomic.build_atomic_test(item, index=test_index)
                test_index += 1
                all_test_cases[tc.get('test_id', '')] = tc
                ex = _execute_tracked(tc)
                if ex:
                    analysis = process_result(tc, ex)
                    progressed = True
                    if analysis.get('call_outcome') == 'business_success' and with_mutations:
                        _run_intelligent_binding_probes(
                            item, tc, test_stage='binding_mutation',
                        )

        if not progressed:
            if ticket_registry.blocking_global() and mode == 'execute' and not resume_mode:
                progress.emit(
                    'TICKET',
                    'global blocking ticket — pausing search until baseline refresh',
                    tickets=len(ticket_registry.blocking_global()),
                )
                stop_reason = 'blocking_ticket'
                break
            if budget.used_http == http_at_round_start:
                idle_rounds += 1
                if deep_think and idle_rounds in (5, 15, 30):
                    _try_frontier_wave(f'idle_{idle_rounds}')
            else:
                idle_rounds = 0
            if idle_rounds >= max_idle_rounds:
                rescued = _try_frontier_rescue('idle_watchdog')
                if rescued:
                    idle_rounds = 0
                else:
                    progress.emit(
                        'WATCHDOG',
                        f'idle loop limit ({max_idle_rounds} rounds without HTTP progress) - stopping search',
                        http=f'{budget.used_http}/{budget.max_http}',
                    )
                    stop_reason = 'idle_watchdog'
                    break
            if not atomic.queue and not beam.select_top_b():
                if _try_frontier_rescue('frontier_exhausted'):
                    idle_rounds = 0
                else:
                    progress.emit(
                        'FRONTIER',
                        'atomic queue empty and no active beam chains',
                        http=f'{budget.used_http}/{budget.max_http}',
                        quarantined=beam.summary().get('by_status', {}).get('quarantined'),
                    )
                    stop_reason = 'frontier_exhausted'
                    break
            atomic.reprioritize()
        else:
            idle_rounds = 0

    # Findings
    progress.emit('FINALIZE', 'adjudicating findings and writing artifacts')
    finding_registry.ingest(adjudicate_findings(
        all_analyses, all_test_cases, baseline_context=baseline_context,
    ))
    finding_registry.apply_lifecycle_rules(all_analyses, all_test_cases)

    from minidrifter.verification.chain_report import build_all_chain_reports
    chain_dicts = beam.all_chains()
    chain_reports = build_all_chain_reports(
        finding_registry.all_findings(),
        depth_chains=chain_dicts,
        executions=all_executions,
        analyses=all_analyses,
        test_cases_by_id=all_test_cases,
    )

    if escalation_log:
        write_json(pack_dir / 'finding_escalation_log.json', {
            'items': escalation_log,
            'confirmed_at_runtime': finding_registry.summary().get('confirmed', 0),
        })
    write_json(pack_dir / 'finding_registry.json', finding_registry.to_document())
    write_json(pack_dir / 'finding_chain_reports.json', chain_reports)
    write_object_pools(pack_dir, object_pool)
    write_json(pack_dir / 'planner_state.json', state)
    _write_jsonl(pack_dir / 'execution_results.jsonl', all_executions)
    _write_jsonl(pack_dir / 'response_analysis.jsonl', all_analyses)
    _write_jsonl(pack_dir / 'test_feedback.jsonl', all_feedback)
    _write_jsonl(pack_dir / 'attribution_records.jsonl', attributions)
    if hop_adjudication_log:
        _write_jsonl(pack_dir / 'hop_adjudication.jsonl', hop_adjudication_log)
        from minidrifter.verification.hop_adjudication_summary import write_hop_summary
        write_hop_summary(pack_dir, hop_adjudication_log)
    persist_material_requests(pack_dir, material_requests)
    write_json(pack_dir / 'transport_family_state.json', transport_tracker.to_dict())
    write_json(pack_dir / 'api_guard_beliefs.json', guard_beliefs.to_dict())
    if finding_registry.all_findings():
        _write_jsonl(pack_dir / 'findings.jsonl', finding_registry.all_findings())
    if prune.pruned:
        _write_jsonl(pack_dir / 'pruned_tests.jsonl', prune.pruned)

    write_json(pack_dir / 'apex_beam_chains.json', {
        'generated_at': _utc_now(),
        'beam': beam.summary(),
        'chains': chain_dicts,
    })
    write_json(pack_dir / 'apex_confidence.json', confidence.to_document())
    write_json(pack_dir / 'apex_circuits.json', circuits.to_dict())
    write_json(pack_dir / 'apex_policy_log.json', {'policies': policy_log})
    write_json(pack_dir / 'chain_reasoning_journals.json', chain_reasoning.to_document())
    if chain_thought_log:
        _write_jsonl(pack_dir / 'chain_reasoning.jsonl', chain_thought_log)
    write_json(pack_dir / 'atomic_probe_state.json', atomic.summary())

    if llm_traces:
        from minidrifter.verification.llm_trace import append_trace_log, write_trace_session
        append_trace_log(pack_dir, llm_traces)
        write_trace_session(pack_dir, llm_traces, {'mode': 'apex_poc', 'calls': len(llm_traces)})
    from minidrifter.verification.llm_health import summarize_llm_health
    llm_health = summarize_llm_health(pack_dir, llm_traces)

    business_success = sum(1 for a in all_analyses if a.get('call_outcome') == 'business_success')
    confirmed = finding_registry.summary().get('confirmed', 0)

    from minidrifter.ir.verification_bridge import beam_chain_to_universal
    live_chains = [beam_chain_to_universal(ch) for ch in chain_dicts]
    ir_session.persist_runtime_chains(live_chains)

    session = {
        'schema_version': '1.0.0',
        'search_mode': 'apex_poc',
        'generated_at': _utc_now(),
        'mode': mode,
        'status': 'completed',
        'stop_reason': stop_reason,
        'deep_think': deep_think,
        'with_llm_chain': effective_chain_llm,
        'resume_mode': resume_mode,
        'llm_health': llm_health,
        'verdict': 'finding_confirmed' if confirmed else ('success' if business_success else 'partial'),
        'budget': budget.to_dict(),
        'workflow_graph_stats': graph_stats,
        'runtime_graph_meta': runtime_graph_meta,
        'universal_ir': ir_session.to_search_context(),
        'finding_lifecycle': finding_registry.summary(),
        'coverage': {
            'http_calls': len(all_executions),
            'atomic_probed': atomic.summary().get('probed_count'),
            'atomic_passed': atomic.summary().get('atomic_passed'),
            'beam_chains': len(chain_dicts),
            'business_success': business_success,
            'findings_confirmed': confirmed,
            'attributions': len(attributions),
            'pruned': len(prune.pruned),
            'llm_traces': len(llm_traces),
            'chain_thoughts': len(chain_thought_log),
            'finding_escalations': len(escalation_log),
            'escalation_tests_queued': sum(e.get('test_count') or 0 for e in escalation_log),
            'hop_adjudications': len(hop_adjudication_log),
            'material_requests': len(material_requests),
            'hop_retries_scheduled': len(retry_queue),
            'transport_blocked_families': len(transport_tracker.blocked_families),
        },
        'apex': {
            'beam': beam.summary(),
            'circuits': circuits.to_dict(),
            'watchdog': watchdog.to_dict(),
            'atomic': atomic.summary(),
            'chain_reasoning': chain_reasoning.to_document().get('by_verdict'),
        },
        'preflight': preflight,
    }
    write_json(pack_dir / 'search_session.json', session)

    from minidrifter.verification.analysis_report import build_verification_analysis_report, write_analysis_report
    report = build_verification_analysis_report(pack_dir, preflight=preflight or {})
    report['search_session'] = session
    report['search_mode'] = 'apex_poc'
    paths = write_analysis_report(pack_dir, report)
    session['analysis_report'] = paths

    from minidrifter.orchestration.run_manifest import finalize_run
    run_doc = finalize_run(pack_dir, project_name=pack_dir.name, snapshot=True)
    session['run_id'] = run_doc.get('run_id')
    session['run_metrics'] = run_doc.get('metrics')
    write_json(pack_dir / 'search_session.json', session)

    progress.summary(
        verdict=session.get('verdict'),
        http=len(all_executions),
        business_success=business_success,
        atomic_passed=atomic.summary().get('atomic_passed'),
        beam_chains=len(chain_dicts),
        findings_confirmed=confirmed,
        attributions=len(attributions),
    )
    return session
