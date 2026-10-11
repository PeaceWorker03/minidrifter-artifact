# -*- coding: utf-8
"""Chain-strict verification — follow one static business chain; no BFS fallback."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from minidrifter.business_chain.chain_run_context import (
    select_top_ranked_chain,
    validate_chain_pack_consistency,
)
from minidrifter.business_chain.chain_intake import (
    BUSINESS_PURPOSE,
    build_chain_intake_checklist,
    render_chain_intake_prompt,
    validate_uploaded_material_against_chain,
)
from minidrifter.business_chain.schema import SCHEMA_VERSION
from minidrifter.core.utils import write_json
from minidrifter.verification.campaign_planner import build_test_case
from minidrifter.verification.credential_probe_planner import plan_intelligent_binding_campaign
from minidrifter.verification.executor import execute_test_case
from minidrifter.verification.finding_adjudicator import (
    adjudicate_findings,
    chain_verdict_from_findings,
)
from minidrifter.verification.finding_classifier import (
    FINDING_F1,
    FINDING_F2,
    FINDING_F3,
)
from minidrifter.verification.finding_lifecycle import FindingRegistry
from minidrifter.verification.chain_object_pool import ChainObjectPool
from minidrifter.verification.hop_policy import (
    HOP_SKIPPED,
    inherit_baseline_params,
    is_success_status,
    should_skip_hop,
    skip_hop_result,
    try_material_backed_hop,
)
from minidrifter.verification.replay_preflight import run_replay_preflight
from minidrifter.verification.response_oracle import analyze_response
from minidrifter.verification.safety_policy import evaluate_test_safety

HOP_STATUS_OK = 'business_success'
HOP_MISSING_OBJECT = 'missing_object'
HOP_TEMPLATE_UNMATERIALIZED = 'template_unmaterialized'
HOP_CRYPTO_FAILED = 'crypto_failed'
HOP_BLOCKED = 'blocked'


def _baseline_producer_values(
    hop: Dict[str, Any],
    baseline_context: Dict[str, Any],
    intake_report: Optional[Dict[str, Any]],
) -> Dict[str, str]:
    produces = hop.get('produces') or []
    if not produces:
        return {}
    resolved = baseline_context.get('resolved_fields') or {}
    agg = ((intake_report or {}).get('decrypted_fields_aggregate') or {}).get('fields') or {}
    out: Dict[str, str] = {}
    for field in produces:
        if field in agg and agg[field] not in (None, ''):
            out[field] = str(agg[field])
            continue
        ent = resolved.get(field) or resolved.get(field.lower())
        if isinstance(ent, dict) and ent.get('value') not in (None, ''):
            out[field] = str(ent['value'])
    return out


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def select_ranked_business_chain(
    pack_dir: Path,
    *,
    chain_id: Optional[str] = None,
    rank_plan: Optional[Dict[str, Any]] = None,
    chains_doc: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Backward-compatible wrapper — Top1 from rank_plan, no stale fallback."""
    chain, _meta = select_top_ranked_chain(
        pack_dir, chain_id=chain_id, chains_doc=chains_doc, rank_plan=rank_plan,
    )
    return chain


def _waiting_for_entry_capture_payload(
    chain_doc: Dict[str, Any],
    *,
    material_validation: Dict[str, Any],
    hop_result: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    entry_path = chain_doc.get('entry_path') or ''
    fields = (
        chain_doc.get('primary_mutation_targets')
        or chain_doc.get('binding_fields')
        or chain_doc.get('objects')
        or []
    )[:6]
    reason = 'missing_entry_capture'
    if chain_doc.get('entry_request_template_partial') and not chain_doc.get('entry_runtime_replay_ready'):
        reason = 'entry_request_template_partial'
    if hop_result and hop_result.get('status') == HOP_TEMPLATE_UNMATERIALIZED:
        reason = 'entry_template_unmaterialized'
    return {
        'verdict': 'waiting_for_entry_capture',
        'next_action': 'request_chain_seed_capture',
        'expected_path': entry_path,
        'expected_fields': fields,
        'entry_page': chain_doc.get('entry_page'),
        'entry_event': chain_doc.get('entry_event'),
        'reason': reason,
        'material_validation': material_validation,
    }


def _diagnose_hop_failure(
    *,
    test_case: Dict[str, Any],
    execution: Dict[str, Any],
    template: Optional[Dict[str, Any]],
    missing_objects: List[str],
) -> Tuple[str, Dict[str, Any]]:
    build = execution.get('build_status') or execution.get('call_outcome')
    if missing_objects:
        return HOP_MISSING_OBJECT, {
            'status': HOP_MISSING_OBJECT,
            'missing_fields': missing_objects,
            'recommended_action': 'provide_chain_entry_capture',
        }
    if not template:
        return HOP_TEMPLATE_UNMATERIALIZED, {
            'status': HOP_TEMPLATE_UNMATERIALIZED,
            'api_id': test_case.get('api_id'),
            'path': test_case.get('path'),
            'message': 'API template not materialized',
        }
    tpl_status = template.get('status') or ''
    if tpl_status not in {'materialized_plain', 'materialized_with_crypto_profile', 'replay_ready'}:
        if template.get('missing_slots'):
            return HOP_TEMPLATE_UNMATERIALIZED, {
                'status': HOP_TEMPLATE_UNMATERIALIZED,
                'missing_slots': template.get('missing_slots'),
                'template_status': tpl_status,
            }
    if build in {'crypto_engine_unavailable', 'missing_crypto_keys'}:
        return HOP_CRYPTO_FAILED, {
            'status': HOP_CRYPTO_FAILED,
            'build_status': build,
            'crypto_profile_id': test_case.get('crypto_profile_id'),
        }
    if execution.get('call_outcome') == 'build_failed':
        reason = (execution.get('errors') or ['build_failed'])[0]
        if 'crypto' in str(reason).lower():
            return HOP_CRYPTO_FAILED, {'status': HOP_CRYPTO_FAILED, 'reason': reason}
        if 'missing' in str(reason).lower():
            return HOP_MISSING_OBJECT, {'status': HOP_MISSING_OBJECT, 'reason': reason}
        return HOP_TEMPLATE_UNMATERIALIZED, {'status': HOP_TEMPLATE_UNMATERIALIZED, 'reason': reason}
    return HOP_BLOCKED, {'status': HOP_BLOCKED, 'call_outcome': execution.get('call_outcome')}


def execute_hop(
    hop: Dict[str, Any],
    *,
    pack_dir: Path,
    baseline_context: Dict[str, Any],
    templates_by_id: Dict[str, Dict[str, Any]],
    chain_pool: ChainObjectPool,
    mode: str,
    source_dir: Optional[Path],
    base_url: Optional[str],
    only_safe: bool,
    hop_index: int,
    material_validation: Optional[Dict[str, Any]] = None,
    intake_report: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    api_id = hop.get('api_id') or ''
    template = templates_by_id.get(api_id)
    missing = chain_pool.missing_for_hop(hop)
    if missing:
        return {
            'hop_index': hop_index,
            'api_id': api_id,
            'path': hop.get('path'),
            'role': hop.get('role'),
            'status': HOP_MISSING_OBJECT,
            'diagnosis': {'missing_fields': missing},
            'executed': False,
        }

    if not template:
        return {
            'hop_index': hop_index,
            'api_id': api_id,
            'path': hop.get('path'),
            'role': hop.get('role'),
            'status': HOP_TEMPLATE_UNMATERIALIZED,
            'diagnosis': {'message': 'no template'},
            'executed': False,
        }

    tc = build_test_case(template, baseline_context=baseline_context, index=3000 + hop_index)
    tc['test_stage'] = 'chain_strict_hop'
    tc['chain_source'] = 'static_business_chain'
    tc['chain_role'] = hop.get('role')
    tc = chain_pool.apply_to_test_case(tc, hop)
    tc = inherit_baseline_params(
        tc, hop, baseline_context=baseline_context, intake_report=intake_report,
    )

    safety = evaluate_test_safety(tc, baseline_context=baseline_context, only_safe=only_safe, mode=mode)
    if not safety.allowed and mode == 'execute':
        return {
            'hop_index': hop_index,
            'api_id': api_id,
            'path': hop.get('path'),
            'role': hop.get('role'),
            'status': HOP_BLOCKED,
            'diagnosis': {'safety_reasons': safety.reasons},
            'executed': False,
        }

    ex = execute_test_case(
        tc, pack_dir=pack_dir, baseline_context=baseline_context,
        mode=mode, source_dir=source_dir, base_url=base_url,
    )
    if mode == 'dry-run' and ex.get('build_status') == 'ok' and not ex.get('executed'):
        return {
            'hop_index': hop_index,
            'api_id': api_id,
            'path': hop.get('path'),
            'role': hop.get('role'),
            'status': HOP_STATUS_OK,
            'test_id': tc.get('test_id'),
            'execution': ex,
            'analysis': {'call_outcome': HOP_STATUS_OK, 'dry_run_built': True},
            'diagnosis': {'dry_run': True, 'build_status': 'ok'},
            'harvested': hop.get('produces') or [],
            'executed': False,
        }

    analysis = analyze_response(ex, tc, baseline_context=baseline_context, pack_dir=pack_dir)
    outcome = analysis.get('call_outcome') or ex.get('call_outcome')

    if outcome != HOP_STATUS_OK:
        backed = try_material_backed_hop(
            hop,
            api_id=api_id,
            chain_pool=chain_pool,
            baseline_context=baseline_context,
            intake_report=intake_report,
            material_validation=material_validation,
            execution=ex,
            analysis=analysis,
        )
        if backed:
            status = HOP_SKIPPED if backed.get('material_source') == 'pool_satisfied_passthrough' else HOP_STATUS_OK
            return {
                'hop_index': hop_index,
                'api_id': api_id,
                'path': hop.get('path'),
                'role': hop.get('role'),
                'status': status,
                'test_id': tc.get('test_id'),
                'execution': ex,
                'analysis': {**analysis, 'material_backed': True},
                'diagnosis': backed,
                'harvested': hop.get('produces') or [],
                'executed': True,
            }
        status, diag = _diagnose_hop_failure(
            test_case=tc, execution=ex, template=template, missing_objects=[],
        )
        return {
            'hop_index': hop_index,
            'api_id': api_id,
            'path': hop.get('path'),
            'role': hop.get('role'),
            'status': status,
            'test_id': tc.get('test_id'),
            'execution': ex,
            'analysis': analysis,
            'diagnosis': diag,
            'executed': True,
        }

    produced = analysis.get('produced_fields') or []
    values = dict(analysis.get('produced_values') or {})
    if not values:
        values = dict(analysis.get('harvested_values') or {})
    chain_pool.harvest(api_id, produced, values)

    return {
        'hop_index': hop_index,
        'api_id': api_id,
        'path': hop.get('path'),
        'role': hop.get('role'),
        'status': HOP_STATUS_OK,
        'test_id': tc.get('test_id'),
        'execution': ex,
        'analysis': analysis,
        'harvested': produced,
        'executed': True,
    }


def run_m7_on_consumer_hop(
    hop: Dict[str, Any],
    *,
    pack_dir: Path,
    baseline_context: Dict[str, Any],
    templates_by_id: Dict[str, Dict[str, Any]],
    chain_pool: ChainObjectPool,
    chain_doc: Dict[str, Any],
    mode: str,
    source_dir: Optional[Path],
    base_url: Optional[str],
    only_safe: bool,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Run M0+M7 only on a consumer/risk hop."""
    api_id = hop.get('api_id') or ''
    template = templates_by_id.get(api_id)
    if not template:
        return [], [], []

    m0 = build_test_case(template, baseline_context=baseline_context, index=4000)
    m0['test_stage'] = 'chain_strict_m0'
    m0['mutation_type'] = 'M0'
    m0['chain_source'] = chain_doc.get('chain_source') or 'static_business_chain'
    m0['chain_hop_role'] = hop.get('role') or 'consumer'
    m0 = chain_pool.apply_to_test_case(m0, hop)

    executions: List[Dict[str, Any]] = []
    analyses: List[Dict[str, Any]] = []
    test_cases: List[Dict[str, Any]] = [m0]

    ex0 = execute_test_case(
        m0, pack_dir=pack_dir, baseline_context=baseline_context,
        mode=mode, source_dir=source_dir, base_url=base_url,
    )
    a0 = analyze_response(ex0, m0, baseline_context=baseline_context, pack_dir=pack_dir)
    executions.append(ex0)
    analyses.append(a0)

    if a0.get('call_outcome') != HOP_STATUS_OK:
        return executions, analyses, test_cases

    seed = {'api_id': api_id, 'path': hop.get('path'), 'template': template, 'seed_id': f'chain_{chain_doc.get("chain_id")}'}
    campaign = plan_intelligent_binding_campaign(
        seed, m0,
        baseline_context=baseline_context,
        object_pool={'pools': chain_pool.param_pool()},
        chain_doc=chain_doc,
        chain_strict=True,
    )
    for i, mtc in enumerate(campaign.get('test_cases') or []):
        mtc = chain_pool.apply_to_test_case(mtc, hop)
        mtc['test_stage'] = 'chain_strict_m7'
        mtc['chain_hop_role'] = hop.get('role') or 'consumer'
        mtc['chain_id'] = chain_doc.get('chain_id')
        test_cases.append(mtc)
        ex = execute_test_case(
            mtc, pack_dir=pack_dir, baseline_context=baseline_context,
            mode=mode, source_dir=source_dir, base_url=base_url,
        )
        analyses.append(analyze_response(ex, mtc, baseline_context=baseline_context, pack_dir=pack_dir))
        executions.append(ex)

    return executions, analyses, test_cases


def run_chain_strict_verification(
    pack_dir: Path,
    *,
    mode: str = 'dry-run',
    chain_id: Optional[str] = None,
    source_dir: Optional[Path] = None,
    base_url: Optional[str] = None,
    only_safe: bool = True,
    skip_preflight: bool = False,
    verbose: bool = True,
) -> Dict[str, Any]:
    """Execute one ranked business chain hop-by-hop; stop on first blocker; M7 on consumer only."""
    pack_dir = Path(pack_dir)
    consistency = validate_chain_pack_consistency(pack_dir)
    if not consistency.get('valid'):
        return {
            'status': 'blocked',
            'verdict': 'stale_chain_artifacts',
            'verify_mode': 'chain_strict',
            'consistency': consistency,
            'business_purpose': BUSINESS_PURPOSE,
        }

    baseline_context = _load_json(pack_dir / 'baseline_runtime_context.json') or {}

    if not skip_preflight:
        pf = run_replay_preflight(pack_dir, source_dir=source_dir, base_url=base_url, live_probe=False)
        write_json(pack_dir / 'replay_preflight_report.json', pf)
        if not pf.get('ready') and mode == 'execute':
            return {'status': 'preflight_blocked', 'preflight': pf, 'verdict': 'blocked', 'verify_mode': 'chain_strict'}

    chain_doc, selection_meta = select_top_ranked_chain(pack_dir, chain_id=chain_id)
    if not chain_doc:
        return {
            'status': 'blocked',
            'verdict': 'stale_chain_reference',
            'verify_mode': 'chain_strict',
            'selection': selection_meta,
            'consistency': consistency,
            'business_purpose': BUSINESS_PURPOSE,
        }

    material_validation = validate_uploaded_material_against_chain(
        pack_dir, chain_id=chain_doc.get('chain_id'),
    )

    intake_report = _load_json(pack_dir / 'baseline_intake_report.json') or {}

    tpl_doc = _load_json(pack_dir / 'materialized_api_templates.json') or {}
    templates_by_id = {t['api_id']: t for t in (tpl_doc.get('templates') or []) if t.get('api_id')}

    hops = chain_doc.get('hops') or []
    chain_pool = ChainObjectPool(chain_doc['chain_id'], static_hops=hops)
    chain_pool.seed_from_baseline(
        baseline_context, chain_doc=chain_doc, intake_report=intake_report,
    )
    hop_results: List[Dict[str, Any]] = []
    stopped = False
    stop_reason: Optional[Dict[str, Any]] = None

    if verbose:
        print(f'[MiniDrifter:chain_strict] chain={chain_doc.get("chain_id")} hops={len(hops)}', flush=True)

    for i, hop in enumerate(hops):
        skip_reason = should_skip_hop(
            hop, chain_pool, chain_doc, hop_index=i, total_hops=len(hops),
            templates_by_id=templates_by_id,
        )
        if skip_reason:
            result = skip_hop_result(hop, hop_index=i, reason=skip_reason)
        else:
            result = execute_hop(
                hop,
                pack_dir=pack_dir,
                baseline_context=baseline_context,
                templates_by_id=templates_by_id,
                chain_pool=chain_pool,
                mode=mode,
                source_dir=source_dir,
                base_url=base_url,
                only_safe=only_safe,
                hop_index=i,
                material_validation=material_validation,
                intake_report=intake_report,
            )
        hop_results.append(result)
        if verbose:
            print(
                f'[MiniDrifter:chain_strict] hop {i+1}/{len(hops)} '
                f'{result.get("path")} -> {result.get("status")}',
                flush=True,
            )
        if not is_success_status(result.get('status') or ''):
            stopped = True
            stop_reason = result.get('diagnosis') or {'status': result.get('status')}
            break

    all_executions: List[Dict[str, Any]] = []
    all_analyses: List[Dict[str, Any]] = []
    all_test_cases: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []

    if not stopped:
        consumer_hops = [
            h for h in hops
            if h.get('role') in {'consumer', 'hop'}
            and h.get('api_id') in (chain_doc.get('risk_hops') or [chain_doc.get('target_hop')])
        ]
        if not consumer_hops:
            consumer_hops = [h for h in hops if h.get('role') == 'consumer']
        if not consumer_hops and len(hops) > 1:
            consumer_hops = [hops[-1]]

        for ch in consumer_hops:
            exs, ans, tcs = run_m7_on_consumer_hop(
                ch,
                pack_dir=pack_dir,
                baseline_context=baseline_context,
                templates_by_id=templates_by_id,
                chain_pool=chain_pool,
                chain_doc=chain_doc,
                mode=mode,
                source_dir=source_dir,
                base_url=base_url,
                only_safe=only_safe,
            )
            all_executions.extend(exs)
            all_analyses.extend(ans)
            all_test_cases.extend(tcs)

        tc_by_id = {t['test_id']: t for t in all_test_cases if t.get('test_id')}
        raw_findings = adjudicate_findings(
            all_analyses, tc_by_id,
            chain_id=chain_doc.get('chain_id'),
            seed_api_id=chain_doc.get('entry_api'),
            baseline_context=baseline_context,
            pack_dir=pack_dir,
            chain_doc=chain_doc,
        )
        findings.extend(raw_findings)

    registry = FindingRegistry()
    registry.ingest(findings)
    if all_analyses and all_test_cases:
        registry.apply_lifecycle_rules(all_analyses, {t['test_id']: t for t in all_test_cases})

    primary = [f for f in registry.all_findings() if f.get('finding_tier') in {FINDING_F2, FINDING_F3}]
    f1_aux = [f for f in registry.all_findings() if f.get('finding_tier') == FINDING_F1]

    diff_export_paths: List[str] = []
    try:
        from minidrifter.verification.binding_diff_exporter import (
            export_diffs_for_findings,
            export_m0_m7_diffs_from_executions,
        )
        if all_test_cases and all_executions:
            m0_m7_paths = export_m0_m7_diffs_from_executions(
                pack_dir,
                test_cases=all_test_cases,
                executions=all_executions,
                analyses=all_analyses,
                chain_doc=chain_doc,
                baseline_context=baseline_context,
                findings=registry.all_findings(),
            )
            diff_export_paths.extend(str(p) for p in m0_m7_paths)
        paths = export_diffs_for_findings(
            pack_dir, registry.all_findings(),
            test_cases=all_test_cases,
            executions=all_executions,
            analyses=all_analyses,
            chain_doc=chain_doc,
            baseline_context=baseline_context,
        )
        diff_export_paths.extend(str(p) for p in paths)
        diff_export_paths = sorted(set(diff_export_paths))
        primary = [f for f in registry.all_findings() if f.get('finding_tier') in {FINDING_F2, FINDING_F3}]
    except Exception:
        pass

    verdict = (
        chain_verdict_from_findings(primary) if primary and not stopped
        else 'chain_blocked' if stopped
        else 'chain_completed_no_drift'
    )
    seeded = bool(chain_pool.objects)
    entry_blocked = (
        stopped
        and hop_results
        and hop_results[0].get('status') in {HOP_TEMPLATE_UNMATERIALIZED, HOP_MISSING_OBJECT}
        and not seeded
    )
    if entry_blocked:
        wait_doc = _waiting_for_entry_capture_payload(
            chain_doc,
            material_validation=material_validation,
            hop_result=hop_results[0],
        )
        verdict = wait_doc['verdict']

    report = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'run_id': consistency.get('run_id'),
        'verify_mode': 'chain_strict',
        'business_purpose': BUSINESS_PURPOSE,
        'no_bfs_fallback': True,
        'consistency': consistency,
        'selection': selection_meta,
        'chain_id': chain_doc.get('chain_id'),
        'chain_type': chain_doc.get('chain_type'),
        'entry_path': chain_doc.get('entry_path'),
        'target_path': chain_doc.get('target_path'),
        'material_validation': material_validation,
        'chain_object_pool': chain_pool.to_dict(),
        'hop_results': hop_results,
        'stopped_early': stopped,
        'stop_reason': stop_reason,
        'findings': registry.all_findings(),
        'primary_findings': primary,
        'auxiliary_findings': f1_aux,
        'binding_evidence_diff_exports': diff_export_paths,
        'verdict': verdict,
    }
    if verdict == 'waiting_for_entry_capture':
        report['next_action'] = _waiting_for_entry_capture_payload(
            chain_doc,
            material_validation=material_validation,
            hop_result=hop_results[0] if hop_results else None,
        )

    write_json(pack_dir / 'chain_strict_report.json', report)

    trace = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'chain_id': chain_doc.get('chain_id'),
        'entry_path': chain_doc.get('entry_path'),
        'target_path': chain_doc.get('target_path'),
        'mode': mode,
        'hop_results': [
            {
                'hop_index': h.get('hop_index'),
                'api_id': h.get('api_id'),
                'path': h.get('path'),
                'role': h.get('role'),
                'status': h.get('status'),
                'executed': h.get('executed'),
                'harvested': h.get('harvested'),
                'diagnosis': h.get('diagnosis'),
                'oracle': (h.get('analysis') or {}).get('call_outcome'),
            }
            for h in hop_results
        ],
        'stopped_early': stopped,
        'stop_reason': stop_reason,
        'object_pool': chain_pool.to_dict(),
    }
    write_json(pack_dir / 'chain_strict_trace.json', trace)

    m7_results = []
    for tc, ex, ana in zip(all_test_cases, all_executions, all_analyses):
        if tc.get('test_stage') != 'chain_strict_m7':
            continue
        m7_results.append({
            'test_id': tc.get('test_id'),
            'api_id': tc.get('api_id'),
            'path': tc.get('path'),
            'mutation_field': tc.get('mutation_field') or tc.get('mutated_field'),
            'chain_hop_role': tc.get('chain_hop_role'),
            'call_outcome': ana.get('call_outcome') or ex.get('call_outcome'),
            'oracle_verdict': ana.get('verdict') or ana.get('binding_verdict'),
            'business_success': ana.get('call_outcome') == HOP_STATUS_OK,
        })
    write_json(pack_dir / 'consumer_m7_results.json', {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'chain_id': chain_doc.get('chain_id'),
        'results': m7_results,
        'count': len(m7_results),
    })

    binding_verdict = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'run_id': consistency.get('run_id'),
        'chain_id': chain_doc.get('chain_id'),
        'selected_from_current_rank_plan': selection_meta.get('selected_from_current_rank_plan'),
        'chain_id_exists_in_business_chains': selection_meta.get('chain_id_exists_in_business_chains'),
        'verdict': report['verdict'],
        'stopped_early': stopped,
        'stop_reason': stop_reason,
        'primary_findings': primary,
        'findings_summary': registry.summary(),
        'material_validation': material_validation,
    }
    write_json(pack_dir / 'binding_verdict.json', binding_verdict)

    write_json(pack_dir / 'finding_registry.json', registry.to_document())
    if registry.all_findings():
        findings_path = pack_dir / 'findings.jsonl'
        with findings_path.open('w', encoding='utf-8') as fh:
            for row in registry.all_findings():
                fh.write(json.dumps(row, ensure_ascii=False) + '\n')

    session_doc = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'search_mode': 'chain_strict',
        'verify_mode': 'chain_strict',
        'status': 'completed' if not stopped else 'stopped',
        'verdict': report['verdict'],
        'stop_reason': stop_reason,
        'chain_id': chain_doc.get('chain_id'),
        'coverage': {
            'http_calls': len(all_executions) + sum(1 for h in hop_results if h.get('executed')),
            'chain_hops_completed': sum(1 for h in hop_results if is_success_status(h.get('status') or '')),
            'chain_hops_total': len(hops),
            'findings_confirmed': sum(1 for f in primary if f.get('status') == 'confirmed'),
            'findings_hypothesis': sum(1 for f in primary if f.get('status') == 'hypothesis'),
        },
        'finding_lifecycle': registry.summary(),
    }
    write_json(pack_dir / 'search_session.json', session_doc)

    write_json(pack_dir / 'chain_object_pool.json', chain_pool.to_dict())
    (pack_dir / 'chain_intake_prompt.md').write_text(render_chain_intake_prompt(pack_dir), encoding='utf-8')
    write_json(pack_dir / 'chain_intake_checklist.json', build_chain_intake_checklist(pack_dir))

    return {
        'status': 'completed' if not stopped else 'stopped',
        'verdict': report['verdict'],
        'verify_mode': 'chain_strict',
        'search_mode': 'chain_strict',
        'chain_strict_report': str(pack_dir / 'chain_strict_report.json'),
        'chain_strict_trace': str(pack_dir / 'chain_strict_trace.json'),
        'consumer_m7_results': str(pack_dir / 'consumer_m7_results.json'),
        'binding_evidence_diff_exports': diff_export_paths,
        'binding_verdict': str(pack_dir / 'binding_verdict.json'),
        'findings_summary': registry.summary(),
        'executive_summary': _executive_summary(report),
        'coverage': {
            'http_calls': len(all_executions) + sum(1 for h in hop_results if h.get('executed')),
            'chain_hops_completed': sum(1 for h in hop_results if is_success_status(h.get('status') or '')),
            'chain_hops_total': len(hops),
            'findings_confirmed': sum(1 for f in primary if f.get('status') == 'confirmed'),
            'findings_hypothesis': sum(1 for f in primary if f.get('status') == 'hypothesis'),
        },
        'search_session': {
            'search_mode': 'chain_strict',
            'verify_mode': 'chain_strict',
            'status': 'completed' if not stopped else 'stopped',
            'stop_reason': stop_reason,
            'coverage': report,
        },
    }


def _executive_summary(report: Dict[str, Any]) -> str:
    hops_ok = sum(1 for h in report.get('hop_results') or [] if is_success_status(h.get('status') or ''))
    hops_total = len(report.get('hop_results') or [])
    primary = len(report.get('primary_findings') or [])
    if report.get('stopped_early'):
        reason = (report.get('stop_reason') or {}).get('status', 'blocked')
        return f'Chain-strict stopped at hop {hops_ok}/{hops_total}: {reason}. Primary findings: {primary}.'
    return f'Chain-strict completed {hops_ok}/{hops_total} hops. Primary F2/F3 findings: {primary}.'
