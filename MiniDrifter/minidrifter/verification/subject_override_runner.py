# -*- coding: utf-8 -*-
"""P4-fix-5 — subject override batch runner (M0 + M7-subject pair)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.business_chain.chain_run_context import load_json
from minidrifter.core.utils import stable_id, write_json
from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.verification.executor import execute_test_case
from minidrifter.verification.request_builder import baseline_pool, build_request_preview
from minidrifter.verification.response_oracle import analyze_response
from minidrifter.verification.mutation_eligibility import can_recompute_or_replay_signature
from minidrifter.verification.sensitive_replay_context_builder import lookup_replay_context
from minidrifter.verification.sensitive_replay_executor import (
    ensure_sensitive_replay_context,
    replay_sensitive_m0_for_override,
    _merged_baseline_context,
)
from minidrifter.verification.subject_override_mutation import (
    build_subject_mutation_plan,
    build_subject_mutation_plans,
)
from minidrifter.verification.subject_override_oracle import (
    classify_subject_override,
    summarize_subject_override_batch,
)
from minidrifter.verification.subject_override_target_selector import (
    select_subject_override_target,
    select_subject_override_targets,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _enrich_cats_pool(pool: Dict[str, Any], pack_dir: Path) -> Dict[str, Any]:
    """Merge runtime pools and optional authorized seeds for CATS candidate resolution."""
    merged = dict(pool or {})
    subj = load_json(pack_dir / 'subject_pool.json') or {}
    for field_key, entries in (subj.get('fields') or {}).items():
        for i, ent in enumerate(entries or []):
            val = (ent or {}).get('value')
            if val not in (None, ''):
                merged[f'{field_key}__pool_{i}'] = str(val)
    obj = load_json(pack_dir / 'object_pool.json') or {}
    for field_key, entries in (obj.get('fields') or {}).items():
        for i, ent in enumerate(entries or []):
            val = (ent or {}).get('value')
            if val not in (None, ''):
                merged[f'{field_key}__obj_{i}'] = str(val)
    seeds_doc = load_json(pack_dir / 'cats_authorized_seeds.json') or {}
    for key, val in (seeds_doc.get('seeds') or {}).items():
        if val not in (None, ''):
            merged[str(key)] = str(val)
    if seeds_doc.get('member_id_seed'):
        merged['authorized_member_id_seed'] = str(seeds_doc['member_id_seed'])
    return merged


def _oracle_plan_for_target(
    pack_dir: Path,
    *,
    path: str,
    plane: Optional[str],
    binding_plan: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if binding_plan and binding_plan.get('oracle'):
        return binding_plan['oracle']
    if plane == 'user_profile_personal_info':
        return {
            'type': 'sensitive_content_fingerprint',
            'fields': ['identityInfo', 'drivingLicenceInfo', 'memberName', 'decodeNo'],
            'empty_response_policy': 'invalid_mutant_no_evidence',
        }
    return None


def _export_subject_diff(
    pack_dir: Path,
    *,
    path: str,
    subject_field: str,
    oracle: Dict[str, Any],
    m0_test_case: Dict[str, Any],
    m7_test_case: Dict[str, Any],
    m0_execution: Dict[str, Any],
    m7_execution: Dict[str, Any],
) -> str:
    fid = stable_id('so', normalize_api_path(path), subject_field)[:16]
    out_dir = pack_dir / 'subject_override_diff' / fid
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'path': path,
        'subject_field': subject_field,
        'subject_override_status': oracle.get('status'),
        'evidence_grade': oracle.get('evidence_grade'),
        'high_risk_candidate': oracle.get('high_risk_candidate'),
        'wire_changed_fields': oracle.get('wire_changed_fields'),
        'credential_anchor_same': oracle.get('credential_anchor_same'),
        'reason_codes': oracle.get('reason_codes'),
        'request_diff': oracle.get('request_diff'),
        'm0_outcome': oracle.get('m0_outcome'),
        'm7_outcome': oracle.get('m7_outcome'),
        'm0_sensitive_read': oracle.get('m0_sensitive_read'),
        'm7_sensitive_read': oracle.get('m7_sensitive_read'),
    }
    write_json(out_dir / 'summary.json', summary)
    return str(out_dir)


def run_subject_override_one(
    target: Dict[str, Any],
    *,
    pack_dir: Path,
    baseline_context: Dict[str, Any],
    templates_by_id: Dict[str, Dict[str, Any]],
    mode: str = 'execute',
    source_dir: Optional[Path] = None,
    base_url: Optional[str] = None,
    replay_context_doc: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Execute M0 + M7-subject for one pilot API."""
    path = target.get('api') or ''
    api_id = target.get('api_id') or ''
    template = templates_by_id.get(api_id)
    sens_row = target.get('sensitive_read_row') or {}
    cand = {
        'api_id': api_id,
        'path': path,
        'campaign_role': target.get('campaign_role'),
        'primary_plane': target.get('plane'),
    }

    m0 = replay_sensitive_m0_for_override(
        cand,
        pack_dir=pack_dir,
        baseline_context=baseline_context,
        templates_by_id=templates_by_id,
        mode=mode,
        source_dir=source_dir,
        base_url=base_url,
        preferred_strategy=sens_row.get('replay_strategy'),
        replay_context_doc=replay_context_doc,
    )
    http_calls = int(m0.get('http_calls') or 0)
    if not m0.get('ok'):
        return {
            'path': path,
            'api_id': api_id,
            'plane': target.get('plane'),
            'subject_override_status': 'subject_override_invalid_test',
            'status': 'm0_failed',
            'http_calls': http_calls,
            'reason': m0.get('reason'),
        }

    m0_tc = m0['test_case']
    m0_ex = m0['execution']
    m0_an = m0['analysis']

    replay_entry = lookup_replay_context(pack_dir, path, context_doc=replay_context_doc) or {}
    merged_context = _merged_baseline_context(baseline_context, replay_entry)
    replay_inner = replay_entry.get('replay_context') or replay_entry
    sig_doc = load_json(pack_dir / 'signature_profile.json') or {}
    can_recompute = can_recompute_or_replay_signature(
        replay_inner,
        sig_doc,
        baseline_context,
        pack_dir=pack_dir,
    )
    replay_mode = replay_inner.get('replay_mode') or replay_entry.get('replay_mode')
    has_sig = bool(
        str(replay_inner.get('signature_mode') or '') == 'reuse_capture_signature'
        or (replay_inner.get('query') or {}).get('signature')
        or (replay_inner.get('query') or {}).get('sign')
        or (replay_inner.get('body') or {}).get('signature')
        or (replay_inner.get('body') or {}).get('sign')
        or (replay_inner.get('headers') or {}).get('Sign')
        or (replay_inner.get('headers') or {}).get('sign')
    )
    signature_bound = has_sig and not can_recompute and replay_mode == 'plaintext_direct'

    enriched_target = select_subject_override_target(
        path,
        pack_dir=pack_dir,
        template=template,
        sensitive_read_row=sens_row,
        test_case=m0_tc,
        execution=m0_ex,
    ) or target
    if not enriched_target.get('selected_field'):
        return {
            'path': path,
            'api_id': api_id,
            'plane': target.get('plane'),
            'subject_override_status': 'subject_override_skipped',
            'status': 'no_wire_subject_field',
            'http_calls': http_calls,
            'reason': 'no_subject_identifier_on_m0_wire',
            'subject_override_attempted': True,
            'sensitive_mutation_tested': False,
        }

    pool = _enrich_cats_pool(
        baseline_pool(merged_context), pack_dir,
    )
    pool.update(load_json(pack_dir / 'aggregate_materials.json').get('fields') or {})

    from minidrifter.verification.cats.synthesizer import lookup_plan_for_path
    binding_plan = lookup_plan_for_path(pack_dir, path)
    oracle_plan = _oracle_plan_for_target(
        pack_dir, path=path, plane=target.get('plane'), binding_plan=binding_plan,
    )

    mutation_plans = build_subject_mutation_plans(
        enriched_target, m0_tc,
        baseline_context=merged_context,
        pool=pool,
        binding_test_plan=binding_plan,
        replay_entry=replay_entry,
    )
    if not mutation_plans:
        plan = build_subject_mutation_plan(
            enriched_target, m0_tc, baseline_context=merged_context, pool=pool,
            replay_entry=replay_entry,
        )
        if plan.get('status') != 'ready':
            return {
                'path': path,
                'api_id': api_id,
                'plane': target.get('plane'),
                'subject_field': enriched_target.get('selected_field'),
                'subject_override_status': 'subject_override_invalid_test',
                'status': 'mutation_blocked',
                'http_calls': http_calls,
                'reason': plan.get('reason'),
            }
        mutation_plans = [plan]

    if signature_bound:
        first = mutation_plans[0]
        sig_row = {
            'path': path,
            'api_id': api_id,
            'plane': target.get('plane'),
            'subject_field': first.get('field') or enriched_target.get('selected_field'),
            'replay_mode': replay_inner.get('replay_mode'),
            'signature_mode': replay_inner.get('signature_mode'),
            'mutation_policy': replay_inner.get('mutation_policy'),
            'm0_outcome': m0_an.get('call_outcome'),
            'm0_sensitive_read': m0_an.get('sensitive_read'),
            'http_calls': http_calls,
            'subject_override_attempted': True,
            'subject_override_inconclusive': True,
            'reason': 'mutation_not_safe_without_signature_recompute',
            'cats_plan_id': (binding_plan or {}).get('plan_id'),
            'cats_cases_planned': len(mutation_plans),
        }
        if mode != 'execute':
            sig_row.update({
                'subject_override_status': 'dry_run_planned_signature_bound',
                'status': 'dry_run_planned',
                'mutation_strategy': first.get('strategy'),
            })
            return sig_row
        sig_row.update({
            'subject_override_status': 'skipped_signature_bound',
            'status': 'skipped_signature_bound',
            'sensitive_mutation_tested': False,
        })
        return sig_row

    if mode != 'execute':
        first = mutation_plans[0]
        return {
            'path': path,
            'api_id': api_id,
            'plane': target.get('plane'),
            'subject_field': first.get('field'),
            'subject_override_status': 'dry_run_planned',
            'status': 'dry_run_planned',
            'http_calls': http_calls + len(mutation_plans),
            'mutation_strategy': first.get('strategy'),
            'cats_plan_id': (binding_plan or {}).get('plan_id'),
            'cats_cases_planned': len(mutation_plans),
            'cats_candidate_policies': [
                p.get('strategy') for p in mutation_plans
            ],
        }

    last_oracle: Dict[str, Any] = {}
    last_plan: Dict[str, Any] = {}
    last_m7_tc: Dict[str, Any] = {}
    last_m7_ex: Dict[str, Any] = {}
    last_m7_an: Dict[str, Any] = {}
    attempt_log: List[Dict[str, Any]] = []

    for plan in mutation_plans:
        m7_tc = plan['m7_test_case']
        preflight_preview = build_request_preview(
            m7_tc, pack_dir=pack_dir, baseline_context=merged_context,
            source_dir=source_dir, replay_entry=replay_entry,
        )
        from minidrifter.runtime.crypto.registry import get_crypto_engine_for_pack
        from minidrifter.verification.crypto_parity_preflight import check_crypto_parity_preflight
        engine, _cap = get_crypto_engine_for_pack(pack_dir, source_dir=source_dir)
        preflight = check_crypto_parity_preflight(
            preflight_preview,
            binding_field=plan.get('field'),
            expected_binding_value=str(plan.get('mutated_value') or ''),
            engine=engine,
        )
        if not preflight.get('ok'):
            attempt_log.append({
                'strategy': plan.get('strategy'),
                'mutated_value_redacted': '***',
                'status': 'subject_override_inconclusive',
                'reason_codes': ['crypto_parity_failed', *preflight.get('reasons', [])],
            })
            last_oracle = {
                'status': 'subject_override_inconclusive',
                'evidence_grade': 'C_inconclusive',
                'high_risk_candidate': False,
                'reason_codes': ['crypto_parity_failed'],
            }
            last_plan = plan
            continue

        m7_ex = execute_test_case(
            m7_tc, pack_dir=pack_dir, baseline_context=merged_context,
            mode=mode, source_dir=source_dir, base_url=base_url,
        )
        m7_an = analyze_response(m7_ex, m7_tc, baseline_context=merged_context, pack_dir=pack_dir)
        http_calls += 1

        oracle = classify_subject_override(
            path=path,
            subject_field=plan['field'],
            m0_test_case=m0_tc,
            m7_test_case=m7_tc,
            m0_execution=m0_ex,
            m7_execution=m7_ex,
            m0_analysis=m0_an,
            m7_analysis=m7_an,
            mutation_plan=plan,
            oracle_plan=oracle_plan,
            crypto_preflight=preflight,
        )
        attempt_log.append({
            'strategy': plan.get('strategy'),
            'mutated_value_redacted': '***',
            'status': oracle.get('status'),
            'reason_codes': oracle.get('reason_codes'),
        })
        last_oracle = oracle
        last_plan = plan
        last_m7_tc = m7_tc
        last_m7_ex = m7_ex
        last_m7_an = m7_an

        if oracle.get('status') == 'subject_override_accepted_sensitive':
            break
        if oracle.get('status') not in {
            'subject_override_inconclusive',
            'subject_override_ignored',
        }:
            break

    diff_path = _export_subject_diff(
        pack_dir,
        path=path,
        subject_field=last_plan.get('field') or enriched_target.get('selected_field'),
        oracle=last_oracle,
        m0_test_case=m0_tc,
        m7_test_case=last_m7_tc,
        m0_execution=m0_ex,
        m7_execution=last_m7_ex,
    )

    return {
        'path': path,
        'api_id': api_id,
        'plane': target.get('plane'),
        'subject_field': last_plan.get('field'),
        'mutation_strategy': last_plan.get('strategy'),
        'cats_plan_id': (binding_plan or {}).get('plan_id'),
        'cats_attempts': attempt_log,
        'cats_cases_executed': len(attempt_log),
        'subject_override_status': last_oracle.get('status'),
        'evidence_grade': last_oracle.get('evidence_grade'),
        'high_risk_candidate': last_oracle.get('high_risk_candidate'),
        'wire_mutation_valid': bool(last_oracle.get('anchor_mutated_on_wire')),
        'wire_changed_fields': last_oracle.get('wire_changed_fields'),
        'credential_anchor_same': last_oracle.get('credential_anchor_same'),
        'm0_sensitive_read': last_oracle.get('m0_sensitive_read'),
        'm7_sensitive_read': last_oracle.get('m7_sensitive_read'),
        'm0_outcome': last_oracle.get('m0_outcome'),
        'm7_outcome': last_oracle.get('m7_outcome'),
        'reason_codes': last_oracle.get('reason_codes'),
        'evidence_diff_path': diff_path,
        'http_calls': http_calls,
        'sensitive_mutation_tested': True,
        'subject_override_attempted': True,
        'subject_override_sensitive_success': last_oracle.get('status') == 'subject_override_accepted_sensitive',
        'status': last_oracle.get('status'),
    }


def run_subject_override_batch(
    pack_dir: Path,
    sensitive_read_results: List[Dict[str, Any]],
    *,
    templates_by_id: Dict[str, Dict[str, Any]],
    mode: str = 'dry-run',
    max_targets: int = 3,
    max_http: int = 20,
    source_dir: Optional[Path] = None,
    base_url: Optional[str] = None,
    verbose: bool = False,
) -> Dict[str, Any]:
    """C2_subject_override — pilot subject mutation on live-M0-sensitive APIs."""
    pack_dir = Path(pack_dir)
    baseline_context = load_json(pack_dir / 'baseline_runtime_context.json') or {}
    from minidrifter.verification.binding_campaign_runner import rebuild_binding_campaign_artifacts
    rebuild_binding_campaign_artifacts(pack_dir)
    replay_context_doc = load_json(pack_dir / 'sensitive_replay_context.json') or {}

    targets = select_subject_override_targets(
        pack_dir, sensitive_read_results, templates_by_id=templates_by_id, max_targets=max_targets,
    )
    # Enroll intake / gap-plan / path-inferred synthetic templates referenced by sensitive read rows.
    from minidrifter.verification.sensitive_target_enrollment import (
        enroll_gap_plan_sensitive_targets,
        enroll_intake_sensitive_targets,
        enroll_path_inferred_sensitive_targets,
    )

    baseline_context_pre = load_json(pack_dir / 'baseline_runtime_context.json') or {}
    seen_enroll: set[str] = set()
    for enroll_fn in (
        enroll_intake_sensitive_targets,
        enroll_gap_plan_sensitive_targets,
        enroll_path_inferred_sensitive_targets,
    ):
        enroll_kwargs: Dict[str, Any] = {
            'pack_dir': pack_dir,
            'covered_paths': set(),
            'seen': seen_enroll,
            'baseline_context': baseline_context_pre,
        }
        if enroll_fn is not enroll_intake_sensitive_targets:
            enroll_kwargs['templates_by_id'] = templates_by_id
        for cand in enroll_fn(**enroll_kwargs):
            if cand.get('api_id') and cand.get('synthetic_template'):
                templates_by_id[cand['api_id']] = cand['synthetic_template']
    for row in sensitive_read_results:
        aid = row.get('api_id') or ''
        if aid in templates_by_id:
            continue
        for cand in enroll_intake_sensitive_targets(
            pack_dir, covered_paths=set(), seen=set(), baseline_context=baseline_context_pre,
        ):
            if cand.get('api_id') == aid and cand.get('synthetic_template'):
                templates_by_id[aid] = cand['synthetic_template']
                break

    results: List[Dict[str, Any]] = []
    http_used = 0

    if verbose:
        print(
            f'[MiniDrifter:subject_override] targets={len(targets)} budget={max_http} mode={mode}',
            flush=True,
        )

    for i, target in enumerate(targets):
        if http_used >= max_http:
            break
        if verbose:
            print(
                f'[MiniDrifter:subject_override] {i+1}/{len(targets)} '
                f'path={target.get("api")} field={target.get("selected_field")}',
                flush=True,
            )
        row = run_subject_override_one(
            target,
            pack_dir=pack_dir,
            baseline_context=baseline_context,
            templates_by_id=templates_by_id,
            mode=mode,
            source_dir=source_dir,
            base_url=base_url,
            replay_context_doc=replay_context_doc,
        )
        calls = row.get('http_calls') or 0
        if http_used + calls > max_http and mode == 'execute':
            row['status'] = 'budget_exhausted'
            results.append(row)
            break
        http_used += calls
        results.append(row)

    summary = summarize_subject_override_batch(results)
    summary['targets_detected'] = len(targets)

    doc = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'verify_mode': 'subject_override',
        'max_targets': max_targets,
        'max_http': max_http,
        'http_calls_total': http_used,
        'results': results,
        'subject_override': summary,
    }
    write_json(pack_dir / 'subject_override_report.json', doc)
    return doc
