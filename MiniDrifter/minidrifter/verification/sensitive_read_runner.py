# -*- coding: utf-8 -*-
"""Sensitive read campaign — M0 sensitive state reads without object-flow chain."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.business_chain.chain_run_context import load_json
from minidrifter.classification.api_plane_classifier import plane_index_by_path
from minidrifter.core.utils import write_json
from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.verification.campaign_planner import build_test_case
from minidrifter.verification.safety_policy import evaluate_test_safety
from minidrifter.verification.sensitive_replay_context_builder import SENSITIVE_READ_ROLES
from minidrifter.verification.sensitive_replay_executor import (
    ensure_sensitive_replay_context,
    replay_sensitive_api,
)
from minidrifter.verification.sensitive_target_enrollment import enroll_intake_sensitive_targets

SENSITIVE_READ_ROLES = SENSITIVE_READ_ROLES  # re-export


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def select_sensitive_read_targets(
    pack_dir: Path,
    *,
    covered_paths: Set[str],
    max_reads: int,
    baseline_context: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Pick sensitive-plane APIs from static index + baseline intake enrollment."""
    pack_dir = Path(pack_dir)
    baseline_context = baseline_context or load_json(pack_dir / 'baseline_runtime_context.json') or {}
    idx = plane_index_by_path(pack_dir)
    tpl_doc = load_json(pack_dir / 'materialized_api_templates.json') or {}
    ready = {
        normalize_api_path(t.get('path') or ''): t
        for t in (tpl_doc.get('ready_for_replay') or [])
        if t.get('status') == 'materialized_with_crypto_profile'
    }
    ready.update({
        normalize_api_path(t.get('path') or ''): t
        for t in (tpl_doc.get('templates') or [])
        if t.get('api_id')
    })

    candidates: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    for path, entry in idx.items():
        role = entry.get('recommended_campaign_role') or ''
        if role not in SENSITIVE_READ_ROLES:
            continue
        if 'action_operation' in (entry.get('planes') or []):
            if entry.get('side_effect') in {'S2_state_changing', 'S3_destructive', 'write', 'state_changing'}:
                continue
        norm = normalize_api_path(path)
        if norm in covered_paths or norm in seen:
            continue
        tpl = ready.get(norm)
        if not tpl:
            continue
        seen.add(norm)
        sens = float(entry.get('sensitivity_score') or 0.5)
        candidates.append({
            'api_id': entry.get('api_id') or tpl.get('api_id'),
            'path': entry.get('path') or tpl.get('path'),
            'rule_score': sens * 100,
            'combined_score': sens * 100,
            'campaign_role': role,
            'primary_plane': entry.get('primary_plane'),
            'planes': entry.get('planes') or [],
            'materialized': True,
            'replay_ready': True,
            'probe_eligible': True,
            'verification_intent': 'sensitive_read_state',
        })

    for cand in enroll_intake_sensitive_targets(
        pack_dir,
        covered_paths=covered_paths,
        seen=seen,
        baseline_context=baseline_context,
    ):
        norm = normalize_api_path(cand.get('path') or '')
        if norm in seen:
            continue
        seen.add(norm)
        candidates.append(cand)

    candidates.sort(key=lambda x: -float(x.get('combined_score') or 0))
    return candidates[:max_reads]


def run_sensitive_read_batch(
    pack_dir: Path,
    *,
    covered_paths: Set[str],
    mode: str = 'dry-run',
    max_reads: int = 12,
    max_http: int = 60,
    source_dir: Optional[Path] = None,
    base_url: Optional[str] = None,
    only_safe: bool = True,
    subject_override: bool = True,
    max_subject_override: int = 3,
    verbose: bool = False,
) -> Dict[str, Any]:
    """Execute read_sensitive_state targets with replay context alignment (P4-fix-4)."""
    pack_dir = Path(pack_dir)
    baseline_context = load_json(pack_dir / 'baseline_runtime_context.json') or {}
    tpl_doc = load_json(pack_dir / 'materialized_api_templates.json') or {}
    templates_by_id = {
        t['api_id']: t for t in (tpl_doc.get('templates') or []) if t.get('api_id')
    }

    selected = select_sensitive_read_targets(
        pack_dir,
        covered_paths=covered_paths,
        max_reads=max_reads,
        baseline_context=baseline_context,
    )
    for cand in selected:
        synth = cand.get('synthetic_template')
        if synth and cand.get('api_id'):
            templates_by_id[cand['api_id']] = synth

    replay_context_doc = ensure_sensitive_replay_context(pack_dir)
    results: List[Dict[str, Any]] = []
    http_used = 0

    if verbose:
        print(
            f'[MiniDrifter:sensitive_read] selected={len(selected)} budget={max_http} mode={mode}',
            flush=True,
        )

    for i, cand in enumerate(selected):
        if http_used >= max_http:
            break
        if verbose:
            print(
                f'[MiniDrifter:sensitive_read] {i+1}/{len(selected)} '
                f'role={cand.get("campaign_role")} path={cand.get("path")} '
                f'intake={bool(cand.get("intake_enrolled"))}',
                flush=True,
            )

        api_id = cand.get('api_id') or ''
        template = templates_by_id.get(api_id)
        if template and mode == 'execute':
            safety = evaluate_test_safety(
                build_test_case(template, baseline_context=baseline_context, index=9000),
                baseline_context=baseline_context,
                only_safe=only_safe,
                mode=mode,
            )
            if not safety.allowed:
                results.append({
                    'api_id': api_id,
                    'path': cand.get('path'),
                    'status': 'safety_blocked',
                    'm0_outcome': 'safety_blocked',
                    'http_calls': 0,
                    'safety_reasons': safety.reasons,
                    'campaign_role': cand.get('campaign_role'),
                    'primary_plane': cand.get('primary_plane'),
                    'intake_enrolled': cand.get('intake_enrolled'),
                })
                continue

        row = replay_sensitive_api(
            cand,
            pack_dir=pack_dir,
            baseline_context=baseline_context,
            templates_by_id=templates_by_id,
            mode=mode,
            source_dir=source_dir,
            base_url=base_url,
            probe_role='sensitive_read',
            replay_context_doc=replay_context_doc,
        )
        row['campaign_role'] = cand.get('campaign_role')
        row['primary_plane'] = cand.get('primary_plane')
        row['verification_intent'] = 'sensitive_read_state'
        row['intake_enrolled'] = cand.get('intake_enrolled')
        calls = row.get('http_calls') or 0
        if http_used + calls > max_http and mode == 'execute':
            row['status'] = 'budget_exhausted'
            results.append(row)
            break
        http_used += calls
        results.append(row)

    subject_override_doc: Dict[str, Any] = {'results': [], 'http_calls_total': 0, 'subject_override': {}}
    if subject_override and results and http_used < max_http:
        from minidrifter.classification.subject_wire_candidate_miner import mine_subject_wire_candidates
        from minidrifter.verification.subject_override_runner import run_subject_override_batch

        mine_subject_wire_candidates(pack_dir, write=True)
        from minidrifter.classification.subject_wire_gap_planner import build_subject_wire_gap_plan
        build_subject_wire_gap_plan(pack_dir, write=True)
        subject_override_doc = run_subject_override_batch(
            pack_dir,
            results,
            templates_by_id=templates_by_id,
            mode=mode,
            max_targets=max_subject_override,
            max_http=max_http - http_used,
            source_dir=source_dir,
            base_url=base_url,
            verbose=verbose,
        )
        http_used += subject_override_doc.get('http_calls_total') or 0

    mutation_tested = sum(1 for r in results if r.get('sensitive_mutation_tested'))
    mutation_tested += sum(
        1 for r in (subject_override_doc.get('results') or []) if r.get('sensitive_mutation_tested')
    )
    subject_override_attempted = sum(
        1 for r in (subject_override_doc.get('results') or []) if r.get('subject_override_attempted')
    )

    doc = {
        'schema_version': '1.3.0',
        'generated_at': _utc_now(),
        'verify_mode': 'sensitive_read',
        'max_reads': max_reads,
        'max_http': max_http,
        'http_calls_total': http_used,
        'reads_run': len(results),
        'intake_enrolled_count': sum(1 for r in results if r.get('intake_enrolled')),
        'sensitive_read_m0_success': sum(1 for r in results if r.get('sensitive_read_m0_success')),
        'live_sensitive_read_m0_success': sum(1 for r in results if r.get('live_sensitive_read_m0_success')),
        'baseline_sensitive_read_m0_success': sum(1 for r in results if r.get('baseline_sensitive_read_m0_success')),
        'replay_failed_but_baseline_valid': sum(1 for r in results if r.get('replay_failed_but_baseline_valid')),
        'sensitive_read_m7_success': sum(1 for r in results if r.get('sensitive_read_m7_success')),
        'sensitive_mutation_tested': mutation_tested,
        'subject_override_attempted': subject_override_attempted,
        'subject_override': subject_override_doc.get('subject_override') or {},
        'subject_override_results': subject_override_doc.get('results') or [],
        'results': results,
    }
    write_json(pack_dir / 'sensitive_read_report.json', doc)
    return doc
