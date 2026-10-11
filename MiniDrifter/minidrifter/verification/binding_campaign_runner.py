# -*- coding: utf-8 -*-
"""Unified binding campaign — orchestrate M0/M7 eligibility and final evidence reports."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.business_chain.chain_run_context import load_json
from minidrifter.classification.object_wire_candidate_miner import mine_object_wire_candidates
from minidrifter.classification.subject_wire_candidate_miner import mine_subject_wire_candidates
from minidrifter.core.utils import write_json
from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.verification.mutation_eligibility import (
    CAPABILITY_LAYERS,
    ELIGIBILITY_MUTATION_ALLOWED,
    evaluate_mutation_eligibility,
    security_conclusion_from_m7,
)
from minidrifter.verification.reporting.sensitive_binding_coverage import (
    PRIORITY_TARGETS,
    _collect_target_paths,
    _subject_candidate_rows,
    _target_rank,
    build_sensitive_api_coverage_records,
)
from minidrifter.verification.sensitive_replay_context_builder import (
    write_sensitive_replay_context,
)


SCHEMA_VERSION = '1.0.0'


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except json.JSONDecodeError:
        return None


def _index_by_path(rows: List[Dict[str, Any]], key: str = 'path') -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        p = normalize_api_path(row.get(key) or row.get('api') or '')
        if p:
            out[p] = row
    return out


def _signature_profile_summary(
    doc: Optional[Dict[str, Any]],
    pack_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    crypto = _load_json(Path(pack_dir) / 'crypto_static_profile.json') if pack_dir else None
    crypto = crypto if isinstance(crypto, dict) else {}
    crypto_can = bool(crypto.get('can_replay'))
    mined_can = (doc or {}).get('can_recompute_signature')
    effective_can = mined_can is True or crypto_can
    if not doc and not crypto_can:
        return {'found': False, 'can_recompute_signature': None, 'reason': 'not_mined'}
    reason = (doc or {}).get('reason') or ('not_mined' if not doc else None)
    if crypto_can and mined_can is not True:
        reason = 'crypto_static_profile_can_replay'
    return {
        'found': bool((doc or {}).get('signature_profile_id') or (doc or {}).get('static_evidence') or crypto_can),
        'profile_id': (doc or {}).get('signature_profile_id') or crypto.get('profile_id'),
        'can_recompute_signature': effective_can,
        'crypto_static_can_replay': crypto_can,
        'confidence': (doc or {}).get('confidence'),
        'reason': reason,
    }


def rebuild_binding_campaign_artifacts(pack_dir: Path) -> None:
    """Force-regenerate replay context and wire miners (avoids stale can_recompute flags)."""
    pack_dir = Path(pack_dir)
    from minidrifter.classification.subject_wire_gap_planner import build_subject_wire_gap_plan
    from minidrifter.verification.sensitive_replay_context_builder import write_sensitive_replay_context

    build_subject_wire_gap_plan(pack_dir, write=True)
    write_sensitive_replay_context(pack_dir)
    mine_subject_wire_candidates(pack_dir, write=True)
    mine_object_wire_candidates(pack_dir, write=True)
    try:
        from minidrifter.verification.cats.synthesizer import write_binding_test_plans
        write_binding_test_plans(pack_dir, limit=120)
    except Exception:
        pass


def _m0_status_from_row(cov: Dict[str, Any], m0_row: Optional[Dict[str, Any]]) -> str:
    if cov.get('replay_coverage_status'):
        return str(cov['replay_coverage_status'])
    if m0_row:
        if m0_row.get('ok'):
            return str(m0_row.get('replay_strategy') or 'live_m0_success')
        return str(m0_row.get('status') or 'm0_failed')
    return 'no_capture'


def _oracle_from_subject_override(so_row: Optional[Dict[str, Any]]) -> Optional[str]:
    if not so_row:
        return None
    st = str(so_row.get('subject_override_status') or so_row.get('status') or '')
    if st == 'subject_override_accepted_sensitive':
        return 'cross_subject_sensitive_success'
    if st in {'subject_override_accepted_no_sensitive', 'subject_override_ignored'}:
        return 'backend_rejected_or_self_bound'
    if st == 'subject_override_blocked':
        return 'backend_rejected_or_self_bound'
    return st or None


def _pick_primary_mutation(
    subject_elig: Dict[str, Any],
    object_elig: Dict[str, Any],
) -> Dict[str, Any]:
    if subject_elig.get('eligible'):
        return subject_elig
    if object_elig.get('eligible'):
        return object_elig
    if subject_elig.get('subject_candidates'):
        return subject_elig
    return subject_elig


def build_final_binding_records(pack_dir: Path) -> List[Dict[str, Any]]:
    pack_dir = Path(pack_dir)
    coverage_rows = build_sensitive_api_coverage_records(pack_dir)
    cov_by_path = _index_by_path(coverage_rows, 'static_path')

    replay_doc = _load_json(pack_dir / 'sensitive_replay_context.json') or {}
    replay_by_path = replay_doc.get('by_path') or _index_by_path(replay_doc.get('entries') or [], 'api')
    wire_doc = _load_json(pack_dir / 'subject_wire_candidates.json') or {}
    obj_doc = _load_json(pack_dir / 'object_wire_candidates.json') or {}
    sr_doc = _load_json(pack_dir / 'sensitive_read_report.json') or {}
    so_doc = _load_json(pack_dir / 'subject_override_report.json') or {}
    sig_doc = _load_json(pack_dir / 'signature_profile.json') or {}
    sig_summary = _signature_profile_summary(sig_doc, pack_dir)

    wire_by_path = _index_by_path(wire_doc.get('candidates') or [])
    obj_by_path = _index_by_path(obj_doc.get('candidates') or [])
    m0_by_path = _index_by_path(sr_doc.get('results') or [])
    so_by_path = _index_by_path(so_doc.get('results') or [])
    baseline_context = load_json(pack_dir / 'baseline_runtime_context.json') or {}

    paths = _collect_target_paths(pack_dir)
    if not paths:
        paths = list(cov_by_path.keys())

    records: List[Dict[str, Any]] = []
    for path in paths:
        norm = normalize_api_path(path)
        cov = cov_by_path.get(norm) or {}
        replay_entry = replay_by_path.get(norm) or {}
        replay_ctx = replay_entry.get('replay_context') or replay_entry
        m0_row = m0_by_path.get(norm)
        so_row = so_by_path.get(norm)
        wire_row = wire_by_path.get(norm)
        obj_row = obj_by_path.get(norm)

        subject_elig = evaluate_mutation_eligibility(
            api=path,
            mutation_type='subject_override',
            replay_context=replay_ctx,
            signature_profile=sig_doc,
            subject_wire_row=wire_row,
            object_wire_row=obj_row,
            m0_result=m0_row,
            baseline_context=baseline_context,
            pack_dir=pack_dir,
        )
        object_elig = evaluate_mutation_eligibility(
            api=path,
            mutation_type='object_override',
            replay_context=replay_ctx,
            signature_profile=sig_doc,
            subject_wire_row=wire_row,
            object_wire_row=obj_row,
            m0_result=m0_row,
            baseline_context=baseline_context,
            pack_dir=pack_dir,
        )
        read_elig = evaluate_mutation_eligibility(
            api=path,
            mutation_type='credential_bound_read',
            replay_context=replay_ctx,
            signature_profile=sig_doc,
            subject_wire_row=wire_row,
            object_wire_row=obj_row,
            m0_result=m0_row,
            baseline_context=baseline_context,
            pack_dir=pack_dir,
        )

        primary = _pick_primary_mutation(subject_elig, object_elig)
        m7_status = 'not_executed'
        oracle_result = None
        if so_row:
            st = str(so_row.get('subject_override_status') or so_row.get('status') or '')
            if st in {'dry_run_planned', 'dry_run_planned_signature_bound'}:
                m7_status = 'dry_run_planned'
            elif st in {'skipped_signature_bound'}:
                m7_status = 'not_executed'
            elif so_row.get('subject_override_attempted') or so_row.get('sensitive_mutation_tested'):
                m7_status = 'executed'
                oracle_result = _oracle_from_subject_override(so_row)

        conclusion = security_conclusion_from_m7(
            eligibility=primary,
            m7_status=m7_status,
            oracle_result=oracle_result,
        )
        if conclusion == 'not_tested' and cov.get('security_conclusion'):
            conclusion = str(cov['security_conclusion'])

        records.append({
            'api': path,
            'rank': cov.get('target_rank') or _target_rank(path, cov.get('business_label') or ''),
            'business_label': cov.get('business_label') or cov.get('business_label_human'),
            'static_recovered': bool(cov.get('static_identified', True)),
            'baseline_matched': bool(cov.get('capture_matched')),
            'match_type': cov.get('match_type'),
            'replay_mode': replay_ctx.get('replay_mode'),
            'm0_status': _m0_status_from_row(cov, m0_row),
            'sensitive_evidence_observed': bool(cov.get('sensitive_response_observed')),
            'subject_candidates': subject_elig.get('subject_candidates') or [
                f.get('field') for f in _subject_candidate_rows(wire_row) if f.get('field')
            ],
            'object_candidates': object_elig.get('object_candidates') or (obj_row or {}).get('object_field_names') or [],
            'signature_profile': sig_summary,
            'mutation_eligibility': primary.get('eligibility_status'),
            'mutation_types': {
                'subject_override': subject_elig,
                'object_override': object_elig,
                'credential_bound_read': read_elig,
            },
            'm7_status': m7_status,
            'mutation_type': primary.get('mutation_type') if primary.get('eligible') else (
                'subject_override' if subject_elig.get('subject_candidates') else primary.get('mutation_type')
            ),
            'oracle_result': oracle_result,
            'security_conclusion': conclusion,
            'block_reason': primary.get('reason') if m7_status == 'not_executed' else None,
        })
    return records


def _summarize_records(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    hist_elig: Dict[str, int] = {}
    hist_conclusion: Dict[str, int] = {}
    m7_executed = 0
    m0_ok = 0
    for r in records:
        elig = str(r.get('mutation_eligibility') or 'unknown')
        hist_elig[elig] = hist_elig.get(elig, 0) + 1
        con = str(r.get('security_conclusion') or 'not_tested')
        hist_conclusion[con] = hist_conclusion.get(con, 0) + 1
        if r.get('m7_status') == 'executed':
            m7_executed += 1
        if str(r.get('m0_status') or '').endswith('success') or 'm0_success' in str(r.get('m0_status') or ''):
            m0_ok += 1
        elif str(r.get('m0_status') or '') in {'capture_exact_matched', 'live_m0_success', 'baseline_m0_success'}:
            m0_ok += 1
    return {
        'api_count': len(records),
        'm0_success_count': m0_ok,
        'm7_executed_count': m7_executed,
        'mutation_eligibility_histogram': hist_elig,
        'security_conclusion_histogram': hist_conclusion,
        'drift_count': hist_conclusion.get('drift', 0),
        'clean_count': hist_conclusion.get('clean', 0),
        'inconclusive_count': hist_conclusion.get('inconclusive', 0),
        'not_tested_count': hist_conclusion.get('not_tested', 0),
    }


def _render_final_binding_md(doc: Dict[str, Any]) -> str:
    lines = [
        '# MiniDrifter Final Binding Report',
        '',
        f"**生成时间**：{doc.get('generated_at')}",
        '',
        '## 能力边界（P0）',
        '',
        '| 层 | 职责 |',
        '|---|---|',
        '| static_recovery | API / 参数 / wrapper / 敏感目标 |',
        '| m0_replay | 原样回放 |',
        '| m7_mutation | subject/object 变异（条件满足才执行） |',
        '| conclusion | drift / clean / inconclusive |',
        '',
        '## 总览',
        '',
    ]
    summary = doc.get('summary') or {}
    lines.append(
        f"- API 数：**{summary.get('api_count', 0)}** · "
        f"M0 成功：**{summary.get('m0_success_count', 0)}** · "
        f"M7 已执行：**{summary.get('m7_executed_count', 0)}**"
    )
    lines.append(
        f"- drift / clean / inconclusive / not_tested："
        f"**{summary.get('drift_count', 0)}** / "
        f"**{summary.get('clean_count', 0)}** / "
        f"**{summary.get('inconclusive_count', 0)}** / "
        f"**{summary.get('not_tested_count', 0)}**"
    )
    lines.extend(['', '## 可测性分布', ''])
    for k, v in sorted((summary.get('mutation_eligibility_histogram') or {}).items()):
        lines.append(f'- `{k}`: {v}')
    lines.extend(['', '## API 记录', '', '| Rank | API | M0 | 可测性 | M7 | 结论 | 阻塞 |', '|---|---|---|---|---|---|---|'])
    for r in doc.get('records') or []:
        lines.append(
            f"| {r.get('rank', '—')} | `{r.get('api', '')}` | {r.get('m0_status', '—')} | "
            f"{r.get('mutation_eligibility', '—')} | {r.get('m7_status', '—')} | "
            f"{r.get('security_conclusion', '—')} | {r.get('block_reason') or '—'} |"
        )
    lines.append('')
    return '\n'.join(lines)


def _render_campaign_md(doc: Dict[str, Any]) -> str:
    lines = [
        '# MiniDrifter Binding Campaign Report',
        '',
        f"**生成时间**：{doc.get('generated_at')}",
        f"**模式**：{doc.get('mode')}",
        '',
        '## RQ 指标快照',
        '',
    ]
    rq = doc.get('rq_metrics') or {}
    for key, val in rq.items():
        lines.append(f'- **{key}**: {val}')
    lines.extend(['', '> 详细 per-API 记录见 `final_binding_report.md`', ''])
    return '\n'.join(lines)


def run_binding_campaign(
    pack_dir: Path,
    *,
    mode: str = 'safe',
    source_dir: Optional[Path] = None,
    run_m7: bool = False,
    max_targets: int = 10,
    max_http: int = 30,
    base_url: Optional[str] = None,
) -> Dict[str, Any]:
    """Orchestrate binding campaign from existing artifacts + optional M7 execute."""
    pack_dir = Path(pack_dir)
    execute_m7 = run_m7 or mode == 'execute'

    rebuild_binding_campaign_artifacts(pack_dir)

    if execute_m7:
        from minidrifter.verification.sensitive_target_enrollment import (
            enroll_gap_plan_sensitive_targets,
            enroll_intake_sensitive_targets,
            enroll_path_inferred_sensitive_targets,
        )
        from minidrifter.verification.sensitive_read_runner import run_sensitive_read_batch
        from minidrifter.verification.subject_override_runner import run_subject_override_batch
        from minidrifter.verification.template_registry import register_enrollment_templates

        sr = load_json(pack_dir / 'sensitive_read_report.json') or {}
        if not sr.get('results'):
            run_sensitive_read_batch(
                pack_dir,
                covered_paths=set(),
                mode='execute',
                max_reads=max(max_targets, 12),
                max_http=max_http,
                source_dir=source_dir,
                base_url=base_url,
                subject_override=False,
                verbose=False,
            )
            sr = load_json(pack_dir / 'sensitive_read_report.json') or {}

        tpl_doc = load_json(pack_dir / 'materialized_api_templates.json') or {}
        templates_by_id = {
            t['api_id']: t for t in (tpl_doc.get('templates') or []) if t.get('api_id')
        }
        baseline = load_json(pack_dir / 'baseline_runtime_context.json') or {}
        seen_paths: set[str] = set()
        enrolled_rows: list = []
        for enroll_fn, kwargs in (
            (enroll_intake_sensitive_targets, {'pack_dir': pack_dir, 'covered_paths': set(), 'seen': seen_paths, 'baseline_context': baseline}),
            (enroll_gap_plan_sensitive_targets, {'pack_dir': pack_dir, 'covered_paths': set(), 'seen': seen_paths, 'baseline_context': baseline, 'templates_by_id': templates_by_id}),
            (enroll_path_inferred_sensitive_targets, {'pack_dir': pack_dir, 'covered_paths': set(), 'seen': seen_paths, 'baseline_context': baseline, 'templates_by_id': templates_by_id}),
        ):
            for cand in enroll_fn(**kwargs):
                enrolled_rows.append(cand)
        templates_by_id = register_enrollment_templates(templates_by_id, enrolled_rows)
        run_subject_override_batch(
            pack_dir,
            sr.get('results') or [],
            templates_by_id=templates_by_id,
            mode='execute' if execute_m7 else 'dry-run',
            max_targets=max_targets,
            max_http=max_http,
            source_dir=source_dir,
            base_url=base_url,
        )

    records = build_final_binding_records(pack_dir)
    summary = _summarize_records(records)

    subject_with_wire = sum(1 for r in records if r.get('subject_candidates'))
    object_with_wire = sum(1 for r in records if r.get('object_candidates'))
    sig_blocked = summary.get('mutation_eligibility_histogram', {}).get('signature_bound_skip', 0)

    rq_metrics = {
        'api_recovery_targets': summary.get('api_count'),
        'm0_success_rate': round(summary.get('m0_success_count', 0) / max(summary.get('api_count', 1), 1), 4),
        'subject_candidate_discovery_rate': round(subject_with_wire / max(summary.get('api_count', 1), 1), 4),
        'object_candidate_discovery_rate': round(object_with_wire / max(summary.get('api_count', 1), 1), 4),
        'signature_bound_skip_count': sig_blocked,
        'm7_executed_count': summary.get('m7_executed_count'),
        'drift_count': summary.get('drift_count'),
    }

    final_doc = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'capability_layers': list(CAPABILITY_LAYERS),
        'summary': summary,
        'records': records,
    }
    campaign_doc = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': final_doc['generated_at'],
        'pack_dir': str(pack_dir),
        'mode': mode,
        'm7_executed': execute_m7,
        'capability_layers': list(CAPABILITY_LAYERS),
        'rq_metrics': rq_metrics,
        'summary': summary,
        'final_binding_report': 'final_binding_report.json',
    }

    write_json(pack_dir / 'final_binding_report.json', final_doc)
    (pack_dir / 'final_binding_report.md').write_text(
        _render_final_binding_md(final_doc), encoding='utf-8',
    )
    write_json(pack_dir / 'binding_campaign_report.json', campaign_doc)
    (pack_dir / 'binding_campaign_report.md').write_text(
        _render_campaign_md(campaign_doc), encoding='utf-8',
    )

    return {
        'final_binding_report': str(pack_dir / 'final_binding_report.json'),
        'binding_campaign_report': str(pack_dir / 'binding_campaign_report.json'),
        'summary': summary,
        'rq_metrics': rq_metrics,
    }


def write_binding_campaign_reports(pack_dir: Path, **kwargs: Any) -> Dict[str, Any]:
    return run_binding_campaign(pack_dir, **kwargs)
