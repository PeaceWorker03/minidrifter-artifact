# -*- coding: utf-8 -*-
"""Per-API sensitive binding coverage — replay / testability / security conclusion."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.classification.api_plane_classifier import (
    classify_path_to_plane_entry,
    plane_index_by_path,
)
from minidrifter.core.utils import write_json
from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.verification.sensitive_api_oracle import analyze_sensitive_response

SCHEMA_VERSION = '1.0.0'

# --- Replay Coverage (layer 1) ---
REPLAY_COVERAGE_STATUSES = frozenset({
    'no_capture',
    'capture_exact_matched',
    'capture_fallback_matched',
    'synthetic_template_only',
    'live_m0_success',
    'baseline_m0_success',
    'm0_failed',
})

# --- Binding Testability (layer 2) ---
BINDING_TESTABILITY_STATUSES = frozenset({
    'no_subject_candidate',
    'subject_candidate_found',
    'mutation_dry_run_planned',
    'mutation_executed',
    'signature_bound_skip',
    'safety_gate_skip',
    'missing_material_skip',
})

# --- Security Conclusion (layer 3) ---
SECURITY_CONCLUSION_STATUSES = frozenset({
    'drift',
    'clean',
    'inconclusive',
    'not_tested',
})

PRIORITY_TARGETS: Tuple[Tuple[str, str, str], ...] = (
    ('P1', 'personalcore', 'user_profile_personal_info'),
    ('P2', 'address/list', 'contact_address_invoice'),
    ('P3', 'remain/money', 'account_state_wallet'),
    ('P4', 'submit/api', 'action_operation'),
)

M7_STATUS_MAP = {
    'skipped_signature_bound': 'signature_bound_skip',
    'dry_run_planned_signature_bound': 'signature_bound_skip',
    'dry_run_planned': 'mutation_dry_run_planned',
    'subject_override_blocked': 'mutation_executed',
    'subject_override_accepted_sensitive': 'mutation_executed',
    'subject_override_accepted_no_sensitive': 'mutation_executed',
    'subject_override_ignored': 'mutation_executed',
    'subject_override_inconclusive': 'mutation_executed',
    'subject_override_invalid_test': 'mutation_executed',
    'subject_override_skipped': 'no_subject_candidate',
    'no_wire_subject_field': 'no_subject_candidate',
    'safety_blocked': 'safety_gate_skip',
    'mutation_blocked': 'missing_material_skip',
    'm0_failed': 'missing_material_skip',
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def _index_by_path(rows: List[Dict[str, Any]], key: str = 'path') -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        p = row.get(key) or row.get('api') or ''
        norm = normalize_api_path(p)
        if norm:
            out[norm] = row
    return out


def _target_rank(path: str, plane: str) -> str:
    low = normalize_api_path(path)
    for rank, token, expected_plane in PRIORITY_TARGETS:
        if token in low:
            return rank
    if plane == 'user_profile_personal_info':
        return 'P1'
    if plane == 'contact_address_invoice':
        return 'P2'
    if plane == 'account_state_wallet':
        return 'P3'
    if plane == 'action_operation':
        return 'P4'
    return 'P5'


def _baseline_capture_for_path(
    intake: Dict[str, Any],
    path: str,
) -> Optional[Dict[str, Any]]:
    norm = normalize_api_path(path)
    best: Optional[Dict[str, Any]] = None
    for cap in intake.get('captures') or []:
        if normalize_api_path(cap.get('path') or '') != norm:
            continue
        if not str(cap.get('overall_status') or '').startswith('acceptable'):
            continue
        if not best:
            best = cap
            continue
        if (cap.get('response_crypto_processing') or {}).get('body_json') and not (
            best.get('response_crypto_processing') or {}
        ).get('body_json'):
            best = cap
    return best


def _capture_match_type(
    static_path: str,
    capture_path: Optional[str],
    match_score: float,
) -> Tuple[str, bool]:
    if not capture_path:
        return 'no_capture', False
    if normalize_api_path(capture_path) == normalize_api_path(static_path):
        return 'exact', True
    if match_score >= 1000:
        return 'exact', True
    if match_score >= 35:
        return 'fallback', True
    return 'fallback', True


def _replay_coverage_status(
    *,
    capture_matched: bool,
    match_type: str,
    m0_row: Optional[Dict[str, Any]],
    baseline_sensitive: bool,
    live_business_ok: bool,
) -> str:
    if not capture_matched:
        if m0_row and m0_row.get('intake_enrolled'):
            return 'synthetic_template_only'
        return 'no_capture'
    if match_type == 'exact':
        pre = 'capture_exact_matched'
    else:
        pre = 'capture_fallback_matched'

    if m0_row:
        if m0_row.get('live_sensitive_read_m0_success'):
            return 'live_m0_success'
        if m0_row.get('baseline_sensitive_read_m0_success') or baseline_sensitive:
            return 'baseline_m0_success'
        if live_business_ok or m0_row.get('m0_outcome') == 'business_success':
            return 'live_m0_success' if m0_row.get('status') == 'live_m0_success' else pre
        if str(m0_row.get('m0_outcome') or '') in {'business_success', 'hop_ok'}:
            return 'live_m0_success'
        if m0_row.get('status') == 'safety_blocked':
            return pre
        return 'm0_failed'
    return pre


def _binding_testability_status(
    *,
    subject_fields: List[Dict[str, Any]],
    so_row: Optional[Dict[str, Any]],
    m0_row: Optional[Dict[str, Any]],
    replay_meta: Dict[str, Any],
    plane: str,
) -> Tuple[str, Optional[str]]:
    if so_row:
        st = so_row.get('subject_override_status') or so_row.get('status') or ''
        mapped = M7_STATUS_MAP.get(st)
        if mapped:
            block = so_row.get('reason')
            if mapped == 'signature_bound_skip':
                block = block or 'signature_not_recomputable'
            return mapped, block
        if so_row.get('subject_override_inconclusive'):
            return 'signature_bound_skip', so_row.get('reason') or 'signature_not_recomputable'

    if m0_row and m0_row.get('status') == 'safety_blocked':
        return 'safety_gate_skip', ';'.join(m0_row.get('safety_reasons') or []) or 'safety_policy'

    if not subject_fields:
        return 'no_subject_candidate', 'no_wire_subject_field'

    if replay_meta.get('can_recompute_signature') is False:
        return 'signature_bound_skip', 'signature_not_recomputable'

    if plane == 'action_operation':
        return 'safety_gate_skip', 'action_operation_safety_gated'

    return 'subject_candidate_found', None


def _security_conclusion(
    *,
    binding_testability: str,
    so_row: Optional[Dict[str, Any]],
    m0_row: Optional[Dict[str, Any]],
    replay_coverage: str,
) -> str:
    if so_row:
        st = so_row.get('subject_override_status') or ''
        if st == 'subject_override_accepted_sensitive' and so_row.get('high_risk_candidate'):
            return 'drift'
        if st in {
            'subject_override_blocked',
            'subject_override_accepted_no_sensitive',
            'subject_override_ignored',
        }:
            return 'clean'
        if st in {'subject_override_inconclusive', 'skipped_signature_bound'}:
            return 'inconclusive'
        if st == 'subject_override_invalid_test':
            return 'inconclusive'

    if binding_testability in {
        'signature_bound_skip',
        'safety_gate_skip',
        'missing_material_skip',
        'mutation_dry_run_planned',
    }:
        return 'inconclusive'

    if binding_testability == 'mutation_executed':
        if so_row and so_row.get('high_risk_candidate'):
            return 'drift'
        if so_row and so_row.get('subject_override_status') == 'subject_override_accepted_sensitive':
            return 'drift'
        return 'clean'

    if replay_coverage in {'no_capture', 'synthetic_template_only', 'm0_failed'}:
        return 'not_tested'

    if binding_testability == 'no_subject_candidate':
        return 'not_tested'

    if binding_testability == 'subject_candidate_found':
        return 'not_tested'

    return 'inconclusive'


def _subject_candidate_rows(wire_row: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not wire_row:
        return []
    out: List[Dict[str, Any]] = []
    for f in wire_row.get('wire_subject_fields') or []:
        out.append({
            'field': f.get('field'),
            'location': f.get('location'),
            'value_present': f.get('value_sample') not in (None, '', '***'),
            'mutation_allowed': f.get('mutation_allowed'),
            'signature_covered': f.get('signature_covered', 'unknown'),
        })
    return out


def _collect_target_paths(pack_dir: Path) -> List[str]:
    paths: Set[str] = set()
    idx = plane_index_by_path(pack_dir)
    for path, entry in idx.items():
        role = entry.get('recommended_campaign_role') or ''
        plane = entry.get('primary_plane') or ''
        if role in {
            'read_sensitive_state', 'account_state_probe',
            'verification_state_probe', 'address_invoice_probe',
        } or plane in {
            'user_profile_personal_info', 'account_state_wallet',
            'contact_address_invoice', 'realname_verification',
        }:
            paths.add(path)

    replay_doc = _load_json(pack_dir / 'sensitive_replay_context.json') or {}
    for entry in replay_doc.get('entries') or []:
        if entry.get('api'):
            paths.add(entry['api'])

    wire_doc = _load_json(pack_dir / 'subject_wire_candidates.json') or {}
    for cand in wire_doc.get('candidates') or []:
        if cand.get('path'):
            paths.add(cand['path'])

    sr_doc = _load_json(pack_dir / 'sensitive_read_report.json') or {}
    for row in sr_doc.get('results') or []:
        if row.get('path'):
            paths.add(row['path'])

    ranked: List[str] = []
    for rank, token, _ in PRIORITY_TARGETS:
        for p in sorted(paths):
            if token in normalize_api_path(p) and p not in ranked:
                ranked.append(p)
    for p in sorted(paths):
        if p not in ranked:
            ranked.append(p)
    return ranked


def build_sensitive_api_coverage_records(pack_dir: Path) -> List[Dict[str, Any]]:
    """Build per-sensitive-API coverage rows from existing OUTPUT artifacts only."""
    pack_dir = Path(pack_dir)
    intake = _load_json(pack_dir / 'baseline_intake_report.json') or {}
    replay_doc = _load_json(pack_dir / 'sensitive_replay_context.json') or {}
    wire_doc = _load_json(pack_dir / 'subject_wire_candidates.json') or {}
    sr_doc = _load_json(pack_dir / 'sensitive_read_report.json') or {}
    so_doc = _load_json(pack_dir / 'subject_override_report.json') or {}
    tpl_doc = _load_json(pack_dir / 'materialized_api_templates.json') or {}

    replay_by_path = replay_doc.get('by_path') or _index_by_path(replay_doc.get('entries') or [], 'api')
    wire_by_path = _index_by_path(wire_doc.get('candidates') or [])
    m0_by_path = _index_by_path(sr_doc.get('results') or [])
    so_by_path = _index_by_path(so_doc.get('results') or [])

    templates_by_path = {
        normalize_api_path(t.get('path') or ''): t
        for t in (tpl_doc.get('templates') or []) if t.get('path')
    }

    records: List[Dict[str, Any]] = []
    for path in _collect_target_paths(pack_dir):
        norm = normalize_api_path(path)
        entry = plane_index_by_path(pack_dir).get(norm) or classify_path_to_plane_entry(path)
        plane = entry.get('primary_plane') or ''
        replay_entry = replay_by_path.get(norm) or {}
        replay_ctx = replay_entry.get('replay_context') or {}
        m0_row = m0_by_path.get(norm)
        so_row = so_by_path.get(norm)
        wire_row = wire_by_path.get(norm)
        tpl = templates_by_path.get(norm)
        cap = _baseline_capture_for_path(intake, path)

        capture_path = replay_entry.get('capture_path') or (cap.get('path') if cap else None)
        match_score = float(replay_entry.get('capture_match_score') or 0)
        match_type, capture_matched = _capture_match_type(path, capture_path, match_score)

        baseline_body = (cap.get('response_crypto_processing') or {}).get('body_json') if cap else None
        baseline_sens = analyze_sensitive_response(path=path, body=baseline_body) if baseline_body else {}
        live_business_ok = bool(
            m0_row and str(m0_row.get('m0_outcome') or '') == 'business_success'
        )

        replay_coverage = _replay_coverage_status(
            capture_matched=capture_matched,
            match_type=match_type,
            m0_row=m0_row,
            baseline_sensitive=bool(baseline_sens.get('has_sensitive')),
            live_business_ok=live_business_ok,
        )

        replay_meta = {
            'replay_mode': replay_entry.get('replay_mode') or replay_ctx.get('replay_mode'),
            'signature_mode': replay_entry.get('signature_mode') or replay_ctx.get('signature_mode'),
            'can_recompute_signature': replay_entry.get('can_recompute_signature', replay_ctx.get('can_recompute_signature')),
            'mutation_policy': replay_entry.get('mutation_policy') or replay_ctx.get('mutation_policy'),
        }

        subject_fields = _subject_candidate_rows(wire_row)
        binding_testability, block_reason = _binding_testability_status(
            subject_fields=subject_fields,
            so_row=so_row,
            m0_row=m0_row,
            replay_meta=replay_meta,
            plane=plane,
        )

        security = _security_conclusion(
            binding_testability=binding_testability,
            so_row=so_row,
            m0_row=m0_row,
            replay_coverage=replay_coverage,
        )

        m0_status = m0_row.get('status') if m0_row else replay_coverage
        if m0_row and m0_row.get('live_sensitive_read_m0_success'):
            m0_status = 'live_m0_success'
        elif m0_row and m0_row.get('baseline_sensitive_read_m0_success'):
            m0_status = 'baseline_m0_success'
        elif baseline_sens.get('has_sensitive') and live_business_ok:
            m0_status = 'baseline_m0_success'

        sens_fields = list(m0_row.get('sensitive_field_reads') or []) if m0_row else []
        if not sens_fields and baseline_sens.get('sensitive_fields'):
            sens_fields = baseline_sens.get('sensitive_fields') or []

        sensitive_observed = bool(
            (m0_row or {}).get('sensitive_read_m0_success')
            or (m0_row or {}).get('live_sensitive_read_m0_success')
            or baseline_sens.get('has_sensitive')
        )

        m7_status = binding_testability
        if binding_testability == 'mutation_dry_run_planned':
            m7_status = 'mutation_dry_run_planned'
        elif binding_testability == 'signature_bound_skip':
            m7_status = 'signature_bound_skip'
            if block_reason in {
                None, 'mutation_not_safe_without_signature_recompute',
            }:
                block_reason = 'signature_not_recomputable'

        static_identified = bool(entry.get('primary_plane') or tpl or cap)

        records.append({
            'api_id': (
                (m0_row or {}).get('api_id')
                or (wire_row or {}).get('api_id')
                or (tpl or {}).get('api_id')
                or replay_entry.get('api_id')
            ),
            'target_rank': _target_rank(path, plane),
            'business_label': plane,
            'business_label_human': entry.get('primary_plane_label') or plane,
            'method': (
                replay_ctx.get('http_method')
                or (cap or {}).get('method')
                or (tpl or {}).get('method')
                or 'GET'
            ),
            'static_path': path,
            'static_identified': static_identified,
            'materialized': bool(tpl),
            'campaign_role': entry.get('recommended_campaign_role'),

            'capture_matched': capture_matched,
            'capture_path': capture_path,
            'match_type': match_type,
            'capture_match_score': match_score,
            'baseline_capture_id': replay_entry.get('capture_index') or (cap or {}).get('capture_index'),
            'baseline_capture_index': replay_entry.get('capture_index') or (cap or {}).get('capture_index'),

            'replay_mode': replay_meta.get('replay_mode'),
            'signature_mode': replay_meta.get('signature_mode'),
            'can_recompute_signature': replay_meta.get('can_recompute_signature'),
            'mutation_policy': replay_meta.get('mutation_policy'),
            'replay_coverage_status': replay_coverage,

            'm0_status': m0_status,
            'business_status': (m0_row or {}).get('m0_outcome'),
            'replay_strategy': (m0_row or {}).get('replay_strategy'),
            'sensitive_response_observed': sensitive_observed,
            'sensitive_fields': sens_fields[:24],
            'baseline_sensitive_fields': baseline_sens.get('sensitive_fields') or [],

            'subject_candidates': subject_fields,
            'binding_testability_status': binding_testability,

            'm7_status': m7_status,
            'security_conclusion': security,
            'block_reason': block_reason,
            'subject_override_status': (so_row or {}).get('subject_override_status'),
        })

    records.sort(key=lambda r: (r.get('target_rank') or 'P9', r.get('static_path') or ''))
    deduped: List[Dict[str, Any]] = []
    seen_norm: Set[str] = set()
    for row in records:
        norm = normalize_api_path(row.get('static_path') or '')
        if norm in seen_norm:
            continue
        seen_norm.add(norm)
        deduped.append(row)
    return deduped


def summarize_sensitive_api_coverage(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    replay_hist: Dict[str, int] = {}
    test_hist: Dict[str, int] = {}
    sec_hist: Dict[str, int] = {}
    for row in records:
        rc = row.get('replay_coverage_status') or 'unknown'
        replay_hist[rc] = replay_hist.get(rc, 0) + 1
        bt = row.get('binding_testability_status') or 'unknown'
        test_hist[bt] = test_hist.get(bt, 0) + 1
        sc = row.get('security_conclusion') or 'unknown'
        sec_hist[sc] = sec_hist.get(sc, 0) + 1

    return {
        'api_count': len(records),
        'live_m0_success': sum(1 for r in records if r.get('m0_status') == 'live_m0_success'),
        'baseline_m0_success': sum(1 for r in records if r.get('m0_status') == 'baseline_m0_success'),
        'signature_bound_skip': sum(
            1 for r in records if r.get('m7_status') == 'signature_bound_skip'
        ),
        'subject_override_attempted': sum(
            1 for r in records if r.get('subject_override_status')
        ),
        'subject_override_inconclusive': sum(
            1 for r in records if r.get('security_conclusion') == 'inconclusive'
        ),
        'drift': sum(1 for r in records if r.get('security_conclusion') == 'drift'),
        'clean': sum(1 for r in records if r.get('security_conclusion') == 'clean'),
        'not_tested': sum(1 for r in records if r.get('security_conclusion') == 'not_tested'),
        'replay_coverage_histogram': replay_hist,
        'binding_testability_histogram': test_hist,
        'security_conclusion_histogram': sec_hist,
    }


def build_sensitive_binding_coverage_report(pack_dir: Path) -> Dict[str, Any]:
    """Aggregate sensitive API experiment status from existing OUTPUT artifacts."""
    pack_dir = Path(pack_dir)
    records = build_sensitive_api_coverage_records(pack_dir)
    summary = summarize_sensitive_api_coverage(records)
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'status_enums': {
            'replay_coverage': sorted(REPLAY_COVERAGE_STATUSES),
            'binding_testability': sorted(BINDING_TESTABILITY_STATUSES),
            'security_conclusion': sorted(SECURITY_CONCLUSION_STATUSES),
        },
        'summary': summary,
        'records': records,
    }


def write_sensitive_binding_coverage_report(pack_dir: Path) -> Path:
    pack_dir = Path(pack_dir)
    doc = build_sensitive_binding_coverage_report(pack_dir)
    out = pack_dir / 'sensitive_binding_coverage_report.json'
    write_json(out, doc)
    md_path = pack_dir / 'sensitive_binding_coverage_report.md'
    md_path.write_text(_render_sensitive_coverage_md(doc), encoding='utf-8')
    return out


def _render_sensitive_coverage_md(doc: Dict[str, Any]) -> str:
    summary = doc.get('summary') or {}
    lines = [
        '# Sensitive Binding Coverage Report',
        '',
        f"**Generated**: {doc.get('generated_at', '')}",
        '',
        '## Summary',
        '',
        f"- APIs tracked: **{summary.get('api_count', 0)}**",
        f"- Live M0 success: **{summary.get('live_m0_success', 0)}**",
        f"- Baseline M0 success: **{summary.get('baseline_m0_success', 0)}**",
        f"- Signature-bound skip: **{summary.get('signature_bound_skip', 0)}**",
        f"- Security inconclusive: **{summary.get('subject_override_inconclusive', 0)}**",
        f"- Drift / clean / not tested: **{summary.get('drift', 0)}** / "
        f"**{summary.get('clean', 0)}** / **{summary.get('not_tested', 0)}**",
        '',
        '> This report aggregates existing artifacts only — no new HTTP requests.',
        '',
        '## Per-API Coverage',
        '',
        '| Rank | API | Replay | M0 | Sensitive | M7 testability | Conclusion | Block reason |',
        '|---|---|---|---|---|---|---|---|',
    ]
    for row in doc.get('records') or []:
        sens = '✓' if row.get('sensitive_response_observed') else '—'
        lines.append(
            f"| {row.get('target_rank', '—')} | `{row.get('static_path', '—')}` | "
            f"{row.get('replay_coverage_status', '—')} | {row.get('m0_status', '—')} | {sens} | "
            f"{row.get('binding_testability_status', '—')} | {row.get('security_conclusion', '—')} | "
            f"{row.get('block_reason') or '—'} |"
        )
    lines.append('')
    return '\n'.join(lines)
