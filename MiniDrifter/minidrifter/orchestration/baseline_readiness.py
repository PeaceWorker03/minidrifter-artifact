# -*- coding: utf-8 -*-
"""baseline_readiness_report.json — L0-L5 funnel snapshot for a pack."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.business_chain.chain_run_context import load_json
from minidrifter.core.utils import write_json
from minidrifter.materials.intake_param_hints import normalize_api_path

SCHEMA_VERSION = '1.0.0'

FAILURE_BUCKETS = (
    'no_capture',
    'no_subject_candidate',
    'signature_bound_skip',
    'm0_failed',
    'validation_error',
    'auth_expired',
    'not_tested',
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _count_failure_reasons(records: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {k: 0 for k in FAILURE_BUCKETS}
    for rec in records:
        mt = rec.get('match_type') or ''
        me = rec.get('mutation_eligibility') or ''
        sec = rec.get('security_conclusion') or ''
        m0 = str(rec.get('m0_status') or '')
        if mt == 'no_capture':
            counts['no_capture'] += 1
        if me == 'no_subject_candidate':
            counts['no_subject_candidate'] += 1
        if me == 'signature_bound_skip':
            counts['signature_bound_skip'] += 1
        if sec == 'not_tested':
            counts['not_tested'] += 1
        br = rec.get('block_reason') or ''
        if br == 'validation_error' or 'validation' in m0:
            counts['validation_error'] += 1
        if br == 'auth_expired' or 'auth_expired' in m0:
            counts['auth_expired'] += 1
        if m0.endswith('failed') or br == 'm0_failed':
            counts['m0_failed'] += 1
    return counts


def build_baseline_readiness_report(
    pack_dir: Path,
    *,
    runtime_index_doc: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    plane = load_json(pack_dir / 'api_plane_index.json') or {}
    fb = load_json(pack_dir / 'final_binding_report.json') or {}
    bc = load_json(pack_dir / 'binding_coverage_report.json') or {}
    intake = load_json(pack_dir / 'baseline_intake_report.json') or {}
    alias = load_json(pack_dir / 'runtime_alias_map.json') or {}
    rci = runtime_index_doc or load_json(pack_dir / 'runtime_capture_index.json') or {}
    pools = {
        name: load_json(pack_dir / name) or {}
        for name in ('subject_pool.json', 'object_pool.json', 'context_pool.json')
    }

    summary = fb.get('summary') or {}
    records = fb.get('records') or []
    frontier = bc.get('coverage_frontier_summary') or {}

    l0 = int(frontier.get('L0_static_recovered') or len(plane.get('entries') or []))
    l1 = int(summary.get('api_count') or frontier.get('L1_materialized') or 0)
    l2 = int((rci.get('summary') or {}).get('capture_count') or intake.get('capture_count') or 0)
    l3 = sum(
        1 for r in records
        if 'success' in str(r.get('m0_status') or '') or 'matched' in str(r.get('m0_status') or '')
    )
    l4 = int(summary.get('m7_executed_count') or sum(1 for r in records if r.get('m7_status') == 'executed'))
    l5 = sum(1 for r in records if (r.get('security_conclusion') or '') not in ('not_tested', 'inconclusive', None, ''))

    alias_rows = alias.get('aliases') or alias.get('mappings') or []
    if isinstance(alias, dict) and not alias_rows:
        alias_rows = [
            v for v in alias.values()
            if isinstance(v, dict) and v.get('static_api')
        ]

    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'funnel': {
            'L0_static_recovered': l0,
            'L1_sensitive_campaign_targets': l1,
            'L2_runtime_captures': l2,
            'L3_m0_success_records': l3,
            'L4_m7_executed': l4,
            'L5_with_security_conclusion': l5,
        },
        'rates': {
            'L2_over_L1': round(l2 / max(l1, 1), 4),
            'L3_over_L1': round(l3 / max(l1, 1), 4),
            'L4_over_L1': round(l4 / max(l1, 1), 4),
            'L5_over_L1': round(l5 / max(l1, 1), 4),
            'not_tested_rate': round((summary.get('not_tested_count') or 0) / max(l1, 1), 4),
        },
        'failure_histogram': _count_failure_reasons(records),
        'pool_summary': {
            name: (doc.get('summary') or {})
            for name, doc in pools.items()
        },
        'runtime_capture_index_summary': rci.get('summary') or {},
        'alias_binding_count': len(alias_rows),
        'crypto_replay_ready': bool((intake.get('crypto_capability') or {}).get('can_replay')),
        'baseline_capture_count': intake.get('capture_count') or 0,
    }


def write_baseline_readiness_report(pack_dir: Path) -> Path:
    pack_dir = Path(pack_dir)
    doc = build_baseline_readiness_report(pack_dir)
    out = pack_dir / 'baseline_readiness_report.json'
    write_json(out, doc)
    return out
