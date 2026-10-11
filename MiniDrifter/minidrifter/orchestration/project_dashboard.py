# -*- coding: utf-8 -*-
"""Project dashboard — user-facing N-tier summary and next actions."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import write_json

N0_LEVEL = 'N0_STATIC_TEMPLATE'
N1_LEVEL = 'N1_BASELINE_RUNTIME_TEMPLATE'


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load(path: Path) -> Any:
    if path.exists():
        return json.loads(path.read_text(encoding='utf-8'))
    return None


def build_project_dashboard(pack_dir: Path, *, project_name: Optional[str] = None) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    erd = _load(pack_dir / 'evidence_requirements.json') or {}
    items = erd.get('items') or []
    n0 = sum(1 for i in items if (i.get('runtime_requirement') or {}).get('level') == N0_LEVEL)
    n1 = sum(1 for i in items if (i.get('runtime_requirement') or {}).get('level') == N1_LEVEL)

    n_tier_doc = _load(pack_dir / 'universal_ir' / 'universal_n_tier_summary.json') or {}
    n_tier_dist = n_tier_doc.get('distribution') or {}
    run_metrics = _load(pack_dir / 'run_metrics.json') or {}

    manifest = _load(pack_dir / 'api_card_pack_manifest.json') or {}
    ctx = _load(pack_dir / 'baseline_runtime_context.json') or {}
    plan = _load(pack_dir / 'acquisition_plan.json') or {}
    plane_doc = _load(pack_dir / 'api_plane_index.json') or {}

    domains: Dict[str, int] = {}
    for i in items:
        d = i.get('domain') or 'general'
        domains[d] = domains.get(d, 0) + 1

    high_risk = [d for d in domains if d in ('order', 'invoice', 'payment', 'device', 'member', 'coupon')]
    api_card_count = (
        plane_doc.get('api_count')
        or len(plane_doc.get('entries') or [])
        or erd.get('card_count')
        or len(items)
    )

    dashboard = {
        'schema_version': '1.1.0',
        'generated_at': _utc_now(),
        'project_name': project_name or pack_dir.name,
        'pack_dir': str(pack_dir),
        'analyzable': True,
        'api_card_count': api_card_count,
        'n0_count': n0,
        'n1_count': n1,
        'n_tier_distribution': n_tier_dist,
        'run_metrics': run_metrics.get('metrics'),
        'metric_definitions': run_metrics.get('metric_definitions'),
        'needs_login_materials': n1 > 0,
        'crypto_replay_ready': bool(ctx.get('crypto_replay_ready')),
        'has_baseline': bool(ctx),
        'domain_distribution': domains,
        'high_risk_domains': high_risk,
        'stage_1_targets': (plan.get('plan_summary') or {}).get('stage_1_target_count'),
        'material_packages': (plan.get('plan_summary') or {}).get('material_package_count'),
        'recommended_next': _next_action(ctx, plan, n_tier_dist),
        'user_input_checklist': str(pack_dir / 'user_intake_checklist.json'),
    }
    return dashboard


def _next_action(ctx: Dict[str, Any], plan: Dict[str, Any], n_tier: Dict[str, int]) -> str:
    if not ctx:
        return 'prepare-runtime: put captures in <项目>/baseline/ (see baseline_capture_requirements.md)'
    if not ctx.get('crypto_replay_ready'):
        return 'intake-baseline: provide successful business request with Token/crypto context in baseline/'
    if not plan:
        return 'verify-prepare: generate acquisition plan'
    if int(n_tier.get('N1-state') or 0) > int(n_tier.get('N1-auth') or 0):
        return 'deep-verify: prioritize N1-auth anchors; ticket N1-state APIs early'
    return 'deep-verify: run chain binding verification'


def write_project_dashboard(pack_dir: Path, *, project_name: Optional[str] = None) -> Dict[str, str]:
    pack_dir = Path(pack_dir)
    doc = build_project_dashboard(pack_dir, project_name=project_name)
    json_path = pack_dir / 'project_dashboard.json'
    write_json(json_path, doc)

    tier_lines = [
        f'  - {k}: **{v}**' for k, v in sorted((doc.get('n_tier_distribution') or {}).items())
    ]
    md_lines = [
        f'# {doc["project_name"]} — MiniDrifter Dashboard',
        '',
        f'- API cards: **{doc.get("api_card_count")}**',
        f'- N0 (static replay): **{doc.get("n0_count")}**',
        f'- N1 (legacy bucket): **{doc.get("n1_count")}**',
        '',
        '## Universal N-tier',
        *tier_lines,
        '',
        f'- Crypto replay ready: **{doc.get("crypto_replay_ready")}**',
        f'- High-risk domains: {", ".join(doc.get("high_risk_domains") or []) or "—"}',
        '',
        f'**Next:** {doc.get("recommended_next")}',
        '',
        'Unified metrics: see `run_metrics.json`. Versioned run: see `runs/latest/`.',
        'Baseline captures: `<项目>/baseline/` — see `baseline_capture_requirements.md`.',
        'See `user_intake_checklist.json` for required HTTP captures.',
    ]
    md_path = pack_dir / 'project_dashboard.md'
    md_path.write_text('\n'.join(md_lines), encoding='utf-8')
    return {'json': str(json_path), 'markdown': str(md_path)}
