# -*- coding: utf-8 -*-
"""Select and score APIs for verification campaign (single-point replay)."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.core.pack_meta import resolve_pack_id
from minidrifter.core.utils import stable_id
from minidrifter.verification import SCHEMA_VERSION
from minidrifter.verification.pack_loader import load_field_ontology
from minidrifter.verification.safety_policy import evaluate_test_safety

AUTO_SIDE_EFFECTS = frozenset({'S0_read_only', 'S1_query_like_post'})


def _replay_ready_statuses(baseline_context: Dict[str, Any]) -> frozenset:
    strategy = (baseline_context.get('intake_strategy') or {}).get('strategy') or baseline_context.get('replay_mode')
    if strategy == 'plaintext_direct':
        return frozenset({'materialized_with_crypto_profile', 'materialized_plain'})
    return frozenset({'materialized_with_crypto_profile'})


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding='utf-8'))


def _replay_rank_map(pack_dir: Path) -> Dict[str, float]:
    plan = _load_json(pack_dir / 'acquisition_plan.json') or {}
    ranks: Dict[str, float] = {}
    for section in ('stage_1_target_apis', 'auto_discovery_apis'):
        for item in plan.get(section) or []:
            cid = item.get('card_id')
            if cid:
                ranks[cid] = float(item.get('replay_safe_rank') or item.get('stage1_score') or 0)
    return ranks


def _domain_entry_paths(pack_dir: Path) -> Set[str]:
    paths: Set[str] = set()
    for wf in pack_dir.glob('*_workflow_plan.json'):
        data = _load_json(wf) or {}
        paths.update(data.get('entrypoints') or [])
    return paths


def _infer_domain(path: str) -> str:
    low = path.lower()
    if re.search(r'invoice|invtitle|tax', low):
        return 'invoice'
    if re.search(r'order|rental|booking', low):
        return 'order'
    if re.search(r'user|profile|cacheinfo|cardinfo', low):
        return 'user_profile'
    if re.search(r'device|store', low):
        return 'device'
    return 'general'


def _binding_expectations(template: Dict[str, Any], baseline_pool: Dict[str, str]) -> List[Dict[str, Any]]:
    expectations = []
    subject = baseline_pool.get('UserId') or baseline_pool.get('userId') or baseline_pool.get('OperatorId')
    if not subject:
        return expectations
    params = (template.get('plain_template') or {}).get('params') or {}
    for key in params:
        if key.lower() in {'userid', 'user_id'}:
            expectations.append({
                'subject': f'$baseline.UserId',
                'object': key,
                'relation': 'same_subject',
            })
    return expectations


def score_template(
    template: Dict[str, Any],
    *,
    replay_ranks: Dict[str, float],
    entry_paths: Set[str],
    baseline_field_count: int,
) -> float:
    api_id = template.get('api_id') or ''
    score = replay_ranks.get(api_id, 0.0)

    status = template.get('status') or ''
    if status == 'materialized_with_crypto_profile':
        score += 25.0
    elif status == 'materialized_plain':
        score += 20.0

    side = template.get('side_effect_level') or ''
    if side == 'S0_read_only':
        score += 15.0
    elif side == 'S1_query_like_post':
        score += 8.0
    else:
        score -= 50.0

    path = template.get('path') or ''
    if path in entry_paths:
        score += 12.0
    if _infer_domain(path) in {'user_profile', 'device', 'invoice'}:
        score += 5.0

    missing = len(template.get('missing_slots') or [])
    score -= missing * 8.0

    resolved = len(template.get('resolved_slots') or {})
    score += min(10.0, resolved * 0.5)

    if baseline_field_count >= 10:
        score += 3.0

    return round(score, 2)


def build_test_case(
    template: Dict[str, Any],
    *,
    baseline_context: Dict[str, Any],
    index: int,
) -> Dict[str, Any]:
    pool = {
        k: (v.get('value') if isinstance(v, dict) else v)
        for k, v in (baseline_context.get('resolved_fields') or {}).items()
    }
    api_id = template.get('api_id') or template.get('card_id')
    path = template.get('path') or ''
    side = template.get('side_effect_level') or 'S0_read_only'
    crypto = template.get('crypto_profile') or {}

    plain = template.get('plain_template') or {}
    return {
        'test_id': stable_id('tc', api_id, 'baseline_replay', index),
        'api_id': api_id,
        'path': path,
        'domain': _infer_domain(path),
        'method': (plain.get('method') or template.get('method') or 'GET').upper(),
        'test_stage': 'single_point',
        'mutation_type': 'M0_baseline_replay',
        'template_ref': f'materialized_api_templates.json#{api_id}',
        'params': plain.get('params') or {},
        'body_params': plain.get('body_params') or {},
        'transport_style': plain.get('transport_style') or crypto.get('transport_style'),
        'http_template': template.get('http_template'),
        'plain_template': plain,
        'status': template.get('status'),
        'template_status': template.get('status'),
        'missing_slots': template.get('missing_slots') or [],
        'crypto_required': bool(crypto.get('available')),
        'crypto_profile_id': crypto.get('profile_id'),
        'safety': {
            'side_effect': side,
            'auto_replay': side in AUTO_SIDE_EFFECTS,
            'requires_execute_flag': True,
        },
        'expected_bindings': _binding_expectations(template, pool),
        'planner_score': template.get('_planner_score'),
    }


def plan_campaign(
    pack_dir: Path,
    *,
    max_tests: int = 20,
    only_safe: bool = True,
    baseline_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    templates_doc = _load_json(pack_dir / 'materialized_api_templates.json') or {}
    baseline_context = baseline_context or _load_json(pack_dir / 'baseline_runtime_context.json') or {}

    templates = templates_doc.get('templates') or []
    ready_ids = {r.get('api_id') for r in (templates_doc.get('ready_for_replay') or [])}
    replay_ranks = _replay_rank_map(pack_dir)
    entry_paths = _domain_entry_paths(pack_dir)
    field_count = int(baseline_context.get('field_count') or 0)

    ready_statuses = _replay_ready_statuses(baseline_context)

    scored = []
    for tpl in templates:
        api_id = tpl.get('api_id')
        if ready_ids and api_id not in ready_ids:
            continue
        if tpl.get('status') not in ready_statuses:
            continue
        side = tpl.get('side_effect_level') or ''
        if only_safe and side not in AUTO_SIDE_EFFECTS:
            continue
        s = score_template(
            tpl, replay_ranks=replay_ranks, entry_paths=entry_paths,
            baseline_field_count=field_count,
        )
        tpl_scored = {**tpl, '_planner_score': s}
        scored.append((s, tpl_scored))

    scored.sort(key=lambda x: x[0], reverse=True)
    selected = [t for _, t in scored[:max_tests]]

    test_cases = []
    blocked = []
    for i, tpl in enumerate(selected):
        tc = build_test_case(tpl, baseline_context=baseline_context, index=i)
        verdict = evaluate_test_safety(
            tc, baseline_context=baseline_context, only_safe=only_safe, mode='dry-run',
        )
        if verdict.allowed:
            test_cases.append(tc)
        else:
            blocked.append({'test_id': tc['test_id'], 'api_id': tc['api_id'], 'reasons': verdict.reasons})

    campaign = {
        'schema_version': SCHEMA_VERSION,
        'pack_id': resolve_pack_id(pack_dir),
        'generated_at': _utc_now(),
        'campaign_mode': 'normal',
        'phase': 'single_point',
        'only_safe': only_safe,
        'max_tests': max_tests,
        'baseline_field_count': field_count,
        'crypto_replay_ready': bool(baseline_context.get('crypto_replay_ready')),
        'crypto_profile': baseline_context.get('crypto_profile'),
        'candidate_count': len(scored),
        'selected_count': len(test_cases),
        'blocked_count': len(blocked),
        'test_case_ids': [t['test_id'] for t in test_cases],
        'top_apis': [
            {'api_id': t['api_id'], 'path': t['path'], 'score': t.get('planner_score')}
            for t in test_cases[:10]
        ],
        'blocked': blocked[:20],
    }
    return {'campaign': campaign, 'test_cases': test_cases}


def score_all_templates(
    pack_dir: Path,
    *,
    only_safe: bool = True,
    baseline_context: Optional[Dict[str, Any]] = None,
    limit: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Return all replay-ready templates sorted by planner score (for breadth queue)."""
    pack_dir = Path(pack_dir)
    templates_doc = _load_json(pack_dir / 'materialized_api_templates.json') or {}
    baseline_context = baseline_context or _load_json(pack_dir / 'baseline_runtime_context.json') or {}

    templates = templates_doc.get('templates') or []
    ready_ids = {r.get('api_id') for r in (templates_doc.get('ready_for_replay') or [])}
    replay_ranks = _replay_rank_map(pack_dir)
    entry_paths = _domain_entry_paths(pack_dir)
    field_count = int(baseline_context.get('field_count') or 0)

    ready_statuses = _replay_ready_statuses(baseline_context)

    scored: List[tuple[float, Dict[str, Any]]] = []
    for tpl in templates:
        api_id = tpl.get('api_id')
        if ready_ids and api_id not in ready_ids:
            continue
        if tpl.get('status') not in ready_statuses:
            continue
        side = tpl.get('side_effect_level') or ''
        if only_safe and side not in AUTO_SIDE_EFFECTS:
            continue
        s = score_template(
            tpl, replay_ranks=replay_ranks, entry_paths=entry_paths,
            baseline_field_count=field_count,
        )
        scored.append((s, {**tpl, '_planner_score': s}))

    scored.sort(key=lambda x: x[0], reverse=True)
    rows = [t for _, t in scored]
    if limit:
        rows = rows[:limit]
    return rows
