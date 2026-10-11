# -*- coding: utf-8 -*-
"""Staleness checks and dependency fingerprints for materialized templates."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


def _file_hash(path: Path) -> Optional[str]:
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def _parse_ts(iso: Optional[str]) -> Optional[datetime]:
    if not iso:
        return None
    try:
        return datetime.fromisoformat(iso.replace('Z', '+00:00'))
    except ValueError:
        return None


def build_materialization_dependencies(
    pack_dir: Path,
    baseline_context: Dict[str, Any],
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    ctx_path = pack_dir / 'baseline_runtime_context.json'
    sk_path = pack_dir / 'runtime_skeletons.json'
    cards_path = pack_dir / 'api_cards.json'

    return {
        'baseline_context_generated_at': baseline_context.get('generated_at'),
        'baseline_context_field_count': baseline_context.get('field_count', 0),
        'baseline_context_hash': _file_hash(ctx_path),
        'skeletons_hash': _file_hash(sk_path),
        'api_cards_hash': _file_hash(cards_path),
        'crypto_replay_ready': baseline_context.get('crypto_replay_ready'),
        'crypto_profile': baseline_context.get('crypto_profile'),
    }


def check_materialization_stale(
    pack_dir: Path,
    *,
    existing_templates: Optional[Dict[str, Any]] = None,
    baseline_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    tpl_path = pack_dir / 'materialized_api_templates.json'
    ctx_path = pack_dir / 'baseline_runtime_context.json'

    if existing_templates is None and tpl_path.exists():
        existing_templates = json.loads(tpl_path.read_text(encoding='utf-8'))
    if baseline_context is None and ctx_path.exists():
        baseline_context = json.loads(ctx_path.read_text(encoding='utf-8'))

    if not existing_templates:
        return {'stale': True, 'reason': 'no_existing_templates'}
    if not baseline_context:
        return {'stale': True, 'reason': 'no_baseline_context'}

    deps = build_materialization_dependencies(pack_dir, baseline_context)
    prev_deps = existing_templates.get('dependencies') or {}
    prev_fc = existing_templates.get('baseline_field_count', 0)
    curr_fc = baseline_context.get('field_count', 0)

    tpl_ts = _parse_ts(existing_templates.get('generated_at'))
    ctx_ts = _parse_ts(baseline_context.get('generated_at'))

    reasons = []
    if ctx_ts and tpl_ts and ctx_ts > tpl_ts:
        reasons.append('baseline_context_newer_than_templates')
    if curr_fc != prev_fc:
        reasons.append(f'field_count_changed:{prev_fc}->{curr_fc}')
    if deps.get('baseline_context_hash') != prev_deps.get('baseline_context_hash'):
        reasons.append('baseline_context_hash_changed')
    if deps.get('skeletons_hash') != prev_deps.get('skeletons_hash'):
        reasons.append('skeletons_hash_changed')

    return {
        'stale': bool(reasons),
        'reasons': reasons,
        'current_dependencies': deps,
        'previous_dependencies': prev_deps,
    }
