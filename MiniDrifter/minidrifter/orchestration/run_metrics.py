# -*- coding: utf-8 -*-
"""Unified run metrics — single definitions, no mixed card/template counts."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

METRIC_DEFINITIONS: Dict[str, str] = {
    'raw_api_card_count': 'All API cards in all_api_cards.json (including audit-only).',
    'operation_api_count': 'Operation-ranked cards (excludes registered-only).',
    'registered_only_count': 'Registry-only cards not in operation ranking.',
    'ranked_candidate_count': 'Entries in ranked_api_candidates.json.',
    'replay_contract_count': 'Replay contract entries.',
    'template_count': 'Request templates before crypto materialization.',
    'materialized_template_count': 'Templates with status materialized_with_crypto_profile.',
    'replay_ready_count': 'Cards/templates marked replay ready in static inventory.',
    'live_executable_count': 'Materialized templates passing preflight execute gate.',
    'business_success_count': 'HTTP responses classified business_success.',
    'confirmed_finding_count': 'Findings with status confirmed after final oracle.',
    'hypothesis_finding_count': 'Findings awaiting escalation evidence.',
    'signal_finding_count': 'Single-hop suspicious signals only.',
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load(path: Path) -> Any:
    if path.exists():
        return json.loads(path.read_text(encoding='utf-8'))
    return None


def _items(doc: Any, *keys: str) -> List[Any]:
    if isinstance(doc, list):
        return doc
    if not isinstance(doc, dict):
        return []
    for key in keys:
        val = doc.get(key)
        if isinstance(val, list):
            return val
    return []


def _load_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    out: List[Dict[str, Any]] = []
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def collect_run_metrics(pack_dir: Path) -> Dict[str, Any]:
    """Collect canonical metrics from one verification pack directory."""
    pack_dir = Path(pack_dir)
    manifest = _load(pack_dir / 'api_card_pack_manifest.json') or {}
    inv = manifest.get('card_inventory') or {}
    replay_inv = manifest.get('replay_inventory') or {}
    readiness = manifest.get('readiness_inventory') or {}

    all_cards_raw = _load(pack_dir / 'all_api_cards.json') or {}
    if isinstance(all_cards_raw, list):
        all_cards_items = all_cards_raw
    else:
        all_cards_items = all_cards_raw.get('items') or all_cards_raw.get('cards') or []
    ranked = _load(pack_dir / 'ranked_api_candidates.json') or {}
    contracts = _load(pack_dir / 'replay_contracts.json') or {}
    mat_report = _load(pack_dir / 'materialization_report.json') or {}
    preflight = _load(pack_dir / 'replay_preflight_report.json') or {}
    session = _load(pack_dir / 'search_session.json') or {}
    finding_doc = _load(pack_dir / 'finding_registry.json') or {}
    n_tier = _load(pack_dir / 'universal_ir' / 'universal_n_tier_summary.json') or {}

    analyses = _load_jsonl(pack_dir / 'response_analysis.jsonl')
    if not analyses and session:
        analyses = []

    by_status = (finding_doc.get('summary') or {}).get('by_status') or {}
    coverage = session.get('coverage') or {}

    materialized = int((mat_report.get('summary') or {}).get('materialized_with_crypto_profile') or 0)
    if not materialized:
        rf = mat_report.get('ready_for_replay')
        if isinstance(rf, list):
            materialized = len(rf)
        else:
            materialized = int(mat_report.get('materialized_count') or rf or 0)
    if not materialized:
        templates = _load(pack_dir / 'request_templates.json') or {}
        items = templates.get('items') or templates.get('templates') or []
        materialized = sum(
            1 for t in items
            if t.get('status') == 'materialized_with_crypto_profile'
        )

    live_exec = int((preflight.get('summary') or {}).get('execute_ready') or 0)
    if not live_exec:
        live_exec = materialized

    business_success = coverage.get('business_success')
    if business_success is None:
        business_success = sum(1 for a in analyses if a.get('call_outcome') == 'business_success')

    metrics = {
        'raw_api_card_count': len(all_cards_items) or inv.get('total_cards'),
        'operation_api_count': (inv.get('by_card_kind') or {}).get('operation') or inv.get('total_cards'),
        'registered_only_count': (inv.get('by_card_kind') or {}).get('registered_only'),
        'ranked_candidate_count': len(_items(ranked, 'items', 'candidates')),
        'replay_contract_count': len(_items(contracts, 'items', 'contracts')),
        'template_count': mat_report.get('template_count') or mat_report.get('total_templates'),
        'materialized_template_count': materialized,
        'replay_ready_count': (readiness.get('by_status') or {}).get('ready') or replay_inv.get('ready_count'),
        'live_executable_count': live_exec,
        'business_success_count': business_success,
        'confirmed_finding_count': by_status.get('confirmed') or coverage.get('findings_confirmed') or 0,
        'hypothesis_finding_count': by_status.get('hypothesis') or 0,
        'signal_finding_count': by_status.get('signal') or 0,
        'http_call_count': coverage.get('http_calls') or len(_load_jsonl(pack_dir / 'execution_results.jsonl')),
        'beam_chain_count': coverage.get('beam_chains') or 0,
    }

    return {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'pack_id': manifest.get('pack_id'),
        'metric_definitions': METRIC_DEFINITIONS,
        'metrics': metrics,
        'n_tier_distribution': n_tier.get('distribution') or (session.get('universal_ir') or {}).get('n_tier_distribution'),
    }
