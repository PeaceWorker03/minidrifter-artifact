# -*- coding: utf-8
"""Export Universal IR bundle from a verification pack directory."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import write_json
from minidrifter.ir.constants import IR_VERSION
from minidrifter.ir.converters import (
    to_universal_api_card,
    to_universal_chain_hypothesis,
    to_universal_feedback_ticket,
    to_universal_object_model,
)
from minidrifter.ir.n_tier import summarize_n_tier_distribution
from minidrifter.reasoning.pack_loader import load_pack


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_json(path: Path) -> Any:
    if path.exists():
        return json.loads(path.read_text(encoding='utf-8'))
    return None


def export_universal_ir(
    pack_dir: Path,
    *,
    profile_id: Optional[str] = None,
    limit: int = 0,
) -> Dict[str, Any]:
    """Build and write universal_ir_bundle.json + per-type artifacts."""
    pack_dir = Path(pack_dir)
    pack = load_pack(pack_dir)
    cards = pack['cards']
    erd_path = pack_dir / 'evidence_requirements.json'
    erd_doc = _load_json(erd_path) or {}
    erd_items = erd_doc.get('items') or []
    erd_by_id = {i.get('card_id'): i for i in erd_items if i.get('card_id')}

    ctx = _load_json(pack_dir / 'baseline_runtime_context.json') or {}
    tickets_doc = _load_json(pack_dir / 'blocking_tickets.json') or {}
    session = _load_json(pack_dir / 'search_session.json') or {}
    chains_doc = _load_json(pack_dir / 'finding_chain_reports.json') or {}

    subset = cards[:limit] if limit else cards
    universal_api_cards = [
        to_universal_api_card(c, erd_by_id.get(c.get('card_id')))
        for c in subset
    ]

    universal_tickets = [
        to_universal_feedback_ticket(t)
        for t in (tickets_doc.get('tickets') or [])
    ]

    universal_chains: List[Dict[str, Any]] = []
    for rep in chains_doc.get('reports') or []:
        ch = rep.get('chain') or {}
        if ch:
            universal_chains.append(to_universal_chain_hypothesis(ch, domain=rep.get('business_domain') or 'general'))

    for ch in session.get('beam_chains') or []:
        if isinstance(ch, dict) and ch.get('chain_id'):
            universal_chains.append(to_universal_chain_hypothesis(ch))

    n_tier_dist = summarize_n_tier_distribution(cards, erd_items)

    bundle = {
        'ir_version': IR_VERSION,
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'profile_id': profile_id or _detect_profile_id(pack_dir),
        'summary': {
            'api_card_count': len(cards),
            'universal_api_card_count': len(universal_api_cards),
            'n_tier_distribution': n_tier_dist,
            'baseline_field_count': ctx.get('field_count') or 0,
            'crypto_replay_ready': bool(ctx.get('crypto_replay_ready')),
            'open_tickets': len([t for t in universal_tickets if t.get('status') == 'open']),
            'chain_hypotheses': len(universal_chains),
            'confirmed_findings': chains_doc.get('confirmed_count') or 0,
        },
        'artifacts': {},
    }

    out = pack_dir / 'universal_ir'
    out.mkdir(parents=True, exist_ok=True)

    paths = {
        'universal_ir_bundle': out / 'universal_ir_bundle.json',
        'universal_api_cards': out / 'universal_api_cards.json',
        'universal_object_model': out / 'universal_object_model.json',
        'universal_chain_hypotheses': out / 'universal_chain_hypotheses.json',
        'universal_feedback_tickets': out / 'universal_feedback_tickets.json',
        'universal_n_tier_summary': out / 'universal_n_tier_summary.json',
    }

    write_json(paths['universal_api_cards'], {
        'ir_version': IR_VERSION,
        'generated_at': bundle['generated_at'],
        'count': len(universal_api_cards),
        'items': universal_api_cards,
    })

    write_json(paths['universal_object_model'], to_universal_object_model(ctx.get('resolved_fields') or {}))

    write_json(paths['universal_chain_hypotheses'], {
        'ir_version': IR_VERSION,
        'generated_at': bundle['generated_at'],
        'count': len(universal_chains),
        'items': universal_chains,
    })

    write_json(paths['universal_feedback_tickets'], {
        'ir_version': IR_VERSION,
        'generated_at': bundle['generated_at'],
        'count': len(universal_tickets),
        'items': universal_tickets,
    })

    write_json(paths['universal_n_tier_summary'], {
        'ir_version': IR_VERSION,
        'generated_at': bundle['generated_at'],
        'distribution': n_tier_dist,
        'total': len(cards),
    })

    bundle['artifacts'] = {k: str(v) for k, v in paths.items()}
    write_json(paths['universal_ir_bundle'], bundle)

    from minidrifter.adapters.pack_resolver import write_adapter_resolution
    adapter_doc = write_adapter_resolution(pack_dir, profile_id=bundle.get('profile_id'))
    bundle['adapter_profile'] = adapter_doc

    return bundle


def _detect_profile_id(pack_dir: Path) -> str:
    from minidrifter.adapters.pack_resolver import resolve_pack_profile
    return resolve_pack_profile(pack_dir).get('profile_id') or 'default'
