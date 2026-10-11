# -*- coding: utf-8 -*-
"""Load frozen API Card pack from an output directory."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


def load_pack(output_dir: str | Path) -> Dict[str, Any]:
    root = Path(output_dir)
    cards = _read_json(root / 'api_cards.json', [])
    manifest = _read_json(root / 'api_card_pack_manifest.json', {})
    return {
        'root': root,
        'cards': cards,
        'manifest': manifest,
        'cards_by_id': {c['card_id']: c for c in cards if c.get('card_id')},
    }


def load_evidence_pack(output_dir: str | Path, card_id: str) -> Optional[Dict[str, Any]]:
    path = Path(output_dir) / 'evidence_packs' / f'{card_id}.json'
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def load_rule_erd(output_dir: str | Path) -> List[Dict[str, Any]]:
    data = _read_json(Path(output_dir) / 'evidence_requirements.json', {})
    if isinstance(data, list):
        return data
    return data.get('items') or []


def load_panel_row(output_dir: str | Path, card_id: str) -> Optional[Dict[str, Any]]:
    panel = _read_json(Path(output_dir) / 'verification_readiness_panel.json', {})
    for row in panel.get('per_card_summary') or []:
        if row.get('card_id') == card_id:
            return row
    return None


def load_acquisition_plan(output_dir: str | Path) -> Optional[Dict[str, Any]]:
    return _read_json(Path(output_dir) / 'acquisition_plan.json', None)


def slim_plan_for_llm(plan: Dict[str, Any]) -> Dict[str, Any]:
    """Compact rule plan for LLM context."""
    return {
        'pack_id': plan.get('pack_id'),
        'phase': plan.get('phase'),
        'plan_summary': plan.get('plan_summary'),
        'stage_1_user_materials': plan.get('stage_1_user_materials'),
        'user_collection_instructions': plan.get('user_collection_instructions'),
        'stage_1_target_apis': (plan.get('stage_1_target_apis') or [])[:15],
        'auto_discovery_apis': plan.get('auto_discovery_apis') or [],
        'deferred_apis': (plan.get('deferred_apis') or [])[:10],
        'explicitly_deferred_examples': plan.get('explicitly_deferred_examples') or [],
        'top_stage_1_recommendation': plan.get('top_stage_1_recommendation') or [],
    }


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding='utf-8'))


def slim_card_for_llm(card: Dict[str, Any]) -> Dict[str, Any]:
    """Reduce token usage while keeping audit-relevant fields."""
    return {
        'card_id': card.get('card_id'),
        'provenance': card.get('provenance'),
        'static': card.get('static'),
        'evidence': card.get('evidence'),
        'bindings': card.get('bindings'),
        'reachability': card.get('reachability'),
        'downstream_policy': card.get('downstream_policy'),
        'replay': {
            'readiness': (card.get('replay') or {}).get('readiness'),
            'transport': (card.get('replay') or {}).get('transport'),
            'auth_dependency': (card.get('replay') or {}).get('auth_dependency'),
            'oracle_hints': (card.get('replay') or {}).get('oracle_hints'),
            'side_effect': (card.get('replay') or {}).get('side_effect'),
            'mutation_points': (card.get('replay') or {}).get('mutation_points'),
            'contract_included_in_top_k': (card.get('replay') or {}).get('contract_included_in_top_k'),
        },
        'ranking': card.get('ranking'),
    }
