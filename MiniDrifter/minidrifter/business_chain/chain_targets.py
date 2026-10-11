# -*- coding: utf-8
"""Chain-first materialization targets — prioritize ranked hop api_ids."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.core.utils import write_json
from minidrifter.materials.intake_param_hints import normalize_api_path


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def _add_api_id(out: List[str], seen: Set[str], aid: Optional[str], *, max_ids: int) -> None:
    if not aid or aid in seen or len(out) >= max_ids:
        return
    seen.add(aid)
    out.append(aid)


def collect_chain_materialization_targets(
    pack_dir: Path,
    *,
    chain_id: Optional[str] = None,
    top_n: int = 25,
    max_ids: int = 120,
) -> List[str]:
    """Ordered api_ids: ranked chains + unlock matrix + probe-eligible consumers."""
    pack_dir = Path(pack_dir)
    rank_plan = _load_json(pack_dir / 'chain_rank_plan.json') or {}
    chains_doc = _load_json(pack_dir / 'business_chains.json') or {}
    unlock = _load_json(pack_dir / 'baseline_unlock_matrix.json') or {}
    risk_doc = _load_json(pack_dir / 'binding_risk_candidates.json') or {}
    chains_by_id = {
        c['chain_id']: c for c in (chains_doc.get('chains') or []) if c.get('chain_id')
    }

    ranked = list(rank_plan.get('top_chains') or [])
    if chain_id:
        ranked = [r for r in ranked if r.get('chain_id') == chain_id]
        if not ranked and chain_id in chains_by_id:
            c = chains_by_id[chain_id]
            ranked = [{
                'chain_id': chain_id,
                'entry_api': c.get('entry_api'),
                'target_hop': c.get('target_hop'),
                'risk_hops': c.get('risk_hops') or [],
            }]

    out: List[str] = []
    seen: Set[str] = set()

    for item in ranked[:top_n]:
        _add_api_id(out, seen, item.get('entry_api'), max_ids=max_ids)
        _add_api_id(out, seen, item.get('target_hop'), max_ids=max_ids)
        for hid in item.get('risk_hops') or []:
            _add_api_id(out, seen, hid, max_ids=max_ids)
        chain = chains_by_id.get(item.get('chain_id') or '') or {}
        for hop in chain.get('hops') or []:
            _add_api_id(out, seen, hop.get('api_id'), max_ids=max_ids)

    for row in (unlock.get('runnable_chains') or [])[:40]:
        chain = chains_by_id.get(row.get('chain_id') or '') or {}
        _add_api_id(out, seen, chain.get('entry_api'), max_ids=max_ids)
        _add_api_id(out, seen, chain.get('target_hop'), max_ids=max_ids)
        for hop in chain.get('hops') or []:
            _add_api_id(out, seen, hop.get('api_id'), max_ids=max_ids)

    for row in (unlock.get('unlocked_probe_apis') or [])[:30]:
        _add_api_id(out, seen, row.get('api_id'), max_ids=max_ids)

    cards_by_path = {}
    ir = _load_json(pack_dir / 'universal_ir' / 'universal_api_cards.json') or {}
    for card in (ir.get('items') or ir.get('cards') or []):
        p = normalize_api_path(card.get('path') or '')
        if p:
            cards_by_path[p] = card

    for cand in (risk_doc.get('candidates') or []):
        if not cand.get('probe_eligible'):
            continue
        _add_api_id(out, seen, cand.get('api_id'), max_ids=max_ids)
        if len(out) >= max_ids:
            break

    for row in (unlock.get('pool_unlocked_materialized_apis') or [])[:30]:
        _add_api_id(out, seen, row.get('api_id'), max_ids=max_ids)

    return out


def merge_materialization_targets(
    chain_ids: List[str],
    other_ids: Optional[List[str]],
    *,
    limit: int = 120,
) -> List[str]:
    """Chain targets first, then supplemental ids, deduped."""
    merged: List[str] = []
    seen: Set[str] = set()
    for aid in list(chain_ids) + list(other_ids or []):
        if not aid or aid in seen:
            continue
        seen.add(aid)
        merged.append(aid)
        if len(merged) >= limit:
            break
    return merged


def run_chain_targeted_materialize(
    pack_dir: Path,
    ctx: Dict[str, Any],
    *,
    chain_id: Optional[str] = None,
    limit: int = 120,
    force: bool = True,
    intake_report: Optional[Dict[str, Any]] = None,
    replay_safe_only: bool = False,
) -> Dict[str, Any]:
    """Materialize templates prioritizing ranked chain hop api_ids."""
    from minidrifter.reasoning.pack_loader import load_pack
    from minidrifter.materials.slot_binder import build_materialized_templates
    from minidrifter.materials.intake_param_hints import resolve_intake_capture_card_ids

    pack_dir = Path(pack_dir)
    pack = load_pack(pack_dir)
    skeletons = _load_json(pack_dir / 'runtime_skeletons.json') or {}
    by_id = skeletons.get('by_card_id') or {
        s['card_id']: s for s in skeletons.get('skeletons', [])
    }

    if intake_report is None:
        intake_report = _load_json(pack_dir / 'baseline_intake_report.json')

    chain_ids = collect_chain_materialization_targets(
        pack_dir, chain_id=chain_id, top_n=25, max_ids=limit,
    )
    capture_ids = resolve_intake_capture_card_ids(intake_report, pack['cards_by_id'])

    plan_path = pack_dir / 'acquisition_plan.json'
    plan_ids: List[str] = []
    if plan_path.exists():
        plan = _load_json(plan_path) or {}
        plan_ids = [
            b['card_id'] for b in (plan.get('stage_1_target_apis') or [])
            if b.get('card_id')
        ]

    target_ids = merge_materialization_targets(
        chain_ids,
        list(dict.fromkeys(capture_ids + plan_ids)),
        limit=limit,
    )
    if not target_ids:
        target_ids = None

    result = build_materialized_templates(
        pack['cards_by_id'],
        by_id,
        ctx,
        target_api_ids=target_ids,
        pack_dir=pack_dir,
        replay_safe_only=replay_safe_only,
        intake_report=intake_report,
    )
    result['chain_target_api_ids'] = chain_ids
    result['materialization_target_count'] = len(target_ids or [])
    tpl_path = pack_dir / 'materialized_api_templates.json'
    write_json(tpl_path, result)
    return result
