# -*- coding: utf-8
"""Run identity and cross-artifact consistency for business chain pipeline."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import stable_id

CHAIN_ARTIFACT_FILES = (
    'business_chains.json',
    'chain_rank_plan.json',
    'chain_material_request_plan.json',
    'business_chain_graph.json',
    'business_api_transitions.json',
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def make_run_id(pack_label: str = 'pack') -> str:
    ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    safe = ''.join(c if c.isalnum() or c in '-_' else '_' for c in (pack_label or 'pack'))
    return f'{ts}_{safe}'


def make_chain_id(chain: Dict[str, Any]) -> str:
    """Unique chain id from full hop path + binding/mutation fields."""
    hops = chain.get('hops') or []
    hop_ids = '->'.join(h.get('api_id') or '' for h in hops)
    hop_paths = '->'.join(h.get('path') or '' for h in hops)
    binding = '|'.join(sorted(chain.get('binding_fields') or []))
    mut = '|'.join(sorted(
        f for h in hops for f in (h.get('mutation_targets') or [])
    ))
    return stable_id(
        'chain',
        chain.get('entry_api') or '',
        chain.get('target_hop') or '',
        hop_ids,
        hop_paths,
        binding,
        mut,
    )


def chain_path_signature(chain: Dict[str, Any]) -> str:
    hops = chain.get('hops') or []
    return '->'.join(h.get('path') or h.get('api_id') or '' for h in hops)


def stamp_run_context(
    doc: Dict[str, Any],
    *,
    run_id: str,
    artifact_name: str,
    pack_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    out = dict(doc)
    out['run_id'] = run_id
    out['artifact'] = artifact_name
    out['source_inputs'] = {
        name: str((Path(pack_dir) / name) if pack_dir else name)
        for name in CHAIN_ARTIFACT_FILES
    }
    return out


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding='utf-8'))


def validate_chain_pack_consistency(
    pack_dir: Path,
    *,
    require_top_chain: bool = True,
) -> Dict[str, Any]:
    """Ensure chain artifacts share run_id and rank_plan Top1 exists in business_chains."""
    pack_dir = Path(pack_dir)
    chains_doc = load_json(pack_dir / 'business_chains.json')
    rank_doc = load_json(pack_dir / 'chain_rank_plan.json')
    plan_doc = load_json(pack_dir / 'chain_material_request_plan.json')

    errors: List[str] = []
    run_ids: Dict[str, Optional[str]] = {
        'business_chains': chains_doc.get('run_id'),
        'chain_rank_plan': rank_doc.get('run_id'),
        'chain_material_request_plan': plan_doc.get('run_id'),
    }
    present = {k: v for k, v in run_ids.items() if v}
    if len(set(present.values())) > 1:
        errors.append(f'run_id_mismatch:{present}')
    if not present:
        errors.append('missing_run_id_on_chain_artifacts')

    by_id = {c['chain_id']: c for c in (chains_doc.get('chains') or []) if c.get('chain_id')}
    chain_ids = list(by_id.keys())
    if chain_ids and len(chain_ids) != len(set(chain_ids)):
        errors.append(f'duplicate_chain_ids:{len(chain_ids) - len(set(chain_ids))}')

    top_ranked = (rank_doc.get('top_chains') or [None])[0]
    top_cid = (top_ranked or {}).get('chain_id')
    top_in_chains = bool(top_cid and top_cid in by_id)
    if require_top_chain and top_cid and not top_in_chains:
        errors.append(f'stale_chain_reference:top_chain_id={top_cid}')

    return {
        'valid': not errors,
        'errors': errors,
        'run_id': next(iter(present.values()), None),
        'top_chain_id': top_cid,
        'top_chain_in_business_chains': top_in_chains,
        'chain_count': len(by_id),
        'unique_chain_ids': len(set(chain_ids)),
        'checked_at': _utc_now(),
    }


def load_chain_registry(pack_dir: Path) -> Dict[str, Dict[str, Any]]:
    """Merge static business chains and runtime object-flow chains."""
    pack_dir = Path(pack_dir)
    by_id: Dict[str, Dict[str, Any]] = {}
    for fname in ('business_chains.json', 'object_flow_chains.json'):
        doc = load_json(pack_dir / fname)
        for c in (doc.get('chains') or []):
            cid = c.get('chain_id')
            if cid:
                by_id[cid] = c
    return by_id


def select_top_ranked_chain(
    pack_dir: Path,
    *,
    chain_id: Optional[str] = None,
    chains_doc: Optional[Dict[str, Any]] = None,
    rank_plan: Optional[Dict[str, Any]] = None,
) -> tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    """Select chain for chain_strict — Top1 from rank_plan only, no stale fallback."""
    pack_dir = Path(pack_dir)
    chains_doc = chains_doc or load_json(pack_dir / 'business_chains.json')
    rank_plan = rank_plan or load_json(pack_dir / 'chain_rank_plan.json')
    by_id = load_chain_registry(pack_dir)

    meta: Dict[str, Any] = {
        'selected_from_current_rank_plan': False,
        'chain_id_exists_in_business_chains': False,
        'stale_chain_reference': False,
        'run_id': chains_doc.get('run_id'),
    }

    if chain_id:
        if chain_id in by_id:
            meta['chain_id_exists_in_business_chains'] = True
            meta['selected_chain_id'] = chain_id
            return by_id[chain_id], meta
        meta['stale_chain_reference'] = True
        meta['selected_chain_id'] = chain_id
        return None, meta

    top = (rank_plan.get('top_chains') or [None])[0]
    if not top:
        return None, meta

    cid = top.get('chain_id')
    meta['selected_chain_id'] = cid
    meta['selected_from_current_rank_plan'] = True
    if cid and cid in by_id:
        meta['chain_id_exists_in_business_chains'] = True
        return by_id[cid], meta

    meta['stale_chain_reference'] = True
    return None, meta
