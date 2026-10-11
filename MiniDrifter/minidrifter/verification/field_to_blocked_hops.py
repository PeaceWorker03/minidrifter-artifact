# -*- coding: utf-8 -*-
"""field_to_blocked_hops.json — index missing fields → blocked chains/hops for partial resume."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import write_json

SCHEMA_VERSION = '1.0.0'


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_index(pack_dir: Path) -> Dict[str, Any]:
    path = Path(pack_dir) / 'field_to_blocked_hops.json'
    if path.exists():
        return json.loads(path.read_text(encoding='utf-8'))
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'index': {},
    }


def _save_index(pack_dir: Path, doc: Dict[str, Any]) -> None:
    doc['generated_at'] = _utc_now()
    write_json(Path(pack_dir) / 'field_to_blocked_hops.json', doc)


def record_blocked_hop(
    pack_dir: Path,
    field: str,
    *,
    chain_id: str,
    blocked_api_id: Optional[str] = None,
    blocked_path: str = '',
    blocked_stage: str = 'M0_BUILD',
    resume_from_hop: Optional[int] = None,
    ticket_id: Optional[str] = None,
) -> None:
    if not field:
        return
    pack_dir = Path(pack_dir)
    doc = _load_index(pack_dir)
    index = doc.setdefault('index', {})
    entries: List[Dict[str, Any]] = list(index.get(field) or [])
    entry = {
        'chain_id': chain_id,
        'blocked_api_id': blocked_api_id,
        'blocked_path': blocked_path,
        'blocked_stage': blocked_stage,
        'resume_from_hop': resume_from_hop,
        'ticket_id': ticket_id,
    }
    key = (chain_id, blocked_path, blocked_stage, ticket_id)
    if not any(
        (e.get('chain_id'), e.get('blocked_path'), e.get('blocked_stage'), e.get('ticket_id')) == key
        for e in entries
    ):
        entries.append(entry)
    index[field] = entries
    _save_index(pack_dir, doc)


def record_blocked_hops_from_ticket(
    pack_dir: Path,
    ticket: Dict[str, Any],
    *,
    hop_verdict: Optional[Dict[str, Any]] = None,
    chain_id: Optional[str] = None,
    hop_index: Optional[int] = None,
) -> None:
    cid = chain_id or ticket.get('chain_id') or ''
    path = (
        (hop_verdict or {}).get('path')
        or ticket.get('blocked_api')
        or (ticket.get('evidence') or {}).get('api')
        or ''
    )
    api_id = (hop_verdict or {}).get('api_id') or (ticket.get('evidence') or {}).get('api_id')
    stage = ticket.get('blocked_stage') or 'M0_BUILD'
    tid = ticket.get('ticket_id')
    fields = ticket.get('missing_fields') or []
    if not fields:
        for m in ticket.get('missing_materials') or []:
            if m.get('field'):
                fields.append(m['field'])
    for field in fields:
        record_blocked_hop(
            pack_dir,
            field,
            chain_id=cid or f'chain:{path}',
            blocked_api_id=api_id,
            blocked_path=path,
            blocked_stage=stage,
            resume_from_hop=hop_index or ticket.get('resume_from_hop'),
            ticket_id=tid,
        )


def chains_blocked_by_fields(pack_dir: Path, fields: List[str]) -> List[str]:
    doc = _load_index(pack_dir)
    index = doc.get('index') or {}
    chain_ids: List[str] = []
    for field in fields:
        for entry in index.get(field) or []:
            cid = entry.get('chain_id')
            if cid and cid not in chain_ids:
                chain_ids.append(cid)
    return chain_ids


def clear_field_blocks(pack_dir: Path, fields: List[str]) -> List[str]:
    """Remove index entries for resolved fields; return revived chain_ids."""
    pack_dir = Path(pack_dir)
    doc = _load_index(pack_dir)
    index = doc.get('index') or {}
    revived: List[str] = []
    for field in fields:
        for entry in index.pop(field, []) or []:
            cid = entry.get('chain_id')
            if cid and cid not in revived:
                revived.append(cid)
    _save_index(pack_dir, doc)
    return revived


def load_hop_state(pack_dir: Path) -> Dict[str, Any]:
    path = Path(pack_dir) / 'hop_state.json'
    if path.exists():
        return json.loads(path.read_text(encoding='utf-8'))
    return {'schema_version': SCHEMA_VERSION, 'chains': {}}


def record_hop_success(
    pack_dir: Path,
    chain_id: str,
    hop_index: int,
    *,
    api_id: str = '',
    path: str = '',
    outcome: str = 'm0_success',
) -> None:
    pack_dir = Path(pack_dir)
    doc = load_hop_state(pack_dir)
    chains = doc.setdefault('chains', {})
    chain = chains.setdefault(chain_id, {'hops': {}})
    hops = chain.setdefault('hops', {})
    hops[str(hop_index)] = {
        'api_id': api_id,
        'path': path,
        'outcome': outcome,
        'completed_at': _utc_now(),
    }
    write_json(pack_dir / 'hop_state.json', doc)


def hops_to_skip(pack_dir: Path, chain_id: str) -> List[int]:
    doc = load_hop_state(pack_dir)
    chain = (doc.get('chains') or {}).get(chain_id) or {}
    hops = chain.get('hops') or {}
    skip: List[int] = []
    for k, v in hops.items():
        if (v or {}).get('outcome', '').startswith('m0') or (v or {}).get('outcome', '').startswith('m7'):
            try:
                skip.append(int(k))
            except ValueError:
                pass
    return sorted(skip)
