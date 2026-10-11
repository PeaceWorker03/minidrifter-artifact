# -*- coding: utf-8 -*-
"""Mine object identifier fields on request wire (addressId, orderId, …)."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.business_chain.chain_run_context import load_json
from minidrifter.classification.api_plane_classifier import (
    classify_path_to_plane_entry,
    plane_index_by_path,
)
from minidrifter.core.utils import write_json
from minidrifter.materials.intake_param_hints import load_intake_report, normalize_api_path
from minidrifter.materials.object_pool_writer import load_baseline_field_pool

SCHEMA_VERSION = '1.0.0'

OBJECT_FIELD_RE = re.compile(
    r'^(ids?|addressid|orderid|invoiceid|couponid|ticketid|recordid|cardid|'
    r'shopid|goodsid|productid|skuid|cartid|deliveryid|paymentid|'
    r'ids\[\d+\])$',
    re.I,
)

SENSITIVE_PLANES = frozenset({
    'user_profile_personal_info',
    'contact_address_invoice',
    'account_state_wallet',
    'business_object',
    'action_operation',
})


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _is_object_field(name: str) -> bool:
    norm = str(name or '').strip()
    if not norm:
        return False
    if norm.lower() in {'userid', 'customerid', 'logincustomerid', 'appletid', 'apitoken', 'nonce', 'timestamp', 'signature'}:
        return False
    return bool(OBJECT_FIELD_RE.match(norm.replace('_', '')) or OBJECT_FIELD_RE.match(norm))


def _wire_from_capture(cap: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    proc = cap.get('crypto_processing') or {}
    decrypted = proc.get('decrypted') or {}
    query = decrypted.get('query') if isinstance(decrypted.get('query'), dict) else {}
    for k, v in (query or {}).items():
        if _is_object_field(str(k)):
            rows.append({
                'field': str(k),
                'location': 'query',
                'value_sample': str(v)[:32] if v is not None else '',
                'source': 'capture_query',
            })
    body_raw = decrypted.get('body_form')
    if isinstance(body_raw, str) and body_raw.strip().startswith('{'):
        try:
            body = json.loads(body_raw)
            if isinstance(body, dict):
                for k, v in body.items():
                    if _is_object_field(str(k)):
                        rows.append({
                            'field': str(k),
                            'location': 'body',
                            'value_sample': str(v)[:32] if v is not None else '',
                            'source': 'capture_body',
                        })
        except json.JSONDecodeError:
            pass
    return rows


def _pool_object_field_names(pack_dir: Path) -> List[str]:
    pool = load_baseline_field_pool(pack_dir)
    return sorted(
        k for k in (pool.get('fields') or {})
        if _is_object_field(str(k))
    )


def mine_object_wire_candidates(
    pack_dir: Path,
    *,
    write: bool = False,
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    intake = load_intake_report(pack_dir) or {}
    pool_hints = _pool_object_field_names(pack_dir)
    by_path: Dict[str, Dict[str, Any]] = {}

    for cap in intake.get('captures') or []:
        path = normalize_api_path(cap.get('path') or '')
        if not path:
            continue
        wire = _wire_from_capture(cap)
        if not wire:
            continue
        row = by_path.setdefault(path, {
            'path': path,
            'capture_index': cap.get('capture_index'),
            'wire_object_fields': [],
            'object_field_names': [],
        })
        seen = {f['field'] for f in row['wire_object_fields']}
        for f in wire:
            if f['field'] not in seen:
                row['wire_object_fields'].append(f)
                seen.add(f['field'])
        row['object_field_names'] = sorted(seen)

    candidates: List[Dict[str, Any]] = []
    for path in sorted(by_path.keys()):
        entry = plane_index_by_path(pack_dir).get(path) or classify_path_to_plane_entry(path)
        plane = entry.get('primary_plane') or ''
        if plane not in SENSITIVE_PLANES and not by_path[path].get('wire_object_fields'):
            continue
        row = by_path[path]
        row['primary_plane'] = plane
        row['mutation_type'] = 'object_override'
        candidates.append(row)

    if pool_hints:
        for row in candidates:
            names = set(row.get('object_field_names') or [])
            for f in pool_hints:
                if f not in names:
                    row['wire_object_fields'].append({
                        'field': f, 'location': 'pool', 'source': 'object_pool',
                    })
                    names.add(f)
            row['object_field_names'] = sorted(names)

    doc = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'candidate_count': len(candidates),
        'candidates': candidates,
    }
    if write:
        write_json(pack_dir / 'object_wire_candidates.json', doc)
    return doc


def build_object_wire_candidates(pack_dir: Path) -> Path:
    doc = mine_object_wire_candidates(pack_dir, write=True)
    return pack_dir / 'object_wire_candidates.json'
