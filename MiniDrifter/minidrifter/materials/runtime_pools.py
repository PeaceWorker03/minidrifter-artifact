# -*- coding: utf-8 -*-
"""subject_pool / object_pool / context_pool — multi-value handles from runtime captures."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.business_chain.chain_run_context import load_json
from minidrifter.core.utils import write_json
from minidrifter.materials.intake_param_hints import load_intake_report, normalize_api_path
from minidrifter.materials.runtime_capture_index import (
    CONTEXT_FIELD_HINTS,
    OBJECT_FIELD_HINTS,
    SUBJECT_FIELD_HINTS,
    build_runtime_capture_index,
)
from minidrifter.verification.subject_override_fields import norm_field

SCHEMA_VERSION = '1.0.0'

POOL_SPECS = (
    ('subject_pool.json', SUBJECT_FIELD_HINTS, 'subject'),
    ('object_pool.json', OBJECT_FIELD_HINTS, 'object'),
    ('context_pool.json', CONTEXT_FIELD_HINTS, 'context'),
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _add_value(
    pool: Dict[str, List[Dict[str, Any]]],
    *,
    field: str,
    value: Any,
    source_capture_id: str,
    source_api: str,
    json_path: str,
    resource_type: str,
) -> None:
    if value in (None, '', [], {}):
        return
    key = norm_field(field)
    if key not in pool:
        pool[key] = []
    val_str = str(value)
    for row in pool[key]:
        if row.get('value') == val_str:
            return
    pool[key].append({
        'field': field,
        'value': val_str,
        'source_capture_id': source_capture_id,
        'source_api': source_api,
        'json_path': json_path,
        'resource_type': resource_type,
    })


def _flatten_json(obj: Any, prefix: str = '', out: Optional[List[tuple]] = None) -> List[tuple]:
    out = out or []
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f'{prefix}.{k}' if prefix else str(k)
            if isinstance(v, (dict, list)):
                _flatten_json(v, path, out)
            else:
                out.append((path, k, v))
    elif isinstance(obj, list):
        for i, item in enumerate(obj[:10]):
            _flatten_json(item, f'{prefix}[{i}]', out)
    return out


def build_runtime_pools(
    pack_dir: Path,
    *,
    capture_index_doc: Optional[Dict[str, Any]] = None,
) -> Dict[str, Dict[str, Any]]:
    pack_dir = Path(pack_dir)
    idx_doc = capture_index_doc or build_runtime_capture_index(pack_dir)
    intake = load_intake_report(pack_dir) or {}
    captures_by_id = {
        str(c.get('capture_id') or f"cap_{c.get('capture_index')}"): c
        for c in (intake.get('captures') or [])
    }

    pools: Dict[str, Dict[str, List[Dict[str, Any]]]] = {
        'subject': {},
        'object': {},
        'context': {},
    }
    hint_sets = {
        'subject': SUBJECT_FIELD_HINTS,
        'object': OBJECT_FIELD_HINTS,
        'context': CONTEXT_FIELD_HINTS,
    }

    for entry in idx_doc.get('entries') or []:
        cap_id = entry.get('capture_id') or ''
        cap = captures_by_id.get(cap_id) or {}
        path = entry.get('path') or ''
        proc = cap.get('crypto_processing') or {}
        decrypted = proc.get('decrypted') or {}
        for bag_name, bag in (
            ('request.query', decrypted.get('body_form') or {}),
            ('request.body', decrypted.get('body_form') or {}),
        ):
            if not isinstance(bag, dict):
                continue
            for field, value in bag.items():
                nf = norm_field(field)
                for pool_name, hints in hint_sets.items():
                    if nf in hints:
                        _add_value(
                            pools[pool_name],
                            field=field,
                            value=value,
                            source_capture_id=cap_id,
                            source_api=path,
                            json_path=f'{bag_name}.{field}',
                            resource_type=pool_name,
                        )
        resp = cap.get('response_crypto_processing') or {}
        body_json = resp.get('body_json')
        if isinstance(body_json, dict):
            for jpath, leaf, value in _flatten_json(body_json):
                nf = norm_field(leaf)
                for pool_name, hints in hint_sets.items():
                    if nf in hints:
                        _add_value(
                            pools[pool_name],
                            field=leaf,
                            value=value,
                            source_capture_id=cap_id,
                            source_api=path,
                            json_path=f'response.{jpath}',
                            resource_type=pool_name,
                        )

    baseline = load_json(pack_dir / 'baseline_runtime_context.json') or {}
    for field, meta in (baseline.get('resolved_fields') or {}).items():
        if not isinstance(meta, dict):
            continue
        nf = norm_field(field)
        for pool_name, hints in hint_sets.items():
            if nf in hints:
                _add_value(
                    pools[pool_name],
                    field=field,
                    value=meta.get('value'),
                    source_capture_id='baseline_runtime_context',
                    source_api=meta.get('source') or 'baseline',
                    json_path=f'resolved_fields.{field}',
                    resource_type=pool_name,
                )

    docs: Dict[str, Dict[str, Any]] = {}
    for filename, _, pool_name in POOL_SPECS:
        rows = pools[pool_name]
        multi = {k: v for k, v in rows.items() if len(v) >= 2}
        docs[filename] = {
            'schema_version': SCHEMA_VERSION,
            'generated_at': _utc_now(),
            'pack_dir': str(pack_dir),
            'pool_type': pool_name,
            'summary': {
                'field_kinds': len(rows),
                'multi_value_fields': len(multi),
                'total_values': sum(len(v) for v in rows.values()),
            },
            'fields': rows,
        }
    return docs


def write_runtime_pools(pack_dir: Path) -> Dict[str, Path]:
    pack_dir = Path(pack_dir)
    docs = build_runtime_pools(pack_dir)
    out: Dict[str, Path] = {}
    for filename in docs:
        path = pack_dir / filename
        write_json(path, docs[filename])
        out[filename] = path
    return out
