# -*- coding: utf-8 -*-
"""Unified API template lookup — align static api_id with intake synthetic templates by path."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from minidrifter.materials.intake_param_hints import normalize_api_path


def build_templates_index(
    templates_by_id: Dict[str, Dict[str, Any]],
    *,
    extra: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Build by_id + by_path indexes from materialized and synthetic templates."""
    by_id: Dict[str, Dict[str, Any]] = dict(templates_by_id or {})
    by_path: Dict[str, Dict[str, Any]] = {}

    def _register(tpl: Dict[str, Any], *, preferred_id: Optional[str] = None) -> None:
        if not tpl:
            return
        path = tpl.get('path') or ''
        norm = normalize_api_path(path)
        api_id = preferred_id or tpl.get('api_id') or tpl.get('card_id')
        if api_id:
            by_id.setdefault(str(api_id), tpl)
        if norm:
            by_path.setdefault(norm, tpl)

    for tpl in by_id.values():
        _register(tpl)
    for row in extra or []:
        synth = row.get('synthetic_template')
        if synth:
            _register(synth, preferred_id=row.get('api_id') or synth.get('api_id'))
    return {'by_id': by_id, 'by_path': by_path}


def resolve_template(
    index: Dict[str, Any],
    *,
    api_id: Optional[str] = None,
    path: Optional[str] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Resolve template by api_id first, then normalized path."""
    by_id = index.get('by_id') or {}
    by_path = index.get('by_path') or {}
    if api_id and by_id.get(api_id):
        return by_id[api_id], str(api_id)
    norm = normalize_api_path(path or '')
    if norm and by_path.get(norm):
        tpl = by_path[norm]
        tid = tpl.get('api_id') or tpl.get('card_id') or api_id
        return tpl, str(tid) if tid else api_id
    if api_id:
        for tid, tpl in by_id.items():
            if normalize_api_path(tpl.get('path') or '') == norm and norm:
                return tpl, tid
    return None, api_id


def register_enrollment_templates(
    templates_by_id: Dict[str, Dict[str, Any]],
    enrolled: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """Merge enrollment rows; alias static api_id and intake api_id for same path."""
    out = dict(templates_by_id or {})
    for row in enrolled:
        synth = row.get('synthetic_template')
        if not synth:
            continue
        path = row.get('path') or synth.get('path') or ''
        norm = normalize_api_path(path)
        api_id = row.get('api_id') or synth.get('api_id')
        if api_id:
            out[str(api_id)] = synth
        if norm:
            for key in (api_id, synth.get('api_id'), synth.get('card_id')):
                if key:
                    out[str(key)] = synth
    return out
