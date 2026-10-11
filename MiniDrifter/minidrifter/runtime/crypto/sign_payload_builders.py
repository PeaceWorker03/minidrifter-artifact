# -*- coding: utf-8 -*-
"""Generic sign payload builders referenced from crypto profiles."""
from __future__ import annotations

import json
from typing import Any, Dict, Mapping, Optional


def _sorted_kv_string(params: Mapping[str, Any]) -> str:
    parts = []
    for key in sorted(params.keys()):
        val = params[key]
        if val is None:
            continue
        if isinstance(val, (dict, list)):
            val = json.dumps(val, ensure_ascii=False, separators=(',', ':'))
        parts.append(f'{key}={val}')
    return '&'.join(parts)


def build_relative_path_merge_params(
    relative_path: str,
    *,
    query: Optional[Dict[str, Any]] = None,
    body: Optional[Dict[str, Any]] = None,
) -> str:
    """Merge relative path + query/body params (uni-app / relative-url HMAC style)."""
    path = (relative_path or '').split('?', 1)[0]
    merged: Dict[str, Any] = {}
    if '?' in (relative_path or ''):
        tail = relative_path.split('?', 1)[1]
        for part in tail.split('&'):
            if not part or '=' not in part:
                continue
            k, v = part.split('=', 1)
            if k:
                merged[k] = v
    for bag in (query or {}, body or {}):
        for k, v in bag.items():
            if v is not None:
                merged[str(k)] = v
    qs = _sorted_kv_string(merged)
    return f'{path}?{qs}' if qs else path
