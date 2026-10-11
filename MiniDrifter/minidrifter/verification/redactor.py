# -*- coding: utf-8 -*-
"""Redact secrets from requests/responses for evidence storage."""
from __future__ import annotations

import copy
import re
from typing import Any, Dict, List, Set

REDACT_HEADERS = frozenset({
    'token', 'authorization', 'appidentity', 'cookie', 'set-cookie',
})
REDACT_FIELD_NAMES = frozenset({
    'token', 'authorization', 'appidentity', 'password', 'phone', 'mobile',
    'idcard', 'identity', 'secret', 'code',
})


def _mask(value: str, keep: int = 4) -> str:
    if not value or len(value) <= keep * 2:
        return '***'
    return value[:keep] + '...' + value[-keep:]


def redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    out = {}
    for k, v in (headers or {}).items():
        if k.lower() in REDACT_HEADERS:
            out[k] = _mask(str(v))
        else:
            out[k] = str(v)
    return out


def redact_value(key: str, value: Any) -> Any:
    if key.lower() in REDACT_FIELD_NAMES and isinstance(value, str):
        return _mask(value)
    return value


def redact_dict(obj: Any, depth: int = 0) -> Any:
    if depth > 12:
        return '...'
    if isinstance(obj, dict):
        return {k: redact_value(k, redact_dict(v, depth + 1)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_dict(x, depth + 1) for x in obj[:50]]
    return obj


def redact_request_preview(preview: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(preview)
    if out.get('headers'):
        out['headers'] = redact_headers(out['headers'])
    return out
