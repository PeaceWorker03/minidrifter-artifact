# -*- coding: utf-8 -*-
"""Deterministic sensitive-content fingerprint for binding drift oracle."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Set

DEFAULT_PII_PATHS = (
    'identityInfo',
    'drivingLicenceInfo',
    'memberName',
    'decodeNo',
    'idNo',
    'realName',
    'identityCard',
    'licenseNo',
)


def _norm_key(key: str) -> str:
    return ''.join(ch for ch in str(key or '').lower() if ch.isalnum())


def _pick_subtree(body: Any, path: str) -> Any:
    if not isinstance(body, dict) or not path:
        return None
    parts = path.split('.')
    cur: Any = body
    for part in parts:
        if not isinstance(cur, dict):
            return None
        target = _norm_key(part)
        nxt = None
        for k, v in cur.items():
            if _norm_key(k) == target:
                nxt = v
                break
        if nxt is None:
            return None
        cur = nxt
    return cur


def extract_sensitive_slices(
    body: Any,
    *,
    fields: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Extract comparable PII slices from decrypted response body."""
    if body is None:
        return {}
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            return {'_raw': body[:500]}
    if not isinstance(body, dict):
        return {'_value': body}

    want = list(fields or DEFAULT_PII_PATHS)
    out: Dict[str, Any] = {}
    for spec in want:
        if '.' in spec:
            val = _pick_subtree(body, spec)
            if val not in (None, '', [], {}):
                out[spec] = val
            continue
        target = _norm_key(spec)
        for k, v in body.items():
            if _norm_key(k) == target and v not in (None, '', [], {}):
                out[spec] = v
                break
    if not out:
        for k in ('identityInfo', 'drivingLicenceInfo', 'data', 'result', 'content'):
            if k in body and body[k] not in (None, '', [], {}):
                out[k] = body[k]
    return out


def fingerprint_sensitive_content(
    body: Any,
    *,
    fields: Optional[List[str]] = None,
) -> Dict[str, Any]:
    slices = extract_sensitive_slices(body, fields=fields)
    canonical = json.dumps(slices, sort_keys=True, ensure_ascii=False, default=str)
    digest = hashlib.sha256(canonical.encode('utf-8')).hexdigest()[:16]
    return {
        'slices': slices,
        'digest': digest,
        'non_empty': bool(slices),
    }


def fingerprints_differ(
    m0_body: Any,
    m7_body: Any,
    *,
    fields: Optional[List[str]] = None,
) -> bool:
    fp0 = fingerprint_sensitive_content(m0_body, fields=fields)
    fp7 = fingerprint_sensitive_content(m7_body, fields=fields)
    if not fp0['non_empty'] and not fp7['non_empty']:
        return False
    if fp0['non_empty'] != fp7['non_empty']:
        return True
    return fp0['digest'] != fp7['digest']


def m7_empty_but_m0_has_pii(m0_body: Any, m7_body: Any, *, fields: Optional[List[str]] = None) -> bool:
    fp0 = fingerprint_sensitive_content(m0_body, fields=fields)
    fp7 = fingerprint_sensitive_content(m7_body, fields=fields)
    return bool(fp0['non_empty'] and not fp7['non_empty'])
