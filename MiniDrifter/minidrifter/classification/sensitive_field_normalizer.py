# -*- coding: utf-8 -*-
"""Sensitive field alias normalization (P4) — project-agnostic."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.classification.api_plane_classifier import load_sensitive_field_ontology

_ALIAS_INDEX: Optional[Dict[str, Set[str]]] = None
_REVERSE_ALIAS: Optional[Dict[str, str]] = None


def _reset_cache() -> None:
    global _ALIAS_INDEX, _REVERSE_ALIAS
    _ALIAS_INDEX = None
    _REVERSE_ALIAS = None


def _norm_key(key: str) -> str:
    return re.sub(r'[^a-z0-9]', '', str(key or '').lower())


def build_alias_index(ontology: Optional[Dict[str, Any]] = None) -> Dict[str, Set[str]]:
    """canonical_field -> set of normalized alias keys."""
    global _ALIAS_INDEX, _REVERSE_ALIAS
    if _ALIAS_INDEX is not None and ontology is None:
        return _ALIAS_INDEX

    ontology = ontology or load_sensitive_field_ontology()
    index: Dict[str, Set[str]] = {}

    for canonical, aliases in (ontology.get('field_aliases') or {}).items():
        bucket = index.setdefault(str(canonical), set())
        bucket.add(_norm_key(canonical))
        for alias in aliases:
            bucket.add(_norm_key(alias))

    for cls, names in (ontology.get('field_classes') or {}).items():
        for name in names:
            nk = _norm_key(name)
            for canonical, aliases in (ontology.get('field_aliases') or {}).items():
                if nk in {_norm_key(a) for a in aliases} or nk == _norm_key(canonical):
                    index.setdefault(canonical, set()).add(nk)
                    break
            else:
                index.setdefault(_norm_key(name), set()).add(nk)

    for plane in (ontology.get('planes') or {}).values():
        for name in (plane.get('response_keys') or []) + (plane.get('param_names') or []):
            nk = _norm_key(name)
            matched = False
            for canonical, aliases in (ontology.get('field_aliases') or {}).items():
                if nk in {_norm_key(a) for a in aliases} or nk == _norm_key(canonical):
                    index.setdefault(canonical, set()).add(nk)
                    matched = True
                    break
            if not matched:
                index.setdefault(nk, set()).add(nk)

    _ALIAS_INDEX = index
    _REVERSE_ALIAS = {}
    for canonical, aliases in index.items():
        for alias in aliases:
            _REVERSE_ALIAS.setdefault(alias, canonical)
    return index


def reverse_alias_index(ontology: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    if _REVERSE_ALIAS is None or ontology is not None:
        build_alias_index(ontology)
    return _REVERSE_ALIAS or {}


def normalize_field_name(raw: str, *, ontology: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """Map raw response/pool key to canonical sensitive field id."""
    nk = _norm_key(raw)
    if not nk:
        return None
    rev = reverse_alias_index(ontology)
    if nk in rev:
        return rev[nk]
    if re.search(r'(phone|mobile|tel)', nk):
        return 'phone'
    if re.search(r'(idno|idcard|identity|certno)', nk):
        return 'id_card'
    if re.search(r'(integral|point|score|remainmoney|money)', nk):
        return 'points' if 'point' in nk or 'score' in nk else 'balance'
    if re.search(r'(authstatus|realnamestatus|verifystatus)', nk):
        return nk.replace('status', '_status') if 'status' in nk else None
    if nk in {'name', 'realname', 'username', 'nickname', 'maskname'}:
        return 'name'
    if nk in {'balance', 'walletamount', 'remainamount', 'remainmoney', 'money'}:
        return 'balance'
    if re.search(r'(address|mapaddress|detailaddress)', nk) and 'addressid' not in nk:
        return 'address_text'
    return None


def canonical_fields_for_plane(plane_id: str, ontology: Optional[Dict[str, Any]] = None) -> List[str]:
    ontology = ontology or load_sensitive_field_ontology()
    explicit = (ontology.get('plane_canonical_fields') or {}).get(plane_id)
    if explicit:
        return list(explicit)
    mapping = {
        'user_profile_personal_info': 'personal_info',
        'realname_verification': 'verification',
        'account_state_wallet': 'account_state',
        'contact_address_invoice': 'address_invoice',
        'business_object': 'business_object',
        'credential_session': 'subject_identity',
    }
    cls = mapping.get(plane_id)
    if not cls:
        return []
    names = (ontology.get('field_classes') or {}).get(cls) or []
    out: List[str] = []
    for name in names:
        canon = normalize_field_name(name, ontology=ontology) or _norm_key(name)
        if canon not in out:
            out.append(canon)
    return out


def pool_has_canonical(
    canonical: str,
    pool_keys: Set[str],
    pool_values: Optional[Dict[str, Any]] = None,
    *,
    ontology: Optional[Dict[str, Any]] = None,
) -> bool:
    """True if pool keys/values satisfy canonical field via alias index."""
    ontology = ontology or load_sensitive_field_ontology()
    index = build_alias_index(ontology)
    aliases = index.get(canonical) or index.get(_norm_key(canonical)) or {_norm_key(canonical)}
    key_norms = {_norm_key(k) for k in pool_keys}
    if aliases & key_norms:
        return True
    if pool_values:
        for k, v in pool_values.items():
            if v in (None, ''):
                continue
            nk = _norm_key(k)
            if nk in aliases:
                return True
            canon = normalize_field_name(k, ontology=ontology)
            if canon == canonical or _norm_key(canon or '') == _norm_key(canonical):
                return True
    return False


def missing_canonical_for_plane(
    plane_id: str,
    pool_keys: Set[str],
    pool_values: Optional[Dict[str, Any]] = None,
    *,
    ontology: Optional[Dict[str, Any]] = None,
    min_satisfied: int = 1,
) -> List[str]:
    canonicals = canonical_fields_for_plane(plane_id, ontology)
    if not canonicals:
        return []
    satisfied = [
        c for c in canonicals
        if pool_has_canonical(c, pool_keys, pool_values, ontology=ontology)
    ]
    if len(satisfied) >= min_satisfied:
        return []
    return [c for c in canonicals if not pool_has_canonical(c, pool_keys, pool_values, ontology=ontology)]


def plane_baseline_satisfied(
    plane_id: str,
    pool_keys: Set[str],
    pool_values: Optional[Dict[str, Any]] = None,
    *,
    ontology: Optional[Dict[str, Any]] = None,
) -> bool:
    canonicals = canonical_fields_for_plane(plane_id, ontology)
    if not canonicals:
        return True
    min_needed = 1
    if plane_id in {'user_profile_personal_info', 'account_state_wallet', 'realname_verification'}:
        min_needed = 1
    satisfied = sum(
        1 for c in canonicals
        if pool_has_canonical(c, pool_keys, pool_values, ontology=ontology)
    )
    return satisfied >= min_needed


def mask_sensitive_value(canonical: str, value: Any) -> str:
    if value in (None, ''):
        return 'absent'
    s = str(value).strip()
    if not s:
        return 'absent'
    canon = _norm_key(canonical)
    if canon in {'phone', 'mobile', 'tel'} or 'phone' in canon:
        digits = re.sub(r'\D', '', s)
        if len(digits) >= 7:
            return f'{digits[:3]}******{digits[-2:]}'
        return 'present'
    if canon in {'idcard', 'idno', 'id_card'} or 'id' in canon:
        if '*' in s or len(s) <= 4:
            return s
        return 'present'
    if canon in {'name', 'realname', 'nickname'}:
        if '*' in s or len(s) <= 2:
            return s
        return 'present'
    if canon in {'email'} and '@' in s:
        local, _, domain = s.partition('@')
        return f'{local[:1]}***@{domain}' if local else 'present'
    return 'present'


def detect_normalized_sensitive_fields(
    body: Any,
    *,
    ontology: Optional[Dict[str, Any]] = None,
    path: str = '',
) -> List[Dict[str, Any]]:
    """Return [{raw_field, normalized_field, plane, masked_value}, ...]."""
    ontology = ontology or load_sensitive_field_ontology()
    flat = _flatten_values(body if isinstance(body, dict) else {})
    plane_for_canonical: Dict[str, str] = {}
    for plane_id in (ontology.get('plane_canonical_fields') or {}):
        for canon in canonical_fields_for_plane(plane_id, ontology):
            plane_for_canonical.setdefault(canon, plane_id)

    found: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str]] = set()
    for raw_key, val in flat.items():
        if val in (None, '', [], {}):
            continue
        leaf = raw_key.split('.')[-1]
        canon = normalize_field_name(leaf, ontology=ontology)
        if not canon:
            continue
        pair = (leaf, canon)
        if pair in seen:
            continue
        seen.add(pair)
        found.append({
            'raw_field': leaf,
            'normalized_field': canon,
            'plane': plane_for_canonical.get(canon, 'user_profile_personal_info'),
            'masked_value': mask_sensitive_value(canon, val),
        })
    return sorted(found, key=lambda x: (x['plane'], x['normalized_field'], x['raw_field']))


def extract_canonical_fields_from_body(
    body: Any,
    *,
    ontology: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Map canonical field ids to raw values from response body."""
    out: Dict[str, Any] = {}
    for row in detect_normalized_sensitive_fields(body, ontology=ontology):
        canon = row['normalized_field']
        raw = row['raw_field']
        val = _flatten_values(body if isinstance(body, dict) else {}).get(raw)
        if val is None:
            for k, v in _flatten_values(body if isinstance(body, dict) else {}).items():
                if k.split('.')[-1] == raw:
                    val = v
                    break
        if val not in (None, ''):
            out[canon] = val
    return out


def expand_canonical_aliases(
    fields: Dict[str, Any],
    *,
    ontology: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Add canonical keys alongside raw harvest keys (non-destructive merge)."""
    ontology = ontology or load_sensitive_field_ontology()
    out = dict(fields)
    for raw_key, val in list(fields.items()):
        if val in (None, ''):
            continue
        canon = normalize_field_name(raw_key, ontology=ontology)
        if canon and canon not in out:
            out[canon] = val
    return out


def _flatten_values(obj: Any, out: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    out = out or {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                _flatten_values(v, out)
            else:
                out[str(k)] = v
    elif isinstance(obj, list):
        for item in obj[:8]:
            _flatten_values(item, out)
    return out


def sensitive_fields_in_body_normalized(
    body: Any,
    *,
    ontology: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """Legacy list of raw field names plus normalized canonical hits."""
    rows = detect_normalized_sensitive_fields(body, ontology=ontology)
    raw = [r['raw_field'] for r in rows]
    canon = [r['normalized_field'] for r in rows]
    return sorted(set(raw + canon))
