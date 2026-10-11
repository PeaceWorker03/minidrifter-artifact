# -*- coding: utf-8
"""Generic nested object harvest from baseline API responses."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.materials.intake_param_hints import normalize_api_path

# Field-name evidence (case-insensitive match on normalized key)
_FIELD_PATTERNS: Dict[str, re.Pattern] = {
    'order': re.compile(
        r'^(order_?id|order_?no|trade_?no|bill_?id|orderid|orderno)$', re.I,
    ),
    'task': re.compile(r'^(task_?id|taskid)$', re.I),
    'member': re.compile(r'^(member_?id|user_?id|userid|memberid|open_?id|openid)$', re.I),
    'device': re.compile(r'^(device_?id|deviceid|vehicle_?id|vehicleid)$', re.I),
    'dept': re.compile(r'^(dept_?id|deptid|store_?id|storeid|city_?id|cityid)$', re.I),
    'card': re.compile(r'^(card_?id|cardid|coupon_?id)$', re.I),
}

_PARENT_ORDER = frozenset({
    'orderlist', 'orders', 'order', 'orderdata', 'orderlistdata',
})
_PARENT_TASK = frozenset({'tasklist', 'tasks', 'task', 'taskdata'})
_PARENT_MEMBER = frozenset({'memberlist', 'members', 'member', 'userlist', 'users', 'user'})
_PARENT_LIST = frozenset({'list', 'records', 'items', 'rows', 'data', 'result', 'content'})
_ORDER_SIBLINGS = frozenset({
    'orderno', 'orderstatus', 'amount', 'paystatus', 'createtime', 'pickuptime',
    'orderamount', 'ordertypedesc', 'returntime',
})
_TASK_SIBLINGS = frozenset({'taskname', 'taskstatus', 'tasktype'})
_ID_FALLBACK = re.compile(r'^id$', re.I)

_PATH_DOMAIN_HINTS: Dict[str, Tuple[str, ...]] = {
    'order': ('/order/', 'orderlist', 'getorderlist', 'orderdetail', 'cardorder'),
    'task': ('/task/', 'tasklist', 'pickuptask', 'deposit/task'),
    'member': ('/member/', '/account/', '/student/', 'memberinfo', 'userinfo'),
    'device': ('/device/', 'vehicle', 'digitalkey', 'hicar'),
    'dept': ('/dept/', 'deptlist', 'listandmap', 'citylist', 'store'),
}

_FIELD_ALIASES: Dict[str, List[str]] = {
    'orderId': ['OrderId', 'order_id', 'id'],
    'orderNo': ['OrderNo', 'order_no'],
    'taskId': ['TaskId', 'task_id'],
    'memberId': ['MemberId', 'userId', 'UserId'],
    'deviceId': ['DeviceId', 'vehicleId'],
    'deptId': ['DeptId', 'storeId'],
}


@dataclass
class HarvestCandidate:
    field: str
    value: Any
    object_type: str
    response_path: str
    confidence: float
    parent_keys: List[str] = field(default_factory=list)
    sibling_keys: List[str] = field(default_factory=list)
    api_path: str = ''
    capture_label: str = ''


def _norm_key(k: str) -> str:
    return re.sub(r'[_\-\s]', '', str(k or '')).lower()


def _infer_object_type_from_field(field_name: str) -> Optional[str]:
    for obj_type, pat in _FIELD_PATTERNS.items():
        if pat.match(str(field_name or '').strip()):
            return obj_type
    return None


def _path_domain(api_path: str) -> Optional[str]:
    low = normalize_api_path(api_path).lower()
    for domain, hints in _PATH_DOMAIN_HINTS.items():
        if any(h in low for h in hints):
            return domain
    return None


def _parent_object_hint(parent_keys: List[str]) -> Optional[str]:
    norms = {_norm_key(p) for p in parent_keys}
    if norms & _PARENT_ORDER:
        return 'order'
    if norms & _PARENT_TASK:
        return 'task'
    if norms & _PARENT_MEMBER:
        return 'member'
    return None


def _score_candidate(
    field_name: str,
    value: Any,
    *,
    parent_keys: List[str],
    sibling_keys: Set[str],
    api_path: str,
) -> Tuple[str, float]:
    if value in (None, ''):
        return 'generic', 0.0
    if isinstance(value, (dict, list)):
        return 'generic', 0.0

    field_type = _infer_object_type_from_field(field_name)
    parent_hint = _parent_object_hint(parent_keys)
    path_domain = _path_domain(api_path)
    sib_norms = {_norm_key(s) for s in sibling_keys}

    obj_type = field_type or parent_hint or path_domain or 'generic'
    score = 0.0

    if field_type:
        score += 0.42
    elif _ID_FALLBACK.match(field_name):
        score += 0.12
        if parent_hint:
            score += 0.18
            obj_type = parent_hint
        elif path_domain:
            score += 0.12
            obj_type = path_domain
    else:
        return obj_type, 0.0

    if parent_hint and parent_hint == obj_type:
        score += 0.22
    if path_domain and path_domain == obj_type:
        score += 0.18
    if obj_type == 'order' and sib_norms & _ORDER_SIBLINGS:
        score += 0.12
    if obj_type == 'task' and sib_norms & _TASK_SIBLINGS:
        score += 0.10
    if isinstance(value, str) and len(str(value).strip()) >= 4:
        score += 0.04

    return obj_type, min(score, 0.99)


def _walk_json(
    obj: Any,
    *,
    api_path: str,
    capture_label: str,
    prefix: str = '$',
    parent_keys: Optional[List[str]] = None,
    out: Optional[List[HarvestCandidate]] = None,
) -> List[HarvestCandidate]:
    if out is None:
        out = []
    parents = list(parent_keys or [])

    if isinstance(obj, dict):
        sibling_keys = set(obj.keys())
        for k, v in obj.items():
            path = f'{prefix}.{k}' if prefix != '$' else f'$.{k}'
            obj_type, conf = _score_candidate(
                k, v,
                parent_keys=parents + [k],
                sibling_keys=sibling_keys,
                api_path=api_path,
            )
            if conf >= 0.35 and not isinstance(v, (dict, list)):
                out.append(HarvestCandidate(
                    field=k,
                    value=v,
                    object_type=obj_type,
                    response_path=path,
                    confidence=conf,
                    parent_keys=parents + [k],
                    sibling_keys=sorted(sibling_keys)[:12],
                    api_path=api_path,
                    capture_label=capture_label,
                ))
            if isinstance(v, (dict, list)):
                _walk_json(
                    v, api_path=api_path, capture_label=capture_label,
                    prefix=path, parent_keys=parents + [k], out=out,
                )
    elif isinstance(obj, list):
        for i, item in enumerate(obj[:25]):
            _walk_json(
                item, api_path=api_path, capture_label=capture_label,
                prefix=f'{prefix}[{i}]', parent_keys=parents, out=out,
            )
    return out


def _body_from_capture(cap: Dict[str, Any]) -> Any:
    resp_proc = cap.get('response_crypto_processing') or {}
    body = resp_proc.get('body_json')
    if body is not None:
        return body
    preview = cap.get('response_body_preview') or cap.get('body_preview') or ''
    if isinstance(preview, str) and preview.strip().startswith(('{', '[')):
        try:
            return json.loads(preview)
        except json.JSONDecodeError:
            return None
    return None


def _canonical_field(field: str, object_type: str) -> str:
    """Prefer camelCase canonical names for pool keys."""
    mapping = {
        ('order', 'orderid'): 'orderId',
        ('order', 'orderno'): 'orderNo',
        ('order', 'id'): 'orderId',
        ('task', 'taskid'): 'taskId',
        ('task', 'id'): 'taskId',
        ('member', 'userid'): 'userId',
        ('member', 'memberid'): 'memberId',
        ('device', 'deviceid'): 'deviceId',
        ('dept', 'deptid'): 'deptId',
        ('dept', 'cityid'): 'cityId',
        ('card', 'cardid'): 'cardId',
    }
    nk = _norm_key(field)
    return mapping.get((object_type, nk), field)


def harvest_objects_from_captures(
    captures: List[Dict[str, Any]],
    *,
    pack_dir: Optional[Any] = None,
) -> Dict[str, Any]:
    """Scan all captures; return objects, flat field merge, and provenance."""
    all_candidates: List[HarvestCandidate] = []
    for cap in captures:
        body = _body_from_capture(cap)
        if body is None:
            continue
        idx = cap.get('capture_index')
        path = normalize_api_path(cap.get('path') or '')
        source_file = cap.get('source_file') or cap.get('source_label') or f'capture_{idx}'
        all_candidates.extend(_walk_json(
            body, api_path=path, capture_label=str(source_file),
        ))

    # Best candidate per (object_type, canonical_field)
    best: Dict[Tuple[str, str], HarvestCandidate] = {}
    for cand in all_candidates:
        canon = _canonical_field(cand.field, cand.object_type)
        key = (cand.object_type, canon)
        prev = best.get(key)
        if prev is None or cand.confidence > prev.confidence:
            best[key] = HarvestCandidate(
                field=canon,
                value=cand.value,
                object_type=cand.object_type,
                response_path=cand.response_path,
                confidence=cand.confidence,
                parent_keys=cand.parent_keys,
                sibling_keys=cand.sibling_keys,
                api_path=cand.api_path,
                capture_label=cand.capture_label,
            )

    objects: List[Dict[str, Any]] = []
    flat_fields: Dict[str, Any] = {}
    flat_sources: Dict[str, str] = {}

    for (obj_type, canon_field), cand in sorted(best.items(), key=lambda x: -x[1].confidence):
        aliases = list(dict.fromkeys(
            [cand.field, canon_field] + _FIELD_ALIASES.get(canon_field, [])
        ))
        prov = {
            'capture': cand.capture_label,
            'api': cand.api_path,
            'response_path': cand.response_path,
            'confidence': round(cand.confidence, 3),
            'parent_keys': cand.parent_keys[-3:],
            'sibling_keys': cand.sibling_keys[:6],
        }
        objects.append({
            'object_type': obj_type,
            'field': canon_field,
            'value': cand.value,
            'source': prov,
            'confidence': round(cand.confidence, 3),
            'aliases': aliases,
        })
        if canon_field not in flat_fields:
            flat_fields[canon_field] = cand.value
            flat_sources[canon_field] = (
                f'{cand.capture_label}::{cand.api_path}::{cand.response_path}'
            )
        for alias in aliases:
            if alias not in flat_fields:
                flat_fields[alias] = cand.value
                flat_sources[alias] = flat_sources[canon_field]

    return {
        'schema_version': '1.0.0',
        'object_count': len(objects),
        'objects': objects,
        'fields': flat_fields,
        'field_sources': flat_sources,
        'field_count': len(flat_fields),
        'candidate_count': len(all_candidates),
    }


def merge_harvest_into_aggregate(
    aggregate: Dict[str, Any],
    harvest: Dict[str, Any],
) -> Dict[str, Any]:
    """Merge harvested fields into decrypted_fields_aggregate without overwriting higher-priority sources."""
    merged = dict(aggregate.get('fields') or {})
    sources = dict(aggregate.get('sources') or {})
    for k, v in (harvest.get('fields') or {}).items():
        if v in (None, ''):
            continue
        if k not in merged:
            merged[k] = v
            sources[k] = f"object_harvester:{harvest.get('field_sources', {}).get(k, 'nested')}"
    aggregate['fields'] = merged
    aggregate['sources'] = sources
    aggregate['field_count'] = len(merged)
    aggregate['harvested_object_count'] = harvest.get('object_count', 0)
    return aggregate
