# -*- coding: utf-8 -*-
"""runtime_capture_index.json — structured runtime request pool from intake captures."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.core.utils import write_json
from minidrifter.materials.capture_sequence import infer_business_domain, infer_stage
from minidrifter.materials.intake_param_hints import load_intake_report, normalize_api_path
from minidrifter.verification.subject_override_fields import (
    field_allowed,
    infer_subject_fields_from_path,
    norm_field,
)

SCHEMA_VERSION = '1.0.0'

SUBJECT_FIELD_HINTS = frozenset({
    'userid', 'memberid', 'customerid', 'uid', 'openid', 'unionid',
    'accountid', 'logincustomerid', 'platformuserid',
})
OBJECT_FIELD_HINTS = frozenset({
    'orderid', 'orderno', 'addressid', 'invoiceid', 'cardid', 'deviceid',
    'vehicleid', 'couponid', 'paymentid', 'taskid', 'deptid', 'storeid',
})
CONTEXT_FIELD_HINTS = frozenset({
    'cityid', 'deptid', 'storeid', 'shopid', 'goodsid', 'skuid',
    'tenantid', 'channelid', 'scene', 'entrance',
})


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _path_tokens(path: str) -> List[str]:
    return [t for t in re.split(r'[/._-]+', normalize_api_path(path).lower()) if len(t) > 2]


def _fields_from_mapping(mapping: Any) -> List[str]:
    if isinstance(mapping, dict):
        return [str(k) for k in mapping if k]
    return []


def _wire_fields_from_capture(cap: Dict[str, Any]) -> tuple[List[str], List[str], List[str]]:
    query_fields: List[str] = []
    body_fields: List[str] = []
    response_fields: List[str] = []

    proc = cap.get('crypto_processing') or {}
    decrypted = proc.get('decrypted') or {}
    query_raw = decrypted.get('query') or ''
    if isinstance(query_raw, str) and query_raw:
        query_fields = [p.split('=', 1)[0] for p in query_raw.split('&') if '=' in p]
    body_form = decrypted.get('body_form') or {}
    if isinstance(body_form, dict):
        body_fields = list(body_form.keys())

    resp = cap.get('response_crypto_processing') or {}
    body_json = resp.get('body_json')
    if isinstance(body_json, dict):
        response_fields.extend(body_json.keys())
    response_fields.extend(cap.get('response_fields') or [])
    harvest = cap.get('object_harvest') or {}
    response_fields.extend(harvest.get('produced_fields') or [])

    return query_fields, body_fields, list(dict.fromkeys(response_fields))


def _classify_fields(fields: List[str]) -> tuple[List[str], List[str], List[str]]:
    subjects: List[str] = []
    objects: List[str] = []
    context: List[str] = []
    for field in fields:
        nf = norm_field(field)
        if nf in SUBJECT_FIELD_HINTS and field_allowed(field)[0]:
            subjects.append(field)
        elif nf in OBJECT_FIELD_HINTS:
            objects.append(field)
        elif nf in CONTEXT_FIELD_HINTS:
            context.append(field)
    return subjects, objects, context


def build_runtime_capture_entry(cap: Dict[str, Any], *, index: int) -> Dict[str, Any]:
    path = cap.get('path') or ''
    norm_path = normalize_api_path(path)
    query_fields, body_fields, response_fields = _wire_fields_from_capture(cap)
    req_fields = list(dict.fromkeys(query_fields + body_fields))
    subj_path = infer_subject_fields_from_path(path)
    subj_fields, obj_fields, ctx_fields = _classify_fields(req_fields + response_fields)
    for s in subj_path:
        if s not in subj_fields:
            subj_fields.append(s)

    proc = cap.get('crypto_processing') or {}
    transport = cap.get('transport_assessment') or {}
    return {
        'capture_id': cap.get('capture_id') or f"cap_{index:04d}",
        'capture_index': cap.get('capture_index') or index,
        'method': str(cap.get('method') or 'GET').upper(),
        'url': cap.get('url') or path,
        'path': path,
        'norm_path': norm_path,
        'host': cap.get('host') or '',
        'headers': list((cap.get('request_headers') or cap.get('headers') or {}).keys()),
        'query_fields': query_fields,
        'body_fields': body_fields,
        'response_fields': response_fields,
        'subject_fields': subj_fields,
        'object_fields': obj_fields,
        'context_fields': ctx_fields,
        'domain_tokens': _path_tokens(path),
        'business_domain': infer_business_domain(path),
        'stage': infer_stage(path),
        'has_auth': bool(transport.get('token_present') or 'token' in {h.lower() for h in (cap.get('request_headers') or {})}),
        'has_signature': bool(transport.get('signature_present') or 'authorization' in {h.lower() for h in (cap.get('request_headers') or {})}),
        'has_encrypted_response': bool((cap.get('response_crypto_processing') or {}).get('body_json') is None and cap.get('response_body_preview')),
        'can_replay': bool(proc.get('can_replay')),
        'overall_status': cap.get('overall_status'),
        'started_at': cap.get('started_at'),
    }


def build_runtime_capture_index(pack_dir: Path) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    intake = load_intake_report(pack_dir) or {}
    captures = intake.get('captures') or []
    entries: List[Dict[str, Any]] = []
    by_path: Dict[str, List[Dict[str, Any]]] = {}

    for i, cap in enumerate(captures, start=1):
        if not str(cap.get('overall_status') or '').startswith('acceptable'):
            continue
        entry = build_runtime_capture_entry(cap, index=i)
        entries.append(entry)
        norm = entry['norm_path']
        by_path.setdefault(norm, []).append(entry)

    paths_with_subject = sum(1 for e in entries if e.get('subject_fields'))
    paths_with_object = sum(1 for e in entries if e.get('object_fields'))
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'summary': {
            'capture_count': len(entries),
            'unique_paths': len(by_path),
            'paths_with_subject_fields': paths_with_subject,
            'paths_with_object_fields': paths_with_object,
        },
        'entries': entries,
        'by_path': by_path,
    }


def write_runtime_capture_index(pack_dir: Path) -> Path:
    pack_dir = Path(pack_dir)
    doc = build_runtime_capture_index(pack_dir)
    out = pack_dir / 'runtime_capture_index.json'
    write_json(out, doc)
    return out
