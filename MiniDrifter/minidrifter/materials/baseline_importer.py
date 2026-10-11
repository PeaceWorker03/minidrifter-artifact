# -*- coding: utf-8 -*-
"""Import user baseline HTTP samples into baseline_runtime_context.json."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

from minidrifter.runtime.crypto_profile import normalize_profile_id

SCHEMA_VERSION = '1.0.0'


def parse_urlencoded_form(body: str) -> Dict[str, str]:
    """Parse x-www-form-urlencoded bodies; keep '+' in base64 cipher blobs."""
    if not body or '=' not in body:
        return {}
    safe = body.replace('+', '%2B')
    return {
        k: unquote(v[0] if len(v) == 1 else v[-1])
        for k, v in parse_qs(safe, keep_blank_values=True).items()
    }

BODY_FIELD_MAP = {
    'cid': 'cid',
    'uid': 'uid',
    'sign': 'sign',
    'q': 'q',
    'token': 'Token',
}

HEADER_FIELD_MAP = {
    'token': 'Token',
    'authorization': 'Authorization',
    'appidentity': 'AppIdentity',
    'appversion': 'AppVersion',
    'appplatform': 'AppPlatform',
    'host': 'Host',
    'timestamp': 'Timestamp',
    'timespan': 'TimeSpan',
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _flatten_json(obj: Any, prefix: str = '') -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f'{prefix}.{k}' if prefix else k
            if isinstance(v, (dict, list)):
                out.update(_flatten_json(v, key))
            else:
                out[key] = v
    elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
        for i, item in enumerate(obj[:3]):
            out.update(_flatten_json(item, f'{prefix}[{i}]' if prefix else f'[{i}]'))
    return out


def _guess_field_aliases(flat: Dict[str, Any]) -> Dict[str, str]:
    resolved: Dict[str, str] = {}
    for path, val in flat.items():
        if val is None or val == '':
            continue
        leaf = path.split('.')[-1].replace('[0]', '').replace('[1]', '')
        for canon in [
            'UserId', 'userId', 'Token', 'Authorization', 'AppIdentity', 'OpenId',
            'OrderId', 'DeviceId', 'Phone', 'MarketToken', 'UserJwt',
        ]:
            if leaf.lower() == canon.lower():
                resolved[canon] = str(val)
    return resolved


def parse_raw_http(text: str) -> Dict[str, Any]:
    """Parse a minimal raw HTTP request block (stops before embedded response)."""
    text = text.replace('\r\n', '\n')
    resp = re.search(r'\nHTTP/\d(?:\.\d)?\s+\d+', text, re.I)
    if resp:
        text = text[:resp.start()]
    lines = text.split('\n')
    if not lines:
        raise ValueError('empty raw HTTP')

    req_line = lines[0].strip()
    m = re.match(r'(GET|POST|PUT|PATCH|DELETE)\s+(\S+)\s+HTTP/', req_line, re.I)
    if not m:
        raise ValueError(f'cannot parse request line: {req_line[:120]}')
    method, target = m.group(1).upper(), m.group(2)

    headers: Dict[str, str] = {}
    i = 1
    while i < len(lines) and lines[i].strip():
        if ':' in lines[i]:
            k, _, v = lines[i].partition(':')
            headers[k.strip()] = v.strip()
        i += 1

    body = '\n'.join(lines[i + 1:]).strip()
    body_json = None
    body_form: Dict[str, str] = {}
    if body.startswith('{') or body.startswith('['):
        try:
            body_json = json.loads(body)
        except json.JSONDecodeError:
            body_json = None
    elif body and '=' in body:
        ct = next((v for k, v in headers.items() if k.lower() == 'content-type'), '')
        if 'form-urlencoded' in ct.lower() or re.match(r'^[a-zA-Z0-9_]+=', body):
            body_form = parse_urlencoded_form(body)

    parsed = urlparse(target)
    query = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed.query).items()}

    return {
        'method': method,
        'url': target,
        'path': parsed.path,
        'query': query,
        'headers': headers,
        'body_raw': body or None,
        'body_json': body_json,
        'body_form': body_form,
    }


def parse_multi_raw_http(text: str) -> List[Dict[str, Any]]:
    from minidrifter.materials.baseline_intake import split_multi_raw_http
    return [parse_raw_http(chunk) for chunk in split_multi_raw_http(text)]


def parse_json_response_file(data: Any) -> Dict[str, Any]:
    if isinstance(data, str):
        data = json.loads(data)
    flat = _flatten_json(data)
    return {
        'body_json': data,
        'flattened_fields': flat,
        'resolved_fields': _guess_field_aliases(flat),
    }


def import_baseline_material(
    material_id: str,
    source_path: Path,
    *,
    format_hint: Optional[str] = None,
) -> Dict[str, Any]:
    text = source_path.read_text(encoding='utf-8', errors='replace')
    suffix = source_path.suffix.lower()
    fmt = format_hint or ('har' if suffix == '.har' else 'raw_http' if suffix in {'.txt', '.http'} else 'json')

    record: Dict[str, Any] = {
        'material_id': material_id,
        'source_file': str(source_path),
        'format': fmt,
        'status': 'parsed',
        'parsed_at': _utc_now(),
    }

    if fmt == 'har' or (suffix == '.har' and text.lstrip().startswith('{')):
        har = json.loads(text)
        from minidrifter.materials.har_sequence import (
            filter_har_entries,
            parse_har_sequence,
        )
        entries = filter_har_entries(har.get('log', {}).get('entries') or [])
        if not entries:
            raise ValueError('HAR has no API-like entries after filtering')
        seq = parse_har_sequence(har)
        primary = seq[0]
        req = primary['request']
        headers = req.get('headers') or {}
        record['request'] = {
            'method': req.get('method'),
            'url': req.get('url'),
            'path': req.get('path'),
            'headers': headers,
            'body_json': req.get('body_json'),
            'body_form': req.get('body_form'),
        }
        if primary.get('response_body') is not None:
            record['response'] = parse_json_response_file(primary['response_body'])
        record['har_sequence'] = {
            'entry_count': len(seq),
            'paths': [s['request'].get('path') for s in seq],
        }
        for item in seq:
            if item.get('response_body') is not None:
                extra = parse_json_response_file(item['response_body'])
                for k, v in (extra.get('resolved_fields') or {}).items():
                    if k not in (record.get('response') or {}).get('resolved_fields', {}):
                        record.setdefault('response', {'resolved_fields': {}})
                        record['response'].setdefault('resolved_fields', {})[k] = v
    elif fmt == 'json' or suffix == '.json':
        data = json.loads(text)
        if isinstance(data, dict) and 'Result' in data:
            from minidrifter.runtime.crypto_profile import load_crypto_capability
            from minidrifter.runtime.crypto_replay import process_response_result
            cap = load_crypto_capability(source_path.parent.parent)
            proc = process_response_result(
                data, cap, output_dir=source_path.parent.parent,
            )
            if proc.get('body_json'):
                record['response'] = parse_json_response_file(proc['body_json'])
                record['response']['decrypt_mode'] = proc.get('decrypt_mode')
                record['produces_fields'] = proc.get('produces_fields')
            else:
                record['response'] = parse_json_response_file(data)
        else:
            record['response'] = parse_json_response_file(data)
    else:
        record['request'] = parse_raw_http(text)
        from minidrifter.materials.baseline_intake import extract_response_json_from_chunk
        from minidrifter.runtime.crypto_profile import load_crypto_capability
        from minidrifter.runtime.crypto_replay import process_response_result
        resp_body = extract_response_json_from_chunk(text)
        if resp_body is not None:
            cap = load_crypto_capability(source_path.parent.parent)
            proc = process_response_result(
                resp_body, cap, output_dir=source_path.parent.parent,
            )
            if proc.get('body_json'):
                record['response'] = parse_json_response_file(proc['body_json'])
                record['response']['decrypt_mode'] = proc.get('decrypt_mode')
                record['produces_fields'] = proc.get('produces_fields')
            else:
                record['response'] = parse_json_response_file(resp_body)

    return record


def merge_baseline_runtime_context(
    existing: Optional[Dict[str, Any]],
    incoming: Dict[str, Any],
) -> Dict[str, Any]:
    """Incremental merge — multiple intake passes accumulate fields and captures."""
    if not existing:
        merged = dict(incoming)
        merged['merge_mode'] = 'initial'
        return merged

    merged = dict(existing)
    merged['generated_at'] = incoming.get('generated_at') or existing.get('generated_at')
    merged['merge_mode'] = 'incremental'

    old_materials = list(existing.get('materials_imported') or [])
    new_materials = list(incoming.get('materials_imported') or [])
    merged['materials_imported'] = list(dict.fromkeys(old_materials + new_materials))

    status = dict(existing.get('material_status') or {})
    status.update(incoming.get('material_status') or {})
    merged['material_status'] = status

    resolved = dict(existing.get('resolved_fields') or {})
    for k, v in (incoming.get('resolved_fields') or {}).items():
        if k not in resolved or resolved[k].get('value') != v.get('value'):
            resolved[k] = v
    merged['resolved_fields'] = resolved
    merged['field_count'] = len(resolved)

    captures = list(existing.get('capture_index') or [])
    seen = {(c.get('material_id'), c.get('path')) for c in captures}
    for mat_id in new_materials:
        if mat_id in old_materials:
            continue
        for c in incoming.get('capture_index') or []:
            key = (c.get('material_id'), c.get('path'))
            if key not in seen:
                captures.append(c)
                seen.add(key)
    if captures:
        merged['capture_index'] = captures

    for key in (
        'crypto_profile', 'crypto_replay_ready', 'transport_style',
        'n1_materialize_allowed', 'intake_strategy', 'replay_mode',
    ):
        if incoming.get(key) is not None:
            merged[key] = incoming[key]

    merged['merge_stats'] = {
        'previous_field_count': existing.get('field_count', 0),
        'incoming_field_count': incoming.get('field_count', 0),
        'merged_field_count': merged['field_count'],
        'materials_added': [m for m in new_materials if m not in old_materials],
    }
    return merged


def build_baseline_runtime_context(
    imported_materials: List[Dict[str, Any]],
    *,
    pack_id: Optional[str] = None,
    account_label: str = 'A',
    intake_report: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    resolved: Dict[str, Dict[str, Any]] = {}
    material_status: Dict[str, str] = {}

    for mat in imported_materials:
        mid = mat['material_id']
        material_status[mid] = mat.get('status', 'parsed')
        req = mat.get('request') or {}
        resp = mat.get('response') or {}

        for hk, canon in HEADER_FIELD_MAP.items():
            for k, v in (req.get('headers') or {}).items():
                if k.lower() == hk and v:
                    resolved[canon] = {
                        'value': v,
                        'source': f'{mid}.request.headers.{k}',
                        'status': 'resolved',
                    }

        for src in (req.get('query') or {}).items():
            canon = src[0]
            if src[1]:
                resolved[canon] = {
                    'value': src[1],
                    'source': f'{mid}.request.query.{canon}',
                    'status': 'resolved',
                }

        if req.get('body_json'):
            for k, v in _guess_field_aliases(_flatten_json(req['body_json'])).items():
                resolved[k] = {'value': v, 'source': f'{mid}.request.body.{k}', 'status': 'resolved'}

        for bk, canon in BODY_FIELD_MAP.items():
            val = (req.get('body_form') or {}).get(bk)
            if val:
                resolved[canon] = {
                    'value': val,
                    'source': f'{mid}.request.body_form.{bk}',
                    'status': 'resolved',
                }
        if (req.get('body_form') or {}).get('uid') and 'Token' not in resolved:
            resolved['Token'] = {
                'value': req['body_form']['uid'],
                'source': f'{mid}.request.body_form.uid_as_session',
                'status': 'resolved_alias',
            }

        for k, v in (resp.get('resolved_fields') or {}).items():
            resolved[k] = {'value': v, 'source': f'{mid}.response.{k}', 'status': 'resolved'}

        for k, v in (resp.get('produces_fields') or {}).items():
            if k not in resolved and v not in (None, ''):
                resolved[k] = {'value': str(v), 'source': f'{mid}.response.produces.{k}', 'status': 'resolved_via_response'}

    if intake_report:
        _merge_intake_decrypted(resolved, intake_report)

    crypto_cap = (intake_report or {}).get('crypto_capability') or {}
    n1_gate = (intake_report or {}).get('n1_gate') or {}

    capture_index = []
    for mat in imported_materials:
        req = mat.get('request') or {}
        capture_index.append({
            'material_id': mat['material_id'],
            'path': req.get('path'),
            'method': req.get('method'),
            'source_file': mat.get('source_file'),
        })

    return {
        'schema_version': SCHEMA_VERSION,
        'pack_id': pack_id,
        'account_label': account_label,
        'generated_at': _utc_now(),
        'materials_imported': [m['material_id'] for m in imported_materials],
        'material_status': material_status,
        'capture_index': capture_index,
        'crypto_profile': normalize_profile_id(crypto_cap.get('profile_id')),
        'crypto_replay_ready': bool(crypto_cap.get('can_replay')),
        'transport_style': crypto_cap.get('transport_style'),
        'n1_materialize_allowed': n1_gate.get('n1_materialize_allowed', True),
        'resolved_fields': resolved,
        'field_count': len(resolved),
    }


def _merge_intake_decrypted(
    resolved: Dict[str, Dict[str, Any]],
    intake_report: Dict[str, Any],
) -> None:
    agg = intake_report.get('decrypted_fields_aggregate') or {}
    fields = agg.get('fields') or {}
    sources = agg.get('sources') or {}
    for k, v in fields.items():
        if v in (None, ''):
            continue
        if k in resolved and resolved[k].get('value') == v:
            continue
        resolved[k] = {
            'value': str(v),
            'source': sources.get(k, 'intake.decrypted_fields_aggregate'),
            'status': 'resolved_via_decrypt',
        }


def import_baseline_from_directory(
    materials_dir: Path,
    template: Dict[str, Any],
    *,
    pack_id: Optional[str] = None,
    intake_report: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Load files named {material_id}.* from directory; prefer .http over .json."""
    imported = []
    for bucket in ('required_materials', 'recommended_materials', 'deferred_materials'):
        for mat in template.get(bucket) or []:
            mid = mat['material_id']
            matches = sorted(Path(materials_dir).glob(f'{mid}.*'), key=_material_file_priority)
            if not matches:
                continue
            imported.append(import_baseline_material(mid, matches[0]))

    if not imported and not intake_report:
        raise FileNotFoundError(f'no material files found in {materials_dir}')

    return build_baseline_runtime_context(
        imported,
        pack_id=pack_id or template.get('pack_id'),
        intake_report=intake_report,
    )


def _material_file_priority(path: Path) -> tuple:
    """Prefer raw HTTP captures over JSON mocks."""
    ext = path.suffix.lower()
    priority = {'.http': 0, '.txt': 1, '.har': 2, '.json': 3}.get(ext, 9)
    mock_penalty = 1 if '.mock' in path.name.lower() else 0
    return (mock_penalty, priority, path.name)
