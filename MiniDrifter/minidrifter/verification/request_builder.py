# -*- coding: utf-8 -*-
"""Build executable HTTP requests from materialized templates + baseline context."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

from minidrifter.materials.capture_authoritative_pool import resolve_capture_authoritative_pool
from minidrifter.materials.form_body_merge import (
    load_merge_keys_from_profile,
    merge_form_body_params,
)
from minidrifter.materials.intake_param_hints import (
    hint_lookup,
    index_capture_query_hints,
    load_intake_report,
    normalize_api_path,
)
from minidrifter.runtime.crypto.profile_key_extract import load_crypto_profile_doc
from minidrifter.runtime.crypto.registry import get_crypto_engine_for_pack
from minidrifter.runtime.crypto.universal_build import (
    build_crypto_http_request,
    session_context_from_pool,
    transport_style_of,
)

BASELINE_REF_RE = re.compile(r'^\$baseline\.(\w+)$')
RUNTIME_REF_RE = re.compile(r'^\$runtime\.(\w+)$')
FORM_BODY_STYLES = frozenset({'form_cid_q_sign', 'form_encrypted_body'})


def baseline_pool(context: Dict[str, Any]) -> Dict[str, str]:
    pool: Dict[str, str] = {}
    for k, v in (context.get('resolved_fields') or {}).items():
        if isinstance(v, dict) and v.get('value') is not None:
            pool[k] = str(v['value'])
    return pool


def resolve_ref(value: str, pool: Dict[str, str]) -> Optional[str]:
    if not isinstance(value, str):
        return str(value) if value is not None else None
    m = BASELINE_REF_RE.match(value.strip())
    if m:
        key = m.group(1)
        if key in pool:
            return pool[key]
        for k, v in pool.items():
            if k.lower() == key.lower():
                return v
        return None
    if RUNTIME_REF_RE.match(value.strip()):
        return None
    return value


def resolve_params(params: Dict[str, Any], pool: Dict[str, str]) -> Tuple[Dict[str, str], List[str]]:
    resolved: Dict[str, str] = {}
    missing: List[str] = []
    for k, v in (params or {}).items():
        if isinstance(v, str):
            val = resolve_ref(v, pool)
        else:
            val = str(v) if v is not None else None
        if val is None:
            missing.append(k)
        else:
            resolved[k] = val
    return resolved, missing


def _coerce_body_params(resolved: Dict[str, str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in resolved.items():
        if v.startswith('[') or v.startswith('{'):
            try:
                out[k] = json.loads(v)
                continue
            except json.JSONDecodeError:
                pass
        if v.isdigit():
            out[k] = int(v)
        else:
            try:
                if '.' in v:
                    out[k] = float(v)
                    continue
            except ValueError:
                pass
            out[k] = v
    return out


def build_request_preview(
    test_case: Dict[str, Any],
    *,
    pack_dir: Path,
    baseline_context: Dict[str, Any],
    source_dir: Optional[Path] = None,
    base_url: Optional[str] = None,
    replay_entry: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    pool, pool_meta = resolve_capture_authoritative_pool(
        baseline_context, test_case=test_case, replay_entry=replay_entry,
    )
    method = (test_case.get('method') or 'GET').upper()
    path = test_case.get('path') or ''
    body_param_source = test_case.get('body_params') or {}
    query_param_source = test_case.get('params') or {}
    transport_style_hint = test_case.get('transport_style') or baseline_context.get('transport_style')
    use_form_body = (
        bool(body_param_source)
        and method in {'POST', 'PUT', 'PATCH'}
        and (
            transport_style_hint in {'form_urlencoded', 'form_cid_q_sign', 'form_encrypted_body'}
            or test_case.get('body_params')
        )
    )
    param_source = body_param_source if use_form_body else (query_param_source or body_param_source)
    params, missing = resolve_params(param_source, pool)

    host = pool.get('Host') or pool.get('api_host') or ''
    if base_url:
        base = base_url.rstrip('/')
    elif host:
        base = host if host.startswith('http') else f'https://{host}'
    else:
        base = ''

    preview: Dict[str, Any] = {
        'method': method,
        'path': path,
        'base_url': base,
        'params_resolved': params,
        'params_missing': missing,
        'crypto_required': bool(test_case.get('crypto_required')),
        'pool_provenance': pool_meta.get('provenance'),
    }

    if missing:
        preview['build_status'] = 'missing_params'
        return preview

    transport_style = baseline_context.get('transport_style') or test_case.get('transport_style')

    if test_case.get('crypto_required'):
        engine, cap = get_crypto_engine_for_pack(pack_dir, source_dir=source_dir)
        if not engine:
            preview['build_status'] = 'crypto_engine_unavailable'
            preview['crypto_reason'] = cap.reason
            return preview

        style = transport_style or transport_style_of(cap)
        session = session_context_from_pool(cap, pool)
        intake_report = load_intake_report(pack_dir)
        path_hints = index_capture_query_hints(intake_report, pack_dir=pack_dir)
        path_hint = hint_lookup(path_hints, path, method)
        prof_doc = load_crypto_profile_doc(cap.profile_id or '')
        merge_keys = load_merge_keys_from_profile(prof_doc)
        merged_params = merge_form_body_params(
            params,
            baseline_context=baseline_context,
            intake_report=intake_report,
            path_hint=path_hint,
            merge_keys=merge_keys,
        ) if style in FORM_BODY_STYLES else params
        body_params = _coerce_body_params(
            {k: str(v) for k, v in merged_params.items()}
        ) if style in FORM_BODY_STYLES else merged_params

        built = build_crypto_http_request(
            engine, cap,
            method=method,
            base_url=base,
            path=path,
            params=body_params,
            ctx=session,
            global_merge=None,
        )
        preview.update({
            'build_status': 'ok',
            'url': built.get('url'),
            'headers': built.get('headers'),
            'body': built.get('body'),
            'body_form': built.get('body_form'),
            'method': built.get('method') or method,
            'query_plain': built.get('query_plain'),
            'profile_id': built.get('profile_id'),
            'transport_style': style,
        })
    else:
        if use_form_body:
            url = f'{base}{path}'
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            body = urlencode(params)
            preview.update({
                'build_status': 'ok',
                'url': url,
                'headers': headers,
                'body': body,
                'method': method,
            })
        else:
            query = '&'.join(f'{k}={v}' for k, v in params.items())
            url = f'{base}{path}' + (f'?{query}' if query else '')
            headers = {'Content-Type': 'application/json'}
            if pool.get('Token'):
                headers['Token'] = pool['Token']
            preview.update({
                'build_status': 'ok',
                'url': url,
                'headers': headers,
            })

    return preview
