# -*- coding: utf-8 -*-
"""Crypto parity preflight — ensure rebuilt requests carry binding mutations on wire."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs

FORM_BODY_STYLES = frozenset({'form_cid_q_sign', 'form_encrypted_body', 'form_urlencoded'})


def _norm_field(name: str) -> str:
    return ''.join(ch for ch in str(name or '').lower() if ch.isalnum())


def _find_binding_value(
    preview: Dict[str, Any],
    binding_field: str,
    *,
    engine: Any = None,
) -> Optional[str]:
    target = _norm_field(binding_field)
    for k, v in (preview.get('params_resolved') or {}).items():
        if _norm_field(k) == target:
            return str(v)

    query_plain = str(preview.get('query_plain') or '')
    if query_plain:
        try:
            parsed = json.loads(query_plain)
            if isinstance(parsed, dict):
                for k, v in parsed.items():
                    if _norm_field(k) == target:
                        return str(v)
        except json.JSONDecodeError:
            if '=' in query_plain:
                for k, vals in parse_qs(query_plain, keep_blank_values=True).items():
                    if _norm_field(k) == target and vals:
                        return str(vals[0])

    body_form = preview.get('body_form') or {}
    if engine and body_form.get('q'):
        try:
            decrypted = engine.decrypt_aes_ecb(str(body_form['q']))
            obj = json.loads(decrypted)
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if _norm_field(k) == target:
                        return str(v)
        except Exception:
            return None
    return None


def check_crypto_parity_preflight(
    preview: Dict[str, Any],
    *,
    binding_field: Optional[str] = None,
    expected_binding_value: Optional[str] = None,
    engine: Any = None,
) -> Dict[str, Any]:
    """Validate request build before M7 execution (transport-aware)."""
    reasons: List[str] = []

    if preview.get('build_status') != 'ok':
        return {
            'ok': False,
            'status': 'build_failed',
            'reasons': [str(preview.get('build_status') or 'build_failed')],
        }

    transport = str(preview.get('transport_style') or '')
    body_form = preview.get('body_form') or {}

    if not binding_field or expected_binding_value is None:
        return {'ok': True, 'status': 'crypto_parity_ok', 'reasons': [], 'wire_binding_value': None}

    found = _find_binding_value(preview, binding_field, engine=engine)
    if found != str(expected_binding_value):
        return {
            'ok': False,
            'status': 'crypto_parity_failed',
            'reasons': ['binding_field_missing_on_wire'],
            'wire_binding_value': found,
        }

    if transport in FORM_BODY_STYLES or body_form.get('q'):
        plain_obj: Dict[str, Any] = {}
        query_plain = preview.get('query_plain') or ''
        if query_plain:
            try:
                parsed = json.loads(query_plain)
                if isinstance(parsed, dict):
                    plain_obj = parsed
            except json.JSONDecodeError:
                pass
        if not plain_obj and not body_form.get('q') and transport in FORM_BODY_STYLES:
            return {
                'ok': False,
                'status': 'crypto_parity_failed',
                'reasons': ['no_encrypted_plaintext'],
                'wire_binding_value': found,
            }

    return {
        'ok': True,
        'status': 'crypto_parity_ok',
        'reasons': reasons,
        'wire_binding_value': found,
    }
