# -*- coding: utf-8 -*-
"""Merge global baseline / intake payload into form-body API params (profile-driven)."""
from __future__ import annotations

import json
from typing import Any, Dict, Optional, Set

TRANSPORT_FIELD_NAMES = frozenset({
    'cid', 'q', 'uid', 'sign', 'token', 'Token',
})

DEFAULT_GLOBAL_MERGE_KEYS = frozenset({
    'bucketIdList', 'bucket_id_list', 'lon', 'lat', 'cityId', 'city_id',
    'estimatedPickupTime', 'estimatedReturnTime', 'channelId', 'appId',
})


def _coerce_value(raw: Any) -> Any:
    if isinstance(raw, (dict, list, bool, int, float)) or raw is None:
        return raw
    text = str(raw).strip()
    if text.startswith('[') or text.startswith('{'):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
    if text.isdigit():
        return int(text)
    try:
        if '.' in text:
            return float(text)
    except ValueError:
        pass
    return text


def global_payload_from_baseline(
    baseline_context: Dict[str, Any],
    *,
    intake_report: Optional[Dict[str, Any]] = None,
    merge_keys: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    keys = merge_keys or DEFAULT_GLOBAL_MERGE_KEYS
    key_low = {x.lower() for x in keys}
    out: Dict[str, Any] = {}

    agg = ((intake_report or {}).get('decrypted_fields_aggregate') or {}).get('fields') or {}
    for k, v in agg.items():
        if k.lower() in {x.lower() for x in TRANSPORT_FIELD_NAMES}:
            continue
        if k not in keys and k.lower() not in key_low:
            continue
        out[k] = _coerce_value(v)

    pool = baseline_context.get('resolved_fields') or {}
    for k, meta in pool.items():
        if k.lower() in {x.lower() for x in TRANSPORT_FIELD_NAMES} or k in out:
            continue
        if k not in keys and k.lower() not in key_low:
            continue
        val = meta.get('value') if isinstance(meta, dict) else meta
        if val not in (None, ''):
            out[k] = _coerce_value(val)

    return out


def merge_form_body_params(
    api_params: Dict[str, Any],
    *,
    baseline_context: Dict[str, Any],
    intake_report: Optional[Dict[str, Any]] = None,
    path_hint: Optional[Dict[str, Any]] = None,
    merge_keys: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    merged = global_payload_from_baseline(
        baseline_context, intake_report=intake_report, merge_keys=merge_keys,
    )

    capture_locked = bool(
        path_hint
        and (
            path_hint.get('capture_locked')
            or path_hint.get('sign_verified')
            or path_hint.get('authorization_verified')
            or path_hint.get('body_params')
        )
    )
    if capture_locked:
        merged = {}

    if path_hint:
        if path_hint.get('body_params'):
            for k, v in path_hint['body_params'].items():
                if k.lower() not in {x.lower() for x in TRANSPORT_FIELD_NAMES}:
                    merged[k] = _coerce_value(v)
        for k, v in path_hint.get('param_pairs') or []:
            if k.lower() not in {x.lower() for x in TRANSPORT_FIELD_NAMES}:
                merged[k] = _coerce_value(v)

    for k, v in (api_params or {}).items():
        if capture_locked:
            continue
        if str(v).startswith('$'):
            continue
        if k.lower() in {x.lower() for x in TRANSPORT_FIELD_NAMES}:
            continue
        if v is not None and str(v).strip() != '':
            merged[k] = _coerce_value(v)

    for tk in list(merged.keys()):
        if tk.lower() in {'cid', 'q', 'sign', 'uid'}:
            merged.pop(tk, None)

    # Binding/mutation overlays must always win over capture-locked merge templates.
    for k, v in (api_params or {}).items():
        if str(v).startswith('$'):
            continue
        if k.lower() in {x.lower() for x in TRANSPORT_FIELD_NAMES}:
            continue
        if v is not None and str(v).strip() != '':
            merged[k] = _coerce_value(v)

    return merged


def load_merge_keys_from_profile(profile_doc: Optional[Dict[str, Any]]) -> Optional[Set[str]]:
    if not profile_doc:
        return DEFAULT_GLOBAL_MERGE_KEYS
    transport = profile_doc.get('transport') or {}
    keys = transport.get('global_merge_fields')
    if transport.get('auto_merge_intake_aggregate') is False:
        return set(keys) if keys else set()
    if keys:
        return set(keys)
    return DEFAULT_GLOBAL_MERGE_KEYS
