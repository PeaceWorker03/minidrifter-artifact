# -*- coding: utf-8 -*-
"""Envelope-preserving counterfactual wire shapes from capture evidence."""
from __future__ import annotations

import copy
import json
from typing import Any, Dict, List, Optional, Set

from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.verification.mutation_engine import _mutation_param_bag

ENVIRONMENT_NOISE_NORM = frozenset({
    'cityid', 'pickupcityid', 'returncityid', 'pickupdeptid', 'returndeptid',
    'deptbtnflag', 'hotcarsflag', 'entrance', 'scenetype', 'searchpickupdeptid',
    'searchreturndeptid', 'pickupway', 'returnway', 'estimatedpickuptime',
    'estimatedreturntime', 'lon', 'lat', 'channelid', 'appid',
})

DEFAULT_ENVELOPE_HINTS = frozenset({
    'bucketidlist', 'bucket_id_list', 'appversion', 'channelid',
})


def _norm_field(name: str) -> str:
    return ''.join(ch for ch in str(name or '').lower() if ch.isalnum())


def envelope_fields_from_capture(body: Dict[str, Any], *, binding_field: str) -> Set[str]:
    """Fields that must be preserved with capture shape (not binding handle)."""
    binding_norm = _norm_field(binding_field)
    out: Set[str] = set()
    for k in body:
        nk = _norm_field(k)
        if nk == binding_norm:
            continue
        if nk in ENVIRONMENT_NOISE_NORM:
            continue
        if nk in DEFAULT_ENVELOPE_HINTS or isinstance(body.get(k), list):
            out.add(k)
    return out


def capture_plaintext_body(replay_entry: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    inner = (replay_entry or {}).get('replay_context') or replay_entry or {}
    body = dict(inner.get('body') or {})
    pool = inner.get('pool') or {}
    for key in ('bucketIdList', 'bucket_id_list'):
        if key not in body and pool.get(key) not in (None, ''):
            raw = pool[key]
            if isinstance(raw, str) and raw.startswith('['):
                try:
                    body[key] = json.loads(raw)
                except json.JSONDecodeError:
                    body[key] = raw
            else:
                body[key] = raw
    return body


def build_counterfactual_wire_body(
    *,
    capture_body: Dict[str, Any],
    binding_field: str,
    mutated_value: Any,
    preserve_envelope: bool = True,
) -> Dict[str, Any]:
    """Keep envelope anchors from capture; substitute only the binding handle."""
    if not capture_body:
        key = binding_field
        return {key: mutated_value}

    binding_norm = _norm_field(binding_field)
    out: Dict[str, Any] = {}
    envelope_keys = envelope_fields_from_capture(capture_body, binding_field=binding_field)

    if preserve_envelope:
        for k, v in capture_body.items():
            nk = _norm_field(k)
            if nk == binding_norm:
                continue
            if nk in ENVIRONMENT_NOISE_NORM:
                continue
            if k in envelope_keys or nk in DEFAULT_ENVELOPE_HINTS:
                out[k] = copy.deepcopy(v)

    key = binding_field
    for k in capture_body:
        if _norm_field(k) == binding_norm:
            key = k
            break
    out[key] = mutated_value
    return out


def apply_envelope_preserving_mutation(
    test_case: Dict[str, Any],
    *,
    field: str,
    mutated_value: Any,
    replay_entry: Optional[Dict[str, Any]] = None,
) -> None:
    """Rewrite test-case wire bag to a capture-grounded counterfactual body."""
    capture_body = capture_plaintext_body(replay_entry)
    if not capture_body:
        bag, bag_key = _mutation_param_bag(test_case)
        key = field
        for k in bag:
            if _norm_field(k) == _norm_field(field):
                key = k
                break
        test_case[bag_key] = {key: mutated_value}
        if bag_key == 'body_params':
            test_case['params'] = {}
        return

    wire = build_counterfactual_wire_body(
        capture_body=capture_body,
        binding_field=field,
        mutated_value=mutated_value,
        preserve_envelope=True,
    )
    bag_key = 'body_params' if test_case.get('body_params') is not None or test_case.get('method', 'POST').upper() != 'GET' else 'params'
    test_case[bag_key] = wire
    if bag_key == 'body_params':
        test_case['params'] = {}
    test_case['envelope_preserving'] = True
    test_case['counterfactual_wire_source'] = 'capture_envelope'
