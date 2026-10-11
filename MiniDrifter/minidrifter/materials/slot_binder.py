# -*- coding: utf-8 -*-
"""Bind baseline_runtime_context fields onto N1 skeletons → materialized API templates."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.core.runtime_taxonomy import is_deferred_obtainability, stage1_user_obtainability
from minidrifter.materials.form_body_merge import (
    load_merge_keys_from_profile,
    merge_form_body_params,
)
from minidrifter.materials.intake_param_hints import (
    hint_lookup,
    index_capture_query_hints,
    merge_plain_params,
    normalize_api_path,
    params_from_intake_hint,
)
from minidrifter.runtime.crypto.profile_key_extract import load_crypto_profile_doc
from minidrifter.materials.materialization_meta import build_materialization_dependencies

from minidrifter.core.schema import SCHEMA_VERSION

CRYPTO_RUNTIME_FIELDS = frozenset({
    'TimeSpan', 'Timestamp', 'TIMESTAMP', 'timeStamp', 'timespan',
    'Authorization', 'AppIdentity', 'encrypted_query', 'encrypted_body',
})

FIELD_ALIASES: Dict[str, List[str]] = {
    'timestamp': ['Timestamp', 'TIMESTAMP', 'timeStamp', 'TimeSpan', 'timespan'],
    'userid': ['UserId', 'userId'],
    'token': ['Token'],
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _resolve_field(name: str, resolved: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if name in resolved:
        return resolved[name]
    low = name.lower()
    for k, v in resolved.items():
        if k.lower() == low:
            return v
    for aliases in FIELD_ALIASES.values():
        if name in aliases or low in [a.lower() for a in aliases]:
            for alias in aliases:
                hit = resolved.get(alias) or next(
                    (resolved[k] for k in resolved if k.lower() == alias.lower()), None
                )
                if hit:
                    return hit
    return None


def _baseline_ref(field_name: str) -> str:
    canon = {'userId': 'UserId', 'userid': 'UserId', 'openId': 'OpenId'}.get(field_name, field_name)
    return f'$baseline.{canon}'


def _is_crypto_runtime_field(name: str) -> bool:
    return name in CRYPTO_RUNTIME_FIELDS or name.lower() in {f.lower() for f in CRYPTO_RUNTIME_FIELDS}


def _infer_plain_params(skeleton: Dict[str, Any], resolved_pool: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    """Map skeleton required fields to plain param names with baseline refs."""
    params: Dict[str, str] = {}
    for f in skeleton.get('required_fields') or []:
        fname = f.get('name')
        if not fname or _is_crypto_runtime_field(fname):
            continue
        role = f.get('role') or ''
        obs = f.get('obtainability') or ''
        where = (f.get('where') or 'body').lower()
        if role in {'crypto_derived', 'static_constant'} and fname not in {'userId', 'UserId'}:
            continue
        if is_deferred_obtainability(obs):
            continue
        hit = _resolve_field(fname, resolved_pool)
        if hit:
            key = fname[0].lower() + fname[1:] if fname[:1].isupper() and fname not in {'UserId'} else fname
            if fname == 'UserId':
                key = 'userId'
            params[key] = _baseline_ref(fname)
        elif fname in {'UserId', 'userId'} and _resolve_field('UserId', resolved_pool):
            params['userId'] = '$baseline.UserId'
    return params


def _build_crypto_profile(baseline_context: Dict[str, Any], method: str) -> Dict[str, Any]:
    profile_id = baseline_context.get('crypto_profile')
    transport_style = baseline_context.get('transport_style') or ''
    if not baseline_context.get('crypto_replay_ready') or not profile_id:
        return {'profile_id': None, 'available': False, 'transport_style': transport_style or None}

    if transport_style in {'form_cid_q_sign', 'form_encrypted_body'}:
        generate = ['cid', 'q', 'sign', 'uid']
    else:
        generate = ['TimeSpan', 'AppIdentity', 'Authorization']
        if method.upper() == 'GET':
            generate.append('encrypted_query')
        else:
            generate.append('encrypted_body')

    return {
        'profile_id': profile_id,
        'available': True,
        'transport_style': transport_style or None,
        'generate_runtime_fields': generate,
    }


def _build_http_template(
    method: str,
    path: str,
    crypto_available: bool,
    *,
    transport_style: Optional[str] = None,
) -> Dict[str, Any]:
    style = transport_style or ''
    if crypto_available and style in {'form_cid_q_sign', 'form_encrypted_body'}:
        return {
            'method': method,
            'path': path,
            'url_mode': 'path_only',
            'headers': {
                'Content-Type': 'application/x-www-form-urlencoded',
                'appletEncrypt': 'appletEncrypt',
            },
            'body_mode': 'form_cid_q_sign',
        }

    headers = {
        'Token': '$baseline.Token',
        'AppVersion': '$baseline.AppVersion',
        'AppPlatform': '$baseline.AppPlatform',
        'Remark': 'Unchecked',
        'Content-Type': 'application/json',
    }
    if crypto_available:
        headers['Authorization'] = '$runtime.Authorization'
        headers['AppIdentity'] = '$runtime.AppIdentity'

    tpl: Dict[str, Any] = {
        'method': method,
        'path': path,
        'url_mode': 'path_plus_encrypted_query_blob' if method.upper() == 'GET' else 'path_plus_encrypted_body',
        'headers': headers,
    }
    if method.upper() == 'GET':
        tpl['query_mode'] = 'encrypted_blob_suffix'
    else:
        tpl['body_mode'] = 'encrypted_blob'
    return tpl


def _is_plaintext_direct(baseline_context: Optional[Dict[str, Any]]) -> bool:
    if not baseline_context:
        return False
    strategy = (baseline_context.get('intake_strategy') or {}).get('strategy')
    return (
        baseline_context.get('replay_mode') == 'plaintext_direct'
        or strategy == 'plaintext_direct'
    )


def _classify_status(
    skeleton: Dict[str, Any],
    card: Dict[str, Any],
    missing_slots: List[Dict[str, Any]],
    blocking_missing: List[Dict[str, Any]],
    defer_missing: List[Dict[str, Any]],
    crypto_available: bool,
    method: str,
    *,
    intake_hint: Optional[Dict[str, Any]] = None,
    baseline_context: Optional[Dict[str, Any]] = None,
) -> tuple[str, str]:
    if method == 'UNKNOWN':
        return 'blocked_method_unknown', 'resolve_method_before_replay'

    if (
        not crypto_available
        and _is_plaintext_direct(baseline_context)
        and intake_hint
        and intake_hint.get('capture_locked')
        and intake_hint.get('param_pairs')
    ):
        return 'materialized_plain', 'baseline_replay_from_capture'

    crypto_only_blocking = blocking_missing and all(
        _is_crypto_runtime_field(m.get('field', '')) or m.get('role') == 'crypto_derived'
        for m in blocking_missing
    )
    stage1_missing = [m for m in blocking_missing if stage1_user_obtainability(m.get('obtainability') or '')]

    if defer_missing and not blocking_missing:
        if crypto_available:
            return 'materialized_with_crypto_profile', 'crypto_replay_with_deferred_objects'
        return 'deferred_requires_first_hop_object', 'defer_until_first_hop_or_workflow_object'

    if stage1_missing:
        return 'partial_missing_stage1_material', 'import_missing_stage1_materials'

    if crypto_only_blocking or (not blocking_missing and crypto_available):
        return 'materialized_with_crypto_profile', 'crypto_replay'

    if not blocking_missing and not crypto_available:
        return 'materialized_plain', 'baseline_replay'

    if any(is_deferred_obtainability(m.get('obtainability') or '') for m in blocking_missing):
        return 'deferred_requires_first_hop_object', 'defer_until_first_hop_or_workflow_object'

    return 'partial_missing_stage1_material', 'import_missing_stage1_materials'


def materialize_api_template(
    skeleton: Dict[str, Any],
    card: Dict[str, Any],
    baseline_context: Dict[str, Any],
    *,
    intake_query_hints: Optional[Dict[str, Dict[str, Any]]] = None,
    intake_report: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    resolved_pool = baseline_context.get('resolved_fields') or {}
    cid = skeleton.get('api_id') or card.get('card_id')
    path = skeleton.get('path') or skeleton.get('endpoint') or ''
    method = skeleton.get('method') or 'UNKNOWN'
    crypto_available = bool(baseline_context.get('crypto_replay_ready'))

    resolved_slots: Dict[str, Any] = {}
    missing_slots: List[Dict[str, Any]] = []
    runtime_generated: List[str] = []

    for f in skeleton.get('required_fields') or []:
        fname = f.get('name')
        if not fname:
            continue
        if _is_crypto_runtime_field(fname) or (
            f.get('role') == 'crypto_derived' and crypto_available
        ):
            runtime_generated.append(fname)
            resolved_slots[fname] = f'$runtime.{fname}'
            continue
        hit = _resolve_field(fname, resolved_pool)
        if hit:
            resolved_slots[fname] = hit['source']
        else:
            missing_slots.append({
                'field': fname,
                'role': f.get('role'),
                'obtainability': f.get('obtainability'),
                'material_candidates': f.get('material_candidates') or [],
                'recommended_resolution': _recommend_resolution(f),
            })

    defer_missing = [m for m in missing_slots if is_deferred_obtainability(m.get('obtainability') or '')]
    blocking_missing = [m for m in missing_slots if not is_deferred_obtainability(m.get('obtainability') or '')]

    method_u = method.upper() if method != 'UNKNOWN' else 'GET'
    hint = hint_lookup(intake_query_hints or {}, path, method_u)
    if not hint and method != method_u:
        hint = hint_lookup(intake_query_hints or {}, path, method)
    if hint and hint.get('capture_locked'):
        method_u = (hint.get('method') or method_u).upper()

    status, next_action = _classify_status(
        skeleton, card, missing_slots, blocking_missing, defer_missing, crypto_available, method_u,
        intake_hint=hint,
        baseline_context=baseline_context,
    )

    plain_params = _infer_plain_params(skeleton, resolved_pool)
    param_source = 'skeleton_inference'
    if hint and hint.get('transport') == 'form_body':
        method_u = (hint.get('method') or 'POST').upper()
    if hint and (hint.get('method') or 'GET').upper() == method_u:
        intake_params = params_from_intake_hint(hint, resolved_pool)
        if intake_params:
            plain_params = merge_plain_params(plain_params, intake_params, prefer_intake=True)
            if hint.get('transport') == 'form_body':
                param_source = 'intake_decrypted_body'
            elif hint.get('source') == 'plaintext_capture_file':
                param_source = 'intake_plaintext_capture'
            else:
                param_source = 'intake_decrypted_query'

    crypto_profile = _build_crypto_profile(baseline_context, method)
    transport_style = baseline_context.get('transport_style') or crypto_profile.get('transport_style') or ''

    if transport_style in {'form_cid_q_sign', 'form_encrypted_body'} and crypto_available:
        profile_id = baseline_context.get('crypto_profile_id') or crypto_profile.get('profile_id') or ''
        prof_doc = load_crypto_profile_doc(profile_id) if profile_id else {}
        merge_keys = load_merge_keys_from_profile(prof_doc)
        plain_params = merge_form_body_params(
            plain_params,
            baseline_context=baseline_context,
            intake_report=intake_report,
            path_hint=hint,
            merge_keys=merge_keys,
        )
        if plain_params != _infer_plain_params(skeleton, resolved_pool):
            param_source = param_source + '+global_merge'

    plain_template: Dict[str, Any] = {'method': method_u, 'path': path, 'param_source': param_source}
    if transport_style in {'form_cid_q_sign', 'form_encrypted_body'} and crypto_available:
        plain_template['body_params'] = plain_params
        plain_template['transport_style'] = transport_style
    elif hint and hint.get('transport') == 'form_body' and method_u in {'POST', 'PUT', 'PATCH'}:
        plain_template['body_params'] = plain_params
        plain_template['transport_style'] = 'form_urlencoded'
    elif method_u == 'GET':
        plain_template['params'] = plain_params
    elif plain_params:
        plain_template['params'] = plain_params
        plain_template['body'] = plain_template.get('body') or {}

    replay = card.get('replay') or {}
    transport = replay.get('transport') or {}

    return {
        'api_id': cid,
        'card_id': cid,
        'path': path,
        'method': method,
        'runtime_sublevel': skeleton.get('runtime_sublevel'),
        'side_effect_level': skeleton.get('side_effect_level'),
        'status': status,
        'resolved_slots': resolved_slots,
        'missing_slots': missing_slots,
        'runtime_generated_fields': sorted(set(runtime_generated)),
        'next_action': next_action,
        'plain_template': plain_template,
        'crypto_profile': crypto_profile,
        'http_template': _build_http_template(
            method_u, path, crypto_profile.get('available', False),
            transport_style=transport_style,
        ),
        'transport_hint': transport.get('body_encoding') or (
            transport_style or ('encrypted' if crypto_profile.get('available') else 'plain')
        ),
        'call_template': {
            'deprecated': True,
            'note': 'Use plain_template + crypto_profile + http_template instead',
        },
    }


def _recommend_resolution(field: Dict[str, Any]) -> str:
    obs = field.get('obtainability') or ''
    mats = field.get('material_candidates') or []
    if obs == 'O3_first_hop_object':
        return f"call_or_import:{mats[0] if mats else 'first_hop_list'}"
    if is_deferred_obtainability(obs):
        return 'auto_discovery_from_list_response'
    if mats:
        return f"import:{mats[0]}"
    return 'import_baseline_material'


def build_materialized_templates(
    cards_by_id: Dict[str, Dict[str, Any]],
    skeletons_by_id: Dict[str, Dict[str, Any]],
    baseline_context: Dict[str, Any],
    *,
    target_api_ids: Optional[List[str]] = None,
    pack_dir: Optional[Path] = None,
    replay_safe_only: bool = False,
    intake_report: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if target_api_ids is None:
        target_api_ids = list(skeletons_by_id.keys())

    intake_query_hints = index_capture_query_hints(intake_report, pack_dir=pack_dir)

    templates = []
    stats: Dict[str, int] = {}

    for cid in target_api_ids:
        sk = skeletons_by_id.get(cid)
        card = cards_by_id.get(cid)
        if not sk or not card:
            continue
        if replay_safe_only:
            side = (sk.get('side_effect_level') or '').split('_')[0]
            if side not in {'S0', 'S1'}:
                continue
        tpl = materialize_api_template(
            sk, card, baseline_context,
            intake_query_hints=intake_query_hints,
            intake_report=intake_report,
        )
        templates.append(tpl)
        stats[tpl['status']] = stats.get(tpl['status'], 0) + 1

    replay_ready_statuses = {
        'materialized_with_crypto_profile',
        'materialized_plain',
    }
    ready = [t for t in templates if t['status'] in replay_ready_statuses]

    deps = build_materialization_dependencies(pack_dir or Path('.'), baseline_context) if pack_dir else {}

    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'account_label': baseline_context.get('account_label', 'A'),
        'baseline_field_count': baseline_context.get('field_count', 0),
        'baseline_context_generated_at': baseline_context.get('generated_at'),
        'crypto_replay_ready': baseline_context.get('crypto_replay_ready'),
        'dependencies': deps,
        'template_count': len(templates),
        'summary': stats,
        'ready_for_replay': [
            {
                'api_id': t['api_id'],
                'path': t['path'],
                'status': t['status'],
                'plain_params': (t.get('plain_template') or {}).get('params'),
            }
            for t in ready[:50]
        ],
        'templates': templates,
    }
