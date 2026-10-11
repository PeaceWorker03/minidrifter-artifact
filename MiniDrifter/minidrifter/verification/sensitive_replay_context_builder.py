# -*- coding: utf-8 -*-
"""P4-fix-4 — build per-API sensitive replay context from baseline / captures."""
from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.business_chain.chain_run_context import load_json
from minidrifter.classification.api_plane_classifier import plane_index_by_path
from minidrifter.core.utils import write_json
from minidrifter.materials.intake_param_hints import load_intake_report, normalize_api_path
from minidrifter.verification.subject_override_fields import (
    SUBJECT_PRIORITY,
    field_allowed,
    infer_subject_fields_from_path,
    norm_field,
    pool_value_for_subject_field,
)

SENSITIVE_READ_ROLES = frozenset({
    'read_sensitive_state',
    'verification_state_probe',
    'account_state_probe',
    'address_invoice_probe',
})

SENSITIVE_PLANES = frozenset({
    'user_profile_personal_info',
    'realname_verification',
    'account_state_wallet',
    'contact_address_invoice',
})

ENV_FIELD_HINTS = frozenset({
    'cityid', 'channel', 'appversion', 'entrance', 'scenetype', 'bucketidlist',
    'pickupcityid', 'returncityid', 'deptbtnflag', 'hotcarsflag',
})

CRYPTO_TRANSPORT_FIELDS = frozenset({
    'cid', 'q', 'uid', 'sign', 'token', 'host', 'timestamp', 'timespan',
})

EXACT_PATH_SCORE = 1000.0
PARTIAL_PATH_SCORE = 35.0
DOMAIN_FALLBACK_SCORE = 5.0


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _baseline_pool(ctx: Dict[str, Any]) -> Dict[str, str]:
    return {
        k: str(v.get('value'))
        for k, v in (ctx.get('resolved_fields') or {}).items()
        if isinstance(v, dict) and v.get('value') is not None
    }


def _capture_pool(capture: Dict[str, Any]) -> Dict[str, str]:
    proc = capture.get('crypto_processing') or {}
    resolved = proc.get('resolved_fields') or {}
    snap = capture.get('transport_snapshot') or {}
    pool: Dict[str, str] = {}
    for k, v in resolved.items():
        if v not in (None, ''):
            pool[k] = str(v)
    for k, v in snap.items():
        if v not in (None, ''):
            pool[k] = str(v)
    host = capture.get('host')
    if host:
        pool.setdefault('Host', str(host))
    return pool


def _capture_body_params(capture: Dict[str, Any]) -> Dict[str, Any]:
    proc = capture.get('crypto_processing') or {}
    plain = (proc.get('decrypted') or {}).get('body_form')
    if not plain:
        return {}
    try:
        parsed = json.loads(str(plain))
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def _parse_query_decrypted(decrypted: Dict[str, Any]) -> Dict[str, str]:
    raw = (decrypted or {}).get('query')
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items() if v is not None}
    if isinstance(raw, str) and raw.strip():
        from minidrifter.runtime.crypto.common import parse_kv_string
        return {k: str(v) for k, v in parse_kv_string(raw).items()}
    return {}


def _capture_wire_params(
    capture: Dict[str, Any],
    *,
    pack_dir: Optional[Path] = None,
) -> Tuple[str, Dict[str, str], Dict[str, Any]]:
    """Extract HTTP method + query/body wire from intake capture (plaintext or decrypted)."""
    method = (capture.get('method') or 'GET').upper()
    proc = capture.get('crypto_processing') or {}
    decrypted = proc.get('decrypted') or {}
    query = _parse_query_decrypted(decrypted)
    body = _capture_body_params(capture)

    if pack_dir and not query and not body:
        from minidrifter.materials.intake_param_hints import _hint_from_plaintext_capture
        hint = _hint_from_plaintext_capture(capture, pack_dir=pack_dir)
        if hint:
            method = str(hint.get('method') or method).upper()
            if hint.get('transport') == 'form_body':
                body = dict(hint.get('body_params') or {})
            else:
                query = {str(k): str(v) for k, v in hint.get('param_pairs') or []}
    return method, query, body


def _load_json_file(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        doc = json.loads(path.read_text(encoding='utf-8'))
        return doc if isinstance(doc, dict) else {}
    except json.JSONDecodeError:
        return {}


def _static_crypto_can_replay(
    pack_dir: Optional[Path],
    baseline_context: Dict[str, Any],
) -> bool:
    if baseline_context.get('crypto_replay_ready') is True:
        return True
    if pack_dir:
        crypto_doc = _load_json_file(Path(pack_dir) / 'crypto_static_profile.json')
        if crypto_doc.get('can_replay'):
            return True
    return False


def _load_signature_profile(pack_dir: Optional[Path]) -> Dict[str, Any]:
    if not pack_dir:
        return {}
    path = Path(pack_dir) / 'signature_profile.json'
    if not path.exists():
        return {}
    try:
        doc = json.loads(path.read_text(encoding='utf-8'))
        return doc if isinstance(doc, dict) else {}
    except json.JSONDecodeError:
        return {}


def _replay_mode_meta(
    capture: Optional[Dict[str, Any]],
    baseline_context: Dict[str, Any],
    *,
    pack_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    if not capture:
        can_replay = _static_crypto_can_replay(pack_dir, baseline_context)
        return {
            'replay_mode': baseline_context.get('replay_mode') or (
                'crypto_materialize' if can_replay else 'template_only'
            ),
            'signature_mode': 'recompute' if can_replay else 'unknown',
            'can_recompute_signature': can_replay,
            'can_replay': can_replay,
            'mutation_policy': 'crypto_materialize' if can_replay else 'template_only',
        }
    status = str(capture.get('overall_status') or '')
    ta = capture.get('transport_assessment') or {}
    proc = capture.get('crypto_processing') or {}
    input_mode = str(proc.get('input_mode') or '')
    is_plain = (
        status.startswith('acceptable_plaintext')
        or ta.get('transport_mode') == 'plaintext_only'
        or ta.get('plaintext_usable')
        or input_mode.startswith('plaintext')
    )
    if is_plain:
        sig_profile = _load_signature_profile(pack_dir)
        can_recompute = bool(sig_profile.get('can_recompute_signature'))
        if not can_recompute:
            can_recompute = _static_crypto_can_replay(pack_dir, baseline_context)
        return {
            'replay_mode': 'plaintext_direct',
            'signature_mode': 'recompute' if can_recompute else 'reuse_capture_signature',
            'can_recompute_signature': can_recompute,
            'can_replay': can_recompute,
            'mutation_policy': 'controlled_subject_mutation' if can_recompute else 'exact_replay_first',
            'signature_profile_id': sig_profile.get('signature_profile_id'),
        }
    can_replay_sig = bool(proc.get('can_replay') and proc.get('sign_check'))
    if not can_replay_sig:
        can_replay_sig = _static_crypto_can_replay(pack_dir, baseline_context)
    return {
        'replay_mode': baseline_context.get('replay_mode') or 'crypto_materialize',
        'signature_mode': 'recompute' if can_replay_sig else 'unknown',
        'can_recompute_signature': can_replay_sig,
        'can_replay': can_replay_sig,
        'mutation_policy': 'crypto_materialize',
    }


def _capture_headers(capture: Dict[str, Any], template: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if template:
        ht = (template.get('http_template') or {}).get('headers') or {}
        headers.update({k: str(v) for k, v in ht.items() if v is not None})
    for layer in capture.get('field_layers') or []:
        if layer.get('location') != 'header':
            continue
        name = layer.get('name')
        if not name:
            continue
        low = str(name).lower()
        if low in {'host', 'content-length', 'connection', 'accept-encoding'}:
            continue
        if low == 'appletencrypt':
            headers.setdefault('appletEncrypt', 'appletEncrypt')
    return headers


def _param_keys(capture: Dict[str, Any]) -> Set[str]:
    keys: Set[str] = set()
    for layer in capture.get('field_layers') or []:
        if layer.get('location') in {'body', 'query'} and layer.get('name'):
            keys.add(str(layer['name']).lower())
    proc = capture.get('crypto_processing') or {}
    for k in (proc.get('resolved_fields') or {}):
        if k.lower() not in CRYPTO_TRANSPORT_FIELDS:
            keys.add(k.lower())
    return keys


def _domain_from_path(path: str) -> str:
    parts = [p for p in normalize_api_path(path).split('/') if p]
    return parts[1] if len(parts) > 2 else ''


def score_capture_match(
    api_path: str,
    api_entry: Dict[str, Any],
    capture: Dict[str, Any],
    *,
    template: Optional[Dict[str, Any]] = None,
) -> float:
    """Rank baseline captures for sensitive API replay context inheritance."""
    score = 0.0
    api_norm = normalize_api_path(api_path)
    cap_path = normalize_api_path(capture.get('path') or '')
    if cap_path == api_norm:
        score += EXACT_PATH_SCORE
    elif cap_path and api_norm and (cap_path in api_norm or api_norm in cap_path):
        score += PARTIAL_PATH_SCORE
    elif _domain_from_path(cap_path) and _domain_from_path(cap_path) == _domain_from_path(api_norm):
        score += DOMAIN_FALLBACK_SCORE

    cap_host = (capture.get('host') or '').lower()
    pool_host = str(
        ((capture.get('crypto_processing') or {}).get('resolved_fields') or {}).get('Host') or ''
    ).lower()
    entry_host = str(api_entry.get('host') or '').lower()
    if cap_host and entry_host and cap_host == entry_host:
        score += 8.0
    if pool_host and entry_host and pool_host == entry_host:
        score += 6.0

    proc = capture.get('crypto_processing') or {}
    tpl_crypto = (template or {}).get('crypto_profile') or {}
    if proc.get('profile_id') and tpl_crypto.get('profile_id'):
        if proc.get('profile_id') == tpl_crypto.get('profile_id'):
            score += 10.0
    if proc.get('can_replay'):
        score += 8.0
    if proc.get('sign_check'):
        score += 5.0

    if str(capture.get('overall_status') or '').startswith('acceptable'):
        score += 6.0

    resp = capture.get('response_crypto_processing') or {}
    if resp.get('body_json'):
        score += 4.0

    tpl_keys: Set[str] = set()
    plain = (template or {}).get('plain_template') or {}
    for bag in (plain.get('body_params') or {}, plain.get('params') or {}):
        tpl_keys.update(str(k).lower() for k in bag)
    if tpl_keys:
        overlap = len(tpl_keys & _param_keys(capture))
        score += overlap * 3.0

    return score


def select_best_matching_capture(
    api_path: str,
    api_entry: Dict[str, Any],
    captures: List[Dict[str, Any]],
    *,
    template: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[Dict[str, Any]], float]:
    acceptable = [
        c for c in captures
        if str(c.get('overall_status') or '').startswith('acceptable')
    ]
    api_norm = normalize_api_path(api_path)
    exact = [
        c for c in acceptable
        if normalize_api_path(c.get('path') or '') == api_norm
    ]
    pool = exact if exact else acceptable
    best: Optional[Dict[str, Any]] = None
    best_score = -1.0
    for cap in pool:
        s = score_capture_match(api_path, api_entry, cap, template=template)
        if s > best_score:
            best_score = s
            best = cap
    return best, best_score


def _environment_fields(
    *,
    aggregate: Dict[str, Any],
    object_pool: Dict[str, Any],
    baseline_context: Dict[str, Any],
) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for src in (
        aggregate.get('fields') or {},
        object_pool.get('objects') or {},
        _baseline_pool(baseline_context),
    ):
        if not isinstance(src, dict):
            continue
        for k, v in src.items():
            if v in (None, ''):
                continue
            if k.lower() in CRYPTO_TRANSPORT_FIELDS:
                continue
            if k.lower() in ENV_FIELD_HINTS or k in ENV_FIELD_HINTS:
                out[k] = str(v)
    return out


def _static_subject_field_names(
    pack_dir: Optional[Path],
    api_path: str,
    template: Optional[Dict[str, Any]],
) -> List[str]:
    names: List[str] = []
    if pack_dir:
        gap_doc = load_json(pack_dir / 'subject_wire_gap_plan.json') or {}
        norm = normalize_api_path(api_path)
        for gap in gap_doc.get('gaps') or []:
            if normalize_api_path(gap.get('path') or gap.get('api') or '') == norm:
                names.extend(gap.get('static_subject_fields') or [])
    names.extend(infer_subject_fields_from_path(api_path))
    if template:
        plain = template.get('plain_template') or {}
        for bag in (plain.get('body_params') or {}, plain.get('params') or {}):
            if isinstance(bag, dict):
                for k in bag:
                    if field_allowed(str(k))[0]:
                        names.append(str(k))
    ordered: List[str] = []
    seen: Set[str] = set()
    by_norm = {norm_field(n): n for n in names}
    for pref in SUBJECT_PRIORITY:
        nf = norm_field(pref)
        if nf in by_norm and nf not in seen:
            seen.add(nf)
            ordered.append(by_norm[nf])
    for n in names:
        nf = norm_field(n)
        if nf not in seen:
            seen.add(nf)
            ordered.append(n)
    return ordered


def _inject_static_subject_fields(
    pack_dir: Optional[Path],
    api_path: str,
    *,
    query_params: Dict[str, str],
    body_params: Dict[str, Any],
    http_method: str,
    pool: Dict[str, str],
    template: Optional[Dict[str, Any]],
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    """Fill missing subject identifiers from gap plan / path hints + baseline pool."""
    fields = _static_subject_field_names(pack_dir, api_path, template)
    if not fields:
        return query_params, body_params

    query_out = dict(query_params)
    body_out = dict(body_params)
    plain = (template or {}).get('plain_template') or {}
    method = str(http_method or plain.get('method') or 'POST').upper()

    for field in fields:
        val = pool_value_for_subject_field(field, pool)
        if not val:
            continue
        target_key = field
        loc = 'body'
        for bag_name, bag in (('body', plain.get('body_params')), ('query', plain.get('params'))):
            if not isinstance(bag, dict):
                continue
            for k in bag:
                if norm_field(k) == norm_field(field):
                    target_key = str(k)
                    loc = bag_name
                    break
        if norm_field(target_key) in {norm_field(k) for k in body_out}:
            if str(body_out.get(target_key) or '') in ('', 'None'):
                body_out[target_key] = val
            continue
        if norm_field(target_key) in {norm_field(k) for k in query_out}:
            if str(query_out.get(target_key) or '') in ('', 'None'):
                query_out[target_key] = val
            continue
        if loc == 'query' or method == 'GET':
            query_out.setdefault(target_key, val)
        else:
            body_out.setdefault(target_key, val)

    path_norm = normalize_api_path(api_path).lower()
    if any(marker in path_norm for marker in ('personaldata', 'identitycard')):
        subject_body: Dict[str, Any] = {}
        for field in fields:
            val = pool_value_for_subject_field(field, pool)
            if not val:
                continue
            key = field
            for k in body_out:
                if norm_field(k) == norm_field(field):
                    key = k
                    break
            subject_body[key] = val
        if subject_body:
            body_out = subject_body
            query_out = {}

    return query_out, body_out


def build_replay_context_for_api(
    api_path: str,
    api_entry: Dict[str, Any],
    *,
    captures: List[Dict[str, Any]],
    baseline_context: Dict[str, Any],
    template: Optional[Dict[str, Any]],
    aggregate: Dict[str, Any],
    object_pool: Dict[str, Any],
    pack_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    capture, match_score = select_best_matching_capture(
        api_path, api_entry, captures, template=template,
    )
    if template and (template.get('path_inferred_synthetic') or template.get('gap_plan_synthetic')):
        capture = None
        match_score = 0.0
    capture_pool = _capture_pool(capture) if capture else {}
    merged_pool = {**_baseline_pool(baseline_context), **capture_pool}
    env_fields = _environment_fields(
        aggregate=aggregate, object_pool=object_pool, baseline_context=baseline_context,
    )
    http_method = 'GET'
    query_params: Dict[str, str] = {}
    body_params: Dict[str, Any] = {}
    if capture:
        http_method, query_params, body_params = _capture_wire_params(capture, pack_dir=pack_dir)
    if not body_params and not query_params and template:
        plain = template.get('plain_template') or {}
        body_params = dict(plain.get('body_params') or {})
        query_params = {str(k): str(v) for k, v in (plain.get('params') or {}).items()}
        http_method = str(plain.get('method') or http_method).upper()

    query_params, body_params = _inject_static_subject_fields(
        pack_dir,
        api_path,
        query_params=query_params,
        body_params=body_params,
        http_method=http_method,
        pool=merged_pool,
        template=template,
    )

    replay_meta = _replay_mode_meta(capture, baseline_context, pack_dir=pack_dir)

    return {
        'api': api_entry.get('path') or api_path,
        'api_id': api_entry.get('api_id'),
        'primary_plane': api_entry.get('primary_plane'),
        'campaign_role': api_entry.get('recommended_campaign_role'),
        'capture_match_score': round(match_score, 2) if capture else 0.0,
        'capture_index': capture.get('capture_index') if capture else None,
        'capture_id': capture.get('capture_id') if capture else None,
        'capture_path': capture.get('path') if capture else None,
        'capture_method': capture.get('method') if capture else None,
        **replay_meta,
        'replay_context': {
            'credential_source': 'baseline',
            'http_method': http_method,
            'headers': _capture_headers(capture, template) if capture else (
                (template or {}).get('http_template') or {}
            ).get('headers') or {},
            'query': query_params,
            'body': body_params,
            'crypto_profile': (
                (template or {}).get('crypto_profile') or {}
            ).get('profile_id') or baseline_context.get('crypto_profile'),
            'transport_style': (
                baseline_context.get('transport_style')
                or ((template or {}).get('crypto_profile') or {}).get('transport_style')
            ),
            'pool': merged_pool,
            'environment_fields': env_fields,
            **replay_meta,
        },
        'evidence_preference': ['live_campaign', 'baseline_intake'],
    }


def build_sensitive_replay_context(
    pack_dir: Path,
    *,
    api_paths: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Build sensitive_replay_context.json for materialized sensitive-plane APIs."""
    pack_dir = Path(pack_dir)
    idx = plane_index_by_path(pack_dir)
    intake = load_intake_report(pack_dir) or {}
    captures = intake.get('captures') or []
    baseline_context = load_json(pack_dir / 'baseline_runtime_context.json') or {}
    aggregate = load_json(pack_dir / 'aggregate_materials.json') or {}
    object_pool = load_json(pack_dir / 'chain_object_pool.json') or {}
    tpl_doc = load_json(pack_dir / 'materialized_api_templates.json') or {}
    templates_by_path = {
        normalize_api_path(t.get('path') or ''): t
        for t in (tpl_doc.get('templates') or []) if t.get('path')
    }
    from minidrifter.verification.sensitive_target_enrollment import (
        collect_enrollment_synthetic_templates,
    )
    for norm, tpl in collect_enrollment_synthetic_templates(
        pack_dir, baseline_context=baseline_context,
    ).items():
        templates_by_path.setdefault(norm, tpl)

    entries: List[Dict[str, Any]] = []
    built_paths: Set[str] = set()

    def _append_entry(path: str, entry: Dict[str, Any], template: Optional[Dict[str, Any]]) -> None:
        norm = normalize_api_path(path)
        if norm in built_paths:
            return
        built_paths.add(norm)
        entries.append(build_replay_context_for_api(
            path, entry,
            captures=captures,
            baseline_context=baseline_context,
            template=template,
            aggregate=aggregate,
            object_pool=object_pool,
            pack_dir=pack_dir,
        ))

    for path, entry in idx.items():
        role = entry.get('recommended_campaign_role') or ''
        plane = entry.get('primary_plane') or ''
        if role not in SENSITIVE_READ_ROLES and plane not in SENSITIVE_PLANES:
            continue
        norm = normalize_api_path(path)
        if api_paths and norm not in {normalize_api_path(p) for p in api_paths}:
            continue
        template = templates_by_path.get(norm)
        if not template:
            continue
        _append_entry(path, entry, template)

    from minidrifter.classification.api_plane_classifier import classify_path_to_plane_entry
    from minidrifter.verification.sensitive_target_enrollment import (
        ENROLLMENT_PLANES,
        ENROLLMENT_ROLES,
        build_intake_synthetic_template,
        _best_capture_for_path,
    )
    paths_seen: Set[str] = set()
    for cap in captures:
        path = cap.get('path') or ''
        norm = normalize_api_path(path)
        if not norm or norm in paths_seen or norm in built_paths:
            continue
        paths_seen.add(norm)
        if api_paths and norm not in {normalize_api_path(p) for p in api_paths}:
            continue
        entry = classify_path_to_plane_entry(path)
        role = entry.get('recommended_campaign_role') or ''
        plane = entry.get('primary_plane') or ''
        if plane not in ENROLLMENT_PLANES and role not in ENROLLMENT_ROLES:
            continue
        best_cap = _best_capture_for_path(captures, path)
        if not best_cap:
            continue
        template = templates_by_path.get(norm) or build_intake_synthetic_template(
            best_cap, baseline_context=baseline_context, plane_entry=entry, pack_dir=pack_dir,
        )
        _append_entry(path, entry, template)

    doc = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'api_count': len(entries),
        'entries': entries,
        'by_path': {
            normalize_api_path(e['api']): e for e in entries if e.get('api')
        },
    }
    return doc


def write_sensitive_replay_context(pack_dir: Path, **kwargs: Any) -> Path:
    pack_dir = Path(pack_dir)
    doc = build_sensitive_replay_context(pack_dir, **kwargs)
    out = pack_dir / 'sensitive_replay_context.json'
    write_json(out, doc)
    return out


def lookup_replay_context(
    pack_dir: Path,
    api_path: str,
    *,
    context_doc: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    if context_doc is None:
        path = Path(pack_dir) / 'sensitive_replay_context.json'
        if not path.exists():
            # Avoid lazy build: enrollment/template synthesis calls lookup during
            # build_sensitive_replay_context and would recurse infinitely.
            return None
        context_doc = json.loads(path.read_text(encoding='utf-8'))
    return (context_doc.get('by_path') or {}).get(normalize_api_path(api_path))
