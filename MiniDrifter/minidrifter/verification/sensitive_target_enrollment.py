# -*- coding: utf-8 -*-
"""P4-fix-4.5 — enroll baseline intake APIs into sensitive_read targets."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Set

from minidrifter.classification.api_plane_classifier import classify_path_to_plane_entry
from minidrifter.materials.intake_param_hints import load_intake_report, normalize_api_path
from minidrifter.verification.sensitive_replay_context_builder import (
    SENSITIVE_PLANES,
    _capture_wire_params,
    _replay_mode_meta,
)
from minidrifter.verification.subject_override_fields import (
    SUBJECT_PRIORITY,
    infer_subject_fields_from_path,
    pool_value_for_subject_field,
)

ENROLLMENT_PLANES = SENSITIVE_PLANES | frozenset({'contact_address_invoice'})

ENROLLMENT_ROLES = frozenset({
    'read_sensitive_state',
    'verification_state_probe',
    'account_state_probe',
    'address_invoice_probe',
})


def is_path_inferred_subject_read_target(path: str) -> bool:
    """Generic path-shape rule for subject-only POST read APIs without baseline capture."""
    norm = normalize_api_path(path).lower()
    if not infer_subject_fields_from_path(path):
        return False
    return 'personaldata' in norm and 'get' in norm


def _api_id_for_path(pack_dir, path: str) -> str:
    from pathlib import Path
    from minidrifter.business_chain.chain_run_context import load_json

    norm = normalize_api_path(path)
    doc = load_json(Path(pack_dir) / 'api_plane_index.json') or {}
    for entry in doc.get('entries') or []:
        if normalize_api_path(entry.get('path') or '') == norm:
            return str(entry.get('api_id') or _stable_api_id(path))
    return _stable_api_id(path)


def discover_path_inferred_subject_read_paths(
    pack_dir,
    *,
    covered_paths: Optional[Set[str]] = None,
    templates_by_id: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[str]:
    """Find sensitive read APIs that match path-shape enrollment but lack materialized templates."""
    from pathlib import Path
    from minidrifter.business_chain.chain_run_context import load_json
    from minidrifter.classification.api_plane_classifier import plane_index_by_path

    pack_dir = Path(pack_dir)
    covered_paths = covered_paths or set()
    templates_by_id = templates_by_id or {}
    mat_paths = {
        normalize_api_path(t.get('path') or '')
        for t in (load_json(pack_dir / 'materialized_api_templates.json') or {}).get('templates') or []
        if t.get('path')
    }
    intake_paths = {
        normalize_api_path(c.get('path') or '')
        for c in (load_intake_report(pack_dir) or {}).get('captures') or []
        if str(c.get('overall_status') or '').startswith('acceptable')
    }

    discovered: List[str] = []
    for path in plane_index_by_path(pack_dir):
        norm = normalize_api_path(path)
        if not norm or norm in covered_paths or norm in mat_paths:
            continue
        if norm in intake_paths:
            continue
        if not is_path_inferred_subject_read_target(path):
            continue
        api_id = _api_id_for_path(pack_dir, path)
        if api_id and templates_by_id.get(api_id):
            continue
        discovered.append(path)
    discovered.sort()
    return discovered


def _stable_api_id(path: str) -> str:
    digest = hashlib.sha256(normalize_api_path(path).encode('utf-8')).hexdigest()[:12]
    return f'intake_{digest}'


def build_intake_synthetic_template(
    capture: Dict[str, Any],
    *,
    baseline_context: Dict[str, Any],
    plane_entry: Dict[str, Any],
    pack_dir=None,
) -> Dict[str, Any]:
    """Minimal materialized template from an intake capture for sensitive replay."""
    path = capture.get('path') or ''
    if pack_dir is not None:
        api_id = _api_id_for_path(pack_dir, path)
    else:
        api_id = _stable_api_id(path)
    transport = (
        baseline_context.get('transport_style')
        or (capture.get('static_crypto_crossref') or {}).get('transport_style')
        or 'form_cid_q_sign'
    )
    profile_id = (
        baseline_context.get('crypto_profile')
        or (capture.get('crypto_processing') or {}).get('profile_id')
        or 'token_sign_aes_wrapper'
    )
    method, query_params, body_params = _capture_wire_params(capture)
    if not isinstance(body_params, dict):
        body_params = {}
    replay_meta = _replay_mode_meta(capture, baseline_context)
    is_plain = replay_meta.get('replay_mode') == 'plaintext_direct'
    return {
        'api_id': api_id,
        'card_id': api_id,
        'path': path,
        'method': method,
        'side_effect_level': 'S0_read_only',
        'status': 'materialized_plain' if is_plain else 'materialized_with_crypto_profile',
        'crypto_required': not is_plain,
        'intake_synthetic': True,
        'plain_template': {
            'method': method,
            'path': path,
            'params': query_params,
            'body_params': body_params,
            'transport_style': transport,
            'param_source': 'intake_plaintext_capture' if is_plain else None,
        },
        'crypto_profile': {
            'profile_id': profile_id,
            'available': not is_plain,
            'transport_style': transport,
        },
        'http_template': {
            'method': method,
            'path': path,
            'headers': {
                'Content-Type': 'application/x-www-form-urlencoded',
                'appletEncrypt': 'appletEncrypt',
            },
            'body_mode': transport,
        },
        'primary_plane': plane_entry.get('primary_plane'),
        'campaign_role': plane_entry.get('recommended_campaign_role'),
        **replay_meta,
    }


def _best_capture_for_path(captures: List[Dict[str, Any]], path: str) -> Optional[Dict[str, Any]]:
    norm = normalize_api_path(path)
    best: Optional[Dict[str, Any]] = None
    best_score = -1.0
    for cap in captures:
        if normalize_api_path(cap.get('path') or '') != norm:
            continue
        if not str(cap.get('overall_status') or '').startswith('acceptable'):
            continue
        score = 0.0
        if (cap.get('crypto_processing') or {}).get('can_replay'):
            score += 5.0
        if (cap.get('crypto_processing') or {}).get('sign_check'):
            score += 3.0
        resp = cap.get('response_crypto_processing') or {}
        if isinstance(resp.get('body_json'), dict):
            score += 4.0
        for layer in cap.get('field_layers') or []:
            name = str(layer.get('name') or '').lower()
            val = str(layer.get('value') or '')
            if name == 'authorization':
                if val.lower().startswith('bearer ') and val not in {'Bearer 123', 'bearer 123'} and len(val) > 24:
                    score += 12.0
                elif val == '123':
                    score -= 4.0
            if name == 'sign' and val:
                score += 6.0
        if score > best_score:
            best_score = score
            best = cap
    return best


def enroll_intake_sensitive_targets(
    pack_dir,
    *,
    covered_paths: Set[str],
    seen: Optional[Set[str]] = None,
    baseline_context: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Discover sensitive-plane APIs from baseline intake not in static plane index."""
    from pathlib import Path

    pack_dir = Path(pack_dir)
    intake = load_intake_report(pack_dir) or {}
    if baseline_context is None:
        from minidrifter.business_chain.chain_run_context import load_json
        baseline_context = load_json(pack_dir / 'baseline_runtime_context.json') or {}

    seen = seen or set()
    captures = intake.get('captures') or []
    paths_seen: Set[str] = set()
    enrolled: List[Dict[str, Any]] = []

    for cap in captures:
        path = cap.get('path') or ''
        norm = normalize_api_path(path)
        if not norm or norm in paths_seen:
            continue
        paths_seen.add(norm)
        if norm in covered_paths or norm in seen:
            continue

        entry = classify_path_to_plane_entry(path)
        role = entry.get('recommended_campaign_role') or ''
        plane = entry.get('primary_plane') or ''
        path_subjects = infer_subject_fields_from_path(path)
        if plane not in ENROLLMENT_PLANES and role not in ENROLLMENT_ROLES:
            if not path_subjects:
                continue

        best_cap = _best_capture_for_path(captures, path)
        if not best_cap:
            continue

        template = build_intake_synthetic_template(
            best_cap, baseline_context=baseline_context, plane_entry=entry, pack_dir=pack_dir,
        )
        sens = float(entry.get('sensitivity_score') or 0.5)
        if 'membership' in norm.lower():
            sens = max(sens, 0.9)

        enrolled.append({
            'api_id': template['api_id'],
            'path': path,
            'rule_score': sens * 100,
            'combined_score': sens * 100 + (20.0 if template.get('intake_synthetic') else 0.0),
            'campaign_role': role,
            'primary_plane': plane,
            'planes': entry.get('planes') or [],
            'materialized': True,
            'replay_ready': True,
            'probe_eligible': True,
            'verification_intent': 'sensitive_read_state',
            'intake_enrolled': True,
            'synthetic_template': template,
        })

    enrolled.sort(key=lambda x: -float(x.get('combined_score') or 0))
    return enrolled


def build_gap_plan_synthetic_template(
    gap: Dict[str, Any],
    *,
    baseline_context: Dict[str, Any],
    plane_entry: Dict[str, Any],
    pack_dir=None,
) -> Dict[str, Any]:
    """Minimal crypto template for gap-plan APIs without baseline capture."""
    from pathlib import Path

    path = gap.get('path') or gap.get('api') or ''
    api_id = gap.get('api_id') or (_api_id_for_path(pack_dir, path) if pack_dir else _stable_api_id(path))
    transport = baseline_context.get('transport_style') or 'form_cid_q_sign'
    profile_id = baseline_context.get('crypto_profile') or 'token_sign_aes_wrapper'
    method = str(gap.get('method') or 'POST').upper()
    pool = {
        k: str(v.get('value'))
        for k, v in (baseline_context.get('resolved_fields') or {}).items()
        if isinstance(v, dict) and v.get('value') is not None
    }
    body_params: Dict[str, Any] = {}
    query_params: Dict[str, str] = {}
    fields = list(gap.get('static_subject_fields') or [])
    for inf in infer_subject_fields_from_path(path):
        if inf not in fields:
            fields.append(inf)
    path_norm = normalize_api_path(path).lower()
    member_only_body = 'personaldata' in path_norm or 'identitycard' in path_norm
    if member_only_body:
        body_params = {}
        query_params = {}
        method = 'POST'
    elif pack_dir:
        from minidrifter.business_chain.chain_run_context import load_json
        from minidrifter.verification.sensitive_replay_context_builder import lookup_replay_context
        replay = lookup_replay_context(Path(pack_dir), path) or {}
        inner = replay.get('replay_context') or {}
        body_params.update(inner.get('body') or {})
        query_params.update({str(k): str(v) for k, v in (inner.get('query') or {}).items()})
        method = str(inner.get('http_method') or method).upper()
    for pref in SUBJECT_PRIORITY:
        for field in fields:
            if field.lower().replace('_', '') != pref.lower().replace('_', ''):
                continue
            val = pool_value_for_subject_field(field, pool)
            if not val:
                continue
            if method == 'GET':
                query_params[field] = val
            else:
                body_params[field] = val
            break
    return {
        'api_id': api_id,
        'card_id': api_id,
        'path': path,
        'method': method,
        'side_effect_level': 'S0_read_only',
        'status': 'materialized_with_crypto_profile',
        'crypto_required': True,
        'gap_plan_synthetic': True,
        'plain_template': {
            'method': method,
            'path': path,
            'params': query_params,
            'body_params': body_params,
            'transport_style': transport,
            'param_source': 'gap_plan_synthetic',
        },
        'crypto_profile': {
            'profile_id': profile_id,
            'available': True,
            'transport_style': transport,
        },
        'http_template': {
            'method': method,
            'path': path,
            'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
            'body_mode': transport,
        },
        'primary_plane': plane_entry.get('primary_plane'),
        'campaign_role': plane_entry.get('recommended_campaign_role'),
    }


def enroll_gap_plan_sensitive_targets(
    pack_dir,
    *,
    covered_paths: Set[str],
    seen: Optional[Set[str]] = None,
    baseline_context: Optional[Dict[str, Any]] = None,
    templates_by_id: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Enroll high-priority gap-plan APIs that lack materialized templates."""
    from pathlib import Path
    from minidrifter.business_chain.chain_run_context import load_json

    pack_dir = Path(pack_dir)
    if baseline_context is None:
        baseline_context = load_json(pack_dir / 'baseline_runtime_context.json') or {}
    gap_doc = load_json(pack_dir / 'subject_wire_gap_plan.json') or {}
    seen = seen or set()
    templates_by_id = templates_by_id or {}
    enrolled: List[Dict[str, Any]] = []

    for gap in sorted(gap_doc.get('gaps') or [], key=lambda g: -float(g.get('priority') or 0)):
        path = gap.get('path') or gap.get('api') or ''
        norm = normalize_api_path(path)
        api_id = gap.get('api_id') or ''
        if not norm or norm in covered_paths or norm in seen:
            continue
        if api_id and templates_by_id.get(api_id):
            continue
        entry = classify_path_to_plane_entry(path)
        template = build_gap_plan_synthetic_template(
            gap,
            baseline_context=baseline_context,
            plane_entry=entry,
            pack_dir=pack_dir,
        )
        enrolled.append({
            'api_id': template['api_id'],
            'path': path,
            'rule_score': float(gap.get('priority') or 0.9) * 100,
            'combined_score': float(gap.get('priority') or 0.9) * 100 + 25.0,
            'campaign_role': gap.get('campaign_role') or entry.get('recommended_campaign_role'),
            'primary_plane': gap.get('plane') or entry.get('primary_plane'),
            'planes': entry.get('planes') or [],
            'materialized': True,
            'replay_ready': True,
            'probe_eligible': True,
            'verification_intent': 'subject_binding_gap_plan',
            'gap_plan_enrolled': True,
            'synthetic_template': template,
        })
        seen.add(norm)
    return enrolled


def enroll_path_inferred_sensitive_targets(
    pack_dir,
    *,
    covered_paths: Set[str],
    seen: Optional[Set[str]] = None,
    baseline_context: Optional[Dict[str, Any]] = None,
    templates_by_id: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Enroll path-shape sensitive read APIs (e.g. personalData/get) without baseline capture."""
    from pathlib import Path
    from minidrifter.business_chain.chain_run_context import load_json

    pack_dir = Path(pack_dir)
    if baseline_context is None:
        baseline_context = load_json(pack_dir / 'baseline_runtime_context.json') or {}
    seen = seen or set()
    templates_by_id = templates_by_id or {}
    enrolled: List[Dict[str, Any]] = []

    for path in discover_path_inferred_subject_read_paths(
        pack_dir,
        covered_paths=covered_paths | seen,
        templates_by_id=templates_by_id,
    ):
        norm = normalize_api_path(path)
        if norm in seen:
            continue
        entry = classify_path_to_plane_entry(path)
        subjects = infer_subject_fields_from_path(path)
        gap = {
            'path': path,
            'api': path,
            'api_id': _api_id_for_path(pack_dir, path),
            'method': 'POST',
            'static_subject_fields': subjects,
            'priority': float(entry.get('sensitivity_score') or 0.9),
        }
        template = build_gap_plan_synthetic_template(
            gap,
            baseline_context=baseline_context,
            plane_entry=entry,
            pack_dir=None,
        )
        template['path_inferred_synthetic'] = True
        template['gap_plan_synthetic'] = False
        enrolled.append({
            'api_id': template['api_id'],
            'path': path,
            'rule_score': float(gap.get('priority') or 0.9) * 100,
            'combined_score': float(gap.get('priority') or 0.9) * 100 + 30.0,
            'campaign_role': entry.get('recommended_campaign_role'),
            'primary_plane': entry.get('primary_plane'),
            'planes': entry.get('planes') or [],
            'materialized': True,
            'replay_ready': True,
            'probe_eligible': True,
            'verification_intent': 'subject_binding_gap_plan',
            'path_inferred_enrolled': True,
            'synthetic_template': template,
        })
        seen.add(norm)
    return enrolled


def collect_enrollment_synthetic_templates(
    pack_dir,
    *,
    baseline_context: Optional[Dict[str, Any]] = None,
    templates_by_id: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Dict[str, Any]]:
    """Merge intake / gap-plan / path-inferred synthetic templates keyed by normalized path."""
    from pathlib import Path

    pack_dir = Path(pack_dir)
    if baseline_context is None:
        from minidrifter.business_chain.chain_run_context import load_json
        baseline_context = load_json(pack_dir / 'baseline_runtime_context.json') or {}

    templates_by_id = dict(templates_by_id or {})
    by_path: Dict[str, Dict[str, Any]] = {}
    seen_paths: Set[str] = set()

    for enroll_fn in (
        enroll_intake_sensitive_targets,
        enroll_gap_plan_sensitive_targets,
        enroll_path_inferred_sensitive_targets,
    ):
        kwargs: Dict[str, Any] = {
            'pack_dir': pack_dir,
            'covered_paths': set(),
            'seen': seen_paths,
            'baseline_context': baseline_context,
        }
        if enroll_fn is not enroll_intake_sensitive_targets:
            kwargs['templates_by_id'] = templates_by_id
        for cand in enroll_fn(**kwargs):
            tpl = cand.get('synthetic_template')
            path = cand.get('path') or (tpl or {}).get('path') or ''
            norm = normalize_api_path(path)
            if not norm or not tpl:
                continue
            by_path[norm] = tpl
            api_id = tpl.get('api_id')
            if api_id:
                templates_by_id[api_id] = tpl
    return by_path
