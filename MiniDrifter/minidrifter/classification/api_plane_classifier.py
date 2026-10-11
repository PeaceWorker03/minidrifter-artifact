# -*- coding: utf-8 -*-
"""Classify APIs into sensitive coverage planes (P4)."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.core.utils import write_json
from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.quality.sensitive_surface import classify_sensitive_surface_from_card

PACKS_ROOT = Path(__file__).resolve().parents[2] / 'packs'
ONTOLOGY_PATH = PACKS_ROOT / 'sensitive_field_ontology.json'

PLANE_ORDER = [
    'realname_verification',
    'user_profile_personal_info',
    'account_state_wallet',
    'contact_address_invoice',
    'business_object',
    'credential_session',
    'action_operation',
    'environment_public',
]

RISK_FROM_SENSITIVITY = (
    (0.9, 'high'),
    (0.7, 'medium'),
    (0.4, 'low'),
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def load_sensitive_field_ontology() -> Dict[str, Any]:
    if not ONTOLOGY_PATH.exists():
        return {'planes': {}, 'field_classes': {}}
    return json.loads(ONTOLOGY_PATH.read_text(encoding='utf-8'))


def _token_re(tokens: List[str]) -> re.Pattern:
    parts = [re.escape(t).replace(r'\ ', r'[\s_/\-]?') for t in tokens if t]
    return re.compile('|'.join(parts), re.I) if parts else re.compile(r'(?!x)x')


def _compile_plane_patterns(ontology: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    compiled: Dict[str, Dict[str, Any]] = {}
    for plane_id, spec in (ontology.get('planes') or {}).items():
        compiled[plane_id] = {
            **spec,
            'path_re': _token_re(spec.get('path_tokens') or []),
            'param_re': _token_re(spec.get('param_names') or []),
            'response_re': _token_re(spec.get('response_keys') or []),
        }
    return compiled


def _field_class_for(name: str, ontology: Dict[str, Any]) -> List[str]:
    nl = str(name or '')
    hits: List[str] = []
    for cls, names in (ontology.get('field_classes') or {}).items():
        for n in names:
            if nl == n or nl.lower() == str(n).lower():
                hits.append(cls)
                break
    return hits


def _risk_tier(sensitivity: float) -> str:
    for threshold, tier in RISK_FROM_SENSITIVITY:
        if sensitivity >= threshold:
            return tier
    return 'low'


def _card_path(card: Dict[str, Any]) -> str:
    ep = (card.get('static') or {}).get('endpoint') or {}
    return ep.get('path') or ep.get('normalized_path') or ''


def _card_method(card: Dict[str, Any]) -> str:
    return ((card.get('static') or {}).get('http') or {}).get('method') or 'GET'


def _card_params(card: Dict[str, Any]) -> List[str]:
    params = ((card.get('bindings') or {}).get('params') or [])
    return [str(p.get('name')) for p in params if p.get('name')]


def _card_side_effect(card: Dict[str, Any]) -> str:
    return ((card.get('replay') or {}).get('side_effect') or {}).get('category') or ''


def classify_api_card(
    card: Dict[str, Any],
    *,
    ontology: Optional[Dict[str, Any]] = None,
    compiled: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Return plane tags + sensitive fields for one API card."""
    ontology = ontology or load_sensitive_field_ontology()
    compiled = compiled or _compile_plane_patterns(ontology)
    path = _card_path(card)
    norm_path = normalize_api_path(path)
    method = _card_method(card)
    param_names = _card_params(card)
    side = _card_side_effect(card)
    pii = classify_sensitive_surface_from_card(card)

    matched_planes: List[str] = []
    plane_scores: Dict[str, float] = {}
    sensitive_fields: Set[str] = set()
    subject_fields: Set[str] = set()

    for plane_id in PLANE_ORDER:
        spec = compiled.get(plane_id) or {}
        score = 0.0
        if spec.get('path_re') and spec['path_re'].search(norm_path):
            score += 0.55
        for pn in param_names:
            if spec.get('param_re') and spec['param_re'].search(pn):
                score += 0.25
                sensitive_fields.add(pn)
                subject_fields.update(_field_class_for(pn, ontology))
        if plane_id == 'action_operation':
            allowed = set(spec.get('side_effects') or [])
            if side in allowed or (
                method in {'POST', 'PUT', 'PATCH', 'DELETE'}
                and spec.get('path_re') and spec['path_re'].search(norm_path)
            ):
                score = max(score, 0.5)
        if plane_id == 'environment_public' and score < 0.4:
            if any(tok in norm_path.lower() for tok in ('city', 'dept', 'banner', 'config', 'dict')):
                score = max(score, 0.45)
        if score >= 0.45:
            matched_planes.append(plane_id)
            plane_scores[plane_id] = round(score, 3)

    if not matched_planes and pii.get('pii_surface'):
        matched_planes.append('user_profile_personal_info')
        plane_scores['user_profile_personal_info'] = 0.5

    if not matched_planes:
        matched_planes = ['business_object'] if 'order' in norm_path.lower() else ['environment_public']
        plane_scores[matched_planes[0]] = 0.35

    max_sens = max(
        float((compiled.get(p) or {}).get('sensitivity') or 0.3)
        for p in matched_planes
    )
    primary = max(matched_planes, key=lambda p: float((compiled.get(p) or {}).get('sensitivity') or 0))
    role = (compiled.get(primary) or {}).get('campaign_role') or 'coverage_probe'

    for pn in param_names:
        if re.search(r'(user|member|customer|open)id', pn, re.I):
            subject_fields.add(pn)

    return {
        'api_id': card.get('card_id') or card.get('api_id'),
        'path': path,
        'method': method,
        'planes': matched_planes,
        'primary_plane': primary,
        'plane_scores': plane_scores,
        'sensitive_fields': sorted(sensitive_fields),
        'subject_fields': sorted(subject_fields),
        'pii_surface': bool(pii.get('pii_surface')),
        'flow_kind': pii.get('flow_kind'),
        'probe_style': pii.get('probe_style'),
        'risk_tier': _risk_tier(max_sens),
        'sensitivity_score': round(max_sens, 3),
        'recommended_campaign_role': role,
        'side_effect': side,
    }


def classify_path_to_plane_entry(
    path: str,
    *,
    ontology: Optional[Dict[str, Any]] = None,
    compiled: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Classify a URL path into sensitive planes without a static API card."""
    ontology = ontology or load_sensitive_field_ontology()
    compiled = compiled or _compile_plane_patterns(ontology)
    norm_path = normalize_api_path(path)
    matched_planes: List[str] = []
    plane_scores: Dict[str, float] = {}

    for plane_id in PLANE_ORDER:
        spec = compiled.get(plane_id) or {}
        score = 0.0
        if spec.get('path_re') and spec['path_re'].search(norm_path):
            score += 0.55
        if plane_id == 'action_operation' and spec.get('path_re') and spec['path_re'].search(norm_path):
            score = max(score, 0.5)
        if plane_id == 'environment_public' and score < 0.4:
            if any(tok in norm_path.lower() for tok in ('city', 'dept', 'banner', 'config', 'dict')):
                score = max(score, 0.45)
        if score >= 0.45:
            matched_planes.append(plane_id)
            plane_scores[plane_id] = round(score, 3)

    if not matched_planes:
        matched_planes = ['business_object'] if 'order' in norm_path.lower() else ['environment_public']
        plane_scores[matched_planes[0]] = 0.35

    max_sens = max(
        float((compiled.get(p) or {}).get('sensitivity') or 0.3)
        for p in matched_planes
    )
    primary = max(matched_planes, key=lambda p: float((compiled.get(p) or {}).get('sensitivity') or 0))
    role = (compiled.get(primary) or {}).get('campaign_role') or 'coverage_probe'

    return {
        'path': path,
        'planes': matched_planes,
        'primary_plane': primary,
        'plane_scores': plane_scores,
        'sensitivity_score': round(max_sens, 3),
        'recommended_campaign_role': role,
        'side_effect': 'read_only',
        'source': 'path_classification',
    }


def build_api_plane_index(pack_dir: Path) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    cards_path = pack_dir / 'api_cards.json'
    if cards_path.exists():
        cards_doc = json.loads(cards_path.read_text(encoding='utf-8'))
    else:
        cards_doc = {}
    if isinstance(cards_doc, list):
        cards = cards_doc
    else:
        cards = cards_doc.get('cards') or cards_doc.get('operation_cards') or []

    ontology = load_sensitive_field_ontology()
    compiled = _compile_plane_patterns(ontology)
    entries: List[Dict[str, Any]] = []
    by_plane: Dict[str, List[str]] = {p: [] for p in PLANE_ORDER}

    for card in cards:
        if card.get('card_kind') == 'non_operation':
            continue
        row = classify_api_card(card, ontology=ontology, compiled=compiled)
        if not row.get('path'):
            continue
        entries.append(row)
        for p in row.get('planes') or []:
            by_plane.setdefault(p, []).append(normalize_api_path(row['path']))

    plane_summary: Dict[str, Dict[str, Any]] = {}
    for plane_id in PLANE_ORDER:
        spec = (ontology.get('planes') or {}).get(plane_id) or {}
        paths = by_plane.get(plane_id) or []
        plane_summary[plane_id] = {
            'label': spec.get('label', plane_id),
            'sensitivity': spec.get('sensitivity'),
            'baseline_category': spec.get('baseline_category'),
            'detected_count': len(paths),
            'sample_paths': paths[:8],
        }

    return {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'source': 'api_plane_classifier',
        'api_count': len(entries),
        'plane_summary': plane_summary,
        'entries': entries,
        'path_index': {
            normalize_api_path(e['path']): e for e in entries if e.get('path')
        },
    }


def write_api_plane_index(pack_dir: Path) -> Path:
    pack_dir = Path(pack_dir)
    doc = build_api_plane_index(pack_dir)
    out = pack_dir / 'api_plane_index.json'
    write_json(out, doc)
    return out


def plane_index_by_path(pack_dir: Path) -> Dict[str, Dict[str, Any]]:
    path = Path(pack_dir) / 'api_plane_index.json'
    if not path.exists():
        write_api_plane_index(pack_dir)
    doc = json.loads(path.read_text(encoding='utf-8'))
    idx = doc.get('path_index') or {}
    if idx:
        return idx
    return {normalize_api_path(e.get('path') or ''): e for e in doc.get('entries') or []}


def build_plane_capture_gaps(pack_dir: Path) -> List[Dict[str, Any]]:
    """Minimal sensitive-plane baseline gaps (one representative capture per plane)."""
    pack_dir = Path(pack_dir)
    ontology = load_sensitive_field_ontology()
    from minidrifter.classification.sensitive_field_normalizer import (
        missing_canonical_for_plane,
        plane_baseline_satisfied,
    )
    from minidrifter.materials.object_pool_writer import load_baseline_field_pool

    plane_doc = build_api_plane_index(pack_dir) if not (pack_dir / 'api_plane_index.json').exists() else json.loads(
        (pack_dir / 'api_plane_index.json').read_text(encoding='utf-8')
    )
    pool = load_baseline_field_pool(pack_dir)
    pool_keys: Set[str] = set(pool.get('field_names') or [])
    pool_values: Dict[str, Any] = pool.get('fields') or {}

    gaps: List[Dict[str, Any]] = []
    for plane_id in PLANE_ORDER:
        spec = (ontology.get('planes') or {}).get(plane_id) or {}
        cat = spec.get('baseline_category')
        if not cat or plane_id == 'environment_public':
            continue
        summary = (plane_doc.get('plane_summary') or {}).get(plane_id) or {}
        detected = int(summary.get('detected_count') or 0)
        if detected <= 0:
            continue
        if plane_baseline_satisfied(plane_id, pool_keys, pool_values, ontology=ontology):
            continue
        missing = missing_canonical_for_plane(
            plane_id, pool_keys, pool_values, ontology=ontology,
        )
        if not missing and plane_id == 'credential_session' and not pool_keys:
            missing = ['token', 'open_id']
        if not missing:
            continue
        sample = (summary.get('sample_paths') or [''])[0]
        gaps.append({
            'plane': plane_id,
            'baseline_category': cat,
            'priority': 'P0' if float(spec.get('sensitivity') or 0) >= 0.88 else 'P1',
            'title': f"{spec.get('label', plane_id)} baseline",
            'detected_apis': detected,
            'missing_harvest_fields': missing[:6],
            'missing_canonical_fields': missing[:6],
            'example_path': sample,
            'why': (
                f"平面 **{spec.get('label', plane_id)}** 有 {detected} 个 API；"
                f"对象池尚未归一命中 `{', '.join(missing[:4])}`。"
            ),
            'save_as': f"baseline/user_materials/need_{plane_id}.http",
        })
    return gaps


def _enrich_sensitive_rows_from_intake(
    pack_dir: Path,
    executed_paths: Set[str],
    executed_rows: Dict[str, Dict[str, Any]],
    path_index: Dict[str, Dict[str, Any]],
) -> None:
    """Count baseline captures with decrypted sensitive fields as M0 sensitive read."""
    from minidrifter.verification.sensitive_read_metrics import attach_sensitive_read_metrics

    intake_path = Path(pack_dir) / 'baseline_intake_report.json'
    if not intake_path.exists():
        return
    try:
        doc = json.loads(intake_path.read_text(encoding='utf-8'))
    except Exception:
        return
    for cap in doc.get('captures') or []:
        if not str(cap.get('overall_status') or '').startswith('acceptable'):
            continue
        path = normalize_api_path(cap.get('path') or '')
        if not path:
            continue
        entry = path_index.get(path) or classify_path_to_plane_entry(path)
        role = entry.get('recommended_campaign_role') or ''
        if role not in {
            'read_sensitive_state', 'verification_state_probe', 'account_state_probe',
            'address_invoice_probe',
        } and entry.get('primary_plane') not in {
            'user_profile_personal_info', 'realname_verification', 'account_state_wallet',
            'contact_address_invoice',
        }:
            continue
        proc = cap.get('response_crypto_processing') or {}
        body = proc.get('body_json')
        if not body or not isinstance(body, dict):
            continue
        existing = executed_rows.get(path) or {}
        if existing.get('baseline_sensitive_read_m0_success') or existing.get('live_sensitive_read_m0_success'):
            continue
        row = attach_sensitive_read_metrics(
            {
                'path': path,
                'm0_outcome': 'business_success',
                'status': 'baseline_capture',
                'source': 'baseline_intake',
                'evidence_source': 'baseline_intake',
            },
            path=path,
            m0_analysis={'call_outcome': 'business_success'},
            m0_execution={'body_json': body, 'status_code': 200},
        )
        if row.get('sensitive_read_m0_success'):
            executed_paths.add(path)
            executed_rows[path] = {**existing, **row}


def build_plane_coverage_stats(
    pack_dir: Path,
    *,
    batch_doc: Optional[Dict[str, Any]] = None,
    risk_probe_doc: Optional[Dict[str, Any]] = None,
    sensitive_read_doc: Optional[Dict[str, Any]] = None,
    subject_override_doc: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Aggregate detected / materialized / executed counts per API plane."""
    from minidrifter.verification.sensitive_read_metrics import aggregate_plane_sensitive_counts

    pack_dir = Path(pack_dir)
    plane_path = pack_dir / 'api_plane_index.json'
    if not plane_path.exists():
        write_api_plane_index(pack_dir)
    plane_doc = json.loads(plane_path.read_text(encoding='utf-8'))
    entries = plane_doc.get('entries') or []
    if batch_doc is None:
        bp = pack_dir / 'chain_batch_report.json'
        batch_doc = json.loads(bp.read_text(encoding='utf-8')) if bp.exists() else {}
    if risk_probe_doc is None:
        rp = pack_dir / 'risk_probe_report.json'
        risk_probe_doc = json.loads(rp.read_text(encoding='utf-8')) if rp.exists() else {}
    if sensitive_read_doc is None:
        sr = pack_dir / 'sensitive_read_report.json'
        sensitive_read_doc = json.loads(sr.read_text(encoding='utf-8')) if sr.exists() else {}
    if subject_override_doc is None:
        so = pack_dir / 'subject_override_report.json'
        if so.exists():
            subject_override_doc = json.loads(so.read_text(encoding='utf-8'))
        else:
            subject_override_doc = {
                'results': sensitive_read_doc.get('subject_override_results') or [],
            }

    executed_paths: Set[str] = set()
    executed_rows: Dict[str, Dict[str, Any]] = {}
    path_index = plane_doc.get('path_index') or {
        normalize_api_path(e.get('path') or ''): e for e in entries if e.get('path')
    }
    for row in batch_doc.get('chain_results') or []:
        for key in ('target_path', 'entry_path', 'consumer_path', 'producer_path'):
            if row.get(key):
                p = normalize_api_path(row[key])
                executed_paths.add(p)
                enriched = dict(row)
                if not enriched.get('sensitive_read_m7_success') and enriched.get('reached_m7'):
                    entry = path_index.get(p) or {}
                    role = entry.get('recommended_campaign_role') or ''
                    if role in {
                        'read_sensitive_state', 'verification_state_probe', 'account_state_probe',
                    } or entry.get('primary_plane') in {
                        'user_profile_personal_info', 'realname_verification', 'account_state_wallet',
                    }:
                        enriched['sensitive_read_m7_success'] = True
                        enriched['sensitive_read_success'] = True
                        if enriched.get('m7_outcome') or enriched.get('findings', 0) is not None:
                            enriched['sensitive_mutation_tested'] = True
                executed_rows[p] = enriched
    for row in risk_probe_doc.get('probe_results') or risk_probe_doc.get('results') or []:
        if row.get('path'):
            p = normalize_api_path(row['path'])
            executed_paths.add(p)
            executed_rows[p] = row
    for row in sensitive_read_doc.get('results') or []:
        if row.get('path'):
            p = normalize_api_path(row['path'])
            executed_paths.add(p)
            executed_rows[p] = row
    for row in subject_override_doc.get('results') or []:
        if row.get('path'):
            p = normalize_api_path(row['path'])
            executed_paths.add(p)
            existing = executed_rows.get(p) or {}
            executed_rows[p] = {**existing, **row}

    _enrich_sensitive_rows_from_intake(pack_dir, executed_paths, executed_rows, path_index)

    tpl_path = pack_dir / 'materialized_api_templates.json'
    materialized_ids: Set[str] = set()
    if tpl_path.exists():
        tpl_doc = json.loads(tpl_path.read_text(encoding='utf-8'))
        for t in tpl_doc.get('templates') or []:
            if t.get('api_id'):
                materialized_ids.add(str(t['api_id']))

    coverage: Dict[str, Dict[str, Any]] = {}
    for plane_id, summary in (plane_doc.get('plane_summary') or {}).items():
        plane_entries = [e for e in entries if plane_id in (e.get('planes') or [])]
        static_paths = {normalize_api_path(e.get('path') or '') for e in plane_entries if e.get('path')}
        intake_paths: Set[str] = set()
        for p in executed_rows:
            if p in static_paths:
                continue
            entry = classify_path_to_plane_entry(p)
            if plane_id in (entry.get('planes') or []):
                intake_paths.add(p)
        plane_paths = static_paths | intake_paths
        mat = sum(1 for e in plane_entries if e.get('api_id') in materialized_ids)
        mat += sum(
            1 for p in intake_paths
            if p in executed_paths and p not in static_paths
        )
        exe = sum(1 for p in plane_paths if p in executed_paths)
        sens_counts = aggregate_plane_sensitive_counts(
            plane_entries, executed_rows, normalize_path=normalize_api_path,
            extra_paths=intake_paths,
        )
        safe_read = 0
        safety_blocked = 0
        if plane_id == 'action_operation':
            for e in plane_entries:
                p = normalize_api_path(e.get('path') or '')
                if p not in executed_paths:
                    continue
                row = executed_rows.get(p) or {}
                side = e.get('side_effect') or ''
                if side in {'S2_state_changing', 'S3_destructive', 'state_changing', 'write'}:
                    safety_blocked += 1
                elif row.get('reached_m7') or row.get('sensitive_read_m0_success'):
                    safe_read += 1
        coverage[plane_id] = {
            'label': summary.get('label', plane_id),
            'detected': int(summary.get('detected_count') or len(plane_entries)),
            'materialized': mat,
            'executed': exe,
            'executed_safe_read': safe_read if plane_id == 'action_operation' else 0,
            'safety_blocked': safety_blocked if plane_id == 'action_operation' else 0,
            **sens_counts,
        }
    return {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'plane_coverage': coverage,
    }


def plane_sensitivity_for_path(path: str, *, pack_dir: Optional[Path] = None) -> Tuple[float, List[str]]:
    norm = normalize_api_path(path or '')
    if pack_dir:
        idx = plane_index_by_path(pack_dir)
        row = idx.get(norm)
        if row:
            return float(row.get('sensitivity_score') or 0.3), list(row.get('planes') or [])
    ontology = load_sensitive_field_ontology()
    compiled = _compile_plane_patterns(ontology)
    planes: List[str] = []
    sens = 0.2
    for plane_id, spec in compiled.items():
        if spec.get('path_re') and spec['path_re'].search(norm):
            planes.append(plane_id)
            sens = max(sens, float(spec.get('sensitivity') or 0))
    return sens, planes
