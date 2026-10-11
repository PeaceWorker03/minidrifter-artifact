# -*- coding: utf-8 -*-
"""P4-fix-5.2 — plan subject-wire capture gaps for single-account baseline expansion."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.business_chain.chain_run_context import load_json
from minidrifter.classification.api_plane_classifier import (
    classify_path_to_plane_entry,
    plane_index_by_path,
)
from minidrifter.classification.subject_wire_candidate_miner import (
    SENSITIVE_PLANES,
    LOGIN_PATH_RE,
    WRITE_PATH_RE,
    load_subject_wire_candidates,
)
from minidrifter.core.utils import write_json
from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.verification.subject_override_fields import (
    field_allowed,
    infer_subject_fields_from_path,
    norm_field as _norm_field,
)

SCHEMA_VERSION = '1.0.0'

READ_PATH_RE = re.compile(
    r'(list|detail|info|query|get|status|page|home|profile|summary|record)',
    re.I,
)

OBJECT_ANCHOR_FIELDS = frozenset({
    'orderid', 'orderno', 'addressid', 'invoiceid', 'cardid', 'vehicleid',
    'deptid', 'storeid', 'couponid', 'paymentid', 'taskid',
})

STATIC_SUBJECT_ROLES = frozenset({
    'subject_identifier_candidate',
    'subject_identifier',
    'subject_binding_candidate',
})

PLANE_CAPTURE_HINTS = {
    'user_profile_personal_info': '个人资料/会员详情类读请求',
    'realname_verification': '实名认证状态或证件信息读请求',
    'account_state_wallet': '账户余额/会员卡/钱包状态读请求',
    'contact_address_invoice': '地址列表/详情或发票抬头读请求',
    'business_object': '订单/业务对象详情读请求（含对象 ID）',
}

ENVIRONMENT_PLANES = frozenset({'environment_public', 'credential_session'})


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_cards(pack_dir: Path) -> List[Dict[str, Any]]:
    for name in ('api_cards.json', 'all_api_cards.json'):
        path = pack_dir / name
        if not path.exists():
            continue
        doc = load_json(path)
        if isinstance(doc, list):
            return doc
        return list(doc.get('cards') or doc.get('operation_cards') or [])
    return []


def _card_path(card: Dict[str, Any]) -> str:
    ep = (card.get('static') or {}).get('endpoint') or {}
    return ep.get('path') or ''


def _static_fields_from_card(card: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    subject: List[str] = []
    objects: List[str] = []
    bindings = card.get('bindings') or {}
    for p in bindings.get('params') or []:
        name = str(p.get('name') or '')
        if not name:
            continue
        nf = _norm_field(name)
        role = str(p.get('static_role') or '')
        allowed, _ = field_allowed(name)
        if allowed or nf in OBJECT_ANCHOR_FIELDS:
            if (
                'subject' in role
                or allowed
                or role == 'object_identifier_candidate'
            ):
                if allowed:
                    subject.append(name)
                elif nf in OBJECT_ANCHOR_FIELDS:
                    objects.append(name)
        elif nf in OBJECT_ANCHOR_FIELDS:
            objects.append(name)
    return sorted(set(subject)), sorted(set(objects))


def _static_fields_from_templates(pack_dir: Path) -> Dict[str, Tuple[List[str], List[str]]]:
    doc = load_json(pack_dir / 'materialized_api_templates.json') or {}
    out: Dict[str, Tuple[List[str], List[str]]] = {}
    for tpl in doc.get('templates') or []:
        path = normalize_api_path(tpl.get('path') or '')
        if not path:
            continue
        plain = tpl.get('plain_template') or {}
        subject: List[str] = []
        objects: List[str] = []
        for bag in (plain.get('body_params') or {}, plain.get('params') or {}):
            if not isinstance(bag, dict):
                continue
            for k, v in bag.items():
                if v is not None and str(v).startswith('$'):
                    continue
                nf = _norm_field(k)
                allowed, _ = field_allowed(k)
                if allowed:
                    subject.append(str(k))
                elif nf in OBJECT_ANCHOR_FIELDS:
                    objects.append(str(k))
        if subject or objects:
            out[path] = (sorted(set(subject)), sorted(set(objects)))
    return out


def _static_fields_from_object_flow(pack_dir: Path) -> Dict[str, Tuple[List[str], List[str]]]:
    doc = load_json(pack_dir / 'object_flow_chains.json') or {}
    out: Dict[str, Tuple[Set[str], Set[str]]] = {}
    for edge in doc.get('edges') or doc.get('chains') or []:
        if isinstance(edge, dict) and edge.get('edge_type') == 'object_flow':
            consumer = normalize_api_path(edge.get('consumer_api') or '')
            field = str(edge.get('object_field') or '')
            if not consumer or not field:
                continue
            subj, obj = out.setdefault(consumer, (set(), set()))
            nf = _norm_field(field)
            allowed, _ = field_allowed(field)
            if allowed:
                subj.add(field)
            elif nf in OBJECT_ANCHOR_FIELDS:
                obj.add(field)
            loc = str(edge.get('consumer_location') or '')
            if loc.startswith('params.') and allowed:
                subj.add(field)
    return {
        p: (sorted(a), sorted(b))
        for p, (a, b) in out.items()
    }


def _static_fields_from_business_chains(pack_dir: Path) -> Dict[str, Tuple[List[str], List[str]]]:
    doc = load_json(pack_dir / 'business_chains.json') or {}
    out: Dict[str, Tuple[Set[str], Set[str]]] = {}
    for chain in doc.get('chains') or []:
        for hop in chain.get('hops') or []:
            path = normalize_api_path(hop.get('path') or '')
            if not path:
                continue
            subj, obj = out.setdefault(path, (set(), set()))
            for field in hop.get('consumes') or []:
                nf = _norm_field(str(field))
                allowed, _ = field_allowed(str(field))
                if allowed:
                    subj.add(str(field))
                elif nf in OBJECT_ANCHOR_FIELDS:
                    obj.add(str(field))
    return {p: (sorted(a), sorted(b)) for p, (a, b) in out.items()}


def _merge_field_maps(*maps: Dict[str, Tuple[List[str], List[str]]]) -> Dict[str, Tuple[List[str], List[str]]]:
    merged: Dict[str, Tuple[Set[str], Set[str]]] = {}
    for m in maps:
        for path, (subj, obj) in m.items():
            s, o = merged.setdefault(path, (set(), set()))
            s.update(subj)
            o.update(obj)
    return {p: (sorted(a), sorted(b)) for p, (a, b) in merged.items()}


def _baseline_capture_paths(pack_dir: Path) -> Set[str]:
    intake = load_json(pack_dir / 'baseline_intake_report.json') or {}
    paths: Set[str] = set()
    for cap in intake.get('captures') or []:
        if str(cap.get('overall_status') or '').startswith('acceptable'):
            p = normalize_api_path(cap.get('path') or '')
            if p:
                paths.add(p)
    return paths


def _wire_subject_covered_paths(pack_dir: Path) -> Set[str]:
    doc = load_subject_wire_candidates(pack_dir)
    covered: Set[str] = set()
    for cand in doc.get('candidates') or []:
        p = normalize_api_path(cand.get('path') or cand.get('api') or '')
        if not p:
            continue
        if any(f.get('mutation_allowed') for f in cand.get('wire_subject_fields') or []):
            covered.add(p)
    return covered


def _credential_bound_paths(pack_dir: Path) -> Set[str]:
    doc = load_subject_wire_candidates(pack_dir)
    sens = load_json(pack_dir / 'sensitive_read_report.json') or {}
    mined_paths = {
        normalize_api_path(c.get('path') or c.get('api') or '')
        for c in doc.get('candidates') or []
    }
    out: Set[str] = set()
    for row in sens.get('results') or []:
        if not row.get('live_sensitive_read_m0_success'):
            continue
        p = normalize_api_path(row.get('path') or '')
        if p and p not in mined_paths:
            out.add(p)
    return out


def _is_read_api(path: str, entry: Dict[str, Any], card: Optional[Dict[str, Any]]) -> bool:
    side = entry.get('side_effect') or ''
    if side in {'S2_state_changing', 'S3_destructive', 'state_changing', 'write'}:
        if not READ_PATH_RE.search(path):
            return False
    if WRITE_PATH_RE.search(path) and not READ_PATH_RE.search(path):
        return False
    method = (entry.get('method') or '').upper()
    if card:
        method = ((card.get('static') or {}).get('http') or {}).get('method') or method
    if method in {'GET', 'HEAD'}:
        return True
    return bool(READ_PATH_RE.search(path))


def _priority_score(
    *,
    entry: Dict[str, Any],
    path: str,
    subject_fields: List[str],
    object_fields: List[str],
    materialized: bool,
    object_flow_backed: bool,
    card_backed: bool,
) -> float:
    score = float(entry.get('sensitivity_score') or 0.3)
    planes = set(entry.get('planes') or [])
    if entry.get('primary_plane') in SENSITIVE_PLANES:
        score += 0.2
    if planes & SENSITIVE_PLANES:
        score += 0.1
    if subject_fields:
        score += min(0.35, 0.12 * len(subject_fields))
        if any(_norm_field(f) in {'memberid', 'customerid', 'userid'} for f in subject_fields):
            score += 0.15
    if object_fields:
        score += min(0.1, 0.05 * len(object_fields))
    if _is_read_api(path, entry, None):
        score += 0.15
    if materialized:
        score += 0.08
    if object_flow_backed:
        score += 0.12
    if card_backed:
        score += 0.08
    if LOGIN_PATH_RE.search(path):
        score -= 0.35
    if WRITE_PATH_RE.search(path) and not READ_PATH_RE.search(path):
        score -= 0.25
    if 'environment_public' in planes:
        score -= 0.4
    return round(max(0.0, min(1.0, score)), 3)


def _recommended_capture(plane: str, subject_fields: List[str], object_fields: List[str]) -> str:
    base = PLANE_CAPTURE_HINTS.get(plane or '', '敏感读请求（含 subject/object 参数）')
    if subject_fields:
        fields = '/'.join(subject_fields[:2])
        return f'{base}（请求含 `{fields}`）'
    if object_fields:
        return f'{base}（请求含对象 ID `{object_fields[0]}`）'
    return base


def _category_key(plane: str, subject_fields: List[str]) -> str:
    primary = subject_fields[0] if subject_fields else 'object_anchor'
    return f'{plane or "unknown"}::{_norm_field(primary)}'


def build_subject_wire_gap_plan(
    pack_dir: Path,
    *,
    write: bool = True,
    max_gaps: int = 24,
) -> Dict[str, Any]:
    """Find sensitive APIs with static subject-like request fields but no baseline wire."""
    pack_dir = Path(pack_dir)
    plane_idx = plane_index_by_path(pack_dir)
    cards = _load_cards(pack_dir)
    cards_by_path = {normalize_api_path(_card_path(c)): c for c in cards if _card_path(c)}

    tpl_fields = _static_fields_from_templates(pack_dir)
    flow_fields = _static_fields_from_object_flow(pack_dir)
    chain_fields = _static_fields_from_business_chains(pack_dir)
    card_fields: Dict[str, Tuple[List[str], List[str]]] = {}
    for path, card in cards_by_path.items():
        card_fields[path] = _static_fields_from_card(card)

    static_map = _merge_field_maps(card_fields, tpl_fields, flow_fields, chain_fields)
    path_inferred: Dict[str, Tuple[List[str], List[str]]] = {}
    for path in plane_idx:
        inferred = infer_subject_fields_from_path(path)
        if inferred:
            path_inferred[path] = (inferred, [])
    static_map = _merge_field_maps(static_map, path_inferred)
    baseline_paths = _baseline_capture_paths(pack_dir)
    wire_covered = _wire_subject_covered_paths(pack_dir)
    credential_bound = _credential_bound_paths(pack_dir)

    mat_paths = {
        normalize_api_path(t.get('path') or '')
        for t in (load_json(pack_dir / 'materialized_api_templates.json') or {}).get('templates') or []
        if t.get('path')
    }

    gaps: List[Dict[str, Any]] = []
    static_subject_like = 0
    covered_by_baseline = 0

    candidate_paths = set(static_map) | set(plane_idx)
    for path in candidate_paths:
        entry = plane_idx.get(path) or classify_path_to_plane_entry(path)
        planes = set(entry.get('planes') or [])
        primary = entry.get('primary_plane') or ''
        if primary not in SENSITIVE_PLANES and not (planes & SENSITIVE_PLANES):
            continue

        subject_fields, object_fields = static_map.get(path, ([], []))
        if not subject_fields:
            continue
        static_subject_like += 1

        current_wire_covered = path in wire_covered
        current_capture = path in baseline_paths
        if current_wire_covered:
            covered_by_baseline += 1
            continue
        if path in credential_bound:
            continue

        card = cards_by_path.get(path)
        if not _is_read_api(path, entry, card):
            continue

        materialized = path in mat_paths
        priority = _priority_score(
            entry=entry,
            path=path,
            subject_fields=subject_fields,
            object_fields=object_fields,
            materialized=materialized,
            object_flow_backed=path in flow_fields,
            card_backed=path in card_fields and bool(card_fields[path][0]),
        )
        if priority < 0.25:
            continue

        why = [
            'sensitive_plane',
            'static_request_schema_contains_subject_like_field',
            'current_baseline_has_no_wire_subject_candidate',
        ]
        if path in flow_fields:
            why.append('object_flow_consumer_hint')
        if card and card_fields.get(path, ([], []))[0]:
            why.append('api_card_binding_hint')
        if materialized:
            why.append('materialized_template')
        if current_capture:
            why.append('capture_exists_but_no_wire_subject')

        gaps.append({
            'gap_type': 'subject_wire_capture_gap',
            'api': entry.get('path') or path,
            'path': path,
            'api_id': entry.get('api_id') or (card or {}).get('card_id'),
            'plane': primary,
            'campaign_role': entry.get('recommended_campaign_role'),
            'static_subject_fields': subject_fields,
            'static_object_fields': object_fields,
            'current_capture_covered': current_capture,
            'wire_subject_covered': current_wire_covered,
            'recommended_capture': _recommended_capture(primary, subject_fields, object_fields),
            'why_useful': why,
            'priority': priority,
            'category_key': _category_key(primary, subject_fields),
        })

    gaps.sort(key=lambda g: -float(g.get('priority') or 0))
    gaps = gaps[:max_gaps]

    categories: Dict[str, Dict[str, Any]] = {}
    for gap in gaps:
        key = gap.get('category_key') or gap.get('plane') or 'unknown'
        if key not in categories:
            categories[key] = {
                'category_key': key,
                'plane': gap.get('plane'),
                'representative_api': gap.get('path'),
                'static_subject_fields': gap.get('static_subject_fields'),
                'recommended_capture': gap.get('recommended_capture'),
                'api_count': 0,
                'top_priority': gap.get('priority'),
            }
        categories[key]['api_count'] += 1
        categories[key]['top_priority'] = max(
            float(categories[key].get('top_priority') or 0),
            float(gap.get('priority') or 0),
        )

    doc = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'summary': {
            'static_subject_like_sensitive_apis': static_subject_like,
            'covered_by_baseline_wire_subject': covered_by_baseline,
            'credential_bound_sensitive_reads': len(credential_bound),
            'uncovered_high_priority': len(gaps),
            'recommended_capture_categories': len(categories),
            'baseline_capture_paths': len(baseline_paths),
        },
        'recommended_capture_categories': sorted(
            categories.values(),
            key=lambda c: -float(c.get('top_priority') or 0),
        ),
        'gaps': gaps,
    }
    if write:
        write_json(pack_dir / 'subject_wire_gap_plan.json', doc)
    return doc


def load_subject_wire_gap_plan(pack_dir: Path) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    path = pack_dir / 'subject_wire_gap_plan.json'
    if path.exists():
        return load_json(path) or {}
    return build_subject_wire_gap_plan(pack_dir, write=True)
