# -*- coding: utf-8 -*-
"""Runtime Requirement Skeleton: field-level N1 requirements with material mapping."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Set

from minidrifter.core.runtime_taxonomy import (
    classify_field,
    classify_side_effect,
    is_deferred_obtainability,
    side_effect_short,
    stage1_user_obtainability,
)
from minidrifter.materials.material_units import material_candidates_for_field

# Re-export taxonomy constants for backward compatibility
O0_STATIC = 'O0_static_derived'
O1_LOGIN = 'O1_login_bootstrap'
O2_HOST = 'O2_host_local'
O3_FIRST_HOP = 'O3_first_hop_object'
O4_WORKFLOW = 'O4_workflow_object'
O5_CAPABILITY = 'O5_sensitive_capability'

N1_A = 'N1-A'
N1_H = 'N1-H'
N1_B = 'N1-B'
N1_C = 'N1-C'
N1_X = 'N1-X'

LIST_PATH_RE = re.compile(r'/(list|list/|/list\?|recent|byuserid)', re.I)
DEVICE_PATH_RE = re.compile(r'/device', re.I)
ORDER_LIST_PATH_RE = re.compile(r'/orders?/list', re.I)
OPENID_PATH_RE = re.compile(r'openid|miniprogram/openid', re.I)
CRYPTO_HEADER_RE = re.compile(
    r'(authorization|appidentity|timespan|timestamp|sign|nonce|encrypted)',
    re.I,
)


def _binding_params(card: Dict[str, Any]) -> List[Dict[str, Any]]:
    return (card.get('bindings') or {}).get('params') or []


def _evidence_refs_for_param(card: Dict[str, Any], param_name: str) -> List[str]:
    refs: List[str] = []
    for cs in (card.get('evidence') or {}).get('callsites') or []:
        eid = cs.get('evidence_id')
        f = cs.get('file')
        line = cs.get('line')
        if eid:
            refs.append(eid)
        if f and line is not None:
            refs.append(f'callsite:{f}:{line}')
    return list(dict.fromkeys(refs))[:5]


def _location_from_where(where: str) -> str:
    w = (where or 'body').lower()
    if w in {'header', 'query', 'body', 'path'}:
        return w
    if w == 'url':
        return 'query'
    return 'body'


def enrich_field_requirement(
    card: Dict[str, Any],
    name: str,
    *,
    where: str = 'body',
    source: str = 'param_schema',
    source_hint: str = '',
    static_binding_role: str = '',
) -> Dict[str, Any]:
    path = ((card.get('static') or {}).get('endpoint') or {}).get('path') or ''
    clf = classify_field(name, path=path, where=where, source_hint=source_hint)
    role = clf['field_role']
    obtainability = clf['obtainability']
    candidates = material_candidates_for_field(name, role, obtainability)

    ranking = card.get('ranking') or {}
    tier = ranking.get('priority_tier') or ''
    val = ranking.get('validation_value') or 'none'

    return {
        'name': name,
        'location': _location_from_where(where),
        'role': role,
        'obtainability': obtainability,
        'source_hint': source_hint or source,
        'required_for_replay': True,
        'required_for_mutation': role in {'object_id', 'subject_id'} and val in {'medium', 'high'},
        'material_candidates': candidates,
        'confidence': clf['confidence'],
        'rule_evidence': clf['rule_evidence'],
        'evidence_refs': _evidence_refs_for_param(card, name),
        'static_binding_role': static_binding_role or None,
    }


def infer_required_fields(card: Dict[str, Any]) -> List[Dict[str, Any]]:
    path = ((card.get('static') or {}).get('endpoint') or {}).get('path') or ''
    fields: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    for p in _binding_params(card):
        name = p.get('name')
        if not name or name in seen:
            continue
        seen.add(name)
        fields.append(enrich_field_requirement(
            card, name,
            where=p.get('where') or 'body',
            source=p.get('source') or 'param_schema',
            source_hint=p.get('binding_expr') or p.get('source') or '',
            static_binding_role=p.get('static_role') or '',
        ))

    replay = card.get('replay') or {}
    auth = replay.get('auth_dependency') or {}
    for h in auth.get('auth_fields') or []:
        if h in seen:
            continue
        seen.add(h)
        fields.append(enrich_field_requirement(
            card, h,
            where='header',
            source='authenticated_request_header',
            static_binding_role='crypto_material' if CRYPTO_HEADER_RE.search(h) else 'auth_credential_candidate',
        ))

    if OPENID_PATH_RE.search(path):
        for name in ['code', 'OpenId', 'appId', 'channelId']:
            if name in seen:
                continue
            seen.add(name)
            fields.append(enrich_field_requirement(
                card, name, where='body', source='openid_flow_inferred',
            ))

    if not fields and auth.get('requires_auth'):
        for name in ['Token', 'UserId']:
            if name not in seen:
                seen.add(name)
                fields.append(enrich_field_requirement(
                    card, name,
                    where='header' if name == 'Token' else 'body',
                    source='project_wrapper_default',
                ))

    return fields


def infer_produces_fields(card: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Lightweight produces on skeleton; full graph uses produces_infer."""
    from minidrifter.graph.produces_infer import infer_produces_from_path, infer_produces_from_snippets, merge_produces_edges

    edges = merge_produces_edges([
        infer_produces_from_path(card),
        infer_produces_from_snippets(card),
    ])
    out = []
    for e in edges:
        fname = e.get('to_field') or e.get('to')
        out.append({
            'name': fname,
            'role': e.get('field_role') or classify_field(fname or '', path=_card_path(card))['field_role'],
            'obtainability': e.get('obtainability') or O3_FIRST_HOP,
            'confidence': e.get('confidence', 0.55),
            'evidence_type': e.get('evidence_type'),
            'evidence_refs': e.get('evidence_refs') or [],
            'source': 'produces_infer',
        })
    return out


def _card_path(card: Dict[str, Any]) -> str:
    return ((card.get('static') or {}).get('endpoint') or {}).get('path') or ''


def classify_side_effect_level(card: Dict[str, Any]) -> str:
    level = classify_side_effect(card)
    return level


def classify_n1_sublevel(card: Dict[str, Any], required_fields: List[Dict[str, Any]]) -> str:
    kind = (card.get('provenance') or {}).get('card_kind')
    http = (card.get('static') or {}).get('http') or {}
    if kind == 'registered_only':
        return N1_X
    if http.get('method') in (None, 'UNKNOWN') or http.get('method_trust_tier') in {'unknown', 'low'}:
        return N1_X
    if not (card.get('evidence') or {}).get('callsites'):
        return N1_X

    obs = {f.get('obtainability') for f in required_fields}
    roles = {f.get('role') for f in required_fields}
    path = _card_path(card)

    if OPENID_PATH_RE.search(path) or obs & {O2_HOST}:
        if obs & {O4_WORKFLOW, O5_CAPABILITY}:
            return N1_B
        return N1_H
    if obs & {O5_CAPABILITY} or obs & {O4_WORKFLOW} and not LIST_PATH_RE.search(path):
        return N1_B
    if obs == {O1_LOGIN} or (obs <= {O0_STATIC, O1_LOGIN} and not obs & {O4_WORKFLOW, O5_CAPABILITY}):
        return N1_A
    if obs & {O3_FIRST_HOP} and LIST_PATH_RE.search(path):
        return N1_A
    if roles & {'environment_context'}:
        return N1_C
    return N1_A


def stage1_user_obtainability_filter(obtainability: str) -> bool:
    return stage1_user_obtainability(obtainability)


def build_runtime_requirement_skeleton(card: Dict[str, Any], runtime_level: str) -> Dict[str, Any]:
    required_fields = infer_required_fields(card)
    produces_fields = infer_produces_fields(card)
    side_level = classify_side_effect_level(card)
    sublevel = classify_n1_sublevel(card, required_fields)

    stage1_fields = [f for f in required_fields if stage1_user_obtainability_filter(f['obtainability'])]
    deferred_fields = [f for f in required_fields if is_deferred_obtainability(f['obtainability'])]
    auto_discovery_fields = [f for f in required_fields if f['obtainability'] == O3_FIRST_HOP]

    path = _card_path(card)
    method = ((card.get('static') or {}).get('http') or {}).get('method') or 'UNKNOWN'

    material_hints: List[str] = []
    for f in required_fields:
        material_hints.extend(f.get('material_candidates') or [])
    material_hints = list(dict.fromkeys(material_hints))

    return {
        'api_id': card.get('card_id'),
        'endpoint': path,
        'path': path,
        'method': method,
        'runtime_level': runtime_level,
        'runtime_sublevel': sublevel,
        'side_effect_level': side_level,
        'side_effect_short': side_effect_short(side_level),
        'required_fields': required_fields,
        'produces_fields': produces_fields,
        'stage1_user_fields': [f['name'] for f in stage1_fields],
        'auto_discovery_fields': [f['name'] for f in auto_discovery_fields],
        'deferred_fields': [f['name'] for f in deferred_fields],
        'template_status': 'unmaterialized',
        'user_material_hints': material_hints,
    }


# Backward-compat aliases used by acquisition_planner
def classify_field_obtainability(name: str, path: str = '') -> str:
    return classify_field(name, path=path)['obtainability']


def classify_runtime_field_role(name: str) -> str:
    return classify_field(name)['field_role']
