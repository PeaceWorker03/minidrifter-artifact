# -*- coding: utf-8 -*-
"""Generic PII / credential surface classification for risk scoring and ERD intent."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

PII_PATH_TOKEN_RE = re.compile(
    r'(id_?card|idcard|identity|real_?name|credential|certify|'
    r'driver|driving_?license|vehicle_?license|license|passport|'
    r'bank_?card|bankcard|id_?no|peccancy|deposit|pledge|auth_?status)',
    re.I,
)

PII_READ_PATH_RE = re.compile(
    r'(get|info|detail|list|query|qua|qualification|status|remain|core|profile|'
    r'personal|member|account|user)',
    re.I,
)

PII_WRITE_PATH_RE = re.compile(
    r'(upload|submit|save|bind|register|apply|insert|update|modify|delete|del/|'
    r'certify|auth(?!status))',
    re.I,
)

PII_PARAM_RE = re.compile(
    r'^(id_?card|id_?card_?no|id_?no|identity|real_?name|name$|license_?no|'
    r'driver_?license|driving_?license|passport|bank_?card|cert_?no|'
    r'card_?no|mobile|phone$|id_number)$',
    re.I,
)

WRITE_SIDE_EFFECTS = frozenset({'state_changing', 'write', 'S2_state_changing'})
READ_SIDE_EFFECTS = frozenset({'read_only', 'query_like', 'S0_read_only', 'S1_query_like_post'})

INTENT_BINDING = 'subject_object_binding_check'
INTENT_PII_SCOPE = 'sensitive_data_scope_check'
INTENT_PII_SUBMIT = 'pii_submission_flow'


def pii_path_match(path: str) -> bool:
    return bool(PII_PATH_TOKEN_RE.search(path or ''))


def pii_param_names(params: Optional[List[Dict[str, Any]]]) -> List[str]:
    out: List[str] = []
    for p in params or []:
        name = p.get('name')
        if name and PII_PARAM_RE.match(str(name)):
            out.append(str(name))
    return out


def _flow_kind_from_path(path: str, method: str) -> str:
    """Return read | write | unknown from path tokens and HTTP method."""
    p = path or ''
    meth = (method or 'GET').upper()
    if PII_WRITE_PATH_RE.search(p) and not PII_READ_PATH_RE.search(p):
        return 'write'
    if meth == 'GET':
        return 'read'
    if PII_READ_PATH_RE.search(p) and not PII_WRITE_PATH_RE.search(p):
        return 'read'
    if PII_WRITE_PATH_RE.search(p):
        return 'write'
    if meth in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        return 'write'
    return 'unknown'


def classify_sensitive_surface(
    path: str,
    *,
    method: Optional[str] = None,
    side_effect_category: Optional[str] = None,
    param_names: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Classify PII/credential API surface — project-agnostic path/param heuristics."""
    path = path or ''
    side = side_effect_category or ''
    pii_params = [n for n in (param_names or []) if PII_PARAM_RE.match(str(n))]
    path_pii = pii_path_match(path)
    pii_surface = path_pii or bool(pii_params)

    flow_kind = _flow_kind_from_path(path, method or 'GET')
    if side in WRITE_SIDE_EFFECTS:
        flow_kind = 'write'
    elif side in READ_SIDE_EFFECTS and flow_kind != 'write':
        flow_kind = 'read'

    probe_blocked = flow_kind == 'write'
    probe_style = 'none'
    if pii_surface and not probe_blocked:
        probe_style = 'pii_scope_m7'
    elif pii_surface and probe_blocked:
        probe_style = 'none'

    return {
        'pii_surface': pii_surface,
        'pii_path_match': path_pii,
        'pii_params': pii_params[:6],
        'flow_kind': flow_kind,
        'probe_blocked': probe_blocked,
        'probe_style': probe_style,
    }


def classify_sensitive_surface_from_card(card: Dict[str, Any]) -> Dict[str, Any]:
    path = ((card.get('static') or {}).get('endpoint') or {}).get('path') or ''
    method = ((card.get('static') or {}).get('http') or {}).get('method') or 'GET'
    side = ((card.get('replay') or {}).get('side_effect') or {}).get('category') or ''
    params = ((card.get('bindings') or {}).get('params') or [])
    param_names = [p.get('name') for p in params if p.get('name')]
    return classify_sensitive_surface(
        path, method=method, side_effect_category=side, param_names=param_names,
    )


N0_LEVEL = 'N0_STATIC_TEMPLATE'


def resolve_verification_intent(
    card: Dict[str, Any],
    *,
    runtime_level: str,
    validation_value: Optional[str] = None,
) -> str:
    """Pick verification_intent including PII read/write surfaces."""
    if runtime_level == N0_LEVEL:
        return 'static_template_probe'
    if validation_value in {'medium', 'high'}:
        return INTENT_BINDING

    surface = classify_sensitive_surface_from_card(card)
    if surface['pii_surface']:
        if surface['flow_kind'] == 'read':
            return INTENT_PII_SCOPE
        if surface['flow_kind'] == 'write':
            return INTENT_PII_SUBMIT
        return INTENT_PII_SCOPE
    return 'baseline_runtime_template'
