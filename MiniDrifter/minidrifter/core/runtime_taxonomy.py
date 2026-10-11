# -*- coding: utf-8 -*-
"""Unified field roles, obtainability O0-O5, and side-effect S0-S4 taxonomy."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

FIELD_ROLES = [
    'auth_token',
    'subject_id',
    'host_identity',
    'object_id',
    'capability_token',
    'environment_context',
    'pagination_filter',
    'crypto_derived',
    'static_constant',
    'local_device_context',
    'ordinary_field',
    'unknown',
]

OBTAINABILITY_LEVELS = [
    'O0_static_derived',
    'O1_login_bootstrap',
    'O2_host_local',
    'O3_first_hop_object',
    'O4_workflow_object',
    'O5_sensitive_capability',
    'OX_unknown',
]

SIDE_EFFECT_LEVELS = [
    'S0_read_only',
    'S1_query_like_post',
    'S2_light_state_change',
    'S3_state_changing',
    'S4_high_risk_business_action',
]

# Legacy short codes used by acquisition planner gates
SIDE_EFFECT_SHORT = {
    'S0_read_only': 'S0',
    'S1_query_like_post': 'S1',
    'S2_light_state_change': 'S2',
    'S3_state_changing': 'S3',
    'S4_high_risk_business_action': 'S4',
}

FIELD_ROLE_RULES: Dict[str, List[str]] = {
    'auth_token': ['token', 'jwt', 'session', 'authorization', 'bearer'],
    'subject_id': ['userid', 'user_id', 'customerid', 'memberid', 'phone', 'phoneno', 'mobile'],
    'host_identity': ['openid', 'unionid', 'code', 'wxcode', 'logincode', 'jscode'],
    'object_id': [
        'orderid', 'invoiceid', 'deviceid', 'addressid', 'couponid', 'ticketuserid',
        'orderno', 'emailid', 'contactid', 'renterid', 'cardid', 'storeid', 'invoicetitleid',
    ],
    'capability_token': [
        'payno', 'paycode', 'qrcode', 'freezeno', 'ticketcode', 'verifycode',
        'prepayid', 'paysign', 'barcode', 'writeoff', 'couponcode', 'invoiceurl',
    ],
    'environment_context': [
        'cityid', 'storeid', 'startdate', 'enddate', 'location', 'latitude', 'longitude',
        'pickup', 'return', 'channelid', 'tenantid', 'companyid',
    ],
    'pagination_filter': ['pageindex', 'pagesize', 'page', 'limit', 'status', 'type', 'sort'],
    'crypto_derived': ['appidentity', 'timespan', 'timestamp', 'sign', 'nonce', 'encrypted'],
    'static_constant': ['appid', 'channelid', 'appversion', 'appplatform', 'platform', 'host'],
    'local_device_context': ['tokencode', 'devicename', 'osversion', 'systeminfo'],
}

WORKFLOW_FIELD_RE = re.compile(
    r'(orderid|orderno|invoiceorderid|rescueid|contractid|payno|freezeno|prepayid|paysign)',
    re.I,
)
CAPABILITY_FIELD_RE = re.compile(
    r'(payno|freezeno|qrcode|barcode|verifycode|writeoff|couponcode|ticketcode|prepayid|paysign|invoiceurl)',
    re.I,
)
FIRST_HOP_OBJECT_RE = re.compile(
    r'(deviceid|addressid|invoicetitleid|emailid|renterid|contactid|cardid)',
    re.I,
)

DEFERRED_PATH_RE = re.compile(
    r'(subscribe|/pay|payment|freeze|refund|cancel|delete|bind|unbind|submit|charge|wallet|preauth)',
    re.I,
)


def _normalize_field_name(name: str) -> str:
    return re.sub(r'[^a-z0-9]', '', (name or '').lower())


def _match_role_rules(name: str) -> List[Tuple[str, str]]:
    norm = _normalize_field_name(name)
    low = (name or '').lower()
    if 'tokencode' in low:
        return [('local_device_context', 'FIELD_ROLE_RULES.local_device_context:tokencode')]
    hits: List[Tuple[str, str]] = []
    for role, tokens in FIELD_ROLE_RULES.items():
        for tok in tokens:
            if tok in norm or norm == tok:
                hits.append((role, f'FIELD_ROLE_RULES.{role}:{tok}'))
                break
    return hits


def classify_field(
    name: str,
    *,
    path: str = '',
    where: str = '',
    source_hint: str = '',
) -> Dict[str, Any]:
    """Classify a field name into role + obtainability with confidence and evidence."""
    if not name:
        return {
            'field_role': 'unknown',
            'obtainability': 'OX_unknown',
            'confidence': 0.0,
            'rule_evidence': ['empty_field_name'],
        }

    rule_hits = _match_role_rules(name)
    role = 'unknown'
    evidence: List[str] = []

    if rule_hits:
        role = rule_hits[0][0]
        evidence.extend(h[1] for h in rule_hits[:2])
        confidence = 0.82
    else:
        confidence = 0.45
        evidence.append('no_rule_match')

    # Refinements overriding generic matches
    low = name.lower()
    if 'tokencode' in low:
        role = 'local_device_context'
        evidence.append('refinement:tokencode_is_device_context')
        confidence = max(confidence, 0.88)
    elif CAPABILITY_FIELD_RE.search(name):
        role = 'capability_token'
        evidence.append('refinement:capability_pattern')
        confidence = max(confidence, 0.9)
    elif WORKFLOW_FIELD_RE.search(name) and role not in {'capability_token'}:
        if 'order' in low or 'invoice' in low or 'contract' in low or 'rescue' in low:
            role = 'object_id'
            evidence.append('refinement:workflow_object_pattern')
            confidence = max(confidence, 0.85)
    elif FIRST_HOP_OBJECT_RE.search(name) and role == 'unknown':
        role = 'object_id'
        evidence.append('refinement:first_hop_object_pattern')
        confidence = max(confidence, 0.75)
    elif role == 'unknown':
        role = 'ordinary_field'
        confidence = 0.4

    obtainability, obs_evidence = _infer_obtainability(name, role, path=path, where=where)
    evidence.extend(obs_evidence)

    if source_hint:
        evidence.append(f'source_hint:{source_hint}')
        if 'globalData' in source_hint and role == 'subject_id':
            confidence = min(0.95, confidence + 0.08)

    return {
        'field_role': role,
        'obtainability': obtainability,
        'confidence': round(min(1.0, confidence), 2),
        'rule_evidence': evidence,
    }


def _infer_obtainability(
    name: str,
    role: str,
    *,
    path: str = '',
    where: str = '',
) -> Tuple[str, List[str]]:
    evidence: List[str] = []
    low = name.lower()

    if role == 'static_constant' or low in {'appid', 'channelid', 'appversion', 'appplatform'}:
        return 'O0_static_derived', ['obtainability:static_constant']

    if role == 'capability_token' or CAPABILITY_FIELD_RE.search(name):
        return 'O5_sensitive_capability', ['obtainability:capability_token']

    if WORKFLOW_FIELD_RE.search(name) and role == 'object_id':
        if re.search(r'/list|recent', path, re.I):
            return 'O3_first_hop_object', ['obtainability:workflow_on_list_path']
        return 'O4_workflow_object', ['obtainability:workflow_object']

    if role == 'object_id' and FIRST_HOP_OBJECT_RE.search(name):
        if re.search(r'/list|recent|device', path, re.I):
            evidence.append('obtainability:first_hop_list_path')
            return 'O3_first_hop_object', evidence
        return 'O3_first_hop_object', ['obtainability:object_id_default_first_hop']

    if role in {'host_identity', 'local_device_context'}:
        return 'O2_host_local', [f'obtainability:{role}']

    if role in {'auth_token', 'subject_id', 'crypto_derived'}:
        if role == 'crypto_derived' and low in {'appidentity'}:
            return 'O0_static_derived', ['obtainability:crypto_header_static']
        return 'O1_login_bootstrap', [f'obtainability:{role}']

    if role == 'environment_context':
        return 'O1_login_bootstrap', ['obtainability:environment_context']

    if role == 'pagination_filter':
        return 'O0_static_derived', ['obtainability:pagination_filter']

    if where == 'header' and role in {'auth_token', 'crypto_derived'}:
        return 'O1_login_bootstrap', ['obtainability:auth_header']

    return 'OX_unknown', ['obtainability:fallback_unknown']


def classify_side_effect(card: Dict[str, Any]) -> str:
    path = ((card.get('static') or {}).get('endpoint') or {}).get('path') or ''
    method = ((card.get('static') or {}).get('http') or {}).get('method') or ''
    replay_cat = (card.get('replay') or {}).get('side_effect', {}).get('category') or 'unknown'
    negatives = set((card.get('ranking') or {}).get('negative_reasons') or [])

    if DEFERRED_PATH_RE.search(path) or 'payment_related' in negatives:
        if re.search(r'pay|freeze|refund|charge|wallet', path, re.I):
            return 'S4_high_risk_business_action'
        return 'S3_state_changing'
    if re.search(r'delete|remove|cancel', path, re.I):
        return 'S3_state_changing'
    if re.search(r'update|save|bind|unbind|submit|mark', path, re.I) and method in {'POST', 'PUT', 'PATCH'}:
        return 'S2_light_state_change'
    if method == 'POST' and re.search(r'search|filter|calculate|query', path, re.I):
        return 'S1_query_like_post'
    if replay_cat == 'read_only' or (
        method == 'GET' and re.search(r'list|detail|info|profile|get|query', path, re.I)
    ):
        return 'S0_read_only'
    if method == 'GET':
        return 'S0_read_only'
    if method == 'POST':
        return 'S1_query_like_post'
    return 'S2_light_state_change'


def side_effect_short(level: str) -> str:
    if level in SIDE_EFFECT_SHORT:
        return SIDE_EFFECT_SHORT[level]
    if level in {'S0', 'S1', 'S2', 'S3', 'S4'}:
        return level
    return 'S3'


def is_stage1_safe_side_effect(level: str) -> bool:
    short = side_effect_short(level)
    return short in {'S0', 'S1'}


def stage1_user_obtainability(obtainability: str) -> bool:
    return obtainability in {
        'O0_static_derived', 'O1_login_bootstrap', 'O2_host_local',
    }


def is_deferred_obtainability(obtainability: str) -> bool:
    return obtainability in {'O4_workflow_object', 'O5_sensitive_capability'}
