# -*- coding: utf-8 -*-
"""Unified field role inference for business chain and binding drift."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

AUTH_MATERIAL = 'AUTH_MATERIAL'
HOST_IDENTITY = 'HOST_IDENTITY'
SUBJECT_ID = 'SUBJECT_ID'
BUSINESS_OBJECT_ID = 'BUSINESS_OBJECT_ID'
CAPABILITY_CREDENTIAL = 'CAPABILITY_CREDENTIAL'
STATE_FIELD = 'STATE_FIELD'
CONTEXT_ID = 'CONTEXT_ID'
CRYPTO_MATERIAL = 'CRYPTO_MATERIAL'
PAGINATION_PARAM = 'PAGINATION_PARAM'
FILTER_PARAM = 'FILTER_PARAM'
UNKNOWN = 'UNKNOWN'

BINDING_HIGH_ROLES = frozenset({
    SUBJECT_ID, BUSINESS_OBJECT_ID, CAPABILITY_CREDENTIAL, HOST_IDENTITY,
})

_AMBIGUOUS_SUBJECT = re.compile(
    r'^(user_?id|userid|uid|customer_?id|member_?id|memberid|login_?customer_?id|platform_?user_?id)$',
    re.I,
)
_OBJECT_ID = re.compile(
    r'^(order_?id|orderid|orderno|order_?no|device_?id|deviceid|invoice_?id|address_?id|'
    r'cart_?id|goods_?id|shop_?id|shopid|store_?id|storeid|card_?id|cardid|'
    r'balance_?id|coupon_?id|ticket_?id|booking_?id)$',
    re.I,
)
_CAPABILITY = re.compile(
    r'(pay_?code|qr_?code|verify_?code|ticket|token_?code|auth_?code|captcha)', re.I,
)
_AUTH = re.compile(r'^(token|authorization|cookie|apitoken|api_?token|session)$', re.I)
_HOST = re.compile(r'^(open_?id|union_?id|wx_?code|session_?key|app_?id)$', re.I)
_CRYPTO = re.compile(r'^(sign|signature|nonce|timestamp|timespan|appidentity)$', re.I)
_STATE = re.compile(r'(status|state|order_?status|pay_?status)$', re.I)
_PAGE = re.compile(r'^(page|page_?no|page_?size|limit|offset|cursor)$', re.I)


def infer_field_role(field_name: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Classify a field for binding relevance and mutation targeting."""
    name = str(field_name or '').strip()
    nl = name.lower().replace('-', '_')
    ctx = context or {}
    evidence: List[str] = []
    ambiguous: List[str] = []

    role = UNKNOWN
    object_type = ''
    binding_relevance = 'low'
    mutation_relevance = 'low'

    if _AUTH.search(nl) or nl.endswith('token'):
        role = AUTH_MATERIAL
        evidence.append('auth_material_pattern')
    elif _HOST.search(nl):
        role = HOST_IDENTITY
        binding_relevance = 'high'
        evidence.append('host_identity_pattern')
    elif _CRYPTO.search(nl):
        role = CRYPTO_MATERIAL
        evidence.append('crypto_material_pattern')
    elif _CAPABILITY.search(nl):
        role = CAPABILITY_CREDENTIAL
        binding_relevance = 'high'
        mutation_relevance = 'high'
        object_type = 'capability'
        evidence.append('capability_pattern')
    elif _STATE.search(nl):
        role = STATE_FIELD
        evidence.append('state_field_pattern')
    elif _PAGE.search(nl):
        role = PAGINATION_PARAM
        evidence.append('pagination_pattern')
    elif _OBJECT_ID.match(nl):
        role = BUSINESS_OBJECT_ID
        binding_relevance = 'high'
        mutation_relevance = 'high'
        object_type = _object_type_from_name(nl)
        evidence.append(f'object_id_pattern:{object_type}')
    elif _AMBIGUOUS_SUBJECT.match(nl):
        role = SUBJECT_ID
        ambiguous = [BUSINESS_OBJECT_ID]
        binding_relevance = 'high'
        mutation_relevance = 'high'
        object_type = _object_type_from_name(nl) or 'subject'
        evidence.append('ambiguous_subject_pattern')
    elif re.search(r'.+(_?id)$', nl) and len(nl) >= 4 and not re.search(
        r'^(app|client|device_?type|msg|request|trace|span)_?id$', nl
    ):
        # Generic *Id / *_id business handles (taskId, cityId, storeId, carId, ...).
        role = BUSINESS_OBJECT_ID
        binding_relevance = 'high'
        mutation_relevance = 'high'
        object_type = _object_type_from_name(nl) or 'resource'
        evidence.append('generic_id_suffix_pattern')

    if ctx.get('path'):
        path_low = str(ctx['path']).lower()
        if role == SUBJECT_ID and any(x in path_low for x in ('order', 'detail', 'invoice')):
            ambiguous = list({SUBJECT_ID, BUSINESS_OBJECT_ID})
            evidence.append('path_suggests_object_context')

    if role in BINDING_HIGH_ROLES:
        binding_relevance = 'high'
        if role in {SUBJECT_ID, BUSINESS_OBJECT_ID, CAPABILITY_CREDENTIAL}:
            mutation_relevance = 'high'

    confidence = 0.55
    if evidence:
        confidence = min(0.95, 0.6 + 0.08 * len(evidence))

    return {
        'field': name,
        'role': role,
        'ambiguous_roles': ambiguous,
        'object_type': object_type,
        'binding_relevance': binding_relevance,
        'mutation_relevance': mutation_relevance,
        'confidence': round(confidence, 2),
        'evidence': evidence,
    }


def _object_type_from_name(nl: str) -> str:
    for key in (
        'order', 'device', 'invoice', 'address', 'cart', 'goods', 'shop', 'store',
        'customer', 'user', 'member', 'task', 'city', 'car', 'booking',
    ):
        if key in nl:
            return key
    return ''
    return ''


def binding_fields_from_list(fields: List[str], *, path: str = '') -> List[str]:
    out: List[str] = []
    for f in fields:
        info = infer_field_role(f, {'path': path})
        if info.get('binding_relevance') == 'high':
            out.append(f)
    return out


def is_runtime_context_field(field_name: str) -> bool:
    nl = str(field_name or '').lower().replace('-', '_')
    if nl in {'token', 'authorization', 'signature', 'sign', 'nonce', 'timestamp'}:
        return True
    return nl in {x.replace('_', '') for x in {
        'appidentity', 'appversion', 'host', 'content_type', 'apitoken',
        'logincustomertoken', 'api_version', 'requestfromtype',
    }}
