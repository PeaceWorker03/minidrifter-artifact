# -*- coding: utf-8 -*-
"""Shared subject override field allow/deny rules (P4-fix-5)."""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

from minidrifter.materials.intake_param_hints import normalize_api_path

ALLOWED_SUBJECT_FIELDS = frozenset({
    'memberid', 'customerid', 'userid', 'uid', 'openid', 'unionid', 'accountid',
    'memberno', 'customerno', 'platformuserid', 'logincustomerid',
    'subjectid', 'personid',
})

FORBIDDEN_SUBJECT_FIELDS = frozenset({
    'name', 'realname', 'idno', 'idcard', 'idcardno', 'driverlicense', 'studentno',
    'truename', 'nativeidno', 'nativephone', 'maskname', 'maskphone', 'certno',
})

CAUTIOUS_PHONE_FIELDS = frozenset({'phone', 'mobile', 'tel', 'telephone'})

CRYPTO_TRANSPORT_FIELDS = frozenset({
    'cid', 'q', 'sign', 'signature', 'timestamp', 'timespan', 'nonce', 'token',
})

SUBJECT_PRIORITY = (
    'memberId', 'MemberId', 'customerId', 'CustomerId', 'userId', 'UserId',
    'uid', 'openId', 'OpenId', 'unionId', 'UnionId', 'accountId', 'AccountId',
    'subjectId', 'personId',
)


def norm_field(field: str) -> str:
    return re.sub(r'[_\-\s]', '', str(field or '')).lower()


def infer_subject_fields_from_path(path: str) -> List[str]:
    """Generic path-shape hints for subject identifiers (not app-specific)."""
    norm = normalize_api_path(path).lower()
    fields: List[str] = []
    if '/byuserid' in norm or norm.endswith('/byuserid'):
        fields.append('userId')
    if 'personaldata' in norm or 'identitycard' in norm:
        fields.append('memberId')
    if 'getmemberinfo' in norm and 'openid' in norm:
        fields.append('openId')
    if '/device/list' in norm or norm.endswith('/device/list'):
        fields.append('userId')
    if 'invoiceablelist' in norm and 'byuserid' in norm:
        fields.append('userId')
    out: List[str] = []
    seen: set[str] = set()
    for name in fields:
        nf = norm_field(name)
        if nf not in seen:
            seen.add(nf)
            out.append(name)
    return out


def pool_value_for_subject_field(field: str, pool: dict) -> Optional[str]:
    """Resolve a subject field value from baseline / aggregate pool."""
    if not pool:
        return None
    target = norm_field(field)
    for k, v in pool.items():
        if v in (None, ''):
            continue
        if norm_field(k) == target:
            return str(v)
    siblings = {
        'memberid': ('userid', 'memberid', 'customerid'),
        'userid': ('userid', 'memberid', 'customerid'),
        'openid': ('openid', 'unionid'),
    }.get(target, ())
    for alt in siblings:
        for k, v in pool.items():
            if v in (None, ''):
                continue
            if norm_field(k) == alt:
                return str(v)
    return None


def field_allowed(
    field: str,
    *,
    value: Optional[str] = None,
    in_request: bool = True,
) -> Tuple[bool, str]:
    nf = norm_field(field)
    if nf in FORBIDDEN_SUBJECT_FIELDS:
        return False, 'forbidden_pii_field'
    if nf in CRYPTO_TRANSPORT_FIELDS:
        return False, 'crypto_transport_field'
    if nf in ALLOWED_SUBJECT_FIELDS:
        return True, 'subject_identifier'
    if nf in CAUTIOUS_PHONE_FIELDS:
        if in_request and value and ('*' in str(value) or '****' in str(value)):
            return True, 'masked_phone_in_request'
        return False, 'phone_not_masked_or_not_in_request'
    return False, 'not_subject_identifier'
