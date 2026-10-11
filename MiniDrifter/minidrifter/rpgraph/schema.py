# -*- coding: utf-8 -*-
"""Schemas and shared helpers for RPGraph reconstruction."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

from minidrifter.business_chain.field_role import (
    BINDING_HIGH_ROLES,
    BUSINESS_OBJECT_ID,
    CAPABILITY_CREDENTIAL,
    SUBJECT_ID,
    infer_field_role,
)

SCHEMA_VERSION = '1.0.0'
PATH_CONTEXT_CRED = '__resource_ctx__'

SENSITIVE_PATH_RE = re.compile(
    r'(order|pay|invoice|device|member|user|balance|coupon|address|booking|'
    r'accident|rescue|qualify|qualification|account|detail|bind|unbind|'
    r'auth|upload|verify|idcard|bank|cert|rent|tenant|register|realname|'
    r'identity|personal|profile)',
    re.I,
)
AUTH_BOOTSTRAP_RE = re.compile(
    r'(login|oauth|signin|signup|auth|token|session|openid|userinfo|code2session|jscode2session)',
    re.I,
)
# True auth/login producers for cross-domain ≺ (avoid matching SignIn/签到)
AUTH_LOGIN_RE = re.compile(
    r'(login|logout|oauth|signup|register|code2session|jscode2session|'
    r'getopenid|wxlogin|ssologin|sso_login|quickgetuserid)',
    re.I,
)
PRODUCER_PATH_RE = re.compile(
    r'(list|query|search|get|detail|info|create|add|save|submit)',
    re.I,
)


SESSION_IDENTITY_NAMES = {
    'token', 'accesstoken', 'access_token', 'openid', 'unionid',
    'sessionkey', 'session_key', 'authorization', 'auth',
}


def is_session_identity(name: str) -> bool:
    low = str(name or '').strip().lower().replace('-', '_')
    return low in SESSION_IDENTITY_NAMES or low.replace('_', '') in {
        'accesstoken', 'sessionkey',
    }


def norm_identity(anchor: Any) -> str:
    if anchor is None or anchor == '':
        return '⊥'
    raw = str(anchor).strip()
    low = raw.lower().replace('-', '_')
    # WeChat mini-program session identity family (token/openid co-scope)
    if is_session_identity(low):
        return 'wechat_session'
    return raw


def field_aliases(name: str) -> Set[str]:
    n = str(name or '')
    out = {n, n.lower(), n.replace('_', '').lower()}
    # Camel/snake soft aliases
    snake = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', n).lower()
    snake = snake.replace('-', '_')
    out.add(snake)
    compact = snake.replace('_', '')
    out.add(compact)
    # accidentid ↔ accident_id ↔ AccidentId / orderId
    if len(compact) > 3:
        for suf in ('id', 'no', 'code'):
            if compact.endswith(suf) and len(compact) > len(suf):
                stem = compact[: -len(suf)]
                out.add(f'{stem}_{suf}')
                out.add(f'{stem}{suf}')
                if stem:
                    out.add(stem + suf[:1].upper() + suf[1:])  # orderId
                break
    return {x for x in out if x}


def continuity_fields(RCR: Dict[str, Any], *, allow_path_context: bool = True) -> List[str]:
    """Fields that participate in RecoverEdge nodes / DirectProp matching.

    Includes binding/business credentials plus session identity credentials.
    Identity/session fields enable SameScope continuity; they are still excluded
    from RR-Drift workflow targets in select_targets.
    """
    seen: Set[str] = set()
    out: List[str] = []

    def _add(name: Any) -> None:
        n = str(name or '').strip()
        if not n or n in seen:
            return
        seen.add(n)
        out.append(n)

    for x in credential_set(RCR, allow_path_context=allow_path_context):
        _add(x)
    rs = RCR.get('request_semantics') or {}
    ia = rs.get('identity_anchor')
    if isinstance(ia, dict):
        ia = ia.get('name')
    if ia and str(ia) != PATH_CONTEXT_CRED:
        _add(ia)
    for c in rs.get('credentials') or []:
        name = c if isinstance(c, str) else (c.get('name') if isinstance(c, dict) else '')
        if name and (is_session_identity(str(name)) or is_business_bind_field(str(name))):
            _add(name)
    return out


def is_business_bind_field(name: str) -> bool:
    role = infer_field_role(name).get('role')
    if role in BINDING_HIGH_ROLES or role in {BUSINESS_OBJECT_ID, CAPABILITY_CREDENTIAL, SUBJECT_ID}:
        return True
    return bool(re.search(r'.+(id|no|code)$', name or '', re.I) and len(name or '') >= 5)


def credential_set(RCR: Dict[str, Any], *, allow_path_context: bool = True) -> List[str]:
    """Prefer binding_credentials; fall back to business-like credentials.

    Sensitive endpoints with no recoverable bind fields still get a path-context
    credential so RPGraph workflows remain reconstructible under
    wrapper-obscured request bodies (general, not app-specific).
    """
    bind = list(RCR.get('binding_credentials') or [])
    if bind:
        return sorted(set(str(x) for x in bind))
    creds = list((RCR.get('request_semantics') or {}).get('credentials') or [])
    biz = sorted({c for c in creds if is_business_bind_field(str(c))})
    if biz:
        return biz
    path = ((RCR.get('endpoint') or {}).get('path') or '')
    if allow_path_context and SENSITIVE_PATH_RE.search(path):
        return [PATH_CONTEXT_CRED]
    return []


def is_sensitive_ccr(RCR: Dict[str, Any]) -> bool:
    path = ((RCR.get('endpoint') or {}).get('path') or '')
    if SENSITIVE_PATH_RE.search(path):
        return True
    # Explicit (non path-inferred) business binds also mark sensitivity.
    notes = RCR.get('notes') or {}
    path_inferred = set()
    if isinstance(notes, dict):
        path_inferred = {str(x) for x in (notes.get('path_inferred_binds') or [])}
    bind = [str(x) for x in (RCR.get('binding_credentials') or []) if str(x) not in path_inferred]
    if any(is_business_bind_field(b) and b != PATH_CONTEXT_CRED for b in bind):
        return True
    creds = list((RCR.get('request_semantics') or {}).get('credentials') or [])
    if any(is_business_bind_field(str(c)) and str(c) not in path_inferred for c in creds):
        return True
    return False


def path_domain(path: str) -> str:
    parts = [p for p in (path or '').split('/') if p]
    if not parts:
        return 'root'
    # Coarse API family: /order/add and /order/calc share domain "order".
    # Keep two segments only under gateway prefixes (Wechat/Accident, api/v1, ...).
    head = parts[0].lower()
    if head in {
        'wechat', 'wx', 'api', 'apis', 'v1', 'v2', 'v3', 'mini', 'minipro',
        'applet', 'gateway', 'mobile', 'app', 'wxa', 'cgi-bin',
    } and len(parts) >= 2:
        return '/'.join(parts[:2]).lower()
    return head
