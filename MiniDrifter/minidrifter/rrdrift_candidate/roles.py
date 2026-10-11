# -*- coding: utf-8 -*-
"""RR-Drift-relevant field roles: identity / binding / resource continuity.

Maps MiniDrifter field_role taxonomy onto E1 C_i^bind (not all request params).
"""
from __future__ import annotations

import re
from typing import Optional

from minidrifter.business_chain.field_role import (
    AUTH_MATERIAL,
    BINDING_HIGH_ROLES,
    BUSINESS_OBJECT_ID,
    CAPABILITY_CREDENTIAL,
    CRYPTO_MATERIAL,
    HOST_IDENTITY,
    PAGINATION_PARAM,
    SUBJECT_ID,
    infer_field_role,
)

SESSION_NAMES = {
    "token", "accesstoken", "access_token", "openid", "unionid", "open_id",
    "sessionkey", "session_key", "authorization", "auth", "authtoken",
    "usertoken", "user_token", "servicetoken", "service_token", "jwt", "sid",
}
NOISE = {
    "code", "status", "msg", "message", "data", "type", "errno", "errmsg",
    "errcode", "ret", "result", "success", "error", "err", "info", "list",
    "page", "pagesize", "timestamp", "nonce", "sign", "signature", "appid",
    "msgid", "requestid", "contenttype", "accept", "host", "width", "height",
    "version", "scene", "traceid", "url", "title", "custom",
}


def is_session(name: str) -> bool:
    n = re.sub(r"[^a-z0-9_]", "", (name or "").lower().replace("-", "_").replace(".", "_"))
    if n in SESSION_NAMES or n.replace("_", "") in {
        "accesstoken", "sessionkey", "usertoken", "authtoken", "servicetoken", "openid",
    }:
        return True
    role = infer_field_role(name).get("role")
    if role in {AUTH_MATERIAL, HOST_IDENTITY} and any(
        k in n for k in ("token", "openid", "session", "authorization", "auth")
    ):
        return True
    return any(k in n for k in ("token", "openid", "sessionkey", "authorization"))


def is_bind(name: str) -> bool:
    n = (name or "").strip()
    if not n or is_session(n):
        return False
    low = n.lower().replace("-", "_").replace(".", "_")
    if low in NOISE:
        return False
    info = infer_field_role(n)
    role = info.get("role")
    if role in {CRYPTO_MATERIAL, PAGINATION_PARAM}:
        return False
    if role in BINDING_HIGH_ROLES or role in {
        BUSINESS_OBJECT_ID, CAPABILITY_CREDENTIAL, SUBJECT_ID, HOST_IDENTITY,
    }:
        # HOST openid already handled as session; remaining host ids rare
        if role == HOST_IDENTITY and is_session(n):
            return False
        return True
    if re.search(r"(id|no|code|num)$", low) and len(low) >= 4 and low not in {"appid", "msgid"}:
        return True
    return bool(re.search(
        r"^(order|member|user|device|invoice|coupon|store|shop|address|ticket|card|booking|goods|product)",
        low,
    ))


def field_role(name: str) -> Optional[str]:
    if is_session(name):
        return "session"
    if is_bind(name):
        return "binding"
    return None


def storage_maps_to_field(key: str) -> Optional[str]:
    k = (key or "").strip()
    if not k:
        return None
    low = k.lower().replace("-", "_")
    leaf = low.split(".")[-1]
    if "openid" in low or leaf in {"openid", "open_id"}:
        return "openid"
    if "unionid" in low:
        return "unionid"
    if "session" in low:
        return "session_key"
    if any(x in low for x in ("token", "auth", "service_token", "servicetoken")):
        return "token"
    if "userid" in low or leaf in {"userid", "user_id", "uid"}:
        return "userId"
    if "member" in low and "id" in low:
        return "memberId"
    if field_role(leaf):
        return leaf
    if field_role(k):
        return k
    return None
