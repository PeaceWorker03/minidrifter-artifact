# -*- coding: utf-8
"""Business chain template matchers — classify chain shape."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from minidrifter.business_chain.schema import (
    CHAIN_BIND_UNBIND,
    CHAIN_CAPABILITY_CONSUME,
    CHAIN_GENERAL,
    CHAIN_LIST_DETAIL,
    CHAIN_OBJECT_CAPABILITY,
    CHAIN_PROFILE_OBJECT,
)

_LIST = re.compile(r'(list|history|search|query|index)', re.I)
_DETAIL = re.compile(r'(detail|info|get\b)', re.I)
_PROFILE = re.compile(r'(personal|profile|member|user/core|sign/json)', re.I)
_PAY = re.compile(r'(pay|qrcode|verify|ticket|code)', re.I)
_BIND = re.compile(r'(bind|unbind)', re.I)
_SUBMIT = re.compile(r'(submit|create|confirm|cancel|delete|pay)', re.I)


def classify_chain_type(hops: List[Dict[str, Any]]) -> str:
    if not hops:
        return CHAIN_GENERAL
    paths = [h.get('path') or '' for h in hops]
    joined = ' '.join(paths).lower()

    if _BIND.search(joined):
        return CHAIN_BIND_UNBIND
    if len(hops) >= 2 and _LIST.search(paths[0]) and _DETAIL.search(paths[-1]):
        return CHAIN_LIST_DETAIL
    if _PROFILE.search(paths[0]):
        return CHAIN_PROFILE_OBJECT
    if any(_PAY.search(p) for p in paths) and len(hops) >= 2:
        if _PAY.search(paths[-1]):
            return CHAIN_CAPABILITY_CONSUME
        return CHAIN_OBJECT_CAPABILITY
    return CHAIN_GENERAL


def is_safe_chain(hops: List[Dict[str, Any]]) -> bool:
    for h in hops:
        side = (h.get('side_effect') or h.get('side_effect_level') or '')
        short = side.split('_')[0] if side else ''
        if short in {'S3', 'S4'} or _SUBMIT.search(h.get('path') or ''):
            if short not in {'S0', 'S1'} and 'read' not in side.lower():
                return False
    return True


def chain_type_label(chain_type: str) -> str:
    return {
        CHAIN_LIST_DETAIL: '列表→详情',
        CHAIN_PROFILE_OBJECT: '个人中心→资产查询',
        CHAIN_OBJECT_CAPABILITY: '对象→能力凭证',
        CHAIN_CAPABILITY_CONSUME: '凭证→消费',
        CHAIN_BIND_UNBIND: '绑定/解绑',
        CHAIN_GENERAL: '通用业务链',
    }.get(chain_type, chain_type)
