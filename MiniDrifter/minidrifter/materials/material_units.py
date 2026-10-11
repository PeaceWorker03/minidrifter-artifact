# -*- coding: utf-8 -*-
"""Standard material units for baseline collection."""
from __future__ import annotations

from typing import Any, Dict, List, Set

from minidrifter.core.runtime_taxonomy import is_deferred_obtainability, stage1_user_obtainability

MATERIAL_UNITS: Dict[str, Dict[str, Any]] = {
    'authenticated_request_sample': {
        'priority': 'required',
        'covers_roles': ['auth_token', 'crypto_derived', 'static_constant'],
        'covers_fields': [
            'Token', 'Authorization', 'AppIdentity', 'AppVersion', 'AppPlatform', 'Host',
            'Timestamp', 'TimeSpan', 'timestamp',
        ],
        'accepted_formats': ['raw_http', 'har', 'mitmproxy_flow', 'burp_item'],
        'reliability': 0.95,
        'user_instruction': '请提供登录后一条成功业务请求的完整 HTTP request 和 response。',
    },
    'login_or_user_profile_response': {
        'priority': 'required',
        'covers_roles': ['subject_id'],
        'covers_fields': ['UserId', 'userId', 'Phone', 'UserJwt', 'MarketToken', 'CustomerId'],
        'accepted_formats': ['json_response', 'raw_http_response', 'burp_item'],
        'reliability': 0.90,
        'user_instruction': '请提供登录接口、个人中心或用户信息接口 response，至少应包含 UserId。',
    },
    'openid_flow_sample': {
        'priority': 'recommended',
        'covers_roles': ['host_identity'],
        'covers_fields': ['OpenId', 'code', 'appId', 'channelId'],
        'accepted_formats': ['raw_http', 'har', 'mitmproxy_flow'],
        'reliability': 0.85,
        'user_instruction': '如存在 /MiniProgram/OpenId 或 wx.login 相关请求，请提供 request/response。',
    },
    'first_hop_response_device_list': {
        'priority': 'recommended',
        'covers_roles': ['object_id', 'local_device_context'],
        'covers_fields': ['DeviceId', 'TokenCode', 'DeviceName', 'OsVersion'],
        'domain': 'device',
        'accepted_formats': ['raw_http', 'har', 'mitmproxy_flow', 'burp_item'],
        'reliability': 0.85,
        'user_instruction': '请提供设备列表接口 request/response，或允许系统用登录材料自动调用设备列表。',
    },
    'first_hop_response_order_list': {
        'priority': 'deferred',
        'covers_roles': ['object_id'],
        'covers_fields': ['OrderId', 'OrderNo', 'StoreId'],
        'domain': 'order',
        'accepted_formats': ['raw_http', 'har', 'mitmproxy_flow'],
        'reliability': 0.80,
        'user_instruction': '订单列表 response（用于自动发现 OrderId，非 stage-1 必填）。',
    },
    'first_hop_response_address_list': {
        'priority': 'deferred',
        'covers_fields': ['AddressId'],
        'domain': 'address',
        'reliability': 0.75,
        'user_instruction': '地址列表 response（自动发现 AddressId）。',
    },
    'first_hop_response_invoice_list': {
        'priority': 'deferred',
        'covers_fields': ['InvoiceTitleId', 'InvoiceId'],
        'domain': 'invoice',
        'reliability': 0.75,
        'user_instruction': '发票抬头/列表 response。',
    },
}

NEVER_REQUEST_STAGE1: List[str] = [
    'PayNo', 'FreezeNo', 'QRCode', 'ContractId', 'InvoiceOrderId',
    'PrepayId', 'PaySign', 'VerifyCode', 'Barcode',
]

FIELD_TO_MATERIAL_HINTS: Dict[str, str] = {
    'DeviceId': 'first_hop_response_device_list',
    'TokenCode': 'first_hop_response_device_list',
    'DeviceName': 'first_hop_response_device_list',
    'OsVersion': 'first_hop_response_device_list',
    'OrderId': 'first_hop_response_order_list',
    'OrderNo': 'first_hop_response_order_list',
    'AddressId': 'first_hop_response_address_list',
    'InvoiceTitleId': 'first_hop_response_invoice_list',
    'OpenId': 'openid_flow_sample',
    'code': 'openid_flow_sample',
}


def material_candidates_for_field(
    name: str,
    role: str,
    obtainability: str,
) -> List[str]:
    """Map a field requirement to material unit IDs."""
    candidates: List[str] = []
    norm = (name or '').lower()

    if is_deferred_obtainability(obtainability):
        hint = FIELD_TO_MATERIAL_HINTS.get(name)
        if hint:
            candidates.append(hint)
        return candidates

    if role in {'auth_token', 'crypto_derived', 'static_constant'}:
        candidates.append('authenticated_request_sample')
    if role == 'subject_id':
        candidates.append('login_or_user_profile_response')
    if role in {'host_identity'} or obtainability == 'O2_host_local':
        candidates.append('openid_flow_sample')
    if role in {'local_device_context', 'object_id'} and obtainability == 'O3_first_hop_object':
        if 'device' in norm:
            candidates.append('first_hop_response_device_list')
        elif 'order' in norm:
            candidates.append('first_hop_response_order_list')
        elif 'address' in norm:
            candidates.append('first_hop_response_address_list')
        elif 'invoice' in norm:
            candidates.append('first_hop_response_invoice_list')

    if norm in {'token', 'authorization', 'appidentity', 'timestamp', 'timespan'}:
        if 'authenticated_request_sample' not in candidates:
            candidates.append('authenticated_request_sample')
    if norm in {'userid', 'user_id', 'phone', 'userjwt'}:
        if 'login_or_user_profile_response' not in candidates:
            candidates.append('login_or_user_profile_response')

    if name in FIELD_TO_MATERIAL_HINTS and FIELD_TO_MATERIAL_HINTS[name] not in candidates:
        if not is_deferred_obtainability(obtainability) or obtainability == 'O3_first_hop_object':
            candidates.append(FIELD_TO_MATERIAL_HINTS[name])

    if not candidates and stage1_user_obtainability(obtainability):
        candidates.append('authenticated_request_sample')

    return list(dict.fromkeys(candidates))


def stage1_material_priority(material_id: str) -> str:
    unit = MATERIAL_UNITS.get(material_id) or {}
    p = unit.get('priority') or 'recommended'
    if p == 'required':
        return 'required'
    if p == 'deferred':
        return 'deferred'
    return 'recommended'


def fields_covered_by_unit(material_id: str) -> Set[str]:
    unit = MATERIAL_UNITS.get(material_id) or {}
    return set(unit.get('covers_fields') or [])
