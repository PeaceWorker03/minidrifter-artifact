# -*- coding: utf-8 -*-
"""Generic API path token semantics — domain-agnostic, evidence-graded."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from minidrifter.materials.intake_param_hints import normalize_api_path

_GENERIC_SEG = frozenset({
    'list', 'detail', 'info', 'get', 'query', 'index', 'v1', 'v2', 'v3', 'v4',
    'wechat', 'wx', 'applet', 'action', 'api', 'resource', 'carrctapi', 'order',
    'orders', 'data', 'json', 'jhtml', 'html',
})

# (pattern, page_label, action_label, domain_hint, page_tokens)
_PATH_SEMANTIC_RULES: List[Tuple[re.Pattern[str], str, str, str, Tuple[str, ...]]] = [
    # Rental / mobility
    (re.compile(r'citylist|opencity|city/list', re.I), '城市/门店选择', '选择城市或门店', 'dept', ('city', 'dept', 'store')),
    (re.compile(r'deptlist|dept.*list|searchdept|listandmap', re.I), '门店搜索/选择', '搜索或选择门店', 'dept', ('city', 'dept', 'store')),
    (re.compile(r'deptdetail|dept.*detail', re.I), '门店详情', '查看门店详情', 'dept', ('dept', 'detail')),
    (re.compile(r'carsubscription|car.*subscription', re.I), '车辆订阅', '浏览订阅车辆', 'order', ('car', 'subscription')),
    (re.compile(r'hicar|digitalkey|bluetooth', re.I), '数字钥匙/设备', '查看数字钥匙', 'device', ('device', 'hicar', 'key')),
    (re.compile(r'dropoff|pickup|returncar', re.I), '取还车', '取车或还车操作', 'order', ('pickup', 'dropoff')),
    # Retail / food / group-buy
    (re.compile(r'purchased/shop|bought.*shop', re.I), '已购店铺', '打开已购店铺列表', 'order', ('shop', 'purchased')),
    (re.compile(r'goods.*list|goods/data|product.*list', re.I), '商品列表', '浏览商品列表', 'general', ('goods', 'shop')),
    (re.compile(r'cart|shoppingcart', re.I), '购物车', '查看购物车', 'cart', ('cart',)),
    (re.compile(r'coupon|voucher', re.I), '优惠券', '浏览优惠券', 'member', ('coupon',)),
    (re.compile(r'super.?member|member.*card', re.I), '超级会员', '打开会员中心', 'member', ('member', 'super')),
    (re.compile(r'personalcore|personal/core|user/personal', re.I), '个人中心', '打开个人中心', 'member', ('person', 'user', 'my')),
    (re.compile(r'address.*list|address/list', re.I), '地址列表', '查看收货地址', 'address', ('address',)),
    (re.compile(r'sign.*json|customer/sign', re.I), '签到/会员', '完成签到或会员操作', 'member', ('sign', 'member')),
    (re.compile(r'urlforward|forwardpage', re.I), '活动跳转页', '打开活动或跳转页', 'general', ('index',)),
    # Shared commerce
    (re.compile(r'order.*list|orderdata/list|order/list', re.I), '订单列表', '浏览订单列表', 'order', ('order', 'orderlist')),
    (re.compile(r'order.*detail|orders/detail', re.I), '订单详情', '查看订单详情', 'order', ('order', 'orderdetail')),
    (re.compile(r'order.*finish|order.*cancel', re.I), '订单操作', '操作订单状态', 'order', ('order',)),
    (re.compile(r'invoice', re.I), '发票', '浏览发票', 'order', ('invoice',)),
    (re.compile(r'payment|pay/|prepay', re.I), '支付', '进入支付流程（勿完成支付）', 'payment', ('pay', 'payment')),
    (re.compile(r'device/list', re.I), '设备列表', '浏览我的设备', 'device', ('device',)),
    (re.compile(r'comment|review', re.I), '评价', '浏览或提交评价', 'order', ('comment',)),
    (re.compile(r'login|bycode|auth', re.I), '登录', '完成登录授权', 'member', ('login', 'bind')),
]


def api_path_tokens(norm_path: str) -> List[str]:
    parts = [p for p in norm_path.split('/') if p and p.lower() not in _GENERIC_SEG]
    low = norm_path.lower()
    if 'order' in low:
        parts.extend(['order', 'orders'])
    if 'list' in low:
        parts.append('list')
    if 'detail' in low:
        parts.append('detail')
    if 'goods' in low:
        parts.append('goods')
    if 'member' in low:
        parts.append('member')
    return list(dict.fromkeys(p.lower() for p in parts if len(p) > 1))


def infer_path_semantic(api_path: str) -> Dict[str, Any]:
    """Generic semantic labels + page token hints from API path."""
    norm = normalize_api_path(api_path)
    parts = [p for p in norm.split('/') if p]
    tail = parts[-1] if parts else ''
    api_label = next(
        (p for p in reversed(parts) if p.lower() not in _GENERIC_SEG and not re.match(r'^v\d+$', p, re.I)),
        tail,
    )
    for pat, page_label, action, domain, page_tokens in _PATH_SEMANTIC_RULES:
        if pat.search(norm) or pat.search(api_label):
            return {
                'page_label': page_label,
                'action_label': action,
                'api_tail': api_label,
                'domain_hint': domain,
                'page_tokens': list(page_tokens),
                'path_tokens': api_path_tokens(norm),
                'rule_matched': pat.pattern[:40],
            }
    seg = api_label or '业务'
    return {
        'page_label': f'{seg} 相关页面',
        'action_label': '触发该业务请求',
        'api_tail': api_label,
        'domain_hint': 'general',
        'page_tokens': api_path_tokens(norm)[:4],
        'path_tokens': api_path_tokens(norm),
        'rule_matched': None,
    }


def page_token_overlap(page_id: str, semantic: Dict[str, Any]) -> float:
    """Score how well a page path matches API semantic tokens."""
    pid = (page_id or '').lower()
    if not pid:
        return 0.0
    score = 0.0
    api_tail = (semantic.get('api_tail') or '').lower()
    if api_tail and api_tail in pid:
        score += 0.55
    for tok in semantic.get('page_tokens') or []:
        if tok in pid:
            score += 0.18
    for tok in semantic.get('path_tokens') or []:
        if len(tok) > 3 and tok in pid:
            score += 0.10
    label = semantic.get('page_label') or ''
    if '订单' in label and 'order' in pid:
        score += 0.28
    if '门店' in label or '城市' in label:
        if any(k in pid for k in ('city', 'dept', 'store', 'shop')):
            score += 0.22
    if '商品' in label and any(k in pid for k in ('goods', 'shop', 'product')):
        score += 0.22
    if '个人' in label and any(k in pid for k in ('person', 'user', 'my', 'member')):
        score += 0.22
    if '会员' in label and 'member' in pid:
        score += 0.20
    return min(score, 0.98)
