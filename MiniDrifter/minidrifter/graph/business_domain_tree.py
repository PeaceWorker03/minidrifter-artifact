# -*- coding: utf-8 -*-
"""Business domain tree: cluster operations by path semantics."""
from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

SCHEMA_VERSION = '1.0.0'

DOMAIN_KEYWORDS: Dict[str, List[str]] = {
    'identity': ['login', 'openid', 'session', 'auth'],
    'user_profile': ['user', 'cardinfo', 'profile', 'member', 'contact', 'email', 'silvercard'],
    'device': ['device'],
    'order': ['order', 'orders', 'booking', 'rent', 'renting'],
    'invoice': ['invoice', 'bill'],
    'payment': ['pay', 'payment', 'preauth', 'freeze', 'refund', 'paypoints', 'wallet'],
    'store_vehicle': ['store', 'vehicle', 'car', 'model'],
    'address': ['address'],
    'coupon': ['coupon', 'promotion', 'discount'],
    'rescue': ['rescue', 'accident'],
    'illegal': ['illegal', 'violation'],
    'contract': ['contract', 'agreement'],
    'news': ['news', 'banner'],
    'session': ['session', 'closingaccount'],
}

OPERATION_SEMANTICS_KEYWORDS: Dict[str, List[str]] = {
    'list': ['list', 'query', 'search', 'page', 'recent', 'banner'],
    'detail': ['detail', 'info', 'byid', 'byuserid', 'get'],
    'create': ['create', 'submit', 'add', 'save'],
    'update': ['update', 'modify', 'edit'],
    'delete': ['delete', 'remove'],
    'pay': ['pay', 'preauth', 'freeze', 'refund', 'charge'],
    'auth': ['auth', 'authorize', 'subscribe'],
    'validate': ['validate', 'check', 'verify'],
}

SUBDOMAIN_HINTS: Dict[str, Dict[str, List[str]]] = {
    'device': {
        'device_management': ['device/list', 'device/update', 'delete/device'],
        'device_session': ['session', 'online/device'],
    },
    'order': {
        'order_query': ['order/list', 'orders/list'],
        'order_detail': ['detail', 'fee'],
        'order_extra': ['remark', 'extra'],
    },
    'user_profile': {
        'user_info': ['cardinfo', 'profile', 'byuserid'],
        'user_contact': ['contact', 'email', 'phone'],
    },
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def classify_business_domain(path: str) -> Tuple[str, float, List[str]]:
    low = (path or '').lower()
    scores: List[Tuple[str, int, List[str]]] = []
    for domain, keywords in DOMAIN_KEYWORDS.items():
        hits = [kw for kw in keywords if kw in low]
        if hits:
            scores.append((domain, len(hits), hits))
    if not scores:
        return 'unknown', 0.35, ['no_domain_keyword_match']
    scores.sort(key=lambda x: (-x[1], x[0]))
    domain, count, hits = scores[0]
    confidence = min(0.95, 0.5 + count * 0.12)
    return domain, round(confidence, 2), [f'domain_keyword:{h}' for h in hits[:3]]


def classify_operation_semantics(path: str, method: str = '') -> Tuple[str, float, List[str]]:
    low = (path or '').lower()
    m = (method or '').upper()
    scores: List[Tuple[str, int, str]] = []
    for sem, keywords in OPERATION_SEMANTICS_KEYWORDS.items():
        for kw in keywords:
            if kw in low:
                scores.append((sem, 2 if kw in {'list', 'detail', 'delete', 'pay'} else 1, kw))
    if m == 'GET' and 'list' in low:
        scores.append(('list', 3, 'method_get_list'))
    if m == 'POST' and re.search(r'search|filter|calculate', low):
        scores.append(('list', 2, 'post_query_like'))
    if not scores:
        return 'unknown', 0.35, ['no_semantics_keyword_match']
    scores.sort(key=lambda x: -x[1])
    sem, _, kw = scores[0]
    return sem, min(0.92, 0.45 + scores[0][1] * 0.15), [f'semantics:{kw}']


def classify_business_subdomain(domain: str, path: str) -> str:
    low = (path or '').lower()
    hints = SUBDOMAIN_HINTS.get(domain) or {}
    for sub, patterns in hints.items():
        if any(p in low for p in patterns):
            return sub
    return f'{domain}_general' if domain != 'unknown' else 'unknown'


def classify_card(card: Dict[str, Any]) -> Dict[str, Any]:
    path = ((card.get('static') or {}).get('endpoint') or {}).get('path') or ''
    method = ((card.get('static') or {}).get('http') or {}).get('method') or 'UNKNOWN'
    domain, dom_conf, dom_ev = classify_business_domain(path)
    semantics, sem_conf, sem_ev = classify_operation_semantics(path, method)
    subdomain = classify_business_subdomain(domain, path)
    tree_path = f'root/{domain}/{semantics}' if domain != 'unknown' else 'root/unknown'
    return {
        'card_id': card.get('card_id'),
        'path': path,
        'method': method,
        'business_domain': domain,
        'business_subdomain': subdomain,
        'operation_semantics': semantics,
        'tree_path': tree_path,
        'confidence': round(min(dom_conf, sem_conf), 2),
        'rule_evidence': dom_ev + sem_ev,
    }


def build_business_domain_tree(
    cards: List[Dict[str, Any]],
    manifest: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    operations = [c for c in cards if (c.get('provenance') or {}).get('card_kind') == 'operation']
    classifications = [classify_card(c) for c in operations]

    domain_tree: Dict[str, Dict[str, List[str]]] = {}
    by_card_id: Dict[str, Dict[str, Any]] = {}
    domain_dist = Counter()
    unknown_count = 0

    for cl in classifications:
        by_card_id[cl['card_id']] = cl
        dom = cl['business_domain']
        sem = cl['operation_semantics']
        domain_dist[dom] += 1
        if dom == 'unknown':
            unknown_count += 1
        domain_tree.setdefault(dom, {})
        domain_tree[dom].setdefault(sem, []).append(cl['card_id'])

    op_count = len(operations)
    known_pct = round(100.0 * (op_count - unknown_count) / max(op_count, 1), 1)

    return {
        'schema_version': SCHEMA_VERSION,
        'pack_id': (manifest or {}).get('pack_id'),
        'generated_at': _utc_now(),
        'generator': {'tool': 'MiniDrifter', 'stage': 'business_domain_tree'},
        'operation_count': op_count,
        'domain_distribution': dict(domain_dist),
        'unknown_domain_count': unknown_count,
        'known_domain_percent': known_pct,
        'domain_tree': domain_tree,
        'classifications': classifications,
        'by_card_id': by_card_id,
    }
