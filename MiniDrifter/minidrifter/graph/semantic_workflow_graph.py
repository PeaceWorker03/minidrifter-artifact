# -*- coding: utf-8
"""Semantic workflow signals — path/page/domain continuity beyond exact field match."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

LIST_DETAIL_PATTERNS = (
    (re.compile(r'/List/?$', re.I), re.compile(r'/Detail|/Info|/Get/?$', re.I)),
    (re.compile(r'/List/', re.I), re.compile(r'/Detail|/Info|/', re.I)),
    (re.compile(r'List/V\d', re.I), re.compile(r'Detail|Query|ById', re.I)),
    (re.compile(r'/History/List', re.I), re.compile(r'/History/Detail|/Invoice/', re.I)),
)

DOMAIN_KEYWORDS = {
    'order': {'order', 'rental', 'booking', 'reservation'},
    'invoice': {'invoice', 'bill', 'receipt', 'fapiao'},
    'device': {'device', 'mini', 'vehicle', 'car'},
    'member': {'user', 'member', 'profile', 'card', 'balance'},
    'coupon': {'coupon', 'promotion', 'discount'},
    'payment': {'pay', 'prepay', 'wallet', 'balance'},
    'address': {'address', 'city', 'store', 'location'},
}


def path_segments(path: str) -> List[str]:
    return [s for s in re.split(r'[/\\]+', path or '') if s]


def infer_domain_from_path(path: str) -> str:
    low = (path or '').lower()
    for domain, kws in DOMAIN_KEYWORDS.items():
        if any(k in low for k in kws):
            return domain
    return 'general'


def list_detail_score(from_path: str, to_path: str) -> float:
    """Score 0-1 for list→detail semantic continuity."""
    if not from_path or not to_path:
        return 0.0
    for list_pat, detail_pat in LIST_DETAIL_PATTERNS:
        if list_pat.search(from_path) and detail_pat.search(to_path):
            if infer_domain_from_path(from_path) == infer_domain_from_path(to_path):
                return 0.85
            return 0.55
    # shared prefix depth
    a, b = path_segments(from_path), path_segments(to_path)
    common = 0
    for x, y in zip(a, b):
        if x.lower() == y.lower():
            common += 1
        else:
            break
    if common >= 2 and len(a) >= 2:
        return min(0.4 + common * 0.1, 0.75)
    return 0.0


def field_alias_overlap(required: Set[str], available: Set[str]) -> Tuple[float, List[str]]:
    """Fuzzy field match: OrderNo vs orderId, billId vs OrderId."""
    aliases = {
        'orderid': {'orderno', 'order_no', 'billid', 'billno', 'order_id'},
        'invoiceid': {'invoiceno', 'invoice_no', 'titleid', 'billid'},
        'deviceid': {'devicecode', 'deviceno', 'equipmentid'},
        'userid': {'customerid', 'memberid', 'openid'},
        'storeid': {'storecode', 'shopid'},
    }
    hints: List[str] = []
    score = 0.0
    req_lower = {r.lower(): r for r in required}
    avail_lower = {a.lower() for a in available}
    for req_l, req_orig in req_lower.items():
        if req_l in avail_lower:
            continue
        for canon, alts in aliases.items():
            if req_l == canon or req_l in alts:
                if canon in avail_lower or alts & avail_lower:
                    score += 0.35
                    hints.append(f'{req_orig}~alias_match')
                    break
    return min(score, 1.0), hints


def score_semantic_link(
    from_path: str,
    to_path: str,
    *,
    required: Set[str],
    available: Set[str],
    domain: Optional[str] = None,
) -> Dict[str, Any]:
    ld = list_detail_score(from_path, to_path)
    alias_s, alias_hints = field_alias_overlap(required, available)
    dom_from = infer_domain_from_path(from_path)
    dom_to = infer_domain_from_path(to_path)
    dom_match = 1.0 if dom_from == dom_to else (0.5 if dom_from != 'general' and dom_to != 'general' else 0.2)
    if domain and domain not in ('general', dom_to):
        dom_match *= 0.7
    total = ld * 0.45 + alias_s * 0.35 + dom_match * 0.2
    return {
        'semantic_score': round(total, 3),
        'list_detail_score': ld,
        'alias_score': alias_s,
        'domain_match': dom_match,
        'alias_hints': alias_hints,
        'from_domain': dom_from,
        'to_domain': dom_to,
    }


def rank_semantic_consumers(
    from_path: str,
    candidates: List[Dict[str, Any]],
    *,
    available_fields: Set[str],
    chain_domain: str = 'general',
    limit: int = 10,
) -> List[Dict[str, Any]]:
    """Rank near-miss / partial candidates by semantic continuity."""
    ranked: List[Dict[str, Any]] = []
    for c in candidates:
        path = c.get('path') or ''
        required = set(c.get('required') or c.get('missing_fields') or [])
        sem = score_semantic_link(
            from_path, path,
            required=required,
            available=available_fields,
            domain=chain_domain,
        )
        if sem['semantic_score'] < 0.25:
            continue
        ranked.append({**c, **sem, 'candidate_type': 'semantic_miss'})
    ranked.sort(key=lambda x: x['semantic_score'], reverse=True)
    return ranked[:limit]
