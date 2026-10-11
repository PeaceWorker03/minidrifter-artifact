# -*- coding: utf-8 -*-
"""Enhanced produces-edge inference for runtime demand graph."""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.core.runtime_taxonomy import classify_field
from minidrifter.graph.business_domain_tree import classify_card

PATH_PRODUCES_RULES: List[Tuple[re.Pattern[str], List[str], float, str]] = [
    (re.compile(r'device/list', re.I), ['DeviceId', 'TokenCode', 'DeviceName', 'OsVersion'], 0.55, 'path_keyword'),
    (re.compile(r'on.?line/device/list', re.I), ['DeviceId', 'TokenCode'], 0.55, 'path_keyword'),
    (re.compile(r'orders?/list', re.I), ['OrderId', 'OrderNo', 'StoreId'], 0.55, 'path_keyword'),
    (re.compile(r'order/list', re.I), ['OrderId', 'OrderNo', 'StoreId'], 0.55, 'path_keyword'),
    (re.compile(r'address.*list|/address', re.I), ['AddressId'], 0.5, 'path_keyword'),
    (re.compile(r'email/list', re.I), ['EmailId'], 0.5, 'path_keyword'),
    (re.compile(r'invoice.*title.*list|invoicetitle', re.I), ['InvoiceTitleId'], 0.5, 'path_keyword'),
    (re.compile(r'invoice.*list', re.I), ['InvoiceId', 'InvoiceTitleId'], 0.45, 'path_keyword'),
    (re.compile(r'contact', re.I), ['ContactId', 'RenterId'], 0.45, 'path_keyword'),
    (re.compile(r'frequent', re.I), ['ContactId'], 0.45, 'path_keyword'),
    (re.compile(r'coupon', re.I), ['CouponId'], 0.45, 'path_keyword'),
    (re.compile(r'rescue.*list', re.I), ['RescueId'], 0.5, 'path_keyword'),
    (re.compile(r'store', re.I), ['StoreId'], 0.45, 'path_keyword'),
    (re.compile(r'cardinfo|byuserid', re.I), ['UserId'], 0.5, 'path_keyword'),
    (re.compile(r'miniprogram/openid|/openid', re.I), ['OpenId', 'code'], 0.55, 'path_keyword'),
]

SNIPPET_PRODUCES_PATTERNS: List[Tuple[re.Pattern[str], str, float]] = [
    (re.compile(r'globalData\.User\s*=', re.I), 'UserId', 0.9),
    (re.compile(r'setStorageSync\s*\(\s*["\']OpenId', re.I), 'OpenId', 0.9),
    (re.compile(r'\.OrderId\b', re.I), 'OrderId', 0.85),
    (re.compile(r'\.DeviceId\b', re.I), 'DeviceId', 0.85),
    (re.compile(r'\.AddressId\b', re.I), 'AddressId', 0.85),
    (re.compile(r'item\.OrderId|list\.map.*OrderId', re.I), 'OrderId', 0.85),
    (re.compile(r'res\.data\.User|data\.UserId', re.I), 'UserId', 0.88),
]

OBJECT_ID_SUFFIX_RE = re.compile(r'(\w+)(Id|No)$', re.I)


def _card_path(card: Dict[str, Any]) -> str:
    return ((card.get('static') or {}).get('endpoint') or {}).get('path') or ''


def _card_method(card: Dict[str, Any]) -> str:
    return ((card.get('static') or {}).get('http') or {}).get('method') or 'UNKNOWN'


def _snippets_from_card(card: Dict[str, Any]) -> List[Dict[str, Any]]:
    ev = card.get('evidence') or {}
    out = []
    for cs in ev.get('callsites') or []:
        out.append({
            'evidence_id': cs.get('evidence_id'),
            'file': cs.get('file'),
            'line': cs.get('line'),
            'text': cs.get('snippet') or cs.get('text') or '',
        })
    return out


def infer_produces_from_path(card: Dict[str, Any]) -> List[Dict[str, Any]]:
    path = _card_path(card)
    cid = card.get('card_id')
    edges = []
    seen: Set[str] = set()
    for pat, fields, conf, etype in PATH_PRODUCES_RULES:
        if pat.search(path):
            for fname in fields:
                if fname in seen:
                    continue
                seen.add(fname)
                clf = classify_field(fname, path=path)
                edges.append({
                    'type': 'produces',
                    'edge_type': 'produces',
                    'from_api': cid,
                    'from': cid,
                    'to_field': fname,
                    'to': fname,
                    'confidence': conf,
                    'evidence_type': etype,
                    'evidence_level': 'static_candidate',
                    'evidence_refs': [f'path:{path}'],
                    'field_role': clf['field_role'],
                    'obtainability': clf['obtainability'],
                    'phase': 'pre_baseline_candidate',
                })
    return edges


def infer_produces_from_snippets(card: Dict[str, Any]) -> List[Dict[str, Any]]:
    path = _card_path(card)
    cid = card.get('card_id')
    edges = []
    seen: Set[Tuple[str, str]] = set()
    for sn in _snippets_from_card(card):
        text = sn.get('text') or ''
        ref = f"callsite:{sn.get('file')}:{sn.get('line')}"
        for pat, fname, conf in SNIPPET_PRODUCES_PATTERNS:
            if pat.search(text):
                key = (fname, ref)
                if key in seen:
                    continue
                seen.add(key)
                clf = classify_field(fname, path=path)
                edges.append({
                    'type': 'produces',
                    'from_api': cid,
                    'from': cid,
                    'to_field': fname,
                    'to': fname,
                    'confidence': conf,
                    'evidence_type': 'response_usage_static',
                    'evidence_refs': [ref, sn.get('evidence_id') or ref],
                    'field_role': clf['field_role'],
                    'obtainability': clf['obtainability'],
                    'phase': 'pre_baseline_candidate',
                })
    return edges


def infer_produces_list_detail_pairs(
    cards: List[Dict[str, Any]],
    classifications: Dict[str, Dict[str, Any]],
    required_by_api: Dict[str, Set[str]],
) -> List[Dict[str, Any]]:
    """If detail API requires XXXId and list API exists in same domain, list produces XXXId."""
    list_apis: Dict[str, List[str]] = defaultdict(list)
    detail_apis: List[Tuple[str, str, Set[str]]] = []

    for card in cards:
        if (card.get('provenance') or {}).get('card_kind') != 'operation':
            continue
        cid = card['card_id']
        cl = classifications.get(cid) or classify_card(card)
        path = _card_path(card)
        sem = cl.get('operation_semantics')
        dom = cl.get('business_domain')
        if sem == 'list' or re.search(r'/list|recent', path, re.I):
            list_apis[dom].append(cid)
        if sem == 'detail' or re.search(r'detail|byid', path, re.I):
            reqs = required_by_api.get(cid, set())
            detail_apis.append((cid, dom, reqs))

    edges = []
    for detail_id, dom, reqs in detail_apis:
        for req_field in reqs:
            m = OBJECT_ID_SUFFIX_RE.search(req_field)
            if not m:
                continue
            base = m.group(1)
            if base.lower() in {'user', 'app', 'channel', 'page'}:
                continue
            for list_id in list_apis.get(dom, []):
                edges.append({
                    'type': 'produces',
                    'from_api': list_id,
                    'from': list_id,
                    'to_field': req_field,
                    'to': req_field,
                    'confidence': 0.6,
                    'evidence_type': 'list_detail_pair',
                    'evidence_refs': [
                        f'consumer:{detail_id}',
                        f'domain:{dom}',
                    ],
                    'field_role': 'object_id',
                    'obtainability': 'O3_first_hop_object',
                    'phase': 'pre_baseline_candidate',
                })
    return edges


def merge_produces_edges(edge_lists: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    merged: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for edges in edge_lists:
        for e in edges:
            key = (e.get('from_api') or e.get('from'), e.get('to_field') or e.get('to'))
            if not key[0] or not key[1]:
                continue
            existing = merged.get(key)
            if existing is None or e.get('confidence', 0) > existing.get('confidence', 0):
                merged[key] = e
            elif existing and e.get('confidence') == existing.get('confidence'):
                refs = list(dict.fromkeys((existing.get('evidence_refs') or []) + (e.get('evidence_refs') or [])))
                existing['evidence_refs'] = refs[:5]
    return list(merged.values())


def build_enhanced_produces(
    cards: List[Dict[str, Any]],
    classifications: Optional[Dict[str, Dict[str, Any]]] = None,
    required_by_api: Optional[Dict[str, Set[str]]] = None,
) -> List[Dict[str, Any]]:
    ops = [c for c in cards if (c.get('provenance') or {}).get('card_kind') == 'operation']
    clf_map = classifications or {}
    req_map = required_by_api or {}

    per_card_path = [infer_produces_from_path(c) for c in ops]
    per_card_snip = [infer_produces_from_snippets(c) for c in ops]
    pairs = infer_produces_list_detail_pairs(ops, clf_map, req_map)

    return merge_produces_edges(per_card_path + per_card_snip + [pairs])


def attach_produces_to_graph(
    graph: Dict[str, Any],
    produces_edges: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Merge enhanced produces into requires graph (no truncation — use preview variant separately)."""
    from minidrifter.graph.runtime_demand_graph import assemble_demand_graph

    requires = [e for e in (graph.get('edges') or []) if e.get('type') == 'requires']
    if not requires and graph.get('api_nodes'):
        requires = [e for e in (graph.get('edges') or []) if e.get('type') != 'produces']
    field_nodes = set(graph.get('field_nodes') or [])
    for e in requires:
        if e.get('to'):
            field_nodes.add(e['to'])
    return assemble_demand_graph(
        graph.get('api_nodes') or [],
        requires,
        produces_edges,
        field_nodes,
    )
