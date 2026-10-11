# -*- coding: utf-8 -*-
"""Feasible precedence r_i ≺ r_j within an identity scope."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Set, Tuple

from minidrifter.rpgraph.schema import AUTH_BOOTSTRAP_RE, AUTH_LOGIN_RE, PRODUCER_PATH_RE, path_domain


def _rank_key(RCR: Dict[str, Any]) -> Tuple[int, int, str]:
    """Lower sorts earlier in feasible order."""
    path = ((RCR.get('endpoint') or {}).get('path') or '')
    method = ((RCR.get('method') or {}).get('value') or (RCR.get('request_semantics') or {}).get('operation', {}).get('method') or 'GET')
    leaf = path.rstrip('/').rsplit('/', 1)[-1].lower()
    early = 0
    if AUTH_BOOTSTRAP_RE.search(path) or AUTH_BOOTSTRAP_RE.search(leaf):
        early -= 20
    if PRODUCER_PATH_RE.search(leaf) or PRODUCER_PATH_RE.search(path):
        early -= 5
    if re.search(r'(detail|update|delete|pay|bind|unbind|submit)', path, re.I):
        early += 10
    if str(method).upper() == 'GET':
        early -= 1
    return (early, len(path), path.lower())


def build_precedence(
    ccrs: List[Dict[str, Any]],
    operation_scope: Dict[str, str],
) -> Dict[str, Any]:
    """Derive feasible precedence pairs with evidence kinds."""
    by_id = {c.get('operation_id'): c for c in ccrs if c.get('operation_id')}
    pairs: List[Dict[str, Any]] = []
    # Group by scope then domain for denser, evidence-supported order.
    scope_groups: Dict[str, List[str]] = {}
    for oid, sc in operation_scope.items():
        scope_groups.setdefault(sc, []).append(oid)

    for sc, oids in scope_groups.items():
        # Subgroup by path domain
        domains: Dict[str, List[str]] = {}
        for oid in oids:
            RCR = by_id.get(oid) or {}
            path = ((RCR.get('endpoint') or {}).get('path') or '')
            domains.setdefault(path_domain(path), []).append(oid)
        for _dom, members in domains.items():
            ordered = sorted(members, key=lambda x: _rank_key(by_id.get(x) or {}))
            # Connect consecutive and producer→consumer within domain window
            for i, a in enumerate(ordered):
                for b in ordered[i + 1:i + 8]:
                    ca, cb = by_id.get(a) or {}, by_id.get(b) or {}
                    pa = ((ca.get('endpoint') or {}).get('path') or '')
                    pb = ((cb.get('endpoint') or {}).get('path') or '')
                    evidence = ['domain_order']
                    if AUTH_BOOTSTRAP_RE.search(pa) and not AUTH_BOOTSTRAP_RE.search(pb):
                        evidence.append('auth_before_business')
                    if PRODUCER_PATH_RE.search(pa) and re.search(r'(detail|pay|update|bind)', pb, re.I):
                        evidence.append('list_or_get_before_mutate')
                    # Page / event co-occurrence
                    ea = ((ca.get('request_semantics') or {}).get('operation') or {}).get('event_linkage')
                    eb = ((cb.get('request_semantics') or {}).get('operation') or {}).get('event_linkage')
                    if ea and eb and ea == eb and ea != 'not_resolved':
                        evidence.append('shared_event_linkage')
                    pairs.append({
                        'pred': a,
                        'succ': b,
                        'scope': sc,
                        'evidence': evidence,
                    })

        # Sparse scopes: also link across coarse domains so /order ↔ /outbound/order
        # still get feasible ≺ when each domain has only a few members.
        if len(oids) >= 3 and len(domains) >= 2:
            ordered_all = sorted(oids, key=lambda x: _rank_key(by_id.get(x) or {}))
            for i, a in enumerate(ordered_all):
                for b in ordered_all[i + 1:i + 5]:
                    ca, cb = by_id.get(a) or {}, by_id.get(b) or {}
                    pa = ((ca.get('endpoint') or {}).get('path') or '')
                    pb = ((cb.get('endpoint') or {}).get('path') or '')
                    if path_domain(pa) == path_domain(pb):
                        continue  # already covered in-domain
                    evidence = ['scope_order']
                    if AUTH_BOOTSTRAP_RE.search(pa) and not AUTH_BOOTSTRAP_RE.search(pb):
                        evidence.append('auth_before_business')
                    if PRODUCER_PATH_RE.search(pa) and re.search(
                        r'(detail|pay|update|bind|submit|add)', pb, re.I
                    ):
                        evidence.append('list_or_get_before_mutate')
                    pairs.append({
                        'pred': a,
                        'succ': b,
                        'scope': sc,
                        'evidence': evidence,
                    })

        # Cross-domain: true login/auth ops precede all other ops in same identity scope
        bootstrap = [
            oid for oid in oids
            if AUTH_LOGIN_RE.search(((by_id.get(oid) or {}).get('endpoint') or {}).get('path') or '')
        ]
        others = [oid for oid in oids if oid not in bootstrap]
        for a in bootstrap:
            for b in others:
                pairs.append({
                    'pred': a,
                    'succ': b,
                    'scope': sc,
                    'evidence': ['auth_bootstrap_precedes'],
                })

    # Dedup
    seen: Set[Tuple[str, str]] = set()
    uniq = []
    for p in pairs:
        key = (p['pred'], p['succ'])
        if key in seen or p['pred'] == p['succ']:
            continue
        seen.add(key)
        uniq.append(p)
    return {
        'precedence_count': len(uniq),
        'pairs': uniq,
        'pair_index': {f"{p['pred']}->{p['succ']}": p for p in uniq},
    }
