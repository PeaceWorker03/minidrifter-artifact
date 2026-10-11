# -*- coding: utf-8 -*-
"""RecoverEdge: DirectProp / RespHandoff under SameScope ∧ precedence."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.rpgraph.schema import (
    AUTH_LOGIN_RE,
    PATH_CONTEXT_CRED,
    PRODUCER_PATH_RE,
    SENSITIVE_PATH_RE,
    continuity_fields,
    credential_set,
    field_aliases,
    is_session_identity,
    path_domain,
)


def _alias_hit(a: str, b: str) -> bool:
    return bool(field_aliases(a) & field_aliases(b))


def _session_family_hit(a: str, b: str) -> bool:
    """token/openid/... share wechat_session identity continuity."""
    return is_session_identity(a) and is_session_identity(b)


def _cred_compatible(a: str, b: str) -> bool:
    return _alias_hit(a, b) or _session_family_hit(a, b)


def _related_handoff(src_field: str, dst_field: str) -> bool:
    if _cred_compatible(src_field, dst_field):
        return True
    sa, sb = src_field.lower(), dst_field.lower()
    # e.g. orderId → orderNo, memberId → encryptMemberId
    core_a = re.sub(r'(id|no|code|list|info)$', '', sa)
    core_b = re.sub(r'(id|no|code|list|info)$', '', sb)
    return bool(core_a and core_b and (core_a in core_b or core_b in core_a) and len(core_a) >= 3)


def recover_edges(
    ccrs: List[Dict[str, Any]],
    operation_scope: Dict[str, str],
    precedence: Dict[str, Any],
) -> Dict[str, Any]:
    by_id = {c.get('operation_id'): c for c in ccrs if c.get('operation_id')}
    pair_index = precedence.get('pair_index') or {}
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []

    # Nodes v_{i,c} — same field universe as DirectProp matching
    for RCR in ccrs:
        oid = RCR.get('operation_id')
        if not oid:
            continue
        fields = continuity_fields(RCR)
        for field in fields:
            nid = f'{oid}::{field}'
            nodes[nid] = {
                'node_id': nid,
                'operation_id': oid,
                'credential': field,
                'scope': operation_scope.get(oid),
                'path': ((RCR.get('endpoint') or {}).get('path') or ''),
                'method': ((RCR.get('method') or {}).get('value')
                           or ((RCR.get('request_semantics') or {}).get('operation') or {}).get('method')),
            }

    # Index nodes by scope and credential aliases
    scope_cred_nodes: Dict[str, Dict[str, List[str]]] = {}
    for nid, node in nodes.items():
        sc = node.get('scope') or '⊥'
        scope_cred_nodes.setdefault(sc, {}).setdefault(node['credential'].lower(), []).append(nid)
        for al in field_aliases(node['credential']):
            scope_cred_nodes.setdefault(sc, {}).setdefault(al, []).append(nid)

    for (pred, succ), pair in (
        ((k.split('->')[0], k.split('->')[1]), v)
        for k, v in pair_index.items() if '->' in k
    ):
        if operation_scope.get(pred) != operation_scope.get(succ):
            continue
        if operation_scope.get(pred) is None:
            continue
        ca, cb = by_id.get(pred) or {}, by_id.get(succ) or {}
        # Use continuity_fields so session Token/token participate in DirectProp
        fa, fb = continuity_fields(ca), continuity_fields(cb)
        if not fa and not fb:
            continue
        pa = ((ca.get('endpoint') or {}).get('path') or '')
        pb = ((cb.get('endpoint') or {}).get('path') or '')
        auth_pred = bool(AUTH_LOGIN_RE.search(pa))
        # DirectProp: at most one session edge + one bind edge per precedence pair
        session_pair_emitted = False
        bind_pair_emitted = False
        for c1 in fa or []:
            for c2 in fb or []:
                if c1 == PATH_CONTEXT_CRED or c2 == PATH_CONTEXT_CRED:
                    continue
                alias = _alias_hit(c1, c2)
                sess = _session_family_hit(c1, c2) and not alias
                is_sess_edge = sess or (alias and is_session_identity(c1))
                if is_sess_edge:
                    if not auth_pred or session_pair_emitted:
                        continue
                    session_pair_emitted = True
                elif alias:
                    if bind_pair_emitted:
                        continue
                    # Bind continuity: producer→consumer, sensitive sink, or
                    # sensitive↔sensitive same-domain under ≺ (RR-Drift slices).
                    if not (
                        PRODUCER_PATH_RE.search(pa)
                        or SENSITIVE_PATH_RE.search(pb)
                        or (
                            SENSITIVE_PATH_RE.search(pa)
                            and path_domain(pa) == path_domain(pb)
                        )
                        or 'list_or_get_before_mutate' in (pair.get('evidence') or [])
                    ):
                        continue
                    bind_pair_emitted = True
                else:
                    continue
                edges.append({
                    'src': f'{pred}::{c1}',
                    'dst': f'{succ}::{c2}',
                    'kind': 'DirectProp',
                    'scope': operation_scope.get(pred),
                    'evidence': {
                        'precedence': pair.get('evidence') or [],
                        'credential_match': [c1, c2],
                        'session_family': bool(sess),
                    },
                })
        # RespHandoff: producer path + related credential names
        if fa and fb and PRODUCER_PATH_RE.search(pa):
            for c1 in fa:
                for c2 in fb:
                    if _cred_compatible(c1, c2):
                        continue  # already DirectProp
                    if _related_handoff(c1, c2):
                        edges.append({
                            'src': f'{pred}::{c1}',
                            'dst': f'{succ}::{c2}',
                            'kind': 'RespHandoff',
                            'scope': operation_scope.get(pred),
                            'evidence': {
                                'precedence': pair.get('evidence') or [],
                                'producer_path': pa,
                                'fields': [c1, c2],
                            },
                        })
        # Path-context / same-domain RespHandoff under SameScope∧≺
        same_dom = path_domain(pa) == path_domain(pb)
        uses_ctx = PATH_CONTEXT_CRED in (fa or []) or PATH_CONTEXT_CRED in (fb or [])
        auth_to_biz = bool(auth_pred and SENSITIVE_PATH_RE.search(pb))
        scope_n = sum(1 for _oid, sc in operation_scope.items() if sc == operation_scope.get(pred))
        small_scope = scope_n <= 12
        large_scope = scope_n > 100
        allow_soft = False
        if auth_to_biz:
            allow_soft = True
        elif large_scope:
            # Keep producer→sensitive same-domain handoffs; drop ctx-only spam
            allow_soft = bool(same_dom and PRODUCER_PATH_RE.search(pa) and SENSITIVE_PATH_RE.search(pb) and not uses_ctx)
        elif same_dom and (uses_ctx or PRODUCER_PATH_RE.search(pa) or SENSITIVE_PATH_RE.search(pb)):
            allow_soft = True
        elif small_scope and (SENSITIVE_PATH_RE.search(pa) or SENSITIVE_PATH_RE.search(pb) or uses_ctx):
            allow_soft = True
        if allow_soft:
            src_fields = list(fa or ([] if not (SENSITIVE_PATH_RE.search(pa) or PRODUCER_PATH_RE.search(pa)) else [PATH_CONTEXT_CRED]))
            dst_fields = list(fb or ([] if not SENSITIVE_PATH_RE.search(pb) else [PATH_CONTEXT_CRED]))
            if not src_fields:
                src_fields = [PATH_CONTEXT_CRED]
            if not dst_fields:
                dst_fields = [PATH_CONTEXT_CRED]
            # Prefer named fields; avoid pure ctx↔ctx on large scopes
            if large_scope:
                src_fields = [x for x in src_fields if x != PATH_CONTEXT_CRED][:2] or src_fields[:1]
                dst_fields = [x for x in dst_fields if x != PATH_CONTEXT_CRED][:2] or dst_fields[:1]
            for c1 in src_fields[:2]:
                for c2 in dst_fields[:2]:
                    if _cred_compatible(c1, c2):
                        continue
                    if large_scope and c1 == PATH_CONTEXT_CRED and c2 == PATH_CONTEXT_CRED:
                        continue
                    edges.append({
                        'src': f'{pred}::{c1}',
                        'dst': f'{succ}::{c2}',
                        'kind': 'RespHandoff',
                        'scope': operation_scope.get(pred),
                        'evidence': {
                            'precedence': pair.get('evidence') or [],
                            'handoff': 'path_context_or_domain',
                            'domains': [path_domain(pa), path_domain(pb)],
                            'fields': [c1, c2],
                        },
                    })

    # Ensure endpoints referenced by edges exist as nodes
    for e in edges:
        for endpoint in (e['src'], e['dst']):
            if endpoint not in nodes:
                oid, _, field = endpoint.partition('::')
                RCR = by_id.get(oid) or {}
                nodes[endpoint] = {
                    'node_id': endpoint,
                    'operation_id': oid,
                    'credential': field,
                    'scope': operation_scope.get(oid),
                    'path': ((RCR.get('endpoint') or {}).get('path') or ''),
                    'method': ((RCR.get('method') or {}).get('value')),
                }

    # Dedup edges; cap pathological fan-out for large packs
    seen: Set[Tuple[str, str, str]] = set()
    uniq = []
    for e in edges:
        key = (e['src'], e['dst'], e['kind'])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(e)
    max_edges = 40000
    if len(uniq) > max_edges:
        # Prefer DirectProp, auth-bootstrap continuity, then evidence-rich RespHandoff
        def _rank(e: Dict[str, Any]) -> Tuple[int, int, int]:
            kind_rank = 0 if e.get('kind') == 'DirectProp' else 1
            ev = e.get('evidence') or {}
            prec = ev.get('precedence') or []
            auth_rank = 0 if (
                ev.get('session_family')
                or 'auth_bootstrap_precedes' in prec
                or 'auth_before_business' in prec
            ) else 1
            rich = len(prec)
            return (kind_rank, auth_rank, -rich)
        uniq = sorted(uniq, key=_rank)[:max_edges]

    return {
        'nodes': list(nodes.values()),
        'edges': uniq,
        'node_count': len(nodes),
        'edge_count': len(uniq),
        'direct_prop_count': sum(1 for e in uniq if e['kind'] == 'DirectProp'),
        'resp_handoff_count': sum(1 for e in uniq if e['kind'] == 'RespHandoff'),
    }
