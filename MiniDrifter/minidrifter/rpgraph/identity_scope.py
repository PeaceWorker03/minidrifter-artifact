# -*- coding: utf-8 -*-
"""Identity scope assignment (SameScope)."""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Tuple

from minidrifter.rpgraph.schema import credential_set, norm_identity


def assign_identity_scopes(ccrs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Group CCRs by canonical identity anchor; attach unanchored when uniquely connectable."""
    by_anchor: Dict[str, List[str]] = defaultdict(list)
    op_scope: Dict[str, str] = {}
    anchored = 0
    for RCR in ccrs:
        oid = RCR.get('operation_id')
        if not oid:
            continue
        anchor = norm_identity((RCR.get('request_semantics') or {}).get('identity_anchor'))
        if anchor != '⊥':
            anchored += 1
            by_anchor[anchor].append(oid)
            op_scope[oid] = anchor
        else:
            op_scope[oid] = '⊥'

    # Unanchored join the dominant anchored scope when exactly one anchored lineage exists,
    # or when they share host with a single dominant scope.
    if len(by_anchor) == 1:
        only = next(iter(by_anchor))
        for oid, sc in list(op_scope.items()):
            if sc == '⊥':
                op_scope[oid] = only
                by_anchor[only].append(oid)
    elif by_anchor:
        # Host-majority vote among anchored scopes.
        host_to_scopes: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        oid_to_ccr = {c.get('operation_id'): c for c in ccrs}
        for oid, sc in op_scope.items():
            if sc == '⊥':
                continue
            host = ((oid_to_ccr.get(oid) or {}).get('endpoint') or {}).get('host') or ''
            host_to_scopes[host][sc] += 1
        for oid, sc in list(op_scope.items()):
            if sc != '⊥':
                continue
            host = ((oid_to_ccr.get(oid) or {}).get('endpoint') or {}).get('host') or ''
            votes = host_to_scopes.get(host) or {}
            if len(votes) == 1:
                chosen = next(iter(votes))
                op_scope[oid] = chosen
                by_anchor[chosen].append(oid)

    # Fallback synthetic scope for remaining ⊥ so they can still form producer edges.
    remaining = [oid for oid, sc in op_scope.items() if sc == '⊥']
    if remaining:
        by_anchor['⊥'].extend(remaining)

    scopes = []
    for anchor, oids in sorted(by_anchor.items(), key=lambda x: (-len(x[1]), x[0])):
        scopes.append({
            'scope_id': f'scope:{anchor}',
            'identity_anchor': None if anchor == '⊥' else anchor,
            'operation_ids': sorted(set(oids)),
            'size': len(set(oids)),
        })
    return {
        'scopes': scopes,
        'operation_scope': op_scope,
        'anchored_operation_count': anchored,
        'scope_count': len(scopes),
    }
