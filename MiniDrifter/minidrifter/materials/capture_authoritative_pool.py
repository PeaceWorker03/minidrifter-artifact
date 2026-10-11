# -*- coding: utf-8 -*-
"""Capture-authoritative runtime pool — per-API capture overrides global baseline."""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

SESSION_CRYPTO_FIELDS = frozenset({
    'cid', 'uid', 'token', 'sign', 'q', 'host', 'timestamp', 'timespan',
})

SESSION_CRYPTO_NORM = frozenset(x.lower() for x in SESSION_CRYPTO_FIELDS)


def _baseline_pool(context: Dict[str, Any]) -> Dict[str, str]:
    pool: Dict[str, str] = {}
    for k, v in (context.get('resolved_fields') or {}).items():
        if isinstance(v, dict) and v.get('value') is not None:
            pool[k] = str(v['value'])
    return pool


def _norm_field(name: str) -> str:
    return ''.join(ch for ch in str(name or '').lower() if ch.isalnum())


def resolve_capture_authoritative_pool(
    baseline_context: Dict[str, Any],
    *,
    test_case: Optional[Dict[str, Any]] = None,
    replay_entry: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    """Merge execution pool with capture-first priority for session/crypto fields."""
    pool = _baseline_pool(baseline_context)
    provenance: Dict[str, str] = {k: 'baseline' for k in pool}

    inner = (replay_entry or {}).get('replay_context') or replay_entry or {}
    for k, v in (inner.get('pool') or {}).items():
        if v in (None, ''):
            continue
        pool[k] = str(v)
        provenance[k] = 'capture_replay_context'

    if test_case:
        for k, v in (test_case.get('chain_param_pool') or {}).items():
            if v in (None, ''):
                continue
            pool[k] = str(v)
            provenance[k] = 'chain_param_pool'

        wire = test_case.get('capture_wire_pool') or {}
        for k, v in wire.items():
            if v in (None, ''):
                continue
            nk = _norm_field(k)
            if nk in SESSION_CRYPTO_NORM:
                pool[k] = str(v)
                provenance[k] = 'capture_wire_pool'

    return pool, {'provenance': provenance, 'capture_authoritative': True}
