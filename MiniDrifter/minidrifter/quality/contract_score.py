# -*- coding: utf-8 -*-
"""Contract recovery quality score for F_i + RCR packs."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

WEIGHTS = {
    'host': 0.10,
    'path': 0.10,
    'method': 0.20,
    'params': 0.10,
    'prov': 0.15,
    'ctx': 0.08,
    'event': 0.02,
    'tx': 0.10,
    'id': 0.05,
    'bind': 0.05,
    'ev': 0.05,
}

DEFAULT_THRESHOLD = 90.0


def score_pack(pack: Path) -> Dict[str, Any]:
    from minidrifter.optimizers.url_utils import is_engine_noise_path, is_frontend_route_path

    rf = json.loads((pack / 'request_facts.json').read_text(encoding='utf-8'))
    from minidrifter.rcr.io import load_rcr_pack
    RCR = load_rcr_pack(pack)
    if not RCR and (pack / 'rcr_pack.json').exists():
        RCR = json.loads((pack / 'rcr_pack.json').read_text(encoding='utf-8'))
    raw_facts = rf.get('request_facts') or []
    # Score only non-noise business-shaped facts (engine/page literals skew packs).
    facts = []
    for f in raw_facts:
        path = ((f.get('endpoint') or {}).get('path') or '')
        if is_frontend_route_path(path) or is_engine_noise_path(path):
            continue
        facts.append(f)
    noise_dropped = len(raw_facts) - len(facts)
    ccrs = {c.get('operation_id'): c for c in (RCR.get('rcrs') or RCR.get('ccrs') or [])}
    # Vacuous / incomplete packs: no recoverable business surface.
    if len(facts) < 3:
        return {
            'n': len(facts),
            'n_raw': len(raw_facts),
            'noise_dropped': noise_dropped,
            'score': 0.0,
            'passed_threshold': False,
            'threshold': DEFAULT_THRESHOLD,
            'structurally_incomplete': True,
            'parts': {k: 0.0 for k in WEIGHTS},
        }
    n = max(len(facts), 1)

    host_ok = sum(1 for f in facts if (f.get('endpoint') or {}).get('host')) / n
    path_ok = sum(1 for f in facts if (f.get('endpoint') or {}).get('path')) / n
    method_ok = sum(
        1 for f in facts if ((f.get('method') or {}).get('value') or 'UNKNOWN') != 'UNKNOWN'
    ) / n
    method_conf = sum(float((f.get('method') or {}).get('confidence') or 0) for f in facts) / n
    has_params = sum(1 for f in facts if f.get('params')) / n

    prov_resolved = 0
    prov_total = 0
    for f in facts:
        for _name, p in (f.get('provenance') or {}).items():
            prov_total += 1
            if (p or {}).get('kind') not in (None, 'unresolved'):
                prov_resolved += 1
    prov_ok = (prov_resolved / prov_total) if prov_total else 0.4

    ctx_ok = sum(1 for f in facts if (f.get('invocation_context') or {}).get('source_file')) / n
    event_ok = sum(
        1
        for f in facts
        if (f.get('invocation_context') or {}).get('event_linkage') not in (None, 'not_resolved')
    ) / n

    tx_bound = 0
    for f in facts:
        txs = f.get('transforms') or []
        if any(
            (t or {}).get('binding') in {
                'wrapper_default_chain', 'wrapper_file', 'wrapper_present',
                'callsite_or_file',
            }
            or (
                (t or {}).get('binding') not in (None, 'unbound')
                and (t or {}).get('kind') not in (None, 'none')
            )
            for t in txs
        ):
            tx_bound += 1
    tx_ok = tx_bound / n

    id_ok = sum(
        1
        for f in facts
        if (ccrs.get(f.get('operation_id')) or {})
        .get('request_semantics', {})
        .get('identity_anchor')
    ) / n
    bind_ok = sum(
        1 for f in facts
        if (ccrs.get(f.get('operation_id')) or {}).get('binding_credentials')
        or (ccrs.get(f.get('operation_id')) or {}).get('request_semantics', {}).get('identity_anchor')
    ) / n
    ev_ok = sum(1 for f in facts if (ccrs.get(f.get('operation_id')) or {}).get('evidence')) / n

    parts = {
        'host': host_ok,
        'path': path_ok,
        'method': method_ok * 0.7 + method_conf * 0.3,
        'params': has_params,
        'prov': prov_ok,
        'ctx': ctx_ok,
        'event': event_ok,
        'tx': tx_ok,
        'id': id_ok,
        'bind': bind_ok,
        'ev': ev_ok,
    }
    score = sum(parts[k] * WEIGHTS[k] for k in WEIGHTS)
    pct = round(score * 100, 2)
    return {
        'n': len(facts),
        'n_raw': len(raw_facts),
        'noise_dropped': noise_dropped,
        'score': pct,
        'passed_threshold': pct >= DEFAULT_THRESHOLD,
        'threshold': DEFAULT_THRESHOLD,
        'structurally_incomplete': False,
        'parts': {k: round(v * 100, 1) for k, v in parts.items()},
        'method_counts': rf.get('method_counts'),
        'prov_total': prov_total,
        'prov_resolved': prov_resolved,
        'id_resolved': RCR.get('identity_resolved_count'),
        'with_bind': RCR.get('with_binding_credentials'),
    }


def write_contract_score(pack: Path, *, threshold: float = DEFAULT_THRESHOLD) -> Dict[str, Any]:
    from minidrifter.core.utils import write_json
    doc = score_pack(pack)
    doc['passed_threshold'] = doc['score'] >= threshold
    doc['threshold'] = threshold
    write_json(Path(pack) / 'contract_recovery_score.json', doc)
    return doc
